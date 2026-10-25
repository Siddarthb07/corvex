"""Single-writer correlator — imports EventBus protocol only for ingest typing."""

from __future__ import annotations

import json
from collections import defaultdict
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence, Set, Tuple

from corvex.audit import AuditLog
from corvex.auth import AuthError, Enrollment
from corvex.detectors import Signal, run_all
from corvex.envelope import EventEnvelope, verify_envelope
from corvex.net_noise import canon_fleet_peer, is_ambient_dst, is_fleet_peer
from corvex.store import Campaign, CampaignStore


def _parse_ts(ts: str) -> datetime:
    # Accept ...Z
    if ts.endswith("Z"):
        ts = ts[:-1] + "+00:00"
    return datetime.fromisoformat(ts)


def _event_ts(ev: Mapping[str, Any]) -> Optional[datetime]:
    raw = ev.get("ts_utc")
    if not raw:
        return None
    try:
        return _parse_ts(str(raw))
    except ValueError:
        return None


def _connected_host_components(
    timed_hosts: Sequence[Tuple[datetime, str]],
    window_seconds: float,
) -> List[List[Tuple[datetime, str]]]:
    """Group timed (ts, host) events into chains with consecutive gaps <= window.

    Returns the event slices (not just host sets) so callers get correct
    per-component time ranges — critical when the same hosts recur later.
    """
    if not timed_hosts:
        return []
    ordered = sorted(timed_hosts, key=lambda x: x[0])
    components: List[List[Tuple[datetime, str]]] = []
    cur: List[Tuple[datetime, str]] = [ordered[0]]
    prev_t = ordered[0][0]
    for t, host in ordered[1:]:
        gap = (t - prev_t).total_seconds()
        if gap <= window_seconds:
            cur.append((t, host))
        else:
            components.append(cur)
            cur = [(t, host)]
        prev_t = t
    components.append(cur)
    return components


def _ranges_overlap(
    a: Tuple[Optional[datetime], Optional[datetime]],
    b: Tuple[Optional[datetime], Optional[datetime]],
    window_seconds: float,
) -> bool:
    """True if time ranges are within window of each other (or either is unknown)."""
    a0, a1 = a
    b0, b1 = b
    if a0 is None or a1 is None or b0 is None or b1 is None:
        return True
    # Expand each range by window/2 equivalent: gap between intervals <= window
    if a1 < b0:
        return (b0 - a1).total_seconds() <= window_seconds
    if b1 < a0:
        return (a0 - b1).total_seconds() <= window_seconds
    return True


@dataclass
class CorrelatorConfig:
    window_seconds: int = 600
    resume_window_seconds: int = 3600  # same-user lateral resume across quiet gaps
    # Day-scale sleeper resume (lim03 / day_gap_*). Separate from resume_window so
    # sequential-reuse / lim09b hard-splits are not inflated to days.
    sleeper_resume_seconds: int = 14 * 24 * 3600
    min_hosts: int = 2
    cross_host_enabled: bool = True  # ablation toggle
    # Shape/gap hard split: defaults derived from window_seconds (no retune dial).
    # When True, refuse merges across a quiet gap >= window when stage sets differ.
    force_split_on_shape_gap: bool = True
    # Hub degree bridge bar: None → max(2, fleet_n // 2). High-degree overlap
    # cannot expand into another operator's hosts (lim09 / lim02), with handoff exceptions.
    hub_degree_bar: Optional[int] = None
    # Runtime host identity: alias → canonical (e.g. host-b-dhcp → host-b). Applied
    # after HMAC verify so live/BYO split-brain stitches without adapt-time rewrite.
    host_aliases: Optional[Dict[str, str]] = None
    # Exfil flood poison: mark dst poisoned when unique hosts in a window component
    # reach this floor (also capped by fanout_bar). CDN bury / noise_5k.
    exfil_poison_host_floor: int = 3
    # Require lateral/auth co-evidence before expanding exfil-only multi-host camps
    # into other clusters (noise_5k_needle).
    exfil_merge_requires_lateral: bool = True


def load_host_aliases(path: Optional[Path] = None) -> Optional[Dict[str, str]]:
    """Load alias→canonical map from JSON (e.g. ``{\"host-b-dhcp\": \"host-b\"}``)."""
    if path is None:
        return None
    # Typer OptionInfo leaks when CLI commands are invoked as plain Python callables.
    if not isinstance(path, (str, Path)):
        return None
    p = Path(path)
    if not p.exists():
        return None
    try:
        data = json.loads(p.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    if not isinstance(data, dict):
        return None
    out = {str(k): str(v) for k, v in data.items() if k and v}
    return out or None


def _resolve_host_alias(host_id: str, aliases: Optional[Mapping[str, str]]) -> str:
    """Map alias host_id → canonical; identity if unknown."""
    if not aliases:
        return host_id
    hid = str(host_id)
    # Single-hop alias table (DHCP re-lease → persistent asset id).
    return str(aliases.get(hid, hid))


def _canonicalize_event(
    ev: Dict[str, Any], aliases: Optional[Mapping[str, str]]
) -> Dict[str, Any]:
    """Rewrite host_id and host-* auth src through host_aliases for fusion."""
    if not aliases:
        return ev
    out = dict(ev)
    out["host_id"] = _resolve_host_alias(str(ev.get("host_id") or ""), aliases)
    payload = ev.get("payload")
    if isinstance(payload, dict):
        payload = dict(payload)
        src = payload.get("src")
        if src and str(src).startswith("host-"):
            payload["src"] = _resolve_host_alias(str(src), aliases)
        out["payload"] = payload
    return out


def _stage_names(stages: Sequence[Mapping[str, Any]]) -> frozenset:
    return frozenset(str(st.get("name") or "") for st in stages if st.get("name"))


def _quiet_gap_seconds(
    a: Tuple[Optional[datetime], Optional[datetime]],
    b: Tuple[Optional[datetime], Optional[datetime]],
) -> float:
    """Seconds of quiet between two ranges (0 if they overlap or either unknown)."""
    a0, a1 = a
    b0, b1 = b
    if a0 is None or a1 is None or b0 is None or b1 is None:
        return 0.0
    if a1 < b0:
        return (b0 - a1).total_seconds()
    if b1 < a0:
        return (a0 - b1).total_seconds()
    return 0.0


def _dns_apex(query: str) -> str:
    """Parent zone used as a multi-host DNS C2 stitch key (e.g. c2.evil.test)."""
    q = str(query or "").strip().lower().rstrip(".")
    if not q or "." not in q:
        return q
    parts = [p for p in q.split(".") if p]
    if len(parts) >= 3:
        return ".".join(parts[1:])
    return q


def _hop_reachable(edges: Sequence[Tuple[str, str]]) -> Set[str]:
    """Undirected hosts reachable via host-* auth src hops."""
    adj: Dict[str, Set[str]] = defaultdict(set)
    for a, b in edges:
        adj[a].add(b)
        adj[b].add(a)
    seen: Set[str] = set()
    for start in list(adj.keys()):
        if start in seen:
            continue
        stack = [start]
        while stack:
            cur = stack.pop()
            if cur in seen:
                continue
            seen.add(cur)
            stack.extend(adj[cur] - seen)
    return seen


def _hop_components_within(
    edges: Sequence[Tuple[str, str]], hosts: Set[str]
) -> List[Set[str]]:
    """Connected components of the hop graph induced by ``hosts``.

    Hosts with no hop edge become singletons. Used so time-windowed lateral
    groups do not glue disjoint svc-account chains that share a quiet window.
    """
    if not hosts:
        return []
    adj: Dict[str, Set[str]] = defaultdict(set)
    for a, b in edges:
        if a in hosts and b in hosts:
            adj[a].add(b)
            adj[b].add(a)
    seen: Set[str] = set()
    comps: List[Set[str]] = []
    for start in sorted(hosts):
        if start in seen:
            continue
        stack = [start]
        comp: Set[str] = set()
        while stack:
            cur = stack.pop()
            if cur in seen:
                continue
            seen.add(cur)
            comp.add(cur)
            stack.extend((adj.get(cur) or set()) - seen)
        comps.append(comp)
    return comps


class Correlator:
    """Owns CampaignStore writes. Dedups on event_id before mutate."""

    def __init__(
        self,
        store: CampaignStore,
        audit: AuditLog,
        config: Optional[CorrelatorConfig] = None,
        detector_only: bool = False,
        enrollment: Optional[Enrollment] = None,
        *,
        allow_unverified: bool = False,
    ):
        self.store = store
        self.audit = audit
        self.config = config or CorrelatorConfig()
        self.detector_only = detector_only
        self.enrollment = enrollment
        self.allow_unverified = allow_unverified
        self.hmac_rejected = 0
        self._seen: Set[str] = set()
        self._events: List[Dict[str, Any]] = []

    def ingest(self, envelopes: Iterable[EventEnvelope]) -> None:
        for env in envelopes:
            if self.enrollment is not None:
                try:
                    secret = self.enrollment.require(env.producer_id, env.host_id)
                except AuthError:
                    self.hmac_rejected += 1
                    self.audit.append(
                        "hmac_reject",
                        {
                            "event_id": env.event_id,
                            "reason": "not_enrolled",
                            "producer_id": env.producer_id,
                            "host_id": env.host_id,
                        },
                    )
                    continue
                if not verify_envelope(env, secret):
                    self.hmac_rejected += 1
                    self.audit.append(
                        "hmac_reject",
                        {
                            "event_id": env.event_id,
                            "reason": "bad_hmac",
                            "producer_id": env.producer_id,
                            "host_id": env.host_id,
                        },
                    )
                    continue
            elif not self.allow_unverified:
                self.hmac_rejected += 1
                self.audit.append(
                    "hmac_reject",
                    {
                        "event_id": env.event_id,
                        "reason": "enrollment_required",
                        "producer_id": env.producer_id,
                        "host_id": env.host_id,
                    },
                )
                continue
            if env.event_id in self._seen:
                continue
            self._seen.add(env.event_id)
            # Verify against the envelope's original host_id; canonicalize for fusion.
            rec = env.to_dict()
            self._events.append(
                _canonicalize_event(rec, self.config.host_aliases)
            )
        self._recompute()

    def _recompute(self) -> None:
        if not self._events:
            return
        # Sort by time
        events = sorted(self._events, key=lambda e: e["ts_utc"])
        signals = run_all(events)

        if self.detector_only:
            campaigns = self._campaigns_from_signals(signals, events)
        elif not self.config.cross_host_enabled:
            campaigns = self._per_host_only(events)
        else:
            campaigns = self._fuse(events, signals)

        # Replace store contents for this run
        existing = {c.campaign_id for c in self.store.all()}
        for cid in existing:
            # rewrite via upsert of new set only
            pass
        # Clear by rewriting path
        self.store._campaigns.clear()
        for c in campaigns:
            self.store.upsert(c)
            self.audit.append(
                "campaign_upsert",
                {"campaign_id": c.campaign_id, "hosts": c.host_ids, "stages": len(c.stages)},
            )

    def _campaigns_from_signals(
        self, signals: Sequence[Signal], events: Sequence[Mapping[str, Any]]
    ) -> List[Campaign]:
        """
        Detector-alert path: one campaign per detector key, no cross-key merge.

        Grouping keys mirror how a SIEM alert row would look before correlation:
        - lateral_auth → user
        - micro_exfil → dst_ip
        - recon_fanout → host (single-host scan alert)

        Cross-key / overlapping-host merge is correlator fusion's job. Unioning
        all hosts per kind here previously hid the fusion gap on sealed packs.
        """
        groups: Dict[Tuple[str, str], List[Signal]] = defaultdict(list)
        for s in signals:
            if s.kind == "lateral_auth":
                key = str(s.attrs.get("user") or "_")
            elif s.kind == "micro_exfil":
                key = str(s.attrs.get("dst_ip") or "_")
            else:
                key = s.host_id
            groups[(s.kind, key)].append(s)

        out: List[Campaign] = []
        for (kind, key), sigs in groups.items():
            hosts = sorted({s.host_id for s in sigs})
            if kind != "recon_fanout" and len(hosts) < self.config.min_hosts:
                continue
            safe = key.replace(".", "-").replace(" ", "_")
            cid = f"det-{kind}-{safe}"
            out.append(
                Campaign(
                    campaign_id=cid,
                    host_ids=hosts,
                    stages=[{"name": kind, "hosts": hosts}],
                    evidence=[
                        {"kind": s.kind, "host_id": s.host_id, "attrs": s.attrs} for s in sigs
                    ],
                    score=min(1.0, sum(s.weight for s in sigs) / max(1, len(sigs))),
                )
            )
        return out

    def _per_host_only(self, events: Sequence[Mapping[str, Any]]) -> List[Campaign]:
        """Ablation: no cross-host fusion — one campaign per noisy host."""
        by_host: Dict[str, int] = defaultdict(int)
        for ev in events:
            if ev.get("payload_type") == "net_conn":
                by_host[str(ev["host_id"])] += 1
        out: List[Campaign] = []
        for host, n in by_host.items():
            if n >= 5:
                out.append(
                    Campaign(
                        campaign_id=f"host-{host}",
                        host_ids=[host],
                        stages=[{"name": "local_noise", "hosts": [host]}],
                        evidence=[{"host_id": host, "net_conn": n}],
                        score=0.3,
                    )
                )
        return out

    def _fuse(
        self, events: Sequence[Mapping[str, Any]], signals: Sequence[Signal]
    ) -> List[Campaign]:
        """Cross-host fusion with time windows and anti-jumpbox merge limits.

        Stage A honesty:
        - `window_seconds` bounds which events may stitch into one key-cluster
        - ubiquitous shared egress (fanout too wide) does not become a campaign
        - high-fanout users keep only host-* hop-linked hosts (drops shared-svc bait)
        - auth ``src`` that names another fleet host counts toward lateral topology
        - DNS apex shared across hosts forms a dns_beacon campaign
        - `resume_window_seconds` re-links same-user laterals across quiet gaps
        - single-host merge only when the bridge is cross-key (auth↔exfil/dns)
        """
        window = float(self.config.window_seconds)
        resume = float(self.config.resume_window_seconds)
        sleeper = float(self.config.sleeper_resume_seconds)
        user_timed: Dict[str, List[Tuple[datetime, str]]] = defaultdict(list)
        user_hops: Dict[str, List[Tuple[str, str]]] = defaultdict(list)
        exfil_timed: Dict[str, List[Tuple[datetime, str]]] = defaultdict(list)
        # dst → event count across all timed rows (ambient CDN density).
        exfil_event_count: Dict[str, int] = defaultdict(int)
        dns_timed: Dict[str, List[Tuple[datetime, str]]] = defaultdict(list)
        recon_hosts: Set[str] = set()
        all_hosts_in_events: Set[str] = {
            str(ev["host_id"]) for ev in events if ev.get("host_id") is not None
        }

        for ev in events:
            host = str(ev["host_id"])
            ts = _event_ts(ev)
            ptype = ev.get("payload_type")
            payload = ev.get("payload", {}) or {}
            if ptype == "auth":
                user = str(payload.get("user", ""))
                if user and ts is not None:
                    user_timed[user].append((ts, host))
                    src = str(payload.get("src") or "")
                    # Fleet peers (host-* or short Windows names), not IPs.
                    if is_fleet_peer(src, host, all_hosts_in_events):
                        peer = canon_fleet_peer(src, all_hosts_in_events)
                        user_timed[user].append((ts, peer))
                        user_hops[user].append((peer, host))
                        all_hosts_in_events.add(peer)
            if ptype == "net_conn" and payload.get("egress"):
                dst = str(payload.get("dst_ip", ""))
                nbytes = int(payload.get("bytes", 0))
                if (
                    dst
                    and not is_ambient_dst(dst)
                    and 0 < nbytes <= 50_000
                    and ts is not None
                ):
                    exfil_timed[dst].append((ts, host))
                    exfil_event_count[dst] += 1
            if ptype == "dns":
                apex = _dns_apex(str(payload.get("query") or ""))
                if apex and ts is not None:
                    dns_timed[apex].append((ts, host))

        for s in signals:
            if s.kind == "recon_fanout":
                recon_hosts.add(s.host_id)

        clusters: List[
            Tuple[str, Set[str], List[Dict[str, Any]], Optional[datetime], Optional[datetime]]
        ] = []
        part = 0

        fleet_n = max(1, len(all_hosts_in_events))
        fanout_bar = max(4, fleet_n - 1)
        hub_bar = (
            int(self.config.hub_degree_bar)
            if self.config.hub_degree_bar is not None
            else max(2, fleet_n // 2)
        )
        # Undirected degree from auth hop edges across all users.
        hop_degree: Dict[str, Set[str]] = defaultdict(set)
        for _user, edges in user_hops.items():
            for a, b in edges:
                hop_degree[a].add(b)
                hop_degree[b].add(a)

        def _degree(h: str) -> int:
            return len(hop_degree.get(h) or ())

        for user, timed in user_timed.items():
            edges = user_hops.get(user) or []
            hop_hosts = _hop_reachable(edges)
            # Domain computer / SYSTEM accounts without hop topology are ambient
            # AD noise on OTRF fleets — do not form mega laterals from
            # time-cooccurrence alone.
            _weak = user.endswith("$") or user.upper() in {
                "SYSTEM",
                "LOCAL SERVICE",
                "NETWORK SERVICE",
                "ANONYMOUS LOGON",
            }
            if _weak and not edges:
                continue
            for group in _connected_host_components(timed, window):
                hosts = {h for _, h in group}
                if len(hosts) < self.config.min_hosts:
                    continue
                # Partition by hop islands so disjoint svc-* chains in the same
                # quiet window do not form one mega lateral (shared_svc).
                if edges:
                    host_parts = [
                        comp
                        for comp in _hop_components_within(edges, hosts)
                        if len(comp) >= self.config.min_hosts
                    ]
                    # No multi-host hop island: keep the time component only when
                    # it is below the fanout bar (non-ubiquitous shared account).
                    if not host_parts and len(hosts) < fanout_bar:
                        host_parts = [hosts]
                else:
                    host_parts = [hosts]
                for part_hosts in host_parts:
                    if len(part_hosts) >= fanout_bar:
                        chained = part_hosts & hop_hosts
                        if len(chained) >= self.config.min_hosts:
                            part_hosts = chained
                        else:
                            continue
                    times = [t for t, h in group if h in part_hosts]
                    if len(part_hosts) < self.config.min_hosts or not times:
                        continue
                    part += 1
                    clusters.append(
                        (
                            f"camp-lateral-{user}-{part}",
                            set(part_hosts),
                            [
                                {
                                    "name": "lateral_auth",
                                    "user": user,
                                    "hosts": sorted(part_hosts),
                                }
                            ],
                            min(times),
                            max(times),
                        )
                    )

        # Poison floor for *density* CDN bury only — host-count poison still uses
        # fanout_bar so small sealed exfil fleets (3 hosts, 1 event each) HELD.
        density_floor = max(
            self.config.min_hosts + 1,
            min(fanout_bar, int(self.config.exfil_poison_host_floor)),
        )
        poisoned_dst: Set[str] = set()
        for dst, timed in exfil_timed.items():
            for group in _connected_host_components(timed, window):
                hosts = {h for _, h in group}
                n_ev = len(group)
                # Ubiquitous fanout (original) OR dense ambient (noise_5k).
                if len(hosts) >= fanout_bar:
                    poisoned_dst.add(dst)
                elif len(hosts) >= density_floor and n_ev >= max(20, 10 * len(hosts)):
                    poisoned_dst.add(dst)
            # Global density: CDN flood to one dst across the pack.
            uniq = {h for _, h in timed}
            if (
                len(uniq) >= density_floor
                and exfil_event_count.get(dst, 0) >= max(50, 8 * len(uniq))
            ):
                poisoned_dst.add(dst)

        for dst, timed in exfil_timed.items():
            if dst in poisoned_dst:
                continue
            for group in _connected_host_components(timed, window):
                hosts = {h for _, h in group}
                if len(hosts) < self.config.min_hosts:
                    continue
                times = [t for t, _ in group]
                part += 1
                clusters.append(
                    (
                        f"camp-exfil-{dst.replace('.', '-')}-{part}",
                        set(hosts),
                        [{"name": "micro_exfil", "dst_ip": dst, "hosts": sorted(hosts)}],
                        min(times) if times else None,
                        max(times) if times else None,
                    )
                )

        for apex, timed in dns_timed.items():
            for group in _connected_host_components(timed, window):
                hosts = {h for _, h in group}
                if len(hosts) < self.config.min_hosts:
                    continue
                times = [t for t, _ in group]
                part += 1
                safe = apex.replace(".", "-")
                clusters.append(
                    (
                        f"camp-dns-{safe}-{part}",
                        set(hosts),
                        [{"name": "dns_beacon", "apex": apex, "hosts": sorted(hosts)}],
                        min(times) if times else None,
                        max(times) if times else None,
                    )
                )

        # Annotate overlapping recon hosts on existing clusters — do NOT union
        # every recon_fanout host into the campaign (that forced Q-all-hosts on
        # noisy OTRF fleets). Multi-host recon stays as camp-recon-multi below.
        if recon_hosts:
            for i, (cid, hosts, stages, t0, t1) in enumerate(list(clusters)):
                overlap = hosts & recon_hosts
                if overlap:
                    stages = list(stages)
                    stages.insert(0, {"name": "recon_fanout", "hosts": sorted(overlap)})
                    clusters[i] = (cid, hosts, stages, t0, t1)

        # Fleet-wide recon (every host noisy) is ambient, not a campaign — emitting
        # camp-recon-multi on APT29/Caldera inflated multi-host counts and Q unions.
        if (
            len(recon_hosts) >= self.config.min_hosts
            and len(recon_hosts) < fanout_bar
        ):
            clusters.append(
                (
                    "camp-recon-multi",
                    set(recon_hosts),
                    [{"name": "recon_fanout", "hosts": sorted(recon_hosts)}],
                    None,
                    None,
                )
            )

        def _host_in_stages(
            stages: Sequence[Mapping[str, Any]], host: str, names: Set[str]
        ) -> bool:
            for st in stages:
                if str(st.get("name", "")) in names and host in {
                    str(x) for x in st.get("hosts", [])
                }:
                    return True
            return False

        def _stage_user(stages: Sequence[Mapping[str, Any]]) -> Optional[str]:
            for st in stages:
                if str(st.get("name", "")) == "lateral_auth" and st.get("user"):
                    return str(st.get("user"))
            return None

        def _cross_key_present(
            stages_a: Sequence[Mapping[str, Any]],
            stages_b: Sequence[Mapping[str, Any]],
        ) -> bool:
            """True if one side is lateral-ish and the other is egress/dns."""
            na, nb = _stage_names(stages_a), _stage_names(stages_b)
            lat = {"lateral_auth"}
            eg = {"micro_exfil", "dns_beacon"}
            return bool((na & lat and nb & eg) or (nb & lat and na & eg))

        def _shared_exfil_dst(
            stages_a: Sequence[Mapping[str, Any]],
            stages_b: Sequence[Mapping[str, Any]],
        ) -> bool:
            def _dsts(stages: Sequence[Mapping[str, Any]]) -> Set[str]:
                out: Set[str] = set()
                for st in stages:
                    if str(st.get("name") or "") in {"micro_exfil", "dns_beacon"}:
                        if st.get("dst_ip"):
                            out.add(str(st.get("dst_ip")))
                        if st.get("dns_apex"):
                            out.add(str(st.get("dns_apex")))
                        if st.get("apex"):
                            out.add(str(st.get("apex")))
                return out

            return bool(_dsts(stages_a) & _dsts(stages_b))

        def _single_host_bridge_ok(
            hosts_a: Set[str],
            stages_a: Sequence[Mapping[str, Any]],
            hosts_b: Set[str],
            stages_b: Sequence[Mapping[str, Any]],
        ) -> bool:
            overlap = hosts_a & hosts_b
            if not overlap:
                return False
            ua, ub = _stage_user(stages_a), _stage_user(stages_b)
            # Multi-host overlap alone used to auto-merge — that glued every
            # ambient exfil/dns camp into one APT29 mega-campaign. Require a
            # semantic bridge: cross-key, shared needle dst, or same lateral user.
            if len(overlap) >= 2:
                if ua and ub and ua == ub:
                    return True
                if _cross_key_present(stages_a, stages_b):
                    # Two laterals meeting on shared hosts still refuse (helpdesk)
                    a_is_lat = "lateral_auth" in _stage_names(stages_a)
                    b_is_lat = "lateral_auth" in _stage_names(stages_b)
                    if a_is_lat and b_is_lat and ua and ub and ua != ub:
                        return False
                    return True
                if _shared_exfil_dst(stages_a, stages_b):
                    return True
                return False
            if len(overlap) != 1:
                return False
            h = next(iter(overlap))
            a_lat = _host_in_stages(stages_a, h, {"lateral_auth"})
            b_lat = _host_in_stages(stages_b, h, {"lateral_auth"})
            a_ex = _host_in_stages(stages_a, h, {"micro_exfil", "dns_beacon"})
            b_ex = _host_in_stages(stages_b, h, {"micro_exfil", "dns_beacon"})
            cross = (a_lat and b_ex) or (b_lat and a_ex)
            if not cross:
                return False
            # Two lateral campaigns meeting at a jumpbox must not glue — even if
            # one side also has exfil on that host (helpdesk hitchhiking).
            a_is_lat = any(str(st.get("name", "")) == "lateral_auth" for st in stages_a)
            b_is_lat = any(str(st.get("name", "")) == "lateral_auth" for st in stages_b)
            if a_is_lat and b_is_lat:
                return False
            return True

        def _user_hop_links(user: Optional[str], a: Set[str], b: Set[str]) -> bool:
            """True if any host in a reaches any host in b via this user's hop graph."""
            if not user or not a or not b:
                return False
            edges = user_hops.get(user) or []
            if not edges:
                return False
            reachable = _hop_reachable(edges)
            # Also require an actual path between the two sets, not just membership
            # in the global reachable set of that user.
            adj: Dict[str, Set[str]] = defaultdict(set)
            for x, y in edges:
                adj[x].add(y)
                adj[y].add(x)
            for start in a:
                if start not in adj and start not in reachable:
                    continue
                seen: Set[str] = set()
                stack = [start]
                while stack:
                    cur = stack.pop()
                    if cur in seen:
                        continue
                    seen.add(cur)
                    if cur in b:
                        return True
                    stack.extend((adj.get(cur) or set()) - seen)
            return False

        def _has_lateral(stages: Sequence[Mapping[str, Any]]) -> bool:
            return "lateral_auth" in _stage_names(stages)

        def _refuse_merge(
            hosts: Set[str],
            stages: List[Dict[str, Any]],
            t0: Optional[datetime],
            t1: Optional[datetime],
            mhosts: Set[str],
            mstages: List[Dict[str, Any]],
            mt0: Optional[datetime],
            mt1: Optional[datetime],
            *,
            allow_same_user_resume: bool,
            time_window: float,
            sleeper_mode: bool = False,
        ) -> bool:
            """Return True if this absorb should be refused (Slice B hard split)."""
            overlap = hosts & mhosts
            ua, ub = _stage_user(stages), _stage_user(mstages)
            same_user = bool(ua and ub and ua == ub)
            shape_gap = float(self.config.window_seconds)
            gap = _quiet_gap_seconds((t0, t1), (mt0, mt1))

            # Gap + different stage sets → hard split even at 100% host overlap.
            # Exception: same-user resume (sleeper) may re-link across a quiet gap
            # even when one side has not yet attached exfil (fleet09 / lim03).
            if (
                self.config.force_split_on_shape_gap
                and gap >= shape_gap
                and _stage_names(stages) != _stage_names(mstages)
                and not (same_user and (allow_same_user_resume or sleeper_mode))
            ):
                return True

            # Exfil-only mega-camp glue: refuse expanding pure egress into another
            # cluster unless lateral co-evidence exists on at least one side.
            if self.config.exfil_merge_requires_lateral:
                na, nb = _stage_names(stages), _stage_names(mstages)
                eg = {"micro_exfil", "dns_beacon"}
                if (na <= eg and nb <= eg) and not (
                    _has_lateral(stages) or _has_lateral(mstages)
                ):
                    # Shared dst alone still OK for same needle; refuse host-union grow
                    # when neither side has lateral (CDN flood swallowing needle).
                    if not _shared_exfil_dst(stages, mstages):
                        return True
                    if not (hosts <= mhosts or mhosts <= hosts):
                        return True

            # Hub bridge: high-degree overlap may attach subset egress to a lateral,
            # but must not expand through a hub into another operator's hosts.
            # Exceptions: shared exfil dst, or handoff where the other side already
            # has micro_exfil on the overlap host (fleet16 dual-user bridge).
            if overlap and any(_degree(h) >= hub_bar for h in overlap):
                na, nb = _stage_names(stages), _stage_names(mstages)
                if "lateral_auth" in (na | nb) and not same_user:
                    if not (hosts <= mhosts or mhosts <= hosts):
                        if _shared_exfil_dst(stages, mstages):
                            pass
                        else:

                            def _exfil_hosts(sts: Sequence[Mapping[str, Any]]) -> Set[str]:
                                hs: Set[str] = set()
                                for st in sts:
                                    if str(st.get("name") or "") == "micro_exfil":
                                        hs |= {str(x) for x in (st.get("hosts") or [])}
                                return hs

                            ea, eb = _exfil_hosts(stages), _exfil_hosts(mstages)
                            handoff = bool(overlap & (ea | eb)) and (
                                ("lateral_auth" in na and bool(eb))
                                or ("lateral_auth" in nb and bool(ea))
                            )
                            if not handoff:
                                return True

            # Different lateral users: host overlap alone is not enough —
            # require cross-key (lateral↔exfil/dns) bridge (fleet16 dual-user).
            if ua and ub and ua != ub:
                if not _cross_key_present(stages, mstages):
                    # Still allow classic single-host cross-key jump (auth↔exfil)
                    if not (
                        overlap
                        and _single_host_bridge_ok(hosts, stages, mhosts, mstages)
                    ):
                        return True
                # Two distinct laterals + no egress on either side → refuse
                na, nb = _stage_names(stages), _stage_names(mstages)
                if "lateral_auth" in na and "lateral_auth" in nb:
                    if not ((na | nb) & {"micro_exfil", "dns_beacon"}):
                        return True

            # Same-user resume: require host overlap OR hop path between clusters.
            # Disjoint svc-sql chains must not glue (shared_svc_two_campaigns).
            if not overlap and allow_same_user_resume and same_user:
                if _user_hop_links(ua, hosts, mhosts):
                    return False
                return True
            # Day-scale sleeper: hop- or overlap-linked extension only — never
            # re-glue an identical host-set re-run (48h sequential reuse).
            if sleeper_mode and same_user:
                if hosts == mhosts:
                    return True
                if overlap or _user_hop_links(ua, hosts, mhosts):
                    return False
                return True
            return False

        def _merge_pass(
            items: List[
                Tuple[str, Set[str], List[Dict[str, Any]], Optional[datetime], Optional[datetime]]
            ],
            *,
            time_window: float,
            allow_same_user_resume: bool,
            sleeper_mode: bool = False,
        ) -> List[
            Tuple[str, Set[str], List[Dict[str, Any]], Optional[datetime], Optional[datetime]]
        ]:
            merged = [
                (cid, set(hosts), list(stages), t0, t1)
                for cid, hosts, stages, t0, t1 in items
            ]
            changed = True
            while changed:
                changed = False
                out_m: List[
                    Tuple[
                        str,
                        Set[str],
                        List[Dict[str, Any]],
                        Optional[datetime],
                        Optional[datetime],
                    ]
                ] = []
                for cid, hosts, stages, t0, t1 in merged:
                    absorbed = False
                    for i, (mcid, mhosts, mstages, mt0, mt1) in enumerate(out_m):
                        if not _ranges_overlap((t0, t1), (mt0, mt1), time_window):
                            continue
                        overlap = hosts & mhosts
                        same_user = False
                        if allow_same_user_resume or sleeper_mode:
                            ua, ub = _stage_user(stages), _stage_user(mstages)
                            same_user = bool(ua and ub and ua == ub)
                        if not overlap and not same_user:
                            continue
                        if _refuse_merge(
                            hosts,
                            stages,
                            t0,
                            t1,
                            mhosts,
                            mstages,
                            mt0,
                            mt1,
                            allow_same_user_resume=allow_same_user_resume,
                            time_window=time_window,
                            sleeper_mode=sleeper_mode,
                        ):
                            continue
                        if overlap and not same_user:
                            if not _single_host_bridge_ok(hosts, stages, mhosts, mstages):
                                continue
                        mhosts |= hosts
                        for st in stages:
                            if st not in mstages:
                                mstages.append(st)
                        nt0 = (
                            min(x for x in (mt0, t0) if x is not None)
                            if (mt0 or t0)
                            else None
                        )
                        nt1 = (
                            max(x for x in (mt1, t1) if x is not None)
                            if (mt1 or t1)
                            else None
                        )
                        out_m[i] = (mcid, mhosts, mstages, nt0, nt1)
                        absorbed = True
                        changed = True
                        break
                    if not absorbed:
                        out_m.append((cid, set(hosts), list(stages), t0, t1))
                merged = out_m
            return merged

        merged = _merge_pass(clusters, time_window=window, allow_same_user_resume=False)
        merged = _merge_pass(merged, time_window=resume, allow_same_user_resume=True)
        # Day-scale sleeper: hop-linked same-user only (does not widen resume_window).
        if sleeper > resume:
            merged = _merge_pass(
                merged,
                time_window=sleeper,
                allow_same_user_resume=False,
                sleeper_mode=True,
            )

        out: List[Campaign] = []
        for cid, hosts, stages, _t0, _t1 in merged:
            if len(hosts) < self.config.min_hosts:
                continue
            evidence = []
            for s in signals:
                if s.host_id in hosts:
                    evidence.append(
                        {"kind": s.kind, "host_id": s.host_id, "attrs": s.attrs}
                    )
            out.append(
                Campaign(
                    campaign_id=cid,
                    host_ids=sorted(hosts),
                    stages=stages,
                    evidence=evidence,
                    score=min(1.0, 0.4 + 0.2 * len(hosts) + 0.1 * len(stages)),
                )
            )
        return out
