"""Single-writer correlator — imports EventBus protocol only for ingest typing."""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence, Set, Tuple

from corvex.audit import AuditLog
from corvex.auth import AuthError, Enrollment
from corvex.detectors import Signal, run_all
from corvex.envelope import EventEnvelope, verify_envelope
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
    min_hosts: int = 2
    cross_host_enabled: bool = True  # ablation toggle
    # Shape/gap hard split: defaults derived from window_seconds (no retune dial).
    # When True, refuse merges across a quiet gap >= window when stage sets differ.
    force_split_on_shape_gap: bool = True
    # Hub degree bridge bar: None → max(2, fleet_n // 2). High-degree overlap
    # cannot expand into another operator's hosts (lim09 / lim02), with handoff exceptions.
    hub_degree_bar: Optional[int] = None


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
            self._events.append(env.to_dict())
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
        user_timed: Dict[str, List[Tuple[datetime, str]]] = defaultdict(list)
        user_hops: Dict[str, List[Tuple[str, str]]] = defaultdict(list)
        exfil_timed: Dict[str, List[Tuple[datetime, str]]] = defaultdict(list)
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
                    if src.startswith("host-") and src != host:
                        user_timed[user].append((ts, src))
                        user_hops[user].append((src, host))
                        all_hosts_in_events.add(src)
            if ptype == "net_conn" and payload.get("egress"):
                dst = str(payload.get("dst_ip", ""))
                nbytes = int(payload.get("bytes", 0))
                if dst and 0 < nbytes <= 50_000 and ts is not None:
                    exfil_timed[dst].append((ts, host))
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
            hop_hosts = _hop_reachable(user_hops.get(user) or [])
            for group in _connected_host_components(timed, window):
                hosts = {h for _, h in group}
                if len(hosts) < self.config.min_hosts:
                    continue
                if len(hosts) >= fanout_bar:
                    chained = hosts & hop_hosts
                    if len(chained) >= self.config.min_hosts:
                        hosts = chained
                    else:
                        continue
                times = [t for t, h in group if h in hosts]
                if len(hosts) < self.config.min_hosts:
                    continue
                part += 1
                clusters.append(
                    (
                        f"camp-lateral-{user}-{part}",
                        set(hosts),
                        [{"name": "lateral_auth", "user": user, "hosts": sorted(hosts)}],
                        min(times) if times else None,
                        max(times) if times else None,
                    )
                )

        poisoned_dst: Set[str] = set()
        for dst, timed in exfil_timed.items():
            for group in _connected_host_components(timed, window):
                hosts = {h for _, h in group}
                if len(hosts) >= fanout_bar:
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

        if recon_hosts:
            for i, (cid, hosts, stages, t0, t1) in enumerate(list(clusters)):
                if hosts & recon_hosts:
                    stages = list(stages)
                    stages.insert(0, {"name": "recon_fanout", "hosts": sorted(hosts & recon_hosts)})
                    hosts = set(hosts) | recon_hosts
                    clusters[i] = (cid, hosts, stages, t0, t1)

        if len(recon_hosts) >= self.config.min_hosts:
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

        def _single_host_bridge_ok(
            hosts_a: Set[str],
            stages_a: Sequence[Mapping[str, Any]],
            hosts_b: Set[str],
            stages_b: Sequence[Mapping[str, Any]],
        ) -> bool:
            overlap = hosts_a & hosts_b
            if len(overlap) >= 2:
                return True
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
                return out

            return bool(_dsts(stages_a) & _dsts(stages_b))

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
                and not same_user
            ):
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

            # Resume pass: same-user glue without overlap is OK; otherwise
            # fall through to existing bridge checks in caller.
            if not overlap and allow_same_user_resume and same_user:
                return False
            return False

        def _merge_pass(
            items: List[
                Tuple[str, Set[str], List[Dict[str, Any]], Optional[datetime], Optional[datetime]]
            ],
            *,
            time_window: float,
            allow_same_user_resume: bool,
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
                        if allow_same_user_resume:
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
