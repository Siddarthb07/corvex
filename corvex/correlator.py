"""Single-writer correlator — imports EventBus protocol only for ingest typing."""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence, Set, Tuple

from corvex.audit import AuditLog
from corvex.detectors import Signal, run_all
from corvex.envelope import EventEnvelope
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
    min_hosts: int = 2
    cross_host_enabled: bool = True  # ablation toggle


class Correlator:
    """Owns CampaignStore writes. Dedups on event_id before mutate."""

    def __init__(
        self,
        store: CampaignStore,
        audit: AuditLog,
        config: Optional[CorrelatorConfig] = None,
        detector_only: bool = False,
    ):
        self.store = store
        self.audit = audit
        self.config = config or CorrelatorConfig()
        self.detector_only = detector_only
        self._seen: Set[str] = set()
        self._events: List[Dict[str, Any]] = []

    def ingest(self, envelopes: Iterable[EventEnvelope]) -> None:
        for env in envelopes:
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
        - single-host merge only when the bridge is cross-key (auth↔exfil);
          two laterals sharing a jumpbox do not glue
        """
        window = float(self.config.window_seconds)
        user_timed: Dict[str, List[Tuple[datetime, str]]] = defaultdict(list)
        exfil_timed: Dict[str, List[Tuple[datetime, str]]] = defaultdict(list)
        recon_hosts: Set[str] = set()
        all_hosts_in_events: Set[str] = set()

        for ev in events:
            host = str(ev["host_id"])
            all_hosts_in_events.add(host)
            ts = _event_ts(ev)
            ptype = ev.get("payload_type")
            payload = ev.get("payload", {})
            if ptype == "auth":
                user = str(payload.get("user", ""))
                if user and ts is not None:
                    user_timed[user].append((ts, host))
            if ptype == "net_conn" and payload.get("egress"):
                dst = str(payload.get("dst_ip", ""))
                nbytes = int(payload.get("bytes", 0))
                if dst and 0 < nbytes <= 50_000 and ts is not None:
                    exfil_timed[dst].append((ts, host))

        for s in signals:
            if s.kind == "recon_fanout":
                recon_hosts.add(s.host_id)

        # Clusters carry (cid, hosts, stages, t_min, t_max)
        clusters: List[Tuple[str, Set[str], List[Dict[str, Any]], Optional[datetime], Optional[datetime]]] = []
        part = 0

        for user, timed in user_timed.items():
            for group in _connected_host_components(timed, window):
                hosts = {h for _, h in group}
                if len(hosts) < self.config.min_hosts:
                    continue
                times = [t for t, _ in group]
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

        fleet_n = max(1, len(all_hosts_in_events))
        # If a dst was ever fleet-wide in this run, treat it as poisoned SaaS/CDN —
        # later 2-host slices of the same dst must not become stitch keys either.
        poisoned_dst: Set[str] = set()
        for dst, timed in exfil_timed.items():
            for group in _connected_host_components(timed, window):
                hosts = {h for _, h in group}
                if len(hosts) >= max(4, fleet_n - 1):
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

        # Recon co-occurrence: only fold recon hosts that appear in-window with cluster
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

        def _single_host_bridge_ok(
            hosts_a: Set[str],
            stages_a: Sequence[Mapping[str, Any]],
            hosts_b: Set[str],
            stages_b: Sequence[Mapping[str, Any]],
        ) -> bool:
            """Allow 1-host glue only when the bridge is cross-key (auth↔exfil).

            Jumpbox failure mode: two lateral users share a host with no exfil
            key on that host. fusion_chain needs auth↔exfil bridges on one host.
            """
            overlap = hosts_a & hosts_b
            if len(overlap) >= 2:
                return True
            if len(overlap) != 1:
                return False
            h = next(iter(overlap))
            a_lat = _host_in_stages(stages_a, h, {"lateral_auth"})
            b_lat = _host_in_stages(stages_b, h, {"lateral_auth"})
            a_ex = _host_in_stages(stages_a, h, {"micro_exfil"})
            b_ex = _host_in_stages(stages_b, h, {"micro_exfil"})
            return (a_lat and b_ex) or (b_lat and a_ex)

        # Time-aware merge. Single-host bridges only when cross-key (auth↔exfil).
        merged: List[Tuple[str, Set[str], List[Dict[str, Any]], Optional[datetime], Optional[datetime]]] = [
            (cid, set(hosts), list(stages), t0, t1) for cid, hosts, stages, t0, t1 in clusters
        ]
        changed = True
        while changed:
            changed = False
            out_m: List[
                Tuple[str, Set[str], List[Dict[str, Any]], Optional[datetime], Optional[datetime]]
            ] = []
            for cid, hosts, stages, t0, t1 in merged:
                absorbed = False
                for i, (mcid, mhosts, mstages, mt0, mt1) in enumerate(out_m):
                    overlap = hosts & mhosts
                    if not overlap:
                        continue
                    if not _ranges_overlap((t0, t1), (mt0, mt1), window):
                        continue
                    if not _single_host_bridge_ok(hosts, stages, mhosts, mstages):
                        continue
                    mhosts |= hosts
                    for st in stages:
                        if st not in mstages:
                            mstages.append(st)
                    nt0 = min(x for x in (mt0, t0) if x is not None) if (mt0 or t0) else None
                    nt1 = max(x for x in (mt1, t1) if x is not None) if (mt1 or t1) else None
                    out_m[i] = (mcid, mhosts, mstages, nt0, nt1)
                    absorbed = True
                    changed = True
                    break
                if not absorbed:
                    out_m.append((cid, set(hosts), list(stages), t0, t1))
            merged = out_m

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
