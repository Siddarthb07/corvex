"""Single-writer correlator — imports EventBus protocol only for ingest typing."""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence, Set, Tuple

from campaignfuse.audit import AuditLog
from campaignfuse.detectors import Signal, run_all
from campaignfuse.envelope import EventEnvelope
from campaignfuse.store import Campaign, CampaignStore


def _parse_ts(ts: str) -> datetime:
    # Accept ...Z
    if ts.endswith("Z"):
        ts = ts[:-1] + "+00:00"
    return datetime.fromisoformat(ts)


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
        by_kind: Dict[str, List[Signal]] = defaultdict(list)
        for s in signals:
            by_kind[s.kind].append(s)
        out: List[Campaign] = []
        for kind, sigs in by_kind.items():
            hosts = sorted({s.host_id for s in sigs})
            if len(hosts) < self.config.min_hosts and kind != "recon_fanout":
                # recon can be single-host in detector-only mode
                if kind != "recon_fanout":
                    continue
            cid = f"det-{kind}"
            out.append(
                Campaign(
                    campaign_id=cid,
                    host_ids=hosts,
                    stages=[{"name": kind, "hosts": hosts}],
                    evidence=[{"kind": s.kind, "host_id": s.host_id, "attrs": s.attrs} for s in sigs],
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
        """Cross-host fusion: link hosts sharing users, exfil dst, or joint recon+lateral."""
        user_hosts: Dict[str, Set[str]] = defaultdict(set)
        exfil_dst_hosts: Dict[str, Set[str]] = defaultdict(set)
        recon_hosts: Set[str] = set()
        stage_hints: Dict[str, List[str]] = defaultdict(list)

        for ev in events:
            host = str(ev["host_id"])
            ptype = ev.get("payload_type")
            payload = ev.get("payload", {})
            if ptype == "auth":
                user = str(payload.get("user", ""))
                if user:
                    user_hosts[user].add(host)
                    stage_hints[host].append("auth")
            if ptype == "net_conn" and payload.get("egress"):
                dst = str(payload.get("dst_ip", ""))
                nbytes = int(payload.get("bytes", 0))
                if dst and 0 < nbytes <= 50_000:
                    exfil_dst_hosts[dst].add(host)
                    stage_hints[host].append("exfil")
            if ptype == "net_conn":
                stage_hints[host].append("net")

        for s in signals:
            if s.kind == "recon_fanout":
                recon_hosts.add(s.host_id)
                stage_hints[s.host_id].append("recon")
            if s.kind == "lateral_auth":
                stage_hints[s.host_id].append("lateral")
            if s.kind == "micro_exfil":
                stage_hints[s.host_id].append("exfil")

        clusters: List[Tuple[str, Set[str], List[Dict[str, Any]]]] = []

        for user, hosts in user_hosts.items():
            if len(hosts) >= self.config.min_hosts:
                clusters.append(
                    (
                        f"camp-lateral-{user}",
                        set(hosts),
                        [{"name": "lateral_auth", "user": user, "hosts": sorted(hosts)}],
                    )
                )

        for dst, hosts in exfil_dst_hosts.items():
            if len(hosts) >= self.config.min_hosts:
                clusters.append(
                    (
                        f"camp-exfil-{dst.replace('.', '-')}",
                        set(hosts),
                        [{"name": "micro_exfil", "dst_ip": dst, "hosts": sorted(hosts)}],
                    )
                )

        # Recon fanout that co-occurs with lateral/exfil on overlapping hosts → merge
        if recon_hosts:
            for cid, hosts, stages in list(clusters):
                if hosts & recon_hosts:
                    stages.insert(0, {"name": "recon_fanout", "hosts": sorted(hosts & recon_hosts)})
                    hosts |= recon_hosts

        # If recon-only multi-host pattern: multiple hosts scanning
        if len(recon_hosts) >= self.config.min_hosts:
            clusters.append(
                (
                    "camp-recon-multi",
                    set(recon_hosts),
                    [{"name": "recon_fanout", "hosts": sorted(recon_hosts)}],
                )
            )

        # Merge overlapping clusters
        merged: List[Tuple[str, Set[str], List[Dict[str, Any]]]] = []
        for cid, hosts, stages in clusters:
            absorbed = False
            for i, (mcid, mhosts, mstages) in enumerate(merged):
                if hosts & mhosts:
                    mhosts |= hosts
                    # keep stable id from first
                    for st in stages:
                        if st not in mstages:
                            mstages.append(st)
                    absorbed = True
                    break
            if not absorbed:
                merged.append((cid, set(hosts), list(stages)))

        out: List[Campaign] = []
        for cid, hosts, stages in merged:
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
