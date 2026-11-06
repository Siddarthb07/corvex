"""Baselines B1 (per-host), B2 (competitive SIEM joins), B3 (window+entity)."""

from __future__ import annotations

from collections import defaultdict
from datetime import datetime, timezone
from typing import Any, Dict, List, Mapping, Optional, Sequence, Set, Tuple

from corvex.store import Campaign


def _parse_ts(raw: Any) -> Optional[datetime]:
    if raw is None:
        return None
    s = str(raw).strip()
    if not s:
        return None
    if s.endswith("Z"):
        s = s[:-1] + "+00:00"
    try:
        dt = datetime.fromisoformat(s)
    except ValueError:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def baseline_b1(events: Sequence[Mapping[str, Any]]) -> List[Campaign]:
    """Per-host thresholds only — no cross-host join."""
    net_by_host: Dict[str, int] = defaultdict(int)
    auth_by_host: Dict[str, int] = defaultdict(int)
    for ev in events:
        host = str(ev["host_id"])
        if ev.get("payload_type") == "net_conn":
            net_by_host[host] += 1
        if ev.get("payload_type") == "auth":
            auth_by_host[host] += 1
    out: List[Campaign] = []
    for host, n in net_by_host.items():
        if n >= 8:
            out.append(
                Campaign(
                    campaign_id=f"b1-{host}",
                    host_ids=[host],
                    stages=[{"name": "per_host_net_threshold", "hosts": [host]}],
                    evidence=[{"host_id": host, "net_conn": n}],
                    score=0.5,
                )
            )
    for host, n in auth_by_host.items():
        if n >= 3:
            out.append(
                Campaign(
                    campaign_id=f"b1-auth-{host}",
                    host_ids=[host],
                    stages=[{"name": "per_host_auth_threshold", "hosts": [host]}],
                    evidence=[{"host_id": host, "auth": n}],
                    score=0.4,
                )
            )
    return out


def baseline_b2(events: Sequence[Mapping[str, Any]]) -> List[Campaign]:
    """
    Competitive SIEM-style joins (documented parity):
    - same user across >=2 hosts (lateral)
    - dst fan-out >=5 on a host plus peer host with same user
    - shared egress dst across >=2 hosts with small bytes (micro-exfil)
    """
    user_hosts: Dict[str, set] = defaultdict(set)
    host_dsts: Dict[str, set] = defaultdict(set)
    egress_dst_hosts: Dict[str, set] = defaultdict(set)

    for ev in events:
        host = str(ev["host_id"])
        payload = ev.get("payload", {})
        ptype = ev.get("payload_type")
        if ptype == "auth":
            user = str(payload.get("user", ""))
            if user:
                user_hosts[user].add(host)
        if ptype == "net_conn":
            dst = str(payload.get("dst_ip", ""))
            if dst:
                host_dsts[host].add(dst)
            if payload.get("egress"):
                nbytes = int(payload.get("bytes", 0))
                if dst and 0 < nbytes <= 50_000:
                    egress_dst_hosts[dst].add(host)

    out: List[Campaign] = []

    for user, hosts in user_hosts.items():
        if len(hosts) >= 2:
            stages = [{"name": "lateral_auth", "user": user, "hosts": sorted(hosts)}]
            recon = [h for h in hosts if len(host_dsts.get(h, ())) >= 5]
            if recon:
                stages.insert(0, {"name": "recon_fanout", "hosts": recon})
            out.append(
                Campaign(
                    campaign_id=f"b2-user-{user}",
                    host_ids=sorted(hosts),
                    stages=stages,
                    evidence=[{"rule": "same_user_multi_host", "user": user}],
                    score=0.7,
                )
            )

    for dst, hosts in egress_dst_hosts.items():
        if len(hosts) >= 2:
            out.append(
                Campaign(
                    campaign_id=f"b2-exfil-{dst.replace('.', '-')}",
                    host_ids=sorted(hosts),
                    stages=[{"name": "micro_exfil", "dst_ip": dst, "hosts": sorted(hosts)}],
                    evidence=[{"rule": "shared_egress_dst", "dst_ip": dst}],
                    score=0.65,
                )
            )

    return out


class _UF:
    def __init__(self) -> None:
        self.p: Dict[str, str] = {}

    def find(self, x: str) -> str:
        self.p.setdefault(x, x)
        while self.p[x] != x:
            self.p[x] = self.p[self.p[x]]
            x = self.p[x]
        return x

    def union(self, a: str, b: str) -> None:
        ra, rb = self.find(a), self.find(b)
        if ra != rb:
            self.p[rb] = ra


def baseline_window_entity(
    events: Sequence[Mapping[str, Any]],
    *,
    window_seconds: float = 600.0,
) -> List[Campaign]:
    """Time-window + shared-entity clustering (non-Corvex correlator baseline).

    Union hosts that share a user, auth src peer, or egress dst inside a sliding
    ``window_seconds`` gap. No hop-graph anti-jumpbox / ambient-poison logic —
    this is the simple clustering arm reviewers ask for beside detector-only.
    """
    rows: List[Tuple[datetime, str, str]] = []
    for ev in events:
        host = str(ev.get("host_id") or "")
        if not host:
            continue
        ts = _parse_ts(ev.get("ts_utc"))
        if ts is None:
            continue
        payload = ev.get("payload") or {}
        ptype = str(ev.get("payload_type") or "")
        entities: Set[str] = set()
        if ptype == "auth":
            user = str(payload.get("user") or "")
            if user:
                entities.add(f"user:{user}")
            src = str(payload.get("src") or "")
            if src:
                entities.add(f"src:{src}")
        elif ptype == "net_conn" and payload.get("egress"):
            dst = str(payload.get("dst_ip") or payload.get("dst") or "")
            if dst:
                entities.add(f"egress:{dst}")
        elif ptype == "dns":
            q = str(payload.get("query") or payload.get("qname") or "")
            if q:
                entities.add(f"dns:{q.lower()}")
        for ent in entities:
            rows.append((ts, host, ent))

    rows.sort(key=lambda r: r[0])
    uf = _UF()
    # entity -> list of (ts, host) recently seen
    recent: Dict[str, List[Tuple[datetime, str]]] = defaultdict(list)
    for ts, host, ent in rows:
        bucket = recent[ent]
        # drop stale
        keep: List[Tuple[datetime, str]] = []
        for pts, ph in bucket:
            if (ts - pts).total_seconds() <= window_seconds:
                keep.append((pts, ph))
                if ph != host:
                    uf.union(host, ph)
        keep.append((ts, host))
        recent[ent] = keep
        uf.find(host)

    comps: Dict[str, Set[str]] = defaultdict(set)
    for host in list(uf.p.keys()):
        comps[uf.find(host)].add(host)

    out: List[Campaign] = []
    for i, hosts in enumerate(sorted(comps.values(), key=lambda s: (-len(s), sorted(s)))):
        if len(hosts) < 2:
            continue
        hs = sorted(hosts)
        out.append(
            Campaign(
                campaign_id=f"b3-window-{i}",
                host_ids=hs,
                stages=[{"name": "window_entity_cluster", "hosts": hs}],
                evidence=[{"rule": "time_window_shared_entity", "window_seconds": window_seconds}],
                score=0.55,
            )
        )
    return out


# Alias used in CLI / raise harness
baseline_b3 = baseline_window_entity
