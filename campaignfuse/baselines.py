"""Baselines B1 (per-host) and B2 (competitive SIEM joins)."""

from __future__ import annotations

from collections import defaultdict
from typing import Any, Dict, List, Mapping, Sequence

from campaignfuse.store import Campaign


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
