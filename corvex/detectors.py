"""Pure detector functions — no I/O, no time, no random. CI enforces this."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, List, Mapping, Sequence, Set

from corvex.net_noise import is_ambient_dst


@dataclass(frozen=True)
class Signal:
    kind: str
    host_id: str
    weight: float
    attrs: Dict[str, Any]


def _events(window: Sequence[Mapping[str, Any]]) -> List[Mapping[str, Any]]:
    return list(window)


def _fleet_hosts(window: Sequence[Mapping[str, Any]]) -> Set[str]:
    return {str(ev["host_id"]) for ev in _events(window) if ev.get("host_id") is not None}


def detect_recon_fanout(window: Sequence[Mapping[str, Any]]) -> List[Signal]:
    """Flag hosts that connect to many distinct destinations (scan-like)."""
    by_host: Dict[str, set] = {}
    for ev in _events(window):
        if ev.get("payload_type") != "net_conn":
            continue
        host = str(ev["host_id"])
        dst = str(ev.get("payload", {}).get("dst_ip", ""))
        if not dst or is_ambient_dst(dst):
            continue
        by_host.setdefault(host, set()).add(dst)
    out: List[Signal] = []
    for host, dsts in by_host.items():
        if len(dsts) >= 5:
            out.append(
                Signal(
                    kind="recon_fanout",
                    host_id=host,
                    weight=min(1.0, len(dsts) / 10.0),
                    attrs={"dst_count": len(dsts)},
                )
            )
    return out


def detect_lateral_auth(window: Sequence[Mapping[str, Any]]) -> List[Signal]:
    """Same user authenticating on multiple hosts.

    Computer accounts (``*$``) alone are weak multi-host signal on domain fleets —
    require at least one auth hop (``payload.src`` naming another fleet host) so
    ambient machine-account logons do not saturate the detector bridge.
    """
    fleet = _fleet_hosts(window)
    user_hosts: Dict[str, set] = {}
    user_has_hop: Dict[str, bool] = {}
    for ev in _events(window):
        if ev.get("payload_type") != "auth":
            continue
        user = str(ev.get("payload", {}).get("user", ""))
        if not user:
            continue
        host = str(ev["host_id"])
        user_hosts.setdefault(user, set()).add(host)
        src = str((ev.get("payload") or {}).get("src") or "")
        if src and src != host and (src in fleet or src.startswith("host-")):
            user_has_hop[user] = True
        elif src and src.lower() in {h.lower() for h in fleet} and src.lower() != host.lower():
            user_has_hop[user] = True
    out: List[Signal] = []
    for user, hosts in user_hosts.items():
        if len(hosts) < 2:
            continue
        weak = user.endswith("$") or user.upper() in {
            "SYSTEM",
            "LOCAL SERVICE",
            "NETWORK SERVICE",
            "ANONYMOUS LOGON",
        }
        if weak and not user_has_hop.get(user):
            continue
        for host in hosts:
            out.append(
                Signal(
                    kind="lateral_auth",
                    host_id=host,
                    weight=min(1.0, len(hosts) / 3.0),
                    attrs={"user": user, "host_count": len(hosts)},
                )
            )
    return out


def detect_micro_exfil(window: Sequence[Mapping[str, Any]]) -> List[Signal]:
    """Many small egress bursts across hosts to shared external destination.

    Skips ambient/metadata destinations and fleet-wide fanout (aligned with
    correlator poison) so detector_only cannot claim free full-fleet coverage.
    """
    fleet_n = max(1, len(_fleet_hosts(window)))
    fanout_bar = max(4, fleet_n - 1)
    dst_hosts: Dict[str, set] = {}
    dst_bytes: Dict[str, int] = {}
    for ev in _events(window):
        if ev.get("payload_type") != "net_conn":
            continue
        payload = ev.get("payload", {})
        if not payload.get("egress"):
            continue
        nbytes = int(payload.get("bytes", 0))
        if nbytes <= 0 or nbytes > 50_000:
            continue
        dst = str(payload.get("dst_ip", ""))
        if not dst or is_ambient_dst(dst):
            continue
        host = str(ev["host_id"])
        dst_hosts.setdefault(dst, set()).add(host)
        dst_bytes[dst] = dst_bytes.get(dst, 0) + nbytes
    out: List[Signal] = []
    for dst, hosts in dst_hosts.items():
        if len(hosts) < 2:
            continue
        if len(hosts) >= fanout_bar:
            continue  # ubiquitous shared egress — correlator poisons these too
        for host in hosts:
            out.append(
                Signal(
                    kind="micro_exfil",
                    host_id=host,
                    weight=min(1.0, len(hosts) / 3.0),
                    attrs={"dst_ip": dst, "host_count": len(hosts), "bytes": dst_bytes[dst]},
                )
            )
    return out


def detect_dns_beacon(window: Sequence[Mapping[str, Any]]) -> List[Signal]:
    """Same DNS apex queried from multiple hosts (C2 / OOB channel)."""
    apex_hosts: Dict[str, set] = {}
    for ev in _events(window):
        if ev.get("payload_type") != "dns":
            continue
        query = str(ev.get("payload", {}).get("query") or "")
        parts = [p for p in query.lower().rstrip(".").split(".") if p]
        if len(parts) >= 3:
            apex = ".".join(parts[1:])
        else:
            apex = query.lower().rstrip(".")
        if not apex:
            continue
        apex_hosts.setdefault(apex, set()).add(str(ev["host_id"]))
    out: List[Signal] = []
    for apex, hosts in apex_hosts.items():
        if len(hosts) >= 2:
            for host in hosts:
                out.append(
                    Signal(
                        kind="dns_beacon",
                        host_id=host,
                        weight=min(1.0, len(hosts) / 3.0),
                        attrs={"apex": apex, "host_count": len(hosts)},
                    )
                )
    return out


def run_all(window: Sequence[Mapping[str, Any]]) -> List[Signal]:
    signals: List[Signal] = []
    signals.extend(detect_recon_fanout(window))
    signals.extend(detect_lateral_auth(window))
    signals.extend(detect_micro_exfil(window))
    signals.extend(detect_dns_beacon(window))
    return signals
