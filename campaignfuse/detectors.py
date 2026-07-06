"""Pure detector functions — no I/O, no time, no random. CI enforces this."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, List, Mapping, Sequence


@dataclass(frozen=True)
class Signal:
    kind: str
    host_id: str
    weight: float
    attrs: Dict[str, Any]


def _events(window: Sequence[Mapping[str, Any]]) -> List[Mapping[str, Any]]:
    return list(window)


def detect_recon_fanout(window: Sequence[Mapping[str, Any]]) -> List[Signal]:
    """Flag hosts that connect to many distinct destinations (scan-like)."""
    by_host: Dict[str, set] = {}
    for ev in _events(window):
        if ev.get("payload_type") != "net_conn":
            continue
        host = str(ev["host_id"])
        dst = str(ev.get("payload", {}).get("dst_ip", ""))
        if not dst:
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
    """Same user authenticating on multiple hosts."""
    user_hosts: Dict[str, set] = {}
    for ev in _events(window):
        if ev.get("payload_type") != "auth":
            continue
        user = str(ev.get("payload", {}).get("user", ""))
        if not user:
            continue
        user_hosts.setdefault(user, set()).add(str(ev["host_id"]))
    out: List[Signal] = []
    for user, hosts in user_hosts.items():
        if len(hosts) >= 2:
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
    """Many small egress bursts across hosts to shared external destination."""
    # (dst_ip) -> set of hosts with small egress
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
        if not dst:
            continue
        host = str(ev["host_id"])
        dst_hosts.setdefault(dst, set()).add(host)
        dst_bytes[dst] = dst_bytes.get(dst, 0) + nbytes
    out: List[Signal] = []
    for dst, hosts in dst_hosts.items():
        if len(hosts) >= 2:
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


def run_all(window: Sequence[Mapping[str, Any]]) -> List[Signal]:
    signals: List[Signal] = []
    signals.extend(detect_recon_fanout(window))
    signals.extend(detect_lateral_auth(window))
    signals.extend(detect_micro_exfil(window))
    return signals
