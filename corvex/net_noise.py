"""Ambient / infrastructure destinations that must not drive fusion or quarantine.

Shared by detectors and correlator so ablation stays fair: detector_only no longer
gets free multi-host coverage from cloud metadata / link-local / loopback noise.
"""

from __future__ import annotations

from typing import FrozenSet

# Exact dsts seen flooding OTRF APT29/APT3 Sysmon+firewall captures.
AMBIENT_EXFIL_DST: FrozenSet[str] = frozenset(
    {
        "169.254.169.254",  # cloud instance metadata
        "168.63.129.16",  # Azure wire server
        "127.0.0.1",
        "::1",
        "0.0.0.0",
        "::",
    }
)


def is_ambient_dst(dst: str) -> bool:
    """True for link-local, loopback, and well-known cloud metadata endpoints."""
    s = (dst or "").strip().lower()
    if not s or s in AMBIENT_EXFIL_DST:
        return True if s else False
    if s in {x.lower() for x in AMBIENT_EXFIL_DST}:
        return True
    # IPv4 link-local
    if s.startswith("169.254."):
        return True
    # IPv6 link-local / ULA noise often shows up in lab captures
    if s.startswith("fe80:") or s.startswith("ff00:"):
        return True
    return False


def looks_like_ip(s: str) -> bool:
    parts = s.split(".")
    if len(parts) == 4 and all(p.isdigit() for p in parts):
        return True
    return ":" in s


def is_fleet_peer(src: str, host: str, fleet: set[str]) -> bool:
    """True when auth ``src`` names another enrolled / observed fleet host.

    Accepts lab ``host-*`` ids, short Windows names present in the fleet
    (case-insensitive), provisional short hostnames (appear as WorkstationName
    before any event on that host), and rejects raw IPs / empty / self.
    """
    if not src or src == host:
        return False
    if looks_like_ip(src):
        return False
    if src.startswith("host-"):
        return True
    if src in fleet:
        return True
    low = {h.lower() for h in fleet}
    if src.lower() in low:
        return True
    # Provisional Windows NETBIOS-ish name (may precede host_id sighting).
    if "." not in src and all(c.isalnum() or c in "-_" for c in src):
        return True
    return False


def canon_fleet_peer(src: str, fleet: set[str]) -> str:
    """Return canonical fleet host_id for ``src`` (preserve case from fleet)."""
    if src in fleet:
        return src
    low = {h.lower(): h for h in fleet}
    return low.get(src.lower(), src)
