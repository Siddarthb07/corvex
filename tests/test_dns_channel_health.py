"""Windows DNS channel_health honesty (Sysmon EID 22 / GAP)."""

from __future__ import annotations

from pathlib import Path

from corvex.correlator import load_host_aliases
from corvex.sensors.windows_os import _annotate_windows_dns_health


def test_dns_health_gap_when_sysmon_not_requested() -> None:
    stats: dict = {"channel_health": {}, "channels": {}, "degraded": []}
    _annotate_windows_dns_health(stats, ["security", "firewall"])
    dns = stats["channel_health"]["dns"]
    assert dns["ok"] is False
    assert dns["reason"] == "sysmon_channel_not_requested"
    assert "dns" in stats["degraded"]


def test_dns_health_ok_when_eid22_adapted() -> None:
    stats: dict = {
        "channel_health": {"sysmon": {"ok": True, "reason": None, "hits": 3}},
        "channels": {"sysmon": 3, "dns": 2},
        "degraded": [],
    }
    _annotate_windows_dns_health(stats, ["security", "sysmon"])
    dns = stats["channel_health"]["dns"]
    assert dns["ok"] is True
    assert dns["reason"] == "sysmon_eid22"
    assert dns["hits"] == 2
    assert "dns" not in stats["degraded"]


def test_dns_health_gap_when_sysmon_missing() -> None:
    stats: dict = {
        "channel_health": {
            "sysmon": {"ok": False, "reason": "channel_missing", "hits": 0}
        },
        "channels": {},
        "degraded": ["sysmon"],
    }
    _annotate_windows_dns_health(stats, ["sysmon"])
    dns = stats["channel_health"]["dns"]
    assert dns["ok"] is False
    assert dns["reason"] == "channel_missing"
    assert "dns" in stats["degraded"]


def test_load_host_aliases_roundtrip(tmp_path: Path) -> None:
    p = tmp_path / "host_aliases.json"
    p.write_text('{"host-b-dhcp": "host-b"}\n', encoding="utf-8")
    assert load_host_aliases(p) == {"host-b-dhcp": "host-b"}
    assert load_host_aliases(tmp_path / "missing.json") is None
