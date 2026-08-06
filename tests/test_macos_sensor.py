"""Stage B macOS network-wide sensor tests."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from corvex.adapters.macos import (
    adapt_macos_export,
    load_macos_allowlist,
    parse_lsof_network,
)
from corvex.lab_enroll import ensure_lab_enrollment
from corvex.sensors.macos_os import run_sensor_macos
from corvex.stage_b import write_lab_override

ROOT = Path(__file__).resolve().parents[1]
FIXTURE = ROOT / "fixtures" / "os_wide_macos" / "multi_channel.jsonl"
ALLOW = ROOT / "fixtures" / "os_wide_macos" / "channels.json"
HOST_MAP = {
    "host-mac-a.local": "host-a",
    "host-mac-b.local": "host-b",
    "host-mac-c.local": "host-c",
    "host-mac-d.local": "host-d",
}


def _lab_unlock(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.delenv("CORVEX_STAGE_B", raising=False)
    monkeypatch.delenv("CFUSE_STAGE_B", raising=False)
    monkeypatch.chdir(tmp_path)
    reports = tmp_path / "reports"
    reports.mkdir(exist_ok=True)
    write_lab_override(reports, reason="pytest macos fixture unlock")


def test_adapt_macos_skips_unknown_kinds():
    envs, stats = adapt_macos_export(
        FIXTURE,
        host_map=HOST_MAP,
        allowlist=load_macos_allowlist(ALLOW),
    )
    assert stats["adapted"] >= 8
    assert stats["skipped"] >= 1  # udp_noise not allowlisted
    types = {e["payload_type"] for e in envs}
    assert "auth" in types
    assert "net_conn" in types
    assert "dns" in types


def test_parse_lsof_network_skips_loopback():
    sample = """
COMMAND   PID USER   FD   TYPE DEVICE SIZE/OFF NODE NAME
curl     1001 me    5u  IPv4 0x1      0t0  TCP 10.0.0.2:5555->198.51.100.40:443 (ESTABLISHED)
helper   1002 me    6u  IPv4 0x2      0t0  TCP 127.0.0.1:49177->127.0.0.1:49227 (ESTABLISHED)
"""
    recs = parse_lsof_network(sample)
    assert len(recs) == 1
    assert recs[0]["dst_ip"] == "198.51.100.40"
    assert recs[0]["dst_port"] == 443
    assert recs[0]["EventID"] == "tcp_established"


def test_sensor_macos_fixture_once(tmp_path: Path, monkeypatch):
    _lab_unlock(tmp_path, monkeypatch)
    enr = ensure_lab_enrollment(tmp_path / "enrollment.json")
    run = tmp_path / "runs" / "os-wide-macos"
    stats = run_sensor_macos(
        run_dir=run,
        enrollment=enr,
        channels=["auth", "net", "dns", "process", "pf"],
        allowlist_path=ALLOW,
        fixture=FIXTURE,
        host_map=HOST_MAP,
        once=True,
        follow=False,
        max_per_sec=100,
    )
    assert stats["published"] >= 5
    assert (run / "events.jsonl").exists()
    assert (run / "timeline.json").exists()
    tl = json.loads((run / "timeline.json").read_text(encoding="utf-8"))
    assert tl.get("sensor") == "macos-os-wide+network"
    status = json.loads((run / "sensor_status.json").read_text(encoding="utf-8"))
    blob = json.dumps(status)
    assert "/Users/" not in blob


def test_macos_multihost_exporter_shape(tmp_path: Path, monkeypatch):
    _lab_unlock(tmp_path, monkeypatch)
    enr = ensure_lab_enrollment(tmp_path / "enrollment.json")
    run = tmp_path / "runs" / "fleet-mac"
    run_sensor_macos(
        run_dir=run,
        enrollment=enr,
        channels=["auth", "net"],
        allowlist_path=ALLOW,
        fixture=FIXTURE,
        host_id="host-a",
        producer_id="prod-a",
        host_map=HOST_MAP,
        once=True,
        follow=False,
    )
    run_sensor_macos(
        run_dir=run,
        enrollment=enr,
        channels=["auth", "net"],
        allowlist_path=ALLOW,
        fixture=FIXTURE,
        host_id="host-b",
        producer_id="prod-b",
        host_map=HOST_MAP,
        once=True,
        follow=False,
    )
    lines = (run / "events.jsonl").read_text(encoding="utf-8").strip().splitlines()
    hosts = {json.loads(x)["host_id"] for x in lines}
    assert "host-a" in hosts and "host-b" in hosts
