"""Stage B OS-wide Windows sensor tests."""

from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

from corvex.adapters.os_wide import adapt_os_wide_export, load_allowlist
from corvex.lab_enroll import ensure_lab_enrollment
from corvex.sensors.windows_os import run_sensor_windows
from corvex.stage_b import StageBGateError, require_stage_b, stage_b_status

ROOT = Path(__file__).resolve().parents[1]
FIXTURE = ROOT / "fixtures" / "os_wide" / "multi_channel.jsonl"
ALLOW = ROOT / "fixtures" / "os_wide" / "channels.json"


def test_adapt_os_wide_skips_unknown_event_ids():
    envs, stats = adapt_os_wide_export(
        FIXTURE,
        host_map={
            "host-a.lab.local": "host-a",
            "host-b.lab.local": "host-b",
            "host-c.lab.local": "host-c",
            "host-d.lab.local": "host-d",
        },
        allowlist=load_allowlist(ALLOW),
    )
    assert stats["adapted"] >= 8
    assert stats["skipped"] >= 1  # 4688 noise
    types = {e["payload_type"] for e in envs}
    assert "auth" in types
    assert "net_conn" in types
    # powershell body truncated — no full script
    ps = [e for e in envs if e["payload"].get("channel") == "powershell"]
    assert ps
    assert "script_sha256_16" in ps[0]["payload"]
    # full script body must not appear as raw ScriptBlockText field
    assert "ScriptBlockText" not in ps[0]["payload"]


def test_sensor_requires_stage_b_gate(tmp_path: Path, monkeypatch):
    monkeypatch.delenv("CORVEX_STAGE_B", raising=False)
    monkeypatch.delenv("CFUSE_STAGE_B", raising=False)
    monkeypatch.chdir(tmp_path)
    (tmp_path / "reports").mkdir()
    (tmp_path / "reports" / "stageA-gate.txt").write_text("PASS\n", encoding="utf-8")
    with pytest.raises(StageBGateError):
        require_stage_b()


def test_sensor_windows_fixture_once(tmp_path: Path, monkeypatch):
    monkeypatch.setenv("CORVEX_STAGE_B", "1")
    monkeypatch.chdir(tmp_path)
    enr = ensure_lab_enrollment(tmp_path / "enrollment.json")
    run = tmp_path / "runs" / "os-wide"
    stats = run_sensor_windows(
        run_dir=run,
        enrollment=enr,
        channels=["security", "sysmon", "firewall", "powershell"],
        allowlist_path=ALLOW,
        fixture=FIXTURE,
        host_map={
            "host-a.lab.local": "host-a",
            "host-b.lab.local": "host-b",
            "host-c.lab.local": "host-c",
            "host-d.lab.local": "host-d",
            "host-a": "host-a",
            "host-b": "host-b",
            "host-c": "host-c",
            "host-d": "host-d",
        },
        once=True,
        follow=False,
        max_per_sec=100,
    )
    assert stats["published"] >= 5
    assert (run / "events.jsonl").exists()
    assert (run / "timeline.json").exists()
    tl = json.loads((run / "timeline.json").read_text(encoding="utf-8"))
    assert len(tl.get("campaigns") or []) >= 1
    # no absolute home paths in sensor_status
    status = json.loads((run / "sensor_status.json").read_text(encoding="utf-8"))
    blob = json.dumps(status)
    assert "Users\\" not in blob and "/Users/" not in blob


def test_multihost_exporter_shape(tmp_path: Path, monkeypatch):
    monkeypatch.setenv("CORVEX_STAGE_B", "1")
    enr = ensure_lab_enrollment(tmp_path / "enrollment.json")
    run = tmp_path / "runs" / "fleet"
    # host-a writes
    run_sensor_windows(
        run_dir=run,
        enrollment=enr,
        channels=["security"],
        allowlist_path=ALLOW,
        fixture=FIXTURE,
        host_id="host-a",
        producer_id="prod-a",
        host_map={"host-a.lab.local": "host-a", "host-b.lab.local": "host-b"},
        once=True,
        follow=False,
    )
    # host-b writes into same run
    run_sensor_windows(
        run_dir=run,
        enrollment=enr,
        channels=["security"],
        allowlist_path=ALLOW,
        fixture=FIXTURE,
        host_id="host-b",
        producer_id="prod-b",
        host_map={"host-a.lab.local": "host-a", "host-b.lab.local": "host-b"},
        once=True,
        follow=False,
    )
    lines = (run / "events.jsonl").read_text(encoding="utf-8").strip().splitlines()
    hosts = {json.loads(x)["host_id"] for x in lines}
    assert "host-a" in hosts and "host-b" in hosts


def test_rate_limiter_drops(tmp_path: Path, monkeypatch):
    monkeypatch.setenv("CORVEX_STAGE_B", "1")
    enr = ensure_lab_enrollment(tmp_path / "enrollment.json")
    run = tmp_path / "runs" / "rate"
    stats = run_sensor_windows(
        run_dir=run,
        enrollment=enr,
        channels=["security", "sysmon", "firewall", "powershell"],
        allowlist_path=ALLOW,
        fixture=FIXTURE,
        host_map={
            "host-a.lab.local": "host-a",
            "host-b.lab.local": "host-b",
            "host-c.lab.local": "host-c",
            "host-d.lab.local": "host-d",
        },
        once=True,
        follow=False,
        max_per_sec=2,
    )
    assert stats["rate_limited"] >= 1 or stats["published"] <= 2
