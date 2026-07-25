"""Phase 2/3: live wevtutil health shape + fuse-run offline merge."""

from __future__ import annotations

import json
from pathlib import Path

from corvex.adapters.lab_flat import adapt_flat_lab_event
from corvex.fusion import fuse_sources
from corvex.lab_enroll import ensure_lab_enrollment
from corvex.sensors.windows_os import poll_wevtutil_channel, run_sensor_windows
from corvex.stage_b import write_lab_override
import pytest


ROOT = Path(__file__).resolve().parents[1]
FIXTURE = ROOT / "fixtures" / "os_wide" / "multi_channel.jsonl"
ALLOW = ROOT / "fixtures" / "os_wide" / "channels.json"


def test_poll_wevtutil_returns_status_dict():
    got = poll_wevtutil_channel("security", allow_ids={"4624"}, max_events=1)
    assert isinstance(got, dict)
    assert "records" in got
    assert "ok" in got
    assert "reason" in got


def test_require_live_rejects_fixture(tmp_path: Path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    (tmp_path / "reports").mkdir(parents=True)
    write_lab_override(tmp_path / "reports", reason="pytest require-live check")
    enr = ensure_lab_enrollment(tmp_path / "enrollment.json")
    with pytest.raises(ValueError, match="require-live"):
        run_sensor_windows(
            run_dir=tmp_path / "run",
            enrollment=enr,
            channels=["security"],
            allowlist_path=ALLOW,
            fixture=FIXTURE,
            once=True,
            require_live=True,
        )


def test_fuse_sources_adapts_lab_and_pc(tmp_path: Path):
    enr = ensure_lab_enrollment(
        tmp_path / "enrollment.json",
        hosts={
            "host-a": "prod-a",
            "host-b": "prod-b",
            "host-pc": "prod-pc",
        },
    )
    lab = tmp_path / "lab" / "events.jsonl"
    lab.parent.mkdir(parents=True)
    rows = [
        {
            "kind": "auth",
            "host_id": "host-a",
            "user": "svc",
            "result": "success",
            "src": "host-b",
            "ts_utc": "2026-07-25T10:00:00Z",
        },
        {
            "kind": "auth",
            "host_id": "host-b",
            "user": "svc",
            "result": "success",
            "src": "host-a",
            "ts_utc": "2026-07-25T10:00:05Z",
        },
    ]
    lab.write_text("\n".join(json.dumps(r) for r in rows) + "\n", encoding="utf-8")
    pc_dir = tmp_path / "pc"
    pc_dir.mkdir()
    env = adapt_flat_lab_event(
        {
            "kind": "net_conn",
            "host_id": "host-pc",
            "dst_ip": "203.0.113.9",
            "dst_port": 443,
            "bytes": 90000,
            "egress": True,
            "ts_utc": "2026-07-25T10:00:10Z",
        },
        enr,
        seq=99,
        host_producers={"host-pc": "prod-pc"},
    )
    # host-pc needs to be in enrollment - ensure_lab_enrollment with hosts above
    (pc_dir / "events.jsonl").write_text(
        json.dumps(env.to_dict()) + "\n", encoding="utf-8"
    )
    out = tmp_path / "fusion"
    stats = fuse_sources(
        sources={"lab": lab, "pc": pc_dir},
        out_dir=out,
        enrollment=enr,
    )
    assert stats["lines_appended"] >= 3
    tl = json.loads((out / "timeline.json").read_text(encoding="utf-8"))
    assert tl.get("mode") == "offline_lab_replay"
    assert int(tl.get("envelope_events") or 0) >= 2
    assert (out / "fusion_status.json").exists()
