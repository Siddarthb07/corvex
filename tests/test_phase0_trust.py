"""Tests for Phase 0 trust + Phase 1 lab flat adapt / HMAC on recompute."""

from __future__ import annotations

import json
from pathlib import Path

from corvex.adapters.lab_flat import adapt_flat_lab_event
from corvex.eval.claim_gates import evaluate_claim_gates
from corvex.lab_enroll import ensure_lab_enrollment
from corvex.sensors.windows_os import recompute_run
from corvex.stage_b import require_stage_b, stage_b_status, write_lab_override
from corvex.stage_b import StageBGateError
import pytest


ROOT = Path(__file__).resolve().parents[1]


def test_agent_stranger_does_not_unlock_claim(tmp_path: Path):
    reports = tmp_path / "reports"
    reports.mkdir()
    (reports / "stageA_heldout.json").write_text(
        json.dumps(
            {
                "metrics": {
                    "correlator": {"false_campaign_rate": 0.0, "campaign_f1": 1.0},
                    "detector_only": {"campaign_f1": 0.5},
                },
                "packs": [{"family": "benign"}] * 5,
            }
        ),
        encoding="utf-8",
    )
    (reports / "non_author_fusion.json").write_text(
        json.dumps(
            {
                "pass": True,
                "f1_lift": 0.5,
                "source": "labs/breaktest/manifests",
                "note": "breaktest",
            }
        ),
        encoding="utf-8",
    )
    (reports / "stranger_dry_run.json").write_text(
        json.dumps(
            {
                "pass": True,
                "operator": "cursor-stranger-agent",
                "attestation_kind": "agent",
                "note": "should not qualify",
            }
        ),
        encoding="utf-8",
    )
    result = evaluate_claim_gates(tmp_path)
    assert result["claim_allowed"] is False
    assert result["gates"]["stranger_success"]["pass"] is False


def test_human_stranger_qualifies_gate(tmp_path: Path):
    reports = tmp_path / "reports"
    reports.mkdir()
    (reports / "stageA_heldout.json").write_text(
        json.dumps(
            {
                "metrics": {
                    "correlator": {"false_campaign_rate": 0.0},
                    "detector_only": {},
                },
                "packs": [{"family": "benign"}] * 5,
            }
        ),
        encoding="utf-8",
    )
    (reports / "non_author_fusion.json").write_text(
        json.dumps({"pass": True, "f1_lift": 0.5, "source": "x"}),
        encoding="utf-8",
    )
    (reports / "stranger_dry_run.json").write_text(
        json.dumps(
            {
                "pass": True,
                "operator": "Alex External",
                "attestation_kind": "human",
                "note": "ran BYO path blind",
            }
        ),
        encoding="utf-8",
    )
    result = evaluate_claim_gates(tmp_path)
    assert result["gates"]["stranger_success"]["pass"] is True
    assert result["claim_allowed"] is True


def test_env_stage_b_ignored(tmp_path: Path, monkeypatch):
    monkeypatch.setenv("CORVEX_STAGE_B", "1")
    monkeypatch.chdir(tmp_path)
    (tmp_path / "reports").mkdir()
    status = stage_b_status(tmp_path / "reports")
    assert status["allowed"] is False
    assert status["env_override_ignored"] is True
    with pytest.raises(StageBGateError):
        require_stage_b()


def test_lab_override_unlocks(tmp_path: Path, monkeypatch):
    monkeypatch.delenv("CORVEX_STAGE_B", raising=False)
    monkeypatch.chdir(tmp_path)
    reports = tmp_path / "reports"
    reports.mkdir()
    write_lab_override(reports, reason="pytest local fixture unlock")
    assert stage_b_status(reports)["allowed"] is True
    require_stage_b()


def test_recompute_rejects_tampered_hmac(tmp_path: Path):
    enr = ensure_lab_enrollment(tmp_path / "enrollment.json")
    run = tmp_path / "run"
    run.mkdir()
    env = adapt_flat_lab_event(
        {
            "kind": "auth",
            "host_id": "host-a",
            "user": "alice",
            "result": "success",
            "src": "host-b",
            "ts_utc": "2026-07-24T12:00:00Z",
        },
        enr,
        seq=1,
    )
    bad = env.to_dict()
    bad["hmac"] = "00" * 32
    good2 = adapt_flat_lab_event(
        {
            "kind": "auth",
            "host_id": "host-b",
            "user": "alice",
            "result": "success",
            "src": "host-a",
            "ts_utc": "2026-07-24T12:00:05Z",
        },
        enr,
        seq=2,
    )
    (run / "events.jsonl").write_text(
        json.dumps(bad) + "\n" + json.dumps(good2.to_dict()) + "\n",
        encoding="utf-8",
    )
    stats = recompute_run(run, enr)
    assert stats["hmac_rejected"] >= 1
    assert stats["events"] >= 1
    tl = json.loads((run / "timeline.json").read_text(encoding="utf-8"))
    assert tl.get("mode") == "offline_lab_replay"


def test_recompute_adapts_flat_lab_rows(tmp_path: Path):
    enr = ensure_lab_enrollment(tmp_path / "enrollment.json")
    run = tmp_path / "run"
    run.mkdir()
    rows = [
        {
            "kind": "auth",
            "host_id": "host-a",
            "user": "svc",
            "result": "success",
            "src": "host-b",
            "ts_utc": "2026-07-24T12:00:00Z",
        },
        {
            "kind": "auth",
            "host_id": "host-b",
            "user": "svc",
            "result": "success",
            "src": "host-a",
            "ts_utc": "2026-07-24T12:00:10Z",
        },
        {
            "kind": "net_conn",
            "host_id": "host-c",
            "dst_ip": "203.0.113.9",
            "dst_port": 443,
            "bytes": 90000,
            "egress": True,
            "ts_utc": "2026-07-24T12:00:20Z",
        },
    ]
    (run / "events.jsonl").write_text(
        "\n".join(json.dumps(r) for r in rows) + "\n", encoding="utf-8"
    )
    stats = recompute_run(run, enr)
    assert stats["flat_lab_adapted"] == 3
    assert stats["hmac_rejected"] == 0
    assert stats["events"] == 3
    tl = json.loads((run / "timeline.json").read_text(encoding="utf-8"))
    assert "flat_lab_events_skipped_for_correlate" not in tl
