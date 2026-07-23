"""Dashboard monitor — run-centric read-only projector."""

from __future__ import annotations

import json
import threading
from pathlib import Path

import pytest

from corvex.contain import (
    L1_ITEMS,
    checklist_complete,
    load_checklist_state,
    require_contain,
    set_checklist_item,
    ContainGateError,
)
from corvex.dash_server import serve
from corvex.dashboard import collect_snapshot, write_dashboard


def _seed_reports(tmp_path: Path) -> None:
    reports = tmp_path / "reports"
    reports.mkdir(parents=True)
    data = {k: False for k in L1_ITEMS}
    data["_meta"] = {"policy": "test"}
    (reports / "security_l1_checklist.json").write_text(
        json.dumps(data, indent=2), encoding="utf-8"
    )
    (reports / "stageA-gate.txt").write_text("PASS\n", encoding="utf-8")
    (reports / "stageA_heldout.json").write_text(
        json.dumps(
            {
                "pass": True,
                "care_vs_incumbent": "unproven",
                "metrics": {
                    "correlator": {
                        "campaign_f1": 1.0,
                        "precision": 1.0,
                        "recall": 1.0,
                        "precision_at_1": 1.0,
                        "false_campaign_rate": 0.0,
                        "ttu_seconds": 0.01,
                    },
                    "b1": {"campaign_f1": 0.0},
                    "b2": {"campaign_f1": 1.0},
                    "detector_only": {"campaign_f1": 0.67},
                },
            }
        ),
        encoding="utf-8",
    )
    (reports / "claim_gates.json").write_text(
        json.dumps({"claim_allowed": False, "claim_language": "lab only"}),
        encoding="utf-8",
    )


def _seed_run(tmp_path: Path) -> Path:
    run = tmp_path / "runs" / "demo"
    run.mkdir(parents=True)
    (run / "timeline.json").write_text(
        json.dumps(
            {
                "pack": "train/x.jsonl",
                "campaigns": [
                    {
                        "campaign_id": "camp-test",
                        "host_ids": ["host-a", "host-b"],
                        "stages": [{"name": "lateral_auth", "hosts": ["host-a", "host-b"]}],
                        "score": 0.9,
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    (run / "reconstruction.json").write_text(
        json.dumps(
            {
                "aggregate_status": "partial",
                "summary": "Partial rebuild for test",
                "campaign_reconstructions": [
                    {
                        "campaign_id": "camp-test",
                        "status": "partial",
                        "confidence": 0.7,
                        "host_ids": ["host-a", "host-b"],
                        "steps": [
                            {
                                "order": 1,
                                "name": "lateral_auth",
                                "hosts": ["host-a", "host-b"],
                                "attack_techniques": ["T1078"],
                                "verified": True,
                            }
                        ],
                        "gaps": ["example gap"],
                        "quarantine": {
                            "mode": "dry_run",
                            "host_ids": ["host-a", "host-b"],
                            "honesty": "Dry-run only",
                        },
                        "honesty": ["test"],
                    }
                ],
                "honesty": ["test honesty"],
            }
        ),
        encoding="utf-8",
    )
    (run / "events.jsonl").write_text(
        "\n".join(
            [
                json.dumps(
                    {
                        "event_id": "e1",
                        "host_id": "host-a",
                        "producer_id": "prod-a",
                        "ts_utc": "2026-07-01T10:00:00Z",
                        "payload_type": "auth",
                        "payload": {
                            "user": "alice",
                            "result": "success",
                            "src": "10.0.0.1",
                            "technique": "T1078",
                        },
                    }
                ),
                json.dumps(
                    {
                        "event_id": "e2",
                        "host_id": "host-b",
                        "producer_id": "prod-b",
                        "ts_utc": "2026-07-01T10:00:20Z",
                        "payload_type": "net_conn",
                        "payload": {
                            "dst_ip": "203.0.113.50",
                            "dst_port": 443,
                            "bytes": 12000,
                            "egress": True,
                            "technique": "T1041",
                        },
                    }
                ),
            ]
        )
        + "\n",
        encoding="utf-8",
    )
    (run / "audit.jsonl").write_text(
        json.dumps(
            {
                "kind": "campaign_upsert",
                "payload": {
                    "campaign_id": "camp-test",
                    "hosts": ["host-a", "host-b"],
                    "stages": 1,
                },
                "entry_hash": "abc123",
            }
        )
        + "\n",
        encoding="utf-8",
    )
    return run


def test_set_checklist_item_roundtrip(tmp_path: Path) -> None:
    _seed_reports(tmp_path)
    assert load_checklist_state(tmp_path)["anti_replay"] is False
    st = set_checklist_item("anti_replay", True, root=tmp_path, source="test")
    assert st["anti_replay"] is True


def test_checklist_complete_gate(tmp_path: Path) -> None:
    _seed_reports(tmp_path)
    assert checklist_complete(root=tmp_path) is False
    with pytest.raises(ContainGateError):
        require_contain(root=tmp_path)


def test_snapshot_run_centric(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _seed_reports(tmp_path)
    run = _seed_run(tmp_path)
    monkeypatch.setenv("CORVEX_RUN_DIR", str(run))
    snap = collect_snapshot(tmp_path)
    assert snap["schema_version"] == 3
    assert snap["run"]["loaded"] is True
    assert len(snap["run"]["campaigns"]) == 1
    assert snap["run"]["reconstruction"]["aggregate_status"] == "partial"
    assert snap["quarantine"]["live_executor"] is False
    assert snap["claim"]["allowed"] is False
    assert snap["sealed_eval"]["binds_to_run"] is False
    assert snap["hero"]["status"] in ("PARTIAL", "CAMPAIGN")
    assert snap["kpis"]["events"] == 2
    assert any(a["kind"] == "AUTH" for a in snap["activity"])
    assert any(a["kind"] == "EXFIL" for a in snap["activity"])


def test_dashboard_html_has_run_sections_not_toggles(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _seed_reports(tmp_path)
    run = _seed_run(tmp_path)
    monkeypatch.setenv("CORVEX_RUN_DIR", str(run))
    out = write_dashboard(tmp_path)
    html = out.read_text(encoding="utf-8")
    assert "run feed" in html
    assert "Activity" in html
    assert "camp-test" in html
    assert "Sealed Day-0" in html
    assert "checkbox" not in html
    assert "file-tail" in html
    assert '"kind": "AUTH"' in html or "AUTH" in html
    assert "events.jsonl" in html
    assert "file_tail" in html


def test_api_snapshot_no_html_rewrite_and_no_post(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _seed_reports(tmp_path)
    run = _seed_run(tmp_path)
    monkeypatch.setenv("CORVEX_RUN_DIR", str(run))
    out = write_dashboard(tmp_path)
    httpd = serve(tmp_path, port=0)  # may rewrite once at bind
    mtime_before = out.stat().st_mtime
    host, port = httpd.server_address
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    try:
        import time
        import urllib.error
        import urllib.request

        with urllib.request.urlopen(f"http://{host}:{port}/api/snapshot", timeout=5) as resp:
            snap = json.loads(resp.read().decode("utf-8"))
        assert snap["schema_version"] == 3
        assert snap["run"]["campaigns"][0]["campaign_id"] == "camp-test"
        assert len(snap["activity"]) == 2
        time.sleep(0.05)
        # Snapshot GET must not rewrite HTML
        assert out.stat().st_mtime == mtime_before

        req = urllib.request.Request(
            f"http://{host}:{port}/api/checklist",
            data=json.dumps({"key": "fail_closed", "enabled": True}).encode("utf-8"),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with pytest.raises(urllib.error.HTTPError) as exc:
            urllib.request.urlopen(req, timeout=5)
        assert exc.value.code in (405, 410)
    finally:
        httpd.shutdown()
        httpd.server_close()
