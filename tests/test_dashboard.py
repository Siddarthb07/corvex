"""Dashboard checklist toggles + contain path fixes."""

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


def _seed_checklist(tmp_path: Path) -> Path:
    reports = tmp_path / "reports"
    reports.mkdir(parents=True)
    data = {k: False for k in L1_ITEMS}
    data["_meta"] = {"policy": "test"}
    path = reports / "security_l1_checklist.json"
    path.write_text(json.dumps(data, indent=2), encoding="utf-8")
    (reports / "stageA-gate.txt").write_text("PASS\n", encoding="utf-8")
    (reports / "stageA_heldout.json").write_text(
        json.dumps(
            {
                "pass": True,
                "care_vs_incumbent": "unproven",
                "metrics": {
                    "correlator": {
                        "campaign_f1": 1.0,
                        "precision_at_1": 1.0,
                        "false_campaign_rate": 0.0,
                        "ttu_seconds": 0.01,
                    },
                    "b1": {"campaign_f1": 0.0},
                    "b2": {"campaign_f1": 1.0},
                    "detector_only": {"campaign_f1": 1.0},
                },
            }
        ),
        encoding="utf-8",
    )
    return path


def test_set_checklist_item_roundtrip(tmp_path: Path) -> None:
    _seed_checklist(tmp_path)
    assert load_checklist_state(tmp_path)["anti_replay"] is False
    st = set_checklist_item("anti_replay", True, root=tmp_path, source="test")
    assert st["anti_replay"] is True
    raw = json.loads((tmp_path / "reports" / "security_l1_checklist.json").read_text(encoding="utf-8"))
    assert raw["anti_replay"] is True
    assert "SET VIA TEST" in raw["_meta"]["evidence_notes"]["anti_replay"]
    set_checklist_item("anti_replay", False, root=tmp_path, source="test")
    assert load_checklist_state(tmp_path)["anti_replay"] is False


def test_checklist_complete_gate(tmp_path: Path) -> None:
    _seed_checklist(tmp_path)
    assert checklist_complete(root=tmp_path) is False
    with pytest.raises(ContainGateError):
        require_contain(root=tmp_path)
    for k in L1_ITEMS:
        set_checklist_item(k, True, root=tmp_path, source="test")
    assert checklist_complete(root=tmp_path) is True


def test_dashboard_snapshot_reads_toggles(tmp_path: Path) -> None:
    _seed_checklist(tmp_path)
    set_checklist_item("dual_control", True, root=tmp_path, source="test")
    snap = collect_snapshot(tmp_path)
    assert snap["stage_d"]["items"]["dual_control"] is True
    assert snap["stage_d"]["checklist_done"] == 1
    out = write_dashboard(tmp_path)
    html = out.read_text(encoding="utf-8")
    assert "Corvex" in html
    assert "type=\\\"checkbox\\\"" in html or 'type="checkbox"' in html
    assert '"dual_control":true' in html.replace(" ", "")


def test_api_checklist_toggle(tmp_path: Path) -> None:
    _seed_checklist(tmp_path)
    write_dashboard(tmp_path)
    httpd = serve(tmp_path, port=0)
    host, port = httpd.server_address
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    try:
        import urllib.request

        req = urllib.request.Request(
            f"http://{host}:{port}/api/checklist",
            data=json.dumps({"key": "fail_closed", "enabled": True}).encode("utf-8"),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=5) as resp:
            body = json.loads(resp.read().decode("utf-8"))
        assert body["ok"] is True
        assert body["items"]["fail_closed"] is True
        assert load_checklist_state(tmp_path)["fail_closed"] is True

        with urllib.request.urlopen(f"http://{host}:{port}/api/snapshot", timeout=5) as resp:
            snap = json.loads(resp.read().decode("utf-8"))
        assert snap["stage_d"]["items"]["fail_closed"] is True
    finally:
        httpd.shutdown()
        httpd.server_close()
