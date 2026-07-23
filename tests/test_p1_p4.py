"""P1–P4: recon regression, claim gates, hostile bus, windows wedge."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from corvex.contain.hostile_bus import run_hostile_bus_selftest, write_hostile_bus_report
from corvex.contain.live import live_gates_satisfied
from corvex.eval.claim_gates import evaluate_claim_gates
from corvex.lab_enroll import ensure_lab_enrollment


def test_hostile_bus_selftest(tmp_path: Path):
    report = run_hostile_bus_selftest(tmp_path)
    assert report["pass"] is True
    cases = {c["case"]: c["pass"] for c in report["cases"]}
    assert cases["missing_authz"] is True
    assert cases["free_form_verb"] is True
    assert cases["replay"] is True
    assert cases["expired"] is True


def test_hostile_bus_report_written(tmp_path: Path, monkeypatch):
    # write into tmp as root
    (tmp_path / "reports").mkdir()
    report = write_hostile_bus_report(tmp_path, tmp_path / "hb")
    assert report["pass"] is True
    assert (tmp_path / "reports" / "hostile_bus_selftest.json").exists()


def test_live_gates_not_ready_by_default(tmp_path: Path, monkeypatch):
    monkeypatch.setenv("CORVEX_CONTAIN", "0")
    (tmp_path / "reports").mkdir()
    (tmp_path / "reports" / "security_l1_checklist.json").write_text(
        json.dumps({"mtls_identities": False}), encoding="utf-8"
    )
    gates = live_gates_satisfied(tmp_path)
    assert gates["ready"] is False
    assert gates["os_executor_implemented"] is False


def test_claim_gates_locked_without_attestation(tmp_path: Path):
    reports = tmp_path / "reports"
    reports.mkdir()
    (reports / "stageA_heldout.json").write_text(
        json.dumps(
            {
                "metrics": {
                    "correlator": {"false_campaign_rate": 0.0, "campaign_f1": 1.0},
                    "detector_only": {"campaign_f1": 0.5},
                },
                "packs": [
                    {"family": "benign"},
                    {"family": "benign"},
                    {"family": "benign"},
                    {"family": "benign"},
                    {"family": "benign"},
                ],
                "by_family": {
                    "correlator": {"fusion_chain": {"campaign_f1": 1.0}},
                    "detector_only": {"fusion_chain": {"campaign_f1": 0.5}},
                },
            }
        ),
        encoding="utf-8",
    )
    result = evaluate_claim_gates(tmp_path)
    assert result["claim_allowed"] is False
    assert result["gates"]["benign_fcr_real_n"]["pass"] is True
    assert result["gates"]["stranger_success"]["pass"] is False
    assert result["gates"]["non_author_fusion_lift"]["pass"] is False


def test_byo_windows_wedge(tmp_path: Path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    # Minimal repo-like layout not required — call adapter + correlate via CLI helpers
    from corvex.adapters.windows_security import adapt_windows_security_export
    from corvex.audit import AuditLog
    from corvex.correlator import Correlator
    from corvex.envelope import sign_envelope
    from corvex.lab_enroll import DEMO_HOSTS
    from corvex.reconstruct import reconstruct_timeline
    from corvex.store import CampaignStore

    root = Path(__file__).resolve().parents[1]
    fixture = root / "fixtures" / "windows_security_sample.json"
    enrollment = ensure_lab_enrollment()
    raw = adapt_windows_security_export(
        fixture,
        host_map={h: h for h in DEMO_HOSTS},
        default_host="host-a",
    )
    events = []
    for rec in raw:
        host_id = rec["host_id"] if rec["host_id"] in DEMO_HOSTS else "host-a"
        prod = DEMO_HOSTS[host_id]
        events.append(
            sign_envelope(
                producer_id=prod,
                host_id=host_id,
                payload_type=rec["payload_type"],
                payload=rec["payload"],
                secret=enrollment.require(prod, host_id),
                event_id=rec["event_id"],
                ts_utc=rec["ts_utc"],
                nonce=rec["nonce"],
            )
        )
    store = CampaignStore(tmp_path / "c.jsonl")
    Correlator(store, AuditLog(tmp_path / "a.jsonl")).ingest(events)
    camps = store.all()
    assert len(camps) >= 1
    assert len(camps[0].host_ids) >= 2
    report = reconstruct_timeline(
        {"campaigns": [c.to_dict() for c in camps], "ground_truth": None}
    )
    assert report["aggregate_status"] in ("complete", "partial")
