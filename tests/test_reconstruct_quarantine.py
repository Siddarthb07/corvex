"""Tests for honest reconstruction + quarantine modes."""

from __future__ import annotations

import json
from pathlib import Path

from corvex.contain.quarantine import attempt_quarantine, resolve_quarantine_mode
from corvex.reconstruct import reconstruct_campaign, reconstruct_timeline, write_reconstruction
from corvex.store import Campaign


def test_reconstruct_refuses_empty():
    rec = reconstruct_campaign(
        Campaign(campaign_id="x", host_ids=[], stages=[], evidence=[]),
        quarantine_mode="dry_run",
    )
    assert rec.status == "empty"
    assert rec.quarantine is None
    assert any("Cannot rebuild" in h or "empty" in h.lower() for h in rec.honesty)


def test_reconstruct_partial_when_single_host():
    rec = reconstruct_campaign(
        Campaign(
            campaign_id="thin",
            host_ids=["host-a"],
            stages=[{"name": "lateral_auth", "hosts": ["host-a"]}],
            evidence=[{"kind": "lateral_auth", "host_id": "host-a", "attrs": {}}],
            score=0.5,
        ),
        quarantine_mode="dry_run",
    )
    assert rec.status in ("partial", "insufficient_evidence")
    assert any("fewer than" in g for g in rec.gaps)


def test_reconstruct_complete_multihost_with_attack_tags():
    rec = reconstruct_campaign(
        Campaign(
            campaign_id="camp-lateral-alice",
            host_ids=["host-a", "host-b", "host-c"],
            stages=[{"name": "lateral_auth", "user": "alice", "hosts": ["host-a", "host-b", "host-c"]}],
            evidence=[
                {"kind": "lateral_auth", "host_id": "host-a", "attrs": {"user": "alice"}},
                {"kind": "lateral_auth", "host_id": "host-b", "attrs": {"user": "alice"}},
            ],
            score=0.9,
        ),
        quarantine_mode="dry_run",
    )
    assert rec.status == "complete"
    assert "T1078" in rec.steps[0].attack_techniques
    assert rec.quarantine is not None
    assert rec.quarantine.mode == "dry_run"
    assert "not armed" in rec.quarantine.honesty.lower() or "Dry-run" in rec.quarantine.honesty
    man = rec.to_manifest()
    assert man["purpose"] == "regression_only"
    assert man["honesty"]


def test_reconstruct_truth_mismatch_is_partial():
    rec = reconstruct_campaign(
        Campaign(
            campaign_id="camp",
            host_ids=["host-a", "host-b"],
            stages=[{"name": "lateral_auth", "hosts": ["host-a", "host-b"]}],
            evidence=[{"kind": "lateral_auth", "host_id": "host-a", "attrs": {}}],
            score=0.8,
        ),
        ground_truth={
            "host_ids": ["host-a", "host-b", "host-c"],
            "stages": [{"name": "lateral_auth"}, {"name": "micro_exfil"}],
        },
        quarantine_mode="dry_run",
    )
    assert rec.status == "partial"
    assert rec.compared_to_truth is not None
    assert rec.compared_to_truth["full_match"] is False


def test_write_reconstruction(tmp_path: Path):
    tl = {
        "pack": "train/x.jsonl",
        "ground_truth": {
            "host_ids": ["host-a", "host-b"],
            "stages": [{"name": "lateral_auth"}],
        },
        "campaigns": [
            {
                "campaign_id": "camp-lateral-alice",
                "host_ids": ["host-a", "host-b"],
                "stages": [{"name": "lateral_auth", "hosts": ["host-a", "host-b"]}],
                "evidence": [{"kind": "lateral_auth", "host_id": "host-a", "attrs": {}}],
                "score": 0.9,
            }
        ],
    }
    (tmp_path / "timeline.json").write_text(json.dumps(tl), encoding="utf-8")
    out = write_reconstruction(tmp_path, quarantine_mode="dry_run")
    assert out.exists()
    report = json.loads(out.read_text(encoding="utf-8"))
    assert report["aggregate_status"] in ("complete", "partial")
    assert (tmp_path / "reconstruction_manifests").is_dir()


def test_quarantine_dry_run(tmp_path: Path, monkeypatch):
    monkeypatch.delenv("LAB_DIR", raising=False)
    monkeypatch.delenv("CORVEX_LAB_DIR", raising=False)
    monkeypatch.setenv("CORVEX_CONTAIN", "0")
    log = tmp_path / "dry.jsonl"
    result = attempt_quarantine(
        ["host-a", "host-b"],
        rationale="test",
        log_path=log,
        root=tmp_path,
    )
    assert result["aggregate"] == "dry_run_only"
    assert result["ok"] is True
    assert all(not h["enforced"] for h in result["hosts"])
    assert log.exists()


def test_quarantine_lab_flag(tmp_path: Path, monkeypatch):
    monkeypatch.setenv("CORVEX_CONTAIN", "0")
    lab = tmp_path / "lab"
    lab.mkdir()
    log = tmp_path / "dry.jsonl"
    result = attempt_quarantine(
        ["host-a"],
        rationale="lab isolate",
        lab_dir=lab,
        log_path=log,
        root=tmp_path,
    )
    assert result["aggregate"] == "lab_quarantined"
    assert (lab / "isolated" / "host-a.flag").exists()
    assert result["hosts"][0]["enforced"] is True
    assert "Not real" in result["message"] or "flag" in result["message"].lower()


def test_quarantine_blocked_when_contain_on_without_executor(tmp_path: Path, monkeypatch):
    monkeypatch.delenv("LAB_DIR", raising=False)
    monkeypatch.delenv("CORVEX_LAB_DIR", raising=False)
    monkeypatch.setenv("CORVEX_CONTAIN", "1")
    # Checklist incomplete → blocked
    reports = tmp_path / "reports"
    reports.mkdir()
    (reports / "security_l1_checklist.json").write_text(
        json.dumps({"mtls_identities": False}), encoding="utf-8"
    )
    caps = resolve_quarantine_mode(root=tmp_path)
    assert caps["mode"] == "blocked"
    result = attempt_quarantine(
        ["host-a"],
        rationale="should refuse",
        root=tmp_path,
        log_path=tmp_path / "x.jsonl",
    )
    assert result["aggregate"] == "cannot_quarantine"
    assert result["ok"] is False
    assert "refusing" in result["message"].lower() or "blocked" in result["message"].lower() or "incomplete" in result["message"].lower()


def test_timeline_aggregate_empty():
    report = reconstruct_timeline({"campaigns": []})
    assert report["aggregate_status"] == "empty"
