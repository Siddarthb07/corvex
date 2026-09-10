"""Atomic playbook bind + gated runner (mocked Invoke-Atomic; no real ART)."""

from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

from corvex.atomic.bindings import binding_for, is_curated
from corvex.atomic.playbook import (
    PlaybookError,
    bind_manifest,
    load_playbook,
    steps_for_role,
    validate_playbook,
)
from corvex.atomic.report import write_atomic_run_report
from corvex.atomic.runner import (
    AtomicGateError,
    InvokeResult,
    build_invoke_script,
    require_atomic_gates,
    run_playbook,
)


MINI = {
    "campaign_id": "test-atomic-mini",
    "hosts": ["host-a", "host-b", "host-c", "host-d"],
    "steps": [
        {
            "kind": "auth",
            "host": "host-a",
            "user": "alice",
            "offset_seconds": 0,
            "technique": "T1078",
        },
        {
            "kind": "auth",
            "host": "host-b",
            "user": "alice",
            "offset_seconds": 5,
            "technique": "T1021",
        },
        {
            "kind": "exfil",
            "host": "host-b",
            "dst_ip": "203.0.113.1",
            "bytes": 1000,
            "offset_seconds": 10,
            "technique": "T1041",
        },
        {
            "kind": "exfil",
            "host": "host-c",
            "dst_ip": "203.0.113.1",
            "bytes": 1000,
            "offset_seconds": 15,
            "technique": "T9999",
        },
    ],
}


def test_binding_curated():
    assert is_curated("T1078")
    assert is_curated("t1041")
    assert is_curated("T1021.001")
    assert not is_curated("T9999")
    b = binding_for("T1041")
    assert b is not None
    assert b["test_number"] == 1


def test_bind_manifest_fills_and_gaps():
    pb = bind_manifest(MINI)
    assert pb["mode"] == "atomic"
    assert pb["purpose"] == "lab_ttp_replay"
    assert pb["atomic_bound_count"] == 3
    assert any("T9999" in g for g in pb["atomic_gaps"])
    host_a = steps_for_role(pb, "host-a")
    assert len(host_a) == 1
    assert host_a[0]["atomic"]["technique"] == "T1078"
    unbound = [s for s in pb["steps"] if s.get("host") == "host-c"][0]
    assert unbound["atomic"] is None


def test_validate_rejects_bad_atomic():
    bad = {
        "campaign_id": "x",
        "hosts": ["h1"],
        "steps": [{"host": "h1", "atomic": {"technique": "T1041"}}],
    }
    with pytest.raises(PlaybookError):
        validate_playbook(bad)


def test_gates_refuse_without_env(monkeypatch):
    monkeypatch.delenv("CORVEX_ATOMIC", raising=False)
    with pytest.raises(AtomicGateError, match="CORVEX_ATOMIC"):
        require_atomic_gates(authorize=True, skip_stage_b=True)


def test_gates_refuse_without_authorize(monkeypatch):
    monkeypatch.setenv("CORVEX_ATOMIC", "1")
    with pytest.raises(AtomicGateError, match="authorize"):
        require_atomic_gates(authorize=False, skip_stage_b=True)


def test_gates_refuse_without_stage_b(monkeypatch, tmp_path):
    monkeypatch.setenv("CORVEX_ATOMIC", "1")
    empty = tmp_path / "reports"
    empty.mkdir()
    with pytest.raises(AtomicGateError, match="Stage B"):
        require_atomic_gates(authorize=True, report_dir=empty, skip_stage_b=False)


def test_run_playbook_role_filter_mocked(monkeypatch, tmp_path):
    monkeypatch.setenv("CORVEX_ATOMIC", "1")
    pb = bind_manifest(MINI)
    calls = []

    def fake_invoke(argv, cwd=None):
        calls.append(list(argv))
        return InvokeResult(returncode=0, stdout="ok", stderr="", argv=argv)

    sleeps = []

    summary = run_playbook(
        pb,
        role="host-b",
        run_dir=tmp_path / "run",
        authorize=True,
        skip_stage_b=True,
        check_invoke=False,
        invoke=fake_invoke,
        sleep_fn=lambda s: sleeps.append(s),
    )
    assert summary["executed"] == 2  # T1021 + T1041 on host-b
    assert summary["techniques"] == ["T1021", "T1041"]
    assert summary["failed_phases"] == 0
    journal = (tmp_path / "run" / "atomic_exec.jsonl").read_text(encoding="utf-8")
    assert "skipped_wrong_role" in journal
    assert "atomic_step" in journal
    # prereq + test + cleanup per step → 6 invoke calls
    assert len(calls) == 6
    assert sleeps  # offset delay between steps


def test_run_playbook_zero_bound_refuses(monkeypatch, tmp_path):
    monkeypatch.setenv("CORVEX_ATOMIC", "1")
    pb = bind_manifest(MINI)
    with pytest.raises(AtomicGateError, match="No bound Atomic"):
        run_playbook(
            pb,
            role="host-d",
            run_dir=tmp_path / "run",
            authorize=True,
            skip_stage_b=True,
            check_invoke=False,
            invoke=lambda a, c=None: InvokeResult(returncode=0),
        )


def test_unlisted_refused_without_flag(monkeypatch, tmp_path):
    monkeypatch.setenv("CORVEX_ATOMIC", "1")
    pb = {
        "campaign_id": "unlisted",
        "hosts": ["host-a"],
        "steps": [
            {
                "host": "host-a",
                "technique": "T9999",
                "offset_seconds": 0,
                "atomic": {
                    "technique": "T9999",
                    "test_number": 1,
                    "get_prereqs": False,
                    "cleanup": False,
                },
            }
        ],
    }
    with pytest.raises(AtomicGateError, match="allowlist"):
        run_playbook(
            pb,
            role="host-a",
            run_dir=tmp_path / "run",
            authorize=True,
            allow_unlisted=False,
            skip_stage_b=True,
            check_invoke=False,
            invoke=lambda a, c=None: InvokeResult(returncode=0),
        )


def test_build_invoke_script_phases():
    s = build_invoke_script(
        technique="T1041",
        test_number=1,
        get_prereqs=True,
        cleanup=True,
        phase="test",
    )
    assert "Invoke-AtomicTest" in s
    assert "T1041" in s
    assert "-TestNumbers 1" in s


def test_write_report(tmp_path):
    pb = bind_manifest(MINI)
    summary = {
        "role": "host-a",
        "techniques": ["T1078"],
        "executed": 1,
        "failed_phases": 0,
    }
    path = write_atomic_run_report(
        report_dir=tmp_path,
        playbook=pb,
        summary=summary,
        run_dir=tmp_path / "run",
        reconstruction_status="partial",
    )
    data = json.loads(path.read_text(encoding="utf-8"))
    assert data["claim_allowed_unchanged"] is True
    assert data["campaign_id"] == "test-atomic-mini"


def test_seed_playbook_loads():
    root = Path(__file__).resolve().parents[1]
    path = root / "labs" / "breaktest" / "manifests" / "art_lateral_chain.atomic.json"
    if not path.exists():
        pytest.skip("seed playbook not generated yet")
    pb = load_playbook(path)
    assert pb["campaign_id"] == "art-lateral-chain-5h"
    assert pb["atomic_bound_count"] >= 8
    assert pb["mode"] == "atomic"
