"""Fail-closed contain gates — ReleaseHost, SOC, dual-control."""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from corvex.contain.fanout import apply_local_from_envelope
from corvex.contain.policy import ContainPolicy, filter_soc, save_policy


def test_release_host_with_contain_zero_refuses(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("CORVEX_CONTAIN", "0")
    monkeypatch.delenv("CORVEX_CONTAIN_AUTHZ", raising=False)
    env = {
        "verb": "ReleaseHost",
        "target": {"host_id": "host-a"},
        "dry_run": False,
        "rationale": "gate-test",
        "idempotency_key": "release-gate-1",
        "expiry": "2099-01-01T00:00:00Z",
        "schema_ver": "1",
        "impact_class": "lab_soft",
        "policy_version": "d0-draft",
    }
    rec = apply_local_from_envelope(env, root=tmp_path, authz_token="x")
    assert rec.get("enforced") is False
    assert rec.get("result") == "refused"
    # Fail-closed: L1 incomplete and/or CORVEX_CONTAIN=0 — must not mutate.
    honesty = str(rec.get("honesty") or "")
    assert "checklist" in honesty.lower() or "CORVEX_CONTAIN=0" in honesty


def test_soc_filter_casefold() -> None:
    pol = ContainPolicy(soc_allowlist=["SOC-Box"])
    assert filter_soc(["soc-box", "worker-1"], pol) == ["worker-1"]


def test_apply_unknown_verb_refuses(tmp_path: Path) -> None:
    rec = apply_local_from_envelope(
        {
            "verb": "rm -rf",
            "target": {"host_id": "host-a"},
            "dry_run": False,
            "rationale": "bad",
        },
        root=tmp_path,
    )
    assert rec.get("result") == "refused"
    assert rec.get("enforced") is False
