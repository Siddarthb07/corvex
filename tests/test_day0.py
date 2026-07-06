"""Day-0 / Stage A contract tests (Lineage A APIs)."""

from __future__ import annotations

import ast
import json
from datetime import datetime, timezone
from pathlib import Path

import pytest

from campaignfuse.audit import AuditLog
from campaignfuse.auth import AuthError, Enrollment, generate_lab_enrollment
from campaignfuse.baselines import baseline_b2
from campaignfuse.bus import JetStreamBus, JsonlBus
from campaignfuse.contain import ContainGateError, checklist_complete, require_contain
from campaignfuse.correlator import Correlator
from campaignfuse.envelope import EventEnvelope, sign_envelope, verify_envelope
from campaignfuse.eval import aggregate_scores, score_pack
from campaignfuse.feeder import generate_campaign_events
from campaignfuse.stage_b import StageBGateError, require_stage_b
from campaignfuse.stage_c import find_destructive_verbs_in_package
from campaignfuse.store import CampaignStore

ROOT = Path(__file__).resolve().parents[1]
DETECTORS = ROOT / "campaignfuse" / "detectors.py"


def test_detectors_ast_purity():
    tree = ast.parse(DETECTORS.read_text(encoding="utf-8"))
    banned_mods = {"socket", "subprocess", "random"}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name.split(".")[0] in banned_mods:
                    pytest.fail(f"banned import {alias.name}")
        if isinstance(node, ast.ImportFrom):
            if (node.module or "").split(".")[0] in banned_mods:
                pytest.fail(f"banned import from {node.module}")
        if isinstance(node, ast.Attribute) and isinstance(node.value, ast.Name):
            if node.value.id == "time" and node.attr == "time":
                pytest.fail("time.time banned in detectors.py")
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
            if node.func.id == "open":
                pytest.fail("open() banned in detectors.py")


def test_hmac_and_enrollment():
    enr = Enrollment({"prod-a": {"host-a"}}, {"prod-a": b"unit-test-secret-not-default-xx"})
    env = sign_envelope(
        producer_id="prod-a",
        host_id="host-a",
        payload_type="auth",
        payload={"user": "u", "result": "success"},
        secret=enr.require("prod-a", "host-a"),
        event_id="e1",
        ts_utc="2026-01-01T00:00:00.000000Z",
        nonce="abc",
    )
    assert verify_envelope(env, enr.require("prod-a", "host-a"))

    tampered = env.to_dict()
    tampered["host_id"] = "host-b"
    bad = EventEnvelope.from_dict(tampered)
    assert not verify_envelope(bad, enr.require("prod-a", "host-a"))


def test_refuse_default_hmac_secret():
    with pytest.raises(AuthError):
        Enrollment({"x": {"h"}}, {"x": b"changeme"})


def test_jsonl_bus_commit(tmp_path):
    bus = JsonlBus(tmp_path / "bus.jsonl")
    enr = Enrollment({"prod-a": {"host-a"}}, {"prod-a": b"unit-test-secret-not-default-yy"})
    env = sign_envelope(
        producer_id="prod-a",
        host_id="host-a",
        payload_type="process",
        payload={"proc": "a"},
        secret=enr.require("prod-a", "host-a"),
        event_id="e1",
        ts_utc="2026-01-01T00:00:00.000000Z",
        nonce="n1",
    )
    bus.publish(env)
    bus.commit("1")
    assert (tmp_path / "bus.jsonl.cursor").read_text(encoding="utf-8").strip() == "1"


def test_jetstream_stub_raises():
    with pytest.raises(NotImplementedError):
        JetStreamBus()


def test_audit_hash_chain(tmp_path):
    audit = AuditLog(tmp_path / "a.jsonl")
    h1 = audit.append("campaign_upsert", {"campaign_id": "c1"})
    h2 = audit.append("campaign_upsert", {"campaign_id": "c2"})
    assert h1 != h2
    assert audit.verify_chain()


def test_no_destructive_verbs_in_package():
    assert find_destructive_verbs_in_package() == []


def test_contain_gate_locked():
    with pytest.raises(ContainGateError):
        require_contain()
    assert checklist_complete() is False


def test_stage_b_gate_locked(monkeypatch, tmp_path):
    monkeypatch.delenv("CFUSE_STAGE_B", raising=False)
    monkeypatch.chdir(tmp_path)
    (tmp_path / "reports").mkdir()
    with pytest.raises(StageBGateError):
        require_stage_b()


def test_b2_anti_sandbag_on_train():
    enr = generate_lab_enrollment(
        {"host-a": "prod-a", "host-b": "prod-b", "host-c": "prod-c"}
    )
    base = datetime(2026, 1, 15, 12, 0, 0, tzinfo=timezone.utc)
    hosts = [("host-a", "prod-a"), ("host-b", "prod-b"), ("host-c", "prod-c")]
    results = []
    for cid, family in [
        ("t1", "lateral"),
        ("t2", "exfil"),
        ("t3", "recon_lateral"),
    ]:
        events, gt = generate_campaign_events(
            campaign_id=cid,
            family=family,
            hosts=hosts,
            enrollment=enr,
            base_time=base,
        )
        camps = baseline_b2([e.to_dict() for e in events])
        results.append(
            score_pack([c.to_dict() for c in camps], gt, ttu_seconds=0.01, benign=False)
        )
    agg = aggregate_scores(results)
    assert agg["campaign_f1"] >= 0.40, agg


def test_correlator_dedup(tmp_path):
    enr = Enrollment(
        {"prod-a": {"host-a", "host-b"}},
        {"prod-a": b"unit-test-secret-not-default-rr"},
    )
    env = sign_envelope(
        producer_id="prod-a",
        host_id="host-a",
        payload_type="auth",
        payload={"user": "u", "result": "success"},
        secret=enr.require("prod-a", "host-a"),
        event_id="same-id",
        ts_utc="2026-01-01T00:00:00.000000Z",
        nonce="n1",
    )
    store = CampaignStore(tmp_path / "c.jsonl")
    audit = AuditLog(tmp_path / "a.jsonl")
    corr = Correlator(store, audit)
    corr.ingest([env, env])
    assert "same-id" in corr._seen
