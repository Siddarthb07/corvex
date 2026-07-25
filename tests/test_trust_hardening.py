"""Correlator HMAC-at-ingest + resign verify-first."""

from __future__ import annotations

from pathlib import Path

from corvex.audit import AuditLog
from corvex.auth import generate_lab_enrollment
from corvex.correlator import Correlator
from corvex.envelope import sign_envelope
from corvex.feeder import resign_events
from corvex.store import CampaignStore


def test_correlator_rejects_bad_hmac(tmp_path: Path):
    enr = generate_lab_enrollment({"host-a": "prod-a", "host-b": "prod-b"})
    secret = enr.require("prod-a", "host-a")
    good = sign_envelope(
        producer_id="prod-a",
        host_id="host-a",
        payload_type="auth",
        payload={"user": "a", "result": "success", "src": "host-b"},
        secret=secret,
        event_id="e1",
        ts_utc="2026-07-25T12:00:00Z",
        nonce="n1",
    )
    from dataclasses import replace

    bad = replace(
        sign_envelope(
            producer_id="prod-a",
            host_id="host-a",
            payload_type="auth",
            payload={"user": "a", "result": "success", "src": "host-b"},
            secret=secret,
            event_id="e2",
            ts_utc="2026-07-25T12:00:01Z",
            nonce="n2",
        ),
        hmac="ff" * 32,
    )
    corr = Correlator(
        CampaignStore(tmp_path / "c.jsonl"),
        AuditLog(tmp_path / "a.jsonl"),
        enrollment=enr,
    )
    corr.ingest([good, bad])
    assert corr.hmac_rejected == 1
    assert len(corr._events) == 1


def test_resign_keeps_verified_tags_foreign(tmp_path: Path):
    enr = generate_lab_enrollment({"host-a": "prod-a"})
    foreign = generate_lab_enrollment({"host-a": "prod-a"})
    secret = enr.require("prod-a", "host-a")
    env = sign_envelope(
        producer_id="prod-a",
        host_id="host-a",
        payload_type="auth",
        payload={"user": "a", "result": "success"},
        secret=secret,
        event_id="e1",
        ts_utc="2026-07-25T12:00:00Z",
        nonce="n1",
    )
    kept = resign_events([env], enr)
    assert kept[0].hmac == env.hmac
    assert "_corvex_provenance" not in kept[0].payload

    stamped = resign_events([env], foreign)
    assert stamped[0].hmac != env.hmac
    assert stamped[0].payload.get("_corvex_provenance") == "locally_stamped"
