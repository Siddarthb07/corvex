"""Abuse / security tests."""

from __future__ import annotations

import importlib
from pathlib import Path

import pytest

from corvex.auth import Enrollment
from corvex.envelope import EventEnvelope, sign_envelope, verify_envelope


def test_bad_mac_rejected():
    enr = Enrollment({"prod-a": {"host-a"}}, {"prod-a": b"unit-test-secret-not-default-zz"})
    env = sign_envelope(
        producer_id="prod-a",
        host_id="host-a",
        payload_type="auth",
        payload={"user": "u"},
        secret=enr.require("prod-a", "host-a"),
        event_id="e1",
        ts_utc="2026-01-01T00:00:00.000000Z",
        nonce="n",
    )
    data = env.to_dict()
    data["hmac"] = "0" * 64
    bad = EventEnvelope.from_dict(data)
    assert not verify_envelope(bad, enr.require("prod-a", "host-a"))


def test_package_does_not_import_drafts():
    import corvex.correlator as c

    src = Path(c.__file__).read_text(encoding="utf-8")
    assert "drafts" not in src


def test_executor_import_absent():
    with pytest.raises(ModuleNotFoundError):
        importlib.import_module("corvex.actions")
    with pytest.raises(ModuleNotFoundError):
        importlib.import_module("corvex.actuators")
