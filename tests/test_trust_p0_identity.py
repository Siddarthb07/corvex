"""Trust-model hardening: 1:1 producer↔host + fail-closed contain authz."""

from __future__ import annotations

import pytest

from corvex.auth import AuthError, Enrollment, generate_lab_enrollment
from corvex.contain import ContainGateError
from corvex.contain.dry_run import propose_action
from corvex.contain.live import execute_live


def test_enrollment_rejects_multihost_producer_by_default():
    with pytest.raises(AuthError, match="1:1"):
        Enrollment(
            {"prod-agg": {"host-a", "host-b"}},
            {"prod-agg": b"unit-test-secret-not-default-aa"},
        )


def test_enrollment_allows_multihost_when_explicit():
    enr = Enrollment(
        {"prod-agg": {"host-a", "host-b"}},
        {"prod-agg": b"unit-test-secret-not-default-bb"},
        allow_multihost_producer=True,
    )
    assert enr.allowed("prod-agg", "host-a")
    assert enr.allowed("prod-agg", "host-b")


def test_generate_lab_enrollment_stays_one_to_one():
    enr = generate_lab_enrollment(
        {"host-a": "prod-a", "host-b": "prod-b", "host-c": "prod-c"}
    )
    assert enr.to_public_dict() == {
        "prod-a": ["host-a"],
        "prod-b": ["host-b"],
        "prod-c": ["host-c"],
    }


def test_live_contain_authz_fail_closed_when_unset(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    (tmp_path / "reports").mkdir()
    # Satisfy earlier gates enough to reach authz check: CONTAIN on + L1 + hostile bus
    # are enforced before authz — stub by patching require_contain / gates.
    monkeypatch.setenv("CORVEX_CONTAIN", "1")
    monkeypatch.delenv("CORVEX_CONTAIN_AUTHZ", raising=False)

    from corvex.contain import live as live_mod

    monkeypatch.setattr(live_mod, "require_contain", lambda root=None: None)
    monkeypatch.setattr(
        live_mod,
        "live_gates_satisfied",
        lambda root=None: {
            "ready": True,
            "corvex_contain": 1,
            "l1_complete": True,
            "hostile_bus_ok": True,
            "hostile_bus_note": "ok",
            "os_executor_implemented": False,
            "honesty": "test",
        },
    )

    env = propose_action("IsolateHost", {"host_id": "host-a"}, rationale="test")
    live_env = env.__class__(
        schema_ver=env.schema_ver,
        verb=env.verb,
        target=dict(env.target),
        impact_class=env.impact_class,
        dry_run=False,
        idempotency_key=env.idempotency_key,
        expiry=env.expiry,
        policy_version=env.policy_version,
        rationale=env.rationale,
    )
    with pytest.raises(ContainGateError, match="CORVEX_CONTAIN_AUTHZ unset"):
        execute_live(live_env, root=tmp_path, authz_token="anything")


def test_live_contain_rejects_hardcoded_default_token(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    (tmp_path / "reports").mkdir()
    monkeypatch.setenv("CORVEX_CONTAIN", "1")
    monkeypatch.setenv("CORVEX_CONTAIN_AUTHZ", "lab-dual-control-token")

    from corvex.contain import live as live_mod

    monkeypatch.setattr(live_mod, "require_contain", lambda root=None: None)
    monkeypatch.setattr(
        live_mod,
        "live_gates_satisfied",
        lambda root=None: {
            "ready": True,
            "corvex_contain": 1,
            "l1_complete": True,
            "hostile_bus_ok": True,
            "hostile_bus_note": "ok",
            "os_executor_implemented": False,
            "honesty": "test",
        },
    )

    env = propose_action("IsolateHost", {"host_id": "host-a"}, rationale="test")
    live_env = env.__class__(
        schema_ver=env.schema_ver,
        verb=env.verb,
        target=dict(env.target),
        impact_class=env.impact_class,
        dry_run=False,
        idempotency_key=env.idempotency_key,
        expiry=env.expiry,
        policy_version=env.policy_version,
        rationale=env.rationale,
    )
    with pytest.raises(ContainGateError, match="forbidden default"):
        execute_live(
            live_env,
            root=tmp_path,
            authz_token="lab-dual-control-token",
        )


def test_load_enrollment_migrates_legacy_multihost(tmp_path):
    import json

    from corvex.auth import load_enrollment

    path = tmp_path / "enrollment.json"
    path.write_text(
        json.dumps(
            {
                "hosts": {"prod-b": ["host-b", "host-b-dhcp"]},
                "secrets_hex": {
                    "prod-b": b"unit-test-secret-not-default-mm".hex()
                },
            }
        ),
        encoding="utf-8",
    )
    enr = load_enrollment(path)
    public = enr.to_public_dict()
    assert public["prod-b"] == ["host-b"]
    assert any(h == ["host-b-dhcp"] for h in public.values())
    enr2 = load_enrollment(path)
    assert enr2.to_public_dict() == public
