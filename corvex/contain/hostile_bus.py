"""Hostile-bus checks for live contain — must pass before any live executor.

Proves: typed verbs only, authz ≠ envelope presence, anti-replay on idempotency keys,
fail-closed on bad/expired envelopes. Does not unlock OS quarantine by itself.
"""

from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Optional, Set

from corvex.contain.dry_run import ALLOWED_VERBS, ActionEnvelope


class HostileBusError(RuntimeError):
    pass


class AntiReplayStore:
    """Durable-ish idempotency / nonce store for contain commands."""

    def __init__(self, path: Path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._seen: Set[str] = set()
        if self.path.exists():
            for line in self.path.read_text(encoding="utf-8").splitlines():
                if line.strip():
                    self._seen.add(line.strip())

    def check_and_remember(self, key: str) -> None:
        if key in self._seen:
            raise HostileBusError("anti_replay: idempotency key already used")
        self._seen.add(key)
        with self.path.open("a", encoding="utf-8") as fh:
            fh.write(key + "\n")


def _parse_expiry(expiry: str) -> datetime:
    text = expiry
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    return datetime.fromisoformat(text)


def validate_action_envelope(
    envelope: ActionEnvelope | Dict[str, Any],
    *,
    now: Optional[datetime] = None,
    require_authz_token: Optional[str] = None,
    authz_presented: Optional[str] = None,
) -> None:
    """Fail-closed validation for live path. Raises HostileBusError."""
    data = envelope.to_dict() if isinstance(envelope, ActionEnvelope) else dict(envelope)
    verb = data.get("verb")
    if verb not in ALLOWED_VERBS:
        raise HostileBusError(f"typed_commands: unknown verb {verb!r}")
    if data.get("dry_run") is True:
        raise HostileBusError("live path refused dry_run=True envelope")
    now = now or datetime.now(timezone.utc)
    try:
        exp = _parse_expiry(str(data.get("expiry") or ""))
    except ValueError as exc:
        raise HostileBusError("fail_closed: bad expiry") from exc
    if exp.tzinfo is None:
        exp = exp.replace(tzinfo=timezone.utc)
    if exp < now:
        raise HostileBusError("anti_replay: envelope expired")
    # authz ≠ signature: even a well-formed envelope needs a separate authz token
    if require_authz_token is not None:
        if not authz_presented or authz_presented != require_authz_token:
            raise HostileBusError("authz_neq_sig: missing or invalid authorization token")
    target = data.get("target")
    if not isinstance(target, dict) or not target.get("host_id"):
        raise HostileBusError("fail_closed: target.host_id required")


def run_hostile_bus_selftest(tmp_dir: Path) -> Dict[str, Any]:
    """Executable self-test used by CI and claim evidence notes."""
    from corvex.contain.dry_run import propose_action

    results = []
    store = AntiReplayStore(tmp_dir / "anti_replay.txt")
    base = propose_action("IsolateHost", {"host_id": "host-a"}, rationale="test")
    live = ActionEnvelope(
        schema_ver=base.schema_ver,
        verb=base.verb,
        target=dict(base.target),
        impact_class=base.impact_class,
        dry_run=False,
        idempotency_key=base.idempotency_key,
        expiry=base.expiry,
        policy_version=base.policy_version,
        rationale=base.rationale,
    )

    # 1) unsigned/missing authz
    try:
        validate_action_envelope(live, require_authz_token="secret-authz", authz_presented=None)
        results.append({"case": "missing_authz", "pass": False})
    except HostileBusError:
        results.append({"case": "missing_authz", "pass": True})

    # 2) bad verb
    bad = {**live.to_dict(), "verb": "rm -rf", "dry_run": False}
    try:
        validate_action_envelope(bad, require_authz_token="x", authz_presented="x")
        results.append({"case": "free_form_verb", "pass": False})
    except HostileBusError:
        results.append({"case": "free_form_verb", "pass": True})

    # 3) replay
    validate_action_envelope(live, require_authz_token="tok", authz_presented="tok")
    store.check_and_remember(live.idempotency_key)
    try:
        store.check_and_remember(live.idempotency_key)
        results.append({"case": "replay", "pass": False})
    except HostileBusError:
        results.append({"case": "replay", "pass": True})

    # 4) expired
    expired = {**live.to_dict(), "expiry": "2000-01-01T00:00:00Z", "idempotency_key": "other"}
    try:
        validate_action_envelope(expired, require_authz_token="tok", authz_presented="tok")
        results.append({"case": "expired", "pass": False})
    except HostileBusError:
        results.append({"case": "expired", "pass": True})

    passed = all(r["pass"] for r in results)
    return {
        "pass": passed,
        "cases": results,
        "honesty": "Hostile-bus selftest ≠ live OS quarantine unlocked.",
    }


def hostile_bus_report_path(root: Path) -> Path:
    return Path(root) / "reports" / "hostile_bus_selftest.json"


def write_hostile_bus_report(root: Path, tmp_dir: Path) -> Dict[str, Any]:
    report = run_hostile_bus_selftest(tmp_dir)
    report["generated_at"] = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    path = hostile_bus_report_path(root)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    return report
