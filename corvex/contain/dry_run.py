"""Stage D dry-run only — proposes typed actions; never mutates hosts."""

from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Literal, Optional

from corvex.contain import ContainGateError, require_contain

ActionVerb = Literal["IsolateHost", "KillPid", "AddFirewallRule"]


@dataclass(frozen=True)
class ActionEnvelope:
    schema_ver: str
    verb: ActionVerb
    target: Dict[str, Any]
    impact_class: str
    dry_run: bool
    idempotency_key: str
    expiry: str
    policy_version: str
    rationale: str

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


ALLOWED_VERBS = ("IsolateHost", "KillPid", "AddFirewallRule")


def propose_action(
    verb: ActionVerb,
    target: Dict[str, Any],
    *,
    rationale: str,
    impact_class: str = "lab_soft",
    policy_version: str = "d0-draft",
    ttl_seconds: int = 300,
) -> ActionEnvelope:
    if verb not in ALLOWED_VERBS:
        raise ValueError(f"unknown verb {verb}")
    now = datetime.now(timezone.utc)
    expiry = datetime.fromtimestamp(now.timestamp() + ttl_seconds, tz=timezone.utc)
    key_src = f"{verb}|{json.dumps(target, sort_keys=True)}|{rationale}|{now.isoformat()}"
    return ActionEnvelope(
        schema_ver="1",
        verb=verb,
        target=target,
        impact_class=impact_class,
        dry_run=True,  # hard-locked for Stage D start
        idempotency_key=hashlib.sha256(key_src.encode()).hexdigest()[:32],
        expiry=expiry.strftime("%Y-%m-%dT%H:%M:%SZ"),
        policy_version=policy_version,
        rationale=rationale,
    )


def execute_action(envelope: ActionEnvelope, log_path: Optional[Path] = None) -> Dict[str, Any]:
    """
    Live mutation path — blocked until L1 checklist 100%.
    Dry-run always logs proposal only.
    """
    path = Path(log_path or Path("reports/stage_d_dry_run.jsonl"))
    path.parent.mkdir(parents=True, exist_ok=True)
    record = {
        "ts": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "envelope": envelope.to_dict(),
        "result": "dry_run_logged",
    }
    if not envelope.dry_run:
        # Even if someone flips dry_run, live path still hits the gate.
        require_contain()
        raise ContainGateError("Live contain executor not implemented — checklist alone is insufficient")
    with path.open("a", encoding="utf-8") as fh:
        fh.write(json.dumps(record, separators=(",", ":")) + "\n")
    return record


def status() -> Dict[str, Any]:
    from corvex.contain import contain_status

    return {
        "phase": "Stage D started — dry-run proposals only",
        "live_contain": False,
        "checklist": contain_status(),
        "allowed_verbs_draft": list(ALLOWED_VERBS),
    }
