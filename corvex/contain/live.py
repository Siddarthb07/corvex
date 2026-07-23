"""Live contain executor — gated; OS quarantine not implemented.

When L1 checklist is complete, hostile-bus selftest has passed, and
CORVEX_CONTAIN!=0:
  - lab_dir set → write sandbox flags (same as lab_flag)
  - else → refuse with honest cannot_quarantine (no Windows firewall / EDR API)

Never reports enforced=True for real OS isolation.
"""

from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Optional, Sequence

from corvex import CORVEX_CONTAIN
from corvex.contain import ContainGateError, checklist_complete, require_contain
from corvex.contain.dry_run import ActionEnvelope, propose_action
from corvex.contain.hostile_bus import (
    AntiReplayStore,
    HostileBusError,
    hostile_bus_report_path,
    validate_action_envelope,
)


def now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def live_gates_satisfied(root: Optional[Path] = None) -> Dict[str, Any]:
    root = Path(root) if root else Path(__file__).resolve().parents[2]
    live_env = int(os.environ.get("CORVEX_CONTAIN", CORVEX_CONTAIN) or 0)
    l1 = checklist_complete(root=root)
    hb_path = hostile_bus_report_path(root)
    hb_ok = False
    hb_note = "missing reports/hostile_bus_selftest.json — run corvex hostile-bus-test"
    if hb_path.exists():
        data = json.loads(hb_path.read_text(encoding="utf-8"))
        hb_ok = bool(data.get("pass"))
        hb_note = "hostile_bus_selftest pass" if hb_ok else "hostile_bus_selftest FAIL"
    ready = live_env != 0 and l1 and hb_ok
    return {
        "ready": ready,
        "corvex_contain": live_env,
        "l1_complete": l1,
        "hostile_bus_ok": hb_ok,
        "hostile_bus_note": hb_note,
        "os_executor_implemented": False,
        "honesty": (
            "Even when ready=true, only lab_flag sandbox isolate is available. "
            "OS/EDR/VLAN quarantine executor is not implemented."
        ),
    }


def execute_live(
    envelope: ActionEnvelope,
    *,
    root: Optional[Path] = None,
    lab_dir: Optional[Path] = None,
    authz_token: Optional[str] = None,
    expected_authz: Optional[str] = None,
    replay_path: Optional[Path] = None,
) -> Dict[str, Any]:
    """
    Live path entry. Requires contain checklist. Validates hostile-bus rules.
    Mutates only lab flag files when lab_dir provided.
    """
    root = Path(root) if root else Path(__file__).resolve().parents[2]
    require_contain(root=root)
    gates = live_gates_satisfied(root)
    if not gates["hostile_bus_ok"]:
        raise ContainGateError(gates["hostile_bus_note"])
    if int(os.environ.get("CORVEX_CONTAIN", CORVEX_CONTAIN) or 0) == 0:
        raise ContainGateError("CORVEX_CONTAIN=0 — live path locked")

    expected = expected_authz or os.environ.get("CORVEX_CONTAIN_AUTHZ", "lab-dual-control-token")
    try:
        validate_action_envelope(
            envelope,
            require_authz_token=expected,
            authz_presented=authz_token,
        )
    except HostileBusError as exc:
        raise ContainGateError(str(exc)) from exc

    store = AntiReplayStore(replay_path or (root / "reports" / "contain_anti_replay.txt"))
    try:
        store.check_and_remember(envelope.idempotency_key)
    except HostileBusError as exc:
        raise ContainGateError(str(exc)) from exc

    host_id = str(envelope.target.get("host_id"))
    if lab_dir is not None:
        lab = Path(lab_dir)
        isolated = lab / "isolated"
        isolated.mkdir(parents=True, exist_ok=True)
        flag = isolated / f"{host_id}.flag"
        flag.write_text(
            json.dumps(
                {
                    "ts": now_iso(),
                    "by": "corvex.contain.live",
                    "rationale": envelope.rationale,
                    "mode": "lab_flag",
                },
                indent=2,
            )
            + "\n",
            encoding="utf-8",
        )
        return {
            "result": "lab_flag_written",
            "enforced": True,
            "host_id": host_id,
            "flag": str(flag),
            "honesty": "Sandbox flag only — not OS firewall quarantine.",
            "gates": gates,
        }

    return {
        "result": "cannot_quarantine",
        "enforced": False,
        "host_id": host_id,
        "honesty": (
            "Live gates passed but no OS/EDR/VLAN executor is implemented. "
            "Refusing to fake host isolation. Pass --lab-dir for sandbox flags only."
        ),
        "gates": gates,
    }


def attempt_live_quarantine(
    host_ids: Sequence[str],
    *,
    rationale: str,
    root: Optional[Path] = None,
    lab_dir: Optional[Path] = None,
    authz_token: Optional[str] = None,
) -> Dict[str, Any]:
    """Propose live IsolateHost per host; aggregate honest results."""
    results = []
    for host in host_ids:
        env = propose_action("IsolateHost", {"host_id": host}, rationale=rationale)
        # Flip to live envelope
        live_env = ActionEnvelope(
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
        try:
            rec = execute_live(
                live_env, root=root, lab_dir=lab_dir, authz_token=authz_token
            )
        except ContainGateError as exc:
            rec = {
                "result": "refused",
                "enforced": False,
                "host_id": host,
                "honesty": str(exc),
            }
        results.append(rec)

    any_lab = any(r.get("result") == "lab_flag_written" for r in results)
    any_ok_gate = any(r.get("result") not in ("refused",) for r in results)
    if any_lab:
        aggregate = "lab_quarantined"
        ok = True
        message = "Lab flags written under live path; OS quarantine still unimplemented."
    elif all(r.get("result") == "cannot_quarantine" for r in results):
        aggregate = "cannot_quarantine"
        ok = False
        message = "Gates may pass but OS executor missing — honest refusal."
    else:
        aggregate = "refused"
        ok = False
        message = "Live quarantine refused (checklist / hostile-bus / CONTAIN / authz)."

    return {
        "ok": ok,
        "aggregate": aggregate,
        "message": message,
        "hosts": results,
        "ts": now_iso(),
        "live_path": True,
    }
