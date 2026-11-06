"""Live contain executor — gated; Windows Firewall self-isolate when unlocked.

When L1 checklist is complete, hostile-bus selftest has passed, and
CORVEX_CONTAIN!=0:
  - lab_dir set → write sandbox flags (same as lab_flag)
  - else on Windows with local host_id match → Windows Firewall IsolateHost/ReleaseHost
  - else → refuse with honest cannot_quarantine

Never reports enforced=True for EDR/VLAN. Windows Firewall ≠ enterprise quarantine.
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
from corvex.contain.windows_firewall import isolate_local, release_local


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
        "os_executor_implemented": True,
        "os_executor_kind": "windows_firewall_self_isolate",
        "honesty": (
            "When ready=true, Windows Firewall self-isolate / release is available "
            "for the local host_id. Not EDR/VLAN. Lab flags still available via lab_dir."
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
    Mutates lab flags when lab_dir provided; else Windows Firewall for local host.
    """
    root = Path(root) if root else Path(__file__).resolve().parents[2]
    require_contain(root=root)
    gates = live_gates_satisfied(root)
    if not gates["hostile_bus_ok"]:
        raise ContainGateError(gates["hostile_bus_note"])
    if int(os.environ.get("CORVEX_CONTAIN", CORVEX_CONTAIN) or 0) == 0:
        raise ContainGateError("CORVEX_CONTAIN=0 — live path locked")

    expected = expected_authz if expected_authz is not None else os.environ.get("CORVEX_CONTAIN_AUTHZ")
    if expected is None or not str(expected).strip():
        raise ContainGateError(
            "CORVEX_CONTAIN_AUTHZ unset — refuse live contain (no hardcoded dual-control fallback)"
        )
    expected = str(expected).strip()
    if expected.lower() in (
        "lab-dual-control-token",
        "changeme",
        "shared",
        "default",
    ):
        raise ContainGateError(
            "CORVEX_CONTAIN_AUTHZ is a forbidden default/shared token — set a unique secret"
        )
    try:
        validate_action_envelope(
            envelope,
            require_authz_token=expected,
            authz_presented=authz_token,
        )
    except HostileBusError as exc:
        raise ContainGateError(str(exc)) from exc

    from corvex.contain.policy import load_policy, soc_set

    pol = load_policy()
    host_id = str(envelope.target.get("host_id") or "")
    verb = str(envelope.verb)

    # SOC allowlist never isolated (casefold compare).
    if host_id and host_id.lower() in soc_set(pol):
        if verb != "ReleaseHost":
            return {
                "result": "refused_soc",
                "enforced": False,
                "host_id": host_id,
                "honesty": "SOC allowlist host — refuse IsolateHost / EstateLockdown.",
                "gates": gates,
            }

    # EstateLockdown (even single-host apply of an estate target) needs dual-control.
    scope = str(envelope.target.get("scope_verb") or verb)
    if scope == "EstateLockdown" and verb != "ReleaseHost":
        second = os.environ.get("CORVEX_CONTAIN_AUTHZ_B", "").strip()
        presented_b = os.environ.get("CORVEX_CONTAIN_AUTHZ_B_PRESENTED", "").strip()
        if not second or presented_b != second or second.lower() in (
            "lab-dual-control-token",
            "changeme",
            "shared",
            "default",
        ):
            raise ContainGateError(
                "EstateLockdown requires dual-control: set CORVEX_CONTAIN_AUTHZ_B "
                "and CORVEX_CONTAIN_AUTHZ_B_PRESENTED to the same unique secret"
            )

    store = AntiReplayStore(replay_path or (root / "reports" / "contain_anti_replay.txt"))
    try:
        store.check_and_remember(envelope.idempotency_key)
    except HostileBusError as exc:
        raise ContainGateError(str(exc)) from exc

    if lab_dir is not None:
        lab = Path(lab_dir)
        isolated = lab / "isolated"
        isolated.mkdir(parents=True, exist_ok=True)
        if verb == "ReleaseHost":
            flag = isolated / f"{host_id}.flag"
            if flag.exists():
                flag.unlink()
            return {
                "result": "lab_flag_released",
                "enforced": False,
                "host_id": host_id,
                "honesty": "Sandbox flag removed — not OS firewall.",
                "gates": gates,
            }
        flag = isolated / f"{host_id}.flag"
        flag.write_text(
            json.dumps(
                {
                    "ts": now_iso(),
                    "by": "corvex.contain.live",
                    "rationale": envelope.rationale,
                    "mode": "lab_flag",
                    "verb": verb,
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

    if verb == "ReleaseHost":
        rec = release_local(host_id, root=root)
        return {**rec, "gates": gates}

    if verb in ("IsolateHost", "EstateLockdown"):
        # EstateLockdown at the edge is still per-host local firewall apply.
        rec = isolate_local(host_id, rationale=envelope.rationale, root=root)
        return {**rec, "gates": gates}

    return {
        "result": "cannot_quarantine",
        "enforced": False,
        "host_id": host_id,
        "honesty": f"Verb {verb} has no live OS executor (typed refuse).",
        "gates": gates,
    }


def attempt_live_quarantine(
    host_ids: Sequence[str],
    *,
    rationale: str,
    root: Optional[Path] = None,
    lab_dir: Optional[Path] = None,
    authz_token: Optional[str] = None,
    verb: str = "IsolateHost",
) -> Dict[str, Any]:
    """Propose live IsolateHost per host; aggregate honest results."""
    from corvex.contain.policy import (
        enforce_blast_cap,
        filter_soc,
        load_policy,
        needs_dual_control,
    )

    pol = load_policy()
    use_verb = verb if verb in ("IsolateHost", "ReleaseHost", "EstateLockdown") else "IsolateHost"
    scope = "estate_lockdown" if use_verb == "EstateLockdown" else "flagged"
    filtered = filter_soc(list(host_ids), pol) if use_verb != "ReleaseHost" else list(host_ids)
    soc_stripped = [h for h in host_ids if h not in filtered and use_verb != "ReleaseHost"]

    if use_verb == "EstateLockdown":
        # EstateLockdown: targets already should be estate-SOC; still re-filter.
        filtered = filter_soc(list(host_ids), pol)
        scope = "estate_lockdown"
        band = "critical"
    elif len(filtered) > 1:
        band = "medium"
        scope = "peer_risk"
    else:
        band = "low"

    if use_verb != "ReleaseHost":
        blast = enforce_blast_cap(
            filtered, estate_n=max(len(host_ids), len(filtered), 1), band=band, policy=pol
        )
        if blast.get("refused"):
            return {
                "ok": False,
                "aggregate": "blast_refused",
                "message": blast.get("honesty") or "Blast radius refuse.",
                "hosts": [
                    {
                        "host_id": h,
                        "result": "refused",
                        "enforced": False,
                        "honesty": blast.get("honesty"),
                    }
                    for h in filtered
                ],
                "soc_stripped": soc_stripped,
                "ts": now_iso(),
                "live_path": True,
            }
        filtered = list(blast.get("targets") or [])

    if needs_dual_control(filtered, scope=scope, policy=pol) and use_verb != "ReleaseHost":
        second = os.environ.get("CORVEX_CONTAIN_AUTHZ_B", "").strip()
        presented_b = os.environ.get("CORVEX_CONTAIN_AUTHZ_B_PRESENTED", "").strip()
        if not second or presented_b != second:
            return {
                "ok": False,
                "aggregate": "dual_control_required",
                "message": (
                    "Multi-host / estate enforce requires CORVEX_CONTAIN_AUTHZ_B "
                    "and CORVEX_CONTAIN_AUTHZ_B_PRESENTED (matching unique secret)."
                ),
                "hosts": [
                    {
                        "host_id": h,
                        "result": "refused",
                        "enforced": False,
                        "honesty": "dual_control_required",
                    }
                    for h in filtered
                ],
                "soc_stripped": soc_stripped,
                "ts": now_iso(),
                "live_path": True,
            }

    results = []
    for host in filtered:
        edge_verb = "IsolateHost" if use_verb == "EstateLockdown" else use_verb
        target = {"host_id": host}
        if use_verb == "EstateLockdown":
            target["scope_verb"] = "EstateLockdown"
        env = propose_action(edge_verb, target, rationale=rationale)  # type: ignore[arg-type]
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

    for h in soc_stripped:
        results.append(
            {
                "host_id": h,
                "result": "refused_soc",
                "enforced": False,
                "honesty": "SOC allowlist — stripped before live apply.",
            }
        )

    any_lab = any(r.get("result") == "lab_flag_written" for r in results)
    any_os = any(r.get("result") in ("os_isolated", "already_isolated") for r in results)
    any_released = any(
        r.get("result") in ("released", "lab_flag_released") for r in results
    )
    wanted = [r for r in results if r.get("result") != "refused_soc"]
    all_ok = bool(wanted) and all(
        r.get("result")
        in (
            "os_isolated",
            "already_isolated",
            "lab_flag_written",
            "released",
            "lab_flag_released",
        )
        for r in wanted
    )
    if all_ok and any_os:
        aggregate = "windows_firewall_isolated"
        ok = True
        message = "Windows Firewall isolate verified on all requested non-SOC targets."
    elif all_ok and any_lab:
        aggregate = "lab_quarantined"
        ok = True
        message = "Lab flags written under live path for all requested non-SOC targets."
    elif all_ok and any_released and use_verb == "ReleaseHost":
        aggregate = "windows_firewall_released"
        ok = True
        message = "Windows Firewall isolate rules removed (or were already absent)."
    elif any_os:
        aggregate = "partial_os_quarantine"
        ok = False
        message = "Partial Windows Firewall isolate — not all targets enforced."
    elif all(r.get("result") == "cannot_quarantine" for r in wanted) and wanted:
        aggregate = "cannot_quarantine"
        ok = False
        message = "Gates may pass but executor refused — honest refusal."
    else:
        aggregate = "refused"
        ok = False
        message = "Live quarantine refused (checklist / hostile-bus / CONTAIN / authz / not-local / SOC / blast)."

    return {
        "ok": ok,
        "aggregate": aggregate,
        "message": message,
        "hosts": results,
        "soc_stripped": soc_stripped,
        "ts": now_iso(),
        "live_path": True,
    }
