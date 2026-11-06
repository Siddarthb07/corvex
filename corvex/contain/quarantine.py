"""Quarantine / isolate — attempt with honest failure modes.

Modes:
- ``dry_run`` — log IsolateHost proposals only (default product path)
- ``lab_flag`` — write sandbox flag files that virtual lab hosts honor
- ``blocked`` — refuse; live OS/EDR/VLAN quarantine not implemented

Never claim a real host was quarantined unless lab_flag actually wrote a flag
or a future live executor (gated) succeeds. Bullshit success is a bug.
"""

from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence

from corvex import CORVEX_CONTAIN
from corvex.contain import checklist_complete, contain_status, load_checklist_state
from corvex.contain.dry_run import execute_action, propose_action


def now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def resolve_quarantine_mode(
    *,
    lab_dir: Optional[Path] = None,
    root: Optional[Path] = None,
) -> Dict[str, Any]:
    """Honest capability report for dash / CLI / reconstruct."""
    st = contain_status(root=root)
    lab = Path(lab_dir) if lab_dir else _env_lab_dir()
    live_env = int(os.environ.get("CORVEX_CONTAIN", CORVEX_CONTAIN) or 0)
    l1 = checklist_complete(root=root)

    if lab is not None:
        mode = "lab_flag"
        can_attempt = True
        message = (
            "Lab quarantine available: IsolateHost writes flag files under "
            f"{lab / 'isolated'} that virtual hosts check before /auth. "
            "Not real firewall / EDR / VLAN isolation."
        )
    elif live_env != 0 and l1:
        # Live Windows Firewall path is implemented; still requires hostile-bus + authz
        # at execute time. Mode signals capability — not that auto-enforce is on.
        mode = "live_windows"
        can_attempt = True
        message = (
            "CORVEX_CONTAIN nonzero and L1 complete — Windows Firewall self-isolate "
            "available for local host_id after hostile-bus + CORVEX_CONTAIN_AUTHZ. "
            "Not EDR/VLAN. Fanout/agent required for remote peers."
        )
    elif live_env != 0 and not l1:
        mode = "blocked"
        can_attempt = False
        missing = [k for k, v in load_checklist_state(root).items() if not v]
        message = (
            "Live contain requested but Security L1 checklist incomplete. "
            f"Missing: {', '.join(missing)}. Dry-run proposals only."
        )
    else:
        mode = "dry_run"
        can_attempt = True  # can attempt dry-run log
        message = (
            "Dry-run only (CORVEX_CONTAIN=0). IsolateHost proposals are logged; "
            "no host is mutated. Lab flag quarantine requires LAB_DIR / breaktest shared volume."
        )

    return {
        "mode": mode,
        "can_attempt": can_attempt,
        "live_executor": mode in ("live_windows", "lab_flag"),
        "live_executor_kind": "windows_firewall_self_isolate"
        if mode == "live_windows"
        else ("lab_flag" if mode == "lab_flag" else None),
        "corvex_contain": live_env,
        "l1_complete": l1,
        "l1_pct": st.get("pct"),
        "lab_dir": str(lab) if lab else None,
        "message": message,
        "honesty": [
            "Corvex does not claim enterprise EDR quarantine.",
            message,
        ],
    }


def _env_lab_dir() -> Optional[Path]:
    for key in ("LAB_DIR", "CORVEX_LAB_DIR"):
        raw = os.environ.get(key, "").strip()
        if raw:
            return Path(raw)
    return None


def attempt_quarantine(
    host_ids: Sequence[str],
    *,
    rationale: str,
    lab_dir: Optional[Path] = None,
    log_path: Optional[Path] = None,
    root: Optional[Path] = None,
    enforce: bool = False,
    authz_token: Optional[str] = None,
    verb: str = "IsolateHost",
) -> Dict[str, Any]:
    """
    Attempt isolate/quarantine for each host. Returns per-host results and
    an aggregate that never claims real-world success when it didn't happen.

    ``enforce=True`` requires mode live_windows (or lab_flag) and dual-control authz.
    """
    caps = resolve_quarantine_mode(lab_dir=lab_dir, root=root)
    mode = caps["mode"]
    hosts = [str(h) for h in host_ids]
    results: List[Dict[str, Any]] = []
    lab = Path(lab_dir) if lab_dir else _env_lab_dir()

    if not hosts:
        return {
            "ok": False,
            "aggregate": "insufficient_targets",
            "mode": mode,
            "message": "No hosts to quarantine — refusing empty isolate.",
            "hosts": [],
            "capability": caps,
        }

    if mode == "blocked":
        return {
            "ok": False,
            "aggregate": "cannot_quarantine",
            "mode": mode,
            "message": caps["message"],
            "hosts": [
                {
                    "host_id": h,
                    "result": "refused",
                    "enforced": False,
                    "honesty": "Did not isolate — live path blocked / incomplete L1.",
                }
                for h in hosts
            ],
            "capability": caps,
        }

    if enforce and mode == "live_windows":
        from corvex.contain.live import attempt_live_quarantine

        live = attempt_live_quarantine(
            hosts,
            rationale=rationale,
            root=root,
            lab_dir=lab,
            authz_token=authz_token,
            verb=verb,
        )
        return {**live, "mode": mode, "capability": caps}

    if enforce and mode == "dry_run":
        return {
            "ok": False,
            "aggregate": "cannot_quarantine",
            "mode": mode,
            "message": "enforce requested but CORVEX_CONTAIN=0 — dry-run only.",
            "hosts": [
                {
                    "host_id": h,
                    "result": "refused",
                    "enforced": False,
                    "honesty": "Set CORVEX_CONTAIN!=0 + L1 + hostile-bus + AUTHZ to enforce.",
                }
                for h in hosts
            ],
            "capability": caps,
        }

    use_verb = verb if verb in ("IsolateHost", "ReleaseHost", "EstateLockdown") else "IsolateHost"
    from corvex.contain.policy import filter_soc, load_policy

    pol = load_policy()
    hosts = filter_soc(hosts, pol) if use_verb != "ReleaseHost" else hosts
    for host in hosts:
        edge = "IsolateHost" if use_verb == "EstateLockdown" else use_verb
        tgt = {"host_id": host}
        if use_verb == "EstateLockdown":
            tgt["scope_verb"] = "EstateLockdown"
        env = propose_action(
            edge,  # type: ignore[arg-type]
            tgt,
            rationale=rationale,
        )
        # Always dry-run log the proposal
        rec = execute_action(env, log_path=log_path)
        enforced = False
        result = "dry_run_logged"
        honesty = "Proposal logged only; host not mutated."

        if mode == "lab_flag" and lab is not None:
            isolated = lab / "isolated"
            isolated.mkdir(parents=True, exist_ok=True)
            flag = isolated / f"{host}.flag"
            flag.write_text(
                json.dumps(
                    {"ts": now_iso(), "by": "corvex", "rationale": rationale, "mode": "lab_flag"},
                    indent=2,
                )
                + "\n",
                encoding="utf-8",
            )
            enforced = True
            result = "lab_flag_written"
            honesty = (
                f"Sandbox flag written at {flag}. Virtual lab hosts refuse auth. "
                "Not OS firewall quarantine."
            )
            rec = {**rec, "sandbox_enforced": True, "flag": str(flag)}

        results.append(
            {
                "host_id": host,
                "result": result,
                "enforced": enforced,
                "honesty": honesty,
                "dry_run_record": rec,
            }
        )

    any_enforced = any(r["enforced"] for r in results)
    if mode == "lab_flag" and any_enforced:
        aggregate = "lab_quarantined"
        message = (
            f"Lab-quarantined {sum(1 for r in results if r['enforced'])}/{len(results)} hosts "
            "(flag file). Not real-network isolation."
        )
        ok = True
    elif mode == "dry_run":
        aggregate = "dry_run_only"
        message = (
            f"Logged IsolateHost for {len(results)} host(s). "
            "Cannot confirm real quarantine — dry-run only."
        )
        ok = True  # dry-run succeeded as designed
    else:
        aggregate = "cannot_quarantine"
        message = caps["message"]
        ok = False

    return {
        "ok": ok,
        "aggregate": aggregate,
        "mode": mode,
        "message": message,
        "hosts": results,
        "capability": caps,
        "ts": now_iso(),
    }
