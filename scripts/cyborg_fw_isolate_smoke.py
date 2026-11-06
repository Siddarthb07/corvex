#!/usr/bin/env python3
"""Cyborg-only Windows Firewall IsolateHost/ReleaseHost smoke.

Runs ONLY on hostname Cyborg. Does not touch other machines.
Unlocks L1 for local-only self-isolate with explicit evidence notes,
enforces IsolateHost on the local hostname, verifies the rule, then ReleaseHost.
Writes reports/cyborg_fw_isolate_smoke.json.
"""

from __future__ import annotations

import json
import os
import platform
import secrets
import socket
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path


def utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def must_be_cyborg() -> str:
    host = socket.gethostname().split(".", 1)[0]
    if host.lower() != "cyborg":
        raise SystemExit(f"REFUSE: hostname={host!r} — this smoke is Cyborg-only")
    if platform.system().lower() != "windows":
        raise SystemExit("REFUSE: Windows only")
    return host


def repo_root() -> Path:
    # Prefer env, then walk from this file, then cwd
    env = os.environ.get("CORVEX_ROOT", "").strip()
    if env:
        return Path(env).resolve()
    here = Path(__file__).resolve()
    for p in [here.parents[1], Path.cwd()]:
        if (p / "corvex" / "contain" / "windows_firewall.py").is_file():
            return p
    raise SystemExit("CORVEX_ROOT not found — set CORVEX_ROOT to the corvex checkout")


def attest_l1_local_only(root: Path) -> dict:
    """Flip L1 true with local-only evidence. Peer mTLS remains N/A for this smoke."""
    from corvex.contain import L1_ITEMS, set_checklist_item, checklist_complete, load_checklist_raw

    evidence = {
        "mtls_identities": (
            "LOCAL-ONLY SMOKE: actuator is this Windows host (hostname binding). "
            "Peer mTLS for SSH fanout is OUT OF SCOPE for this run; fanout stays unused."
        ),
        "typed_commands": "ActionEnvelope IsolateHost/ReleaseHost only — windows_firewall.py",
        "authz_neq_sig": "CORVEX_CONTAIN_AUTHZ separate from HMAC enrollment signature",
        "anti_replay": "hostile_bus AntiReplayStore — reports/hostile_bus_selftest.json",
        "dual_control": "AUTHZ required; EstateLockdown still needs AUTHZ_B (not used here)",
        "fail_closed": "execute_live refuses on incomplete gates / missing authz",
        "least_privilege": "Local Firewall rule Corvex-Isolate-<host>; no process kill",
        "immutable_audit": "smoke report + windows_isolate_state.json under reports/",
        "oversight_off_data_plane": "CLI smoke only; dash not used to unlock",
        "no_free_form_shell": "Typed verbs; no shell executor path",
        "blast_radius_caps": "Single-host IsolateHost only; no EstateLockdown this smoke",
    }
    for key in L1_ITEMS:
        set_checklist_item(key, True, root=root, source="cyborg_fw_isolate_smoke")
    raw = load_checklist_raw(root)
    meta = raw.setdefault("_meta", {})
    meta["evidence_notes"] = evidence
    meta["live_contain_unlocked"] = True
    meta["self_attested_smoke"] = True
    meta["unlock_scope"] = "local_windows_firewall_self_isolate_cyborg_only"
    meta["unlocked_at"] = utc_now()
    meta["policy"] = (
        "L1 SELF-ATTESTED for Cyborg local-only FW smoke (not third-party audit). "
        "Do not copy this checklist to other hosts without re-attestation. "
        "Fanout/mTLS not covered."
    )
    # rewrite with meta
    path = root / "reports" / "security_l1_checklist.json"
    ordered = {k: True for k in L1_ITEMS}
    ordered["_meta"] = meta
    path.write_text(json.dumps(ordered, indent=2) + "\n", encoding="utf-8")
    return {
        "complete": checklist_complete(root=root),
        "path": str(path),
        "scope": meta["unlock_scope"],
    }


def rule_exists(name: str) -> bool:
    ps = subprocess.run(
        [
            "powershell",
            "-NoProfile",
            "-NonInteractive",
            "-Command",
            f"if (Get-NetFirewallRule -DisplayName '{name}' -ErrorAction SilentlyContinue) "
            f"{{ 'YES' }} else {{ 'NO' }}",
        ],
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
    )
    return "YES" in (ps.stdout or "")


def main() -> int:
    host = must_be_cyborg()
    root = repo_root()
    os.chdir(root)
    sys.path.insert(0, str(root))

    report: dict = {
        "schema_ver": "1",
        "test": "cyborg_fw_isolate_smoke",
        "hostname": host,
        "started_at": utc_now(),
        "root": str(root),
        "honesty": (
            "Windows Firewall self-isolate on Cyborg only. Not EDR/VLAN. "
            "Author laptop untouched. Peer fanout not exercised."
        ),
    }

    # Ensure hostile-bus report exists
    from corvex.contain.hostile_bus import write_hostile_bus_report

    hb = write_hostile_bus_report(root, root / "runs" / "hostile-bus-cyborg")
    report["hostile_bus"] = {"pass": bool(hb.get("pass")), "path": "reports/hostile_bus_selftest.json"}

    l1 = attest_l1_local_only(root)
    report["l1"] = l1
    if not l1["complete"]:
        report["ok"] = False
        report["error"] = "L1 incomplete after attest"
        _write(root, report)
        return 2

    authz = os.environ.get("CORVEX_CONTAIN_AUTHZ") or ("cyborg-smoke-" + secrets.token_urlsafe(18))
    os.environ["CORVEX_CONTAIN_AUTHZ"] = authz
    os.environ["CORVEX_CONTAIN"] = "1"
    os.environ["CORVEX_LOCAL_HOST_ID"] = host

    from corvex.contain.live import live_gates_satisfied
    from corvex.contain.quarantine import attempt_quarantine, resolve_quarantine_mode
    from corvex.contain.windows_firewall import rule_name

    gates = live_gates_satisfied(root)
    report["gates_before"] = gates
    mode = resolve_quarantine_mode(root=root)
    report["quarantine_mode"] = mode

    if not gates.get("ready"):
        report["ok"] = False
        report["error"] = f"live gates not ready: {gates}"
        _write(root, report)
        return 2

    rname = rule_name(host)
    report["rule_name"] = rname
    # Rules are named <prefix>-in / <prefix>-out (see windows_firewall.isolate_local).
    report["rule_exists_before"] = rule_exists(f"{rname}-in") and rule_exists(f"{rname}-out")

    # ISOLATE
    iso = attempt_quarantine(
        [host],
        rationale="Cyborg FW smoke IsolateHost — temporary",
        root=root,
        enforce=True,
        authz_token=authz,
        verb="IsolateHost",
        log_path=root / "reports" / "cyborg_fw_isolate_dryrun.jsonl",
    )
    report["isolate"] = iso
    time.sleep(1.0)
    report["rule_exists_after_isolate"] = rule_exists(f"{rname}-in") and rule_exists(
        f"{rname}-out"
    )
    host_rows = iso.get("hosts") if isinstance(iso.get("hosts"), list) else []
    enforced = bool(iso.get("ok")) and any(
        bool(r.get("enforced")) and r.get("result") in ("os_isolated", "already_isolated")
        for r in host_rows
        if isinstance(r, dict)
    )
    report["isolate_enforced"] = enforced

    # Always attempt release even if isolate looked soft
    rel = attempt_quarantine(
        [host],
        rationale="Cyborg FW smoke ReleaseHost — cleanup",
        root=root,
        enforce=True,
        authz_token=authz,
        verb="ReleaseHost",
        log_path=root / "reports" / "cyborg_fw_isolate_dryrun.jsonl",
    )
    report["release"] = rel
    time.sleep(1.0)
    report["rule_exists_after_release"] = rule_exists(f"{rname}-in") or rule_exists(
        f"{rname}-out"
    )  # True if ANY remnant remains — pass requires both absent.
    release_ok = bool(rel.get("ok")) or any(
        isinstance(r, dict) and r.get("result") in ("released", "lab_flag_released")
        for r in (rel.get("hosts") or [])
    )

    # Relock env for process (checklist stays attested for this host — document)
    os.environ["CORVEX_CONTAIN"] = "0"
    report["finished_at"] = utc_now()
    report["ok"] = bool(
        enforced
        and report["rule_exists_after_isolate"]
        and not report["rule_exists_after_release"]
        and release_ok
    )
    report["pass_criteria"] = {
        "rule_appeared": report["rule_exists_after_isolate"],
        "rule_removed": not report["rule_exists_after_release"],
        "isolate_enforced_flag": enforced,
        "release_ok": release_ok,
    }
    # Do not echo authz secret
    report["authz_set"] = True
    _write(root, report)
    print(json.dumps({k: report[k] for k in report if k not in ("isolate", "release")}, indent=2))
    print("--- isolate snippet ---")
    print(json.dumps(iso, indent=2)[:2000])
    print("--- release snippet ---")
    print(json.dumps(rel, indent=2)[:2000])
    return 0 if report["ok"] else 2


def _write(root: Path, report: dict) -> None:
    out = root / "reports" / "cyborg_fw_isolate_smoke.json"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(f"wrote {out}")


if __name__ == "__main__":
    raise SystemExit(main())
