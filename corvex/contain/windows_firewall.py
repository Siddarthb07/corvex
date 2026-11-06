"""Local Windows Firewall IsolateHost / ReleaseHost executor.

Typed verbs only — no free-form shell. Creates named rules ``Corvex-Isolate-<host_id>``.
``enforced=true`` only after rule create + verify. Non-Windows → honest refusal.
"""

from __future__ import annotations

import json
import os
import platform
import re
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence


RULE_PREFIX = "Corvex-Isolate-"
STATE_NAME = "windows_isolate_state.json"


def now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def is_windows() -> bool:
    return platform.system().lower() == "windows"


def _safe_id(host_id: str) -> str:
    return re.sub(r"[^A-Za-z0-9_.-]+", "-", str(host_id))[:64] or "host"


def rule_name(host_id: str) -> str:
    return f"{RULE_PREFIX}{_safe_id(host_id)}"


def local_host_id() -> str:
    env = os.environ.get("CORVEX_LOCAL_HOST_ID", "").strip()
    if env:
        return env
    try:
        import socket

        return socket.gethostname().split(".", 1)[0]
    except OSError:
        return "localhost"


def _run_ps(script: str) -> subprocess.CompletedProcess:
    return subprocess.run(
        [
            "powershell",
            "-NoProfile",
            "-NonInteractive",
            "-ExecutionPolicy",
            "Bypass",
            "-Command",
            script,
        ],
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
    )


def _rule_exists(name: str) -> bool:
    if not is_windows():
        return False
    # Prefer Get-NetFirewallRule; fall back to netsh show
    ps = _run_ps(
        f"if (Get-NetFirewallRule -DisplayName '{name}' -ErrorAction SilentlyContinue) "
        f"{{ 'YES' }} else {{ 'NO' }}"
    )
    if "YES" in (ps.stdout or ""):
        return True
    netsh = subprocess.run(
        ["netsh", "advfirewall", "firewall", "show", "rule", f"name={name}"],
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )
    out = (netsh.stdout or "") + (netsh.stderr or "")
    return "No rules match" not in out and name.lower() in out.lower()


def state_path(root: Optional[Path] = None) -> Path:
    base = Path(root) if root else Path(__file__).resolve().parents[2]
    return base / "reports" / STATE_NAME


def _load_state(root: Optional[Path] = None) -> Dict[str, Any]:
    p = state_path(root)
    if not p.is_file():
        return {"hosts": {}}
    try:
        return json.loads(p.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {"hosts": {}}


def _save_state(state: Dict[str, Any], root: Optional[Path] = None) -> None:
    p = state_path(root)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(state, indent=2) + "\n", encoding="utf-8")


def isolate_local(
    host_id: str,
    *,
    rationale: str,
    root: Optional[Path] = None,
    allow_cidrs: Optional[Sequence[str]] = None,
    force_non_local: bool = False,
) -> Dict[str, Any]:
    """Block most inbound/outbound traffic on THIS machine for host_id.

    Only succeeds when host_id matches local identity (unless force_non_local
    for lab misconfig tests — still only mutates the local firewall).
    """
    local = local_host_id()
    if not force_non_local and str(host_id).lower() not in {
        local.lower(),
        local.lower().replace("_", "-"),
        local.lower().replace("-", "_"),
    } and os.environ.get("CORVEX_ISOLATE_ANY_LOCAL", "").strip() != "1":
        # Allow enrolled aliases via env map
        aliases = {
            a.strip().lower()
            for a in os.environ.get("CORVEX_LOCAL_HOST_ALIASES", "").split(",")
            if a.strip()
        }
        if str(host_id).lower() not in aliases and str(host_id) != local:
            return {
                "result": "refused_not_local",
                "enforced": False,
                "host_id": host_id,
                "local_host_id": local,
                "honesty": (
                    f"Windows executor only mutates the local host "
                    f"(local={local}, target={host_id}). Use fanout/agent on the peer."
                ),
            }

    if not is_windows():
        return {
            "result": "cannot_quarantine",
            "enforced": False,
            "host_id": host_id,
            "honesty": "Windows Firewall executor not available on this OS.",
        }

    name = rule_name(host_id)
    if _rule_exists(f"{name}-out") and _rule_exists(f"{name}-in"):
        return {
            "result": "already_isolated",
            "enforced": True,
            "host_id": host_id,
            "rule": name,
            "honesty": "Named Corvex isolate rules already present (in+out verified).",
        }

    # Block all outbound + inbound; optional allowlist remote IPs for SOC/correlator
    allow_raw = [a for a in (allow_cidrs or []) if a]
    env_allow = os.environ.get("CORVEX_ISOLATE_ALLOW_CIDRS", "").strip()
    if env_allow:
        allow_raw.extend(x.strip() for x in env_allow.split(",") if x.strip())
    allow: List[str] = []
    for cidr in allow_raw:
        # Strict IPv4 CIDR / address — reject shell metacharacters for PS injection.
        if not re.fullmatch(
            r"(?:\d{1,3}\.){3}\d{1,3}(?:/\d{1,2})?",
            cidr,
        ):
            return {
                "result": "cannot_quarantine",
                "enforced": False,
                "host_id": host_id,
                "honesty": f"Invalid allow CIDR rejected: {cidr!r}",
            }
        allow.append(cidr)

    # Create block-all rules (in + out). Note: Windows block rules typically win
    # over later allows — treat allow_cidrs as best-effort, not guaranteed reachability.
    scripts: List[str] = [
        f"New-NetFirewallRule -DisplayName '{name}-out' -Direction Outbound "
        f"-Action Block -Enabled True -Profile Any -ErrorAction Stop",
        f"New-NetFirewallRule -DisplayName '{name}-in' -Direction Inbound "
        f"-Action Block -Enabled True -Profile Any -ErrorAction Stop",
    ]
    for i, cidr in enumerate(allow):
        scripts.append(
            f"New-NetFirewallRule -DisplayName '{name}-allow-{i}' -Direction Outbound "
            f"-Action Allow -RemoteAddress '{cidr}' -Enabled True -Profile Any -ErrorAction Stop"
        )
        scripts.append(
            f"New-NetFirewallRule -DisplayName '{name}-allow-in-{i}' -Direction Inbound "
            f"-Action Allow -RemoteAddress '{cidr}' -Enabled True -Profile Any -ErrorAction Stop"
        )

    errors: List[str] = []
    for script in scripts:
        proc = _run_ps(script)
        if proc.returncode != 0:
            errors.append((proc.stderr or proc.stdout or "firewall rule failed").strip()[:400])

    # Both inbound and outbound block rules must verify before enforced=true.
    ok_out = _rule_exists(f"{name}-out")
    ok_in = _rule_exists(f"{name}-in")
    if not (ok_out and ok_in):
        # Best-effort cleanup of partial rules
        _run_ps(
            f"Get-NetFirewallRule -DisplayName '{name}*' -ErrorAction SilentlyContinue "
            f"| Remove-NetFirewallRule -ErrorAction SilentlyContinue"
        )
        return {
            "result": "cannot_quarantine",
            "enforced": False,
            "host_id": host_id,
            "honesty": (
                "Firewall rule create/verify failed (need elevation?). "
                + "; ".join(errors[:2])
            ),
            "errors": errors or ["missing in/out rules after create"],
        }

    st = _load_state(root)
    st.setdefault("hosts", {})[str(host_id)] = {
        "ts": now_iso(),
        "rule": name,
        "rationale": rationale,
        "allow_cidrs": allow,
        "enforced": True,
    }
    _save_state(st, root)
    return {
        "result": "os_isolated",
        "enforced": True,
        "host_id": host_id,
        "rule": name,
        "allow_cidrs": allow,
        "honesty": (
            "Local Windows Firewall block rules applied and verified (in+out). "
            "Not EDR/VLAN quarantine. Allow-CIDR rules are best-effort — "
            "Windows block precedence may still cut management paths."
        ),
        "errors": errors or None,
    }


def release_local(
    host_id: str,
    *,
    root: Optional[Path] = None,
) -> Dict[str, Any]:
    if not is_windows():
        return {
            "result": "cannot_quarantine",
            "enforced": False,
            "host_id": host_id,
            "honesty": "Windows Firewall executor not available on this OS.",
        }
    name = rule_name(host_id)
    # Remove all rules with our display-name prefix
    ps = _run_ps(
        f"Get-NetFirewallRule -DisplayName '{name}*' -ErrorAction SilentlyContinue "
        f"| Remove-NetFirewallRule -ErrorAction SilentlyContinue; 'DONE'"
    )
    # Also try exact legacy single name
    _run_ps(
        f"Get-NetFirewallRule -DisplayName '{name}' -ErrorAction SilentlyContinue "
        f"| Remove-NetFirewallRule -ErrorAction SilentlyContinue"
    )
    still = _rule_exists(f"{name}-out") or _rule_exists(name)
    st = _load_state(root)
    if str(host_id) in (st.get("hosts") or {}):
        del st["hosts"][str(host_id)]
        _save_state(st, root)
    return {
        "result": "released" if not still else "release_partial",
        "enforced": False,
        "host_id": host_id,
        "rule": name,
        "honesty": (
            "Corvex isolate firewall rules removed."
            if not still
            else "Release attempted; some rules may remain — check elevation."
        ),
        "stderr_tail": (ps.stderr or "")[-300:],
    }


def isolate_status(host_id: Optional[str] = None, *, root: Optional[Path] = None) -> Dict[str, Any]:
    st = _load_state(root)
    hosts = st.get("hosts") or {}
    if host_id:
        rec = hosts.get(str(host_id))
        return {
            "host_id": host_id,
            "isolated": bool(rec and rec.get("enforced")),
            "record": rec,
            "rule_present": _rule_exists(rule_name(host_id) + "-out")
            if is_windows()
            else False,
        }
    return {"hosts": hosts, "local_host_id": local_host_id(), "windows": is_windows()}
