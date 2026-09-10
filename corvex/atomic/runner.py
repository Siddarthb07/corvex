"""Gated Atomic Red Team runner — shells out to Invoke-AtomicTest.

Never vendors Atomic bodies. Hashes stdout/stderr instead of dumping payloads.
"""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Dict, List, Mapping, Optional, Sequence

from corvex.atomic.bindings import is_curated
from corvex.atomic.playbook import bound_atomic_steps, steps_for_role
from corvex.stage_b import stage_b_status

InvokeFn = Callable[[List[str], Optional[Path]], "InvokeResult"]


class AtomicGateError(RuntimeError):
    pass


class InvokeResult:
    def __init__(
        self,
        *,
        returncode: int,
        stdout: str = "",
        stderr: str = "",
        argv: Optional[Sequence[str]] = None,
    ) -> None:
        self.returncode = returncode
        self.stdout = stdout or ""
        self.stderr = stderr or ""
        self.argv = list(argv or [])


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def _sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8", errors="replace")).hexdigest()


def _env_truthy(name: str) -> bool:
    return os.environ.get(name, "").strip() in {"1", "true", "TRUE", "yes", "YES"}


def require_atomic_gates(
    *,
    authorize: bool,
    report_dir: Optional[Path] = None,
    skip_stage_b: bool = False,
) -> None:
    """CORVEX_ATOMIC=1 + --i-authorize-lab-ttp + Stage B unlock."""
    if not _env_truthy("CORVEX_ATOMIC"):
        raise AtomicGateError(
            "Atomic replay locked. Set CORVEX_ATOMIC=1 for this shell "
            "(lab purple-team only; does not flip claim_allowed)."
        )
    if not authorize:
        raise AtomicGateError(
            "Atomic replay locked. Pass --i-authorize-lab-ttp to confirm "
            "this is an authorized lab host."
        )
    if skip_stage_b:
        return
    status = stage_b_status(Path(report_dir) if report_dir else None)
    if not status.get("allowed"):
        msg = (
            "Stage B locked. Need held-out PASS + human stranger_dry_run.json + "
            "reports/stage-b-allowed, or: corvex stage-b-lab-unlock --reason '…'."
        )
        if status.get("env_override_ignored"):
            msg += " CORVEX_STAGE_B=1 is ignored (removed)."
        if status.get("stranger_note"):
            msg += f" ({status['stranger_note']})"
        raise AtomicGateError(msg)


def find_powershell() -> Optional[str]:
    for name in ("pwsh", "powershell"):
        path = shutil.which(name)
        if path:
            return path
    return None


def preflight(
    *,
    authorize: bool,
    report_dir: Optional[Path] = None,
    check_invoke: bool = True,
    skip_stage_b: bool = False,
    require_powershell: bool = True,
) -> Dict[str, Any]:
    """Validate gates + tooling. Returns status dict; raises AtomicGateError on hard fail."""
    require_atomic_gates(
        authorize=authorize,
        report_dir=report_dir,
        skip_stage_b=skip_stage_b,
    )
    ps = find_powershell()
    if not ps and require_powershell:
        raise AtomicGateError(
            "PowerShell not found (pwsh/powershell). Install PowerShell to run ART."
        )
    if not ps:
        ps = "powershell"
    atomics_path = os.environ.get("ATOMICS_PATH") or os.environ.get("ATOMIC_REDTTEAM_PATH")
    invoke_ok = None
    invoke_note = None
    if check_invoke:
        probe = (
            "try { "
            "Get-Command Invoke-AtomicTest -ErrorAction Stop | Out-Null; "
            "Write-Output 'OK' "
            "} catch { Write-Output ('MISSING:' + $_.Exception.Message); exit 2 }"
        )
        try:
            proc = subprocess.run(
                [ps, "-NoProfile", "-NonInteractive", "-Command", probe],
                capture_output=True,
                text=True,
                timeout=60,
                check=False,
            )
            out = (proc.stdout or "").strip()
            if proc.returncode == 0 and out.startswith("OK"):
                invoke_ok = True
            else:
                invoke_ok = False
                invoke_note = (
                    "Invoke-AtomicTest not found. Install Invoke-AtomicRedTeam "
                    "and set ATOMICS_PATH. See docs/atomic-replay.md."
                )
                raise AtomicGateError(invoke_note)
        except subprocess.TimeoutExpired as exc:
            raise AtomicGateError("Invoke-AtomicTest probe timed out") from exc

    return {
        "powershell": ps,
        "atomics_path": atomics_path,
        "invoke_atomic_ok": invoke_ok,
        "invoke_note": invoke_note,
        "corvex_atomic": True,
        "authorized": True,
    }


def _ps_quote(value: str) -> str:
    return "'" + str(value).replace("'", "''") + "'"


def build_invoke_script(
    *,
    technique: str,
    test_number: int,
    get_prereqs: bool,
    cleanup: bool,
    input_args: Optional[Mapping[str, Any]] = None,
    atomics_path: Optional[str] = None,
    phase: str,
) -> str:
    """Build a PowerShell one-liner for prereq | test | cleanup phases."""
    parts: List[str] = []
    if atomics_path:
        parts.append(f"$env:ATOMICS_PATH = {_ps_quote(atomics_path)}")
    tech_q = _ps_quote(technique)
    args_frag = ""
    if input_args:
        # Hashtable literal for -InputArgs @{ k = 'v'; ... }
        kv = []
        for k, v in input_args.items():
            kv.append(f"{k} = {_ps_quote(str(v))}")
        args_frag = " -InputArgs @{" + "; ".join(kv) + "}"
    if phase == "prereq":
        parts.append(
            f"Invoke-AtomicTest {tech_q} -TestNumbers {int(test_number)} "
            f"-GetPrereqs{args_frag}"
        )
    elif phase == "test":
        parts.append(
            f"Invoke-AtomicTest {tech_q} -TestNumbers {int(test_number)}{args_frag}"
        )
    elif phase == "cleanup":
        parts.append(
            f"Invoke-AtomicTest {tech_q} -TestNumbers {int(test_number)} "
            f"-Cleanup{args_frag}"
        )
    else:
        raise ValueError(f"unknown phase {phase}")
    # Silence unused flags for callers that pass get_prereqs/cleanup into builder
    _ = get_prereqs
    _ = cleanup
    return "; ".join(parts)


def default_invoke(argv: List[str], cwd: Optional[Path] = None) -> InvokeResult:
    proc = subprocess.run(
        argv,
        capture_output=True,
        text=True,
        timeout=600,
        check=False,
        cwd=str(cwd) if cwd else None,
    )
    return InvokeResult(
        returncode=proc.returncode,
        stdout=proc.stdout or "",
        stderr=proc.stderr or "",
        argv=argv,
    )


def _append_journal(path: Path, rec: Mapping[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as fh:
        fh.write(json.dumps(rec, separators=(",", ":")) + "\n")


def run_playbook(
    playbook: Mapping[str, Any],
    *,
    role: str,
    run_dir: Path,
    authorize: bool,
    allow_unlisted: bool = False,
    report_dir: Optional[Path] = None,
    dry_run: bool = False,
    check_invoke: bool = True,
    skip_stage_b: bool = False,
    invoke: Optional[InvokeFn] = None,
    sleep_fn: Callable[[float], None] = time.sleep,
) -> Dict[str, Any]:
    """Execute bound Atomic steps for ``role``. Returns summary dict."""
    run_dir = Path(run_dir)
    run_dir.mkdir(parents=True, exist_ok=True)
    journal = run_dir / "atomic_exec.jsonl"

    pf = preflight(
        authorize=authorize,
        report_dir=report_dir,
        check_invoke=check_invoke and not dry_run and invoke is None,
        skip_stage_b=skip_stage_b,
        require_powershell=not dry_run and invoke is None,
    )
    ps = pf["powershell"]
    atomics_path = pf.get("atomics_path")
    inv = invoke or default_invoke

    role_steps = steps_for_role(playbook, role)
    bound = bound_atomic_steps(role_steps)
    if not bound:
        raise AtomicGateError(
            f"No bound Atomic steps for role={role!r}. "
            "Run corvex atomic-bind and ensure steps for this host have atomic blocks."
        )

    # Also journal skips for other hosts (visibility)
    for step in playbook.get("steps") or []:
        host = str(step.get("host") or "")
        if host != role:
            _append_journal(
                journal,
                {
                    "kind": "skipped_wrong_role",
                    "ts_utc": _now(),
                    "host": host,
                    "role": role,
                    "technique": step.get("technique"),
                    "kind_step": step.get("kind"),
                },
            )

    executed: List[Dict[str, Any]] = []
    failed = 0
    last_offset = 0.0

    for step in bound:
        atomic = step["atomic"]
        tech = str(atomic.get("technique") or step.get("technique") or "")
        test_number = int(atomic["test_number"])
        if not is_curated(tech) and not allow_unlisted:
            raise AtomicGateError(
                f"Technique {tech} is not in the curated allowlist. "
                "Re-bind with a curated technique or pass --allow-unlisted."
            )

        offset = float(step.get("offset_seconds") or 0)
        delay = max(0.0, offset - last_offset)
        if delay > 0 and not dry_run:
            sleep_fn(delay)
        last_offset = offset

        phases: List[str] = []
        if atomic.get("get_prereqs", True):
            phases.append("prereq")
        phases.append("test")
        if atomic.get("cleanup", True):
            phases.append("cleanup")

        step_rec: Dict[str, Any] = {
            "kind": "atomic_step",
            "ts_utc": _now(),
            "host": step.get("host"),
            "role": role,
            "technique": tech,
            "test_number": test_number,
            "offset_seconds": offset,
            "phases": [],
            "dry_run": dry_run,
        }

        for phase in phases:
            script = build_invoke_script(
                technique=tech,
                test_number=test_number,
                get_prereqs=bool(atomic.get("get_prereqs", True)),
                cleanup=bool(atomic.get("cleanup", True)),
                input_args=atomic.get("input_args") or {},
                atomics_path=atomics_path if isinstance(atomics_path, str) else None,
                phase=phase,
            )
            argv = [ps, "-NoProfile", "-NonInteractive", "-Command", script]
            if dry_run:
                phase_rec = {
                    "phase": phase,
                    "argv_hash": _sha256_text(" ".join(argv)),
                    "returncode": 0,
                    "stdout_sha256": None,
                    "stderr_sha256": None,
                    "dry_run": True,
                }
            else:
                result = inv(argv, run_dir)
                phase_rec = {
                    "phase": phase,
                    "argv_hash": _sha256_text(" ".join(result.argv or argv)),
                    "returncode": result.returncode,
                    "stdout_sha256": _sha256_text(result.stdout),
                    "stderr_sha256": _sha256_text(result.stderr),
                    "stdout_bytes": len(result.stdout.encode("utf-8", errors="replace")),
                    "stderr_bytes": len(result.stderr.encode("utf-8", errors="replace")),
                }
                if result.returncode != 0:
                    failed += 1
            step_rec["phases"].append(phase_rec)

        _append_journal(journal, step_rec)
        executed.append(step_rec)

    summary = {
        "schema_ver": "1",
        "kind": "atomic_run_summary",
        "campaign_id": playbook.get("campaign_id"),
        "role": role,
        "run_dir": str(run_dir),
        "journal": str(journal),
        "executed": len(executed),
        "failed_phases": failed,
        "techniques": [e["technique"] for e in executed],
        "dry_run": dry_run,
        "honesty": (
            "Lab Atomic replay journal only. Does not flip claim_allowed. "
            "Payload bodies are not stored — hashes only."
        ),
        "finished_at": _now(),
    }
    (run_dir / "atomic_summary.json").write_text(
        json.dumps(summary, indent=2) + "\n", encoding="utf-8"
    )
    return summary
