"""Stage B — gated: one OS sensor + NATS JetStream mTLS; habit-loop metric; no actuators.

Honest unlock: held-out Stage A PASS + human stranger dry-run + reports/stage-b-allowed.

Lab unlock (does NOT flip claim_allowed): ``corvex stage-b-lab-unlock`` writes
``reports/stage-b-lab-override.json``. The old ``CORVEX_STAGE_B=1`` env bypass is gone.
"""

from __future__ import annotations

import json
import os
import ssl
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterator, Optional

from corvex.envelope import EventEnvelope

ROOT = Path(__file__).resolve().parents[1]
LAB_OVERRIDE_NAME = "stage-b-lab-override.json"


class StageBGateError(RuntimeError):
    pass


def _stranger_human_ok(sdata: Dict[str, Any]) -> bool:
    """Agent / author self-attestation must not unlock Stage B or claims."""
    if not bool(sdata.get("pass")):
        return False
    op = str(sdata.get("operator") or sdata.get("operator_id") or "").strip().lower()
    if not op or op in {"replace", "author", "self", "n/a", "none"}:
        return False
    if "agent" in op or op.startswith("cursor-") or op.startswith("ci-"):
        return False
    kind = str(sdata.get("attestation_kind") or "").strip().lower()
    if kind and kind != "human":
        return False
    # Prefer explicit human marker; allow legacy human files without the field
    # only when operator does not look automated.
    if kind == "human":
        return True
    return True


def lab_override_path(report_dir: Optional[Path] = None) -> Path:
    return Path(report_dir or Path("reports")) / LAB_OVERRIDE_NAME


def write_lab_override(
    report_dir: Optional[Path] = None,
    *,
    reason: str,
) -> Path:
    """Auditable local-lab unlock file. Does not flip claim_allowed."""
    reason = (reason or "").strip()
    if len(reason) < 8:
        raise StageBGateError("lab unlock requires --reason (min 8 chars)")
    rd = Path(report_dir or Path("reports"))
    rd.mkdir(parents=True, exist_ok=True)
    path = rd / LAB_OVERRIDE_NAME
    payload = {
        "schema_ver": "1",
        "kind": "stage_b_lab_override",
        "reason": reason,
        "created_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "honesty": (
            "Local lab unlock only. Does not flip claim_allowed. "
            "Not a stranger attestation. Remove when done."
        ),
    }
    path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    return path


def _lab_override_ok(rd: Path) -> bool:
    path = rd / LAB_OVERRIDE_NAME
    if not path.exists():
        return False
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return False
    return data.get("kind") == "stage_b_lab_override" and bool(data.get("reason"))


def stage_b_status(report_dir: Optional[Path] = None) -> Dict[str, Any]:
    rd = Path(report_dir or Path("reports"))
    gate_txt = rd / "stageA-gate.txt"
    stage_a = rd / "stageA.json"
    if not stage_a.exists():
        stage_a = rd / "stageA_heldout.json"
    stranger = rd / "stranger_dry_run.json"
    allowed_marker = rd / "stage-b-allowed"

    passed = False
    if gate_txt.exists() and gate_txt.read_text(encoding="utf-8").strip() == "PASS":
        passed = True
    elif stage_a.exists():
        data = json.loads(stage_a.read_text(encoding="utf-8"))
        passed = bool(data.get("gate", {}).get("pass", data.get("pass")))

    # Env bypass removed (council). Detect leftover env for honest messaging only.
    env_present = (
        os.environ.get("CORVEX_STAGE_B") == "1" or os.environ.get("CFUSE_STAGE_B") == "1"
    )

    stranger_ok = False
    stranger_note = None
    if stranger.exists():
        try:
            sdata = json.loads(stranger.read_text(encoding="utf-8"))
            stranger_ok = _stranger_human_ok(sdata)
            if bool(sdata.get("pass")) and not stranger_ok:
                stranger_note = (
                    "stranger_dry_run pass ignored — operator looks like an agent "
                    "or attestation_kind is not human"
                )
        except (json.JSONDecodeError, OSError):
            stranger_ok = False
    marker_ok = allowed_marker.exists()
    lab_override = _lab_override_ok(rd)
    allowed = lab_override or (passed and stranger_ok and marker_ok)
    return {
        "allowed": allowed,
        "pass": passed,
        "stranger_dry_run": stranger_ok,
        "stage_b_allowed_marker": marker_ok,
        "lab_override": lab_override,
        "env_override_ignored": env_present,
        "stranger_note": stranger_note,
    }


def require_stage_b(report_path: Optional[Path] = None) -> None:
    status = stage_b_status(Path(report_path).parent if report_path else None)
    if not status["allowed"]:
        msg = (
            "Stage B locked. Need held-out PASS + human stranger_dry_run.json + "
            "reports/stage-b-allowed, or: corvex stage-b-lab-unlock --reason '…'."
        )
        if status.get("env_override_ignored"):
            msg += " CORVEX_STAGE_B=1 is ignored (removed)."
        if status.get("stranger_note"):
            msg += f" ({status['stranger_note']})"
        raise StageBGateError(msg)


class SysmonJsonSensor:
    """One OS sensor adapter — reads exported Sysmon-like JSONL (observe-only)."""

    def __init__(self, path: Path) -> None:
        require_stage_b()
        self.path = Path(path)

    def iter_raw(self) -> Iterator[dict]:
        with self.path.open("r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line:
                    yield json.loads(line)


class JetStreamBus:
    """NATS JetStream EventBus — mTLS required before remote publish (Stage B+)."""

    def __init__(
        self,
        url: str,
        *,
        subject: str = "corvex.events",
        ca_cert: Path,
        client_cert: Path,
        client_key: Path,
    ) -> None:
        require_stage_b()
        if not (Path(ca_cert).exists() and Path(client_cert).exists() and Path(client_key).exists()):
            raise StageBGateError("mTLS material required before remote publish")
        self.url = url
        self.subject = subject
        self._ssl = ssl.create_default_context(cafile=str(ca_cert))
        self._ssl.load_cert_chain(str(client_cert), str(client_key))
        self._cursor = "0"
        self._connected = False

    def connect(self) -> None:
        require_stage_b()
        try:
            import nats  # noqa: F401
        except ImportError as e:
            raise StageBGateError("Install nats-py for JetStreamBus (optional stageb extra)") from e
        self._connected = True

    def publish(self, envelope: EventEnvelope) -> None:
        require_stage_b()
        if not self._connected:
            raise StageBGateError("JetStreamBus.connect() required before publish")
        raise NotImplementedError(
            "JetStream publish is lab-wired post-gate; mTLS context is ready. "
            "Use JsonlBus for Stage A."
        )

    def subscribe(self, cursor: Optional[str] = None) -> Iterator[EventEnvelope]:
        require_stage_b()
        raise NotImplementedError("JetStream subscribe lab-wired post-gate")
        yield  # pragma: no cover

    def commit(self, cursor: str) -> None:
        require_stage_b()
        self._cursor = cursor


def habit_loop_metric(operator_timeline_correct: bool) -> dict:
    """PASS includes habit metric: external operator correct timeline, no author help."""
    return {
        "habit_loop_pass": bool(operator_timeline_correct),
        "definition": (
            "external operator produces correct timeline from scripted purple run "
            "without author help"
        ),
    }
