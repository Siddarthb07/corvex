"""Stage B — gated: one OS sensor + NATS JetStream mTLS; habit-loop metric; no actuators.

Unlock only after held-out Stage A PASS + stranger dry-run + reports/stage-b-allowed
(or CFUSE_STAGE_B=1 for local lab).
"""

from __future__ import annotations

import json
import os
import ssl
from pathlib import Path
from typing import Any, Dict, Iterator, Optional

from campaignfuse.envelope import EventEnvelope

ROOT = Path(__file__).resolve().parents[1]


class StageBGateError(RuntimeError):
    pass


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

    env_override = os.environ.get("CFUSE_STAGE_B") == "1"
    stranger_ok = stranger.exists()
    marker_ok = allowed_marker.exists()
    allowed = env_override or (passed and stranger_ok and marker_ok)
    return {
        "allowed": allowed,
        "pass": passed,
        "stranger_dry_run": stranger_ok,
        "stage_b_allowed_marker": marker_ok,
        "env_override": env_override,
    }


def require_stage_b(report_path: Optional[Path] = None) -> None:
    status = stage_b_status(Path(report_path).parent if report_path else None)
    if not status["allowed"]:
        raise StageBGateError(
            "Stage B locked. Need held-out PASS + reports/stranger_dry_run.json + "
            "reports/stage-b-allowed (or CFUSE_STAGE_B=1)."
        )


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
        subject: str = "campaignfuse.events",
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
