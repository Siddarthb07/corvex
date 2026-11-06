"""Always-on contain agent — heartbeat + pull/apply signed ActionEnvelopes.

Lab transport: JSONL inbox under ``runs/contain-agent/inbox.jsonl`` and
heartbeat ``runs/contain-agent/heartbeat.json``. HMAC enrollment can wrap
envelopes later; v1 trusts local inbox + live gates on apply.
"""

from __future__ import annotations

import json
import os
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from corvex.contain.fanout import apply_local_from_envelope
from corvex.contain.windows_firewall import isolate_status, local_host_id


def now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def agent_dir(root: Optional[Path] = None) -> Path:
    base = Path(root) if root else Path(__file__).resolve().parents[2]
    env = os.environ.get("CORVEX_AGENT_DIR", "").strip()
    if env:
        return Path(env)
    return base / "runs" / "contain-agent"


def inbox_path(root: Optional[Path] = None) -> Path:
    return agent_dir(root) / "inbox.jsonl"


def outbox_path(root: Optional[Path] = None) -> Path:
    return agent_dir(root) / "outbox.jsonl"


def heartbeat_path(root: Optional[Path] = None) -> Path:
    return agent_dir(root) / "heartbeat.json"


def state_path(root: Optional[Path] = None) -> Path:
    return agent_dir(root) / "agent_state.json"


def enqueue_envelope(envelope: Dict[str, Any], *, root: Optional[Path] = None) -> Path:
    path = inbox_path(root)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as fh:
        fh.write(json.dumps(envelope, separators=(",", ":")) + "\n")
    return path


def write_heartbeat(root: Optional[Path] = None) -> Dict[str, Any]:
    hid = local_host_id()
    st = isolate_status(root=root)
    beat = {
        "ts": now_iso(),
        "host_id": hid,
        "isolated_hosts": list((st.get("hosts") or {}).keys()),
        "pid": os.getpid(),
    }
    path = heartbeat_path(root)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(beat, indent=2) + "\n", encoding="utf-8")
    return beat


def _read_inbox(root: Optional[Path] = None) -> List[Dict[str, Any]]:
    path = inbox_path(root)
    if not path.is_file():
        return []
    rows: List[Dict[str, Any]] = []
    for line in path.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        try:
            rows.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    return rows


def _truncate_inbox(root: Optional[Path] = None) -> None:
    path = inbox_path(root)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("", encoding="utf-8")


def process_inbox_once(
    *,
    root: Optional[Path] = None,
    authz_token: Optional[str] = None,
) -> Dict[str, Any]:
    """Drain inbox, apply envelopes, append outbox results, clear inbox."""
    items = _read_inbox(root)
    results: List[Dict[str, Any]] = []
    out = outbox_path(root)
    out.parent.mkdir(parents=True, exist_ok=True)
    for env in items:
        try:
            rec = apply_local_from_envelope(env, root=root, authz_token=authz_token)
        except Exception as exc:  # noqa: BLE001 — agent must not die on one bad row
            rec = {
                "result": "error",
                "enforced": False,
                "honesty": str(exc),
                "host_id": (env.get("target") or {}).get("host_id"),
            }
        row = {"ts": now_iso(), "envelope": env, "apply": rec}
        results.append(row)
        with out.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(row, separators=(",", ":")) + "\n")
    _truncate_inbox(root)
    beat = write_heartbeat(root)
    state = {
        "ts": now_iso(),
        "processed": len(results),
        "heartbeat": beat,
        "last_results": results[-5:],
    }
    state_path(root).write_text(json.dumps(state, indent=2) + "\n", encoding="utf-8")
    return state


def run_agent_loop(
    *,
    root: Optional[Path] = None,
    poll_seconds: float = 2.0,
    max_cycles: Optional[int] = None,
    authz_token: Optional[str] = None,
) -> int:
    """Blocking agent loop. Returns 0."""
    cycles = 0
    while True:
        process_inbox_once(root=root, authz_token=authz_token)
        cycles += 1
        if max_cycles is not None and cycles >= max_cycles:
            return 0
        time.sleep(max(0.2, float(poll_seconds)))
