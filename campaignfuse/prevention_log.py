"""Prevention log — attacks Corvex detected and stopped/isolated."""

from __future__ import annotations

import json
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional


def prevention_log_path(root: Path) -> Path:
    return Path(root) / "reports" / "prevention_log.jsonl"


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def append_prevention(
    root: Path,
    *,
    attack_type: str,
    attack_name: str,
    summary: str,
    hosts: List[str],
    actions: List[str],
    status: str = "prevented",
    campaign_id: Optional[str] = None,
    source: Optional[str] = None,
    identity: Optional[str] = None,
    extra: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """Append one prevented-attack record (deploy-facing history)."""
    path = prevention_log_path(root)
    path.parent.mkdir(parents=True, exist_ok=True)
    rec: Dict[str, Any] = {
        "id": str(uuid.uuid4())[:12],
        "ts": _now(),
        "status": status,
        "attack_type": attack_type,
        "attack_name": attack_name,
        "campaign_id": campaign_id,
        "source": source,
        "identity": identity,
        "hosts": list(hosts),
        "actions": list(actions),
        "summary": summary,
    }
    if extra:
        rec["extra"] = extra
    with path.open("a", encoding="utf-8") as fh:
        fh.write(json.dumps(rec, separators=(",", ":")) + "\n")
    return rec


def load_prevention_log(root: Path, *, limit: int = 200) -> List[Dict[str, Any]]:
    path = prevention_log_path(root)
    if not path.exists():
        return []
    rows: List[Dict[str, Any]] = []
    for line in path.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        try:
            rows.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    rows.reverse()  # newest first
    return rows[:limit]


def seed_from_live_lab(root: Path) -> Optional[Dict[str, Any]]:
    """One-shot import of last Docker lab result into prevention log (if not already present)."""
    candidates = [
        Path(root) / ".sandbox" / "demo" / "live-corvex_state.json",
        Path(root) / "reports" / "dashboard" / "media" / "live-corvex_state.json",
    ]
    data = None
    for p in candidates:
        if p.exists():
            data = json.loads(p.read_text(encoding="utf-8"))
            break
    if not data:
        return None

    existing = load_prevention_log(root, limit=500)
    camp_id = None
    camps = data.get("campaigns") or []
    if camps:
        camp_id = camps[0].get("campaign_id")
    if camp_id and any(r.get("campaign_id") == camp_id for r in existing):
        return None

    attacker = data.get("attacker") or {}
    defended = data.get("defended") or []
    return append_prevention(
        root,
        attack_type="lateral_auth",
        attack_name="Lateral authentication campaign",
        campaign_id=camp_id or "camp-lateral-alice",
        source="10.1.0.5",
        identity="alice",
        hosts=list(defended),
        actions=[f"IsolateHost {h}" for h in defended]
        + [f"Blocked retry on {h}" for h in defended],
        status="prevented",
        summary=(
            f"Stolen account alice from 10.1.0.5 gained {attacker.get('wave1_successes', '?')} "
            f"footholds; Corvex isolated {len(defended)} hosts and blocked "
            f"{attacker.get('wave2_blocked', '?')} retry attempts."
        ),
        extra={"outcome": attacker.get("outcome"), "lab": True},
    )
