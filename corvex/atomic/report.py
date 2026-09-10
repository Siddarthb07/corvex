"""Write atomic lab run reports (no claim upgrade)."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Mapping, Optional


def write_atomic_run_report(
    *,
    report_dir: Path,
    playbook: Mapping[str, Any],
    summary: Mapping[str, Any],
    run_dir: Path,
    campaign_ids: Optional[list] = None,
    reconstruction_status: Optional[str] = None,
) -> Path:
    """Write reports/atomic_run_<campaign_id>.json — does not flip claim_allowed."""
    report_dir = Path(report_dir)
    report_dir.mkdir(parents=True, exist_ok=True)
    cid = str(playbook.get("campaign_id") or summary.get("campaign_id") or "unknown")
    safe = "".join(c if c.isalnum() or c in "-_" else "_" for c in cid)
    path = report_dir / f"atomic_run_{safe}.json"
    payload: Dict[str, Any] = {
        "schema_ver": "1",
        "kind": "atomic_run_report",
        "campaign_id": cid,
        "role": summary.get("role"),
        "run_dir": str(run_dir),
        "techniques_executed": list(summary.get("techniques") or []),
        "executed_steps": summary.get("executed"),
        "failed_phases": summary.get("failed_phases"),
        "campaign_ids_found": list(campaign_ids or []),
        "reconstruction_status": reconstruction_status,
        "claim_allowed_unchanged": True,
        "honesty": (
            "Atomic lab replay evidence only. Does not unlock claim_allowed. "
            "Standing claim remains synthetic-fleet research until existing "
            "stranger/second-host gates pass."
        ),
        "finished_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
    }
    path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    return path
