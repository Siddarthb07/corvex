"""Reconstruction → manifest round-trip regression (lab honesty engine)."""

from __future__ import annotations

import json
import tempfile
from pathlib import Path
from typing import Any, Dict, List, Optional

from corvex.audit import AuditLog
from corvex.auth import Enrollment
from corvex.correlator import Correlator
from corvex.feeder import load_pack_events, resign_events
from corvex.reconstruct import reconstruct_campaign
from corvex.store import CampaignStore


def _jaccard(a: List[str], b: List[str]) -> float:
    sa, sb = set(a), set(b)
    if not sa and not sb:
        return 1.0
    if not sa or not sb:
        return 0.0
    return len(sa & sb) / len(sa | sb)


def score_recon_pack(
    pack: Path,
    enrollment: Enrollment,
    *,
    quarantine_mode: str = "dry_run",
) -> Dict[str, Any]:
    """Replay pack → reconstruct top campaign → compare hosts/stages to GT."""
    events, gt = load_pack_events(pack)
    events = resign_events(events, enrollment)
    with tempfile.TemporaryDirectory() as tmp:
        store = CampaignStore(Path(tmp) / "c.jsonl")
        audit = AuditLog(Path(tmp) / "a.jsonl")
        Correlator(store, audit).ingest(events)
        camps = store.all()

    benign = gt.get("family") == "benign"
    if benign:
        # Benign truth has empty hosts — reconstruction should not invent a campaign story.
        if not camps:
            return {
                "pack": pack.name,
                "family": "benign",
                "ok": True,
                "note": "no campaigns on benign — correct",
                "host_jaccard": 1.0,
                "status": "empty",
            }
        # Any campaign on pure benign is a soft fail for recon honesty publishing
        return {
            "pack": pack.name,
            "family": "benign",
            "ok": False,
            "note": f"unexpected {len(camps)} campaign(s) on benign pack",
            "host_jaccard": 0.0,
            "status": "false_campaign",
        }

    if not camps:
        return {
            "pack": pack.name,
            "family": gt.get("family"),
            "ok": False,
            "note": "correlator produced no campaigns — cannot reconstruct",
            "host_jaccard": 0.0,
            "status": "insufficient_evidence",
        }

    # Prefer best Jaccard vs truth hosts
    truth_hosts = list(gt.get("host_ids") or [])
    best = max(camps, key=lambda c: _jaccard(c.host_ids, truth_hosts))
    rec = reconstruct_campaign(best, ground_truth=gt, quarantine_mode=quarantine_mode)
    man = rec.to_manifest()
    assert man.get("purpose") == "regression_only"
    host_j = float((rec.compared_to_truth or {}).get("host_jaccard") or 0.0)
    # Round-trip: manifest hosts should match reconstruction hosts
    man_hosts = list(man.get("hosts") or [])
    round_trip_ok = set(man_hosts) == set(rec.host_ids)
    ok = (
        rec.status in ("complete", "partial")
        and host_j >= 0.5
        and round_trip_ok
        and man.get("purpose") == "regression_only"
    )
    return {
        "pack": pack.name,
        "family": gt.get("family"),
        "campaign_id": rec.campaign_id,
        "status": rec.status,
        "confidence": rec.confidence,
        "host_jaccard": host_j,
        "gaps": list(rec.gaps),
        "round_trip_ok": round_trip_ok,
        "manifest_purpose": man.get("purpose"),
        "ok": ok,
        "note": (
            "reconstruction matches GT hosts at Jaccard>=0.5"
            if ok
            else "reconstruction miss or incomplete vs GT"
        ),
    }


def run_recon_regression(
    packs: List[Path],
    enrollment: Enrollment,
    *,
    quarantine_mode: str = "dry_run",
) -> Dict[str, Any]:
    rows = [score_recon_pack(p, enrollment, quarantine_mode=quarantine_mode) for p in packs]
    attack = [r for r in rows if r.get("family") != "benign"]
    benign = [r for r in rows if r.get("family") == "benign"]
    n_ok = sum(1 for r in rows if r.get("ok"))
    return {
        "schema_ver": "1",
        "purpose": "regression_only",
        "honesty": (
            "Reconstruction exports are for lab pack scoring — not attack playbooks. "
            "Partial/insufficient statuses are publishable findings."
        ),
        "n_packs": len(rows),
        "n_ok": n_ok,
        "pass": n_ok == len(rows) and len(rows) > 0,
        "attack_ok": sum(1 for r in attack if r.get("ok")),
        "attack_n": len(attack),
        "benign_ok": sum(1 for r in benign if r.get("ok")),
        "benign_n": len(benign),
        "packs": rows,
    }


def write_recon_regression(report: Dict[str, Any], path: Path) -> Path:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    return path
