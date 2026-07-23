"""P3 claim gates — unlock 'useful on real attacks' language only when all pass.

Gates (all required):
1. non_author_fusion_lift — fusion beats detector-only on non-feeder / public-TTP packs
2. stranger_success — external operator attestation file present and pass=true
3. benign_fcr_real_n — held-out benign N >= min_n and FCR within bar

Until then claim_allowed=false. Never flip by dashboard toggle.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

MIN_BENIGN_N = 5
MAX_BENIGN_FCR = 0.10
MIN_FUSION_LIFT = 0.05  # correlator F1 - detector_only F1 on non-author set


def _repo_rel(root: Path, path: Any) -> str:
    """Repo-relative POSIX path for published reports (no home-dir leak)."""
    p = Path(path)
    try:
        return p.resolve().relative_to(Path(root).resolve()).as_posix()
    except (ValueError, OSError):
        text = str(path).replace("\\", "/")
        for marker in ("labs/", "reports/", "heldout/", "train/", "fixtures/"):
            idx = text.lower().find(marker)
            if idx >= 0:
                return text[idx:]
        return p.name


def _load(path: Path) -> Optional[Dict[str, Any]]:
    if not path.exists():
        return None
    return json.loads(path.read_text(encoding="utf-8"))


def evaluate_claim_gates(
    root: Path,
    *,
    min_benign_n: int = MIN_BENIGN_N,
    max_benign_fcr: float = MAX_BENIGN_FCR,
    min_fusion_lift: float = MIN_FUSION_LIFT,
) -> Dict[str, Any]:
    root = Path(root)
    reports = root / "reports"
    held = _load(reports / "stageA_heldout.json") or _load(reports / "stageA.json") or {}
    hm = (held.get("metrics") or {}) if held else {}
    corr = hm.get("correlator") or {}
    det = hm.get("detector_only") or {}

    # Benign N from pack meta
    packs = held.get("packs") or []
    benign_packs = [p for p in packs if (p.get("family") == "benign")]
    n_benign = len(benign_packs)
    fcr = float(corr.get("false_campaign_rate") or 0.0)
    benign_gate = {
        "id": "benign_fcr_real_n",
        "pass": n_benign >= min_benign_n and fcr <= max_benign_fcr,
        "n_benign": n_benign,
        "min_n": min_benign_n,
        "false_campaign_rate": fcr,
        "max_fcr": max_benign_fcr,
        "note": (
            f"Held-out benign N={n_benign} (need >={min_benign_n}), FCR={fcr:.3f}."
            if held
            else "No held-out eval report — run corvex eval --split heldout first."
        ),
    }

    # Non-author fusion lift: prefer dedicated breaktest / non_author report
    non_author = _load(reports / "non_author_fusion.json")
    if non_author:
        lift = float(non_author.get("f1_lift") or 0.0)
        non_author_gate = {
            "id": "non_author_fusion_lift",
            "pass": bool(non_author.get("pass")) and lift >= min_fusion_lift,
            "f1_lift": lift,
            "min_lift": min_fusion_lift,
            "source": (
                _repo_rel(root, non_author["source"])
                if non_author.get("source")
                else None
            ),
            "note": non_author.get("note")
            or "Loaded reports/non_author_fusion.json",
        }
    else:
        # Soft probe: fusion_chain family on held-out (still author-designed — does NOT pass gate)
        by_fam = ((held.get("by_family") or {}).get("correlator") or {})
        det_fam = ((held.get("by_family") or {}).get("detector_only") or {})
        fc = by_fam.get("fusion_chain") or {}
        fd = det_fam.get("fusion_chain") or {}
        soft_lift = float(fc.get("campaign_f1") or 0) - float(fd.get("campaign_f1") or 0)
        non_author_gate = {
            "id": "non_author_fusion_lift",
            "pass": False,
            "f1_lift": soft_lift,
            "min_lift": min_fusion_lift,
            "source": "heldout_fusion_chain_soft_probe",
            "note": (
                "FAIL: no reports/non_author_fusion.json. "
                f"Author-designed fusion_chain soft lift={soft_lift:+.3f} is NOT claim evidence. "
                "Run corvex score-non-author on breaktest/public TTP packs."
            ),
        }

    stranger_path = reports / "stranger_dry_run.json"
    stranger = _load(stranger_path)
    if stranger and "pass" in stranger:
        stranger_gate = {
            "id": "stranger_success",
            "pass": bool(stranger.get("pass")),
            "path": _repo_rel(root, stranger_path),
            "operator": stranger.get("operator"),
            "note": stranger.get("note")
            or ("Stranger attestation pass=true" if stranger.get("pass") else "Stranger attestation present but pass!=true"),
        }
    elif stranger:
        stranger_gate = {
            "id": "stranger_success",
            "pass": False,
            "path": _repo_rel(root, stranger_path),
            "note": (
                "FAIL: reports/stranger_dry_run.json exists but lacks P3 schema field "
                "'pass' (legacy Stage-B file). Replace with docs/stranger-checklist.md attestation."
            ),
        }
    else:
        stranger_gate = {
            "id": "stranger_success",
            "pass": False,
            "path": _repo_rel(root, stranger_path),
            "note": (
                "FAIL: missing reports/stranger_dry_run.json. "
                "External operator must run Windows export→timeline and write attestation "
                "(see docs/stranger-checklist.md)."
            ),
        }

    gates = [non_author_gate, stranger_gate, benign_gate]
    claim_allowed = all(bool(g.get("pass")) for g in gates)
    return {
        "schema_ver": "1",
        "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "claim_allowed": claim_allowed,
        "claim_language": (
            "useful on real attacks"
            if claim_allowed
            else "lab / BYO campaign stitch only — claim locked"
        ),
        "gates": {g["id"]: g for g in gates},
        "honesty": (
            "Do not publish 'useful on real attacks' until claim_allowed=true. "
            "Soft probes and author packs never flip this alone."
        ),
    }


def write_claim_gates(report: Dict[str, Any], path: Path) -> Path:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    return path
