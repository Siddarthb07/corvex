"""Compare correlator vs detector-only and emit break-point diagnostics.

Does not run sealed eval — call from break-test tooling after predictions exist.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List, Mapping, Optional, Sequence, Set


def _jaccard(a: Set[str], b: Set[str]) -> float:
    if not a and not b:
        return 1.0
    if not a or not b:
        return 0.0
    return len(a & b) / len(a | b)


def _host_set(camp: Mapping[str, Any]) -> Set[str]:
    return {str(h) for h in camp.get("host_ids") or []}


def analyze_break_points(
    *,
    truth: Mapping[str, Any],
    correlator: Sequence[Mapping[str, Any]],
    detector_only: Sequence[Mapping[str, Any]],
    b1: Optional[Sequence[Mapping[str, Any]]] = None,
) -> Dict[str, Any]:
    """
    Publish where fusion helps and where it still fails.

    Break categories:
      - missed_hosts: in truth, in no correlator campaign
      - over_merged: correlator hosts not in truth (extra)
      - thin_detector_alerts: detector campaigns with Jaccard < 0.5 vs truth
      - fusion_lift: correlator matched truth and detector_only did not
      - never_fused: truth hosts that appear only in disjoint detector keys
    """
    truth_hosts = {str(h) for h in truth.get("host_ids") or []}
    corr_hosts: Set[str] = set()
    for c in correlator:
        corr_hosts |= _host_set(c)
    det_hosts: Set[str] = set()
    for c in detector_only:
        det_hosts |= _host_set(c)

    best_corr = max((_jaccard(_host_set(c), truth_hosts) for c in correlator), default=0.0)
    best_det = max((_jaccard(_host_set(c), truth_hosts) for c in detector_only), default=0.0)
    corr_match = best_corr >= 0.5
    det_match = best_det >= 0.5

    thin = [
        {
            "campaign_id": c.get("campaign_id"),
            "hosts": sorted(_host_set(c)),
            "jaccard_vs_truth": round(_jaccard(_host_set(c), truth_hosts), 4),
        }
        for c in detector_only
        if _jaccard(_host_set(c), truth_hosts) < 0.5
    ]

    best_corr_hosts: Set[str] = set()
    ranked_corr: List[Dict[str, Any]] = []
    if correlator:
        ranked_corr = sorted(
            [
                {
                    "campaign_id": c.get("campaign_id"),
                    "hosts": sorted(_host_set(c)),
                    "score": float(c.get("score") or 0.0),
                    "jaccard_vs_truth": round(_jaccard(_host_set(c), truth_hosts), 4),
                }
                for c in correlator
            ],
            key=lambda row: (row["jaccard_vs_truth"], row["score"]),
            reverse=True,
        )
        best_c = max(correlator, key=lambda c: _jaccard(_host_set(c), truth_hosts))
        best_corr_hosts = _host_set(best_c)

    # Margin: confidence(top) − confidence(2nd-best) by correlator score among campaigns.
    by_score = sorted(
        (float(c.get("score") or 0.0) for c in correlator),
        reverse=True,
    )
    if len(by_score) >= 2:
        confidence_margin = round(by_score[0] - by_score[1], 4)
    elif len(by_score) == 1:
        confidence_margin = round(by_score[0], 4)
    else:
        confidence_margin = None

    report: Dict[str, Any] = {
        "campaign_id": truth.get("campaign_id"),
        "family": truth.get("family"),
        "truth_hosts": sorted(truth_hosts),
        "n_hosts": len(truth_hosts),
        "correlator": {
            "n_campaigns": len(correlator),
            "best_jaccard": round(best_corr, 4),
            "matched": corr_match,
            "hosts_union": sorted(corr_hosts),
            "best_campaign_hosts": sorted(best_corr_hosts),
            "campaigns_ranked": ranked_corr,
            "confidence_margin": confidence_margin,
        },
        "detector_only": {
            "n_campaigns": len(detector_only),
            "best_jaccard": round(best_det, 4),
            "matched": det_match,
            "hosts_union": sorted(det_hosts),
            "thin_alerts": thin,
        },
        "break_points": {
            "missed_hosts": sorted(truth_hosts - corr_hosts),
            # Over-merge vs the best-matching campaign (secondary campaigns are separate).
            "over_merged_hosts": sorted(best_corr_hosts - truth_hosts),
            "secondary_hosts_outside_truth": sorted((corr_hosts - best_corr_hosts) - truth_hosts),
            "hosts_never_in_detector": sorted(truth_hosts - det_hosts),
            "fusion_lift": bool(corr_match and not det_match),
            "both_missed": bool(not corr_match and not det_match),
            "detector_over_fragmented": bool(len(detector_only) >= 2 and not det_match),
        },
        "source": truth.get("source") or {},
    }
    if truth.get("truth_campaigns"):
        report["truth_campaigns"] = truth.get("truth_campaigns")
    if truth.get("host_aliases"):
        report["host_aliases"] = truth.get("host_aliases")
    if b1 is not None:
        best_b1 = max((_jaccard(_host_set(c), truth_hosts) for c in b1), default=0.0)
        b1_hosts: Set[str] = set()
        for c in b1:
            b1_hosts |= _host_set(c)
        report["b1"] = {
            "n_campaigns": len(b1),
            "best_jaccard": round(best_b1, 4),
            "matched": best_b1 >= 0.5,
            "hosts_union": sorted(b1_hosts),
            "campaigns": [
                {
                    "campaign_id": c.get("campaign_id"),
                    "hosts": sorted(_host_set(c)),
                    "score": float(c.get("score") or 0.0),
                }
                for c in b1
            ],
        }
    return report


def write_break_report(path: Path, report: Mapping[str, Any]) -> None:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(dict(report), indent=2) + "\n", encoding="utf-8")


def summarize_reports(reports: Sequence[Mapping[str, Any]]) -> Dict[str, Any]:
    n = len(reports)
    lift = sum(1 for r in reports if (r.get("break_points") or {}).get("fusion_lift"))
    both_miss = sum(1 for r in reports if (r.get("break_points") or {}).get("both_missed"))
    missed_host_packs = [
        r.get("campaign_id")
        for r in reports
        if (r.get("break_points") or {}).get("missed_hosts")
    ]
    return {
        "n_packs": n,
        "fusion_lift_count": lift,
        "both_missed_count": both_miss,
        "packs_with_missed_hosts": missed_host_packs,
        "fusion_lift_rate": (lift / n) if n else 0.0,
    }
