"""Eval package — must NOT import the correlator module (CI enforced)."""

from __future__ import annotations

import json
import time
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Dict, List, Mapping, Optional, Sequence, Set, Tuple


@dataclass
class ScoreResult:
    campaign_f1: float
    precision_at_1: float
    false_campaign_rate: float
    ttu_seconds: float
    tp: int
    fp: int
    fn: int
    details: Dict[str, Any]

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


def _jaccard(a: Set[str], b: Set[str]) -> float:
    if not a and not b:
        return 1.0
    if not a or not b:
        return 0.0
    return len(a & b) / len(a | b)


def match_campaigns(
    predicted: Sequence[Mapping[str, Any]],
    truth: Sequence[Mapping[str, Any]],
    host_jaccard_threshold: float = 0.5,
) -> Tuple[int, int, int, List[Tuple[str, str]]]:
    """
    Frozen matching rules (hashed with sealed packs):
    - A predicted campaign matches a truth campaign if host-set Jaccard >= 0.5
      AND at least one stage name overlaps (or truth has empty stages for benign skip).
    - Greedy best-match, each truth used once.
    """
    truth_benign = [t for t in truth if t.get("family") == "benign" or not t.get("host_ids")]
    truth_pos = [t for t in truth if t not in truth_benign]

    pairs: List[Tuple[float, int, int]] = []
    for i, pred in enumerate(predicted):
        ph = set(pred.get("host_ids", []))
        pstages = {s.get("name") for s in pred.get("stages", []) if s.get("name")}
        for j, t in enumerate(truth_pos):
            th = set(t.get("host_ids", []))
            tstages = {s.get("name") for s in t.get("stages", []) if s.get("name")}
            jac = _jaccard(ph, th)
            stage_ok = bool(pstages & tstages) or not tstages
            if jac >= host_jaccard_threshold and stage_ok:
                pairs.append((jac, i, j))
    pairs.sort(reverse=True)
    used_p: Set[int] = set()
    used_t: Set[int] = set()
    matches: List[Tuple[str, str]] = []
    for jac, i, j in pairs:
        if i in used_p or j in used_t:
            continue
        used_p.add(i)
        used_t.add(j)
        matches.append(
            (
                str(predicted[i].get("campaign_id")),
                str(truth_pos[j].get("campaign_id")),
            )
        )
    tp = len(matches)
    fp = len(predicted) - tp
    fn = len(truth_pos) - tp
    return tp, fp, fn, matches


def campaign_f1(tp: int, fp: int, fn: int) -> float:
    if tp == 0:
        return 0.0
    prec = tp / (tp + fp) if (tp + fp) else 0.0
    rec = tp / (tp + fn) if (tp + fn) else 0.0
    if prec + rec == 0:
        return 0.0
    return 2 * prec * rec / (prec + rec)


def precision_at_1(
    predicted: Sequence[Mapping[str, Any]],
    truth: Sequence[Mapping[str, Any]],
) -> float:
    if not predicted:
        return 0.0
    ranked = sorted(predicted, key=lambda c: float(c.get("score", 0)), reverse=True)
    top = ranked[0]
    tp, _, _, _ = match_campaigns([top], truth)
    return 1.0 if tp == 1 else 0.0


def false_campaign_rate(predicted: Sequence[Mapping[str, Any]]) -> float:
    """For benign-only packs: any predicted campaign is a false campaign."""
    return 1.0 if predicted else 0.0


def score_pack(
    predicted: Sequence[Mapping[str, Any]],
    truth: Mapping[str, Any],
    *,
    ttu_seconds: float,
    benign: bool = False,
) -> ScoreResult:
    truths = [truth]
    if benign or truth.get("family") == "benign":
        fcr = false_campaign_rate(predicted)
        return ScoreResult(
            campaign_f1=1.0 if fcr == 0 else 0.0,
            precision_at_1=1.0 if fcr == 0 else 0.0,
            false_campaign_rate=fcr,
            ttu_seconds=ttu_seconds,
            tp=0,
            fp=len(predicted),
            fn=0,
            details={"benign": True},
        )
    tp, fp, fn, matches = match_campaigns(predicted, truths)
    return ScoreResult(
        campaign_f1=campaign_f1(tp, fp, fn),
        precision_at_1=precision_at_1(predicted, truths),
        false_campaign_rate=0.0,
        ttu_seconds=ttu_seconds,
        tp=tp,
        fp=fp,
        fn=fn,
        details={"matches": matches},
    )


def aggregate_scores(scores: Sequence[ScoreResult]) -> Dict[str, float]:
    if not scores:
        return {
            "campaign_f1": 0.0,
            "precision_at_1": 0.0,
            "false_campaign_rate": 0.0,
            "ttu_seconds": 0.0,
        }
    benign = [s for s in scores if s.details.get("benign")]
    non = [s for s in scores if not s.details.get("benign")]
    f1 = sum(s.campaign_f1 for s in non) / len(non) if non else 0.0
    p1 = sum(s.precision_at_1 for s in non) / len(non) if non else 0.0
    fcr = sum(s.false_campaign_rate for s in benign) / len(benign) if benign else 0.0
    ttu = max(s.ttu_seconds for s in scores)
    return {
        "campaign_f1": f1,
        "precision_at_1": p1,
        "false_campaign_rate": fcr,
        "ttu_seconds": ttu,
    }


PASS_BARS = {
    "min_f1": 0.70,
    "min_precision_at_1": 0.80,
    "max_false_campaign_rate": 0.10,
    "max_ttu_seconds": 2.0,
}


def evaluate_pass(
    correlator_metrics: Mapping[str, float],
    b2_metrics: Mapping[str, float],
    ablation: Mapping[str, float],
) -> Tuple[bool, List[str]]:
    """
    H1 PASS bars (automated only):
    - F1 >= max(0.70, B2_F1) and F1 >= B2_F1
    - Precision@1 >= 0.80
    - false campaign rate <= 0.10
    - TTU <= 2s
    - ablation: raw F1 >= detector_only F1 - 0.05 OR raw F1 >= B2_F1
    """
    reasons: List[str] = []
    c_f1 = float(correlator_metrics["campaign_f1"])
    b2_f1 = float(b2_metrics["campaign_f1"])
    need = max(PASS_BARS["min_f1"], b2_f1)
    if c_f1 < need:
        reasons.append(f"F1 {c_f1:.3f} < required {need:.3f}")
    if c_f1 < b2_f1:
        reasons.append(f"F1 {c_f1:.3f} < B2 {b2_f1:.3f}")
    if correlator_metrics["precision_at_1"] < PASS_BARS["min_precision_at_1"]:
        reasons.append("Precision@1 below 0.80")
    if correlator_metrics["false_campaign_rate"] > PASS_BARS["max_false_campaign_rate"]:
        reasons.append("false campaign rate above 0.10")
    if correlator_metrics["ttu_seconds"] > PASS_BARS["max_ttu_seconds"]:
        reasons.append("TTU above 2s")
    raw_f1 = float(ablation.get("raw_f1", c_f1))
    det_f1 = float(ablation.get("detector_only_f1", 0.0))
    if not (raw_f1 >= det_f1 - 0.05 or raw_f1 >= b2_f1):
        reasons.append("ablation: correlator dominated by detector-only without beating B2")
    return (len(reasons) == 0), reasons


def load_ground_truth_file(path: Path) -> Dict[str, Any]:
    return json.loads(Path(path).read_text(encoding="utf-8"))
