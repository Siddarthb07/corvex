"""Eval package — must NOT import the correlator module (CI enforced)."""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Mapping, Optional, Sequence, Set, Tuple


@dataclass
class ScoreResult:
    campaign_f1: float
    precision: float
    recall: float
    precision_at_1: float
    false_campaign_rate: float
    ttu_seconds: float
    tp: int
    fp: int
    fn: int
    details: Dict[str, Any] = field(default_factory=dict)

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


def precision_recall(tp: int, fp: int, fn: int) -> Tuple[float, float]:
    prec = tp / (tp + fp) if (tp + fp) else 0.0
    rec = tp / (tp + fn) if (tp + fn) else 0.0
    return prec, rec


def campaign_f1(tp: int, fp: int, fn: int) -> float:
    if tp == 0:
        return 0.0
    prec, rec = precision_recall(tp, fp, fn)
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


def isolate_dry_run_metrics(
    predicted: Sequence[Mapping[str, Any]],
    truth: Mapping[str, Any],
) -> Dict[str, Any]:
    """
    If every predicted campaign host were dry-run IsolateHost targets:
    how many hosts are correct vs false isolates vs missed.
    Benign packs: any isolate is a false isolate.
    """
    pred_hosts: Set[str] = set()
    for c in predicted:
        pred_hosts |= set(c.get("host_ids") or [])
    if truth.get("family") == "benign" or not truth.get("host_ids"):
        return {
            "hosts_proposed": len(pred_hosts),
            "hosts_correct": 0,
            "false_isolates": len(pred_hosts),
            "missed_hosts": 0,
            "false_isolate_rate": 1.0 if pred_hosts else 0.0,
            "isolate_precision": 0.0 if pred_hosts else 1.0,
            "isolate_recall": 1.0,
        }
    truth_hosts = set(truth.get("host_ids") or [])
    correct = pred_hosts & truth_hosts
    false_iso = pred_hosts - truth_hosts
    missed = truth_hosts - pred_hosts
    return {
        "hosts_proposed": len(pred_hosts),
        "hosts_correct": len(correct),
        "false_isolates": len(false_iso),
        "missed_hosts": len(missed),
        "false_isolate_rate": (len(false_iso) / len(pred_hosts)) if pred_hosts else 0.0,
        "isolate_precision": (len(correct) / len(pred_hosts)) if pred_hosts else 0.0,
        "isolate_recall": (len(correct) / len(truth_hosts)) if truth_hosts else 0.0,
    }


def score_pack(
    predicted: Sequence[Mapping[str, Any]],
    truth: Mapping[str, Any],
    *,
    ttu_seconds: float,
    benign: bool = False,
) -> ScoreResult:
    truths = [truth]
    family = str(truth.get("family") or "unknown")
    if benign or family == "benign":
        fcr = false_campaign_rate(predicted)
        iso = isolate_dry_run_metrics(predicted, truth)
        return ScoreResult(
            campaign_f1=1.0 if fcr == 0 else 0.0,
            precision=1.0 if fcr == 0 else 0.0,
            recall=1.0 if fcr == 0 else 0.0,
            precision_at_1=1.0 if fcr == 0 else 0.0,
            false_campaign_rate=fcr,
            ttu_seconds=ttu_seconds,
            tp=0,
            fp=len(predicted),
            fn=0,
            details={"benign": True, "family": family, "isolate_dry_run": iso},
        )
    tp, fp, fn, matches = match_campaigns(predicted, truths)
    prec, rec = precision_recall(tp, fp, fn)
    iso = isolate_dry_run_metrics(predicted, truth)
    return ScoreResult(
        campaign_f1=campaign_f1(tp, fp, fn),
        precision=prec,
        recall=rec,
        precision_at_1=precision_at_1(predicted, truths),
        false_campaign_rate=0.0,
        ttu_seconds=ttu_seconds,
        tp=tp,
        fp=fp,
        fn=fn,
        details={"matches": matches, "family": family, "isolate_dry_run": iso},
    )


def aggregate_scores(scores: Sequence[ScoreResult]) -> Dict[str, float]:
    if not scores:
        return {
            "campaign_f1": 0.0,
            "precision": 0.0,
            "recall": 0.0,
            "precision_at_1": 0.0,
            "false_campaign_rate": 0.0,
            "ttu_seconds": 0.0,
            "tp": 0,
            "fp": 0,
            "fn": 0,
        }
    benign = [s for s in scores if s.details.get("benign")]
    non = [s for s in scores if not s.details.get("benign")]
    fcr = sum(s.false_campaign_rate for s in benign) / len(benign) if benign else 0.0
    if non:
        f1 = sum(s.campaign_f1 for s in non) / len(non)
        p1 = sum(s.precision_at_1 for s in non) / len(non)
        tp = sum(s.tp for s in non)
        fp = sum(s.fp for s in non)
        fn = sum(s.fn for s in non)
        prec, rec = precision_recall(tp, fp, fn)
    else:
        # Benign-only bucket: campaign F1 is not meaningful — surface clean FCR instead.
        f1 = 1.0 - fcr
        p1 = 1.0 - fcr
        tp = fp = fn = 0
        prec = 1.0 - fcr
        rec = 1.0 if fcr == 0.0 else 0.0
    ttu = max(s.ttu_seconds for s in scores)
    return {
        "campaign_f1": f1,
        "precision": prec,
        "recall": rec,
        "precision_at_1": p1,
        "false_campaign_rate": fcr,
        "ttu_seconds": ttu,
        "tp": float(tp),
        "fp": float(fp),
        "fn": float(fn),
    }


def aggregate_by_family(scores: Sequence[ScoreResult]) -> Dict[str, Dict[str, float]]:
    buckets: Dict[str, List[ScoreResult]] = {}
    for s in scores:
        fam = str(s.details.get("family") or "unknown")
        buckets.setdefault(fam, []).append(s)
    return {fam: aggregate_scores(items) for fam, items in sorted(buckets.items())}


def aggregate_isolate_dry_run(scores: Sequence[ScoreResult]) -> Dict[str, Any]:
    """Pool dry-run isolate host decisions across packs."""
    proposed = correct = false_iso = missed = 0
    for s in scores:
        iso = s.details.get("isolate_dry_run") or {}
        proposed += int(iso.get("hosts_proposed") or 0)
        correct += int(iso.get("hosts_correct") or 0)
        false_iso += int(iso.get("false_isolates") or 0)
        missed += int(iso.get("missed_hosts") or 0)
    return {
        "hosts_proposed": proposed,
        "hosts_correct": correct,
        "false_isolates": false_iso,
        "missed_hosts": missed,
        "false_isolate_rate": (false_iso / proposed) if proposed else 0.0,
        "isolate_precision": (correct / proposed) if proposed else 0.0,
        "isolate_recall": (correct / (correct + missed)) if (correct + missed) else 0.0,
    }


def vs_baseline_lift(
    correlator: Mapping[str, float],
    baseline: Mapping[str, float],
) -> Dict[str, Any]:
    """What cross-host correlation adds over a naive single-host baseline."""
    return {
        "correlator_f1": float(correlator.get("campaign_f1") or 0.0),
        "baseline_f1": float(baseline.get("campaign_f1") or 0.0),
        "f1_lift": float(correlator.get("campaign_f1") or 0.0)
        - float(baseline.get("campaign_f1") or 0.0),
        "correlator_recall": float(correlator.get("recall") or 0.0),
        "baseline_recall": float(baseline.get("recall") or 0.0),
        "recall_lift": float(correlator.get("recall") or 0.0)
        - float(baseline.get("recall") or 0.0),
        "correlator_precision": float(correlator.get("precision") or 0.0),
        "baseline_precision": float(baseline.get("precision") or 0.0),
        "baseline_false_campaign_rate": float(baseline.get("false_campaign_rate") or 0.0),
        "correlator_false_campaign_rate": float(correlator.get("false_campaign_rate") or 0.0),
    }


PASS_BARS = {
    "min_f1": 0.70,
    "min_precision": 0.80,
    "min_recall": 0.70,
    "min_precision_at_1": 0.80,
    "max_false_campaign_rate": 0.10,
    "max_ttu_seconds": 2.0,
    "max_false_isolate_rate": 0.10,
}


def evaluate_pass(
    correlator_metrics: Mapping[str, float],
    b2_metrics: Mapping[str, float],
    ablation: Mapping[str, float],
    *,
    contain_metrics: Optional[Mapping[str, Any]] = None,
) -> Tuple[bool, List[str]]:
    """
    Automated PASS bars (publish precision+recall; do not gate on a lone accuracy):
    - F1 >= max(0.70, B2_F1) and F1 >= B2_F1
    - precision >= 0.80, recall >= 0.70, Precision@1 >= 0.80
    - false campaign rate (benign packs) <= 0.10
    - TTU <= 2s
    - ablation: raw F1 >= detector_only F1 - 0.05 OR raw F1 >= B2_F1
    - optional dry-run false isolate rate <= 0.10
    """
    reasons: List[str] = []
    c_f1 = float(correlator_metrics["campaign_f1"])
    b2_f1 = float(b2_metrics["campaign_f1"])
    need = max(PASS_BARS["min_f1"], b2_f1)
    if c_f1 < need:
        reasons.append(f"F1 {c_f1:.3f} < required {need:.3f}")
    if c_f1 < b2_f1:
        reasons.append(f"F1 {c_f1:.3f} < B2 {b2_f1:.3f}")
    if float(correlator_metrics.get("precision", 1.0)) < PASS_BARS["min_precision"]:
        reasons.append(
            f"precision {float(correlator_metrics.get('precision', 0)):.3f} < "
            f"{PASS_BARS['min_precision']:.2f}"
        )
    if float(correlator_metrics.get("recall", 1.0)) < PASS_BARS["min_recall"]:
        reasons.append(
            f"recall {float(correlator_metrics.get('recall', 0)):.3f} < "
            f"{PASS_BARS['min_recall']:.2f}"
        )
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
    if contain_metrics is not None:
        fir = float(contain_metrics.get("false_isolate_rate") or 0.0)
        if fir > PASS_BARS["max_false_isolate_rate"]:
            reasons.append(f"false isolate rate {fir:.3f} > {PASS_BARS['max_false_isolate_rate']:.2f}")
    return (len(reasons) == 0), reasons


def load_ground_truth_file(path: Path) -> Dict[str, Any]:
    return json.loads(Path(path).read_text(encoding="utf-8"))
