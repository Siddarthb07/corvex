"""Precision/recall + dry-run isolate metric contracts."""

from __future__ import annotations

from corvex.eval import (
    aggregate_isolate_dry_run,
    aggregate_scores,
    isolate_dry_run_metrics,
    score_pack,
    vs_baseline_lift,
)


def test_score_pack_reports_precision_and_recall() -> None:
    truth = {
        "campaign_id": "c1",
        "family": "lateral",
        "host_ids": ["host-a", "host-b"],
        "stages": [{"name": "auth"}],
    }
    pred = [
        {
            "campaign_id": "p1",
            "host_ids": ["host-a", "host-b"],
            "stages": [{"name": "auth"}],
            "score": 1.0,
        }
    ]
    s = score_pack(pred, truth, ttu_seconds=0.01)
    assert s.precision == 1.0
    assert s.recall == 1.0
    assert s.tp == 1 and s.fp == 0 and s.fn == 0


def test_benign_false_campaign_rate() -> None:
    truth = {"campaign_id": "b", "family": "benign", "host_ids": [], "stages": []}
    clean = score_pack([], truth, ttu_seconds=0.0, benign=True)
    noisy = score_pack(
        [{"campaign_id": "x", "host_ids": ["h1"], "stages": [], "score": 1.0}],
        truth,
        ttu_seconds=0.0,
        benign=True,
    )
    assert clean.false_campaign_rate == 0.0
    assert noisy.false_campaign_rate == 1.0


def test_isolate_dry_run_false_host() -> None:
    truth = {
        "campaign_id": "c1",
        "family": "exfil",
        "host_ids": ["host-a", "host-b"],
        "stages": [{"name": "exfil"}],
    }
    pred = [
        {
            "campaign_id": "p1",
            "host_ids": ["host-a", "host-b", "host-c"],
            "stages": [{"name": "exfil"}],
            "score": 1.0,
        }
    ]
    s = score_pack(pred, truth, ttu_seconds=0.0)
    iso = s.details["isolate_dry_run"]
    assert iso["false_isolates"] == 1
    assert iso["hosts_correct"] == 2
    assert iso["false_isolate_rate"] == 1 / 3
    pooled = aggregate_isolate_dry_run([s])
    assert pooled["false_isolates"] == 1


def test_vs_b1_lift_helper() -> None:
    lift = vs_baseline_lift(
        {"campaign_f1": 1.0, "recall": 1.0, "precision": 1.0, "false_campaign_rate": 0.0},
        {"campaign_f1": 0.0, "recall": 0.0, "precision": 0.0, "false_campaign_rate": 1.0},
    )
    assert lift["f1_lift"] == 1.0
    assert lift["recall_lift"] == 1.0
    agg = aggregate_scores([])
    assert "precision" in agg and "recall" in agg


def test_aggregate_f1_is_micro_harmonic_of_pooled_pr() -> None:
    """CSET review: P=0.33 and R=0.67 cannot yield F1=0.67 (macro-of-F1 bug).

    Pooled tp=2, fp=4, fn=1 → P=1/3, R=2/3, micro-F1=0.4.
    Macro mean of pack F1s would be (0.5 + 2/3)/2 ≈ 0.583 — must not be campaign_f1.
    """
    from corvex.eval import ScoreResult

    a = ScoreResult(
        campaign_f1=0.5,
        precision=1 / 3,
        recall=1.0,
        precision_at_1=0.0,
        false_campaign_rate=0.0,
        ttu_seconds=0.0,
        tp=1,
        fp=2,
        fn=0,
        details={"family": "lateral"},
    )
    b = ScoreResult(
        campaign_f1=2 / 3,
        precision=1.0,
        recall=0.5,
        precision_at_1=1.0,
        false_campaign_rate=0.0,
        ttu_seconds=0.0,
        tp=1,
        fp=0,
        fn=1,
        details={"family": "exfil"},
    )
    agg = aggregate_scores([a, b])
    assert agg["tp"] == 2 and agg["fp"] == 2 and agg["fn"] == 1
    assert abs(agg["precision"] - 0.5) < 1e-9
    assert abs(agg["recall"] - (2 / 3)) < 1e-9
    # Harmonic mean of micro P/R
    expect = 2 * 0.5 * (2 / 3) / (0.5 + 2 / 3)
    assert abs(agg["campaign_f1"] - expect) < 1e-9
    assert agg["campaign_f1"] < 0.58  # not the old macro-of-F1
    assert abs(agg["macro_campaign_f1"] - (0.5 + 2 / 3) / 2) < 1e-9
    assert agg["f1_aggregation"] == "micro_from_tp_fp_fn"
