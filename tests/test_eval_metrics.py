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
