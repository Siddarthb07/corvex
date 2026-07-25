"""Unit tests for ambiguity-margin fragile scoring (multi-campaign)."""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import run_attack_fleet_limits as limits  # noqa: E402


def test_ambiguity_margin_clean_triple_no_competitor():
    ranked = [
        {"campaign_id": "c1", "score": 1.0},
        {"campaign_id": "c2", "score": 1.0},
        {"campaign_id": "c3", "score": 1.0},
    ]
    multi = {
        "collapsed": False,
        "min_jaccard": 1.0,
        "matches": [
            {"pred_id": "c1", "jaccard": 1.0},
            {"pred_id": "c2", "jaccard": 1.0},
            {"pred_id": "c3", "jaccard": 1.0},
        ],
    }
    # Old top−2nd would be 0.0; ambiguity should be 1.0 (no unmatched competitor).
    assert limits._ambiguity_margin(ranked, multi) == 1.0
    assert not limits._is_fragile("HELD", 1.0, [])


def test_ambiguity_margin_near_competitor_is_fragile():
    ranked = [
        {"campaign_id": "c1", "score": 1.0},
        {"campaign_id": "c2", "score": 1.0},
        {"campaign_id": "decoy", "score": 0.95},
    ]
    multi = {
        "collapsed": False,
        "min_jaccard": 1.0,
        "matches": [
            {"pred_id": "c1", "jaccard": 1.0},
            {"pred_id": "c2", "jaccard": 1.0},
        ],
    }
    m = limits._ambiguity_margin(ranked, multi)
    assert m == 0.05
    assert limits._is_fragile("HELD", m, [])


def test_ambiguity_margin_returns_none_when_collapsed():
    ranked = [{"campaign_id": "blob", "score": 1.0}]
    multi = {
        "collapsed": True,
        "min_jaccard": 0.5,
        "matches": [{"pred_id": "blob", "jaccard": 0.5}],
    }
    assert limits._ambiguity_margin(ranked, multi) is None


def test_raw_top_minus_second_still_used_without_multi():
    # Single-truth path: annotate uses whatever margin caller supplies.
    assert limits._is_fragile("HELD", 0.1, [])
    assert not limits._is_fragile("HELD", 0.5, [])
