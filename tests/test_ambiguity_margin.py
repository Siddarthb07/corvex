"""Unit tests for ambiguity-margin fragile scoring (multi-campaign).

Logic previously lived in scripts/run_attack_fleet_limits.py (removed with the
lab harness). Kept here as a self-contained unit so CI does not need that script.
"""

from __future__ import annotations

from typing import Any, Dict, Mapping, Optional, Sequence

FRAGILE_MARGIN = 0.2
MULTI_CLEAN_JACCARD = 0.9


def _ambiguity_margin(
    campaigns_ranked: Sequence[Mapping[str, Any]],
    multi: Optional[Mapping[str, Any]],
    *,
    clean_jaccard: float = MULTI_CLEAN_JACCARD,
) -> Optional[float]:
    """Margin that measures host/campaign *ambiguity*, not multi-campaign existence.

    Returns None when multi-campaign truth is absent or not cleanly resolved —
    caller should fall back to raw top−2nd score gap.
    """
    if not multi:
        return None
    matches = list(multi.get("matches") or [])
    if not matches:
        return None
    if multi.get("collapsed"):
        return None
    try:
        min_j = float(multi.get("min_jaccard") or 0.0)
    except (TypeError, ValueError):
        return None
    if min_j < clean_jaccard:
        return None
    matched_ids = {
        str(m.get("pred_id"))
        for m in matches
        if m.get("pred_id") is not None and float(m.get("jaccard") or 0.0) >= clean_jaccard
    }
    if len(matched_ids) < len(matches):
        return None
    by_id: Dict[str, float] = {}
    for c in campaigns_ranked:
        cid = str(c.get("campaign_id") or "")
        if not cid:
            continue
        by_id[cid] = float(c.get("score") or 0.0)
    matched_scores = [by_id[i] for i in matched_ids if i in by_id]
    if not matched_scores:
        return None
    unmatched_scores = [s for cid, s in by_id.items() if cid not in matched_ids]
    floor = min(matched_scores)
    if not unmatched_scores:
        return round(floor, 4)
    return round(floor - max(unmatched_scores), 4)


def _is_fragile(verdict: str, margin: Any, false_q: Sequence[str]) -> bool:
    """HELD with razor-thin *ambiguity* margin is not a clean pass."""
    if verdict != "HELD":
        return False
    if margin is None:
        return bool(false_q)
    try:
        m = float(margin)
    except (TypeError, ValueError):
        return bool(false_q)
    return m < FRAGILE_MARGIN


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
    assert _ambiguity_margin(ranked, multi) == 1.0
    assert not _is_fragile("HELD", 1.0, [])


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
    m = _ambiguity_margin(ranked, multi)
    assert m == 0.05
    assert _is_fragile("HELD", m, [])


def test_ambiguity_margin_returns_none_when_collapsed():
    ranked = [{"campaign_id": "blob", "score": 1.0}]
    multi = {
        "collapsed": True,
        "min_jaccard": 0.5,
        "matches": [{"pred_id": "blob", "jaccard": 0.5}],
    }
    assert _ambiguity_margin(ranked, multi) is None


def test_raw_top_minus_second_still_used_without_multi():
    # Single-truth path: annotate uses whatever margin caller supplies.
    assert _is_fragile("HELD", 0.1, [])
    assert not _is_fragile("HELD", 0.5, [])
