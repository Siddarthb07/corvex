"""Eval harness helpers that stay free of correlator imports."""

# Re-export scoring API for `from campaignfuse.eval.harness import ...`
from campaignfuse.eval import (  # noqa: F401
    PASS_BARS,
    ScoreResult,
    aggregate_scores,
    evaluate_pass,
    score_pack,
)
