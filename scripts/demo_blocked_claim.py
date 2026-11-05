#!/usr/bin/env python3
"""Demonstrate a drafted public claim blocked by claim-gates (CSET review ask).

Prints a soft marketing sentence, runs evaluate_claim_gates, and shows which
gate refuses it. Does not flip claim_allowed. Does not write attestation files.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from corvex.eval.claim_gates import evaluate_claim_gates

DRAFTED = (
    "Corvex works on real multi-host attacks in enterprise networks and is "
    "ready for production SOC use."
)

STANDING = (
    "Research correlator — holds up against synthetic ATT&CK-shaped fleets; "
    "not validated against real telemetry or benign baselines."
)


def main() -> int:
    root = ROOT
    result = evaluate_claim_gates(root)
    failed = [
        g
        for g in (result.get("gates") or {}).values()
        if isinstance(g, dict) and not g.get("pass")
    ]
    print("=== Drafted claim (would overclaim) ===")
    print(DRAFTED)
    print()
    print("=== Standing public claim (allowed today) ===")
    print(STANDING)
    print()
    print("=== claim-gates machine check ===")
    print(
        json.dumps(
            {
                "claim_allowed": result.get("claim_allowed"),
                "lab_verified": result.get("lab_verified"),
                "blocking_gates": [
                    {
                        "id": g.get("id"),
                        "pass": g.get("pass"),
                        "note": g.get("note"),
                    }
                    for g in failed
                ],
                "protocol": (
                    "Any sentence implying real-enterprise usefulness is refused "
                    "while claim_allowed=false. stage-b-lab-unlock and author HMAC "
                    "do not flip this bit."
                ),
            },
            indent=2,
        )
    )
    return 0 if not result.get("claim_allowed") else 1


if __name__ == "__main__":
    raise SystemExit(main())
