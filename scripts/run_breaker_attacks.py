#!/usr/bin/env python3
"""Score breaker manifests designed to defeat Corvex — publish failures honestly."""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
MANIFESTS = ROOT / "labs" / "breaktest" / "manifests"
RUN_DIR = ROOT / "runs" / "breakers"

BREAKERS = [
    "break_disjoint_islands.json",
    "break_overmerge_jumpbox.json",
    "break_blind_dns_c2.json",
]


def main() -> int:
    RUN_DIR.mkdir(parents=True, exist_ok=True)
    rows = []
    for name in BREAKERS:
        path = MANIFESTS / name
        out = RUN_DIR / f"{path.stem}.jsonl"
        report = RUN_DIR / f"{path.stem}.breaks.json"
        print(f"\n=== BREAKER: {name} ===", flush=True)
        subprocess.run(
            [
                sys.executable,
                "-m",
                "corvex",
                "build-breaktest",
                str(path),
                "--out",
                str(out),
                "--report",
                str(report),
            ],
            cwd=str(ROOT),
            check=True,
        )
        data = json.loads(report.read_text(encoding="utf-8"))
        bp = data.get("break_points") or {}
        intent = (data.get("break_intent") or data.get("source") or {}).get("note") if False else None
        # break_intent lives on GT in pack; surface from report if present
        row = {
            "manifest": name,
            "campaign_id": data.get("campaign_id"),
            "break_intent": data.get("break_intent"),
            "corr_matched": (data.get("correlator") or {}).get("matched"),
            "corr_jaccard": (data.get("correlator") or {}).get("best_jaccard"),
            "det_matched": (data.get("detector_only") or {}).get("matched"),
            "det_jaccard": (data.get("detector_only") or {}).get("best_jaccard"),
            "fusion_lift": bp.get("fusion_lift"),
            "both_missed": bp.get("both_missed"),
            "missed_hosts": bp.get("missed_hosts"),
            "over_merged_hosts": bp.get("over_merged_hosts"),
            "correlator_campaigns": (data.get("correlator") or {}).get("n_campaigns"),
            "detector_campaigns": (data.get("detector_only") or {}).get("n_campaigns"),
        }
        # Pull intent from breaks file if adapter put it on truth
        raw = report.read_text(encoding="utf-8")
        if "break_intent" in data:
            row["break_intent"] = data.get("break_intent")
        rows.append(row)
        print(json.dumps(row, indent=2), flush=True)

    # Enrich break_intent from manifests
    for row in rows:
        man = json.loads((MANIFESTS / row["manifest"]).read_text(encoding="utf-8"))
        row["break_intent"] = man.get("break_intent")

    summary = {
        "purpose": "Adversarial packs meant to break Corvex — publish failures",
        "n": len(rows),
        "both_missed": sum(1 for r in rows if r.get("both_missed")),
        "over_merged": sum(1 for r in rows if r.get("over_merged_hosts")),
        "missed_any": sum(1 for r in rows if r.get("missed_hosts")),
        "corr_matched": sum(1 for r in rows if r.get("corr_matched")),
        "packs": rows,
        "honesty": (
            "These are author-designed kill shots, not stranger traffic. "
            "A miss here is a product limit to publish, not a silent footnote."
        ),
    }
    out_path = RUN_DIR / "breaker_summary.json"
    out_path.write_text(json.dumps(summary, indent=2) + "\n", encoding="utf-8")
    print("\n=== BREAKER SUMMARY ===", flush=True)
    print(json.dumps(summary, indent=2), flush=True)
    print(f"\nwrote {out_path}", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
