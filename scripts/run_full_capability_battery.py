#!/usr/bin/env python3
"""Full Corvex capability battery — sealed, breaktest, fleets, limits, intensive.

Runs the evaluation surfaces needed to answer: how capable is it, and where
does it break? Emits a consolidated report. Does **not** flip claim_allowed.

  python scripts/run_full_capability_battery.py
  python scripts/run_full_capability_battery.py --skip-scale   # skip T1/T2
  python scripts/run_full_capability_battery.py --quick        # shorter intensive + intensity 1
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

ROOT = Path(__file__).resolve().parents[1]
OUT_JSON = ROOT / "reports" / "full_capability_battery.json"
OUT_MD = ROOT / "reports" / "full_capability_battery.md"


def run(cmd: List[str], *, timeout: Optional[int] = None) -> Dict[str, Any]:
    t0 = time.perf_counter()
    try:
        proc = subprocess.run(
            cmd,
            cwd=str(ROOT),
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        return {
            "cmd": cmd,
            "ok": proc.returncode == 0,
            "returncode": proc.returncode,
            "wall_seconds": round(time.perf_counter() - t0, 4),
            "stdout_tail": (proc.stdout or "")[-2000:],
            "stderr_tail": (proc.stderr or "")[-2000:],
        }
    except subprocess.TimeoutExpired as exc:
        return {
            "cmd": cmd,
            "ok": False,
            "returncode": -1,
            "wall_seconds": round(time.perf_counter() - t0, 4),
            "error": f"timeout after {timeout}s",
            "stdout_tail": (exc.stdout or "")[-2000:] if isinstance(exc.stdout, str) else "",
            "stderr_tail": (exc.stderr or "")[-2000:] if isinstance(exc.stderr, str) else "",
        }


def _load_json(path: Path) -> Optional[Dict[str, Any]]:
    if not path.is_file():
        return None
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return None


def _summarize_limits(path: Path) -> Dict[str, Any]:
    data = _load_json(path) or {}
    attacks = data.get("attacks") or data.get("results") or []
    if not attacks and isinstance(data.get("fleet"), list):
        attacks = data["fleet"]
    held = sum(1 for a in attacks if a.get("verdict") == "HELD")
    fragile = sum(1 for a in attacks if a.get("fragile"))
    partial = sum(1 for a in attacks if a.get("verdict") == "PARTIAL")
    broke = sum(1 for a in attacks if a.get("verdict") == "BROKE")
    return {
        "path": str(path),
        "n": len(attacks),
        "held": held,
        "fragile": fragile,
        "partial": partial,
        "broke": broke,
        "wall_seconds": data.get("wall_seconds"),
        "intensity_rounds": data.get("intensity_rounds"),
    }


def write_md(report: Dict[str, Any]) -> None:
    steps = report.get("steps") or []
    lines = [
        "# Full Corvex capability battery",
        "",
        f"Generated: **{report.get('generated_utc')}**",
        "",
        "Standing claim unchanged: synthetic ATT&CK-shaped fleets only; "
        f"**claim_allowed={report.get('claim_allowed')}**.",
        "",
        f"Wall: **{report.get('wall_seconds')}s** | Steps ok: "
        f"**{sum(1 for s in steps if s.get('ok'))}/{len(steps)}**",
        "",
        "## Scoreboard rollup",
        "",
        "| Suite | N | HELD | fragile | PARTIAL | BROKE | Notes |",
        "|-------|---|------|---------|---------|-------|-------|",
    ]
    for name, block in (report.get("suites") or {}).items():
        if not isinstance(block, dict):
            continue
        lines.append(
            f"| {name} | {block.get('n', '—')} | {block.get('held', '—')} | "
            f"{block.get('fragile', '—')} | {block.get('partial', '—')} | "
            f"{block.get('broke', '—')} | {block.get('notes', '')} |"
        )
    lines.extend(
        [
            "",
            "## Exact break list (BROKE + PARTIAL across suites)",
            "",
        ]
    )
    breaks = report.get("breaks") or []
    if not breaks:
        lines.append("_No BROKE/PARTIAL rows collected (or suites skipped)._")
    else:
        lines.append("| Suite | Campaign | Verdict | J | Why |")
        lines.append("|-------|----------|---------|---|-----|")
        for b in breaks:
            why = "; ".join(b.get("reasons") or []) or b.get("note") or "—"
            lines.append(
                f"| {b.get('suite')} | `{b.get('campaign_id')}` | **{b.get('verdict')}** | "
                f"{b.get('jaccard', '—')} | {why} |"
            )
    lines.extend(
        [
            "",
            "## Sealed / breaktest metrics",
            "",
            "```json",
            json.dumps(report.get("metrics") or {}, indent=2),
            "```",
            "",
            "## Step log",
            "",
            "| Step | OK | Wall (s) |",
            "|------|----|----------|",
        ]
    )
    for s in steps:
        lines.append(
            f"| `{s.get('name')}` | {'yes' if s.get('ok') else 'NO'} | {s.get('wall_seconds')} |"
        )
    lines.extend(
        [
            "",
            "## Honesty",
            "",
            "- All suites are lab/synthetic unless noted.",
            "- Intensive domain/container axes are host_id namespaces, not live AD/K8s.",
            "- See `reports/intensive_capability_matrix.md` and `docs/stress-failure-modes.md`.",
            "",
        ]
    )
    OUT_MD.write_text("\n".join(lines) + "\n", encoding="utf-8")


def collect_breaks() -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    sources = [
        ("fleet-limits", ROOT / "reports" / "attack_fleet_limits.json"),
        ("fleet20", ROOT / "reports" / "attack_fleet20.json"),
        ("intensive", ROOT / "reports" / "intensive_capability_matrix.json"),
        ("fleet-limits-t1", ROOT / "reports" / "attack_fleet_limits_t1_nodecoy.json"),
        ("fleet-limits-t2", ROOT / "reports" / "attack_fleet_limits_t2_nodecoy.json"),
    ]
    for suite, path in sources:
        data = _load_json(path)
        if not data:
            continue
        attacks = data.get("attacks") or []
        for a in attacks:
            v = str(a.get("verdict") or "")
            if v not in ("BROKE", "PARTIAL"):
                continue
            out.append(
                {
                    "suite": suite,
                    "campaign_id": a.get("campaign_id"),
                    "verdict": a.get("verdict_label") or v,
                    "jaccard": a.get("corr_jaccard"),
                    "reasons": a.get("verdict_reasons") or [],
                }
            )
    # Breakers summary
    br = _load_json(ROOT / "runs" / "breakers" / "breaker_summary.json")
    if br:
        for p in br.get("packs") or []:
            if p.get("both_missed") or (p.get("missed_hosts") and not p.get("corr_matched")):
                out.append(
                    {
                        "suite": "breakers",
                        "campaign_id": p.get("campaign_id") or p.get("manifest"),
                        "verdict": "BROKE" if p.get("both_missed") else "PARTIAL",
                        "jaccard": p.get("corr_jaccard"),
                        "reasons": [str(p.get("break_intent") or "breaker miss")],
                    }
                )
    return out


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--quick", action="store_true")
    ap.add_argument("--skip-scale", action="store_true")
    ap.add_argument("--skip-pytest", action="store_true")
    args = ap.parse_args()
    intensity = 1 if args.quick else 2
    py = sys.executable

    steps_out: List[Dict[str, Any]] = []
    t_all = time.perf_counter()

    plan: List[tuple[str, List[str], Optional[int]]] = []
    if not args.skip_pytest:
        plan.append(("pytest", [py, "-m", "pytest", "-q", "--tb=no"], 600))
    plan.extend(
        [
            ("eval-heldout", [py, "-m", "corvex", "eval", "--split", "heldout"], 300),
            ("score-non-author", [py, "-m", "corvex", "score-non-author"], 600),
            ("claim-gates", [py, "-m", "corvex", "claim-gates"], 120),
            (
                "fleet20",
                [py, str(ROOT / "scripts" / "run_attack_fleet10.py"), str(intensity)],
                900,
            ),
            (
                "fleet-limits",
                [
                    py,
                    str(ROOT / "scripts" / "run_attack_fleet_limits.py"),
                    "--intensity",
                    str(intensity),
                ],
                900,
            ),
            ("breakers", [py, str(ROOT / "scripts" / "run_breaker_attacks.py")], 300),
            (
                "sql-art",
                [py, str(ROOT / "scripts" / "run_sql_art_stress.py")],
                300,
            ),
            (
                "intensive",
                [
                    py,
                    str(ROOT / "scripts" / "run_intensive_multifactor.py"),
                    "--intensity",
                    str(intensity),
                ]
                + (["--quick"] if args.quick else []),
                1800,
            ),
            (
                "opensource-fetch",
                [py, str(ROOT / "scripts" / "fetch_opensource_corpora.py")],
                600,
            ),
            (
                "opensource-eval",
                [py, str(ROOT / "scripts" / "run_opensource_attack_eval.py")],
                1800,
            ),
        ]
    )
    if not args.skip_scale:
        plan.extend(
            [
                (
                    "fleet-limits-t1",
                    [
                        py,
                        str(ROOT / "scripts" / "run_attack_fleet_limits_scale.py"),
                        "--hosts",
                        "15",
                        "--intensity",
                        "1",
                        "--no-decoy",
                    ],
                    1200,
                ),
                (
                    "fleet-limits-t2",
                    [
                        py,
                        str(ROOT / "scripts" / "run_attack_fleet_limits_scale.py"),
                        "--hosts",
                        "50",
                        "--intensity",
                        "1",
                        "--no-decoy",
                    ],
                    1800,
                ),
            ]
        )

    for name, cmd, timeout in plan:
        print(f"\n######## {name} ########", flush=True)
        print(" ".join(cmd), flush=True)
        result = run(cmd, timeout=timeout)
        result["name"] = name
        # claim-gates exits 1 while claim_allowed is false by design — treat as
        # OK when the report wrote and lab_verified is true.
        if name == "claim-gates" and not result["ok"]:
            cg = _load_json(ROOT / "reports" / "claim_gates.json") or {}
            if cg.get("lab_verified") is True and cg.get("claim_allowed") is False:
                result["ok"] = True
                result["expected_locked"] = True
                result["note"] = "exit 1 expected: claim_allowed=false, lab_verified=true"
        steps_out.append(result)
        status = "OK" if result["ok"] else "FAIL"
        print(f"[{status}] {name} in {result['wall_seconds']}s", flush=True)
        if not result["ok"]:
            print(result.get("stderr_tail") or result.get("stdout_tail") or result.get("error"), flush=True)
        elif result.get("expected_locked"):
            print(f"  (expected locked claim) {result.get('note')}", flush=True)

    # Metrics snapshots
    metrics: Dict[str, Any] = {}
    for label, path in [
        ("heldout", ROOT / "reports" / "stageA_heldout.json"),
        ("non_author", ROOT / "reports" / "non_author_fusion.json"),
        ("claim_gates", ROOT / "reports" / "claim_gates.json"),
        ("sql_art", ROOT / "reports" / "sql_art_stress.json"),
    ]:
        data = _load_json(path)
        if data:
            metrics[label] = data

    claim = _load_json(ROOT / "reports" / "claim_gates.json") or {}
    suites = {
        "fleet-limits": _summarize_limits(ROOT / "reports" / "attack_fleet_limits.json"),
        "fleet20": _summarize_limits(ROOT / "reports" / "attack_fleet20.json"),
        "intensive": _summarize_limits(ROOT / "reports" / "intensive_capability_matrix.json"),
        "fleet-limits-t1": _summarize_limits(
            ROOT / "reports" / "attack_fleet_limits_t1_nodecoy.json"
        ),
        "fleet-limits-t2": _summarize_limits(
            ROOT / "reports" / "attack_fleet_limits_t2_nodecoy.json"
        ),
    }
    # Annotate notes from metrics
    if "heldout" in metrics:
        m = metrics["heldout"]
        # structure varies — best-effort
        suites["sealed-heldout"] = {
            "n": m.get("n_attack") or m.get("n"),
            "notes": "see metrics.heldout; micro-F1 in RESULTS.md",
        }
    if "non_author" in metrics:
        na = metrics["non_author"]
        suites["breaktest-non-author"] = {
            "notes": f"lift={na.get('lift') or (na.get('metrics') or {}).get('lift')}",
        }

    # Enrich intensive notes
    if suites["intensive"].get("n"):
        suites["intensive"]["notes"] = "domain×container×sequence×style matrix"

    report = {
        "generated_utc": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "wall_seconds": round(time.perf_counter() - t_all, 4),
        "claim_allowed": claim.get("claim_allowed", False),
        "lab_verified": claim.get("lab_verified"),
        "quick": bool(args.quick),
        "intensity": intensity,
        "steps": [{"name": s["name"], "ok": s["ok"], "wall_seconds": s["wall_seconds"], "returncode": s.get("returncode")} for s in steps_out],
        "steps_detail": steps_out,
        "suites": suites,
        "metrics": {
            k: {
                kk: vv
                for kk, vv in (v.items() if isinstance(v, dict) else [])
                if kk
                in (
                    "claim_allowed",
                    "lab_verified",
                    "gates",
                    "lift",
                    "correlator",
                    "detector_only",
                    "metrics",
                    "summary",
                    "n",
                    "n_attack",
                    "n_benign",
                    "fusion_lift",
                    "campaign_f1",
                    "precision",
                    "recall",
                )
                or not isinstance(vv, (dict, list))
            }
            for k, v in metrics.items()
        },
        "breaks": collect_breaks(),
        "honesty": (
            "Synthetic / author-built suites. Not enterprise validation. "
            "claim_allowed remains false until live_second_host + benign estate."
        ),
    }
    # Slim metrics if huge
    OUT_JSON.write_text(json.dumps(report, indent=2, default=str) + "\n", encoding="utf-8")
    write_md(report)
    print(f"\nwrote {OUT_JSON}\nwrote {OUT_MD}", flush=True)
    print(
        json.dumps(
            {
                "wall_seconds": report["wall_seconds"],
                "claim_allowed": report["claim_allowed"],
                "suites": {k: {kk: vv for kk, vv in v.items() if kk != "path"} for k, v in suites.items()},
                "break_rows": len(report["breaks"]),
            },
            indent=2,
        ),
        flush=True,
    )
    failed = [s for s in steps_out if not s["ok"]]
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
