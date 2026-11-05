#!/usr/bin/env python3
"""Continuous SQL ART stress — multi-retry correlator break report.

Runs the break-sql-continuous-art manifest N times in a short wall window,
scores correlator vs detector-only, and emits a per-host table covering:
  - time-to-first-host-breach (from manifest FIRST_COMPROMISE)
  - hosts saved (innocent + not falsely quarantined)
  - every host: role, compromised, flagged, quarantine proposed, methods

Lab telemetry only — no live SQL injection.
"""

from __future__ import annotations

import json
import shutil
import subprocess
import sys
import time
from pathlib import Path
from typing import Any, Dict, List, Set

ROOT = Path(__file__).resolve().parents[1]
MANIFEST = ROOT / "labs" / "breaktest" / "manifests" / "break_sql_continuous_art.json"
OUT = ROOT / "runs" / "sql-art-stress"
REPORT = ROOT / "reports" / "sql_art_stress.json"
MD = ROOT / "reports" / "sql_art_stress.md"


def run(cmd: List[str]) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, cwd=str(ROOT), check=False, text=True, capture_output=True)


def _first_compromise(man: Dict[str, Any]) -> Dict[str, Any]:
    for step in man.get("steps") or []:
        note = str(step.get("note") or "")
        if "FIRST_COMPROMISE" in note or note.lower().startswith("first"):
            return {
                "host": step.get("host"),
                "offset_seconds": float(step.get("offset_seconds") or 0),
                "user": step.get("user"),
                "technique": step.get("technique"),
                "method": note,
            }
    # fallback: first auth on truth host
    truth = set(man.get("truth_hosts") or [])
    for step in man.get("steps") or []:
        if str(step.get("kind")).lower() == "auth" and step.get("host") in truth:
            return {
                "host": step.get("host"),
                "offset_seconds": float(step.get("offset_seconds") or 0),
                "user": step.get("user"),
                "technique": step.get("technique"),
                "method": step.get("note") or "first_auth",
            }
    return {"host": None, "offset_seconds": None}


def _methods_by_host(man: Dict[str, Any]) -> Dict[str, List[str]]:
    out: Dict[str, List[str]] = {}
    for step in man.get("steps") or []:
        host = str(step.get("host") or "")
        note = str(step.get("note") or step.get("technique") or step.get("kind") or "")
        if "method=" in note:
            method = note.split("method=", 1)[1].split()[0].strip()
        else:
            method = note[:60]
        out.setdefault(host, []).append(method)
    return {h: list(dict.fromkeys(ms)) for h, ms in out.items()}


def _hosts_from_camps(camps: List[Dict[str, Any]]) -> Set[str]:
    s: Set[str] = set()
    for c in camps:
        for h in c.get("host_ids") or []:
            s.add(str(h))
    return s


def one_attempt(attempt: int) -> Dict[str, Any]:
    attempt_dir = OUT / f"attempt-{attempt:02d}"
    if attempt_dir.exists():
        shutil.rmtree(attempt_dir)
    attempt_dir.mkdir(parents=True)
    pack = attempt_dir / "pack.jsonl"
    breaks = attempt_dir / "breaks.json"
    t0 = time.perf_counter()
    proc = run(
        [
            sys.executable,
            "-m",
            "corvex",
            "build-breaktest",
            str(MANIFEST),
            "--out",
            str(pack),
            "--report",
            str(breaks),
        ]
    )
    build_s = time.perf_counter() - t0
    if proc.returncode != 0 or not breaks.is_file():
        return {
            "attempt": attempt,
            "ok": False,
            "build_seconds": round(build_s, 4),
            "error": (proc.stderr or proc.stdout or "")[-800:],
        }
    br = json.loads(breaks.read_text(encoding="utf-8"))

    # Replay → reconstruction for quarantine dry-run proposals
    replay = attempt_dir / "replay"
    t1 = time.perf_counter()
    proc2 = run(
        [
            sys.executable,
            "-m",
            "corvex",
            "replay",
            str(pack),
            "--out-dir",
            str(replay),
        ]
    )
    replay_s = time.perf_counter() - t1
    q_hosts: Set[str] = set()
    camps: List[Dict[str, Any]] = []
    if (replay / "reconstruction.json").is_file():
        recon = json.loads((replay / "reconstruction.json").read_text(encoding="utf-8"))
        for item in recon.get("campaign_reconstructions") or []:
            q = item.get("quarantine") or {}
            for h in q.get("host_ids") or item.get("host_ids") or []:
                q_hosts.add(str(h))
    if (replay / "timeline.json").is_file():
        tl = json.loads((replay / "timeline.json").read_text(encoding="utf-8"))
        camps = list(tl.get("campaigns") or [])

    corr = br.get("correlator") or {}
    det = br.get("detector_only") or {}
    bp = br.get("break_points") or {}
    return {
        "attempt": attempt,
        "ok": proc.returncode == 0 and proc2.returncode == 0,
        "build_seconds": round(build_s, 4),
        "replay_seconds": round(replay_s, 4),
        "wall_seconds": round(build_s + replay_s, 4),
        "correlator_jaccard": corr.get("best_jaccard"),
        "correlator_matched": corr.get("matched"),
        "correlator_hosts": corr.get("hosts_union") or sorted(_hosts_from_camps(camps)),
        "detector_jaccard": det.get("best_jaccard"),
        "detector_hosts": det.get("hosts_union"),
        "over_merged_hosts": bp.get("over_merged_hosts") or [],
        "missed_hosts": bp.get("missed_hosts") or [],
        "quarantine_proposed": sorted(q_hosts),
        "n_campaigns": corr.get("n_campaigns") or len(camps),
    }


def build_host_table(
    man: Dict[str, Any],
    attempt: Dict[str, Any],
) -> List[Dict[str, Any]]:
    roles = man.get("host_roles") or {}
    truth = set(man.get("truth_hosts") or [])
    fleet = list(man.get("hosts") or [])
    methods = _methods_by_host(man)
    flagged = set(attempt.get("correlator_hosts") or [])
    over = set(attempt.get("over_merged_hosts") or [])
    missed = set(attempt.get("missed_hosts") or [])
    qprop = set(attempt.get("quarantine_proposed") or [])
    rows = []
    for h in fleet:
        compromised = h in truth
        in_corr = h in flagged
        q = h in qprop
        false_q = q and not compromised
        saved = (not compromised) and (not false_q)
        # "contained" = compromised and proposed for dry-run isolate
        contained_dry = compromised and q
        rows.append(
            {
                "host": h,
                "role": roles.get(h, ""),
                "compromised_truth": compromised,
                "correlator_flagged": in_corr,
                "over_merged": h in over,
                "missed": h in missed,
                "quarantine_dry_run": q,
                "saved": saved,
                "contained_dry_run": contained_dry,
                "attack_methods": methods.get(h, []),
            }
        )
    return rows


def markdown_report(report: Dict[str, Any]) -> str:
    fc = report["first_compromise"]
    summary = report["summary"]
    lines = [
        "# Continuous SQL ART stress report",
        "",
        "Lab correlator stress only — **no live SQL injection** was executed.",
        "",
        f"- Manifest: `{report['manifest']}`",
        f"- Retries: **{report['retries']}** in ~**{report['total_wall_seconds']}s** wall",
        f"- First host breached (scripted): **{fc.get('host')}** at **T+{fc.get('offset_seconds')}s** "
        f"({fc.get('method')})",
        f"- Truth compromised hosts: {', '.join(summary['truth_hosts'])}",
        f"- Saved hosts (innocent + not falsely quarantined): "
        f"**{summary['hosts_saved_count']}** -> {', '.join(summary['hosts_saved']) or '—'}",
        f"- Falsely quarantined (dry-run): "
        f"**{summary['false_quarantine_count']}** -> {', '.join(summary['false_quarantine']) or '—'}",
        f"- Correlator match rate across retries: "
        f"**{summary['match_rate']}** (mean Jaccard **{summary['mean_jaccard']}**)",
        f"- Where it stayed / broke: over-merge residual "
        f"**{summary['common_over_merged']}**; missed **{summary['common_missed']}**",
        "",
        "## Per-host detail (last successful attempt)",
        "",
        "| Host | Role | Compromised | Flagged | Over-merge | Quarantine dry-run | Saved | Methods |",
        "|------|------|-------------|---------|------------|--------------------|-------|---------|",
    ]
    for row in report["host_table"]:
        methods = ", ".join(row["attack_methods"][:4])
        if len(row["attack_methods"]) > 4:
            methods += ", ..."
        lines.append(
            "| {host} | {role} | {c} | {f} | {o} | {q} | {s} | {m} |".format(
                host=row["host"],
                role=row["role"].replace("|", "/"),
                c="yes" if row["compromised_truth"] else "no",
                f="yes" if row["correlator_flagged"] else "no",
                o="yes" if row["over_merged"] else "no",
                q="yes" if row["quarantine_dry_run"] else "no",
                s="yes" if row["saved"] else "no",
                m=methods.replace("|", "/"),
            )
        )
    lines.extend(
        [
            "",
            "## Retry attempts",
            "",
            "| # | OK | Wall s | Jaccard | Matched | Over-merged | Quarantine proposed |",
            "|---|----|--------|---------|---------|-------------|---------------------|",
        ]
    )
    for a in report["attempts"]:
        if not a.get("ok"):
            lines.append(f"| {a['attempt']} | no | {a.get('wall_seconds')} | - | - | - | - |")
            continue
        lines.append(
            "| {n} | yes | {w} | {j} | {m} | {o} | {q} |".format(
                n=a["attempt"],
                w=a.get("wall_seconds"),
                j=a.get("correlator_jaccard"),
                m=a.get("correlator_matched"),
                o=", ".join(a.get("over_merged_hosts") or []) or "-",
                q=", ".join(a.get("quarantine_proposed") or []) or "-",
            )
        )
    lines.extend(
        [
            "",
            "## Honesty",
            "",
            "- Quarantine column is **dry-run IsolateHost proposals**, not live OS quarantine.",
            "- DNS OOB SQLi channels are intentional blind spots in current detectors.",
            "- Saved = innocent host not falsely proposed for isolate.",
            "",
        ]
    )
    return "\n".join(lines)


def main() -> int:
    retries = 8
    if len(sys.argv) > 1:
        retries = max(1, int(sys.argv[1]))
    man = json.loads(MANIFEST.read_text(encoding="utf-8"))
    if OUT.exists():
        shutil.rmtree(OUT)
    OUT.mkdir(parents=True)

    wall0 = time.perf_counter()
    attempts = [one_attempt(i + 1) for i in range(retries)]
    total_wall = round(time.perf_counter() - wall0, 4)

    ok_attempts = [a for a in attempts if a.get("ok")]
    last = ok_attempts[-1] if ok_attempts else attempts[-1]
    host_table = build_host_table(man, last) if last.get("ok") else []

    truth = list(man.get("truth_hosts") or [])
    saved = [r["host"] for r in host_table if r["saved"]]
    false_q = [r["host"] for r in host_table if r["quarantine_dry_run"] and not r["compromised_truth"]]
    jacs = [float(a["correlator_jaccard"]) for a in ok_attempts if a.get("correlator_jaccard") is not None]
    matches = [bool(a.get("correlator_matched")) for a in ok_attempts]

    # stable residuals across retries
    from collections import Counter

    over_c = Counter()
    miss_c = Counter()
    for a in ok_attempts:
        over_c.update(a.get("over_merged_hosts") or [])
        miss_c.update(a.get("missed_hosts") or [])
    n_ok = max(1, len(ok_attempts))
    common_over = sorted(h for h, c in over_c.items() if c >= n_ok // 2 + (n_ok % 2))
    common_miss = sorted(h for h, c in miss_c.items() if c >= n_ok // 2 + (n_ok % 2))

    report = {
        "test": "Continuous SQL ART stress",
        "manifest": "labs/breaktest/manifests/break_sql_continuous_art.json",
        "retries": retries,
        "total_wall_seconds": total_wall,
        "first_compromise": _first_compromise(man),
        "break_methods": [
            "union_select_probe",
            "boolean_blind_retry",
            "time_based_blind_retry",
            "credential_spray_sql_logins",
            "stacked_query / xp_cmdshell",
            "stolen_sa_lateral",
            "linked_server_hop",
            "svc_account_reuse_burst",
            "bulk_table_dump",
            "dns_oob_sqli_exfil",
            "shared_sql_svc_benign_bait",
        ],
        "summary": {
            "truth_hosts": truth,
            "hosts_saved": saved,
            "hosts_saved_count": len(saved),
            "false_quarantine": false_q,
            "false_quarantine_count": len(false_q),
            "match_rate": round(sum(1 for m in matches if m) / max(1, len(matches)), 3),
            "mean_jaccard": round(sum(jacs) / max(1, len(jacs)), 4) if jacs else None,
            "common_over_merged": common_over,
            "common_missed": common_miss,
            "held": "truth APT {a,b,c} matched" if matches and all(matches) else "unstable or partial",
            "broke_on": common_over or common_miss or ["none_stable"],
        },
        "host_table": host_table,
        "attempts": attempts,
        "honesty": (
            "Synthetic ART-style event sketches. No live SQLi. "
            "Quarantine = dry-run proposals only. CORVEX_CONTAIN remains locked."
        ),
    }
    REPORT.parent.mkdir(parents=True, exist_ok=True)
    REPORT.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    MD.write_text(markdown_report(report), encoding="utf-8")
    text = markdown_report(report)
    try:
        print(text)
    except UnicodeEncodeError:
        sys.stdout.buffer.write(text.encode("utf-8", errors="replace"))
        sys.stdout.buffer.write(b"\n")
    print(f"\nJSON: {REPORT}")
    return 0 if ok_attempts else 1


if __name__ == "__main__":
    raise SystemExit(main())
