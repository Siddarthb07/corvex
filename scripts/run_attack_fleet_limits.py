#!/usr/bin/env python3
"""Fleet: Limits — falsifiable breaking-point suite (find where Corvex fails).

See docs/attack-fleet-limits.md for scoring criteria stated before the run.
"""

from __future__ import annotations

import argparse
import json
import random
import shutil
import subprocess
import sys
import time
from pathlib import Path
from typing import Any, Dict, List, Mapping, Optional, Sequence, Set, Tuple

ROOT = Path(__file__).resolve().parents[1]
FLEET_DIR = ROOT / "labs" / "breaktest" / "manifests" / "fleet-limits"
RUN = ROOT / "runs" / "attack-fleet-limits"
REPORT_JSON = ROOT / "reports" / "attack_fleet_limits.json"
REPORT_MD = ROOT / "reports" / "attack_fleet_limits.md"

HOSTS5 = ["host-a", "host-b", "host-c", "host-d", "host-e"]
HOSTS6 = HOSTS5 + ["host-f"]
PRODUCERS5 = {h: f"prod-{h[-1]}" for h in HOSTS5}
PRODUCERS6 = {**PRODUCERS5, "host-f": "prod-f"}

FRAGILE_MARGIN = 0.2

# Consequence order for write-ups (lead with FP / structural, not raw BROKE count).
WRITEUP_PRIORITY = [
    "lim10-authorized-redteam",       # #10 — FP worse than baseline
    "lim09b-sequential-reuse",        # #9b — structural small-fleet failure
    "lim09-max-density-overlap",      # #9 — hub / identity
    "lim11-hostname-split-brain",     # #11 — identity twin of #9
    "lim02-triple-concurrent-shared", # #2 — chained over-merge
    "lim03-slow-low-day-gaps",        # #3 — operational lookback boundary
    "lim09d-benign-hub-pivot",        # #9d — often fragile HELD
    "lim01-dual-ambiguous-lateral",   # #1 — soft near-miss
]


def _is_fragile(verdict: str, margin: Any, false_q: Sequence[str]) -> bool:
    """HELD with razor-thin margin (or collateral FQ + thin margin) is not a clean pass."""
    if verdict != "HELD":
        return False
    if margin is None:
        return bool(false_q)
    try:
        m = float(margin)
    except (TypeError, ValueError):
        return bool(false_q)
    return m < FRAGILE_MARGIN


def _verdict_label(a: Mapping[str, Any]) -> str:
    v = str(a.get("verdict") or "")
    if a.get("fragile") and v == "HELD":
        return "HELD, fragile"
    return v


def _priority_key(a: Mapping[str, Any]) -> Tuple[int, str]:
    cid = str(a.get("campaign_id") or "")
    try:
        return (WRITEUP_PRIORITY.index(cid), cid)
    except ValueError:
        return (len(WRITEUP_PRIORITY), cid)


HEADLINE_IDS = {
    "lim09-max-density-overlap",
    "lim09b-sequential-reuse",
    "lim09c-positional-bias",
    "lim09d-benign-hub-pivot",
    "lim10-authorized-redteam",
}

SCORING_PREAMBLE = """
## Scoring criteria (stated before the run)

| Verdict | Criteria |
|---------|----------|
| **HELD** | Best-campaign Jaccard ≥ 0.9, no false-negative on any truth host, ambiguous legitimate activity correctly kept split (not merged into the malicious campaign). |
| **PARTIAL** | Jaccard 0.5–0.89, OR a truth host missed but recovered on replay, OR a benign host wrongly merged into the malicious campaign (over-merge) without being falsely quarantined. |
| **BROKE** | Jaccard < 0.5, OR a truth host never recovered, OR a benign host proposed for quarantine as part of the malicious campaign specifically because it got merged in. |

Also: **margin** = confidence(top) − confidence(2nd-best). **baseline** = B1 single-host isolation (no cross-host correlation).
**HELD, fragile** = HELD with margin < 0.2 (near-miss wearing a pass — not equivalent to a clean HELD).
""".strip()


def _annotate_fragile(row: Dict[str, Any]) -> Dict[str, Any]:
    row["fragile"] = _is_fragile(
        str(row.get("verdict") or ""),
        row.get("confidence_margin"),
        row.get("false_quarantine") or [],
    )
    row["verdict_label"] = _verdict_label(row)
    return row


def _jaccard(a: Set[str], b: Set[str]) -> float:
    if not a and not b:
        return 1.0
    if not a or not b:
        return 0.0
    return len(a & b) / len(a | b)


def base_man(
    campaign_id: str,
    *,
    truth: List[str],
    techniques: List[str],
    narrative: List[str],
    steps: List[Dict[str, Any]],
    break_intent: Dict[str, Any],
    hosts: Optional[List[str]] = None,
    producers: Optional[Dict[str, str]] = None,
    family: str = "genuine_vuln_breaker",
    headline: bool = False,
    truth_campaigns: Optional[List[Dict[str, Any]]] = None,
    host_clock_skew_seconds: Optional[Dict[str, float]] = None,
    drop_hosts: Optional[List[str]] = None,
    host_aliases: Optional[Dict[str, str]] = None,
    reference_jaccard: Optional[float] = None,
) -> Dict[str, Any]:
    hs = hosts or HOSTS5
    man: Dict[str, Any] = {
        "campaign_id": campaign_id,
        "family": family,
        "ood": True,
        "hosts": hs,
        "truth_hosts": truth,
        "producers": producers or ({h: f"prod-{h.split('-')[-1]}" for h in hs}),
        "base_time_utc": "2026-07-25T14:00:00Z",
        "fleet_origin": "original",
        "fleet_suite": "limits",
        "headline": headline,
        "source": {
            "style": "Fleet-limits breaking-point sketches",
            "repo": "https://github.com/Siddarthb07/corvex",
            "techniques": techniques,
            "note": break_intent.get("name") or campaign_id,
        },
        "narrative": narrative,
        "break_intent": break_intent,
        "steps": steps,
    }
    if truth_campaigns is not None:
        man["truth_campaigns"] = truth_campaigns
    if host_clock_skew_seconds:
        man["host_clock_skew_seconds"] = host_clock_skew_seconds
    if drop_hosts:
        man["drop_hosts"] = drop_hosts
    if host_aliases:
        man["host_aliases"] = host_aliases
    if reference_jaccard is not None:
        man["reference_jaccard"] = reference_jaccard
    return man


def fleet_manifests() -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []

    # 1 — Dual ambiguous lateral (share host-c)
    out.append(
        base_man(
            "lim01-dual-ambiguous-lateral",
            truth=["host-a", "host-b", "host-c"],
            techniques=["T1021.001", "T1078", "T1041"],
            narrative=[
                "APT a→b→c with RDP. Helpdesk RDP also touches c and reaches d/e in the same ±90s window.",
            ],
            break_intent={
                "name": "shared-node helpdesk overlap",
                "break_criterion": "d or e appears in the malicious campaign's Q dry-run list",
                "success_criteria_attacker": ["host-d or host-e in best-campaign quarantine"],
            },
            steps=[
                {"kind": "auth", "host": "host-a", "user": "apt-rdp", "src": "203.0.113.21", "offset_seconds": 0, "technique": "T1021.001"},
                {"kind": "auth", "host": "host-b", "user": "apt-rdp", "src": "host-a", "offset_seconds": 20, "technique": "T1021.001"},
                {"kind": "auth", "host": "host-c", "user": "apt-rdp", "src": "host-b", "offset_seconds": 40, "technique": "T1021.001"},
                {"kind": "exfil", "host": "host-c", "dst_ip": "198.51.100.190", "bytes": 16000, "offset_seconds": 55, "technique": "T1041"},
                {"kind": "exfil", "host": "host-b", "dst_ip": "198.51.100.190", "bytes": 14000, "offset_seconds": 60, "technique": "T1041"},
                # helpdesk overlaps ±90s, shares c, continues to d then e
                {"kind": "auth", "host": "host-c", "user": "helpdesk", "src": "10.30.0.9", "offset_seconds": 35, "technique": "T1021.001"},
                {"kind": "auth", "host": "host-d", "user": "helpdesk", "src": "host-c", "offset_seconds": 50, "technique": "T1021.001"},
                {"kind": "auth", "host": "host-e", "user": "helpdesk", "src": "host-d", "offset_seconds": 70, "technique": "T1021.001"},
            ],
        )
    )

    # 2 — Triple concurrent with chained shared hosts (needs host-f)
    out.append(
        base_man(
            "lim02-triple-concurrent-shared",
            hosts=HOSTS6,
            producers=PRODUCERS6,
            truth=["host-a", "host-b", "host-c", "host-d", "host-e", "host-f"],
            techniques=["T1003.001", "T1550.002", "T1110.003", "T1486", "T1078", "T1041"],
            narrative=[
                "Three concurrent incidents: PtH a-b-c, spray c-d, ransom d-e-f. Shared nodes must not collapse into one blob.",
            ],
            truth_campaigns=[
                {"id": "camp1-pth", "hosts": ["host-a", "host-b", "host-c"]},
                {"id": "camp2-spray", "hosts": ["host-c", "host-d"]},
                {"id": "camp3-ransom", "hosts": ["host-d", "host-e", "host-f"]},
            ],
            break_intent={
                "name": "triple concurrent collapse",
                "break_criterion": "any two of the three campaigns collapse into a single reported campaign",
                "success_criteria_attacker": ["two truth campaigns covered by one predicted campaign"],
            },
            steps=[
                # camp1 PtH
                {"kind": "auth", "host": "host-a", "user": "Administrator", "src": "203.0.113.10", "offset_seconds": 0, "technique": "T1003.001"},
                {"kind": "auth", "host": "host-b", "user": "Administrator", "src": "host-a", "offset_seconds": 8, "technique": "T1550.002"},
                {"kind": "auth", "host": "host-c", "user": "Administrator", "src": "host-b", "offset_seconds": 16, "technique": "T1550.002"},
                {"kind": "exfil", "host": "host-c", "dst_ip": "198.51.100.20", "bytes": 22000, "offset_seconds": 28, "technique": "T1041"},
                # camp2 spray success
                {"kind": "auth", "host": "host-c", "user": "spray-hit", "src": "203.0.113.99", "offset_seconds": 12, "technique": "T1110.003"},
                {"kind": "auth", "host": "host-d", "user": "spray-hit", "src": "host-c", "offset_seconds": 22, "technique": "T1078"},
                {"kind": "exfil", "host": "host-d", "dst_ip": "198.51.100.60", "bytes": 18000, "offset_seconds": 35, "technique": "T1041"},
                # camp3 ransom / quiet op
                {"kind": "auth", "host": "host-d", "user": "ransom-op", "src": "203.0.113.77", "offset_seconds": 18, "technique": "T1486"},
                {"kind": "auth", "host": "host-e", "user": "ransom-op", "src": "host-d", "offset_seconds": 30, "technique": "T1486"},
                {"kind": "auth", "host": "host-f", "user": "ransom-op", "src": "host-e", "offset_seconds": 42, "technique": "T1486"},
                {"kind": "exfil", "host": "host-f", "dst_ip": "198.51.100.100", "bytes": 25000, "offset_seconds": 55, "technique": "T1041"},
            ],
        )
    )

    # 3 — Slow-and-low day-scale gaps
    day = 86400
    out.append(
        base_man(
            "lim03-slow-low-day-gaps",
            truth=["host-a", "host-b", "host-c"],
            techniques=["T1078", "T1041"],
            narrative=[
                "Same sleeper identity across 14d / 21d / 9d quiet gaps — finds lookback cliffs.",
            ],
            break_intent={
                "name": "day-scale sleeper",
                "break_criterion": "any truth-host event outside the window silently dropped from campaign reconstruction",
                "success_criteria_attacker": ["truth hosts fragmented across campaigns or missed"],
            },
            steps=[
                {"kind": "auth", "host": "host-a", "user": "sleeper", "src": "203.0.113.55", "offset_seconds": 0, "technique": "T1078"},
                {"kind": "auth", "host": "host-b", "user": "sleeper", "src": "host-a", "offset_seconds": 30, "technique": "T1078"},
                {"kind": "exfil", "host": "host-b", "dst_ip": "198.51.100.90", "bytes": 12000, "offset_seconds": 60, "technique": "T1041"},
                # +14 days
                {"kind": "auth", "host": "host-b", "user": "sleeper", "src": "10.1.0.50", "offset_seconds": 14 * day, "technique": "T1078"},
                {"kind": "auth", "host": "host-c", "user": "sleeper", "src": "10.1.0.51", "offset_seconds": 14 * day + 120, "technique": "T1078"},
                {"kind": "exfil", "host": "host-c", "dst_ip": "198.51.100.91", "bytes": 15000, "offset_seconds": 14 * day + 240, "technique": "T1041"},
                # +21 days from second wave
                {"kind": "auth", "host": "host-c", "user": "sleeper", "src": "10.1.0.52", "offset_seconds": (14 + 21) * day, "technique": "T1078"},
                {"kind": "exfil", "host": "host-a", "dst_ip": "198.51.100.92", "bytes": 11000, "offset_seconds": (14 + 21) * day + 180, "technique": "T1041"},
                # +9 days from third wave
                {"kind": "auth", "host": "host-a", "user": "sleeper", "src": "10.1.0.53", "offset_seconds": (14 + 21 + 9) * day, "technique": "T1078"},
                {"kind": "exfil", "host": "host-b", "dst_ip": "198.51.100.93", "bytes": 13000, "offset_seconds": (14 + 21 + 9) * day + 90, "technique": "T1041"},
            ],
        )
    )

    # 4 — Timing jitter (seeded) vs DNS C2 / hybrid shapes
    rng = random.Random(42)
    base_iv = 5.0
    jitter_steps: List[Dict[str, Any]] = []
    t = 0.0
    dns_hosts = ["host-a", "host-a", "host-b", "host-b", "host-c", "host-c"]
    for i, h in enumerate(dns_hosts):
        jitter_steps.append(
            {
                "kind": "dns",
                "host": h,
                "query": f"{i}.c2.evil.test",
                "offset_seconds": round(t, 2),
                "technique": "T1071.004",
            }
        )
        t += base_iv * rng.uniform(0.0, 6.0)
    jitter_steps.extend(
        [
            {"kind": "auth", "host": "host-a", "user": "hybrid", "src": "203.0.113.19", "offset_seconds": round(t + 10, 2), "technique": "T1078"},
            {"kind": "auth", "host": "host-b", "user": "hybrid", "src": "host-a", "offset_seconds": round(t + 10 + base_iv * rng.uniform(0, 6), 2), "technique": "T1078"},
            {"kind": "auth", "host": "host-c", "user": "hybrid", "src": "host-b", "offset_seconds": round(t + 40 + base_iv * rng.uniform(0, 6), 2), "technique": "T1078"},
            {"kind": "exfil", "host": "host-c", "dst_ip": "198.51.100.170", "bytes": 14000, "offset_seconds": round(t + 80, 2), "technique": "T1041"},
        ]
    )
    out.append(
        base_man(
            "lim04-timing-jitter",
            truth=["host-a", "host-b", "host-c"],
            techniques=["T1071.004", "T1078", "T1041"],
            narrative=["Same shape as fleet05/17 with per-stage uniform 0–6× interval jitter."],
            reference_jaccard=1.0,
            break_intent={
                "name": "timing jitter evasion",
                "break_criterion": "Jaccard drop vs #5/#17 baseline at matched technique set",
                "success_criteria_attacker": ["corr_jaccard < reference_jaccard"],
            },
            steps=jitter_steps,
        )
    )

    # 5 — Technique substitution (Kerberoast → WinRM → exfil)
    out.append(
        base_man(
            "lim05-technique-sub-kerberoast",
            truth=["host-a", "host-b", "host-c"],
            techniques=["T1558", "T1021.006", "T1041"],
            narrative=["Off-library techniques: Kerberoast foothold, WinRM lateral, exfil."],
            break_intent={
                "name": "off-library technique substitution",
                "break_criterion": "campaign not detected, or techniques logged but not correlated",
                "success_criteria_attacker": ["both_missed or fragmented"],
            },
            steps=[
                {"kind": "auth", "host": "host-a", "user": "svc-sql", "src": "203.0.113.40", "offset_seconds": 0, "technique": "T1558"},
                {"kind": "auth", "host": "host-a", "user": "svc-sql", "src": "203.0.113.40", "offset_seconds": 5, "technique": "T1558"},
                {"kind": "auth", "host": "host-b", "user": "svc-sql", "src": "host-a", "offset_seconds": 15, "technique": "T1021.006"},
                {"kind": "auth", "host": "host-c", "user": "svc-sql", "src": "host-b", "offset_seconds": 25, "technique": "T1021.006"},
                {"kind": "exfil", "host": "host-c", "dst_ip": "198.51.100.210", "bytes": 20000, "offset_seconds": 40, "technique": "T1041"},
                {"kind": "exfil", "host": "host-b", "dst_ip": "198.51.100.210", "bytes": 15000, "offset_seconds": 45, "technique": "T1041"},
            ],
        )
    )

    # 6 — Clock skew +47s on host-b (fleet01 shape)
    out.append(
        base_man(
            "lim06-clock-skew-47s",
            truth=["host-a", "host-b", "host-c"],
            techniques=["T1003.001", "T1550.002", "T1021", "T1041"],
            narrative=["Cred dump→PtH with host-b clock +47s (unannounced NTP drift)."],
            host_clock_skew_seconds={"host-b": 47.0},
            break_intent={
                "name": "clock skew",
                "break_criterion": "causal ordering a→b→c wrong, or b dropped due to apparent gap",
                "success_criteria_attacker": ["host-b missed or campaign fragmented"],
            },
            steps=[
                {"kind": "auth", "host": "host-a", "user": "Administrator", "src": "203.0.113.10", "offset_seconds": 0, "technique": "T1003.001"},
                {"kind": "auth", "host": "host-a", "user": "Administrator", "src": "203.0.113.10", "offset_seconds": 3, "technique": "T1003.001"},
                {"kind": "auth", "host": "host-b", "user": "Administrator", "src": "host-a", "offset_seconds": 8, "technique": "T1550.002"},
                {"kind": "auth", "host": "host-b", "user": "Administrator", "src": "host-a", "offset_seconds": 11, "technique": "T1550.002"},
                {"kind": "auth", "host": "host-c", "user": "Administrator", "src": "host-b", "offset_seconds": 16, "technique": "T1021"},
                {"kind": "auth", "host": "host-c", "user": "Administrator", "src": "host-b", "offset_seconds": 19, "technique": "T1021"},
                {"kind": "exfil", "host": "host-c", "dst_ip": "198.51.100.20", "bytes": 24000, "offset_seconds": 28, "technique": "T1041"},
                {"kind": "exfil", "host": "host-b", "dst_ip": "198.51.100.20", "bytes": 18000, "offset_seconds": 32, "technique": "T1041"},
            ],
        )
    )

    # 7 — Dropped mid-chain (host-c silent)
    out.append(
        base_man(
            "lim07-dropped-mid-chain",
            truth=["host-a", "host-b", "host-c", "host-d"],
            techniques=["T1021.002", "T1078", "T1041"],
            narrative=["SMB hop a→b→c→d but host-c agent is down — missing witness."],
            drop_hosts=["host-c"],
            break_intent={
                "name": "dropped mid-chain",
                "break_criterion": "PARTIAL/BROKE, or false confidence that a,d is complete",
                "success_criteria_attacker": ["host-c missed; incomplete chain treated as complete"],
            },
            steps=[
                {"kind": "recon", "host": "host-a", "dst_ips": ["10.50.0.11", "10.50.0.12", "10.50.0.13", "10.50.0.14", "10.50.0.15", "10.50.0.16"], "dst_port": 445, "dst_step": 1, "offset_seconds": 0, "technique": "T1021.002"},
                {"kind": "auth", "host": "host-a", "user": "svc-deploy", "src": "10.50.0.9", "offset_seconds": 10, "technique": "T1078"},
                {"kind": "auth", "host": "host-b", "user": "svc-deploy", "src": "host-a", "offset_seconds": 14, "technique": "T1021.002"},
                {"kind": "auth", "host": "host-c", "user": "svc-deploy", "src": "host-b", "offset_seconds": 18, "technique": "T1021.002"},
                {"kind": "auth", "host": "host-d", "user": "svc-deploy", "src": "host-c", "offset_seconds": 22, "technique": "T1021.002"},
                {"kind": "exfil", "host": "host-d", "dst_ip": "198.51.100.40", "bytes": 30000, "offset_seconds": 35, "technique": "T1041"},
            ],
        )
    )

    # 8 — Out-of-order arrival (exfil ts before lateral)
    out.append(
        base_man(
            "lim08-out-of-order-arrival",
            truth=["host-a", "host-b"],
            techniques=["T1041", "T1105", "T1078"],
            narrative=["Chunked exfil on b arrives/timestamped before the lateral from a that caused it."],
            break_intent={
                "name": "out-of-order",
                "break_criterion": "causal chain backwards, or split into two false fragments",
                "success_criteria_attacker": ["fragmented or inverted chain"],
            },
            steps=[
                # CDN bait
                {"kind": "exfil", "host": "host-c", "dst_ip": "104.18.32.7", "bytes": 8000, "offset_seconds": 0, "technique": "T1105"},
                {"kind": "exfil", "host": "host-d", "dst_ip": "104.18.32.7", "bytes": 7900, "offset_seconds": 5, "technique": "T1105"},
                # exfil BEFORE causal auth (shipping delay / skew)
                {"kind": "exfil", "host": "host-b", "dst_ip": "198.51.100.80", "bytes": 9000, "offset_seconds": 10, "technique": "T1041"},
                {"kind": "exfil", "host": "host-a", "dst_ip": "198.51.100.80", "bytes": 9000, "offset_seconds": 12, "technique": "T1041"},
                {"kind": "auth", "host": "host-a", "user": "chunker", "src": "203.0.113.8", "offset_seconds": 40, "technique": "T1078"},
                {"kind": "auth", "host": "host-b", "user": "chunker", "src": "host-a", "offset_seconds": 45, "technique": "T1078"},
                {"kind": "exfil", "host": "host-b", "dst_ip": "198.51.100.80", "bytes": 9000, "offset_seconds": 55, "technique": "T1041"},
                {"kind": "exfil", "host": "host-a", "dst_ip": "198.51.100.80", "bytes": 9000, "offset_seconds": 58, "technique": "T1041"},
            ],
        )
    )

    # 9 — Max density overlap on 5 hosts
    out.append(
        base_man(
            "lim09-max-density-overlap",
            truth=["host-a", "host-b", "host-c", "host-d", "host-e"],
            techniques=["T1003.001", "T1550.002", "T1110.003", "T1486", "T1078", "T1041"],
            headline=True,
            narrative=["Three overlapping campaigns; host-c in all three — combinatorial density stress."],
            truth_campaigns=[
                {"id": "c1-pth", "hosts": ["host-a", "host-b", "host-c"]},
                {"id": "c2-spray", "hosts": ["host-b", "host-c", "host-d"]},
                {"id": "c3-ransom", "hosts": ["host-c", "host-d", "host-e"]},
            ],
            break_intent={
                "name": "max density overlap",
                "break_criterion": "any two campaigns collapse, or host-c attribution near-random",
                "success_criteria_attacker": ["campaign collapse or mis-attribution at hub"],
            },
            steps=[
                {"kind": "auth", "host": "host-a", "user": "Administrator", "src": "203.0.113.10", "offset_seconds": 0, "technique": "T1003.001"},
                {"kind": "auth", "host": "host-b", "user": "Administrator", "src": "host-a", "offset_seconds": 8, "technique": "T1550.002"},
                {"kind": "auth", "host": "host-c", "user": "Administrator", "src": "host-b", "offset_seconds": 16, "technique": "T1550.002"},
                {"kind": "exfil", "host": "host-c", "dst_ip": "198.51.100.20", "bytes": 22000, "offset_seconds": 30, "technique": "T1041"},
                {"kind": "auth", "host": "host-b", "user": "spray-hit", "src": "203.0.113.99", "offset_seconds": 5, "technique": "T1110.003"},
                {"kind": "auth", "host": "host-c", "user": "spray-hit", "src": "host-b", "offset_seconds": 14, "technique": "T1078"},
                {"kind": "auth", "host": "host-d", "user": "spray-hit", "src": "host-c", "offset_seconds": 24, "technique": "T1078"},
                {"kind": "exfil", "host": "host-d", "dst_ip": "198.51.100.60", "bytes": 18000, "offset_seconds": 40, "technique": "T1041"},
                {"kind": "auth", "host": "host-c", "user": "ransom-op", "src": "203.0.113.77", "offset_seconds": 10, "technique": "T1486"},
                {"kind": "auth", "host": "host-d", "user": "ransom-op", "src": "host-c", "offset_seconds": 20, "technique": "T1486"},
                {"kind": "auth", "host": "host-e", "user": "ransom-op", "src": "host-d", "offset_seconds": 32, "technique": "T1486"},
                {"kind": "exfil", "host": "host-e", "dst_ip": "198.51.100.100", "bytes": 25000, "offset_seconds": 50, "technique": "T1041"},
            ],
        )
    )

    # 9b — Sequential reuse same hosts
    out.append(
        base_man(
            "lim09b-sequential-reuse",
            truth=["host-a", "host-b", "host-c"],
            techniques=["T1071.004", "T1053.005", "T1078", "T1041"],
            headline=True,
            narrative=["DNS C2 shape then scheduled-task shape on same a/b/c after 10 min quiet."],
            truth_campaigns=[
                {"id": "inc1-dns", "hosts": ["host-a", "host-b", "host-c"]},
                {"id": "inc2-task", "hosts": ["host-a", "host-b", "host-c"]},
            ],
            break_intent={
                "name": "sequential reuse",
                "break_criterion": "incident1 and incident2 reported as a single continuous campaign",
                "success_criteria_attacker": ["two incidents collapsed into one campaign"],
            },
            steps=[
                # incident 1 — DNS C2
                {"kind": "dns", "host": "host-a", "query": "a1.c2.evil.test", "offset_seconds": 0, "technique": "T1071.004"},
                {"kind": "dns", "host": "host-b", "query": "b1.c2.evil.test", "offset_seconds": 10, "technique": "T1071.004"},
                {"kind": "dns", "host": "host-c", "query": "c1.c2.evil.test", "offset_seconds": 20, "technique": "T1071.004"},
                {"kind": "auth", "host": "host-a", "user": "dns-only-a", "src": "203.0.113.1", "offset_seconds": 30, "technique": "T1078"},
                # 10 minute gap then incident 2 — scheduled task shape
                {"kind": "auth", "host": "host-a", "user": "tasksvc", "src": "203.0.113.12", "offset_seconds": 630, "technique": "T1053.005"},
                {"kind": "auth", "host": "host-b", "user": "tasksvc", "src": "host-a", "offset_seconds": 640, "technique": "T1078"},
                {"kind": "auth", "host": "host-c", "user": "tasksvc", "src": "host-b", "offset_seconds": 650, "technique": "T1078"},
                {"kind": "exfil", "host": "host-c", "dst_ip": "198.51.100.110", "bytes": 17000, "offset_seconds": 665, "technique": "T1041"},
            ],
        )
    )

    # 9c — Positional bias: e as patient zero (fleet01 + fleet06 rotated)
    # Rotation map: a<-e, b<-a, c<-b, d<-c, e<-d  so e plays former a
    rot = {"host-a": "host-e", "host-b": "host-a", "host-c": "host-b", "host-d": "host-c", "host-e": "host-d"}

    def R(h: str) -> str:
        return rot[h]

    out.append(
        base_man(
            "lim09c-positional-bias",
            truth=[R("host-a"), R("host-b"), R("host-c")],  # e, a, b
            techniques=["T1003.001", "T1550.002", "T1021", "T1110.003", "T1078", "T1041"],
            headline=True,
            narrative=["fleet01+fleet06 shapes with host labels rotated so e is patient zero."],
            reference_jaccard=1.0,
            break_intent={
                "name": "positional bias",
                "break_criterion": "Jaccard or margin regression vs original #1/#6 from host relabeling alone",
                "success_criteria_attacker": ["jaccard < reference after rotation"],
            },
            steps=[
                # rotated fleet01
                {"kind": "auth", "host": R("host-a"), "user": "Administrator", "src": "203.0.113.10", "offset_seconds": 0, "technique": "T1003.001"},
                {"kind": "auth", "host": R("host-b"), "user": "Administrator", "src": R("host-a"), "offset_seconds": 8, "technique": "T1550.002"},
                {"kind": "auth", "host": R("host-c"), "user": "Administrator", "src": R("host-b"), "offset_seconds": 16, "technique": "T1021"},
                {"kind": "exfil", "host": R("host-c"), "dst_ip": "198.51.100.20", "bytes": 24000, "offset_seconds": 28, "technique": "T1041"},
                # rotated spray success wave
                {"kind": "auth", "host": R("host-a"), "user": "jdoe", "src": "203.0.113.99", "offset_seconds": 50, "technique": "T1078"},
                {"kind": "auth", "host": R("host-b"), "user": "jdoe", "src": R("host-a"), "offset_seconds": 54, "technique": "T1078"},
                {"kind": "auth", "host": R("host-c"), "user": "jdoe", "src": R("host-b"), "offset_seconds": 58, "technique": "T1078"},
                {"kind": "exfil", "host": R("host-c"), "dst_ip": "198.51.100.60", "bytes": 21000, "offset_seconds": 70, "technique": "T1041"},
            ],
        )
    )

    # 9d — Benign hub + attack pivot on same host-c
    hub_bg: List[Dict[str, Any]] = []
    for i, peer in enumerate(["host-a", "host-b", "host-d", "host-e"]):
        for k in range(6):
            hub_bg.append(
                {
                    "kind": "auth",
                    "host": "host-c",
                    "user": f"biz-{peer[-1]}",
                    "src": peer,
                    "offset_seconds": i * 8 + k,
                    "technique": "T1021.001",
                }
            )
            hub_bg.append(
                {
                    "kind": "auth",
                    "host": peer,
                    "user": f"biz-{peer[-1]}",
                    "src": "host-c",
                    "offset_seconds": i * 8 + k + 1,
                    "technique": "T1021.002",
                }
            )
    attack = [
        {"kind": "auth", "host": "host-a", "user": "apt-pivot", "src": "203.0.113.88", "offset_seconds": 40, "technique": "T1078"},
        {"kind": "auth", "host": "host-c", "user": "apt-pivot", "src": "host-a", "offset_seconds": 48, "technique": "T1078"},
        {"kind": "auth", "host": "host-e", "user": "apt-pivot", "src": "host-c", "offset_seconds": 56, "technique": "T1078"},
        {"kind": "exfil", "host": "host-e", "dst_ip": "198.51.100.220", "bytes": 19000, "offset_seconds": 70, "technique": "T1041"},
        {"kind": "exfil", "host": "host-c", "dst_ip": "198.51.100.220", "bytes": 15000, "offset_seconds": 75, "technique": "T1041"},
    ]
    out.append(
        base_man(
            "lim09d-benign-hub-pivot",
            truth=["host-a", "host-c", "host-e"],
            techniques=["T1021.001", "T1021.002", "T1078", "T1041"],
            headline=True,
            narrative=["host-c is a busy legitimate jump box AND the real APT pivot; b/d are normal peers."],
            break_intent={
                "name": "benign hub masking",
                "break_criterion": "attack missed (BROKE) or b/d False Q via association",
                "success_criteria_attacker": ["truth miss or false quarantine of hub peers"],
            },
            steps=hub_bg + attack,
        )
    )

    # 10 — Authorized red-team (truth empty)
    out.append(
        base_man(
            "lim10-authorized-redteam",
            truth=[],
            techniques=["T1003.001", "T1021", "T1078"],
            headline=True,
            narrative=["Authorized credential audit — same fingerprint as fleet01, no malicious campaign."],
            break_intent={
                "name": "authorized red team FP",
                "break_criterion": "any host proposed for quarantine dry-run when truth is empty",
                "success_criteria_attacker": ["any quarantine proposal"],
            },
            steps=[
                {"kind": "auth", "host": "host-a", "user": "Administrator", "src": "203.0.113.10", "offset_seconds": 0, "technique": "T1003.001"},
                {"kind": "auth", "host": "host-b", "user": "Administrator", "src": "host-a", "offset_seconds": 8, "technique": "T1021"},
                {"kind": "auth", "host": "host-c", "user": "Administrator", "src": "host-b", "offset_seconds": 16, "technique": "T1021"},
                # no exfil — audit stop
            ],
        )
    )

    # 11 — Hostname / IP split-brain
    out.append(
        base_man(
            "lim11-hostname-split-brain",
            truth=["host-a", "host-b", "host-c"],
            techniques=["T1021", "T1078", "T1041"],
            hosts=HOSTS5 + ["host-b-dhcp"],
            producers={**PRODUCERS5, "host-b-dhcp": "prod-b"},
            host_aliases={"host-b-dhcp": "host-b"},
            narrative=["host-b DHCP re-lease mid-attack: later events arrive as host-b-dhcp."],
            break_intent={
                "name": "hostname split-brain",
                "break_criterion": "b's two identities treated as separate hosts, splitting coverage",
                "success_criteria_attacker": ["host-b under-counted / campaign split"],
            },
            steps=[
                {"kind": "auth", "host": "host-a", "user": "ops", "src": "203.0.113.200", "offset_seconds": 0, "technique": "T1078"},
                {"kind": "auth", "host": "host-b", "user": "ops", "src": "10.1.0.11", "offset_seconds": 8, "technique": "T1021"},
                {"kind": "auth", "host": "host-b", "user": "ops", "src": "10.1.0.11", "offset_seconds": 20, "technique": "T1021", "emit_host": "host-b-dhcp"},
                {"kind": "auth", "host": "host-c", "user": "ops", "src": "10.1.0.12", "offset_seconds": 28, "technique": "T1021"},
                {"kind": "exfil", "host": "host-c", "dst_ip": "198.51.100.70", "bytes": 19000, "offset_seconds": 40, "technique": "T1041"},
                {"kind": "exfil", "host": "host-b", "dst_ip": "198.51.100.70", "bytes": 16000, "offset_seconds": 44, "technique": "T1041", "emit_host": "host-b-dhcp"},
            ],
        )
    )

    # 12 — Near-duplicate CDN mimicry
    out.append(
        base_man(
            "lim12-near-dup-cdn-mimicry",
            truth=["host-a", "host-b", "host-c"],
            techniques=["T1105", "T1078", "T1041"],
            narrative=["C2 traffic matches CDN bait timing/volume exactly; APT still moves underneath."],
            reference_jaccard=1.0,
            break_intent={
                "name": "CDN mimicry",
                "break_criterion": "Jaccard regression vs #8/#20 passing results",
                "success_criteria_attacker": ["jaccard < reference or innocents false-Q"],
            },
            steps=[
                # fleet CDN — same cadence/bytes as "C2"
                *[{"kind": "exfil", "host": h, "dst_ip": "104.18.32.7", "bytes": 7500, "offset_seconds": i * 3, "technique": "T1105"} for i, h in enumerate(HOSTS5)],
                # APT C2 shaped identically (same interval/bytes) to different dst
                *[{"kind": "exfil", "host": h, "dst_ip": "198.51.100.80", "bytes": 7500, "offset_seconds": 20 + i * 3, "technique": "T1105"} for i, h in enumerate(["host-a", "host-b", "host-c"])],
                {"kind": "auth", "host": "host-a", "user": "under", "src": "203.0.113.22", "offset_seconds": 45, "technique": "T1078"},
                {"kind": "auth", "host": "host-b", "user": "under", "src": "host-a", "offset_seconds": 53, "technique": "T1078"},
                {"kind": "auth", "host": "host-c", "user": "under", "src": "host-b", "offset_seconds": 61, "technique": "T1078"},
                {"kind": "exfil", "host": "host-c", "dst_ip": "198.51.100.200", "bytes": 7500, "offset_seconds": 75, "technique": "T1041"},
                {"kind": "exfil", "host": "host-b", "dst_ip": "198.51.100.200", "bytes": 7500, "offset_seconds": 78, "technique": "T1041"},
            ],
        )
    )

    return out


def write_manifests() -> List[Path]:
    if FLEET_DIR.exists():
        shutil.rmtree(FLEET_DIR)
    FLEET_DIR.mkdir(parents=True)
    paths = []
    for man in fleet_manifests():
        path = FLEET_DIR / f"{man['campaign_id']}.json"
        path.write_text(json.dumps(man, indent=2) + "\n", encoding="utf-8")
        paths.append(path)
    return paths


def _canon(hosts: Sequence[str], aliases: Dict[str, str]) -> Set[str]:
    return {aliases.get(str(h), str(h)) for h in hosts}


def _collapse_pair(pred_hosts: Set[str], t1: Set[str], t2: Set[str]) -> bool:
    """True when one predicted campaign looks like the *union* of two truths.

    Overlap alone is not collapse — shared hosts between concurrent incidents
    are expected (lim09 hub). Collapse requires the pred to match the union
    better than either truth alone.
    """
    if not t1 or not t2 or not pred_hosts:
        return False
    cov1 = len(pred_hosts & t1) / len(t1)
    cov2 = len(pred_hosts & t2) / len(t2)
    if cov1 < 0.5 or cov2 < 0.5:
        return False
    union = t1 | t2
    j_union = _jaccard(pred_hosts, union)
    j1 = _jaccard(pred_hosts, t1)
    j2 = _jaccard(pred_hosts, t2)
    return j_union >= 0.75 and j_union > max(j1, j2) + 0.05


def _multi_campaign_stats(
    pred_camps: List[Dict[str, Any]],
    truth_campaigns: List[Dict[str, Any]],
    aliases: Dict[str, str],
) -> Dict[str, Any]:
    truths = [
        {"id": tc.get("id"), "hosts": _canon(tc.get("hosts") or [], aliases)}
        for tc in truth_campaigns
    ]
    preds = [
        {
            "campaign_id": c.get("campaign_id"),
            "hosts": _canon(c.get("hosts") or c.get("host_ids") or [], aliases),
            "score": float(c.get("score") or 0.0),
        }
        for c in pred_camps
    ]
    # Host-set collapse only when truth campaigns are *distinct* host sets.
    # Sequential reuse (same hosts, different incidents) uses pred-count instead.
    identical_host_truths = len({frozenset(t["hosts"]) for t in truths}) < len(truths)
    collapsed_pairs: List[List[str]] = []
    if not identical_host_truths:
        for i, t1 in enumerate(truths):
            for t2 in truths[i + 1 :]:
                for p in preds:
                    if _collapse_pair(p["hosts"], t1["hosts"], t2["hosts"]):
                        collapsed_pairs.append([t1["id"], t2["id"], p["campaign_id"]])
                        break
    # Greedy best Jaccard assignment (for distinct host sets).
    used: Set[int] = set()
    matches = []
    jaccards = []
    for t in truths:
        best_i, best_j = -1, -1.0
        for i, p in enumerate(preds):
            if i in used and not identical_host_truths:
                continue
            j = _jaccard(p["hosts"], t["hosts"])
            if j > best_j:
                best_j, best_i = j, i
        if best_i >= 0:
            if not identical_host_truths:
                used.add(best_i)
            matches.append(
                {
                    "truth_id": t["id"],
                    "pred_id": preds[best_i]["campaign_id"],
                    "jaccard": round(best_j, 4),
                    "pred_hosts": sorted(preds[best_i]["hosts"]),
                    "truth_hosts": sorted(t["hosts"]),
                }
            )
            jaccards.append(best_j)
        else:
            matches.append(
                {
                    "truth_id": t["id"],
                    "pred_id": None,
                    "jaccard": 0.0,
                    "pred_hosts": [],
                    "truth_hosts": sorted(t["hosts"]),
                }
            )
            jaccards.append(0.0)
    return {
        "collapsed_pairs": collapsed_pairs,
        "collapsed": bool(collapsed_pairs),
        "identical_host_truths": identical_host_truths,
        "n_pred_campaigns": len(preds),
        "matches": matches,
        "mean_jaccard": round(sum(jaccards) / max(1, len(jaccards)), 4),
        "min_jaccard": round(min(jaccards) if jaccards else 0.0, 4),
    }


def _verdict_limits(
    *,
    man: Dict[str, Any],
    corr_jaccard: float,
    missed: List[str],
    over_merged: List[str],
    false_q: List[str],
    best_campaign_hosts: Set[str],
    multi: Optional[Dict[str, Any]],
    recovered_on_replay: bool,
) -> Tuple[str, List[str]]:
    reasons: List[str] = []
    truth = set(man.get("truth_hosts") or [])
    aliases = {str(k): str(v) for k, v in (man.get("host_aliases") or {}).items()}
    break_crit = str((man.get("break_intent") or {}).get("break_criterion") or "")

    # Empty truth — FP stress
    if "truth_hosts" in man and not truth and not man.get("truth_campaigns"):
        if false_q:
            reasons.append("quarantine proposed with empty truth")
            return "BROKE", reasons
        reasons.append("no quarantine with empty truth")
        return "HELD", reasons

    # Multi-campaign collapse
    if multi is not None:
        if multi.get("collapsed"):
            reasons.append(f"campaigns collapsed: {multi['collapsed_pairs']}")
            return "BROKE", reasons
        mj = float(multi.get("min_jaccard") or 0.0)
        mean_j = float(multi.get("mean_jaccard") or 0.0)
        if mj < 0.5:
            reasons.append(f"min multi-campaign jaccard={mj}")
            return "BROKE", reasons
        if mean_j < 0.9 or mj < 0.9:
            reasons.append(f"multi-campaign mean/min jaccard={mean_j}/{mj}")
            return "PARTIAL", reasons
        # Sequential reuse (same hosts): need ≥2 predicted campaigns to count as split.
        if multi.get("identical_host_truths"):
            n_pred = int(multi.get("n_pred_campaigns") or 0)
            if n_pred < 2:
                reasons.append(
                    f"sequential incidents collapsed into {n_pred} campaign(s)"
                )
                return "BROKE", reasons
            reasons.append(f"sequential incidents split across {n_pred} campaigns")
            return "HELD", reasons
        reasons.append("multi-campaign held")
        # still allow false-Q via merge into best
        merge_fq = sorted((set(false_q) & best_campaign_hosts) - truth)
        if merge_fq:
            reasons.append(f"benign merged into malicious Q: {merge_fq}")
            return "BROKE", reasons
        return "HELD", reasons

    # Manifest-specific: shared-node helpdesk (#1)
    if man["campaign_id"] == "lim01-dual-ambiguous-lateral":
        if any(h in best_campaign_hosts and h in false_q for h in ("host-d", "host-e")):
            reasons.append("d/e in malicious campaign Q dry-run")
            return "BROKE", reasons

    # Reference jaccard regression (#4, #9c, #12)
    ref = man.get("reference_jaccard")
    if ref is not None and corr_jaccard + 1e-9 < float(ref):
        reasons.append(f"jaccard {corr_jaccard} < reference {ref}")
        # classify by magnitude
        if corr_jaccard < 0.5:
            return "BROKE", reasons
        if corr_jaccard < 0.9:
            return "PARTIAL", reasons

    # Split-brain: after aliasing, host-b should be covered
    if man.get("host_aliases") and missed:
        reasons.append(f"alias coverage miss: {missed}")

    # Dropped mid-chain: host-c will be missed in telemetry — still truth
    if man.get("drop_hosts") and any(h in missed for h in man["drop_hosts"]):
        reasons.append("dropped-host truth not inferred")

    merge_fq = sorted((set(false_q) & best_campaign_hosts) - truth)
    if merge_fq:
        reasons.append(f"benign merged into malicious Q: {merge_fq}")
        return "BROKE", reasons

    if corr_jaccard < 0.5 or (missed and not recovered_on_replay):
        if missed and not recovered_on_replay:
            reasons.append(f"truth never recovered: {missed}")
        else:
            reasons.append(f"jaccard {corr_jaccard} < 0.5")
        return "BROKE", reasons

    if 0.5 <= corr_jaccard < 0.9 or over_merged or (missed and recovered_on_replay):
        if missed and recovered_on_replay:
            reasons.append(f"missed then recovered on replay: {missed}")
        elif over_merged:
            reasons.append(f"over-merged (no FQ): {over_merged}")
        else:
            reasons.append(f"jaccard {corr_jaccard} in PARTIAL band")
        return "PARTIAL", reasons

    if missed:
        reasons.append(f"false-negative hosts: {missed}")
        return "BROKE", reasons

    reasons.append("matched truth without merge-FQ")
    if break_crit:
        reasons.append(f"break_criterion not triggered: {break_crit}")
    return "HELD", reasons


def score_one(
    path: Path,
    *,
    intensity_rounds: int,
    baseline: str,
) -> Dict[str, Any]:
    stem = path.stem
    man = json.loads(path.read_text(encoding="utf-8"))
    hosts = list(man.get("hosts") or HOSTS5)
    aliases = {str(k): str(v) for k, v in (man.get("host_aliases") or {}).items()}
    truth = set(man.get("truth_hosts") or [])
    rounds = []
    t0 = time.perf_counter()
    for r in range(1, intensity_rounds + 1):
        out_dir = RUN / stem / f"r{r}"
        if out_dir.exists():
            shutil.rmtree(out_dir)
        out_dir.mkdir(parents=True)
        pack = out_dir / "pack.jsonl"
        breaks = out_dir / "breaks.json"
        proc = subprocess.run(
            [
                sys.executable,
                "-m",
                "corvex",
                "build-breaktest",
                str(path),
                "--out",
                str(pack),
                "--report",
                str(breaks),
            ],
            cwd=str(ROOT),
            capture_output=True,
            text=True,
        )
        row: Dict[str, Any] = {"round": r, "build_ok": proc.returncode == 0}
        if not breaks.is_file():
            row["error"] = (proc.stderr or proc.stdout or "")[-800:]
            rounds.append(row)
            continue
        br = json.loads(breaks.read_text(encoding="utf-8"))
        bp = br.get("break_points") or {}
        corr = br.get("correlator") or {}
        det = br.get("detector_only") or {}
        b1 = br.get("b1") or {}
        row.update(
            {
                "corr_matched": corr.get("matched"),
                "corr_jaccard": corr.get("best_jaccard"),
                "det_jaccard": det.get("best_jaccard"),
                "missed_hosts": bp.get("missed_hosts") or [],
                "over_merged_hosts": bp.get("over_merged_hosts") or [],
                "fusion_lift": bp.get("fusion_lift"),
                "both_missed": bp.get("both_missed"),
                "corr_hosts": corr.get("hosts_union") or [],
                "best_campaign_hosts": corr.get("best_campaign_hosts") or [],
                "confidence_margin": corr.get("confidence_margin"),
                "campaigns_ranked": corr.get("campaigns_ranked") or [],
                "b1_hosts": b1.get("hosts_union") or [],
                "b1_campaigns": b1.get("campaigns") or [],
            }
        )
        multi = None
        if man.get("truth_campaigns"):
            multi = _multi_campaign_stats(
                row["campaigns_ranked"],
                man["truth_campaigns"],
                aliases,
            )
            row["multi_campaign"] = multi

        replay = out_dir / "replay"
        subprocess.run(
            [
                sys.executable,
                "-m",
                "corvex",
                "replay",
                str(pack),
                "--out-dir",
                str(replay),
            ],
            cwd=str(ROOT),
            capture_output=True,
            text=True,
        )
        q: Set[str] = set()
        recon_hosts: Set[str] = set()
        recon_path = replay / "reconstruction.json"
        if recon_path.is_file():
            recon = json.loads(recon_path.read_text(encoding="utf-8"))
            for item in recon.get("campaign_reconstructions") or []:
                recon_hosts |= set(str(h) for h in (item.get("host_ids") or []))
                qq = item.get("quarantine") or {}
                # Empty host_ids [] is intentional (contain gate refused) — do not
                # fall through to campaign hosts via `or`.
                if "host_ids" in qq:
                    q.update(str(h) for h in (qq.get("host_ids") or []))
                else:
                    q.update(str(h) for h in (item.get("host_ids") or []))
        row["quarantine_proposed"] = sorted(_canon(q, aliases))
        row["recon_hosts"] = sorted(_canon(recon_hosts, aliases))
        rounds.append(row)

    wall = round(time.perf_counter() - t0, 4)
    last = rounds[-1] if rounds else {}
    best_hosts = _canon(last.get("best_campaign_hosts") or [], aliases)
    corr_hosts = _canon(last.get("corr_hosts") or [], aliases)
    qprop = set(last.get("quarantine_proposed") or [])
    recon = set(last.get("recon_hosts") or [])
    # Missed vs correlator, then whether replay recovered
    raw_missed = [h for h in sorted(truth - corr_hosts)]
    recovered = [h for h in raw_missed if h in recon]
    still_missed = [h for h in raw_missed if h not in recon]
    over = [h for h in (last.get("over_merged_hosts") or []) if aliases.get(h, h) not in truth]
    # Innocents = fleet hosts minus truth (alias-canonical), excluding alias emit ids
    fleet_hosts = _canon([h for h in hosts if h not in aliases], aliases)
    if man.get("truth_campaigns"):
        truth_union = set()
        for tc in man["truth_campaigns"]:
            truth_union |= _canon(tc.get("hosts") or [], aliases)
        innocents = fleet_hosts - truth_union
        truth_for_fq = truth_union
    else:
        innocents = fleet_hosts - truth
        truth_for_fq = truth
    saved = sorted(h for h in innocents if h not in qprop)
    false_q = sorted(h for h in innocents if h in qprop)

    # Baseline B1
    b1_hosts = _canon(last.get("b1_hosts") or [], aliases)
    b1_fq = sorted(h for h in innocents if h in b1_hosts)
    b1_cov = sorted(h for h in truth_for_fq if h in b1_hosts) if truth_for_fq else []
    corr_cov = sorted(h for h in truth_for_fq if h in corr_hosts) if truth_for_fq else []
    baseline_wins = False
    if baseline == "single-host-isolation":
        # Wins = strictly fewer False Q with coverage of truth at least as good.
        # Equal empty FQ on empty-truth is not a baseline win (both clean).
        if not truth_for_fq:
            baseline_wins = len(b1_fq) < len(false_q)
        else:
            baseline_wins = len(b1_fq) < len(false_q) and len(b1_cov) >= len(corr_cov)
            if len(b1_fq) < len(false_q) and len(b1_cov) > len(corr_cov):
                baseline_wins = True
            elif len(b1_fq) == len(false_q) and len(b1_cov) > len(corr_cov):
                baseline_wins = True

    j = float(last.get("corr_jaccard") or 0.0)
    if man.get("truth_campaigns") and last.get("multi_campaign"):
        j = float(last["multi_campaign"].get("mean_jaccard") or j)

    # For empty truth, jaccard vs empty is awkward — treat as 1.0 if no camps / no Q
    if "truth_hosts" in man and not truth and not man.get("truth_campaigns"):
        j = 1.0 if not qprop else 0.0

    verdict, reasons = _verdict_limits(
        man=man,
        corr_jaccard=j,
        missed=still_missed,
        over_merged=over,
        false_q=false_q,
        best_campaign_hosts=best_hosts,
        multi=last.get("multi_campaign"),
        recovered_on_replay=bool(recovered) and not still_missed,
    )

    margin = last.get("confidence_margin")
    row_out = {
        "campaign_id": man["campaign_id"],
        "origin": man.get("fleet_origin"),
        "headline": bool(man.get("headline")) or man["campaign_id"] in HEADLINE_IDS,
        "techniques": (man.get("source") or {}).get("techniques"),
        "truth_hosts": sorted(truth),
        "truth_campaigns": man.get("truth_campaigns"),
        "break_criterion": (man.get("break_intent") or {}).get("break_criterion"),
        "verdict": verdict,
        "verdict_reasons": reasons,
        "intensity_rounds": intensity_rounds,
        "wall_seconds": wall,
        "corr_jaccard": j,
        "confidence_margin": margin,
        "missed_hosts": still_missed,
        "recovered_on_replay": recovered,
        "over_merged_hosts": over,
        "quarantine_proposed": sorted(qprop),
        "hosts_saved": saved,
        "false_quarantine": false_q,
        "baseline": {
            "policy": baseline,
            "hosts_flagged": sorted(b1_hosts),
            "false_quarantine": b1_fq,
            "truth_coverage": b1_cov,
            "corr_truth_coverage": corr_cov,
            "baseline_wins": baseline_wins,
        },
        "multi_campaign": last.get("multi_campaign"),
        "fusion_lift": last.get("fusion_lift"),
        "rounds": rounds,
        "narrative": (man.get("narrative") or [""])[0],
    }
    return _annotate_fragile(row_out)


def markdown(report: Dict[str, Any]) -> str:
    attacks = [_annotate_fragile(dict(a)) for a in report["attacks"]]
    fragile_n = sum(1 for a in attacks if a.get("fragile") and a.get("verdict") == "HELD")
    by_priority = sorted(attacks, key=_priority_key)

    lines = [
        "# Attack fleet: Limits — breaking-point suite",
        "",
        "Purple-team **event sketches** only. Goal: find where Corvex fails. "
        "Quarantine = dry-run proposals. Live OS quarantine is not implemented.",
        "",
        SCORING_PREAMBLE,
        "",
        f"- Attacks: **{report['n']}** | Intensity rounds/attack: **{report['intensity_rounds']}**",
        f"- Baseline: **{report['baseline_policy']}**",
        f"- Wall: **{report['total_wall_seconds']}s**",
        f"- HELD: **{report['counts']['HELD']}** (of which **fragile**: {fragile_n}) | "
        f"PARTIAL: **{report['counts']['PARTIAL']}** | BROKE: **{report['counts']['BROKE']}**",
        f"- Baseline wins: **{report['baseline_wins_count']}**",
        "",
        "## Lead with #10 — false positives beat missed detections",
        "",
        "For a security tool, quarantining authorized activity *worse than doing nothing* "
        "is a harder sell than any missed-detection number. False positives are what get "
        "a tool turned off. Lead every write-up with this row — not the BROKE count.",
        "",
    ]
    lead = next((a for a in attacks if a["campaign_id"] == "lim10-authorized-redteam"), None)
    if lead:
        b = lead.get("baseline") or {}
        fq = ", ".join(lead.get("false_quarantine") or []) or "—"
        bw = b.get("baseline_wins")
        lines.extend(
            [
                f"- **{lead['campaign_id']}**: **{_verdict_label(lead)}** — "
                f"truth ∅, dry-run Q on {fq}",
                f"- Baseline wins: **{bw}** "
                + (
                    "(B1 cleaner FQ than correlator — fusion hurt)"
                    if bw
                    else "(both clean or correlator not worse than B1 on empty-truth FQ)"
                ),
                f"- Reasons: {'; '.join(lead.get('verdict_reasons') or [])}",
                "",
            ]
        )

    lines.extend(
        [
            "## Consequence-ordered findings",
            "",
            "Ordered by operational severity, not by suite index.",
            "",
        ]
    )
    notes = {
        "lim10-authorized-redteam": (
            "Narrow contain gate: inert lateral-only no longer proposes IsolateHost. "
            "Does NOT solve general FP — exfil-shaped authorized pentests still clear the gate."
        ),
        "lim09b-sequential-reuse": (
            "Structural, not an edge case. Small fixed host pools will reuse infrastructure "
            "across unrelated incidents. Fix likely needs hard split on temporal gap + "
            "technique-shape discontinuity even at 100% host overlap."
        ),
        "lim09-max-density-overlap": (
            "Hub collapse: one host, too many roles. Likely same identity/attribution gap as #11."
        ),
        "lim11-hostname-split-brain": (
            "Split-brain: one host, two labels. Pair with #9 — persistent asset ID + "
            "degree-weighted hub evidence may fix both."
        ),
        "lim02-triple-concurrent-shared": (
            "Chained shared-host over-merge across three concurrent incidents."
        ),
        "lim03-slow-low-day-gaps": (
            "Good failure: states an operational boundary (reliable inside lookback, "
            "degrades past day-scale gaps) instead of an unfalsifiable claim."
        ),
        "lim09d-benign-hub-pivot": (
            "Do not read as a clean HELD if fragile — margin < 0.2 with collateral FQ on hub peers."
        ),
        "lim01-dual-ambiguous-lateral": (
            "APT matched; helpdesk still False-Q as a separate campaign — soft near-miss (check margin)."
        ),
    }
    for a in by_priority:
        if a["verdict"] == "HELD" and not a.get("fragile") and a["campaign_id"] not in (
            "lim10-authorized-redteam",
            "lim09d-benign-hub-pivot",
            "lim01-dual-ambiguous-lateral",
        ):
            continue
        if a["verdict"] == "HELD" and not a.get("fragile") and a["campaign_id"] not in notes:
            continue
        note = notes.get(a["campaign_id"], "")
        if a["verdict"] == "HELD" and not a.get("fragile") and a["campaign_id"] not in (
            "lim09d-benign-hub-pivot",
            "lim01-dual-ambiguous-lateral",
            "lim10-authorized-redteam",
        ):
            continue
        lines.append(
            f"- **{a['campaign_id']}** — **{_verdict_label(a)}** "
            f"(J={a.get('corr_jaccard')}, margin={a.get('confidence_margin')}, "
            f"FQ={', '.join(a.get('false_quarantine') or []) or '-'}). {note}"
        )

    lines.extend(
        [
            "",
            "## Headline table (priority order)",
            "",
            "| Priority | Campaign | Verdict | Jaccard | Margin | False Q | Baseline wins |",
            "|----------|----------|---------|---------|--------|---------|---------------|",
        ]
    )
    headline = [a for a in by_priority if a.get("headline")]
    # Always include #10/#9b/#9/#9c/#9d even if somehow unmarked
    seen = {a["campaign_id"] for a in headline}
    for a in by_priority:
        if a["campaign_id"] in HEADLINE_IDS and a["campaign_id"] not in seen:
            headline.append(a)
            seen.add(a["campaign_id"])
    for i, a in enumerate(headline, 1):
        b = a.get("baseline") or {}
        lines.append(
            "| {i} | {cid} | **{v}** | {j} | {m} | {fq} | {bw} |".format(
                i=i,
                cid=a["campaign_id"],
                v=_verdict_label(a),
                j=a.get("corr_jaccard"),
                m=a.get("confidence_margin"),
                fq=", ".join(a.get("false_quarantine") or []) or "-",
                bw=b.get("baseline_wins"),
            )
        )

    lines.extend(
        [
            "",
            "## Identity / attribution cluster (#9 + #11)",
            "",
            "#9 is \"one host, too many roles\"; #11 is \"one host, two identities.\" "
            "Both point at reasoning over **host labels** rather than **host identity + role over time**. "
            "A shared fix path: persistent asset ID (not hostname) and degree-weighting so a "
            "high-connectivity node needs stronger evidence before merging campaigns through it.",
            "",
            "## Fleet scoreboard",
            "",
            "| # | Campaign | Verdict | Jaccard | Margin | Missed | Over-merged | Saved | False Q | Baseline FQ | Baseline wins |",
            "|---|----------|---------|---------|--------|--------|-------------|-------|---------|-------------|---------------|",
        ]
    )
    for i, a in enumerate(attacks, 1):
        b = a.get("baseline") or {}
        lines.append(
            "| {i} | {cid}{h} | **{v}** | {j} | {m} | {miss} | {om} | {s} | {fq} | {bfq} | {bw} |".format(
                i=i,
                cid=a["campaign_id"],
                h=" ★" if a.get("headline") else "",
                v=_verdict_label(a),
                j=a.get("corr_jaccard"),
                m=a.get("confidence_margin"),
                miss=", ".join(a.get("missed_hosts") or []) or "-",
                om=", ".join(a.get("over_merged_hosts") or []) or "-",
                s=", ".join(a.get("hosts_saved") or []) or "-",
                fq=", ".join(a.get("false_quarantine") or []) or "-",
                bfq=", ".join(b.get("false_quarantine") or []) or "-",
                bw=b.get("baseline_wins"),
            )
        )

    lines.extend(["", "## Where it broke / partial / fragile (priority order)", ""])
    notable = [
        a
        for a in by_priority
        if a["verdict"] != "HELD" or a.get("fragile")
    ]
    if not notable:
        lines.append(
            "No PARTIAL/BROKE/fragile — treat with skepticism; suite may still be too easy."
        )
    for a in notable:
        lines.append(
            f"- **{a['campaign_id']}** ({_verdict_label(a)}): "
            f"{'; '.join(a.get('verdict_reasons') or [])} — {a.get('break_criterion')}"
        )

    lines.extend(["", "## Baseline won (correlation made FP worse)", ""])
    wins = [a for a in attacks if (a.get("baseline") or {}).get("baseline_wins")]
    if not wins:
        lines.append("None — correlator never lost to single-host isolation on FQ/coverage.")
    for a in wins:
        lines.append(
            f"- **{a['campaign_id']}**: baseline fewer/equal FQ with ≥ coverage — "
            "this attack is not testing fusion value; fusion hurt."
        )

    clean = [
        a
        for a in attacks
        if a["verdict"] == "HELD" and not a.get("fragile")
    ]
    lines.extend(
        [
            "",
            f"## Clean HELD ({len(clean)}) — not fragile",
            "",
        ]
    )
    if not clean:
        lines.append("None.")
    else:
        lines.append(
            ", ".join(f"`{a['campaign_id']}`" for a in clean)
            + " — confident passes (margin ≥ 0.2, no fragile flag)."
        )

    lines.extend(["", "## Per-attack detail", ""])
    for a in attacks:
        b = a.get("baseline") or {}
        frag = " | **fragile**" if a.get("fragile") else ""
        lines.extend(
            [
                f"### {a['campaign_id']}"
                + (" ★ headline" if a.get("headline") else "")
                + frag,
                "",
                f"- Break criterion: {a.get('break_criterion')}",
                f"- Truth: {', '.join(a['truth_hosts']) or '∅'}",
                f"- Verdict: **{_verdict_label(a)}** | Jaccard={a.get('corr_jaccard')} | "
                f"margin={a.get('confidence_margin')}",
                f"- Reasons: {'; '.join(a.get('verdict_reasons') or [])}",
                f"- Quarantine dry-run: {', '.join(a.get('quarantine_proposed') or []) or '-'}",
                f"- Saved: {', '.join(a.get('hosts_saved') or []) or '-'} | "
                f"False Q: {', '.join(a.get('false_quarantine') or []) or '-'}",
                f"- Baseline FQ: {', '.join(b.get('false_quarantine') or []) or '-'} | "
                f"baseline_wins={b.get('baseline_wins')}",
                "",
            ]
        )
    lines.extend(
        [
            "## Honesty",
            "",
            "- Lead with #10 (FP / baseline-wins), then #9b (structural reuse), then identity cluster (#9/#11).",
            "- HELD ≠ clean: margin < 0.2 → **HELD, fragile**.",
            "- Event sketches only; no live exploitation. Live OS quarantine remains unimplemented.",
            "",
        ]
    )
    return "\n".join(lines)


def main() -> int:
    ap = argparse.ArgumentParser(description="Run Corvex fleet-limits breaking-point suite")
    ap.add_argument("--intensity", type=int, default=2, help="Rounds per attack")
    ap.add_argument(
        "--baseline",
        default="single-host-isolation",
        choices=["single-host-isolation"],
        help="Naive no-correlation baseline policy",
    )
    ap.add_argument(
        "--from-json",
        type=Path,
        default=None,
        help="Regenerate markdown from an existing report JSON (skip re-run)",
    )
    args = ap.parse_args()

    if args.from_json is not None:
        src = Path(args.from_json)
        report = json.loads(src.read_text(encoding="utf-8"))
        report["attacks"] = [_annotate_fragile(dict(a)) for a in report.get("attacks") or []]
        report.setdefault("scoring", {})["fragile"] = (
            f"HELD with margin < {FRAGILE_MARGIN} → HELD, fragile"
        )
        report["fragile_count"] = sum(
            1 for a in report["attacks"] if a.get("fragile") and a.get("verdict") == "HELD"
        )
        text = markdown(report)
        REPORT_JSON.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
        REPORT_MD.write_text(text, encoding="utf-8")
        try:
            print(text)
        except UnicodeEncodeError:
            sys.stdout.buffer.write(text.encode("utf-8", errors="replace"))
        print(f"\nRegenerated from {src}")
        print(f"JSON: {REPORT_JSON}")
        print(f"MD:   {REPORT_MD}")
        return 0

    intensity = max(1, int(args.intensity))

    paths = write_manifests()
    if RUN.exists():
        shutil.rmtree(RUN)
    RUN.mkdir(parents=True)

    wall0 = time.perf_counter()
    attacks = []
    for path in paths:
        print(f"=== {path.name} ===", flush=True)
        row = score_one(path, intensity_rounds=intensity, baseline=args.baseline)
        attacks.append(row)
        print(
            json.dumps(
                {
                    k: row[k]
                    for k in (
                        "campaign_id",
                        "verdict",
                        "verdict_label",
                        "fragile",
                        "corr_jaccard",
                        "confidence_margin",
                        "missed_hosts",
                        "false_quarantine",
                        "verdict_reasons",
                    )
                },
                indent=2,
            ),
            flush=True,
        )

    counts = {k: sum(1 for a in attacks if a["verdict"] == k) for k in ("HELD", "PARTIAL", "BROKE")}
    baseline_wins_count = sum(1 for a in attacks if (a.get("baseline") or {}).get("baseline_wins"))
    fragile_count = sum(1 for a in attacks if a.get("fragile") and a.get("verdict") == "HELD")
    report = {
        "test": "Attack fleet: Limits — breaking-point suite",
        "n": len(attacks),
        "intensity_rounds": intensity,
        "baseline_policy": args.baseline,
        "total_wall_seconds": round(time.perf_counter() - wall0, 4),
        "counts": counts,
        "baseline_wins_count": baseline_wins_count,
        "fragile_count": fragile_count,
        "scoring": {
            "HELD": "Jaccard≥0.9, no FN, ambiguous activity kept split",
            "PARTIAL": "Jaccard 0.5–0.89 OR recovered miss OR over-merge without FQ",
            "BROKE": "Jaccard<0.5 OR never recovered OR benign FQ via merge",
            "fragile": f"HELD with margin < {FRAGILE_MARGIN} → HELD, fragile",
            "margin": "confidence(top)−confidence(2nd-best)",
            "baseline": "B1 single-host isolation",
            "writeup_priority": WRITEUP_PRIORITY,
        },
        "attacks": attacks,
        "honesty": (
            "Lead with #10 (FP/baseline-wins), then #9b (structural), then #9/#11 (identity). "
            "Event sketches only; no live exploitation."
        ),
    }
    REPORT_JSON.parent.mkdir(parents=True, exist_ok=True)
    REPORT_JSON.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    text = markdown(report)
    REPORT_MD.write_text(text, encoding="utf-8")
    try:
        print(text)
    except UnicodeEncodeError:
        sys.stdout.buffer.write(text.encode("utf-8", errors="replace"))
    print(f"\nJSON: {REPORT_JSON}")
    print(f"MD:   {REPORT_MD}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
