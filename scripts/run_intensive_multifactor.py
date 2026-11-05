#!/usr/bin/env python3
"""Intensive multi-factor Corvex stress — domain × container × sequence × style.

Purple-team event sketches only. Goal: map capability and exact break surfaces
across identity domains, container-shaped host IDs, attack timing/sequences,
and ATT&CK-shaped styles. Authorship is in-repo (not independent red team).

  python scripts/run_intensive_multifactor.py
  python scripts/run_intensive_multifactor.py --intensity 2 --quick
"""

from __future__ import annotations

import argparse
import json
import shutil
import subprocess
import sys
import time
from pathlib import Path
from typing import Any, Dict, List, Mapping, Optional, Sequence, Set, Tuple

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import run_attack_fleet_limits as limits  # noqa: E402

MAN_DIR = ROOT / "labs" / "breaktest" / "manifests" / "fleet-intensive"
RUN = ROOT / "runs" / "attack-fleet-intensive"
REPORT_JSON = ROOT / "reports" / "intensive_capability_matrix.json"
REPORT_MD = ROOT / "reports" / "intensive_capability_matrix.md"

FRAGILE_MARGIN = 0.2
DAY = 86400.0

# Override limits.RUN so score_one writes under intensive run dir.
limits.RUN = RUN


def _prod(hosts: Sequence[str]) -> Dict[str, str]:
    """Stable 1:1 producer per host_id — must not reuse numeric slots across cells.

    Lab enrollment is persistent; index-based prod-00..N collides when cell A
    maps host X→prod-02 and cell B maps host Y→prod-02 (AuthError multihost).
    """
    out: Dict[str, str] = {}
    for h in hosts:
        safe = "".join(ch if ch.isalnum() else "-" for ch in h).strip("-").lower()
        out[h] = f"prod-mf-{safe}"
    return out


def _hosts_for(domain: str, container: str) -> Tuple[List[str], Dict[str, str], List[str]]:
    """Return (hosts, host_aliases, core_truth_slots).

    core_truth_slots are indices into hosts for the primary attack chain (0,1,2).
    """
    aliases: Dict[str, str] = {}
    if domain == "single":
        bare = ["corp-ws01", "corp-ws02", "corp-ws03", "corp-ws04", "corp-ws05"]
    elif domain == "cross":
        bare = ["corp-ws01", "corp-ws02", "dmz-gw01", "dmz-app01", "corp-ws03"]
    elif domain == "forest":
        bare = [
            "corp-dc01",
            "partner-ws01",
            "finance-ws01",
            "corp-ws02",
            "partner-ws02",
            "finance-ws02",
        ]
    else:
        raise ValueError(domain)

    if container == "bare":
        hosts = list(bare)
    elif container == "docker":
        # Container IDs as first-class host_ids (no alias collapse).
        hosts = [
            f"ctr-{bare[0].split('-', 1)[-1]}-web",
            f"ctr-{bare[1].split('-', 1)[-1]}-api",
            f"ctr-{bare[2].split('-', 1)[-1]}-db",
            f"ctr-{bare[3].split('-', 1)[-1]}-cache",
            f"node-{bare[4].split('-', 1)[-1]}",
        ]
        if domain == "forest":
            hosts.append(f"ctr-{bare[5].split('-', 1)[-1]}-batch")
    elif container == "mixed":
        # Containers emit under ctr-* but alias to bare node identity.
        hosts = list(bare)
        aliases = {
            f"ctr-{bare[1]}": bare[1],
            f"ctr-{bare[2]}": bare[2],
        }
    else:
        raise ValueError(container)

    return hosts, aliases, [0, 1, 2]


def _style_steps(
    style: str,
    hosts: Sequence[str],
    sequence: str,
    *,
    truth_idx: Sequence[int],
) -> Tuple[List[Dict[str, Any]], List[str], List[str], Optional[List[Dict[str, Any]]]]:
    """Build steps + techniques + truth hosts + optional truth_campaigns."""
    t = [hosts[i] for i in truth_idx]
    h0, h1, h2 = t[0], t[1], t[2]
    innocents = [h for h in hosts if h not in t]
    tech: List[str]
    steps: List[Dict[str, Any]]
    truth_camps: Optional[List[Dict[str, Any]]] = None

    # Timing profiles
    if sequence == "burst":
        gaps = [0, 12, 24, 36, 48, 60]
    elif sequence == "slow":
        # Bridge host across gaps (lim03-shaped): day0 h0→h1, day14 h1→h2,
        # else the sleeper axis confounds with missing topology continuity.
        gaps = [0, 30, 60, 14 * DAY, 14 * DAY + 120, 14 * DAY + 240]
    elif sequence == "ooo":
        # Exfil timestamps before lateral (causal inversion).
        gaps = [80, 20, 40, 5, 100, 110]
    elif sequence == "concurrent":
        gaps = [0, 10, 20, 15, 25, 40]
    else:
        raise ValueError(sequence)

    if style == "pth_lateral":
        tech = ["T1003.001", "T1550.002", "T1041"]
        if sequence == "slow":
            # day0: h0→h1 + exfil h1; day14: resume h1→h2 + exfil h2
            steps = [
                {"kind": "auth", "host": h0, "user": "sleeper", "src": "203.0.113.10", "offset_seconds": gaps[0], "technique": "T1003.001"},
                {"kind": "auth", "host": h1, "user": "sleeper", "src": h0, "offset_seconds": gaps[1], "technique": "T1550.002"},
                {"kind": "exfil", "host": h1, "dst_ip": "198.51.100.20", "bytes": 18000, "offset_seconds": gaps[2], "technique": "T1041"},
                {"kind": "auth", "host": h1, "user": "sleeper", "src": "10.1.0.50", "offset_seconds": gaps[3], "technique": "T1550.002"},
                {"kind": "auth", "host": h2, "user": "sleeper", "src": h1, "offset_seconds": gaps[4], "technique": "T1550.002"},
                {"kind": "exfil", "host": h2, "dst_ip": "198.51.100.21", "bytes": 22000, "offset_seconds": gaps[5], "technique": "T1041"},
            ]
        else:
            steps = [
                {"kind": "auth", "host": h0, "user": "Administrator", "src": "203.0.113.10", "offset_seconds": gaps[0], "technique": "T1003.001"},
                {"kind": "auth", "host": h1, "user": "Administrator", "src": h0, "offset_seconds": gaps[1], "technique": "T1550.002"},
                {"kind": "auth", "host": h2, "user": "Administrator", "src": h1, "offset_seconds": gaps[2], "technique": "T1550.002"},
                {"kind": "exfil", "host": h2, "dst_ip": "198.51.100.20", "bytes": 22000, "offset_seconds": gaps[3], "technique": "T1041"},
                {"kind": "exfil", "host": h1, "dst_ip": "198.51.100.20", "bytes": 18000, "offset_seconds": gaps[4], "technique": "T1041"},
            ]
    elif style == "dns_c2":
        tech = ["T1071.004"]
        steps = []
        dns_hosts = [h0, h0, h1, h1, h2, h2]
        for i, h in enumerate(dns_hosts):
            off = gaps[min(i, len(gaps) - 1)] if sequence != "burst" else i * 5.0
            steps.append(
                {
                    "kind": "dns",
                    "host": h,
                    "query": f"{i}.c2.evil.test",
                    "offset_seconds": off,
                    "technique": "T1071.004",
                }
            )
    elif style == "spray":
        tech = ["T1110.003", "T1078", "T1041"]
        steps = [
            {"kind": "auth", "host": h0, "user": "spray-hit", "src": "203.0.113.99", "offset_seconds": gaps[0], "technique": "T1110.003"},
            {"kind": "auth", "host": h1, "user": "spray-hit", "src": h0, "offset_seconds": gaps[1], "technique": "T1078"},
            {"kind": "auth", "host": h2, "user": "spray-hit", "src": h1, "offset_seconds": gaps[2], "technique": "T1078"},
            {"kind": "exfil", "host": h2, "dst_ip": "198.51.100.60", "bytes": 16000, "offset_seconds": gaps[3], "technique": "T1041"},
        ]
    elif style == "exfil_bury":
        tech = ["T1041", "T1078"]
        steps = [
            {"kind": "auth", "host": h0, "user": "apt-op", "src": "203.0.113.40", "offset_seconds": gaps[0], "technique": "T1078"},
            {"kind": "auth", "host": h1, "user": "apt-op", "src": h0, "offset_seconds": gaps[1], "technique": "T1078"},
            {"kind": "exfil", "host": h1, "dst_ip": "198.51.100.77", "bytes": 14000, "offset_seconds": gaps[2], "technique": "T1041"},
        ]
        # Benign CDN bury to shared dst
        bury_t0 = gaps[2] - 30 if gaps[2] > 30 else 0
        for i, h in enumerate(hosts):
            for j in range(8):
                steps.append(
                    {
                        "kind": "exfil",
                        "host": h,
                        "dst_ip": "203.0.113.200",
                        "bytes": 9000 + j * 100,
                        "offset_seconds": bury_t0 + i * 3 + j * 0.5,
                        "technique": "T1041",
                    }
                )
    elif style == "helpdesk_overlap":
        tech = ["T1021.001", "T1078", "T1041"]
        help_user = "helpdesk"
        steps = [
            {"kind": "auth", "host": h0, "user": "apt-rdp", "src": "203.0.113.21", "offset_seconds": gaps[0], "technique": "T1021.001"},
            {"kind": "auth", "host": h1, "user": "apt-rdp", "src": h0, "offset_seconds": gaps[1], "technique": "T1021.001"},
            {"kind": "auth", "host": h2, "user": "apt-rdp", "src": h1, "offset_seconds": gaps[2], "technique": "T1021.001"},
            {"kind": "exfil", "host": h2, "dst_ip": "198.51.100.190", "bytes": 16000, "offset_seconds": gaps[3], "technique": "T1041"},
            {"kind": "auth", "host": h2, "user": help_user, "src": "10.30.0.9", "offset_seconds": gaps[1] + 5, "technique": "T1021.001"},
        ]
        if innocents:
            steps.append(
                {
                    "kind": "auth",
                    "host": innocents[0],
                    "user": help_user,
                    "src": h2,
                    "offset_seconds": gaps[2] + 10,
                    "technique": "T1021.001",
                }
            )
            if len(innocents) > 1:
                steps.append(
                    {
                        "kind": "auth",
                        "host": innocents[1],
                        "user": help_user,
                        "src": innocents[0],
                        "offset_seconds": gaps[3] + 10,
                        "technique": "T1021.001",
                    }
                )
    else:
        raise ValueError(style)

    # Concurrent: second disjoint-ish campaign sharing middle host when possible
    if sequence == "concurrent" and style != "dns_c2":
        other_user = "camp2-op"
        h_share = h1
        h_extra = innocents[0] if innocents else h2
        steps.extend(
            [
                {
                    "kind": "auth",
                    "host": h_share,
                    "user": other_user,
                    "src": "203.0.113.88",
                    "offset_seconds": gaps[0] + 8,
                    "technique": "T1078",
                },
                {
                    "kind": "auth",
                    "host": h_extra,
                    "user": other_user,
                    "src": h_share,
                    "offset_seconds": gaps[1] + 8,
                    "technique": "T1078",
                },
                {
                    "kind": "exfil",
                    "host": h_extra,
                    "dst_ip": "198.51.100.88",
                    "bytes": 12000,
                    "offset_seconds": gaps[3] + 8,
                    "technique": "T1041",
                },
            ]
        )
        truth_camps = [
            {"id": "camp-primary", "hosts": list(t)},
            {"id": "camp-secondary", "hosts": [h_share, h_extra]},
        ]

    return steps, tech, list(t), truth_camps


def _apply_mixed_emit(
    steps: List[Dict[str, Any]],
    aliases: Mapping[str, str],
) -> List[Dict[str, Any]]:
    """For mixed factor: rewrite some mid-chain hosts to emit under alias keys."""
    if not aliases:
        return steps
    # Map canonical -> alias emit label
    inv = {v: k for k, v in aliases.items()}
    out: List[Dict[str, Any]] = []
    for i, step in enumerate(steps):
        s = dict(step)
        host = str(s.get("host") or "")
        if host in inv and i % 2 == 1 and s.get("kind") in ("auth", "exfil", "dns"):
            s["emit_host"] = inv[host]
            # keep logical host for truth / producer lookup
        out.append(s)
    return out


def cell_manifest(
    *,
    domain: str,
    container: str,
    sequence: str,
    style: str,
) -> Dict[str, Any]:
    hosts, aliases, truth_idx = _hosts_for(domain, container)
    steps, tech, truth, truth_camps = _style_steps(
        style, hosts, sequence, truth_idx=truth_idx
    )
    if container == "mixed":
        steps = _apply_mixed_emit(steps, aliases)
        # Enroll alias keys are skipped in build-breaktest; ensure bare hosts listed.
        for alias_host in aliases:
            if alias_host not in hosts:
                # alias emit ids are not enrolled as separate hosts
                pass

    cid = f"mf-{domain}-{container}-{sequence}-{style}"
    man: Dict[str, Any] = {
        "campaign_id": cid,
        "family": "intensive_multifactor",
        "ood": True,
        "hosts": hosts,
        "truth_hosts": truth if not truth_camps else sorted(
            {h for c in truth_camps for h in c["hosts"]}
        ),
        "producers": _prod(hosts),
        "base_time_utc": "2026-07-25T14:00:00Z",
        "fleet_origin": "original",
        "fleet_suite": "intensive",
        "factors": {
            "domain": domain,
            "container": container,
            "sequence": sequence,
            "style": style,
        },
        "source": {
            "style": "Intensive multi-factor stress sketches",
            "repo": "https://github.com/Siddarthb07/corvex",
            "techniques": tech,
            "note": f"{domain}/{container}/{sequence}/{style}",
        },
        "narrative": [
            f"Factor cell: domain={domain} container={container} sequence={sequence} style={style}."
        ],
        "break_intent": {
            "name": cid,
            "break_criterion": "Jaccard < 0.5 OR truth host never recovered OR benign merge-FQ",
            "success_criteria_defender": ["matched truth_hosts", "empty over_merged_hosts"],
        },
        "steps": steps,
    }
    if aliases:
        man["host_aliases"] = aliases
    if truth_camps:
        man["truth_campaigns"] = truth_camps
    return man


def factor_grid(*, quick: bool) -> List[Dict[str, Any]]:
    """Representative cells — not full Cartesian (would be 180+)."""
    domains = ["single", "cross", "forest"]
    containers = ["bare", "docker", "mixed"]
    sequences = ["burst", "slow", "ooo", "concurrent"]
    styles = ["pth_lateral", "dns_c2", "spray", "exfil_bury", "helpdesk_overlap"]

    cells: List[Tuple[str, str, str, str]] = []

    # Axis sweeps: hold others at baseline (single/bare/burst/pth)
    for d in domains:
        cells.append((d, "bare", "burst", "pth_lateral"))
    for c in containers:
        cells.append(("single", c, "burst", "pth_lateral"))
    for seq in sequences:
        cells.append(("single", "bare", seq, "pth_lateral"))
    for st in styles:
        cells.append(("single", "bare", "burst", st))

    # High-stress corners (where reviews said capability is unknown)
    corners = [
        ("cross", "docker", "concurrent", "helpdesk_overlap"),
        ("cross", "mixed", "ooo", "pth_lateral"),
        ("forest", "bare", "slow", "pth_lateral"),
        ("forest", "docker", "burst", "dns_c2"),
        ("forest", "mixed", "concurrent", "exfil_bury"),
        ("cross", "bare", "slow", "dns_c2"),
        ("single", "docker", "ooo", "exfil_bury"),
        ("cross", "docker", "burst", "spray"),
        ("forest", "bare", "concurrent", "helpdesk_overlap"),
        ("single", "mixed", "slow", "spray"),
        ("cross", "mixed", "burst", "dns_c2"),
        ("forest", "docker", "ooo", "helpdesk_overlap"),
        # Intentional kill: day-gap with NO bridging host (topology confound)
        ("single", "bare", "slow", "exfil_bury"),
        ("cross", "docker", "slow", "helpdesk_overlap"),
        ("forest", "mixed", "ooo", "spray"),
        ("single", "docker", "concurrent", "dns_c2"),
    ]
    cells.extend(corners)

    # Dedup preserve order
    seen: Set[str] = set()
    out: List[Dict[str, Any]] = []
    for d, c, seq, st in cells:
        key = f"{d}|{c}|{seq}|{st}"
        if key in seen:
            continue
        seen.add(key)
        out.append(cell_manifest(domain=d, container=c, sequence=seq, style=st))
        if quick and len(out) >= 12:
            break
    return out


def write_manifests(mans: Sequence[Dict[str, Any]]) -> List[Path]:
    if MAN_DIR.exists():
        shutil.rmtree(MAN_DIR)
    MAN_DIR.mkdir(parents=True)
    paths: List[Path] = []
    for man in mans:
        path = MAN_DIR / f"{man['campaign_id']}.json"
        path.write_text(json.dumps(man, indent=2) + "\n", encoding="utf-8")
        paths.append(path)
    return paths


def _matrix_pivot(attacks: Sequence[Mapping[str, Any]]) -> Dict[str, Any]:
    by_factor: Dict[str, Dict[str, Dict[str, int]]] = {
        "domain": {},
        "container": {},
        "sequence": {},
        "style": {},
    }
    for a in attacks:
        factors = a.get("factors") or {}
        label = str(a.get("verdict_label") or a.get("verdict") or "?")
        bucket = "fragile" if "fragile" in label else label
        for axis in by_factor:
            val = str(factors.get(axis) or "?")
            by_factor[axis].setdefault(val, {"HELD": 0, "fragile": 0, "PARTIAL": 0, "BROKE": 0, "ERROR": 0})
            key = bucket if bucket in by_factor[axis][val] else "ERROR"
            if label.startswith("HELD") and "fragile" not in label:
                key = "HELD"
            elif "fragile" in label:
                key = "fragile"
            elif label == "PARTIAL":
                key = "PARTIAL"
            elif label == "BROKE":
                key = "BROKE"
            else:
                key = "ERROR"
            by_factor[axis][val][key] = by_factor[axis][val].get(key, 0) + 1
    return by_factor


def write_report(report: Dict[str, Any]) -> None:
    attacks = report.get("attacks") or []
    lines: List[str] = [
        "# Intensive multi-factor capability matrix",
        "",
        "Synthetic ATT&CK-shaped sketches across **domain × container × sequence × style**.",
        "Not enterprise telemetry. `claim_allowed` stays false.",
        "",
        "## Scoring",
        "",
        "Same HELD / HELD,fragile / PARTIAL / BROKE bar as fleet-limits "
        "(Jaccard ≥ 0.9, no merge-FQ, ambiguity margin < 0.2 ⇒ fragile).",
        "",
        f"- Cells: **{report.get('n')}** | Intensity: **{report.get('intensity_rounds')}** | Wall: **{report.get('wall_seconds')}s**",
        f"- HELD: **{report.get('held')}** (fragile: **{report.get('fragile')}**) | PARTIAL: **{report.get('partial')}** | BROKE: **{report.get('broke')}** | ERROR: **{report.get('error')}**",
        "",
        "## Where it breaks (BROKE / PARTIAL first)",
        "",
    ]
    hard = [a for a in attacks if a.get("verdict") in ("BROKE", "PARTIAL") or a.get("fragile")]
    hard.sort(key=lambda a: (0 if a.get("verdict") == "BROKE" else 1 if a.get("verdict") == "PARTIAL" else 2, a.get("campaign_id")))
    if not hard:
        lines.append("_No BROKE/PARTIAL/fragile cells in this run._")
    else:
        lines.append("| Campaign | Verdict | J | Margin | Missed | Over-merge | Factors |")
        lines.append("|----------|---------|---|--------|--------|------------|---------|")
        for a in hard:
            f = a.get("factors") or {}
            fac = f"{f.get('domain')}/{f.get('container')}/{f.get('sequence')}/{f.get('style')}"
            lines.append(
                f"| `{a.get('campaign_id')}` | **{a.get('verdict_label')}** | {a.get('corr_jaccard')} | "
                f"{a.get('confidence_margin')} | {', '.join(a.get('missed_hosts') or []) or '-'} | "
                f"{', '.join(a.get('over_merged_hosts') or []) or '-'} | `{fac}` |"
            )
    lines.extend(["", "## Factor pivots", ""])
    pivots = report.get("factor_pivots") or {}
    for axis, levels in pivots.items():
        lines.append(f"### {axis}")
        lines.append("")
        lines.append("| Level | HELD | fragile | PARTIAL | BROKE | ERROR |")
        lines.append("|-------|------|---------|---------|-------|-------|")
        for level, counts in sorted(levels.items()):
            lines.append(
                f"| `{level}` | {counts.get('HELD', 0)} | {counts.get('fragile', 0)} | "
                f"{counts.get('PARTIAL', 0)} | {counts.get('BROKE', 0)} | {counts.get('ERROR', 0)} |"
            )
        lines.append("")

    lines.extend(
        [
            "## Full scoreboard",
            "",
            "| # | Campaign | Verdict | J | Margin | Domain | Container | Sequence | Style |",
            "|---|----------|---------|---|--------|--------|-----------|----------|-------|",
        ]
    )
    for i, a in enumerate(attacks, 1):
        f = a.get("factors") or {}
        lines.append(
            f"| {i} | `{a.get('campaign_id')}` | **{a.get('verdict_label')}** | {a.get('corr_jaccard')} | "
            f"{a.get('confidence_margin')} | {f.get('domain')} | {f.get('container')} | "
            f"{f.get('sequence')} | {f.get('style')} |"
        )
    lines.extend(
        [
            "",
            "## Honesty",
            "",
            "- Author-built factor cells; not an independent red team.",
            "- Domain/container labels are host_id namespaces — not live AD/K8s.",
            "- DNS-only cells probe correlator fusion of `dns` payloads; OS DNS channel may still be GAP.",
            "",
        ]
    )
    REPORT_MD.write_text("\n".join(lines) + "\n", encoding="utf-8")


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--intensity", type=int, default=2)
    ap.add_argument("--quick", action="store_true", help="12-cell smoke subset")
    ap.add_argument("--baseline", default="single-host-isolation")
    args = ap.parse_args()
    intensity = max(1, int(args.intensity))

    mans = factor_grid(quick=bool(args.quick))
    paths = write_manifests(mans)
    if RUN.exists():
        shutil.rmtree(RUN)
    RUN.mkdir(parents=True)

    attacks: List[Dict[str, Any]] = []
    t0 = time.perf_counter()
    for path in paths:
        print(f"=== {path.stem} ===", flush=True)
        try:
            row = limits.score_one(
                path, intensity_rounds=intensity, baseline=args.baseline
            )
            man = json.loads(path.read_text(encoding="utf-8"))
            row["factors"] = man.get("factors")
            row = limits._annotate_fragile(row)
            attacks.append(row)
            print(
                f"  -> {row.get('verdict_label')} J={row.get('corr_jaccard')} "
                f"margin={row.get('confidence_margin')}",
                flush=True,
            )
        except Exception as exc:  # noqa: BLE001 — surface per-cell failure
            attacks.append(
                {
                    "campaign_id": path.stem,
                    "verdict": "ERROR",
                    "verdict_label": "ERROR",
                    "error": str(exc),
                    "factors": json.loads(path.read_text(encoding="utf-8")).get("factors"),
                    "fragile": False,
                    "corr_jaccard": 0.0,
                    "confidence_margin": None,
                    "missed_hosts": [],
                    "over_merged_hosts": [],
                }
            )
            print(f"  -> ERROR: {exc}", flush=True)

    wall = round(time.perf_counter() - t0, 4)
    held = sum(1 for a in attacks if a.get("verdict") == "HELD")
    fragile = sum(1 for a in attacks if a.get("fragile"))
    partial = sum(1 for a in attacks if a.get("verdict") == "PARTIAL")
    broke = sum(1 for a in attacks if a.get("verdict") == "BROKE")
    error = sum(1 for a in attacks if a.get("verdict") == "ERROR")

    report = {
        "test": "Intensive multi-factor capability matrix",
        "honesty": (
            "Synthetic factor cells (domain/container/sequence/style). "
            "Not enterprise telemetry. claim_allowed remains false."
        ),
        "n": len(attacks),
        "intensity_rounds": intensity,
        "wall_seconds": wall,
        "held": held,
        "fragile": fragile,
        "partial": partial,
        "broke": broke,
        "error": error,
        "factor_pivots": _matrix_pivot(attacks),
        "attacks": attacks,
        "manifest_dir": str(MAN_DIR),
    }
    REPORT_JSON.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    write_report(report)
    print(json.dumps({k: report[k] for k in ("n", "held", "fragile", "partial", "broke", "error", "wall_seconds")}, indent=2))
    print(f"wrote {REPORT_JSON}\nwrote {REPORT_MD}", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
