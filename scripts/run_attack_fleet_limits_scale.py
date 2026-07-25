#!/usr/bin/env python3
"""T1 host-scale ladder: remap fleet-limits shapes onto N hosts (default 15).

No correlator engine change — enrollment already accepts arbitrary hosts.
Measures wall time + peak RSS vs the T0 (5–6 host) suite.

  python scripts/run_attack_fleet_limits_scale.py --hosts 15 --intensity 2
"""

from __future__ import annotations

import argparse
import json
import shutil
import sys
import time
from pathlib import Path
from typing import Any, Dict, List, Optional

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import run_attack_fleet_limits as limits  # noqa: E402

SCALE_DIR = ROOT / "labs" / "breaktest" / "manifests" / "fleet-limits-t1"
RUN = ROOT / "runs" / "attack-fleet-limits-t1"
REPORT_JSON = ROOT / "reports" / "attack_fleet_limits_t1.json"
REPORT_MD = ROOT / "reports" / "attack_fleet_limits_t1.md"

# Letter hosts used in T0 manifests → numeric slots.
LETTER_MAP = {
    "host-a": 0,
    "host-b": 1,
    "host-c": 2,
    "host-d": 3,
    "host-e": 4,
    "host-f": 5,
}


def host_id(i: int) -> str:
    return f"host-{i:02d}"


def producer_id(i: int) -> str:
    return f"prod-{i:02d}"


def scale_hosts(n: int) -> List[str]:
    if n < 6:
        raise ValueError("T1 scale needs ≥6 hosts (adapter + host-f slot)")
    return [host_id(i) for i in range(n)]


def remap_host(name: str, n: int) -> str:
    """Map T0 host labels onto host-00..; preserve -dhcp suffix for aliases."""
    raw = str(name)
    suffix = ""
    base = raw
    if raw.endswith("-dhcp"):
        base = raw[: -len("-dhcp")]
        suffix = "-dhcp"
    if base in LETTER_MAP:
        idx = LETTER_MAP[base]
        if idx >= n:
            raise ValueError(f"need ≥{idx + 1} hosts to map {base}")
        return host_id(idx) + suffix
    # Already numeric / unknown — pass through if in range
    if base.startswith("host-") and base[5:].isdigit():
        idx = int(base[5:])
        if idx >= n:
            raise ValueError(f"host index {idx} ≥ n={n}")
        return host_id(idx) + suffix
    return raw


def remap_value(val: Any, n: int) -> Any:
    if isinstance(val, str):
        if val.startswith("host-"):
            return remap_host(val, n)
        return val
    if isinstance(val, list):
        return [remap_value(x, n) for x in val]
    if isinstance(val, dict):
        return {k: remap_value(v, n) for k, v in val.items()}
    return val


def remap_manifest(man: Dict[str, Any], n: int) -> Dict[str, Any]:
    hosts = scale_hosts(n)
    producers = {h: producer_id(i) for i, h in enumerate(hosts)}
    # Aliases: host-01-dhcp → host-01
    aliases_in = man.get("host_aliases") or {}
    aliases = {}
    for k, v in aliases_in.items():
        aliases[remap_host(str(k), n)] = remap_host(str(v), n)
    # DHCP emit hosts need producers (same as canonical)
    for emit, canon in list(aliases.items()):
        if emit not in producers:
            # inherit producer from canonical
            producers[emit] = producers.get(canon, producer_id(0))
        if emit not in hosts:
            hosts = list(hosts) + [emit]

    out = dict(man)
    out["campaign_id"] = f"t1-{man['campaign_id']}"
    out["hosts"] = [h for h in hosts if not h.endswith("-dhcp")]
    out["producers"] = {h: producers[h] for h in out["hosts"]}
    for emit, canon in aliases.items():
        out["producers"][emit] = producers.get(canon, producers.get(emit, producer_id(0)))
    out["truth_hosts"] = remap_value(man.get("truth_hosts") or [], n)
    if man.get("truth_campaigns"):
        out["truth_campaigns"] = remap_value(man["truth_campaigns"], n)
    if man.get("drop_hosts"):
        out["drop_hosts"] = remap_value(man["drop_hosts"], n)
    if man.get("host_clock_skew_seconds"):
        out["host_clock_skew_seconds"] = {
            remap_host(k, n): v for k, v in man["host_clock_skew_seconds"].items()
        }
    if aliases:
        out["host_aliases"] = aliases
    out["steps"] = remap_value(man.get("steps") or [], n)
    out["fleet_suite"] = "limits-t1"
    out["scale"] = {"tier": "T1", "n_hosts": n, "source_campaign_id": man["campaign_id"]}
    # Density decoys: benign lateral on unused high hosts (does not touch truth)
    decoy_user = f"decoy-{man['campaign_id'][-6:]}"
    unused = [h for h in out["hosts"] if h not in set(out["truth_hosts"] or [])]
    # Leave most unused quiet; add one decoy pair if ≥2 unused beyond first 6 slots
    quiet = [h for h in unused if int(h.split("-")[1]) >= 6]
    if len(quiet) >= 2 and man.get("truth_hosts") is not None:
        out["steps"] = list(out["steps"]) + [
            {
                "kind": "auth",
                "host": quiet[0],
                "user": decoy_user,
                "src": "10.99.0.1",
                "offset_seconds": 120,
                "technique": "T1078",
            },
            {
                "kind": "auth",
                "host": quiet[1],
                "user": decoy_user,
                "src": quiet[0],
                "offset_seconds": 130,
                "technique": "T1078",
            },
        ]
    return out


def peak_rss_mb() -> Optional[float]:
    try:
        import resource  # Unix

        usage = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
        # Linux: KB; macOS: bytes
        if sys.platform == "darwin":
            return round(usage / (1024.0 * 1024.0), 2)
        return round(usage / 1024.0, 2)
    except ImportError:
        pass
    try:
        import psutil  # type: ignore

        return round(psutil.Process().memory_info().rss / (1024.0 * 1024.0), 2)
    except Exception:
        return None


def write_scaled_manifests(n: int) -> List[Path]:
    if SCALE_DIR.exists():
        shutil.rmtree(SCALE_DIR)
    SCALE_DIR.mkdir(parents=True)
    # Generate T0 manifests in memory (don't clobber fleet-limits dir permanently)
    base = limits.fleet_manifests()
    paths = []
    for man in base:
        scaled = remap_manifest(man, n)
        path = SCALE_DIR / f"{scaled['campaign_id']}.json"
        path.write_text(json.dumps(scaled, indent=2) + "\n", encoding="utf-8")
        paths.append(path)
    return paths


def markdown_t1(report: Dict[str, Any]) -> str:
    body = limits.markdown(report)
    # Retitle + add scale banner
    lines = body.splitlines()
    if lines and lines[0].startswith("#"):
        lines[0] = f"# Attack fleet: Limits T1 — {report.get('n_hosts', 15)}-host scale"
    banner = [
        "",
        f"**Scale tier:** T1 | **Hosts:** {report.get('n_hosts')} | "
        f"**Wall:** {report.get('total_wall_seconds')}s | "
        f"**Peak RSS:** {report.get('peak_rss_mb')} MB",
        f"**Gate to T2:** wall < 120s and RSS < 500MB → "
        f"{'PASS' if report.get('t2_gate_pass') else 'FAIL / not yet'}",
        "",
    ]
    # Insert after first blank following title
    out = [lines[0]] + banner + lines[1:]
    return "\n".join(out)


def main() -> int:
    ap = argparse.ArgumentParser(description="Run fleet-limits remapped to N hosts (T1)")
    ap.add_argument("--hosts", type=int, default=15, help="Host count (T1 default 15)")
    ap.add_argument("--intensity", type=int, default=2)
    ap.add_argument(
        "--baseline",
        default="single-host-isolation",
        choices=["single-host-isolation"],
    )
    args = ap.parse_args()
    n = max(6, int(args.hosts))
    intensity = max(1, int(args.intensity))

    # Point limits scorer at T1 paths
    limits.FLEET_DIR = SCALE_DIR
    limits.RUN = RUN
    limits.REPORT_JSON = REPORT_JSON
    limits.REPORT_MD = REPORT_MD
    # Innocents = all scaled hosts; score_one reads hosts from each manifest
    limits.HOSTS5 = scale_hosts(n)  # fallback only

    paths = write_scaled_manifests(n)
    if RUN.exists():
        shutil.rmtree(RUN)
    RUN.mkdir(parents=True)

    wall0 = time.perf_counter()
    attacks = []
    for path in paths:
        print(f"=== {path.name} ===", flush=True)
        row = limits.score_one(path, intensity_rounds=intensity, baseline=args.baseline)
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
                        "false_quarantine",
                    )
                    if k in row
                },
                indent=2,
            ),
            flush=True,
        )

    wall = round(time.perf_counter() - wall0, 4)
    rss = peak_rss_mb()
    counts = {k: sum(1 for a in attacks if a["verdict"] == k) for k in ("HELD", "PARTIAL", "BROKE")}
    fragile_count = sum(1 for a in attacks if a.get("fragile") and a.get("verdict") == "HELD")
    baseline_wins_count = sum(
        1 for a in attacks if (a.get("baseline") or {}).get("baseline_wins")
    )
    t2_gate = wall < 120.0 and (rss is None or rss < 500.0)

    report = {
        "test": f"Attack fleet: Limits T1 — {n}-host scale",
        "n": len(attacks),
        "n_hosts": n,
        "tier": "T1",
        "intensity_rounds": intensity,
        "baseline_policy": args.baseline,
        "total_wall_seconds": wall,
        "peak_rss_mb": rss,
        "t2_gate_pass": t2_gate,
        "counts": counts,
        "baseline_wins_count": baseline_wins_count,
        "fragile_count": fragile_count,
        "scoring": {
            **(limits.SCORING_PREAMBLE and {}),
            "fragile": f"HELD with margin < {limits.FRAGILE_MARGIN} → HELD, fragile",
            "writeup_priority": limits.WRITEUP_PRIORITY,
        },
        "attacks": attacks,
        "honesty": (
            f"T0 fleet-limits shapes remapped to {n} hosts with quiet decoy laterals "
            "on unused high slots. Event sketches only."
        ),
    }
    REPORT_JSON.parent.mkdir(parents=True, exist_ok=True)
    REPORT_JSON.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    text = markdown_t1(report)
    REPORT_MD.write_text(text, encoding="utf-8")
    try:
        print(text)
    except UnicodeEncodeError:
        sys.stdout.buffer.write(text.encode("utf-8", errors="replace"))
    print(f"\nJSON: {REPORT_JSON}")
    print(f"MD:   {REPORT_MD}")
    print(f"T2 gate (wall<120s, RSS<500MB): {'PASS' if t2_gate else 'FAIL'} "
          f"(wall={wall}s rss={rss})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
