#!/usr/bin/env python3
"""T1 host-scale ladder: remap fleet-limits shapes onto N hosts (default 15).

No correlator engine change — enrollment already accepts arbitrary hosts.
Measures wall time + peak RSS vs the T0 (5–6 host) suite.

  python scripts/run_attack_fleet_limits_scale.py --hosts 15 --intensity 2
  python scripts/run_attack_fleet_limits_scale.py --hosts 15 --intensity 2 --no-decoy
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
SCALE_DIR_NODECOY = ROOT / "labs" / "breaktest" / "manifests" / "fleet-limits-t1-nodecoy"
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


def tier_for_hosts(n: int) -> str:
    if n <= 6:
        return "T0"
    if n <= 15:
        return "T1"
    if n <= 50:
        return "T2"
    return "T3"


def remap_manifest(man: Dict[str, Any], n: int, *, tier: Optional[str] = None) -> Dict[str, Any]:
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

    tier_name = tier or tier_for_hosts(n)
    prefix = tier_name.lower()  # t1 / t2 / t3
    out = dict(man)
    out["campaign_id"] = f"{prefix}-{man['campaign_id']}"
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
    out["fleet_suite"] = f"limits-{prefix}"
    out["scale"] = {
        "tier": tier_name,
        "n_hosts": n,
        "source_campaign_id": man["campaign_id"],
        "decoys": False,
    }
    return out


def inject_decoy_laterals(man: Dict[str, Any]) -> Dict[str, Any]:
    """Benign lateral on unused high hosts (does not touch truth). Optional control knob."""
    out = dict(man)
    decoy_user = f"decoy-{man['campaign_id'][-6:]}"
    unused = [h for h in out["hosts"] if h not in set(out.get("truth_hosts") or [])]
    quiet = [
        h
        for h in unused
        if "-" in h and h.split("-")[1].isdigit() and int(h.split("-")[1]) >= 6
    ]
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
        scale = dict(out.get("scale") or {})
        scale["decoys"] = True
        out["scale"] = scale
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


def write_scaled_manifests(
    n: int,
    *,
    decoys: bool = True,
    dest: Optional[Path] = None,
    tier: Optional[str] = None,
) -> List[Path]:
    out_dir = dest or SCALE_DIR
    if out_dir.exists():
        shutil.rmtree(out_dir)
    out_dir.mkdir(parents=True)
    # Generate T0 manifests in memory (don't clobber fleet-limits dir permanently)
    base = limits.fleet_manifests()
    tier_name = tier or tier_for_hosts(n)
    paths = []
    for man in base:
        scaled = remap_manifest(man, n, tier=tier_name)
        if decoys:
            scaled = inject_decoy_laterals(scaled)
        path = out_dir / f"{scaled['campaign_id']}.json"
        path.write_text(json.dumps(scaled, indent=2) + "\n", encoding="utf-8")
        paths.append(path)
    return paths


def markdown_scale(report: Dict[str, Any]) -> str:
    body = limits.markdown(report)
    tier = report.get("tier", "T1")
    lines = body.splitlines()
    if lines and lines[0].startswith("#"):
        lines[0] = (
            f"# Attack fleet: Limits {tier} — {report.get('n_hosts', '?')}-host scale"
        )
    fragile_rate = report.get("fragile_rate_held")
    frag_note = (
        f"fragile_rate={fragile_rate}"
        if fragile_rate is not None
        else f"fragile={report.get('fragile_count')}"
    )
    gate_bits = []
    if report.get("t2_gate_pass") is not None and tier in ("T1", "T2"):
        gate_bits.append(
            f"wall/RSS → {'PASS' if report.get('t2_gate_pass') else 'FAIL'}"
        )
    if report.get("fragile_gate_pass") is not None:
        gate_bits.append(
            f"fragile-rate → {'PASS' if report.get('fragile_gate_pass') else 'FAIL'}"
        )
    gate_line = (
        f"**Gates:** {'; '.join(gate_bits)}" if gate_bits else ""
    )
    banner = [
        "",
        f"**Scale tier:** {tier} | **Hosts:** {report.get('n_hosts')} | "
        f"**Decoys:** {report.get('decoys')} | "
        f"**Wall:** {report.get('total_wall_seconds')}s | "
        f"**Peak RSS:** {report.get('peak_rss_mb')} MB | **{frag_note}**",
    ]
    if gate_line:
        banner.append(gate_line)
    banner.append("")
    out = [lines[0]] + banner + lines[1:]
    return "\n".join(out)


def main() -> int:
    ap = argparse.ArgumentParser(
        description="Run fleet-limits remapped to N hosts (T1=15, T2=50, …)"
    )
    ap.add_argument("--hosts", type=int, default=15, help="Host count (T1=15, T2=50)")
    ap.add_argument("--intensity", type=int, default=2)
    ap.add_argument(
        "--no-decoy",
        action="store_true",
        help="Control: quiet hosts stay quiet (no decoy laterals). Writes *_nodecoy reports.",
    )
    ap.add_argument(
        "--t0-fragile-rate",
        type=float,
        default=None,
        help="Reference T0 fragile_rate_held for quality gate (default: read reports/attack_fleet_limits.json)",
    )
    ap.add_argument(
        "--baseline",
        default="single-host-isolation",
        choices=["single-host-isolation"],
    )
    args = ap.parse_args()
    n = max(6, int(args.hosts))
    intensity = max(1, int(args.intensity))
    decoys = not bool(args.no_decoy)
    tier = tier_for_hosts(n)
    prefix = tier.lower()

    report_json = ROOT / "reports" / f"attack_fleet_limits_{prefix}.json"
    report_md = ROOT / "reports" / f"attack_fleet_limits_{prefix}.md"
    run_dir = ROOT / "runs" / f"attack-fleet-limits-{prefix}"
    scale_dir = ROOT / "labs" / "breaktest" / "manifests" / f"fleet-limits-{prefix}"
    if not decoys:
        report_json = ROOT / "reports" / f"attack_fleet_limits_{prefix}_nodecoy.json"
        report_md = ROOT / "reports" / f"attack_fleet_limits_{prefix}_nodecoy.md"
        run_dir = ROOT / "runs" / f"attack-fleet-limits-{prefix}-nodecoy"
        scale_dir = (
            ROOT / "labs" / "breaktest" / "manifests" / f"fleet-limits-{prefix}-nodecoy"
        )

    # Point limits scorer at scale paths
    limits.FLEET_DIR = scale_dir
    limits.RUN = run_dir
    limits.REPORT_JSON = report_json
    limits.REPORT_MD = report_md
    limits.HOSTS5 = scale_hosts(n)

    paths = write_scaled_manifests(n, decoys=decoys, dest=scale_dir, tier=tier)
    if run_dir.exists():
        shutil.rmtree(run_dir)
    run_dir.mkdir(parents=True)

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
                        "confidence_margin_kind",
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
    held_n = counts["HELD"]
    fragile_rate = round(fragile_count / held_n, 4) if held_n else None
    baseline_wins_count = sum(
        1 for a in attacks if (a.get("baseline") or {}).get("baseline_wins")
    )
    perf_gate = wall < 120.0 and (rss is None or rss < 500.0)

    t0_rate = args.t0_fragile_rate
    if t0_rate is None:
        t0_path = ROOT / "reports" / "attack_fleet_limits.json"
        if t0_path.is_file():
            try:
                t0 = json.loads(t0_path.read_text(encoding="utf-8"))
                t0_held = sum(1 for a in t0.get("attacks") or [] if a.get("verdict") == "HELD")
                t0_frag = sum(
                    1
                    for a in t0.get("attacks") or []
                    if a.get("fragile") and a.get("verdict") == "HELD"
                )
                if t0_held:
                    t0_rate = round(t0_frag / t0_held, 4)
            except (OSError, json.JSONDecodeError, ZeroDivisionError):
                t0_rate = None
    fragile_gate = None
    if fragile_rate is not None and t0_rate is not None and not decoys:
        fragile_gate = fragile_rate <= (t0_rate + 0.10)

    decoy_note = (
        "with quiet decoy laterals on unused high slots"
        if decoys
        else "NO decoys — unused hosts truly quiet (margin control)"
    )
    report = {
        "test": f"Attack fleet: Limits {tier} — {n}-host scale"
        + ("" if decoys else " (no-decoy control)"),
        "n": len(attacks),
        "n_hosts": n,
        "tier": tier,
        "decoys": decoys,
        "intensity_rounds": intensity,
        "baseline_policy": args.baseline,
        "total_wall_seconds": wall,
        "peak_rss_mb": rss,
        "t2_gate_pass": perf_gate,
        "t0_fragile_rate_ref": t0_rate,
        "fragile_gate_pass": fragile_gate,
        "counts": counts,
        "baseline_wins_count": baseline_wins_count,
        "fragile_count": fragile_count,
        "fragile_rate_held": fragile_rate,
        "scoring": {
            "fragile": (
                f"HELD with ambiguity margin < {limits.FRAGILE_MARGIN} → HELD, fragile "
                "(multi-campaign uses unmatched-competitor gap, not top−2nd among equals)"
            ),
            "writeup_priority": limits.WRITEUP_PRIORITY,
            "margin_def": (
                "ambiguity: min(matched)−max(unmatched) when multi clean; "
                "else top−2nd (confidence_margin_raw always retained)"
            ),
        },
        "attacks": attacks,
        "honesty": (
            f"T0 fleet-limits shapes remapped to {n} hosts {decoy_note}. Event sketches only."
        ),
    }
    report_json.parent.mkdir(parents=True, exist_ok=True)
    report_json.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    text = markdown_scale(report)
    report_md.write_text(text, encoding="utf-8")
    try:
        print(text)
    except UnicodeEncodeError:
        sys.stdout.buffer.write(text.encode("utf-8", errors="replace"))
    print(f"\nJSON: {report_json}")
    print(f"MD:   {report_md}")
    print(
        f"perf_gate={perf_gate} fragile_gate={fragile_gate} "
        f"(wall={wall}s rss={rss}) decoys={decoys} fragile_rate={fragile_rate} "
        f"t0_ref={t0_rate}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
