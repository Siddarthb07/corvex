#!/usr/bin/env python3
"""Run the benign-baseline gate against a labs/benign/<name> corpus.

Pre-committed bars are in corvex.eval.benign_baseline — do not change them
after seeing results. Mixed/attack OTRF slices report metrics but stay INCOMPLETE.
"""

from __future__ import annotations

import argparse
import json
import re
import shutil
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Mapping, Optional, Set

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from corvex.adapters.otrf import adapt_otrf_paths
from corvex.adapters.os_wide import adapt_os_wide_export, load_allowlist
from corvex.adapters.windows_security import write_byo_jsonl
from corvex.audit import AuditLog
from corvex.auth import Enrollment, generate_lab_enrollment, save_enrollment
from corvex.correlator import Correlator, CorrelatorConfig
from corvex.envelope import EventEnvelope, sign_envelope
from corvex.eval.benign_baseline import (
    auth_hop_degrees,
    count_false_campaigns,
    count_isolate_proposals,
    host_hours_from_events,
    hub_coverage,
    score_benign_baseline,
)
from corvex.reconstruct import write_reconstruction
from corvex.store import CampaignStore

BARS_PREAMBLE = """
## Pre-committed bars (locked 2026-07-25 — before this run)

| Metric | Bar |
|--------|-----|
| Minimum corpus | ≥ 72 host-hours and ≥ 3 distinct hosts |
| Eligible kinds | `pure_benign`, `home_lab_capture` only |
| Primary (IsolateHost FP) | FP_iso / H ≤ 1/1000 host-hours |
| Secondary (false campaigns) | FP_seal / H ≤ 1/100 host-hours |
| Hub coverage | Report OK if any host ≥ hub-degree bar; else **GAP** |

Mixed / attack-ambient public slices may be scored for metrics but **cannot PASS**.
Hand-crafted SCCM/RDP synthetic noise is forbidden for this gate.
""".strip()


def _slug_host(raw: str) -> str:
    base = str(raw).split(".", 1)[0].lower()
    base = re.sub(r"[^a-z0-9_-]+", "-", base).strip("-") or "host"
    return base


def _discover_raw(corpus: Path, man: Mapping[str, Any]) -> List[Path]:
    raw_dir = corpus / "raw"
    patterns = []
    glob = man.get("raw_glob")
    if glob:
        patterns.append(str(glob))
    patterns.extend(["raw/*.json", "raw/*.jsonl"])
    found: List[Path] = []
    seen: Set[str] = set()
    for pat in patterns:
        for p in sorted(corpus.glob(pat)):
            key = str(p.resolve())
            if key in seen or p.name.startswith("fetch_meta"):
                continue
            seen.add(key)
            found.append(p)
    if not found and raw_dir.exists():
        for p in sorted(raw_dir.iterdir()):
            if p.suffix.lower() in {".json", ".jsonl"} and p.name != "fetch_meta.json":
                found.append(p)
    return found


def _build_host_map(
    envs: List[Dict[str, Any]], man: Mapping[str, Any]
) -> Dict[str, str]:
    configured = {str(k).lower(): str(v) for k, v in (man.get("host_map") or {}).items()}
    # Also accept Computer FQDN keys as written in events before remap
    out: Dict[str, str] = dict(configured)
    for env in envs:
        hid = str(env.get("host_id") or "")
        if not hid:
            continue
        key = hid.lower()
        if key not in out:
            out[key] = _slug_host(hid)
    return out


def _sign_envs(
    unsigned: List[Dict[str, Any]], enrollment: Enrollment
) -> List[EventEnvelope]:
    out: List[EventEnvelope] = []
    for rec in unsigned:
        host = str(rec["host_id"])
        producer = str(rec["producer_id"])
        secret = enrollment.require(producer, host)
        out.append(
            sign_envelope(
                producer_id=producer,
                host_id=host,
                payload_type=str(rec["payload_type"]),
                payload=dict(rec.get("payload") or {}),
                secret=secret,
                event_id=str(rec["event_id"]),
                ts_utc=str(rec["ts_utc"]),
                nonce=str(rec.get("nonce") or rec["event_id"]),
            )
        )
    return out


def _enrollment_for_hosts(hosts: List[str], dest: Path) -> Enrollment:
    mapping = {h: f"prod-{h}" for h in hosts}
    enr = generate_lab_enrollment(mapping)
    save_enrollment(dest, enr)
    return enr


def convert_corpus(
    corpus: Path,
    man: Mapping[str, Any],
    *,
    adapter: str,
    allowlist: Optional[Path],
) -> tuple[List[Dict[str, Any]], Dict[str, Any]]:
    paths = _discover_raw(corpus, man)
    if not paths:
        raise FileNotFoundError(f"no raw JSON/JSONL under {corpus / 'raw'}")
    host_map = {str(k): str(v) for k, v in (man.get("host_map") or {}).items()}
    if adapter == "otrf":
        envs, stats = adapt_otrf_paths(
            paths, host_map=host_map or None, allowlist_path=allowlist
        )
    else:
        allow = load_allowlist(allowlist)
        envs = []
        stats = {"skipped": 0, "adapted": 0, "by_channel": {}, "files": 0}
        for i, path in enumerate(paths):
            chunk, st = adapt_os_wide_export(
                path,
                host_map=host_map or None,
                allowlist=allow,
                id_prefix=f"benign{i}",
            )
            envs.extend(chunk)
            stats["files"] = int(stats["files"]) + 1
            stats["skipped"] = int(stats["skipped"]) + int(st.get("skipped") or 0)
            stats["adapted"] = int(stats["adapted"]) + int(st.get("adapted") or 0)
            for ch, n in (st.get("by_channel") or {}).items():
                stats["by_channel"][ch] = int(stats["by_channel"].get(ch, 0)) + int(n)

    # Normalize host ids via slug map (1:1 enrollment needs stable short ids)
    hmap = _build_host_map(envs, man)
    # Also map short NetBIOS-style auth src fields onto canonical host ids.
    src_aliases = dict(hmap)
    for raw, canon in list(hmap.items()):
        src_aliases[_slug_host(raw)] = canon
        src_aliases[raw.split(".", 1)[0].lower()] = canon
    remapped: List[Dict[str, Any]] = []
    for env in envs:
        hid = str(env["host_id"])
        canon = hmap.get(hid.lower(), hmap.get(hid, _slug_host(hid)))
        row = dict(env)
        row["host_id"] = canon
        row["producer_id"] = f"prod-{canon}"
        payload = dict(row.get("payload") or {})
        src = str(payload.get("src") or "")
        if src:
            key = src.lower()
            slug = _slug_host(src)
            if key in src_aliases:
                payload["src"] = src_aliases[key]
            elif slug in src_aliases:
                payload["src"] = src_aliases[slug]
            row["payload"] = payload
        remapped.append(row)
    stats["host_map_effective"] = hmap
    stats["source_files"] = [p.name for p in paths]
    return remapped, stats


def run_correlate(
    events: List[EventEnvelope], run_dir: Path, enrollment: Enrollment
) -> Dict[str, Any]:
    run_dir.mkdir(parents=True, exist_ok=True)
    store = CampaignStore(run_dir / "campaigns.jsonl")
    audit = AuditLog(run_dir / "audit.jsonl")
    corr = Correlator(store, audit, config=CorrelatorConfig(), enrollment=enrollment)
    corr.ingest(events)
    camps = [c.to_dict() for c in store.all()]
    timeline = {
        "pack": "benign-baseline",
        "mode": "offline_lab_replay",
        "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "envelope_events": len(events),
        "campaigns": camps,
    }
    (run_dir / "timeline.json").write_text(
        json.dumps(timeline, indent=2) + "\n", encoding="utf-8"
    )
    events_path = run_dir / "events.jsonl"
    with events_path.open("w", encoding="utf-8") as fh:
        for env in events:
            fh.write(json.dumps(env.to_dict(), separators=(",", ":")) + "\n")
    write_reconstruction(run_dir, quarantine_mode="dry_run")
    return timeline


def render_md(report: Mapping[str, Any]) -> str:
    gate = report["gate"]
    lines = [
        "# Benign baseline report",
        "",
        BARS_PREAMBLE,
        "",
        f"**Gate:** `{gate}`",
        f"**Corpus:** `{report.get('corpus_name')}` ({report.get('corpus_kind')})",
        f"**Host-hours (H):** {report.get('host_hours')}",
        f"**Hosts:** {report.get('n_hosts')}",
        f"**FP_iso (IsolateHost proposals):** {report.get('fp_iso')} "
        f"(rate={report.get('fp_iso_per_host_hour')})",
        f"**FP_seal (campaigns):** {report.get('fp_seal')} "
        f"(rate={report.get('fp_seal_per_host_hour')})",
        f"**hub_coverage:** `{report.get('hub_coverage')}`",
        "",
        "## Reasons",
        "",
    ]
    for r in report.get("reasons") or []:
        lines.append(f"- {r}")
    lines.extend(
        [
            "",
            "## Honesty",
            "",
            "- Quarantine = dry-run IsolateHost proposals only.",
            "- Standing claim sentence still applies unless gate is PASS:",
            "",
            "> Research correlator — holds up against synthetic ATT&CK-shaped fleets; "
            "not yet validated against real telemetry or benign baselines.",
            "",
        ]
    )
    return "\n".join(lines) + "\n"


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument(
        "--corpus",
        type=Path,
        required=True,
        help="Path to labs/benign/<name> (must contain manifest.json + raw/)",
    )
    ap.add_argument(
        "--adapter",
        choices=("otrf", "os_wide"),
        default="otrf",
        help="otrf=Mordor/Security-Datasets; os_wide=Event Viewer–shaped JSON",
    )
    ap.add_argument(
        "--allowlist",
        type=Path,
        default=ROOT / "fixtures" / "os_wide" / "channels.json",
    )
    ap.add_argument(
        "--report-stem",
        default=None,
        help="reports/<stem>.{json,md} (default: benign_baseline_<corpus>)",
    )
    args = ap.parse_args()
    corpus = Path(args.corpus)
    if not corpus.is_absolute():
        corpus = ROOT / corpus
    man_path = corpus / "manifest.json"
    if not man_path.is_file():
        print(f"missing manifest: {man_path}", file=sys.stderr)
        return 2
    man = json.loads(man_path.read_text(encoding="utf-8"))

    unsigned, adapt_stats = convert_corpus(
        corpus, man, adapter=args.adapter, allowlist=args.allowlist
    )
    conv = corpus / "converted"
    if conv.exists():
        shutil.rmtree(conv)
    conv.mkdir(parents=True)
    write_byo_jsonl(unsigned, conv / "byo_unsigned.jsonl")
    (conv / "adapt_stats.json").write_text(
        json.dumps(adapt_stats, indent=2) + "\n", encoding="utf-8"
    )

    hosts = sorted({str(e["host_id"]) for e in unsigned})
    run_dir = ROOT / "runs" / "benign-baseline" / corpus.name
    if run_dir.exists():
        shutil.rmtree(run_dir)
    run_dir.mkdir(parents=True)
    enrollment = _enrollment_for_hosts(hosts, run_dir / "enrollment.json")
    # Re-stamp producer_id to match enrollment
    for e in unsigned:
        e["producer_id"] = f"prod-{e['host_id']}"
    signed = _sign_envs(unsigned, enrollment)
    timeline = run_correlate(signed, run_dir, enrollment)

    recon = json.loads((run_dir / "reconstruction.json").read_text(encoding="utf-8"))
    fp_iso, iso_hosts = count_isolate_proposals(recon)
    excluded: Set[str] = set()
    for w in man.get("attack_windows") or []:
        for h in w.get("hosts") or []:
            excluded.add(_slug_host(str(h)))
    fp_seal, seal_ids = count_false_campaigns(
        timeline.get("campaigns") or [], excluded_hosts=excluded or None
    )

    H, per_host = host_hours_from_events([e.to_dict() for e in signed])
    degrees = auth_hop_degrees([e.to_dict() for e in signed])
    hub = hub_coverage(degrees, n_hosts=len(hosts))

    scored = score_benign_baseline(
        corpus_kind=str(man.get("corpus_kind") or "unknown"),
        host_hours=H,
        n_hosts=len(hosts),
        fp_iso=fp_iso,
        fp_seal=fp_seal,
        hub=hub,
    )
    report = {
        **scored,
        "corpus_name": corpus.name,
        "corpus_path": str(corpus.relative_to(ROOT)) if ROOT in corpus.parents else str(corpus),
        "adapt_stats": adapt_stats,
        "hosts": hosts,
        "host_hours_per_host": per_host,
        "isolate_hosts": iso_hosts,
        "campaign_ids": seal_ids,
        "run_dir": str(run_dir.relative_to(ROOT)),
        "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
    }

    stem = args.report_stem or f"benign_baseline_{corpus.name}"
    reports = ROOT / "reports"
    reports.mkdir(parents=True, exist_ok=True)
    (reports / f"{stem}.json").write_text(
        json.dumps(report, indent=2) + "\n", encoding="utf-8"
    )
    (reports / f"{stem}.md").write_text(render_md(report), encoding="utf-8")
    (run_dir / "benign_baseline_report.json").write_text(
        json.dumps(report, indent=2) + "\n", encoding="utf-8"
    )

    print(json.dumps({k: report[k] for k in (
        "gate", "corpus_kind", "host_hours", "n_hosts", "fp_iso", "fp_seal",
        "hub_coverage", "reasons",
    )}, indent=2))
    print(f"wrote reports/{stem}.md", flush=True)
    # Exit 0 even on FAIL/INCOMPLETE — the report is the result; CI can assert later.
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
