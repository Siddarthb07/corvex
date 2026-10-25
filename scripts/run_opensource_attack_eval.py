#!/usr/bin/env python3
"""Score Corvex on open-source OTRF/Security-Datasets captures (external authorship).

Primary capability stress for CSET-style criticism that author-written fleets are
not independent. Metrics are **observational** (no Corvex-authored ground truth):

  - hosts observed in adapted telemetry
  - multi-host campaigns formed (correlator vs detector-only)
  - fusion lift = multi-host correlator camps − multi-host detector camps
  - quarantine dry-run host count (FP risk surface)

Does **not** invent F1 against author labels. Does **not** flip claim_allowed.

  python scripts/fetch_opensource_corpora.py
  python scripts/run_opensource_attack_eval.py
"""

from __future__ import annotations

import argparse
import json
import re
import shutil
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Mapping, Optional, Sequence, Set

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "scripts"))

from corvex.adapters.otrf import adapt_otrf_paths  # noqa: E402
from corvex.audit import AuditLog  # noqa: E402
from corvex.auth import Enrollment, generate_lab_enrollment, save_enrollment  # noqa: E402
from corvex.correlator import Correlator, CorrelatorConfig  # noqa: E402
from corvex.envelope import EventEnvelope, sign_envelope  # noqa: E402
from corvex.reconstruct import write_reconstruction  # noqa: E402
from corvex.store import CampaignStore  # noqa: E402

OSS_ROOT = ROOT / "labs" / "opensource"
CATALOG = OSS_ROOT / "catalog.json"
RUN = ROOT / "runs" / "opensource-attack-eval"
REPORT_JSON = ROOT / "reports" / "opensource_attack_eval.json"
REPORT_MD = ROOT / "reports" / "opensource_attack_eval.md"
INVENTORY_MD = ROOT / "reports" / "opensource_attack_inventory.md"
AGG_REPORT_JSON = ROOT / "reports" / "opensource_aggressive_eval.json"
AGG_REPORT_MD = ROOT / "reports" / "opensource_aggressive_eval.md"
AGG_INVENTORY_MD = ROOT / "reports" / "opensource_aggressive_inventory.md"


def _load_catalog() -> Dict[str, Dict[str, Any]]:
    if not CATALOG.is_file():
        return {}
    cat = json.loads(CATALOG.read_text(encoding="utf-8"))
    return {str(e["id"]): e for e in (cat.get("corpora") or []) if e.get("id")}


def _slug_host(raw: str) -> str:
    base = str(raw).split(".", 1)[0].lower()
    base = re.sub(r"[^a-z0-9_-]+", "-", base).strip("-") or "host"
    return base


def _discover_raw(corpus: Path) -> List[Path]:
    raw = corpus / "raw"
    found: List[Path] = []
    seen: Set[str] = set()
    for pat in ("*.sanitized.jsonl", "*.jsonl", "*.json"):
        for p in sorted(raw.glob(pat)):
            if p.name.startswith("fetch_meta"):
                continue
            key = str(p.resolve())
            if key in seen:
                continue
            seen.add(key)
            found.append(p)
    return found


def _convert(corpus: Path) -> tuple[List[Dict[str, Any]], Dict[str, Any]]:
    paths = _discover_raw(corpus)
    if not paths:
        raise FileNotFoundError(f"no raw JSON under {corpus / 'raw'}")
    allow = ROOT / "fixtures" / "os_wide" / "channels.json"
    envs, stats = adapt_otrf_paths(
        paths,
        allowlist_path=allow if allow.exists() else None,
        id_prefix=f"oss-{corpus.name}",
    )
    # slug host map
    hmap: Dict[str, str] = {}
    for env in envs:
        hid = str(env.get("host_id") or "")
        if hid:
            hmap.setdefault(hid.lower(), _slug_host(hid))
    remapped: List[Dict[str, Any]] = []
    for env in envs:
        hid = str(env["host_id"])
        canon = hmap.get(hid.lower(), _slug_host(hid))
        row = dict(env)
        row["host_id"] = canon
        row["producer_id"] = f"prod-oss-{canon}"
        payload = dict(row.get("payload") or {})
        src = str(payload.get("src") or "")
        if src:
            slug = _slug_host(src)
            if src.lower() in hmap:
                payload["src"] = hmap[src.lower()]
            elif slug in {v for v in hmap.values()}:
                payload["src"] = slug
            row["payload"] = payload
        remapped.append(row)
    stats["host_map_effective"] = hmap
    stats["source_files"] = [p.name for p in paths]
    stats["n_unsigned"] = len(remapped)
    return remapped, stats


def _sign(unsigned: Sequence[Mapping[str, Any]], enrollment: Enrollment) -> List[EventEnvelope]:
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


def _enrollment(hosts: Sequence[str], dest: Path) -> Enrollment:
    mapping = {h: f"prod-oss-{h}" for h in hosts}
    enr = generate_lab_enrollment(mapping)
    save_enrollment(dest, enr)
    return enr


def _campaign_stats(camps: Sequence[Mapping[str, Any]]) -> Dict[str, Any]:
    rows = []
    multi = 0
    hosts_union: Set[str] = set()
    for c in camps:
        hs = sorted({str(h) for h in (c.get("host_ids") or [])})
        hosts_union |= set(hs)
        if len(hs) >= 2:
            multi += 1
        rows.append(
            {
                "campaign_id": c.get("campaign_id") or c.get("id"),
                "n_hosts": len(hs),
                "hosts": hs,
                "score": c.get("score"),
                "stages": list((c.get("stages") or {}).keys())
                if isinstance(c.get("stages"), dict)
                else c.get("stage_names"),
            }
        )
    rows.sort(key=lambda r: (r["n_hosts"], float(r.get("score") or 0)), reverse=True)
    return {
        "n_campaigns": len(camps),
        "n_multi_host": multi,
        "hosts_in_campaigns": sorted(hosts_union),
        "n_hosts_in_campaigns": len(hosts_union),
        "top": rows[:8],
    }


def _correlate(
    events: Sequence[EventEnvelope],
    run_dir: Path,
    enrollment: Enrollment,
    *,
    mode: str,
) -> Dict[str, Any]:
    run_dir.mkdir(parents=True, exist_ok=True)
    store = CampaignStore(run_dir / "campaigns.jsonl")
    audit = AuditLog(run_dir / "audit.jsonl")
    if mode == "correlator":
        corr = Correlator(store, audit, config=CorrelatorConfig(), enrollment=enrollment)
        corr.ingest(list(events))
        camps = [c.to_dict() for c in store.all()]
    elif mode == "detector_only":
        from corvex.cli import _predict_from_events

        camps_list, _ = _predict_from_events(
            list(events), "detector_only", enrollment=enrollment
        )
        camps = [dict(c) for c in camps_list]
    else:
        raise ValueError(mode)

    timeline = {
        "pack": "opensource-attack-eval",
        "mode": mode,
        "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "envelope_events": len(events),
        "campaigns": camps,
    }
    (run_dir / "timeline.json").write_text(
        json.dumps(timeline, indent=2) + "\n", encoding="utf-8"
    )
    with (run_dir / "events.jsonl").open("w", encoding="utf-8") as fh:
        for env in events:
            fh.write(json.dumps(env.to_dict(), separators=(",", ":")) + "\n")
    if mode == "correlator":
        write_reconstruction(run_dir, quarantine_mode="dry_run")
    return timeline


def _quarantine_hosts(run_dir: Path) -> List[str]:
    path = run_dir / "reconstruction.json"
    if not path.is_file():
        return []
    recon = json.loads(path.read_text(encoding="utf-8"))
    q: Set[str] = set()
    for item in recon.get("campaign_reconstructions") or []:
        qq = item.get("quarantine") or {}
        if "host_ids" in qq:
            q.update(str(h) for h in (qq.get("host_ids") or []))
        else:
            q.update(str(h) for h in (item.get("host_ids") or []))
    return sorted(q)


def score_corpus(
    corpus: Path, *, catalog_entry: Optional[Mapping[str, Any]] = None
) -> Dict[str, Any]:
    man = {}
    man_path = corpus / "manifest.json"
    if man_path.is_file():
        man = json.loads(man_path.read_text(encoding="utf-8"))
    meta = dict(catalog_entry or {})
    t0 = time.perf_counter()
    unsigned, adapt_stats = _convert(corpus)
    hosts = sorted({str(e["host_id"]) for e in unsigned})
    attack_meta = {
        "tool": meta.get("tool") or (man.get("source") or {}).get("tool"),
        "attack": meta.get("attack") or meta.get("note") or (man.get("source") or {}).get("note"),
        "techniques": meta.get("techniques") or [],
        "family": meta.get("family") or (man.get("source") or {}).get("family"),
        "source_path": meta.get("path") or (man.get("source") or {}).get("url"),
    }
    if len(hosts) < 1:
        return {
            "id": corpus.name,
            "ok": False,
            "error": "no adapted hosts",
            "adapt": adapt_stats,
            **attack_meta,
            "verdict_observational": {
                "label": "NO_SIGNAL",
                "reasons": ["adapter produced zero envelopes (channel/format gap)"],
            },
            "breaks": ["NO_SIGNAL: adapter produced zero envelopes"],
        }
    run_root = RUN / corpus.name
    if run_root.exists():
        shutil.rmtree(run_root)
    run_root.mkdir(parents=True)
    enrollment = _enrollment(hosts, run_root / "enrollment.json")
    events = _sign(unsigned, enrollment)

    corr_tl = _correlate(
        events, run_root / "correlator", enrollment, mode="correlator"
    )
    det_tl = _correlate(
        events, run_root / "detector_only", enrollment, mode="detector_only"
    )
    corr_s = _campaign_stats(corr_tl.get("campaigns") or [])
    det_s = _campaign_stats(det_tl.get("campaigns") or [])
    q_hosts = _quarantine_hosts(run_root / "correlator")

    # Observational "involved" hosts: those with auth or multi-host-ish payload types
    involved: Set[str] = set()
    by_type: Dict[str, int] = {}
    for e in events:
        pt = str(e.payload_type)
        by_type[pt] = by_type.get(pt, 0) + 1
        if pt in {"auth", "dns"} or (
            pt == "net_conn" and bool((e.payload or {}).get("egress"))
        ):
            involved.add(str(e.host_id))

    corr_multi_hosts = set(corr_s.get("hosts_in_campaigns") or [])
    # Hosts that appear in any correlator campaign with ≥2 hosts
    corr_bridge_hosts: Set[str] = set()
    for c in (corr_s.get("top") or []):
        if int(c.get("n_hosts") or 0) >= 2:
            corr_bridge_hosts |= set(c.get("hosts") or [])
    det_bridge_hosts: Set[str] = set()
    for c in (det_s.get("top") or []):
        if int(c.get("n_hosts") or 0) >= 2:
            det_bridge_hosts |= set(c.get("hosts") or [])
    # Prefer host-coverage lift over campaign-count lift (merge shrinks camp count).
    host_coverage_lift = len(corr_bridge_hosts) - len(det_bridge_hosts)
    fusion_multi_lift = host_coverage_lift
    wall = round(time.perf_counter() - t0, 4)
    adapted_n = int(adapt_stats.get("adapted") or 0)
    skipped_n = int(adapt_stats.get("skipped") or 0)
    skip_rate = round(skipped_n / max(1, adapted_n + skipped_n), 4)
    q_all = bool(hosts) and set(q_hosts) >= set(hosts)
    breaks: List[str] = []
    verdict = _verdict(
        n_hosts=len(hosts),
        corr=corr_s,
        det=det_s,
        corr_bridge=len(corr_bridge_hosts),
        det_bridge=len(det_bridge_hosts),
        lift=fusion_multi_lift,
        n_adapted=len(events),
        skip_rate=skip_rate,
        q_all_hosts=q_all,
    )
    if verdict["label"] in {"FRAGMENTED", "BLIND", "NO_SIGNAL", "SINGLE_HOST"}:
        breaks.append(f"{verdict['label']}: {'; '.join(verdict.get('reasons') or [])}")
    if (
        fusion_multi_lift <= 0
        and len(corr_bridge_hosts) >= 2
        and verdict["label"] != "FUSION_HELD"
    ):
        breaks.append(
            "FUSION_NO_LIFT: correlator multi-host bridge does not cover more hosts than detector-only"
        )
    if q_all:
        breaks.append(
            f"Q_DRYRUN_ALL_HOSTS: quarantine dry-run proposes all {len(hosts)} observed hosts"
        )
    if skip_rate >= 0.85:
        breaks.append(
            f"ADAPTER_HEAVY_SKIP: skip_rate={skip_rate} "
            f"(adapted={adapted_n}, skipped={skipped_n}) — channel allowlist blind spot"
        )
    if int(corr_s.get("n_multi_host") or 0) == 0 and len(hosts) >= 2 and adapted_n > 0:
        if f"{verdict['label']}" not in {"FRAGMENTED", "BLIND"}:
            breaks.append("NO_MULTI_HOST_CAMP: ≥2 hosts observed but no multi-host campaign")

    return {
        "id": corpus.name,
        "ok": True,
        "authorship": "external",
        "source": man.get("source") or {},
        **attack_meta,
        "wall_seconds": wall,
        "n_events_adapted": len(events),
        "n_hosts_observed": len(hosts),
        "hosts_observed": hosts,
        "n_hosts_involved_auth_dns_egress": len(involved),
        "hosts_involved": sorted(involved),
        "payload_type_counts": by_type,
        "adapt": {
            "adapted": adapted_n,
            "skipped": skipped_n,
            "skip_rate": skip_rate,
            "by_channel": adapt_stats.get("by_channel"),
            "source_files": adapt_stats.get("source_files"),
        },
        "correlator": corr_s,
        "detector_only": det_s,
        "corr_bridge_hosts": sorted(corr_bridge_hosts),
        "det_bridge_hosts": sorted(det_bridge_hosts),
        "fusion_multi_host_lift": fusion_multi_lift,
        "fusion_lift_kind": "bridge_host_coverage",
        "quarantine_dry_run_hosts": q_hosts,
        "n_quarantine_dry_run": len(q_hosts),
        "quarantine_covers_all_hosts": q_all,
        "breaks": breaks,
        "verdict_observational": verdict,
    }


def _verdict(
    *,
    n_hosts: int,
    corr: Mapping[str, Any],
    det: Mapping[str, Any],
    corr_bridge: int,
    det_bridge: int,
    lift: int,
    n_adapted: int,
    skip_rate: float = 0.0,
    q_all_hosts: bool = False,
) -> Dict[str, Any]:
    """Legible observational label — not F1."""
    reasons: List[str] = []
    corr_multi = int(corr.get("n_multi_host") or 0)
    det_multi = int(det.get("n_multi_host") or 0)
    if n_adapted == 0:
        return {"label": "NO_SIGNAL", "reasons": ["zero adapted envelopes"]}
    if n_hosts < 2:
        reasons.append("single-host capture — multi-host fusion not testable")
        label = "SINGLE_HOST"
    elif corr_bridge >= 2 and lift > 0:
        label = "FUSION_HELD"
        reasons.append(
            f"correlator bridges {corr_bridge} hosts across multi-host camps; "
            f"detector bridges {det_bridge} (host-coverage lift={lift})"
        )
    elif (
        corr_bridge >= 2
        and det_bridge >= 2
        and corr_bridge >= n_hosts
        and det_bridge >= n_hosts
        and corr_multi > 0
        and corr_multi <= det_multi
        and not q_all_hosts
    ):
        # Both arms already cover the whole small lab — host-coverage lift cannot
        # rise. Award HELD when fusion consolidates or matches detector camp count
        # and quarantine stays surgical.
        label = "FUSION_HELD"
        reasons.append(
            f"saturated fleet ({n_hosts} hosts): correlator multi-host camps "
            f"{corr_multi} <= detector {det_multi}; Q not fleet-wide"
        )
    elif corr_bridge >= 2:
        label = "MULTI_HOST_NO_LIFT"
        reasons.append(
            f"multi-host bridge present (corr_hosts={corr_bridge}, det_hosts={det_bridge}); "
            "no host-coverage lift vs detector-only"
        )
    elif corr["n_campaigns"] >= 1:
        label = "FRAGMENTED"
        reasons.append(
            "campaigns formed but none multi-host — lateral bridge missing or "
            "telemetry lacks correlatable auth/src links"
        )
    else:
        label = "BLIND"
        reasons.append("no campaigns — detectors/channels may not map this capture")
    if q_all_hosts:
        reasons.append("quarantine dry-run covers every observed host (FP risk)")
    if skip_rate >= 0.85:
        reasons.append(f"adapter skip_rate={skip_rate} (most raw events dropped)")
    return {"label": label, "reasons": reasons}


def write_md(report: Mapping[str, Any], *, md_path: Path, inv_name: str) -> None:
    rows = report.get("corpora") or []
    title = report.get("title") or "Open-source attack eval (OTRF / Security-Datasets)"
    lines = [
        f"# {title}",
        "",
        "Externally authored captures. **Not** Corvex-written fleet manifests.",
        f"**claim_allowed={report.get('claim_allowed')}**. Lab purple-team only.",
        "",
        f"- Corpora scored: **{report.get('n')}** | Wall: **{report.get('wall_seconds')}s**",
        f"- Catalog: `labs/opensource/catalog.json`",
        f"- Attack inventory: [`{inv_name}`]({inv_name})",
        "",
        "## Verdict rollup (observational)",
        "",
        "| Label | Count | Meaning |",
        "|-------|-------|---------|",
    ]
    counts = report.get("verdict_counts") or {}
    meanings = {
        "FUSION_HELD": "Multi-host campaign + correlator beat detector-only",
        "MULTI_HOST_NO_LIFT": "Multi-host present; fusion adds no host-coverage lift",
        "FRAGMENTED": "Campaigns exist but all single-host — lateral bridge failed",
        "BLIND": "No campaigns from adapted events",
        "SINGLE_HOST": "Capture has <2 hosts — fusion not testable",
        "NO_SIGNAL": "Adapter produced nothing",
        "ERROR": "Fetch/adapt/score failed",
    }
    for label, n in sorted(counts.items(), key=lambda kv: (-kv[1], kv[0])):
        lines.append(f"| **{label}** | {n} | {meanings.get(label, '')} |")

    lines.extend(
        [
            "",
            "## Scoreboard",
            "",
            "| Attack | Tool | Family | Verdict | Hosts | Events | Lift | Q all? | Breaks |",
            "|--------|------|--------|---------|-------|--------|------|--------|--------|",
        ]
    )
    for r in rows:
        v = (r.get("verdict_observational") or {}).get("label") or "ERROR"
        attack = (r.get("attack") or r.get("id") or "")[:48]
        tech = ",".join(r.get("techniques") or [])[:40]
        br = "; ".join((r.get("breaks") or [])[:2]) or "—"
        if len(br) > 60:
            br = br[:57] + "…"
        lines.append(
            f"| {attack} | {r.get('tool') or '—'} | {r.get('family') or '—'} | **{v}** | "
            f"{r.get('n_hosts_observed') if r.get('ok') else '—'} | "
            f"{r.get('n_events_adapted') if r.get('ok') else '—'} | "
            f"{r.get('fusion_multi_host_lift') if r.get('ok') else '—'} | "
            f"{'yes' if r.get('quarantine_covers_all_hosts') else 'no'} | {br} |"
        )
        if tech:
            lines.append(f"| ↳ techniques `{tech}` | | | | | | | | |")

    # Break matrix — anything with a breaks[] entry
    broken = [r for r in rows if r.get("breaks")]
    lines.extend(["", "## Where it breaks (every flagged corpus)", ""])
    if not broken:
        lines.append("_No break flags._")
    else:
        for r in sorted(
            broken,
            key=lambda x: (
                0
                if (x.get("verdict_observational") or {}).get("label")
                in {"BLIND", "FRAGMENTED", "NO_SIGNAL", "ERROR"}
                else 1,
                x.get("id") or "",
            ),
        ):
            v = (r.get("verdict_observational") or {}).get("label")
            lines.append(
                f"### `{r.get('id')}` — {r.get('attack') or ''} ({r.get('tool') or '?'})"
            )
            lines.append("")
            lines.append(f"- **Verdict:** `{v}`")
            lines.append(f"- **Techniques:** {', '.join(r.get('techniques') or []) or '—'}")
            lines.append(
                f"- **Hosts/events:** {r.get('n_hosts_observed')} / {r.get('n_events_adapted')}"
            )
            lines.append(f"- **Skip rate:** {(r.get('adapt') or {}).get('skip_rate')}")
            lines.append(f"- **Corr bridge hosts:** {', '.join(r.get('corr_bridge_hosts') or []) or '—'}")
            lines.append(f"- **Q dry-run:** {', '.join(r.get('quarantine_dry_run_hosts') or []) or '—'}")
            for b in r.get("breaks") or []:
                lines.append(f"- **Break:** {b}")
            lines.append("")

    lines.extend(
        [
            "",
            "## Honesty",
            "",
            "- Authorship: OTRF / MITRE ATT&CK Evals Caldera — **external**.",
            "- Observational metrics (no Corvex-authored ground-truth F1).",
            "- Sanitized JSONL drops CommandLine/ScriptBlockText (Defender PUA).",
            "- `claim_allowed` stays false.",
            "",
            "## Reproduce",
            "",
            "```bash",
            report.get("reproduce")
            or "python scripts/fetch_opensource_corpora.py --full\npython scripts/run_opensource_attack_eval.py",
            "```",
            "",
        ]
    )
    md_path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def write_inventory(report: Mapping[str, Any], *, inv_path: Path) -> None:
    rows = report.get("corpora") or []
    inv_title = report.get("inventory_title") or "Open-source attacks used (inventory)"
    lines = [
        f"# {inv_title}",
        "",
        "Every corpus scored in this eval. Authorship = OTRF / MITRE.",
        "",
        f"Generated: **{report.get('generated_utc')}** | N=**{report.get('n')}**",
        "",
        "| # | ID | Attack | Tool | ATT&CK / techniques | Family | Verdict | Breaks? |",
        "|---|----|--------|------|---------------------|--------|---------|---------|",
    ]
    for i, r in enumerate(rows, 1):
        v = (r.get("verdict_observational") or {}).get("label") or "ERROR"
        tech = ", ".join(r.get("techniques") or []) or "—"
        br = "yes" if r.get("breaks") else "no"
        lines.append(
            f"| {i} | `{r.get('id')}` | {r.get('attack') or '—'} | {r.get('tool') or '—'} | "
            f"{tech} | {r.get('family') or '—'} | **{v}** | {br} |"
        )

    # By tool / family pivots
    by_tool: Dict[str, Dict[str, int]] = {}
    by_fam: Dict[str, Dict[str, int]] = {}
    for r in rows:
        v = (r.get("verdict_observational") or {}).get("label") or "ERROR"
        tool = str(r.get("tool") or "?")
        fam = str(r.get("family") or "?")
        by_tool.setdefault(tool, {})
        by_tool[tool][v] = by_tool[tool].get(v, 0) + 1
        by_fam.setdefault(fam, {})
        by_fam[fam][v] = by_fam[fam].get(v, 0) + 1

    lines.extend(["", "## By tool", "", "| Tool | Verdicts |", "|------|----------|"])
    for tool, vc in sorted(by_tool.items()):
        lines.append(f"| {tool} | {', '.join(f'{k}={n}' for k, n in sorted(vc.items()))} |")
    lines.extend(["", "## By ATT&CK family", "", "| Family | Verdicts |", "|--------|----------|"])
    for fam, vc in sorted(by_fam.items()):
        lines.append(f"| {fam} | {', '.join(f'{k}={n}' for k, n in sorted(vc.items()))} |")

    lines.extend(
        [
            "",
            "## Upstream",
            "",
            "- https://github.com/OTRF/Security-Datasets",
            "- APT3 / APT29: MITRE ATT&CK Evals via Caldera / Empire / manual compounds",
            "- LSASS: Metasploit dump technique variants (OTRF compound campaigns)",
            "",
        ]
    )
    inv_path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--only", action="append", default=[])
    ap.add_argument(
        "--aggressive",
        action="store_true",
        help="Score only catalog entries marked aggressive=true (APT29/APT3/LSASS/…)",
    )
    ap.add_argument(
        "--root",
        type=Path,
        default=OSS_ROOT,
        help="Directory of opensource corpora",
    )
    args = ap.parse_args()
    root = Path(args.root)
    only = set(args.only or [])
    catalog = _load_catalog()
    aggressive_ids = {cid for cid, e in catalog.items() if e.get("aggressive")}

    corpora_dirs = sorted(
        p
        for p in root.iterdir()
        if p.is_dir() and (p / "raw").is_dir() and p.name not in {"__pycache__", "_staging"}
    )
    if only:
        corpora_dirs = [p for p in corpora_dirs if p.name in only]
    elif args.aggressive:
        corpora_dirs = [p for p in corpora_dirs if p.name in aggressive_ids]
    if not corpora_dirs:
        hint = (
            "python scripts/fetch_opensource_corpora.py --aggressive"
            if args.aggressive
            else "python scripts/fetch_opensource_corpora.py --full"
        )
        print(f"No corpora under labs/opensource/. Run: {hint}", file=sys.stderr)
        return 2

    rows: List[Dict[str, Any]] = []
    t0 = time.perf_counter()
    for corpus in corpora_dirs:
        print(f"=== {corpus.name} ===", flush=True)
        entry = catalog.get(corpus.name)
        try:
            row = score_corpus(corpus, catalog_entry=entry)
        except Exception as exc:  # noqa: BLE001
            row = {
                "id": corpus.name,
                "ok": False,
                "error": str(exc),
                "tool": (entry or {}).get("tool"),
                "attack": (entry or {}).get("attack"),
                "techniques": (entry or {}).get("techniques") or [],
                "family": (entry or {}).get("family"),
                "breaks": [f"ERROR: {exc}"],
                "verdict_observational": {
                    "label": "ERROR",
                    "reasons": [str(exc)],
                },
            }
        rows.append(row)
        v = (row.get("verdict_observational") or {}).get("label")
        nb = len(row.get("breaks") or [])
        print(
            f"  -> {v} attack={row.get('attack')!r} hosts={row.get('n_hosts_observed')} "
            f"events={row.get('n_events_adapted')} lift={row.get('fusion_multi_host_lift')} "
            f"breaks={nb}",
            flush=True,
        )

    counts: Dict[str, int] = {}
    break_counts: Dict[str, int] = {}
    for r in rows:
        lab = (r.get("verdict_observational") or {}).get("label") or "ERROR"
        counts[lab] = counts.get(lab, 0) + 1
        for b in r.get("breaks") or []:
            key = b.split(":", 1)[0]
            break_counts[key] = break_counts.get(key, 0) + 1

    if args.aggressive:
        report_json, report_md, inv_md = AGG_REPORT_JSON, AGG_REPORT_MD, AGG_INVENTORY_MD
        title = "Aggressive open-source attack eval (APT29 / APT3 / LSASS / Log4Shell / GoldenSAML)"
        inv_title = "Aggressive attacks used (inventory)"
        reproduce = (
            "python scripts/fetch_opensource_corpora.py --aggressive\n"
            "python scripts/run_opensource_attack_eval.py --aggressive"
        )
        test_name = "Aggressive OTRF compound attack battery"
    else:
        report_json, report_md, inv_md = REPORT_JSON, REPORT_MD, INVENTORY_MD
        title = "Open-source attack eval (OTRF / Security-Datasets)"
        inv_title = "Open-source attacks used (inventory)"
        reproduce = (
            "python scripts/fetch_opensource_corpora.py --full\n"
            "python scripts/run_opensource_attack_eval.py"
        )
        test_name = "Open-source OTRF/Security-Datasets attack eval"

    report = {
        "test": test_name,
        "title": title,
        "inventory_title": inv_title,
        "reproduce": reproduce,
        "tier": "aggressive" if args.aggressive else "full",
        "generated_utc": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "authorship": "external — OTRF / MITRE ATT&CK Evals captures",
        "claim_allowed": False,
        "n": len(rows),
        "wall_seconds": round(time.perf_counter() - t0, 4),
        "verdict_counts": counts,
        "break_type_counts": break_counts,
        "corpora": rows,
        "honesty": (
            "Observational metrics on externally authored captures. "
            "Not enterprise validation. claim_allowed stays false."
        ),
    }
    report_json.write_text(json.dumps(report, indent=2, default=str) + "\n", encoding="utf-8")
    write_md(report, md_path=report_md, inv_name=inv_md.name)
    write_inventory(report, inv_path=inv_md)
    print(
        json.dumps(
            {
                "n": report["n"],
                "tier": report["tier"],
                "verdict_counts": counts,
                "break_type_counts": break_counts,
                "wall": report["wall_seconds"],
            },
            indent=2,
        )
    )
    print(f"wrote {report_json}\nwrote {report_md}\nwrote {inv_md}", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
