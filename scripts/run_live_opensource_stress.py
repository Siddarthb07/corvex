#!/usr/bin/env python3
"""Live laptop stress: keep Corvex correlator+dash running while OTRF attacks stream in.

Does **not** execute Empire/Covenant/malware on the host. Replays externally authored
OTRF/Security-Datasets captures into a live run dir (observe/correlate). Optional
``sensor-windows --once`` samples concurrent laptop telemetry (Stage B observe-only).

  python scripts/fetch_opensource_corpora.py --live-stress
  python scripts/run_live_opensource_stress.py
  python scripts/run_live_opensource_stress.py --limit 20 --dash

claim_allowed stays false. Mode label: offline_lab_replay_into_live_correlator.
"""

from __future__ import annotations

import argparse
import json
import re
import shutil
import subprocess
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
from corvex.auth import (  # noqa: E402
    Enrollment,
    generate_lab_enrollment,
    load_enrollment,
    save_enrollment,
)
import secrets as _secrets  # noqa: E402
from corvex.correlator import Correlator, CorrelatorConfig  # noqa: E402
from corvex.envelope import EventEnvelope, sign_envelope  # noqa: E402
from corvex.reconstruct import write_reconstruction  # noqa: E402
from corvex.store import CampaignStore  # noqa: E402

OSS_ROOT = ROOT / "labs" / "opensource"
CATALOG = OSS_ROOT / "catalog.json"
LIVE = ROOT / "runs" / "live-oss-stress"
REPORT_JSON = ROOT / "reports" / "live_opensource_stress.json"
REPORT_MD = ROOT / "reports" / "live_opensource_stress.md"


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
        id_prefix=f"live-{corpus.name}",
    )
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
        row["producer_id"] = f"prod-live-{canon}"
        payload = dict(row.get("payload") or {})
        src = str(payload.get("src") or "")
        if src:
            slug = _slug_host(src)
            if src.lower() in hmap:
                payload["src"] = hmap[src.lower()]
            elif slug in set(hmap.values()):
                payload["src"] = slug
            row["payload"] = payload
        remapped.append(row)
    stats["host_map"] = hmap
    stats["n_unsigned"] = len(remapped)
    return remapped, stats


def _ensure_enrollment(hosts: Sequence[str], path: Path) -> Enrollment:
    """Grow enrollment 1:1 without rotating secrets for already-signed hosts."""
    wanted = {h: f"prod-live-{h}" for h in hosts}
    if path.is_file():
        enr = load_enrollment(path)
        host_map = {h: set(v) for h, v in enr.to_public_dict().items()}
        secrets_map = dict(enr._secrets)
        for host_id, producer_id in wanted.items():
            # producer -> hosts is inverted in Enrollment
            if producer_id in host_map and host_id in host_map[producer_id]:
                continue
            if producer_id not in host_map:
                host_map[producer_id] = {host_id}
                secrets_map[producer_id] = _secrets.token_bytes(32)
            else:
                host_map[producer_id].add(host_id)
        enr = Enrollment(host_map, secrets_map)
        save_enrollment(path, enr)
        return enr
    enr = generate_lab_enrollment(wanted)
    save_enrollment(path, enr)
    return enr


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


def _load_all_events(path: Path) -> List[EventEnvelope]:
    if not path.is_file():
        return []
    out: List[EventEnvelope] = []
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line:
            continue
        out.append(EventEnvelope.from_dict(json.loads(line)))
    return out


def _append_events(path: Path, events: Sequence[EventEnvelope]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as fh:
        for env in events:
            fh.write(json.dumps(env.to_dict(), separators=(",", ":")) + "\n")


def _recompute(run_dir: Path, enrollment: Enrollment) -> Dict[str, Any]:
    events_path = run_dir / "events.jsonl"
    events = _load_all_events(events_path)
    # Fresh store each recompute (correlator is batch ingest)
    camps_path = run_dir / "campaigns.jsonl"
    if camps_path.exists():
        camps_path.unlink()
    audit_path = run_dir / "audit.jsonl"
    if audit_path.exists():
        audit_path.unlink()
    store = CampaignStore(camps_path)
    audit = AuditLog(audit_path)
    corr = Correlator(store, audit, config=CorrelatorConfig(), enrollment=enrollment)
    corr.ingest(list(events))
    camps = [c.to_dict() for c in store.all()]
    timeline = {
        "pack": "live-opensource-stress",
        "mode": "offline_lab_replay_into_live_correlator",
        "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "envelope_events": len(events),
        "campaigns": camps,
        "honesty": (
            "OTRF captures replayed into a live Corvex process on this laptop. "
            "Not live malware execution. claim_allowed=false."
        ),
    }
    (run_dir / "timeline.json").write_text(
        json.dumps(timeline, indent=2) + "\n", encoding="utf-8"
    )
    write_reconstruction(run_dir, quarantine_mode="dry_run")
    try:
        from corvex.dashboard import write_dashboard

        write_dashboard(run_dir)
    except Exception as exc:  # noqa: BLE001
        timeline["dashboard_error"] = str(exc)
    multi = [c for c in camps if len(c.get("host_ids") or []) >= 2]
    return {
        "n_events": len(events),
        "n_campaigns": len(camps),
        "n_multi_host": len(multi),
        "multi_hosts": sorted(
            {h for c in multi for h in (c.get("host_ids") or [])}
        ),
        "top_campaigns": sorted(
            [
                {
                    "id": c.get("campaign_id"),
                    "n_hosts": len(c.get("host_ids") or []),
                    "hosts": c.get("host_ids"),
                    "score": c.get("score"),
                }
                for c in camps
            ],
            key=lambda r: (r["n_hosts"], float(r.get("score") or 0)),
            reverse=True,
        )[:8],
    }


def _catch_label(
    *,
    n_hosts_batch: int,
    snapshot_before: Mapping[str, Any],
    snapshot_after: Mapping[str, Any],
) -> Dict[str, Any]:
    """Did the live correlator pick up new multi-host structure from this attack?"""
    before_multi = int(snapshot_before.get("n_multi_host") or 0)
    after_multi = int(snapshot_after.get("n_multi_host") or 0)
    before_hosts = set(snapshot_before.get("multi_hosts") or [])
    after_hosts = set(snapshot_after.get("multi_hosts") or [])
    new_bridge = sorted(after_hosts - before_hosts)
    multi_delta = after_multi - before_multi
    if n_hosts_batch < 2:
        label = "SINGLE_HOST_BATCH"
        caught = after_multi > 0 or int(snapshot_after.get("n_campaigns") or 0) > int(
            snapshot_before.get("n_campaigns") or 0
        )
        detail = "batch has <2 hosts — fusion not required; campaign growth counts as soft catch"
    elif multi_delta > 0 or new_bridge:
        label = "CAUGHT"
        caught = True
        detail = (
            f"multi-host camps {before_multi}->{after_multi}; "
            f"new bridge hosts={new_bridge or '—'}"
        )
    elif after_multi > 0:
        label = "ALREADY_COVERED"
        caught = True
        detail = "attack hosts already inside existing multi-host campaigns"
    elif int(snapshot_after.get("n_campaigns") or 0) > int(
        snapshot_before.get("n_campaigns") or 0
    ):
        label = "PARTIAL"
        caught = False
        detail = "single-host campaigns formed; no multi-host bridge"
    else:
        label = "MISS"
        caught = False
        detail = "no new campaigns after inject"
    return {"label": label, "caught": caught, "detail": detail, "multi_delta": multi_delta}


def _start_dash(run_dir: Path, port: int) -> Optional[subprocess.Popen]:
    cmd = [
        sys.executable,
        "-m",
        "corvex",
        "dash",
        "--run-dir",
        str(run_dir),
        "--host",
        "127.0.0.1",
        "--port",
        str(port),
        "--no-open",
    ]
    try:
        import shutil as _sh

        if _sh.which("corvex"):
            cmd = [
                "corvex",
                "dash",
                "--run-dir",
                str(run_dir),
                "--host",
                "127.0.0.1",
                "--port",
                str(port),
                "--no-open",
            ]
    except Exception:
        pass
    print(f"[live] starting dash: {' '.join(cmd)}", flush=True)
    try:
        return subprocess.Popen(
            cmd,
            cwd=str(ROOT),
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
    except Exception as exc:  # noqa: BLE001
        print(f"[live] dash start failed: {exc}", flush=True)
        return None


def _sensor_once(run_dir: Path) -> Dict[str, Any]:
    """Best-effort laptop observe sample — degrade honestly if wevtutil blocked."""
    dest = run_dir / "pc-sensor"
    dest.mkdir(parents=True, exist_ok=True)
    cmd = [
        sys.executable,
        "-m",
        "corvex",
        "sensor-windows",
        "--run-dir",
        str(dest),
    ]
    print(f"[live] sensor-windows once -> {dest}", flush=True)
    try:
        proc = subprocess.run(
            cmd,
            cwd=str(ROOT),
            capture_output=True,
            text=True,
            timeout=120,
        )
        return {
            "ok": proc.returncode == 0,
            "returncode": proc.returncode,
            "stdout_tail": (proc.stdout or "")[-500:],
            "stderr_tail": (proc.stderr or "")[-500:],
        }
    except Exception as exc:  # noqa: BLE001
        return {"ok": False, "error": str(exc)}


def write_report(report: Mapping[str, Any]) -> None:
    rows = report.get("attacks") or []
    lines = [
        "# Live open-source stress (laptop)",
        "",
        "Corvex correlator + dash kept running while OTRF attack captures were "
        "**replayed** into `runs/live-oss-stress/`. Not live malware execution.",
        f"**claim_allowed={report.get('claim_allowed')}** · mode=`{report.get('mode')}`",
        "",
        f"- Attacks streamed: **{report.get('n')}**",
        f"- Wall: **{report.get('wall_seconds')}s**",
        f"- Catch rollup: `{json.dumps(report.get('catch_counts') or {})}`",
        f"- Dash: `{report.get('dash_url') or '—'}`",
        f"- Sensor sample: `{json.dumps(report.get('sensor_once') or {})[:200]}`",
        "",
        "## Scoreboard",
        "",
        "| # | Attack | Tool | Family | Hosts | Events | Catch | Detail |",
        "|---|--------|------|--------|-------|--------|-------|--------|",
    ]
    for i, r in enumerate(rows, 1):
        catch = (r.get("catch") or {}).get("label") or "?"
        detail = ((r.get("catch") or {}).get("detail") or "")[:70]
        lines.append(
            f"| {i} | {(r.get('attack') or r.get('id') or '')[:42]} | "
            f"{r.get('tool') or '—'} | {r.get('family') or '—'} | "
            f"{r.get('n_hosts_batch')} | {r.get('n_events_batch')} | "
            f"**{catch}** | {detail} |"
        )
    lines.extend(
        [
            "",
            "## Honesty",
            "",
            "- Authorship: OTRF / MITRE — external captures.",
            "- Laptop role: correlator process + optional Stage B sensor sample.",
            "- Quarantine: dry_run only (`CORVEX_CONTAIN=0`).",
            "- Does **not** prove enterprise detection or claim_allowed.",
            "",
            "## Reproduce",
            "",
            "```bash",
            "python scripts/fetch_opensource_corpora.py --live-stress",
            "python scripts/run_live_opensource_stress.py --dash",
            "```",
            "",
        ]
    )
    REPORT_MD.write_text("\n".join(lines) + "\n", encoding="utf-8")


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--limit", type=int, default=0, help="Max attacks (0=all live_stress present)")
    ap.add_argument("--dash", action="store_true", help="Start corvex dash in background")
    ap.add_argument("--port", type=int, default=8765)
    ap.add_argument("--pause", type=float, default=0.4, help="Seconds between attack injects")
    ap.add_argument("--sensor", action="store_true", help="Also run sensor-windows once")
    ap.add_argument("--reset", action="store_true", default=True)
    ap.add_argument("--no-reset", action="store_true")
    args = ap.parse_args()

    catalog = {
        str(e["id"]): e
        for e in (json.loads(CATALOG.read_text(encoding="utf-8")).get("corpora") or [])
        if e.get("id")
    }
    live_ids = [cid for cid, e in catalog.items() if e.get("live_stress")]
    corpora = [
        OSS_ROOT / cid
        for cid in live_ids
        if (OSS_ROOT / cid / "raw").is_dir() and _discover_raw(OSS_ROOT / cid)
    ]
    # Prefer multi-host / aggressive first for catch signal
    def _rank(p: Path) -> tuple:
        e = catalog.get(p.name) or {}
        return (
            0 if e.get("aggressive") else 1,
            0 if str(e.get("family") or "").startswith("compound") else 1,
            0 if e.get("family") == "lateral_movement" else 1,
            p.name,
        )

    corpora = sorted(corpora, key=_rank)
    if args.limit and args.limit > 0:
        corpora = corpora[: args.limit]
    if not corpora:
        print(
            "No live_stress corpora on disk. Run: python scripts/fetch_opensource_corpora.py --live-stress",
            file=sys.stderr,
        )
        return 2

    if args.no_reset:
        args.reset = False
    if args.reset and LIVE.exists():
        shutil.rmtree(LIVE, ignore_errors=True)
    LIVE.mkdir(parents=True, exist_ok=True)
    (LIVE / "pc-sensor").mkdir(parents=True, exist_ok=True)

    dash_proc: Optional[subprocess.Popen] = None
    dash_url = None
    if args.dash:
        dash_proc = _start_dash(LIVE, args.port)
        dash_url = f"http://127.0.0.1:{args.port}/"
        time.sleep(1.5)

    sensor_once: Dict[str, Any] = {}
    if args.sensor:
        sensor_once = _sensor_once(LIVE)

    all_hosts: Set[str] = set()
    enrollment_path = LIVE / "enrollment.json"
    events_path = LIVE / "events.jsonl"
    if events_path.exists() and args.reset:
        events_path.unlink()

    rows: List[Dict[str, Any]] = []
    t0 = time.perf_counter()
    snap = {"n_events": 0, "n_campaigns": 0, "n_multi_host": 0, "multi_hosts": []}

    print(f"[live] streaming {len(corpora)} OTRF attacks into {LIVE}", flush=True)
    for i, corpus in enumerate(corpora, 1):
        entry = catalog.get(corpus.name) or {}
        print(
            f"=== [{i}/{len(corpora)}] {corpus.name} — {entry.get('attack') or ''} ===",
            flush=True,
        )
        try:
            unsigned, adapt_stats = _convert(corpus)
        except Exception as exc:  # noqa: BLE001
            rows.append(
                {
                    "id": corpus.name,
                    "ok": False,
                    "error": str(exc),
                    "attack": entry.get("attack"),
                    "tool": entry.get("tool"),
                    "family": entry.get("family"),
                    "catch": {"label": "ERROR", "caught": False, "detail": str(exc)},
                }
            )
            continue
        batch_hosts = sorted({str(e["host_id"]) for e in unsigned})
        all_hosts |= set(batch_hosts)
        enrollment = _ensure_enrollment(sorted(all_hosts), enrollment_path)
        # Re-sign needs producers for all hosts in this batch
        try:
            signed = _sign(unsigned, enrollment)
        except Exception as exc:  # noqa: BLE001
            # Expand enrollment and retry
            enrollment = _ensure_enrollment(sorted(all_hosts), enrollment_path)
            signed = _sign(unsigned, enrollment)

        before = dict(snap)
        _append_events(events_path, signed)
        snap = _recompute(LIVE, enrollment)
        catch = _catch_label(
            n_hosts_batch=len(batch_hosts),
            snapshot_before=before,
            snapshot_after=snap,
        )
        row = {
            "id": corpus.name,
            "ok": True,
            "attack": entry.get("attack"),
            "tool": entry.get("tool"),
            "family": entry.get("family"),
            "techniques": entry.get("techniques") or [],
            "n_hosts_batch": len(batch_hosts),
            "hosts_batch": batch_hosts,
            "n_events_batch": len(signed),
            "adapt_skip_rate": (adapt_stats or {}).get("skip_rate")
            if isinstance(adapt_stats, dict)
            else None,
            "live_after": {
                "n_events": snap.get("n_events"),
                "n_campaigns": snap.get("n_campaigns"),
                "n_multi_host": snap.get("n_multi_host"),
                "multi_hosts": snap.get("multi_hosts"),
            },
            "catch": catch,
        }
        rows.append(row)
        print(
            f"  -> {catch['label']} hosts={len(batch_hosts)} events={len(signed)} "
            f"live_multi={snap.get('n_multi_host')} detail={catch['detail']}",
            flush=True,
        )
        if args.pause > 0:
            time.sleep(args.pause)

    catch_counts: Dict[str, int] = {}
    for r in rows:
        lab = (r.get("catch") or {}).get("label") or "ERROR"
        catch_counts[lab] = catch_counts.get(lab, 0) + 1

    report = {
        "test": "Live open-source OTRF stress on laptop",
        "mode": "offline_lab_replay_into_live_correlator",
        "generated_utc": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "claim_allowed": False,
        "n": len(rows),
        "wall_seconds": round(time.perf_counter() - t0, 4),
        "run_dir": str(LIVE),
        "dash_url": dash_url,
        "dash_running": bool(dash_proc and dash_proc.poll() is None),
        "sensor_once": sensor_once,
        "final_snapshot": snap,
        "catch_counts": catch_counts,
        "attacks": rows,
        "honesty": (
            "OTRF captures streamed into a live Corvex correlator on this Windows laptop. "
            "Not executing attacker tooling. Not enterprise validation. claim_allowed=false."
        ),
    }
    REPORT_JSON.write_text(json.dumps(report, indent=2, default=str) + "\n", encoding="utf-8")
    write_report(report)
    print(json.dumps({"n": report["n"], "catch_counts": catch_counts, "dash": dash_url}, indent=2))
    print(f"wrote {REPORT_JSON}\nwrote {REPORT_MD}", flush=True)
    if dash_proc and dash_proc.poll() is None:
        print(
            f"[live] dash still running at {dash_url} (pid={dash_proc.pid}) — stop manually when done",
            flush=True,
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
