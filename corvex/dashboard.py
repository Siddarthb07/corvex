"""Corvex Monitor — Orqis-style mission control for a loaded run.

Shows attack events, campaigns, correlator audit, and quarantine honesty.
Read-only. No checklist toggles. No fake live isolate. Sealed eval is secondary.
"""

from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from corvex import CORVEX_CONTAIN, __version__


def _public_path(path: Optional[Path], root: Path) -> Optional[str]:
    """Repo-relative path for snapshots — avoid leaking home-dir usernames."""
    if path is None:
        return None
    try:
        return Path(path).resolve().relative_to(Path(root).resolve()).as_posix()
    except ValueError:
        return Path(path).name


def _load_jsonl(path: Path, *, limit: int = 400) -> List[Dict[str, Any]]:
    if not path.exists():
        return []
    rows: List[Dict[str, Any]] = []
    for line in path.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        try:
            rows.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    return rows[-limit:]


def _resolve_run_dir(root: Path) -> Optional[Path]:
    env = os.environ.get("CORVEX_RUN_DIR")
    if env:
        p = Path(env)
        return p if p.exists() else None
    latest = root / "runs" / "latest"
    if latest.is_symlink() or latest.is_dir():
        return latest.resolve()
    if latest.is_file():
        target = Path(latest.read_text(encoding="utf-8").strip())
        return target if target.exists() else None
    runs = root / "runs"
    if not runs.is_dir():
        return None
    candidates = sorted(
        (p.parent for p in runs.glob("*/timeline.json")),
        key=lambda p: p.stat().st_mtime,
        reverse=True,
    )
    return candidates[0] if candidates else None


def _product_version() -> str:
    return str(__version__)


def _event_line(ev: Dict[str, Any]) -> Dict[str, Any]:
    """Normalize EventEnvelope OR live-lab flat bus rows into a log-row shape."""
    # Live Docker lab writes flat {kind, host_id, ...}; replay writes envelopes.
    if ev.get("payload_type"):
        payload = ev.get("payload") or {}
        ptype = str(ev.get("payload_type") or "event")
        host = str(ev.get("host_id") or "—")
        ts = str(ev.get("ts_utc") or "")
    else:
        kind = str(ev.get("kind") or "event")
        if kind in ("auth", "auth_blocked"):
            ptype = "auth"
            payload = {
                "user": ev.get("user"),
                "result": ev.get("result"),
                "src": ev.get("src"),
                "technique": ev.get("technique"),
            }
        elif kind == "net_conn":
            ptype = "net_conn"
            payload = {
                "dst_ip": ev.get("dst_ip"),
                "dst_port": ev.get("dst_port"),
                "bytes": ev.get("bytes"),
                "egress": ev.get("egress"),
                "technique": ev.get("technique"),
            }
        elif kind == "dns":
            ptype = "dns"
            payload = {
                "query": ev.get("query"),
                "qtype": ev.get("qtype"),
                "technique": ev.get("technique"),
            }
        else:
            # attacker_state / theatre noise — keep as INFO log line
            return {
                "id": str(ev.get("event_id") or ev.get("ts_utc") or kind),
                "ts": str(ev.get("ts_utc") or ""),
                "level": "INFO",
                "kind": kind.upper()[:12],
                "host": str(ev.get("host_id") or ev.get("target") or "—"),
                "producer": "lab",
                "line": json.dumps(
                    {k: v for k, v in ev.items() if k not in ("kind", "ts_utc")},
                    separators=(",", ":"),
                )[:160],
                "payload_type": kind,
            }
        host = str(ev.get("host_id") or ev.get("target") or "—")
        ts = str(ev.get("ts_utc") or "")

    level = "INFO"
    kind = ptype.upper()
    if ptype == "auth":
        level = "WARNING" if payload.get("result") == "success" else "INFO"
        if payload.get("result") == "blocked_by_corvex" or str(ev.get("kind")) == "auth_blocked":
            level = "ERROR"
            kind = "BLOCKED"
        else:
            kind = "AUTH"
        detail = (
            f"user={payload.get('user') or '?'} result={payload.get('result') or '?'}"
            f" src={payload.get('src') or '?'}"
        )
        technique = payload.get("technique")
    elif ptype == "net_conn":
        egress = bool(payload.get("egress"))
        nbytes = int(payload.get("bytes") or 0)
        if egress and 0 < nbytes <= 50_000:
            level = "WARNING"
            kind = "EXFIL"
        elif egress and nbytes > 50_000:
            level = "ERROR"
            kind = "BLOB"
        else:
            kind = "NET"
            level = "INFO"
        detail = (
            f"dst={payload.get('dst_ip') or '?'}:{payload.get('dst_port') or '?'}"
            f" bytes={nbytes} egress={str(egress).lower()}"
        )
        technique = payload.get("technique")
    elif ptype == "dns":
        level = "WARNING"
        kind = "DNS"
        detail = f"q={payload.get('query') or '?'} type={payload.get('qtype') or 'A'}"
        technique = payload.get("technique")
    else:
        detail = json.dumps(payload, separators=(",", ":"))[:160]
        technique = payload.get("technique") if isinstance(payload, dict) else None

    if technique:
        detail = f"{detail} · {technique}"

    return {
        "id": str(ev.get("event_id") or f"{host}-{ts}-{kind}"),
        "ts": ts,
        "level": level,
        "kind": kind,
        "host": host,
        "producer": str(ev.get("producer_id") or "lab"),
        "line": detail,
        "payload_type": ptype,
    }


def _audit_line(row: Dict[str, Any]) -> Dict[str, Any]:
    payload = row.get("payload") or {}
    kind = str(row.get("kind") or "audit")
    hosts = payload.get("hosts") or []
    return {
        "id": str(row.get("entry_hash") or kind)[:16],
        "ts": "",
        "level": "INFO",
        "kind": kind.upper().replace("_", " "),
        "host": ", ".join(str(h) for h in hosts[:6]) if hosts else "—",
        "producer": "correlator",
        "line": (
            f"{payload.get('campaign_id') or '—'} · "
            f"hosts={len(hosts)} stages={payload.get('stages') or '?'}"
        ),
        "payload_type": "audit",
    }


def collect_snapshot(root: Path) -> Dict[str, Any]:
    """Run-centric snapshot (schema_version 3) with activity feed."""
    root = Path(root)
    reports = root / "reports"
    held = _load(reports / "stageA_heldout.json") or {}
    train = _load(reports / "stageA_train.json") or {}
    claim = _load(reports / "claim_gates.json") or {}
    checklist = _load(reports / "security_l1_checklist.json") or {}
    gate_path = reports / "stageA-gate.txt"
    gate = gate_path.read_text(encoding="utf-8").strip() if gate_path.exists() else "UNKNOWN"

    l1_items = {
        k: bool(v)
        for k, v in checklist.items()
        if not str(k).startswith("_") and isinstance(v, bool)
    }
    l1_done = sum(1 for v in l1_items.values() if v)
    l1_total = max(1, len(l1_items)) if l1_items else 11

    hm = held.get("metrics") or {}

    def mget(block: str, field: str = "campaign_f1") -> Optional[float]:
        b = hm.get(block) or {}
        val = b.get(field)
        return float(val) if val is not None else None

    run_dir = _resolve_run_dir(root)
    timeline: Dict[str, Any] = {}
    campaigns: List[Dict[str, Any]] = []
    reconstruction: Dict[str, Any] = {}
    raw_events: List[Dict[str, Any]] = []
    raw_audit: List[Dict[str, Any]] = []
    if run_dir is not None:
        tl_path = run_dir / "timeline.json"
        if tl_path.exists():
            timeline = json.loads(tl_path.read_text(encoding="utf-8"))
            campaigns = list(timeline.get("campaigns") or [])
        recon_path = run_dir / "reconstruction.json"
        if recon_path.exists():
            reconstruction = json.loads(recon_path.read_text(encoding="utf-8"))
        raw_events = _load_jsonl(run_dir / "events.jsonl", limit=500)
        # Replay puts audit next to timeline; live Docker lab uses shared/corvex/
        raw_audit = _load_jsonl(run_dir / "audit.jsonl", limit=200)
        if not raw_audit:
            raw_audit = _load_jsonl(run_dir / "corvex" / "audit.jsonl", limit=200)
        # Live lab: campaigns live in corvex_state.json / campaigns.jsonl
        if not campaigns:
            state = _load(run_dir / "corvex_state.json") or {}
            live_camps = state.get("campaigns") or []
            if live_camps:
                campaigns = [
                    {
                        "campaign_id": c.get("campaign_id") or c.get("id") or "campaign",
                        "host_ids": c.get("host_ids") or c.get("hosts") or [],
                        "stages": c.get("stages") or [{"name": "live", "hosts": c.get("host_ids") or c.get("hosts") or []}],
                        "score": c.get("score"),
                    }
                    for c in live_camps
                    if isinstance(c, dict)
                ]
                timeline = {
                    "pack": "docker-live",
                    "campaigns": campaigns,
                    "source": "corvex_state.json",
                }
            else:
                for row in _load_jsonl(run_dir / "corvex" / "campaigns.jsonl", limit=50):
                    campaigns.append(
                        {
                            "campaign_id": row.get("campaign_id") or "campaign",
                            "host_ids": row.get("host_ids") or [],
                            "stages": row.get("stages") or [],
                            "score": row.get("score"),
                        }
                    )
                if campaigns:
                    timeline = {
                        "pack": "docker-live",
                        "campaigns": campaigns,
                        "source": "corvex/campaigns.jsonl",
                    }

    from corvex.contain.quarantine import resolve_quarantine_mode
    from corvex.prevention_log import load_prevention_log

    quarantine = resolve_quarantine_mode(root=root)
    prevention = load_prevention_log(root, limit=50)

    activity = [_event_line(ev) for ev in raw_events]
    activity = list(reversed(activity))
    audit_feed = list(reversed([_audit_line(a) for a in raw_audit]))

    events_path = (run_dir / "events.jsonl") if run_dir is not None else None
    events_mtime = None
    if events_path is not None and events_path.exists():
        events_mtime = datetime.fromtimestamp(
            events_path.stat().st_mtime, tz=timezone.utc
        ).strftime("%Y-%m-%dT%H:%M:%SZ")

    hosts_seen = sorted({str(ev.get("host_id")) for ev in raw_events if ev.get("host_id")})
    by_kind: Dict[str, int] = {}
    for row in activity:
        by_kind[row["kind"]] = by_kind.get(row["kind"], 0) + 1

    recon_status = reconstruction.get("aggregate_status") if reconstruction else None
    claim_allowed = bool(claim.get("claim_allowed")) if claim else False

    if not run_dir:
        hero = "NO_RUN"
        hero_detail = "No run loaded — corvex replay … or corvex dash --run-dir …"
    elif recon_status == "insufficient_evidence":
        hero = "REFUSE"
        hero_detail = "Insufficient evidence — will not invent a timeline"
    elif recon_status == "partial":
        hero = "PARTIAL"
        hero_detail = reconstruction.get("summary") or "Partial rebuild — gaps listed, not filled"
    elif campaigns:
        hero = "CAMPAIGN"
        hero_detail = f"{len(campaigns)} campaign(s) · {len(activity)} events in this run"
    elif activity:
        hero = "EMPTY"
        hero_detail = f"{len(activity)} events ingested — correlator found no campaign"
    else:
        hero = "EMPTY"
        hero_detail = "Run loaded but no events or campaigns"

    recon_by_id = {
        str(r.get("campaign_id")): r
        for r in (reconstruction.get("campaign_reconstructions") or [])
        if isinstance(r, dict)
    }

    return {
        "schema_version": 3,
        "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "product": {"name": "corvex", "version": _product_version()},
        "hero": {"status": hero, "detail": hero_detail},
        "kpis": {
            "events": len(activity),
            "hosts": len(hosts_seen),
            "campaigns": len(campaigns),
            "auth": by_kind.get("AUTH", 0),
            "exfil": by_kind.get("EXFIL", 0) + by_kind.get("BLOB", 0),
            "dns": by_kind.get("DNS", 0),
            "by_kind": by_kind,
        },
        "run": {
            "dir": _public_path(run_dir, root),
            "pack": timeline.get("pack"),
            "loaded": run_dir is not None,
            "ttu_seconds": timeline.get("ttu_seconds"),
            "campaigns": campaigns,
            "reconstruction": reconstruction,
            "hosts": hosts_seen,
        },
        "activity": activity,
        "audit": audit_feed,
        "prevention": prevention,
        "recon_by_id": recon_by_id,
        "feed": {
            "mode": "file_tail",
            "poll_ms": 2000,
            "events_path": _public_path(events_path, root),
            "events_mtime": events_mtime,
            "events_count": len(activity),
            "note": (
                "Polls events.jsonl + timeline.json on the loaded --run-dir. "
                "Not a WebSocket to the bus. New attack lines appear if that file grows "
                "(live lab / replay writing into the same run dir)."
            ),
        },
        "quarantine": {
            "mode": quarantine.get("mode"),
            "can_attempt": quarantine.get("can_attempt"),
            "live_executor": bool(quarantine.get("live_executor")),
            "corvex_contain": int(quarantine.get("corvex_contain") or CORVEX_CONTAIN or 0),
            "l1_complete": bool(quarantine.get("l1_complete")),
            "l1_pct": quarantine.get("l1_pct"),
            "message": quarantine.get("message"),
            "honesty": quarantine.get("honesty") or [],
        },
        "claim": {
            "allowed": claim_allowed,
            "language": claim.get("claim_language")
            or "lab / BYO campaign stitch only — claim locked",
        },
        "checklist": {
            "role": "engineering_notebook",
            "unlocks_contain": False,
            "done": l1_done,
            "total": len(l1_items) or l1_total,
            "items": l1_items,
            "note": "L1 evidence count only — does not unlock OS quarantine.",
        },
        "sealed_eval": {
            "binds_to_run": False,
            "label": "Sealed Day-0 heldout — not this run",
            "gate": gate,
            "heldout_pass": bool(held.get("pass")),
            "train_pass": bool(train.get("pass")),
            "care_vs_incumbent": held.get("care_vs_incumbent", "unproven"),
            "metrics": {
                "precision": mget("correlator", "precision"),
                "recall": mget("correlator", "recall"),
                "correlator_f1": mget("correlator"),
                "detector_only_f1": mget("detector_only"),
                "b1_f1": mget("b1"),
                "false_campaign_rate": mget("correlator", "false_campaign_rate"),
            },
        },
        "gate": gate,
        "version": _product_version(),
        "campaigns": campaigns,
        "reconstruction": reconstruction,
        "corvex_contain": int(quarantine.get("corvex_contain") or CORVEX_CONTAIN or 0),
        "stage_d": {
            "checklist_done": l1_done,
            "checklist_total": len(l1_items) or l1_total,
            "checklist_pct": round(100.0 * l1_done / max(1, len(l1_items) or l1_total), 1),
            "items": l1_items,
            "live_contain": False,
        },
    }


def render_html(snap: Dict[str, Any]) -> str:
    """Run-feed shell. Paint from embedded snapshot + /api/snapshot poll."""
    boot = json.dumps(snap, ensure_ascii=False).replace("<", "\\u003c")
    ver = str((snap.get("product") or {}).get("version") or snap.get("version") or "")
    template = Path(__file__).resolve().parent / "dash_static" / "monitor.html"
    html = template.read_text(encoding="utf-8")
    return html.replace("__BOOT__", boot).replace("__VER__", ver)



def write_dashboard(root: Path, out: Optional[Path] = None) -> Path:
    snap = collect_snapshot(root)
    out = Path(out or (Path(root) / "reports" / "dashboard" / "index.html"))
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(render_html(snap), encoding="utf-8")
    (out.parent / "snapshot.json").write_text(json.dumps(snap, indent=2), encoding="utf-8")
    return out
