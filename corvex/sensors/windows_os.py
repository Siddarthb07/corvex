"""Windows OS-wide observe-only collector (Stage B gated).

Sources:
- fixture / JSONL export (CI + stranger-friendly)
- wevtutil poll when available on Windows (best-effort; degrades honestly)

Writes signed envelopes to ``<run-dir>/events.jsonl``, bookmark under
``<run-dir>/sensor_bookmarks.json``, optional correlator refresh to timeline.json.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Mapping, Optional, Sequence, Set

from corvex.adapters.os_wide import (
    DEFAULT_ALLOWLIST,
    adapt_os_wide_records,
    load_allowlist,
)
from corvex.audit import AuditLog
from corvex.auth import Enrollment
from corvex.correlator import Correlator, CorrelatorConfig
from corvex.envelope import EventEnvelope, sign_envelope
from corvex.lab_enroll import DEMO_HOSTS
from corvex.stage_b import StageBGateError, require_stage_b
from corvex.store import CampaignStore

# Official log names for wevtutil (when channel present)
WEVT_LOGS = {
    "security": "Security",
    "sysmon": "Microsoft-Windows-Sysmon/Operational",
    "firewall": "Microsoft-Windows-Windows Firewall With Advanced Security/Firewall",
    "powershell": "Microsoft-Windows-PowerShell/Operational",
}


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _load_bookmarks(path: Path) -> Dict[str, Any]:
    if not path.exists():
        return {"channels": {}}
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return {"channels": {}}


def _save_bookmarks(path: Path, data: Mapping[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(dict(data), indent=2) + "\n", encoding="utf-8")


class RateLimiter:
    """Soft per-second cap; returns True if the event should be dropped."""

    def __init__(self, max_per_sec: float) -> None:
        self.max_per_sec = float(max_per_sec)
        self._window_start = time.monotonic()
        self._count = 0
        self.dropped = 0

    def should_drop(self) -> bool:
        if self.max_per_sec <= 0:
            return False
        now = time.monotonic()
        if now - self._window_start >= 1.0:
            self._window_start = now
            self._count = 0
        if self._count >= self.max_per_sec:
            self.dropped += 1
            return True
        self._count += 1
        return False


def _wevtutil_available() -> bool:
    return shutil.which("wevtutil") is not None


def poll_wevtutil_channel(
    channel: str,
    *,
    allow_ids: Set[str],
    max_events: int = 40,
    min_record_id: Optional[int] = None,
) -> Dict[str, Any]:
    """Best-effort wevtutil JSON query with explicit degrade reasons.

    Returns ``{"records": [...], "ok": bool, "reason": str|None, "max_record_id": int|None}``.
    """
    log_name = WEVT_LOGS.get(channel)
    if not log_name:
        return {"records": [], "ok": False, "reason": "unknown_channel", "max_record_id": None}
    if not _wevtutil_available():
        return {"records": [], "ok": False, "reason": "no_wevtutil", "max_record_id": None}
    if not allow_ids:
        return {"records": [], "ok": False, "reason": "empty_allowlist", "max_record_id": None}
    id_clause = " or ".join(f"EventID={i}" for i in sorted(allow_ids))
    query = f"*[System[({id_clause})]]"
    if min_record_id is not None and min_record_id > 0:
        # Prefer events after last bookmark when RecordId is available
        query = (
            f"*[System[({id_clause}) and EventRecordID > {int(min_record_id)}]]"
        )
    cmd = [
        "wevtutil",
        "qe",
        log_name,
        f"/q:{query}",
        "/f:json",
        f"/c:{max_events}",
        "/rd:true",
    ]
    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=20,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        return {
            "records": [],
            "ok": False,
            "reason": f"wevtutil_error:{type(exc).__name__}",
            "max_record_id": None,
        }
    err = (proc.stderr or "").lower()
    if proc.returncode != 0:
        reason = "channel_missing_or_denied"
        if "access" in err or "denied" in err or "privilege" in err:
            reason = "access_denied_need_elevation"
        elif "not found" in err or "cannot find" in err:
            reason = "channel_missing"
        return {"records": [], "ok": False, "reason": reason, "max_record_id": None}
    if not proc.stdout.strip():
        return {"records": [], "ok": True, "reason": "zero_hits", "max_record_id": min_record_id}

    raw = proc.stdout.strip()
    records: List[Dict[str, Any]] = []

    def _ingest(rec: Dict[str, Any]) -> None:
        rec = dict(rec)
        rec["channel"] = channel
        records.append(rec)

    try:
        data = json.loads(raw)
        if isinstance(data, list):
            for rec in data:
                if isinstance(rec, dict):
                    _ingest(rec)
        elif isinstance(data, dict):
            _ingest(data)
    except json.JSONDecodeError:
        chunk = ""
        for line in raw.splitlines():
            chunk += line
            if line.strip().endswith("}"):
                try:
                    rec = json.loads(chunk)
                    if isinstance(rec, dict):
                        _ingest(rec)
                except json.JSONDecodeError:
                    pass
                chunk = ""

    max_rid: Optional[int] = min_record_id
    for rec in records:
        rid = rec.get("RecordId") or rec.get("EventRecordID")
        try:
            rid_i = int(rid) if rid is not None else None
        except (TypeError, ValueError):
            rid_i = None
        if rid_i is not None and (max_rid is None or rid_i > max_rid):
            max_rid = rid_i
    return {
        "records": records,
        "ok": True,
        "reason": None if records else "zero_hits",
        "max_record_id": max_rid,
    }


def sign_unsigned(
    unsigned: Sequence[Mapping[str, Any]],
    enrollment: Enrollment,
    *,
    host_override: Optional[str] = None,
    producer_override: Optional[str] = None,
    demo_hosts: Optional[Mapping[str, str]] = None,
) -> List[EventEnvelope]:
    hosts = dict(demo_hosts or DEMO_HOSTS)
    out: List[EventEnvelope] = []
    for rec in unsigned:
        host_id = host_override or str(rec["host_id"])
        if host_id not in hosts:
            # keep as-is if enrollment already knows it via producer in rec
            host_id = host_override or str(rec["host_id"])
        prod = producer_override or hosts.get(host_id) or str(rec["producer_id"])
        if host_id in hosts:
            prod = hosts[host_id]
        secret = enrollment.require(prod, host_id)
        out.append(
            sign_envelope(
                producer_id=prod,
                host_id=host_id,
                payload_type=str(rec["payload_type"]),
                payload=dict(rec["payload"]),
                secret=secret,
                event_id=str(rec["event_id"]),
                ts_utc=str(rec["ts_utc"]),
                nonce=str(rec["nonce"]),
            )
        )
    return out


def append_events(path: Path, envelopes: Sequence[EventEnvelope]) -> int:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as fh:
        for env in envelopes:
            fh.write(json.dumps(env.to_dict(), separators=(",", ":")) + "\n")
    return len(envelopes)


def recompute_run(run_dir: Path, enrollment: Enrollment) -> Dict[str, Any]:
    """Load events.jsonl, adapt flat lab rows, verify HMAC, rewrite timeline.json.

    Flat Docker-lab rows are adapted and re-signed with ``enrollment`` (offline lab
    replay — not remote provenance). Bad or unverifiable HMACs are dropped.
    Campaigns come only from the correlator — never copied from theatre state.
    """
    from corvex.adapters.lab_flat import try_adapt_row
    from corvex.auth import AuthError
    from corvex.envelope import EventEnvelope, verify_envelope

    run_dir = Path(run_dir)
    events_path = run_dir / "events.jsonl"
    if not events_path.exists():
        return {"campaigns": 0, "events": 0}
    envs: List[EventEnvelope] = []
    adapted = 0
    skipped = 0
    rejected_hmac = 0
    seq = 0
    for line in events_path.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        try:
            rec = json.loads(line)
        except json.JSONDecodeError:
            skipped += 1
            continue
        seq += 1
        env, status = try_adapt_row(rec, enrollment, seq=seq)
        if env is None:
            skipped += 1
            continue
        if status == "adapted":
            adapted += 1
        try:
            secret = enrollment.require(env.producer_id, env.host_id)
        except AuthError:
            rejected_hmac += 1
            continue
        if not verify_envelope(env, secret):
            rejected_hmac += 1
            continue
        envs.append(env)
    store_path = run_dir / "campaigns.jsonl"
    if store_path.exists():
        store_path.write_text("", encoding="utf-8")
    store = CampaignStore(store_path)
    audit = AuditLog(run_dir / "audit.jsonl")
    corr = Correlator(store, audit, config=CorrelatorConfig())
    t0 = time.perf_counter()
    if envs:
        corr.ingest(envs)
    ttu = time.perf_counter() - t0
    camps = [c.to_dict() for c in store.all()]
    timeline = {
        "pack": "pc-and-lab-fusion",
        "ttu_seconds": ttu,
        "campaigns": camps,
        "sensor": "windows-os-wide+docker-lab",
        "mode": "offline_lab_replay",
        "generated_at": _now(),
        "envelope_events": len(envs),
        "flat_lab_events_adapted": adapted,
        "rows_skipped": skipped,
        "hmac_rejected": rejected_hmac,
    }
    (run_dir / "timeline.json").write_text(
        json.dumps(timeline, indent=2) + "\n", encoding="utf-8"
    )
    try:
        from corvex.reconstruct import write_reconstruction

        write_reconstruction(run_dir)
    except Exception:
        pass
    return {
        "campaigns": len(camps),
        "events": len(envs),
        "flat_lab_adapted": adapted,
        "rows_skipped": skipped,
        "hmac_rejected": rejected_hmac,
        "ttu_seconds": ttu,
    }


def run_sensor_windows(
    *,
    run_dir: Path,
    enrollment: Enrollment,
    channels: Sequence[str],
    allowlist_path: Optional[Path] = None,
    fixture: Optional[Path] = None,
    host_id: Optional[str] = None,
    producer_id: Optional[str] = None,
    host_map: Optional[Mapping[str, str]] = None,
    follow: bool = False,
    once: bool = True,
    max_per_sec: float = 50.0,
    poll_seconds: float = 2.0,
    max_cycles: Optional[int] = None,
    recompute_every: int = 1,
    require_live: bool = False,
) -> Dict[str, Any]:
    """Main Stage B sensor loop. ``once`` drains one cycle; ``follow`` polls."""
    require_stage_b()
    if require_live and fixture is not None:
        raise ValueError("--require-live cannot be combined with --fixture")
    run_dir = Path(run_dir)
    run_dir.mkdir(parents=True, exist_ok=True)
    events_path = run_dir / "events.jsonl"
    bookmark_path = run_dir / "sensor_bookmarks.json"
    audit_path = run_dir / "sensor_audit.jsonl"
    allow = load_allowlist(allowlist_path)
    chans = [c.strip().lower() for c in channels if c.strip()]
    limiter = RateLimiter(max_per_sec)
    bookmarks = _load_bookmarks(bookmark_path)
    channel_bookmarks: Dict[str, Any] = dict(bookmarks.get("channels") or {})
    stats: Dict[str, Any] = {
        "adapted": 0,
        "skipped": 0,
        "published": 0,
        "rate_limited": 0,
        "cycles": 0,
        "channels": {},
        "channel_health": {},
        "source": "fixture" if fixture else "wevtutil",
        "fixture_seed": bool(fixture),
        "honesty": (
            "Observe-only OS-wide Windows sensor. No firewall/EDR mutation. "
            "Missing channels degrade; Sysmon absence is normal. "
            "Fixture path is CI-only — not live Event Log."
        ),
        "degraded": [],
    }

    def _one_cycle(cycle: int) -> int:
        records: List[Dict[str, Any]] = []
        if fixture is not None:
            from corvex.adapters.os_wide import iter_os_wide_records

            # On follow+fixture, only emit on first cycle unless file grows — for tests use once
            if cycle == 0 or not follow:
                for rec in iter_os_wide_records(Path(fixture)):
                    records.append(dict(rec))
            else:
                # fixture follow: no-op after first (live path uses wevtutil)
                return 0
        else:
            for ch in chans:
                last_rid = channel_bookmarks.get(ch)
                try:
                    min_rid = int(last_rid) if last_rid is not None else None
                except (TypeError, ValueError):
                    min_rid = None
                poll = poll_wevtutil_channel(
                    ch, allow_ids=allow.get(ch, set()), min_record_id=min_rid
                )
                health = {
                    "ok": bool(poll.get("ok")),
                    "reason": poll.get("reason"),
                    "hits": len(poll.get("records") or []),
                }
                stats["channel_health"][ch] = health
                if not poll.get("ok") or poll.get("reason") in {
                    "channel_missing",
                    "access_denied_need_elevation",
                    "no_wevtutil",
                    "channel_missing_or_denied",
                }:
                    if ch not in stats["degraded"]:
                        stats["degraded"].append(ch)
                if poll.get("max_record_id") is not None:
                    channel_bookmarks[ch] = poll["max_record_id"]
                records.extend(list(poll.get("records") or []))
            bookmarks["channels"] = channel_bookmarks

        # Bookmark dedupe: skip event_ids already seen for this exporter identity
        exporter = host_id or "default"
        seen_all = bookmarks.get("seen_by_exporter") or {}
        seen: Set[str] = set(seen_all.get(exporter) or [])
        fresh: List[Dict[str, Any]] = []
        for rec in records:
            key = (
                f"{rec.get('channel')}|{rec.get('EventID')}|{rec.get('Computer')}|"
                f"{rec.get('TimeCreated')}|{rec.get('RecordId') or rec.get('EventRecordID')}"
            )
            if key in seen:
                continue
            seen.add(key)
            fresh.append(rec)
        seen_all[exporter] = list(seen)[-5000:]
        bookmarks["seen_by_exporter"] = seen_all
        bookmarks["updated_at"] = _now()
        _save_bookmarks(bookmark_path, bookmarks)

        demo = dict(DEMO_HOSTS)
        default_host = host_id or "host-a"
        prod = producer_id or demo.get(default_host, "prod-a")
        unsigned, st = adapt_os_wide_records(
            fresh,
            producer_id=prod,
            default_host=default_host,
            host_map=host_map,
            allowlist=allow,
            channels=chans,
            id_prefix=f"osw{cycle}",
        )
        stats["adapted"] += int(st.get("adapted", 0))
        stats["skipped"] += int(st.get("skipped", 0))
        for k, v in (st.get("by_channel") or {}).items():
            stats["channels"][k] = int(stats["channels"].get(k, 0)) + int(v)

        kept = []
        for rec in unsigned:
            if limiter.should_drop():
                continue
            # Force host/producer overrides for multi-host exporter shape
            if host_id:
                rec = dict(rec)
                rec["host_id"] = host_id
                rec["producer_id"] = prod
            kept.append(rec)
        stats["rate_limited"] = limiter.dropped
        if limiter.dropped:
            with audit_path.open("a", encoding="utf-8") as af:
                af.write(
                    json.dumps(
                        {
                            "ts": _now(),
                            "kind": "sensor_rate_limited",
                            "dropped": limiter.dropped,
                            "max_per_sec": max_per_sec,
                        }
                    )
                    + "\n"
                )

        envs = sign_unsigned(
            kept,
            enrollment,
            host_override=host_id,
            producer_override=producer_id,
        )
        n = append_events(events_path, envs)
        stats["published"] += n
        return n

    cycles = 0
    while True:
        published = _one_cycle(cycles)
        cycles += 1
        stats["cycles"] = cycles
        if recompute_every > 0 and cycles % recompute_every == 0:
            stats["timeline"] = recompute_run(run_dir, enrollment)
        if once and not follow:
            break
        if max_cycles is not None and cycles >= max_cycles:
            break
        if follow:
            time.sleep(poll_seconds)
        else:
            break

    if require_live:
        health = stats.get("channel_health") or {}
        live_hits = sum(int(h.get("hits") or 0) for h in health.values())
        if stats["source"] != "wevtutil" or (stats["published"] == 0 and live_hits == 0):
            stats["require_live_failed"] = True
            stats["require_live_note"] = (
                "No live Event Log hits. Elevate PowerShell / enable channels, "
                "or drop --require-live for fixture CI."
            )

    (run_dir / "sensor_status.json").write_text(
        json.dumps(stats, indent=2) + "\n", encoding="utf-8"
    )
    return stats
