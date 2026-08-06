"""macOS OS-wide / network observe-only collector (Stage B gated).

Sources:
- fixture / JSONL export (CI)
- live ``lsof`` TCP established flows (primary network channel; no root required
  for the calling user's processes)
- best-effort ``log show`` for auth/dns (degrades honestly when sandboxed /
  permission denied)
- optional ``ps`` process sample
- optional ``pfctl`` state (often needs root — degrades)

Writes signed envelopes to ``<run-dir>/events.jsonl``, bookmarks under
``<run-dir>/sensor_bookmarks.json``, optional correlator refresh to timeline.json.

Multi-host: same binary on each Mac with ``--host-id`` / ``--producer`` into one
shared run directory (network share / scp merge).
"""

from __future__ import annotations

import json
import platform
import shutil
import subprocess
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Mapping, Optional, Sequence, Set

from corvex.adapters.macos import (
    adapt_macos_records,
    iter_macos_records,
    load_macos_allowlist,
    parse_lsof_network,
)
from corvex.auth import Enrollment
from corvex.lab_enroll import DEMO_HOSTS
from corvex.sensors.windows_os import (
    RateLimiter,
    append_events,
    recompute_run,
    sign_unsigned,
)
from corvex.stage_b import require_stage_b

MACOS_CHANNELS = ("auth", "net", "dns", "process", "pf")


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


def _is_macos() -> bool:
    return platform.system() == "Darwin"


def _run_cmd(cmd: Sequence[str], *, timeout: float = 8.0) -> Dict[str, Any]:
    if shutil.which(cmd[0]) is None:
        return {"ok": False, "reason": f"no_{cmd[0]}", "stdout": "", "stderr": ""}
    try:
        proc = subprocess.run(
            list(cmd),
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
    except subprocess.TimeoutExpired:
        return {"ok": False, "reason": "timeout", "stdout": "", "stderr": ""}
    except OSError as exc:
        return {"ok": False, "reason": f"os_error:{exc.__class__.__name__}", "stdout": "", "stderr": ""}
    if proc.returncode != 0:
        err = (proc.stderr or proc.stdout or "").strip().lower()
        reason = "command_failed"
        if "operation not permitted" in err or "permission" in err:
            reason = "permission_denied"
        if "sandboxed" in err:
            reason = "sandboxed"
        return {
            "ok": False,
            "reason": reason,
            "stdout": proc.stdout or "",
            "stderr": proc.stderr or "",
        }
    return {"ok": True, "reason": None, "stdout": proc.stdout or "", "stderr": proc.stderr or ""}


def poll_macos_net(*, max_events: int = 80) -> Dict[str, Any]:
    """Poll established TCP via lsof (user-visible network-wide flows)."""
    if not _is_macos():
        return {"records": [], "ok": False, "reason": "not_macos", "cursor": None}
    res = _run_cmd(["lsof", "-iTCP", "-sTCP:ESTABLISHED", "-n", "-P"], timeout=10.0)
    if not res["ok"]:
        # Fallback: netstat (often needs elevated rights on modern macOS)
        ns = _run_cmd(["netstat", "-n", "-f", "inet", "-p", "tcp"], timeout=8.0)
        if not ns["ok"]:
            return {
                "records": [],
                "ok": False,
                "reason": res.get("reason") or ns.get("reason") or "no_net_source",
                "cursor": None,
            }
        return {
            "records": [],
            "ok": False,
            "reason": "netstat_parse_unsupported_use_lsof",
            "cursor": None,
        }
    records = parse_lsof_network(res["stdout"])[:max_events]
    cursor = hashlib_cursor(records)
    return {
        "records": records,
        "ok": True,
        "reason": None if records else "zero_hits",
        "cursor": cursor,
    }


def hashlib_cursor(records: Sequence[Mapping[str, Any]]) -> str:
    import hashlib

    blob = "|".join(
        f"{r.get('dst_ip')}:{r.get('dst_port')}:{r.get('pid')}:{r.get('image')}"
        for r in records
    )
    return hashlib.sha256(blob.encode("utf-8")).hexdigest()[:32]


def poll_macos_auth(*, max_events: int = 20) -> Dict[str, Any]:
    """Best-effort unified log auth signals (sshd / login)."""
    if not _is_macos():
        return {"records": [], "ok": False, "reason": "not_macos", "cursor": None}
    pred = (
        '(process == "sshd") OR (eventMessage CONTAINS "Accepted password") '
        'OR (eventMessage CONTAINS "Failed password") '
        'OR (process == "loginwindow" AND eventMessage CONTAINS "logged in")'
    )
    res = _run_cmd(
        ["log", "show", "--style", "compact", "--last", "2m", "--predicate", pred],
        timeout=12.0,
    )
    if not res["ok"]:
        return {"records": [], "ok": False, "reason": res.get("reason") or "no_log", "cursor": None}
    records: List[Dict[str, Any]] = []
    now = _now()
    for line in (res["stdout"] or "").splitlines():
        if len(records) >= max_events:
            break
        low = line.lower()
        if "accepted" in low or "logged in" in low:
            kind = "ssh_accept" if "ssh" in low or "accepted" in low else "login_success"
            result = "success"
        elif "failed" in low or "invalid" in low:
            kind = "ssh_fail"
            result = "failure"
        else:
            continue
        records.append(
            {
                "channel": "auth",
                "EventID": kind,
                "TimeCreated": now,
                "user": "unknown",
                "result": result,
                "src": None,
                "Computer": "localhost",
                "raw_snip": line[:160],
            }
        )
    return {
        "records": records,
        "ok": True,
        "reason": None if records else "zero_hits",
        "cursor": _now(),
    }


def poll_macos_dns(*, max_events: int = 20) -> Dict[str, Any]:
    """Best-effort mDNSResponder / dns query lines from unified log."""
    if not _is_macos():
        return {"records": [], "ok": False, "reason": "not_macos", "cursor": None}
    pred = 'process == "mDNSResponder" AND eventMessage CONTAINS "Query"'
    res = _run_cmd(
        ["log", "show", "--style", "compact", "--last", "1m", "--predicate", pred],
        timeout=12.0,
    )
    if not res["ok"]:
        return {"records": [], "ok": False, "reason": res.get("reason") or "no_log", "cursor": None}
    records: List[Dict[str, Any]] = []
    now = _now()
    import re

    qre = re.compile(r"([A-Za-z0-9_.-]+\.[A-Za-z]{2,})")
    for line in (res["stdout"] or "").splitlines():
        if len(records) >= max_events:
            break
        m = qre.search(line)
        if not m:
            continue
        records.append(
            {
                "channel": "dns",
                "EventID": "query",
                "TimeCreated": now,
                "query": m.group(1).rstrip("."),
                "qtype": "A",
                "Computer": "localhost",
            }
        )
    return {
        "records": records,
        "ok": True,
        "reason": None if records else "zero_hits",
        "cursor": _now(),
    }


def poll_macos_process(*, max_events: int = 40) -> Dict[str, Any]:
    """Lightweight ``ps`` sample (not full EndpointSecurity — honesty note)."""
    if not _is_macos():
        return {"records": [], "ok": False, "reason": "not_macos", "cursor": None}
    res = _run_cmd(["ps", "-axo", "user=,pid=,comm=,args="], timeout=6.0)
    if not res["ok"]:
        return {"records": [], "ok": False, "reason": res.get("reason") or "no_ps", "cursor": None}
    records: List[Dict[str, Any]] = []
    now = _now()
    for line in (res["stdout"] or "").splitlines():
        if len(records) >= max_events:
            break
        line = line.strip()
        if not line:
            continue
        parts = line.split(None, 3)
        if len(parts) < 3:
            continue
        user, pid, comm = parts[0], parts[1], parts[2]
        args = parts[3] if len(parts) > 3 else comm
        records.append(
            {
                "channel": "process",
                "EventID": "sample",
                "TimeCreated": now,
                "user": user,
                "image": comm,
                "command_line": args[:240],
                "pid": int(pid) if pid.isdigit() else None,
                "Computer": "localhost",
            }
        )
    return {
        "records": records,
        "ok": True,
        "reason": None if records else "zero_hits",
        "cursor": hashlib_cursor(records),
    }


def poll_macos_pf(*, max_events: int = 20) -> Dict[str, Any]:
    """pfctl info — usually needs root; degrade honestly."""
    if not _is_macos():
        return {"records": [], "ok": False, "reason": "not_macos", "cursor": None}
    res = _run_cmd(["pfctl", "-s", "info"], timeout=4.0)
    if not res["ok"]:
        return {"records": [], "ok": False, "reason": res.get("reason") or "no_pfctl", "cursor": None}
    # Info alone does not yield connection events — mark ok with zero_hits
    return {"records": [], "ok": True, "reason": "pf_info_only_no_flow_events", "cursor": _now()}


_POLLERS = {
    "net": poll_macos_net,
    "auth": poll_macos_auth,
    "dns": poll_macos_dns,
    "process": poll_macos_process,
    "pf": poll_macos_pf,
}


def poll_macos_channel(channel: str, *, max_events: int = 80) -> Dict[str, Any]:
    ch = channel.strip().lower()
    fn = _POLLERS.get(ch)
    if not fn:
        return {"records": [], "ok": False, "reason": "unknown_channel", "cursor": None}
    return fn(max_events=max_events)


def run_sensor_macos(
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
    """Main Stage B macOS sensor loop. ``once`` drains one cycle; ``follow`` polls."""
    require_stage_b()
    if require_live and fixture is not None:
        raise ValueError("--require-live cannot be combined with --fixture")
    run_dir = Path(run_dir)
    run_dir.mkdir(parents=True, exist_ok=True)
    events_path = run_dir / "events.jsonl"
    bookmark_path = run_dir / "sensor_bookmarks.json"
    audit_path = run_dir / "sensor_audit.jsonl"
    allow = load_macos_allowlist(allowlist_path)
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
        "source": "fixture" if fixture else "macos_live",
        "fixture_seed": bool(fixture),
        "platform": platform.system(),
        "honesty": (
            "Observe-only macOS network-wide sensor. No pf/firewall mutation. "
            "Primary live channel is lsof TCP established (per-user visibility). "
            "Unified-log auth/dns degrade when sandboxed or denied. "
            "Not EndpointSecurity — process channel is a ps sample only. "
            "Fixture path is CI-only — not live telemetry."
        ),
        "degraded": [],
    }

    def _one_cycle(cycle: int) -> int:
        records: List[Dict[str, Any]] = []
        if fixture is not None:
            if cycle == 0 or not follow:
                for rec in iter_macos_records(Path(fixture)):
                    records.append(dict(rec))
            else:
                return 0
        else:
            for ch in chans:
                poll = poll_macos_channel(ch)
                health = {
                    "ok": bool(poll.get("ok")),
                    "reason": poll.get("reason"),
                    "hits": len(poll.get("records") or []),
                }
                stats["channel_health"][ch] = health
                if not poll.get("ok") or poll.get("reason") in {
                    "not_macos",
                    "permission_denied",
                    "sandboxed",
                    "no_lsof",
                    "no_log",
                    "no_pfctl",
                    "no_net_source",
                }:
                    if ch not in stats["degraded"]:
                        stats["degraded"].append(ch)
                if poll.get("cursor") is not None:
                    channel_bookmarks[ch] = poll["cursor"]
                records.extend(list(poll.get("records") or []))
            bookmarks["channels"] = channel_bookmarks

        exporter = host_id or "default"
        seen_all = bookmarks.get("seen_by_exporter") or {}
        seen: Set[str] = set(seen_all.get(exporter) or [])
        fresh: List[Dict[str, Any]] = []
        for rec in records:
            key = (
                f"{rec.get('channel')}|{rec.get('EventID')}|{rec.get('Computer')}|"
                f"{rec.get('TimeCreated')}|{rec.get('dst_ip')}|{rec.get('dst_port')}|"
                f"{rec.get('pid')}|{rec.get('query')}|{rec.get('user')}"
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
        # Ensure enrollment pair exists for forced host
        unsigned, st = adapt_macos_records(
            fresh,
            producer_id=prod,
            default_host=default_host,
            host_map=host_map,
            allowlist=allow,
            channels=chans,
            id_prefix=f"mac{cycle}",
        )
        stats["adapted"] += int(st.get("adapted", 0))
        stats["skipped"] += int(st.get("skipped", 0))
        for k, v in (st.get("by_channel") or {}).items():
            stats["channels"][k] = int(stats["channels"].get(k, 0)) + int(v)

        kept = []
        for rec in unsigned:
            if limiter.should_drop():
                continue
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
            # Tag sensor in timeline for honesty
            tl_path = run_dir / "timeline.json"
            if tl_path.exists():
                try:
                    tl = json.loads(tl_path.read_text(encoding="utf-8"))
                    tl["sensor"] = "macos-os-wide+network"
                    tl_path.write_text(json.dumps(tl, indent=2) + "\n", encoding="utf-8")
                except json.JSONDecodeError:
                    pass
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
        if stats["source"] != "macos_live" or (stats["published"] == 0 and live_hits == 0):
            stats["require_live_failed"] = True
            stats["require_live_note"] = (
                "No live macOS hits. Check lsof/net permissions, or drop "
                "--require-live for fixture CI."
            )

    (run_dir / "sensor_status.json").write_text(
        json.dumps(stats, indent=2) + "\n", encoding="utf-8"
    )
    return stats
