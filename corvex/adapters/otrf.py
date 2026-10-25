"""OTRF / Security-Datasets (Mordor) JSON → os_wide-compatible records.

Public captured telemetry — not hand-crafted benign noise. Supports:

- Flat NXLog/Mordor rows (Channel, EventID, Hostname, …)
- Winlogbeat ECS rows (`winlog.*`) from ATT&CK Evals / Caldera captures

Remaps Security-channel firewall IDs (5156/5157) onto the firewall channel.
Streams JSONL so multi-hundred-MB corpora do not need a full in-memory read.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, Iterator, List, Mapping, Optional, Sequence, Set, Tuple

from corvex.adapters.os_wide import (
    CHANNEL_ALIASES,
    adapt_os_wide_records,
    load_allowlist,
)

# Windows Filtering Platform / firewall IDs often land on the Security channel
# in Mordor exports; Corvex maps them under channel=firewall.
_SECURITY_FIREWALL_IDS = {"5156", "5157", "5158"}


def _norm_eid(eid: Any) -> str:
    s = str(eid)
    if s.replace(".", "", 1).isdigit():
        return str(int(float(s)))
    return s


def _flatten_winlogbeat(rec: Mapping[str, Any]) -> Dict[str, Any]:
    """Map winlogbeat ECS → Mordor-like flat fields for os_wide adapt."""
    winlog = rec.get("winlog") if isinstance(rec.get("winlog"), Mapping) else {}
    host_obj = rec.get("host") if isinstance(rec.get("host"), Mapping) else {}
    event_obj = rec.get("event") if isinstance(rec.get("event"), Mapping) else {}
    ed_raw = winlog.get("event_data") if isinstance(winlog.get("event_data"), Mapping) else {}
    ed = {str(k): v for k, v in ed_raw.items()}
    computer = (
        winlog.get("computer_name")
        or host_obj.get("hostname")
        or host_obj.get("name")
        or rec.get("Hostname")
    )
    channel = winlog.get("channel") or event_obj.get("provider")
    eid = winlog.get("event_id") or event_obj.get("code") or event_obj.get("id")
    out: Dict[str, Any] = {
        "Hostname": computer,
        "Computer": computer,
        "Channel": channel,
        "EventID": eid,
        "EventData": ed,
        "TimeCreated": rec.get("@timestamp") or event_obj.get("created"),
    }
    for key in (
        "Image",
        "CommandLine",
        "User",
        "DestinationIp",
        "DestinationPort",
        "SourceIp",
        "SourcePort",
        "QueryName",
        "TargetUserName",
        "SubjectUserName",
        "IpAddress",
        "DestAddress",
        "DestPort",
        "WorkstationName",
        "TargetServerName",
        "ClientName",
        "ServiceName",
        "LogonType",
    ):
        if key in ed and key not in out:
            out[key] = ed[key]
    return out


def normalize_otrf_record(rec: Mapping[str, Any]) -> Dict[str, Any]:
    """Copy one Mordor/OTRF/winlogbeat row into an os_wide-friendly dict."""
    if isinstance(rec.get("winlog"), Mapping) and not rec.get("Channel") and not rec.get("EventID"):
        rec = _flatten_winlogbeat(rec)

    out = dict(rec)
    host = (
        rec.get("Hostname")
        or rec.get("Computer")
        or rec.get("hostname")
        or (rec.get("host") if isinstance(rec.get("host"), str) else None)
    )
    if isinstance(rec.get("host"), Mapping) and not host:
        host = rec["host"].get("hostname") or rec["host"].get("name")
    if host and not out.get("Computer"):
        out["Computer"] = str(host)
    if host and not out.get("Hostname"):
        out["Hostname"] = str(host)

    ch_raw = str(rec.get("Channel") or rec.get("channel") or "").strip()
    ch = CHANNEL_ALIASES.get(ch_raw.lower(), ch_raw.lower())
    eid = _norm_eid(rec.get("EventID") or rec.get("event_id"))

    if ch in {"security", ""} and eid in _SECURITY_FIREWALL_IDS:
        out["Channel"] = "firewall"
        out["channel"] = "firewall"
    elif ch_raw and "channel" not in {k.lower() for k in out}:
        out["Channel"] = ch_raw

    ed = out.get("EventData")
    if not isinstance(ed, Mapping):
        ed = {}
    else:
        ed = dict(ed)
    for key in (
        "Image",
        "CommandLine",
        "User",
        "DestinationIp",
        "DestinationPort",
        "SourceIp",
        "SourcePort",
        "QueryName",
        "QueryType",
        "TargetUserName",
        "SubjectUserName",
        "IpAddress",
        "DestAddress",
        "DestPort",
        "ScriptBlockText",
        "UserId",
        "WorkstationName",
        "TargetServerName",
        "ClientName",
        "ServiceName",
        "LogonType",
    ):
        if key not in ed and rec.get(key) is not None:
            ed[key] = rec.get(key)
    if ed:
        out["EventData"] = ed

    if rec.get("@timestamp") and not out.get("TimeCreated"):
        out["TimeCreated"] = rec["@timestamp"]
    elif rec.get("UtcTime") and not out.get("TimeCreated"):
        out["TimeCreated"] = rec["UtcTime"]

    return out


def iter_otrf_records(path: Path) -> Iterator[Mapping[str, Any]]:
    """Yield normalized records from JSONL, JSON array, or single object.

    Streams line-by-line for JSONL (including 100MB+ ATT&CK Evals dumps).
    """
    path = Path(path)
    with path.open("rb") as fh:
        head = b""
        while True:
            chunk = fh.read(4096)
            if not chunk:
                break
            head += chunk
            if head.strip():
                break
        if not head.strip():
            return
        fh.seek(0)
        stripped = head.lstrip()
        if stripped.startswith(b"["):
            text = path.read_text(encoding="utf-8", errors="replace").strip()
            data = json.loads(text)
            if isinstance(data, list):
                for rec in data:
                    if isinstance(rec, Mapping):
                        yield normalize_otrf_record(rec)
            return
        pending = ""
        for raw in fh:
            try:
                piece = raw.decode("utf-8", errors="replace")
            except Exception:
                continue
            if pending:
                piece = pending + piece
                pending = ""
            line = piece.strip()
            if not line:
                continue
            try:
                rec = json.loads(line)
            except json.JSONDecodeError:
                # Multi-line JSON object — accumulate until parse works
                pending = piece if not pending else pending + piece
                try:
                    rec = json.loads(pending)
                    pending = ""
                except json.JSONDecodeError:
                    continue
            if isinstance(rec, Mapping):
                yield normalize_otrf_record(rec)


def adapt_otrf_export(
    path: Path,
    *,
    producer_id: str = "prod-windows",
    default_host: str = "host-a",
    host_map: Optional[Mapping[str, str]] = None,
    allowlist: Optional[Mapping[str, Set[str]]] = None,
    channels: Optional[Sequence[str]] = None,
    id_prefix: str = "otrf",
) -> Tuple[List[Dict[str, Any]], Dict[str, int]]:
    """Mordor/OTRF file → unsigned Corvex envelope dicts + adapt stats."""
    records = list(iter_otrf_records(Path(path)))
    return adapt_os_wide_records(
        records,
        producer_id=producer_id,
        default_host=default_host,
        host_map=host_map,
        allowlist=allowlist,
        channels=channels,
        id_prefix=id_prefix,
    )


def adapt_otrf_paths(
    paths: Sequence[Path],
    *,
    host_map: Optional[Mapping[str, str]] = None,
    allowlist_path: Optional[Path] = None,
    id_prefix: str = "otrf",
) -> Tuple[List[Dict[str, Any]], Dict[str, int]]:
    """Adapt one or more OTRF JSON/JSONL files; merge stats."""
    allow = load_allowlist(allowlist_path)
    all_envs: List[Dict[str, Any]] = []
    merged: Dict[str, Any] = {"skipped": 0, "adapted": 0, "by_channel": {}, "files": 0}
    for i, path in enumerate(paths):
        envs, stats = adapt_otrf_export(
            Path(path),
            host_map=host_map,
            allowlist=allow,
            id_prefix=f"{id_prefix}{i}",
        )
        all_envs.extend(envs)
        merged["files"] = int(merged["files"]) + 1
        merged["skipped"] = int(merged["skipped"]) + int(stats.get("skipped") or 0)
        merged["adapted"] = int(merged["adapted"]) + int(stats.get("adapted") or 0)
        by = merged["by_channel"]
        assert isinstance(by, dict)
        for ch, n in (stats.get("by_channel") or {}).items():
            by[ch] = int(by.get(ch, 0)) + int(n)
    return all_envs, merged
