"""OTRF / Security-Datasets (Mordor) JSON → os_wide-compatible records.

Public captured telemetry — not hand-crafted benign noise. Mordor rows are
flat NXLog-style (Channel, EventID, Hostname, DestinationIp at top level).
This module normalizes them into the shape ``adapt_os_wide_records`` expects
and remaps Security-channel firewall IDs (5156/5157) onto the firewall channel.
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


def normalize_otrf_record(rec: Mapping[str, Any]) -> Dict[str, Any]:
    """Copy one Mordor/OTRF row into an os_wide-friendly dict."""
    out = dict(rec)
    host = (
        rec.get("Hostname")
        or rec.get("Computer")
        or rec.get("hostname")
        or (rec.get("host") if isinstance(rec.get("host"), str) else None)
    )
    if host and not out.get("Computer"):
        out["Computer"] = str(host)

    ch_raw = str(rec.get("Channel") or rec.get("channel") or "").strip()
    ch = CHANNEL_ALIASES.get(ch_raw.lower(), ch_raw.lower())
    eid = _norm_eid(rec.get("EventID") or rec.get("event_id"))

    # Remap WFP events off Security → firewall so default allowlist applies.
    if ch in {"security", ""} and eid in _SECURITY_FIREWALL_IDS:
        out["Channel"] = "firewall"
        out["channel"] = "firewall"
    elif ch_raw and "channel" not in {k.lower() for k in out}:
        out["Channel"] = ch_raw

    # Promote flat Sysmon/Security fields into EventData when missing.
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
    """Yield normalized records from JSONL, JSON array, or single object."""
    path = Path(path)
    text = path.read_text(encoding="utf-8").strip()
    if not text:
        return
    if text.startswith("["):
        data = json.loads(text)
        if isinstance(data, list):
            for rec in data:
                if isinstance(rec, Mapping):
                    yield normalize_otrf_record(rec)
        return
    # JSONL (Mordor default) or one object
    if text.startswith("{") and "\n" not in text:
        obj = json.loads(text)
        if isinstance(obj, Mapping):
            yield normalize_otrf_record(obj)
        return
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        rec = json.loads(line)
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
