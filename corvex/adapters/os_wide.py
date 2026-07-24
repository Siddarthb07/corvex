"""OS-wide Windows channel adapters — Security / Sysmon / Firewall / PowerShell.

Observe-only. Maps Event Log–shaped JSON into unsigned Corvex envelope dicts.
Unknown Event IDs are skipped (counted by caller). Never invents payload fields
beyond what the record supplies.
"""

from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterator, List, Mapping, Optional, Sequence, Set, Tuple

from corvex.adapters.windows_security import (
    _event_id,
    _host_id,
    _parse_ts,
    _src_ip,
    _user,
)

# Default allowlists (noise control). Override via channels config JSON.
DEFAULT_ALLOWLIST: Dict[str, Set[str]] = {
    "security": {"4624", "4625", "4648"},
    "sysmon": {"1", "3", "22"},
    "firewall": {"2004", "2005", "2006", "5156", "5157"},
    "powershell": {"4103", "4104"},
}

CHANNEL_ALIASES = {
    "security": "security",
    "sysmon": "sysmon",
    "firewall": "firewall",
    "powershell": "powershell",
    "microsoft-windows-sysmon/operational": "sysmon",
    "microsoft-windows-windows firewall with advanced security/firewall": "firewall",
    "microsoft-windows-powershell/operational": "powershell",
    "windows powershell": "powershell",
}


def _norm_eid(eid: Any) -> str:
    s = str(eid)
    if s.replace(".", "", 1).isdigit():
        return str(int(float(s)))
    return s


def _event_data(rec: Mapping[str, Any]) -> Dict[str, Any]:
    data = rec.get("EventData") or rec.get("event_data") or {}
    if not isinstance(data, Mapping):
        return {}
    items = data.get("Data")
    if isinstance(items, list):
        kv = {
            str(i.get("Name")): i.get("Value")
            for i in items
            if isinstance(i, Mapping) and i.get("Name")
        }
        if kv:
            return kv
    return dict(data)


def _channel(rec: Mapping[str, Any], default: str = "security") -> str:
    raw = (
        rec.get("channel")
        or rec.get("Channel")
        or rec.get("LogName")
        or (rec.get("System") or {}).get("Channel")
        or default
    )
    key = str(raw).strip().lower()
    return CHANNEL_ALIASES.get(key, key)


def load_allowlist(path: Optional[Path] = None) -> Dict[str, Set[str]]:
    if path is None or not Path(path).exists():
        return {k: set(v) for k, v in DEFAULT_ALLOWLIST.items()}
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    out: Dict[str, Set[str]] = {}
    for ch, ids in (data.get("allowlist") or data).items():
        ch_n = CHANNEL_ALIASES.get(str(ch).lower(), str(ch).lower())
        out[ch_n] = {_norm_eid(x) for x in ids}
    for k, v in DEFAULT_ALLOWLIST.items():
        out.setdefault(k, set(v))
    return out


def iter_os_wide_records(path: Path) -> Iterator[Mapping[str, Any]]:
    """Yield records from JSON array, JSONL, or {\"Events\": [...]} export."""
    text = Path(path).read_text(encoding="utf-8").strip()
    if not text:
        return
    if text.startswith("["):
        data = json.loads(text)
        if isinstance(data, list):
            for rec in data:
                if isinstance(rec, Mapping):
                    yield rec
        return
    if text.startswith("{"):
        # single object or wrapper
        try:
            obj = json.loads(text)
        except json.JSONDecodeError:
            obj = None
        if isinstance(obj, Mapping):
            events = obj.get("Events") or obj.get("events")
            if isinstance(events, list):
                for rec in events:
                    if isinstance(rec, Mapping):
                        yield rec
                return
            yield obj
            return
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        rec = json.loads(line)
        if isinstance(rec, Mapping):
            yield rec


def _map_security(rec: Mapping[str, Any], eid: str, host_id: str, ts: str) -> Optional[Dict[str, Any]]:
    result = "success" if eid in {"4624", "4648"} else "failure" if eid == "4625" else "success"
    return {
        "payload_type": "auth",
        "payload": {
            "user": _user(rec),
            "result": result,
            "src": _src_ip(rec),
            "windows_event_id": eid,
            "channel": "security",
        },
    }


def _map_sysmon(rec: Mapping[str, Any], eid: str, host_id: str, ts: str) -> Optional[Dict[str, Any]]:
    ed = _event_data(rec)
    if eid == "1":
        return {
            "payload_type": "process",
            "payload": {
                "image": str(ed.get("Image") or rec.get("Image") or "unknown"),
                "command_line": str(ed.get("CommandLine") or rec.get("CommandLine") or "")[:240],
                "user": str(ed.get("User") or rec.get("User") or _user(rec)),
                "windows_event_id": eid,
                "channel": "sysmon",
            },
        }
    if eid == "3":
        dst = str(ed.get("DestinationIp") or rec.get("DestinationIp") or "0.0.0.0")
        port = int(ed.get("DestinationPort") or rec.get("DestinationPort") or 0)
        return {
            "payload_type": "net_conn",
            "payload": {
                "dst_ip": dst,
                "dst_port": port,
                "bytes": int(ed.get("bytes") or rec.get("bytes") or 1200),
                "egress": True,
                "windows_event_id": eid,
                "channel": "sysmon",
            },
        }
    if eid == "22":
        query = str(ed.get("QueryName") or rec.get("QueryName") or "unknown")
        return {
            "payload_type": "dns",
            "payload": {
                "query": query,
                "qtype": str(ed.get("QueryType") or rec.get("QueryType") or "A"),
                "windows_event_id": eid,
                "channel": "sysmon",
            },
        }
    return None


def _map_firewall(rec: Mapping[str, Any], eid: str, host_id: str, ts: str) -> Optional[Dict[str, Any]]:
    ed = _event_data(rec)
    dst = str(
        ed.get("DestAddress")
        or ed.get("DestinationIp")
        or rec.get("DestAddress")
        or "0.0.0.0"
    )
    port = int(ed.get("DestPort") or ed.get("DestinationPort") or rec.get("DestPort") or 0)
    blocked = eid in {"5157", "2004"} or str(ed.get("Action") or "").lower() in {
        "block",
        "deny",
    }
    return {
        "payload_type": "net_conn",
        "payload": {
            "dst_ip": dst,
            "dst_port": port,
            "bytes": int(ed.get("bytes") or 800),
            "egress": True,
            "blocked": blocked,
            "windows_event_id": eid,
            "channel": "firewall",
        },
    }


def _map_powershell(rec: Mapping[str, Any], eid: str, host_id: str, ts: str) -> Optional[Dict[str, Any]]:
    ed = _event_data(rec)
    body = str(
        ed.get("ScriptBlockText")
        or rec.get("ScriptBlockText")
        or ed.get("Payload")
        or ""
    )
    # Never ship full script bodies in envelopes — hash + short prefix only
    digest = hashlib.sha256(body.encode("utf-8", errors="replace")).hexdigest()[:16]
    prefix = body[:80].replace("\n", " ") if body else ""
    return {
        "payload_type": "process",
        "payload": {
            "image": "powershell",
            "command_line": f"script_sha256={digest}" + (f" prefix={prefix}" if prefix else ""),
            "user": str(ed.get("UserId") or rec.get("UserId") or _user(rec)),
            "script_sha256_16": digest,
            "windows_event_id": eid,
            "channel": "powershell",
        },
    }


_MAPPERS = {
    "security": _map_security,
    "sysmon": _map_sysmon,
    "firewall": _map_firewall,
    "powershell": _map_powershell,
}


def adapt_os_wide_records(
    records: Sequence[Mapping[str, Any]],
    *,
    producer_id: str = "prod-windows",
    default_host: str = "host-a",
    host_map: Optional[Mapping[str, str]] = None,
    allowlist: Optional[Mapping[str, Set[str]]] = None,
    channels: Optional[Sequence[str]] = None,
    id_prefix: str = "osw",
) -> Tuple[List[Dict[str, Any]], Dict[str, int]]:
    """Map OS-wide Event Log records → unsigned envelope dicts.

    Returns (envelopes, stats) where stats includes skipped / by_channel counts.
    """
    allow = {k: set(v) for k, v in (allowlist or DEFAULT_ALLOWLIST).items()}
    wanted_ch = (
        {CHANNEL_ALIASES.get(c.lower(), c.lower()) for c in channels}
        if channels
        else set(allow.keys())
    )
    hmap = dict(host_map or {})
    out: List[Dict[str, Any]] = []
    stats = {"skipped": 0, "adapted": 0, "by_channel": {}}  # type: ignore
    seq = 0
    for rec in records:
        ch = _channel(rec)
        if ch not in wanted_ch:
            stats["skipped"] += 1
            continue
        eid = _norm_eid(_event_id(rec))
        if eid not in allow.get(ch, set()):
            stats["skipped"] += 1
            continue
        mapper = _MAPPERS.get(ch)
        if mapper is None:
            stats["skipped"] += 1
            continue
        raw_host = _host_id(rec, default_host)
        host_id = hmap.get(raw_host, hmap.get(raw_host.lower(), raw_host))
        ts = _parse_ts(
            rec.get("TimeCreated")
            or rec.get("ts_utc")
            or rec.get("@timestamp")
            or (rec.get("System") or {}).get("TimeCreated")
        )
        mapped = mapper(rec, eid, host_id, ts)
        if mapped is None:
            stats["skipped"] += 1
            continue
        seq += 1
        event_id = f"{id_prefix}-{ch}-{host_id}-{seq:05d}"
        out.append(
            {
                "schema_ver": "1",
                "event_id": event_id,
                "producer_id": producer_id,
                "host_id": host_id,
                "ts_utc": ts,
                "nonce": event_id,
                "payload_type": mapped["payload_type"],
                "payload": mapped["payload"],
            }
        )
        stats["adapted"] += 1
        by = stats["by_channel"]
        assert isinstance(by, dict)
        by[ch] = int(by.get(ch, 0)) + 1
    return out, stats


def adapt_os_wide_export(
    path: Path,
    *,
    producer_id: str = "prod-windows",
    default_host: str = "host-a",
    host_map: Optional[Mapping[str, str]] = None,
    allowlist: Optional[Mapping[str, Set[str]]] = None,
    channels: Optional[Sequence[str]] = None,
    id_prefix: str = "osw",
) -> Tuple[List[Dict[str, Any]], Dict[str, int]]:
    records = list(iter_os_wide_records(Path(path)))
    return adapt_os_wide_records(
        records,
        producer_id=producer_id,
        default_host=default_host,
        host_map=host_map,
        allowlist=allowlist,
        channels=channels,
        id_prefix=id_prefix,
    )
