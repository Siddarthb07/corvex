"""Windows Security / auth export → unsigned EventEnvelope dicts (BYO path).

Ungated observe-only converter. Strangers export Event Viewer JSON (or EVTX→JSON),
run this adapter, then `corvex ingest-byo`. Does not unlock Stage B live sensors.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterator, List, Mapping, Optional, Sequence


# Common successful-logon Event IDs (Security log).
_AUTH_SUCCESS_IDS = {4624, "4624", "4624.0"}


def _parse_ts(raw: Any) -> str:
    if raw is None:
        return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")
    if isinstance(raw, (int, float)):
        return datetime.fromtimestamp(float(raw), tz=timezone.utc).strftime(
            "%Y-%m-%dT%H:%M:%S.%fZ"
        )
    text = str(raw).strip()
    if text.endswith("Z"):
        return text if "." in text else text.replace("Z", ".000000Z")
    try:
        dt = datetime.fromisoformat(text.replace("Z", "+00:00"))
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")
    except ValueError:
        return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def _event_id(rec: Mapping[str, Any]) -> Any:
    for key in ("EventID", "event_id", "Id", "id"):
        if key in rec:
            return rec[key]
    system = rec.get("System") or {}
    if isinstance(system, Mapping):
        eid = system.get("EventID")
        if isinstance(eid, Mapping):
            return eid.get("#text", eid.get("Value"))
        return eid
    return None


def _host_id(rec: Mapping[str, Any], default_host: str) -> str:
    for key in ("host_id", "Computer", "Hostname", "MachineName"):
        val = rec.get(key)
        if val:
            # Strip domain suffix for lab-friendly ids when present
            return str(val).split(".", 1)[0].lower()
    system = rec.get("System") or {}
    if isinstance(system, Mapping) and system.get("Computer"):
        return str(system["Computer"]).split(".", 1)[0].lower()
    return default_host


def _user(rec: Mapping[str, Any]) -> str:
    for key in ("TargetUserName", "user", "User", "AccountName"):
        val = rec.get(key)
        if val and str(val) not in ("-", ""):
            return str(val)
    data = rec.get("EventData") or rec.get("event_data") or {}
    if isinstance(data, Mapping):
        for key in ("TargetUserName", "SubjectUserName", "User"):
            val = data.get(key)
            if val and str(val) not in ("-", ""):
                return str(val)
        # Flat list form from some exporters: [{"Name": "...", "Value": "..."}]
        items = data.get("Data")
        if isinstance(items, list):
            kv = {
                str(i.get("Name")): i.get("Value")
                for i in items
                if isinstance(i, Mapping) and i.get("Name")
            }
            for key in ("TargetUserName", "SubjectUserName"):
                if kv.get(key) and str(kv[key]) not in ("-", ""):
                    return str(kv[key])
    return "unknown"


def _src_ip(rec: Mapping[str, Any]) -> str:
    for key in ("IpAddress", "src", "SourceAddress", "IpAddress"):
        val = rec.get(key)
        if val and str(val) not in ("-", "::1", "127.0.0.1"):
            return str(val)
    data = rec.get("EventData") or {}
    if isinstance(data, Mapping):
        val = data.get("IpAddress") or data.get("SourceNetworkAddress")
        if val and str(val) not in ("-", ""):
            return str(val)
    return "0.0.0.0"


def _iter_records(path: Path) -> Iterator[Mapping[str, Any]]:
    text = path.read_text(encoding="utf-8").strip()
    if not text:
        return
    # JSON array export
    if text.startswith("["):
        data = json.loads(text)
        if isinstance(data, list):
            for rec in data:
                if isinstance(rec, Mapping):
                    yield rec
        return
    # JSONL or single object
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        rec = json.loads(line)
        if isinstance(rec, Mapping):
            yield rec


def adapt_windows_security_export(
    path: Path,
    *,
    producer_id: str = "prod-windows",
    default_host: str = "host-a",
    host_map: Optional[Mapping[str, str]] = None,
    event_ids: Optional[Sequence[Any]] = None,
) -> List[Dict[str, Any]]:
    """
    Convert a Windows Security JSON/JSONL export into unsigned envelope dicts.

    Caller signs via `corvex ingest-byo` (re-HMAC with local enrollment) or
    `resign_events` after wrapping as EventEnvelope.
    """
    path = Path(path)
    wanted = set(event_ids) if event_ids is not None else set(_AUTH_SUCCESS_IDS)
    # Normalize wanted to strings for comparison
    wanted_norm = {str(int(x)) if str(x).replace(".", "", 1).isdigit() else str(x) for x in wanted}
    host_map = dict(host_map or {})
    out: List[Dict[str, Any]] = []
    seq = 0
    for rec in _iter_records(path):
        eid = _event_id(rec)
        eid_norm = str(int(eid)) if str(eid).replace(".", "", 1).isdigit() else str(eid)
        if eid_norm not in wanted_norm and eid not in wanted:
            continue
        raw_host = _host_id(rec, default_host)
        host_id = host_map.get(raw_host, host_map.get(raw_host.lower(), raw_host))
        seq += 1
        ts = _parse_ts(
            rec.get("TimeCreated")
            or rec.get("ts_utc")
            or rec.get("@timestamp")
            or (rec.get("System") or {}).get("TimeCreated")
        )
        event_id = f"win-auth-{host_id}-{seq:04d}"
        out.append(
            {
                "schema_ver": "1",
                "event_id": event_id,
                "producer_id": producer_id,
                "host_id": host_id,
                "ts_utc": ts,
                "nonce": event_id,
                "payload_type": "auth",
                "payload": {
                    "user": _user(rec),
                    "result": "success",
                    "src": _src_ip(rec),
                    "windows_event_id": eid_norm,
                },
            }
        )
    return out


def write_byo_jsonl(envelopes: Sequence[Mapping[str, Any]], dest: Path) -> int:
    dest = Path(dest)
    dest.parent.mkdir(parents=True, exist_ok=True)
    with dest.open("w", encoding="utf-8") as fh:
        for env in envelopes:
            fh.write(json.dumps(dict(env), separators=(",", ":")) + "\n")
    return len(envelopes)
