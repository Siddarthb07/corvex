"""macOS channel adapters — auth / net / dns / process / pf.

Observe-only. Maps Mac-shaped JSON records into unsigned Corvex envelope dicts
with the same payload_type conventions as Windows OS-wide (auth, net_conn, dns,
process). Unknown event kinds are skipped.
"""

from __future__ import annotations

import hashlib
import json
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterator, List, Mapping, Optional, Sequence, Set, Tuple

# Channel → allowlisted event kinds (not Windows EIDs).
DEFAULT_ALLOWLIST: Dict[str, Set[str]] = {
    "auth": {"ssh_accept", "ssh_fail", "login_success", "login_fail", "sudo"},
    "net": {"tcp_established", "udp_flow", "tcp_listen"},
    "dns": {"query"},
    "process": {"exec", "sample"},
    "pf": {"pass", "block"},
}

CHANNEL_ALIASES = {
    "auth": "auth",
    "net": "net",
    "network": "net",
    "dns": "dns",
    "process": "process",
    "proc": "process",
    "pf": "pf",
    "firewall": "pf",
}


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _norm_kind(kind: Any) -> str:
    return str(kind or "").strip().lower()


def _channel(rec: Mapping[str, Any], default: str = "net") -> str:
    raw = rec.get("channel") or rec.get("Channel") or default
    return CHANNEL_ALIASES.get(str(raw).strip().lower(), str(raw).strip().lower())


def _parse_ts(rec: Mapping[str, Any]) -> str:
    raw = rec.get("TimeCreated") or rec.get("ts_utc") or rec.get("timestamp") or _now()
    s = str(raw).strip()
    if s.endswith("Z") or "+" in s[10:]:
        # normalize to second precision Z
        try:
            if s.endswith("Z"):
                s = s[:-1] + "+00:00"
            dt = datetime.fromisoformat(s.replace("Z", "+00:00"))
            return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        except ValueError:
            pass
    return _now()


def _host_id(rec: Mapping[str, Any], default: str, host_map: Optional[Mapping[str, str]]) -> str:
    raw = str(
        rec.get("host_id")
        or rec.get("Computer")
        or rec.get("hostname")
        or default
    ).strip()
    if host_map:
        if raw in host_map:
            return str(host_map[raw])
        low = raw.lower()
        if low in host_map:
            return str(host_map[low])
    if raw.endswith(".local"):
        base = raw[: -len(".local")]
        if host_map and base in host_map:
            return str(host_map[base])
    return raw


def load_macos_allowlist(path: Optional[Path] = None) -> Dict[str, Set[str]]:
    if path is None or not Path(path).exists():
        return {k: set(v) for k, v in DEFAULT_ALLOWLIST.items()}
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    out: Dict[str, Set[str]] = {}
    for ch, ids in (data.get("allowlist") or data).items():
        ch_n = CHANNEL_ALIASES.get(str(ch).lower(), str(ch).lower())
        out[ch_n] = {_norm_kind(x) for x in ids}
    for k, v in DEFAULT_ALLOWLIST.items():
        out.setdefault(k, set(v))
    return out


def iter_macos_records(path: Path) -> Iterator[Mapping[str, Any]]:
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


def _map_auth(rec: Mapping[str, Any], kind: str) -> Optional[Dict[str, Any]]:
    result = "success"
    if kind in {"ssh_fail", "login_fail"} or str(rec.get("result") or "").lower() in {
        "failure",
        "fail",
        "denied",
    }:
        result = "failure"
    user = str(rec.get("user") or rec.get("User") or "unknown")
    src = rec.get("src") or rec.get("src_ip") or rec.get("IpAddress")
    return {
        "payload_type": "auth",
        "payload": {
            "user": user,
            "result": result,
            "src": src,
            "macos_event": kind,
            "channel": "auth",
        },
    }


def _map_net(rec: Mapping[str, Any], kind: str) -> Optional[Dict[str, Any]]:
    dst = str(rec.get("dst_ip") or rec.get("DestinationIp") or rec.get("foreign_ip") or "")
    if not dst or dst in {"*", "0.0.0.0", "::"}:
        return None
    try:
        port = int(rec.get("dst_port") or rec.get("DestinationPort") or rec.get("foreign_port") or 0)
    except (TypeError, ValueError):
        port = 0
    try:
        nbytes = int(rec.get("bytes") or 1200)
    except (TypeError, ValueError):
        nbytes = 1200
    egress = rec.get("egress")
    if egress is None:
        # Treat non-loopback foreign as egress
        egress = dst not in {"127.0.0.1", "::1"}
    return {
        "payload_type": "net_conn",
        "payload": {
            "dst_ip": dst,
            "dst_port": port,
            "bytes": nbytes,
            "egress": bool(egress),
            "macos_event": kind,
            "channel": "net",
            "image": str(rec.get("image") or rec.get("command") or "")[:120] or None,
            "pid": rec.get("pid"),
        },
    }


def _map_dns(rec: Mapping[str, Any], kind: str) -> Optional[Dict[str, Any]]:
    query = str(rec.get("query") or rec.get("QueryName") or "").strip()
    if not query:
        return None
    return {
        "payload_type": "dns",
        "payload": {
            "query": query,
            "qtype": str(rec.get("qtype") or rec.get("QueryType") or "A"),
            "macos_event": kind,
            "channel": "dns",
        },
    }


def _map_process(rec: Mapping[str, Any], kind: str) -> Optional[Dict[str, Any]]:
    image = str(rec.get("image") or rec.get("command") or rec.get("comm") or "unknown")
    cmdline = str(rec.get("command_line") or rec.get("args") or "")[:240]
    user = str(rec.get("user") or "unknown")
    payload: Dict[str, Any] = {
        "image": image,
        "command_line": cmdline,
        "user": user,
        "macos_event": kind,
        "channel": "process",
    }
    # Hash long args rather than storing secrets wholesale
    raw = str(rec.get("script") or "")
    if raw:
        payload["script_sha256_16"] = hashlib.sha256(raw.encode("utf-8")).hexdigest()[:16]
    return {"payload_type": "process", "payload": payload}


def _map_pf(rec: Mapping[str, Any], kind: str) -> Optional[Dict[str, Any]]:
    mapped = _map_net(rec, kind)
    if not mapped:
        return None
    mapped["payload"]["channel"] = "pf"
    mapped["payload"]["blocked"] = kind == "block" or str(rec.get("action") or "").lower() == "block"
    mapped["payload"]["macos_event"] = kind
    return mapped


_MAPPERS = {
    "auth": _map_auth,
    "net": _map_net,
    "dns": _map_dns,
    "process": _map_process,
    "pf": _map_pf,
}


def adapt_macos_records(
    records: Sequence[Mapping[str, Any]],
    *,
    producer_id: str = "prod-macos",
    default_host: str = "host-mac",
    host_map: Optional[Mapping[str, str]] = None,
    allowlist: Optional[Mapping[str, Set[str]]] = None,
    channels: Optional[Sequence[str]] = None,
    id_prefix: str = "mac",
) -> Tuple[List[Dict[str, Any]], Dict[str, int]]:
    allow = allowlist or DEFAULT_ALLOWLIST
    want = {CHANNEL_ALIASES.get(c.lower(), c.lower()) for c in (channels or allow.keys())}
    out: List[Dict[str, Any]] = []
    stats: Dict[str, Any] = {"adapted": 0, "skipped": 0, "by_channel": {}}
    for i, rec in enumerate(records):
        ch = _channel(rec)
        if ch not in want:
            stats["skipped"] += 1
            continue
        kind = _norm_kind(rec.get("EventID") or rec.get("event") or rec.get("kind") or "unknown")
        allowed = allow.get(ch) or set()
        if allowed and kind not in allowed and "*" not in allowed:
            stats["skipped"] += 1
            continue
        mapper = _MAPPERS.get(ch)
        if not mapper:
            stats["skipped"] += 1
            continue
        mapped = mapper(rec, kind)
        if not mapped:
            stats["skipped"] += 1
            continue
        # Drop None payload fields
        payload = {k: v for k, v in mapped["payload"].items() if v is not None}
        host = _host_id(rec, default_host, host_map)
        ts = _parse_ts(rec)
        eid = str(rec.get("event_id") or f"{id_prefix}-{ch}-{kind}-{i}")
        nonce = hashlib.sha256(f"{eid}|{ts}|{host}".encode("utf-8")).hexdigest()[:24]
        out.append(
            {
                "schema_ver": "1",
                "event_id": eid,
                "producer_id": producer_id,
                "host_id": host,
                "ts_utc": ts,
                "nonce": nonce,
                "payload_type": mapped["payload_type"],
                "payload": payload,
            }
        )
        stats["adapted"] += 1
        stats["by_channel"][ch] = int(stats["by_channel"].get(ch, 0)) + 1
    return out, stats


def adapt_macos_export(
    path: Path,
    *,
    producer_id: str = "prod-macos",
    default_host: str = "host-mac",
    host_map: Optional[Mapping[str, str]] = None,
    allowlist: Optional[Mapping[str, Set[str]]] = None,
    channels: Optional[Sequence[str]] = None,
    id_prefix: str = "mac",
) -> Tuple[List[Dict[str, Any]], Dict[str, int]]:
    records = list(iter_macos_records(Path(path)))
    return adapt_macos_records(
        records,
        producer_id=producer_id,
        default_host=default_host,
        host_map=host_map,
        allowlist=allowlist,
        channels=channels,
        id_prefix=id_prefix,
    )


_LSOF_LINE = re.compile(
    r"^(?P<cmd>\S+)\s+(?P<pid>\d+)\s+(?P<user>\S+)\s+\S+\s+\S+\s+\S+\s+\S+\s+\S+\s+"
    r"(?:TCP|UDP)\s+(?P<name>.+)$"
)


def parse_lsof_network(text: str) -> List[Dict[str, Any]]:
    """Parse ``lsof -iTCP -sTCP:ESTABLISHED -n -P`` (and UDP) into Mac net records."""
    out: List[Dict[str, Any]] = []
    now = _now()
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("COMMAND"):
            continue
        # NAME looks like: 10.0.0.1:54520->74.125.200.188:443 (ESTABLISHED)
        if "->" not in line:
            continue
        parts = line.split()
        if len(parts) < 9:
            continue
        cmd, pid, user = parts[0], parts[1], parts[2]
        name = parts[-2] if parts[-1].startswith("(") else parts[-1]
        # strip IPv6 brackets in endpoints
        if "->" not in name:
            continue
        local, foreign = name.split("->", 1)
        foreign = foreign.split()[0]
        # port is after last colon (IPv4) or ]:port
        def _split_host_port(endpoint: str) -> Tuple[str, int]:
            endpoint = endpoint.strip()
            if endpoint.startswith("["):
                # [ipv6]:port
                m = re.match(r"^\[([^\]]+)\]:(\d+)$", endpoint)
                if m:
                    return m.group(1), int(m.group(2))
            if ":" not in endpoint:
                return endpoint, 0
            host, _, port_s = endpoint.rpartition(":")
            try:
                return host, int(port_s)
            except ValueError:
                return endpoint, 0

        dst_ip, dst_port = _split_host_port(foreign)
        if dst_ip in {"127.0.0.1", "::1"}:
            continue  # skip loopback noise by default
        out.append(
            {
                "channel": "net",
                "EventID": "tcp_established",
                "TimeCreated": now,
                "dst_ip": dst_ip,
                "dst_port": dst_port,
                "bytes": 1500,
                "egress": True,
                "image": cmd,
                "pid": int(pid) if pid.isdigit() else None,
                "user": user,
                "Computer": "localhost",
            }
        )
    return out
