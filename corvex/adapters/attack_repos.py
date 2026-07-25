"""Adapters for public attack / purple-team repo exports → Corvex envelopes.

Sources are simulation frameworks (Atomic Red Team–style technique telemetry),
not malware droppers. Manifests declare technique IDs + host topology; adapters
normalize exported JSONL into unsigned EventEnvelope dicts for BYO ingest.
"""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, List, Mapping, Optional, Sequence


def load_manifest(path: Path) -> Dict[str, Any]:
    path = Path(path)
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError(f"manifest must be a JSON object: {path}")
    required = {"campaign_id", "hosts", "steps"}
    missing = required - set(data)
    if missing:
        raise ValueError(f"manifest missing {sorted(missing)}")
    return data


def _ts(base: datetime, offset_s: float) -> str:
    return (base + timedelta(seconds=offset_s)).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def _base_time(manifest: Mapping[str, Any]) -> datetime:
    raw = manifest.get("base_time_utc")
    if not raw:
        return datetime(2026, 6, 1, 14, 0, 0, tzinfo=timezone.utc)
    text = str(raw)
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    return datetime.fromisoformat(text)


def adapt_attack_manifest(
    manifest: Mapping[str, Any],
    *,
    producer_prefix: str = "prod",
) -> tuple[List[Dict[str, Any]], Dict[str, Any]]:
    """
    Expand a break-test manifest into unsigned envelope dicts + ground truth.

    Step kinds (aligned with Corvex detectors):
      - auth: {host, user, src?}
      - egress / exfil: {host, dst_ip, dst_port?, bytes?}
      - recon: {host, dst_ips: [...]}  (fan-out scan)

    Optional `source` metadata (repo URL, technique IDs) is copied into GT only.
    """
    hosts: Sequence[str] = list(manifest["hosts"])
    if len(hosts) < 4:
        raise ValueError("break-test manifests need ≥4 hosts")

    host_producer = {
        h: f"{producer_prefix}-{chr(ord('a') + i)}" if i < 26 else f"{producer_prefix}-{i}"
        for i, h in enumerate(hosts)
    }
    # Prefer explicit producer map when present
    for h, p in (manifest.get("producers") or {}).items():
        host_producer[str(h)] = str(p)

    # Optional per-host clock skew (seconds added to that host's event timestamps).
    skew_map = {
        str(h): float(s)
        for h, s in (manifest.get("host_clock_skew_seconds") or {}).items()
    }
    # Simulate agent outage: drop all events for these hosts after expansion.
    drop_hosts = {str(h) for h in (manifest.get("drop_hosts") or [])}
    # Logical host aliases for scoring (e.g. DHCP re-lease → two host_ids, one identity).
    host_aliases = {
        str(k): str(v) for k, v in (manifest.get("host_aliases") or {}).items()
    }

    def _alias(hid: str) -> str:
        return host_aliases.get(hid, hid)

    base = _base_time(manifest)
    events: List[Dict[str, Any]] = []
    seq = 0
    stage_names: Dict[str, List[str]] = {}

    def _emit_host(step: Mapping[str, Any], logical: str) -> str:
        # emit_host / host_id_override: report under a different hostname (split-brain).
        return str(step.get("emit_host") or step.get("host_id_override") or logical)

    def _producer_for(emit: str, logical: str) -> str:
        if emit in host_producer:
            return host_producer[emit]
        if logical in host_producer:
            return host_producer[logical]
        raise KeyError(f"no producer for emit_host={emit!r} / host={logical!r}")

    for step in manifest["steps"]:
        kind = str(step.get("kind") or step.get("type") or "").lower()
        offset = float(step.get("offset_seconds", seq * 20))
        if kind == "auth":
            logical = str(step["host"])
            if logical in drop_hosts:
                continue
            host = _emit_host(step, logical)
            if host in drop_hosts:
                continue
            seq += 1
            eid = f"{manifest['campaign_id']}-auth-{seq:04d}"
            ts_off = offset + skew_map.get(logical, 0.0) + float(step.get("clock_skew_seconds") or 0)
            events.append(
                {
                    "schema_ver": "1",
                    "event_id": eid,
                    "producer_id": _producer_for(host, logical),
                    "host_id": host,
                    "ts_utc": _ts(base, ts_off),
                    "nonce": eid,
                    "payload_type": "auth",
                    "payload": {
                        "user": str(step.get("user") or "attacker"),
                        "result": "success",
                        "src": str(step.get("src") or "10.1.0.5"),
                        "technique": step.get("technique"),
                    },
                }
            )
            stage_names.setdefault("lateral_auth", []).append(host)
        elif kind in ("egress", "exfil", "micro_exfil"):
            logical = str(step["host"])
            if logical in drop_hosts:
                continue
            host = _emit_host(step, logical)
            if host in drop_hosts:
                continue
            seq += 1
            eid = f"{manifest['campaign_id']}-exfil-{seq:04d}"
            ts_off = offset + skew_map.get(logical, 0.0) + float(step.get("clock_skew_seconds") or 0)
            events.append(
                {
                    "schema_ver": "1",
                    "event_id": eid,
                    "producer_id": _producer_for(host, logical),
                    "host_id": host,
                    "ts_utc": _ts(base, ts_off),
                    "nonce": eid,
                    "payload_type": "net_conn",
                    "payload": {
                        "dst_ip": str(step.get("dst_ip") or "203.0.113.50"),
                        "dst_port": int(step.get("dst_port") or 443),
                        "bytes": int(step.get("bytes") or 12_000),
                        "egress": True,
                        "technique": step.get("technique"),
                    },
                }
            )
            stage_names.setdefault("micro_exfil", []).append(host)
        elif kind in ("recon", "recon_fanout"):
            logical = str(step["host"])
            if logical in drop_hosts:
                continue
            host = _emit_host(step, logical)
            if host in drop_hosts:
                continue
            dsts = list(step.get("dst_ips") or [f"10.20.30.{j+1}" for j in range(8)])
            for j, dst in enumerate(dsts):
                seq += 1
                eid = f"{manifest['campaign_id']}-recon-{seq:04d}"
                ts_off = (
                    offset
                    + j * float(step.get("dst_step", 5))
                    + skew_map.get(logical, 0.0)
                    + float(step.get("clock_skew_seconds") or 0)
                )
                events.append(
                    {
                        "schema_ver": "1",
                        "event_id": eid,
                        "producer_id": _producer_for(host, logical),
                        "host_id": host,
                        "ts_utc": _ts(base, ts_off),
                        "nonce": eid,
                        "payload_type": "net_conn",
                        "payload": {
                            "dst_ip": str(dst),
                            "dst_port": int(step.get("dst_port") or 445),
                            "bytes": int(step.get("bytes") or 60),
                            "egress": False,
                            "technique": step.get("technique"),
                        },
                    }
                )
            stage_names.setdefault("recon_fanout", []).append(host)
        elif kind == "dns":
            logical = str(step["host"])
            if logical in drop_hosts:
                continue
            host = _emit_host(step, logical)
            if host in drop_hosts:
                continue
            seq += 1
            eid = f"{manifest['campaign_id']}-dns-{seq:04d}"
            ts_off = offset + skew_map.get(logical, 0.0) + float(step.get("clock_skew_seconds") or 0)
            events.append(
                {
                    "schema_ver": "1",
                    "event_id": eid,
                    "producer_id": _producer_for(host, logical),
                    "host_id": host,
                    "ts_utc": _ts(base, ts_off),
                    "nonce": eid,
                    "payload_type": "dns",
                    "payload": {
                        "query": str(step.get("query") or f"c2-{seq}.example.com"),
                        "qtype": str(step.get("qtype") or "A"),
                        "technique": step.get("technique"),
                    },
                }
            )
        else:
            raise ValueError(f"unknown step kind: {kind!r}")

    # Normalize emit_host / DHCP aliases to persistent asset IDs before pack write
    # so the correlator never sees split-brain labels (lim11).
    if host_aliases:
        for ev in events:
            ev["host_id"] = _alias(str(ev["host_id"]))
            payload = ev.get("payload")
            if isinstance(payload, dict):
                src = payload.get("src")
                if src and str(src) in host_aliases:
                    payload["src"] = _alias(str(src))

    events.sort(key=lambda e: e["ts_utc"])
    stages = [
        {"name": name, "hosts": sorted(set(hs))} for name, hs in stage_names.items()
    ]
    # truth_hosts: distinguish missing (default all hosts) from explicit empty (FP stress).
    if "truth_hosts" in manifest:
        truth_hosts = list(manifest.get("truth_hosts") or [])
    else:
        truth_hosts = list(hosts)
    gt: Dict[str, Any] = {
        "campaign_id": str(manifest["campaign_id"]),
        "host_ids": truth_hosts,
        "stages": stages,
        "family": str(manifest.get("family") or "attack_repo"),
        "ood": bool(manifest.get("ood", False)),
        "source": manifest.get("source") or {},
        "break_intent": manifest.get("break_intent"),
    }
    if manifest.get("truth_campaigns"):
        gt["truth_campaigns"] = list(manifest["truth_campaigns"])
    if host_aliases:
        gt["host_aliases"] = host_aliases
    if drop_hosts:
        gt["drop_hosts"] = sorted(drop_hosts)
    if skew_map:
        gt["host_clock_skew_seconds"] = skew_map
    return events, gt


def write_unsigned_pack(
    path: Path,
    events: Sequence[Mapping[str, Any]],
    ground_truth: Mapping[str, Any],
) -> None:
    """JSONL pack with ground_truth + unsigned event dicts (sign on ingest/replay)."""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as fh:
        fh.write(
            json.dumps({"type": "ground_truth", **ground_truth}, separators=(",", ":")) + "\n"
        )
        for env in events:
            fh.write(json.dumps({"type": "event", **dict(env)}, separators=(",", ":")) + "\n")
