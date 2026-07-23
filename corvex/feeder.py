"""Synthetic multi-host event feeder + pack generator."""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, List, Mapping, Optional, Sequence, Tuple

from corvex.auth import Enrollment
from corvex.bus import JsonlBus
from corvex.envelope import EventEnvelope, sign_envelope
from corvex.ingest import publish_verified


def _ts(base: datetime, seconds: int) -> str:
    return (base + timedelta(seconds=seconds)).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def _sign(
    enrollment: Enrollment,
    producer_id: str,
    host_id: str,
    payload_type: str,
    payload: Mapping[str, Any],
    ts: str,
    event_id: str,
) -> EventEnvelope:
    secret = enrollment.require(producer_id, host_id)
    return sign_envelope(
        producer_id=producer_id,
        host_id=host_id,
        payload_type=payload_type,
        payload=payload,
        secret=secret,
        event_id=event_id,
        ts_utc=ts,
        nonce=event_id,  # unique per event (do not truncate)
    )


def generate_campaign_events(
    *,
    campaign_id: str,
    family: str,
    hosts: Sequence[Tuple[str, str]],
    enrollment: Enrollment,
    base_time: datetime,
    include_benign_ratio: float = 0.35,
    ood: bool = False,
) -> Tuple[List[EventEnvelope], Dict[str, Any]]:
    """
    families: lateral | exfil | recon_lateral | fusion_chain | benign
    ood: different TTP timing/noise (slow drip, alternate ports, service accounts)

    fusion_chain: multi-key hop chain across ≥4 hosts. Each detector key covers a
    thin host pair; only cross-key fusion recovers the full truth set — the pack
    that makes detector-only lose and the correlator win.
    """
    events: List[EventEnvelope] = []
    eid = 0

    def next_id(prefix: str) -> str:
        nonlocal eid
        eid += 1
        return f"{campaign_id}-{prefix}-{eid:04d}"

    host_list = list(hosts)
    truth_hosts = [h for h, _ in host_list]

    if family == "benign":
        # Keep unique dests/host < recon_fanout threshold (5) to avoid FCR on benign-only.
        for i, (host, prod) in enumerate(host_list):
            for j in range(8):
                events.append(
                    _sign(
                        enrollment,
                        prod,
                        host,
                        "net_conn",
                        {
                            "dst_ip": f"10.0.{i}.{(j % 3) + 1}",
                            "dst_port": 443,
                            "bytes": 1200,
                            "egress": False,
                        },
                        _ts(base_time, i * 10 + j),
                        next_id("benign"),
                    )
                )
        gt = {
            "campaign_id": campaign_id,
            "host_ids": [],
            "stages": [],
            "family": "benign",
            "ood": ood,
        }
        return events, gt

    if family == "lateral":
        user = "svc-backup" if ood else "alice"
        # slow drip OOD vs burst
        step = 90 if ood else 15
        for i, (host, prod) in enumerate(host_list):
            events.append(
                _sign(
                    enrollment,
                    prod,
                    host,
                    "auth",
                    {"user": user, "result": "success", "src": "10.1.0.5"},
                    _ts(base_time, i * step),
                    next_id("auth"),
                )
            )
        stages = [{"name": "lateral_auth", "hosts": truth_hosts}]
    elif family == "exfil":
        dst = "198.51.100.77" if ood else "203.0.113.50"
        step = 120 if ood else 20
        nbytes = 800 if ood else 12_000
        for i, (host, prod) in enumerate(host_list):
            events.append(
                _sign(
                    enrollment,
                    prod,
                    host,
                    "net_conn",
                    {"dst_ip": dst, "dst_port": 8443 if ood else 443, "bytes": nbytes, "egress": True},
                    _ts(base_time, i * step),
                    next_id("exfil"),
                )
            )
        stages = [{"name": "micro_exfil", "hosts": truth_hosts}]
    elif family == "recon_lateral":
        user = "deploy" if ood else "bob"
        scanner, sprod = host_list[0]
        # fan-out scan
        for j in range(8):
            events.append(
                _sign(
                    enrollment,
                    sprod,
                    scanner,
                    "net_conn",
                    {
                        "dst_ip": f"10.20.30.{j+1}",
                        "dst_port": 22 if ood else 445,
                        "bytes": 60,
                        "egress": False,
                    },
                    _ts(base_time, j * (25 if ood else 5)),
                    next_id("recon"),
                )
            )
        for i, (host, prod) in enumerate(host_list):
            events.append(
                _sign(
                    enrollment,
                    prod,
                    host,
                    "auth",
                    {"user": user, "result": "success", "src": "10.1.0.9"},
                    _ts(base_time, 100 + i * (70 if ood else 12)),
                    next_id("auth"),
                )
            )
        stages = [
            {"name": "recon_fanout", "hosts": [scanner]},
            {"name": "lateral_auth", "hosts": truth_hosts},
        ]
    elif family == "fusion_chain":
        # Need ≥4 hosts so pair-sized detector alerts stay below Jaccard 0.5 vs truth.
        if len(host_list) < 4:
            raise ValueError("fusion_chain requires ≥4 hosts")
        user_a = "svc-backup" if ood else "alice"
        user_b = "svc-deploy" if ood else "bob"
        dst_bridge = "198.51.100.77" if ood else "203.0.113.50"
        dst_tail = "198.51.100.88" if ood else "203.0.113.60"
        step = 75 if ood else 18
        nbytes = 900 if ood else 11_000
        # Pair hops: auth A–B, exfil B–C, auth C–D, optional exfil D–E
        a_host, a_prod = host_list[0]
        b_host, b_prod = host_list[1]
        c_host, c_prod = host_list[2]
        d_host, d_prod = host_list[3]
        for i, (host, prod, user) in enumerate(
            [
                (a_host, a_prod, user_a),
                (b_host, b_prod, user_a),
                (c_host, c_prod, user_b),
                (d_host, d_prod, user_b),
            ]
        ):
            events.append(
                _sign(
                    enrollment,
                    prod,
                    host,
                    "auth",
                    {"user": user, "result": "success", "src": "10.1.0.5"},
                    _ts(base_time, i * step),
                    next_id("auth"),
                )
            )
        for i, (host, prod) in enumerate([(b_host, b_prod), (c_host, c_prod)]):
            events.append(
                _sign(
                    enrollment,
                    prod,
                    host,
                    "net_conn",
                    {
                        "dst_ip": dst_bridge,
                        "dst_port": 8443 if ood else 443,
                        "bytes": nbytes,
                        "egress": True,
                    },
                    _ts(base_time, 200 + i * step),
                    next_id("exfil"),
                )
            )
        if len(host_list) >= 5:
            e_host, e_prod = host_list[4]
            for i, (host, prod) in enumerate([(d_host, d_prod), (e_host, e_prod)]):
                events.append(
                    _sign(
                        enrollment,
                        prod,
                        host,
                        "net_conn",
                        {
                            "dst_ip": dst_tail,
                            "dst_port": 8443 if ood else 443,
                            "bytes": nbytes,
                            "egress": True,
                        },
                        _ts(base_time, 400 + i * step),
                        next_id("exfil"),
                    )
                )
        stages = [
            {"name": "lateral_auth", "hosts": truth_hosts[:4]},
            {"name": "micro_exfil", "hosts": truth_hosts[1:]},
        ]
    else:
        raise ValueError(f"unknown family {family}")

    # Benign chatter >= ~30%
    benign_n = max(1, int(len(events) * include_benign_ratio / (1 - include_benign_ratio)))
    for j in range(benign_n):
        host, prod = host_list[j % len(host_list)]
        events.append(
            _sign(
                enrollment,
                prod,
                host,
                "dns",
                {"query": f"update{j}.example.com", "qtype": "A"},
                _ts(base_time, 500 + j),
                next_id("dns"),
            )
        )

    events.sort(key=lambda e: e.ts_utc)
    # Cap 200-500
    if len(events) > 500:
        events = events[:500]

    gt = {
        "campaign_id": campaign_id,
        "host_ids": truth_hosts,
        "stages": stages,
        "family": family,
        "ood": ood,
    }
    return events, gt


def write_pack(
    path: Path,
    events: Sequence[EventEnvelope],
    ground_truth: Mapping[str, Any],
) -> None:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as fh:
        fh.write(
            json.dumps({"type": "ground_truth", **ground_truth}, separators=(",", ":")) + "\n"
        )
        for env in events:
            fh.write(json.dumps({"type": "event", **env.to_dict()}, separators=(",", ":")) + "\n")


def load_pack_events(path: Path) -> Tuple[List[EventEnvelope], Dict[str, Any]]:
    events: List[EventEnvelope] = []
    gt: Dict[str, Any] = {}
    for line in Path(path).read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        rec = json.loads(line)
        if rec.get("type") == "ground_truth":
            gt = {k: v for k, v in rec.items() if k != "type"}
        elif rec.get("type") == "event":
            data = {k: v for k, v in rec.items() if k != "type"}
            events.append(EventEnvelope.from_dict(data))
    return events, gt


def resign_events(
    events: Sequence[EventEnvelope],
    enrollment: Enrollment,
) -> List[EventEnvelope]:
    """Re-HMAC pack events with the caller's lab enrollment (demo / clean-clone path)."""
    out: List[EventEnvelope] = []
    for env in events:
        secret = enrollment.require(env.producer_id, env.host_id)
        out.append(
            sign_envelope(
                producer_id=env.producer_id,
                host_id=env.host_id,
                payload_type=env.payload_type,
                payload=env.payload,
                secret=secret,
                event_id=env.event_id,
                ts_utc=env.ts_utc,
                nonce=env.nonce,
            )
        )
    return out


def feed_bus(
    bus: JsonlBus,
    events: Sequence[EventEnvelope],
    enrollment: Enrollment,
) -> int:
    """Publish via the same verified ingest path as BYO."""
    n = 0
    for env in events:
        publish_verified(bus, env, enrollment)
        n += 1
    return n
