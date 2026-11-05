#!/usr/bin/env python3
"""Measure single-writer JSONL bus + CampaignStore rewrite costs (lab limits).

Produces reports/single_writer_limits.json for the systems paper — not a field
throughput claim. Documents that Corvex is an append/rewrite file pipeline.
"""

from __future__ import annotations

import json
import tempfile
import time
from pathlib import Path

from corvex.bus import JsonlBus
from corvex.envelope import EventEnvelope
from corvex.store import Campaign, CampaignStore


def _envelope(i: int) -> EventEnvelope:
    return EventEnvelope(
        schema_ver="1",
        event_id=f"e-{i}",
        producer_id="bench",
        host_id=f"host-{i % 8}",
        ts_utc="2026-11-05T00:00:00Z",
        nonce=f"n-{i}",
        payload_type="auth",
        payload={"user": "svc", "result": "success"},
        hmac="00",
    )


def bench_bus_append(n: int) -> dict:
    with tempfile.TemporaryDirectory() as td:
        path = Path(td) / "events.jsonl"
        bus = JsonlBus(path)
        t0 = time.perf_counter()
        for i in range(n):
            bus.publish(_envelope(i))
        elapsed = time.perf_counter() - t0
        size = path.stat().st_size
    return {
        "n_events": n,
        "seconds": round(elapsed, 6),
        "events_per_sec": round(n / elapsed, 2) if elapsed else None,
        "bytes": size,
    }


def bench_store_rewrite(n_upserts: int, n_campaigns: int = 20) -> dict:
    with tempfile.TemporaryDirectory() as td:
        path = Path(td) / "campaigns.jsonl"
        store = CampaignStore(path)
        camps = [
            Campaign(
                campaign_id=f"c-{i}",
                host_ids=[f"host-{i}", f"host-{(i + 1) % 8}"],
                stages=[{"name": "lateral_auth", "hosts": [f"host-{i}"]}],
                evidence=[],
                score=1.0,
            )
            for i in range(n_campaigns)
        ]
        t0 = time.perf_counter()
        for j in range(n_upserts):
            store.upsert(camps[j % n_campaigns])
        elapsed = time.perf_counter() - t0
        size = path.stat().st_size if path.exists() else 0
    return {
        "n_upserts": n_upserts,
        "n_campaigns": n_campaigns,
        "seconds": round(elapsed, 6),
        "upserts_per_sec": round(n_upserts / elapsed, 2) if elapsed else None,
        "bytes_after": size,
        "note": "each upsert rewrites the full campaigns.jsonl (single-writer)",
    }


def main() -> None:
    root = Path(__file__).resolve().parents[1]
    out = {
        "schema_ver": "1",
        "mode": "local_tmpfs_or_disk_microbench",
        "claim": (
            "Lab single-writer file pipeline limits only. "
            "Not multi-writer bus throughput; not enterprise SIEM scale."
        ),
        "bus_append": {
            "n_1k": bench_bus_append(1000),
            "n_10k": bench_bus_append(10000),
        },
        "store_rewrite": {
            "upserts_200": bench_store_rewrite(200),
            "upserts_1000": bench_store_rewrite(1000),
        },
    }
    reports = root / "reports"
    reports.mkdir(parents=True, exist_ok=True)
    path = reports / "single_writer_limits.json"
    path.write_text(json.dumps(out, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(out, indent=2))
    print(f"wrote {path}")


if __name__ == "__main__":
    main()
