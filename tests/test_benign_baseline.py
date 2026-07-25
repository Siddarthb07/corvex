"""OTRF adapter + pre-committed benign-baseline bars."""

from __future__ import annotations

import json
from pathlib import Path

from corvex.adapters.otrf import adapt_otrf_export, normalize_otrf_record
from corvex.eval.benign_baseline import (
    MAX_FP_ISO_PER_HOST_HOUR,
    MIN_HOST_HOURS,
    auth_hop_degrees,
    host_hours_from_events,
    hub_coverage,
    score_benign_baseline,
)

ROOT = Path(__file__).resolve().parents[1]
FIXTURE = ROOT / "fixtures" / "benign" / "otrf_smoke.jsonl"


def test_normalize_remaps_security_firewall_and_hostname():
    rec = normalize_otrf_record(
        {
            "Channel": "Security",
            "EventID": 5156,
            "Hostname": "WORKSTATION6.theshire.local",
            "@timestamp": "2020-09-20T16:17:10.000Z",
            "DestAddress": "198.51.100.40",
            "DestPort": 443,
        }
    )
    assert rec["Computer"] == "WORKSTATION6.theshire.local"
    assert rec["channel"] == "firewall" or rec["Channel"] == "firewall"
    assert rec["EventData"]["DestAddress"] == "198.51.100.40"


def test_adapt_otrf_smoke_skips_noise_and_maps_types():
    envs, stats = adapt_otrf_export(FIXTURE)
    assert stats["adapted"] >= 5
    assert stats["skipped"] >= 1  # 4688
    types = {e["payload_type"] for e in envs}
    assert "auth" in types
    assert "net_conn" in types
    hosts = {e["host_id"] for e in envs}
    assert "workstation5" in hosts
    assert "mordordc" in hosts


def test_bars_locked_constants():
    assert MIN_HOST_HOURS == 72.0
    assert MAX_FP_ISO_PER_HOST_HOUR == 1.0 / 1000.0


def test_mixed_corpus_cannot_pass_even_with_zero_fp():
    hub = hub_coverage({"a": 1}, n_hosts=3)
    scored = score_benign_baseline(
        corpus_kind="mixed",
        host_hours=100.0,
        n_hosts=3,
        fp_iso=0,
        fp_seal=0,
        hub=hub,
    )
    assert scored["gate"] == "INCOMPLETE"
    assert scored["claim_sentence_still_applies"] is True


def test_pure_benign_pass_and_fail():
    hub = hub_coverage({"jump": 3, "a": 1, "b": 1}, n_hosts=3)
    assert hub["hub_coverage"] == "OK"
    ok = score_benign_baseline(
        corpus_kind="pure_benign",
        host_hours=100.0,
        n_hosts=3,
        fp_iso=0,
        fp_seal=0,
        hub=hub,
    )
    assert ok["gate"] == "PASS"
    bad = score_benign_baseline(
        corpus_kind="home_lab_capture",
        host_hours=100.0,
        n_hosts=3,
        fp_iso=1,  # 1/100 = 0.01 > 0.001
        fp_seal=0,
        hub=hub,
    )
    assert bad["gate"] == "FAIL"


def test_hub_gap_when_no_high_degree_host():
    hub = hub_coverage({"a": 1, "b": 1}, n_hosts=4)
    assert hub["hub_coverage"] == "GAP"


def test_host_hours_and_auth_degree_helpers():
    events = [
        {"host_id": "a", "ts_utc": "2026-01-01T00:00:00Z", "payload_type": "auth", "payload": {"src": "b"}},
        {"host_id": "a", "ts_utc": "2026-01-01T10:00:00Z", "payload_type": "auth", "payload": {"src": "b"}},
        {"host_id": "b", "ts_utc": "2026-01-01T00:00:00Z", "payload_type": "auth", "payload": {"src": "a"}},
        {"host_id": "b", "ts_utc": "2026-01-01T05:00:00Z", "payload_type": "auth", "payload": {"src": "a"}},
    ]
    H, per = host_hours_from_events(events)
    assert H == 15.0  # 10h + 5h
    assert per["a"] == 10.0
    deg = auth_hop_degrees(events)
    assert deg["a"] == 1
    assert deg["b"] == 1
