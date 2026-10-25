"""Adapter + runtime host_aliases normalize split-brain hostnames."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path

from corvex.adapters.attack_repos import adapt_attack_manifest
from corvex.audit import AuditLog
from corvex.correlator import Correlator, CorrelatorConfig
from corvex.envelope import EventEnvelope
from corvex.store import CampaignStore


def test_host_aliases_rewrite_emit_host():
    man = {
        "campaign_id": "alias-test",
        "hosts": ["host-a", "host-b", "host-c", "host-d", "host-b-dhcp"],
        "truth_hosts": ["host-a", "host-b", "host-c"],
        "producers": {
            "host-a": "prod-a",
            "host-b": "prod-b",
            "host-c": "prod-c",
            "host-d": "prod-d",
            "host-b-dhcp": "prod-b",
        },
        "host_aliases": {"host-b-dhcp": "host-b"},
        "steps": [
            {"kind": "auth", "host": "host-a", "user": "ops", "src": "203.0.113.1", "offset_seconds": 0},
            {
                "kind": "auth",
                "host": "host-b",
                "user": "ops",
                "src": "10.1.0.11",
                "offset_seconds": 8,
                "emit_host": "host-b-dhcp",
            },
            {"kind": "auth", "host": "host-c", "user": "ops", "src": "10.1.0.12", "offset_seconds": 16},
            {
                "kind": "exfil",
                "host": "host-b",
                "dst_ip": "198.51.100.70",
                "bytes": 16000,
                "offset_seconds": 30,
                "emit_host": "host-b-dhcp",
            },
        ],
    }
    events, gt = adapt_attack_manifest(man)
    assert all(e["host_id"] != "host-b-dhcp" for e in events)
    assert any(e["host_id"] == "host-b" for e in events)
    assert gt.get("host_aliases") == {"host-b-dhcp": "host-b"}


def test_correlator_runtime_host_aliases_stitch_dhcp(tmp_path: Path) -> None:
    """Live/BYO path: events still labeled host-b-dhcp; correlator aliases stitch."""
    base = datetime(2026, 7, 25, 14, 0, 0, tzinfo=timezone.utc)

    def _ts(sec: float) -> str:
        return (base + timedelta(seconds=sec)).strftime("%Y-%m-%dT%H:%M:%SZ")

    def _auth(eid: str, host: str, user: str, ts: str, *, src: str | None = None) -> EventEnvelope:
        payload = {"user": user, "result": "success"}
        if src:
            payload["src"] = src
        return EventEnvelope(
            schema_ver="1",
            event_id=eid,
            producer_id="test",
            host_id=host,
            ts_utc=ts,
            nonce=eid,
            payload_type="auth",
            payload=payload,
            hmac="00",
        )

    def _exfil(eid: str, host: str, dst: str, nbytes: int, ts: str) -> EventEnvelope:
        return EventEnvelope(
            schema_ver="1",
            event_id=eid,
            producer_id="test",
            host_id=host,
            ts_utc=ts,
            nonce=eid,
            payload_type="net_conn",
            payload={"dst_ip": dst, "dst_port": 443, "bytes": nbytes, "egress": True},
            hmac="00",
        )

    c = Correlator(
        CampaignStore(tmp_path / "campaigns.jsonl"),
        AuditLog(tmp_path / "audit.jsonl"),
        config=CorrelatorConfig(
            window_seconds=600,
            min_hosts=2,
            host_aliases={"host-b-dhcp": "host-b"},
        ),
        allow_unverified=True,
    )
    c.ingest(
        [
            _auth("a1", "host-a", "ops", _ts(0)),
            _auth("a2", "host-b", "ops", _ts(8), src="10.1.0.11"),
            _auth("a3", "host-b-dhcp", "ops", _ts(20), src="10.1.0.11"),
            _auth("a4", "host-c", "ops", _ts(28), src="10.1.0.12"),
            _exfil("x1", "host-c", "198.51.100.70", 19000, _ts(40)),
            _exfil("x2", "host-b-dhcp", "198.51.100.70", 16000, _ts(44)),
        ]
    )
    camps = c.store.all()
    assert any(set(camp.host_ids) >= {"host-a", "host-b", "host-c"} for camp in camps)
    assert not any("host-b-dhcp" in camp.host_ids for camp in camps)
