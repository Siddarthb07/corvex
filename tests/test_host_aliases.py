"""Adapter host_aliases normalize split-brain hostnames before correlator."""

from __future__ import annotations

from corvex.adapters.attack_repos import adapt_attack_manifest


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
