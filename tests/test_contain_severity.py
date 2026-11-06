"""Scale-invariant severity bands → isolate scope.

Fixtures use default ContainPolicy thresholds (low 0.25 / medium 0.45 / critical 0.75,
blast 25/50/100, absolute critical = 5 hosts inside 30 minutes). Scores below were
checked against score_campaign so a band assertion cannot pass on the wrong band.
"""

from __future__ import annotations

from corvex.contain.policy import ContainPolicy
from corvex.contain.severity import resolve_isolate_scope


def _estate(n: int) -> list:
    return [f"h{i}" for i in range(n)]


def test_blast_allows_single_host_on_estate_n1():
    from corvex.contain.policy import enforce_blast_cap

    out = enforce_blast_cap(["solo"], estate_n=1, band="low", policy=ContainPolicy())
    assert out.get("refused") is not True
    assert out["targets"] == ["solo"]
    assert out["max_hosts"] >= 1


def test_observe_band():
    out = resolve_isolate_scope(
        {"host_ids": ["h0"], "stages": [], "score": 0.1},
        estate_hosts=_estate(8),
        policy=ContainPolicy(),
    )
    assert out["band"] == "observe"
    assert out["scope"] == "observe"
    assert out["verb"] == "IsolateHost"
    assert out["targets"] == []
    assert out["propose"] is False
    assert out["severity"]["score"] < 0.25


def test_low_band_flagged_only():
    flagged = ["h0", "h1", "h2"]
    out = resolve_isolate_scope(
        {
            "host_ids": flagged,
            "stages": [{"name": "lateral_auth"}],
            "confidence": 0.7,
        },
        estate_hosts=_estate(12),
        policy=ContainPolicy(),
    )
    assert out["band"] == "low"
    assert out["scope"] == "flagged"
    assert out["verb"] == "IsolateHost"
    assert out["targets"] == flagged
    assert out["propose"] is True
    assert out["blast"].get("refused") is not True


def test_medium_band_peer_risk():
    out = resolve_isolate_scope(
        {
            "host_ids": ["h0", "h1"],
            "stages": [
                {"name": "lateral_auth", "hosts": ["h0", "h1", "h2"]},
                {"name": "micro_exfil", "hosts": ["h0"]},
            ],
            "confidence": 0.8,
        },
        estate_hosts=_estate(10),
        policy=ContainPolicy(),
    )
    assert out["band"] == "medium"
    assert out["scope"] == "peer_risk"
    assert out["verb"] == "IsolateHost"
    assert out["targets"] == ["h0", "h1", "h2"]
    assert "h9" not in out["targets"]
    assert out["propose"] is True


def test_critical_band_estate_lockdown():
    estate = ["h1", "h2", "h3", "h4"]
    out = resolve_isolate_scope(
        {
            "host_ids": estate,
            "stages": [
                {"name": "lateral_auth"},
                {"name": "micro_exfil"},
                {"name": "dns_beacon"},
                {"name": "recon_fanout"},
            ],
            "confidence": 0.95,
        },
        estate_hosts=estate,
        policy=ContainPolicy(),
    )
    assert out["severity"]["features"]["absolute_critical"] is False
    assert out["band"] == "critical"
    assert out["scope"] == "estate_lockdown"
    assert out["verb"] == "EstateLockdown"
    assert out["targets"] == estate
    assert out["auto_enforce"] is False
    assert out["requires_dual_control"] is True


def test_soc_allowlist_stripped():
    pol = ContainPolicy(soc_allowlist=["soc-box"])
    low = resolve_isolate_scope(
        {
            "host_ids": ["h0", "h1", "soc-box"],
            "stages": [{"name": "lateral_auth"}],
            "confidence": 0.7,
        },
        estate_hosts=["h0", "h1", "soc-box"] + [f"x{i}" for i in range(9)],
        policy=pol,
    )
    assert low["band"] == "low"
    assert low["targets"] == ["h0", "h1"]
    assert "soc-box" not in low["targets"]

    estate = ["h1", "h2", "h3", "h4", "soc-box"]
    crit = resolve_isolate_scope(
        {
            "host_ids": estate,
            "stages": [
                {"name": "lateral_auth"},
                {"name": "micro_exfil"},
                {"name": "dns_beacon"},
                {"name": "recon_fanout"},
            ],
            "confidence": 0.95,
        },
        estate_hosts=estate,
        policy=pol,
    )
    assert crit["band"] == "critical"
    assert crit["scope"] == "estate_lockdown"
    assert crit["targets"] == ["h1", "h2", "h3", "h4"]
    assert "soc-box" in crit["soc_preserved"]


def test_blast_radius_refuse():
    flagged = _estate(8)
    out = resolve_isolate_scope(
        {
            "host_ids": flagged,
            "stages": [{"name": "lateral_auth"}],
            "confidence": 0.6,
        },
        estate_hosts=_estate(20),
        policy=ContainPolicy(),
    )
    assert out["band"] == "low"
    assert out["blast"]["refused"] is True
    assert out["propose"] is False
    assert out["blast"]["max_hosts"] == 5
    assert len(out["targets"]) == 5
    assert any("Blast radius refuse" in line for line in out["honesty"])


def test_absolute_critical_five_hosts_in_ten_minutes():
    estate = _estate(20)
    flagged = estate[:5]
    fast = {
        "host_ids": flagged,
        "stages": [{"name": "micro_exfil"}],
        "confidence": 0.6,
        "first_seen": "2026-11-06T12:00:00Z",
        "last_seen": "2026-11-06T12:10:00Z",
    }
    out = resolve_isolate_scope(fast, estate_hosts=estate, policy=ContainPolicy())
    feats = out["severity"]["features"]
    assert feats["host_count"] == 5
    assert feats["span_minutes"] == 10.0
    assert feats["absolute_critical"] is True
    # Score stays under the critical (and medium) cutoffs — pace is what escalates.
    assert out["severity"]["score"] < 0.45
    assert out["band"] == "critical"
    assert out["scope"] == "estate_lockdown"
    assert out["verb"] == "EstateLockdown"
    assert out["targets"] == estate

    slow = dict(fast)
    slow["last_seen"] = "2026-11-06T12:45:00Z"
    held = resolve_isolate_scope(slow, estate_hosts=estate, policy=ContainPolicy())
    assert held["severity"]["features"]["absolute_critical"] is False
    assert held["severity"]["features"]["span_minutes"] == 45.0
    assert held["band"] == "low"
    assert held["scope"] == "flagged"
    assert held["targets"] == flagged
