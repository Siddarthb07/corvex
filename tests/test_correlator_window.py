"""Stage A honesty: window_seconds, CDN fanout skip, anti-jumpbox merge."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path

from corvex.audit import AuditLog
from corvex.correlator import Correlator, CorrelatorConfig
from corvex.envelope import EventEnvelope
from corvex.store import CampaignStore


def _ts(base: datetime, seconds: float) -> str:
    return (base + timedelta(seconds=seconds)).strftime("%Y-%m-%dT%H:%M:%SZ")


def _auth(
    eid: str, host: str, user: str, ts: str, *, src: str | None = None
) -> EventEnvelope:
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


def _corr(tmp_path: Path) -> Correlator:
    return Correlator(
        CampaignStore(tmp_path / "campaigns.jsonl"),
        AuditLog(tmp_path / "audit.jsonl"),
        config=CorrelatorConfig(window_seconds=600, min_hosts=2),
        allow_unverified=True,
    )


def test_window_splits_same_user_across_48h(tmp_path: Path) -> None:
    base = datetime(2026, 6, 1, 8, 0, 0, tzinfo=timezone.utc)
    c = _corr(tmp_path)
    c.ingest(
        [
            _auth("e1", "host-a", "svc", _ts(base, 0)),
            _auth("e2", "host-b", "svc", _ts(base, 30)),
            _auth("e3", "host-a", "svc", _ts(base, 172800)),
            _auth("e4", "host-b", "svc", _ts(base, 172830)),
        ]
    )
    camps = c.store.all()
    assert len(camps) == 2
    for camp in camps:
        assert set(camp.host_ids) == {"host-a", "host-b"}


def test_ubiquitous_cdn_does_not_form_campaign(tmp_path: Path) -> None:
    base = datetime(2026, 6, 1, 8, 0, 0, tzinfo=timezone.utc)
    c = _corr(tmp_path)
    events = [
        _exfil(f"cdn-{h}", h, "104.18.32.7", 8000, _ts(base, i * 30))
        for i, h in enumerate(["host-a", "host-b", "host-c", "host-d", "host-e"])
    ]
    c.ingest(events)
    assert c.store.all() == []


def test_single_jumpbox_does_not_glue_campaigns(tmp_path: Path) -> None:
    base = datetime(2026, 6, 1, 8, 0, 0, tzinfo=timezone.utc)
    c = _corr(tmp_path)
    c.ingest(
        [
            _auth("a1", "host-a", "svc-backup", _ts(base, 0)),
            _auth("a2", "host-b", "svc-backup", _ts(base, 30)),
            _auth("a3", "host-c", "svc-backup", _ts(base, 60)),
            _auth("b1", "host-c", "helpdesk", _ts(base, 120)),
            _auth("b2", "host-d", "helpdesk", _ts(base, 150)),
        ]
    )
    camps = c.store.all()
    host_sets = {frozenset(x.host_ids) for x in camps}
    assert frozenset({"host-a", "host-b", "host-c"}) in host_sets
    assert frozenset({"host-c", "host-d"}) in host_sets
    assert not any(set(x.host_ids) == {"host-a", "host-b", "host-c", "host-d"} for x in camps)


def test_shared_svc_account_fanout_does_not_overmerge_innocents(tmp_path: Path) -> None:
    """Fleet-wide sql-svc (APT + DBA + BI) must not quarantine innocents."""
    base = datetime(2026, 7, 25, 12, 0, 0, tzinfo=timezone.utc)
    c = _corr(tmp_path)
    c.ingest(
        [
            _auth("w1", "host-a", "sql-web", _ts(base, 42)),
            _auth("sa1", "host-b", "sa", _ts(base, 52), src="host-a"),
            _auth("svc1", "host-c", "sql-svc", _ts(base, 68), src="host-b"),
            _auth("svc2", "host-b", "sql-svc", _ts(base, 78), src="host-a"),
            _auth("dba", "host-d", "sql-svc", _ts(base, 60)),
            _auth("bi", "host-e", "sql-svc", _ts(base, 70)),
            _exfil("x1", "host-b", "198.51.100.44", 28000, _ts(base, 95)),
            _exfil("x2", "host-c", "198.51.100.44", 22000, _ts(base, 102)),
        ]
    )
    camps = c.store.all()
    union = set()
    for camp in camps:
        union |= set(camp.host_ids)
    assert {"host-a", "host-b", "host-c"} <= union
    assert "host-d" not in union
    assert "host-e" not in union


def test_auth_src_host_joins_lateral_chain(tmp_path: Path) -> None:
    base = datetime(2026, 7, 25, 12, 0, 0, tzinfo=timezone.utc)
    c = _corr(tmp_path)
    c.ingest(
        [
            _auth("sa1", "host-b", "sa", _ts(base, 10), src="host-a"),
            _auth("sa2", "host-b", "sa", _ts(base, 20), src="host-a"),
            _exfil("x1", "host-b", "198.51.100.9", 12000, _ts(base, 40)),
            _exfil("x2", "host-c", "198.51.100.9", 11000, _ts(base, 50)),
        ]
    )
    camps = c.store.all()
    assert any(set(c.host_ids) >= {"host-a", "host-b", "host-c"} for c in camps)


def test_dns_apex_forms_multi_host_campaign(tmp_path: Path) -> None:
    base = datetime(2026, 7, 25, 12, 0, 0, tzinfo=timezone.utc)
    c = _corr(tmp_path)

    def _dns(eid: str, host: str, query: str, ts: str) -> EventEnvelope:
        return EventEnvelope(
            schema_ver="1",
            event_id=eid,
            producer_id="test",
            host_id=host,
            ts_utc=ts,
            nonce=eid,
            payload_type="dns",
            payload={"query": query, "qtype": "A"},
            hmac="00",
        )

    c.ingest(
        [
            _dns("d1", "host-a", "a1.c2.evil.test", _ts(base, 0)),
            _dns("d2", "host-b", "b1.c2.evil.test", _ts(base, 10)),
            _dns("d3", "host-c", "payload.c2.evil.test", _ts(base, 20)),
        ]
    )
    camps = c.store.all()
    assert any(set(x.host_ids) >= {"host-a", "host-b", "host-c"} for x in camps)


def test_same_user_resume_across_window_gap(tmp_path: Path) -> None:
    base = datetime(2026, 7, 25, 12, 0, 0, tzinfo=timezone.utc)
    c = _corr(tmp_path)
    c.ingest(
        [
            _auth("a1", "host-a", "sleeper", _ts(base, 0)),
            _auth("a2", "host-b", "sleeper", _ts(base, 20), src="host-a"),
            _exfil("x1", "host-b", "198.51.100.90", 12000, _ts(base, 40)),
            _auth("b1", "host-b", "sleeper", _ts(base, 700)),
            _auth("b2", "host-c", "sleeper", _ts(base, 720)),
            _exfil("x2", "host-c", "198.51.100.91", 15000, _ts(base, 740)),
        ]
    )
    camps = c.store.all()
    assert any(set(x.host_ids) >= {"host-a", "host-b", "host-c"} for x in camps)


def test_four_host_hop_chain_not_poisoned(tmp_path: Path) -> None:
    """svc-deploy across 4 hosts with host-* hops must not be dropped as shared-svc."""
    base = datetime(2026, 7, 25, 12, 0, 0, tzinfo=timezone.utc)
    c = _corr(tmp_path)
    c.ingest(
        [
            _auth("a", "host-a", "svc-deploy", _ts(base, 10)),
            _auth("b", "host-b", "svc-deploy", _ts(base, 14), src="host-a"),
            _auth("c", "host-c", "svc-deploy", _ts(base, 18), src="host-b"),
            _auth("d", "host-d", "svc-deploy", _ts(base, 22), src="host-c"),
            _exfil("x1", "host-d", "198.51.100.40", 30000, _ts(base, 35)),
            _exfil("x2", "host-c", "198.51.100.40", 22000, _ts(base, 38)),
        ]
    )
    camps = c.store.all()
    union = set()
    for camp in camps:
        union |= set(camp.host_ids)
    assert {"host-a", "host-b", "host-c", "host-d"} <= union


def test_sequential_reuse_shape_gap_splits(tmp_path: Path) -> None:
    """lim09b shape: DNS C2 then tasksvc lateral after >=window gap → ≥2 campaigns."""
    base = datetime(2026, 7, 25, 12, 0, 0, tzinfo=timezone.utc)
    c = _corr(tmp_path)

    def _dns(eid: str, host: str, query: str, ts: str) -> EventEnvelope:
        return EventEnvelope(
            schema_ver="1",
            event_id=eid,
            producer_id="test",
            host_id=host,
            ts_utc=ts,
            nonce=eid,
            payload_type="dns",
            payload={"query": query, "qtype": "A"},
            hmac="00",
        )

    c.ingest(
        [
            _dns("d1", "host-a", "a1.c2.evil.test", _ts(base, 0)),
            _dns("d2", "host-b", "b1.c2.evil.test", _ts(base, 10)),
            _dns("d3", "host-c", "c1.c2.evil.test", _ts(base, 20)),
            _auth("t1", "host-a", "tasksvc", _ts(base, 630)),
            _auth("t2", "host-b", "tasksvc", _ts(base, 640), src="host-a"),
            _auth("t3", "host-c", "tasksvc", _ts(base, 650), src="host-b"),
            _exfil("x1", "host-c", "198.51.100.110", 17000, _ts(base, 665)),
        ]
    )
    camps = c.store.all()
    assert len(camps) >= 2
    kinds = []
    for camp in camps:
        kinds.append({str(st.get("name")) for st in camp.stages})
    assert any("dns_beacon" in k for k in kinds)
    assert any("lateral_auth" in k for k in kinds)


def test_hub_degree_refuses_distinct_lateral_merge(tmp_path: Path) -> None:
    """High-degree overlap must not glue two distinct lateral users (lim09 shape)."""
    base = datetime(2026, 7, 25, 12, 0, 0, tzinfo=timezone.utc)
    c = _corr(tmp_path)
    # host-c is a hub: peers a,b from Admin and d,e from ransom via hops
    c.ingest(
        [
            _auth("a1", "host-a", "Administrator", _ts(base, 0)),
            _auth("a2", "host-b", "Administrator", _ts(base, 8), src="host-a"),
            _auth("a3", "host-c", "Administrator", _ts(base, 16), src="host-b"),
            _exfil("ax", "host-c", "198.51.100.20", 22000, _ts(base, 30)),
            _auth("s1", "host-b", "spray-hit", _ts(base, 5)),
            _auth("s2", "host-c", "spray-hit", _ts(base, 14), src="host-b"),
            _auth("s3", "host-d", "spray-hit", _ts(base, 24), src="host-c"),
            _exfil("sx", "host-d", "198.51.100.60", 18000, _ts(base, 40)),
            _auth("r1", "host-c", "ransom-op", _ts(base, 10)),
            _auth("r2", "host-d", "ransom-op", _ts(base, 20), src="host-c"),
            _auth("r3", "host-e", "ransom-op", _ts(base, 32), src="host-d"),
            _exfil("rx", "host-e", "198.51.100.100", 25000, _ts(base, 50)),
        ]
    )
    camps = c.store.all()
    users = set()
    for camp in camps:
        for st in camp.stages:
            if st.get("name") == "lateral_auth" and st.get("user"):
                users.add(str(st["user"]))
    # Should retain distinct operator campaigns, not one blob covering all users.
    assert len(users) >= 2
    assert not any(
        {"Administrator", "spray-hit", "ransom-op"}
        <= {
            str(st.get("user"))
            for st in camp.stages
            if st.get("name") == "lateral_auth"
        }
        for camp in camps
    )
