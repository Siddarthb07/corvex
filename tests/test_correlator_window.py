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


def _auth(eid: str, host: str, user: str, ts: str) -> EventEnvelope:
    return EventEnvelope(
        schema_ver="1",
        event_id=eid,
        producer_id="test",
        host_id=host,
        ts_utc=ts,
        nonce=eid,
        payload_type="auth",
        payload={"user": user, "result": "success"},
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
