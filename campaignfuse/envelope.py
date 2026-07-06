"""EventEnvelope v1 — host-bound HMAC authentication."""

from __future__ import annotations

import hashlib
import hmac
import json
import secrets
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from typing import Any, Dict, Mapping, Optional


SCHEMA_VER = "1"


def _canonical_payload(payload: Mapping[str, Any]) -> bytes:
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")


def payload_hash(payload: Mapping[str, Any]) -> str:
    return hashlib.sha256(_canonical_payload(payload)).hexdigest()


def hmac_message(
    schema_ver: str,
    producer_id: str,
    host_id: str,
    event_id: str,
    ts_utc: str,
    nonce: str,
    payload_type: str,
    payload_digest: str,
) -> bytes:
    parts = [
        schema_ver,
        producer_id,
        host_id,
        event_id,
        ts_utc,
        nonce,
        payload_type,
        payload_digest,
    ]
    return "||".join(parts).encode("utf-8")


@dataclass(frozen=True)
class EventEnvelope:
    schema_ver: str
    event_id: str
    producer_id: str
    host_id: str
    ts_utc: str
    nonce: str
    payload_type: str
    payload: Dict[str, Any]
    hmac: str

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "EventEnvelope":
        return cls(
            schema_ver=str(data["schema_ver"]),
            event_id=str(data["event_id"]),
            producer_id=str(data["producer_id"]),
            host_id=str(data["host_id"]),
            ts_utc=str(data["ts_utc"]),
            nonce=str(data["nonce"]),
            payload_type=str(data["payload_type"]),
            payload=dict(data["payload"]),
            hmac=str(data["hmac"]),
        )


def sign_envelope(
    *,
    producer_id: str,
    host_id: str,
    payload_type: str,
    payload: Mapping[str, Any],
    secret: bytes,
    event_id: Optional[str] = None,
    ts_utc: Optional[str] = None,
    nonce: Optional[str] = None,
) -> EventEnvelope:
    eid = event_id or secrets.token_hex(16)
    ts = ts_utc or datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")
    n = nonce or secrets.token_hex(8)
    digest = payload_hash(payload)
    msg = hmac_message(SCHEMA_VER, producer_id, host_id, eid, ts, n, payload_type, digest)
    mac = hmac.new(secret, msg, hashlib.sha256).hexdigest()
    return EventEnvelope(
        schema_ver=SCHEMA_VER,
        event_id=eid,
        producer_id=producer_id,
        host_id=host_id,
        ts_utc=ts,
        nonce=n,
        payload_type=payload_type,
        payload=dict(payload),
        hmac=mac,
    )


def verify_envelope(env: EventEnvelope, secret: bytes) -> bool:
    digest = payload_hash(env.payload)
    msg = hmac_message(
        env.schema_ver,
        env.producer_id,
        env.host_id,
        env.event_id,
        env.ts_utc,
        env.nonce,
        env.payload_type,
        digest,
    )
    expected = hmac.new(secret, msg, hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected, env.hmac)
