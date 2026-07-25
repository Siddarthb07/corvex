"""Adapt flat Docker-lab bus rows into signed EventEnvelopes (offline lab replay).

Lab attackers write ``{kind, host_id, ...}`` JSONL. Fusion/recompute re-signs with
the operator's lab enrollment so one correlator path can verify HMAC. This is
**lab adapter signing**, not proof of remote host provenance.
"""

from __future__ import annotations

from typing import Any, Mapping, Optional, Tuple

from corvex.auth import AuthError, Enrollment
from corvex.envelope import EventEnvelope, sign_envelope
from corvex.lab_enroll import DEMO_HOSTS


def _producer_for(host_id: str, host_producers: Optional[Mapping[str, str]] = None) -> str:
    if host_producers and host_id in host_producers:
        return host_producers[host_id]
    if host_id in DEMO_HOSTS:
        return DEMO_HOSTS[host_id]
    if host_id == "host-pc":
        return "prod-pc"
    raise KeyError(f"unknown lab host_id={host_id}")


def adapt_flat_lab_event(
    raw: Mapping[str, Any],
    enrollment: Enrollment,
    *,
    seq: int,
    host_producers: Optional[Mapping[str, str]] = None,
) -> EventEnvelope:
    """Convert one flat lab row into a signed envelope using ``enrollment``."""
    host_id = str(raw["host_id"])
    producer = _producer_for(host_id, host_producers)
    secret = enrollment.require(producer, host_id)
    kind = raw.get("kind") or raw.get("payload_type")
    ts = str(raw.get("ts_utc") or "")
    if kind == "net_conn" or raw.get("payload_type") == "net_conn":
        payload = {
            "dst_ip": raw.get("dst_ip"),
            "dst_port": int(raw.get("dst_port") or 443),
            "bytes": int(raw.get("bytes") or 0),
            "egress": bool(raw.get("egress", False)),
            "lab_adapted": True,
        }
        payload_type = "net_conn"
        prefix = "lab-net"
    elif kind == "auth" or raw.get("payload_type") == "auth":
        payload = {
            "user": raw.get("user"),
            "result": raw.get("result"),
            "src": raw.get("src"),
            "lab_adapted": True,
        }
        payload_type = "auth"
        prefix = "lab-auth"
    else:
        raise ValueError(f"unsupported flat lab kind={kind!r}")
    return sign_envelope(
        producer_id=producer,
        host_id=host_id,
        payload_type=payload_type,
        payload=payload,
        secret=secret,
        event_id=f"{prefix}-{host_id}-{seq:06d}",
        ts_utc=ts or None,
        nonce=f"{prefix}-{host_id}-{seq:06d}-{ts}",
    )


def is_flat_lab_row(rec: Mapping[str, Any]) -> bool:
    if rec.get("schema_ver") and rec.get("payload_type"):
        return False
    return bool(rec.get("kind") and rec.get("host_id"))


def try_adapt_row(
    rec: Mapping[str, Any],
    enrollment: Enrollment,
    *,
    seq: int,
    host_producers: Optional[Mapping[str, str]] = None,
) -> Tuple[Optional[EventEnvelope], str]:
    """Return (envelope, status) where status is ok|adapted|flat_skip|bad_shape."""
    row = dict(rec)
    if row.get("type") == "event":
        row = {k: v for k, v in row.items() if k != "type"}
    if row.get("schema_ver") and row.get("payload_type"):
        try:
            return EventEnvelope.from_dict(row), "ok"
        except (KeyError, TypeError, ValueError):
            return None, "bad_shape"
    if not is_flat_lab_row(row):
        return None, "flat_skip"
    try:
        return (
            adapt_flat_lab_event(
                row, enrollment, seq=seq, host_producers=host_producers
            ),
            "adapted",
        )
    except (KeyError, TypeError, ValueError, AuthError):
        return None, "flat_skip"
