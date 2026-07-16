"""Single ingest path for Feeder and BYO-JSONL."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Iterable, List

from corvex.auth import AuthError, Enrollment
from corvex.bus import EventBus
from corvex.envelope import EventEnvelope, verify_envelope


class IngestError(ValueError):
    pass


# Simple in-process nonce cache with bound size (restart loses — documented L0 limit).
_NONCE_CACHE: dict = {}
_NONCE_MAX = 50_000


def _remember_nonce(producer_id: str, nonce: str) -> None:
    key = f"{producer_id}:{nonce}"
    if key in _NONCE_CACHE:
        raise IngestError("replay detected")
    if len(_NONCE_CACHE) >= _NONCE_MAX:
        # drop arbitrary half
        for i, k in enumerate(list(_NONCE_CACHE.keys())):
            if i % 2 == 0:
                _NONCE_CACHE.pop(k, None)
    _NONCE_CACHE[key] = True


def publish_verified(bus: EventBus, env: EventEnvelope, enrollment: Enrollment) -> None:
    try:
        secret = enrollment.require(env.producer_id, env.host_id)
    except AuthError as exc:
        raise IngestError(str(exc)) from exc
    if not verify_envelope(env, secret):
        raise IngestError("bad HMAC")
    _remember_nonce(env.producer_id, env.nonce)
    bus.publish(env)


def load_byo_jsonl(path: Path) -> List[EventEnvelope]:
    """Load exported envelopes (one JSON object per line, EventEnvelope fields)."""
    out: List[EventEnvelope] = []
    for line in Path(path).read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        rec = json.loads(line)
        if rec.get("type") == "event":
            rec = {k: v for k, v in rec.items() if k != "type"}
        out.append(EventEnvelope.from_dict(rec))
    return out


def ingest_byo(bus: EventBus, path: Path, enrollment: Enrollment) -> int:
    envs = load_byo_jsonl(path)
    for env in envs:
        publish_verified(bus, env, enrollment)
    return len(envs)
