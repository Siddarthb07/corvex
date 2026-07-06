"""Stage B sensor adapter — file-tail of JSONL envelopes (observe-only)."""

from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Optional

from campaignfuse.auth import Enrollment
from campaignfuse.bus import EventBus
from campaignfuse.envelope import EventEnvelope
from campaignfuse.ingest import publish_verified


def tail_jsonl(
    path: Path,
    bus: EventBus,
    enrollment: Enrollment,
    *,
    poll_seconds: float = 0.5,
    max_idle_polls: Optional[int] = 1,
) -> int:
    from campaignfuse.stage_b import require_stage_b

    require_stage_b()
    path = Path(path)
    offset = 0
    published = 0
    idle = 0
    while True:
        if not path.exists():
            time.sleep(poll_seconds)
            idle += 1
            if max_idle_polls is not None and idle >= max_idle_polls:
                break
            continue
        with path.open("r", encoding="utf-8") as fh:
            fh.seek(offset)
            for line in fh:
                if not line.strip():
                    continue
                rec = json.loads(line)
                if rec.get("type") == "event":
                    rec = {k: v for k, v in rec.items() if k != "type"}
                env = EventEnvelope.from_dict(rec)
                publish_verified(bus, env, enrollment)
                published += 1
            offset = fh.tell()
        idle += 1
        if max_idle_polls is not None and idle >= max_idle_polls:
            break
        time.sleep(poll_seconds)
    return published
