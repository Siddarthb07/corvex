"""Offline lab fusion: merge lab + PC event JSONL, recompute with HMAC verify.

This is **batch/follow file merge**, not a concurrency-safe product bus.
Labelled offline_lab_replay in timeline metadata.
"""

from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any, Dict, Mapping, Optional

from corvex.auth import Enrollment
from corvex.sensors.windows_os import recompute_run


def tail_merge_bytes(src: Path, dest: Path, state: Dict[str, Any], key: str) -> int:
    """Append new bytes from src into dest using byte offset state[key]."""
    if not src.exists():
        return 0
    data = src.read_bytes()
    offset = int(state.get(key, 0))
    if offset > len(data):
        offset = 0
    chunk = data[offset:]
    if not chunk:
        return 0
    dest.parent.mkdir(parents=True, exist_ok=True)
    with dest.open("ab") as fh:
        fh.write(chunk)
    state[key] = len(data)
    return chunk.count(b"\n")


def fuse_sources(
    *,
    sources: Mapping[str, Path],
    out_dir: Path,
    enrollment: Enrollment,
    state: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """Merge named source event files into out_dir/events.jsonl and recompute."""
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    events = out_dir / "events.jsonl"
    st = dict(state or {})
    added = 0
    for key, src in sources.items():
        src = Path(src)
        # Accept either a file path or a run dir containing events.jsonl
        if src.is_dir():
            src = src / "events.jsonl"
        added += tail_merge_bytes(src, events, st, key)
    stats: Dict[str, Any] = {"lines_appended": added, "sources": {k: str(v) for k, v in sources.items()}}
    if added or not (out_dir / "timeline.json").exists():
        stats["recompute"] = recompute_run(out_dir, enrollment)
    (out_dir / "fusion_status.json").write_text(
        json.dumps(
            {
                "mode": "offline_lab_replay",
                "offsets": {k: st.get(k, 0) for k in sources},
                "events_path": str(events.as_posix()),
                "sources": list(sources.keys()),
                "updated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            },
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )
    return {"state": st, **stats}


def follow_fuse(
    *,
    sources: Mapping[str, Path],
    out_dir: Path,
    enrollment: Enrollment,
    poll_seconds: float = 2.0,
    max_cycles: Optional[int] = None,
    stop_flag: Optional[List[bool]] = None,
) -> Dict[str, Any]:
    """Poll sources and recompute until max_cycles or stop_flag[0]."""
    state: Dict[str, Any] = {}
    cycles = 0
    last: Dict[str, Any] = {}
    while True:
        if stop_flag and stop_flag[0]:
            break
        last = fuse_sources(
            sources=sources, out_dir=out_dir, enrollment=enrollment, state=state
        )
        state = last["state"]
        cycles += 1
        if max_cycles is not None and cycles >= max_cycles:
            break
        time.sleep(max(0.2, poll_seconds))
    last["cycles"] = cycles
    return last
