"""Phase 0: dump one wevtutil cycle to home-lab raw JSONL (Event Log shape)."""
from __future__ import annotations

import json
from pathlib import Path

from corvex.adapters.os_wide import DEFAULT_ALLOWLIST
from corvex.sensors.windows_os import poll_wevtutil_channel

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "labs" / "benign" / "home-lab-2026-08-13" / "raw" / "host-win.jsonl"


def main() -> None:
    records = []
    for ch, ids in DEFAULT_ALLOWLIST.items():
        poll = poll_wevtutil_channel(ch, allow_ids=set(ids), max_events=80)
        records.extend(poll.get("records") or [])
    OUT.parent.mkdir(parents=True, exist_ok=True)
    with OUT.open("w", encoding="utf-8") as fh:
        for rec in records:
            fh.write(json.dumps(rec, separators=(",", ":")) + "\n")
    print(json.dumps({"wrote": str(OUT), "records": len(records)}))


if __name__ == "__main__":
    main()
