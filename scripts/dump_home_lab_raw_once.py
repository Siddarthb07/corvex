"""Phase 0: dump one wevtutil cycle to home-lab raw JSONL (Event Log shape)."""
from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

from corvex.adapters.os_wide import DEFAULT_ALLOWLIST
from corvex.sensors.windows_os import poll_wevtutil_channel

ROOT = Path(__file__).resolve().parents[1]
RAW = ROOT / "labs" / "benign" / "home-lab-2026-08-13" / "raw"


def main() -> None:
    records = []
    for ch, ids in DEFAULT_ALLOWLIST.items():
        poll = poll_wevtutil_channel(ch, allow_ids=set(ids), max_events=80)
        records.extend(poll.get("records") or [])
    RAW.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    out = RAW / f"host-win-{stamp}.jsonl"
    with out.open("a", encoding="utf-8") as fh:
        for rec in records:
            fh.write(json.dumps(rec, separators=(",", ":")) + "\n")
    print(json.dumps({"wrote": str(out), "records": len(records), "note": "dated file; does not overwrite host-win.jsonl"}))


if __name__ == "__main__":
    main()
