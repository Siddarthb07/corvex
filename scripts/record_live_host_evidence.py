#!/usr/bin/env python3
"""Record live wevtutil evidence for the live_second_host claim gate.

Run on a physical Windows host (elevated), NOT on the author laptop alone if that
laptop already counts as host-1 — the gate wants a second machine.

  python scripts/record_live_host_evidence.py --run-dir runs/live-host-2

Writes reports/live_second_host.json only when sensor_status.source == wevtutil
and at least one Security event was seen.
"""

from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--run-dir", type=Path, required=True)
    ap.add_argument("--host-id", default="")
    ap.add_argument("--out", type=Path, default=ROOT / "reports" / "live_second_host.json")
    args = ap.parse_args()
    run = Path(args.run_dir)
    status_path = run / "sensor_status.json"
    if not status_path.is_file():
        print(f"missing {status_path} — run corvex sensor-windows --require-live first", file=sys.stderr)
        return 1
    status = json.loads(status_path.read_text(encoding="utf-8"))
    source = str(status.get("source") or status.get("backend") or "").lower()
    events = int(status.get("events") or status.get("security_events") or 0)
    host_id = args.host_id or str(status.get("host_id") or "")
    ok = source == "wevtutil" and events > 0 and bool(host_id)
    payload = {
        "pass": ok,
        "source": source or "unknown",
        "host_id": host_id,
        "security_events_seen": events > 0,
        "events": events,
        "run_dir": str(run.as_posix()),
        "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "note": (
            "Elevated wevtutil Security channel evidence."
            if ok
            else "FAIL: need source=wevtutil with Security events on this physical host."
        ),
    }
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(payload, indent=2))
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
