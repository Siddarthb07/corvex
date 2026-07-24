#!/usr/bin/env python3
"""Smoke: two host exporters into one run dir (Stage B multi-host shape)."""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

os.environ.setdefault("CORVEX_STAGE_B", "1")

from corvex.lab_enroll import ensure_lab_enrollment
from corvex.sensors.windows_os import run_sensor_windows

FIXTURE = ROOT / "fixtures" / "os_wide" / "multi_channel.jsonl"
ALLOW = ROOT / "fixtures" / "os_wide" / "channels.json"


def main() -> int:
    run = ROOT / "runs" / "fleet-smoke"
    if run.exists():
        for p in run.glob("*"):
            if p.is_file():
                p.unlink()
    enr = ensure_lab_enrollment()
    hmap = {
        "host-a.lab.local": "host-a",
        "host-b.lab.local": "host-b",
        "host-c.lab.local": "host-c",
        "host-d.lab.local": "host-d",
    }
    for host, prod in (("host-a", "prod-a"), ("host-b", "prod-b")):
        run_sensor_windows(
            run_dir=run,
            enrollment=enr,
            channels=["security", "sysmon", "firewall", "powershell"],
            allowlist_path=ALLOW,
            fixture=FIXTURE,
            host_id=host,
            producer_id=prod,
            host_map=hmap,
            once=True,
            follow=False,
        )
    lines = (run / "events.jsonl").read_text(encoding="utf-8").splitlines()
    hosts = sorted({json.loads(x)["host_id"] for x in lines if x.strip()})
    print(json.dumps({"run_dir": "runs/fleet-smoke", "events": len(lines), "hosts": hosts}, indent=2))
    return 0 if "host-a" in hosts and "host-b" in hosts else 1


if __name__ == "__main__":
    raise SystemExit(main())
