#!/usr/bin/env python3
"""Break-test: OS-wide sensor channel liveness (Security/Sysmon/Firewall/PowerShell)."""

from __future__ import annotations

import json
import shutil
import sys
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from corvex.lab_enroll import ensure_lab_enrollment
from corvex.sensors.windows_os import poll_wevtutil_channel, run_sensor_windows
from corvex.adapters.os_wide import DEFAULT_ALLOWLIST, load_allowlist
from corvex.stage_b import stage_b_status


REQUIRED = ("security", "sysmon", "firewall", "powershell")


def main() -> int:
    man = json.loads(
        (ROOT / "labs/breaktest/manifests/break_os_wide_sensors.json").read_text(encoding="utf-8")
    )
    fixture = ROOT / man["fixture"]
    allow = ROOT / "fixtures/os_wide/channels.json"
    run_dir = ROOT / "runs" / "breaktest" / "break_os_wide_sensors"
    if run_dir.exists():
        shutil.rmtree(run_dir)
    run_dir.mkdir(parents=True)

    gate = stage_b_status(ROOT / "reports")
    enr = ensure_lab_enrollment()
    hmap = {f"{h}.lab.local": h for h in ("host-a", "host-b", "host-c", "host-d", "host-e")}
    hmap.update({h: h for h in ("host-a", "host-b", "host-c", "host-d", "host-e")})

    stats = run_sensor_windows(
        run_dir=run_dir,
        enrollment=enr,
        channels=list(REQUIRED),
        allowlist_path=allow if allow.exists() else None,
        fixture=fixture,
        host_map=hmap,
        once=True,
        follow=False,
        max_per_sec=100,
    )

    channels = stats.get("channels") or {}
    missing = [c for c in REQUIRED if int(channels.get(c, 0)) < 1]
    tl_path = run_dir / "timeline.json"
    campaigns = []
    if tl_path.exists():
        campaigns = json.loads(tl_path.read_text(encoding="utf-8")).get("campaigns") or []

    # Best-effort live wevtutil probe (does not fail the break if empty)
    live = {}
    allow_sets = load_allowlist(allow) if allow.exists() else DEFAULT_ALLOWLIST
    for ch in REQUIRED:
        got = poll_wevtutil_channel(ch, allow_ids=allow_sets.get(ch, set()), max_events=5)
        live[ch] = {"events_sampled": len(got), "active": len(got) > 0}

    report = {
        "campaign_id": man["campaign_id"],
        "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "stage_b": gate,
        "fixture": str(man["fixture"]),
        "run_dir": "runs/breaktest/break_os_wide_sensors",
        "sensor_stats": stats,
        "required_channels": list(REQUIRED),
        "channels_active": {c: int(channels.get(c, 0)) for c in REQUIRED},
        "missing_channels": missing,
        "all_channels_active": len(missing) == 0,
        "campaigns": len(campaigns),
        "campaign_ids": [c.get("campaign_id") for c in campaigns],
        "live_wevtutil_probe": live,
        "break_points": {
            "all_channels_active": len(missing) == 0,
            "has_campaign": len(campaigns) >= 1,
            "pass": len(missing) == 0 and len(campaigns) >= 1,
        },
        "honesty": (
            "Fixture path proves adapters + correlator for all four channels. "
            "live_wevtutil_probe reflects this machine's Event Logs (Sysmon often absent)."
        ),
    }
    out = ROOT / "runs" / "breaktest" / "break_os_wide_sensors.breaks.json"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    # also copy under reports for quick read (relative paths only)
    (ROOT / "reports" / "break_os_wide_sensors.json").write_text(
        json.dumps(report, indent=2) + "\n", encoding="utf-8"
    )
    print(json.dumps(report, indent=2))
    return 0 if report["break_points"]["pass"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
