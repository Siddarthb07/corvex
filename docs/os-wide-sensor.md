# Multi-host OS-wide exporter (Stage B)

Same `corvex sensor-windows` binary on each enrolled lab host; central run dir collects signed events.

## Lab unlock

```bash
# Local build without stranger (does NOT flip claim_allowed):
set CORVEX_STAGE_B=1

# Honest unlock (after outsider stranger PASS):
#   write reports/stranger_dry_run.json with pass:true
#   create empty reports/stage-b-allowed
corvex stage-b-check
```

## Fixture / CI (no admin Event Log)

```bash
set CORVEX_STAGE_B=1
corvex sensor-windows --fixture fixtures/os_wide/multi_channel.jsonl \
  --allowlist fixtures/os_wide/channels.json \
  --host-map fixtures/windows_host_map.json \
  --run-dir runs/os-wide --once
corvex dash --run-dir runs/os-wide
```

## Live local PC (wevtutil)

```bash
set CORVEX_STAGE_B=1
corvex sensor-windows --run-dir runs/os-wide-live --follow \
  --channels security,sysmon,firewall,powershell
```

Missing Sysmon degrades honestly (listed in `sensor_status.json`). Security log often needs elevation.

## Multi-host shape

On each host (or container), force identity and share one run directory:

```bash
# host-a
corvex sensor-windows --host-id host-a --producer prod-a \
  --fixture fixtures/os_wide/multi_channel.jsonl \
  --run-dir runs/fleet --once

# host-b (same run-dir — network share, scp merge, or copy events)
corvex sensor-windows --host-id host-b --producer prod-b \
  --fixture fixtures/os_wide/multi_channel.jsonl \
  --run-dir runs/fleet --once
```

Central operator opens `corvex dash --run-dir runs/fleet`. Correlator recomputes from the shared `events.jsonl`.

Enrollment: `corvex init` / `~/.corvex/enrollment.json` must include each host/producer pair.
