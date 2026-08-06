# Multi-host OS-wide exporter (Stage B)

Same Stage B gate for Windows (`corvex sensor-windows`) and macOS
(`corvex sensor-macos`). Central run dir collects signed events.

**Mode:** offline lab / observe-only. Not a live streaming product bus yet.

- Windows guide: this doc + [`sensor-windows.md`](sensor-windows.md)
- **macOS guide (detailed):** [`sensor-macos.md`](sensor-macos.md)

## Lab unlock

```bash
# Local build without stranger (does NOT flip claim_allowed):
corvex stage-b-lab-unlock --reason "local fixture CI"
# CORVEX_STAGE_B=1 is ignored (removed).

# Honest unlock (after human outsider stranger PASS):
#   write reports/stranger_dry_run.json with pass:true, attestation_kind=human
#   create empty reports/stage-b-allowed
corvex stage-b-check
```

## Fixture / CI (no admin Event Log)

### Windows

```bash
corvex stage-b-lab-unlock --reason "local fixture CI"
corvex sensor-windows --fixture fixtures/os_wide/multi_channel.jsonl \
  --allowlist fixtures/os_wide/channels.json \
  --host-map fixtures/windows_host_map.json \
  --run-dir runs/os-wide --once
corvex dash --run-dir runs/os-wide
```

### macOS

```bash
corvex stage-b-lab-unlock --reason "local macos fixture CI"
corvex sensor-macos --fixture fixtures/os_wide_macos/multi_channel.jsonl \
  --allowlist fixtures/os_wide_macos/channels.json \
  --host-map fixtures/os_wide_macos/host_map.json \
  --run-dir runs/os-wide-macos --once
corvex dash --run-dir runs/os-wide-macos
```

## Live local PC

### Windows (wevtutil)

Requires elevation for Security log on most machines. Sysmon optional (degrades honestly).

```bash
corvex sensor-windows --run-dir runs/os-wide-live --follow \
  --channels security,sysmon,firewall,powershell \
  --host-id host-pc --producer prod-pc
# Fail CI/local if Event Log produced nothing:
corvex sensor-windows --run-dir runs/os-wide-live --once --require-live
```

### macOS (lsof net + optional log/ps)

Primary live channel is `lsof` TCP established (no root required for calling-user
visibility). Auth/dns via unified log degrade when sandboxed.

```bash
corvex sensor-macos --run-dir runs/os-wide-macos-live --once \
  --channels net,process \
  --host-id host-mac --producer prod-mac
corvex sensor-macos --run-dir runs/os-wide-macos-live --once \
  --channels net --require-live --host-id host-mac --producer prod-mac
```

`sensor_status.json` includes `channel_health` with reasons
(`access_denied_need_elevation`, `sandboxed`, `permission_denied`,
`channel_missing`, `zero_hits`, …). Fixture path remains CI-only (`fixture_seed: true`).

## Offline fusion CLI

```bash
# After lab shared events + PC sensor have written JSONL:
corvex fuse-run --lab labs/breaktest/shared/events.jsonl \
  --pc runs/pc-sensor --out-dir runs/pc-and-lab --once
corvex dash --run-dir runs/pc-and-lab
# Or: corvex fuse-run ... --dash

# macOS live run as the "pc" side:
corvex fuse-run --lab labs/breaktest/shared/events.jsonl \
  --pc runs/os-wide-macos-live --out-dir runs/pc-and-lab-macos --once
```

Mode is **offline_lab_replay** (file merge + HMAC verify). Not JetStream; not a concurrency-safe product bus.

## Multi-host shape

On each host (or container), force identity and share one run directory:

```bash
# Windows host-a
corvex sensor-windows --host-id host-a --producer prod-a \
  --fixture fixtures/os_wide/multi_channel.jsonl \
  --run-dir runs/fleet --once

# macOS host-b (same run-dir — network share, scp merge, or copy events)
corvex sensor-macos --host-id host-b --producer prod-b \
  --fixture fixtures/os_wide_macos/multi_channel.jsonl \
  --run-dir runs/fleet --once
```

Central operator opens `corvex dash --run-dir runs/fleet`. Correlator recomputes from the shared `events.jsonl` **after HMAC verify** (tampered rows dropped).

Enrollment: `corvex init` / `~/.corvex/enrollment.json` must include each host/producer pair (owner-only ACL on save).
