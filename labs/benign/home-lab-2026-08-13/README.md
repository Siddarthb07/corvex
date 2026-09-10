# Home-lab capture — Phase 0 (single Windows host)

**Status:** capture window **OPEN** (single host). Follow last wrote `runs/home-lab-capture` on **2026-08-13**; docs hygiene pass **2026-09-09** (restart helpers linked; gate still needs ≥3 hosts). Cannot PASS the benign gate until ≥3 hosts and ≥72 host-hours. Do not peek or curate.

| Field | Value |
|-------|--------|
| `capture_start_utc` | see `manifest.json` |
| Host | `host-win` (physical Windows / NetBIOS `cyborg_1`) |
| Sensor | `corvex sensor-windows` (Sysmon installed; live wevtutil XML) |
| Follow run-dir | `runs/home-lab-capture` |

## Rules

- Routine work only — no ART / red-team in this corpus.
- Do not peek or curate mid-window.
- When Mac + Win-VM join, prefer continuing this window rather than stitching quiet slices.

## Restart elevated follow (if it dies)

In an **elevated** PowerShell from the repo root:

```powershell
python -m corvex stage-b-lab-unlock --reason "phase0 home-lab single-host capture"
python -m corvex sensor-windows --follow --require-live `
  --run-dir runs/home-lab-capture `
  --channels security,sysmon,firewall,powershell `
  --host-id host-win --producer prod-win `
  --host-map fixtures/os_wide/host_map_phase0.json `
  --poll-seconds 30
```

Helper (same thing): `scripts\restart_home_lab_follow.ps1` (must be elevated).

Periodically refresh Event Log–shaped raw for the scorer (writes a **dated**
file; does not overwrite `raw/host-win.jsonl`):

```powershell
python scripts/dump_home_lab_raw_once.py
```

## Phase 1 — add hosts (same window)

Do **not** close this corpus and start a new folder. Do **not** peek or curate
events. Join extra sensors into `runs/home-lab-capture` until ≥3 hosts and ≥72
host-hours. Prefer a jump/management host so hub is not GAP by construction.

| Join | Where | Command |
|------|--------|---------|
| Second physical Windows | PC-2 (also S2) | `scripts\run_s2_second_host.ps1` then keep `--follow` into this run-dir, or `scripts\join_home_lab_host.ps1 -HostId host-pc-2 -Producer prod-pc-2` |
| macOS | Mac on the same LAN | `corvex sensor-macos --follow --run-dir runs/home-lab-capture --host-id host-mac --producer prod-mac` (see `docs/sensor-macos.md`) |
| Windows VM | only if it is a distinct OS install | `scripts\join_home_lab_host.ps1 -HostId host-win-vm -Producer prod-win-vm` |

After a new hostname appears, add it to `manifest.json` `host_map` / `roles` and
`fixtures/os_wide/host_map_phase0.json`. Do not drop quiet hosts.

Score stays **INCOMPLETE** until size bars pass. Do not retune bars.

## Score (dry-run while open / single-host)

```bash
python scripts/run_benign_baseline.py \
  --corpus labs/benign/home-lab-2026-08-13 \
  --adapter os_wide
```

Expect **INCOMPLETE** / below-min hosts until Phase 1.
