# Home-lab capture — Phase 0 (single Windows host)

**Status:** capture window **OPEN** (single host). Cannot PASS the benign gate until ≥3 hosts and ≥72 host-hours.

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

Periodically refresh Event Log–shaped raw for the scorer:

```powershell
python scripts/dump_home_lab_raw_once.py
```

## Score (dry-run while open / single-host)

```bash
python scripts/run_benign_baseline.py \
  --corpus labs/benign/home-lab-2026-08-13 \
  --adapter os_wide
```

Expect **INCOMPLETE** / below-min hosts until Phase 1.
