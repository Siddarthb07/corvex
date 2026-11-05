# PC-2 command list (S2 live wevtutil)

Second **physical** Windows PC only. Not `cyborg_1` (that is host-1). Elevated PowerShell. Observe-only. Do not hand-write `reports/live_second_host.json`. Do not use `--fixture` or Docker.

Full rules: [s2-second-host.md](s2-second-host.md). Script: `scripts/run_s2_second_host.ps1`.

## 1. Install (once)

```powershell
git clone https://github.com/Siddarthb07/corvex.git
cd corvex
python -m pip install -e ".[dev]"
hostname
```

If hostname is `cyborg_1`, stop.

## 2. One-shot S2 (preferred)

```powershell
powershell -ExecutionPolicy Bypass -File scripts\run_s2_second_host.ps1
```

Lab unlock does not flip `claim_allowed`. Pass only if `sensor_status.source` is `wevtutil` and events > 0.

## 3. Manual equivalent

```powershell
python -m corvex stage-b-lab-unlock --reason "s2 second physical Windows host live wevtutil"

python -m corvex sensor-windows --require-live --once `
  --run-dir runs\live-host-2 `
  --channels security,sysmon,firewall,powershell `
  --host-id host-pc-2 --producer prod-pc-2

python scripts\record_live_host_evidence.py --run-dir runs\live-host-2 --host-id host-pc-2
```

If Security is empty, log in or unlock the screen, then rerun the sensor and record commands. Sysmon can be missing; the sensor should degrade honestly.

## 4. Optional follow (S3-style, not required for S2)

```powershell
python -m corvex sensor-windows --follow --require-live `
  --run-dir runs\os-wide-live `
  --channels security,sysmon,firewall,powershell `
  --host-id host-pc-2 --producer prod-pc-2
```

Ctrl+C when bookmarks advance under `runs\os-wide-live\sensor_bookmarks.json`.

## 5. Copy back to the author checkout, then

Copy `reports\live_second_host.json` (and optionally `runs\live-host-2\sensor_status.json`) onto the main Corvex tree. Then:

```powershell
python -m corvex claim-gates
```

Expect `live_second_host.pass=true` if the JSON is real wevtutil. `claim_allowed` can still be false. That is expected.

This is not a field-efficacy result. It is evidence that a second physical host produced live Security events.
