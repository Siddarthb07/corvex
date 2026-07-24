# Corvex — future plans

Where Corvex is today: **Stage A correlator honesty closed**; **Stage B OS-wide Windows sensor shipped** (observe-only, gated). Claim still locked on stranger attestation. Live OS quarantine still unimplemented.

## Done this wave

- Stage A: windowing, poisoned CDN dst, jumpbox guard, breakers, dash path scrub
- Stage B: `corvex sensor-windows` — Security + Sysmon + Firewall + PowerShell → signed `events.jsonl` → correlator → dash
- Fixtures under `fixtures/os_wide/`; multi-host exporter smoke (`scripts/smoke_os_wide_multihost.py`)
- Docs: [`docs/os-wide-sensor.md`](docs/os-wide-sensor.md), [`docs/sensor-windows.md`](docs/sensor-windows.md)

## Stage B unlock (claim vs lab)

**Honest unlock:** outsider completes [`docs/stranger-checklist.md`](docs/stranger-checklist.md) → `reports/stranger_dry_run.json` `"pass": true` → create `reports/stage-b-allowed` → `corvex stage-b-check`.

**Lab-only:** `CORVEX_STAGE_B=1` — run the sensor locally; does **not** flip `claim_allowed`.

## Still open

1. **Stranger attestation** — author cannot self-attest (blocks `claim_allowed`).
2. External habit-loop PASS (`corvex habit-loop --correct`) after purple run without author help.
3. Real elevated wevtutil follow on a lab PC (fixture path is CI-complete).
4. **OS/EDR/VLAN quarantine** — only after L1 evidenced + hostile-bus + larger false-isolate rates.
5. JetStream/mTLS bus — deferred (stubs remain).

## What not to do

- Set `claim_allowed` by hand
- Flip L1 checklist without evidence
- Claim “useful on real attacks” while stranger gate is false
- Fake OS isolate success
- Treat `CORVEX_STAGE_B=1` as claim unlock

## If only one thing

Get one outsider through the stranger checklist.
