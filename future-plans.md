# Corvex — future plans

Where Corvex is today: **Stage A correlator honesty closed**; **Stage B OS-wide Windows sensor shipped** (observe-only, gated). **Phase 0 trust fixes in progress/shipped:** HMAC verify on recompute, agent stranger rejected for claims, `CORVEX_STAGE_B=1` removed (use `stage-b-lab-unlock`), dash LAN token. Claim still locked on **human** stranger attestation. Live OS quarantine still unimplemented.

## Done this wave

- Stage A: windowing, poisoned CDN dst, jumpbox guard, breakers, dash path scrub
- Stage B: `corvex sensor-windows` — Security + Sysmon + Firewall + PowerShell → signed `events.jsonl` → correlator → dash
- Fixtures under `fixtures/os_wide/`; multi-host exporter smoke (`scripts/smoke_os_wide_multihost.py`)
- Docs: [`docs/os-wide-sensor.md`](docs/os-wide-sensor.md), [`docs/sensor-windows.md`](docs/sensor-windows.md)
- Trust: `recompute_run` verifies HMAC + adapts flat lab rows; agent stranger cannot flip `claim_allowed`

## Stage B unlock (claim vs lab)

**Honest unlock:** human outsider completes [`docs/stranger-checklist.md`](docs/stranger-checklist.md) with `attestation_kind=human` → `reports/stranger_dry_run.json` `"pass": true` → create `reports/stage-b-allowed` → `corvex stage-b-check`.

**Lab-only:** `corvex stage-b-lab-unlock --reason "…"` → `reports/stage-b-lab-override.json`. Does **not** flip `claim_allowed`. `CORVEX_STAGE_B=1` is ignored.

## Still open

1. **Human stranger attestation** — author/agent cannot self-attest (blocks `claim_allowed`).
2. External habit-loop PASS (`corvex habit-loop --correct`) after purple run without author help.
3. Real elevated wevtutil follow on a lab PC (fixture path is CI-complete) — deferred until outsider signal + concurrency-safe bus.
4. **OS/EDR/VLAN quarantine** — only after L1 evidenced + hostile-bus + larger false-isolate rates.
5. JetStream/mTLS bus — deferred (stubs remain).
6. Continuous `fuse-run` CLI — deferred (offline fusion script is lab-only).

## What not to do

- Set `claim_allowed` by hand
- Treat agent Cursor dry-runs as stranger PASS
- Treat `CORVEX_STAGE_B=1` or lab-override as claim unlock
- Call the file bus “trusted” without verify on the correlator path
- Fake live OS quarantine success

## If only one thing

Get one **human** outsider through the stranger checklist.
