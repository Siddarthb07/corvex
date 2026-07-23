# Corvex — future plans

Where Corvex is today: **Stage A honesty closed for the correlator** (windowing + anti-jumpbox + SaaS dst poison). Sealed held-out still **PASS**. Claim still locked on stranger attestation. Live OS quarantine still unimplemented.

## Done this wave

- Re-seal + RESULTS refresh
- `eval-recon`, `byo-windows`, `claim-gates`, `score-non-author`, `hostile-bus-test`
- Live contain scaffold (`contain/live.py`) — lab flags only when gated
- Dash run feed (paths hidden from hero/feed)
- Stage A correlator honesty: `window_seconds`, poisoned CDN dst, jumpbox lateral guard
- Genuine breakers published under `labs/breaktest/manifests/` (incl. CDN Bridge)

## Stage B — start tomorrow

**Real unlock (honest):** outsider completes [`docs/stranger-checklist.md`](docs/stranger-checklist.md) with `"pass": true`, then create `reports/stage-b-allowed`.

**Lab-only override (not a claim):** `CORVEX_STAGE_B=1` — local sensor/JetStream scaffold only; does **not** flip `claim_allowed`.

### Tomorrow checklist

1. Hand stranger checklist to one external operator (fixture path is fine for dry-run).
2. After attestation lands: `corvex claim-gates` → confirm `stranger_success`, then touch `reports/stage-b-allowed`.
3. First Stage B build slice: observe-only Sysmon/JSON sensor path already stubbed in `corvex/stage_b.py` — wire a real export, **no** actuators.
4. Do **not** start OS-wide sensor or live quarantine.

## Still open

1. **Stranger attestation** — author cannot self-attest.
2. **Real Windows multi-host export** (not just the fixture) through `byo-windows`.
3. **OS/EDR/VLAN quarantine executor** — only after L1 evidenced + hostile-bus + published false-isolate rates on larger sets.
4. Optional: streaming correlator / JetStream — deferred.

## What not to do

- Set `claim_allowed` by hand
- Flip L1 checklist without evidence
- Claim “useful on real attacks” while stranger gate is false
- Fake OS isolate success
- Treat `CORVEX_STAGE_B=1` as claim unlock

## If only one thing

Get one outsider through the stranger checklist. That unlocks the last P3 gate and the honest Stage B marker.
