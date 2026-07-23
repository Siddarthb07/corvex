# Corvex — future plans

Where Corvex is today: **P1–P4 scaffolded and published**. Fusion beats detector-only on sealed held-out (+0.33 F1) and breaktest (+0.84). Benign FCR 0 at N=5. Reconstruction regression green. Claim still locked on stranger attestation. Live OS quarantine still unimplemented.

## Done this wave

- Re-seal + RESULTS refresh
- `eval-recon`, `byo-windows`, `claim-gates`, `score-non-author`, `hostile-bus-test`
- Live contain scaffold (`contain/live.py`) — lab flags only when gated

## Still open

1. **Stranger attestation** — external operator completes [`docs/stranger-checklist.md`](docs/stranger-checklist.md) → flip `reports/stranger_dry_run.json` `pass: true` (author cannot self-attest).
2. **Real Windows multi-host export** (not just the fixture) through `byo-windows`.
3. **OS/EDR/VLAN quarantine executor** — only after L1 evidenced with real notes (not dashboard toggles) + hostile-bus + published false-isolate rates on larger sets.
4. Optional: streaming correlator / JetStream — deferred.

## What not to do

- Set `claim_allowed` by hand
- Flip L1 checklist without evidence
- Claim “useful on real attacks” while stranger gate is false
- Fake OS isolate success

## If only one thing

Get one outsider through the stranger checklist. That unlocks the last P3 gate.
