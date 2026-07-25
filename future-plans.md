# Corvex — future plans

Where Corvex is today: **Stage A correlator honesty closed**; **Stage B OS-wide Windows sensor shipped**; Phase 0 trust + Phase 1 offline fusion + Phase 2/3 (`--require-live`, `fuse-run`) shipped. **claim_allowed=true** (human stranger Jack). Live OS quarantine still unimplemented.

## Done this wave

- Stage A + Stage B sensor + trust harden (HMAC on recompute, lab-unlock, agent stranger reject)
- Human stranger PASS → claim unlocked
- `corvex fuse-run` offline lab+PC merge; wevtutil channel health / `--require-live`

## Still open

1. Real elevated wevtutil follow validation on a second physical Windows host (cross-host claim).
2. External habit-loop PASS after purple run without author help.
3. Concurrency-safe bus (SQLite WAL / socket / JetStream) before calling fusion “live product”.
4. **OS/EDR/VLAN quarantine** — only after L1 evidenced + hostile-bus + larger false-isolate rates.

## What not to do

- Set `claim_allowed` by hand without gates
- Treat agent Cursor dry-runs as stranger PASS
- Fake live OS quarantine success
- Pretend file JSONL fuse-run is JetStream

## If only one thing

Run elevated `corvex sensor-windows --require-live --follow` on a real PC and confirm `sensor_status.source=wevtutil` with Security hits.
