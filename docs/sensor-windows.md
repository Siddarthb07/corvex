# Windows Security → Corvex (observe-only)

One real sensor path before JetStream/mTLS: export auth logs, adapt, correlate, reconstruct.

## Pipeline strangers can copy

```bash
# 1. On a Windows lab box — export successful logons (Event ID 4624)
#    Event Viewer → Windows Logs → Security → Filter → Save as JSON
#    or: wevtutil qe Security /q:"*[System[(EventID=4624)]]" /f:json > export.json

# 2a. One-shot wedge (adapt + correlate + reconstruct)
corvex byo-windows path/to/export.json \
  --host-map fixtures/windows_host_map.json \
  --out-dir runs/windows-wedge

# 2b. Or step-by-step
corvex adapt-windows path/to/export.json \
  --host-map fixtures/windows_host_map.json \
  --out runs/sensors/windows_auth.jsonl
corvex correlate-byo runs/sensors/windows_auth.jsonl --out-dir runs/windows-wedge

# 3. Monitor (campaigns + reconstruction gaps + quarantine honesty)
corvex dash --run-dir runs/windows-wedge
```

Sample fixture: `fixtures/windows_security_sample.json`  
Host map: `fixtures/windows_host_map.json` (Computer / hostname → enrolled `host-a`…`host-e`)

## Multi-host enrollment map

Corvex signs with local `~/.corvex/enrollment.json`. Map each Windows `Computer` name to an enrolled host id via `--host-map`. Unmapped computers fall back to `--default-host` (usually wrong for multi-host — always provide a map in real labs).

## What this is / isn't

| Is | Isn't |
|----|--------|
| Observe-only converter + correlator wedge | Live Stage B sensor unlock |
| Event 4624 → `auth` envelopes → campaigns | Full EVTX parser / Sysmon coverage |
| Reconstruction with honest gaps | Proof of real-attack usefulness (needs P3 gates) |
| Documented stranger path | mTLS / JetStream bus |

Stage B live sensors stay gated. Claim language stays lab/BYO until `corvex claim-gates` reports `claim_allowed=true`.
