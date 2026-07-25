# Windows sensors → Corvex (observe-only)

Two paths: **stranger BYO wedge** (4624 export) and **Stage B OS-wide collector** (Security + Sysmon + Firewall + PowerShell).

## Stranger / BYO wedge (ungated converter)

```bash
corvex byo-windows path/to/export.json \
  --host-map fixtures/windows_host_map.json \
  --out-dir runs/windows-wedge
corvex dash --run-dir runs/windows-wedge
```

Sample: `fixtures/windows_security_sample.json`  
Host map: `fixtures/windows_host_map.json`

This is the P3 stranger checklist path. It does **not** by itself unlock Stage B live collection.

## Stage B — OS-wide Windows sensor

Gated by `require_stage_b` (Stage A PASS + **human** stranger PASS + `reports/stage-b-allowed`, **or** `corvex stage-b-lab-unlock`). `CORVEX_STAGE_B=1` is ignored.

Full guide: [`docs/os-wide-sensor.md`](os-wide-sensor.md)

```bash
corvex stage-b-lab-unlock --reason "local fixture CI"
corvex sensor-windows --fixture fixtures/os_wide/multi_channel.jsonl \
  --allowlist fixtures/os_wide/channels.json \
  --host-map fixtures/windows_host_map.json \
  --run-dir runs/os-wide --once
corvex dash --run-dir runs/os-wide
```

Live follow (wevtutil, best-effort; productize deferred):

```bash
corvex sensor-windows --run-dir runs/os-wide-live --follow
```

Channels: Security (4624/4625/4648), Sysmon (1/3/22 if installed), Firewall, PowerShell (hashed script blocks). Allowlists + rate caps control noise. **No actuators.**

## Multi-host enrollment map

Corvex signs with local `~/.corvex/enrollment.json` (owner-only ACL on save). Map each Windows `Computer` name to an enrolled host id via `--host-map`.

## What this is / isn't

| Is | Isn't |
|----|--------|
| Observe-only 4624 BYO wedge | Claim unlock by itself |
| Stage B OS-wide collector (gated) | JetStream/mTLS bus (still stub) |
| Fixture CI without admin rights | Proof of real-attack usefulness (`claim_allowed`) |
| Multi-host exporter shape | Live OS quarantine |
| HMAC verify on recompute | Trusted remote provenance from lab adapter signing |

Claim language stays lab/BYO until `corvex claim-gates` → `claim_allowed=true` (human stranger required).
