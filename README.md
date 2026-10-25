# Corvex

**Keywords:** threat hunting · MITRE ATT&CK · multi-host campaign correlation · lateral movement · SIEM-style fusion · cybersecurity research · observe-only sensors

Multi-host **campaign correlator** for threat hunting — fuses weak per-host detectors (lateral auth, micro-exfil, recon fanout) into ATT&CK-shaped attack timelines. SIEM-style correlation without an LLM or cloud API.

**Public claim (standing):** research correlator — holds up against synthetic ATT&CK-shaped fleets; **not yet validated against real telemetry or benign baselines.** Observe and correlate first. Live containment stays locked behind safety controls.

## Quick start

Requires Python 3.9+.

```bash
git clone https://github.com/Siddarthb07/corvex.git
cd corvex
python -m pip install -e ".[dev]"

# Replay a sample multi-host attack (auto-creates ~/.corvex/enrollment.json)
corvex replay train/train-lateral.jsonl --out-dir runs/demo

# Open the monitor (prints URLs after bind)
corvex dash --run-dir runs/demo
```

| Surface | Path (after `corvex dash`) |
|---------|----------------------------|
| Monitor | `/` — campaigns + eval + safety controls |
| Prevention log | `/logs.html` |

Defaults bind to loopback. Share on a lab LAN:

```bash
corvex dash --host 0.0.0.0 --port 8765 --run-dir runs/demo
```

CLI: `corvex` (legacy alias `cfuse`). Optional: `corvex init` to create enrollment without replaying.

## Host sensors (observe-only)

Stage B gated collectors write HMAC-signed envelopes into a shared run directory.
Unlock locally with `corvex stage-b-lab-unlock --reason "…"` (does **not** flip
`claim_allowed`), or via the honest stranger path.

| Platform | CLI | Live source (primary) |
|----------|-----|----------------------|
| Windows | `corvex sensor-windows` | wevtutil (Security / Sysmon / Firewall / PowerShell) |
| macOS | `corvex sensor-macos` | `lsof` TCP established (+ optional unified-log auth/dns, `ps`, pf) |

### macOS fixture

```bash
corvex stage-b-lab-unlock --reason "local macos fixture CI"

corvex sensor-macos \
  --fixture fixtures/os_wide_macos/multi_channel.jsonl \
  --allowlist fixtures/os_wide_macos/channels.json \
  --host-map fixtures/os_wide_macos/host_map.json \
  --run-dir runs/os-wide-macos --once

corvex dash --run-dir runs/os-wide-macos
```

### Windows fixture

```bash
corvex stage-b-lab-unlock --reason "local fixture CI"
corvex sensor-windows --fixture fixtures/os_wide/multi_channel.jsonl \
  --allowlist fixtures/os_wide/channels.json \
  --host-map fixtures/windows_host_map.json \
  --run-dir runs/os-wide --once
```

Stranger / BYO auth wedge: `corvex byo-windows`.

## Bring your own events

```bash
corvex ingest-byo path/to/export.jsonl --out-bus runs/prod/events.jsonl
corvex dash
```

Enrollment / HMAC secrets live **outside** the repo (`~/.corvex/` by default). Do not commit keys.

Public train packs are re-signed with your local enrollment on replay so a clean clone works without sealed held-out material.

## What works today

| Capability | Status |
|------------|--------|
| Correlator + monitor + prevention log | Ready |
| Replay / BYO JSONL ingest | Ready |
| Windows auth export → BYO (`adapt-windows` / `byo-windows`) | Ready (observe-only) |
| OS-wide Windows sensor (`sensor-windows`) | Ready — Stage B gated / `stage-b-lab-unlock` |
| OS-wide macOS network sensor (`sensor-macos`) | Ready — Stage B gated; live net via `lsof` |
| Live host isolate | Dry-run only (`CORVEX_CONTAIN=0`) |

```text
Sensors (Windows / macOS) / Feeder / BYO-JSONL
        → EventBus (JSONL now; JetStream+mTLS later)
        → detectors (pure functions)
        → correlator
        → CampaignStore + Prevention log
        → Contain (gated)
```

## Reconstruct + quarantine (honest modes)

```bash
corvex replay train/train-lateral.jsonl
corvex reconstruct runs/replay
corvex quarantine-status
corvex quarantine host-a,host-b --rationale "mid-chain cut"
```

Reconstruction writes `reconstruction.json` with status `complete` / `partial` / `insufficient_evidence` — gaps listed, no invented TTPs. Quarantine is `dry_run` (default), `lab_flag` (sandbox), or `blocked` (refuse; no live OS executor yet).

## Safety

Dashboard toggles gate detect → act (sensor identity, authz ≠ HMAC, named actions only, anti-replay, dual control, blast-radius caps, fail closed). Flipping toggles does **not** unlock real LAN quarantine. Checklist POSTs stay **loopback-only** when the dash is bound on `0.0.0.0`.

Details: [`corvex/contain/CHECKLIST.md`](corvex/contain/CHECKLIST.md) · [`SECURITY.md`](SECURITY.md) · [`THREAT_MODEL.md`](THREAT_MODEL.md)

## Repo layout

| Path | Role |
|------|------|
| `corvex/` | Package / CLI |
| `tests/` | Unit + abuse tests |
| `fixtures/` | Sensor / adapter smoke fixtures |
| `train/` | Public signed train packs for `corvex replay` |

## License

MIT — see [`LICENSE`](LICENSE).
