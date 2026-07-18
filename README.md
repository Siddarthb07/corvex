# Corvex

Multi-host **campaign correlator** — stitches weak signals across machines into one attack timeline.

Observe and correlate first. Live containment stays locked behind safety controls.

## Demos

### 30s walkthrough

![Corvex 30s pitch](docs/assets/corvex-pitch-30s.gif)

[Full MP4](docs/assets/corvex-pitch-30s.mp4)

### Live Docker lab

Real HTTP attack across virtual hosts; Corvex isolates mid-campaign; retries return `403`.

![Corvex live lab](docs/assets/corvex-live-lab.gif)

[Full MP4](docs/assets/corvex-live-lab.mp4)

### Attack theatre

Lateral-auth hop across `host-a` / `host-b` / `host-c`.

![Corvex attack theatre](docs/assets/corvex-attack-theatre.gif)

[Full MP4](docs/assets/corvex-attack-theatre.mp4)

## Quick start

Requires Python 3.9+.

```bash
git clone https://github.com/Siddarthb07/corvex.git
cd corvex
python -m pip install -e ".[dev]"

# 1) Replay a sample multi-host attack into the store
corvex replay train/train-lateral.jsonl --out-dir runs/demo

# 2) Open the monitor (default port 8765)
corvex dash
```

After `corvex dash` starts, open the URLs it prints:

| Surface | Path |
|---------|------|
| Monitor | `/` |
| Prevention log | `/logs.html` |

Defaults bind to loopback only. To share the dash on a lab LAN:

```bash
corvex dash --host 0.0.0.0 --port 8765
# then browse http://<this-machine-ip>:8765/
```

CLI name: `corvex` (legacy alias: `cfuse`).

## Bring your own events

Point exporters or sensors at Corvex with signed JSONL, then run the dash on that bus:

```bash
corvex ingest-byo path/to/export.jsonl --out-bus runs/prod/events.jsonl
corvex dash
```

Enrollment / HMAC secrets live **outside** the repo (`~/.corvex/` by default). Do not commit keys.

## Docker attack lab

Needs Docker. Spins up 3 virtual hosts + attacker + Corvex on an isolated bridge network:

```bash
python scripts/run_live_lab.py
```

Same flow as the live-lab demo: detect → isolate flags → blocked retries. No production machines involved.

## What works today vs later

| Capability | Status |
|------------|--------|
| Correlator + monitor + prevention log | Ready |
| Replay / BYO JSONL ingest | Ready |
| Sensors + JetStream/mTLS bus | Stub / gated |
| Live host isolate | Dry-run only (`CORVEX_CONTAIN=0`) |

Target shape when contain is unlocked:

```text
[Host sensors] --mTLS--> [Event bus] --> [Corvex correlator]
                                              |
                                              v
                                    Prevention log + Monitor
                                              |
                         safety checklist complete
                         + contain switch armed
                                              v
                                    Contain executor (IsolateHost)
```

## Safety

Dashboard toggles map to `reports/security_l1_checklist.json`. They gate “we saw an attack” → “we change a host”:

- Prove sensor identity (mTLS)
- Signed ≠ allowed (authz separate from HMAC)
- Named actions only (no free-form shell)
- Anti-replay, dual control, blast-radius caps
- Fail closed, tamper-evident log, off-bus kill switch

Flipping toggles does **not** unlock real LAN quarantine. Dry-run only until a real executor exists.

Details: [`corvex/contain/CHECKLIST.md`](corvex/contain/CHECKLIST.md) · [`docs/contain.md`](docs/contain.md)

## Architecture

```text
Sensors / Feeder / BYO-JSONL
        → EventBus (JSONL now; JetStream+mTLS later)
        → detectors (pure functions)
        → correlator
        → CampaignStore + Prevention log
        → Contain (gated)
```

## Docs

- [`SECURITY.md`](SECURITY.md) · [`THREAT_MODEL.md`](THREAT_MODEL.md)
- [`docs/contain.md`](docs/contain.md) · [`reports/RESULTS.md`](reports/RESULTS.md)

## License

MIT — see `pyproject.toml`.
