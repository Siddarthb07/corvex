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

# Replay a sample multi-host attack (auto-creates ~/.corvex/enrollment.json)
corvex replay train/train-lateral.jsonl --out-dir runs/demo

# Open the monitor (prints URLs after bind)
corvex dash --run-dir runs/demo
```

| Surface | Path (after `corvex dash`) |
|---------|----------------------------|
| Monitor | `/` — campaigns + eval + safety controls |
| Prevention log | `/logs.html` |

Defaults bind to loopback. Share on a lab LAN (view-only checklist from remote hosts):

```bash
corvex dash --host 0.0.0.0 --port 8765 --run-dir runs/demo
# browse http://<this-machine-ip>:8765/
```

CLI: `corvex` (legacy alias `cfuse`). Optional: `corvex init` to create enrollment without replaying.

## Bring your own events

```bash
corvex ingest-byo path/to/export.jsonl --out-bus runs/prod/events.jsonl
corvex dash
```

Enrollment / HMAC secrets live **outside** the repo (`~/.corvex/` by default). Do not commit keys.

Public train packs are re-signed with your local enrollment on replay so a clean clone works without sealed held-out material.

## Docker attack lab

Needs Docker. Sources live in `labs/live/`:

```bash
python scripts/run_live_lab.py
```

Spins up 3 virtual hosts + attacker + Corvex on an isolated bridge network. Same flow as the live-lab demo.

## What works today vs later

| Capability | Status |
|------------|--------|
| Correlator + monitor + prevention log | Ready |
| Replay / BYO JSONL ingest | Ready |
| Sensors + JetStream/mTLS bus | Stub / gated |
| Live host isolate | Dry-run only (`CORVEX_CONTAIN=0`) |

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

Dashboard toggles map to `reports/security_l1_checklist.json`. They gate detect → act:

- Prove sensor identity (mTLS)
- Signed ≠ allowed (authz separate from HMAC)
- Named actions only (no free-form shell)
- Anti-replay, dual control, blast-radius caps
- Fail closed, tamper-evident log, off-bus kill switch

Flipping toggles does **not** unlock real LAN quarantine. When the dash is bound on `0.0.0.0`, checklist POSTs are still **loopback-only**.

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

- [`SECURITY.md`](SECURITY.md) · [`THREAT_MODEL.md`](THREAT_MODEL.md) · [`LICENSE`](LICENSE)
- [`docs/contain.md`](docs/contain.md) · [`reports/RESULTS.md`](reports/RESULTS.md) — precision+recall, benign FCR, vs B1, train/held-out gap, dry-run isolates

## License

MIT — see [`LICENSE`](LICENSE).
