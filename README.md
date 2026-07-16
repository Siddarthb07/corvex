# Corvex

Multi-host **campaign correlator** — stitches weak signals across machines into one attack timeline.

Not a swarm / WBC product. Observe and correlate first; containment stays locked behind safety controls.

## Demos

### 30s narrated walkthrough

Attack type → detect → defend → dash result.

![Corvex 30s pitch](docs/assets/corvex-pitch-30s.gif)

[Full MP4](docs/assets/corvex-pitch-30s.mp4)

### Live Docker lab (real HTTP attack)

Attacker hits virtual hosts; Corvex isolates mid-campaign; retries return `403`.

![Corvex live lab](docs/assets/corvex-live-lab.gif)

[Full MP4](docs/assets/corvex-live-lab.mp4)

### Attack theatre

Visual lateral-auth hop across `host-a` / `host-b` / `host-c`.

![Corvex attack theatre](docs/assets/corvex-attack-theatre.gif)

[Full MP4](docs/assets/corvex-attack-theatre.mp4)

## Install (laptop / lab box)

```bash
git clone https://github.com/Siddarthb07/corvex.git
cd corvex
python -m pip install -e ".[dev]"
python -m corvex.cli dash          # http://127.0.0.1:8765/
```

CLI entrypoints: `corvex` or `cfuse`.

| Surface | URL / command |
|---------|----------------|
| Monitor | http://127.0.0.1:8765/ |
| Prevention log | http://127.0.0.1:8765/logs.html |
| Replay sample attack | `corvex replay train/train-lateral.jsonl --out-dir runs/demo` |

## Deploy on a network (current reality)

Corvex today is **observe + correlate**. You can put it where it can *see* events. Live quarantine of real PCs is still **locked**.

### Minimal deploy (single host)

1. Install on a lab/admin machine (commands above).
2. Point sensors or exporters at Corvex via **BYO JSONL** or the file-tail sensor.
3. Run the dash; watch campaigns and the **Prevention log**.
4. Leave contain off (`CORVEX_CONTAIN=0`) until safety checklist + executor exist.

```bash
# Ingest your own signed/exported events
corvex ingest-byo path/to/export.jsonl --out-bus runs/prod/events.jsonl
corvex dash
```

### Lab deploy with Docker (attack simulation)

Requires Docker Desktop. Runs 3 virtual hosts + attacker + Corvex defender on an isolated bridge network:

```bash
python scripts/run_live_lab.py
```

This is the same flow as the live-lab video: real HTTP auth across containers, detect, isolate flags, blocked retries. No production machines involved.

### Target production shape

```text
[Host sensors] --mTLS--> [Event bus] --> [Corvex correlator]
                                              |
                                              v
                                    Prevention log + Monitor
                                              |
                         all safety controls ON
                         + contain switch armed
                                              v
                                    Contain executor (IsolateHost)
```

| Capability | Status |
|------------|--------|
| Correlator + dash + local eval | Ready |
| Sensors + JetStream/mTLS bus | Stub / gated |
| Live isolate behind L1 checklist | Dry-run only |

## Safety controls (why they matter)

Dashboard toggles map to `reports/security_l1_checklist.json`. They are the **gate** between “we saw an attack” and “we change a host”:

- Prove sensor identity (mTLS)
- Signed ≠ allowed (authz separate from HMAC)
- Named actions only (no free-form shell)
- Anti-replay, dual control, blast-radius caps
- Fail closed, tamper-evident log, off-bus kill switch

**Today:** Corvex can detect and *propose* `IsolateHost` (dry-run / lab isolate flags).  
**Not today:** flipping toggles does **not** unlock real LAN quarantine — `CORVEX_CONTAIN=0` and no production executor yet.

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
