# Corvex

Multi-host **campaign correlator** — stitches weak signals across machines into one attack timeline.

Observe and correlate first. Live containment stays locked behind safety controls.

## Quick start

Requires Python 3.9+.

```bash
git clone <this-repo-url>
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

## Results (sealed held-out)

Synthetic multi-host packs (incl. `fusion_chain` + benign **N=5**). **Care vs commercial tools: unproven.** Claim language stays lab/BYO until `corvex claim-gates` → `claim_allowed=true`.

### Detection

| Metric | Corvex | Notes |
|--------|--------|--------|
| Precision | **1.00** | Flagged campaigns that matched ground truth |
| Recall | **1.00** | True multi-host campaigns recovered |
| Campaign F1 | **1.00** | Harmonic mean of P+R |
| Precision@1 | **1.00** | Top-ranked campaign correct |
| Benign false-campaign rate | **0.00** | Held-out benign packs (**N=5**) |
| Time-to-correlate | **~0.005 s** | First ingest → campaigns (lab machine) |

**N:** attack packs **3**; benign packs **5**.

### vs baselines (why fusion)

| | Correlator | Detector-only | B1 naive |
|--|------------|---------------|----------|
| F1 | **1.00** | **0.67** | **0.00** |
| Precision | **1.00** | **0.33** | **0.00** |
| Recall | **1.00** | **0.67** | **0.00** |

Held-out now separates fusion from detector-only (**+0.33 F1**). Break-test public-TTP manifests: correlator **1.00** vs detector-only **0.16** (lift **+0.84**).

### Held-out vs train

| Split | Precision | Recall | F1 | Det-only F1 | Benign FCR | TTU |
|-------|-----------|--------|-----|-------------|------------|-----|
| Train (dev only) | 1.00 | 1.00 | 1.00 | 0.67 | 0.00 (N=2) | ~0.006 s |
| Held-out (sealed) | 1.00 | 1.00 | 1.00 | 0.67 | 0.00 (N=5) | ~0.005 s |

Train is **context**, not the sealed claim.

### By attack pattern (held-out)

| Family | Precision | Recall | F1 | Benign FCR |
|--------|-----------|--------|-----|------------|
| lateral (OOD timing) | 1.00 | 1.00 | 1.00 | — |
| exfil | 1.00 | 1.00 | 1.00 | — |
| fusion_chain | 1.00 | 1.00 | 1.00 | — |
| benign (N=5) | — | — | — | **0.00** |

### Contain dry-run (`IsolateHost`, not live)

| Metric | Held-out |
|--------|----------|
| Hosts proposed | 11 |
| Correct isolates | 11 |
| False isolates | **0** |
| False-isolate rate | **0.00** |

`CORVEX_CONTAIN=0`. Live path is scaffolded (L1 + hostile-bus) but OS quarantine is not implemented.

**Proves (narrow):** Sealed packs; fusion beats detector-only; benign FCR at N=5; dry-run isolates clean.  
**Does not prove:** Real malware defense, stranger Windows success, commercial parity, or live contain safety.

Full write-up: [`reports/RESULTS.md`](reports/RESULTS.md).

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
| Fusion-gap packs (`fusion_chain`) + break-test lab | Ready (run locally — see [`labs/breaktest/README.md`](labs/breaktest/README.md)) |
| Windows auth export → BYO (`adapt-windows`) | Scaffolded (observe-only) |
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

## Reconstruct + quarantine (honest modes)

```bash
corvex replay train/train-lateral.jsonl
corvex reconstruct runs/replay
corvex quarantine-status
corvex quarantine host-a,host-b --rationale "mid-chain cut"
```

Reconstruction writes `reconstruction.json` with status `complete` / `partial` / `insufficient_evidence` — gaps listed, no invented TTPs. Quarantine is `dry_run` (default), `lab_flag` (sandbox), or `blocked` (refuse; no live OS executor yet).

## Docs

- [`CHANGELOG.md`](CHANGELOG.md) · [`SECURITY.md`](SECURITY.md) · [`THREAT_MODEL.md`](THREAT_MODEL.md) · [`LICENSE`](LICENSE)
- [`docs/how-corvex-works.md`](docs/how-corvex-works.md) · [`docs/contain.md`](docs/contain.md) · [`docs/sensor-windows.md`](docs/sensor-windows.md) · [`docs/stranger-checklist.md`](docs/stranger-checklist.md) · [`reports/RESULTS.md`](reports/RESULTS.md)
- [`labs/breaktest/README.md`](labs/breaktest/README.md) · [`future-plans.md`](future-plans.md)

## License

MIT — see [`LICENSE`](LICENSE).
