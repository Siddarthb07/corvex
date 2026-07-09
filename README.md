# Corvex

Multi-host **campaign correlator** — stitches weak signals across machines into one attack timeline.

Not a swarm / WBC product. Observe and correlate first; containment stays locked behind safety controls.

## Install

```bash
pip install -e ".[dev]"
python -m campaignfuse.cli dash          # http://127.0.0.1:8765/
```

CLI entrypoints: `corvex` or `cfuse`.

## What you get

| Surface | Purpose |
|---------|---------|
| Correlator + detectors | Multi-host campaign detection |
| Monitor dash | Scores, stages, safety toggles |
| Prevention log | `/logs.html` — attacks stopped/isolated |
| Contain dry-run | Propose `IsolateHost` (no live mutation yet) |

## Quick demo (synthetic packs)

```bash
corvex replay train/train-lateral.jsonl --out-dir runs/demo
corvex timeline runs/demo
```

BYO events:

```bash
corvex ingest-byo fixtures/byo_export_sample.jsonl --out-bus runs/byo/events.jsonl
```

## Architecture

```text
Sensors / Feeder / BYO-JSONL
        → EventBus (JSONL now; JetStream+mTLS later)
        → detectors (pure functions)
        → correlator
        → CampaignStore + Prevention log
        → Contain (gated; dry-run only until L1 checklist + executor)
```

## Safety / stages

- **A** — correlator bake-off (local research eval; sealed packs stay off git)
- **B** — live sensors + bus (gated)
- **C** — OSS retention
- **D** — contain only after Security L1 checklist is evidenced (`campaignfuse/contain/CHECKLIST.md`)

Live quarantine is **off** (`CFUSE_CONTAIN=0`) until a real executor and checklist proof exist.

## Docs

- [`SECURITY.md`](SECURITY.md) · [`THREAT_MODEL.md`](THREAT_MODEL.md)
- [`docs/STAGE_D.md`](docs/STAGE_D.md) · [`reports/RESULTS.md`](reports/RESULTS.md)

## License

MIT — see `pyproject.toml`.
