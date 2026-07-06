# Corvex

Multi-host **campaign correlator**. Metrics, CLI, and PASS criteria never use immune/swarm metaphor labels.

> Formerly prototyped as CampaignFuse — product name is **Corvex**.

**Authoritative numbers:** [`reports/RESULTS.md`](reports/RESULTS.md) · [`reports/dashboard/index.html`](reports/dashboard/index.html)

## Monitor

```bash
python -m campaignfuse.cli dash --build   # write reports/dashboard/
python -m campaignfuse.cli dash           # serve http://127.0.0.1:8765/
```

Daily honest GitHub trail: [`docs/DAILY_COMMIT_PLAN.md`](docs/DAILY_COMMIT_PLAN.md) · `scripts/daily_audit.ps1`  
College spike map (private-ish): [`docs/COLLEGE_SPIKE.md`](docs/COLLEGE_SPIKE.md)

## Hypothesis (H1)

On sealed held-out packs: correlator Campaign-F1 ≥ max(0.70, B2_F1) and ≥ B2_F1, Precision@1 ≥ 0.80, false-campaign rate on benign-only ≤ 0.10, compute TTU ≤ 2s. Ablation required.

**FAIL H1 → stop.** No Stage B.

## Latest held-out result (re-run locally to verify)

Stage A gate: **PASS** — see `reports/stageA_heldout.json`. Care vs commercial hunt tools: **unproven**. Live contain: **locked** (Stage D dry-run only; L1 checklist 0%).

## Quick start

```bash
pip install -e ".[dev]"
cfuse seal-day0          # Day 0: train + sealed held-out (key outside repo)
python scripts/publish_seal.py
cfuse eval --split train
cfuse eval --split heldout
cfuse gate
```

Held-out key: `%USERPROFILE%\.campaignfuse\heldout.key`

## Personas

| Phase | User | Job |
|-------|------|-----|
| Stage A | Bake-off operator | Prove H1 with sealed eval |
| Stage A | BYO-JSONL experimenter | `cfuse ingest-byo` → `cfuse replay` / timeline |
| Stage B+ | Lab purple-team | Timeline after purple run |

## Architecture

Feeder / BYO-JSONL → EventBus (`JsonlBus` in Stage A) → detectors → correlator → CampaignStore → eval (no correlator imports).

## BYO-JSONL

Same envelope → enrollment → Bus path as Feeder:

```bash
cfuse ingest-byo fixtures/byo_export_sample.jsonl --out-bus runs/byo/events.jsonl
cfuse replay train/train-lateral.jsonl --out-dir runs/demo
cfuse timeline runs/demo
```

Ablation toggles on replay: `--ablation-no-cross` / `--detector-only`

## Stages

- **A** — sealed bake-off (core)
- **B** — gated: one sensor + NATS JetStream mTLS; habit-loop metric; no actuators
- **C** — OSS wheel without destructive Action verbs; retention ≥3 labs×2
- **D** — Contain only after Security L1 checklist 100%

See `THREAT_MODEL.md`, `SECURITY.md`, `campaignfuse/contain/CHECKLIST.md`.
