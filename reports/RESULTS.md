# Evaluation results (summary)

Held-out correlator bake-off on sealed synthetic multi-host packs.

## Held-out gate (last published run)

| Field | Value |
|-------|--------|
| Gate | **PASS** |
| Correlator Campaign-F1 | **1.0** |
| B1 (per-host) F1 | **0.0** |
| B2 (SIEM joins) F1 | **1.0** |
| Precision@1 | **1.0** |
| False campaign rate | **0.0** |
| Care vs commercial tools | **unproven** |

## What this proves / does not

**Proves (narrow):** On sealed synthetic multi-host packs, the correlator met pre-registered bars and beat per-host B1.

**Does not prove:** Real malware defense, product-market fit, or autonomous containment.

## Capability status

| Capability | Status |
|------------|--------|
| Held-out eval | PASS |
| Sensors / event bus | Gated |
| Live contain | Dry-run only; live locked |

## Reproduce

Sealed held-out packs and keys are **not** in this repo (generated locally under `~/.corvex/`). With keys available:

```bash
pip install -e ".[dev]"
corvex eval --split heldout
corvex gate
```

Public train packs under `train/` work without sealing:

```bash
corvex replay train/train-lateral.jsonl --out-dir runs/demo
corvex dash
```
