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
| Held-out eval | PASS (local key + sealed packs required) |
| Sensors / event bus | Gated |
| Live contain | Dry-run only; live locked |

## Reproduce

### Public path (no secrets)

```bash
pip install -e ".[dev]"
corvex replay train/train-lateral.jsonl --out-dir runs/demo
corvex dash --run-dir runs/demo
```

Replay auto-creates `~/.corvex/enrollment.json` and re-signs the public train pack for your machine.

### Held-out eval (local only)

Sealed packs live under `heldout/` (gitignored). The unlock key is `~/.corvex/heldout.key` (or `CORVEX_HELDOUT_KEY`). On a machine that already ran `corvex seal-day0`:

```bash
corvex eval --split heldout
corvex gate
```
