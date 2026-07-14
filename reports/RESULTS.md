# Evaluation results (summary)

Authoritative local bake-off snapshot. **Do not lead with immune/swarm metaphor.**

## Held-out gate (last local run)

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

**Proves (narrow):** On sealed synthetic multi-host packs (generated locally), the correlator met pre-registered bars and beat per-host B1.

**Does not prove:** Real malware defense, product-market fit, or autonomous containment.

## Capability status

| Capability | Status |
|------------|--------|
| Held-out bake-off | PASS (local) |
| Sensors / event bus | Gated |
| Live contain | Dry-run only; live locked |

## Reproduce locally

Sealed packs and keys are **not** in this repo. On a lab machine:

```bash
pip install -e ".[dev]"
python -m campaignfuse.cli eval --split heldout
python -m campaignfuse.cli gate
```
