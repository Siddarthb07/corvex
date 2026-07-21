# Evaluation results

Sealed synthetic multi-host packs. Numbers below are from the last local held-out + train runs after the precision/recall scorer landed. **Care vs commercial tools: unproven.**

This page intentionally avoids a single aggregate “accuracy.” Security correlators that only publish recall (or only F1) can look strong while flooding a SOC with false alarms.

## Held-out detection (sealed)

| Metric | Corvex | Notes |
|--------|--------|--------|
| Precision | **1.00** | Of campaigns flagged, share that matched ground truth |
| Recall | **1.00** | Of true multi-host campaigns, share recovered |
| Campaign F1 | **1.00** | Harmonic mean of the two above |
| Precision@1 | **1.00** | Top-ranked campaign correct |
| Benign false-campaign rate | **0.00** | On the held-out benign multi-host pack |
| Time-to-correlate | **~0.012 s** | Wall time from first ingest to campaigns (lab machine) |

Counts (attack packs only): TP=2, FP=0, FN=0.

### Why naive numbers can lie here

A detector that flags every host as a campaign gets perfect recall and useless precision. We gate and publish **both** precision and recall, plus an explicit **benign false-campaign rate**.

## vs single-host baseline (the correlator premise)

| | Corvex | B1 (per-host naive) |
|--|--------|---------------------|
| F1 | **1.00** | **0.00** |
| Recall | **1.00** | **0.00** |
| Precision | **1.00** | **0.00** |
| Benign false-campaign rate | **0.00** | **1.00** |

**Lift:** F1 +1.00, recall +1.00. B1 misses the multi-host campaigns entirely and still cries wolf on the benign pack. That gap is the justification for cross-host correlation — not the absolute Corvex score alone.

Competitive SIEM-style joins (B2) also hit F1 1.00 on this sealed set. Detector-only (no cross-host fusion) also hit F1 1.00 on held-out. On **train**, detector-only F1 was **0.89** vs correlator **1.00** — fusion helps there; held-out does not currently separate them. That is an honest limit of this pack grammar, not a marketing win.

## Held-out vs train gap

| Split | Precision | Recall | F1 | Benign FCR | TTU |
|-------|-----------|--------|-----|------------|-----|
| Train (dev) | 1.00 | 1.00 | 1.00 | n/a (no benign pack) | ~0.011 s |
| Held-out (sealed) | 1.00 | 1.00 | 1.00 | 0.00 | ~0.012 s |

**Gap:** ~0 on headline P/R/F1. Small gap ≠ proof of real-world generalization — packs are author-designed synthetic grammar; OOD is timing/noise within that grammar.

Train numbers are **dev/tuning context only**. They are not the sealed result.

## By attack pattern (held-out)

| Family | Precision | Recall | F1 | Benign FCR |
|--------|-----------|--------|-----|------------|
| lateral (OOD timing) | 1.00 | 1.00 | 1.00 | — |
| exfil | 1.00 | 1.00 | 1.00 | — |
| benign multi-host | — | — | — | **0.00** |

No family-level failure on this sealed set. If a future pack shows exfil ≪ lateral (or the reverse), that split is what gets published — not a buried row under a single F1.

## Containment dry-run (not live)

If every host in a flagged campaign were proposed for `IsolateHost` (dry-run only; `CORVEX_CONTAIN=0`):

| Metric | Held-out |
|--------|----------|
| Hosts proposed | 6 |
| Correct isolates | 6 |
| False isolates | **0** |
| Missed hosts | 0 |
| False-isolate rate | **0.00** |
| Isolate precision / recall | 1.00 / 1.00 |

Train dry-run: 9/9 correct, **0** false isolates. Nonzero false-isolate rate on a future run is a publishable finding, not a footnote.

## What this does / does not prove

**Proves (narrow):** On sealed synthetic multi-host packs, Corvex met pre-registered bars for precision+recall+benign FCR+TTU, beat per-host B1 on recall and benign FCR, and would not have false-isolated on dry-run host sets.

**Does not prove:** Real malware defense, SOC workload reduction, commercial-tool parity, or that live contain is safe to arm.

## Reproduce

Public path (no sealed key):

```bash
pip install -e ".[dev]"
corvex replay train/train-lateral.jsonl --out-dir runs/demo
corvex dash --run-dir runs/demo
```

Sealed held-out (local key + `heldout/*.sealed` only):

```bash
corvex eval --split train    # context only — not the sealed claim
corvex eval --split heldout  # sealed claim
corvex gate
```
