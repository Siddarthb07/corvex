# Fleet-limits T2 — 50-host scale run

Purple-team **event sketches** only. Quarantine = dry-run IsolateHost proposals. Live OS quarantine is not implemented.

## Status

| Check | Result |
|-------|--------|
| Wall / RSS (wall &lt; 120s, RSS &lt; 500MB) | **PASS** (~33s / ~34MB, no-decoy) |
| Fragile-rate gate (no-decoy ≤ T0 + 0.10) | **PASS** — rate **0.3571** = T0 |
| Verdicts | **14 HELD (5 fragile / 9 clean) / 1 PARTIAL / 0 BROKE** |
| fleet20 regression | **20/20 HELD** |
| pytest | **75 passed** |
| T2 go-ahead (quality + perf) | **PASS** on no-decoy control |

Decoy-on T2 remains a density stress only (fragile_rate=1.0 expected) — **not** used for the quality gate.

## How to run

```bash
# Quality gate (required)
python scripts/run_attack_fleet_limits_scale.py --hosts 50 --intensity 2 --no-decoy

# Density stress (optional)
python scripts/run_attack_fleet_limits_scale.py --hosts 50 --intensity 2
```

| Artifact | Path |
|----------|------|
| No-decoy report | `reports/attack_fleet_limits_t2_nodecoy.{md,json}` |
| Decoy stress | `reports/attack_fleet_limits_t2.{md,json}` |
| Manifests | `labs/breaktest/manifests/fleet-limits-t2[-nodecoy]/` |

## Recorded run (2026-07-25)

| Metric | T2 no-decoy | T2 decoy | T1 no-decoy | T0 |
|--------|-------------|----------|-------------|-----|
| Hosts | 50 | 50 | 15 | 5–6 |
| Wall | ~33s | ~35s | ~36s | ~31s |
| Peak RSS | ~34 MB | ~34 MB | ~34 MB | — |
| HELD / fragile / clean | 14 / **5** / **9** | 14 / 14 / 0 | 14 / 5 / 9 | 14 / 5 / 9 |
| fragile_rate | **0.3571** | 1.00 | 0.3571 | 0.3571 |
| PARTIAL / BROKE | 1 / 0 | 1 / 0 | 1 / 0 | 1 / 0 |

## Margin metric (prerequisite to this gate)

Fragile now uses **ambiguity margin**, not raw top−2nd among all campaigns:

- Multi-campaign cleanly attributed → `min(matched scores) − max(unmatched competitor)`; no competitor → `min(matched)`.
- Single-truth → still top−2nd.
- Raw top−2nd kept as `confidence_margin_raw`.

So #9 / #2 clean 3-way splits are **HELD** (not “fragile-but-fine”). Remaining fragile rows (#1 helpdesk competitor, #8 FQ, #9b/#9c/#9d) are real near-ties or collateral — not scoring artifacts.

## Headline (no-decoy)

| Attack | Verdict | Notes |
|--------|---------|-------|
| #10 authorized red-team | **HELD** | Contain gate; empty truth |
| #9 density overlap | **HELD** | 3× Jaccard 1.0; ambiguity margin 1.0 |
| #9b sequential reuse | **HELD, fragile** | Split held; margin still thin (same-host incidents) |
| #11 split-brain | **HELD** | Aliases |
| #3 day-gap | **PARTIAL** | Lookback cliff |
| #2 triple concurrent | **HELD** | ambiguity margin 0.9 |

## Honesty

- Event sketches only; no live exploitation.
- Do not summarize as bare “14 HELD” — say **14 HELD (5 fragile / 9 clean)**.
- Do not greenlight on decoy fragile-rate.
- Live OS quarantine remains unimplemented.
