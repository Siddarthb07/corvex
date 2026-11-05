# Fleet-limits T1 — 15-host scale run

Purple-team **event sketches** only. Quarantine = dry-run IsolateHost proposals. Live OS quarantine is not implemented.

## Status (after margin-metric fix)

| Check | Result |
|-------|--------|
| Wall / RSS | **PASS** (~36s / ~34MB) |
| Fragile-rate vs T0 (no-decoy) | **PASS** — **0.3571** = T0 (5 fragile / 9 clean of 14 HELD) |
| fleet20 regression | **20/20 HELD** |
| Ready for T2? | **Yes** — see `docs/attack-fleet-limits-t2-run.md` |

## Purpose

Remap T0 fleet-limits shapes onto **15 hosts**. Default adds decoy laterals; `--no-decoy` is the margin-quality control.

## How to run

```bash
python scripts/run_attack_fleet_limits_scale.py --hosts 15 --intensity 2 --no-decoy
python scripts/run_attack_fleet_limits_scale.py --hosts 15 --intensity 2
```

## Margin metric fix (scoring definition, not detection)

**Bug:** `margin = top − 2nd` across *all* campaigns made any correctly separated multi-campaign pack look fragile whenever equals tied (three campaigns at score 1.0 → margin 0 forever).

**Fix:** fragile uses **ambiguity margin** when multi-campaign truth is cleanly attributed (min Jaccard ≥ 0.9, no collapse):

`min(matched scores) − max(unmatched competitor scores)`  
(no unmatched competitor → `min(matched scores)`).

Single-truth packs still use top−2nd. Raw top−2nd retained as `confidence_margin_raw`.

After the fix, #9 and #2 report **HELD** (clean) at T0 and T1 no-decoy — not “fragile asterisk forever.”

## Controls — what was confirmed empirically vs analytically

| Claim | Evidence strength |
|-------|-------------------|
| Decoys caused margin collapse on **single-truth** lim04–07 / lim10–12 | **Empirical** — no-decoy recovers margin 1.0; decoy compresses to ~0.1 |
| Old multi-campaign “fragile” was a **metric** artifact, not a detection miss | **Analytical** on the formula + **empirical** after the fix (#9/#2 → clean HELD with ambiguity margin) |
| Multi-campaign margin≈0 was “not a host-count artifact” | **Do not overclaim.** T0 *does* include multi-campaign cases (`lim02`, `lim09` with `truth_campaigns`). Matching fragile rates T0↔T1 after the fix is empirical for *those* packs. Separating host-count from campaign-count as independent variables was **not** done as a factorial experiment — quiet hosts at N=15 still leave campaign structure unchanged. |

## Recorded no-decoy (2026-07-25, post metric fix)

| Metric | T0 | T1 no-decoy |
|--------|----|-------------|
| HELD / fragile / clean | 14 / 5 / 9 | 14 / 5 / 9 |
| fragile_rate | 0.3571 | 0.3571 |
| PARTIAL / BROKE | 1 / 0 | 1 / 0 |

Remaining fragile (real near-ties / competitors, not equal-score artifacts): lim01, lim08, lim09b, lim09c, lim09d.

## #9 attribution

Clean 3-way: each truth ↔ pred at Jaccard **1.0**, `collapsed=false`. Ambiguity margin **1.0** with no decoy competitor.

## Host-scale ladder

| Tier | Hosts | Status |
|------|-------|--------|
| T0 | 5–6 | baseline |
| **T1** | **15** | **validated** (perf + fragile-rate) |
| **T2** | **50** | **cleared** — `docs/attack-fleet-limits-t2-run.md` |
| T3 | 100–200 | needs incremental fuse |

## Honesty

- Never summarize as bare “14 HELD.”
- Decoy runs are density stress only — not the fragile-rate gate.
- Live OS quarantine unimplemented.
