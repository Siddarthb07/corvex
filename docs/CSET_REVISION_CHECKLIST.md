# CSET / SaTML rejection → revision checklist

Source of truth for what the prior Corvex paper got wrong and how this draft
answers it. Keep this file next to [`CORVEX_PAPER_DRAFT.md`](CORVEX_PAPER_DRAFT.md).
**Do not** flip `claim_allowed` in prose.

## What reviewers objected to (compressed)

| Critique | Symptom in v1 | Required response |
|----------|---------------|-------------------|
| **Inconsistent F1** | Tables with P≈0.33, R≈0.67, F1≈0.67 (macro mean of pack F1s while P/R were micro) | Micro F1 = `2PR/(P+R)` from pooled TP/FP/FN; macro only diagnostic |
| **N too small** | Tiny sealed attack set | Expand sealed attack packs (now N=6 attack / N=6 benign); still say “modest” |
| **Author-written tests** | Fleet20 / breaktest look like self-grading | Lead with **external** OTRF/Security-Datasets + ATT&CK Evals; demote author fleets |
| **“BROKE” without why** | Named failures, no mechanism | [`stress-failure-modes.md`](stress-failure-modes.md) — mode → mechanism → status |
| **Lab→field language drift** | Strong sealed F1 read as “works in production” | Standing claim + machine-checked `claim_allowed=false` + blocked-claim demo |
| **Missing ablation** | Fusion asserted without detector-only baseline | Always report correlator vs detector-only (and B1 where relevant) |
| **Harder / OOD stress missing or soft** | Only easy sealed packs | Breaktest drop (≈0.65 vs 1.00) + OTRF observational scoreboard + aggressive APT29/APT3 |
| **Novelty overclaim** | Sounded like new SOTA IDS | Frame as **experience report / evaluation protocol** around an open correlator |

SaTML rejection is treated as venue/fit for Anima + Corvex packaging; Corvex revision targets **CSET-style claim-production scrutiny**.

## Rubrics for a clean draft (non-negotiable)

1. **One standing claim** until gates pass — synthetic ATT&CK-shaped fleets; not enterprise; not pure-benign PASS.
2. **Lead with measured external evidence**, not author fleets.
3. **Every table**: units, N, authorship column or caption, micro vs macro labeled.
4. **Name failures with mechanisms** — never “BROKE” alone.
5. **Separate** `lab_verified` from `claim_allowed`.
6. **Containment** = dry_run / lab_flag / blocked only; `CORVEX_CONTAIN=0`.
7. **ATT&CK tags** = coarse stage hypotheses.
8. **Live laptop stress** = OTRF *replay* into a running correlator — not malware execution on the author’s PC.
9. **Limitations section** must list what is still deferred (second physical host, ≥72 host-hour benign, enterprise telemetry).
10. **Reproduce appendix** with exact commands from a clean clone.

## Evidence map (this tree)

| Claim in draft | Artifact |
|----------------|----------|
| Micro-F1 fix | `tests/test_eval_metrics.py`, `corvex/eval` aggregate |
| Sealed N=6 / F1=1.00 / det 0.625 | `reports/RESULTS.md` |
| Breaktest lift ≈+0.44 | `reports/non_author_fusion.json` |
| OTRF primary scoreboard | `reports/opensource_attack_eval.md` |
| Aggressive APT29/APT3 HELD | `reports/opensource_aggressive_eval.md` |
| Live replay 0 MISS / 56 attacks | `reports/live_opensource_stress.md` |
| Failure mechanisms | `docs/stress-failure-modes.md` |
| Blocked marketing sentence | `scripts/demo_blocked_claim.py`, `reports/claim_gates.json` |

## Draft status

- [`CORVEX_PAPER_FINAL.md`](CORVEX_PAPER_FINAL.md) + IEEE PDF [`paper/Corvex_Claim_Gates_FINAL.pdf`](paper/Corvex_Claim_Gates_FINAL.pdf) — **Anima-style rebuild** (8 figures from locked JSON, RQs, TP/FP/FN, non-claims). Rebuild: `python scripts/build_journal_paper_pdf.py`. Figures: `scripts/render_paper_figures.py` → `docs/paper/figures/`. Lockfile: `docs/paper/NUMBERS_LOCKED.json`. Venue map: [`venues/journal-workshop/VENUE_MAP.md`](venues/journal-workshop/VENUE_MAP.md).
- [`CORVEX_PAPER_DRAFT.md`](CORVEX_PAPER_DRAFT.md) kept as working history; prefer FINAL for submission.
- Experience-report framing; OTRF-first; micro-F1; mechanisms; `claim_allowed=false` locked.
- **FIRST Bangalore 2027 talk brief PDF:** [`venues/first-blr-2027/Corvex_FIRST_Bangalore_2027_Brief.pdf`](venues/first-blr-2027/Corvex_FIRST_Bangalore_2027_Brief.pdf) + [`venues/first-blr-2027/CFS_PASTE.md`](venues/first-blr-2027/CFS_PASTE.md). Rebuild: `python scripts/build_first_blr_pdf.py`. CFS deadline 21 Nov 2026.
- Second-host evidence still deferred (gate stays false).

## Still open (say so in Limitations)

- `live_second_host` gate fail → `claim_allowed=false`
- Pure-benign home-lab PASS/FAIL not shipped as claim softener
- Broad OTRF atomic set often forms multi-host camps without host-coverage lift vs detector-only (honest observational metric)
- Adapter skip rates on APT29 remain high (channel allowlist)
