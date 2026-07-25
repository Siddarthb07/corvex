# Attack fleet: Limits T2 — 50-host scale

**Scale tier:** T2 | **Hosts:** 50 | **Decoys:** False | **Wall:** 32.9576s | **Peak RSS:** 33.85 MB | **fragile_rate=0.3571**
**Gates:** wall/RSS → PASS; fragile-rate → PASS


Purple-team **event sketches** only. Goal: find where Corvex fails. Quarantine = dry-run proposals. Live OS quarantine is not implemented.

## Scoring criteria (stated before the run)

| Verdict | Criteria |
|---------|----------|
| **HELD** | Best-campaign Jaccard ≥ 0.9, no false-negative on any truth host, ambiguous legitimate activity correctly kept split (not merged into the malicious campaign). |
| **PARTIAL** | Jaccard 0.5–0.89, OR a truth host missed but recovered on replay, OR a benign host wrongly merged into the malicious campaign (over-merge) without being falsely quarantined. |
| **BROKE** | Jaccard < 0.5, OR a truth host never recovered, OR a benign host proposed for quarantine as part of the malicious campaign specifically because it got merged in. |

Also: **margin** (fragile gate) = ambiguity margin — for multi-campaign truth,
`min(matched scores) − max(unmatched competitor scores)` when every truth is
cleanly attributed (min Jaccard ≥ 0.9, no collapse); if there is no unmatched
competitor, margin = min(matched scores). Single-truth packs still use
confidence(top) − confidence(2nd-best). Raw top−2nd is retained as
`confidence_margin_raw` for diagnostics.
**HELD, fragile** = HELD with ambiguity margin < 0.2 (near-miss wearing a pass —
not equivalent to a clean HELD). Correctly separated equal-score campaigns are
**not** fragile under this definition.

- Attacks: **15** | Intensity rounds/attack: **2**
- Baseline: **single-host-isolation**
- Wall: **32.9576s**
- HELD: **14** (of which **fragile**: 5) | PARTIAL: **1** | BROKE: **0**
- Baseline wins: **0**

## Lead with #10 — false positives beat missed detections

For a security tool, quarantining authorized activity *worse than doing nothing* is a harder sell than any missed-detection number. False positives are what get a tool turned off. Lead every write-up with this row — not the BROKE count.

## Consequence-ordered findings

Ordered by operational severity, not by suite index.

- **t2-lim09b-sequential-reuse** — **HELD, fragile** (J=1.0, margin=0.0, FQ=-). 
- **t2-lim03-slow-low-day-gaps** — **PARTIAL** (J=0.6667, margin=0.0, FQ=-). 
- **t2-lim09d-benign-hub-pivot** — **HELD, fragile** (J=1.0, margin=0.1, FQ=-). 
- **t2-lim01-dual-ambiguous-lateral** — **HELD, fragile** (J=1.0, margin=0.0, FQ=-). 
- **t2-lim08-out-of-order-arrival** — **HELD, fragile** (J=1.0, margin=0.1, FQ=host-02, host-03). 
- **t2-lim09c-positional-bias** — **HELD, fragile** (J=1.0, margin=0.0, FQ=-). 

## Headline table (priority order)

| Priority | Campaign | Verdict | Jaccard | Margin | False Q | Baseline wins |
|----------|----------|---------|---------|--------|---------|---------------|
| 1 | t2-lim10-authorized-redteam | **HELD** | 1.0 | 1.0 | - | False |
| 2 | t2-lim09b-sequential-reuse | **HELD, fragile** | 1.0 | 0.0 | - | False |
| 3 | t2-lim09-max-density-overlap | **HELD** | 1.0 | 1.0 | - | False |
| 4 | t2-lim09d-benign-hub-pivot | **HELD, fragile** | 1.0 | 0.1 | - | False |
| 5 | t2-lim09c-positional-bias | **HELD, fragile** | 1.0 | 0.0 | - | False |

## Identity / attribution cluster (#9 + #11)

#9 is "one host, too many roles"; #11 is "one host, two identities." Both point at reasoning over **host labels** rather than **host identity + role over time**. A shared fix path: persistent asset ID (not hostname) and degree-weighting so a high-connectivity node needs stronger evidence before merging campaigns through it.

## Fleet scoreboard

| # | Campaign | Verdict | Jaccard | Margin | Missed | Over-merged | Saved | False Q | Baseline FQ | Baseline wins |
|---|----------|---------|---------|--------|--------|-------------|-------|---------|-------------|---------------|
| 1 | t2-lim01-dual-ambiguous-lateral | **HELD, fragile** | 1.0 | 0.0 | - | - | host-03, host-04, host-05, host-06, host-07, host-08, host-09, host-10, host-11, host-12, host-13, host-14, host-15, host-16, host-17, host-18, host-19, host-20, host-21, host-22, host-23, host-24, host-25, host-26, host-27, host-28, host-29, host-30, host-31, host-32, host-33, host-34, host-35, host-36, host-37, host-38, host-39, host-40, host-41, host-42, host-43, host-44, host-45, host-46, host-47, host-48, host-49 | - | - | False |
| 2 | t2-lim02-triple-concurrent-shared | **HELD** | 1.0 | 0.9 | - | - | host-06, host-07, host-08, host-09, host-10, host-11, host-12, host-13, host-14, host-15, host-16, host-17, host-18, host-19, host-20, host-21, host-22, host-23, host-24, host-25, host-26, host-27, host-28, host-29, host-30, host-31, host-32, host-33, host-34, host-35, host-36, host-37, host-38, host-39, host-40, host-41, host-42, host-43, host-44, host-45, host-46, host-47, host-48, host-49 | - | - | False |
| 3 | t2-lim03-slow-low-day-gaps | **PARTIAL** | 0.6667 | 0.0 | - | - | host-03, host-04, host-05, host-06, host-07, host-08, host-09, host-10, host-11, host-12, host-13, host-14, host-15, host-16, host-17, host-18, host-19, host-20, host-21, host-22, host-23, host-24, host-25, host-26, host-27, host-28, host-29, host-30, host-31, host-32, host-33, host-34, host-35, host-36, host-37, host-38, host-39, host-40, host-41, host-42, host-43, host-44, host-45, host-46, host-47, host-48, host-49 | - | - | False |
| 4 | t2-lim04-timing-jitter | **HELD** | 1.0 | 1.0 | - | - | host-03, host-04, host-05, host-06, host-07, host-08, host-09, host-10, host-11, host-12, host-13, host-14, host-15, host-16, host-17, host-18, host-19, host-20, host-21, host-22, host-23, host-24, host-25, host-26, host-27, host-28, host-29, host-30, host-31, host-32, host-33, host-34, host-35, host-36, host-37, host-38, host-39, host-40, host-41, host-42, host-43, host-44, host-45, host-46, host-47, host-48, host-49 | - | - | False |
| 5 | t2-lim05-technique-sub-kerberoast | **HELD** | 1.0 | 1.0 | - | - | host-03, host-04, host-05, host-06, host-07, host-08, host-09, host-10, host-11, host-12, host-13, host-14, host-15, host-16, host-17, host-18, host-19, host-20, host-21, host-22, host-23, host-24, host-25, host-26, host-27, host-28, host-29, host-30, host-31, host-32, host-33, host-34, host-35, host-36, host-37, host-38, host-39, host-40, host-41, host-42, host-43, host-44, host-45, host-46, host-47, host-48, host-49 | - | - | False |
| 6 | t2-lim06-clock-skew-47s | **HELD** | 1.0 | 1.0 | - | - | host-03, host-04, host-05, host-06, host-07, host-08, host-09, host-10, host-11, host-12, host-13, host-14, host-15, host-16, host-17, host-18, host-19, host-20, host-21, host-22, host-23, host-24, host-25, host-26, host-27, host-28, host-29, host-30, host-31, host-32, host-33, host-34, host-35, host-36, host-37, host-38, host-39, host-40, host-41, host-42, host-43, host-44, host-45, host-46, host-47, host-48, host-49 | - | - | False |
| 7 | t2-lim07-dropped-mid-chain | **HELD** | 1.0 | 1.0 | - | - | host-04, host-05, host-06, host-07, host-08, host-09, host-10, host-11, host-12, host-13, host-14, host-15, host-16, host-17, host-18, host-19, host-20, host-21, host-22, host-23, host-24, host-25, host-26, host-27, host-28, host-29, host-30, host-31, host-32, host-33, host-34, host-35, host-36, host-37, host-38, host-39, host-40, host-41, host-42, host-43, host-44, host-45, host-46, host-47, host-48, host-49 | - | - | False |
| 8 | t2-lim08-out-of-order-arrival | **HELD, fragile** | 1.0 | 0.1 | - | - | host-04, host-05, host-06, host-07, host-08, host-09, host-10, host-11, host-12, host-13, host-14, host-15, host-16, host-17, host-18, host-19, host-20, host-21, host-22, host-23, host-24, host-25, host-26, host-27, host-28, host-29, host-30, host-31, host-32, host-33, host-34, host-35, host-36, host-37, host-38, host-39, host-40, host-41, host-42, host-43, host-44, host-45, host-46, host-47, host-48, host-49 | host-02, host-03 | - | False |
| 9 | t2-lim09-max-density-overlap ★ | **HELD** | 1.0 | 1.0 | - | - | host-05, host-06, host-07, host-08, host-09, host-10, host-11, host-12, host-13, host-14, host-15, host-16, host-17, host-18, host-19, host-20, host-21, host-22, host-23, host-24, host-25, host-26, host-27, host-28, host-29, host-30, host-31, host-32, host-33, host-34, host-35, host-36, host-37, host-38, host-39, host-40, host-41, host-42, host-43, host-44, host-45, host-46, host-47, host-48, host-49 | - | - | False |
| 10 | t2-lim09b-sequential-reuse ★ | **HELD, fragile** | 1.0 | 0.0 | - | - | host-03, host-04, host-05, host-06, host-07, host-08, host-09, host-10, host-11, host-12, host-13, host-14, host-15, host-16, host-17, host-18, host-19, host-20, host-21, host-22, host-23, host-24, host-25, host-26, host-27, host-28, host-29, host-30, host-31, host-32, host-33, host-34, host-35, host-36, host-37, host-38, host-39, host-40, host-41, host-42, host-43, host-44, host-45, host-46, host-47, host-48, host-49 | - | - | False |
| 11 | t2-lim09c-positional-bias ★ | **HELD, fragile** | 1.0 | 0.0 | - | - | host-02, host-03, host-05, host-06, host-07, host-08, host-09, host-10, host-11, host-12, host-13, host-14, host-15, host-16, host-17, host-18, host-19, host-20, host-21, host-22, host-23, host-24, host-25, host-26, host-27, host-28, host-29, host-30, host-31, host-32, host-33, host-34, host-35, host-36, host-37, host-38, host-39, host-40, host-41, host-42, host-43, host-44, host-45, host-46, host-47, host-48, host-49 | - | - | False |
| 12 | t2-lim09d-benign-hub-pivot ★ | **HELD, fragile** | 1.0 | 0.1 | - | - | host-01, host-03, host-05, host-06, host-07, host-08, host-09, host-10, host-11, host-12, host-13, host-14, host-15, host-16, host-17, host-18, host-19, host-20, host-21, host-22, host-23, host-24, host-25, host-26, host-27, host-28, host-29, host-30, host-31, host-32, host-33, host-34, host-35, host-36, host-37, host-38, host-39, host-40, host-41, host-42, host-43, host-44, host-45, host-46, host-47, host-48, host-49 | - | host-01, host-03 | False |
| 13 | t2-lim10-authorized-redteam ★ | **HELD** | 1.0 | 1.0 | - | host-00, host-01, host-02 | host-00, host-01, host-02, host-03, host-04, host-05, host-06, host-07, host-08, host-09, host-10, host-11, host-12, host-13, host-14, host-15, host-16, host-17, host-18, host-19, host-20, host-21, host-22, host-23, host-24, host-25, host-26, host-27, host-28, host-29, host-30, host-31, host-32, host-33, host-34, host-35, host-36, host-37, host-38, host-39, host-40, host-41, host-42, host-43, host-44, host-45, host-46, host-47, host-48, host-49 | - | - | False |
| 14 | t2-lim11-hostname-split-brain | **HELD** | 1.0 | 1.0 | - | - | host-03, host-04, host-05, host-06, host-07, host-08, host-09, host-10, host-11, host-12, host-13, host-14, host-15, host-16, host-17, host-18, host-19, host-20, host-21, host-22, host-23, host-24, host-25, host-26, host-27, host-28, host-29, host-30, host-31, host-32, host-33, host-34, host-35, host-36, host-37, host-38, host-39, host-40, host-41, host-42, host-43, host-44, host-45, host-46, host-47, host-48, host-49 | - | - | False |
| 15 | t2-lim12-near-dup-cdn-mimicry | **HELD** | 1.0 | 1.0 | - | - | host-03, host-04, host-05, host-06, host-07, host-08, host-09, host-10, host-11, host-12, host-13, host-14, host-15, host-16, host-17, host-18, host-19, host-20, host-21, host-22, host-23, host-24, host-25, host-26, host-27, host-28, host-29, host-30, host-31, host-32, host-33, host-34, host-35, host-36, host-37, host-38, host-39, host-40, host-41, host-42, host-43, host-44, host-45, host-46, host-47, host-48, host-49 | - | - | False |

## Where it broke / partial / fragile (priority order)

- **t2-lim09b-sequential-reuse** (HELD, fragile): sequential incidents split across 2 campaigns — incident1 and incident2 reported as a single continuous campaign
- **t2-lim03-slow-low-day-gaps** (PARTIAL): jaccard 0.6667 in PARTIAL band — any truth-host event outside the window silently dropped from campaign reconstruction
- **t2-lim09d-benign-hub-pivot** (HELD, fragile): matched truth without merge-FQ; break_criterion not triggered: attack missed (BROKE) or b/d False Q via association — attack missed (BROKE) or b/d False Q via association
- **t2-lim01-dual-ambiguous-lateral** (HELD, fragile): matched truth without merge-FQ; break_criterion not triggered: d or e appears in the malicious campaign's Q dry-run list — d or e appears in the malicious campaign's Q dry-run list
- **t2-lim08-out-of-order-arrival** (HELD, fragile): matched truth without merge-FQ; break_criterion not triggered: causal chain backwards, or split into two false fragments — causal chain backwards, or split into two false fragments
- **t2-lim09c-positional-bias** (HELD, fragile): matched truth without merge-FQ; break_criterion not triggered: Jaccard or margin regression vs original #1/#6 from host relabeling alone — Jaccard or margin regression vs original #1/#6 from host relabeling alone

## Baseline won (correlation made FP worse)

None — correlator never lost to single-host isolation on FQ/coverage.

## Clean HELD (9) — not fragile

`t2-lim02-triple-concurrent-shared`, `t2-lim04-timing-jitter`, `t2-lim05-technique-sub-kerberoast`, `t2-lim06-clock-skew-47s`, `t2-lim07-dropped-mid-chain`, `t2-lim09-max-density-overlap`, `t2-lim10-authorized-redteam`, `t2-lim11-hostname-split-brain`, `t2-lim12-near-dup-cdn-mimicry` — confident passes (margin ≥ 0.2, no fragile flag).

## Per-attack detail

### t2-lim01-dual-ambiguous-lateral | **fragile**

- Break criterion: d or e appears in the malicious campaign's Q dry-run list
- Truth: host-00, host-01, host-02
- Verdict: **HELD, fragile** | Jaccard=1.0 | margin=0.0
- Reasons: matched truth without merge-FQ; break_criterion not triggered: d or e appears in the malicious campaign's Q dry-run list
- Quarantine dry-run: host-00, host-01, host-02
- Saved: host-03, host-04, host-05, host-06, host-07, host-08, host-09, host-10, host-11, host-12, host-13, host-14, host-15, host-16, host-17, host-18, host-19, host-20, host-21, host-22, host-23, host-24, host-25, host-26, host-27, host-28, host-29, host-30, host-31, host-32, host-33, host-34, host-35, host-36, host-37, host-38, host-39, host-40, host-41, host-42, host-43, host-44, host-45, host-46, host-47, host-48, host-49 | False Q: -
- Baseline FQ: - | baseline_wins=False

### t2-lim02-triple-concurrent-shared

- Break criterion: any two of the three campaigns collapse into a single reported campaign
- Truth: host-00, host-01, host-02, host-03, host-04, host-05
- Verdict: **HELD** | Jaccard=1.0 | margin=0.9
- Reasons: multi-campaign held
- Quarantine dry-run: -
- Saved: host-06, host-07, host-08, host-09, host-10, host-11, host-12, host-13, host-14, host-15, host-16, host-17, host-18, host-19, host-20, host-21, host-22, host-23, host-24, host-25, host-26, host-27, host-28, host-29, host-30, host-31, host-32, host-33, host-34, host-35, host-36, host-37, host-38, host-39, host-40, host-41, host-42, host-43, host-44, host-45, host-46, host-47, host-48, host-49 | False Q: -
- Baseline FQ: - | baseline_wins=False

### t2-lim03-slow-low-day-gaps

- Break criterion: any truth-host event outside the window silently dropped from campaign reconstruction
- Truth: host-00, host-01, host-02
- Verdict: **PARTIAL** | Jaccard=0.6667 | margin=0.0
- Reasons: jaccard 0.6667 in PARTIAL band
- Quarantine dry-run: -
- Saved: host-03, host-04, host-05, host-06, host-07, host-08, host-09, host-10, host-11, host-12, host-13, host-14, host-15, host-16, host-17, host-18, host-19, host-20, host-21, host-22, host-23, host-24, host-25, host-26, host-27, host-28, host-29, host-30, host-31, host-32, host-33, host-34, host-35, host-36, host-37, host-38, host-39, host-40, host-41, host-42, host-43, host-44, host-45, host-46, host-47, host-48, host-49 | False Q: -
- Baseline FQ: - | baseline_wins=False

### t2-lim04-timing-jitter

- Break criterion: Jaccard drop vs #5/#17 baseline at matched technique set
- Truth: host-00, host-01, host-02
- Verdict: **HELD** | Jaccard=1.0 | margin=1.0
- Reasons: matched truth without merge-FQ; break_criterion not triggered: Jaccard drop vs #5/#17 baseline at matched technique set
- Quarantine dry-run: host-00, host-01, host-02
- Saved: host-03, host-04, host-05, host-06, host-07, host-08, host-09, host-10, host-11, host-12, host-13, host-14, host-15, host-16, host-17, host-18, host-19, host-20, host-21, host-22, host-23, host-24, host-25, host-26, host-27, host-28, host-29, host-30, host-31, host-32, host-33, host-34, host-35, host-36, host-37, host-38, host-39, host-40, host-41, host-42, host-43, host-44, host-45, host-46, host-47, host-48, host-49 | False Q: -
- Baseline FQ: - | baseline_wins=False

### t2-lim05-technique-sub-kerberoast

- Break criterion: campaign not detected, or techniques logged but not correlated
- Truth: host-00, host-01, host-02
- Verdict: **HELD** | Jaccard=1.0 | margin=1.0
- Reasons: matched truth without merge-FQ; break_criterion not triggered: campaign not detected, or techniques logged but not correlated
- Quarantine dry-run: host-00, host-01, host-02
- Saved: host-03, host-04, host-05, host-06, host-07, host-08, host-09, host-10, host-11, host-12, host-13, host-14, host-15, host-16, host-17, host-18, host-19, host-20, host-21, host-22, host-23, host-24, host-25, host-26, host-27, host-28, host-29, host-30, host-31, host-32, host-33, host-34, host-35, host-36, host-37, host-38, host-39, host-40, host-41, host-42, host-43, host-44, host-45, host-46, host-47, host-48, host-49 | False Q: -
- Baseline FQ: - | baseline_wins=False

### t2-lim06-clock-skew-47s

- Break criterion: causal ordering a→b→c wrong, or b dropped due to apparent gap
- Truth: host-00, host-01, host-02
- Verdict: **HELD** | Jaccard=1.0 | margin=1.0
- Reasons: matched truth without merge-FQ; break_criterion not triggered: causal ordering a→b→c wrong, or b dropped due to apparent gap
- Quarantine dry-run: host-00, host-01, host-02
- Saved: host-03, host-04, host-05, host-06, host-07, host-08, host-09, host-10, host-11, host-12, host-13, host-14, host-15, host-16, host-17, host-18, host-19, host-20, host-21, host-22, host-23, host-24, host-25, host-26, host-27, host-28, host-29, host-30, host-31, host-32, host-33, host-34, host-35, host-36, host-37, host-38, host-39, host-40, host-41, host-42, host-43, host-44, host-45, host-46, host-47, host-48, host-49 | False Q: -
- Baseline FQ: - | baseline_wins=False

### t2-lim07-dropped-mid-chain

- Break criterion: PARTIAL/BROKE, or false confidence that a,d is complete
- Truth: host-00, host-01, host-02, host-03
- Verdict: **HELD** | Jaccard=1.0 | margin=1.0
- Reasons: matched truth without merge-FQ; break_criterion not triggered: PARTIAL/BROKE, or false confidence that a,d is complete
- Quarantine dry-run: host-00, host-01, host-02, host-03
- Saved: host-04, host-05, host-06, host-07, host-08, host-09, host-10, host-11, host-12, host-13, host-14, host-15, host-16, host-17, host-18, host-19, host-20, host-21, host-22, host-23, host-24, host-25, host-26, host-27, host-28, host-29, host-30, host-31, host-32, host-33, host-34, host-35, host-36, host-37, host-38, host-39, host-40, host-41, host-42, host-43, host-44, host-45, host-46, host-47, host-48, host-49 | False Q: -
- Baseline FQ: - | baseline_wins=False

### t2-lim08-out-of-order-arrival | **fragile**

- Break criterion: causal chain backwards, or split into two false fragments
- Truth: host-00, host-01
- Verdict: **HELD, fragile** | Jaccard=1.0 | margin=0.1
- Reasons: matched truth without merge-FQ; break_criterion not triggered: causal chain backwards, or split into two false fragments
- Quarantine dry-run: host-00, host-01, host-02, host-03
- Saved: host-04, host-05, host-06, host-07, host-08, host-09, host-10, host-11, host-12, host-13, host-14, host-15, host-16, host-17, host-18, host-19, host-20, host-21, host-22, host-23, host-24, host-25, host-26, host-27, host-28, host-29, host-30, host-31, host-32, host-33, host-34, host-35, host-36, host-37, host-38, host-39, host-40, host-41, host-42, host-43, host-44, host-45, host-46, host-47, host-48, host-49 | False Q: host-02, host-03
- Baseline FQ: - | baseline_wins=False

### t2-lim09-max-density-overlap ★ headline

- Break criterion: any two campaigns collapse, or host-c attribution near-random
- Truth: host-00, host-01, host-02, host-03, host-04
- Verdict: **HELD** | Jaccard=1.0 | margin=1.0
- Reasons: multi-campaign held
- Quarantine dry-run: -
- Saved: host-05, host-06, host-07, host-08, host-09, host-10, host-11, host-12, host-13, host-14, host-15, host-16, host-17, host-18, host-19, host-20, host-21, host-22, host-23, host-24, host-25, host-26, host-27, host-28, host-29, host-30, host-31, host-32, host-33, host-34, host-35, host-36, host-37, host-38, host-39, host-40, host-41, host-42, host-43, host-44, host-45, host-46, host-47, host-48, host-49 | False Q: -
- Baseline FQ: - | baseline_wins=False

### t2-lim09b-sequential-reuse ★ headline | **fragile**

- Break criterion: incident1 and incident2 reported as a single continuous campaign
- Truth: host-00, host-01, host-02
- Verdict: **HELD, fragile** | Jaccard=1.0 | margin=0.0
- Reasons: sequential incidents split across 2 campaigns
- Quarantine dry-run: host-00, host-01, host-02
- Saved: host-03, host-04, host-05, host-06, host-07, host-08, host-09, host-10, host-11, host-12, host-13, host-14, host-15, host-16, host-17, host-18, host-19, host-20, host-21, host-22, host-23, host-24, host-25, host-26, host-27, host-28, host-29, host-30, host-31, host-32, host-33, host-34, host-35, host-36, host-37, host-38, host-39, host-40, host-41, host-42, host-43, host-44, host-45, host-46, host-47, host-48, host-49 | False Q: -
- Baseline FQ: - | baseline_wins=False

### t2-lim09c-positional-bias ★ headline | **fragile**

- Break criterion: Jaccard or margin regression vs original #1/#6 from host relabeling alone
- Truth: host-00, host-01, host-04
- Verdict: **HELD, fragile** | Jaccard=1.0 | margin=0.0
- Reasons: matched truth without merge-FQ; break_criterion not triggered: Jaccard or margin regression vs original #1/#6 from host relabeling alone
- Quarantine dry-run: -
- Saved: host-02, host-03, host-05, host-06, host-07, host-08, host-09, host-10, host-11, host-12, host-13, host-14, host-15, host-16, host-17, host-18, host-19, host-20, host-21, host-22, host-23, host-24, host-25, host-26, host-27, host-28, host-29, host-30, host-31, host-32, host-33, host-34, host-35, host-36, host-37, host-38, host-39, host-40, host-41, host-42, host-43, host-44, host-45, host-46, host-47, host-48, host-49 | False Q: -
- Baseline FQ: - | baseline_wins=False

### t2-lim09d-benign-hub-pivot ★ headline | **fragile**

- Break criterion: attack missed (BROKE) or b/d False Q via association
- Truth: host-00, host-02, host-04
- Verdict: **HELD, fragile** | Jaccard=1.0 | margin=0.1
- Reasons: matched truth without merge-FQ; break_criterion not triggered: attack missed (BROKE) or b/d False Q via association
- Quarantine dry-run: host-00, host-02, host-04
- Saved: host-01, host-03, host-05, host-06, host-07, host-08, host-09, host-10, host-11, host-12, host-13, host-14, host-15, host-16, host-17, host-18, host-19, host-20, host-21, host-22, host-23, host-24, host-25, host-26, host-27, host-28, host-29, host-30, host-31, host-32, host-33, host-34, host-35, host-36, host-37, host-38, host-39, host-40, host-41, host-42, host-43, host-44, host-45, host-46, host-47, host-48, host-49 | False Q: -
- Baseline FQ: host-01, host-03 | baseline_wins=False

### t2-lim10-authorized-redteam ★ headline

- Break criterion: any host proposed for quarantine dry-run when truth is empty
- Truth: ∅
- Verdict: **HELD** | Jaccard=1.0 | margin=1.0
- Reasons: no quarantine with empty truth
- Quarantine dry-run: -
- Saved: host-00, host-01, host-02, host-03, host-04, host-05, host-06, host-07, host-08, host-09, host-10, host-11, host-12, host-13, host-14, host-15, host-16, host-17, host-18, host-19, host-20, host-21, host-22, host-23, host-24, host-25, host-26, host-27, host-28, host-29, host-30, host-31, host-32, host-33, host-34, host-35, host-36, host-37, host-38, host-39, host-40, host-41, host-42, host-43, host-44, host-45, host-46, host-47, host-48, host-49 | False Q: -
- Baseline FQ: - | baseline_wins=False

### t2-lim11-hostname-split-brain

- Break criterion: b's two identities treated as separate hosts, splitting coverage
- Truth: host-00, host-01, host-02
- Verdict: **HELD** | Jaccard=1.0 | margin=1.0
- Reasons: matched truth without merge-FQ; break_criterion not triggered: b's two identities treated as separate hosts, splitting coverage
- Quarantine dry-run: host-00, host-01, host-02
- Saved: host-03, host-04, host-05, host-06, host-07, host-08, host-09, host-10, host-11, host-12, host-13, host-14, host-15, host-16, host-17, host-18, host-19, host-20, host-21, host-22, host-23, host-24, host-25, host-26, host-27, host-28, host-29, host-30, host-31, host-32, host-33, host-34, host-35, host-36, host-37, host-38, host-39, host-40, host-41, host-42, host-43, host-44, host-45, host-46, host-47, host-48, host-49 | False Q: -
- Baseline FQ: - | baseline_wins=False

### t2-lim12-near-dup-cdn-mimicry

- Break criterion: Jaccard regression vs #8/#20 passing results
- Truth: host-00, host-01, host-02
- Verdict: **HELD** | Jaccard=1.0 | margin=1.0
- Reasons: matched truth without merge-FQ; break_criterion not triggered: Jaccard regression vs #8/#20 passing results
- Quarantine dry-run: host-00, host-01, host-02
- Saved: host-03, host-04, host-05, host-06, host-07, host-08, host-09, host-10, host-11, host-12, host-13, host-14, host-15, host-16, host-17, host-18, host-19, host-20, host-21, host-22, host-23, host-24, host-25, host-26, host-27, host-28, host-29, host-30, host-31, host-32, host-33, host-34, host-35, host-36, host-37, host-38, host-39, host-40, host-41, host-42, host-43, host-44, host-45, host-46, host-47, host-48, host-49 | False Q: -
- Baseline FQ: - | baseline_wins=False

## Honesty

- Lead with #10 (FP / baseline-wins), then #9b (structural reuse), then identity cluster (#9/#11).
- HELD ≠ clean: margin < 0.2 → **HELD, fragile**.
- Event sketches only; no live exploitation. Live OS quarantine remains unimplemented.