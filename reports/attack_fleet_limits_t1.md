# Attack fleet: Limits T1 — 15-host scale

**Scale tier:** T1 | **Hosts:** 15 | **Decoys:** True | **Wall:** 116.8722s | **Peak RSS:** 15.09 MB | **fragile_rate=1.0**
**Gates:** wall/RSS → PASS


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
- Wall: **116.8722s**
- HELD: **13** (of which **fragile**: 13) | PARTIAL: **1** | BROKE: **1**
- Baseline wins: **0**

## Lead with #10 — false positives beat missed detections

For a security tool, quarantining authorized activity *worse than doing nothing* is a harder sell than any missed-detection number. False positives are what get a tool turned off. Lead every write-up with this row — not the BROKE count.

## Consequence-ordered findings

Ordered by operational severity, not by suite index.

- **t1-lim10-authorized-redteam** — **HELD, fragile** (J=1.0, margin=0.1, FQ=-). 
- **t1-lim09b-sequential-reuse** — **HELD, fragile** (J=1.0, margin=0.0, FQ=-). 
- **t1-lim09-max-density-overlap** — **HELD, fragile** (J=1.0, margin=0.1, FQ=-). 
- **t1-lim11-hostname-split-brain** — **BROKE** (J=0.0, margin=None, FQ=-). 
- **t1-lim02-triple-concurrent-shared** — **HELD, fragile** (J=1.0, margin=0.0, FQ=-). 
- **t1-lim03-slow-low-day-gaps** — **PARTIAL** (J=0.6667, margin=0.0, FQ=-). 
- **t1-lim09d-benign-hub-pivot** — **HELD, fragile** (J=1.0, margin=0.1, FQ=-). 
- **t1-lim01-dual-ambiguous-lateral** — **HELD, fragile** (J=1.0, margin=0.0, FQ=-). 
- **t1-lim04-timing-jitter** — **HELD, fragile** (J=1.0, margin=0.1, FQ=-). 
- **t1-lim05-technique-sub-kerberoast** — **HELD, fragile** (J=1.0, margin=0.1, FQ=-). 
- **t1-lim06-clock-skew-47s** — **HELD, fragile** (J=1.0, margin=0.1, FQ=-). 
- **t1-lim07-dropped-mid-chain** — **HELD, fragile** (J=1.0, margin=0.1, FQ=-). 
- **t1-lim08-out-of-order-arrival** — **HELD, fragile** (J=1.0, margin=0.1, FQ=host-02, host-03). 
- **t1-lim09c-positional-bias** — **HELD, fragile** (J=1.0, margin=0.0, FQ=-). 
- **t1-lim12-near-dup-cdn-mimicry** — **HELD, fragile** (J=1.0, margin=0.1, FQ=-). 

## Headline table (priority order)

| Priority | Campaign | Verdict | Jaccard | Margin | False Q | Baseline wins |
|----------|----------|---------|---------|--------|---------|---------------|
| 1 | t1-lim10-authorized-redteam | **HELD, fragile** | 1.0 | 0.1 | - | False |
| 2 | t1-lim09b-sequential-reuse | **HELD, fragile** | 1.0 | 0.0 | - | False |
| 3 | t1-lim09-max-density-overlap | **HELD, fragile** | 1.0 | 0.1 | - | False |
| 4 | t1-lim09d-benign-hub-pivot | **HELD, fragile** | 1.0 | 0.1 | - | False |
| 5 | t1-lim09c-positional-bias | **HELD, fragile** | 1.0 | 0.0 | - | False |

## Identity / attribution cluster (#9 + #11)

#9 is "one host, too many roles"; #11 is "one host, two identities." Both point at reasoning over **host labels** rather than **host identity + role over time**. A shared fix path: persistent asset ID (not hostname) and degree-weighting so a high-connectivity node needs stronger evidence before merging campaigns through it.

## Fleet scoreboard

| # | Campaign | Verdict | Jaccard | Margin | Missed | Over-merged | Saved | False Q | Baseline FQ | Baseline wins |
|---|----------|---------|---------|--------|--------|-------------|-------|---------|-------------|---------------|
| 1 | t1-lim01-dual-ambiguous-lateral | **HELD, fragile** | 1.0 | 0.0 | - | - | host-03, host-04, host-05, host-06, host-07, host-08, host-09, host-10, host-11, host-12, host-13, host-14 | - | - | False |
| 2 | t1-lim02-triple-concurrent-shared | **HELD, fragile** | 1.0 | 0.0 | - | - | host-06, host-07, host-08, host-09, host-10, host-11, host-12, host-13, host-14 | - | - | False |
| 3 | t1-lim03-slow-low-day-gaps | **PARTIAL** | 0.6667 | 0.0 | - | - | host-03, host-04, host-05, host-06, host-07, host-08, host-09, host-10, host-11, host-12, host-13, host-14 | - | - | False |
| 4 | t1-lim04-timing-jitter | **HELD, fragile** | 1.0 | 0.1 | - | - | host-03, host-04, host-05, host-06, host-07, host-08, host-09, host-10, host-11, host-12, host-13, host-14 | - | - | False |
| 5 | t1-lim05-technique-sub-kerberoast | **HELD, fragile** | 1.0 | 0.1 | - | - | host-03, host-04, host-05, host-06, host-07, host-08, host-09, host-10, host-11, host-12, host-13, host-14 | - | - | False |
| 6 | t1-lim06-clock-skew-47s | **HELD, fragile** | 1.0 | 0.1 | - | - | host-03, host-04, host-05, host-06, host-07, host-08, host-09, host-10, host-11, host-12, host-13, host-14 | - | - | False |
| 7 | t1-lim07-dropped-mid-chain | **HELD, fragile** | 1.0 | 0.1 | - | - | host-04, host-05, host-06, host-07, host-08, host-09, host-10, host-11, host-12, host-13, host-14 | - | - | False |
| 8 | t1-lim08-out-of-order-arrival | **HELD, fragile** | 1.0 | 0.1 | - | - | host-04, host-05, host-06, host-07, host-08, host-09, host-10, host-11, host-12, host-13, host-14 | host-02, host-03 | - | False |
| 9 | t1-lim09-max-density-overlap ★ | **HELD, fragile** | 1.0 | 0.1 | - | - | host-05, host-06, host-07, host-08, host-09, host-10, host-11, host-12, host-13, host-14 | - | - | False |
| 10 | t1-lim09b-sequential-reuse ★ | **HELD, fragile** | 1.0 | 0.0 | - | - | host-03, host-04, host-05, host-06, host-07, host-08, host-09, host-10, host-11, host-12, host-13, host-14 | - | - | False |
| 11 | t1-lim09c-positional-bias ★ | **HELD, fragile** | 1.0 | 0.0 | - | - | host-02, host-03, host-05, host-06, host-07, host-08, host-09, host-10, host-11, host-12, host-13, host-14 | - | - | False |
| 12 | t1-lim09d-benign-hub-pivot ★ | **HELD, fragile** | 1.0 | 0.1 | - | - | host-01, host-03, host-05, host-06, host-07, host-08, host-09, host-10, host-11, host-12, host-13, host-14 | - | host-01, host-03 | False |
| 13 | t1-lim10-authorized-redteam ★ | **HELD, fragile** | 1.0 | 0.1 | - | host-00, host-01, host-02 | host-00, host-01, host-02, host-03, host-04, host-05, host-06, host-07, host-08, host-09, host-10, host-11, host-12, host-13, host-14 | - | - | False |
| 14 | t1-lim11-hostname-split-brain | **BROKE** | 0.0 | None | host-00, host-01, host-02 | - | host-03, host-04, host-05, host-06, host-07, host-08, host-09, host-10, host-11, host-12, host-13, host-14 | - | - | False |
| 15 | t1-lim12-near-dup-cdn-mimicry | **HELD, fragile** | 1.0 | 0.1 | - | - | host-03, host-04, host-05, host-06, host-07, host-08, host-09, host-10, host-11, host-12, host-13, host-14 | - | - | False |

## Where it broke / partial / fragile (priority order)

- **t1-lim10-authorized-redteam** (HELD, fragile): no quarantine with empty truth — any host proposed for quarantine dry-run when truth is empty
- **t1-lim09b-sequential-reuse** (HELD, fragile): sequential incidents split across 3 campaigns — incident1 and incident2 reported as a single continuous campaign
- **t1-lim09-max-density-overlap** (HELD, fragile): multi-campaign held — any two campaigns collapse, or host-c attribution near-random
- **t1-lim11-hostname-split-brain** (BROKE): alias coverage miss: ['host-00', 'host-01', 'host-02']; truth never recovered: ['host-00', 'host-01', 'host-02'] — b's two identities treated as separate hosts, splitting coverage
- **t1-lim02-triple-concurrent-shared** (HELD, fragile): multi-campaign held — any two of the three campaigns collapse into a single reported campaign
- **t1-lim03-slow-low-day-gaps** (PARTIAL): jaccard 0.6667 in PARTIAL band — any truth-host event outside the window silently dropped from campaign reconstruction
- **t1-lim09d-benign-hub-pivot** (HELD, fragile): matched truth without merge-FQ; break_criterion not triggered: attack missed (BROKE) or b/d False Q via association — attack missed (BROKE) or b/d False Q via association
- **t1-lim01-dual-ambiguous-lateral** (HELD, fragile): matched truth without merge-FQ; break_criterion not triggered: d or e appears in the malicious campaign's Q dry-run list — d or e appears in the malicious campaign's Q dry-run list
- **t1-lim04-timing-jitter** (HELD, fragile): matched truth without merge-FQ; break_criterion not triggered: Jaccard drop vs #5/#17 baseline at matched technique set — Jaccard drop vs #5/#17 baseline at matched technique set
- **t1-lim05-technique-sub-kerberoast** (HELD, fragile): matched truth without merge-FQ; break_criterion not triggered: campaign not detected, or techniques logged but not correlated — campaign not detected, or techniques logged but not correlated
- **t1-lim06-clock-skew-47s** (HELD, fragile): matched truth without merge-FQ; break_criterion not triggered: causal ordering a→b→c wrong, or b dropped due to apparent gap — causal ordering a→b→c wrong, or b dropped due to apparent gap
- **t1-lim07-dropped-mid-chain** (HELD, fragile): matched truth without merge-FQ; break_criterion not triggered: PARTIAL/BROKE, or false confidence that a,d is complete — PARTIAL/BROKE, or false confidence that a,d is complete
- **t1-lim08-out-of-order-arrival** (HELD, fragile): matched truth without merge-FQ; break_criterion not triggered: causal chain backwards, or split into two false fragments — causal chain backwards, or split into two false fragments
- **t1-lim09c-positional-bias** (HELD, fragile): matched truth without merge-FQ; break_criterion not triggered: Jaccard or margin regression vs original #1/#6 from host relabeling alone — Jaccard or margin regression vs original #1/#6 from host relabeling alone
- **t1-lim12-near-dup-cdn-mimicry** (HELD, fragile): matched truth without merge-FQ; break_criterion not triggered: Jaccard regression vs #8/#20 passing results — Jaccard regression vs #8/#20 passing results

## Baseline won (correlation made FP worse)

None — correlator never lost to single-host isolation on FQ/coverage.

## Clean HELD (0) — not fragile

None.

## Per-attack detail

### t1-lim01-dual-ambiguous-lateral | **fragile**

- Break criterion: d or e appears in the malicious campaign's Q dry-run list
- Truth: host-00, host-01, host-02
- Verdict: **HELD, fragile** | Jaccard=1.0 | margin=0.0
- Reasons: matched truth without merge-FQ; break_criterion not triggered: d or e appears in the malicious campaign's Q dry-run list
- Quarantine dry-run: host-00, host-01, host-02
- Saved: host-03, host-04, host-05, host-06, host-07, host-08, host-09, host-10, host-11, host-12, host-13, host-14 | False Q: -
- Baseline FQ: - | baseline_wins=False

### t1-lim02-triple-concurrent-shared | **fragile**

- Break criterion: any two of the three campaigns collapse into a single reported campaign
- Truth: host-00, host-01, host-02, host-03, host-04, host-05
- Verdict: **HELD, fragile** | Jaccard=1.0 | margin=0.0
- Reasons: multi-campaign held
- Quarantine dry-run: -
- Saved: host-06, host-07, host-08, host-09, host-10, host-11, host-12, host-13, host-14 | False Q: -
- Baseline FQ: - | baseline_wins=False

### t1-lim03-slow-low-day-gaps

- Break criterion: any truth-host event outside the window silently dropped from campaign reconstruction
- Truth: host-00, host-01, host-02
- Verdict: **PARTIAL** | Jaccard=0.6667 | margin=0.0
- Reasons: jaccard 0.6667 in PARTIAL band
- Quarantine dry-run: -
- Saved: host-03, host-04, host-05, host-06, host-07, host-08, host-09, host-10, host-11, host-12, host-13, host-14 | False Q: -
- Baseline FQ: - | baseline_wins=False

### t1-lim04-timing-jitter | **fragile**

- Break criterion: Jaccard drop vs #5/#17 baseline at matched technique set
- Truth: host-00, host-01, host-02
- Verdict: **HELD, fragile** | Jaccard=1.0 | margin=0.1
- Reasons: matched truth without merge-FQ; break_criterion not triggered: Jaccard drop vs #5/#17 baseline at matched technique set
- Quarantine dry-run: host-00, host-01, host-02
- Saved: host-03, host-04, host-05, host-06, host-07, host-08, host-09, host-10, host-11, host-12, host-13, host-14 | False Q: -
- Baseline FQ: - | baseline_wins=False

### t1-lim05-technique-sub-kerberoast | **fragile**

- Break criterion: campaign not detected, or techniques logged but not correlated
- Truth: host-00, host-01, host-02
- Verdict: **HELD, fragile** | Jaccard=1.0 | margin=0.1
- Reasons: matched truth without merge-FQ; break_criterion not triggered: campaign not detected, or techniques logged but not correlated
- Quarantine dry-run: host-00, host-01, host-02
- Saved: host-03, host-04, host-05, host-06, host-07, host-08, host-09, host-10, host-11, host-12, host-13, host-14 | False Q: -
- Baseline FQ: - | baseline_wins=False

### t1-lim06-clock-skew-47s | **fragile**

- Break criterion: causal ordering a→b→c wrong, or b dropped due to apparent gap
- Truth: host-00, host-01, host-02
- Verdict: **HELD, fragile** | Jaccard=1.0 | margin=0.1
- Reasons: matched truth without merge-FQ; break_criterion not triggered: causal ordering a→b→c wrong, or b dropped due to apparent gap
- Quarantine dry-run: host-00, host-01, host-02
- Saved: host-03, host-04, host-05, host-06, host-07, host-08, host-09, host-10, host-11, host-12, host-13, host-14 | False Q: -
- Baseline FQ: - | baseline_wins=False

### t1-lim07-dropped-mid-chain | **fragile**

- Break criterion: PARTIAL/BROKE, or false confidence that a,d is complete
- Truth: host-00, host-01, host-02, host-03
- Verdict: **HELD, fragile** | Jaccard=1.0 | margin=0.1
- Reasons: matched truth without merge-FQ; break_criterion not triggered: PARTIAL/BROKE, or false confidence that a,d is complete
- Quarantine dry-run: host-00, host-01, host-02, host-03
- Saved: host-04, host-05, host-06, host-07, host-08, host-09, host-10, host-11, host-12, host-13, host-14 | False Q: -
- Baseline FQ: - | baseline_wins=False

### t1-lim08-out-of-order-arrival | **fragile**

- Break criterion: causal chain backwards, or split into two false fragments
- Truth: host-00, host-01
- Verdict: **HELD, fragile** | Jaccard=1.0 | margin=0.1
- Reasons: matched truth without merge-FQ; break_criterion not triggered: causal chain backwards, or split into two false fragments
- Quarantine dry-run: host-00, host-01, host-02, host-03
- Saved: host-04, host-05, host-06, host-07, host-08, host-09, host-10, host-11, host-12, host-13, host-14 | False Q: host-02, host-03
- Baseline FQ: - | baseline_wins=False

### t1-lim09-max-density-overlap ★ headline | **fragile**

- Break criterion: any two campaigns collapse, or host-c attribution near-random
- Truth: host-00, host-01, host-02, host-03, host-04
- Verdict: **HELD, fragile** | Jaccard=1.0 | margin=0.1
- Reasons: multi-campaign held
- Quarantine dry-run: -
- Saved: host-05, host-06, host-07, host-08, host-09, host-10, host-11, host-12, host-13, host-14 | False Q: -
- Baseline FQ: - | baseline_wins=False

### t1-lim09b-sequential-reuse ★ headline | **fragile**

- Break criterion: incident1 and incident2 reported as a single continuous campaign
- Truth: host-00, host-01, host-02
- Verdict: **HELD, fragile** | Jaccard=1.0 | margin=0.0
- Reasons: sequential incidents split across 3 campaigns
- Quarantine dry-run: host-00, host-01, host-02
- Saved: host-03, host-04, host-05, host-06, host-07, host-08, host-09, host-10, host-11, host-12, host-13, host-14 | False Q: -
- Baseline FQ: - | baseline_wins=False

### t1-lim09c-positional-bias ★ headline | **fragile**

- Break criterion: Jaccard or margin regression vs original #1/#6 from host relabeling alone
- Truth: host-00, host-01, host-04
- Verdict: **HELD, fragile** | Jaccard=1.0 | margin=0.0
- Reasons: matched truth without merge-FQ; break_criterion not triggered: Jaccard or margin regression vs original #1/#6 from host relabeling alone
- Quarantine dry-run: -
- Saved: host-02, host-03, host-05, host-06, host-07, host-08, host-09, host-10, host-11, host-12, host-13, host-14 | False Q: -
- Baseline FQ: - | baseline_wins=False

### t1-lim09d-benign-hub-pivot ★ headline | **fragile**

- Break criterion: attack missed (BROKE) or b/d False Q via association
- Truth: host-00, host-02, host-04
- Verdict: **HELD, fragile** | Jaccard=1.0 | margin=0.1
- Reasons: matched truth without merge-FQ; break_criterion not triggered: attack missed (BROKE) or b/d False Q via association
- Quarantine dry-run: host-00, host-02, host-04
- Saved: host-01, host-03, host-05, host-06, host-07, host-08, host-09, host-10, host-11, host-12, host-13, host-14 | False Q: -
- Baseline FQ: host-01, host-03 | baseline_wins=False

### t1-lim10-authorized-redteam ★ headline | **fragile**

- Break criterion: any host proposed for quarantine dry-run when truth is empty
- Truth: ∅
- Verdict: **HELD, fragile** | Jaccard=1.0 | margin=0.1
- Reasons: no quarantine with empty truth
- Quarantine dry-run: -
- Saved: host-00, host-01, host-02, host-03, host-04, host-05, host-06, host-07, host-08, host-09, host-10, host-11, host-12, host-13, host-14 | False Q: -
- Baseline FQ: - | baseline_wins=False

### t1-lim11-hostname-split-brain

- Break criterion: b's two identities treated as separate hosts, splitting coverage
- Truth: host-00, host-01, host-02
- Verdict: **BROKE** | Jaccard=0.0 | margin=None
- Reasons: alias coverage miss: ['host-00', 'host-01', 'host-02']; truth never recovered: ['host-00', 'host-01', 'host-02']
- Quarantine dry-run: -
- Saved: host-03, host-04, host-05, host-06, host-07, host-08, host-09, host-10, host-11, host-12, host-13, host-14 | False Q: -
- Baseline FQ: - | baseline_wins=False

### t1-lim12-near-dup-cdn-mimicry | **fragile**

- Break criterion: Jaccard regression vs #8/#20 passing results
- Truth: host-00, host-01, host-02
- Verdict: **HELD, fragile** | Jaccard=1.0 | margin=0.1
- Reasons: matched truth without merge-FQ; break_criterion not triggered: Jaccard regression vs #8/#20 passing results
- Quarantine dry-run: host-00, host-01, host-02
- Saved: host-03, host-04, host-05, host-06, host-07, host-08, host-09, host-10, host-11, host-12, host-13, host-14 | False Q: -
- Baseline FQ: - | baseline_wins=False

## Honesty

- Lead with #10 (FP / baseline-wins), then #9b (structural reuse), then identity cluster (#9/#11).
- HELD ≠ clean: margin < 0.2 → **HELD, fragile**.
- Event sketches only; no live exploitation. Live OS quarantine remains unimplemented.