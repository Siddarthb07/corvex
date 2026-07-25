# Attack fleet: Limits — breaking-point suite

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
- Wall: **31.435s**
- HELD: **14** (of which **fragile**: 5) | PARTIAL: **1** | BROKE: **0**
- Baseline wins: **0**

## Lead with #10 — false positives beat missed detections

For a security tool, quarantining authorized activity *worse than doing nothing* is a harder sell than any missed-detection number. False positives are what get a tool turned off. Lead every write-up with this row — not the BROKE count.

- **lim10-authorized-redteam**: **HELD** — truth ∅, dry-run Q on —
- Baseline wins: **False** (both clean or correlator not worse than B1 on empty-truth FQ)
- Reasons: no quarantine with empty truth

## Consequence-ordered findings

Ordered by operational severity, not by suite index.

- **lim10-authorized-redteam** — **HELD** (J=1.0, margin=1.0, FQ=-). Narrow contain gate: inert lateral-only no longer proposes IsolateHost. Does NOT solve general FP — exfil-shaped authorized pentests still clear the gate.
- **lim09b-sequential-reuse** — **HELD, fragile** (J=1.0, margin=0.0, FQ=-). Structural, not an edge case. Small fixed host pools will reuse infrastructure across unrelated incidents. Fix likely needs hard split on temporal gap + technique-shape discontinuity even at 100% host overlap.
- **lim03-slow-low-day-gaps** — **PARTIAL** (J=0.6667, margin=0.0, FQ=-). Good failure: states an operational boundary (reliable inside lookback, degrades past day-scale gaps) instead of an unfalsifiable claim.
- **lim09d-benign-hub-pivot** — **HELD, fragile** (J=1.0, margin=0.1, FQ=-). Do not read as a clean HELD if fragile — margin < 0.2 with collateral FQ on hub peers.
- **lim01-dual-ambiguous-lateral** — **HELD, fragile** (J=1.0, margin=0.0, FQ=-). APT matched; helpdesk still False-Q as a separate campaign — soft near-miss (check margin).
- **lim08-out-of-order-arrival** — **HELD, fragile** (J=1.0, margin=0.1, FQ=host-c, host-d). 
- **lim09c-positional-bias** — **HELD, fragile** (J=1.0, margin=0.0, FQ=-). 

## Headline table (priority order)

| Priority | Campaign | Verdict | Jaccard | Margin | False Q | Baseline wins |
|----------|----------|---------|---------|--------|---------|---------------|
| 1 | lim10-authorized-redteam | **HELD** | 1.0 | 1.0 | - | False |
| 2 | lim09b-sequential-reuse | **HELD, fragile** | 1.0 | 0.0 | - | False |
| 3 | lim09-max-density-overlap | **HELD** | 1.0 | 1.0 | - | False |
| 4 | lim09d-benign-hub-pivot | **HELD, fragile** | 1.0 | 0.1 | - | False |
| 5 | lim09c-positional-bias | **HELD, fragile** | 1.0 | 0.0 | - | False |

## Identity / attribution cluster (#9 + #11)

#9 is "one host, too many roles"; #11 is "one host, two identities." Both point at reasoning over **host labels** rather than **host identity + role over time**. A shared fix path: persistent asset ID (not hostname) and degree-weighting so a high-connectivity node needs stronger evidence before merging campaigns through it.

## Fleet scoreboard

| # | Campaign | Verdict | Jaccard | Margin | Missed | Over-merged | Saved | False Q | Baseline FQ | Baseline wins |
|---|----------|---------|---------|--------|--------|-------------|-------|---------|-------------|---------------|
| 1 | lim01-dual-ambiguous-lateral | **HELD, fragile** | 1.0 | 0.0 | - | - | host-d, host-e | - | - | False |
| 2 | lim02-triple-concurrent-shared | **HELD** | 1.0 | 0.9 | - | - | - | - | - | False |
| 3 | lim03-slow-low-day-gaps | **PARTIAL** | 0.6667 | 0.0 | - | - | host-d, host-e | - | - | False |
| 4 | lim04-timing-jitter | **HELD** | 1.0 | 1.0 | - | - | host-d, host-e | - | - | False |
| 5 | lim05-technique-sub-kerberoast | **HELD** | 1.0 | 1.0 | - | - | host-d, host-e | - | - | False |
| 6 | lim06-clock-skew-47s | **HELD** | 1.0 | 1.0 | - | - | host-d, host-e | - | - | False |
| 7 | lim07-dropped-mid-chain | **HELD** | 1.0 | 1.0 | - | - | host-e | - | - | False |
| 8 | lim08-out-of-order-arrival | **HELD, fragile** | 1.0 | 0.1 | - | - | host-e | host-c, host-d | - | False |
| 9 | lim09-max-density-overlap ★ | **HELD** | 1.0 | 1.0 | - | - | - | - | - | False |
| 10 | lim09b-sequential-reuse ★ | **HELD, fragile** | 1.0 | 0.0 | - | - | host-d, host-e | - | - | False |
| 11 | lim09c-positional-bias ★ | **HELD, fragile** | 1.0 | 0.0 | - | - | host-c, host-d | - | - | False |
| 12 | lim09d-benign-hub-pivot ★ | **HELD, fragile** | 1.0 | 0.1 | - | - | host-b, host-d | - | host-b, host-d | False |
| 13 | lim10-authorized-redteam ★ | **HELD** | 1.0 | 1.0 | - | host-a, host-b, host-c | host-a, host-b, host-c, host-d, host-e | - | - | False |
| 14 | lim11-hostname-split-brain | **HELD** | 1.0 | 1.0 | - | - | host-d, host-e | - | - | False |
| 15 | lim12-near-dup-cdn-mimicry | **HELD** | 1.0 | 1.0 | - | - | host-d, host-e | - | - | False |

## Where it broke / partial / fragile (priority order)

- **lim09b-sequential-reuse** (HELD, fragile): sequential incidents split across 2 campaigns — incident1 and incident2 reported as a single continuous campaign
- **lim03-slow-low-day-gaps** (PARTIAL): jaccard 0.6667 in PARTIAL band — any truth-host event outside the window silently dropped from campaign reconstruction
- **lim09d-benign-hub-pivot** (HELD, fragile): matched truth without merge-FQ; break_criterion not triggered: attack missed (BROKE) or b/d False Q via association — attack missed (BROKE) or b/d False Q via association
- **lim01-dual-ambiguous-lateral** (HELD, fragile): matched truth without merge-FQ; break_criterion not triggered: d or e appears in the malicious campaign's Q dry-run list — d or e appears in the malicious campaign's Q dry-run list
- **lim08-out-of-order-arrival** (HELD, fragile): matched truth without merge-FQ; break_criterion not triggered: causal chain backwards, or split into two false fragments — causal chain backwards, or split into two false fragments
- **lim09c-positional-bias** (HELD, fragile): matched truth without merge-FQ; break_criterion not triggered: Jaccard or margin regression vs original #1/#6 from host relabeling alone — Jaccard or margin regression vs original #1/#6 from host relabeling alone

## Baseline won (correlation made FP worse)

None — correlator never lost to single-host isolation on FQ/coverage.

## Clean HELD (9) — not fragile

`lim02-triple-concurrent-shared`, `lim04-timing-jitter`, `lim05-technique-sub-kerberoast`, `lim06-clock-skew-47s`, `lim07-dropped-mid-chain`, `lim09-max-density-overlap`, `lim10-authorized-redteam`, `lim11-hostname-split-brain`, `lim12-near-dup-cdn-mimicry` — confident passes (margin ≥ 0.2, no fragile flag).

## Per-attack detail

### lim01-dual-ambiguous-lateral | **fragile**

- Break criterion: d or e appears in the malicious campaign's Q dry-run list
- Truth: host-a, host-b, host-c
- Verdict: **HELD, fragile** | Jaccard=1.0 | margin=0.0
- Reasons: matched truth without merge-FQ; break_criterion not triggered: d or e appears in the malicious campaign's Q dry-run list
- Quarantine dry-run: host-a, host-b, host-c
- Saved: host-d, host-e | False Q: -
- Baseline FQ: - | baseline_wins=False

### lim02-triple-concurrent-shared

- Break criterion: any two of the three campaigns collapse into a single reported campaign
- Truth: host-a, host-b, host-c, host-d, host-e, host-f
- Verdict: **HELD** | Jaccard=1.0 | margin=0.9
- Reasons: multi-campaign held
- Quarantine dry-run: -
- Saved: - | False Q: -
- Baseline FQ: - | baseline_wins=False

### lim03-slow-low-day-gaps

- Break criterion: any truth-host event outside the window silently dropped from campaign reconstruction
- Truth: host-a, host-b, host-c
- Verdict: **PARTIAL** | Jaccard=0.6667 | margin=0.0
- Reasons: jaccard 0.6667 in PARTIAL band
- Quarantine dry-run: -
- Saved: host-d, host-e | False Q: -
- Baseline FQ: - | baseline_wins=False

### lim04-timing-jitter

- Break criterion: Jaccard drop vs #5/#17 baseline at matched technique set
- Truth: host-a, host-b, host-c
- Verdict: **HELD** | Jaccard=1.0 | margin=1.0
- Reasons: matched truth without merge-FQ; break_criterion not triggered: Jaccard drop vs #5/#17 baseline at matched technique set
- Quarantine dry-run: host-a, host-b, host-c
- Saved: host-d, host-e | False Q: -
- Baseline FQ: - | baseline_wins=False

### lim05-technique-sub-kerberoast

- Break criterion: campaign not detected, or techniques logged but not correlated
- Truth: host-a, host-b, host-c
- Verdict: **HELD** | Jaccard=1.0 | margin=1.0
- Reasons: matched truth without merge-FQ; break_criterion not triggered: campaign not detected, or techniques logged but not correlated
- Quarantine dry-run: host-a, host-b, host-c
- Saved: host-d, host-e | False Q: -
- Baseline FQ: - | baseline_wins=False

### lim06-clock-skew-47s

- Break criterion: causal ordering a→b→c wrong, or b dropped due to apparent gap
- Truth: host-a, host-b, host-c
- Verdict: **HELD** | Jaccard=1.0 | margin=1.0
- Reasons: matched truth without merge-FQ; break_criterion not triggered: causal ordering a→b→c wrong, or b dropped due to apparent gap
- Quarantine dry-run: host-a, host-b, host-c
- Saved: host-d, host-e | False Q: -
- Baseline FQ: - | baseline_wins=False

### lim07-dropped-mid-chain

- Break criterion: PARTIAL/BROKE, or false confidence that a,d is complete
- Truth: host-a, host-b, host-c, host-d
- Verdict: **HELD** | Jaccard=1.0 | margin=1.0
- Reasons: matched truth without merge-FQ; break_criterion not triggered: PARTIAL/BROKE, or false confidence that a,d is complete
- Quarantine dry-run: host-a, host-b, host-c, host-d
- Saved: host-e | False Q: -
- Baseline FQ: - | baseline_wins=False

### lim08-out-of-order-arrival | **fragile**

- Break criterion: causal chain backwards, or split into two false fragments
- Truth: host-a, host-b
- Verdict: **HELD, fragile** | Jaccard=1.0 | margin=0.1
- Reasons: matched truth without merge-FQ; break_criterion not triggered: causal chain backwards, or split into two false fragments
- Quarantine dry-run: host-a, host-b, host-c, host-d
- Saved: host-e | False Q: host-c, host-d
- Baseline FQ: - | baseline_wins=False

### lim09-max-density-overlap ★ headline

- Break criterion: any two campaigns collapse, or host-c attribution near-random
- Truth: host-a, host-b, host-c, host-d, host-e
- Verdict: **HELD** | Jaccard=1.0 | margin=1.0
- Reasons: multi-campaign held
- Quarantine dry-run: -
- Saved: - | False Q: -
- Baseline FQ: - | baseline_wins=False

### lim09b-sequential-reuse ★ headline | **fragile**

- Break criterion: incident1 and incident2 reported as a single continuous campaign
- Truth: host-a, host-b, host-c
- Verdict: **HELD, fragile** | Jaccard=1.0 | margin=0.0
- Reasons: sequential incidents split across 2 campaigns
- Quarantine dry-run: host-a, host-b, host-c
- Saved: host-d, host-e | False Q: -
- Baseline FQ: - | baseline_wins=False

### lim09c-positional-bias ★ headline | **fragile**

- Break criterion: Jaccard or margin regression vs original #1/#6 from host relabeling alone
- Truth: host-a, host-b, host-e
- Verdict: **HELD, fragile** | Jaccard=1.0 | margin=0.0
- Reasons: matched truth without merge-FQ; break_criterion not triggered: Jaccard or margin regression vs original #1/#6 from host relabeling alone
- Quarantine dry-run: -
- Saved: host-c, host-d | False Q: -
- Baseline FQ: - | baseline_wins=False

### lim09d-benign-hub-pivot ★ headline | **fragile**

- Break criterion: attack missed (BROKE) or b/d False Q via association
- Truth: host-a, host-c, host-e
- Verdict: **HELD, fragile** | Jaccard=1.0 | margin=0.1
- Reasons: matched truth without merge-FQ; break_criterion not triggered: attack missed (BROKE) or b/d False Q via association
- Quarantine dry-run: host-a, host-c, host-e
- Saved: host-b, host-d | False Q: -
- Baseline FQ: host-b, host-d | baseline_wins=False

### lim10-authorized-redteam ★ headline

- Break criterion: any host proposed for quarantine dry-run when truth is empty
- Truth: ∅
- Verdict: **HELD** | Jaccard=1.0 | margin=1.0
- Reasons: no quarantine with empty truth
- Quarantine dry-run: -
- Saved: host-a, host-b, host-c, host-d, host-e | False Q: -
- Baseline FQ: - | baseline_wins=False

### lim11-hostname-split-brain

- Break criterion: b's two identities treated as separate hosts, splitting coverage
- Truth: host-a, host-b, host-c
- Verdict: **HELD** | Jaccard=1.0 | margin=1.0
- Reasons: matched truth without merge-FQ; break_criterion not triggered: b's two identities treated as separate hosts, splitting coverage
- Quarantine dry-run: host-a, host-b, host-c
- Saved: host-d, host-e | False Q: -
- Baseline FQ: - | baseline_wins=False

### lim12-near-dup-cdn-mimicry

- Break criterion: Jaccard regression vs #8/#20 passing results
- Truth: host-a, host-b, host-c
- Verdict: **HELD** | Jaccard=1.0 | margin=1.0
- Reasons: matched truth without merge-FQ; break_criterion not triggered: Jaccard regression vs #8/#20 passing results
- Quarantine dry-run: host-a, host-b, host-c
- Saved: host-d, host-e | False Q: -
- Baseline FQ: - | baseline_wins=False

## Honesty

- Lead with #10 (FP / baseline-wins), then #9b (structural reuse), then identity cluster (#9/#11).
- HELD ≠ clean: margin < 0.2 → **HELD, fragile**.
- Event sketches only; no live exploitation. Live OS quarantine remains unimplemented.
