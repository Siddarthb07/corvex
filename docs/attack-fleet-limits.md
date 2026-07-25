# Fleet: Limits (`fleet-limits`) — Corvex Breaking-Point Suite

**Goal:** find where Corvex fails, not confirm it doesn't.

Fleet20 returned 20/20 HELD with Jaccard 1.0. That is more likely to mean "the test set is too easy / too self-consistent" than "the correlator is bulletproof," especially since many attacks were authored by the same person who wrote the detector. This suite is designed against that bias.

Purple-team **event sketches** only. Quarantine = dry-run IsolateHost proposals. Live OS quarantine is not implemented.

## How to run

```bash
python scripts/run_attack_fleet_limits.py --intensity 2 --baseline single-host-isolation
# regenerate write-up framing from last JSON without re-running:
python scripts/run_attack_fleet_limits.py --from-json reports/attack_fleet_limits.json
# T1 scale (15 hosts) / T2 (50 hosts):
python scripts/run_attack_fleet_limits_scale.py --hosts 15 --intensity 2 --no-decoy
python scripts/run_attack_fleet_limits_scale.py --hosts 50 --intensity 2 --no-decoy
```

Reports: `reports/attack_fleet_limits.md`, `attack_fleet_limits_t1_nodecoy.md`, `attack_fleet_limits_t2_nodecoy.md`  
Manifests: `labs/breaktest/manifests/fleet-limits/`, `fleet-limits-t1[-nodecoy]/`, `fleet-limits-t2[-nodecoy]/`

## Scoring (falsifiable — stated before the run)

| Verdict | Criteria |
|---------|----------|
| **HELD** | Best-campaign Jaccard ≥ 0.9, no false-negative on any truth host, ambiguous legitimate activity correctly kept split (not merged into the malicious campaign). |
| **HELD, fragile** | Same as HELD, but **ambiguity margin &lt; 0.2**. Near-miss wearing a pass — not equivalent to a clean HELD (e.g. #9d). |
| **PARTIAL** | Jaccard 0.5–0.89, **or** a truth host missed but recovered on replay, **or** a benign host wrongly merged into the malicious campaign (over-merge) without being falsely quarantined. |
| **BROKE** | Jaccard &lt; 0.5, **or** a truth host never recovered, **or** a benign host proposed for quarantine as part of the malicious campaign specifically because it got merged in. |

Also:

- **margin (fragile gate)** = ambiguity margin. For multi-campaign truth cleanly attributed (min Jaccard ≥ 0.9, no collapse): `min(matched scores) − max(unmatched competitor)`; if no unmatched competitor, `min(matched)`. Single-truth packs: `confidence(top) − confidence(2nd-best)`. Raw top−2nd retained as `confidence_margin_raw`. Correctly separated equal-score campaigns are **not** fragile.
- **baseline** = single-host isolation (B1). If baseline wins (fewer False Q, same coverage), fusion made things worse — lead with that, don't bury it.

### Contain gate (#10) — narrow honesty

IsolateHost proposals require `micro_exfil` / `dns_beacon` **or** `recon_fanout`+`lateral_auth`. Lateral-only campaigns are still **correlated and reported**; contain is refused.

This closes **attack-shaped-but-clearly-inert** (lim10). It does **not** solve general false positives: authorized pentests that include exfil-shaped traffic still clear the gate. Intent is not in telemetry — do not cite as “FP problem solved.”

## How to write up results (consequence order)

Do **not** lead with the BROKE count. Lead with operational severity:

1. **#10 authorized red-team (empty truth)** — Most important. Every other failure is "misses or conflates an attack." This one is "quarantines innocent, authorized activity, and does it worse than doing nothing." Baseline winning means correlation *actively hurt*. False positives get tools turned off.
2. **#9b sequential reuse** — Structural, not an edge case. Small fixed host pools will reuse infrastructure across unrelated incidents. Fix should be a hard requirement: temporal gap + technique-shape discontinuity force a split even at 100% host overlap.
3. **#9 hub collapse + #11 split-brain** — Same identity/attribution gap: "one host, too many roles" vs "one host, two labels." Shared fix path: persistent asset ID (not hostname) + degree-weighted evidence before merging through high-connectivity nodes.
4. **#3 day-gap PARTIAL** — Good failure: states an operational boundary ("reliable to N days, degrades past that") instead of an unfalsifiable claim.
5. **Fragile HELDs (#9d, #1)** — Margin < 0.2 with collateral False Q is not a clean pass.

## Attack catalog

| # | ID | What it probes |
|---|-----|----------------|
| 1 | dual-ambiguous-lateral | Helpdesk shares host **c** with APT (tighter than fleet20#19) |
| 2 | triple-concurrent-shared | Three campaigns chained via shared hosts |
| 3 | slow-low-day-gaps | 14 / 21 / 9 day inter-stage gaps |
| 4 | timing-jitter | Randomized delays vs DNS C2 / hybrid baselines |
| 5 | technique-sub-kerberoast | T1558 → T1021.006 → T1041 (off fleet20 library) |
| 6 | clock-skew-47s | +47s skew on host-b (fleet01 shape) |
| 7 | dropped-mid-chain | Host-c telemetry dropped (SMB hop shape) |
| 8 | out-of-order-arrival | Exfil timestamped before causal lateral |
| 9 | max-density-overlap | 3 campaigns, hub host **c** in all three |
| 9b | sequential-reuse | Two incidents, same hosts, 10 min gap |
| 9c | positional-bias | Rotate so **e** is patient-zero (#1/#6 shapes) |
| 9d | benign-hub-pivot | High benign RDP/SMB on **c** + real pivot |
| 10 | authorized-redteam | Attack-shaped, truth = ∅ |
| 11 | hostname-split-brain | Host-b dual hostname mid-attack |
| 12 | near-dup-cdn-mimicry | C2 matches CDN bait timing/volume |

## What success looks like

Not another N/N HELD. A useful outcome is mixed HELD/PARTIAL/BROKE that shows the boundary — especially a clean story on #10, a structural read on #9b, and an operational lookback number from #3.

## Honesty

- All scenarios stay at ≤6 hosts for T0 (mostly 5). Scale remaps are separate (T1/T2).
- No live exploitation. Event sketches only.
- Do not treat N/N HELD as “works on real attacks.”

### Publication decision (evasion cookbook tradeoff)

**Decision (2026-07-25): keep these docs public** for early-stage authenticity — the suite exists to falsify Corvex, and hiding break criteria undercuts that. Audience today is the author plus reviewers/admissions readers, not a production SOC defending a networked deployment.

Accepted tradeoff: thresholds and bypass shapes (day-gap, hub-degree, sequential-reuse, contain gate) are visible. Revisit (private mirror or redact knobs) **before** any networked bus / live contain deployment. Until then, prefer fix+regress over secrecy.
- Live OS quarantine remains unimplemented.
