# Corvex local stress / break results

Generated: **2026-08-06T12:35:15Z** (local Mac run, no Docker).

Standing claim unchanged: research correlator — holds up against synthetic ATT&CK-shaped fleets; **not** validated against real telemetry or pure-benign baselines.

## Suite summary

| Suite | Result | Artifact |
|-------|--------|----------|
| Unit tests | 88 passed (pre-macos); macos tests added separately | `pytest tests` |
| Fleet-limits T0 (5–6 hosts) | {'HELD, fragile': 5, 'HELD': 8, 'PARTIAL': 1, 'BROKE': 1} | `reports/attack_fleet_limits.md` |
| Fleet-limits T1 (15 hosts) | {'HELD, fragile': 13, 'PARTIAL': 1, 'BROKE': 1} | `reports/attack_fleet_limits_t1.md` |
| Fleet-limits T2 (50 hosts) | {'HELD, fragile': 13, 'PARTIAL': 1, 'BROKE': 1} | `reports/attack_fleet_limits_t2.md` |
| Fleet20 black-box | {'HELD': 20} | `reports/attack_fleet20.md` |
| SQL ART continuous stress | ok rounds / retries recorded | `reports/sql_art_stress.md` |
| Custom adversarial battery | BROKE=12 HELD=6 | `runs/adversarial-limits/report.json` |

## Hard breaks (reliable failures)

| Failure mode | Where seen | What happens |
|--------------|------------|--------------|
| Hostname / DHCP alias split-brain | `lim11` BROKE at T0/T1/T2 (J=0.0) | `host-b` vs `host-b-dhcp` never stitch — truth never recovered |
| Day-scale lookback cliff | `lim03` PARTIAL (J≈0.67); custom `day_gap_*` BROKE even at 1d w/ 24h window | Sleeper identity across quiet gaps fragments the campaign |
| DNS-only C2 | custom `dns_only_c2_blind` → 0 campaigns | No DNS correlator path from dns-only traffic in this harness shape |
| Shared service-account glue | custom `shared_svc_two_campaigns` → 1 campaign, J=0.5/0.5 | Two unrelated `svc-sql` chains over-merge |
| High-volume benign egress bury | custom `noise_5k_needle` J=0.15 | 5k CDN-ish conns → one mega-campaign of all hosts; needle lost |
| Window-edge bleed | custom `window_edge_600s` | Event at `window+1s` still merges into prior campaign |
| Disjoint islands | `break_disjoint_islands` | `both_missed`, misses `host-c` |
| Jumpbox over-merge | `break_overmerge_jumpbox` | Innocent `host-c` pulled into campaign |

## Fleet-limits weak rows

### T0

| ID | Verdict | Jaccard | Reasons |
|----|---------|---------|---------|
| `lim01-dual-ambiguous-lateral` | **HELD, fragile** | 1.0 | matched truth without merge-FQ; break_criterion not triggered: d or e appears in the malicious campaign's Q dry-run list |
| `lim03-slow-low-day-gaps` | **PARTIAL** | 0.6667 | jaccard 0.6667 in PARTIAL band |
| `lim08-out-of-order-arrival` | **HELD, fragile** | 1.0 | matched truth without merge-FQ; break_criterion not triggered: causal chain backwards, or split into two false fragments |
| `lim09b-sequential-reuse` | **HELD, fragile** | 1.0 | sequential incidents split across 2 campaigns |
| `lim09c-positional-bias` | **HELD, fragile** | 1.0 | matched truth without merge-FQ; break_criterion not triggered: Jaccard or margin regression vs original #1/#6 from host relabeling alone |
| `lim09d-benign-hub-pivot` | **HELD, fragile** | 1.0 | matched truth without merge-FQ; break_criterion not triggered: attack missed (BROKE) or b/d False Q via association |
| `lim11-hostname-split-brain` | **BROKE** | 0.0 | alias coverage miss: ['host-a', 'host-b', 'host-c']; truth never recovered: ['host-a', 'host-b', 'host-c'] |

### T1

| ID | Verdict | Jaccard | Reasons |
|----|---------|---------|---------|
| `t1-lim01-dual-ambiguous-lateral` | **HELD, fragile** | 1.0 | matched truth without merge-FQ; break_criterion not triggered: d or e appears in the malicious campaign's Q dry-run list |
| `t1-lim02-triple-concurrent-shared` | **HELD, fragile** | 1.0 | multi-campaign held |
| `t1-lim03-slow-low-day-gaps` | **PARTIAL** | 0.6667 | jaccard 0.6667 in PARTIAL band |
| `t1-lim04-timing-jitter` | **HELD, fragile** | 1.0 | matched truth without merge-FQ; break_criterion not triggered: Jaccard drop vs #5/#17 baseline at matched technique set |
| `t1-lim05-technique-sub-kerberoast` | **HELD, fragile** | 1.0 | matched truth without merge-FQ; break_criterion not triggered: campaign not detected, or techniques logged but not correlated |
| `t1-lim06-clock-skew-47s` | **HELD, fragile** | 1.0 | matched truth without merge-FQ; break_criterion not triggered: causal ordering a→b→c wrong, or b dropped due to apparent gap |
| `t1-lim07-dropped-mid-chain` | **HELD, fragile** | 1.0 | matched truth without merge-FQ; break_criterion not triggered: PARTIAL/BROKE, or false confidence that a,d is complete |
| `t1-lim08-out-of-order-arrival` | **HELD, fragile** | 1.0 | matched truth without merge-FQ; break_criterion not triggered: causal chain backwards, or split into two false fragments |
| `t1-lim09-max-density-overlap` | **HELD, fragile** | 1.0 | multi-campaign held |
| `t1-lim09b-sequential-reuse` | **HELD, fragile** | 1.0 | sequential incidents split across 3 campaigns |
| `t1-lim09c-positional-bias` | **HELD, fragile** | 1.0 | matched truth without merge-FQ; break_criterion not triggered: Jaccard or margin regression vs original #1/#6 from host relabeling alone |
| `t1-lim09d-benign-hub-pivot` | **HELD, fragile** | 1.0 | matched truth without merge-FQ; break_criterion not triggered: attack missed (BROKE) or b/d False Q via association |
| `t1-lim10-authorized-redteam` | **HELD, fragile** | 1.0 | no quarantine with empty truth |
| `t1-lim11-hostname-split-brain` | **BROKE** | 0.0 | alias coverage miss: ['host-00', 'host-01', 'host-02']; truth never recovered: ['host-00', 'host-01', 'host-02'] |
| `t1-lim12-near-dup-cdn-mimicry` | **HELD, fragile** | 1.0 | matched truth without merge-FQ; break_criterion not triggered: Jaccard regression vs #8/#20 passing results |

### T2

| ID | Verdict | Jaccard | Reasons |
|----|---------|---------|---------|
| `t2-lim01-dual-ambiguous-lateral` | **HELD, fragile** | 1.0 | matched truth without merge-FQ; break_criterion not triggered: d or e appears in the malicious campaign's Q dry-run list |
| `t2-lim02-triple-concurrent-shared` | **HELD, fragile** | 1.0 | multi-campaign held |
| `t2-lim03-slow-low-day-gaps` | **PARTIAL** | 0.6667 | jaccard 0.6667 in PARTIAL band |
| `t2-lim04-timing-jitter` | **HELD, fragile** | 1.0 | matched truth without merge-FQ; break_criterion not triggered: Jaccard drop vs #5/#17 baseline at matched technique set |
| `t2-lim05-technique-sub-kerberoast` | **HELD, fragile** | 1.0 | matched truth without merge-FQ; break_criterion not triggered: campaign not detected, or techniques logged but not correlated |
| `t2-lim06-clock-skew-47s` | **HELD, fragile** | 1.0 | matched truth without merge-FQ; break_criterion not triggered: causal ordering a→b→c wrong, or b dropped due to apparent gap |
| `t2-lim07-dropped-mid-chain` | **HELD, fragile** | 1.0 | matched truth without merge-FQ; break_criterion not triggered: PARTIAL/BROKE, or false confidence that a,d is complete |
| `t2-lim08-out-of-order-arrival` | **HELD, fragile** | 1.0 | matched truth without merge-FQ; break_criterion not triggered: causal chain backwards, or split into two false fragments |
| `t2-lim09-max-density-overlap` | **HELD, fragile** | 1.0 | multi-campaign held |
| `t2-lim09b-sequential-reuse` | **HELD, fragile** | 1.0 | sequential incidents split across 3 campaigns |
| `t2-lim09c-positional-bias` | **HELD, fragile** | 1.0 | matched truth without merge-FQ; break_criterion not triggered: Jaccard or margin regression vs original #1/#6 from host relabeling alone |
| `t2-lim09d-benign-hub-pivot` | **HELD, fragile** | 1.0 | matched truth without merge-FQ; break_criterion not triggered: attack missed (BROKE) or b/d False Q via association |
| `t2-lim10-authorized-redteam` | **HELD, fragile** | 1.0 | no quarantine with empty truth |
| `t2-lim11-hostname-split-brain` | **BROKE** | 0.0 | alias coverage miss: ['host-00', 'host-01', 'host-02']; truth never recovered: ['host-00', 'host-01', 'host-02'] |
| `t2-lim12-near-dup-cdn-mimicry` | **HELD, fragile** | 1.0 | matched truth without merge-FQ; break_criterion not triggered: Jaccard regression vs #8/#20 passing results |

## Soft breaks (HELD but fragile)

At **T1/T2** almost every HELD is **fragile** (ambiguity margin < 0.2): dual ambiguous lateral, out-of-order arrival (false-Q collateral on c/d), sequential reuse, positional bias, benign-hub pivot.

Custom `hub_fanout_20h`: attack Jaccard=1.0 but **17 innocents overmerged** — “held” on truth match, fails as containment evidence.

## What held under pressure

- Fleet20: 20/20 HELD (many `fusion_lift=false` — detector already enough)
- SQL ART continuous: innocents saved; truth hosts matched across retries
- Long 10-host hop, CDN bury of a clear auth chain, clock-skew ±47s, 50 parallel short chains, disjoint islands when users differ
- Abuse / HMAC / trust unit tests green
- Scale to 50 hosts does **not** invent new BROKE modes beyond alias + lookback; wall ~73s, RSS ~15MB

## Breaktest manifest scorecard (no Docker)

| Manifest | fusion_lift | both_missed | missed | over_merged | exit |
|----------|-------------|-------------|--------|-------------|------|
| `art_cred_hop.json` | True | False | [] | [] | 0 |
| `art_lateral_chain.json` | True | False | [] | [] | 0 |
| `art_recon_exfil_split.json` | False | False | [] | [] | 0 |
| `art_recon_pivot.json` | False | False | [] | [] | 0 |
| `art_slow_drip.json` | True | False | [] | [] | 0 |
| `break_blind_dns_c2.json` | True | False | [] | [] | 0 |
| `break_cdn_bridge_compound.json` | False | False | [] | [] | 0 |
| `break_disjoint_islands.json` | False | True | ['host-c'] | [] | 0 |
| `break_os_wide_sensors.json` | None | None | None | None | 1 |
| `break_overmerge_jumpbox.json` | False | False | [] | ['host-c'] | 0 |
| `break_sql_continuous_art.json` | False | False | [] | [] | 0 |

## Custom adversarial battery

- **BROKE:** `day_gap_1d`, `day_gap_2d`, `day_gap_3d`, `day_gap_7d`, `day_gap_14d`, `day_gap_21d`, `day_gap_30d`, `alias_dhcp_split`, `shared_svc_two_campaigns`, `noise_5k_needle`, `window_edge_600s`, `dns_only_c2_blind`
- **HELD:** `hub_fanout_20h`, `cdn_bury_20h`, `clock_skew_out_of_order`, `long_hop_10h`, `disjoint_should_split`, `parallel_50_chains`

Per-case detail: `runs/adversarial-limits/report.json`.

## Bottom line

Corvex breaks first on **identity** (aliases), **time** (day gaps / window edges), **shared principals** (svc accounts / hubs), and **channel coverage** (DNS-only) — not on host count. At ≥15 hosts almost every “pass” is fragile.

## Follow-ups enabled on this Mac

- New: `corvex sensor-macos` — see `docs/sensor-macos.md`
- Live net channel uses `lsof` TCP established (no Docker required)
- Live smoke on this machine: `runs/os-wide-macos-live/` — net hits=25, process sample hits=80, published=50 (rate-limited)
- Fixture smoke: `runs/os-wide-macos/` — 11 adapted envelopes from `fixtures/os_wide_macos/multi_channel.jsonl`

## Artifact index

```
reports/attack_fleet_limits.md
reports/attack_fleet_limits_t1.md
reports/attack_fleet_limits_t2.md
reports/attack_fleet20.md
reports/sql_art_stress.md
runs/breakers/breaker_summary.json
runs/breaktest-all/summary.json
runs/adversarial-limits/report.json
reports/local_stress_break_results.md  (this file)
```

