# Evaluation results

Sealed synthetic multi-host packs after `corvex seal-day0 --force` (expanded attack N + micro-F1 fix, 2026-10-23). **Care vs commercial tools: unproven.** Claim language: **`lab_verified`** (sealed + breaktest); **`claim_allowed=false`** until live second-host evidence lands.

**F1 reporting:** `campaign_f1` is the harmonic mean of **micro-averaged** precision and recall from pooled TP/FP/FN. Macro mean of per-pack F1 is `macro_campaign_f1` only (diagnostics). Prior tables that showed detector-only P≈0.33, R≈0.67, F1≈0.67 were inconsistent; that bug is fixed in `corvex.eval.aggregate_scores`.

## Held-out detection (sealed)

| Metric | Corvex | Detector-only | Notes |
|--------|--------|---------------|--------|
| Precision (micro) | **1.00** | **0.50** | Pooled TP/FP |
| Recall (micro) | **1.00** | **0.83** | Pooled TP/FN |
| Campaign F1 (micro) | **1.00** | **0.625** | `2PR/(P+R)` from pooled counts |
| Macro F1 (diagnostic) | 1.00 | ≈0.78 | Mean of pack F1s — not the headline |
| Precision@1 | **1.00** | ≈0.83 | |
| Benign false-campaign rate | **0.00** | — | Held-out benign packs (**N=6**) |
| Time-to-correlate | **~0.01 s** | — | Lab machine |

**Sample size (held-out):** attack packs **N=6** (lateral×2, exfil×2, fusion_chain, recon_lateral); benign packs **N=6**.

### Fusion vs detector-only

| | Correlator | Detector-only | B1 naive |
|--|------------|---------------|----------|
| F1 (micro) | **1.00** | **0.625** | **0.00** |
| Precision | **1.00** | **0.50** | **0.00** |
| Recall | **1.00** | **0.83** | **0.00** |

**Lift:** correlator micro-F1 **+0.375** vs detector-only on this sealed set. B1 misses multi-host campaigns.

Break-test / public-TTP manifests (`corvex score-non-author`): correlator micro-F1 **≈0.65** vs detector-only **≈0.20** (lift **≈+0.44**). Necessary for P3 non-author gate; **not** stranger Windows telemetry. Manifests are author-assembled with public TTP IDs.

## Held-out vs train

Re-run `corvex eval --split train` / `heldout` after seal. Prefer micro P/R/F1 columns in any table.

## By attack pattern (held-out)

After expansion, families include lateral, exfil, fusion_chain, recon_lateral, benign. See latest `reports/stageA_heldout.json` / eval markdown for per-family micro metrics.

## Stage A correlator honesty

| Control | Status |
|---------|--------|
| `window_seconds` enforced on key-clusters | **shipped** |
| Fleet-wide / poisoned SaaS dst skip | **shipped** |
| Jumpbox: no lateral↔lateral 1-host glue | **shipped** |
| Auth↔exfil 1-host bridges (fusion_chain) | **kept** |
| Micro-F1 aggregation | **shipped** (2026-10-23) |

## Stage B OS-wide sensor

Observe-only Windows / macOS collectors. Lab unlock: `corvex stage-b-lab-unlock` (`CORVEX_STAGE_B=1` removed). DNS coverage requires Sysmon EID 22 (Windows) or unified-log dns (macOS); otherwise `channel_health.dns` GAP.

| Check | Status |
|-------|--------|
| Stranger attestation | **pass** — Jack Ed25519 |
| `claim_allowed` | **locked** — needs `reports/live_second_host.json` |
| HMAC verify on ingest | **shipped** |

## Claim gates (`corvex claim-gates`)

| Gate | Status |
|------|--------|
| non_author_fusion_lift | pass (breaktest micro lift ≈+0.44) |
| benign_fcr_real_n | pass (N=6, FCR=0) |
| stranger_success | **pass** (Jack, Ed25519) |
| trust_integrity | pass |
| live_second_host | **fail** until second physical PC |
| **lab_verified** | **true** |
| **claim_allowed** | **false** |

Blocked overclaim demo: `python scripts/demo_blocked_claim.py`. Semantics: `docs/claim-gates.md`. Stress WHY: `docs/stress-failure-modes.md`.

## Open-source attack eval (primary — external authorship)

[`opensource_attack_eval.md`](opensource_attack_eval.md) · [`opensource_attack_inventory.md`](opensource_attack_inventory.md) · [`../labs/opensource/`](../labs/opensource/)

**36** OTRF/Security-Datasets + ATT&CK Evals corpora (Empire, Covenant, PurpleSharp, Caldera APT3, native). **Not** Corvex-authored tests.

| Result | Detail |
|--------|--------|
| Verdicts | **34** MULTI_HOST_NO_LIFT · **2** SINGLE_HOST (Empire APT3 compound, ntdsutil) |
| Breaks | FUSION_NO_LIFT×34 · Q_DRYRUN_ALL_HOSTS×30 · ADAPTER_HEAVY_SKIP×26 |
| Read | Forms multi-host camps on public captures; **never** beats detector-only host coverage; dry-run Q often marks every host; adapter drops most raw events |

```bash
python scripts/fetch_opensource_corpora.py --full
python scripts/run_opensource_attack_eval.py
```

## Aggressive compound battery (hardest public captures)

[`opensource_aggressive_eval.md`](opensource_aggressive_eval.md) · [`opensource_aggressive_inventory.md`](opensource_aggressive_inventory.md)

**14** hardest OTRF compounds: APT29 day1/day2 (ATT&CK Evals R2), Caldera/Empire APT3, 7× Metasploit LSASS dump variants, Log4Shell Sysmon/Security, Golden SAML Windows.

| Result | Detail |
|--------|--------|
| Verdicts | **4** FUSION_HELD · **10** SINGLE_HOST · **0** MULTI_HOST_NO_LIFT · **0** Q_DRYRUN_ALL_HOSTS |
| APT29 day1/day2 | FUSION_HELD — saturated 4-host lab; correlator consolidates vs detector; surgical Q (cut-point) |
| Caldera APT3 | FUSION_HELD — 5-host fleet; same |
| Golden SAML | FUSION_HELD — 2-host ADFS lateral |
| Empire APT3 / LSASS×7 / Log4Shell | SINGLE_HOST — capture shape, fusion not testable |
| Remaining breaks | ADAPTER_HEAVY_SKIP (allowlist noise) · SINGLE_HOST only — not fusion failures |
| Fixes landed | ambient micro-exfil poison · hop peers (WorkstationName) · no recon host-union · no fleet-wide recon camp · surgical Q · weak-account hop gate |

```bash
python scripts/fetch_opensource_corpora.py --aggressive
python scripts/run_opensource_attack_eval.py --aggressive
```

**claim_allowed stays false** — lab purple-team only; not enterprise validation.

## Live laptop stress (Corvex running + OTRF replay)

[`live_opensource_stress.md`](live_opensource_stress.md) · run dir `runs/live-oss-stress/` · dash `http://127.0.0.1:8765/`

Catalog expanded to **76** OTRF entries (**58** `live_stress`); **56** streamed on this Windows laptop while correlator+dash stayed up. Mode: `offline_lab_replay_into_live_correlator` — **not** live malware execution.

| Catch | N |
|-------|---|
| **CAUGHT** (new multi-host bridge / camp growth) | **20** |
| **ALREADY_COVERED** (hosts already in multi-host camps) | **19** |
| **SINGLE_HOST_BATCH** (capture &lt;2 hosts) | **17** |
| **MISS** | **0** |

Final live state: **55** multi-host campaigns, APT29/Caldera/Covenant/Empire/PurpleSharp all produced bridge growth. Optional `sensor-windows` once sampled PC telemetry (Stage B observe-only).

```bash
python scripts/fetch_opensource_corpora.py --live-stress
python scripts/run_live_opensource_stress.py --dash --sensor
```

## Author-fleet battery (secondary)

[`full_capability_battery.md`](full_capability_battery.md) · [`intensive_capability_matrix.md`](intensive_capability_matrix.md) · [`../docs/stress-failure-modes.md`](../docs/stress-failure-modes.md)

Engineering probes only (exfil_bury BROKE, helpdesk fragile, lim07 PARTIAL). Do not lead with these for independence.

## What this does / does not prove

**Proves (narrow):** Sealed micro-F1 discipline; breaktest fusion lift; open-source captures form multi-host campaigns without author-written GT; claim gate stays locked without second-host evidence.

**Does not prove:** Fusion lift on OTRF vs detector-only; enterprise telemetry; OS quarantine; commercial parity.

## Reproduce

```bash
python scripts/fetch_opensource_corpora.py
python scripts/run_opensource_attack_eval.py
corvex eval --split heldout
corvex claim-gates
python scripts/demo_blocked_claim.py
```
