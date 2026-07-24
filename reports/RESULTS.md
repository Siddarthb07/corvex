# Evaluation results

Sealed synthetic multi-host packs after `corvex seal-day0 --force` (fusion_chain + expanded benign N). **Care vs commercial tools: unproven.** Claim language stays lab/BYO until `corvex claim-gates` → `claim_allowed=true`.

## Held-out detection (sealed)

| Metric | Corvex | Notes |
|--------|--------|--------|
| Precision | **1.00** | Flagged campaigns that matched ground truth |
| Recall | **1.00** | True multi-host campaigns recovered |
| Campaign F1 | **1.00** | Harmonic mean of P+R |
| Precision@1 | **1.00** | Top-ranked campaign correct |
| Benign false-campaign rate | **0.00** | Held-out benign packs (**N=5**) |
| Time-to-correlate | **~0.01 s** | Wall time ingest→campaigns (lab machine) |

**Sample size (held-out):** attack packs **N=3** (lateral OOD, exfil, fusion_chain); benign packs **N=5**.

### Fusion vs detector-only (the correlator premise)

| | Correlator | Detector-only | B1 naive |
|--|------------|---------------|----------|
| F1 | **1.00** | **0.67** | **0.00** |
| Precision | **1.00** | **0.33** | **0.00** |
| Recall | **1.00** | **0.67** | **0.00** |

**Lift:** correlator F1 **+0.33** vs detector-only on this sealed set (fusion_chain is what separates them). B1 still misses multi-host campaigns entirely.

Break-test / public-TTP manifests (`corvex score-non-author`): correlator F1 **~0.63** vs detector-only **~0.19** (lift **~+0.44** after window/anti-jumpbox honesty). Necessary for P3 non-author gate; **not** stranger Windows telemetry.

## Held-out vs train

| Split | Precision | Recall | F1 | Det-only F1 | Benign FCR | TTU |
|-------|-----------|--------|-----|-------------|------------|-----|
| Train | 1.00 | 1.00 | 1.00 | 0.67 | 0.00 (N=2) | ~0.01 s |
| Held-out | 1.00 | 1.00 | 1.00 | 0.67 | 0.00 (N=5) | ~0.01 s |

## By attack pattern (held-out)

| Family | Precision | Recall | F1 | Benign FCR |
|--------|-----------|--------|-----|------------|
| lateral (OOD) | 1.00 | 1.00 | 1.00 | — |
| exfil | 1.00 | 1.00 | 1.00 | — |
| fusion_chain | 1.00 | 1.00 | 1.00 | — |
| benign (N=5) | — | — | — | **0.00** |

## Stage A correlator honesty (post CDN Bridge)

| Control | Status |
|---------|--------|
| `window_seconds` enforced on key-clusters | **shipped** |
| Fleet-wide / poisoned SaaS dst skip | **shipped** |
| Jumpbox: no lateral↔lateral 1-host glue | **shipped** |
| Auth↔exfil 1-host bridges (fusion_chain) | **kept** |

**Operation CDN Bridge** (`labs/breaktest/manifests/break_cdn_bridge_compound.json`): best Jaccard vs truth **1.0** (APT `{a,b,c}` no longer fat-merged with CDN). Residual: separate helpdesk campaign still contributes `host-d` to the all-campaigns union; DNS / >50KB blob remain invisible by design.

## Stage B OS-wide sensor

Observe-only Windows collector: `corvex sensor-windows` (Security + Sysmon + Firewall + PowerShell). Fixture CI path: `fixtures/os_wide/multi_channel.jsonl`. Lab unlock `CORVEX_STAGE_B=1`; honest unlock needs stranger PASS + `reports/stage-b-allowed`.

| Check | Status |
|-------|--------|
| Fixture `--once` → campaigns | **pass** (unit + smoke) |
| Multi-host exporter shape | **pass** (`scripts/smoke_os_wide_multihost.py`) |
| Allowlist + rate cap | **shipped** |
| wevtutil `--follow` on live PC | best-effort (degrades if channel missing) |
| Stranger / `claim_allowed` | **still locked** |

Docs: [`docs/os-wide-sensor.md`](../docs/os-wide-sensor.md).

## Reconstruction regression

`corvex eval-recon --split heldout` → **8/8** packs ok (3 attack + 5 benign). Manifests labeled `regression_only`.

## Containment dry-run (not live)

| Metric | Held-out |
|--------|----------|
| Hosts proposed | 11 |
| Correct isolates | 11 |
| False isolates | **0** |
| False-isolate rate | **0.00** |

`CORVEX_CONTAIN=0`. Live path scaffolded behind L1 + hostile-bus; OS quarantine still unimplemented.

## Claim gates (`corvex claim-gates`)

| Gate | Status |
|------|--------|
| non_author_fusion_lift | pass (breaktest lift ~+0.44) |
| benign_fcr_real_n | pass (N=5, FCR=0) |
| stranger_success | **fail** (pending external operator) |
| **claim_allowed** | **false** |

## What this does / does not prove

**Proves (narrow):** Sealed packs separate fusion from detector-only; window/anti-jumpbox honesty holds without collapsing Stage A gate; benign FCR holds at N=5; reconstruction round-trips; breaktest fusion lift remains positive.

**Does not prove:** Real malware defense, stranger Windows success, commercial parity, or that live contain is safe to arm.

## Reproduce

```bash
corvex seal-day0 --force
corvex eval --split train
corvex eval --split heldout
corvex eval-recon --split heldout
corvex score-non-author
corvex claim-gates
corvex hostile-bus-test
```
