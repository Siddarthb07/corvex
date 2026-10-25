# Claim Gates for Synthetic Security Evaluations: Sealed Packs, Detector Ablation, External Corpora, and Machine-Checked Field Language

> **Prefer the final package for submission:** [`CORVEX_PAPER_FINAL.md`](CORVEX_PAPER_FINAL.md) · PDF [`paper/Corvex_Claim_Gates_FINAL.pdf`](paper/Corvex_Claim_Gates_FINAL.pdf). This file is retained as working history.

**Venue framing:** Workshop / experience paper (CSET-style claim-production review).  
**Artifact:** https://github.com/Siddarthb07/corvex · CLI `corvex`  
**Draft date:** 2026-10-24 · Numbers from in-repo reports after micro-F1 fix + OTRF / live-stress batteries.  
**Standing claim (unchanged):** Research correlator — holds up on synthetic ATT&CK-shaped fleets; **not** validated on real enterprise telemetry or pure-benign baselines.  
**`claim_allowed`:** false (`live_second_host` gate open).

Companion: [`CSET_REVISION_CHECKLIST.md`](CSET_REVISION_CHECKLIST.md).

---

## Abstract

Security evaluation papers often report near-perfect scores on small synthetic benchmarks and then allow abstracts, READMEs, and portfolios to drift into field language. We report an **evaluation protocol** built around Corvex, an open-source multi-host campaign correlator (HMAC-signed event envelopes; weak per-host detectors; optional cross-host fusion). The protocol has five parts: (1) Fernet-sealed held-out packs and an isolated scorer; (2) a detector-only ablation that disables cross-host merge; (3) a harder public-TTP breaktest corpus that was not the tuning target; (4) **externally authored** OTRF/Security-Datasets and MITRE ATT&CK Evals captures as the primary independence stress; (5) a machine-checked **claim gate** that refuses `claim_allowed=true` until live second-host and related evidence exist.

We correct a prior reporting error in which campaign F1 was the mean of per-pack F1s while precision and recall were micro-averaged (impossible triples such as P≈0.33, R≈0.67, F1≈0.67). After the fix, sealed held-out correlator micro-F1 remains **1.00** (N_attack=6, N_benign=6) while detector-only micro-F1 is **0.625**. On the breaktest corpus, correlator micro-F1 is approximately **0.65** versus detector-only approximately **0.20** (lift ≈+0.44). On **14** hardest public compounds (APT29 day1/day2, Caldera APT3, Golden SAML, LSASS variants, Log4Shell), multi-host captures score **4 FUSION_HELD** and **10 SINGLE_HOST** after correlator/quarantine fixes—with surgical dry-run quarantine (no fleet-wide spray). Streaming **56** OTRF captures into a live correlator process on a Windows laptop yields **0 MISS** (20 CAUGHT, 19 ALREADY_COVERED, 17 single-host batches). We document stress-failure **mechanisms** (not bare “BROKE” labels) and show a drafted marketing sentence blocked by the gate. Limitations remain: sealed N is modest; enterprise telemetry and home-lab benign PASS are deferred; `claim_allowed` stays false.

---

## 1. Introduction

Venues that scrutinize security claims care as much about **how scores become sentences** as about ROC curves. A recurring failure mode is **lab-to-field language drift**: a system scores well on synthetic packs; the abstract and README then imply production usefulness.

Corvex fuses weak per-host detectors (lateral authentication, micro-exfiltration, recon fanout, optional DNS beacons) into multi-host campaigns. This paper is **not** a claim of a new state-of-the-art IDS, nor of enterprise validation. It is an **experience report** on forcing evaluation discipline around that correlator: seal answers, ablate fusion, publish harder and external scores, name failure mechanisms, and lock field language behind machine-checked gates.

### 1.1 Why the previous draft was rejected (and what we changed)

Both SaTML and CSET rejected earlier packaging; CSET-style feedback was actionable. Table 1 maps critique → response. Detail: [`CSET_REVISION_CHECKLIST.md`](CSET_REVISION_CHECKLIST.md).

| Critique | Response in this draft |
|----------|------------------------|
| Inconsistent F1 (macro of pack F1s vs micro P/R) | Micro F1 = harmonic mean of pooled P and R; macro diagnostic only |
| Sealed N too small | Attack packs expanded to N=6 (+ N=6 benign); still labeled modest |
| Author-written fleets as “the” test | **OTRF / ATT&CK Evals lead** independence; author fleets secondary |
| “BROKE” without mechanism | [`stress-failure-modes.md`](stress-failure-modes.md) |
| Soft field language after F1=1.00 | Standing claim + `claim_allowed=false` + blocked-claim demo |
| Missing ablation / harder OOD | Detector-only tables; breaktest drop; aggressive APT29/APT3 |

### 1.2 Contributions

1. A concrete protocol (seal, ablate, breaktest, **external OTRF**, claim gate) with open tooling.
2. Correction and re-publication of campaign F1 as micro-consistent.
3. External-authorship scoreboards (OTRF atomic + APT29/APT3 compounds + live replay) that do not invent Corvex-authored ground-truth F1 on those packs.
4. Named stress-failure mechanisms with before/after status.
5. An explicit blocked overclaim demonstration (`python scripts/demo_blocked_claim.py`).

---

## 2. System under evaluation (brief)

Corvex ingests signed `EventEnvelope` records, runs per-host detectors, then optionally fuses across hosts using time windows, hop graphs, ambient-destination poison, and anti-jumpbox merge rules. Quarantine modes are `dry_run` / `lab_flag` / `blocked` only; live OS containment defaults off (`CORVEX_CONTAIN=0`). Stage B sensors are observe-only. ATT&CK tags are coarse hypotheses from stage names.

**Terminology.**

| Term | Meaning |
|------|---------|
| Correlator | Fusion path (cross-key / cross-host merge) |
| Detector-only | Alerts grouped by detector key **without** that merge |
| Breaktest | Public-TTP-shaped manifests under `labs/breaktest/` (still author-assembled) |
| OTRF corpus | Externally authored Mordor / Security-Datasets / ATT&CK Evals captures |
| Claim gate | `corvex claim-gates` predicates over on-disk artifacts |

---

## 3. Evaluation protocol

### 3.1 Seal held-out packs

Campaign generators write JSONL packs; packs are Fernet-sealed under an external key before correlator retunes. Scorer rules are sealed separately. Sealing reduces accidental train/test snooping; it does **not** create outsider authorship.

**Current sealed held-out size:** attack **N=6** (lateral×2, exfil×2, fusion_chain, recon_lateral); benign **N=6**. Still synthetic.

### 3.2 Detector-only ablation

The same events are scored under `detector_only=True`. Fusion lift is correlator micro-F1 minus detector-only micro-F1 (or, on observational OTRF packs without author GT, host-coverage / consolidation metrics defined in §5.3).

### 3.3 Breaktest (harder, still author-assembled)

Manifests under `labs/breaktest/manifests` cite public Atomic / ATT&CK technique IDs but are author-assembled. Results are reported even when worse than sealed.

### 3.4 External open-source captures (primary independence stress)

OTRF/Security-Datasets and MITRE ATT&CK Evals Caldera/manual captures are fetched, sanitized (CommandLine/ScriptBlockText stripped for Defender), adapted, signed under lab enrollment, and scored with **observational** verdicts (no Corvex-authored ground-truth F1). Catalog: `labs/opensource/catalog.json` (76 entries as of this draft).

### 3.5 Claim gates

`claim_allowed` requires all of: non-author fusion lift, human Ed25519 stranger attestation, sealed benign FCR with minimum N, trust integrity probes, and `reports/live_second_host.json` from elevated wevtutil on a **second physical** Windows host. `stage-b-lab-unlock` unlocks sensors only — it does not flip `claim_allowed`. Details: [`claim-gates.md`](claim-gates.md).

**Blocked claim example.** Drafted sentence: “Corvex works on real multi-host attacks in enterprise networks and is ready for production SOC use.” Gate result today: `claim_allowed=false`, blocked on `live_second_host`. Allowed sentence remains the standing claim. Reproduce: `python scripts/demo_blocked_claim.py`.

---

## 4. Metrics correction (reviewer Table 2)

Previously, aggregate `campaign_f1` was the **mean of per-pack F1**, while `precision` and `recall` were computed from **pooled TP/FP/FN**. That can yield inconsistent triples (e.g. P≈0.33, R≈0.67, F1≈0.67), which is not a harmonic mean of those P and R.

**Fix.** `aggregate_scores` sets `campaign_f1 = 2PR/(P+R)` from pooled counts (`f1_aggregation: micro_from_tp_fp_fn`). Macro mean of pack F1s is retained as `macro_campaign_f1` for diagnostics only. Regression: `tests/test_eval_metrics.py`.

---

## 5. Results

### 5.1 Sealed held-out (synthetic, author-generated, sealed)

| Metric | Correlator | Detector-only | B1 (single-host) |
|--------|------------|---------------|------------------|
| Precision (micro) | 1.00 | 0.50 | 0.00 |
| Recall (micro) | 1.00 | 0.83 | 0.00 |
| F1 (micro) | **1.00** | **0.625** | 0.00 |
| Macro F1 (diagnostic) | 1.00 | ≈0.78 | — |
| Benign FCR | 0.00 (N=6) | — | — |

Reproduce: `corvex seal-day0 --force` then `corvex eval --split heldout`.

**Interpretation.** Perfect correlator F1 on N=6 sealed attack packs is **necessary but not sufficient**. Detector-only micro-F1 0.625 shows fusion still matters on this set; the absolute correlator score remains a small synthetic upper bound.

### 5.2 Breaktest / public-TTP (author-assembled, harder)

| Metric | Correlator | Detector-only |
|--------|------------|---------------|
| Precision (micro) | ≈0.50 | ≈0.13 |
| Recall (micro) | ≈0.91 | ≈0.45 |
| F1 (micro) | ≈**0.65** | ≈**0.20** |
| F1 lift | ≈**+0.44** | — |

Reproduce: `corvex score-non-author`. Authorship: in-repo manifests with public TTP IDs — **not** an independent enterprise red team.

### 5.3 External OTRF scoreboards (primary independence)

#### 5.3.1 Broad atomic + Caldera APT3 day1 (observational)

Current scoreboard on **36** Empire/Covenant/PurpleSharp/native + Caldera APT3 corpora (external authorship; `reports/opensource_attack_eval.md`):

| Verdict / break | Count |
|-----------------|-------|
| MULTI_HOST_NO_LIFT | **34** |
| SINGLE_HOST | **2** |
| FUSION_NO_LIFT (break flag) | 34 |
| Q_DRYRUN_ALL_HOSTS | 30 |
| ADAPTER_HEAVY_SKIP | 26 |

Read honestly: multi-host campaigns **form** on public captures, but this broad atomic set **does not** beat detector-only host coverage, and dry-run quarantine often marks every host. Those failure modes drove correlator and quarantine fixes (ambient micro-exfil poison, hop peers via WorkstationName, no recon host-union, surgical cut-point quarantine) that are measured on the **aggressive** compounds below—not claimed as a retroactive rewrite of this atomic table.

Reproduce: `python scripts/fetch_opensource_corpora.py --full && python scripts/run_opensource_attack_eval.py`.

#### 5.3.2 Aggressive compounds (APT29 / APT3 / Golden SAML / LSASS / Log4Shell)

| Verdict | N | Meaning |
|---------|---|---------|
| **FUSION_HELD** | **4** | APT29 day1, APT29 day2, Caldera APT3 day1, Golden SAML — saturated small fleets; correlator consolidates vs detector; Q not fleet-wide |
| **SINGLE_HOST** | **10** | Empire APT3 compound, 7× LSASS Metasploit variants, Log4Shell×2 — fusion not testable |
| FUSION_NO_LIFT / Q_DRYRUN_ALL_HOSTS | **0** | After fixes |

Honesty: on saturated 4–5 host labs, host-coverage lift can be definitionally zero when both arms already cover all hosts; HELD here means consolidation + surgical quarantine, not “more hosts than detector.” Adapter skip rates on APT29 remain high (≈0.86–0.94) — allowlist noise, stated as a remaining break type.

Reproduce: `python scripts/fetch_opensource_corpora.py --aggressive && python scripts/run_opensource_attack_eval.py --aggressive`.

#### 5.3.3 Live laptop stress (correlator running + OTRF replay)

**Mode:** `offline_lab_replay_into_live_correlator` — captures are replayed into a live Corvex process and dash on the author’s Windows laptop. This is **not** executing Empire/Covenant/malware on that laptop.

| Catch label | N (of 56) |
|-------------|-----------|
| CAUGHT (new multi-host bridge / camp growth) | 20 |
| ALREADY_COVERED | 19 |
| SINGLE_HOST_BATCH | 17 |
| **MISS** | **0** |

Final live snapshot: 139 594 events; 55 multi-host campaigns spanning APT29, Caldera, Mordor workstation, and Golden SAML hostnames.

Reproduce: `python scripts/fetch_opensource_corpora.py --live-stress && python scripts/run_live_opensource_stress.py --dash`.

### 5.4 Author-fleet stress (secondary engineering probes)

| Suite | Result (summary) |
|-------|------------------|
| Fleet20 | 20 HELD; fragile_rate 0.05 — never report bare 20/20 |
| Fleet-limits T0 | HELD 14 (fragile 5); PARTIAL 1; BROKE 0 |
| Intensive multifactor | HELD 23; fragile 5; PARTIAL 2; BROKE 3 (exfil_bury) |

These packs are **in-repo** purple-team sketches. They are useful for mechanism debugging; they are **not** the independence headline.

### 5.5 Stress failures — what broke and why

| Mode | Mechanism | Status |
|------|-----------|--------|
| DHCP hostname split-brain | Distinct `host_id` strings; multihost enrollment refuse | HELD (runtime aliases) |
| Day-scale sleeper | 1h resume fragmented chains | HELD (separate sleeper resume) |
| Shared svc-account | Time window glued disjoint hop islands | Unit HELD (hop partition) |
| High-volume egress bury | CDN-like dst fanout swallowed needle | Unit poison HELD; intensive bury cells still BROKE on 3/4 |
| DNS-only C2 | No Sysmon EID 22 → no DNS events | Honest `channel_health.dns` GAP |
| Dropped mid-chain | Truth host with no telemetry | Remains PARTIAL (correct) |
| Fleet-wide Q dry-run | Recon union + egress-on-all-hosts spray | Fixed: annotate-only recon; cut-point Q |
| Ambient metadata micro-exfil | `169.254.169.254` / Azure wire free multi-host detector coverage | Fixed: ambient poison in detectors + correlator |

Full table: [`stress-failure-modes.md`](stress-failure-modes.md).

---

## 6. What the protocol prevented

Without gates, the natural README sentence after sealed F1=1.00 would soft-upgrade to “works on multi-host attacks.” The claim evaluator keeps `claim_allowed=false` while `live_second_host` is absent. That is a **process** contribution: a claim that was drafted and then blocked, with reproducible evidence on disk (`reports/claim_gates.json`).

---

## 7. Limitations

1. **Sample size.** Sealed attack N=6 is expanded but still modest. Larger N reduces variance; it does not create field validity.
2. **Authorship tiers.** Sealed and breaktest packs are primarily author-generated. OTRF packs are external in origin but remain lab purple-team captures, not enterprise estates.
3. **Observational OTRF metrics.** We do not invent Corvex-authored GT F1 on OTRF. FUSION_HELD on saturated fleets is consolidation/Q discipline, not proof of host-coverage lift over detector-only on every atomic.
4. **No enterprise telemetry** in this draft. Second physical Windows host evidence and ≥72 host-hour home-lab benign capture are deferred until hardware/operator time exists.
5. **Claim lock is not DRM.** It is reproducible and auditable; a determined author can forge files. The intended consumer is peer review and portfolio honesty.
6. **Novelty.** Seal / ablate / OOD / gate are known practices; the contribution is packaging them into one open correlator artifact with corrected metrics, external scoreboards, named failure mechanisms, and a refused-claim example.
7. **Live stress ≠ live malware.** Laptop stress replays sanitized OTRF JSONL into Corvex; it does not demonstrate catching an active implant on that machine.

---

## 8. Related work and positioning

Held-out sealing relates to classic train/test hygiene and competition leaderboards that hide labels. Ablation mirrors standard ML baseline tables. Breaktests and OTRF suites resemble adversarial or OOD evaluation. Claim gates resemble release criteria and model cards, applied to **security field language**. We do not claim theoretical novelty for any single component.

---

## 9. Conclusion

Synthetic security evaluations need hard stops between lab scores and field claims. Corvex’s protocol—seal, ablate, breaktest, external OTRF, gate—makes that stop executable. After correcting micro-F1 reporting, we still observe a large drop from sealed correlator F1=1.00 to breaktest F1≈0.65; we lead independence claims with external captures; we name failure mechanisms; and we keep `claim_allowed=false` until second-host evidence exists. Future work: independent operator packs, home-lab benign PASS/FAIL against pre-committed bars, and live second-host attestation—without softening claims ahead of evidence.

---

## Appendix A — Reproduce

```bash
pip install -e ".[dev]"

# Metrics + sealed
corvex seal-day0 --force
corvex eval --split heldout
corvex score-non-author
pytest tests/test_eval_metrics.py -q

# External independence (primary)
python scripts/fetch_opensource_corpora.py --full
python scripts/run_opensource_attack_eval.py
python scripts/fetch_opensource_corpora.py --aggressive
python scripts/run_opensource_attack_eval.py --aggressive

# Live replay (optional; dash)
python scripts/fetch_opensource_corpora.py --live-stress
python scripts/run_live_opensource_stress.py --dash

# Claim discipline
corvex claim-gates
python scripts/demo_blocked_claim.py
```

## Appendix B — Artifact map

| Document | Role |
|----------|------|
| `docs/CSET_REVISION_CHECKLIST.md` | Rejection → response map |
| `docs/claim-gates.md` | Gate semantics and tamper honesty |
| `docs/stress-failure-modes.md` | Failure mechanisms |
| `reports/RESULTS.md` | Scoreboard hub |
| `reports/opensource_attack_eval.md` | Broad OTRF |
| `reports/opensource_aggressive_eval.md` | APT29/APT3/… |
| `reports/live_opensource_stress.md` | Laptop live replay |
| `reports/claim_gates.json` | Current gate bitfield |
| `reports/non_author_fusion.json` | Breaktest micro metrics |

## Appendix C — Drafting rubrics (self-check before submit)

- [ ] Abstract never upgrades past standing claim
- [ ] Every numeric table has N, units, and authorship note
- [ ] F1 columns are micro-consistent (or explicitly diagnostic macro)
- [ ] External OTRF appears before author fleets
- [ ] Every “BROKE/PARTIAL” has a mechanism sentence
- [ ] `claim_allowed=false` stated; blocked sentence shown
- [ ] Limitations list deferred second-host and benign PASS
- [ ] Live stress wording says **replay**, not live malware execution
- [ ] Reproduce commands run from a clean clone
