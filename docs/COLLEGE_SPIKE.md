# College application spike — full portfolio reference

Private/working reference. Public Corvex claims belong in `reports/RESULTS.md`.

## Spike sentence (say once)

> I build pre-registered, adversarially-honest evaluation into everything I ship — I try to make it structurally impossible to fool myself about whether something works.

**One-paragraph expansion:** Across research, tooling, finance, law, and health, the recurring artifact isn’t the product demo — it’s the check on the product. A sealed test set hashed before the evaluation code exists. A negative result reported instead of buried. A disclosure that my own model underestimates risk for people who look like me. The common thread isn’t “AI.” It’s refusing to let my systems mark their own homework.

**Discipline:** Open with the spike once. Go deep on **Anima** (and **Corvex** as co-proof of rigor). Treat Orqis / GeoQuant / Health AI as short confirmations — not five rehearsals of the same sentence.

---

## Tier 1 — Flagship

### Anima (primary essay anchor)

| | |
|--|--|
| **Role** | Full essay depth; physics → interpretability pivot; most personally connected |
| **Spike fit** | Benchmarks / interpretability checks that can falsify a claim |
| **Essay job** | Carry the Common App narrative |
| **Interview line** | Lead with the scientific/interpretability problem and what would count as failure |

Keep unchanged as primary. Corvex does not replace Anima in the essay — it can *confirm* the honesty method with cleaner eval plumbing.

### Corvex (co-flagship — Stage A landed)

| | |
|--|--|
| **Role** | Structurally cleanest proof of the spike (eval machinery) |
| **Status** | Stage A held-out **PASS** with checkable artifacts |
| **Lead with** | Numbers, not “white blood cell swarm” |

**One-line:** Built a multi-host campaign correlator with held-out packs sealed/hash-published before evaluation, pre-registered pass bars, anti-sandbag baseline floor, and an explicit ban on metaphor-as-metric — held-out **PASS** (correlator F1 1.0 vs per-host B1 0.0; tied competitive SIEM B2; care vs commercial hunt tools marked **unproven**; live contain still locked).

**Disclose if pressed:** Solo key = tamper-evident not peek-proof; packs are author-designed synthetic grammar; detector-only also hit F1 1.0 on held-out (train showed more separation); OSS retention not met.

---

## Tier 2 — Secondary confirmations

### Orqis

| | |
|--|--|
| **Role** | Traction / external validation (different proof than honesty spike) |
| **Line** | Co-founded an SDK that detects runaway agent-pipeline failures in real time and ships a verified fix as a reviewable PR — on track for YC seed funding (decision by end of August). |

Do not force Orqis into the honesty-spike sentence. It’s the “other people and process validate this” card.

### GeoQuant

| | |
|--|--|
| **Role** | Most timestamped negative-result proof |
| **Line** | Built a cost-aware walk-forward trading pipeline; reported a negative Sharpe (−0.47) from the first real run rather than tuning until it looked good. |

Keep. Do not cut.

### Health AI — Drift (recommended name)

| | |
|--|--|
| **Role** | Self-critical fairness disclosure (rare builder artifact) |
| **Line** | Built a health-risk tool with hard data-gating (refuses a score without enough input) and publicly documented that it likely underestimates cardiovascular/diabetes risk for South Asian users by ~1.5–2× because of NHANES underrepresentation — the population I belong to. |

Elevate as secondary. Strongest “I audited myself” confirmation of the spike.

---

## Tier 3 — Cut from named case files

### VidhiSethu / VidhiSetu

**Cut as headline.** Not hosted; 0 real users. “Closed beta / pilot users” will not survive a direct question.  
Optional activities-list only, flat and honest, no beta/user claims.

### trade_bot

**Cut.** No confirmed live usage. Same exposure risk as VidhiSethu.

---

## Background / credentials (not projects)

| Item | How to state |
|------|----------------|
| **Football** | All-India CBSE tournament, **2nd place**, Goa Globe — strongest non-technical external verify |
| **Skating** | State level, real club; state timeframe honestly (earlier years) |
| **NGO web builds** | “Built and deployed websites for [N] NGOs, enabling online [signups/donations/…]” — outcome-based |
| **Athera** | Founder; 3–4 paying clients; ₹2+ lakh profit; clients via personal cold outreach — separate business proof; don’t stretch into the honesty spike |
| **MUN (1 yr), 50+ hrs service** | Minor lines only |

---

## Suggested essay / interview shape

1. Spike sentence (once).  
2. Deep dive: Anima (problem → method → what failure looks like).  
3. One rigor co-proof: Corvex numbers + disclosures.  
4. Optional 15–20s confirmations: GeoQuant negative Sharpe; Drift self-audit; Orqis if asked about building with others/funding.  
5. Stop. Do not walk five projects proving the same sentence.

---

## Corvex artifact map (for you)

| Claim | Artifact |
|-------|----------|
| Pre-registered bars | `Corvex/eval/__init__.py` PASS_BARS + sealed scorer rules |
| Held-out sealed before eval | Generated locally under `heldout/` — **not** in git |
| Reported PASS | `reports/RESULTS.md` (summary); full JSON stays local |
| Metaphor banned from metrics | README + RESULTS |
| Contain not fake-unlocked | `reports/security_l1_checklist.json` all false; dry-run only |
| Continuous honesty trail | `docs/DAILY_COMMIT_PLAN.md`, `scripts/daily_audit.ps1` |
