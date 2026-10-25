# FIRST Bangalore 2027 — CFS paste fields

Source brief: [`Corvex_FIRST_Bangalore_2027_Brief.pdf`](Corvex_FIRST_Bangalore_2027_Brief.pdf)  
Rebuild: `python scripts/build_first_blr_pdf.py`  
CFS: https://www.first.org/events/colloquia/bangalore2027/cfs  
Deadline: **21 Nov 2026** (UTC+14:00)

## Format

Presentation (30 minutes + 5 minutes Q&A) · English · TLP:CLEAR

## Title

When F1=1.00 Still Lies: Claim Gates, External Purple-Team Corpora, and Honest Multi-Host Campaign Correlation

## Topic buckets

- Primary: Detection, Threat Intelligence and Adversary Analysis
- Secondary: Defending the Defenders; Human-Machine Incident Response

## Abstract (~145 words)

Security tools often look excellent on author-written lab packs, then soft-upgrade into "works in production" language. This talk is a practitioner experience report on stopping that drift. Using Corvex — an open-source multi-host campaign correlator that fuses weak per-host detectors via HMAC-signed events — we show a five-part discipline: seal held-out packs, ablate fusion against detector-only baselines, score harder public-TTP breaktests, lead independence claims with externally authored OTRF / MITRE ATT&CK Evals captures (APT29, Caldera APT3, Golden SAML), and lock field language behind a machine-checked claim gate that stays false without live second-host evidence. We corrected an inconsistent F1 bug, report sealed correlator micro-F1 1.00 dropping to breaktest ~0.65, show 4 fusion holds on hardest compounds after named fixes, and stream 56 OTRF captures into a live correlator with 0 miss (replay, not malware execution). Attendees leave with a reusable claim checklist — not a product pitch.

## Detailed outline (~420 words)

**0-3 min — Hook.** Show a sealed lab table with correlator F1=1.00 next to a drafted README sentence that soft-claims "multi-host attacks in the enterprise." Run the claim gate: blocked. Problem statement: scores are not sentences.

**3-8 min — System sketch (short).** Corvex as a research correlator: signed EventEnvelopes, weak detectors (lateral auth, micro-exfil, recon), optional cross-host fusion, quarantine dry-run only. Explicit non-goals: not EDR replacement, not LLM detection, not enterprise-validated.

**8-14 min — Protocol.** Walk five controls: (1) Fernet-sealed held-out packs; (2) detector-only ablation; (3) breaktest manifests with public TTP IDs; (4) external OTRF / ATT&CK Evals as the independence headline; (5) claim_allowed predicates on disk. Emphasize authorship tiers.

**14-22 min — Results that survive peer pressure.** Sealed N=6: correlator micro-F1 1.00 vs detector-only 0.625. Breaktest: ~0.65 vs ~0.20. Broad OTRF atomics: 34/36 no host-coverage lift. Aggressive compounds: 4 FUSION_HELD, 10 single-host, 0 fleet-wide quarantine spray. Live laptop: 56 OTRF replays, 0 miss — clarify replay vs live malware.

**22-27 min — Named failures + takeaways.** Ambient metadata micro-exfil poison, recon mega-camps, fleet-wide dry-run quarantine, APT29 adapter skip rates, egress bury. Hand a one-page claim checklist.

**27-30 min — Close.** Re-state locked claim. Point to open repo. Invite hard questions on second physical host and benign baseline.

**Q&A (5 min).** Metric honesty, quarantine cut-points, porting the protocol without Corvex.

## Speaker note (problem / benefit / qualification)

**Problem:** Detection engineering and research tooling overclaim from small synthetic wins; IR teams inherit inflated confidence.

**Benefit:** CSIRT/SOC detection engineers, purple teams, and student builders get a portable seal/ablate/external/gate checklist and concrete failure patterns.

**Qualification:** Built and open-sourced Corvex end-to-end; ran APT29/APT3 external batteries and live replay stress; revised after CSET-style claim-production critique (inconsistent F1, author-only tests, BROKE-without-why, lab-to-field drift).

## Standing claim (do not upgrade in CFS)

Holds on synthetic ATT&CK-shaped fleets and externally authored lab purple-team captures. Not validated on real enterprise telemetry or pure-benign baselines. `claim_allowed=false` until live second-host evidence exists. Not a product pitch.
