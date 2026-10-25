# Venue map — Corvex final paper (journal / workshop track)

Canonical PDF: [`Corvex_Claim_Gates_FINAL.pdf`](Corvex_Claim_Gates_FINAL.pdf)  
Sources: [`../../paper/corvex_paper.tex`](../../paper/corvex_paper.tex), [`../../paper/refs.bib`](../../paper/refs.bib)  
Markdown mirror: [`../../CORVEX_PAPER_FINAL.md`](../../CORVEX_PAPER_FINAL.md)  
Rebuild: `python scripts/build_journal_paper_pdf.py`

Standing claim stays locked (`claim_allowed=false`). Do not upgrade camera-ready past it.

## Primary fits

| Venue class | Why Corvex fits | Form |
|-------------|-----------------|------|
| **CSET-style** (Cyber Security Experimentation and Test) | Metrics consistency, dataset authorship, reproducibility, claim discipline | Experience / long paper (IEEE, ≤8 pp excl. refs) |
| **ACSAC / NDSS / IEEE S&P workshops** on evaluation, datasets, measurement | Same meta-eval angle | Workshop paper |
| **IEEE Security & Privacy Magazine** (departments / experience) | Practitioner-readable protocol + honest limits | Magazine article (adapt length) |
| **Digital Threats: Research and Practice (DTRAP)** | Tools & methodologies / experience | Journal experience paper |

## Practitioner track (separate artifact)

| Venue | Artifact |
|-------|----------|
| **FIRST TC Bangalore 2027** | [`../first-blr-2027/`](../first-blr-2027/) talk brief + CFS paste — not this IEEE PDF |

## Poor fits (do not force)

| Venue | Why |
|-------|-----|
| SaTML / NeurIPS / ICML security ML tracks | Not a novel learning algorithm; prior packaging misfit |
| Full IEEE S&P / USENIX Security research track as SOTA IDS | Overclaims vs standing claim; wrong bar |

## Submission hygiene

1. Anonymize author block if double-blind (`\IEEEauthorblockN{Anonymous}`).
2. Keep abstract ≤ standing claim.
3. Lead with OTRF tables before author fleets.
4. Attach or link artifact URL after acceptance if blind.
5. TLP:CLEAR for public purple-team datasets; no live malware claims.
