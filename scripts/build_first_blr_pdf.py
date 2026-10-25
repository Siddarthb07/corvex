#!/usr/bin/env python3
"""Build FIRST Bangalore TC supporting brief PDF (practitioner-readable)."""

from __future__ import annotations

from pathlib import Path

from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER, TA_JUSTIFY, TA_LEFT
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.platypus import (
    KeepTogether,
    ListFlowable,
    ListItem,
    PageBreak,
    Paragraph,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
    HRFlowable,
)

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "docs" / "venues" / "first-blr-2027" / "Corvex_FIRST_Bangalore_2027_Brief.pdf"
OUT_COPY = ROOT / "output" / "pdf" / "Corvex_FIRST_Bangalore_2027_Brief.pdf"

INK = colors.HexColor("#1a1f2e")
MUTED = colors.HexColor("#4a5568")
ACCENT = colors.HexColor("#0d7377")
RULE = colors.HexColor("#c5cdd8")
SOFT = colors.HexColor("#f4f7f8")
WARN_BG = colors.HexColor("#fff8e8")
WARN_BORDER = colors.HexColor("#d4a017")
OK_BG = colors.HexColor("#eef8f4")
ROW_ALT = colors.HexColor("#f7fafb")


def styles():
    base = getSampleStyleSheet()
    s = {
        "cover_kicker": ParagraphStyle(
            "cover_kicker",
            parent=base["Normal"],
            fontName="Helvetica",
            fontSize=9,
            textColor=ACCENT,
            tracking=1.2,
            spaceAfter=8,
            alignment=TA_CENTER,
        ),
        "cover_title": ParagraphStyle(
            "cover_title",
            parent=base["Normal"],
            fontName="Helvetica-Bold",
            fontSize=20,
            leading=26,
            textColor=INK,
            alignment=TA_CENTER,
            spaceAfter=10,
        ),
        "cover_sub": ParagraphStyle(
            "cover_sub",
            parent=base["Normal"],
            fontName="Helvetica",
            fontSize=11,
            leading=16,
            textColor=MUTED,
            alignment=TA_CENTER,
            spaceAfter=6,
        ),
        "h1": ParagraphStyle(
            "h1",
            parent=base["Heading1"],
            fontName="Helvetica-Bold",
            fontSize=14,
            leading=18,
            textColor=INK,
            spaceBefore=14,
            spaceAfter=8,
        ),
        "h2": ParagraphStyle(
            "h2",
            parent=base["Heading2"],
            fontName="Helvetica-Bold",
            fontSize=11.5,
            leading=15,
            textColor=ACCENT,
            spaceBefore=11,
            spaceAfter=5,
        ),
        "body": ParagraphStyle(
            "body",
            parent=base["Normal"],
            fontName="Helvetica",
            fontSize=9.5,
            leading=13.5,
            textColor=INK,
            alignment=TA_JUSTIFY,
            spaceAfter=7,
        ),
        "body_left": ParagraphStyle(
            "body_left",
            parent=base["Normal"],
            fontName="Helvetica",
            fontSize=9.5,
            leading=13.5,
            textColor=INK,
            alignment=TA_LEFT,
            spaceAfter=6,
        ),
        "bullet": ParagraphStyle(
            "bullet",
            parent=base["Normal"],
            fontName="Helvetica",
            fontSize=9.5,
            leading=13,
            textColor=INK,
            leftIndent=2,
            spaceAfter=3,
        ),
        "meta": ParagraphStyle(
            "meta",
            parent=base["Normal"],
            fontName="Helvetica",
            fontSize=8.5,
            leading=11.5,
            textColor=MUTED,
            alignment=TA_CENTER,
            spaceAfter=3,
        ),
        "caption": ParagraphStyle(
            "caption",
            parent=base["Normal"],
            fontName="Helvetica-Oblique",
            fontSize=8,
            leading=10.5,
            textColor=MUTED,
            spaceBefore=2,
            spaceAfter=8,
        ),
        "callout": ParagraphStyle(
            "callout",
            parent=base["Normal"],
            fontName="Helvetica",
            fontSize=9,
            leading=12.5,
            textColor=INK,
            alignment=TA_LEFT,
        ),
        "callout_title": ParagraphStyle(
            "callout_title",
            parent=base["Normal"],
            fontName="Helvetica-Bold",
            fontSize=9,
            leading=12,
            textColor=INK,
            spaceAfter=3,
        ),
        "footer": ParagraphStyle(
            "footer",
            parent=base["Normal"],
            fontName="Helvetica",
            fontSize=7.5,
            textColor=MUTED,
        ),
        "toc": ParagraphStyle(
            "toc",
            parent=base["Normal"],
            fontName="Helvetica",
            fontSize=9.5,
            leading=14,
            textColor=INK,
            spaceAfter=3,
        ),
        "table_cell": ParagraphStyle(
            "table_cell",
            parent=base["Normal"],
            fontName="Helvetica",
            fontSize=8,
            leading=10.5,
            textColor=INK,
        ),
        "table_head": ParagraphStyle(
            "table_head",
            parent=base["Normal"],
            fontName="Helvetica-Bold",
            fontSize=8,
            leading=10.5,
            textColor=colors.white,
        ),
    }
    return s


def p(text: str, style) -> Paragraph:
    return Paragraph(text, style)


def hr():
    return HRFlowable(width="100%", thickness=0.6, color=RULE, spaceBefore=4, spaceAfter=8)


def callout(title: str, body: str, s, bg=WARN_BG, border=WARN_BORDER):
    inner = [
        p(f"<b>{title}</b>", s["callout_title"]),
        p(body, s["callout"]),
    ]
    t = Table([[inner]], colWidths=[160 * mm])
    t.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, -1), bg),
                ("BOX", (0, 0), (-1, -1), 1, border),
                ("LEFTPADDING", (0, 0), (-1, -1), 10),
                ("RIGHTPADDING", (0, 0), (-1, -1), 10),
                ("TOPPADDING", (0, 0), (-1, -1), 8),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
            ]
        )
    )
    return t


def simple_table(headers, rows, s, col_widths=None):
    head = [p(h, s["table_head"]) for h in headers]
    data = [head]
    for row in rows:
        data.append([p(str(c), s["table_cell"]) for c in row])
    t = Table(data, colWidths=col_widths, repeatRows=1)
    style_cmds = [
        ("BACKGROUND", (0, 0), (-1, 0), ACCENT),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("GRID", (0, 0), (-1, -1), 0.4, RULE),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("LEFTPADDING", (0, 0), (-1, -1), 5),
        ("RIGHTPADDING", (0, 0), (-1, -1), 5),
        ("TOPPADDING", (0, 0), (-1, -1), 4),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
    ]
    for i in range(1, len(data)):
        if i % 2 == 0:
            style_cmds.append(("BACKGROUND", (0, i), (-1, i), ROW_ALT))
    t.setStyle(TableStyle(style_cmds))
    return t


def bullets(items, s):
    return ListFlowable(
        [ListItem(p(i, s["bullet"]), leftIndent=8, bulletColor=ACCENT) for i in items],
        bulletType="bullet",
        start="-",
        leftIndent=12,
        spaceBefore=2,
        spaceAfter=6,
    )


def add_page_number(canvas, doc):
    canvas.saveState()
    page = canvas.getPageNumber()
    canvas.setFont("Helvetica", 7.5)
    canvas.setFillColor(MUTED)
    canvas.drawString(18 * mm, 10 * mm, "Corvex · FIRST Bangalore TC supporting brief · TLP:CLEAR")
    canvas.drawRightString(192 * mm, 10 * mm, f"{page}")
    canvas.setStrokeColor(RULE)
    canvas.setLineWidth(0.4)
    canvas.line(18 * mm, 13 * mm, 192 * mm, 13 * mm)
    canvas.restoreState()


def build():
    s = styles()
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT_COPY.parent.mkdir(parents=True, exist_ok=True)

    doc = SimpleDocTemplate(
        str(OUT),
        pagesize=A4,
        leftMargin=18 * mm,
        rightMargin=18 * mm,
        topMargin=16 * mm,
        bottomMargin=18 * mm,
        title="Claim Discipline for Multi-Host Campaign Correlation - FIRST Bangalore 2027",
        author="Siddarth Boggarapu",
        subject="FIRST Technical Colloquium Bangalore supporting brief",
    )

    story = []

    # ----- Cover -----
    story.append(Spacer(1, 18 * mm))
    story.append(p("FIRST TECHNICAL COLLOQUIUM · BANGALORE 2027", s["cover_kicker"]))
    story.append(p("Supporting brief for a 30-minute talk proposal", s["cover_sub"]))
    story.append(Spacer(1, 4 * mm))
    story.append(
        p(
            "Claim Discipline for Multi-Host Campaign Correlation:<br/>"
            "Sealed Packs, External Corpora, Named Failures, and Machine-Checked Field Language",
            s["cover_title"],
        )
    )
    story.append(Spacer(1, 3 * mm))
    story.append(hr())
    story.append(p("<b>Speaker:</b> Siddarth Boggarapu · Bangalore, India", s["meta"]))
    story.append(p("siddarthb078@gmail.com · github.com/Siddarthb07/corvex", s["meta"]))
    story.append(
        p(
            "Format: Presentation (30 min + 5 min Q&amp;A) · Language: English · TLP:CLEAR · Open tooling",
            s["meta"],
        )
    )
    story.append(
        p(
            "CFS window: opens 5 Oct 2026 · deadline 21 Nov 2026 · notifications week of 8 Dec 2026",
            s["meta"],
        )
    )
    story.append(Spacer(1, 6 * mm))
    story.append(
        callout(
            "Standing claim (locked)",
            "Corvex holds up on synthetic ATT&amp;CK-shaped fleets and externally authored "
            "lab purple-team captures. It is <b>not</b> validated on real enterprise telemetry "
            "or pure-benign home-lab baselines. Machine gate <b>claim_allowed=false</b> until "
            "live second-host evidence exists. This brief does not sell a product.",
            s,
            bg=WARN_BG,
            border=WARN_BORDER,
        )
    )
    story.append(Spacer(1, 8 * mm))
    story.append(p("<b>How to use this PDF</b>", s["h2"]))
    story.append(
        p(
            "FIRST does not require a formal paper. Section 1 is the CFS-ready abstract and "
            "detailed outline you can paste into the submission form. The rest is optional "
            "supporting material for program-committee review and for building the live talk: "
            "readable numbers, failure mechanisms, and takeaways an IR/SOC team can reuse "
            "without adopting Corvex.",
            s["body"],
        )
    )
    story.append(p("<b>Contents</b>", s["h2"]))
    for line in [
        "1. CFS packet - title, abstract, outline, speaker note, topic fit",
        "2. The problem in plain language - lab scores that become field sentences",
        "3. What Corvex is (and is not)",
        "4. Evaluation protocol - seal, ablate, breaktest, external OTRF, claim gate",
        "5. Results - sealed, breaktest, OTRF aggressive, live laptop replay",
        "6. What broke and why - mechanisms, not bare labels",
        "7. What IR teams can steal tomorrow",
        "8. Limits, venue map, reproduce",
        "Appendix - why an earlier academic packaging was rejected",
    ]:
        story.append(p(line, s["toc"]))

    story.append(PageBreak())

    # ----- 1. CFS packet -----
    story.append(p("1. CFS packet (paste-ready)", s["h1"]))
    story.append(hr())

    story.append(p("Proposed talk title", s["h2"]))
    story.append(
        p(
            "When F1=1.00 Still Lies: Claim Gates, External Purple-Team Corpora, and "
            "Honest Multi-Host Campaign Correlation",
            s["body_left"],
        )
    )

    story.append(p("Suggested FIRST topic buckets", s["h2"]))
    story.append(
        bullets(
            [
                "Primary: <b>Detection, Threat Intelligence and Adversary Analysis</b> "
                "(campaign correlation, measurable detection lift, ATT&amp;CK-shaped fleets).",
                "Secondary: <b>Defending the Defenders</b> "
                "(how detection tooling overclaims; claim gates as anti-self-deception).",
                "Secondary: <b>Human-Machine Incident Response</b> "
                "(automation that refuses field language until evidence exists).",
            ],
            s,
        )
    )

    story.append(p("Abstract (approx. 145 words - under 250 max)", s["h2"]))
    story.append(
        p(
            "Security tools often look excellent on author-written lab packs, then soft-upgrade "
            "into \"works in production\" language. This talk is a practitioner experience report "
            "on stopping that drift. Using Corvex - an open-source multi-host campaign correlator "
            "that fuses weak per-host detectors via HMAC-signed events - we show a five-part "
            "discipline: seal held-out packs, ablate fusion against detector-only baselines, "
            "score harder public-TTP breaktests, lead independence claims with externally authored "
            "OTRF / MITRE ATT&amp;CK Evals captures (APT29, Caldera APT3, Golden SAML), and lock "
            "field language behind a machine-checked claim gate that stays false without live "
            "second-host evidence. We corrected an inconsistent F1 bug, report sealed correlator "
            "micro-F1 1.00 dropping to breaktest ~0.65, show 4 fusion holds on hardest compounds "
            "after named fixes, and stream 56 OTRF captures into a live correlator with 0 miss "
            "(replay, not malware execution). Attendees leave with a reusable claim checklist - "
            "not a product pitch.",
            s["body"],
        )
    )

    story.append(p("Detailed outline (approx. 420 words)", s["h2"]))
    story.append(
        p(
            "<b>0-3 min - Hook.</b> Show a sealed lab table with correlator F1=1.00 next to a "
            "drafted README sentence that soft-claims \"multi-host attacks in the enterprise.\" "
            "Run the claim gate: blocked. Problem statement: scores are not sentences.",
            s["body"],
        )
    )
    story.append(
        p(
            "<b>3-8 min - System sketch (short).</b> Corvex as a research correlator: signed "
            "EventEnvelopes, weak detectors (lateral auth, micro-exfil, recon), optional cross-host "
            "fusion, quarantine dry-run only. Explicit non-goals: not EDR replacement, not LLM "
            "detection, not enterprise-validated. Audience gets enough architecture to trust later "
            "tables without drowning in code.",
            s["body"],
        )
    )
    story.append(
        p(
            "<b>8-14 min - Protocol.</b> Walk five controls: (1) Fernet-sealed held-out packs; "
            "(2) detector-only ablation; (3) breaktest manifests with public TTP IDs; "
            "(4) external OTRF / ATT&amp;CK Evals as the independence headline; "
            "(5) claim_allowed predicates on disk. Emphasize authorship tiers - sealed and "
            "breaktest are still author-assembled; OTRF is external origin but still lab purple-team.",
            s["body"],
        )
    )
    story.append(
        p(
            "<b>14-22 min - Results that survive peer pressure.</b> Sealed N=6 attack / N=6 benign: "
            "correlator micro-F1 1.00 vs detector-only 0.625. Breaktest: ~0.65 vs ~0.20 (lift ~+0.44). "
            "Broad OTRF atomics: campaigns form, but 34/36 show no host-coverage lift - say so. "
            "Aggressive compounds: 4 FUSION_HELD (APT29 day1/day2, Caldera APT3, Golden SAML), "
            "10 single-host (fusion not testable), 0 fleet-wide quarantine spray after fixes. "
            "Live laptop stress: 56 OTRF replays into a running correlator - 20 caught, 19 already "
            "covered, 17 single-host batches, 0 miss. Clarify replay vs live malware.",
            s["body"],
        )
    )
    story.append(
        p(
            "<b>22-27 min - Named failures + takeaways.</b> Mechanisms: ambient cloud-metadata "
            "micro-exfil poison, recon host-union mega-camps, fleet-wide dry-run quarantine, "
            "adapter allowlist skip rates on APT29, high-volume egress bury still broken on some "
            "author cells. Hand the audience a one-page claim checklist they can apply to any "
            "internal detection project.",
            s["body"],
        )
    )
    story.append(
        p(
            "<b>27-30 min - Close.</b> Re-state locked claim. Point to open repo and reproduce "
            "commands. Invite hard questions about what is still missing (second physical host, "
            "benign baseline PASS/FAIL).",
            s["body"],
        )
    )
    story.append(
        KeepTogether(
            [
                p(
                    "<b>Q&amp;A (5 min).</b> Prefer questions on metric honesty, quarantine cut-points, "
                    "and how to port the protocol without Corvex.",
                    s["body"],
                ),
                p("What problem / who benefits / why this speaker", s["h2"]),
                bullets(
                    [
                        "<b>Problem:</b> Detection engineering and research tooling overclaim from small "
                        "synthetic wins; IR teams inherit inflated confidence.",
                        "<b>Benefit:</b> CSIRT/SOC detection engineers, purple teams, and student builders "
                        "get a portable seal/ablate/external/gate checklist and concrete failure patterns.",
                        "<b>Qualification:</b> Built and open-sourced Corvex end-to-end (correlator, "
                        "Windows/macOS observe-only sensors, sealed eval, OTRF adapters, claim gates); "
                        "ran APT29/APT3 external batteries and live replay stress on a Windows laptop; "
                        "revised after CSET-style claim-production critique (inconsistent F1, author-only "
                        "tests, BROKE-without-why, lab-to-field drift).",
                    ],
                    s,
                ),
            ]
        )
    )

    # ----- 2. Problem -----
    # Continues on same page as CFS speaker note when space allows (avoids sparse page).
    story.append(p("2. The problem in plain language", s["h1"]))
    story.append(hr())
    story.append(
        p(
            "Incident responders and detection engineers live under two pressures that fight each "
            "other. On one side, leadership wants confidence: \"does this catch multi-host "
            "campaigns?\" On the other side, honest telemetry is messy, sparse, and rarely "
            "labeled. Lab packs fill the gap. That is fine - until the lab number becomes the "
            "sentence on a README, a slide, or a vendor brief.",
            s["body"],
        )
    )
    story.append(
        p(
            "Call the failure mode <b>lab-to-field language drift</b>. A correlator scores "
            "perfectly on six sealed synthetic packs. Someone writes \"works on multi-host "
            "attacks.\" A reader hears \"enterprise-ready.\" Nothing in the math forced the lie; "
            "the packaging did.",
            s["body"],
        )
    )
    story.append(
        p(
            "FIRST audiences already know purple-team captures are not production estates. The "
            "contribution here is making the stop between score and sentence <b>executable</b>: "
            "seal answers, ablate fusion, prefer external corpora, name failure mechanisms, and "
            "keep a machine gate that refuses field language until second-host evidence exists.",
            s["body"],
        )
    )
    story.append(
        callout(
            "Audience takeaway (early)",
            "Treat every detection F1 as a claim about a specific authorship tier and sample "
            "size. If the abstract upgrades the tier, the abstract is wrong - even if the F1 is "
            "correct.",
            s,
            bg=OK_BG,
            border=ACCENT,
        )
    )

    # ----- 3. What Corvex is -----
    story.append(p("3. What Corvex is (and is not)", s["h1"]))
    story.append(hr())
    story.append(
        p(
            "Corvex is an open-source research correlator. Hosts emit HMAC-signed "
            "<b>EventEnvelope</b> records. Per-host detectors raise weak signals "
            "(lateral authentication, micro-exfiltration, recon fanout, optional DNS beacons). "
            "A correlator optionally merges those signals across hosts using time windows, hop "
            "graphs, ambient-destination poison, and anti-jumpbox rules. Quarantine proposals "
            "exist only as <b>dry_run / lab_flag / blocked</b>. Live OS containment defaults off "
            "(<font face='Courier'>CORVEX_CONTAIN=0</font>). Windows and macOS Stage B sensors "
            "are observe-only. ATT&amp;CK tags are coarse stage hypotheses, not high-confidence "
            "attributions.",
            s["body"],
        )
    )
    story.append(p("Terminology used in the rest of this brief", s["h2"]))
    story.append(
        simple_table(
            ["Term", "Meaning"],
            [
                ["Correlator", "Fusion path - cross-key / cross-host merge"],
                ["Detector-only", "Same alerts, grouped by detector key without that merge"],
                ["Breaktest", "Public-TTP-shaped manifests (author-assembled)"],
                ["OTRF corpus", "Externally authored Mordor / Security-Datasets / ATT&amp;CK Evals"],
                ["Claim gate", "On-disk predicates evaluated by <font face='Courier'>corvex claim-gates</font>"],
            ],
            s,
            col_widths=[40 * mm, 120 * mm],
        )
    )
    story.append(
        p(
            "Table 1. Shared vocabulary. Use these terms when asking questions in the talk.",
            s["caption"],
        )
    )
    story.append(
        p(
            "<b>Not claimed:</b> commercial EDR/XDR parity; enterprise telemetry validation; "
            "live malware catch on a laptop; automatic containment that is safe to enable.",
            s["body"],
        )
    )

    # ----- 4. Protocol -----
    story.append(p("4. Evaluation protocol", s["h1"]))
    story.append(hr())
    story.append(
        p(
            "Five parts. None of them is theoretically novel alone. Together they make claim "
            "discipline reproducible from a clean clone.",
            s["body"],
        )
    )
    story.append(p("4.1 Seal held-out packs", s["h2"]))
    story.append(
        p(
            "Generators write JSONL packs. Packs and scorer rules are Fernet-sealed under an "
            "external key before correlator retunes. Sealing reduces accidental train/test "
            "snooping. It does <b>not</b> create outsider authorship. Current sealed size: "
            "attack N=6 (lateral x2, exfil x2, fusion_chain, recon_lateral) and benign N=6. "
            "Still synthetic; still modest.",
            s["body"],
        )
    )
    story.append(p("4.2 Detector-only ablation", s["h2"]))
    story.append(
        p(
            "Score the same events with fusion disabled. Fusion lift is correlator micro-F1 minus "
            "detector-only micro-F1 when ground truth exists. On OTRF packs without Corvex-authored "
            "GT, use observational verdicts (host coverage, consolidation, quarantine spray) "
            "instead of inventing F1.",
            s["body"],
        )
    )
    story.append(p("4.3 Breaktest (harder, still author-assembled)", s["h2"]))
    story.append(
        p(
            "Manifests under <font face='Courier'>labs/breaktest/</font> cite public Atomic / "
            "ATT&amp;CK technique IDs. Results are published even when worse than sealed. "
            "Necessary for a non-author fusion gate; still not stranger enterprise traffic.",
            s["body"],
        )
    )
    story.append(p("4.4 External open-source captures (primary independence)", s["h2"]))
    story.append(
        p(
            "OTRF/Security-Datasets and MITRE ATT&amp;CK Evals Caldera/manual captures are "
            "fetched, sanitized (CommandLine/ScriptBlockText stripped for Defender), adapted, "
            "signed under lab enrollment, and scored observationally. Catalog size as of this "
            "brief: 76 entries. This is the independence headline - not Fleet20.",
            s["body"],
        )
    )
    story.append(p("4.5 Claim gates", s["h2"]))
    story.append(
        p(
            "<font face='Courier'>claim_allowed</font> requires non-author fusion lift, human "
            "Ed25519 stranger attestation, sealed benign FCR with minimum N, trust integrity "
            "probes, and <font face='Courier'>reports/live_second_host.json</font> from elevated "
            "wevtutil on a <b>second physical</b> Windows host. Lab unlock for sensors does not "
            "flip the claim bit. A drafted marketing sentence is demonstrated blocked today.",
            s["body"],
        )
    )
    story.append(
        callout(
            "Blocked sentence (demo)",
            "Drafted: \"Corvex works on real multi-host attacks in enterprise networks and is "
            "ready for production SOC use.\" Gate today: claim_allowed=false (live_second_host "
            "fail). Allowed sentence remains the standing claim. Reproduce: "
            "<font face='Courier'>python scripts/demo_blocked_claim.py</font>",
            s,
        )
    )

    # ----- 5. Results -----
    story.append(p("5. Results (numbers with authorship)", s["h1"]))
    story.append(hr())
    story.append(
        p(
            "Every table below names N and authorship. Micro-F1 means the harmonic mean of "
            "pooled precision and recall from TP/FP/FN - not the mean of per-pack F1s. That "
            "bug produced impossible triples (e.g. P~0.33, R~0.67, F1~0.67) in an earlier draft "
            "and is fixed.",
            s["body"],
        )
    )

    story.append(p("5.1 Sealed held-out (synthetic, author-generated, sealed)", s["h2"]))
    story.append(
        simple_table(
            ["Metric", "Correlator", "Detector-only", "B1 single-host"],
            [
                ["Precision (micro)", "1.00", "0.50", "0.00"],
                ["Recall (micro)", "1.00", "0.83", "0.00"],
                ["F1 (micro)", "<b>1.00</b>", "<b>0.625</b>", "0.00"],
                ["Benign FCR (N=6)", "0.00", " - ", " - "],
            ],
            s,
            col_widths=[45 * mm, 35 * mm, 40 * mm, 40 * mm],
        )
    )
    story.append(
        p(
            "Table 2. Perfect correlator F1 on N=6 is necessary but not sufficient. Fusion still "
            "matters (lift +0.375 vs detector-only). Absolute score remains a small synthetic upper bound.",
            s["caption"],
        )
    )

    story.append(p("5.2 Breaktest / public-TTP (author-assembled, harder)", s["h2"]))
    story.append(
        simple_table(
            ["Metric", "Correlator", "Detector-only"],
            [
                ["Precision (micro)", "~0.50", "~0.13"],
                ["Recall (micro)", "~0.91", "~0.45"],
                ["F1 (micro)", "<b>~0.65</b>", "<b>~0.20</b>"],
                ["F1 lift", "<b>~+0.44</b>", " - "],
            ],
            s,
            col_widths=[50 * mm, 55 * mm, 55 * mm],
        )
    )
    story.append(
        p(
            "Table 3. Same metric, harder packs. Drop from sealed 1.00 to ~0.65 is the point - "
            "publish it. Source: reports/non_author_fusion.json.",
            s["caption"],
        )
    )

    story.append(p("5.3 Broad OTRF atomics (external; observational)", s["h2"]))
    story.append(
        p(
            "On 36 Empire / Covenant / PurpleSharp / native + Caldera APT3 corpora, multi-host "
            "campaigns form readily - but the current scoreboard is honest about fusion:",
            s["body"],
        )
    )
    story.append(
        simple_table(
            ["Verdict / break", "Count", "Read"],
            [
                ["MULTI_HOST_NO_LIFT", "34", "Camps form; no host-coverage lift vs detector"],
                ["SINGLE_HOST", "2", "Fusion not testable"],
                ["Q_DRYRUN_ALL_HOSTS", "30", "Dry-run often marks every host (pre-fix pressure)"],
                ["ADAPTER_HEAVY_SKIP", "26", "Channel allowlist drops many raw events"],
            ],
            s,
            col_widths=[45 * mm, 22 * mm, 93 * mm],
        )
    )
    story.append(
        p(
            "Table 4. Do not lead independence claims with \"it worked on OTRF\" without this table. "
            "These failures drove the correlator/quarantine fixes measured next.",
            s["caption"],
        )
    )

    story.append(p("5.4 Aggressive compounds (APT29 / APT3 / Golden SAML / …)", s["h2"]))
    story.append(
        simple_table(
            ["Verdict", "N", "Meaning"],
            [
                [
                    "<b>FUSION_HELD</b>",
                    "4",
                    "APT29 day1, APT29 day2, Caldera APT3 day1, Golden SAML - consolidation + surgical Q",
                ],
                ["SINGLE_HOST", "10", "Empire APT3 compound, 7x LSASS, Log4Shell x2 - fusion not testable"],
                ["FUSION_NO_LIFT / Q-all-hosts", "0", "After ambient poison, hop peers, no recon-union, cut-point Q"],
            ],
            s,
            col_widths=[40 * mm, 15 * mm, 105 * mm],
        )
    )
    story.append(
        p(
            "Table 5. On saturated 4-5 host labs, host-coverage lift can be definitionally zero when "
            "both arms already cover all hosts. HELD here means consolidation + surgical quarantine, "
            "not \"more hosts than detector.\" APT29 adapter skip rates remain high (~0.86-0.94) - "
            "allowlist noise, still a remaining break type.",
            s["caption"],
        )
    )

    story.append(
        KeepTogether(
            [
                p("5.5 Live laptop stress (correlator running + OTRF replay)", s["h2"]),
                callout(
                    "Mode honesty",
                    "offline_lab_replay_into_live_correlator - captures are replayed into a live Corvex "
                    "process and dash on the author's Windows laptop. This is <b>not</b> executing "
                    "Empire/Covenant/malware on that laptop.",
                    s,
                    bg=OK_BG,
                    border=ACCENT,
                ),
                Spacer(1, 2 * mm),
                simple_table(
                    ["Catch label", "N of 56", "Meaning"],
                    [
                        ["CAUGHT", "20", "New multi-host bridge / camp growth"],
                        ["ALREADY_COVERED", "19", "Attack hosts already inside multi-host camps"],
                        ["SINGLE_HOST_BATCH", "17", "Capture has &lt;2 hosts - fusion not required"],
                        ["MISS", "<b>0</b>", "No multi-host capture failed to register"],
                    ],
                    s,
                    col_widths=[42 * mm, 25 * mm, 93 * mm],
                ),
                p(
                    "Table 6. Final live snapshot: 139,594 events; 55 multi-host campaigns spanning APT29, "
                    "Caldera, Mordor workstation, and Golden SAML hostnames. Dash left on :8765 during the run.",
                    s["caption"],
                ),
                p("5.6 Author fleets (secondary engineering probes only)", s["h2"]),
                p(
                    "Fleet20: 20 HELD (fragile_rate 0.05) - never report bare 20/20. Intensive multifactor: "
                    "HELD 23 (fragile 5), PARTIAL 2, BROKE 3 (exfil_bury). Useful for mechanism debugging. "
                    "<b>Not</b> the independence headline.",
                    s["body"],
                ),
            ]
        )
    )

    # ----- 6. Failures -----
    story.append(p("6. What broke and why", s["h1"]))
    story.append(hr())
    story.append(
        p(
            "Earlier packaging named BROKE without mechanism. Reviewers rightly rejected that. "
            "Table 7 is the condensed WHY list IR engineers can argue with.",
            s["body"],
        )
    )
    story.append(
        simple_table(
            ["Mode", "Mechanism", "Status"],
            [
                [
                    "DHCP hostname split-brain",
                    "Distinct host_id strings; multihost enrollment refuse",
                    "HELD (runtime aliases)",
                ],
                [
                    "Day-scale sleeper",
                    "1h resume fragmented long chains",
                    "HELD (separate sleeper resume)",
                ],
                [
                    "Shared svc-account glue",
                    "Time window glued disjoint hop islands",
                    "Unit HELD (hop partition)",
                ],
                [
                    "High-volume egress bury",
                    "CDN-like dst fanout swallows needle",
                    "Unit poison HELD; some intensive cells still BROKE",
                ],
                [
                    "DNS-only C2",
                    "No Sysmon EID 22 -> no DNS events",
                    "Honest channel_health.dns GAP",
                ],
                [
                    "Fleet-wide Q dry-run",
                    "Recon union + egress-on-all-hosts spray",
                    "Fixed: annotate-only recon; cut-point Q",
                ],
                [
                    "Ambient metadata micro-exfil",
                    "169.254.169.254 / Azure wire free multi-host coverage",
                    "Fixed: ambient poison in detectors + correlator",
                ],
                [
                    "APT29 adapter skip",
                    "Channel allowlist drops majority of raw events",
                    "Remaining - report skip_rate",
                ],
            ],
            s,
            col_widths=[42 * mm, 70 * mm, 48 * mm],
        )
    )
    story.append(
        p(
            "Table 7. Condensed from docs/stress-failure-modes.md. Prefer mechanism sentences "
            "in any talk slide that shows red cells.",
            s["caption"],
        )
    )

    # ----- 7. Steal -----
    story.append(p("7. What IR teams can steal tomorrow (without Corvex)", s["h1"]))
    story.append(hr())
    story.append(
        bullets(
            [
                "<b>Authorship column on every scoreboard.</b> Author-synthetic / author-breaktest / "
                "external-lab / stranger-enterprise - never mix tiers in one headline number.",
                "<b>Micro-F1 only for headline.</b> If P and R are pooled, F1 must be 2PR/(P+R) "
                "from those same pools. Macro mean of pack F1s is diagnostic only.",
                "<b>Always ablate fusion.</b> A correlator that cannot beat detector-only on the "
                "metric you care about has not earned a fusion claim.",
                "<b>External corpora before self-fleets.</b> Prefer OTRF / ATT&amp;CK Evals / "
                "Atomic before author purple scripts when arguing independence.",
                "<b>Name failure mechanisms.</b> \"BROKE\" is a status; \"CDN egress bury drowned "
                "the needle\" is engineering.",
                "<b>Claim gate as release criteria.</b> Even a shell script that greps for "
                "required evidence files beats social pressure to soft-upgrade the README.",
                "<b>Quarantine cut-points.</b> If dry-run proposes every host, your automation "
                "is not ready for human trust - fix the spray before enabling action.",
                "<b>Replay honesty.</b> Streaming sanitized captures into a detector is not the "
                "same as catching a live implant. Say which one you ran.",
            ],
            s,
        )
    )

    # ----- 8. Limits -----
    story.append(p("8. Limits (say these out loud)", s["h1"]))
    story.append(hr())
    story.append(
        bullets(
            [
                "Sealed attack N=6 is expanded but still modest.",
                "Sealed and breaktest packs remain primarily author-generated.",
                "OTRF packs are external in origin but still lab purple-team - not enterprise estates.",
                "Broad OTRF atomics still show MULTI_HOST_NO_LIFT at scale; aggressive HELD does not rewrite that table.",
                "No enterprise telemetry in this brief; second physical Windows host evidence deferred.",
                "Home-lab benign PASS/FAIL against pre-committed bars not yet a claim softener.",
                "Claim lock is auditable process, not DRM - a determined author can forge files.",
                "Live stress is replay, not live malware execution on the laptop.",
            ],
            s,
        )
    )

    story.append(p("Venue map (shortlist context)", s["h2"]))
    story.append(
        p(
            "<b>Primary for this PDF:</b> FIRST Technical Colloquium Bangalore 2027 - practitioner "
            "talk; abstract + outline required; formal paper optional; this brief is supporting "
            "material. <b>Secondary academic track:</b> CSET-style claim-production workshops "
            "(prior packaging rejected; revision checklist lives in-repo). SaTML-style ML venues "
            "were a poor fit for this correlator story and are not the focus here.",
            s["body"],
        )
    )

    story.append(p("Reproduce (clean clone)", s["h2"]))
    story.append(
        p(
            "<font face='Courier' size='8'>"
            "pip install -e \".[dev]\"<br/>"
            "corvex seal-day0 --force &amp;&amp; corvex eval --split heldout<br/>"
            "corvex score-non-author &amp;&amp; corvex claim-gates<br/>"
            "python scripts/fetch_opensource_corpora.py --aggressive<br/>"
            "python scripts/run_opensource_attack_eval.py --aggressive<br/>"
            "python scripts/fetch_opensource_corpora.py --live-stress<br/>"
            "python scripts/run_live_opensource_stress.py --dash<br/>"
            "python scripts/demo_blocked_claim.py"
            "</font>",
            s["body_left"],
        )
    )
    story.append(
        p(
            "Artifact: https://github.com/Siddarthb07/corvex · Full academic draft: "
            "docs/CORVEX_PAPER_DRAFT.md · Checklist: docs/CSET_REVISION_CHECKLIST.md",
            s["body"],
        )
    )

    story.append(PageBreak())

    # ----- Appendix -----
    story.append(p("Appendix - Why earlier academic packaging was rejected", s["h1"]))
    story.append(hr())
    story.append(
        p(
            "This appendix is for program-committee members who want the revision trail. "
            "It is not required reading for the live talk.",
            s["body"],
        )
    )
    story.append(
        simple_table(
            ["Critique", "Symptom in v1", "Response now"],
            [
                [
                    "Inconsistent F1",
                    "Macro mean of pack F1s with micro P/R",
                    "Micro F1 = 2PR/(P+R); macro diagnostic only",
                ],
                [
                    "N too small",
                    "Tiny sealed attack set",
                    "N=6 attack / N=6 benign; still labeled modest",
                ],
                [
                    "Author-written tests",
                    "Fleet20 as the headline",
                    "OTRF / ATT&amp;CK Evals lead; fleets secondary",
                ],
                [
                    "BROKE without why",
                    "Red cells, no mechanism",
                    "stress-failure-modes.md + Table 7",
                ],
                [
                    "Lab-to-field drift",
                    "F1=1.00 soft-upgraded",
                    "Standing claim + claim_allowed=false + blocked demo",
                ],
                [
                    "Missing ablation / OOD",
                    "Fusion asserted alone",
                    "Detector-only tables; breaktest drop; aggressive battery",
                ],
                [
                    "Novelty overclaim",
                    "Read as SOTA IDS",
                    "Experience report / protocol around open correlator",
                ],
            ],
            s,
            col_widths=[38 * mm, 55 * mm, 67 * mm],
        )
    )
    story.append(
        p(
            "Table 8. Rejection-to-response map. Full checklist: docs/CSET_REVISION_CHECKLIST.md.",
            s["caption"],
        )
    )
    story.append(
        p(
            "Closing line for the talk, if needed: synthetic security evaluations need hard "
            "stops between lab scores and field claims. Seal, ablate, prefer external corpora, "
            "name mechanisms, and keep the claim bit false until second-host evidence exists. "
            "That discipline travels farther than any single correlator score.",
            s["body"],
        )
    )
    story.append(Spacer(1, 8 * mm))
    story.append(hr())
    story.append(
        p(
            "Document version 2026-10-24 · Numbers from in-repo reports after micro-F1 fix and "
            "OTRF / live-stress batteries · claim_allowed=false",
            s["meta"],
        )
    )

    doc.build(story, onFirstPage=add_page_number, onLaterPages=add_page_number)
    OUT_COPY.write_bytes(OUT.read_bytes())
    return OUT


if __name__ == "__main__":
    path = build()
    print(f"Wrote {path}")
    print(f"Copy  {OUT_COPY}")
