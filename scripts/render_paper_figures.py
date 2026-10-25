#!/usr/bin/env python3
"""Render paper figures from locked Corvex report JSON (no re-eval).

Anima-style: numbers come from reports/*.json only; never invent metrics.
"""

from __future__ import annotations

import json
from collections import Counter
from pathlib import Path

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np

ROOT = Path(__file__).resolve().parents[1]
REPORTS = ROOT / "reports"
OUT = ROOT / "docs" / "paper" / "figures"
OUT.mkdir(parents=True, exist_ok=True)


def _load(name: str) -> dict:
    p = REPORTS / name
    if not p.is_file():
        raise FileNotFoundError(p)
    return json.loads(p.read_text(encoding="utf-8"))


def _style(ax):
    ax.spines["top"].set_visible(False)
    ax.spines["right"].set_visible(False)


def _verdict_label(c: dict) -> str:
    v = c.get("verdict_observational") or c.get("verdict")
    if isinstance(v, dict):
        return str(v.get("label") or "?")
    return str(v or "?")


def fig1_sealed_vs_breaktest():
    held = _load("stageA_heldout.json")["metrics"]
    brk = _load("non_author_fusion.json")
    labels = ["Precision", "Recall", "F1 (micro)"]
    sealed_c = [
        held["correlator"]["precision"],
        held["correlator"]["recall"],
        held["correlator"]["campaign_f1"],
    ]
    sealed_d = [
        held["detector_only"]["precision"],
        held["detector_only"]["recall"],
        held["detector_only"]["campaign_f1"],
    ]
    brk_c = [
        brk["correlator"]["precision"],
        brk["correlator"]["recall"],
        brk["correlator"]["campaign_f1"],
    ]
    brk_d = [
        brk["detector_only"]["precision"],
        brk["detector_only"]["recall"],
        brk["detector_only"]["campaign_f1"],
    ]

    x = np.arange(len(labels))
    w = 0.18
    fig, axes = plt.subplots(1, 2, figsize=(8.2, 3.4), dpi=200, sharey=True)
    for ax, title, cvals, dvals in (
        (axes[0], "Sealed held-out (N_atk=6)", sealed_c, sealed_d),
        (axes[1], "Breaktest / public-TTP", brk_c, brk_d),
    ):
        ax.bar(x - w, cvals, w * 1.6, label="Correlator", color="#1565c0")
        ax.bar(x + w, dvals, w * 1.6, label="Detector-only", color="#90a4ae")
        ax.set_xticks(x)
        ax.set_xticklabels(labels, fontsize=8)
        ax.set_ylim(0, 1.08)
        ax.set_title(title, fontsize=9)
        _style(ax)
    axes[0].set_ylabel("Score")
    axes[0].legend(fontsize=7, loc="lower right")
    fig.suptitle("Fig. 1  Micro P/R/F1: sealed hero numbers collapse on breaktest", fontsize=10)
    fig.tight_layout()
    fig.savefig(OUT / "fig1_sealed_vs_breaktest.png")
    fig.savefig(OUT / "fig1_sealed_vs_breaktest.pdf")
    plt.close(fig)


def fig2_fusion_lift():
    held = _load("stageA_heldout.json")["metrics"]
    brk = _load("non_author_fusion.json")
    sealed_lift = held["correlator"]["campaign_f1"] - held["detector_only"]["campaign_f1"]
    brk_lift = brk["f1_lift"]
    fig, ax = plt.subplots(figsize=(5.2, 3.4), dpi=200)
    bars = ax.bar(
        ["Sealed\nheld-out", "Breaktest\n(public-TTP)"],
        [sealed_lift, brk_lift],
        color=["#2e7d32", "#ef6c00"],
        width=0.55,
    )
    for b, v in zip(bars, [sealed_lift, brk_lift]):
        ax.text(b.get_x() + b.get_width() / 2, v + 0.02, f"{v:.3f}", ha="center", fontsize=9)
    ax.axhline(0.05, color="#455a64", ls="--", lw=0.8, label="Gate min lift (0.05)")
    ax.set_ylabel("F1 lift (correlator − detector-only)")
    ax.set_ylim(0, 0.55)
    ax.set_title("Fig. 2  Fusion lift is real — and smaller on harder packs")
    ax.legend(fontsize=7)
    _style(ax)
    fig.tight_layout()
    fig.savefig(OUT / "fig2_fusion_lift.png")
    fig.savefig(OUT / "fig2_fusion_lift.pdf")
    plt.close(fig)


def fig3_otrf_broad_verdicts():
    oss = _load("opensource_attack_eval.json")
    vc = oss["verdict_counts"]
    bc = oss.get("break_type_counts") or {}
    fig, axes = plt.subplots(1, 2, figsize=(8.2, 3.5), dpi=200)

    labels = list(vc.keys())
    vals = [vc[k] for k in labels]
    colors = ["#c62828" if "NO_LIFT" in k else "#90a4ae" for k in labels]
    axes[0].barh(labels, vals, color=colors)
    axes[0].set_xlabel("Corpora (N=36)")
    axes[0].set_title("Observational verdicts", fontsize=9)
    for i, v in enumerate(vals):
        axes[0].text(v + 0.3, i, str(v), va="center", fontsize=8)
    _style(axes[0])

    blabels = list(bc.keys())
    bvals = [bc[k] for k in blabels]
    axes[1].barh(blabels, bvals, color="#6a1b9a")
    axes[1].set_xlabel("Flag count")
    axes[1].set_title("Break flags (can co-occur)", fontsize=9)
    for i, v in enumerate(bvals):
        axes[1].text(v + 0.3, i, str(v), va="center", fontsize=8)
    _style(axes[1])

    fig.suptitle("Fig. 3  Broad OTRF atomics: camps form, fusion does not lift (external authorship)", fontsize=10)
    fig.tight_layout()
    fig.savefig(OUT / "fig3_otrf_broad.png")
    fig.savefig(OUT / "fig3_otrf_broad.pdf")
    plt.close(fig)


def fig4_aggressive_compounds():
    agg = _load("opensource_aggressive_eval.json")
    rows = []
    for c in agg["corpora"]:
        if not c.get("ok"):
            continue
        name = (c.get("attack") or c["id"])[:42]
        verd = _verdict_label(c)
        hosts = c.get("n_hosts_observed") or 0
        skip = (c.get("adapt") or {}).get("skip_rate")
        rows.append((name, verd, hosts, skip))

    # sort: HELD first
    order = {"FUSION_HELD": 0, "SINGLE_HOST": 1, "MULTI_HOST_NO_LIFT": 2}
    rows.sort(key=lambda r: (order.get(r[1], 9), r[0]))

    fig, ax = plt.subplots(figsize=(8.4, 4.6), dpi=200)
    y = np.arange(len(rows))
    colors = []
    for _, verd, _, _ in rows:
        if verd == "FUSION_HELD":
            colors.append("#2e7d32")
        elif verd == "SINGLE_HOST":
            colors.append("#90a4ae")
        else:
            colors.append("#c62828")
    hosts = [r[2] for r in rows]
    ax.barh(y, hosts, color=colors)
    ax.set_yticks(y)
    ax.set_yticklabels([r[0] for r in rows], fontsize=6.5)
    ax.set_xlabel("Hosts observed in capture")
    ax.set_title("Fig. 4  Aggressive compounds (N=14): green=FUSION_HELD, gray=SINGLE_HOST")
    # legend proxies
    from matplotlib.patches import Patch

    ax.legend(
        handles=[
            Patch(color="#2e7d32", label="FUSION_HELD (4)"),
            Patch(color="#90a4ae", label="SINGLE_HOST (10)"),
        ],
        fontsize=7,
        loc="lower right",
    )
    _style(ax)
    fig.tight_layout()
    fig.savefig(OUT / "fig4_aggressive.png")
    fig.savefig(OUT / "fig4_aggressive.pdf")
    plt.close(fig)


def fig5_live_catch():
    live = _load("live_opensource_stress.json")
    counts = Counter(live.get("catch_counts") or {})
    if not counts:
        for row in live.get("attacks") or []:
            lab = row.get("catch")
            if lab:
                counts[lab] += 1
    if "MISS" not in counts:
        counts["MISS"] = 0

    order = ["CAUGHT", "ALREADY_COVERED", "SINGLE_HOST_BATCH", "MISS"]
    labels = [k for k in order if k in counts] + [k for k in counts if k not in order]
    vals = [counts[k] for k in labels]
    colors = {
        "CAUGHT": "#2e7d32",
        "ALREADY_COVERED": "#1565c0",
        "SINGLE_HOST_BATCH": "#90a4ae",
        "MISS": "#c62828",
    }
    fig, ax = plt.subplots(figsize=(6.4, 3.5), dpi=200)
    bars = ax.bar(labels, vals, color=[colors.get(k, "#455a64") for k in labels])
    for b, v in zip(bars, vals):
        ax.text(b.get_x() + b.get_width() / 2, v + 0.4, str(v), ha="center", fontsize=9)
    ax.set_ylabel("Attack captures")
    ax.set_ylim(0, max(vals) * 1.25 if vals else 1)
    snap = live.get("final_snapshot") or {}
    ax.set_title(
        f"Fig. 5  Live laptop replay (N={live.get('n', sum(vals))}): "
        f"{snap.get('n_events', '?')} events → {snap.get('n_multi_host', '?')} multi-host camps\n"
        f"mode={live.get('mode', 'replay')} — not live malware execution"
    )
    _style(ax)
    fig.tight_layout()
    fig.savefig(OUT / "fig5_live_catch.png")
    fig.savefig(OUT / "fig5_live_catch.pdf")
    plt.close(fig)


def fig6_claim_gates():
    cg = _load("claim_gates.json")
    gates = cg["gates"]
    names = list(gates.keys())
    passed = [1 if gates[k].get("pass") else 0 for k in names]
    colors = ["#2e7d32" if p else "#c62828" for p in passed]
    fig, ax = plt.subplots(figsize=(7.2, 3.4), dpi=200)
    y = np.arange(len(names))
    ax.barh(y, [1] * len(names), color=colors, height=0.6)
    ax.set_yticks(y)
    ax.set_yticklabels(names, fontsize=8)
    ax.set_xlim(0, 1.35)
    ax.set_xticks([])
    for i, (n, p) in enumerate(zip(names, passed)):
        ax.text(1.05, i, "PASS" if p else "FAIL", va="center", fontsize=8, fontweight="bold",
                color="#2e7d32" if p else "#c62828")
    second = bool((cg.get("gates") or {}).get("live_second_host", {}).get("pass"))
    ax.set_title(
        "Fig. 6  Evidence checklist: lab items may pass while field-scope is withheld\n"
        f"(second-host physical telemetry: {'PASS' if second else 'FAIL'})"
    )
    _style(ax)
    fig.tight_layout()
    fig.savefig(OUT / "fig6_claim_gates.png")
    fig.savefig(OUT / "fig6_claim_gates.pdf")
    plt.close(fig)


def fig7_adapter_skip_held():
    agg = _load("opensource_aggressive_eval.json")
    held = [
        c
        for c in agg["corpora"]
        if c.get("ok") and _verdict_label(c) == "FUSION_HELD"
    ]
    names = [c["id"].replace("otrf-", "") for c in held]
    skips = [float((c.get("adapt") or {}).get("skip_rate") or 0.0) for c in held]
    n_hosts = [c.get("n_hosts_observed") or 0 for c in held]
    qn = [len(c.get("quarantine_dry_run_hosts") or []) for c in held]

    fig, ax1 = plt.subplots(figsize=(6.8, 3.6), dpi=200)
    x = np.arange(len(names))
    ax1.bar(x - 0.2, skips, 0.25, color="#6a1b9a", label="Adapter skip_rate")
    ax1.set_ylabel("Adapter skip rate")
    ax1.set_ylim(0, 1.05)
    ax2 = ax1.twinx()
    ax2.bar(x + 0.05, n_hosts, 0.25, color="#00838f", label="Hosts in capture")
    ax2.bar(x + 0.3, qn, 0.25, color="#ef6c00", label="Q dry-run hosts")
    ax2.set_ylabel("Host counts")
    ax1.set_xticks(x)
    ax1.set_xticklabels(names, fontsize=7, rotation=15, ha="right")
    ax1.set_title("Fig. 7  FUSION_HELD compounds: skip_rate vs hosts vs surgical Q")
    h1, l1 = ax1.get_legend_handles_labels()
    h2, l2 = ax2.get_legend_handles_labels()
    ax1.legend(h1 + h2, l1 + l2, fontsize=7, loc="upper right")
    _style(ax1)
    fig.tight_layout()
    fig.savefig(OUT / "fig7_adapter_skip.png")
    fig.savefig(OUT / "fig7_adapter_skip.pdf")
    plt.close(fig)


def fig8_family_sealed():
    held = _load("stageA_heldout.json")
    fam = (held.get("by_family") or {}).get("correlator") or {}
    # exclude benign for attack view; include all with F1
    names, f1s = [], []
    for k, v in fam.items():
        if not isinstance(v, dict):
            continue
        names.append(k)
        f1s.append(float(v.get("campaign_f1") or 0.0))
    if not names:
        return
    fig, ax = plt.subplots(figsize=(6.4, 3.3), dpi=200)
    ax.bar(names, f1s, color="#1565c0")
    ax.set_ylim(0, 1.08)
    ax.set_ylabel("Correlator micro-F1")
    ax.set_title("Fig. 8  Sealed held-out by family (still synthetic authorship)")
    ax.tick_params(axis="x", labelsize=8)
    _style(ax)
    fig.tight_layout()
    fig.savefig(OUT / "fig8_sealed_families.png")
    fig.savefig(OUT / "fig8_sealed_families.pdf")
    plt.close(fig)


def write_numbers_lock():
    """Emit docs/paper/NUMBERS_LOCKED.json for tex sync / reviewers."""
    held = _load("stageA_heldout.json")["metrics"]
    brk = _load("non_author_fusion.json")
    oss = _load("opensource_attack_eval.json")
    agg = _load("opensource_aggressive_eval.json")
    live = _load("live_opensource_stress.json")
    cg = _load("claim_gates.json")
    lock = {
        "sealed": {
            "n_attack": 6,
            "n_benign": 6,
            "correlator_f1": held["correlator"]["campaign_f1"],
            "detector_f1": held["detector_only"]["campaign_f1"],
            "correlator_p": held["correlator"]["precision"],
            "correlator_r": held["correlator"]["recall"],
            "detector_p": held["detector_only"]["precision"],
            "detector_r": held["detector_only"]["recall"],
            "b1_f1": held["b1"]["campaign_f1"],
            "benign_fcr": held["correlator"]["false_campaign_rate"],
            "tp_fp_fn": [held["correlator"]["tp"], held["correlator"]["fp"], held["correlator"]["fn"]],
        },
        "breaktest": {
            "correlator_f1": brk["correlator"]["campaign_f1"],
            "detector_f1": brk["detector_only"]["campaign_f1"],
            "lift": brk["f1_lift"],
            "tp_fp_fn_corr": [brk["correlator"]["tp"], brk["correlator"]["fp"], brk["correlator"]["fn"]],
            "tp_fp_fn_det": [brk["detector_only"]["tp"], brk["detector_only"]["fp"], brk["detector_only"]["fn"]],
        },
        "otrf_broad": {
            "n": oss["n"],
            "verdicts": oss["verdict_counts"],
            "breaks": oss.get("break_type_counts"),
        },
        "aggressive": {
            "n": agg["n"],
            "verdicts": agg["verdict_counts"],
        },
        "live": {
            "n": live["n"],
            "mode": live["mode"],
            "n_events": (live.get("final_snapshot") or {}).get("n_events"),
            "n_multi_host": (live.get("final_snapshot") or {}).get("n_multi_host"),
        },
        "claim_gates": {
            "claim_allowed": cg["claim_allowed"],
            "lab_verified": cg["lab_verified"],
            "gates": {k: v.get("pass") for k, v in cg["gates"].items()},
        },
    }
    out = ROOT / "docs" / "paper" / "NUMBERS_LOCKED.json"
    out.write_text(json.dumps(lock, indent=2), encoding="utf-8")
    print(f"Wrote {out}")


def main():
    fig1_sealed_vs_breaktest()
    fig2_fusion_lift()
    fig3_otrf_broad_verdicts()
    fig4_aggressive_compounds()
    fig5_live_catch()
    fig6_claim_gates()
    fig7_adapter_skip_held()
    fig8_family_sealed()
    write_numbers_lock()
    print(f"Figures in {OUT}")


if __name__ == "__main__":
    main()
