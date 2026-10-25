#!/usr/bin/env python3
"""Compile docs/paper/corvex_paper.tex -> PDF copies for journal/workshop track."""

from __future__ import annotations

import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PAPER = ROOT / "docs" / "paper"
TEX = PAPER / "corvex_paper.tex"
OUT_PRIMARY = PAPER / "Corvex_Claim_Gates_FINAL.pdf"
OUT_VENUE = ROOT / "docs" / "venues" / "journal-workshop" / "Corvex_Claim_Gates_FINAL.pdf"
OUT_COPY = ROOT / "output" / "pdf" / "Corvex_Claim_Gates_FINAL.pdf"


def run_pdflatex(pass_n: int) -> None:
    cmd = [
        "pdflatex",
        "-interaction=nonstopmode",
        "-halt-on-error",
        TEX.name,
    ]
    print(f"[pdflatex pass {pass_n}]")
    r = subprocess.run(cmd, cwd=PAPER, capture_output=True, text=True)
    if r.returncode != 0:
        sys.stderr.write(r.stdout[-4000:] if r.stdout else "")
        sys.stderr.write(r.stderr[-2000:] if r.stderr else "")
        raise SystemExit(f"pdflatex failed (pass {pass_n})")


def run_bibtex() -> None:
    print("[bibtex]")
    r = subprocess.run(
        ["bibtex", "corvex_paper"],
        cwd=PAPER,
        capture_output=True,
        text=True,
    )
    # bibtex return code can be non-zero on warnings; check .bbl exists
    bbl = PAPER / "corvex_paper.bbl"
    if not bbl.exists():
        sys.stderr.write(r.stdout or "")
        sys.stderr.write(r.stderr or "")
        raise SystemExit("bibtex failed: no .bbl")


def main() -> None:
    if not TEX.exists():
        raise SystemExit(f"missing {TEX}")
    OUT_VENUE.parent.mkdir(parents=True, exist_ok=True)
    OUT_COPY.parent.mkdir(parents=True, exist_ok=True)

    # Refresh figures from locked JSON before compile (Anima-style).
    render = ROOT / "scripts" / "render_paper_figures.py"
    if render.exists():
        print("[render_paper_figures]")
        r = subprocess.run([sys.executable, str(render)], cwd=ROOT)
        if r.returncode != 0:
            raise SystemExit("figure render failed")

    run_pdflatex(1)
    run_bibtex()
    run_pdflatex(2)
    run_pdflatex(3)

    built = PAPER / "corvex_paper.pdf"
    if not built.exists():
        raise SystemExit("corvex_paper.pdf not produced")

    for dest in (OUT_PRIMARY, OUT_VENUE, OUT_COPY):
        shutil.copy2(built, dest)
        print(f"Wrote {dest}")

    # page count
    try:
        import pdfplumber

        with pdfplumber.open(built) as pdf:
            print(f"pages={len(pdf.pages)} bytes={built.stat().st_size}")
    except Exception as e:  # noqa: BLE001
        print(f"(page count skipped: {e})")


if __name__ == "__main__":
    main()
