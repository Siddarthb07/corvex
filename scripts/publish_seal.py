#!/usr/bin/env python3
"""Publish SEALED.sha256 digest to git notes (immutable timestamp proxy)."""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def main() -> int:
    sealed = (ROOT / "heldout" / "SEALED.sha256").read_text(encoding="utf-8").splitlines()[0].strip()
    # orphan empty commit note via git notes — requires git repo with commit
    try:
        subprocess.run(["git", "rev-parse", "HEAD"], cwd=ROOT, check=True, capture_output=True)
    except subprocess.CalledProcessError:
        print("No HEAD yet — writing heldout/SEAL_TIMESTAMP.txt only", file=sys.stderr)
        (ROOT / "heldout" / "SEAL_TIMESTAMP.txt").write_text(sealed + "\n", encoding="utf-8")
        return 0

    subprocess.run(
        ["git", "notes", "--ref", "refs/notes/corvex-seal", "add", "-f", "-m", sealed],
        cwd=ROOT,
        check=False,
    )
    (ROOT / "heldout" / "SEAL_TIMESTAMP.txt").write_text(sealed + "\n", encoding="utf-8")
    print(sealed)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
