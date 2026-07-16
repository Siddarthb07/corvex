#!/usr/bin/env python3
"""One-command seal helper (Fernet; key outside repo)."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from corvex.seal import ensure_key, key_path, seal_file, unseal_file  # noqa: E402


def main() -> int:
    p = argparse.ArgumentParser(description="Corvex held-out seal")
    p.add_argument("mode", choices=["encrypt", "decrypt", "ensure-key"])
    p.add_argument("src", nargs="?", type=Path)
    p.add_argument("dest", nargs="?", type=Path)
    args = p.parse_args()
    if args.mode == "ensure-key":
        ensure_key()
        print(key_path())
        return 0
    key = ensure_key()
    if args.mode == "encrypt":
        print(seal_file(args.src, args.dest, key))
    else:
        args.dest.write_bytes(unseal_file(args.src, key))
        print(args.dest)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
