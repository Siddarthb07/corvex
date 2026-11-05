#!/usr/bin/env python3
"""Wrapper — delegates to `corvex seal-day0`."""

from __future__ import annotations

import sys

from corvex.cli import seal_day0


def main() -> int:
    seal_day0(force="--force" in sys.argv)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
