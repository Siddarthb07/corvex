#!/usr/bin/env python3
"""Fetch a public OTRF/Security-Datasets zip into labs/benign/<name>/raw/.

Does not invent benign traffic — downloads captured telemetry you did not author.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
import urllib.request
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

# Default smoke slice: multi-host Mordor lab (DC + workstations), ~2 min span.
# Mixed attack+ambient — cannot PASS the pure-benign gate; adapter/smoke only.
DEFAULT_URL = (
    "https://raw.githubusercontent.com/OTRF/Security-Datasets/master/"
    "datasets/atomic/windows/lateral_movement/host/"
    "empire_psexec_dcerpc_tcp_svcctl.zip"
)
DEFAULT_NAME = "otrf-empire-psexec"


def _sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def fetch(url: str, dest_dir: Path) -> dict:
    dest_dir.mkdir(parents=True, exist_ok=True)
    (dest_dir / ".gitkeep").touch()
    zip_path = dest_dir / "download.zip"
    print(f"GET {url}", flush=True)
    with urllib.request.urlopen(url, timeout=120) as resp:
        zip_path.write_bytes(resp.read())
    extracted: list[str] = []
    with zipfile.ZipFile(zip_path, "r") as zf:
        for name in zf.namelist():
            if name.endswith("/"):
                continue
            target = dest_dir / Path(name).name
            target.write_bytes(zf.read(name))
            extracted.append(target.name)
    meta = {
        "source_url": url,
        "zip_sha256": _sha256(zip_path),
        "extracted": extracted,
        "license_note": "OTRF Security-Datasets — see upstream LICENSE (GPL-3.0).",
    }
    (dest_dir / "fetch_meta.json").write_text(
        json.dumps(meta, indent=2) + "\n", encoding="utf-8"
    )
    zip_path.unlink(missing_ok=True)
    return meta


def write_manifest(corpus_dir: Path, *, url: str, meta: dict) -> Path:
    man = {
        "name": corpus_dir.name,
        "corpus_kind": "mixed",
        "source": {
            "project": "OTRF/Security-Datasets",
            "url": url,
            "note": (
                "Attack simulation capture with ambient lab noise. "
                "Not a pure-benign corpus — gate stays INCOMPLETE."
            ),
        },
        "raw_glob": "raw/*.json",
        "host_map": {},
        "attack_windows": [],
        "roles": {
            "mordordc": "domain_controller_candidate",
            "workstation5": "endpoint",
            "workstation6": "endpoint",
        },
        "fetch": meta,
        "bars_locked": "2026-07-25",
    }
    path = corpus_dir / "manifest.json"
    path.write_text(json.dumps(man, indent=2) + "\n", encoding="utf-8")
    return path


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--url", default=DEFAULT_URL)
    ap.add_argument("--name", default=DEFAULT_NAME)
    ap.add_argument(
        "--out",
        type=Path,
        default=None,
        help="Corpus dir (default: labs/benign/<name>)",
    )
    args = ap.parse_args()
    corpus = Path(args.out) if args.out else ROOT / "labs" / "benign" / args.name
    raw = corpus / "raw"
    meta = fetch(args.url, raw)
    write_manifest(corpus, url=args.url, meta=meta)
    readme = corpus / "README.md"
    if not readme.exists():
        readme.write_text(
            f"""# {corpus.name}

Public OTRF/Security-Datasets slice (captured telemetry — not hand-authored).

- **corpus_kind:** `mixed` (attack + ambient). Cannot PASS the pure-benign gate.
- **Source:** {args.url}
- **Raw:** `raw/` (gitignored). Re-fetch: `python scripts/fetch_otrf_corpus.py --name {corpus.name}`

See `labs/benign/README.md` and `future-plans.md` § Benign corpus plan.
""",
            encoding="utf-8",
        )
    print(json.dumps({"corpus": str(corpus), "extracted": meta["extracted"]}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
