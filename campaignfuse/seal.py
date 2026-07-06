"""Held-out sealing with Fernet (age-compatible workflow: key outside repo)."""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
from typing import Iterable, List, Optional, Tuple

from cryptography.fernet import Fernet


def key_path() -> Path:
    override = os.environ.get("CFUSE_HELDOUT_KEY")
    if override:
        return Path(override)
    return Path.home() / ".campaignfuse" / "heldout.key"


def ensure_key(path: Optional[Path] = None) -> bytes:
    path = path or key_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists():
        return path.read_bytes().strip()
    key = Fernet.generate_key()
    path.write_bytes(key + b"\n")
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass
    return key


def seal_file(plain: Path, out: Path, key: bytes) -> str:
    token = Fernet(key).encrypt(plain.read_bytes())
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_bytes(token)
    return hashlib.sha256(token).hexdigest()


def unseal_file(sealed: Path, key: bytes) -> bytes:
    return Fernet(key).decrypt(sealed.read_bytes())


def write_sealed_manifest(heldout_dir: Path, digests: Iterable[Tuple[str, str]]) -> str:
    """digests: list of (relative_name, sha256). Returns aggregate SEALED.sha256 content hash."""
    heldout_dir = Path(heldout_dir)
    lines = [f"{digest}  {name}" for name, digest in digests]
    # Include scorer rules hash marker file if present
    text = "\n".join(sorted(lines)) + "\n"
    man = heldout_dir / "SEALED.sha256"
    man.write_text(text, encoding="utf-8")
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def scorer_rules_blob() -> str:
    """Frozen matching rules text hashed into sealed bundle."""
    return json.dumps(
        {
            "host_jaccard_threshold": 0.5,
            "stage_name_overlap_required": True,
            "ttu_clock": "wall_time_of_predict_function",
            "f1_definition": "2pr/(p+r) over greedy Jaccard matches",
            "pass_bars": {
                "f1": ">= max(0.70, B2_F1) and >= B2_F1",
                "precision_at_1": ">= 0.80",
                "false_campaign_rate": "<= 0.10",
                "ttu_seconds": "<= 2.0",
            },
        },
        sort_keys=True,
        separators=(",", ":"),
    )
