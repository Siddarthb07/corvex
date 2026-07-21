"""Lab enrollment helpers for local demos (secrets stay outside the repo)."""

from __future__ import annotations

from pathlib import Path
from typing import Optional

from corvex.auth import (
    Enrollment,
    default_secrets_path,
    generate_lab_enrollment,
    load_enrollment,
    save_enrollment,
)

# Default demo hosts used by train packs + live lab.
DEMO_HOSTS = {
    "host-a": "prod-a",
    "host-b": "prod-b",
    "host-c": "prod-c",
    "host-d": "prod-d",
}


def ensure_lab_enrollment(
    path: Optional[Path] = None,
    *,
    hosts: Optional[dict] = None,
) -> Enrollment:
    """Load enrollment from disk, or create a fresh lab enrollment once."""
    dest = Path(path) if path else default_secrets_path()
    if dest.exists():
        return load_enrollment(dest)
    enrollment = generate_lab_enrollment(hosts or DEMO_HOSTS)
    save_enrollment(dest, enrollment)
    return enrollment
