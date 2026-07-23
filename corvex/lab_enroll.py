"""Lab enrollment helpers for local demos (secrets stay outside the repo)."""

from __future__ import annotations

import secrets
from pathlib import Path
from typing import Optional

from corvex.auth import (
    Enrollment,
    default_secrets_path,
    generate_lab_enrollment,
    load_enrollment,
    save_enrollment,
)

# Default demo hosts used by train packs + live / break-test labs.
DEMO_HOSTS = {
    "host-a": "prod-a",
    "host-b": "prod-b",
    "host-c": "prod-c",
    "host-d": "prod-d",
    "host-e": "prod-e",
}


def ensure_lab_enrollment(
    path: Optional[Path] = None,
    *,
    hosts: Optional[dict] = None,
) -> Enrollment:
    """Load enrollment from disk, or create a fresh lab enrollment once.

    If an enrollment already exists, missing DEMO hosts/producers are merged in
    so 5-host packs work without wiping local secrets.
    """
    dest = Path(path) if path else default_secrets_path()
    wanted = hosts or DEMO_HOSTS
    if not dest.exists():
        enrollment = generate_lab_enrollment(wanted)
        save_enrollment(dest, enrollment)
        return enrollment

    enrollment = load_enrollment(dest)
    host_map = {h: set(hs) for h, hs in enrollment._hosts.items()}
    secrets_map = dict(enrollment._secrets)
    changed = False
    for host_id, producer_id in wanted.items():
        if producer_id not in secrets_map:
            secrets_map[producer_id] = secrets.token_bytes(32)
            changed = True
        if host_id not in host_map.setdefault(producer_id, set()):
            host_map[producer_id].add(host_id)
            changed = True
    if changed:
        enrollment = Enrollment(host_map, secrets_map)
        save_enrollment(dest, enrollment)
    return enrollment
