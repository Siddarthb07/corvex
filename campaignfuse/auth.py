"""Enrollment + per-producer secrets. CI must fail on shared/default secrets."""

from __future__ import annotations

import json
import os
import secrets
from pathlib import Path
from typing import Dict, Mapping, Set

# Explicit poison values — tests assert these never appear as committed secrets.
FORBIDDEN_DEFAULT_SECRETS = {
    "changeme",
    "shared",
    "default",
    "campaignfuse-shared-secret",
    "test-shared-hmac",
}


class AuthError(ValueError):
    pass


class Enrollment:
    """producer_id -> allowed host_id set + per-producer HMAC secret."""

    def __init__(self, mapping: Mapping[str, Set[str]], secrets_map: Mapping[str, bytes]):
        self._hosts = {k: set(v) for k, v in mapping.items()}
        self._secrets = dict(secrets_map)
        for pid, secret in self._secrets.items():
            text = secret.decode("utf-8", errors="replace")
            if text.lower() in FORBIDDEN_DEFAULT_SECRETS:
                raise AuthError(f"forbidden default/shared secret for producer {pid}")
            if len(secret) < 16:
                raise AuthError(f"secret too short for producer {pid}")

    def allowed(self, producer_id: str, host_id: str) -> bool:
        return host_id in self._hosts.get(producer_id, set())

    def secret_for(self, producer_id: str) -> bytes:
        if producer_id not in self._secrets:
            raise AuthError(f"unknown producer_id={producer_id}")
        return self._secrets[producer_id]

    def require(self, producer_id: str, host_id: str) -> bytes:
        if not self.allowed(producer_id, host_id):
            raise AuthError(f"producer {producer_id} not enrolled for host {host_id}")
        return self.secret_for(producer_id)

    def to_public_dict(self) -> Dict[str, list]:
        return {k: sorted(v) for k, v in self._hosts.items()}


def generate_lab_enrollment(
    hosts: Mapping[str, str],
) -> Enrollment:
    """hosts: host_id -> producer_id"""
    by_producer: Dict[str, Set[str]] = {}
    secrets_map: Dict[str, bytes] = {}
    for host_id, producer_id in hosts.items():
        by_producer.setdefault(producer_id, set()).add(host_id)
        if producer_id not in secrets_map:
            secrets_map[producer_id] = secrets.token_bytes(32)
    return Enrollment(by_producer, secrets_map)


def save_enrollment(path: Path, enrollment: Enrollment) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    # Secrets stored outside repo preference: if under ~/.campaignfuse, OK.
    payload = {
        "hosts": enrollment.to_public_dict(),
        "secrets_hex": {k: v.hex() for k, v in enrollment._secrets.items()},
    }
    path.write_text(json.dumps(payload, indent=2), encoding="utf-8")


def load_enrollment(path: Path) -> Enrollment:
    data = json.loads(path.read_text(encoding="utf-8"))
    hosts = {k: set(v) for k, v in data["hosts"].items()}
    secrets_map = {k: bytes.fromhex(v) for k, v in data["secrets_hex"].items()}
    return Enrollment(hosts, secrets_map)


def default_secrets_path() -> Path:
    override = os.environ.get("CFUSE_ENROLLMENT")
    if override:
        return Path(override)
    return Path.home() / ".campaignfuse" / "enrollment.json"
