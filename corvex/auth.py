"""Enrollment + per-producer secrets. CI must fail on shared/default secrets.

Default trust model is **1 producer_id ↔ 1 host_id**. A shared secret across
many hosts under one producer lets a single compromised credential forge events
as any enrolled peer — which defeats host-identity resolution (Slice C).

Opt into aggregators only with `CORVEX_ALLOW_MULTIHOST_PRODUCER=1` or
`allow_multihost_producer=True` (tests / explicit lab).
"""

from __future__ import annotations

import json
import os
import secrets
from pathlib import Path
from typing import Dict, Mapping, Optional, Set

# Explicit poison values — tests assert these never appear as committed secrets.
FORBIDDEN_DEFAULT_SECRETS = {
    "changeme",
    "shared",
    "default",
    "corvex-shared-secret",
    "test-shared-hmac",
    # Contain dual-control must not reuse these either (see contain/live.py).
    "lab-dual-control-token",
}


class AuthError(ValueError):
    pass


def _multihost_producer_allowed(explicit: Optional[bool] = None) -> bool:
    if explicit is not None:
        return bool(explicit)
    return os.environ.get("CORVEX_ALLOW_MULTIHOST_PRODUCER", "").strip() in (
        "1",
        "true",
        "TRUE",
        "yes",
    )


class Enrollment:
    """producer_id -> allowed host_id set + per-producer HMAC secret.

    By default each producer may enroll **exactly one** host. Multi-host
    producers require an explicit opt-in (see module docstring).
    """

    def __init__(
        self,
        mapping: Mapping[str, Set[str]],
        secrets_map: Mapping[str, bytes],
        *,
        allow_multihost_producer: Optional[bool] = None,
    ):
        self._hosts = {k: set(v) for k, v in mapping.items()}
        self._secrets = dict(secrets_map)
        self._allow_multihost = _multihost_producer_allowed(allow_multihost_producer)
        for pid, hosts in self._hosts.items():
            if len(hosts) > 1 and not self._allow_multihost:
                raise AuthError(
                    f"producer {pid} enrolled for {len(hosts)} hosts; "
                    "default trust model is 1:1 producer↔host. "
                    "Set CORVEX_ALLOW_MULTIHOST_PRODUCER=1 only if you accept "
                    "that one leaked secret forges events for every peer host."
                )
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
    *,
    allow_multihost_producer: Optional[bool] = None,
) -> Enrollment:
    """hosts: host_id -> producer_id"""
    by_producer: Dict[str, Set[str]] = {}
    secrets_map: Dict[str, bytes] = {}
    for host_id, producer_id in hosts.items():
        by_producer.setdefault(producer_id, set()).add(host_id)
        if producer_id not in secrets_map:
            secrets_map[producer_id] = secrets.token_bytes(32)
    return Enrollment(
        by_producer,
        secrets_map,
        allow_multihost_producer=allow_multihost_producer,
    )


def _harden_secrets_file(path: Path) -> None:
    """Best-effort: owner-only ACL. Not a substitute for OS keystore (DPAPI later)."""
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass
    if os.name == "nt":
        try:
            import subprocess

            user = os.environ.get("USERNAME") or os.environ.get("USER") or ""
            if user:
                subprocess.run(
                    [
                        "icacls",
                        str(path),
                        "/inheritance:r",
                        "/grant:r",
                        f"{user}:(R,W)",
                    ],
                    check=False,
                    capture_output=True,
                    timeout=15,
                )
        except Exception:
            pass


def save_enrollment(path: Path, enrollment: Enrollment) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    # Secrets stored outside repo preference: if under ~/.corvex, OK.
    # Plaintext JSON + owner-only ACL — rotate by deleting enrollment.json and re-enrolling.
    payload = {
        "hosts": enrollment.to_public_dict(),
        "secrets_hex": {k: v.hex() for k, v in enrollment._secrets.items()},
    }
    path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    _harden_secrets_file(path)


def _split_multihost_producers(
    hosts: Mapping[str, Set[str]],
    secrets_map: Mapping[str, bytes],
) -> tuple:
    """Migrate aggregator producers → 1:1 (extra hosts get new producer ids + secrets)."""
    new_hosts: Dict[str, Set[str]] = {}
    new_secrets: Dict[str, bytes] = {}
    for pid, hs in hosts.items():
        ordered = sorted(hs)
        if len(ordered) <= 1:
            new_hosts[pid] = set(ordered)
            if pid in secrets_map:
                new_secrets[pid] = secrets_map[pid]
            continue
        # Preserve original producer+secret for the first host; split the rest.
        new_hosts[pid] = {ordered[0]}
        new_secrets[pid] = secrets_map[pid]
        for host_id in ordered[1:]:
            new_pid = f"{pid}__{host_id}"
            while new_pid in new_hosts:
                new_pid = f"{new_pid}_x"
            new_hosts[new_pid] = {host_id}
            new_secrets[new_pid] = secrets.token_bytes(32)
    return new_hosts, new_secrets


def load_enrollment(path: Path, *, migrate_multihost: bool = True) -> Enrollment:
    data = json.loads(path.read_text(encoding="utf-8"))
    hosts = {k: set(v) for k, v in data["hosts"].items()}
    secrets_map = {k: bytes.fromhex(v) for k, v in data["secrets_hex"].items()}
    try:
        return Enrollment(hosts, secrets_map)
    except AuthError as exc:
        if not migrate_multihost or "1:1" not in str(exc):
            raise
        hosts, secrets_map = _split_multihost_producers(hosts, secrets_map)
        enrollment = Enrollment(hosts, secrets_map)
        save_enrollment(path, enrollment)
        return enrollment


def default_secrets_path() -> Path:
    override = os.environ.get("CORVEX_ENROLLMENT") or os.environ.get("CFUSE_ENROLLMENT")
    if override:
        return Path(override)
    new = Path.home() / ".corvex" / "enrollment.json"
    legacy = Path.home() / ".campaignfuse" / "enrollment.json"
    if new.exists() or not legacy.exists():
        return new
    return legacy
