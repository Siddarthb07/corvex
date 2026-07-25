"""Stranger attestation crypto — Ed25519 self-sign (stranger holds private key).

Author-held HMAC keys are advisory / legacy and do not unlock claim_allowed.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
from pathlib import Path
from typing import Any, Dict, Optional, Tuple

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)


def canonical_attestation_body(attestation: Dict[str, Any]) -> bytes:
    skip = {
        "attestation_hmac",
        "attestation_sig",
        "attestation_pubkey",
        "attestation_alg",
        "attestation_custody",
    }
    body = {k: v for k, v in attestation.items() if k not in skip}
    return json.dumps(body, sort_keys=True, separators=(",", ":")).encode("utf-8")


def attestation_key_path(root: Path) -> Path:
    return Path(root) / "reports" / ".claim_attestation_key"


def stranger_private_key_path(root: Path) -> Path:
    return Path(root) / "reports" / ".stranger_ed25519_private.pem"


def load_attestation_hmac_secret(root: Path) -> Optional[bytes]:
    env = os.environ.get("CORVEX_ATTESTATION_HMAC") or ""
    if env.strip():
        return env.strip().encode("utf-8")
    path = attestation_key_path(root)
    if path.exists():
        raw = path.read_text(encoding="utf-8").strip()
        if raw:
            return raw.encode("utf-8")
    return None


def sign_attestation_hmac(attestation: Dict[str, Any], secret: bytes) -> Dict[str, Any]:
    """Legacy author-held HMAC — custody=author_key; does not unlock claims."""
    out = dict(attestation)
    for k in ("attestation_hmac", "attestation_sig", "attestation_pubkey", "attestation_alg"):
        out.pop(k, None)
    mac = hmac.new(secret, canonical_attestation_body(out), hashlib.sha256).hexdigest()
    out["attestation_hmac"] = mac
    out["attestation_alg"] = "hmac-sha256"
    out["attestation_custody"] = "author_key"
    return out


def verify_attestation_hmac(attestation: Dict[str, Any], secret: bytes) -> bool:
    got = str(attestation.get("attestation_hmac") or "")
    if not got or len(got) < 32:
        return False
    expected = hmac.new(
        secret, canonical_attestation_body(attestation), hashlib.sha256
    ).hexdigest()
    return hmac.compare_digest(expected, got)


def generate_stranger_keypair(path: Path) -> Tuple[Ed25519PrivateKey, str]:
    """Write PEM private key (gitignored). Returns key + base64 raw public key."""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    key = Ed25519PrivateKey.generate()
    pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    path.write_bytes(pem)
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass
    pub_b64 = base64.urlsafe_b64encode(
        key.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
    ).decode("ascii").rstrip("=")
    return key, pub_b64


def load_stranger_private_key(path: Path) -> Ed25519PrivateKey:
    data = Path(path).read_bytes()
    return serialization.load_pem_private_key(data, password=None)


def sign_attestation_ed25519(
    attestation: Dict[str, Any],
    private_key: Ed25519PrivateKey,
) -> Dict[str, Any]:
    out = dict(attestation)
    for k in ("attestation_hmac", "attestation_sig", "attestation_pubkey", "attestation_alg"):
        out.pop(k, None)
    pub_b64 = base64.urlsafe_b64encode(
        private_key.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
    ).decode("ascii").rstrip("=")
    sig = private_key.sign(canonical_attestation_body(out))
    out["attestation_alg"] = "ed25519"
    out["attestation_custody"] = "stranger_private_key"
    out["attestation_pubkey"] = pub_b64
    out["attestation_sig"] = base64.urlsafe_b64encode(sig).decode("ascii").rstrip("=")
    return out


def _b64decode(data: str) -> bytes:
    pad = "=" * (-len(data) % 4)
    return base64.urlsafe_b64decode(data + pad)


def verify_attestation_ed25519(attestation: Dict[str, Any]) -> bool:
    if str(attestation.get("attestation_alg") or "").lower() != "ed25519":
        return False
    pub_b64 = str(attestation.get("attestation_pubkey") or "")
    sig_b64 = str(attestation.get("attestation_sig") or "")
    if not pub_b64 or not sig_b64:
        return False
    try:
        pub = Ed25519PublicKey.from_public_bytes(_b64decode(pub_b64))
        pub.verify(_b64decode(sig_b64), canonical_attestation_body(attestation))
        return True
    except Exception:
        return False


def stranger_signature_ok(attestation: Dict[str, Any], root: Path) -> Tuple[bool, str, str]:
    """Return (ok, custody, note). Only ed25519 stranger custody unlocks claims."""
    alg = str(attestation.get("attestation_alg") or "").lower()
    if alg == "ed25519" or attestation.get("attestation_sig"):
        if verify_attestation_ed25519(attestation):
            custody = str(attestation.get("attestation_custody") or "stranger_private_key")
            if custody != "stranger_private_key":
                return False, custody, "FAIL: ed25519 sig ok but custody must be stranger_private_key"
            return True, "stranger_private_key", "Ed25519 stranger self-signature verified"
        return False, "invalid", "FAIL: ed25519 attestation_sig did not verify"
    secret = load_attestation_hmac_secret(root)
    if secret and verify_attestation_hmac(attestation, secret):
        return (
            False,
            "author_key",
            "FAIL: author-held HMAC verifies but does not unlock claim_allowed "
            "(use corvex stranger-keygen + sign-stranger-attestation --ed25519).",
        )
    return False, "unsigned", "FAIL: no verifying ed25519 stranger signature"
