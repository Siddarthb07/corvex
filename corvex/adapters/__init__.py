"""Observe-only adapters: external exports → Corvex EventEnvelope / BYO JSONL."""

from corvex.adapters.attack_repos import adapt_attack_manifest, load_manifest
from corvex.adapters.windows_security import adapt_windows_security_export

__all__ = [
    "adapt_windows_security_export",
    "adapt_attack_manifest",
    "load_manifest",
]
