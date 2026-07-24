"""Observe-only adapters: external exports → Corvex EventEnvelope / BYO JSONL."""

from corvex.adapters.attack_repos import adapt_attack_manifest, load_manifest
from corvex.adapters.os_wide import adapt_os_wide_export, adapt_os_wide_records
from corvex.adapters.windows_security import adapt_windows_security_export

__all__ = [
    "adapt_windows_security_export",
    "adapt_os_wide_export",
    "adapt_os_wide_records",
    "adapt_attack_manifest",
    "load_manifest",
]
