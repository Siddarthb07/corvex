"""Atomic Red Team playbook orchestration (lab purple-team only).

Does **not** vendor Atomic YAML or payloads. Shells out to an operator-installed
Invoke-AtomicRedTeam. Does not flip claim_allowed.
"""

from __future__ import annotations

from corvex.atomic.bindings import BINDINGS, binding_for
from corvex.atomic.playbook import bind_manifest, load_playbook, validate_playbook
from corvex.atomic.runner import AtomicGateError, preflight, run_playbook

__all__ = [
    "BINDINGS",
    "AtomicGateError",
    "bind_manifest",
    "binding_for",
    "load_playbook",
    "preflight",
    "run_playbook",
    "validate_playbook",
]
