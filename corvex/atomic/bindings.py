"""Curated technique → Atomic Red Team test_number defaults.

These are lab-oriented picks for Corvex core techniques. They are **not**
vendored Atomic bodies — only technique IDs + recommended test numbers.
Operators must verify against their local atomics folder before running.
"""

from __future__ import annotations

from typing import Any, Dict, Mapping, Optional

# technique_id -> binding template (without runtime host/input overrides)
BINDINGS: Dict[str, Dict[str, Any]] = {
    "T1078": {
        "technique": "T1078",
        "test_number": 1,
        "get_prereqs": True,
        "cleanup": True,
        "input_args": {},
        "note": (
            "Valid Accounts — prefer a low-impact local-account style Atomic. "
            "Confirm test # against local atomics before lab run."
        ),
        "risk": "low",
    },
    "T1021": {
        "technique": "T1021",
        "test_number": 1,
        "get_prereqs": True,
        "cleanup": True,
        "input_args": {},
        "note": (
            "Remote Services parent. Prefer mapping to T1021.001 if your atomics "
            "tree uses sub-technique folders."
        ),
        "risk": "medium",
    },
    "T1021.001": {
        "technique": "T1021.001",
        "test_number": 1,
        "get_prereqs": True,
        "cleanup": True,
        "input_args": {},
        "note": "Remote Desktop Protocol — lab only; needs RDP-capable target.",
        "risk": "medium",
    },
    "T1041": {
        "technique": "T1041",
        "test_number": 1,
        "get_prereqs": True,
        "cleanup": True,
        "input_args": {},
        "note": (
            "Exfiltration Over C2 Channel — pick a test that generates outbound "
            "net telemetry without wiping disks."
        ),
        "risk": "low",
    },
    "T1046": {
        "technique": "T1046",
        "test_number": 1,
        "get_prereqs": True,
        "cleanup": True,
        "input_args": {},
        "note": "Network Service Discovery — PowerShell/nmap-style scan for recon_fanout signal.",
        "risk": "low",
    },
    "T1071.004": {
        "technique": "T1071.004",
        "test_number": 1,
        "get_prereqs": True,
        "cleanup": True,
        "input_args": {},
        "note": "Application Layer Protocol: DNS — for dns_beacon-shaped telemetry.",
        "risk": "low",
    },
    "T1110": {
        "technique": "T1110",
        "test_number": 1,
        "get_prereqs": True,
        "cleanup": True,
        "input_args": {},
        "note": "Brute Force — lab accounts only; never against production IdP.",
        "risk": "medium",
    },
    "T1190": {
        "technique": "T1190",
        "test_number": 1,
        "get_prereqs": True,
        "cleanup": True,
        "input_args": {},
        "note": "Exploit Public-Facing Application — only if Atomic exists for your lab app.",
        "risk": "high",
    },
}


def normalize_technique(technique: Optional[str]) -> Optional[str]:
    if not technique:
        return None
    t = str(technique).strip().upper()
    if not t.startswith("T"):
        return t
    return t


def binding_for(technique: Optional[str]) -> Optional[Dict[str, Any]]:
    """Return a copy of the curated binding, or None if unlisted."""
    tid = normalize_technique(technique)
    if not tid:
        return None
    base = BINDINGS.get(tid)
    if base is None and "." in tid:
        # Fall back to parent technique (T1021.001 → T1021)
        base = BINDINGS.get(tid.split(".", 1)[0])
    if base is None:
        return None
    out = dict(base)
    out["technique"] = tid if tid in BINDINGS else out["technique"]
    return out


def is_curated(technique: Optional[str]) -> bool:
    tid = normalize_technique(technique)
    if not tid:
        return False
    if tid in BINDINGS:
        return True
    if "." in tid and tid.split(".", 1)[0] in BINDINGS:
        return True
    return False


def merge_atomic_override(
    technique: Optional[str],
    existing: Optional[Mapping[str, Any]],
) -> Optional[Dict[str, Any]]:
    """Merge curated defaults with an explicit playbook atomic block."""
    curated = binding_for(technique)
    if existing is None and curated is None:
        return None
    if existing is None:
        return curated
    # Explicit null / empty means leave unbound
    if existing is False:
        return None
    merged: Dict[str, Any] = dict(curated or {})
    for key, val in existing.items():
        if val is not None:
            merged[key] = val
    tech = normalize_technique(str(merged.get("technique") or technique or ""))
    if tech:
        merged["technique"] = tech
    if "test_number" not in merged or merged.get("test_number") is None:
        return None
    merged.setdefault("get_prereqs", True)
    merged.setdefault("cleanup", True)
    merged.setdefault("input_args", {})
    return merged
