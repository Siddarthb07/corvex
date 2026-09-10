"""Atomic playbook load / validate / bind from breaktest manifests."""

from __future__ import annotations

import copy
import json
from pathlib import Path
from typing import Any, Dict, List, Mapping, Optional, Sequence

from corvex.atomic.bindings import is_curated, merge_atomic_override, normalize_technique

PLAYBOOK_SCHEMA_VER = "1"
REQUIRED_TOP = {"campaign_id", "hosts", "steps"}


class PlaybookError(ValueError):
    pass


def load_playbook(path: Path) -> Dict[str, Any]:
    path = Path(path)
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise PlaybookError(f"playbook must be a JSON object: {path}")
    validate_playbook(data)
    return data


def validate_playbook(data: Mapping[str, Any]) -> None:
    missing = REQUIRED_TOP - set(data)
    if missing:
        raise PlaybookError(f"playbook missing {sorted(missing)}")
    hosts = data.get("hosts")
    if not isinstance(hosts, list) or not hosts:
        raise PlaybookError("hosts must be a non-empty list")
    steps = data.get("steps")
    if not isinstance(steps, list) or not steps:
        raise PlaybookError("steps must be a non-empty list")
    for i, step in enumerate(steps):
        if not isinstance(step, Mapping):
            raise PlaybookError(f"steps[{i}] must be an object")
        if not step.get("host") and not step.get("kind"):
            raise PlaybookError(f"steps[{i}] needs host and/or kind")
        atomic = step.get("atomic")
        if atomic is None:
            continue
        if atomic is False:
            continue
        if not isinstance(atomic, Mapping):
            raise PlaybookError(f"steps[{i}].atomic must be object|null|false")
        if atomic.get("test_number") is None:
            raise PlaybookError(f"steps[{i}].atomic.test_number required when atomic set")
        tech = atomic.get("technique") or step.get("technique")
        if not tech:
            raise PlaybookError(f"steps[{i}].atomic needs technique")


def bind_manifest(
    manifest: Mapping[str, Any],
    *,
    allow_unlisted: bool = False,
) -> Dict[str, Any]:
    """Expand a breaktest (or partial) manifesto into an atomic playbook.

    Steps without a curated binding get ``atomic: null`` and a gap entry.
    """
    out = copy.deepcopy(dict(manifest))
    out["schema_ver"] = PLAYBOOK_SCHEMA_VER
    out["mode"] = "atomic"
    out["purpose"] = "lab_ttp_replay"
    out["honesty"] = (
        "Lab purple-team only. Does not vendor Atomic scripts. "
        "Does not flip claim_allowed. Authorized lab hosts only."
    )
    source = dict(out.get("source") or {})
    source["style"] = (
        "Atomic Red Team / ATT&CK technique replay (orchestrated, not vendored)"
    )
    source.setdefault("repo", "https://github.com/redcanaryco/atomic-red-team")
    source["note"] = (
        "No Atomic scripts are vendored. Steps bind to Invoke-AtomicTest by "
        "technique + test_number; operator must install ART locally."
    )
    out["source"] = source

    gaps: List[str] = list(out.get("atomic_gaps") or [])
    new_steps: List[Dict[str, Any]] = []
    for i, step in enumerate(out.get("steps") or []):
        st = dict(step)
        tech = normalize_technique(st.get("technique") or (st.get("atomic") or {}).get("technique"))
        existing = st.get("atomic")
        if existing is False:
            st["atomic"] = None
            gaps.append(f"steps[{i}] host={st.get('host')}: explicitly unbound")
            new_steps.append(st)
            continue

        if isinstance(existing, Mapping) and existing.get("test_number") is not None:
            # Explicit pin — keep, fill technique if missing
            merged = merge_atomic_override(tech or existing.get("technique"), existing)
            if merged is None:
                st["atomic"] = None
                gaps.append(f"steps[{i}] host={st.get('host')}: incomplete atomic pin")
            else:
                if not is_curated(merged.get("technique")) and not allow_unlisted:
                    gaps.append(
                        f"steps[{i}] technique={merged.get('technique')}: "
                        "unlisted — kept because test_number pinned; pass "
                        "--allow-unlisted on atomic-run to execute"
                    )
                st["atomic"] = merged
            new_steps.append(st)
            continue

        if not is_curated(tech) and not allow_unlisted:
            st["atomic"] = None
            gaps.append(
                f"steps[{i}] host={st.get('host')} technique={tech or '?'}: "
                "no curated binding"
            )
            new_steps.append(st)
            continue

        merged = merge_atomic_override(tech, existing if isinstance(existing, Mapping) else None)
        if merged is None:
            st["atomic"] = None
            gaps.append(
                f"steps[{i}] host={st.get('host')} technique={tech or '?'}: "
                "could not bind"
            )
        else:
            st["atomic"] = merged
            if tech and not st.get("technique"):
                st["technique"] = tech
        new_steps.append(st)

    out["steps"] = new_steps
    out["atomic_gaps"] = gaps
    bound = sum(1 for s in new_steps if isinstance(s.get("atomic"), Mapping))
    out["atomic_bound_count"] = bound
    return out


def steps_for_role(
    playbook: Mapping[str, Any],
    role: str,
) -> List[Dict[str, Any]]:
    """Return steps whose host matches role (exact string)."""
    role = str(role)
    out: List[Dict[str, Any]] = []
    for step in playbook.get("steps") or []:
        if str(step.get("host") or "") == role:
            out.append(dict(step))
    return out


def bound_atomic_steps(steps: Sequence[Mapping[str, Any]]) -> List[Dict[str, Any]]:
    return [
        dict(s)
        for s in steps
        if isinstance(s.get("atomic"), Mapping) and s["atomic"].get("test_number") is not None
    ]


def write_playbook(path: Path, playbook: Mapping[str, Any]) -> Path:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(playbook, indent=2) + "\n", encoding="utf-8")
    return path
