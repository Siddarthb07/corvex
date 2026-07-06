"""Stage D Contain — gated behind Security L1 checklist 100%. No live executors until then."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

# contain/__init__.py → package → repo root
REPO_ROOT = Path(__file__).resolve().parents[2]
STATE_PATH = REPO_ROOT / "reports" / "security_l1_checklist.json"

L1_ITEMS = [
    "mtls_identities",
    "typed_commands",
    "authz_neq_sig",
    "anti_replay",
    "dual_control",
    "fail_closed",
    "least_privilege",
    "immutable_audit",
    "oversight_off_data_plane",
    "no_free_form_shell",
    "blast_radius_caps",
]


class ContainGateError(RuntimeError):
    pass


def checklist_file(root: Optional[Path] = None) -> Path:
    return (Path(root) if root else REPO_ROOT) / "reports" / "security_l1_checklist.json"


def load_checklist_raw(root: Optional[Path] = None) -> Dict[str, Any]:
    path = checklist_file(root)
    if path.exists():
        return json.loads(path.read_text(encoding="utf-8"))
    return {k: False for k in L1_ITEMS}


def load_checklist_state(root: Optional[Path] = None) -> Dict[str, bool]:
    raw = load_checklist_raw(root)
    return {k: bool(raw.get(k)) for k in L1_ITEMS}


def set_checklist_item(
    key: str,
    enabled: bool,
    *,
    root: Optional[Path] = None,
    source: str = "dashboard",
) -> Dict[str, bool]:
    """Flip one L1 control and persist. Does not unlock live contain by itself."""
    if key not in L1_ITEMS:
        raise ValueError(f"unknown checklist key: {key}")
    path = checklist_file(root)
    path.parent.mkdir(parents=True, exist_ok=True)
    raw = load_checklist_raw(root)
    raw[key] = bool(enabled)
    meta = raw.get("_meta") if isinstance(raw.get("_meta"), dict) else {}
    notes = meta.get("evidence_notes") if isinstance(meta.get("evidence_notes"), dict) else {}
    stamp = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    if enabled:
        notes[key] = f"SET VIA {source.upper()} @ {stamp} — not a formal attestation."
    else:
        notes[key] = f"CLEARED VIA {source.upper()} @ {stamp}."
    meta["evidence_notes"] = notes
    meta["last_dashboard_edit"] = stamp
    meta.setdefault("policy", "All items default false. Do not flip true without evidence.")
    meta.setdefault("live_contain_unlocked", False)
    raw["_meta"] = meta
    # Keep stable key order: L1 items then _meta
    ordered: Dict[str, Any] = {k: bool(raw.get(k)) for k in L1_ITEMS}
    ordered["_meta"] = raw["_meta"]
    path.write_text(json.dumps(ordered, indent=2) + "\n", encoding="utf-8")
    return load_checklist_state(root)


def checklist_complete(state: Optional[Dict[str, bool]] = None, root: Optional[Path] = None) -> bool:
    st = state if state is not None else load_checklist_state(root)
    return all(bool(st.get(k)) for k in L1_ITEMS)


def require_contain(root: Optional[Path] = None) -> None:
    if not checklist_complete(root=root):
        missing = [k for k in L1_ITEMS if not load_checklist_state(root).get(k)]
        raise ContainGateError(
            "Stage D Contain locked until Security L1 checklist 100%. Missing: "
            + ", ".join(missing)
        )


def contain_status(root: Optional[Path] = None) -> dict:
    st = load_checklist_state(root)
    done = sum(1 for k in L1_ITEMS if st.get(k))
    return {
        "complete": checklist_complete(st, root=root),
        "items": st,
        "pct": 100.0 * done / len(L1_ITEMS),
        "live_executor": False,
        "dry_run_available": True,
    }


ALLOWED_COMMAND_TYPES: List[str] = []
