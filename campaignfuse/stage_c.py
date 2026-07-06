"""Stage C OSS gates — no destructive Action *executors* in public package; retention helper."""

from __future__ import annotations

import ast
import json
from pathlib import Path
from typing import List, Optional

ROOT = Path(__file__).resolve().parents[1]

# Executor-shaped names we refuse to ship as callables in the installable package.
_EXECUTOR_NAMES = {
    "isolate_host",
    "kill_pid",
    "kill_process",
    "add_firewall_rule",
    "execute_contain",
    "run_contain",
}


def find_destructive_verbs_in_package(package_root: Optional[Path] = None) -> List[str]:
    """Return hits for FunctionDef/ClassDef names that look like live contain executors."""
    root = Path(package_root) if package_root else (ROOT / "campaignfuse")
    hits: List[str] = []
    for path in root.rglob("*.py"):
        try:
            tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        except SyntaxError:
            continue
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                if node.name.lower() in _EXECUTOR_NAMES:
                    hits.append(f"{path}:{node.name}")
    return hits


def retention_status(labs_runs_path: Optional[Path] = None) -> dict:
    path = labs_runs_path or (ROOT / "reports" / "oss_retention.json")
    if not path.exists():
        return {"met": False, "labs": 0, "reason": "no retention log — stay private"}
    data = json.loads(path.read_text(encoding="utf-8"))
    labs = data.get("labs") or []
    qualified = [lab for lab in labs if int(lab.get("unprompted_runs", 0)) >= 2]
    return {
        "met": len(qualified) >= 3,
        "labs": len(qualified),
        "required_labs": 3,
        "required_runs_each": 2,
    }


def stage_c_ready() -> dict:
    verbs = find_destructive_verbs_in_package()
    ret = retention_status()
    return {
        "no_destructive_verbs": verbs == [],
        "destructive_hits": verbs,
        "retention": ret,
        "ready_for_public": verbs == [] and ret["met"],
    }
