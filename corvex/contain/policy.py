"""Scale-invariant contain policy — SOC allowlist, blast caps, FP gates.

Config lives at ``~/.corvex/contain_policy.json`` (or ``CORVEX_CONTAIN_POLICY``).
Defaults are conservative: no auto-enforce, dual-control for multi-host / estate.
"""

from __future__ import annotations

import json
import os
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Mapping, Optional, Sequence, Set


DEFAULT_POLICY_PATH = Path.home() / ".corvex" / "contain_policy.json"


@dataclass
class ContainPolicy:
    schema_ver: str = "1"
    soc_allowlist: List[str] = field(default_factory=list)
    auto_enforce: bool = False
    require_dual_control_multi_host: bool = True
    require_dual_control_estate: bool = True
    confidence_floor: float = 0.55
    max_isolate_fp_per_host_hour: float = 0.001
    estate_lockdown_on_benign_is_fail: bool = True
    blast_radius_max_pct: Dict[str, float] = field(
        default_factory=lambda: {
            "observe": 0.0,
            "low": 25.0,
            "medium": 50.0,
            "critical": 100.0,
        }
    )
    severity_weights: Dict[str, float] = field(
        default_factory=lambda: {
            "host_frac": 0.25,
            "stage_diversity": 0.15,
            "exfil": 0.20,
            "dns_c2": 0.15,
            "lateral": 0.10,
            "confidence": 0.10,
            "pace": 0.05,
        }
    )
    # Absolute pace triggers (work at any N)
    critical_min_hosts: int = 5
    critical_max_minutes: float = 30.0
    critical_score: float = 0.75
    medium_score: float = 0.45
    low_score: float = 0.25
    # Peer-risk neighborhood expansion for medium
    peer_risk_enabled: bool = True

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, raw: Mapping[str, Any]) -> "ContainPolicy":
        base = cls()
        data = asdict(base)
        for k, v in raw.items():
            if k in data and k != "schema_ver":
                data[k] = v
        data["schema_ver"] = str(raw.get("schema_ver") or base.schema_ver)
        return cls(**data)


def policy_path(explicit: Optional[Path] = None) -> Path:
    if explicit is not None:
        return Path(explicit)
    env = os.environ.get("CORVEX_CONTAIN_POLICY", "").strip()
    if env:
        return Path(env)
    return DEFAULT_POLICY_PATH


class PolicyLoadError(RuntimeError):
    """Corrupt contain policy — callers must fail closed on enforce."""


def load_policy(path: Optional[Path] = None, *, strict: bool = False) -> ContainPolicy:
    p = policy_path(path)
    if not p.is_file():
        return ContainPolicy()
    try:
        raw = json.loads(p.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        if strict:
            raise PolicyLoadError(f"corrupt contain policy at {p}: {exc}") from exc
        # Non-strict: empty default — dash/severity still work; enforce paths
        # should pass strict=True.
        return ContainPolicy()
    if not isinstance(raw, dict):
        if strict:
            raise PolicyLoadError(f"contain policy at {p} is not an object")
        return ContainPolicy()
    try:
        return ContainPolicy.from_dict(raw)
    except (TypeError, ValueError) as exc:
        if strict:
            raise PolicyLoadError(str(exc)) from exc
        return ContainPolicy()


def save_policy(policy: ContainPolicy, path: Optional[Path] = None) -> Path:
    p = policy_path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(policy.to_dict(), indent=2) + "\n", encoding="utf-8")
    return p


def soc_set(policy: ContainPolicy) -> Set[str]:
    return {str(h).strip().lower() for h in (policy.soc_allowlist or []) if str(h).strip()}


def filter_soc(hosts: Sequence[str], policy: ContainPolicy) -> List[str]:
    blocked = soc_set(policy)
    # Preserve original casing in output; compare casefold.
    return [str(h) for h in hosts if str(h).strip().lower() not in blocked]


def enforce_blast_cap(
    targets: Sequence[str],
    *,
    estate_n: int,
    band: str,
    policy: ContainPolicy,
) -> Dict[str, Any]:
    """Trim or refuse targets that exceed the band's max % of estate."""
    n = max(1, int(estate_n))
    pct = float((policy.blast_radius_max_pct or {}).get(band, 0.0))
    if band == "critical":
        # Critical may take 100% minus SOC — SOC already filtered by caller.
        max_hosts = n if pct >= 100.0 else max(0, int(n * pct / 100.0))
    elif pct <= 0:
        max_hosts = 0
    else:
        # Floor would refuse the only host on N=1 (25% of 1 → 0). Keep at least
        # one slot whenever the band allows a nonzero percentage.
        max_hosts = max(1, int(n * pct / 100.0))
    hosts = [str(h) for h in targets]
    if len(hosts) <= max_hosts:
        return {
            "ok": True,
            "targets": hosts,
            "capped": False,
            "max_hosts": max_hosts,
            "pct_of_n": round(100.0 * len(hosts) / n, 2),
        }
    if band == "critical" and pct >= 100.0:
        return {
            "ok": True,
            "targets": hosts,
            "capped": False,
            "max_hosts": max_hosts,
            "pct_of_n": round(100.0 * len(hosts) / n, 2),
        }
    return {
        "ok": False,
        "targets": hosts[:max_hosts],
        "capped": True,
        "refused": True,
        "max_hosts": max_hosts,
        "pct_of_n": round(100.0 * len(hosts) / n, 2),
        "honesty": (
            f"Blast radius refuse: {len(hosts)} hosts exceeds {pct}% of estate N={n} "
            f"(max {max_hosts}) for band={band}."
        ),
    }


def needs_dual_control(
    targets: Sequence[str],
    *,
    scope: str,
    policy: ContainPolicy,
) -> bool:
    if scope == "estate_lockdown" and policy.require_dual_control_estate:
        return True
    if len(targets) > 1 and policy.require_dual_control_multi_host:
        return True
    return False
