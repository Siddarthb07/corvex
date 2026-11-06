"""Scale-invariant campaign severity → isolate scope.

Works for any estate size N. Absolute pace triggers (e.g. 5 hosts in 30 min)
can escalate to estate_lockdown even when host_frac is small.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, List, Mapping, Optional, Sequence, Set

from corvex.contain.policy import (
    ContainPolicy,
    enforce_blast_cap,
    filter_soc,
    load_policy,
    needs_dual_control,
    soc_set,
)

EGRESS = frozenset({"micro_exfil", "dns_beacon", "exfil"})
DNS = frozenset({"dns_beacon"})
LATERAL = frozenset({"lateral_auth", "lateral", "auth"})
RECON = frozenset({"recon_fanout", "recon"})


def _stage_names(stages: Sequence[Mapping[str, Any]]) -> Set[str]:
    out: Set[str] = set()
    for st in stages or []:
        out.add(str(st.get("name") or st.get("stage") or ""))
    return out


def _parse_ts(raw: Any) -> Optional[datetime]:
    if raw is None:
        return None
    if isinstance(raw, (int, float)):
        return datetime.fromtimestamp(float(raw), tz=timezone.utc)
    s = str(raw).strip()
    if not s:
        return None
    try:
        if s.endswith("Z"):
            s = s[:-1] + "+00:00"
        return datetime.fromisoformat(s)
    except ValueError:
        return None


def score_campaign(
    campaign: Mapping[str, Any],
    *,
    estate_n: int,
    policy: Optional[ContainPolicy] = None,
) -> Dict[str, Any]:
    """Return severity score in [0,1] plus feature breakdown."""
    pol = policy or load_policy()
    n = max(1, int(estate_n))
    hosts = [str(h) for h in (campaign.get("host_ids") or campaign.get("hosts") or [])]
    stages = list(campaign.get("stages") or [])
    names = _stage_names(stages)
    conf = float(campaign.get("score") or campaign.get("confidence") or 0.0)
    if conf > 1.0:
        conf = conf / 100.0
    conf = max(0.0, min(1.0, conf))

    host_frac = len(set(hosts)) / n
    stage_div = min(1.0, len(names) / 4.0)
    has_exfil = 1.0 if names & (EGRESS - DNS) else 0.0
    has_dns = 1.0 if names & DNS else 0.0
    has_lat = 1.0 if names & LATERAL else 0.0

    # Pace: span of stage host activity if timestamps present on campaign
    t0 = _parse_ts(campaign.get("first_seen") or campaign.get("t0") or campaign.get("start_ts"))
    t1 = _parse_ts(campaign.get("last_seen") or campaign.get("t1") or campaign.get("end_ts"))
    minutes = None
    pace = 0.0
    if t0 and t1 and t1 >= t0:
        minutes = max(0.01, (t1 - t0).total_seconds() / 60.0)
        # Fast multi-host → high pace
        if len(hosts) >= 2 and minutes <= float(pol.critical_max_minutes):
            pace = min(1.0, (len(hosts) / max(1.0, minutes)) / 2.0)
        elif minutes > 0:
            pace = min(1.0, len(hosts) / max(minutes, 1.0) / 5.0)

    w = pol.severity_weights or {}
    score = (
        float(w.get("host_frac", 0.25)) * host_frac
        + float(w.get("stage_diversity", 0.15)) * stage_div
        + float(w.get("exfil", 0.20)) * has_exfil
        + float(w.get("dns_c2", 0.15)) * has_dns
        + float(w.get("lateral", 0.10)) * has_lat
        + float(w.get("confidence", 0.10)) * conf
        + float(w.get("pace", 0.05)) * pace
    )
    score = max(0.0, min(1.0, score))

    # Absolute critical escalate: enough hosts in a short window
    absolute_critical = bool(
        len(set(hosts)) >= int(pol.critical_min_hosts)
        and minutes is not None
        and minutes <= float(pol.critical_max_minutes)
        and (has_exfil > 0 or has_dns > 0 or (has_lat > 0 and stage_div >= 0.5))
    )

    return {
        "score": round(score, 4),
        "features": {
            "host_count": len(set(hosts)),
            "estate_n": n,
            "host_frac": round(host_frac, 4),
            "stage_diversity": round(stage_div, 4),
            "exfil": bool(has_exfil),
            "dns_c2": bool(has_dns),
            "lateral": bool(has_lat),
            "confidence": conf,
            "span_minutes": minutes,
            "pace": round(pace, 4),
            "absolute_critical": absolute_critical,
        },
    }


def band_for_score(score: float, *, absolute_critical: bool, policy: ContainPolicy) -> str:
    if absolute_critical or score >= float(policy.critical_score):
        return "critical"
    if score >= float(policy.medium_score):
        return "medium"
    if score >= float(policy.low_score):
        return "low"
    return "observe"


def peer_risk_hosts(
    campaign: Mapping[str, Any],
    *,
    all_enrolled: Sequence[str],
) -> List[str]:
    """Neighborhood expansion: hosts sharing stage user/egress keys in the campaign graph.

    Without a full estate graph we approximate peer-risk as flagged hosts only
    plus any hosts listed inside stage payloads — never the whole estate.
    """
    flagged = {str(h) for h in (campaign.get("host_ids") or campaign.get("hosts") or [])}
    peers = set(flagged)
    for st in campaign.get("stages") or []:
        for h in st.get("hosts") or []:
            peers.add(str(h))
    enrolled = {str(h) for h in all_enrolled}
    return sorted(peers & enrolled) if enrolled else sorted(peers)


def resolve_isolate_scope(
    campaign: Mapping[str, Any],
    *,
    estate_hosts: Sequence[str],
    policy: Optional[ContainPolicy] = None,
    peer_hosts: Optional[Sequence[str]] = None,
) -> Dict[str, Any]:
    """Map campaign → severity band + target host_ids (SOC stripped)."""
    pol = policy or load_policy()
    estate = [str(h) for h in estate_hosts]
    n = max(1, len(estate))
    scored = score_campaign(campaign, estate_n=n, policy=pol)
    feats = scored["features"]
    band = band_for_score(
        float(scored["score"]),
        absolute_critical=bool(feats.get("absolute_critical")),
        policy=pol,
    )
    flagged = [str(h) for h in (campaign.get("host_ids") or campaign.get("hosts") or [])]
    soc = soc_set(pol)

    if band == "observe":
        scope = "observe"
        targets: List[str] = []
        verb = "IsolateHost"
    elif band == "low":
        scope = "flagged"
        targets = filter_soc(flagged, pol)
        verb = "IsolateHost"
    elif band == "medium":
        scope = "peer_risk"
        neighborhood = list(peer_hosts) if peer_hosts is not None else peer_risk_hosts(
            campaign, all_enrolled=estate
        )
        if not pol.peer_risk_enabled:
            neighborhood = flagged
        targets = filter_soc(neighborhood, pol)
        verb = "IsolateHost"
    else:
        scope = "estate_lockdown"
        targets = filter_soc(estate, pol)
        verb = "EstateLockdown"

    blast = enforce_blast_cap(targets, estate_n=n, band=band, policy=pol)
    final_targets = list(blast.get("targets") or [])
    conf = float(feats.get("confidence") or 0.0)
    fp_gate_ok = conf >= float(pol.confidence_floor) or band == "observe"
    if band != "observe" and not (set(_stage_names(campaign.get("stages") or [])) & (EGRESS | RECON | LATERAL)):
        fp_gate_ok = False

    dual = needs_dual_control(final_targets, scope=scope, policy=pol)
    propose = band != "observe" and fp_gate_ok and not blast.get("refused")
    auto = bool(pol.auto_enforce) and propose and not dual  # dual always blocks auto

    return {
        "severity": scored,
        "band": band,
        "scope": scope,
        "verb": verb,
        "targets": final_targets,
        "flagged": flagged,
        "soc_preserved": sorted(soc),
        "estate_n": n,
        "pct_of_n": blast.get("pct_of_n"),
        "blast": blast,
        "fp_gate_ok": fp_gate_ok,
        "propose": propose,
        "auto_enforce": auto,
        "requires_dual_control": dual,
        "honesty": [
            "Severity is scale-invariant in estate N; absolute pace can escalate to estate_lockdown.",
            "SOC allowlist hosts are never auto-isolated.",
            "auto_enforce defaults false; dual-control required for multi-host / estate.",
            "Windows Firewall enforce ≠ EDR/VLAN quarantine.",
        ]
        + ([str(blast["honesty"])] if blast.get("honesty") else []),
    }
