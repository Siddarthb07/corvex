"""Attack reconstruction — honesty-first timeline rebuild from campaigns.

Never invent CVE, malware names, or missing hops. If evidence is thin,
status is ``insufficient_evidence`` or ``partial`` with explicit gaps.
Reconstruction exports (manifest / pack) are for **lab regression**, not
operator attack playbooks.
"""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Mapping, Optional, Sequence

from corvex.store import Campaign

# Detector / stage name → MITRE ATT&CK technique IDs (coarse, labeled unverified).
STAGE_ATTACK: Dict[str, List[str]] = {
    "lateral_auth": ["T1078", "T1021"],
    "micro_exfil": ["T1041"],
    "recon_fanout": ["T1046"],
    "auth": ["T1078"],
    "exfil": ["T1041"],
    "recon": ["T1046"],
    "lateral": ["T1021"],
    "local_noise": [],
}

MIN_HOSTS_FOR_COMPLETE = 2
MIN_STAGES_FOR_COMPLETE = 1
MIN_EVIDENCE_FOR_COMPLETE = 1


@dataclass
class ReconstructionStep:
    order: int
    name: str
    hosts: List[str]
    attack_techniques: List[str]
    confidence: float
    verified: bool
    note: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class QuarantinePlan:
    """Proposed IsolateHost targets — not a claim that live quarantine ran."""

    verb: str
    host_ids: List[str]
    cut_point_host: Optional[str]
    rationale: str
    mode: str  # dry_run | lab_flag | blocked
    honesty: str

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class Reconstruction:
    schema_ver: str
    status: str  # complete | partial | insufficient_evidence | empty
    confidence: float
    campaign_id: Optional[str]
    host_ids: List[str]
    steps: List[ReconstructionStep]
    gaps: List[str]
    hypotheses: List[str]
    quarantine: Optional[QuarantinePlan]
    honesty: List[str]
    compared_to_truth: Optional[Dict[str, Any]] = None
    generated_at: str = field(
        default_factory=lambda: datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    )

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        return d

    def to_manifest(self) -> Dict[str, Any]:
        """Regression export shaped like break-test / ART manifests (not weaponized)."""
        steps_out: List[Dict[str, Any]] = []
        for st in self.steps:
            for host in st.hosts:
                steps_out.append(
                    {
                        "kind": _stage_to_kind(st.name),
                        "host": host,
                        "technique": (st.attack_techniques[0] if st.attack_techniques else None),
                        "verified": st.verified,
                        "note": "reconstructed — not an attack recipe",
                    }
                )
        return {
            "schema_ver": "1",
            "name": f"recon-{self.campaign_id or 'unknown'}",
            "purpose": "regression_only",
            "source": "corvex.reconstruct",
            "honesty": "Do not treat as a red-team playbook. Gaps omitted are unknown.",
            "status": self.status,
            "hosts": list(self.host_ids),
            "steps": steps_out,
            "gaps": list(self.gaps),
        }

    def to_pack_ground_truth(self) -> Dict[str, Any]:
        """Ground-truth-shaped dict for sealed-pack round-trip scoring."""
        return {
            "campaign_id": self.campaign_id or "recon-unknown",
            "host_ids": list(self.host_ids),
            "stages": [
                {"name": s.name, "hosts": list(s.hosts)} for s in self.steps if s.verified
            ],
            "family": "reconstructed",
            "reconstruction_status": self.status,
            "gaps": list(self.gaps),
        }


def _stage_to_kind(name: str) -> str:
    if name in ("lateral_auth", "auth", "lateral"):
        return "auth"
    if name in ("micro_exfil", "exfil"):
        return "exfil"
    if name in ("recon_fanout", "recon"):
        return "recon"
    return "unknown"


def _techniques_for(stage_name: str) -> List[str]:
    return list(STAGE_ATTACK.get(stage_name, []))


def _jaccard(a: Sequence[str], b: Sequence[str]) -> float:
    sa, sb = set(a), set(b)
    if not sa and not sb:
        return 1.0
    if not sa or not sb:
        return 0.0
    return len(sa & sb) / len(sa | sb)


def compare_to_truth(
    reconstructed_hosts: Sequence[str],
    reconstructed_stages: Sequence[str],
    ground_truth: Mapping[str, Any],
) -> Dict[str, Any]:
    """Honest overlap vs pack ground truth when present."""
    truth_hosts = list(ground_truth.get("host_ids") or ground_truth.get("hosts") or [])
    truth_stages = [
        str(s.get("name") or s.get("stage") or "")
        for s in (ground_truth.get("stages") or [])
        if isinstance(s, Mapping)
    ]
    host_j = _jaccard(reconstructed_hosts, truth_hosts)
    stage_j = _jaccard(reconstructed_stages, [t for t in truth_stages if t])
    missing_hosts = sorted(set(truth_hosts) - set(reconstructed_hosts))
    extra_hosts = sorted(set(reconstructed_hosts) - set(truth_hosts))
    notes: List[str] = []
    if missing_hosts:
        notes.append(f"missed truth hosts: {', '.join(missing_hosts)}")
    if extra_hosts:
        notes.append(f"extra hosts not in truth: {', '.join(extra_hosts)}")
    if host_j < 0.99 or stage_j < 0.99:
        notes.append("reconstruction does not fully match ground truth — do not overclaim")
    return {
        "host_jaccard": round(host_j, 4),
        "stage_jaccard": round(stage_j, 4),
        "missing_hosts": missing_hosts,
        "extra_hosts": extra_hosts,
        "notes": notes,
        "full_match": host_j >= 0.99 and stage_j >= 0.99,
    }


def quarantine_plan_for(
    host_ids: Sequence[str],
    *,
    steps: Sequence[ReconstructionStep],
    mode: str,
) -> QuarantinePlan:
    hosts = list(host_ids)
    cut: Optional[str] = None
    if len(hosts) >= 2:
        # Prefer second host in first multi-host stage as mid-chain cut.
        for st in steps:
            if len(st.hosts) >= 2:
                cut = st.hosts[1]
                break
        if cut is None:
            cut = hosts[1]
    if mode == "lab_flag":
        honesty = (
            "Lab sandbox only: isolate writes a flag file that virtual hosts honor. "
            "Not OS firewall / EDR / VLAN quarantine."
        )
    elif mode == "dry_run":
        honesty = (
            "Dry-run IsolateHost proposals only. Live quarantine executor is not armed "
            "(CORVEX_CONTAIN=0 until L1 checklist + hostile-bus tests)."
        )
    else:
        honesty = (
            "Cannot quarantine real hosts: live contain blocked. "
            "Refusing to pretend isolation succeeded."
        )
    return QuarantinePlan(
        verb="IsolateHost",
        host_ids=hosts,
        cut_point_host=cut,
        rationale=(
            f"Propose IsolateHost on campaign hosts"
            + (f"; mid-chain cut at {cut}" if cut else "")
        ),
        mode=mode,
        honesty=honesty,
    )


def reconstruct_campaign(
    campaign: Campaign | Mapping[str, Any],
    *,
    ground_truth: Optional[Mapping[str, Any]] = None,
    quarantine_mode: str = "dry_run",
) -> Reconstruction:
    if isinstance(campaign, Campaign):
        cid = campaign.campaign_id
        hosts = list(campaign.host_ids)
        stages = list(campaign.stages)
        evidence = list(campaign.evidence)
        score = float(campaign.score)
    else:
        cid = str(campaign.get("campaign_id") or "")
        hosts = list(campaign.get("host_ids") or [])
        stages = list(campaign.get("stages") or [])
        evidence = list(campaign.get("evidence") or [])
        score = float(campaign.get("score") or 0.0)

    honesty: List[str] = [
        "ATT&CK tags are coarse mappings from detector stage names — unverified hypotheses.",
        "No CVE, malware family, or initial-access vector is inferred from correlator output alone.",
        "Gaps listed below are unknown; they are not filled with guesses.",
    ]
    gaps: List[str] = []
    hypotheses: List[str] = []

    if not hosts and not stages and not evidence:
        return Reconstruction(
            schema_ver="1",
            status="empty",
            confidence=0.0,
            campaign_id=cid or None,
            host_ids=[],
            steps=[],
            gaps=["no campaign hosts, stages, or evidence"],
            hypotheses=[],
            quarantine=None,
            honesty=honesty
            + ["Cannot rebuild: empty campaign — refusing to invent a timeline."],
        )

    steps: List[ReconstructionStep] = []
    for i, st in enumerate(stages):
        if not isinstance(st, Mapping):
            gaps.append(f"stage[{i}] is not a mapping — skipped")
            continue
        name = str(st.get("name") or st.get("stage") or "unknown")
        st_hosts = list(st.get("hosts") or hosts)
        techniques = _techniques_for(name)
        verified = name != "unknown" and bool(st_hosts)
        conf = min(1.0, 0.35 + 0.25 * score + (0.2 if verified else 0.0))
        note = ""
        if not techniques:
            note = "no ATT&CK mapping for this stage name"
            gaps.append(f"unmapped stage '{name}'")
        else:
            hypotheses.append(
                f"{name} → {', '.join(techniques)} (unverified; from stage name only)"
            )
        steps.append(
            ReconstructionStep(
                order=i + 1,
                name=name,
                hosts=st_hosts,
                attack_techniques=techniques,
                confidence=round(conf, 3),
                verified=verified,
                note=note,
            )
        )

    if not steps and evidence:
        # Fall back: group evidence kinds into steps — still honest about thinness.
        by_kind: Dict[str, List[str]] = {}
        for ev in evidence:
            if not isinstance(ev, Mapping):
                continue
            kind = str(ev.get("kind") or "unknown")
            hid = str(ev.get("host_id") or "")
            by_kind.setdefault(kind, [])
            if hid and hid not in by_kind[kind]:
                by_kind[kind].append(hid)
        for i, (kind, khosts) in enumerate(by_kind.items()):
            techniques = _techniques_for(kind)
            steps.append(
                ReconstructionStep(
                    order=i + 1,
                    name=kind,
                    hosts=khosts or list(hosts),
                    attack_techniques=techniques,
                    confidence=round(min(0.55, 0.3 + 0.2 * score), 3),
                    verified=False,
                    note="derived from evidence only — stage list was empty",
                )
            )
        gaps.append("stages empty; steps inferred from evidence kinds only")

    if len(hosts) < MIN_HOSTS_FOR_COMPLETE:
        gaps.append(
            f"fewer than {MIN_HOSTS_FOR_COMPLETE} hosts — cannot claim multi-host campaign rebuild"
        )
    if len(steps) < MIN_STAGES_FOR_COMPLETE:
        gaps.append("no reconstructable stages")
    if len(evidence) < MIN_EVIDENCE_FOR_COMPLETE and not steps:
        gaps.append("insufficient evidence records")

    # Ordering honesty: correlator stages are not a proven kill-chain chronology.
    if len(steps) >= 2:
        hypotheses.append(
            "Step order follows correlator stage list, not proven kill-chain chronology"
        )

    compared = None
    if ground_truth:
        compared = compare_to_truth(
            hosts,
            [s.name for s in steps],
            ground_truth,
        )
        gaps.extend(compared.get("notes") or [])

    # Status decision — refuse "complete" when gaps or thin evidence.
    if not hosts or (not steps and not evidence):
        status = "insufficient_evidence"
        confidence = 0.0
        honesty.append(
            "INSUFFICIENT EVIDENCE: cannot rebuild this attack. Reporting failure honestly."
        )
    elif gaps or len(hosts) < MIN_HOSTS_FOR_COMPLETE or any(not s.verified for s in steps):
        status = "partial"
        confidence = round(min(0.75, 0.25 + 0.15 * len(steps) + 0.1 * len(hosts)), 3)
        honesty.append(
            "PARTIAL rebuild only — gaps remain. Do not present this as a full attack reconstruction."
        )
    elif compared is not None and not compared.get("full_match"):
        status = "partial"
        confidence = round(min(0.8, 0.4 + 0.3 * float(compared.get("host_jaccard") or 0)), 3)
        honesty.append("Compared to ground truth: not a full match.")
    else:
        status = "complete"
        confidence = round(min(0.95, 0.55 + 0.1 * len(steps) + 0.05 * len(hosts)), 3)
        honesty.append(
            "Complete relative to correlator output only — not proof of full attacker TTPs."
        )

    qplan = None
    if hosts and status != "empty":
        qplan = quarantine_plan_for(hosts, steps=steps, mode=quarantine_mode)

    if status == "insufficient_evidence":
        qplan = None  # do not propose isolate on garbage

    return Reconstruction(
        schema_ver="1",
        status=status,
        confidence=confidence,
        campaign_id=cid or None,
        host_ids=hosts,
        steps=steps,
        gaps=gaps,
        hypotheses=hypotheses,
        quarantine=qplan,
        honesty=honesty,
        compared_to_truth=compared,
    )


def reconstruct_timeline(
    timeline: Mapping[str, Any],
    *,
    quarantine_mode: str = "dry_run",
) -> Dict[str, Any]:
    """Rebuild every campaign in a timeline.json; aggregate honesty."""
    campaigns = list(timeline.get("campaigns") or [])
    gt = timeline.get("ground_truth")
    # Pack GT may be a single object or list
    gt_single: Optional[Mapping[str, Any]] = None
    if isinstance(gt, Mapping):
        gt_single = gt
    elif isinstance(gt, list) and gt and isinstance(gt[0], Mapping):
        gt_single = gt[0]

    results: List[Dict[str, Any]] = []
    for camp in campaigns:
        if not isinstance(camp, Mapping):
            continue
        rec = reconstruct_campaign(
            camp, ground_truth=gt_single, quarantine_mode=quarantine_mode
        )
        results.append(rec.to_dict())

    statuses = [r["status"] for r in results]
    if not results:
        aggregate = "empty"
        summary = "No campaigns to rebuild."
    elif all(s == "complete" for s in statuses):
        aggregate = "complete"
        summary = f"Rebuilt {len(results)} campaign(s) from correlator output (correlator-complete only)."
    elif any(s == "insufficient_evidence" for s in statuses) and not any(
        s in ("complete", "partial") for s in statuses
    ):
        aggregate = "insufficient_evidence"
        summary = "Cannot rebuild: insufficient evidence on all campaigns."
    else:
        aggregate = "partial"
        summary = (
            f"Partial: {statuses.count('complete')} complete, "
            f"{statuses.count('partial')} partial, "
            f"{statuses.count('insufficient_evidence')} insufficient, "
            f"{statuses.count('empty')} empty — gaps are listed per campaign."
        )

    return {
        "schema_ver": "1",
        "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "pack": timeline.get("pack"),
        "aggregate_status": aggregate,
        "summary": summary,
        "campaign_reconstructions": results,
        "honesty": [
            "Reconstruction is a read-only honesty / regression plane.",
            "Exports (to_manifest / to_pack) are for scoring known labs — not attack kits.",
            summary,
        ],
    }


def write_reconstruction(run_dir: Path, *, quarantine_mode: str = "dry_run") -> Path:
    run_dir = Path(run_dir)
    path = run_dir / "timeline.json"
    if not path.exists():
        raise FileNotFoundError(f"missing {path}")
    timeline = json.loads(path.read_text(encoding="utf-8"))
    report = reconstruct_timeline(timeline, quarantine_mode=quarantine_mode)
    out = run_dir / "reconstruction.json"
    out.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    # Also write per-campaign manifests for regression
    man_dir = run_dir / "reconstruction_manifests"
    man_dir.mkdir(parents=True, exist_ok=True)
    for item in report.get("campaign_reconstructions") or []:
        rec = Reconstruction(
            schema_ver=item.get("schema_ver", "1"),
            status=item["status"],
            confidence=float(item.get("confidence") or 0),
            campaign_id=item.get("campaign_id"),
            host_ids=list(item.get("host_ids") or []),
            steps=[
                ReconstructionStep(**s) if isinstance(s, dict) else s
                for s in (item.get("steps") or [])
            ],
            gaps=list(item.get("gaps") or []),
            hypotheses=list(item.get("hypotheses") or []),
            quarantine=(
                QuarantinePlan(**item["quarantine"])
                if isinstance(item.get("quarantine"), dict)
                else None
            ),
            honesty=list(item.get("honesty") or []),
            compared_to_truth=item.get("compared_to_truth"),
            generated_at=item.get("generated_at")
            or datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        )
        cid = rec.campaign_id or "unknown"
        safe = "".join(c if c.isalnum() or c in "-_" else "_" for c in cid)
        (man_dir / f"{safe}.json").write_text(
            json.dumps(rec.to_manifest(), indent=2) + "\n", encoding="utf-8"
        )
    return out
