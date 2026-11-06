#!/usr/bin/env python3
"""Score IsolateHost / EstateLockdown *proposals* on pure-benign correlator output.

Uses ``severity.resolve_isolate_scope`` on campaigns from sealed held-out benign
packs when the local held-out key can open them, otherwise the plaintext train
benign packs (same feeder family). Does not execute containment and does not
change ``claim_allowed`` or ``CORVEX_CONTAIN``.

  python scripts/run_contain_fp_scoreboard.py

Writes ``reports/contain_fp_scoreboard.json`` and ``.md``.
Pure benign must have ``n_estate_lockdown_propose == 0``.
"""

from __future__ import annotations

import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Mapping, Sequence

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from corvex.audit import AuditLog  # noqa: E402
from corvex.contain.policy import ContainPolicy  # noqa: E402
from corvex.contain.severity import resolve_isolate_scope  # noqa: E402
from corvex.correlator import Correlator, CorrelatorConfig  # noqa: E402
from corvex.envelope import EventEnvelope  # noqa: E402
from corvex.feeder import load_pack_events, resign_events  # noqa: E402
from corvex.lab_enroll import ensure_lab_enrollment  # noqa: E402
from corvex.store import Campaign, CampaignStore  # noqa: E402

REPORT_JSON = ROOT / "reports" / "contain_fp_scoreboard.json"
REPORT_MD = ROOT / "reports" / "contain_fp_scoreboard.md"


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _unseal_benign(dest: Path) -> List[Path]:
    """Decrypt held-benign-*.jsonl.sealed when a key already exists.

    Does not call ``ensure_key`` (that would mint a new key and then fail).
    """
    from corvex.seal import key_path, unseal_file

    kp = key_path()
    if not kp.is_file():
        return []
    key = kp.read_bytes().strip()
    sealed = sorted((ROOT / "heldout").glob("held-benign-*.jsonl.sealed"))
    if not sealed:
        return []
    dest.mkdir(parents=True, exist_ok=True)
    out: List[Path] = []
    for path in sealed:
        plain = dest / path.name.replace(".sealed", "")
        try:
            plain.write_bytes(unseal_file(path, key))
        except Exception:
            return []
        out.append(plain)
    return out


def _train_benign() -> List[Path]:
    return sorted((ROOT / "train").glob("train-benign-*.jsonl"))


def _estate_hosts(events: Sequence[EventEnvelope]) -> List[str]:
    return sorted({str(ev.host_id) for ev in events if ev.host_id})


def _attach_window(camp: Mapping[str, Any], events: Sequence[EventEnvelope]) -> Dict[str, Any]:
    """Copy the campaign and stamp first/last seen from events on its hosts.

    ``Campaign`` does not store the cluster window. Pace / absolute-critical
    in ``resolve_isolate_scope`` needs those timestamps to be real.
    """
    payload = dict(camp)
    hosts = {str(h) for h in (payload.get("host_ids") or [])}
    stamps = [ev.ts_utc for ev in events if str(ev.host_id) in hosts and ev.ts_utc]
    if stamps:
        payload["first_seen"] = min(stamps)
        payload["last_seen"] = max(stamps)
    return payload


def _correlate(events: Sequence[EventEnvelope], run_dir: Path) -> List[Campaign]:
    if run_dir.exists():
        for child in run_dir.iterdir():
            if child.is_file():
                child.unlink()
    run_dir.mkdir(parents=True, exist_ok=True)
    store = CampaignStore(run_dir / "campaigns.jsonl")
    audit = AuditLog(run_dir / "audit.jsonl")
    corr = Correlator(
        store,
        audit,
        CorrelatorConfig(),
        enrollment=ensure_lab_enrollment(),
    )
    corr.ingest(list(events))
    return store.all()


def _score_pack(
    path: Path,
    *,
    policy: ContainPolicy,
    work: Path,
) -> Dict[str, Any]:
    events, gt = load_pack_events(path)
    family = str(gt.get("family") or "")
    enrollment = ensure_lab_enrollment()
    signed = resign_events(events, enrollment)
    camps = _correlate(signed, work / path.stem)
    estate = _estate_hosts(signed)
    rows: List[Dict[str, Any]] = []
    n_iso = 0
    n_estate = 0
    for camp in camps:
        payload = _attach_window(camp.to_dict(), signed)
        scope = resolve_isolate_scope(payload, estate_hosts=estate, policy=policy)
        propose = bool(scope.get("propose"))
        verb = str(scope.get("verb") or "")
        if propose and verb == "IsolateHost":
            n_iso += 1
        if propose and verb == "EstateLockdown":
            n_estate += 1
        rows.append(
            {
                "campaign_id": camp.campaign_id,
                "host_ids": list(camp.host_ids),
                "band": scope.get("band"),
                "verb": verb,
                "propose": propose,
                "scope": scope.get("scope"),
                "targets": scope.get("targets") or [],
                "fp_gate_ok": scope.get("fp_gate_ok"),
            }
        )
    return {
        "pack": path.name,
        "family": family,
        "n_events": len(signed),
        "n_hosts": len(estate),
        "estate_hosts": estate,
        "n_campaigns": len(camps),
        "n_isolate_propose": n_iso,
        "n_estate_lockdown_propose": n_estate,
        "campaigns": rows,
    }


def _render_md(report: Mapping[str, Any]) -> str:
    lines = [
        "# Contain FP scoreboard",
        "",
        "IsolateHost and EstateLockdown figures are **proposals** from "
        "`severity.resolve_isolate_scope`. Nothing was isolated.",
        "",
        f"- Generated: `{report.get('generated_at')}`",
        f"- Source: `{report.get('source')}`",
        f"- Packs: **{report.get('n_packs')}**",
        f"- Campaigns: **{report.get('n_campaigns')}**",
        f"- IsolateHost proposals: **{report.get('n_isolate_propose')}**",
        f"- EstateLockdown proposals: **{report.get('n_estate_lockdown_propose')}**",
        f"- Pure-benign estate bar: **{report.get('estate_lockdown_bar')}**",
        "",
        "## Packs",
        "",
        "| Pack | Family | Hosts | Campaigns | IsolateHost propose | EstateLockdown propose |",
        "|------|--------|-------|-----------|---------------------|------------------------|",
    ]
    for pack in report.get("packs") or []:
        lines.append(
            f"| `{pack.get('pack')}` | {pack.get('family')} | {pack.get('n_hosts')} | "
            f"{pack.get('n_campaigns')} | {pack.get('n_isolate_propose')} | "
            f"{pack.get('n_estate_lockdown_propose')} |"
        )
    lines.extend(["", "## Honesty", ""])
    for item in report.get("honesty") or []:
        lines.append(f"- {item}")
    lines.append("")
    return "\n".join(lines)


def build_report() -> Dict[str, Any]:
    policy = ContainPolicy()
    work = ROOT / "runs" / "contain-fp-scoreboard"
    work.mkdir(parents=True, exist_ok=True)
    unsealed = _unseal_benign(work / "unsealed")
    if unsealed:
        source = "sealed_benign"
        paths = unsealed
        source_note = (
            "Scored unsealed held-benign-*.jsonl.sealed with the local held-out key. "
            "Plaintext stays under runs/ (gitignored)."
        )
    else:
        source = "train_benign"
        paths = _train_benign()
        source_note = (
            "Held-out key missing or decrypt failed. Scored plaintext "
            "train/train-benign-*.jsonl (feeder family=benign). These are not the sealed bytes."
        )
    if not paths:
        raise SystemExit("no benign packs found (heldout held-benign-* or train/train-benign-*)")

    packs = [_score_pack(path, policy=policy, work=work) for path in paths]
    n_campaigns = sum(int(p["n_campaigns"]) for p in packs)
    n_iso = sum(int(p["n_isolate_propose"]) for p in packs)
    n_estate = sum(int(p["n_estate_lockdown_propose"]) for p in packs)
    families = {str(p.get("family") or "") for p in packs}
    pure = families <= {"benign"} and source in {"sealed_benign", "train_benign"}
    if pure and n_estate == 0:
        bar = "PASS"
    elif pure:
        bar = "FAIL"
    else:
        bar = "NOT_PURE_BENIGN"

    honesty = [
        "Counts are resolve_isolate_scope proposals on correlator campaigns. Containment was not executed.",
        "CORVEX_CONTAIN was not changed. Live OS quarantine stays unimplemented.",
        "Scored with the in-repo default ContainPolicy (auto_enforce false). "
        "A machine-local contain_policy.json, when present, was not applied.",
        "first_seen/last_seen on each campaign are the min/max event timestamps for its hosts.",
        "On pure benign, n_estate_lockdown_propose must be 0.",
        source_note,
        "Train and sealed benign packs are synthetic feeder noise (egress false). They are not an enterprise benign baseline.",
        "This scoreboard does not set claim_allowed.",
        "Windows DNS-only C2 stays a sensor GAP unless Sysmon EID 22 arrives; the dashboard sensor note already says so when channel_health.dns is down.",
    ]
    return {
        "generated_at": _now(),
        "source": source,
        "n_packs": len(packs),
        "n_campaigns": n_campaigns,
        "n_isolate_propose": n_iso,
        "n_estate_lockdown_propose": n_estate,
        "pure_benign": pure,
        "estate_lockdown_bar": bar,
        "policy": "ContainPolicy defaults (not ~/.corvex/contain_policy.json)",
        "packs": packs,
        "honesty": honesty,
    }


def main() -> int:
    report = build_report()
    REPORT_JSON.parent.mkdir(parents=True, exist_ok=True)
    REPORT_JSON.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    REPORT_MD.write_text(_render_md(report), encoding="utf-8")
    print(
        json.dumps(
            {
                "source": report["source"],
                "n_packs": report["n_packs"],
                "n_campaigns": report["n_campaigns"],
                "n_isolate_propose": report["n_isolate_propose"],
                "n_estate_lockdown_propose": report["n_estate_lockdown_propose"],
                "estate_lockdown_bar": report["estate_lockdown_bar"],
            },
            indent=2,
        )
    )
    print(f"wrote {REPORT_JSON.relative_to(ROOT)}", flush=True)
    if report["estate_lockdown_bar"] == "FAIL":
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
