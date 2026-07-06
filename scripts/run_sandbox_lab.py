#!/usr/bin/env python3
"""Isolated Corvex sandbox: exercise product with safety controls OFF vs ON.

Does not mutate the real repo checklist. Writes results under .sandbox/lab/.
"""

from __future__ import annotations

import json
import shutil
import sys
import threading
import traceback
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

ROOT = Path(__file__).resolve().parents[1]
SANDBOX = ROOT / ".sandbox" / "lab"
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from campaignfuse.contain import (  # noqa: E402
    L1_ITEMS,
    ContainGateError,
    checklist_complete,
    contain_status,
    load_checklist_state,
    require_contain,
    set_checklist_item,
)
from campaignfuse.contain.dry_run import ActionEnvelope, execute_action, propose_action  # noqa: E402
from campaignfuse.correlator import Correlator, CorrelatorConfig  # noqa: E402
from campaignfuse.dashboard import collect_snapshot, write_dashboard  # noqa: E402
from campaignfuse.dash_server import serve  # noqa: E402
from campaignfuse.feeder import generate_campaign_events  # noqa: E402
from campaignfuse.auth import Enrollment  # noqa: E402
from campaignfuse.store import CampaignStore  # noqa: E402
from campaignfuse.audit import AuditLog  # noqa: E402


@dataclass
class CaseResult:
    name: str
    ok: bool
    detail: str
    data: Dict[str, Any] = field(default_factory=dict)


def _seed_sandbox() -> Path:
    if SANDBOX.exists():
        shutil.rmtree(SANDBOX)
    reports = SANDBOX / "reports"
    reports.mkdir(parents=True)
    checklist = {k: False for k in L1_ITEMS}
    checklist["_meta"] = {
        "policy": "sandbox only — not production evidence",
        "live_contain_unlocked": False,
        "sandbox": True,
    }
    (reports / "security_l1_checklist.json").write_text(
        json.dumps(checklist, indent=2) + "\n", encoding="utf-8"
    )
    (reports / "stageA-gate.txt").write_text("PASS\n", encoding="utf-8")
    (reports / "AUDIT_BENCHMARK.json").write_text(
        json.dumps({"CFUSE_CONTAIN": 0, "version": "0.4.0-sandbox"}, indent=2) + "\n",
        encoding="utf-8",
    )
    # Minimal held-out metrics so the dash has numbers
    (reports / "stageA_heldout.json").write_text(
        json.dumps(
            {
                "pass": True,
                "care_vs_incumbent": "unproven",
                "metrics": {
                    "correlator": {
                        "campaign_f1": 1.0,
                        "precision_at_1": 1.0,
                        "false_campaign_rate": 0.0,
                        "ttu_seconds": 0.01,
                    },
                    "b1": {"campaign_f1": 0.0},
                    "b2": {"campaign_f1": 1.0},
                    "detector_only": {"campaign_f1": 1.0},
                },
                "ablation": {"detector_only_f1": 1.0},
            },
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )
    (reports / "oss_retention.json").write_text(json.dumps({"labs": []}) + "\n", encoding="utf-8")
    return SANDBOX


def _set_all(enabled: bool) -> None:
    for k in L1_ITEMS:
        set_checklist_item(k, enabled, root=SANDBOX, source="sandbox")


def _try(name: str, fn) -> CaseResult:
    try:
        detail, data = fn()
        return CaseResult(name=name, ok=True, detail=detail, data=data or {})
    except Exception as exc:  # noqa: BLE001
        return CaseResult(
            name=name,
            ok=False,
            detail=f"{type(exc).__name__}: {exc}",
            data={"traceback": traceback.format_exc()},
        )


def scenario_core_detection() -> CaseResult:
    """Correlator still works regardless of Stage D checklist."""

    def run():
        enr = Enrollment(
            {"prod-a": {"host-a"}, "prod-b": {"host-b"}},
            {"prod-a": b"sandbox-secret-aaaa-bbbb-cccc", "prod-b": b"sandbox-secret-dddd-eeee-ffff"},
        )
        from datetime import datetime, timezone

        events, _gt = generate_campaign_events(
            campaign_id="sandbox-lat",
            family="lateral",
            hosts=[("host-a", "prod-a"), ("host-b", "prod-b")],
            enrollment=enr,
            base_time=datetime(2026, 3, 1, 12, 0, 0, tzinfo=timezone.utc),
        )
        store = CampaignStore()
        audit = AuditLog(SANDBOX / "runs" / "audit.jsonl")
        corr = Correlator(store, audit, CorrelatorConfig())
        for env in events:
            corr.on_event(env)
        camps = list(store.all())
        return (
            f"ingested {len(events)} events → {len(camps)} campaign(s)",
            {"events": len(events), "campaigns": len(camps)},
        )

    return _try("core_detection_correlator", run)


def scenario_safety(label: str, *, expect_complete: bool) -> List[CaseResult]:
    results: List[CaseResult] = []
    st = contain_status(root=SANDBOX)
    results.append(
        CaseResult(
            name=f"{label}.status",
            ok=(st["complete"] is expect_complete),
            detail=f"complete={st['complete']} pct={st['pct']:.1f} live_executor={st['live_executor']}",
            data=st,
        )
    )

    def dry():
        env = propose_action("IsolateHost", {"host_id": "sandbox-host-1"}, rationale=f"{label} dry")
        assert env.dry_run is True
        rec = execute_action(env, log_path=SANDBOX / "reports" / "stage_d_dry_run.jsonl")
        return ("dry-run logged proposal (no host mutation)", rec)

    results.append(_try(f"{label}.dry_run_isolate", dry))

    def live_blocked():
        # Force the live path: dry_run=False must still refuse to mutate.
        bad = ActionEnvelope(
            schema_ver="1",
            verb="IsolateHost",
            target={"host_id": "sandbox-host-1"},
            impact_class="lab_soft",
            dry_run=False,
            idempotency_key="sandbox-live-probe",
            expiry="2099-01-01T00:00:00Z",
            policy_version="sandbox",
            rationale="must not execute",
        )
        try:
            execute_action(bad, log_path=SANDBOX / "reports" / "stage_d_live_probe.jsonl")
            return ("UNEXPECTED: live path returned", {"error": "no gate"})
        except ContainGateError as exc:
            return (f"live path blocked: {exc}", {"blocked": True})

    live = _try(f"{label}.live_path_blocked", live_blocked)
    # Success means we got a ContainGateError (blocked). Fail if unexpected return.
    if live.ok and live.data.get("blocked"):
        live.ok = True
    elif live.ok and live.data.get("error") == "no gate":
        live.ok = False
        live.detail = "Live path was NOT blocked — unsafe"
    results.append(live)

    def gate():
        if expect_complete:
            require_contain(root=SANDBOX)
            return ("require_contain() passed checklist gate", {})
        try:
            require_contain(root=SANDBOX)
            return ("UNEXPECTED pass", {"passed": True})
        except ContainGateError as exc:
            return (f"require_contain blocked: {exc}", {"blocked": True})

    g = _try(f"{label}.require_contain", gate)
    if not expect_complete:
        if g.ok and g.data.get("blocked"):
            g.ok = True
        elif g.ok and g.data.get("passed"):
            g.ok = False
            g.detail = "Gate should have blocked when checklist incomplete"
    results.append(g)

    def dash():
        snap = collect_snapshot(SANDBOX)
        out = write_dashboard(SANDBOX)
        items_on = sum(1 for v in snap["stage_d"]["items"].values() if v)
        return (
            f"dash wrote {out.name}; safety {items_on}/{len(L1_ITEMS)} on; contain flag={snap['cfuse_contain']}",
            {
                "checklist_pct": snap["stage_d"]["checklist_pct"],
                "items_on": items_on,
                "cfuse_contain": snap["cfuse_contain"],
                "gate": snap["gate"],
            },
        )

    results.append(_try(f"{label}.dashboard_snapshot", dash))
    return results


def scenario_api_toggle() -> List[CaseResult]:
    results: List[CaseResult] = []
    write_dashboard(SANDBOX)
    httpd = serve(SANDBOX, port=0)
    host, port = httpd.server_address
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    try:
        import urllib.request

        def post(key: str, enabled: bool) -> dict:
            req = urllib.request.Request(
                f"http://{host}:{port}/api/checklist",
                data=json.dumps({"key": key, "enabled": enabled}).encode(),
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            with urllib.request.urlopen(req, timeout=5) as resp:
                return json.loads(resp.read().decode())

        def run():
            # start from known off
            set_checklist_item("blast_radius_caps", False, root=SANDBOX, source="sandbox")
            on = post("blast_radius_caps", True)
            assert on["ok"] and on["items"]["blast_radius_caps"] is True
            off = post("blast_radius_caps", False)
            assert off["items"]["blast_radius_caps"] is False
            return (
                f"API toggle on ephemeral port {port} OK",
                {"port": port, "on": True, "off": True},
            )

        results.append(_try("api.toggle_roundtrip", run))
    finally:
        httpd.shutdown()
        httpd.server_close()
    return results


def main() -> int:
    print(f"Sandbox root: {SANDBOX}")
    _seed_sandbox()
    all_results: List[CaseResult] = []

    all_results.append(scenario_core_detection())

    print("\n=== SAFETY CONTROLS: OFF (0/11) ===")
    _set_all(False)
    assert checklist_complete(root=SANDBOX) is False
    all_results.extend(scenario_safety("safety_off", expect_complete=False))

    print("\n=== SAFETY CONTROLS: ON (11/11) ===")
    _set_all(True)
    assert checklist_complete(root=SANDBOX) is True
    all_results.extend(scenario_safety("safety_on", expect_complete=True))

    print("\n=== DASH TOGGLE API (isolated) ===")
    # leave checklist all-on from previous; API test flips one bit
    all_results.extend(scenario_api_toggle())

    # Restore sandbox to off for a clean leftover state
    _set_all(False)

    report = {
        "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "sandbox": str(SANDBOX),
        "passed": sum(1 for r in all_results if r.ok),
        "failed": sum(1 for r in all_results if not r.ok),
        "cases": [
            {"name": r.name, "ok": r.ok, "detail": r.detail, "data": r.data} for r in all_results
        ],
    }
    out = SANDBOX / "SANDBOX_REPORT.json"
    out.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")

    md = SANDBOX / "SANDBOX_REPORT.md"
    lines = [
        "# Corvex sandbox lab report",
        "",
        f"Generated: `{report['generated_at']}`",
        f"Root: `{SANDBOX}`",
        f"Result: **{report['passed']} passed / {report['failed']} failed**",
        "",
        "## Findings",
        "",
        "| Case | OK | Detail |",
        "|------|----|--------|",
    ]
    for r in all_results:
        mark = "yes" if r.ok else "NO"
        detail = r.detail.replace("|", "\\|")
        lines.append(f"| `{r.name}` | {mark} | {detail} |")
    lines.extend(
        [
            "",
            "## What this proves",
            "",
            "- **Detection still runs** with safety OFF or ON (correlator is independent of Stage D locks).",
            "- **Dry-run isolate** always logs; it never mutates a host.",
            "- **Live contain path stays blocked** even when all 11 safety toggles are ON "
            "(no executor + checklist alone is not enough).",
            "- **`require_contain()`** fails when toggles are OFF; passes the checklist gate when all ON.",
            "- Dashboard/API toggles work against the isolated sandbox root only.",
            "",
        ]
    )
    md.write_text("\n".join(lines) + "\n", encoding="utf-8")

    print("\n=== SUMMARY ===")
    for r in all_results:
        print(f"[{'PASS' if r.ok else 'FAIL'}] {r.name}: {r.detail}")
    print(f"\nWrote {out}")
    print(f"Wrote {md}")
    return 0 if report["failed"] == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
