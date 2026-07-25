"""Re-run Operation CDN Bridge with safety gates enforced.

Safety stack exercised:
- claim gates evaluate (claim_allowed may be false; require lab_verified + trust_integrity)
- Stage B honest unlock (no CORVEX_STAGE_B env bypass; lab-override removed for this run)
- hostile-bus selftest
- pack signed + feed_bus publish_verified (HMAC)
- recompute_run HMAC reject of tampered row
- default CorrelatorConfig (window_seconds / CDN poison / jumpbox guard)
- contain remains locked (CORVEX_CONTAIN=0)
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
MANIFEST = ROOT / "labs" / "breaktest" / "manifests" / "break_cdn_bridge_compound.json"
OUT = ROOT / "runs" / "cdn-bridge-safe"
LAB_OVERRIDE = ROOT / "reports" / "stage-b-lab-override.json"


def run(cmd: list[str]) -> subprocess.CompletedProcess:
    print("+", " ".join(cmd), flush=True)
    return subprocess.run(cmd, cwd=str(ROOT), check=False, text=True, capture_output=True)


def main() -> int:
    os.environ["CORVEX_CONTAIN"] = "0"
    os.environ.pop("CORVEX_STAGE_B", None)
    os.environ.pop("CFUSE_STAGE_B", None)

    lab_override_backup = None
    if LAB_OVERRIDE.exists():
        lab_override_backup = LAB_OVERRIDE.read_text(encoding="utf-8")
        LAB_OVERRIDE.unlink()

    report: dict = {
        "test": "Operation CDN Bridge (safe harness)",
        "manifest": "labs/breaktest/manifests/break_cdn_bridge_compound.json",
        "safety": {
            "CORVEX_CONTAIN": "0",
            "CORVEX_STAGE_B": "unset",
            "lab_override_removed_for_run": lab_override_backup is not None,
            "hmac_verify": True,
            "tamper_injection": True,
            "default_correlator_config": True,
        },
        "gates": {},
        "break_points": {},
        "hmac": {},
    }

    try:
        proc = run([sys.executable, "-m", "corvex", "claim-gates"])
        claim_payload = None
        if proc.stdout.strip():
            try:
                claim_payload = json.loads(proc.stdout)
            except json.JSONDecodeError:
                claim_payload = None
        trust_ok = bool(
            claim_payload
            and claim_payload.get("lab_verified")
            and (claim_payload.get("gates") or {}).get("trust_integrity", {}).get("pass")
        )
        report["gates"]["claim_gates"] = {
            "exit": proc.returncode,
            "pass": trust_ok,
            "claim_allowed": bool(claim_payload and claim_payload.get("claim_allowed")),
            "lab_verified": bool(claim_payload and claim_payload.get("lab_verified")),
            "payload": claim_payload,
        }

        for name, args in (
            ("stage_b_check", [sys.executable, "-m", "corvex", "stage-b-check"]),
            ("hostile_bus", [sys.executable, "-m", "corvex", "hostile-bus-test"]),
        ):
            proc = run(args)
            report["gates"][name] = {
                "exit": proc.returncode,
                "pass": proc.returncode == 0,
            }
            if proc.stdout.strip():
                try:
                    report["gates"][name]["payload"] = json.loads(proc.stdout)
                except json.JSONDecodeError:
                    report["gates"][name]["stdout_tail"] = proc.stdout[-500:]

        if not all(
            report["gates"][k]["pass"]
            for k in ("claim_gates", "stage_b_check", "hostile_bus")
        ):
            report["pass"] = False
            report["note"] = (
                "Safety gates failed — need lab_verified+trust_integrity, "
                "stage-b-check, hostile-bus (claim_allowed may stay false)"
            )
            _write(report)
            print(json.dumps(report, indent=2))
            return 1

        if OUT.exists():
            shutil.rmtree(OUT)
        OUT.mkdir(parents=True)
        pack = OUT / "pack.jsonl"
        breaks = OUT / "breaks.json"
        proc = run(
            [
                sys.executable,
                "-m",
                "corvex",
                "build-breaktest",
                str(MANIFEST),
                "--out",
                str(pack),
                "--report",
                str(breaks),
            ]
        )
        if proc.returncode != 0:
            report["pass"] = False
            report["build_error"] = proc.stderr or proc.stdout
            _write(report)
            print(json.dumps(report, indent=2))
            return 1
        br = json.loads(breaks.read_text(encoding="utf-8"))
        report["break_points"] = br.get("break_points") or {}
        report["correlator"] = br.get("correlator") or {}
        report["source_note"] = (br.get("source") or {}).get("note")

        replay = OUT / "replay"
        proc = run(
            [
                sys.executable,
                "-m",
                "corvex",
                "replay",
                str(pack),
                "--out-dir",
                str(replay),
            ]
        )
        report["replay_exit"] = proc.returncode
        if proc.returncode != 0:
            report["pass"] = False
            report["replay_error"] = proc.stderr or proc.stdout
            _write(report)
            print(json.dumps(report, indent=2))
            return 1

        sys.path.insert(0, str(ROOT))
        from corvex.lab_enroll import ensure_lab_enrollment
        from corvex.sensors.windows_os import recompute_run

        enr = ensure_lab_enrollment()
        events_path = replay / "events.jsonl"
        lines = events_path.read_text(encoding="utf-8").splitlines()
        tampered = None
        for line in lines:
            if not line.strip():
                continue
            rec = json.loads(line)
            if rec.get("schema_ver") and rec.get("hmac"):
                tampered = dict(rec)
                tampered["hmac"] = "00" * 32
                tampered["event_id"] = str(tampered.get("event_id")) + "-TAMPER"
                break
        if tampered is None:
            report["hmac"] = {"ok": False, "reason": "no_envelope_to_tamper"}
        else:
            fuse_dir = OUT / "hmac-check"
            fuse_dir.mkdir(parents=True)
            (fuse_dir / "events.jsonl").write_text(
                "\n".join(lines + [json.dumps(tampered)]) + "\n",
                encoding="utf-8",
            )
            stats = recompute_run(fuse_dir, enr)
            report["hmac"] = {
                "ok": int(stats.get("hmac_rejected") or 0) >= 1,
                "hmac_rejected": stats.get("hmac_rejected"),
                "events_accepted": stats.get("events"),
                "mode": "offline_lab_replay_verify",
            }

        jaccard = float((report.get("correlator") or {}).get("best_jaccard") or 0)
        matched = bool((report.get("correlator") or {}).get("matched"))
        hmac_ok = bool((report.get("hmac") or {}).get("ok"))
        report["pass"] = matched and jaccard >= 0.99 and hmac_ok and proc.returncode == 0
        report["dash_run_dir"] = "runs/cdn-bridge-safe/replay"
        report["honesty"] = (
            "Safety harness does not require claim_allowed. "
            "CDN Bridge residual host-d helpdesk stitch remains a published limit."
        )
        _write(report)
        print(json.dumps(report, indent=2))
        return 0 if report["pass"] else 1
    finally:
        if lab_override_backup is not None:
            LAB_OVERRIDE.write_text(lab_override_backup, encoding="utf-8")


def _write(report: dict) -> None:
    OUT.mkdir(parents=True, exist_ok=True)
    path = OUT / "safety_report.json"
    path.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    (ROOT / "reports" / "cdn_bridge_safe.json").write_text(
        json.dumps(report, indent=2) + "\n", encoding="utf-8"
    )


if __name__ == "__main__":
    raise SystemExit(main())
