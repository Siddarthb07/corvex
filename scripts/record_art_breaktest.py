#!/usr/bin/env python3
"""Score every ART break-test manifest, run Docker ART attack, export videos."""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
LAB = ROOT / "labs" / "breaktest"
MANIFESTS = LAB / "manifests"
SHARED = LAB / "shared"
OUT_DIR = ROOT / "docs" / "assets"
RUN_DIR = ROOT / "runs" / "breaktest"
HOSTS = ["host-a", "host-b", "host-c", "host-d", "host-e"]

# Record these live (sequential ART, not single-user easy lateral alone)
LIVE_MANIFESTS = [
    "art_lateral_chain.json",
    "art_cred_hop.json",
    "art_recon_pivot.json",
]


def run(cmd: list[str], cwd: Path | None = None, env: dict | None = None) -> None:
    print("+", " ".join(cmd), flush=True)
    merged = os.environ.copy()
    if env:
        merged.update(env)
    subprocess.run(cmd, cwd=str(cwd or ROOT), check=True, env=merged)


def score_all() -> list[dict]:
    RUN_DIR.mkdir(parents=True, exist_ok=True)
    summary = []
    for path in sorted(MANIFESTS.glob("*.json")):
        out = RUN_DIR / f"{path.stem}.jsonl"
        report = RUN_DIR / f"{path.stem}.breaks.json"
        run(
            [
                sys.executable,
                "-m",
                "corvex",
                "build-breaktest",
                str(path),
                "--out",
                str(out),
                "--report",
                str(report),
            ]
        )
        data = json.loads(report.read_text(encoding="utf-8"))
        summary.append(
            {
                "manifest": path.name,
                "campaign_id": data.get("campaign_id"),
                "fusion_lift": (data.get("break_points") or {}).get("fusion_lift"),
                "corr_jaccard": (data.get("correlator") or {}).get("best_jaccard"),
                "det_jaccard": (data.get("detector_only") or {}).get("best_jaccard"),
                "techniques": ((data.get("source") or {}).get("techniques") or []),
            }
        )
    summary_path = RUN_DIR / "art_manifest_summary.json"
    summary_path.write_text(json.dumps(summary, indent=2) + "\n", encoding="utf-8")
    print("\n=== ART MANIFEST SCORE SUMMARY ===", flush=True)
    print(json.dumps(summary, indent=2), flush=True)
    return summary


def docker_art_run(manifest_name: str) -> Path:
    if SHARED.exists():
        shutil.rmtree(SHARED, ignore_errors=True)
    SHARED.mkdir(parents=True)
    (SHARED / "isolated").mkdir(parents=True)

    env = {"ATTACK_MANIFEST": f"/manifests/{manifest_name}"}
    run(["docker", "compose", "down", "-v", "--remove-orphans"], cwd=LAB)
    run(
        ["docker", "compose", "up", "--build", "-d", *HOSTS, "corvex"],
        cwd=LAB,
        env=env,
    )
    time.sleep(3)
    run(["docker", "compose", "up", "--build", "-d", "attacker"], cwd=LAB, env=env)

    deadline = time.time() + 300
    state_path = SHARED / "attacker_state.json"
    while time.time() < deadline:
        if state_path.exists():
            try:
                st = json.loads(state_path.read_text(encoding="utf-8"))
                if st.get("kind") == "attack_complete":
                    print("\n=== ATTACK COMPLETE ===", flush=True)
                    print(json.dumps(st, indent=2), flush=True)
                    break
            except json.JSONDecodeError:
                pass
        time.sleep(0.5)
    else:
        run(["docker", "compose", "logs", "--no-color"], cwd=LAB, env=env)
        raise SystemExit(f"timeout waiting for {manifest_name}")

    time.sleep(2)
    run(["docker", "compose", "logs", "--no-color", "attacker", "corvex"], cwd=LAB, env=env)

    dest = RUN_DIR / "docker" / Path(manifest_name).stem
    dest.mkdir(parents=True, exist_ok=True)
    for name in (
        "attacker_state.json",
        "events.jsonl",
        "attacker.jsonl",
        "corvex_state.json",
        "theatre_state.json",
    ):
        src = SHARED / name
        if src.exists():
            shutil.copy2(src, dest / name)

    run(["docker", "compose", "down", "-v"], cwd=LAB, env=env)
    return dest


def export_video(theatre_dir: Path, stem: str = "breaktest") -> None:
    """Write the single published demo: docs/assets/corvex-breaktest.{gif,mp4}."""
    sys.path.insert(0, str(ROOT / "scripts"))
    from export_live_lab_video import export_replay
    from run_breaktest_lab import _replay_html

    theatre = theatre_dir / "theatre_state.json"
    if not theatre.exists():
        raise SystemExit(f"missing theatre state in {theatre_dir}")
    state = json.loads(theatre.read_text(encoding="utf-8"))
    print(f"\n=== THEATRE FEED ({stem}) ===", flush=True)
    for item in state.get("feed") or []:
        text = str(item.get("text") or "").encode("ascii", "replace").decode("ascii")
        print(f"  [{item.get('type')}] {text}", flush=True)

    replay = theatre_dir / "breaktest-replay.html"
    replay.write_text(_replay_html(state), encoding="utf-8")
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    import export_live_lab_video as ev

    old = ev.DURATION_S
    ev.DURATION_S = 18.0
    try:
        export_replay(
            replay,
            OUT_DIR / "corvex-breaktest.gif",
            OUT_DIR / "corvex-breaktest.mp4",
        )
    finally:
        ev.DURATION_S = old


def main() -> int:
    if shutil.which("docker") is None:
        print("Docker required", file=sys.stderr)
        return 1

    score_all()

    # Live-run every sequential ART attack; publish only one demo video (primary).
    for i, name in enumerate(LIVE_MANIFESTS):
        print(f"\n######## LIVE ART RUN: {name} ########", flush=True)
        dest = docker_art_run(name)
        if i == 0:
            export_video(dest, Path(name).stem)

    print("\nPublished demo:", OUT_DIR / "corvex-breaktest.mp4", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
