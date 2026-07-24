#!/usr/bin/env python3
"""Docker breaktest lab + whole-PC OS-wide sensor → one dash run dir.

Lab writes flat events into labs/breaktest/shared/events.jsonl.
PC sensor writes signed envelopes into runs/pc-sensor/events.jsonl.
This process merges both into runs/pc-and-lab/events.jsonl and refreshes timeline.
Dash should be pointed at runs/pc-and-lab.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import threading
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
LAB = ROOT / "labs" / "breaktest"
SHARED = LAB / "shared"
PC_RUN = ROOT / "runs" / "pc-sensor"
FUSION = ROOT / "runs" / "pc-and-lab"
HOSTS = ["host-a", "host-b", "host-c", "host-d", "host-e"]


def _tail_merge(src: Path, dest: Path, state: dict, key: str) -> int:
    if not src.exists():
        return 0
    data = src.read_bytes()
    offset = int(state.get(key, 0))
    if offset > len(data):
        offset = 0
    chunk = data[offset:]
    if not chunk:
        return 0
    dest.parent.mkdir(parents=True, exist_ok=True)
    with dest.open("ab") as fh:
        fh.write(chunk)
    state[key] = len(data)
    return chunk.count(b"\n")


def merge_loop(stop: threading.Event) -> None:
    sys.path.insert(0, str(ROOT))
    from corvex.lab_enroll import ensure_lab_enrollment
    from corvex.sensors.windows_os import recompute_run

    enr = ensure_lab_enrollment(
        hosts={
            "host-a": "prod-a",
            "host-b": "prod-b",
            "host-c": "prod-c",
            "host-d": "prod-d",
            "host-e": "prod-e",
            "host-pc": "prod-pc",
        }
    )
    state: dict = {}
    events = FUSION / "events.jsonl"
    if events.exists():
        events.unlink()
    last_recompute = 0.0
    while not stop.is_set():
        n1 = _tail_merge(SHARED / "events.jsonl", events, state, "lab")
        n2 = _tail_merge(PC_RUN / "events.jsonl", events, state, "pc")
        now = time.time()
        if (n1 or n2) and now - last_recompute > 2.0:
            try:
                recompute_run(FUSION, enr)
            except Exception as exc:
                print("recompute:", exc, flush=True)
            last_recompute = now
            (FUSION / "fusion_status.json").write_text(
                json.dumps(
                    {
                        "lab_bytes": state.get("lab", 0),
                        "pc_bytes": state.get("pc", 0),
                        "events_path": "runs/pc-and-lab/events.jsonl",
                        "sources": ["labs/breaktest/shared", "runs/pc-sensor"],
                    },
                    indent=2,
                )
                + "\n",
                encoding="utf-8",
            )
        time.sleep(0.5)


def main() -> int:
    if shutil.which("docker") is None:
        print("Docker required", file=sys.stderr)
        return 1

    # Fresh dirs
    if SHARED.exists():
        shutil.rmtree(SHARED, ignore_errors=True)
    SHARED.mkdir(parents=True)
    (SHARED / "isolated").mkdir(parents=True)
    for d in (PC_RUN, FUSION):
        if d.exists():
            shutil.rmtree(d, ignore_errors=True)
        d.mkdir(parents=True)

    stop = threading.Event()
    merger = threading.Thread(target=merge_loop, args=(stop,), daemon=True)
    merger.start()

    env = os.environ.copy()
    env["ATTACK_MANIFEST"] = env.get("ATTACK_MANIFEST", "/manifests/art_lateral_chain.json")

    def dcmd(*args: str) -> None:
        print("+", " ".join(args), flush=True)
        subprocess.run(list(args), cwd=str(LAB), check=True, env=env)

    dcmd("docker", "compose", "down", "-v", "--remove-orphans")
    dcmd("docker", "compose", "up", "--build", "-d", *HOSTS, "corvex")
    time.sleep(3)

    # Whole-PC sensor (wevtutil follow) + seed fixture so dash shows host-pc even if EL empty
    seed = ROOT / "fixtures" / "os_wide" / "multi_channel.jsonl"
    pc_env = os.environ.copy()
    # Stage B already allowed via stranger marker; keep override as belt-and-suspenders
    pc_env["CORVEX_STAGE_B"] = "1"

    print("+ seeding PC sensor from fixture as host-pc", flush=True)
    subprocess.run(
        [
            sys.executable,
            "-m",
            "corvex",
            "sensor-windows",
            "--fixture",
            str(seed),
            "--host-id",
            "host-pc",
            "--producer",
            "prod-pc",
            "--allowlist",
            str(ROOT / "fixtures/os_wide/channels.json"),
            "--run-dir",
            str(PC_RUN),
            "--once",
        ],
        cwd=str(ROOT),
        check=False,
        env=pc_env,
    )

    print("+ starting PC wevtutil --follow (best-effort live OS logs)", flush=True)
    pc_follow = subprocess.Popen(
        [
            sys.executable,
            "-m",
            "corvex",
            "sensor-windows",
            "--host-id",
            "host-pc",
            "--producer",
            "prod-pc",
            "--allowlist",
            str(ROOT / "fixtures/os_wide/channels.json"),
            "--run-dir",
            str(PC_RUN),
            "--follow",
            "--poll-seconds",
            "3",
            "--max-cycles",
            "40",
        ],
        cwd=str(ROOT),
        env=pc_env,
    )

    print("+ starting dash on runs/pc-and-lab", flush=True)
    dash = subprocess.Popen(
        [
            sys.executable,
            "-m",
            "corvex",
            "dash",
            "--run-dir",
            str(FUSION),
            "--host",
            "127.0.0.1",
            "--port",
            "8765",
            "--no-open",
        ],
        cwd=str(ROOT),
        env=pc_env,
    )

    time.sleep(2)
    dcmd("docker", "compose", "up", "--build", "-d", "attacker")

    deadline = time.time() + 240
    state_path = SHARED / "attacker_state.json"
    result = 1
    while time.time() < deadline:
        if state_path.exists():
            try:
                st = json.loads(state_path.read_text(encoding="utf-8"))
                if st.get("kind") == "attack_complete":
                    print("\n=== ATTACK COMPLETE ===", flush=True)
                    print(json.dumps(st, indent=2), flush=True)
                    result = 0
                    break
            except json.JSONDecodeError:
                pass
        time.sleep(0.5)
    else:
        print("timeout waiting for attack", file=sys.stderr)
        subprocess.run(["docker", "compose", "logs", "--no-color"], cwd=str(LAB))

    # Let merger catch final lines
    time.sleep(4)
    stop.set()
    merger.join(timeout=5)
    pc_follow.terminate()
    # leave dash running for the user
    print(
        json.dumps(
            {
                "dash": "http://127.0.0.1:8765/",
                "run_dir": "runs/pc-and-lab",
                "sources": ["labs/breaktest/shared (docker)", "runs/pc-sensor (whole PC)"],
                "dash_pid": dash.pid,
                "events": (FUSION / "events.jsonl").exists()
                and sum(1 for _ in (FUSION / "events.jsonl").open(encoding="utf-8") if _.strip()),
                "fusion_status": json.loads((FUSION / "fusion_status.json").read_text(encoding="utf-8"))
                if (FUSION / "fusion_status.json").exists()
                else None,
            },
            indent=2,
        ),
        flush=True,
    )
    return result


if __name__ == "__main__":
    raise SystemExit(main())
