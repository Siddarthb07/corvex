"""Live attacker — actually HTTP-auths across virtual hosts, then retries after defend."""

from __future__ import annotations

import json
import os
import time
from datetime import datetime, timezone
from pathlib import Path

import requests

LAB = Path(os.environ.get("LAB_DIR", "/lab"))
ATTACKER_SRC = os.environ.get("ATTACKER_SRC", "10.1.0.5")
USER = os.environ.get("ATTACK_USER", "alice")

_DEFAULT_TARGETS = [
    ("host-a", "http://host-a:8080"),
    ("host-b", "http://host-b:8080"),
    ("host-c", "http://host-c:8080"),
]


def _targets_from_env() -> list:
    raw = os.environ.get("ATTACK_TARGETS", "").strip()
    if not raw:
        return list(_DEFAULT_TARGETS)
    out = []
    for name in raw.split(","):
        name = name.strip()
        if name:
            out.append((name, f"http://{name}:8080"))
    return out or list(_DEFAULT_TARGETS)


TARGETS = _targets_from_env()
LOG = LAB / "attacker.jsonl"
STATE = LAB / "attacker_state.json"


def now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def log(rec: dict) -> None:
    LAB.mkdir(parents=True, exist_ok=True)
    with LOG.open("a", encoding="utf-8") as fh:
        fh.write(json.dumps(rec, separators=(",", ":")) + "\n")
    STATE.write_text(json.dumps({**rec, "updated": now()}, indent=2), encoding="utf-8")
    print(json.dumps(rec), flush=True)


def wait_healthy(timeout: float = 60.0) -> None:
    deadline = time.time() + timeout
    while time.time() < deadline:
        ok = 0
        for name, base in TARGETS:
            try:
                r = requests.get(f"{base}/health", timeout=2)
                if r.status_code == 200:
                    ok += 1
            except requests.RequestException:
                pass
        if ok == len(TARGETS):
            return
        time.sleep(0.5)
    raise SystemExit("hosts not healthy in time")


def try_auth(name: str, base: str, wave: str) -> dict:
    url = f"{base}/auth"
    try:
        r = requests.post(
            url,
            json={"user": USER, "src": ATTACKER_SRC},
            timeout=5,
        )
        body = {}
        try:
            body = r.json()
        except Exception:
            body = {"raw": r.text[:200]}
        rec = {
            "kind": "attack_attempt",
            "wave": wave,
            "ts_utc": now(),
            "target": name,
            "url": url,
            "user": USER,
            "src": ATTACKER_SRC,
            "http_status": r.status_code,
            "ok": bool(body.get("ok")),
            "result": body.get("result") or r.reason,
            "message": body.get("message"),
        }
    except requests.RequestException as exc:
        rec = {
            "kind": "attack_attempt",
            "wave": wave,
            "ts_utc": now(),
            "target": name,
            "url": url,
            "user": USER,
            "src": ATTACKER_SRC,
            "http_status": 0,
            "ok": False,
            "result": "network_error",
            "message": str(exc),
        }
    log(rec)
    return rec


def main() -> None:
    LAB.mkdir(parents=True, exist_ok=True)
    if LOG.exists():
        LOG.unlink()
    log({"kind": "attacker_boot", "ts_utc": now(), "targets": [t[0] for t in TARGETS]})
    wait_healthy()
    # Give Corvex a moment to start tailing
    time.sleep(1.5)

    log(
        {
            "kind": "phase",
            "ts_utc": now(),
            "phase": "wave1_lateral",
            "detail": f"Attempting lateral auth as {USER} from {ATTACKER_SRC}",
        }
    )

    successes = 0
    for i, (name, base) in enumerate(TARGETS):
        rec = try_auth(name, base, wave="wave1")
        if rec.get("ok"):
            successes += 1
        # Real pacing so Corvex can catch mid-campaign
        time.sleep(2.0 if i < len(TARGETS) - 1 else 0.5)

    log(
        {
            "kind": "phase",
            "ts_utc": now(),
            "phase": "wait_for_defense",
            "detail": "Waiting for Corvex isolate flags…",
            "wave1_successes": successes,
        }
    )
    # Wait until all targets isolated or timeout
    need = len(TARGETS)
    deadline = time.time() + 25
    while time.time() < deadline:
        flags = list((LAB / "isolated").glob("*.flag")) if (LAB / "isolated").exists() else []
        if len(flags) >= need:
            break
        time.sleep(0.4)

    log(
        {
            "kind": "phase",
            "ts_utc": now(),
            "phase": "wave2_retry",
            "detail": "Retrying auth after Corvex defense — should be blocked",
        }
    )
    blocked = 0
    for name, base in TARGETS:
        rec = try_auth(name, base, wave="wave2")
        if rec.get("http_status") == 403 or rec.get("result") == "blocked_by_corvex":
            blocked += 1
        time.sleep(0.8)

    log(
        {
            "kind": "attack_complete",
            "ts_utc": now(),
            "wave1_successes": successes,
            "wave2_blocked": blocked,
            "outcome": "contained" if blocked >= need else "partial",
        }
    )


if __name__ == "__main__":
    main()
