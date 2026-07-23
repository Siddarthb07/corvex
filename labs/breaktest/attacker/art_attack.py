"""Manifest-driven sequential attacker for break-test (ART-style steps).

Reads a Corvex break-test manifest and executes steps in order:
  - auth  → live HTTP /auth against virtual hosts
  - exfil → appends net_conn events Corvex tails
  - recon → appends fan-out net_conn events

Not malware — purple-team event sketches from public technique IDs.
"""

from __future__ import annotations

import json
import os
import time
from datetime import datetime, timezone
from pathlib import Path

import requests

LAB = Path(os.environ.get("LAB_DIR", "/lab"))
MANIFEST = Path(os.environ.get("ATTACK_MANIFEST", ""))
ATTACKER_SRC = os.environ.get("ATTACKER_SRC", "10.1.0.5")
LOG = LAB / "attacker.jsonl"
STATE = LAB / "attacker_state.json"
EVENTS = LAB / "events.jsonl"


def now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def log(rec: dict) -> None:
    LAB.mkdir(parents=True, exist_ok=True)
    with LOG.open("a", encoding="utf-8") as fh:
        fh.write(json.dumps(rec, separators=(",", ":")) + "\n")
    STATE.write_text(json.dumps({**rec, "updated": now()}, indent=2), encoding="utf-8")
    print(json.dumps(rec), flush=True)


def append_bus(rec: dict) -> None:
    LAB.mkdir(parents=True, exist_ok=True)
    with EVENTS.open("a", encoding="utf-8") as fh:
        fh.write(json.dumps(rec, separators=(",", ":")) + "\n")


def wait_healthy(hosts: list[str], timeout: float = 60.0) -> None:
    deadline = time.time() + timeout
    while time.time() < deadline:
        ok = 0
        for name in hosts:
            try:
                r = requests.get(f"http://{name}:8080/health", timeout=2)
                if r.status_code == 200:
                    ok += 1
            except requests.RequestException:
                pass
        if ok == len(hosts):
            return
        time.sleep(0.5)
    raise SystemExit("hosts not healthy in time")


def try_auth(host: str, user: str, src: str, wave: str) -> dict:
    url = f"http://{host}:8080/auth"
    try:
        r = requests.post(url, json={"user": user, "src": src}, timeout=5)
        body = {}
        try:
            body = r.json()
        except Exception:
            body = {"raw": r.text[:200]}
        rec = {
            "kind": "attack_attempt",
            "wave": wave,
            "ts_utc": now(),
            "target": host,
            "url": url,
            "user": user,
            "src": src,
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
            "target": host,
            "url": url,
            "user": user,
            "src": src,
            "http_status": 0,
            "ok": False,
            "result": "network_error",
            "message": str(exc),
        }
    log(rec)
    return rec


def emit_exfil(host: str, step: dict) -> None:
    append_bus(
        {
            "kind": "net_conn",
            "host_id": host,
            "ts_utc": now(),
            "dst_ip": str(step.get("dst_ip") or "203.0.113.50"),
            "dst_port": int(step.get("dst_port") or 443),
            "bytes": int(step.get("bytes") or 12_000),
            "egress": True,
            "technique": step.get("technique"),
        }
    )
    log(
        {
            "kind": "exfil_emit",
            "ts_utc": now(),
            "host": host,
            "dst_ip": step.get("dst_ip"),
            "technique": step.get("technique"),
        }
    )


def emit_recon(host: str, step: dict) -> None:
    dsts = list(step.get("dst_ips") or [f"10.20.30.{j+1}" for j in range(8)])
    for j, dst in enumerate(dsts):
        append_bus(
            {
                "kind": "net_conn",
                "host_id": host,
                "ts_utc": now(),
                "dst_ip": str(dst),
                "dst_port": int(step.get("dst_port") or 445),
                "bytes": int(step.get("bytes") or 60),
                "egress": False,
                "technique": step.get("technique"),
            }
        )
        time.sleep(float(step.get("dst_step", 0.15)))
    log(
        {
            "kind": "recon_emit",
            "ts_utc": now(),
            "host": host,
            "dst_count": len(dsts),
            "technique": step.get("technique"),
        }
    )


def load_manifest() -> dict:
    if not MANIFEST.exists():
        raise SystemExit(f"ATTACK_MANIFEST missing: {MANIFEST}")
    return json.loads(MANIFEST.read_text(encoding="utf-8"))


def main() -> None:
    LAB.mkdir(parents=True, exist_ok=True)
    if LOG.exists():
        LOG.unlink()
    man = load_manifest()
    hosts = list(man.get("hosts") or [])
    steps = list(man.get("steps") or [])
    src = ATTACKER_SRC
    techniques = (man.get("source") or {}).get("techniques") or []

    log(
        {
            "kind": "attacker_boot",
            "ts_utc": now(),
            "manifest": str(MANIFEST),
            "campaign_id": man.get("campaign_id"),
            "targets": hosts,
            "techniques": techniques,
            "steps": len(steps),
        }
    )
    wait_healthy(hosts)
    time.sleep(1.5)

    log(
        {
            "kind": "phase",
            "ts_utc": now(),
            "phase": "wave1_manifest",
            "detail": f"Executing {len(steps)} sequential ART-style steps",
        }
    )

    successes = 0
    blocked_mid = 0
    for i, step in enumerate(steps):
        kind = str(step.get("kind") or step.get("type") or "").lower()
        host = str(step.get("host") or "")
        # Pace between steps so correlator can isolate mid-chain
        if i:
            time.sleep(1.6)

        if kind == "auth":
            user = str(step.get("user") or "attacker")
            rec = try_auth(host, user, src, wave="wave1")
            if rec.get("ok"):
                successes += 1
            elif rec.get("http_status") == 403:
                blocked_mid += 1
        elif kind in ("egress", "exfil", "micro_exfil"):
            emit_exfil(host, step)
        elif kind in ("recon", "recon_fanout"):
            emit_recon(host, step)
        else:
            log({"kind": "skip_unknown_step", "step": step, "ts_utc": now()})

    log(
        {
            "kind": "phase",
            "ts_utc": now(),
            "phase": "wait_for_defense",
            "detail": "Waiting for Corvex isolate flags…",
            "wave1_successes": successes,
            "blocked_mid_chain": blocked_mid,
        }
    )
    need = len(hosts)
    deadline = time.time() + 30
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
    users = sorted(
        {
            str(s.get("user") or "attacker")
            for s in steps
            if str(s.get("kind") or "").lower() == "auth"
        }
    ) or ["attacker"]
    for host in hosts:
        rec = try_auth(host, users[0], src, wave="wave2")
        if rec.get("http_status") == 403 or rec.get("result") == "blocked_by_corvex":
            blocked += 1
        time.sleep(0.6)

    log(
        {
            "kind": "attack_complete",
            "ts_utc": now(),
            "campaign_id": man.get("campaign_id"),
            "techniques": techniques,
            "wave1_successes": successes,
            "blocked_mid_chain": blocked_mid,
            "wave2_blocked": blocked,
            "outcome": "contained" if blocked >= need else "partial",
        }
    )


if __name__ == "__main__":
    main()
