"""Corvex defender — tails live host events, correlates, isolates virtual hosts."""

from __future__ import annotations

import json
import os
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Set

from corvex.audit import AuditLog
from corvex.auth import Enrollment
from corvex.contain.dry_run import execute_action, propose_action
from corvex.correlator import Correlator, CorrelatorConfig
from corvex.envelope import sign_envelope
from corvex.store import CampaignStore

LAB = Path(os.environ.get("LAB_DIR", "/lab"))
EVENTS = LAB / "events.jsonl"
ISOLATED = LAB / "isolated"
RUNS = LAB / "corvex"
STATE = LAB / "corvex_state.json"
THEATRE = LAB / "theatre_state.json"

_ALL_HOST_META = {
    "host-a": ("prod-a", "workstation"),
    "host-b": ("prod-b", "fileserver"),
    "host-c": ("prod-c", "jump box"),
    "host-d": ("prod-d", "db"),
    "host-e": ("prod-e", "egress proxy"),
}

# Default live lab = 3 hosts. Break-test sets CORVEX_LAB_HOSTS=host-a,...,host-e
_lab_hosts_env = os.environ.get("CORVEX_LAB_HOSTS", "").strip()
if _lab_hosts_env:
    _wanted = {h.strip() for h in _lab_hosts_env.split(",") if h.strip()}
    HOST_META = {h: _ALL_HOST_META[h] for h in _wanted if h in _ALL_HOST_META}
else:
    HOST_META = {h: _ALL_HOST_META[h] for h in ("host-a", "host-b", "host-c")}



def now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def write_json(path: Path, data: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")


def update_theatre(**kwargs: Any) -> None:
    cur: Dict[str, Any] = {}
    if THEATRE.exists():
        try:
            cur = json.loads(THEATRE.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            cur = {}
    cur.update(kwargs)
    cur["updated"] = now()
    write_json(THEATRE, cur)


def isolate_host(host_id: str, rationale: str) -> dict:
    ISOLATED.mkdir(parents=True, exist_ok=True)
    flag = ISOLATED / f"{host_id}.flag"
    flag.write_text(
        json.dumps({"ts": now(), "by": "corvex", "rationale": rationale}, indent=2),
        encoding="utf-8",
    )
    env = propose_action(
        "IsolateHost",
        {"host_id": host_id},
        rationale=rationale,
    )
    rec = execute_action(env, log_path=RUNS / "interrupt_dry_run.jsonl")
    # Mark as sandbox-enforced (flag file makes host refuse auth)
    rec = {**rec, "sandbox_enforced": True, "flag": str(flag)}
    return rec


def to_envelope(raw: dict, enrollment: Enrollment, seq: int):
    host_id = raw["host_id"]
    producer, _role = HOST_META[host_id]
    secret = enrollment.require(producer, host_id)
    kind = raw.get("kind")
    if kind == "net_conn" or raw.get("payload_type") == "net_conn":
        payload = {
            "dst_ip": raw.get("dst_ip"),
            "dst_port": int(raw.get("dst_port") or 443),
            "bytes": int(raw.get("bytes") or 0),
            "egress": bool(raw.get("egress", False)),
        }
        payload_type = "net_conn"
        prefix = "live-net"
    else:
        payload = {
            "user": raw.get("user"),
            "result": raw.get("result"),
            "src": raw.get("src"),
        }
        payload_type = "auth"
        prefix = "live-auth"
    return sign_envelope(
        producer_id=producer,
        host_id=host_id,
        payload_type=payload_type,
        payload=payload,
        secret=secret,
        event_id=f"{prefix}-{host_id}-{seq:04d}",
        ts_utc=raw.get("ts_utc") or now(),
        nonce=f"{prefix}-{host_id}-{seq:04d}-{raw.get('ts_utc','')}",
    )


def _after_ingest(
    *,
    host_id: str,
    feed: list,
    defended: set,
    store: CampaignStore,
    corr_note: str,
) -> None:
    hit_hosts = {f["host"] for f in feed if f.get("type") in ("auth", "exfil", "recon")}
    hosts_state = {
        h: {
            "role": role,
            "state": (
                "isolated"
                if h in defended
                else ("hit" if h in hit_hosts else "open")
            ),
        }
        for h, (_, role) in HOST_META.items()
    }
    camps = store.all()
    update_theatre(
        phase="ATTACK_SEEN",
        caption=corr_note,
        hosts=hosts_state,
        campaigns=[
            {"id": c.campaign_id, "hosts": c.host_ids, "score": c.score}
            for c in camps
        ],
        feed=feed[-20:],
    )


def _maybe_isolate(
    *,
    store: CampaignStore,
    defended: set,
    feed: list,
) -> None:
    camps = store.all()
    if not camps:
        return
    camp = camps[0]
    targets = list(dict.fromkeys([*camp.host_ids, *HOST_META.keys()]))
    new_targets = [h for h in targets if h not in defended]
    if not new_targets:
        return
    update_theatre(
        phase="DETECT",
        caption=f"Campaign {camp.campaign_id} across {', '.join(camp.host_ids)}",
        campaigns=[
            {"id": c.campaign_id, "hosts": c.host_ids, "score": c.score}
            for c in camps
        ],
        feed=feed[-20:]
        + [
            {
                "ts": now(),
                "type": "detect",
                "text": f"Detected {camp.campaign_id} ({len(camp.host_ids)} hosts)",
            }
        ],
    )
    print(f"[corvex] DETECT {camp.campaign_id} hosts={camp.host_ids}", flush=True)
    isolates = []
    for h in new_targets:
        rec = isolate_host(
            h,
            f"Live lab: quarantine {h} after {camp.campaign_id}",
        )
        defended.add(h)
        isolates.append(rec)
        feed.append(
            {
                "ts": now(),
                "type": "defend",
                "host": h,
                "text": f"Isolated {h} — further auth will be refused",
            }
        )
        print(f"[corvex] ISOLATE {h}", flush=True)
        time.sleep(0.35)
    update_theatre(
        phase="DEFEND",
        caption="Corvex isolated compromised hosts — later ART steps blocked",
        hosts={
            h: {
                "role": role,
                "state": "isolated" if h in defended else "open",
            }
            for h, (_, role) in HOST_META.items()
        },
        campaigns=[
            {"id": c.campaign_id, "hosts": c.host_ids, "score": c.score}
            for c in store.all()
        ],
        feed=feed[-30:],
        isolates=isolates,
    )


def main() -> None:
    LAB.mkdir(parents=True, exist_ok=True)
    ISOLATED.mkdir(parents=True, exist_ok=True)
    RUNS.mkdir(parents=True, exist_ok=True)
    if EVENTS.exists():
        EVENTS.write_text("", encoding="utf-8")

    enrollment = Enrollment(
        {p: {h} for h, (p, _) in HOST_META.items()},
        {
            "prod-a": b"live-lab-secret-aaaa-bbbb-cccc",
            "prod-b": b"live-lab-secret-dddd-eeee-ffff",
            "prod-c": b"live-lab-secret-gggg-hhhh-iiii",
            "prod-d": b"live-lab-secret-jjjj-kkkk-llll",
            "prod-e": b"live-lab-secret-mmmm-nnnn-oooo",
        },
    )
    store = CampaignStore(RUNS / "campaigns.jsonl")
    audit = AuditLog(RUNS / "audit.jsonl")
    corr = Correlator(store, audit, CorrelatorConfig(min_hosts=2, window_seconds=600))

    seen_lines = 0
    seq = 0
    defended: Set[str] = set()
    feed: List[dict] = []

    update_theatre(
        phase="WATCHING",
        caption="Corvex online — watching virtual hosts for lateral auth…",
        hosts={h: {"role": role, "state": "open"} for h, (_, role) in HOST_META.items()},
        campaigns=[],
        feed=feed,
        isolates=[],
    )
    write_json(STATE, {"status": "watching", "ts": now()})
    print("[corvex] watching", EVENTS, flush=True)

    deadline = time.time() + 180
    while time.time() < deadline:
        if EVENTS.exists():
            lines = EVENTS.read_text(encoding="utf-8").splitlines()
            new = lines[seen_lines:]
            seen_lines = len(lines)
            for line in new:
                if not line.strip():
                    continue
                raw = json.loads(line)
                kind = raw.get("kind")
                host_id = raw.get("host_id")
                if kind == "auth" and raw.get("result") == "success" and host_id in HOST_META:
                    seq += 1
                    env = to_envelope(raw, enrollment, seq)
                    corr.ingest([env])
                    feed.append(
                        {
                            "ts": raw.get("ts_utc"),
                            "type": "auth",
                            "host": host_id,
                            "text": f"{raw.get('user')} logged into {host_id} from {raw.get('src')}",
                        }
                    )
                    print(
                        f"[corvex] ingested auth on {host_id}; campaigns={len(store.all())}",
                        flush=True,
                    )
                    _after_ingest(
                        host_id=host_id,
                        feed=feed,
                        defended=defended,
                        store=store,
                        corr_note=f"Live auth on {host_id} — correlator recomputing…",
                    )
                    _maybe_isolate(store=store, defended=defended, feed=feed)
                elif kind == "net_conn" and host_id in HOST_META:
                    seq += 1
                    env = to_envelope(raw, enrollment, seq)
                    corr.ingest([env])
                    egress = bool(raw.get("egress"))
                    feed.append(
                        {
                            "ts": raw.get("ts_utc"),
                            "type": "exfil" if egress else "recon",
                            "host": host_id,
                            "text": (
                                f"{'Egress' if egress else 'Scan'} from {host_id} -> "
                                f"{raw.get('dst_ip')}:{raw.get('dst_port')}"
                            ),
                        }
                    )
                    print(
                        f"[corvex] ingested net_conn on {host_id} egress={egress}; "
                        f"campaigns={len(store.all())}",
                        flush=True,
                    )
                    _after_ingest(
                        host_id=host_id,
                        feed=feed,
                        defended=defended,
                        store=store,
                        corr_note=f"Net event on {host_id} — correlator recomputing…",
                    )
                    _maybe_isolate(store=store, defended=defended, feed=feed)
                elif kind == "auth_blocked":
                    feed.append(
                        {
                            "ts": raw.get("ts_utc"),
                            "type": "blocked",
                            "host": host_id,
                            "text": f"Auth BLOCKED on {host_id} (Corvex isolate)",
                        }
                    )
                    update_theatre(
                        phase="CONTAINED",
                        caption=f"Attack blocked on {host_id} — defense holding",
                        feed=feed[-30:],
                        hosts={
                            h: {
                                "role": role,
                                "state": "isolated" if h in defended else "open",
                            }
                            for h, (_, role) in HOST_META.items()
                        },
                    )
                    print(f"[corvex] saw blocked auth on {host_id}", flush=True)

        # Exit when attack complete marker exists
        attacker_state = LAB / "attacker_state.json"
        if attacker_state.exists():
            try:
                st = json.loads(attacker_state.read_text(encoding="utf-8"))
                if st.get("kind") == "attack_complete":
                    update_theatre(
                        phase="DONE",
                        caption=(
                            f"Break-test complete — wave1 ok={st.get('wave1_successes')}, "
                            f"mid-chain blocked={st.get('blocked_mid_chain')}, "
                            f"wave2 blocked={st.get('wave2_blocked')}"
                        ),
                        outcome=st,
                        feed=feed[-40:],
                    )
                    write_json(
                        STATE,
                        {
                            "status": "done",
                            "ts": now(),
                            "campaigns": [c.to_dict() for c in store.all()],
                            "defended": sorted(defended),
                            "attacker": st,
                        },
                    )
                    print("[corvex] done", flush=True)
                    return
            except json.JSONDecodeError:
                pass
        time.sleep(0.2)

    write_json(STATE, {"status": "timeout", "ts": now(), "defended": sorted(defended)})
    print("[corvex] timeout", flush=True)


if __name__ == "__main__":
    main()
