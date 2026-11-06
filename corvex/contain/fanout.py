"""Signed IsolateHost fanout to SSH peers (lab scale-N bridge).

Peers file: ``~/.corvex/contain_peers.json``
  { "host-pc-2": {"ssh": "siddu@192.168.1.32", "identity": "~/.ssh/corvex_s2"}, ... }
"""

from __future__ import annotations

import json
import os
import subprocess
from pathlib import Path
from typing import Any, Dict, List, Mapping, Optional, Sequence

from corvex.contain.dry_run import ActionEnvelope, propose_action
from corvex.contain.policy import ContainPolicy, filter_soc, load_policy


DEFAULT_PEERS = Path.home() / ".corvex" / "contain_peers.json"


def peers_path() -> Path:
    env = os.environ.get("CORVEX_CONTAIN_PEERS", "").strip()
    return Path(env) if env else DEFAULT_PEERS


def load_peers(path: Optional[Path] = None) -> Dict[str, Dict[str, Any]]:
    p = path or peers_path()
    if not p.is_file():
        return {}
    try:
        raw = json.loads(p.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}
    if not isinstance(raw, dict):
        return {}
    return {str(k): (v if isinstance(v, dict) else {"ssh": str(v)}) for k, v in raw.items()}


def envelope_to_json(env: ActionEnvelope) -> str:
    return json.dumps(env.to_dict(), separators=(",", ":"))


def apply_local_from_envelope(
    envelope: Mapping[str, Any],
    *,
    root: Optional[Path] = None,
    authz_token: Optional[str] = None,
) -> Dict[str, Any]:
    """Apply a typed envelope on this host via live path (or dry-run)."""
    from corvex.contain.dry_run import ActionEnvelope as AE, ActionVerb
    from corvex.contain.live import execute_live

    verb = str(envelope.get("verb") or "")
    target = dict(envelope.get("target") or {})
    host_id = str(target.get("host_id") or "")
    rationale = str(envelope.get("rationale") or "fanout-apply")
    dry = bool(envelope.get("dry_run", True))

    # EstateLockdown is a scope, not an edge verb. The actuator is IsolateHost;
    # the scope rides in target["scope_verb"] so ActionVerb stays IsolateHost.
    if verb == "EstateLockdown":
        target = {**target, "host_id": host_id, "scope_verb": "EstateLockdown"}
        verb = "IsolateHost"

    allowed = {
        "IsolateHost",
        "ReleaseHost",
        "KillPid",
        "AddFirewallRule",
    }
    if verb not in allowed:
        return {
            "result": "refused",
            "enforced": False,
            "host_id": host_id,
            "honesty": f"Unknown verb {verb!r} — refuse (no coerce-to-IsolateHost).",
        }

    typed_verb: ActionVerb = verb  # type: ignore[assignment]
    env = AE(
        schema_ver=str(envelope.get("schema_ver") or "1"),
        verb=typed_verb,
        target=target if target else {"host_id": host_id},
        impact_class=str(envelope.get("impact_class") or "lab_soft"),
        dry_run=dry,
        idempotency_key=str(envelope.get("idempotency_key") or "fanout"),
        expiry=str(envelope.get("expiry") or ""),
        policy_version=str(envelope.get("policy_version") or "d0-draft"),
        rationale=rationale,
    )
    if dry:
        from corvex.contain.dry_run import execute_action

        return execute_action(env)
    # ReleaseHost and IsolateHost both go through execute_live gates — never
    # call release_local / isolate_local directly from the edge.
    from corvex.contain import ContainGateError

    try:
        return execute_live(env, root=root, authz_token=authz_token)
    except ContainGateError as exc:
        return {
            "result": "refused",
            "enforced": False,
            "host_id": host_id,
            "honesty": str(exc),
        }


def _ssh_apply(
    peer: Mapping[str, Any],
    envelope: Mapping[str, Any],
    *,
    remote_root: str = "C:/Users/siddu/corvex",
) -> Dict[str, Any]:
    import base64
    import re

    ssh_target = str(peer.get("ssh") or "")
    if not ssh_target or not re.fullmatch(r"[A-Za-z0-9_.@:-]+", ssh_target):
        return {"ok": False, "error": "peer ssh target missing or invalid"}
    identity = peer.get("identity")
    remote_root = str(peer.get("remote_root") or remote_root)
    # Strict Windows/Unix path: drive letters, alnum, slash, underscore, dash, dot only.
    if not re.fullmatch(r"(?:[A-Za-z]:)?[/\\][\w./\\-]+", remote_root.replace("\\", "/")):
        return {"ok": False, "error": "peer remote_root rejected"}
    if ".." in remote_root or any(c in remote_root for c in "&|<>^%\n\r\"'"):
        return {"ok": False, "error": "peer remote_root rejected"}
    # Base64 envelope + optional authz via env (never interpolate JSON into cmd).
    b64 = base64.b64encode(json.dumps(envelope, separators=(",", ":")).encode("utf-8")).decode(
        "ascii"
    )
    if not re.fullmatch(r"[A-Za-z0-9+/=]+", b64):
        return {"ok": False, "error": "envelope encoding rejected"}
    authz = os.environ.get("CORVEX_CONTAIN_AUTHZ", "").strip()
    # Remote: decode b64 argv → quarantine-apply. No shell metacharacters in path.
    root_safe = remote_root.replace("/", "\\") if ":" in remote_root[:3] else remote_root
    remote_cmd = (
        f"cd /d {root_safe} && "
        f"set CORVEX_CONTAIN_AUTHZ={authz}&& "
        f"python -c \"import base64,subprocess,sys;"
        f"e=base64.b64decode(sys.argv[1]).decode();"
        f"r=subprocess.run([sys.executable,'-m','corvex','quarantine-apply','--envelope-json',e]"
        f"+ (['--authz',sys.argv[2]] if len(sys.argv)>2 and sys.argv[2] else []);"
        f"capture_output=True,text=True);"
        f"sys.stdout.write(r.stdout);sys.stderr.write(r.stderr);raise SystemExit(r.returncode)\" "
        f"{b64} {authz}"
    )
    cmd = ["ssh", "-o", "BatchMode=yes", "-o", "ConnectTimeout=20", "-o", "IdentitiesOnly=yes"]
    if identity:
        cmd.extend(["-i", str(Path(str(identity)).expanduser())])
    cmd.extend([ssh_target, remote_cmd])
    proc = subprocess.run(cmd, capture_output=True, text=True, timeout=120, check=False)
    out = (proc.stdout or "").strip()
    err = (proc.stderr or "").strip()
    parsed: Any = None
    try:
        # last JSON object in stdout
        if out.startswith("{"):
            parsed = json.loads(out)
        else:
            idx = out.rfind("\n{")
            if idx >= 0:
                parsed = json.loads(out[idx + 1 :])
            elif "{" in out:
                parsed = json.loads(out[out.find("{") :])
    except json.JSONDecodeError:
        parsed = None
    return {
        "ok": proc.returncode == 0 and bool(parsed),
        "returncode": proc.returncode,
        "ssh": ssh_target,
        "result": parsed,
        "stdout_tail": out[-800:],
        "stderr_tail": err[-400:],
    }


def _row_enforced(row: Mapping[str, Any]) -> bool:
    """True when this host row or its nested apply result actually enforced."""
    if row.get("enforced"):
        return True
    nested = row.get("result")
    return bool(isinstance(nested, Mapping) and nested.get("enforced"))


def fanout_isolate(
    host_ids: Sequence[str],
    *,
    rationale: str,
    dry_run: bool = True,
    authz_token: Optional[str] = None,
    policy: Optional[ContainPolicy] = None,
    peers: Optional[Mapping[str, Mapping[str, Any]]] = None,
    verb: str = "IsolateHost",
    root: Optional[Path] = None,
) -> Dict[str, Any]:
    """Propose/apply IsolateHost (or EstateLockdown per-host) across peers + local."""
    from corvex.contain.windows_firewall import local_host_id

    pol = policy or load_policy()
    targets = filter_soc(list(host_ids), pol)
    peer_map = dict(peers) if peers is not None else load_peers()
    local = local_host_id()
    rows: List[Dict[str, Any]] = []

    for hid in targets:
        env = propose_action(
            "IsolateHost",  # EstateLockdown expands to per-host IsolateHost at edge
            {"host_id": hid, "scope_verb": verb},
            rationale=rationale,
        )
        payload = env.to_dict()
        payload["dry_run"] = dry_run
        if not dry_run:
            payload["dry_run"] = False

        if hid.lower() == local.lower() or hid in {
            a.strip() for a in os.environ.get("CORVEX_LOCAL_HOST_ALIASES", "").split(",") if a.strip()
        }:
            rec = apply_local_from_envelope(payload, root=root, authz_token=authz_token)
            rows.append({"host_id": hid, "channel": "local", **rec})
            continue

        peer = peer_map.get(hid)
        if not peer:
            rows.append(
                {
                    "host_id": hid,
                    "channel": "none",
                    "result": "no_peer",
                    "enforced": False,
                    "honesty": f"No contain_peers entry for {hid}; cannot fanout.",
                }
            )
            continue
        if dry_run:
            rows.append(
                {
                    "host_id": hid,
                    "channel": "ssh",
                    "result": "dry_run_fanout_planned",
                    "enforced": False,
                    "ssh": peer.get("ssh"),
                    "envelope": payload,
                    "honesty": "SSH fanout dry-run — remote firewall not mutated.",
                }
            )
            continue
        ssh_res = _ssh_apply(peer, payload)
        rows.append({"host_id": hid, "channel": "ssh", **ssh_res})

    enforced = sum(1 for r in rows if _row_enforced(r))
    no_peer = sum(1 for r in rows if r.get("result") == "no_peer")
    if dry_run:
        # Success only if every target was planned or locally dry-logged — not
        # if the entire fanout is missing peers.
        ok = len(rows) > 0 and no_peer < len(rows)
    else:
        ok = len(targets) > 0 and enforced == len(targets)
    return {
        "ok": ok,
        "verb": verb,
        "dry_run": dry_run,
        "n": len(rows),
        "enforced_count": enforced,
        "no_peer_count": no_peer,
        "hosts": rows,
        "soc_preserved": list(pol.soc_allowlist or []),
    }
