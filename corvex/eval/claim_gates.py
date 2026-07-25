"""P3 claim gates — unlock 'useful on real attacks' only when integrity + evidence hold.

Gates (all required for claim_allowed):
1. non_author_fusion_lift — fusion beats detector-only on breaktest / public-TTP packs
2. stranger_success — human outsider with Ed25519 self-signature (stranger holds private key)
3. benign_fcr_real_n — held-out benign N >= min_n and FCR within bar
4. trust_integrity — functional probes (HMAC at Correlator.ingest, resign verify-first,
   dash does not embed snapshot, ingest rejects without enrollment)

Author-held HMAC attestations and unsigned JSON are advisory only.
Until all pass: claim_allowed=false. lab_verified may still be true for sealed/breaktest.
Never flip by dashboard toggle.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Optional, Tuple

from corvex.eval.attestation_crypto import stranger_signature_ok

MIN_BENIGN_N = 5
MAX_BENIGN_FCR = 0.10
MIN_FUSION_LIFT = 0.05


def _repo_rel(root: Path, path: Any) -> str:
    p = Path(path)
    try:
        return p.resolve().relative_to(Path(root).resolve()).as_posix()
    except (ValueError, OSError):
        text = str(path).replace("\\", "/")
        for marker in ("labs/", "reports/", "heldout/", "train/", "fixtures/"):
            idx = text.lower().find(marker)
            if idx >= 0:
                return text[idx:]
        return p.name


def _load(path: Path) -> Optional[Dict[str, Any]]:
    if not path.exists():
        return None
    return json.loads(path.read_text(encoding="utf-8"))


# Re-exports for CLI / tests
from corvex.eval.attestation_crypto import (  # noqa: E402
    attestation_key_path,
    load_attestation_hmac_secret as load_attestation_secret,
    sign_attestation_ed25519,
    sign_attestation_hmac as sign_attestation,
    stranger_private_key_path,
    verify_attestation_ed25519,
    verify_attestation_hmac as verify_attestation,
)


def _stranger_human_ok(stranger: Dict[str, Any]) -> Tuple[bool, str]:
    if not bool(stranger.get("pass")):
        return False, "Stranger attestation present but pass!=true"
    op = str(stranger.get("operator") or stranger.get("operator_id") or "").strip()
    op_l = op.lower()
    if not op or op_l in {"replace", "author", "self", "n/a", "none"}:
        return False, "FAIL: stranger operator missing or self/author placeholder"
    if "agent" in op_l or op_l.startswith("cursor-") or op_l.startswith("ci-"):
        return (
            False,
            f"FAIL: operator={op!r} looks like an agent/automation — "
            "claim_allowed requires an independent human (attestation_kind=human).",
        )
    kind = str(stranger.get("attestation_kind") or "").strip().lower()
    if kind and kind != "human":
        return False, f"FAIL: attestation_kind={kind!r} is not human"
    if kind != "human":
        return (
            False,
            "FAIL: set attestation_kind=human on stranger_dry_run.json "
            "(agent dry-runs do not qualify).",
        )
    return True, "Human stranger attestation shape ok"


def _probe_trust_integrity() -> Dict[str, Any]:
    from dataclasses import replace
    import tempfile

    from corvex.audit import AuditLog
    from corvex.auth import generate_lab_enrollment
    from corvex.correlator import Correlator
    from corvex.dashboard import render_html
    from corvex.envelope import sign_envelope
    from corvex.feeder import resign_events
    from corvex.store import CampaignStore

    checks: Dict[str, Any] = {}
    with tempfile.TemporaryDirectory() as td:
        root = Path(td)
        enr = generate_lab_enrollment({"host-a": "prod-a"})
        secret = enr.require("prod-a", "host-a")
        good = sign_envelope(
            producer_id="prod-a",
            host_id="host-a",
            payload_type="auth",
            payload={"user": "a", "result": "success"},
            secret=secret,
            event_id="e-good",
            ts_utc="2026-07-25T00:00:00Z",
            nonce="n1",
        )
        bad = replace(
            sign_envelope(
                producer_id="prod-a",
                host_id="host-a",
                payload_type="auth",
                payload={"user": "a", "result": "success"},
                secret=secret,
                event_id="e-bad",
                ts_utc="2026-07-25T00:00:01Z",
                nonce="n2",
            ),
            hmac="00" * 32,
        )
        store = CampaignStore(root / "c.jsonl")
        audit = AuditLog(root / "a.jsonl")
        corr = Correlator(store, audit, enrollment=enr)
        corr.ingest([good, bad])
        checks["correlator_ingest_rejects_bad_hmac"] = corr.hmac_rejected >= 1 and len(
            corr._events
        ) == 1

        bare = Correlator(
            CampaignStore(root / "c2.jsonl"),
            AuditLog(root / "a2.jsonl"),
        )
        bare.ingest([good])
        checks["correlator_rejects_without_enrollment"] = (
            bare.hmac_rejected >= 1 and len(bare._events) == 0
        )

        kept = resign_events([good], enr, allow_local_stamp=True)
        checks["resign_keeps_verified"] = (
            len(kept) == 1
            and kept[0].hmac == good.hmac
            and "_corvex_provenance" not in (kept[0].payload or {})
        )
        foreign = generate_lab_enrollment({"host-a": "prod-a"})
        stamped = resign_events([good], foreign, allow_local_stamp=True)
        checks["resign_tags_local_stamp"] = (
            len(stamped) == 1
            and (stamped[0].payload or {}).get("_corvex_provenance") == "locally_stamped"
        )

        html = render_html(
            {
                "version": "test",
                "product": {"version": "test"},
                "run": {"campaigns": [{"campaign_id": "SECRET-CAMP-XYZ"}]},
            },
            embed_snapshot=False,
        )
        checks["dash_boot_no_embed"] = "SECRET-CAMP-XYZ" not in html and "null" in html

    passed = all(bool(v) for v in checks.values())
    return {
        "id": "trust_integrity",
        "pass": passed,
        "checks": checks,
        "note": (
            "Functional probes green."
            if passed
            else "FAIL: one or more trust probes failed — claim locked."
        ),
    }


def evaluate_claim_gates(
    root: Path,
    *,
    min_benign_n: int = MIN_BENIGN_N,
    max_benign_fcr: float = MAX_BENIGN_FCR,
    min_fusion_lift: float = MIN_FUSION_LIFT,
) -> Dict[str, Any]:
    root = Path(root)
    reports = root / "reports"
    held = _load(reports / "stageA_heldout.json") or _load(reports / "stageA.json") or {}
    hm = (held.get("metrics") or {}) if held else {}
    corr = hm.get("correlator") or {}

    packs = held.get("packs") or []
    benign_packs = [p for p in packs if (p.get("family") == "benign")]
    n_benign = len(benign_packs)
    fcr = float(corr.get("false_campaign_rate") or 0.0)
    benign_gate = {
        "id": "benign_fcr_real_n",
        "pass": n_benign >= min_benign_n and fcr <= max_benign_fcr,
        "n_benign": n_benign,
        "min_n": min_benign_n,
        "false_campaign_rate": fcr,
        "max_fcr": max_benign_fcr,
        "note": (
            f"Held-out benign N={n_benign} (need >={min_benign_n}), FCR={fcr:.3f}."
            if held
            else "No held-out eval report — run corvex eval --split heldout first."
        ),
    }

    non_author = _load(reports / "non_author_fusion.json")
    if non_author:
        lift = float(non_author.get("f1_lift") or 0.0)
        non_author_gate = {
            "id": "non_author_fusion_lift",
            "pass": bool(non_author.get("pass")) and lift >= min_fusion_lift,
            "f1_lift": lift,
            "min_lift": min_fusion_lift,
            "source": (
                _repo_rel(root, non_author["source"])
                if non_author.get("source")
                else None
            ),
            "note": non_author.get("note")
            or "Loaded reports/non_author_fusion.json",
        }
    else:
        by_fam = ((held.get("by_family") or {}).get("correlator") or {})
        det_fam = ((held.get("by_family") or {}).get("detector_only") or {})
        fc = by_fam.get("fusion_chain") or {}
        fd = det_fam.get("fusion_chain") or {}
        soft_lift = float(fc.get("campaign_f1") or 0) - float(fd.get("campaign_f1") or 0)
        non_author_gate = {
            "id": "non_author_fusion_lift",
            "pass": False,
            "f1_lift": soft_lift,
            "min_lift": min_fusion_lift,
            "source": "heldout_fusion_chain_soft_probe",
            "note": (
                "FAIL: no reports/non_author_fusion.json. "
                f"Author-designed fusion_chain soft lift={soft_lift:+.3f} is NOT claim evidence. "
                "Run corvex score-non-author on breaktest/public TTP packs."
            ),
        }

    stranger_path = reports / "stranger_dry_run.json"
    stranger = _load(stranger_path)
    if stranger and "pass" in stranger:
        human_ok, human_note = _stranger_human_ok(stranger)
        sig_ok, custody, sig_note = stranger_signature_ok(stranger, root)
        if human_ok and sig_ok:
            stranger_gate = {
                "id": "stranger_success",
                "pass": True,
                "path": _repo_rel(root, stranger_path),
                "operator": stranger.get("operator") or stranger.get("operator_id"),
                "attestation_kind": stranger.get("attestation_kind"),
                "attestation_custody": custody,
                "attestation_signed": True,
                "note": stranger.get("note") or sig_note,
            }
        elif human_ok:
            stranger_gate = {
                "id": "stranger_success",
                "pass": False,
                "path": _repo_rel(root, stranger_path),
                "operator": stranger.get("operator") or stranger.get("operator_id"),
                "attestation_kind": stranger.get("attestation_kind"),
                "attestation_custody": custody,
                "attestation_signed": False,
                "advisory": True,
                "note": sig_note + " " + human_note,
            }
        else:
            stranger_gate = {
                "id": "stranger_success",
                "pass": False,
                "path": _repo_rel(root, stranger_path),
                "operator": stranger.get("operator") or stranger.get("operator_id"),
                "attestation_kind": stranger.get("attestation_kind"),
                "attestation_signed": False,
                "note": human_note,
            }
    elif stranger:
        stranger_gate = {
            "id": "stranger_success",
            "pass": False,
            "path": _repo_rel(root, stranger_path),
            "note": (
                "FAIL: reports/stranger_dry_run.json exists but lacks P3 schema field "
                "'pass' (legacy Stage-B file). Replace with docs/stranger-checklist.md attestation."
            ),
        }
    else:
        stranger_gate = {
            "id": "stranger_success",
            "pass": False,
            "path": _repo_rel(root, stranger_path),
            "note": (
                "FAIL: missing reports/stranger_dry_run.json. "
                "External operator must run Windows export→timeline and write attestation "
                "(see docs/stranger-checklist.md)."
            ),
        }

    integrity_gate = _probe_trust_integrity()
    live2 = _load(reports / "live_second_host.json") or {}
    live2_gate = {
        "id": "live_second_host",
        "pass": bool(live2.get("pass"))
        and str(live2.get("source") or "").lower() == "wevtutil"
        and bool(live2.get("host_id"))
        and bool(live2.get("security_events_seen")),
        "path": "reports/live_second_host.json",
        "note": (
            live2.get("note")
            if live2
            else (
                "FAIL: missing reports/live_second_host.json — elevated wevtutil on a "
                "second physical Windows host (see docs/trust-hardening.md)."
            )
        ),
    }

    gates = [non_author_gate, stranger_gate, benign_gate, integrity_gate, live2_gate]
    claim_allowed = all(bool(g.get("pass")) for g in gates)
    lab_verified = bool(non_author_gate.get("pass")) and bool(benign_gate.get("pass")) and bool(
        integrity_gate.get("pass")
    )
    if claim_allowed:
        language = "useful on real attacks"
    elif lab_verified:
        language = (
            "lab_verified — sealed held-out + breaktest + trust probes; "
            "need Ed25519 stranger self-sign + live second host for claim_allowed"
        )
    else:
        language = "lab / BYO campaign stitch only — claim locked"

    return {
        "schema_ver": "3",
        "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "claim_allowed": claim_allowed,
        "lab_verified": lab_verified,
        "claim_language": language,
        "gates": {g["id"]: g for g in gates},
        "honesty": (
            "Do not publish 'useful on real attacks' until claim_allowed=true. "
            "Author-held HMAC and unsigned stranger JSON are advisory. "
            "lab_verified means sealed/breaktest + trust probes only."
        ),
    }


def write_claim_gates(report: Dict[str, Any], path: Path) -> Path:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    return path
