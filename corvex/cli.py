"""CLI: corvex replay | eval | timeline | reconstruct | quarantine | ingest-byo | adapt-windows | build-breaktest | dash | seal-day0 | freeze."""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import tempfile
import time
from pathlib import Path
from typing import Any, Dict, List, Optional

import typer

from corvex.audit import AuditLog
from corvex.auth import (
    default_secrets_path,
    generate_lab_enrollment,
    load_enrollment,
    save_enrollment,
)
from corvex.baselines import baseline_b1, baseline_b2
from corvex.bus import JsonlBus
from corvex.correlator import Correlator, CorrelatorConfig
from corvex.eval import (
    aggregate_by_family,
    aggregate_isolate_dry_run,
    aggregate_scores,
    evaluate_pass,
    score_pack,
    vs_baseline_lift,
)
from corvex.feeder import (
    feed_bus,
    generate_campaign_events,
    load_pack_events,
    resign_events,
    write_pack,
)
from corvex.ingest import ingest_byo
from corvex.lab_enroll import DEMO_HOSTS, ensure_lab_enrollment
from corvex.seal import (
    ensure_key,
    key_path,
    scorer_rules_blob,
    seal_file,
    unseal_file,
    write_sealed_manifest,
)
from corvex.store import CampaignStore

app = typer.Typer(add_completion=False, no_args_is_help=True)
_PKG_ROOT = Path(__file__).resolve().parents[1]


def _repo_root() -> Path:
    """Prefer CORVEX_ROOT, then cwd if it looks like the checkout, else editable package parent."""
    env = os.environ.get("CORVEX_ROOT")
    if env:
        return Path(env).resolve()
    cwd = Path.cwd().resolve()
    if (cwd / "pyproject.toml").exists() and (
        (cwd / "corvex").is_dir() or (cwd / "train").is_dir()
    ):
        return cwd
    return _PKG_ROOT


@app.command("init")
def init_cmd(
    force: bool = typer.Option(False, help="Overwrite existing lab enrollment"),
) -> None:
    """Create a local lab enrollment under ~/.corvex/ (required for replay / ingest)."""
    path = default_secrets_path()
    if path.exists() and not force:
        typer.echo(f"enrollment already present: {path}")
        typer.echo("pass --force to regenerate")
        return
    enrollment = generate_lab_enrollment(DEMO_HOSTS)
    save_enrollment(path, enrollment)
    typer.echo(f"wrote lab enrollment: {path}")
    typer.echo("secrets stay outside the repo — do not commit this file")


@app.command("seal-day0")
def seal_day0(
    force: bool = typer.Option(False, help="Regenerate train/heldout from scratch"),
) -> None:
    """Enrollment, train packs, encrypt held-out, write SEALED.sha256."""
    root = _repo_root()
    train_dir = root / "train"
    heldout_dir = root / "heldout"
    if force and train_dir.exists():
        shutil.rmtree(train_dir)
    if force and heldout_dir.exists():
        shutil.rmtree(heldout_dir)
    train_dir.mkdir(parents=True, exist_ok=True)
    heldout_dir.mkdir(parents=True, exist_ok=True)

    hosts = {
        "host-a": "prod-a",
        "host-b": "prod-b",
        "host-c": "prod-c",
        "host-d": "prod-d",
        "host-e": "prod-e",
    }
    enrollment = generate_lab_enrollment(hosts)
    save_enrollment(default_secrets_path(), enrollment)

    from datetime import datetime, timezone

    base = datetime(2026, 1, 15, 12, 0, 0, tzinfo=timezone.utc)
    host_pairs = [(h, p) for h, p in hosts.items()]

    # Train packs — includes fusion_chain (5 hosts) where detector-only must lose
    train_specs = [
        ("train-lateral", "lateral", host_pairs[:3], False),
        ("train-exfil", "exfil", host_pairs[1:4], False),
        ("train-recon-lateral", "recon_lateral", host_pairs[:3], False),
        ("train-fusion-chain", "fusion_chain", host_pairs[:5], False),
        ("train-benign-a", "benign", host_pairs[:3], False),
        ("train-benign-b", "benign", host_pairs[1:4], False),
    ]
    for cid, family, hs, ood in train_specs:
        events, gt = generate_campaign_events(
            campaign_id=cid,
            family=family,
            hosts=hs,
            enrollment=enrollment,
            base_time=base,
            ood=ood,
        )
        write_pack(train_dir / f"{cid}.jsonl", events, gt)

    # BYO fixture: same export→envelope path as Feeder (first 20 events)
    byo_dir = root / "fixtures"
    byo_dir.mkdir(parents=True, exist_ok=True)
    sample_events, _ = generate_campaign_events(
        campaign_id="byo-sample",
        family="lateral",
        hosts=host_pairs[:3],
        enrollment=enrollment,
        base_time=base,
    )
    with (byo_dir / "byo_export_sample.jsonl").open("w", encoding="utf-8") as fh:
        for env in sample_events[:20]:
            fh.write(json.dumps(env.to_dict(), separators=(",", ":")) + "\n")

    # Held-out plaintext in temp, then seal: ≥2 including ≥1 OOD + multiple benign
    key = ensure_key()
    rules_path = heldout_dir / "scorer_rules.json"
    rules_path.write_text(scorer_rules_blob(), encoding="utf-8")

    heldout_specs = [
        ("held-lateral-ood", "lateral", host_pairs[:3], True),
        ("held-exfil", "exfil", host_pairs[1:4], False),
        ("held-fusion-chain", "fusion_chain", host_pairs[:5], True),
        ("held-benign-a", "benign", host_pairs[:3], False),
        ("held-benign-b", "benign", host_pairs[1:4], False),
        ("held-benign-c", "benign", host_pairs[2:5], False),
        ("held-benign-d", "benign", host_pairs[:4], False),
        ("held-benign-e", "benign", host_pairs[0:5:2], False),
    ]
    digests = []
    with tempfile.TemporaryDirectory() as tmp:
        tmp_path = Path(tmp)
        for cid, family, hs, ood in heldout_specs:
            events, gt = generate_campaign_events(
                campaign_id=cid,
                family=family,
                hosts=hs,
                enrollment=enrollment,
                base_time=base,
                ood=ood,
            )
            plain = tmp_path / f"{cid}.jsonl"
            write_pack(plain, events, gt)
            sealed = heldout_dir / f"{cid}.jsonl.sealed"
            digest = seal_file(plain, sealed, key)
            digests.append((sealed.name, digest))
        # seal scorer rules too
        rules_sealed = heldout_dir / "scorer_rules.json.sealed"
        digest = seal_file(rules_path, rules_sealed, key)
        digests.append((rules_sealed.name, digest))
        # remove plaintext rules from heldout (keep sealed only)
        rules_path.unlink(missing_ok=True)

    agg = write_sealed_manifest(heldout_dir, digests)
    stamp = root / "heldout" / "SEALED.PUBLISH.txt"
    stamp.write_text(
        f"aggregate_sha256={agg}\npublished_before_correlator=true\n",
        encoding="utf-8",
    )
    # Immutable-ish local note (git note substitute for solo)
    notes = root / ".git"
    typer.echo(f"Seal complete. Key: {key_path()}")
    typer.echo(f"SEALED aggregate: {agg}")
    typer.echo(f"Enrollment: {default_secrets_path()}")


@app.command("replay")
def replay(
    pack: Path = typer.Argument(..., help="Train pack JSONL"),
    out_dir: Path = typer.Option(Path("runs/replay"), help="Output run directory"),
    ablation_no_cross: bool = typer.Option(False, help="Disable cross-host fusion"),
    detector_only: bool = typer.Option(False, help="Detector alerts path only"),
) -> None:
    """Run correlator on a pack and write campaign store + timeline."""
    enrollment = ensure_lab_enrollment()
    events, gt = load_pack_events(pack)
    # Committed train packs were signed with a prior enrollment — re-HMAC for this machine.
    events = resign_events(events, enrollment)
    out_dir = Path(out_dir)
    if out_dir.exists():
        shutil.rmtree(out_dir)
    out_dir.mkdir(parents=True)
    bus = JsonlBus(out_dir / "events.jsonl")
    feed_bus(bus, events, enrollment)
    store = CampaignStore(out_dir / "campaigns.jsonl")
    audit = AuditLog(out_dir / "audit.jsonl")
    cfg = CorrelatorConfig(cross_host_enabled=not ablation_no_cross)
    corr = Correlator(store, audit, cfg, detector_only=detector_only)
    t0 = time.perf_counter()
    corr.ingest(events)
    ttu = time.perf_counter() - t0
    timeline = {
        "pack": str(pack),
        "ground_truth": gt,
        "ttu_seconds": ttu,
        "campaigns": [c.to_dict() for c in store.all()],
    }
    (out_dir / "timeline.json").write_text(json.dumps(timeline, indent=2), encoding="utf-8")
    from corvex.contain.quarantine import resolve_quarantine_mode
    from corvex.reconstruct import write_reconstruction

    qmode = resolve_quarantine_mode(root=_repo_root())["mode"]
    recon_path = write_reconstruction(out_dir, quarantine_mode=qmode)
    # Pointer so `corvex dash` can show the latest replay without extra flags.
    latest = _repo_root() / "runs" / "latest"
    latest.parent.mkdir(parents=True, exist_ok=True)
    try:
        if latest.exists() or latest.is_symlink():
            latest.unlink()
        latest.symlink_to(out_dir.resolve(), target_is_directory=True)
    except OSError:
        latest.write_text(str(out_dir.resolve()), encoding="utf-8")
    typer.echo(
        json.dumps(
            {
                "campaigns": len(store.all()),
                "ttu_seconds": ttu,
                "out_dir": str(out_dir),
                "reconstruction": str(recon_path),
            },
            indent=2,
        )
    )


@app.command("timeline")
def timeline(
    run_dir: Path = typer.Argument(..., help="Run directory with timeline.json"),
) -> None:
    path = Path(run_dir) / "timeline.json"
    if not path.exists():
        raise typer.BadParameter(f"missing {path}")
    typer.echo(path.read_text(encoding="utf-8"))


@app.command("reconstruct")
def reconstruct_cmd(
    run_dir: Path = typer.Argument(..., help="Run directory with timeline.json"),
) -> None:
    """Rebuild attack timeline from campaigns — honest gaps, no invented TTPs."""
    from corvex.contain.quarantine import resolve_quarantine_mode
    from corvex.reconstruct import write_reconstruction

    qmode = resolve_quarantine_mode(root=_repo_root())["mode"]
    out = write_reconstruction(Path(run_dir), quarantine_mode=qmode)
    report = json.loads(out.read_text(encoding="utf-8"))
    typer.echo(
        json.dumps(
            {
                "out": str(out),
                "aggregate_status": report.get("aggregate_status"),
                "summary": report.get("summary"),
                "honesty": report.get("honesty"),
            },
            indent=2,
        )
    )


@app.command("quarantine")
def quarantine_cmd(
    hosts: str = typer.Argument(..., help="Comma-separated host_ids"),
    rationale: str = typer.Option(..., "--rationale"),
    lab_dir: Optional[Path] = typer.Option(
        None, "--lab-dir", help="Lab shared dir (enables lab_flag isolate)"
    ),
    log: Path = typer.Option(Path("reports/stage_d_dry_run.jsonl"), help="Dry-run log path"),
) -> None:
    """Attempt isolate/quarantine — dry-run, lab flags, or honest refusal."""
    from corvex.contain.quarantine import attempt_quarantine

    host_ids = [h.strip() for h in hosts.split(",") if h.strip()]
    result = attempt_quarantine(
        host_ids,
        rationale=rationale,
        lab_dir=lab_dir,
        log_path=log,
        root=_repo_root(),
    )
    typer.echo(json.dumps(result, indent=2))
    if not result.get("ok") and result.get("aggregate") == "cannot_quarantine":
        raise typer.Exit(2)


@app.command("quarantine-status")
def quarantine_status_cmd() -> None:
    """Honest quarantine capability (dry-run / lab_flag / blocked)."""
    from corvex.contain.quarantine import resolve_quarantine_mode

    typer.echo(json.dumps(resolve_quarantine_mode(root=_repo_root()), indent=2))


@app.command("eval-recon")
def eval_recon_cmd(
    split: str = typer.Option("train", help="train|heldout"),
    report: Path = typer.Option(Path("reports/reconstruction_regression.json")),
) -> None:
    """Reconstruction→manifest regression on sealed/train packs (honesty engine)."""
    from corvex.eval.recon_regression import run_recon_regression, write_recon_regression
    from corvex.seal import ensure_key, unseal_file

    root = _repo_root()
    enrollment = load_enrollment(default_secrets_path())
    packs: List[Path] = []
    tmp_keep = None
    if split == "train":
        packs = sorted((root / "train").glob("*.jsonl"))
    else:
        key = ensure_key()
        tmp_keep = tempfile.TemporaryDirectory()
        tmp = Path(tmp_keep.name)
        for sealed in sorted((root / "heldout").glob("*.jsonl.sealed")):
            plain = tmp / sealed.name.replace(".sealed", "")
            plain.write_bytes(unseal_file(sealed, key))
            packs.append(plain)
    if not packs:
        raise typer.Exit("no packs — run corvex seal-day0 first")
    result = run_recon_regression(packs, enrollment)
    write_recon_regression(result, Path(report))
    typer.echo(json.dumps({k: result[k] for k in ("pass", "n_ok", "n_packs", "attack_ok", "benign_ok", "honesty") if k in result}, indent=2))
    if tmp_keep:
        tmp_keep.cleanup()
    raise typer.Exit(0 if result.get("pass") else 1)


@app.command("claim-gates")
def claim_gates_cmd(
    report: Path = typer.Option(Path("reports/claim_gates.json")),
) -> None:
    """Evaluate P3 claim gates — claim_allowed stays false until all pass."""
    from corvex.eval.claim_gates import evaluate_claim_gates, write_claim_gates

    result = evaluate_claim_gates(_repo_root())
    write_claim_gates(result, Path(report))
    typer.echo(json.dumps(result, indent=2))
    raise typer.Exit(0 if result.get("claim_allowed") else 1)


@app.command("score-non-author")
def score_non_author_cmd(
    manifests: Optional[Path] = typer.Option(
        None,
        help="Directory of breaktest/public TTP manifests (default: labs/breaktest/manifests)",
    ),
    report: Path = typer.Option(Path("reports/non_author_fusion.json")),
) -> None:
    """Score fusion vs detector-only on public-TTP/breaktest manifests (P3 gate input)."""
    from corvex.adapters.attack_repos import adapt_attack_manifest, load_manifest
    from corvex.envelope import sign_envelope
    from corvex.eval import aggregate_scores, score_pack, vs_baseline_lift

    root = _repo_root()
    man_dir = Path(manifests) if manifests else root / "labs" / "breaktest" / "manifests"
    enrollment = ensure_lab_enrollment()
    if not man_dir.is_dir():
        raise typer.Exit(f"missing manifests dir {man_dir}")
    corr_scores = []
    det_scores = []
    pack_rows = []
    for path in sorted(man_dir.glob("*.json")):
        man = load_manifest(path)
        raw_events, gt = adapt_attack_manifest(man)
        signed = []
        for rec in raw_events:
            secret = enrollment.require(rec["producer_id"], rec["host_id"])
            signed.append(
                sign_envelope(
                    producer_id=rec["producer_id"],
                    host_id=rec["host_id"],
                    payload_type=rec["payload_type"],
                    payload=rec["payload"],
                    secret=secret,
                    event_id=rec["event_id"],
                    ts_utc=rec["ts_utc"],
                    nonce=rec["nonce"],
                )
            )
        benign = gt.get("family") == "benign"
        pred_c, ttu_c = _predict_from_events(signed, "raw")
        pred_d, ttu_d = _predict_from_events(signed, "detector_only")
        corr_scores.append(score_pack(pred_c, gt, ttu_seconds=ttu_c, benign=benign))
        det_scores.append(score_pack(pred_d, gt, ttu_seconds=ttu_d, benign=benign))
        pack_rows.append(path.name)
    if not corr_scores:
        raise typer.Exit("no manifests scored")
    m_c = aggregate_scores(corr_scores)
    m_d = aggregate_scores(det_scores)
    lift = vs_baseline_lift(m_c, m_d)
    f1_lift = float(lift.get("f1_lift") or 0.0)
    # Author-adjacent ART manifests still aren't stranger telemetry — require lift AND label honesty
    passed = f1_lift >= 0.05
    result = {
        "source": str(man_dir),
        "packs": pack_rows,
        "correlator": m_c,
        "detector_only": m_d,
        "f1_lift": f1_lift,
        "pass": passed,
        "note": (
            "Public-TTP/breaktest manifest score. Still not stranger Windows telemetry — "
            "necessary but not sufficient for claim_allowed."
            if passed
            else "Fusion lift < 0.05 on breaktest manifests — gate stays closed."
        ),
        "honesty": "Breaktest manifests are public-TTP shaped, not independent enterprise traffic.",
    }
    Path(report).parent.mkdir(parents=True, exist_ok=True)
    Path(report).write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    typer.echo(json.dumps(result, indent=2))
    raise typer.Exit(0 if passed else 1)


@app.command("correlate-byo")
def correlate_byo_cmd(
    path: Path = typer.Argument(..., help="Signed BYO JSONL"),
    out_dir: Path = typer.Option(Path("runs/byo"), help="Output run directory"),
) -> None:
    """Correlate signed BYO events → timeline + reconstruction (Windows wedge)."""
    from corvex.contain.quarantine import resolve_quarantine_mode
    from corvex.ingest import load_byo_jsonl
    from corvex.reconstruct import write_reconstruction

    enrollment = ensure_lab_enrollment()
    events = load_byo_jsonl(Path(path))
    events = resign_events(events, enrollment)
    out_dir = Path(out_dir)
    if out_dir.exists():
        shutil.rmtree(out_dir)
    out_dir.mkdir(parents=True)
    bus = JsonlBus(out_dir / "events.jsonl")
    feed_bus(bus, events, enrollment)
    store = CampaignStore(out_dir / "campaigns.jsonl")
    audit = AuditLog(out_dir / "audit.jsonl")
    t0 = time.perf_counter()
    Correlator(store, audit).ingest(events)
    ttu = time.perf_counter() - t0
    timeline = {
        "pack": str(path),
        "ground_truth": None,
        "ttu_seconds": ttu,
        "campaigns": [c.to_dict() for c in store.all()],
        "source": "byo",
    }
    (out_dir / "timeline.json").write_text(json.dumps(timeline, indent=2), encoding="utf-8")
    qmode = resolve_quarantine_mode(root=_repo_root())["mode"]
    recon_path = write_reconstruction(out_dir, quarantine_mode=qmode)
    latest = _repo_root() / "runs" / "latest"
    latest.parent.mkdir(parents=True, exist_ok=True)
    try:
        if latest.exists() or latest.is_symlink():
            latest.unlink()
        latest.symlink_to(out_dir.resolve(), target_is_directory=True)
    except OSError:
        latest.write_text(str(out_dir.resolve()), encoding="utf-8")
    typer.echo(
        json.dumps(
            {
                "campaigns": len(store.all()),
                "ttu_seconds": ttu,
                "out_dir": str(out_dir),
                "reconstruction": str(recon_path),
            },
            indent=2,
        )
    )


@app.command("byo-windows")
def byo_windows_cmd(
    export: Path = typer.Argument(..., help="Windows Security JSON/JSONL export"),
    out_dir: Path = typer.Option(Path("runs/windows-wedge"), help="Run output"),
    host_map: Optional[Path] = typer.Option(
        None, "--host-map", help="JSON map Computer→host_id (e.g. fixtures/windows_host_map.json)"
    ),
    default_host: str = typer.Option("host-a"),
) -> None:
    """Full wedge: Windows 4624 export → adapt → correlate → reconstruct."""
    # Reuse adapt-windows logic then correlate-byo
    adapted = Path(out_dir) / "windows_auth.jsonl"
    # Call adapt inline
    from corvex.adapters.windows_security import adapt_windows_security_export
    from corvex.envelope import sign_envelope

    enrollment = ensure_lab_enrollment()
    hmap: Dict[str, str] = {h: h for h in DEMO_HOSTS}
    if host_map and Path(host_map).exists():
        loaded = json.loads(Path(host_map).read_text(encoding="utf-8"))
        if isinstance(loaded, dict):
            hmap.update({str(k).lower(): str(v) for k, v in loaded.items()})
            hmap.update({str(k): str(v) for k, v in loaded.items()})
    raw = adapt_windows_security_export(
        Path(export),
        producer_id=DEMO_HOSTS.get(default_host, "prod-a"),
        default_host=default_host,
        host_map=hmap,
    )
    adapted.parent.mkdir(parents=True, exist_ok=True)
    n = 0
    with adapted.open("w", encoding="utf-8") as fh:
        for rec in raw:
            host_id = str(rec["host_id"])
            # Apply map values that point at enrolled hosts
            if host_id not in DEMO_HOSTS:
                # try lowercase computer already mapped
                mapped = hmap.get(host_id) or hmap.get(host_id.lower())
                host_id = mapped if mapped in DEMO_HOSTS else default_host
            prod = DEMO_HOSTS[host_id]
            secret = enrollment.require(prod, host_id)
            env = sign_envelope(
                producer_id=prod,
                host_id=host_id,
                payload_type=rec["payload_type"],
                payload=rec["payload"],
                secret=secret,
                event_id=rec["event_id"],
                ts_utc=rec["ts_utc"],
                nonce=rec["nonce"],
            )
            fh.write(json.dumps(env.to_dict(), separators=(",", ":")) + "\n")
            n += 1
    if n == 0:
        raise typer.Exit("no 4624 events adapted — check export")
    # Correlate into out_dir (correlate-byo clears out_dir — preserve adapted by writing to subpath first)
    auth_copy = Path(tempfile.mkdtemp()) / "windows_auth.jsonl"
    shutil.copy(adapted, auth_copy)
    correlate_byo_cmd(auth_copy, out_dir=Path(out_dir))
    # Restore adapted artifact into out_dir
    shutil.copy(auth_copy, Path(out_dir) / "windows_auth.jsonl")
    typer.echo(json.dumps({"adapted": n, "out_dir": str(out_dir)}, indent=2))


@app.command("hostile-bus-test")
def hostile_bus_test_cmd(
    report: Path = typer.Option(Path("reports/hostile_bus_selftest.json")),
) -> None:
    """Run hostile-bus selftest (P4 gate evidence) — does not unlock OS quarantine."""
    from corvex.contain.hostile_bus import write_hostile_bus_report

    with tempfile.TemporaryDirectory() as tmp:
        result = write_hostile_bus_report(_repo_root(), Path(tmp))
    # Allow custom report path override
    if Path(report).resolve() != (_repo_root() / "reports" / "hostile_bus_selftest.json").resolve():
        Path(report).parent.mkdir(parents=True, exist_ok=True)
        Path(report).write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    typer.echo(json.dumps(result, indent=2))
    raise typer.Exit(0 if result.get("pass") else 1)


@app.command("ingest-byo")
def ingest_byo_cmd(
    path: Path = typer.Argument(..., help="BYO JSONL envelopes"),
    out_bus: Path = typer.Option(Path("runs/byo/events.jsonl")),
) -> None:
    enrollment = ensure_lab_enrollment()
    bus = JsonlBus(out_bus)
    n = ingest_byo(bus, path, enrollment)
    typer.echo(f"ingested {n} events into {out_bus}")


def _predict_from_events(events, mode: str) -> tuple:
    from corvex.envelope import EventEnvelope

    dicts = [e.to_dict() if isinstance(e, EventEnvelope) else e for e in events]
    t0 = time.perf_counter()
    if mode == "b1":
        camps = baseline_b1(dicts)
    elif mode == "b2":
        camps = baseline_b2(dicts)
    elif mode == "detector_only":
        store = CampaignStore(Path(tempfile.mkdtemp()) / "c.jsonl")
        audit = AuditLog(Path(tempfile.mkdtemp()) / "a.jsonl")
        corr = Correlator(store, audit, detector_only=True)
        corr.ingest(events)
        camps = store.all()
    elif mode == "ablate":
        store = CampaignStore(Path(tempfile.mkdtemp()) / "c.jsonl")
        audit = AuditLog(Path(tempfile.mkdtemp()) / "a.jsonl")
        corr = Correlator(store, audit, CorrelatorConfig(cross_host_enabled=False))
        corr.ingest(events)
        camps = store.all()
    else:
        store = CampaignStore(Path(tempfile.mkdtemp()) / "c.jsonl")
        audit = AuditLog(Path(tempfile.mkdtemp()) / "a.jsonl")
        corr = Correlator(store, audit)
        corr.ingest(events)
        camps = store.all()
    ttu = time.perf_counter() - t0
    return [c.to_dict() for c in camps], ttu


@app.command("eval")
def eval_cmd(
    split: str = typer.Option("heldout", help="train|heldout"),
    report_dir: Path = typer.Option(Path("reports")),
) -> None:
    """One-shot eval. Held-out decrypts with external key; writes PASS/FAIL report."""
    root = _repo_root()
    report_dir = Path(report_dir)
    report_dir.mkdir(parents=True, exist_ok=True)
    enrollment = load_enrollment(default_secrets_path())

    packs: List[Path] = []
    tmp_keep = None
    if split == "train":
        packs = sorted((root / "train").glob("*.jsonl"))
    else:
        key = ensure_key()
        tmp_keep = tempfile.TemporaryDirectory()
        tmp = Path(tmp_keep.name)
        for sealed in sorted((root / "heldout").glob("*.jsonl.sealed")):
            plain = tmp / sealed.name.replace(".sealed", "")
            plain.write_bytes(unseal_file(sealed, key))
            packs.append(plain)
        # verify scorer rules sealed
        rules_sealed = root / "heldout" / "scorer_rules.json.sealed"
        if rules_sealed.exists():
            _ = unseal_file(rules_sealed, key)

    if not packs:
        raise typer.Exit("no packs found — run `corvex seal-day0` first")

    # Freeze manifest of source files
    manifest = {
        "correlator_sha": _file_sha(root / "corvex" / "correlator.py"),
        "detectors_sha": _file_sha(root / "corvex" / "detectors.py"),
        "scorer_sha": _file_sha(root / "corvex" / "eval" / "__init__.py"),
        "b2_sha": _file_sha(root / "corvex" / "baselines.py"),
        "config_sha": hashlib.sha256(b"window=600;min_hosts=2").hexdigest(),
    }

    modes = ["correlator", "b1", "b2", "detector_only"]
    per_mode: Dict[str, List] = {m: [] for m in modes}

    mode_alias = {
        "correlator": "raw",
        "b1": "b1",
        "b2": "b2",
        "detector_only": "detector_only",
    }
    pack_meta: List[Dict[str, Any]] = []
    for pack in packs:
        events, gt = load_pack_events(pack)
        benign = gt.get("family") == "benign"
        pack_meta.append(
            {
                "pack": pack.name,
                "family": gt.get("family"),
                "ood": bool(gt.get("ood")),
            }
        )
        for mode in modes:
            pred, ttu = _predict_from_events(events, mode_alias[mode])
            per_mode[mode].append(score_pack(pred, gt, ttu_seconds=ttu, benign=benign))

    metrics = {m: aggregate_scores(per_mode[m]) for m in modes}
    by_family = {
        m: aggregate_by_family(per_mode[m]) for m in modes
    }
    contain_dry_run = aggregate_isolate_dry_run(per_mode["correlator"])
    vs_b1 = vs_baseline_lift(metrics["correlator"], metrics["b1"])
    ablation = {
        "raw_f1": metrics["correlator"]["campaign_f1"],
        "detector_only_f1": metrics["detector_only"]["campaign_f1"],
        "b1_f1": metrics["b1"]["campaign_f1"],
        "b2_f1": metrics["b2"]["campaign_f1"],
        "correlator_precision": metrics["correlator"]["precision"],
        "correlator_recall": metrics["correlator"]["recall"],
        "b1_precision": metrics["b1"]["precision"],
        "b1_recall": metrics["b1"]["recall"],
    }
    # B2 train floor check when split=train
    b2_train_ok = True
    if split == "train":
        b2_train_ok = metrics["b2"]["campaign_f1"] >= 0.40

    passed, reasons = evaluate_pass(
        metrics["correlator"],
        metrics["b2"],
        ablation,
        contain_metrics=contain_dry_run,
    )
    if split == "train" and not b2_train_ok:
        passed = False
        reasons.append("B2 train F1 < 0.40 (sandbag)")

    result = {
        "split": split,
        "pass": passed,
        "gate": {"pass": passed, "reasons": reasons},
        "reasons": reasons,
        "metrics": metrics,
        "by_family": by_family,
        "vs_b1": vs_b1,
        "contain_dry_run": contain_dry_run,
        "packs": pack_meta,
        "ablation": ablation,
        "freeze_manifest": manifest,
        "care_vs_incumbent": "unproven",
        "care_banner": "care vs incumbent unproven",
        "ood_note": "OOD packs are author-designed; no generalization claim beyond lab grammar.",
        "b2_train_floor_ok": b2_train_ok,
    }
    (report_dir / f"stageA_{split}.json").write_text(
        json.dumps(result, indent=2), encoding="utf-8"
    )
    if split == "heldout":
        (report_dir / "stageA.json").write_text(json.dumps(result, indent=2), encoding="utf-8")
    md = _render_report(result)
    out_md = report_dir / ("stageA.md" if split == "heldout" else f"stageA_{split}.md")
    out_md.write_text(md, encoding="utf-8")

    # Gate tag helper
    gate = report_dir / "stageA-gate.txt"
    if split == "heldout":
        gate.write_text("PASS\n" if passed else "FAIL\n", encoding="utf-8")
    typer.echo(md)
    if tmp_keep:
        tmp_keep.cleanup()
    raise typer.Exit(code=0 if passed or split == "train" else 1)


def _file_sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _render_report(result: Dict[str, Any]) -> str:
    status = "PASS" if result["pass"] else "FAIL"
    c = result["metrics"]["correlator"]
    b1 = result["metrics"]["b1"]
    lines = [
        f"# Eval report ({result['split']}) — **{status}**",
        "",
        f"Care vs incumbent: **{result.get('care_vs_incumbent', 'unproven')}**",
        "",
        "## Detection (publish P+R, not a lone accuracy)",
        f"- precision **{c.get('precision', 0):.3f}** · recall **{c.get('recall', 0):.3f}** · F1 **{c.get('campaign_f1', 0):.3f}**",
        f"- Precision@1 **{c.get('precision_at_1', 0):.3f}**",
        f"- benign false-campaign rate **{c.get('false_campaign_rate', 0):.3f}**",
        f"- time-to-correlate **{c.get('ttu_seconds', 0):.4f}s**",
        "",
        "## vs single-host baseline (B1)",
        f"- correlator F1 **{c.get('campaign_f1', 0):.3f}** vs B1 **{b1.get('campaign_f1', 0):.3f}** "
        f"(lift **{result.get('vs_b1', {}).get('f1_lift', 0):+.3f}**)",
        f"- correlator recall **{c.get('recall', 0):.3f}** vs B1 **{b1.get('recall', 0):.3f}**",
        "",
        "## Contain dry-run (IsolateHost hosts)",
        "```json",
        json.dumps(result.get("contain_dry_run") or {}, indent=2),
        "```",
        "",
        "## By attack family",
        "```json",
        json.dumps((result.get("by_family") or {}).get("correlator") or {}, indent=2),
        "```",
        "",
        "## Full metrics",
        "```json",
        json.dumps(result["metrics"], indent=2),
        "```",
        "",
        "## Ablation",
        "```json",
        json.dumps(result["ablation"], indent=2),
        "```",
        "",
        "## Reasons",
    ]
    if result["reasons"]:
        lines.extend(f"- {r}" for r in result["reasons"])
    else:
        lines.append("- none")
    lines.extend(
        [
            "",
            "## Freeze manifest",
            "```json",
            json.dumps(result["freeze_manifest"], indent=2),
            "```",
            "",
        ]
    )
    if not result["pass"]:
        lines.append("FAIL->stop: do not create `stage-b-allowed` unless held-out PASS.")
        lines.append("")
    return "\n".join(lines)


@app.command("gate")
def gate_cmd(
    report: Path = typer.Option(Path("reports/stageA.json"), help="Held-out eval report"),
) -> None:
    """CI gate: exit 0 iff held-out PASS."""
    path = Path(report)
    if not path.exists():
        # fall back to gate txt / heldout report
        alt = Path("reports/stageA_heldout.json")
        path = alt if alt.exists() else path
    if not path.exists():
        typer.echo("FAIL: no eval report")
        raise typer.Exit(1)
    data = json.loads(path.read_text(encoding="utf-8"))
    passed = bool(data.get("gate", {}).get("pass", data.get("pass")))
    typer.echo("PASS" if passed else "FAIL")
    raise typer.Exit(0 if passed else 1)


@app.command("stage-b-check")
def stage_b_check_cmd() -> None:
    """Refuse sensor unlock unless held-out PASS + stranger dry-run + stage-b-allowed."""
    from corvex.stage_b import stage_b_status

    status = stage_b_status()
    typer.echo(json.dumps(status, indent=2))
    raise typer.Exit(0 if status["allowed"] else 1)


@app.command("dash")
def dash_cmd(
    build_only: bool = typer.Option(False, "--build", help="Write HTML and exit"),
    host: str = typer.Option(
        "127.0.0.1",
        "--host",
        help="Bind address (use 0.0.0.0 to share on a lab LAN)",
    ),
    port: int = typer.Option(8765, "--port", help="HTTP port"),
    run_dir: Optional[Path] = typer.Option(
        None,
        "--run-dir",
        help="Replay/run directory with timeline.json (default: runs/latest)",
    ),
    open_browser: bool = typer.Option(
        True,
        "--open/--no-open",
        help="Open the monitor in a browser when the server starts",
    ),
    open_file: bool = typer.Option(False, "--open-file", help="Open index.html via file:// only"),
) -> None:
    """Build read-only run monitor from reports/; serve unless --build/--open-file."""
    from corvex.dashboard import write_dashboard
    from corvex.dash_server import serve
    import webbrowser

    root = _repo_root()
    if run_dir is not None:
        os.environ["CORVEX_RUN_DIR"] = str(Path(run_dir).resolve())
    out = write_dashboard(root)
    typer.echo(f"wrote {out}")
    file_url = out.resolve().as_uri()

    if build_only:
        return
    if open_file:
        webbrowser.open(file_url)
        typer.echo(f"opened {file_url}")
        return

    try:
        httpd = serve(root, port=port, host=host)
    except OSError as exc:
        typer.echo(f"bind {host}:{port} failed ({exc}); opening file instead (server needed for live snapshot)")
        webbrowser.open(file_url)
        raise typer.Exit(0)

    bound_host, bound_port = httpd.server_address[:2]
    display_host = "127.0.0.1" if bound_host in ("0.0.0.0", "::") else bound_host
    url = f"http://{display_host}:{bound_port}/"
    typer.echo(f"Monitor (read-only): {url}")
    if host in ("0.0.0.0", "::"):
        typer.echo(f"Bound on {host}:{bound_port} — reachable from other machines on your network")
    typer.echo("Ctrl+C to stop")
    if open_browser:
        try:
            webbrowser.open(url)
        except Exception:
            pass
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        typer.echo("stopped")
    finally:
        httpd.server_close()


@app.command("contain-status")
def contain_status_cmd() -> None:
    """Show contain checklist + quarantine capability (never claims live contain)."""
    from corvex.contain.dry_run import status
    from corvex.contain.quarantine import resolve_quarantine_mode

    typer.echo(
        json.dumps(
            {"contain": status(), "quarantine": resolve_quarantine_mode(root=_repo_root())},
            indent=2,
        )
    )


@app.command("contain-dry-run")
def contain_dry_run_cmd(
    verb: str = typer.Argument(..., help="IsolateHost|KillPid|AddFirewallRule"),
    host: str = typer.Option(..., "--host", help="Target host_id"),
    rationale: str = typer.Option(..., "--rationale"),
    pid: Optional[int] = typer.Option(None, "--pid"),
) -> None:
    """Propose a typed contain action as dry-run log only — no host mutation."""
    from corvex.contain.dry_run import execute_action, propose_action

    target: Dict[str, Any] = {"host_id": host}
    if pid is not None:
        target["pid"] = pid
    env = propose_action(verb, target, rationale=rationale)  # type: ignore[arg-type]
    rec = execute_action(env)
    typer.echo(json.dumps(rec, indent=2))


@app.command("adapt-windows")
def adapt_windows_cmd(
    path: Path = typer.Argument(..., help="Windows Security JSON/JSONL export"),
    out: Path = typer.Option(Path("runs/sensors/windows_auth.jsonl"), help="Signed BYO JSONL"),
    default_host: str = typer.Option("host-a", help="Fallback host_id"),
    host_map: Optional[Path] = typer.Option(
        None, "--host-map", help="JSON map Computer name → enrolled host_id"
    ),
) -> None:
    """Convert Windows Security auth export → signed BYO JSONL (observe-only)."""
    from corvex.adapters.windows_security import adapt_windows_security_export
    from corvex.envelope import sign_envelope

    enrollment = ensure_lab_enrollment()
    # Prefer demo host→producer map; unknown computers fall back to default_host
    hmap: Dict[str, str] = {h: h for h in DEMO_HOSTS}
    if host_map and Path(host_map).exists():
        loaded = json.loads(Path(host_map).read_text(encoding="utf-8"))
        if isinstance(loaded, dict):
            hmap.update({str(k): str(v) for k, v in loaded.items()})
            hmap.update({str(k).lower(): str(v) for k, v in loaded.items()})
    raw = adapt_windows_security_export(
        path,
        producer_id=DEMO_HOSTS.get(default_host, "prod-a"),
        default_host=default_host,
        host_map=hmap,
    )
    out = Path(out)
    out.parent.mkdir(parents=True, exist_ok=True)
    n = 0
    with out.open("w", encoding="utf-8") as fh:
        for rec in raw:
            host_id = str(rec["host_id"])
            if host_id not in DEMO_HOSTS:
                mapped = hmap.get(host_id) or hmap.get(host_id.lower())
                host_id = mapped if mapped in DEMO_HOSTS else default_host
            prod = DEMO_HOSTS[host_id]
            secret = enrollment.require(prod, host_id)
            env = sign_envelope(
                producer_id=prod,
                host_id=host_id,
                payload_type=rec["payload_type"],
                payload=rec["payload"],
                secret=secret,
                event_id=rec["event_id"],
                ts_utc=rec["ts_utc"],
                nonce=rec["nonce"],
            )
            fh.write(json.dumps(env.to_dict(), separators=(",", ":")) + "\n")
            n += 1
    typer.echo(json.dumps({"adapted": n, "out": str(out)}, indent=2))


@app.command("build-breaktest")
def build_breaktest_cmd(
    manifest: Path = typer.Argument(..., help="Break-test manifest JSON"),
    out: Path = typer.Option(
        Path("runs/breaktest/pack.jsonl"), help="Signed pack JSONL with ground_truth"
    ),
    report: Optional[Path] = typer.Option(
        None, help="Write break-point JSON (correlator vs detector-only)"
    ),
) -> None:
    """Expand an attack-repo manifest into a signed pack + optional break report."""
    from corvex.adapters.attack_repos import adapt_attack_manifest, load_manifest
    from corvex.envelope import EventEnvelope, sign_envelope
    from corvex.eval.break_points import analyze_break_points, write_break_report

    enrollment = ensure_lab_enrollment()
    man = load_manifest(manifest)
    raw_events, gt = adapt_attack_manifest(man)
    signed = []
    for rec in raw_events:
        secret = enrollment.require(rec["producer_id"], rec["host_id"])
        signed.append(
            sign_envelope(
                producer_id=rec["producer_id"],
                host_id=rec["host_id"],
                payload_type=rec["payload_type"],
                payload=rec["payload"],
                secret=secret,
                event_id=rec["event_id"],
                ts_utc=rec["ts_utc"],
                nonce=rec["nonce"],
            )
        )
    write_pack(Path(out), signed, gt)

    payload: Dict[str, Any] = {"pack": str(out), "hosts": gt.get("host_ids"), "events": len(signed)}
    if report is not None:
        corr_camps, _ = _predict_from_events(signed, "correlator")
        det_camps, _ = _predict_from_events(signed, "detector_only")
        b1_camps, _ = _predict_from_events(signed, "b1")
        br = analyze_break_points(
            truth=gt,
            correlator=corr_camps,
            detector_only=det_camps,
            b1=b1_camps,
        )
        write_break_report(Path(report), br)
        payload["break_report"] = str(report)
        payload["fusion_lift"] = br["break_points"]["fusion_lift"]
        payload["break_points"] = br["break_points"]
    typer.echo(json.dumps(payload, indent=2))


@app.command("freeze-check")
def freeze_check(report: Path = typer.Option(Path("reports/stageA_heldout.json"))) -> None:
    """Fail if tip SHAs != freeze manifest in report."""
    data = json.loads(Path(report).read_text(encoding="utf-8"))
    root = _repo_root()
    man = data["freeze_manifest"]
    current = {
        "correlator_sha": _file_sha(root / "corvex" / "correlator.py"),
        "detectors_sha": _file_sha(root / "corvex" / "detectors.py"),
        "scorer_sha": _file_sha(root / "corvex" / "eval" / "__init__.py"),
        "b2_sha": _file_sha(root / "corvex" / "baselines.py"),
    }
    bad = [k for k in current if current[k] != man.get(k)]
    if bad:
        typer.echo(f"freeze mismatch: {bad}")
        raise typer.Exit(1)
    typer.echo("freeze OK")


def main() -> None:
    app()


if __name__ == "__main__":
    main()
