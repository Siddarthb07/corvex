"""CLI: corvex replay | eval | timeline | ingest-byo | dash | seal-day0 | freeze."""

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
    train_dir.mkdir(parents=True, exist_ok=True)
    heldout_dir.mkdir(parents=True, exist_ok=True)

    hosts = {
        "host-a": "prod-a",
        "host-b": "prod-b",
        "host-c": "prod-c",
        "host-d": "prod-d",
    }
    enrollment = generate_lab_enrollment(hosts)
    save_enrollment(default_secrets_path(), enrollment)

    from datetime import datetime, timezone

    base = datetime(2026, 1, 15, 12, 0, 0, tzinfo=timezone.utc)
    host_pairs = [(h, p) for h, p in hosts.items()]

    # Train: ≤3 campaigns
    train_specs = [
        ("train-lateral", "lateral", host_pairs[:3], False),
        ("train-exfil", "exfil", host_pairs[1:4], False),
        ("train-recon-lateral", "recon_lateral", host_pairs[:3], False),
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

    # Held-out plaintext in temp, then seal: ≥2 including ≥1 OOD + benign
    key = ensure_key()
    rules_path = heldout_dir / "scorer_rules.json"
    rules_path.write_text(scorer_rules_blob(), encoding="utf-8")

    heldout_specs = [
        ("held-lateral-ood", "lateral", host_pairs[:3], True),
        ("held-exfil", "exfil", host_pairs[1:4], False),
        ("held-benign", "benign", host_pairs[:3], False),
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
    # Pointer so `corvex dash` can show the latest replay without extra flags.
    latest = _repo_root() / "runs" / "latest"
    latest.parent.mkdir(parents=True, exist_ok=True)
    try:
        if latest.exists() or latest.is_symlink():
            latest.unlink()
        latest.symlink_to(out_dir.resolve(), target_is_directory=True)
    except OSError:
        latest.write_text(str(out_dir.resolve()), encoding="utf-8")
    typer.echo(json.dumps({"campaigns": len(store.all()), "ttu_seconds": ttu, "out_dir": str(out_dir)}, indent=2))


@app.command("timeline")
def timeline(
    run_dir: Path = typer.Argument(..., help="Run directory with timeline.json"),
) -> None:
    path = Path(run_dir) / "timeline.json"
    if not path.exists():
        raise typer.BadParameter(f"missing {path}")
    typer.echo(path.read_text(encoding="utf-8"))


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
            "FAIL->stop: do not create `stage-b-allowed` unless held-out PASS.",
            "",
        ]
    )
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
    """Build monitoring dashboard from reports/; serve with toggle API unless --build/--open-file."""
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
        typer.echo(f"bind {host}:{port} failed ({exc}); opening file instead (toggles need the server)")
        webbrowser.open(file_url)
        raise typer.Exit(0)

    bound_host, bound_port = httpd.server_address[:2]
    display_host = "127.0.0.1" if bound_host in ("0.0.0.0", "::") else bound_host
    url = f"http://{display_host}:{bound_port}/"
    typer.echo(f"Monitor:         {url}")
    typer.echo(f"Prevention log:  {url}logs.html")
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
    """Show contain checklist + dry-run availability (never claims live contain)."""
    from corvex.contain.dry_run import status

    typer.echo(json.dumps(status(), indent=2))


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
