"""Clean-clone / stranger happy-path checks."""

from __future__ import annotations

import json
from pathlib import Path

from corvex.cli import replay
from corvex.dashboard import collect_snapshot, write_dashboard
from corvex.lab_enroll import ensure_lab_enrollment


def test_replay_with_fresh_enrollment(tmp_path: Path, monkeypatch) -> None:
    enroll = tmp_path / "enrollment.json"
    monkeypatch.setenv("CORVEX_ENROLLMENT", str(enroll))
    monkeypatch.chdir(tmp_path)
    # Point package at real repo for train pack + repo root
    repo = Path(__file__).resolve().parents[1]
    monkeypatch.setenv("CORVEX_ROOT", str(repo))
    out = tmp_path / "run"
    pack = repo / "train" / "train-lateral.jsonl"
    assert pack.exists()
    replay(pack=pack, out_dir=out)
    assert enroll.exists()
    timeline = json.loads((out / "timeline.json").read_text(encoding="utf-8"))
    assert timeline["campaigns"]
    snap = collect_snapshot(repo)
    # With CORVEX_RUN_DIR unset, may not see this run; set and re-check
    monkeypatch.setenv("CORVEX_RUN_DIR", str(out))
    snap = collect_snapshot(repo)
    assert snap["campaigns"]
    html = write_dashboard(repo, out=tmp_path / "dash" / "index.html").read_text(encoding="utf-8")
    assert "Campaigns" in html


def test_ensure_lab_enrollment_idempotent(tmp_path: Path, monkeypatch) -> None:
    path = tmp_path / "enrollment.json"
    monkeypatch.setenv("CORVEX_ENROLLMENT", str(path))
    a = ensure_lab_enrollment()
    b = ensure_lab_enrollment()
    assert path.exists()
    assert a.secret_for("prod-a") == b.secret_for("prod-a")
