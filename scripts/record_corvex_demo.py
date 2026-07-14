#!/usr/bin/env python3
"""Record an isolated Corvex demo: detect multi-host campaign → interrupt (dry-run).

Outputs under .sandbox/demo/:
  - events.jsonl / timeline.json  (machine-readable)
  - frames/*.png                  (storyboard)
  - corvex-demo.gif               (animated recording)
  - index.html                    (autoplay replay)
  - DEMO_REPORT.md
"""

from __future__ import annotations

import json
import shutil
import sys
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Tuple

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / ".sandbox" / "demo"
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from PIL import Image, ImageDraw, ImageFont  # noqa: E402

from campaignfuse.audit import AuditLog  # noqa: E402
from campaignfuse.auth import Enrollment  # noqa: E402
from campaignfuse.contain import (  # noqa: E402
    L1_ITEMS,
    ContainGateError,
    checklist_complete,
    require_contain,
    set_checklist_item,
)
from campaignfuse.contain.dry_run import ActionEnvelope, execute_action, propose_action  # noqa: E402
from campaignfuse.correlator import Correlator, CorrelatorConfig  # noqa: E402
from campaignfuse.feeder import generate_campaign_events  # noqa: E402
from campaignfuse.store import CampaignStore  # noqa: E402


@dataclass
class Beat:
    t: float
    title: str
    lines: List[str]
    accent: str = "good"  # good | warn | bad | mute
    mode: str = ""  # optional badge


def _seed_checklist(all_on: bool) -> None:
    reports = OUT / "reports"
    reports.mkdir(parents=True, exist_ok=True)
    raw = {k: False for k in L1_ITEMS}
    raw["_meta"] = {"policy": "demo sandbox only", "sandbox": True}
    (reports / "security_l1_checklist.json").write_text(
        json.dumps(raw, indent=2) + "\n", encoding="utf-8"
    )
    for k in L1_ITEMS:
        set_checklist_item(k, all_on, root=OUT, source="demo")


def run_scenario(*, safety_on: bool) -> Dict[str, Any]:
    label = "safety_on" if safety_on else "safety_off"
    run_dir = OUT / "runs" / label
    if run_dir.exists():
        shutil.rmtree(run_dir)
    run_dir.mkdir(parents=True)

    _seed_checklist(safety_on)

    enr = Enrollment(
        {"prod-a": {"host-a"}, "prod-b": {"host-b"}, "prod-c": {"host-c"}},
        {
            "prod-a": b"demo-secret-prod-a-xxxxxxxx",
            "prod-b": b"demo-secret-prod-b-yyyyyyyy",
            "prod-c": b"demo-secret-prod-c-zzzzzzzz",
        },
    )
    events, gt = generate_campaign_events(
        campaign_id="demo-lat",
        family="lateral",
        hosts=[("host-a", "prod-a"), ("host-b", "prod-b"), ("host-c", "prod-c")],
        enrollment=enr,
        base_time=datetime(2026, 7, 22, 12, 0, 0, tzinfo=timezone.utc),
    )

    bus_path = run_dir / "events.jsonl"
    with bus_path.open("w", encoding="utf-8") as fh:
        for env in events:
            fh.write(json.dumps(env.to_dict(), separators=(",", ":")) + "\n")

    store = CampaignStore(run_dir / "campaigns.jsonl")
    audit = AuditLog(run_dir / "audit.jsonl")
    corr = Correlator(store, audit, CorrelatorConfig(min_hosts=2))
    corr.ingest(events)
    camps = store.all()

    targets: List[str] = []
    if camps:
        targets = sorted({h for c in camps for h in c.host_ids})
    if not targets:
        targets = list(gt.get("hosts") or ["host-a", "host-b", "host-c"])

    interrupt_log = run_dir / "interrupt_dry_run.jsonl"
    interrupt_records = []
    for host in targets[:3]:
        env = propose_action(
            "IsolateHost",
            {"host_id": host},
            rationale=f"Corvex demo: quarantine {host} after multi-host campaign detect",
        )
        rec = execute_action(env, log_path=interrupt_log)
        interrupt_records.append(rec)

    # Live path probe (must always fail)
    live_block_reason = None
    live_probe = ActionEnvelope(
        schema_ver="1",
        verb="IsolateHost",
        target={"host_id": targets[0]},
        impact_class="lab_soft",
        dry_run=False,
        idempotency_key="demo-live-probe",
        expiry="2099-01-01T00:00:00Z",
        policy_version="demo",
        rationale="must not execute",
    )
    try:
        execute_action(live_probe, log_path=run_dir / "live_probe.jsonl")
        live_blocked = False
        live_block_reason = "UNEXPECTED: live path returned"
    except ContainGateError as exc:
        live_blocked = True
        live_block_reason = str(exc)

    gate_pass = None
    gate_err = None
    try:
        require_contain(root=OUT)
        gate_pass = True
    except ContainGateError as exc:
        gate_pass = False
        gate_err = str(exc)

    return {
        "label": label,
        "safety_on": safety_on,
        "checklist_complete": checklist_complete(root=OUT),
        "events": len(events),
        "campaigns": len(camps),
        "campaign_summaries": [
            {
                "id": c.campaign_id,
                "hosts": list(c.host_ids),
                "score": c.score,
            }
            for c in camps
        ],
        "targets": targets,
        "interrupts_logged": len(interrupt_records),
        "interrupt_records": interrupt_records,
        "live_blocked": live_blocked,
        "live_block_reason": live_block_reason,
        "require_contain_pass": gate_pass,
        "require_contain_error": gate_err,
        "bus_path": str(bus_path),
        "interrupt_log": str(interrupt_log),
    }


def _font(size: int) -> ImageFont.ImageFont:
    for name in (
        r"C:\Windows\Fonts\segoeui.ttf",
        r"C:\Windows\Fonts\arial.ttf",
        r"C:\Windows\Fonts\calibri.ttf",
    ):
        p = Path(name)
        if p.exists():
            return ImageFont.truetype(str(p), size=size)
    return ImageFont.load_default()


def _draw_frame(beat: Beat, idx: int, total: int) -> Image.Image:
    w, h = 1280, 720
    img = Image.new("RGB", (w, h), "#06080b")
    draw = ImageDraw.Draw(img)
    # soft glow blobs
    overlay = Image.new("RGBA", (w, h), (0, 0, 0, 0))
    od = ImageDraw.Draw(overlay)
    od.ellipse((-120, -80, 420, 320), fill=(77, 184, 255, 28))
    od.ellipse((900, -40, 1400, 360), fill=(47, 214, 123, 18))
    img = Image.alpha_composite(img.convert("RGBA"), overlay).convert("RGB")
    draw = ImageDraw.Draw(img)

    font_brand = _font(28)
    font_title = _font(44)
    font_body = _font(26)
    font_small = _font(18)
    font_mono = _font(20)

    accents = {
        "good": "#2fd67b",
        "warn": "#e8b84a",
        "bad": "#ff5c6a",
        "mute": "#8b96a8",
    }
    color = accents.get(beat.accent, accents["good"])

    draw.text((48, 36), "CORVEX", fill="#f2f5f8", font=font_brand)
    draw.text((160, 44), "demo recording", fill="#5c6778", font=font_small)
    if beat.mode:
        draw.rounded_rectangle((1000, 36, 1232, 72), radius=14, fill="#10151d", outline="#2a3340")
        draw.text((1020, 44), beat.mode, fill="#8b96a8", font=font_small)

    # progress
    bar_y = 96
    draw.rounded_rectangle((48, bar_y, 1232, bar_y + 8), radius=4, fill="#1b2431")
    fill_w = 48 + int((1232 - 48) * ((idx + 1) / max(1, total)))
    draw.rounded_rectangle((48, bar_y, fill_w, bar_y + 8), radius=4, fill=color)

    draw.text((48, 140), beat.title, fill=color, font=font_title)
    y = 220
    for line in beat.lines:
        draw.text((56, y), line, fill="#d7dde8", font=font_body)
        y += 42

    draw.text((48, 670), f"{idx + 1}/{total}", fill="#5c6778", font=font_mono)
    draw.text((1100, 670), "sandbox · no live hosts", fill="#5c6778", font=font_small)
    return img


def build_story(off: Dict[str, Any], on: Dict[str, Any]) -> List[Beat]:
    camp = (off.get("campaign_summaries") or [{}])[0]
    hosts = camp.get("hosts") or off.get("targets") or []
    host_txt = ", ".join(hosts[:4]) if hosts else "multiple hosts"
    return [
        Beat(
            0,
            "Corvex sandbox demo",
            [
                "Isolated lab — no real machines touched.",
                "Goal: detect a multi-host attack, then interrupt.",
                "Interrupt = dry-run IsolateHost (logged only).",
            ],
            "mute",
            "LAB ONLY",
        ),
        Beat(
            1,
            "Attack begins",
            [
                f"Ingesting {off['events']} signed events across hosts.",
                "Family: lateral movement campaign.",
                "Sensors → correlator (observe only).",
            ],
            "warn",
            "INGEST",
        ),
        Beat(
            2,
            "Detected",
            [
                f"Campaigns found: {off['campaigns']}",
                f"Hosts in campaign: {host_txt}",
                "Cross-host link established — not a single-PC alert.",
            ],
            "good",
            "DETECT",
        ),
        Beat(
            3,
            "Interrupt (safety OFF)",
            [
                f"Safety controls: 0/{len(L1_ITEMS)} — contain gate locked.",
                f"Dry-run IsolateHost × {off['interrupts_logged']} logged.",
                "Live isolate: BLOCKED (as required).",
            ],
            "warn",
            "SAFETY OFF",
        ),
        Beat(
            4,
            "Interrupt (safety ON)",
            [
                f"Safety controls: {len(L1_ITEMS)}/{len(L1_ITEMS)} checklist gate open.",
                f"Dry-run IsolateHost × {on['interrupts_logged']} still logged.",
                "Live isolate: STILL BLOCKED — no executor yet.",
            ],
            "good",
            "SAFETY ON",
        ),
        Beat(
            5,
            "Honest takeaway",
            [
                "Detection works with or without safety toggles.",
                "Interruption today = propose + log, not kill the host.",
                "Live contain stays off until a real executor ships.",
            ],
            "mute",
            "DONE",
        ),
    ]


def write_html(beats: List[Beat], gif_name: str) -> None:
    slides = [
        {
            "title": b.title,
            "lines": b.lines,
            "accent": b.accent,
            "mode": b.mode,
        }
        for b in beats
    ]
    html = f"""<!DOCTYPE html>
<html lang="en"><head>
<meta charset="utf-8"/><meta name="viewport" content="width=device-width, initial-scale=1"/>
<title>Corvex Demo Recording</title>
<style>
:root {{ --bg:#06080b; --panel:#10151d; --text:#f2f5f8; --muted:#8b96a8;
  --good:#2fd67b; --warn:#e8b84a; --bad:#ff5c6a; --mute:#8b96a8; }}
* {{ box-sizing:border-box; }}
body {{ margin:0; font-family:Segoe UI,system-ui,sans-serif; background:var(--bg); color:var(--text);
  min-height:100vh; display:grid; place-items:center; }}
.stage {{ width:min(960px,94vw); }}
.top {{ display:flex; justify-content:space-between; align-items:center; margin-bottom:14px; }}
.brand {{ font-weight:700; letter-spacing:.04em; }}
.brand span {{ color:var(--muted); font-weight:500; margin-left:8px; }}
.card {{ background:var(--panel); border:1px solid rgba(255,255,255,.08); border-radius:16px;
  padding:28px 28px 22px; min-height:360px; position:relative; overflow:hidden; }}
.mode {{ position:absolute; top:18px; right:18px; font-size:.75rem; color:var(--muted);
  border:1px solid rgba(255,255,255,.1); padding:6px 10px; border-radius:999px; }}
.title {{ font-size:clamp(1.6rem,3vw,2.2rem); font-weight:700; margin:28px 0 16px; }}
.title.good {{ color:var(--good); }} .title.warn {{ color:var(--warn); }}
.title.bad {{ color:var(--bad); }} .title.mute {{ color:var(--text); }}
.lines {{ margin:0; padding:0; list-style:none; }}
.lines li {{ color:#d7dde8; font-size:1.05rem; line-height:1.45; margin:0 0 12px;
  opacity:0; transform:translateY(6px); transition:opacity .35s ease, transform .35s ease; }}
.lines li.show {{ opacity:1; transform:none; }}
.bar {{ height:6px; background:#1b2431; border-radius:99px; margin-top:18px; overflow:hidden; }}
.bar > i {{ display:block; height:100%; width:0; background:var(--good); transition:width .4s ease; }}
.row {{ display:flex; gap:12px; margin-top:14px; align-items:center; }}
button {{ background:#141b25; color:var(--text); border:1px solid rgba(255,255,255,.12);
  border-radius:10px; padding:10px 14px; cursor:pointer; font-weight:600; }}
button:hover {{ border-color:rgba(255,255,255,.24); }}
.meta {{ color:var(--muted); font-size:.85rem; }}
.gif {{ margin-top:18px; width:100%; border-radius:12px; border:1px solid rgba(255,255,255,.08); }}
</style></head><body>
<div class="stage">
  <div class="top"><div class="brand">CORVEX <span>demo recording</span></div>
    <div class="meta" id="clock">autoplay</div></div>
  <div class="card">
    <div class="mode" id="mode"></div>
    <div class="title" id="title"></div>
    <ul class="lines" id="lines"></ul>
    <div class="bar"><i id="prog"></i></div>
  </div>
  <div class="row">
    <button id="replay" type="button">Replay</button>
    <div class="meta">Detect → dry-run interrupt · sandbox only</div>
  </div>
  <img class="gif" src="{gif_name}" alt="Corvex demo GIF"/>
</div>
<script>
const slides = {json.dumps(slides)};
let timer;
function show(i) {{
  const s = slides[i];
  const title = document.getElementById('title');
  title.textContent = s.title;
  title.className = 'title ' + s.accent;
  document.getElementById('mode').textContent = s.mode || '';
  document.getElementById('prog').style.width = ((i+1)/slides.length*100) + '%';
  document.getElementById('prog').style.background =
    getComputedStyle(document.documentElement).getPropertyValue('--' + (s.accent==='mute'?'muted':s.accent)) || '#2fd67b';
  const ul = document.getElementById('lines');
  ul.innerHTML = '';
  s.lines.forEach((line, idx) => {{
    const li = document.createElement('li');
    li.textContent = line;
    ul.appendChild(li);
    setTimeout(() => li.classList.add('show'), 120 + idx*140);
  }});
  document.getElementById('clock').textContent = (i+1) + ' / ' + slides.length;
}}
function play() {{
  clearInterval(timer);
  let i = 0;
  show(0);
  timer = setInterval(() => {{
    i += 1;
    if (i >= slides.length) {{ clearInterval(timer); return; }}
    show(i);
  }}, 2800);
}}
document.getElementById('replay').onclick = play;
play();
</script>
</body></html>
"""
    (OUT / "index.html").write_text(html, encoding="utf-8")


def main() -> int:
    if OUT.exists():
        shutil.rmtree(OUT)
    OUT.mkdir(parents=True)
    (OUT / "frames").mkdir()

    print("Running scenario: safety OFF…")
    off = run_scenario(safety_on=False)
    print("Running scenario: safety ON…")
    on = run_scenario(safety_on=True)

    timeline = {
        "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "product": "Corvex",
        "note": "Interrupt is dry-run only. Live contain is blocked in both modes.",
        "safety_off": off,
        "safety_on": on,
    }
    (OUT / "timeline.json").write_text(json.dumps(timeline, indent=2) + "\n", encoding="utf-8")

    beats = build_story(off, on)
    frames: List[Image.Image] = []
    for i, beat in enumerate(beats):
        frame = _draw_frame(beat, i, len(beats))
        frame.save(OUT / "frames" / f"frame_{i:02d}.png")
        frames.append(frame)

    gif_path = OUT / "corvex-demo.gif"
    frames[0].save(
        gif_path,
        save_all=True,
        append_images=frames[1:],
        duration=2200,
        loop=0,
    )
    write_html(beats, gif_path.name)

    md = f"""# Corvex demo recording

Generated: `{timeline['generated_at']}`

## What was recorded
1. **Detect** — lateral multi-host campaign correlator run in an isolated sandbox
2. **Interrupt** — `IsolateHost` dry-run proposals logged (no host mutation)
3. Compared **safety OFF** vs **safety ON**

## Results

| Mode | Events | Campaigns | Dry-run interrupts | Live blocked | require_contain |
|------|--------|-----------|--------------------|--------------|-----------------|
| Safety OFF | {off['events']} | {off['campaigns']} | {off['interrupts_logged']} | {off['live_blocked']} | {off['require_contain_pass']} |
| Safety ON | {on['events']} | {on['campaigns']} | {on['interrupts_logged']} | {on['live_blocked']} | {on['require_contain_pass']} |

## Files
- Replay: `.sandbox/demo/index.html`
- GIF: `.sandbox/demo/corvex-demo.gif`
- Raw timeline: `.sandbox/demo/timeline.json`

## Honesty
Live quarantine does **not** run even with all safety toggles on — there is no executor yet.
"""
    (OUT / "DEMO_REPORT.md").write_text(md, encoding="utf-8")

    # keep gitignore
    gi = ROOT / ".gitignore"
    text = gi.read_text(encoding="utf-8") if gi.exists() else ""
    if ".sandbox/" not in text:
        gi.write_text(text.rstrip() + "\n\n# local demo / lab sandboxes\n.sandbox/\n", encoding="utf-8")

    print(f"\nGIF  → {gif_path}")
    print(f"HTML → {OUT / 'index.html'}")
    print(f"Report → {OUT / 'DEMO_REPORT.md'}")
    print(md)
    return 0 if off["campaigns"] >= 1 and off["live_blocked"] and on["live_blocked"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
