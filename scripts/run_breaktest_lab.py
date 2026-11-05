#!/usr/bin/env python3
"""Run 5-host ART break-test Docker lab (manifest-driven), export GIF+MP4.

Default manifest: art_lateral_chain.json (override with ATTACK_MANIFEST).
For the full ART suite + per-manifest videos, use scripts/record_art_breaktest.py.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
LAB = ROOT / "labs" / "breaktest"
SHARED = LAB / "shared"
OUT_DIR = ROOT / "docs" / "assets"
RUN_DIR = ROOT / "runs" / "breaktest" / "docker"

HOSTS = ["host-a", "host-b", "host-c", "host-d", "host-e"]


def run(cmd: list[str], cwd: Path | None = None, env: dict | None = None) -> None:
    print("+", " ".join(cmd), flush=True)
    merged = os.environ.copy()
    if env:
        merged.update(env)
    subprocess.run(cmd, cwd=str(cwd or LAB), check=True, env=merged)


def main() -> int:
    if shutil.which("docker") is None:
        print("Docker required", file=sys.stderr)
        return 1

    if SHARED.exists():
        shutil.rmtree(SHARED, ignore_errors=True)
    SHARED.mkdir(parents=True)
    (SHARED / "isolated").mkdir(parents=True)

    env = {"ATTACK_MANIFEST": os.environ.get("ATTACK_MANIFEST", "/manifests/art_lateral_chain.json")}
    run(["docker", "compose", "down", "-v", "--remove-orphans"])
    run(
        [
            "docker",
            "compose",
            "up",
            "--build",
            "-d",
            *HOSTS,
            "corvex",
        ],
        env=env,
    )
    time.sleep(3)
    run(["docker", "compose", "up", "--build", "-d", "attacker"], env=env)

    deadline = time.time() + 240
    state_path = SHARED / "attacker_state.json"
    while time.time() < deadline:
        if state_path.exists():
            try:
                st = json.loads(state_path.read_text(encoding="utf-8"))
                if st.get("kind") == "attack_complete":
                    print("\n=== ATTACK COMPLETE ===", flush=True)
                    print(json.dumps(st, indent=2), flush=True)
                    break
            except json.JSONDecodeError:
                pass
        time.sleep(0.5)
    else:
        print("timeout waiting for attack", file=sys.stderr)
        run(["docker", "compose", "logs", "--no-color"])
        return 1

    time.sleep(2)
    print("\n=== CORVEX / ATTACKER LOGS ===", flush=True)
    run(["docker", "compose", "logs", "--no-color", "attacker", "corvex"])

    RUN_DIR.mkdir(parents=True, exist_ok=True)
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    for name in (
        "attacker_state.json",
        "events.jsonl",
        "attacker.jsonl",
        "corvex_state.json",
        "theatre_state.json",
    ):
        src = SHARED / name
        if src.exists():
            shutil.copy2(src, RUN_DIR / name)

    # Isolate trail from flag files + corvex state
    flags = sorted((SHARED / "isolated").glob("*.flag")) if (SHARED / "isolated").exists() else []
    print("\n=== ISOLATE FLAGS (written mid-campaign, before wave2) ===", flush=True)
    for f in flags:
        print(f"  {f.name}: {f.read_text(encoding='utf-8').strip()}", flush=True)

    theatre_path = SHARED / "theatre_state.json"
    if not theatre_path.exists():
        print("missing theatre_state.json — cannot export video", file=sys.stderr)
        run(["docker", "compose", "down", "-v"])
        return 1

    state = json.loads(theatre_path.read_text(encoding="utf-8"))
    print("\n=== THEATRE FEED (detect -> isolate -> block) ===", flush=True)
    for item in state.get("feed") or []:
        print(f"  [{item.get('type')}] {item.get('text')}", flush=True)

    replay = RUN_DIR / "breaktest-replay.html"
    replay.write_text(_replay_html(state), encoding="utf-8")

    sys.path.insert(0, str(Path(__file__).resolve().parent))
    from export_live_lab_video import export_replay

    gif = OUT_DIR / "corvex-breaktest.gif"
    mp4 = OUT_DIR / "corvex-breaktest.mp4"
    export_replay(replay, gif, mp4)

    run(["docker", "compose", "down", "-v"])
    print("\nArtifacts:", flush=True)
    print(" ", mp4, flush=True)
    print(" ", gif, flush=True)
    print(" ", replay, flush=True)
    print(" ", RUN_DIR, flush=True)
    return 0


def _replay_html(state: dict) -> str:
    """5-host cinematic replay from captured break-test theatre feed."""
    payload = json.dumps(state)
    return f"""<!DOCTYPE html>
<html lang="en"><head>
<meta charset="utf-8"/><meta name="viewport" content="width=device-width, initial-scale=1"/>
<title>Corvex Break-Test Replay</title>
<link href="https://fonts.googleapis.com/css2?family=IBM+Plex+Mono:wght@400;500;600&family=Outfit:wght@500;700&display=swap" rel="stylesheet"/>
<style>
:root{{--bg:#05070a;--attack:#ff5c6a;--detect:#4db8ff;--defend:#2fd67b;--text:#eef3f8;--muted:#8b96a8}}
*{{box-sizing:border-box}} body{{margin:0;font-family:Outfit,system-ui,sans-serif;background:var(--bg);color:var(--text);overflow:hidden}}
.app{{max-width:1280px;margin:0 auto;padding:16px;height:100vh;display:grid;grid-template-rows:auto 1fr}}
.top{{display:flex;justify-content:space-between;align-items:center}}
.phase{{font-family:IBM Plex Mono,monospace;font-size:.75rem;padding:6px 10px;border-radius:999px;border:1px solid #222}}
.stage{{display:grid;grid-template-columns:1.35fr .65fr;gap:12px;min-height:0;margin-top:12px}}
.panel{{background:#0d1219;border:1px solid #1c2430;border-radius:16px;position:relative;overflow:hidden}}
svg{{width:100%;height:100%}}
.host{{fill:#121821;stroke:#2a3344;stroke-width:2}} .host.hit{{stroke:var(--attack);fill:rgba(255,92,106,.14)}}
.host.isolated{{stroke:var(--defend);fill:rgba(47,214,123,.14)}}
.attacker{{fill:#1a1012;stroke:var(--attack);stroke-width:2}}
.label{{fill:#eef3f8;font-size:12px;font-weight:600}} .sub{{fill:#8b96a8;font-size:9px;font-family:IBM Plex Mono,monospace}}
.link{{fill:none;stroke:var(--attack);stroke-width:2;opacity:0}} .link.on{{opacity:1}}
.mesh{{fill:none;stroke:var(--detect);stroke-width:1.5;stroke-dasharray:5 5;opacity:0}} .mesh.on{{opacity:1}}
.shield{{fill:none;stroke:var(--defend);stroke-width:3;opacity:0}} .shield.on{{opacity:1}}
.caption{{position:absolute;left:14px;right:14px;bottom:14px;background:rgba(5,7,10,.85);border:1px solid #1c2430;border-radius:12px;padding:12px;font-size:.9rem}}
.stream{{padding:12px;overflow:auto;font-family:IBM Plex Mono,monospace;font-size:.7rem;height:100%}}
.evt{{border:1px solid #1c2430;border-radius:10px;padding:8px;margin-bottom:6px;background:#0a0f16}}
.evt.auth{{border-color:rgba(255,92,106,.35)}} .evt.detect{{border-color:rgba(77,184,255,.4)}}
.evt.defend,.evt.blocked{{border-color:rgba(47,214,123,.4)}}
</style></head><body>
<div class="app">
  <div class="top"><strong>Corvex · 5-host break-test</strong><div class="phase" id="phase">REPLAY</div></div>
  <div class="stage">
    <div class="panel" style="min-height:560px">
      <svg viewBox="0 0 980 600">
        <circle class="attacker" cx="90" cy="300" r="32"/>
        <text class="label" x="90" y="305" text-anchor="middle">Attacker</text>
        <text class="sub" x="90" y="348" text-anchor="middle">10.1.0.5</text>

        <path id="la" class="link" d="M122 270 C200 160 280 120 360 110"/>
        <path id="lb" class="link" d="M122 285 C220 220 320 200 420 200"/>
        <path id="lc" class="link" d="M122 300 C260 300 400 300 520 300"/>
        <path id="ld" class="link" d="M122 315 C220 380 320 400 420 400"/>
        <path id="le" class="link" d="M122 330 C200 440 280 480 360 490"/>

        <path id="mab" class="mesh" d="M400 130 L460 180"/><path id="mbc" class="mesh" d="M500 220 L540 280"/>
        <path id="mcd" class="mesh" d="M540 320 L500 380"/><path id="mde" class="mesh" d="M460 420 L400 470"/>
        <path id="mac" class="mesh" d="M400 150 L540 280"/><path id="mae" class="mesh" d="M400 150 L400 470"/>

        <circle id="ha" class="host" cx="400" cy="110" r="36"/><circle id="sa" class="shield" cx="400" cy="110" r="48"/>
        <text class="label" x="400" y="114" text-anchor="middle">host-a</text>
        <text class="sub" x="400" y="162" text-anchor="middle">workstation</text>

        <circle id="hb" class="host" cx="500" cy="200" r="36"/><circle id="sb" class="shield" cx="500" cy="200" r="48"/>
        <text class="label" x="500" y="204" text-anchor="middle">host-b</text>
        <text class="sub" x="500" y="252" text-anchor="middle">fileserver</text>

        <circle id="hc" class="host" cx="580" cy="300" r="36"/><circle id="sc" class="shield" cx="580" cy="300" r="48"/>
        <text class="label" x="580" y="304" text-anchor="middle">host-c</text>
        <text class="sub" x="580" y="352" text-anchor="middle">jump box</text>

        <circle id="hd" class="host" cx="500" cy="400" r="36"/><circle id="sd" class="shield" cx="500" cy="400" r="48"/>
        <text class="label" x="500" y="404" text-anchor="middle">host-d</text>
        <text class="sub" x="500" y="452" text-anchor="middle">db</text>

        <circle id="he" class="host" cx="400" cy="490" r="36"/><circle id="se" class="shield" cx="400" cy="490" r="48"/>
        <text class="label" x="400" y="494" text-anchor="middle">host-e</text>
        <text class="sub" x="400" y="542" text-anchor="middle">egress proxy</text>

        <text id="camp" x="720" y="50" fill="#4db8ff" font-family="IBM Plex Mono" font-size="12" opacity="0"></text>
      </svg>
      <div class="caption" id="caption"></div>
    </div>
    <div class="panel"><div class="stream" id="stream"></div></div>
  </div>
</div>
<script>
const STATE = {payload};
const feed = STATE.feed || [];
const stream = document.getElementById('stream');
const map = {{
  'host-a':['ha','la','sa'],
  'host-b':['hb','lb','sb'],
  'host-c':['hc','lc','sc'],
  'host-d':['hd','ld','sd'],
  'host-e':['he','le','se']
}};
let i = 0;
function add(item){{
  const el=document.createElement('div');
  el.className='evt '+(item.type||'');
  el.innerHTML=`<div>${{item.text||''}}</div>`;
  stream.prepend(el);
  if(item.host && map[item.host]){{
    const [h,l,s]=map[item.host];
    if(item.type==='auth'){{ document.getElementById(h).classList.add('hit'); document.getElementById(l).classList.add('on'); }}
    if(item.type==='defend'||item.type==='blocked'){{
      document.getElementById(h).classList.add('isolated'); document.getElementById(s).classList.add('on');
    }}
  }}
  if(item.type==='detect'){{
    ['mab','mbc','mcd','mde','mac','mae'].forEach(id=>document.getElementById(id).classList.add('on'));
    const c=(STATE.campaigns||[])[0]; if(c){{ const e=document.getElementById('camp'); e.textContent=c.id+' · '+((c.hosts)||[]).join(','); e.style.opacity=1; }}
    document.getElementById('phase').textContent='DETECT';
  }}
  if(item.type==='defend') document.getElementById('phase').textContent='ISOLATE (mid-campaign)';
  if(item.type==='blocked') document.getElementById('phase').textContent='WAVE2 BLOCKED';
  document.getElementById('caption').textContent=item.text||STATE.caption||'';
}}
function tick(){{
  if(i>=feed.length){{
    document.getElementById('phase').textContent='DONE';
    document.getElementById('caption').textContent=STATE.caption||'Break-test complete — later hops blocked';
    return;
  }}
  add(feed[i++]);
  setTimeout(tick, 550);
}}
setTimeout(tick, 400);
</script></body></html>
"""


if __name__ == "__main__":
    raise SystemExit(main())
