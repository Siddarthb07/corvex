#!/usr/bin/env python3
"""Run the live Docker sandbox attack, then export GIF + MP4 of the theatre."""

from __future__ import annotations

import json
import shutil
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
LAB = ROOT / ".sandbox" / "live-lab"
SHARED = LAB / "shared"
THEATRE_SRC = LAB / "theatre" / "index.html"
OUT_DIR = ROOT / ".sandbox" / "demo"


def run(cmd: list[str], cwd: Path | None = None) -> None:
    print("+", " ".join(cmd), flush=True)
    subprocess.run(cmd, cwd=str(cwd or LAB), check=True)


def main() -> int:
    if shutil.which("docker") is None:
        print("Docker required", file=sys.stderr)
        return 1

    if SHARED.exists():
        shutil.rmtree(SHARED, ignore_errors=True)
    SHARED.mkdir(parents=True)
    (SHARED / "isolated").mkdir(parents=True)
    # Serve theatre from shared so browser can poll theatre_state.json
    shutil.copy2(THEATRE_SRC, SHARED / "index.html")

    run(["docker", "compose", "down", "-v", "--remove-orphans"])
    run(["docker", "compose", "up", "--build", "-d", "host-a", "host-b", "host-c", "corvex"])
    time.sleep(2)
    run(["docker", "compose", "up", "--build", "-d", "attacker"])

    # Wait for attack_complete
    deadline = time.time() + 180
    state_path = SHARED / "attacker_state.json"
    while time.time() < deadline:
        if state_path.exists():
            try:
                st = json.loads(state_path.read_text(encoding="utf-8"))
                if st.get("kind") == "attack_complete":
                    print("attack complete:", st, flush=True)
                    break
            except json.JSONDecodeError:
                pass
        time.sleep(0.5)
    else:
        print("timeout waiting for attack", file=sys.stderr)
        run(["docker", "compose", "logs", "--no-color"])
        return 1

    # Let corvex finalize theatre state
    time.sleep(2)
    run(["docker", "compose", "logs", "--no-color", "attacker", "corvex"])

    # Copy artifacts into demo folder
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    for name in ("theatre_state.json", "events.jsonl", "attacker.jsonl"):
        src = SHARED / name
        if src.exists():
            shutil.copy2(src, OUT_DIR / f"live-{name}")
    shutil.copy2(SHARED / "index.html", OUT_DIR / "live-lab-theatre.html")
    if (SHARED / "corvex_state.json").exists():
        shutil.copy2(SHARED / "corvex_state.json", OUT_DIR / "live-corvex_state.json")

    # Build cinematic replay from captured live feed
    state = json.loads((SHARED / "theatre_state.json").read_text(encoding="utf-8"))
    replay = OUT_DIR / "live-lab-replay.html"
    replay.write_text(_replay_html(state), encoding="utf-8")

    sys.path.insert(0, str(Path(__file__).resolve().parent))
    from export_live_lab_video import export_replay

    export_replay(replay, OUT_DIR / "corvex-live-lab.gif", OUT_DIR / "corvex-live-lab.mp4")

    run(["docker", "compose", "down", "-v"])
    print("\nArtifacts:")
    print(" ", OUT_DIR / "corvex-live-lab.mp4")
    print(" ", OUT_DIR / "corvex-live-lab.gif")
    print(" ", OUT_DIR / "live-lab-theatre.html")
    return 0


def _replay_html(state: dict) -> str:
    """Cinematic replay that animates the captured live feed."""
    payload = json.dumps(state)
    return f"""<!DOCTYPE html>
<html lang="en"><head>
<meta charset="utf-8"/><meta name="viewport" content="width=device-width, initial-scale=1"/>
<title>Corvex Live Lab Replay</title>
<link href="https://fonts.googleapis.com/css2?family=IBM+Plex+Mono:wght@400;500;600&family=Outfit:wght@500;700&display=swap" rel="stylesheet"/>
<style>
:root{{--bg:#05070a;--attack:#ff5c6a;--detect:#4db8ff;--defend:#2fd67b;--text:#eef3f8;--muted:#8b96a8}}
*{{box-sizing:border-box}} body{{margin:0;font-family:Outfit,system-ui,sans-serif;background:var(--bg);color:var(--text);overflow:hidden}}
.app{{max-width:1200px;margin:0 auto;padding:16px;height:100vh;display:grid;grid-template-rows:auto 1fr}}
.top{{display:flex;justify-content:space-between;align-items:center}}
.phase{{font-family:IBM Plex Mono,monospace;font-size:.75rem;padding:6px 10px;border-radius:999px;border:1px solid #222}}
.stage{{display:grid;grid-template-columns:1.2fr .8fr;gap:12px;min-height:0;margin-top:12px}}
.panel{{background:#0d1219;border:1px solid #1c2430;border-radius:16px;position:relative;overflow:hidden}}
svg{{width:100%;height:100%}}
.host{{fill:#121821;stroke:#2a3344;stroke-width:2}} .host.hit{{stroke:var(--attack);fill:rgba(255,92,106,.14)}}
.host.isolated{{stroke:var(--defend);fill:rgba(47,214,123,.14)}}
.attacker{{fill:#1a1012;stroke:var(--attack);stroke-width:2}}
.label{{fill:#eef3f8;font-size:13px;font-weight:600}} .sub{{fill:#8b96a8;font-size:10px;font-family:IBM Plex Mono,monospace}}
.link{{fill:none;stroke:var(--attack);stroke-width:2;opacity:0}} .link.on{{opacity:1}}
.mesh{{fill:none;stroke:var(--detect);stroke-width:2;stroke-dasharray:6 6;opacity:0}} .mesh.on{{opacity:1}}
.shield{{fill:none;stroke:var(--defend);stroke-width:3;opacity:0}} .shield.on{{opacity:1}}
.caption{{position:absolute;left:14px;right:14px;bottom:14px;background:rgba(5,7,10,.8);border:1px solid #1c2430;border-radius:12px;padding:12px}}
.stream{{padding:12px;overflow:auto;font-family:IBM Plex Mono,monospace;font-size:.72rem;height:100%}}
.evt{{border:1px solid #1c2430;border-radius:10px;padding:10px;margin-bottom:8px;background:#0a0f16}}
.evt.auth{{border-color:rgba(255,92,106,.35)}} .evt.detect{{border-color:rgba(77,184,255,.4)}}
.evt.defend,.evt.blocked{{border-color:rgba(47,214,123,.4)}}
</style></head><body>
<div class="app">
  <div class="top"><strong>Corvex · live lab replay</strong><div class="phase" id="phase">REPLAY</div></div>
  <div class="stage">
    <div class="panel" style="min-height:520px">
      <svg viewBox="0 0 900 560">
        <circle class="attacker" cx="120" cy="280" r="34"/><text class="label" x="120" y="286" text-anchor="middle">Attacker</text>
        <text class="sub" x="120" y="330" text-anchor="middle">10.1.0.5</text>
        <path id="la" class="link" d="M154 260 C260 180 320 150 378 145"/>
        <path id="lb" class="link" d="M154 280 C300 280 480 280 578 280"/>
        <path id="lc" class="link" d="M154 300 C260 380 320 410 378 415"/>
        <path id="mab" class="mesh" d="M462 155 L578 255"/><path id="mbc" class="mesh" d="M578 305 L462 405"/><path id="mac" class="mesh" d="M420 182 L420 378"/>
        <circle id="ha" class="host" cx="420" cy="140" r="42"/><circle id="sa" class="shield" cx="420" cy="140" r="54"/>
        <text class="label" x="420" y="146" text-anchor="middle">host-a</text><text class="sub" x="420" y="198" text-anchor="middle">workstation</text>
        <circle id="hb" class="host" cx="620" cy="280" r="42"/><circle id="sb" class="shield" cx="620" cy="280" r="54"/>
        <text class="label" x="620" y="286" text-anchor="middle">host-b</text><text class="sub" x="620" y="338" text-anchor="middle">fileserver</text>
        <circle id="hc" class="host" cx="420" cy="420" r="42"/><circle id="sc" class="shield" cx="420" cy="420" r="54"/>
        <text class="label" x="420" y="426" text-anchor="middle">host-c</text><text class="sub" x="420" y="478" text-anchor="middle">jump box</text>
        <text id="camp" x="700" y="60" fill="#4db8ff" font-family="IBM Plex Mono" font-size="12" opacity="0"></text>
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
const map = {{'host-a':['ha','la','sa'],'host-b':['hb','lb','sb'],'host-c':['hc','lc','sc']}};
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
    document.getElementById('mab').classList.add('on');
    document.getElementById('mbc').classList.add('on');
    document.getElementById('mac').classList.add('on');
    const c=(STATE.campaigns||[])[0]; if(c){{ const e=document.getElementById('camp'); e.textContent=c.id; e.style.opacity=1; }}
    document.getElementById('phase').textContent='DETECT';
  }}
  if(item.type==='defend') document.getElementById('phase').textContent='DEFEND';
  if(item.type==='blocked') document.getElementById('phase').textContent='CONTAINED';
  document.getElementById('caption').textContent=item.text||STATE.caption||'';
}}
function tick(){{
  if(i>=feed.length){{ document.getElementById('phase').textContent='DONE'; document.getElementById('caption').textContent=STATE.caption||'Live lab complete'; return; }}
  add(feed[i++]);
  setTimeout(tick, 700);
}}
setTimeout(tick, 500);
</script></body></html>
"""


if __name__ == "__main__":
    # late import helper file written next
    raise SystemExit(main())
