"""Prevention logs page — deploy-facing list of stopped attacks."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List, Optional

from corvex.prevention_log import load_prevention_log, seed_from_live_lab


def render_logs_html(root: Path, entries: List[Dict[str, Any]]) -> str:
    payload = json.dumps({"entries": entries}, separators=(",", ":"))
    count = len(entries)
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8"/>
<meta name="viewport" content="width=device-width, initial-scale=1"/>
<title>Corvex — Prevention log</title>
<link rel="preconnect" href="https://fonts.googleapis.com"/>
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin/>
<link href="https://fonts.googleapis.com/css2?family=IBM+Plex+Mono:wght@400;500;600&family=Outfit:wght@400;500;600;700&display=swap" rel="stylesheet"/>
<style>
:root {{
  --bg:#06080b; --panel:#10151d; --panel-hover:#141b25;
  --line:rgba(255,255,255,0.07); --line-strong:rgba(255,255,255,0.12);
  --text:#f2f5f8; --muted:#8b96a8; --dim:#5c6778;
  --good:#2fd67b; --good-bg:rgba(47,214,123,0.1);
  --bad:#ff5c6a; --warn:#e8b84a; --accent:#4db8ff;
  --font:"Outfit",system-ui,sans-serif; --mono:"IBM Plex Mono",ui-monospace,monospace;
}}
* {{ box-sizing:border-box; }}
html,body {{ margin:0; min-height:100%; }}
body {{
  font-family:var(--font); color:var(--text); background:var(--bg);
  -webkit-font-smoothing:antialiased;
}}
.app {{ max-width:960px; margin:0 auto; padding:0 20px 48px; }}
.top {{
  display:flex; align-items:center; justify-content:space-between; gap:12px;
  padding:18px 0 16px; border-bottom:1px solid var(--line);
}}
.brand {{ font-size:1.05rem; font-weight:600; margin:0; }}
.brand span {{ color:var(--dim); font-weight:500; margin-left:6px; }}
.nav {{ display:flex; gap:8px; }}
.nav a {{
  color:var(--muted); text-decoration:none; font-size:0.84rem; font-weight:500;
  padding:6px 10px; border-radius:8px; border:1px solid transparent;
}}
.nav a:hover {{ color:var(--text); background:var(--panel); }}
.nav a.active {{ color:var(--text); border-color:var(--line); background:var(--panel); }}
.hero {{ margin-top:22px; }}
.hero h2 {{ margin:0 0 6px; font-size:1.35rem; letter-spacing:-0.02em; }}
.hero p {{ margin:0; color:var(--muted); font-size:0.92rem; line-height:1.45; max-width:40rem; }}
.stats {{ display:flex; gap:10px; flex-wrap:wrap; margin-top:16px; }}
.stat {{
  border:1px solid var(--line); background:var(--panel); border-radius:12px;
  padding:10px 14px; font-size:0.8rem; color:var(--muted);
}}
.stat b {{ color:var(--text); font-family:var(--mono); font-size:1rem; margin-right:6px; }}
.list {{ margin-top:20px; display:flex; flex-direction:column; gap:10px; }}
.card {{
  border:1px solid var(--line); background:var(--panel); border-radius:14px; padding:14px 16px;
}}
.card:hover {{ background:var(--panel-hover); }}
.row1 {{ display:flex; justify-content:space-between; gap:12px; align-items:baseline; flex-wrap:wrap; }}
.name {{ font-size:1rem; font-weight:600; letter-spacing:-0.01em; }}
.when {{ font-family:var(--mono); font-size:0.72rem; color:var(--dim); }}
.pill {{
  display:inline-block; font-size:0.72rem; font-weight:500; padding:3px 8px; border-radius:999px;
  border:1px solid var(--line); color:var(--muted); margin-right:6px; margin-top:8px;
}}
.pill.ok {{ color:var(--good); border-color:rgba(47,214,123,0.3); background:var(--good-bg); }}
.pill.warn {{ color:var(--warn); border-color:rgba(232,184,74,0.3); background:rgba(232,184,74,0.08); }}
.summary {{ margin:10px 0 0; color:var(--muted); font-size:0.86rem; line-height:1.45; }}
.actions {{ margin-top:10px; font-family:var(--mono); font-size:0.72rem; color:var(--dim); line-height:1.5; }}
.empty {{
  margin-top:28px; border:1px dashed var(--line); border-radius:14px; padding:28px;
  color:var(--muted); text-align:center; font-size:0.92rem;
}}
</style>
</head>
<body>
<div class="app">
  <header class="top">
    <h1 class="brand">Corvex <span>Prevention log</span></h1>
    <nav class="nav">
      <a href="./">Monitor</a>
      <a class="active" href="./logs.html">Prevention log</a>
    </nav>
  </header>
  <section class="hero">
    <h2>Attacks prevented</h2>
    <p>Deploy-facing history of campaigns Corvex detected and stopped or isolated. Newest first.</p>
    <div class="stats">
      <div class="stat"><b id="count">{count}</b> recorded</div>
      <div class="stat"><b id="hosts">0</b> hosts touched</div>
    </div>
  </section>
  <section class="list" id="list"></section>
  <div class="empty" id="empty" hidden>No prevented attacks yet. When Corvex isolates or blocks a campaign in production, it shows up here.</div>
</div>
<script type="application/json" id="data">{payload}</script>
<script>
(function(){{
  const {{ entries }} = JSON.parse(document.getElementById('data').textContent);
  const list = document.getElementById('list');
  const empty = document.getElementById('empty');
  document.getElementById('count').textContent = String(entries.length);
  const hostSet = new Set();
  entries.forEach(e => (e.hosts||[]).forEach(h => hostSet.add(h)));
  document.getElementById('hosts').textContent = String(hostSet.size);

  if (!entries.length) {{ empty.hidden = false; return; }}

  list.innerHTML = entries.map(e => {{
    const hosts = (e.hosts||[]).join(', ') || '—';
    const actions = (e.actions||[]).map(a => `· ${{a}}`).join('<br/>');
    const status = e.status || 'prevented';
    return `<article class="card">
      <div class="row1">
        <div class="name">${{e.attack_name || e.attack_type || 'Attack'}}</div>
        <div class="when">${{e.ts || ''}}</div>
      </div>
      <div>
        <span class="pill ok">${{status}}</span>
        ${{e.attack_type ? `<span class="pill">${{e.attack_type}}</span>` : ''}}
        ${{e.campaign_id ? `<span class="pill">${{e.campaign_id}}</span>` : ''}}
        ${{e.identity ? `<span class="pill warn">${{e.identity}}</span>` : ''}}
        ${{e.source ? `<span class="pill">${{e.source}}</span>` : ''}}
      </div>
      <p class="summary">${{e.summary || ''}}</p>
      <div class="actions">Hosts: ${{hosts}}${{actions ? '<br/>'+actions : ''}}</div>
    </article>`;
  }}).join('');

  // Live refresh when served
  setInterval(async () => {{
    try {{
      const res = await fetch('/api/prevention?ts=' + Date.now(), {{ cache:'no-store' }});
      if (!res.ok) return;
      const data = await res.json();
      if ((data.entries||[]).length !== entries.length) location.reload();
    }} catch (e) {{}}
  }}, 5000);
}})();
</script>
</body>
</html>
"""


def write_logs_page(root: Path, out_dir: Optional[Path] = None) -> Path:
    seed_from_live_lab(root)
    entries = load_prevention_log(root)
    out_dir = Path(out_dir or (Path(root) / "reports" / "dashboard"))
    out_dir.mkdir(parents=True, exist_ok=True)
    path = out_dir / "logs.html"
    path.write_text(render_logs_html(root, entries), encoding="utf-8")
    (out_dir / "prevention.json").write_text(
        json.dumps({"entries": entries}, indent=2) + "\n", encoding="utf-8"
    )
    return path
