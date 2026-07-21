"""Generate Corvex monitoring dashboard from reports/*.json."""

from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from html import escape
from pathlib import Path
from typing import Any, Dict, Optional


def _load(path: Path) -> Optional[Dict[str, Any]]:
    if not path.exists():
        return None
    return json.loads(path.read_text(encoding="utf-8"))


def _resolve_run_dir(root: Path) -> Optional[Path]:
    env = os.environ.get("CORVEX_RUN_DIR")
    if env:
        p = Path(env)
        return p if p.exists() else None
    latest = root / "runs" / "latest"
    if latest.is_symlink() or latest.is_dir():
        return latest.resolve()
    if latest.is_file():
        target = Path(latest.read_text(encoding="utf-8").strip())
        return target if target.exists() else None
    # Fall back to newest runs/*/timeline.json
    runs = root / "runs"
    if not runs.is_dir():
        return None
    candidates = sorted(
        (p.parent for p in runs.glob("*/timeline.json")),
        key=lambda p: p.stat().st_mtime,
        reverse=True,
    )
    return candidates[0] if candidates else None


def collect_snapshot(root: Path) -> Dict[str, Any]:
    reports = root / "reports"
    held = _load(reports / "stageA_heldout.json") or {}
    train = _load(reports / "stageA_train.json") or {}
    audit = _load(reports / "AUDIT_BENCHMARK.json") or {}
    checklist = _load(reports / "security_l1_checklist.json") or {}
    gate_path = reports / "stageA-gate.txt"
    gate = gate_path.read_text(encoding="utf-8").strip() if gate_path.exists() else "UNKNOWN"
    retention = _load(reports / "oss_retention.json") or {"labs": []}
    dry_lines = 0
    dry = reports / "stage_d_dry_run.jsonl"
    if dry.exists():
        dry_lines = sum(1 for line in dry.read_text(encoding="utf-8").splitlines() if line.strip())

    l1_items = {
        k: v
        for k, v in checklist.items()
        if not str(k).startswith("_") and isinstance(v, bool)
    }
    l1_done = sum(1 for v in l1_items.values() if v)
    hm = held.get("metrics") or {}

    def mget(block_name: str, field: str = "campaign_f1") -> float:
        block = hm.get(block_name) or {}
        val = block.get(field)
        return float(val) if val is not None else 0.0

    run_dir = _resolve_run_dir(root)
    timeline: Dict[str, Any] = {}
    campaigns: list = []
    if run_dir is not None:
        tl_path = run_dir / "timeline.json"
        if tl_path.exists():
            timeline = json.loads(tl_path.read_text(encoding="utf-8"))
            campaigns = list(timeline.get("campaigns") or [])

    return {
        "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "gate": gate,
        "heldout_pass": bool(held.get("pass")),
        "train_pass": bool(train.get("pass")),
        "care_vs_incumbent": held.get("care_vs_incumbent", "unproven"),
        "metrics": {
            "correlator_f1": mget("correlator"),
            "b1_f1": mget("b1"),
            "b2_f1": mget("b2"),
            "detector_only_f1": mget("detector_only"),
            "precision_at_1": mget("correlator", "precision_at_1"),
            "false_campaign_rate": mget("correlator", "false_campaign_rate"),
            "ttu_seconds": mget("correlator", "ttu_seconds"),
        },
        "ablation": held.get("ablation") or {},
        "stage_b_allowed": (reports / "stage-b-allowed").exists(),
        "stage_c_retention_labs": len(retention.get("labs") or []),
        "stage_d": {
            "checklist_pct": round(100.0 * l1_done / max(1, len(l1_items)), 1) if l1_items else 0.0,
            "checklist_done": l1_done,
            "checklist_total": len(l1_items),
            "items": l1_items,
            "dry_run_lines": dry_lines,
            "live_contain": False,
        },
        "corvex_contain": int(
            audit.get("CORVEX_CONTAIN", audit.get("CFUSE_CONTAIN", 0)) or 0
        ),
        "version": str(audit.get("version") or "0.4.0"),
        "run_dir": str(run_dir) if run_dir else None,
        "campaigns": campaigns,
        "timeline_pack": timeline.get("pack"),
        "timeline_ttu": timeline.get("ttu_seconds"),
    }


CHECKLIST_COPY = {
    "mtls_identities": ("Prove who’s talking", "Sensors must prove TLS identity."),
    "typed_commands": ("Named actions only", "Fixed actions only — no free-form shell."),
    "authz_neq_sig": ("Signed ≠ allowed", "Signature alone is not permission."),
    "anti_replay": ("Block reused commands", "Old quarantine messages can’t be resent."),
    "dual_control": ("Two-person approval", "Destructive actions need two approvals."),
    "fail_closed": ("Stop if unsure", "Refuse when auth/policy breaks."),
    "least_privilege": ("Min permissions", "Only the OS rights required."),
    "immutable_audit": ("Tamper-proof log", "Hash-chained quarantine decisions."),
    "oversight_off_data_plane": ("Separate kill switch", "Stop control off the data channel."),
    "no_free_form_shell": ("No remote shell", "Cannot open arbitrary shells."),
    "blast_radius_caps": ("Limit blast radius", "Cap how many hosts per window."),
}


def render_html(snap: Dict[str, Any]) -> str:
    payload = json.dumps({"snap": snap, "checklist_copy": CHECKLIST_COPY}, separators=(",", ":"))
    gen = escape(snap["generated_at"])
    ver = escape(str(snap.get("version")))
    gate = escape(str(snap.get("gate")))
    passed = snap.get("gate") == "PASS"

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8"/>
<meta name="viewport" content="width=device-width, initial-scale=1"/>
<title>Corvex</title>
<link rel="preconnect" href="https://fonts.googleapis.com"/>
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin/>
<link href="https://fonts.googleapis.com/css2?family=IBM+Plex+Mono:wght@400;500;600&family=Outfit:wght@400;500;600;700&display=swap" rel="stylesheet"/>
<style>
:root {{
  --bg: #06080b; --panel: #10151d; --panel-hover: #141b25;
  --line: rgba(255,255,255,0.07); --line-strong: rgba(255,255,255,0.12);
  --text: #f2f5f8; --muted: #8b96a8; --dim: #5c6778;
  --good: #2fd67b; --good-bg: rgba(47,214,123,0.12);
  --bad: #ff5c6a; --warn: #e8b84a; --warn-bg: rgba(232,184,74,0.1);
  --accent: #4db8ff; --radius: 12px;
  --font: "Outfit", system-ui, sans-serif;
  --mono: "IBM Plex Mono", ui-monospace, monospace;
}}
* {{ box-sizing: border-box; }}
html, body {{ margin: 0; min-height: 100%; }}
body {{
  font-family: var(--font); color: var(--text); background: var(--bg);
  -webkit-font-smoothing: antialiased;
}}
body::before {{
  content:""; position:fixed; inset:0; pointer-events:none; z-index:0;
  background:
    radial-gradient(ellipse 80% 50% at 0% -10%, rgba(77,184,255,0.09), transparent 50%),
    radial-gradient(ellipse 60% 40% at 100% 0%, rgba(47,214,123,0.05), transparent 45%);
}}
.app {{ position:relative; z-index:1; max-width:1080px; margin:0 auto; padding:0 20px 48px; }}
.top {{
  display:flex; align-items:center; justify-content:space-between; gap:16px;
  padding:18px 0 16px; border-bottom:1px solid var(--line);
}}
.brand-row {{ display:flex; align-items:center; gap:12px; }}
.mark {{
  width:28px; height:28px; border-radius:8px; display:grid; place-items:center;
  background:linear-gradient(145deg,#1a3040,#0e1822); border:1px solid var(--line-strong);
}}
.mark svg {{ width:14px; height:14px; }}
.brand {{ font-size:1.05rem; font-weight:600; letter-spacing:-0.02em; margin:0; }}
.brand span {{ color:var(--dim); font-weight:500; margin-left:6px; font-size:0.85rem; }}
.top-meta {{
  display:flex; align-items:center; gap:10px; flex-wrap:wrap; justify-content:flex-end;
  font-family:var(--mono); font-size:0.7rem; color:var(--dim);
}}
.live {{
  display:inline-flex; align-items:center; gap:6px; padding:4px 9px; border-radius:999px;
  border:1px solid var(--line); background:#0c1016; color:var(--muted);
}}
.live i {{
  width:6px; height:6px; border-radius:50%; background:var(--good);
  box-shadow:0 0 0 3px rgba(47,214,123,0.2);
}}
.hero {{ display:grid; grid-template-columns:1.4fr 1fr; gap:12px; margin-top:20px; }}
.panel {{ background:var(--panel); border:1px solid var(--line); border-radius:var(--radius); }}
.status-card {{ padding:22px 24px; }}
.status-label {{
  font-size:0.7rem; font-weight:500; letter-spacing:0.08em;
  text-transform:uppercase; color:var(--dim); margin-bottom:10px;
}}
.status-word {{
  font-size:clamp(2.4rem,5vw,3.2rem); font-weight:700;
  letter-spacing:-0.04em; line-height:1;
}}
.status-word.pass {{ color:var(--good); }}
.status-word.fail {{ color:var(--bad); }}
.pill-row {{ display:flex; flex-wrap:wrap; gap:8px; margin-top:16px; }}
.pill {{
  font-size:0.75rem; font-weight:500; padding:5px 10px; border-radius:999px;
  border:1px solid var(--line); color:var(--muted); background:#0c1016;
}}
.pill.on {{ color:var(--good); border-color:rgba(47,214,123,0.28); background:var(--good-bg); }}
.pill.warn {{ color:var(--warn); border-color:rgba(232,184,74,0.28); background:var(--warn-bg); }}
.side-stack {{ display:flex; flex-direction:column; gap:12px; }}
.mini {{ flex:1; padding:16px 18px; }}
.mini .k {{ font-size:0.7rem; letter-spacing:0.06em; text-transform:uppercase; color:var(--dim); }}
.mini .v {{ font-size:1.35rem; font-weight:600; letter-spacing:-0.02em; margin-top:6px; }}
.section {{ margin-top:24px; }}
.section-head {{ display:flex; align-items:baseline; justify-content:space-between; gap:12px; margin-bottom:12px; }}
.section-head h2 {{ margin:0; font-size:0.95rem; font-weight:600; }}
.section-head p {{ margin:0; font-size:0.8rem; color:var(--dim); }}
.metrics {{ display:grid; grid-template-columns:repeat(4,1fr); gap:10px; }}
.metric {{
  padding:16px; background:var(--panel); border:1px solid var(--line); border-radius:var(--radius);
}}
.metric .label {{ font-size:0.72rem; color:var(--muted); font-weight:500; }}
.metric .value {{
  font-family:var(--mono); font-size:1.55rem; font-weight:600;
  letter-spacing:-0.03em; margin-top:10px; font-variant-numeric:tabular-nums;
}}
.grid-2 {{ display:grid; grid-template-columns:1.15fr 0.85fr; gap:12px; }}
.card {{ padding:18px; }}
.card-title {{
  font-size:0.72rem; letter-spacing:0.07em; text-transform:uppercase;
  color:var(--dim); margin-bottom:14px; font-weight:500;
}}
.bar {{ margin-bottom:14px; }}
.bar:last-child {{ margin-bottom:0; }}
.bar-top {{ display:flex; justify-content:space-between; margin-bottom:6px; gap:8px; }}
.bar-top strong {{ font-size:0.85rem; font-weight:500; }}
.bar-top span {{ font-family:var(--mono); font-size:0.72rem; color:var(--muted); }}
.track {{ height:6px; border-radius:999px; background:rgba(255,255,255,0.06); overflow:hidden; }}
.fill {{ height:100%; border-radius:inherit; background:var(--good); }}
.fill.warn {{ background:var(--warn); }}
.fill.bad {{ background:var(--bad); min-width:4px; }}
.note {{
  margin-top:14px; padding:10px 12px; border-radius:8px; font-size:0.78rem;
  color:#e8d4a0; background:var(--warn-bg); border:1px solid rgba(232,184,74,0.22);
}}
.note[hidden] {{ display:none; }}
.roadmap {{ display:grid; grid-template-columns:repeat(4,1fr); gap:0; position:relative; }}
.roadmap::before {{
  content:""; position:absolute; left:12%; right:12%; top:27px; height:1px;
  background:var(--line-strong); z-index:0;
}}
.step {{ position:relative; z-index:1; text-align:center; padding:0 8px 4px; }}
.dot {{
  width:14px; height:14px; border-radius:50%; margin:20px auto 12px;
  border:2px solid var(--line-strong); background:var(--bg);
}}
.step.done .dot {{ background:var(--good); border-color:var(--good); }}
.step.active .dot {{ border-color:var(--warn); background:var(--warn); }}
.step .name {{ font-size:0.82rem; font-weight:600; }}
.step .desc {{ font-size:0.72rem; color:var(--dim); margin-top:4px; }}
.step .badge {{
  display:inline-block; margin-top:8px; font-family:var(--mono); font-size:0.65rem;
  padding:3px 7px; border-radius:999px; border:1px solid var(--line); color:var(--muted);
}}
.step.done .badge {{ color:var(--good); border-color:rgba(47,214,123,0.3); background:var(--good-bg); }}
.step.active .badge {{ color:var(--warn); border-color:rgba(232,184,74,0.3); background:var(--warn-bg); }}
.controls {{ overflow:hidden; }}
.ctrl-row {{
  display:grid; grid-template-columns:1fr auto; gap:12px; align-items:center;
  padding:12px 16px; border-bottom:1px solid var(--line);
}}
.ctrl-row:last-child {{ border-bottom:none; }}
.ctrl-row:hover {{ background:var(--panel-hover); }}
.ctrl-name {{ font-size:0.86rem; font-weight:500; }}
.switch {{
  position:relative; width:44px; height:26px; flex-shrink:0;
}}
.switch input {{
  opacity:0; width:0; height:0; position:absolute;
}}
.switch span {{
  position:absolute; inset:0; cursor:pointer; border-radius:999px;
  background:rgba(255,255,255,0.1); border:1px solid var(--line-strong);
  transition: background .15s ease, border-color .15s ease;
}}
.switch span::before {{
  content:""; position:absolute; width:20px; height:20px; border-radius:50%;
  left:2px; top:2px; background:#d7dde8; transition: transform .15s ease, background .15s ease;
}}
.switch input:checked + span {{
  background:var(--good-bg); border-color:rgba(47,214,123,0.45);
}}
.switch input:checked + span::before {{
  transform: translateX(18px); background:var(--good);
}}
.switch input:disabled + span {{ opacity:0.45; cursor:not-allowed; }}
.switch.busy span {{ opacity:0.6; }}
.toast {{
  position:fixed; bottom:20px; left:50%; transform:translateX(-50%);
  background:#1a2230; border:1px solid var(--line-strong); color:var(--text);
  padding:10px 14px; border-radius:10px; font-size:0.82rem; z-index:20;
  box-shadow:0 12px 40px rgba(0,0,0,0.45); display:none;
}}
.toast.show {{ display:block; }}
.toast.err {{ border-color:rgba(255,92,106,0.4); color:#ffc4c9; }}
.toast.err {{ border-color:rgba(255,92,106,0.4); color:#ffc4c9; }}
.nav {{ display:flex; gap:8px; align-items:center; }}
.nav a {{
  color:var(--muted); text-decoration:none; font-size:0.84rem; font-weight:500;
  padding:6px 10px; border-radius:8px; border:1px solid transparent;
}}
.nav a:hover {{ color:var(--text); background:var(--panel); }}
.nav a.active {{ color:var(--text); border-color:var(--line); background:var(--panel); }}
@media (max-width:860px) {{
  .hero,.grid-2,.metrics {{ grid-template-columns:1fr 1fr; }}
  .roadmap {{ grid-template-columns:1fr 1fr; gap:16px; }}
  .roadmap::before {{ display:none; }}
}}
@media (max-width:560px) {{
  .hero,.grid-2,.metrics,.roadmap {{ grid-template-columns:1fr; }}
  .top {{ flex-direction:column; align-items:flex-start; }}
}}
</style>
</head>
<body>
<div class="app">
  <header class="top">
    <div class="brand-row">
      <div class="mark" aria-hidden="true">
        <svg viewBox="0 0 16 16" fill="none">
          <path d="M3 11.5C5.5 11.5 7 9.2 8.2 6.8C9.1 5 10.2 3.5 12.5 3.2" stroke="#4db8ff" stroke-width="1.5" stroke-linecap="round"/>
          <path d="M8.2 6.8C7.2 8.5 6.8 10.2 8 12.2" stroke="#4db8ff" stroke-width="1.5" stroke-linecap="round"/>
          <circle cx="12.6" cy="3.2" r="1.1" fill="#4db8ff"/>
        </svg>
      </div>
      <h1 class="brand">Corvex <span>Monitor</span></h1>
    </div>
    <div class="top-meta">
      <nav class="nav">
        <a class="active" href="./">Monitor</a>
        <a href="./logs.html">Prevention log</a>
      </nav>
      <span class="live"><i></i> live</span>
      <span>v{ver}</span>
      <span id="genStamp">{gen}</span>
    </div>
  </header>

  <section class="hero">
    <div class="panel status-card">
      <div class="status-label">Eval gate</div>
      <div class="status-word {'pass' if passed else 'fail'}" id="gateWord">{gate}</div>
      <div class="pill-row" id="pills"></div>
    </div>
    <div class="side-stack">
      <div class="panel mini">
        <div class="k">Containment</div>
        <div class="v" id="containTitle">—</div>
      </div>
      <div class="panel mini">
        <div class="k">Safety ready</div>
        <div class="v" id="readyTitle">—</div>
      </div>
    </div>
  </section>

  <section class="section">
    <div class="section-head"><h2>Campaigns</h2><p id="runHint"></p></div>
    <div class="panel card" id="campaigns">No replay loaded yet — run <code>corvex replay train/train-lateral.jsonl</code></div>
  </section>

  <section class="section">
    <div class="section-head"><h2>Detection</h2></div>
    <div class="metrics" id="metrics"></div>
  </section>

  <section class="section">
    <div class="grid-2">
      <div class="panel card">
        <div class="card-title">Comparison</div>
        <div id="bars"></div>
        <div class="note" id="honesty" hidden></div>
      </div>
      <div class="panel card">
        <div class="card-title">Capability</div>
        <div class="roadmap" id="roadmap"></div>
      </div>
    </div>
  </section>

  <section class="section">
    <div class="section-head">
      <h2>Safety controls</h2>
      <p id="ctrlSummary"></p>
    </div>
    <div class="panel controls" id="controls"></div>
  </section>
</div>
<div class="toast" id="toast"></div>
<script type="application/json" id="data">{payload}</script>
<script>
(function(){{
  let {{ snap, checklist_copy }} = JSON.parse(document.getElementById('data').textContent);
  const fmt = (x, digits=2) => x==null ? '—' : Number(x).toLocaleString(undefined, {{
    minimumFractionDigits: digits, maximumFractionDigits: digits
  }});
  const pct = (x) => Math.max(0, Math.min(100, Number(x||0)*100));
  const toast = (msg, err=false) => {{
    const el = document.getElementById('toast');
    el.textContent = msg;
    el.className = 'toast show' + (err ? ' err' : '');
    clearTimeout(toast._t);
    toast._t = setTimeout(() => el.classList.remove('show'), 2200);
  }};

  function render(s) {{
    snap = s;
    const m = s.metrics || {{}};
    const d = s.stage_d || {{}};
    const pass = s.gate === 'PASS';
    const containOff = s.corvex_contain === 0;
    const labs = s.stage_c_retention_labs || 0;
    let readyPct = d.checklist_pct || 0;

    document.getElementById('gateWord').textContent = pass ? 'PASS' : (s.gate === 'UNKNOWN' || !s.gate ? '—' : s.gate);
    document.getElementById('gateWord').className = 'status-word ' + (pass ? 'pass' : 'fail');
    document.getElementById('genStamp').textContent = s.generated_at || '';
    document.getElementById('pills').innerHTML = [
      `<span class="pill ${{s.train_pass ? 'on' : ''}}">Train ${{s.train_pass ? 'ok' : '—'}}</span>`,
      `<span class="pill warn">vs tools: ${{s.care_vs_incumbent || 'unproven'}}</span>`,
      `<span class="pill">Isolate ${{containOff ? 'off' : 'on'}}</span>`,
    ].join('');

    document.getElementById('containTitle').textContent = containOff ? 'Dry-run only' : 'Live on';
    document.getElementById('containTitle').style.color = containOff ? 'var(--muted)' : 'var(--warn)';

    const camps = s.campaigns || [];
    const runHint = document.getElementById('runHint');
    if (s.run_dir) {{
      runHint.textContent = `${{camps.length}} campaign(s) · ${{s.timeline_pack || s.run_dir}}`;
    }} else {{
      runHint.textContent = 'Load a replay with `corvex replay …` or `corvex dash --run-dir runs/demo`';
    }}
    const campEl = document.getElementById('campaigns');
    if (!camps.length) {{
      campEl.innerHTML = 'No campaigns yet. Replay a train pack first.';
    }} else {{
      campEl.innerHTML = camps.map(c => {{
        const hosts = (c.host_ids || []).join(', ');
        const stages = (c.stages || []).map(st => st.name || st.stage || '?').join(' → ');
        return `<div class="ctrl-row"><div class="ctrl-name"><strong>${{c.campaign_id || 'campaign'}}</strong><div class="desc" style="color:var(--muted);font-size:12px;margin-top:4px">${{hosts}}</div><div class="desc" style="color:var(--muted);font-size:12px;margin-top:2px">${{stages || '—'}}</div></div><span class="badge">${{Number(c.score||0).toFixed(2)}}</span></div>`;
      }}).join('');
    }}

    const items = d.items || {{}};
    const keys = Object.keys(items).sort();
    const onCount = keys.filter(k => items[k]).length;
    readyPct = keys.length ? Math.round(1000 * onCount / keys.length) / 10 : readyPct;
    document.getElementById('readyTitle').textContent = `${{onCount}}/${{keys.length}} controls`;
    document.getElementById('ctrlSummary').textContent = `${{onCount}}/${{keys.length}} on`;

    document.getElementById('metrics').innerHTML = [
      ['Our score', m.correlator_f1],
      ['Naive', m.b1_f1],
      ['Classic', m.b2_f1],
      ['False alarms', m.false_campaign_rate],
    ].map(([label, value]) =>
      `<div class="metric"><div class="label">${{label}}</div><div class="value">${{fmt(value)}}</div></div>`
    ).join('');

    document.getElementById('bars').innerHTML = [
      ['Ours', m.correlator_f1],
      ['Patterns only', m.detector_only_f1],
      ['Classic', m.b2_f1],
      ['Naive', m.b1_f1],
    ].map(([label, value]) => {{
      const v = Number(value||0);
      const cls = v < 0.05 ? 'fill bad' : (v < 0.7 ? 'fill warn' : 'fill');
      const width = v < 0.05 ? '4px' : (pct(v) + '%');
      return `<div class="bar"><div class="bar-top"><strong>${{label}}</strong><span>${{fmt(v)}}</span></div>
        <div class="track"><div class="${{cls}}" style="width:${{width}}"></div></div></div>`;
    }}).join('');

    const honesty = document.getElementById('honesty');
    const det = Number(m.detector_only_f1||0), corr = Number(m.correlator_f1||0);
    if (Math.abs(det - corr) < 0.05) {{
      honesty.hidden = false;
      honesty.textContent = 'Patterns-only matched full linking on this test.';
    }} else {{
      honesty.hidden = true;
    }}

    document.getElementById('roadmap').innerHTML = [
      {{ name:'Eval', desc:'Held-out gate', cls: pass?'done':'locked', badge: pass?'PASS':(s.gate||'—') }},
      {{ name:'Sensors', desc:'Live hosts', cls: s.stage_b_allowed?'done':(pass?'active':'locked'), badge: s.stage_b_allowed?'open':'locked' }},
      {{ name:'Share', desc:'External labs', cls: labs>=3?'done':'locked', badge: `${{labs}}/3` }},
      {{ name:'Isolate', desc:'Quarantine', cls: readyPct>=100?'done':'locked', badge: `${{readyPct}}%` }},
    ].map(st => `<div class="step ${{st.cls}}"><div class="dot"></div><div class="name">${{st.name}}</div>
      <div class="desc">${{st.desc}}</div><span class="badge">${{st.badge}}</span></div>`).join('');

    document.getElementById('controls').innerHTML = keys.map(k => {{
      const copy = checklist_copy[k] || [k, ''];
      const on = !!items[k];
      return `<div class="ctrl-row" title="${{copy[1]}}">
        <div class="ctrl-name">${{copy[0]}}</div>
        <label class="switch">
          <input type="checkbox" data-key="${{k}}" ${{on?'checked':''}} aria-label="${{copy[0]}}"/>
          <span></span>
        </label>
      </div>`;
    }}).join('') || '<div class="ctrl-row"><div class="ctrl-name">No controls loaded</div></div>';

    document.querySelectorAll('#controls input[type=checkbox]').forEach(input => {{
      input.addEventListener('change', async () => {{
        const key = input.getAttribute('data-key');
        const enabled = !!input.checked;
        const label = input.closest('.switch');
        label.classList.add('busy');
        input.disabled = true;
        try {{
          const res = await fetch('/api/checklist', {{
            method: 'POST',
            headers: {{ 'Content-Type': 'application/json' }},
            body: JSON.stringify({{ key, enabled }}),
          }});
          const data = await res.json();
          if (!res.ok || !data.ok) throw new Error((data && data.error) || res.statusText);
          render(data.snap);
          toast((checklist_copy[key]||[key])[0] + (enabled ? ' on' : ' off'));
        }} catch (err) {{
          input.checked = !enabled;
          toast(String(err.message || err), true);
          input.disabled = false;
          label.classList.remove('busy');
        }}
      }});
    }});

  }}

  render(snap);
  // Prefer live API so toggles match disk after rebuilds
  fetch('/api/snapshot').then(r => r.json()).then(s => render(s)).catch(() => {{}});
}})();
</script>
</body>
</html>
"""


def write_dashboard(root: Path, out: Optional[Path] = None) -> Path:
    snap = collect_snapshot(root)
    out = Path(out or (root / "reports" / "dashboard" / "index.html"))
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(render_html(snap), encoding="utf-8")
    (out.parent / "snapshot.json").write_text(json.dumps(snap, indent=2), encoding="utf-8")
    from corvex.logs_page import write_logs_page

    write_logs_page(root, out_dir=out.parent)
    return out
