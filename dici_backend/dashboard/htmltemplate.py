
# ══════════════════════════════════════════════════════════════════════
# HTML TEMPLATE  –  full single-page dynamic dashboard
# ══════════════════════════════════════════════════════════════════════
HTML = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>DICI · Dynamic IDS Dashboard</title>
<script src="https://cdn.plot.ly/plotly-2.27.0.min.js"></script>
<link href="https://fonts.googleapis.com/css2?family=Space+Mono:wght@400;700&family=DM+Sans:wght@300;400;500;700&display=swap" rel="stylesheet">
<style>
:root{
  --bg:#050810;--surface:#0c1120;--card:#111827;--card2:#161f30;
  --border:#1e2d45;--border2:#243349;
  --accent:#00d4ff;--accent2:#00ff9d;--warn:#ffb700;--danger:#ff4757;
  --text:#e8f0fe;--muted:#607080;--faint:#2a3a52;
  --font-mono:'Space Mono',monospace;--font-body:'DM Sans',sans-serif;
  --glow-blue:0 0 20px rgba(0,212,255,.25);--glow-green:0 0 20px rgba(0,255,157,.2);
}
*{box-sizing:border-box;margin:0;padding:0;}
html,body{background:var(--bg);color:var(--text);font-family:var(--font-body);min-height:100vh;overflow-x:hidden;}
body::before{content:'';position:fixed;inset:0;background:
  radial-gradient(ellipse 80% 50% at 20% 10%,rgba(0,212,255,.05) 0%,transparent 60%),
  radial-gradient(ellipse 60% 40% at 80% 80%,rgba(0,255,157,.04) 0%,transparent 60%);
  pointer-events:none;z-index:0;}

/* ── Header ── */
header{
  position:sticky;top:0;z-index:100;
  background:rgba(5,8,16,.92);backdrop-filter:blur(20px);
  border-bottom:1px solid var(--border);
  display:flex;align-items:center;gap:20px;padding:14px 32px;
}
header .logo{font-family:var(--font-mono);font-size:1.2rem;font-weight:700;
  background:linear-gradient(135deg,var(--accent),var(--accent2));
  -webkit-background-clip:text;-webkit-text-fill-color:transparent;}
header .subtitle{color:var(--muted);font-size:.75rem;letter-spacing:.06em;text-transform:uppercase;}
.pill{background:rgba(0,212,255,.12);border:1px solid rgba(0,212,255,.3);
  color:var(--accent);padding:3px 10px;border-radius:20px;font-size:.7rem;
  font-family:var(--font-mono);letter-spacing:.08em;}
.pill.green{background:rgba(0,255,157,.1);border-color:rgba(0,255,157,.3);color:var(--accent2);}
.pill.warn{background:rgba(255,183,0,.1);border-color:rgba(255,183,0,.3);color:var(--warn);}
.pill.red{background:rgba(255,71,87,.1);border-color:rgba(255,71,87,.3);color:var(--danger);}
header .right{margin-left:auto;display:flex;align-items:center;gap:12px;}
.pulse{width:8px;height:8px;border-radius:50%;background:var(--accent2);
  animation:pulse 2s infinite;}
@keyframes pulse{0%,100%{opacity:1;box-shadow:0 0 0 0 rgba(0,255,157,.4);}
  50%{opacity:.6;box-shadow:0 0 0 6px transparent;}}
.ts{font-size:.72rem;color:var(--muted);font-family:var(--font-mono);}

/* ── Run button ── */
.run-btn{
  background:linear-gradient(135deg,var(--accent),#0090ff);
  border:none;color:#000;font-family:var(--font-mono);font-weight:700;
  font-size:.75rem;letter-spacing:.1em;padding:8px 20px;
  border-radius:6px;cursor:pointer;transition:all .2s;
  box-shadow:var(--glow-blue);}
.run-btn:hover{transform:translateY(-1px);box-shadow:0 0 30px rgba(0,212,255,.4);}
.run-btn:active{transform:translateY(0);}
.run-btn:disabled{opacity:.5;cursor:not-allowed;transform:none;}

/* ── KPI grid ── */
.kpi-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(180px,1fr));
  gap:12px;padding:20px 32px 0;}
.kpi{
  background:var(--card);border:1px solid var(--border);border-radius:12px;
  padding:18px 20px;position:relative;overflow:hidden;
  transition:border-color .25s,box-shadow .25s;cursor:default;
}
.kpi::before{content:'';position:absolute;inset:0;opacity:0;
  background:linear-gradient(135deg,rgba(0,212,255,.06),transparent);
  transition:opacity .3s;}
.kpi:hover{border-color:var(--border2);box-shadow:var(--glow-blue);}
.kpi:hover::before{opacity:1;}
.kpi .label{font-size:.68rem;color:var(--muted);letter-spacing:.08em;text-transform:uppercase;margin-bottom:8px;}
.kpi .val{font-family:var(--font-mono);font-size:1.9rem;font-weight:700;line-height:1;}
.kpi .sub{font-size:.68rem;color:var(--muted);margin-top:5px;}
.kpi .bar{height:2px;background:var(--faint);border-radius:2px;margin-top:10px;overflow:hidden;}
.kpi .bar-fill{height:100%;border-radius:2px;transition:width .6s ease;}
.c-blue{color:var(--accent);}
.c-green{color:var(--accent2);}
.c-warn{color:var(--warn);}
.c-red{color:var(--danger);}

/* ── Section headers ── */
.section{padding:24px 32px 0;}
.section-title{font-family:var(--font-mono);font-size:.72rem;color:var(--muted);
  letter-spacing:.12em;text-transform:uppercase;
  display:flex;align-items:center;gap:10px;margin-bottom:16px;}
.section-title::after{content:'';flex:1;height:1px;background:var(--border);}

/* ── Chart grid ── */
.chart-grid{display:grid;gap:16px;padding:0 32px;}
.chart-grid.two{grid-template-columns:1fr 1fr;}
.chart-grid.three{grid-template-columns:2fr 1fr;}
.chart-grid.one{grid-template-columns:1fr;}
@media(max-width:900px){.chart-grid.two,.chart-grid.three{grid-template-columns:1fr;}}

.chart-card{
  background:var(--card);border:1px solid var(--border);border-radius:14px;
  padding:20px;overflow:hidden;position:relative;
  transition:border-color .25s;
}
.chart-card:hover{border-color:var(--border2);}
.chart-card h3{font-family:var(--font-mono);font-size:.7rem;color:var(--muted);
  letter-spacing:.1em;text-transform:uppercase;margin-bottom:14px;
  display:flex;align-items:center;gap:8px;}
.chart-card h3 .num{background:var(--faint);color:var(--accent);
  padding:1px 7px;border-radius:4px;font-size:.65rem;}
.plotly-chart{width:100%;}

/* ── Table ── */
.tbl-wrap{background:var(--card);border:1px solid var(--border);border-radius:14px;
  overflow:hidden;margin:0 32px 32px;}
.tbl-head{padding:16px 20px;border-bottom:1px solid var(--border);
  font-family:var(--font-mono);font-size:.7rem;color:var(--muted);
  letter-spacing:.08em;text-transform:uppercase;}
table{width:100%;border-collapse:collapse;}
th{background:var(--card2);padding:10px 16px;text-align:left;
   font-size:.68rem;color:var(--muted);letter-spacing:.06em;text-transform:uppercase;
   font-family:var(--font-mono);}
td{padding:10px 16px;font-size:.82rem;border-top:1px solid var(--border);}
tr:hover td{background:var(--card2);}
.badge{display:inline-block;padding:2px 8px;border-radius:4px;font-size:.65rem;
  font-family:var(--font-mono);}
.badge.b{background:rgba(0,255,157,.1);color:var(--accent2);}
.badge.m{background:rgba(255,71,87,.1);color:var(--danger);}
.badge.o{background:rgba(255,183,0,.1);color:var(--warn);}

/* ── Alert bar ── */
.alert{
  margin:0 32px 16px;padding:12px 20px;border-radius:8px;font-size:.8rem;
  display:none;
}
.alert.info{background:rgba(0,212,255,.08);border:1px solid rgba(0,212,255,.2);color:var(--accent);}
.alert.success{background:rgba(0,255,157,.08);border:1px solid rgba(0,255,157,.2);color:var(--accent2);}
.alert.running{background:rgba(255,183,0,.08);border:1px solid rgba(255,183,0,.2);color:var(--warn);display:block;}

/* ── Footer ── */
footer{text-align:center;padding:24px;color:var(--muted);font-size:.7rem;
  border-top:1px solid var(--border);font-family:var(--font-mono);letter-spacing:.05em;}
</style>
</head>
<body>

<!-- ── HEADER ── -->
<header>
  <div>
    <div class="logo">⚡ DICI</div>
    <div class="subtitle">Dynamic IDS with CTI Integrated · IEEE TMLCN 2025</div>
  </div>
  <span class="pill green">ML-IDS</span>
  <span class="pill">KMeans++</span>
  <span class="pill warn">Online Learning</span>
  <div class="right">
    <div class="pulse"></div>
    <span class="ts" id="ts">Loading…</span>
    <button class="run-btn" id="runBtn" onclick="runPipeline()">▶ RUN PIPELINE</button>
  </div>
</header>

<!-- ── ALERT ── -->
<div class="alert running" id="alertBar" style="display:none">
  ⚡ Pipeline running… Charts will update automatically when complete.
</div>

<!-- ── KPI CARDS ── -->
<div class="kpi-grid">
  <div class="kpi">
    <div class="label">IDS + CTI · F1 Score</div>
    <div class="val c-green" id="kpi_f1_cti">—</div>
    <div class="sub">Paper target: 89.52%</div>
    <div class="bar"><div class="bar-fill" id="bar_f1_cti" style="width:0%;background:var(--accent2)"></div></div>
  </div>
  <div class="kpi">
    <div class="label">Baseline · No CTI</div>
    <div class="val c-blue" id="kpi_f1_base">—</div>
    <div class="sub">Static offline model</div>
    <div class="bar"><div class="bar-fill" id="bar_f1_base" style="width:0%;background:var(--accent)"></div></div>
  </div>
  <div class="kpi">
    <div class="label">CTI F1 Improvement</div>
    <div class="val c-warn" id="kpi_imp">—</div>
    <div class="sub">Paper: +9.29%</div>
    <div class="bar"><div class="bar-fill" id="bar_imp" style="width:0%;background:var(--warn)"></div></div>
  </div>
  <div class="kpi">
    <div class="label">KMeans++ vs Rule</div>
    <div class="val c-green" id="kpi_km_imp">—</div>
    <div class="sub">Paper: +30.92%</div>
    <div class="bar"><div class="bar-fill" id="bar_km" style="width:0%;background:var(--accent2)"></div></div>
  </div>
  <div class="kpi">
    <div class="label">SVM False Positive Rate</div>
    <div class="val c-blue" id="kpi_svm_fpr">—</div>
    <div class="sub">Paper: 7.70%</div>
    <div class="bar"><div class="bar-fill" id="bar_svm_fpr" style="width:0%;background:var(--accent)"></div></div>
  </div>
  <div class="kpi">
    <div class="label">KMeans False Positive</div>
    <div class="val c-warn" id="kpi_km_fpr">—</div>
    <div class="sub">Paper: 42.78%</div>
    <div class="bar"><div class="bar-fill" id="bar_km_fpr" style="width:0%;background:var(--warn)"></div></div>
  </div>
</div>

<!-- ── SECTION 1: F1 OVER ITERATIONS ── -->
<div class="section">
  <div class="section-title"><span class="num">Fig 6</span>F1 Score – Online Learning Iterations</div>
</div>
<div class="chart-grid one" style="padding:0 32px;">
  <div class="chart-card">
    <h3><span class="num">EXP 1</span>IDS with CTI vs IDS without CTI  <span style="margin-left:auto;font-size:.65rem;color:var(--muted)">Hover · Zoom · Pan</span></h3>
    <div id="chart_f1_iter" class="plotly-chart" style="height:340px"></div>
  </div>
</div>

<!-- ── SECTION 2: CTI vs IoC + Sighting Types ── -->
<div class="section" style="margin-top:20px;">
  <div class="section-title"><span class="num">Fig 8/12</span>CTI Transfer Model vs IoC Database · Sighting Type Impact</div>
</div>
<div class="chart-grid two" style="padding:0 32px;">
  <div class="chart-card">
    <h3><span class="num">EXP 2</span>Performance Metrics Comparison</h3>
    <div id="chart_exp2" class="plotly-chart" style="height:320px"></div>
  </div>
  <div class="chart-card">
    <h3><span class="num">EXP 4</span>F1 Score by Sighting Type</h3>
    <div id="chart_sighting" class="plotly-chart" style="height:320px"></div>
  </div>
</div>

<!-- ── SECTION 3: ML vs Rule + Feature Count ── -->
<div class="section" style="margin-top:20px;">
  <div class="section-title"><span class="num">Fig 13</span>KMeans++ vs Rule-based CTI Processing</div>
</div>
<div class="chart-grid two" style="padding:0 32px;">
  <div class="chart-card">
    <h3><span class="num">EXP 3</span>F1 Score vs Number of CTI Features</h3>
    <div id="chart_feat" class="plotly-chart" style="height:320px"></div>
  </div>
  <div class="chart-card">
    <h3><span class="num">EXP 3</span>KMeans++ vs Rule-based Metrics</h3>
    <div id="chart_km_rb" class="plotly-chart" style="height:320px"></div>
  </div>
</div>

<!-- ── SECTION 4: Batch size + Traffic ── -->
<div class="section" style="margin-top:20px;">
  <div class="section-title"><span class="num">Fig 14/15</span>Batch Size Optimisation · Traffic Distribution</div>
</div>
<div class="chart-grid three" style="padding:0 32px;">
  <div class="chart-card">
    <h3><span class="num">EXP 5</span>F1 Score vs Batch Size per Epoch  <span style="margin-left:auto;font-size:.65rem;color:var(--muted)">Click legend to toggle</span></h3>
    <div id="chart_batch" class="plotly-chart" style="height:340px"></div>
  </div>
  <div class="chart-card">
    <h3><span class="num">LIVE</span>Traffic Classification</h3>
    <div id="chart_traffic" class="plotly-chart" style="height:340px"></div>
  </div>
</div>

<!-- ── SECTION 5: Resource comparison ── -->
<div class="section" style="margin-top:20px;">
  <div class="section-title"><span class="num">Fig 7</span>ML-IDS vs DL-IDS Resource Utilisation</div>
</div>
<div class="chart-grid one" style="padding:0 32px;margin-bottom:24px;">
  <div class="chart-card">
    <h3><span class="num">PAPER</span>Resource Efficiency – ML-IDS vs DL-IDS  (values from paper Section VI-B)</h3>
    <div id="chart_resource" class="plotly-chart" style="height:300px"></div>
  </div>
</div>

<!-- ── RESULTS TABLE ── -->
<div class="section" style="margin-top:4px;">
  <div class="section-title">Detailed Results Table</div>
</div>
<div class="tbl-wrap">
  <div class="tbl-head">Experiment Summary</div>
  <table>
    <thead><tr>
      <th>Experiment</th><th>Configuration</th>
      <th>F1 Score</th><th>Precision</th><th>Recall</th><th>vs Paper</th>
    </tr></thead>
    <tbody id="tbl_body">
      <tr><td colspan="6" style="text-align:center;color:var(--muted);padding:24px;">
        No results yet — click <strong>▶ RUN PIPELINE</strong> or check the dashboard refreshes automatically.
      </td></tr>
    </tbody>
  </table>
</div>

<footer>DICI · Evolving ML-Based Intrusion Detection with Cyber Threat Intelligence · IEEE TMLCN 2025</footer>

<!-- ══════════════════════════════════════════════════════════════════ -->
<script>
/* ── Plotly theme ── */
const BG   = '#111827';
const CARD = '#161f30';
const GRID = '#1e2d45';
const TEXT = '#607080';
const T    = '#e8f0fe';
const BLUE = '#00d4ff';
const GRN  = '#00ff9d';
const YLW  = '#ffb700';
const RED  = '#ff4757';
const PRP  = '#a78bfa';
const ORG  = '#fb923c';

const BASE_LAYOUT = {
  paper_bgcolor: BG, plot_bgcolor: BG,
  font: {family:"'Space Mono', monospace", color: TEXT, size: 11},
  margin: {t:20, r:20, b:40, l:50},
  legend: {bgcolor:'rgba(0,0,0,0)', font:{color:T}, orientation:'h', y:1.08},
  xaxis: {gridcolor: GRID, color: TEXT, zerolinecolor: GRID, tickfont:{color:T}},
  yaxis: {gridcolor: GRID, color: TEXT, zerolinecolor: GRID, tickfont:{color:T}},
  hoverlabel: {bgcolor: '#1e2d45', font:{color:T, size:12}, bordercolor: GRID},
  transition: {duration: 500, easing: 'cubic-in-out'},
};
const PLOTLY_CONFIG = {responsive:true, displayModeBar:true,
  modeBarButtonsToRemove:['lasso2d','select2d'],
  toImageButtonOptions:{format:'png',filename:'dici_chart',scale:2}};

function layout(overrides={}) {
  return {...BASE_LAYOUT, ...overrides,
    xaxis: {...BASE_LAYOUT.xaxis, ...(overrides.xaxis||{})},
    yaxis: {...BASE_LAYOUT.yaxis, ...(overrides.yaxis||{})},
  };
}

/* ── Initialise empty charts ── */
Plotly.newPlot('chart_f1_iter', [], layout({
  yaxis:{...BASE_LAYOUT.yaxis, title:'F1 Score (%)', range:[60,100]},
  xaxis:{...BASE_LAYOUT.xaxis, title:'Iteration'},
}), PLOTLY_CONFIG);

Plotly.newPlot('chart_exp2', [], layout({
  barmode:'group',
  yaxis:{...BASE_LAYOUT.yaxis, title:'Performance (%)'},
  xaxis:{...BASE_LAYOUT.xaxis},
}), PLOTLY_CONFIG);

Plotly.newPlot('chart_sighting', [], layout({
  yaxis:{...BASE_LAYOUT.yaxis, title:'F1 Score (%)'},
  xaxis:{...BASE_LAYOUT.xaxis},
}), PLOTLY_CONFIG);

Plotly.newPlot('chart_feat', [], layout({
  yaxis:{...BASE_LAYOUT.yaxis, title:'F1 Score (%)'},
  xaxis:{...BASE_LAYOUT.xaxis, title:'Number of Features'},
}), PLOTLY_CONFIG);

Plotly.newPlot('chart_km_rb', [], layout({
  barmode:'group',
  yaxis:{...BASE_LAYOUT.yaxis, title:'Score (%)'},
}), PLOTLY_CONFIG);

Plotly.newPlot('chart_batch', [], layout({
  yaxis:{...BASE_LAYOUT.yaxis, title:'F1 Score (%)', range:[40,100]},
  xaxis:{...BASE_LAYOUT.xaxis, title:'Batch Size'},
}), PLOTLY_CONFIG);

Plotly.newPlot('chart_traffic', [], layout({paper_bgcolor:BG, plot_bgcolor:BG,
  margin:{t:20,r:20,b:20,l:20}}), PLOTLY_CONFIG);

/* Resource comparison - static paper values */
const res_cats = ['Training Time (s)','Memory (MB)','CPU Usage (%)'];
const res_ml   = [3.22, 17.43, 36.6];
const res_dl   = [59.30, 65.14, 79.5];
Plotly.newPlot('chart_resource', [
  {type:'bar', name:'ML-IDS', x:res_cats, y:res_ml,
   marker:{color:BLUE, opacity:.85}, text:res_ml.map(v=>v+''), textposition:'outside',
   hovertemplate:'<b>ML-IDS</b><br>%{x}: %{y}<extra></extra>'},
  {type:'bar', name:'DL-IDS', x:res_cats, y:res_dl,
   marker:{color:RED, opacity:.85}, text:res_dl.map(v=>v+''), textposition:'outside',
   hovertemplate:'<b>DL-IDS</b><br>%{x}: %{y}<extra></extra>'},
], layout({barmode:'group', yaxis:{...BASE_LAYOUT.yaxis, title:'Value'}}), PLOTLY_CONFIG);

/* ── Helpers ── */
function fmt(v) { return v!=null ? (+v).toFixed(2)+'%' : '—'; }
function fmtNum(v) { return v!=null ? (+v).toFixed(2) : '—'; }

function setKPI(id, val, barId, max) {
  const el = document.getElementById(id);
  if (el) el.textContent = val;
  const bar = document.getElementById(barId);
  if (bar && max) bar.style.width = Math.min(100, Math.abs(parseFloat(val)||0) / max * 100) + '%';
}

/* ── Main update function ── */
async function fetchAndUpdate() {
  try {
    const r = await fetch('/api/state');
    const d = await r.json();
    document.getElementById('ts').textContent = 'Updated: ' + (d.last_updated || '—');

    const res = d.results || {};
    if (!Object.keys(res).length) return;

    // ── KPIs ──
    const e1 = res.exp1 || {};
    const e3 = res.exp3 || {};
    const baseline = e1.no_cti_f1 ? e1.no_cti_f1[0] : null;
    const withCTI  = e1.final_with || null;
    const imp = e1.improvement || 0;
    setKPI('kpi_f1_cti',  fmt(withCTI),  'bar_f1_cti',  100);
    setKPI('kpi_f1_base', fmt(baseline), 'bar_f1_base', 100);
    setKPI('kpi_imp',    (imp>=0?'+':'')+fmtNum(imp)+'%', 'bar_imp', 20);
    const km_m = e3.kmeanspp || {}; const rb_m = e3.rule_based || {};
    const km_imp = (km_m.f1||0) - (rb_m.f1||0);
    setKPI('kpi_km_imp', (km_imp>=0?'+':'')+fmtNum(km_imp)+'%', 'bar_km', 50);
    // SVM / KMeans FPR (from exp2 standalone IDS metrics)
    const sa = (res.exp2||{}).Standalone_IDS || {};
    setKPI('kpi_svm_fpr', fmt(sa.svm_fpr||null), 'bar_svm_fpr', 20);
    setKPI('kpi_km_fpr',  fmt(sa.kmeans_fpr||null), 'bar_km_fpr', 60);

    // ── Chart 1: F1 over iterations ──
    if (e1.with_cti_f1 && e1.no_cti_f1) {
      const iters = e1.iterations || [...Array(e1.with_cti_f1.length).keys()];
      Plotly.react('chart_f1_iter', [
        {type:'scatter', mode:'lines+markers', name:'ML-IDS + CTI',
         x:iters, y:e1.with_cti_f1,
         line:{color:GRN, width:2.5}, marker:{size:6, color:GRN},
         hovertemplate:'Iteration %{x}<br>F1: <b>%{y:.2f}%</b><extra>IDS+CTI</extra>',
         fill:'tozeroy', fillcolor:'rgba(0,255,157,.04)'},
        {type:'scatter', mode:'lines+markers', name:'ML-IDS (no CTI)',
         x:iters.slice(0, e1.no_cti_f1.length), y:e1.no_cti_f1.slice(0, iters.length),
         line:{color:RED, width:2, dash:'dot'}, marker:{size:6, color:RED, symbol:'x'},
         hovertemplate:'Iteration %{x}<br>F1: <b>%{y:.2f}%</b><extra>No CTI</extra>'},
        {type:'scatter', mode:'lines', name:'Paper target (89.52%)',
         x:[0, iters.length-1], y:[89.52, 89.52],
         line:{color:YLW, width:1, dash:'dashdot'}, showlegend:true,
         hovertemplate:'Paper: 89.52%<extra></extra>'},
      ], layout({
        yaxis:{...BASE_LAYOUT.yaxis, title:'F1 Score (%)', range:[60,100]},
        xaxis:{...BASE_LAYOUT.xaxis, title:'Iteration'},
        annotations:[{
          x: iters[iters.length-1], y: e1.with_cti_f1[e1.with_cti_f1.length-1]+1,
          text: `<b>+${imp.toFixed(2)}%</b>`, showarrow:false,
          font:{color:GRN, size:12, family:"'Space Mono',monospace"},
        }]
      }), PLOTLY_CONFIG);
    }

    // ── Chart 2: Exp 2 bar ──
    const e2 = res.exp2 || {};
    const exp2keys = ['IDS_CTI_Transfer','IDS_IoC_Database','Standalone_IDS','IoC_DB_only'];
    const exp2lab  = ['IDS+CTI<br>Transfer','IDS+IoC<br>Database','Standalone<br>IDS','IoC DB<br>Only'];
    if (Object.keys(e2).length) {
      Plotly.react('chart_exp2', [
        {type:'bar', name:'F1 Score',  x:exp2lab,
         y:exp2keys.map(k=>(e2[k]||{}).f1||0),
         marker:{color:BLUE,opacity:.85},
         text:exp2keys.map(k=>fmt((e2[k]||{}).f1)), textposition:'outside',
         hovertemplate:'%{x}<br>F1: <b>%{y:.2f}%</b><extra></extra>'},
        {type:'bar', name:'Precision', x:exp2lab,
         y:exp2keys.map(k=>(e2[k]||{}).precision||0),
         marker:{color:GRN,opacity:.85},
         hovertemplate:'%{x}<br>Prec: <b>%{y:.2f}%</b><extra></extra>'},
        {type:'bar', name:'Recall',    x:exp2lab,
         y:exp2keys.map(k=>(e2[k]||{}).recall||0),
         marker:{color:YLW,opacity:.85},
         hovertemplate:'%{x}<br>Recall: <b>%{y:.2f}%</b><extra></extra>'},
      ], layout({barmode:'group',
        yaxis:{...BASE_LAYOUT.yaxis, title:'Performance (%)', range:[0,110]},
      }), PLOTLY_CONFIG);
    }

    // ── Chart 3: Sighting types ──
    const e4 = res.exp4 || {};
    if (Object.keys(e4).length) {
      const st  = Object.keys(e4).sort((a,b)=>e4[a]-e4[b]);
      const sf1 = st.map(k=>e4[k]);
      const sc  = sf1.map(v => v===Math.max(...sf1) ? GRN : BLUE);
      Plotly.react('chart_sighting', [
        {type:'bar', orientation:'h', name:'F1 Score',
         y:st, x:sf1, marker:{color:sc, opacity:.85},
         text:sf1.map(v=>v.toFixed(2)+'%'), textposition:'outside',
         hovertemplate:'<b>%{y}</b><br>F1: %{x:.2f}%<extra></extra>'},
      ], layout({
        xaxis:{...BASE_LAYOUT.xaxis, title:'F1 Score (%)', range:[0,105]},
        yaxis:{...BASE_LAYOUT.yaxis, automargin:true},
        margin:{...BASE_LAYOUT.margin, l:130},
        annotations:[{
          x:sf1[sf1.length-1]+1, y:st[st.length-1],
          text:'⭐ Best', showarrow:false, font:{color:GRN, size:10}
        }]
      }), PLOTLY_CONFIG);
    }

    // ── Chart 4: Feature count ──
    const fc_raw = (e3.feature_count_f1) || {};
    const fc_keys = Object.keys(fc_raw).map(Number).sort((a,b)=>a-b);
    if (fc_keys.length) {
      const fc_vals = fc_keys.map(k=>fc_raw[k]);
      const rb_f1   = rb_m.f1 || 0;
      Plotly.react('chart_feat', [
        {type:'scatter', mode:'lines+markers', name:'KMeans++',
         x:fc_keys, y:fc_vals,
         line:{color:BLUE, width:2.5}, marker:{size:7,color:BLUE},
         fill:'tozeroy', fillcolor:'rgba(0,212,255,.05)',
         hovertemplate:'%{x} features<br>F1: <b>%{y:.2f}%</b><extra>KMeans++</extra>'},
        {type:'scatter', mode:'lines', name:`Rule-based (${rb_f1.toFixed(1)}%)`,
         x:[Math.min(...fc_keys), Math.max(...fc_keys)], y:[rb_f1, rb_f1],
         line:{color:RED, width:1.5, dash:'dash'},
         hovertemplate:`Rule-based F1: ${rb_f1.toFixed(1)}%<extra></extra>`},
        {type:'scatter', mode:'lines', name:'Optimal zone',
         x:[40, 60, 60, 40, 40], y:[0, 0, 100, 100, 0],
         fill:'toself', fillcolor:'rgba(0,255,157,.04)',
         line:{color:'rgba(0,255,157,.2)', width:1}, showlegend:true,
         hoverinfo:'skip'},
      ], layout({
        yaxis:{...BASE_LAYOUT.yaxis, title:'F1 Score (%)'},
        xaxis:{...BASE_LAYOUT.xaxis, title:'Number of Features'},
        annotations:[{
          x:50, y:(fc_vals.length ? Math.max(...fc_vals)-2 : 95),
          text:'Optimal<br>zone', showarrow:false,
          font:{color:'rgba(0,255,157,.6)', size:10}
        }]
      }), PLOTLY_CONFIG);
    }

    // ── Chart 5: KMeans++ vs Rule-based bar ──
    if (km_m.f1 || rb_m.f1) {
      const cats = ['F1 Score','Precision','Recall','Accuracy'];
      Plotly.react('chart_km_rb', [
        {type:'bar', name:'KMeans++', x:cats,
         y:[km_m.f1||0, km_m.precision||0, km_m.recall||0, km_m.accuracy||0],
         marker:{color:GRN, opacity:.85},
         text:cats.map((_,i)=>[[km_m.f1,km_m.precision,km_m.recall,km_m.accuracy][i]||0].map(v=>v.toFixed(1)+'%')[0]),
         textposition:'outside',
         hovertemplate:'KMeans++<br>%{x}: <b>%{y:.2f}%</b><extra></extra>'},
        {type:'bar', name:'Rule-based', x:cats,
         y:[rb_m.f1||0, rb_m.precision||0, rb_m.recall||0, rb_m.accuracy||0],
         marker:{color:RED, opacity:.85},
         hovertemplate:'Rule-based<br>%{x}: <b>%{y:.2f}%</b><extra></extra>'},
      ], layout({barmode:'group',
        yaxis:{...BASE_LAYOUT.yaxis, title:'Score (%)', range:[0,110]},
        annotations:[{
          x:0, y:Math.max(km_m.f1||0,rb_m.f1||0)+6,
          text:`<b>+${km_imp.toFixed(1)}% F1</b>`,
          showarrow:false, font:{color:GRN, size:11}
        }]
      }), PLOTLY_CONFIG);
    }

    // ── Chart 6: Batch size ──
    const e5 = res.exp5 || {};
    if (Object.keys(e5).length) {
      const epochs     = [...new Set(Object.keys(e5).map(k=>+k.split('_')[1]))].sort((a,b)=>a-b);
      const batches    = [...new Set(Object.keys(e5).map(k=>+k.split('_')[0]))].sort((a,b)=>a-b);
      const colors     = ['#1e4d8c','#1e6bb8','#1e85d4','#00b4e6','#00d4ff'].slice(0, epochs.length);
      const batchTraces = epochs.map((ep,i) => ({
        type:'scatter', mode:'lines+markers', name:`Epoch ${ep}`,
        x:batches, y:batches.map(bs => (e5[`${bs}_${ep}`]||{}).f1||0),
        line:{color:colors[i]||BLUE, width:2},
        marker:{size:6, color:colors[i]||BLUE},
        hovertemplate:`Epoch ${ep}<br>Batch %{x}<br>F1: <b>%{y:.2f}%</b><extra></extra>`,
      }));
      batchTraces.push({
        type:'scatter', mode:'lines', name:'Optimal (224)',
        x:[224,224], y:[40,100],
        line:{color:YLW, width:1.5, dash:'dash'},
        hovertemplate:'Optimal batch size: 224<extra></extra>'
      });
      Plotly.react('chart_batch', batchTraces, layout({
        yaxis:{...BASE_LAYOUT.yaxis, title:'F1 Score (%)', range:[40,100]},
        xaxis:{...BASE_LAYOUT.xaxis, title:'Batch Size'},
        legend:{...BASE_LAYOUT.legend, orientation:'h'},
      }), PLOTLY_CONFIG);
    }

    // ── Chart 7: Traffic donut ──
    const ts_ = d.traffic_stream || {};
    Plotly.react('chart_traffic', [{
      type:'pie', hole:.55,
      labels:['Benign','Malicious','Outlier'],
      values:[ts_.benign||70, ts_.malicious||20, ts_.outlier||10],
      marker:{colors:[GRN, RED, YLW],
              line:{color:BG, width:2}},
      textinfo:'label+percent',
      textfont:{color:T, size:11},
      hovertemplate:'<b>%{label}</b><br>Count: %{value}<br>%{percent}<extra></extra>',
      rotation:180,
    }], layout({
      paper_bgcolor:BG, plot_bgcolor:BG,
      margin:{t:20,r:20,b:20,l:20},
      annotations:[{
        x:.5, y:.5, text:`<b>${(ts_.total||100)}</b><br><span style="font-size:10px">flows</span>`,
        showarrow:false, font:{color:T, size:16},
      }]
    }), PLOTLY_CONFIG);

    // ── Results table ──
    buildTable(res);

  } catch(e) {
    console.error('Fetch error:', e);
  }
}

function buildTable(res) {
  const e1 = res.exp1||{}, e2 = res.exp2||{}, e3 = res.exp3||{};
  const rows = [];
  const add  = (exp,cfg,f1,pr,rc,note,cls='') =>
    rows.push(`<tr>
      <td style="color:var(--muted)">${exp}</td>
      <td><b>${cfg}</b></td>
      <td style="color:var(--accent2)">${f1}</td>
      <td>${pr}</td><td>${rc}</td>
      <td><span class="badge ${cls}">${note}</span></td>
    </tr>`);

  if(e1.final_with) {
    add('Exp1','IDS + CTI Transfer', fmt(e1.final_with), '—','—', `+${(e1.improvement||0).toFixed(2)}% vs paper`, 'b');
    add('Exp1','IDS without CTI',    fmt(e1.final_no||e1.no_cti_f1?.[0]), '—','—', 'baseline', 'o');
  }
  for(const [k,lb,cls] of [
    ['IDS_CTI_Transfer','IDS+CTI Transfer','b'],
    ['IDS_IoC_Database','IDS+IoC Database','o'],
    ['Standalone_IDS',  'Standalone IDS', 'm'],
  ]) {
    const m = e2[k]||{};
    if(m.f1) add('Exp2', lb, fmt(m.f1), fmt(m.precision), fmt(m.recall), cls==='b'?'✓ best':'', cls);
  }
  const km=e3.kmeanspp||{}, rb=e3.rule_based||{};
  if(km.f1) add('Exp3','KMeans++',   fmt(km.f1),fmt(km.precision),fmt(km.recall),`+${((km.f1||0)-(rb.f1||0)).toFixed(2)}%`,'b');
  if(rb.f1) add('Exp3','Rule-based', fmt(rb.f1),fmt(rb.precision),fmt(rb.recall),'baseline','o');

  const tb = document.getElementById('tbl_body');
  tb.innerHTML = rows.length ? rows.join('') :
    '<tr><td colspan="6" style="text-align:center;color:var(--muted);padding:24px;">Run pipeline to see results</td></tr>';
}

/* ── Run pipeline ── */
async function runPipeline() {
  const btn = document.getElementById('runBtn');
  const alr = document.getElementById('alertBar');
  btn.disabled = true; btn.textContent = '⚡ Running…';
  alr.style.display = 'block';
  try {
    const r = await fetch('/api/run_pipeline', {method:'POST'});
    const d = await r.json();
    if(d.status === 'started') {
      pollUntilDone();
    } else {
      btn.disabled = false; btn.textContent = '▶ RUN PIPELINE';
      alr.style.display = 'none';
    }
  } catch(e) {
    btn.disabled=false; btn.textContent='▶ RUN PIPELINE'; alr.style.display='none';
    console.error(e);
  }
}

function pollUntilDone() {
  const btn = document.getElementById('runBtn');
  const alr = document.getElementById('alertBar');
  let dots = 0;
  const iv = setInterval(async () => {
    dots = (dots+1)%4;
    btn.textContent = '⚡ Running' + '.'.repeat(dots+1);
    try {
      const r = await fetch('/api/pipeline_status');
      const d = await r.json();
      if(!d.running) {
        clearInterval(iv);
        btn.disabled=false; btn.textContent='▶ RUN PIPELINE';
        alr.style.display='none';
        await fetchAndUpdate();
      }
    } catch(e) { clearInterval(iv); btn.disabled=false; btn.textContent='▶ RUN PIPELINE'; }
  }, 2000);
}

/* ── Simulate live traffic ── */
async function simTraffic() {
  await fetch('/api/simulate_traffic', {method:'POST', headers:{'Content-Type':'application/json'},
    body: JSON.stringify({n: Math.floor(Math.random()*200+100)})});
}

/* ── Auto refresh ── */
fetchAndUpdate();
setInterval(fetchAndUpdate, {{ INTERVAL }});
setInterval(simTraffic, 4000);
</script>
</body>
</html>"""