"""
  src/dashboard.py  
  Module 8 — Visualization Dashboard
  NEW: AI Report button calls Claude API to auto-generate
       a professional security incident report.
"""

import os
import threading
from datetime import datetime
from flask import Flask, jsonify, render_template_string # type: ignore


DASHBOARD_HTML = """
<!DOCTYPE html>
<html lang="en">

<head>
  <meta charset="UTF-8"/>
  <meta name="viewport" content="width=device-width, initial-scale=1.0"/>
  <title>Hybrid AI-Enhanced NIDS Dashboard</title>
  <script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.0/dist/chart.umd.min.js"></script>
  <style>
    * { box-sizing:border-box; margin:0; padding:0; }
    body { font-family:'Segoe UI',sans-serif; background:#0d1117; color:#c9d1d9; }

    header { background:linear-gradient(90deg,#161b22,#1f2937);
      padding:16px 24px; border-bottom:2px solid #21d4fd;
      display:flex; align-items:center; gap:12px; }
    header h1 { font-size:1.3rem; color:#21d4fd; flex:1; }
    header span { font-size:0.8rem; color:#8b949e; }
    .status-dot { width:10px; height:10px; border-radius:50%;
      background:#3fb950; animation:pulse 1.5s infinite; }
    @keyframes pulse { 0%,100%{opacity:1} 50%{opacity:0.4} }

    .ai-btn { background:linear-gradient(135deg,#6e40c9,#2e75b6);
      color:white; border:none; border-radius:8px; padding:10px 20px;
      font-size:0.9rem; font-weight:600; cursor:pointer;
      display:flex; align-items:center; gap:8px;
      transition:all 0.3s; white-space:nowrap; }
    .ai-btn:hover { transform:translateY(-2px);
      box-shadow:0 4px 15px rgba(110,64,201,0.4); }
    .ai-btn:disabled { opacity:0.6; cursor:not-allowed; transform:none; }
    .spinner { width:16px; height:16px; border:2px solid rgba(255,255,255,0.3);
      border-top-color:white; border-radius:50%;
      animation:spin 0.8s linear infinite; display:none; }
    @keyframes spin { to { transform:rotate(360deg); } }

    .cards { display:flex; gap:16px; padding:20px 24px; flex-wrap:wrap; }
    .card { background:#161b22; border:1px solid #30363d;
      border-radius:10px; padding:16px 24px;
      flex:1; min-width:180px; text-align:center; }
    .card .value { font-size:2rem; font-weight:700; }
    .card .label { font-size:0.8rem; color:#8b949e; margin-top:4px; }
    .total   .value { color:#58a6ff; }
    .critical .value { color:#ff7b72; }
    .ips     .value { color:#d2a8ff; }
    .ml      .value { color:#3fb950; }

    .charts { display:grid; grid-template-columns:1fr 1fr; gap:16px;
      padding:0 24px 24px; }
    .chart-box { background:#161b22; border:1px solid #30363d;
      border-radius:10px; padding:16px; }
    .chart-box h3 { font-size:0.9rem; color:#8b949e;
      margin-bottom:12px; text-transform:uppercase; }
    canvas { max-height:250px; }

    .alerts-table { margin:0 24px 24px; background:#161b22;
      border:1px solid #30363d; border-radius:10px; overflow:hidden; }
    .alerts-table h3 { padding:12px 16px; font-size:0.9rem; color:#8b949e;
      text-transform:uppercase; border-bottom:1px solid #30363d; }
    table { width:100%; border-collapse:collapse; font-size:0.82rem; }
    th { background:#21262d; padding:8px 12px; text-align:left; color:#8b949e; }
    td { padding:7px 12px; border-bottom:1px solid #21262d; }
    tr:last-child td { border-bottom:none; }
    .sev { padding:2px 8px; border-radius:4px; font-weight:600; font-size:0.75rem; }
    .CRITICAL{background:#3d1c1c;color:#ff7b72;}
    .HIGH    {background:#3d2f00;color:#e3b341;}
    .MEDIUM  {background:#001f3d;color:#58a6ff;}
    .LOW     {background:#0f2d0f;color:#3fb950;}
    .badge-rule{background:#0d2640;color:#58a6ff;}
    .badge-ml  {background:#0d2a0d;color:#3fb950;}
    .badge{padding:1px 6px;border-radius:4px;font-size:0.7rem;}

    /* Modal */
    .overlay { display:none; position:fixed; inset:0;
      background:rgba(0,0,0,0.85); z-index:1000;
      align-items:center; justify-content:center; padding:20px; }
    .overlay.active { display:flex; }
    .modal { background:#161b22; border:1px solid #30363d;
      border-radius:16px; width:100%; max-width:820px;
      max-height:88vh; display:flex; flex-direction:column;
      box-shadow:0 20px 60px rgba(0,0,0,0.5); }
    .modal-hdr { padding:20px 24px 16px; border-bottom:1px solid #30363d;
      display:flex; align-items:center; gap:12px; }
    .modal-hdr h2 { font-size:1.1rem; color:#21d4fd; flex:1; }
    .modal-close { background:none; border:none; color:#8b949e;
      font-size:1.4rem; cursor:pointer; padding:4px 8px;
      border-radius:6px; transition:background 0.2s; }
    .modal-close:hover { background:#21262d; color:#c9d1d9; }
    .modal-body { padding:24px; overflow-y:auto; flex:1; }

    .loading { display:flex; flex-direction:column; align-items:center;
      justify-content:center; padding:60px 20px; gap:20px; }
    .loading-ring { width:60px; height:60px; border:4px solid #30363d;
      border-top-color:#6e40c9; border-radius:50%;
      animation:spin 1s linear infinite; }
    .loading p { color:#8b949e; font-size:0.9rem; }

    .report { line-height:1.7; }
    .report h2 { color:#21d4fd; font-size:1.05rem; margin:20px 0 8px;
      padding-bottom:6px; border-bottom:1px solid #30363d; }
    .report h2:first-child { margin-top:0; }
    .report p  { color:#c9d1d9; margin-bottom:10px; font-size:0.92rem; }
    .report ul { padding-left:20px; margin-bottom:10px; }
    .report li { color:#c9d1d9; margin-bottom:4px; font-size:0.92rem; }
    .report strong { color:#e3b341; }
    .report code { background:#21262d; padding:1px 6px;
      border-radius:4px; font-size:0.85rem; color:#79c0ff; }
    .report-meta { font-size:0.78rem; color:#8b949e; margin-bottom:20px;
      padding:10px 14px; background:#0d1117; border-radius:8px;
      border-left:3px solid #6e40c9; }

    .modal-foot { padding:16px 24px; border-top:1px solid #30363d;
      display:flex; gap:12px; justify-content:flex-end; }
    .btn { padding:8px 18px; border-radius:8px; font-size:0.85rem;
      font-weight:600; cursor:pointer; border:none; transition:all 0.2s; }
    .btn-copy  { background:#21262d; color:#c9d1d9; }
    .btn-copy:hover  { background:#30363d; }
    .btn-print { background:#2e75b6; color:white; }
    .btn-print:hover { background:#1B3A6B; }
  </style>
</head>
<body>

<header>
  <div class="status-dot"></div>
  <h1>  Hybrid AI-Enhanced NIDS</h1>
  <span id="last-update">Initialising …</span>
  <button class="ai-btn" onclick="genReport()" id="reportBtn">
    <div class="spinner" id="spin"></div>
    <span id="btnTxt"> Generate AI Report</span>
  </button>
</header>

<div class="cards">
  <div class="card total">
    <div class="value" id="total-alerts">—</div>
    <div class="label">Total Alerts</div>
  </div>
  <div class="card critical">
    <div class="value" id="critical-alerts">—</div>
    <div class="label">Critical Alerts</div>
  </div>
  <div class="card ips">
    <div class="value" id="unique-ips">—</div>
    <div class="label">Unique Attacker IPs</div>
  </div>
  <div class="card ml">
    <div class="value" id="ml-alerts">—</div>
    <div class="label">ML Anomalies Detected</div>
  </div>
</div>

<div class="charts">
  <div class="chart-box"><h3>Alert Timeline (last 60 min)</h3>
    <canvas id="timelineChart"></canvas></div>
  <div class="chart-box"><h3>Attack Distribution</h3>
    <canvas id="pieChart"></canvas></div>
  <div class="chart-box"><h3>Top Attacker IPs</h3>
    <canvas id="attackersChart"></canvas></div>
  <div class="chart-box"><h3>Severity Breakdown</h3>
    <canvas id="severityChart"></canvas></div>
</div>

<div class="alerts-table">
  <h3>Recent Alerts</h3>
  <table>
    <thead><tr>
      <th>#</th><th>Time</th><th>Type</th><th>Source IP</th>
      <th>Dest:Port</th><th>Severity</th><th>Engine</th><th>Detail</th>
    </tr></thead>
    <tbody id="alerts-body"></tbody>
  </table>
</div>

<!-- AI Report Modal -->
<div class="overlay" id="modal">
  <div class="modal">
    <div class="modal-hdr">
      <h2> AI-Generated Security Incident Report</h2>
      <button class="modal-close" onclick="closeModal()">✕</button>
    </div>
    <div class="modal-body" id="modalBody"></div>
    <div class="modal-foot" id="modalFoot" style="display:none">
      <button class="btn btn-copy"  onclick="copyRpt()"> Copy</button>
      <button class="btn btn-print" onclick="printRpt()"> Print / Save PDF</button>
    </div>
  </div>
</div>

<script>
// ── Charts ────────────────────────────────────────────────────────────────────
const PAL = ['#58a6ff','#3fb950','#e3b341','#ff7b72','#d2a8ff','#79c0ff'];

const mkLine = id => new Chart(document.getElementById(id),{
  type:'line', data:{labels:[],datasets:[{label:'Alerts',data:[],
  borderColor:'#58a6ff',backgroundColor:'rgba(88,166,255,0.1)',
  tension:0.3,fill:true,pointRadius:3}]},
  options:{responsive:true,scales:{
    x:{ticks:{color:'#8b949e'},grid:{color:'#21262d'}},
    y:{ticks:{color:'#8b949e'},grid:{color:'#21262d'},beginAtZero:true}
  },plugins:{legend:{labels:{color:'#c9d1d9'}}}}});

const mkPie = id => new Chart(document.getElementById(id),{
  type:'doughnut', data:{labels:[],datasets:[{data:[],backgroundColor:PAL}]},
  options:{responsive:true,plugins:{legend:{labels:{color:'#c9d1d9'}}}}});

const mkBar = (id,lbl,col) => new Chart(document.getElementById(id),{
  type:'bar', data:{labels:[],datasets:[{label:lbl,data:[],
  backgroundColor:col,borderRadius:4}]},
  options:{indexAxis:'y',responsive:true,scales:{
    x:{ticks:{color:'#8b949e'},grid:{color:'#21262d'}},
    y:{ticks:{color:'#8b949e'},grid:{color:'#21262d'}}
  },plugins:{legend:{labels:{color:'#c9d1d9'}}}}});

const tl  = mkLine('timelineChart');
const pie = mkPie('pieChart');
const atk = mkBar('attackersChart','Alerts','#ff7b72');
const sev = mkBar('severityChart','Count','#d2a8ff');

// ── Refresh ───────────────────────────────────────────────────────────────────
async function refresh(){
  try {
    const [st,di,at,tl2,re] = await Promise.all([
      fetch('/api/stats').then(r=>r.json()),
      fetch('/api/distribution').then(r=>r.json()),
      fetch('/api/top_attackers').then(r=>r.json()),
      fetch('/api/timeline').then(r=>r.json()),
      fetch('/api/recent').then(r=>r.json()),
    ]);
    document.getElementById('total-alerts').textContent   = st.total;
    document.getElementById('critical-alerts').textContent= st.critical;
    document.getElementById('unique-ips').textContent     = st.unique_attacker_ips;
    document.getElementById('ml-alerts').textContent      = st.ml_count||0;
    document.getElementById('last-update').textContent    =
      'Last updated: '+new Date().toLocaleTimeString();

    tl.data.labels           = tl2.map(t=>t.minute.slice(11));
    tl.data.datasets[0].data = tl2.map(t=>t.count);   tl.update();
    pie.data.labels          = di.map(d=>d.attack_type);
    pie.data.datasets[0].data= di.map(d=>d.count);    pie.update();
    atk.data.labels          = at.map(a=>a.ip);
    atk.data.datasets[0].data= at.map(a=>a.count);    atk.update();
    const sm={CRITICAL:0,HIGH:0,MEDIUM:0,LOW:0};
    re.forEach(a=>{if(sm[a.severity]!==undefined)sm[a.severity]++;});
    sev.data.labels          = Object.keys(sm);
    sev.data.datasets[0].data= Object.values(sm);     sev.update();

    document.getElementById('alerts-body').innerHTML =
      re.slice(0,50).map(a=>`<tr>
        <td>${a.id}</td><td>${a.timestamp.slice(11,19)}</td>
        <td>${a.attack_type}</td><td>${a.source_ip}</td>
        <td>${a.destination_ip}:${a.port}</td>
        <td><span class="sev ${a.severity}">${a.severity}</span></td>
        <td><span class="badge badge-${a.source.toLowerCase()}">${a.source}</span></td>
        <td style="max-width:200px;overflow:hidden;text-overflow:ellipsis;
          white-space:nowrap" title="${a.detail}">${a.detail}</td>
      </tr>`).join('');
  } catch(e){ console.warn(e); }
}
refresh();
setInterval(refresh,3000);

// ── AI Report ─────────────────────────────────────────────────────────────────
let rptTxt = '';

async function genReport(){
  const btn=document.getElementById('reportBtn');
  const sp =document.getElementById('spin');
  const bt =document.getElementById('btnTxt');
  const mb =document.getElementById('modalBody');
  const mf =document.getElementById('modalFoot');

  document.getElementById('modal').classList.add('active');
  mf.style.display='none';
  mb.innerHTML=`<div class="loading">
    <div class="loading-ring"></div>
    <p> AI is analysing your network security data…</p>
    <p style="font-size:0.8rem;color:#6e40c9;margin-top:-10px">
      Reading alerts → Building threat model → Writing report
    </p></div>`;

  btn.disabled=true; sp.style.display='block'; bt.textContent='Generating…';

  try {
    const r = await fetch('/api/ai_report',{method:'POST'});
    const d = await r.json();
    if(d.error){
      mb.innerHTML=`<div style="color:#ff7b72;padding:20px">
        <h3> ${d.error}</h3></div>`;
    } else {
      rptTxt = d.report;
      mb.innerHTML=`
        <div class="report-meta">
           Generated: ${new Date().toLocaleString()} &nbsp;|&nbsp;
           Powered by Claude AI &nbsp;|&nbsp;
           Based on ${d.alert_count} alerts
        </div>
        <div class="report">${md2html(d.report)}</div>`;
      mf.style.display='flex';
    }
  } catch(e){
    mb.innerHTML=`<div style="color:#ff7b72;padding:20px">
      <h3> Error: ${e.message}</h3></div>`;
  } finally {
    btn.disabled=false; sp.style.display='none';
    bt.textContent=' Generate AI Report';
  }
}

function md2html(md){
  return md
    .replace(/^## (.+)$/gm,'<h2>$1</h2>')
    .replace(/\*\*(.+?)\*\*/g,'<strong>$1</strong>')
    .replace(/`(.+?)`/g,'<code>$1</code>')
    .replace(/^[-*] (.+)$/gm,'<li>$1</li>')
    .replace(/(<li>[\s\S]*?<\/li>)/g,'<ul>$1</ul>')
    .replace(/<\/ul>\s*<ul>/g,'')
    .replace(/\n\n/g,'</p><p>')
    .replace(/^([^<])/gm,'$1') || md;
}

function closeModal(){
  document.getElementById('modal').classList.remove('active');
}
document.getElementById('modal').addEventListener('click',
  e=>{ if(e.target===e.currentTarget) closeModal(); });

async function copyRpt(){
  await navigator.clipboard.writeText(rptTxt);
  const b=document.querySelector('.btn-copy');
  b.textContent=' Copied!';
  setTimeout(()=>b.textContent=' Copy',2000);
}

function printRpt(){
  const w=window.open('','_blank');
  w.document.write(`<html><head><title>NIDS Security Report</title>
    <style>body{font-family:Arial,sans-serif;max-width:800px;margin:40px auto;
    line-height:1.6;}h1{color:#1B3A6B;border-bottom:2px solid #2E75B6;
    padding-bottom:10px;}h2{color:#2E75B6;margin-top:20px;}
    .meta{background:#f5f5f5;padding:10px;border-radius:6px;
    font-size:0.85rem;color:#666;margin-bottom:20px;}</style></head><body>
    <h1> Network Security Incident Report</h1>
    <div class="meta">Generated: ${new Date().toLocaleString()} | Hybrid AI-Enhanced NIDS</div>
    ${md2html(rptTxt)}</body></html>`);
  w.document.close(); w.print();
}
</script>
</body>
</html>
"""


def run_dashboard(alert_list, alert_lock, port=5000):
    from src.logger      import Logger
    from src.ai_reporter import generate_report
    from collections import defaultdict

    db  = Logger()
    app = Flask(__name__, static_folder=None)
    app.config["DEBUG"] = False

    @app.route("/")
    def index():
        return render_template_string(DASHBOARD_HTML)

    @app.route("/api/stats")
    def api_stats():
        # Primary: use in-memory alert_list for instant updates
        with alert_lock:
            alerts = list(alert_list)
        total    = len(alerts)
        critical = sum(1 for a in alerts if a.get("severity") == "CRITICAL")
        ml_count = sum(1 for a in alerts if a.get("source") == "ML")
        unique_ips = len(set(a.get("source_ip","") for a in alerts))
        # Fallback to DB if memory is empty
        if total == 0:
            db_stats = db.get_stats()
            db_stats["ml_count"] = 0
            return jsonify(db_stats)
        return jsonify({
            "total": total,
            "critical": critical,
            "unique_attacker_ips": unique_ips,
            "ml_count": ml_count
        })

    @app.route("/api/distribution")
    def api_distribution():
        # Primary: compute from in-memory alert_list
        with alert_lock:
            alerts = list(alert_list)
        if not alerts:
            return jsonify(db.get_attack_distribution())
        counts = defaultdict(int)
        for a in alerts:
            counts[a.get("attack_type", "Unknown")] += 1
        return jsonify([{"attack_type": k, "count": v}
                        for k, v in sorted(counts.items(),
                                           key=lambda x: -x[1])])

    @app.route("/api/top_attackers")
    def api_top_attackers():
        # Primary: compute from in-memory alert_list
        with alert_lock:
            alerts = list(alert_list)
        if not alerts:
            return jsonify(db.get_top_attackers(10))
        counts = defaultdict(int)
        for a in alerts:
            counts[a.get("source_ip", "Unknown")] += 1
        top = sorted(counts.items(), key=lambda x: -x[1])[:10]
        return jsonify([{"ip": k, "count": v} for k, v in top])

    @app.route("/api/timeline")
    def api_timeline():
        return jsonify(db.get_timeline(hours=1))

    @app.route("/api/recent")
    def api_recent():
        # Primary: serve directly from in-memory for zero-lag updates
        with alert_lock:
            alerts = list(reversed(alert_list))[:100]
        if not alerts:
            return jsonify(db.get_recent_alerts(100))
        # Add id field for table rendering
        result = []
        for i, a in enumerate(alerts):
            result.append({
                "id"            : len(alert_list) - i,
                "timestamp"     : a.get("timestamp", ""),
                "source_ip"     : a.get("source_ip", ""),
                "destination_ip": a.get("destination_ip", ""),
                "protocol"      : a.get("protocol", "TCP"),
                "port"          : a.get("port", 0),
                "attack_type"   : a.get("attack_type", ""),
                "severity"      : a.get("severity", "LOW"),
                "source"        : a.get("source", "RULE"),
                "detail"        : a.get("detail", ""),
            })
        return jsonify(result)

    # ── AI Report Endpoint ────────────────────────────────────────────────────
    @app.route("/api/ai_report", methods=["POST"])
    def api_ai_report():
        try:
            stats = db.get_stats()
            with alert_lock:
                stats["ml_count"] = sum(
                    1 for a in alert_list if a.get("source") == "ML")

            if stats.get("total", 0) == 0:
                return jsonify({
                    "error": "No alerts yet! Run the NIDS for a "
                             "few minutes to collect data first, "
                             "then click Generate AI Report."
                })

            report = generate_report(
                stats         = stats,
                distribution  = db.get_attack_distribution(),
                top_attackers = db.get_top_attackers(10),
                recent        = db.get_recent_alerts(50)
            )
            return jsonify({
                "report"      : report,
                "alert_count" : stats.get("total", 0),
                "generated_at": datetime.now().isoformat()
            })
        except Exception as e:
            return jsonify({"error": str(e)}), 500

    import logging
    logging.getLogger("werkzeug").setLevel(logging.ERROR)
    app.run(host="0.0.0.0", port=port, threaded=True)