"""
  src/dashboard.py
  Module 8 — Visualization Dashboard (Flask backend)
  Serves the real-time monitoring dashboard at port 5000.
  Provides REST API endpoints consumed by Chart.js.
"""
import os
import json
import threading
from datetime import datetime
 
from flask import Flask, jsonify, render_template_string
# ── Dashboard HTML + Chart.js (single-file, no external templates needed) ─────
DASHBOARD_HTML = """
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8"/>
  <meta name="viewport" content="width=device-width, initial-scale=1.0"/>
  <title>Hybrid AI-Enhanced NIDS Dashboard</title>
  <script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.0/dist/chart.umd.min.js"></script>
  <style>
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body { font-family: 'Segoe UI', sans-serif; background: #0d1117; color: #c9d1d9; }
    header {
      background: linear-gradient(90deg, #161b22, #1f2937);
      padding: 16px 24px;
      border-bottom: 2px solid #21d4fd;
      display: flex; align-items: center; gap: 12px;
    }
    header h1 { font-size: 1.3rem; color: #21d4fd; }
    header span { font-size: 0.8rem; color: #8b949e; }
    .status-dot { width: 10px; height: 10px; border-radius: 50%;
                  background: #3fb950; animation: pulse 1.5s infinite; }
    @keyframes pulse { 0%,100%{opacity:1} 50%{opacity:0.4} }
 
    .cards { display: flex; gap: 16px; padding: 20px 24px; flex-wrap: wrap; }
    .card {
      background: #161b22; border: 1px solid #30363d;
      border-radius: 10px; padding: 16px 24px;
      flex: 1; min-width: 180px; text-align: center;
    }
    .card .value { font-size: 2rem; font-weight: 700; }
    .card .label { font-size: 0.8rem; color: #8b949e; margin-top: 4px; }
    .total   .value { color: #58a6ff; }
    .critical .value { color: #ff7b72; }
    .ips     .value { color: #d2a8ff; }
    .ml      .value { color: #3fb950; }
 
    .charts { display: grid; grid-template-columns: 1fr 1fr; gap: 16px;
              padding: 0 24px 24px; }
    .chart-box {
      background: #161b22; border: 1px solid #30363d;
      border-radius: 10px; padding: 16px;
    }
    .chart-box h3 { font-size: 0.9rem; color: #8b949e;
                    margin-bottom: 12px; text-transform: uppercase; }
    canvas { max-height: 250px; }
 
    .alerts-table { margin: 0 24px 24px; background: #161b22;
                    border: 1px solid #30363d; border-radius: 10px;
                    overflow: hidden; }
    .alerts-table h3 { padding: 12px 16px; font-size: 0.9rem; color: #8b949e;
                       text-transform: uppercase; border-bottom: 1px solid #30363d; }
    table { width: 100%; border-collapse: collapse; font-size: 0.82rem; }
    th { background: #21262d; padding: 8px 12px; text-align: left;
         color: #8b949e; }
    td { padding: 7px 12px; border-bottom: 1px solid #21262d; }
    tr:last-child td { border-bottom: none; }
    .sev { padding: 2px 8px; border-radius: 4px; font-weight: 600;
           font-size: 0.75rem; }
    .CRITICAL { background: #3d1c1c; color: #ff7b72; }
    .HIGH     { background: #3d2f00; color: #e3b341; }
    .MEDIUM   { background: #001f3d; color: #58a6ff; }
    .LOW      { background: #0f2d0f; color: #3fb950; }
    .badge-rule { background: #0d2640; color: #58a6ff; }
    .badge-ml   { background: #0d2a0d; color: #3fb950; }
    .badge { padding: 1px 6px; border-radius: 4px; font-size: 0.7rem; }
  </style>
</head>
<body>
<header>
  <div class="status-dot"></div>
  <h1>🛡️  Hybrid AI-Enhanced NIDS</h1>
  <span id="last-update">Initialising …</span>
</header>
 
<!-- KPI Cards -->
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
 
<!-- Charts -->
<div class="charts">
  <div class="chart-box">
    <h3>Alert Timeline (last 60 min)</h3>
    <canvas id="timelineChart"></canvas>
  </div>
  <div class="chart-box">
    <h3>Attack Distribution</h3>
    <canvas id="pieChart"></canvas>
  </div>
  <div class="chart-box">
    <h3>Top Attacker IPs</h3>
    <canvas id="attackersChart"></canvas>
  </div>
  <div class="chart-box">
    <h3>Severity Breakdown</h3>
    <canvas id="severityChart"></canvas>
  </div>
</div>
 
<!-- Recent Alerts Table -->
<div class="alerts-table">
  <h3>Recent Alerts</h3>
  <table>
    <thead>
      <tr>
        <th>#</th><th>Time</th><th>Type</th><th>Source IP</th>
        <th>Dest IP:Port</th><th>Severity</th><th>Engine</th><th>Detail</th>
      </tr>
    </thead>
    <tbody id="alerts-body"></tbody>
  </table>
</div>
 
<script>
// ─── Chart.js instances ──────────────────────────────────────────────────────
const PALETTE = ['#58a6ff','#3fb950','#e3b341','#ff7b72',
                 '#d2a8ff','#79c0ff','#56d364','#ffa657'];
 
function mkLine(id) {
  return new Chart(document.getElementById(id), {
    type: 'line',
    data: { labels: [], datasets: [{ label: 'Alerts', data: [],
      borderColor: '#58a6ff', backgroundColor: 'rgba(88,166,255,0.1)',
      tension: 0.3, fill: true, pointRadius: 3 }] },
    options: { responsive:true, scales: {
      x: { ticks:{color:'#8b949e'}, grid:{color:'#21262d'} },
      y: { ticks:{color:'#8b949e'}, grid:{color:'#21262d'}, beginAtZero:true }
    }, plugins:{legend:{labels:{color:'#c9d1d9'}}} }
  });
}
 
function mkPie(id) {
  return new Chart(document.getElementById(id), {
    type: 'doughnut',
    data: { labels: [], datasets: [{ data: [], backgroundColor: PALETTE }] },
    options: { responsive:true, plugins:{legend:{labels:{color:'#c9d1d9'}}} }
  });
}
 
function mkBar(id, label, colour) {
  return new Chart(document.getElementById(id), {
    type: 'bar',
    data: { labels: [], datasets: [{ label, data: [],
      backgroundColor: colour, borderRadius: 4 }] },
    options: { indexAxis:'y', responsive:true, scales: {
      x: { ticks:{color:'#8b949e'}, grid:{color:'#21262d'} },
      y: { ticks:{color:'#8b949e'}, grid:{color:'#21262d'} }
    }, plugins:{legend:{labels:{color:'#c9d1d9'}}} }
  });
}
 
const timelineChart  = mkLine('timelineChart');
const pieChart       = mkPie('pieChart');
const attackersChart = mkBar('attackersChart', 'Alerts', '#ff7b72');
const severityChart  = mkBar('severityChart',  'Count',  '#d2a8ff');
 
// ─── Data refresh ─────────────────────────────────────────────────────────────
async function refresh() {
  try {
    const [stats, dist, attackers, timeline, recent] = await Promise.all([
      fetch('/api/stats').then(r=>r.json()),
      fetch('/api/distribution').then(r=>r.json()),
      fetch('/api/top_attackers').then(r=>r.json()),
      fetch('/api/timeline').then(r=>r.json()),
      fetch('/api/recent').then(r=>r.json()),
    ]);
 
    // KPI cards
    document.getElementById('total-alerts').textContent    = stats.total;
    document.getElementById('critical-alerts').textContent = stats.critical;
    document.getElementById('unique-ips').textContent      = stats.unique_attacker_ips;
    document.getElementById('ml-alerts').textContent       = stats.ml_count || 0;
    document.getElementById('last-update').textContent     =
      'Last updated: ' + new Date().toLocaleTimeString();
 
    // Timeline
    timelineChart.data.labels                 = timeline.map(t=>t.minute.slice(11));
    timelineChart.data.datasets[0].data       = timeline.map(t=>t.count);
    timelineChart.update();
 
    // Pie
    pieChart.data.labels                      = dist.map(d=>d.attack_type);
    pieChart.data.datasets[0].data            = dist.map(d=>d.count);
    pieChart.update();
 
    // Top attackers
    attackersChart.data.labels                = attackers.map(a=>a.ip);
    attackersChart.data.datasets[0].data      = attackers.map(a=>a.count);
    attackersChart.update();
 
    // Severity bar chart (compute from dist)
    const sevMap = {CRITICAL:0,HIGH:0,MEDIUM:0,LOW:0};
    recent.forEach(a=>{ if(sevMap[a.severity]!==undefined) sevMap[a.severity]++ });
    severityChart.data.labels                 = Object.keys(sevMap);
    severityChart.data.datasets[0].data       = Object.values(sevMap);
    severityChart.update();
 
    // Recent alerts table
    const tbody = document.getElementById('alerts-body');
    tbody.innerHTML = recent.slice(0,50).map((a,i) => `
      <tr>
        <td>${a.id}</td>
        <td>${a.timestamp.slice(11,19)}</td>
        <td>${a.attack_type}</td>
        <td>${a.source_ip}</td>
        <td>${a.destination_ip}:${a.port}</td>
        <td><span class="sev ${a.severity}">${a.severity}</span></td>
        <td><span class="badge badge-${a.source.toLowerCase()}">${a.source}</span></td>
        <td style="max-width:200px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap"
            title="${a.detail}">${a.detail}</td>
      </tr>`).join('');
  } catch(e) {
    console.warn('Refresh error', e);
  }
}
 
refresh();
setInterval(refresh, 3000);   // Auto-refresh every 3 seconds
</script>
</body>
</html>
"""
 
 
def run_dashboard(alert_list, alert_lock, port=5000):
    """
    Creates and runs the Flask app in a background thread.
    All API endpoints read from alert_list (in-memory) for speed,
    and from the SQLite DB for historical aggregates.
    """
    from src.logger import Logger
    db = Logger()   # Separate connection for read-only dashboard queries
 
    app = Flask(__name__, static_folder=None)
    app.config["DEBUG"] = False
 
    @app.route("/")
    def index():
        return render_template_string(DASHBOARD_HTML)
 
    @app.route("/api/stats")
    def api_stats():
        stats = db.get_stats()
        # Count ML-sourced alerts from in-memory list
        with alert_lock:
            ml_count = sum(1 for a in alert_list if a.get("source") == "ML")
        stats["ml_count"] = ml_count
        return jsonify(stats)
 
    @app.route("/api/distribution")
    def api_distribution():
        return jsonify(db.get_attack_distribution())
 
    @app.route("/api/top_attackers")
    def api_top_attackers():
        return jsonify(db.get_top_attackers(10))
 
    @app.route("/api/timeline")
    def api_timeline():
        return jsonify(db.get_timeline(hours=1))
 
    @app.route("/api/recent")
    def api_recent():
        return jsonify(db.get_recent_alerts(100))
 
    # Suppress Flask's default banner
    import logging
    log = logging.getLogger("werkzeug")
    log.setLevel(logging.ERROR)
 
