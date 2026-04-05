"""
  demo.py — NIDS Demo with Flask Dashboard
  Simulates packets continuously, detects attacks, and shows
  a live dashboard at http://127.0.0.1:5000
  Run: python demo.py
  No root, no Scapy, no live network needed!
"""

import sys, os, time, random, threading, webbrowser
sys.path.insert(0, os.path.dirname(__file__))

from src.feature_extractor import FeatureExtractor
from src.rule_engine       import RuleEngine
from src.anomaly_detector  import AnomalyDetector
from src.alert_system      import AlertSystem
from src.logger            import Logger
from datetime              import datetime
from flask                 import Flask, jsonify, render_template_string

# ── Shared state ───────────────────────────────────────────────────────────────
alert_list  = []
alert_lock  = threading.Lock()
stats       = {
    "packets_processed" : 0,
    "total_alerts"      : 0,
    "critical"          : 0,
    "ml_count"          : 0,
}

# ── Attack scenarios ───────────────────────────────────────────────────────────
SCENARIOS = [
    ("192.168.1.10", "192.168.1.1",  80,   "TCP",  512,  "PA"),
    ("192.168.1.11", "192.168.1.1",  443,  "TCP",  800,  "PA"),
    ("10.0.0.1",     "192.168.1.1",  22,   "TCP",  60,   "S" ),
    ("10.0.0.1",     "192.168.1.1",  23,   "TCP",  60,   "S" ),
    ("172.16.0.5",   "192.168.1.1",  445,  "TCP",  60,   "S" ),
    ("203.0.113.42", "192.168.1.1",  0,    "ICMP", 65000,""  ),
    ("10.0.0.1",     "192.168.1.1",  3389, "TCP",  60,   "S" ),
    ("172.16.0.5",   "192.168.1.1",  3306, "TCP",  60,   "S" ),
]

DASHBOARD_HTML = """
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8"/>
  <meta name="viewport" content="width=device-width,initial-scale=1"/>
  <title>NIDS Live Demo Dashboard</title>
  <script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.0/dist/chart.umd.min.js"></script>
  <style>
    *{box-sizing:border-box;margin:0;padding:0}
    body{font-family:'Segoe UI',sans-serif;background:#0d1117;color:#c9d1d9}
    header{background:linear-gradient(90deg,#161b22,#1f2937);padding:14px 24px;
           border-bottom:2px solid #21d4fd;display:flex;align-items:center;gap:12px}
    header h1{font-size:1.2rem;color:#21d4fd}
    header span{font-size:0.8rem;color:#8b949e;margin-left:auto}
    .dot{width:10px;height:10px;border-radius:50%;background:#3fb950;animation:pulse 1.5s infinite}
    @keyframes pulse{0%,100%{opacity:1}50%{opacity:0.3}}
    .cards{display:flex;gap:14px;padding:18px 24px;flex-wrap:wrap}
    .card{background:#161b22;border:1px solid #30363d;border-radius:10px;
          padding:14px 20px;flex:1;min-width:160px;text-align:center}
    .card .val{font-size:2rem;font-weight:700}
    .card .lbl{font-size:0.75rem;color:#8b949e;margin-top:4px}
    .c1 .val{color:#58a6ff}.c2 .val{color:#ff7b72}
    .c3 .val{color:#3fb950}.c4 .val{color:#d2a8ff}
    .charts{display:grid;grid-template-columns:1fr 1fr;gap:14px;padding:0 24px 18px}
    .box{background:#161b22;border:1px solid #30363d;border-radius:10px;padding:14px}
    .box h3{font-size:0.8rem;color:#8b949e;margin-bottom:10px;
            text-transform:uppercase;letter-spacing:1px}
    canvas{max-height:220px}
    .tbl-wrap{margin:0 24px 24px;background:#161b22;
              border:1px solid #30363d;border-radius:10px;overflow:hidden}
    .tbl-wrap h3{padding:10px 16px;font-size:0.8rem;color:#8b949e;
                 text-transform:uppercase;border-bottom:1px solid #30363d}
    table{width:100%;border-collapse:collapse;font-size:0.8rem}
    th{background:#21262d;padding:7px 12px;text-align:left;color:#8b949e}
    td{padding:6px 12px;border-bottom:1px solid #21262d}
    tr:last-child td{border-bottom:none}
    .sev{padding:2px 7px;border-radius:4px;font-weight:700;font-size:0.7rem}
    .CRITICAL{background:#3d1c1c;color:#ff7b72}
    .HIGH{background:#3d2f00;color:#e3b341}
    .MEDIUM{background:#001f3d;color:#58a6ff}
    .LOW{background:#0f2d0f;color:#3fb950}
    .eng{padding:2px 6px;border-radius:4px;font-size:0.7rem}
    .RULE{background:#0d2640;color:#58a6ff}
    .ML{background:#0d2a0d;color:#3fb950}
  </style>
</head>
<body>
<header>
  <div class="dot"></div>
  <h1>&#128737;  Hybrid AI-Enhanced NIDS &mdash; Live Demo Dashboard</h1>
  <span id="ts">Connecting ...</span>
</header>
<div class="cards">
  <div class="card c1"><div class="val" id="v-pkts">0</div><div class="lbl">Packets Processed</div></div>
  <div class="card c2"><div class="val" id="v-tot">0</div><div class="lbl">Total Alerts</div></div>
  <div class="card c3"><div class="val" id="v-crit">0</div><div class="lbl">Critical Alerts</div></div>
  <div class="card c4"><div class="val" id="v-ml">0</div><div class="lbl">ML Anomalies</div></div>
</div>
<div class="charts">
  <div class="box"><h3>Attack Distribution</h3><canvas id="pieChart"></canvas></div>
  <div class="box"><h3>Alerts by Severity</h3><canvas id="sevChart"></canvas></div>
  <div class="box"><h3>Top Attacker IPs</h3><canvas id="ipChart"></canvas></div>
  <div class="box"><h3>Alert Timeline</h3><canvas id="lineChart"></canvas></div>
</div>
<div class="tbl-wrap">
  <h3>Live Alerts Feed</h3>
  <table>
    <thead><tr>
      <th>#</th><th>Time</th><th>Attack Type</th>
      <th>Source IP</th><th>Dest IP : Port</th>
      <th>Severity</th><th>Engine</th>
    </tr></thead>
    <tbody id="tbody"></tbody>
  </table>
</div>
<script>
const PAL=['#ff7b72','#e3b341','#58a6ff','#3fb950','#d2a8ff','#79c0ff','#ffa657'];
const mkPie=id=>new Chart(document.getElementById(id),{
  type:'doughnut',data:{labels:[],datasets:[{data:[],backgroundColor:PAL}]},
  options:{responsive:true,plugins:{legend:{labels:{color:'#c9d1d9'}}}}});
const mkBar=(id,lbl,col,horiz=false)=>new Chart(document.getElementById(id),{
  type:'bar',
  data:{labels:[],datasets:[{label:lbl,data:[],backgroundColor:col,borderRadius:4}]},
  options:{indexAxis:horiz?'y':'x',responsive:true,
    scales:{x:{ticks:{color:'#8b949e'},grid:{color:'#21262d'}},
            y:{ticks:{color:'#8b949e'},grid:{color:'#21262d'},beginAtZero:true}},
    plugins:{legend:{labels:{color:'#c9d1d9'}}}}});
const mkLine=id=>new Chart(document.getElementById(id),{
  type:'line',
  data:{labels:[],datasets:[{label:'Alerts',data:[],
    borderColor:'#58a6ff',backgroundColor:'rgba(88,166,255,0.1)',
    tension:0.3,fill:true,pointRadius:3}]},
  options:{responsive:true,
    scales:{x:{ticks:{color:'#8b949e'},grid:{color:'#21262d'}},
            y:{ticks:{color:'#8b949e'},grid:{color:'#21262d'},beginAtZero:true}},
    plugins:{legend:{labels:{color:'#c9d1d9'}}}}});

const pieChart=mkPie('pieChart');
const sevChart=mkBar('sevChart','Count',['#ff7b72','#e3b341','#58a6ff','#3fb950']);
const ipChart=mkBar('ipChart','Alerts','#d2a8ff',true);
const lineChart=mkLine('lineChart');

async function refresh(){
  try{
    const d=await fetch('/api/data').then(r=>r.json());
    document.getElementById('v-pkts').textContent=d.stats.packets_processed;
    document.getElementById('v-tot').textContent=d.stats.total_alerts;
    document.getElementById('v-crit').textContent=d.stats.critical;
    document.getElementById('v-ml').textContent=d.stats.ml_count;
    document.getElementById('ts').textContent='Updated: '+new Date().toLocaleTimeString();
    pieChart.data.labels=d.distribution.map(x=>x.type);
    pieChart.data.datasets[0].data=d.distribution.map(x=>x.count);
    pieChart.update();
    sevChart.data.labels=['CRITICAL','HIGH','MEDIUM','LOW'];
    sevChart.data.datasets[0].data=[d.severity.CRITICAL||0,d.severity.HIGH||0,
                                     d.severity.MEDIUM||0,d.severity.LOW||0];
    sevChart.update();
    ipChart.data.labels=d.top_ips.map(x=>x.ip);
    ipChart.data.datasets[0].data=d.top_ips.map(x=>x.count);
    ipChart.update();
    lineChart.data.labels=d.timeline.map(x=>x.t);
    lineChart.data.datasets[0].data=d.timeline.map(x=>x.c);
    lineChart.update();
    document.getElementById('tbody').innerHTML=d.recent.map(a=>`
      <tr>
        <td>${a.id}</td><td>${a.timestamp.slice(11,19)}</td>
        <td>${a.attack_type}</td><td>${a.source_ip}</td>
        <td>${a.destination_ip}:${a.port}</td>
        <td><span class="sev ${a.severity}">${a.severity}</span></td>
        <td><span class="eng ${a.source}">${a.source}</span></td>
      </tr>`).join('');
  }catch(e){console.warn(e)}
}
refresh();
setInterval(refresh,2000);
</script>
</body>
</html>
"""

app = Flask(__name__)

@app.route("/")
def index():
    return render_template_string(DASHBOARD_HTML)

@app.route("/api/data")
def api_data():
    with alert_lock:
        alerts = list(alert_list)

    dist_map = {}
    for a in alerts:
        dist_map[a["attack_type"]] = dist_map.get(a["attack_type"], 0) + 1
    distribution = [{"type":k,"count":v} for k,v in
                    sorted(dist_map.items(), key=lambda x:-x[1])]

    sev = {"CRITICAL":0,"HIGH":0,"MEDIUM":0,"LOW":0}
    for a in alerts:
        sev[a.get("severity","LOW")] = sev.get(a.get("severity","LOW"),0) + 1

    ip_map = {}
    for a in alerts:
        ip_map[a["source_ip"]] = ip_map.get(a["source_ip"],0) + 1
    top_ips = [{"ip":k,"count":v} for k,v in
               sorted(ip_map.items(), key=lambda x:-x[1])[:8]]

    from collections import Counter
    mins = Counter(a["timestamp"][11:16] for a in alerts[-100:])
    timeline = [{"t":k,"c":v} for k,v in sorted(mins.items())[-20:]]

    recent = []
    for i, a in enumerate(reversed(alerts[-30:]), 1):
        recent.append({
            "id"            : len(alerts)-i+1,
            "timestamp"     : a.get("timestamp",""),
            "attack_type"   : a.get("attack_type",""),
            "source_ip"     : a.get("source_ip",""),
            "destination_ip": a.get("destination_ip",""),
            "port"          : a.get("port",0),
            "severity"      : a.get("severity","LOW"),
            "source"        : a.get("source","RULE"),
        })

    return jsonify({
        "stats":stats,"distribution":distribution,
        "severity":sev,"top_ips":top_ips,
        "timeline":timeline,"recent":recent,
    })


def run_simulation():
    """Runs forever in background — simulates packets through detection pipeline."""
    extractor        = FeatureExtractor()
    rule_engine      = RuleEngine()
    anomaly_detector = AnomalyDetector()
    alert_system     = AlertSystem(verbose=True)
    logger           = Logger()

    print("[*] Training anomaly detector ...")
    anomaly_detector.train_on_synthetic()
    print("[+] Training complete!\n")
    print("[*] Simulating network traffic ...\n")

    packet_num = 0
    while True:
        s = random.choice(SCENARIOS)
        raw = {
            "source_ip"       : s[0],
            "destination_ip"  : s[1],
            "source_port"     : random.randint(49152, 65535),
            "destination_port": s[2],
            "protocol"        : s[3],
            "packet_size"     : s[4] + random.randint(-20, 20),
            "tcp_flags"       : s[5],
            "timestamp"       : datetime.now().isoformat(),
        }

        features    = extractor.extract(raw)
        rule_alerts = rule_engine.analyze(features)
        ml_alert    = anomaly_detector.predict(features)
        all_alerts  = rule_alerts + ([ml_alert] if ml_alert else [])

        for alert in all_alerts:
            alert_system.dispatch(alert)
            logger.log_alert(alert)
            with alert_lock:
                alert_list.append(alert)
                if len(alert_list) > 500:
                    alert_list.pop(0)
            stats["total_alerts"] += 1
            if alert.get("severity") == "CRITICAL":
                stats["critical"] += 1
            if alert.get("source") == "ML":
                stats["ml_count"] += 1

        packet_num += 1
        stats["packets_processed"] = packet_num
        time.sleep(0.15)


def main():
    print("=" * 60)
    print("  Hybrid AI-Enhanced NIDS — Demo + Dashboard")
    print("=" * 60)

    # Start simulation thread
    threading.Thread(target=run_simulation, daemon=True).start()

    # Auto-open browser after 3 sec
    def open_browser():
        time.sleep(3)
        webbrowser.open("http://127.0.0.1:5000")
    threading.Thread(target=open_browser, daemon=True).start()

    print("[+] Dashboard at http://127.0.0.1:5000")
    print("[*] Browser opens automatically in 3 seconds ...")
    print("[*] Press Ctrl+C to stop.\n")

    import logging
    logging.getLogger("werkzeug").setLevel(logging.ERROR)

    app.run(host="127.0.0.1", port=5000, debug=False, threaded=True)


if __name__ == "__main__":
    main()
