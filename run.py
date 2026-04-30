"""
  run.py — MASTER RUNNER
  Hybrid AI-Enhanced NIDS — Complete Project

  USAGE:
    python run.py            → Interactive menu
    python run.py --demo     → Quick 200-packet demo
    python run.py --train    → Train ML model only
    python run.py --evaluate → Train + test with metrics
    python run.py --compare  → Compare 3 ML algorithms
    python run.py --features → Feature importance analysis
    python run.py --live     → Full live system + dashboard
    python run.py --all      → Run EVERYTHING in sequence

"""

import os, sys, time, argparse, threading, queue, random
from datetime import datetime

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, BASE_DIR)

# ── Colours ───────────────────────────────────────────────────────────────────
class C:
    BLUE='\033[94m'; CYAN='\033[96m'; GREEN='\033[92m'
    YELLOW='\033[93m'; RED='\033[91m'; BOLD='\033[1m'; RESET='\033[0m'

def banner():
    print(f"""{C.BOLD}{C.BLUE}
╔══════════════════════════════════════════════════════════════╗
║      HYBRID AI-ENHANCED NETWORK INTRUSION DETECTION          ║
║                      SYSTEM  (NIDS)                          ║
║               B.Tech Cybersecurity Project                   ║
╚══════════════════════════════════════════════════════════════╝{C.RESET}""")

def section(title):
    print(f"\n{C.BOLD}{C.CYAN}{'═'*60}\n  {title}\n{'═'*60}{C.RESET}\n")

def ok(msg):   print(f"{C.GREEN}  ✅ {msg}{C.RESET}")
def info(msg): print(f"{C.BLUE}  ℹ  {msg}{C.RESET}")
def warn(msg): print(f"{C.YELLOW}  ⚠  {msg}{C.RESET}")
def err(msg):  print(f"{C.RED}  ✗  {msg}{C.RESET}")


# ─────────────────────────────────────────────────────────────────────────────
#  SHARED FUNCTIONS
# ─────────────────────────────────────────────────────────────────────────────

def check_dependencies():
    section("Checking Dependencies")
    required = {"sklearn":"scikit-learn","numpy":"numpy",
                "flask":"flask","matplotlib":"matplotlib"}
    optional = {"scapy":"scapy","pandas":"pandas"}
    all_ok = True
    for mod, pkg in required.items():
        try:    __import__(mod); ok(f"{pkg}")
        except: err(f"{pkg} MISSING — run: pip install {pkg}"); all_ok=False
    for mod, pkg in optional.items():
        try:    __import__(mod); ok(f"{pkg} (optional)")
        except: warn(f"{pkg} not installed (optional)")
    if not all_ok:
        err("Install missing: pip install -r requirements.txt"); sys.exit(1)
    ok("All required dependencies OK!")


def setup_folders():
    section("Setting Up Project Folders")
    for folder in ["models","logs","results","static/css","static/js"]:
        os.makedirs(os.path.join(BASE_DIR, folder), exist_ok=True)
        ok(f"Ready: {folder}/")


def train_model():
    section("Training ML Anomaly Detection Model")
    info("Algorithm  : Isolation Forest (Unsupervised)")
    info("Samples    : 5,000 synthetic normal traffic vectors")
    try:
        from src.anomaly_detector import AnomalyDetector
        AnomalyDetector().train_on_synthetic()
        ok("Model saved → models/anomaly_model.pkl")
    except Exception as e:
        err(f"Training failed: {e}"); return
    try:
        from src.anomaly_detector_v2 import AnomalyDetectorV2
        AnomalyDetectorV2().train_on_synthetic()
        ok("Enhanced model saved → models/anomaly_model_v2.pkl")
    except Exception as e:
        warn(f"Enhanced model skipped: {e}")


# ─────────────────────────────────────────────────────────────────────────────
#  OPTIONAL FUNCTIONS
# ─────────────────────────────────────────────────────────────────────────────

def run_demo():
    section("Quick Demo  —  200 Simulated Packets")
    info("Scenarios  : Normal HTTP + Port Scan + Brute Force + ICMP + DDoS")
    info("Engines    : Rule-based + ML Anomaly Detection")
    try:
        import importlib.util
        spec = importlib.util.spec_from_file_location(
            "demo", os.path.join(BASE_DIR,"demo.py"))
        m = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(m); m.main()
    except Exception as e:
        err(f"Demo failed: {e}")


def run_evaluation():
    section("Train / Test Evaluation  —  Upgrade 1")
    info("Test set   : 1,000 normal  +  500 attack samples")
    info("Metrics    : Accuracy, Precision, Recall, F1, FPR")
    try:
        import importlib.util
        spec = importlib.util.spec_from_file_location(
            "train_test", os.path.join(BASE_DIR,"train_test.py"))
        m = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(m)
        metrics = m.main()
        print(f"\n{C.BOLD}  Results:{C.RESET}")
        for lbl,key in [("Accuracy","accuracy"),("Precision","precision"),
                        ("Recall","recall"),("F1 Score","f1_score")]:
            print(f"  {lbl:<12}: {C.GREEN}{metrics[key]}%{C.RESET}")
        ok("Charts saved → results/")
    except Exception as e:
        err(f"Evaluation failed: {e}")


def run_comparison():
    section("ML Algorithm Comparison  —  Upgrade 2")
    info("Models     : Isolation Forest  vs  One-Class SVM  vs  LOF")
    try:
        import importlib.util
        spec = importlib.util.spec_from_file_location(
            "model_compare", os.path.join(BASE_DIR,"model_compare.py"))
        m = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(m)
        results = m.main()
        best = max(results, key=lambda x: x['f1_score'])
        ok(f"Best model: {best['name']}  (F1={best['f1_score']}%)")
        ok("Charts saved → results/")
    except Exception as e:
        err(f"Comparison failed: {e}")


def run_feature_importance():
    section("Feature Importance Analysis  —  Upgrade 3")
    info("Method     : Permutation-based importance across 12 features")
    try:
        from src.anomaly_detector_v2 import AnomalyDetectorV2
        d = AnomalyDetectorV2()
        if d.model is None:
            info("Training v2 model first …"); d.train_on_synthetic()
        d.print_importance_table()
        d.plot_feature_importance()
        ok("Chart saved → results/feature_importance.png")
    except Exception as e:
        err(f"Feature importance failed: {e}")


# ─────────────────────────────────────────────────────────────────────────────
#  LIVE SYSTEM  —  THE MAIN SHOW
# ─────────────────────────────────────────────────────────────────────────────

def _prepopulate(extractor, rule_eng, anomaly_det,
                 alert_sys, logger, alert_list, alert_lock):
    """Rapidly generate 40 alerts so dashboard is NOT empty on first load."""
    scenarios = [
        ("10.0.0.1",    "192.168.1.1", 22,   "TCP",  60,    "S"),
        ("10.0.0.1",    "192.168.1.1", 22,   "TCP",  60,    "S"),
        ("10.0.0.1",    "192.168.1.1", 22,   "TCP",  60,    "S"),
        ("10.0.0.1",    "192.168.1.1", 22,   "TCP",  60,    "S"),
        ("10.0.0.1",    "192.168.1.1", 22,   "TCP",  60,    "S"),
        ("10.0.0.1",    "192.168.1.1", 22,   "TCP",  60,    "S"),
        ("10.0.0.1",    "192.168.1.1", 22,   "TCP",  60,    "S"),
        ("10.0.0.1",    "192.168.1.1", 22,   "TCP",  60,    "S"),
        ("10.0.0.1",    "192.168.1.1", 22,   "TCP",  60,    "S"),
        ("10.0.0.1",    "192.168.1.1", 22,   "TCP",  60,    "S"),
        ("172.16.0.5",  "192.168.1.1", 1,    "TCP",  60,    "S"),
        ("172.16.0.5",  "192.168.1.1", 2,    "TCP",  60,    "S"),
        ("172.16.0.5",  "192.168.1.1", 3,    "TCP",  60,    "S"),
        ("172.16.0.5",  "192.168.1.1", 4,    "TCP",  60,    "S"),
        ("172.16.0.5",  "192.168.1.1", 5,    "TCP",  60,    "S"),
        ("172.16.0.5",  "192.168.1.1", 6,    "TCP",  60,    "S"),
        ("172.16.0.5",  "192.168.1.1", 7,    "TCP",  60,    "S"),
        ("172.16.0.5",  "192.168.1.1", 8,    "TCP",  60,    "S"),
        ("172.16.0.5",  "192.168.1.1", 9,    "TCP",  60,    "S"),
        ("172.16.0.5",  "192.168.1.1", 10,   "TCP",  60,    "S"),
        ("172.16.0.5",  "192.168.1.1", 11,   "TCP",  60,    "S"),
        ("172.16.0.5",  "192.168.1.1", 12,   "TCP",  60,    "S"),
        ("172.16.0.5",  "192.168.1.1", 13,   "TCP",  60,    "S"),
        ("172.16.0.5",  "192.168.1.1", 14,   "TCP",  60,    "S"),
        ("172.16.0.5",  "192.168.1.1", 15,   "TCP",  60,    "S"),
        ("203.0.113.42","192.168.1.1", 0,    "ICMP", 65000, ""),
        ("203.0.113.42","192.168.1.1", 0,    "ICMP", 65000, ""),
        ("203.0.113.42","192.168.1.1", 0,    "ICMP", 65000, ""),
        ("10.0.0.1",    "192.168.1.1", 3389, "TCP",  60,    "S"),
        ("10.0.0.1",    "192.168.1.1", 23,   "TCP",  60,    "S"),
        ("10.0.0.1",    "192.168.1.1", 445,  "TCP",  60,    "S"),
        ("172.16.0.5",  "192.168.1.1", 3306, "TCP",  60,    "S"),
        ("203.0.113.42","192.168.1.1", 0,    "ICMP", 50000, ""),
        ("10.0.0.1",    "192.168.1.1", 22,   "TCP",  60,    "S"),
        ("10.0.0.1",    "192.168.1.1", 22,   "TCP",  60,    "S"),
        ("10.0.0.1",    "192.168.1.1", 22,   "TCP",  60,    "S"),
        ("172.16.0.5",  "192.168.1.1", 21,   "TCP",  60,    "S"),
        ("203.0.113.42","192.168.1.1", 0,    "ICMP", 40000, ""),
        ("10.0.0.1",    "192.168.1.1", 1433, "TCP",  60,    "S"),
        ("172.16.0.5",  "192.168.1.1", 5432, "TCP",  60,    "S"),
    ]
    for s in scenarios:
        raw = {
            "source_ip": s[0], "destination_ip": s[1],
            "source_port": random.randint(49152,65535),
            "destination_port": s[2], "protocol": s[3],
            "packet_size": s[4], "tcp_flags": s[5],
            "timestamp": datetime.now().isoformat(),
        }
        features = extractor.extract(raw)
        for alert in rule_eng.analyze(features):
            alert_sys.dispatch(alert)
            logger.log_alert(alert)
            with alert_lock:
                alert_list.append(alert)
        ml = anomaly_det.predict(features)
        if ml:
            alert_sys.dispatch(ml)
            logger.log_alert(ml)
            with alert_lock:
                alert_list.append(ml)


def run_live(port=5000):
    section("Launching Live NIDS + Dashboard")
    logger = None
    try:
        from src.packet_capture    import PacketCaptureEngine
        from src.feature_extractor import FeatureExtractor
        from src.rule_engine       import RuleEngine
        from src.anomaly_detector  import AnomalyDetector
        from src.alert_system      import AlertSystem
        from src.logger            import Logger
        from src.dashboard         import run_dashboard

        pkt_q      = queue.Queue(maxsize=2000)
        alert_list = []
        alert_lock = threading.Lock()

        extractor   = FeatureExtractor()
        rule_eng    = RuleEngine()
        anomaly_det = AnomalyDetector()
        alert_sys   = AlertSystem()

        # 1. Create DB first
        print(f"\n{C.CYAN}  [1/4] Initialising database …{C.RESET}")
        logger = Logger()
        ok("Database ready → logs/nids.db")

        # 2. Pre-populate so dashboard is NOT empty
        print(f"\n{C.CYAN}  [2/4] Pre-generating alerts for dashboard …{C.RESET}")
        _prepopulate(extractor, rule_eng, anomaly_det,
                     alert_sys, logger, alert_list, alert_lock)
        ok(f"Dashboard pre-loaded with {len(alert_list)} alerts")

        # 3. Start detection worker
        print(f"\n{C.CYAN}  [3/4] Starting detection engine …{C.RESET}")
        def worker():
            while True:
                try:
                    features = pkt_q.get(timeout=1)
                except queue.Empty:
                    continue
                try:
                    for alert in rule_eng.analyze(features):
                        alert_sys.dispatch(alert)
                        logger.log_alert(alert)
                        with alert_lock:
                            alert_list.append(alert)
                            if len(alert_list) > 500: alert_list.pop(0)
                    ml = anomaly_det.predict(features)
                    if ml:
                        alert_sys.dispatch(ml)
                        logger.log_alert(ml)
                        with alert_lock:
                            alert_list.append(ml)
                            if len(alert_list) > 500: alert_list.pop(0)
                except Exception:
                    pass
                pkt_q.task_done()

        threading.Thread(target=worker, daemon=True).start()
        ok("Rule engine + ML detector → running")

        # 4. Start dashboard
        print(f"\n{C.CYAN}  [4/4] Starting web dashboard …{C.RESET}")
        threading.Thread(
            target=run_dashboard,
            args=(alert_list, alert_lock, port),
            daemon=True
        ).start()
        time.sleep(1.5)   # Let Flask fully start
        ok(f"Dashboard → http://127.0.0.1:{port}")

        # Ready!
        print(f"""\n{C.BOLD}{C.GREEN}
  ╔════════════════════════════════════════════════════╗
  ║     NIDS IS LIVE AND RUNNING!                    ║
  ╠════════════════════════════════════════════════════╣
  ║    Open Dashboard : http://127.0.0.1:{port}       ║
  ║    Live Alerts   : Generating every second       ║
  ║    AI Report     : Click button on dashboard     ║
  ╠════════════════════════════════════════════════════╣
  ║   Press Ctrl+C to stop                             ║
  ╚════════════════════════════════════════════════════╝
{C.RESET}""")

        # Start packet capture
        capture = PacketCaptureEngine(
            interface="eth0",
            packet_queue=pkt_q,
            extractor=extractor,
            simulate=True
        )
        capture.start()   # Blocks here until Ctrl+C

    except KeyboardInterrupt:
        print(f"\n{C.YELLOW}  Stopping NIDS …{C.RESET}")
        if logger:
            try: logger.close()
            except: pass
        print(f"{C.GREEN}   NIDS stopped cleanly.{C.RESET}\n")
    except Exception as e:
        err(f"Live system error: {e}")
        import traceback; traceback.print_exc()


# ─────────────────────────────────────────────────────────────────────────────
#  RUN ALL  —  COMPLETE PIPELINE
# ─────────────────────────────────────────────────────────────────────────────

def run_all():
    steps = [
        ("Dependency Check",          check_dependencies),
        ("Folder Setup",              setup_folders),
        ("Train ML Models",           train_model),
        ("Evaluate Model (Metrics)",  run_evaluation),
        ("Compare 3 Algorithms",      run_comparison),
        ("Feature Importance",        run_feature_importance),
        ("Quick Demo (200 packets)",  run_demo),
    ]
    total = len(steps)
    for i, (name, fn) in enumerate(steps, 1):
        print(f"\n{C.BOLD}{C.CYAN}  [{i}/{total}] {name}{C.RESET}")
        print(f"  {'─'*50}")
        try:    fn()
        except Exception as e: warn(f"Skipped — {e}")

    print(f"""{C.BOLD}{C.GREEN}
  ╔══════════════════════════════════════════════════════╗
  ║     ALL STEPS COMPLETE!                            ║
  ╠══════════════════════════════════════════════════════╣
  ║    Charts   → results/                            ║
  ║    Database → logs/nids.db                        ║
  ║    Models   → models/                             ║
  ╠══════════════════════════════════════════════════════╣
  ║   Now run:  python run.py --live                     ║
  ║   Open   :  http://127.0.0.1:5000                   ║
  ╚══════════════════════════════════════════════════════╝
{C.RESET}""")


# ─────────────────────────────────────────────────────────────────────────────
#  INTERACTIVE MENU
# ─────────────────────────────────────────────────────────────────────────────

def interactive_menu():
    banner()
    print(f"""
{C.CYAN}  Choose what to run:{C.RESET}

  {C.BOLD}[1]{C.RESET}  Quick Demo          — 200 packets, alerts on screen
  {C.BOLD}[2]{C.RESET}  Train ML Models     — Train Isolation Forest
  {C.BOLD}[3]{C.RESET}  Evaluate Model      — Metrics + Confusion Matrix
  {C.BOLD}[4]{C.RESET}  Compare Algorithms  — IF vs SVM vs LOF
  {C.BOLD}[5]{C.RESET}  Feature Importance  — Which features matter most
  {C.BOLD}[6]{C.RESET}  Live NIDS + Dashboard — THE MAIN SHOW 
  {C.BOLD}[7]{C.RESET}  Run ALL             — Full pipeline
  {C.BOLD}[0]{C.RESET}  Exit
""")
    choice = input(f"  {C.YELLOW}Enter choice (0-7): {C.RESET}").strip()
    menu = {
        "1": run_demo, "2": train_model, "3": run_evaluation,
        "4": run_comparison, "5": run_feature_importance,
        "6": run_live, "7": run_all,
        "0": lambda: print(f"\n  {C.CYAN}Goodbye! {C.RESET}\n")
    }
    fn = menu.get(choice)
    if fn: fn()
    else:  err("Invalid choice. Run again.")


# ─────────────────────────────────────────────────────────────────────────────
#  ENTRY POINT
# ─────────────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="Hybrid AI-Enhanced NIDS")
    parser.add_argument("--demo",     action="store_true")
    parser.add_argument("--train",    action="store_true")
    parser.add_argument("--evaluate", action="store_true")
    parser.add_argument("--compare",  action="store_true")
    parser.add_argument("--features", action="store_true")
    parser.add_argument("--live",     action="store_true")
    parser.add_argument("--all",      action="store_true")
    parser.add_argument("--port", type=int, default=5000)
    args = parser.parse_args()

    banner()

    if   args.demo:     check_dependencies(); setup_folders(); train_model(); run_demo()
    elif args.train:    check_dependencies(); setup_folders(); train_model()
    elif args.evaluate: check_dependencies(); setup_folders(); train_model(); run_evaluation()
    elif args.compare:  check_dependencies(); setup_folders(); run_comparison()
    elif args.features: check_dependencies(); setup_folders(); run_feature_importance()
    elif args.all:      run_all()
    elif args.live:
        check_dependencies()
        setup_folders()
        train_model()
        run_live(args.port)
    else:
        interactive_menu()


if __name__ == "__main__":
    main()
    