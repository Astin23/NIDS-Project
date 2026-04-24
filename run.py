
"""
  run.py — MASTER RUNNER
  Hybrid AI-Enhanced NIDS — Complete Project
  Single command to run the ENTIRE project:

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

import os
import sys
import time
import argparse
import threading
import queue

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, BASE_DIR)

# ── Terminal colours ───────────────────────────────────────────────────────────
class C:
    BLUE   = '\033[94m'
    CYAN   = '\033[96m'
    GREEN  = '\033[92m'
    YELLOW = '\033[93m'
    RED    = '\033[91m'
    BOLD   = '\033[1m'
    RESET  = '\033[0m'

# ── Print helpers ──────────────────────────────────────────────────────────────
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


# ═══════════════════════════════════════════════════════════════════════════════
#  STEP 0 — CHECK DEPENDENCIES
# ═══════════════════════════════════════════════════════════════════════════════
def check_dependencies():
    section("Step 0 — Checking Dependencies")
    required = {"sklearn":"scikit-learn", "numpy":"numpy",
                "flask":"flask", "matplotlib":"matplotlib"}
    optional = {"scapy":"scapy", "pandas":"pandas"}
    all_ok = True
    for mod, pkg in required.items():
        try:
            __import__(mod); ok(f"{pkg}")
        except ImportError:
            err(f"{pkg} MISSING — run: pip install {pkg}"); all_ok = False
    for mod, pkg in optional.items():
        try:
            __import__(mod); ok(f"{pkg} (optional)")
        except ImportError:
            warn(f"{pkg} not installed (optional)")
    if not all_ok:
        err("Install missing packages: pip install -r requirements.txt")
        sys.exit(1)
    ok("All required dependencies OK!")


# ═══════════════════════════════════════════════════════════════════════════════
#  STEP 1 — FOLDER SETUP
# ═══════════════════════════════════════════════════════════════════════════════
def setup_folders():
    section("Step 1 — Setting Up Project Folders")
    for folder in ["models","logs","results","static/css","static/js"]:
        path = os.path.join(BASE_DIR, folder)
        os.makedirs(path, exist_ok=True)
        ok(f"Ready: {folder}/")


# ═══════════════════════════════════════════════════════════════════════════════
#  STEP 2 — TRAIN MODEL
# ═══════════════════════════════════════════════════════════════════════════════
def train_model():
    section("Step 2 — Training ML Anomaly Detection Model")
    info("Algorithm  : Isolation Forest (Unsupervised)")
    info("Samples    : 5,000 synthetic normal traffic vectors")
    try:
        from src.anomaly_detector import AnomalyDetector
        AnomalyDetector().train_on_synthetic()
        ok("Model saved → models/anomaly_model.pkl")
    except Exception as e:
        err(f"Training failed: {e}"); return False
    try:
        from src.anomaly_detector_v2 import AnomalyDetectorV2
        AnomalyDetectorV2().train_on_synthetic()
        ok("Enhanced model saved → models/anomaly_model_v2.pkl")
    except Exception as e:
        warn(f"Enhanced model skipped: {e}")
    return True


# ═══════════════════════════════════════════════════════════════════════════════
#  STEP 3 — TRAIN / TEST EVALUATION
# ═══════════════════════════════════════════════════════════════════════════════
def run_evaluation():
    section("Step 3 — Train / Test Evaluation  (Upgrade 1)")
    info("Test set   : 1,000 normal  +  500 attack samples")
    info("Metrics    : Accuracy, Precision, Recall, F1, FPR")
    info("Charts     : Confusion matrix, metrics bar, score dist, per-attack")
    try:
        import train_test
        m = train_test.main()
        print(f"\n{C.BOLD}  Final Metrics:{C.RESET}")
        for label, key in [("Accuracy","accuracy"),("Precision","precision"),
                            ("Recall","recall"),("F1 Score","f1_score")]:
            print(f"  {label:<12}: {C.GREEN}{m[key]}%{C.RESET}")
        ok("4 charts saved → results/")
        return True
    except Exception as e:
        err(f"Evaluation failed: {e}"); return False


# ═══════════════════════════════════════════════════════════════════════════════
#  STEP 4 — ALGORITHM COMPARISON
# ═══════════════════════════════════════════════════════════════════════════════
def run_comparison():
    section("Step 4 — ML Algorithm Comparison  (Upgrade 2)")
    info("Models     : Isolation Forest vs One-Class SVM vs LOF")
    info("Charts     : Bar comparison, Radar chart, Speed comparison")
    try:
        import model_compare
        results = model_compare.main()
        best = max(results, key=lambda x: x['f1_score'])
        ok(f"Best: {best['name']}  (F1={best['f1_score']}%)")
        ok("3 charts saved → results/")
        return True
    except Exception as e:
        err(f"Comparison failed: {e}"); return False


# ═══════════════════════════════════════════════════════════════════════════════
#  STEP 5 — FEATURE IMPORTANCE
# ═══════════════════════════════════════════════════════════════════════════════
def run_feature_importance():
    section("Step 5 — Feature Importance Analysis  (Upgrade 3)")
    info("Method     : Permutation-based importance")
    info("Features   : 12 features ranked by contribution")
    try:
        from src.anomaly_detector_v2 import AnomalyDetectorV2
        d = AnomalyDetectorV2()
        if d.model is None:
            info("Training v2 model first …"); d.train_on_synthetic()
        d.print_importance_table()
        d.plot_feature_importance()
        ok("Chart saved → results/feature_importance.png")
        return True
    except Exception as e:
        err(f"Feature importance failed: {e}"); return False


# ═══════════════════════════════════════════════════════════════════════════════
#  STEP 6 — QUICK DEMO
# ═══════════════════════════════════════════════════════════════════════════════
def run_demo():
    section("Step 6 — Quick Demo  (200 Simulated Packets)")
    info("Scenarios  : Normal HTTP + Port Scan + Brute Force + ICMP Flood + DDoS")
    info("Engines    : Rule-based + ML Anomaly Detection")
    info("Watch the colour-coded alerts:\n")
    try:
        import demo; demo.main(); return True
    except Exception as e:
        err(f"Demo failed: {e}"); return False


# ═══════════════════════════════════════════════════════════════════════════════
#  STEP 7 — LIVE SYSTEM + DASHBOARD
# ═══════════════════════════════════════════════════════════════════════════════
def run_live(port=5000):
    section("Step 7 — Live System + Dashboard")
    info("Mode       : SIMULATION (no root / Scapy needed)")
    info(f"Dashboard  : http://127.0.0.1:{port}")
    info("Press Ctrl+C to stop\n")
    try:
        from src.packet_capture    import PacketCaptureEngine
        from src.feature_extractor import FeatureExtractor
        from src.rule_engine       import RuleEngine
        from src.anomaly_detector  import AnomalyDetector
        from src.alert_system      import AlertSystem
        from src.logger            import Logger
        from src.dashboard         import run_dashboard

        pkt_q      = queue.Queue(maxsize=1000)
        alert_list = []
        alert_lock = threading.Lock()

        extractor   = FeatureExtractor()
        rule_eng    = RuleEngine()
        anomaly_det = AnomalyDetector()
        alert_sys   = AlertSystem()
        logger      = Logger()

        def worker():
            while True:
                try:
                    features = pkt_q.get(timeout=1)
                except queue.Empty:
                    continue
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
                pkt_q.task_done()

        threading.Thread(target=worker, daemon=True).start()
        threading.Thread(target=run_dashboard,
                         args=(alert_list, alert_lock, port),
                         daemon=True).start()

        ok(f"Dashboard → http://127.0.0.1:{port}")
        ok("Detection worker → running")

        PacketCaptureEngine(
            interface="eth0", packet_queue=pkt_q,
            extractor=extractor, simulate=True
        ).start()

    except KeyboardInterrupt:
        warn("System stopped by user.")
        try: logger.close()
        except: pass
    except Exception as e:
        err(f"Live system error: {e}")


# ═══════════════════════════════════════════════════════════════════════════════
#  RUN EVERYTHING
# ═══════════════════════════════════════════════════════════════════════════════
def run_all():
    check_dependencies()
    setup_folders()
    train_model()
    run_evaluation()
    run_comparison()
    run_feature_importance()
    run_demo()
    section("  ALL STEPS COMPLETE!")
    ok("Charts  → results/")
    ok("Database→ logs/nids.db")
    ok("Models  → models/")
    info("Run  python run.py --live  to launch the live dashboard")


# ═══════════════════════════════════════════════════════════════════════════════
#  INTERACTIVE MENU
# ═══════════════════════════════════════════════════════════════════════════════
def show_menu():
    print(f"""
{C.BOLD}  Choose what to run:{C.RESET}

  {C.CYAN}[1]{C.RESET}  Quick Demo           — 200 packets, live colour alerts
  {C.CYAN}[2]{C.RESET}  Train ML Model       — Isolation Forest training
  {C.CYAN}[3]{C.RESET}  Evaluate Model       — Metrics + 4 charts
  {C.CYAN}[4]{C.RESET}  Compare Algorithms   — IF vs SVM vs LOF + 3 charts
  {C.CYAN}[5]{C.RESET}  Feature Importance   — Which features matter most
  {C.CYAN}[6]{C.RESET}  Live System          — Full NIDS + dashboard
  {C.CYAN}[7]{C.RESET}  Run Everything       — All steps in sequence (~2 min)
  {C.CYAN}[0]{C.RESET}  Exit
""")
    return input(f"  {C.BOLD}Enter choice [0-7]: {C.RESET}").strip()


# ═══════════════════════════════════════════════════════════════════════════════
#  MAIN
# ═══════════════════════════════════════════════════════════════════════════════
def main():
    parser = argparse.ArgumentParser(description="Hybrid AI-Enhanced NIDS — Master Runner")
    parser.add_argument("--demo",      action="store_true")
    parser.add_argument("--train",     action="store_true")
    parser.add_argument("--evaluate",  action="store_true")
    parser.add_argument("--compare",   action="store_true")
    parser.add_argument("--features",  action="store_true")
    parser.add_argument("--live",      action="store_true")
    parser.add_argument("--all",       action="store_true")
    parser.add_argument("--port", type=int, default=5000)
    args = parser.parse_args()

    banner()

    if args.all:      run_all();                                     return
    if args.demo:     check_dependencies(); setup_folders(); train_model(); run_demo();             return
    if args.train:    check_dependencies(); setup_folders(); train_model();                         return
    if args.evaluate: check_dependencies(); setup_folders(); train_model(); run_evaluation();       return
    if args.compare:  check_dependencies(); setup_folders(); run_comparison();                      return
    if args.features: check_dependencies(); setup_folders(); run_feature_importance();              return
    if args.live:     check_dependencies(); setup_folders(); train_model(); run_live(args.port);    return

    # Interactive menu
    check_dependencies()
    setup_folders()
    while True:
        choice = show_menu()
        if   choice == "1": run_demo()
        elif choice == "2": train_model()
        elif choice == "3": run_evaluation()
        elif choice == "4": run_comparison()
        elif choice == "5": run_feature_importance()
        elif choice == "6": run_live(args.port)
        elif choice == "7": run_all()
        elif choice == "0":
            print(f"\n{C.GREEN}  Thank you! {C.RESET}\n"); break
        else:
            warn("Enter 0-7")
        input(f"\n  {C.BOLD}Press Enter to return to menu …{C.RESET}")

if __name__ == "__main__":
    main()
