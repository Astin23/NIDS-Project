"""
  train_test.py — Upgrade 1
  Proper Train / Test Evaluation with Metrics
  Shows: Confusion Matrix, Precision, Recall, F1, Accuracy
  Run: python train_test.py
"""
 
import os
import sys
import numpy as np
import matplotlib
matplotlib.use('Agg')   # non-interactive backend for saving figures
import matplotlib.pyplot as plt
import matplotlib.patches as mpatches
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import (
    precision_score, recall_score, f1_score,
    accuracy_score, confusion_matrix
)
 
sys.path.insert(0, os.path.dirname(__file__))
 
RESULTS_DIR = os.path.join(os.path.dirname(__file__), "results")
os.makedirs(RESULTS_DIR, exist_ok=True)
 
# ── Colour palette for plots ───────────────────────────────────────────────────
NAVY   = "#1B3A6B"
BLUE   = "#2E75B6"
RED    = "#C00000"
GREEN  = "#375623"
ORANGE = "#E36C09"
GRAY   = "#D9D9D9"
 
# ═══════════════════════════════════════════════════════════════════════════════
#  DATA GENERATION
# ═══════════════════════════════════════════════════════════════════════════════
 
def generate_normal_traffic(n=5000, seed=42):
    """
    Generates synthetic NORMAL traffic feature vectors.
    12 features matching FeatureExtractor.get_ml_vector() order:
    packet_size, protocol_num, destination_port, packet_rate,
    connection_attempts, icmp_count, avg_packet_size,
    syn, ack, fin, rst, psh
    """
    rng = np.random.default_rng(seed)
    rows = []
    for _ in range(n):
        proto    = rng.choice([0, 1], p=[0.8, 0.2])
        dst_port = int(rng.choice([80, 443, 8080, 53], p=[0.4,0.4,0.1,0.1]))
        pkt_size = int(np.clip(rng.normal(500, 300), 64, 1500))
        rate     = float(np.clip(rng.exponential(5), 0.1, 30))
        conn     = int(rng.integers(1, 5))
        icmp     = 0
        avg_sz   = float(np.clip(rng.normal(500, 100), 64, 1500))
        syn      = int(rng.random() < 0.3)
        ack      = int(rng.random() < 0.6)
        fin      = int(rng.random() < 0.1)
        rst      = int(rng.random() < 0.05)
        psh      = int(rng.random() < 0.4)
        rows.append([pkt_size, proto, dst_port, rate, conn,
                     icmp, avg_sz, syn, ack, fin, rst, psh])
    return np.array(rows, dtype=float)
 
 
def generate_attack_traffic(n=500, seed=99):
    """
    Generates synthetic ATTACK traffic for testing.
    Simulates 5 attack types with anomalous feature patterns.
    """
    rng  = np.random.default_rng(seed)
    rows = []
    labels = []   # attack type name for each sample
 
    per_attack = n // 5
 
    # ── Port Scan: many unique ports, SYN only, tiny packets ─────────────────
    for _ in range(per_attack):
        rows.append([
            int(rng.integers(40, 80)),           # tiny SYN packet
            0,                                    # TCP
            int(rng.integers(1, 1024)),           # scanning low ports
            float(rng.uniform(20, 60)),           # moderate rate
            int(rng.integers(50, 200)),           # MANY unique ports
            0, 60, 1, 0, 0, 0, 0                 # SYN only
        ])
        labels.append("Port Scan")
 
    # ── Brute Force: high rate to single port, SYN flood ─────────────────────
    for _ in range(per_attack):
        rows.append([
            int(rng.integers(40, 120)),
            0,                                    # TCP
            22,                                   # SSH port
            float(rng.uniform(50, 150)),          # very high rate
            1,                                    # single port only
            0,
            int(np.clip(rng.normal(80, 20), 40,200)),
            1, 0, 0, 0, 0                         # SYN only
        ])
        labels.append("Brute Force")
 
    # ── ICMP Flood: massive ICMP count, large packets ─────────────────────────
    for _ in range(per_attack):
        rows.append([
            int(rng.integers(1000, 65535)),       # huge packet
            2,                                    # ICMP
            0,
            float(rng.uniform(80, 200)),          # very high rate
            0,
            int(rng.integers(100, 500)),          # massive ICMP count
            int(rng.integers(1000, 65535)),
            0, 0, 0, 0, 0
        ])
        labels.append("ICMP Flood")
 
    # ── DDoS: extremely high packet rate ─────────────────────────────────────
    for _ in range(per_attack):
        rows.append([
            int(rng.integers(100, 1500)),
            0,
            int(rng.choice([80, 443])),
            float(rng.uniform(200, 500)),         # extreme rate
            int(rng.integers(1, 3)),
            0,
            float(np.clip(rng.normal(800, 200), 100,1500)),
            1, 0, 0, 1, 0                         # SYN + RST
        ])
        labels.append("DDoS")
 
    # ── Unknown Anomaly: weird protocol + size combination ───────────────────
    for _ in range(per_attack):
        rows.append([
            int(rng.integers(50000, 65535)),      # abnormally huge
            3,                                    # OTHER protocol
            int(rng.integers(10000, 60000)),      # unusual port
            float(rng.uniform(0.001, 0.01)),      # very slow (covert)
            int(rng.integers(200, 500)),
            0,
            int(rng.integers(50000, 65535)),
            0, 1, 1, 1, 1                         # unusual flag combo
        ])
        labels.append("Unknown Anomaly")
 
    return np.array(rows, dtype=float), labels
 
 
# ═══════════════════════════════════════════════════════════════════════════════
#  TRAINING
# ═══════════════════════════════════════════════════════════════════════════════
 
def train_model(X_train):
    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(X_train)
    model = IsolationForest(
        n_estimators=100,
        contamination=0.05,
        random_state=42,
        n_jobs=-1
    )
    model.fit(X_scaled)
    return model, scaler
 
 
# ═══════════════════════════════════════════════════════════════════════════════
#  EVALUATION
# ═══════════════════════════════════════════════════════════════════════════════
 
def evaluate(model, scaler, X_normal_test, X_attack_test):
    """
    Build combined test set, predict, compute all metrics.
    Returns y_true, y_pred, scores
    """
    X_test  = np.vstack([X_normal_test, X_attack_test])
    y_true  = np.array([1]*len(X_normal_test) + [-1]*len(X_attack_test))
 
    X_scaled   = scaler.transform(X_test)
    y_pred     = model.predict(X_scaled)       # 1=normal, -1=anomaly
    scores     = model.score_samples(X_scaled) # anomaly scores
 
    return y_true, y_pred, scores
 
 
def compute_metrics(y_true, y_pred):
    # sklearn uses 1=positive class; our anomaly=-1
    # Flip so anomaly=1 (positive) for standard metrics
    yt = (y_true  == -1).astype(int)
    yp = (y_pred  == -1).astype(int)
 
    cm        = confusion_matrix(yt, yp)
    acc       = accuracy_score(yt, yp)
    prec      = precision_score(yt, yp, zero_division=0)
    rec       = recall_score(yt, yp, zero_division=0)
    f1        = f1_score(yt, yp, zero_division=0)
 
    tn, fp, fn, tp = cm.ravel()
    fpr = fp / (fp + tn) if (fp + tn) > 0 else 0
 
    return {
        "accuracy"   : round(acc  * 100, 2),
        "precision"  : round(prec * 100, 2),
        "recall"     : round(rec  * 100, 2),
        "f1_score"   : round(f1   * 100, 2),
        "fpr"        : round(fpr  * 100, 2),
        "tp"         : int(tp),
        "fp"         : int(fp),
        "tn"         : int(tn),
        "fn"         : int(fn),
        "cm"         : cm,
    }
 
 
# ═══════════════════════════════════════════════════════════════════════════════
#  PLOTS
# ═══════════════════════════════════════════════════════════════════════════════
 
def plot_confusion_matrix(cm, path):
    fig, ax = plt.subplots(figsize=(6, 5))
    fig.patch.set_facecolor("#F8F9FA")
    ax.set_facecolor("#F8F9FA")
 
    im = ax.imshow(cm, interpolation='nearest', cmap='Blues')
    plt.colorbar(im, ax=ax)
 
    classes = ['Normal', 'Attack']
    tick_marks = [0, 1]
    ax.set_xticks(tick_marks); ax.set_xticklabels(classes, fontsize=12)
    ax.set_yticks(tick_marks); ax.set_yticklabels(classes, fontsize=12)
 
    thresh = cm.max() / 2.0
    for i in range(2):
        for j in range(2):
            ax.text(j, i, format(cm[i, j], 'd'),
                    ha="center", va="center", fontsize=16, fontweight='bold',
                    color="white" if cm[i, j] > thresh else "black")
 
    ax.set_ylabel('Actual Label', fontsize=12, fontweight='bold')
    ax.set_xlabel('Predicted Label', fontsize=12, fontweight='bold')
    ax.set_title('Confusion Matrix — Isolation Forest', fontsize=14,
                 fontweight='bold', color=NAVY, pad=15)
    plt.tight_layout()
    plt.savefig(path, dpi=150, bbox_inches='tight')
    plt.close()
    print(f"  Saved: {path}")
 
 
def plot_metrics_bar(metrics, path):
    labels = ['Accuracy', 'Precision', 'Recall', 'F1 Score']
    values = [metrics['accuracy'], metrics['precision'],
              metrics['recall'],   metrics['f1_score']]
    colors = [NAVY, BLUE, GREEN, ORANGE]
 
    fig, ax = plt.subplots(figsize=(8, 5))
    fig.patch.set_facecolor("#F8F9FA")
    ax.set_facecolor("#F8F9FA")
 
    bars = ax.bar(labels, values, color=colors, width=0.5,
                  edgecolor='white', linewidth=1.5)
 
    for bar, val in zip(bars, values):
        ax.text(bar.get_x() + bar.get_width()/2, bar.get_height() + 0.5,
                f'{val:.1f}%', ha='center', va='bottom',
                fontsize=13, fontweight='bold', color='#333333')
 
    ax.set_ylim(0, 110)
    ax.set_ylabel('Score (%)', fontsize=12, fontweight='bold')
    ax.set_title('Model Performance Metrics — Isolation Forest',
                 fontsize=14, fontweight='bold', color=NAVY, pad=15)
    ax.axhline(y=90, color='red', linestyle='--', linewidth=1,
               alpha=0.5, label='90% threshold')
    ax.legend(fontsize=10)
    ax.grid(axis='y', alpha=0.3)
    ax.spines['top'].set_visible(False)
    ax.spines['right'].set_visible(False)
    plt.tight_layout()
    plt.savefig(path, dpi=150, bbox_inches='tight')
    plt.close()
    print(f"  Saved: {path}")
 
 
def plot_anomaly_scores(scores_normal, scores_attack, path):
    fig, ax = plt.subplots(figsize=(10, 5))
    fig.patch.set_facecolor("#F8F9FA")
    ax.set_facecolor("#F8F9FA")
 
    ax.hist(scores_normal, bins=40, alpha=0.7, color=BLUE,
            label='Normal Traffic', edgecolor='white')
    ax.hist(scores_attack, bins=40, alpha=0.7, color=RED,
            label='Attack Traffic', edgecolor='white')
 
    ax.axvline(x=-0.1, color='orange', linestyle='--',
               linewidth=2, label='Decision Threshold')
    ax.set_xlabel('Anomaly Score', fontsize=12, fontweight='bold')
    ax.set_ylabel('Number of Packets', fontsize=12, fontweight='bold')
    ax.set_title('Anomaly Score Distribution — Normal vs Attack Traffic',
                 fontsize=14, fontweight='bold', color=NAVY, pad=15)
    ax.legend(fontsize=11)
    ax.grid(alpha=0.3)
    ax.spines['top'].set_visible(False)
    ax.spines['right'].set_visible(False)
    plt.tight_layout()
    plt.savefig(path, dpi=150, bbox_inches='tight')
    plt.close()
    print(f"  Saved: {path}")
 
 
def plot_per_attack_detection(attack_labels, y_pred_attack, path):
    """Shows detection rate per attack type."""
    from collections import defaultdict
    attack_types = list(set(attack_labels))
    detected     = defaultdict(int)
    total        = defaultdict(int)
 
    for label, pred in zip(attack_labels, y_pred_attack):
        total[label] += 1
        if pred == -1:       # correctly detected as anomaly
            detected[label] += 1
 
    rates  = [detected[t]/total[t]*100 for t in attack_types]
    colors = [NAVY, BLUE, GREEN, ORANGE, RED]
 
    fig, ax = plt.subplots(figsize=(10, 5))
    fig.patch.set_facecolor("#F8F9FA")
    ax.set_facecolor("#F8F9FA")
 
    bars = ax.bar(attack_types, rates, color=colors[:len(attack_types)],
                  width=0.5, edgecolor='white', linewidth=1.5)
 
    for bar, rate in zip(bars, rates):
        ax.text(bar.get_x() + bar.get_width()/2, bar.get_height() + 0.5,
                f'{rate:.1f}%', ha='center', va='bottom',
                fontsize=12, fontweight='bold')
 
    ax.set_ylim(0, 115)
    ax.set_ylabel('Detection Rate (%)', fontsize=12, fontweight='bold')
    ax.set_title('Attack Detection Rate by Attack Type',
                 fontsize=14, fontweight='bold', color=NAVY, pad=15)
    ax.axhline(y=80, color='red', linestyle='--',
               linewidth=1, alpha=0.5, label='80% target')
    ax.legend(fontsize=10)
    ax.grid(axis='y', alpha=0.3)
    ax.spines['top'].set_visible(False)
    ax.spines['right'].set_visible(False)
    plt.tight_layout()
    plt.savefig(path, dpi=150, bbox_inches='tight')
    plt.close()
    print(f"  Saved: {path}")
 
 
# ═══════════════════════════════════════════════════════════════════════════════
#  MAIN
# ═══════════════════════════════════════════════════════════════════════════════
 
def main():
    print("=" * 60)
    print("  NIDS — Train / Test Evaluation  (Upgrade 1)")
    print("=" * 60)
 
    # ── 1. Generate data ───────────────────────────────────────────────────────
    print("\n[1/5] Generating training data (5000 normal samples) …")
    X_all_normal   = generate_normal_traffic(n=6000, seed=42)
    X_train        = X_all_normal[:5000]     # 5000 for training
    X_normal_test  = X_all_normal[5000:]     # 1000 for testing
 
    print("[1/5] Generating attack test data (500 attack samples) …")
    X_attack_test, attack_labels = generate_attack_traffic(n=500, seed=99)
 
    print(f"  Training  : {len(X_train)} normal samples")
    print(f"  Test Normal: {len(X_normal_test)} samples")
    print(f"  Test Attack: {len(X_attack_test)} samples")
    print(f"  Attack types: {set(attack_labels)}")
 
    # ── 2. Train ───────────────────────────────────────────────────────────────
    print("\n[2/5] Training Isolation Forest …")
    model, scaler = train_model(X_train)
    print("  Training complete!")
 
    # ── 3. Evaluate ───────────────────────────────────────────────────────────
    print("\n[3/5] Evaluating on test set …")
    y_true, y_pred, scores = evaluate(model, scaler, X_normal_test, X_attack_test)
    metrics = compute_metrics(y_true, y_pred)
 
    # Separate scores for plotting
    n_normal = len(X_normal_test)
    scores_normal = scores[:n_normal]
    scores_attack = scores[n_normal:]
 
    # Predictions on attack samples only (for per-type chart)
    X_attack_scaled = scaler.transform(X_attack_test)
    y_pred_attack   = model.predict(X_attack_scaled)
 
    # ── 4. Print results ───────────────────────────────────────────────────────
    print("\n[4/5] Results:")
    print("─" * 50)
    print(f"  True Positives  (Attacks detected)   : {metrics['tp']}")
    print(f"  False Positives (Normal flagged)      : {metrics['fp']}")
    print(f"  True Negatives  (Normal passed)       : {metrics['tn']}")
    print(f"  False Negatives (Attacks missed)      : {metrics['fn']}")
    print("─" * 50)
    print(f"  Accuracy   : {metrics['accuracy']}%")
    print(f"  Precision  : {metrics['precision']}%")
    print(f"  Recall     : {metrics['recall']}%")
    print(f"  F1 Score   : {metrics['f1_score']}%")
    print(f"  False +ve Rate: {metrics['fpr']}%")
    print("─" * 50)
 
    # ── 5. Save plots ──────────────────────────────────────────────────────────
    print("\n[5/5] Saving evaluation plots …")
    plot_confusion_matrix(
        metrics['cm'],
        os.path.join(RESULTS_DIR, "confusion_matrix.png")
    )
    plot_metrics_bar(
        metrics,
        os.path.join(RESULTS_DIR, "performance_metrics.png")
    )
    plot_anomaly_scores(
        scores_normal, scores_attack,
        os.path.join(RESULTS_DIR, "anomaly_score_distribution.png")
    )
    plot_per_attack_detection(
        attack_labels, y_pred_attack,
        os.path.join(RESULTS_DIR, "per_attack_detection_rate.png")
    )
 
    print(f"\n✅ All results saved to: {RESULTS_DIR}/")
    print("=" * 60)
    print("  Evaluation Complete!")
    print("=" * 60)
 
    return metrics
 
 
if __name__ == "__main__":
    main()
 
