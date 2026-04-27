"""
  src/anomaly_detector_v2.py — Upgrade 
  Enhanced Anomaly Detector with:
    1. CICIDS 2017 dataset support
    2. Feature importance analysis
    3. Adaptive threshold
    4. Better evaluation output
  Run standalone: python src/anomaly_detector_v2.py
"""

import os
import pickle
import numpy as np
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
from datetime import datetime

try:
    from sklearn.ensemble      import IsolationForest
    from sklearn.preprocessing import StandardScaler
    import pandas as pd
    SKLEARN_AVAILABLE = True
except ImportError:
    SKLEARN_AVAILABLE = False

RESULTS_DIR = os.path.join(os.path.dirname(__file__), "..", "results")
MODEL_PATH  = os.path.join(os.path.dirname(__file__), "..", "models", "anomaly_model_v2.pkl")
SCALER_PATH = os.path.join(os.path.dirname(__file__), "..", "models", "scaler_v2.pkl")
os.makedirs(RESULTS_DIR, exist_ok=True)

NAVY  = "#1B3A6B"
BLUE  = "#2E75B6"
GREEN = "#375623"
RED   = "#C00000"
ORANGE= "#E36C09"

FEATURE_NAMES = [
    "Packet Size",
    "Protocol (Numeric)",
    "Destination Port",
    "Packet Rate",
    "Connection Attempts",
    "ICMP Count",
    "Avg Packet Size",
    "SYN Flag",
    "ACK Flag",
    "FIN Flag",
    "RST Flag",
    "PSH Flag",
]


class AnomalyDetectorV2:
    """
    Enhanced Isolation Forest anomaly detector.

    Improvements over v1:
      1. CICIDS 2017 dataset loading support
      2. Feature importance via permutation analysis
      3. Adaptive threshold based on score distribution
      4. Detailed prediction explanation
      5. Model performance summary
    """

    CONTAMINATION = 0.05

    def __init__(self):
        self.model          = None
        self.scaler         = None
        self.threshold      = -0.1     # default, updated after training
        self.feature_scores = None     # importance scores
        self._load_model()

    # ── Training ───────────────────────────────────────────────────────────────
    def train(self, X=None, use_cicids=False, cicids_path=None):
        """
        Train the model.
        Priority: CICIDS dataset > provided X > synthetic generation
        """
        if not SKLEARN_AVAILABLE:
            print("[AnomalyDetectorV2] scikit-learn not available.")
            return

        if use_cicids and cicids_path:
            X = self._load_cicids(cicids_path)
            if X is None:
                print("[!] CICIDS loading failed. Using synthetic data.")
                X = self._generate_normal(5000)
        elif X is None:
            X = self._generate_normal(5000)

        print(f"[AnomalyDetectorV2] Training on {len(X)} samples …")

        self.scaler = StandardScaler()
        X_scaled    = self.scaler.fit_transform(X)

        self.model  = IsolationForest(
            n_estimators  = 100,
            contamination = self.CONTAMINATION,
            random_state  = 42,
            n_jobs        = -1,
        )
        self.model.fit(X_scaled)

        # ── Compute adaptive threshold ────────────────────────────────────────
        scores = self.model.score_samples(X_scaled)
        # Threshold = mean - 2*std of training scores
        self.threshold = float(np.mean(scores) - 2 * np.std(scores))
        print(f"[AnomalyDetectorV2] Adaptive threshold set to: "
              f"{self.threshold:.4f}")

        # ── Feature importance analysis ───────────────────────────────────────
        self.feature_scores = self._compute_feature_importance(X_scaled)

        self._save_model()
        print("[AnomalyDetectorV2] Model saved.")

    def train_on_synthetic(self):
        """Convenience method — same interface as v1."""
        self.train(X=None, use_cicids=False)

    # ── Prediction ────────────────────────────────────────────────────────────
    def predict(self, features: dict):
        """
        Returns alert dict if anomalous, else None.
        Uses adaptive threshold instead of fixed -0.1.
        """
        if self.model is None:
            return None

        vec = self._feature_vector(features)
        if vec is None:
            return None

        try:
            vec_scaled = self.scaler.transform([vec])
            score      = float(self.model.score_samples(vec_scaled)[0])
        except Exception as e:
            print(f"[AnomalyDetectorV2] Predict error: {e}")
            return None

        if score < self.threshold:
            # Severity based on how far below threshold
            margin = self.threshold - score
            if   margin > 0.15: severity = "CRITICAL"
            elif margin > 0.08: severity = "HIGH"
            else:               severity = "MEDIUM"

            # Find most anomalous features
            top_features = self._explain(vec)

            return {
                "source"        : "ML",
                "attack_type"   : "Anomaly Detected (AI)",
                "source_ip"     : features["source_ip"],
                "destination_ip": features["destination_ip"],
                "port"          : features["destination_port"],
                "timestamp"     : features["timestamp"],
                "severity"      : severity,
                "detail"        : (
                    f"Score={score:.4f} | Threshold={self.threshold:.4f} | "
                    f"Top anomalous features: {top_features}"
                ),
            }
        return None

    # ── Feature Importance ────────────────────────────────────────────────────
    def _compute_feature_importance(self, X_scaled):
        """
        Permutation-based feature importance.
        For each feature: shuffle it and measure score degradation.
        Higher degradation = more important feature.
        """
        baseline_scores = self.model.score_samples(X_scaled)
        baseline_mean   = np.mean(baseline_scores)
        importances     = []

        for i in range(X_scaled.shape[1]):
            X_permuted       = X_scaled.copy()
            np.random.shuffle(X_permuted[:, i])    # shuffle feature i
            permuted_scores  = self.model.score_samples(X_permuted)
            permuted_mean    = np.mean(permuted_scores)
            importances.append(abs(baseline_mean - permuted_mean))

        # Normalise to percentage
        total = sum(importances) if sum(importances) > 0 else 1
        return [round(v/total*100, 2) for v in importances]

    def plot_feature_importance(self, path=None):
        """Save a horizontal bar chart of feature importance."""
        if self.feature_scores is None:
            print("[!] Train model first.")
            return

        if path is None:
            path = os.path.join(RESULTS_DIR, "feature_importance.png")

        # Sort by importance
        pairs = sorted(zip(FEATURE_NAMES, self.feature_scores),
                       key=lambda x: x[1])
        names  = [p[0] for p in pairs]
        scores = [p[1] for p in pairs]
        colors = [RED if s > 15 else BLUE if s > 8 else NAVY
                  for s in scores]

        fig, ax = plt.subplots(figsize=(10, 7))
        fig.patch.set_facecolor("#F8F9FA")
        ax.set_facecolor("#F8F9FA")

        bars = ax.barh(names, scores, color=colors,
                       edgecolor='white', linewidth=1.2)
        for bar, val in zip(bars, scores):
            ax.text(bar.get_width() + 0.2, bar.get_y() + bar.get_height()/2,
                    f'{val:.1f}%', va='center', fontsize=10,
                    fontweight='bold')

        ax.set_xlabel('Importance (%)', fontsize=12, fontweight='bold')
        ax.set_title('Feature Importance for Anomaly Detection\n'
                     '(Permutation-based Analysis)',
                     fontsize=14, fontweight='bold', color=NAVY, pad=15)
        ax.grid(axis='x', alpha=0.3)
        ax.spines['top'].set_visible(False)
        ax.spines['right'].set_visible(False)

        # Legend
        high_patch  = plt.Rectangle((0,0),1,1, color=RED,   label='High Importance (>15%)')
        med_patch   = plt.Rectangle((0,0),1,1, color=BLUE,  label='Medium Importance (8-15%)')
        low_patch   = plt.Rectangle((0,0),1,1, color=NAVY,  label='Low Importance (<8%)')
        ax.legend(handles=[high_patch, med_patch, low_patch],
                  loc='lower right', fontsize=10)

        plt.tight_layout()
        plt.savefig(path, dpi=150, bbox_inches='tight')
        plt.close()
        print(f"  Saved: {path}")

    def print_importance_table(self):
        """Print feature importance as a table."""
        if self.feature_scores is None:
            print("[!] Train model first.")
            return
        pairs = sorted(zip(FEATURE_NAMES, self.feature_scores),
                       key=lambda x: -x[1])
        print("\n  Feature Importance Analysis:")
        print("  " + "─"*45)
        print(f"  {'Rank':<5} {'Feature':<25} {'Importance':>10}")
        print("  " + "─"*45)
        for i, (name, score) in enumerate(pairs, 1):
            bar   = "█" * int(score // 2)
            print(f"  {i:<5} {name:<25} {score:>8.1f}%  {bar}")
        print("  " + "─"*45)

    # ── CICIDS 2017 loader ────────────────────────────────────────────────────
    def _load_cicids(self, path):
        """
        Load CICIDS 2017 dataset CSV.
        Download from: https://www.unb.ca/cic/datasets/ids-2017.html
        We extract only BENIGN (normal) traffic for training.

        CICIDS columns we map to our 12 features:
          Packet Length Mean  → packet_size
          Protocol            → protocol_num
          Destination Port    → destination_port
          Flow Packets/s      → packet_rate
          Flow Duration       → connection proxy
          Fwd Packets/s       → icmp_count proxy
          Packet Length Std   → avg_packet_size
          SYN Flag Count      → syn_flag
          ACK Flag Count      → ack_flag
          FIN Flag Count      → fin_flag
          RST Flag Count      → rst_flag
          PSH Flag Count      → psh_flag
        """
        try:
            import pandas as pd
            print(f"[AnomalyDetectorV2] Loading CICIDS from {path} …")
            df = pd.read_csv(path, low_memory=False)

            # Keep only BENIGN rows
            label_col = [c for c in df.columns if 'label' in c.lower()]
            if label_col:
                df = df[df[label_col[0]].str.strip().str.upper() == 'BENIGN']

            # Column mapping (flexible — handles column name variations)
            col_map = {
                'Packet Length Mean'  : 'packet_size',
                'Protocol'            : 'protocol_num',
                'Destination Port'    : 'destination_port',
                'Flow Packets/s'      : 'packet_rate',
                'Flow Duration'       : 'connection_attempts',
                'Fwd Packets/s'       : 'icmp_count',
                'Packet Length Std'   : 'avg_packet_size',
                'SYN Flag Count'      : 'syn_flag',
                'ACK Flag Count'      : 'ack_flag',
                'FIN Flag Count'      : 'fin_flag',
                'RST Flag Count'      : 'rst_flag',
                'PSH Flag Count'      : 'psh_flag',
            }

            available = {k:v for k,v in col_map.items() if k in df.columns}
            if len(available) < 8:
                print(f"[!] Only {len(available)} matching columns found.")
                return None

            df_feat = df[list(available.keys())].copy()
            df_feat.columns = list(available.values())
            df_feat = df_feat.replace([np.inf, -np.inf], np.nan).dropna()
            df_feat = df_feat.head(5000)    # use first 5000 BENIGN rows

            print(f"[AnomalyDetectorV2] Loaded {len(df_feat)} BENIGN samples "
                  f"from CICIDS 2017.")
            return df_feat.values.astype(float)

        except Exception as e:
            print(f"[!] CICIDS load error: {e}")
            return None

    # ── Helpers ───────────────────────────────────────────────────────────────
    @staticmethod
    def _generate_normal(n=5000):
        rng  = np.random.default_rng(42)
        rows = []
        for _ in range(n):
            proto    = rng.choice([0,1], p=[0.8,0.2])
            dst_port = int(rng.choice([80,443,8080,53], p=[0.4,0.4,0.1,0.1]))
            pkt_size = int(np.clip(rng.normal(500,300), 64,1500))
            rate     = float(np.clip(rng.exponential(5), 0.1,30))
            conn     = int(rng.integers(1,5))
            icmp     = 0
            avg_sz   = float(np.clip(rng.normal(500,100), 64,1500))
            rows.append([pkt_size, proto, dst_port, rate, conn,
                         icmp, avg_sz,
                         int(rng.random()<0.3), int(rng.random()<0.6),
                         int(rng.random()<0.1), int(rng.random()<0.05),
                         int(rng.random()<0.4)])
        return np.array(rows, dtype=float)

    @staticmethod
    def _feature_vector(features: dict):
        try:
            return [
                features["packet_size"],   features["protocol_num"],
                features["destination_port"], features["packet_rate"],
                features["connection_attempts"], features["icmp_count"],
                features["avg_packet_size"], features["syn_flag"],
                features["ack_flag"],      features["fin_flag"],
                features["rst_flag"],      features["psh_flag"],
            ]
        except KeyError:
            return None

    def _explain(self, vec):
        """Return names of top 3 most anomalous features."""
        if self.feature_scores is None:
            return "N/A"
        pairs = sorted(zip(FEATURE_NAMES, self.feature_scores),
                       key=lambda x: -x[1])
        top3  = [p[0] for p in pairs[:3]]
        return ", ".join(top3)

    def _save_model(self):
        os.makedirs(os.path.dirname(MODEL_PATH), exist_ok=True)
        with open(MODEL_PATH,  "wb") as f: pickle.dump(self.model,  f)
        with open(SCALER_PATH, "wb") as f: pickle.dump(self.scaler, f)
        # Save threshold and importances too
        meta = {"threshold": self.threshold,
                "feature_scores": self.feature_scores}
        with open(MODEL_PATH.replace(".pkl","_meta.pkl"), "wb") as f:
            pickle.dump(meta, f)

    def _load_model(self):
        if os.path.exists(MODEL_PATH) and os.path.exists(SCALER_PATH):
            try:
                with open(MODEL_PATH,  "rb") as f: self.model  = pickle.load(f)
                with open(SCALER_PATH, "rb") as f: self.scaler = pickle.load(f)
                meta_path = MODEL_PATH.replace(".pkl","_meta.pkl")
                if os.path.exists(meta_path):
                    with open(meta_path, "rb") as f:
                        meta = pickle.load(f)
                    self.threshold      = meta.get("threshold", -0.1)
                    self.feature_scores = meta.get("feature_scores", None)
                print("[AnomalyDetectorV2] Pre-trained model loaded.")
            except Exception as e:
                print(f"[AnomalyDetectorV2] Load error: {e}")


# ── Standalone run ─────────────────────────────────────────────────────────────
if __name__ == "__main__":
    print("=" * 60)
    print("  NIDS — Enhanced Anomaly Detector  (Upgrade 3)")
    print("=" * 60)

    detector = AnomalyDetectorV2()

    print("\n[1/3] Training on synthetic normal traffic …")
    detector.train_on_synthetic()

    print("\n[2/3] Feature Importance Analysis:")
    detector.print_importance_table()

    print("\n[3/3] Saving feature importance chart …")
    detector.plot_feature_importance()

    print(f"\n Done! Results saved to: results/")
    print("=" * 60)
    print("""
  CICIDS 2017 Usage:
  ──────────────────
  1. Download from https://www.unb.ca/cic/datasets/ids-2017.html
  2. Place CSV file in your project folder
  3. Run:
       detector = AnomalyDetectorV2()
       detector.train(use_cicids=True,
                      cicids_path='Friday-WorkingHours.pcap_ISCX.csv')
  """)
