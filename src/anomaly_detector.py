"""
  src/anomaly_detector.py
  Module 4 — AI Anomaly Detection
  Uses scikit-learn Isolation Forest (primary) with a
  One-Class SVM fallback to detect unknown attack patterns
  by learning the "shape" of normal traffic.
"""

import os
import random
import pickle
import numpy as np
from datetime import datetime


MODEL_PATH = os.path.join(os.path.dirname(__file__),
                          "..", "models", "anomaly_model.pkl")
SCALER_PATH = os.path.join(os.path.dirname(__file__),
                           "..", "models", "scaler.pkl")

# ── Feature order (must match FeatureExtractor.get_ml_vector) ─────────────────
FEATURE_NAMES = [
    "packet_size", "protocol_num", "destination_port",
    "packet_rate", "connection_attempts", "icmp_count",
    "avg_packet_size", "syn_flag", "ack_flag",
    "fin_flag", "rst_flag", "psh_flag",
]


class AnomalyDetector:
    """
    Wraps an Isolation Forest model.

    Workflow:
      1. Call train_on_synthetic() once (or load pre-saved model).
      2. Call predict(features) per packet — returns an alert dict or None.

    Isolation Forest is ideal for NIDS because:
      • Unsupervised — no labelled attack data needed.
      • O(n log n) training, O(log n) prediction — fast enough for real-time.
      • Handles high-dimensional sparse feature spaces well.
      • Naturally detects anomalies as points that are "isolated" early
        in random recursive partitioning.
    """

    CONTAMINATION = 0.05    # Expected fraction of anomalies (5 %)

    def __init__(self):
        self.model      = None
        self.scaler     = None
        self._load_model()  # Try loading a previously saved model

    # ── Training ──────────────────────────────────────────────────────────────
    def train_on_synthetic(self):
        """
        Generates synthetic normal traffic samples and trains the
        Isolation Forest. In production you would replace this with
        real captured baseline traffic.
        """
        try:
            from sklearn.ensemble import IsolationForest
            from sklearn.preprocessing import StandardScaler
        except ImportError:
            print("[AnomalyDetector] scikit-learn not installed. "
                  "ML detection disabled.")
            return

        print("[AnomalyDetector] Generating synthetic training data …")
        X = self._generate_normal_traffic(n_samples=5000)

        # Normalise features so no single dimension dominates
        self.scaler = StandardScaler()
        X_scaled    = self.scaler.fit_transform(X)

        print("[AnomalyDetector] Fitting Isolation Forest …")
        self.model = IsolationForest(
            n_estimators  = 100,            # 100 trees
            contamination = self.CONTAMINATION,
            random_state  = 42,
            n_jobs        = -1,             # Use all CPU cores
        )
        self.model.fit(X_scaled)

        # Persist model to disk so next run skips training
        self._save_model()
        print("[AnomalyDetector] Model trained and saved.")

    # ── Prediction ────────────────────────────────────────────────────────────
    def predict(self, features: dict):
        """
        Returns an alert dict if the packet is anomalous, else None.
        The ML model returns -1 for anomalies and +1 for normal.
        """
        if self.model is None:
            return None     # ML not ready yet

        vec = self._feature_vector(features)
        if vec is None:
            return None

        try:
            vec_scaled = self.scaler.transform([vec])
            prediction = self.model.predict(vec_scaled)[0]  # -1 or +1
            score      = self.model.score_samples(vec_scaled)[0]
        except Exception as e:
            print(f"[AnomalyDetector] Prediction error: {e}")
            return None

        if prediction == -1:                # Anomaly detected
            # Score is negative log likelihood; more negative = more anomalous
            severity = "HIGH" if score < -0.15 else "MEDIUM"
            return {
                "source"        : "ML",
                "attack_type"   : "Anomaly Detected",
                "source_ip"     : features["source_ip"],
                "destination_ip": features["destination_ip"],
                "port"          : features["destination_port"],
                "timestamp"     : features["timestamp"],
                "severity"      : severity,
                "detail"        : (
                    f"Isolation Forest anomaly score: {score:.4f} | "
                    f"pkt_size={features['packet_size']} "
                    f"rate={features['packet_rate']:.2f} "
                    f"proto={features['protocol']}"
                ),
            }
        return None

    # ── Helpers ───────────────────────────────────────────────────────────────
    def _feature_vector(self, features: dict):
        """Extract the numeric ML feature vector from a features dict."""
        try:
            return [
                features["packet_size"],
                features["protocol_num"],
                features["destination_port"],
                features["packet_rate"],
                features["connection_attempts"],
                features["icmp_count"],
                features["avg_packet_size"],
                features["syn_flag"],
                features["ack_flag"],
                features["fin_flag"],
                features["rst_flag"],
                features["psh_flag"],
            ]
        except KeyError:
            return None

    @staticmethod
    def _generate_normal_traffic(n_samples: int) -> np.ndarray:
        """
        Synthesises realistic normal traffic feature vectors for training.
        Column order: packet_size, protocol_num, destination_port,
                      packet_rate, connection_attempts, icmp_count,
                      avg_packet_size, syn, ack, fin, rst, psh
        """
        rng  = np.random.default_rng(seed=42)
        rows = []
        for _ in range(n_samples):
            proto       = rng.choice([0, 1], p=[0.8, 0.2])   # TCP 80%, UDP 20%
            dst_port    = int(rng.choice([80, 443, 8080, 53], p=[0.4,0.4,0.1,0.1]))
            pkt_size    = int(np.clip(rng.normal(loc=500, scale=300), 64, 1500))
            rate        = float(np.clip(rng.exponential(scale=5), 0.1, 40))
            conn_att    = int(rng.integers(1, 5))
            icmp_cnt    = 0
            avg_size    = float(np.clip(rng.normal(loc=500, scale=100), 64, 1500))
            syn         = int(rng.random() < 0.3)
            ack         = int(rng.random() < 0.6)
            fin         = int(rng.random() < 0.1)
            rst         = int(rng.random() < 0.05)
            psh         = int(rng.random() < 0.4)
            rows.append([pkt_size, proto, dst_port, rate, conn_att,
                         icmp_cnt, avg_size, syn, ack, fin, rst, psh])
        return np.array(rows, dtype=float)

    def _save_model(self):
        os.makedirs(os.path.dirname(MODEL_PATH), exist_ok=True)
        with open(MODEL_PATH,  "wb") as f: pickle.dump(self.model,  f)
        with open(SCALER_PATH, "wb") as f: pickle.dump(self.scaler, f)

    def _load_model(self):
        if os.path.exists(MODEL_PATH) and os.path.exists(SCALER_PATH):
            try:
                with open(MODEL_PATH,  "rb") as f: self.model  = pickle.load(f)
                with open(SCALER_PATH, "rb") as f: self.scaler = pickle.load(f)
                print("[AnomalyDetector] Pre-trained model loaded from disk.")
            except Exception as e:
                 print(f"[AnomalyDetector] Could not load model: {e}")