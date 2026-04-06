"""
  Hybrid AI-Enhanced Network Intrusion Detection System
  main.py — Entry Point
  B.Tech Cybersecurity Project
  Purpose : Starts the packet capture, rule engine, ML
            anomaly detector, logger and dashboard together.
"""
 
import threading
import time
import argparse
import sys
 
from src.packet_capture   import PacketCaptureEngine
from src.feature_extractor import FeatureExtractor
from src.rule_engine      import RuleEngine

 
# ─── Shared state (thread-safe queue + shared lists) ──────────────────────────
import queue
 
packet_queue   = queue.Queue(maxsize=1000)   # Raw packet features flow here
alert_list     = []                          # Accumulated alerts for dashboard
alert_lock     = threading.Lock()

def main():
    parser = argparse.ArgumentParser(description="Hybrid AI-Enhanced NIDS")
    parser.add_argument("--interface", default="eth0",
                        help="Network interface to sniff (default: eth0)")
    parser.add_argument("--simulate", action="store_true",
                        help="Run with simulated traffic (no root needed)")
    parser.add_argument("--train",    action="store_true",
                        help="Train ML model on synthetic normal traffic first")
    parser.add_argument("--port",     type=int, default=5000,
                        help="Dashboard port (default: 5000)")
    args = parser.parse_args()
 
    print("=" * 60)
    print("  Hybrid AI-Enhanced NIDS  —  Starting Up")
    print("=" * 60)
