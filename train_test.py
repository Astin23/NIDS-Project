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
