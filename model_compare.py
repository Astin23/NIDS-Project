"""
============================================================
  model_compare.py — Upgrade 2
  Compare 3 Unsupervised ML Algorithms:
    1. Isolation Forest
    2. One-Class SVM
    3. Local Outlier Factor
  Shows side-by-side metrics + comparison chart
  Run: python model_compare.py
============================================================
"""
 
import os
import sys
import time
import numpy as np
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
from sklearn.ensemble        import IsolationForest
from sklearn.svm             import OneClassSVM
from sklearn.neighbors       import LocalOutlierFactor
from sklearn.preprocessing   import StandardScaler
from sklearn.metrics         import (
    precision_score, recall_score, f1_score, accuracy_score
)
 
