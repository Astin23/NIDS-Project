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
