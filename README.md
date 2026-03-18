#  NIDS-Project

## Hybrid AI-Enhanced Network Intrusion Detection System

---

##  Overview

The **Hybrid AI-Enhanced Network Intrusion Detection System (NIDS)** is a cybersecurity project designed to monitor network traffic in real time and detect malicious activities using a combination of:

*  Rule-Based Detection (Signature Matching)
*  AI-Based Anomaly Detection (Machine Learning)

This hybrid approach allows the system to detect both **known attacks** and **unknown (zero-day) threats**, making it more effective than traditional IDS systems.

---

##  Features

*  Real-time packet capture using **Scapy**
*  Machine Learning-based anomaly detection (Isolation Forest)
*  Rule-based detection for common attacks:

  * Port Scanning
  * Brute Force Login
  * Suspicious Port Access
  * ICMP Flood
  * DDoS Behavior
*  Real-time alert generation with severity levels
*  Logging system using **SQLite / CSV**
*  Web dashboard using **Flask + Chart.js**
*  Visualization of network activity and attack patterns

---

##  System Architecture

The system follows a layered architecture:

1. **Data Collection Layer**

   * Packet capture
   * Flow monitoring

2. **Preprocessing Layer**

   * Feature extraction
   * Data normalization

3. **Detection Layer**

   * Rule-based detection
   * AI anomaly detection

4. **Decision & Alert Layer**

   * Threat classification
   * Severity scoring
   * Logging

5. **Visualization Layer**

   * Dashboard for monitoring

---

##  Tech Stack

| Technology            | Purpose          |
| --------------------- | ---------------- |
| Python                | Core development |
| Scapy                 | Packet sniffing  |
| Scikit-learn          | Machine learning |
| Flask                 | Web dashboard    |
| SQLite                | Logging database |
| Matplotlib / Chart.js | Visualization    |

---

##  Project Structure

```
NIDS_Project/
│
├── main.py
├── requirements.txt
│
├── src/
│   ├── packet_capture.py
│   ├── feature_extractor.py
│   ├── rule_engine.py
│   ├── anomaly_detector.py
│   ├── alert_system.py
│   ├── logger.py
│   └── dashboard.py
│
├── models/
├── logs/
└── static/
```

---

##  Installation

### 1️ Clone the Repository

```
git clone https://github.com/your-username/NIDS-Project.git
cd NIDS-Project
```

### 2️ Create Virtual Environment (Recommended)

```
python -m venv venv
venv\Scripts\activate   # Windows
```

### 3️ Install Dependencies

```
pip install -r requirements.txt
```

---

##  Usage

### Run in Simulation Mode

```
python main.py --simulate --train
```

### Run Dashboard

```
python main.py
```


##  Sample Output

```
[ALERT] Port Scan Detected
Source IP: 192.168.1.5
Severity: HIGH
```

---

##  Future Enhancements

* Deep Learning-based detection (LSTM, Autoencoders)
* Integration with SIEM tools (Splunk, ELK)
* Automated attack blocking (Firewall integration)
* Distributed IDS architecture
* Threat intelligence integration

---


##  License

This project is for educational and research purposes.

---

 If you found this project useful, consider giving it a star!
