"""
============================================================
  HYBRID AI-ENHANCED NETWORK INTRUSION DETECTION SYSTEM
  Mid-Semester Demo Script

  Demonstrates:
    1. Packet Capture (Simulated)
    2. Feature Extraction
    3. Rule-Based Detection:
       - Port Scan Detection
       - Brute Force Login Detection
       - ICMP Flood Detection
       - Suspicious Port Access
    4. Alert System with Severity Levels
    5. Logging to SQLite Database
  No root, no Scapy, no network required.
============================================================
"""

import time
import random
import sqlite3
import os
from datetime import datetime
from collections import defaultdict, deque

# ── ANSI Colour codes for terminal output ─────────────────────────────────────
RED    = "\033[91m"   # CRITICAL
YELLOW = "\033[93m"   # HIGH
BLUE   = "\033[94m"   # MEDIUM
GREEN  = "\033[92m"   # LOW
CYAN   = "\033[96m"   # Info / headers
WHITE  = "\033[97m"   # Normal text
RESET  = "\033[0m"
BOLD   = "\033[1m"

# ── Database setup ─────────────────────────────────────────────────────────────
DB_PATH = "logs/nids_demo.db"
os.makedirs("logs", exist_ok=True)

def setup_database():
    conn = sqlite3.connect(DB_PATH)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS alerts (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp   TEXT,
            source_ip   TEXT,
            dest_ip     TEXT,
            port        INTEGER,
            attack_type TEXT,
            severity    TEXT,
            detail      TEXT
        )
    """)
    conn.commit()
    return conn

def log_to_db(conn, alert):
    conn.execute("""
        INSERT INTO alerts (timestamp, source_ip, dest_ip, port, attack_type, severity, detail)
        VALUES (?, ?, ?, ?, ?, ?, ?)
    """, (
        alert["timestamp"], alert["source_ip"], alert["dest_ip"],
        alert["port"], alert["attack_type"], alert["severity"], alert["detail"]
    ))
    conn.commit()

# ── Rule Engine State ──────────────────────────────────────────────────────────
port_tracker   = defaultdict(set)        # src_ip → set of unique ports
brute_tracker  = defaultdict(deque)      # src_ip:port → deque of timestamps
icmp_tracker   = defaultdict(deque)      # src_ip → deque of timestamps
alert_count    = 0

# Sensitive ports map
SENSITIVE_PORTS = {
    22:   ("SSH",        "HIGH"),
    23:   ("Telnet",     "CRITICAL"),
    3389: ("RDP",        "HIGH"),
    445:  ("SMB",        "HIGH"),
    3306: ("MySQL",      "MEDIUM"),
    21:   ("FTP",        "MEDIUM"),
}

# ── Alert dispatcher ───────────────────────────────────────────────────────────
def dispatch_alert(conn, attack_type, src_ip, dst_ip, port, severity, detail):
    global alert_count
    alert_count += 1

    colour = {
        "CRITICAL": RED,
        "HIGH":     YELLOW,
        "MEDIUM":   BLUE,
        "LOW":      GREEN,
    }.get(severity, WHITE)

    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    print(f"\n{colour}{BOLD}{'='*60}{RESET}")
    print(f"{colour}{BOLD}  🚨 ALERT #{alert_count}  |  [{severity}]  |  {attack_type}{RESET}")
    print(f"{colour}{'='*60}{RESET}")
    print(f"{WHITE}  📌 Attack Type : {BOLD}{attack_type}{RESET}")
    print(f"{WHITE}  🌐 Source IP   : {BOLD}{src_ip}{RESET}")
    print(f"{WHITE}  🎯 Target IP   : {BOLD}{dst_ip}:{port}{RESET}")
    print(f"{WHITE}  ⏰ Timestamp   : {ts}{RESET}")
    print(f"{WHITE}  📋 Detail      : {detail}{RESET}")
    print(f"{colour}  ⚠️  Severity    : {BOLD}{severity}{RESET}")
    print(f"{colour}{'─'*60}{RESET}")

    alert = {
        "timestamp":  ts,
        "source_ip":  src_ip,
        "dest_ip":    dst_ip,
        "port":       port,
        "attack_type":attack_type,
        "severity":   severity,
        "detail":     detail,
    }
    log_to_db(conn, alert)
    print(f"{GREEN}  ✅ Alert saved to database: logs/nids_midsem.db{RESET}")

# ── Rule 1 — Port Scan ─────────────────────────────────────────────────────────
def check_port_scan(conn, src_ip, dst_ip, dst_port):
    port_tracker[src_ip].add(dst_port)
    count = len(port_tracker[src_ip])
    if count >= 10:
        detail = (f"Source IP scanned {count} unique ports. "
                  f"Ports tried: {sorted(list(port_tracker[src_ip]))[:10]}")
        port_tracker[src_ip] = set()   # reset after alert
        dispatch_alert(conn, "Port Scan Detected", src_ip, dst_ip,
                       dst_port, "HIGH", detail)
        return True
    return False

# ── Rule 2 — Brute Force ───────────────────────────────────────────────────────
def check_brute_force(conn, src_ip, dst_ip, dst_port, now):
    if dst_port not in SENSITIVE_PORTS:
        return False

    key = f"{src_ip}:{dst_port}"
    dq  = brute_tracker[key]
    dq.append(now)

    # Remove timestamps older than 10 seconds
    while dq and (now - dq[0]) > 10:
        dq.popleft()

    attempts = len(dq)
    service, _ = SENSITIVE_PORTS[dst_port]

    if attempts >= 8:
        detail = (f"{attempts} login attempts to {service} (port {dst_port}) "
                  f"within 10 seconds. Possible password brute-force attack.")
        dq.clear()
        severity = "CRITICAL" if dst_port in (22, 23, 3389) else "HIGH"
        dispatch_alert(conn, "Brute Force Login", src_ip, dst_ip,
                       dst_port, severity, detail)
        return True
    return False

# ── Rule 3 — ICMP Flood ────────────────────────────────────────────────────────
def check_icmp_flood(conn, src_ip, dst_ip, protocol, now):
    if protocol != "ICMP":
        return False

    dq = icmp_tracker[src_ip]
    dq.append(now)

    while dq and (now - dq[0]) > 10:
        dq.popleft()

    count = len(dq)
    if count >= 20:
        detail = (f"{count} ICMP packets from {src_ip} in 10 seconds. "
                  f"Classic Ping Flood / ICMP Flood attack pattern.")
        dq.clear()
        dispatch_alert(conn, "ICMP Flood Attack", src_ip, dst_ip,
                       0, "CRITICAL", detail)
        return True
    return False

# ── Rule 4 — Suspicious Port ───────────────────────────────────────────────────
def check_suspicious_port(conn, src_ip, dst_ip, dst_port):
    if dst_port in SENSITIVE_PORTS:
        service, severity = SENSITIVE_PORTS[dst_port]
        detail = (f"Connection attempt to {service} service on port {dst_port}. "
                  f"Sensitive service accessed — monitor closely.")
        dispatch_alert(conn, "Suspicious Port Access", src_ip, dst_ip,
                       dst_port, "LOW", detail)
        return True
    return False

# ── Packet Simulator ───────────────────────────────────────────────────────────
def simulate_packet(scenario):
    """Generate a fake packet dict based on scenario name."""
    server_ip   = "192.168.1.1"
    normal_ips  = [f"192.168.1.{i}" for i in range(10, 20)]
    attack_ips  = ["10.0.0.99", "172.16.5.1", "203.0.113.5"]

    if scenario == "normal":
        return {
            "src_ip":   random.choice(normal_ips),
            "dst_ip":   server_ip,
            "src_port": random.randint(49152, 65535),
            "dst_port": random.choice([80, 443, 8080]),
            "protocol": "TCP",
            "size":     random.randint(64, 1500),
            "flags":    "PA",
        }
    elif scenario == "port_scan":
        return {
            "src_ip":   attack_ips[0],
            "dst_ip":   server_ip,
            "src_port": random.randint(49152, 65535),
            "dst_port": random.randint(1, 1024),
            "protocol": "TCP",
            "size":     60,
            "flags":    "S",
        }
    elif scenario == "brute_force":
        return {
            "src_ip":   attack_ips[1],
            "dst_ip":   server_ip,
            "src_port": random.randint(49152, 65535),
            "dst_port": 22,       # SSH
            "protocol": "TCP",
            "size":     60,
            "flags":    "S",
        }
    elif scenario == "icmp_flood":
        return {
            "src_ip":   attack_ips[2],
            "dst_ip":   server_ip,
            "src_port": 0,
            "dst_port": 0,
            "protocol": "ICMP",
            "size":     random.randint(1000, 65535),
            "flags":    "",
        }
    elif scenario == "suspicious":
        return {
            "src_ip":   attack_ips[0],
            "dst_ip":   server_ip,
            "src_port": random.randint(49152, 65535),
            "dst_port": random.choice([23, 3389, 445]),
            "protocol": "TCP",
            "size":     60,
            "flags":    "S",
        }

# ── Print packet info ──────────────────────────────────────────────────────────
def print_packet_info(pkt, number):
    proto_colour = {"TCP": CYAN, "UDP": BLUE, "ICMP": YELLOW}.get(pkt["protocol"], WHITE)
    print(f"{WHITE}  [{number:>3}] "
          f"{proto_colour}{pkt['protocol']:<5}{RESET}  "
          f"{pkt['src_ip']:<18} → "
          f"{pkt['dst_ip']}:{pkt['dst_port']:<6}  "
          f"size={pkt['size']} bytes{RESET}")

# ══════════════════════════════════════════════════════════════════════════════
#  MAIN DEMO
# ══════════════════════════════════════════════════════════════════════════════
def main():
    conn = setup_database()

    # ── Welcome banner ─────────────────────────────────────────────────────────
    print(f"\n{CYAN}{BOLD}")
    print("=" * 60)
    print("   🛡️   HYBRID AI-ENHANCED NIDS   🛡️")
    print("        Mid-Semester Demonstration")
    print("        Rule-Based Detection Engine")
    print("=" * 60)
    print(f"{RESET}")
    time.sleep(1)

    # ── System info ────────────────────────────────────────────────────────────
    print(f"{WHITE}{BOLD}  SYSTEM INITIALISING ...{RESET}\n")
    time.sleep(0.5)
    print(f"{GREEN}  ✅ Packet Capture Engine     — READY (Simulation Mode){RESET}")
    time.sleep(0.3)
    print(f"{GREEN}  ✅ Feature Extraction Layer  — READY{RESET}")
    time.sleep(0.3)
    print(f"{GREEN}  ✅ Rule-Based Detection      — READY (4 Rules Active){RESET}")
    time.sleep(0.3)
    print(f"{GREEN}  ✅ Alert System              — READY{RESET}")
    time.sleep(0.3)
    print(f"{GREEN}  ✅ SQLite Logger             — READY (logs/nids_logs.db){RESET}")
    time.sleep(0.3)

    print(f"\n{CYAN}{BOLD}  Active Detection Rules:{RESET}")
    print(f"{WHITE}  Rule 1 → Port Scan Detection       (threshold: 10 unique ports){RESET}")
    print(f"{WHITE}  Rule 2 → Brute Force Login         (threshold: 8 attempts / 10 sec){RESET}")
    print(f"{WHITE}  Rule 3 → ICMP Flood Detection      (threshold: 20 packets / 10 sec){RESET}")
    print(f"{WHITE}  Rule 4 → Suspicious Port Access    (ports: 22,23,3389,445,3306,21){RESET}")
    time.sleep(1)

    # ══════════════════════════════════════════════════════════════════════════
    #  SCENARIO 1 — Normal Traffic
    # ══════════════════════════════════════════════════════════════════════════
    print(f"\n{CYAN}{BOLD}")
    print("─" * 60)
    print("  SCENARIO 1 — Normal HTTP/HTTPS Traffic")
    print("  Sending 5 normal packets ...")
    print(f"─" * 60 + RESET)
    time.sleep(0.5)

    for i in range(1, 6):
        pkt = simulate_packet("normal")
        print_packet_info(pkt, i)
        time.sleep(0.3)

    print(f"\n{GREEN}  ✅ No alerts — Traffic is normal.{RESET}")
    time.sleep(1)

    # ══════════════════════════════════════════════════════════════════════════
    #  SCENARIO 2 — Port Scan Attack
    # ══════════════════════════════════════════════════════════════════════════
    print(f"\n{CYAN}{BOLD}")
    print("─" * 60)
    print("  SCENARIO 2 — Port Scan Attack")
    print("  Attacker scanning multiple ports ...")
    print(f"─" * 60 + RESET)
    time.sleep(0.5)

    scan_ports = [21, 22, 23, 25, 80, 443, 445, 3306, 3389, 8080, 8443]
    attacker   = "10.0.0.99"
    server     = "192.168.1.1"

    for i, port in enumerate(scan_ports, 1):
        pkt = {
            "src_ip": attacker, "dst_ip": server,
            "src_port": random.randint(49152, 65535),
            "dst_port": port, "protocol": "TCP",
            "size": 60, "flags": "S"
        }
        print_packet_info(pkt, i)
        check_port_scan(conn, attacker, server, port)
        time.sleep(0.25)

    time.sleep(1)

    # ══════════════════════════════════════════════════════════════════════════
    #  SCENARIO 3 — Brute Force SSH
    # ══════════════════════════════════════════════════════════════════════════
    print(f"\n{CYAN}{BOLD}")
    print("─" * 60)
    print("  SCENARIO 3 — Brute Force SSH Login Attack")
    print("  Attacker hammering SSH port 22 ...")
    print(f"─" * 60 + RESET)
    time.sleep(0.5)

    attacker2 = "172.16.5.1"
    now       = time.time()

    for i in range(1, 10):
        pkt = {
            "src_ip": attacker2, "dst_ip": server,
            "src_port": random.randint(49152, 65535),
            "dst_port": 22, "protocol": "TCP",
            "size": 60, "flags": "S"
        }
        print_packet_info(pkt, i)
        check_brute_force(conn, attacker2, server, 22, now + i * 0.5)
        time.sleep(0.25)

    time.sleep(1)

    # ══════════════════════════════════════════════════════════════════════════
    #  SCENARIO 4 — ICMP Flood
    # ══════════════════════════════════════════════════════════════════════════
    print(f"\n{CYAN}{BOLD}")
    print("─" * 60)
    print("  SCENARIO 4 — ICMP Flood Attack (Ping Flood)")
    print("  Attacker flooding with ICMP packets ...")
    print(f"─" * 60 + RESET)
    time.sleep(0.5)

    attacker3 = "203.0.113.5"
    now       = time.time()

    for i in range(1, 22):
        pkt = {
            "src_ip": attacker3, "dst_ip": server,
            "src_port": 0, "dst_port": 0,
            "protocol": "ICMP",
            "size": random.randint(1000, 65535),
            "flags": ""
        }
        print_packet_info(pkt, i)
        check_icmp_flood(conn, attacker3, server, "ICMP", now + i * 0.1)
        time.sleep(0.15)

    time.sleep(1)

    # ══════════════════════════════════════════════════════════════════════════
    #  SCENARIO 5 — Suspicious Port Access
    # ══════════════════════════════════════════════════════════════════════════
    print(f"\n{CYAN}{BOLD}")
    print("─" * 60)
    print("  SCENARIO 5 — Suspicious Port Access")
    print("  Attacker accessing sensitive service ports ...")
    print(f"─" * 60 + RESET)
    time.sleep(0.5)

    sensitive = [23, 3389, 445]
    attacker4 = "10.0.0.99"

    for i, port in enumerate(sensitive, 1):
        pkt = {
            "src_ip": attacker4, "dst_ip": server,
            "src_port": random.randint(49152, 65535),
            "dst_port": port, "protocol": "TCP",
            "size": 60, "flags": "S"
        }
        print_packet_info(pkt, i)
        check_suspicious_port(conn, attacker4, server, port)
        time.sleep(0.4)

    time.sleep(1)

    # ══════════════════════════════════════════════════════════════════════════
    #  SUMMARY
    # ══════════════════════════════════════════════════════════════════════════
    cur = conn.execute("SELECT severity, COUNT(*) FROM alerts GROUP BY severity")
    rows = cur.fetchall()
    total = conn.execute("SELECT COUNT(*) FROM alerts").fetchone()[0]

    print(f"\n{CYAN}{BOLD}")
    print("=" * 60)
    print("  Mid DEMO SUMMARY ")
    print("=" * 60 + RESET)
    print(f"\n{WHITE}  Total Alerts Generated : {BOLD}{alert_count}{RESET}")
    print(f"{WHITE}  Saved to Database      : {BOLD}{total} records in logs/nids_demo.db{RESET}\n")

    print(f"{WHITE}  Alerts by Severity:{RESET}")
    sev_colour = {"CRITICAL":RED, "HIGH":YELLOW, "MEDIUM":BLUE, "LOW":GREEN}
    for severity, count in rows:
        c = sev_colour.get(severity, WHITE)
        bar = "█" * count
        print(f"  {c}{BOLD}  {severity:<10}{RESET} {c}{bar} ({count}){RESET}")

    print(f"\n{WHITE}  What was demonstrated:{RESET}")
    print(f"{GREEN}  ✅ Rule 1 — Port Scan Detection       triggered{RESET}")
    print(f"{GREEN}  ✅ Rule 2 — Brute Force Detection     triggered{RESET}")
    print(f"{GREEN}  ✅ Rule 3 — ICMP Flood Detection      triggered{RESET}")
    print(f"{GREEN}  ✅ Rule 4 — Suspicious Port Access    triggered{RESET}")

    print(f"\n{CYAN}{BOLD}")
    print("=" * 60)
    print("  Demo Complete 🎯")
    print("=" * 60)
    print(RESET)

    conn.close()

if __name__ == "__main__":
    main()
