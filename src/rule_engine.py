"""
  src/rule_engine.py
  Module 3 — Rule-Based Detection Engine
  Implements five rule families with severity classification:
    1. Port Scan Detection
    2. Brute-Force Login Detection
    3. Suspicious Port Access
    4. ICMP Flood Detection
    5. DDoS Behaviour Detection
"""

import time
from collections import defaultdict, deque
from datetime import datetime


# ── Alert severity constants ──────────────────────────────────────────────────
SEVERITY = {
    "CRITICAL" : 1,
    "HIGH"     : 2,
    "MEDIUM"   : 3,
    "LOW"      : 4,
}

# ── Suspicious / sensitive ports ──────────────────────────────────────────────
SUSPICIOUS_PORT_MAP = {
    22   : ("SSH",        "HIGH"),
    23   : ("Telnet",     "CRITICAL"),   # Telnet is plaintext — very dangerous
    3389 : ("RDP",        "HIGH"),
    445  : ("SMB",        "HIGH"),
    3306 : ("MySQL",      "MEDIUM"),
    5432 : ("PostgreSQL", "MEDIUM"),
    1433 : ("MSSQL",      "HIGH"),
    21   : ("FTP",        "MEDIUM"),
    2222 : ("Alt-SSH",    "HIGH"),
}


class RuleEngine:
    """
    Stateful rule engine.  analyze(features) is called once per
    packet-feature-vector and returns a (possibly empty) list of
    alert dicts.

    Internal state (per-IP counters, time-windows) is maintained
    using Python dictionaries — O(1) average lookup.
    """

    # ── Configurable thresholds ───────────────────────────────────────────────
    PORT_SCAN_THRESHOLD   = 15    # unique ports in window → port scan
    BRUTE_FORCE_THRESHOLD = 10    # login attempts to same port in window
    ICMP_FLOOD_THRESHOLD  = 50    # ICMP packets in window → flood
    DDOS_RATE_THRESHOLD   = 100   # packets/sec → DDoS behaviour
    WINDOW_SECONDS        = 10    # sliding window duration

    def __init__(self):
        # Hash tables keyed by source IP for fast O(1) access
        self._port_tracker  = defaultdict(set)          # src_ip → set of dst_ports
        self._brute_tracker = defaultdict(               # src_ip → {port: deque}
            lambda: defaultdict(deque))
        self._icmp_tracker  = defaultdict(deque)        # src_ip → deque of timestamps
        self._rate_tracker  = defaultdict(deque)        # src_ip → deque of timestamps
        self._last_cleanup  = time.time()

    # ── Public API ────────────────────────────────────────────────────────────
    def analyze(self, features: dict) -> list:
        """
        Run all rules against the given feature vector.
        Returns a list of alert dicts (may be empty).
        """
        alerts = []
        now    = time.time()

        # Periodic cleanup to avoid unbounded memory growth
        if now - self._last_cleanup > 30:
            self._cleanup(now)
            self._last_cleanup = now

        src_ip   = features["source_ip"]
        dst_ip   = features["destination_ip"]
        dst_port = features["destination_port"]
        protocol = features["protocol"]
        ts       = features["timestamp"]

        # ── Rule 1 — Port Scan ────────────────────────────────────────────────
        alert = self._check_port_scan(src_ip, dst_ip, dst_port, ts)
        if alert:
            alerts.append(alert)

        # ── Rule 2 — Brute Force ──────────────────────────────────────────────
        alert = self._check_brute_force(src_ip, dst_ip, dst_port, protocol, ts, now)
        if alert:
            alerts.append(alert)

        # ── Rule 3 — Suspicious Port ──────────────────────────────────────────
        alert = self._check_suspicious_port(src_ip, dst_ip, dst_port, ts)
        if alert:
            alerts.append(alert)

        # ── Rule 4 — ICMP Flood ───────────────────────────────────────────────
        alert = self._check_icmp_flood(src_ip, dst_ip, protocol, ts, now)
        if alert:
            alerts.append(alert)

        # ── Rule 5 — DDoS Behaviour ───────────────────────────────────────────
        alert = self._check_ddos(src_ip, dst_ip, ts, now,
                                 features["packet_rate"])
        if alert:
            alerts.append(alert)

        return alerts

    # ── Rule implementations ──────────────────────────────────────────────────

    def _check_port_scan(self, src_ip, dst_ip, dst_port, ts):
        """
        Rule: If a single source IP accesses more than PORT_SCAN_THRESHOLD
        unique destination ports → flag as port scan.
        Uses a set (hash table) per source IP for O(1) insertion.
        """
        self._port_tracker[src_ip].add(dst_port)
        unique_ports = len(self._port_tracker[src_ip])

        if unique_ports >= self.PORT_SCAN_THRESHOLD:
            # Reset to avoid repeated alerts from same host
            self._port_tracker[src_ip] = set()
            return self._make_alert(
                attack_type    = "Port Scan",
                source_ip      = src_ip,
                destination_ip = dst_ip,
                port           = dst_port,
                timestamp      = ts,
                severity       = "HIGH",
                detail         = f"Scanned {unique_ports} unique ports"
            )
        return None

    def _check_brute_force(self, src_ip, dst_ip, dst_port, protocol, ts, now):
        """
        Rule: Repeated connections to the same port from same IP.
        Targets: SSH (22), Telnet (23), RDP (3389).
        """
        if protocol not in ("TCP",) or dst_port not in SUSPICIOUS_PORT_MAP:
            return None

        dq = self._brute_tracker[src_ip][dst_port]
        dq.append(now)
        # Keep only timestamps within the window
        while dq and (now - dq[0]) > self.WINDOW_SECONDS:
            dq.popleft()

        attempts = len(dq)
        if attempts >= self.BRUTE_FORCE_THRESHOLD:
            dq.clear()           # Reset counter
            service, _ = SUSPICIOUS_PORT_MAP.get(dst_port, ("Unknown", "MEDIUM"))
            severity   = "CRITICAL" if dst_port in (22, 23, 3389) else "HIGH"
            return self._make_alert(
                attack_type    = "Brute Force Login",
                source_ip      = src_ip,
                destination_ip = dst_ip,
                port           = dst_port,
                timestamp      = ts,
                severity       = severity,
                detail         = f"{attempts} login attempts to {service} port {dst_port}"
            )
        return None

    def _check_suspicious_port(self, src_ip, dst_ip, dst_port, ts):
        """
        Rule: Any access to a sensitive service port generates a LOW alert.
        Severity is looked up from the SUSPICIOUS_PORT_MAP hash table.
        """
        if dst_port in SUSPICIOUS_PORT_MAP:
            service, severity = SUSPICIOUS_PORT_MAP[dst_port]
            return self._make_alert(
                attack_type    = "Suspicious Port Access",
                source_ip      = src_ip,
                destination_ip = dst_ip,
                port           = dst_port,
                timestamp      = ts,
                severity       = "LOW",              # Low — just informational
                detail         = f"Access to {service} port {dst_port}"
            )
        return None

    def _check_icmp_flood(self, src_ip, dst_ip, protocol, ts, now):
        """
        Rule: High-volume ICMP from a single source → ICMP Flood / Ping Flood.
        """
        if protocol != "ICMP":
            return None

        dq = self._icmp_tracker[src_ip]
        dq.append(now)
        while dq and (now - dq[0]) > self.WINDOW_SECONDS:
            dq.popleft()

        count = len(dq)
        if count >= self.ICMP_FLOOD_THRESHOLD:
            dq.clear()
            return self._make_alert(
                attack_type    = "ICMP Flood",
                source_ip      = src_ip,
                destination_ip = dst_ip,
                port           = 0,
                timestamp      = ts,
                severity       = "CRITICAL",
                detail         = f"{count} ICMP packets in {self.WINDOW_SECONDS}s window"
            )
        return None

    def _check_ddos(self, src_ip, dst_ip, ts, now, packet_rate):
        """
        Rule: Extremely high packet rate from a single source → DDoS.
        We use the pre-computed packet_rate from the feature extractor.
        """
        if packet_rate >= self.DDOS_RATE_THRESHOLD:
            return self._make_alert(
                attack_type    = "DDoS Behaviour",
                source_ip      = src_ip,
                destination_ip = dst_ip,
                port           = 0,
                timestamp      = ts,
                severity       = "CRITICAL",
                detail         = f"Packet rate {packet_rate:.1f} pkt/s (threshold {self.DDOS_RATE_THRESHOLD})"
            )
        return None

    # ── Alert factory ─────────────────────────────────────────────────────────
    @staticmethod
    def _make_alert(attack_type, source_ip, destination_ip, port,
                    timestamp, severity, detail=""):
        return {
            "source"        : "RULE",
            "attack_type"   : attack_type,
            "source_ip"     : source_ip,
            "destination_ip": destination_ip,
            "port"          : port,
            "timestamp"     : timestamp,
            "severity"      : severity,
            "detail"        : detail,
        }

    # ── Housekeeping ──────────────────────────────────────────────────────────
    def _cleanup(self, now):
        """
        Remove stale entries from all trackers to prevent memory leaks
        during long-running captures.
        """
        # Remove port-scan sets for IPs not seen for 60 s
        # (Simplified: clear sets that are very small — likely stale)
        for ip in list(self._port_tracker.keys()):
            if len(self._port_tracker[ip]) == 0:
                del self._port_tracker[ip]

        # Prune brute-force deques
        for ip in list(self._brute_tracker.keys()):
            for port in list(self._brute_tracker[ip].keys()):
                dq = self._brute_tracker[ip][port]
                while dq and (now - dq[0]) > self.WINDOW_SECONDS:
                    dq.popleft()