"""
  src/packet_capture.py
  Module 1 — Packet Capture Engine
  Uses Scapy to sniff live packets OR generates simulated
  traffic for demo/testing without root privileges.
"""

import time
import random
import threading
from datetime import datetime

# Scapy is imported lazily so the rest of the system
# still runs in simulation mode without it installed.
try:
    from scapy.all import sniff, IP, TCP, UDP, ICMP
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False


class PacketCaptureEngine:
    """
    Captures network packets from a live interface using Scapy,
    extracts raw fields, converts them via FeatureExtractor, and
    pushes the feature-vector onto the shared processing queue.

    In --simulate mode no Scapy / root access is needed.
    """

    # Known suspicious ports used by rule engine later
    SUSPICIOUS_PORTS = {22: "SSH", 23: "Telnet", 3389: "RDP",
                        445: "SMB", 3306: "MySQL", 5432: "PostgreSQL"}

    def __init__(self, interface, packet_queue, extractor, simulate=False):
        self.interface    = interface
        self.packet_queue = packet_queue
        self.extractor    = extractor
        self.simulate     = simulate
        self.packet_count = 0           # Total packets seen

    # ── Public entry point ─────────────────────────────────────────────────────
    def start(self):
        if self.simulate:
            self._run_simulation()
        elif not SCAPY_AVAILABLE:
            print("[!] Scapy not installed. Falling back to simulation mode.")
            self._run_simulation()
        else:
            self._run_live_capture()

    # ── Live capture via Scapy ─────────────────────────────────────────────────
    def _run_live_capture(self):
        print(f"[PacketCapture] Sniffing on {self.interface} …")
        # filter="" means capture everything; prn is called per packet
        sniff(iface=self.interface, prn=self._process_packet, store=False)

    def _process_packet(self, pkt):
        """Scapy callback — called for every captured packet."""
        if not pkt.haslayer(IP):
            return                          # Ignore non-IP frames

        raw = self._extract_raw_fields(pkt)
        features = self.extractor.extract(raw)
        self._enqueue(features)

    def _extract_raw_fields(self, pkt):
        """Pull low-level fields from a Scapy packet object."""
        ip_layer = pkt[IP]

        proto     = "OTHER"
        sport     = 0
        dport     = 0
        tcp_flags = ""

        if pkt.haslayer(TCP):
            proto     = "TCP"
            sport     = pkt[TCP].sport
            dport     = pkt[TCP].dport
            tcp_flags = str(pkt[TCP].flags)   # e.g. "S", "SA", "PA"
        elif pkt.haslayer(UDP):
            proto = "UDP"
            sport = pkt[UDP].sport
            dport = pkt[UDP].dport
        elif pkt.haslayer(ICMP):
            proto = "ICMP"

        return {
            "source_ip"      : ip_layer.src,
            "destination_ip" : ip_layer.dst,
            "source_port"    : sport,
            "destination_port": dport,
            "protocol"       : proto,
            "packet_size"    : len(pkt),
            "tcp_flags"      : tcp_flags,
            "timestamp"      : datetime.now().isoformat(),
        }

    # ── Simulation mode ────────────────────────────────────────────────────────
    def _run_simulation(self):
        """
        Generates synthetic packets at ~50/sec:
          • Normal HTTP/HTTPS traffic   (40%)
          • Port scan attempts          (20%) <- higher for fast alerts
          • Brute-force SSH             (20%) <- higher for fast alerts
          • ICMP flood bursts           (10%) <- higher for fast alerts
          • DDoS simulation             (10%) <- higher for fast alerts
        Sends 5 packets per 0.1s = 50 pkt/sec.
        Dashboard fills in ~10-15 seconds.
        """
        print("[PacketCapture] Running in SIMULATION mode ...")
        print("[PacketCapture] 50 pkt/sec -> dashboard fills in ~10 sec")
        normal_ips   = [f"192.168.1.{i}" for i in range(10, 30)]
        attacker_ips = ["10.0.0.1", "172.16.0.5", "203.0.113.42"]
        server_ip    = "192.168.1.1"

        while True:
            for _ in range(5):
                roll = random.random()
                if   roll < 0.40: raw = self._sim_normal(normal_ips, server_ip)
                elif roll < 0.60: raw = self._sim_port_scan(attacker_ips, server_ip)
                elif roll < 0.80: raw = self._sim_brute_force(attacker_ips, server_ip)
                elif roll < 0.90: raw = self._sim_icmp_flood(attacker_ips, server_ip)
                else:             raw = self._sim_ddos(attacker_ips, server_ip)
                features = self.extractor.extract(raw)
                self._enqueue(features)
                self.packet_count += 1
            time.sleep(0.1)

    # ── Simulation helpers ─────────────────────────────────────────────────────
    @staticmethod
    def _sim_normal(src_ips, dst_ip):
        return {
            "source_ip"       : random.choice(src_ips),
            "destination_ip"  : dst_ip,
            "source_port"     : random.randint(49152, 65535),
            "destination_port": random.choice([80, 443, 8080]),
            "protocol"        : "TCP",
            "packet_size"     : random.randint(64, 1500),
            "tcp_flags"       : random.choice(["S", "SA", "PA", "FA"]),
            "timestamp"       : datetime.now().isoformat(),
        }

    @staticmethod
    def _sim_port_scan(src_ips, dst_ip):
        return {
            "source_ip"       : random.choice(src_ips),
            "destination_ip"  : dst_ip,
            "source_port"     : random.randint(49152, 65535),
            "destination_port": random.randint(1, 1024),  # scanning low ports
            "protocol"        : "TCP",
            "packet_size"     : 60,            # SYN packets are tiny
            "tcp_flags"       : "S",           # Only SYN — classic port scan
            "timestamp"       : datetime.now().isoformat(),
        }

    @staticmethod
    def _sim_brute_force(src_ips, dst_ip):
        return {
            "source_ip"       : random.choice(src_ips),
            "destination_ip"  : dst_ip,
            "source_port"     : random.randint(49152, 65535),
            "destination_port": 22,            # SSH
            "protocol"        : "TCP",
            "packet_size"     : random.randint(60, 200),
            "tcp_flags"       : "S",
            "timestamp"       : datetime.now().isoformat(),
        }

    @staticmethod
    def _sim_icmp_flood(src_ips, dst_ip):
        return {
            "source_ip"       : random.choice(src_ips),
            "destination_ip"  : dst_ip,
            "source_port"     : 0,
            "destination_port": 0,
            "protocol"        : "ICMP",
            "packet_size"     : random.randint(64, 65535),
            "tcp_flags"       : "",
            "timestamp"       : datetime.now().isoformat(),
        }

    @staticmethod
    def _sim_ddos(src_ips, dst_ip):
        # Many packets from same IP in a short window
        return {
            "source_ip"       : src_ips[0],   # Always same attacker IP
            "destination_ip"  : dst_ip,
            "source_port"     : random.randint(1024, 65535),
            "destination_port": random.choice([80, 443]),
            "protocol"        : "TCP",
            "packet_size"     : random.randint(100, 1500),
            "tcp_flags"       : "S",
            "timestamp"       : datetime.now().isoformat(),
        }

    # ── Queue helper ───────────────────────────────────────────────────────────
    def _enqueue(self, features):
        try:
            self.packet_queue.put_nowait(features)
        except Exception:
            pass    # Drop packet if queue full (back-pressure)