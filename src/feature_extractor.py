"""
  Module 2 — Feature Extraction Layer
  Converts raw packet fields into a structured feature vector
  suitable for both the rule engine and ML model.
"""
 
import time
from collections import defaultdict, deque
 
 
class FeatureExtractor:
    """
    Maintains short-term per-IP state to compute derived features:
      • packet_rate        — packets/sec from source IP
      • connection_attempts— unique dst ports tried by source IP
      • icmp_count         — ICMP packets per source IP
      • avg_packet_size    — rolling average payload length
    These derived features make both rule-based and ML detection
    significantly more accurate than raw fields alone.
    """
 
    WINDOW_SECONDS = 10     # Rolling time window for rate calculations
 
    def __init__(self):
        # Per-IP packet timestamps  { src_ip: deque([timestamps]) }
        self._ip_timestamps  = defaultdict(lambda: deque())
        # Per-IP unique destination ports in window
        self._ip_ports       = defaultdict(set)
        # Per-IP ICMP count in window
        self._ip_icmp        = defaultdict(int)
        # Per-IP packet sizes for average
        self._ip_sizes       = defaultdict(list)
 
    # ── Public API ─────────────────────────────────────────────────────────────
    def extract(self, raw: dict) -> dict:
        """
        raw dict keys (from PacketCaptureEngine):
            source_ip, destination_ip, source_port, destination_port,
            protocol, packet_size, tcp_flags, timestamp
        Returns an enriched feature vector dict.
        """
        src_ip   = raw["source_ip"]
        protocol = raw["protocol"]
        dst_port = raw["destination_port"]
        pkt_size = raw["packet_size"]
        now      = time.time()
 
        # ── Update rolling state ───────────────────────────────────────────────
        self._update_state(src_ip, dst_port, protocol, pkt_size, now)
 
        # ── Compute derived features ───────────────────────────────────────────
        packet_rate         = self._packet_rate(src_ip, now)
        connection_attempts = len(self._ip_ports[src_ip])
        icmp_count          = self._ip_icmp[src_ip]
        sizes               = self._ip_sizes[src_ip]
        avg_pkt_size        = sum(sizes) / len(sizes) if sizes else pkt_size
 
        # ── TCP flag encoding (numeric for ML) ────────────────────────────────
        tcp_flags_raw = raw.get("tcp_flags", "")
        syn_flag   = 1 if "S"  in tcp_flags_raw else 0
        ack_flag   = 1 if "A"  in tcp_flags_raw else 0
        fin_flag   = 1 if "F"  in tcp_flags_raw else 0
        rst_flag   = 1 if "R"  in tcp_flags_raw else 0
        psh_flag   = 1 if "P"  in tcp_flags_raw else 0
 
        # ── Protocol encoding (numeric for ML) ────────────────────────────────
        proto_map = {"TCP": 0, "UDP": 1, "ICMP": 2, "OTHER": 3}
        proto_num = proto_map.get(protocol, 3)
 
        return {
            # Raw fields
            "source_ip"          : src_ip,
            "destination_ip"     : raw["destination_ip"],
            "source_port"        : raw["source_port"],
            "destination_port"   : dst_port,
            "protocol"           : protocol,
            "protocol_num"       : proto_num,
            "packet_size"        : pkt_size,
            "tcp_flags"          : tcp_flags_raw,
            "timestamp"          : raw["timestamp"],
            # Derived features
            "packet_rate"        : round(packet_rate, 3),
            "connection_attempts": connection_attempts,
            "icmp_count"         : icmp_count,
            "avg_packet_size"    : round(avg_pkt_size, 2),
            # Encoded flags (for ML numeric vector)
            "syn_flag"           : syn_flag,
            "ack_flag"           : ack_flag,
            "fin_flag"           : fin_flag,
            "rst_flag"           : rst_flag,
            "psh_flag"           : psh_flag,
        }
 
    def get_ml_vector(self, features: dict) -> list:
        """
        Returns a flat numeric list for ML model input.
        Order must match the training schema exactly.
        """
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
 
    # ── Internal helpers ───────────────────────────────────────────────────────
    def _update_state(self, src_ip, dst_port, protocol, pkt_size, now):
        ts_deque = self._ip_timestamps[src_ip]
        ts_deque.append(now)
 
        # Prune timestamps older than the window
        while ts_deque and (now - ts_deque[0]) > self.WINDOW_SECONDS:
            ts_deque.popleft()
 
        # Track unique destination ports
        self._ip_ports[src_ip].add(dst_port)
 
        # ICMP counter
        if protocol == "ICMP":
            self._ip_icmp[src_ip] += 1
 
        # Rolling size list (last 50 packets)
        sizes = self._ip_sizes[src_ip]
        sizes.append(pkt_size)
        if len(sizes) > 50:
            sizes.pop(0)
 
    def _packet_rate(self, src_ip, now) -> float:
        """Packets per second from src_ip within rolling window."""
        ts_deque = self._ip_timestamps[src_ip]
        count = len(ts_deque)
        if count < 2:
            return float(count)
        elapsed = now - ts_deque[0]
        if elapsed == 0:
            return float(count)
        return count / elapsed
 