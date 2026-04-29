"""
  src/logger.py
  Module 6 — Logging System
  Persists all alerts to an SQLite database for forensic
  analysis and populates the dashboard's historical view.
"""
import os
import sqlite3
import threading
from datetime import datetime
 
DB_PATH = os.path.join(os.path.dirname(__file__), "..", "logs", "nids.db")
 
 
class Logger:
    """
    Thread-safe SQLite logger.
 
    Schema (alerts table):
      id            INTEGER PRIMARY KEY AUTOINCREMENT
      timestamp     TEXT       — ISO-8601 string
      source_ip     TEXT
      destination_ip TEXT
      protocol      TEXT
      port          INTEGER
      attack_type   TEXT
      severity      TEXT       — CRITICAL / HIGH / MEDIUM / LOW
      source        TEXT       — RULE or ML
      detail        TEXT       — human-readable context
 
    Uses a threading.Lock so multiple threads can safely call
    log_alert() without corrupting the database.
    """
 
    def __init__(self):
        os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
        self._lock = threading.Lock()
        self._conn = sqlite3.connect(DB_PATH, check_same_thread=False)
        self._create_tables()
        print(f"[Logger] Database ready at {DB_PATH}")
 
    # ── Schema setup ──────────────────────────────────────────────────────────
    def _create_tables(self):
        with self._conn:
            self._conn.execute("""
                CREATE TABLE IF NOT EXISTS alerts (
                    id             INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp      TEXT    NOT NULL,
                    source_ip      TEXT    NOT NULL,
                    destination_ip TEXT    NOT NULL,
                    protocol       TEXT    DEFAULT 'UNKNOWN',
                    port           INTEGER DEFAULT 0,
                    attack_type    TEXT    NOT NULL,
                    severity       TEXT    NOT NULL,
                    source         TEXT    DEFAULT 'RULE',
                    detail         TEXT    DEFAULT ''
                )
            """)
            # Index for fast time-range queries on the dashboard
            self._conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_timestamp
                ON alerts(timestamp)
            """)
            # Index for per-IP forensic queries
            self._conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_source_ip
                ON alerts(source_ip)
            """)
 
    # ── Write ──────────────────────────────────────────────────────────────────
    def log_alert(self, alert: dict):
        """Insert a single alert row (thread-safe)."""
        with self._lock:
            try:
                self._conn.execute("""
                    INSERT INTO alerts
                        (timestamp, source_ip, destination_ip, protocol,
                         port, attack_type, severity, source, detail)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    alert.get("timestamp", datetime.now().isoformat()),
                    alert.get("source_ip",       "N/A"),
                    alert.get("destination_ip",  "N/A"),
                    alert.get("protocol",        "UNKNOWN"),
                    alert.get("port",            0),
                    alert.get("attack_type",     "Unknown"),
                    alert.get("severity",        "LOW"),
                    alert.get("source",          "RULE"),
                    alert.get("detail",          ""),
                ))
                self._conn.commit()
            except sqlite3.Error as e:
                print(f"[Logger] DB write error: {e}")
 
    # ── Read (for dashboard API) ───────────────────────────────────────────────
    def get_recent_alerts(self, limit: int = 100) -> list:
        """Return the most recent alerts as a list of dicts."""
        with self._lock:
            cur = self._conn.execute("""
                SELECT id, timestamp, source_ip, destination_ip,
                       protocol, port, attack_type, severity, source, detail
                FROM   alerts
                ORDER  BY id DESC
                LIMIT  ?
            """, (limit,))
            cols = [d[0] for d in cur.description]
            return [dict(zip(cols, row)) for row in cur.fetchall()]
 
    def get_attack_distribution(self) -> list:
        """
        Aggregate count per attack_type for the pie chart.
        Returns: [{"attack_type": "Port Scan", "count": 42}, …]
        """
        with self._lock:
            cur = self._conn.execute("""
                SELECT attack_type, COUNT(*) as count
                FROM   alerts
                GROUP  BY attack_type
                ORDER  BY count DESC
            """)
            return [{"attack_type": r[0], "count": r[1]}
                    for r in cur.fetchall()]
 
    def get_top_attackers(self, n: int = 10) -> list:
        """Top N source IPs by alert count."""
        with self._lock:
            cur = self._conn.execute("""
                SELECT source_ip, COUNT(*) as count
                FROM   alerts
                GROUP  BY source_ip
                ORDER  BY count DESC
                LIMIT  ?
            """, (n,))
            return [{"ip": r[0], "count": r[1]} for r in cur.fetchall()]
 
    def get_timeline(self, hours: int = 1) -> list:
        """
        Alerts per minute over last `hours` hours for the line chart.
        """
        with self._lock:
            cur = self._conn.execute("""
                SELECT strftime('%Y-%m-%d %H:%M', timestamp) as minute,
                       COUNT(*) as count
                FROM   alerts
                WHERE  timestamp >= datetime('now', ?)
                GROUP  BY minute
                ORDER  BY minute ASC
            """, (f"-{hours} hours",))
            return [{"minute": r[0], "count": r[1]}
                    for r in cur.fetchall()]
 
    def get_stats(self) -> dict:
        """Summary statistics for the dashboard header cards."""
        with self._lock:
            total = self._conn.execute(
                "SELECT COUNT(*) FROM alerts").fetchone()[0]
            critical = self._conn.execute(
                "SELECT COUNT(*) FROM alerts WHERE severity='CRITICAL'"
            ).fetchone()[0]
            unique_ips = self._conn.execute(
                "SELECT COUNT(DISTINCT source_ip) FROM alerts"
            ).fetchone()[0]
        return {"total": total, "critical": critical,
                "unique_attacker_ips": unique_ips}
 
    # ── Cleanup ────────────────────────────────────────────────────────────────
    def close(self):
        self._conn.close()
        print("[Logger] Database connection closed.")
    
