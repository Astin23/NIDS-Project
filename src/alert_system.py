"""
============================================================
  src/alert_system.py
  Module 5 — Alert System
  Dispatches alerts to console with colour-coded severity.
  Extensible to email / Slack / SIEM webhooks.
============================================================
"""

from datetime import datetime

# ANSI colour codes for terminal output
COLOURS = {
    "CRITICAL" : "\033[91m",    # Red
    "HIGH"     : "\033[93m",    # Yellow
    "MEDIUM"   : "\033[94m",    # Blue
    "LOW"      : "\033[92m",    # Green
    "RESET"    : "\033[0m",
    "BOLD"     : "\033[1m",
}


class AlertSystem:
    """
    Receives fully-formed alert dicts from the detection worker
    and dispatches them to configured outputs.

    Current outputs:
      • Colour-coded terminal (always on)

    Future outputs (stub methods provided):
      • Email via SMTP
      • Slack webhook
      • Syslog / SIEM (CEF format)
    """

    def __init__(self, verbose: bool = True):
        self.verbose = verbose
        self.alert_count = 0

    def dispatch(self, alert: dict):
        """Main entry point — route alert to all outputs."""
        self.alert_count += 1
        if self.verbose:
            self._print_alert(alert)

        # Stub: uncomment to enable additional outputs
        # self._send_email(alert)
        # self._send_slack(alert)
        # self._send_syslog(alert)

    # ── Terminal output ────────────────────────────────────────────────────────
    def _print_alert(self, alert: dict):
        severity = alert.get("severity", "LOW")
        colour   = COLOURS.get(severity, "")
        reset    = COLOURS["RESET"]
        bold     = COLOURS["BOLD"]
        source   = alert.get("source", "?")
        tag      = f"[{source}]"

        print(
            f"{colour}{bold}"
            f"[ALERT #{self.alert_count}] [{severity}] {tag} "
            f"{alert['attack_type']}{reset}"
        )
        print(
            f"  Src: {alert['source_ip']}  →  "
            f"Dst: {alert['destination_ip']}:{alert['port']}"
        )
        print(f"  Time: {alert['timestamp']}")
        if alert.get("detail"):
            print(f"  Info: {alert['detail']}")
        print("-" * 60)

    # ── Stub: Email notification ───────────────────────────────────────────────
    def _send_email(self, alert: dict):
        """
        Send alert via SMTP.  Fill in credentials in config.py.
        import smtplib, email.mime.text as needed.
        """
        pass    # TODO: implement for production use

    # ── Stub: Slack webhook ───────────────────────────────────────────────────
    def _send_slack(self, alert: dict):
        """
        POST alert JSON to a Slack Incoming Webhook URL.
        Requires: requests library + SLACK_WEBHOOK_URL env var.
        """
        pass    # TODO: implement for production use

    # ── Stub: Syslog / SIEM ───────────────────────────────────────────────────
    def _send_syslog(self, alert: dict):
        """
        Send a CEF-formatted message to a SIEM collector.
        """
        pass    # TODO: implement for production use
