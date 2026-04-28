"""
  src/ai_reporter.py
  AI-Powered Attack Report Generator
  Uses Claude API to auto-generate professional security
  reports from detected alerts in the SQLite database.
"""

import json
import urllib.request
import urllib.error
from datetime import datetime


def generate_report(stats: dict, distribution: list,
                    top_attackers: list, recent: list) -> str:
    """
    Sends alert data to Claude API and returns a professional
    security incident report as markdown text.
    """

    # ── Build a compact summary to send to Claude ─────────────────────────────
    attack_summary = "\n".join([
        f"- {d['attack_type']}: {d['count']} incidents"
        for d in distribution
    ])

    attacker_summary = "\n".join([
        f"- {a['ip']}: {a['count']} alerts"
        for a in top_attackers[:5]
    ])

    recent_summary = "\n".join([
        f"- [{r['severity']}] {r['attack_type']} | "
        f"Src:{r['source_ip']} → Dst:{r['destination_ip']}:{r['port']} "
        f"| Engine:{r['source']} | {r['timestamp'][:19]}"
        for r in recent[:15]
    ])

    prompt = f"""You are a senior cybersecurity analyst.
Generate a professional Network Security Incident Report based on the following NIDS alert data.

=== ALERT STATISTICS ===
Total Alerts     : {stats.get('total', 0)}
Critical Alerts  : {stats.get('critical', 0)}
Unique Attacker IPs : {stats.get('unique_attacker_ips', 0)}
ML Anomalies     : {stats.get('ml_count', 0)}
Report Generated : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

=== ATTACK DISTRIBUTION ===
{attack_summary}

=== TOP ATTACKER IPs ===
{attacker_summary}

=== RECENT ALERTS (last 15) ===
{recent_summary}

Generate a professional security report with these sections:
1. Executive Summary (2-3 sentences, non-technical)
2. Threat Assessment (severity level: LOW/MEDIUM/HIGH/CRITICAL)
3. Attack Analysis (explain each attack type detected)
4. Top Threat Actors (analyse attacker IPs)
5. AI vs Rule Detection (what ML caught vs rules)
6. Immediate Recommendations (3-5 specific actions)
7. Conclusion

Keep it professional, concise and suitable for presentation to faculty/management.
Use markdown formatting with ## headers.
"""

    # ── Call Claude API ────────────────────────────────────────────────────────
    payload = json.dumps({
        "model"     : "claude-sonnet-4-20250514",
        "max_tokens": 1000,
        "messages"  : [{"role": "user", "content": prompt}]
    }).encode("utf-8")

    req = urllib.request.Request(
        "https://api.anthropic.com/v1/messages",
        data    = payload,
        headers = {"Content-Type": "application/json"},
        method  = "POST"
    )

    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            data = json.loads(resp.read().decode("utf-8"))
            # Extract text from response
            for block in data.get("content", []):
                if block.get("type") == "text":
                    return block["text"]
            return "⚠️ No report content returned from AI."

    except urllib.error.HTTPError as e:
        body = e.read().decode("utf-8", errors="ignore")
        return f"⚠️ API Error {e.code}: {body[:200]}"
    except urllib.error.URLError as e:
        return f"⚠️ Connection Error: {e.reason}"
    except Exception as e:
        return f"⚠️ Unexpected error: {str(e)}"
