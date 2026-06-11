from __future__ import annotations

import json
import sqlite3
from collections import Counter
from pathlib import Path

DB_PATH = Path("data/alerts.db")

DISPLAY_NAMES = {
    "PORT_SCAN": "Port Scan",
    "SYN_FLOOD_PATTERN": "SYN Flood Activity",
    "MALICIOUS_DNS_QUERY": "Malicious DNS Request",
    "REPEATED_LARGE_PACKETS": "Large Data Transfer",
    "MALICIOUS_IP_COMMUNICATION": "Communication with Blocklisted IP",
}


def _normalize_alert(row: sqlite3.Row) -> dict:
    alert = dict(row)

    alert["display_name"] = DISPLAY_NAMES.get(
        alert.get("alert_type"),
        alert.get("alert_type"),
    )

    try:
        alert["mitre_attack"] = json.loads(alert.get("mitre_attack") or "null")
    except Exception:
        alert["mitre_attack"] = None

    try:
        alert["evidence"] = json.loads(alert.get("evidence") or "{}")
    except Exception:
        alert["evidence"] = {}

    return alert


def load_alerts(severity: str | None = None) -> list[dict]:
    if not DB_PATH.exists():
        return []

    query = "SELECT * FROM alerts"
    params = []

    if severity:
        query += " WHERE severity = ?"
        params.append(severity)

    query += " ORDER BY id DESC"

    with sqlite3.connect(DB_PATH) as conn:
        conn.row_factory = sqlite3.Row
        rows = conn.execute(query, params).fetchall()

    return [_normalize_alert(row) for row in rows]


def search_alerts_by_ip(ip_query: str) -> list[dict]:
    if not DB_PATH.exists():
        return []

    ip_query = ip_query.strip()

    if not ip_query:
        return load_alerts()

    with sqlite3.connect(DB_PATH) as conn:
        conn.row_factory = sqlite3.Row
        rows = conn.execute(
            """
            SELECT *
            FROM alerts
            WHERE source_ip LIKE ?
               OR destination_ip LIKE ?
            ORDER BY id DESC
            """,
            (f"%{ip_query}%", f"%{ip_query}%"),
        ).fetchall()

    return [_normalize_alert(row) for row in rows]


def build_summary() -> dict:
    alerts = load_alerts()

    return {
        "total": len(alerts),
        "high": sum(1 for a in alerts if a["severity"] == "high"),
        "medium": sum(1 for a in alerts if a["severity"] == "medium"),
        "low": sum(1 for a in alerts if a["severity"] == "low"),
    }


def build_analytics(alerts: list[dict]) -> dict:
    alert_type_counts = Counter(
        a.get("display_name")
        for a in alerts
    )

    mitre_counts = Counter()

    for alert in alerts:
        mitre = alert.get("mitre_attack")

        if mitre:
            key = f"{mitre.get('technique_id')} — {mitre.get('technique_name')}"
            mitre_counts[key] += 1

    severity_counts = Counter(a["severity"] for a in alerts)

    return {
        "top_alert_types": alert_type_counts.most_common(5),
        "top_mitre": mitre_counts.most_common(5),
        "severity_counts": {
            "high": severity_counts.get("high", 0),
            "medium": severity_counts.get("medium", 0),
            "low": severity_counts.get("low", 0),
        },
    }

def build_chart_data(alerts: list[dict]) -> dict:
    analytics = build_analytics(alerts)

    return {
        "severity_labels": ["High", "Medium", "Low"],
        "severity_values": [
            analytics["severity_counts"]["high"],
            analytics["severity_counts"]["medium"],
            analytics["severity_counts"]["low"],
        ],
        "alert_type_labels": [
            item[0] for item in analytics["top_alert_types"]
        ],
        "alert_type_values": [
            item[1] for item in analytics["top_alert_types"]
        ],
        "mitre_labels": [
            item[0] for item in analytics["top_mitre"]
        ],
        "mitre_values": [
            item[1] for item in analytics["top_mitre"]
        ],
    }