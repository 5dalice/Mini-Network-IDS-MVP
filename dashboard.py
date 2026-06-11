from __future__ import annotations

import json
import sqlite3
from collections import Counter
from pathlib import Path

from flask import Flask, render_template_string

DB_PATH = Path("data/alerts.db")

app = Flask(__name__)


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

    alerts = []

    for row in rows:
        alert = dict(row)

        try:
            alert["mitre_attack"] = json.loads(alert.get("mitre_attack") or "null")
        except Exception:
            alert["mitre_attack"] = None

        try:
            alert["evidence"] = json.loads(alert.get("evidence") or "{}")
        except Exception:
            alert["evidence"] = {}

        alerts.append(alert)

    return alerts


def build_summary() -> dict:
    alerts = load_alerts()

    return {
        "total": len(alerts),
        "high": sum(1 for a in alerts if a["severity"] == "high"),
        "medium": sum(1 for a in alerts if a["severity"] == "medium"),
        "low": sum(1 for a in alerts if a["severity"] == "low"),
    }


def build_analytics(alerts: list[dict]) -> dict:
    alert_type_counts = Counter(a["alert_type"] for a in alerts)

    mitre_counts = Counter()
    for alert in alerts:
        mitre = alert.get("mitre_attack")
        if mitre:
            key = f"{mitre.get('technique_id')} — {mitre.get('technique_name')}"
            mitre_counts[key] += 1

    severity_counts = Counter(a["severity"] for a in alerts)
    max_severity = max(severity_counts.values(), default=1)

    return {
        "top_alert_types": alert_type_counts.most_common(5),
        "top_mitre": mitre_counts.most_common(5),
        "severity_counts": {
            "high": severity_counts.get("high", 0),
            "medium": severity_counts.get("medium", 0),
            "low": severity_counts.get("low", 0),
        },
        "max_severity": max_severity,
    }


def render_dashboard(alerts: list[dict], selected_severity: str | None = None):
    summary = build_summary()
    analytics = build_analytics(alerts)

    return render_template_string(
        """
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>Mini Network IDS Dashboard</title>

<style>
:root {
    --bg: #0f172a;
    --panel: #111827;
    --panel-soft: #1f2937;
    --border: #334155;
    --text: #e5e7eb;
    --muted: #94a3b8;
    --high: #ef4444;
    --medium: #f59e0b;
    --low: #22c55e;
    --accent: #38bdf8;
}

* {
    box-sizing: border-box;
}

body {
    margin: 0;
    font-family: "Segoe UI", Arial, sans-serif;
    background: linear-gradient(135deg, #020617, #0f172a);
    color: var(--text);
}

.container {
    max-width: 1320px;
    margin: 0 auto;
    padding: 32px;
}

.header {
    display: flex;
    justify-content: space-between;
    align-items: flex-start;
    gap: 24px;
    margin-bottom: 28px;
}

.header h1 {
    margin: 0;
    font-size: 32px;
    letter-spacing: -0.5px;
}

.header p {
    margin-top: 8px;
    color: var(--muted);
}

.status-pill {
    padding: 8px 12px;
    border: 1px solid var(--border);
    background: rgba(56, 189, 248, 0.08);
    color: var(--accent);
    border-radius: 999px;
    font-size: 13px;
    white-space: nowrap;
}

.cards {
    display: grid;
    grid-template-columns: repeat(4, minmax(160px, 1fr));
    gap: 16px;
    margin-bottom: 24px;
}

.card,
.analytics-card {
    background: rgba(17, 24, 39, 0.95);
    border: 1px solid var(--border);
    border-radius: 14px;
    padding: 20px;
    box-shadow: 0 10px 30px rgba(0,0,0,0.25);
}

.card-label {
    color: var(--muted);
    font-size: 13px;
    text-transform: uppercase;
    letter-spacing: 0.08em;
}

.card-value {
    display: block;
    margin-top: 10px;
    font-size: 34px;
    font-weight: 700;
}

.card.high .card-value {
    color: var(--high);
}

.card.medium .card-value {
    color: var(--medium);
}

.card.low .card-value {
    color: var(--low);
}

.analytics-grid {
    display: grid;
    grid-template-columns: 1.1fr 1.1fr 0.8fr;
    gap: 16px;
    margin-bottom: 24px;
}

.analytics-card h2 {
    margin: 0 0 16px 0;
    font-size: 17px;
}

.metric-row {
    display: flex;
    justify-content: space-between;
    gap: 12px;
    padding: 10px 0;
    border-bottom: 1px solid rgba(51, 65, 85, 0.65);
}

.metric-row:last-child {
    border-bottom: none;
}

.metric-name {
    color: var(--text);
    font-size: 14px;
}

.metric-value {
    color: var(--accent);
    font-weight: 700;
}

.bar-row {
    margin-bottom: 16px;
}

.bar-label {
    display: flex;
    justify-content: space-between;
    margin-bottom: 7px;
    color: var(--muted);
    font-size: 13px;
}

.bar-track {
    width: 100%;
    height: 11px;
    background: #020617;
    border-radius: 999px;
    overflow: hidden;
    border: 1px solid var(--border);
}

.bar-fill {
    height: 100%;
    border-radius: 999px;
}

.bar-fill.high {
    background: var(--high);
}

.bar-fill.medium {
    background: var(--medium);
}

.bar-fill.low {
    background: var(--low);
}

.toolbar {
    display: flex;
    justify-content: space-between;
    align-items: center;
    gap: 16px;
    margin-bottom: 18px;
}

.filters {
    display: flex;
    gap: 10px;
    flex-wrap: wrap;
}

.filters a {
    color: var(--text);
    text-decoration: none;
    background: var(--panel-soft);
    border: 1px solid var(--border);
    padding: 9px 14px;
    border-radius: 999px;
    font-size: 14px;
}

.filters a:hover {
    border-color: var(--accent);
    color: var(--accent);
}

.filters a.active {
    background: var(--accent);
    color: #020617;
    border-color: var(--accent);
    font-weight: 700;
}

.table-panel {
    background: rgba(17, 24, 39, 0.95);
    border: 1px solid var(--border);
    border-radius: 14px;
    overflow: hidden;
    box-shadow: 0 10px 30px rgba(0,0,0,0.25);
}

.table-title {
    padding: 18px 20px;
    border-bottom: 1px solid var(--border);
    display: flex;
    justify-content: space-between;
    align-items: center;
}

.table-title h2 {
    margin: 0;
    font-size: 18px;
}

.table-title span {
    color: var(--muted);
    font-size: 14px;
}

table {
    width: 100%;
    border-collapse: collapse;
}

th {
    text-align: left;
    padding: 14px 16px;
    color: var(--muted);
    background: #020617;
    font-size: 12px;
    text-transform: uppercase;
    letter-spacing: 0.08em;
}

td {
    padding: 14px 16px;
    border-top: 1px solid var(--border);
    font-size: 14px;
}

tr:hover td {
    background: rgba(56, 189, 248, 0.05);
}

.badge {
    display: inline-block;
    min-width: 72px;
    text-align: center;
    padding: 5px 9px;
    border-radius: 999px;
    font-size: 12px;
    font-weight: 700;
    text-transform: uppercase;
}

.badge.high {
    color: #fecaca;
    background: rgba(239, 68, 68, 0.18);
    border: 1px solid rgba(239, 68, 68, 0.35);
}

.badge.medium {
    color: #fde68a;
    background: rgba(245, 158, 11, 0.18);
    border: 1px solid rgba(245, 158, 11, 0.35);
}

.badge.low {
    color: #bbf7d0;
    background: rgba(34, 197, 94, 0.18);
    border: 1px solid rgba(34, 197, 94, 0.35);
}

.mitre {
    color: var(--accent);
    font-weight: 600;
}

.description {
    color: var(--muted);
}

.empty {
    padding: 32px;
    text-align: center;
    color: var(--muted);
}

@media (max-width: 1000px) {
    .cards,
    .analytics-grid {
        grid-template-columns: 1fr 1fr;
    }

    .header,
    .toolbar {
        flex-direction: column;
        align-items: flex-start;
    }
}

@media (max-width: 700px) {
    .cards,
    .analytics-grid {
        grid-template-columns: 1fr;
    }

    .container {
        padding: 18px;
    }
}
</style>
</head>

<body>
<div class="container">

    <div class="header">
        <div>
            <h1>Mini Network IDS Dashboard</h1>
            <p>SQLite-backed alert monitoring with MITRE ATT&CK context.</p>
        </div>
        <div class="status-pill">Database: data/alerts.db</div>
    </div>

    <div class="cards">
        <div class="card">
            <span class="card-label">Total Alerts</span>
            <span class="card-value">{{ summary.total }}</span>
        </div>

        <div class="card high">
            <span class="card-label">High Severity</span>
            <span class="card-value">{{ summary.high }}</span>
        </div>

        <div class="card medium">
            <span class="card-label">Medium Severity</span>
            <span class="card-value">{{ summary.medium }}</span>
        </div>

        <div class="card low">
            <span class="card-label">Low Severity</span>
            <span class="card-value">{{ summary.low }}</span>
        </div>
    </div>

    <div class="analytics-grid">
        <div class="analytics-card">
            <h2>Top Alert Types</h2>
            {% if analytics.top_alert_types %}
                {% for name, count in analytics.top_alert_types %}
                <div class="metric-row">
                    <span class="metric-name">{{ name }}</span>
                    <span class="metric-value">{{ count }}</span>
                </div>
                {% endfor %}
            {% else %}
                <div class="empty">No alert type data available.</div>
            {% endif %}
        </div>

        <div class="analytics-card">
            <h2>Top MITRE ATT&CK Techniques</h2>
            {% if analytics.top_mitre %}
                {% for name, count in analytics.top_mitre %}
                <div class="metric-row">
                    <span class="metric-name">{{ name }}</span>
                    <span class="metric-value">{{ count }}</span>
                </div>
                {% endfor %}
            {% else %}
                <div class="empty">No MITRE data available.</div>
            {% endif %}
        </div>

        <div class="analytics-card">
            <h2>Severity Distribution</h2>

            <div class="bar-row">
                <div class="bar-label">
                    <span>High</span>
                    <span>{{ analytics.severity_counts.high }}</span>
                </div>
                <div class="bar-track">
                    <div class="bar-fill high" style="width: {{ (analytics.severity_counts.high / analytics.max_severity * 100) if analytics.max_severity else 0 }}%"></div>
                </div>
            </div>

            <div class="bar-row">
                <div class="bar-label">
                    <span>Medium</span>
                    <span>{{ analytics.severity_counts.medium }}</span>
                </div>
                <div class="bar-track">
                    <div class="bar-fill medium" style="width: {{ (analytics.severity_counts.medium / analytics.max_severity * 100) if analytics.max_severity else 0 }}%"></div>
                </div>
            </div>

            <div class="bar-row">
                <div class="bar-label">
                    <span>Low</span>
                    <span>{{ analytics.severity_counts.low }}</span>
                </div>
                <div class="bar-track">
                    <div class="bar-fill low" style="width: {{ (analytics.severity_counts.low / analytics.max_severity * 100) if analytics.max_severity else 0 }}%"></div>
                </div>
            </div>
        </div>
    </div>

    <div class="toolbar">
        <div class="filters">
            <a href="/" class="{% if not selected_severity %}active{% endif %}">All</a>
            <a href="/alerts/high" class="{% if selected_severity == 'high' %}active{% endif %}">High</a>
            <a href="/alerts/medium" class="{% if selected_severity == 'medium' %}active{% endif %}">Medium</a>
            <a href="/alerts/low" class="{% if selected_severity == 'low' %}active{% endif %}">Low</a>
        </div>
    </div>

    <div class="table-panel">
        <div class="table-title">
            <h2>
                {% if selected_severity %}
                    {{ selected_severity|capitalize }} Alerts
                {% else %}
                    All Alerts
                {% endif %}
            </h2>
            <span>{{ alerts|length }} rows shown</span>
        </div>

        {% if alerts %}
        <table>
            <thead>
                <tr>
                    <th>ID</th>
                    <th>Timestamp</th>
                    <th>Severity</th>
                    <th>Alert Type</th>
                    <th>Source IP</th>
                    <th>Destination IP</th>
                    <th>Description</th>
                    <th>MITRE</th>
                </tr>
            </thead>

            <tbody>
                {% for alert in alerts %}
                <tr>
                    <td>{{ alert.id }}</td>
                    <td>{{ alert.timestamp }}</td>
                    <td>
                        <span class="badge {{ alert.severity }}">
                            {{ alert.severity }}
                        </span>
                    </td>
                    <td>{{ alert.alert_type }}</td>
                    <td>{{ alert.source_ip }}</td>
                    <td>{{ alert.destination_ip }}</td>
                    <td class="description">{{ alert.description }}</td>
                    <td class="mitre">
                        {% if alert.mitre_attack %}
                            {{ alert.mitre_attack.technique_id }}
                        {% else %}
                            —
                        {% endif %}
                    </td>
                </tr>
                {% endfor %}
            </tbody>
        </table>
        {% else %}
            <div class="empty">No alerts found for this filter.</div>
        {% endif %}
    </div>

</div>
</body>
</html>
        """,
        alerts=alerts,
        summary=summary,
        analytics=analytics,
        selected_severity=selected_severity,
    )


@app.route("/")
def dashboard():
    alerts = load_alerts()
    return render_dashboard(alerts)


@app.route("/alerts/<severity>")
def alerts_by_severity(severity: str):
    allowed = {"high", "medium", "low"}

    if severity not in allowed:
        alerts = load_alerts()
        return render_dashboard(alerts)

    alerts = load_alerts(severity)
    return render_dashboard(alerts, selected_severity=severity)


if __name__ == "__main__":
    app.run(debug=True)