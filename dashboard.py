from __future__ import annotations

import json
import sqlite3
from pathlib import Path

from flask import Flask, render_template_string

DB_PATH = Path("data/alerts.db")

app = Flask(__name__)


def load_alerts(severity: str | None = None):
    if not DB_PATH.exists():
        return []

    query = """
        SELECT *
        FROM alerts
    """
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
            alert["mitre_attack"] = json.loads(
                alert.get("mitre_attack") or "null"
            )
        except Exception:
            alert["mitre_attack"] = None

        alerts.append(alert)

    return alerts


def build_summary():
    alerts = load_alerts()

    return {
        "total": len(alerts),
        "high": sum(1 for a in alerts if a["severity"] == "high"),
        "medium": sum(1 for a in alerts if a["severity"] == "medium"),
        "low": sum(1 for a in alerts if a["severity"] == "low"),
    }


def render_dashboard(alerts, selected_severity: str | None = None):
    summary = build_summary()

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
    max-width: 1280px;
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

.card {
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

@media (max-width: 900px) {
    .cards {
        grid-template-columns: repeat(2, 1fr);
    }

    .header,
    .toolbar {
        flex-direction: column;
        align-items: flex-start;
    }

    table {
        font-size: 12px;
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