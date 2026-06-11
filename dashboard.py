from __future__ import annotations

import json
import sqlite3
from pathlib import Path

from flask import Flask, render_template_string

DB_PATH = Path("data/alerts.db")

app = Flask(__name__)


def load_alerts():
    if not DB_PATH.exists():
        return []

    with sqlite3.connect(DB_PATH) as conn:
        conn.row_factory = sqlite3.Row

        rows = conn.execute(
            """
            SELECT *
            FROM alerts
            ORDER BY id DESC
            """
        ).fetchall()

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


@app.route("/")
def dashboard():
    alerts = load_alerts()

    total = len(alerts)
    high = sum(1 for a in alerts if a["severity"] == "high")
    medium = sum(1 for a in alerts if a["severity"] == "medium")
    low = sum(1 for a in alerts if a["severity"] == "low")

    return render_template_string(
        """
<!DOCTYPE html>
<html>
<head>
<title>Mini Network IDS Dashboard</title>

<style>
body {
    font-family: Arial;
    margin: 40px;
    background: #f5f5f5;
}

.card {
    display: inline-block;
    padding: 15px;
    margin-right: 10px;
    background: white;
    border-radius: 8px;
}

table {
    width: 100%;
    border-collapse: collapse;
    background: white;
    margin-top: 20px;
}

th, td {
    border: 1px solid #ddd;
    padding: 8px;
}

th {
    background: #222;
    color: white;
}

.high {
    color: red;
    font-weight: bold;
}

.medium {
    color: orange;
    font-weight: bold;
}

.low {
    color: green;
    font-weight: bold;
}
</style>

</head>
<body>

<h1>Mini Network IDS Dashboard</h1>

<div class="card">
    <strong>Total Alerts:</strong> {{ total }}
</div>

<div class="card">
    <strong>High:</strong> {{ high }}
</div>

<div class="card">
    <strong>Medium:</strong> {{ medium }}
</div>

<div class="card">
    <strong>Low:</strong> {{ low }}
</div>

<table>

<tr>
    <th>ID</th>
    <th>Timestamp</th>
    <th>Severity</th>
    <th>Alert Type</th>
    <th>Source IP</th>
    <th>Destination IP</th>
    <th>MITRE</th>
</tr>

{% for alert in alerts %}
<tr>
    <td>{{ alert.id }}</td>
    <td>{{ alert.timestamp }}</td>
    <td class="{{ alert.severity }}">{{ alert.severity }}</td>
    <td>{{ alert.alert_type }}</td>
    <td>{{ alert.source_ip }}</td>
    <td>{{ alert.destination_ip }}</td>
    <td>
        {% if alert.mitre_attack %}
            {{ alert.mitre_attack.technique_id }}
        {% endif %}
    </td>
</tr>
{% endfor %}

</table>

</body>
</html>
        """,
        alerts=alerts,
        total=total,
        high=high,
        medium=medium,
        low=low,
    )


if __name__ == "__main__":
    app.run(debug=True)