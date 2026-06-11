from __future__ import annotations

from flask import Flask, render_template

from ids.dashboard_data import (
    build_analytics,
    build_chart_data,
    build_summary,
    load_alerts,
)

app = Flask(__name__)


@app.route("/")
def dashboard():
    alerts = load_alerts()

    return render_template(
        "dashboard.html",
        alerts=alerts,
        summary=build_summary(),
        analytics=build_analytics(alerts),
        chart_data=build_chart_data(alerts),
        selected_severity=None,
    )


@app.route("/alerts/<severity>")
def alerts_by_severity(severity: str):
    allowed = {"high", "medium", "low"}

    if severity not in allowed:
        severity = None

    alerts = load_alerts(severity)

    return render_template(
        "dashboard.html",
        alerts=alerts,
        summary=build_summary(),
        analytics=build_analytics(alerts),
        chart_data=build_chart_data(alerts),
        selected_severity=severity,
    )


if __name__ == "__main__":
    app.run(debug=True)