from __future__ import annotations
from ids.correlation import build_incidents
from flask import Flask, render_template, request

from ids.dashboard_data import (
    build_analytics,
    build_chart_data,
    build_summary,
    load_alerts,
    search_alerts_by_ip,
)

app = Flask(__name__)


def render_alert_dashboard(
    alerts: list[dict],
    *,
    selected_severity: str | None = None,
    search_ip: str | None = None,
):
  return render_template(
    "dashboard.html",
    alerts=alerts,
    summary=build_summary(),
    analytics=build_analytics(alerts),
    chart_data=build_chart_data(alerts),
    incidents=build_incidents(alerts),
    selected_severity=selected_severity,
    search_ip=search_ip,
)


@app.route("/")
def dashboard():
    alerts = load_alerts()
    return render_alert_dashboard(alerts)


@app.route("/alerts/<severity>")
def alerts_by_severity(severity: str):
    allowed = {"high", "medium", "low"}

    if severity not in allowed:
        severity = None
        alerts = load_alerts()
    else:
        alerts = load_alerts(severity)

    return render_alert_dashboard(
        alerts,
        selected_severity=severity,
    )


@app.route("/search")
def search():
    ip_query = request.args.get("ip", "").strip()
    alerts = search_alerts_by_ip(ip_query)

    return render_alert_dashboard(
        alerts,
        search_ip=ip_query,
    )


if __name__ == "__main__":
    app.run(debug=True)