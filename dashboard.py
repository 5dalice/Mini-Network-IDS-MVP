from __future__ import annotations

from flask import Flask, render_template, request

from ids.correlation import build_incidents
from ids.dashboard_data import (
    build_analytics,
    build_chart_data,
    build_summary,
    filter_alerts,
    get_filter_options,
    load_alerts,
)

app = Flask(__name__)


def render_alert_dashboard(
    alerts: list[dict],
    *,
    selected_severity: str | None = None,
    search_ip: str | None = None,
    selected_alert_type: str | None = None,
    selected_risk_level: str | None = None,
):
    return render_template(
        "dashboard.html",
        alerts=alerts,
        summary=build_summary(),
        analytics=build_analytics(alerts),
        chart_data=build_chart_data(alerts),
        incidents=build_incidents(alerts),
        filter_options=get_filter_options(),
        selected_severity=selected_severity,
        search_ip=search_ip,
        selected_alert_type=selected_alert_type,
        selected_risk_level=selected_risk_level,
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
    severity = request.args.get("severity", "").strip()
    alert_type = request.args.get("alert_type", "").strip()
    risk_level = request.args.get("risk_level", "").strip()

    alerts = filter_alerts(
        ip_query=ip_query,
        severity=severity,
        alert_type=alert_type,
        risk_level=risk_level,
    )

    return render_alert_dashboard(
        alerts,
        selected_severity=severity or None,
        search_ip=ip_query or None,
        selected_alert_type=alert_type or None,
        selected_risk_level=risk_level or None,
    )


if __name__ == "__main__":
    app.run(debug=True)