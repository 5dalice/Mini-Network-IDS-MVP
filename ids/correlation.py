from __future__ import annotations

from collections import defaultdict
from datetime import datetime
from typing import Any


def _risk_level_from_score(score: int) -> str:
    if score >= 150:
        return "critical"

    if score >= 90:
        return "high"

    if score >= 40:
        return "medium"

    return "low"


def _parse_timestamp(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def build_incidents(alerts: list[dict[str, Any]]) -> list[dict[str, Any]]:
    grouped: dict[str, list[dict[str, Any]]] = defaultdict(list)

    for alert in alerts:
        source_ip = alert.get("source_ip") or "unknown"
        grouped[source_ip].append(alert)

    incidents = []

    for index, (source_ip, source_alerts) in enumerate(grouped.items(), start=1):
        sorted_alerts = sorted(
            source_alerts,
            key=lambda alert: alert.get("timestamp", ""),
        )

        total_score = sum(alert.get("threat_score", 0) for alert in sorted_alerts)
        max_score = max((alert.get("threat_score", 0) for alert in sorted_alerts), default=0)

        alert_types = sorted(
            {
                alert.get("display_name") or alert.get("alert_type")
                for alert in sorted_alerts
            }
        )

        first_seen = sorted_alerts[0].get("timestamp")
        last_seen = sorted_alerts[-1].get("timestamp")

        incidents.append(
            {
                "incident_id": index,
                "source_ip": source_ip,
                "alert_count": len(sorted_alerts),
                "total_score": total_score,
                "max_alert_score": max_score,
                "risk_level": _risk_level_from_score(total_score),
                "first_seen": first_seen,
                "last_seen": last_seen,
                "alert_types": alert_types,
                "alerts": sorted_alerts,
            }
        )

    return sorted(
        incidents,
        key=lambda incident: incident["total_score"],
        reverse=True,
    )