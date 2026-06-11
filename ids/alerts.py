from __future__ import annotations

from datetime import datetime, timezone
from typing import Any


def iso_timestamp(epoch_seconds: float | int | None) -> str:
    if epoch_seconds is None:
        return datetime.now(timezone.utc).isoformat()
    return datetime.fromtimestamp(float(epoch_seconds), tz=timezone.utc).isoformat()


def create_alert(
    *,
    timestamp: float | int | None,
    alert_type: str,
    severity: str,
    source_ip: str | None,
    destination_ip: str | None,
    description: str,
    evidence: dict[str, Any],
) -> dict[str, Any]:
    """Create a normalized IDS alert object."""
    return {
        "timestamp": iso_timestamp(timestamp),
        "alert_type": alert_type,
        "severity": severity,
        "source_ip": source_ip,
        "destination_ip": destination_ip,
        "description": description,
        "evidence": evidence,
    }
