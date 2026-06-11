from __future__ import annotations

import json
from collections import Counter
from pathlib import Path
from typing import Any

from rich.console import Console
from rich.table import Table

console = Console()


def filter_alerts_by_severity(alerts: list[dict[str, Any]], severity: str) -> list[dict[str, Any]]:
    return [alert for alert in alerts if alert.get("severity") == severity]


def summarize_alerts(alerts: list[dict[str, Any]]) -> dict[str, int]:
    counts = Counter(alert["severity"] for alert in alerts)
    return {
        "total": len(alerts),
        "high": counts.get("high", 0),
        "medium": counts.get("medium", 0),
        "low": counts.get("low", 0),
    }


def print_report(alerts: list[dict[str, Any]], *, show_summary: bool = False) -> None:
    table = Table(title="Mini Network IDS Alerts")
    table.add_column("Timestamp")
    table.add_column("Severity")
    table.add_column("Type")
    table.add_column("Source")
    table.add_column("Destination")
    table.add_column("Description")

    for alert in alerts:
        table.add_row(
            alert["timestamp"],
            alert["severity"],
            alert["alert_type"],
            str(alert["source_ip"]),
            str(alert["destination_ip"]),
            alert["description"],
        )

    console.print(table)

    if show_summary:
        summary = summarize_alerts(alerts)
        console.print("\nAnalysis complete.")
        console.print(f"Total alerts: {summary['total']}")
        console.print(f"High: {summary['high']}")
        console.print(f"Medium: {summary['medium']}")
        console.print(f"Low: {summary['low']}")


def save_json_report(alerts: list[dict[str, Any]], output_path: str | Path) -> None:
    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    report = {
        "summary": summarize_alerts(alerts),
        "alerts": alerts,
    }
    path.write_text(json.dumps(report, indent=2), encoding="utf-8")
