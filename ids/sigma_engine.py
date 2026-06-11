from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml

from ids.alerts import create_alert


FIELD_MAP = {
    "source_ip": "src_ip",
    "destination_ip": "dst_ip",
    "source_port": "src_port",
    "destination_port": "dst_port",
    "protocol": "protocol",
    "domain": "dns_query",
}


def load_sigma_rules(rules_dir: str | Path = "rules/sigma") -> list[dict[str, Any]]:
    rules = []

    rules_path = Path(rules_dir)

    if not rules_path.exists():
        return rules

    for path in rules_path.glob("*.yml"):
        with open(path, "r", encoding="utf-8") as file:
            rule = yaml.safe_load(file)

        if rule:
            rule["_file"] = str(path)
            rules.append(rule)

    return rules


def _normalize_value(value: Any) -> str:
    return str(value).lower().rstrip(".")


def _packet_matches_field(packet: dict[str, Any], sigma_field: str, expected_values: list[Any]) -> bool:
    packet_field = FIELD_MAP.get(sigma_field)

    if not packet_field:
        return False

    packet_value = packet.get(packet_field)

    if packet_value is None:
        return False

    normalized_packet_value = _normalize_value(packet_value)
    normalized_expected_values = {
        _normalize_value(value)
        for value in expected_values
    }

    return normalized_packet_value in normalized_expected_values


def _packet_matches_detection(packet: dict[str, Any], detection: dict[str, Any]) -> bool:
    for sigma_field, expected_values in detection.items():
        if sigma_field == "condition":
            continue

        if not isinstance(expected_values, list):
            expected_values = [expected_values]

        if not _packet_matches_field(packet, sigma_field, expected_values):
            return False

    return True


def run_sigma_rules(
    packets: list[dict[str, Any]],
    rules: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    alerts = []

    for rule in rules:
        detection = rule.get("detection", {})

        if not detection:
            continue

        for packet in packets:
            if not _packet_matches_detection(packet, detection):
                continue

            alerts.append(
                create_alert(
                    timestamp=packet["timestamp"],
                    alert_type="SIGMA_RULE_MATCH",
                    severity=rule.get("severity", "medium"),
                    source_ip=packet.get("src_ip"),
                    destination_ip=packet.get("dst_ip"),
                    description=rule.get(
                        "description",
                        rule.get("title", "Sigma rule matched"),
                    ),
                    evidence={
                        "rule_title": rule.get("title"),
                        "rule_file": rule.get("_file"),
                        "rule_type": "sigma",
                        "detection": detection,
                    },
                )
            )

    return alerts