from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml

from ids.alerts import create_alert


def load_sigma_rules(rules_dir: str = "rules/sigma") -> list[dict[str, Any]]:
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


def run_sigma_rules(
    packets: list[dict[str, Any]],
    rules: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    alerts = []

    for rule in rules:
        detection = rule.get("detection", {})
        domains = detection.get("domain", [])

        if not domains:
            continue

        normalized_domains = {
            domain.lower().rstrip(".")
            for domain in domains
        }

        for packet in packets:
            dns_query = packet.get("dns_query")

            if not dns_query:
                continue

            normalized_query = dns_query.lower().rstrip(".")

            if normalized_query in normalized_domains:
                alerts.append(
                    create_alert(
                        timestamp=packet["timestamp"],
                        alert_type="SIGMA_DNS_MATCH",
                        severity=rule.get("severity", "medium"),
                        source_ip=packet["src_ip"],
                        destination_ip=packet["dst_ip"],
                        description=rule.get(
                            "description",
                            rule.get("title", "Sigma rule matched"),
                        ),
                        evidence={
                            "rule_title": rule.get("title"),
                            "rule_file": rule.get("_file"),
                            "matched_domain": normalized_query,
                            "rule_type": "sigma",
                        },
                    )
                )

    return alerts