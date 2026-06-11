from __future__ import annotations

from datetime import datetime, timezone
from typing import Any


MITRE_MAPPING = {
    "PORT_SCAN": {
        "technique_id": "T1046",
        "technique_name": "Network Service Discovery",
        "tactic": "Discovery",
    },
    "SYN_FLOOD_PATTERN": {
        "technique_id": "T1498",
        "technique_name": "Network Denial of Service",
        "tactic": "Impact",
    },
    "MALICIOUS_DNS_QUERY": {
        "technique_id": "T1071.004",
        "technique_name": "Application Layer Protocol: DNS",
        "tactic": "Command and Control",
    },
    "MALICIOUS_IP_COMMUNICATION": {
        "technique_id": "T1071",
        "technique_name": "Application Layer Protocol",
        "tactic": "Command and Control",
    },
    "REPEATED_LARGE_PACKETS": {
        "technique_id": "T1041",
        "technique_name": "Exfiltration Over C2 Channel",
        "tactic": "Exfiltration",
    },
    "SIGMA_DNS_MATCH": {
        "technique_id": "T1071.004",
        "technique_name": "Application Layer Protocol: DNS",
        "tactic": "Command and Control",
    },
}


ALERT_DISPLAY_NAMES = {
    "PORT_SCAN": "Port Scan Detected",
    "SYN_FLOOD_PATTERN": "TCP SYN Flood Pattern",
    "MALICIOUS_DNS_QUERY": "Malicious DNS Query",
    "REPEATED_LARGE_PACKETS": "Repeated Large Packet Transfer",
    "MALICIOUS_IP_COMMUNICATION": "Malicious IP Communication",
    "SIGMA_DNS_MATCH": "Sigma DNS Rule Match",
}


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
    return {
        "timestamp": iso_timestamp(timestamp),
        "alert_type": alert_type,
        "display_name": ALERT_DISPLAY_NAMES.get(alert_type, alert_type),
        "severity": severity,
        "source_ip": source_ip,
        "destination_ip": destination_ip,
        "description": description,
        "mitre_attack": MITRE_MAPPING.get(alert_type),
        "evidence": evidence,
    }