from __future__ import annotations


SEVERITY_SCORES = {
    "low": 10,
    "medium": 30,
    "high": 60,
}


ALERT_TYPE_BONUS = {
    "PORT_SCAN": 20,
    "SYN_FLOOD_PATTERN": 30,
    "MALICIOUS_DNS_QUERY": 40,
    "MALICIOUS_IP_COMMUNICATION": 50,
    "REPEATED_LARGE_PACKETS": 15,
    "SIGMA_DNS_MATCH": 35,
    "SIGMA_RULE_MATCH": 35,
}


def calculate_threat_score(alert: dict) -> int:
    severity = alert.get("severity", "low")
    alert_type = alert.get("alert_type", "")

    base_score = SEVERITY_SCORES.get(severity, 10)
    bonus_score = ALERT_TYPE_BONUS.get(alert_type, 0)

    score = base_score + bonus_score

    return min(score, 100)


def apply_threat_scores(alerts: list[dict]) -> list[dict]:
    for alert in alerts:
        alert["threat_score"] = calculate_threat_score(alert)

        if alert["threat_score"] >= 80:
            alert["risk_level"] = "critical"
        elif alert["threat_score"] >= 60:
            alert["risk_level"] = "high"
        elif alert["threat_score"] >= 30:
            alert["risk_level"] = "medium"
        else:
            alert["risk_level"] = "low"

    return alerts