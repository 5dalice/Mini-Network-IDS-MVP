from __future__ import annotations


SEVERITY_SCORES = {
    "low": 10,
    "medium": 30,
    "high": 60,
}


ALERT_TYPE_WEIGHTS = {
    "PORT_SCAN": 20,
    "SYN_FLOOD_PATTERN": 35,
    "MALICIOUS_DNS_QUERY": 40,
    "MALICIOUS_IP_COMMUNICATION": 50,
    "REPEATED_LARGE_PACKETS": 20,
    "SIGMA_DNS_MATCH": 35,
    "SIGMA_RULE_MATCH": 35,
}


MITRE_TACTIC_WEIGHTS = {
    "Discovery": 10,
    "Command and Control": 25,
    "Exfiltration": 30,
    "Impact": 30,
}


THREAT_INTEL_ALERTS = {
    "MALICIOUS_DNS_QUERY",
    "MALICIOUS_IP_COMMUNICATION",
    "SIGMA_DNS_MATCH",
    "SIGMA_RULE_MATCH",
}


def calculate_risk_level(score: int) -> str:
    if score >= 90:
        return "critical"

    if score >= 70:
        return "high"

    if score >= 40:
        return "medium"

    return "low"


def calculate_threat_score(alert: dict) -> int:
    severity = alert.get("severity", "low")
    alert_type = alert.get("alert_type", "")

    score = 0

    score += SEVERITY_SCORES.get(severity, 10)
    score += ALERT_TYPE_WEIGHTS.get(alert_type, 0)

    mitre = alert.get("mitre_attack") or {}
    tactic = mitre.get("tactic")

    if tactic:
        score += MITRE_TACTIC_WEIGHTS.get(tactic, 0)

    evidence = alert.get("evidence") or {}

    if alert_type in THREAT_INTEL_ALERTS:
        score += 15

    if evidence.get("rule_type") == "sigma":
        score += 10

    return min(score, 100)


def apply_threat_scores(alerts: list[dict]) -> list[dict]:
    for alert in alerts:
        score = calculate_threat_score(alert)

        alert["threat_score"] = score
        alert["risk_level"] = calculate_risk_level(score)

    return alerts