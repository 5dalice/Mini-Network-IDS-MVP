from __future__ import annotations

from collections import defaultdict, deque
from typing import Any

from ids.alerts import create_alert


def _windowed_groups(items: list[dict[str, Any]], window_seconds: int):
    ordered = sorted(items, key=lambda p: p["timestamp"])
    window = deque()

    for packet in ordered:
        window.append(packet)
        while window and packet["timestamp"] - window[0]["timestamp"] > window_seconds:
            window.popleft()
        yield packet, list(window)


def detect_port_scan(
    packets: list[dict[str, Any]],
    *,
    port_threshold: int = 20,
    window_seconds: int = 60,
) -> list[dict[str, Any]]:
    """Detect one source contacting many destination ports on the same target."""
    alerts = []
    candidates = [p for p in packets if p.get("dst_port") is not None]
    seen: set[tuple[str, str, int]] = set()

    for packet, window in _windowed_groups(candidates, window_seconds):
        key = (packet["src_ip"], packet["dst_ip"])
        same_pair = [p for p in window if (p["src_ip"], p["dst_ip"]) == key]
        unique_ports = {p["dst_port"] for p in same_pair if p.get("dst_port") is not None}

        if len(unique_ports) > port_threshold:
            dedupe = (packet["src_ip"], packet["dst_ip"], int(packet["timestamp"] // window_seconds))
            if dedupe in seen:
                continue
            seen.add(dedupe)
            alerts.append(
                create_alert(
                    timestamp=packet["timestamp"],
                    alert_type="PORT_SCAN",
                    severity="medium",
                    source_ip=packet["src_ip"],
                    destination_ip=packet["dst_ip"],
                    description="Possible port scan detected",
                    evidence={
                        "unique_ports": len(unique_ports),
                        "time_window_seconds": window_seconds,
                        "threshold": port_threshold,
                    },
                )
            )
    return alerts


def detect_syn_flood(
    packets: list[dict[str, Any]],
    *,
    syn_threshold: int = 100,
    window_seconds: int = 60,
) -> list[dict[str, Any]]:
    """Detect many TCP SYN packets from the same source within a time window."""
    alerts = []
    syn_packets = [
        p for p in packets
        if p.get("protocol") == "TCP" and p.get("flags") and "S" in p["flags"] and "A" not in p["flags"]
    ]
    seen: set[tuple[str, int]] = set()

    for packet, window in _windowed_groups(syn_packets, window_seconds):
        same_src = [p for p in window if p["src_ip"] == packet["src_ip"]]
        if len(same_src) > syn_threshold:
            dedupe = (packet["src_ip"], int(packet["timestamp"] // window_seconds))
            if dedupe in seen:
                continue
            seen.add(dedupe)
            severity = "high" if len(same_src) > syn_threshold * 2 else "medium"
            alerts.append(
                create_alert(
                    timestamp=packet["timestamp"],
                    alert_type="SYN_FLOOD_PATTERN",
                    severity=severity,
                    source_ip=packet["src_ip"],
                    destination_ip=packet["dst_ip"],
                    description="High number of TCP SYN packets detected from one source",
                    evidence={
                        "syn_packets": len(same_src),
                        "time_window_seconds": window_seconds,
                        "threshold": syn_threshold,
                    },
                )
            )
    return alerts


def detect_malicious_dns(
    packets: list[dict[str, Any]],
    domain_blocklist: set[str],
) -> list[dict[str, Any]]:
    alerts = []
    for packet in packets:
        query = packet.get("dns_query")
        if query and query.lower().rstrip(".") in domain_blocklist:
            alerts.append(
                create_alert(
                    timestamp=packet["timestamp"],
                    alert_type="MALICIOUS_DNS_QUERY",
                    severity="high",
                    source_ip=packet["src_ip"],
                    destination_ip=packet["dst_ip"],
                    description="DNS query matched malicious domain blocklist",
                    evidence={"domain": query},
                )
            )
    return alerts


def detect_large_packets(
    packets: list[dict[str, Any]],
    *,
    size_threshold: int = 1400,
    repeated_threshold: int = 5,
    window_seconds: int = 60,
) -> list[dict[str, Any]]:
    """Detect repeated unusually large packets between the same endpoints."""
    alerts = []
    large_packets = [p for p in packets if p.get("size", 0) > size_threshold]
    seen: set[tuple[str, str, int]] = set()

    for packet, window in _windowed_groups(large_packets, window_seconds):
        key = (packet["src_ip"], packet["dst_ip"])
        same_pair = [p for p in window if (p["src_ip"], p["dst_ip"]) == key]
        if len(same_pair) >= repeated_threshold:
            dedupe = (packet["src_ip"], packet["dst_ip"], int(packet["timestamp"] // window_seconds))
            if dedupe in seen:
                continue
            seen.add(dedupe)
            severity = "medium" if len(same_pair) >= repeated_threshold * 2 else "low"
            alerts.append(
                create_alert(
                    timestamp=packet["timestamp"],
                    alert_type="REPEATED_LARGE_PACKETS",
                    severity=severity,
                    source_ip=packet["src_ip"],
                    destination_ip=packet["dst_ip"],
                    description="Repeated unusually large packets detected",
                    evidence={
                        "packet_count": len(same_pair),
                        "size_threshold": size_threshold,
                        "time_window_seconds": window_seconds,
                    },
                )
            )
    return alerts


def detect_malicious_ips(
    packets: list[dict[str, Any]],
    ip_blocklist: set[str],
) -> list[dict[str, Any]]:
    alerts = []
    for packet in packets:
        src_match = packet["src_ip"].lower() in ip_blocklist
        dst_match = packet["dst_ip"].lower() in ip_blocklist
        if src_match or dst_match:
            matched_ip = packet["src_ip"] if src_match else packet["dst_ip"]
            alerts.append(
                create_alert(
                    timestamp=packet["timestamp"],
                    alert_type="MALICIOUS_IP_COMMUNICATION",
                    severity="high",
                    source_ip=packet["src_ip"],
                    destination_ip=packet["dst_ip"],
                    description="Packet matched malicious IP blocklist",
                    evidence={"matched_ip": matched_ip},
                )
            )
    return alerts
