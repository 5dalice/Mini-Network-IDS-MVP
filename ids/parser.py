from __future__ import annotations

from pathlib import Path
from typing import Any

from scapy.all import DNS, DNSQR, IP, TCP, UDP, rdpcap


def _protocol(packet: Any) -> str:
    if packet.haslayer(TCP):
        return "TCP"
    if packet.haslayer(UDP):
        return "UDP"
    if packet.haslayer(IP):
        return "IP"
    return "OTHER"


def _dns_query(packet: Any) -> str | None:
    if packet.haslayer(DNSQR):
        query = packet[DNSQR].qname
        if isinstance(query, bytes):
            query = query.decode(errors="ignore")
        return str(query).rstrip(".").lower()
    return None


def normalize_packet(packet: Any) -> dict[str, Any] | None:
    """Normalize a Scapy packet into the IDS internal dictionary format."""
    if not packet.haslayer(IP):
        return None

    src_port = None
    dst_port = None
    flags = None

    if packet.haslayer(TCP):
        src_port = int(packet[TCP].sport)
        dst_port = int(packet[TCP].dport)
        flags = str(packet[TCP].flags)
    elif packet.haslayer(UDP):
        src_port = int(packet[UDP].sport)
        dst_port = int(packet[UDP].dport)

    return {
        "timestamp": float(packet.time),
        "src_ip": packet[IP].src,
        "dst_ip": packet[IP].dst,
        "src_port": src_port,
        "dst_port": dst_port,
        "protocol": _protocol(packet),
        "size": len(packet),
        "flags": flags,
        "dns_query": _dns_query(packet),
    }


def parse_pcap(path: str | Path) -> list[dict[str, Any]]:
    """Read a .pcap file and return normalized IP packets."""
    pcap_path = Path(path)
    if not pcap_path.exists():
        raise FileNotFoundError(f"PCAP file not found: {pcap_path}")

    packets = rdpcap(str(pcap_path))
    normalized = [normalize_packet(packet) for packet in packets]
    return [packet for packet in normalized if packet is not None]
