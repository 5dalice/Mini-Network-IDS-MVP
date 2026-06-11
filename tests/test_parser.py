from scapy.all import IP, TCP

from ids.parser import normalize_packet


def test_normalize_tcp_packet():
    packet = IP(src="192.168.1.10", dst="192.168.1.20") / TCP(sport=12345, dport=80, flags="S")
    packet.time = 1718020800

    normalized = normalize_packet(packet)

    assert normalized["src_ip"] == "192.168.1.10"
    assert normalized["dst_ip"] == "192.168.1.20"
    assert normalized["src_port"] == 12345
    assert normalized["dst_port"] == 80
    assert normalized["protocol"] == "TCP"
    assert normalized["flags"] == "S"
