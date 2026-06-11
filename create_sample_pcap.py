from scapy.all import IP, TCP, UDP, DNS, DNSQR, Raw, wrpcap

packets = []
base_time = 1718020800

# Port scan: same source, same destination, many destination ports
for i, port in enumerate(range(1, 25)):
    pkt = IP(src="192.168.1.10", dst="192.168.1.20") / TCP(sport=50000 + i, dport=port, flags="S")
    pkt.time = base_time + i
    packets.append(pkt)

# Malicious DNS query
pkt = (
    IP(src="192.168.1.30", dst="8.8.8.8")
    / UDP(sport=53000, dport=53)
    / DNS(rd=1, qd=DNSQR(qname="bad-domain.test"))
)
pkt.time = base_time + 30
packets.append(pkt)

# Malicious IP communication
pkt = IP(src="192.168.1.40", dst="45.133.1.23") / TCP(sport=44444, dport=443, flags="S")
pkt.time = base_time + 31
packets.append(pkt)

# Repeated large packets
for i in range(5):
    pkt = (
        IP(src="192.168.1.50", dst="192.168.1.60")
        / UDP(sport=40000 + i, dport=9999)
        / Raw(load=b"A" * 1500)
    )
    pkt.time = base_time + 40 + i
    packets.append(pkt)

wrpcap("samples/test_traffic.pcap", packets)

print("Created samples/test_traffic.pcap")