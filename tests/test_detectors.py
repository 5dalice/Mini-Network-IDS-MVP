from ids.detectors import detect_malicious_dns, detect_malicious_ips, detect_port_scan


def test_detect_port_scan():
    packets = []
    for port in range(1, 23):
        packets.append(
            {
                "timestamp": 1000 + port,
                "src_ip": "192.168.1.10",
                "dst_ip": "192.168.1.20",
                "src_port": 50000 + port,
                "dst_port": port,
                "protocol": "TCP",
                "size": 60,
                "flags": "S",
                "dns_query": None,
            }
        )

    alerts = detect_port_scan(packets, port_threshold=20, window_seconds=60)

    assert len(alerts) == 1
    assert alerts[0]["alert_type"] == "PORT_SCAN"
    assert alerts[0]["severity"] == "medium"


def test_detect_malicious_ip():
    packets = [
        {
            "timestamp": 1000,
            "src_ip": "192.168.1.10",
            "dst_ip": "45.133.1.23",
            "src_port": 12345,
            "dst_port": 443,
            "protocol": "TCP",
            "size": 100,
            "flags": "S",
            "dns_query": None,
        }
    ]

    alerts = detect_malicious_ips(packets, {"45.133.1.23"})

    assert len(alerts) == 1
    assert alerts[0]["alert_type"] == "MALICIOUS_IP_COMMUNICATION"
    assert alerts[0]["severity"] == "high"


def test_detect_malicious_dns():
    packets = [
        {
            "timestamp": 1000,
            "src_ip": "192.168.1.10",
            "dst_ip": "8.8.8.8",
            "src_port": 53000,
            "dst_port": 53,
            "protocol": "UDP",
            "size": 80,
            "flags": None,
            "dns_query": "bad-domain.test",
        }
    ]

    alerts = detect_malicious_dns(packets, {"bad-domain.test"})

    assert len(alerts) == 1
    assert alerts[0]["alert_type"] == "MALICIOUS_DNS_QUERY"
    assert alerts[0]["severity"] == "high"
