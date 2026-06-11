from ids.alerts import create_alert


def test_create_alert_has_required_fields():
    alert = create_alert(
        timestamp=1718020800,
        alert_type="PORT_SCAN",
        severity="medium",
        source_ip="192.168.1.10",
        destination_ip="192.168.1.20",
        description="Possible port scan detected",
        evidence={"unique_ports": 25},
    )

    assert alert["alert_type"] == "PORT_SCAN"
    assert alert["severity"] == "medium"
    assert alert["source_ip"] == "192.168.1.10"
    assert alert["destination_ip"] == "192.168.1.20"
    assert "timestamp" in alert
    assert "evidence" in alert
