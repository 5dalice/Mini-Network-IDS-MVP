# Mini Network IDS

Mini Network IDS is a lightweight Python-based intrusion detection system that analyzes `.pcap` files and detects suspicious network behavior such as port scanning, SYN flooding patterns, malicious DNS queries, repeated large packets, and communication with known suspicious IP addresses.

The project is designed as a defensive cybersecurity portfolio project focused on network traffic analysis, alert generation, and security automation.

## Features

- Reads `.pcap` files with Scapy
- Extracts normalized packet metadata
- Detects suspicious traffic using rule-based logic
- Prints alerts in the terminal using Rich
- Exports JSON reports
- Supports simple blocklists for domains and IP addresses
- Includes pytest-based tests

## Installation

```bash
python -m venv .venv
source .venv/bin/activate  # Linux/macOS
pip install -r requirements.txt
```

On Windows PowerShell:

```powershell
python -m venv .venv
.venv\Scripts\Activate.ps1
pip install -r requirements.txt
```

## Usage

```bash
python mini_ids.py --pcap samples/test_traffic.pcap --output reports/report.json --show-summary
```

Filter by severity:

```bash
python mini_ids.py --pcap samples/test_traffic.pcap --severity high
```

Use a custom rules directory:

```bash
python mini_ids.py --pcap samples/test_traffic.pcap --rules rules/
```

## Detection Rules

| Rule | Description | Severity |
|---|---|---|
| PORT_SCAN | One source contacts more than 20 destination ports on the same target within 60 seconds | medium |
| SYN_FLOOD_PATTERN | One source sends more than 100 TCP SYN packets within 60 seconds | medium/high |
| MALICIOUS_DNS_QUERY | DNS query matches malicious domain blocklist | high |
| REPEATED_LARGE_PACKETS | Repeated packets larger than 1400 bytes | low/medium |
| MALICIOUS_IP_COMMUNICATION | Source or destination IP matches malicious IP blocklist | high |

## Alert Format

```json
{
  "timestamp": "2026-06-10T12:00:00+00:00",
  "alert_type": "PORT_SCAN",
  "severity": "medium",
  "source_ip": "192.168.1.10",
  "destination_ip": "192.168.1.20",
  "description": "Possible port scan detected",
  "evidence": {
    "unique_ports": 25,
    "time_window_seconds": 60
  }
}
```

## Run Tests

```bash
pytest
```

## Limitations

- This version analyzes saved `.pcap` files only.
- It does not sniff live traffic.
- Detection logic is rule-based and intentionally simple.
- Blocklists are local static files.
- Alerts are indicators, not proof of compromise.

## Ethics

Use this project only for:

- owned lab environments
- education
- authorized traffic analysis
- defensive security work

Do not use it for unauthorized monitoring, intrusion, exploitation, or surveillance.

## Future Improvements

- Live packet sniffing
- SQLite storage
- HTML report
- Docker support
- GitHub Actions
- MITRE ATT&CK mapping
- Suricata rule import
- GeoIP lookup
- Web dashboard
