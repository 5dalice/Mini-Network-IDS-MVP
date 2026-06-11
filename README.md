# Mini Network IDS

Mini Network IDS is a Python-based intrusion detection and incident analysis platform that analyzes `.pcap` files, detects suspicious network activity, applies threat scoring, correlates alerts into incidents, and visualizes results through a web dashboard.

## Features

* PCAP analysis using Scapy
* Rule-based network detections
* Sigma-style detection rules (YAML)
* MITRE ATT&CK mapping
* Threat scoring and risk levels
* Incident correlation engine
* SQLite alert storage
* JSON and HTML reports
* Flask web dashboard
* Chart.js visualizations
* Severity filtering and IP search
* Automated tests with pytest

## Detection Capabilities

* Port Scan Detection
* SYN Flood Detection
* Malicious DNS Queries
* Malicious IP Communication
* Large Packet Transfer Detection
* Sigma Rule Matching

## Technologies

* Python
* Flask
* SQLite
* Scapy
* PyYAML
* Chart.js
* Pytest
* MITRE ATT&CK
* Sigma Rules

## Quick Start

```bash
python mini_ids.py \
  --pcap samples/test_traffic.pcap \
  --output reports/report.json \
  --db-output data/alerts.db \
  --show-summary
```

Start the dashboard:

```bash
python dashboard.py
```

Open:

```text
http://127.0.0.1:5000
```

## Current SOC Features

* Alert generation
* Threat intelligence matching
* MITRE ATT&CK enrichment
* Threat scoring
* Risk classification
* Incident correlation
* Dashboard analytics
* Incident investigation workflow

## Future Improvements

* Case management
* Analyst notes
* GeoIP enrichment
* Docker deployment
* GitHub Actions CI/CD
* Threat intelligence feeds
* Live packet capture
* MITRE Navigator export
