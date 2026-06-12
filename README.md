# Mini Network IDS

Mini Network IDS is a Python-based cybersecurity lab project that analyzes `.pcap` files and identifies potentially suspicious network activity using rule-based detections.

The project demonstrates packet analysis, detection engineering, Sigma-style rules, MITRE ATT&CK mapping, threat scoring, incident correlation, and dashboard-based alert investigation.

## Features

- PCAP analysis with Scapy
- Rule-based network detections
- Sigma-style detection rules
- MITRE ATT&CK enrichment
- Threat scoring and risk levels
- Incident correlation
- SQLite alert storage
- JSON and HTML reporting
- Flask web dashboard
- Automated tests with pytest

## Detection Capabilities

- Port Scan Detection
- SYN Flood Detection
- Malicious DNS Queries
- Malicious IP Communication
- Large Packet Transfer Detection
- Sigma Rule Matching

## Installation

```bash
pip install -r requirements.txt