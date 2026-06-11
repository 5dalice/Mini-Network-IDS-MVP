from __future__ import annotations

import argparse
from pathlib import Path

from ids.config import load_blocklist
from ids.database import save_alerts_to_db
from ids.detectors import (
    detect_large_packets,
    detect_malicious_dns,
    detect_malicious_ips,
    detect_port_scan,
    detect_syn_flood,
)
from ids.html_reporter import save_html_report
from ids.parser import parse_pcap
from ids.reporter import (
    filter_alerts_by_severity,
    print_report,
    save_json_report,
)


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Mini Network IDS - analyze .pcap files for suspicious network traffic."
    )

    parser.add_argument(
        "--pcap",
        required=True,
        help="Path to the .pcap file to analyze.",
    )

    parser.add_argument(
        "--output",
        default="reports/report.json",
        help="Path where the JSON report should be written.",
    )

    parser.add_argument(
        "--html-output",
        help="Path where the HTML report should be written.",
    )

    parser.add_argument(
        "--db-output",
        help="Path where alerts should be saved as a SQLite database.",
    )

    parser.add_argument(
        "--rules",
        default="rules",
        help="Directory containing malicious_domains.txt and malicious_ips.txt.",
    )

    parser.add_argument(
        "--severity",
        choices=["low", "medium", "high"],
        help="Only display/save alerts with this severity.",
    )

    parser.add_argument(
        "--show-summary",
        action="store_true",
        help="Show summary counts by severity.",
    )

    return parser


def analyze(pcap_path: str, rules_dir: str) -> list[dict]:
    packets = parse_pcap(pcap_path)

    rules_path = Path(rules_dir)

    domain_blocklist = load_blocklist(
        rules_path / "malicious_domains.txt"
    )

    ip_blocklist = load_blocklist(
        rules_path / "malicious_ips.txt"
    )

    alerts: list[dict] = []

    alerts.extend(detect_port_scan(packets))
    alerts.extend(detect_syn_flood(packets))
    alerts.extend(
        detect_malicious_dns(
            packets,
            domain_blocklist,
        )
    )
    alerts.extend(detect_large_packets(packets))
    alerts.extend(
        detect_malicious_ips(
            packets,
            ip_blocklist,
        )
    )

    return alerts


def main() -> None:
    args = build_arg_parser().parse_args()

    alerts = analyze(
        args.pcap,
        args.rules,
    )

    if args.severity:
        alerts = filter_alerts_by_severity(
            alerts,
            args.severity,
        )

    print_report(
        alerts,
        show_summary=args.show_summary,
    )

    save_json_report(
        alerts,
        args.output,
    )

    if args.html_output:
        save_html_report(
            alerts,
            args.html_output,
        )

    if args.db_output:
        save_alerts_to_db(
            alerts,
            args.db_output,
        )


if __name__ == "__main__":
    main()