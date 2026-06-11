from __future__ import annotations

from pathlib import Path
from html import escape


def save_html_report(alerts: list[dict], output_path: str | Path) -> None:
    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)

    rows = []

    for alert in alerts:
        mitre = alert.get("mitre_attack") or {}

        rows.append(
            f"""
            <tr>
                <td>{escape(alert.get("timestamp", ""))}</td>
                <td class="{escape(alert.get("severity", ""))}">
                    {escape(alert.get("severity", ""))}
                </td>
                <td>{escape(alert.get("alert_type", ""))}</td>
                <td>{escape(str(alert.get("source_ip", "")))}</td>
                <td>{escape(str(alert.get("destination_ip", "")))}</td>
                <td>{escape(alert.get("description", ""))}</td>
                <td>{escape(mitre.get("technique_id", ""))}</td>
                <td>{escape(mitre.get("technique_name", ""))}</td>
            </tr>
            """
        )

    html = f"""
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>Mini Network IDS Report</title>

<style>
body {{
    font-family: Arial, sans-serif;
    margin: 40px;
    background-color: #f4f4f4;
}}

h1 {{
    color: #222;
}}

table {{
    width: 100%;
    border-collapse: collapse;
    background: white;
}}

th, td {{
    border: 1px solid #ddd;
    padding: 10px;
    text-align: left;
}}

th {{
    background-color: #222;
    color: white;
}}

.high {{
    color: red;
    font-weight: bold;
}}

.medium {{
    color: orange;
    font-weight: bold;
}}

.low {{
    color: green;
    font-weight: bold;
}}
</style>
</head>

<body>

<h1>Mini Network IDS Report</h1>

<p><strong>Total alerts:</strong> {len(alerts)}</p>

<table>
<thead>
<tr>
<th>Timestamp</th>
<th>Severity</th>
<th>Alert Type</th>
<th>Source IP</th>
<th>Destination IP</th>
<th>Description</th>
<th>MITRE ID</th>
<th>MITRE Technique</th>
</tr>
</thead>

<tbody>
{''.join(rows)}
</tbody>

</table>

</body>
</html>
"""

    path.write_text(html, encoding="utf-8")