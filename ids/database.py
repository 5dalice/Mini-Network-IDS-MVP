from __future__ import annotations

import json
import sqlite3
from pathlib import Path


def init_db(db_path: str | Path) -> None:
    path = Path(db_path)
    path.parent.mkdir(parents=True, exist_ok=True)

    with sqlite3.connect(path) as conn:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS alerts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                alert_type TEXT NOT NULL,
                severity TEXT NOT NULL,
                source_ip TEXT,
                destination_ip TEXT,
                description TEXT NOT NULL,
                mitre_attack TEXT,
                evidence TEXT
            )
            """
        )


def save_alerts_to_db(alerts: list[dict], db_path: str | Path) -> None:
    init_db(db_path)

    with sqlite3.connect(db_path) as conn:
        conn.executemany(
            """
            INSERT INTO alerts (
                timestamp,
                alert_type,
                severity,
                source_ip,
                destination_ip,
                description,
                mitre_attack,
                evidence
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            [
                (
                    alert.get("timestamp"),
                    alert.get("alert_type"),
                    alert.get("severity"),
                    alert.get("source_ip"),
                    alert.get("destination_ip"),
                    alert.get("description"),
                    json.dumps(alert.get("mitre_attack"), ensure_ascii=False),
                    json.dumps(alert.get("evidence"), ensure_ascii=False),
                )
                for alert in alerts
            ],
        )