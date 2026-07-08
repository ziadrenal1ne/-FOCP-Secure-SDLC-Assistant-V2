"""SQLite database for scan history."""

from __future__ import annotations

import json
import logging
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from focp_sec.core.config import get_config
from focp_sec.core.models import ScanResult

logger = logging.getLogger(__name__)


class ScanDatabase:
    """Persistent storage for scan results."""

    def __init__(self, db_path: Path | None = None) -> None:
        self.db_path = db_path or get_config().database_path
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._init_db()

    def _init_db(self) -> None:
        """Initialize database schema."""
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS scans (
                    scan_id TEXT PRIMARY KEY,
                    project_path TEXT NOT NULL,
                    project_name TEXT NOT NULL,
                    timestamp TEXT NOT NULL,
                    score REAL NOT NULL,
                    findings_count INTEGER NOT NULL,
                    result_json TEXT NOT NULL
                )
            """)
            conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_scans_timestamp ON scans(timestamp DESC)
            """)
            conn.commit()

    def save_scan(self, result: ScanResult) -> None:
        """Save scan result to database."""
        with sqlite3.connect(self.db_path) as conn:
            conn.execute(
                """
                INSERT OR REPLACE INTO scans
                (scan_id, project_path, project_name, timestamp, score, findings_count, result_json)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    result.scan_id,
                    result.project.path,
                    result.project.name,
                    result.timestamp.isoformat(),
                    result.score.overall,
                    len(result.all_findings),
                    json.dumps(result.to_dict()),
                ),
            )
            conn.commit()
        logger.info("Saved scan %s to database", result.scan_id)

    def get_scan(self, scan_id: str) -> dict[str, Any] | None:
        """Retrieve scan by ID."""
        with sqlite3.connect(self.db_path) as conn:
            row = conn.execute(
                "SELECT result_json FROM scans WHERE scan_id = ?", (scan_id,)
            ).fetchone()
        if row:
            return json.loads(row[0])
        return None

    def list_scans(self, limit: int = 50) -> list[dict[str, Any]]:
        """List recent scans."""
        with sqlite3.connect(self.db_path) as conn:
            rows = conn.execute(
                """
                SELECT scan_id, project_path, project_name, timestamp, score, findings_count
                FROM scans ORDER BY timestamp DESC LIMIT ?
                """,
                (limit,),
            ).fetchall()
        return [
            {
                "scan_id": r[0],
                "project_path": r[1],
                "project_name": r[2],
                "timestamp": r[3],
                "score": r[4],
                "findings_count": r[5],
            }
            for r in rows
        ]

    def delete_scan(self, scan_id: str) -> bool:
        """Delete scan by ID."""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.execute("DELETE FROM scans WHERE scan_id = ?", (scan_id,))
            conn.commit()
            return cursor.rowcount > 0
