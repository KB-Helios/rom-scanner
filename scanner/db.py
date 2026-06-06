"""
SQLite manifest storage.
========================
WAL-mode SQLite backend for scan records with migration from manifest.json.
"""

import json
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterator, List, Optional

from scanner.config import db_path
from scanner.storage import manifest_path


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


SCHEMA = """
CREATE TABLE IF NOT EXISTS scans (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    filename TEXT NOT NULL,
    stage TEXT NOT NULL,
    verdict TEXT NOT NULL,
    container_sha256 TEXT,
    risk_score REAL,
    report_json TEXT NOT NULL,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_scans_filename ON scans(filename);
CREATE INDEX IF NOT EXISTS idx_scans_stage ON scans(stage);
"""


@contextmanager
def _connect(home: Optional[Path] = None) -> Iterator[sqlite3.Connection]:
    path = db_path(home)
    path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(path), timeout=30.0)
    conn.row_factory = sqlite3.Row
    try:
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA foreign_keys=ON")
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def init_db(home: Optional[Path] = None) -> None:
    """Create schema and migrate from manifest.json if present."""
    with _connect(home) as conn:
        conn.executescript(SCHEMA)
    _migrate_json_manifest(home)


def _migrate_json_manifest(home: Optional[Path] = None) -> None:
    """One-time import from legacy manifest.json."""
    json_path = manifest_path(home)
    if not json_path.exists():
        return

    with _connect(home) as conn:
        count = conn.execute("SELECT COUNT(*) FROM scans").fetchone()[0]
        if count > 0:
            return

        try:
            with open(json_path, encoding="utf-8") as f:
                data = json.load(f)
        except (json.JSONDecodeError, OSError):
            return

        for entry in data.get("entries", []):
            _insert_entry(conn, entry)


def _insert_entry(conn: sqlite3.Connection, entry: Dict[str, Any]) -> None:
    ts = entry.get("timestamp") or _utc_now()
    report = {k: v for k, v in entry.items()
              if k not in ("filename", "stage", "verdict", "container_sha256", "timestamp")}
    conn.execute(
        """
        INSERT INTO scans (filename, stage, verdict, container_sha256, risk_score,
                           report_json, created_at, updated_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            entry.get("filename", ""),
            entry.get("stage", ""),
            entry.get("verdict", ""),
            entry.get("container_sha256", ""),
            entry.get("risk_score", 0.0),
            json.dumps(report),
            ts,
            ts,
        ),
    )


def _row_to_entry(row: sqlite3.Row) -> Dict[str, Any]:
    report = json.loads(row["report_json"])
    entry = {
        "filename": row["filename"],
        "stage": row["stage"],
        "verdict": row["verdict"],
        "container_sha256": row["container_sha256"] or "",
        "risk_score": row["risk_score"] or 0.0,
        "timestamp": row["updated_at"],
    }
    entry.update(report)
    return entry


def load_all(home: Optional[Path] = None) -> List[Dict[str, Any]]:
    """Load all manifest entries (newest first)."""
    init_db(home)
    with _connect(home) as conn:
        rows = conn.execute(
            "SELECT * FROM scans ORDER BY updated_at DESC"
        ).fetchall()
    return [_row_to_entry(r) for r in rows]


def record_entry(entry: Dict[str, Any], home: Optional[Path] = None) -> Dict[str, Any]:
    """Insert a manifest entry dict."""
    init_db(home)
    ts = entry.get("timestamp") or _utc_now()
    report = {k: v for k, v in entry.items()
              if k not in ("filename", "stage", "verdict", "container_sha256", "timestamp")}
    with _connect(home) as conn:
        conn.execute(
            """
            INSERT INTO scans (filename, stage, verdict, container_sha256, risk_score,
                               report_json, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                entry.get("filename", ""),
                entry.get("stage", ""),
                entry.get("verdict", ""),
                entry.get("container_sha256", ""),
                entry.get("risk_score", 0.0),
                json.dumps(report),
                ts,
                ts,
            ),
        )
    return entry


def update_entry(
    filename: str,
    *,
    stage: str,
    verdict: str,
    path: Optional[Path] = None,
    home: Optional[Path] = None,
) -> Optional[Dict[str, Any]]:
    """Update the latest entry matching filename."""
    init_db(home)
    basename = Path(filename).name
    with _connect(home) as conn:
        row = conn.execute(
            """
            SELECT * FROM scans WHERE filename = ?
            ORDER BY updated_at DESC LIMIT 1
            """,
            (basename,),
        ).fetchone()
        if row is None:
            return None

        report = json.loads(row["report_json"])
        if path is not None:
            report["path"] = str(path)
        ts = _utc_now()
        conn.execute(
            """
            UPDATE scans SET stage = ?, verdict = ?, report_json = ?, updated_at = ?
            WHERE id = ?
            """,
            (stage, verdict, json.dumps(report), ts, row["id"]),
        )

    updated = _row_to_entry(row)
    updated["stage"] = stage
    updated["verdict"] = verdict
    updated["timestamp"] = ts
    if path is not None:
        updated["path"] = str(path)
    return updated


def export_json(home: Optional[Path] = None) -> Dict[str, Any]:
    """Export manifest as legacy JSON structure."""
    entries = load_all(home)
    return {"entries": entries}
