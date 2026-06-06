"""
Poll scan storage for new verdicts and emit tray notifications.
==============================================================
Primary source: SQLite scans.db (Phase 4 schema).
Fallback: manifest.json entries when the database is unavailable.
"""

from __future__ import annotations

import json
import sqlite3
import threading
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, List, Optional

from scanner.storage import get_home, manifest_path, stage_paths

NotifyCallback = Callable[[str, str], None]


@dataclass
class ScanEvent:
    """A scan verdict suitable for tray display."""

    scan_id: int
    filename: str
    stage: str
    verdict: str
    risk_score: float
    updated_at: str


def scans_db_path(home: Optional[Path] = None) -> Path:
    return (home or get_home()) / "scans.db"


class VerdictNotifier:
    """Background poller for new scan verdicts."""

    def __init__(
        self,
        on_notify: NotifyCallback,
        *,
        home: Optional[Path] = None,
        poll_interval_sec: float = 5.0,
    ) -> None:
        self._home = home or get_home()
        self._on_notify = on_notify
        self._poll_interval = poll_interval_sec
        self._stop = threading.Event()
        self._thread: Optional[threading.Thread] = None
        self._last_sqlite_id = 0
        self._seen_manifest_keys: set[str] = set()
        self._bootstrap_cursor()

    def _bootstrap_cursor(self) -> None:
        db = scans_db_path(self._home)
        if db.exists():
            try:
                with sqlite3.connect(db) as conn:
                    row = conn.execute("SELECT MAX(id) FROM scans").fetchone()
                    self._last_sqlite_id = int(row[0] or 0)
            except sqlite3.Error:
                self._last_sqlite_id = 0
        else:
            for entry in _load_manifest_entries(self._home):
                key = _manifest_key(entry)
                self._seen_manifest_keys.add(key)

    def start(self) -> None:
        if self._thread and self._thread.is_alive():
            return
        self._stop.clear()
        self._thread = threading.Thread(target=self._poll_loop, daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=self._poll_interval + 2)

    def _poll_loop(self) -> None:
        while not self._stop.wait(self._poll_interval):
            for event in self.poll_once():
                title, message = format_notification(event)
                self._on_notify(title, message)

    def poll_once(self) -> List[ScanEvent]:
        db = scans_db_path(self._home)
        if db.exists():
            events = self._poll_sqlite(db)
            if events is not None:
                return events
        return self._poll_manifest()

    def _poll_sqlite(self, db: Path) -> Optional[List[ScanEvent]]:
        try:
            with sqlite3.connect(db) as conn:
                conn.row_factory = sqlite3.Row
                rows = conn.execute(
                    """
                    SELECT id, filename, stage, verdict, risk_score, updated_at
                    FROM scans
                    WHERE id > ?
                    ORDER BY id ASC
                    """,
                    (self._last_sqlite_id,),
                ).fetchall()
        except sqlite3.Error:
            return None

        events: List[ScanEvent] = []
        for row in rows:
            self._last_sqlite_id = int(row["id"])
            events.append(
                ScanEvent(
                    scan_id=int(row["id"]),
                    filename=row["filename"],
                    stage=row["stage"],
                    verdict=row["verdict"],
                    risk_score=float(row["risk_score"] or 0.0),
                    updated_at=row["updated_at"] or "",
                )
            )
        return events

    def _poll_manifest(self) -> List[ScanEvent]:
        events: List[ScanEvent] = []
        for index, entry in enumerate(_load_manifest_entries(self._home)):
            key = _manifest_key(entry)
            if key in self._seen_manifest_keys:
                continue
            self._seen_manifest_keys.add(key)
            events.append(
                ScanEvent(
                    scan_id=index,
                    filename=entry.get("filename", "?"),
                    stage=entry.get("stage", "?"),
                    verdict=entry.get("verdict", "?"),
                    risk_score=float(entry.get("risk_score", 0.0)),
                    updated_at=entry.get("timestamp", ""),
                )
            )
        return events


def _load_manifest_entries(home: Path) -> List[dict]:
    path = manifest_path(home)
    if not path.exists():
        return []
    try:
        with open(path, encoding="utf-8") as handle:
            data = json.load(handle)
    except (OSError, json.JSONDecodeError):
        return []
    entries = data.get("entries", [])
    return sorted(entries, key=lambda item: item.get("timestamp", ""))


def _manifest_key(entry: dict) -> str:
    return f"{entry.get('filename', '')}:{entry.get('timestamp', '')}:{entry.get('verdict', '')}"


def format_notification(event: ScanEvent) -> tuple[str, str]:
    if event.verdict in ("approved", "approved_manual") or event.stage == "approved":
        title = "ROM approved"
        message = f"{event.filename} passed scanning (risk {event.risk_score:.2f})"
    elif event.verdict == "scan_interrupted":
        title = "Scan interrupted"
        message = f"{event.filename} was re-queued after an interrupted scan"
    else:
        title = "ROM quarantined"
        message = f"{event.filename} failed scanning (risk {event.risk_score:.2f})"
    return title, message


def count_pending(home: Optional[Path] = None) -> int:
    """Count files waiting in incoming/ or scanning/."""
    root = home or get_home()
    total = 0
    for stage in ("incoming", "scanning"):
        stage_dir = stage_paths(root).get(stage)
        if stage_dir and stage_dir.is_dir():
            total += sum(1 for item in stage_dir.iterdir() if item.is_file())
    return total


def latest_verdict_summary(home: Optional[Path] = None) -> str:
    """Short status line for the tray menu."""
    pending = count_pending(home)
    db = scans_db_path(home or get_home())
    if db.exists():
        try:
            with sqlite3.connect(db) as conn:
                row = conn.execute(
                    """
                    SELECT filename, verdict, updated_at
                    FROM scans
                    ORDER BY id DESC
                    LIMIT 1
                    """
                ).fetchone()
            if row:
                filename, verdict, updated_at = row
                ts = (updated_at or "")[:19].replace("T", " ")
                pending_note = f", {pending} pending" if pending else ""
                return f"Last: {filename} -> {verdict} ({ts}){pending_note}"
        except sqlite3.Error:
            pass

    entries = _load_manifest_entries(home or get_home())
    if entries:
        latest = entries[-1]
        filename = latest.get("filename", "?")
        verdict = latest.get("verdict", "?")
        ts = latest.get("timestamp", "")[:19].replace("T", " ")
        pending_note = f", {pending} pending" if pending else ""
        return f"Last: {filename} -> {verdict} ({ts}){pending_note}"

    if pending:
        return f"{pending} file(s) pending scan"
    return "No scans yet"
