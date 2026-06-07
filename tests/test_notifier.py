"""Tests for tray/notifier.py."""

import sqlite3
from pathlib import Path

from scanner.db import init_db
from scanner.storage import ensure_layout
from tray.notifier import VerdictNotifier, count_pending


def _insert_scan_row(db_path: Path, filename: str, stage: str, verdict: str, risk: float = 0.1):
    import json
    with sqlite3.connect(db_path) as conn:
        conn.execute(
            """
            INSERT INTO scans (filename, stage, verdict, risk_score, report_json, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, datetime('now'), datetime('now'))
            """,
            (filename, stage, verdict, risk, json.dumps({})),
        )


def test_poll_sqlite_new_rows(pipeline_home: Path):
    ensure_layout(pipeline_home)
    init_db(pipeline_home)

    notifications = []

    def on_notify(title, message):
        notifications.append((title, message))

    notifier = VerdictNotifier(on_notify, home=pipeline_home)

    _insert_scan_row(pipeline_home / "scans.db", "game.nsp", "approved", "approved")
    events = notifier.poll_once()

    assert len(events) == 1
    assert events[0].filename == "game.nsp"
    assert events[0].stage == "approved"
    assert events[0].verdict == "approved"


def test_count_pending(pipeline_home: Path):
    paths = ensure_layout(pipeline_home)
    (paths["incoming"] / "a.nsp").write_bytes(b"x")
    (paths["incoming"] / "b.nsp").write_bytes(b"x")
    (paths["scanning"] / "c.nsp").write_bytes(b"x")

    total = count_pending(pipeline_home)
    assert total == 3
