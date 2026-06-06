"""Tests for scanner/db.py."""

import json
import threading
from pathlib import Path

from scanner.db import export_json, init_db, load_all, record_entry, update_entry
from scanner.storage import manifest_path


def test_record_and_load(pipeline_home: Path):
    init_db(pipeline_home)
    record_entry(
        {
            "filename": "game.nsp",
            "stage": "quarantined",
            "verdict": "quarantined",
            "risk_score": 0.5,
            "file_type": "NSP",
        },
        pipeline_home,
    )
    entries = load_all(pipeline_home)
    assert len(entries) == 1
    assert entries[0]["filename"] == "game.nsp"
    assert entries[0]["stage"] == "quarantined"
    assert entries[0]["risk_score"] == 0.5


def test_update_entry(pipeline_home: Path):
    init_db(pipeline_home)
    record_entry(
        {
            "filename": "game.nsp",
            "stage": "quarantined",
            "verdict": "quarantined",
            "risk_score": 0.6,
        },
        pipeline_home,
    )
    updated = update_entry(
        "game.nsp",
        stage="approved",
        verdict="approved_manual",
        path=pipeline_home / "approved" / "game.nsp",
        home=pipeline_home,
    )
    assert updated is not None
    assert updated["stage"] == "approved"
    assert updated["verdict"] == "approved_manual"

    entries = load_all(pipeline_home)
    assert entries[0]["stage"] == "approved"


def test_concurrent_writes(pipeline_home: Path):
    init_db(pipeline_home)
    errors: list[Exception] = []

    def writer(i: int):
        try:
            record_entry(
                {
                    "filename": f"file{i}.nsp",
                    "stage": "incoming",
                    "verdict": "pending",
                    "risk_score": 0.0,
                },
                pipeline_home,
            )
        except Exception as e:
            errors.append(e)

    threads = [threading.Thread(target=writer, args=(i,)) for i in range(20)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert not errors
    entries = load_all(pipeline_home)
    assert len(entries) == 20


def test_json_manifest_migration(pipeline_home: Path):
    legacy = {
        "entries": [
            {
                "filename": "legacy.nsp",
                "stage": "approved",
                "verdict": "approved",
                "container_sha256": "abc",
                "timestamp": "2020-01-01T00:00:00+00:00",
                "risk_score": 0.1,
            }
        ]
    }
    mp = manifest_path(pipeline_home)
    pipeline_home.mkdir(parents=True, exist_ok=True)
    mp.write_text(json.dumps(legacy), encoding="utf-8")

    init_db(pipeline_home)
    entries = load_all(pipeline_home)
    assert len(entries) == 1
    assert entries[0]["filename"] == "legacy.nsp"


def test_export_json(pipeline_home: Path):
    init_db(pipeline_home)
    record_entry(
        {"filename": "a.nsp", "stage": "incoming", "verdict": "pending"},
        pipeline_home,
    )
    data = export_json(pipeline_home)
    assert "entries" in data
    assert len(data["entries"]) == 1
