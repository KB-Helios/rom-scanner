"""Tests for scanner/recovery.py."""

from pathlib import Path

from scanner.recovery import recover_orphans
from scanner.storage import ensure_layout


def test_orphan_in_scanning_requeued(pipeline_home: Path):
    paths = ensure_layout(pipeline_home)
    orphan = paths["scanning"] / "stuck.nsp"
    orphan.write_bytes(b"PFS0" + b"\x00" * 32)

    results = recover_orphans(pipeline_home, requeue=True)
    assert len(results) == 1
    assert results[0] == ("stuck.nsp", "requeued")
    assert (paths["incoming"] / "stuck.nsp").is_file()
    assert not orphan.exists()


def test_orphan_quarantined_with_verdict(pipeline_home: Path):
    paths = ensure_layout(pipeline_home)
    orphan = paths["scanning"] / "crashed.nsp"
    orphan.write_bytes(b"PFS0" + b"\x00" * 32)

    results = recover_orphans(pipeline_home, requeue=False)
    assert results[0][1] == "quarantined"
    assert (paths["quarantined"] / "crashed.nsp").is_file()


def test_empty_scanning_dir(pipeline_home: Path):
    ensure_layout(pipeline_home)
    assert recover_orphans(pipeline_home) == []
