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


def test_recovered_orphan_is_scanned(pipeline_home: Path, monkeypatch):
    """Orphan in scanning/ should be requeued then drained to approved/ or quarantined/."""
    import types

    from scanner.db import init_db
    from scanner.pipeline import drain_pending

    # Disable Defender to avoid platform-dependent behavior
    monkeypatch.setenv('ROM_SCANNER_DEFENDER_SCAN', '0')

    paths = ensure_layout(pipeline_home)
    init_db(pipeline_home)

    # Write a valid minimal NSP orphan directly into scanning/
    orphan = paths["scanning"] / "orphan.nsp"
    from tests.conftest import build_minimal_nsp
    orphan.write_bytes(build_minimal_nsp(include_nca=True))

    args = types.SimpleNamespace(
        vt_key=None, sandbox=False, verbose=False, timeout=60, no_network=False,
    )
    drain_pending(pipeline_home, args, quiet=True)

    # File should have been moved out of scanning/ and into approved/ or quarantined/
    assert not orphan.exists()
    assert (
        (paths["approved"] / "orphan.nsp").is_file()
        or (paths["quarantined"] / "orphan.nsp").is_file()
    )
    assert not list(paths["incoming"].iterdir())
