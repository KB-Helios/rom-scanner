"""Tests for scanner/watch.py."""

import os
from pathlib import Path
from unittest.mock import patch

from scanner.watch import DownloadWatcher


def test_skips_crdownload(tmp_path: Path):
    dl = tmp_path / "downloads"
    dl.mkdir()
    partial = dl / "game.nsp.crdownload"
    partial.write_bytes(b"partial download in progress")

    watcher = DownloadWatcher(downloads_path=dl, extensions=[".nsp"])
    assert watcher.poll_once() == []
    assert not watcher._is_target(partial)


def test_skips_tmp_suffix(tmp_path: Path):
    dl = tmp_path / "downloads"
    dl.mkdir()
    (dl / "game.nsp.tmp").write_bytes(b"x")
    watcher = DownloadWatcher(downloads_path=dl, extensions=[".nsp"])
    assert watcher.poll_once() == []


def test_stable_size_detection(tmp_path: Path):
    dl = tmp_path / "downloads"
    dl.mkdir()
    nsp = dl / "stable.nsp"
    nsp.write_bytes(b"PFS0" + b"\x00" * 128)

    watcher = DownloadWatcher(
        downloads_path=dl,
        stable_size_sec=10.0,
        extensions=[".nsp"],
    )

    t = [100.0]

    def fake_monotonic():
        return t[0]

    with patch("scanner.watch.time.monotonic", side_effect=fake_monotonic):
        ev1 = watcher.poll_once()
        assert any(e.kind == "detected" for e in ev1)
        assert not any(e.kind == "stable" for e in ev1)

        t[0] = 105.0
        ev2 = watcher.poll_once()
        assert ev2 == []

        t[0] = 110.0
        ev3 = watcher.poll_once()
        assert any(e.kind == "stable" for e in ev3)


def test_size_change_resets_stability(tmp_path: Path):
    dl = tmp_path / "downloads"
    dl.mkdir()
    nsp = dl / "growing.nsp"
    nsp.write_bytes(b"a" * 100)

    watcher = DownloadWatcher(
        downloads_path=dl,
        stable_size_sec=10.0,
        extensions=[".nsp"],
    )

    t = [200.0]

    with patch("scanner.watch.time.monotonic", side_effect=lambda: t[0]):
        watcher.poll_once()
        t[0] = 205.0
        with nsp.open("wb") as f:
            f.write(b"a" * 200)
            f.flush()
            os.fsync(f.fileno())
        watcher.poll_once()
        t[0] = 212.0
        events = watcher.poll_once()
        assert not any(e.kind == "stable" for e in events)


def test_is_partial_helper():
    watcher = DownloadWatcher(downloads_path=Path("/unused"))
    assert watcher._is_partial(Path("x.nsp.crdownload"))
    assert watcher._is_partial(Path("x.tmp"))
    assert not watcher._is_partial(Path("x.nsp"))
