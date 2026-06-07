"""Tests for scanner/watch.py."""

import os
from pathlib import Path
from unittest.mock import patch

import pytest

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


def test_get_stable_files_returns_last_stable(tmp_path: Path):
    dl = tmp_path / "downloads"
    dl.mkdir()
    nsp = dl / "stable2.nsp"
    nsp.write_bytes(b"PFS0" + b"\x00" * 128)

    watcher = DownloadWatcher(
        downloads_path=dl,
        stable_size_sec=5.0,
        extensions=[".nsp"],
    )

    t = [300.0]

    with patch("scanner.watch.time.monotonic", side_effect=lambda: t[0]):
        watcher.poll_once()
        assert watcher.get_stable_files() == []

        t[0] = 306.0
        watcher.poll_once()
        stable = watcher.get_stable_files()
        assert len(stable) == 1
        assert stable[0].name == "stable2.nsp"

        # After next poll, last_stable is reset
        watcher.poll_once()
        assert watcher.get_stable_files() == []


def test_is_partial_helper():
    watcher = DownloadWatcher(downloads_path=Path("/unused"))
    assert watcher._is_partial(Path("x.nsp.crdownload"))
    assert watcher._is_partial(Path("x.tmp"))
    assert not watcher._is_partial(Path("x.nsp"))


def test_run_forever_calls_drain_callback(tmp_path: Path):
    dl = tmp_path / "downloads"
    dl.mkdir()
    nsp = dl / "auto.nsp"
    nsp.write_bytes(b"PFS0" + b"\x00" * 64)

    watcher = DownloadWatcher(
        downloads_path=dl,
        poll_interval_sec=0.01,
        stable_size_sec=0.0,
        extensions=[".nsp"],
    )
    ingested: list[Path] = []
    drain_calls: list[str] = []

    def ingest_callback(path: Path) -> bool:
        ingested.append(path)
        return True

    def drain_callback() -> None:
        drain_calls.append("drained")

    t = [0.0]
    iterations = [0]

    def fake_monotonic():
        return t[0]

    def fake_sleep(_sec: float) -> None:
        iterations[0] += 1
        t[0] += 0.02
        if iterations[0] >= 3:
            raise KeyboardInterrupt

    with patch("scanner.watch.time.monotonic", side_effect=fake_monotonic):
        with patch("scanner.watch.time.sleep", side_effect=fake_sleep):
            with pytest.raises(KeyboardInterrupt):
                watcher.run_forever(ingest_callback, drain_callback=drain_callback)

    assert ingested
    assert drain_calls
