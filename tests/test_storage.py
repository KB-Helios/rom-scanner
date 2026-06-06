"""Tests for scanner/storage.py."""

from pathlib import Path

import pytest

from scanner.storage import (
    copy_to_stage,
    ensure_layout,
    find_in_pipeline,
    move_from_external,
    move_to_stage,
    unique_dest,
)


def test_ensure_layout_creates_stages(pipeline_home: Path):
    paths = ensure_layout(pipeline_home)
    assert set(paths.keys()) == {"incoming", "scanning", "approved", "quarantined"}
    for p in paths.values():
        assert p.is_dir()


def test_move_to_stage(pipeline_home: Path, minimal_nsp_path: Path):
    dest = copy_to_stage(minimal_nsp_path, "incoming", pipeline_home)
    assert dest.parent.name == "incoming"
    assert dest.is_file()
    assert minimal_nsp_path.is_file()

    scanning = move_to_stage(dest, "scanning", pipeline_home)
    assert scanning.parent.name == "scanning"
    assert not dest.exists()
    assert find_in_pipeline("minimal.nsp", pipeline_home) == ("scanning", scanning)


def test_unique_dest_collision(pipeline_home: Path, minimal_nsp_path: Path):
    incoming = pipeline_home / "incoming"
    incoming.mkdir(parents=True, exist_ok=True)
    first = incoming / "minimal.nsp"
    first.write_bytes(minimal_nsp_path.read_bytes())

    second_src = pipeline_home / "source.nsp"
    second_src.write_bytes(b"other content")
    dest = unique_dest(incoming, "minimal.nsp")
    assert dest.name == "minimal_1.nsp"
    assert not dest.exists()


def test_move_from_external(pipeline_home: Path, tmp_path: Path):
    external = tmp_path / "download.nsp"
    external.write_bytes(b"PFS0" + b"\x00" * 32)
    dest = move_from_external(external, "incoming", pipeline_home)
    assert dest.is_file()
    assert not external.exists()
    assert dest.parent.name == "incoming"


def test_move_unknown_stage_raises(pipeline_home: Path, minimal_nsp_path: Path):
    with pytest.raises(ValueError, match="Unknown stage"):
        move_to_stage(minimal_nsp_path, "bogus", pipeline_home)


def test_find_in_pipeline_missing(pipeline_home: Path):
    assert find_in_pipeline("missing.nsp", pipeline_home) is None
