"""Tests for parsers/nsp_parser.py."""

from pathlib import Path

from parsers.nsp_parser import NSPParser
from tests.conftest import build_minimal_nsp, build_pfs0


def test_parse_valid_pfs0_header(minimal_nsp_path: Path):
    parser = NSPParser(str(minimal_nsp_path))
    assert parser.parse() is True
    assert parser.header is not None
    assert parser.header.magic == b"PFS0"
    assert parser.header.num_files == 4
    assert len(parser.entries) == 4
    assert parser.errors == []


def test_parse_invalid_magic(tmp_path: Path):
    path = tmp_path / "bad.nsp"
    path.write_bytes(b"XXXX" + b"\x00" * 12)
    parser = NSPParser(str(path))
    assert parser.parse() is False
    assert any("Invalid magic" in e for e in parser.errors)


def test_entry_hashes_computed(minimal_nsp_path: Path):
    parser = NSPParser(str(minimal_nsp_path))
    parser.parse()
    for entry in parser.entries:
        assert len(entry.sha256) == 64
        assert len(entry.md5) == 32
        assert len(entry.sha1) == 40


def test_suspicious_extension_flagged(tmp_path: Path):
    path = tmp_path / "evil.nsp"
    path.write_bytes(build_minimal_nsp(include_nca=True, suspicious=True))
    parser = NSPParser(str(path))
    parser.parse()
    exe_entries = [e for e in parser.entries if e.name.endswith(".exe")]
    assert len(exe_entries) == 1
    assert exe_entries[0].is_suspicious
    assert any("Suspicious extension" in r for r in exe_entries[0].suspicion_reasons)


def test_truncated_file_rejected(tmp_path: Path):
    path = tmp_path / "trunc.nsp"
    path.write_bytes(build_pfs0([("a.nca", b"\x00" * 100)])[:20])
    parser = NSPParser(str(path))
    assert parser.parse() is False
    assert any("Truncated" in e for e in parser.errors)
