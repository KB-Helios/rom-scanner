"""Tests for parsers/xci_parser.py."""

from pathlib import Path

from parsers.xci_parser import XCIParser
from tests.conftest import build_hfs0


def test_parse_valid_hfs0_header(minimal_xci_path: Path):
    parser = XCIParser(str(minimal_xci_path))
    assert parser.parse() is True
    assert parser.header is not None
    assert parser.header.magic == b"HFS0"
    assert len(parser.partitions) == 3
    names = {p.name.lower() for p in parser.partitions}
    assert names == {"secure", "normal", "update"}


def test_inner_hfs0_entries_parsed(minimal_xci_path: Path):
    parser = XCIParser(str(minimal_xci_path))
    parser.parse()
    secure = next(p for p in parser.partitions if p.name == "secure")
    assert secure.hfs0_header is not None
    assert len(secure.entries) >= 1
    assert secure.entries[0].sha256


def test_invalid_magic_rejected(tmp_path: Path):
    path = tmp_path / "bad.xci"
    path.write_bytes(b"XXXX" + b"\x00" * 12)
    parser = XCIParser(str(path))
    assert parser.parse() is False
    assert any("Invalid magic" in e for e in parser.errors)


def test_unusual_partition_warns(tmp_path: Path):
    path = tmp_path / "odd.xci"
    inner = build_hfs0([("file.nca", b"\xab" * 16)])
    path.write_bytes(build_hfs0([("weird", inner)]))
    parser = XCIParser(str(path))
    parser.parse()
    assert any("Unusual partition" in w for w in parser.warnings)
