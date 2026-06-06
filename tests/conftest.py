"""Shared pytest fixtures for rom-scanner."""

import json
import struct
import sys
from pathlib import Path

import pytest

import scanner.config as config_module


def build_pfs0(entries: list[tuple[str, bytes]]) -> bytes:
    """Build a minimal PFS0 container (NSP format)."""
    num_files = len(entries)
    string_table = b""
    name_offsets: list[int] = []
    for name, _ in entries:
        name_offsets.append(len(string_table))
        string_table += name.encode("utf-8") + b"\x00"

    string_table_size = len(string_table)
    file_table = b""
    file_data = b""
    data_offset = 0

    for i, (_name, data) in enumerate(entries):
        file_table += struct.pack("<QQII", data_offset, len(data), name_offsets[i], 0)
        file_data += data
        data_offset += len(data)

    header = b"PFS0" + struct.pack("<II", num_files, string_table_size) + b"\x00\x00\x00\x00"
    return header + file_table + string_table + file_data


def build_hfs0(entries: list[tuple[str, bytes]]) -> bytes:
    """Build a minimal HFS0 container (XCI partition format)."""
    blob = build_pfs0(entries)
    return b"HFS0" + blob[4:]


def build_minimal_nsp(*, include_nca: bool = True, suspicious: bool = False) -> bytes:
    """Synthetic NSP with optional .nca / CNMT entries."""
    entries: list[tuple[str, bytes]] = []
    if include_nca:
        entries.append(("program.nca", b"\x00" * 64))
        entries.append(("program.cnmt.nca", b"\x01" * 32))
        entries.append(("program.tik", b"\x02" * 16))
        entries.append(("program.cert", b"\x03" * 16))
    else:
        entries.append(("readme.txt", b"not a real nsp"))
    if suspicious:
        entries.append(("payload.exe", b"MZ" + b"\x00" * 62))
    return build_pfs0(entries)


def build_minimal_xci() -> bytes:
    """Synthetic XCI with secure/normal/update partitions."""
    inner_secure = build_hfs0([("header.nca", b"\x10" * 48)])
    inner_normal = build_hfs0([("data.nca", b"\x20" * 48)])
    inner_update = build_hfs0([("update.nca", b"\x30" * 32)])
    return build_hfs0([
        ("secure", inner_secure),
        ("normal", inner_normal),
        ("update", inner_update),
    ])


@pytest.fixture
def reset_config_cache():
    """Clear cached config between tests."""
    config_module._config_cache = None
    yield
    config_module._config_cache = None


@pytest.fixture
def pipeline_home(tmp_path, monkeypatch, reset_config_cache):
    """Isolated ROM_SCANNER_HOME with defender disabled for tests."""
    home = tmp_path / "rom_scanner_home"
    home.mkdir()
    monkeypatch.setenv("ROM_SCANNER_HOME", str(home))
    monkeypatch.setenv("ROM_SCANNER_DEFENDER_SCAN", "0")
    config_module._config_cache = None

    cfg = config_module.default_config(home)
    cfg["scan"]["defender_scan"] = False
    cfg["scan"]["risk_threshold"] = 0.3
    with open(home / "config.json", "w", encoding="utf-8") as f:
        json.dump(cfg, f)

    config_module._config_cache = None
    return home


@pytest.fixture
def minimal_nsp_path(tmp_path) -> Path:
    """Write a valid minimal NSP fixture to disk."""
    path = tmp_path / "minimal.nsp"
    path.write_bytes(build_minimal_nsp(include_nca=True))
    return path


@pytest.fixture
def quarantine_nsp_path(tmp_path) -> Path:
    """NSP missing .nca — routes to quarantine."""
    path = tmp_path / "bad.nsp"
    path.write_bytes(build_minimal_nsp(include_nca=False))
    return path


@pytest.fixture
def minimal_xci_path(tmp_path) -> Path:
    """Write a valid minimal XCI fixture to disk."""
    path = tmp_path / "minimal.xci"
    path.write_bytes(build_minimal_xci())
    return path


@pytest.fixture
def fixtures_dir() -> Path:
    return Path(__file__).parent / "fixtures"


def pytest_configure(config):
    """Ensure project root is importable."""
    root = Path(__file__).resolve().parent.parent
    if str(root) not in sys.path:
        sys.path.insert(0, str(root))
