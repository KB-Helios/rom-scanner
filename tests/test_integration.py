"""End-to-end pipeline integration tests."""

from argparse import Namespace
from pathlib import Path
from unittest.mock import patch

import scanner.config as config_module
from rom_scanner import _ingest_path, cmd_promote
from scanner.storage import ensure_layout, find_in_pipeline, stage_paths


def test_ingest_quarantine_promote(pipeline_home: Path, quarantine_nsp_path: Path):
    """Ingest fake NSP → quarantine → manual promote."""
    config_module._config_cache = None
    ensure_layout(pipeline_home)

    args = Namespace(vt_key=None, json=True, sandbox=False, verbose=False)
    with patch("rom_scanner.print_scan_report"), patch("builtins.print"):
        ok = _ingest_path(quarantine_nsp_path, pipeline_home, args, json_output=True)

    assert ok is False
    located = find_in_pipeline("bad.nsp", pipeline_home)
    assert located is not None
    stage, path = located
    assert stage == "quarantined"

    args_promote = Namespace(file="bad.nsp")
    with patch("builtins.print"), patch("rom_scanner.sys.exit"):
        cmd_promote(args_promote)

    located = find_in_pipeline("bad.nsp", pipeline_home)
    assert located is not None
    assert located[0] == "approved"


def test_ingest_clean_nsp_to_approved(pipeline_home: Path, minimal_nsp_path: Path):
    """Valid minimal NSP should route to approved when risk is low."""
    config_module._config_cache = None
    ensure_layout(pipeline_home)

    args = Namespace(vt_key=None, json=True, sandbox=False, verbose=False)
    with patch("rom_scanner.print_scan_report"), patch("builtins.print"):
        ok = _ingest_path(minimal_nsp_path, pipeline_home, args, json_output=True)

    assert ok is True
    located = find_in_pipeline("minimal.nsp", pipeline_home)
    assert located is not None
    assert located[0] == "approved"


def test_ingest_leaves_copy_in_source(pipeline_home: Path, minimal_nsp_path: Path):
    """Non-sandbox ingest copies source; original path remains."""
    config_module._config_cache = None
    src = pipeline_home / "external" / "minimal.nsp"
    src.parent.mkdir(parents=True)
    src.write_bytes(minimal_nsp_path.read_bytes())

    args = Namespace(vt_key=None, json=False, sandbox=False, verbose=False)
    with patch("rom_scanner.print_scan_report"), patch("builtins.print"):
        _ingest_path(src, pipeline_home, args)

    assert src.is_file()
    paths = stage_paths(pipeline_home)
    assert any(paths["approved"].glob("minimal*.nsp"))
