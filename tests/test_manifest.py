"""Tests for scanner/manifest.py."""

from pathlib import Path

from scanner.hash_scanner import ContainerReport
from scanner.manifest import load_manifest, record_scan, update_stage


def test_record_scan(pipeline_home: Path, minimal_nsp_path: Path):
    report = ContainerReport(
        filepath=str(minimal_nsp_path),
        file_size=minimal_nsp_path.stat().st_size,
        file_type="NSP",
        is_valid=True,
        overall_safe=True,
        risk_score=0.1,
    )
    entry = record_scan(
        report,
        stage="approved",
        path=minimal_nsp_path,
        verdict="approved",
        home=pipeline_home,
    )
    assert entry["filename"] == minimal_nsp_path.name
    assert entry["stage"] == "approved"
    assert entry["container_sha256"]

    entries = load_manifest(pipeline_home)
    assert len(entries) == 1
    assert entries[0]["file_type"] == "NSP"


def test_update_stage(pipeline_home: Path, minimal_nsp_path: Path):
    report = ContainerReport(
        filepath=str(minimal_nsp_path),
        file_size=100,
        file_type="NSP",
        is_valid=True,
        risk_score=0.5,
    )
    record_scan(
        report,
        stage="quarantined",
        path=minimal_nsp_path,
        verdict="quarantined",
        home=pipeline_home,
    )
    approved_path = pipeline_home / "approved" / minimal_nsp_path.name
    updated = update_stage(
        minimal_nsp_path.name,
        stage="approved",
        verdict="approved_manual",
        path=approved_path,
        home=pipeline_home,
    )
    assert updated is not None
    assert updated["stage"] == "approved"
    assert updated["path"] == str(approved_path)
