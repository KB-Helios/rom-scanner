"""
Scan manifest persistence.
==========================
Stores ContainerReport results via SQLite (with one-time JSON migration).
"""

import hashlib
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from scanner.db import init_db, load_all, record_entry, update_entry
from scanner.hash_scanner import ContainerReport


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _file_sha256(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def _report_to_entry(
    report: ContainerReport,
    *,
    stage: str,
    path: Path,
    verdict: str,
    container_sha256: Optional[str] = None,
) -> Dict[str, Any]:
    return {
        "path": str(path),
        "filename": path.name,
        "stage": stage,
        "verdict": verdict,
        "timestamp": _utc_now(),
        "container_sha256": container_sha256 or "",
        "file_type": report.file_type,
        "file_size": report.file_size,
        "is_valid": report.is_valid,
        "overall_safe": report.overall_safe,
        "risk_score": report.risk_score,
        "parse_errors": report.parse_errors,
        "parse_warnings": report.parse_warnings,
        "entries": [
            {
                "filename": e.filename,
                "sha256": e.sha256,
                "md5": e.md5,
                "sha1": e.sha1,
                "size": e.size,
                "is_suspicious": e.is_suspicious,
                "suspicion_reasons": e.suspicion_reasons,
                "local_match": e.local_match,
                "vt_positives": e.vt_positives,
                "vt_total": e.vt_total,
                "vt_permalink": e.vt_permalink,
            }
            for e in report.entries
        ],
    }


def load_manifest(home: Optional[Path] = None) -> List[Dict[str, Any]]:
    """Load all manifest entries (newest first)."""
    init_db(home)
    return load_all(home)


def record_scan(
    report: ContainerReport,
    *,
    stage: str,
    path: Path,
    verdict: str,
    home: Optional[Path] = None,
    container_sha256: Optional[str] = None,
) -> Dict[str, Any]:
    """Append a scan result to the manifest."""
    if container_sha256 is None and path.is_file():
        container_sha256 = _file_sha256(path)

    entry = _report_to_entry(
        report,
        stage=stage,
        path=path,
        verdict=verdict,
        container_sha256=container_sha256,
    )
    init_db(home)
    return record_entry(entry, home)


def update_stage(
    filename: str,
    *,
    stage: str,
    verdict: str,
    path: Optional[Path] = None,
    home: Optional[Path] = None,
) -> Optional[Dict[str, Any]]:
    """Update the latest manifest entry matching filename."""
    init_db(home)
    return update_entry(
        filename,
        stage=stage,
        verdict=verdict,
        path=path,
        home=home,
    )
