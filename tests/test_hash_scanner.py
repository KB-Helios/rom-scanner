"""Tests for scanner/hash_scanner.py."""

import json
import urllib.error
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from parsers.nsp_parser import PFS0FileEntry
from scanner.hash_scanner import ContainerReport, HashScanner, ScanResult


def test_risk_score_low_for_clean_nsp(minimal_nsp_path: Path):
    scanner = HashScanner()
    report = scanner.scan_file(str(minimal_nsp_path))
    assert report.is_valid
    assert report.risk_score < 0.3
    assert report.overall_safe


def test_risk_score_high_for_invalid_nsp(tmp_path: Path):
    path = tmp_path / "bad.nsp"
    path.write_bytes(b"NOTPFS0" + b"\x00" * 20)
    scanner = HashScanner()
    report = scanner.scan_file(str(path))
    assert not report.is_valid
    assert report.risk_score == 1.0
    assert not report.overall_safe


def test_risk_score_increases_with_malware_match(tmp_path: Path, minimal_nsp_path: Path):
    parser_report = HashScanner().scan_file(str(minimal_nsp_path))
    entry_sha = parser_report.entries[0].sha256

    threat_db = tmp_path / "threat_db.json"
    threat_db.write_text(
        json.dumps({"sha256": {entry_sha: "Test trojan"}, "md5": {}}),
        encoding="utf-8",
    )
    scanner = HashScanner(threat_db_path=str(threat_db))
    report = scanner.scan_file(str(minimal_nsp_path))
    assert report.overall_suspicious
    assert report.risk_score >= 0.5
    assert not report.overall_safe


def test_threat_db_merge(tmp_path: Path):
    threat_db = tmp_path / "threat_db.json"
    digest = "a" * 64
    threat_db.write_text(
        json.dumps({"sha256": {digest: "Merged threat"}, "md5": {}}),
        encoding="utf-8",
    )
    scanner = HashScanner(threat_db_path=str(threat_db))
    assert digest in scanner._malware_sha256
    assert scanner._malware_sha256[digest] == "Merged threat"


def test_threat_db_load_error_logs_warning(tmp_path: Path, caplog):
    bad_db = tmp_path / "bad.json"
    bad_db.write_text("{not json", encoding="utf-8")
    with caplog.at_level("WARNING"):
        scanner = HashScanner(threat_db_path=str(bad_db))
    assert scanner._malware_sha256 == {}
    assert any("Failed to load threat DB" in r.message for r in caplog.records)


def test_vt_404_not_suspicious():
    scanner = HashScanner(vt_api_key="test-key")
    result = ScanResult(
        filename="test.nca",
        sha256="b" * 64,
        md5="c" * 32,
        sha1="d" * 40,
        size=64,
    )

    def raise_404(*_args, **_kwargs):
        raise urllib.error.HTTPError(
            url="http://example",
            code=404,
            msg="Not Found",
            hdrs=MagicMock(),
            fp=MagicMock(),
        )

    with patch("urllib.request.urlopen", side_effect=raise_404):
        scanner._check_virustotal(result)

    assert not result.is_suspicious
    assert result.vt_scanned is False
    assert result.vt_positives == 0
    assert not any("Not found" in r for r in result.suspicion_reasons)


def test_vt_positive_marks_suspicious():
    scanner = HashScanner(vt_api_key="test-key")
    result = ScanResult(
        filename="test.nca",
        sha256="e" * 64,
        md5="f" * 32,
        sha1="0" * 40,
        size=64,
    )

    payload = json.dumps({
        "data": {
            "attributes": {
                "last_analysis_stats": {
                    "malicious": 3,
                    "harmless": 70,
                    "undetected": 5,
                }
            }
        }
    }).encode()

    mock_resp = MagicMock()
    mock_resp.read.return_value = payload
    mock_resp.__enter__ = lambda s: s
    mock_resp.__exit__ = MagicMock(return_value=False)

    with patch("urllib.request.urlopen", return_value=mock_resp):
        scanner._check_virustotal(result)

    assert result.is_suspicious
    assert result.vt_positives == 3
    assert result.vt_scanned is True


def test_scan_entry_local_match():
    scanner = HashScanner()
    digest = "1" * 64
    scanner._malware_sha256[digest] = "Known bad"
    entry = PFS0FileEntry(index=0, offset=0, size=10, name_offset=0, name="x.nca")
    entry.sha256 = digest
    entry.md5 = "2" * 32
    entry.sha1 = "3" * 40
    scan = scanner._scan_entry(entry)
    assert scan.is_suspicious
    assert scan.local_match == "Known bad"


@pytest.mark.parametrize(
    "positives,expected_min",
    [
        (0, 0.0),
        (1, 0.2),
        (6, 0.4),
    ],
)
def test_compute_risk_score_vt_weight(positives, expected_min):
    scanner = HashScanner()
    report = ContainerReport(
        filepath="x.nsp",
        file_size=100,
        file_type="NSP",
        is_valid=True,
    )
    report.entries.append(
        ScanResult(
            filename="a.nca",
            sha256="x",
            md5="y",
            sha1="z",
            size=10,
            is_suspicious=positives > 0,
            vt_positives=positives,
            vt_total=80,
            vt_scanned=positives > 0,
        )
    )
    scanner._compute_risk_score(report)
    if positives == 0:
        assert report.risk_score == 0.0
    else:
        assert report.risk_score >= expected_min
