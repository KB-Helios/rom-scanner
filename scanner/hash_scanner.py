"""
Hash Scanner & VirusTotal Checker
==================================
Scans extracted file hashes against:
  1. Local signature database (known-malware hashes)
  2. VirusTotal API (if API key configured)
  3. Known clean homebrew hashes

Also runs structural anomaly detection on parsed containers.
"""

import json
import logging
import os
import sys
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional

from parsers.nsp_parser import NSPParser, PFS0FileEntry
from parsers.xci_parser import XCIParser

logger = logging.getLogger(__name__)


@dataclass
class ScanResult:
    """Result for a single file entry scan."""
    filename: str
    sha256: str
    md5: str
    sha1: str
    size: int
    vt_positives: int = 0
    vt_total: int = 0
    vt_permalink: str = ""
    vt_scanned: bool = False
    local_match: str = ""
    known_homebrew: bool = False
    is_suspicious: bool = False
    suspicion_reasons: List[str] = field(default_factory=list)


@dataclass
class ContainerReport:
    """Full scan report for a container (NSP/XCI)."""
    filepath: str
    file_size: int
    file_type: str  # "NSP" or "XCI"
    is_valid: bool
    parse_errors: List[str] = field(default_factory=list)
    parse_warnings: List[str] = field(default_factory=list)
    entries: List[ScanResult] = field(default_factory=list)
    overall_safe: bool = True
    overall_suspicious: bool = False
    risk_score: float = 0.0  # 0.0 (safe) to 1.0 (dangerous)


def _bundled_path(name: str) -> Path:
    """Return path to a bundled data file, supporting PyInstaller frozen builds."""
    if getattr(sys, "frozen", False) and hasattr(sys, "_MEIPASS"):
        return Path(sys._MEIPASS) / "scanner" / name
    return Path(__file__).parent / name


class HashScanner:
    """Scan ROM containers for malware and anomalies."""

    def __init__(
        self,
        vt_api_key: Optional[str] = None,
        threat_db_path: Optional[str] = None,
        risk_threshold: float = 0.3,
        homebrew_db_path: Optional[str] = None,
        homebrew_trust: bool = True,
    ):
        self.vt_api_key = vt_api_key or os.environ.get("VIRUSTOTAL_API_KEY")
        self._risk_threshold = risk_threshold
        self._homebrew_trust = homebrew_trust
        if threat_db_path:
            self._local_db_path = Path(threat_db_path)
        else:
            self._local_db_path = _bundled_path("threat_db.json")
        if homebrew_db_path:
            self._homebrew_db_path: Optional[Path] = Path(homebrew_db_path)
        else:
            self._homebrew_db_path = _bundled_path("homebrew_db.json")
        self._malware_sha256: Dict[str, str] = {}
        self._malware_md5: Dict[str, str] = {}
        self._homebrew_entry_sha256: Dict[str, str] = {}
        self._homebrew_container_sha256: Dict[str, str] = {}
        self._vt_rate_limited = False
        self._load_threat_db()
        if self._homebrew_trust:
            self._load_homebrew_db()

    def _load_threat_db(self) -> None:
        """Merge threat_db.json into in-memory malware hash tables."""
        if not self._local_db_path.exists():
            return
        try:
            with open(self._local_db_path, encoding="utf-8") as f:
                data = json.load(f)
        except (json.JSONDecodeError, OSError) as e:
            logger.warning("Failed to load threat DB %s: %s", self._local_db_path, e)
            return

        for digest, description in data.get("sha256", {}).items():
            if digest.startswith("_"):
                continue
            self._malware_sha256[digest.lower()] = description
        for digest, description in data.get("md5", {}).items():
            if digest.startswith("_"):
                continue
            self._malware_md5[digest.lower()] = description

    def _load_homebrew_db(self) -> None:
        """Load homebrew allowlist from homebrew_db.json."""
        if self._homebrew_db_path is None or not self._homebrew_db_path.exists():
            return
        try:
            with open(self._homebrew_db_path, encoding="utf-8") as f:
                data = json.load(f)
        except (json.JSONDecodeError, OSError) as e:
            logger.warning("Failed to load homebrew DB %s: %s", self._homebrew_db_path, e)
            return

        for digest, label in data.get("entry_sha256", {}).items():
            if not digest.startswith("_"):
                self._homebrew_entry_sha256[digest.lower()] = label
        for digest, label in data.get("container_sha256", {}).items():
            if not digest.startswith("_"):
                self._homebrew_container_sha256[digest.lower()] = label

    def scan_file(self, filepath: str) -> ContainerReport:
        """Scan an NSP or XCI file."""
        filepath = str(filepath)
        ext = Path(filepath).suffix.lower()

        if ext == ".nsp":
            return self._scan_nsp(filepath)
        elif ext == ".xci":
            return self._scan_xci(filepath)
        else:
            report = ContainerReport(
                filepath=filepath,
                file_size=Path(filepath).stat().st_size,
                file_type="UNKNOWN",
                is_valid=False,
            )
            report.parse_errors.append(
                f"Unsupported file type: {ext}. Supported: .nsp, .xci"
            )
            report.overall_safe = False
            return report

    def _scan_nsp(self, filepath: str) -> ContainerReport:
        """Scan an NSP file."""
        parser = NSPParser(filepath)
        valid = parser.parse()

        report = ContainerReport(
            filepath=filepath,
            file_size=parser.file_size,
            file_type="NSP",
            is_valid=valid,
            parse_errors=parser.errors.copy(),
            parse_warnings=parser.warnings.copy(),
        )

        if not valid:
            report.overall_safe = False
            report.risk_score = 1.0
            return report

        # Structural checks
        self._check_nsp_structure(parser, report)

        # Check container SHA256 against homebrew allowlist
        if self._homebrew_container_sha256:
            container_sha = _file_sha256(filepath)
            if container_sha and container_sha.lower() in self._homebrew_container_sha256:
                report.overall_safe = True
                report.risk_score = 0.0
                return report

        # Scan each entry
        for entry in parser.entries:
            scan = self._scan_entry(entry)
            report.entries.append(scan)
            if scan.is_suspicious:
                report.overall_suspicious = True

        self._compute_risk_score(report)
        return report

    def _scan_xci(self, filepath: str) -> ContainerReport:
        """Scan an XCI file."""
        parser = XCIParser(filepath)
        valid = parser.parse()

        report = ContainerReport(
            filepath=filepath,
            file_size=parser.file_size,
            file_type="XCI",
            is_valid=valid,
            parse_errors=parser.errors.copy(),
            parse_warnings=parser.warnings.copy(),
        )

        if not valid:
            report.overall_safe = False
            report.risk_score = 1.0
            return report

        # Structural checks
        self._check_xci_structure(parser, report)

        # Check container SHA256 against homebrew allowlist
        if self._homebrew_container_sha256:
            container_sha = _file_sha256(filepath)
            if container_sha and container_sha.lower() in self._homebrew_container_sha256:
                report.overall_safe = True
                report.risk_score = 0.0
                return report

        # Scan each partition's entries
        for partition in parser.partitions:
            for entry in partition.entries:
                scan = self._scan_entry(entry)
                scan.filename = f"{partition.name}/{scan.filename}"
                report.entries.append(scan)
                if scan.is_suspicious:
                    report.overall_suspicious = True

        self._compute_risk_score(report)
        return report

    def _scan_entry(self, entry: PFS0FileEntry) -> ScanResult:
        """Scan a single file entry."""
        result = ScanResult(
            filename=entry.name or f"<unnamed_{entry.index}>",
            sha256=entry.sha256,
            md5=entry.md5,
            sha1=entry.sha1,
            size=entry.size,
            is_suspicious=entry.is_suspicious,
            suspicion_reasons=entry.suspicion_reasons.copy(),
        )

        # ── Check homebrew allowlist ──
        sha256 = entry.sha256.lower() if entry.sha256 else ""
        if sha256 and sha256 in self._homebrew_entry_sha256:
            result.known_homebrew = True
            result.is_suspicious = False
            result.suspicion_reasons = []
            return result

        # ── Check local malware DB ──
        md5 = entry.md5.lower() if entry.md5 else ""
        if sha256 in self._malware_sha256:
            result.local_match = self._malware_sha256[sha256]
            result.is_suspicious = True
            result.suspicion_reasons.append(
                f"KNOWN MALWARE: {result.local_match}"
            )
        elif md5 in self._malware_md5:
            result.local_match = self._malware_md5[md5]
            result.is_suspicious = True
            result.suspicion_reasons.append(
                f"KNOWN MALWARE: {result.local_match}"
            )

        # ── Check VirusTotal ──
        if self.vt_api_key:
            self._check_virustotal(result)

        return result

    def _check_virustotal(self, result: ScanResult):
        """Query VirusTotal API for a hash."""
        if not result.sha256 or not self.vt_api_key:
            return
        if self._vt_rate_limited:
            return

        url = (
            f"https://www.virustotal.com/api/v3/files/{result.sha256}"
        )
        req = urllib.request.Request(url)
        req.add_header("x-apikey", self.vt_api_key)

        try:
            with urllib.request.urlopen(req, timeout=15) as resp:
                data = json.loads(resp.read().decode())
                attrs = data.get("data", {}).get("attributes", {})
                stats = attrs.get("last_analysis_stats", {})
                result.vt_positives = stats.get("malicious", 0)
                result.vt_total = sum(stats.values())
                result.vt_permalink = (
                    f"https://www.virustotal.com/gui/file/{result.sha256}"
                )
                result.vt_scanned = True

                if result.vt_positives > 0:
                    result.is_suspicious = True
                    result.suspicion_reasons.append(
                        f"VirusTotal: {result.vt_positives}/{result.vt_total} "
                        f"engines flagged as malicious"
                    )
        except urllib.error.HTTPError as e:
            if e.code == 404:
                # Not in VT — benign; do not mark suspicious
                result.vt_scanned = False
            elif e.code == 429:
                self._vt_rate_limited = True
                logger.warning("VirusTotal rate limit hit — skipping remaining lookups")
            else:
                logger.warning("VirusTotal HTTP error %s for %s", e.code, result.sha256)
        except Exception as e:
            logger.warning("VirusTotal error for %s: %s", result.sha256, e)

    # ─── Structure Validation ────────────────────────────────────

    def _check_nsp_structure(self, parser: NSPParser, report: ContainerReport):
        """Validate NSP structural integrity."""
        # NSP should have at least one .nca file
        nca_files = [e for e in parser.entries if e.name.endswith(".nca")]
        if not nca_files:
            report.parse_warnings.append(
                "No .nca files found — invalid NSP structure"
            )
            report.overall_suspicious = True

        # Check for CNMT (Content Meta) — every valid NSP has one
        cnmt_files = [e for e in parser.entries if ".cnmt." in e.name]
        if not cnmt_files:
            report.parse_warnings.append(
                "No CNMT (Content Meta) file found — may be incomplete/modified"
            )

        # Check for ticket + cert pair
        tik_files = [e for e in parser.entries if e.name.endswith(".tik")]
        cert_files = [e for e in parser.entries if e.name.endswith(".cert")]
        if tik_files and not cert_files:
            report.parse_warnings.append(
                "Ticket found without matching certificate"
            )

        # Check for overlapping offsets (could indicate tampering)
        if len(parser.entries) > 1:
            regions = sorted(
                [(e.offset, e.offset + e.size) for e in parser.entries],
                key=lambda x: x[0],
            )
            for i in range(len(regions) - 1):
                if regions[i][1] > regions[i + 1][0]:
                    report.parse_warnings.append(
                        "Overlapping file regions detected — possible tampering"
                    )
                    report.overall_suspicious = True
                    break

    def _check_xci_structure(self, parser: XCIParser, report: ContainerReport):
        """Validate XCI structural integrity."""
        # XCI should have at least 'secure' partition
        partition_names = {p.name.lower() for p in parser.partitions}
        if "secure" not in partition_names:
            report.parse_warnings.append(
                "No 'secure' partition found — invalid XCI"
            )
            report.overall_suspicious = True

        # Check partition sizes make sense
        total_data = sum(p.size for p in parser.partitions)
        if total_data > parser.file_size * 1.5:
            report.parse_warnings.append(
                f"Partition data ({total_data} bytes) exceeds "
                f"file size ({parser.file_size} bytes) — corrupt"
            )
            report.overall_suspicious = True

    def _compute_risk_score(self, report: ContainerReport):
        """Compute a 0.0–1.0 risk score and set overall_safe."""
        if not report.is_valid:
            report.overall_safe = False
            report.risk_score = 1.0
            return

        score = 0.0

        # Parse errors add risk
        score += len(report.parse_errors) * 0.3

        # Parse warnings add moderate risk
        score += len(report.parse_warnings) * 0.1

        # Suspicious entries add risk
        for entry in report.entries:
            if entry.is_suspicious:
                # Known malware is max risk
                if entry.local_match:
                    score += 0.5
                # VT positives scale with count
                elif entry.vt_positives > 5:
                    score += 0.4
                elif entry.vt_positives > 0:
                    score += 0.2
                # Structural issues
                else:
                    score += 0.15 * len(entry.suspicion_reasons)

        # Normalize to 0.0–1.0
        report.risk_score = min(score, 1.0)
        report.overall_safe = report.risk_score < self._risk_threshold and not report.overall_suspicious


def _file_sha256(filepath: str) -> Optional[str]:
    """Compute SHA-256 of a file for container-level homebrew check."""
    import hashlib
    try:
        h = hashlib.sha256()
        with open(filepath, "rb") as f:
            for chunk in iter(lambda: f.read(65536), b""):
                h.update(chunk)
        return h.hexdigest()
    except OSError:
        return None
