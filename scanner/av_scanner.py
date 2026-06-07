"""
Windows Defender integration.
=============================
Runs MpCmdRun.exe custom scan on raw ROM files before container parsing.
"""

import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Optional

DEFENDER_PATHS = [
    r"C:\Program Files\Windows Defender\MpCmdRun.exe",
    r"C:\Program Files (x86)\Windows Defender\MpCmdRun.exe",
    r"C:\ProgramData\Microsoft\Windows Defender\Platform\*\MpCmdRun.exe",
]


@dataclass
class AVScanResult:
    """Result of a Windows Defender scan."""
    filepath: str
    scanned: bool = False
    clean: bool = True
    threat_name: str = ""
    exit_code: int = 0
    output: str = ""
    errors: List[str] = field(default_factory=list)


def _find_mpcmdrun() -> Optional[Path]:
    for path in DEFENDER_PATHS:
        if "*" in path:
            import glob
            matches = glob.glob(path)
            if matches:
                return Path(matches[-1])
        elif Path(path).exists():
            return Path(path)
    return None


def scan_file(filepath: str, *, enabled: bool = True) -> AVScanResult:
    """
    Run Defender custom scan on a file.

    Fail closed: errors or detections mark the file as not clean.
    """
    result = AVScanResult(filepath=str(Path(filepath).resolve()))

    if not enabled:
        result.scanned = False
        result.clean = True
        return result

    if sys.platform != "win32":
        result.scanned = False
        result.clean = True
        return result

    mpcmd = _find_mpcmdrun()
    if mpcmd is None:
        result.scanned = False
        result.errors.append("MpCmdRun.exe not found")
        result.clean = False
        return result

    if not Path(filepath).is_file():
        result.errors.append(f"File not found: {filepath}")
        result.clean = False
        return result

    try:
        proc = subprocess.run(
            [str(mpcmd), "-Scan", "-ScanType", "3", "-File", str(filepath)],
            capture_output=True,
            text=True,
            timeout=3600,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
        result.scanned = True
        result.exit_code = proc.returncode
        result.output = (proc.stdout or "") + (proc.stderr or "")

        output_lower = result.output.lower()
        if proc.returncode == 2:
            result.clean = False
            result.threat_name = "Defender detected threat"
        elif ("threat" in output_lower or "found" in output_lower) and "no threats" not in output_lower:
            result.clean = False
            for line in result.output.splitlines():
                if "threat" in line.lower() or "virus" in line.lower():
                    result.threat_name = line.strip()
                    break
            # Fallback if no specific threat line was found
            if not result.threat_name:
                # Use first non-empty output line as fallback
                for line in result.output.splitlines():
                    if line.strip():
                        result.threat_name = line.strip()
                        break
                # If still empty, use generic message
                if not result.threat_name:
                    result.threat_name = "detected (no name)"
        elif proc.returncode != 0:
            result.clean = False
            result.errors.append(f"Defender exit code {proc.returncode}")

    except subprocess.TimeoutExpired:
        result.scanned = True
        result.clean = False
        result.errors.append("Defender scan timed out")
    except OSError as e:
        result.scanned = False
        result.clean = False
        result.errors.append(f"Defender scan failed: {e}")

    return result
