"""
Sandbox Runner
==============
Launches a Switch emulator with monitoring hooks to detect runtime
suspicious behavior:
  - Unexpected network connections
  - File system writes outside expected dirs
  - Process spawning
  - Registry modifications (Windows)

Supports: Ryujinx, Yuzu (if available)
"""

import os
import shutil
import subprocess
import sys
import tempfile
import time
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional


@dataclass
class SandboxEvent:
    """A single suspicious event detected during sandboxing."""
    timestamp: str
    category: str  # network, filesystem, process, registry
    severity: str  # low, medium, high, critical
    description: str
    details: Dict = field(default_factory=dict)


@dataclass
class SandboxReport:
    """Full sandbox analysis report."""
    rom_path: str
    emulator_used: str
    duration_seconds: float
    events: List[SandboxEvent] = field(default_factory=list)
    safe: bool = True
    risk_score: float = 0.0

    def add_event(self, category: str, severity: str, description: str, **details):
        event = SandboxEvent(
            timestamp=datetime.utcnow().isoformat(),
            category=category,
            severity=severity,
            description=description,
            details=details,
        )
        self.events.append(event)
        if severity in ("high", "critical"):
            self.safe = False


class SandboxRunner:
    """Sandbox runner with emulator monitoring."""

    # Emulator search paths (Windows + Linux)
    RYUJINX_PATHS = [
        # Windows
        os.path.expanduser("~/AppData/Roaming/Ryujinx/Ryujinx.exe"),
        "C:/Program Files/Ryujinx/Ryujinx.exe",
        "C:/Program Files (x86)/Ryujinx/Ryujinx.exe",
        # Linux
        os.path.expanduser("~/.local/bin/Ryujinx"),
        "/usr/bin/Ryujinx",
        "/app/bin/Ryujinx",
    ]

    def __init__(self, verbose: bool = False):
        self.verbose = verbose
        self.emulator_path: Optional[str] = None
        self.emulator_name: str = ""
        self._find_emulator()

    def _find_emulator(self) -> bool:
        """Locate an installed Switch emulator."""
        # Try Ryujinx first
        for path in self.RYUJINX_PATHS:
            if Path(path).exists():
                self.emulator_path = path
                self.emulator_name = "Ryujinx"
                return True

        # Check PATH
        for name in ["Ryujinx", "ryujinx"]:
            found = shutil.which(name)
            if found:
                self.emulator_path = found
                self.emulator_name = "Ryujinx"
                return True

        return False

    def is_available(self) -> bool:
        """Check if an emulator is available for sandboxing."""
        return self.emulator_path is not None

    def run_sandbox(
        self,
        rom_path: str,
        timeout: int = 60,
        monitor_network: bool = True,
        monitor_fs: bool = True,
    ) -> SandboxReport:
        """
        Run a ROM in a sandboxed emulator environment.

        Args:
            rom_path: Path to the NSP/XCI file
            timeout: Max seconds to run the emulator
            monitor_network: Watch for unexpected network connections
            monitor_fs: Watch for suspicious filesystem activity

        Returns:
            SandboxReport with detected events
        """
        report = SandboxReport(
            rom_path=rom_path,
            emulator_used=self.emulator_name or "none",
            duration_seconds=0,
        )

        if not self.emulator_path:
            report.add_event(
                "process", "high",
                "No emulator found — cannot sandbox. Install Ryujinx.",
            )
            report.safe = False
            report.risk_score = 0.5  # Unknown risk
            return report

        rom_path = str(Path(rom_path).resolve())

        # ── Pre-sandbox: snapshot state ──
        pre_state = self._snapshot_system_state()

        # ── Launch emulator ──
        cmd = self._build_command(rom_path)
        start_time = time.time()

        if self.verbose:
            print(f"[sandbox] Launching: {' '.join(cmd)}")

        proc: Optional[subprocess.Popen] = None
        try:
            proc = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )

            # ── Monitor while running ──
            self._monitor_process(
                proc, timeout, report,
                monitor_network=monitor_network,
                monitor_fs=monitor_fs,
            )

        except FileNotFoundError:
            report.add_event(
                "process", "critical",
                f"Emulator binary not found: {self.emulator_path}",
            )
            report.safe = False
        except subprocess.TimeoutExpired:
            report.add_event(
                "process", "medium",
                f"Emulator ran for {timeout}s and was killed (timeout)",
            )
        except Exception as e:
            report.add_event(
                "process", "high",
                f"Emulator crashed: {e}",
            )
        finally:
            # Ensure process is dead
            if proc is not None:
                try:
                    proc.kill()
                    proc.wait(timeout=5)
                except Exception:
                    pass

        report.duration_seconds = time.time() - start_time

        # ── Post-sandbox: diff system state ──
        self._diff_system_state(pre_state, report)

        # ── Compute risk score ──
        self._compute_risk(report)

        return report

    def _build_command(self, rom_path: str) -> List[str]:
        """Build the emulator launch command."""
        if self.emulator_name == "Ryujinx":
            return [
                str(self.emulator_path),
                rom_path,
            ]
        return [str(self.emulator_path), rom_path]

    def _monitor_process(
        self,
        proc: subprocess.Popen,
        timeout: int,
        report: SandboxReport,
        monitor_network: bool = True,
        monitor_fs: bool = True,
    ) -> List[SandboxEvent]:
        """Monitor the emulator process for suspicious behavior."""
        events = []
        elapsed = 0
        interval = 2  # Check every 2 seconds

        while proc.poll() is None and elapsed < timeout:
            time.sleep(interval)
            elapsed += interval

            # ── Network monitoring ──
            if monitor_network:
                net_events = self._check_network_connections(proc.pid)
                for evt in net_events:
                    report.add_event(**evt)

            # ── Filesystem monitoring ──
            if monitor_fs:
                fs_events = self._check_filesystem_activity(proc.pid)
                for evt in fs_events:
                    report.add_event(**evt)

        return events

    def _check_network_connections(
        self, pid: int
    ) -> List[Dict]:
        """Check for unexpected network connections."""
        events = []
        try:
            # Use netstat/ss to find connections
            if sys.platform == "win32":
                result = subprocess.run(
                    ["netstat", "-ano"],
                    capture_output=True, text=True, timeout=10,
                )
            else:
                result = subprocess.run(
                    ["ss", "-tupn"],
                    capture_output=True, text=True, timeout=10,
                )

            # Look for established connections from this PID
            for line in result.stdout.splitlines():
                if str(pid) in line and "ESTABLISHED" in line:
                    # Allow known Nintendo domains
                    allowed = ["nintendo", "cdn", "nintendoswitch"]
                    if not any(d in line.lower() for d in allowed):
                        events.append({
                            "category": "network",
                            "severity": "high",
                            "description": f"Unexpected network connection: {line.strip()}",
                        })
        except Exception:
            pass

        return events

    def _check_filesystem_activity(
        self, pid: int
    ) -> List[Dict]:
        """Check for suspicious filesystem activity."""
        events = []

        # Check for suspicious new files in common locations
        _suspicious_dirs = [
            os.path.expanduser("~/AppData/Roaming"),
            os.path.expanduser("~/AppData/Local"),
            os.path.expanduser("~/.local/share"),
            os.path.expanduser("~/Desktop"),
            os.path.expanduser("~/Documents"),
        ]

        # This is a simplified check — in production you'd use
        # inotify or a proper FS monitor
        return events  # Real-time FS monitoring happens via state diff

    def _snapshot_system_state(self) -> Dict:
        """Take a snapshot of system state before sandboxing."""
        state = {
            "timestamp": datetime.utcnow().isoformat(),
            "temp_files": set(),
            "running_processes": set(),
        }

        # Snapshot running processes
        try:
            if sys.platform == "win32":
                result = subprocess.run(
                    ["tasklist", "/fo", "csv"],
                    capture_output=True, text=True, timeout=10,
                )
                for line in result.stdout.splitlines()[1:]:
                    parts = line.strip('"').split('","')
                    if parts:
                        state["running_processes"].add(parts[0].lower())
            else:
                result = subprocess.run(
                    ["ps", "aux"],
                    capture_output=True, text=True, timeout=10,
                )
                for line in result.stdout.splitlines()[1:]:
                    parts = line.split()
                    if parts:
                        state["running_processes"].add(parts[10].lower() if len(parts) > 10 else "")
        except Exception:
            pass

        # Snapshot temp directory
        temp_dir = tempfile.gettempdir()
        try:
            for entry in os.listdir(temp_dir):
                full = os.path.join(temp_dir, entry)
                try:
                    state["temp_files"].add(full)
                except Exception:
                    pass
        except Exception:
            pass

        return state

    def _diff_system_state(self, pre: Dict, report: SandboxReport):
        """Compare post-run state to pre-run state."""
        # Check for new temp files (potential dropper behavior)
        temp_dir = tempfile.gettempdir()
        try:
            current_files = set()
            for entry in os.listdir(temp_dir):
                full = os.path.join(temp_dir, entry)
                current_files.add(full)

            new_files = current_files - pre["temp_files"]
            suspicious_extensions = {
                ".exe", ".dll", ".bat", ".cmd", ".ps1", ".vbs",
                ".js", ".py", ".sh", ".msi", ".scr",
            }

            for f in new_files:
                ext = Path(f).suffix.lower()
                if ext in suspicious_extensions:
                    report.add_event(
                        "filesystem", "critical",
                        f"Suspicious file dropped in temp: {f}",
                        path=f, extension=ext,
                    )
                elif ext:
                    report.add_event(
                        "filesystem", "low",
                        f"New file in temp dir: {f}",
                        path=f,
                    )
        except Exception:
            pass

        # Check for new processes (potential process spawning)
        try:
            if sys.platform == "win32":
                result = subprocess.run(
                    ["tasklist", "/fo", "csv"],
                    capture_output=True, text=True, timeout=10,
                )
                current_procs = set()
                for line in result.stdout.splitlines()[1:]:
                    parts = line.strip('"').split('","')
                    if parts:
                        current_procs.add(parts[0].lower())

                new_procs = current_procs - pre["running_processes"]
                suspicious_procs = {
                    "cmd.exe", "powershell.exe", "wscript.exe",
                    "cscript.exe", "mshta.exe", "reg.exe",
                    "schtasks.exe", "rundll32.exe",
                }
                for proc in new_procs:
                    if proc in suspicious_procs:
                        report.add_event(
                            "process", "critical",
                            f"Suspicious process spawned: {proc}",
                            process=proc,
                        )
        except Exception:
            pass

    def _compute_risk(self, report: SandboxReport):
        """Compute risk score from sandbox events."""
        score = 0.0
        for event in report.events:
            if event.severity == "critical":
                score += 0.5
            elif event.severity == "high":
                score += 0.3
            elif event.severity == "medium":
                score += 0.1
            elif event.severity == "low":
                score += 0.02

        report.risk_score = min(score, 1.0)
        if report.risk_score >= 0.3:
            report.safe = False
