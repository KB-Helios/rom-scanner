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

    YUZU_PATHS = [
        # Windows standard install paths
        os.path.expanduser("~/AppData/Roaming/yuzu/yuzu.exe"),
        os.path.expanduser("~/AppData/Local/yuzu/yuzu-windows-msvc/yuzu.exe"),
        "C:/Program Files/yuzu/yuzu.exe",
        "C:/Program Files (x86)/yuzu/yuzu.exe",
        os.path.expanduser("~/AppData/Local/Programs/yuzu/yuzu.exe"),
    ]

    SUSPICIOUS_EXTENSIONS = {
        ".exe", ".dll", ".bat", ".cmd", ".ps1", ".vbs",
        ".js", ".py", ".sh", ".msi", ".scr",
    }

    DEEP_FS_DIRS = [
        "~/AppData/Roaming",
        "~/AppData/Local",
        "~/.local/share",
        "~/Desktop",
        "~/Documents",
    ]

    def __init__(
        self,
        verbose: bool = False,
        preferred_emulator: str = "auto",
        *,
        monitor_registry: bool = True,
        monitor_fs_depth: str = "basic",
    ):
        self.verbose = verbose
        self.preferred_emulator = preferred_emulator.lower()
        self.monitor_registry = monitor_registry
        self.monitor_fs_depth = monitor_fs_depth.lower()
        self.emulator_path: Optional[str] = None
        self.emulator_name: str = ""
        self._temp_fs_baseline: set = set()
        self._reported_fs_paths: set = set()
        self._find_emulator()

    def _find_emulator(self) -> bool:
        """Locate an installed Switch emulator."""
        if self.preferred_emulator == "yuzu":
            return self._try_yuzu() or self._try_ryujinx()
        # Default: try Ryujinx first, then Yuzu
        return self._try_ryujinx() or self._try_yuzu()

    def _try_ryujinx(self) -> bool:
        """Try to locate Ryujinx."""
        for path in self.RYUJINX_PATHS:
            if Path(path).exists():
                self.emulator_path = path
                self.emulator_name = "Ryujinx"
                return True
        for name in ["Ryujinx", "ryujinx"]:
            found = shutil.which(name)
            if found:
                self.emulator_path = found
                self.emulator_name = "Ryujinx"
                return True
        return False

    def _try_yuzu(self) -> bool:
        """Try to locate Yuzu."""
        for path in self.YUZU_PATHS:
            if Path(path).exists():
                self.emulator_path = path
                self.emulator_name = "Yuzu"
                return True
        for name in ["yuzu", "yuzu-cmd"]:
            found = shutil.which(name)
            if found:
                self.emulator_path = found
                self.emulator_name = "Yuzu"
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
        self._temp_fs_baseline = self._snapshot_temp_files()
        self._reported_fs_paths = set()
        pre_state = self._snapshot_system_state()
        pre_state["temp_files"] = set(self._temp_fs_baseline)

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
        if self.emulator_name == "Yuzu":
            # Yuzu uses -g flag to load a game
            return [str(self.emulator_path), "-g", rom_path]
        # Ryujinx and default: positional argument
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

    def _netstat_pid_matches(self, line: str, pid: int) -> bool:
        """Return True if a netstat/ss line belongs to the given PID."""
        parts = line.split()
        if not parts:
            return False
        if sys.platform == "win32":
            # TCP/UDP ... ESTABLISHED <pid>
            return parts[-1] == str(pid) and "ESTABLISHED" in line
        # ss -tupn: ... users:(("proc",pid=1234,fd=...))
        pid_marker = f"pid={pid}"
        return pid_marker in line and "ESTAB" in line

    def _check_network_connections(
        self, pid: int
    ) -> List[Dict]:
        """Check for unexpected network connections, filtered by PID."""
        events = []
        allowed = ["nintendo", "cdn", "nintendoswitch"]
        try:
            if sys.platform == "win32":
                result = subprocess.run(
                    ["netstat", "-ano"],
                    capture_output=True, text=True, timeout=10,
                )
                for line in result.stdout.splitlines():
                    if not self._netstat_pid_matches(line, pid):
                        continue
                    if not any(d in line.lower() for d in allowed):
                        events.append({
                            "category": "network",
                            "severity": "high",
                            "description": f"Unexpected network connection: {line.strip()}",
                        })
            else:
                result = subprocess.run(
                    ["ss", "-tupn"],
                    capture_output=True, text=True, timeout=10,
                )
                for line in result.stdout.splitlines():
                    if not self._netstat_pid_matches(line, pid):
                        continue
                    if not any(d in line.lower() for d in allowed):
                        events.append({
                            "category": "network",
                            "severity": "high",
                            "description": f"Unexpected network connection: {line.strip()}",
                        })
        except Exception:
            pass

        return events

    def _snapshot_temp_files(self) -> set:
        """Snapshot file paths in the system temp directory."""
        temp_dir = tempfile.gettempdir()
        snapshot: set = set()
        try:
            for entry in os.listdir(temp_dir):
                full = os.path.join(temp_dir, entry)
                try:
                    if os.path.isfile(full):
                        snapshot.add(full)
                except OSError:
                    pass
        except OSError:
            pass
        return snapshot

    def _temp_snapshot_diff_events(self) -> List[Dict]:
        """Compare current temp dir against pre-sandbox baseline."""
        events: List[Dict] = []
        current = self._snapshot_temp_files()
        new_files = current - self._temp_fs_baseline - self._reported_fs_paths

        for path in new_files:
            ext = Path(path).suffix.lower()
            if ext in self.SUSPICIOUS_EXTENSIONS:
                events.append({
                    "category": "filesystem",
                    "severity": "critical",
                    "description": f"Suspicious file dropped in temp: {path}",
                    "path": path,
                    "extension": ext,
                })
            elif ext:
                events.append({
                    "category": "filesystem",
                    "severity": "low",
                    "description": f"New file in temp dir: {path}",
                    "path": path,
                })
            self._reported_fs_paths.add(path)

        return events

    def _deep_fs_scan_events(self) -> List[Dict]:
        """Deep mode: flag recently modified executables outside temp."""
        events: List[Dict] = []
        cutoff = time.time() - 10
        for rel in self.DEEP_FS_DIRS:
            check_path = Path(os.path.expanduser(rel))
            if not check_path.exists():
                continue
            try:
                for entry in check_path.iterdir():
                    if not entry.is_file():
                        continue
                    ext = entry.suffix.lower()
                    if ext not in self.SUSPICIOUS_EXTENSIONS:
                        continue
                    path_str = str(entry)
                    if path_str in self._reported_fs_paths:
                        continue
                    try:
                        if entry.stat().st_mtime > cutoff:
                            events.append({
                                "category": "filesystem",
                                "severity": "high",
                                "description": f"Executable file recently modified: {entry}",
                                "path": path_str,
                            })
                            self._reported_fs_paths.add(path_str)
                    except OSError:
                        pass
            except (OSError, PermissionError):
                pass
        return events

    def _check_filesystem_activity(
        self, pid: int
    ) -> List[Dict]:
        """Check filesystem activity via pre/post temp snapshot diff."""
        events = self._temp_snapshot_diff_events()
        if self.monitor_fs_depth == "deep":
            events.extend(self._deep_fs_scan_events())
        return events

    def _reg_query(self, key: str) -> List[str]:
        """Query a Windows registry key; return list of value strings."""
        if sys.platform != "win32":
            return []
        try:
            result = subprocess.run(
                ["reg", "query", key],
                capture_output=True, text=True, timeout=10,
            )
            return [line.strip() for line in result.stdout.splitlines() if line.strip()]
        except Exception:
            return []

    def _snapshot_registry(self) -> Dict[str, List[str]]:
        """Snapshot Windows Run/RunOnce registry keys."""
        if sys.platform != "win32":
            return {}
        run_keys = [
            r"HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
            r"HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
            r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
            r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
        ]
        return {key: self._reg_query(key) for key in run_keys}

    def _diff_registry(self, pre: Dict[str, List[str]], report: SandboxReport):
        """Compare pre/post registry snapshots and emit events for new entries."""
        post = self._snapshot_registry()
        for key, post_values in post.items():
            pre_values = set(pre.get(key, []))
            for val in post_values:
                if val not in pre_values:
                    report.add_event(
                        "registry", "critical",
                        f"New registry Run entry: {val}",
                        key=key,
                        value=val,
                    )

    def _snapshot_system_state(self) -> Dict:
        """Take a snapshot of system state before sandboxing."""
        state = {
            "timestamp": datetime.utcnow().isoformat(),
            "temp_files": set(),
            "running_processes": set(),
            "registry": {},
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

        # Snapshot temp directory (reuse baseline captured at run start)
        state["temp_files"] = set(self._temp_fs_baseline)

        # Snapshot registry Run keys (Windows only)
        if self.monitor_registry:
            state["registry"] = self._snapshot_registry()

        return state

    def _diff_system_state(self, pre: Dict, report: SandboxReport):
        """Compare post-run state to pre-run state."""
        # Final temp snapshot diff (catches files created after last poll)
        for evt in self._temp_snapshot_diff_events():
            report.add_event(**evt)

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

        # Check registry for new Run/RunOnce entries
        if self.monitor_registry:
            self._diff_registry(pre.get("registry", {}), report)

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
