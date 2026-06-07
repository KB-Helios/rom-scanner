"""Tests for scanner/sandbox.py."""

from unittest.mock import patch

from scanner.sandbox import SandboxReport, SandboxRunner


def test_no_emulator_marks_unsafe(tmp_path):
    with patch.object(SandboxRunner, "_find_emulator", return_value=False):
        runner = SandboxRunner()
        runner.emulator_path = None
        runner.emulator_name = ""

    assert not runner.is_available()
    rom = tmp_path / "game.nsp"
    rom.write_bytes(b"PFS0" + b"\x00" * 32)
    report = runner.run_sandbox(str(rom))
    assert report.safe is False
    assert report.risk_score > 0.0


def test_build_command_ryujinx(tmp_path):
    runner = SandboxRunner.__new__(SandboxRunner)
    runner.verbose = False
    runner.preferred_emulator = "auto"
    runner.emulator_path = "C:/Ryujinx/Ryujinx.exe"
    runner.emulator_name = "Ryujinx"

    cmd = runner._build_command("game.nsp")
    assert cmd == ["C:/Ryujinx/Ryujinx.exe", "game.nsp"]
    assert "-g" not in cmd


def test_build_command_yuzu(tmp_path):
    runner = SandboxRunner.__new__(SandboxRunner)
    runner.verbose = False
    runner.preferred_emulator = "yuzu"
    runner.emulator_path = "C:/yuzu/yuzu.exe"
    runner.emulator_name = "Yuzu"

    cmd = runner._build_command("game.nsp")
    assert "-g" in cmd
    assert "game.nsp" in cmd
    assert cmd[0] == "C:/yuzu/yuzu.exe"


def test_compute_risk_from_events():
    report = SandboxReport(
        rom_path="game.nsp",
        emulator_used="Ryujinx",
        duration_seconds=5.0,
    )
    report.add_event(
        "filesystem", "critical",
        "Suspicious file dropped in temp: /tmp/payload.exe",
        path="/tmp/payload.exe",
    )
    runner = SandboxRunner.__new__(SandboxRunner)
    runner._compute_risk(report)
    assert report.risk_score >= 0.5
    assert report.safe is False


def test_netstat_pid_matches():
    runner = SandboxRunner.__new__(SandboxRunner)
    runner.verbose = False
    runner.preferred_emulator = "auto"
    runner.monitor_registry = True
    runner.monitor_fs_depth = "basic"
    pid = 4242
    line = "  TCP    10.0.0.1:443    192.168.1.1:50123    ESTABLISHED    4242"
    assert runner._netstat_pid_matches(line, pid) is True
    assert runner._netstat_pid_matches(line, 9999) is False
    assert runner._netstat_pid_matches("  TCP    0.0.0.0:80    0.0.0.0:0    LISTENING    4242", pid) is False


def test_temp_snapshot_diff_detects_new_exe(tmp_path, monkeypatch):
    temp_dir = tmp_path / "temp"
    temp_dir.mkdir()
    monkeypatch.setattr("scanner.sandbox.tempfile.gettempdir", lambda: str(temp_dir))

    runner = SandboxRunner.__new__(SandboxRunner)
    runner.monitor_fs_depth = "basic"
    runner._reported_fs_paths = set()
    runner._temp_fs_baseline = runner._snapshot_temp_files()

    dropper = temp_dir / "payload.exe"
    dropper.write_bytes(b"MZ")
    events = runner._temp_snapshot_diff_events()
    assert any("payload.exe" in e["description"] for e in events)
    assert events[0]["severity"] == "critical"


def test_diff_registry_skipped_when_disabled():
    runner = SandboxRunner.__new__(SandboxRunner)
    runner.monitor_registry = False
    runner._temp_fs_baseline = set()
    runner._reported_fs_paths = set()
    report = SandboxReport(
        rom_path="game.nsp",
        emulator_used="Ryujinx",
        duration_seconds=1.0,
    )
    with patch.object(SandboxRunner, "_snapshot_registry") as mock_snap:
        runner._diff_system_state({"registry": {}, "running_processes": set()}, report)
        mock_snap.assert_not_called()
