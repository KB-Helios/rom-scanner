"""Tests for scanner/av_scanner.py."""

from unittest.mock import MagicMock, patch

from scanner.av_scanner import scan_file


def test_disabled_returns_not_scanned(tmp_path):
    f = tmp_path / "game.nsp"
    f.write_bytes(b"PFS0" + b"\x00" * 32)
    result = scan_file(str(f), enabled=False)
    assert result.scanned is False
    assert result.clean is True


def test_mpcmdrun_missing_fail_closed(tmp_path):
    f = tmp_path / "game.nsp"
    f.write_bytes(b"PFS0" + b"\x00" * 32)
    with patch("scanner.av_scanner._find_mpcmdrun", return_value=None):
        with patch("scanner.av_scanner.sys") as mock_sys:
            mock_sys.platform = "win32"
            result = scan_file(str(f), enabled=True)
    assert result.scanned is False
    assert result.clean is False
    assert any("MpCmdRun" in e for e in result.errors)


def test_detection_exit_code_2(tmp_path):
    f = tmp_path / "game.nsp"
    f.write_bytes(b"PFS0" + b"\x00" * 32)
    mock_proc = MagicMock()
    mock_proc.returncode = 2
    mock_proc.stdout = "Threat detected: Win32/Trojan"
    mock_proc.stderr = ""
    fake_exe = tmp_path / "MpCmdRun.exe"
    fake_exe.write_bytes(b"")
    with patch("scanner.av_scanner._find_mpcmdrun", return_value=fake_exe):
        with patch("scanner.av_scanner.sys") as mock_sys:
            mock_sys.platform = "win32"
            with patch("subprocess.run", return_value=mock_proc):
                result = scan_file(str(f), enabled=True)
    assert result.scanned is True
    assert result.clean is False


def test_clean_scan(tmp_path):
    f = tmp_path / "game.nsp"
    f.write_bytes(b"PFS0" + b"\x00" * 32)
    mock_proc = MagicMock()
    mock_proc.returncode = 0
    mock_proc.stdout = "Scanning ... No threats found."
    mock_proc.stderr = ""
    fake_exe = tmp_path / "MpCmdRun.exe"
    fake_exe.write_bytes(b"")
    with patch("scanner.av_scanner._find_mpcmdrun", return_value=fake_exe):
        with patch("scanner.av_scanner.sys") as mock_sys:
            mock_sys.platform = "win32"
            with patch("subprocess.run", return_value=mock_proc):
                result = scan_file(str(f), enabled=True)
    assert result.scanned is True
    assert result.clean is True


def test_non_windows_fail_closed(tmp_path):
    f = tmp_path / "game.nsp"
    f.write_bytes(b"PFS0" + b"\x00" * 32)
    with patch("scanner.av_scanner.sys") as mock_sys:
        mock_sys.platform = "linux"
        result = scan_file(str(f), enabled=True)
    assert result.scanned is False
    assert result.clean is False
    assert any("Windows" in e for e in result.errors)
