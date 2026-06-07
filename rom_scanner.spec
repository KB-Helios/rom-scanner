# -*- mode: python ; coding: utf-8 -*-
"""PyInstaller spec: rom-scanner CLI + rom-scanner-tray (Windows one-file exes)."""

from pathlib import Path

block_cipher = None
root = Path(SPECPATH)

scanner_datas = [
    (str(root / "scanner" / "threat_db.json"), "scanner"),
    (str(root / "scanner" / "homebrew_db.json"), "scanner"),
]

cli_hiddenimports = [
    "scanner.av_scanner",
    "scanner.config",
    "scanner.db",
    "scanner.hash_scanner",
    "scanner.logging_config",
    "scanner.manifest",
    "scanner.pipeline",
    "scanner.recovery",
    "scanner.sandbox",
    "scanner.storage",
    "scanner.threat_feed",
    "scanner.watch",
    "parsers.nsp_parser",
    "parsers.xci_parser",
]

tray_hiddenimports = cli_hiddenimports + [
    "pystray",
    "pystray._win32",
    "PIL",
    "PIL.Image",
    "PIL.ImageDraw",
    "PIL._imaging",
    "tray.notifier",
]

# ── rom-scanner CLI ──────────────────────────────────────────────
a_cli = Analysis(
    [str(root / "rom_scanner.py")],
    pathex=[str(root)],
    binaries=[],
    datas=scanner_datas,
    hiddenimports=cli_hiddenimports,
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
    noarchive=False,
    optimize=0,
)
pyz_cli = PYZ(a_cli.pure, a_cli.zipped_data, cipher=block_cipher)
exe_cli = EXE(
    pyz_cli,
    a_cli.scripts,
    a_cli.binaries,
    a_cli.zipfiles,
    a_cli.datas,
    [],
    name="rom-scanner",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=True,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
)

# ── rom-scanner-tray ─────────────────────────────────────────────
a_tray = Analysis(
    [str(root / "tray" / "app.py")],
    pathex=[str(root)],
    binaries=[],
    datas=scanner_datas,
    hiddenimports=tray_hiddenimports,
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
    noarchive=False,
    optimize=0,
)
pyz_tray = PYZ(a_tray.pure, a_tray.zipped_data, cipher=block_cipher)
exe_tray = EXE(
    pyz_tray,
    a_tray.scripts,
    a_tray.binaries,
    a_tray.zipfiles,
    a_tray.datas,
    [],
    name="rom-scanner-tray",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=False,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
)
