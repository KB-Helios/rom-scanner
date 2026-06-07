# Production Deployment Guide

This guide covers a full Windows production setup: isolated downloads, automated scanning, system tray notifications, and Ryujinx integration.

## Directory layout

Default home: `C:\RomScanner` (override with `ROM_SCANNER_HOME`).

```
C:\RomScanner\
├── config.json           # Pipeline, Sandboxie, scan, and watch settings
├── rom-scanner.log       # Rotating application log
├── scans.db              # SQLite scan manifest (replaces manifest.json)
├── incoming/             # New files awaiting scan
├── scanning/             # Active scan in progress
├── approved/             # Clean files — Ryujinx game_dirs target
├── quarantined/          # Failed or suspicious files
└── sbx\RomQuarantine\    # Sandboxie file root
    └── user\current\Downloads\   # Watch target for Chrome downloads
```

## Quick install

From a clone of this repository (PowerShell as your user):

```powershell
cd C:\path\to\rom-scanner
.\scripts\install.ps1
```

The installer:

1. `pip install -e ".[tray]"` — CLI + tray entry points
2. `rom-scanner init` — creates layout and default config
3. Registers Task Scheduler task **RomScannerWatch** (`rom-scanner watch --daemon` at logon)
4. Adds a Startup shortcut for **rom-scanner-tray**

## Standalone installer (no Python required)

Build self-contained executables with PyInstaller:

```powershell
pip install -e ".[build,tray]"
.\scripts\build-installer.ps1
```

Output: `release\rom-scanner\`

- `release\rom-scanner\rom-scanner.exe` — CLI (console)
- `release\rom-scanner\rom-scanner-tray.exe` — System tray (no console window)

Copy the entire `release\rom-scanner\` folder to the target machine. No Python installation
required. Set `ROM_SCANNER_HOME` and run `rom-scanner.exe init` to get started.

To rebuild cleanly:

```powershell
.\scripts\build-installer.ps1 -Clean
```

## Manual setup

### 1. Install the package

```powershell
python -m pip install -e ".[tray]"
```

Optional development tools:

```powershell
python -m pip install -e ".[dev]"
```

### 2. Initialize

```powershell
set ROM_SCANNER_HOME=C:\RomScanner
rom-scanner init
```

### 3. Environment variables

| Variable | Purpose |
|----------|---------|
| `ROM_SCANNER_HOME` | Pipeline root (default `~\rom-scanner` or `C:\RomScanner` in production) |
| `VIRUSTOTAL_API_KEY` | VirusTotal API key for hash lookups |

### 4. Sandboxie + Chrome

See [sandboxie-setup.md](sandboxie-setup.md).

### 5. Watch daemon

Foreground (debugging):

```powershell
rom-scanner watch --verbose
```

Background (`--daemon` also drains `incoming/` each poll when `watch.drain_incoming_on_poll` is true):

```powershell
rom-scanner watch --daemon
```

Task Scheduler (installed by `install.ps1`):

```powershell
Get-ScheduledTask -TaskName RomScannerWatch
```

### 6. System tray

```powershell
rom-scanner-tray
```

Tray menu:

- **Status** — last verdict and pending count
- **Open approved / quarantined** — Explorer shortcuts
- **Launch sandboxed Chrome** — `rom-scanner launch-chrome`
- **Start / stop watch daemon** — subprocess control
- **Exit**

## Standalone executables (PyInstaller)

For machines without Python installed, build one-file Windows exes from the repo:

```powershell
.\scripts\build-installer.ps1
```

Output:

```
release\rom-scanner\rom-scanner.exe
release\rom-scanner\rom-scanner-tray.exe
```

Bundled `threat_db.json` and `homebrew_db.json` ship inside each exe; `HashScanner` resolves them via `_bundled_path()` when `sys.frozen` is set. Pipeline data (`config.json`, `scans.db`, stage folders) still lives under `ROM_SCANNER_HOME` — run `rom-scanner.exe init` once on the target machine.

Optional build extra:

```powershell
python -m pip install -e ".[build,tray]"
python -m PyInstaller --noconfirm --clean rom_scanner.spec
```

Point Task Scheduler and Startup shortcuts at the `.exe` paths instead of pip entry points when deploying frozen builds.

## Threat feed

Configure a remote JSON feed in `config.json`:

```json
{
  "scan": {
    "threat_feed_url": "https://example.com/threat_db.json",
    "threat_feed_interval_hours": 24,
    "threat_db_path": "C:\\RomScanner\\threat_db.json"
  }
}
```

Update manually or on a schedule:

```powershell
rom-scanner update-threat-db
rom-scanner update-threat-db --force
```

The watch daemon calls `update_if_stale()` on startup when `threat_feed_url` is set. ETag-based conditional fetch avoids re-downloading unchanged feeds.

## Sandbox monitoring

Behavioral sandbox settings under `sandbox` in `config.json`:

| Key | Default | Purpose |
|-----|---------|---------|
| `preferred_emulator` | `auto` | `auto`, `ryujinx`, or `yuzu` |
| `monitor_registry` | `true` | Diff HKCU/HKLM Run and RunOnce before/after emulator run |
| `monitor_fs_depth` | `basic` | `basic` = temp-dir snapshot diff; `deep` = also scan AppData/Desktop for new executables |

Network monitoring uses PID-filtered `netstat -ano` (Windows) or `ss -tupn` (Linux).

## Ryujinx approved library

Point Ryujinx at `approved/` only:

```powershell
rom-scanner configure-ryujinx
```

This backs up `%APPDATA%\Ryujinx\Config.json` and sets `game_dirs` to your approved path.

**Never** add `incoming/`, `scanning/`, or `quarantined/` to Ryujinx.

## Logging

Logs write to `{ROM_SCANNER_HOME}/rom-scanner.log` with rotation (5 MB × 3 files).

Enable debug output on the CLI:

```powershell
rom-scanner --verbose watch
rom-scanner --verbose ingest game.nsp
```

## Scan pipeline order

Automated ingest (`watch` or `ingest`):

1. **Windows Defender** — `MpCmdRun.exe` custom scan (config: `scan.defender_scan`)
2. **Static HashScanner** — NSP/XCI parse, local threat DB, optional VirusTotal
3. **Route** — `approved/` or `quarantined/`, recorded in `scans.db`

Manual override after review:

```powershell
rom-scanner promote filename.nsp
rom-scanner quarantine filename.nsp
```

## Troubleshooting

### Files stuck in `scanning/`

A crash during scan can leave orphans. Recovery runs on `init`, `watch`, and `ingest` startup:

- Re-queues or quarantines with `verdict=scan_interrupted`

Manual check:

```powershell
dir %ROM_SCANNER_HOME%\scanning
rom-scanner status --stage scanning
```

### Defender false positives

1. Inspect `rom-scanner.log` for Defender output.
2. Temporarily disable Defender scan in `config.json`:
   ```json
   { "scan": { "defender_scan": false } }
   ```
3. After manual review, use `rom-scanner promote`.

### Sandboxie path changes after upgrade

1. Open Sandboxie-Plus → RomQuarantine → Sandbox Options → Resource Access.
2. Note the sandbox Downloads path.
3. Update `sandboxie.downloads_path` in `config.json`.
4. Restart the watch daemon.

### VirusTotal rate limits (HTTP 429)

- Set `VIRUSTOTAL_API_KEY`; free tier is rate-limited.
- Scanner backs off after 429; large ROMs may skip per-entry VT lookups.
- Container SHA-256 is checked first when configured.

### Tray not notifying

1. Confirm `rom-scanner-tray` is running (Startup shortcut or manual).
2. Check `scans.db` has new rows: `rom-scanner status`
3. Review `rom-scanner.log` for notifier errors.

### UTF-8 / emoji in console

`rom_scanner.py` reconfigures stdout/stderr to UTF-8 on Windows. If icons still fail, use `--json` output or check the log file.

## Export and scripting

```powershell
rom-scanner export --format json
rom-scanner status --stage quarantined
rom-scanner scan game.nsp --json
```

## Uninstall

```powershell
Unregister-ScheduledTask -TaskName RomScannerWatch -Confirm:$false
Remove-Item "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup\ROM Scanner Tray.lnk" -ErrorAction SilentlyContinue
python -m pip uninstall rom-scanner
```

Pipeline data under `ROM_SCANNER_HOME` is not removed automatically.
