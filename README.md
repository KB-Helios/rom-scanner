# ROM Scanner & Sandbox

A security analysis tool for Nintendo Switch ROM files (NSP/XCI). Parses binary containers, validates structure, hashes contents, checks VirusTotal and Windows Defender, and routes files through a quarantine pipeline before they reach your emulator library.

## Features

- **NSP (PFS0) / XCI (HFS0) parsers** — full binary container parsing
- **Hash extraction** — SHA-256, MD5, SHA-1 for every contained file
- **VirusTotal integration** — optional hash lookups (API key required)
- **Windows Defender** — local AV scan before static analysis (production pipeline)
- **Local threat DB** — match against known-malicious ROM hashes
- **Quarantine pipeline** — `incoming → scanning → approved / quarantined`
- **Sandboxie-isolated downloads** — Chrome in a dedicated box; `watch` auto-ingests
- **System tray notifier** — scan verdicts, folder shortcuts, watch control
- **Ryujinx sandbox runner** — optional behavioral analysis
- **Risk scoring** — 0.0–1.0 with structured logging to `rom-scanner.log`

## Production Quick Start (Windows)

```powershell
# Clone and install (CLI + tray)
cd rom-scanner
.\scripts\install.ps1

# Or manually:
python -m pip install -e ".[tray]"
set ROM_SCANNER_HOME=C:\RomScanner
rom-scanner init
```

1. **Sandboxie** — follow [docs/sandboxie-setup.md](docs/sandboxie-setup.md) to create the `RomQuarantine` box.
2. **Watch daemon** — `rom-scanner watch --daemon` (registered at logon by `install.ps1`).
3. **Tray** — `rom-scanner-tray` for notifications and quick actions.
4. **Download** — tray menu → *Launch sandboxed Chrome*; save NSP/XCI inside the sandbox.
5. **Play** — only load games from `approved/` in Ryujinx (`rom-scanner configure-ryujinx`).

Full deployment guide: [docs/production-deployment.md](docs/production-deployment.md).

## Developer Quick Start

```bash
# Editable install with test/lint/type-check tooling
pip install -e ".[dev,tray]"

# Lint, type check, and test
python -m ruff check .
python -m pyrefly check
python -m pytest tests/ -v

# Quick safety check (static, no VT)
python rom_scanner.py quick game.nsp

# Full static scan
python rom_scanner.py scan game.nsp

# Full scan with VirusTotal
python rom_scanner.py scan game.nsp --vt-key YOUR_API_KEY

# JSON output for scripting
python rom_scanner.py scan game.nsp --json

# Sandbox run (requires Ryujinx)
python rom_scanner.py sandbox game.nsp
```

After `pip install -e .`, use the `rom-scanner` command instead of `python rom_scanner.py`.

CI runs ruff, pyrefly, and pytest on **windows-latest** via
[`.github/workflows/ci.yml`](.github/workflows/ci.yml). Pyrefly is Meta's fast Rust-based Python type
checker; configuration lives in `[tool.pyrefly]` in `pyproject.toml`.

## Quarantine Pipeline

Files move through staged directories under `ROM_SCANNER_HOME`:

```
C:\RomScanner\                 # production default (or ~/rom-scanner)
├── config.json
├── rom-scanner.log
├── scans.db                   # SQLite manifest
├── incoming/
├── scanning/
├── approved/                  # Ryujinx game_dirs target
├── quarantined/
└── sbx\RomQuarantine\...      # Sandboxie download isolation
```

Set a custom home:

```powershell
set ROM_SCANNER_HOME=C:\path\to\my-scanner-data
```

### Pipeline commands

```bash
rom-scanner init                          # Create layout + config.json
rom-scanner ingest game.nsp               # Copy → scan → route
rom-scanner watch --daemon                # Auto-ingest from Sandboxie Downloads
rom-scanner launch-chrome                 # Sandboxed Chrome
rom-scanner promote game.nsp              # Manual approve after review
rom-scanner quarantine game.nsp           # Force quarantine
rom-scanner status                        # List manifest entries
rom-scanner status --stage quarantined
rom-scanner export --format json          # Scripting export
```

## Configuration Reference

`config.json` lives in `ROM_SCANNER_HOME`. Environment variables override where noted.

| Key | Default | Description |
|-----|---------|-------------|
| `home` | `ROM_SCANNER_HOME` or `~/rom-scanner` | Pipeline root |
| `sandboxie.box_name` | `RomQuarantine` | Sandboxie box for Chrome |
| `sandboxie.downloads_path` | `{home}/sbx/.../Downloads` | Folder watched by `watch` |
| `sandboxie.start_exe` | `C:/Program Files/Sandboxie-Plus/Start.exe` | Sandboxie launcher |
| `scan.vt_api_key_env` | `VIRUSTOTAL_API_KEY` | Env var name for VT key |
| `scan.defender_scan` | `true` | Run Windows Defender before static scan |
| `scan.risk_threshold` | `0.3` | Score above this → quarantine |
| `watch.poll_interval_sec` | `5` | Download folder poll interval |
| `watch.stable_size_sec` | `10` | Wait for stable file size before ingest |
| `watch.extensions` | `[".nsp", ".xci"]` | Extensions to ingest |
| `ryujinx.games_path` | `{home}/approved` | Approved library path |

Example:

```json
{
  "home": "C:/RomScanner",
  "sandboxie": {
    "box_name": "RomQuarantine",
    "downloads_path": "C:/RomScanner/sbx/RomQuarantine/user/current/Downloads",
    "start_exe": "C:/Program Files/Sandboxie-Plus/Start.exe"
  },
  "scan": {
    "vt_api_key_env": "VIRUSTOTAL_API_KEY",
    "defender_scan": true,
    "risk_threshold": 0.3
  },
  "watch": {
    "poll_interval_sec": 5,
    "stable_size_sec": 10,
    "extensions": [".nsp", ".xci"]
  },
  "ryujinx": {
    "games_path": "C:/RomScanner/approved"
  }
}
```

## How It Works

### Automated ingest (`watch` / `ingest`)

1. **Defender** — `MpCmdRun.exe` custom scan on the raw file
2. **Static HashScanner** — parse NSP/XCI, validate structure, hash entries
3. **Threat checks** — local DB + optional VirusTotal per-entry
4. **Route** — move to `approved/` or `quarantined/`, record in `scans.db`

### Static analysis (`scan` / `quick`)

1. Parses the binary container (PFS0 / HFS0)
2. Validates magic bytes, offsets, overlapping regions
3. Extracts contained files with hashes
4. Flags suspicious extensions (.exe, .dll, .bat inside a ROM)
5. Validates ROM-specific structure (CNMT, tickets, partitions)
6. Queries VirusTotal when an API key is set
7. Computes risk score and verdict

### Sandbox analysis (`sandbox`)

1. Snapshots system state
2. Launches ROM in Ryujinx
3. Monitors network, temp-file drops, process spawning
4. Diffs pre/post state and combines with static report

## Threat Model

### What ROM Scanner detects

| Threat | Method |
|--------|--------|
| Trojans / droppers inside ROMs | Suspicious file extensions in NSP/XCI |
| Known-malicious hashes | Local threat DB + VirusTotal |
| Tampered containers | Structural validation, offset checks |
| Windows malware on disk | Windows Defender (pipeline ingest) |
| Behavioral indicators | Ryujinx sandbox (optional): network, temp drops, child processes |

### What it does not guarantee

- **Zero-day malware** not in Defender, VT, or the local DB
- **Malware outside the ROM container** on your host (use Sandboxie for downloads)
- **Emulator exploits** — Ryujinx sandbox is shallow; only load `approved/` files
- **Legal compliance** — you are responsible for only scanning ROMs you may possess
- **Torrent / URL download safety** — out of scope; use sandboxed Chrome only

### Fail-closed behavior

- Defender error or detection → `quarantined`
- Static scan failure or high risk score → `quarantined`
- Interrupted scan → recovery re-queues or quarantines with `scan_interrupted`
- Manual `promote` is required to override a quarantine after human review

## VirusTotal

Get a free API key at https://www.virustotal.com/

```powershell
set VIRUSTOTAL_API_KEY=your_key_here
rom-scanner scan game.nsp
```

Free tier is rate-limited (HTTP 429). The scanner backs off after rate limits; large ROMs may skip per-entry VT lookups.

## System Tray

```powershell
pip install rom-scanner[tray]
rom-scanner-tray
```

Tray menu: status, open approved/quarantined folders, launch sandboxed Chrome, start/stop watch daemon, exit. Verdict notifications poll `scans.db` (falls back to `manifest.json` during migration).

## Project Structure

```
rom-scanner/
├── rom_scanner.py              # CLI entry point
├── pyproject.toml              # Package + entry points
├── scripts/install.ps1         # Windows production installer
├── tray/
│   ├── app.py                  # System tray (pystray)
│   └── notifier.py             # Verdict polling
├── parsers/
│   ├── nsp_parser.py
│   └── xci_parser.py
├── scanner/
│   ├── hash_scanner.py
│   ├── storage.py
│   ├── manifest.py
│   ├── logging_config.py
│   ├── sandbox.py
│   └── threat_db.json
└── docs/
    ├── sandboxie-setup.md
    └── production-deployment.md
```

## Requirements

- **Python 3.10+** — core scanning uses stdlib only
- **Windows 10/11** — Defender, Sandboxie, tray, and `install.ps1`
- **Sandboxie-Plus** — isolated Chrome downloads (production)
- **Ryujinx** — optional sandbox mode
- **VirusTotal API key** — optional VT lookups
- **Tray extras** — `pip install rom-scanner[tray]` (pystray, Pillow)

## Disclaimer

This tool is for **security analysis** of files you own. Always dump your own games from cartridges you own. Downloading commercial ROMs you don't own is copyright infringement.

## License

MIT
