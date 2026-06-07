"""
ROM Scanner & Sandbox — CLI
===========================
Command-line interface for scanning NSP/XCI files for malware
and running them in a sandboxed emulator environment.

Usage:
    python rom_scanner.py scan <file.nsp|xci> [--vt-key KEY] [--json]
    python rom_scanner.py sandbox <file.nsp|xci> [--timeout 60] [--no-network]
    python rom_scanner.py quick <file.nsp|xci>
    python rom_scanner.py ingest <file.nsp|xci>
    python rom_scanner.py promote <file>
    python rom_scanner.py quarantine <file>
    python rom_scanner.py status
    python rom_scanner.py init
    python rom_scanner.py watch [--daemon]
    python rom_scanner.py launch-chrome
    python rom_scanner.py export --format json
    python rom_scanner.py configure-ryujinx
    python rom_scanner.py update-threat-db [--force]
"""

import argparse
import json
import os
import shutil
import subprocess
import sys
import time
from pathlib import Path

if __name__ == "__main__":
    sys.path.insert(0, str(Path(__file__).parent))

from scanner.config import get_home, load_config, write_config
from scanner.db import export_json, init_db
from scanner.hash_scanner import ContainerReport, HashScanner
from scanner.logging_config import setup_logging
from scanner.manifest import load_manifest, update_stage
from scanner.pipeline import (
    drain_pending,
    route_verdict,
)
from scanner.pipeline import (
    ingest_path as _pipeline_ingest,
)
from scanner.pipeline import (
    make_scanner as _pipeline_make_scanner,
)
from scanner.recovery import recover_orphans
from scanner.sandbox import SandboxRunner
from scanner.storage import (
    ensure_layout,
    find_in_pipeline,
    move_to_stage,
)
from scanner.watch import create_watcher


# ─── ANSI Colors ───
class Colors:
    RED = "\033[91m"
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    BLUE = "\033[94m"
    MAGENTA = "\033[95m"
    CYAN = "\033[96m"
    BOLD = "\033[1m"
    DIM = "\033[2m"
    RESET = "\033[0m"

    @classmethod
    def severity(cls, sev: str) -> str:
        return {
            "critical": f"{cls.RED}{cls.BOLD}",
            "high": f"{cls.RED}",
            "medium": f"{cls.YELLOW}",
            "low": f"{cls.CYAN}",
        }.get(sev, "")

    @classmethod
    def risk(cls, score: float) -> str:
        if score < 0.3:
            return f"{cls.GREEN}LOW{cls.RESET}"
        elif score < 0.6:
            return f"{cls.YELLOW}MEDIUM{cls.RESET}"
        elif score < 0.8:
            return f"{cls.RED}HIGH{cls.RESET}"
        else:
            return f"{cls.RED}{cls.BOLD}CRITICAL{cls.RESET}"


def print_header(text: str):
    print(f"\n{Colors.BLUE}{'═' * 60}{Colors.RESET}")
    print(f"{Colors.BOLD}{Colors.CYAN}  {text}{Colors.RESET}")
    print(f"{Colors.BLUE}{'═' * 60}{Colors.RESET}\n")


def print_section(text: str):
    print(f"\n{Colors.BOLD}{Colors.MAGENTA}▶ {text}{Colors.RESET}")


def format_size(size: int) -> str:
    """Format byte size as human-readable."""
    value = float(size)
    for unit in ["B", "KB", "MB", "GB"]:
        if value < 1024:
            return f"{value:.1f} {unit}"
        value /= 1024
    return f"{value:.1f} TB"


def print_scan_report(report: ContainerReport):
    """Print a beautifully formatted scan report."""
    print_header("ROM SCANNER — ANALYSIS REPORT")

    print_section("File Information")
    print(f"  Path:      {report.filepath}")
    print(f"  Type:      {report.file_type}")
    print(f"  Size:      {format_size(report.file_size)}")
    print(f"  Valid:     {Colors.GREEN if report.is_valid else Colors.RED}"
          f"{'Yes' if report.is_valid else 'No'}{Colors.RESET}")

    if report.parse_errors:
        print_section("Parse Errors")
        for err in report.parse_errors:
            print(f"  {Colors.RED}✗ {err}{Colors.RESET}")

    if report.parse_warnings:
        print_section("Parse Warnings")
        for warn in report.parse_warnings:
            print(f"  {Colors.YELLOW}⚠ {warn}{Colors.RESET}")

    if report.entries:
        print_section(f"Contained Files ({len(report.entries)})")
        print(f"  {'Name':<40} {'Size':>10} {'Status':<12} {'Hashes'}")
        print(f"  {'─' * 40} {'─' * 10} {'─' * 12} {'─' * 20}")

        for entry in report.entries:
            status = (
                f"{Colors.RED}SUSPICIOUS{Colors.RESET}"
                if entry.is_suspicious
                else f"{Colors.GREEN}OK{Colors.RESET}"
            )
            vt_info = ""
            if entry.vt_scanned:
                vt_info = f"VT:{entry.vt_positives}/{entry.vt_total}"
            elif entry.local_match:
                vt_info = f"LOCAL:{entry.local_match[:20]}"

            name = entry.filename[:38] + ".." if len(entry.filename) > 40 else entry.filename
            print(f"  {name:<40} {format_size(entry.size):>10} {status:<22} {vt_info}")

    suspicious_entries = [e for e in report.entries if e.is_suspicious]
    if suspicious_entries:
        print_section("⚠ Suspicious Findings")
        for entry in suspicious_entries:
            print(f"\n  {Colors.RED}{Colors.BOLD}{entry.filename}{Colors.RESET}")
            for reason in entry.suspicion_reasons:
                print(f"    {Colors.RED}• {reason}{Colors.RESET}")
            if entry.vt_permalink:
                print(f"    {Colors.DIM}VirusTotal: {entry.vt_permalink}{Colors.RESET}")

    print_section("Risk Assessment")
    risk_label = Colors.risk(report.risk_score)
    print(f"  Risk Score:  {report.risk_score:.2f} / 1.00  [{risk_label}]")
    print(f"  Overall:     {'✅ SAFE' if report.overall_safe else '❌ UNSAFE'}")

    print()
    if report.overall_safe:
        if report.risk_score < 0.1:
            print(f"  {Colors.GREEN}{Colors.BOLD}✅ VERDICT: File appears clean — no threats detected{Colors.RESET}")
        else:
            print(f"  {Colors.YELLOW}VERDICT: Minor concerns detected — proceed with caution{Colors.RESET}")
    else:
        print(f"  {Colors.RED}{Colors.BOLD}❌ VERDICT: THREATS DETECTED — do not run this file!{Colors.RESET}")

    print()


def print_sandbox_report(report):
    """Print a sandbox analysis report."""
    print_header("SANDBOX ANALYSIS REPORT")

    print_section("Sandbox Configuration")
    print(f"  ROM:         {report.rom_path}")
    print(f"  Emulator:    {report.emulator_used}")
    print(f"  Duration:    {report.duration_seconds:.1f}s")

    if report.events:
        print_section(f"Events Detected ({len(report.events)})")
        for event in report.events:
            sev_color = Colors.severity(event.severity)
            icon = {
                "critical": "🔴",
                "high": "🟠",
                "medium": "🟡",
                "low": "🔵",
            }.get(event.severity, "⚪")
            print(f"  {icon} {sev_color}[{event.severity.upper()}]{Colors.RESET} "
                  f"{event.category}: {event.description}")
            if event.details:
                for k, v in event.details.items():
                    print(f"      {k}: {v}")
    else:
        print_section("Events Detected")
        print(f"  {Colors.GREEN}No suspicious events detected{Colors.RESET}")

    print_section("Risk Assessment")
    risk_label = Colors.risk(report.risk_score)
    print(f"  Risk Score:  {report.risk_score:.2f} / 1.00  [{risk_label}]")
    print(f"  Overall:     {'✅ SAFE' if report.safe else '❌ UNSAFE'}")

    print()


def _make_scanner(args, home=None) -> HashScanner:
    return _pipeline_make_scanner(args, home)


def _route_verdict(report: ContainerReport, home=None) -> tuple:
    return route_verdict(report, home)


def _run_recovery(home: Path, quiet: bool = False) -> None:
    orphans = recover_orphans(home)
    if orphans and not quiet:
        for name, action in orphans:
            print(f"{Colors.YELLOW}Recovery: {name} -> {action}{Colors.RESET}")


def _ingest_path(
    src: Path,
    home: Path,
    args,
    *,
    from_sandbox: bool = False,
    json_output: bool = False,
) -> bool:
    """Ingest a file through the pipeline. Returns True on safe outcome."""
    report, dest, stage, verdict = _pipeline_ingest(
        src, home, args, from_sandbox=from_sandbox
    )

    if json_output:
        output = {
            "path": str(dest),
            "stage": stage,
            "verdict": verdict,
            "overall_safe": report.overall_safe,
            "risk_score": report.risk_score,
        }
        print(json.dumps(output, indent=2))
    else:
        print_scan_report(report)
        print(f"{Colors.BOLD}Routed to {stage}/: {dest.name}{Colors.RESET}")

    return report.overall_safe


def cmd_scan(args):
    """Handle the 'scan' command."""
    scanner = _make_scanner(args)

    if not Path(args.file).exists():
        print(f"{Colors.RED}Error: File not found: {args.file}{Colors.RESET}")
        sys.exit(1)

    print(f"{Colors.CYAN}Scanning: {args.file}{Colors.RESET}")
    report = scanner.scan_file(args.file)

    if args.json:
        output = {
            "filepath": report.filepath,
            "file_type": report.file_type,
            "file_size": report.file_size,
            "is_valid": report.is_valid,
            "parse_errors": report.parse_errors,
            "parse_warnings": report.parse_warnings,
            "overall_safe": report.overall_safe,
            "risk_score": report.risk_score,
            "entries": [
                {
                    "filename": e.filename,
                    "sha256": e.sha256,
                    "md5": e.md5,
                    "size": e.size,
                    "is_suspicious": e.is_suspicious,
                    "suspicion_reasons": e.suspicion_reasons,
                    "vt_positives": e.vt_positives,
                    "vt_total": e.vt_total,
                    "vt_permalink": e.vt_permalink,
                }
                for e in report.entries
            ],
        }
        print(json.dumps(output, indent=2))
    else:
        print_scan_report(report)

    sys.exit(0 if report.overall_safe else 1)


def cmd_sandbox(args):
    """Handle the 'sandbox' command — only files in approved/."""
    home = get_home()

    located = find_in_pipeline(args.file, home)
    if not located or located[0] != "approved":
        print(f"{Colors.RED}Error: Sandbox only accepts files in approved/.{Colors.RESET}")
        print(f"{Colors.DIM}Use ingest to scan new files, or promote after review.{Colors.RESET}")
        sys.exit(1)

    _, approved_path = located
    cfg = load_config(home)
    sandbox_cfg = cfg.get("sandbox", {})
    preferred = sandbox_cfg.get("preferred_emulator", "auto")
    runner = SandboxRunner(
        verbose=args.verbose,
        preferred_emulator=preferred,
        monitor_registry=sandbox_cfg.get("monitor_registry", True),
        monitor_fs_depth=sandbox_cfg.get("monitor_fs_depth", "basic"),
    )

    if not runner.is_available():
        print(f"{Colors.YELLOW}Warning: No Switch emulator found.{Colors.RESET}")
        print("Install Ryujinx for full sandbox analysis:")
        print("  https://ryujinx.org/")
        print()
        print("Running static scan only...")
        scanner = _make_scanner(args, home)
        report = scanner.scan_file(str(approved_path))
        print_scan_report(report)
        sys.exit(0 if report.overall_safe else 1)

    print(f"{Colors.CYAN}Sandboxing: {approved_path}{Colors.RESET}")
    print(f"{Colors.DIM}Emulator: {runner.emulator_name}{Colors.RESET}")
    print(f"{Colors.DIM}Timeout: {args.timeout}s{Colors.RESET}")

    sandbox_report = runner.run_sandbox(
        str(approved_path),
        timeout=args.timeout,
        monitor_network=not args.no_network,
    )

    print_sandbox_report(sandbox_report)

    print(f"{Colors.DIM}Running static scan...{Colors.RESET}")
    scanner = _make_scanner(args, home)
    static_report = scanner.scan_file(str(approved_path))
    print_scan_report(static_report)

    sys.exit(0 if (sandbox_report.safe and static_report.overall_safe) else 1)


def cmd_ingest(args):
    """Copy an external file into the pipeline, scan, and route."""
    src = Path(args.path).resolve()
    if not src.is_file():
        print(f"{Colors.RED}Error: File not found: {args.path}{Colors.RESET}")
        sys.exit(1)

    home = get_home()
    ensure_layout(home)
    init_db(home)
    _run_recovery(home)
    drain_pending(home, args, quiet=True)

    print(f"{Colors.CYAN}Pipeline home: {home}{Colors.RESET}")
    print(f"{Colors.DIM}Ingesting: {src}{Colors.RESET}")

    ok = _ingest_path(src, home, args, from_sandbox=False, json_output=args.json)
    sys.exit(0 if ok else 1)


def cmd_promote(args):
    """Manually promote a file to approved/ after review."""
    home = get_home()
    ensure_layout(home)

    located = find_in_pipeline(args.file, home)
    if not located:
        print(f"{Colors.RED}Error: File not found in pipeline: {args.file}{Colors.RESET}")
        sys.exit(1)

    stage, current_path = located
    if stage == "approved":
        print(f"{Colors.YELLOW}Already in approved/: {current_path.name}{Colors.RESET}")
        sys.exit(0)

    dest = move_to_stage(current_path, "approved", home)
    update_stage(
        dest.name,
        stage="approved",
        verdict="approved_manual",
        path=dest,
        home=home,
    )

    print(f"{Colors.GREEN}Promoted to approved/: {dest.name}{Colors.RESET}")
    if stage == "quarantined":
        print(f"{Colors.YELLOW}Note: file was previously quarantined — manual override applied{Colors.RESET}")
    sys.exit(0)


def cmd_quarantine(args):
    """Explicitly move a file to quarantined/."""
    home = get_home()
    ensure_layout(home)

    located = find_in_pipeline(args.file, home)
    if not located:
        print(f"{Colors.RED}Error: File not found in pipeline: {args.file}{Colors.RESET}")
        sys.exit(1)

    stage, current_path = located
    if stage == "quarantined":
        print(f"{Colors.YELLOW}Already in quarantined/: {current_path.name}{Colors.RESET}")
        sys.exit(0)

    dest = move_to_stage(current_path, "quarantined", home)
    update_stage(
        dest.name,
        stage="quarantined",
        verdict="quarantined_manual",
        path=dest,
        home=home,
    )

    print(f"{Colors.RED}Moved to quarantined/: {dest.name}{Colors.RESET}")
    sys.exit(0)


def cmd_status(args):
    """Show manifest entries for scanned pipeline files."""
    home = get_home()
    entries = load_manifest(home)

    if args.stage:
        entries = [e for e in entries if e.get("stage") == args.stage]

    if not entries:
        print(f"{Colors.DIM}No manifest entries"
              f"{f' in stage {args.stage}' if args.stage else ''}.{Colors.RESET}")
        print(f"{Colors.DIM}Pipeline home: {home}{Colors.RESET}")
        sys.exit(0)

    print_header("PIPELINE STATUS")
    print(f"  Home: {home}")
    print(f"  Entries: {len(entries)}\n")
    print(f"  {'File':<30} {'Stage':<12} {'Verdict':<18} {'Risk':>6}  {'When'}")
    print(f"  {'─' * 30} {'─' * 12} {'─' * 18} {'─' * 6}  {'─' * 24}")

    for entry in entries:
        name = entry.get("filename", "?")
        if len(name) > 28:
            name = name[:26] + ".."
        stage = entry.get("stage", "?")
        verdict = entry.get("verdict", "?")
        risk = entry.get("risk_score", 0.0)
        ts = entry.get("timestamp", "")[:19].replace("T", " ")
        safe_icon = f"{Colors.GREEN}✓{Colors.RESET}" if entry.get("overall_safe") else f"{Colors.RED}✗{Colors.RESET}"
        print(f"  {safe_icon} {name:<28} {stage:<12} {verdict:<18} {risk:>6.2f}  {ts}")

    print()
    sys.exit(0)


def cmd_quick(args):
    """Quick scan — static analysis only, no VT, minimal output."""
    scanner = _make_scanner(args)

    if not Path(args.file).exists():
        print(f"{Colors.RED}Error: File not found: {args.file}{Colors.RESET}")
        sys.exit(1)

    report = scanner.scan_file(args.file)

    status = "✅ SAFE" if report.overall_safe else "❌ UNSAFE"
    risk_label = Colors.risk(report.risk_score)
    print(f"{status}  risk={report.risk_score:.2f} [{risk_label}]  "
          f"type={report.file_type}  "
          f"entries={len(report.entries)}  "
          f"{report.filepath}")

    if not report.overall_safe:
        for entry in report.entries:
            if entry.is_suspicious:
                print(f"  ⚠ {entry.filename}: {'; '.join(entry.suspicion_reasons)}")

    sys.exit(0 if report.overall_safe else 1)


def cmd_init(args):
    """Create directory layout and default config.json."""
    home = get_home()
    paths = ensure_layout(home)
    cfg_path = write_config(home)
    init_db(home)
    _run_recovery(home)

    # Copy bundled threat_db.json if missing
    _copy_bundled_db(home, "threat_db.json")
    # Copy bundled homebrew_db.json if missing
    _copy_bundled_db(home, "homebrew_db.json")

    # Drain any files already waiting in incoming/ after recovery
    drain_pending(home, quiet=True)

    sbx_downloads = Path(load_config(home)["sandboxie"]["downloads_path"])
    sbx_downloads.mkdir(parents=True, exist_ok=True)

    print(f"{Colors.GREEN}Initialized ROM Scanner at {home}{Colors.RESET}")
    print(f"  Config: {cfg_path}")
    for stage, path in paths.items():
        print(f"  {stage}/: {path}")
    print(f"  Sandbox downloads: {sbx_downloads}")
    sys.exit(0)


def _copy_bundled_db(home: Path, filename: str) -> None:
    """Copy a bundled scanner/ data file to home if not already present."""
    dest = home / filename
    if dest.exists():
        return
    bundled = Path(__file__).parent / "scanner" / filename
    if bundled.exists():
        try:
            shutil.copy2(str(bundled), str(dest))
        except OSError:
            pass


def cmd_launch_chrome(args):
    """Launch Chrome inside the Sandboxie quarantine box."""
    cfg = load_config()
    sbx = cfg.get("sandboxie", {})
    start_exe = Path(sbx.get("start_exe", ""))
    box_name = sbx.get("box_name", "RomQuarantine")

    if not start_exe.exists():
        print(f"{Colors.RED}Error: Sandboxie Start.exe not found: {start_exe}{Colors.RESET}")
        print(f"{Colors.DIM}Install Sandboxie-Plus and update config.json sandboxie.start_exe{Colors.RESET}")
        sys.exit(1)

    chrome_paths = [
        Path(os.environ.get("PROGRAMFILES", "C:/Program Files")) / "Google/Chrome/Application/chrome.exe",
        Path(os.environ.get("PROGRAMFILES(X86)", "C:/Program Files (x86)")) / "Google/Chrome/Application/chrome.exe",
        Path(os.environ.get("LOCALAPPDATA", "")) / "Google/Chrome/Application/chrome.exe",
    ]
    chrome = next((p for p in chrome_paths if p.exists()), None)
    if chrome is None:
        print(f"{Colors.RED}Error: Chrome not found.{Colors.RESET}")
        sys.exit(1)

    cmd = [str(start_exe), f"/box:{box_name}", str(chrome)]
    print(f"{Colors.CYAN}Launching sandboxed Chrome: {' '.join(cmd)}{Colors.RESET}")
    subprocess.Popen(cmd)
    sys.exit(0)


def cmd_watch(args):
    """Watch Sandboxie downloads folder and auto-ingest completed ROMs."""
    home = get_home()
    ensure_layout(home)
    init_db(home)
    _run_recovery(home)
    drain_pending(home, quiet=True)

    cfg = load_config(home)

    # Update threat feed on startup if configured
    try:
        from scanner.threat_feed import update_if_stale
        update_if_stale(home, cfg)
    except Exception as e:
        import logging
        logger = logging.getLogger(__name__)
        logger.warning("threat feed update failed for home=%s cfg=%s: %s", home, cfg, e, exc_info=True)

    downloads = Path(cfg["sandboxie"]["downloads_path"])
    print(f"{Colors.CYAN}Watching: {downloads}{Colors.RESET}")
    print(f"{Colors.DIM}Poll every {cfg['watch']['poll_interval_sec']}s, "
          f"stable for {cfg['watch']['stable_size_sec']}s{Colors.RESET}")

    class WatchArgs:
        vt_key = getattr(args, "vt_key", None)
        sandbox = False
        verbose = getattr(args, "verbose", False)
        timeout = 60
        no_network = False

    watch_args = WatchArgs()

    def ingest_callback(path: Path) -> bool:
        print(f"{Colors.CYAN}Ingesting: {path.name}{Colors.RESET}")
        try:
            return _ingest_path(path, home, watch_args, from_sandbox=True)
        except Exception as e:
            print(f"{Colors.RED}Ingest failed: {e}{Colors.RESET}")
            return False

    watcher = create_watcher(home)

    if args.daemon:
        drain_cb = None
        if cfg.get("watch", {}).get("drain_incoming_on_poll", True):
            drain_cb = lambda: drain_pending(home, watch_args, quiet=True)  # noqa: E731
        watcher.run_forever(ingest_callback, drain_callback=drain_cb)
    else:
        try:
            while True:
                for evt in watcher.poll_once():
                    if evt.kind == "stable":
                        ingest_callback(Path(evt.path))
                if cfg.get("watch", {}).get("drain_incoming_on_poll", True):
                    drain_pending(home, watch_args, quiet=True)
                time.sleep(watcher.poll_interval_sec)
        except KeyboardInterrupt:
            print(f"\n{Colors.DIM}Watch stopped.{Colors.RESET}")
            sys.exit(0)


def cmd_export(args):
    """Export manifest to JSON for scripting."""
    home = get_home()
    if args.format == "json":
        data = export_json(home)
        print(json.dumps(data, indent=2))
    else:
        print(f"{Colors.RED}Unsupported format: {args.format}{Colors.RESET}")
        sys.exit(1)
    sys.exit(0)


def cmd_configure_ryujinx(args):
    """Configure Ryujinx to load games only from approved/."""
    cfg = load_config()
    approved = Path(cfg["ryujinx"]["games_path"]).resolve()

    ryujinx_config = Path(os.environ.get("APPDATA", "")) / "Ryujinx" / "Config.json"
    if not ryujinx_config.exists():
        print(f"{Colors.RED}Error: Ryujinx config not found: {ryujinx_config}{Colors.RESET}")
        sys.exit(1)

    with open(ryujinx_config, encoding="utf-8") as f:
        ryujinx_data = json.load(f)

    backup = ryujinx_config.with_suffix(".json.bak")
    if not backup.exists():
        shutil.copy2(ryujinx_config, backup)
        print(f"{Colors.DIM}Backup saved: {backup}{Colors.RESET}")

    ryujinx_data["game_dirs"] = [str(approved)]
    with open(ryujinx_config, "w", encoding="utf-8") as f:
        json.dump(ryujinx_data, f, indent=2)

    print(f"{Colors.GREEN}Ryujinx game_dirs set to: {approved}{Colors.RESET}")
    print(f"{Colors.YELLOW}Launch games only from the approved library.{Colors.RESET}")
    sys.exit(0)


def cmd_update_threat_db(args):
    """Download/update threat_db.json from the configured feed URL."""
    from scanner.threat_feed import update_if_stale

    home = get_home()
    cfg = load_config(home)
    url = cfg.get("scan", {}).get("threat_feed_url", "")
    if not url:
        print(f"{Colors.YELLOW}No threat_feed_url configured in config.json.{Colors.RESET}")
        print(f"{Colors.DIM}Add \"scan\": {{\"threat_feed_url\": \"https://...\"}}{Colors.RESET}")
        sys.exit(1)

    force = getattr(args, "force", False)
    print(f"{Colors.CYAN}Checking threat feed: {url}{Colors.RESET}")
    updated = update_if_stale(home, cfg, force=force)
    if updated:
        print(f"{Colors.GREEN}Threat DB updated.{Colors.RESET}")
    else:
        print(f"{Colors.DIM}Threat DB is up to date (use --force to override).{Colors.RESET}")
    sys.exit(0)


def main():
    parser = argparse.ArgumentParser(
        description="🛡️ ROM Scanner & Sandbox — Scan NSP/XCI files for malware",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  rom_scanner.py scan game.nsp              # Full static scan
  rom_scanner.py scan game.nsp --vt-key KEY # With VirusTotal
  rom_scanner.py sandbox game.nsp           # Run in emulator sandbox (approved only)
  rom_scanner.py quick game.nsp             # Quick safety check
  rom_scanner.py ingest game.nsp            # Quarantine pipeline ingest
  rom_scanner.py ingest game.nsp --sandbox  # Ingest + Ryujinx sandbox test
  rom_scanner.py init                       # Initialize pipeline layout
  rom_scanner.py watch                      # Auto-ingest sandbox downloads
  rom_scanner.py launch-chrome              # Open sandboxed Chrome
  rom_scanner.py configure-ryujinx          # Point Ryujinx at approved/
  rom_scanner.py export --format json       # Export manifest
  rom_scanner.py status                     # Show pipeline manifest
  rom_scanner.py update-threat-db           # Update threat DB from feed
  rom_scanner.py update-threat-db --force   # Force update regardless of interval
        """,
    )
    parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="Enable verbose/debug logging",
    )
    subparsers = parser.add_subparsers(dest="command", help="Command to run")

    scan_parser = subparsers.add_parser("scan", help="Static scan an NSP/XCI file")
    scan_parser.add_argument("file", help="Path to NSP or XCI file")
    scan_parser.add_argument("--vt-key", help="VirusTotal API key")
    scan_parser.add_argument("--json", action="store_true", help="JSON output")
    scan_parser.set_defaults(func=cmd_scan)

    sandbox_parser = subparsers.add_parser("sandbox", help="Sandbox run in emulator (approved only)")
    sandbox_parser.add_argument("file", help="Collision-resolved basename (as stored in manifest/pipeline)")
    sandbox_parser.add_argument("--timeout", type=int, default=60, help="Sandbox timeout (seconds)")
    sandbox_parser.add_argument("--no-network", action="store_true", help="Disable network monitoring")
    sandbox_parser.add_argument("--vt-key", help="VirusTotal API key")
    sandbox_parser.set_defaults(func=cmd_sandbox)

    quick_parser = subparsers.add_parser("quick", help="Quick safety check")
    quick_parser.add_argument("file", help="Path to NSP or XCI file")
    quick_parser.set_defaults(func=cmd_quick)

    ingest_parser = subparsers.add_parser(
        "ingest", help="Copy file into pipeline, scan, and route"
    )
    ingest_parser.add_argument("path", help="Path to external NSP or XCI file")
    ingest_parser.add_argument("--vt-key", help="VirusTotal API key")
    ingest_parser.add_argument("--json", action="store_true", help="JSON output")
    ingest_parser.add_argument(
        "--sandbox", action="store_true",
        help="Run Ryujinx sandbox after static pass (approved-boundary only)",
    )
    ingest_parser.add_argument("--timeout", type=int, default=60, help="Sandbox timeout (seconds)")
    ingest_parser.add_argument("--no-network", action="store_true", help="Disable network monitoring")
    ingest_parser.set_defaults(func=cmd_ingest)

    promote_parser = subparsers.add_parser(
        "promote", help="Manually promote a pipeline file to approved/"
    )
    promote_parser.add_argument("file", help="Collision-resolved basename (as stored in manifest/pipeline)")
    promote_parser.set_defaults(func=cmd_promote)

    quarantine_parser = subparsers.add_parser(
        "quarantine", help="Explicitly move a pipeline file to quarantined/"
    )
    quarantine_parser.add_argument("file", help="Collision-resolved basename (as stored in manifest/pipeline)")
    quarantine_parser.set_defaults(func=cmd_quarantine)

    status_parser = subparsers.add_parser(
        "status", help="Show scan manifest entries"
    )
    status_parser.add_argument(
        "--stage",
        choices=["incoming", "scanning", "approved", "quarantined"],
        help="Filter by pipeline stage",
    )
    status_parser.set_defaults(func=cmd_status)

    init_parser = subparsers.add_parser("init", help="Create pipeline layout and config")
    init_parser.set_defaults(func=cmd_init)

    watch_parser = subparsers.add_parser("watch", help="Watch sandbox downloads and auto-ingest")
    watch_parser.add_argument("--daemon", action="store_true", help="Run as background loop")
    watch_parser.add_argument("--vt-key", help="VirusTotal API key")
    watch_parser.set_defaults(func=cmd_watch)

    launch_parser = subparsers.add_parser("launch-chrome", help="Launch Chrome in Sandboxie box")
    launch_parser.set_defaults(func=cmd_launch_chrome)

    export_parser = subparsers.add_parser("export", help="Export manifest data")
    export_parser.add_argument("--format", default="json", choices=["json"], help="Output format")
    export_parser.set_defaults(func=cmd_export)

    ryujinx_parser = subparsers.add_parser(
        "configure-ryujinx", help="Set Ryujinx game_dirs to approved/"
    )
    ryujinx_parser.set_defaults(func=cmd_configure_ryujinx)

    update_db_parser = subparsers.add_parser(
        "update-threat-db", help="Download/update threat_db.json from configured feed URL"
    )
    update_db_parser.add_argument(
        "--force", action="store_true",
        help="Force update even if interval has not elapsed",
    )
    update_db_parser.set_defaults(func=cmd_update_threat_db)

    args = parser.parse_args()

    # Set up logging after args are parsed
    setup_logging(verbose=args.verbose)

    if not args.command:
        parser.print_help()
        sys.exit(1)

    args.func(args)


if __name__ == "__main__":
    main()
