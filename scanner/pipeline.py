"""
Pipeline — scan routing and ingest logic.
==========================================
Extracted from rom_scanner.py so that the core pipeline can be used
independently of the CLI (e.g. by the watch daemon, tests, and drain_pending).
"""

import logging
import os
import types
from pathlib import Path
from typing import Optional, Tuple

from scanner.av_scanner import scan_file as defender_scan
from scanner.config import load_config
from scanner.hash_scanner import ContainerReport, HashScanner
from scanner.manifest import record_scan, update_stage
from scanner.recovery import recover_orphans
from scanner.storage import copy_to_stage, ensure_layout, move_from_external, move_to_stage

logger = logging.getLogger(__name__)


# ─── Scanner factory ─────────────────────────────────────────────

def make_scanner(args, home: Optional[Path] = None) -> HashScanner:
    """Build a HashScanner from config + args."""
    cfg = load_config(home)
    scan_cfg = cfg.get("scan", {})
    vt_key = getattr(args, "vt_key", None)
    if not vt_key:
        vt_key = os.environ.get(scan_cfg.get("vt_api_key_env", "VIRUSTOTAL_API_KEY"))
    threat_db: Optional[str] = scan_cfg.get("threat_db_path") or None
    if threat_db:
        threat_db = str(threat_db)
    risk_threshold = float(scan_cfg.get("risk_threshold", 0.3))
    homebrew_db: Optional[str] = scan_cfg.get("homebrew_db_path") or None
    if homebrew_db:
        homebrew_db = str(homebrew_db)
    homebrew_trust = bool(scan_cfg.get("homebrew_trust", True))
    return HashScanner(
        vt_api_key=vt_key,
        threat_db_path=threat_db,
        risk_threshold=risk_threshold,
        homebrew_db_path=homebrew_db,
        homebrew_trust=homebrew_trust,
    )


# ─── Verdict routing ─────────────────────────────────────────────

def route_verdict(report: ContainerReport, home: Optional[Path] = None) -> Tuple[str, str]:
    """Return (stage, verdict) based on scan report's overall_safe flag."""
    if report.overall_safe:
        return "approved", "approved"
    return "quarantined", "quarantined"


# ─── Core pipeline ───────────────────────────────────────────────

def pipeline_scan(
    scanning_path: Path,
    home: Path,
    args,
    *,
    json_output: bool = False,
) -> Tuple[ContainerReport, Path, str, str]:
    """
    Run Defender + static scan on a file in scanning/ and route to final stage.
    Returns (report, dest_path, stage, verdict).
    """
    cfg = load_config(home)
    defender_enabled = cfg.get("scan", {}).get("defender_scan", True)
    defender_required = cfg.get("scan", {}).get("defender_required", True)

    av_result = defender_scan(str(scanning_path), enabled=defender_enabled)

    # Always quarantine if Defender actually detected a threat
    if av_result.scanned and not av_result.clean:
        dest = move_to_stage(scanning_path, "quarantined", home)
        report = ContainerReport(
            filepath=str(dest),
            file_size=dest.stat().st_size,
            file_type=dest.suffix.upper().lstrip(".") or "UNKNOWN",
            is_valid=False,
            overall_safe=False,
            risk_score=1.0,
        )
        reason = av_result.threat_name or "; ".join(av_result.errors) or "Defender detection"
        report.parse_errors.append(f"Defender: {reason}")
        record_scan(report, stage="quarantined", path=dest, verdict="defender_blocked", home=home)
        return report, dest, "quarantined", "defender_blocked"

    # Quarantine if Defender was required but couldn't run
    if defender_enabled and defender_required and not av_result.scanned:
        dest = move_to_stage(scanning_path, "quarantined", home)
        report = ContainerReport(
            filepath=str(dest),
            file_size=dest.stat().st_size,
            file_type=dest.suffix.upper().lstrip(".") or "UNKNOWN",
            is_valid=False,
            overall_safe=False,
            risk_score=1.0,
        )
        reason = "; ".join(av_result.errors) or "Defender unavailable"
        report.parse_errors.append(f"Defender unavailable: {reason}")
        record_scan(
            report, stage="quarantined", path=dest,
            verdict="defender_unavailable", home=home,
        )
        return report, dest, "quarantined", "defender_unavailable"

    scanner = make_scanner(args, home)
    report = scanner.scan_file(str(scanning_path))
    stage, verdict = route_verdict(report, home)
    dest = move_to_stage(scanning_path, stage, home)
    record_scan(report, stage=stage, path=dest, verdict=verdict, home=home)

    if getattr(args, "sandbox", False) and stage == "approved":
        from scanner.sandbox import SandboxRunner
        preferred = cfg.get("sandbox", {}).get("preferred_emulator", "auto")
        runner = SandboxRunner(
            verbose=getattr(args, "verbose", False),
            preferred_emulator=preferred,
        )
        if runner.is_available():
            sandbox_report = runner.run_sandbox(
                str(dest),
                timeout=getattr(args, "timeout", 60),
                monitor_network=not getattr(args, "no_network", False),
            )
            if not sandbox_report.safe:
                dest = move_to_stage(dest, "quarantined", home)
                update_stage(
                    dest.name, stage="quarantined",
                    verdict="sandbox_failed", path=dest, home=home,
                )
                report.overall_safe = False
                stage, verdict = "quarantined", "sandbox_failed"

    return report, dest, stage, verdict


def ingest_path(
    src: Path,
    home: Path,
    args,
    *,
    from_sandbox: bool = False,
) -> Tuple[ContainerReport, Path, str, str]:
    """
    Ingest a file through the pipeline.
    Returns (report, dest_path, stage, verdict).
    """
    if from_sandbox:
        incoming_path = move_from_external(src, "incoming", home)
    else:
        incoming_path = copy_to_stage(src, "incoming", home)

    scanning_path = move_to_stage(incoming_path, "scanning", home)
    return pipeline_scan(scanning_path, home, args)


def drain_pending(home: Path, args=None, *, quiet: bool = False) -> None:
    """
    Recover orphans then scan every pending file in incoming/.

    Calls recover_orphans(home) first (re-queues scanning/ orphans back to
    incoming/), then scans every NSP/XCI in incoming/ through the full pipeline.
    """
    if args is None:
        args = types.SimpleNamespace(
            vt_key=None, sandbox=False, verbose=False,
            timeout=60, no_network=False,
        )

    cfg = load_config(home)
    extensions = [
        e.lower()
        for e in cfg.get("watch", {}).get("extensions", [".nsp", ".xci"])
    ]

    recover_orphans(home)

    ensure_layout(home)
    incoming_dir = Path(home) / "incoming"
    if not incoming_dir.exists():
        return

    for f in list(incoming_dir.iterdir()):
        if not f.is_file() or f.suffix.lower() not in extensions:
            continue
        try:
            scanning_path = move_to_stage(f, "scanning", home)
            pipeline_scan(scanning_path, home, args)
        except Exception as e:
            if not quiet:
                logger.warning("drain_pending: failed to ingest %s: %s", f.name, e)
