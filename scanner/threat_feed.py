"""
Threat feed updater.
====================
Downloads and atomically updates threat_db.json from a remote feed URL.
Supports ETag-based conditional fetching to avoid unnecessary downloads.
"""

import json
import logging
import os
import tempfile
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from scanner.config import load_config

logger = logging.getLogger(__name__)


def fetch_threat_feed(url: str, dest: Path, *, etag: str = "") -> str:
    """
    Download threat feed from url, write atomically to dest.

    Returns the new ETag (empty string if not provided by server).
    Raises urllib.error.URLError on network errors.
    Skips download if server returns 304 Not Modified.
    """
    req = urllib.request.Request(url)
    if etag:
        req.add_header("If-None-Match", etag)
    req.add_header("User-Agent", "rom-scanner/1.0")

    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            new_etag = resp.headers.get("ETag", "")
            data = resp.read()
    except urllib.error.HTTPError as e:
        if e.code == 304:
            logger.debug("Threat feed not modified (304), skipping")
            return etag
        raise

    # Validate it's valid JSON before writing
    try:
        parsed = json.loads(data.decode("utf-8"))
    except (json.JSONDecodeError, UnicodeDecodeError) as e:
        raise ValueError(f"Threat feed response is not valid JSON: {e}") from e

    if "sha256" not in parsed and "md5" not in parsed:
        raise ValueError("Threat feed missing required 'sha256' or 'md5' keys")

    # Atomic write: write to temp file then rename
    dest.parent.mkdir(parents=True, exist_ok=True)
    tmp_fd, tmp_path = tempfile.mkstemp(dir=dest.parent, suffix=".tmp")
    try:
        with os.fdopen(tmp_fd, "wb") as f:
            f.write(data)
        Path(tmp_path).replace(dest)
    except Exception:
        try:
            os.unlink(tmp_path)
        except OSError:
            pass
        raise

    logger.info("Threat feed updated: %s (%d bytes)", dest, len(data))
    return new_etag


def update_if_stale(home: Path, cfg: Optional[dict] = None, *, force: bool = False) -> bool:
    """
    Check if the threat feed is stale and update if needed.

    Returns True if the feed was updated, False if skipped.
    """
    if cfg is None:
        cfg = load_config(home)

    scan_cfg = cfg.get("scan", {})
    url = scan_cfg.get("threat_feed_url", "")
    if not url:
        logger.debug("No threat_feed_url configured, skipping update")
        return False

    interval_hours = float(scan_cfg.get("threat_feed_interval_hours", 24))
    last_check_str = scan_cfg.get("threat_feed_last_check", "")
    etag = scan_cfg.get("threat_feed_etag", "")

    if not force and last_check_str:
        try:
            last_check = datetime.fromisoformat(last_check_str)
            if last_check.tzinfo is None:
                last_check = last_check.replace(tzinfo=timezone.utc)
            now = datetime.now(tz=timezone.utc)
            elapsed_hours = (now - last_check).total_seconds() / 3600
            if elapsed_hours < interval_hours:
                logger.debug(
                    "Threat feed checked %.1fh ago (interval %.1fh), skipping",
                    elapsed_hours, interval_hours,
                )
                return False
        except (ValueError, TypeError):
            pass

    threat_db_path = Path(scan_cfg.get("threat_db_path") or home / "threat_db.json")

    new_etag = etag
    updated = False
    try:
        new_etag = fetch_threat_feed(url, threat_db_path, etag=etag)
        # Only mark as updated if the ETag changed (i.e., new content was written)
        updated = (new_etag != etag)
    except urllib.error.URLError as e:
        logger.warning("Threat feed fetch failed: %s", e)
        updated = False
    except ValueError as e:
        logger.warning("Threat feed validation failed: %s", e)
        updated = False

    # Always update last_check timestamp so we don't hammer on repeated failures
    now_str = datetime.now(tz=timezone.utc).isoformat()
    cfg_path = home / "config.json"
    if cfg_path.exists():
        try:
            with open(cfg_path, encoding="utf-8") as f:
                on_disk = json.load(f)
            on_disk.setdefault("scan", {})["threat_feed_last_check"] = now_str
            if updated and new_etag:
                on_disk["scan"]["threat_feed_etag"] = new_etag
            with open(cfg_path, "w", encoding="utf-8") as f:
                json.dump(on_disk, f, indent=2)
        except (OSError, json.JSONDecodeError) as e:
            logger.warning("Could not update config with last_check: %s", e)

    return updated
