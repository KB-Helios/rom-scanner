"""
Structured logging for ROM Scanner.
====================================
Rotating log file under ROM_SCANNER_HOME/rom-scanner.log.
"""

import logging
import sys
from logging.handlers import RotatingFileHandler
from pathlib import Path
from typing import Optional

from scanner.storage import get_home

_LOG_NAME = "rom_scanner"
_CONFIGURED = False


def setup_logging(verbose: bool = False, home: Optional[Path] = None) -> logging.Logger:
    """Configure root rom_scanner logger with file + stderr handlers."""
    global _CONFIGURED

    logger = logging.getLogger(_LOG_NAME)
    if _CONFIGURED:
        logger.setLevel(logging.DEBUG if verbose else logging.INFO)
        return logger

    root = home or get_home()
    root.mkdir(parents=True, exist_ok=True)
    log_file = root / "rom-scanner.log"

    logger.setLevel(logging.DEBUG)
    logger.propagate = False

    formatter = logging.Formatter(
        "%(asctime)s %(levelname)s [%(name)s] %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )

    file_handler = RotatingFileHandler(
        log_file,
        maxBytes=5 * 1024 * 1024,
        backupCount=3,
        encoding="utf-8",
    )
    file_handler.setLevel(logging.DEBUG)
    file_handler.setFormatter(formatter)
    logger.addHandler(file_handler)

    console = logging.StreamHandler(sys.stderr)
    console.setLevel(logging.DEBUG if verbose else logging.INFO)
    console.setFormatter(formatter)
    logger.addHandler(console)

    _CONFIGURED = True
    return logger


def get_logger(name: str) -> logging.Logger:
    """Return a child logger under the rom_scanner namespace."""
    if name.startswith(_LOG_NAME):
        return logging.getLogger(name)
    return logging.getLogger(f"{_LOG_NAME}.{name}")
