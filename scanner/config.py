"""
Unified configuration for ROM Scanner.
======================================
Loads from ROM_SCANNER_HOME/config.json with environment variable overrides.
"""

import json
import os
from pathlib import Path
from typing import Any, Dict, Optional

DEFAULT_HOME = Path("C:/RomScanner")

DEFAULT_CONFIG: Dict[str, Any] = {
    "home": str(DEFAULT_HOME),
    "sandboxie": {
        "box_name": "RomQuarantine",
        "downloads_path": str(
            DEFAULT_HOME / "sbx/RomQuarantine/user/current/Downloads"
        ),
        "start_exe": "C:/Program Files/Sandboxie-Plus/Start.exe",
    },
    "scan": {
        "vt_api_key_env": "VIRUSTOTAL_API_KEY",
        "defender_scan": True,
        "risk_threshold": 0.3,
        "threat_db_path": "",
    },
    "watch": {
        "poll_interval_sec": 5,
        "stable_size_sec": 10,
        "extensions": [".nsp", ".xci"],
    },
    "ryujinx": {
        "games_path": str(DEFAULT_HOME / "approved"),
    },
}

_config_cache: Optional[Dict[str, Any]] = None


def _deep_merge(base: Dict[str, Any], override: Dict[str, Any]) -> Dict[str, Any]:
    """Recursively merge override into base."""
    result = dict(base)
    for key, value in override.items():
        if key in result and isinstance(result[key], dict) and isinstance(value, dict):
            result[key] = _deep_merge(result[key], value)
        else:
            result[key] = value
    return result


def _resolve_home_from_env() -> Optional[Path]:
    env = os.environ.get("ROM_SCANNER_HOME")
    if env:
        return Path(env).expanduser().resolve()
    return None


def get_home() -> Path:
    """Root directory for the quarantine pipeline."""
    env_home = _resolve_home_from_env()
    if env_home:
        return env_home
    cfg = load_config()
    return Path(cfg["home"]).expanduser().resolve()


def config_path(home: Optional[Path] = None) -> Path:
    """Path to config.json under ROM_SCANNER_HOME."""
    root = home or _resolve_home_from_env() or DEFAULT_HOME.expanduser().resolve()
    return root / "config.json"


def default_config(home: Optional[Path] = None) -> Dict[str, Any]:
    """Return default config with home paths adjusted."""
    root = home or _resolve_home_from_env() or DEFAULT_HOME
    root = Path(root).expanduser().resolve()
    cfg = _deep_merge({}, DEFAULT_CONFIG)
    cfg["home"] = str(root)
    cfg["sandboxie"]["downloads_path"] = str(
        root / "sbx/RomQuarantine/user/current/Downloads"
    )
    cfg["ryujinx"]["games_path"] = str(root / "approved")
    return cfg


def load_config(home: Optional[Path] = None, *, reload: bool = False) -> Dict[str, Any]:
    """Load config from disk, applying env overrides."""
    global _config_cache
    if _config_cache is not None and not reload and home is None:
        return _config_cache

    root = home or _resolve_home_from_env()
    if root is None:
        root = DEFAULT_HOME
    root = Path(root).expanduser().resolve()

    cfg = default_config(root)
    path = root / "config.json"
    if path.exists():
        try:
            with open(path, encoding="utf-8") as f:
                file_cfg = json.load(f)
            cfg = _deep_merge(cfg, file_cfg)
        except (json.JSONDecodeError, OSError):
            pass

    # Environment overrides
    env_home = _resolve_home_from_env()
    if env_home:
        cfg["home"] = str(env_home)

    vt_env = os.environ.get("VIRUSTOTAL_API_KEY")
    if vt_env:
        cfg.setdefault("scan", {})["vt_api_key"] = vt_env

    if os.environ.get("ROM_SCANNER_DEFENDER_SCAN") == "0":
        cfg.setdefault("scan", {})["defender_scan"] = False

    if home is None and not reload:
        _config_cache = cfg
    return cfg


def write_config(home: Optional[Path] = None) -> Path:
    """Write default config.json to home; return path."""
    root = home or get_home()
    root = Path(root).expanduser().resolve()
    root.mkdir(parents=True, exist_ok=True)
    path = root / "config.json"
    cfg = default_config(root)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(cfg, f, indent=2)
    return path


def db_path(home: Optional[Path] = None) -> Path:
    """Path to SQLite scans database."""
    root = home or get_home()
    return Path(root).resolve() / "scans.db"
