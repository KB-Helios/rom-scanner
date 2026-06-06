"""
Quarantine pipeline storage layout.
===================================
Manages stage directories under ROM_SCANNER_HOME.
"""

import shutil
from pathlib import Path
from typing import Dict, Optional

from scanner.config import get_home

STAGE_NAMES = ("incoming", "scanning", "approved", "quarantined")


def stage_paths(home: Optional[Path] = None) -> Dict[str, Path]:
    """Return mapping of stage name -> directory path."""
    root = home or get_home()
    return {name: root / name for name in STAGE_NAMES}


def ensure_layout(home: Optional[Path] = None) -> Dict[str, Path]:
    """Create stage directories if missing; return stage paths."""
    paths = stage_paths(home)
    for path in paths.values():
        path.mkdir(parents=True, exist_ok=True)
    return paths


def manifest_path(home: Optional[Path] = None) -> Path:
    """Path to the legacy scan manifest JSON file."""
    return (home or get_home()) / "manifest.json"


def unique_dest(stage_dir: Path, filename: str) -> Path:
    """Return a non-colliding path inside stage_dir for filename."""
    dest = stage_dir / Path(filename).name
    if not dest.exists():
        return dest
    stem = dest.stem
    suffix = dest.suffix
    n = 1
    while True:
        candidate = stage_dir / f"{stem}_{n}{suffix}"
        if not candidate.exists():
            return candidate
        n += 1


def move_to_stage(
    src: Path,
    stage: str,
    home: Optional[Path] = None,
) -> Path:
    """Move src into the given pipeline stage; return final path."""
    paths = ensure_layout(home)
    if stage not in paths:
        raise ValueError(f"Unknown stage: {stage}")
    dest = unique_dest(paths[stage], src.name)
    shutil.move(str(src), str(dest))
    return dest


def copy_to_stage(
    src: Path,
    stage: str,
    home: Optional[Path] = None,
) -> Path:
    """Copy src into the given pipeline stage; return final path."""
    paths = ensure_layout(home)
    if stage not in paths:
        raise ValueError(f"Unknown stage: {stage}")
    dest = unique_dest(paths[stage], src.name)
    shutil.copy2(str(src), str(dest))
    return dest


def move_from_external(
    src: Path,
    stage: str,
    home: Optional[Path] = None,
) -> Path:
    """
    Move a file from an external location (e.g. Sandboxie downloads) into a stage.
    Uses move (not copy) to avoid duplicating large ROM files.
    """
    paths = ensure_layout(home)
    if stage not in paths:
        raise ValueError(f"Unknown stage: {stage}")
    if not src.is_file():
        raise FileNotFoundError(f"Source file not found: {src}")
    dest = unique_dest(paths[stage], src.name)
    shutil.move(str(src), str(dest))
    return dest


def find_in_pipeline(
    name: str,
    home: Optional[Path] = None,
) -> Optional[tuple]:
    """
    Locate a file by basename across all stages.
    Returns (stage_name, path) or None.
    """
    paths = stage_paths(home)
    basename = Path(name).name
    for stage, stage_dir in paths.items():
        if not stage_dir.exists():
            continue
        direct = stage_dir / basename
        if direct.is_file():
            return stage, direct
        for candidate in stage_dir.iterdir():
            if candidate.is_file() and candidate.name == basename:
                return stage, candidate
    return None


def is_in_stage(path: Path, stage: str, home: Optional[Path] = None) -> bool:
    """Return True if path is a file inside the given pipeline stage."""
    paths = stage_paths(home)
    stage_dir = paths.get(stage)
    if stage_dir is None:
        return False
    try:
        path.resolve().relative_to(stage_dir.resolve())
        return path.is_file()
    except ValueError:
        return False
