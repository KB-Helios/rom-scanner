"""
Pipeline crash recovery.
========================
Re-queue or quarantine files orphaned in scanning/ after interrupted runs.
"""

from pathlib import Path
from typing import List, Optional, Tuple

from scanner.config import get_home
from scanner.manifest import update_stage
from scanner.storage import ensure_layout, move_to_stage


def recover_orphans(
    home: Optional[Path] = None,
    *,
    requeue: bool = True,
) -> List[Tuple[str, str]]:
    """
    Scan scanning/ for orphaned files.

    Returns list of (filename, action) where action is 'requeued' or 'quarantined'.
    """
    root = home or get_home()
    paths = ensure_layout(root)
    scanning_dir = paths["scanning"]
    results: List[Tuple[str, str]] = []

    if not scanning_dir.exists():
        return results

    for candidate in list(scanning_dir.iterdir()):
        if not candidate.is_file():
            continue

        if requeue:
            dest = move_to_stage(candidate, "incoming", root)
            results.append((dest.name, "requeued"))
        else:
            dest = move_to_stage(candidate, "quarantined", root)
            update_stage(
                dest.name,
                stage="quarantined",
                verdict="scan_interrupted",
                path=dest,
                home=root,
            )
            results.append((dest.name, "quarantined"))

    return results
