"""
Sandboxie download folder watcher.
==================================
Polls the Sandboxie downloads directory for completed NSP/XCI files
and ingests them into the pipeline.
"""

import os
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Dict, List, Optional, Set

from scanner.config import load_config

PARTIAL_SUFFIXES = (".crdownload", ".tmp", ".part", ".download")


@dataclass
class WatchEvent:
    """Event emitted by the watch loop."""
    kind: str  # detected, stable, ingested, failed, skipped
    path: str
    message: str = ""


@dataclass
class _TrackedFile:
    path: Path
    size: int
    stable_since: float = 0.0


@dataclass
class DownloadWatcher:
    """Poll-based watcher for Sandboxie download folder."""

    downloads_path: Optional[Path] = None
    poll_interval_sec: float = 5.0
    stable_size_sec: float = 10.0
    extensions: List[str] = field(default_factory=lambda: [".nsp", ".xci"])
    on_event: Optional[Callable[[WatchEvent], None]] = None
    _tracked: Dict[str, _TrackedFile] = field(default_factory=dict, init=False)
    _processed: Set[str] = field(default_factory=set, init=False)
    _last_stable: List[Path] = field(default_factory=list, init=False)

    def __post_init__(self):
        if self.downloads_path is None:
            cfg = load_config()
            self.downloads_path = Path(cfg["sandboxie"]["downloads_path"])
        self.extensions = [e.lower() for e in self.extensions]

    def _emit(self, kind: str, path: Path, message: str = "") -> WatchEvent:
        evt = WatchEvent(kind=kind, path=str(path), message=message)
        if self.on_event:
            self.on_event(evt)
        return evt

    def _is_partial(self, path: Path) -> bool:
        name_lower = path.name.lower()
        if any(name_lower.endswith(s) for s in PARTIAL_SUFFIXES):
            return True
        if name_lower.endswith(".nsp.crdownload") or name_lower.endswith(".xci.crdownload"):
            return True
        return False

    def _is_target(self, path: Path) -> bool:
        if not path.is_file():
            return False
        if self._is_partial(path):
            return False
        return path.suffix.lower() in self.extensions

    def poll_once(self) -> List[WatchEvent]:
        """Single poll iteration; returns events."""
        self._last_stable = []
        events: List[WatchEvent] = []
        dl_dir = self.downloads_path
        if dl_dir is None or not dl_dir.exists():
            return events

        now = time.monotonic()
        seen_keys: Set[str] = set()

        for entry in os.scandir(dl_dir):
            path = Path(entry.path)
            if not self._is_target(path):
                continue

            key = str(path.resolve())
            seen_keys.add(key)

            if key in self._processed:
                continue

            try:
                size = path.stat().st_size
            except OSError:
                continue

            tracked = self._tracked.get(key)
            if tracked is None:
                self._tracked[key] = _TrackedFile(path=path, size=size, stable_since=now)
                events.append(self._emit("detected", path, f"size={size}"))
                continue

            if size != tracked.size:
                tracked.size = size
                tracked.stable_since = now
                continue

            if now - tracked.stable_since >= self.stable_size_sec:
                self._last_stable.append(path)
                events.append(self._emit("stable", path, f"size={size}"))
                del self._tracked[key]
                self._processed.add(key)
            else:
                self._tracked[key] = tracked

        # Drop tracking for files that disappeared
        for key in list(self._tracked):
            if key not in seen_keys:
                del self._tracked[key]

        return events

    def get_stable_files(self) -> List[Path]:
        """Return paths that became stable in the last poll_once()."""
        return list(self._last_stable)

    def run_forever(
        self,
        ingest_callback: Callable[[Path], bool],
        drain_callback: Optional[Callable[[], None]] = None,
    ) -> None:
        """Run watch loop until interrupted."""
        while True:
            for evt in self.poll_once():
                if evt.kind == "stable":
                    path = Path(evt.path)
                    try:
                        ok = ingest_callback(path)
                        if ok:
                            self._emit("ingested", path)
                            try:
                                path.unlink(missing_ok=True)
                            except OSError:
                                self._emit("failed", path, "could not delete sandbox source")
                        else:
                            self._emit("failed", path, "ingest returned failure")
                    except Exception as e:
                        self._emit("failed", path, str(e))
            if drain_callback is not None:
                try:
                    drain_callback()
                except Exception:
                    pass
            time.sleep(self.poll_interval_sec)


def create_watcher(home: Optional[Path] = None, **kwargs) -> DownloadWatcher:
    """Factory using config defaults."""
    cfg = load_config(home)
    watch_cfg = cfg.get("watch", {})
    sbx_cfg = cfg.get("sandboxie", {})
    return DownloadWatcher(
        downloads_path=Path(sbx_cfg.get("downloads_path", "")),
        poll_interval_sec=watch_cfg.get("poll_interval_sec", 5),
        stable_size_sec=watch_cfg.get("stable_size_sec", 10),
        extensions=watch_cfg.get("extensions", [".nsp", ".xci"]),
        **kwargs,
    )
