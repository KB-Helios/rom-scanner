"""
ROM Scanner system tray application (Windows).
==============================================
Optional dependency: pip install rom-scanner[tray]
"""

from __future__ import annotations

import os
import subprocess
import sys
import threading
from pathlib import Path
from typing import Optional

if sys.platform != "win32":
    print("rom-scanner-tray requires Windows.", file=sys.stderr)
    sys.exit(1)

try:
    import pystray
    from PIL import Image, ImageDraw
except ImportError as exc:
    print(
        "Tray dependencies missing. Install with: pip install rom-scanner[tray]",
        file=sys.stderr,
    )
    raise SystemExit(1) from exc

from scanner.logging_config import setup_logging
from scanner.storage import get_home, stage_paths
from tray.notifier import VerdictNotifier, latest_verdict_summary

_watch_process: Optional[subprocess.Popen] = None
_icon: Optional[pystray.Icon] = None
_notifier: Optional[VerdictNotifier] = None
_status_item: Optional[pystray.MenuItem] = None
_watch_item: Optional[pystray.MenuItem] = None


def _rom_scanner_cmd(*args: str) -> list[str]:
    """Resolve rom-scanner executable or fall back to python -m style."""
    import shutil

    exe = shutil.which("rom-scanner")
    if exe:
        return [exe, *args]
    script = Path(__file__).resolve().parent.parent / "rom_scanner.py"
    return [sys.executable, str(script), *args]


def _create_icon_image() -> Image.Image:
    size = 64
    image = Image.new("RGBA", (size, size), (0, 0, 0, 0))
    draw = ImageDraw.Draw(image)
    draw.ellipse((4, 4, size - 4, size - 4), fill=(34, 139, 34, 255))
    draw.rectangle((28, 18, 36, 46), fill=(255, 255, 255, 255))
    draw.polygon([(20, 30), (32, 18), (44, 30), (32, 42)], fill=(255, 255, 255, 255))
    return image


def _open_folder(stage: str) -> None:
    folder = stage_paths().get(stage)
    if folder is None:
        return
    folder.mkdir(parents=True, exist_ok=True)
    os.startfile(folder)  # type: ignore[attr-defined]


def _launch_chrome(_icon: pystray.Icon, _item: pystray.MenuItem) -> None:
    subprocess.Popen(
        _rom_scanner_cmd("launch-chrome"),
        creationflags=subprocess.CREATE_NO_WINDOW,
    )


def _is_watch_running() -> bool:
    global _watch_process
    if _watch_process is None:
        return False
    code = _watch_process.poll()
    if code is not None:
        _watch_process = None
        return False
    return True


def _start_watch(_icon: pystray.Icon, _item: pystray.MenuItem) -> None:
    global _watch_process
    if _is_watch_running():
        _icon.notify("ROM Scanner", "Watch daemon is already running")
        return
    _watch_process = subprocess.Popen(
        _rom_scanner_cmd("watch", "--daemon"),
        creationflags=subprocess.CREATE_NO_WINDOW,
    )
    _icon.notify("ROM Scanner", "Watch daemon started")
    _refresh_menu()


def _stop_watch(_icon: pystray.Icon, _item: pystray.MenuItem) -> None:
    global _watch_process
    if not _is_watch_running() or _watch_process is None:
        _icon.notify("ROM Scanner", "Watch daemon is not running")
        return
    _watch_process.terminate()
    try:
        _watch_process.wait(timeout=10)
    except subprocess.TimeoutExpired:
        _watch_process.kill()
    _watch_process = None
    _icon.notify("ROM Scanner", "Watch daemon stopped")
    _refresh_menu()


def _toggle_watch(icon: pystray.Icon, _item: pystray.MenuItem) -> None:
    if _is_watch_running():
        _stop_watch(icon, _item)
    else:
        _start_watch(icon, _item)


def _watch_label(_item: pystray.MenuItem) -> str:
    return "Stop watch daemon" if _is_watch_running() else "Start watch daemon"


def _status_label(_item: pystray.MenuItem) -> str:
    return latest_verdict_summary()


def _refresh_menu() -> None:
    if _icon is not None:
        _icon.update_menu()


def _schedule_menu_refresh() -> None:
    def _loop() -> None:
        while _icon is not None:
            _refresh_menu()
            threading.Event().wait(10)

    threading.Thread(target=_loop, daemon=True).start()


def _on_notify(title: str, message: str) -> None:
    if _icon is not None:
        _icon.notify(message, title)
        _refresh_menu()


def _exit(icon: pystray.Icon, _item: pystray.MenuItem) -> None:
    global _watch_process, _notifier
    if _notifier is not None:
        _notifier.stop()
    if _is_watch_running() and _watch_process is not None:
        _watch_process.terminate()
        try:
            _watch_process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            _watch_process.kill()
        _watch_process = None
    icon.stop()


def main() -> None:
    global _icon, _notifier, _status_item, _watch_item

    setup_logging(verbose=False)
    home = get_home()
    home.mkdir(parents=True, exist_ok=True)

    _status_item = pystray.MenuItem(_status_label, None, enabled=False)
    _watch_item = pystray.MenuItem(_watch_label, _toggle_watch)

    menu = pystray.Menu(
        _status_item,
        pystray.Menu.SEPARATOR,
        pystray.MenuItem("Open approved folder", lambda *_: _open_folder("approved")),
        pystray.MenuItem(
            "Open quarantined folder", lambda *_: _open_folder("quarantined")
        ),
        pystray.Menu.SEPARATOR,
        pystray.MenuItem("Launch sandboxed Chrome", _launch_chrome),
        _watch_item,
        pystray.Menu.SEPARATOR,
        pystray.MenuItem("Exit", _exit),
    )

    _icon = pystray.Icon("rom-scanner", _create_icon_image(), "ROM Scanner", menu)
    _notifier = VerdictNotifier(_on_notify, home=home)
    _notifier.start()
    _schedule_menu_refresh()
    _icon.run()


if __name__ == "__main__":
    main()
