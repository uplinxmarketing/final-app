"""
tray.pyw — Uplinx Meta Manager system tray launcher.

Run with pythonw.exe (no console window).  Starts the FastAPI server in a
background process, opens the browser, and shows a tray icon with a menu to
open the app or stop it.
"""
import os
import socket
import subprocess
import sys
import time
import webbrowser
from pathlib import Path


def find_free_port(start: int = 8000) -> int:
    for port in range(start, start + 11):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(0.1)
            if s.connect_ex(("127.0.0.1", port)) != 0:
                return port
    return start


def make_icon():
    """Draw a simple purple 'U' icon for the tray."""
    from PIL import Image, ImageDraw, ImageFont

    size = 64
    img = Image.new("RGBA", (size, size), (0, 0, 0, 0))
    draw = ImageDraw.Draw(img)

    # Purple rounded square background
    draw.rounded_rectangle([0, 0, size - 1, size - 1], radius=14,
                           fill=(108, 99, 255, 255))

    # White 'U' letter
    try:
        font = ImageFont.truetype("arial.ttf", 38)
    except Exception:
        font = ImageFont.load_default()

    bbox = draw.textbbox((0, 0), "U", font=font)
    w, h = bbox[2] - bbox[0], bbox[3] - bbox[1]
    draw.text(((size - w) // 2 - bbox[0], (size - h) // 2 - bbox[1] - 2),
              "U", font=font, fill=(255, 255, 255, 255))

    return img


def main():
    try:
        import pystray
        from PIL import Image
    except ImportError:
        # pystray or Pillow not installed — fall back to plain subprocess + browser
        port = find_free_port()
        _start_server(port)
        time.sleep(3)
        webbrowser.open(f"http://localhost:{port}")
        return

    port = find_free_port()
    url = f"http://localhost:{port}"

    server_proc = _start_server(port)

    # Give the server a moment to start, then open the browser
    def _open_after_start():
        time.sleep(3)
        webbrowser.open(url)

    import threading
    threading.Thread(target=_open_after_start, daemon=True).start()

    # ── Tray menu actions ─────────────────────────────────────────────────
    def open_browser(icon, item):
        webbrowser.open(url)

    def stop_app(icon, item):
        icon.stop()
        if server_proc and server_proc.poll() is None:
            server_proc.terminate()
            try:
                server_proc.wait(timeout=5)
            except Exception:
                server_proc.kill()
        os._exit(0)

    menu = pystray.Menu(
        pystray.MenuItem("Open Uplinx", open_browser, default=True),
        pystray.Menu.SEPARATOR,
        pystray.MenuItem(f"Running on port {port}", None, enabled=False),
        pystray.Menu.SEPARATOR,
        pystray.MenuItem("Stop App", stop_app),
    )

    try:
        icon_image = make_icon()
    except Exception:
        icon_image = Image.new("RGB", (64, 64), (108, 99, 255))

    tray = pystray.Icon("Uplinx Meta Manager", icon_image,
                        "Uplinx Meta Manager", menu)
    tray.run()


def _start_server(port: int) -> "subprocess.Popen | None":
    """Launch uvicorn as a hidden subprocess."""
    script_dir = Path(__file__).parent
    uvicorn_exe = script_dir / "venv" / "Scripts" / "uvicorn.exe"

    if not uvicorn_exe.exists():
        uvicorn_exe = script_dir / "venv" / "Scripts" / "uvicorn"

    kwargs: dict = {
        "cwd": str(script_dir),
    }

    # Hide the console window on Windows
    if sys.platform == "win32":
        import ctypes
        kwargs["creationflags"] = subprocess.CREATE_NO_WINDOW  # type: ignore[attr-defined]

    try:
        return subprocess.Popen(
            [str(uvicorn_exe), "main:app",
             "--host", "0.0.0.0", "--port", str(port)],
            **kwargs,
        )
    except Exception as exc:
        # Last resort: write error to a log file next to tray.pyw
        log = Path(__file__).parent / "logs" / "tray_error.log"
        log.parent.mkdir(exist_ok=True)
        log.write_text(f"Failed to start server: {exc}\n")
        return None


if __name__ == "__main__":
    main()
