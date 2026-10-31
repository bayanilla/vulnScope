"""Start the vulnScope upload page from VS Code's Run Python File button."""

import os
from pathlib import Path
import socket
import threading
import time
from urllib.error import URLError
from urllib.request import urlopen
import webbrowser

from vulnflow.cli import main

HOST = "127.0.0.1"
PORT = 8080
URL = f"http://{HOST}:{PORT}/"


def _upload_page_is_ready() -> bool:
    try:
        with urlopen(URL, timeout=0.5) as response:
            return b"<title>vulnScope</title>" in response.read(4096)
    except (OSError, URLError):
        return False


def _port_is_in_use() -> bool:
    try:
        with socket.create_connection((HOST, PORT), timeout=0.5):
            return True
    except OSError:
        return False


def _open_when_ready() -> None:
    for _ in range(100):
        if _upload_page_is_ready():
            webbrowser.open(URL)
            return
        time.sleep(0.1)


if __name__ == "__main__":
    os.chdir(Path(__file__).resolve().parent)
    if _upload_page_is_ready():
        webbrowser.open(URL)
    elif _port_is_in_use():
        raise SystemExit(f"Port {PORT} is already used by another app. Stop it, then run this file again.")
    else:
        threading.Thread(target=_open_when_ready, daemon=True).start()
        raise SystemExit(main(["serve", "--port", str(PORT)]))
