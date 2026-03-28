"""
main.py — EDI Exception Auto-Router entry point.

Starts the SFTP/FTP watcher daemon thread, then launches the Textual TUI.
When the user quits the TUI, shuts down the watcher and closes the DB.

Usage (dev):
    python3 main.py

Usage (deployed .exe):
    edi-router.exe
    (config.toml and edi_router.db must be in the same directory as the .exe)
"""

import queue
import sys

from config import load_config
from db import init_db
from ui_textual import EDIRouterApp
from watcher import EDIWatcher


def main() -> None:
    # Load config (raises FileNotFoundError if config.toml is missing)
    try:
        config = load_config()
    except FileNotFoundError as e:
        print(f"ERROR: {e}", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(f"ERROR loading config.toml: {e}", file=sys.stderr)
        sys.exit(1)

    # Open / initialize database
    conn = init_db()

    # Event queue for watcher → TUI communication
    event_queue: queue.Queue = queue.Queue(maxsize=500)

    # Start background watcher (daemon thread — dies automatically if main exits)
    watcher = EDIWatcher(config, conn, event_queue)
    watcher.start()

    # Launch Textual TUI (blocks until user presses Q)
    app = EDIRouterApp(config, conn, event_queue)
    app.run()

    # Graceful shutdown
    watcher.stop()
    conn.close()


if __name__ == "__main__":
    main()
