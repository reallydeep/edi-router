"""
watcher.py — Background polling daemon for EDI files.

Supports SFTP (paramiko) and plain FTP (ftplib) based on config.connection.protocol.
Runs as a daemon thread. Communicates with the TUI via a shared queue.Queue.

Event types pushed to the queue:
  {"type": "poll_start"}
  {"type": "file_received",    "filename": str, "tx_type": str}
  {"type": "exception_detected", "error_code": str, "severity": str, "description": str}
  {"type": "email_sent",       "recipients": list, "rule": str}
  {"type": "connection_error", "message": str}
  {"type": "poll_complete",    "files_processed": int, "exceptions_found": int}
"""

from __future__ import annotations

import io
import queue
import sqlite3
import threading
import time
from datetime import datetime, timedelta, timezone
from typing import List, Optional

from classifier import classify
from config import AppConfig
from db import (
    file_already_processed,
    get_unsent_batch,
    insert_edi_file,
    insert_exception,
    update_edi_file_status,
)
from mailer import send_batch
from parser import parse_raw
from router import route_all


class EDIWatcher:
    def __init__(
        self,
        config: AppConfig,
        conn: sqlite3.Connection,
        event_queue: queue.Queue,
        templates: Optional[dict] = None,
    ):
        self.config = config
        self.conn = conn
        self.event_queue = event_queue
        self.templates = templates or {}
        self._stop_event = threading.Event()
        self._thread: Optional[threading.Thread] = None

        # Batch flush timestamps
        self._last_hourly_flush: datetime = datetime.now(timezone.utc)
        self._last_daily_flush: datetime = datetime.now(timezone.utc)

    # ------------------------------------------------------------------
    # Public
    # ------------------------------------------------------------------

    def start(self) -> threading.Thread:
        """Start the watcher daemon thread. Returns the thread."""
        self._thread = threading.Thread(
            target=self._poll_loop,
            name="EDIWatcher",
            daemon=True,
        )
        self._thread.start()
        return self._thread

    def stop(self) -> None:
        """Signal the daemon thread to stop gracefully."""
        self._stop_event.set()

    def is_alive(self) -> bool:
        return self._thread is not None and self._thread.is_alive()

    # ------------------------------------------------------------------
    # Poll loop
    # ------------------------------------------------------------------

    def _poll_loop(self) -> None:
        interval = self.config.connection.poll_interval_seconds
        while not self._stop_event.is_set():
            try:
                self._poll_once()
            except Exception as exc:
                self._push({"type": "connection_error", "message": str(exc)})

            self._maybe_flush_batches()

            # Sleep in small increments so stop_event is checked promptly
            for _ in range(interval):
                if self._stop_event.is_set():
                    return
                time.sleep(1)

    def _poll_once(self) -> None:
        """Connect, list remote dir, download and process new files."""
        self._push({"type": "poll_start"})

        protocol = self.config.connection.protocol
        files_processed = 0
        exceptions_found = 0

        try:
            if protocol == "sftp":
                files, download_fn = self._list_sftp()
            else:
                files, download_fn = self._list_ftp()
        except Exception as exc:
            self._push({"type": "connection_error", "message": f"Failed to connect: {exc}"})
            self._push({"type": "poll_complete", "files_processed": 0, "exceptions_found": 0})
            return

        for filename in files:
            if file_already_processed(self.conn, filename):
                continue
            try:
                content_bytes = download_fn(filename)
                n_exc = self._process_file(filename, content_bytes)
                exceptions_found += n_exc
                files_processed += 1
            except Exception as exc:
                self._push({
                    "type": "connection_error",
                    "message": f"Error processing {filename}: {exc}",
                })

        self._push({
            "type": "poll_complete",
            "files_processed": files_processed,
            "exceptions_found": exceptions_found,
        })

    def _process_file(self, filename: str, content_bytes: bytes) -> int:
        """Parse, classify, route, and log a single EDI file. Returns exception count."""
        # Decode content
        try:
            content = content_bytes.decode("utf-8")
        except UnicodeDecodeError:
            content = content_bytes.decode("latin-1")

        # Parse
        result = parse_raw(content, filename=filename)

        # Determine primary TX type and ISA control for DB record
        primary_tx = result.transactions[0] if result.transactions else None
        tx_type = primary_tx.tx_type if primary_tx else None
        isa_control = primary_tx.isa_control if primary_tx else None
        sender_id = primary_tx.sender_id if primary_tx else None
        receiver_id = primary_tx.receiver_id if primary_tx else None

        # Insert file record
        try:
            file_id = insert_edi_file(
                self.conn,
                filename=filename,
                isa_control_number=isa_control,
                tx_type=tx_type,
                sender_id=sender_id,
                receiver_id=receiver_id,
                raw_content=content,
            )
        except Exception:
            # Duplicate ISA unique index hit — file sneaked through the filename check
            return 0

        # Push file received event
        self._push({
            "type": "file_received",
            "filename": filename,
            "tx_type": tx_type or "?",
        })

        # Classify
        exceptions = classify(result, self.conn, file_id=file_id)

        if not exceptions:
            update_edi_file_status(self.conn, file_id, "parsed")
            return 0

        # Insert exceptions into DB so they get IDs, then route
        for exc in exceptions:
            eid = insert_exception(
                self.conn,
                file_id=file_id,
                error_code=exc.error_code,
                severity=exc.severity,
                tx_type=exc.tx_type,
                description=exc.description,
            )
            exc.exception_id = eid
            exc.file_id = file_id

            self._push({
                "type": "exception_detected",
                "error_code": exc.error_code,
                "severity": exc.severity,
                "description": exc.description,
            })

        # Route all (sends emails / enqueues batches)
        rules = route_all(exceptions, self.config, self.conn, self.templates)

        for exc, rule in zip(exceptions, rules):
            if rule.startswith("rule-1") or rule.startswith("rule-2") or \
               rule.startswith("rule-3") or rule.startswith("rule-4"):
                # Immediate email was (attempted to be) sent
                self._push({
                    "type": "email_sent",
                    "rule": rule,
                    "error_code": exc.error_code,
                })

        update_edi_file_status(self.conn, file_id, "parsed")
        return len(exceptions)

    # ------------------------------------------------------------------
    # Batch flush
    # ------------------------------------------------------------------

    def _maybe_flush_batches(self) -> None:
        now = datetime.now(timezone.utc)

        if now - self._last_hourly_flush >= timedelta(hours=1):
            try:
                n = send_batch(self.config.smtp, self.config.routing, self.conn, "hourly")
                if n > 0:
                    self._push({"type": "email_sent", "rule": "batch-hourly", "count": n})
            except Exception as exc:
                self._push({"type": "connection_error", "message": f"Hourly batch error: {exc}"})
            self._last_hourly_flush = now

        if now - self._last_daily_flush >= timedelta(hours=24):
            try:
                n = send_batch(self.config.smtp, self.config.routing, self.conn, "daily")
                if n > 0:
                    self._push({"type": "email_sent", "rule": "batch-daily", "count": n})
            except Exception as exc:
                self._push({"type": "connection_error", "message": f"Daily batch error: {exc}"})
            self._last_daily_flush = now

    # ------------------------------------------------------------------
    # SFTP / FTP connectors
    # ------------------------------------------------------------------

    def _list_sftp(self):
        """Returns (list_of_filenames, download_fn) using paramiko SFTP."""
        import paramiko

        conn_cfg = self.config.connection
        transport = paramiko.Transport((conn_cfg.host, conn_cfg.port))
        transport.connect(username=conn_cfg.username, password=conn_cfg.password)
        sftp = paramiko.SFTPClient.from_transport(transport)

        attrs = sftp.listdir_attr(conn_cfg.remote_path)
        edi_files = [
            a.filename for a in attrs
            if a.filename.lower().endswith((".edi", ".x12", ".txt"))
        ]

        def download(filename: str) -> bytes:
            remote = f"{conn_cfg.remote_path.rstrip('/')}/{filename}"
            buf = io.BytesIO()
            sftp.getfo(remote, buf)
            return buf.getvalue()

        return edi_files, download

    def _list_ftp(self):
        """Returns (list_of_filenames, download_fn) using stdlib ftplib."""
        import ftplib

        conn_cfg = self.config.connection
        ftp = ftplib.FTP()
        ftp.connect(conn_cfg.host, conn_cfg.port, timeout=30)
        ftp.login(conn_cfg.username, conn_cfg.password)
        ftp.cwd(conn_cfg.remote_path)

        all_files = ftp.nlst()
        edi_files = [
            f for f in all_files
            if f.lower().endswith((".edi", ".x12", ".txt"))
        ]

        def download(filename: str) -> bytes:
            buf = io.BytesIO()
            ftp.retrbinary(f"RETR {filename}", buf.write)
            return buf.getvalue()

        return edi_files, download

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _push(self, event: dict) -> None:
        """Push an event to the UI queue (non-blocking)."""
        try:
            self.event_queue.put_nowait(event)
        except queue.Full:
            pass  # TUI not draining fast enough — drop event rather than block
