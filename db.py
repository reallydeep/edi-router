"""
db.py — SQLite schema, initialization, and thread-safe helpers.
Uses WAL mode so background watcher thread and Textual UI thread can read/write concurrently.
All timestamps stored as UTC ISO-8601 strings.
"""

import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Optional

from config import db_path


def _now_utc() -> str:
    return datetime.now(timezone.utc).isoformat()


def init_db(path: Optional[Path] = None) -> sqlite3.Connection:
    """Create (or open) the SQLite database, apply schema, return connection."""
    target = str(path or db_path())
    conn = sqlite3.connect(target, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    _create_schema(conn)
    conn.commit()
    return conn


def _create_schema(conn: sqlite3.Connection) -> None:
    conn.executescript("""
        CREATE TABLE IF NOT EXISTS edi_files (
            id                  INTEGER PRIMARY KEY AUTOINCREMENT,
            filename            TEXT NOT NULL,
            isa_control_number  TEXT,
            received_at         TEXT NOT NULL,
            tx_type             TEXT,
            sender_id           TEXT,
            receiver_id         TEXT,
            raw_content         TEXT,
            status              TEXT NOT NULL DEFAULT 'received'
        );

        CREATE UNIQUE INDEX IF NOT EXISTS idx_isa_control
            ON edi_files(isa_control_number)
            WHERE isa_control_number IS NOT NULL;

        CREATE TABLE IF NOT EXISTS exceptions (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            file_id         INTEGER REFERENCES edi_files(id),
            error_code      TEXT NOT NULL,
            severity        TEXT NOT NULL,
            tx_type         TEXT,
            description     TEXT,
            detected_at     TEXT NOT NULL,
            routed_at       TEXT,
            route_status    TEXT NOT NULL DEFAULT 'pending'
        );

        CREATE TABLE IF NOT EXISTS batch_queue (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            exception_id    INTEGER REFERENCES exceptions(id),
            batch_type      TEXT NOT NULL,
            queued_at       TEXT NOT NULL,
            sent_at         TEXT
        );

        CREATE TABLE IF NOT EXISTS routing_log (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            exception_id    INTEGER,
            recipient       TEXT,
            route_rule      TEXT,
            sent_at         TEXT,
            success         INTEGER,
            error_message   TEXT
        );
    """)


# ---------------------------------------------------------------------------
# edi_files helpers
# ---------------------------------------------------------------------------

def insert_edi_file(
    conn: sqlite3.Connection,
    filename: str,
    isa_control_number: Optional[str],
    tx_type: Optional[str] = None,
    sender_id: Optional[str] = None,
    receiver_id: Optional[str] = None,
    raw_content: Optional[str] = None,
) -> int:
    """Insert a new EDI file record. Returns the new row id."""
    cur = conn.execute(
        """
        INSERT INTO edi_files
            (filename, isa_control_number, received_at, tx_type, sender_id, receiver_id, raw_content)
        VALUES (?, ?, ?, ?, ?, ?, ?)
        """,
        (filename, isa_control_number, _now_utc(), tx_type, sender_id, receiver_id, raw_content),
    )
    conn.commit()
    return cur.lastrowid


def update_edi_file_status(conn: sqlite3.Connection, file_id: int, status: str) -> None:
    conn.execute("UPDATE edi_files SET status = ? WHERE id = ?", (status, file_id))
    conn.commit()


def check_duplicate_isa(conn: sqlite3.Connection, isa_control_number: str) -> bool:
    """Return True if this ISA control number has been seen before."""
    row = conn.execute(
        "SELECT 1 FROM edi_files WHERE isa_control_number = ? LIMIT 1",
        (isa_control_number,),
    ).fetchone()
    return row is not None


def file_already_processed(conn: sqlite3.Connection, filename: str) -> bool:
    """Return True if this filename has already been loaded."""
    row = conn.execute(
        "SELECT 1 FROM edi_files WHERE filename = ? LIMIT 1",
        (filename,),
    ).fetchone()
    return row is not None


# ---------------------------------------------------------------------------
# exceptions helpers
# ---------------------------------------------------------------------------

def insert_exception(
    conn: sqlite3.Connection,
    file_id: Optional[int],
    error_code: str,
    severity: str,
    tx_type: Optional[str] = None,
    description: Optional[str] = None,
) -> int:
    """Insert a detected exception. Returns new row id."""
    cur = conn.execute(
        """
        INSERT INTO exceptions (file_id, error_code, severity, tx_type, description, detected_at)
        VALUES (?, ?, ?, ?, ?, ?)
        """,
        (file_id, error_code, severity, tx_type, description, _now_utc()),
    )
    conn.commit()
    return cur.lastrowid


def mark_exception_routed(
    conn: sqlite3.Connection,
    exception_id: int,
    route_status: str,  # "sent" | "batched" | "suppressed"
) -> None:
    conn.execute(
        "UPDATE exceptions SET route_status = ?, routed_at = ? WHERE id = ?",
        (route_status, _now_utc(), exception_id),
    )
    conn.commit()


def get_pending_exceptions(
    conn: sqlite3.Connection,
    severity: Optional[str] = None,
    limit: int = 200,
) -> List[dict]:
    """Return pending (unrouted) exceptions, optionally filtered by severity."""
    if severity:
        rows = conn.execute(
            """
            SELECT e.*, f.filename FROM exceptions e
            LEFT JOIN edi_files f ON e.file_id = f.id
            WHERE e.route_status = 'pending' AND e.severity = ?
            ORDER BY e.detected_at DESC LIMIT ?
            """,
            (severity, limit),
        ).fetchall()
    else:
        rows = conn.execute(
            """
            SELECT e.*, f.filename FROM exceptions e
            LEFT JOIN edi_files f ON e.file_id = f.id
            WHERE e.route_status = 'pending'
            ORDER BY e.detected_at DESC LIMIT ?
            """,
            (limit,),
        ).fetchall()
    return [dict(r) for r in rows]


def get_exceptions_for_dashboard(
    conn: sqlite3.Connection,
    severity_filter: Optional[str] = None,
    tx_type_filter: Optional[str] = None,
    limit: int = 200,
) -> List[dict]:
    """Return exceptions for the TUI dashboard with optional filters."""
    conditions = []
    params: list = []

    if severity_filter:
        conditions.append("e.severity = ?")
        params.append(severity_filter)
    if tx_type_filter:
        conditions.append("e.tx_type = ?")
        params.append(tx_type_filter)

    where = ("WHERE " + " AND ".join(conditions)) if conditions else ""
    params.append(limit)

    rows = conn.execute(
        f"""
        SELECT e.id, e.error_code, e.severity, e.tx_type, e.description,
               e.route_status, e.detected_at, f.filename
        FROM exceptions e
        LEFT JOIN edi_files f ON e.file_id = f.id
        {where}
        ORDER BY e.detected_at DESC LIMIT ?
        """,
        params,
    ).fetchall()
    return [dict(r) for r in rows]


# ---------------------------------------------------------------------------
# batch_queue helpers
# ---------------------------------------------------------------------------

def enqueue_batch(
    conn: sqlite3.Connection,
    exception_id: int,
    batch_type: str,  # "hourly" | "daily"
) -> None:
    conn.execute(
        "INSERT INTO batch_queue (exception_id, batch_type, queued_at) VALUES (?, ?, ?)",
        (exception_id, batch_type, _now_utc()),
    )
    conn.commit()


def get_unsent_batch(
    conn: sqlite3.Connection,
    batch_type: str,
) -> List[dict]:
    """Return all unsent batch queue entries for a given batch type."""
    rows = conn.execute(
        """
        SELECT bq.id AS batch_id, bq.exception_id, bq.batch_type, bq.queued_at,
               e.error_code, e.severity, e.tx_type, e.description,
               f.filename
        FROM batch_queue bq
        JOIN exceptions e ON bq.exception_id = e.id
        LEFT JOIN edi_files f ON e.file_id = f.id
        WHERE bq.batch_type = ? AND bq.sent_at IS NULL
        ORDER BY bq.queued_at ASC
        """,
        (batch_type,),
    ).fetchall()
    return [dict(r) for r in rows]


def mark_batch_sent(conn: sqlite3.Connection, batch_ids: List[int]) -> None:
    if not batch_ids:
        return
    placeholders = ",".join("?" * len(batch_ids))
    conn.execute(
        f"UPDATE batch_queue SET sent_at = ? WHERE id IN ({placeholders})",
        [_now_utc(), *batch_ids],
    )
    conn.commit()


# ---------------------------------------------------------------------------
# routing_log helpers
# ---------------------------------------------------------------------------

def log_routing(
    conn: sqlite3.Connection,
    exception_id: Optional[int],
    recipient: str,
    route_rule: str,
    success: bool,
    error_message: Optional[str] = None,
) -> None:
    conn.execute(
        """
        INSERT INTO routing_log (exception_id, recipient, route_rule, sent_at, success, error_message)
        VALUES (?, ?, ?, ?, ?, ?)
        """,
        (exception_id, recipient, route_rule, _now_utc(), int(success), error_message),
    )
    conn.commit()


def get_last_batch_sent(conn: sqlite3.Connection, batch_type: str) -> Optional[datetime]:
    """Return the UTC datetime of the most recent successful batch send of given type."""
    row = conn.execute(
        """
        SELECT MAX(bq.sent_at) FROM batch_queue bq
        WHERE bq.batch_type = ? AND bq.sent_at IS NOT NULL
        """,
        (batch_type,),
    ).fetchone()
    if row and row[0]:
        return datetime.fromisoformat(row[0])
    return None


# ---------------------------------------------------------------------------
# Verify / CLI
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import tempfile, os

    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
        tmp = Path(f.name)

    try:
        conn = init_db(tmp)
        print("Schema created OK")

        fid = insert_edi_file(conn, "TEST_850.edi", "000000001", tx_type="850",
                              sender_id="SENDER01", receiver_id="RECEIVER1")
        print(f"Inserted edi_file id={fid}")

        eid = insert_exception(conn, fid, "E-850-STR", "HIGH", tx_type="850",
                               description="Missing BEG segment")
        print(f"Inserted exception id={eid}")

        duped = check_duplicate_isa(conn, "000000001")
        print(f"Duplicate ISA check (expect True): {duped}")

        pending = get_pending_exceptions(conn)
        print(f"Pending exceptions: {len(pending)} (expect 1)")

        enqueue_batch(conn, eid, "hourly")
        batch = get_unsent_batch(conn, "hourly")
        print(f"Batch queue (expect 1): {len(batch)}")

        mark_batch_sent(conn, [b["batch_id"] for b in batch])
        batch_after = get_unsent_batch(conn, "hourly")
        print(f"Batch queue after mark sent (expect 0): {len(batch_after)}")

        log_routing(conn, eid, "edi-team@bergen.com", "rule-5-medium-batch", True)
        print("Routing log insert OK")

        conn.close()
        print("\nAll checks passed.")
    finally:
        os.unlink(tmp)
