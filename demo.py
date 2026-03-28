"""
demo.py — Demo mode for the EDI Exception Auto-Router.

run_demo() processes 7 fake EDI files through the REAL parse → classify pipeline,
determines routing using the REAL rules, but intercepts email dispatch — instead
of connecting to SMTP it pushes "demo_email_preview" events to the queue so the
TUI can display toast notifications showing what would have been sent.

All exceptions are written to the real SQLite DB so they appear in the Live Queue
exactly as they would during live operation.

Demo files cover:
  File 1: 850 PO — clean, no exceptions (shows normal flow)
  File 2: 997 Ack — rejection (AK5=R) → E-997-REJ CRITICAL → ops_manager
  File 3: 810 Invoice — amount mismatch → E-810-AMT HIGH → wms_team
  File 4: 856 ASN — missing BSN segment → E-856-STR HIGH → wms_team
  File 5: 850 PO — missing PO1 line items → E-850-STR HIGH → wms_team
  File 6: 810 Invoice — envelope control # mismatch → E-ENV-004 CRITICAL → ops_manager
  File 7: 997 Ack — unknown TX type wrapper → E-UNK-TX MEDIUM → edi_team (batch)
"""

from __future__ import annotations

import queue
import sqlite3
import time
from datetime import datetime, timezone
from typing import List, Optional, Tuple

from classifier import EDIException, classify
from config import AppConfig, RoutingConfig
from db import insert_edi_file, insert_exception, mark_exception_routed, enqueue_batch
from parser import parse_raw


# ---------------------------------------------------------------------------
# Routing rule matching — pure function, no email side effects
# ---------------------------------------------------------------------------

def match_rule(exc: EDIException, routing: RoutingConfig) -> Tuple[str, List[str], str]:
    """
    Determine which routing rule matches an exception.
    Returns (rule_name, recipients_list, delivery_description) — no side effects.
    """
    r = routing

    if exc.error_code.startswith("E-ENV-"):
        return ("rule-1-env-error",
                [r.ops_manager] if r.ops_manager else ["ops-manager@bergen.com (demo)"],
                "Immediate email")

    if exc.severity == "CRITICAL":
        return ("rule-2-critical",
                [r.ops_manager] if r.ops_manager else ["ops-manager@bergen.com (demo)"],
                "Immediate email")

    if exc.severity == "HIGH" and exc.tx_type == "997":
        recipients = [a for a in (r.edi_team, r.team_lead) if a]
        if not recipients:
            recipients = ["edi-team@bergen.com (demo)", "team-lead@bergen.com (demo)"]
        return ("rule-3-high-997", recipients, "Immediate email")

    if exc.severity == "HIGH":
        return ("rule-4-high",
                [r.wms_team] if r.wms_team else ["wms-team@bergen.com (demo)"],
                "Immediate email")

    if exc.severity == "MEDIUM":
        return ("rule-5-medium-batch",
                [r.edi_team] if r.edi_team else ["edi-team@bergen.com (demo)"],
                "Queued → hourly digest")

    if exc.severity == "LOW":
        return ("rule-6-low-daily",
                [r.edi_team] if r.edi_team else ["edi-team@bergen.com (demo)"],
                "Queued → daily digest")

    return ("rule-unmatched", [], "No rule matched")


# ---------------------------------------------------------------------------
# Sample EDI files
# ---------------------------------------------------------------------------

def _make_isa(control_num: int, date: str = "260328") -> str:
    """Build an ISA header string with the given 9-digit control number."""
    ctrl = str(control_num).zfill(9)
    return (
        f"ISA*00*          *00*          *ZZ*BERGEN01       *ZZ*SML0000001     "
        f"*{date}*1000*^*00501*{ctrl}*0*P*>"
    )


def _build_demo_files(base_ctrl: int) -> List[Tuple[str, str]]:
    """
    Return list of (filename, raw_edi) tuples.
    base_ctrl ensures unique ISA control numbers across demo runs.
    """
    files = []

    # ── File 1: Clean 850 PO — no exceptions ──────────────────────────────
    isa = _make_isa(base_ctrl + 1)
    files.append(("DEMO_850_CLEAN.edi", "\n".join([
        isa + "~",
        "GS*PO*BERGEN01*SML0000001*20260328*1000*1*X*005010~",
        "ST*850*0001~",
        "BEG*00*SA*PO-DEMO-001**20260328~",
        "REF*DP*DEPT-42~",
        "PO1*1*50*EA*12.50**VP*SKU-A001~",
        "PO1*2*20*EA*8.75**VP*SKU-B002~",
        "PO1*3*100*EA*3.00**VP*SKU-C003~",
        "CTT*3~",
        "SE*9*0001~",
        "GE*1*1~",
        f"IEA*1*{str(base_ctrl + 1).zfill(9)}~",
    ])))

    # ── File 2: 997 Ack — rejection (AK5=R) ──────────────────────────────
    isa = _make_isa(base_ctrl + 2)
    files.append(("DEMO_997_REJECTION.edi", "\n".join([
        isa + "~",
        "GS*FA*SML0000001*BERGEN01*20260328*1005*2*X*005010~",
        "ST*997*0001~",
        "AK1*PO*1~",
        "AK2*850*0001~",
        "AK3*PO1*6**8~",
        "AK4*4**6~",
        "AK5*R*5~",
        "AK9*R*1*1*0~",
        "SE*8*0001~",
        "GE*1*2~",
        f"IEA*1*{str(base_ctrl + 2).zfill(9)}~",
    ])))

    # ── File 3: 810 Invoice — amount mismatch ─────────────────────────────
    # IT1 lines sum to $625.00 but TDS01 says $999.00
    isa = _make_isa(base_ctrl + 3)
    files.append(("DEMO_810_AMT_MISMATCH.edi", "\n".join([
        isa + "~",
        "GS*IN*SML0000001*BERGEN01*20260328*1010*3*X*005010~",
        "ST*810*0001~",
        "BIG*20260328*INV-SML-2026-0042**PO-BERGEN-001~",
        "REF*IA*SML0000001~",
        "IT1*1*50*EA*7.50**VP*SKU-A001~",
        "IT1*2*20*EA*8.75**VP*SKU-B002~",
        "IT1*3*100*EA*3.00**VP*SKU-C003~",
        "TDS*99900~",    # claims $999.00 — but 50*7.50+20*8.75+100*3.00 = 375+175+300 = $850.00
        "SE*8*0001~",
        "GE*1*3~",
        f"IEA*1*{str(base_ctrl + 3).zfill(9)}~",
    ])))

    # ── File 4: 856 ASN — missing BSN segment ─────────────────────────────
    isa = _make_isa(base_ctrl + 4)
    files.append(("DEMO_856_MISSING_BSN.edi", "\n".join([
        isa + "~",
        "GS*SH*SML0000001*BERGEN01*20260328*1015*4*X*005010~",
        "ST*856*0001~",
        # BSN intentionally omitted
        "HL*1**S~",
        "TD5*B*2*UPSN~",
        "HL*2*1*O~",
        "PRF*PO-BERGEN-001~",
        "HL*3*2*P~",
        "MAN*GM*00012345678900000001~",
        "SE*8*0001~",
        "GE*1*4~",
        f"IEA*1*{str(base_ctrl + 4).zfill(9)}~",
    ])))

    # ── File 5: 850 PO — missing PO1 line items ───────────────────────────
    isa = _make_isa(base_ctrl + 5)
    files.append(("DEMO_850_NO_LINES.edi", "\n".join([
        isa + "~",
        "GS*PO*BERGEN01*SML0000001*20260328*1020*5*X*005010~",
        "ST*850*0001~",
        "BEG*00*SA*PO-DEMO-002**20260328~",
        "REF*DP*DEPT-42~",
        # PO1 intentionally omitted — no line items
        "CTT*0~",
        "SE*5*0001~",
        "GE*1*5~",
        f"IEA*1*{str(base_ctrl + 5).zfill(9)}~",
    ])))

    # ── File 6: 810 Invoice — ISA/IEA control number mismatch ────────────
    isa = _make_isa(base_ctrl + 6)
    files.append(("DEMO_810_ENV_ERROR.edi", "\n".join([
        isa + "~",
        "GS*IN*SML0000001*BERGEN01*20260328*1025*6*X*005010~",
        "ST*810*0001~",
        "BIG*20260328*INV-SML-2026-0043~",
        "IT1*1*10*EA*15.00**VP*SKU-D004~",
        "TDS*15000~",
        "SE*5*0001~",
        "GE*1*6~",
        f"IEA*1*{str(base_ctrl + 999).zfill(9)}~",   # WRONG — mismatch with ISA13
    ])))

    # ── File 7: Unknown TX type ────────────────────────────────────────────
    isa = _make_isa(base_ctrl + 7)
    files.append(("DEMO_UNKNOWN_TX.edi", "\n".join([
        isa + "~",
        "GS*XX*SML0000001*BERGEN01*20260328*1030*7*X*005010~",
        "ST*999*0001~",
        "ZZZ*CUSTOM-SEGMENT*DATA-ELEMENT~",
        "SE*3*0001~",
        "GE*1*7~",
        f"IEA*1*{str(base_ctrl + 7).zfill(9)}~",
    ])))

    return files


# ---------------------------------------------------------------------------
# Core demo runner
# ---------------------------------------------------------------------------

def run_demo(
    conn: sqlite3.Connection,
    event_queue: queue.Queue,
    config: AppConfig,
    delay_between_files: float = 0.8,
) -> None:
    """
    Process all demo EDI files through the full parse → classify → route pipeline.
    Email dispatch is intercepted — "demo_email_preview" events are pushed to the
    queue instead of connecting to SMTP.

    Meant to be called from a background thread.
    """
    # Use current timestamp to create unique ISA control numbers per run
    base_ctrl = int(datetime.now(timezone.utc).strftime("%m%d%H%M"))

    demo_files = _build_demo_files(base_ctrl)

    _push(event_queue, {
        "type": "demo_start",
        "total": len(demo_files),
    })

    total_exceptions = 0

    for filename, raw_edi in demo_files:
        time.sleep(delay_between_files)

        # Parse
        result = parse_raw(raw_edi, filename=filename)

        primary_tx = result.transactions[0] if result.transactions else None
        tx_type    = primary_tx.tx_type if primary_tx else "?"
        isa_ctrl   = primary_tx.isa_control if primary_tx else None
        sender_id  = primary_tx.sender_id if primary_tx else None
        receiver_id = primary_tx.receiver_id if primary_tx else None

        _push(event_queue, {
            "type": "file_received",
            "filename": filename,
            "tx_type": tx_type,
        })

        # Insert file record (skip silently if ISA control already exists)
        try:
            file_id = insert_edi_file(
                conn,
                filename=filename,
                isa_control_number=isa_ctrl,
                tx_type=tx_type,
                sender_id=sender_id,
                receiver_id=receiver_id,
                raw_content=raw_edi,
            )
        except Exception:
            _push(event_queue, {
                "type": "connection_error",
                "message": f"Demo: skipped {filename} (already in DB)",
            })
            continue

        # Classify
        exceptions = classify(result, conn, file_id=file_id)

        if not exceptions:
            _push(event_queue, {
                "type": "demo_file_clean",
                "filename": filename,
                "tx_type": tx_type,
            })
            continue

        total_exceptions += len(exceptions)

        # Insert exceptions into DB, determine routing, push preview events
        for exc in exceptions:
            eid = insert_exception(
                conn,
                file_id=file_id,
                error_code=exc.error_code,
                severity=exc.severity,
                tx_type=exc.tx_type,
                description=exc.description,
            )
            exc.exception_id = eid
            exc.file_id = file_id

            _push(event_queue, {
                "type": "exception_detected",
                "error_code": exc.error_code,
                "severity": exc.severity,
                "description": exc.description,
            })

            # Determine routing rule (no actual email sent)
            rule_name, recipients, delivery = match_rule(exc, config.routing)

            # Mark in DB
            if "batch" in delivery.lower() or "digest" in delivery.lower():
                enqueue_batch(conn, eid, "hourly" if "hourly" in delivery else "daily")
                mark_exception_routed(conn, eid, "batched")
            else:
                mark_exception_routed(conn, eid, "sent")

            # Push email preview event for the TUI to show as a toast
            _push(event_queue, {
                "type": "demo_email_preview",
                "rule": rule_name,
                "severity": exc.severity,
                "error_code": exc.error_code,
                "tx_type": exc.tx_type,
                "recipients": recipients,
                "delivery": delivery,
                "subject": _build_subject(exc),
                "description": exc.description,
            })

            time.sleep(0.15)  # brief pause so each toast is visible

    _push(event_queue, {
        "type": "demo_complete",
        "files": len(demo_files),
        "exceptions": total_exceptions,
    })


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _push(event_queue: queue.Queue, event: dict) -> None:
    try:
        event_queue.put_nowait(event)
    except queue.Full:
        pass


def _build_subject(exc: EDIException) -> str:
    prefix = {
        "CRITICAL": "[CRITICAL] EDI Alert",
        "HIGH":     "[HIGH] EDI Alert",
        "MEDIUM":   "[MEDIUM] EDI Notice",
        "LOW":      "[LOW] EDI Digest Item",
    }.get(exc.severity, "[EDI Alert]")
    return f"{prefix} — {exc.error_code} | TX {exc.tx_type}"
