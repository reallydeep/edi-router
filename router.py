"""
router.py — First-match-wins routing engine.

Routing rules (evaluated in priority order):
  1. error_code starts with E-ENV-*  → Immediate → ops_manager
  2. severity = CRITICAL             → Immediate → ops_manager
  3. severity = HIGH AND tx = 997    → Immediate → edi_team + team_lead
  4. severity = HIGH                 → Immediate → wms_team
  5. severity = MEDIUM               → Enqueue hourly batch → edi_team
  6. severity = LOW                  → Enqueue daily digest → edi_team

The router calls mailer.send_immediate() or db.enqueue_batch() based on the rule,
then marks the exception as routed in the database.
"""

from __future__ import annotations

import sqlite3
from typing import List, Optional

from classifier import EDIException
from config import AppConfig
from db import enqueue_batch, mark_exception_routed
from mailer import send_immediate


def route(
    exc: EDIException,
    config: AppConfig,
    conn: sqlite3.Connection,
    templates: Optional[dict] = None,
) -> str:
    """
    Apply routing rules to a single exception.
    Returns the name of the rule that matched (for logging).
    The exception must have exception_id set before calling this.
    """
    r = config.routing
    smtp = config.smtp

    # Rule 1: Envelope errors → immediate to ops_manager (regardless of severity)
    if exc.error_code.startswith("E-ENV-"):
        recipients = [r.ops_manager] if r.ops_manager else []
        rule = "rule-1-env-error"
        if recipients:
            send_immediate(smtp, recipients, exc, rule, conn, templates)
        if exc.exception_id is not None:
            mark_exception_routed(conn, exc.exception_id, "sent" if recipients else "suppressed")
        return rule

    # Rule 2: CRITICAL → immediate to ops_manager
    if exc.severity == "CRITICAL":
        recipients = [r.ops_manager] if r.ops_manager else []
        rule = "rule-2-critical"
        if recipients:
            send_immediate(smtp, recipients, exc, rule, conn, templates)
        if exc.exception_id is not None:
            mark_exception_routed(conn, exc.exception_id, "sent" if recipients else "suppressed")
        return rule

    # Rule 3: HIGH + 997 → immediate to edi_team + team_lead
    if exc.severity == "HIGH" and exc.tx_type == "997":
        recipients = [addr for addr in (r.edi_team, r.team_lead) if addr]
        rule = "rule-3-high-997"
        if recipients:
            send_immediate(smtp, recipients, exc, rule, conn, templates)
        if exc.exception_id is not None:
            mark_exception_routed(conn, exc.exception_id, "sent" if recipients else "suppressed")
        return rule

    # Rule 4: HIGH (non-997) → immediate to wms_team
    if exc.severity == "HIGH":
        recipients = [r.wms_team] if r.wms_team else []
        rule = "rule-4-high"
        if recipients:
            send_immediate(smtp, recipients, exc, rule, conn, templates)
        if exc.exception_id is not None:
            mark_exception_routed(conn, exc.exception_id, "sent" if recipients else "suppressed")
        return rule

    # Rule 5: MEDIUM → hourly batch to edi_team
    if exc.severity == "MEDIUM":
        rule = "rule-5-medium-batch"
        if exc.exception_id is not None:
            enqueue_batch(conn, exc.exception_id, "hourly")
            mark_exception_routed(conn, exc.exception_id, "batched")
        return rule

    # Rule 6: LOW → daily digest to edi_team
    if exc.severity == "LOW":
        rule = "rule-6-low-daily"
        if exc.exception_id is not None:
            enqueue_batch(conn, exc.exception_id, "daily")
            mark_exception_routed(conn, exc.exception_id, "batched")
        return rule

    # Fallback (should never reach here with valid severity values)
    return "rule-unmatched"


def route_all(
    exceptions: List[EDIException],
    config: AppConfig,
    conn: sqlite3.Connection,
    templates: Optional[dict] = None,
) -> List[str]:
    """Route a list of exceptions. Returns list of matched rule names."""
    return [route(exc, config, conn, templates) for exc in exceptions]
