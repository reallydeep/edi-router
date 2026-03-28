"""
mailer.py — Email dispatch for EDI exception alerts.

Supports:
  - Immediate emails (CRITICAL / HIGH exceptions)
  - Batch emails (MEDIUM hourly digest, LOW daily digest)

Uses smtplib with STARTTLS (port 587) or SSL (port 465) depending on config.
Microsoft 365: use an App Password generated in M365 admin portal as the password.
"""

from __future__ import annotations

import smtplib
import sqlite3
from datetime import datetime, timezone
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from typing import List, Optional

from config import SMTPConfig, RoutingConfig
from classifier import EDIException


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _build_immediate_email(
    exc: EDIException,
    from_address: str,
    recipients: List[str],
    rule_name: str,
) -> MIMEMultipart:
    severity_prefix = {
        "CRITICAL": "[CRITICAL] EDI Alert",
        "HIGH": "[HIGH] EDI Alert",
    }.get(exc.severity, "[EDI Alert]")

    subject = f"{severity_prefix} — {exc.error_code} | TX {exc.tx_type}"
    body = _immediate_body(exc, rule_name)

    msg = MIMEMultipart()
    msg["From"] = from_address
    msg["To"] = ", ".join(recipients)
    msg["Subject"] = subject
    msg.attach(MIMEText(body, "plain"))
    return msg


def _immediate_body(exc: EDIException, rule_name: str) -> str:
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    return f"""EDI EXCEPTION ALERT
{'='*50}

Severity:    {exc.severity}
Error Code:  {exc.error_code}
TX Type:     {exc.tx_type}
Detected:    {now}
Route Rule:  {rule_name}

Description:
{exc.description}

{'='*50}
Recommended Actions:

{_recommended_action(exc.error_code)}

{'—'*50}
Sent by EDI Exception Auto-Router
"""


def _batch_body(exceptions: List[dict], batch_type: str) -> str:
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    label = "Hourly" if batch_type == "hourly" else "Daily"
    lines = [
        f"EDI {label.upper()} EXCEPTION DIGEST",
        "=" * 50,
        f"Generated: {now}",
        f"Exceptions: {len(exceptions)}",
        "",
    ]
    for i, exc in enumerate(exceptions, 1):
        lines.append(f"[{i}] {exc.get('error_code', '?')} | {exc.get('severity', '?')} | TX {exc.get('tx_type', '?')}")
        lines.append(f"    File: {exc.get('filename', 'unknown')}")
        lines.append(f"    {exc.get('description', '')}")
        lines.append("")

    lines += [
        "=" * 50,
        "Sent by EDI Exception Auto-Router",
    ]
    return "\n".join(lines)


def _recommended_action(error_code: str) -> str:
    actions = {
        "E-ENV-001": "Check ISA envelope structure. Verify the file is a valid X12 EDI document.",
        "E-ENV-002": "GS functional group is missing or misplaced. Review the file structure.",
        "E-ENV-003": "ST/SE transaction set boundary error. The transaction may be truncated.",
        "E-ENV-004": "Control number mismatch between ISA/IEA or GS/GE. Re-request the file from SML.",
        "E-ENV-005": "Segment count in SE01 doesn't match actual count. File may be corrupted.",
        "E-997-REJ": "Trading partner rejected your EDI. Check the AK3/AK4 error segments for specifics, correct the originating transaction, and resend.",
        "E-810-AMT": "Invoice total doesn't match line item sum. Verify quantities and unit prices with SML.",
        "E-856-STR": "ASN is missing required structure. Contact SML to resend the shipment notification.",
        "E-850-STR": "Purchase Order is missing required data. Check BEG header and PO1 line items.",
        "E-855-STR": "PO Acknowledgment missing BAK segment. Contact trading partner.",
        "E-860-STR": "PO Change Order missing BCH segment. Contact trading partner.",
        "E-UNK-TX":  "Unrecognized transaction type received. Check if SML is sending a new document type.",
        "E-DUP-ISA": "This ISA control number was already processed. Check for duplicate file transmission.",
        "E-STALE":   "Transaction is more than 48 hours old. Verify file delivery pipeline is working correctly.",
    }
    code = error_code.split(":")[0].strip()
    return actions.get(code, "Review the exception details and contact the trading partner if needed.")


def _send_message(smtp_config: SMTPConfig, msg: MIMEMultipart) -> Optional[str]:
    """
    Send a MIMEMultipart message. Returns None on success, error string on failure.
    Handles both STARTTLS (use_ssl=False) and SSL (use_ssl=True).
    """
    try:
        if smtp_config.use_ssl:
            with smtplib.SMTP_SSL(smtp_config.host, smtp_config.port, timeout=30) as server:
                if smtp_config.username:
                    server.login(smtp_config.username, smtp_config.password)
                server.send_message(msg)
        else:
            with smtplib.SMTP(smtp_config.host, smtp_config.port, timeout=30) as server:
                server.ehlo()
                server.starttls()
                server.ehlo()
                if smtp_config.username:
                    server.login(smtp_config.username, smtp_config.password)
                server.send_message(msg)
        return None  # success
    except smtplib.SMTPException as e:
        return f"SMTP error: {e}"
    except OSError as e:
        return f"Connection error: {e}"


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def send_immediate(
    smtp_config: SMTPConfig,
    recipients: List[str],
    exc: EDIException,
    rule_name: str,
    conn: Optional[sqlite3.Connection] = None,
) -> bool:
    """
    Send an immediate alert email for a single exception.
    Logs result to routing_log if conn is provided.
    Returns True on success.
    """
    from db import log_routing

    msg = _build_immediate_email(exc, smtp_config.from_address, recipients, rule_name)
    error = _send_message(smtp_config, msg)
    success = error is None

    if conn and exc.exception_id is not None:
        for recipient in recipients:
            log_routing(conn, exc.exception_id, recipient, rule_name, success, error)

    return success


def send_batch(
    smtp_config: SMTPConfig,
    routing_config: RoutingConfig,
    conn: sqlite3.Connection,
    batch_type: str,  # "hourly" | "daily"
) -> int:
    """
    Flush the batch queue for the given batch_type, send a single digest email.
    Marks all sent entries in batch_queue.
    Returns the number of exceptions included in the digest (0 if nothing to send).
    """
    from db import get_unsent_batch, mark_batch_sent, log_routing

    batch_entries = get_unsent_batch(conn, batch_type)
    if not batch_entries:
        return 0

    label = "Hourly" if batch_type == "hourly" else "Daily"
    subject = f"[EDI {label} Digest] {len(batch_entries)} exception(s)"

    body = _batch_body(batch_entries, batch_type)

    msg = MIMEMultipart()
    msg["From"] = smtp_config.from_address
    msg["To"] = routing_config.edi_team
    msg["Subject"] = subject
    msg.attach(MIMEText(body, "plain"))

    error = _send_message(smtp_config, msg)
    success = error is None

    if success:
        mark_batch_sent(conn, [e["batch_id"] for e in batch_entries])

    for entry in batch_entries:
        log_routing(
            conn,
            entry.get("exception_id"),
            routing_config.edi_team,
            f"batch-{batch_type}",
            success,
            error,
        )

    return len(batch_entries) if success else 0


# ---------------------------------------------------------------------------
# CLI test
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import sys

    print("mailer.py — to test, call send_immediate() or send_batch() from your code.")
    print("Set SMTP credentials in config.toml first.")
    print("\nSMTP settings check:")

    from config import load_config
    cfg = load_config()
    s = cfg.smtp
    mode = "SSL (port 465)" if s.use_ssl else "STARTTLS (port 587)"
    print(f"  Host:     {s.host or '(not set)'}")
    print(f"  Port:     {s.port}")
    print(f"  Mode:     {mode}")
    print(f"  From:     {s.from_address or '(not set)'}")
    print(f"  Username: {s.username or '(not set)'}")
    print(f"  Password: {'***' if s.password else '(not set)'}")
