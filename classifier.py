"""
classifier.py — EDI exception detection and severity scoring.

Takes a ParseResult from parser.py and returns a list of EDIException objects,
one per detected problem. Also accepts the database connection to check for
duplicate ISA control numbers.

Error code taxonomy:
  E-ENV-001..005  Envelope structural errors         → CRITICAL
  E-997-REJ       997 functional acknowledgment rejection → CRITICAL
  E-810-AMT       810 invoice amount mismatch        → HIGH
  E-856-STR       856 ASN structural error           → HIGH
  E-850-STR       850 PO structural error            → HIGH
  E-UNK-TX        Unknown/unsupported TX type        → MEDIUM
  E-DUP-ISA       Duplicate ISA control number       → MEDIUM
  E-STALE         Transaction older than 48 hours    → LOW
"""

from __future__ import annotations

import sqlite3
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import List, Optional

from parser import (
    ParseResult,
    ParsedTransaction,
    get_element,
    get_first_segment,
    get_segments_by_id,
    KNOWN_TX_TYPES,
)


@dataclass
class EDIException:
    error_code: str       # E-ENV-001, E-997-REJ, etc.
    severity: str         # CRITICAL | HIGH | MEDIUM | LOW
    tx_type: str          # "850", "997", "UNKNOWN", etc.
    description: str
    file_id: Optional[int] = None     # set after DB insert of edi_file
    exception_id: Optional[int] = None  # set after DB insert


# ---------------------------------------------------------------------------
# Top-level entry point
# ---------------------------------------------------------------------------

def classify(
    result: ParseResult,
    conn: Optional[sqlite3.Connection] = None,
    file_id: Optional[int] = None,
) -> List[EDIException]:
    """
    Classify all exceptions in a ParseResult.

    Args:
        result:  ParseResult from parser.parse_file() or parser.parse_raw()
        conn:    SQLite connection for duplicate ISA check (optional but recommended)
        file_id: Row ID from edi_files table (attached to returned exceptions)

    Returns:
        List of EDIException, one per problem found.
    """
    exceptions: List[EDIException] = []

    # 1. Envelope structural errors from the parser itself
    for parse_error in result.parse_errors:
        code = parse_error.split(":")[0].strip()  # e.g. "E-ENV-001"
        if code.startswith("E-ENV-"):
            exc = EDIException(
                error_code=code,
                severity="CRITICAL",
                tx_type="N/A",
                description=parse_error,
                file_id=file_id,
            )
            exceptions.append(exc)

    # 2. Per-transaction checks
    for tx in result.transactions:
        exceptions.extend(_check_transaction(tx, conn, file_id))

    return exceptions


# ---------------------------------------------------------------------------
# Per-transaction checks
# ---------------------------------------------------------------------------

def _check_transaction(
    tx: ParsedTransaction,
    conn: Optional[sqlite3.Connection],
    file_id: Optional[int],
) -> List[EDIException]:
    found: List[EDIException] = []

    # Unknown TX type
    if tx.tx_type not in KNOWN_TX_TYPES:
        found.append(EDIException(
            error_code="E-UNK-TX",
            severity="MEDIUM",
            tx_type=tx.tx_type or "UNKNOWN",
            description=f"Unrecognized transaction type: ST01={tx.tx_type!r}",
            file_id=file_id,
        ))
        return found  # can't do further TX-specific checks

    # Duplicate ISA control number
    if conn and tx.isa_control:
        from db import check_duplicate_isa
        if check_duplicate_isa(conn, tx.isa_control):
            found.append(EDIException(
                error_code="E-DUP-ISA",
                severity="MEDIUM",
                tx_type=tx.tx_type,
                description=f"Duplicate ISA control number: {tx.isa_control}",
                file_id=file_id,
            ))

    # Stale transaction (ISA date > 48h ago)
    stale = _check_stale(tx)
    if stale:
        found.append(EDIException(
            error_code="E-STALE",
            severity="LOW",
            tx_type=tx.tx_type,
            description=stale,
            file_id=file_id,
        ))

    # TX-specific structural + business rule checks
    if tx.tx_type == "997":
        found.extend(_check_997(tx, file_id))
    elif tx.tx_type == "810":
        found.extend(_check_810(tx, file_id))
    elif tx.tx_type == "856":
        found.extend(_check_856(tx, file_id))
    elif tx.tx_type == "850":
        found.extend(_check_850(tx, file_id))
    elif tx.tx_type == "855":
        found.extend(_check_855(tx, file_id))
    elif tx.tx_type == "860":
        found.extend(_check_860(tx, file_id))

    return found


# ---------------------------------------------------------------------------
# Stale check
# ---------------------------------------------------------------------------

def _check_stale(tx: ParsedTransaction) -> Optional[str]:
    """Return description string if the ISA date is > 48h old, else None."""
    if not tx.date or len(tx.date) < 6:
        return None
    try:
        # ISA09 format: YYMMDD (6 digits) — some implementations use CCYYMMDD (8 digits)
        date_str = tx.date
        time_str = tx.time if tx.time and len(tx.time) >= 4 else "0000"

        if len(date_str) == 6:
            dt = datetime.strptime(date_str + time_str[:4], "%y%m%d%H%M")
        elif len(date_str) == 8:
            dt = datetime.strptime(date_str + time_str[:4], "%Y%m%d%H%M")
        else:
            return None

        dt = dt.replace(tzinfo=timezone.utc)
        age = datetime.now(timezone.utc) - dt
        if age > timedelta(hours=48):
            return (
                f"Transaction is {int(age.total_seconds() // 3600)}h old "
                f"(ISA date {tx.date} {tx.time}) — threshold 48h"
            )
    except ValueError:
        pass  # unparseable date — don't flag as stale
    return None


# ---------------------------------------------------------------------------
# TX-specific checks
# ---------------------------------------------------------------------------

def _check_997(tx: ParsedTransaction, file_id: Optional[int]) -> List[EDIException]:
    """
    E-997-REJ: AK501 ≠ 'A' (accepted) indicates trading partner rejected our EDI.

    AK5 values:
      A = Accepted
      E = Accepted with errors
      R = Rejected
      P = Partially accepted
    """
    exceptions = []
    for ak5 in get_segments_by_id(tx, "AK5"):
        ak501 = get_element(ak5, 0)  # acceptance code
        if ak501 != "A":
            # Try to get the referenced TX type from AK1
            ak1 = get_first_segment(tx, "AK1")
            ref_tx = get_element(ak1, 0) if ak1 else "unknown"
            ak9 = get_first_segment(tx, "AK9")
            ak901 = get_element(ak9, 0) if ak9 else ak501

            status_labels = {"R": "Rejected", "E": "Accepted with errors", "P": "Partially accepted"}
            status = status_labels.get(ak501, f"Code={ak501!r}")

            exceptions.append(EDIException(
                error_code="E-997-REJ",
                severity="CRITICAL",
                tx_type=tx.tx_type,
                description=(
                    f"997 {status}: trading partner rejected TX group {ref_tx!r}. "
                    f"AK501={ak501!r}, AK901={ak901!r}"
                ),
                file_id=file_id,
            ))
    return exceptions


def _check_810(tx: ParsedTransaction, file_id: Optional[int]) -> List[EDIException]:
    """
    E-810-STR: Missing BIG, IT1, or TDS segments.
    E-810-AMT: TDS01 (total) doesn't match sum of IT1 line amounts.

    Note: Amount precision may be explicit (12.50) or implied (1250 = $12.50).
    We attempt both interpretations; if neither gives an exact match we report
    a mismatch with a note about precision.
    """
    exceptions = []

    # Structural check
    for seg_id in ("BIG", "IT1", "TDS"):
        if not get_first_segment(tx, seg_id):
            exceptions.append(EDIException(
                error_code="E-810-AMT",
                severity="HIGH",
                tx_type="810",
                description=f"810 Invoice missing required segment: {seg_id}",
                file_id=file_id,
            ))

    # Amount check — only if TDS and IT1 are present
    tds = get_first_segment(tx, "TDS")
    it1_segs = get_segments_by_id(tx, "IT1")

    if tds and it1_segs:
        tds01 = get_element(tds, 0).replace(",", "")
        try:
            total_declared = float(tds01)
        except ValueError:
            exceptions.append(EDIException(
                error_code="E-810-AMT",
                severity="HIGH",
                tx_type="810",
                description=f"810 Invoice TDS01 is not a valid number: {tds01!r}",
                file_id=file_id,
            ))
            return exceptions

        # Sum IT1 lines: IT102 = quantity, IT104 = unit price
        line_total = 0.0
        for it1 in it1_segs:
            qty_str = get_element(it1, 1).replace(",", "")  # IT102
            price_str = get_element(it1, 3).replace(",", "")  # IT104
            try:
                line_total += float(qty_str) * float(price_str)
            except ValueError:
                pass  # skip lines with unparseable amounts

        # Compare with tolerance (rounding to 2 decimal places)
        total_rounded = round(line_total, 2)
        declared_rounded = round(total_declared, 2)

        if total_rounded != declared_rounded:
            # Try implied decimal: divide line total by 100
            implied_total = round(line_total / 100, 2)
            if implied_total == declared_rounded:
                pass  # implied decimal match — valid, no exception
            else:
                exceptions.append(EDIException(
                    error_code="E-810-AMT",
                    severity="HIGH",
                    tx_type="810",
                    description=(
                        f"810 Invoice amount mismatch: TDS01={total_declared:.2f} "
                        f"but IT1 lines sum to {total_rounded:.2f} "
                        f"(confirm explicit vs implied decimal with SML)"
                    ),
                    file_id=file_id,
                ))

    return exceptions


def _check_856(tx: ParsedTransaction, file_id: Optional[int]) -> List[EDIException]:
    """E-856-STR: Missing BSN segment or zero HL loops."""
    exceptions = []

    if not get_first_segment(tx, "BSN"):
        exceptions.append(EDIException(
            error_code="E-856-STR",
            severity="HIGH",
            tx_type="856",
            description="856 ASN missing required BSN segment",
            file_id=file_id,
        ))

    hl_count = len(get_segments_by_id(tx, "HL"))
    if hl_count == 0:
        exceptions.append(EDIException(
            error_code="E-856-STR",
            severity="HIGH",
            tx_type="856",
            description="856 ASN has no HL (hierarchical level) loops — shipment structure is empty",
            file_id=file_id,
        ))

    return exceptions


def _check_850(tx: ParsedTransaction, file_id: Optional[int]) -> List[EDIException]:
    """E-850-STR: Missing BEG segment or zero PO1 line items."""
    exceptions = []

    if not get_first_segment(tx, "BEG"):
        exceptions.append(EDIException(
            error_code="E-850-STR",
            severity="HIGH",
            tx_type="850",
            description="850 Purchase Order missing required BEG segment",
            file_id=file_id,
        ))

    po1_count = len(get_segments_by_id(tx, "PO1"))
    if po1_count == 0:
        exceptions.append(EDIException(
            error_code="E-850-STR",
            severity="HIGH",
            tx_type="850",
            description="850 Purchase Order has no PO1 line items",
            file_id=file_id,
        ))

    return exceptions


def _check_855(tx: ParsedTransaction, file_id: Optional[int]) -> List[EDIException]:
    """Basic structural check: BAK segment required."""
    if not get_first_segment(tx, "BAK"):
        return [EDIException(
            error_code="E-855-STR",
            severity="HIGH",
            tx_type="855",
            description="855 PO Acknowledgment missing required BAK segment",
            file_id=file_id,
        )]
    return []


def _check_860(tx: ParsedTransaction, file_id: Optional[int]) -> List[EDIException]:
    """Basic structural check: BCH segment required."""
    if not get_first_segment(tx, "BCH"):
        return [EDIException(
            error_code="E-860-STR",
            severity="HIGH",
            tx_type="860",
            description="860 PO Change Order missing required BCH segment",
            file_id=file_id,
        )]
    return []


# ---------------------------------------------------------------------------
# CLI / Verification
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import sys
    from parser import parse_raw, parse_file

    def _run_classifier_tests() -> None:
        print("Running classifier tests...\n")

        isa = "ISA*00*          *00*          *ZZ*SENDER01       *ZZ*RECEIVER1      *260328*1000*^*00501*000000001*0*P*>"

        # --- Test 1: Valid 850, no exceptions ---
        edi_850_ok = (
            isa + "~\n"
            "GS*PO*SENDER01*RECEIVER1*20260328*1000*1*X*005010~\n"
            "ST*850*0001~\n"
            "BEG*00*SA*PO12345**20260328~\n"
            "PO1*1*10*EA*5.00**VP*ITEM001~\n"
            "SE*4*0001~\n"
            "GE*1*1~\n"
            "IEA*1*000000001~\n"
        )
        r = parse_raw(edi_850_ok, "test_850_ok.edi")
        excs = classify(r)
        assert len(excs) == 0, f"Expected 0 exceptions, got: {excs}"
        print("  ✓ Valid 850 — no exceptions")

        # --- Test 2: 997 rejection → E-997-REJ ---
        edi_997_rej = (
            isa + "~\n"
            "GS*FA*SENDER01*RECEIVER1*20260328*1000*1*X*005010~\n"
            "ST*997*0001~\n"
            "AK1*PO*1~\n"
            "AK2*850*0001~\n"
            "AK3*BEG*3**8~\n"
            "AK4*1**8~\n"
            "AK5*R*5~\n"
            "AK9*R*1*1*0~\n"
            "SE*8*0001~\n"
            "GE*1*1~\n"
            "IEA*1*000000001~\n"
        )
        r997 = parse_raw(edi_997_rej, "test_997_rej.edi")
        excs997 = classify(r997)
        rej = [e for e in excs997 if e.error_code == "E-997-REJ"]
        assert rej, f"Expected E-997-REJ, got: {excs997}"
        assert rej[0].severity == "CRITICAL"
        print("  ✓ E-997-REJ detected (997 rejection, CRITICAL)")

        # --- Test 3: 856 missing BSN → E-856-STR ---
        edi_856_bad = (
            isa + "~\n"
            "GS*SH*SENDER01*RECEIVER1*20260328*1000*1*X*005010~\n"
            "ST*856*0001~\n"
            "HL*1**S~\n"
            "SE*3*0001~\n"
            "GE*1*1~\n"
            "IEA*1*000000001~\n"
        )
        r856 = parse_raw(edi_856_bad, "test_856_bad.edi")
        excs856 = classify(r856)
        assert any(e.error_code == "E-856-STR" for e in excs856), f"Expected E-856-STR: {excs856}"
        print("  ✓ E-856-STR detected (856 missing BSN)")

        # --- Test 4: 810 amount mismatch → E-810-AMT ---
        edi_810_mismatch = (
            isa + "~\n"
            "GS*IN*SENDER01*RECEIVER1*20260328*1000*1*X*005010~\n"
            "ST*810*0001~\n"
            "BIG*20260328*INV001~\n"
            "IT1*1*10*EA*5.00~\n"
            "TDS*9999~\n"   # declared total 99.99, but IT1 is 10*5.00=50.00 → mismatch
            "SE*5*0001~\n"
            "GE*1*1~\n"
            "IEA*1*000000001~\n"
        )
        r810 = parse_raw(edi_810_mismatch, "test_810_mismatch.edi")
        excs810 = classify(r810)
        assert any(e.error_code == "E-810-AMT" for e in excs810), f"Expected E-810-AMT: {excs810}"
        print("  ✓ E-810-AMT detected (invoice total mismatch)")

        # --- Test 5: Unknown TX type → E-UNK-TX ---
        edi_unk = (
            isa + "~\n"
            "GS*XX*SENDER01*RECEIVER1*20260328*1000*1*X*005010~\n"
            "ST*999*0001~\n"
            "ZZZ*somedata~\n"
            "SE*3*0001~\n"
            "GE*1*1~\n"
            "IEA*1*000000001~\n"
        )
        r_unk = parse_raw(edi_unk, "test_unk.edi")
        excs_unk = classify(r_unk)
        unk_exc = [e for e in excs_unk if e.error_code == "E-UNK-TX"]
        assert unk_exc, f"Expected E-UNK-TX: {excs_unk}"
        assert unk_exc[0].severity == "MEDIUM"
        print("  ✓ E-UNK-TX detected (unknown TX type, MEDIUM)")

        print("\nAll classifier tests passed.")

    _run_classifier_tests()
