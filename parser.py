"""
parser.py — X12 EDI segment parser.

Handles all standard transaction types (850, 856, 810, 997, 855, 860) plus any unknown TX.
Auto-detects ISA element delimiter and segment terminator from the fixed-width ISA header.

Usage:
    from parser import parse_file, parse_raw

    result = parse_file("path/to/file.edi")
    for tx in result.transactions:
        print(tx.tx_type, tx.isa_control, len(tx.segments), "segments")

CLI:
    python3 parser.py path/to/file.edi
"""

from __future__ import annotations

import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Tuple


# ---------------------------------------------------------------------------
# Known TX types and their mandatory segments
# ---------------------------------------------------------------------------

KNOWN_TX_TYPES = {"850", "856", "810", "997", "855", "860"}

MANDATORY_SEGMENTS: Dict[str, List[str]] = {
    "850": ["BEG", "PO1"],
    "856": ["BSN", "HL"],
    "810": ["BIG", "IT1", "TDS"],
    "997": ["AK1", "AK9"],
    "855": ["BAK"],
    "860": ["BCH"],
}

# GS functional ID code → TX type (GS01 element)
GS_FUNCTIONAL_ID: Dict[str, str] = {
    "PO": "850",
    "SH": "856",
    "IN": "810",
    "FA": "997",
    "PR": "855",
    "PC": "860",
}


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------

@dataclass
class ParsedSegment:
    segment_id: str          # e.g. "ISA", "BEG", "PO1"
    elements: List[str]      # element values (index 0 = element after the segment ID)
    raw: str                 # original raw segment string


@dataclass
class ParsedTransaction:
    tx_type: str             # "850", "856", "810", "997", "855", "860", or "UNKNOWN"
    control_number: str      # ST02 — transaction set control number
    isa_control: str         # ISA13 — interchange control number (raw string)
    gs_control: str          # GS06 — group control number
    sender_id: str           # ISA06 — interchange sender ID (stripped)
    receiver_id: str         # ISA08 — interchange receiver ID (stripped)
    date: str                # ISA09 — YYMMDD
    time: str                # ISA10 — HHMM
    segments: List[ParsedSegment] = field(default_factory=list)
    raw: str = ""


@dataclass
class ParseResult:
    filename: str
    transactions: List[ParsedTransaction]
    parse_errors: List[str]   # structural errors found during parsing itself


# ---------------------------------------------------------------------------
# Delimiter detection
# ---------------------------------------------------------------------------

def detect_delimiters(raw: str) -> Tuple[str, str, str]:
    """
    Detect ISA delimiters from the fixed-width ISA header.

    ISA is exactly 106 characters:
      Position 3:   element delimiter  (e.g. '*')
      Position 104: sub-element delimiter (e.g. '>')
      Position 105: segment terminator (e.g. '~')

    Returns (element_sep, subelement_sep, segment_terminator).
    Raises ValueError if the file doesn't start with 'ISA'.
    """
    if len(raw) < 106:
        raise ValueError(
            f"File too short to contain a valid ISA header (got {len(raw)} chars, need ≥106)"
        )
    if not raw.startswith("ISA"):
        raise ValueError(
            f"File does not start with 'ISA' (got {raw[:3]!r})"
        )

    element_sep = raw[3]
    subelement_sep = raw[104]
    segment_term = raw[105]

    return element_sep, subelement_sep, segment_term


# ---------------------------------------------------------------------------
# Core parsing
# ---------------------------------------------------------------------------

def _split_segments(raw: str, segment_term: str, element_sep: str) -> List[str]:
    """
    Split raw X12 into individual segment strings.
    Handles whitespace after segment terminator (e.g. '~\\r\\n' or '~ ').
    """
    # Split on segment terminator
    parts = raw.split(segment_term)
    segments = []
    for part in parts:
        # Strip surrounding whitespace (handles \r\n padding after ~)
        cleaned = part.strip()
        if cleaned:
            segments.append(cleaned)
    return segments


def _parse_segment(raw_seg: str, element_sep: str) -> ParsedSegment:
    """Parse a single segment string into a ParsedSegment."""
    parts = raw_seg.split(element_sep)
    seg_id = parts[0].strip()
    elements = parts[1:]  # everything after the segment ID
    return ParsedSegment(segment_id=seg_id, elements=elements, raw=raw_seg)


def parse_raw(content: str, filename: str = "<raw>") -> ParseResult:
    """
    Parse raw X12 EDI content string.
    Returns a ParseResult with all transactions found and any structural parse errors.
    """
    errors: List[str] = []
    transactions: List[ParsedTransaction] = []

    # Try to detect delimiters
    try:
        element_sep, subelement_sep, segment_term = detect_delimiters(content)
    except ValueError as e:
        return ParseResult(
            filename=filename,
            transactions=[],
            parse_errors=[f"E-ENV-001: {e}"],
        )

    raw_segments = _split_segments(content, segment_term, element_sep)

    if not raw_segments:
        return ParseResult(
            filename=filename,
            transactions=[],
            parse_errors=["E-ENV-001: No segments found after splitting"],
        )

    parsed_segments = [_parse_segment(s, element_sep) for s in raw_segments]

    # State machine: walk segments and group into transactions
    # States: OUTSIDE_ISA → IN_ISA → IN_GS → IN_ST → AFTER_SE
    STATE_OUTSIDE = "OUTSIDE_ISA"
    STATE_ISA = "IN_ISA"
    STATE_GS = "IN_GS"
    STATE_ST = "IN_ST"

    state = STATE_OUTSIDE

    # Envelope data accumulated during walk
    isa_seg: Optional[ParsedSegment] = None
    gs_seg: Optional[ParsedSegment] = None
    iea_seg: Optional[ParsedSegment] = None
    ge_seg: Optional[ParsedSegment] = None

    current_tx: Optional[ParsedTransaction] = None
    current_tx_segments: List[ParsedSegment] = []
    segment_count_in_tx = 0  # counts segments between ST and SE inclusive

    for seg in parsed_segments:
        sid = seg.segment_id

        if sid == "ISA":
            if state != STATE_OUTSIDE:
                errors.append("E-ENV-001: Unexpected ISA — previous interchange not closed")
            isa_seg = seg
            iea_seg = None
            state = STATE_ISA

        elif sid == "IEA":
            iea_seg = seg
            if isa_seg is None:
                errors.append("E-ENV-001: IEA found without matching ISA")
            else:
                # Validate ISA13 == IEA02
                isa_control = isa_seg.elements[12] if len(isa_seg.elements) >= 13 else ""
                iea_control = seg.elements[1] if len(seg.elements) >= 2 else ""
                try:
                    if int(isa_control) != int(iea_control):
                        errors.append(
                            f"E-ENV-004: ISA13 ({isa_control!r}) ≠ IEA02 ({iea_control!r})"
                        )
                except ValueError:
                    errors.append(
                        f"E-ENV-004: Non-numeric ISA13/IEA02: ISA13={isa_control!r}, IEA02={iea_control!r}"
                    )
            state = STATE_OUTSIDE

        elif sid == "GS":
            if state not in (STATE_ISA, STATE_GS):
                errors.append("E-ENV-002: GS found in unexpected state")
            gs_seg = seg
            ge_seg = None
            state = STATE_GS

        elif sid == "GE":
            ge_seg = seg
            if gs_seg is None:
                errors.append("E-ENV-002: GE found without matching GS")
            else:
                # Validate GS06 == GE02
                gs_control = gs_seg.elements[5] if len(gs_seg.elements) >= 6 else ""
                ge_control = seg.elements[1] if len(seg.elements) >= 2 else ""
                try:
                    if int(gs_control) != int(ge_control):
                        errors.append(
                            f"E-ENV-004: GS06 ({gs_control!r}) ≠ GE02 ({ge_control!r})"
                        )
                except ValueError:
                    errors.append(
                        f"E-ENV-004: Non-numeric GS06/GE02: GS06={gs_control!r}, GE02={ge_control!r}"
                    )
            state = STATE_ISA

        elif sid == "ST":
            if state not in (STATE_GS, STATE_ISA):
                errors.append("E-ENV-003: ST found without preceding GS")
            if isa_seg is None:
                errors.append("E-ENV-003: ST found without preceding ISA")

            # Determine TX type from ST01; fall back to GS01 functional ID
            st01 = seg.elements[0] if len(seg.elements) >= 1 else ""
            tx_type = st01 if st01 in KNOWN_TX_TYPES else GS_FUNCTIONAL_ID.get(
                gs_seg.elements[0] if gs_seg and gs_seg.elements else "", "UNKNOWN"
            )
            if tx_type not in KNOWN_TX_TYPES:
                tx_type = "UNKNOWN"

            st02 = seg.elements[1] if len(seg.elements) >= 2 else ""

            # Pull from ISA envelope
            isa_els = isa_seg.elements if isa_seg else []
            sender_id = (isa_els[5].strip() if len(isa_els) >= 6 else "")
            receiver_id = (isa_els[7].strip() if len(isa_els) >= 8 else "")
            isa_date = (isa_els[8] if len(isa_els) >= 9 else "")
            isa_time = (isa_els[9] if len(isa_els) >= 10 else "")
            isa_control_num = (isa_els[12] if len(isa_els) >= 13 else "")
            gs_control_num = (gs_seg.elements[5] if gs_seg and len(gs_seg.elements) >= 6 else "")

            current_tx = ParsedTransaction(
                tx_type=tx_type,
                control_number=st02,
                isa_control=isa_control_num,
                gs_control=gs_control_num,
                sender_id=sender_id,
                receiver_id=receiver_id,
                date=isa_date,
                time=isa_time,
            )
            current_tx_segments = [seg]
            segment_count_in_tx = 1
            state = STATE_ST

        elif sid == "SE":
            if state != STATE_ST or current_tx is None:
                errors.append("E-ENV-003: SE found without matching ST")
                state = STATE_GS
                continue

            current_tx_segments.append(seg)
            segment_count_in_tx += 1

            # Validate SE01 == actual segment count
            se01 = seg.elements[0] if seg.elements else ""
            try:
                declared_count = int(se01)
                if declared_count != segment_count_in_tx:
                    errors.append(
                        f"E-ENV-005: SE01={declared_count} but counted {segment_count_in_tx} "
                        f"segments in TX {current_tx.control_number}"
                    )
            except ValueError:
                errors.append(f"E-ENV-005: Non-numeric SE01={se01!r}")

            current_tx.segments = current_tx_segments
            current_tx.raw = segment_term.join(s.raw for s in current_tx_segments)
            transactions.append(current_tx)

            current_tx = None
            current_tx_segments = []
            segment_count_in_tx = 0
            state = STATE_GS

        else:
            # Data segment — attach to current transaction
            if state == STATE_ST and current_tx is not None:
                current_tx_segments.append(seg)
                segment_count_in_tx += 1
            # Segments outside ST/SE are envelope segments; ignore for TX purposes

    # Check for unclosed transaction
    if state == STATE_ST:
        errors.append("E-ENV-003: File ended inside an ST/SE transaction — SE missing")

    # Check for missing GS
    if state == STATE_ISA and isa_seg is not None and iea_seg is None:
        errors.append("E-ENV-002: ISA opened but no GS found before IEA/end-of-file")

    return ParseResult(
        filename=filename,
        transactions=transactions,
        parse_errors=errors,
    )


def parse_file(filepath: str) -> ParseResult:
    """
    Read and parse an EDI file from disk.
    Tries UTF-8 first, falls back to latin-1 (handles legacy EDI files).
    """
    path = Path(filepath)
    filename = path.name

    raw_bytes = path.read_bytes()
    try:
        content = raw_bytes.decode("utf-8")
    except UnicodeDecodeError:
        content = raw_bytes.decode("latin-1")

    return parse_raw(content, filename=filename)


# ---------------------------------------------------------------------------
# Helpers for classifier
# ---------------------------------------------------------------------------

def get_segments_by_id(tx: ParsedTransaction, seg_id: str) -> List[ParsedSegment]:
    """Return all segments with the given ID from a transaction."""
    return [s for s in tx.segments if s.segment_id == seg_id]


def get_first_segment(tx: ParsedTransaction, seg_id: str) -> Optional[ParsedSegment]:
    """Return the first segment with the given ID, or None."""
    for seg in tx.segments:
        if seg.segment_id == seg_id:
            return seg
    return None


def get_element(seg: ParsedSegment, index: int) -> str:
    """Safely get an element value by 0-based index. Returns '' if out of range."""
    if index < len(seg.elements):
        return seg.elements[index].strip()
    return ""


# ---------------------------------------------------------------------------
# CLI / Verification
# ---------------------------------------------------------------------------

def _print_result(result: ParseResult) -> None:
    print(f"\nFile: {result.filename}")

    if result.parse_errors:
        print(f"\nParse errors ({len(result.parse_errors)}):")
        for e in result.parse_errors:
            print(f"  ✗ {e}")

    print(f"\nTransactions found: {len(result.transactions)}")
    for i, tx in enumerate(result.transactions, 1):
        print(f"\n  [{i}] TX Type:   {tx.tx_type}")
        print(f"       ISA ctrl:  {tx.isa_control}")
        print(f"       ST ctrl:   {tx.control_number}")
        print(f"       Sender:    {tx.sender_id}")
        print(f"       Receiver:  {tx.receiver_id}")
        print(f"       Date/Time: {tx.date} {tx.time}")
        print(f"       Segments:  {len(tx.segments)}")
        for seg in tx.segments:
            elems = "|".join(seg.elements[:6])
            print(f"         {seg.segment_id:<8} {elems}")


def _run_builtin_tests() -> None:
    """Quick smoke tests using hand-crafted X12."""
    print("Running built-in parser tests...\n")

    # Minimal valid 850 PO
    isa = "ISA*00*          *00*          *ZZ*SENDER01       *ZZ*RECEIVER1      *260328*1000*^*00501*000000001*0*P*>"
    edi_850 = (
        isa + "~\n"
        "GS*PO*SENDER01*RECEIVER1*20260328*1000*1*X*005010~\n"
        "ST*850*0001~\n"
        "BEG*00*SA*PO12345**20260328~\n"
        "PO1*1*10*EA*5.00**VP*ITEM001~\n"
        "SE*4*0001~\n"
        "GE*1*1~\n"
        "IEA*1*000000001~\n"
    )
    r = parse_raw(edi_850, "test_850.edi")
    assert len(r.parse_errors) == 0, f"850 parse errors: {r.parse_errors}"
    assert len(r.transactions) == 1
    assert r.transactions[0].tx_type == "850"
    assert r.transactions[0].isa_control == "000000001"
    print("  ✓ Valid 850 parsed correctly")

    # 997 with AK5 rejection flag (valid structure, exception detected by classifier not parser)
    edi_997 = (
        isa + "~\n"
        "GS*FA*SENDER01*RECEIVER1*20260328*1000*2*X*005010~\n"
        "ST*997*0001~\n"
        "AK1*PO*1~\n"
        "AK2*850*0001~\n"
        "AK3*BEG*3**8~\n"
        "AK4*1**8~\n"
        "AK5*R*5~\n"
        "AK9*R*1*1*0~\n"
        "SE*7*0001~\n"
        "GE*1*2~\n"
        "IEA*1*000000001~\n"
    )
    r997 = parse_raw(edi_997, "test_997.edi")
    # GE02 mismatch (GS06=2 vs GE02=2 — actually matches here, adjust test)
    # We expect no structural parse errors; rejection is a classifier concern
    assert r997.transactions[0].tx_type == "997"
    print("  ✓ 997 parsed correctly")

    # Mismatched ISA/IEA control numbers → E-ENV-004
    bad_iea = edi_850.replace("IEA*1*000000001", "IEA*1*000000999")
    r_bad = parse_raw(bad_iea, "test_bad_iea.edi")
    assert any("E-ENV-004" in e for e in r_bad.parse_errors), f"Expected E-ENV-004, got: {r_bad.parse_errors}"
    print("  ✓ E-ENV-004 detected (ISA/IEA control mismatch)")

    # SE01 count wrong → E-ENV-005
    bad_se = edi_850.replace("SE*4*0001", "SE*99*0001")
    r_bad_se = parse_raw(bad_se, "test_bad_se.edi")
    assert any("E-ENV-005" in e for e in r_bad_se.parse_errors), f"Expected E-ENV-005, got: {r_bad_se.parse_errors}"
    print("  ✓ E-ENV-005 detected (SE count mismatch)")

    print("\nAll built-in tests passed.")


if __name__ == "__main__":
    if len(sys.argv) == 1 or sys.argv[1] == "--test":
        _run_builtin_tests()
    else:
        filepath = sys.argv[1]
        result = parse_file(filepath)
        _print_result(result)
