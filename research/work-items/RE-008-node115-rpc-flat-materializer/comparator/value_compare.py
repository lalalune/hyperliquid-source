"""Strict parent-side RPC frame parsing; no executable launch or value oracle.

Unexecuted draft pending root source/effects admission. Input expectations must
remain outside the child. Protocol syntax and semantic invariants are distinct.
"""
from dataclasses import dataclass
import re

MAX_BYTES = 16_777_216
MAX_RECORDS = 16_384
MAX_CAPACITY = 256
MAX_QUERIES = 32
U64_MAX = (1 << 64) - 1
ID_RE = re.compile(r"[A-Za-z0-9_-]{1,64}")
DECIMAL_RE = re.compile(r"0|[1-9][0-9]*")
HEX16_RE = re.compile(r"[0-9a-f]{16}")
HEX64_RE = re.compile(r"[0-9a-f]{64}")
HEX80_RE = re.compile(r"[0-9a-f]{80}")


class ProtocolError(ValueError):
    """Malformed representation, distinct from a well-formed wrong value."""


class AdmissionError(ValueError):
    """Inputs/expected data fail the parent comparator's admission."""


@dataclass(frozen=True)
class Frame:
    identifier: str
    operation: str
    capacity: int
    head: int
    live_len: int
    rows: tuple
    queries: tuple


@dataclass(frozen=True)
class Reply:
    fields: tuple
    tag: str
    logical: int | None = None
    physical: int | None = None
    insertion: int | None = None
    values: tuple = ()


def _lines(raw, label):
    if type(raw) is not bytes or not 0 < len(raw) <= MAX_BYTES:
        raise ProtocolError(label + ": empty or oversized byte stream")
    try:
        text = raw.decode("ascii")
    except UnicodeDecodeError as exc:
        raise ProtocolError(label + ": non-ASCII byte") from exc
    if "\r" in text or not text.endswith("\n"):
        raise ProtocolError(label + ": requires LF only and final LF")
    lines = text[:-1].split("\n")
    if not 1 <= len(lines) <= MAX_RECORDS or any(not line for line in lines):
        raise ProtocolError(label + ": invalid record count or empty record")
    return lines


def _uint(token, maximum, label):
    # Bound decimal length before int conversion; do not invoke huge-int parsing.
    if (not DECIMAL_RE.fullmatch(token) or
            len(token) > len(str(maximum))):
        raise ProtocolError(label + ": noncanonical or oversized decimal")
    value = int(token)
    if value > maximum:
        raise ProtocolError(label + ": integer outside permitted width")
    return value


def _hex_value(token, label):
    if not HEX16_RE.fullmatch(token):
        raise ProtocolError(label + ": requires exactly16 lowercase hex digits")
    return int(token, 16)


def parse_inputs(raw):
    frames = []
    seen = set()
    for ordinal, line in enumerate(_lines(raw, "input")):
        fields = line.split("\t")
        label = f"input row {ordinal}"
        if len(fields) != 7:
            raise ProtocolError(label + ": requires seven fields")
        identifier, operation, c_text, h_text, n_text, row_text, query_text = fields
        if not ID_RE.fullmatch(identifier) or identifier in seen:
            raise ProtocolError(label + ": invalid or duplicate ID")
        seen.add(identifier)
        if operation not in ("S", "M"):
            raise ProtocolError(label + ": invalid operation")
        capacity = _uint(c_text, MAX_CAPACITY, label + " capacity")
        head = _uint(h_text, MAX_CAPACITY, label + " head")
        live_len = _uint(n_text, MAX_CAPACITY, label + " live length")
        if live_len > capacity or (capacity == 0 and head != 0) or (capacity and head >= capacity):
            raise ProtocolError(label + ": invalid supplied header")
        if capacity == 0:
            if row_text != "-":
                raise ProtocolError(label + ": zero capacity requires '-' rows")
            rows = ()
        else:
            encoded_rows = row_text.split(",")
            if len(encoded_rows) != capacity or any(not HEX80_RE.fullmatch(row) for row in encoded_rows):
                raise ProtocolError(label + ": incomplete or malformed physical rows")
            rows = tuple((bytes.fromhex(row[:64]), int(row[64:], 16)) for row in encoded_rows)
        if query_text == "-":
            queries = ()
        else:
            encoded_queries = query_text.split(",")
            if not 1 <= len(encoded_queries) <= MAX_QUERIES or any(not HEX64_RE.fullmatch(q) for q in encoded_queries):
                raise ProtocolError(label + ": invalid query encoding/count")
            queries = tuple(bytes.fromhex(q) for q in encoded_queries)
        if operation == "S" and len(queries) != 1:
            raise ProtocolError(label + ": S requires exactly one query")
        # Validate the chosen supplied-input domain, not a lookup result.
        live = tuple(rows[(head + i) % capacity] for i in range(live_len))
        if any(value == 0 for _, value in live):
            raise ProtocolError(label + ": zero live value")
        if any(left[0] > right[0] for left, right in zip(live, live[1:])):
            raise ProtocolError(label + ": live keys are not nondecreasing")
        frames.append(Frame(identifier, operation, capacity, head, live_len, rows, queries))
    return tuple(frames)


def parse_outputs(raw, frames, label):
    lines = _lines(raw, label)
    if len(lines) != len(frames):
        raise ProtocolError(label + ": output record count differs from input")
    replies = []
    for ordinal, (line, frame) in enumerate(zip(lines, frames)):
        fields = tuple(line.split("\t"))
        at = f"{label} row {ordinal}"
        if len(fields) < 2 or fields[0] != frame.identifier:
            raise ProtocolError(at + ": ID differs from exact input order")
        tag = fields[1]
        if frame.operation == "S" and tag == "H" and len(fields) == 5:
            replies.append(Reply(fields, tag,
                                 logical=_uint(fields[2], U64_MAX, at + " logical"),
                                 physical=_uint(fields[3], U64_MAX, at + " physical"),
                                 values=(_hex_value(fields[4], at + " value"),)))
        elif frame.operation == "S" and tag == "N" and len(fields) == 3:
            replies.append(Reply(fields, tag, insertion=_uint(fields[2], U64_MAX, at + " insertion")))
        elif frame.operation == "M" and tag == "F" and len(fields) == 2:
            replies.append(Reply(fields, tag))
        elif frame.operation == "M" and tag == "V" and len(fields) == 3:
            if fields[2] == "-":
                values = ()
            else:
                encoded_values = fields[2].split(",")
                if not 1 <= len(encoded_values) <= MAX_QUERIES:
                    raise ProtocolError(at + ": V exceeds syntactic element limit")
                values = tuple(_hex_value(value, at + " V value") for value in encoded_values)
            replies.append(Reply(fields, tag, values=values))
        else:
            raise ProtocolError(at + ": invalid tag, operation association or field arity")
    return tuple(replies)


def semantic_violations(frame, reply):
    """Input-dependent invariants; never reclassify these as syntax failures."""
    violations = []
    if reply.tag == "H":
        if reply.logical >= frame.live_len:
            violations.append("logical_index_outside_live_length")
        if reply.physical >= frame.capacity:
            violations.append("physical_index_outside_capacity")
        if reply.values[0] == 0:
            violations.append("zero_found_value")
    elif reply.tag == "N":
        if reply.insertion > frame.live_len:
            violations.append("insertion_index_above_live_length")
    elif reply.tag == "V":
        if len(reply.values) != len(frame.queries):
            violations.append("materialized_length_differs_from_query_count")
        if any(value == 0 for value in reply.values):
            violations.append("zero_materialized_value")
    return violations


def prepare(inputs_raw, expected_raw):
    """Strictly admit input/expected files before interpreting child success."""
    try:
        frames = parse_inputs(inputs_raw)
        expected = parse_outputs(expected_raw, frames, "expected")
    except ProtocolError as exc:
        raise AdmissionError(str(exc)) from exc
    for frame, reply in zip(frames, expected):
        issues = semantic_violations(frame, reply)
        if issues:
            raise AdmissionError("expected " + frame.identifier + ": " + ",".join(issues))
    return frames, expected


def compare_prepared(frames, expected, actual_raw):
    """Caller must first establish completed child exit0 and retained evidence."""
    if len(frames) != len(expected):
        raise AdmissionError("prepared expected record count differs from input")
    try:
        actual = parse_outputs(actual_raw, frames, "actual")
    except ProtocolError as exc:
        return {"classification": "protocol_failure", "protocol_error": str(exc),
                "semantic_mismatch_count": None, "semantic_mismatches": []}
    mismatches = []
    for ordinal, (frame, wanted, observed) in enumerate(zip(frames, expected, actual)):
        issues = semantic_violations(frame, observed)
        if observed.fields != wanted.fields or issues:
            mismatches.append({"ordinal": ordinal, "id": frame.identifier,
                               "expected_fields": list(wanted.fields),
                               "actual_fields": list(observed.fields),
                               "semantic_invariant_violations": issues})
    return {"classification": "semantic_mismatch" if mismatches else "match",
            "records": len(frames), "semantic_mismatch_count": len(mismatches),
            "semantic_mismatches": mismatches}
