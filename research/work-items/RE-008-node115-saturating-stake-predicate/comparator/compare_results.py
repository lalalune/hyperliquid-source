#!/usr/bin/env python3
"""Parent-only comparison of retained stake-driver result streams.

No process is launched. The caller supplies the independently recorded child
exit code and raw stdout/stderr. Expectations never become driver inputs.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import sys

HOST_CONTRACT_SHA256 = "4bb6a164423609b2310b7952351be5e88f8583d205b1ec144e9393cfde92a28e"
U64_MAX = (1 << 64) - 1
MAX_ROWS = 8192
# 64-byte ID + four tabs + "ok" + two 20-digit sums + boolean + LF.
MAX_OUTPUT_BYTES = MAX_ROWS * 112
ID = re.compile(rb"[A-Za-z0-9_-]{1,64}\Z")
DECIMAL = re.compile(rb"(?:0|[1-9][0-9]{0,19})\Z")
SHA256 = re.compile(r"[0-9a-f]{64}\Z")
# (id bytes, status, selected_sum, total_sum, passes); refusals have None fields.
Row = tuple[bytes, str, int | None, int | None, int | None]


class FormatError(ValueError):
    def __init__(self, reason: str, line: int | None = None):
        super().__init__(reason)
        self.reason = reason
        self.line = line


class ArtifactError(ValueError):
    def __init__(self, reason: str, role: str):
        super().__init__(reason)
        self.reason = reason
        self.role = role


def parse_u64(field: bytes, line: int) -> int:
    # Check length/grammar before int(): never accept signs, whitespace or
    # alternative encodings, and never parse an unbounded digit string.
    if DECIMAL.fullmatch(field) is None:
        raise FormatError("noncanonical_u64", line)
    value = int(field)
    if value > U64_MAX:
        raise FormatError("u64_overflow", line)
    return value


def parse_output(data: bytes) -> tuple[Row, ...]:
    """Parse only result grammar, never the stake relation or an expected value."""
    if type(data) is not bytes:
        raise TypeError("result stream must be bytes")
    if len(data) > MAX_OUTPUT_BYTES:
        raise FormatError("output_byte_limit")
    if not data:
        return ()
    if not data.endswith(b"\n"):
        raise FormatError("missing_final_lf")
    if any(byte > 127 for byte in data):
        raise FormatError("non_ascii")
    if b"\r" in data or b"\x00" in data:
        raise FormatError("forbidden_byte")
    lines = data.split(b"\n")[:-1]
    if len(lines) > MAX_ROWS:
        raise FormatError("record_limit")
    seen: set[bytes] = set()
    rows: list[Row] = []
    for number, raw in enumerate(lines, 1):
        if not raw:
            raise FormatError("blank_line", number)
        fields = raw.split(b"\t")
        if ID.fullmatch(fields[0]) is None:
            raise FormatError("invalid_id", number)
        ident = fields[0]
        if ident in seen:
            raise FormatError("duplicate_id", number)
        seen.add(ident)
        if len(fields) < 2:
            raise FormatError("field_count", number)
        status = fields[1]
        if status == b"ok":
            if len(fields) != 5:
                raise FormatError("field_count", number)
            selected = parse_u64(fields[2], number)
            total = parse_u64(fields[3], number)
            if fields[4] not in (b"0", b"1"):
                raise FormatError("invalid_boolean", number)
            rows.append((ident, "ok", selected, total, int(fields[4])))
        elif status in (b"bounds", b"order"):
            if len(fields) != 2:
                raise FormatError("field_count", number)
            rows.append((ident, status.decode("ascii"), None, None, None))
        else:
            raise FormatError("invalid_status", number)
    return tuple(rows)


def failure(reason: str, **details: object) -> dict:
    return {"kind": "qualification_failure", "reason": reason, **details}


def value(row: Row) -> dict:
    result = {"status": row[1]}
    if row[1] == "ok":
        result.update(selected_sum=row[2], total_sum=row[3], passes=row[4])
    return result


def compare_bytes(
    expected: bytes, actual: bytes, process_exit: int, stderr: bytes
) -> dict:
    """Compare one completed invocation, without executing or querying a driver.

    Precedence: invalid caller types; expected grammar; child process/stderr;
    actual grammar; row count; ID identity/order; finally semantic values.
    """
    if type(process_exit) is not int:
        return failure("invalid_process_exit")
    if type(stderr) is not bytes:
        return failure("invalid_stderr_type")
    if type(expected) is not bytes or type(actual) is not bytes:
        return failure("invalid_stream_type")
    try:
        wanted = parse_output(expected)
    except FormatError as error:
        return failure("expected_format", format_reason=error.reason, line=error.line)
    if process_exit != 0 or stderr:
        return failure(
            "process_failure",
            process_exit=process_exit,
            stderr_nonempty=bool(stderr),
            expected_rows=len(wanted),
        )
    try:
        got = parse_output(actual)
    except FormatError as error:
        reason = "duplicate_rows" if error.reason == "duplicate_id" else "actual_format"
        return failure(reason, format_reason=error.reason, line=error.line)
    counts = {"expected_rows": len(wanted), "actual_rows": len(got)}
    if len(got) < len(wanted):
        return failure("missing_rows", missing=len(wanted) - len(got), **counts)
    if len(got) > len(wanted):
        return failure("extra_rows", extra=len(got) - len(wanted), **counts)
    expected_ids = [row[0] for row in wanted]
    actual_ids = [row[0] for row in got]
    if actual_ids != expected_ids:
        reason = "id_order" if set(actual_ids) == set(expected_ids) else "id_identity"
        index = next(i for i, pair in enumerate(zip(expected_ids, actual_ids))
                     if pair[0] != pair[1])
        return failure(
            reason,
            first_row=index,
            expected_id=expected_ids[index].decode("ascii"),
            actual_id=actual_ids[index].decode("ascii"),
            **counts,
        )
    mismatch_count = 0
    examples = []
    for index, (left, right) in enumerate(zip(wanted, got)):
        if left[1:] != right[1:]:
            mismatch_count += 1
            if len(examples) < 8:
                examples.append({
                    "row": index,
                    "id": left[0].decode("ascii"),
                    "expected": value(left),
                    "actual": value(right),
                })
    if mismatch_count:
        return {
            "kind": "value_mismatch",
            "reason": "different_values",
            "mismatch_count": mismatch_count,
            "examples": examples,
            **counts,
        }
    return {"kind": "match", "mismatch_count": 0, **counts}


def verify_digest(data: bytes, pin: str, role: str) -> None:
    """Small exact-buffer admission helper used by synthetic controls."""
    if SHA256.fullmatch(pin) is None:
        raise ArtifactError("invalid_sha256", role)
    if hashlib.sha256(data).hexdigest() != pin:
        raise ArtifactError("digest_mismatch", role)


def read_pinned(path: Path, pin: str, role: str, keep: int) -> tuple[bytes, dict]:
    """Hash one opened regular file; retain only a bounded prefix.

    The stdout/expected prefix includes one byte beyond the grammar maximum so
    oversize output cannot become a truncated apparent match. Stderr needs only
    a nonempty witness. Its entire raw file is still hashed against the pin.
    """
    if SHA256.fullmatch(pin) is None:
        raise ArtifactError("invalid_sha256", role)
    digest = hashlib.sha256()
    length = 0
    prefix = bytearray()
    with path.open("rb") as stream:
        if not stat.S_ISREG(os.fstat(stream.fileno()).st_mode):
            raise ArtifactError("not_regular_file", role)
        while chunk := stream.read(1024 * 1024):
            digest.update(chunk)
            length += len(chunk)
            remaining = keep - len(prefix)
            if remaining > 0:
                prefix.extend(chunk[:remaining])
    observed = digest.hexdigest()
    if observed != pin:
        raise ArtifactError("digest_mismatch", role)
    return bytes(prefix), {"sha256": observed, "bytes": length}


def outcome_exit(result: dict) -> int:
    if result["kind"] == "match":
        return 0
    if result["kind"] == "value_mismatch":
        return 1
    return 2


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, allow_abbrev=False)
    for role in ("expected", "actual", "stderr"):
        parser.add_argument("--" + role, type=Path, required=True)
        parser.add_argument("--" + role + "-sha256", required=True)
    parser.add_argument("--exit-code", type=int, required=True)
    args = parser.parse_args(argv)
    try:
        expected, expected_meta = read_pinned(
            args.expected, args.expected_sha256, "expected", MAX_OUTPUT_BYTES + 1
        )
        actual, actual_meta = read_pinned(
            args.actual, args.actual_sha256, "actual", MAX_OUTPUT_BYTES + 1
        )
        stderr, stderr_meta = read_pinned(
            args.stderr, args.stderr_sha256, "stderr", 1
        )
        result = compare_bytes(expected, actual, args.exit_code, stderr)
        result["artifacts"] = {
            "expected": expected_meta, "actual": actual_meta, "stderr": stderr_meta
        }
    except ArtifactError as error:
        result = failure("artifact_admission", artifact=error.role, detail=error.reason)
    except OSError as error:
        # Do not echo local filenames or synthesize these diagnostics as child stderr.
        result = failure("artifact_io", exception=type(error).__name__, errno=error.errno)
    result["schema"] = "stake-parent-result-comparison-v1"
    result["host_contract_sha256"] = HOST_CONTRACT_SHA256
    result["process_exit_is_caller_recorded_not_measured_here"] = True
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    return outcome_exit(result)


if __name__ == "__main__":
    sys.exit(main())

