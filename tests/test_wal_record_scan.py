"""Tests for tools/wal_record_scan.py (RE-001, node #94 0x51628f0).

Each test drives the model with a scripted buffered read returning
(status, code, fragment, aux) tuples, mirroring the evidence packet's
arms. Packet checks (verify.py, MANIFEST, excerpt regeneration) are
covered by test_packet_checks.
"""
import json
import subprocess
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))

from wal_record_scan import APPEND_CAP, LengthError, WalRecordScan
import wal_record_scan

ROOT = Path(__file__).resolve().parents[1]
PACKET = ROOT / "research/work-items/RE-001-wal-record-scan-94"


def scripted(rows):
    rows = list(rows)
    state = {"i": 0}

    def read(scan):
        row = rows[state["i"]]
        state["i"] += 1
        return row

    return read


class FakeStream:
    def __init__(self):
        self.finished = 0

    def finish(self):
        self.finished += 1


def test_status_zero_returns_zero_immediately():
    scan = WalRecordScan(entry_remaining=100)
    assert scan.scan(scripted([(0, 1, b"x", 0)])) == 0
    assert scan.out_record == b""


def test_stream_finish_prologue():
    stream = FakeStream()
    scan = WalRecordScan(entry_remaining=100, stream=stream)
    scan.scan(scripted([(0, 1, b"x", 0)]))
    assert stream.finished == 1
    assert scan.stream_finished is True


def test_no_stream_no_finish():
    scan = WalRecordScan(entry_remaining=100, stream=None)
    scan.scan(scripted([(0, 1, b"x", 0)]))
    assert scan.stream_finished is False


def test_full_record_fresh():
    scan = WalRecordScan(entry_remaining=77)
    status = scan.scan(scripted([(3, 1, b"hello", 0)]))
    assert status == 3
    assert scan.out_record == b"hello"
    assert scan.success_offset == 77
    assert scan.flag_71 is True
    assert scan.in_fragment is False
    assert scan.reports == []


def test_full_record_code_5_variant():
    scan = WalRecordScan(entry_remaining=10)
    assert scan.scan(scripted([(2, 5, b"v", 0)])) == 2
    assert scan.out_record == b"v"


def test_full_while_in_fragment_reports_partial_1():
    scan = WalRecordScan(entry_remaining=10)
    scan.scan(scripted([
        (1, 2, b"ab", 0),
        (1, 1, b"cd", 0),
    ]))
    assert scan.reports == [("partial record without end(1)", 2)]
    assert scan.out_record == b"cd"
    assert scan.accumulator == bytearray()
    assert scan.in_fragment is False


def test_full_while_in_fragment_empty_accumulator_no_report():
    scan = WalRecordScan(entry_remaining=10)
    scan.in_fragment = True
    scan.scan(scripted([(1, 1, b"z", 0)]))
    assert scan.reports == []
    assert scan.out_record == b"z"


def test_first_middle_last_assembly():
    scan = WalRecordScan(entry_remaining=42)
    status = scan.scan(scripted([
        (1, 6, b"aa", 0),
        (1, 7, b"bb", 0),
        (9, 8, b"cc", 0),
    ]))
    assert status == 9
    assert scan.out_record == b"aabbcc"
    assert scan.scratch == b"aabbcc"
    assert scan.success_offset == 42
    assert scan.flag_71 is True
    assert scan.accumulator == bytearray()
    assert scan.reports == []


def test_first_while_in_fragment_reports_partial_2():
    scan = WalRecordScan(entry_remaining=10)
    scan.scan(scripted([
        (1, 2, b"ab", 0),
        (1, 2, b"cd", 0),
        (1, 4, b"", 0),
    ]))
    assert scan.reports == [("partial record without end(2)", 2)]
    assert scan.out_record == b"cd"


def test_middle_without_start_reports_and_loops():
    scan = WalRecordScan(entry_remaining=10)
    scan.scan(scripted([
        (1, 3, b"xx", 0),
        (1, 1, b"ok", 0),
    ]))
    assert scan.reports == [("missing start of fragmented record(1)", 2)]
    assert scan.out_record == b"ok"


def test_last_without_start_reports_and_loops():
    scan = WalRecordScan(entry_remaining=10)
    scan.scan(scripted([
        (1, 4, b"xx", 0),
        (1, 1, b"ok", 0),
    ]))
    assert scan.reports == [("missing start of fragmented record(2)", 2)]
    assert scan.out_record == b"ok"


def test_middle_append_cap_raises():
    # The real cap is 0x3fffffffffffffff and cannot be materialised;
    # shrink it for this test via the module global the model reads.
    old = wal_record_scan.APPEND_CAP
    wal_record_scan.APPEND_CAP = 20
    try:
        scan = WalRecordScan(entry_remaining=10)
        scan.in_fragment = True
        scan.accumulator = bytearray(b"x" * 10)
        with pytest.raises(LengthError):
            scan.scan(scripted([(1, 3, b"y" * 11, 0)]))
    finally:
        wal_record_scan.APPEND_CAP = old


def test_middle_append_at_cap_boundary_ok():
    old = wal_record_scan.APPEND_CAP
    wal_record_scan.APPEND_CAP = 20
    try:
        scan = WalRecordScan(entry_remaining=10)
        scan.in_fragment = True
        scan.accumulator = bytearray(b"x" * 10)
        scan.scan(scripted([
            (1, 3, b"y" * 10, 0),
            (1, 4, b"", 0),
        ]))
        assert len(scan.out_record) == 20
    finally:
        wal_record_scan.APPEND_CAP = old


def test_compression_tag_zero_parses_but_does_not_set_in_fragment():
    # Regression control for slopbot's low_quality note on #1948: the
    # compression completion jumps to 0x5162aff, skipping the flag set
    # at 0x5162af8, so a following last fragment reports missing start.
    parsed = []
    scan = WalRecordScan(entry_remaining=55)
    scan.scan(scripted([
        (1, 9, b"\x00\x00\x00\x00BODY", 0),
        (1, 4, b"tail", 0),
        (1, 1, b"done", 0),
    ]), parser=lambda tag, rest: parsed.append((tag, rest)))
    assert parsed == [(0, b"BODY")]
    assert scan.parser_calls == [(0, b"BODY")]
    assert scan.in_fragment is False
    assert scan.reports == [("missing start of fragmented record(2)", 4)]
    assert scan.out_record == b"done"


def test_compression_then_middle_reports_missing_start():
    scan = WalRecordScan(entry_remaining=55)
    scan.scan(scripted([
        (1, 9, b"\x00\x00\x00\x00BODY", 0),
        (1, 3, b"mid", 0),
        (1, 1, b"done", 0),
    ]))
    assert scan.reports == [("missing start of fragmented record(1)", 3)]
    assert scan.in_fragment is False


def test_compression_tag_seven_parses():
    parsed = []
    scan = WalRecordScan(entry_remaining=55)
    scan.scan(scripted([
        (1, 9, b"\x07\x00\x00\x00ZZ", 0),
        (1, 1, b"done", 0),
    ]), parser=lambda tag, rest: parsed.append((tag, rest)))
    assert parsed == [(7, b"ZZ")]
    assert scan.reports == []


def test_compression_other_tag_reports_could_not_decode():
    scan = WalRecordScan(entry_remaining=55)
    scan.scan(scripted([
        (1, 9, b"\x03\x00\x00\x00ZZ", 0),
        (1, 1, b"done", 0),
    ]))
    # The slice was advanced past the 4-byte tag, so the reported value
    # is 6 - 4 = 2, not the original length.
    assert scan.reports == [("could not decode SetCompressionType record", 2)]
    assert scan.parser_calls == []


def test_compression_short_slice_reports_could_not_decode():
    scan = WalRecordScan(entry_remaining=55)
    scan.scan(scripted([
        (1, 9, b"\x00\x00", 0),
        (1, 1, b"done", 0),
    ]))
    assert scan.reports == [("could not decode SetCompressionType record", 2)]


def test_compression_warnings_both_fire_in_order():
    scan = WalRecordScan(entry_remaining=55, flag_73=True, flag_71=True)
    scan.scan(scripted([
        (1, 9, b"\x00\x00\x00\x00Q", 0),
        (1, 1, b"done", 0),
    ]))
    assert scan.reports[:2] == [
        ("read multiple SetCompressionType records", 5),
        ("SetCompressionType not the first record", 5),
    ]


def test_error_code_silent_when_not_in_fragment():
    scan = WalRecordScan(entry_remaining=10)
    scan.scan(scripted([
        (1, 11, b"e", 0),
        (1, 1, b"ok", 0),
    ]))
    assert scan.reports == []
    assert scan.out_record == b"ok"


def test_error_code_in_fragment_reports_and_clears():
    scan = WalRecordScan(entry_remaining=10)
    scan.scan(scripted([
        (1, 2, b"ab", 0),
        (1, 12, b"e", 0),
        (1, 1, b"ok", 0),
    ]))
    assert scan.reports == [("error in middle of record", 2)]
    assert scan.in_fragment is False
    assert scan.out_record == b"ok"


def test_checksum_with_flag_70_returns_zero_and_clears():
    scan = WalRecordScan(entry_remaining=10, flag_70=True)
    scan.in_fragment = True
    scan.accumulator = bytearray(b"ab")
    assert scan.scan(scripted([(1, 15, b"e", 99)])) == 0
    assert scan.accumulator == bytearray()
    assert scan.reports == []


def test_checksum_without_flag_70_reports_and_continues():
    scan = WalRecordScan(entry_remaining=10)
    scan.in_fragment = True
    scan.accumulator = bytearray(b"ab")
    scan.scan(scripted([
        (1, 15, b"e", 4242),
        (1, 1, b"ok", 0),
    ]))
    assert scan.reports == [
        ("checksum mismatch", 4242),
        ("error in middle of record", 2),
    ]
    assert scan.out_record == b"ok"


def test_unknown_code_formats_message():
    scan = WalRecordScan(entry_remaining=10)
    scan.scan(scripted([
        (1, 99, b"abcd", 0),
        (1, 1, b"ok", 0),
    ]))
    assert scan.reports == [("unknown record type 99", 4)]


def test_unknown_code_in_fragment_adds_accumulator_length():
    scan = WalRecordScan(entry_remaining=10)
    scan.scan(scripted([
        (1, 2, b"ab", 0),
        (1, 0, b"cde", 0),
        (1, 1, b"ok", 0),
    ]))
    # Regression control for slopbot's low_quality note on #1948: the
    # unknown arm joins the error tail at 0x5162a15, which clears the
    # accumulator and the flag, so the closing full record reports
    # nothing.
    assert scan.reports == [("unknown record type 0", 5)]


def test_unknown_clears_accumulator_and_flag():
    scan = WalRecordScan(entry_remaining=10)
    scan.scan(scripted([
        (1, 2, b"ab", 0),
        (1, 99, b"cde", 0),
        (1, 3, b"mid", 0),
        (1, 1, b"ok", 0),
    ]))
    assert scan.reports == [
        ("unknown record type 99", 5),
        ("missing start of fragmented record(1)", 3),
    ]
    assert scan.out_record == b"ok"


def test_unknown_code_14():
    scan = WalRecordScan(entry_remaining=10)
    scan.scan(scripted([
        (1, 14, b"xy", 0),
        (1, 1, b"ok", 0),
    ]))
    assert scan.reports == [("unknown record type 14", 2)]


def test_packet_checks():
    result = subprocess.run(
        [sys.executable, str(PACKET / "verify.py")],
        cwd=ROOT, capture_output=True, text=True, check=False)
    assert result.returncode == 0, result.stdout + result.stderr
    assert "ALL CHECKS PASSED" in result.stdout


def test_records_json_is_semantic_only():
    records = json.loads((PACKET / "records.json").read_text())
    assert "instructions" not in records
    assert "mnemonics" not in records
    assert records["window"]["start"] == "0x51628f0"
    assert "0x5162b88" in records["dispatch"]["table"]["9"]
