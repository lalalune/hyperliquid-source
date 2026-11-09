#!/usr/bin/env python3
"""Tests for tools/tracer_header_footer115.py.

Every expectation is grounded in the node #115 binary
(work/hl-node-115.bin, SHA-256 a6e2897c...): the four FDEs
(ShouldSkipTrace 0x61b1930, WriteTrace 0x61b1a10, WriteFooter
0x61b35c0, WriteHeader 0x61b3860), the constructor 0x61b3e60, and
the vendor census records node115-vendor-61b1930/61b1a10/61b35c0/
61b3860.  The binary is never executed.
"""

import csv
import struct
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))

from tracer_header_footer115 import (  # noqa: E402
    MAGIC,
    FakeClock,
    FakeWriter,
    LengthError_,
    Status,
    Trace,
    Tracer,
    _check_append,
    encode_trace,
    generate_cases,
    header_payload,
    set_payload_map,
)

TOOL = Path(__file__).resolve().parents[1] / "tools" / "tracer_header_footer115.py"


def make_tracer(clock_value=0, **kwargs):
    kwargs.setdefault("writer", FakeWriter())
    return Tracer(FakeClock(clock_value), **kwargs)


class HeaderPayloadTests(unittest.TestCase):
    def test_golden_90_bytes(self):
        self.assertEqual(
            header_payload(),
            b"feedcafedeadbeef\tTrace Version: 0.2\t"
            b"RocksDB Version: 8.1\t"
            b"Format: Timestamp OpType Payload\n",
        )
        self.assertEqual(len(header_payload()), 90)

    def test_payload_splits_like_parse_trace_header(self):
        # The consumer (ParseTraceHeader, 0x61b4840) splits on TAB
        # into three fields and reads field[1][15:] / field[2][17:].
        fields = header_payload().split(b"\t")
        self.assertEqual(fields[0], MAGIC)
        self.assertEqual(fields[1][15:], b"0.2")
        self.assertEqual(fields[2][17:], b"8.1")
        self.assertEqual(fields[3], b"Format: Timestamp OpType Payload\n")

    def test_version_digits(self):
        # The four version ints are immediates in the binary:
        # operator<<(int) with 0, 2, 8, 1.
        self.assertIn(b"Trace Version: 0.2\t", header_payload())
        self.assertIn(b"RocksDB Version: 8.1\t", header_payload())


class EncodeTraceTests(unittest.TestCase):
    def test_layout(self):
        data = encode_trace(Trace(0x0102030405060708, 1, 0, b"abc"))
        self.assertEqual(
            data,
            struct.pack("<Q", 0x0102030405060708) + b"\x01"
            + struct.pack("<I", 3) + b"abc",
        )

    def test_empty_payload(self):
        data = encode_trace(Trace(0, 2, 0, b""))
        self.assertEqual(data, b"\x00" * 8 + b"\x02" + b"\x00" * 4)

    def test_capacity_guard(self):
        with self.assertRaises(LengthError_):
            _check_append(0x3FFFFFFFFFFFFFFF, 8)


class ShouldSkipTraceTests(unittest.TestCase):
    def test_file_size_gate(self):
        # helper 0x61b1910: GetFileSize() > max -> skip; equal -> record.
        tr = make_tracer(max_trace_file_size=100, sampling_period=1,
                         writer=FakeWriter(file_size=100))
        self.assertFalse(tr.should_skip_trace(3))
        tr = make_tracer(max_trace_file_size=100, sampling_period=1,
                         writer=FakeWriter(file_size=101))
        self.assertTrue(tr.should_skip_trace(3))

    def test_type_to_mask_mapping(self):
        # Jump table at .rodata 0x97c5f4: 3->0x02, 4->0x01, 5->0x04,
        # 6->0x08, 13->0x10; a set bit skips at once (counter untouched).
        cases = [(3, 0x02), (4, 0x01), (5, 0x04), (6, 0x08), (13, 0x10)]
        for typ, bit in cases:
            tr = make_tracer(sampling_period=1, skip_flags=bit)
            self.assertTrue(tr.should_skip_trace(typ))
            self.assertEqual(tr.counter, 0)
            tr = make_tracer(sampling_period=1, skip_flags=0)
            self.assertFalse(tr.should_skip_trace(typ))

    def test_types_without_flag_test(self):
        # Types 0, 1, 2, 7..12 and >= 14 go straight to the sampling
        # counter: even with every flag bit set they are not skipped
        # by the flag test (period 1 records them).
        for typ in [0, 1, 2, 7, 8, 9, 10, 11, 12, 14, 15, 255]:
            tr = make_tracer(sampling_period=1, skip_flags=0x1F)
            self.assertFalse(tr.should_skip_trace(typ))

    def test_sampling_sequence_period_3(self):
        tr = make_tracer(sampling_period=3)
        got = [tr.should_skip_trace(7) for _ in range(6)]
        self.assertEqual(got, [True, True, False, True, True, False])
        self.assertEqual(tr.counter, 0)

    def test_period_zero_and_one_record_everything(self):
        for period in (0, 1):
            tr = make_tracer(sampling_period=period)
            self.assertEqual(
                [tr.should_skip_trace(7) for _ in range(3)],
                [False, False, False],
            )

    def test_counter_is_shared_across_types(self):
        tr = make_tracer(sampling_period=3)
        self.assertTrue(tr.should_skip_trace(3))   # counter 1
        self.assertTrue(tr.should_skip_trace(7))   # counter 2
        self.assertFalse(tr.should_skip_trace(13))  # counter 3 -> record

    def test_flag_skip_does_not_advance_counter(self):
        tr = make_tracer(sampling_period=3, skip_flags=0x02)
        self.assertTrue(tr.should_skip_trace(3))
        self.assertEqual(tr.counter, 0)
        self.assertTrue(tr.should_skip_trace(7))  # counter 1
        self.assertEqual(tr.counter, 1)

    def test_counter_wraps_at_2_to_64(self):
        tr = make_tracer(sampling_period=10)
        tr.counter = (1 << 64) - 1
        self.assertTrue(tr.should_skip_trace(7))
        self.assertEqual(tr.counter, 0)


class WriteTraceTests(unittest.TestCase):
    def test_writer_receives_encoded_record(self):
        tr = make_tracer()
        status = tr.write_trace(Trace(42, 1, 0, b"feedcafedeadbeef"))
        self.assertTrue(status.ok())
        self.assertEqual(len(tr.writer.written), 1)
        self.assertEqual(
            tr.writer.written[0],
            struct.pack("<Q", 42) + b"\x01" + struct.pack("<I", 16)
            + b"feedcafedeadbeef",
        )

    def test_writer_error_propagates(self):
        err = Status(2, b"disk full")
        tr = make_tracer(writer=FakeWriter(write_status=err))
        self.assertEqual(tr.write_trace(Trace(0, 2, 0, b"")), err)


class SetPayloadMapTests(unittest.TestCase):
    def test_sets_bit_and_reports_change(self):
        # 0x61b18b0: bts sets bit `type` in the map word and returns
        # whether it changed (setne).
        self.assertEqual(set_payload_map(0, 0), (1, True))
        self.assertEqual(set_payload_map(1, 0), (1, False))
        self.assertEqual(set_payload_map(0, 3), (8, True))
        self.assertEqual(set_payload_map(0b101, 1), (0b111, True))

    def test_footer_trace_has_payload_map_one(self):
        # WriteFooter calls SetPayloadMap(map, kEmptyPayload=0), so
        # the in-memory footer Trace has payload_map 1 -- but
        # EncodeTrace never serializes payload_map, so the record on
        # disk is still 13 bytes (ts 8 + type 1 + length 0).
        tr = make_tracer(clock_value=99)
        trace = tr.build_footer_trace()
        self.assertEqual(trace.payload_map, 1)
        self.assertEqual(trace.type, 2)
        self.assertEqual(trace.payload, b"")
        self.assertTrue(tr.write_footer().ok())
        self.assertEqual(
            tr.writer.written[0],
            struct.pack("<Q", 99) + b"\x02" + struct.pack("<I", 0),
        )
        self.assertEqual(len(tr.writer.written[0]), 13)


class HeaderFooterTests(unittest.TestCase):
    def test_write_header_record(self):
        tr = make_tracer(clock_value=1700000000000000)
        self.assertTrue(tr.write_header().ok())
        self.assertEqual(tr.clock.calls, 1)
        self.assertEqual(
            tr.writer.written[0],
            struct.pack("<Q", 1700000000000000) + b"\x01"
            + struct.pack("<I", 90) + header_payload(),
        )

    def test_write_footer_record(self):
        tr = make_tracer(clock_value=99)
        self.assertTrue(tr.write_footer().ok())
        self.assertEqual(tr.clock.calls, 1)
        self.assertEqual(
            tr.writer.written[0],
            struct.pack("<Q", 99) + b"\x02" + struct.pack("<I", 0),
        )

    def test_header_then_footer_share_the_writer(self):
        tr = make_tracer(clock_value=7)
        tr.write_header()
        tr.write_footer()
        self.assertEqual(len(tr.writer.written), 2)
        self.assertEqual(tr.writer.written[0][8], 1)  # kTraceBegin
        self.assertEqual(tr.writer.written[1][8], 2)  # kTraceEnd


class CasesTests(unittest.TestCase):
    def _replay(self, kind, inp, want):
        if kind == "should_skip":
            parts = inp.split("|")
            steps = 1
            if len(parts) == 7 and parts[6].startswith("steps="):
                steps = int(parts[6][6:])
                parts = parts[:6]
            t, flags, period, max_size, fsize, counter0 = map(int, parts)
            tr = Tracer(FakeClock(), max_trace_file_size=max_size,
                        sampling_period=period, skip_flags=flags,
                        writer=FakeWriter(file_size=fsize))
            tr.counter = counter0
            pattern = []
            for _ in range(steps):
                pattern.append("1" if tr.should_skip_trace(t) else "0")
            got = f"{','.join(pattern)}|{tr.counter}" if steps > 1 \
                else f"{pattern[0]}|{tr.counter}"
            self.assertEqual(got, want)
        elif kind == "write_trace":
            parts = inp.split("|")
            err = None
            if len(parts) == 4 and parts[3].startswith("err="):
                err = int(parts[3][4:])
                parts = parts[:3]
            ts, typ, payload = int(parts[0]), int(parts[1]), \
                bytes.fromhex(parts[2])
            if err is not None:
                status = Status(err, b"disk full")
                tr = Tracer(FakeClock(), writer=FakeWriter(write_status=status))
                got_status = tr.write_trace(Trace(ts, typ, 0, payload))
                self.assertEqual(
                    want, f"STATUS|{got_status.code}|"
                    f"{got_status.message.hex()}")
            else:
                tr = Tracer(FakeClock(), writer=FakeWriter())
                tr.write_trace(Trace(ts, typ, 0, payload))
                self.assertEqual(want, tr.writer.written[0].hex())
        elif kind in ("write_header", "write_footer"):
            tr = Tracer(FakeClock(int(inp)), writer=FakeWriter())
            if kind == "write_header":
                tr.write_header()
            else:
                tr.write_footer()
            self.assertEqual(want, tr.writer.written[0].hex())
        else:
            self.fail(f"unknown kind {kind}")

    def test_all_committed_cases_replay(self):
        cases_path = (
            Path(__file__).resolve().parents[1] / "research" / "work-items"
            / "re-002-node115-tracer-header-footer-115" / "cases.tsv"
        )
        with open(cases_path) as fh:
            rows = list(csv.DictReader(fh, delimiter="\t"))
        self.assertEqual(len(rows), 2400)
        for row in rows:
            with self.subTest(kind=row["kind"], input=row["input"][:40]):
                self._replay(row["kind"], row["input"], row["want"])

    def test_regeneration_matches(self):
        self.assertEqual(len(generate_cases()), 2400)


if __name__ == "__main__":
    unittest.main()
