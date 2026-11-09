#!/usr/bin/env python3
"""Tests for tools/tracer_write115.py.

Every expectation is grounded in the node #115 binary
(work/hl-node-115.bin, SHA-256 a6e2897c...): the Write FDE
(0x61b1af0..0x61b1e18), the vendor census record
node115-vendor-61b1af0, the SetPayloadMap helper (0x61b18b0),
EncodeVarint32 (0x61bd410), ShouldSkipTrace (0x61b1930) and
WriteTrace (0x61b1a10) as modelled in the header/footer packet,
and WriteBatch::Clear (0x5fb7220) for the rep_ offset.  The binary
is never executed.
"""

import csv
import struct
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))

from tracer_write115 import (  # noqa: E402
    K_TRACE_WRITE,
    K_WRITE_BATCH_DATA,
    FakeClock,
    FakeWriter,
    LengthError_,
    Status,
    Tracer,
    _check_append,
    build_write_payload,
    encode_varint32,
    generate_cases,
    put_fixed64,
    set_payload_map,
)

TOOL = Path(__file__).resolve().parents[1] / "tools" / "tracer_write115.py"


def make_tracer(clock_value=0, **kwargs):
    kwargs.setdefault("writer", FakeWriter())
    return Tracer(FakeClock(clock_value), **kwargs)


class EncodeVarint32Tests(unittest.TestCase):
    def test_boundaries(self):
        # 0x61bd410 unrolls the 1/2/3/4/5-byte paths at 0x7f,
        # 0x3fff, 0x1fffff, 0xfffffff.
        cases = [
            (0, "00"),
            (1, "01"),
            (127, "7f"),
            (128, "8001"),
            (16383, "ff7f"),
            (16384, "808001"),
            (2097151, "ffff7f"),
            (2097152, "80808001"),
            (268435455, "ffffff7f"),
            (268435456, "8080808001"),
            (0xFFFFFFFF, "ffffffff0f"),
        ]
        for value, want in cases:
            self.assertEqual(encode_varint32(value).hex(), want,
                             hex(value))

    def test_length_is_ceil_bits_over_7(self):
        for value in [0, 127, 128, 16383, 16384, 2097151, 2097152,
                      268435455, 268435456, 0xFFFFFFFF]:
            n = max(1, (value.bit_length() + 6) // 7)
            self.assertEqual(len(encode_varint32(value)), n)

    def test_masks_to_32_bits(self):
        # The binary passes the size through r13d (low 32 bits)
        # before EncodeVarint32; the encoder itself masks too.
        self.assertEqual(encode_varint32(0x100000000),
                         encode_varint32(0))
        self.assertEqual(encode_varint32(0x1FFFFFFFF),
                         encode_varint32(0xFFFFFFFF))


class PayloadTests(unittest.TestCase):
    def test_empty_batch_payload(self):
        # PutFixed64(payload_map=2) + varint(0): 9 bytes.
        self.assertEqual(
            build_write_payload(b""),
            b"\x02\x00\x00\x00\x00\x00\x00\x00" + b"\x00",
        )

    def test_empty_write_batch_rep(self):
        # A fresh WriteBatch rep is the 12-byte header (8-byte
        # sequence + 4-byte count), all zero.
        self.assertEqual(
            build_write_payload(b"\x00" * 12),
            b"\x02\x00\x00\x00\x00\x00\x00\x00"
            + b"\x0c" + b"\x00" * 12,
        )

    def test_varint_length_prefix(self):
        # 127 bytes -> 1-byte varint; 128 bytes -> 2-byte varint.
        self.assertEqual(build_write_payload(b"a" * 127)[8:9], b"\x7f")
        self.assertEqual(build_write_payload(b"a" * 128)[8:10],
                         b"\x80\x01")
        self.assertEqual(len(build_write_payload(b"a" * 128)),
                         8 + 2 + 128)

    def test_put_fixed64(self):
        self.assertEqual(put_fixed64(b"", 2),
                         b"\x02\x00\x00\x00\x00\x00\x00\x00")
        self.assertEqual(put_fixed64(b"", 0x0102030405060708),
                         struct.pack("<Q", 0x0102030405060708))

    def test_length_guard(self):
        # The guard itself; reaching it through the payload
        # builder would need a >2^62-byte string, so the guard is
        # tested directly (as in the header/footer packet).
        with self.assertRaises(LengthError_):
            _check_append(0x3FFFFFFFFFFFFFFF, 8)


class WriteTests(unittest.TestCase):
    def test_golden_empty_batch_record(self):
        # clock 0, empty batch: ts 8x00, type 03, payload-len 9,
        # payload = PutFixed64(2) + varint(0).  22 bytes total.
        tr = make_tracer(clock_value=0)
        self.assertTrue(tr.write(b"").ok())
        self.assertEqual(tr.clock.calls, 1)
        self.assertEqual(
            tr.writer.written[0],
            b"\x00" * 8 + b"\x03" + struct.pack("<I", 9)
            + b"\x02\x00\x00\x00\x00\x00\x00\x00" + b"\x00",
        )
        self.assertEqual(len(tr.writer.written[0]), 22)

    def test_trace_fields(self):
        # build_write_trace returns None on skip; otherwise the
        # Trace has type 3, payload_map 2 (SetPayloadMap bit 1).
        tr = make_tracer(clock_value=42)
        trace = tr.build_write_trace(b"\x00" * 12)
        self.assertIsNotNone(trace)
        self.assertEqual(trace.timestamp, 42)
        self.assertEqual(trace.type, K_TRACE_WRITE)
        self.assertEqual(trace.payload_map, 2)
        self.assertEqual(trace.payload, build_write_payload(b"\x00" * 12))

    def test_flag_skip_returns_ok_without_clock_or_writer(self):
        # ShouldSkipTrace (0x61b1930): Write's flag bit is 0x02;
        # a set bit skips at once (counter untouched), the clock is
        # never consulted and nothing is written.
        tr = make_tracer(clock_value=7, sampling_period=3,
                         skip_flags=0x02)
        self.assertTrue(tr.write(b"abc").ok())
        self.assertEqual(tr.clock.calls, 0)
        self.assertEqual(tr.writer.write_calls, 0)
        self.assertEqual(tr.counter, 0)

    def test_file_size_gate(self):
        # helper 0x61b1910: GetFileSize() > max -> skip; equal -> record.
        tr = make_tracer(max_trace_file_size=100, sampling_period=1,
                         writer=FakeWriter(file_size=100))
        self.assertTrue(tr.write(b"abc").ok())
        self.assertEqual(len(tr.writer.written), 1)
        tr = make_tracer(max_trace_file_size=100, sampling_period=1,
                         writer=FakeWriter(file_size=101))
        self.assertTrue(tr.write(b"abc").ok())
        self.assertEqual(len(tr.writer.written), 0)
        self.assertEqual(tr.clock.calls, 0)

    def test_sampling_sequence(self):
        # Period 3, counter 0: skip, skip, record, skip, skip, record.
        tr = make_tracer(sampling_period=3)
        got = []
        for _ in range(6):
            tr.write(b"x")
            got.append(len(tr.writer.written))
        self.assertEqual(got, [0, 0, 1, 1, 1, 2])
        self.assertEqual(tr.counter, 0)

    def test_writer_error_propagates(self):
        # WriteTrace's Status is forwarded unchanged.
        err = Status(2, b"disk full")
        tr = make_tracer(writer=FakeWriter(write_status=err))
        self.assertEqual(tr.write(b"abc"), err)
        self.assertEqual(len(tr.writer.written), 1)

    def test_clock_called_once_per_record(self):
        tr = make_tracer(clock_value=99)
        tr.write(b"a")
        tr.write(b"b")
        self.assertEqual(tr.clock.calls, 2)
        self.assertEqual(len(tr.writer.written), 2)
        self.assertEqual(tr.writer.written[0][8], 3)
        self.assertEqual(tr.writer.written[1][8], 3)

    def test_set_payload_map_bit_1(self):
        # 0x61b18b0: bts sets bit `type`; Write passes
        # kWriteBatchData (1), so the map becomes 2.
        self.assertEqual(set_payload_map(0, K_WRITE_BATCH_DATA), (2, True))
        self.assertEqual(set_payload_map(2, K_WRITE_BATCH_DATA), (2, False))


class CasesTests(unittest.TestCase):
    def _replay(self, kind, inp, want):
        if kind == "write":
            parts = inp.split("|")
            err = None
            steps = 1
            if parts[-1].startswith("err="):
                err = int(parts[-1][4:])
                parts = parts[:-1]
            if parts[-1].startswith("steps="):
                steps = int(parts[-1][6:])
                parts = parts[:-1]
            (clock, flags, period, max_size, fsize, counter0) = \
                map(int, parts[:6])
            data = bytes.fromhex(parts[6])
            tr = Tracer(FakeClock(clock), max_trace_file_size=max_size,
                        sampling_period=period, skip_flags=flags,
                        writer=FakeWriter(
                            file_size=fsize,
                            write_status=(Status(err, b"disk full")
                                          if err is not None else None)))
            tr.counter = counter0
            if err is not None:
                status = tr.write(data)
                self.assertEqual(
                    want,
                    f"STATUS|{status.code}|{status.message.hex()}")
                return
            pattern = []
            for _ in range(steps):
                before = len(tr.writer.written)
                status = tr.write(data)
                self.assertTrue(status.ok())
                pattern.append(
                    "R" if len(tr.writer.written) > before else "S")
            if steps > 1:
                self.assertEqual(
                    want, f"{','.join(pattern)}|{tr.counter}")
            elif pattern[0] == "S":
                self.assertEqual(want, f"SKIP|{tr.clock.calls}")
            else:
                self.assertEqual(want, tr.writer.written[0].hex())
        elif kind == "write_payload":
            data = bytes.fromhex(inp)
            self.assertEqual(want, build_write_payload(data).hex())
        elif kind == "encode_varint32":
            self.assertEqual(want, encode_varint32(int(inp)).hex())
        else:
            self.fail(f"unknown kind {kind}")

    def test_all_committed_cases_replay(self):
        cases_path = (
            Path(__file__).resolve().parents[1] / "research" / "work-items"
            / "re-002-node115-tracer-write-115" / "cases.tsv"
        )
        with open(cases_path) as fh:
            rows = list(csv.DictReader(fh, delimiter="\t"))
        self.assertEqual(len(rows), 2400)
        for row in rows:
            with self.subTest(kind=row["kind"], inp=row["input"][:40]):
                self._replay(row["kind"], row["input"], row["want"])

    def test_generator_reproduces_committed_cases(self):
        # The committed cases.tsv is exactly what the seeded
        # generator produces (no hand edits).
        cases_path = (
            Path(__file__).resolve().parents[1] / "research" / "work-items"
            / "re-002-node115-tracer-write-115" / "cases.tsv"
        )
        with open(cases_path) as fh:
            committed = fh.read()
        lines = ["kind\tinput\twant"]
        for kind, inp, want in generate_cases():
            lines.append(f"{kind}\t{inp}\t{want}")
        self.assertEqual(committed, "\n".join(lines) + "\n")


if __name__ == "__main__":
    unittest.main()
