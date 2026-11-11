#!/usr/bin/env python3
"""Tests for tools/tracer_iterator_seek_for_prev115.py.

Every expectation is grounded in the node #115 binary
(work/hl-node-115.bin, SHA-256 a6e2897c...): the IteratorSeekForPrev FDE
(0x61b2760..0x61b2ca8), the vendor census record
node115-vendor-61b2760, the SetPayloadMap helper (0x61b18b0),
EncodeVarint32 (0x61bd410), ShouldSkipTrace (0x61b1930) and
WriteTrace (0x61b1a10) as modelled in the header/footer packet.
The CF id is the uint32_t the caller passes by reference.  The
binary is never executed.
"""

import csv
import struct
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))

from tracer_iterator_seek_for_prev115 import (  # noqa: E402
    K_ITER_CF_ID,
    K_ITER_KEY,
    K_ITER_LOWER_BOUND,
    K_ITER_UPPER_BOUND,
    K_TRACE_ITERATOR_SEEK_FOR_PREV,
    FakeClock,
    FakeWriter,
    LengthError_,
    Status,
    Tracer,
    _check_append,
    build_iterator_seek_for_prev_payload,
    encode_varint32,
    generate_cases,
    put_fixed32,
    put_fixed64,
    set_payload_map,
)

TOOL = Path(__file__).resolve().parents[1] / "tools" / "tracer_iterator_seek_for_prev115.py"


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
        # The binary passes the size through esi (a 32-bit load)
        # before EncodeVarint32; the encoder itself masks too.
        self.assertEqual(encode_varint32(0x100000000),
                         encode_varint32(0))
        self.assertEqual(encode_varint32(0x1FFFFFFFF),
                         encode_varint32(0xFFFFFFFF))


class PayloadTests(unittest.TestCase):
    def test_empty_bounds_payload(self):
        # PutFixed64(payload_map=48) + PutFixed32(0) + varint(0):
        # 13 bytes; empty bounds append nothing and set no bits.
        self.assertEqual(
            build_iterator_seek_for_prev_payload(0, b""),
            b"\x30\x00\x00\x00\x00\x00\x00\x00"
            + b"\x00\x00\x00\x00" + b"\x00",
        )

    def test_realistic_seek_payload(self):
        # CF 0, key "key", lower "lo", upper "hi": map 240, cf id 0,
        # varint(3) + "key", varint(2) + "lo", varint(2) + "hi".
        self.assertEqual(
            build_iterator_seek_for_prev_payload(0, b"key", b"lo", b"hi"),
            b"\xf0\x00\x00\x00\x00\x00\x00\x00"
            + b"\x00\x00\x00\x00" + b"\x03" + b"key"
            + b"\x02" + b"lo" + b"\x02" + b"hi",
        )

    def test_bound_bits_follow_emptiness(self):
        # Lower only -> map 112 (0x70); upper only -> map 176 (0xb0);
        # neither -> 48; both -> 240.
        self.assertEqual(
            build_iterator_seek_for_prev_payload(0, b"k", b"lo", b"")[:8],
            b"\x70\x00\x00\x00\x00\x00\x00\x00")
        self.assertEqual(
            build_iterator_seek_for_prev_payload(0, b"k", b"", b"hi")[:8],
            b"\xb0\x00\x00\x00\x00\x00\x00\x00")
        self.assertEqual(
            build_iterator_seek_for_prev_payload(0, b"k", b"lo", b"hi")[:8],
            b"\xf0\x00\x00\x00\x00\x00\x00\x00")

    def test_empty_bound_appends_nothing(self):
        # An empty bound contributes no varint and no bytes: the
        # payload with empty bounds is exactly the key-only one.
        self.assertEqual(
            build_iterator_seek_for_prev_payload(0, b"key", b"", b""),
            build_iterator_seek_for_prev_payload(0, b"key"))
        self.assertEqual(len(build_iterator_seek_for_prev_payload(0, b"key")),
                         8 + 4 + 1 + 3)

    def test_cf_id_is_little_endian_u32(self):
        # CF id 0x01020304 is stored little-endian, not varint.
        self.assertEqual(
            build_iterator_seek_for_prev_payload(0x01020304, b"")[:12],
            b"\x30\x00\x00\x00\x00\x00\x00\x00"
            + b"\x04\x03\x02\x01",
        )

    def test_varint_length_prefix(self):
        # 127 bytes -> 1-byte varint; 128 bytes -> 2-byte varint.
        self.assertEqual(
            build_iterator_seek_for_prev_payload(0, b"a" * 127)[12:13], b"\x7f")
        self.assertEqual(
            build_iterator_seek_for_prev_payload(0, b"a" * 128)[12:14],
            b"\x80\x01")
        self.assertEqual(len(build_iterator_seek_for_prev_payload(0, b"a" * 128)),
                         8 + 4 + 2 + 128)

    def test_put_fixed64(self):
        self.assertEqual(put_fixed64(b"", 48),
                         b"\x30\x00\x00\x00\x00\x00\x00\x00")
        self.assertEqual(put_fixed64(b"", 0x0102030405060708),
                         struct.pack("<Q", 0x0102030405060708))

    def test_put_fixed32(self):
        self.assertEqual(put_fixed32(b"", 0),
                         b"\x00\x00\x00\x00")
        self.assertEqual(put_fixed32(b"", 0x01020304),
                         struct.pack("<I", 0x01020304))

    def test_length_guard(self):
        # The guard itself; reaching it through the payload
        # builder would need a >2^62-byte string, so the guard is
        # tested directly (as in the header/footer packet).
        with self.assertRaises(LengthError_):
            _check_append(0x3FFFFFFFFFFFFFFF, 8)


class IteratorSeekForPrevTests(unittest.TestCase):
    def test_golden_empty_bounds_record(self):
        # clock 0, CF 0, empty key and bounds: ts 8x00, type 06,
        # payload-len 13, payload = PutFixed64(48) + PutFixed32(0)
        # + varint(0).  26 bytes total.
        tr = make_tracer(clock_value=0)
        self.assertTrue(tr.iterator_seek_for_prev(0, b"").ok())
        self.assertEqual(tr.clock.calls, 1)
        self.assertEqual(
            tr.writer.written[0],
            b"\x00" * 8 + b"\x06" + struct.pack("<I", 13)
            + b"\x30\x00\x00\x00\x00\x00\x00\x00"
            + b"\x00\x00\x00\x00" + b"\x00",
        )
        self.assertEqual(len(tr.writer.written[0]), 26)

    def test_golden_both_bounds_record(self):
        # clock 0, CF 0, key "key", lower "lo", upper "hi": map 240,
        # payload 22 bytes, record 35 bytes.
        tr = make_tracer(clock_value=0)
        self.assertTrue(tr.iterator_seek_for_prev(0, b"key", b"lo", b"hi").ok())
        self.assertEqual(
            tr.writer.written[0],
            b"\x00" * 8 + b"\x06" + struct.pack("<I", 22)
            + b"\xf0\x00\x00\x00\x00\x00\x00\x00"
            + b"\x00\x00\x00\x00" + b"\x03" + b"key"
            + b"\x02" + b"lo" + b"\x02" + b"hi",
        )
        self.assertEqual(len(tr.writer.written[0]), 35)

    def test_trace_fields(self):
        # build_iterator_seek_for_prev_trace returns None on skip; otherwise
        # the Trace has type 6 and payload_map 240 with both bounds
        # (48 + 64 + 128).
        tr = make_tracer(clock_value=42)
        trace = tr.build_iterator_seek_for_prev_trace(2, b"key", b"lo", b"hi")
        self.assertIsNotNone(trace)
        self.assertEqual(trace.timestamp, 42)
        self.assertEqual(trace.type, K_TRACE_ITERATOR_SEEK_FOR_PREV)
        self.assertEqual(trace.payload_map, 240)
        self.assertEqual(
            trace.payload,
            build_iterator_seek_for_prev_payload(2, b"key", b"lo", b"hi"))

    def test_trace_fields_bound_combos(self):
        # payload_map follows bound emptiness: 48 / 112 / 176 / 240.
        tr = make_tracer(clock_value=1)
        self.assertEqual(
            tr.build_iterator_seek_for_prev_trace(0, b"k").payload_map, 48)
        self.assertEqual(
            tr.build_iterator_seek_for_prev_trace(0, b"k", b"lo").payload_map,
            112)
        self.assertEqual(
            tr.build_iterator_seek_for_prev_trace(0, b"k", b"", b"hi").payload_map,
            176)
        self.assertEqual(
            tr.build_iterator_seek_for_prev_trace(0, b"k", b"lo", b"hi")
            .payload_map, 240)

    def test_flag_skip_returns_ok_without_clock_or_writer(self):
        # ShouldSkipTrace (0x61b1930): IteratorSeekForPrev's flag bit is
        # 0x08; a set bit skips at once (counter untouched), the
        # clock is never consulted and nothing is written.
        tr = make_tracer(clock_value=7, sampling_period=3,
                         skip_flags=0x08)
        self.assertTrue(tr.iterator_seek_for_prev(0, b"abc", b"lo", b"hi").ok())
        self.assertEqual(tr.clock.calls, 0)
        self.assertEqual(tr.writer.write_calls, 0)
        self.assertEqual(tr.counter, 0)

    def test_file_size_gate(self):
        # helper 0x61b1910: GetFileSize() > max -> skip; equal -> record.
        tr = make_tracer(max_trace_file_size=100, sampling_period=1,
                         writer=FakeWriter(file_size=100))
        self.assertTrue(tr.iterator_seek_for_prev(0, b"abc").ok())
        self.assertEqual(len(tr.writer.written), 1)
        tr = make_tracer(max_trace_file_size=100, sampling_period=1,
                         writer=FakeWriter(file_size=101))
        self.assertTrue(tr.iterator_seek_for_prev(0, b"abc").ok())
        self.assertEqual(len(tr.writer.written), 0)
        self.assertEqual(tr.clock.calls, 0)

    def test_sampling_sequence(self):
        # Period 3, counter 0: skip, skip, record, skip, skip, record.
        tr = make_tracer(sampling_period=3)
        got = []
        for _ in range(6):
            tr.iterator_seek_for_prev(0, b"x", b"lo", b"hi")
            got.append(len(tr.writer.written))
        self.assertEqual(got, [0, 0, 1, 1, 1, 2])
        self.assertEqual(tr.counter, 0)

    def test_writer_error_propagates(self):
        # WriteTrace's Status is forwarded unchanged.
        err = Status(2, b"disk full")
        tr = make_tracer(writer=FakeWriter(write_status=err))
        self.assertEqual(tr.iterator_seek_for_prev(0, b"abc"), err)
        self.assertEqual(len(tr.writer.written), 1)

    def test_clock_called_once_per_record(self):
        tr = make_tracer(clock_value=99)
        tr.iterator_seek_for_prev(0, b"a")
        tr.iterator_seek_for_prev(1, b"b", b"lo", b"hi")
        self.assertEqual(tr.clock.calls, 2)
        self.assertEqual(len(tr.writer.written), 2)
        self.assertEqual(tr.writer.written[0][8], 6)
        self.assertEqual(tr.writer.written[1][8], 6)

    def test_set_payload_map_bits_4_to_7(self):
        # 0x61b18b0: bts sets bit `type`; IteratorSeekForPrev passes
        # kIterCFID (4) then kIterKey (5), then conditionally
        # kIterLowerBound (6) and kIterUpperBound (7): 48, 112,
        # 176, 240.
        self.assertEqual(set_payload_map(0, K_ITER_CF_ID), (16, True))
        self.assertEqual(set_payload_map(16, K_ITER_KEY), (48, True))
        self.assertEqual(
            set_payload_map(48, K_ITER_LOWER_BOUND), (112, True))
        self.assertEqual(
            set_payload_map(112, K_ITER_UPPER_BOUND), (240, True))
        self.assertEqual(
            set_payload_map(240, K_ITER_CF_ID), (240, False))


class CasesTests(unittest.TestCase):
    def _replay(self, kind, inp, want):
        if kind == "iterator_seek_for_prev":
            parts = inp.split("|")
            err = None
            steps = 1
            if parts[-1].startswith("err="):
                err = int(parts[-1][4:])
                parts = parts[:-1]
            if parts[-1].startswith("steps="):
                steps = int(parts[-1][6:])
                parts = parts[:-1]
            (clock, flags, period, max_size, fsize, counter0,
             cf_id) = map(int, parts[:7])
            key = bytes.fromhex(parts[7])
            lower = bytes.fromhex(parts[8])
            upper = bytes.fromhex(parts[9])
            tr = Tracer(FakeClock(clock), max_trace_file_size=max_size,
                        sampling_period=period, skip_flags=flags,
                        writer=FakeWriter(
                            file_size=fsize,
                            write_status=(Status(err, b"disk full")
                                          if err is not None else None)))
            tr.counter = counter0
            if err is not None:
                status = tr.iterator_seek_for_prev(cf_id, key, lower, upper)
                self.assertEqual(
                    want,
                    f"STATUS|{status.code}|{status.message.hex()}")
                return
            pattern = []
            for _ in range(steps):
                before = len(tr.writer.written)
                status = tr.iterator_seek_for_prev(cf_id, key, lower, upper)
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
        elif kind == "iterator_seek_for_prev_payload":
            cf_id_s, key_hex, lower_hex, upper_hex = inp.split("|")
            key = bytes.fromhex(key_hex)
            lower = bytes.fromhex(lower_hex)
            upper = bytes.fromhex(upper_hex)
            self.assertEqual(
                want,
                build_iterator_seek_for_prev_payload(int(cf_id_s), key, lower,
                                            upper).hex())
        elif kind == "encode_varint32":
            self.assertEqual(want, encode_varint32(int(inp)).hex())
        else:
            self.fail(f"unknown kind {kind}")

    def test_all_committed_cases_replay(self):
        cases_path = (
            Path(__file__).resolve().parents[1] / "research" / "work-items"
            / "re-002-node115-tracer-iterator-seek-for-prev-115" / "cases.tsv"
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
            / "re-002-node115-tracer-iterator-seek-for-prev-115" / "cases.tsv"
        )
        with open(cases_path) as fh:
            committed = fh.read()
        lines = ["kind\tinput\twant"]
        for kind, inp, want in generate_cases():
            lines.append(f"{kind}\t{inp}\t{want}")
        self.assertEqual(committed, "\n".join(lines) + "\n")


if __name__ == "__main__":
    unittest.main()
