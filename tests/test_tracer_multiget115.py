#!/usr/bin/env python3
"""Tests for tools/tracer_multiget115.py.

Every expectation is grounded in the node #115 binary
(work/hl-node-115.bin, SHA-256 a6e2897c...): the MultiGet FDE
(0x61b2cf0..0x61b3596), the vendor census record
node115-vendor-61b2cf0, the SetPayloadMap helper (0x61b18b0),
EncodeVarint32 (0x61bd410), ShouldSkipTrace (0x61b1930) and
WriteTrace (0x61b1a10) as modelled in the header/footer packet.
The CF ids are the uint32_t each handle's GetID() returns.  The
binary is never executed.
"""

import csv
import struct
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))

from tracer_multiget115 import (  # noqa: E402
    K_MULTIGET_CFIDS,
    K_MULTIGET_KEYS,
    K_MULTIGET_SIZE,
    K_TRACE_MULTIGET,
    SIZE_MISMATCH_MESSAGE,
    FakeClock,
    FakeWriter,
    LengthError_,
    Status,
    Tracer,
    _check_append,
    build_multiget_payload,
    encode_varint32,
    generate_cases,
    put_fixed32,
    put_fixed64,
    set_payload_map,
)

TOOL = Path(__file__).resolve().parents[1] / "tools" / "tracer_multiget115.py"


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
    def test_empty_multiget_payload(self):
        # PutFixed64(payload_map=0x700) + PutFixed32(0) +
        # varint(0) + varint(0): 14 bytes; both blobs are empty.
        self.assertEqual(
            build_multiget_payload([], []),
            b"\x00\x07\x00\x00\x00\x00\x00\x00"
            + b"\x00\x00\x00\x00" + b"\x00" + b"\x00",
        )

    def test_single_key_payload(self):
        # CF 0, key "": map 0x700, size 1, cfids blob
        # PutFixed32(0) (4 bytes, prefixed 0x04), keys blob
        # varint(0) (1 byte, prefixed 0x01).
        self.assertEqual(
            build_multiget_payload([0], [b""]),
            b"\x00\x07\x00\x00\x00\x00\x00\x00"
            + b"\x01\x00\x00\x00" + b"\x04" + b"\x00\x00\x00\x00"
            + b"\x01" + b"\x00",
        )

    def test_realistic_two_key_payload(self):
        # CFs 0 and 1, keys "key1"/"key2": map 0x700, size 2,
        # cfids blob 8 bytes (prefixed 0x08), keys blob 10 bytes
        # (prefixed 0x0a).
        self.assertEqual(
            build_multiget_payload([0, 1], [b"key1", b"key2"]),
            b"\x00\x07\x00\x00\x00\x00\x00\x00"
            + b"\x02\x00\x00\x00" + b"\x08"
            + b"\x00\x00\x00\x00" + b"\x01\x00\x00\x00"
            + b"\x0a" + b"\x04" + b"key1" + b"\x04" + b"key2",
        )

    def test_payload_map_is_always_0x700(self):
        # The three SetPayloadMap calls are unconditional: the map
        # is 0x700 whatever the keys are, including the empty
        # multiget.
        for cf_ids, keys in ([], []), ([0], [b""]), (
                [0, 1, 2], [b"a", b"b", b"c"]):
            self.assertEqual(
                build_multiget_payload(cf_ids, keys)[:8],
                b"\x00\x07\x00\x00\x00\x00\x00\x00")

    def test_blobs_preserve_order(self):
        # cfids blob: the ids in order, each a fixed u32.
        # keys blob: each key length-prefixed, in order.
        self.assertEqual(
            build_multiget_payload([0x01020304, 5], [b"ab", b"c"]),
            b"\x00\x07\x00\x00\x00\x00\x00\x00"
            + b"\x02\x00\x00\x00" + b"\x08"
            + b"\x04\x03\x02\x01" + b"\x05\x00\x00\x00"
            + b"\x05" + b"\x02" + b"ab" + b"\x01" + b"c",
        )

    def test_varint_length_prefix(self):
        # 127 bytes -> 1-byte varint; 128 bytes -> 2-byte varint
        # (inside the keys blob, then prefixed again).
        self.assertEqual(
            build_multiget_payload([0], [b"a" * 127])[19:20], b"\x7f")
        self.assertEqual(
            build_multiget_payload([0], [b"a" * 128])[19:21],
            b"\x80\x01")
        self.assertEqual(len(build_multiget_payload([0], [b"a" * 128])),
                         8 + 4 + 1 + 4 + 2 + 2 + 128)

    def test_put_fixed64(self):
        self.assertEqual(put_fixed64(b"", 0x700),
                         b"\x00\x07\x00\x00\x00\x00\x00\x00")
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


class MultiGetTests(unittest.TestCase):
    def test_golden_empty_record(self):
        # clock 0, no CFs, no keys: ts 8x00, type 0d,
        # payload-len 14, payload = PutFixed64(0x700) +
        # PutFixed32(0) + varint(0) + varint(0).  27 bytes total.
        tr = make_tracer(clock_value=0)
        self.assertTrue(tr.multiget([], []).ok())
        self.assertEqual(tr.clock.calls, 1)
        self.assertEqual(
            tr.writer.written[0],
            b"\x00" * 8 + b"\x0d" + struct.pack("<I", 14)
            + b"\x00\x07\x00\x00\x00\x00\x00\x00"
            + b"\x00\x00\x00\x00" + b"\x00" + b"\x00",
        )
        self.assertEqual(len(tr.writer.written[0]), 27)

    def test_golden_single_key_record(self):
        # clock 0, CF 0, key "": payload 19 bytes, record 32.
        tr = make_tracer(clock_value=0)
        self.assertTrue(tr.multiget([0], [b""]).ok())
        self.assertEqual(
            tr.writer.written[0],
            b"\x00" * 8 + b"\x0d" + struct.pack("<I", 19)
            + b"\x00\x07\x00\x00\x00\x00\x00\x00"
            + b"\x01\x00\x00\x00" + b"\x04" + b"\x00\x00\x00\x00"
            + b"\x01" + b"\x00",
        )
        self.assertEqual(len(tr.writer.written[0]), 32)

    def test_golden_two_key_record(self):
        # clock 0, CFs 0 and 1, keys "key1"/"key2": payload 32
        # bytes, record 45 bytes.
        tr = make_tracer(clock_value=0)
        self.assertTrue(tr.multiget([0, 1], [b"key1", b"key2"]).ok())
        self.assertEqual(
            tr.writer.written[0],
            b"\x00" * 8 + b"\x0d" + struct.pack("<I", 32)
            + b"\x00\x07\x00\x00\x00\x00\x00\x00"
            + b"\x02\x00\x00\x00" + b"\x08"
            + b"\x00\x00\x00\x00" + b"\x01\x00\x00\x00"
            + b"\x0a" + b"\x04" + b"key1" + b"\x04" + b"key2",
        )
        self.assertEqual(len(tr.writer.written[0]), 45)

    def test_trace_fields(self):
        # build_multiget_trace returns None on skip; otherwise
        # the Trace has type 13 and payload_map 0x700.
        tr = make_tracer(clock_value=42)
        trace = tr.build_multiget_trace([2, 3], [b"a", b"b"])
        self.assertIsNotNone(trace)
        self.assertEqual(trace.timestamp, 42)
        self.assertEqual(trace.type, K_TRACE_MULTIGET)
        self.assertEqual(trace.payload_map, 0x700)
        self.assertEqual(
            trace.payload,
            build_multiget_payload([2, 3], [b"a", b"b"]))

    def test_size_mismatch_returns_corruption(self):
        # The size check runs before the gate: the exact 42-byte
        # message, code 2, no clock consultation, no write, the
        # sampling counter untouched.
        tr = make_tracer(clock_value=7)
        self.assertEqual(
            tr.multiget([0, 1], [b"only"]),
            Status(2, SIZE_MISMATCH_MESSAGE))
        self.assertEqual(len(SIZE_MISMATCH_MESSAGE), 42)
        self.assertEqual(tr.clock.calls, 0)
        self.assertEqual(tr.writer.write_calls, 0)
        self.assertEqual(tr.counter, 0)

    def test_size_mismatch_precedes_the_gate(self):
        # Even with the MultiGet flag set AND an oversized file,
        # a mismatched multiget returns Corruption, not OK-skip.
        tr = make_tracer(clock_value=7, skip_flags=0x10,
                         max_trace_file_size=100,
                         writer=FakeWriter(file_size=101))
        self.assertEqual(
            tr.multiget([0], []),
            Status(2, SIZE_MISMATCH_MESSAGE))
        self.assertEqual(tr.clock.calls, 0)

    def test_flag_skip_returns_ok_without_clock_or_writer(self):
        # ShouldSkipTrace (0x61b1930): MultiGet's flag bit is
        # 0x10; a set bit skips at once (counter untouched), the
        # clock is never consulted and nothing is written.
        tr = make_tracer(clock_value=7, sampling_period=3,
                         skip_flags=0x10)
        self.assertTrue(tr.multiget([0, 1], [b"a", b"b"]).ok())
        self.assertEqual(tr.clock.calls, 0)
        self.assertEqual(tr.writer.write_calls, 0)
        self.assertEqual(tr.counter, 0)

    def test_file_size_gate(self):
        # helper 0x61b1910: GetFileSize() > max -> skip; equal -> record.
        tr = make_tracer(max_trace_file_size=100, sampling_period=1,
                         writer=FakeWriter(file_size=100))
        self.assertTrue(tr.multiget([0], [b"abc"]).ok())
        self.assertEqual(len(tr.writer.written), 1)
        tr = make_tracer(max_trace_file_size=100, sampling_period=1,
                         writer=FakeWriter(file_size=101))
        self.assertTrue(tr.multiget([0], [b"abc"]).ok())
        self.assertEqual(len(tr.writer.written), 0)
        self.assertEqual(tr.clock.calls, 0)

    def test_sampling_sequence(self):
        # Period 3, counter 0: skip, skip, record, skip, skip, record.
        tr = make_tracer(sampling_period=3)
        got = []
        for _ in range(6):
            tr.multiget([0], [b"x"])
            got.append(len(tr.writer.written))
        self.assertEqual(got, [0, 0, 1, 1, 1, 2])
        self.assertEqual(tr.counter, 0)

    def test_writer_error_propagates(self):
        # WriteTrace's Status is forwarded unchanged.
        err = Status(2, b"disk full")
        tr = make_tracer(writer=FakeWriter(write_status=err))
        self.assertEqual(tr.multiget([0], [b"abc"]), err)
        self.assertEqual(len(tr.writer.written), 1)

    def test_clock_called_once_per_record(self):
        tr = make_tracer(clock_value=99)
        tr.multiget([0], [b"a"])
        tr.multiget([1, 2], [b"b", b"c"])
        self.assertEqual(tr.clock.calls, 2)
        self.assertEqual(len(tr.writer.written), 2)
        self.assertEqual(tr.writer.written[0][8], 13)
        self.assertEqual(tr.writer.written[1][8], 13)

    def test_set_payload_map_bits_8_to_10(self):
        # 0x61b18b0: bts sets bit `type`; MultiGet passes
        # kMultiGetSize (8) then kMultiGetCFIDs (9) then
        # kMultiGetKeys (10): 256, 768, 1792.
        self.assertEqual(set_payload_map(0, K_MULTIGET_SIZE), (256, True))
        self.assertEqual(
            set_payload_map(256, K_MULTIGET_CFIDS), (768, True))
        self.assertEqual(
            set_payload_map(768, K_MULTIGET_KEYS), (1792, True))
        self.assertEqual(
            set_payload_map(1792, K_MULTIGET_SIZE), (1792, False))


def _parse_lists(cf_s, k_s):
    cf_ids = [] if cf_s == "-" else [int(c) for c in cf_s.split(",")]
    keys = [] if k_s == "-" else [bytes.fromhex(h) for h in k_s.split(",")]
    return cf_ids, keys


class CasesTests(unittest.TestCase):
    def _replay(self, kind, inp, want):
        if kind == "multiget":
            parts = inp.split("|")
            err = None
            steps = 1
            mismatch = False
            if parts[-1] == "mismatch":
                mismatch = True
                parts = parts[:-1]
            if parts[-1].startswith("err="):
                err = int(parts[-1][4:])
                parts = parts[:-1]
            if parts[-1].startswith("steps="):
                steps = int(parts[-1][6:])
                parts = parts[:-1]
            (clock, flags, period, max_size, fsize, counter0) = map(
                int, parts[:6])
            cf_ids, keys = _parse_lists(parts[6], parts[7])
            tr = Tracer(FakeClock(clock), max_trace_file_size=max_size,
                        sampling_period=period, skip_flags=flags,
                        writer=FakeWriter(
                            file_size=fsize,
                            write_status=(Status(err, b"disk full")
                                          if err is not None else None)))
            tr.counter = counter0
            if mismatch:
                status = tr.multiget(cf_ids, keys)
                self.assertEqual(
                    want,
                    f"STATUS|{status.code}|{status.message.hex()}")
                self.assertEqual(tr.clock.calls, 0)
                self.assertEqual(len(tr.writer.written), 0)
                self.assertEqual(tr.counter, counter0)
                return
            if err is not None:
                status = tr.multiget(cf_ids, keys)
                self.assertEqual(
                    want,
                    f"STATUS|{status.code}|{status.message.hex()}")
                return
            pattern = []
            for _ in range(steps):
                before = len(tr.writer.written)
                status = tr.multiget(cf_ids, keys)
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
        elif kind == "multiget_payload":
            cf_s, k_s = inp.split("|")
            cf_ids, keys = _parse_lists(cf_s, k_s)
            self.assertEqual(
                want, build_multiget_payload(cf_ids, keys).hex())
        elif kind == "encode_varint32":
            self.assertEqual(want, encode_varint32(int(inp)).hex())
        else:
            self.fail(f"unknown kind {kind}")

    def test_all_committed_cases_replay(self):
        cases_path = (
            Path(__file__).resolve().parents[1] / "research" / "work-items"
            / "re-002-node115-tracer-multiget-115" / "cases.tsv"
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
            / "re-002-node115-tracer-multiget-115" / "cases.tsv"
        )
        with open(cases_path) as fh:
            committed = fh.read()
        lines = ["kind\tinput\twant"]
        for kind, inp, want in generate_cases():
            lines.append(f"{kind}\t{inp}\t{want}")
        self.assertEqual(committed, "\n".join(lines) + "\n")


if __name__ == "__main__":
    unittest.main()
