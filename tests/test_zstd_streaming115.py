"""Tests for tools/zstd_streaming115.py (RE-002, node #115).

2,400 deterministic cases (400 create, 400 reset, 800 compress,
800 uncompress) plus targeted boundary/corruption controls. The model
is checked against INDEPENDENT expectations, not against itself:

  * create: null-vs-object gate on the type byte, field values.
  * reset: stored input buffer zeroed; a post-reset compress emits a
    fresh frame (decompresses to the input alone).
  * compress: empty input returns 0; same-object continuation finishes
    the frame; a new object restarts it; the same object with a new
    size keeps the OLD size (binary quirk); every produced frame has
    the checksum flag and one-shot-decompresses to exactly the input.
  * uncompress: whole-frame, nullptr-continuation, re-passed-input
    restart, empty input, garbage/corrupt frames -> -1 + reset state.
  * error branches: the engine passthroughs are stubbed to return a
    ZSTD error code, asserting Reset + return -1.
  * ledger: the committed cases.tsv matches a fresh regeneration.

The ZSTD engine is the system libzstd.so.1 via ctypes (see the tool
docstring). Frame bytes are not asserted: they depend on the libzstd
version. Return values, positions, state transitions and decompressed
bytes are asserted: those are the wrapper's contract.
"""

import hashlib
import os
import random
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
import zstd_streaming115 as m


def _sha(b):
    return hashlib.sha256(b).hexdigest()


class CreateTests(unittest.TestCase):
    def test_gate_and_fields(self):
        for case in m.generate_cases():
            if case["op"] != "create":
                continue
            obj = m.StreamingCompress.create(
                case["type"], case["options"], case["format_version"],
                case["max_output_len"])
            if case["type"] != 7:
                self.assertIsNone(obj, case["id"])
                obj2 = m.StreamingUncompress.create(
                    case["type"], case["format_version"],
                    case["max_output_len"])
                self.assertIsNone(obj2, case["id"])
                continue
            self.assertIsNotNone(obj, case["id"])
            self.assertEqual(obj.compression_type, 7)
            self.assertEqual(obj.options, case["options"])
            self.assertEqual(obj.format_version,
                             case["format_version"] & 0xFFFFFFFF)
            self.assertEqual(obj.max_output_len, case["max_output_len"])
            self.assertEqual(obj.in_buffer(), (False, 0, 0))
            obj.close()
            obj2 = m.StreamingUncompress.create(
                case["type"], case["format_version"],
                case["max_output_len"])
            self.assertIsNotNone(obj2, case["id"])
            self.assertEqual(obj2.format_version,
                             case["format_version"] & 0xFFFFFFFF)
            self.assertEqual(obj2.max_output_len, case["max_output_len"])
            self.assertEqual(obj2.in_buffer(), (False, 0, 0))
            obj2.close()

    def test_observed_caller_args(self):
        # The binary's only Create callers pass format_version=2 and
        # max_output_len 0x7ff5/0x7ff9 (compress) and 0x8000 (uncompress).
        for max_len in (0x7FF5, 0x7FF9):
            obj = m.StreamingCompress.create(7, bytes(48), 2, max_len)
            self.assertIsNotNone(obj)
            self.assertEqual(obj.max_output_len, max_len)
            obj.close()
        obj = m.StreamingUncompress.create(7, 2, 0x8000)
        self.assertIsNotNone(obj)
        self.assertEqual(obj.max_output_len, 0x8000)
        obj.close()


class ResetTests(unittest.TestCase):
    def test_reset_clears_buffer_and_fresh_frame(self):
        for case in m.generate_cases():
            if case["op"] != "reset":
                continue
            data = case["data"]
            if case["side"] == "compress":
                obj = m.StreamingCompress.create(
                    7, bytes(48), 2, case["max_output_len"])
                out = bytearray(case["max_output_len"])
                if data:
                    obj.compress(data, len(data), out)
                    self.assertEqual(obj.in_buffer()[0], True)
                obj.reset()
                self.assertEqual(obj.in_buffer(), (False, 0, 0))
                if data:
                    out2 = bytearray(case["max_output_len"])
                    ret, pos = obj.compress(data, len(data), out2)
                    # drain a multi-call frame
                    frame = bytes(out2[:pos])
                    while ret != 0:
                        out3 = bytearray(case["max_output_len"])
                        ret, pos = obj.compress(data, len(data), out3)
                        frame += bytes(out3[:pos])
                    dec = m.one_shot_decompress(frame, max(len(data), 1))
                    self.assertEqual(dec, data, case["id"])
                    self.assertTrue(m.frame_has_checksum(frame), case["id"])
                obj.close()
            else:
                obj = m.StreamingUncompress.create(
                    7, 2, case["max_output_len"])
                obj.reset()
                self.assertEqual(obj.in_buffer(), (False, 0, 0))
                obj.close()


class CompressTests(unittest.TestCase):
    def _drain(self, obj, data, max_len):
        frame = bytearray()
        out = bytearray(max_len)
        ret, pos = obj.compress(data, len(data), out)
        frame += out[:pos]
        while ret != 0 and ret != -1:
            out = bytearray(max_len)
            ret, pos = obj.compress(data, len(data), out)
            frame += out[:pos]
        return ret, bytes(frame)

    def test_roundtrip_and_checksum(self):
        for case in m.generate_cases():
            if case["op"] != "compress":
                continue
            data = case["data"]
            obj = m.StreamingCompress.create(
                7, bytes(48), 2, case["max_output_len"])
            if not data:
                ret, pos = obj.compress(b"", 0, bytearray(16))
                self.assertEqual((ret, pos), (0, 0), case["id"])
                obj.close()
                continue
            ret, frame = self._drain(obj, data, case["max_output_len"])
            self.assertEqual(ret, 0, case["id"])
            self.assertTrue(m.frame_has_checksum(frame), case["id"])
            dec = m.one_shot_decompress(frame, max(len(data), 1))
            self.assertEqual(dec, data, case["id"])
            obj.close()

    def test_same_object_continues_new_object_restarts(self):
        rng = random.Random(99)
        data = bytes(rng.randrange(256) for _ in range(5000))
        # small output forces multi-call continuation
        obj = m.StreamingCompress.create(7, bytes(48), 2, 64)
        ret, frame = self._drain(obj, data, 64)
        self.assertEqual(ret, 0)
        self.assertEqual(m.one_shot_decompress(frame, len(data)), data)
        obj.close()
        # a NEW bytes object with identical content restarts the frame:
        # compressing it yields a fresh, complete frame on its own
        obj = m.StreamingCompress.create(7, bytes(48), 2, 65536)
        out = bytearray(65536)
        ret, pos = obj.compress(bytes(data), len(data), out)
        self.assertEqual(ret, 0)
        self.assertEqual(m.one_shot_decompress(bytes(out[:pos]), len(data)),
                         data)
        obj.close()

    def test_same_object_new_size_keeps_old_size(self):
        # Binary quirk: with the same input pointer the stored size is
        # NOT re-read. The second call continues from the stored pos
        # (100, fully consumed) over the stored size (100), so it emits
        # only an empty frame tail -- the new 200-byte size is ignored
        # and the second 100 bytes are never compressed.
        data = b"Z" * 100 + b"Y" * 100
        obj = m.StreamingCompress.create(7, bytes(48), 2, 65536)
        out = bytearray(65536)
        ret, pos = obj.compress(data, 100, out)
        self.assertEqual(ret, 0)
        first_frame = bytes(out[:pos])
        self.assertEqual(m.one_shot_decompress(first_frame, 100), data[:100])
        # same object, declared size 200: old size (100) still governs
        out2 = bytearray(65536)
        ret2, pos2 = obj.compress(data, 200, out2)
        self.assertEqual(ret2, 0)
        self.assertEqual(m.one_shot_decompress(bytes(out2[:pos2]), 200), b"")
        self.assertNotEqual(m.one_shot_decompress(bytes(out2[:pos2]), 200),
                            data)
        obj.close()

    def test_error_branch_resets_and_returns_minus_one(self):
        obj = m.StreamingCompress.create(7, bytes(48), 2, 65536)
        real = m.compress_stream2

        def failing(*args, **kwargs):
            return (2 ** 64 - 70), 0, 0  # ZSTD error code

        m.compress_stream2 = failing
        try:
            data = b"error-path probe" * 10
            ret, pos = obj.compress(data, len(data),
                                    bytearray(65536))
            self.assertEqual((ret, pos), (-1, 0))
            self.assertEqual(obj.in_buffer(), (False, 0, 0))
        finally:
            m.compress_stream2 = real
            obj.close()


class UncompressTests(unittest.TestCase):
    def _frame(self, data, max_len=65536):
        obj = m.StreamingCompress.create(7, bytes(48), 2, max_len)
        out = bytearray(max_len)
        ret, pos = obj.compress(data, len(data), out)
        frame = bytearray(out[:pos])
        while ret != 0:
            out = bytearray(max_len)
            ret, pos = obj.compress(data, len(data), out)
            frame += out[:pos]
        obj.close()
        return bytes(frame)

    def test_roundtrip_feeds(self):
        for case in m.generate_cases():
            if case["op"] != "uncompress":
                continue
            data = case["data"]
            frame = self._frame(data)
            obj = m.StreamingUncompress.create(
                7, 2, case["max_output_len"])
            out = bytearray(case["max_output_len"])
            if case["feed"] == "garbage":
                bad = bytes(random.Random(7).randrange(256)
                            for _ in range(32))
                ret, produced = obj.uncompress(bad, len(bad), out)
                self.assertEqual(ret, -1, case["id"])
                self.assertEqual(obj.in_buffer(), (False, 0, 0))
                obj.close()
                continue
            if case["feed"] == "corrupt" and len(frame) > 20:
                bad = bytearray(frame)
                bad[len(bad) // 2] ^= 0xFF
                ret, produced = obj.uncompress(bytes(bad), len(bad), out)
                # The checksum is only checked at the end of the frame,
                # so with a small output buffer the error may surface
                # only after draining with nullptr continuation.
                guard = 0
                while ret > 0:
                    guard += 1
                    self.assertLess(guard, 10000, case["id"])
                    out2 = bytearray(case["max_output_len"])
                    ret, produced = obj.uncompress(None, 1, out2)
                self.assertEqual(ret, -1, case["id"])
                self.assertEqual(obj.in_buffer(), (False, 0, 0))
                obj.close()
                continue
            if not data:
                ret, produced = obj.uncompress(b"", 0, out)
                self.assertEqual((ret, produced), (0, 0), case["id"])
                obj.close()
                continue
            if case["feed"] == "chunks-repassed":
                # Re-passing is a restart ONLY at a frame boundary: the
                # binary replaces the input buffer without resetting the
                # DCtx, so a mid-frame re-pass corrupts the stream (see
                # test_mid_frame_repass_corrupts_stream). Here the frame
                # is first fully consumed, then re-passed for a fresh,
                # complete decompression.
                ret, produced = obj.uncompress(frame, len(frame), out)
                got = bytearray(out[:produced])
                guard = 0
                while ret > 0:
                    guard += 1
                    self.assertLess(guard, 10000, case["id"])
                    out2 = bytearray(case["max_output_len"])
                    ret, produced = obj.uncompress(None, 1, out2)
                    got += out2[:produced]
                self.assertEqual(ret, 0, case["id"])
                self.assertEqual(bytes(got), data, case["id"])
                ret, produced = obj.uncompress(frame, len(frame), out)
                got = bytearray(out[:produced])
                while ret > 0:
                    guard += 1
                    self.assertLess(guard, 10000, case["id"])
                    out2 = bytearray(case["max_output_len"])
                    ret, produced = obj.uncompress(None, 1, out2)
                    got += out2[:produced]
                self.assertEqual(ret, 0, case["id"])
                self.assertEqual(bytes(got), data, case["id"])
                obj.close()
                continue
            # whole + chunks-null: drain with nullptr continuation
            ret, produced = obj.uncompress(frame, len(frame), out)
            got = bytearray(out[:produced])
            guard = 0
            while ret > 0:
                guard += 1
                self.assertLess(guard, 10000, case["id"])
                out2 = bytearray(case["max_output_len"])
                ret, produced = obj.uncompress(None, 1, out2)
                got += out2[:produced]
            self.assertEqual(ret, 0, case["id"])
            self.assertEqual(bytes(got), data, case["id"])
            obj.close()

    def test_empty_input_returns_zero(self):
        obj = m.StreamingUncompress.create(7, 2, 0x8000)
        ret, pos = obj.uncompress(b"x", 0, bytearray(0x8000))
        self.assertEqual((ret, pos), (0, 0))
        obj.close()

    def test_null_input_without_buffer_is_noop(self):
        obj = m.StreamingUncompress.create(7, 2, 0x8000)
        ret, pos = obj.uncompress(None, 1, bytearray(0x8000))
        self.assertEqual((ret, pos), (0, 0))
        self.assertEqual(obj.in_buffer(), (False, 0, 0))
        obj.close()

    def test_mid_frame_repass_corrupts_stream(self):
        # The binary replaces the input buffer on a non-null input
        # WITHOUT resetting the DCtx, so re-passing the same frame
        # mid-stream feeds the frame header bytes to a mid-block
        # decoder: the engine drains its internal buffer, then errors.
        # The wrapper propagates that as Reset + return -1. The exact
        # drain count at which the error surfaces is engine-internal.
        data = bytes(random.Random(5).randrange(256) for _ in range(192))
        frame = self._frame(data)
        obj = m.StreamingUncompress.create(7, 2, 16)
        out = bytearray(16)
        ret, produced = obj.uncompress(frame, len(frame), out)
        self.assertGreater(ret, 0)
        ret, produced = obj.uncompress(frame, len(frame), out)
        guard = 0
        while ret > 0:
            guard += 1
            self.assertLess(guard, 10000)
            out2 = bytearray(16)
            ret, produced = obj.uncompress(None, 1, out2)
        self.assertEqual(ret, -1)
        self.assertEqual(obj.in_buffer(), (False, 0, 0))
        obj.close()

    def test_error_branch_resets_and_returns_minus_one(self):
        obj = m.StreamingUncompress.create(7, 2, 65536)
        real = m.decompress_stream

        def failing(*args, **kwargs):
            return (2 ** 64 - 70), 0, 0

        m.decompress_stream = failing
        try:
            ret, pos = obj.uncompress(b"garbage", 7, bytearray(65536))
            self.assertEqual((ret, pos), (-1, 0))
            self.assertEqual(obj.in_buffer(), (False, 0, 0))
        finally:
            m.decompress_stream = real
            obj.close()

    def test_is_error_predicate_matches_binary(self):
        # 0x620dd60: cmp rdi, -0x78; seta  (error iff code > 2**64-120)
        self.assertFalse(m.is_error(0))
        self.assertFalse(m.is_error(2 ** 64 - 120))
        self.assertTrue(m.is_error(2 ** 64 - 119))
        self.assertTrue(m.is_error(2 ** 64 - 1))


class LedgerTests(unittest.TestCase):
    def test_cases_tsv_matches_regeneration(self):
        packet = Path(__file__).resolve().parents[1] / "research" / \
            "work-items" / "re-002-node115-zstd-streaming-115" / "cases.tsv"
        self.assertTrue(packet.exists(), "cases.tsv missing from packet")
        import io
        buf = io.StringIO()
        rows = m.case_ledger(m.generate_cases())
        buf.write("case_id\top\tinput_sha256_16\tinput_len_or_type\t"
                  "max_output_len_or_side\tmode\toutcome\t"
                  "produced\tverdict\n")
        for row in rows:
            buf.write("\t".join(str(c) for c in row) + "\n")
        self.assertEqual(packet.read_text(), buf.getvalue())
        self.assertEqual(len(rows), 2400)


if __name__ == "__main__":
    unittest.main()
