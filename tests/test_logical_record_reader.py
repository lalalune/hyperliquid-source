"""Tests for tools/logical_record_reader.py (node #94 0x51618e0).

The decode hook is scripted: each entry is (code, fragment, remaining,
cumulative, buffer_remaining); the hook installs the buffer accounting
and returns the decode outcome. Reports, stream calls, transforms and
parser calls are recorded by stub hooks so every arm's observable
behavior is pinned end to end.
"""

import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "tools"))

import logical_record_reader as lr

REPO = Path(__file__).resolve().parent.parent
PACKET = REPO / "research" / "work-items" / "RE-001-logical-record-reader-94"
BINARY = REPO / "work" / "hl-node-94.bin"


def scripted(entries):
    """Build a decode hook from a list of outcome tuples.

    Each entry is (code, fragment, remaining, cumulative_after,
    buffer_remaining_after): the hook returns the decode outcome and
    installs the accounting the decode leaves behind. The window
    computes each loop-head snapshot BEFORE the decode call (reader
    +0x60 minus reader +0x40), so a snapshot reflects the accounting
    left by the previous call, not the current one — exactly as in
    the binary, where the reader fields persist across calls.
    """
    queue = list(entries)

    def decode(state):
        code, fragment, remaining, cumulative, buffer_remaining = \
            queue.pop(0)
        state.cumulative = cumulative
        state.buffer_remaining = buffer_remaining
        return code, bytes(fragment), remaining

    return decode


class Harness:
    def __init__(self, mode=0, transform_out=None, entries=(),
                 state_extra=None, initial=(0, 0)):
        self.reports = []
        self.stream_calls = []
        self.transforms = []
        self.parses = []
        self.details = []
        self.attached_hooks = []
        self.state = lr.ReaderState(mode=mode, transform_out=transform_out)
        self.state.cumulative, self.state.buffer_remaining = initial
        if state_extra:
            for key, value in state_extra.items():
                setattr(self.state, key, value)
        self.reader = lr.LogicalReader(
            decode=scripted(entries),
            report=lambda n, m: self.reports.append((n, m)),
            stream_create=lambda: self.stream_calls.append(
                ("create",)) or "stream-obj",
            stream_reset=lambda obj: self.stream_calls.append(
                ("reset", obj)) or 1,
            stream_append=lambda obj, frag: self.stream_calls.append(
                ("append", obj, bytes(frag))),
            stream_finish=lambda obj: self.stream_calls.append(
                ("finish", obj)) or "finish-value",
            transform_one_shot=lambda frag: self.transforms.append(
                bytes(frag)) or "transform-value",
            attached_hook=lambda obj: self.attached_hooks.append(obj),
            parse_compression=lambda s, t: (
                self.parses.append(t),
                lr._default_parse_compression(s, t)),
            detail_builder=lambda p, d: self.details.append(
                (p, d)) or (p + ": " + d),
        )

    def run(self):
        return self.reader.read_record(self.state)


class TestFullAndFragmented(unittest.TestCase):
    def test_full_record_plain(self):
        h = Harness(initial=(100, 90),
                    entries=[(1, b"hello", 0, 100, 80)])
        self.assertTrue(h.run())
        self.assertEqual(h.state.out_slice, b"hello")
        self.assertTrue(h.state.seen_record)
        self.assertEqual(h.state.success_offset, 10)
        self.assertEqual(h.reports, [])

    def test_recyclable_full(self):
        h = Harness(entries=[(5, b"data", 0, 50, 40)])
        self.assertTrue(h.run())
        self.assertEqual(h.state.out_slice, b"data")

    def test_fragmented_record(self):
        h = Harness(initial=(100, 90), entries=[
            (2, b"ab", 0, 100, 90),
            (3, b"cd", 0, 100, 80),
            (4, b"ef", 0, 100, 70),
        ])
        self.assertTrue(h.run())
        self.assertEqual(h.state.out_slice, b"abcdef")
        # Success offset is the FIRST fragment's snapshot, not the last.
        self.assertEqual(h.state.success_offset, 10)
        self.assertTrue(h.state.seen_record)

    def test_recyclable_fragmented(self):
        h = Harness(entries=[
            (6, b"x", 0, 10, 9),
            (7, b"y", 0, 10, 8),
            (8, b"z", 0, 10, 7),
        ])
        self.assertTrue(h.run())
        self.assertEqual(h.state.out_slice, b"xyz")

    def test_first_restarts_partial_record(self):
        h = Harness(entries=[
            (2, b"old", 0, 10, 9),
            (2, b"new", 0, 10, 8),
            (4, b"!", 0, 10, 7),
        ])
        self.assertTrue(h.run())
        self.assertEqual(h.state.out_slice, b"new!")
        self.assertEqual(h.reports, [(3, lr.MSG_PARTIAL_NO_END_2)])
        # Plain mode: the stream reset is still called, with None.
        self.assertIn(("reset", None), h.stream_calls)

    def test_full_ends_partial_record(self):
        h = Harness(entries=[
            (2, b"old", 0, 10, 9),
            (1, b"whole", 0, 10, 8),
        ])
        self.assertTrue(h.run())
        self.assertEqual(h.state.out_slice, b"whole")
        self.assertEqual(h.reports, [(3, lr.MSG_PARTIAL_NO_END_1)])

    def test_middle_without_start_then_full(self):
        h = Harness(entries=[
            (3, b"orphan", 0, 10, 9),
            (1, b"whole", 0, 10, 8),
        ])
        self.assertTrue(h.run())
        self.assertEqual(h.reports, [(6, lr.MSG_MISSING_START_1)])
        self.assertEqual(h.state.out_slice, b"whole")

    def test_last_without_start_then_full(self):
        h = Harness(entries=[
            (4, b"orphan", 0, 10, 9),
            (1, b"whole", 0, 10, 8),
        ])
        self.assertTrue(h.run())
        self.assertEqual(h.reports, [(6, lr.MSG_MISSING_START_2)])

    def test_unknown_codes_loop_on(self):
        h = Harness(entries=[
            (0, b"??", 0, 10, 9),
            (99, b"??", 0, 10, 9),
            (1, b"ok", 0, 10, 8),
        ])
        self.assertTrue(h.run())
        self.assertEqual(h.reports, [
            (2, "unknown record type 0"),
            (2, "unknown record type 99"),
        ])
        self.assertEqual(h.state.out_slice, b"ok")

    def test_unknown_code_counts_accumulator(self):
        h = Harness(entries=[
            (2, b"ab", 0, 10, 9),
            (0, b"zz", 0, 10, 8),
            (1, b"ok", 0, 10, 7),
        ])
        self.assertTrue(h.run())
        # Bytes = fragment length + accumulator length while in-fragment.
        self.assertEqual(h.reports, [(4, "unknown record type 0")])


class TestSkipLoop(unittest.TestCase):
    def test_trailer_mid_fragment_loops(self):
        h = Harness(mode=3, entries=[
            (2, b"ab", 0, 10, 9),
            (11, b"", 0, 10, 8),
            (1, b"ok", 0, 10, 7),
        ])
        self.assertTrue(h.run())
        self.assertEqual(h.reports, [(2, lr.MSG_ERROR_IN_MIDDLE)])
        self.assertEqual(h.state.out_slice, b"ok")

    def test_log_number_mismatch_loops(self):
        h = Harness(mode=3, entries=[
            (13, b"", 0, 10, 9),
            (1, b"ok", 0, 10, 8),
        ])
        self.assertTrue(h.run())
        self.assertEqual(h.reports, [])

    def test_truncated_loops(self):
        h = Harness(mode=3, entries=[
            (2, b"ab", 0, 10, 9),
            (14, b"", 7, 10, 8),
            (1, b"ok", 0, 10, 7),
        ])
        self.assertTrue(h.run())
        self.assertEqual(h.reports, [
            (7, lr.MSG_BAD_LENGTH),
            (2, lr.MSG_ERROR_IN_MIDDLE),
        ])

    def test_truncated_short_final_returns(self):
        h = Harness(mode=3, state_extra={"short_final": True},
                    entries=[(14, b"", 7, 10, 9)])
        self.assertFalse(h.run())
        self.assertEqual(h.reports, [])

    def test_crc_loops(self):
        h = Harness(mode=3, entries=[
            (15, b"", 9, 10, 9),
            (1, b"ok", 0, 10, 8),
        ])
        self.assertTrue(h.run())
        self.assertEqual(h.reports, [(9, lr.MSG_CHECKSUM)])

    def test_eof_in_fragment_returns_cleared(self):
        h = Harness(mode=3, entries=[
            (2, b"ab", 0, 10, 9),
            (10, b"", 0, 10, 8),
        ])
        self.assertFalse(h.run())
        self.assertEqual(h.state.accumulator, bytearray())
        self.assertEqual(h.reports, [])

    def test_leftover_returns(self):
        h = Harness(mode=3, entries=[(12, b"", 3, 10, 9)])
        self.assertFalse(h.run())
        self.assertEqual(h.reports, [])


class TestStrictLoop(unittest.TestCase):
    def test_mode0_eof_in_fragment_silent(self):
        h = Harness(mode=0, entries=[
            (2, b"ab", 0, 10, 9),
            (10, b"", 0, 10, 8),
        ])
        self.assertFalse(h.run())
        self.assertEqual(h.reports, [])
        self.assertEqual(h.state.accumulator, bytearray())

    def test_mode1_eof_in_fragment_reports(self):
        h = Harness(mode=1, entries=[
            (2, b"ab", 0, 10, 9),
            (10, b"", 0, 10, 8),
        ])
        self.assertFalse(h.run())
        self.assertEqual(h.reports, [(2, lr.MSG_TRAILING_DATA)])

    def test_mode2_matches_strict(self):
        h = Harness(mode=2, entries=[
            (2, b"ab", 0, 10, 9),
            (12, b"", 4, 10, 8),
        ])
        self.assertFalse(h.run())
        self.assertEqual(h.reports, [
            (4, lr.MSG_TRUNCATED_HEADER),
            (2, lr.MSG_TRAILING_DATA),
        ])

    def test_mode0_leftover_silent(self):
        h = Harness(mode=0, entries=[(12, b"", 4, 10, 9)])
        self.assertFalse(h.run())
        self.assertEqual(h.reports, [])

    def test_mode1_leftover_not_in_fragment(self):
        h = Harness(mode=1, entries=[(12, b"", 4, 10, 9)])
        self.assertFalse(h.run())
        self.assertEqual(h.reports, [(4, lr.MSG_TRUNCATED_HEADER)])

    def test_mode0_log_number_in_fragment_silent(self):
        h = Harness(mode=0, entries=[
            (2, b"ab", 0, 10, 9),
            (13, b"", 0, 10, 8),
        ])
        self.assertFalse(h.run())
        self.assertEqual(h.reports, [])

    def test_mode1_log_number_in_fragment_reports(self):
        h = Harness(mode=1, entries=[
            (2, b"ab", 0, 10, 9),
            (13, b"", 0, 10, 8),
        ])
        self.assertFalse(h.run())
        self.assertEqual(h.reports, [(2, lr.MSG_TRAILING_DATA)])

    def test_trailer_loops_in_strict_loop(self):
        h = Harness(mode=1, entries=[
            (2, b"ab", 0, 10, 9),
            (11, b"", 0, 10, 8),
            (1, b"ok", 0, 10, 7),
        ])
        self.assertTrue(h.run())
        self.assertEqual(h.reports, [(2, lr.MSG_ERROR_IN_MIDDLE)])

    def test_truncated_short_final_strict_reports_no_clear(self):
        h = Harness(mode=1, state_extra={"short_final": True},
                    entries=[
                        (2, b"ab", 0, 10, 9),
                        (14, b"", 6, 10, 8),
                    ])
        self.assertFalse(h.run())
        self.assertEqual(h.reports, [(6, lr.MSG_TRUNCATED_BODY)])
        # The bytes say this return path does NOT clear the accumulator.
        self.assertEqual(h.state.accumulator, bytearray(b"ab"))

    def test_truncated_short_final_tolerate_silent(self):
        h = Harness(mode=0, state_extra={"short_final": True},
                    entries=[(14, b"", 6, 10, 9)])
        self.assertFalse(h.run())
        self.assertEqual(h.reports, [])

    def test_truncated_strict_loops(self):
        h = Harness(mode=1, entries=[
            (14, b"", 6, 10, 9),
            (1, b"ok", 0, 10, 8),
        ])
        self.assertTrue(h.run())
        self.assertEqual(h.reports, [(6, lr.MSG_BAD_LENGTH)])

    def test_truncated_mode0_sticky_returns(self):
        h = Harness(mode=0, state_extra={"sticky": True},
                    entries=[
                        (2, b"ab", 0, 10, 9),
                        (14, b"", 6, 10, 8),
                    ])
        self.assertFalse(h.run())
        self.assertEqual(h.reports, [])

    def test_truncated_mode0_no_sticky_loops(self):
        h = Harness(mode=0, entries=[
            (14, b"", 6, 10, 9),
            (1, b"ok", 0, 10, 8),
        ])
        self.assertTrue(h.run())
        self.assertEqual(h.reports, [(6, lr.MSG_BAD_LENGTH)])

    def test_crc_no_sticky_loops(self):
        h = Harness(mode=0, entries=[
            (15, b"", 9, 10, 9),
            (1, b"ok", 0, 10, 8),
        ])
        self.assertTrue(h.run())
        self.assertEqual(h.reports, [(9, lr.MSG_CHECKSUM)])

    def test_crc_sticky_mode0_returns(self):
        h = Harness(mode=0, state_extra={"sticky": True},
                    entries=[
                        (2, b"ab", 0, 10, 9),
                        (15, b"", 9, 10, 8),
                    ])
        self.assertFalse(h.run())
        self.assertEqual(h.reports, [])

    def test_crc_sticky_strict_loops(self):
        h = Harness(mode=1, state_extra={"sticky": True},
                    entries=[
                        (15, b"", 9, 10, 9),
                        (1, b"ok", 0, 10, 8),
                    ])
        self.assertTrue(h.run())
        self.assertEqual(h.reports, [(9, lr.MSG_CHECKSUM)])

    def test_mode_byte_masked(self):
        # Only the low byte is consulted: 0x103 behaves as mode 3.
        h = Harness(mode=0x103, entries=[
            (11, b"", 0, 10, 9),
            (1, b"ok", 0, 10, 8),
        ])
        self.assertTrue(h.run())
        self.assertEqual(h.reports, [])


class TestCompressionArm(unittest.TestCase):
    def _compression_body(self, tag, extra=b"PAYLOAD"):
        frag = bytes([tag, 0, 0, 0]) + extra
        return frag

    def test_tag_zero_parses(self):
        h = Harness(entries=[
            (9, self._compression_body(0), 0, 10, 9),
            (1, b"ok", 0, 10, 8),
        ])
        self.assertTrue(h.run())
        self.assertEqual(h.parses, [0])
        self.assertTrue(h.state.compression_seen)
        self.assertEqual(h.state.compression_type, 0)
        self.assertIsNotNone(h.state.attached)
        self.assertEqual(len(h.state.stream_buffer), 0x8000)
        self.assertEqual(h.reports, [])

    def test_tag_seven_parses(self):
        h = Harness(entries=[
            (9, self._compression_body(7), 0, 10, 9),
            (1, b"ok", 0, 10, 8),
        ])
        self.assertTrue(h.run())
        self.assertEqual(h.parses, [7])

    def test_other_tag_reports_and_loops(self):
        h = Harness(entries=[
            (9, self._compression_body(5), 0, 10, 9),
            (1, b"ok", 0, 10, 8),
        ])
        self.assertTrue(h.run())
        self.assertEqual(h.details, [(
            "CompressionTypeRecord",
            "WAL compression type not supported")])
        self.assertEqual(h.reports, [
            (len(self._compression_body(5)), lr.MSG_DECODE_COMPRESSION)])
        self.assertEqual(h.parses, [])

    def test_short_body_reports(self):
        h = Harness(entries=[
            (9, b"\x00\x00", 0, 10, 9),
            (1, b"ok", 0, 10, 8),
        ])
        self.assertTrue(h.run())
        self.assertEqual(h.details, [(
            "CompressionTypeRecord",
            "Error decoding WAL compression type")])
        self.assertEqual(h.reports, [(2, lr.MSG_DECODE_COMPRESSION)])

    def test_second_compression_warns_but_parses(self):
        h = Harness(entries=[
            (9, self._compression_body(0), 0, 10, 9),
            (9, self._compression_body(7), 0, 10, 8),
            (1, b"ok", 0, 10, 7),
        ])
        self.assertTrue(h.run())
        self.assertEqual(h.parses, [0, 7])
        self.assertEqual(h.reports, [(
            len(self._compression_body(7)), lr.MSG_MULTIPLE_COMPRESSION)])

    def test_compression_after_record_warns(self):
        h = Harness(entries=[
            (1, b"first", 0, 10, 9),
        ])
        self.assertTrue(h.run())
        h2 = Harness(entries=[
            (9, self._compression_body(0), 0, 20, 19),
            (1, b"ok", 0, 20, 18),
        ])
        h2.state.seen_record = True
        self.assertTrue(h2.run())
        self.assertEqual(h2.reports, [(
            len(self._compression_body(0)), lr.MSG_COMPRESSION_NOT_FIRST)])
        self.assertEqual(h2.parses, [0])

    def test_compression_mid_fragment_clears_but_keeps_state(self):
        h = Harness(initial=(10, 9), entries=[
            (2, b"ab", 0, 20, 15),
            (9, self._compression_body(0), 0, 30, 29),
            (4, b"cd", 0, 30, 28),
        ])
        self.assertTrue(h.run())
        # Accumulator was cleared by the compression arm, so only the
        # last fragment survives; the success offset is the
        # compression arm's snapshot, which overwrote the first one.
        self.assertEqual(h.state.out_slice, b"cd")
        self.assertEqual(h.state.success_offset, 5)


class TestStreamMode(unittest.TestCase):
    def test_fragmented_stream_path(self):
        slot = lr.Slot()
        h = Harness(transform_out=slot, entries=[
            (2, b"ab", 0, 10, 9),
            (3, b"cd", 0, 10, 8),
            (4, b"ef", 0, 10, 7),
        ])
        self.assertTrue(h.run())
        self.assertEqual(h.state.out_slice, b"abcdef")
        self.assertEqual(slot.value, "finish-value")
        kinds = [c[0] for c in h.stream_calls]
        self.assertEqual(kinds, ["create", "reset",
                                 "append", "append", "append", "finish"])

    def test_full_stream_path_uses_one_shot(self):
        slot = lr.Slot()
        h = Harness(transform_out=slot, entries=[(1, b"full", 0, 10, 9)])
        self.assertTrue(h.run())
        self.assertEqual(h.state.out_slice, b"full")
        self.assertEqual(slot.value, "transform-value")
        self.assertEqual(h.transforms, [b"full"])

    def test_full_stream_suppressed_when_attached(self):
        slot = lr.Slot()
        h = Harness(transform_out=slot,
                    state_extra={"attached": object()},
                    entries=[(1, b"full", 0, 10, 9)])
        self.assertTrue(h.run())
        self.assertIsNone(slot.value)
        self.assertEqual(h.transforms, [])
        self.assertEqual(len(h.attached_hooks), 1)

    def test_prologue_attached_hook(self):
        marker = object()
        h = Harness(state_extra={"attached": marker},
                    entries=[(1, b"ok", 0, 10, 9)])
        self.assertTrue(h.run())
        self.assertEqual(h.attached_hooks, [marker])

    def test_append_overflow_raises(self):
        import logical_record_reader as mod
        old_cap = mod.APPEND_CAP
        mod.APPEND_CAP = 10
        try:
            h = Harness(entries=[
                (2, b"123456", 0, 10, 9),
                (3, b"12345", 0, 10, 8),
            ])
            with self.assertRaises(lr.LengthError):
                h.run()
        finally:
            mod.APPEND_CAP = old_cap


class TestPacket(unittest.TestCase):
    def test_verify_script_passes(self):
        result = subprocess.run(
            [sys.executable, str(PACKET / "verify.py")],
            cwd=REPO, capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("ALL CHECKS PASSED", result.stdout)

    def test_sampled_instructions_byte_for_byte(self):
        data = BINARY.read_bytes()

        def file_offset(vaddr):
            return vaddr - 0x1000 if vaddr >= 0x1343C80 else vaddr

        samples = {
            0x51618E0: bytes.fromhex("f30f1efa"),  # endbr64
            0x51619C6: bytes.fromhex("e835faffff"),  # decode call site 1
            0x5161EC9: bytes.fromhex("e832f5ffff"),  # decode call site 2
            0x5161D94: bytes.fromhex("e8b7faffff"),  # parser call
        }
        for vaddr, expected in samples.items():
            off = file_offset(vaddr)
            self.assertEqual(data[off:off + len(expected)], expected,
                             hex(vaddr))
        # The same instructions in a fresh objdump run.
        fresh = subprocess.run(
            ["objdump", "-d", "--start-address=0x51618e0",
             "--stop-address=0x516231c", "work/hl-node-94.bin"],
            cwd=REPO, capture_output=True, text=True, check=True).stdout
        for line in ["51618e0:\tf3 0f 1e fa",
                     "51619c6:\te8 35 fa ff ff",
                     "5161ec9:\te8 32 f5 ff ff",
                     "5161d94:\te8 b7 fa ff ff"]:
            self.assertIn(line, fresh)

    def test_corruption_control(self):
        with tempfile.TemporaryDirectory() as tmp:
            import shutil
            copy = Path(tmp) / "packet"
            shutil.copytree(PACKET, copy)
            window = copy / "window.txt"
            text = window.read_text()
            window.write_text(text.replace("endbr64", "endbrXX", 1))
            result = subprocess.run(
                [sys.executable, str(copy / "verify.py"),
                 "--packet-dir", str(copy)],
                cwd=REPO, capture_output=True, text=True)
            self.assertNotEqual(result.returncode, 0)


if __name__ == "__main__":
    unittest.main()
