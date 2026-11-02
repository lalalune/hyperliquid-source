"""Tests for tools/wal_replay_step.py (RE-001 wal replay step).

Run from the repository root:
    python3 -m unittest tests.test_wal_replay_step -v
"""
import struct
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from tools.wal_replay_step import (
    CLEAR_PREFIX,
    DEFAULT_METHOD,
    INVERTED_PREFIX,
    LOG_FILE,
    LOG_FORMAT,
    SHORT_CODE,
    SHORT_MESSAGE,
    FakeHeap,
    OutOfRangeError,
    OutStatus,
    RecordState,
    ReplayStep,
    basename_of,
    filter_elements,
)

PACKET = Path(__file__).resolve().parents[1] / (
    "research/work-items/RE-001-wal-replay-step-94")


def make_scratch(heap, ptr_data=b"detail", u16_0=0x0201):
    """A 16-byte scratch status: u16@0, u8@2, u16@3, u8@5, ptr@8."""
    scratch = bytearray(16)
    struct.pack_into("<H", scratch, 0, u16_0)
    scratch[2] = 0x03
    struct.pack_into("<H", scratch, 3, 0x0504)
    scratch[5] = 0x06
    handle = heap.alloc(ptr_data) if ptr_data is not None else 0
    struct.pack_into("<Q", scratch, 8, handle)
    return scratch


class TestBasename(unittest.TestCase):
    def test_slash(self):
        self.assertEqual(basename_of("db/wal/000123.log"), "000123.log")

    def test_backslash(self):
        self.assertEqual(basename_of("db\\wal\\000123.log"), "000123.log")

    def test_no_separator(self):
        self.assertEqual(basename_of("000123.log"), "000123.log")

    def test_trailing_separator(self):
        self.assertEqual(basename_of("db/wal/"), "")

    def test_mixed_separators_take_last(self):
        self.assertEqual(basename_of("a/b\\c/d"), "d")


class TestFilter(unittest.TestCase):
    def test_keep_only_predicated_non_default(self):
        elements = [
            {"method": 0x111, "pred": 1, "ptr": "a", "ref": 1},
            {"method": DEFAULT_METHOD, "pred": 1, "ptr": "b", "ref": 1},
            {"method": 0x222, "pred": 0, "ptr": "c", "ref": 1},
            {"method": 0x333, "pred": 1, "ptr": "d", "ref": 1},
        ]
        kept = filter_elements(elements)
        self.assertEqual([e["ptr"] for e in kept], ["a", "d"])

    def test_empty(self):
        self.assertEqual(filter_elements([]), [])


class TestEntryAndGate(unittest.TestCase):
    def test_entry_copy_writes_status_fields(self):
        step = ReplayStep()
        out = OutStatus()
        step.run(out, "db/000001.log", [], None, (0x11223344, 0x5566, b"st"))
        self.assertEqual(out.u32_at_0(), 0x11223344)
        self.assertEqual(out.u16_at_4(), 0x5566)
        self.assertEqual(step.heap.read(out.ptr_at_8()), b"st")

    def test_gate_skips_reader_and_leaves_arg5_unwritten(self):
        step = ReplayStep()
        out = OutStatus()
        out.raw[0] = 1  # entry copy overwrites +0..+3, so gate via entry u32
        result = step.run(out, "db/000001.log", [], None,
                          (0x00000001, 0, None))
        self.assertIsNone(result)
        self.assertNotIn("reader-construct", step.events)
        self.assertNotIn("record-read", step.events)
        self.assertEqual(step.events[0], "state-vector-release")
        self.assertEqual(step.events[-1], "trailing-release")


class TestShortPath(unittest.TestCase):
    def setUp(self):
        self.step = ReplayStep()
        self.out = OutStatus()

    def run_short(self, record=b"short", scratch_u16=0x0201, **kwargs):
        scratch = make_scratch(self.step.heap, u16_0=scratch_u16)
        kwargs.setdefault("entry_status", (0, 0, None))
        result = self.step.run(self.out, "db/wal/000123.log", [],
                               record, scratch=scratch, **kwargs)
        return result, scratch

    def test_short_logs_with_exact_format_and_fields(self):
        result, _ = self.run_short()
        self.assertEqual(len(self.step.log_records), 1)
        log = self.step.log_records[0]
        self.assertEqual(log["level"], 2)
        self.assertEqual(log["format"], LOG_FORMAT)
        self.assertEqual(log["file"], LOG_FILE)
        self.assertEqual(log["prefix"], CLEAR_PREFIX)
        self.assertEqual(log["filename"], "db/wal/000123.log")
        self.assertEqual(log["length"], 5)
        self.assertEqual(log["formatted"], f"status:{SHORT_CODE}:{SHORT_MESSAGE}")

    def test_short_inverted_flag_uses_ignoring_prefix(self):
        self.run_short(inverted_flag=True)
        self.assertEqual(self.step.log_records[0]["prefix"], INVERTED_PREFIX)

    def test_short_boundary_length_11_logs(self):
        self.run_short(record=b"01234567890")
        self.assertEqual(len(self.step.log_records), 1)

    def test_short_field_copy_writes_exact_bytes(self):
        result, scratch = self.run_short()
        self.assertEqual(self.out.raw[0:2], scratch[0:2])
        self.assertEqual(self.out.raw[2], scratch[2])
        self.assertEqual(self.out.raw[3:5], scratch[3:5])
        self.assertEqual(self.out.raw[5], scratch[5])
        self.assertEqual(self.step.heap.read(self.out.ptr_at_8()), b"detail")

    def test_short_teardown_rule_default_zero(self):
        result, _ = self.run_short()
        self.assertEqual(result, 0)
        self.assertEqual(
            self.step.events[-10:],
            ["accumulator-dispose", "reader-dtor", "handle-dispose",
             "state-vector-release", "state-subobject-50-release",
             "state-vcall-40", "state-subobject-28-release",
             "state-vcall-00", "state-free", "trailing-release"])

    def test_short_teardown_rule_one(self):
        # The rule reads the POST-copy out byte, so the scratch's
        # low byte must be 0 for the rule to yield 1.
        result, _ = self.run_short(scratch_u16=0x0200, flag_7f=0, flag_7d=1)
        self.assertEqual(result, 1)

    def test_short_teardown_rule_post_copy_byte_governs(self):
        # Scratch low byte nonzero -> copied out byte nonzero ->
        # rule yields 0 even with both flags set for 1.
        result, _ = self.run_short(scratch_u16=0x0201, flag_7f=0, flag_7d=1)
        self.assertEqual(result, 0)

    def test_short_teardown_rule_flag7f_blocks(self):
        result, _ = self.run_short(flag_7f=1, flag_7d=1)
        self.assertEqual(result, 0)

    def test_short_state_basename_and_filter(self):
        elements = [
            {"method": 0x111, "pred": 1, "ptr": "a", "ref": 1},
            {"method": DEFAULT_METHOD, "pred": 1, "ptr": "b", "ref": 1},
        ]
        scratch = make_scratch(self.step.heap)
        self.step.run(self.out, "db/wal/000123.log", elements, b"short",
                      (0, 0, None), scratch=scratch)
        self.assertEqual(self.step.state["basename"], "000123.log")
        self.assertEqual([e["ptr"] for e in self.step.kept], ["a"])


class TestLongPath(unittest.TestCase):
    def test_long_applies_moves_zero_and_returns_head(self):
        step = ReplayStep()
        out = OutStatus()
        record = b"RECORDBY" + b"012345"  # 14 bytes > 11
        result = step.run(out, "f.log", [], record, (0xAABBCC00, 0x1234, b"old"))
        self.assertEqual(result, struct.unpack_from("<Q", b"RECORDBY", 0)[0])
        self.assertEqual(out.u32_at_0(), 0)
        self.assertEqual(out.u16_at_4(), 0)
        self.assertEqual(out.ptr_at_8(), 0)
        self.assertIn("record-state-construct", step.events)
        self.assertIn("record-apply", step.events)
        self.assertIn("out-zero-move", step.events)
        self.assertIn("record-state-reset", step.events)
        self.assertEqual(step.events[-1], "trailing-release")

    def test_long_boundary_length_12_applies(self):
        step = ReplayStep()
        out = OutStatus()
        result = step.run(out, "f.log", [], b"012345678901", (0, 0, None))
        self.assertIsNotNone(result)
        self.assertEqual(len(step.log_records), 0)

    def test_record_state_apply_and_head(self):
        state = RecordState()
        state.apply(b"ABCDEFGH rest")
        self.assertEqual(state.flag_24, 1)
        self.assertEqual(state.string, b"ABCDEFGH rest")
        self.assertEqual(state.head_qword(),
                         struct.unpack_from("<Q", b"ABCDEFGH", 0)[0])


class TestReadFail(unittest.TestCase):
    def test_read_fail_no_log_no_apply(self):
        step = ReplayStep()
        out = OutStatus()
        result = step.run(out, "f.log", [], None, (0, 0, None))
        self.assertEqual(result, 0)
        self.assertEqual(step.log_records, [])
        self.assertNotIn("record-apply", step.events)

    def test_read_fail_rule_one(self):
        step = ReplayStep()
        out = OutStatus()
        result = step.run(out, "f.log", [], None, (0, 0, None),
                          flag_7f=0, flag_7d=7)
        self.assertEqual(result, 1)


class TestPacket(unittest.TestCase):
    def test_packet_verify_passes(self):
        import subprocess
        proc = subprocess.run(
            ["python3", str(PACKET / "verify.py")],
            capture_output=True, text=True, cwd=PACKET.parents[2],
        )
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        self.assertIn("ALL CHECKS PASSED", proc.stdout)

    def test_excerpt_regeneration_is_stable(self):
        import subprocess
        import tempfile
        with tempfile.TemporaryDirectory() as tmp:
            for name in ("window.txt", "caller-site-1.txt", "caller-site-2.txt"):
                before = (PACKET / name).read_bytes()
                proc = subprocess.run(
                    ["python3", str(PACKET / "export_excerpts.py")],
                    capture_output=True, text=True, cwd=PACKET.parents[2],
                )
                self.assertEqual(proc.returncode, 0, proc.stderr)
                after = (PACKET / name).read_bytes()
                self.assertEqual(before, after, f"excerpt changed: {name}")
                _ = tmp

    def test_no_mnemonic_list_in_records(self):
        import json
        records = json.loads((PACKET / "records.json").read_text())
        blob = json.dumps(records)
        self.assertNotIn("mnemonic", blob)


if __name__ == "__main__":
    unittest.main()
