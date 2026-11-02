"""Tests for the node #94 timed snapshot refresh model (0x514f270)."""

import struct
import subprocess
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
import foundation_timed_snapshot as subject

REPO = Path(__file__).resolve().parents[1]
PACKET = REPO / "research" / "work-items" / "RE-001-timed-snapshot-94"

CLOCK_CELL = "clock-sentinel"
CONSUMER_CELL = "consumer-sentinel"


def builder(snapshot, clock_value):
    """Stand-in for the 0x514ed50 snapshot builder.

    The binary passes the RAW clock value in rcx (copied at 0x514f34f
    before the elapsed subtraction), so +0x128 holds the clock value,
    not the elapsed value (regression: slopbot review of PR #1665)."""
    snapshot["bytes"][0x128:0x130] = (clock_value & subject.MASK64).to_bytes(
        8, "little")
    snapshot["bytes"][0x120:0x124] = (41).to_bytes(4, "little")
    snapshot["string"] = "name@0x1234#99"


def fresh_state():
    inner = {0x2C0: 1000, 0x2C8: 1000}
    return subject.TimedSnapshot(inner)


def clock_chain(values):
    """Chain nodes with the given slot values, each returning 5000."""
    return [subject.make_node(slot, 5000) for slot in values]


class ThresholdTests(unittest.TestCase):
    def test_flag_zero_thresholds(self):
        self.assertEqual(subject.thresholds_for(0), (500, 180000000))

    def test_flag_nonzero_thresholds(self):
        for flag in (1, 2, 255):
            self.assertEqual(subject.thresholds_for(flag), (10, 10000000))


class RefreshTests(unittest.TestCase):
    def test_null_inner_is_noop(self):
        snap = subject.TimedSnapshot(None)
        result = snap.refresh(0, clock_chain([CLOCK_CELL]),
                              [subject.make_node("consumer-live", None)],
                              builder, CLOCK_CELL, CONSUMER_CELL)
        self.assertEqual(result, "noop")
        self.assertEqual(snap.events, [])

    def test_snapshot_path_end_to_end(self):
        snap = fresh_state()
        # Clock value 5000, last commit 1000: elapsed 4000 > 10? No:
        # flag 0 limit is 180000000, so use a huge clock value.
        clock = [subject.make_node("clock-value", 200000000)]
        result = snap.refresh(0, clock,
                              [subject.make_node("consumer-live", None)],
                              builder, CLOCK_CELL, CONSUMER_CELL)
        self.assertEqual(result, "snapshot")
        self.assertEqual(snap.inner[0x2C0], 200000000)
        # Commit calls the clock head directly again: same value.
        self.assertEqual(snap.inner[0x2C8], 200000000)
        # +0x128 holds the RAW clock value, not elapsed (200000000 - 1000).
        self.assertEqual(
            int.from_bytes(snap.working[0x128:0x130], "little"),
            200000000)
        self.assertEqual(
            int.from_bytes(snap.working[0x130:0x138], "little"),
            200000000)
        self.assertEqual(snap.published_string, "name@0x1234#99")
        self.assertEqual(snap.published[0x120:0x124], (41).to_bytes(4,
                                                                 "little"))
        # The string object bytes are not raw-copied into published.
        self.assertEqual(snap.published[0x20:0x40], bytes(32))
        self.assertEqual(snap.events,
                         ["lock_a", "consumer_called", "lock_b",
                          "unlock_b", "unlock_a"])

    def test_skip_path_increments_counter_only(self):
        snap = fresh_state()
        snap.working[0x124:0x128] = (7).to_bytes(4, "little")
        clock = [subject.make_node("clock-value", 1500)]
        result = snap.refresh(1, clock,
                              [subject.make_node("consumer-live", None)],
                              builder, CLOCK_CELL, CONSUMER_CELL)
        # Elapsed 500 <= 10000000: skip.
        self.assertEqual(result, "skip")
        self.assertEqual(int.from_bytes(snap.working[0x124:0x128],
                                        "little"), 8)
        # No rebuild: the builder's counter mark and string are absent,
        # no commit store, and the commit timestamp is untouched.
        self.assertEqual(snap.working[0x120:0x124], bytes(4))
        self.assertEqual(snap.inner[0x2C8], 1000)
        self.assertEqual(snap.working[0x130:0x138], bytes(8))
        self.assertEqual(snap.published[0x124:0x128],
                         (8).to_bytes(4, "little"))
        self.assertNotIn("consumer_called", snap.events)

    def test_boundary_elapsed_equals_limit_skips(self):
        snap = fresh_state()
        clock = [subject.make_node("clock-value", 1000 + 10000000)]
        result = snap.refresh(1, clock,
                              [subject.make_node("consumer-live", None)],
                              builder, CLOCK_CELL, CONSUMER_CELL)
        self.assertEqual(result, "skip")

    def test_boundary_elapsed_one_over_limit_snapshots(self):
        snap = fresh_state()
        clock = [subject.make_node("clock-value", 1000 + 10000001)]
        result = snap.refresh(1, clock,
                              [subject.make_node("consumer-live", None)],
                              builder, CLOCK_CELL, CONSUMER_CELL)
        self.assertEqual(result, "snapshot")

    def test_stale_adjustment_inflates_threshold(self):
        # last_snapshot 1000 < last_commit 3000: gap 2000 * count 10
        # = 20000 > 10000000? No: 20000 < 10000000, so no inflation.
        # Use a bigger gap: last_commit 3000000, gap 2999000 * 10
        # = 29990000 > 10000000, so the threshold becomes 29990000.
        inner = {0x2C0: 1000, 0x2C8: 3000000}
        snap = subject.TimedSnapshot(inner)
        clock = [subject.make_node("clock-value", 3000000 + 20000000)]
        result = snap.refresh(1, clock,
                              [subject.make_node("consumer-live", None)],
                              builder, CLOCK_CELL, CONSUMER_CELL)
        # Elapsed 20000000 <= inflated 29990000: skip.
        self.assertEqual(result, "skip")
        self.assertIn("stale_adjust", snap.events)

    def test_stale_adjustment_below_limit_keeps_limit(self):
        inner = {0x2C0: 1000, 0x2C8: 2000}
        snap = subject.TimedSnapshot(inner)
        clock = [subject.make_node("clock-value", 2000 + 10000001)]
        result = snap.refresh(1, clock,
                              [subject.make_node("consumer-live", None)],
                              builder, CLOCK_CELL, CONSUMER_CELL)
        # Gap 1000 * 10 = 10000 < 10000000: threshold unchanged, and
        # elapsed 10000001 > 10000000: snapshot.
        self.assertEqual(result, "snapshot")
        self.assertIn("stale_adjust", snap.events)

    def test_skip_counter_wraps_32_bit(self):
        snap = fresh_state()
        snap.working[0x124:0x128] = (0xFFFFFFFF).to_bytes(4, "little")
        clock = [subject.make_node("clock-value", 1500)]
        snap.refresh(1, clock, [subject.make_node("consumer-live", None)],
                     builder, CLOCK_CELL, CONSUMER_CELL)
        self.assertEqual(snap.working[0x124:0x128], bytes(4))

    def test_post_call_callback_arm(self):
        snap = fresh_state()

        def cb_builder(snapshot, clock_value):
            builder(snapshot, clock_value)
            snapshot["callback"] = 1

        clock = [subject.make_node("clock-value", 200000000)]
        snap.refresh(0, clock, [subject.make_node("consumer-live", None)],
                     cb_builder, CLOCK_CELL, CONSUMER_CELL)
        self.assertIn("post_call_callback", snap.events)

    def test_post_call_callback_absent_when_zero(self):
        snap = fresh_state()
        clock = [subject.make_node("clock-value", 200000000)]
        snap.refresh(0, clock, [subject.make_node("consumer-live", None)],
                     builder, CLOCK_CELL, CONSUMER_CELL)
        self.assertNotIn("post_call_callback", snap.events)


class ChainWalkTests(unittest.TestCase):
    def test_clock_dispatch_at_each_position(self):
        for position in range(4):
            slots = [CLOCK_CELL] * position + ["live"]
            nodes = [subject.make_node(slot, 7000 + position)
                     for slot in slots]
            value, visited = subject._walk_chain(
                nodes, CLOCK_CELL, subject.CLOCK_MAX_NODES)
            self.assertEqual(value, 7000 + position)
            self.assertEqual(visited, position + 1)

    def test_clock_fourth_node_unconditional(self):
        nodes = [subject.make_node(CLOCK_CELL, 1111) for _ in range(4)]
        value, visited = subject._walk_chain(
            nodes, CLOCK_CELL, subject.CLOCK_MAX_NODES)
        self.assertEqual(value, 1111)
        self.assertEqual(visited, 4)

    def test_clock_chain_exhaustion(self):
        nodes = [subject.make_node(CLOCK_CELL, 1111) for _ in range(3)]
        with self.assertRaises(subject.ChainExhausted):
            subject._walk_chain(nodes, CLOCK_CELL,
                                subject.CLOCK_MAX_NODES)

    def test_consumer_eleventh_node_unconditional(self):
        nodes = [subject.make_node(CONSUMER_CELL, 2222)
                 for _ in range(11)]
        value, visited = subject._walk_chain(
            nodes, CONSUMER_CELL, subject.CONSUMER_MAX_NODES)
        self.assertEqual(value, 2222)
        self.assertEqual(visited, 11)

    def test_consumer_dispatch_at_position_six(self):
        slots = [CONSUMER_CELL] * 5 + ["live"]
        nodes = [subject.make_node(slot, 3333) for slot in slots]
        value, visited = subject._walk_chain(
            nodes, CONSUMER_CELL, subject.CONSUMER_MAX_NODES)
        self.assertEqual(value, 3333)
        self.assertEqual(visited, 6)

    def test_consumer_chain_exhaustion(self):
        nodes = [subject.make_node(CONSUMER_CELL, 4444)
                 for _ in range(10)]
        with self.assertRaises(subject.ChainExhausted):
            subject._walk_chain(nodes, CONSUMER_CELL,
                                subject.CONSUMER_MAX_NODES)


class PacketTests(unittest.TestCase):
    def test_packet_verification(self):
        result = subprocess.run(
            [sys.executable, str(PACKET / "verify.py"),
             "--binary", "work/hl-node-94.bin"],
            cwd=str(REPO), capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stdout)
        self.assertIn("ALL CHECKS PASSED", result.stdout)

    def test_excerpt_regeneration(self):
        import tempfile
        with tempfile.TemporaryDirectory() as tmp:
            result = subprocess.run(
                [sys.executable, str(PACKET / "export_excerpts.py"),
                 "--binary", "work/hl-node-94.bin", "--out", tmp],
                cwd=str(REPO), capture_output=True, text=True)
            # Only checks the script runs; byte equality is covered by
            # verify.py's own regeneration check.
            self.assertEqual(result.returncode, 0, result.stderr)


if __name__ == "__main__":
    unittest.main()
