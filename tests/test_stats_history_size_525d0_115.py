"""Tests for the node #115 in-memory stats history size model
(tools/stats_history_size_525d0_115.py, routine 0x5d525d0, RE-001)."""
import unittest

from tools.stats_history_size_525d0_115 import (
    Entry,
    History,
    Slice,
    post_gc_log_line,
    pre_gc_log_line,
    stats_history_size,
    trim_history,
)


def hist(*slices):
    return History([Slice(entries) for entries in slices])


class TestStatsHistorySize(unittest.TestCase):
    def test_empty_history_returns_48(self):
        self.assertEqual(stats_history_size(hist()), 48)

    def test_one_empty_slice(self):
        self.assertEqual(stats_history_size(hist([])), 56)

    def test_one_sso_entry(self):
        self.assertEqual(stats_history_size(hist([Entry(True)])), 56 + 55)

    def test_one_heap_entry(self):
        self.assertEqual(stats_history_size(hist([Entry(False, 100)])), 56 + 140)

    def test_heap_capacity_zero(self):
        self.assertEqual(stats_history_size(hist([Entry(False, 0)])), 56 + 40)

    def test_sso_ignores_capacity(self):
        # The binary never reads a capacity for an SSO string.
        entry = Entry(True)
        entry.capacity = 9999
        self.assertEqual(stats_history_size(hist([entry])), 56 + 55)

    def test_mixed_entries(self):
        entries = [Entry(True), Entry(False, 20), Entry(False, 0)]
        self.assertEqual(stats_history_size(hist(entries)), 56 + 55 + 60 + 40)

    def test_only_oldest_slice_is_walked(self):
        # Two slices: the second slice's huge entry must not count;
        # the sum comes from the oldest slice only, times the count.
        history = hist([Entry(True)], [Entry(False, 1000)])
        self.assertEqual(stats_history_size(history), 2 * (56 + 55))

    def test_count_multiplies_oldest_sum(self):
        history = hist([Entry(False, 10)], [], [])
        self.assertEqual(stats_history_size(history), 3 * (56 + 50))

    def test_negative_capacity_rejected(self):
        with self.assertRaises(ValueError):
            Entry(False, -1)

    def test_pre_gc_log_line(self):
        history = hist([Entry(True)])
        self.assertEqual(
            pre_gc_log_line(history),
            "[db/db_impl/db_impl.cc:976] [Pre-GC] In-memory stats history size: 111 bytes, slice count: 1")

    def test_post_gc_log_line(self):
        history = hist([Entry(False, 100)])
        self.assertEqual(
            post_gc_log_line(history),
            "[db/db_impl/db_impl.cc:985] [Post-GC] In-memory stats history size: 196 bytes, slice count: 1")

    def test_trim_noop_when_under_limit(self):
        history = hist([Entry(True)])
        lines = trim_history(history, 1000)
        self.assertEqual(len(history.slices), 1)
        self.assertIn("[Pre-GC]", lines[0])
        self.assertIn("[Post-GC]", lines[1])
        self.assertIn("111 bytes, slice count: 1", lines[1])

    def test_trim_erases_oldest_until_under_limit(self):
        # Sizes: 3 slices, oldest [heap 100] -> 3*196=588; after
        # erasing oldest, 2 slices over [SSO] -> 2*111=222; limit 300
        # stops after one erase.
        history = hist([Entry(False, 100)], [Entry(True)], [Entry(True)])
        lines = trim_history(history, 300)
        self.assertEqual(len(history.slices), 2)
        self.assertIn("588 bytes, slice count: 3", lines[0])
        self.assertIn("222 bytes, slice count: 2", lines[1])

    def test_trim_to_empty_when_limit_tiny(self):
        history = hist([Entry(True)], [Entry(True)])
        lines = trim_history(history, 0)
        self.assertEqual(len(history.slices), 0)
        # Zero slices returns the binary's 48 constant.
        self.assertIn("48 bytes, slice count: 0", lines[1])

    def test_trim_at_exact_limit_is_noop(self):
        history = hist([Entry(True)])
        trim_history(history, 111)
        self.assertEqual(len(history.slices), 1)


if __name__ == "__main__":
    unittest.main()
