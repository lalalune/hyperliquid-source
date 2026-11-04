"""Tests for the node #115 sorted-unique clear model (0x5d50470, RE-001)."""
import unittest

from tools.sorted_unique_clear_50470_115 import (
    NullObjectError, clear_container)


def new_tracker():
    return {"disposed": [], "head_calls": [], "chain_calls": [],
            "chain_deleted": []}


def obj(flag=True, pairs=(), capacity=64, buffer=True,
        head=None, head_args=(0, 0), chain=()):
    return {"flag": flag, "pairs": list(pairs),
            "capacity_bytes": capacity, "buffer_present": buffer,
            "head": head, "head_args": head_args,
            "chain": list(chain)}


class SortedUniqueClearTest(unittest.TestCase):
    def test_flag_clear_frees_only(self):
        tracker = new_tracker()
        o = obj(flag=False, pairs=[(9, 90)], head="h", head_args=(1, 2),
                chain=[{"func": "c1", "args": (3, 4)}])
        out = clear_container(o, tracker)
        self.assertEqual(tracker["disposed"], [])
        self.assertEqual(tracker["head_calls"], [])
        self.assertEqual(tracker["chain_calls"], [])
        self.assertEqual(out, {"freed_bytes": 64, "tail": True})
        self.assertEqual(o["head"], "h")  # untouched on this path
        self.assertEqual(len(o["chain"]), 1)
        self.assertFalse(o["flag"])

    def test_empty_range_flag_set_runs_virtual_phase(self):
        tracker = new_tracker()
        o = obj(flag=True, pairs=[], head="h", head_args=(10, 20),
                chain=[{"func": "c1", "args": (30, 40)}])
        out = clear_container(o, tracker)
        self.assertEqual(tracker["disposed"], [])
        self.assertEqual(tracker["head_calls"], [("h", 10, 20)])
        self.assertEqual(tracker["chain_calls"], [("c1", 30, 40)])
        self.assertEqual(tracker["chain_deleted"], [32])
        self.assertIsNone(o["head"])
        self.assertEqual(o["chain"], [])
        self.assertEqual(out["freed_bytes"], 64)

    def test_sort_unique_dispose_order(self):
        tracker = new_tracker()
        o = obj(pairs=[(5, 50), (2, 20), (5, 50), (1, 10), (2, 21),
                       (5, 49)])
        clear_container(o, tracker)
        # Sorted: (1,10),(2,20),(2,21),(5,49),(5,50),(5,50);
        # the duplicate (5,50) is disposed once.
        self.assertEqual(tracker["disposed"],
                         [(1, 10), (2, 20), (2, 21), (5, 49), (5, 50)])
        self.assertEqual(o["pairs"], [])

    def test_no_duplicates_all_disposed_sorted(self):
        tracker = new_tracker()
        o = obj(pairs=[(9, 1), (3, 7), (4, 4)])
        clear_container(o, tracker)
        self.assertEqual(tracker["disposed"], [(3, 7), (4, 4), (9, 1)])

    def test_single_element(self):
        tracker = new_tracker()
        o = obj(pairs=[(7, 70)])
        clear_container(o, tracker)
        self.assertEqual(tracker["disposed"], [(7, 70)])

    def test_all_duplicates_disposed_once(self):
        tracker = new_tracker()
        o = obj(pairs=[(4, 40), (4, 40), (4, 40)])
        clear_container(o, tracker)
        self.assertEqual(tracker["disposed"], [(4, 40)])

    def test_duplicate_at_end(self):
        tracker = new_tracker()
        o = obj(pairs=[(1, 10), (2, 20), (2, 20)])
        clear_container(o, tracker)
        self.assertEqual(tracker["disposed"], [(1, 10), (2, 20)])

    def test_same_first_different_second_both_kept(self):
        tracker = new_tracker()
        o = obj(pairs=[(5, 51), (5, 50)])
        clear_container(o, tracker)
        self.assertEqual(tracker["disposed"], [(5, 50), (5, 51)])

    def test_chain_order_and_delete_sizes(self):
        tracker = new_tracker()
        o = obj(pairs=[], head="h", head_args=(1, 2),
                chain=[{"func": "c1", "args": (3, 4)},
                       {"func": "c2", "args": (5, 6)}])
        clear_container(o, tracker)
        self.assertEqual(tracker["head_calls"], [("h", 1, 2)])
        self.assertEqual(tracker["chain_calls"],
                         [("c1", 3, 4), ("c2", 5, 6)])
        self.assertEqual(tracker["chain_deleted"], [32, 32])

    def test_null_head_skips_head_and_chain(self):
        # 0x5d505a4: a null head jumps straight to 0x5d505e4, which
        # zeroes +0x00 and +0x18 without walking the +0x18 chain, so
        # the chain nodes are abandoned, never called or deleted.
        tracker = new_tracker()
        o = obj(pairs=[], head=None,
                chain=[{"func": "c1", "args": (3, 4)}])
        clear_container(o, tracker)
        self.assertEqual(tracker["head_calls"], [])
        self.assertEqual(tracker["chain_calls"], [])
        self.assertEqual(tracker["chain_deleted"], [])
        self.assertEqual(o["chain"], [])  # pointer zeroed, nodes abandoned

    def test_no_buffer_nothing_freed(self):
        tracker = new_tracker()
        o = obj(pairs=[], buffer=False)
        out = clear_container(o, tracker)
        self.assertIsNone(out["freed_bytes"])
        self.assertTrue(out["tail"])

    def test_second_clear_frees_again(self):
        # The routine never clears +0x28, so a flag-cleared object
        # frees its buffer again on a second clear.
        tracker = new_tracker()
        o = obj(flag=True, pairs=[])
        clear_container(o, tracker)
        out = clear_container(o, tracker)
        self.assertEqual(out["freed_bytes"], 64)
        self.assertEqual(tracker["head_calls"], [])

    def test_null_object_guard(self):
        with self.assertRaises(NullObjectError):
            clear_container(None, new_tracker())


if __name__ == "__main__":
    unittest.main()
