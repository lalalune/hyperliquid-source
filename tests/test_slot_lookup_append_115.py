#!/usr/bin/env python3
"""Tests for tools/slot_lookup_append_115.py (node #115 RE-001 windows
0x5f45cf0, 0x5f6b620, 0x5f78060).

Run under plain python3 (pytest is not installed on this VM):
  python3 tests/test_slot_lookup_append_115.py
"""
import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "tools"))
from slot_lookup_append_115 import (
    SlotLookupError,
    make_accumulator,
    make_element,
    make_group,
    make_slot,
    slot_lookup,
)


def run_case(slot, element=None, groups=None, index=0, acc=None):
    element = element if element is not None else make_element()
    acc = acc if acc is not None else make_accumulator(groups or [make_group()])
    return slot_lookup([slot], acc, element, index), acc, element


class TestStage1(unittest.TestCase):
    def test_hit_flag_set_updates_totals(self):
        slot = make_slot(mode1=0, chain1=[7, 9])
        element = make_element(key=9, lo=30, hi=100, ref=5, flag=1)
        acc = make_accumulator([make_group()])
        acc["fb0"], acc["fb8"], acc["fc0"] = 1000, 500, 10
        outcome, acc, element = run_case(slot, element, acc=acc)
        self.assertEqual(outcome, "leaf")
        self.assertEqual(acc["fb0"], 1000 + 100 - 30)
        self.assertEqual(acc["fb8"], 500 - 100)
        self.assertEqual(acc["fc0"], 9)
        self.assertEqual(element["ref"], 5)  # leaf never touches +0xb0

    def test_hit_flag_clear_is_noop(self):
        slot = make_slot(mode1=0, chain1=[9])
        element = make_element(key=9, lo=30, hi=100, flag=0)
        acc = make_accumulator([make_group()])
        acc["fb0"], acc["fb8"], acc["fc0"] = 1000, 500, 10
        outcome, acc, _ = run_case(slot, element, acc=acc)
        self.assertEqual(outcome, "leaf")
        self.assertEqual((acc["fb0"], acc["fb8"], acc["fc0"]),
                         (1000, 500, 10))

    def test_miss_falls_through_to_append(self):
        slot = make_slot(mode1=0, chain1=[7], mode2=0, list2=[])
        element = make_element(key=9, ref=0, flag=1)
        group = make_group(cap=2)
        outcome, acc, element = run_case(
            slot, element, groups=[group])
        self.assertEqual(outcome, "append")
        self.assertEqual(group["items"], [element])
        self.assertEqual(element["ref"], 1)

    def test_leaf_wraps(self):
        slot = make_slot(mode1=0, chain1=[3])
        element = make_element(key=3, lo=50, hi=20, flag=1)
        acc = make_accumulator([make_group()])
        acc["fb0"], acc["fb8"] = 10, 5
        _, acc, _ = run_case(slot, element, acc=acc)
        self.assertEqual(acc["fb0"], (10 + 20 - 50) % (1 << 64))
        self.assertEqual(acc["fb8"], (5 - 20) % (1 << 64))


class TestStage2(unittest.TestCase):
    def test_first_record_hit(self):
        slot = make_slot(mode1=1, count1=4, table1={1: [9, 5]})
        element = make_element(key=9, lo=0, hi=7, flag=1)
        acc = make_accumulator([make_group()])
        outcome, _, _ = run_case(slot, element, acc=acc)
        self.assertEqual(outcome, "leaf")

    def test_chain_hit_bucket_consistent(self):
        # key 9, count 4 -> bucket 1; chain [5, 9]: 5 % 4 == 1 ok.
        slot = make_slot(mode1=1, count1=4, table1={1: [5, 9]})
        element = make_element(key=9, lo=0, hi=7, flag=1)
        acc = make_accumulator([make_group()])
        outcome, _, _ = run_case(slot, element, acc=acc)
        self.assertEqual(outcome, "leaf")

    def test_chain_bucket_mismatch_falls_through_to_append(self):
        # key 9, count 4 -> bucket 1; chain [5, 6]: 6 % 4 == 2 != 1,
        # so the walk abandons stage 2 and the empty list appends.
        slot = make_slot(mode1=1, count1=4, table1={1: [5, 6]},
                         mode2=0, list2=[])
        element = make_element(key=9, ref=0, flag=1)
        group = make_group(cap=2)
        outcome, _, element = run_case(slot, element, groups=[group])
        self.assertEqual(outcome, "append")
        self.assertEqual(group["items"], [element])

    def test_null_bucket_falls_through_to_stage3_leaf(self):
        element = make_element(key=9, lo=0, hi=7, flag=1)
        other = make_element(key=9)
        slot = make_slot(mode1=1, count1=4, table1={},
                         mode2=1, count2=4,
                         table2={1: [{"key": 9, "owner": other}]})
        acc = make_accumulator([make_group()])
        outcome, _, _ = run_case(slot, element, acc=acc)
        self.assertEqual(outcome, "leaf")


class TestStage3AndList(unittest.TestCase):
    def test_stage3_owner_differs_is_leaf(self):
        element = make_element(key=9, lo=0, hi=7, flag=1)
        other = make_element(key=9)
        slot = make_slot(mode1=0, chain1=[], mode2=1, count2=4,
                         table2={1: [{"key": 9, "owner": other}]})
        acc = make_accumulator([make_group()])
        outcome, _, _ = run_case(slot, element, acc=acc)
        self.assertEqual(outcome, "leaf")

    def test_stage3_owner_same_is_append(self):
        element = make_element(key=9, ref=2, flag=1)
        slot = make_slot(mode1=0, chain1=[], mode2=1, count2=4,
                         table2={1: [{"key": 9, "owner": element}]})
        group = make_group(cap=2)
        outcome, _, element = run_case(slot, element, groups=[group])
        self.assertEqual(outcome, "append")
        self.assertEqual(group["items"], [element])
        self.assertEqual(element["ref"], 3)

    def test_stage3_miss_is_append(self):
        element = make_element(key=9, ref=0, flag=1)
        slot = make_slot(mode1=0, chain1=[], mode2=1, count2=4,
                         table2={1: [{"key": 5, "owner": element}]})
        group = make_group(cap=2)
        outcome, _, _ = run_case(slot, element, groups=[group])
        self.assertEqual(outcome, "append")

    def test_list_owner_differs_is_leaf(self):
        element = make_element(key=9, lo=0, hi=7, flag=1)
        other = make_element(key=9)
        slot = make_slot(mode1=0, chain1=[], mode2=0,
                         list2=[{"key": 9, "owner": other}])
        acc = make_accumulator([make_group()])
        outcome, _, _ = run_case(slot, element, acc=acc)
        self.assertEqual(outcome, "leaf")

    def test_append_grow_path(self):
        element = make_element(key=9, ref=4, flag=1)
        group = make_group(items=[make_element()], cap=1)
        slot = make_slot(mode1=0, chain1=[], mode2=0, list2=[])
        outcome, _, element = run_case(slot, element, groups=[group])
        self.assertEqual(outcome, "append")
        self.assertEqual(group["items"][-1], element)
        self.assertEqual(element["ref"], 5)
        self.assertGreaterEqual(group["cap"], len(group["items"]))


class TestMaskAndGuards(unittest.TestCase):
    def test_key_mask_applied(self):
        # Raw key 0x4000000000000009 masks to 9, matching the chain.
        slot = make_slot(mode1=0, chain1=[9])
        element = make_element(key=0x4000000000000009, lo=0, hi=1, flag=1)
        acc = make_accumulator([make_group()])
        outcome, _, _ = run_case(slot, element, acc=acc)
        self.assertEqual(outcome, "leaf")

    def test_zero_count_traps(self):
        slot = make_slot(mode1=1, count1=0, table1={})
        with self.assertRaises(SlotLookupError):
            run_case(slot)
        slot = make_slot(mode1=0, chain1=[], mode2=1, count2=0,
                         table2={})
        with self.assertRaises(SlotLookupError):
            run_case(slot)

    def test_bad_index_guards(self):
        slot = make_slot(mode1=0, chain1=[9])
        element = make_element(key=9)
        acc = make_accumulator([make_group()])
        with self.assertRaises(SlotLookupError):
            slot_lookup([slot], acc, element, -1)
        with self.assertRaises(SlotLookupError):
            slot_lookup([slot], acc, element, 1)


if __name__ == "__main__":
    unittest.main()
