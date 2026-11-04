"""Tests for the node #115 pair insertion sort model (0x5d497e0, RE-001)."""
import random
import unittest

from tools.pair_insertion_sort_497e0_115 import insertion_sort

U64 = (1 << 64) - 1


class PairInsertionSortTest(unittest.TestCase):
    def test_empty_range_noop(self):
        self.assertEqual(insertion_sort([]), [])

    def test_single_element_noop(self):
        self.assertEqual(insertion_sort([(7, 70)]), [(7, 70)])

    def test_two_elements_swap(self):
        self.assertEqual(insertion_sort([(5, 50), (2, 20)]),
                         [(2, 20), (5, 50)])

    def test_two_elements_already_sorted(self):
        self.assertEqual(insertion_sort([(2, 20), (5, 50)]),
                         [(2, 20), (5, 50)])

    def test_equal_first_orders_by_second(self):
        self.assertEqual(insertion_sort([(5, 50), (5, 20), (5, 35)]),
                         [(5, 20), (5, 35), (5, 50)])

    def test_equal_pairs_unchanged(self):
        pairs = [(4, 40), (4, 40), (4, 40)]
        self.assertEqual(insertion_sort(pairs), pairs)

    def test_reverse_sorted(self):
        pairs = [(5, 5), (4, 4), (3, 3), (2, 2), (1, 1)]
        self.assertEqual(insertion_sort(pairs),
                         [(1, 1), (2, 2), (3, 3), (4, 4), (5, 5)])

    def test_smallest_last_takes_begin_insert_path(self):
        # The binary's 0x5d49852 block: a current pair strictly less
        # than the begin element shifts the whole prefix right.
        pairs = [(9, 1), (8, 2), (7, 3), (1, 9)]
        self.assertEqual(insertion_sort(pairs),
                         [(1, 9), (7, 3), (8, 2), (9, 1)])

    def test_unsigned_order_across_sign_boundary(self):
        # Unsigned comparison: 2**63 sorts after 2**63 - 1, and
        # 2**64 - 1 sorts last, not first.
        pairs = [(U64, 0), (0, U64), (1 << 63, 1 << 63),
                 ((1 << 63) - 1, 0)]
        self.assertEqual(insertion_sort(pairs),
                         [(0, U64), ((1 << 63) - 1, 0),
                          (1 << 63, 1 << 63), (U64, 0)])

    def test_sixteen_elements_full_small_range(self):
        # The callers pass at most 16 elements to this helper.
        pairs = [(i, 100 - i) for i in range(16, 0, -1)]
        self.assertEqual(insertion_sort(pairs),
                         sorted(pairs))

    def test_twenty_elements_beyond_caller_cap(self):
        # The routine itself has no length cap; callers cap at 16
        # only by their own argument setup.
        pairs = [(i % 5, i) for i in range(20, 0, -1)]
        self.assertEqual(insertion_sort(pairs), sorted(pairs))

    def test_random_against_python_sorted(self):
        rng = random.Random(115)
        pairs = [(rng.getrandbits(64), rng.getrandbits(64))
                 for _ in range(64)]
        self.assertEqual(insertion_sort(pairs), sorted(pairs))

    def test_input_not_mutated(self):
        pairs = [(3, 30), (1, 10), (2, 20)]
        insertion_sort(pairs)
        self.assertEqual(pairs, [(3, 30), (1, 10), (2, 20)])

    def test_qword_guard(self):
        with self.assertRaises(ValueError):
            insertion_sort([(1 << 64, 0)])


if __name__ == "__main__":
    unittest.main()
