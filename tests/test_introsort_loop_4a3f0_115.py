"""Tests for the node #115 pair introsort loop model (0x5d4a3f0, RE-001)."""
import random
import unittest

from tools.introsort_loop_4a3f0_115 import (
    adjust_heap,
    heapsort,
    introsort_loop,
    median_to_first,
    partition,
)

U64 = (1 << 64) - 1


def is_max_heap(pairs):
    for i in range(1, len(pairs)):
        if pairs[(i - 1) // 2] < pairs[i]:
            return False
    return True


def insertion_sort(pairs):
    out = list(pairs)
    for i in range(1, len(out)):
        cur = out[i]
        j = i - 1
        while j >= 0 and out[j] > cur:
            out[j + 1] = out[j]
            j -= 1
        out[j + 1] = cur
    return out


class IntrosortLoopTest(unittest.TestCase):
    def test_empty_range_noop(self):
        self.assertEqual(introsort_loop([], 4), [])

    def test_small_range_unchanged(self):
        pairs = [(5, 5), (1, 1), (9, 9), (3, 3)]
        self.assertEqual(introsort_loop(pairs, 10), pairs)

    def test_sixteen_elements_unchanged(self):
        pairs = [(i, 100 - i) for i in range(16, 0, -1)]
        self.assertEqual(introsort_loop(pairs, 10), pairs)

    def test_depth_zero_large_sorts_fully(self):
        rng = random.Random(42)
        pairs = [(rng.randrange(50), rng.randrange(50))
                 for _ in range(40)]
        self.assertEqual(introsort_loop(pairs, 0), sorted(pairs))

    def test_loop_output_completed_by_insertion_sort(self):
        rng = random.Random(7)
        for size in (17, 20, 33, 64, 100):
            for depth in (0, 1, 2, 5, 20):
                pairs = [(rng.randrange(30), rng.randrange(30))
                         for _ in range(size)]
                out = introsort_loop(pairs, depth)
                self.assertEqual(sorted(out), sorted(pairs))
                self.assertEqual(insertion_sort(out), sorted(pairs))

    def test_loop_random_depths_preserve_permutation(self):
        rng = random.Random(1234)
        for _ in range(30):
            size = rng.randrange(17, 80)
            pairs = [(rng.randrange(1 << 63), rng.randrange(1 << 63))
                     for _ in range(size)]
            out = introsort_loop(pairs, rng.randrange(0, 12))
            self.assertEqual(sorted(out), sorted(pairs))
            self.assertEqual(insertion_sort(out), sorted(pairs))

    def test_unsigned_order_across_sign_boundary(self):
        pairs = [(U64, 0), (0, U64), (1 << 63, 1 << 63),
                 ((1 << 63) - 1, 0)] * 6
        out = introsort_loop(pairs, 0)
        self.assertEqual(out, sorted(pairs))

    def test_qword_guard(self):
        with self.assertRaises(ValueError):
            introsort_loop([(1 << 64, 0)] * 20, 0)


class MedianToFirstTest(unittest.TestCase):
    def test_median_moves_to_begin(self):
        rng = random.Random(99)
        for _ in range(200):
            vals = [(rng.randrange(20), rng.randrange(20))
                    for _ in range(3)]
            # Candidates sit exactly at p1=1, mid=12, last=24.
            size = 25
            pairs = [(i, i) for i in range(size)]
            mid = size // 2
            pairs[1] = vals[0]
            pairs[mid] = vals[1]
            pairs[size - 1] = vals[2]
            before = sorted(pairs)
            median_to_first(pairs, 0, size)
            self.assertEqual(pairs[0], sorted(vals)[1])
            self.assertEqual(sorted(pairs), before)

    def test_all_equal_candidates(self):
        pairs = [(4, 4)] * 25
        median_to_first(pairs, 0, 25)
        self.assertEqual(pairs, [(4, 4)] * 25)


class PartitionTest(unittest.TestCase):
    def test_partition_property(self):
        rng = random.Random(5)
        for _ in range(100):
            size = rng.randrange(17, 50)
            pairs = [(rng.randrange(20), rng.randrange(20))
                     for _ in range(size)]
            median_to_first(pairs, 0, size)
            pivot = pairs[0]
            cut = partition(pairs, 0, size)
            self.assertTrue(lo_ok(pairs, cut, pivot))
            self.assertTrue(hi_ok(pairs, cut, pivot))

    def test_partition_preserves_permutation(self):
        rng = random.Random(11)
        pairs = [(rng.randrange(10), rng.randrange(10))
                 for _ in range(30)]
        before = sorted(pairs)
        median_to_first(pairs, 0, 30)
        partition(pairs, 0, 30)
        self.assertEqual(sorted(pairs), before)


def lo_ok(pairs, cut, pivot):
    return all(p <= pivot for p in pairs[:cut])


def hi_ok(pairs, cut, pivot):
    return all(p >= pivot for p in pairs[cut:])


class AdjustHeapTest(unittest.TestCase):
    def test_adjust_restores_heap_and_multiset(self):
        rng = random.Random(3)
        for _ in range(100):
            size = rng.randrange(2, 40)
            heap = sorted(
                ((rng.randrange(30), rng.randrange(30))
                 for _ in range(size)), reverse=True)
            hole = rng.randrange(size)
            # Precondition: the value comes from the hole's own
            # subtree (so it is at most every ancestor above the
            # hole, as in the binary's heapify/pop uses).
            subtree = [hole]
            for i in list(subtree):
                for child in (2 * i + 1, 2 * i + 2):
                    if child < size:
                        subtree.append(child)
            value = heap[rng.choice(subtree)]
            arr = list(heap)
            adjust_heap(arr, 0, hole, size, value)
            self.assertTrue(is_max_heap(arr))
            self.assertEqual(sorted(arr),
                             sorted(heap[:hole] + heap[hole + 1:]
                                    + [value]))

    def test_adjust_even_length_lone_child(self):
        # Length 4, hole 1 == (4 - 2) // 2: the lone left child at
        # index 3 must move up before the push-up phase.
        arr = [(30, 0), (0, 0), (20, 0), (25, 0)]
        adjust_heap(arr, 0, 1, 4, (5, 0))
        self.assertTrue(is_max_heap(arr))
        self.assertEqual(sorted(arr),
                         sorted([(30, 0), (20, 0), (25, 0), (5, 0)]))

    def test_adjust_tie_prefers_right_child(self):
        # Children equal: the right child moves up, so the hole
        # ends at the right child's index and the value lands there
        # only if it is not pushed back up.
        arr = [(0, 0), (9, 9), (9, 9)]
        adjust_heap(arr, 0, 0, 3, (1, 1))
        self.assertEqual(arr[0], (9, 9))
        self.assertTrue(is_max_heap(arr))


class HeapsortTest(unittest.TestCase):
    def test_heapsort_random(self):
        rng = random.Random(21)
        for size in (17, 18, 25, 50, 101):
            pairs = [(rng.randrange(40), rng.randrange(40))
                     for _ in range(size)]
            arr = list(pairs)
            heapsort(arr, 0, size)
            self.assertEqual(arr, sorted(pairs))

    def test_heapsort_subrange(self):
        pairs = [(9, 1), (8, 2)] + [(5, 5)] * 20 + [(1, 9)]
        arr = list(pairs)
        heapsort(arr, 2, 22)
        self.assertEqual(arr[2:22], sorted([(5, 5)] * 20))
        self.assertEqual(arr[:2], [(9, 1), (8, 2)])
        self.assertEqual(arr[22:], [(1, 9)])


if __name__ == "__main__":
    unittest.main()
