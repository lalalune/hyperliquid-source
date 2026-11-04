"""Tests for the node #115 flag-gated range reverse and sum threshold
model (tools/reversed_sum_threshold_532e0_115.py, routine 0x5d532e0,
RE-001)."""
import unittest

from tools.reversed_sum_threshold_532e0_115 import (
    Holder,
    check,
    consumer_branch,
    evaluate_range,
    reverse_in_place,
    sum_second_fields,
)


def el(first, second):
    return (first, second)


class TestReverse(unittest.TestCase):
    def test_empty_reverses_to_itself(self):
        self.assertEqual(reverse_in_place([]), [])

    def test_singleton_reverses_to_itself(self):
        self.assertEqual(reverse_in_place([el(1, 2)]), [el(1, 2)])

    def test_pair_swaps(self):
        self.assertEqual(reverse_in_place([el(1, 10), el(2, 20)]),
                         [el(2, 20), el(1, 10)])

    def test_odd_length_middle_stays(self):
        elems = [el(1, 10), el(2, 20), el(3, 30)]
        self.assertEqual(reverse_in_place(elems),
                         [el(3, 30), el(2, 20), el(1, 10)])

    def test_even_length_full_reverse(self):
        elems = [el(i, i * 10) for i in range(4)]
        self.assertEqual(reverse_in_place(elems), list(reversed(elems)))


class TestSum(unittest.TestCase):
    def test_first_fields_ignored(self):
        self.assertEqual(sum_second_fields([el(999, 5), el(1, 7)]), 12)

    def test_empty_sum_is_zero(self):
        self.assertEqual(sum_second_fields([]), 0)

    def test_wraps_mod_2_to_64(self):
        self.assertEqual(
            sum_second_fields([el(0, 1 << 63), el(0, 1 << 63)]), 0)

    def test_out_of_range_rejected(self):
        with self.assertRaises(ValueError):
            sum_second_fields([el(0, 1 << 64)])


class TestThreshold(unittest.TestCase):
    def test_at_threshold_is_false(self):
        self.assertFalse(evaluate_range([el(0, 0x7FFF)]))

    def test_just_above_threshold_small_count_is_true(self):
        # 0x8000 >> 8 == 0x80 == 128 >= 1.
        self.assertTrue(evaluate_range([el(0, 0x8000)]))

    def test_scaled_sum_below_count_is_false(self):
        # 0x8000 >> 8 == 128 < 129 elements.
        self.assertFalse(evaluate_range([el(0, 1)] * 129
                                        + [el(0, 0x8000 - 129)]))

    def test_scaled_sum_equal_count_is_true(self):
        # Sum 0x8000 over 128 elements: 128 >= 128.
        elems = [el(0, 0x40)] * 127 + [el(0, 0x8000 - 127 * 0x40)]
        self.assertEqual(len(elems), 128)
        self.assertTrue(evaluate_range(elems))

    def test_two_element_small_path(self):
        self.assertFalse(evaluate_range([el(0, 100), el(0, 200)]))
        self.assertTrue(evaluate_range([el(0, 0x8000), el(0, 0x8000)]))

    def test_many_elements_simd_shape(self):
        # 19 elements: SIMD pairs plus a one-element tail in the
        # binary; the model sums the same set either way.
        elems = [el(i, 0x1000) for i in range(19)]
        self.assertTrue(evaluate_range(elems))
        elems = [el(i, 10) for i in range(19)]
        self.assertFalse(evaluate_range(elems))


class TestCheck(unittest.TestCase):
    def test_flag_set_reverses_and_clears(self):
        holder = Holder([el(1, 0x8000), el(2, 0x8000)], flag=1)
        elems, flag_after, result = check(holder)
        self.assertEqual(elems, [el(2, 0x8000), el(1, 0x8000)])
        self.assertEqual(flag_after, 0)
        self.assertTrue(result)

    def test_flag_clear_leaves_order(self):
        holder = Holder([el(1, 0x8000), el(2, 0x8000)], flag=0)
        elems, flag_after, result = check(holder)
        self.assertEqual(elems, [el(1, 0x8000), el(2, 0x8000)])
        self.assertEqual(flag_after, 0)
        self.assertTrue(result)

    def test_flag_set_empty_still_clears_and_false(self):
        holder = Holder([], flag=1)
        elems, flag_after, result = check(holder)
        self.assertEqual(elems, [])
        self.assertEqual(flag_after, 0)
        self.assertFalse(result)

    def test_flag_set_singleton_clears(self):
        holder = Holder([el(9, 5)], flag=1)
        elems, flag_after, result = check(holder)
        self.assertEqual(elems, [el(9, 5)])
        self.assertEqual(flag_after, 0)
        self.assertFalse(result)

    def test_null_pair_uses_global_and_ignores_flag(self):
        holder = Holder(None, flag=1)
        elems, flag_after, result = check(
            holder, global_pair=[el(0, 0x8000)])
        self.assertIsNone(elems)
        self.assertEqual(flag_after, 1)
        self.assertTrue(result)

    def test_null_pair_empty_global_is_false(self):
        holder = Holder(None, flag=1)
        _elems, flag_after, result = check(holder, global_pair=[])
        self.assertEqual(flag_after, 1)
        self.assertFalse(result)

    def test_consumer_branch(self):
        self.assertEqual(consumer_branch(True), "allocate")
        self.assertEqual(consumer_branch(False), "walk")


if __name__ == "__main__":
    unittest.main()
