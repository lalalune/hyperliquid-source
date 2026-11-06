"""Tests for the node #115 tagged-value destructor model
(tools/tagged_value_drop_aa810_115.py, routine 0x57aa810, RE-001)."""
import unittest

from tools.tagged_value_drop_aa810_115 import Value, drop

BUF = 0x900000
CHILD = 0x800000


def heap_of(mapping):
    return lambda ptr: mapping[ptr]


EMPTY_HEAP = heap_of({})


class TestNoPayloadTags(unittest.TestCase):
    def test_all_no_payload_tags_have_no_effects(self):
        for tag in (0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 13, 15, 16, 18):
            v = Value(tag, a=7, b=BUF, c=3)
            self.assertEqual(drop(v, EMPTY_HEAP), [], f"tag {tag}")


class TestByteBufferTags(unittest.TestCase):
    def test_zero_capacity_is_a_no_op(self):
        for tag in (12, 14):
            self.assertEqual(drop(Value(tag, a=0, b=BUF, c=9), EMPTY_HEAP), [])

    def test_capacity_is_the_unshifted_dealloc_size(self):
        for tag in (12, 14):
            v = Value(tag, a=0x1234, b=BUF, c=9)
            self.assertEqual(drop(v, EMPTY_HEAP),
                             [("dealloc", BUF, 0x1234)], f"tag {tag}")

    def test_length_field_is_irrelevant(self):
        for c in (0, 1, 1 << 40):
            v = Value(12, a=5, b=BUF, c=c)
            self.assertEqual(drop(v, EMPTY_HEAP), [("dealloc", BUF, 5)])


class TestBoxTags(unittest.TestCase):
    def test_recursion_then_unconditional_box_free(self):
        child = Value(3)
        v = Value(17, a=CHILD)
        self.assertEqual(
            drop(v, heap_of({CHILD: child})),
            [("self", CHILD), ("dealloc", CHILD, 0x20)])

    def test_tag19_body_matches_tag17(self):
        child = Value(20, a=2, b=BUF, c=1)
        want = [("self", CHILD), ("twin", BUF), ("dealloc", BUF, 0x40),
                ("dealloc", CHILD, 0x20)]
        for tag in (17, 19):
            self.assertEqual(
                drop(Value(tag, a=CHILD), heap_of({CHILD: child})),
                want, f"tag {tag}")

    def test_nested_boxes_unwind_inside_out(self):
        inner = Value(0)
        mid = Value(19, a=CHILD + 0x40)
        v = Value(17, a=CHILD)
        heap = heap_of({CHILD: mid, CHILD + 0x40: inner})
        self.assertEqual(
            drop(v, heap),
            [("self", CHILD), ("self", CHILD + 0x40),
             ("dealloc", CHILD + 0x40, 0x20), ("dealloc", CHILD, 0x20)])


class TestVectorTag(unittest.TestCase):
    def test_elements_drop_forward_with_the_twin(self):
        v = Value(20, a=4, b=BUF, c=3)
        self.assertEqual(
            drop(v, EMPTY_HEAP),
            [("twin", BUF), ("twin", BUF + 0x20), ("twin", BUF + 0x40),
             ("dealloc", BUF, 4 << 5)])

    def test_zero_length_still_frees_the_buffer(self):
        v = Value(20, a=2, b=BUF, c=0)
        self.assertEqual(drop(v, EMPTY_HEAP), [("dealloc", BUF, 2 << 5)])

    def test_zero_capacity_skips_the_dealloc(self):
        v = Value(20, a=0, b=BUF, c=2)
        self.assertEqual(drop(v, EMPTY_HEAP),
                         [("twin", BUF), ("twin", BUF + 0x20)])


class TestPairVectorDefault(unittest.TestCase):
    def test_pairs_drop_both_halves_in_order(self):
        v = Value(21, a=2, b=BUF, c=2)
        self.assertEqual(
            drop(v, EMPTY_HEAP),
            [("twin", BUF), ("twin", BUF + 0x20),
             ("twin", BUF + 0x40), ("twin", BUF + 0x60),
             ("dealloc", BUF, 2 << 6)])

    def test_every_tag_above_20_takes_the_default_arm(self):
        for tag in (21, 22, 100, 255):
            v = Value(tag, a=1, b=BUF, c=1)
            self.assertEqual(
                drop(v, EMPTY_HEAP),
                [("twin", BUF), ("twin", BUF + 0x20),
                 ("dealloc", BUF, 1 << 6)], f"tag {tag}")

    def test_zero_pairs_and_zero_capacity(self):
        self.assertEqual(drop(Value(21, a=0, b=BUF, c=0), EMPTY_HEAP), [])
        self.assertEqual(drop(Value(21, a=3, b=BUF, c=0), EMPTY_HEAP),
                         [("dealloc", BUF, 3 << 6)])


if __name__ == "__main__":
    unittest.main()
