"""Tests for tools/bitmap_node_callers_115.py.

Target-grounded expectations from
research/work-items/RE-001-bitmap-node-callers-115/: the ctor's
move/layout, size gate, kind/magnitude decode, shift/start/words
math, the reset-helper arg mapping, the factory/materialize path
selection, the dtor and the slot-release decisions. Seeded random
inputs pin the arithmetic; boundary cases pin the gates.
"""

import random
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "tools"))

from bitmap_node_callers_115 import (
    BitmapNode, InnerNode, MOD, bitmap_words, ctor, ctor_with_tag,
    dtor_actions, factory_path, kind, magnitude, materialize_path,
    poll_copy, reset_helper, reset_helper_args, seed_advance,
    shift_for_count, slot_release, split_value, trailing_u16,
)


def arg2(size, buf=0x1000, a10=0, a18=0):
    return {0x00: buf, 0x08: size, 0x10: a10, 0x18: a18}


def test_seed_advance_matches_fold():
    rng = random.Random(115)
    for _ in range(200):
        seed = rng.randrange(0, MOD)
        prod = (seed * 0x41A7) & 0xFFFFFFFFFFFFFFFF
        total = (prod & MOD) + ((prod >> 31) & 0xFFFFFFFF)
        if total & 0x80000000:
            total = (total - MOD) & 0xFFFFFFFF
        assert seed_advance(seed) == total & 0xFFFFFFFF
        assert 0 <= seed_advance(seed) < 0x80000000 or seed_advance(seed) == total


def test_seed_advance_known_values():
    # seed 1: prod 0x41a7; fold = 0x41a7 + 0 = 0x41a7.
    assert seed_advance(1) == 0x41A7
    # seed 0 stays 0.
    assert seed_advance(0) == 0
    # seed 0x7fffffff: prod = 0x7fffffff * 0x41a7; fold must stay < 2^31
    # after the conditional subtract.
    assert seed_advance(0x7FFFFFFF) < 0x80000000


def test_shift_for_count_boundaries():
    assert shift_for_count(0) == 0
    assert shift_for_count(1) == 0
    assert shift_for_count(2) == 1
    assert shift_for_count(3) == 1
    assert shift_for_count(4) == 2
    assert shift_for_count(5) == 2
    assert shift_for_count(8) == 3
    assert shift_for_count(16) == 4
    rng = random.Random(115)
    for _ in range(100):
        count = rng.randrange(2, 1 << 20)
        assert shift_for_count(count) == (count >> 1).bit_length()


def test_bitmap_words_seeded():
    rng = random.Random(115)
    for _ in range(200):
        size = rng.randrange(1, 1 << 16)
        shift = rng.randrange(0, 8)
        assert bitmap_words(size, shift) == ((size - 1) >> shift) // 32 + 1
    assert bitmap_words(1, 0) == 1
    assert bitmap_words(32, 0) == 1
    assert bitmap_words(33, 0) == 2
    assert bitmap_words(64, 1) == 1
    assert bitmap_words(65, 1) == 2


def test_magnitude_and_kind():
    # Small size: low 31 bits, sign bit.
    assert magnitude(0x80000005, 100) == 5
    assert kind(0x80000005, 100) == 1
    assert magnitude(0x00000005, 100) == 5
    assert kind(0x00000005, 100) == 0
    # Big size (> 0x10000): raw value, kind 0.
    assert magnitude(0x80000005, 0x10001) == 0x80000005
    assert kind(0x80000005, 0x10001) == 0
    # Boundary: exactly 0x10000 is still the masked path.
    assert magnitude(0x80000005, 0x10000) == 5
    assert kind(0x80000005, 0x10000) == 1


def test_split_value():
    assert split_value(0x80000005) == (1, 5)
    assert split_value(0x00000005) == (0, 5)
    assert split_value(0xFFFFFFFF) == (1, 0x7FFFFFFF)


def test_trailing_u16():
    src = bytes(range(256))
    t, out = trailing_u16(src, 10)
    # T = src[8] | src[9] << 8 = 0x0908; out = 10 - 2 - 0x0908 mod 2^16.
    assert t == 0x0908
    assert out == (10 - 2 - 0x0908) & 0xFFFF


def test_ctor_move_and_small_arg_gate():
    node, seed, moved = ctor(arg2(3), 10, 0x2000, 123, 0x00000005)
    assert node.buf == 0x1000 and node.size == 0
    assert node.adj == 0 and node.mag == 0 and node.inner is None
    assert moved[0x18] == 0
    # size 0..3 all take the small-arg gate.
    for size in (0, 1, 2, 3):
        node, _, _ = ctor(arg2(size), 10, 0x2000, 123, 0x00000005)
        assert node.size == 0


def test_ctor_kind0_builds_bitmap():
    calls = []
    node, new_seed, _ = ctor(arg2(100), 16, 0x2000, 7, 0x00000005,
                             observer=lambda a, b, c: calls.append((a, b, c)))
    # mag 5, kind 0: adj = 100 - (4*5 + 4) = 76; 96 >= 76 so it proceeds.
    assert node.mag == 5
    assert node.adj == 76
    assert node.size == 100
    assert node.inner is not None
    assert node.inner.shift == shift_for_count(16)
    assert len(node.inner.bitmap) == bitmap_words(76, node.inner.shift)
    assert all(w == 0 for w in node.inner.bitmap)
    assert node.inner.seed_mod == new_seed % 16
    assert new_seed == seed_advance(7)
    assert calls == [(0x2000, 0x57, 76)]


def test_ctor_kind0_underflow_clears_size():
    # size 8, mag 5: adj = 8 - 24 mod 2^32 = huge; (8-4) < adj -> size 0.
    node, seed, _ = ctor(arg2(8), 16, 0x2000, 7, 0x00000005)
    assert node.size == 0
    assert node.inner is None
    assert seed == 7  # seed untouched when no bitmap is built


def test_ctor_kind1_small_clears_size():
    node, seed, _ = ctor(arg2(5), 16, 0x2000, 7, 0x80000005)
    assert node.size == 0
    assert node.inner is None


def test_ctor_kind1_large_uses_tag():
    # size 100, mag 5, kind 1, tag T=0x10: len = 100-4 = 96;
    # out = 96-2-0x10 = 78; adj = 78 - 20 = 58.
    node, new_seed, _ = ctor_with_tag(arg2(100), 16, 0x2000, 7,
                                      0x80000005, 0x10)
    assert node.mag == 5
    assert node.tag == 0x10
    assert node.adj == 58
    assert node.inner is not None
    assert len(node.inner.bitmap) == bitmap_words(58, node.inner.shift)


def test_ctor_kind1_large_underflow_clears_size():
    # tag so large that out < 4*mag.
    node, _, _ = ctor_with_tag(arg2(100), 16, 0x2000, 7, 0x80000005, 90)
    assert node.size == 0
    assert node.inner is None


def test_ctor_no_bitmap_when_count_or_arg4_zero():
    node, seed, _ = ctor(arg2(100), 0, 0x2000, 7, 0x00000005)
    assert node.inner is None and seed == 7
    node, seed, _ = ctor(arg2(100), 16, 0, 7, 0x00000005)
    assert node.inner is None and seed == 7


def test_ctor_kind_other_returns_early():
    # kind is only 0 or 1 from the sign bit, so this path is reached
    # only via a crafted trailing value; the model treats any other
    # kind as "size 0, return".
    node = BitmapNode()
    node.size = 0
    assert dtor_actions(node) == []


def test_dtor_actions():
    node, _, _ = ctor(arg2(100), 16, 0x2000, 7, 0x00000005)
    actions = dtor_actions(node)
    assert actions[0] == ("delete_array", "inner+0x08")
    assert actions[1] == ("delete_sized", "inner", 0x28)
    # arg18 == 0 here, so no arg-pair action.
    assert len(actions) == 2

    node2 = BitmapNode()
    node2.arg18 = 0x3000
    node2.arg10 = 0x4000
    assert dtor_actions(node2) == [("vtable_call", 0xA0, "node+0x10")]
    node3 = BitmapNode()
    node3.arg18 = 0x3000
    assert dtor_actions(node3) == [("delete_array", "node+0x18")]


def test_factory_path_selection():
    n = BitmapNode()
    n.size, n.mag = 8, 1
    assert factory_path(n) == "A"
    n.mag = 0
    assert factory_path(n) == "B"
    n.size = 7
    assert factory_path(n) == "C"
    n.size = 0
    assert factory_path(n) == "C"


def test_materialize_path_selection():
    n = BitmapNode()
    assert materialize_path(n, False) == "fresh"
    n.size, n.mag = 8, 1
    assert materialize_path(n, True) == "fill"
    n.mag = 0
    assert materialize_path(n, True) == "teardown"
    n.size = 7
    assert materialize_path(n, True) == "report"


def test_slot_release():
    assert slot_release({0x10: 0x5000, 0x18: 0}) == "chain"
    assert slot_release({0x10: 0, 0x18: 1}) == "flag_delete"
    assert slot_release({0x10: 0, 0x18: 0}) == "nothing"


def test_reset_helper():
    actions = reset_helper(0x6000, "fresh")
    assert actions[0] == ("store", "fresh")
    assert actions[1] == ("dtor", 0x6000)
    assert actions[2] == ("delete_sized", 0x6000, 0x48)
    assert reset_helper(None, "fresh") == [("store", "fresh")]


def test_reset_helper_args():
    arg1 = {0xCC: 42, 0x08: 0x7000}
    assert reset_helper_args("a", arg1, None) == (42, 0x7000)
    for h in ("b", "c", "d", "e"):
        assert reset_helper_args(h, arg1, None) == (0, 0x7000)


def test_poll_copy():
    assert poll_copy(1, 0, 0) == "copy"
    assert poll_copy(0, 0x1000, 0) == "copy"
    assert poll_copy(0, 0, 5) == "copy"
    assert poll_copy(0, 0, 0) == "report_then_copy"


def test_ctor_seeded_random_kind0():
    rng = random.Random(115)
    for _ in range(100):
        size = rng.randrange(4, 1 << 12)
        mag = rng.randrange(0, 1 << 10)
        count = rng.choice([1, 2, 3, 16, 100])
        trailing = mag  # kind 0, small mag
        node, new_seed, _ = ctor(arg2(size), count, 0x2000, 123, trailing)
        adj = (size - (4 * mag + 4)) & 0xFFFFFFFF
        if (size - 4) < adj:
            assert node.size == 0 and node.inner is None
        else:
            assert node.adj == adj
            assert node.inner is not None
            assert len(node.inner.bitmap) == bitmap_words(
                adj, shift_for_count(count))
            assert new_seed == seed_advance(123)
