"""Model tests for the node #115 sort pipeline
(RE-001-sort-pipeline-53470-115).

Run directly (pytest is not installed on this VM):
    python3 -c "import importlib.util; ..."
or through the packet's verify.py, which imports every test_*
function here and runs it. Elements are (key, serial) pairs: the
key stands in for the int32 the virtual slot +0x30 returns, and
the serial stands in for the tie-break the virtual slot +0x10
returns the sign of. The order the model must produce is
(key, serial) ascending.
"""

import random
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from tools.sort_pipeline_53470_115 import (
    INLINE_CAPACITY, THRESHOLD, SsoList, adjust_heap, depth_limit,
    heapsort, insertion_sort, introsort_loop, less_than,
    median_to_first, partition, sort_entry, swap_elements,
    unguarded_linear_insert,
)


def _key(elem):
    return elem[0]


def _tiebreak(a, b):
    return (a[1] > b[1]) - (a[1] < b[1])


def _sorted(elements):
    return sorted(elements, key=lambda e: (e[0], e[1]))


def _check_sorted(container, expected):
    assert container.data == expected, (
        "got %r, want %r" % (container.data, expected))


def test_depth_limit_matches_bsr_doubling():
    assert depth_limit(1) == 0
    assert depth_limit(2) == 2
    assert depth_limit(3) == 2
    assert depth_limit(4) == 4
    assert depth_limit(16) == 8
    assert depth_limit(17) == 8
    assert depth_limit(32) == 10
    assert depth_limit(1000) == 18


def test_sso_addressing_boundary():
    c = SsoList(range(40))
    assert c.address_kind(0) == "inline"
    assert c.address_kind(31) == "inline"
    assert c.address_kind(32) == "heap"
    assert c.address_kind(39) == "heap"
    assert c.slot(31) == 31
    assert c.slot(32) == 32


def test_swap_across_addressing_kinds():
    c = SsoList(list(range(40)))
    swap_elements(c, 0, 39)
    assert c.slot(0) == 39 and c.slot(39) == 0
    swap_elements(c, 31, 32)
    assert c.slot(31) == 32 and c.slot(32) == 31
    swap_elements(c, 5, 5)
    assert c.slot(5) == 5


def test_predicate_key_then_tiebreak():
    assert less_than((1, 0), (2, 0), _key, _tiebreak) == 1
    assert less_than((2, 0), (1, 0), _key, _tiebreak) == 0
    assert less_than((1, 0), (1, 1), _key, _tiebreak) == 1
    assert less_than((1, 1), (1, 0), _key, _tiebreak) == 0
    assert less_than((1, 0), (1, 0), _key, _tiebreak) == 0


def test_flag_and_empty_guards():
    c = SsoList([(2, 0), (1, 0)])
    assert sort_entry(c, True, _key, _tiebreak) is False
    assert c.data == [(2, 0), (1, 0)]
    assert sort_entry(SsoList([]), False, _key, _tiebreak) is False
    single = SsoList([(7, 0)])
    assert sort_entry(single, False, _key, _tiebreak) is True
    assert single.data == [(7, 0)]


def test_sort_small_sizes():
    for n in (2, 3, 5, 15, 16):
        rng = random.Random(1000 + n)
        elements = [(rng.randrange(5), i) for i in range(n)]
        c = SsoList(elements)
        assert sort_entry(c, False, _key, _tiebreak) is True
        _check_sorted(c, _sorted(elements))


def test_sort_threshold_boundary():
    for n in (17, 31, 32, 33, 40):
        rng = random.Random(2000 + n)
        elements = [(rng.randrange(7), i) for i in range(n)]
        c = SsoList(elements)
        assert sort_entry(c, False, _key, _tiebreak) is True
        _check_sorted(c, _sorted(elements))


def test_sort_large_random_and_adversarial():
    rng = random.Random(42)
    for n in (100, 200, 500):
        elements = [(rng.randrange(50), i) for i in range(n)]
        c = SsoList(elements)
        assert sort_entry(c, False, _key, _tiebreak) is True
        _check_sorted(c, _sorted(elements))
    for n in (100, 200):
        elements = [(i, 0) for i in range(n)]  # already sorted
        c = SsoList(elements)
        sort_entry(c, False, _key, _tiebreak)
        _check_sorted(c, _sorted(elements))
        elements = [(n - i, 0) for i in range(n)]  # reversed
        c = SsoList(elements)
        sort_entry(c, False, _key, _tiebreak)
        _check_sorted(c, _sorted(elements))
        elements = [(3, i) for i in range(n)]  # all equal keys
        c = SsoList(elements)
        sort_entry(c, False, _key, _tiebreak)
        _check_sorted(c, _sorted(elements))


def test_sort_is_a_permutation():
    rng = random.Random(7)
    elements = [(rng.randrange(10), i) for i in range(120)]
    c = SsoList(elements)
    sort_entry(c, False, _key, _tiebreak)
    assert sorted(c.data) == sorted(elements)


def test_partition_cut_property():
    rng = random.Random(99)
    for trial in range(20):
        n = rng.randrange(20, 80)
        elements = [(rng.randrange(20), i) for i in range(n)]
        c = SsoList(elements)
        median_to_first(c, 0, n, _key, _tiebreak)
        cut = partition(c, 0, n, _key, _tiebreak)
        assert 1 <= cut <= n
        pivot = c.data[0]
        for i in range(cut):
            assert not less_than(pivot, c.data[i], _key, _tiebreak), (
                "left of cut greater than pivot: %r vs %r"
                % (c.data[i], pivot))
        assert sorted(c.data) == sorted(elements)


def test_introsort_loop_plus_insertion_tail():
    rng = random.Random(1234)
    for n in (17, 50, 300):
        elements = [(rng.randrange(30), i) for i in range(n)]
        c = SsoList(elements)
        introsort_loop(c, 0, n, depth_limit(n), _key, _tiebreak)
        # Ranges of 16 or fewer are left for the insertion tail.
        insertion_sort(c, 0, n, _key, _tiebreak)
        _check_sorted(c, _sorted(elements))


def test_heapsort_fallback_sorts_alone():
    rng = random.Random(555)
    for n in (17, 64, 150):
        elements = [(rng.randrange(40), i) for i in range(n)]
        c = SsoList(elements)
        heapsort(c, 0, n, _key, _tiebreak)
        _check_sorted(c, _sorted(elements))
        # Zero depth forces the fallback inside the loop.
        elements = [(rng.randrange(40), i) for i in range(n)]
        c = SsoList(elements)
        introsort_loop(c, 0, n, 0, _key, _tiebreak)
        insertion_sort(c, 0, n, _key, _tiebreak)
        _check_sorted(c, _sorted(elements))


def test_adjust_heap_sifts_value_down():
    elements = [(9, 0), (1, 1), (8, 2), (2, 3), (7, 4),
                (3, 5), (6, 6)]
    c = SsoList(elements)
    adjust_heap(c, 0, 0, len(elements), c.slot(0), _key, _tiebreak)
    assert c.slot(0) == (9, 0)
    assert sorted(c.data) == sorted(elements)


def test_insertion_pass_and_step():
    elements = [(5, 0), (2, 1), (4, 2), (1, 3), (3, 4)]
    c = SsoList(elements)
    insertion_sort(c, 0, len(elements), _key, _tiebreak)
    _check_sorted(c, _sorted(elements))
    elements = [(1, 0), (2, 1), (4, 2), (5, 3), (0, 4)]
    c = SsoList(elements)
    unguarded_linear_insert(c, 4, _key, _tiebreak)
    assert c.data == [(0, 4), (1, 0), (2, 1), (4, 2), (5, 3)]


def test_insertion_pass_first_element_path():
    # The shift arm: an element smaller than the first goes to lo.
    elements = [(4, 0), (5, 1), (1, 2), (6, 3)]
    c = SsoList(elements)
    insertion_sort(c, 0, len(elements), _key, _tiebreak)
    _check_sorted(c, _sorted(elements))
