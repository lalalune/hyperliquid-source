"""Tests for the node #115 two-run search model (0x57f8bb0).

Target-grounded expectations: the empty-descriptor return, the
single-run search when run B is empty, the head-comparison
routing when the logical sequence wraps, the exact match and
insertion indices of both segment searches (including the
loop's duplicate behaviour), and the input guards. Run from
the repository root:

    python3 tests/test_two_run_search_57f8bb0_115.py
"""

import sys
from bisect import bisect_left
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
from two_run_search_57f8bb0_115 import two_run_search

CHECKS = []


def check(label, actual, expected):
    CHECKS.append(label)
    if actual != expected:
        raise AssertionError("%s: got %r, want %r" % (label, actual, expected))


def build(f0, start, logical):
    """Physical key list for a ring: logical index i < skip sits
    at start + i, later indices wrap to 0, 1, ..."""
    skip = f0 - start
    keys = [0] * (f0 + 2)
    for i, value in enumerate(logical):
        if i < skip:
            keys[start + i] = value
        else:
            keys[i - skip] = value
    return keys


def run_tests():
    # Empty descriptor: no record is read.
    check("empty", two_run_search(8, 3, 0, [7] * 10, 42), (1, 0))
    check("empty zero capacity", two_run_search(0, 0, 0, [], 1), (1, 0))

    # Single run (f3 <= skip): logical [10,20,30,40] at physical 3..6.
    keys = build(8, 3, [10, 20, 30, 40])
    for key, want in ((10, (0, 0)), (20, (0, 1)), (40, (0, 3)),
                      (5, (1, 0)), (25, (1, 2)), (45, (1, 4))):
        check("single run key %d" % key,
              two_run_search(8, 3, 4, keys, key), want)
    # Same ring reached with the wrapped head word f2 = f0 + start.
    for key, want in ((20, (0, 1)), (25, (1, 2))):
        check("single run wrapped head key %d" % key,
              two_run_search(8, 11, 4, keys, key), want)

    # Wrapped sequence: logical [10,20,30,40,50], start 6, skip 2,
    # run B [30,40,50] at physical 0..2, head word is 30.
    keys = build(8, 6, [10, 20, 30, 40, 50])
    for key, want in ((30, (0, 2)),          # head equality -> (0, skip)
                      (10, (0, 0)), (20, (0, 1)),   # routed into run A
                      (15, (1, 1)), (5, (1, 0)),    # run A insertions
                      (40, (0, 3)), (50, (0, 4)),   # run B matches
                      (35, (1, 3)), (60, (1, 5))):  # run B insertions
        check("wrapped key %d" % key,
              two_run_search(8, 6, 5, keys, key), want)

    # Boundary f3 == skip: run B empty, single run A [10,20] at 6..7.
    keys = build(8, 6, [10, 20])
    for key, want in ((20, (0, 1)), (15, (1, 1)), (30, (1, 2))):
        check("boundary key %d" % key,
              two_run_search(8, 6, 2, keys, key), want)

    # Boundary len1 == 1: logical [10,20,30], run B is [30] alone.
    keys = build(8, 6, [10, 20, 30])
    for key, want in ((30, (0, 2)), (25, (1, 2)), (35, (1, 3))):
        check("len1 one key %d" % key,
              two_run_search(8, 6, 3, keys, key), want)

    # skip == 0 (start == f0 via f2 == 2*f0): all of the logical
    # sequence is run B; a key below the head returns (1, 0).
    keys = build(4, 0, [10, 20, 30])
    keys = [10, 20, 30, 0, 0, 0]
    for key, want in ((5, (1, 0)), (10, (0, 0)), (20, (0, 1)),
                      (99, (1, 3))):
        check("skip zero key %d" % key,
              two_run_search(4, 8, 3, keys, key), want)

    # Duplicates: the head equality fires first when record 0 is
    # a copy; inside run A the loop settles on the second copy.
    keys = build(8, 6, [10, 20, 20, 20, 30])
    check("duplicate at head", two_run_search(8, 6, 5, keys, 20), (0, 2))
    keys = build(8, 6, [20, 20, 30, 40])
    check("duplicate in run A", two_run_search(8, 6, 4, keys, 20), (0, 1))

    # Seeded sweep against the logical binary-search contract:
    # a found key's logical slot holds the key; a miss returns
    # the bisect insertion point.
    import random
    rng = random.Random(20261106)
    for trial in range(500):
        f0 = rng.randint(1, 40)
        start = rng.randint(0, f0 - 1) if f0 > 1 else 0
        f3 = rng.randint(0, f0)
        logical = sorted(rng.randint(0, 500) for _ in range(f3))
        keys = build(f0, start, logical)
        key = rng.randint(0, 520)
        flag, index = two_run_search(f0, start, f3, keys, key)
        pos = bisect_left(logical, key)
        if pos < f3 and logical[pos] == key:
            if not (flag == 0 and logical[index] == key):
                raise AssertionError(
                    "sweep found trial %d: (%d, %d)" % (trial, flag, index))
        else:
            if not (flag == 1 and index == pos):
                raise AssertionError(
                    "sweep miss trial %d: (%d, %d) want (1, %d)"
                    % (trial, flag, index, pos))
        CHECKS.append("sweep %d" % trial)

    # Guards.
    for bad in (-1, 1 << 64):
        try:
            two_run_search(bad, 0, 0, [], 0)
        except ValueError:
            CHECKS.append("guard %r" % bad)
        else:
            raise AssertionError("guard did not raise for %r" % bad)

    print("%d checks pass" % len(CHECKS))


if __name__ == "__main__":
    run_tests()
