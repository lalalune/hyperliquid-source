#!/usr/bin/env python3
"""Check a hand-reconstructed four-row selector; never execute target bytes."""
from itertools import product


def four(rows, wrong_tie=False):
    # 0x14c5b50 pairs rows 0/1 and 2/3, then merges their extrema.
    # Row identity is retained separately from the compared byte string.
    less = lambda a, b: a[0] < b[0]
    a, b, c, d = rows
    x0, x1 = (b, a) if less(b, a) else (a, b)
    y0, y1 = (d, c) if less(d, c) else (c, d)
    lo = less(y0, x0)
    hi = less(y1, x1)
    mid_a = y0 if hi else x1
    if lo:
        mid_a = x0
    first = y0 if lo else x0
    mid_b = x1 if lo else y0
    last = x1 if hi else y1
    if hi:
        mid_b = y1
    swap = mid_b[0] <= mid_a[0] if wrong_tie else less(mid_b, mid_a)
    second, third = (mid_b, mid_a) if swap else (mid_a, mid_b)
    return [first, second, third, last]


def main():
    cases = 0
    rejected = 0
    for keys in product([b'', b'a', b'aa', b'\x80'], repeat=4):
        rows = list(zip(keys, range(4)))
        expected = sorted(rows, key=lambda row: row[0])
        assert four(rows) == expected, keys
        rejected += four(rows, wrong_tie=True) != expected
        cases += 1
    assert rejected > 0
    print(f'PASS: {cases} four-row order/tie cases; wrong-equality control rejected in {rejected}')


if __name__ == '__main__':
    main()
