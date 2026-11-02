#!/usr/bin/env python3
"""Combinatorial coverage checks for the retained search-window arithmetic.

Not an instruction emulator or captured-code execution. The bytes and written
proof establish which intervals and comparisons the target requests.
"""
import json
from pathlib import Path


def candidate_intervals(length):
    if length < 4:
        return []
    if length <= 18:
        return [(0, length - 3)]
    intervals, residual = [], 0
    if length >= 68:
        while True:
            intervals.extend((residual + shift, residual + shift + 16)
                             for shift in (0, 16, 32, 48))
            old = residual
            residual += 64
            if old + 131 >= length:
                break
    if residual + 19 < length:
        while True:
            intervals.append((residual, residual + 16))
            if residual + 35 >= length:
                break
            residual += 16
    intervals.append((length - 19, length - 3))
    return intervals


def verify_coverage():
    count, covered = 0, 0
    for length in range(4097):
        intervals = candidate_intervals(length)
        positions = {i for low, high in intervals for i in range(low, high)}
        expected = set(range(max(0, length - 3)))
        if positions != expected:
            raise ValueError(f'coverage mismatch at length {length}')
        count += 1
        covered += len(positions)
    # The helper's 16-bit ROL(0xfffe, ctz(mask)) clears exactly the least set bit.
    for mask in range(1, 1 << 16):
        bit = (mask & -mask).bit_length() - 1
        rotated = ((0xfffe << bit) | (0xfffe >> (16 - bit))) & 0xffff
        if mask & rotated != mask & (mask - 1):
            raise ValueError('candidate removal identity')
    return {'lengths_checked': count, 'distinct_length_position_pairs': covered,
            'nonzero_16_bit_masks_checked': 65535,
            'limits': 'Finite checks support PROOF.md induction; not target execution or equivalence.'}


if __name__ == '__main__':
    print(json.dumps(verify_coverage(), indent=2))
