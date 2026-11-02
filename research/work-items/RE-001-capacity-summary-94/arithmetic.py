#!/usr/bin/env python3
"""Finite arithmetic checks supporting the static proof; no target interpreter."""
import json
from pathlib import Path


def require(ok, message):
    if not ok:
        raise ValueError(message)


def verify_arithmetic():
    limit, maximum, unit = (1 << 63) - 1, (1 << 64) - 1, 1 << 30
    values = (0, 1, unit - 1, unit, unit + 1, limit - 1, limit, limit + 1, maximum)
    pairs = []
    for total in values:
        for available in values:
            if available > total:
                continue
            a, b = min(total, limit), min(available, limit)
            difference = a - b
            require(0 <= difference <= limit, 'ordered clamps bound the difference')
            require((difference >> 30) == difference // unit, 'nonnegative signed shift is floor')
            require((a >> 30) == a // unit, 'clamped total shift')
            pairs.append({'raw_total': str(total), 'raw_second': str(available),
                          'scaled_difference': difference // unit, 'scaled_total': a // unit})
    # The emitted bias/shift implements truncation toward zero for an arbitrary
    # signed difference. Negative differences are unreachable for admitted pairs.
    signed = (-limit, -unit-1, -unit, -unit+1, -1, 0, 1, unit-1, unit, unit+1, limit)
    for value in signed:
        shifted = (value + (unit - 1 if value < 0 else 0)) >> 30
        require(shifted == (-((-value)//unit) if value < 0 else value//unit), 'signed truncation lemma')
    # Real selector ranking is on raw totals, before the clamp: these rank
    # differently even though their clamped/scaled totals are equal.
    require(limit < limit+1 < maximum, 'raw ordering boundary')
    require(len({min(a, limit)//unit for a in (limit, limit+1, maximum)}) == 1, 'clamped tie boundary')
    # The release predicate uses wrapping 2*C: its two exceptional values.
    capacities = tuple(range(4097)) + (limit, limit+1, maximum)
    for capacity in capacities:
        require((((2*capacity) & maximum) == 0) == (capacity in (0, 1 << 63)), 'release sentinel predicate')
    # Two overlapping eight-byte stores initialize exactly thirteen bytes.
    positions = set(range(0x10,0x18)) | set(range(0x15,0x1d))
    require(positions == set(range(0x10,0x1d)), 'worker option span')
    return {'admitted_boundary_pairs': pairs, 'pair_count': len(pairs),
            'signed_division_values': len(signed), 'release_capacity_values': len(capacities),
            'worker_option_bytes': len(positions),
            'scope': 'Arithmetic lemmas only; no original execution, emulation, selector implementation or runtime equivalence'}


if __name__ == '__main__':
    result = verify_arithmetic()
    require(result == json.loads(Path(__file__).with_suffix('.json').read_text()), 'arithmetic record drift')
    print(json.dumps(result, indent=2))
