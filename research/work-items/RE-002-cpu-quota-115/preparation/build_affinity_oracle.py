#!/usr/bin/env python3
"""Replay the original inline fixture construction without rewriting its freeze.

This script records that preparer after its original inline run; the retained
AFFINITY-FREEZE.json predates the new Rust source. No target code runs.
"""
import argparse
import json
from pathlib import Path
import random


def rows():
    rng = random.Random(0x5ba9687)
    masks = [[0] * 16, [(1 << 64) - 1] * 16]
    for bit in range(1024):
        mask = [0] * 16
        mask[bit // 64] = 1 << (bit % 64)
        masks.append(mask)
    masks += [[rng.getrandbits(64) for _ in range(16)] for _ in range(256)]
    result = []
    for i, mask in enumerate(masks):
        count = sum(bin(word).count('1') for word in mask)
        cache = [0, 1, 17, (1 << 64) - 1][i % 4]
        result.append(dict(mask=mask, sysconf=-1, cache=cache, logical=count,
                           cached_or_logical=cache or count))
    for sc in [-(1 << 63), -1024, -1, 0, 1, 2, 3, 1024, (1 << 63) - 1]:
        for cache in [0, 1, 17, (1 << 64) - 1]:
            count = max(sc, 1)
            result.append(dict(mask=None, sysconf=sc, cache=cache, logical=count,
                               cached_or_logical=cache or count))
    return result


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out', type=Path, required=True)
    args = parser.parse_args()
    args.out.write_text(json.dumps(rows(), indent=2) + '\n')
