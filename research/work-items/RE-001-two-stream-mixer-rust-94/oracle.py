#!/usr/bin/env python3
"""Independent mathematical fixtures, not a captured-instruction evaluator.

The recurrence is justified by the static proof in README.md. There are no
registers, pointers, decoder operands, flags, or target instruction dispatch.
This file does not read the Rust implementation or historical model outputs.
"""

import argparse
from functools import reduce
import hashlib
import json
from pathlib import Path

HERE = Path(__file__).resolve().parent
TARGET_SHA = "3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f"
RADIX = 2**64


def fold_product(x, y):
    """Schoolbook base-2^32 multiplication, followed by xor of its two limbs."""
    x1, x0 = divmod(x, 2**32)
    y1, y0 = divmod(y, 2**32)
    product = x0 * y0 + (x1 * y0 + x0 * y1) * 2**32 + x1 * y1 * RADIX
    high, low = divmod(product, RADIX)
    return high ^ low


def value(data, seed_b, seed_a, key):
    n = len(data)
    rounds = 0 if n < 16 else (n + 31) // 32

    def word(offset):
        if not 0 <= offset <= n - 8:
            raise ValueError("mathematical index outside fixture")
        return sum(data[offset + j] * 256**j for j in range(8))

    def next_pair(state, j):
        a, b = state
        first, last = 16 * j, n - 16 * (j + 1)
        return (fold_product(a ^ word(first + 8), key ^ word(last + 8)),
                fold_product(b ^ word(first), key ^ word(last)))

    a, b = reduce(next_pair, range(rounds), (seed_a, seed_b))
    return a ^ b


def stream(label, n):
    # Counter-hashed synthetic bytes: no user data, random-library version,
    # target process or external reference implementation is involved.
    return b"".join(hashlib.sha256(f"two-stream-v1:{label}:{j}".encode()).digest()
                    for j in range((n + 31) // 32))[:n]


def fixtures():
    def words(*items):
        return b"".join(x.to_bytes(8, "little") for x in items)

    # These hand-derived checks are worked out in the proof, including a high
    # limb in each lane separately. They are not old interpreter outputs.
    hand = [
        ("hand-empty", b"", 0x2222, 0x1111, 0, 0x3333),
        ("hand-short", bytes(15), 0x2222, 0x1111, 0, 0x3333),
        ("hand-16", words(1, 2), 5, 3, 0, 6),
        ("hand-32", words(1, 2, 3, 4), 5, 3, 0, 8),
        ("hand-48-overlap", words(1, 2, 3, 4, 5, 6), 5, 3, 0, 77),
        ("hand-high-a", words(0, 3), 0, RADIX - 1, 0, RADIX - 10),
        ("hand-high-b", words(3, 0), RADIX - 1, 0, 0, RADIX - 10),
    ]
    for label, data, b, a, key, expected in hand:
        if value(data, b, a, key) != expected:
            raise ValueError(f"hand calculation disagrees: {label}")
        yield label, data, b, a, key
    for n in range(513):
        yield f"length-{n}-zero", bytes(n), RADIX - 1, 2**63, 0
        yield f"length-{n}-dense", stream(f"length-{n}", n), 0x0123456789ABCDEF, 0xF1E2D3C4B5A69788, RADIX - 1
    for n in (16, 17, 31, 32, 33, 47, 48, 49, 63, 64, 65):
        # Each byte separately perturbed: the tails and shared middle bytes
        # must influence the correct lane(s), even at unaligned backward loads.
        base = stream(f"perturb-{n}", n)
        yield f"perturb-{n}-base", base, RADIX - 1, 2**63 + 1, 0xAA5500FF55AAFF00
        for j in range(n):
            data = bytearray(base)
            data[j] ^= 0x80
            yield f"perturb-{n}-{j}", bytes(data), RADIX - 1, 2**63 + 1, 0xAA5500FF55AAFF00
    edges = (0, 1, 2**32 - 1, 2**32, 2**63 - 1, 2**63, RADIX - 1)
    for i in range(256):
        raw = stream(f"varied-{i}", 32)
        n = int.from_bytes(raw[:2], "big") % 4097
        yield f"varied-{i}", stream(f"bytes-{i}", n), edges[i % 7], edges[(i // 7) % 7], int.from_bytes(raw[8:16], "big")
    for n in (1023, 1024, 1025, 4095, 4096, 4097, 8191, 8192, 8193):
        yield f"long-{n}", stream(f"long-{n}", n), RADIX - 1, RADIX - 2, 2**63


def generate():
    inputs, expected, count = [], [], 0
    for label, data, b, a, key in fixtures():
        inputs.append(f"{label}\t{b:016x}\t{a:016x}\t{key:016x}\t{data.hex() or '-'}\n")
        expected.append(f"{label}\t{value(data, b, a, key):016x}\n")
        count += 1
    files = {"inputs.tsv": "".join(inputs).encode(), "expected.tsv": "".join(expected).encode()}
    freeze = {"target_sha256": TARGET_SHA, "function": ["0x16488e0", "0x1648946"],
              "method": "static mathematical recurrence; no target execution or instruction emulation",
              "cases": count,
              "sha256": {name: hashlib.sha256(raw).hexdigest() for name, raw in files.items()},
              "oracle_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest()}
    files["freeze.json"] = (json.dumps(freeze, indent=2, sort_keys=True) + "\n").encode()
    return files


def check(directory):
    files = generate()
    for name, raw in files.items():
        if (directory / name).read_bytes() != raw:
            raise ValueError(f"frozen fixture drift: {name}")
    return json.loads(files["freeze.json"])


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, help="Create a fresh fixture directory; never overwrite a freeze")
    args = parser.parse_args()
    if args.out:
        args.out.mkdir(parents=True, exist_ok=False)
        for name, raw in generate().items():
            (args.out / name).write_bytes(raw)
        print(f"Frozen fixtures: {args.out}")
    else:
        print(json.dumps(check(HERE / "fixtures"), indent=2, sort_keys=True))
