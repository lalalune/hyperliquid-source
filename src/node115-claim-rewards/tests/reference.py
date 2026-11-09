#!/usr/bin/env python3
"""Generate deterministic arbitrary-precision arithmetic reference cases."""
import hashlib
import random
from pathlib import Path

r = random.Random(0x2157)
lines = []
for _ in range(10000):
    d = r.randrange(20)
    first_width = r.randrange(d, 20)
    width = r.randrange(d, 20)
    floor = (100_000_000 * 10 ** (width - d)) // 10 ** (first_width - d)
    candidates = [1, (1 << 64) - 1, max(0, min((1 << 64) - 1, floor - 1)), min((1 << 64) - 1, floor)]
    amount = r.choice(candidates)
    claimed = r.getrandbits(64)
    ok = amount != 0 and floor < (1 << 64) and amount >= floor
    lines.append(f'{d} {first_width} {width} {amount} {claimed} {int(ok)}\n')
path = Path(__file__).with_name('reference-vectors.txt')
path.write_text(''.join(lines))
print(len(lines), hashlib.sha256(path.read_bytes()).hexdigest())
