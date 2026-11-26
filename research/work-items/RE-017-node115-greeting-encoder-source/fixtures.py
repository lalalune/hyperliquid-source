#!/usr/bin/env python3
"""Independent field-schema fixture generator; no target execution/emulation."""
from pathlib import Path
BOUNDS = [0, 250, 251, 65535, 65536, 2**32-1, 2**32, 2**64-1]

def integer(n):
    if n <= 250:
        return bytes([n])
    width, marker = next((w, m) for w, m in [(2, 251), (4, 252), (8, 253)] if n < 1 << (8*w))
    return bytes([marker]) + n.to_bytes(width, 'little')

def sig(seed):
    return b''.join(integer(BOUNDS[(seed+i) % 8]) for i in range(8)) + bytes([(seed*31) % 256])

def prefix(seed, tag):
    blob = bytes((i+seed) % 256 for i in range([0, 1, 250, 251][seed % 4]))
    return b'\0' + integer(len(blob)) + blob + integer(BOUNDS[seed % 8]) + bytes([tag])

def fixed(seed):
    return b''.join(integer(BOUNDS[(seed+i) % 8]) + integer(BOUNDS[(seed+i+3) % 8]) + bytes((j+i+seed) % 256 for j in range(2048)) for i in range(3))

rows=[]
for seed in range(8):
    rows.append(('summary', seed, b'\1' + b''.join(integer(BOUNDS[(seed+i) % 8]) for i in range(3))))
    left, right = [sig(seed), sig(seed+1)], [sig(seed+2)]
    rows.append(('vectors', seed, prefix(seed, 0) + bytes([seed])*32 + integer(len(left)) + b''.join(left) + integer(len(right)) + b''.join(right) + bytes([seed+1])*32))
    left = [bytes([key])*20 + sig(seed+key) for key in [1, 3, 7]]
    right = [bytes([key])*20 + sig(seed+key) for key in [2, 4]]
    rows.append(('maps', seed, prefix(seed, 1) + bytes([seed])*32 + integer(3) + b''.join(left) + integer(2) + b''.join(right) + bytes([seed+1])*32))
for seed in range(2):
    rows.append(('fixed', seed, prefix(seed, 2) + fixed(seed)))
text = '# Independent schema fixtures, not observations of target execution.\n' + ''.join(f'{kind}\t{seed}\t{data.hex()}\n' for kind,seed,data in rows)
out = Path(__file__).parents[3] / 'src/node115-greeting-encoder/tests/schema.tsv'
if __name__ == '__main__':
    import argparse
    p=argparse.ArgumentParser();p.add_argument('--check', action='store_true');args=p.parse_args()
    if args.check:
        assert out.read_text() == text, 'fixture differs'
        print(f'PASS: {len(rows)} independent schema fixtures')
    else:
        out.write_text(text)
