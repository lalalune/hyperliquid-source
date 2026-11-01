"""Pre-Rust nearest binary64 oracle by exact ordered-code binary search."""
from fractions import Fraction
import gzip
import hashlib
import json
from pathlib import Path
import struct

PACKET = Path(__file__).resolve().parent
ROOT = PACKET.parents[2]
SIGN = 1 << 63
TOP = 1 << 127
MOD = 1 << 128

def require(ok, message):
    if not ok:
        raise ValueError(message)

def sha(raw):
    return hashlib.sha256(raw).hexdigest()

def value(code):
    if code == 0:
        return Fraction(0)
    exponent = (code >> 52) - 1023 - 52
    significand = (1 << 52) + (code & ((1 << 52) - 1))
    return Fraction(significand * (1 << max(exponent, 0)), 1 << max(-exponent, 0))

def nearest(raw):
    signed = raw if raw < TOP else raw - MOD
    magnitude = abs(signed)
    if magnitude == 0:
        return 0
    # Positive normal codes are ordered exactly as their rational values.
    low, high = 0x3ff0000000000000, 0x47e0000000000000
    while low < high:
        middle = (low + high + 1) // 2
        if value(middle) <= magnitude:
            low = middle
        else:
            high = middle - 1
    floor = low
    if value(floor) == magnitude:
        chosen = floor
    else:
        ceiling = floor + 1
        down, up = magnitude - value(floor), value(ceiling) - magnitude
        chosen = floor if down < up or (down == up and floor % 2 == 0) else ceiling
    return chosen | (SIGN if signed < 0 else 0)

def corpus():
    words = {0, 1, MOD - 1, TOP, TOP - 1, TOP + 1}
    def add_signed(n):
        if -TOP <= n < TOP:
            words.add(n % MOD)
    for exponent in range(128):
        for delta in (-2, -1, 0, 1, 2):
            for sign in (-1, 1):
                add_signed(sign * ((1 << exponent) + delta))
    # Exact representables, ties and their adjacent integers, both signs.
    for exponent in range(53, 128):
        unit = 1 << (exponent - 52)
        for significand in ((1 << 52), (1 << 52) + 1, (1 << 52) + 2,
                            (1 << 53) - 3, (1 << 53) - 2, (1 << 53) - 1):
            for center in (significand * unit, significand * unit + unit // 2):
                for delta in (-1, 0, 1):
                    for sign in (-1, 1):
                        add_signed(sign * (center + delta))
    for n in range(-256, 257):
        add_signed(n)
    for index in range(4096):
        words.add(int.from_bytes(hashlib.sha256(f'i128-f64-94:{index}'.encode()).digest()[:16], 'little'))
    return sorted(words)

def fixtures():
    words = corpus()
    inputs = b''.join(n.to_bytes(16, 'little') for n in words)
    expected = b''.join(struct.pack('<Q', nearest(n)) for n in words)
    record = {'cases': len(words), 'positive_cases': sum(0 < n < TOP for n in words),
              'negative_cases': sum(n >= TOP for n in words), 'zero_cases': words.count(0),
              'inputs_sha256': sha(inputs), 'expected_sha256': sha(expected),
              'method': 'binary search on ordered binary64 codes; exact rational distance; ties select even code',
              'domain': 'all signed i128 inputs; finite corpus is not exhaustive'}
    return inputs, expected, record

if __name__ == '__main__':
    import sys
    require(sys.argv[1:] == ['--freeze'], 'only --freeze is supported')
    require(not (ROOT / 'src/node94-i128-f64/lib.rs').exists(), 'freeze must precede Rust')
    inputs, expected, record = fixtures()
    record['oracle_sha256_at_freeze'] = sha(Path(__file__).read_bytes())
    record['rust_source_existed_at_freeze'] = False
    for name, raw in [('inputs', inputs), ('expected', expected)]:
        with (PACKET / (name + '.bin.gz')).open('xb') as f:
            f.write(gzip.compress(raw, mtime=0))
    with (PACKET / 'frozen.json').open('x') as f:
        json.dump(record, f, indent=2, sort_keys=True)
        f.write('\n')
    print(json.dumps(record, indent=2))
