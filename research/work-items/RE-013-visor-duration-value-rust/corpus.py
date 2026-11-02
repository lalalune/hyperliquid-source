#!/usr/bin/env python3
"""Pre-source exact-rational expectations, no native instruction evaluation.

The oracle uses distance to neighboring integer nanoseconds and an exact
overflow-midpoint comparison. Future production is planned around bounded
integer significands/quotient remainders, not this Fraction implementation.
"""
import argparse
from fractions import Fraction
import gzip
import hashlib
import json
from pathlib import Path

SIGN = 1 << 63
MASK = (1 << 52)-1
INF = 0x7ff0000000000000
MAX = INF-1
BILLION = 1_000_000_000
MILLION = 1_000_000
OVERFLOW_MIDPOINT = Fraction((1 << 1024)-(1 << 970))


def require(ok, message):
    if not ok:
        raise ValueError(message)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def finite_value(bits):
    exponent = (bits >> 52) & 2047
    require(exponent < 2047, 'nonfinite rational input')
    fraction = bits & MASK
    magnitude = fraction if exponent == 0 else (1 << 52)+fraction
    power = -1074 if exponent == 0 else exponent-1075
    value = Fraction(magnitude << power) if power >= 0 else Fraction(magnitude, 1 << -power)
    return -value if bits & SIGN else value


def nearest_integer(value):
    require(value >= 0, 'nonnegative distance input')
    lower = value.numerator // value.denominator
    upper = lower+1
    left, right = value-lower, upper-value
    if left < right:
        return lower
    if right < left:
        return upper
    return lower if lower % 2 == 0 else upper


def expected(bits):
    require(0 <= bits < (1 << 64), 'raw input range')
    absolute = bits & ~SIGN
    if bits & SIGN or absolute >= INF or absolute == 0:
        return 0, 0
    x = finite_value(bits)
    if x < (1 << 64):
        return divmod(nearest_integer(x*BILLION), BILLION)
    if x*MILLION >= OVERFLOW_MIDPOINT:
        return 0, 0
    seconds, microseconds = divmod((1 << 64)-1, MILLION)
    return seconds, microseconds*1000


def neighbor_bits(value):
    """Adjacent positive finite encodings around a rational input, for inputs only."""
    require(value >= 0, 'positive input construction')
    low, high = 0, INF
    while low+1 < high:
        mid = (low+high)//2
        if finite_value(mid) <= value:
            low = mid
        else:
            high = mid
    return low, high


def cases():
    selected = {}
    def add(bits, label):
        if 0 <= bits < (1 << 64):
            selected.setdefault(bits, label)
    fractions = [0, 1, 2, 3, (1 << 26)-1, 1 << 26, (1 << 51)-1,
                 1 << 51, (1 << 51)+1, MASK-2, MASK-1, MASK]
    for exponent in range(2048):
        for fraction in fractions:
            for sign in (0, SIGN):
                add(sign | (exponent << 52) | fraction, 'all-exponents/fraction-classes')
    for raw in (0, 1, 0x0010000000000000, 0x3df0000000000000,
                0x3e00000000000000, 0x3f50000000000000, 0x3f68000000000000,
                0x3ff0000000000000, 0x4330000000000000, 0x43f0000000000000,
                0x7eb0c6f7a0b5ed8d, MAX, INF, INF+(1 << 51)):
        for delta in range(-17, 18):
            add(raw+delta, 'neighbor of class/tie/carry boundary')
            add((raw+delta) | SIGN, 'negative class/tie/carry neighbor')
    # Construct both neighbors of many exact half-nanosecond targets. Labels
    # are separate provenance; input IDs never expose which family was used.
    for k in list(range(128))+[976562, 2929687, BILLION-1, BILLION, 2*BILLION-1]:
        for raw in neighbor_bits(Fraction(2*k+1, 2*BILLION)):
            for delta in (-1, 0, 1):
                add(raw+delta, 'half-nanosecond rational neighbors')
                add((raw+delta) | SIGN, 'negative half-nanosecond neighbors')
    for seconds in [1, 2, 3, 5, 10, 60, 300, 999, 1 << 20, 1 << 32, 1 << 52, 1 << 63]:
        for raw in neighbor_bits(Fraction(seconds)):
            for delta in range(-5, 6):
                add(raw+delta, 'integer seconds and carry neighbors')
    for i in range(8192):
        raw = hashlib.sha256(b'visor-duration-pre-source-v1/'+i.to_bytes(8, 'big')).digest()
        add(int.from_bytes(raw[:8], 'big'), 'deterministic full-bit sample')
    # Deliberately not numeric bit order: the input client must preserve IDs
    # and stream order rather than sort or infer outcome classes from position.
    return sorted(selected.items(), key=lambda item: hashlib.sha256(item[0].to_bytes(8, 'big')).digest())


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--out', type=Path, required=True)
    args = parser.parse_args()
    require(not args.out.exists(), 'fresh corpus output required')
    args.out.mkdir(parents=True)
    inputs, outputs, provenance = [], [], []
    for index, (bits, label) in enumerate(cases()):
        opaque = f'{index:016x}'
        seconds, nano = expected(bits)
        require(0 <= seconds < (1 << 64) and 0 <= nano < BILLION, 'canonical returned pair')
        inputs.append(f'{opaque}\t{bits:016x}\n')
        outputs.append(f'{opaque}\t{seconds}\t{nano}\n')
        provenance.append(f'{opaque}\t{label}\n')
    files = {}
    for name, lines in [('inputs.tsv.gz', inputs), ('expected.tsv.gz', outputs), ('provenance.tsv.gz', provenance)]:
        raw = ''.join(lines).encode()
        packed = gzip.compress(raw, mtime=0)
        (args.out/name).write_bytes(packed)
        files[name] = dict(raw_bytes=len(raw), raw_sha256=sha(raw), bytes=len(packed), sha256=sha(packed))
    summary = dict(cases=len(inputs), files=files, algorithm='Exact Fraction input; adjacent integer distance/tie selection; exact overflow midpoint. No floating host operations or native evaluator.',
                   limits='Finite synthetic qualification corpus; universal correspondence needs the addressed manual proof and domain lemmas. IDs have no semantics.')
    (args.out/'summary.json').write_text(json.dumps(summary, sort_keys=True, separators=(',', ':'))+'\n')
    print(json.dumps(dict(cases=len(inputs), inputs_sha256=files['inputs.tsv.gz']['raw_sha256'], expected_sha256=files['expected.tsv.gz']['raw_sha256'])))


if __name__ == '__main__':
    main()
