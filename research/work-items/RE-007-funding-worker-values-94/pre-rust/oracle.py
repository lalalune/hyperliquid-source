#!/usr/bin/env python3
"""Independent value oracle: exact rationals and adjacent binary64 search.

No captured-code loading, decoding, instruction state or host floating point.
This script is frozen before the production implementation exists.
"""
import argparse
from collections import Counter
from fractions import Fraction
from functools import lru_cache
import gzip
import hashlib
import json
from pathlib import Path
import random
import struct

MIN = -(1 << 63)
MAX = (1 << 63) - 1
SIGN = 1 << 63
INF = 0x7ff0000000000000
MAX_FINITE = INF - 1


def require(ok, message):
    if not ok:
        raise ValueError(message)


@lru_cache(maxsize=32768)
def rational(bits):
    """Exact mathematical real of a finite IEEE binary64 encoding."""
    e = (bits >> 52) & 2047
    require(e != 2047, 'nonfinite rational input')
    f = bits & ((1 << 52) - 1)
    significand, power = (f, -1074) if e == 0 else ((1 << 52) + f, e - 1075)
    value = Fraction(significand << power) if power >= 0 else Fraction(significand, 1 << -power)
    return -value if bits & SIGN else value


@lru_cache(maxsize=16384)
def nearest(value, negative_zero=False):
    """Nearest neighboring representable real, ties to even; no bit-shift rounding."""
    sign = SIGN if value < 0 or (value == 0 and negative_zero) else 0
    value = abs(value)
    # The midpoint between max finite and the next exponent's exact value.
    overflow_midpoint = Fraction((1 << 1024) - (1 << 970))
    if value >= overflow_midpoint:
        return sign | INF
    low, high = 0, MAX_FINITE
    while low < high:
        middle = (low + high + 1) // 2
        if rational(middle) <= value:
            low = middle
        else:
            high = middle - 1
    if low == MAX_FINITE:
        return sign | low
    below, above = value - rational(low), rational(low + 1) - value
    if above < below or (above == below and low & 1):
        low += 1
    return sign | low


def amount(product, rate):
    if (rate & ~SIGN) >= INF:
        return 0
    integer_rounded = rational(nearest(Fraction(product)))
    exact = integer_rounded * rational(rate)
    rounded_bits = nearest(exact, product == 0 and bool(rate & SIGN))
    if rounded_bits & ~SIGN == INF:
        return 0
    rounded = rational(rounded_bits)
    if rounded >= 1 << 63:
        return MAX
    if rounded <= MIN:
        return MIN
    # Fraction's int conversion is exact truncation toward zero.
    return int(rounded)


def saturate(value):
    return min(MAX, max(MIN, value)), not MIN <= value <= MAX


def expected(case):
    positions = sorted(case['positions'])
    rates = dict(case['rates'])
    if case['bypass'] == 0 and case['address'] not in case['members']:
        return {'status': 0, 'balance': case['balance'], 'positions': positions}
    rows = []
    for position in positions:
        asset, tag, local, size, c0, c1, c2 = position
        rate = rates.get(asset)
        if rate is None or rate & ~SIGN == 0:
            continue
        index = asset % 10000
        if index >= len(case['prices']):
            return {'status': 2, 'asset': asset, 'reason': 0}
        if size == 0:
            continue
        price = case['prices'][index]
        if price < 0:
            return {'status': 2, 'asset': asset, 'reason': 1}
        product = price * size
        if not MIN <= product <= MAX:
            return {'status': 2, 'asset': asset, 'reason': 2}
        m = amount(product, rate)
        if m == MIN:
            return {'status': 2, 'asset': asset, 'reason': 3}
        if case['time'][:4] != bytes(4):
            rows.append((asset, -m, size, rate, product, case['address'], case['time']))

    # Independent coordinate decomposition: classify/filter first, derive each
    # position separately, then a prefix fold only for shared balance and sum.
    by_asset = {row[0]: -row[1] for row in rows}
    shared = case['balance']
    new_positions, requests = [], []
    for asset, tag, local, size, c0, c1, c2 in positions:
        if asset not in by_asset:
            new_positions.append((asset, tag, local, size, c0, c1, c2))
            continue
        m = by_asset[asset]
        if tag == 1:
            local, overflow = saturate(local - m)
        else:
            shared, overflow = saturate(shared - m)
        if overflow:
            requests.append((asset, 0))
        values = []
        for i, old in enumerate((c0, c1, c2)):
            value, overflow = saturate(old + m)
            values.append(value)
            if overflow:
                requests.append((asset, i + 1))
        new_positions.append((asset, tag, local, size, *values))
    total = 0
    for i, row in enumerate(rows):
        total, overflow = saturate(total + row[1])
        if overflow:
            require(i != 0, 'impossible first sum overflow')
            requests.append((row[0], 4))
    selected = None
    if rows:
        _, row = max(enumerate(rows), key=lambda pair: (abs(pair[1][4]), -pair[0]))
        selected = (row[0], abs(row[4]), row[5])
    return {'status': 1, 'balance': shared, 'positions': new_positions,
            'rows': rows, 'sum': total, 'selected': selected, 'requests': requests}


def pack_position(p):
    return struct.pack('<QIqqqqq', *p)


def encode_input(case):
    b = bytearray(case['address'] + bytes([case['bypass']]) + case['time'])
    b += struct.pack('<qI', case['balance'], len(case['members']))
    b += b''.join(sorted(case['members']))
    b += struct.pack('<I', len(case['prices']))
    b += b''.join(struct.pack('<q', p) for p in case['prices'])
    b += struct.pack('<I', len(case['rates']))
    b += b''.join(struct.pack('<QQ', *r) for r in sorted(case['rates']))
    b += struct.pack('<I', len(case['positions']))
    b += b''.join(pack_position(p) for p in sorted(case['positions']))
    return bytes(b)


def encode_output(out):
    b = bytearray([out['status']])
    if out['status'] == 2:
        return bytes(b) + struct.pack('<QB', out['asset'], out['reason'])
    b += struct.pack('<qI', out['balance'], len(out['positions']))
    b += b''.join(pack_position(p) for p in out['positions'])
    if out['status'] == 0:
        return bytes(b)
    b += struct.pack('<I', len(out['rows']))
    for asset, payment, size, rate, product, address, time in out['rows']:
        b += struct.pack('<QqqQq', asset, payment, size, rate, product) + address + time
    b += struct.pack('<qB', out['sum'], int(out['selected'] is not None))
    if out['selected'] is not None:
        asset, magnitude, address = out['selected']
        b += struct.pack('<QQ', asset, magnitude) + address
    b += struct.pack('<I', len(out['requests']))
    b += b''.join(struct.pack('<QB', *request) for request in out['requests'])
    return bytes(b)


def base(product=1, rate=0x3ff0000000000000):
    return {'address': bytes(range(20)), 'bypass': 1, 'members': [],
            'time': bytes.fromhex('0100000000000080ffffffff'), 'balance': 0,
            'prices': [0 if product == 0 else 1], 'rates': [(0, rate)],
            'positions': [(0, 0, 7, 1 if product == 0 else product, 0, 0, 0)]}


def cases():
    integers = sorted({MIN, MIN + 1, MIN + 1024, MIN + 1025,
                       MAX, MAX - 1, MAX - 1023, MAX - 1024, 0, 1, -1, 2, -2, 3, -3,
                       *[s * ((1 << k) + d) for k in (51, 52, 53, 54, 60, 62)
                         for d in (-3, -2, -1, 0, 1, 2, 3) for s in (-1, 1)]})
    rates = {0, 1, 2, (1 << 52) - 1, 1 << 52, (1 << 52) + 1,
             MAX_FINITE, INF, INF + 1, INF + (1 << 51), INF + (1 << 51) + 19,
             0x3fe0000000000000, 0x3ff0000000000000, 0x4000000000000000,
             0x43dfffffffffffff, 0x43e0000000000000}
    for exponent in (1, 2, 10, 500, 960, 970, 1022, 1023, 1024, 1075, 1086, 2045, 2046):
        for d in (-1, 0, 1):
            rates.add((exponent << 52) + d)
    rates |= {r | SIGN for r in rates}
    for n in integers:
        for rate in sorted(rates):
            yield 'rounding-domain', base(n, rate)
    for tag in (0, 1, 2, 0xffffffff, 0x100, 0x10001):
        for m in (-MAX, -3, -1, 0, 1, 3, MAX):
            for old in (MIN, MIN + 1, -1, 0, 1, MAX - 1, MAX):
                c = base(m); c['balance'] = old
                p = list(c['positions'][0]); p[1] = tag; p[2] = old; p[4:] = [old] * 3
                c['positions'] = [tuple(p)]
                yield 'saturation-fields', c
    for bypass in (0, 1, 2, 255):
        for membership in (False, True):
            c = base(MIN); c['bypass'] = bypass
            c['members'] = [bytes(20), bytes([255]) * 20]
            if membership: c['members'].append(c['address'])
            yield 'eligibility-before-rejection', c
    for time in (bytes(12), bytes.fromhex('00000000ffffffffffffffff'),
                 bytes.fromhex('000000800000000000000000'), bytes([255]) * 12):
        for asset in (0, 9999, 10000, (1 << 64) - 1):
            for mode in ('missing', 'zero', 'nonzero', 'nan'):
                c = base(MIN); c['time'] = time
                c['positions'] = [(asset, 0, 0, MIN, 0, 0, 0)]
                c['rates'] = [] if mode == 'missing' else [(asset, {'zero': 0, 'nonzero': 0x3ff0000000000000, 'nan': INF+7}[mode])]
                yield 'guard-order', c
    for price in (-1, MIN, 0, 1, 2, MAX):
        for size in (MIN, -2, -1, 0, 1, 2, MAX):
            c = base(); c['prices'] = [price]
            c['positions'] = [(0, 0, 0, size, 0, 0, 0)]
            yield 'checked-product', c
    for products in ([1, -1], [MIN, MAX], [7, -7, 7], [0, 0, 0],
                     [MAX, MAX, -MAX], [-MAX, -MAX, MAX], [3, 5, 5, -8, 8],
                     [1 << 62, 1 << 62, -(1 << 62)],
                     [-(1 << 62), -(1 << 62), 1 << 62]):
        for raw_rate in (0x3ff0000000000000, 0xbff0000000000000, INF+29):
            c = base(); c['prices'] = [1] * len(products)
            c['positions'] = [(i, i % 2, 0, n, 0, 0, 0) for i, n in enumerate(products)]
            c['rates'] = [(i, raw_rate) for i in range(len(products))]
            yield 'ordered-summary', c
    for key in (9999, 10000, (1 << 64) - 1):
        c = base(); c['prices'] = [1] * 10000
        c['positions'] = [(key, 0, 0, 7, 0, 0, 0)]
        c['rates'] = [(key, 0x3ff0000000000000)]
        yield 'full-u64-index', c
    c = base(); c['prices'] = [0] * 3
    c['positions'] = [(i, 0, 0, 1, 0, 0, 0) for i in range(3)]
    c['rates'] = [(i, 0x3ff0000000000000) for i in range(3)]
    yield 'zero-product-first-max', c
    rng = random.Random(0x3757610)
    choices = [MIN, MIN+1, MAX-1, MAX, -100, -1, 0, 1, 100]
    rate_choices = sorted(rates)
    for i in range(1200):
        c = base(); count = rng.randrange(0, 41)
        c['balance'] = rng.choice(choices); c['bypass'] = rng.randrange(256)
        c['prices'] = [rng.choice([0, 1, 2, 7, MAX]) for _ in range(count)]
        c['positions'] = [(j + 10000*rng.randrange(0, 10), rng.choice([0,1,2,0xffffffff]),
                           rng.choice(choices), rng.choice(choices), *[rng.choice(choices) for _ in range(3)]) for j in range(count)]
        c['rates'] = [(p[0], rng.choice(rate_choices)) for p in c['positions'] if rng.randrange(5)]
        if i % 7 == 0: c['time'] = bytes(4) + bytes([i % 256])*8
        yield 'composed-state', c


def controls():
    require(nearest(Fraction(0), True) == SIGN, 'negative zero')
    require(nearest(Fraction(1, 1 << 1075)) == 0, 'underflow even zero')
    require(nearest(Fraction(3, 1 << 1075)) == 2, 'subnormal halfway even')
    require(nearest(Fraction((1 << 53) + 1)) == 0x4340000000000000, 'integer halfway down')
    require(nearest(Fraction((1 << 53) + 3)) == 0x4340000000000002, 'integer halfway up')
    midpoint = (1 << 1024) - (1 << 970)
    require(nearest(Fraction(midpoint)) == INF, 'overflow midpoint')
    require(nearest(Fraction(midpoint - 1)) == MAX_FINITE, 'below overflow midpoint')
    require(amount(MIN, 0x3ff0000000000000) == MIN, 'finite minimum rejected domain')
    require(amount(MIN, INF) == 0, 'nonfinite positive')
    require(amount(MAX, SIGN | INF) == 0, 'nonfinite negative')
    require(amount(MAX, 0x3ff0000000000000) == MAX, 'positive clamp after integer round')
    M = 0x346dc5d63886594b
    require(M * 10000 == (1 << 75) + 432, 'reciprocal identity')
    require(432 * (((1 << 64)-1)//10000) + M*9999 < 1 << 75, 'reciprocal bound')
    return 13


def generate(out):
    require(not out.exists(), 'existing output refused')
    checked = controls()
    inputs, outputs = bytearray(), bytearray()
    counts, statuses = Counter(), Counter()
    for identifier, (kind, case) in enumerate(cases()):
        require(len(case['address']) == 20 and len(case['time']) == 12, 'fixed input width')
        require(len(dict(case['rates'])) == len(case['rates']), 'duplicate rate key')
        require(len({p[0] for p in case['positions']}) == len(case['positions']), 'duplicate position key')
        answer = expected(case)
        inp, result = encode_input(case), encode_output(answer)
        inputs += struct.pack('<QI', identifier, len(inp)) + inp
        outputs += struct.pack('<QI', identifier, len(result)) + result
        counts[kind] += 1; statuses[str(answer['status'])] += 1
    out.mkdir(parents=True)
    files = {}
    for name, raw in [('inputs.bin.gz', inputs), ('expected.bin.gz', outputs)]:
        compressed = gzip.compress(bytes(raw), mtime=0)
        (out/name).write_bytes(compressed)
        files[name] = {'raw_bytes': len(raw), 'raw_sha256': hashlib.sha256(raw).hexdigest(),
                       'stored_bytes': len(compressed), 'stored_sha256': hashlib.sha256(compressed).hexdigest()}
    metadata = {'count': sum(counts.values()), 'classes': dict(counts), 'statuses': dict(statuses),
                'mathematical_controls': checked, 'files': files,
                'oracle': 'Exact Fraction values, binary search for neighboring representable values, tie parity; no host float or target evaluation.',
                'failure_scope': 'Safe supplied-input refusals only; no native failure state or rollback equivalence.'}
    (out/'corpus.json').write_text(json.dumps(metadata, indent=2)+'\n')
    return metadata


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out', type=Path, required=True)
    args = parser.parse_args()
    print(json.dumps(generate(args.out), indent=2))
