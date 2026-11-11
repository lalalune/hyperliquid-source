#!/usr/bin/env python3
"""Independent flattened-book/rational-binary64 model, not native execution."""
from fractions import Fraction
from pathlib import Path
import hashlib
import json
import random
import struct
import sys

MAX = (1 << 64) - 1
LIMIT = (1 << 63) - 2


def binary64(value):
    if not value:
        return Fraction(0)
    sign = -1 if value < 0 else 1
    value = abs(value)
    exponent = value.numerator.bit_length() - value.denominator.bit_length()
    if value < Fraction(2) ** exponent:
        exponent -= 1
    shift = 52 - exponent
    n, d = value.numerator, value.denominator
    if shift >= 0:
        n <<= shift
    else:
        d <<= -shift
    q, r = divmod(n, d)
    q += int(2*r > d or (2*r == d and q & 1))
    return sign * (Fraction(q, 1 << shift) if shift >= 0 else Fraction(q << -shift))


def impact(levels, target, upward=False):
    accumulated_n = accumulated_q = 0
    for price, quantity in levels:
        if quantity == 0 or price * quantity > LIMIT:
            return 0
        after = min(MAX, accumulated_n + price * quantity)
        if after < target:
            accumulated_n = after
            accumulated_q = min(MAX, accumulated_q + quantity)
            continue
        if price == 0:
            return 'fault'
        remaining = max(0, target - accumulated_n)
        part = (remaining + (price - 1 if upward else 0)) // price
        if price * part > LIMIT:
            return 0
        n = min(MAX, accumulated_n + price * part)
        q = min(MAX, accumulated_q + part)
        return n // q if 0 < q <= n else 0
    return 0


def premium(a, b, oracle, decimals, mode, divided):
    scale = Fraction(10**(6-decimals))
    reference = binary64(binary64(Fraction(oracle)) / scale)
    first = binary64(binary64(Fraction(a)) / scale)
    second = binary64(binary64(Fraction(b)) / scale)
    if mode:
        positive = max(Fraction(0), binary64(first-reference))
        negative = max(Fraction(0), -binary64(second-reference))
        result = binary64(binary64(positive-negative) / reference)
    else:
        mean = binary64(binary64(first+second) * Fraction(1,2))
        result = binary64(binary64(mean/reference) - 1)
    if divided:
        result = binary64(result / 100)
    return min(Fraction(1,2), max(Fraction(-1,2), result))


def main():
    rng = random.Random(11539134319)
    rows = ['# decimals mode divided oracle target first_price_qty[3] second_price_qty[3] first_impact second_impact value_bits_or_none']
    outcomes = {'some': 0, 'none': 0}
    controls = {'ceil_partial': 0, 'flip_mode': 0, 'omit_divide': 0}
    specials = [0, 1, 2, 127, 1_000_000, 1 << 53, (1 << 53)+1, LIMIT, LIMIT+1, (1 << 63)-1]
    for i in range(10000):
        decimals, mode, divided = i % 7, (i//7) % 2, (i//14) % 2
        if i < 7000:
            first = [(rng.randrange(1,1000001), rng.randrange(1,1000001)) for _ in range(3)]
            second = [(rng.randrange(1,1000001), rng.randrange(1,1000001)) for _ in range(3)]
            available = min(sum(p*q for p,q in first), sum(p*q for p,q in second))
            target = rng.randrange(1,available+1)
            oracle = rng.randrange(1,1500001)
        elif i < 9000:
            # Successful large impacts exercise the unsigned casts and their
            # rounding, not only rejection paths at the signed notional cap.
            anchor = ((1 << 53), (1 << 54), (1 << 62), LIMIT - 4096)[i % 4]
            a_price = anchor + rng.randrange(0, 2048)
            b_price = anchor + rng.randrange(0, 2048)
            first = [(a_price, 1)] * 3
            second = [(b_price, 1)] * 3
            target = max(a_price, b_price)
            oracle = (MAX, (1 << 53)+1, (1 << 63)+1, anchor+1023)[(i//4)%4]
        else:
            first = [(specials[(i+j)%len(specials)], (1,2,MAX)[(i+j)%3]) for j in range(3)]
            second = [(specials[(i+j+2)%len(specials)], (1,2,MAX)[(i+j+1)%3]) for j in range(3)]
            target = (0,1,LIMIT,MAX)[i%4]
            oracle = specials[(i+5)%len(specials)]
            # Fault paths are checked directly, not represented as a fake zero result.
            if oracle and (impact(first,target) == 'fault' or impact(second,target) == 'fault'):
                target = 1
        a,b = (impact(first,target),impact(second,target)) if oracle else (0,0)
        assert a != 'fault' and b != 'fault'
        if oracle and a and b:
            result = premium(a,b,oracle,decimals,mode,divided)
            bits = struct.pack('>d',float(result)).hex()
            outcomes['some'] += 1
            controls['flip_mode'] += premium(a,b,oracle,decimals,1-mode,divided) != result
            controls['omit_divide'] += divided and premium(a,b,oracle,decimals,mode,False) != result
        else:
            bits = 'none'
            outcomes['none'] += 1
        controls['ceil_partial'] += oracle != 0 and (impact(first,target,True), impact(second,target,True)) != (a,b)
        fields = [decimals,mode,divided,oracle,target,*[x for row in first+second for x in row],a,b]
        rows.append(' '.join(map(str,fields)) + ' ' + bits)
    contents = '\n'.join(rows) + '\n'
    root = Path(__file__).resolve().parents[3]
    fixture = root / 'src/node115-funding-premium/tests/reference-vectors.txt'
    if '--write' in sys.argv:
        fixture.parent.mkdir(parents=True,exist_ok=True)
        fixture.write_text(contents)
    else:
        assert fixture.read_text() == contents
    assert all(controls.values())
    print(json.dumps({'cases':10000,'outcomes':outcomes,'controls_differing':controls,
        'sha256':hashlib.sha256(contents.encode()).hexdigest(),
        'method':'Flattened integer books and independently rounded rational binary64 operations, not native execution'},indent=2))


if __name__ == '__main__':
    main()
