#!/usr/bin/env python3
"""Check operand-derived arithmetic relations; do not run or emulate target code."""
import argparse
import itertools
import math
import struct
from fractions import Fraction
import verify

MAX = (1 << 64) - 1

def operands(data):
    im = verify.Image(data)
    f = lambda a: struct.unpack('<d', im.get(a, 8))[0]
    u = lambda a, n: int.from_bytes(im.get(a, n), 'little')
    return {'coarse_scale': f(0x459a60), 'fine_scale': f(0x458cd0),
            'cast_upper': f(0x459090), 'signed_bias': f(0x459360),
            'last_representable_u64': f(0x458d58),
            'limit': u(0x3bf2dd6, 4), 'reject_condition': u(0x3bf2ddb, 1),
            'coarse_complement': u(0x3bf2de1, 4),
            'fine_complement': u(0x3bf2ed9, 4)}

def projected_cast(product, o):
    bits = struct.unpack('<Q', struct.pack('<d', product))[0]
    if bits & 0x7fffffffffffffff > 0x7fefffffffffffff:
        return 0
    clipped = min(o['cast_upper'], max(0.0, product))
    return MAX if clipped > o['last_representable_u64'] else int(clipped)

def mathematical_cast(product):
    if not math.isfinite(product) or product <= 0:
        return 0
    exact = Fraction.from_float(product)
    return min(MAX, exact.numerator // exact.denominator)

def project(x, o):
    coarse = projected_cast(x * o['coarse_scale'], o)
    reject = coarse > o['limit'] if o['reject_condition'] == 0x87 else coarse >= o['limit']
    if reject:
        return ('reject-raw-18',)
    fine = projected_cast(x * o['fine_scale'], o)
    return ('continue', coarse, o['coarse_complement'] - coarse,
            fine, max(0, o['fine_complement'] - fine))

def mutation(data, va, byte, x):
    im = verify.Image(data)
    mutated = bytearray(data)
    mutated[im.off(va)] = byte
    before, after = project(x, operands(data)), project(x, operands(mutated))
    verify.require(before != after, 'counterfactual survived')
    return {'va': hex(va), 'byte': byte, 'input_hex': x.hex(),
            'original': list(before), 'mutated': list(after)}

def evaluate(data):
    o = operands(data)
    verify.require(o == {'coarse_scale': 1000.0, 'fine_scale': 100000000.0,
                        'cast_upper': float(1 << 64), 'signed_bias': float(1 << 63),
                        'last_representable_u64': math.nextafter(float(1 << 64), 0),
                        'limit': 1000, 'reject_condition': 0x87,
                        'coarse_complement': 1000, 'fine_complement': 100000000}, 'native operands')
    values = [0.0, -0.0, -1.0, 0.00000001, 0.0009, 0.001, 0.125, 0.5, 0.9999,
              1.0, 1.0005, 1.001, -math.inf, math.inf, math.nan]
    for x in [0.001, 1.0, 1.001, float(1 << 64) / 1000,
              float.fromhex('0x1.fffffffffffffp+1023') / 1000]:
        values.extend([math.nextafter(x, -math.inf), x, math.nextafter(x, math.inf)])
    for sign, exponent, mantissa in itertools.product([0, 1], [0, 1, 512, 1022, 1023, 1063, 1087, 2046, 2047], [0, 1, (1 << 51), (1 << 52)-1]):
        values.append(struct.unpack('<d', struct.pack('<Q', (sign << 63) | (exponent << 52) | mantissa))[0])
    casts = 0
    for x in values:
        for scale in [1000.0, 100000000.0]:
            product = x * scale
            verify.require(projected_cast(product, o) == mathematical_cast(product), 'finite saturation relation')
            casts += 1
        coarse, fine = mathematical_cast(x * 1000), mathematical_cast(x * 100000000)
        expected = ('reject-raw-18',) if coarse > 1000 else ('continue', coarse, 1000-coarse, fine, max(0, 100000000-fine))
        verify.require(project(x, o) == expected, 'independent scale/complement relation')
    examples = []
    for x in [0.0009, 0.5, 1.0, 1.0005, 1.001]:
        examples.append({'input_hex': x.hex(), 'projection': list(project(x, o))})
    return {'native_operands': o, 'projection_cases': len(values), 'cast_cases': casts,
            'examples': examples,
            'counterfactuals': [mutation(data, 0x459a66, 0x8e, 0.5),
                                mutation(data, 0x3bf2ddb, 0x83, 1.0),
                                mutation(data, 0x458cd6, 0xd6, 0.5)],
            'limits': 'Arithmetic relations assume ordinary binary64 multiplication rounding. They independently check conversion and complement algebra, not native runtime equivalence. The entry helper and token tag checks must also pass. Outer action validation can impose a stricter [0,1] domain; the internal acceptance of a projected value is not an action-level acceptance claim. Payout, state mutation and economic units remain unresolved.'}

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--write', action='store_true')
    args = parser.parse_args()
    data = verify.TARGET.read_bytes()
    verify.require(verify.sha(data) == verify.DIGEST, 'wrong target')
    result = verify.encoded(evaluate(data))
    if args.write:
        (verify.PACKET / 'relations.json').write_text(result)
    else:
        verify.require((verify.PACKET / 'relations.json').read_text() == result, 'relations drift')
    print('PASS: native operand relations and three counterfactuals')
