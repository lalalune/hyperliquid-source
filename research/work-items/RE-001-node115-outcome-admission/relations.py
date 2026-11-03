#!/usr/bin/env python3
"""Operand-derived static relations, not execution/emulation of the capture."""
import argparse
import random
import struct
import verify

MASK = (1 << 64) - 1


def operands(data):
    image = verify.Image(data)
    return {'multiplier': struct.unpack('<Q', image.get(0x283b826, 8))[0],
            'rotate': image.get(0x283b837, 1)[0],
            'limit': struct.unpack('<Q', image.get(0x283b83a, 8))[0],
            'branch': image.get(0x283b84a, 2).hex(),
            'length_limit': image.get(0x283b79e, 1)[0]}


def arithmetic(value, op):
    product = (value * op['multiplier']) & MASK
    n = op['rotate'] & 63
    rotated = ((product >> n) | (product << ((64 - n) & 63))) & MASK
    if op['branch'] == '0f82':
        return rotated < op['limit']
    if op['branch'] == '0f86':
        return rotated <= op['limit']
    raise ValueError('unmodelled native comparison')


def amount_route(first_word, second_word):
    """Projection only for the four measured tags, after the admission gates."""
    tag = first_word ^ (1 << 63) if first_word >> 63 else 3
    if tag not in range(4):
        raise ValueError('outside measured descriptor tag domain')
    if tag in (1, 2) and second_word == 1 << 63:
        return tag, None
    return tag, 0 if tag == 3 else 8


def evaluate(data):
    image = verify.Image(data)
    op = operands(data)
    odd, divisor = 3125, 100000
    verify.require(op['rotate'] == 5 and op['branch'] == '0f82', 'native rotate/comparison')
    verify.require((op['multiplier'] * odd) & MASK == 1, 'odd-factor modular inverse')
    verify.require(odd << op['rotate'] == divisor, 'divisor factorization')
    verify.require(op['limit'] == MASK // divisor + 1, 'exclusive quotient bound')
    verify.require((op['limit'] - 1) < 1 << (64 - op['rotate']), 'no left-rotate wrap for accepted quotient')
    verify.require(op['length_limit'] == 101, 'native length limit')
    rng = random.Random(115)
    values = {0, 1, MASK, MASK - 1}
    for q in [0, 1, 2, 17, MASK // divisor, MASK // divisor - 1] + [rng.randrange(MASK // divisor + 1) for _ in range(1000)]:
        for delta in (-1, 0, 1):
            if 0 <= q * divisor + delta <= MASK:
                values.add(q * divisor + delta)
    values.update(rng.getrandbits(64) for _ in range(3000))
    verify.require(all(arithmetic(x, op) == (x % divisor == 0) for x in values), 'divisibility projection')
    table = 0x5f7478
    targets = [table + x for x in struct.unpack('<4i', image.get(table, 16))]
    starts = {a for a, _, _ in verify.export_rows(image, 'handler', *verify.BODIES['handler'][:2])}
    verify.require(all(x in starts for x in targets), 'dispatch instruction boundaries')
    mutations = [(0x283b826, 1, 'multiplier'), (0x283b837, 1, 'rotate'),
                 (0x283b83a, 1, 'exclusive-limit'), (0x283b84b, 4, 'unsigned-branch')]
    # The strict/inclusive witness is the inverse image of exactly the bound.
    y = op['limit']
    witness = (((y << 5) | (y >> 59)) * odd) & MASK
    values.add(witness)
    controls = []
    for va, xor, label in mutations:
        changed = bytearray(data)
        changed[image.off(va)] ^= xor
        mutated = operands(changed)
        differs = [x for x in sorted(values) if arithmetic(x, mutated) != (x % divisor == 0)]
        verify.require(differs, 'counterfactual must change relation: ' + label)
        controls.append({'operand': label, 'va': hex(va), 'xor': xor, 'witness': differs[0],
                         'original': arithmetic(differs[0], op), 'mutated': arithmetic(differs[0], mutated)})
    changed = bytearray(data)
    changed[image.off(0x283b79e)] = 100
    verify.require(100 < op['length_limit'] and not 100 < operands(changed)['length_limit'], 'length counterfactual')
    routes = [{'first_word': hex(w), 'second_word': hex(s), 'tag': amount_route(w, s)[0],
               'amount_descriptor_offset': amount_route(w, s)[1]}
              for w in [0, MASK >> 1] + [(1 << 63) + t for t in range(4)]
              for s in [0, 1 << 63]]
    return {'native_operands': op, 'unsigned_divisor': divisor, 'checked_values': len(values),
            'proof': 'Multiplication by the inverse of 3125 and rotation by 5 are bijections on u64. Accepted rotated values y are 0..floor(MAX/100000). On that interval ROL5(y)=32*y without wrap, and the inverse image is exactly 100000*y without overflow. Thus precisely the multiples of 100000 pass.',
            'dispatch_targets': [hex(x) for x in targets], 'descriptor_cases': routes,
            'counterfactuals': controls, 'length_counterfactual_witness': 100,
            'limits': 'Parser and conversion helpers are opaque. Zero passes this local arithmetic test, not necessarily the whole action. Raw descriptor tags outside 0..3 are excluded. No target execution or emulation.'}


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--write', action='store_true')
    args = parser.parse_args()
    data = verify.TARGET.read_bytes()
    verify.require(verify.sha(data) == verify.DIGEST, 'wrong target')
    text = verify.encoded(evaluate(data))
    if args.write:
        (verify.PACKET / 'relations.json').write_text(text)
    else:
        verify.require((verify.PACKET / 'relations.json').read_text() == text, 'relations drift')
    print('PASS: operand-derived divisibility proof, descriptor table and counterfactuals')
