#!/usr/bin/env python3
"""Algebra for selected native relations; never execute or emulate the capture."""
import argparse
import struct
import verify

MASK = (1 << 64) - 1
SIGN = 1 << 63


def parameters(data):
    image = verify.Image(data)
    u = lambda a, n: int.from_bytes(image.get(a, n), 'little')
    return {'accepted_tag': u(0x2c64ade, 2),
            'scale': u(0x2c65706, 4),
            'presence_mask': u(0x2c65724, 1),
            'route_condition': u(0x2c65741, 1),
            'location_condition': u(0x2c65748, 1),
            'magnitude_condition': u(0x2c6574f, 1),
            'direct_sign_xor': u(0x2c649e3, 8),
            'tagged_sign_xor': u(0x2c64b60, 8)}


def signed(bits):
    return bits if bits < SIGN else bits - (1 << 64)


def addition(a, b, sign_xor):
    """The local ADD/JO/SAR/XOR/CMOVNO relation, if the overflow hook returns."""
    wrapped = (a + b) & MASK
    overflow = bool((~(a ^ b) & (a ^ wrapped)) & SIGN)
    endpoint = ((MASK if wrapped & SIGN else 0) ^ sign_xor) & MASK
    return signed(endpoint if overflow else wrapped)


def seed_admitted(mode, tag, p):
    return mode == 0 or tag == p['accepted_tag']


def cmov(condition, borrow, zero):
    if condition == 0x42:  # CMOVB: the capture
        return borrow
    if condition == 0x46:  # CMOVBE: an explicit counterfactual
        return borrow or zero
    raise ValueError('unsupported condition')


def residual(quantity, presence, value, p):
    """Per yielded pair in R9B=0 mode; lookup result supplied as a premise."""
    assert 0 <= quantity <= MASK and 0 <= value <= MASK
    product = quantity * p['scale']
    if product > MASK:
        return {'request': False, 'reason': 'unsigned product overflow'}
    have = value if presence & p['presence_mask'] else 0
    d1, d2 = (have - product) & MASK, (product - have) & MASK
    destination = 'shortfall' if cmov(p['route_condition'], have < product, have == product) else 'surplus'
    location = 113 if cmov(p['location_condition'], have < product, have == product) else 110
    magnitude = d1 if cmov(p['magnitude_condition'], product < have, product == have) else d2
    return {'request': True, 'destination': destination, 'location_line': location, 'value': magnitude}


def deductions(data):
    p = parameters(data)
    verify.require(p == {'accepted_tag': 0x1a2, 'scale': 100, 'presence_mask': 1,
                         'route_condition': 0x42, 'location_condition': 0x42,
                         'magnitude_condition': 0x42, 'direct_sign_xor': SIGN,
                         'tagged_sign_xor': SIGN}, 'relation parameters changed')
    signed_values = {-SIGN, -SIGN + 1, -1, 0, 1, SIGN - 2, SIGN - 1}
    for exponent in range(63):
        for delta in (-1, 0, 1):
            for sign in (-1, 1):
                x = sign * ((1 << exponent) + delta)
                if -SIGN <= x < SIGN:
                    signed_values.add(x)
    pairs = {(a, b) for a in signed_values for b in (-SIGN, -1, 0, 1, SIGN - 1)}
    for a, b in pairs:
        expected = min(SIGN - 1, max(-SIGN, a + b))
        for key in ('direct_sign_xor', 'tagged_sign_xor'):
            verify.require(addition(a, b, p[key]) == expected, 'signed saturation algebra')
    maximum = MASK // 100
    cases = [(0, 1, 0, 'surplus', 0), (1, 1, 100, 'surplus', 0),
             (1, 1, 99, 'shortfall', 1), (1, 1, 101, 'surplus', 1),
             (1, 0, MASK, 'shortfall', 100), (1, 2, MASK, 'shortfall', 100),
             (1, 3, 101, 'surplus', 1), (maximum, 1, MASK, 'surplus', 15),
             (maximum, 0, 0, 'shortfall', MASK - 15)]
    table = []
    for q, flag, value, destination, amount in cases:
        row = residual(q, flag, value, p)
        verify.require(row == {'request': True, 'destination': destination,
                               'location_line': 113 if destination == 'shortfall' else 110,
                               'value': amount}, 'independent residual boundary')
        table.append({'quantity': q, 'presence_byte': flag, 'lookup_value': value, **row})
    for quantity in (maximum + 1, SIGN, MASK):
        row = residual(quantity, 1, MASK, p)
        verify.require(not row['request'], 'scale overflow must skip, not saturate')
        table.append({'quantity': quantity, **row})
    # The raw u16 comparison is exact. Nonzero input bytes all select the tagged path.
    for mode in (0, 1, 2, 255):
        for tag in range(65536):
            verify.require(seed_admitted(mode, tag, p) == (mode == 0 or tag == 418), 'tag gate')
    # Independent integer reference for each side and all raw low-byte presence flags.
    residual_count = 0
    for q in (0, 1, maximum - 1, maximum, maximum + 1, MASK):
        for flag in range(256):
            for value in (0, 99, 100, 101, SIGN, MASK):
                row = residual(q, flag, value, p)
                if q > maximum:
                    verify.require(not row['request'], 'overflow relation')
                else:
                    delta = (value if flag % 2 else 0) - 100 * q
                    verify.require(row['destination'] == ('surplus' if delta >= 0 else 'shortfall')
                                   and row['value'] == abs(delta), 'residual algebra')
                residual_count += 1
    return {'schema': 1, 'target_sha256': verify.DIGEST, 'parameters': p,
            'scope': 'Static algebra under helper-return, valid-memory and yielded-pair premises; no capture execution/emulation.',
            'signed_add_pairs_per_mode': len(pairs), 'tag_mode_pairs': 4 * 65536,
            'residual_cases': residual_count, 'boundary_table': table,
            'max_scaled_input': maximum, 'next_input_is_skipped': maximum + 1}


def counterfacts(data):
    image = verify.Image(data)
    trials = [
        ('accepted tag', 0x2c64ade, 0xa3, lambda p: seed_admitted(1, 418, p)),
        ('unsigned multiplier', 0x2c65706, 99, lambda p: residual(MASK // 100 + 1, 1, MASK, p)),
        ('presence low bit', 0x2c65724, 2, lambda p: residual(1, 2, 101, p)),
        ('equality destination', 0x2c65741, 0x46, lambda p: residual(1, 1, 100, p)),
        ('equality source location', 0x2c65748, 0x46, lambda p: residual(1, 1, 100, p)),
        ('positive signed endpoint', 0x2c649ea, 0, lambda p: addition(SIGN - 1, 1, p['direct_sign_xor'])),
        ('negative signed endpoint', 0x2c64b67, 0, lambda p: addition(-SIGN, -1, p['tagged_sign_xor'])),
    ]
    rows = []
    for name, va, byte, prediction in trials:
        changed = bytearray(data)
        changed[image.off(va)] = byte
        before, after = prediction(parameters(data)), prediction(parameters(changed))
        verify.require(before != after, 'inert counterfactual: ' + name)
        try:
            verify.observe(changed, body_hashes=False, exports=False)
        except ValueError as error:
            rows.append({'name': name, 'va': hex(va), 'before': before, 'after': after, 'rejection': str(error)})
        else:
            raise ValueError('counterfactual survived: ' + name)
    return rows


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--write', action='store_true')
    args = parser.parse_args()
    data = verify.TARGET.read_bytes()
    verify.require(verify.sha(data) == verify.DIGEST, 'wrong artifact')
    report = deductions(data)
    report['actual_byte_counterfacts'] = counterfacts(data)
    text = verify.encoded(report)
    path = verify.PACKET / 'relations.json'
    if args.write:
        path.write_text(text)
    else:
        verify.require(path.read_text() == text, 'relation regeneration differs')
    print('PASS: seed tag, signed saturation, unsigned scale/residual boundaries, 7 byte counterfacts')


if __name__ == '__main__':
    main()
