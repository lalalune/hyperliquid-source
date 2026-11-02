#!/usr/bin/env python3
"""Static algebra for the admitted sampler operands; never execute the capture."""
import argparse
import struct
import verify

U32 = (1 << 32) - 1
U64 = (1 << 64) - 1


def parameters(data):
    image = verify.Image(data)
    u = lambda a, n=1: int.from_bytes(image.get(a, n), 'little')
    return {'record_stride': u(0x5b29b5a, 4), 'value_offset': u(0x5b29b66),
            'group_offset': u(0x5b29b89, 4), 'sequence_offset': u(0x5b29ba7, 4),
            'pair_shift': u(0x5b29b0a), 'first_count': u(0x5b29bd9),
            'second_count': u(0x5b29ce2), 'gate': u(0x5b29d21),
            'hour_multiplier': u(0x5b29cf1, 4), 'hour_shift': u(0x5b29cfc),
            'hour_scale': u(0x5b29cff), 'minute_multiplier': u(0x5b29d01, 4),
            'minute_shift': u(0x5b29d0c), 'reduce_multiplier': u(0x5b29d10, 4),
            'reduce_shift': u(0x5b29d17), 'reduce_scale': u(0x5b29d1a)}


def gate_word(word, p):
    """Unsigned arithmetic of the selected straight-line instruction span."""
    assert 0 <= word <= U32
    first = ((word * p['hour_multiplier']) >> p['hour_shift']) * p['hour_scale']
    minutes = (word * p['minute_multiplier']) >> p['minute_shift']
    reduced = ((minutes * p['reduce_multiplier']) >> p['reduce_shift']) * p['reduce_scale']
    return (minutes - reduced + first) & U32


def calls(first_count, second_count, word, outer_byte, p):
    assert 0 <= first_count <= U64 and 0 <= second_count <= U64 and 0 <= outer_byte < 256
    if outer_byte == 0:
        return []
    result = []
    if first_count >= p['first_count']:
        result.append('0x5b29cba')
    if second_count > p['second_count'] and gate_word(word, p) >= p['gate']:
        result.append('0x5b29e02')
    return result


def spans(capacity, head, length):
    """The non-sentinel flat branch, with explicit coherent-ring premises."""
    assert 0 < capacity < (1 << 63) and 0 <= head < 2 * capacity and 0 <= length <= capacity
    if length == 0:
        return (0, 0), (0, 0)
    start = head - (capacity if head >= capacity else 0)
    remaining = capacity - start
    return ((start, capacity), (0, length - remaining)) if length > remaining else ((start, start + length), (0, 0))


def pair(record, p):
    """Record loads only; the group-map lookup/reserve behavior is a premise."""
    base = p['value_offset']
    group, = struct.unpack_from('<I', record, base + p['group_offset'])
    sequence, = struct.unpack_from('<Q', record, base + p['sequence_offset'])
    key, = struct.unpack_from('<Q', record, 0)
    return {'group_request_key': group, 'pair': [sequence, key]}


def reciprocal_proof(divisor, multiplier, shift, maximum):
    # x = d*q+r.  x*M/2**s = q + (q*e+r*M)/2**s, e=d*M-2**s.
    # A nonnegative residual strictly below 2**s proves floor division for
    # every admitted x, without enumerating 2**32 inputs.
    error = divisor * multiplier - (1 << shift)
    bound = (maximum // divisor) * error + (divisor - 1) * multiplier
    verify.require(error >= 0 and bound < 1 << shift, 'reciprocal interval proof')
    verify.require(maximum * multiplier <= U64, 'native multiply cannot overflow')
    return {'divisor': divisor, 'multiplier': multiplier, 'shift': shift,
            'maximum_input': maximum, 'error': error, 'residual_upper_bound': bound,
            'exclusive_limit': 1 << shift}


def deductions(data):
    p = parameters(data)
    verify.require(p == {'record_stride': 616, 'value_offset': 8, 'group_offset': 576,
                         'sequence_offset': 512, 'pair_shift': 4, 'first_count': 3,
                         'second_count': 1, 'gate': 6, 'hour_multiplier': 0x91a2b3c5,
                         'hour_shift': 43, 'hour_scale': 60, 'minute_multiplier': 0x88888889,
                         'minute_shift': 37, 'reduce_multiplier': 0x8888889,
                         'reduce_shift': 33, 'reduce_scale': 60}, 'changed relation operands')
    proofs = [reciprocal_proof(3600, p['hour_multiplier'], p['hour_shift'], U32),
              reciprocal_proof(60, p['minute_multiplier'], p['minute_shift'], U32),
              reciprocal_proof(60, p['reduce_multiplier'], p['reduce_shift'], U32 // 60)]
    # floor(floor(x/60)/60)=floor(x/3600), so the two scaled terms cancel.
    # Both scaled terms and their final sum fit u32 over the admitted domain.
    verify.require((U32 // 3600) * 60 <= U32 and U32 // 60 <= U32, 'u32 range proof')
    values = {0, 1, 59, 60, 359, 360, 361, 3599, 3600, 3601, 86399, 86400, U32}
    for shift in range(32):
        for d in (-1, 0, 1):
            x = (1 << shift) + d
            if 0 <= x <= U32:
                values.add(x)
    for q in range(1441):
        for d in (-1, 0, 1):
            x = 60 * q + d
            if 0 <= x <= U32:
                values.add(x)
    for x in values:
        verify.require(gate_word(x, p) == x // 60, 'reciprocal reference')
    span_count = 0
    for capacity in range(1, 41):
        for head in range(2 * capacity):
            for length in range(capacity + 1):
                a, b = spans(capacity, head, length)
                actual = list(range(*a)) + list(range(*b))
                expected = [(head + i) % capacity for i in range(length)]
                verify.require(actual == expected, 'independent circular-index reference')
                span_count += 1
    gate_cases = 0
    for outer in range(256):
        for first in (0, 1, 2, 3, 4, U64):
            for second in (0, 1, 2, 3, U64):
                for word in (0, 359, 360, 361, 3599, 3600, U32):
                    expected = ([] if not outer else
                                (['0x5b29cba'] if first >= 3 else []) +
                                (['0x5b29e02'] if second >= 2 and word >= 360 else []))
                    verify.require(calls(first, second, word, outer, p) == expected, 'independent gates')
                    gate_cases += 1
    record = bytearray(616)
    struct.pack_into('<Q', record, 0, 0x1122334455667788)
    struct.pack_into('<Q', record, 0x208, 0xaabbccddeeff0011)
    struct.pack_into('<I', record, 0x248, 0x10203040)
    loaded = pair(record, p)
    verify.require(loaded == {'group_request_key': 0x10203040,
                             'pair': [0xaabbccddeeff0011, 0x1122334455667788]}, 'independent record layout')
    return {'schema': 1, 'target_sha256': verify.DIGEST, 'parameters': p,
            'scope': 'Static relations under valid-container and normal-helper premises; no execution or full sampler equivalence.',
            'reciprocal_proofs': proofs, 'raw_u32_inputs_covered_by_proof': 1 << 32,
            'independent_word_checks': len(values), 'ring_span_cases': span_count,
            'independent_gate_cases': gate_cases, 'record_layout_witness': loaded,
            'same_count_examples': [{'count': n, 'word': x, 'calls': calls(n, n, x, 1, p)}
                                    for n in (0, 1, 2, 3) for x in (359, 360)]}


def counterfacts(data):
    image = verify.Image(data)
    record = bytearray(616)
    struct.pack_into('<Q', record, 0x208, 11)
    struct.pack_into('<Q', record, 0x210, 22)
    trials = [
        ('first count gate', 0x5b29bd9, 2, lambda p: calls(2, 2, 0, 1, p)),
        ('second count gate', 0x5b29ce2, 2, lambda p: calls(2, 2, 360, 1, p)),
        ('first reciprocal', 0x5b29cf1, 0xc4, lambda p: gate_word(3600, p)),
        ('minute reciprocal', 0x5b29d01, 0x88, lambda p: gate_word(360, p)),
        ('reduction reciprocal', 0x5b29d10, 0x88, lambda p: gate_word(3600, p)),
        ('normalized threshold', 0x5b29d21, 7, lambda p: calls(2, 2, 360, 1, p)),
        ('sequence source field', 0x5b29ba7, 8, lambda p: pair(record, p)),
        ('flat record advance', 0x5b29b5a, 0x60, lambda p: 0x1000 + p['record_stride']),
    ]
    rows = []
    for name, va, byte, predict in trials:
        changed = bytearray(data)
        changed[image.off(va)] = byte
        before, after = predict(parameters(data)), predict(parameters(changed))
        verify.require(before != after, 'inert counterfactual: ' + name)
        try:
            verify.observe(changed, body_hashes=False, exports=False)
        except ValueError as error:
            rows.append({'name': name, 'va': hex(va), 'original_byte': image.get(va, 1).hex(),
                         'replacement_byte': f'{byte:02x}', 'before': before, 'after': after,
                         'rejection': str(error)})
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
    print('PASS: full-u32 reciprocal proof, flat-span and pair-layout relations, independent gates, 8 byte counterfacts')


if __name__ == '__main__':
    main()
