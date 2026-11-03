#!/usr/bin/env python3
"""Static prefix collection and lookup-result relations from native operands."""
import argparse
import itertools
import struct
import verify


def operands(data):
    image = verify.Image(data)
    return {'input_strides': [image.get(a, 1)[0] for a in (0x5b9cad8, 0x5b9cb93)],
            'first_stop': image.get(0x5b9cb2f, 2).hex(),
            'later_stop': image.get(0x5b9cbfb, 1).hex(),
            'failure_values': [image.get(a, 1)[0] for a in (0x5b9cc32, 0x5b9cc56)],
            'first_allocation_bytes': struct.unpack('<I', image.get(0x5b9cb47, 4))[0],
            'tree_compare_bytes': struct.unpack('<I', image.get(0x4fbbafa, 4))[0]}


def collect(results, initial_flag, op):
    """Normal allocator/helper-return projection; results are supplied opaque handles."""
    prefix, flag, calls = [], initial_flag, []
    for i, value in enumerate(results):
        offset = 0 if i == 0 else op['input_strides'][0] + (i - 1) * op['input_strides'][1]
        calls.append(offset)
        branch = op['first_stop'] if i == 0 else op['later_stop']
        if branch in ('0f84', '74'):
            stop = value == 0
        elif branch in ('0f85', '75'):
            stop = value != 0
        else:
            raise ValueError('unmodelled native stop branch')
        if stop:
            flag = op['failure_values'][int(i != 0)]
            break
        prefix.append(value)
    return {'prefix': prefix, 'flag': flag, 'lookup_byte_offsets': calls}


def flat_slot(capacity, head, length, helper_tag, helper_index):
    if helper_tag & 1 or helper_index >= length:
        return None
    position = head + helper_index
    if position >= capacity:
        position -= capacity
    return 40 * position + 32


def evaluate(data):
    image, op = verify.Image(data), operands(data)
    verify.require(op == {'input_strides': [32, 32], 'first_stop': '0f84',
                         'later_stop': '74', 'failure_values': [1, 1],
                         'first_allocation_bytes': 32, 'tree_compare_bytes': 32}, 'native RPC operands')
    checked = 0
    for length in range(8):
        for seq in itertools.product((0, 8, 24), repeat=length):
            first_zero = seq.index(0) if 0 in seq else len(seq)
            for flag in (0, 1, 2, 255):
                expected = {'prefix': list(seq[:first_zero]), 'flag': 1 if first_zero < len(seq) else flag,
                            'lookup_byte_offsets': [32 * i for i in range(min(len(seq), first_zero + 1))]}
                verify.require(collect(seq, flag, op) == expected, 'first-zero prefix relation')
                checked += 1
    slots = 0
    for capacity in range(1, 17):
        for head in range(capacity):
            for length in range(capacity + 1):
                for index in range(length + 2):
                    for tag in range(4):
                        expected = None if tag & 1 or index >= length else 40 * ((head + index) % capacity) + 32
                        verify.require(flat_slot(capacity, head, length, tag, index) == expected, 'flat ring slot')
                        slots += 1
    reference_cases = []
    for old in (0, 1, (1 << 63) - 2, (1 << 63) - 1, 1 << 63, (1 << 64) - 2, (1 << 64) - 1):
        new = (old + 1) & ((1 << 64) - 1)
        zf, sf, of = new == 0, bool(new >> 63), old == (1 << 63) - 1
        trap = zf or sf != of
        verify.require(trap == bool(old >> 63), 'INC/JLE flag relation')
        reference_cases.append({'old': hex(old), 'new': hex(new), 'trap': trap})
    controls = []
    for va, value, label, seq in [(0x5b9cb30, 0x85, 'first zero stop', [8, 0, 24]),
                                 (0x5b9cbfb, 0x75, 'later zero stop', [8, 0, 24]),
                                 (0x5b9cc56, 2, 'later failure value', [8, 0]),
                                 (0x5b9cb93, 31, 'input stride', [8, 24, 8])]:
        changed = bytearray(data)
        changed[image.off(va)] = value
        original, mutated = collect(seq, 0, op), collect(seq, 0, operands(changed))
        verify.require(original != mutated, 'operand counterfactual: ' + label)
        controls.append({'operand': label, 'va': hex(va), 'new_byte': value, 'helper_results': seq,
                         'original': original, 'mutated': mutated})
    return {'native_operands': op, 'prefix_cases': checked, 'flat_slot_cases': slots,
            'reference_increment_cases': reference_cases,
            'counterfactuals': controls,
            'lookup': {'tree_key_bytes': 32, 'tree_count_offset': 450, 'tree_children_offset': 456,
                       'flat_row_bytes': 40, 'flat_value_offset': 32,
                       'hit': 'load handle, LOCK INC at handle+0, then JLE to UD2 (ZF or SF != OF); this rejects signed-negative pre-increment words',
                       'miss': 'return zero after lock/timing cleanup'},
            'limits': 'Normal helper/allocator returns and valid collection/iterator layouts only. Flat search helper, public request types, timing/locks, concurrency, malformed input and full unwind ownership remain outside the relation. No target execution or emulation.'}


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
    print('PASS: first-zero prefix, sticky failure flag and flat lookup slot relations')
