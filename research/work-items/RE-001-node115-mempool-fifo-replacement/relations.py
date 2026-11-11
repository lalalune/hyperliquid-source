#!/usr/bin/env python3
"""Check native-operand relations; do not execute or emulate the target."""
import argparse
import itertools
import json
import verify

def read(data, va, size=1):
    return int.from_bytes(verify.Image(data).get(va, size), 'little')

def mutated(data, va, byte):
    result = bytearray(data)
    result[verify.Image(data).off(va)] = byte
    return result

def operands(data):
    return {'occupied_tag': read(data, 0x2cacddf),
            'limit_offset': read(data, 0x2cacea0),
            'exit_condition': read(data, 0x2cacea2),
            'tail_stride': (read(data, 0x2cacf8e) >> 6) & 3,
            'map_offset': read(data, 0x2cacdcd)}

def projected(queue, rows, key, value, limit, o):
    queue, rows = list(queue), dict(rows)
    events = []
    occupied = 1 if key in rows else 0
    if occupied == o['occupied_tag']:
        rows[key] = value
        events.append('replace')
    else:
        rows[key] = value
        queue.append(key)
        events.append('insert-and-append')
    # Counterfactual offset 0x38 would read the map count, not the limit.
    bound = limit if o['limit_offset'] == 0x40 else len(rows)
    while queue and (len(queue) > bound if o['exit_condition'] == 0x86 else len(queue) >= bound):
        old = queue.pop(0)
        events.extend(['pop:' + str(old), 'remove:' + str(old)])
        rows.pop(old, None)
    return queue, sorted(rows.items()), events

def independent(queue, rows, key, value, limit):
    order = list(queue) + ([] if key in rows else [key])
    mapping = dict(rows); mapping[key] = value
    excess = max(0, len(order) - limit)
    evicted, retained = order[:excess], order[excess:]
    return retained, sorted((k, v) for k, v in mapping.items() if k not in evicted)

def evaluate_raw(data):
    o = operands(data)
    verify.require(o == {'occupied_tag': 1, 'limit_offset': 64, 'exit_condition': 134,
                         'tail_stride': 3, 'map_offset': 32}, 'native FIFO operands')
    cases = 0
    for size in range(6):
        for order in itertools.permutations(range(size)):
            rows = {k: k + 20 for k in order}
            for key, limit in itertools.product(range(size + 1), range(7)):
                result = projected(order, rows, key, 99, limit, o)
                verify.require(result[:2] == independent(order, rows, key, 99, limit), 'FIFO relation')
                ev = result[2][1:]
                verify.require(all(ev[i].replace('pop:', '') == ev[i+1].replace('remove:', '') for i in range(0, len(ev), 2)), 'pop-before-remove')
                cases += 1
    ring_cases = 0
    for cap in range(1, 17):
        for front, length in itertools.product(range(cap), range(cap)):
            native_tail = front + length - (cap if front + length >= cap else 0)
            verify.require(native_tail == (front + length) % cap, 'wrapped tail')
            verify.require((front + 1 - (cap if front + 1 >= cap else 0)) == (front + 1) % cap, 'wrapped front')
            ring_cases += 1
    witness = ([1, 2], {1: 10, 2: 20}, 1, 99, 2)
    controls = []
    for va, byte, args in [(0x2cacddf, 0, witness),
                            (0x2cacea0, 0x38, ([1, 2], {1: 10, 2: 20}, 1, 99, 1)),
                            (0x2cacea2, 0x82, witness)]:
        original = projected(*args, o)
        changed = projected(*args, operands(mutated(data, va, byte)))
        verify.require(original != changed, 'counterfactual survived')
        controls.append({'va': hex(va), 'byte': byte, 'original': original, 'mutated': changed})
    return {'native_operands': o, 'queue_cases': cases, 'ring_cases': ring_cases,
            'examples': {'replacement_keeps_position': projected(*witness, o),
                         'replacement_after_limit_reduction': projected(*witness[:-1], 1, o),
                         'zero_limit': projected([], {}, 7, 99, 0, o)},
            'counterfactuals': controls,
            'limits': 'Relations assume valid queue/map consistency, unique queued keys, successful generic lookup/insertion/removal, and valid allocation/ring layout. Ring checks exclude full capacity because native code grows first. These are independent algebraic models of the selected policy, not execution, emulation or proof of allocator/map equivalence.'}

def evaluate(data):
    return json.loads(verify.encoded(evaluate_raw(data)))

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
