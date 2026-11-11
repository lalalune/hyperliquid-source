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
    return {'original_xor': read(data, 0x4d56b92), 'alias_xor': read(data, 0x4d56c90),
            'fallback_raw': read(data, 0x4d56c92), 'select_condition': read(data, 0x4d56c9a),
            'missing_raw': read(data, 0x4d56b57), 'row_offset': read(data, 0x4d56b90)}

def projected(original, alias, available, o):
    raw = o['missing_raw'] if original is None else original ^ o['original_xor']
    if not available or alias is None:
        return raw
    alias_raw = alias ^ o['alias_xor']
    keep = raw != o['fallback_raw'] if o['select_condition'] == 0x45 else raw == o['fallback_raw']
    return raw if keep else alias_raw

def evaluate_raw(data):
    o = operands(data)
    verify.require(o == {'original_xor': 1, 'alias_xor': 1, 'fallback_raw': 2,
                         'select_condition': 0x45, 'missing_raw': 2, 'row_offset': 24}, 'native IP operands')
    cases = 0
    for original, alias, available in itertools.product([None] + list(range(256)), [None] + list(range(256)), [False, True]):
        raw = 2 if original is None else original ^ 1
        expected = alias ^ 1 if available and alias is not None and raw == 2 else raw
        verify.require(projected(original, alias, available, o) == expected, 'raw precedence relation')
        cases += 1
    controls = []
    for va, byte, args in [(0x4d56b92, 0, (0, 1, True)),
                            (0x4d56c92, 3, (None, 0, True)),
                            (0x4d56c9a, 0x44, (1, 0, True))]:
        original = projected(*args, o)
        changed = projected(*args, operands(mutated(data, va, byte)))
        verify.require(original != changed, 'counterfactual survived')
        controls.append({'va': hex(va), 'byte': byte, 'inputs': args, 'original': original, 'mutated': changed})
    return {'native_operands': o, 'raw_precedence_cases': cases,
            'examples': [{'original_byte': a, 'alias_byte': b, 'alias_available': c,
                          'result': projected(a, b, c, o)} for a,b,c in
                         [(0,1,True),(1,0,True),(None,0,True),(None,1,True),(None,None,True),(3,0,True),(None,0,False)]],
            'counterfactuals': controls,
            'limits': 'The algebra exhausts all original/alias byte states plus absence and alias availability. It does not establish runtime map validity, concurrent behavior, translation initialization, or the meaning of raw statuses. Canonical Boolean rows 0/1 preserve the original result; a noncanonical row byte 3 also yields fallback raw 2. The native original query precedes the alias query even when the original result will win.'}

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
