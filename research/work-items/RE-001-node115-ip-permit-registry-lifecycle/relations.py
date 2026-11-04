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
    return {'occupied_tag': read(data, 0x476fba8),
            'limit_high_shift': read(data, 0x476fbd2),
            'tree_equal_condition': read(data, 0x4765bb1),
            'flat_equal_condition': read(data, 0x476af08),
            'state_offset': read(data, 0x4765ba9),
            'limit_offset': read(data, 0x4784ae8),
            'key_tail_offset': read(data, 0x4784ac6)}

def removed(state, limit, o, tree=True):
    equal = state // 2 == limit
    condition = o['tree_equal_condition'] if tree else o['flat_equal_condition']
    return equal if condition in (0x84, 0x74) else not equal

def entry(existing, limit, o):
    tag = 2 if existing is not None else 0
    if tag == o['occupied_tag']:
        return ('reuse', existing)
    if limit >> o['limit_high_shift']:
        return ('panic-limit', None)
    return ('create', limit * 2)

def transaction(rows, key, limit, cadence, o):
    kept = {k:v for k,v in rows.items() if not cadence or not removed(v, limit, o)}
    decision, state = entry(kept.get(key), limit, o)
    if state is not None:
        kept[key] = state
    return decision, state, sorted(kept.items())

def evaluate_raw(data):
    o = operands(data)
    verify.require(o == {'occupied_tag':2, 'limit_high_shift':61,
                         'tree_equal_condition':0x84, 'flat_equal_condition':0x74,
                         'state_offset':48, 'limit_offset':40, 'key_tail_offset':16}, 'native lifecycle operands')
    prune_cases = 0
    values = list(range(66)) + [(1<<61)-1, 1<<61, (1<<64)-1]
    for state, limit in itertools.product(values, [0,1,2,7,31,32,(1<<61)-1]):
        expected = state // 2 == limit
        verify.require(removed(state, limit, o) == expected == removed(state, limit, o, False), 'both pruning predicates')
        # Closed low bit cannot affect this observed pruning decision.
        verify.require(removed(state ^ 1, limit, o) == expected, 'low-bit independence')
        prune_cases += 1
    entry_cases = 0
    limits=[0,1,2,31,(1<<61)-1,1<<61,(1<<64)-1]
    for existing, limit in itertools.product([None,0,1,2,6,7], limits):
        expected = ('reuse', existing) if existing is not None else (('create',2*limit) if limit < (1<<61) else ('panic-limit',None))
        verify.require(entry(existing,limit,o) == expected, 'create/reuse relation')
        entry_cases += 1
    examples=[]
    for cadence, limit in itertools.product([False,True],[2,3,4]):
        examples.append({'rows':[['a',6],['b',4]], 'requested_key':'a',
                         'limit':limit, 'cadence':cadence,
                         'before_acquisition':transaction({'a':6,'b':4},'a',limit,cadence,o)})
    controls=[]
    for va,byte,kind,args in [(0x476fba8,1,'entry',(6,4)),
                              (0x476fbd2,62,'entry',(None,1<<61)),
                              (0x4765bb1,0x85,'prune',(6,3))]:
        fn = entry if kind == 'entry' else removed
        before=fn(*args,o);after=fn(*args,operands(mutated(data,va,byte)))
        verify.require(before != after,'counterfactual survived')
        controls.append({'va':hex(va),'byte':byte,'inputs':args,'original':before,'mutated':after})
    return {'native_operands':o,'pruning_cases':prune_cases,'entry_cases':entry_cases,
            'examples_before_acquisition':examples,'counterfactuals':controls,
            'limits':'Relations stop before already documented packed permit acquisition. They assume valid keys, layouts, successful allocation/map operations and a supplied cadence outcome. Pruning reads an atomic state snapshot; this is not a concurrency proof, elapsed-time expiry claim, or claim that all configuration changes are supported. Equality uses the current limit, not a stored original capacity.'}

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
