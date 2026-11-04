#!/usr/bin/env python3
"""Check address-validation ordering using native operands, without target execution."""
import argparse
import json
import verify

def read(data, va, size=1):
    return int.from_bytes(verify.Image(data).get(va, size), 'little')

def mutated(data, va, byte):
    result = bytearray(data)
    result[verify.Image(data).off(va)] = byte
    return result

def operands(data):
    return {'accepted_variant': read(data, 0x5ab4150), 'invalid_fd': read(data, 0x5ab4177),
            'diagnostic_length': read(data, 0x5ab415b, 4), 'address_offset': read(data, 0x5ab4194),
            'port_offset': read(data, 0x5ab41b6), 'error_raw': read(data, 0x5ab418c, 4),
            'pending_raw': read(data, 0x5ab424b, 4), 'constructor_slot': 0x5ab41ca + int.from_bytes(verify.Image(data).get(0x5ab41c6, 4), 'little', signed=True)}

def projected(outcome, variant, fd, o):
    if outcome == 'pending':
        return {'events': ['pending'], 'raw': o['pending_raw']}
    if outcome == 'error':
        return {'events': ['convert_connection_error'], 'raw': o['error_raw']}
    if variant == o['accepted_variant']:
        return {'events': ['read_saved_variant', 'read_ipv4_and_port', 'call_existing_constructor'], 'raw': 'constructor result'}
    invalid_fd = o['invalid_fd'] if o['invalid_fd'] < 128 else o['invalid_fd'] - 256
    return {'events': ['read_saved_variant', 'build_error', 'first_cleanup'] + (['close'] if fd != invalid_fd else []) + ['second_cleanup'],
            'raw': o['error_raw'], 'diagnostic_length': o['diagnostic_length']}

def evaluate(data):
    o = operands(data)
    verify.require(o == {'accepted_variant': 0, 'invalid_fd': 255, 'diagnostic_length': 9,
                         'address_offset': 34, 'port_offset': 38, 'error_raw': 2,
                         'pending_raw': 3, 'constructor_slot': 0x64e7540}, 'native connector operands')
    verify.require(verify.Image(data).get(0x93c599, o['diagnostic_length']) == b'ip not v4', 'bounded error text')
    cases = 0
    examples = []
    for outcome in ['pending', 'error', 'success']:
        for variant in range(256):
            for fd in [-2147483648, -1, 0, 1, 2147483647]:
                result = projected(outcome, variant, fd, o)
                events = result['events']
                verify.require(('read_saved_variant' in events) == (outcome == 'success'), 'validation ordering')
                verify.require(('call_existing_constructor' in events) == (outcome == 'success' and variant == 0), 'constructor reachability')
                verify.require(('close' in events) == (outcome == 'success' and variant != 0 and fd != -1), 'invalid address close')
                cases += 1
                if variant in (0, 1) and fd in (-1, 0):
                    examples.append({'outcome': outcome, 'variant': variant, 'fd': fd, 'result': result})
    controls = []
    for va, byte, args in [(0x5ab4150, 1, ('success', 0, 7)),
                           (0x5ab4177, 0, ('success', 1, 0)),
                           (0x5ab415b, 8, ('success', 1, -1))]:
        original = projected(*args, o)
        changed = projected(*args, operands(mutated(data, va, byte)))
        verify.require(original != changed, 'counterfactual survived')
        controls.append({'va': hex(va), 'byte': byte, 'inputs': list(args), 'original': original, 'mutated': changed})
    return {'native_operands': o, 'ordering_cases': cases, 'examples': examples, 'counterfactuals': controls,
            'limits': 'This models the selected address check after an explicitly supplied underlying connection outcome. It does not execute networking, emulate the captured code, establish cleanup helper effects or close success, or recover constructor internals. An enum producer is not recovered; nonzero variants are exhaustive raw-byte inputs rather than a claim that every value can occur.'}

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
    print('PASS: address validation ordering and three operand counterfactuals')
