#!/usr/bin/env python3
"""Reproduce static evidence and real byte-corruption controls, without execution."""
import argparse
import copy
import json
import tempfile
from pathlib import Path
from unittest.mock import patch

import corpus
import evidence as e


def rejects(operation, expected):
    try:
        operation()
    except ValueError as error:
        e.need(expected in str(error), 'unintended control rejection: ' + str(error))
        return str(error)
    raise ValueError('corruption accepted: ' + expected)


def equal(first, second):
    e.need(first == second, 'retained evidence differs')


def verify():
    first = e.collect(); second = e.collect()
    equal(first, second)
    equal(first, {p.name: p.read_bytes() for p in (e.HERE / 'observed').iterdir() if p.is_file()})
    fixtures = corpus.generate()
    for name, raw in fixtures.items():
        equal(raw, (e.HERE / name).read_bytes())
    freeze = json.loads((e.HERE / 'PRE-RUST-FREEZE.json').read_text())
    e.need(freeze['fixtureHashes'] == {k: e.sha(v) for k, v in fixtures.items()}, 'frozen fixture hashes differ')
    e.need(freeze['wrapperApisAbsent'] is True, 'pre-implementation freeze declaration differs')
    for name, digest in freeze['derivationSourceHashes'].items():
        e.need(e.sha((e.HERE / name).read_bytes()) == digest, 'frozen derivation source changed')
    retained = json.loads(first['records.json'])
    e.need(sum(r['bytes'] for r in retained['ranges'].values()) == 1374 and
           sum(r['instructions'] for r in retained['ranges'].values()) == 406,
           'native comparison denominator differs')
    original = e.admit(e.TARGET.read_bytes()); record = e.validate(original); controls = []
    def mutate(label, coordinate, address, replacement, reason):
        offset = original.offset(address, len(replacement)) if coordinate == 'va' else address
        changed = bytearray(original.data)
        before = bytes(changed[offset:offset + len(replacement)])
        e.need(before != replacement, 'ineffective mutation')
        changed[offset:offset + len(replacement)] = replacement
        image = copy.copy(original); image.data = bytes(changed)
        rejection = rejects(lambda: e.validate(image), reason)
        item = {'control': label, 'coordinate': coordinate, 'address': hex(address),
                'before': before.hex(), 'after': replacement.hex(), 'rejected': rejection}
        controls.append(item)
        return image, item
    for label, va, byte, reason in [
        ('charge-offset', 0x466bc19, 0x18, 'complete body changed'),
        ('limit-store-order-branch', 0x466bc2f, 0x72, 'complete body changed'),
        ('reader-output-offset', 0x466d87c, 8, 'complete body changed'),
        ('reader-cursor-update-offset', 0x466d86f, 0x10, 'complete body changed'),
        ('wrapper-slow-call-displacement', 0x466bcb2, 0x83, 'complete body changed'),
        ('request-first-status', 0x438b650, 0x13, 'complete body changed'),
        ('request-second-status', 0x438b668, 0x13, 'complete body changed'),
        ('request-output-field', 0x438b67b, 0x18, 'complete body changed'),
        ('error-builder-code-offset', 0x466dac9, 3, 'complete body changed'),
        ('request-literal', 0x204640, ord('X'), 'request type literal changed'),
        ('request-range-record', 0x20941c, 3, 'request range record changed')]:
        mutate(label, 'va', va, bytes([byte]), reason)
    for table in e.TABLES:
        mutate('dispatch-' + hex(table), 'va', table, bytes([original.at(table, 1)[0] ^ 1]), 'dispatch table changed')
    for binding in record['relocations']:
        for extra, suffix in ((12, 'symbol-index'), (16, 'addend')):
            offset = binding['fileOffset'] + extra
            mutate('relocation-' + binding['slot'] + '-' + suffix, 'file', offset,
                   bytes([original.data[offset] ^ 1]), 'RELATIVE binding changed')
    for label, info in record['ranges'].items():
        va = int(info['fde']['va'], 16) + 12
        mutate('FDE-' + label, 'va', va, bytes([original.at(va, 1)[0] ^ 1]), 'FDE extent changed')
    # These independent scalar counterfactuals read altered captured operands.
    # They expose changed value/state expectations; no instruction is evaluated.
    for label, va, byte, width, mode, limit, charge, raw in [
        ('charge-amount', 0x466bc27, 5, 32, 1, 4, 0, b'\x01'),
        ('fast-threshold', 0x466bd40, 9, 64, 0, 0, 0, b'\xfe' + bytes(8)),
        ('fast-error-code', 0x466bdc9, 3, 64, 0, 0, 0, b'\xfe' + bytes(8)),
        ('mode-enable-value', 0x466bc13, 0, 32, 1, 0, 0, b'\x01'),
        ('overflow-cutoff', 0x466bd1d, 0xf6, 64, 1, corpus.MAX, corpus.MAX - 8, b'\x01')]:
        image, item = mutate(label, 'va', va, bytes([byte]), 'complete body changed')
        before = corpus.integer(width, mode, limit, charge, raw, e.parameters(original))
        after = corpus.integer(width, mode, limit, charge, raw, e.parameters(image))
        e.need(before != after, 'scalar counterfactual did not change expectation')
        def readable(value):
            result, counter, suffix = value
            return {'activeResult': result, 'charge': counter, 'suffixHex': suffix.hex()}
        item['scalarCounterfactual'] = {'before': readable(before), 'after': readable(after)}
    text = first['u32-wrapper.gnu.txt'].decode()
    lines = text.splitlines()
    index = next(i for i, line in enumerate(lines) if line.lstrip().startswith('466bc10:'))
    for label, altered in [('missing-native-row', '\n'.join(lines[:index] + lines[index + 1:])),
                            ('wrong-native-byte', text.replace('466bc10:\t53', '466bc10:\t52', 1))]:
        e.need(altered != text, 'native mutation ineffective')
        controls.append({'control': label, 'rejected': rejects(
            lambda: e.rows(altered, original, 0x466bc10, 0x466bd03), 'native ')})
    altered = dict(first); altered.pop('u64-wrapper.llvm.txt')
    controls.append({'control': 'missing-independent-export', 'rejected': rejects(lambda: equal(first, altered), 'retained evidence differs')})
    with tempfile.TemporaryDirectory(prefix='wrapper-controls-') as temp:
        temp = Path(temp); bad = temp / 'bad'
        for label, data in [('truncated', original.data[:-1]), ('extended', original.data + b'\0'),
                            ('wrong-byte', bytes([original.data[0] ^ 1]) + original.data[1:])]:
            bad.write_bytes(data)
            with patch.object(e, 'native', side_effect=RuntimeError('native tool reached before admission')):
                reason = rejects(lambda: e.collect(bad), 'wrong complete node94 identity')
            controls.append({'control': label + '-before-native', 'rejected': reason})
        existing = temp / 'existing'; existing.mkdir(); (existing / 'keep').write_bytes(b'keep')
        controls.append({'control': 'preserve-output', 'rejected': rejects(lambda: e.write_new(existing, first), 'preserve existing output')})
        e.need(list(existing.iterdir()) == [existing / 'keep'] and (existing / 'keep').read_bytes() == b'keep', 'existing output changed')
    return {'status': 'PASS', 'freshRegenerationsEqual': 2, 'files': len(first),
            'cases': len(fixtures['inputs.tsv'].splitlines()), 'controls': controls,
            'capturedExecution': False, 'instructionEvaluation': False}


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--gnu', default=e.GNU)
    parser.add_argument('--llvm', default=e.LLVM)
    parser.add_argument('--readelf', default=e.READELF)
    args = parser.parse_args()
    e.GNU, e.LLVM, e.READELF = args.gnu, args.llvm, args.readelf
    print(json.dumps(verify(), indent=2))
