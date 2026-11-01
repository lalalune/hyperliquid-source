#!/usr/bin/env python3
"""Piecewise value/state equations derived in PROOF.md, not an ISA evaluator."""
import argparse
import datetime
import json
from pathlib import Path

import evidence as e

MAX = (1 << 64) - 1
SOURCE = e.ROOT / 'src/bincode-varint/src/lib.rs'


def integer(width, mode, limit, charge, raw, p):
    """Return active value/error, new charge and suffix; input bytes are data."""
    fields = p[width]
    if mode == fields['mode']:
        if charge > fields['overflow_max']:
            return ('limit', '-'), charge, raw
        charge += fields['charge']
        if charge > limit:
            return ('limit', '-'), charge, raw
    n = len(raw)
    if not n:
        return ('end', '1'), charge, raw
    tag = raw[0]
    fast = n > fields['threshold']
    if tag < 251:
        return ('ok', str(tag)), charge, raw[1:]
    rejected = {253: 3, 254: 4, 255: 12} if width == 32 else {254: 4, 255: 12}
    if tag in rejected:
        expected = fields['fast_expected'] if fast else fields['reader_expected']
        return ('type', f'{expected}:{rejected[tag]}'), charge, raw if fast else raw[1:]
    payload = {251: 2, 252: 4, 253: 8}[tag]
    if n < payload + 1:
        return ('end', str(payload + 1 - n)), charge, raw[1:]
    number = int.from_bytes(raw[1:1 + payload], 'little')
    return ('ok', str(number)), charge, raw[1 + payload:]


def relation(operation, mode, limit, charge, raw, p):
    if operation in ('32', '64'):
        return integer(int(operation), mode, limit, charge, raw, p)
    e.need(operation == 'request', 'unknown corpus operation')
    header, charge, rest = integer(32, mode, limit, charge, raw, p)
    if header[0] != 'ok':
        return header, charge, rest
    tag = int(header[1])
    if tag in (1, 2):
        return ('unit', str(tag)), charge, rest
    if tag != 0:
        return ('badtag', str(tag)), charge, rest
    first, charge, rest = integer(64, mode, limit, charge, rest, p)
    if first[0] != 'ok':
        return first, charge, rest
    second, charge, rest = integer(64, mode, limit, charge, rest, p)
    if second[0] != 'ok':
        return second, charge, rest
    return ('pair', first[1] + ':' + second[1]), charge, rest


def stimuli():
    cases = set()
    def add(op, mode, limit, charge, raw):
        cases.add((str(op), mode, limit, charge, raw))
    for width in (32, 64):
        w = width // 8
        for tag in range(256):
            for n in (1, w, w + 1, 10):
                add(width, 0, 0, 42, bytes([tag]) + bytes(range(1, n)))
        for tag in range(251, 256):
            for n in range(1, 12):
                for tail in (bytes(n - 1), b'\xff' * (n - 1), bytes(range(1, n))):
                    for mode in (0, 1):
                        add(width, mode, MAX, 0, bytes([tag]) + tail)
        representatives = [b'', b'\x01', b'\xfb\x34', b'\xfb\x34\x12',
                           b'\xfc\x78\x56\x34\x12', b'\xfe', b'\xfe' + bytes(w),
                           b'\xff' + bytes(w - 1), b'\xfd' + bytes(range(1, 9))]
        for charge in (0, 1, MAX - w - 1, MAX - w, MAX - w + 1, MAX):
            for limit in (0, w - 1, w, w + 1, MAX - 1, MAX):
                for raw in representatives:
                    add(width, 1, limit, charge, raw)
        for mode in (0, 2, (1 << 32) - 1):
            for raw in representatives:
                add(width, mode, 0, MAX, raw)
    request_inputs = {b'', b'\x00', b'\x00\x01', b'\x00\x01\x02',
                      b'\x00\xfb\x34\x12\xfc\x78\x56\x34\x12',
                      b'\x00\xfd' + bytes(range(1, 9)) + b'\x02',
                      b'\xfc\x00\x00\x00\x00\x01\x02'}
    for n in range(13):
        for prefix in (b'\x00\xfe', b'\x00\x01\xfe', b'\xfe', b'\xff',
                       b'\x01', b'\x02', b'\x03', b'\xfb', b'\xfc'):
            request_inputs.add(prefix + bytes(range(n)))
    for raw in request_inputs:
        add('request', 0, 0, 42, raw)
        for charge, limit in [(0, n) for n in (0, 3, 4, 11, 12, 19, 20, MAX)] + [(MAX - 4, MAX), (MAX, MAX)]:
            add('request', 1, limit, charge, raw)
    return sorted(cases)


def generate():
    image = e.admit(e.TARGET.read_bytes()); e.validate(image); params = e.parameters(image)
    inputs = []; expected = []
    for i, (operation, mode, limit, charge, raw) in enumerate(stimuli()):
        result, updated, suffix = relation(operation, mode, limit, charge, raw, params)
        inputs.append(f'{i}\t{operation}\t{mode}\t{limit}\t{charge}\t{raw.hex() or "-"}\n')
        expected.append(f'{i}\t{result[0]}\t{result[1]}\t{len(raw) - len(suffix)}\t{updated}\t{suffix.hex() or "-"}\n')
    return {'inputs.tsv': ''.join(inputs).encode(), 'expected.tsv': ''.join(expected).encode()}


def freeze():
    e.need(not (e.HERE / 'PRE-RUST-FREEZE.json').exists(), 'freeze already exists')
    source = SOURCE.read_bytes()
    e.need(b'pub struct SliceDecoder' not in source and b'pub enum SliceError' not in source,
           'wrapper source exists before expectation freeze')
    files = generate()
    for name, data in files.items():
        e.need(not (e.HERE / name).exists(), 'preserve existing fixture')
        (e.HERE / name).write_bytes(data)
    record = {'utc': datetime.datetime.now(datetime.timezone.utc).isoformat(),
              'targetSha256': e.DIGEST, 'priorComponentSourceSha256': e.sha(source),
              'wrapperApisAbsent': True, 'fixtureHashes': {k: e.sha(v) for k, v in files.items()},
              'cases': len(files['inputs.tsv'].splitlines()),
              'derivationSourceHashes': {name: e.sha((e.HERE / name).read_bytes()) for name in ('evidence.py', 'corpus.py')},
              'scope': 'Active fields, charge and suffix. Piecewise equations, not captured execution or instruction emulation.'}
    (e.HERE / 'PRE-RUST-FREEZE.json').write_bytes(e.encoded(record))
    return record


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--freeze', action='store_true', required=True)
    parser.parse_args()
    print(json.dumps(freeze(), indent=2))
