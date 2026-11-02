#!/usr/bin/env python3
"""Verify bounded read-exact/write-all instruction facts; never execute the node."""
import hashlib
import json
from pathlib import Path
import struct
import sys

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / 'tools'))
from elf_index import sections
from fde_extents import eh_frame_records

DIGEST = '3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f'
TARGET = ROOT / 'artifacts/node/94/hl-node'
PACKET = Path(__file__).resolve().parent
RANGES = {'read_exact': (0x2034eb0, 0x203516e), 'write_all': (0x2036460, 0x20367c3)}
# Each row is an observed instruction, not an inferred original source name.
FACTS = [
    ('read_remaining', 0x2034f83, '4929d5'),
    ('read_complete', 0x2034f8c, '7476', 0x2035004),
    ('read_poll', 0x2034f9b, 'e8d07ff402', 0x4f7cf70),
    ('read_pending', 0x2034fa2, '7571', 0x2035015),
    ('read_error', 0x2034fa7, '7539', 0x2034fe2),
    ('read_progress_loop', 0x2034fc6, '75b8', 0x2034f80),
    ('read_eof_literal', 0x2034fc8, '488d3505bd79fe', 0x7d0cd4),
    ('read_eof_length', 0x2034fcf, 'ba09000000'),
    ('read_eof_kind', 0x2034fd4, 'bf25000000'),
    ('read_eof_constructor_slot', 0x2034fd9, 'ff15819e7303', 0x576ee60),
    ('write_empty_check', 0x2036580, '4885c9'),
    ('write_complete', 0x2036583, '7465', 0x20365ea),
    ('write_zero_error_value', 0x203656e, '49bc0300000017000000'),
    ('write_poll', 0x2036596, 'e8056cf402', 0x4f7d1a0),
    ('write_pending', 0x203659f, '745b', 0x20365fc),
    ('write_error', 0x20365a3, '7563', 0x2036608),
    ('write_advance_remaining', 0x20365c9, '4829d1'),
    ('write_advance_pointer', 0x20365d2, '4801d0'),
    ('write_progress_check', 0x20365e3, '4885d2'),
    ('write_progress_loop', 0x20365e6, '7598', 0x2036580),
    ('write_zero_error_path', 0x20365e8, 'eb21', 0x203660b),
]


def require(condition, reason):
    if not condition:
        raise ValueError(reason)


def inspect(data):
    """Structural seam; does not authenticate callers' counterfactual bytes."""
    sec = sections(data)
    _, frames = eh_frame_records(data, sec)

    def read(address, length):
        matches = [s for s in sec if s['type'] != 8 and s['address'] <= address
                   and address + length <= s['address'] + s['size']]
        require(len(matches) == 1, f'ambiguous file mapping at {address:#x}')
        s = matches[0]
        start = s['offset'] + address - s['address']
        return data[start:start + length]

    functions = {}
    for name, (start, end) in RANGES.items():
        matched = [f for f in frames if f['start'] < end and f['end'] > start]
        require(len(matched) == 1 and (matched[0]['start'], matched[0]['end']) == (start, end),
                f'changed {name} FDE extent')
        functions[name] = {'start': hex(start), 'end': hex(end), 'bytes': end - start,
                           'body_sha256': hashlib.sha256(read(start, end - start)).hexdigest()}
    facts = []
    for row in FACTS:
        name, address, raw = row[:3]
        body = read(address, len(bytes.fromhex(raw)))
        require(body.hex() == raw, f'changed instruction: {name}')
        item = {'name': name, 'address': hex(address), 'bytes': raw}
        if len(row) == 4:
            if len(body) == 2:
                destination = address + 2 + struct.unpack('<b', body[1:])[0]
            else:
                destination = address + len(body) + struct.unpack('<i', body[-4:])[0]
            require(destination == row[3], f'changed target: {name}')
            item['reference_target'] = hex(destination)
        facts.append(item)
    require(read(0x7d0cd4, 9) == b'early eof', 'changed EOF text')
    rela = next(s for s in sec if s['name'] == '.rela.dyn')
    entries = [struct.unpack_from('<QQq', data, i)
               for i in range(rela['offset'], rela['offset'] + rela['size'], 24)]
    matches = [r for r in entries if r[0] == 0x576ee60]
    require(matches == [(0x576ee60, 8, 0x4edac60)], 'changed EOF constructor relocation')
    return {'origin': 'unqualified structural inspection', 'functions': functions,
            'instructions': facts, 'eof_literal': 'early eof',
            'eof_constructor': {'slot': '0x576ee60', 'kind': 8, 'symbol': 0,
                                'addend': '0x4edac60'},
            'limits': ['Static selected branch/data facts, not complete runtime behavior.',
                       'poll_read/poll_write callees, scheduling, timeout and error formatting remain open.',
                       'Names describe the observed loops and exact-version source correspondence; no debug symbols recovered.']}


def analyze(data):
    require(len(data) == 91774280 and hashlib.sha256(data).hexdigest() == DIGEST,
            'node #94 identity differs')
    result = inspect(data)
    result['origin'] = 'authenticated node #94'
    result['target_sha256'] = DIGEST
    return result


def main():
    actual = analyze(TARGET.read_bytes())
    if '--write' in sys.argv:
        (PACKET / 'records.json').write_text(json.dumps(actual, indent=2) + '\n')
    else:
        expected = json.loads((PACKET / 'records.json').read_text())
        require(actual == expected, 'retained instruction evidence differs')
        print('Verified node #94 exact-I/O loops: 2 full FDEs, 21 selected instructions.')


if __name__ == '__main__':
    main()
