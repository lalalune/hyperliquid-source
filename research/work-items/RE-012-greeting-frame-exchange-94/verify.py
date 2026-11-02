#!/usr/bin/env python3
"""Verify the selected greeting request and reply-frame bindings, without execution."""
import hashlib
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / 'tools'))
from tcp_frame_read_static import Image
import tcp_frame_write_static

PACKET = Path(__file__).resolve().parent
TARGET = ROOT / 'artifacts/node/94/hl-node'
DIGEST = '3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f'
ANCHORS = json.loads((PACKET / 'anchors.json').read_text())


def require(condition, message):
    if not condition:
        raise ValueError(message)


def inspect(data):
    """Below-digest counterfactual checks do not authenticate an artifact."""
    image = Image(data)
    for name, row in ANCHORS['ranges'].items():
        require(image.fde(row['start']) == (row['start'], row['end']), 'FDE extent changed: ' + name)
    for row in ANCHORS['facts']:
        address = int(row['address'], 16)
        expected = bytes.fromhex(row['bytes'])
        require(image.read(address, len(expected)) == expected, 'instruction changed: ' + row['address'])
    return {'origin': 'unqualified structural inspection', 'facts_checked': len(ANCHORS['facts'])}


def analyze(data):
    require(len(data) == 91774280 and hashlib.sha256(data).hexdigest() == DIGEST, 'node94 identity changed')
    result = inspect(data)
    callers = tcp_frame_write_static.analyse(data)['callers']
    writer = next(row for row in callers if row['call'] == '0x203812e')
    require(writer['arg0'] == 0 and writer['arg8_seconds'] == 60 and writer['chunk_timeout_selected'] == 20,
            'greeting writer timeout binding changed')
    result.update({'origin': 'authenticated node94', 'target_sha256': DIGEST,
                   'writer': writer, 'payload': ['original byte +0x201', 'original byte +0x202', 0],
                   'reply_limit': {'first_zero': 1000, 'first_nonzero': 3000000000},
                   'header_timeout_flag': 'original byte +0x203, independently copied to reader argument +8',
                   'boundary': 'send complete request, then receive a frame; semantic reply decoder follows separately',
                   'limits': ['Selected fresh post-connect caller, not a recovered connection or complete greeting protocol.',
                              'Native bytes and source correspondence, not target execution or a complete ABI proof.']})
    return result


if __name__ == '__main__':
    result = analyze(TARGET.read_bytes())
    path = PACKET / 'records.json'
    if '--write' in sys.argv:
        path.write_text(json.dumps(result, indent=2) + '\n')
    else:
        require(result == json.loads(path.read_text()), 'stored greeting record changed')
        print('Verified greeting frame boundary: 5 FDE extents, 63 instructions and selected writer timeout.')
