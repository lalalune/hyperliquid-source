#!/usr/bin/env python3
"""Authenticate retained native evidence for initial reply routing; never execute it."""
import hashlib
import json
from pathlib import Path
import struct
import sys

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / 'tools'))
from tcp_frame_read_static import Image

PACKET = Path(__file__).resolve().parent
TARGET = ROOT / 'artifacts/node/94/hl-node'
ANCHORS = json.loads((PACKET / 'anchors.json').read_text())
DIGEST = '3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f'


def require(ok, why):
    if not ok:
        raise ValueError(why)


def inspect(data, layout=None):
    """Fixed-layout corruption seam; this does not authenticate changed inputs."""
    im = layout or Image(data)
    def read(va, count):
        off = im.offset(va)
        return data[off:off + count]
    for fact in ANCHORS['facts']:
        raw = bytes.fromhex(fact['bytes'])
        require(read(fact['address'], len(raw)) == raw, 'instruction changed')
    for name, row in ANCHORS['ranges'].items():
        require(im.fde(row['start']) == (row['start'], row['end']), 'FDE changed: ' + name)
        require(hashlib.sha256(read(row['start'], row['end'] - row['start'])).hexdigest() == row['sha256'], 'body changed: ' + name)
    for name, table in ANCHORS['tables'].items():
        raw = bytes.fromhex(table['bytes']); base = int(table['address'], 16)
        require(read(base, len(raw)) == raw, 'table changed: ' + name)
        for row in table['entries']:
            target = base + struct.unpack_from('<i', raw, row['index'] * 4)[0]
            require(target == int(row['target'], 16), 'table destination changed')
    for row in ANCHORS['strings']:
        require(read(int(row['address'], 16), row['length']) == row['text'].encode(), 'error text changed')
    for row in ANCHORS['relocations']:
        off = row['file_offset']; raw = bytes.fromhex(row['bytes'])
        require(data[off:off + len(raw)] == raw, 'relocation changed')
        expected = tuple(int(row[k], 16) for k in ['r_offset', 'r_info', 'r_addend'])
        require(struct.unpack('<QQq', raw) == expected, 'relocation tuple changed')
    for row in ANCHORS['imports'].values():
        raw = bytes.fromhex(row['bytes']); off = row['file_offset']
        require(data[off:off + len(raw)] == raw, 'import changed')
    return {'origin': 'unqualified structural inspection', 'FDEs': len(ANCHORS['ranges']),
            'context_bytes': sum(r['end'] - r['start'] for r in ANCHORS['ranges'].values()),
            'instructions': len(ANCHORS['facts']), 'table_regions': len(ANCHORS['tables']),
            'complete_routing_tables': 2, 'initial_state_table_entries': 1,
            'relocations': len(ANCHORS['relocations']), 'error_strings': len(ANCHORS['strings'])}


def analyze(data):
    require(len(data) == 91774280 and hashlib.sha256(data).hexdigest() == DIGEST, 'node94 identity changed')
    result = inspect(data)
    result.update({'origin': 'authenticated node94', 'target_sha256': DIGEST,
                   'scope': ANCHORS['scope'], 'flag': 'first transmitted request byte',
                   'data_test': 'bit zero set', 'empty_success_test': 'whole byte zero'})
    return result


if __name__ == '__main__':
    result = analyze(TARGET.read_bytes())
    path = PACKET / 'records.json'
    if '--write' in sys.argv:
        path.write_text(json.dumps(result, indent=2) + '\n')
    else:
        require(result == json.loads(path.read_text()), 'stored result changed')
        print(json.dumps(result, sort_keys=True))
