#!/usr/bin/env python3
"""Authenticate and verify retained static greeting-reply bindings."""
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
DIGEST = '3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f'
ANCHORS = json.loads((PACKET / 'anchors.json').read_text())
FIXTURES = {'records': '74cb2f0edfea1dc9ca59f10e00d4a6f77658a7434f96572810625bebe5a6cada',
            'values': 'a9929e3ad9c81477177faa2356c27aaca30a28f4b7661b4944d35d7fc5ef00af',
            'maps': '3ce03689ca1ab37a552ea86420285cfdb02fc303ccb2878fc6712631a01b06db'}


def require(ok, why):
    if not ok:
        raise ValueError(why)


class Layout:
    def __init__(self, data):
        self.image = Image(data)
        section = next(s for s in self.image.secs if s['name'] == '.rela.dyn')
        slots = {r[0] for r in ANCHORS['relocations']}
        self.relocations = {}
        for off in range(section['offset'], section['offset'] + section['size'], 24):
            address = struct.unpack_from('<Q', data, off)[0]
            if address in slots:
                require(address not in self.relocations, 'duplicate relocation')
                self.relocations[address] = off


def inspect(data, layout=None):
    """A fixed-layout mutation seam, without authenticated-origin claims."""
    layout = layout or Layout(data)
    im = layout.image
    def read(address, count):
        off = im.offset(address)
        return data[off:off + count]
    for row in ANCHORS['facts']:
        expected = bytes.fromhex(row['bytes'])
        require(read(row['address'], len(expected)) == expected, f'instruction changed: {row["address"]:#x}')
    for name, row in ANCHORS['ranges'].items():
        require(im.fde(row['start']) == (row['start'], row['end']), 'FDE changed: ' + name)
        require(hashlib.sha256(read(row['start'], row['bytes'])).hexdigest() == row['sha256'], 'body changed: ' + name)
    for address, row in ANCHORS['tables'].items():
        raw = bytes.fromhex(row['bytes'])
        require(read(int(address, 16), len(raw)) == raw, 'dispatch table changed')
    for row in ANCHORS['relocations']:
        require(row[0] in layout.relocations, 'relocation missing')
        require(tuple(row) == struct.unpack_from('<QQq', data, layout.relocations[row[0]]), 'relocation changed')
    path = ANCHORS['compiler_path']
    at = path['file_offset']
    require(data[at:at + len(path['text'])] == path['text'].encode(), 'compiler source path changed')
    for entry in ANCHORS['imports'].values():
        at = entry['file_offset']
        require(data[at:at + len(entry['name']) + 1] == entry['name'].encode() + b'\0', 'import name changed')
    return {'origin': 'unqualified structural inspection', 'FDEs': len(ANCHORS['ranges']), 'instructions': len(ANCHORS['facts']), 'tables': len(ANCHORS['tables']), 'relocations': len(ANCHORS['relocations'])}


def fixture_bytes(name, data):
    require(hashlib.sha256(data).hexdigest() == FIXTURES[name], 'fixture identity changed: ' + name)


def analyze(data):
    require(len(data) == 91774280 and hashlib.sha256(data).hexdigest() == DIGEST, 'node94 identity changed')
    result = inspect(data)
    for name in FIXTURES:
        fixture_bytes(name, (PACKET / 'fixtures' / f'{name}.jsonl.gz').read_bytes())
    result.update({'origin': 'authenticated node94', 'target_sha256': DIGEST, 'domain': 'mode1 greeting wire/value projection; no native ABI, tree-layout, allocator or peer-acceptance equivalence', 'outer_variants': 6, 'hash_variants': 3, 'record_count': 3, 'record_array_bytes': 2048})
    return result


if __name__ == '__main__':
    result = analyze(TARGET.read_bytes())
    path = PACKET / 'records.json'
    if '--write' in sys.argv:
        path.write_text(json.dumps(result, indent=2) + '\n')
    else:
        require(result == json.loads(path.read_text()), 'stored result changed')
        print(json.dumps(result, sort_keys=True))
