#!/usr/bin/env python3
"""Authenticate the node115 vault query future; static reads only."""
import hashlib
import json
import struct
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[3]
PACKET = Path(__file__).resolve().parent
TARGET = ROOT / 'artifacts/node/115/hl-node'
DIGEST = 'a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301'
SIZE = 105896032
sys.path.insert(0, str(ROOT / 'tools'))
from elf_index import sections
from fde_extents import eh_frame_records

BODIES = {
    'poll': (0x297f560, 0x297f70d),
}
EXPECTED_HASHES = {
    'poll': '1d8745567af23f1e9f0375824bbf1c22f4038c7e87df885579fb17986843703c',
}
TABLE_VA = 0x60028c
TABLE_TARGETS = [0x297f588, 0x297f698, 0x297f68b, 0x297f5d4,
                 0x297f728, 0x297f838, 0x297f82b, 0x297f774]
RELATIVE = {0x6443108: 0x297f560, 0x6442ad8: 0x2979c10}
LITERALS = {0x60176d: b'small_vault_summaries_get'}
INSTRUCTIONS = {
    0x29696eb: bytes.fromhex('488d157b80c9fd'),
    0x29696f7: bytes.fromhex('48c744244819000000'),
    0x296973e: bytes.fromhex('e83d1f0500'),
    0x297f574: bytes.fromhex('0fb64629'),
    0x297f5ec: bytes.fromhex('48b80000000000000080'),
    0x297f5f6: bytes.fromhex('498906'),
    0x297f5f9: bytes.fromhex('b003'),
    0x297f662: bytes.fromhex('b001'),
    0x297f664: bytes.fromhex('884329'),
    0x297f651: bytes.fromhex('488b442410'),
    0x297f656: bytes.fromhex('49894610'),
    0x297f65a: bytes.fromhex('0f280424'),
    0x297f65e: bytes.fromhex('410f1106'),
    0x297f66e: bytes.fromhex('5b415c415d415e415f5d'),
}
DIRECT_CALLS = {0x296973e: 0x29bb680}


def require(ok, message):
    if not ok:
        raise ValueError(message)


def sha(data):
    return hashlib.sha256(data).hexdigest()


class Image:
    def __init__(self, data):
        self.data = data
        self.sections = sections(data)
        require(len({s['name'] for s in self.sections}) == len(self.sections),
                'duplicate ELF sections')

    def off(self, va, size=1):
        matches = [s for s in self.sections if s['type'] != 8 and
                   s['address'] <= va and va + size <= s['address'] + s['size']]
        require(len(matches) == 1, f'ambiguous or unbacked VA {hex(va)}')
        return matches[0]['offset'] + va - matches[0]['address']

    def get(self, va, size):
        off = self.off(va, size)
        return self.data[off:off + size]

    def relocs(self):
        sec, = [s for s in self.sections if s['name'] == '.rela.dyn']
        require(sec['size'] % 24 == 0, 'partial RELA section')
        result = {}
        for off in range(sec['offset'], sec['offset'] + sec['size'], 24):
            slot, info, addend = struct.unpack_from('<QQq', self.data, off)
            require(slot not in result, 'duplicate relocation')
            result[slot] = (info, addend, off)
        return result


def observe(data, authenticate=True, body_hashes=True):
    if authenticate:
        require(len(data) == SIZE, 'target size mismatch')
        require(sha(data) == DIGEST, 'target digest mismatch')
    image = Image(data)
    _, fdes = eh_frame_records(data, image.sections)
    bodies = []
    for name, (start, end) in BODIES.items():
        found = [f for f in fdes if f['start'] == start]
        require(len(found) == 1 and found[0]['end'] == end, f'FDE {name}')
        digest = sha(image.get(start, end - start))
        if body_hashes:
            require(digest == EXPECTED_HASHES[name], f'body hash {name}')
        bodies.append({'name': name, 'start': hex(start), 'end': hex(end),
                       'bytes': end - start, 'sha256': digest,
                       'fde': found[0]})
    relocs = image.relocs()
    bindings = []
    for slot, target in RELATIVE.items():
        require(relocs.get(slot, ())[:2] == (8, target), f'RELATIVE {hex(slot)}')
        bindings.append({'slot': hex(slot), 'target': hex(target),
                         'relocation_file_offset': hex(relocs[slot][2])})
    table = []
    for index, target in enumerate(TABLE_TARGETS):
        displacement = struct.unpack('<i', image.get(TABLE_VA + index * 4, 4))[0]
        actual = TABLE_VA + displacement
        require(actual == target, f'jump table state {index}: {hex(actual)}')
        table.append({'state': index, 'displacement': displacement,
                      'target': hex(actual)})
    for va, expected in LITERALS.items():
        require(image.get(va, len(expected)) == expected, f'label at {hex(va)}')
    for va, expected in INSTRUCTIONS.items():
        require(image.get(va, len(expected)) == expected, f'instruction at {hex(va)}')
    for site, target in DIRECT_CALLS.items():
        instruction = image.get(site, 5)
        require(instruction[0] == 0xe8 and
                site + 5 + struct.unpack_from('<i', instruction, 1)[0] == target,
                f'direct call target at {hex(site)}')

    # The caller evidence is separately authenticated by the refresh-trigger packet.
    parent = ROOT / 'research/work-items/RE-001-node115-vault-summary-refresh-trigger/request.gnu.txt'
    caller = parent.read_text()
    for address in ('29696eb', '296973e', '2969743', '2969748', '296974c', '2969751'):
        require(address in caller, f'parent caller anchor {address}')
    caller_copy = {
        0x2969743: bytes.fromhex('488b442470'),
        0x2969748: bytes.fromhex('49894610'),
        0x296974c: bytes.fromhex('0f10442460'),
        0x2969751: bytes.fromhex('410f1106'),
    }
    for va, expected in caller_copy.items():
        require(image.get(va, len(expected)) == expected, f'outer copy at {hex(va)}')
    return {'target_sha256': sha(data), 'bodies': bodies,
            'relative_bindings': bindings, 'state_table': table,
            'result_bytes': 24, 'target_executed_or_emulated': False}


def controls(data):
    image = Image(data)
    mutations = [
        (image.off(0x297f574), 'poll state load'),
        (image.off(TABLE_VA + 3 * 4), 'pending-state table entry'),
        (image.relocs()[0x6443108][2] + 16, 'poll-slot relocation'),
        (image.off(0x60176d), 'query label'),
        (image.off(0x297f5ec), 'pending sentinel'),
        (image.off(0x296974c), 'outer 24-byte copy'),
    ]
    results = []
    for offset, role in mutations:
        altered = bytearray(data)
        altered[offset] ^= 1
        try:
            observe(bytes(altered), authenticate=False, body_hashes=False)
        except (ValueError, AssertionError):
            results.append({'role': role, 'rejected': True})
        else:
            raise ValueError('corruption accepted: ' + role)
    return results


def main():
    data = TARGET.read_bytes()
    result = observe(data)
    (PACKET / 'state-table.json').write_text(json.dumps(result['state_table'], indent=2) + '\n')
    if '--controls' in sys.argv:
        result['controls'] = controls(data)
        require(len(result['controls']) == 6, 'control count')
        (PACKET / 'controls.json').write_text(json.dumps(result['controls'], indent=2) + '\n')
    (PACKET / 'verification.json').write_text(json.dumps(result, indent=2) + '\n')
    print('PASS: target digest, FDEs, vtables, state table, caller envelope and controls')


if __name__ == '__main__':
    main()
