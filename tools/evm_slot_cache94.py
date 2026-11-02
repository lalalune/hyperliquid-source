#!/usr/bin/env python3
"""Extract the node 94 EVM slot cache decision path from authenticated ELF bytes."""
import argparse
import hashlib
import json
from pathlib import Path
import struct

from elf_index import sections
from fde_extents import fde_extents

ROOT = Path(__file__).resolve().parents[1]
TARGET = ROOT / 'artifacts/node/94/hl-node'
DIGEST = '3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f'
FUNCTIONS = {
    0x32ab8f0: (929, '71590f56d21ca0d099d5ed98086d2f9de08ed7ca3f3dac709fa22471f22afc70'),
    0x32abca0: (929, '1916384d0d90f0bf8761a2cfc4690ba7aed6b89cac3eb14fc705ed810c67a454'),
    0x32ac050: (667, '3b353a6c33ac7d20174f7a6e6828cf85fab91f9589b0096db616d4127c1fb0f7'),
    0x37a0e50: (292, '475ae6d60ab14b309f73d942e08cdd49986b47a0fad44fae39eb35d2eb046cac'),
    0x379ab70: (378, '2be3e2b9f1e76e11113bd0259fddca55c5d7802c159ca0d968c3f7f57e7da0f0'),
    0x37a0d20: (295, 'ca7743eff582aed00e1a8bca4ae442ce50fa7c0bee8513173b45fe561cc31afb'),
}
# Instruction boundaries identified by bounded disassembly; no linear-sweep census.
BRANCHES = {
    0x32ab91f: 0x32abc40, 0x32ab965: 0x32aba43,
    0x32ab9a1: 0x32aba72, 0x32ab9dd: 0x32aba84,
    0x32aba30: 0x32aba84, 0x32aba65: 0x32abb7e,
    0x32abadc: 0x32abc5a, 0x32abaf2: 0x32abc7c,
    0x32abb8a: 0x32abc4d, 0x32abbbc: 0x32abbcc,
    0x32abc74: 0x32abae2,
    0x32ac0b9: 0x32ac0d4, 0x32ac100: 0x32ac2c4,
    0x32ac11a: 0x32ac2d1, 0x32ac145: 0x32ac24d,
    0x32ac152: 0x32ac2de, 0x32ac183: 0x32ac19d,
    0x37a0e55: 0x37a0f71, 0x37a0ee7: 0x37a0f40,
    0x37a0f27: 0x37a0f5e, 0x37a0f34: 0x37a0ee9, 0x37a0f4c: 0x37a0f64,
    0x379ac0f: 0x379ac60, 0x379ac4f: 0x379ac7e,
    0x379ac5c: 0x379ac11, 0x379ac6c: 0x379ac92,
    0x379ac97: 0x379acbc,
    0x37a0d25: 0x37a0e44, 0x37a0dba: 0x37a0e10,
    0x37a0dfd: 0x37a0e2e, 0x37a0e0a: 0x37a0dbc,
    0x37a0e1c: 0x37a0e34,
}
CALLS = {0x32ab917: 0x37a0d20, 0x32ab958: 0x379ab70,
         0x32ab9d2: 0x37d0fb0, 0x32aba26: 0x37d11d0}
WRAPPER_CALLS = {0x32ac095:0x32abca0, 0x32ac0f8:0x37a0d20,
                 0x32ac112:0x37a0e50}
# Address-dependent disp32 fields in the two bodies. These are not asserted
# to be ELF relocation records and are never credited as raw-equal bytes.
DISPLACEMENTS = (0x28, 0x69, 0xe3, 0x137, 0x2d8, 0x353, 0x359, 0x360, 0x366)


def checked_data(path=TARGET):
    data = path.read_bytes()
    if hashlib.sha256(data).hexdigest() != DIGEST:
        raise ValueError('target SHA-256 mismatch')
    return data


def read_va(data, va, size, sec):
    if va < 0 or size <= 0:
        raise ValueError('invalid range')
    matches = [s for s in sec if s['type'] != 8 and s['address'] <= va
               and va + size <= s['address'] + s['size']]
    if len(matches) != 1:
        raise ValueError('range is not uniquely file-backed')
    s = matches[0]
    off = s['offset'] + va - s['address']
    if off + size > len(data):
        raise ValueError('range exceeds file')
    return data[off:off + size]


def branch(data, va, sec):
    raw = read_va(data, va, 6, sec)
    if raw[0] in (0x74, 0x75, 0x79):
        size, cond, disp = 2, raw[0], struct.unpack_from('<b', raw, 1)[0]
    elif raw[0] == 0x0f and raw[1] in (0x84, 0x85, 0x89):
        size, cond, disp = 6, raw[1] - 0x10, struct.unpack_from('<i', raw, 2)[0]
    else:
        raise ValueError('unexpected branch opcode')
    return {'site': hex(va), 'bytes': raw[:size].hex(),
            'condition': {0x74:'equal', 0x75:'not_equal', 0x79:'not_sign'}[cond],
            'target': hex(va + size + disp), 'fallthrough': hex(va + size)}


def direct_call(data, va, sec):
    raw = read_va(data, va, 5, sec)
    if raw[0] != 0xe8:
        raise ValueError('unexpected call opcode')
    return {'site':hex(va), 'bytes':raw.hex(),
            'target':hex(va + 5 + struct.unpack_from('<i', raw, 1)[0])}



# Instruction-aligned slices support the claims in the accompanying branch table.
WINDOWS = {
 'account_and_slot_lookup': (0x32ab910, 0x32ab96b),
 'flag_and_account_fallback': (0x32ab99d, 0x32ab9e3),
 'slot_fallback_and_zero': (0x32ab9e3, 0x32aba43),
 'cached_slot_and_flag': (0x32aba43, 0x32aba72),
 'insert_controls': (0x32abac3, 0x32abb7e),
 'journal_tag_7': (0x32abb7e, 0x32abc14),
 'return_layout': (0x32abc14, 0x32abc40),
 'update_compare': (0x32ac0f1, 0x32ac14b),
 'journal_tag_6_and_update': (0x32ac14b, 0x32ac201),
 'update_result': (0x32ac201, 0x32ac2c4),
 'update_failures': (0x32ac2c4, 0x32ac2eb),
 'address_key_comparison': (0x37a0dca, 0x37a0dff),
 'slot_key_comparison': (0x379ac1c, 0x379ac51),
 'slot_find_comparison': (0x37a0ef4, 0x37a0f29),
}
LOCATIONS = (0x56dff80, 0x56dff98, 0x56dffc8, 0x56dffe0, 0x56dfff8)
SLOTS = (0x576e470, 0x5773270)


def metadata(data, sec):
    rel = [s for s in sec if s['name'] == '.rela.dyn' and s['type'] == 4]
    if len(rel) != 1 or rel[0]['size'] % 24:
        raise ValueError('invalid dynamic relocation section')
    wanted = set(LOCATIONS + SLOTS)
    found = {}
    r = rel[0]
    for off in range(r['offset'], r['offset'] + r['size'], 24):
        slot, info, addend = struct.unpack_from('<QQq', data, off)
        if slot in wanted:
            if info != 8 or slot in found:
                raise ValueError('invalid relative relocation')
            found[slot] = addend
    if set(found) != wanted:
        raise ValueError('missing relative relocation')
    records = []
    for addr in LOCATIONS:
        raw = read_va(data, addr, 24, sec)
        pointer, length, line, column = struct.unpack('<QQII', raw)
        if pointer != 0 or length > 256:
            raise ValueError('invalid location record')
        source = read_va(data, found[addr], length, sec)
        suffix = b'revm-19.2.0/src/journaled_state.rs'
        if not source.endswith(suffix):
            raise ValueError('unexpected location source')
        records.append({'va':hex(addr), 'bytes':raw.hex(), 'source_va':hex(found[addr]),
                        'source_length':length, 'source_sha256':hashlib.sha256(source).hexdigest(),
                        'source_suffix':suffix.decode('ascii'), 'line':line, 'column':column})
    return records, [{'slot':hex(x), 'type':8, 'addend':hex(found[x])} for x in SLOTS]


def generate(data):
    if hashlib.sha256(data).hexdigest() != DIGEST:
        raise ValueError('target SHA-256 mismatch')
    sec = sections(data)
    _, fdes, _ = fde_extents(data)
    found = {f['start']:f for f in fdes if f['start'] in FUNCTIONS}
    if set(found) != set(FUNCTIONS):
        raise ValueError('missing function FDE')
    bodies = {}
    functions = []
    for start, (size, digest) in sorted(FUNCTIONS.items()):
        if found[start]['end'] != start + size:
            raise ValueError('unexpected FDE extent')
        body = read_va(data, start, size, sec)
        if hashlib.sha256(body).hexdigest() != digest:
            raise ValueError('unexpected function bytes')
        bodies[start] = body
        functions.append({'start':hex(start), 'end_exclusive':hex(start+size),
                          'size':size, 'sha256':digest, 'bytes':body.hex()})
    branches = []
    for site, target in sorted(BRANCHES.items()):
        row = branch(data, site, sec)
        if int(row['target'], 16) != target:
            raise ValueError('unexpected branch target')
        branches.append(row)
        if 0x32ab8f0 <= site < 0x32abc91:
            twin = branch(data, site + 0x3b0, sec)
            if int(twin['target'],16) != target + 0x3b0 or twin['condition'] != row['condition']:
                raise ValueError('unexpected twin branch')
            branches.append(twin)
    calls = []
    for site, target in sorted(CALLS.items()):
        for offset in (0, 0x3b0):
            row = direct_call(data, site + offset, sec)
            if int(row['target'],16) != target:
                raise ValueError('unexpected call target')
            calls.append(row)
    for site, target in sorted(WRAPPER_CALLS.items()):
        row = direct_call(data, site, sec)
        if int(row['target'],16) != target:
            raise ValueError('unexpected wrapper call')
        calls.append(row)
    a, b = bodies[0x32ab8f0], bodies[0x32abca0]
    excluded = {i for off in DISPLACEMENTS for i in range(off, off + 4)}
    if any(a[i] != b[i] for i in range(len(a)) if i not in excluded):
        raise ValueError('twin bodies differ outside selected displacements')
    locations, slots = metadata(data, sec)
    windows = [{'name':name, 'start':hex(start), 'end_exclusive':hex(end),
                'bytes':read_va(data,start,end-start,sec).hex()}
               for name,(start,end) in sorted(WINDOWS.items())]
    return {'target_sha256': DIGEST, 'locations':locations, 'relocation_slots':slots,
            'windows':windows, 'coordinates':'ELF virtual addresses, FDE ends exclusive',
            'functions':functions, 'calls':calls, 'branches':branches,
            'twin_comparison': {'raw_equal_positions':sum(x == y for x,y in zip(a,b)),
              'compared_positions':len(a), 'excluded_displacement_offsets':[hex(x) for x in DISPLACEMENTS],
              'excluded_bytes':len(excluded), 'equal_outside_excluded':len(a)-len(excluded),
              'note':'Selected PC-relative displacement fields, not relocation-qualified equivalence.'}}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out', required=True, type=Path)
    args = parser.parse_args()
    result = generate(checked_data())
    args.out.mkdir(parents=True, exist_ok=True)
    (args.out / 'slot-cache.json').write_text(json.dumps(result, indent=2, sort_keys=True)+'\n', encoding='utf-8')


if __name__ == '__main__':
    main()
