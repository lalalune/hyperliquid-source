#!/usr/bin/env python3
"""Check selected node 115 ELF records and recompute relative call targets."""
import hashlib
import json
from pathlib import Path
import struct
import sys

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
sys.path.insert(0, str(ROOT / 'tools'))
from elf_index import sections
from fde_extents import eh_frame_records

def require(ok, message):
    if not ok:
        raise ValueError(message)

def verify():
    packet = json.loads((HERE / 'records.json').read_text())
    data = (ROOT / 'artifacts/node/115/hl-node').read_bytes()
    require(len(data) == 105896032 and hashlib.sha256(data).hexdigest() == packet['sha256'], 'target identity')
    secs = sections(data)
    frames = {(f['start'], f['end']) for f in eh_frame_records(data, secs)[1]}
    def read(addr, size):
        hits = [s for s in secs if s['type'] != 8 and s['address'] <= addr and addr + size <= s['address'] + s['size']]
        require(len(hits) == 1, 'ambiguous or missing section')
        off = hits[0]['offset'] + addr - hits[0]['address']
        return data[off:off + size]
    for f in packet['functions']:
        start, end = int(f['start'],16), int(f['end'],16)
        require((start, end) in frames, 'wrong FDE')
        require(hashlib.sha256(read(start, end-start)).hexdigest() == f['sha256'], 'changed body')
        for va, raw, operation in f['instructions']:
            at, want = int(va,16), bytes.fromhex(raw)
            require(start <= at < at + len(want) <= end and read(at,len(want)) == want, f'{va} {operation}')
    reloc_section = next(s for s in secs if s['name'] == '.rela.dyn')
    table = {slot: (typ, target) for slot,typ,target in struct.iter_unpack('<QQq', read(reloc_section['address'],reloc_section['size']))}
    def check_call(at, six_bytes, expected):
        require(six_bytes[:2] == b'\xff\x15', 'unexpected call form')
        slot = at + 6 + int.from_bytes(six_bytes[2:], 'little', signed=True)
        require(table.get(slot) == (8, expected), 'wrong call destination')
    for at, expected in packet['calls']:
        at, expected = int(at,16), int(expected,16)
        instruction = read(at,6)
        check_call(at, instruction, expected)
        # Preserve the call opcode but shift its slot by one byte.
        changed = instruction[:2] + (int.from_bytes(instruction[2:], 'little', signed=True) + 1).to_bytes(4, 'little', signed=True)
        try:
            check_call(at, changed, expected)
        except ValueError:
            pass
        else:
            raise AssertionError('shifted call unexpectedly accepted')
    for addr, raw in packet['literals'].items():
        want = bytes.fromhex(raw)
        require(read(int(addr,16),len(want)) == want, f'wrong literal at {addr}')
    from build_mode_arg_selection import decode_packed_format

    def lea_target(at):
        instruction = read(at, 7)
        require(instruction[:3] in (b'\x48\x8d\x35', b'\x48\x8d\x05', b'\x48\x8d\x3d'), 'format reference')
        return at + 7 + int.from_bytes(instruction[3:], 'little', signed=True)

    templates = {
        0x38c4154: '{0}/data/{1}',
        0x38c4192: '{0}/{1}',
        0x38c43f1: '/tmp/evm_state_checkpoints_{0}_{1}_{2}.tar',
        0x38c4478: '{0}/data/daily_evm_checkpoints/{1}/{2}_{3}.tar',
        0x38c4ebc: 'periodic_abci_state_status_base_dir does not exist: {0}',
    }
    for site, expected in templates.items():
        require(decode_packed_format(data, secs, lea_target(site)) == expected, f'format {site:#x}')
    descriptor = lea_target(0x38c413c)
    kind, address = table[descriptor]
    size = int.from_bytes(read(descriptor + 8, 8), 'little')
    require(kind == 8 and read(address, size) == b'periodic_abci_state_statuses', 'status descriptor')
    require(table[0x64e0b68] == (8, 0x150ce90) and read(lea_target(0x150ceb2), 6) == b'%Y%m%d', 'date format')
    require(table[0x64e0a98] == (8, 0x1689420), 'unsigned height and temporary ID display')

    for site, expected in [(0x38c428b, 0x15b54d0), (0x15b5512, 0x153f7b0),
                            (0x153f873, 0x155ca60), (0x38c42bb, 0x4468e30),
                            (0x38c4361, 0x3d71420), (0x38c4819, 0x37c0160)]:
        instruction = read(site, 5)
        target = site + 5 + int.from_bytes(instruction[1:], 'little', signed=True)
        require(instruction[0] == 0xe8 and target == expected, f'direct call {site:#x}')
    print(f"Verified {len(packet['functions'])} FDEs, {sum(len(f['instructions']) for f in packet['functions'])} selected instructions and {len(packet['calls'])} callee bindings; all shifted call controls rejected.")

if __name__ == '__main__':
    verify()
