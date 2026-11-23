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
    kind, address = table[0x64dfc30]
    require(kind == 8, 'whitespace table binding')
    pages = read(address, 256)
    classes = {n for n in range(33) if (0x100003e00 >> n) & 1} | {0x1680, 0x3000}
    classes.update(n for n in range(128,256) if pages[n] & 1)
    classes.update(0x2000+n for n in range(256) if pages[n] & 2)
    expected = {*range(9,14), 32, 0x85, 0xa0, 0x1680, *range(0x2000,0x200b), 0x2028, 0x2029, 0x202f, 0x205f, 0x3000}
    require(classes == expected, 'wrong whitespace contract')
    print(f"Verified {len(packet['functions'])} FDEs, {sum(len(f['instructions']) for f in packet['functions'])} selected instructions and {len(packet['calls'])} callee bindings; all shifted call controls rejected.")

if __name__ == '__main__':
    verify()
