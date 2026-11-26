#!/usr/bin/env python3
"""Authenticate retained response-writer observations without executing target code."""
import argparse
import hashlib
import json
from pathlib import Path
import struct
import sys

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / 'tools'))
from elf_index import unwind_index
from fde_extents import eh_frame_records

P = Path(__file__).with_name('records.json')

def require(ok, message):
    if not ok: raise ValueError(message)

def verify(target):
    p = json.loads(P.read_text()); data = target.read_bytes()
    require(len(data) == p['target_size'] and hashlib.sha256(data).hexdigest() == p['target_sha256'], 'wrong target')
    secs, _ = unwind_index(data); _, fdes = eh_frame_records(data, secs)
    bounds = {(f['start'], f['end']) for f in fdes}
    def read(address, count):
        for sec in secs:
            if sec['type'] != 8 and sec['address'] <= address and address + count <= sec['address'] + sec['size']:
                off = sec['offset'] + address - sec['address']; return data[off:off + count]
        raise ValueError('unmapped')
    for w in p['windows']:
        a, e = int(w['start'],16),int(w['end'],16)
        require((a,e) in bounds, 'wrong FDE')
        require(hashlib.sha256(read(a,e-a)).hexdigest() == w['sha256'], 'wrong function bytes')
    for addr, expected in p['constants'].items():
        require(read(int(addr,16), len(bytes.fromhex(expected))) == bytes.fromhex(expected), 'wrong constant')
    require(bytes.fromhex(p['constants']['0x459e7c']) == b'Hash' and bytes.fromhex(p['constants']['0x459ff0']) == b'Full' and bytes.fromhex(p['constants']['0x455d40']) == b'0123456789abcdef', 'wrong literal')
    sec = next(s for s in secs if s['name']=='.rela.dyn')
    rels = {slot:(info, addend) for slot,info,addend in struct.iter_unpack('<QQq',data[sec['offset']:sec['offset']+sec['size']])}
    require(rels[int(p['relocation']['slot'],16)] == (8,int(p['relocation']['target'],16)), 'wrong hex relocation')
    def witness(w, raw):
        require(raw == bytes.fromhex(w['bytes']), 'instruction mismatch')
    expected = {
        '0x506e2d6':'803b02', '0x506e2f6':'c704306e756c6c',
        '0x4d6d17f':'803f01', '0x4d6d19c':'c604307b',
        '0x4d6d20d':'c604303a', '0x4d6d310':'c604307d',
        '0x502d0fd':'c604305b', '0x502d111':'496bec38',
        '0x502d135':'c604302c', '0x502d158':'c604305b',
        '0x502d1bf':'c604302c', '0x502d1df':'c604305b',
        '0x502d292':'c604305d', '0x502d2b8':'c604305d',
        '0x2eabb62':'66c7073078', '0x4e1c27a':'c6043122',
    }
    rows = {w['address']: w for w in p['witnesses']}
    for address, raw in expected.items():
        require(rows[address]['bytes'] == raw, f'semantic bytes differ: {address}')
    for site, target in [('0x4d6d248',0x4e1c250),('0x502d194',0x4e1c250),('0x502d1f9',0x54834d0)]:
        b=bytes.fromhex(rows[site]['bytes']); require(b[0]==0xe8 and int(site,16)+5+struct.unpack('<i',b[1:])[0]==target, 'wrong call target')
    for w in p['witnesses']:
        raw=read(int(w['address'],16),len(bytes.fromhex(w['bytes']))); witness(w,raw)
        changed=bytearray(raw); changed[-1]^=1
        try: witness(w,changed)
        except ValueError: pass
        else: raise ValueError('corruption accepted')
    print(f"PASS: {len(p['windows'])} FDEs and {len(p['witnesses'])} instruction witnesses; {len(p['witnesses'])} changed-byte controls rejected")
if __name__ == '__main__':
    parser=argparse.ArgumentParser();parser.add_argument('--target',type=Path,required=True);verify(parser.parse_args().target)
