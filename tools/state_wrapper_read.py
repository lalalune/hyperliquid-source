#!/usr/bin/env python3
"""Static #94 state-wrapper decoder evidence, using ELF bytes only."""
import argparse
import hashlib
import json
from pathlib import Path
import struct
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
from elf_index import sections
from fde_extents import fde_extents

DIGEST = '3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f'
BINARY = ROOT / 'artifacts/node/94/hl-node'
PARSERS = (0x1799b10, 0x405b970)
TABLES = ((0x2c88a0, 0x6b55f0, 225), (0x2c8c24, 0x6b5974, 18),
          (0x2c8cec, 0x6b5a3c, 225), (0x2c9070, 0x6b5dc0, 18),
          (0x2c90b8, 0x6b5e08, 32))

def require(ok, message):
    if not ok:
        raise ValueError(message)

def verified(data):
    require(hashlib.sha256(data).hexdigest() == DIGEST, 'unexpected node digest')

def at(data, va, size):
    require(size >= 0, 'negative size')
    matches = [s for s in sections(data) if s['type'] != 8 and s['address'] <= va
               and va + size <= s['address'] + s['size']]
    require(len(matches) == 1, 'unmapped or ambiguous VA')
    s = matches[0]
    off = s['offset'] + va - s['address']
    return data[off:off + size]

def expect(data, va, pattern):
    raw = at(data, va, len(pattern))
    require(raw == pattern, 'instruction mismatch at ' + hex(va))
    return raw.hex()

def rel32(data, va, op):
    raw = at(data, va, len(op) + 4)
    require(raw.startswith(op), 'unexpected instruction at ' + hex(va))
    return va + len(raw) + struct.unpack('<i', raw[-4:])[0]

def branch(data, va, opcode):
    return rel32(data, va, opcode)

def decode_key(data, base):
    # Repeated cmp byte ptr [r12+offset], immediate; the first is offset zero.
    p = base + 0x6c6
    raw = at(data, p, 5)
    require(raw[:4] == b'\x41\x80\x3c\x24', 'first key compare changed')
    chars = [raw[4]]
    require(at(data, p + 5, 1) == b'\x75', 'first key mismatch branch changed')
    p += 7  # cmp plus short conditional branch
    for offset in range(1, 8):
        raw = at(data, p, 6)
        require(raw[:4] == b'\x41\x80\x7c\x24' and raw[4] == offset,
                'key compare sequence changed')
        chars.append(raw[5])
        if offset < 7:
            require(at(data, p + 6, 1) == b'\x75', 'key mismatch branch changed')
        p += 8
    return bytes(chars)

def classify(key, seen, expected):
    if key != expected:
        return 'skip-unknown-value'
    return 'duplicate-field' if seen else 'decode-value'

def extract(data):
    verified(data)
    _, fdes, _ = fde_extents(data)
    selected = {}
    for f in fdes:
        if f['start'] in (*PARSERS, 0x28e96b0, 0x432fe50):
            require(f['start'] not in selected, 'duplicate FDE')
            selected[f['start']] = f
    require(len(selected) == 4, 'missing or duplicate FDE')
    bodies = []
    for start in (*PARSERS, 0x28e96b0, 0x432fe50):
        f = selected[start]
        raw = at(data, start, f['end'] - start)
        bodies.append(dict(start=hex(start), end=hex(f['end']), fde=hex(f['fde']),
                           size=len(raw), sha256=hashlib.sha256(raw).hexdigest()))
    keys = [decode_key(data, p) for p in PARSERS]
    require(keys[0] == keys[1] == at(data, 0x20a468, 8), 'key copies disagree')
    key = keys[0]
    require(key == b'exchange', 'unexpected field')
    tables = []
    for a, b, count in TABLES:
        left = [a + n[0] for n in struct.iter_unpack('<i', at(data, a, count * 4))]
        right = [b + n[0] for n in struct.iter_unpack('<i', at(data, b, count * 4))]
        left_offsets = [x - PARSERS[0] for x in left]
        right_offsets = [x - PARSERS[1] for x in right]
        require(all(0 <= x < selected[PARSERS[0]]['end'] - PARSERS[0] for x in left_offsets), 'left table target outside extent')
        require(all(0 <= x < selected[PARSERS[1]]['end'] - PARSERS[1] for x in right_offsets), 'right table target outside extent')
        require(left_offsets == right_offsets, 'table copies differ')
        tables.append(dict(left=hex(a), right=hex(b), entries=count,
                           target_offsets=[hex(x) for x in left_offsets]))
    pins = []
    # These contiguous byte sequences bind key-length, map loop, duplicate and missing branches.
    for p in PARSERS:
        for offset, pattern, label in [
            (0x6be, 'b0014183ff08', 'key-length'),
            (0x425, '48c784249020000002000000', 'empty-slot-tag'),
            (0x4a5, '41ffcd', 'map-count-decrement'),
            (0xb4f, '83bc249020000002', 'seen-slot-test'),
            (0xb68, '31d2', 'value-decoder-argument'),
            (0x2e9, '49c7461800000000', 'truncated-input-zero-remaining'),
            (0xbe9, '4983ff02', 'missing-slot-test'),
            (0x10a, '4883f902', 'short-two-byte-length-test'),
            (0xde8, '85ed', 'sequence-count-test'),
            (0xf12, '83fd01', 'sequence-one-element-test'),
            (0xf27, 'bac81f0000', 'successful-sequence-copy-size'),
        ]:
            raw = bytes.fromhex(pattern)
            pins.append(dict(site=hex(p+offset), role=label, bytes=expect(data,p+offset,raw)))
    edges = []
    for p in PARSERS:
        for off, opcode, role in [(0x4a8,b'\x0f\x84','end-map'),
                                   (0x434,b'\x0f\x84','empty-map-missing'),
                                   (0x7b6,b'\xe8','unknown-value-helper'),
                                   (0xb57,b'\x0f\x85','duplicate-field'),
                                   (0xb6a,b'\xe8','value-decoder'),
                                   (0xdea,b'\x0f\x84','empty-sequence-error'),
                                   (0xdfd,b'\xe8','sequence-value-decoder'),
                                  ]:
            target = branch(data, p+off, opcode)
            edges.append(dict(site=hex(p+off), target=hex(target), role=role))
    require(rel32(data, 0x28e9bac, b'\xe8') == PARSERS[0], 'file loader edge changed')
    require(rel32(data, 0x432fea7, b'\xe8') == PARSERS[1], 'buffer wrapper edge changed')
    require(at(data, 0x1df8f3, 16) == b'\x0fmissing field `', 'missing-field template changed')
    require(at(data, 0x1e0fd5, 18) == b'\x11duplicate field `', 'duplicate-field template changed')
    loader_pins = []
    for va, pattern, role in [(0x28e9828, '4080fe72', 'extension-r'),
                              (0x28e9849, '4080fe6d', 'extension-m'),
                              (0x28e9866, '80f970', 'extension-p'),
                              (0x28e9c72, 'bac81f0000', 'file-success-copy-size'),
                              (0x432fef7, 'bac81f0000', 'buffer-success-copy-size'),
                              (0x432ff40, '49c70602000000', 'buffer-error-tag')]:
        loader_pins.append(dict(site=hex(va), role=role, bytes=expect(data,va,bytes.fromhex(pattern))))
    mutations = [key[:i] + bytes([c ^ 1]) + key[i+1:] for i,c in enumerate(key)]
    cases = [dict(key=x.hex(), unseen=classify(x,False,key), seen=classify(x,True,key))
             for x in [key, b'', key+b'X'] + mutations]
    return dict(binary_sha256=DIGEST, coordinate='ELF virtual address', functions=bodies,
                key=key.decode('ascii'), templates={'missing':at(data,0x1df8f3,16).hex(),
                'duplicate':at(data,0x1e0fd5,18).hex()}, pins=pins, loader_pins=loader_pins, edges=edges,
                entry_edges=[{'site':hex(0x28e9bac),'target':hex(PARSERS[0])},
                             {'site':hex(0x432fea7),'target':hex(PARSERS[1])}],
                tables=tables, key_cases=cases,
                limits='FDE extents are unwind ranges, not complete CFG proof. Tables and key cases are static byte-derived models, not execution. Value decoder, unknown-value skipper, input reachability and full state schema remain open.')

def main():
    ap=argparse.ArgumentParser(); ap.add_argument('--out', required=True, type=Path); args=ap.parse_args()
    result=extract(BINARY.read_bytes())
    args.out.mkdir(parents=True,exist_ok=True)
    (args.out/'records.json').write_text(json.dumps(result,indent=2,sort_keys=True)+'\n',encoding='utf-8')

if __name__ == '__main__': main()
