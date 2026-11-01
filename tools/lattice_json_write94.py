#!/usr/bin/env python3
"""Extract selected #94 lattice JSON writer evidence from authenticated ELF bytes."""
import argparse
import hashlib
import json
from pathlib import Path
import struct
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
from elf_index import sections, unwind_index
from fde_extents import eh_frame_records

DIGEST = '3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f'
BINARY = ROOT / 'artifacts/node/94/hl-node'
BODIES = {
    0x3c8c100: '4a69792f41c6613cbbf76ad9c089c13544971f75d3bd60ba4d2ce5137d2296b6',
    0x3c83850: '89c656f3154296195980175d030ec2195391b83c4d81b69eb2a07e9c593cfb2f',
    0x3bebf60: 'd59d5fc614084e7fb508750f3201750a90fadc182dc9b41128cec2e3af4ab30f',
    0x3c1d4d0: '7f2a73a6b3222d0ce322a4d2b3b4293fb2815f4846b8f8c4ddd80f510ea6fe53',
}
# Pins are instruction-aligned windows inspected manually; the enclosing upstream
# serializer is prior work and is used only for these contextual call sites.
PINS = {
  0x3c8385b: 'e860b1010041803e01744a',
  0x3c8c111: 'e8aa28010041803e017479',
  0x3bebf6e: '488b6f104883fdff0f8454030000',
  0x3bec0c5: '3c0a7317',
  0x3bebff0: '488b034c29f04883f8010f8694010000',
  0x3bebfdd: '488b430842c604300a49ffc6eb24',
  0x37eb894: '488d8b00080000488d3507fadafc4889e7ba0a000000e851084a00',
  0x37eb8c2: '488d8b08080000488d35e3f9dafc4889e7ba07000000e823084a00',
  0x37eb8f0: '488d35c5e4a1fc4889e7ba040000004889d9e8497f4900',
  0x3c8388f: '498d7e08b9000800004c89f64889dae8bd86f6ff',
  0x3c8c14d: '4889e6e87b13f9ff',
  0x3bebf98: '488b430842c604305b49ffc64c8973104885c90f847a020000',
  0x3bec080: '488b4424180fb6004883f86376320fb6c88d14898d0cd1c1e90c6bd16428d00fb6c0488d15e4d79cfc0fb70442668944242131d289c8eb110f1f840000000000ba020000003c0a73170c3088441420eb246666666666662e0f1f840000000000488d0da6d79cfc0fb704416689442421ba010000004989d549',
  0x3bec126: '488b0c24c641180131c0488b7424104889f2483b7424080f858dfeffff',
  0x3bec22f: '4c39337457488b430842c604305d49ffc64c897310',
  0x3c1d4d0: '53b8140000004881ff102700000f82aa000000b91400000049b84b598638d6c56d344c8d0d94c399fc0f1f',
  0x3c1d500: '4889f849f7e04889c84883c0fc0f80e500000048c1ea0b4c69da102700004989fa4d29da',
  0x3c1d5e2: '4883f8147710ba140000004829c24801c64889f05b',
}

def checked_digest(data, expected=None):
    if hashlib.sha256(data).hexdigest() != (DIGEST if expected is None else expected):
        raise ValueError('node #94 SHA-256 mismatch')

def at(data, secs, va, size):
    if size < 0:
        raise ValueError('negative length')
    hits = [s for s in secs if s['type'] != 8 and s['address'] <= va
            and va + size <= s['address'] + s['size'] and (size or va < s['address'] + s['size'])]
    if len(hits) != 1:
        raise ValueError('unmapped or ambiguous file-backed VA')
    s = hits[0]
    off = s['offset'] + va - s['address']
    return data[off:off + size]

def require(data, secs, va, expected):
    raw = at(data, secs, va, len(expected))
    if raw != expected:
        raise ValueError('instruction pin mismatch at %#x' % va)
    return raw

def rel32(data, secs, site, opcode=b'\xe8'):
    raw = at(data, secs, site, 5)
    if raw[:1] != opcode:
        raise ValueError('unexpected relative call opcode')
    return site + 5 + struct.unpack_from('<i', raw, 1)[0]

def rip(data, secs, site, prefix):
    raw = at(data, secs, site, 7)
    if raw[:3] != prefix:
        raise ValueError('unexpected RIP instruction')
    return site + 7 + struct.unpack_from('<i', raw, 3)[0]

def decimal_byte(value, pairs, limit):
    if not 0 <= value < limit or len(pairs) != 200:
        raise ValueError('byte or digit table out of range')
    if value < 10:
        return bytes([0x30 | value])
    if value <= 99:
        return pairs[value * 2:value * 2 + 2]
    # This is the multiply/shift sequence at the byte writer.
    hundreds = (value * 41) >> 12
    remainder = value - hundreds * 100
    return bytes([0x30 | hundreds]) + pairs[remainder * 2:remainder * 2 + 2]

def decimal_u64(value, pairs, magic, width, chunk):
    if not 0 <= value < 1 << 64 or len(pairs) != 200 or width != 20 or chunk != 10000:
        raise ValueError('integer or formatter constants out of range')
    n = value
    tails = []
    while n >= chunk:
        quotient = ((n * magic) >> 64) >> 11
        rest = n - quotient * chunk
        if not 0 <= rest < chunk:
            raise ValueError('invalid quotient')
        tails.append(pairs[(rest // 100)*2:(rest // 100)*2+2] + pairs[(rest % 100)*2:(rest % 100)*2+2])
        n = quotient
    if n < 10:
        lead = bytes([0x30 | n])
    elif n < 100:
        lead = pairs[2*n:2*n+2]
    else:
        lead = decimal_byte(n // 100, pairs, 256) + pairs[(n % 100)*2:(n % 100)*2+2]
    return lead + b''.join(reversed(tails))

def extract(data):
    checked_digest(data)
    secs, index = unwind_index(data)
    _, frames = eh_frame_records(data, secs)
    by_start = {}
    for f in frames:
        if f['start'] in BODIES:
            by_start.setdefault(f['start'], []).append(f)
    index_pairs = {(e['start'], e['fde']) for e in index}
    bodies = []
    for start, expected in sorted(BODIES.items()):
        matches = by_start.get(start, [])
        if len(matches) != 1 or (start, matches[0]['fde']) not in index_pairs:
            raise ValueError('missing or ambiguous indexed FDE')
        f = matches[0]
        raw = at(data, secs, start, f['end'] - start)
        actual = hashlib.sha256(raw).hexdigest()
        if actual != expected:
            raise ValueError('body hash mismatch at %#x' % start)
        bodies.append({'start':hex(start), 'end_exclusive':hex(f['end']), 'fde':hex(f['fde']), 'body_sha256':actual})
    windows = []
    for va, expected in sorted(PINS.items()):
        raw = require(data, secs, va, bytes.fromhex(expected))
        windows.append({'va':hex(va), 'bytes':raw.hex()})
    edges = []
    for site, target in [(0x37eb8aa,0x3c8c100),(0x37eb8d8,0x3c8c100),
                         (0x37eb902,0x3c83850),(0x3c8389e,0x3bebf60),
                         (0x3c8c150,0x3c1d4d0)]:
        got = rel32(data, secs, site)
        if got != target:
            raise ValueError('unexpected call target')
        edges.append({'site':hex(site),'target':hex(got)})
    branches = []
    for site in (0x3c83864, 0x3c8c11a, 0x3bebf76, 0x3bebfab, 0x3bec08c, 0x3bec0c7, 0x3bec13d,
                 0x3bebf92, 0x3bebfd7, 0x3bebffa, 0x3bec039,
                 0x3bec105, 0x3bec1c5, 0x3bec232,
                 0x3c8c135, 0x3c8c165, 0x3c8387b):
        lead = at(data, secs, site, 2)
        if 0x70 <= lead[0] <= 0x7f:
            raw = lead
            dest = site + 2 + struct.unpack('<b', raw[1:])[0]
        elif lead[0] == 0x0f and 0x80 <= lead[1] <= 0x8f:
            raw = at(data, secs, site, 6)
            dest = site + 6 + struct.unpack_from('<i', raw, 2)[0]
        else:
            raise ValueError('unexpected conditional branch')
        branches.append({'site':hex(site),'opcode':raw[:len(raw)- (1 if len(raw)==2 else 4)].hex(),'destination':hex(dest)})
    table_va = rip(data, secs, 0x3c1d4f2, b'\x4c\x8d\x0d')
    if table_va != rip(data, secs, 0x3bec0a2, b'\x48\x8d\x15'):
        raise ValueError('digit tables differ')
    pairs = at(data, secs, table_va, 200)
    if pairs != b''.join(('%02d' % i).encode('ascii') for i in range(100)):
        raise ValueError('invalid decimal table')
    names = []
    for site, prefix, length in [(0x37eb89b,b'\x48\x8d\x35',10),
                                  (0x37eb8c9,b'\x48\x8d\x35',7),
                                  (0x37eb8f0,b'\x48\x8d\x35',4)]:
        va = rip(data, secs, site, prefix)
        names.append({'va':hex(va),'ascii':at(data, secs, va, length).decode('ascii')})
    if [n['ascii'] for n in names] != ['n_elements','n_bytes','hash']:
        raise ValueError('unexpected field names')
    byte_count = struct.unpack('<I',at(data, secs, 0x3c83894,4))[0]
    width = struct.unpack('<I',at(data, secs, 0x3c1d4d2,4))[0]
    chunk = struct.unpack('<I',at(data, secs, 0x3c1d4d9,4))[0]
    magic = struct.unpack('<Q',at(data, secs, 0x3c1d4ea,8))[0]
    if (byte_count,width,chunk,magic) != (2048,20,10000,0x346dc5d63886594b):
        raise ValueError('unexpected formatter constants')
    return {'target_sha256':DIGEST,'coordinate_system':'linked ELF virtual address',
            'fdes':bodies,'windows':windows,'calls':edges,'branches':branches,'fields':names,
            'hash_input_bytes':byte_count,'decimal_table_va':hex(table_va),
            'decimal_table_ascii':pairs.decode('ascii'), 'integer_buffer_width':width,
            'chunk_base':chunk,'chunk_reciprocal':hex(magic)}

def write(out, rec):
    out.mkdir(parents=True, exist_ok=True)
    pairs = rec['decimal_table_ascii'].encode('ascii')
    rows = ['input_byte\tdecimal_ascii']
    for v in range(256):
        rows.append('%d\t%s' % (v,decimal_byte(v,pairs,256).decode('ascii')))
    (out / 'byte-decimal.tsv').write_text('\n'.join(rows)+'\n',encoding='utf-8')
    (out / 'records.json').write_text(json.dumps(rec,indent=2,sort_keys=True)+'\n',encoding='utf-8')

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--out',required=True,type=Path)
    args = ap.parse_args()
    write(args.out,extract(BINARY.read_bytes()))

if __name__ == '__main__':
    main()
