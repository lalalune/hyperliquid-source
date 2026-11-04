#!/usr/bin/env python3
"""Regenerate the node #115 folded-product update evidence without execution."""
import argparse
import hashlib
import json
import mmap
from pathlib import Path
import struct

from elf_index import sections
from fde_extents import eh_frame_records

ROOT = Path(__file__).resolve().parents[1]
TARGET = ROOT / 'artifacts/node/115/hl-node'
SHA = 'a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301'
START, END = 0x1452020, 0x14520cb
BODY_SHA = '25284b67050c3005c1a8984afde7cc6e9a1b1b0779a6920db014d1ea9b830d60'
FDE = {'fde': 0xcaa498, 'cie': 0xca6ed8, 'start': START, 'end': END, 'lsda': None}
FDE_HEX = '18000000c4350000807b7a00ab00000000410e10830202a90e080000'
CIE_HEX = '1400000000000000017a5200017810011b0c070890010000'
# This finite decoder recognizes only the exact encodings in this function.
# Each entry is one entire x86 instruction; unknown encodings fail closed.
INSTRUCTIONS = [
    ('53', 'push   rbx'),
    ('0fb64e20', 'movzx  ecx,BYTE PTR [rsi+0x20]'),
    ('4c8b0e', 'mov    r9,QWORD PTR [rsi]'),
    ('488b4608', 'mov    rax,QWORD PTR [rsi+0x8]'),
    ('4c8b4610', 'mov    r8,QWORD PTR [rsi+0x10]'),
    ('488b5618', 'mov    rdx,QWORD PTR [rsi+0x18]'),
    ('4c8b17', 'mov    r10,QWORD PTR [rdi]'),
    ('80f941', 'cmp    cl,0x41'),
    ('721f', 'jb     145205b'),
    ('4c31ca', 'xor    rdx,r9'),
    ('4d8b00', 'mov    r8,QWORD PTR [r8]'),
    ('4c31c0', 'xor    rax,r8'),
    ('48f7e2', 'mul    rdx'),
    ('4831c2', 'xor    rdx,rax'),
    ('4c8b4f08', 'mov    r9,QWORD PTR [rdi+0x8]'),
    ('4883c710', 'add    rdi,0x10'),
    ('4531db', 'xor    r11d,r11d'),
    ('4889fb', 'mov    rbx,rdi'),
    ('eb48', 'jmp    14520a3'),
    ('4531db', 'xor    r11d,r11d'),
    ('4d0fa5d3', 'shld   r11,r10,cl'),
    ('49d3e2', 'shl    r10,cl'),
    ('31db', 'xor    ebx,ebx'),
    ('f6c140', 'test   cl,0x40'),
    ('4d0f45da', 'cmovne r11,r10'),
    ('4c0f45d3', 'cmovne r10,rbx'),
    ('4909c3', 'or     r11,rax'),
    ('4d09ca', 'or     r10,r9'),
    ('488d5f10', 'lea    rbx,[rdi+0x10]'),
    ('4c8b4f08', 'mov    r9,QWORD PTR [rdi+0x8]'),
    ('4d8b00', 'mov    r8,QWORD PTR [r8]'),
    ('84c9', 'test   cl,cl'),
    ('741c', 'je     14520a3'),
    ('4c31d2', 'xor    rdx,r10'),
    ('4d31d8', 'xor    r8,r11'),
    ('4c89c0', 'mov    rax,r8'),
    ('48f7e2', 'mul    rdx'),
    ('4831c2', 'xor    rdx,rax'),
    ('48895618', 'mov    QWORD PTR [rsi+0x18],rdx'),
    ('8b03', 'mov    eax,DWORD PTR [rbx]'),
    ('b260', 'mov    dl,0x60'),
    ('4c89c9', 'mov    rcx,r9'),
    ('eb1c', 'jmp    14520bf'),
    ('4c31d2', 'xor    rdx,r10'),
    ('4d09d9', 'or     r9,r11'),
    ('4d31c1', 'xor    r9,r8'),
    ('8b0b', 'mov    ecx,DWORD PTR [rbx]'),
    ('4c89c8', 'mov    rax,r9'),
    ('48f7e2', 'mul    rdx'),
    ('4831c2', 'xor    rdx,rax'),
    ('48895618', 'mov    QWORD PTR [rsi+0x18],rdx'),
    ('b220', 'mov    dl,0x20'),
    ('31c0', 'xor    eax,eax'),
    ('48890e', 'mov    QWORD PTR [rsi],rcx'),
    ('48894608', 'mov    QWORD PTR [rsi+0x8],rax'),
    ('885620', 'mov    BYTE PTR [rsi+0x20],dl'),
    ('5b', 'pop    rbx'),
    ('c3', 'ret'),
]


def decode(body, fde):
    if fde != FDE:
        raise ValueError('FDE extent or identity changed')
    rows = []
    offset = 0
    for raw, meaning in INSTRUCTIONS:
        expected = bytes.fromhex(raw)
        if body[offset:offset + len(expected)] != expected:
            raise ValueError('unsupported or changed instruction')
        row = {'address': START + offset, 'bytes': raw, 'instruction': meaning}
        if expected[0] in (0x72, 0x74, 0xeb):
            target = START + offset + 2 + struct.unpack('b', expected[1:2])[0]
            row['branch_target'] = target
        rows.append(row)
        offset += len(expected)
    if offset != len(body) or hashlib.sha256(body).hexdigest() != BODY_SHA:
        raise ValueError('body extent or hash changed')
    starts = {row['address'] for row in rows}
    if any(row.get('branch_target', START) not in starts for row in rows):
        raise ValueError('branch does not target a decoded instruction')
    return rows


def fold(a, b):
    p = a * b
    return (p & ((1 << 64) - 1)) ^ (p >> 64)


def model(words, key, count, block):
    """Model the observed update; words are state +0,+8,+24 and key is *+16."""
    mask = (1 << 64) - 1
    if (len(words) != 3 or len(block) != 20 or not 0 <= count <= 255 or
            any(not 0 <= x <= mask for x in (*words, key))):
        raise ValueError('invalid model input')
    lo, hi, acc = words
    x = int.from_bytes(block[:8], 'little')
    y = int.from_bytes(block[8:16], 'little')
    z = int.from_bytes(block[16:20], 'little')
    if count > 64:
        acc = fold(acc ^ lo, hi ^ key)
        low, high = x, 0
    else:
        if count == 0:
            low, high = x, 0
        elif count == 64:
            low, high = 0, x
        else:
            low, high = (x << count) & mask, x >> (64 - count)
        low |= lo
        high |= hi
    if 0 < count <= 64:
        return (y, z, fold(acc ^ low, key ^ high), 96)
    return (z, 0, fold(acc ^ low, key ^ (y | high)), 32)


def inspect(data):
    if hashlib.sha256(data).hexdigest() != SHA:
        raise ValueError('node #115 digest mismatch')
    secs = sections(data)
    text = [s for s in secs if s['name'] == '.text' and s['flags'] & 4]
    if len(text) != 1 or text[0]['address'] != 0x1419300 or text[0]['size'] != 0x63f0a00 - 0x1419300:
        raise ValueError('unexpected text mapping')
    s = text[0]
    body_off = s['offset'] + START - s['address']
    cies, fdes = eh_frame_records(data, secs)
    matches = [f for f in fdes if f['start'] == START]
    if matches != [FDE]:
        raise ValueError('unexpected FDE')
    frame = next(x for x in secs if x['name'] == '.eh_frame')
    def frame_bytes(va, n):
        off = frame['offset'] + va - frame['address']
        return data[off:off+n]
    if frame_bytes(FDE['fde'], len(bytes.fromhex(FDE_HEX))).hex() != FDE_HEX or frame_bytes(FDE['cie'], len(bytes.fromhex(CIE_HEX))).hex() != CIE_HEX:
        raise ValueError('frame bytes changed')
    rows = decode(data[body_off:body_off + END - START], matches[0])
    pad = data[body_off + END - START:body_off + END - START + 5]
    if pad != b'\xcc' * 5:
        raise ValueError('post-body padding changed')
    callers = []
    for opcode in (0xe8, 0xe9):
        pos = s['offset']
        limit = s['offset'] + s['size']
        while True:
            pos = data.find(bytes([opcode]), pos, limit - 4)
            if pos < 0:
                break
            va = s['address'] + pos - s['offset']
            if va + 5 + struct.unpack_from('<i', data, pos + 1)[0] == START:
                callers.append({'address': va, 'opcode': f'{opcode:02x}', 'bytes': data[pos:pos+5].hex()})
            pos += 1
    callers.sort(key=lambda x: x['address'])
    if [(x['address'], x['opcode']) for x in callers] != [(0x1451621, 'e8'), (0x1451ed5, 'e8')]:
        raise ValueError('rel32 census changed')
    return {'target_sha256': SHA, 'window': {'start': START, 'end': END, 'size': END-START,
            'file_offset': body_off, 'body_sha256': BODY_SHA, 'padding_hex': pad.hex()},
            'fde': FDE, 'fde_bytes': FDE_HEX, 'cie': cies[FDE['cie']], 'cie_bytes': CIE_HEX,
            'instructions': rows, 'callees': [], 'rel32_candidates': callers,
            'census': {'text_start': s['address'], 'text_end': s['address'] + s['size'],
                       'method': 'all byte offsets with e8/e9 and signed rel32', 'candidate_count': len(callers)},
            'counts': {'instructions': len(rows), 'callees': 0, 'rel32_candidates': len(callers)}}


def generate(target, out):
    with open(target, 'rb') as f, mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ) as data:
        records = inspect(data)
    out.mkdir(parents=True, exist_ok=True)
    (out / 'records.json').write_text(json.dumps(records, indent=2) + '\n', encoding='utf-8')
    return records


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--target', type=Path, default=TARGET)
    p.add_argument('--out', type=Path, required=True)
    args = p.parse_args()
    generate(args.target, args.out)


if __name__ == '__main__':
    main()
