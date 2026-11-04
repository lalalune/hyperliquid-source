#!/usr/bin/env python3
"""Reproduce the #115 0x243ca40 static search certificate; never executes it."""
import argparse
import hashlib
import json
import mmap
from pathlib import Path
import struct

ROOT = Path(__file__).resolve().parents[1]
TARGET = ROOT / 'artifacts/node/115/hl-node'
DIGEST = 'a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301'
START, END = 0x243ca40, 0x243cabb
TEXT_START, TEXT_END, TEXT_FILE = 0x1419300, 0x63f0a00, 0x1418300
FDE, CIE = 0xd0f804, 0xca6ed8
BODY_HASH = '46b83804c37ee1e4667c35161e74896eb3d3f11f3b46bed08b5ad3a21b6e3bc0'
# Each row is one complete instruction, with exact encoding and decoded effect.
# Branch displacements are also decoded and checked against instruction starts.
INSTRUCTIONS = [
 ('488b0f','mov rcx,[rdi]'), ('4885c9','test rcx,rcx'), ('7470','je 0x243cab8'),
 ('488b5708','mov rdx,[rdi+8]'), ('488b36','mov rsi,[rsi]'), ('31c0','xor eax,eax'),
 ('440fb74162','movzx r8d,word [rcx+0x62]'), ('4589c1','mov r9d,r8d'),
 ('41c1e103','shl r9d,3'), ('48c7c7ffffffff','mov rdi,-1'),
 ('6666662e0f1f840000000000','nop'), ('4d85c9','test r9,r9'),
 ('742b','je 0x243caa0'), ('483b74f910','cmp rsi,[rcx+rdi*8+0x10]'),
 ('410f97c2','seta r10b'), ('4180da00','sbb r10b,0'), ('48ffc7','inc rdi'),
 ('4983c1f8','add r9,-8'), ('4180fa01','cmp r10b,1'), ('74e1','je 0x243ca70'),
 ('450fb6c2','movzx r8d,r10b'), ('4585c0','test r8d,r8d'), ('7418','je 0x243cab0'),
 ('eb09','jmp 0x243caa3'), ('660f1f440000','nop'), ('4c89c7','mov rdi,r8'),
 ('4883ea01','sub rdx,1'), ('7211','jb 0x243caba'),
 ('488b4cf968','mov rcx,[rcx+rdi*8+0x68]'), ('eba1','jmp 0x243ca51'),
 ('4883c164','add rcx,0x64'), ('4889c8','mov rax,rcx'), ('c3','ret'),
 ('31c0','xor eax,eax'), ('c3','ret'),
]


def decode(body):
    if len(body) != END - START:
        raise ValueError('window extent')
    result, pos, branches = [], 0, []
    for code, effect in INSTRUCTIONS:
        raw = bytes.fromhex(code)
        if body[pos:pos + len(raw)] != raw:
            raise ValueError('instruction mismatch at ' + hex(START + pos))
        item = {'address': hex(START + pos), 'bytes': code, 'instruction': effect}
        if raw[0] in (0x74, 0x72, 0xeb):
            dest = START + pos + 2 + struct.unpack('b', raw[1:2])[0]
            if dest != int(effect.split()[-1], 16):
                raise ValueError('branch target mismatch')
            item['target'] = hex(dest)
            branches.append(dest)
        result.append(item)
        pos += len(raw)
    if pos != len(body) or any(hex(x) not in {i['address'] for i in result} for x in branches):
        raise ValueError('instruction coverage or branch boundary')
    if hashlib.sha256(body).hexdigest() != BODY_HASH:
        raise ValueError('body hash')
    return result


def check_frame(frame, cie):
    # zR CIE, signed PC-relative 4-byte FDE start, unsigned 4-byte range, empty augmentation.
    if cie != bytes.fromhex('1400000000000000017a5200017810011b0c070890010000'):
        raise ValueError('unexpected CIE')
    if len(frame) != 20:
        raise ValueError('unexpected FDE length')
    length, cie_delta, start_delta, size = struct.unpack_from('<IIiI', frame)
    if length != 16 or FDE + 4 - cie_delta != CIE or FDE + 8 + start_delta != START or size != END - START or frame[16:] != b'\0\0\0\0':
        raise ValueError('FDE binding mismatch')


def rel32_target(site, raw):
    if len(raw) != 5 or raw[0] not in (0xe8, 0xe9):
        raise ValueError('invalid rel32 instruction')
    return site + 5 + struct.unpack_from('<i', raw, 1)[0]


def direct_hits(data):
    # Bytewise scan, including potentially unaligned opcode-looking bytes. It is
    # an over-approximation, not a whole-program instruction-boundary census.
    end = TEXT_FILE + TEXT_END - TEXT_START
    pos, hits = TEXT_FILE, []
    while pos < end - 4:
        call = data.find(b'\xe8', pos, end - 4)
        jump = data.find(b'\xe9', pos, end - 4)
        choices = [x for x in (call, jump) if x >= 0]
        if not choices:
            break
        off = min(choices)
        site = TEXT_START + off - TEXT_FILE
        if rel32_target(site, data[off:off + 5]) == START:
            hits.append({'site': hex(site), 'opcode': hex(data[off]), 'bytes': data[off:off + 5].hex()})
        pos = off + 1
    return hits


def check_callers(hits):
    if hits != [
        {'site': '0x28d37b2', 'opcode': '0xe8', 'bytes': 'e88992b6ff'},
        {'site': '0x2c49c8d', 'opcode': '0xe8', 'bytes': 'e8ae2d7fff'},
    ]:
        raise ValueError('caller census changed')


def authenticate(data):
    if len(data) != 105896032 or hashlib.sha256(data).hexdigest() != DIGEST:
        raise ValueError('target digest/size mismatch')


def build(data):
    authenticate(data)
    body = data[START - 0x1000:END - 0x1000]
    walk = decode(body)
    check_frame(data[FDE:FDE + 20], data[CIE:CIE + 24])
    padding = data[END - 0x1000:0x243cac0 - 0x1000]
    if padding != b'\xcc' * 5:
        raise ValueError('unexpected padding')
    callers = direct_hits(data)
    check_callers(callers)
    caller_frames = []
    for off, start, size in ((0x11568b8, 0x28cd7a0, 45860), (0x118c3e4, 0x2c47660, 23689)):
        header = data[off:off + 16]
        length, cie_delta, delta, extent = struct.unpack('<IIiI', header)
        if length < 12 or off + 8 + delta != start or extent != size:
            raise ValueError('caller FDE mismatch')
        caller_frames.append({'fde_file_offset': hex(off), 'cie_file_offset': hex(off + 4 - cie_delta),
                              'start': hex(start), 'end': hex(start + extent), 'header_bytes': header.hex()})
    # Source-location association belongs to the caller FDE, not the leaf.
    lea = data[0x28ce692 - 0x1000:0x28ce692 - 0x1000 + 7]
    if lea[:3] != bytes.fromhex('488d35') or 0x28ce699 + struct.unpack_from('<i', lea, 3)[0] != 0x6432fa0:
        raise ValueError('source-location LEA mismatch')
    if data[0x53070:0x53088] != bytes.fromhex('a02f43060000000008000000000000004bdf430000000000'):
        raise ValueError('source-location relocation mismatch')
    if data[0x6430fa0:0x6430fb8] != bytes.fromhex('000000000000000017000000000000000600000001000000') or data[0x43df4b:0x43df4b+23] != b'l1/src/qtys/impl_ntl.rs':
        raise ValueError('source-location data mismatch')
    return {
        'caller_source_association': {'caller_fde_start': '0x28cd7a0', 'caller_fde_end': '0x28d8ac4', 'lea_site': '0x28ce692', 'lea_bytes': lea.hex(), 'location': '0x6432fa0', 'relocation_file_offset': '0x53070', 'relocation_bytes': data[0x53070:0x53088].hex(), 'path': 'l1/src/qtys/impl_ntl.rs', 'line': 6, 'column': 1},
        'target': {'release': 115, 'sha256': DIGEST, 'size': len(data)},
        'window': {'start': hex(START), 'end': hex(END), 'size': len(body),
                   'file_offset': hex(START - 0x1000), 'sha256': BODY_HASH,
                   'padding': {'start': hex(END), 'end': '0x243cac0', 'bytes': padding.hex()}},
        'unwind': {'fde_file_offset': hex(FDE), 'fde_bytes': data[FDE:FDE+20].hex(),
                   'cie_file_offset': hex(CIE), 'cie_bytes': data[CIE:CIE+24].hex(),
                   'cie_augmentation': 'zR', 'fde_encoding': 'pcrel sdata4', 'lsda': None},
        'instructions': walk,
        'callees': [],
        'direct_rel32_scan': {'text_start': hex(TEXT_START), 'text_end': hex(TEXT_END),
                              'method': 'all byte offsets, e8/e9 rel32; candidates, not guaranteed boundaries',
                              'hits': callers, 'caller_fdes': caller_frames},
    }


def search(root, depth, query, nodes):
    """Model valid memory: nodes map addresses to (keys, children). Returns value address or zero."""
    if root == 0:
        return 0
    while True:
        keys, children = nodes[root]
        index = 0
        while index < len(keys) and query > keys[index]:
            index += 1
        if index < len(keys) and query == keys[index]:
            return root + 0x64
        if depth == 0:
            return 0
        depth -= 1
        root = children[index]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out', type=Path, required=True)
    parser.add_argument('--binary', type=Path, default=TARGET)
    args = parser.parse_args()
    with args.binary.open('rb') as stream, mmap.mmap(stream.fileno(), 0, access=mmap.ACCESS_READ) as data:
        record = build(data)
    # README and verifier are independently reviewed, fixed packet inputs.
    for name in ('README.md', 'verify.py'):
        if not (args.out / name).is_file():
            raise ValueError('missing packet input ' + name)
    encoded = (json.dumps(record, indent=2) + '\n').encode()
    (args.out / 'records.json').write_bytes(encoded)
    names = ('README.md', 'records.json', 'verify.py')
    manifest = ''.join(hashlib.sha256((args.out / n).read_bytes()).hexdigest() + '  ' + n + '\n' for n in names)
    (args.out / 'MANIFEST.sha256').write_text(manifest, encoding='utf-8')

if __name__ == '__main__':
    main()
