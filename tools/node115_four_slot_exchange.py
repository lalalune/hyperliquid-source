#!/usr/bin/env python3
"""Static, digest-bound RE-001 evidence for one 32-byte exchange leaf."""
import argparse
import hashlib
import json
import mmap
from pathlib import Path
import struct

from elf_index import sections

ROOT = Path(__file__).resolve().parents[1]
TARGET = ROOT / 'artifacts/node/115/hl-node'
SHA = 'a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301'
START, END = 0x4333080, 0x43330c0
FDE, CIE = 0xe9cb20, 0xca6ed8
BODY_SHA = '6c697f188d25ae843793c124035ebbd19baefec1d9b9288c5dd441b826d7b25e'
FDE_BYTES = bytes.fromhex('100000004c5c1f00586549034000000000000000')
# Each row is an exact supported instruction encoding and its decoded meaning.
# Rejecting unknown bytes prevents a change in operands from being silently accepted.
ROWS = [
 ('488b4730', 'mov rax, qword [rdi+0x30]'),
 ('4883f804', 'cmp rax, 4'),
 ('7233', 'jb 0x43330bd'),
 ('488b4f28', 'mov rcx, qword [rdi+0x28]'),
 ('48c1e005', 'shl rax, 5'),
 ('0f10440180', 'movups xmm0, [rcx+rax-0x80]'),
 ('0f104c0190', 'movups xmm1, [rcx+rax-0x70]'),
 ('0f105401e0', 'movups xmm2, [rcx+rax-0x20]'),
 ('0f105c01f0', 'movups xmm3, [rcx+rax-0x10]'),
 ('0f114401e0', 'movups [rcx+rax-0x20], xmm0'),
 ('0f11540180', 'movups [rcx+rax-0x80], xmm2'),
 ('0f114c01f0', 'movups [rcx+rax-0x10], xmm1'),
 ('0f115c0190', 'movups [rcx+rax-0x70], xmm3'),
 ('31c0', 'xor eax, eax'),
 ('c3', 'ret'),
 ('b02c', 'mov al, 0x2c'),
 ('c3', 'ret'),
]


def digest(data):
    return hashlib.sha256(data).hexdigest()


def decode(body):
    """Decode this exact instruction vocabulary; assert control-flow and extent."""
    rows, pos = [], 0
    for encoded, meaning in ROWS:
        instruction = bytes.fromhex(encoded)
        if body[pos:pos + len(instruction)] != instruction:
            raise ValueError('unsupported or changed instruction at %#x' % (START + pos))
        if instruction[0] == 0x72:
            target = START + pos + 2 + struct.unpack('<b', instruction[1:])[0]
            if target != 0x43330bd:
                raise ValueError('branch target changed')
        rows.append({'va': START + pos, 'bytes_hex': encoded, 'instruction': meaning})
        pos += len(instruction)
    if pos != len(body) or pos != END - START or digest(body) != BODY_SHA:
        raise ValueError('body extent or hash changed')
    return rows


def check_frame(raw):
    if raw != FDE_BYTES:
        raise ValueError('FDE changed')
    length, delta, relative, size = struct.unpack_from('<IIiI', raw)
    if length + 4 != len(raw) or FDE + 4 - delta != CIE or FDE + 8 + relative != START or size != END - START or raw[16] != 0:
        raise ValueError('FDE binding changed')


def check_relocation(raw, slot):
    if len(raw) != 24 or struct.unpack('<QQq', raw) != (slot, 8, START):
        raise ValueError('relative relocation changed')


def scan_rel32(image, text_section):
    """Every byte offset, including possible non-instruction candidates."""
    hits = []
    base, offset, size = (text_section[k] for k in ('address', 'offset', 'size'))
    for opcode in (0xe8, 0xe9):
        pos = offset
        while True:
            pos = image.find(bytes([opcode]), pos, offset + size - 4)
            if pos < 0:
                break
            va = base + pos - offset
            dest = va + 5 + struct.unpack_from('<i', image, pos + 1)[0]
            if dest == START:
                hits.append({'site': va, 'opcode': '%02x' % opcode, 'target': dest})
            pos += 1
    return sorted(hits, key=lambda row: row['site'])


def inspect(image, authenticate=True):
    if authenticate and digest(image) != SHA:
        raise ValueError('node #115 digest mismatch')
    ss = sections(image)
    texts = [s for s in ss if s['name'] == '.text' and s['flags'] & 4]
    if len(texts) != 1 or (texts[0]['address'], texts[0]['size']) != (0x1419300, 0x63f0a00 - 0x1419300):
        raise ValueError('unexpected .text')
    text = texts[0]
    off = text['offset'] + START - text['address']
    body = image[off:off + END - START]
    instructions = decode(body)
    raw_fde = image[FDE:FDE + len(FDE_BYTES)]
    check_frame(raw_fde)
    cie = image[CIE:CIE + 24]
    if cie != bytes.fromhex('1400000000000000017a5200017810011b0c070890010000'):
        raise ValueError('CIE changed')
    if image[off - 4:off] != b'\xcc' * 4:
        raise ValueError('preceding padding changed')
    next_fde = image[FDE + 20:FDE + 40]
    if next_fde != bytes.fromhex('10000000605c1f00846549034c00000000000000'):
        raise ValueError('adjacent FDE changed')
    if FDE + 28 + struct.unpack_from('<i', next_fde, 8)[0] != END:
        raise ValueError('adjacent FDE start changed')
    relocs = []
    for roff, slot in ((0xb4900, 0x6486388), (0xb6730, 0x64870f0)):
        raw = image[roff:roff + 24]
        check_relocation(raw, slot)
        relocs.append({'file_offset': roff, 'slot_va': slot, 'type': 8, 'addend': START, 'bytes_hex': raw.hex()})
    return {'target_sha256': SHA, 'coordinate_system': 'ELF virtual address unless file offset specified',
            'window': {'start': START, 'end': END, 'size': len(body), 'file_offset': off,
                       'body_sha256': digest(body), 'body_hex': body.hex(),
                       'preceding_padding_hex': image[off - 4:off].hex(), 'following_padding_hex': ''},
            'fde': {'file_offset': FDE, 'cie_file_offset': CIE, 'bytes_hex': raw_fde.hex(),
                    'cie_bytes_hex': cie.hex(), 'start': START, 'end': END, 'lsda': None,
                    'next_fde_file_offset': FDE + 20, 'next_fde_bytes_hex': next_fde.hex(),
                    'next_fde_start': END},
            'instructions': instructions, 'callees': [], 'direct_rel32_candidates': scan_rel32(image, text),
            'relative_relocations': relocs}


def model(items):
    """Independent sequence model: copies inputs and returns low status byte."""
    result = list(items)
    if len(result) < 4:
        return result, 0x2c
    result[-4], result[-1] = result[-1], result[-4]
    return result, 0


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--out', required=True, type=Path)
    ap.add_argument('--binary', default=TARGET, type=Path)
    args = ap.parse_args()
    with args.binary.open('rb') as f, mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ) as image:
        record = inspect(image)
    args.out.mkdir(parents=True, exist_ok=True)
    (args.out / 'records.json').write_text(json.dumps(record, indent=2) + '\n', encoding='utf-8')


if __name__ == '__main__':
    main()
