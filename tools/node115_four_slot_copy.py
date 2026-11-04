#!/usr/bin/env python3
"""Bind one #115 leaf from ELF bytes, without executing or disassembling it."""
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
START, END = 0x50b4950, 0x50b498a
FDE, CIE = 0xf4eb80, 0xca6ed8  # checked against parsed records below
SLOT = 0x649f2b8

# Exact instruction forms, with immediate fields decoded and checked separately.
# This deliberately rejects encodings other than the observed forms.
FORMS = [
 ('488b4730', 'mov rax, [rdi+0x30]'),
 ('488d48fc', 'lea rcx, [rax-4]'),
 ('4881f9fb030000', 'cmp rcx, 0x3fb'),
 ('7726', 'ja 0x50b4987'),
 ('488d4801', 'lea rcx, [rax+1]'),
 ('488b5728', 'mov rdx, [rdi+0x28]'),
 ('48c1e005', 'shl rax, 5'),
 ('0f10440280', 'movups xmm0, [rdx+rax-0x80]'),
 ('0f104c0290', 'movups xmm1, [rdx+rax-0x70]'),
 ('0f114c0210', 'movups [rdx+rax+0x10], xmm1'),
 ('0f110402', 'movups [rdx+rax], xmm0'),
 ('48894f30', 'mov [rdi+0x30], rcx'),
 ('31c0', 'xor eax, eax'),
 ('c3', 'ret'),
 ('b02d', 'mov al, 0x2d'),
 ('c3', 'ret'),
]


def decode(body):
    """Strictly match each entire instruction and validate the sole branch target."""
    pos = 0
    rows = []
    for raw, text in FORMS:
        code = bytes.fromhex(raw)
        if body[pos:pos + len(code)] != code:
            raise ValueError('instruction encoding changed at %#x' % (START + pos))
        if code[0] == 0x77 and START + pos + 2 + struct.unpack('b', code[1:])[0] != 0x50b4987:
            raise ValueError('branch target changed')
        rows.append({'address': START + pos, 'bytes': code.hex(), 'instruction': text})
        pos += len(code)
    if pos != len(body):
        raise ValueError('incomplete instruction coverage')
    return rows


def direct_refs(data, text, target=START):
    """Scan every byte, including unaligned bytes; candidates are not proven callers."""
    lo, hi = text['offset'], text['offset'] + text['size']
    out = []
    for opcode in (b'\xe8', b'\xe9'):
        p = lo
        while True:
            p = data.find(opcode, p, hi - 4)
            if p < 0:
                break
            va = text['address'] + p - lo
            dest = va + 5 + struct.unpack_from('<i', data, p + 1)[0]
            if dest == target:
                out.append({'address': va, 'opcode': opcode.hex(), 'target': dest})
            p += 1
    return sorted(out, key=lambda x: x['address'])


def inspect(data, authenticate=True):
    if authenticate and hashlib.sha256(data).hexdigest() != SHA:
        raise ValueError('node #115 digest mismatch')
    secs = sections(data)
    text = next(s for s in secs if s['name'] == '.text')
    if (text['address'], text['size'], text['offset'], text['flags']) != (0x1419300, 0x4fd7700, 0x1418300, 6):
        raise ValueError('unexpected text geometry')
    cies, fdes = eh_frame_records(data, secs)
    matching = [f for f in fdes if f['start'] == START]
    if matching != [{'fde': FDE, 'cie': CIE, 'start': START, 'end': END, 'lsda': None}]:
        raise ValueError('FDE changed')
    cie = cies[CIE]
    if cie['augmentation'] != 'zR' or cie['fde_encoding'] != 0x1b:
        raise ValueError('CIE changed')
    off = text['offset'] + START - text['address']
    body = bytes(data[off:off + END - START])
    instructions = decode(body)
    padding = bytes(data[off + len(body):off + len(body) + 6])
    if padding != b'\xcc' * 6:
        raise ValueError('padding changed')
    # The relocation is a RELA record: r_offset, r_info, signed addend.
    rela = next(s for s in secs if s['name'] == '.rela.dyn')
    matches = []
    for p in range(rela['offset'], rela['offset'] + rela['size'], 24):
        dest, info, addend = struct.unpack_from('<QQq', data, p)
        if dest == SLOT:
            matches.append((info, addend))
    if matches != [(8, START)]:
        raise ValueError('relative relocation target changed')
    callers = direct_refs(data, text)
    return {'target_sha256': SHA, 'window': {'start': START, 'end': END,
            'file_offset': off, 'size': len(body), 'body_sha256': hashlib.sha256(body).hexdigest(),
            'fde': matching[0], 'cie_augmentation': cie['augmentation'], 'padding_hex': padding.hex()},
            'instructions': instructions, 'callees': [], 'direct_rel32_candidates': callers,
            'relocation': {'slot': SLOT, 'type': 'R_X86_64_RELATIVE', 'addend': START},
            'rule': {'minimum_index': 4, 'maximum_index': 1023, 'slot_size': 32,
                     'source_slots_back': 4, 'failure_al': 45, 'success_al': 0}}


def model(index, slots):
    """Independent raw-slot model; returns status and updated list without mutation."""
    if not 0 <= index < 2**64:
        raise ValueError('index must be u64')
    result = list(slots)
    if index < 4 or index > 1023:
        return 45, index, result
    if len(result) <= index or any(len(x) != 32 for x in result):
        raise ValueError('need complete 32-byte slots through index')
    result[index] = result[index - 4]
    return 0, index + 1, result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out', required=True, type=Path)
    parser.add_argument('--target', default=TARGET, type=Path)
    args = parser.parse_args()
    with args.target.open('rb') as f, mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ) as data:
        record = inspect(data)
    args.out.mkdir(parents=True, exist_ok=True)
    (args.out / 'records.json').write_text(json.dumps(record, indent=2) + '\n')


if __name__ == '__main__':
    main()
