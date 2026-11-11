#!/usr/bin/env python3
"""Bind one byte-prefix step from node #115 without executing the capture."""
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
START, END, FDE, CIE = 0x5434bb0, 0x5434c2f, 0xf7dfbc, 0xca6ed8
DESCRIPTOR = 0x64b0270
CALLERS = (0x534f9b1, 0x534fb6b, 0x534ff57, 0x5350475)
# Complete ordered encodings, including all branch and data-displacement bytes.
FORMS = [
 ('488b4618','mov rax, [rsi+0x18]'), ('4885c0','test rax, rax'),
 ('7421','je 0x5434bda'), ('488b5610','mov rdx, [rsi+0x10]'),
 ('48ffc8','dec rax'), ('0fb60a','movzx ecx, byte [rdx]'),
 ('48ffc2','inc rdx'), ('48895610','mov [rsi+0x10], rdx'),
 ('48894618','mov [rsi+0x18], rax'), ('b002','mov al, 2'),
 ('84c9','test cl, cl'), ('780a','js 0x5434bde'),
 ('31d2','xor edx, edx'), ('89ce','mov esi, ecx'), ('eb40','jmp 0x5434c1a'),
 ('31c0','xor eax, eax'), ('eb3c','jmp 0x5434c1a'),
 ('b2e0','mov dl, 0xe0'), ('80f9df','cmp cl, 0xdf'), ('7604','jbe 0x5434be9'),
 ('89ce','mov esi, ecx'), ('eb31','jmp 0x5434c1a'),
 ('80f990','cmp cl, 0x90'), ('7309','jae 0x5434bf7'),
 ('80e10f','and cl, 0x0f'), ('b280','mov dl, 0x80'),
 ('89ce','mov esi, ecx'), ('eb23','jmp 0x5434c1a'),
 ('80f9a0','cmp cl, 0xa0'), ('7309','jae 0x5434c05'),
 ('80e10f','and cl, 0x0f'), ('b290','mov dl, 0x90'),
 ('89ce','mov esi, ecx'), ('eb15','jmp 0x5434c1a'),
 ('89ce','mov esi, ecx'), ('4080e61f','and sil, 0x1f'),
 ('b2a0','mov dl, 0xa0'), ('80f9c0','cmp cl, 0xc0'),
 ('7208','jb 0x5434c1a'), ('89ca','mov edx, ecx'),
 ('7504','jne 0x5434c1a'), ('c60709','mov byte [rdi], 9'), ('c3','ret'),
 ('8807','mov byte [rdi], al'), ('885701','mov byte [rdi+1], dl'),
 ('40887702','mov byte [rdi+2], sil'), ('488d0546b60701','lea rax, [rip+0x107b646]'),
 ('48894708','mov [rdi+8], rax'), ('c3','ret'),
]


def decode(body):
    rows, pos, branch_targets = [], 0, []
    for raw, instruction in FORMS:
        code = bytes.fromhex(raw)
        if body[pos:pos + len(code)] != code:
            raise ValueError('instruction changed at %#x' % (START + pos))
        va = START + pos
        if code[0] in (0x72, 0x73, 0x74, 0x75, 0x76, 0x78, 0xeb):
            dest = va + 2 + struct.unpack('b', code[1:])[0]
            if instruction.split()[-1] != hex(dest):
                raise ValueError('branch target changed')
            branch_targets.append(dest)
        if code[:3] == b'\x48\x8d\x05':
            if va + len(code) + struct.unpack('<i', code[3:])[0] != DESCRIPTOR:
                raise ValueError('descriptor target changed')
        rows.append({'address': va, 'bytes': code.hex(), 'instruction': instruction})
        pos += len(code)
    if pos != len(body) or not set(branch_targets).issubset({r['address'] for r in rows}):
        raise ValueError('incomplete body or branch into instruction')
    return rows


def direct_refs(data, text):
    lo, hi = text['offset'], text['offset'] + text['size']
    result = []
    for op in (b'\xe8', b'\xe9'):
        pos = lo
        while True:
            pos = data.find(op, pos, hi - 4)
            if pos < 0:
                break
            va = text['address'] + pos - lo
            if va + 5 + struct.unpack_from('<i', data, pos + 1)[0] == START:
                result.append({'address': va, 'bytes': bytes(data[pos:pos+5]).hex(),
                               'opcode': op.hex(), 'target': START})
            pos += 1
    return sorted(result, key=lambda x: x['address'])


def inspect(data, authenticate=True):
    if authenticate and hashlib.sha256(data).hexdigest() != SHA:
        raise ValueError('node #115 digest mismatch')
    secs = sections(data)
    text = next(s for s in secs if s['name'] == '.text')
    if (text['address'], text['size'], text['offset'], text['flags']) != (0x1419300, 0x4fd7700, 0x1418300, 6):
        raise ValueError('unexpected text geometry')
    cies, fdes = eh_frame_records(data, secs)
    matches = [f for f in fdes if f['start'] == START]
    if matches != [{'fde': FDE, 'cie': CIE, 'start': START, 'end': END, 'lsda': None}]:
        raise ValueError('FDE changed')
    cie = cies[CIE]
    if cie['augmentation'] != 'zR' or cie['fde_encoding'] != 0x1b:
        raise ValueError('CIE changed')
    frame = next(s for s in secs if s['name'] == '.eh_frame')
    def frame_record(va):
        p = frame['offset'] + va - frame['address']
        length = struct.unpack_from('<I', data, p)[0]
        return bytes(data[p:p+4+length]).hex()
    off = text['offset'] + START - text['address']
    body = bytes(data[off:off+END-START])
    digest = hashlib.sha256(body).hexdigest()
    if digest != '4a021dbd4e8c12f7758be77760ec0e777966aaf3de048ed2fbda0f3e27c1e4ec':
        raise ValueError('body digest changed')
    rows = decode(body)
    padding = bytes(data[off+len(body):off+len(body)+1])
    if padding != b'\xcc':
        raise ValueError('padding changed')
    refs = direct_refs(data, text)
    if tuple(r['address'] for r in refs) != CALLERS or any(r['opcode'] != 'e8' for r in refs):
        raise ValueError('direct-reference census changed')
    return {'target_sha256': SHA, 'window': {'start': START, 'end': END, 'size': len(body),
            'file_offset': off, 'body_sha256': digest, 'fde': matches[0],
            'fde_bytes': frame_record(FDE), 'cie_bytes': frame_record(CIE),
            'cie_augmentation': cie['augmentation'], 'padding_hex': padding.hex()},
            'instructions': rows, 'callees': [], 'direct_rel32_candidates': refs,
            'descriptor_address': DESCRIPTOR,
            'rule': {'empty_tag': 0, 'nonempty_tag': 2, 'special_input': 192,
                     'special_tag': 9, 'input_cursor_offset': 16, 'input_count_offset': 24,
                     'output_descriptor_offset': 8}}


def model(byte):
    """Return the definite output writes (offset -> byte or descriptor VA)."""
    if byte is None:
        return {0: 0, 8: DESCRIPTOR}  # +1/+2 are incoming register bytes
    if not isinstance(byte, int) or not 0 <= byte <= 255:
        raise ValueError('expected a byte or None')
    if byte == 0xc0:
        return {0: 9}
    if byte < 0x80:
        x, y = 0, byte
    elif byte < 0x90:
        x, y = 0x80, byte & 15
    elif byte < 0xa0:
        x, y = 0x90, byte & 15
    elif byte < 0xc0:
        x, y = 0xa0, byte & 31
    elif byte <= 0xdf:
        x, y = byte, byte & 31
    else:
        x, y = 0xe0, byte
    return {0: 2, 1: x, 2: y, 8: DESCRIPTOR}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out', required=True, type=Path)
    parser.add_argument('--target', default=TARGET, type=Path)
    args = parser.parse_args()
    with args.target.open('rb') as f, mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ) as data:
        record = inspect(data)
    source = ROOT / 'research/work-items/RE-001-node115-byte-prefix-step'
    static = {name: (source / name).read_bytes() for name in ('README.md', 'verify.py')}
    args.out.mkdir(parents=True, exist_ok=True)
    (args.out / 'records.json').write_text(json.dumps(record, indent=2) + '\n', encoding='utf-8')
    for name, contents in static.items():
        (args.out / name).write_bytes(contents)
    names = ('README.md', 'records.json', 'verify.py')
    manifest = ''.join(hashlib.sha256((args.out / name).read_bytes()).hexdigest() + '  ' + name + '\n' for name in names)
    (args.out / 'MANIFEST.sha256').write_text(manifest, encoding='ascii')


if __name__ == '__main__':
    main()
