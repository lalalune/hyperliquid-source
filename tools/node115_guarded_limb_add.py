#!/usr/bin/env python3
"""Regenerate a static #115 guarded four-limb addition certificate (stdlib only)."""
import argparse
import hashlib
import json
import mmap
from pathlib import Path
import struct

from elf_index import sections
from fde_extents import eh_frame_records

ROOT = Path(__file__).resolve().parents[1]
PACKET = ROOT / 'research/work-items/RE-001-node115-guarded-limb-add'
TARGET = ROOT / 'artifacts/node/115/hl-node'
SHA = 'a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301'
BODY_SHA = '272d95480ebd94fb1aadb38d2f0a3eb1ba4d041b26947a919af5e0cc1d36061f'
START, END = 0x298f5b0, 0x298f5f9
FDE = {'fde': 0xd732d0, 'cie': 0xca6ed8, 'start': START, 'end': END, 'lsda': None}
# Exact supported instruction forms, in order. The conditional displacement is
# decoded separately; unsupported encodings fail closed rather than being guessed.
FORMS = (
 ('488b4730', 'mov rax, [rdi+0x30]'),
 ('4883f802', 'cmp rax, 2'),
 ('72', 'jb'),
 ('488b4f28', 'mov rcx, [rdi+0x28]'),
 ('48ffc8', 'dec rax'),
 ('4889c2', 'mov rdx, rax'),
 ('48c1e205', 'shl rdx, 5'),
 ('488b3411', 'mov rsi, [rcx+rdx]'),
 ('4c8b441108', 'mov r8, [rcx+rdx+8]'),
 ('4c8b4c1110', 'mov r9, [rcx+rdx+16]'),
 ('4c8b541118', 'mov r10, [rcx+rdx+24]'),
 ('48894730', 'mov [rdi+0x30], rax'),
 ('48017411e0', 'add [rcx+rdx-32], rsi'),
 ('4c114411e8', 'adc [rcx+rdx-24], r8'),
 ('4c114c11f0', 'adc [rcx+rdx-16], r9'),
 ('4c115411f8', 'adc [rcx+rdx-8], r10'),
 ('31c0', 'xor eax, eax'),
 ('c3', 'ret'),
 ('b02c', 'mov al, 0x2c'),
 ('c3', 'ret'),
)


def decode(body):
    """Strictly decode this body's supported instruction forms and branch."""
    rows, pos = [], 0
    for code, operation in FORMS:
        pattern = bytes.fromhex(code)
        if body[pos:pos + len(pattern)] != pattern:
            raise ValueError('Unsupported or changed instruction at offset %#x' % pos)
        length = len(pattern)
        row = {'address': START + pos, 'bytes': pattern.hex(), 'operation': operation}
        if operation == 'jb':
            if pos + 2 > len(body):
                raise ValueError('Truncated branch')
            displacement = struct.unpack_from('<b', body, pos + 1)[0]
            length = 2
            row['bytes'] = body[pos:pos + length].hex()
            row['target'] = START + pos + length + displacement
            if row['target'] != 0x298f5f6:
                raise ValueError('Changed branch target')
        rows.append(row)
        pos += length
    if pos != len(body):
        raise ValueError('Instruction coverage does not equal FDE extent')
    return rows


def scan_transfers(data, text_section, target=START):
    """Scan every byte offset, not only decoded instruction boundaries."""
    off, size, base = (text_section[k] for k in ('offset', 'size', 'address'))
    result = []
    for op in (0xe8, 0xe9):
        cursor = off
        while True:
            at = data.find(bytes((op,)), cursor, off + size - 4)
            if at < 0:
                break
            site = base + at - off
            if site + 5 + struct.unpack_from('<i', data, at + 1)[0] == target:
                result.append({'site': site, 'opcode': '%02x' % op, 'target': target})
            cursor = at + 1
    return sorted(result, key=lambda row: row['site'])


def collect(data, authenticate=True):
    if authenticate and hashlib.sha256(data).hexdigest() != SHA:
        raise ValueError('Node #115 digest mismatch')
    secs = sections(data)
    text = [s for s in secs if s['name'] == '.text']
    if len(text) != 1 or text[0]['address'] != 0x1419300 or text[0]['size'] != 0x63f0a00 - 0x1419300 or text[0]['flags'] & 4 == 0:
        raise ValueError('Unexpected .text mapping')
    t = text[0]
    off = t['offset'] + START - t['address']
    if off != 0x298e5b0:
        raise ValueError('Unexpected file mapping')
    body = bytes(data[off:off + END - START])
    rows = decode(body)
    if hashlib.sha256(body).hexdigest() != BODY_SHA:
        raise ValueError('Changed body')
    cies, fdes = eh_frame_records(data, secs)
    frame = next(s for s in secs if s['name'] == '.eh_frame')
    def frame_bytes(va):
        at = frame['offset'] + va - frame['address']
        length = struct.unpack_from('<I', data, at)[0] + 4
        if length < 8 or at + length > frame['offset'] + frame['size']:
            raise ValueError('Invalid frame length')
        return bytes(data[at:at + length]).hex()
    fde_raw, cie_raw = frame_bytes(FDE['fde']), frame_bytes(FDE['cie'])
    if (fde_raw != '10000000fcc30c00d8c2c1014900000000000000' or
            cie_raw != '1400000000000000017a5200017810011b0c070890010000'):
        raise ValueError('Changed FDE or CIE bytes')
    matches = [f for f in fdes if f['start'] == START]
    if matches != [FDE] or cies[FDE['cie']]['augmentation'] != 'zR':
        raise ValueError('Changed FDE or CIE')
    if any(f['start'] < END and f['end'] > START and f != FDE for f in fdes):
        raise ValueError('Overlapping FDE')
    pad = bytes(data[off + len(body):off + len(body) + 7])
    if pad != b'\xcc' * 7 or not any(f['start'] == END + len(pad) for f in fdes):
        raise ValueError('Changed following padding or FDE')
    callers = scan_transfers(data, t)
    if callers:
        raise ValueError('Unexpected direct rel32 candidate')
    rela = [s for s in secs if s['name'] == '.rela.dyn' and s['type'] == 4]
    if len(rela) != 1 or rela[0]['size'] % 24:
        raise ValueError('Unexpected relocation section')
    relocs = []
    for p in range(rela[0]['offset'], rela[0]['offset'] + rela[0]['size'], 24):
        slot, info, addend = struct.unpack_from('<QQq', data, p)
        if addend == START:
            relocs.append({'file_offset': p, 'slot': slot, 'info': info, 'addend': addend})
    if relocs != [{'file_offset': 0x61068, 'slot': 0x6441218, 'info': 8, 'addend': START},
                  {'file_offset': 0x62df0, 'slot': 0x6441f08, 'info': 8, 'addend': START}]:
        raise ValueError('Changed entry relocations')
    return {'target_sha256': SHA, 'window': {'start': START, 'end': END, 'size': len(body),
            'file_offset': off, 'body_sha256': BODY_SHA, 'fde': FDE,
            'cie': cies[FDE['cie']], 'fde_raw_hex': fde_raw, 'cie_raw_hex': cie_raw,
            'padding_hex': pad.hex()},
            'instructions': rows, 'callees': [], 'direct_rel32_candidates': callers,
            'entry_relocations': relocs,
            'counts': {'instruction_count': len(rows), 'body_bytes': len(body),
                       'padding_bytes': len(pad), 'callee_count': 0, 'caller_count': len(callers),
                       'entry_relocation_count': len(relocs),
                       'adc_count': sum(row['operation'].startswith('adc ') for row in rows)}}


def model(count, lower, upper):
    """Value-level rule, no machine state or captured code execution."""
    if not 0 <= count < 1 << 64 or not 0 <= lower < 1 << 256 or not 0 <= upper < 1 << 256:
        raise ValueError('input outside unsigned domain')
    if count < 2:
        return count, lower, 0x2c
    return count - 1, (lower + upper) % (1 << 256), 0


def render(record):
    return (json.dumps(record, indent=2) + '\n').encode()


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--out', type=Path, required=True)
    p.add_argument('--binary', type=Path, default=TARGET)
    args = p.parse_args()
    with args.binary.open('rb') as f, mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ) as data:
        record = collect(data)
    args.out.mkdir(parents=True, exist_ok=True)
    (args.out / 'records.json').write_bytes(render(record))
    # The narrative and verifier are authored boilerplate; semantic records above
    # are regenerated from the authenticated artifact, not copied.
    for name in ('README.md', 'verify.py'):
        source = PACKET / name
        dest = args.out / name
        if source.resolve() != dest.resolve():
            dest.write_bytes(source.read_bytes())
    names = ('README.md', 'records.json', 'verify.py')
    manifest = ''.join(hashlib.sha256((args.out / name).read_bytes()).hexdigest()
                       + '  ' + name + '\n' for name in names)
    (args.out / 'MANIFEST.sha256').write_text(manifest)
    print('Authenticated #115; regenerated packet')


if __name__ == '__main__':
    main()
