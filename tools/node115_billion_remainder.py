#!/usr/bin/env python3
"""Statically bind one #115 leaf; never execute the captured ELF."""
import argparse
import hashlib
import json
import mmap
from pathlib import Path
import struct

ROOT = Path(__file__).resolve().parents[1]
PACKET = ROOT / 'research/work-items/RE-001-node115-billion-remainder'
TARGET = ROOT / 'artifacts/node/115/hl-node'
DIGEST = 'a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301'
START, END = 0x63bfbc0, 0x63bfbed
TEXT_START, TEXT_END, TEXT_OFFSET = 0x1419300, 0x63f0a00, 0x1418300
FDE, CIE = 0x1037d48, 0xca6ed8
BODY_HASH = '28a0128a34a47371283b6550713075e152b3c8f3f91cd676d12b83cabf598a85'

# Complete instruction encodings. Immediates are parsed separately, not guessed
# from source: the shape is strict and the resulting operands are checked.
def decode(body):
    specs = [
        ('f30f1efa', 'endbr64'), ('48b8', 'movabs rax,imm64', 8),
        ('488b0f', 'mov rcx,[rdi]'), ('4889ca', 'mov rdx,rcx'),
        ('48c1ea', 'shr rdx,imm8', 1), ('48f7e2', 'mul rdx'),
        ('4889c8', 'mov rax,rcx'), ('48c1ea', 'shr rdx,imm8', 1),
        ('4869f2', 'imul rsi,rdx,imm32', 4), ('4829f0', 'sub rax,rsi'),
        ('c3', 'ret')]
    rows, pos = [], 0
    for spec in specs:
        prefix, name = bytes.fromhex(spec[0]), spec[1]
        n = spec[2] if len(spec) == 3 else 0
        if body[pos:pos + len(prefix)] != prefix or pos + len(prefix) + n > len(body):
            raise ValueError('unrecognized instruction or truncated body')
        end = pos + len(prefix) + n
        row = {'va': START + pos, 'bytes': body[pos:end].hex(), 'instruction': name}
        if n:
            row['immediate'] = int.from_bytes(body[pos + len(prefix):end], 'little')
        rows.append(row)
        pos = end
    if pos != len(body):
        raise ValueError('unconsumed instruction bytes')
    if [rows[i]['immediate'] for i in (1, 4, 7, 8)] != [0x44b82fa09b5a53, 9, 11, 1000000000]:
        raise ValueError('unexpected arithmetic operand')
    return rows


def frame(fde, cie):
    # This CIE is the first record in .eh_frame, with the observed zR layout.
    if cie != bytes.fromhex('1400000000000000017a5200017810011b0c070890010000'):
        raise ValueError('unexpected CIE')
    if len(fde) != 20:
        raise ValueError('bad FDE length')
    length, delta, rel, size = struct.unpack_from('<IIiI', fde)
    if (length, FDE + 4 - delta, FDE + 8 + rel, size, fde[16:]) != (16, CIE, START, END-START, b'\0'*4):
        raise ValueError('unexpected FDE')
    return {'fde_va': FDE, 'fde_file_offset': FDE, 'fde_bytes': fde.hex(),
            'cie_va': CIE, 'cie_file_offset': CIE, 'cie_bytes': cie.hex(),
            'cie_augmentation': 'zR', 'lsda': None}


def direct_target(site, data):
    if len(data) != 5 or data[0] not in (0xe8, 0xe9):
        raise ValueError('not a rel32 direct call or jump')
    return site + 5 + struct.unpack_from('<i', data, 1)[0]


def check_reference(site, data):
    if direct_target(site, data) != START:
        raise ValueError('unexpected direct-reference target')


def scan(data):
    # Scan each byte, not just presumed instruction boundaries. This includes
    # accidental opcode bytes; the two hits are separately contextualized.
    hits = []
    lo, hi = TEXT_OFFSET, TEXT_OFFSET + TEXT_END - TEXT_START
    for op in (b'\xe8', b'\xe9'):
        pos = lo
        while True:
            pos = data.find(op, pos, hi - 4)
            if pos < 0:
                break
            site = TEXT_START + pos - TEXT_OFFSET
            raw = data[pos:pos + 5]
            if direct_target(site, raw) == START:
                check_reference(site, raw)
                hits.append({'site': site, 'opcode': op.hex(), 'bytes': raw.hex(),
                             'target': START})
            pos += 1
    hits.sort(key=lambda x: x['site'])
    if [(h['site'], h['opcode']) for h in hits] != [(0x6368113, 'e8'), (0x636874e, 'e8')]:
        raise ValueError('unexpected direct-reference census')
    return hits


def checked_records(data):
    if len(data) != 105896032 or hashlib.sha256(data).hexdigest() != DIGEST:
        raise ValueError('node #115 size or digest mismatch')
    # ELF64 little-endian; validate target section geometry from the ELF table.
    if data[:16] != bytes.fromhex('7f454c46020101000000000000000000'):
        raise ValueError('unsupported ELF')
    shoff = struct.unpack_from('<Q', data, 40)[0]
    entsize, count, names_index = struct.unpack_from('<HHH', data, 58)
    if entsize != 64 or names_index >= count or shoff + count * entsize > len(data):
        raise ValueError('invalid section table')
    headers = [struct.unpack_from('<IIQQQQIIQQ', data, shoff+i*entsize) for i in range(count)]
    names = headers[names_index]
    strings = data[names[4]:names[4]+names[5]]
    found = {}
    for h in headers:
        p = h[0]
        if p >= len(strings):
            raise ValueError('bad section name')
        end = strings.find(b'\0', p)
        if end < 0:
            raise ValueError('bad section name terminator')
        name = strings[p:end]
        if name in (b'.text', b'.eh_frame'):
            if name in found:
                raise ValueError('duplicate section')
            found[name] = h
    text = found[b'.text']
    eh = found[b'.eh_frame']
    if (text[2], text[3], text[4], text[5]) != (6, TEXT_START, TEXT_OFFSET, TEXT_END-TEXT_START):
        raise ValueError('unexpected text geometry')
    if (eh[3], eh[4], eh[5]) != (CIE, CIE, 0x77137c):
        raise ValueError('unexpected frame geometry')
    raw = data[START-0x1000:END-0x1000]
    if hashlib.sha256(raw).hexdigest() != BODY_HASH:
        raise ValueError('body mismatch')
    walk = decode(raw)
    frames = frame(data[FDE:FDE+20], data[CIE:CIE+24])
    pad = data[END-0x1000:END-0x1000+3]
    if pad != b'\xcc'*3:
        raise ValueError('unexpected trailing padding')
    hits = scan(data)
    caller_fde = 16967832
    caller_raw = data[caller_fde:caller_fde+48]
    if caller_raw != bytes.fromhex('2c000000c4793800c0953305df0f000000450e108602430d06498f038e048d058c0683070379030a0c0708460b000000'):
        raise ValueError('unexpected caller FDE')
    length, delta, rel, size = struct.unpack_from('<IIiI', caller_raw)
    if (length, caller_fde+4-delta, caller_fde+8+rel, size) != (44, CIE, 0x6367e60, 0xfdf):
        raise ValueError('invalid caller FDE geometry')
    # Validate immediate call-site context without claiming the enclosing owner.
    for hit, before in zip(hits, (bytes.fromhex('4c89e7488985b0feffff'), bytes.fromhex('4c89f7488985b0feffff'))):
        off = hit['site']-0x1000
        if data[off-len(before):off] != before:
            raise ValueError('unexpected caller context')
    return {'target': {'sha256': DIGEST, 'size': len(data)},
            'function': {'start': START, 'end': END, 'size': len(raw), 'file_offset': START-0x1000,
                         'body_sha256': BODY_HASH, 'body_hex': raw.hex(), 'padding_hex': pad.hex(),
                         'instructions': walk, 'frame': frames, 'callees': []},
            'direct_references': hits,
            'direct_reference_scan': {'start': TEXT_START, 'end': TEXT_END, 'method': 'every-byte e8/e9 rel32'},
            'arithmetic': {'divisor': 1000000000, 'reduced_divisor': 1953125,
                           'multiplier': 0x44b82fa09b5a53, 'reduced_shift': 75,
                           'reciprocal_error': 399807, 'maximum_reduced_input': (1<<55)-1},
            'caller_context': {'fde_start': 0x6367e60, 'fde_end': 0x6368e3f,
                               'fde_va': caller_fde, 'fde_bytes': caller_raw.hex(),
                               'qualification': 'contextual call sites; enclosing function behavior unbound'}}


def generate(binary, out):
    with binary.open('rb') as file, mmap.mmap(file.fileno(), 0, access=mmap.ACCESS_READ) as data:
        record = checked_records(data)
    # Authenticate before creating output. Static packet companions are copied verbatim.
    out.mkdir(parents=True, exist_ok=True)
    (out/'records.json').write_text(json.dumps(record, indent=2, sort_keys=True)+'\n', encoding='utf-8')
    for name in ('README.md', 'verify.py'):
        content = (PACKET/name).read_bytes()
        (out/name).write_bytes(content)
    names = ('README.md', 'records.json', 'verify.py')
    (out/'MANIFEST.sha256').write_text(''.join(hashlib.sha256((out/n).read_bytes()).hexdigest()+'  '+n+'\n' for n in names), encoding='ascii')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary', type=Path, default=TARGET)
    parser.add_argument('--out', type=Path, required=True)
    args = parser.parse_args()
    generate(args.binary, args.out)


if __name__ == '__main__':
    main()
