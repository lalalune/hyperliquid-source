#!/usr/bin/env python3
"""Digest-bound static decoder for node #94's two field-name tags."""
import argparse
import hashlib
import json
import mmap
from pathlib import Path
import struct

DIGEST = '3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f'
START, END = 0x3325860, 0x33258c2
FDE = 0x114848
# Complete instruction encodings; branches and RIP-relative operands are decoded
# below, not inferred from assembler labels. Unknown or altered bytes fail closed.
OPS = [
 ('4889f8','mov rax, rdi'), ('4883fa15','cmp rdx, 21'), ('741e','je'),
 ('4883fa08','cmp rdx, 8'), ('7541','jne'),
 ('48b96170705f68617368','mov rcx, little-endian "app_hash"'),
 ('48390e','cmp qword [rsi], rcx'), ('7532','jne'), ('31c9','xor ecx, ecx'),
 ('884801','mov [rax+1], cl'), ('c60009','mov byte [rax], 9'), ('c3','ret'),
 ('f30f6f06','movdqu xmm0, [rsi]'), ('f30f6f4e05','movdqu xmm1, [rsi+5]'),
 ('660f740de8e2edfc','pcmpeqb xmm1, [rip+disp32]'),
 ('660f74052013eefc','pcmpeqb xmm0, [rip+disp32]'),
 ('660fdbc1','pand xmm0, xmm1'), ('660fd7c8','pmovmskb ecx, xmm0'),
 ('81f9ffff0000','cmp ecx, 0xffff'), ('7409','je'),
 ('b102','mov cl, 2'), ('884801','mov [rax+1], cl'), ('c60009','mov byte [rax], 9'), ('c3','ret'),
 ('b101','mov cl, 1'), ('884801','mov [rax+1], cl'), ('c60009','mov byte [rax], 9'), ('c3','ret')]


def decode(blob, start=START):
    """Recognize the complete instruction stream; return walk and references."""
    pos = 0
    walk, branches, refs = [], [], []
    for encoded, desc in OPS:
        expected = bytes.fromhex(encoded)
        actual = blob[pos:pos + len(expected)]
        if actual != expected:
            raise ValueError('instruction mismatch at %#x' % (start + pos))
        site = start + pos
        if actual[0] in (0x74, 0x75):
            target = site + 2 + struct.unpack('<b', actual[1:])[0]
            branches.append({'site': hex(site), 'target': hex(target), 'condition': desc})
            desc += ' ' + hex(target)
        if actual[:3] == bytes.fromhex('660f74'):
            target = site + len(actual) + struct.unpack('<i', actual[-4:])[0]
            refs.append(target)
            desc += ' = ' + hex(target)
        walk.append('%#x  %-20s %s' % (site, actual.hex(), desc))
        pos += len(actual)
    if pos != len(blob):
        raise ValueError('instruction stream extent mismatch')
    if {int(b['target'], 16) for b in branches} - {start + sum(len(bytes.fromhex(x[0])) for x in OPS[:i]) for i in range(len(OPS))}:
        raise ValueError('branch outside instruction boundaries')
    return walk, branches, refs


def sections(data):
    if data[:6] != b'\x7fELF\x02\x01':
        raise ValueError('not ELF64 little endian')
    shoff = struct.unpack_from('<Q', data, 0x28)[0]
    entsize, count, names_idx = struct.unpack_from('<HHH', data, 0x3a)
    if entsize != 64 or names_idx >= count:
        raise ValueError('bad ELF section table')
    def sh(i): return struct.unpack_from('<IIQQQQIIQQ', data, shoff + i * entsize)
    names = sh(names_idx); table = data[names[4]:names[4]+names[5]]
    result = {}
    for i in range(count):
        row = sh(i); n = row[0]; end = table.find(b'\0', n)
        if end < 0: raise ValueError('bad section name')
        result[table[n:end].decode('ascii')] = {'va': row[3], 'offset': row[4], 'size': row[5]}
    return result


def view(data, sec, va, size):
    offset = va - sec['va']
    if offset < 0 or size < 0 or offset + size > sec['size']:
        raise ValueError('address outside section')
    return data[sec['offset']+offset:sec['offset']+offset+size]


def read_fde(data, eh, relative=FDE):
    if relative < 0 or relative + 16 > eh['size']: raise ValueError('FDE outside section')
    off = eh['offset'] + relative
    length, cie_delta, delta, size = struct.unpack_from('<IIiI', data, off)
    pc = eh['va'] + relative + 8 + delta
    cie = relative + 4 - cie_delta
    if (length, cie, pc, size) != (16, 0, START, END-START):
        raise ValueError('FDE identity mismatch')
    return {'section_offset': hex(relative), 'cie_section_offset': hex(cie), 'length': length,
            'start': hex(pc), 'end_exclusive': hex(pc + size)}


def decode_call(site, raw):
    if len(raw) != 5 or raw[0] != 0xe8:
        raise ValueError('invalid direct call')
    return site + 5 + struct.unpack_from('<i', raw, 1)[0]


def census(data, text, target=START):
    begin, end = text['offset'], text['offset'] + text['size']
    result = {'e8': [], 'e9': []}
    for opcode in (0xe8, 0xe9):
        p = begin
        while True:
            p = data.find(bytes([opcode]), p, end-4)
            if p < 0: break
            va = text['va'] + p - begin
            if va + 5 + struct.unpack_from('<i', data, p+1)[0] == target:
                result[hex(opcode)[2:]].append(hex(va))
            p += 1
    return result


def analyze(data, expected_digest=DIGEST, fde_offset=FDE, target=START):
    if hashlib.sha256(data).hexdigest() != expected_digest or expected_digest != DIGEST:
        raise ValueError('target digest mismatch')
    sec = sections(data); text, eh = sec['.text'], sec['.eh_frame']
    body = view(data, text, START, END-START)
    walk, branches, refs = decode(body)
    if refs != [0x203b80, 0x206bc0]: raise ValueError('constant target mismatch')
    # These constants are in a separate ELF section; verify address mapping.
    def read_va(va, size):
        for section in sec.values():
            if section['va'] <= va and va + size <= section['va'] + section['size']:
                return view(data, section, va, size)
        raise ValueError('unmapped constant')
    c1, c0 = (read_va(addr, 16) for addr in refs)
    if c0 != b'hot_user_to_sign' or c1 != b'ser_to_signature' or c0[5:] != c1[:11]:
        raise ValueError('constant mismatch')
    padding = view(data, text, END, 14)
    if padding != b'\xcc' * 14: raise ValueError('padding mismatch')
    fde = read_fde(data, eh, fde_offset)
    off = eh['offset'] + 0x11485c
    length, cie_delta, delta, size = struct.unpack_from('<IIiI', data, off)
    next_start = eh['va'] + 0x11485c + 8 + delta
    if (length, 0x11485c + 4 - cie_delta, next_start, size) != (16, 0, 0x33258d0, 0xf9):
        raise ValueError('next FDE mismatch')
    context = view(data, text, 0x2cb05fb, 34)
    if context != bytes.fromhex('488bb42438010000488b942440010000488dbc24e0000000e848526700e959010000'):
        raise ValueError('caller instruction context mismatch')
    if decode_call(0x2cb0613, context[24:29]) != START:
        raise ValueError('caller target mismatch')
    callers = census(data, text, target)
    if target != START or callers != {'e8': ['0x2cb0613'], 'e9': []}:
        raise ValueError('caller target or census mismatch')
    result = {'target': {'release': 'node #94', 'sha256': DIGEST, 'size': len(data)},
      'function': {'start': hex(START), 'end_exclusive': hex(END), 'size': len(body),
                   'sha256': hashlib.sha256(body).hexdigest(), 'padding_bytes': len(padding),
                   'padding_byte': 'cc', 'fde': fde,
                   'next_fde': {'section_offset': '0x11485c', 'start': hex(next_start), 'end_exclusive': hex(next_start + size)}},
      'constants': [{'address': hex(refs[0]), 'bytes_hex': c1.hex()}, {'address': hex(refs[1]), 'bytes_hex': c0.hex()}],
      'branches': branches, 'callees': [], 'caller_census': callers,
      'rule': {'output_prefix': 9, 'tags': {'app_hash': 0, 'hot_user_to_signature': 1}, 'fallback': 2,
               'return': 'output pointer'},
      'scan': {'section': '.text', 'start': hex(text['va']), 'end_exclusive': hex(text['va']+text['size']),
               'method': 'all byte offsets, unprefixed e8/e9 rel32 candidates'}}
    return result, walk


def model(name):
    return bytes((9, {b'app_hash': 0, b'hot_user_to_signature': 1}.get(name, 2)))


def main():
    ap = argparse.ArgumentParser(); ap.add_argument('--binary', default='artifacts/node/94/hl-node'); ap.add_argument('--out', required=True)
    args = ap.parse_args(); out = Path(args.out)
    with open(args.binary, 'rb') as f, mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ) as data:
        record, walk = analyze(data)
    out.mkdir(parents=True, exist_ok=True)
    (out/'records.json').write_text(json.dumps(record, indent=2) + '\n')
    (out/'instructions.txt').write_text('\n'.join(walk) + '\n')
    names = ('README.md', 'instructions.txt', 'records.json', 'verify.py')
    if all((out/name).is_file() for name in names):
        (out/'MANIFEST.sha256').write_text(''.join(hashlib.sha256((out/name).read_bytes()).hexdigest() + '  ' + name + '\n' for name in names))
    print('decoded', record['function']['size'], 'bytes')

if __name__ == '__main__': main()
