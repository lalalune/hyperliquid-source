#!/usr/bin/env python3
"""Digest-bound, static RE-001 field-name dispatch evidence; Python 3.10+."""
import argparse
import hashlib
import json
import mmap
from pathlib import Path
import struct

ROOT = Path(__file__).resolve().parents[1]
BINARY = ROOT / 'artifacts/node/94/hl-node'
DIGEST = '3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f'
START, END, NEXT = 0x42c5340, 0x42c538e, 0x42c5390
BODY_SHA = 'de7739862640e67242ed231fb437a48881b3f0fea327a69059735275ea78b7a8'
FDE_OFFSET = 0x1de34c
CALLER = 0x40e8ef8

# Exact opcode/operand encodings form a deliberately narrow decoder. Relative
# branches are decoded separately and validated against their expected targets.
WALK = [
 ('4889f8','mov rax, rdi'), ('4883fa06','cmp rdx, 6'),
 ('74','je 0x42c5367',0x42c5367), ('4883fa08','cmp rdx, 8'),
 ('75','jne 0x42c537c',0x42c537c),
 ('48b96f726465725f737a','mov rcx, 0x7a735f726564726f'),
 ('48390e','cmp qword [rsi], rcx'), ('75','jne 0x42c537c',0x42c537c),
 ('31c9','xor ecx, ecx'), ('884801','mov byte [rax+1], cl'),
 ('c60009','mov byte [rax], 9'), ('c3','ret'),
 ('b9706f696e','mov ecx, 0x6e696f70'), ('330e','xor ecx, dword [rsi]'),
 ('0fb75604','movzx edx, word [rsi+4]'), ('81f274730000','xor edx, 0x7374'),
 ('09ca','or edx, ecx'), ('74','je 0x42c5385',0x42c5385),
 ('b102','mov cl, 2'), ('884801','mov byte [rax+1], cl'),
 ('c60009','mov byte [rax], 9'), ('c3','ret'),
 ('b101','mov cl, 1'), ('884801','mov byte [rax+1], cl'),
 ('c60009','mov byte [rax], 9'), ('c3','ret'),
]


def decode_rel(raw, site, opcode, target):
    size = 2 if opcode in (0x74, 0x75) else 5
    if len(raw) != size or raw[0] != opcode:
        raise ValueError('invalid relative instruction')
    disp = int.from_bytes(raw[1:], 'little', signed=True)
    actual = site + size + disp
    if actual != target:
        raise ValueError('unexpected relative target')
    return actual


def decode(body):
    pos, lines, branches = 0, [], []
    for item in WALK:
        encoded = bytes.fromhex(item[0])
        size = 2 if len(item) == 3 else len(encoded)
        raw = body[pos:pos + size]
        if len(item) == 3:
            decode_rel(raw, START + pos, encoded[0], item[2])
            branches.append({'site': START + pos, 'target': item[2]})
        elif raw != encoded:
            raise ValueError('unsupported or altered instruction at %#x' % (START + pos))
        lines.append((START + pos, raw.hex(), item[1]))
        pos += size
    if pos != len(body) or START + pos != END:
        raise ValueError('instruction window extent mismatch')
    return lines, branches


def sections(data):
    if data[:6] != b'\x7fELF\x02\x01':
        raise ValueError('expected ELF64 little endian')
    off = struct.unpack_from('<Q', data, 0x28)[0]
    entsize, count, stridx = struct.unpack_from('<HHH', data, 0x3a)
    if entsize != 64 or not 0 < stridx < count or off + count * entsize > len(data):
        raise ValueError('invalid section table')
    def entry(i):
        return struct.unpack_from('<IIQQQQIIQQ', data, off + i * entsize)
    names = entry(stridx)
    name_off, name_size = names[4], names[5]
    if name_off + name_size > len(data):
        raise ValueError('invalid string table')
    result = {}
    for i in range(count):
        e = entry(i)
        p = name_off + e[0]
        if p >= name_off + name_size:
            raise ValueError('invalid section name')
        end = data.find(b'\0', p, name_off + name_size)
        if end < 0: raise ValueError('unterminated section name')
        name = data[p:end].decode('ascii')
        if name in ('.text', '.eh_frame'):
            if name in result or e[4] + e[5] > len(data):
                raise ValueError('duplicate or truncated section')
            result[name] = {'va': e[3], 'offset': e[4], 'size': e[5]}
    if set(result) != {'.text', '.eh_frame'}: raise ValueError('missing sections')
    return result


def frame_check(data, frame, offset=FDE_OFFSET):
    if offset != FDE_OFFSET: raise ValueError('unexpected FDE offset')
    p = frame['offset'] + offset
    if data[frame['offset']:frame['offset'] + 24] != bytes.fromhex('1400000000000000017a5200017810011b0c070890010000'):
        raise ValueError('unexpected CIE')
    raw = data[p:p+20]
    if len(raw) != 20: raise ValueError('truncated FDE')
    length, delta, rel, extent = struct.unpack_from('<IIiI', raw)
    if (length != 16 or p + 4 - delta != frame['offset'] or
            frame['va'] + offset + 8 + rel != START or extent != END - START or
            raw[16:] != b'\0\0\0\0'):
        raise ValueError('FDE association mismatch')
    raw = data[p+20:p+40]
    if len(raw) != 20: raise ValueError('truncated next FDE')
    length, delta, rel, extent = struct.unpack_from('<IIiI', raw)
    if (length != 16 or p + 24 - delta != frame['offset'] or
            frame['va'] + offset + 28 + rel != NEXT or extent != 323 or raw[16:] != b'\0\0\0\0'):
        raise ValueError('next FDE association mismatch')


def scan(data, section):
    start, stop, va = section['offset'], section['offset'] + section['size'], section['va']
    result = {'calls': [], 'jumps': []}
    for opcode, key in ((0xe8, 'calls'), (0xe9, 'jumps')):
        cursor = start
        while True:
            p = data.find(bytes([opcode]), cursor, stop)
            if p < 0: break
            if p + 5 <= stop:
                site = va + p - start
                if site + 5 + struct.unpack_from('<i', data, p + 1)[0] == START:
                    result[key].append(site)
            cursor = p + 1
    return result


def analyze(data, digest=DIGEST):
    if hashlib.sha256(data).hexdigest() != digest or digest != DIGEST:
        raise ValueError('target digest mismatch')
    sec = sections(data); text, frame = sec['.text'], sec['.eh_frame']
    if not text['va'] <= START < NEXT <= text['va'] + text['size']:
        raise ValueError('window outside .text')
    frame_check(data, frame)
    off = text['offset'] + START - text['va']
    body = data[off:off + END - START]
    if hashlib.sha256(body).hexdigest() != BODY_SHA: raise ValueError('body hash mismatch')
    lines, branches = decode(body)
    if data[off + len(body):off + NEXT - START] != b'\xcc\xcc': raise ValueError('padding mismatch')
    incoming = scan(data, text)
    if incoming != {'calls': [CALLER], 'jumps': []}: raise ValueError('incoming census mismatch')
    calloff = text['offset'] + CALLER - text['va']
    decode_rel(data[calloff:calloff+5], CALLER, 0xe8, START)
    rec = {'target_sha256': DIGEST, 'coordinate_system': 'ELF virtual address',
           'window': {'start': START, 'end_exclusive': END, 'size': END - START,
                      'file_offset': off, 'body_sha256': BODY_SHA, 'fde_section_offset': FDE_OFFSET,
                      'cie_section_offset': 0, 'next_fde_start': NEXT, 'padding_hex': 'cccc'},
           'branches': branches, 'direct_callees': [], 'indirect_callees': [],
           'incoming_rel32_byte_candidates': incoming,
           'rule': {'output_byte_0': 9, 'output_byte_1': {'order_sz': 0, 'points': 1, 'other': 2},
                    'returned_pointer': 'rdi'},
           'vectors': [{'input_hex': v.hex(), 'result_hex': bytes((9, classify(v))).hex()} for v in
                       (b'order_sz', b'points', b'', b'order_sZ', b'point', b'points\0', b'\0'*8)]}
    return rec, lines


def classify(value):
    return 0 if value == b'order_sz' else 1 if value == b'points' else 2


def records_bytes(rec):
    return (json.dumps(rec, indent=2, sort_keys=True) + '\n').encode()


def manifest_bytes(path):
    names = ('README.md', 'records.json', 'verify.py')
    return ''.join(hashlib.sha256((path / n).read_bytes()).hexdigest() + '  ' + n + '\n' for n in names).encode()


def main():
    parser = argparse.ArgumentParser(); parser.add_argument('--out', type=Path, required=True)
    args = parser.parse_args()
    with BINARY.open('rb') as f, mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ) as data:
        rec, _ = analyze(data)
    args.out.mkdir(parents=True, exist_ok=True)
    (args.out / 'records.json').write_bytes(records_bytes(rec))
    (args.out / 'MANIFEST.sha256').write_bytes(manifest_bytes(args.out))
    print('Recorded %#x..%#x' % (START, END))

if __name__ == '__main__': main()
