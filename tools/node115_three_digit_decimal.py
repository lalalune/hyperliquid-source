#!/usr/bin/env python3
"""Regenerate one #115 instruction-bound decimal parser packet, without execution."""
import argparse
import hashlib
import json
import mmap
from pathlib import Path
import struct

ROOT = Path(__file__).resolve().parents[1]
PACKET = ROOT / 'research/work-items/RE-001-node115-three-digit-decimal'
TARGET = ROOT / 'artifacts/node/115/hl-node'
SHA = 'a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301'
START, END = 0x179b360, 0x179b3b5
FDE, CIE = 0xcd0138, 0xca6ed8
CALLER, CALL = 0x17985c0, 0x17989a6
CALLER_FDE, CALLER_CIE = 0x108281c, 0x103d604

# Every entry is an entire instruction, in order. Matching these exact
# encodings is deliberate: no guessed lengths or unsupported opcode forms.
OPS = [
 ('4883fe03', 'cmp rsi, 3'), ('7530', 'jne 0x179b396'),
 ('0fb60f', 'movzx ecx, byte [rdi]'), ('0fb64701', 'movzx eax, byte [rdi+1]'),
 ('04d0', 'add al, 0xd0'), ('0fb65702', 'movzx edx, byte [rdi+2]'),
 ('80c2d0', 'add dl, 0xd0'), ('8d71c6', 'lea esi, [rcx-58]'),
 ('4080fef7', 'cmp sil, 247'), ('400f92c6', 'setb sil'),
 ('3c0a', 'cmp al, 10'), ('400f93c7', 'setae dil'),
 ('80fa0a', 'cmp dl, 10'), ('410f93c0', 'setae r8b'),
 ('4108f8', 'or r8b, dil'), ('4108f0', 'or r8b, sil'),
 ('7403', 'je 0x179b399'), ('31c0', 'xor eax, eax'), ('c3', 'ret'),
 ('0fb6d2', 'movzx edx, dl'), ('80c1d0', 'add cl, 0xd0'),
 ('0fb6c9', 'movzx ecx, cl'), ('6bc964', 'imul ecx, ecx, 100'),
 ('0fb6c0', 'movzx eax, al'), ('01c0', 'add eax, eax'),
 ('8d0480', 'lea eax, [rax+rax*4]'), ('0fb6c0', 'movzx eax, al'),
 ('01c8', 'add eax, ecx'), ('01d0', 'add eax, edx'), ('c3', 'ret'),
]


def decode(body):
    """Strictly decode exactly this x86-64 subset and validate both branch edges."""
    rows, pos = [], 0
    for expected, text in OPS:
        n = len(expected) // 2
        b = body[pos:pos+n]
        if b.hex() != expected:
            raise ValueError(f'instruction encoding mismatch at {START+pos:#x}')
        row = {'va': START + pos, 'bytes': b.hex(), 'instruction': text}
        if b[0] in (0x75, 0x74) and len(b) == 2:
            target = START + pos + 2 + struct.unpack('b', b[1:])[0]
            if target not in (0x179b396, 0x179b399):
                raise ValueError('unexpected branch destination')
            row['target'] = target
        rows.append(row)
        pos += n
    if pos != len(body) or pos != END-START:
        raise ValueError('body extent mismatch')
    return rows


def parse_sections(d):
    if d[:16] != b'\x7fELF\x02\x01\x01' + b'\0'*9 or struct.unpack_from('<H', d, 18)[0] != 62:
        raise ValueError('not x86-64 ELF64 little-endian')
    shoff = struct.unpack_from('<Q', d, 40)[0]
    entsize, count, names_index = struct.unpack_from('<HHH', d, 58)
    if entsize != 64 or not 0 < names_index < count or shoff + entsize*count > len(d):
        raise ValueError('invalid section table')
    entries = [struct.unpack_from('<IIQQQQIIQQ', d, shoff+i*64) for i in range(count)]
    ns = entries[names_index]
    names = d[ns[4]:ns[4]+ns[5]]
    result = {}
    for e in entries:
        if e[0] >= len(names):
            raise ValueError('invalid section name')
        stop = names.find(b'\0', e[0])
        if stop < 0:
            raise ValueError('unterminated section name')
        name = names[e[0]:stop].decode('ascii')
        if name in ('.text', '.eh_frame'):
            if name in result or e[4]+e[5] > len(d):
                raise ValueError('duplicate or truncated section')
            result[name] = {'address': e[3], 'offset': e[4], 'size': e[5], 'flags': e[2]}
    if set(result) != {'.text', '.eh_frame'}:
        raise ValueError('missing sections')
    text = result['.text']
    if (text['address'], text['offset'], text['size'], text['flags']) != (0x1419300, 0x1418300, 0x4fd7700, 6):
        raise ValueError('unexpected text mapping')
    if result['.eh_frame']['address'] != result['.eh_frame']['offset']:
        raise ValueError('unexpected frame mapping')
    return result


def section_bytes(d, sec, va, size):
    off = sec['offset'] + va - sec['address']
    if size < 0 or va < sec['address'] or off + size > sec['offset'] + sec['size']:
        raise ValueError('range outside section')
    return bytes(d[off:off+size])


def check_frame(raw, va, cie, start, end, lsda=None):
    if len(raw) < 17:
        raise ValueError('short FDE')
    length, delta, rel, extent = struct.unpack_from('<IIiI', raw)
    if len(raw) != length + 4 or va + 4 - delta != cie or va + 8 + rel != start or start + extent != end:
        raise ValueError('FDE identity or range changed')
    aug = raw[16]
    if lsda is None:
        if aug != 0:
            raise ValueError('unexpected FDE augmentation')
    elif aug != 4 or va + 17 + struct.unpack_from('<i', raw, 17)[0] != lsda:
        raise ValueError('FDE LSDA changed')
    return {'va': va, 'file_offset': va, 'cie_va': cie, 'start': start, 'end': end,
            'lsda': lsda, 'raw_hex': raw.hex()}


def check_call(b):
    if len(b) != 23 or b[0] != 0xe8 or b[5:] != bytes.fromhex('6685c00f84e9fcffff6641890641c6464007'):
        raise ValueError('caller instruction sequence changed')
    target = CALL + 5 + struct.unpack_from('<i', b, 1)[0]
    branch = CALL + 14 + struct.unpack_from('<i', b, 10)[0]
    if target != START or branch != 0x179869d:
        raise ValueError('caller target changed')
    return {'site': CALL, 'opcode': 'e8', 'target': target, 'bytes': b.hex(),
            'instructions': [
                {'va': CALL, 'bytes': b[:5].hex(), 'instruction': 'call 0x179b360'},
                {'va': CALL+5, 'bytes': b[5:8].hex(), 'instruction': 'test ax, ax'},
                {'va': CALL+8, 'bytes': b[8:14].hex(), 'instruction': 'je 0x179869d'},
                {'va': CALL+14, 'bytes': b[14:18].hex(), 'instruction': 'mov word [r14], ax'},
                {'va': CALL+18, 'bytes': b[18:23].hex(), 'instruction': 'mov byte [r14+0x40], 7'},
            ], 'zero_branch_target': branch, 'enclosing_fde_start': CALLER}


def model(length, data):
    """Value rule for readable three-byte inputs; invalid length reads no data."""
    if length != 3:
        return 0
    if len(data) < 3:
        raise ValueError('three readable bytes required')
    a, b, c = data[:3]
    if not (49 <= a <= 57 and 48 <= b <= 57 and 48 <= c <= 57):
        return 0
    return 100*(a-48) + 10*(b-48) + c-48


def analyze(d):
    sections = parse_sections(d)
    t, eh = sections['.text'], sections['.eh_frame']
    body = section_bytes(d, t, START, END-START)
    instructions = decode(body)
    cie_raw = section_bytes(d, eh, CIE, 24)
    if cie_raw.hex() != '1400000000000000017a5200017810011b0c070890010000':
        raise ValueError('CIE changed')
    frame = check_frame(section_bytes(d, eh, FDE, 20), FDE, CIE, START, END)
    caller_cie_raw = section_bytes(d, eh, CALLER_CIE, 32)
    if caller_cie_raw.hex() != '1c00000000000000017a504c5200017810079b11244b051b1b0c070890010000':
        raise ValueError('caller CIE changed')
    caller_frame = check_frame(section_bytes(d, eh, CALLER_FDE, 84), CALLER_FDE, CALLER_CIE, CALLER, 0x1798ad5, 0x19fe58)
    caller_frame['cie_raw_hex'] = caller_cie_raw.hex()
    caller = check_call(section_bytes(d, t, CALL, 23))
    padding = section_bytes(d, t, END, 11)
    if padding != b'\xcc'*11:
        raise ValueError('padding changed')
    # Scan every byte position, including unaligned false-positive candidates.
    # Search mmap directly to avoid a second 84 MB text copy.
    hits = []
    lo, hi = t['offset'], t['offset'] + t['size']
    for opcode in (0xe8, 0xe9):
        p = lo
        while True:
            p = d.find(bytes([opcode]), p, hi - 4)
            if p < 0:
                break
            va = t['address'] + p - lo
            if va + 5 + struct.unpack_from('<i', d, p+1)[0] == START:
                hits.append({'site': va, 'opcode': f'{opcode:02x}'})
            p += 1
    hits.sort(key=lambda x: x['site'])
    if hits != [{'site': CALL, 'opcode': 'e8'}]:
        raise ValueError('unexpected full-text rel32 candidate census')
    return {
        'target_sha256': SHA,
        'target_size': len(d),
        'coordinate_system': 'ELF virtual addresses; section-derived file offsets',
        'text': t,
        'function': {'start': START, 'end': END, 'file_offset': t['offset'] + START-t['address'],
                     'body_sha256': hashlib.sha256(body).hexdigest(), 'body_hex': body.hex(),
                     'fde': frame, 'cie_raw_hex': cie_raw.hex(), 'instructions': instructions,
                     'padding_hex': padding.hex()},
        'callees': [], 'rel32_candidates': hits, 'confirmed_caller': caller, 'caller_fde': caller_frame,
        'counts': {'function_bytes': len(body), 'instructions': len(instructions),
                   'return_count': sum(row['instruction'] == 'ret' for row in instructions),
                   'callee_count': sum(row['instruction'].startswith(('call ', 'jmp ')) for row in instructions),
                   'rel32_candidates': len(hits), 'confirmed_direct_callers': int(caller['target'] == START),
                   'padding_bytes': len(padding)},
    }


def manifest(record_bytes):
    entries = [('README.md', (PACKET/'README.md').read_bytes()), ('records.json', record_bytes),
               ('verify.py', (PACKET/'verify.py').read_bytes()),
               ('../../../tools/node115_three_digit_decimal.py', Path(__file__).read_bytes()),
               ('../../../tests/test_node115_three_digit_decimal.py', (ROOT/'tests/test_node115_three_digit_decimal.py').read_bytes())]
    return ''.join(f'{hashlib.sha256(value).hexdigest()}  {name}\n' for name, value in entries)


def generate(target, out):
    with open(target, 'rb') as f:
        with mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ) as data:
            if hashlib.sha256(data).hexdigest() != SHA:
                raise ValueError('node #115 digest mismatch')
            records = analyze(data)
    raw = (json.dumps(records, indent=2) + '\n').encode()
    out.mkdir(parents=True, exist_ok=True)
    (out/'records.json').write_bytes(raw)
    (out/'MANIFEST.sha256').write_text(manifest(raw))
    return records


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--target', type=Path, default=TARGET)
    parser.add_argument('--out', type=Path, required=True)
    args = parser.parse_args()
    result = generate(args.target, args.out)
    print(json.dumps(result['counts'], sort_keys=True))


if __name__ == '__main__':
    main()
