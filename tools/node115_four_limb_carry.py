#!/usr/bin/env python3
"""Extract one authenticated node #115 arithmetic leaf, without target execution."""
import argparse
import hashlib
import json
import mmap
from pathlib import Path
import struct

ROOT = Path(__file__).resolve().parents[1]
TARGET = ROOT / 'artifacts/node/115/hl-node'
PACKET = ROOT / 'research/work-items/RE-001-node115-four-limb-carry'
DIGEST = 'a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301'
START, END, NEXT = 0x4fb12f0, 0x4fb1321, 0x4fb1330
FDE, CIE = 0xf3b5c0, 0xca6ed8
# A deliberately narrow instruction grammar. Exact ModRM/SIB/displacements are
# accepted only for this body; unsupported instructions fail rather than guess.
GRAMMAR = [
 ('488b02', 'mov rax, [rdx]'), ('480106', 'add [rsi], rax'),
 ('488b4208', 'mov rax, [rdx+8]'), ('48114608', 'adc [rsi+8], rax'),
 ('488b4210', 'mov rax, [rdx+16]'), ('48114610', 'adc [rsi+16], rax'),
 ('488b4218', 'mov rax, [rdx+24]'), ('48114618', 'adc [rsi+24], rax'),
 ('0f1006', 'movups xmm0, [rsi]'), ('0f1107', 'movups [rdi], xmm0'),
 ('0f104610', 'movups xmm0, [rsi+16]'), ('0f114710', 'movups [rdi+16], xmm0'),
 ('0f924720', 'setb byte [rdi+32]'), ('c3', 'ret')]
FILES = ('README.md', 'records.json', 'verify.py',
         '../../../tools/node115_four_limb_carry.py',
         '../../../tests/test_node115_four_limb_carry.py')


def require(ok, message):
    if not ok:
        raise ValueError(message)


def sections(data):
    require(data[:6] == b'\x7fELF\x02\x01', 'expected ELF64 little endian')
    off = struct.unpack_from('<Q', data, 40)[0]
    entsize, count, names_index = struct.unpack_from('<HHH', data, 58)
    require(entsize == 64 and 0 < names_index < count, 'section table')
    require(off + entsize * count <= len(data), 'section table truncated')
    rows = [struct.unpack_from('<IIQQQQIIQQ', data, off + i * 64) for i in range(count)]
    names = rows[names_index]
    require(names[4] + names[5] <= len(data), 'section names truncated')
    strings = data[names[4]:names[4] + names[5]]
    result = {}
    for row in rows:
        pos = row[0]
        require(pos < len(strings), 'bad section name')
        end = strings.find(b'\0', pos)
        require(end >= 0, 'bad section name terminator')
        name = strings[pos:end].decode('ascii')
        if name in ('.text', '.eh_frame'):
            require(name not in result and row[4] + row[5] <= len(data), 'bad selected section')
            result[name] = {'address': row[3], 'offset': row[4], 'size': row[5], 'flags': row[2]}
    require(set(result) == {'.text', '.eh_frame'}, 'missing section')
    require(result['.text'] == {'address': 0x1419300, 'offset': 0x1418300,
                              'size': 0x4fd7700, 'flags': 6}, 'text mapping')
    return result


def read_va(data, sec, address, size):
    require(sec['address'] <= address and address + size <= sec['address'] + sec['size'], 'address outside section')
    p = sec['offset'] + address - sec['address']
    return bytes(data[p:p + size])


def decode_body(body):
    rows, p = [], 0
    for encoding, asm in GRAMMAR:
        raw = bytes.fromhex(encoding)
        require(body[p:p + len(raw)] == raw, 'unsupported or altered instruction at ' + hex(START + p))
        rows.append({'address': hex(START + p), 'bytes': raw.hex(), 'instruction': asm})
        p += len(raw)
    require(p == len(body) == END - START, 'instruction coverage')
    return rows


def decode_fde(data, frame):
    raw = read_va(data, frame, FDE, 20)
    length, delta, displacement, size = struct.unpack_from('<IIiI', raw)
    cie = FDE + 4 - delta
    start = FDE + 8 + displacement
    require(length == 16 and cie == CIE and start == START and size == END - START,
            'FDE identity or extent')
    require(raw[16:] == b'\0\0\0\0', 'FDE augmentation or instructions')
    cie_raw = read_va(data, frame, cie, 24)
    require(cie_raw == bytes.fromhex('1400000000000000017a5200017810011b0c070890010000'), 'CIE encoding')
    next_fde = FDE + 20
    next_header = read_va(data, frame, next_fde, 16)
    next_length, next_delta, next_displacement, next_size = struct.unpack('<IIiI', next_header)
    require(next_length == 76 and next_fde + 4 - next_delta == CIE and
            next_fde + 8 + next_displacement == NEXT and next_size == 1052,
            'neighboring FDE')
    return {'fde_va': hex(FDE), 'fde_file_offset': hex(frame['offset'] + FDE - frame['address']),
            'fde_hex': raw.hex(), 'cie_va': hex(cie),
            'cie_file_offset': hex(frame['offset'] + cie - frame['address']), 'cie_hex': cie_raw.hex(),
            'start': hex(start), 'end': hex(start + size), 'lsda': None,
            'next_fde_va': hex(next_fde), 'next_fde_header_hex': next_header.hex(),
            'next_start': hex(NEXT), 'next_end': hex(NEXT + next_size)}


def decode_call(data, text, address):
    raw = read_va(data, text, address, 5)
    require(raw[0] == 0xe8, 'expected direct call')
    target = address + 5 + struct.unpack_from('<i', raw, 1)[0]
    require(target == START, 'wrong direct call target')
    # Anchors establish the adjacent call setup and carry-byte read on each hit.
    prefix = read_va(data, text, address - 20, 20)
    suffix = read_va(data, text, address + 5, 8)
    require(prefix == bytes.fromhex('480f45d0488dbc24b0000000488db42430010000') and
            suffix == bytes.fromhex('80bc24d000000000'), 'caller context changed')
    return {'address': hex(address), 'bytes': raw.hex(), 'target': hex(target),
            'context_before': [
                {'address': hex(address - 20), 'bytes': prefix[:4].hex(), 'instruction': 'cmovne rdx, rax'},
                {'address': hex(address - 16), 'bytes': prefix[4:12].hex(), 'instruction': 'lea rdi, [rsp+0xb0]'},
                {'address': hex(address - 8), 'bytes': prefix[12:].hex(), 'instruction': 'lea rsi, [rsp+0x130]'}],
            'context_after': {'address': hex(address + 5), 'bytes': suffix.hex(),
                              'instruction': 'cmp byte [rsp+0xd0], 0'}}


def scan_calls(data, text):
    # Search every byte, including unaligned opcode-like bytes, for both encodings.
    start, end = text['offset'], text['offset'] + text['size']
    hits = []
    for op in (0xe8, 0xe9):
        p = start
        while True:
            p = data.find(bytes([op]), p, end - 4)
            if p < 0:
                break
            va = text['address'] + p - start
            if va + 5 + struct.unpack_from('<i', data, p + 1)[0] == START:
                hits.append((va, op))
            p += 1
    require(sorted(hits) == [(0x4fb85c7, 0xe8), (0x4fb93f7, 0xe8)], 'raw rel32 census changed')
    return [decode_call(data, text, va) for va, _ in sorted(hits)]


def extract(data, authenticate=True):
    if authenticate:
        require(hashlib.sha256(data).hexdigest() == DIGEST, 'node #115 digest mismatch')
    sec = sections(data)
    fde = decode_fde(data, sec['.eh_frame'])
    body = read_va(data, sec['.text'], START, END - START)
    instructions = decode_body(body)
    padding = read_va(data, sec['.text'], END, NEXT - END)
    require(padding == b'\xcc' * 15, 'padding changed')
    callers = scan_calls(data, sec['.text'])
    return {'target_sha256': DIGEST, 'coordinate_system': 'ELF virtual address',
            'text': {'start': '0x1419300', 'end': '0x63f0a00'},
            'function': {'start': hex(START), 'end': hex(END), 'size': len(body),
                         'file_offset': hex(sec['.text']['offset'] + START - sec['.text']['address']),
                         'body_sha256': hashlib.sha256(body).hexdigest(),
                         'fde': fde, 'padding_end': hex(NEXT), 'padding_hex': padding.hex(),
                         'instructions': instructions, 'callees': []},
            'direct_rel32_hits': callers,
            'counts': {'body_bytes': len(body), 'instructions': len(instructions),
                       'padding_bytes': len(padding), 'callees': 0, 'direct_rel32_hits': len(callers)}}


def model(left, right):
    """Pure mathematical rule, for disjoint valid native memory operands."""
    if not (0 <= left < 1 << 256 and 0 <= right < 1 << 256):
        raise ValueError('inputs must be 256-bit unsigned values')
    total = left + right
    return total % (1 << 256), total >> 256


def manifest(out):
    lines = []
    for name in FILES:
        path = out / name if not name.startswith('../../../') else ROOT / name[9:]
        lines.append(hashlib.sha256(path.read_bytes()).hexdigest() + '  ' + name + '\n')
    return ''.join(lines)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out', type=Path, default=PACKET)
    parser.add_argument('--binary', type=Path, default=TARGET)
    args = parser.parse_args()
    with args.binary.open('rb') as f, mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ) as data:
        result = extract(data)
    args.out.mkdir(parents=True, exist_ok=True)
    # The prose and verifier are fixed packet inputs, not synthesized claims.
    if args.out.resolve() != PACKET.resolve():
        for name in ('README.md', 'verify.py'):
            (args.out / name).write_bytes((PACKET / name).read_bytes())
    (args.out / 'records.json').write_text(json.dumps(result, indent=2) + '\n')
    (args.out / 'MANIFEST.sha256').write_text(manifest(args.out))
    print('authenticated extraction: ' + hex(START))


if __name__ == '__main__':
    main()
