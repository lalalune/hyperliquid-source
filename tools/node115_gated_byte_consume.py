#!/usr/bin/env python3
"""Bind a #115 guarded byte-consumption leaf using only static ELF bytes."""
import argparse
import hashlib
import json
import mmap
from pathlib import Path
import struct

ROOT = Path(__file__).resolve().parents[1]
TARGET = ROOT / 'artifacts/node/115/hl-node'
PACKET = ROOT / 'research/work-items/RE-001-node115-gated-byte-consume'
DIGEST = 'a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301'
START, END, NEXT = 0x232b1b0, 0x232b209, 0x232b210
FDE, CIE = 0xd0092c, 0xca6ed8
FILES = ('README.md', 'records.json', 'verify.py',
         '../../../tools/node115_gated_byte_consume.py',
         '../../../tests/test_node115_gated_byte_consume.py')

# Each accepted instruction has exactly one encoding, including branch displacements.
GRAMMAR = [
 ('4889f8', 'mov rax,rdi'), ('833e01', 'cmp dword [rsi],1'),
 ('751b', 'jne 0x232b1d3'), ('488b4e20', 'mov rcx,[rsi+0x20]'),
 ('4883f9ff', 'cmp rcx,-1'), ('7443', 'je 0x232b205'),
 ('488b5608', 'mov rdx,[rsi+8]'), ('488d7901', 'lea rdi,[rcx+1]'),
 ('48897e20', 'mov [rsi+0x20],rdi'), ('4839d1', 'cmp rcx,rdx'),
 ('7332', 'jae 0x232b205'), ('488b4e18', 'mov rcx,[rsi+0x18]'),
 ('4885c9', 'test rcx,rcx'), ('741d', 'je 0x232b1f9'),
 ('488b5610', 'mov rdx,[rsi+0x10]'), ('0fb63a', 'movzx edi,byte [rdx]'),
 ('48ffc2', 'inc rdx'), ('48ffc9', 'dec rcx'),
 ('48895610', 'mov [rsi+0x10],rdx'), ('48894e18', 'mov [rsi+0x18],rcx'),
 ('40887801', 'mov byte [rax+1],dil'), ('c60012', 'mov byte [rax],0x12'),
 ('c3', 'ret'), ('c60000', 'mov byte [rax],0'),
 ('48c7400801000000', 'mov qword [rax+8],1'), ('c3', 'ret'),
 ('c60002', 'mov byte [rax],2'), ('c3', 'ret')]


def require(value, message):
    if not value:
        raise ValueError(message)


def sections(data):
    require(data[:6] == b'\x7fELF\x02\x01', 'ELF64 little endian required')
    off = struct.unpack_from('<Q', data, 40)[0]
    size, count, names_id = struct.unpack_from('<HHH', data, 58)
    require(size == 64 and 0 < names_id < count and off + size * count <= len(data), 'section table')
    rows = [struct.unpack_from('<IIQQQQIIQQ', data, off + i * size) for i in range(count)]
    names = rows[names_id]
    require(names[4] + names[5] <= len(data), 'section names')
    strings = data[names[4]:names[4]+names[5]]
    result = {}
    for row in rows:
        require(row[0] < len(strings), 'section name offset')
        end = strings.find(b'\0', row[0])
        require(end >= 0, 'section name terminator')
        name = strings[row[0]:end].decode('ascii')
        if name in ('.text', '.eh_frame'):
            require(name not in result and row[4] + row[5] <= len(data), 'section bounds')
            result[name] = {'address': row[3], 'offset': row[4], 'size': row[5], 'flags': row[2]}
    require(result.get('.text') == {'address': 0x1419300, 'offset': 0x1418300,
            'size': 0x4fd7700, 'flags': 6}, 'text mapping')
    require(result.get('.eh_frame') == {'address': 0xca6ed8, 'offset': 0xca6ed8,
            'size': 0x77137c, 'flags': 2}, 'frame mapping')
    return result


def read_va(data, section, va, n):
    require(section['address'] <= va and va + n <= section['address'] + section['size'], 'VA bounds')
    p = section['offset'] + va - section['address']
    return bytes(data[p:p+n])


def decode_body(body):
    rows, p = [], 0
    for encoded, instruction in GRAMMAR:
        raw = bytes.fromhex(encoded)
        require(body[p:p+len(raw)] == raw, 'instruction mismatch at ' + hex(START+p))
        row = {'address': hex(START+p), 'bytes': raw.hex(), 'instruction': instruction}
        if raw[0] in (0x74, 0x75, 0x73):
            target = START + p + len(raw) + struct.unpack('<b', raw[1:])[0]
            require(target == int(instruction.split()[-1], 16), 'branch target')
            row['branch_target'] = hex(target)
        rows.append(row)
        p += len(raw)
    require(p == len(body) == END-START, 'body coverage')
    boundaries = {int(row['address'], 16) for row in rows}
    require(all(int(row['branch_target'], 16) in boundaries for row in rows if 'branch_target' in row), 'branch boundary')
    return rows


def decode_fde(data, frame):
    raw = read_va(data, frame, FDE, 20)
    length, back, disp, size = struct.unpack_from('<IIiI', raw)
    require(length == 16 and FDE+4-back == CIE and FDE+8+disp == START and size == END-START,
            'FDE identity or extent')
    require(raw[16:] == b'\0'*4, 'FDE augmentation')
    cie = read_va(data, frame, CIE, 24)
    require(cie == bytes.fromhex('1400000000000000017a5200017810011b0c070890010000'), 'CIE')
    neighbor = read_va(data, frame, FDE+20, 16)
    nlen, nback, ndisp, nsize = struct.unpack('<IIiI', neighbor)
    require(nlen == 60 and FDE+24-nback == CIE and FDE+28+ndisp == NEXT and nsize == 340, 'next FDE')
    return {'fde_va': hex(FDE), 'fde_file_offset': hex(FDE), 'fde_hex': raw.hex(),
            'cie_va': hex(CIE), 'cie_file_offset': hex(CIE), 'cie_hex': cie.hex(),
            'start': hex(START), 'end': hex(END), 'lsda': None,
            'next_fde_va': hex(FDE+20), 'next_fde_header_hex': neighbor.hex(),
            'next_start': hex(NEXT), 'next_end': hex(NEXT+nsize)}


def scan_calls(data, text):
    hits = []
    start, end = text['offset'], text['offset']+text['size']
    for op in (0xe8, 0xe9):
        pos = start
        while True:
            pos = data.find(bytes([op]), pos, end-4)
            if pos < 0:
                break
            va = text['address'] + pos-start
            if va+5+struct.unpack_from('<i', data, pos+1)[0] == START:
                hits.append({'address': hex(va), 'bytes': bytes(data[pos:pos+5]).hex(),
                             'kind': 'call' if op == 0xe8 else 'jump', 'target': hex(START)})
            pos += 1
    require(not hits, 'rel32 census changed')
    return hits


def extract(data, authenticate=True):
    if authenticate:
        require(hashlib.sha256(data).hexdigest() == DIGEST, 'node #115 digest mismatch')
    sec = sections(data)
    fde = decode_fde(data, sec['.eh_frame'])
    body = read_va(data, sec['.text'], START, END-START)
    instructions = decode_body(body)
    padding = read_va(data, sec['.text'], END, NEXT-END)
    require(padding == b'\xcc'*7, 'padding changed')
    hits = scan_calls(data, sec['.text'])
    return {'target_sha256': DIGEST, 'coordinate_system': 'ELF virtual address',
            'text': {'start': '0x1419300', 'end': '0x63f0a00'},
            'function': {'start': hex(START), 'end': hex(END), 'size': len(body),
                         'file_offset': hex(START-0x1000), 'body_sha256': hashlib.sha256(body).hexdigest(),
                         'fde': fde, 'padding_end': hex(NEXT), 'padding_hex': padding.hex(),
                         'instructions': instructions, 'callees': []},
            'direct_rel32_hits': hits,
            'counts': {'body_bytes': len(body), 'instructions': len(instructions),
                       'padding_bytes': len(padding), 'callees': 0, 'direct_rel32_hits': len(hits)}}


def model(mode, count, limit, remaining, byte=None):
    """Return (tag, counter, consumed, output byte, qword-at-output+8)."""
    require(0 <= mode < 2**32 and all(0 <= x < 2**64 for x in (count, limit, remaining)), 'input width')
    if mode == 1:
        if count == 2**64-1:
            return (2, count, 0, None, None)
        old = count
        count += 1
        if old >= limit:
            return (2, count, 0, None, None)
    if not remaining:
        return (0, count, 0, None, 1)
    require(byte is not None and 0 <= byte < 256, 'byte required')
    return (0x12, count, 1, byte, None)


def manifest(out):
    return ''.join(hashlib.sha256((ROOT / name[9:] if name.startswith('../../../') else out / name).read_bytes()).hexdigest()
                   + '  ' + name + '\n' for name in FILES)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out', type=Path, default=PACKET)
    parser.add_argument('--binary', type=Path, default=TARGET)
    args = parser.parse_args()
    with args.binary.open('rb') as f, mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ) as data:
        record = extract(data)
    args.out.mkdir(parents=True, exist_ok=True)
    if args.out.resolve() != PACKET.resolve():
        for name in ('README.md', 'verify.py'):
            (args.out / name).write_bytes((PACKET / name).read_bytes())
    (args.out / 'records.json').write_text(json.dumps(record, indent=2) + '\n')
    (args.out / 'MANIFEST.sha256').write_text(manifest(args.out))
    print('authenticated extraction:', hex(START))


if __name__ == '__main__':
    main()
