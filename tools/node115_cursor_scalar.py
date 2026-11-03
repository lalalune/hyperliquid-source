#!/usr/bin/env python3
"""Bind the node #115 cursor scalar reader, without executing the capture."""
import argparse
import hashlib
import json
import mmap
from pathlib import Path
import struct

ROOT = Path(__file__).resolve().parents[1]
TARGET = ROOT / 'artifacts/node/115/hl-node'
SHA = 'a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301'
SIZE = 105896032
START, END = 0x1621dc0, 0x1621e4c
TEXT_START, TEXT_END, TEXT_FILE = 0x1419300, 0x63f0a00, 0x1418300
FDE, CIE = 0xcbe624, 0xca6ed8
CALLERS = (0x162284c, 0x16228cf, 0x1622aa1, 0x1622b2d, 0x1622d9f, 0x1622f38, 0x1622fb5)
# Exact opcode/operand forms accepted by this deliberately narrow decoder.
# The semantic strings are Intel syntax and the sequence covers the entire FDE.
INSTRUCTIONS = (
    ('488b37', 'mov    rsi,QWORD PTR [rdi]'),
    ('483b7708', 'cmp    rsi,QWORD PTR [rdi+0x8]'),
    ('7414', 'je     1621ddd'),
    ('488d4601', 'lea    rax,[rsi+0x1]'),
    ('488907', 'mov    QWORD PTR [rdi],rax'),
    ('0fb616', 'movzx  edx,BYTE PTR [rsi]'),
    ('84d2', 'test   dl,dl'),
    ('7809', 'js     1621de0'),
    ('b801000000', 'mov    eax,0x1'),
    ('c3', 'ret'),
    ('31c0', 'xor    eax,eax'),
    ('c3', 'ret'),
    ('89d1', 'mov    ecx,edx'),
    ('83e11f', 'and    ecx,0x1f'),
    ('488d4602', 'lea    rax,[rsi+0x2]'),
    ('488907', 'mov    QWORD PTR [rdi],rax'),
    ('440fb64e01', 'movzx  r9d,BYTE PTR [rsi+0x1]'),
    ('4183e13f', 'and    r9d,0x3f'),
    ('b801000000', 'mov    eax,0x1'),
    ('80fadf', 'cmp    dl,0xdf'),
    ('763a', 'jbe    1621e39'),
    ('4c8d4603', 'lea    r8,[rsi+0x3]'),
    ('4c8907', 'mov    QWORD PTR [rdi],r8'),
    ('440fb64602', 'movzx  r8d,BYTE PTR [rsi+0x2]'),
    ('41c1e106', 'shl    r9d,0x6'),
    ('4183e03f', 'and    r8d,0x3f'),
    ('4509c8', 'or     r8d,r9d'),
    ('80faf0', 'cmp    dl,0xf0'),
    ('7227', 'jb     1621e42'),
    ('488d5604', 'lea    rdx,[rsi+0x4]'),
    ('488917', 'mov    QWORD PTR [rdi],rdx'),
    ('0fb65603', 'movzx  edx,BYTE PTR [rsi+0x3]'),
    ('83e107', 'and    ecx,0x7'),
    ('c1e112', 'shl    ecx,0x12'),
    ('41c1e006', 'shl    r8d,0x6'),
    ('83e23f', 'and    edx,0x3f'),
    ('4409c2', 'or     edx,r8d'),
    ('09ca', 'or     edx,ecx'),
    ('c3', 'ret'),
    ('c1e106', 'shl    ecx,0x6'),
    ('4409c9', 'or     ecx,r9d'),
    ('89ca', 'mov    edx,ecx'),
    ('c3', 'ret'),
    ('c1e10c', 'shl    ecx,0xc'),
    ('4109c8', 'or     r8d,ecx'),
    ('4489c2', 'mov    edx,r8d'),
    ('c3', 'ret'),
)
FDE_BYTES = bytes.fromhex('1000000050770100943796008c00000000000000')
CIE_BYTES = bytes.fromhex('1400000000000000017a5200017810011b0c070890010000')


def decode(body):
    """Decode only the exact instruction forms and immediates bound by this packet."""
    rows, pos, starts, targets = [], 0, set(), []
    for encoding, operation in INSTRUCTIONS:
        expected = bytes.fromhex(encoding)
        actual = body[pos:pos + len(expected)]
        if actual != expected:
            raise ValueError('unknown or changed instruction at %#x' % (START + pos))
        addr = START + pos
        starts.add(addr)
        row = {'address': addr, 'bytes': actual.hex(), 'instruction': operation}
        if actual[0] in (0x74, 0x78, 0x76, 0x72, 0xeb):
            target = addr + 2 + struct.unpack('<b', actual[1:2])[0]
            row['branch_target'] = target
            targets.append(target)
        rows.append(row)
        pos += len(expected)
    if pos != len(body) or any(t not in starts for t in targets):
        raise ValueError('instruction coverage or branch target mismatch')
    return rows


def frame(fde, cie):
    if fde != FDE_BYTES or cie != CIE_BYTES:
        raise ValueError('FDE or CIE mismatch')
    length, delta, disp, extent = struct.unpack_from('<IIiI', fde)
    if length != 16 or FDE + 4 - delta != CIE or FDE + 8 + disp != START or extent != END - START:
        raise ValueError('FDE address or extent mismatch')
    return {'offset': FDE, 'cie_offset': CIE, 'fde_bytes': fde.hex(),
            'cie_bytes': cie.hex(), 'cie_augmentation': 'zR', 'lsda': None}


def direct_target(address, raw):
    if len(raw) != 5 or raw[0] not in (0xe8, 0xe9):
        raise ValueError("not a direct rel32 transfer")
    return address + 5 + struct.unpack_from("<i", raw, 1)[0]


def require_target(address, raw):
    if direct_target(address, raw) != START:
        raise ValueError("wrong rel32 target")


def call_sites(data):
    """Scan every byte in .text for E8/E9 rel32, including possible unaligned data."""
    found = []
    end = TEXT_FILE + TEXT_END - TEXT_START
    for opcode in (0xe8, 0xe9):
        pos = TEXT_FILE
        while True:
            pos = data.find(bytes([opcode]), pos, end - 4)
            if pos < 0:
                break
            addr = TEXT_START + pos - TEXT_FILE
            if addr + 5 + struct.unpack_from('<i', data, pos + 1)[0] == START:
                raw = data[pos:pos + 5]
                require_target(addr, raw)
                found.append({'address': addr, 'opcode': 'call' if opcode == 0xe8 else 'jmp',
                              'bytes': raw.hex()})
            pos += 1
    found.sort(key=lambda x: x['address'])
    if tuple(row['address'] for row in found) != CALLERS or any(row['opcode'] != 'call' for row in found):
        raise ValueError('rel32 caller census mismatch')
    return found


def model(data, cursor, end):
    """Return (status, value-or-None, cursor). Only accessed bytes must exist."""
    if cursor == end:
        return 0, None, cursor
    if cursor < 0 or cursor >= len(data):
        raise ValueError('first byte inaccessible')
    b = data[cursor]
    n = 1 if b < 0x80 else 2 if b <= 0xdf else 3 if b < 0xf0 else 4
    if cursor + n > len(data):
        raise ValueError('continuation byte inaccessible')
    if n == 1:
        value = b
    else:
        value = b & (7 if n == 4 else 31)
        for c in data[cursor + 1:cursor + n]:
            value = (value << 6) | (c & 63)
    return 1, value, cursor + n


def collect(data):
    if len(data) != SIZE or hashlib.sha256(data).hexdigest() != SHA:
        raise ValueError('target size or SHA-256 mismatch')
    offset = TEXT_FILE + START - TEXT_START
    body = data[offset:offset + END - START]
    rows = decode(body)
    f = frame(data[FDE:FDE + len(FDE_BYTES)], data[CIE:CIE + len(CIE_BYTES)])
    padding = data[offset + len(body):offset + len(body) + 4]
    if padding != b'\xcc' * 4:
        raise ValueError('following padding mismatch')
    callers = call_sites(data)
    caller_fde = 0xcbe674
    length, delta, disp, extent = struct.unpack_from('<IIiI', data, caller_fde)
    if (length, caller_fde + 4 - delta, caller_fde + 8 + disp, extent) != (80, CIE, 0x1621f30, 0x11c4):
        raise ValueError('caller FDE mismatch')
    return {'target_sha256': SHA, 'target_size': SIZE, 'function': {
        'start': START, 'end': END, 'file_offset': offset, 'size': len(body),
        'body_sha256': hashlib.sha256(body).hexdigest(), 'frame': f,
        'padding_hex': padding.hex(), 'instructions': rows, 'callees': [],
        'rel32_caller_candidates': callers,
        'candidate_enclosing_fde': {'offset': caller_fde, 'cie_offset': CIE,
            'start': 0x1621f30, 'end': 0x16230f4,
            'bytes': data[caller_fde:caller_fde + length + 4].hex()},
        'caller_scan': {'start': TEXT_START, 'end': TEXT_END, 'opcodes': ['e8', 'e9'],
                        'method': 'all byte offsets, little-endian signed rel32'}}}


def render(records):
    return (json.dumps(records, indent=2) + '\n').encode()


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--binary', type=Path, default=TARGET)
    p.add_argument('--out', type=Path, required=True)
    args = p.parse_args()
    with args.binary.open('rb') as f:
        if f.seek(0, 2) != SIZE:
            raise ValueError('target size or SHA-256 mismatch')
        with mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ) as data:
            records = collect(data)
    args.out.mkdir(parents=True, exist_ok=True)
    (args.out / 'records.json').write_bytes(render(records))


if __name__ == '__main__':
    main()
