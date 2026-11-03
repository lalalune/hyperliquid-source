#!/usr/bin/env python3
"""Regenerate a static, digest-bound certificate for one #115 arithmetic leaf."""
import argparse
import hashlib
import json
from pathlib import Path
import struct

from elf_index import sections
from fde_extents import eh_frame_records

ROOT = Path(__file__).resolve().parents[1]
TARGET = ROOT / 'artifacts/node/115/hl-node'
SHA = 'a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301'
START, END = 0x29fc880, 0x29fc8b1
CALL = 0x2a1e7b7
BODY_SHA = '9b53b28d56b050e0fb3b421ec6eadfe83deb4d37b53dad0b4c3b0328190dcce4'
# Each accepted instruction encoding includes all operands, not merely an opcode.
OPS = [
 ('488b02', 'load rax from [rdx+0]'),
 ('480106', 'add rax to [rsi+0], set carry'),
 ('488b4208', 'load rax from [rdx+8]'),
 ('48114608', 'add rax and carry to [rsi+8], set carry'),
 ('488b4210', 'load rax from [rdx+16]'),
 ('48114610', 'add rax and carry to [rsi+16], set carry'),
 ('488b4218', 'load rax from [rdx+24]'),
 ('48114618', 'add rax and carry to [rsi+24], set carry'),
 ('0f1006', 'load 16 bytes from [rsi+0] into xmm0'),
 ('0f1107', 'store xmm0 to [rdi+0]'),
 ('0f104610', 'load 16 bytes from [rsi+16] into xmm0'),
 ('0f114710', 'store xmm0 to [rdi+16]'),
 ('0f924720', 'store carry as byte at [rdi+32]'),
 ('c3', 'return'),
]


def offset(section, va):
    if not section['address'] <= va < section['address'] + section['size']:
        raise ValueError('address outside section')
    return section['offset'] + va - section['address']


def decode(body):
    """Recognize the complete encoding sequence and reject any other instruction."""
    result, pos = [], 0
    for encoding, meaning in OPS:
        raw = bytes.fromhex(encoding)
        if body[pos:pos + len(raw)] != raw:
            raise ValueError('unexpected instruction or operands')
        result.append({'va': START + pos, 'bytes': encoding, 'effect': meaning})
        pos += len(raw)
    if pos != len(body):
        raise ValueError('extra or truncated instruction bytes')
    return result


def model(a, b):
    """Unsigned arithmetic, disjoint valid input/output buffers assumed."""
    if not (0 <= a < 1 << 256 and 0 <= b < 1 << 256):
        raise ValueError('expected unsigned 256-bit inputs')
    total = a + b
    return total & ((1 << 256) - 1), total >> 256


def rel32_candidates(data, text_section):
    lo, hi = text_section['offset'], text_section['offset'] + text_section['size']
    found = []
    for opcode in (0xe8, 0xe9):
        p = lo
        while True:
            p = data.find(bytes([opcode]), p, hi - 4)
            if p < 0:
                break
            va = text_section['address'] + p - lo
            if va + 5 + struct.unpack_from('<i', data, p + 1)[0] == START:
                found.append({'va': va, 'opcode': f'{opcode:02x}', 'bytes': data[p:p+5].hex()})
            p += 1
    return sorted(found, key=lambda row: row['va'])


def inspect(data, authenticate=True):
    if authenticate and hashlib.sha256(data).hexdigest() != SHA:
        raise ValueError('node #115 digest mismatch')
    secs = sections(data)
    text = next(s for s in secs if s['name'] == '.text')
    if (text['address'], text['size'], text['offset'], text['flags']) != (0x1419300, 0x4fd7700, 0x1418300, 6):
        raise ValueError('unexpected .text mapping')
    cies, fdes = eh_frame_records(data, secs)
    expected = {'fde': 0xd78350, 'cie': 0xca6ed8, 'start': START, 'end': END, 'lsda': None}
    if [x for x in fdes if x['start'] == START] != [expected]:
        raise ValueError('unexpected FDE')
    if cies[expected['cie']]['augmentation'] != 'zR':
        raise ValueError('unexpected CIE')
    off = offset(text, START)
    body = data[off:off + END - START]
    if hashlib.sha256(body).hexdigest() != BODY_SHA:
        raise ValueError('unexpected body hash')
    instructions = decode(body)
    padding = data[off + len(body):off + len(body) + 15]
    if padding != b'\xcc' * 15:
        raise ValueError('unexpected padding')
    candidates = rel32_candidates(data, text)
    if candidates != [{'va': CALL, 'opcode': 'e8', 'bytes': 'e8c4e0fdff'}]:
        raise ValueError('direct-transfer census changed')
    owner = {'fde': 0x116b584, 'cie': 0x103d604, 'start': 0x2a1dd50,
             'end': 0x2a1eb71, 'lsda': 0x250610}
    owners = [x for x in fdes if x['start'] == owner['start']]
    if owners != [owner]:
        raise ValueError('unexpected caller owner')
    context = data[offset(text, CALL - 16):offset(text, CALL + 13)]
    if context != bytes.fromhex('488dbc24b0000000488db42430010000e8c4e0fdff80bc24d000000000'):
        raise ValueError('caller instruction context changed')
    return {
        'target_sha256': SHA,
        'coordinate_system': 'ELF virtual address, half-open ranges',
        'function': {'start': START, 'end': END, 'size': END - START,
                     'file_offset': off, 'sha256': BODY_SHA, 'fde': expected,
                     'fde_raw': data[0xd78350:0xd78364].hex(),
                     'cie_raw': data[0xca6ed8:0xca6ef0].hex(),
                     'padding_start': END, 'padding_bytes': padding.hex(),
                     'instructions': instructions, 'callee_count': 0},
        'caller_census': {'method': 'all byte offsets in .text, e8/e9 rel32',
                          'candidates': candidates, 'candidate_count': len(candidates),
                          'confirmed_direct_calls': 1, 'caller_fde': owners[0],
                          'caller_context_start': CALL - 16, 'caller_context_hex': context.hex()},
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out', type=Path, required=True)
    parser.add_argument('--binary', type=Path, default=TARGET)
    args = parser.parse_args()
    record = inspect(args.binary.read_bytes())
    args.out.mkdir(parents=True, exist_ok=True)
    (args.out / 'records.json').write_text(json.dumps(record, indent=2) + '\n')


if __name__ == '__main__':
    main()
