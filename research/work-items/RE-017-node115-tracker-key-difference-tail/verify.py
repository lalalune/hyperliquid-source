#!/usr/bin/env python3
"""Check bounded instruction anchors and direct calls in node #115; no execution."""
import hashlib
import struct
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
TARGET = ROOT / 'artifacts/node/115/hl-node'
SHA = 'a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301'
ANCHORS = {95904072: '488b5424084c8b62404d85e40f84fa040000488b0a488b5a08488b42104c8b7a18488b52484889942480000000ba010000004889542448eb4c6666666666662e0f1f8400000000004b8d04b68b8c24c0000000894c82100f288424b000000048895424500f11048249ffc64c897424484c89742420b101b8000000004d85e40f8487040000f6c1010f84cd040000', 95904624: '4d8d77014889cb4b8d04bf4c8d04814983c008488bb42480000000488b3e49ffcc8b548118895424700f104481080f2944246048897c24304885ff0f841f0200004c894424584c89642408488b46084889842488000000eb390f1f80000000004889d8498d4e014c894c24084b8d14b6488d34904883c60848897424588b749018897424700f104490080f294424604989ce4c8bbc2488000000488b442430488d700848894424380fb780e600000048894424288d048500000000488d2c8049c7c5ffffffff662e0f1f8400000000004885ed744b4c8d6614ba14000000488d7c2460ff15f796960048984885c00f98c10f9fc028c849ffc54883c5ec4c89e63c0174cc0fb6c085c074454983ef01731ee93a010000662e0f1f8400000000004c8b6c24284983ef010f8221010000488b4424384a8b84e8e8000000e95effffff6666666666662e0f1f8400000000004c8b4c24084983e9010f82850100000fb783e60000004939c60f82f1feffff', 95905216: '4d89f74c8b6424084c8b442458eb04904d89f7418b4010410f10000f298424b0000000898424c00000004c8b7424484c3b742410488b5424500f8591fbffffba01000000b90100000041b814000000488d7c24104c89f6e8f4d3deff488b542418e96afbffff', 95905364: '488b4c2420488b44244048894810488b4c2410488908488b4c241848894808'}


def regions(data):
    if data[:6] != b'\x7fELF\x02\x01':
        raise ValueError('not ELF64 little endian')
    phoff, = struct.unpack_from('<Q', data, 32)
    entsize, count = struct.unpack_from('<HH', data, 54)
    if entsize < 56 or phoff + count * entsize > len(data):
        raise ValueError('invalid program headers')
    out = []
    for i in range(count):
        typ, _, off, va, _, filesz, _, _ = struct.unpack_from('<IIQQQQQQ', data, phoff + i * entsize)
        if typ == 1:
            out.append((va, va + filesz, off))
    return out


def va_offset(data, addr, size):
    hits = [off + addr - lo for lo, hi, off in regions(data) if lo <= addr and addr + size <= hi]
    if len(hits) != 1 or hits[0] + size > len(data):
        raise ValueError('address not uniquely file-backed')
    return hits[0]


def check(data, authenticate=True):
    if authenticate and hashlib.sha256(data).hexdigest() != SHA:
        raise ValueError('target digest mismatch')
    for addr, hexdump in ANCHORS.items():
        expected = bytes.fromhex(hexdump)
        off = va_offset(data, addr, len(expected))
        if data[off:off + len(expected)] != expected:
            raise ValueError(f'instruction anchor mismatch at {addr:#x}')
    for site, target in ((0x5b76617, 0x5963a10),):
        off = va_offset(data, site, 5)
        if data[off] != 0xe8 or site + 5 + struct.unpack_from('<i', data, off + 1)[0] != target:
            raise ValueError(f'call target mismatch at {site:#x}')
    return len(ANCHORS)


def main():
    data = TARGET.read_bytes()
    count = check(data)
    for addr in ANCHORS:
        mutant = bytearray(data)
        mutant[va_offset(mutant, addr, 1)] ^= 1
        try:
            check(mutant, authenticate=False)
        except ValueError:
            continue
        raise AssertionError(f'mutation accepted at {addr:#x}')
    print(f'OK: {count} anchors, 1 direct-call target; {count} anchor mutations rejected')


if __name__ == '__main__':
    main()
