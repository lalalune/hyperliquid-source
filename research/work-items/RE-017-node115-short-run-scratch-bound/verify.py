#!/usr/bin/env python3
"""Check bounded instruction anchors and ELF relocations in node #115; no execution."""
import hashlib
import struct
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
TARGET = ROOT / 'artifacts/node/115/hl-node'
SHA = 'a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301'
ANCHORS = {57553712: '4989d64889f148d1e94889f04829c84881fe90d00300bb90d00300480f42de4839c3480f46d8', 57553750: '4881fb81000000730a4989e7b980000000eb434989dc49', 57553836: '4531c04883fe41410f92c04c89fa4d89f1e89e4d710048', 64979333: '4883fe020f82520600004989c9', 64979377: '4889f04881fe01100000731d48d1e84889f14829c14883f940b840000000480f42c14889442420eb2a', 64979512: '4c894c24284889742440488b4c24404c29e94c89', 64979634: '483b4c24207357807c2454007460', 64979648: '4989ce4883f920b8200000004c0f43f0488b442430488904244c89e74c89f6488b542408488b5c24284889d94531c04531c9ff15a8156f02', 70133425: '4c894c24484989cc4989f54889f94883fe21488954241873084889cfe9550500004489', 70134823: '4c89ee488b5424184c89e14c8b8424d0000000e8a1080d00', 70989043: '4883fe020f8228060000488d46104839c10f82790600004889'}


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
    for site, target in ((0x36e33bd, 0x3df8160), (0x42e2c3a, 0x43b34e0)):
        off = va_offset(data, site, 5)
        if data[off] != 0xe8 or site + 5 + struct.unpack_from('<i', data, off + 1)[0] != target:
            raise ValueError(f'call target mismatch at {site:#x}')
    site = 0x3df82f2
    off = va_offset(data, site, 6)
    if data[off:off + 2] != b"\xff\x15" or site + 6 + struct.unpack_from('<i', data, off + 2)[0] != 0x64e98a0:
        raise ValueError('indirect call slot mismatch')
    # Scan SHT_RELA sections for the unique R_X86_64_RELATIVE slot binding.
    shoff, = struct.unpack_from('<Q', data, 40)
    shsize, shcount = struct.unpack_from('<HH', data, 58)
    if shsize < 64 or shoff + shsize * shcount > len(data):
        raise ValueError('invalid section headers')
    matches = []
    for i in range(shcount):
        _, typ, _, _, off, size, _, _, _, entsize = struct.unpack_from('<IIQQQQIIQQ', data, shoff + i * shsize)
        if typ != 4:
            continue
        if entsize != 24 or off + size > len(data) or size % entsize:
            raise ValueError('invalid RELA table')
        for pos in range(off, off + size, entsize):
            address, info, addend = struct.unpack_from('<QQq', data, pos)
            if address == 0x64e98a0:
                matches.append((info, addend))
    if matches != [(8, 0x42e26a0)]:
        raise ValueError('slot relocation mismatch')
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
    print(f'OK: {count} anchors, 2 direct calls and indirect slot relocation; {count} anchor mutations rejected')


if __name__ == '__main__':
    main()
