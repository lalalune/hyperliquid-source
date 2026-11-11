#!/usr/bin/env python3
"""Check bounded instruction anchors and ELF relocations in node #115; no execution."""
import hashlib
import struct
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
TARGET = ROOT / 'artifacts/node/115/hl-node'
SHA = 'a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301'
ANCHORS = {87328520: '488d54240f4c89f74c89feff15ffc61901e9fefeffff', 57553696: '4157415641554154534881ec001000004989d64889f148d1e94889f04829c84881fe90d00300bb90d00300480f42de4839c3480f46d8', 57553750: '4881fb81000000730a4989e7b980000000eb434989dc49c1e40548c1e8', 57553769: '4989dc49c1e40548c1e83b0f95c04885db0f98c108c1740b31ff4c89e6ff150cc1df024989', 57553804: '4989ff4c89e74989f5ff15e5c0df024c89ff4c89ee4989c74889d94885c07442', 57553836: '4531c04883fe41410f92c04c89fa4d89f1e89e4d71004881fb80000000761248c1e305', 57553858: '4881fb80000000761248c1e3054c89ff4889de31d2ff15c3c0df024881c4001000005b41', 57553902: 'bf010000004c89e6ff159cc0df024989c64881fb8100000073084c89f7e840', 57553936: '48c1e3054c89ff4889de31d2ff157ec0df024c89f7e826d6d002'}


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
    site = 0x36e33bd
    off = va_offset(data, site, 5)
    if data[off] != 0xe8 or site + 5 + struct.unpack_from('<i', data, off + 1)[0] != 0x3df8160:
        raise ValueError('selected direct-call target mismatch')
    site = 0x5348713
    off = va_offset(data, site, 6)
    if data[off:off + 2] != b"\xff\x15" or site + 6 + struct.unpack_from('<i', data, off + 2)[0] != 0x64e4e18:
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
            if address == 0x64e4e18:
                matches.append((info, addend))
    if matches != [(8, 0x36e3320)]:
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
    print(f'OK: {count} anchors, direct call and indirect slot relocation; {count} anchor mutations rejected')


if __name__ == '__main__':
    main()
