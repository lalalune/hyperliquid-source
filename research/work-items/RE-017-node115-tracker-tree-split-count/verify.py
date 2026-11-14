#!/usr/bin/env python3
"""Check bounded instruction anchors and direct calls in node #115; no execution."""
import hashlib
import struct
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
TARGET = ROOT / 'artifacts/node/115/hl-node'
SHA = 'a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301'
ANCHORS = {81679862: '48be00000000000000804d8b6e184d85ed0f841f010000498d6e0848837d00000f84400400004889ef4889d6e859efebff4989c74989d448894424304889542438488d5424304c89ef4889eee829e5ebff48be00000000000000804989d5498946184c897c24104c896424284c89642418', 80362352: '4889f8488b7e08488b4a084839cf0f8387000000488b160fb78a7a0300004885ff0f84f00000004531c9660f1f4400004c89ce4989d04a8b94ca80030000440fb78a7a0300004c01c941b90000000048ffcf75dc410fb7907a030000bf010000004839d6730a4c89c2eb280f1f440000498b104885d20f849b00000048ffc7410fb7b0780300004989d0663bb27a03000073dd48ffc64989f1eb95488b320fb7967a0300004885c974774531c90f1f004c89cf4989f04a8bb4ce80030000440fb78e7a0300004c01ca41b90000000048ffc975dc410fb7b07a030000b9010000004839f7730a4c89c6eb240f1f440000498b304885f6742948ffc1410fb7b8780300004989f0663bbe7a03000073e148ffc74989f9eb994829c84889c24889c8c34829d0c3'}


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
    for site, target in ((0x4de5622, 0x4ca4580), (0x4de5642, 0x4ca3b70)):
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
    print(f'OK: {count} anchors, 2 direct-call targets; {count} anchor mutations rejected')


if __name__ == '__main__':
    main()
