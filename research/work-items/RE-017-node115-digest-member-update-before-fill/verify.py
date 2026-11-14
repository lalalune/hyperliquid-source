#!/usr/bin/env python3
"""Check bounded instruction anchors and direct calls in node #115; no execution."""
import hashlib
import struct
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
TARGET = ROOT / 'artifacts/node/115/hl-node'
SHA = 'a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301'
ANCHORS = {95396801: '4989f64989ff488d7c24604c89fe48894c2418e8679a87ff', 87629498: '4d89ee4d8dbdb80d000031db4c8da424300100004c8dac2420070000488d6c2420eb104c89ff4c89eee87867e4ff488b4424', 87629618: '488d0489488d04818b4c0710898c24500200000f1004070f298424400200000fb6440714eb48', 87629728: '3c0274588b8c2450020000898c2430070000660f6f842440020000660f7f842420070000a8010f8411ffffff8b84245002000089842440010000660f6f842440020000660f7f8424300100004c89ff4c89e6e8e90ae4ffe9ecfeffff', 87629820: '488d7c2420e82a6004004c89f731f6e8708e13004c89f7be01000000e8638e13004c89f7be02000000e8568e13004c89f7be03000000e8498e1300', 88911970: '488dbd503e0000488d95083f0000488d4c24084889eee833f36200', 87506808: 'f20f104638f20f118424c0000000488b014889842498000000', 87508629: '4c8d7614ba14000000488d7c2410ff15a7b4160148984885c00f98c10f9fc028c849ffc74883c5ec4c89f63c0174cc0fb6c0'}


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
    for site, target in ((0x5391ee3, 0x51d8660), (0x5391ff2, 0x51d2ae0), (0x5392032, 0x54cae80), (0x54cb078, 0x5afa3b0), (0x5afa3d4, 0x5373e40)):
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
    print(f'OK: {count} anchors, 5 direct-call targets; {count} anchor mutations rejected')


if __name__ == '__main__':
    main()
