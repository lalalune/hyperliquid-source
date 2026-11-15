#!/usr/bin/env python3
"""Check bounded instruction anchors and direct calls in node #115; no execution."""
import hashlib
import struct
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
TARGET = ROOT / 'artifacts/node/115/hl-node'
SHA = 'a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301'
ANCHORS = {95396807: '488d7c24604c89fe48894c2418e8679a87ff488b4424604c8b64246848', 87506496: '554157415641554154534881ecf80100004989d74889bc247001000048c78424a800000000000000', 87506851: '488b8424b0000000486bcb68', 87506940: '48ffc348899c24b8000000', 87506960: '488dbc24b0010000e8434eaaff4885c00f84460a00004889d3807a200074e1488b0b4c39', 87507600: '488d742410e81643fdff4c89ff488bb424a00100004c89eae8c33c35fe4189c64c89efe8a828edff4584f60f846ffeff', 87509553: '488b8c247801000048894c24104889442438488b9c24b8000000483b9c24a80000000f', 87509612: '488b8c24b8000000488b842470010000488948100f108424a80000000f11004881c4f8', 95396825: '488b4424604c8b642468488b4c2470486bd968498d141c4c896424404c8964244848'}


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
    for site, target in ((0x5afa3d4, 0x5373e40), (0x5374018, 0x4e18e60), (0x5374295, 0x53485b0), (0x53742a8, 0x36c7f70), (0x53742b3, 0x5246b60)):
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
