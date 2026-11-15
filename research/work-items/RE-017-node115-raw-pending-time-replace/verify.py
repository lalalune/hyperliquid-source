#!/usr/bin/env python3
"""Check bounded instruction anchors and direct calls in node #115; no execution."""
import hashlib
import struct
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
TARGET = ROOT / 'artifacts/node/115/hl-node'
SHA = 'a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301'
ANCHORS = {95396801: '4989f64989ff488d7c24604c89fe48894c2418e8679a87ff488b4424604c8b642468488b4c2470', 95396885: '498b461048894424104983c6604983c468662e', 95396917: '498b4424a048b901000000000000804839c80f843c0100004d8b6c24984889442478498b44', 95397006: '498b87800000004939c5490f47c50f11450049898780000000', 95397045: '488d7c2420498d77604c89ea4c89f14c8d0565239c00e8103d2cff', 81519072: '554157415641554154534881ecd800000048894c24084989d44989f648897c246848899424d00000004c8b3e488b4618', 81519770: '4839f20f83b1010000498b46104801d031d24839c8480f43d14829d0498b4e08488d0440488d34c14883c608488b5424088b4e08488b442468894808488b0e488908488b0a48890e8b4a08894e08e93c010000', 81519984: '4d85c0743b4c3b64d010410f97c14180d9004883c60c48ffc24983c0f84180f90174dd410fb6f985ff0f8427ffffff'}


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
    for site, target in ((0x5afa3d4, 0x5373e40), (0x5afa4cb, 0x4dbe1e0)):
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
