#!/usr/bin/env python3
"""Check bounded instruction anchors and direct calls in node #115; no execution."""
import hashlib
import struct
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
TARGET = ROOT / 'artifacts/node/115/hl-node'
SHA = 'a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301'
ANCHORS = {88911505: '4889fd8b476889442418488b47604889442410488d87b80d00004889442408400fb6c6488d0db5bb45fb486304814801c8ffe0', 88911970: '488dbd503e0000488d95083f0000488d4c24084889eee833f36200', 95396801: '4989f64989ff488d7c24604c89fe48894c2418e8679a87ff', 95396885: '498b461048894424104983c660', 95397045: '488d7c2420498d77604c89ea4c89f14c8d0565239c00e8103d2cff', 88653517: '498d5c246066410f1104248b430889842428020000488b034889842420020000498db424983d00004d8db424083f00004c8dbc24c0000000488d9424200200004c89ff4c89f1e8d8e266008b430889842428020000488b034889842420020000498db424503e0000488d9c2430010000488d9424200200004889df4c89f1e8e0e06600', 95395942: '498d4648498db688000000488914244c897424084889442410488974241848894c2420488d4424404889442428488d44243848894424304889e6e89b642eff', 92095736: '488b0648898424800000004c8b2f48897c2478488b4718f20f1000'}


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
    for site, target in ((0x54cb078, 0x5afa3b0), (0x5afa4cb, 0x4dbe1e0), (0x548bf4b, 0x5afa030), (0x5afa0a0, 0x4de0540)):
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
    print(f'OK: {count} anchors, 4 direct-call targets; {count} anchor mutations rejected')


if __name__ == '__main__':
    main()
