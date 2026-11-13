#!/usr/bin/env python3
"""Check bounded instruction anchors and direct calls in node #115; no execution."""
import hashlib
import struct
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
TARGET = ROOT / 'artifacts/node/115/hl-node'
SHA = 'a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301'
ANCHORS = {70818055: '488b442460488d04804c8b7c24204d8d24874983c4ec488b5c2418488d4483ec4889442410488b7c2408488d6fec', 70818112: '41c1ee1f4f8d04b6488b7c24084a8d3c87440fb64424384588c54e8d04ad000000004d01e8488b5c24284a8d1c834983c7140f1006410f1104248b7610418974241088d148f7d9488d0c89488b542410488d148a4889542410c1f81f4898488d0480488d6c85004983c4ec48ff4c2430746c', 70818226: 'ba1400000048897c24084889deff158b6115024189c64531ed48895c24284889d84585f60f994424387905488b4424080f1000410f11078b401041894710ba14000000488b5c24104889df4889eeff154a61150231c94889de85c00f99c20f892affffff4889eee922ffffff', 70818392: '31c031c94839eb0f93c00f92c14889fa480f42d38b7210418977100f1002410f1107488d0c89488d1c8b488d0480488d3c87483b7c24100f95c04839eb74a9b0014c'}


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
    for site, target in ():
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
    print(f'OK: {count} anchors, 0 direct-call targets; {count} anchor mutations rejected')


if __name__ == '__main__':
    main()
