#!/usr/bin/env python3
"""Check bounded instruction anchors and direct calls in node #115; no execution."""
import hashlib
import struct
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
TARGET = ROOT / 'artifacts/node/115/hl-node'
SHA = 'a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301'
ANCHORS = {92350448: '55415741564155415453504989c94929d10f84c20000004d85c00f84b90000004c89c84801f8490f43c14989ff4929d74989fc4929cc4d89c54d29fd0f86a60000004c39c00f83010100004889d54d39e00f86960100004d29e74a8d04fd00000000488d1c40488d041e49c1e5034a8d146d000000004c01ea4989fd4889c74989f648890c24ff15eccccc004d29fd4a8d046d000000004c01e8498d34c64c89f74889daff15cecccc00488d046d000000004801e8498d34c6488b0424488d0440498d3cc649c1e4034b8d1464488b05a4cccc00e9ec010000', 92350780: '4d29e00f86270100004d29fc488d0452488d04c6488d0c49488d1cce49c1e7034f8d347f488b2d01cccc004889df4989f74889c64c89f24d89c5ffd54c01f349c1e4034f8d34644889df4c89fe4c89f2ffd54d01fe49c1e5034a8d146d000000004c01ea4c89ff4c89f64889e8e907010000', 92351154: '4c89e04883c4085b415c415d415e415f5dffe0'}


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
