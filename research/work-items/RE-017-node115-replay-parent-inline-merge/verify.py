#!/usr/bin/env python3
"""Check bounded instruction anchors and direct calls in node #115; no execution."""
import hashlib
import struct
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
TARGET = ROOT / 'artifacts/node/115/hl-node'
SHA = 'a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301'
ANCHORS = {79910020: '4a8bacfbe000000049ffcf48895c245848897c24604c897c246848896c24704c8974247848898c24800000004c89b42488000000440fb785e6000000428d1400ffc283fa0c0f83dd030000498d340048ffc64883fe0c0f83fd030000', 79910160: '0fb793e60000006685d20f84ef0300004c8b83f000000048899c24900000004889bc249800000048c78424a00000000000000048898c24a80000004c89b424b00000004c898424b80000004c89b424c0000000450fb788e60000', 79910298: '0fb7c2488944244848897424386689b5e60000004a8d3cfb4883c7084e8b74fb084a8d34fb4883c6104d89fc49f7d44901c44a8d14e5000000004889542440488b05889f8a01ffd04c8b6c24204e8974ed08488b442418488d7008488b442408488d7cc508488b4424108d14c5000000004c8b35f69e8a0141ffd6', 79910421: '4b8d047f488d3c834883c7608b4c8368894c2430488b4c836048894c2428488d34834883c66c49c1e4024b8d14644c8b351e9f8a0141ffd64a8d046d000000004c01e8488b4c242848894c85608b4c2430894c8568488b442418488d7060488b442408488d0440488d7c8560488b4424108d048500000000488d1440ff15719e8a01', 79910551: '4d8d67014a8d3cfb4881c7f00000004a8d34fb4881c6f8000000488b54244041ffd6488b7424484c39e64c8b742450', 79910762: '66ff8be6000000bee80000004983fe024c8b7c24180f82bbfcffff488b54241048ffc24c8b6424384c89e0482b4424204839c20f8553010000488d85e80000004c8b6c24084a8d3ce8498db7e8000000c1e203ff15459d8a014489', 79909952: '4c89ff31d2ff1555a08a010fb783e60000006683f80477c6'}


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
