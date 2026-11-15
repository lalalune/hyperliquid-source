#!/usr/bin/env python3
"""Check bounded instruction anchors and direct calls in node #115; no execution."""
import hashlib
import struct
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
TARGET = ROOT / 'artifacts/node/115/hl-node'
SHA = 'a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301'
ANCHORS = {87328480: '4983ff1573224c89f74c89fee80f7a0a00e926ffffff', 88015104: '554157415641554154534883ec384989f44989fe49c1e4054901fc488d472031db488b2d28fa0e01', 88015137: '488b2d28fa0e014c8d7c241048893c24', 88015172: '0f284424100f284c2420410f114c2410410f1104244c8b642408498d', 88015211: '4c89f64989c6ba200000004889c7ffd585c079df410f1006410f104e100f294c', 88015231: '410f1006410f104e100f294c24200f294424104989dd4d89f40f1f840000', 88015264: '410f104424e0410f104c24f0410f114c2410410f1104244d85ed74', 88015292: '498d7424c0ba200000004c89ffffd54983c4e04983c52085c078c9', 88015319: 'e968ffffff4883c4385b415c415d415e415f5dc3'}


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
    site, target = 0x53486ec, 0x53f0100
    off = va_offset(data, site, 5)
    if data[off] != 0xe8 or site + 5 + struct.unpack_from('<i', data, off + 1)[0] != target:
        raise ValueError('selected direct-call target mismatch')
    slot_site = 0x53f0121
    off = va_offset(data, slot_site, 7)
    if slot_site + 7 + struct.unpack_from('<i', data, off + 3)[0] != 0x64dfb50:
        raise ValueError('comparison slot mismatch')
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
    print(f'OK: {count} anchors, direct-call target and comparison slot; {count} anchor mutations rejected')


if __name__ == '__main__':
    main()
