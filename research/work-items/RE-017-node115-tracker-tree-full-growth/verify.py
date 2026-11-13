#!/usr/bin/env python3
"""Check bounded instruction anchors and direct calls in node #115; no execution."""
import hashlib
import struct
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
TARGET = ROOT / 'artifacts/node/115/hl-node'
SHA = 'a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301'
ANCHORS = {80386543: '410fb787e60000004883f80b0f824ffeffff31db666666662e0f1f8400000000004d8b3f4d85ff741848ffc3664183bfe60000000b73eaeb5e0f1f8400000000004d8b3424498b5c2408bf48010000ff153c5a83014885c00f84310300004989c748c7000000000066c780e600000000004c89b0e800000048ffc30f84200300004d893e6641c786e400000000004d893c2449895c2408', 80386694: '4c89e5bfe8000000ff15ec5983014885c00f84b40200004989c44989de48c7000000000066c780e6000000000049ffce744a0f1f840000000000bf48010000ff15b55983014885c00f845202000048c7000000000066c780e600000000004c89a0e8000000498904246641c78424e400000000004989c449ffce75be', 80386818: '410fb787e60000004883f80b0f834f0200008d48016641898fe6000000488d0c808b5424704189548f18660f6f442460f3410f7f448f084d89a4c7f000000048ffc04d893c246641898424e40000004885db0f84ce000000'}


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
