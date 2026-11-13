#!/usr/bin/env python3
"""Check bounded instruction anchors and direct calls in node #115; no execution."""
import hashlib
import struct
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
TARGET = ROOT / 'artifacts/node/115/hl-node'
SHA = 'a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301'
ANCHORS = {81101296: '554156534889f8488d7e144c8b46384c8b4e28f606017413488b56088b4e104989fa85c9752fe9c80000004d39c10f84bf0000004d8d59184c895e28498b11418b49084983c10c4d89ca4d89d985c90f849e000000458b5a0844895c24f84d8b124c895424f04d39c10f848f0000004d8d51184c895628498b19458b590848895e0844895e10418b6914896f084d8b490c4c890f4585db746c0f1f80000000004839da75604489d9448b4f0844894c24f84c8b0f4c894c24f04d39c274404d8d4a184c894e28498b1a458b5a0848895e0844895e104d8b720c458b5214448957084c89374585db741c4d89ca4839da74b4eb1248c7060000000031c9eb21c746100000000048c706010000008b7424f8897014488b7424f04889700c48891089', 80488976: '488d5424688b4a08894c2418488b0a48894c24108d48016641898fe60000004d896cc708488d04408b4c241841894c8768488b4c241049894c876048ff034c89f74c89e6e897570900837c2468000f848b0200004c8b6c2460410fb787e60000004883f80b7299', 85317328: '7424684c896424704889442478488d7c2430488d742440488d542410e8ef51b6ff0f10442430488b4424100f110348894310eb2e48c7030000000048c7431000000000488b4424184885c07415488b7c242048c1e003488d344031d2ff156e1d38014889d84881c4880000005b415c415e415fc34983ff15732c488d4c2440ba010000004c89f74c89fee8312b2900e914ffffffbf08000000bee8000000ff15'}


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
    for site, target in ((0x4cc2a54, 0x4d581f0),):
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
    print(f'OK: {count} anchors, 1 direct-call target; {count} anchor mutations rejected')


if __name__ == '__main__':
    main()
