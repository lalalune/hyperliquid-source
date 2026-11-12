#!/usr/bin/env python3
"""Check bounded instruction anchors and direct calls in node #115; no execution."""
import hashlib
import struct
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
TARGET = ROOT / 'artifacts/node/115/hl-node'
SHA = 'a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301'
ANCHORS = {87331341: '488d7c2430488d742440488d542410e80f0596ff0f10442430488b4424100f11', 80386128: '8d48016641898fe6000000488d04808b4c247041894c8718660f6f442460f3410f7f44870849ff45000fb6', 80386184: '80fa0275334839c10f84b7030000488d511448895424280f10010f298424800000008b4910898c24900000004889d1eb27', 80386272: '8b94249000000089542410660f6f842480000000660f7f04244839c10f84be000000488d511448895424288b7110418970100f1001410f1100f30f6f442441660f6e4c2410660f6e542451660f74d1660f740424660fdbc2660fd7f840b60181ffffff00000f858c000000f30f6f01660f7f04248b4910894c24104839c274644889d18b5210418950100f1001410f1100f30f6f442441660f6e4c2410660f6e542451660f740424660f74d1660fdbc2660fd7d081faffff0000752c488d5114f3410f6f00660f7f0424418b7010897424104839c275a931f6eb100f1f44000031f6eb1331f6eb0a40b6014883c1144889ca48895424284088742440660f6f0424660f7f4424608b44241089442470410fb787e60000004883f80b0f824ffeffff'}


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
    for site, target in ((0x534921c, 0x4ca9730),):
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
