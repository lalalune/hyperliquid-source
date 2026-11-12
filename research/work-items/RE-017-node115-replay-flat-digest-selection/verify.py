#!/usr/bin/env python3
"""Check bounded instruction anchors and direct calls in node #115; no execution."""
import hashlib
import struct
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
TARGET = ROOT / 'artifacts/node/115/hl-node'
SHA = 'a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301'
ANCHORS = {95395908: '488d7e60488b467831f6482de8030000480f43f0488974243848c744244000000000498d4648498db688000000488914244c897424084889442410488974241848894c2420488d4424404889442428488d44243848894424304889e6e89b642eff', 81659209: '4881ecd00000004889fb49bd000000000000008031c0483b070f818f000000', 81659383: '4889dfe89110a100488b4318', 92214942: '48897424104989fe4c8b67184d85e4745e498b5e104d8b3e498b4608488d0c', 92214992: '4a8d042b4c39f8b800000000490f43c748c1e003488d04404883c5184889ee4829c6488b7c2410e8d42dfeff84c0741c49ffc54d39ec75c8e93f010000', 92095713: '4989f748bd08ac1c5a643bdfff48bb115839b4c876beff488b0648898424800000004c8b2f48897c2478488b4718f20f10008b4610898424d8000000488b460848898424d0000000ff1541cad000', 92096026: '418b1424413955000f9dc27433e950010000c7442410000000004c8d259533c9fa488d059633c9fa488d0d8b33c9fa418b1424413955000f9dc20f85220100008b0941394d040f93c20f85130100008b00413945080f820f01000049be0000000000000080488b5c2478488b7308488d7c24104c8bbc24800000004c89fae85337baff498d460148394424100f849c030000', 92096380: '84d20f85f1feffff4983c708418b4708898424d8000000498b0748898424d0000000f20f1005724fc8faff15c4c7d000'}


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
    for site, target in ((0x5afa0a0, 0x4de0540), (0x4de05fa, 0x57f1690), (0x57f16f7, 0x57d44d0), (0x57d4698, 0x5377df0)):
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
