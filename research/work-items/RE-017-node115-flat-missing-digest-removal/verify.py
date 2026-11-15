#!/usr/bin/env python3
"""Check bounded instruction anchors and direct calls in node #115; no execution."""
import hashlib
import struct
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
TARGET = ROOT / 'artifacts/node/115/hl-node'
SHA = 'a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301'
ANCHORS = {87522800: '554157415641554154534881eca80000004989f64989fc49bd00000000000000804889942480000000488b5e184889d848f7d80f817e0000004d8b7e204d85ff0f84a9010000', 87523295: '49ffc54d892c244c89e04881c4a80000005b415c415d415e415f5dc3', 92096117: '49be0000000000000080488b5c2478488b7308488d7c24104c8bbc24800000004c89fae85337baff498d460148394424100f849c030000', 92097089: '49ffc64c89731031c04881c4b80100005b415c415d415e415f5dc3', 92214992: '4a8d042b4c39f8b800000000490f43c748c1e003488d04404883c5184889ee4829c6488b7c2410e8d42dfeff84c0741c49ffc54d39ec75c8', 92215346: '4889e84c8b7424084c8b24244d39e573094c39e874044d896e184883c4385b415c415d415e415f5dc3'}


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
    for site, target in ((0x57d4698, 0x5377df0), (0x57f16f7, 0x57d44d0)):
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
