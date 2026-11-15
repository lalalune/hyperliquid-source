#!/usr/bin/env python3
"""Check bounded instruction anchors and direct calls in node #115; no execution."""
import hashlib
import struct
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
TARGET = ROOT / 'artifacts/node/115/hl-node'
SHA = 'a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301'
ANCHORS = {4559848: '0000000000002440', 4544960: '00000000000000800000000000000080', 96750799: '896c242444895c24144489c54889ee4889c24c89f94889fb4989c6ff1508ae89004989c44889d648895424184889c1490fafcf49f7e64801ca490faff64801d64829c34819f54c8b2d6ccb89004889df4889ee41ffd5f20f114424084c89f74c89feff15b1148a00f20f104c2408f20f5ec8f20f114c24084c89e7488b74241841ffd5', 96750930: '660f57c9f20f105c2408660f2ed9751d7a1b837c241400785bb8010000004883c4285b415c415d415e415f5dc3660f28d3f20f58d0f20f11542408f20f1005534681fa8b7c2424ff15c1268a00660f28c8f20f11442418f20f10442408f20f59c1ff15d7ca8900f20f5e442418837c24140079a5660f5705f20b81faeb', 104792192: '660f28c889f8f7d80f48c7a8017406660f28c1eb17f20f1005139206faeb0d90f20f59c9a8017404f20f59c1d1e875f085ff7801c3f20f100df39106faf20f5ec8660f28c1c3', 104791616: '660f28c8660f2805745b06fa660f54c1660f5605081006faf20f58c166480f7ec04889c248c1ea3481e2ff07000081fa32040000773a8d8a01fcffff48be000000000000f0ff48d3fe81faff03000048b90000000000000080480f43ce4889ca48f7d24885c274084821c166480f6ec1c3'}


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
