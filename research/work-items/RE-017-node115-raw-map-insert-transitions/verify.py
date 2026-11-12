#!/usr/bin/env python3
"""Check bounded instruction anchors and direct calls in node #115; no execution."""
import hashlib
import struct
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
TARGET = ROOT / 'artifacts/node/115/hl-node'
SHA = 'a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301'
ANCHORS = {95397045: '488d7c2420498d77604c89ea4c89f14c8d0565239c00e8103d2cff', 81519072: '554157415641554154534881ecd800000048894c24084989d44989f648897c246848899424d00000004c8b3e488b46184c89f948f7d90f90c14883f8200f92c220ca80fa010f8530010000498b4e08498b561049', 81519243: '48898c248800000048898c24a800000048898424c8000000488d7c2410488db42488000000e8ab85dc00', 81519427: '4d893e49895e0849c7461000000000488b4424604989461848bb00000000000000804939df0f84d0010000488db424d00000004c89f7e852b2a3004885c00f95c1498b76184883fe40400f93c74084f90f848d000000410f1006410f104e100f294c24200f2944241049c706000000004d8d7e0849c74608080000000f57c0410f114610488d7c2470488d742410e84af23900498b064839d80f8597000000498b0f4885c90f84ff000000498b', 92247641: '4939ca74044883d60031c04939ca0f95c04801f2c331d24531c0eb06', 81659794: '488b43184c392b0f94c14883f8200f92c220ca80fa010f8529010000'}


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
    for site, target in ((0x5afa4cb, 0x4dbe1e0), (0x4dbe2b0, 0x5b86860), (0x4dbe379, 0x57f95d0), (0x4dbe3d1, 0x515d620)):
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
