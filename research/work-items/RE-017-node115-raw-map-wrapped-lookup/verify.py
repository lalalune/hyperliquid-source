#!/usr/bin/env python3
"""Check bounded instruction anchors and direct calls in node #115; no execution."""
import hashlib
import struct
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
TARGET = ROOT / 'artifacts/node/115/hl-node'
SHA = 'a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301'
ANCHORS = {81519451: '48bb00000000000000804939df0f84d0010000488db424d00000004c89f7e852b2a3004885c00f95c1498b76184883fe40400f93c74084f90f848d000000', 92247504: '488b47184885c00f8491000000488b174c8b471031c94939d0480f43ca4929c84c29c24989c14929d1767a488b7f084c8b17488b0e4939ca0f97c01c000fb6c084c00f84be0000003dff0000000f85b400000031f64983f901742e0f1f4400004889f04d89c849d1e84c01c64c8d14764a390cd7480f47f04d29c14983f90177df488d04764c8b14c74939ca74044883d60031c04939ca0f95c04801f2c331d24531c0eb064c01c04889c24b8d0c4048c1e10348034f084c29c2b8010000004885d27455488b3631ff4883fa017422904989f84989d149d1e94c01cf4c8d147f4a3934d1490f47f84c29ca4883fa0177df488d147f483934d1750431c0eb044883d7004889fac34b8d0440488d0cc7b8010000004885d275ab31d2c3'}


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
    for site, target in ((0x4dbe379, 0x57f95d0),):
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
