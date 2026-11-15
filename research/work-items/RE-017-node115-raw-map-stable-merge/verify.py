#!/usr/bin/env python3
"""Check bounded instruction anchors and direct calls in node #115; no execution."""
import hashlib
import struct
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
TARGET = ROOT / 'artifacts/node/115/hl-node'
SHA = 'a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301'
ANCHORS = {83458352: '4d85ed0f84aafeffff4d39ef4c89e8490f42c74839c50f8297feffff4a8d0c6d000000004c01e9488d2ccb4d39fd4889de480f47f548c1e0034c8d24404889d74c89e2ff158f7b54014c8b4c24184d01cc4d39fd7667488b8424880000006690488d4de8498d5424e8498b7424e831ff4531c0483b75e8400f92c7410f93c0480f42d1488b4a10488948100f10020f11004b8d0c40488d6ccde8488d0c7f4d8d24cc4983c4e84839dd0f84d3fdffff4883c0e84d39cc75a8e9c5fdffff4c89ce4c8b8c24800000000f1f840000000000488b4d0031c031d2483b0e0f92c10f93c24889f7480f42fd4c8b47104c8943100f10070f1103488d1452488d34d64883c3184c39e60f847dfdffff88c8488d0440488d6cc5004c39cd75b5e968fdffff'}


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
