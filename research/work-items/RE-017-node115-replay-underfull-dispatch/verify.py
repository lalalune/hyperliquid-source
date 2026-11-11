#!/usr/bin/env python3
"""Check bounded instruction anchors and direct calls in node #115; no execution."""
import hashlib
import struct
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
TARGET = ROOT / 'artifacts/node/115/hl-node'
SHA = 'a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301'
ANCHORS = {80920824: '418d47ff668985e60000004d8b6424086683f8040f8793010000488b45004885c00f8404010000498d4c24010fb795e40000004885d27453488b', 80920880: '488bb4d0e000000048ffca488944244848894c2450488954245848897424604c8964246848896c24704c896424780fb786e60000004101c74183ff0c0f838b000000488d7c2408488d742448ba0100', 80920963: '6683b8e6000000000f8475010000488b90f0000000488984248000000048898c248800000048c7842490000000000000004889ac24980000004c89a424a000000048899424a80000004c89a424b00000000fb782e60000004101c74183ff0c', 80921060: '488d7c2408488db4248000000031d24c89e9e88538f7ffeb35488d7c2448be01000000e82464f6ff49ffc5eb12488dbc2480000000be01000000e86dc1f6ff48896c24084c896424', 80921138: '488b6c24084c8b6424104c8b6c2418488b7d004885ff745b498d742401e8ac91f0ff84c0754d'}


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
    for site, target in ((0x4d2c1f6, 0x4c9fa80), (0x4d2c207, 0x4c92630), (0x4d2c21e, 0x4c98390), (0x4d2c24f, 0x4c35400)):
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
