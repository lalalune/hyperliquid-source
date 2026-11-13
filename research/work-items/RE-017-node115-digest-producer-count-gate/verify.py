#!/usr/bin/env python3
"""Check bounded instruction anchors and direct calls in node #115; no execution."""
import hashlib
import struct
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
TARGET = ROOT / 'artifacts/node/115/hl-node'
SHA = 'a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301'
ANCHORS = {87506808: 'f20f104638f20f118424c0000000488b014889842498000000', 87507876: '488dbc24e0000000488d742410e88a4dfdfff20f108424c0000000660f57c9660f2ec1b301488b9424e0000000754b7a49', 87508064: '31d2b101b8000000004901d34c8dac24080100000f8241060000', 87508512: '488d72014989cc488d04928b54811889542420660f10448108660f294424104d8b294d85ed0f8415feffff', 87508624: '4885ed744b4c8d7614ba14000000488d7c2410ff15a7b4160148984885c00f98c10f9fc028c849ffc74883c5ec4c89f63c0174cc0fb6c085c07445', 87508752: 'ba010000004c8b8c2498000000488bac24a00000004c8b9424d80000004c8b9c24d0000000488bb424c8000000e920fdffff', 87508864: '66490f6ec3f30f7e1583ca0dfb660f62c2660f281dd7b90dfb660f5cc3660f28c8660f15c8f20f58c8f3410f7e4110660f62c2660f5cc3660f28d0660f15d0f20f58d0f20f599424c0000000660f2eca0f97c34c8bbc24', 87509032: '84db488d5c24180f84fbf8ffff'}


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
    for site, target in ((0x53743b1, 0x5349140),):
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
