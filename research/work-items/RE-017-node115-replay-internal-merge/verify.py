#!/usr/bin/env python3
"""Check bounded instruction anchors and direct calls in node #115; no execution."""
import hashlib
import struct
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
TARGET = ROOT / 'artifacts/node/115/hl-node'
SHA = 'a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301'
ANCHORS = {80345742: '4c8b7618450fb796e60000004c89d04883fa01750b488b46280fb780e60000004839c10f87830300004c8b6e28450fb78de60000004f8d040a', 80345848: '48894c2450488b46204889442430498d420148894424104c896c24184c8b7e1066458986e6000000', 80346346: '6641ff8c24e6000000bee800000048837c2460024c8b7c2418488b0c244c8d61010f82ea000000488b6c2408488d5d014c8d2c2949ffc54c89e84829c84839c30f853c', 80346416: '498d86e80000004a8d3ce0498db7e80000008d14dd00000000ff15b9f783014c89e04883e30374', 80346456: '488b0424498d0cc64881c1f000000031c00f1f8000000000488b14c14c8932418d34046689b2e400000048ffc04839c375e64c01e0', 80346528: '498b8cc6e80000004c8931668981e4000000498b8cc6f00000004c89318d5001668991e4000000498b8cc6f80000004c89318d5002668991e4000000498b8cc6000100004c8931488d5003668991e40000004883c0044c39ea75a5', 80346619: '31db4c89ff31d2ff1598f68301f644243801490f45dc48035c2440488b4424484c8930488b4c24304889480848895810'}


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
