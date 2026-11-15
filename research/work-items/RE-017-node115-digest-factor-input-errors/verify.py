#!/usr/bin/env python3
"""Check bounded instruction anchors and direct calls in node #115; no execution."""
import hashlib
import struct
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
TARGET = ROOT / 'artifacts/node/115/hl-node'
SHA = 'a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301'
ANCHORS = {87609921: '4983fe650f8355340000', 87609987: '0fb74424203da20100000f858b530000', 87610037: '4983ff650f83a3680000', 87610090: '0fb74424203da2010000f30f7e9c24000200000f85f27a0000', 87623328: '4885ed740e4889df4889ee31d2ff15eded1401488b4424084c89701866c7005801e9c91f0000', 87631390: '0fb74c2426488b54240866894a068b4c2422894a02f20f104424280f284c24400f294a200f284c24500f294a300f284c24600f294a400f284c24700f294a500f288c24800000000f294a60660f284c2430660f294a10668902f20f1142084885ed740e4889df4889ee31d2ff1511ce1401', 87636834: '4d85e4740e4c89ef4c89e631d2ff152bb91401488b4424084c89781866c7005801e963120000', 87641589: '0fb74c2426488b54240866894a068b4c2422894a02f30f7e4424280f284c24400f294a200f284c24500f294a300f284c24600f294a400f284c24700f294a500f288c24800000000f294a60660f284c2430660f294a10668902660fd642084d85e474934c89ef4c89e631d2ff153aa61401488b6c2408eb33', 87648978: '31d2ff15c6891401e9c1e3ffff'}


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
