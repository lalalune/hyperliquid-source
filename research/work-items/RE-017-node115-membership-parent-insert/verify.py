#!/usr/bin/env python3
"""Check bounded instruction anchors and direct calls in node #115; no execution."""
import hashlib
import struct
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
TARGET = ROOT / 'artifacts/node/115/hl-node'
SHA = 'a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301'
ANCHORS = {79927163: 'f6c1010f84110600004c89f64889ea4889c50fb792e4000000440fb7a8e60000004983fd0b4c897424480f820a040000', 79928245: '4989ef418d4d01488d5a01488d04924c8d3485080000004901ee664439ea736e498d4708890c24488d0c9b488d3c884d89ec4929d44a8d04a5000000004889d5488d14804c89f6ff1566598a010f28442420410f11068b44243041894610498d34df4881c6e8000000498d3cef4881c7f800000049c1e4034c89e2ff1532598a018b0c24488b7424484889eaeb118b442430418946100f28442420410f11', 79928404: '498d45024989b4d7f00000006641898fe600000039c3488b6c24400f83b50000004d89f94489e929d1', 79928480: '488b3cd64c890f448d041366448987e400000048ffc24839d175e54801d34183fd0372666666662e0f1f840000000000498b8cd9e80000004c8909668999e4000000498b8cd9f00000004c89098d5301668991e4000000498b8cd9f80000004c89098d5302668991e4000000498b8cd9000100004c89098d5303668991e40000004883c3044839c375'}


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
