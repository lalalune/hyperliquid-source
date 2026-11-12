#!/usr/bin/env python3
"""Check bounded instruction anchors and direct calls in node #115; no execution."""
import hashlib
import struct
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
TARGET = ROOT / 'artifacts/node/115/hl-node'
SHA = 'a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301'
ANCHORS = {83457180: '4881fe0110000048897424304889f0731d48d1e84889f14829c14883f940b840000000480f42c14889442420eb274883c801480fbdc889c8d1e883e10101c1b80100000048d3e048d3ee4801c648d1ee4889742420', 83457408: '488d345b488b442410488d3cf04c3b4c2420734c807c244c0074554983f920b8200000004c0f43c8488b442428488904244c89ce4889e94531c04d89cf4531c94d89deff15074355014d89f3488b5424184489f8e9570100000f1f80000000004983f902732a4c89c8e9420100006690488b4424204939c14c0f43c84d01c9e9340100006666662e0f1f840000000000488b0f4c8b57184939ca4d89ce723ab8020000004983f9020f8402010000488b442450488d34f0b8020000004d89d0904d89c14c8b064d39c8725f48ffc04883c6184939c675e9eb3e4983f902750cb802000000b901000000eb63488b442450488d34f0b8020000004d89d00f1f40004d89c14c8b064d39c8731f48ffc04883c6184939c675e94d89f14c89f0483b4424200f82ecfeffffeb0e4d89f1483b44'}


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
