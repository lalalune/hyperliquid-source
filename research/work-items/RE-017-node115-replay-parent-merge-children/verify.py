#!/usr/bin/env python3
"""Check bounded instruction anchors and direct calls in node #115; no execution."""
import hashlib
import struct
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
TARGET = ROOT / 'artifacts/node/115/hl-node'
SHA = 'a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301'
ANCHORS = {79910072: '440fb785e6000000428d1400ffc283fa0c0f83dd030000498d340048ffc64883fe0c0f83fd0300000fb793e6000000498d780148897c240848894c241848894424104c89442420e9', 79910243: '450fb788e60000004a8d340848ffc64883fe0c0f8347030000488d780148897c24084889cd4c894424184531ff48894424204c894c24100fb7c2488944244848897424386689b5', 79910762: '66ff8be6000000bee80000004983fe024c8b7c24180f82bbfcffff488b54241048ffc24c8b6424384c89e0482b4424204839c20f8553010000488d85e80000004c8b6c24084a8d3ce8498db7e8000000c1e2', 79910845: 'ff15459d8a014489e14429e9ffc14c89e883e103742b4c89ea662e0f1f840000000000488d4201488bb4d5e800000048892e668996e40000004889c248ffc975e24c89e14c29e9be4801000083f9030f822efc', 79910916: 'be4801000083f9030f822efcffff66666666662e0f1f840000000000488b8cc5e8000000488929668981e4000000488b8cc5f00000004889298d5001668991e4000000488b8cc5f80000004889298d5002668991e4000000488b8cc500010000488929488d5003668991e40000004883c004', 79909952: '4c89ff31d2ff1555a08a010fb783e60000006683f80477c6'}


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
