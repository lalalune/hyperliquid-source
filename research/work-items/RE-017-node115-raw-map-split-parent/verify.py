#!/usr/bin/env python3
"""Check bounded instruction anchors and direct calls in node #115; no execution."""
import hashlib
import struct
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
TARGET = ROOT / 'artifacts/node/115/hl-node'
SHA = 'a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301'
ANCHORS = {79951316: '4c89f34989c2410fb7a8e4000000440fb7b8e60000004983ff0b488904244c897424284c896c24400f8296040000', 79952536: '418d57014c8d6501664439fd0f83c9000000498d7a08498d34ea4883c608428d04e50000000048894424384801c74d89fd4929ef4e8d34fd00000000895424204c89f2488b1d86fa8901ffd3488d0c6d000000004801e9488b0424488d7488604b8d0464488b0c24488d3c814883c76049c1e7024b8d147f4d89efffd3488b442408488b0c24488d146d000000004801ea48894491608b442410488b0c2489449168488b0424488b4c2438488db408e80000004c8b6c2440488b0424488d3ce84881c7f80000004c89f2ffd38b542420488b5c24284c8b1424eb1e488d046d000000004801e88b4c241041894c8268488b4c240849894c8260488b7c24784c8b5c24704c8b7424684d896cea08498d470249899ceaf000000066418992e60000004139c40f83bf0000004489f929e9ffc14929ef83e10374404989f9498d34ea4881c6f000000031d26666666666662e0f1f840000000000488b3cd64c8917458d041466448987e400000048ffc24839d175e54901d44c89cf4183ff03726a660f1f8400000000004b8b8ce2e80000004c8911664489a1e40000004b8b8ce2f00000004c8911418d542401668991e40000004b8b8ce2f80000004c8911418d542402668991e40000004b8b8ce2000100004c8911418d542403668991e40000004983c4044939c4759f4c8b7c2418'}


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
