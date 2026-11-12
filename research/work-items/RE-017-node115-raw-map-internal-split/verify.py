#!/usr/bin/env python3
"""Check bounded instruction anchors and direct calls in node #115; no execution."""
import hashlib
import struct
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
TARGET = ROOT / 'artifacts/node/115/hl-node'
SHA = 'a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301'
ANCHORS = {79951316: '4c89f34989c2410fb7a8e4000000440fb7b8e60000004983ff0b488904244c897424284c896c24400f82960400006683', 79951362: '6683fd054c89bc2480000000731041bf040000004531f6eb350f1f4400004883fd05741283fd06751541b60141bf0500000031edeb184531f64989efeb104883c5f941b60141bf060000000f1f00bf48010000ff1525fe89014885c00f84930600004989c44489b4248c0000004989c649c70424000000006641c78424e60000000000488b14240fb782e60000004d89fd49f7d54901c5664589ac24e60000004a8b74fa084b8d047f8b4c8268894c2460488b44826048894424584983fd0c0f83df0500004889742420488d4208488d4a6048894c24384a8d34f84883c608498d7c24084a8d14ed00000000488b1d13fe8901ffd34b8d047f4883c003488b4c2438488d3481498d7c246049c1e5024a8d146d000000004c01eaffd3488b0c24664489b9e6000000488b44245848894424488b44246089442450450fb7aee6000000498d55014983fd0c0f8370050000488b8424800000004429f839d00f85a205000048ff442430498dbc24e80000004a8d34f94881c6f0000000c1e203ff1582fd890131c00f1f84000000'}


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
