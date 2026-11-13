#!/usr/bin/env python3
"""Check bounded instruction anchors and direct calls in node #115; no execution."""
import hashlib
import struct
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
TARGET = ROOT / 'artifacts/node/115/hl-node'
SHA = 'a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301'
ANCHORS = {87328374: '4c897c2458c644246002488d7c2430488d742440488d542410e80cf39bff0f1044243048', 80771488: '554157415641554154534881ecb80000004989d54989fc4c8b3f488b4f084885', 80771792: '8d48016641898f6a010000c1e005660f6f442470660f6f8c2480000000f3410f7f4c0710f3410f7f', 80771838: '0fb6542420488b4c2408488b44241880fa02752e4839c10f84e2030000488d512048895424080f10', 80771867: '488d512048895424080f10010f1049100f298424900000000f298c24a00000004889', 80771993: '410f114810410f1100f30f6f442421f30f6f4c2431660f744c2460660f74442450660fdbc1660fd7f840b60181ffffff00000f85', 80772080: '4889d10f10020f104a10410f114810410f1100f30f6f442421f30f6f4c2431660f744c2460660f74', 80772131: '81faffff0000752d488d5120f3410f6f00f3410f6f4810660f7f442450660f', 80772199: '4088742420660f6f442450660f6f4c2460660f7f442470660f7f8c2480000000410fb7876a0100004883f80b0f82', 80772231: '410fb7876a0100004883f80b0f8237feffff31db0f1f4400004d8bbf600100', 80772256: '4d8bbf600100004d85ff741448ffc3664183bf6a0100000b73e6eb62', 80772522: '410fb7876a0100004883f80b0f83460200008d48016641898f6a01000089c1c1e105660f6f442470660f6f'}


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
    site, target = 0x534868f, 0x4d079a0
    off = va_offset(data, site, 5)
    if data[off] != 0xe8 or site + 5 + struct.unpack_from('<i', data, off + 1)[0] != target:
        raise ValueError('selected direct-call target mismatch')
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
    print(f'OK: {count} anchors, selected direct-call target; {count} anchor mutations rejected')


if __name__ == '__main__':
    main()
