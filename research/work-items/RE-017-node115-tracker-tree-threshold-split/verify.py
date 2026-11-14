#!/usr/bin/env python3
"""Check bounded instruction anchors and direct calls in node #115; no execution."""
import hashlib
import struct
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
TARGET = ROOT / 'artifacts/node/115/hl-node'
SHA = 'a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301'
ANCHORS = {81679847: '4c8b2e4c89e848f7d80f818e00000048be00000000000000804d8b6e184d85ed0f841f010000498d6e0848837d00000f84400400004889ef4889d6e859efebff4989c74989d448894424304889542438488d5424304c89ef4889eee829e5ebff48be00000000000000804989d549894618', 80364928: '554157415641554154534881ecb80000004989f448893c244c8b7f08bf80030000ff15d9ae83014885c00f84040900004989c548c7000000000066c7807a03000000004d85ff7457488b1db1ae83014d89fe66666666662e0f1f840000000000bfe0030000ffd34885c00f848008000048c7000000000066c7807a03000000004c89a880030000498945006641c7857803000000004989c549ffce75c3eb034c89e8498b1c244c897c241848894424104889c5488b0424eb240f1f80000000004d85ff0f84960100004b8d04f448058003000049ffcf488bad800300004c8b20498d442408450fb7ac247a0300004489e9c1e10348c7c2ffffffff0f1f4400004885c9741b4c8d72014883c1f8483b5cd0084c89f277e9eb0a0f1f80000000004d89ee6683bd7a030000000f85a60700004c89f14c29e9748748894c24084d29f5664589b4247a030000664489ad7a0300004a8d34f0488d7d084a8d14ed00000000ff1520ae83014b8d04f6498d34c44883c660488d7d604a8d04ed00000000488d14c0ff15fead83014d85ff0f84cc000000'}


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
    for site, target in ((0x4de5622, 0x4ca4580), (0x4de5642, 0x4ca3b70)):
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
    print(f'OK: {count} anchors, 2 direct-call targets; {count} anchor mutations rejected')


if __name__ == '__main__':
    main()
