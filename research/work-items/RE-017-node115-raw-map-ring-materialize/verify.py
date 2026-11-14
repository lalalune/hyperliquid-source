#!/usr/bin/env python3
"""Check bounded instruction anchors and direct calls in node #115; no execution."""
import hashlib
import struct
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
TARGET = ROOT / 'artifacts/node/115/hl-node'
SHA = 'a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301'
ANCHORS = {85317152: '415741564154534881ec880000004889fb0f10060f104e100f294c24500f29442440488d7c2418488d742440e80f2fa200', 95946080: '55415741564155415453504989f4488b6e18488d04ed000000004c8d344048b855555555555555054839c5760d31ff4c89f6ff1500ef95000f0b4889fb4d85f60f840a0100004c89f7ff15d1ee95004885c00f841d0100004989c74989ed498b0424498b7c24084885ed0f84fb00', 95946192: '498b5424104531e44839c24889c1490f42cc4829ca4889c14829d1488d342a4839e9480f42f04839f27445488d1452488d14d74839cd4889ce480f42f548c1e603488d34764531e44531c00f1f4400004e8b4c02104f894c071042', 95946272: '4e8b4c02104f894c0710420f100402430f11040749ffc44983c0184c39c675e04839e973394b8d1464498d14d7480f47cd48c1e103488d0c494929ce31c96690488b740f104889740a100f10040f0f11040a49ffc44883c1184939ce75e24885', 95946368: 'c0741048c1e003488d344031d2ff150dee95004c892b4c897b084c8963104889d84883c4085b415c415d415e415f5dc341bf080000004531ed498b0424498b7c24084885ed0f8505ffffff4531e44885c075b0ebbebf08000000e9b0feffff'}


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
    for site, target in ((0x515d64c, 0x5b80560),):
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
