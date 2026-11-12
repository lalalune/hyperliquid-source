#!/usr/bin/env python3
"""Check bounded instruction anchors and direct calls in node #115; no execution."""
import hashlib
import struct
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
TARGET = ROOT / 'artifacts/node/115/hl-node'
SHA = 'a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301'
ANCHORS = {87520617: 'f20f104d40660f57c0660f2ec875597a574c8b742470488d9c24f0000000488b8c24100100004885c97469488b942418010000488b84242001000048c74424180000000048894c2420488954242848c74424380000000048894c24404889542448b901000000eb30498b5e104885db74a0498b064885c0f20f114c24780f8400010000498b4e08ba010000004889dee9f3000000', 87521074: '488dbc24f00000004c89e6e86ee87f004c8b7424700f57c0f2480f2a84240001000066480f6ecb660f620daf9a0dfb660f5c0d078a0dfb660f28d1660f15d1f20f58d1f20f5ec2f20f100d2f1b0efbf20f5cc8f20f10442478660f2ec1488b8424f0000000488bbc24f800000073134885c0488d9c24f00000000f84d5fdffffeb19', 95903664: '554157415641554154534881ece80000004889f348897c24404889f7e85f275cff4885c00f84ee000000488b4b4848894c24284c8d64241048895c2408eb1490488b7c2408e836275cff4885c00f84c50000008b4810894c242048894424300f10000f29442410488b4424284c8b384d85ff0f84c1000000488b4424284c8b6808498d7708410fb787e600000048894424388d048500000000488d2c8048c7c3ffffffff6666662e0f1f8400000000004885ed744b4c8d7614ba140000004c89e7ff15d99a960048984885c00f98c10f9fc028c848ffc34883c5ec4c89f63c0174ce0fb6c085c00f8453ffffff4983ed017318eb4466662e0f1f840000000000488b5c24384983ed01722e4d8bbcdfe8000000e969ffffff488b44244048c7000000000048c740080100000048c7401000000000e98a050000488b4c24308b4110898424a00000000f10010f29842490000000bf50000000ff15729396004885c00f849b0500008b8c24a00000008948100f288424900000000f110048c7442410040000004889442450488944241848c744242001000000'}


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
    for site, target in ((0x537773d, 0x5b75fb0), (0x5b75fcc, 0x5138730), (0x5b75ff5, 0x5138730)):
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
    print(f'OK: {count} anchors, 3 direct-call targets; {count} anchor mutations rejected')


if __name__ == '__main__':
    main()
