#!/usr/bin/env python3
"""Check bounded instruction anchors and direct calls in node #115; no execution."""
import hashlib
import struct
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
TARGET = ROOT / 'artifacts/node/115/hl-node'
SHA = 'a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301'
ANCHORS = {80920880: '488bb4d0e000000048ffca488944244848894c2450488954245848897424604c8964246848896c24704c896424780fb786e60000004101c74183ff0c0f838b000000488d7c2408488d742448ba0100', 80921085: '488d7c2448be01000000e82464f6ff49ffc5', 80291390: '488b6f28440fb7ade60000004a8d042e4883f80c0f83910200004889f34c8b6718450fb7bc24e60000004d89fe4929f60f828e02000048897c2440664589b424e60000004889442438668985e6000000', 80291470: '488d7508488d3cdd080000004801ef428d14ed000000004889542428ff15b8ce8401488d7560488d045b488d3c85600000004801ef4c896c2430428d04ad00000000488d1440ff158ece84014d8d6e01', 80291546: '4d8d6e014d29ef488d43ff4939c70f852d0200004b8d34ec4883c608428d14fd00000000488d7d08ff1500ce84014c896c24204a8d046d000000004c01e8498d34844883c66041c1e7024f8d2c7f4c8d7d604c89ff4c89eaff15d0cd8401', 80291640: '4b8b44f4084b8d0c76498b548c6048891424418b4c8c68894c24084c8b442440498b08498b5010488d3452488b7cd108488944d1088b44b16889442418488b44b1604889442410488b0424488944b1608b4424088944b16848897cdd008b4424184389442f08488b4424104b89042f', 80291751: '4983782000498b4030746d4885c07471', 80291871: '4885c00f84b200000048'}


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
    for site, target in ((0x4d2c207, 0x4c92630),):
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
