#!/usr/bin/env python3
"""Check bounded instruction anchors and direct calls in node #115; no execution."""
import hashlib
import struct
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
TARGET = ROOT / 'artifacts/node/115/hl-node'
SHA = 'a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301'
ANCHORS = {95951308: '4c89f7e8dc595bff4885c00f84780200000f10000f1048100f294c24300f294424204183', 95951744: '4c89e7e828585bff4885c00f849e0000000f10000f1048100f298c24800000000f294424704c', 85160880: '50488b47404885c0743948ffc848894740833f010f8500020000488b57084885d27424', 85160923: '0fb78a820400004839c80f83c50000004889d1e9e300000031c0', 85160947: '31c059c3', 85161136: '488b8a600100004885c90f84fb00000048ffc60fb782800400004889ca663b818204000073da', 85161174: '4885f67447488d14c14881c2900400004989f14983e107743c4531d266666666', 85161250: '488d70014989c8eb56', 85161345: '488d14c048c1e0054801c8488d14d14881c2680100004c89470848c74710000000004889771859', 85161418: '488d3d97aa3601ff1559823a010f0b', 85160992: '488b928804000049ffc04c39c675f14889ce4c29', 85161024: '488b8a88040000488b8988040000488b8988040000488b8988040000488b8988040000488b8988040000488b8988040000'}


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
    for site in (0x5b819cf, 0x5b81b83):
        off = va_offset(data, site, 5)
        if data[off] != 0xe8 or site + 5 + struct.unpack_from('<i', data, off + 1)[0] != 0x51373b0:
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
