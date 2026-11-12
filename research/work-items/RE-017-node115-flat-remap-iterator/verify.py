#!/usr/bin/env python3
"""Check bounded instruction anchors and direct calls in node #115; no execution."""
import hashlib
import struct
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
TARGET = ROOT / 'artifacts/node/115/hl-node'
SHA = 'a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301'
ANCHORS = {92096785: 'bf0200000048897c24104c8944241848894c24204889542428488974243048c74424380000000048894c244048895424484c894c24504889442458488d842488000000488944246031ed488dbc24d0000000488d742410e8c35e3a00', 95922241: '4989f748893c244c8b7648488b6e50488d9c24b00000004c8da42420010000', 95922288: '41833f020f85a6000000498b47204885c00f84d3060000498b4f18488d5101498b7708498b7f104839f2ba00000000480f42f248f7de488d143148ffc24989571848ffc849894720486bc1680f1004070f104c07100f105407200f105c07300f29842490000000488b4c076048898c24f00000000f104407500f298424e00000000f104407400f298424d00000000f299c24c00000000f299424b00000000f298c24a0000000', 95922464: '4c89e74c89fee8955266ff488b8424200100004885c00f843b060000488b8c2430010000488d14c948c1e1050f1004080f104c08100f298c24a00000000f298424900000000f1084d0680100000f108cd0780100000f1094d0880100000f109cd0980100000f11030f114b100f1153200f115b30488b84d0a801000048894340', 95922592: '0f288424900000000f288c24a00000000f298c24000200000f298424f0010000488b4d004c89e74c89f64c89eaff1595a696006681bc2420010000a201740d4c89e7e86908faffe984feffff8b8424'}


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
    for site, target in ((0x57d4968, 0x5b7a830), (0x5b7a926, 0x51dfbc0)):
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
