#!/usr/bin/env python3
"""Check bounded instruction anchors and direct calls in node #115; no execution."""
import hashlib
import struct
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
TARGET = ROOT / 'artifacts/node/115/hl-node'
SHA = 'a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301'
ANCHORS = {81659794: '488b43184c392b0f94c14883f8200f92c220ca80fa010f8529010000488b4b08488b531048c743080000000048c74318000000004885c9742d48c74424300000000048894c2438488954244048c74424500000000048894c24584889542460b901000000eb0431c931c048894c242848894c24484889442468488d7c2470488d742428e84660da00', 95971546: '498b564048899424e0000000410f1006410f104e10410f105620410f105e300f299c24d00000000f299424c00000000f298c24b00000000f298424a00000004c39fa0f87e60000', 95971621: '498b4e4048894c2460410f1006410f104e10410f105620410f105e300f295c24500f295424400f294c24300f294424204b8d0c644c8d2cc84983c50c4c8db424880000004c8d7c242066904c89f74c89fee8f55a65ff', 85836926: '488b46404885c00f848e00000048ffc848894640833e010f8570030000488b7e084885ff0f8403010000', 85837227: '488d4610488b7e10488b4e184885c974724889ca4883e2070f849e0100004531c00f1f4000488bbfe800000049ffc04c39c275f14889ca4c29c24883f90872430f1f440000488b8fe8000000488b89e8000000488b89e8000000488b89e8000000488b89e8000000488b89e8000000488b89e8000000488bb9e80000004883c2f875c2'}


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
    for site, target in ((0x4de0815, 0x5b86860), (0x5b86976, 0x51dc470)):
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
