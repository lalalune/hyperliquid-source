#!/usr/bin/env python3
"""Check bounded instruction anchors and direct calls in node #115; no execution."""
import hashlib
import struct
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
TARGET = ROOT / 'artifacts/node/115/hl-node'
SHA = 'a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301'
ANCHORS = {95926551: '833e027540498d4f08498b4708498b57104839d0751e410f1047180f11014989471849895720498b4708493b47100f849d020000488d50604889114885c07516e9970200004c89ffe89cf85bff4885c00f84860200008b4810894c24300f10000f29442420', 85176832: '50488b47404885c0743948ffc848894740833f010f85f1010000488b47084885c07424488b7710488b4f180fb790fe0300004839d10f83c50000004889c2e9df00000031c059c3488d4f10488b4710488b57184885d274764889d64883e6070f84850100004531c00f1f840000000000488b800004000049ffc04c39c675f14889d64c29c64883fa0872430f1f440000488b8000040000488b8000040000488b8000040000488b8000040000488b8000040000488b8000040000488b8000040000488b80000400004883c6f875c248c70701000000488947080f57c00f110131c931f60fb790fe0300004839d10f8248ffffff666666662e0f1f840000000000488b104885d20f84f000000048ffc60fb788fc0300004889d0663b8afe03000073de', 85177281: '488d0489488d0482480520030000488d0cc9488d54ca084c89470848c74710000000004889771859c3'}


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
    for site, target in ((0x5b7b95f, 0x513b200),):
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
