#!/usr/bin/env python3
"""Check bounded instruction anchors and direct calls in node #115; no execution."""
import hashlib
import struct
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
TARGET = ROOT / 'artifacts/node/115/hl-node'
SHA = 'a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301'
ANCHORS = {9577952: 'bcada604', 87608624: '554157415641554154534881ec280e00004989d54989f7488b2e4889e84883e814b94d000000480f43c848897c2408488d05065759fb48630c884801c1ffe1', 87609896: '4c896c2410498b6f08498b5f104d8b77184d8b67204d8b6f284983fe650f8355340000410fb64738884424184d8b7f304889ac243001000048899c24380100004c89b42440010000488d7c2420488db42430010000ff156d9815010fb74424203da20100000f858b530000f30f7e4424284885ed660fd6842400020000', 87610037: '4983ff650f83a36800004c89a424300100004c89ac24380100004c89bc2440010000488d7c2420488db42430010000ff15069815010fb74424203da2010000f30f7e9c24000200000f85f27a0000', 87610167: '66480f7ed948b8ffffffffffffff7f4821c1f20f10255fbf0cfb48baffffffffffffef7f660f28c44839d17f14660f57d2f20f5fd3f20f10059cc60cfbf20f5dc266480f7ec94821c148b8000000000000f07f4839c1488b7c24107c04660f28cc0fb6742418'}


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
    for site, target in ((0x538d39d, 0x54cf1b0),):
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
