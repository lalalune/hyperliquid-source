#!/usr/bin/env python3
"""Check bounded instruction anchors and direct calls in node #115; no execution."""
import hashlib
import struct
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
TARGET = ROOT / 'artifacts/node/115/hl-node'
SHA = 'a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301'
ANCHORS = {85865136: '55415741564155415453504989fd488b46404885c00f848e00000048ffc848894640833e010f8570030000488b7e084885ff0f8403010000488b46104c8b76180fb78f7a03000049', 85865451: '488d4610488b7e10488b4e184885c974724889ca4883e2070f849e0100004531c00f1f4000488bbf8003000049ffc04c39c275f14889ca4c29c24883f90872430f1f440000488b8f80030000488b8980030000488b8980030000488b8980030000488b8980030000488b8980030000488b8980030000488bb9800300004883c2f875c248c7060100000048897e080f57c00f11004531f631c00fb78f7a0300004939ce0f826cfeffff', 85865720: '498d56014c89f8eb504c89e731d24983fc0872450f1f4000488b01488b8080030000488b8080030000488b8080030000488b8080030000488b8080030000488b8080030000488b8080030000488d88800300004883c7f875bf4d897d004d8965084d8975104889460848c7461000000000488956184883c4085b415c415d415e415f5dc3', 96004817: '48bd01000000000000800f1f4400004c89f74c89fee8c54765ff488b4424684885c00f8482000000488b542478488b4cd008'}


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
    for site, target in ((0x5b8eae6, 0x51e32b0),):
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
