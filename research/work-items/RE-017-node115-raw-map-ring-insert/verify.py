#!/usr/bin/env python3
"""Check bounded instruction anchors and direct calls in node #115; no execution."""
import hashlib
import struct
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
TARGET = ROOT / 'artifacts/node/115/hl-node'
SHA = 'a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301'
ANCHORS = {92194576: '41574156415453504c8b47184c39c60f87cf0000004889d34989f74989fe488b3f4939f875104c89f7ff151197cf00498b3e4d8b46184d29f8498b56104d39f873474a8d043a4531e44839f84889f9490f42cc4829c84a8d0c3a48ffc14839f94889fa490f42d44829d1498b76084889c2e86a6002004d037e10498b064939c7490f42c44929c7eb31488d42ff4889c14801f9480f43c849894e10498b76084d89f8e8396002004d037e10498b0631c94939c7480f43c84929cf4b8d047f48c1e0034903460849ff4618488b4b10488948100f10030f11004883c4085b415c415e415fc3488d3dc09c14fb488d15ee44cc00be27000000ff15ab2ecf00cc', 81519654: '498b0e4839d90f840c010000a80174644c89a42488000000488b4c2408488b0148898424900000008b410889842498000000488d8424880000004c89f74889d64889d34889c2e89fe2a2004889d8e99f010000'}


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
    for site, target in ((0x4dbe46c, 0x57ec710), (0x57ec781, 0x58127f0), (0x57ec7b2, 0x58127f0)):
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
