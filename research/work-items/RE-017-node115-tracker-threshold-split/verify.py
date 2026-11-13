#!/usr/bin/env python3
"""Check bounded instruction anchors and direct calls in node #115; no execution."""
import hashlib
import struct
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
TARGET = ROOT / 'artifacts/node/115/hl-node'
SHA = 'a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301'
ANCHORS = {95397089: '4981ed50c30000b8000000004c0f42e8488d0550239c0048890424488d7c24204c89fe4c89ea488b4c24184531c0e86cca87ff', 87519148: '4883c618488dbc24e8010000488d942478010000e80be6a6ff0f1045180f104d280f298c24900100000f29842480010000660f108424e8010000660f108c24f8010000660f114d28660f114518', 81680004: '4c89f74889d6e801d2a000498b6e184989ef4929c70f82a40300004c89f948c1e104488d348948b99a9999999999990148ffc94939cf760831ffff15d49d6f014885f60f84760200004989c4488934244889f7ff15a39d6f014885c00f84830300004889c7', 81680841: '4929cc488d0c8948c1e1044801ce49c1e4044989c54b8d14a44889fdff151d9b6f014d896e18488b0424488944240848896c241048c7442418000000004c897c2420488b442408488b4c2410488b54241848895310488b5424204889531848890348894b084889d84881c4c80000005b415c415d415e415f5dc3', 92219536: '488b57184885d27434488b0f4c8b471031c04939c8480f43c14929c04c29c14889d04829c8761d488b5708488b3e48393a73714883f802737e4801c8c331c94531c0eb064c01c24889d14b8d148048c1e204480357084c29c14885c97456488b3631c04883f901742a0f1f80000000004889cf48d1ef4c8d04074f8d0c8049c1e1044a39340a490f42c04829f94883f90177dd488d0c8048c1e1044839340a4883d000c34b8d048048c1e0044801c24885c975aa31c0c3'}


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
    for site, target in ((0x5afa50f, 0x5376f80), (0x5376fc0, 0x4de55d0), (0x4de568a, 0x57f2890)):
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
