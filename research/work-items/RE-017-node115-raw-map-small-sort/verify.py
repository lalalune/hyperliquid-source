#!/usr/bin/env python3
"""Check bounded instruction anchors and direct calls in node #115; no execution."""
import hashlib
import struct
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
TARGET = ROOT / 'artifacts/node/115/hl-node'
SHA = 'a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301'
ANCHORS = {81519470: '488db424d00000004c89f7e852b2a3004885c00f95c1498b76184883fe40400f93c74084f90f848d000000410f1006410f104e100f294c24200f2944241049c706000000004d8d7e0849c74608080000000f57c0410f114610488d7c2470488d742410e84af23900', 85317152: '415741564154534881ec880000004889fb0f10060f104e100f294c24500f29442440488d7c2418488d742440e80f2fa2004c8b7c24284d85ff0f84a50000004c8b742420488d44240f48894424404983ff010f85cc0000004c8b', 85317230: '4983ff010f85cc0000004c8b642418bfe8000000ff15f81d38014885c00f84d300000048c70000000000', 85317304: '4b8d047f498d04c648c7442440000000004c897424604c897424684c896424704889442478488d7c2430488d742440488d542410e8ef51b6ff0f10442430488b4424100f110348', 85317380: '48c7030000000048c7431000000000488b4424184885c07415488b7c242048c1e003488d344031d2ff156e1d38014889d84881c4880000005b415c415e41', 85317444: '4983ff15732c488d4c2440ba010000004c89f74c89fee8312b2900e914ffffffbf08000000bee8000000ff151c1d38010f0b488d5424404c89f74c89feff1571813801e9ecfeffff', 88015504: '488d42ff4839f00f83910000004839f27501c3488d0476488d04c748c1e203488d0c52488d140feb240f1f80000000004989f84989300f284424e8410f1140084883c2184883c1184839c274c5488b32483b72e873ea0f1042080f294424e84989c966666666662e0f1f8400000000004e8b440ff84e89440f10420f10440fe8420f11040f4983f91874a54d8d41e84a3b740fd04d89c172d74901f8eb950f0b'}


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
    for site, target in ((0x4dbe3d1, 0x515d620), (0x515d64c, 0x5b80560), (0x515d75a, 0x53f0290), (0x515d6ec, 0x4cc28e0)):
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
    print(f'OK: {count} anchors, 4 direct-call targets; {count} anchor mutations rejected')


if __name__ == '__main__':
    main()
