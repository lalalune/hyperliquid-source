#!/usr/bin/env python3
"""Check bounded instruction anchors and direct calls in node #115; no execution."""
import hashlib
import struct
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
TARGET = ROOT / 'artifacts/node/115/hl-node'
SHA = 'a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301'
ANCHORS = {80920963: '6683b8e6000000000f8475010000488b90f0000000488984248000000048898c248800000048c7842490000000000000004889ac24980000004c89a424a000000048899424a80000004c89a424b0000000', 80921044: '0fb782e60000004101c74183ff0c732d488d7c2408488db4248000000031d24c89e9e88538f7ffeb35488d7c2448be01', 80921105: '488dbc2480000000be01000000e86dc1f6ff', 80315294: '4c8b7f18450fb787e60000004a8d04064883f80c0f83010300004889f34989fe488b6f280fb78de60000004829f10f820003000066418987e600000066898de6000000', 80315361: '488b44dd0048894c2408488d0c9d00000000488d5449f44889542438488d144948895424408b4c155c894c2418488b4c155448894c2410', 80315416: '498b0e498b5610488d3452488b7cd108488944d1088b44b16889442428488b44b1604889442420488b442410488944b1608b4424188944b1684b897cc7084f8d24408b442428438944a768488b4424204b8944a760', 80315501: '488d75084c894424304b8d3cc74883c710488d14ddf8ffffff4c8b2d7b70840141ffd54b8d3ca74883c76c488d7560488b54243841ffd5488d34dd080000004801ee4c8b6c2408468d24ed00000000488d7d084c89e2ff159f708401488b442440488d34284883c660428d04ad00000000488d1440488d7d60ff157c708401', 80315628: '49837e2000498b46300f84ee0000004885c00f84ee', 80315881: '4885c00f84b8000000'}


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
    for site, target in ((0x4d2c21e, 0x4c98390),):
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
