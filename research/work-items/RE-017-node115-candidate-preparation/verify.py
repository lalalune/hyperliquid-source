#!/usr/bin/env python3
"""Check bounded instruction anchors and direct calls in node #115; no execution."""
import hashlib
import struct
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
TARGET = ROOT / 'artifacts/node/115/hl-node'
SHA = 'a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301'
ANCHORS = {87507600: '488d742410e81643fdff4c89ff488bb424a00100004c89eae8c33c35fe4189c64c89efe8a828edff4584f60f846ffeff', 87328176: '415741564154534881ec880000004889fb488b464048898424800000000f1006', 87328240: '488d7c2418488d742440e8719383004c8b7c24284d85ff0f849a0000004c8b7424', 87328274: '4983ff010f85c40000004c8b642418bf70010000ff15546e19014885c00f84c10000', 87328309: '49c1e7054d01f748c780600100000000000066c7806a0100000000', 87328374: '4c897c2458c644246002488d7c2430488d742440488d542410e80cf39bff0f10442430', 87328423: '48c7030000000048c7431000000000488b7424184885f67411488b7c242048c1e60531d2ff15cf6d1901', 87328480: '4983ff1573224c89f74c89fee80f7a0a00e926ffffff', 87328520: '488d54240f4c89f74c89feff15ffc61901e9fefeffff', 87328502: 'bf08000000be70010000ff158a6d19010f0b'}


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
    for site, target in ((0x5374295, 0x53485b0), (0x53742a8, 0x36c7f70), (0x53485fa, 0x5b81970), (0x534868f, 0x4d079a0), (0x53486ec, 0x53f0100)):
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
    print(f'OK: {count} anchors, 5 direct-call targets; {count} anchor mutations rejected')


if __name__ == '__main__':
    main()
