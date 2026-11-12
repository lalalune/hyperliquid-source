#!/usr/bin/env python3
"""Check bounded instruction anchors and direct calls in node #115; no execution."""
import hashlib
import struct
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
TARGET = ROOT / 'artifacts/node/115/hl-node'
SHA = 'a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301'
ANCHORS = {87519655: '488d048948c1e004488b0c0748898c24a0000000488b5407080f104407100f298424a00100000f104407200f298424b00100000f104407300f298424c0010000660f10440740eb6c', 87519835: '660f298424d00100004c39f20f84750500004889942430010000660f288424a0010000660f288c24b0010000660f289424c00100000f289c24d0010000488d8424510100000f115817660f115007660f1148f7660f1140e780bc24500100000048895424080f859e0100004c39fa0f85c1000000', 87520144: '488dbc2430010000488db42451010000e82b204800a8010f85a3000000483b9424480100000f83950000004803942440010000488b4c24084839cab800000000480f43c14829c2488b842438010000488d0c5248c1e1054c8d24084983c420498b44242049bf00000000000000804c39f80f849a000000', 92247124: '4531f64531edeb064c01e84989c64a8d2c6d000000004c01ed48c1e50548036f084d29eeb8010000004d85f60f84350100004531ed4983fe01743f904d89ec4c89f348d1eb4901dd4a8d3c6d000000004c01ef48c1e7054801efba200000004c89feff159466ce004c89fe85c04d0f4fec4929de4983fe0177c24a8d046d000000004c01e848c1e0054801c5ba200000004889efff156266ce0085c07413c1e81f4901c54d89eeb801000000e9b600000031c04d89eee9ac000000'}


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
    for site, target in ((0x53773a0, 0x57f93d0),):
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
