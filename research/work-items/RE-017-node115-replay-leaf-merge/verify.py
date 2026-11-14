#!/usr/bin/env python3
"""Check bounded instruction anchors and direct calls in node #115; no execution."""
import hashlib
import struct
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
TARGET = ROOT / 'artifacts/node/115/hl-node'
SHA = 'a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301'
ANCHORS = {80920926: '0fb786e60000004101c74183ff0c0f838b000000488d7c2408488d742448ba01000000eb', 80921044: '0fb782e60000004101c74183ff0c732d488d7c2408488db4248000000031d24c89e9e88538f7ff', 80345742: '4c8b7618450fb796e60000004c89d04883fa01750b488b46280fb780e60000004839c10f87830300004c8b6e28450fb78de60000004f8d040a49ffc04983f80c0f837f030000', 80345880: '66458986e60000004b8d7cfc084b8b44fc08488904244b8d74fc104c894c24084c89fd48f7d54801cd488d14ed0000000048895424584c89d3ff1511fa8301488b0424498944de08498d7508488b442410498d3cc64883c7084c8b6c2408428d14ed00000000ff1584f983014b8d04', 80345988: '4b8d047f498d3c844883c760418b4c8468894c2428498b4c846048894c2420498d34844883c66c48c1e502488d146d000000004801eaff15a8f9830148891c24488d045b488b4c242049894c86608b4c242841894c8668488b442418488d7060488b442410488d0440498d3c864883c760428d04ad00000000488d1440ff1501f98301', 80346119: '498d5f014b8d2cfc4881c5f00000004b8d34fc4881c6f80000004889ef488b542458ff1539f983014c8b4424504c39c30f83ad0000', 80346346: '6641ff8c24e6000000bee800000048837c2460024c8b7c2418488b0c244c8d61010f82ea00', 80346619: '31db4c89ff31d2ff1598f68301f644243801490f45dc48035c2440488b4424484c8930488b4c24304889480848895810'}


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
    for site, target in ((0x4d2c1f6, 0x4c9fa80),):
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
