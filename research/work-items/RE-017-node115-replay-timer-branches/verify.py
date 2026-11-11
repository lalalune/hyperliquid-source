#!/usr/bin/env python3
"""Check bounded instruction anchors and ELF relocations in node #115; no execution."""
import hashlib
import struct
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
TARGET = ROOT / 'artifacts/node/115/hl-node'
SHA = 'a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301'
ANCHORS = {4560664: '0000000000004e40', 85270899: '488d2c5b498b44dd084889442410488b4424084c8b38488b4018f20f1000418b44ad68898424e8000000498b44ad6048898424e0000000', 85270954: 'ff15c0ed380189d6b900ca9a3b48f7e14889c189f04801c14883d20048b8', 85271047: 'ff156bed3801488b44242048b908ac1c5a643bdfff48', 85271177: 'ff1511e8380185c07441894424188b842484', 85271242: '4139170f9dc27429eb3fc7', 85271252: 'c744241800000000488d0df15631fb488d05ee5631fb488d15df5631fb8b124139170f9dc275188b0941394f', 85271291: '8b0941394f040f93c2750d8b0041394708720de98b020000', 85271315: '84d20f8583020000488d04ad60000000', 85271323: '488d04ad600000004c01e88b4808898c24e8000000488b0048898424e0000000f20f1005d57330fbff1527ec380189d6', 85271355: 'f20f1005d57330fbff1527ec380189d6b9', 85271572: 'ff1586e6380185c074378944241889ac', 85271676: '8b0941394f040f93c2750a8b00413947087306eb1d', 85271701: '488b4c2408488b4128488b5130488b08483b0a0f82ef010000', 85271966: '49bf0000000000000080488b442408488b7008488d7c2418488b542410e83058220049'}


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
    site = 0x51525bb
    off = va_offset(data, site, 5)
    if data[off] != 0xe8 or site + 5 + struct.unpack_from('<i', data, off + 1)[0] != 0x5377df0:
        raise ValueError('selected direct-call target mismatch')
    expected = {0x64e0f70: 0x15ed960, 0x64e0f78: 0x162a9a0, 0x64e0aa0: 0x16290d0}
    for site, slot in ((0x51521aa, 0x64e0f70), (0x5152207, 0x64e0f78), (0x5152289, 0x64e0aa0), (0x5152343, 0x64e0f70), (0x51523a0, 0x64e0f78), (0x5152414, 0x64e0aa0)):
        off = va_offset(data, site, 6)
        if data[off:off + 2] != b"\xff\x15" or site + 6 + struct.unpack_from('<i', data, off + 2)[0] != slot:
            raise ValueError(f'indirect slot mismatch at {site:#x}')
    shoff, = struct.unpack_from('<Q', data, 40)
    shsize, shcount = struct.unpack_from('<HH', data, 58)
    if shsize < 64 or shoff + shsize * shcount > len(data):
        raise ValueError('invalid section headers')
    matches = {slot: [] for slot in expected}
    for i in range(shcount):
        _, typ, _, _, off, size, _, _, _, entsize = struct.unpack_from('<IIQQQQIIQQ', data, shoff + i * shsize)
        if typ != 4:
            continue
        if entsize != 24 or off + size > len(data) or size % entsize:
            raise ValueError('invalid RELA table')
        for pos in range(off, off + size, entsize):
            address, info, addend = struct.unpack_from('<QQq', data, pos)
            if address in matches:
                matches[address].append((info, addend))
    if any(matches[slot] != [(8, target)] for slot, target in expected.items()):
        raise ValueError('slot relocation mismatch')
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
    print(f'OK: {count} anchors, 1 direct call and 6 indirect slots with 3 relocations; {count} anchor mutations rejected')


if __name__ == '__main__':
    main()
