#!/usr/bin/env python3
"""Check bounded instruction anchors and ELF relocations in node #115; no execution."""
import hashlib
import struct
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
TARGET = ROOT / 'artifacts/node/115/hl-node'
SHA = 'a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301'
ANCHORS = {57553836: '4531c04883fe41410f92c04c89fa4d89f1e89e4d710048', 64979296: '554157415641554154534881ecf80200004c894c24304489442454488954240848897c24184883fe020f', 64979346: '48b8000000000000004031d248f7f64883fa014883d8ff48898424800000004889f04881fe01100000731d48', 64979377: '4889f04881fe01100000731d48d1e84889f14829c14883f940b840000000480f42c14889442420eb2a', 64979418: '4883c801480fbdc889c8d1e883e10101c1b80100000048d3e04889f248d3ea4801c248d1ea4889542420', 64979616: '4c8964244849c1e505488b4424184e8d2428483b4c24207357807c24540074604989ce4883f9', 64979648: '4989ce4883f920b8200000004c0f43f0488b442430488904244c89e74c89f6488b542408488b5c24284889d94531c04531c9ff', 64979728: '4883f902732a4989cee93b0100006690', 64979776: '4889cb498d7c2420ba200000004c89e6ff15fa776e0285c0784a41be', 64980961: '4881c4f80200005b415c415d415e415f5dc3', 64979698: 'ff15a8156f02'}


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
    site = 0x36e33bd
    off = va_offset(data, site, 5)
    if data[off] != 0xe8 or site + 5 + struct.unpack_from('<i', data, off + 1)[0] != 0x3df8160:
        raise ValueError('selected direct-call target mismatch')
    site = 0x3df82f2
    off = va_offset(data, site, 6)
    if data[off:off + 2] != b"\xff\x15" or site + 6 + struct.unpack_from('<i', data, off + 2)[0] != 0x64e98a0:
        raise ValueError('indirect call slot mismatch')
    # Scan SHT_RELA sections for the unique R_X86_64_RELATIVE slot binding.
    shoff, = struct.unpack_from('<Q', data, 40)
    shsize, shcount = struct.unpack_from('<HH', data, 58)
    if shsize < 64 or shoff + shsize * shcount > len(data):
        raise ValueError('invalid section headers')
    matches = []
    for i in range(shcount):
        _, typ, _, _, off, size, _, _, _, entsize = struct.unpack_from('<IIQQQQIIQQ', data, shoff + i * shsize)
        if typ != 4:
            continue
        if entsize != 24 or off + size > len(data) or size % entsize:
            raise ValueError('invalid RELA table')
        for pos in range(off, off + size, entsize):
            address, info, addend = struct.unpack_from('<QQq', data, pos)
            if address == 0x64e98a0:
                matches.append((info, addend))
    if matches != [(8, 0x42e26a0)]:
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
    print(f'OK: {count} anchors, direct call and indirect slot relocation; {count} anchor mutations rejected')


if __name__ == '__main__':
    main()
