#!/usr/bin/env python3
"""Check bounded instruction anchors and ELF relocations in node #115; no execution."""
import hashlib
import struct
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
TARGET = ROOT / 'artifacts/node/115/hl-node'
SHA = 'a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301'
ANCHORS = {
    0x37141b0: '554157415641554154534881ec980000004889f34989fe488b47584889442418',
    0x3714263: '488d7424184c89f7e8a0d5e300a8017548493b56187342',
    0x371427a: '4903561031c04c39fa490f43c74829c2498b4608486bca38488d3c084883c70848b80000000000000080483907744148',
    0x37142a9: '4889dee8af57e4004885c00f94c0e9bc0000',
    0x37142bc: '66c74424209b00488d7c2420e8636bfcff31c0e9a40000',
    0x37142f7: '4c8b2552b8dc02',
    0x3714325: '4c8d7620ba200000004889df41ffd44898',
    0x371435d: '4983ef01488b7424100f8261ffffff4a8bb4ee88040000eb88b001',
    0x537bbed: 'ff15cdae160184c04c8b6c24100f84d0fdffff',
}


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
    # The direct calls' rel32 encodings and the indirect RIP slot are independently resolved.
    for site, target in ((0x371426b, 0x4551810), (0x37142ac, 0x4559a60), (0x37142c8, 0x36dae30)):
        off = va_offset(data, site, 5)
        if data[off] != 0xe8 or site + 5 + struct.unpack_from('<i', data, off + 1)[0] != target:
            raise ValueError(f'call target mismatch at {site:#x}')
    site = 0x537bbed
    off = va_offset(data, site, 6)
    if site + 6 + struct.unpack_from('<i', data, off + 2)[0] != 0x64e6ac0:
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
            if address == 0x64e6ac0:
                matches.append((info, addend))
    if matches != [(8, 0x37141b0)]:
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
    print(f'OK: {count} anchors, 3 direct calls, indirect slot relocation; {count} anchor mutations rejected')


if __name__ == '__main__':
    main()
