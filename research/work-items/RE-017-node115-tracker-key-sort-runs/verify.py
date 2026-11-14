#!/usr/bin/env python3
"""Check bounded instruction anchors and direct calls in node #115; no execution."""
import hashlib
import struct
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
TARGET = ROOT / 'artifacts/node/115/hl-node'
SHA = 'a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301'
ANCHORS = {57552732: '4531c04883fe41410f92c04c89fa4c89e14d89f1e81b7b7600', 65317520: '554157415641554154534881ecf80200004c894c2438448944244c488954240848897c24184883fe020f82a20600004989c948b8000000000000004031d248f7f64883fa014883d8ff48894424784889f04881fe01100000731d48d1e84889f14829c14883f940b840000000480f42c14889442428eb2a4883c801480fbdc889c8d1e883e10101c1b80100000048d3e04889f248d3ea4801c248d1ea4889542428', 65317824: '4e8d3cad000000004d01ef488b4424184e8d24b8483b4c24287365807c244c000f84aa0000004989ce4883f920b8200000004c0f43f0488b442438488904244c89e74c89f6488b5424084c8b7c24304c89f94c89c34531c04531c9ff1527f269024d89f94989d84489f0488d0c4501000000e996010000660f1f8400000000004883f9024989ce0f82730100004c89442410498d7c2414ba140000004c89e6ff15eb4e690285c0793b4983fe020f858100000041be02000000b8010000004c8b442410e9cf0000000f1f840000000000488b4424284839c1480f43c84801c9e9240100004c89f141be020000004883f9024c8b4424100f84040100004889cb89442420488b4424504e8d3cb80f1f4000498d77ecba140000004c89ffff156e4e690285c0784f49ffc64983c7144c39f375deeb3e894424204c89f3488b4424504e8d3cb841be02000000660f1f440000498d77ecba140000004c89ffff152e4e690285c0790f49ffc64983c7144c39f375de4989de'}


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
    for site, target in ((0x36e2f70, 0x3e4aa90),):
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
