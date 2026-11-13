#!/usr/bin/env python3
"""Check bounded instruction anchors and direct calls in node #115; no execution."""
import hashlib
import struct
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
TARGET = ROOT / 'artifacts/node/115/hl-node'
SHA = 'a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301'
ANCHORS = {87520514: '4c8944241048897c2418488944242048894c2428488954243048c744243800000000488944244048894c24484889742450488dbc24f80000004c8d6424104c89e6e8f81bfdff488d8c24f8000000488b41104889842420010000660f1001660f29842410010000', 87331200: '488d7c2418488d742440e8712783004c8b7c24284d85ff0f84', 87331441: '4983ff1573224c89f74c89fee8aec50900e925ffffff', 95926551: '833e027540498d4f08498b4708498b57104839d0751e410f1047180f11014989471849895720498b4708493b47100f849d020000488d50604889114885c07516e9970200004c89ffe89cf85bff4885c00f84860200008b4810894c24300f10000f29442420', 95926979: '48837c2420027555488b442428488b4c24304839c87526488d5424280f1042100f1102488944243848894c2440488b442428483b4424300f84c4000000488d486048894c24284885c07523e9bc000000666666662e0f1f8400000000004c89e7e8d8f65bff4885c00f849e0000008b4810898c24800000000f10000f294424704c3b742408', 87971888: '554157415641554154534883ec284889fb488d04b64c8d3c87488d47144531e4488b2df9a20f014989e648897c24184c897c2420eb31662e0f1f8400000000004c8b7c24188b442410418947100f280424410f11074c8b7c2420488d43144983c4ec4c39f8745b4889de4889c3ba140000004889c7ffd585c079df8b4310894424100f10030f2904244d89e54989df90418b47fc41894710410f1047ec410f11074d85ed749a498d77d8ba140000004c89f7ffd54983c7ec4983c51485c078d0eb834883c4285b415c415d415e415f5dc3'}


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
    for site, target in ((0x5377543, 0x5349140), (0x534918a, 0x5b7b900), (0x534927d, 0x53e5830), (0x534921c, 0x4ca9730)):
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
