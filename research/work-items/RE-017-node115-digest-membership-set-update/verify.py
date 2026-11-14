#!/usr/bin/env python3
"""Check bounded instruction anchors and direct calls in node #115; no execution."""
import hashlib
import struct
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
TARGET = ROOT / 'artifacts/node/115/hl-node'
SHA = 'a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301'
ANCHORS = {87629533: '4c89ff4c89eee87867e4ff', 87629728: '3c0274588b8c2450020000898c2430070000660f6f842440020000660f7f842420070000a8010f8411ffffff8b84245002000089842440010000660f6f842440020000660f7f8424300100004c89ff4c89e6e8e90ae4ffe9ecfeffff', 85821038: '4c8b3f4d85ff0f84280100004989f648897c2418488b470848894424104c8b2dbe743001410fb787e600000048894424208d048500000000488d1c8048f7db48c7c5ffffffff41bc08000000660f1f4400004a8d04234883f80874364b8d3427ba140000004c89f741ffd548984885c00f98c10f9fc028c848ffc54983c4143c0174cf0f', 85821222: '4c897c2428488b442410488944243048896c2438488b5c241848895c2440c644240f00488d7c2448488d742428488d54240fe88390b5ff48ff4b10807c240f017536488b3b4885ff7443488b43084885c07447488b8fe800000048890b48ffc84889430848c70100000000be4801000031d2ff15026d3001b001eb0231c0', 85797617: '4989f64c8b3f4d85ff0f84ab00000048897c2418488b4708488904244c8b2d3cd03001410fb787e600000048894424208d048500000000488d1c8048f7db48c7c5ffffffff41bc080000000f1f40004a8d04234883f80874364b8d3427ba140000004c89f741ffd548984885c00f98c10f9fc028c848ffc54983c4143c0174cf0fb6c085c0742ceb0b660f1f440000488b6c2420488b04244883e8010f823d010000488904244d8bbcefe8000000e970ffffffb001', 85797803: '4531ff498b06498b4e08418b56108954241048894c240848897c24284c897c243048c74424380000000048896c24404c8d7424484889442448488b44240848894424508b442410894424588b4424148944245c4d85ff7458', 85797979: '4889fbbfe8000000ff1517c830014885c0746c48c7000000000066c780e6000000000048890348c74308000000000fb788e60000004883f90b73544889de8d5101668990e6000000488d0c89418b561089548818410f10060f1144880848ff461031c04881c4b80000005b415c415d415e415f5dc3'}


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
    for site, target in ((0x5391ee3, 0x51d8660), (0x5391ff2, 0x51d2ae0), (0x51d8758, 0x4d317e0), (0x51d2c4f, 0x4c39500)):
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
