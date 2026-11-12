#!/usr/bin/env python3
"""Check bounded instruction anchors and direct calls in node #115; no execution."""
import hashlib
import struct
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
TARGET = ROOT / 'artifacts/node/115/hl-node'
SHA = 'a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301'
ANCHORS = {81679953: '4989d5498946184c897c24104c896424284c896424184939360f94c14c896c2420488974240884c90f85d2000000', 81680209: '4883f81f0f8709010000498b4e08498b561049c746080000000049c74618000000004885c9743f48c78424800000000000000048898c2488000000488994249000000048c78424a00000000000000048898c24a800000048899424b0000000b901000000eb0431c931c048894c247848898c249800000048898424b8000000488d7c2430488d742478e8d191da00488b6c2438488b44244048890424498b4e084885c97435498b5610498b461848c74424380000000048894c2440488954244848c74424580000000048894c24604889542468b901000000eb0431c931c04c8b64243048894c243048894c24504889442470488d7c2430e8a3ee46004d892649896e0849c7461000000000488b0424498946184983fd1f0f879d01000048c74424100000000048c7442420000000004d85ff744448c7842480000000000000004c89bc2488000000488b442428488984249000000048c78424a0000000000000004c89bc24a800000048898424b0000000b801000000eb0531c04531ed488944247848898424980000004c89ac24b8000000488d7c2430488d742478e8be90da004c8b6424304c8b7c24384c8b74244048c74424300000000048c74424500000000048c744247000000000488d7c2430e8caed46004c896424084c897c241048c7442418000000004c89742420e9c8000000', 96004528: '554157415641554154534881ec180100004989f64c8b7e404c89f848c1e004488d348048b899999999999999014939c7760a31ffff15ae0a95000f0b4889fb4885f6741b4989f44889f7ff15800a95004885c07512bf080000004c89e6ebd5b80800000045'}


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
    for site, target in ((0x4de57da, 0x5b8e9b0), (0x4de58ed, 0x5b8e9b0)):
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
    print(f'OK: {count} anchors, 2 direct-call targets; {count} anchor mutations rejected')


if __name__ == '__main__':
    main()
