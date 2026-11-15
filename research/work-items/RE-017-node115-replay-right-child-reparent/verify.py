#!/usr/bin/env python3
"""Check bounded instruction anchors and direct calls in node #115; no execution."""
import hashlib
import struct
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
TARGET = ROOT / 'artifacts/node/115/hl-node'
SHA = 'a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301'
ANCHORS = {80315294: '4c8b7f18450fb787e60000004a8d04064883f80c0f83010300004889f34989fe488b6f280fb78de60000004829f10f820003000066418987e600000066898de6000000', 80315556: '488d34dd080000004801ee4c8b6c2408468d24ed00000000488d7d084c89e2ff159f708401', 80315628: '49837e2000498b46300f84ee0000004885c00f84ee0000004c8b6c24304d8d7501488db5e80000004b8d3cf74881c7e8000000488d14dd00000000ff15db6f8401488d34dd', 80315693: '488d34dde80000004801ee4983c408488dbde80000004c89e2ff151c7084014b8b84eff00000004c8938664489b0e40000004883fb01746a4b8b84eff80000004c8938418d4d02668988e40000004883fb02744e4b8b84ef000100', 80315855: '488b4c2408488d510189d083e00383f903732931c9e9a70000004885c00f84b8000000488d3d9daec7fb', 80315936: '488bb4cde800000048892e89cf66898ee4000000488bb4cdf000000048892e448d470166448986e4000000488bb4cdf800000048892e448d470266448986e4000000488bb4cd000100004883c10448892e83c7036689bee40000004839d175a04885c0742566662e0f1f840000000000488b94cde8000000', 80316048: '488b94cde800000048892a66898ae400000048ffc148ffc875e64883c4485b415c415d415e415f5dc3'}


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
    for site, target in ():
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
    print(f'OK: {count} anchors, 0 direct-call targets; {count} anchor mutations rejected')


if __name__ == '__main__':
    main()
