#!/usr/bin/env python3
"""Check bounded instruction anchors and direct calls in node #115; no execution."""
import hashlib
import struct
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
TARGET = ROOT / 'artifacts/node/115/hl-node'
SHA = 'a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301'
ANCHORS = {92096388: '4983c708418b4708898424d8000000498b0748898424d0000000f20f1005724fc8faff15c4c7d000', 92096656: '418b16413955000f9dc2742beb43c7442410000000004c8d352331c9fa488d052431c9fa488d0d1931c9fa418b16413955000f9dc2751a8b0941394d040f93c2750f8b08b00141394d08730fe969010000b00184d20f845f010000488b442478488b4828488b7030488b11b001483b160f834401000048ffc2488911e937010000', 92097089: '49ffc64c89731031c04881c4b80100005b415c415d415e415f5dc3', 92214950: '4c8b67184d85e4745e498b5e104d8b3e498b4608488d0c5b488d2cc84883c5e84531ed0f1f80000000004a8d042b4c39f8b800000000490f43c748c1e003488d04404883c5184889ee4829c6488b7c2410e8d42dfeff84c0741c49ffc54d39ec75c8e93f010000', 92215136: '4989d4488d042a4839d84889d8b900000000480f42c148c1e003488d04404d89f74929c7488b7c24104c89fee83f2dfeff84c0751b48ffc54983c618483b2c244c89e272bbe988000000660f1f440000488b34244939f50f839e00', 92215216: '488b34244939f50f839e0000004c89e24b8d042c4839d8b900000000480f43cb4829c8488d0440488b7c2418488b4cc71048894c24300f1004c70f29442420498b4f10410f10070f1104c748894cc710488b442430498947100f28442420410f1107488d450149ffc54839f00f8220ffffff4989f448ffc54889e84c8b742408eb0c', 92215358: '4d39e573094c39e874044d896e18'}


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
    for site, target in ((0x57f16f7, 0x57d44d0), (0x57f178c, 0x57d44d0)):
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
