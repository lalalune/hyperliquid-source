#!/usr/bin/env python3
"""Check bounded instruction anchors and direct calls in node #115; no execution."""
import hashlib
import struct
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
TARGET = ROOT / 'artifacts/node/115/hl-node'
SHA = 'a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301'
ANCHORS = {80291390: '488b6f28440fb7ade60000004a8d042e4883f80c0f83910200004889f34c8b6718450fb7bc24e60000004d89fe4929f60f828e02000048897c2440664589b424e60000004889442438', 80291546: '4d8d6e014d29ef488d43ff4939c70f852d020000', 80291751: '4983782000498b4030746d4885c074714c8db5e8000000488d3cdde80000004801ef4c8d2cdd00', 80291785: '4c8d2cdd00000000488b5424284883c2084c89f6ff1585cd8401488b442420498d34c44881c6e80000004c89f74c89eaff1509cd8401488b442430488d140348ffc289d083e00348837c24380373', 80291905: '83e23c31c9662e0f1f840000000000488bb4cde800000048892e89cf66898ee4000000488bb4cdf000000048892e448d470166448986e4000000488bb4cdf800000048892e448d470266448986e4000000488bb4cd000100004883c10448892e83c7036689bee40000004839d175a04885c074', 80292032: '488b94cde800000048892a66898ae400000048ffc148ffc875e64883c4485b415c415d415e415f5dc348'}


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
