#!/usr/bin/env python3
"""Check bounded instruction anchors and direct calls in node #115; no execution."""
import hashlib
import struct
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
TARGET = ROOT / 'artifacts/node/115/hl-node'
SHA = 'a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301'
ANCHORS = {4562896: '44617465', 52400624: '55415741564154534881ecb00000000fb64620440fb64621c64620013c017562488b4e184885c974', 52400711: '3c90730a240f4189c0e99b0000003ca0730a240f4189c0e9fe0000004189c04180', 52400993: '450fb6f00fb746226685c00f846e07000066ffc8668946220f84aa0300004989fc4585f60f84d20400', 52401035: '488d153e0c26fd488d7c2430b9040000004889f3e86cf3d6ff0fb64424303c090f85d40100004183fe010f', 52401073: '4183fe010f84dc0400008b6c2434458d7efe488d7c24304889de31d2e85e9304000fb64424303c090f85600300000f1044', 52401119: '0f10442438896c24180f114424204c89e7e9cc040000488b46104c8b46184983', 52402269: '4889f3488d0d599326034531ff488d7c2410488d54240f31f6e81566d8ffeb38488b74', 52402327: '488d0d22932603488d7c2410488d54240fbe01000000e8de65d8ff4531ff4c89e70f'}
ANCHORS[0x31f98f1] = "4585ff0f84b50000004529fe0f82f9010000c6442470044489742474e9d80000"


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
    for site, target in ((0x31f939f, 0x2f68710), (0x31f93cd, 0x3242730), (0x31f9876, 0x2f7fe90), (0x31f98ad, 0x2f7fe90)):
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
