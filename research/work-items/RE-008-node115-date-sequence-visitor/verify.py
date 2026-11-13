#!/usr/bin/env python3
"""Check bounded instruction anchors and direct calls in node #115; no execution."""
import hashlib
import struct
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
TARGET = ROOT / 'artifacts/node/115/hl-node'
SHA = 'a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301'
ANCHORS = {58124081: '48897c24188b6e0881fdaaaa0000bbaaaa00000f42dd85ed0f84bc0000004989', 58124114: '8d04dd000000004c8d3c404c89ffff151a0dd7024885c00f849901000048', 58124176: '488b4424084b8d0c64891cc80f284424400f1144c8048b5424508954c81449ffc44c89642410', 58124219: '41896e08488d7c24204c89fe31d2e822aaa8ff0fb64424203c090f85b50000008b5c2428418b', 58124251: '8b5c2428418b4510410f1045000f294424408944245085db74304c8b64', 58124273: '85db74304c8b6424104c3b242475904889e7ff15277dd702eb85', 58124299: '48c704240000000048c74424080800000048c744241000000000', 58124325: '488b44241048894424700f1004240f29442460488d7c2420488d742460e8a9d65400488b', 58124432: '8b4c24218b542424488b5c241889530c894b098b4c2428418b5510410f1045000f29442440895424508953240f11431488430889', 58124525: '488d35f4f302fdba0d000000e8c27d8dff'}
ANCHORS[0x79dce8] = "6475706c6963617465206b6579"


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
    for site, target in ((0x376e7c9, 0x31f91f0), (0x376e842, 0x3cbbef0), (0x376e8f9, 0x30466c0)):
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
    print(f'OK: {count} anchors, 3 direct-call targets; {count} anchor mutations rejected')


if __name__ == '__main__':
    main()
