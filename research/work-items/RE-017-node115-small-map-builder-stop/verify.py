#!/usr/bin/env python3
"""Check bounded instruction anchors and direct calls in node #115; no execution."""
import hashlib
import struct
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
TARGET = ROOT / 'artifacts/node/115/hl-node'
SHA = 'a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301'
ANCHORS = {81659900: '48894c242848894c24484889442468488d7c2470488d742428e84660da000f10442470488b84248000000048c74424180000000048894424200f11442408', 95971440: '4989f64c8b7e404a8d04fd00000000488d344048b855555555555555054939c7760a31ffff15fe8b95000f0b4889fb4885f6741b4989f44889f7ff15d08b95004885c07512bf080000004c89e6ebd5b8080000004531ff4c897c2408488944241048c744241800000000', 95971669: '4b8d0c644c8d2cc84983c50c4c8db424880000004c8d7c242066904c89f74c89fee8f55a65ff488b8424880000004885c07433488b942498000000488d34528b4cb06085c9741f488b54d008488b44b064498955f441894dfc4989450049ffc44983c518ebb5', 95971771: '4c896424184c8d7424704c8d7c2420660f1f4400004c89f74c89fee8955a65ff48837c24700075ed488b442418488943100f104424080f11034889d84881c4f00000005b415c415d415e415fc3'}


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
    for site, target in ((0x4de0815, 0x5b86860), (0x5b86976, 0x51dc470), (0x5b869d6, 0x51dc470)):
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
