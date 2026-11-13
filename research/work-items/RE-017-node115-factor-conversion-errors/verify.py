#!/usr/bin/env python3
"""Check bounded instruction anchors and direct calls in node #115; no execution."""
import hashlib
import struct
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
TARGET = ROOT / 'artifacts/node/115/hl-node'
SHA = 'a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301'
ANCHORS = {69330144: '534881eca00000004889fb488b4608488b5610488d7c24204889c6ff155f692c020fb74424203da201000075510f104424240f114424020f29842490000000488dbc2490000000ff153b692c0266c7442420af004883f8010f858c000000f20f11430866c703a201488d7c2420e87e3b01004889d84881c4a00000005bc3', 69330270: '0fb74c243266894c24100f104424220f2904240f108424800000000f1143600f104424740f1143540f104424640f1143440f104424540f1143340f104424440f1143240f104424340f1143140fb74c241066894b120f2804240f1143026689034889d84881c4a00000005bc3', 69330378: '0f288424800000000f2943600f284424700f2943500f284424600f2943400fb7442420488b4c24228b54242a0fb774242e0f284424300f284c24400f285424500f2953300f294b200f29431066890348894b0289530a6689730e4889d84881c4a00000005bc3', 87609987: '0fb74424203da20100000f858b530000', 87610090: '0fb74424203da2010000f30f7e9c24000200000f85f27a0000', 87631390: '0fb74c2426488b54240866894a068b4c2422894a02f20f104424280f284c24400f294a200f284c24500f294a300f284c24600f294a400f284c24700f294a500f288c24800000000f294a60660f284c2430660f294a10668902f20f114208', 87641589: '0fb74c2426488b54240866894a068b4c2422894a02f30f7e4424280f284c24400f294a200f284c24500f294a300f284c24600f294a400f284c24700f294a500f288c24800000000f294a60660f284c2430660f294a10668902660fd64208'}


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
    for site, target in ((0x421e54d, 0x42320d0),):
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
