#!/usr/bin/env python3
"""Check bounded instruction anchors and direct calls in node #115; no execution."""
import hashlib
import struct
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
TARGET = ROOT / 'artifacts/node/115/hl-node'
SHA = 'a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301'
ANCHORS = {95971669: '4b8d0c644c8d2cc84983c50c4c8db424880000004c8d7c242066904c89f74c89fee8f55a65ff488b8424880000004885c07433488b942498000000488d34528b4cb06085c9741f488b54d008488b44b064498955f441894dfc4989450049ffc44983c518ebb5', 85836926: '488b46404885c00f848e00000048ffc848894640833e010f8570030000488b7e084885ff0f8403010000488b46104c8b76180fb78fe60000004939ce0f83940100004989c44989ff4d85e40f84e90100004b8d0cf74881c1f00000', 85837007: '4b8d0cf74881c1f00000004c89e24883e2070f84da0100004531c0660f1f440000488b01488d88e800000049ffc04c39c275ee4c89e74c29c731d24983fc080f83bc010000e9f8010000', 85837081: '488b16488b4e084c8b7610488b461848c706000000004883fa0175694885c90f84fe0100004d89f74989ce498b064885c0743641bce8000000488b1d472f30014c89f70f1f40004989c64d85ff4d8d7f01be48010000490f44f431d2ffd3498b064c89f74885c075de4d85ffb8e8000000be48010000480f44f04c89f731d2ff15022f300149c7450000000000e98201', 85837396: '4c892c244989f5bde8000000488b1d392e3001660f1f8400000000004c8b3f4d85ff0f84670100004c8d6001440fb7b7e40000004885c0be48010000480f44f531d2ffd34c89ff4c89e066453bb7e600000073c84c89ee4c8b2c244d85e40f8517feffff', 85837496: '498d56014c89f8eb50', 85837505: '4c89e731d24983fc0872450f1f4000488b01488b80e8000000488b80e8000000488b80e8000000488b80e8000000488b80e8000000488b80e8000000488b80e8000000488d88e80000004883c7f875bf4d897d004d8965084d8975104889460848c746100000000048895618'}


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
    for site, target in ((0x5b86976, 0x51dc470),):
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
