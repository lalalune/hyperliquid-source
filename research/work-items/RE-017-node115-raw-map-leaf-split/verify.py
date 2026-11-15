#!/usr/bin/env python3
"""Check bounded instruction anchors and direct calls in node #115; no execution."""
import hashlib
import struct
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
TARGET = ROOT / 'artifacts/node/115/hl-node'
SHA = 'a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301'
ANCHORS = {79950536: '4c8b7e104983ff0548897c24784c898424a00000000f83b40000004c897c241841bf0400000031db', 79950743: '74194983ff06751c41bf05000000b30148c744241800000000eb1a31db4c897c2418eb114983c7f94c897c241841bf06000000b301488b46084889442430bfe8000000ff15a0008a014885c00f84520900004989c648892c2448c7000000000066c780e60000000000410fb78424e60000004c89fd48f7d54801c5664189aee60000004b8b74fc084b8d047f418b4c8468894c2460498b44846048894424584883fd0c0f83e20800004c896c24284889742420498d442408498d4c246048894c24404a8d74f808498d7e08488d14ed000000004c8b2d97008a0141ffd54b8d047f4883c003488b4c2440488d3481498d7e6048c1e502488d146d000000004801ea41ffd54d89e0664589bc24e6000000488b44245848894424488b4424608944245031c084db4d89f54d0f44ec480f444424304889442470410fb79de6000000488b4c24184839cb765f498d4508488d34cd080000004c01ee488d3cc84883c7084189df4129cf428d14fd00000000488b2d5b008a01ffd5488b442418488d0440488d3485600000004c01ee488d3c856c0000004c01ef41c1e7024b8d147fffd54d89e0488b4c2418488b0424498944cd08ffc3488d0449488b5424288b4a0841894c8568488b0a49894c85604c896c24686641899de60000008b44245089442410488b4424484889442408498b004885c00f842004000048837c2430000f94'}


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
