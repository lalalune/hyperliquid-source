#!/usr/bin/env python3
"""Check bounded instruction anchors and direct calls in node #115; no execution."""
import hashlib
import struct
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
TARGET = ROOT / 'artifacts/node/115/hl-node'
SHA = 'a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301'
ANCHORS = {87328240: '488d7c2418488d742440e8719383004c8b7c2428', 95951216: '554157415641554154534881ec980000004989f64989fc833e027540498d4e08', 95951239: '833e027540498d4e08498b4608498b56104839d0751e410f1046180f1101', 95951291: '488d50684889114885c07516e9890200004c89f7e8dc595bff4885', 95951308: '4c89f7e8dc595bff4885c00f84780200000f10000f1048100f294c24300f294424204183', 95951399: '48ffc048c7c1ffffffff480f45c84883f905bb04000000480f43d94989df49c1e70548', 95951487: '0f284424200f284c24300f1148100f110048895c2408488944241048c74424', 95951616: '0f284424700f288c2480000000410f114c1d10410f11441d0049ffc64c897424184883c320', 95951714: '488d486848894c24284885c07521e9ba0000', 95951744: '4c89e7e828585bff4885c00f849e0000000f10000f1048100f298c24800000000f29442470', 95951876: 'b90100000041b8200000004c89ff4c89f6e8f61ddeff4c8b6c2410e9dcfeff', 95951919: '488b4424184c8b64246849894424100f10442408410f110424eb2531c04885c00f8588fdff', 95951957: '49c704240000000049c74424080100000049c744241000000000'}


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
    for site, target in ((0x53485fa, 0x5b81970), (0x5b819cf, 0x51373b0), (0x5b81b83, 0x51373b0), (0x5b81c15, 0x5963a10)):
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
