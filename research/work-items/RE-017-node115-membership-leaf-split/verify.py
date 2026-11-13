#!/usr/bin/env python3
"""Check bounded instruction anchors and direct calls in node #115; no execution."""
import hashlib
import struct
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
TARGET = ROOT / 'artifacts/node/115/hl-node'
SHA = 'a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301'
ANCHORS = {79926691: '4c8b7e104983ff0548898c24a0000000730f4c897c240841bf0400000031dbeb3574194983ff06751c41bf05000000b30148c744240800000000eb1a31db4c897c2408eb114983c7f94c897c240841bf06000000b301', 79926777: '488b46084889442418bfe8000000ff15735e8a014885c00f84d90700004989c648c7000000000066c780e600000000000fb785e60000004c89fe48f7d64801c6664189b6e60000004b8d04bf8b4c8518898c24800000000f104485080f294424704883fe0c0f83750700004c89ac2498000000488d0485080000004801e84883c014498d7e0848c1e602488d14b64889c6ff15785e8a01664489bde60000000f284424700f2944', 79926957: '31c084db4c89f1480f44cd480f4444241848898424900000000fb799e600000048894c24404c8d7908488b4c24084c8d2c894839cb761d4b8d34af4b8d3caf4883c71489d829c8c1e002488d1480ff15675e8a01ffc3418b442410438944af10410f100424430f1104af488b442440668998e6000000', 85797936: '4c8d44245c488dbc24a0000000488db42480000000488d542460488d4c2428e8ac68a6ff488b742428eb5d4889fbbfe8'}


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
    for site, target in ((0x51d2c4f, 0x4c39500),):
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
