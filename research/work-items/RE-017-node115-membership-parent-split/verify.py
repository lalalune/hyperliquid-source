#!/usr/bin/env python3
"""Check bounded instruction anchors and direct calls in node #115; no execution."""
import hashlib
import struct
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
TARGET = ROOT / 'artifacts/node/115/hl-node'
SHA = 'a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301'
ANCHORS = {79927181: '0fb792e4000000440fb7a8e60000004983fd0b4c897424480f820a0400006683fa05730f488954241041bf0400000031dbeb404883fa05741883fa06751fb30141bf0500000048c744241000000000eb2231db48895424104989d7eb164883c2f94889542410b30141bf060000000f1f440000', 79927296: 'bf48010000ff15755c8a014885c00f849a0500004989c44989c649c70424000000006641c78424e600000000000fb785e60000004c89fe48f7d64801c6664189b424e60000004b8d04bf8b4c8518898c24800000000f104485080f294424704883fe0c0f83f7040000488d0485080000004801e84883c014498d7c240848c1e602488d14b64889c6ff157a5c8a0148892c24664489bde60000000f284424700f294424508b84248000000089442460', 79927471: '410fb7aee6000000488d55014883fd0c0f83b40400004529fd4139d50f85ed04000048ff442418498dbc24e8000000488b04244a8d34f84881c6f0000000c1e203ff15125c8a0131c00f1f8400000000004889c14839e84883d000498b94cee80000004c893266898ae40000004839e973054839e876da', 79927614: '84db4c0f442424410fb7ac24e6000000488b542410488d5a014989e8488d04924d8d2c844983c5084929d00f8681000000498d442408488d0c9b488d3c884189ef4129d7428d04bd00000000488d14804c89ee4c898424a8000000ff15c95b8a010f28442420410f1145008b44243041894510498d34dc4881c6e8000000488b442410498d3cc44881c7f800000041c1e7034c89faff158f5b8a014c8b8424a8000000488b542410eb1a0f1f8400000000008b442430418945100f28442420410f114500488b7424488d4d01488d45024989b4d4f00000006641898c24e600000039c3', 79927847: '29d5ffc583e503742c498d14d44881c2f000000031c90f1f00488b34ca4c89268d3c0b6689bee400000048ffc14839cd75e74801cb4183f8030f82eafcffff662e0f1f840000000000498b8cdce80000004c8921668999e4000000498b8cdcf00000004c89218d5301668991e4000000498b8cdcf80000004c89218d5302668991e4000000498b8cdc000100004c89218d5303668991e40000004883c3044839c375a6'}


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
