#!/usr/bin/env python3
"""Check bounded instruction anchors and direct calls in node #115; no execution."""
import hashlib
import struct
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
TARGET = ROOT / 'artifacts/node/115/hl-node'
SHA = 'a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301'
ANCHORS = {95395942: '498d4648498db688000000488914244c897424084889442410488974241848894c2420488d4424404889442428488d44243848894424304889e6', 92096127: '488b5c2478488b7308488d7c24104c8bbc24800000004c89fae85337baff498d460148394424100f849c030000', 92096172: '0f104424600f298424800100000f104424500f298424700100000f104424100f104c24200f105424300f105c24400f299c24600100000f299424500100000f298c24400100000f298424300100000f298c24a00000000f298424900000000f299c24a00100000f2994249001', 92096296: '488b4320488b485848898c24880000004c8b842490000000488b8c2498000000488b9424', 92096859: '488dbc24d0000000488d742410e8c35e3a0031ed488dbc24b0000000488db424d0000000e8acb95eff488d8424', 92096900: '488d842470010000488b5b100f10000f1048100f298c24200100000f298424100100000f1050e00f1058f00f10a424b00000000f10ac24c00000004c897c24100f116424180f116c24280f115424380f115c24480f114424580f114c24684c8b73104c3b33750948', 92097004: '89dfff151c07d100488b4308496bce68488b54247048895408600f104424600f114408500f104424500f114408400f104424100f104c24200f105424300f105c24400f115c08300f115408200f114c08100f11040849ffc64c89731031'}


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
    for site, target in ((0x57d4698, 0x5377df0), (0x57d4968, 0x5b7a830), (0x57d497f, 0x4dc0330)):
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
