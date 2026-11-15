#!/usr/bin/env python3
"""Check bounded instruction anchors and direct calls in node #115; no execution."""
import hashlib
import struct
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
TARGET = ROOT / 'artifacts/node/115/hl-node'
SHA = 'a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301'
ANCHORS = {96750414: '448b1f448b47044489ddc1ed1081e5ff0000007417488b7f0841f7c3000001007532b8010000004531ffeb39', 96750498: 'b80a0000004531ff83fd010f841c01000041f7c3000002007420b96400000048f7e14989d74489d981e10000fe0081f9000002000f84f300000041f7c3000004007420b91027000048f7e14989d74489d9', 96750597: '41f7c3000008007420b900e1f50548f7e14989d74489d981e10000f80081f9000008000f84a100000041f7c300001000742148b90000c16ff286230048f7e14989d74489d981e10000f00081f9000010007477', 96750680: '41f7c3000020000f846b01000048bb0000000081efac854889c14c89f848f7e34889c60f90c04d85ff410f95c14108c148ba5b416d2dee0400004889c848f7e2410f90c24508ca4801c64889c848f7e34989d74901f70f92c14408d10f85160100004489d981e10000e00081f9000020000f8501010000', 96750799: '896c242444895c24144489c54889ee4889c24c89f94889fb4989c6ff1508ae89004989c44889d648895424184889c1490fafcf49f7e64801ca490faff64801d64829c34819f54c8b2d6ccb89004889df4889ee41ffd5f20f114424084c89f74c89feff15b1148a00f20f104c2408f20f5ec8f20f114c24084c89e7488b74241841ffd5', 96751056: '488d3d99c28700ff1593aa8900'}


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
