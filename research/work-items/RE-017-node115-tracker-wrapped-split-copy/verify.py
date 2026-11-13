#!/usr/bin/env python3
"""Check bounded instruction anchors and direct calls in node #115; no execution."""
import hashlib
import struct
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
TARGET = ROOT / 'artifacts/node/115/hl-node'
SHA = 'a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301'
ANCHORS = {81680004: '4c89f74889d6e801d2a000498b6e184989ef4929c70f82a40300004c89f948c1e104488d348948b99a9999999999990148ffc94939cf760831ffff15d49d6f014885f60f84760200004989c4488934244889f7ff15a39d6f014885c00f84830300004889c74c89fe4c89e04885ed488934240f845b020000498b561031c94c39ea490f43cd4829ca4c89e94829d14989ec4929cc0f87410200004801d54531e44989ede933020000', 81680735: '498b76084929d54889c14c29e9735b488d0c9248c1e1044929c5488d148048c1e2044801ca4801f249c1e5044f8d6cad004889fd48897424284889d648898424c00000004c89eaff155c9b6f014901ed49c1e4044b8d14a44c89ef4c8bac24c0000000488b742428eb1c4929cc488d0c8948c1e1044801ce49c1e4044989c54b8d14a44889fdff151d9b6f014d896e18488b0424488944240848896c241048c7442418000000004c897c2420488b442408488b4c2410488b54241848895310488b5424204889531848890348894b084889d84881c4c80000005b415c415d415e415f5dc3'}


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
    for site, target in ((0x4de568a, 0x57f2890),):
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
