#!/usr/bin/env python3
"""RE-018 independent verifier. Imports nothing from tools/.

Checks every key VA byte by byte against the pinned node #94 binary, re-derives each
call target, re-hashes each [-0x40,+6) window, re-runs the ff15 caller pass over
.text/.init/.fini/.plt with its own code, and checks the packet JSON against
MANIFEST.sha256. Prints PASS, FAIL or INCONCLUSIVE; exit 0, 1 or 2.
"""
import bisect
import hashlib
from pathlib import Path
import struct

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
BINARY = ROOT / 'artifacts' / 'node' / '94' / 'hl-node'
SHA256 = '3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f'
PACKET_JSON = HERE / 'materializer-call-abi.json'
SLOT = 0x5773aa8
SITES = (0x226685a, 0x2268f61, 0x4359d34, 0x4746097, 0x4b2c8e2)
WINDOW_BEFORE = 0x40

KEYS = [
    (0x226683a, '488dbc24404b0000'), (0x2266842, '488db424500a0000'), (0x226684a, '4c8db42420010000'),
    (0x2266852, '488d4c2450'), (0x2266857, '4c89f2'), (0x226685a, 'ff1548d25003'),
    (0x2266860, 'c6832a08000000'),
    (0x2268f12, 'bac81f0000'), (0x2268f17, '4c89ef'), (0x2268f20, '4c89a42400770000'),
    (0x2268f28, '4c89b42408770000'), (0x2268f46, '4c8da42400770000'), (0x2268f4e, '488d8c24f0000000'),
    (0x2268f56, '48897c2418'), (0x2268f5b, '4c89ee'), (0x2268f5e, '4c89e2'),
    (0x2268f61, 'ff1541ab5003'), (0x2268f67, 'c683f049000001'),
    (0x4359d11, '488dbc24804a0000'), (0x4359d19, '488db424300a0000'), (0x4359d21, '488d942470010000'),
    (0x4359d29, '4c8db424e0000000'), (0x4359d31, '4c89f1'), (0x4359d34, 'ff156e9d4101'),
    (0x4359d3a, '41c6852a08000000'),
    (0x474607a, '488dbc2400440000'), (0x4746082, '488db42440040000'), (0x474608a, '488d9424f0000000'),
    (0x4746092, '488d4c2430'), (0x4746097, 'ff150bda0201'), (0x474609d, 'c6834a06000000'),
    (0x4b2c8bf, '488dbc24a04a0000'), (0x4b2c8c7, '488db424a0090000'), (0x4b2c8cf, '488d942480010000'),
    (0x4b2c8d7, '4c8db42400010000'), (0x4b2c8df, '4c89f1'), (0x4b2c8e2, 'ff15c071c400'),
    (0x4b2c8e8, 'c6832a08000000'),
]
WINDOWS = {
    0x226685a: '075b66c40847507e08da722c48f3d6e797b8c0eaeb8d2dad53e90570f7f672fb',
    0x2268f61: '3e65fcde868013b53f4d3afe2ac52c156b051bf4dc95b5bdc91556d3b043222e',
    0x4359d34: '4fa51f80e5d4975a39eb0e18265b866f771114e5ec088d6eaead59bc7fb83299',
    0x4746097: '198667520dbd3291a2cc763f39a8e8af7dced316254d3e82c119adff81e270f6',
    0x4b2c8e2: '4045a5ab2ee545659ad589577d66061a1625996fa3f7ab6a26e381bb72a2f918',
}
CALLERS = [0x226685a, 0x2268f61, 0x3273920, 0x4359d34, 0x4746097, 0x4b2c8e2]
SCAN = (b'.text\0', b'.init\0', b'.fini\0', b'.plt\0')
FDES = {
    0x226685a: 0x22615b0, 0x2268f61: 0x22689f0, 0x3273920: 0x3273810,
    0x4359d34: 0x4356c90, 0x4746097: 0x4744160, 0x4b2c8e2: 0x4b29760,
}


def load_segments(data):
    phoff, = struct.unpack_from('<Q', data, 0x20)
    phentsize, phnum = struct.unpack_from('<HH', data, 0x36)
    segs = []
    for i in range(phnum):
        t, _f, off, va, _p, fs, _m, _a = struct.unpack_from('<IIQQQQQQ', data, phoff + i * phentsize)
        if t == 1:
            segs.append((va, off, fs))
    return segs


def at(data, segs, va, n):
    for base, off, size in segs:
        if base <= va and va + n <= base + size:
            return bytes(data[off + va - base: off + va - base + n])
    raise KeyError(hex(va))


def shdrs(data):
    shoff, = struct.unpack_from('<Q', data, 0x28)
    shentsize, shnum, shstrndx = struct.unpack_from('<HHH', data, 0x3a)
    sh = [struct.unpack_from('<IIQQQQIIQQ', data, shoff + i * shentsize) for i in range(shnum)]
    stroff = sh[shstrndx][4]
    for h in sh:
        name = bytes(data[stroff + h[0]: stroff + h[0] + 16]).split(b'\0', 1)[0] + b'\0'
        yield name, h


def fde_start(data, segs, va):
    for name, h in shdrs(data):
        if name == b'.eh_frame_hdr\0':
            o, a = h[4], h[3]
            if tuple(data[o + 1:o + 4]) != (0x1b, 0x03, 0x3b):
                raise ValueError('eh_frame_hdr encodings')
            n, = struct.unpack_from('<I', data, o + 8)
            tab = [struct.unpack_from('<ii', data, o + 12 + 8 * i) for i in range(n)]
            starts = [a + x for x, _ in tab]
            i = bisect.bisect_right(starts, va) - 1
            fva = a + tab[i][1]
            b = at(data, segs, fva, 16)
            pc, = struct.unpack_from('<i', b, 8)
            return fva + 8 + pc
    raise KeyError('.eh_frame_hdr')


def check_callers(data):
    found = []
    n_sec = 0
    for name, h in shdrs(data):
        if name not in SCAN:
            continue
        n_sec += 1
        addr, b = h[3], bytes(data[h[4]:h[4] + h[5]])
        i = b.find(b'\xff\x15')
        while i != -1 and i + 6 <= len(b):
            t = addr + i + 6 + struct.unpack_from('<i', b, i + 2)[0]
            if t == SLOT:
                found.append(addr + i)
            i = b.find(b'\xff\x15', i + 1)
    fails = [] if n_sec == len(SCAN) else [f'scanned {n_sec} sections != {len(SCAN)}']
    if found != CALLERS:
        fails.append(f'ff15 -> {SLOT:#x}: {[hex(x) for x in found]} != {[hex(x) for x in CALLERS]}')
    return fails


def check_keys(data, check_sha=True, callers=True, windows=True):
    if check_sha and hashlib.sha256(data).hexdigest() != SHA256:
        return ['binary sha256 mismatch']
    fails = []
    segs = load_segments(data)
    for va, hx in KEYS:
        got = at(data, segs, va, len(hx) // 2).hex()
        if got != hx:
            fails.append(f'{va:#x}: {got} != {hx}')
    for site in SITES:
        b = at(data, segs, site, 6)
        t = site + 6 + struct.unpack_from('<i', b, 2)[0]
        if t != SLOT:
            fails.append(f'{site:#x}: target {t:#x} != {SLOT:#x}')
        if fde_start(data, segs, site) != FDES[site]:
            fails.append(f'{site:#x}: fde {fde_start(data, segs, site):#x} != {FDES[site]:#x}')
        if windows:
            w = at(data, segs, site - WINDOW_BEFORE, WINDOW_BEFORE + 6)
            if hashlib.sha256(w).hexdigest() != WINDOWS[site]:
                fails.append(f'{site:#x}: window sha mismatch')
    if callers:
        fails += check_callers(data)
    return fails


def check_packet():
    manifest = HERE / 'MANIFEST.sha256'
    if not manifest.exists() or not PACKET_JSON.exists():
        return ['packet json or MANIFEST.sha256 missing']
    pins = dict(reversed(line.split('  ', 1)) for line in manifest.read_text().splitlines() if line)
    if hashlib.sha256(PACKET_JSON.read_bytes()).hexdigest() != pins.get('materializer-call-abi.json'):
        return ['materializer-call-abi.json does not match MANIFEST.sha256']
    return []


def main():
    if not BINARY.exists():
        print('INCONCLUSIVE: binary not present at', BINARY)
        return 2
    try:
        fails = check_keys(BINARY.read_bytes()) + check_packet()
    except (KeyError, ValueError, struct.error) as e:
        print('INCONCLUSIVE:', e)
        return 2
    for f in fails:
        print('FAIL', f)
    print(f'{"FAIL" if fails else "PASS"}: key_insns={len(KEYS)} sites={len(SITES)} windows={len(WINDOWS)} '
          f'callers={len(CALLERS)} failures={len(fails)}')
    return 1 if fails else 0


if __name__ == '__main__':
    raise SystemExit(main())
