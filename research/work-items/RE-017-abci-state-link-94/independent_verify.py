#!/usr/bin/env python3
"""RE-017 independent verifier. Imports nothing from tools/.

Checks every key VA byte by byte against the pinned node #94 binary, re-derives each
rel32 / RIP-relative target, re-parses .rela.dyn for slot 0x57755a8 and the Location
pointer, re-reads the Location record, re-runs the e8/ff15 caller pass over
.text/.init/.fini/.plt with its own code, and checks the packet JSON against MANIFEST.sha256.
Prints PASS, FAIL or INCONCLUSIVE; exit 0, 1 or 2.
"""
import hashlib
from pathlib import Path
import struct

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
BINARY = ROOT / 'artifacts' / 'node' / '94' / 'hl-node'
SHA256 = '3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f'
PACKET_JSON = HERE / 'abci-state-link.json'
EXTENT = (0x3273810, 0x327396c, 'ae961c6ff6f14718032ef8b469845ff4ecd79501528c5902a5f046cc584349f6')

KEYS = [
    (0x3272785, 'ff151d2e5002'), (0x327278b, '83bc24503b000002'), (0x3272793, '0f847a020000'),
    (0x327276f, '488dbc24503b0000'), (0x3273810, '4157415641554154534881ec00100000'),
    (0x3273846, '4881ecb00f0000'), (0x327384d, '4d89c7'), (0x3273850, '4889cb'), (0x3273853, '4989fe'),
    (0x3273856, '488d0d9bc34602'), (0x327385d, '488d7c2420'), (0x3273862, 'e8391d9a00'),
    (0x3273871, '4983fd02'), (0x3273875, '7541'), (0x3273877, '4d896608'), (0x327387b, '49c70602000000'),
    (0x3273890, 'ff157aa74f02'), (0x327389d, 'e8be631800'), (0x32738b0, 'ff155aa74f02'),
    (0x32738b8, '488d742430'), (0x32738bd, '488dbc24f81f0000'), (0x32738c5, 'bab81f0000'),
    (0x32738ca, 'ff1510a74f02'), (0x32738d0, '4c89ac24e81f0000'), (0x32738d8, '4c89a424f01f0000'),
    (0x327390d, '488db424e81f0000'), (0x3273915, '4889e2'), (0x3273918, '488d4c2420'),
    (0x327391d, '4c89f7'), (0x3273920, 'ff1582015002'), (0x3273926, '4c89f0'),
    (0x3273929, '4881c4b03f0000'), (0x3273939, 'c3'),
]
# (site, insn length, expected target)
TARGETS = [
    (0x3272785, 6, 0x57755a8), (0x3273856, 7, 0x56dfbf8), (0x3273862, 5, 0x3c155a0),
    (0x3273890, 6, 0x576e010), (0x327389d, 5, 0x33f9c60), (0x32738b0, 6, 0x576e010),
    (0x32738ca, 6, 0x576dfe0), (0x3273920, 6, 0x5773aa8),
]
CALLERS = {
    ('e8', 0x3273810): [],
    ('ff15', 0x57755a8): [0x3272785],
    ('ff15', 0x5773aa8): [0x226685a, 0x2268f61, 0x3273920, 0x4359d34, 0x4746097, 0x4b2c8e2],
}
SCAN = (b'.text\0', b'.init\0', b'.fini\0', b'.plt\0')
LOCATION = (0x56dfbf8, 0x1dd8eb, 49, 107, 37, b'/home/ubuntu/hl/code_Mainnet/l1/src/abci/state.rs')


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


def rela(data):
    for name, h in shdrs(data):
        if name == b'.rela.dyn\0':
            for o in range(h[4], h[4] + h[5], 24):
                yield struct.unpack_from('<QQq', data, o)
            return
    raise KeyError('.rela.dyn')


def check_callers(data):
    found = {k: [] for k in CALLERS}
    want = {}
    for op, t in CALLERS:
        want.setdefault(op, set()).add(t)
    n_sec = 0
    for name, h in shdrs(data):
        if name not in SCAN:
            continue
        n_sec += 1
        addr, b = h[3], bytes(data[h[4]:h[4] + h[5]])
        for op, pat, n in (('e8', b'\xe8', 5), ('ff15', b'\xff\x15', 6)):
            i = b.find(pat)
            while i != -1 and i + n <= len(b):
                t = addr + i + n + struct.unpack_from('<i', b, i + n - 4)[0]
                if t in want[op]:
                    found[(op, t)].append(addr + i)
                i = b.find(pat, i + 1)
    fails = [] if n_sec == len(SCAN) else [f'scanned {n_sec} sections != {len(SCAN)}']
    for k, v in CALLERS.items():
        if sorted(found[k]) != v:
            fails.append(f'{k[0]} -> {k[1]:#x}: {[hex(x) for x in sorted(found[k])]} != {[hex(x) for x in v]}')
    return fails


def check_keys(data, check_sha=True, callers=True):
    if check_sha and hashlib.sha256(data).hexdigest() != SHA256:
        return ['binary sha256 mismatch']
    fails = []
    segs = load_segments(data)
    for va, hx in KEYS:
        got = at(data, segs, va, len(hx) // 2).hex()
        if got != hx:
            fails.append(f'{va:#x}: {got} != {hx}')
    for site, n, want in TARGETS:
        b = at(data, segs, site, n)
        t = site + n + struct.unpack_from('<i', b, n - 4)[0]
        if t != want:
            fails.append(f'{site:#x}: target {t:#x} != {want:#x}')
    s, e, h = EXTENT
    if hashlib.sha256(at(data, segs, s, e - s)).hexdigest() != h:
        fails.append('extent 0x3273810..0x327396c bytes sha256 mismatch')
    slot, carriers, loc_ptr = [], [], []
    for off, info, add in rela(data):
        if off == 0x57755a8:
            slot.append((info & 0xffffffff, info >> 32, add))
        if add == 0x3273810:
            carriers.append(off)
        if off == LOCATION[0]:
            loc_ptr.append((info & 0xffffffff, add))
    if slot != [(8, 0, 0x3273810)]:
        fails.append(f'reloc 0x57755a8: {slot}')
    if carriers != [0x57755a8]:
        fails.append(f'addend 0x3273810 carried by {[hex(x) for x in carriers]}')
    if loc_ptr != [(8, LOCATION[1])]:
        fails.append(f'Location pointer reloc {loc_ptr}')
    ln, line, col = struct.unpack('<QII', at(data, segs, LOCATION[0] + 8, 16))
    if (ln, line, col) != LOCATION[2:5] or at(data, segs, LOCATION[1], ln) != LOCATION[5]:
        fails.append(f'Location record ({ln}, {line}, {col})')
    return fails + (check_callers(data) if callers else [])


def check_packet():
    manifest = HERE / 'MANIFEST.sha256'
    if not manifest.exists() or not PACKET_JSON.exists():
        return ['packet json or MANIFEST.sha256 missing']
    pins = dict(reversed(line.split('  ', 1)) for line in manifest.read_text().splitlines() if line)
    if hashlib.sha256(PACKET_JSON.read_bytes()).hexdigest() != pins.get('abci-state-link.json'):
        return ['abci-state-link.json does not match MANIFEST.sha256']
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
    print(f'{"FAIL" if fails else "PASS"}: keys={len(KEYS)} targets={len(TARGETS)} extent=1 relocs=2 '
          f'location=1 callers={sum(len(v) for v in CALLERS.values())}/{len(CALLERS)} failures={len(fails)}')
    return 1 if fails else 0


if __name__ == '__main__':
    raise SystemExit(main())
