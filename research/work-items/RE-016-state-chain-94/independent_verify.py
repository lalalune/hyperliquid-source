#!/usr/bin/env python3
"""RE-016 independent verifier. Imports nothing from tools/.

Checks every key VA of the chain byte by byte against the pinned node #94 binary,
re-derives each rel32 / RIP-relative target from those bytes, re-parses .rela.dyn for
the two GOT slots, rescans .text/.init/.fini/.plt for every e8/ff15 site reaching the chain, and checks the packet JSON against MANIFEST.sha256.
Prints PASS, FAIL or INCONCLUSIVE; exit 0, 1 or 2.
"""
import hashlib
from pathlib import Path
import struct
import sys

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
BINARY = ROOT / 'artifacts' / 'node' / '94' / 'hl-node'
SHA256 = '3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f'
PACKET_JSON = HERE / 'state-chain.json'

KEYS = [
    # materializer 0x3751e80
    (0x3751e80, '554157415641554154', 'materializer prologue push rbp,r15,r14,r13,r12'),
    (0x3751eb8, '4989fe', 'materializer: mov r14,rdi (output object)'),
    (0x375220d, '488dbc2450050000', 'materializer: lea rdi,[rsp+0x550] (callee out buffer)'),
    (0x3752220, 'e84be3b1ff', 'materializer: call 0x3270570 (rel32)'),
    (0x3752287, '4c8b3d52bd0102', 'materializer: mov r15,[0x576dfe0] (memcpy slot)'),
    (0x375285e, '498dbec00b0000', 'materializer: lea rdi,[r14+0xbc0]'),
    (0x3752865, '488db42450050000', 'materializer: lea rsi,[rsp+0x550]'),
    (0x375286d, 'bae8250000', 'materializer: mov edx,0x25e8'),
    (0x3752872, '41ffd7', 'materializer: call r15 (memcpy)'),
    (0x37529a1, '4c89f0', 'materializer: mov rax,r14'),
    (0x37529b5, 'c3', 'materializer: ret'),
    # wrapper 0x3270570
    (0x3270570, '5541574156', 'wrapper prologue push rbp,r15,r14'),
    (0x32705ac, '4889fb', 'wrapper: mov rbx,rdi (output object)'),
    (0x327066d, '488dbc24700a0000', 'wrapper: lea rdi,[rsp+0xa70] (callee out buffer)'),
    (0x3270682, 'ff15f84e5002', 'wrapper: call [rip+0x2504ef8] -> slot 0x5775580, no index register'),
    (0x32706a5, '488b2d34d94f02', 'wrapper: mov rbp,[0x576dfe0] (memcpy slot)'),
    (0x327074e, '488db424700a0000', 'wrapper: lea rsi,[rsp+0xa70]'),
    (0x3270756, 'ba381b0000', 'wrapper: mov edx,0x1b38'),
    (0x327075b, '4889df', 'wrapper: mov rdi,rbx'),
    (0x327075e, 'ffd5', 'wrapper: call rbp (memcpy)'),
    (0x327079f, '4889d8', 'wrapper: mov rax,rbx'),
    (0x32707b3, 'c3', 'wrapper: ret'),
    # leaf 0x326e460
    (0x326e460, '41574156534881ec00100000', 'leaf prologue push r15,r14,rbx; sub rsp,0x1000'),
    (0x326e47b, '4889d3', 'leaf: mov rbx,rdx'),
    (0x326e47e, '4989f7', 'leaf: mov r15,rsi'),
    (0x326e481, '4989fe', 'leaf: mov r14,rdi'),
    (0x326e48a, 'e811245600', 'leaf: call 0x37d08a0'),
    (0x326e49f, 'e89cef0b00', 'leaf: call 0x332d440'),
    (0x326e4ab, 'e880695600', 'leaf: call 0x37d4e30'),
    (0x326e4b0, '488d7c2460', 'leaf: lea rdi,[rsp+0x60]'),
    (0x326e4bb, 'e820b6ffff', 'leaf: call 0x3269ae0 (top LtHash fn, #262/#316)'),
    (0x326e4c0, '498b4710', 'leaf: mov rax,[r15+0x10]'),
    (0x326e4c4, '498986301b0000', 'leaf: mov [r14+0x1b30],rax'),
    (0x326e4cb, '410f1007', 'leaf: movups xmm0,[r15]'),
    (0x326e4cf, '410f1186201b0000', 'leaf: movups [r14+0x1b20],xmm0'),
    (0x326e4d7, '488d742460', 'leaf: lea rsi,[rsp+0x60]'),
    (0x326e4dc, 'ba201b0000', 'leaf: mov edx,0x1b20'),
    (0x326e4e1, '4c89f7', 'leaf: mov rdi,r14'),
    (0x326e4e4, 'ff15f6fa4f02', 'leaf: call [0x576dfe0] (memcpy)'),
    (0x326e4f0, '740c', 'leaf: je 0x326e4fe (skip free when [rbx]==0)'),
    (0x326e4f8, 'ff1512fb4f02', 'leaf: call [0x576e010] (free)'),
    (0x326e4fe, '4c89f0', 'leaf: mov rax,r14'),
    (0x326e50d, 'c3', 'leaf: ret'),
]
# (site, length, expected target): rel32 for e8, RIP slot for ff15 / 8b
TARGETS = [
    (0x3752220, 5, 0x3270570), (0x3270682, 6, 0x5775580),
    (0x326e48a, 5, 0x37d08a0), (0x326e49f, 5, 0x332d440), (0x326e4ab, 5, 0x37d4e30),
    (0x326e4bb, 5, 0x3269ae0), (0x326e4e4, 6, 0x576dfe0), (0x326e4f8, 6, 0x576e010),
    (0x3752287, 7, 0x576dfe0), (0x32706a5, 7, 0x576dfe0),
]
RELOCS = {0x5773aa8: 0x3751e80, 0x5775580: 0x326e460}
# whole-section caller pass: every byte offset tried as e8 rel32 / ff15 rip slot
CALLERS = {
    ('e8', 0x3751e80): [], ('e8', 0x326e460): [], ('e8', 0x3270570): [0x3752220],
    ('ff15', 0x5773aa8): [0x226685a, 0x2268f61, 0x3273920, 0x4359d34, 0x4746097, 0x4b2c8e2],
    ('ff15', 0x5775580): [0x3270682],
}
SCAN = (b'.text\0', b'.init\0', b'.fini\0', b'.plt\0')


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


def rela(data):
    shoff, = struct.unpack_from('<Q', data, 0x28)
    shentsize, shnum, shstrndx = struct.unpack_from('<HHH', data, 0x3a)
    sh = [struct.unpack_from('<IIQQQQIIQQ', data, shoff + i * shentsize) for i in range(shnum)]
    stroff = sh[shstrndx][4]
    for h in sh:
        name = bytes(data[stroff + h[0]: stroff + h[0] + 10])
        if name == b'.rela.dyn\0':
            for o in range(h[4], h[4] + h[5], 24):
                yield struct.unpack_from('<QQq', data, o)
            return
    raise KeyError('.rela.dyn')


def section_hdrs(data):
    shoff, = struct.unpack_from('<Q', data, 0x28)
    shentsize, shnum, shstrndx = struct.unpack_from('<HHH', data, 0x3a)
    sh = [struct.unpack_from('<IIQQQQIIQQ', data, shoff + i * shentsize) for i in range(shnum)]
    stroff = sh[shstrndx][4]
    for h in sh:
        for n in SCAN:
            if bytes(data[stroff + h[0]: stroff + h[0] + len(n)]) == n:
                yield h[3], h[4], h[5]


def check_callers(data):
    found = {k: [] for k in CALLERS}
    want = {}
    for (op, t) in CALLERS:
        want.setdefault(op, set()).add(t)
    n_sec = 0
    for addr, offset, size in section_hdrs(data):
        n_sec += 1
        b = bytes(data[offset:offset + size])
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
            fails.append(f'{k[0]} -> {k[1]:#x}: sites {[hex(x) for x in sorted(found[k])]} != {[hex(x) for x in v]}')
    return fails


def check_keys(data, check_sha=True):
    """Return a list of failure strings (empty means every key holds)."""
    fails = []
    if check_sha and hashlib.sha256(data).hexdigest() != SHA256:
        return ['binary sha256 mismatch']
    segs = load_segments(data)
    for va, hx, role in KEYS:
        got = at(data, segs, va, len(hx) // 2).hex()
        if got != hx:
            fails.append(f'{va:#x} {role}: {got} != {hx}')
    for site, n, want in TARGETS:
        b = at(data, segs, site, n)
        disp, = struct.unpack_from('<i', b, n - 4)
        if site + n + disp != want:
            fails.append(f'{site:#x}: target {site + n + disp:#x} != {want:#x}')
    seen = {k: [] for k in RELOCS}
    by_addend = {v: [] for v in RELOCS.values()}
    for off, info, add in rela(data):
        if off in seen:
            seen[off].append((info & 0xffffffff, info >> 32, add))
        if add in by_addend:
            by_addend[add].append(off)
    for slot, target in RELOCS.items():
        if seen[slot] != [(8, 0, target)]:
            fails.append(f'reloc {slot:#x}: {seen[slot]} != [(8, 0, {target:#x})]')
        if by_addend[target] != [slot]:
            fails.append(f'addend {target:#x} carried by {[hex(x) for x in by_addend[target]]}')
    return fails + check_callers(data)


def check_packet():
    manifest = HERE / 'MANIFEST.sha256'
    if not manifest.exists() or not PACKET_JSON.exists():
        return ['packet json or MANIFEST.sha256 missing']
    pins = dict(reversed(line.split('  ', 1)) for line in manifest.read_text().splitlines() if line)
    want = pins.get('state-chain.json')
    if hashlib.sha256(PACKET_JSON.read_bytes()).hexdigest() != want:
        return ['state-chain.json does not match MANIFEST.sha256']
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
    print(f'{"FAIL" if fails else "PASS"}: keys={len(KEYS)} targets={len(TARGETS)} relocs={len(RELOCS)} '
          f'callers={sum(len(v) for v in CALLERS.values())}/{len(CALLERS)} failures={len(fails)}')
    return 1 if fails else 0


if __name__ == '__main__':
    raise SystemExit(main())
