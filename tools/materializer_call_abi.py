#!/usr/bin/env python3
"""RE-018: materializer-call ABI at the five [0x5773aa8] sites outside 0x3273810 (node #94).

Standalone. From the pinned node #94 binary only, it recovers:
  * a whole-section e8/ff15 caller pass: the six ff15 sites through GOT slot 0x5773aa8
    (five contested + 0x3273920 cited from RE-017) and confirms 0 rel32 callers of the
    slot (slots are not e8 targets);
  * the .eh_frame_hdr FDE start for each of the five sites;
  * for each of the five sites, a fixed pre-call window of 0x40 bytes ending at the
    call, the call's 6 bytes, and the pinned lea/mov instructions that load
    rdi/rsi/rdx/rcx immediately before the call;
  * the post-call `mov byte [rbx+imm32], 1` form where it is present.
Output is sorted, deterministic JSON. Every expected value is pinned exactly.
Imports only the Python standard library.
"""
import argparse
import bisect
import hashlib
import json
from pathlib import Path
import struct
import sys

ROOT = Path(__file__).resolve().parents[1]
TARGET = ROOT / 'artifacts' / 'node' / '94' / 'hl-node'
BINARY_SHA256 = '3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f'

SLOT = 0x5773aa8
SCAN_SECTIONS = ('.fini', '.init', '.plt', '.text')
# The five contested callers; 0x3273920 is listed in the scan but owned by RE-017.
SITES = (0x226685a, 0x2268f61, 0x4359d34, 0x4746097, 0x4b2c8e2)
WINDOW_BEFORE = 0x40

# (va, hex bytes, role) — arg-setup + call + distinctive post-byte where present
KEY_INSNS = [
    # --- 0x226685a in FDE 0x22615b0 ---
    (0x226683a, '488dbc24404b0000', '0x226685a: lea rdi,[rsp+0x4b40]'),
    (0x2266842, '488db424500a0000', '0x226685a: lea rsi,[rsp+0xa50]'),
    (0x226684a, '4c8db42420010000', '0x226685a: lea r14,[rsp+0x120]'),
    (0x2266852, '488d4c2450', '0x226685a: lea rcx,[rsp+0x50]'),
    (0x2266857, '4c89f2', '0x226685a: mov rdx,r14'),
    (0x226685a, 'ff1548d25003', '0x226685a: call [0x5773aa8]'),
    (0x2266860, 'c6832a08000000', '0x226685a: mov byte [rbx+0x82a],0'),
    # --- 0x2268f61 in FDE 0x22689f0 ---
    (0x2268f12, 'bac81f0000', '0x2268f61: mov edx,0x1fc8'),
    (0x2268f17, '4c89ef', '0x2268f61: mov rdi,r13'),
    (0x2268f20, '4c89a42400770000', '0x2268f61: mov [rsp+0x7700],r12'),
    (0x2268f28, '4c89b42408770000', '0x2268f61: mov [rsp+0x7708],r14'),
    (0x2268f46, '4c8da42400770000', '0x2268f61: lea r12,[rsp+0x7700]'),
    (0x2268f4e, '488d8c24f0000000', '0x2268f61: lea rcx,[rsp+0xf0]'),
    (0x2268f56, '48897c2418', '0x2268f61: mov [rsp+0x18],rdi'),
    (0x2268f5b, '4c89ee', '0x2268f61: mov rsi,r13'),
    (0x2268f5e, '4c89e2', '0x2268f61: mov rdx,r12'),
    (0x2268f61, 'ff1541ab5003', '0x2268f61: call [0x5773aa8]'),
    (0x2268f67, 'c683f049000001', '0x2268f61: mov byte [rbx+0x49f0],1'),
    # --- 0x4359d34 in FDE 0x4356c90 ---
    (0x4359d11, '488dbc24804a0000', '0x4359d34: lea rdi,[rsp+0x4a80]'),
    (0x4359d19, '488db424300a0000', '0x4359d34: lea rsi,[rsp+0xa30]'),
    (0x4359d21, '488d942470010000', '0x4359d34: lea rdx,[rsp+0x170]'),
    (0x4359d29, '4c8db424e0000000', '0x4359d34: lea r14,[rsp+0xe0]'),
    (0x4359d31, '4c89f1', '0x4359d34: mov rcx,r14'),
    (0x4359d34, 'ff156e9d4101', '0x4359d34: call [0x5773aa8]'),
    (0x4359d3a, '41c6852a08000000', '0x4359d34: mov byte [r13+0x82a],0'),
    # --- 0x4746097 in FDE 0x4744160 ---
    (0x474607a, '488dbc2400440000', '0x4746097: lea rdi,[rsp+0x4400]'),
    (0x4746082, '488db42440040000', '0x4746097: lea rsi,[rsp+0x440]'),
    (0x474608a, '488d9424f0000000', '0x4746097: lea rdx,[rsp+0xf0]'),
    (0x4746092, '488d4c2430', '0x4746097: lea rcx,[rsp+0x30]'),
    (0x4746097, 'ff150bda0201', '0x4746097: call [0x5773aa8]'),
    (0x474609d, 'c6834a06000000', '0x4746097: mov byte [rbx+0x64a],0'),
    # --- 0x4b2c8e2 in FDE 0x4b29760 ---
    (0x4b2c8bf, '488dbc24a04a0000', '0x4b2c8e2: lea rdi,[rsp+0x4aa0]'),
    (0x4b2c8c7, '488db424a0090000', '0x4b2c8e2: lea rsi,[rsp+0x9a0]'),
    (0x4b2c8cf, '488d942480010000', '0x4b2c8e2: lea rdx,[rsp+0x180]'),
    (0x4b2c8d7, '4c8db42400010000', '0x4b2c8e2: lea r14,[rsp+0x100]'),
    (0x4b2c8df, '4c89f1', '0x4b2c8e2: mov rcx,r14'),
    (0x4b2c8e2, 'ff15c071c400', '0x4b2c8e2: call [0x5773aa8]'),
    (0x4b2c8e8, 'c6832a08000000', '0x4b2c8e2: mov byte [rbx+0x82a],0'),
]

# window sha256 of [site-0x40, site+6) for each site — filled after first run
WINDOW_SHA = {
    '0x226685a': '075b66c40847507e08da722c48f3d6e797b8c0eaeb8d2dad53e90570f7f672fb',
    '0x2268f61': '3e65fcde868013b53f4d3afe2ac52c156b051bf4dc95b5bdc91556d3b043222e',
    '0x4359d34': '4fa51f80e5d4975a39eb0e18265b866f771114e5ec088d6eaead59bc7fb83299',
    '0x4746097': '198667520dbd3291a2cc763f39a8e8af7dced316254d3e82c119adff81e270f6',
    '0x4b2c8e2': '4045a5ab2ee545659ad589577d66061a1625996fa3f7ab6a26e381bb72a2f918',
}

EXPECT = {
    'binary_sha256': BINARY_SHA256,
    'slot': hex(SLOT),
    'sites': [hex(s) for s in SITES],
    'site_fdes': {
        '0x226685a': '0x22615b0',
        '0x2268f61': '0x22689f0',
        '0x3273920': '0x3273810',
        '0x4359d34': '0x4356c90',
        '0x4746097': '0x4744160',
        '0x4b2c8e2': '0x4b29760',
    },
    'caller_scan': {
        'ff15_slot_sites': {
            hex(SLOT): ['0x226685a', '0x2268f61', '0x3273920', '0x4359d34', '0x4746097', '0x4b2c8e2'],
        },
        'sections': ['.fini', '.init', '.plt', '.text'],
    },
    'call_targets': {hex(s): hex(SLOT) for s in SITES},
    'window_sha256': WINDOW_SHA,
    'key_insns': len(KEY_INSNS),
}


def segments(data):
    if data[:4] != b'\x7fELF' or data[4] != 2 or data[5] != 1:
        raise ValueError('not an ELF64 little-endian file')
    phoff, = struct.unpack_from('<Q', data, 0x20)
    phentsize, phnum = struct.unpack_from('<HH', data, 0x36)
    out = []
    for i in range(phnum):
        p_type, _f, off, va, _pa, filesz, _m, _a = struct.unpack_from('<IIQQQQQQ', data, phoff + i * phentsize)
        if p_type == 1:
            out.append((va, off, filesz))
    return out


def reader(data):
    segs = segments(data)

    def read(va, n):
        for base, off, size in segs:
            if base <= va and va + n <= base + size:
                return data[off + va - base: off + va - base + n]
        raise ValueError(f'{va:#x}+{n:#x} not in a file-backed PT_LOAD segment')
    return read


def sections(data):
    shoff, = struct.unpack_from('<Q', data, 0x28)
    shentsize, shnum, shstrndx = struct.unpack_from('<HHH', data, 0x3a)
    hdrs = [struct.unpack_from('<IIQQQQIIQQ', data, shoff + i * shentsize) for i in range(shnum)]
    stroff = hdrs[shstrndx][4]
    out = {}
    for h in hdrs:
        end = data.index(b'\0', stroff + h[0])
        out[data[stroff + h[0]:end].decode()] = {'addr': h[3], 'offset': h[4], 'size': h[5]}
    return out


def fde_index(data, sec, read):
    h = sec['.eh_frame_hdr']
    o, a = h['offset'], h['addr']
    if tuple(data[o + 1:o + 4]) != (0x1b, 0x03, 0x3b):
        raise ValueError('unexpected .eh_frame_hdr encodings')
    n, = struct.unpack_from('<I', data, o + 8)
    tab = [struct.unpack_from('<ii', data, o + 12 + 8 * i) for i in range(n)]
    starts = [a + x for x, _ in tab]

    def lookup(va):
        i = bisect.bisect_right(starts, va) - 1
        fva = a + tab[i][1]
        b = read(fva, 16)
        pc, = struct.unpack_from('<i', b, 8)
        rng, = struct.unpack_from('<I', b, 12)
        start = fva + 8 + pc
        if not start <= va < start + rng:
            raise ValueError(f'{va:#x} not covered by an FDE')
        return start, start + rng
    return lookup


def caller_scan(data, sec):
    slot = {hex(SLOT): []}
    for name in SCAN_SECTIONS:
        h = sec[name]
        b, base = data[h['offset']:h['offset'] + h['size']], h['addr']
        i = b.find(b'\xff\x15')
        while i != -1 and i + 6 <= len(b):
            disp, = struct.unpack_from('<i', b, i + 2)
            t = hex(base + i + 6 + disp)
            if t in slot:
                slot[t].append(hex(base + i))
            i = b.find(b'\xff\x15', i + 1)
    return {'sections': sorted(SCAN_SECTIONS), 'ff15_slot_sites': slot}


def analyse(data, check_sha=True):
    if check_sha and hashlib.sha256(data).hexdigest() != BINARY_SHA256:
        raise ValueError('binary sha256 mismatch')
    read = reader(data)
    sec = sections(data)
    lookup = fde_index(data, sec, read)
    scan = caller_scan(data, sec)
    all_sites = scan['ff15_slot_sites'][hex(SLOT)]
    site_fdes = {s: hex(lookup(int(s, 16))[0]) for s in all_sites}
    key_bytes = {hex(va): read(va, len(hx) // 2).hex() for va, hx, _ in KEY_INSNS}
    call_targets = {}
    windows = {}
    for site in SITES:
        b = read(site, 6)
        if b[:2] != b'\xff\x15':
            raise ValueError(f'{site:#x} is not ff15')
        disp, = struct.unpack_from('<i', b, 2)
        call_targets[hex(site)] = hex(site + 6 + disp)
        w = read(site - WINDOW_BEFORE, WINDOW_BEFORE + 6)
        windows[hex(site)] = hashlib.sha256(w).hexdigest()
    return {
        'binary_sha256': BINARY_SHA256,
        'slot': hex(SLOT),
        'sites': [hex(s) for s in SITES],
        'site_fdes': site_fdes,
        'caller_scan': scan,
        'call_targets': call_targets,
        'window_sha256': windows,
        'key_bytes': key_bytes,
    }


def expectation_errors(r):
    e = []
    for k in ('binary_sha256', 'slot', 'sites', 'caller_scan', 'call_targets', 'window_sha256'):
        if r[k] != EXPECT[k]:
            e.append(f'{k}: {r[k]!r} != {EXPECT[k]!r}')
    # site_fdes must contain at least the five + the cited 0x3273920
    for s, f in EXPECT['site_fdes'].items():
        if r['site_fdes'].get(s) != f:
            e.append(f'site_fdes[{s}]: {r["site_fdes"].get(s)} != {f}')
    want = {hex(va): hx for va, hx, _ in KEY_INSNS}
    for va, hx in want.items():
        if r['key_bytes'].get(va) != hx:
            e.append(f'key {va}: {r["key_bytes"].get(va)} != {hx}')
    if len(r['key_bytes']) != EXPECT['key_insns']:
        e.append('key instruction count')
    return e


def render(result):
    return json.dumps(result, indent=1, sort_keys=True) + '\n'


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument('--binary', type=Path, default=TARGET)
    ap.add_argument('--out', type=Path)
    ap.add_argument('--no-check', action='store_true', help=argparse.SUPPRESS)
    a = ap.parse_args(argv)
    result = analyse(a.binary.read_bytes())
    errs = expectation_errors(result)
    if errs and not a.no_check:
        for x in errs:
            print('FAIL', x, file=sys.stderr)
        return 1
    text = render(result)
    if a.out:
        a.out.write_text(text)
    else:
        sys.stdout.write(text)
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
