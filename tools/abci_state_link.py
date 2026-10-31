#!/usr/bin/env python3
"""RE-017: l1/abci/state.rs line-66 -> line-107 GOT-indirect link into slot 0x5773aa8 (node #94).

Standalone. From the bytes of the pinned node #94 binary only, it recovers:
  * the R_X86_64_RELATIVE entry that fills GOT slot 0x57755a8 with 0x3273810, and that
    no other .rela.dyn entry carries 0x3273810 as its addend;
  * a caller pass over every byte offset of .text/.init/.fini/.plt: e8 rel32 sites whose
    target (site+5+disp32) is 0x3273810, and ff15 sites whose RIP slot (site+6+disp32)
    is 0x57755a8 or 0x5773aa8;
  * the .eh_frame_hdr FDE that contains each site, and the FDE of 0x3273810 itself;
  * the core::panic::Location record at 0x56dfbf8 (file pointer by RELATIVE reloc,
    length, line, column) and the file string it names;
  * the exact bytes of the fixed instructions of 0x3273810 and of the call site 0x3272785.
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

FN, OUTER_FN = 0x3273810, 0x32725d0
SLOT_FN, SLOT_MAT = 0x57755a8, 0x5773aa8
LOCATION = 0x56dfbf8
SCAN_SECTIONS = ('.fini', '.init', '.plt', '.text')
R_X86_64_RELATIVE = 8

# (va, hex bytes, role) for the fixed instructions; every one is checked byte for byte
KEY_INSNS = [
    (0x3272785, 'ff151d2e5002', 'outer: call [rip+0x2502e1d] -> slot 0x57755a8'),
    (0x327278b, '83bc24503b000002', 'outer: cmp dword [rsp+0x3b50],2 (result tag)'),
    (0x3272793, '0f847a020000', 'outer: je 0x3272a13 (tag 2 path)'),
    (0x327276f, '488dbc24503b0000', 'outer: lea rdi,[rsp+0x3b50] (out)'),
    (0x3273810, '4157415641554154534881ec00100000', 'fn prologue push r15..rbx; sub rsp,0x1000'),
    (0x3273846, '4881ecb00f0000', 'fn: sub rsp,0xfb0 (frame 0x3fb0)'),
    (0x327384d, '4d89c7', 'fn: mov r15,r8'),
    (0x3273850, '4889cb', 'fn: mov rbx,rcx'),
    (0x3273853, '4989fe', 'fn: mov r14,rdi (out)'),
    (0x3273856, '488d0d9bc34602', 'fn: lea rcx,[rip+0x246c39b] -> Location 0x56dfbf8'),
    (0x327385d, '488d7c2420', 'fn: lea rdi,[rsp+0x20]'),
    (0x3273862, 'e8391d9a00', 'fn: call 0x3c155a0 (rel32)'),
    (0x3273871, '4983fd02', 'fn: cmp r13,2'),
    (0x3273875, '7541', 'fn: jne 0x32738b8'),
    (0x3273877, '4d896608', 'fn: mov [r14+8],r12'),
    (0x327387b, '49c70602000000', 'fn: mov qword [r14],2'),
    (0x3273890, 'ff157aa74f02', 'fn: call [0x576e010] (free r15 buffer)'),
    (0x327389d, 'e8be631800', 'fn: call 0x33f9c60 (rel32, drop r15+0x18)'),
    (0x32738b0, 'ff155aa74f02', 'fn: call [0x576e010] (free rbx buffer)'),
    (0x32738b8, '488d742430', 'fn: lea rsi,[rsp+0x30]'),
    (0x32738bd, '488dbc24f81f0000', 'fn: lea rdi,[rsp+0x1ff8]'),
    (0x32738c5, 'bab81f0000', 'fn: mov edx,0x1fb8'),
    (0x32738ca, 'ff1510a74f02', 'fn: call [0x576dfe0] (memcpy)'),
    (0x32738d0, '4c89ac24e81f0000', 'fn: mov [rsp+0x1fe8],r13'),
    (0x32738d8, '4c89a424f01f0000', 'fn: mov [rsp+0x1ff0],r12'),
    (0x327390d, '488db424e81f0000', 'fn: lea rsi,[rsp+0x1fe8]'),
    (0x3273915, '4889e2', 'fn: mov rdx,rsp'),
    (0x3273918, '488d4c2420', 'fn: lea rcx,[rsp+0x20]'),
    (0x327391d, '4c89f7', 'fn: mov rdi,r14'),
    (0x3273920, 'ff1582015002', 'fn: call [rip+0x2500182] -> slot 0x5773aa8'),
    (0x3273926, '4c89f0', 'fn: mov rax,r14'),
    (0x3273929, '4881c4b03f0000', 'fn: add rsp,0x3fb0'),
    (0x3273939, 'c3', 'fn: ret'),
]

EXPECT = {
    'binary_sha256': BINARY_SHA256,
    'fn_fde': {'end': '0x327396c', 'start': '0x3273810'},
    'fn_bytes_sha256': None,  # filled below from the pinned constant
    'relocation': {'addend': '0x3273810', 'slot': '0x57755a8', 'sym': 0, 'type': 8},
    'addend_carriers': ['0x57755a8'],
    'caller_scan': {
        'ff15_slot_sites': {'0x5773aa8': ['0x226685a', '0x2268f61', '0x3273920', '0x4359d34',
                                          '0x4746097', '0x4b2c8e2'],
                            '0x57755a8': ['0x3272785']},
        'rel32_call_sites': {'0x3273810': []},
        'sections': ['.fini', '.init', '.plt', '.text'],
    },
    'site_fdes': {'0x226685a': '0x22615b0', '0x2268f61': '0x22689f0', '0x3272785': '0x32725d0',
                  '0x3273920': '0x3273810', '0x4359d34': '0x4356c90', '0x4746097': '0x4744160',
                  '0x4b2c8e2': '0x4b29760'},
    'location': {'col': 37, 'file': 'l1/src/abci/state.rs', 'file_len': 49,
                 'file_ptr': '0x1dd8eb', 'line': 107, 'va': '0x56dfbf8'},
    'targets': {'0x3272785': '0x57755a8', '0x3273856': '0x56dfbf8', '0x3273862': '0x3c155a0',
                '0x3273890': '0x576e010', '0x327389d': '0x33f9c60', '0x32738b0': '0x576e010',
                '0x32738ca': '0x576dfe0', '0x3273920': '0x5773aa8'},
    'key_insns': len(KEY_INSNS),
}
FN_BYTES_SHA256 = 'ae961c6ff6f14718032ef8b469845ff4ecd79501528c5902a5f046cc584349f6'
EXPECT['fn_bytes_sha256'] = FN_BYTES_SHA256


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


def rela_dyn(data, sec):
    s = sec['.rela.dyn']
    if s['size'] % 24:
        raise ValueError('.rela.dyn size not a multiple of 24')
    for o in range(s['offset'], s['offset'] + s['size'], 24):
        r_off, info, add = struct.unpack_from('<QQq', data, o)
        yield r_off, info & 0xffffffff, info >> 32, add


def fde_index(data, sec, read):
    """.eh_frame_hdr binary-search table (datarel sdata4 pairs) -> (starts, lookup)."""
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
    rel = {hex(FN): []}
    slot = {hex(SLOT_MAT): [], hex(SLOT_FN): []}
    for name in SCAN_SECTIONS:
        h = sec[name]
        b, base = data[h['offset']:h['offset'] + h['size']], h['addr']
        for pat, n, want in ((b'\xe8', 5, rel), (b'\xff\x15', 6, slot)):
            i = b.find(pat)
            while i != -1 and i + n <= len(b):
                disp, = struct.unpack_from('<i', b, i + n - 4)
                t = hex(base + i + n + disp)
                if t in want:
                    want[t].append(hex(base + i))
                i = b.find(pat, i + 1)
    return {'sections': sorted(SCAN_SECTIONS), 'rel32_call_sites': rel, 'ff15_slot_sites': slot}


def analyse(data, check_sha=True):
    if check_sha and hashlib.sha256(data).hexdigest() != BINARY_SHA256:
        raise ValueError('binary sha256 mismatch')
    read = reader(data)
    sec = sections(data)
    reloc, carriers, loc_ptr = None, [], None
    for r_off, rtype, sym, add in rela_dyn(data, sec):
        if r_off == SLOT_FN:
            reloc = {'addend': hex(add), 'slot': hex(r_off), 'sym': sym, 'type': rtype}
        if add == FN:
            carriers.append(hex(r_off))
        if r_off == LOCATION and rtype == R_X86_64_RELATIVE:
            loc_ptr = add
    lookup = fde_index(data, sec, read)
    fs, fe = lookup(FN)
    scan = caller_scan(data, sec)
    sites = sorted({s for v in scan['ff15_slot_sites'].values() for s in v}, key=lambda x: int(x, 16))
    site_fdes = {s: hex(lookup(int(s, 16))[0]) for s in sites}
    file_len, line, col = struct.unpack('<QII', read(LOCATION + 8, 16))
    fname = read(loc_ptr, file_len).decode() if loc_ptr is not None else None
    key_bytes = {hex(va): read(va, len(hx) // 2).hex() for va, hx, _ in KEY_INSNS}
    targets = {}
    for va, hx, _ in KEY_INSNS:
        b = read(va, len(hx) // 2)
        if b[:1] == b'\xe8' or b[:2] == b'\xff\x15' or (b[:3] == b'\x48\x8d\x0d'):
            disp, = struct.unpack_from('<i', b, len(b) - 4)
            targets[hex(va)] = hex(va + len(b) + disp)
    return {
        'binary_sha256': BINARY_SHA256,
        'fn_fde': {'start': hex(fs), 'end': hex(fe)},
        'fn_bytes_sha256': hashlib.sha256(read(fs, fe - fs)).hexdigest(),
        'relocation': reloc,
        'addend_carriers': carriers,
        'caller_scan': scan,
        'site_fdes': site_fdes,
        'location': {'va': hex(LOCATION), 'file_ptr': hex(loc_ptr) if loc_ptr is not None else None,
                     'file_len': file_len, 'line': line, 'col': col,
                     'file': fname.split('code_Mainnet/', 1)[-1] if fname else None},
        'key_bytes': key_bytes,
        'targets': targets,
    }


def expectation_errors(r):
    e = []
    for k in ('binary_sha256', 'fn_fde', 'fn_bytes_sha256', 'relocation', 'addend_carriers',
              'caller_scan', 'site_fdes', 'location', 'targets'):
        if r[k] != EXPECT[k]:
            e.append(f'{k}: {r[k]!r} != {EXPECT[k]!r}')
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
