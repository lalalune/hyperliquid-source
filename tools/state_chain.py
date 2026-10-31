#!/usr/bin/env python3
"""RE-016: GOT-indirect state chain [0x5773aa8] -> 0x3751e80 -> 0x3270570 -> [0x5775580] -> 0x326e460 in node #94.

Standalone. It reads the pinned node #94 binary, maps virtual addresses through the
ELF program headers, parses .rela.dyn (bounded: that section only) and decodes three
bounded function extents with a small length decoder, recovering from bytes alone:
  * the two R_X86_64_RELATIVE entries that fill GOT slots 0x5773aa8 and 0x5775580,
    and that no other .rela.dyn entry carries either target as its addend;
  * each extent's instruction count, branch count and calls (rel32 target, GOT slot
    or register), with the rdi/rsi/edx set up for each call;
  * the edges: 0x3751e80 calls 0x3270570 by rel32, 0x3270570 calls through slot
    0x5775580, and the output-buffer copies that move each callee's result outward.
It also runs one bounded caller pass over .text/.init/.fini/.plt: every byte offset is
tried as e8 rel32 (target = site+5+disp) and ff15 RIP slot (target = site+6+disp); a
byte-offset superset of aligned instructions, so zero counts are upper-bound proofs. Output is sorted, deterministic JSON.
Every expected value is pinned exactly. Imports only the Python standard library.
"""
import argparse
import hashlib
import json
from pathlib import Path
import struct
import sys

ROOT = Path(__file__).resolve().parents[1]
TARGET = ROOT / 'artifacts' / 'node' / '94' / 'hl-node'
BINARY_SHA256 = '3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f'

SLOT_OUTER, SLOT_INNER = 0x5773aa8, 0x5775580
MATERIALIZER, WRAPPER, LEAF = 0x3751e80, 0x3270570, 0x326e460
EXTENTS = {MATERIALIZER: 0x37529b6, WRAPPER: 0x32707b4, LEAF: 0x326e50e}
MEMCPY_SLOT, FREE_SLOT = 0x576dfe0, 0x576e010
R_X86_64_RELATIVE = 8
REG64 = ['rax', 'rcx', 'rdx', 'rbx', 'rsp', 'rbp', 'rsi', 'rdi',
         'r8', 'r9', 'r10', 'r11', 'r12', 'r13', 'r14', 'r15']

_MODRM1 = (set(range(0x00, 0x04)) | set(range(0x08, 0x0c)) | set(range(0x10, 0x14))
           | set(range(0x18, 0x1c)) | set(range(0x20, 0x24)) | set(range(0x28, 0x2c))
           | set(range(0x30, 0x34)) | set(range(0x38, 0x3c))
           | {0x63, 0x69, 0x6b, 0x80, 0x81, 0x83, 0x84, 0x85, 0x86, 0x87, 0x88, 0x89,
              0x8a, 0x8b, 0x8d, 0xc0, 0xc1, 0xc6, 0xc7, 0xd0, 0xd1, 0xd2, 0xd3, 0xf6, 0xf7,
              0xfe, 0xff})
_IMM1 = {0x69: 4, 0x6b: 1, 0x80: 1, 0x81: 4, 0x83: 1, 0xc0: 1, 0xc1: 1, 0xc6: 1, 0xc7: 4}
_MODRM0F = ({0x10, 0x11, 0x1f, 0x28, 0x29, 0x2e, 0x2f, 0x6f, 0x7f, 0xaf, 0xb6, 0xb7, 0xbe, 0xbf,
             0xd6, 0xd7, 0xef} | set(range(0x40, 0x50)) | set(range(0x90, 0xa0)))

EXPECT = {
    'relocations': {
        hex(SLOT_OUTER): {'addend': hex(MATERIALIZER), 'sym': 0, 'type': 8},
        hex(SLOT_INNER): {'addend': hex(LEAF), 'sym': 0, 'type': 8},
    },
    'addend_entries': {hex(MATERIALIZER): [hex(SLOT_OUTER)], hex(LEAF): [hex(SLOT_INNER)]},
    'neighbour_slots': {'0x5773aa0': '0x4f94140', '0x5773ab0': '0x4743490',
                        '0x5775578': '0x4f93d90', '0x5775588': '0x4e35e80'},
    'slots_in_got': True,
    'counts': {hex(MATERIALIZER): (448, 0), hex(WRAPPER): (112, 0), hex(LEAF): (44, 1)},
    'edges': [
        ['got', hex(SLOT_OUTER), hex(MATERIALIZER)],
        ['rel32', '0x3752220', hex(WRAPPER)],
        ['got_call', '0x3270682', hex(SLOT_INNER)],
        ['got', hex(SLOT_INNER), hex(LEAF)],
        ['rel32', '0x326e4bb', '0x3269ae0'],
    ],
    'leaf_rel32': ['0x37d08a0', '0x332d440', '0x37d4e30', '0x3269ae0'],
    'copies': {
        '0x326e4e4': {'dst': 'entry_rdi', 'len': '0x1b20', 'src': 'rsp+0x60'},
        '0x327075e': {'dst': 'entry_rdi', 'len': '0x1b38', 'src': 'rsp+0xa70'},
        '0x3752872': {'dst': 'entry_rdi+0xbc0', 'len': '0x25e8', 'src': 'rsp+0x550'},
    },
    'caller_scan': {
        'sections': ['.fini', '.init', '.plt', '.text'],
        'ff15_slot_sites': {hex(SLOT_OUTER): ['0x226685a', '0x2268f61', '0x3273920', '0x4359d34',
                                               '0x4746097', '0x4b2c8e2'],
                            hex(SLOT_INNER): ['0x3270682']},
        'rel32_call_sites': {hex(LEAF): [], hex(WRAPPER): ['0x3752220'], hex(MATERIALIZER): []},
    },
    'out_buffers': {'0x3752220': 'rsp+0x550', '0x3270682': 'rsp+0xa70', '0x326e4bb': 'rsp+0x60'},
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


def rela_dyn(data, sec):
    s = sec['.rela.dyn']
    if s['size'] % 24:
        raise ValueError('.rela.dyn size not a multiple of 24')
    for o in range(s['offset'], s['offset'] + s['size'], 24):
        r_off, info, add = struct.unpack_from('<QQq', data, o)
        yield r_off, info & 0xffffffff, info >> 32, add


def _modrm(b, i, rex):
    m = b[i]
    mod, reg, rm = m >> 6, ((m >> 3) & 7) | ((rex & 4) << 1), m & 7
    i += 1
    base = None
    if mod == 3:
        return i, reg, ('reg', rm | ((rex & 1) << 3)), 0
    if rm == 4:
        sib = b[i]
        i += 1
        index = ((sib >> 3) & 7) | ((rex & 2) << 2)
        base = (sib & 7) | ((rex & 1) << 3)
        if index != 4:
            base = ('sib', base)
        if mod == 0 and (sib & 7) == 5:
            i += 4
            base = ('abs', None)
    elif mod == 0 and rm == 5:
        disp, = struct.unpack_from('<i', b, i)
        return i + 4, reg, ('rip', None), disp
    else:
        base = rm | ((rex & 1) << 3)
    disp = 0
    if mod == 1:
        disp, = struct.unpack_from('<b', b, i)
        i += 1
    elif mod == 2:
        disp, = struct.unpack_from('<i', b, i)
        i += 4
    return i, reg, ('mem', base), disp


def decode(read, va):
    """Decode one instruction: dict(len, kind, ...). Only the forms in the three extents."""
    b = read(va, 16)
    i, rex, opsz = 0, 0, False
    while b[i] in (0x66, 0xf2, 0xf3, 0x2e, 0x3e):
        opsz |= b[i] == 0x66
        i += 1
    if 0x40 <= b[i] <= 0x4f:
        rex = b[i]
        i += 1
    op = b[i]
    i += 1
    if op == 0x0f:
        op2 = b[i]
        i += 1
        if 0x80 <= op2 <= 0x8f:
            rel, = struct.unpack_from('<i', b, i)
            return {'len': i + 4, 'kind': 'branch', 'target': va + i + 4 + rel}
        if op2 not in _MODRM0F:
            raise ValueError(f'{va:#x}: 0f {op2:02x} not supported')
        n, _r, _rm, _d = _modrm(b, i, rex)
        return {'len': n, 'kind': 'other'}
    if op in (0xe8, 0xe9):
        rel, = struct.unpack_from('<i', b, i)
        return {'len': i + 4, 'kind': 'call' if op == 0xe8 else 'branch', 'target': va + i + 4 + rel}
    if 0x70 <= op <= 0x7f or op == 0xeb:
        rel, = struct.unpack_from('<b', b, i)
        return {'len': i + 1, 'kind': 'branch', 'target': va + i + 1 + rel}
    if op == 0xc3:
        return {'len': i, 'kind': 'ret'}
    if 0xb8 <= op <= 0xbf:
        n = 8 if rex & 8 else 4
        imm = int.from_bytes(b[i:i + n], 'little')
        return {'len': i + n, 'kind': 'movimm', 'dst': (op - 0xb8) | ((rex & 1) << 3), 'imm': imm}
    if op in _MODRM1:
        n, reg, rm, disp = _modrm(b, i, rex)
        imm = _IMM1.get(op, 0)
        if op in (0xf6, 0xf7) and (reg & 7) in (0, 1):
            imm = 1 if op == 0xf6 else (2 if opsz else 4)
        if imm == 4 and opsz:
            imm = 2
        d = {'len': n + imm, 'kind': 'other'}
        if op == 0xff and (reg & 7) == 2:
            if rm[0] == 'rip':
                d.update(kind='call_slot', slot=va + n + disp)
            elif rm[0] == 'reg':
                d.update(kind='call_reg', reg=REG64[rm[1]])
            else:
                raise ValueError(f'{va:#x}: memory-indirect call form not supported')
        elif op == 0xff and (reg & 7) in (4, 5):
            d['kind'] = 'branch'
        elif op == 0x8d and rm[0] == 'mem' and isinstance(rm[1], int):
            d.update(kind='lea', dst=reg, src=f'{REG64[rm[1]]}+{disp:#x}')
        elif op == 0x8d and rm[0] == 'rip':
            d.update(kind='lea_rip', target=va + n + disp)
        elif op == 0x8b and rm[0] == 'rip':
            d.update(kind='load_slot', dst=reg, slot=va + n + disp)
        elif op == 0x8b and rm[0] == 'mem' and isinstance(rm[1], int):
            d.update(kind='load', dst=reg, src=f'[{REG64[rm[1]]}+{disp:#x}]')
        elif op in (0x89, 0x8b) and rm[0] == 'reg' and rex & 8:
            dst, src = (rm[1], reg) if op == 0x89 else (reg, rm[1])
            d.update(kind='movreg', dst=dst, src=REG64[src])
        elif op in (0x31, 0x33) and rm[0] == 'reg' and rm[1] == reg:
            d.update(kind='zero', dst=reg)
        return d
    if 0x50 <= op <= 0x5f or op in (0x90, 0x98, 0x99, 0xcc):
        return {'len': i, 'kind': 'other'}
    if 0xb0 <= op <= 0xb7 or op in (0x04, 0x0c, 0x24, 0x2c, 0x34, 0x3c, 0xa8, 0x6a):
        return {'len': i + 1, 'kind': 'other'}
    if op in (0x05, 0x0d, 0x25, 0x2d, 0x35, 0x3d, 0xa9, 0x68):
        return {'len': i + 4, 'kind': 'other'}
    raise ValueError(f'{va:#x}: opcode {op:02x} not supported')


def scan(read, start, end):
    """Walk start..end linearly. Track rdi/rsi/rdx and register-held GOT slots per call."""
    insns, branches, calls, rip_leas = 0, [], [], []
    args, held = {}, {}
    va = start
    last = None
    while va < end:
        d = decode(read, va)
        k = d['kind']
        if k == 'branch':
            branches.append(hex(va))
        elif k == 'lea_rip':
            rip_leas.append(hex(d['target']))
        elif k == 'lea':
            base, disp = d['src'].split('+')
            b = args.get(REG64.index(base))
            args[d['dst']] = f'{b}+{disp}' if b and b.startswith('entry_') and '+' not in b else d['src']
            held.pop(d['dst'], None)
        elif k == 'load':
            args[d['dst']] = d['src']
            held.pop(d['dst'], None)
        elif k == 'load_slot':
            held[d['dst']] = d['slot']
            args[d['dst']] = f'[{d["slot"]:#x}]'
        elif k == 'movreg':
            args[d['dst']] = args.get(REG64.index(d['src']), 'entry_' + d['src'])
        elif k == 'movimm':
            args[d['dst']] = hex(d['imm'])
        elif k == 'zero':
            args[d['dst']] = '0x0'
        elif k in ('call', 'call_slot', 'call_reg'):
            c = {'va': hex(va), 'kind': {'call': 'rel32', 'call_slot': 'got', 'call_reg': 'reg'}[k],
                 'rdi': args.get(7), 'rsi': args.get(6), 'rdx': args.get(2)}
            if k == 'call':
                c['target'] = hex(d['target'])
            elif k == 'call_slot':
                c['slot'] = hex(d['slot'])
            else:
                c['reg'] = d['reg']
                r = REG64.index(d['reg'])
                if r in held:
                    c['slot'] = hex(held[r])
            calls.append(c)
            for r in (0, 1, 2, 6, 7, 8, 9, 10, 11):
                args.pop(r, None)
        last = k
        insns += 1
        va += d['len']
    if va != end or last != 'ret':
        raise ValueError(f'{start:#x}: extent does not end on ret at {end:#x}')
    return {'instructions': insns, 'branches': branches, 'calls': calls, 'rip_lea_targets': rip_leas}


SCAN_SECTIONS = ('.fini', '.init', '.plt', '.text')


def caller_scan(data, sec):
    """Every byte offset of the executable sections tried as e8 rel32 and ff15 rip slot."""
    rel = {hex(t): [] for t in (MATERIALIZER, WRAPPER, LEAF)}
    slot = {hex(t): [] for t in (SLOT_OUTER, SLOT_INNER)}
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
    got = sec['.got']
    relocs, by_addend, slot_fill = {}, {hex(MATERIALIZER): [], hex(LEAF): []}, {}
    rela_n = 0
    for r_off, rtype, sym, add in rela_dyn(data, sec):
        rela_n += 1
        if r_off in (SLOT_OUTER, SLOT_INNER):
            relocs[hex(r_off)] = {'addend': hex(add), 'sym': sym, 'type': rtype}
        if hex(add) in by_addend:
            by_addend[hex(add)].append(hex(r_off))
        if r_off in (SLOT_OUTER - 8, SLOT_OUTER + 8, SLOT_INNER - 8, SLOT_INNER + 8) and rtype == R_X86_64_RELATIVE:
            slot_fill[hex(r_off)] = hex(add)
    funcs = {hex(s): scan(read, s, e) for s, e in sorted(EXTENTS.items())}
    edges = [['got', k, v['addend']] for k, v in sorted(relocs.items(), key=lambda kv: kv[0] != hex(SLOT_OUTER))
             if v['type'] == R_X86_64_RELATIVE and v['sym'] == 0]
    copies, out_buffers = {}, {}
    for fn in (MATERIALIZER, WRAPPER, LEAF):
        for c in funcs[hex(fn)]['calls']:
            if c['kind'] == 'rel32' and c['target'] in (hex(WRAPPER), '0x3269ae0'):
                edges.append(['rel32', c['va'], c['target']])
                out_buffers[c['va']] = c['rdi']
            if c['kind'] == 'got' and c['slot'] == hex(SLOT_INNER):
                edges.append(['got_call', c['va'], c['slot']])
                out_buffers[c['va']] = c['rdi']
            if c.get('slot') == hex(MEMCPY_SLOT) and c['rdi'] is not None and c['rdi'].startswith('entry_'):
                copies[c['va']] = {'dst': c['rdi'], 'len': c['rdx'], 'src': c['rsi']}
    order = {e: i for i, e in enumerate(['got', 'rel32', 'got_call'])}
    def chain_key(e):
        seq = [hex(SLOT_OUTER), '0x3752220', '0x3270682', hex(SLOT_INNER), '0x326e4bb']
        return seq.index(e[1]) if e[1] in seq else 99 + order[e[0]]
    edges.sort(key=chain_key)
    keep = {'0x326e4e4', '0x327075e', '0x3752872'}
    return {
        'binary_sha256': BINARY_SHA256,
        'rela_dyn': {'entries': rela_n, 'offset': hex(sec['.rela.dyn']['offset']),
                     'size': hex(sec['.rela.dyn']['size'])},
        'got': {'start': hex(got['addr']), 'end': hex(got['addr'] + got['size'])},
        'slots_in_got': all(got['addr'] <= s < got['addr'] + got['size'] for s in (SLOT_OUTER, SLOT_INNER)),
        'relocations': relocs,
        'addend_entries': by_addend,
        'neighbour_slots': slot_fill,
        'functions': funcs,
        'edges': edges,
        'output_copies': {k: v for k, v in copies.items() if k in keep},
        'out_buffers': out_buffers,
        'caller_scan': caller_scan(data, sec),
    }


def expectation_errors(r):
    e = []
    for key in ('relocations', 'addend_entries', 'neighbour_slots', 'slots_in_got', 'edges', 'out_buffers', 'caller_scan'):
        if r[key] != EXPECT[key]:
            e.append(f'{key}: {r[key]!r} != {EXPECT[key]!r}')
    if r['output_copies'] != EXPECT['copies']:
        e.append(f'output_copies: {r["output_copies"]!r}')
    for fn, (n, nb) in EXPECT['counts'].items():
        f = r['functions'][fn]
        if (f['instructions'], len(f['branches'])) != (n, nb):
            e.append(f'{fn}: counts {(f["instructions"], len(f["branches"]))} != {(n, nb)}')
    for fn, f in r['functions'].items():
        if f['rip_lea_targets']:
            e.append(f'{fn}: rip-relative lea present {f["rip_lea_targets"]}')
    leaf = r['functions'][hex(LEAF)]
    rel = [c['target'] for c in leaf['calls'] if c['kind'] == 'rel32']
    if rel != EXPECT['leaf_rel32']:
        e.append(f'leaf rel32 calls {rel}')
    if leaf['branches'] != ['0x326e4f0']:
        e.append(f'leaf branch set {leaf["branches"]}')
    slots = [c.get('slot') for c in leaf['calls'] if c['kind'] == 'got']
    if slots != [hex(MEMCPY_SLOT), hex(FREE_SLOT)]:
        e.append(f'leaf got calls {slots}')
    w = [c for c in r['functions'][hex(WRAPPER)]['calls'] if c['kind'] != 'reg']
    if [(c['va'], c['kind']) for c in w] != [('0x3270682', 'got')]:
        e.append(f'wrapper non-register calls {w}')
    m = [c for c in r['functions'][hex(MATERIALIZER)]['calls'] if c['kind'] == 'rel32']
    if [(c['va'], c['target']) for c in m] != [('0x3752220', hex(WRAPPER))]:
        e.append(f'materializer rel32 calls {m}')
    return e


def render(result):
    return json.dumps(result, indent=1, sort_keys=True) + '\n'


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument('--binary', type=Path, default=TARGET)
    ap.add_argument('--out', type=Path)
    a = ap.parse_args(argv)
    result = analyse(a.binary.read_bytes())
    errs = expectation_errors(result)
    if errs:
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
