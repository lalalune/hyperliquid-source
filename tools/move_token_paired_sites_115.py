#!/usr/bin/env python3
"""Resolve the node #115 move_token call sites left unresolved by stage 101 (stage 102).

move_token 0x5580d10 returns tag 0x1a2 before either leg when
r8 == [rsp+0x1b0] (caller [rsp], stack argument 0) and (r8 == 0 or
r9 == [rsp+0x1b8] (caller [rsp+0x8], stack argument 1)) -- pinned at
0x5580d7e..0x5580d99 (#6214). Stage 101 left 24 of the 51 direct calls
unresolved because r8 or stack argument 0 is not a constant. This tool reads
the bytes before each of those 24 calls and binds them to one of three shapes:

P (14 sites)  r8 = 1; stack argument 0 = (rcx == 0) via
              mov rcx,[X+0x58] / xor eax,eax / test rcx,rcx / sete al /
              mov [rsp],rax; stack arguments 1 and 2 = 0 via a zeroed xmm
              stored at [rsp+0x8]. The early exit then needs [X+0x58] == 0
              and r9 == 0; otherwise the legs run.
Z (9 sites)   stack argument 0 = 0 via mov qword [rsp],0 (no later [rsp]
              store); r8 is a register or memory value. The early exit then
              needs r8 == 0 (the r9 compare is skipped).
S (1 site)    r8 = 0 via xor r8d,r8d; stack arguments come from push 0 /
              push <arg1> / push <arg0>. The early exit then needs arg0 == 0.

For each P site the tool also records the register loaded into r9 and the
register used to reach the 0x510-byte Locus cls element whose +0x58 word
feeds argument 0 (the index passed to slot 0x64e7b20, or the multiplicand of
imul ...,0x510), and whether they are the same register.

The captured binary is not executed. objdump and readelf are not started.
"""
import argparse
import json
import struct
from pathlib import Path

from artifacts import ROOT, check, manifest_item
from fde_extents import fde_extents
from freeze_snapshot_115 import SHA256, RELATIVE, TARGET, read_va, fixed, direct_calls, frame, relative_relocations

PACKET = ROOT / 'research/work-items/RE-008-move-token-paired-sites-115'
MOVE_TOKEN = 0x5580d10
CLS_SLOT, CLS_GET = 0x64e7b20, 0x446b370
WINDOW = 0x60

EARLY_EXIT = {
    0x5580d7e: '4c3bbc24b0010000',  # cmp r15, [rsp+0x1b0]
    0x5580d86: '7517',              # jne 0x5580d9f
    0x5580d88: '4d85ff',            # test r15, r15
    0x5580d8b: '0f84da050000',      # je 0x558136b
    0x5580d91: '483bac24b8010000',  # cmp rbp, [rsp+0x1b8]
    0x5580d99: '0f84cc050000',      # je 0x558136b
}
EXPECTED = {
    'P': [0x54d7a22, 0x556b1f5, 0x556ba56, 0x55704bd, 0x558aad2, 0x558af61, 0x558de33,
          0x558eb2f, 0x559021b, 0x5590a4a, 0x5590f71, 0x55923cd, 0x5593581, 0x5593c22],
    'Z': [0x55886ac, 0x558ae39, 0x558d886, 0x558ffd8, 0x559071c, 0x5591020, 0x5592481,
          0x5593630, 0x5593ce5],
    'S': [0x5588e9a],
}
REGS = ['rax', 'rcx', 'rdx', 'rbx', 'rsp', 'rbp', 'rsi', 'rdi',
        'r8', 'r9', 'r10', 'r11', 'r12', 'r13', 'r14', 'r15']


def _last(win, pat, before=None):
    end = len(win) if before is None else before
    return win.rfind(pat, 0, end)


def _rcx_plus58_load(win):
    """Last `mov rcx, [base(+index)+0x58]` (REX.W, opcode 8b, reg=rcx, disp8 0x58)."""
    best = -1
    for i in range(len(win) - 4):
        rex, op, modrm = win[i], win[i + 1], win[i + 2]
        if not (0x48 <= rex <= 0x4f) or rex & 4 or op != 0x8b or modrm >> 6 != 1 or (modrm >> 3) & 7 != 1:
            continue
        disp_at = i + 4 if modrm & 7 == 4 else i + 3
        if disp_at < len(win) and win[disp_at] == 0x58:
            best = i
    return best


def _mov_to(win, dest, before):
    """Last `mov dest, reg` (89, mod 3) or `mov dest, [mem]` (8b) before `before`; dest 0..15."""
    best = None
    for i in range(before - 3, -1, -1):
        rex, op, modrm = win[i], win[i + 1], win[i + 2]
        if not (0x48 <= rex <= 0x4f):
            continue
        if op == 0x89 and modrm >> 6 == 3 and (modrm & 7) | ((rex & 1) << 3) == dest:
            return i, REGS[((modrm >> 3) & 7) | ((rex & 4) << 1)]
        if op == 0x8b and ((modrm >> 3) & 7) | ((rex & 4) << 1) == dest and modrm >> 6 != 3:
            return i, 'memory'
    return best


def _index_reg(data, site):
    """Register indexing the cls element: rsi before `call [rip->0x64e7b20]`, or imul src,0x510."""
    lo = site - 0xc0
    win = read_va(data, lo, site - lo)
    found = None
    for i in range(len(win) - 6):
        if win[i:i + 2] == b'\xff\x15':
            target = lo + i + 6 + struct.unpack_from('<i', win, i + 2)[0]
            if target == CLS_SLOT:
                hit = _mov_to(win, 6, i)
                if hit:
                    found = ('slot 0x64e7b20 rsi', hit[1], lo + hit[0])
        rex = win[i]
        if 0x48 <= rex <= 0x4f and win[i + 1] == 0x69 and win[i + 2] >> 6 == 3 and win[i + 3:i + 7] == b'\x10\x05\x00\x00':
            found = ('imul *0x510', REGS[(win[i + 2] & 7) | ((rex & 1) << 3)], lo + i)
        # bounds check against Locus cls length: cmp REG, [X+0x7d0]
        if 0x48 <= rex <= 0x4f and win[i + 1] == 0x3b and win[i + 2] >> 6 == 2 and win[i + 2] & 7 != 4 \
                and win[i + 3:i + 7] == b'\xd0\x07\x00\x00':
            found = ('cmp len +0x7d0', REGS[((win[i + 2] >> 3) & 7) | ((rex & 4) << 1)], lo + i)
    return found


def _copies(data, site, dst, src):
    """True if `mov dst, src` (reg-reg) occurs in the 0xc0 bytes before the call."""
    lo = site - 0xc0
    win = read_va(data, lo, site - lo)
    for i in range(len(win) - 2):
        rex, op, modrm = win[i], win[i + 1], win[i + 2]
        if 0x48 <= rex <= 0x4f and op == 0x89 and modrm >> 6 == 3 \
                and REGS[(modrm & 7) | ((rex & 1) << 3)] == dst \
                and REGS[((modrm >> 3) & 7) | ((rex & 4) << 1)] == src:
            return lo + i
    return None


def classify(data, site):
    lo = site - WINDOW
    win = read_va(data, lo, WINDOW)
    # S: three pushes right before the call, r8 zeroed
    if win[-5:] == b'\x6a\x00\x41\x56\x53' and _last(win, b'\x45\x31\xc0') >= 0:
        return {'shape': 'S', 'r8': 0, 'arg0': 'rbx', 'arg1': 'r14', 'arg2': 0,
                'pins': {'xor_r8d': hex(lo + _last(win, b'\x45\x31\xc0')), 'pushes': hex(site - 5)},
                'no_op_when': 'rbx == 0 (destination kind 0)'}
    zero_store = _last(win, b'\x48\xc7\x04\x24\x00\x00\x00\x00')
    if zero_store >= 0 and _last(win, b'\x41\xb8') < zero_store:
        later = win[zero_store + 8:]
        if b'\x89\x04\x24' in later:
            raise ValueError(f'{site:#x}: [rsp] rewritten after zero store')
        hit = _mov_to(win, 8, WINDOW)
        if hit is None or hit[0] < _last(win, b'\x45\x31\xc0'):
            raise ValueError(f'{site:#x}: r8 setter not found')
        return {'shape': 'Z', 'r8': hit[1], 'arg0': 0,
                'pins': {'arg0_zero': hex(lo + zero_store), 'r8': hex(lo + hit[0])},
                'no_op_when': 'r8 == 0 (source kind 0)'}
    sete = _last(win, b'\x0f\x94\xc0')
    test = _last(win, b'\x48\x85\xc9', sete)
    load = _rcx_plus58_load(win[:test]) if test > 0 else -1
    store0 = _last(win, b'\x48\x89\x04\x24')
    xmm = max(_last(win, b'\x0f\x11\x44\x24\x08'), _last(win, b'\xf3\x0f\x7f\x44\x24\x08'))
    zero = max(_last(win, b'\x0f\x57\xc0'), _last(win, b'\x66\x0f\xef\xc0'))
    r8one = _last(win, b'\x41\xb8\x01\x00\x00\x00')
    if min(sete, test, load, store0, xmm, zero, r8one) < 0 or not (load < test < sete < store0 and zero < xmm):
        raise ValueError(f'{site:#x}: no known shape')
    r9 = _mov_to(win, 9, WINDOW)
    if r9 is None or r9[0] < r8one - 0x20:
        raise ValueError(f'{site:#x}: r9 setter not found')
    idx = _index_reg(data, site)
    copy = _copies(data, site, r9[1], idx[1]) if idx and idx[1] != r9[1] else None
    return {'shape': 'P', 'r8': 1, 'arg0': '([cls_elem+0x58] == 0) as u64', 'arg1': 0,
            'r9': r9[1], 'index': idx[1] if idx else None, 'index_via': idx[0] if idx else None,
            'index_copy': hex(copy) if copy else None,
            'r9_is_index': bool(idx and (idx[1] == r9[1] or copy)),
            'pins': {'load_plus58': hex(lo + load), 'sete': hex(lo + sete), 'arg0_store': hex(lo + store0),
                     'arg1_zero_xmm': hex(lo + xmm), 'r8': hex(lo + r8one), 'r9': hex(lo + r9[0])},
            'no_op_when': '[cls_elem+0x58] == 0 and r9 == 0'}


def bind(data, fdes):
    for va, expect in EARLY_EXIT.items():
        fixed(data, va, expect)
    if relative_relocations(data).get(CLS_SLOT) != CLS_GET:
        raise ValueError('cls slot relocation changed')
    calls = direct_calls(data, MOVE_TOKEN)
    if len(calls) != 51:
        raise ValueError(f'expected 51 direct calls, found {len(calls)}')
    sites, got = [], {}
    for shape, vas in EXPECTED.items():
        for va in vas:
            if va not in calls:
                raise ValueError(f'{va:#x} is not a direct call to move_token')
            row = classify(data, va)
            if row['shape'] != shape:
                raise ValueError(f'{va:#x}: shape {row["shape"]}, expected {shape}')
            row = {'site': hex(va), 'function': hex(frame(fdes, va)), **row}
            sites.append(row)
            got[shape] = got.get(shape, 0) + 1
    by_fn = {}
    for row in sites:
        by_fn.setdefault(row['function'], []).append(f"{row['site']} {row['shape']}")
    p_rows = [r for r in sites if r['shape'] == 'P']
    return {
        'target': RELATIVE, 'sha256': SHA256, 'task': 'RE-008', 'component': 'exchange',
        'move_token': hex(MOVE_TOKEN),
        'early_exit': 'r8 == arg0 and (r8 == 0 or r9 == arg1) -> 0x1a2 before either leg (0x5580d7e..0x5580d99)',
        'shapes': got,
        'p_r9_is_cls_index': sum(r['r9_is_index'] for r in p_rows),
        'sites': sites,
        'by_function': by_fn,
        'totals_after_stage_102': {
            'can-move (stage 101)': 23, 'early-exit (stage 101)': 4,
            'conditional P: no-op iff cls[+0x58]==0 and r9==0': got.get('P', 0),
            'conditional Z: no-op iff r8==0': got.get('Z', 0),
            'conditional S: no-op iff arg0==0': got.get('S', 0),
            'unresolved': 24 - sum(got.values()),
        },
        'gates_changed': False,
    }


def render(result):
    return (json.dumps(result, indent=2, sort_keys=True) + '\n').encode()


def generate(binary=TARGET, output=PACKET):
    identity = manifest_item(ROOT, RELATIVE)
    check(binary, identity)
    if identity['sha256'] != SHA256:
        raise ValueError('pinned node #115 digest changed')
    data = binary.read_bytes()
    _, fdes, _ = fde_extents(data)
    result = bind(data, fdes)
    output.mkdir(parents=True, exist_ok=True)
    (output / 'evidence.json').write_bytes(render(result))
    return result


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out', type=Path, default=PACKET)
    parser.add_argument('--check', action='store_true')
    args = parser.parse_args(argv)
    expected = (PACKET / 'evidence.json').read_bytes() if args.check else None
    result = generate(output=args.out)
    if args.check and (args.out / 'evidence.json').read_bytes() != expected:
        raise SystemExit('evidence.json does not match the committed packet')
    print(json.dumps(result['shapes']), 'p_r9_is_cls_index', result['p_r9_is_cls_index'])
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
