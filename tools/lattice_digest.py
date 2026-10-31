#!/usr/bin/env python3
"""RE-009-D: per-lane digest of the three 0x800-byte lattices in node #94 (0x37e2610).

Standalone. It reads the pinned node #94 binary, maps virtual addresses through the
ELF program headers, decodes the instructions at pinned addresses with a small
x86-64 decoder (only the forms that occur there), and interprets the straight-line
body of 0x37e2610 symbolically to recover, from bytes alone:
  * which input bytes each of the three hasher runs consumes (lane base, length);
  * where each 32-byte digest and each 16-byte lane trailer lands in the 0x90-byte
    output struct, and that the trailers are copied, not hashed;
  * that each hasher's chaining value starts from the 32 bytes at 0x20c020, and
    that those bytes equal the SHA-256 initial hash words, computed here;
  * that both callers copy the three 0x810-byte lattices, call 0x37e2610 on the
    copies, and only then call the writer 0x32699c0;
  * that the writer reads exactly rdi, rsi and rdx as arguments (no selector).
Output is sorted, deterministic JSON. Every expected value is pinned exactly.
Imports only the Python standard library.
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

DIGEST_FN, DIGEST_RET = 0x37e2610, 0x37e2957
WRITER_FN, WRITER_SAVE_CALL = 0x32699c0, 0x3269a7b
IV_VA = 0x20c020
SLOT_PLATFORM, SLOT_UPDATE, SLOT_FINALIZE = 0x57700c0, 0x57700c8, 0x57700d0
SLOT_NAMES = {SLOT_PLATFORM: 'platform', SLOT_UPDATE: 'update', SLOT_FINALIZE: 'finalize'}
# BLAKE3 structure anchors outside 0x37e2610 (names are stripped; these are bytes):
# the update target buffers a 0x400-byte chunk, the finalize target ORs ROOT flag 8.
ANCHORS = [
    (0x14f940d, '483d01040000', 'update target: cmp rax,0x401 (chunk length bound)'),
    (0x14f9419, '41be00040000', 'update target: mov r14d,0x400 (chunk size)'),
    (0x14fa020, 'e85bebffff', 'finalize target: call 0x14f8b80'),
    (0x14fa048, '0c08', 'finalize target: or al,0x8 (ROOT flag)'),
]
CALLERS = {
    0x326aec0: {'state_reg': 'r15', 'once_load': 0x326aef0,
                'copies': [0x326aefe, 0x326af1f, 0x326af36], 'lens': [0x326af14, 0x326af2e, 0x326af45],
                'dsts': [0x326af05, 0x326af26, 0x326af3d], 'digest_args': [0x326af4d, 0x326af52],
                'digest_call': 0x326af55, 'dir_load': 0x326af5a, 'writer_rdi': 0x326afea,
                'writer_call': 0x326aff3},
    0x32fc190: {'state_reg': 'r12', 'once_load': 0x32fc1bf,
                'copies': [0x32fc1cd, 0x32fc1ee, 0x32fc205], 'lens': [0x32fc1e4, 0x32fc1fe, 0x32fc215],
                'dsts': [0x32fc1d5, 0x32fc1f6, 0x32fc20d], 'digest_args': [0x32fc21c, 0x32fc221],
                'digest_call': 0x32fc224, 'dir_load': 0x32fc229, 'writer_rdi': 0x32fc261,
                'writer_call': 0x32fc267},
}

REG64 = ['rax', 'rcx', 'rdx', 'rbx', 'rsp', 'rbp', 'rsi', 'rdi',
         'r8', 'r9', 'r10', 'r11', 'r12', 'r13', 'r14', 'r15']
ARG_REGS = ['rdi', 'rsi', 'rdx', 'rcx', 'r8', 'r9']
CALLER_SAVED = ['rax', 'rcx', 'rdx', 'rsi', 'rdi', 'r8', 'r9', 'r10', 'r11']


def segments(data):
    if data[:4] != b'\x7fELF' or data[4] != 2 or data[5] != 1:
        raise ValueError('not an ELF64 little-endian file')
    phoff, = struct.unpack_from('<Q', data, 0x20)
    phentsize, phnum = struct.unpack_from('<HH', data, 0x36)
    out = []
    for i in range(phnum):
        p_type, _flags, off, va, _pa, filesz, _memsz, _al = struct.unpack_from('<IIQQQQQQ', data, phoff + i * phentsize)
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


class Insn:
    def __init__(self, va, raw, op, dst=None, src=None, reads=(), writes=()):
        self.va, self.raw, self.op, self.dst, self.src = va, raw, op, dst, src
        self.reads, self.writes = list(reads), list(writes)
        self.next = va + len(raw)


def modrm(code, i, rex, va_after_fn):
    """Decode ModRM (+SIB, disp). Returns (operand, regfield, new index).
    operand is ('reg', name) or ('mem', base, disp) with base 'rip' resolved by caller."""
    m = code[i]
    i += 1
    mod, reg, rm = m >> 6, ((m >> 3) & 7) | ((rex & 4) << 1), m & 7
    if mod == 3:
        return ('reg', REG64[rm | ((rex & 1) << 3)]), reg, i
    if rm == 4:
        sib = code[i]
        i += 1
        if (sib >> 3) & 7 != 4 or (sib & 7) == 5:
            raise ValueError('SIB with index or no base not supported')
        base = REG64[(sib & 7) | ((rex & 1) << 3)]
    elif rm == 5 and mod == 0:
        disp, = struct.unpack_from('<i', code, i)
        return ('mem', 'rip', disp), reg, i + 4
    else:
        base = REG64[rm | ((rex & 1) << 3)]
    if mod == 0:
        disp = 0
    elif mod == 1:
        disp = struct.unpack_from('<b', code, i)[0]
        i += 1
    else:
        disp, = struct.unpack_from('<i', code, i)
        i += 4
    return ('mem', base, disp), reg, i


def decode(read, va):
    code = read(va, 16)
    i, rex = 0, 0
    if 0x40 <= code[0] <= 0x4f:
        rex, i = code[0], 1
    op = code[i]
    i += 1

    def fin(n, *args, **kw):
        insn = Insn(va, code[:n], *args, **kw)
        for o in (insn.dst, insn.src):
            if o and o[0] == 'mem' and o[1] == 'rip':
                insn_o = ('abs', va + n + o[2])
                if o is insn.dst:
                    insn.dst = insn_o
                else:
                    insn.src = insn_o
        return insn

    def mem_regs(o):
        return [o[1]] if o and o[0] == 'mem' and o[1] != 'rip' else []

    if 0x50 <= op <= 0x57:
        r = REG64[(op - 0x50) | ((rex & 1) << 3)]
        return fin(i, 'push', src=('reg', r), reads=[r, 'rsp'], writes=['rsp'])
    if 0x58 <= op <= 0x5f:
        r = REG64[(op - 0x58) | ((rex & 1) << 3)]
        return fin(i, 'pop', dst=('reg', r), reads=['rsp'], writes=[r, 'rsp'])
    if op == 0xc3:
        return fin(i, 'ret')
    if op == 0xe8:
        rel, = struct.unpack_from('<i', code, i)
        return fin(i + 4, 'call', src=('abs', va + i + 4 + rel))
    if 0xb8 <= op <= 0xbf:
        imm, = struct.unpack_from('<I', code, i)
        r = REG64[(op - 0xb8) | ((rex & 1) << 3)]
        return fin(i + 4, 'mov', dst=('reg', r), src=('imm', imm), writes=[r])
    if op in (0x88, 0x89, 0x8b, 0x8d):
        rm, reg, j = modrm(code, i, rex, None)
        regop = ('reg', REG64[reg])
        if op in (0x88, 0x89):
            reads = [REG64[reg]] + (mem_regs(rm))
            writes = [rm[1]] if rm[0] == 'reg' else []
            return fin(j, 'mov', dst=rm, src=regop, reads=reads, writes=writes)
        name = 'lea' if op == 0x8d else 'mov'
        reads = mem_regs(rm) if rm[0] == 'mem' else [rm[1]]
        return fin(j, name, dst=regop, src=rm, reads=reads, writes=[REG64[reg]])
    if op in (0x81, 0x83, 0xc7):
        rm, reg, j = modrm(code, i, rex, None)
        if op == 0x83:
            imm = struct.unpack_from('<b', code, j)[0]
            j += 1
        else:
            imm, = struct.unpack_from('<i', code, j)
            j += 4
        sub = reg & 7
        name = {(0x81, 0): 'add', (0x83, 0): 'add', (0x81, 5): 'sub', (0xc7, 0): 'mov'}[(op, sub)]
        reads = mem_regs(rm) + ([rm[1]] if rm[0] == 'reg' and name != 'mov' else [])
        writes = [rm[1]] if rm[0] == 'reg' else []
        return fin(j, name, dst=rm, src=('imm', imm), reads=reads, writes=writes)
    if op == 0xff:
        rm, reg, j = modrm(code, i, rex, None)
        if reg & 7 != 2:
            raise ValueError(f'{va:#x}: ff /{reg & 7} not supported')
        return fin(j, 'call', src=rm, reads=mem_regs(rm) + ([rm[1]] if rm[0] == 'reg' else []))
    if op == 0x0f:
        op2 = code[i]
        i += 1
        rm, reg, j = modrm(code, i, rex, None)
        xmm = ('xmm', reg)
        if rm[0] == 'reg':
            rm = ('xmm', REG64.index(rm[1]))
        name = {0x10: 'movups', 0x11: 'movups', 0x28: 'movaps', 0x29: 'movaps', 0x57: 'xorps'}[op2]
        if op2 in (0x11, 0x29):
            return fin(j, name, dst=rm, src=xmm, reads=mem_regs(rm))
        return fin(j, name, dst=xmm, src=rm, reads=mem_regs(rm))
    raise ValueError(f'{va:#x}: opcode {code[:4].hex()} not supported')


def iv_words():
    """SHA-256 initial hash words: first 32 bits of the fractional parts of the
    square roots of the first eight primes (FIPS 180-4, 5.3.3), computed exactly."""
    from math import isqrt
    out = []
    for p in (2, 3, 5, 7, 11, 13, 17, 19):
        out.append(isqrt(p << 64) & 0xffffffff)
    return b''.join(struct.pack('<I', w) for w in out)


def interpret_digest(read):
    """Symbolic run of the straight-line body 0x37e2610..0x37e2957."""
    regs = {'rdi': ('out', 0), 'rsi': ('in', 0), 'rsp': ('sp', 0)}
    xmm = {}
    stack = {}          # rsp-relative byte offset -> 16-byte symbolic value (xmm stores)
    stack_q = {}        # rsp-relative offset -> 64-bit symbolic value
    out = {}            # output-struct offset -> (len, symbolic value)
    runs, platform_calls, finalized = [], 0, 0
    insns, va = [], DIGEST_FN
    while True:
        ins = decode(read, va)
        insns.append(ins)
        if ins.op == 'ret':
            break
        if ins.op in ('jmp', 'jcc'):
            raise ValueError('unexpected branch')
        va = ins.next

    def addr(o):
        if o[0] == 'abs':
            return ('abs', o[1])
        b = regs.get(o[1])
        if b is None:
            raise ValueError(f'unknown base {o[1]}')
        return (b[0], b[1] + o[2])

    for ins in insns:
        d, s = ins.dst, ins.src
        if ins.op in ('push', 'pop', 'ret'):
            continue
        if ins.op == 'sub' and d == ('reg', 'rsp'):
            continue
        if ins.op == 'add' and d == ('reg', 'rsp'):
            continue
        if ins.op == 'xorps':
            xmm[d[1]] = ('zero',)
        elif ins.op in ('movups', 'movaps'):
            if d[0] == 'xmm':
                if s[0] == 'xmm':
                    xmm[d[1]] = xmm[s[1]]
                else:
                    a = addr(s)
                    if a[0] == 'abs':
                        xmm[d[1]] = ('const', a[1])
                    elif a[0] == 'in':
                        xmm[d[1]] = ('input', a[1])
                    elif a[0] == 'sp':
                        xmm[d[1]] = stack[a[1]]
                    else:
                        raise ValueError(f'{ins.va:#x}: load from {a}')
            else:
                a = addr(d)
                v = xmm[s[1]]
                if a[0] == 'sp':
                    stack[a[1]] = v
                elif a[0] == 'out':
                    out[a[1]] = (16, v, ins.va)
                else:
                    raise ValueError(f'{ins.va:#x}: store to {a}')
        elif ins.op in ('mov', 'lea'):
            if d[0] == 'reg':
                if ins.op == 'lea':
                    regs[d[1]] = addr(s)
                elif s[0] == 'reg':
                    regs[d[1]] = regs.get(s[1], ('unknown', s[1]))
                elif s[0] == 'imm':
                    regs[d[1]] = ('imm', s[1])
                elif s[0] == 'abs':
                    regs[d[1]] = ('got', s[1])
                else:
                    a = addr(s)
                    regs[d[1]] = stack_q[a[1]] if a[0] == 'sp' else ('load', a)
            else:
                a = addr(d)
                if a[0] != 'sp':
                    raise ValueError(f'{ins.va:#x}: scalar store outside the frame')
                stack_q[a[1]] = regs.get(s[1], ('unknown', s[1])) if s[0] == 'reg' else ('imm', s[1])
        elif ins.op == 'call':
            tgt = regs[s[1]] if s[0] == 'reg' else None
            if not tgt or tgt[0] != 'got' or tgt[1] not in SLOT_NAMES:
                raise ValueError(f'{ins.va:#x}: call target {tgt}')
            kind = SLOT_NAMES[tgt[1]]
            if kind == 'platform':
                platform_calls += 1
            elif kind == 'update':
                h = regs['rdi']
                cv = [stack.get(h[1] + 0x40), stack.get(h[1] + 0x50)]
                runs.append({'call': f'{ins.va:#x}', 'hasher': f'rsp+{h[1]:#x}',
                             'input_offset': f"{regs['rsi'][1]:#x}" if regs['rsi'][0] == 'in' else None,
                             'len': f"{regs['rdx'][1]:#x}",
                             'cv_init': [f'{c[1]:#x}' if c and c[0] == 'const' else None for c in cv]})
            else:
                o = regs['rdi']
                if o != ('sp', 0) or regs['rsi'][1] != int(runs[-1]['hasher'][4:], 16):
                    raise ValueError(f'{ins.va:#x}: finalize arguments')
                runs[-1]['finalize'] = f'{ins.va:#x}'
                stack[0] = ('digest', finalized, 0)
                stack[0x10] = ('digest', finalized, 16)
                finalized += 1
            for r in CALLER_SAVED:
                regs.pop(r, None)
            xmm.clear()
        else:
            raise ValueError(f'{ins.va:#x}: {ins.op} not interpreted')
    return insns, runs, platform_calls, out, regs


def arguments(insns):
    """Registers among the SysV argument registers read before any write or call."""
    written, used = set(), []
    for ins in insns:
        for r in ins.reads:
            if r in ARG_REGS and r not in written and r not in used:
                used.append(r)
        if ins.op == 'call':
            break
        written.update(ins.writes)
    return used


def describe(v, lanes):
    if v[0] == 'digest':
        return f'lane{v[1]} digest[{v[2]:#x}:{v[2] + 16:#x}]'
    if v[0] == 'input':
        for k, base in enumerate(lanes):
            if base <= v[1] < base + 0x810:
                return f'lane{k} input[{v[1] - base:#x}:{v[1] - base + 16:#x}] (copied, not hashed)'
    raise ValueError(f'unexplained output value {v}')


def callers(read):
    res = []
    for fn, c in sorted(CALLERS.items()):
        once = decode(read, c['once_load'])
        copies = []
        for cv, lv, dv in zip(c['copies'], c['lens'], c['dsts']):
            ci, li, di = decode(read, cv), decode(read, lv), decode(read, dv)
            if ci.op != 'lea' or ci.dst != ('reg', 'rsi') or ci.src[1] != c['state_reg']:
                raise ValueError(f'{cv:#x}: copy source')
            copies.append({'src': f"{c['state_reg']}+{ci.src[2]:#x}", 'src_offset': f'{ci.src[2]:#x}',
                           'len': f'{li.src[1]:#x}', 'dst': f'rsp+{di.src[2]:#x}', 'dst_off': di.src[2]})
        a_rdi, a_rsi = (decode(read, v) for v in c['digest_args'])
        dcall, wcall = decode(read, c['digest_call']), decode(read, c['writer_call'])
        wrdi, dirl = decode(read, c['writer_rdi']), decode(read, c['dir_load'])
        for ins, reg in ((a_rdi, 'rdi'), (a_rsi, 'rsi'), (wrdi, 'rdi')):
            if ins.dst != ('reg', reg):
                raise ValueError(f'{ins.va:#x}: expected a write to {reg}')
        rsi_src = a_rsi.src[1]
        first_dst = next(decode(read, v).dst[1] for v in c['dsts'][:1])
        res.append({
            'function': f'{fn:#x}',
            'once_flag': f'{once.src[1]:#x}',
            'lattice_copies': [{k: v for k, v in x.items() if k != 'dst_off'} for x in copies],
            'copy_stride': sorted({f"{b['dst_off'] - a['dst_off']:#x}" for a, b in zip(copies, copies[1:])}),
            'digest_call': f'{dcall.va:#x}', 'digest_target': f'{dcall.src[1]:#x}',
            'digest_out': f'rsp+{a_rdi.src[2]:#x}',
            'digest_in_is_first_copy': rsi_src == first_dst,
            'writer_call': f'{wcall.va:#x}', 'writer_target': f'{wcall.src[1]:#x}',
            'writer_rdi': wrdi.src[1], 'writer_rdi_is_state': wrdi.src[1] == c['state_reg'],
            'digest_before_writer': dcall.va < wcall.va,
            'directory_base': f"[{dirl.src[1]}+{dirl.src[2]:#x}] -> {dirl.dst[1]}",
        })
    return res


def writer(read):
    insns, va = [], WRITER_FN
    while va <= WRITER_SAVE_CALL:
        ins = decode(read, va)
        insns.append(ins)
        va = ins.next
    by = {i.va: i for i in insns}
    tmpl = by[0x32699fe].src[1]
    raw = read(tmpl, 0x40)
    tbytes = raw[:raw.index(0)]
    copies = []
    for i in insns:
        if i.op == 'lea' and i.dst == ('reg', 'rsi') and i.src[0] == 'mem' and i.src[1] == 'rbx':
            copies.append(f'{i.src[2]:#x}')
        if i.op == 'add' and i.dst == ('reg', 'rbx'):
            copies.append(f'{i.src[1]:#x}')
    lens = sorted({f'{i.src[1]:#x}' for i in insns if i.op == 'mov' and i.dst == ('reg', 'rdx') and i.src[0] == 'imm'})
    calls = [i for i in insns if i.op == 'call']
    return {
        'function': f'{WRITER_FN:#x}',
        'decoded_prefix': [f'{WRITER_FN:#x}', f'{WRITER_SAVE_CALL:#x}'],
        'arguments_read': arguments(insns),
        'argument_moves': [f'{i.src[1]}->' + (i.dst[1] if i.dst[0] == 'reg' else f'[{i.dst[1]}+{i.dst[2]:#x}]')
                           for i in insns[:next(k for k, i in enumerate(insns) if i.op == 'call')]
                           if i.op == 'mov' and i.src[0] == 'reg' and i.src[1] in ARG_REGS],
        'path_template': f'{tmpl:#x}',
        'path_template_bytes': tbytes.hex(),
        'path_literal': tbytes[tbytes.index(b'/'):].decode(),
        'state_offsets_copied': copies,
        'copy_len': lens,
        'format_call_slot': f'{calls[0].src[1]:#x}',
        'save_helper': f'{calls[-1].src[1]:#x}',
        'save_record': f'{by[0x3269a6e].src[1]:#x}',
    }



# Post-digest windows: from the insn after each digest call to the caller's ret.
# A length decoder walks every instruction and records each [rsp+disp] operand.
POST_WINDOWS = {
    'A': {'caller': 0x326aec0, 'start': 0x326af5a, 'end': 0x326b018,
          'struct': (0x8, 0x98), 'frame_free': 0x326b006, 'frame_size': 0x18c8},
    'B': {'caller': 0x32fc190, 'start': 0x32fc229, 'end': 0x32fc44e,
          'struct': (0x20, 0xb0), 'frame_free': 0x32fc43c, 'frame_size': 0x1948,
          'overwrite': (0x32fc33a, 0x32fc345, 0x32fc34a),
          'header_free_load': 0x32fc429},
}


_MODRM1 = (set(range(0x00, 0x04)) | set(range(0x08, 0x0c)) | set(range(0x10, 0x14))
           | set(range(0x18, 0x1c)) | set(range(0x20, 0x24)) | set(range(0x28, 0x2c))
           | set(range(0x30, 0x34)) | set(range(0x38, 0x3c))
           | {0x63, 0x69, 0x6b, 0x80, 0x81, 0x83, 0x84, 0x85, 0x86, 0x87, 0x88, 0x89,
              0x8a, 0x8b, 0x8d, 0xc0, 0xc1, 0xc6, 0xc7, 0xd0, 0xd1, 0xd2, 0xd3, 0xf6, 0xf7,
              0xfe, 0xff})
_IMM1 = {0x69: 4, 0x6b: 1, 0x80: 1, 0x81: 4, 0x83: 1, 0xc0: 1, 0xc1: 1, 0xc6: 1, 0xc7: 4}
_MODRM0F = ({0x10, 0x11, 0x1f, 0x28, 0x29, 0x6f, 0x7f, 0xaf, 0xb6, 0xb7, 0xbe, 0xbf, 0xd6,
             0xd7, 0xef} | set(range(0x40, 0x50)) | set(range(0x90, 0xa0)))


def length_scan(read, va):
    """(length, opcode-class, rsp-disp-or-None) for one instruction."""
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
            return i + 4, 'jcc', None
        if op2 == 0x0b:
            return i, 'ud2', None
        if op2 not in _MODRM0F:
            raise ValueError(f'{va:#x}: 0f {op2:02x} not supported')
        n, disp = _modrm_len(b, i, rex)
        return n, f'0f{op2:02x}', disp
    if op in _MODRM1:
        n, disp = _modrm_len(b, i, rex)
        imm = _IMM1.get(op, 0)
        if op in (0xf6, 0xf7) and (b[i] >> 3) & 7 in (0, 1):
            imm = 1 if op == 0xf6 else (2 if opsz else 4)
        if imm == 4 and opsz:
            imm = 2
        return n + imm, f'{op:02x}', disp
    if 0x50 <= op <= 0x5f or op in (0x90, 0x98, 0x99, 0xc3, 0xcc):
        return i, f'{op:02x}', None
    if 0x70 <= op <= 0x7f or op == 0xeb:
        return i + 1, 'jcc8', None
    if op in (0xe8, 0xe9):
        return i + 4, f'{op:02x}', None
    if 0xb8 <= op <= 0xbf:
        return i + (8 if rex & 8 else 4), 'movimm', None
    if 0xb0 <= op <= 0xb7 or op in (0x04, 0x0c, 0x24, 0x2c, 0x34, 0x3c, 0xa8, 0x6a):
        return i + 1, f'{op:02x}', None
    if op in (0x05, 0x0d, 0x25, 0x2d, 0x35, 0x3d, 0xa9, 0x68):
        return i + 4, f'{op:02x}', None
    raise ValueError(f'{va:#x}: opcode {op:02x} not supported')


def _modrm_len(b, i, rex):
    m = b[i]
    mod, rm = m >> 6, m & 7
    i += 1
    base_rsp = False
    if mod != 3 and rm == 4:
        sib = b[i]
        i += 1
        # rsp-only SIB: base=rsp, index=none (scale/index=0b100), REX.B unset
        base_rsp = (sib & 7) == 4 and not (rex & 1) and ((sib >> 3) & 7) == 4
        if mod == 0 and (sib & 7) == 5:
            i += 4
    disp = 0
    if mod == 1:
        disp = struct.unpack_from('<b', b, i)[0]
        i += 1
    elif mod == 2:
        disp = struct.unpack_from('<i', b, i)[0]
        i += 4
    elif mod == 0 and rm == 5:
        i += 4
    return i, (disp if base_rsp else None)


def post_digest(read):
    """Classify the 0x90 digest as dead (bounded): no consumer observed in either caller's post-digest window."""
    res = {}
    for name, w in sorted(POST_WINDOWS.items()):
        lo, hi = w['struct']
        va, n, accesses, frees = w['start'], 0, [], []
        while va < w['end']:
            ln, cls, disp = length_scan(read, va)
            raw = read(va, ln)
            if disp is not None and lo <= disp < hi:
                kind = ('pointer' if cls == '8d'
                        else 'write' if cls in ('89', '0f11', '0f29', 'c7')
                        else 'read')
                accesses.append({'va': f'{va:#x}', 'kind': kind,
                                 'rsp_disp': f'{disp:#x}',
                                 'struct_offset': f'{disp - lo:#x}'})
            if raw[:3] == b'\x48\x81\xc4':
                frees.append({'va': f'{va:#x}',
                              'size': f"{struct.unpack_from('<i', raw, 3)[0]:#x}"})
            va += ln
            n += 1
        if va != w['end']:
            raise ValueError(f'window {name} overran to {va:#x}')
        overwrites = [a['va'] for a in accesses if a['kind'] == 'write']
        # Optional static pin: if POST_WINDOWS names overwrite VAs, they must match discovery.
        named = [f'{x:#x}' for x in w.get('overwrite', ())]
        if named and named != overwrites:
            raise ValueError(f'{name} overwrite mismatch: {overwrites} != {named}')
        frame = frees[0] if frees else None
        expected_free = w.get('frame_free')
        if expected_free is not None and (frame is None or int(frame['va'], 16) != expected_free):
            raise ValueError(f'{name} frame_free mismatch: {frame}')
        write_offs = [a['struct_offset'] for a in accesses if a['kind'] == 'write']
        header_loads = [a['va'] for a in accesses if a['kind'] == 'read']
        # digest_content_reads = reads that are NOT the single header-free load (offset 0x8).
        digest_reads = [a for a in accesses if a['kind'] == 'read'
                        and a['struct_offset'] != '0x8']
        res[name] = {
            'caller': f"{w['caller']:#x}",
            'window': [f"{w['start']:#x}", f"{w['end']:#x}"],
            'instructions': n,
            'struct_rsp_range': [f'{lo:#x}', f'{hi:#x}'],
            'struct_accesses': accesses,
            'digest_content_reads': len(digest_reads),
            'overwrite_stores': overwrites,
            'write_struct_offsets': write_offs,
            'header_free_load': header_loads[0] if header_loads else None,
            'frame_free': frame,
            'claim': ('dead (bounded): frame freed, no read observed'
                      if name == 'A'
                      else 'dead (bounded): first 32 bytes overwritten then header freed; no digest read observed'),
        }
    return res



def analyse(data, check_sha=True):
    if check_sha and hashlib.sha256(data).hexdigest() != BINARY_SHA256:
        raise ValueError('binary sha256 mismatch')
    read = reader(data)
    insns, runs, platform_calls, out, end_regs = interpret_digest(read)
    lanes = [int(r['input_offset'], 16) for r in runs]
    fields = [{'offset': f'{k:#x}', 'len': f'{v[0]:#x}', 'value': describe(v[1], lanes), 'store': f'{v[2]:#x}'}
              for k, v in sorted(out.items())]
    cover = [0] * 0x90
    for k, v in out.items():
        for b in range(k, k + v[0]):
            cover[b] += 1
    hashed = [[r['input_offset'], f"{int(r['input_offset'], 16) + int(r['len'], 16):#x}"] for r in runs]
    trailers = sorted(f['value'] for f in fields if 'not hashed' in f['value'])
    iv = read(IV_VA, 32)
    anchors = [{'va': f'{va:#x}', 'bytes': read(va, len(h) // 2).hex(), 'expected': h, 'role': role,
                'match': read(va, len(h) // 2).hex() == h} for va, h, role in ANCHORS]
    return {
        'schema': 're009d-lattice-digest/1',
        'binary_sha256': BINARY_SHA256,
        'digest_function': {
            'start': f'{DIGEST_FN:#x}', 'ret': f'{DIGEST_RET:#x}',
            'instructions': len(insns),
            'branches': sum(i.op.startswith('j') for i in insns),
            'arguments_read': arguments(insns),
            'platform_calls': platform_calls,
            'hasher_runs': runs,
            'hashed_input_ranges': hashed,
            'output_fields': fields,
            'output_size': f'{len(cover):#x}',
            'output_bytes_written_once': all(c == 1 for c in cover),
            'unhashed_trailers': trailers,
            'returns': repr(end_regs.get('rax')),
        },
        'iv': {'va': f'{IV_VA:#x}', 'bytes': iv.hex(), 'equals_sha256_initial_words': iv == iv_words()},
        'blake3_anchors': anchors,
        'callers': callers(read),
        'writer': writer(read),
        'post_digest': post_digest(read),
    }


# Exact expectations (never >=). The tool refuses to emit output that differs.
EXPECT = {
    'instructions': 147, 'branches': 0, 'platform_calls': 3,
    'arguments_read': ['rsi', 'rdi'],
    'hashed_input_ranges': [['0x0', '0x800'], ['0x810', '0x1010'], ['0x1020', '0x1820']],
    'update_calls': ['0x37e270a', '0x37e27f4', '0x37e28d4'],
    'finalize_calls': ['0x37e2719', '0x37e27fc', '0x37e28dc'],
    'cv_init': [['0x20c020', '0x20c030']] * 3,
    'fields': [('0x0', 'lane0 digest[0x0:0x10]'), ('0x10', 'lane0 digest[0x10:0x20]'),
               ('0x20', 'lane0 input[0x800:0x810] (copied, not hashed)'),
               ('0x30', 'lane1 digest[0x0:0x10]'), ('0x40', 'lane1 digest[0x10:0x20]'),
               ('0x50', 'lane1 input[0x800:0x810] (copied, not hashed)'),
               ('0x60', 'lane2 digest[0x0:0x10]'), ('0x70', 'lane2 digest[0x10:0x20]'),
               ('0x80', 'lane2 input[0x800:0x810] (copied, not hashed)')],
    'returns': "('out', 0)",
    'digest_out': ['rsp+0x8', 'rsp+0x20'],
    'directory_base': ['[r15+0x1b18] -> rsi', '[r12+0x1b18] -> r13'],
    'callers': [('0x326aec0', '0x326af55', '0x326aff3', ['0xf8', '0xa00', '0x1308']),
                ('0x32fc190', '0x32fc224', '0x32fc267', ['0xf8', '0xa00', '0x1308'])],
    'writer': {'arguments_read': ['rdi', 'rsi', 'rdx'], 'path_literal': '/lt_hashes.json',
               'path_template': '0x201e63', 'state_offsets_copied': ['0xf8', '0xa00', '0x1308'],
               'copy_len': ['0x810'], 'save_helper': '0x3c16810', 'save_record': '0x56dfb28',
               'format_call_slot': '0x576e040',
               'argument_moves': ['rdi->rbx', 'rsi->[rsp+0x20]', 'rdx->[rsp+0x28]']},
    # Negative: the digest is computed and discarded in both callers (no downstream consumer observed).
    'post_digest': {
        'A': {'digest_content_reads': 0,
              'frame_free': {'va': '0x326b006', 'size': '0x18c8'},
              'overwrite_stores': [], 'write_struct_offsets': [],
              'header_free_load': None},
        'B': {'digest_content_reads': 0,
              'frame_free': {'va': '0x32fc43c', 'size': '0x1948'},
              'overwrite_stores': ['0x32fc33a', '0x32fc345', '0x32fc34a'],
              'write_struct_offsets': ['0x18', '0x8', '0x0'],
              'header_free_load': '0x32fc429'},
    },
}


def expectation_errors(r):
    d, e, errs = r['digest_function'], EXPECT, []
    for k in ('instructions', 'branches', 'platform_calls', 'arguments_read', 'hashed_input_ranges'):
        if d[k] != e[k]:
            errs.append(f'{k}: {d[k]} != {e[k]}')
    runs = d['hasher_runs']
    if [x['call'] for x in runs] != e['update_calls']:
        errs.append('update calls')
    if [x.get('finalize') for x in runs] != e['finalize_calls']:
        errs.append('finalize calls')
    if [x['cv_init'] for x in runs] != e['cv_init']:
        errs.append('cv init')
    if [(f['offset'], f['value']) for f in d['output_fields']] != e['fields']:
        errs.append('output field map')
    if d['output_size'] != '0x90' or not d['output_bytes_written_once']:
        errs.append('output coverage')
    if d['returns'] != e['returns']:
        errs.append('does not return the output struct')
    for k in ('digest_out', 'directory_base'):
        if [c[k] for c in r['callers']] != e[k]:
            errs.append(f'callers {k}')
    if not r['iv']['equals_sha256_initial_words']:
        errs.append('iv is not the SHA-256 initial words')
    if not all(a['match'] for a in r['blake3_anchors']):
        errs.append('blake3 anchor bytes')
    got = [(c['function'], c['digest_call'], c['writer_call'], [x['src_offset'] for x in c['lattice_copies']])
           for c in r['callers']]
    if got != e['callers']:
        errs.append(f'callers {got}')
    for c in r['callers']:
        if not (c['digest_before_writer'] and c['digest_in_is_first_copy'] and c['writer_rdi_is_state']
                and c['copy_stride'] == ['0x810'] and c['digest_target'] == '0x37e2610'
                and c['writer_target'] == '0x32699c0' and c['once_flag'] == '0x577ab98'
                and [x['len'] for x in c['lattice_copies']] == ['0x810'] * 3):
            errs.append(f"caller {c['function']} dataflow")
    for name, want in e['post_digest'].items():
        got = r['post_digest'][name]
        have = {k: got[k] for k in ('digest_content_reads', 'frame_free', 'overwrite_stores',
                                     'write_struct_offsets', 'header_free_load')}
        if have != want:
            errs.append(f'post_digest {name}: {have} != {want}')
    # Caveat gate: B must not read digest bytes at struct_offset >= 0x20 (past the 32-byte overwrite).
    b = r['post_digest']['B']['struct_accesses']
    if [a for a in b if a['kind'] == 'read' and int(a['struct_offset'], 16) >= 0x20]:
        errs.append('post_digest B reads digest bytes beyond the overwritten record')
    for k, v in e['writer'].items():
        if r['writer'][k] != v:
            errs.append(f'writer {k}: {r["writer"][k]} != {v}')
    return errs


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
