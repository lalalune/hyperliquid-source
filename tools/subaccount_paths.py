#!/usr/bin/env python3
"""vaults: node #94 sub-account paths: subAccountTransfer, the create and modify wrappers and the address input.

subAccountTransfer is 0x1e60d00 -> 0x27148e0.  subAccountModify is the wrapper 0x22cdfb0.  createSubAccount
is the wrapper 0x27e3140.  The address input is 0x3c97900 -> 0x1592160.  This tool reads ELF bytes only.  It
decodes pinned instructions with a small fail-closed x86-64 subset decoder and evaluates the listed function
bodies in Python, with their other calls replaced by named stubs.  Each result is compared with a plain
formula over deterministic vectors.  Nothing from the binary runs.

    python3 tools/subaccount_paths.py --out <dir>

writes evidence.json, functions.tsv, stubs.tsv, callers.tsv, status_sites.tsv, link_readers.tsv, pins.tsv,
layout.tsv, locations.tsv, cases.tsv and outcomes.tsv.
"""

import argparse
import bisect
import hashlib
import json
import math
from pathlib import Path
import re
import struct
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))

from elf_index import sections  # noqa: E402
from fde_extents import eh_frame_records  # noqa: E402

BINARY = 'artifacts/node/94/hl-node'
SHA256 = '3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f'

M64 = (1 << 64) - 1
SCRATCH = 0x7000000
REGS = ['rax', 'rcx', 'rdx', 'rbx', 'rsp', 'rbp', 'rsi', 'rdi', 'r8', 'r9', 'r10', 'r11', 'r12', 'r13', 'r14', 'r15']
ALU = {0x00: 'add', 0x08: 'or', 0x20: 'and', 0x28: 'sub', 0x30: 'xor', 0x38: 'cmp'}
GRP1 = ['add', 'or', 'adc', 'sbb', 'and', 'sub', 'xor', 'cmp']
CC = ['o', 'no', 'b', 'ae', 'e', 'ne', 'be', 'a', 's', 'ns', 'p', 'np', 'l', 'ge', 'le', 'g']
SSE = {(0xf2, 0x10): 'movsd', (0xf2, 0x11): 'movsd.st', (0xf2, 0x59): 'mulsd', (0xf2, 0x5e): 'divsd', (0xf2, 0x58): 'addsd',
       (0xf2, 0x5c): 'subsd', (0xf2, 0x5f): 'maxsd', (0xf2, 0x5d): 'minsd', (0x66, 0x2e): 'ucomisd', (0x66, 0xef): 'pxor',
       (0, 0x57): 'xorps', (0x66, 0x57): 'xorpd', (0x66, 0x6f): 'movdqa', (0x66, 0x28): 'movapd', (0, 0x28): 'movaps', (0x66, 0x60): 'punpcklbw', (0x66, 0x76): 'pcmpeqd',
       (0x66, 0x62): 'punpckldq', (0x66, 0x5c): 'subpd', (0x66, 0x15): 'unpckhpd', (0xf3, 0x6f): 'movdqu',
       (0, 0x10): 'movups', (0, 0x11): 'movups.st', (0x66, 0x7f): 'movdqa.st', (0xf3, 0x7f): 'movdqu.st', (0, 0x29): 'movaps.st', (0x66, 0x29): 'movapd.st', (0x66, 0x10): 'movupd', (0x66, 0x11): 'movupd.st', (0x66, 0x74): 'pcmpeqb', (0x66, 0xdb): 'pand'}


class Panic(Exception):
    pass


class Insn:
    __slots__ = ('va', 'size', 'op', 'args')

    def __init__(self, va, size, op, args):
        self.va, self.size, self.op, self.args = va, size, op, args

    def text(self):
        return self.op + (' ' + ','.join(fmt(a) for a in self.args) if self.args else '')


def fmt(a):
    k = a[0]
    if k == 'r':
        return REGS[a[1]] + {64: '', 32: 'd', 16: 'w', 8: 'b'}[a[2]]
    if k == 'x':
        return f'xmm{a[1]}'
    if k == 'i':
        return hex(a[1])
    if k == 't':
        return hex(a[1])
    if k == 'rip':
        return f'[{a[1]:#x}]:{a[2]}'
    if k == 'm':
        s = REGS[a[1]] if a[1] is not None else ''
        if a[2] is not None:
            s += ('+' if s else '') + f'{REGS[a[2]]}*{a[3]}'
        if a[4]:
            s += f'{a[4]:+#x}'
        return f'[{s}]:{a[5]}'
    raise ValueError(a)


def decode(code, va):
    """code(va, n) returns n bytes.  Unknown encodings raise instead of guessing."""
    raw = code(va, 16)
    p = 0
    pre = 0
    rex = 0
    while raw[p] in (0x2e, 0x66, 0xf2, 0xf3):
        pre = raw[p] if raw[p] != 0x2e else pre
        p += 1
    if 0x40 <= raw[p] <= 0x4f:
        rex = raw[p]
        p += 1
    w, r, x, b = rex >> 3 & 1, rex >> 2 & 1, rex >> 1 & 1, rex & 1
    bits = 64 if w else 16 if pre == 0x66 else 32
    op = raw[p]
    p += 1

    def modrm(mbits):
        nonlocal p
        m = raw[p]
        p += 1
        mod, reg, rm = m >> 6, (m >> 3 & 7), m & 7
        if mod == 3:
            return reg, ('R', rm | b << 3, mbits)
        if rm == 5 and mod == 0:
            disp = struct.unpack_from('<i', raw, p)[0]
            p += 4
            return reg, ('RIP', disp, mbits)
        base, idx, scale = rm | b << 3, None, 1
        if rm == 4:
            s = raw[p]
            p += 1
            scale = 1 << (s >> 6)
            i = (s >> 3 & 7) | x << 3
            base = (s & 7) | b << 3
            if i != 4:
                idx = i
            if s & 7 == 5 and mod == 0:
                disp = struct.unpack_from('<i', raw, p)[0]
                p += 4
                return reg, ('m', None, idx, scale, disp, mbits)
        disp = 0
        if mod == 1:
            disp = struct.unpack_from('<b', raw, p)[0]
            p += 1
        elif mod == 2:
            disp = struct.unpack_from('<i', raw, p)[0]
            p += 4
        return reg, ('m', base, idx, scale, disp, mbits)

    def fin(e, xmm=False, extra=0):
        if e[0] == 'R':
            return ('x', e[1]) if xmm else ('r', e[1], e[2])
        if e[0] == 'RIP':
            return ('RIP', e[1], e[2], extra)
        return e

    def done(name, *args):
        size = p
        out = []
        for a in args:
            if a[0] == 'r' and a[2] == 8 and 4 <= a[1] <= 7 and not rex:
                raise ValueError(f'high byte register at {va:#x}')
            if a[0] == 'RIP':
                out.append(('rip', va + size + a[1], a[2]))
            else:
                out.append(a)
        return Insn(va, size, name, out)

    def imm(n):
        nonlocal p
        v = int.from_bytes(raw[p:p + n], 'little', signed=True)
        p += n
        return v

    if op == 0x0f:
        o2 = raw[p]
        p += 1
        if o2 == 0x1f:
            modrm(bits)
            return done('nop')
        if o2 == 0x0b:
            return done('ud2')
        if 0xc8 <= o2 <= 0xcf:
            return done('bswap', ('r', (o2 & 7) | b << 3, bits))
        if o2 == 0xaf:
            reg, e = modrm(bits)
            return done('imul', ('r', reg | r << 3, bits), fin(e))
        if o2 == 0xbc and pre == 0xf3:
            reg, e = modrm(bits)
            return done('tzcnt', ('r', reg | r << 3, 32 if not w else 64), fin(e))
        if o2 == 0x70 and pre in (0x66, 0xf2):
            reg, e = modrm(128)
            return done('pshufd' if pre == 0x66 else 'pshuflw', ('x', reg | r << 3), fin(e, True), ('i', imm(1) & 255))
        if 0x80 <= o2 <= 0x8f:
            d = imm(4)
            return done('j' + CC[o2 & 15], ('t', va + p + d))
        if 0x40 <= o2 <= 0x4f:
            reg, e = modrm(bits)
            return done('cmov' + CC[o2 & 15], ('r', reg | r << 3, bits), fin(e))
        if 0x90 <= o2 <= 0x9f:
            reg, e = modrm(8)
            return done('set' + CC[o2 & 15], fin(e))
        if o2 == 0xb6:
            reg, e = modrm(8)
            return done('movzx', ('r', reg | r << 3, bits), fin(e))
        if o2 == 0xb7:
            reg, e = modrm(16)
            return done('movzx', ('r', reg | r << 3, bits), fin(e))
        if o2 == 0x2a and pre == 0xf2:
            reg, e = modrm(64 if w else 32)
            return done('cvtsi2sd', ('x', reg | r << 3), fin(e))
        if o2 == 0x2c and pre == 0xf2:
            reg, e = modrm(64)
            return done('cvttsd2si', ('r', reg | r << 3, bits), fin(e, True))
        if o2 == 0x6e and pre == 0x66:
            reg, e = modrm(64 if w else 32)
            return done('movq' if w else 'movd', ('x', reg | r << 3), fin(e))
        if o2 == 0x7e and pre == 0x66:
            reg, e = modrm(64 if w else 32)
            return done('movq.r' if w else 'movd.r', fin(e), ('x', reg | r << 3))
        if o2 == 0xd7 and pre == 0x66:
            reg, e = modrm(128)
            return done('pmovmskb', ('r', reg | r << 3, 32), fin(e, True))
        key = (pre, o2)
        if key in SSE:
            reg, e = modrm(64 if SSE[key].endswith('sd') or SSE[key].endswith('sd.st') else 128)
            return done(SSE[key], ('x', reg | r << 3), fin(e, True))
        raise ValueError(f'unknown 0f {o2:02x} at {va:#x}')
    if 0x50 <= op <= 0x5f:
        return done('push' if op < 0x58 else 'pop', ('r', (op & 7) | b << 3, 64))
    if 0x70 <= op <= 0x7f:
        d = imm(1)
        return done('j' + CC[op & 15], ('t', va + p + d))
    if op == 0xeb:
        d = imm(1)
        return done('jmp', ('t', va + p + d))
    if op == 0xe9:
        d = imm(4)
        return done('jmp', ('t', va + p + d))
    if op == 0xe8:
        d = imm(4)
        return done('call', ('t', va + p + d))
    if op == 0xf6:
        reg, e = modrm(8)
        if reg == 2:
            return done('not', fin(e))
        if reg != 0:
            raise ValueError(f'f6 /{reg} at {va:#x}')
        return done('test', fin(e), ('i', imm(1) & 255))
    if op == 0xf7:
        reg, e = modrm(bits)
        if reg == 0:
            return done('test', fin(e), ('i', imm(2 if bits == 16 else 4) & M64))
        if reg == 2:
            return done('not', fin(e))
        if reg == 3:
            return done('neg', fin(e))
        if reg == 5:
            return done('imul1', fin(e))
        if reg != 4:
            raise ValueError(f'f7 /{reg} at {va:#x}')
        return done('mul', fin(e))
    if op == 0x90:
        return done('nop')
    if op == 0xc3:
        return done('ret')
    if op == 0x68:
        return done('push', ('i', imm(4) & M64))
    if op == 0xa8:
        return done('test', ('r', 0, 8), ('i', imm(1) & 255))
    if op == 0xa9:
        return done('test', ('r', 0, bits), ('i', imm(4) & 0xffffffff))
    if op == 0x98 and w:
        return done('cdqe')
    if op in (0x69, 0x6b):
        reg, e = modrm(bits)
        v = imm(1) if op == 0x6b else imm(2 if bits == 16 else 4)
        return done('imul3', ('r', reg | r << 3, bits), fin(e), ('i', v & ((1 << bits) - 1)))
    if op == 0xff:
        reg, e = modrm(64)
        if reg == 2:
            return done('call', fin(e))
        if reg in (0, 1):
            return done(('inc', 'dec')[reg], fin(e))
        if reg == 4 and e[0] == 'R':
            return done('jmpr', fin(e))
        raise ValueError(f'ff /{reg} at {va:#x}')
    if op == 0x63 and w:
        reg, e = modrm(32)
        return done('movsxd', ('r', reg | r << 3, 64), fin(e))
    if op & 0xc7 in (0x00, 0x01, 0x02, 0x03) and op & 0xf8 in ALU:
        name = ALU[op & 0xf8]
        sz = 8 if not op & 1 else bits
        reg, e = modrm(sz)
        a, c = fin(e), ('r', reg | r << 3, sz)
        return done(name, *((c, a) if op & 2 else (a, c)))
    if op == 0x3c:
        v = imm(1)
        return done('cmp', ('r', 0, 8), ('i', v & 255))
    if op == 0x3d:
        v = imm(4)
        return done('cmp', ('r', 0, bits), ('i', v & 0xffffffff))
    if op in (0x84, 0x85):
        sz = 8 if op == 0x84 else bits
        reg, e = modrm(sz)
        return done('test', fin(e), ('r', reg | r << 3, sz))
    if op in (0x88, 0x89, 0x8a, 0x8b):
        sz = 8 if not op & 1 else bits
        reg, e = modrm(sz)
        a, c = fin(e), ('r', reg | r << 3, sz)
        return done('mov', *((c, a) if op & 2 else (a, c)))
    if op == 0x8d:
        reg, e = modrm(bits)
        return done('lea', ('r', reg | r << 3, bits), fin(e))
    if op in (0x80, 0x81, 0x83):
        sz = 8 if op == 0x80 else bits
        reg, e = modrm(sz)
        v = imm(1) if op != 0x81 else imm(2 if sz == 16 else 4)
        return done(GRP1[reg], fin(e), ('i', v & ((1 << sz) - 1)))
    if op == 0xc1:
        reg, e = modrm(bits)
        v = imm(1)
        if reg not in (0, 4, 5, 7):
            raise ValueError(f'c1 /{reg} at {va:#x}')
        return done({0: 'rol', 4: 'shl', 5: 'shr', 7: 'sar'}[reg], fin(e), ('i', v & 255))
    if op == 0xc6:
        reg, e = modrm(8)
        return done('mov', fin(e), ('i', imm(1) & 255))
    if op == 0xc7:
        reg, e = modrm(bits)
        v = imm(2 if bits == 16 else 4)
        return done('mov', fin(e), ('i', v & M64 if bits == 64 else v & ((1 << bits) - 1)))
    if 0xb8 <= op <= 0xbf:
        n = 8 if w else 2 if bits == 16 else 4
        v = int.from_bytes(raw[p:p + n], 'little')
        p += n
        return done('mov', ('r', (op & 7) | b << 3, bits), ('i', v))
    if 0xb0 <= op <= 0xb7:
        v = raw[p]
        p += 1
        return done('mov', ('r', (op & 7) | b << 3, 8), ('i', v))
    raise ValueError(f'unknown opcode {op:02x} at {va:#x}')


def f2i(x):
    return struct.unpack('<Q', struct.pack('<d', x))[0]


def i2f(v):
    return struct.unpack('<d', struct.pack('<Q', v & M64))[0]


def sx(v, bits):
    return v - (1 << bits) if v >> (bits - 1) & 1 else v


class Machine:
    cache = {}
    real_map = {}

    def __init__(self, code, rodata, hook):
        self.code, self.rodata, self.hook = code, rodata, hook
        self.r = [0] * 16
        self.x = [[0, 0] for _ in range(16)]
        self.mem = {}
        self.cf = self.zf = self.sf = self.of = self.pf = False
        self.records = []
        self.steps = 0

    def ea(self, a):
        if a[0] == 'rip':
            return a[1]
        return ((self.r[a[1]] if a[1] is not None else 0) + (self.r[a[2]] * a[3] if a[2] is not None else 0) + a[4]) & M64

    def load(self, addr, n):
        out = bytearray()
        for i in range(n):
            if addr + i in self.mem:
                out.append(self.mem[addr + i])
            else:
                out += self.rodata(addr + i, 1) if addr + i < SCRATCH else b'\0'
        return bytes(out)

    def store(self, addr, b):
        for i, v in enumerate(b):
            self.mem[addr + i] = v

    def get(self, a):
        k = a[0]
        if k == 'r':
            return self.r[a[1]] & ((1 << a[2]) - 1)
        if k == 'i':
            return a[1]
        if k == 'm':
            return int.from_bytes(self.load(self.ea(a), a[5] // 8), 'little')
        if k == 'rip':
            return int.from_bytes(self.load(a[1], a[2] // 8), 'little')
        raise ValueError(a)

    def put(self, a, v):
        if a[0] == 'r':
            bits = a[2]
            if bits == 64:
                self.r[a[1]] = v & M64
            elif bits == 32:
                self.r[a[1]] = v & 0xffffffff
            else:
                m = (1 << bits) - 1
                self.r[a[1]] = (self.r[a[1]] & ~m & M64) | (v & m)
        elif a[0] == 'm':
            self.store(self.ea(a), (v & ((1 << a[5]) - 1)).to_bytes(a[5] // 8, 'little'))
        else:
            raise ValueError(a)

    def sd(self, a):
        return self.x[a[1]][0] if a[0] == 'x' else self.get(a)

    def x128(self, a):
        if a[0] == 'x':
            return list(self.x[a[1]])
        addr = self.ea(a) if a[0] == 'm' else a[1]
        b = self.load(addr, 16)
        return [int.from_bytes(b[:8], 'little'), int.from_bytes(b[8:], 'little')]

    def flags_logic(self, res, bits):
        self.cf = self.of = False
        self.zf = res == 0
        self.sf = bool(res >> (bits - 1) & 1)
        self.pf = bin(res & 255).count('1') % 2 == 0

    def cond(self, c):
        return {'o': self.of, 'no': not self.of, 'b': self.cf, 'ae': not self.cf, 'e': self.zf, 'ne': not self.zf,
                'be': self.cf or self.zf, 'a': not (self.cf or self.zf), 's': self.sf, 'ns': not self.sf, 'p': self.pf,
                'np': not self.pf, 'l': self.sf != self.of, 'ge': self.sf == self.of,
                'le': self.zf or self.sf != self.of, 'g': not self.zf and self.sf == self.of}[c]

    def run(self, pc, exits, limit=400):
        trace = []
        for _ in range(limit):
            if pc in exits:
                return pc, trace
            i = self.cache.get(pc)
            if i is None:
                i = decode(self.code, pc)
                self.cache[pc] = i
            trace.append(pc)
            self.steps += 1
            pc += i.size
            op, a = i.op, i.args
            if op == 'mov' or op == 'movzx':
                self.put(a[0], self.get(a[1]))
            elif op == 'lea':
                self.put(a[0], self.ea(a[1]))
            elif op in ('add', 'adc', 'sub', 'sbb', 'cmp', 'and', 'xor', 'or', 'test'):
                bits = a[0][2] if a[0][0] == 'r' else a[0][-1]
                m = (1 << bits) - 1
                u, v = self.get(a[0]), self.get(a[1]) & m
                if op in ('add', 'adc'):
                    c = int(self.cf) if op == 'adc' else 0
                    res = (u + v + c) & m
                    self.cf = u + v + c > m
                    self.of = bool((~(u ^ v) & (u ^ res)) >> (bits - 1) & 1)
                elif op in ('sub', 'cmp', 'sbb'):
                    c = int(self.cf) if op == 'sbb' else 0
                    res = (u - v - c) & m
                    self.cf = u < v + c
                    self.of = bool(((u ^ v) & (u ^ res)) >> (bits - 1) & 1)
                else:
                    res = {'and': u & v, 'test': u & v, 'xor': u ^ v, 'or': u | v}[op]
                    self.flags_logic(res, bits)
                self.zf = res == 0
                self.sf = bool(res >> (bits - 1) & 1)
                self.pf = bin(res & 255).count('1') % 2 == 0
                if op not in ('cmp', 'test'):
                    self.put(a[0], res)
            elif op == 'push':
                self.r[4] -= 8
                self.store(self.r[4], self.get(a[0]).to_bytes(8, 'little'))
            elif op == 'ret':
                self.r[4] += 8
                pc = int.from_bytes(self.load(self.r[4] - 8, 8), 'little')
            elif op == 'ud2':
                raise Panic('ud2', i.va)
            elif op == 'neg':
                bits = a[0][2] if a[0][0] == 'r' else a[0][-1]
                u = self.get(a[0])
                res = -u & ((1 << bits) - 1)
                self.cf = u != 0
                self.of = u == 1 << (bits - 1)
                self.zf, self.sf = res == 0, bool(res >> (bits - 1) & 1)
                self.put(a[0], res)
            elif op == 'not':
                bits = a[0][2] if a[0][0] == 'r' else a[0][-1]
                self.put(a[0], ~self.get(a[0]) & ((1 << bits) - 1))
            elif op == 'cdqe':
                self.r[0] = sx(self.r[0] & 0xffffffff, 32) & M64
            elif op == 'tzcnt':
                u = self.get(a[1])
                n = (u & -u).bit_length() - 1 if u else a[0][2]
                self.cf, self.zf = u == 0, n == 0
                self.put(a[0], n)
            elif op == 'rol':
                u, n = self.get(a[0]), a[1][1]
                self.put(a[0], (u << n | u >> (64 - n)) & M64)
            elif op == 'imul':
                res = sx(self.get(a[0]), 64) * sx(self.get(a[1]), 64)
                self.cf = self.of = not -(1 << 63) <= res < 1 << 63
                self.put(a[0], res & M64)
            elif op == 'imul3':
                bits = a[0][2]
                res = sx(self.get(a[1]), bits) * sx(a[2][1], bits)
                self.cf = self.of = not -(1 << (bits - 1)) <= res < 1 << (bits - 1)
                self.put(a[0], res & ((1 << bits) - 1))
            elif op == 'imul1':
                res = sx(self.r[0], 64) * sx(self.get(a[0]), 64)
                self.r[0], self.r[2] = res & M64, (res >> 64) & M64
                self.cf = self.of = not -(1 << 63) <= res < 1 << 63
            elif op == 'pop':
                self.put(a[0], int.from_bytes(self.load(self.r[4], 8), 'little'))
                self.r[4] += 8
            elif op in ('inc', 'dec'):
                bits = a[0][2] if a[0][0] == 'r' else a[0][-1]
                res = (self.get(a[0]) + (1 if op == 'inc' else -1)) & ((1 << bits) - 1)
                self.zf, self.sf = res == 0, bool(res >> (bits - 1) & 1)
                self.put(a[0], res)
            elif op == 'nop':
                pass
            elif op == 'sar':
                bits = a[0][2]
                v = sx(self.get(a[0]), bits) >> a[1][1]
                self.put(a[0], v & M64)
            elif op == 'shl':
                self.put(a[0], self.get(a[0]) << a[1][1])
            elif op == 'shr':
                self.put(a[0], self.get(a[0]) >> a[1][1])
            elif op == 'mul':
                res = self.r[0] * self.get(a[0])
                self.r[0], self.r[2] = res & M64, res >> 64
                self.cf = self.of = res >> 64 != 0
            elif op.startswith('set'):
                self.put(a[0], int(self.cond(op[3:])))
            elif op.startswith('cmov'):
                if self.cond(op[4:]):
                    self.put(a[0], self.get(a[1]))
                elif a[0][2] == 32:
                    self.put(a[0], self.get(a[0]))
            elif op == 'jmp':
                pc = a[0][1]
            elif op == 'jmpr':
                pc = self.get(a[0])
            elif op == 'movsxd':
                self.put(a[0], sx(self.get(a[1]), 32) & M64)
            elif op == 'bswap':
                n = a[0][2] // 8
                self.put(a[0], int.from_bytes(self.get(a[0]).to_bytes(n, 'little'), 'big'))
            elif op[0] == 'j':
                if self.cond(op[1:]):
                    pc = a[0][1]
            elif op == 'call':
                target = self.r[a[0][1]] if a[0][0] == 'r' else a[0][1]
                real = self.real_target(target)
                if real is not None:
                    self.r[4] -= 8
                    self.store(self.r[4], pc.to_bytes(8, 'little'))
                    pc = real
                elif not self.hook(target, self):
                    raise ValueError(f'unmodelled call at {i.va:#x}')
            elif op == 'cvtsi2sd':
                self.x[a[0][1]][0] = f2i(float(sx(self.get(a[1]), a[1][2] if a[1][0] == 'r' else a[1][-1])))
            elif op == 'cvttsd2si':
                f = i2f(self.sd(a[1]))
                self.put(a[0], (int(f) if -2.0 ** 63 <= f < 2.0 ** 63 else -(1 << 63)) & M64)
            elif op in ('movsd', 'movq'):
                if a[1][0] == 'x':
                    self.x[a[0][1]][0] = self.x[a[1][1]][0]
                else:
                    self.x[a[0][1]] = [self.get(a[1]), 0]
            elif op == 'movsd.st':
                if a[1][0] == 'x':
                    self.x[a[1][1]][0] = self.x[a[0][1]][0]
                else:
                    self.put(a[1], self.x[a[0][1]][0])
            elif op == 'movq.r':
                self.put(a[0], self.x[a[1][1]][0])
            elif op in ('movdqa', 'movapd', 'movaps', 'movdqu', 'movups', 'movupd'):
                self.x[a[0][1]] = self.x128(a[1])
            elif op in ('movups.st', 'movupd.st', 'movaps.st', 'movapd.st', 'movdqa.st', 'movdqu.st'):
                lo, hi = self.x[a[0][1]]
                self.store(self.ea(a[1]), lo.to_bytes(8, 'little') + hi.to_bytes(8, 'little'))
            elif op == 'movd':
                self.x[a[0][1]] = [self.get(a[1]), 0]
            elif op == 'pcmpeqb':
                u, v = self.x[a[0][1]], self.x128(a[1])
                ub = u[0].to_bytes(8, 'little') + u[1].to_bytes(8, 'little')
                vb = v[0].to_bytes(8, 'little') + v[1].to_bytes(8, 'little')
                b = bytes(255 if p == q else 0 for p, q in zip(ub, vb))
                self.x[a[0][1]] = [int.from_bytes(b[:8], 'little'), int.from_bytes(b[8:], 'little')]
            elif op == 'pcmpeqd':
                u, v = self.x[a[0][1]], self.x128(a[1])
                ub = u[0].to_bytes(8, 'little') + u[1].to_bytes(8, 'little')
                vb = v[0].to_bytes(8, 'little') + v[1].to_bytes(8, 'little')
                b = b''.join(b'\xff\xff\xff\xff' if ub[n:n + 4] == vb[n:n + 4] else b'\0\0\0\0' for n in (0, 4, 8, 12))
                self.x[a[0][1]] = [int.from_bytes(b[:8], 'little'), int.from_bytes(b[8:], 'little')]
            elif op == 'punpcklbw':
                u, v = self.x[a[0][1]], self.x128(a[1])
                ub, vb = u[0].to_bytes(8, 'little'), v[0].to_bytes(8, 'little')
                b = bytes(z for pair in zip(ub, vb) for z in pair)
                self.x[a[0][1]] = [int.from_bytes(b[:8], 'little'), int.from_bytes(b[8:], 'little')]
            elif op == 'pshuflw':
                u = self.x128(a[1])
                w = [u[0] >> (16 * n) & 0xffff for n in range(4)]
                lo = sum(w[a[2][1] >> (2 * n) & 3] << (16 * n) for n in range(4))
                self.x[a[0][1]] = [lo, u[1]]
            elif op == 'pshufd':
                u = self.x128(a[1])
                w = [u[0] & 0xffffffff, u[0] >> 32, u[1] & 0xffffffff, u[1] >> 32]
                o = [w[a[2][1] >> (2 * n) & 3] for n in range(4)]
                self.x[a[0][1]] = [o[0] | o[1] << 32, o[2] | o[3] << 32]
            elif op == 'pand':
                u, v = self.x[a[0][1]], self.x128(a[1])
                self.x[a[0][1]] = [u[0] & v[0], u[1] & v[1]]
            elif op == 'pmovmskb':
                u = self.x[a[1][1]]
                b = u[0].to_bytes(8, 'little') + u[1].to_bytes(8, 'little')
                self.put(a[0], sum((p >> 7) << n for n, p in enumerate(b)))
            elif op in ('mulsd', 'divsd', 'addsd', 'subsd', 'maxsd', 'minsd'):
                u, v = i2f(self.x[a[0][1]][0]), i2f(self.sd(a[1]))
                if op == 'mulsd':
                    res = u * v
                elif op == 'addsd':
                    res = u + v
                elif op == 'subsd':
                    res = u - v
                elif op == 'divsd':
                    res = u / v if v else (math.nan if u == 0 or u != u else math.copysign(math.inf, u) * math.copysign(1, v))
                elif op == 'maxsd':
                    res = u if u > v else v
                else:
                    res = u if u < v else v
                self.x[a[0][1]][0] = f2i(res)
            elif op == 'ucomisd':
                u, v = i2f(self.x[a[0][1]][0]), i2f(self.sd(a[1]))
                self.of = self.sf = False
                if u != u or v != v:
                    self.zf = self.pf = self.cf = True
                else:
                    self.pf = False
                    self.zf = u == v
                    self.cf = u < v
            elif op in ('pxor', 'xorps', 'xorpd'):
                s = self.x128(a[1])
                d = self.x[a[0][1]]
                self.x[a[0][1]] = [d[0] ^ s[0], d[1] ^ s[1]]
            elif op == 'punpckldq':
                d, s = self.x[a[0][1]], self.x128(a[1])
                self.x[a[0][1]] = [(d[0] & 0xffffffff) | (s[0] & 0xffffffff) << 32,
                                   d[0] >> 32 | (s[0] >> 32) << 32]
            elif op == 'subpd':
                d, s = self.x[a[0][1]], self.x128(a[1])
                self.x[a[0][1]] = [f2i(i2f(d[0]) - i2f(s[0])), f2i(i2f(d[1]) - i2f(s[1]))]
            elif op == 'unpckhpd':
                d, s = self.x[a[0][1]], self.x128(a[1])
                self.x[a[0][1]] = [d[1], s[1]]
            else:
                raise ValueError(f'unmodelled {op} at {i.va:#x}')
        raise ValueError('step limit')

    def real_target(self, target):
        return self.real_map.get(target)


PINS = [
    ('transfer wrapper', 0x1e60d30, 'cmp [rax+0x3c]:8,0x3', 'class byte of the master'),
    ('transfer wrapper', 0x1e60d38, 'cmp [r12+0x5b1]:8,0x0', 'class 3 reads pass byte 0x5b1'),
    ('transfer wrapper', 0x1e60d45, 'cmp [r12+0x5b0]:8,0x0', 'class above 3 reads pass byte 0x5b0'),
    ('transfer wrapper', 0x1e60d6c, 'cmp [rax+0x3c]:8,0x3', 'class byte of the sub-account, same rule'),
    ('transfer wrapper', 0x1e60d7f, 'mov [rbx+0x8]:16,0x16f', 'code 367'),
    ('transfer wrapper', 0x1e60daf, 'call 0x27148e0', 'body call'),
    ('transfer wrapper', 0x1e60db4, 'cmp [rsp]:16,0x186', 'code 390 maps to tag 13'),
    ('transfer body', 0x27148f1, 'mov rbx,[rcx]:64', 'usd'),
    ('transfer body', 0x27148f4, 'mov rax,0xccccccccccccccc', 'usd cut'),
    ('transfer body', 0x2714a55, 'mov [rdi]:16,0x13f', 'code 319 before the zero test'),
    ('transfer body', 0x2714a63, 'mov [rdi]:16,0x31', 'code 49'),
    ('transfer body', 0x2714910, 'movzx raxd,[rcx+0x1c]:8', 'is_deposit'),
    ('transfer body', 0x2714933, 'cmovne r8,rdx', 'deposit picks the master as sender'),
    ('transfer body', 0x2714937, 'cmove rax,rdx', 'withdraw picks the master as receiver'),
    ('transfer body', 0x2714961, 'cmp [rsi+0x3828]:64,0x0', 'empty link table means code 218'),
    ('transfer body', 0x271498f, 'call 0x399c7a0', 'hash of the sub-account address'),
    ('transfer body', 0x2714b12, 'mov [rdi]:16,0xda', 'code 218 for both miss and wrong master'),
    ('transfer body', 0x2714b52, 'cmp [rcx+0x5c8]:64,0x0', 'clearinghouse count tested after the link'),
    ('transfer body', 0x2714bcc, 'call [0x5774660]:64', 'available balance of the sender'),
    ('transfer body', 0x2714bda, 'mov [r13]:16,0x33', 'code 51'),
    ('transfer body', 0x2714bf1, 'call [0x57749d8]:64', 'debit of the sender'),
    ('transfer body', 0x2714c05, 'call 0x36ff4f0', 'credit of the receiver'),
    ('transfer body', 0x2714c0d, 'cvtsi2sd xmm0,rbx', 'usd read as a signed i64'),
    ('transfer body', 0x2714c12, 'divsd xmm0,[0x20ae60]:64', 'divide by 1e6'),
    ('transfer body', 0x2714c53, 'mov rax,0x800000000000000e', 'event tag'),
    ('transfer body', 0x2714c65, 'mov rdid,0x28', 'user Vec of 40 bytes'),
    ('transfer body', 0x2714cc6, 'cmp [r15]:32,0x1', 'real hash only when exchange +0 is 1'),
    ('transfer body', 0x2714d3f, 'call [0x5774738]:64', 'event push before the two account rows'),
    ('transfer body', 0x2714d71, 'call 0x1f849b0', 'sender row'),
    ('transfer body', 0x2714d79, 'mov rcx,0x346dc5d63886594b', 'divide by 10000 multiplier'),
    ('transfer body', 0x2714d8c, 'shr rbx,0xb', 'quotient shift'),
    ('transfer body', 0x2714da0, 'jo 0x2714e32', 'sender +0x10 overflow arm'),
    ('transfer body', 0x2714db4, 'jo 0x2714e61', 'sender +0x18 overflow arm'),
    ('transfer body', 0x2714de3, 'call 0x1f849b0', 'receiver row'),
    ('transfer body', 0x2714df2, 'jo 0x2714e93', 'receiver +0x10 overflow arm'),
    ('transfer body', 0x2714e09, 'jo 0x2714ebe', 'receiver +0x18 overflow arm'),
    ('transfer body', 0x2714e13, 'mov [rdi]:16,0x186', 'code 390'),
    ('modify wrapper', 0x22cdfcc, 'cmp rax,[rsi]:64', 'None test: 0 - word overflows only for i64::MIN'),
    ('modify wrapper', 0x22cdfd1, 'mov r12,0x8000000000000000', 'None passes i64::MIN on'),
    ('modify wrapper', 0x22ce056, 'call [0x5773d20]:64', 'call through the slot for 0x36f40d0, also for None'),
    ('modify wrapper', 0x22ce05e, 'cmp [rsp+0x38]:16,0x186', 'code 390 maps to tag 13'),
    ('create wrapper', 0x27e317d, 'call [0x5774f40]:64', 'derive first'),
    ('create wrapper', 0x27e31d2, 'cmp [r14+0x758]:64,0x0', 'empty user table skips the test'),
    ('create wrapper', 0x27e335e, 'mov [rbx+0x8]:16,0xd8', 'code 216 from the user table'),
    ('create wrapper', 0x27e3317, 'call 0x275fee0', 'equity of the master'),
    ('create wrapper', 0x27e33ba, 'call [0x5774f48]:64', 'inner create with the equity'),
    ('create wrapper', 0x27e341a, 'call rbp', 'settings of the master'),
    ('create wrapper', 0x27e3438, 'call rbp', 'settings of the new sub-account'),
    ('create wrapper', 0x27e3443, 'ucomisd xmm0,[rsp+0xe8]:64', 'f64 word +0x70 first'),
    ('create wrapper', 0x27e34eb, 'mov raxd,[rsp+0x1a8]:32', 'u32 +0x68 of the master'),
    ('create wrapper', 0x27e3507, 'je 0x27e3586', 'both non-zero compares the middle words'),
    ('create wrapper', 0x27e3669, 'call 0x1f84840', 'row entry for the sub-account'),
    ('create wrapper', 0x27e366e, 'mov [rax]:64,0x1', 'first word of the row is 1'),
    ('create wrapper', 0x27e36f4, 'call 0x1f849b0', 'user row for the sub-account'),
    ('create wrapper', 0x27e3717, 'call 0x1f84b30', 'second row map'),
    ('create wrapper', 0x27e371c, 'mov [rbx]:8,0x6', 'success tag 6 with the address at +1'),
    ('token list', 0x3c97940, 'mov [rbx]:8,0x6', 'String token'),
    ('token list', 0x3c9795d, 'mov [rbx+0x28]:8,0x0', 'Address token'),
    ('token list', 0x3c97971, 'mov [rbx+0x50]:8,0x4', 'Uint token'),
    ('token list', 0x3c97975, 'mov [rbx+0x58]:64,rax', 'low limb is the count'),
    ('token list', 0x3c9799e, 'mov rdxd,0x3', 'three tokens'),
    ('token list', 0x3c979a9, 'call [0x576ed20]:64', 'encode through the slot'),
]


LAYOUT_ROWS = [
    ('transfer_action', 0x00, 8, 0x27148f1, '[rcx]:64', 'usd'),
    ('transfer_action', 0x08, 20, 0x1e60d58, '[r14+0x8]:128', 'sub-account address'),
    ('transfer_action', 0x1c, 1, 0x2714910, '[rcx+0x1c]:8', 'is_deposit'),
    ('modify_action', 0x00, 8, 0x22cdfcc, '[rsi]:64', 'Option<String> capacity word; i64::MIN is None'),
    ('modify_action', 0x08, 8, 0x22cdfe1, '[r15+0x8]:64', 'name pointer'),
    ('modify_action', 0x10, 8, 0x22cdfe5, '[r15+0x10]:64', 'name length'),
    ('modify_action', 0x18, 20, 0x22ce031, '[r15]:128', 'sub-account address; r15 = action + 0x18'),
    ('create_action', 0x08, 8, 0x27e3324, '[r13+0x8]:64', 'name pointer'),
    ('create_action', 0x10, 8, 0x27e3328, '[r13+0x10]:64', 'name length'),
    ('exchange', 0x00, 4, 0x2714cc6, '[r15]:32', 'equal to 1 selects a real hash from 0x3987cb0, otherwise 32 zero bytes'),
    ('exchange', 0x60, 12, 0x2714cbd, '[r15+0x60]:64', 'time copied into the event'),
    ('exchange', 0x318, 16, 0x27e36f9, 'r14', 'second row map argument of 0x1f84b30, row 0x58 bytes'),
    ('exchange', 0x5b0, 1, 0x1e60d45, '[r12+0x5b0]:8', 'pass byte for user class above 3'),
    ('exchange', 0x5b1, 1, 0x1e60d38, '[r12+0x5b1]:8', 'pass byte for user class 3'),
    ('exchange', 0x5c0, 8, 0x2714b65, '[rcx+0x5c0]:64', 'clearinghouse array pointer'),
    ('exchange', 0x5c8, 8, 0x2714b52, '[rcx+0x5c8]:64', 'clearinghouse count; zero panics with code 321 in the Err payload'),
    ('exchange', 0x5d0, 16, 0x27e33fe, '[r14+0x5d0]', 'argument of 0x3743df0 for master and sub-account'),
    ('exchange', 0x690, 16, 0x27e364e, '[r14+0x690]', 'map argument of 0x1f84840, row 0xe8 bytes'),
    ('exchange', 0x740, 8, 0x27e31fb, '[r14+0x740]:64', 'user table control bytes, row 0x58 bytes'),
    ('exchange', 0x748, 8, 0x27e3202, '[r14+0x748]:64', 'user table mask'),
    ('exchange', 0x758, 8, 0x27e31d2, '[r14+0x758]:64', 'user table item count'),
    ('exchange', 0x760, 16, 0x27e31e0, '[r14+0x760]', 'user table hasher argument of 0x2840fb0'),
    ('exchange', 0x8f2, 1, 0x2714cd9, '[r12+0x8f2]:8', 'chain byte passed to the hash'),
    ('exchange', 0x37e0, 16, 0x27e315d, '[rcx+0x37e0]', 'SubAccounts; user_to_sub_accounts map starts here'),
    ('exchange', 0x3810, 8, 0x271499e, '[r15+0x3810]:64', 'sub_account_to_master control bytes, row 0x28 bytes'),
    ('exchange', 0x3818, 8, 0x27149a5, '[r15+0x3818]:64', 'sub_account_to_master mask'),
    ('exchange', 0x3828, 8, 0x2714961, '[rsi+0x3828]:64', 'sub_account_to_master item count'),
    ('exchange', 0x3830, 16, 0x271497d, '[rsi+0x3830]', 'sub_account_to_master hasher argument of 0x399c7a0'),
    ('sub_account_row', 0x00, 20, 0x2714a01 - 6, '[r8+r14*8]:128', 'key: sub-account address'),
    ('sub_account_row', 0x14, 20, 0x2714a6d, '[rdx+r14*8-0x14]:128', 'value: master address'),
    ('user_row', 0x10, 8, 0x2714d96, '[r14+0x10]:64', 'i64 sum, transfer moves usd / 10000'),
    ('user_row', 0x18, 8, 0x2714daa, '[r14+0x18]:64', 'i64 sum, transfer moves usd / 10000'),
    ('user_row', 0x3c, 1, 0x1e60d30, '[rax+0x3c]:8', 'user class byte read through 0x2755400; row pointer is key + 0x18'),
    ('event', 0x00, 8, 0x2714c5d, '[rsp+0x150]:64', 'tag 0x800000000000000e'),
    ('event', 0x08, 8, 0x2714c1a, '[rsp+0x158]:64', 'usd as f64 / 1e6'),
    ('event', 0x10, 20, 0x2714c27, '[rsp+0x160]', 'from'),
    ('event', 0x24, 20, 0x2714c3f, '[rsp+0x174]', 'to'),
    ('token', 0x00, 1, 0x3c97940, '[rbx]:8', 'first ethabi token tag 6 String: capacity, pointer and length follow at +0x08'),
    ('token', 0x28, 1, 0x3c9795d, '[rbx+0x28]:8', 'second token tag 0 Address: 20 bytes at +0x29'),
    ('token', 0x50, 1, 0x3c97971, '[rbx+0x50]:8', 'third token tag 4 Uint: little-endian limbs at +0x58'),
    ('encoder_input', 0x00, 24, 0x3c97933, '[r15]:128', 'domain String, 24 bytes moved to the token'),
    ('encoder_input', 0x18, 20, 0x3c97961, '[r15+0x18]:128', 'master address'),
    ('encoder_input', 0x30, 8, 0x3c9793c, '[r15+0x30]:64', 'sub-account count, low limb of the Uint'),
]

LOCATIONS = [(0x5715ef8, 'account sum add'), (0x56e9af8, 'clearinghouse unwrap in the transfer body')]

FUNCS = [(0x1e60d00, 'subAccountTransfer wrapper, dispatch index 31'), (0x27148e0, 'subAccountTransfer body'),
         (0x22cdfb0, 'subAccountModify wrapper, dispatch index 30'), (0x27e3140, 'createSubAccount wrapper, dispatch index 6'),
         (0x2755400, 'user row lookup with default row'), (0x3c97900, 'token list for the sub-account address'),
         (0x1592160, 'ethabi encode entry'), (0x158fb50, 'mediate each token'), (0x1591a00, 'mediate one token'),
         (0x1591cd0, 'pad bytes into words'), (0x1592460, 'head length of one mediate'), (0x15924e0, 'tail length of one mediate'),
         (0x1591f20, 'write heads and tails'), (0x158fc70, 'flatten words into bytes')]

STUBS = [(0x576dfd8, 'allocate'), (0x576dfe0, 'memcpy'), (0x576e010, 'free'), (0x5773190, 'overflow recorder'),
         (0x3379490, 'drop of a code value'), (0x3987cb0, '32-byte hash'), (0x5774660, 'available balance'),
         (0x57749d8, 'debit'), (0x36ff4f0, 'credit'), (0x5774738, 'event push'), (0x1f849b0, 'user account entry'),
         (0x399c7a0, 'hash of a 20-byte address, sub-account table'), (0x2840fb0, 'hash of a 20-byte address, user table'),
         (0x5774f40, 'derive sub-account user, address held by open PR #615'),
         (0x5774f48, 'create sub-account row, address held by open PR #615'),
         (0x5773d20, 'modify sub-account name, address held by open PR #615'),
         (0x275fee0, 'equity of the master'), (0x57748f8, 'per-user settings read, 15 f64 words'),
         (0x1f84840, 'settings row entry'), (0x1f84b30, 'second row map entry'), (0x3bbc830, 'ethabi token drop'),
         (0x1590370, 'mediate list drop')]

STATUS = [(214, 'TooManySubAccounts'), (215, 'SubAccountNameNotUnique'), (216, 'DuplicateSubAccountUser'), (217, 'SubAccountInvalidName'),
          (218, 'SubAccountTransferNotAllowed'), (219, 'SubAccountNotAllowed'), (220, 'SubAccountNotRegistered'),
          (221, 'SubAccountsNotEligible'), (222, 'SelfTransfer')]

LABELS = {0x27148e0: 'subAccountTransfer body', 0x27e3140: 'createSubAccount wrapper', 0x21e00b0: 'startFeeTrial, dispatch index 55',
          0x36f3610: 'create row, open PR #615', 0x36f40d0: 'modify name, open PR #615', 0x36f43c0: 'name check, open PR #615',
          0x2717a70: 'reference hint: subAccountSpotTransfer core', 0x2710530: 'reference hint: usdSend core'}

CUT = 0x0ccccccccccccccc
OK = 0x186
I64MAX, I64MIN = (1 << 63) - 1, -(1 << 63)
SENT = 0x10
SP = 0x7f00000
HEAP = 0x8000000
EX = 0x7900000
CH = 0x7a00000
ACTION = 0x7810000
USER = 0x7830000
OUT = 0x7820000
SUB_CTRL = 0x7880000
USER_CTRL = 0x7860000
DEFAULT_ROW = 0x5786190
H_SUB = 0x5a00000000000000
H_USER = 0x3300000000000000


class Image:
    def __init__(self, data):
        self.data = data
        self.secs = sections(data)
        self.mapped = sorted(((s['address'], s['size'], s['offset'], s['name']) for s in self.secs
                              if s['type'] != 8 and s['address']), key=lambda s: s[0])
        self.starts = [s[0] for s in self.mapped]
        self.cache = {}
        self._rel = None

    def rd(self, va, n):
        i = bisect.bisect_right(self.starts, va) - 1
        if i < 0 or va >= self.mapped[i][0] + self.mapped[i][1]:
            raise ValueError(f'{va:#x} is outside file-backed sections')
        addr, size, off, _ = self.mapped[i]
        return self.data[off + va - addr:off + va - addr + min(n, addr + size - va)]

    def section(self, name):
        return next(s for s in self.secs if s['name'] == name)

    def relative(self):
        if self._rel is None:
            self._rel = {}
            s = self.section('.rela.dyn')
            for pos in range(s['offset'], s['offset'] + s['size'], 24):
                where, info, addend = struct.unpack_from('<QQq', self.data, pos)
                if info & 0xffffffff == 8:
                    self._rel[where] = addend
        return self._rel


def load():
    data = (ROOT / BINARY).read_bytes()
    if hashlib.sha256(data).hexdigest() != SHA256:
        raise SystemExit('hl-node SHA-256 mismatch')
    return data


def i64(v):
    return sx(v & M64, 64)


def addr(n):
    """Twenty distinct bytes for one fixture address."""
    return bytes((n * 37 + 11 + i * 5) & 255 for i in range(20))


def q(m, a, v):
    m.store(a, (v & M64).to_bytes(8, 'little'))


def rq(m, a):
    return int.from_bytes(m.load(a, 8), 'little')


class World:
    """One fixture: a Machine, its bump heap and the named stubs."""

    def __init__(self, img):
        self.img = img
        self.m = Machine(img.rd, img.rd, self.hook)
        self.m.cache = img.cache
        self.m.r[4] = SP
        self.heap = HEAP
        self.recorded = []
        self.log = []
        self.events = []
        self.accounts = {}
        self.balance = 0
        self.derive = (OK, addr(90))
        self.inner = (OK, addr(90), b'')
        self.modify = (OK, b'')
        self.equity = 0
        self.settings = {}
        self.setting_rows = {}
        self.second_rows = []
        self.freed = 0
        self.stubs = {0x576dfd8: self.malloc, 0x576dfe0: self.memcpy, 0x576e010: self.free, 0x5773190: self.recorder,
                      0x3379490: lambda *a: 0, 0x3987cb0: self.hash32, 0x5774660: self.avail, 0x57749d8: self.debit,
                      0x36ff4f0: self.credit, 0x5774738: self.event, 0x1f849b0: self.account,
                      0x399c7a0: lambda *a: H_SUB, 0x2840fb0: lambda *a: H_USER, 0x5774f40: self.derive_stub,
                      0x5774f48: self.inner_stub, 0x5773d20: self.modify_stub, 0x275fee0: self.equity_stub,
                      0x57748f8: self.settings_stub, 0x1f84840: self.setting_row, 0x1f84b30: self.second_row,
                      0x3bbc830: lambda *a: 0, 0x1590370: lambda *a: 0, 0x576e048: self.panic_unwrap, 0x576e118: self.panic_rdi,
                      0x576e1b0: self.panic_rdi, 0x576dfb8: self.panic_alloc}
        q(self.m, 0x57748f8, 0x57748f8)
        q(self.m, 0x57749b8, DEFAULT_ROW)
        self.m.store(DEFAULT_ROW, bytes(0x48))

    def alloc(self, n):
        a = self.heap
        self.heap += (n + 63) & ~15
        return a

    def hook(self, target, m):
        f = self.stubs.get(target)
        if f is None:
            return False
        ret = f(m, m.r[7], m.r[6], m.r[2], m.r[1], m.r[8], m.r[9])
        for i in (1, 2, 6, 7, 8, 9, 10, 11):
            m.r[i] = 0xdead0000dead0000
        m.r[0] = (ret or 0) & M64
        return True

    def malloc(self, m, n, *_):
        return self.alloc(n)

    def memcpy(self, m, a, b, n, *_):
        m.store(a, m.load(b, n))
        return a

    def free(self, m, *_):
        self.freed += 1

    def recorder(self, m, a, b, *_):
        self.recorded.append(b)

    def hash32(self, m, out, a, b, c, d, *_):
        self.log.append(('hash', a & 255, b, c, d))
        m.store(out, bytes(range(0x90, 0xb0)))

    def avail(self, m, ch, key, *_):
        self.log.append(('avail', ch, m.load(key, 20).hex()))
        return self.balance

    def debit(self, m, ch, key, usd, *_):
        self.log.append(('debit', ch, m.load(key, 20).hex(), usd))

    def credit(self, m, ch, key, usd, *_):
        self.log.append(('credit', ch, m.load(key, 20).hex(), usd))

    def event(self, m, ptr, users, when, hsh, ev, *_):
        self.log.append(('event',))
        self.events.append((ptr, rq(m, users), rq(m, users + 16), m.load(rq(m, users + 8), 40).hex(), m.load(when, 12).hex(), m.load(hsh, 32).hex(),
                            rq(m, ev), rq(m, ev + 8), m.load(ev + 0x10, 20).hex(), m.load(ev + 0x24, 20).hex()))

    def account(self, m, map_ptr, key, *_):
        k = m.load(key, 20)
        self.log.append(('account', map_ptr, k.hex()))
        if k not in self.accounts:
            self.accounts[k] = self.alloc(0x40)
        return self.accounts[k]

    def derive_stub(self, m, out, subs, key, *_):
        self.log.append(('derive', subs, m.load(key, 20).hex()))
        m.store(out, self.derive[0].to_bytes(2, 'little') + self.derive[1])

    def inner_stub(self, m, out, subs, key, name, equity, *_):
        n = rq(m, name + 16)
        self.log.append(('inner', subs, m.load(key, 20).hex(), rq(m, name), m.load(rq(m, name + 8), n).hex(), n, equity))
        code, a, tail = self.inner
        m.store(out, code.to_bytes(2, 'little') + a)
        m.store(out + 22, tail)

    def modify_stub(self, m, out, subs, key, act, *_):
        cap, n = rq(m, act), rq(m, act + 16)
        name = None if cap == 1 << 63 else (cap, m.load(rq(m, act + 8), n).hex(), n)
        self.log.append(('modify', subs, m.load(key, 20).hex(), name, m.load(act + 24, 20).hex()))
        m.store(out, self.modify[0].to_bytes(2, 'little') + self.modify[1])

    def equity_stub(self, m, ex, key, *_):
        self.log.append(('equity', ex, m.load(key, 20).hex()))
        return self.equity

    def settings_stub(self, m, out, base, key, *_):
        k = m.load(key, 20)
        self.log.append(('settings', base, k.hex()))
        m.store(out, self.settings.get(k, bytes(0x78)))

    def setting_row(self, m, base, key, *_):
        k = m.load(key, 20)
        self.setting_rows[k] = self.alloc(0xd8)
        self.log.append(('setting_row', base, k.hex()))
        return self.setting_rows[k]

    def second_row(self, m, base, key, *_):
        self.log.append(('second_row', base, m.load(key, 20).hex()))

    def panic_unwrap(self, m, msg, n, payload, vt, loc, *_):
        raise Panic('unwrap', loc, m.load(payload, 2))

    def panic_rdi(self, m, loc, *_):
        raise Panic('panic', loc)

    def panic_alloc(self, m, *_):
        raise Panic('alloc')


REAL = {t: t for t, _ in FUNCS[4:] + FUNCS[:3]}
REAL.update({0x576ed20: 0x1592160})
del REAL[0x1592160]
REAL[0x1592160] = 0x1592160
Machine.real_map = REAL


def call(w, fn, *args):
    m = w.m
    m.r[4] -= 8
    q(m, m.r[4], SENT)
    for reg, v in zip((7, 6, 2, 1, 8, 9), args):
        m.r[reg] = v
    m.run(fn, {SENT}, 400000)


def swiss(w, ctrl, rows, row_size, tag, mask=31):
    """Write rows into a SwissTable at ctrl; every key shares one hash, the row compare picks the key."""
    m = w.m
    m.store(ctrl, bytes((0xff,)) * (mask + 1 + 16))
    for i, row in enumerate(rows):
        m.store(ctrl + i, bytes((tag,)))
        if i < 16:
            m.store(ctrl + mask + 1 + i, bytes((tag,)))
        m.store(ctrl - (i + 1) * row_size, row)


def exchange(w, links, users, gates, flag=1, chs=1):
    """links: sub-account -> master.  users: address -> class byte."""
    m = w.m
    m.store(EX, flag.to_bytes(4, 'little'))
    q(m, EX + 8, 0x1111)
    q(m, EX + 0x28, 0x2222)
    q(m, EX + 0x60, 0x0807060504030201)
    m.store(EX + 0x68, bytes((9, 10, 11, 12)))
    m.store(EX + 0x5b0, bytes(gates))
    q(m, EX + 0x5c0, CH)
    q(m, EX + 0x5c8, chs)
    m.store(EX + 0x8f2, bytes((3,)))
    swiss(w, SUB_CTRL, [k + v for k, v in sorted(links.items())], 0x28, H_SUB >> 57)
    q(m, EX + 0x3810, SUB_CTRL)
    q(m, EX + 0x3818, 31)
    q(m, EX + 0x3828, len(links))
    rows = []
    for k, cls in sorted(users.items()):
        b = bytearray(0x58)
        b[:20] = k
        b[0x18 + 0x3c] = cls
        rows.append(bytes(b))
    swiss(w, USER_CTRL, rows, 0x58, H_USER >> 57)
    q(m, EX + 0x740, USER_CTRL)
    q(m, EX + 0x748, 31)
    q(m, EX + 0x758, len(users))


# subAccountTransfer: 0x1e60d00 -> 0x27148e0

def run_transfer(img, master, sub, usd, deposit, links, users, gates, balance, flag=1, chs=1, start=None):
    w = World(img)
    m = w.m
    exchange(w, links, users, gates, flag, chs)
    w.balance = balance
    for k, (a, b) in (start or {}).items():
        p = w.alloc(0x40)
        w.accounts[k] = p
        q(m, p + 0x10, a)
        q(m, p + 0x18, b)
    m.store(USER, master)
    q(m, ACTION, usd)
    m.store(ACTION + 8, sub)
    m.store(ACTION + 0x1c, bytes((deposit,)))
    res = {}
    try:
        call(w, 0x1e60d00, OUT, ACTION, USER, EX)
    except Panic as e:
        return {'panic': e.args[0], 'loc': e.args[1], 'payload': e.args[2].hex() if len(e.args) > 2 else ''}
    tag = m.load(OUT, 1)[0]
    res['tag'] = tag
    if tag == 14:
        res['code'] = int.from_bytes(m.load(OUT + 8, 2), 'little')
        if res['code'] == 0x13f:
            res['usd'] = rq(m, OUT + 0x10)
        if res['code'] == 0xda:
            res['legs'] = m.load(OUT + 10, 40).hex()
    res['log'] = w.log
    res['events'] = w.events
    res['recorded'] = len(w.recorded)
    res['accounts'] = [(k.hex(), i64(rq(m, p + 0x10)), i64(rq(m, p + 0x18))) for k, p in sorted(w.accounts.items())]
    return res


def add_sat(a, b):
    v = a + b
    return max(I64MIN, min(I64MAX, v)), int(v != max(I64MIN, min(I64MAX, v)))


def model_transfer(master, sub, usd, deposit, links, users, gates, balance, flag=1, chs=1, start=None):
    def gated(u):
        k = users.get(u, 0)
        return k < 3 or gates[0 if k > 3 else 1] != 0
    log = []
    res = {}
    done = {'log': log, 'events': [], 'recorded': 0, 'accounts': sorted((k.hex(), a, b) for k, (a, b) in (start or {}).items())}

    def err(code, **kw):
        return dict(done, tag=14, code=code, **kw)
    if not gated(master) or not gated(sub):
        return err(0x16f)
    if usd >= CUT:
        return err(0x13f, usd=usd)
    if usd == 0:
        return err(0x31)
    src, dst = (master, sub) if deposit else (sub, master)
    if links.get(sub) != master:
        return err(0xda, legs=(src + dst).hex())
    if chs == 0:
        return {'panic': 'unwrap', 'loc': 0x56e9af8, 'payload': (0x141).to_bytes(2, 'little').hex()}
    log.append(('avail', CH, src.hex()))
    if balance < usd:
        return err(0x33)
    log.append(('debit', CH, src.hex(), usd))
    log.append(('credit', CH, dst.hex(), usd))
    hsh = bytes(32)
    if flag == 1:
        log.append(('hash', 3, 0x2222, 0x1111, 0))
        hsh = bytes(range(0x90, 0xb0))
    log.append(('event',))
    ev = (EX + 0x8f3, 2, 2, (master + sub).hex(), (0x0807060504030201).to_bytes(8, 'little').hex() + '090a0b0c', hsh.hex(),
          0x800000000000000e, f2i(float(usd) / 1e6), src.hex(), dst.hex())
    acc = dict((start or {}))
    rec = 0
    step = usd // 10000
    for u, s in ((src, -step), (dst, step)):
        log.append(('account', EX + 0x740, u.hex()))
        a, b = acc.get(u, (0, 0))
        a, r1 = add_sat(a, s)
        b, r2 = add_sat(b, s)
        rec += r1 + r2
        acc[u] = (a, b)
    return {'tag': 13, 'log': log, 'events': [ev], 'recorded': rec, 'accounts': sorted((k.hex(), a, b) for k, (a, b) in acc.items())}


# subAccountModify wrapper: 0x22cdfb0

def run_modify(img, master, sub, name, code, tail):
    w = World(img)
    m = w.m
    w.modify = (code, tail)
    m.store(USER, master)
    if name is None:
        q(m, ACTION, 1 << 63)
    else:
        p = w.alloc(max(len(name), 1))
        m.store(p, name)
        q(m, ACTION, len(name) + 7)
        q(m, ACTION + 8, p)
        q(m, ACTION + 16, len(name))
    m.store(ACTION + 0x18, sub)
    call(w, 0x22cdfb0, OUT, ACTION, USER, EX)
    tag = m.load(OUT, 1)[0]
    return {'tag': tag, 'word': int.from_bytes(m.load(OUT + 8, 2), 'little') if tag == 14 else None,
            'tail': m.load(OUT + 10, len(tail)).hex() if tag == 14 else None, 'log': w.log}


def model_modify(master, sub, name, code, tail):
    arg = None if name is None else (len(name), name.hex(), len(name))
    return {'tag': 13 if code == OK else 14, 'word': None if code == OK else code, 'tail': None if code == OK else tail.hex(),
            'log': [('modify', EX + 0x37e0, master.hex(), arg, sub.hex())]}


# createSubAccount wrapper: 0x27e3140

def run_create(img, case):
    w = World(img)
    m = w.m
    exchange(w, {}, {u: 0 for u in case['users']}, (0, 0))
    w.derive = (case['derive'], case['sub'])
    w.inner = (case['inner'], case['sub'] if case['inner'] == OK else case['payload'][:20], case['payload'][20:])
    w.equity = case['equity']
    w.settings = case['settings']
    m.store(USER, case['master'])
    name = case['name']
    p = w.alloc(max(len(name), 1))
    m.store(p, name)
    q(m, ACTION, len(name) + 3)
    q(m, ACTION + 8, p)
    q(m, ACTION + 16, len(name))
    call(w, 0x27e3140, OUT, ACTION, USER, EX)
    tag = m.load(OUT, 1)[0]
    res = {'tag': tag, 'log': w.log}
    if tag == 6:
        res['sub'] = m.load(OUT + 1, 20).hex()
    else:
        res['word'] = int.from_bytes(m.load(OUT + 8, 2), 'little')
        res['payload'] = m.load(OUT + 10, 20).hex()
    res['copied'] = {k.hex(): (rq(m, p), m.load(p + 8, 0x78).hex()) for k, p in w.setting_rows.items()}
    return res


def words(b):
    return struct.unpack('<15Q', b)


def settings_equal(a, b):
    """The compare in 0x27e3140: f64 words by ==, the u32 at +0x68 decides whether the middle words count."""
    fa, fb = [i2f(x) for x in words(a)], [i2f(x) for x in words(b)]
    if fa[14] != fb[14] or any(fa[i] != fb[i] for i in range(5)):
        return False
    ca, cb = struct.unpack_from('<I', a, 0x68)[0], struct.unpack_from('<I', b, 0x68)[0]
    if ca == 0 or cb == 0:
        return ca == cb
    return all(fa[i] == fb[i] for i in range(5, 13)) and ca == cb


def model_create(c):
    master, sub = c['master'], c['sub']
    log = [('derive', EX + 0x37e0, master.hex())]
    if c['derive'] != OK:
        return {'tag': 14, 'log': log, 'word': c['derive'], 'payload': sub.hex(), 'copied': {}}
    if sub in c['users']:
        return {'tag': 14, 'log': log, 'word': 0xd8, 'payload': sub.hex(), 'copied': {}}
    log.append(('equity', EX, master.hex()))
    n = len(c['name'])
    log.append(('inner', EX + 0x37e0, master.hex(), n, c['name'].hex(), n, c['equity']))
    if c['inner'] != OK:
        return {'tag': 14, 'log': log, 'word': c['inner'], 'payload': c['payload'][:20].hex(), 'copied': {}}
    log.append(('settings', EX + 0x5d0, master.hex()))
    log.append(('settings', EX + 0x5d0, sub.hex()))
    a, b = c['settings'].get(master, bytes(0x78)), c['settings'].get(sub, bytes(0x78))
    copied = {}
    if not settings_equal(a, b):
        log.append(('setting_row', EX + 0x690, sub.hex()))
        copied = {sub.hex(): (1, a.hex())}
    log.append(('account', EX + 0x740, sub.hex()))
    log.append(('second_row', EX + 0x318, sub.hex()))
    return {'tag': 6, 'log': log, 'sub': sub.hex(), 'copied': copied}


# Sub-account address input: 0x3c97900 -> ethabi encode 0x1592160

def run_encode(img, domain, master, count):
    w = World(img)
    m = w.m
    p = w.alloc(max(len(domain), 1))
    m.store(p, domain)
    inp = ACTION
    q(m, inp, len(domain))
    q(m, inp + 8, p)
    q(m, inp + 16, len(domain))
    m.store(inp + 0x18, master)
    q(m, inp + 0x30, count)
    call(w, 0x3c97900, OUT, inp)
    return m.load(rq(m, OUT + 8), rq(m, OUT + 16))


def model_encode(domain, master, count):
    """abi.encode(string, address, uint256) with one dynamic head."""
    pad = (32 - len(domain) % 32) % 32
    return ((0x60).to_bytes(32, 'big') + bytes(12) + master + count.to_bytes(32, 'big') + len(domain).to_bytes(32, 'big')
            + domain + bytes(pad))


TOKEN_TAGS = {0: 'Address', 1: 'FixedBytes', 2: 'Bytes', 3: 'Int', 4: 'Uint', 5: 'Bool', 6: 'String'}


def run_tokens(img, tokens):
    """tokens: (tag, value) rows passed straight to 0x1592160, one 0x28-byte slot each."""
    w = World(img)
    m = w.m
    arr = w.alloc(0x28 * len(tokens) + 8)
    for i, (tag, v) in enumerate(tokens):
        t = arr + i * 0x28
        m.store(t, bytes((tag,)))
        if tag == 0:
            m.store(t + 1, v)
        elif tag == 5:
            m.store(t + 1, bytes((v,)))
        elif tag in (3, 4):
            m.store(t + 8, (v & ((1 << 256) - 1)).to_bytes(32, 'little'))
        else:
            p = w.alloc(max(len(v), 1))
            m.store(p, v)
            q(m, t + 8, len(v))
            q(m, t + 16, p)
            q(m, t + 24, len(v))
    call(w, 0x1592160, OUT, arr, len(tokens))
    return m.load(rq(m, OUT + 8), rq(m, OUT + 16))


def pad(b):
    return b + bytes((32 - len(b) % 32) % 32)


def model_tokens(tokens):
    heads = []
    tails = []
    dyn = sum(1 + (len(v) + 31) // 32 for t, v in tokens if t in (2, 6))
    fixed = sum(1 if t in (0, 3, 4, 5, 2, 6) else (len(v) + 31) // 32 for t, v in tokens)
    off = fixed * 32
    for t, v in tokens:
        if t == 0:
            heads.append(bytes(12) + v)
        elif t == 1:
            heads.append(pad(v))
        elif t in (3, 4):
            heads.append((v & ((1 << 256) - 1)).to_bytes(32, 'big'))
        elif t == 5:
            heads.append(bytes(31) + bytes((v,)))
        else:
            heads.append(off.to_bytes(32, 'big'))
            tail = len(v).to_bytes(32, 'big') + pad(v)
            tails.append(tail)
            off += len(tail)
    assert off == (fixed + dyn) * 32
    return b''.join(heads) + b''.join(tails)


# Deterministic vectors.

class Stream:
    def __init__(self, seed):
        self.seed, self.n, self.buf = seed.encode(), 0, b''

    def u(self, k):
        while len(self.buf) < 8:
            self.buf += hashlib.sha256(self.seed + self.n.to_bytes(8, 'little')).digest()
            self.n += 1
        v = int.from_bytes(self.buf[:8], 'little')
        self.buf = self.buf[8:]
        return v % k

    def pick(self, seq):
        return seq[self.u(len(seq))]


USD = [0, 1, 9999, 10000, 10001, 19999, 1000000, 123456789, CUT - 1, CUT, CUT + 1, 1 << 63, M64]
EDGE = [0, 5, -5, I64MAX, I64MAX - 1, I64MAX - 40000000, I64MIN, I64MIN + 1, I64MIN + 40000000]


def transfer_cases(n):
    s = Stream('transfer')
    for _ in range(n):
        master, sub, other = addr(1), addr(2), addr(3)
        count = s.pick([1, 2, 5, 18])
        links = {sub: master}
        for i in range(count - 1):
            links[addr(10 + i)] = addr(40 + s.u(3))
        r = s.u(12)
        if r == 0:
            links[sub] = other
        elif r == 1:
            del links[sub]
        elif r == 2:
            links = {}
        users = {}
        if s.u(2):
            users[master] = s.pick([0, 1, 2, 3, 4, 5])
        if s.u(2):
            users[sub] = s.pick([0, 1, 2, 3, 4, 5])
        gates = (s.u(2), s.u(2))
        usd = s.pick(USD)
        balance = s.pick([0, 1, usd, max(usd - 1, 0), usd + 1, M64])
        start = {}
        for k in (master, sub):
            if s.u(2):
                start[k] = (s.pick(EDGE), s.pick(EDGE))
        yield master, sub, usd, s.u(2), links, users, gates, balance, s.u(2), 0 if s.u(16) == 0 else 1, start


def settings_bytes(s):
    w = [f2i(s.pick([0.0, 1.0, 0.5, 2.5e-4, math.nan, -0.0])) for _ in range(13)] + [0, f2i(s.pick([0.0, 1.0, 0.9, math.nan]))]
    b = bytearray(struct.pack('<15Q', *w))
    struct.pack_into('<II', b, 0x68, s.pick([0, 0, 1, 2]), 0)
    return bytes(b)


def create_cases(n):
    s = Stream('create')
    for _ in range(n):
        master, sub = addr(5), addr(6)
        users = [master] + [addr(70 + i) for i in range(s.u(4))]
        if s.u(8) == 0:
            users.append(sub)
        a = settings_bytes(s)
        b = a if s.u(2) else settings_bytes(s)
        if s.u(3) == 0:
            c = bytearray(a)
            pos = s.pick([0, 0x20, 0x28, 0x58, 0x60, 0x68, 0x70])
            struct.pack_into('<Q', c, pos, 0x3ff0000000000000 + s.u(9))
            b = bytes(c)
        yield {'master': master, 'sub': sub, 'users': users, 'derive': OK if s.u(16) else 0xd9, 'inner': OK if s.u(3) else s.pick([0xd6, 0xd7, 0xd8, 0xd9, 0xdd, 0x143]),
               'payload': bytes(range(1, 0x57)), 'equity': s.pick([0, 9999999, 10000000, 10 ** 11]), 'name': bytes(97 + i for i in range(s.u(21))),
               'settings': {master: a, sub: b}}


def modify_cases(n):
    s = Stream('sub-modify')
    for _ in range(n):
        name = None if s.u(3) == 0 else bytes(65 + i % 26 for i in range(s.pick([0, 1, 16, 17, 100, 101])))
        yield addr(7), addr(8), name, s.pick([OK, OK, 0xd7, 0xd9, 0xdc, 0x143]), bytes(range(0x40, 0x56))


def encode_cases(n):
    s = Stream('encode')
    dom = b'createSubAccount'
    for i in range(n):
        yield dom if i % 4 else bytes(66 + j % 20 for j in range(s.pick([0, 1, 31, 32, 33, 64, 65]))), addr(s.u(250)), s.pick([0, 1, 9, 10, 49, 50, 255, 256, 1 << 32, M64])


def token_cases(n):
    s = Stream('tokens')
    for i in range(n):
        if i % 6 == 0:
            yield [(6, b'x' * s.pick([1, 17, 31, 32, 33])), (0, addr(1)), (0, addr(2)), (4, s.u(1 << 40)), (4, s.u(1 << 40))]
            continue
        row = []
        for _ in range(1 + s.u(6)):
            t = s.u(7)
            if t == 0:
                row.append((0, addr(s.u(200))))
            elif t == 5:
                row.append((5, s.u(2)))
            elif t in (3, 4):
                row.append((t, s.pick([0, 1, 255, 1 << 63, 1 << 64, (1 << 200) + 5, (1 << 256) - 1])))
            else:
                row.append((t, bytes(65 + j % 26 for j in range(s.pick([0, 1, 31, 32, 33, 64, 65, 96])))))
        yield row


def named_cases(img):
    """Named scenarios that a reader can follow; each row is the observed result of the real bytes."""
    m, sub, x = addr(1), addr(2), addr(3)
    link = {sub: m}
    rows = []

    def tr(name, *a, **k):
        got, want = run_transfer(img, *a, **k), model_transfer(*a, **k)
        rows.append(('transfer', name, got.get('tag', 'panic'), got.get('code', got.get('loc')), json.dumps(got.get('accounts')), 'same' if got == want else 'DIFF'))

    tr('deposit: master pays, sub-account receives', m, sub, 25000, 1, link, {}, (1, 1), 25000)
    tr('withdraw: sub-account pays, master receives', m, sub, 25000, 0, link, {}, (1, 1), 25000)
    tr('balance one below usd: code 51', m, sub, 25000, 1, link, {}, (1, 1), 24999)
    tr('usd 9999: the two sums move 0', m, sub, 9999, 1, link, {}, (1, 1), 9999)
    tr('usd 19999: the two sums move 1', m, sub, 19999, 1, link, {}, (1, 1), 19999)
    tr('zero usd beats the link test', m, x, 0, 1, {}, {}, (1, 1), 0)
    tr('usd at the cut beats zero and link tests', m, x, CUT, 1, {}, {}, (1, 1), 0)
    tr('address linked to another master: code 218', x, sub, 5, 1, link, {}, (1, 1), 5)
    tr('unknown address: code 218, same as another master', m, x, 5, 1, link, {}, (1, 1), 5)
    tr('master class 3, byte 1 zero: code 367', m, sub, 5, 1, link, {m: 3}, (1, 0), 5)
    tr('sub-account class 4, byte 0 zero: code 367', m, sub, 5, 1, link, {sub: 4}, (0, 1), 5)
    tr('class 2 passes with both bytes zero', m, sub, 5, 1, link, {m: 2, sub: 2}, (0, 0), 5)
    tr('no clearinghouse: unwrap panic after the link test', m, sub, 5, 1, link, {}, (1, 1), 5, 1, 0)
    tr('sender sums near i64::MIN saturate, recorder runs', m, sub, 500000000, 1, link, {}, (1, 1), 500000000, 1, 1, {m: (I64MIN + 5, I64MIN + 5)})
    tr('receiver sums near i64::MAX saturate, recorder runs', m, sub, 500000000, 1, link, {}, (1, 1), 500000000, 1, 1, {sub: (I64MAX - 5, I64MAX - 5)})
    tr('flag word 0: 32 zero bytes in the event hash', m, sub, 5, 1, link, {}, (1, 1), 5, 0)
    many = {addr(100 + i): addr(50) for i in range(19)}
    many[sub] = m
    tr('link stored past the first 16 rows: second probe group', m, sub, 5, 1, many, {}, (1, 1), 5)
    tr('master == sub-account linked to itself: no self test in this path', m, m, 5, 1, {m: m}, {}, (1, 1), 5)

    def cr(name, **kw):
        c = dict(master=addr(5), sub=addr(6), users=[addr(5)], derive=OK, inner=OK, payload=bytes(range(1, 0x57)), equity=10 ** 7, name=b'desk', settings={})
        c.update(kw)
        got, want = run_create(img, c), model_create(c)
        rows.append(('create', name, got['tag'], got.get('word', got.get('sub')), json.dumps(sorted(got['copied'])), 'same' if got == want else 'DIFF'))

    plain = bytes(0x78)
    fee = bytearray(0x78)
    struct.pack_into('<d', fee, 0x10, 0.5)
    cr('created, both settings equal: no row written')
    cr('derived address already in the user table: code 216', users=[addr(5), addr(6)])
    cr('inner code copied out with its payload', inner=0xd7)
    cr('settings differ: master copy stored under the sub-account', settings={addr(5): bytes(fee), addr(6): plain})
    nan = bytearray(0x78)
    struct.pack_into('<d', nan, 0x70, math.nan)
    cr('NaN word compares unequal: copy runs on equal bytes', settings={addr(5): bytes(nan), addr(6): bytes(nan)})

    def tk(name, tokens):
        got, want = run_tokens(img, tokens), model_tokens(tokens)
        rows.append(('encode', name, len(tokens), len(got), hashlib.sha256(got).hexdigest(), 'same' if got == want else 'DIFF'))

    tk('withdrawal shape string, address, address, uint, uint: 17-byte literal', [(6, b'x' * 17), (0, m), (0, sub), (4, 7), (4, 9)])
    tk('two dynamic fields: tails follow in token order', [(6, b'ab'), (4, 1), (2, b'c' * 33)])
    tk('empty string: length word only', [(6, b'')])
    tk('FixedBytes of 33 bytes: two head words, right padded, no length word', [(1, b'd' * 33), (5, 1)])
    tk('Int minus one: all 32 bytes ff', [(3, -1)])
    return rows


def evaluate(img, n_transfer=512, n_create=512, n_modify=64, n_encode=96, n_tokens=128):
    counts = {}
    bad = []

    def note(kind, got, want, label):
        key = (kind, str(got.get('panic', got.get('code', got.get('word')))), label)
        counts[key] = counts.get(key, 0) + 1
        if got != want:
            bad.append((kind, got, want))

    for args in transfer_cases(n_transfer):
        got, want = run_transfer(img, *args), model_transfer(*args)
        note('transfer', got, want, f"tag={got.get('tag')}")
    for c in create_cases(n_create):
        got, want = run_create(img, c), model_create(c)
        note('create', got, want, f"tag={got['tag']} copied={len(got['copied'])}")
    for args in modify_cases(n_modify):
        got, want = run_modify(img, *args), model_modify(*args)
        note('modify', got, want, f"tag={got['tag']}")
    for args in encode_cases(n_encode):
        got, want = run_encode(img, *args), model_encode(*args)
        g = {'code': len(got) // 32}
        note('encode', g, g if got == want else {'mismatch': want.hex()}, 'words')
    for tokens in token_cases(n_tokens):
        got, want = run_tokens(img, tokens), model_tokens(tokens)
        g = {'code': len(tokens)}
        note('tokens', g, g if got == want else {'tokens': repr(tokens), 'got': got.hex(), 'want': want.hex()}, 'token count')
    return counts, bad


def check_tables(img):
    rows = []
    for group, va, text, note in PINS:
        i = decode(img.rd, va)
        if i.text() != text:
            raise ValueError(f'pin mismatch at {va:#x}: {i.text()} != {text}')
        rows.append((group, f'{va:#x}', text, note))
    layout = []
    for st, off, width, va, operand, note in LAYOUT_ROWS:
        i = decode(img.rd, va)
        if operand not in i.text():
            raise ValueError(f'layout operand {operand} not at {va:#x}: {i.text()}')
        layout.append((st, f'{off:#x}', str(width), f'{va:#x}', i.text(), note))
    return rows, layout


def fdes(data):
    return sorted((r['start'], r['end']) for r in eh_frame_records(data)[1])


def extent(table, va):
    i = bisect.bisect_right([f[0] for f in table], va) - 1
    return table[i]


def function_rows(img, table):
    rows = []
    for va, role in FUNCS:
        s, e = extent(table, va)
        if s != va:
            raise ValueError(f'{va:#x} is not an FDE start')
        rows.append((f'{s:#x}', f'{e:#x}', str(e - s), hashlib.sha256(img.rd(s, e - s)).hexdigest(), role))
    return rows


def stub_rows(img, table):
    rel = img.relative()
    rows = []
    for va, role in STUBS:
        t = rel.get(va, va)
        s, e = extent(table, t)
        rows.append((f'{va:#x}', 'slot' if va in rel else 'direct', f'{t:#x}', f'{s:#x}', f'{e:#x}', role))
    return rows


def text_body(img):
    text = img.section('.text')
    return text['address'], img.data[text['offset']:text['offset'] + text['size']]


def caller_rows(img, table):
    """Byte census of e8 and ff 15/25 sites that land on a path function or a held sub-account helper."""
    rel = img.relative()
    base, body = text_body(img)
    size = len(body)
    targets = {va for va, _ in FUNCS[:4] + FUNCS[5:6]} | {0x36f3ed0, 0x36f3fe0, 0x36f3610, 0x36f3c20, 0x36f40d0}
    slots = {w for w, t in rel.items() if t in targets}
    rows = set()
    for x in re.finditer(rb'\xe8', body):
        p = x.start()
        if p + 5 > size:
            continue
        t = (base + p + 5 + struct.unpack_from('<i', body, p + 1)[0]) & M64
        if t in targets:
            rows.add((t, base + p, 'call', extent(table, base + p)[0]))
    for x in re.finditer(rb'\xff[\x15\x25]', body):
        p = x.start()
        if p + 6 > size:
            continue
        slot = (base + p + 6 + struct.unpack_from('<i', body, p + 2)[0]) & M64
        if slot in slots:
            rows.add((rel[slot], base + p, 'slot call' if body[p + 1] == 0x15 else 'slot jump', extent(table, base + p)[0]))
    return [(f'{t:#x}', f'{s:#x}', k, f'{f:#x}') for t, s, k, f in sorted(rows)]


def status_rows(img, table):
    """Word stores of the sub-account result codes, found by byte pattern and kept only when the decoder agrees."""
    base, body = text_body(img)
    names = dict(STATUS)
    rows = []
    for x in re.finditer(rb'\x66[\x41\x42\x43]?\xc7', body):
        va = base + x.start()
        try:
            i = decode(img.rd, va)
        except ValueError:
            continue
        if i.op == 'mov' and len(i.args) == 2 and i.args[0][0] == 'm' and i.args[0][5] == 16 and i.args[1][0] == 'i' and i.args[1][1] in names:
            f = extent(table, va)
            if f[0] <= va < f[1]:
                rows.append((str(i.args[1][1]), names[i.args[1][1]], f'{va:#x}', f'{f[0]:#x}', LABELS.get(f[0], '')))
    return sorted(rows, key=lambda r: (int(r[0]), int(r[2], 16)))


def reader_rows(img, table):
    """Inlined reads of sub_account_to_master: cmp qword [reg+0x3828], 0."""
    base, body = text_body(img)
    rows = []
    for x in re.finditer(rb'[\x48\x49]\x83[\xb8-\xbf]\x28\x38\x00\x00\x00', body):
        va = base + x.start()
        i = decode(img.rd, va)
        f = extent(table, va)
        if i.op == 'cmp' and f[0] <= va < f[1]:
            rows.append((f'{va:#x}', f'{f[0]:#x}', i.text(), LABELS.get(f[0], '')))
    return rows


def location_rows(img):
    rel = img.relative()
    rows = []
    for va, role in LOCATIONS:
        p = rel[va]
        n, line, col = struct.unpack('<QII', img.rd(va + 8, 16))
        path = img.rd(p, n).decode()
        for cut in ('code_Mainnet/', '/rustc/'):
            if cut in path:
                path = path.split(cut)[1]
        rows.append((f'{va:#x}', path, str(line), str(col), role))
    return rows


def write_tsv(path, header, rows):
    with open(path, 'w', encoding='ascii', newline='\n') as f:
        f.write('\t'.join(header) + '\n')
        for r in rows:
            f.write('\t'.join(str(x) for x in r) + '\n')


def generate(out):
    data = load()
    img = Image(data)
    out = Path(out)
    out.mkdir(parents=True, exist_ok=True)
    table = fdes(data)
    pins, layout = check_tables(img)
    counts, bad = evaluate(img)
    if bad:
        raise SystemExit(f'{len(bad)} vectors disagree; first {bad[0]}')
    named = named_cases(img)
    if any(r[-1] != 'same' for r in named):
        raise SystemExit(f'named case disagrees: {[r for r in named if r[-1] != "same"][0]}')
    funcs, stubs = function_rows(img, table), stub_rows(img, table)
    callers = caller_rows(img, table)
    status = status_rows(img, table)
    readers = reader_rows(img, table)
    locs = location_rows(img)
    domain = run_encode(img, img.rd(0x2035a0, 16), addr(1), 3)
    write_tsv(out / 'functions.tsv', ('start', 'end', 'bytes', 'sha256', 'role'), funcs)
    write_tsv(out / 'stubs.tsv', ('site', 'kind', 'target', 'fde_start', 'fde_end', 'role'), stubs)
    write_tsv(out / 'callers.tsv', ('function', 'site', 'kind', 'site_fde'), callers)
    write_tsv(out / 'status_sites.tsv', ('code', 'name_from_reference', 'site', 'site_fde', 'label'), status)
    write_tsv(out / 'link_readers.tsv', ('site', 'site_fde', 'instruction', 'label'), readers)
    write_tsv(out / 'pins.tsv', ('group', 'va', 'instruction', 'meaning'), pins)
    write_tsv(out / 'layout.tsv', ('struct', 'offset', 'width', 'va', 'instruction', 'meaning'), layout)
    write_tsv(out / 'locations.tsv', ('record', 'path', 'line', 'column', 'use'), locs)
    write_tsv(out / 'outcomes.tsv', ('action', 'result', 'class', 'vectors'),
              [(k[0], k[1], k[2], v) for k, v in sorted(counts.items())])
    write_tsv(out / 'cases.tsv', ('action', 'scenario', 'tag', 'code_or_panic', 'accounts_or_copied', 'model'), named)
    evidence = {'binary': BINARY, 'sha256': SHA256, 'pins': len(pins), 'layout_rows': len(layout), 'functions': len(funcs),
                'function_bytes': sum(int(r[2]) for r in funcs), 'stubs': len(stubs), 'caller_sites': len(callers), 'status_sites': len(status),
                'link_readers': len(readers), 'link_reader_functions': len({r[1] for r in readers}), 'locations': len(locs),
                'named_cases': len(named), 'vectors': {'transfer': 512, 'create': 512, 'modify': 64, 'encode': 96, 'tokens': 128}, 'vector_disagreements': 0,
                'token_tags': {str(k): v for k, v in sorted(TOKEN_TAGS.items())},
                'distinct_outcomes': len(counts), 'domain_literal': img.rd(0x2035a0, 16).decode(), 'sample_preimage': domain.hex(),
                'constants': {'event_divisor': struct.unpack('<d', img.rd(0x20ae60, 8))[0]}}
    (out / 'evidence.json').write_text(json.dumps(evidence, indent=1, sort_keys=True) + '\n', encoding='ascii')


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--out', required=True)
    generate(ap.parse_args().out)


if __name__ == '__main__':
    main()
