#!/usr/bin/env python3
"""vaults: node #94 subAccountSpotTransfer path and the shared spot transfer core.

This tool reads ELF bytes only.  It decodes pinned instructions with a small fail-closed x86-64 subset
decoder and evaluates the listed function bodies in Python, with their other calls replaced by named
stubs.  Each result and the ordered stub log are compared with a plain model over deterministic vectors.
Nothing from the binary runs.

    python3 tools/vault_subaccount_spot.py --out <dir>
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
       (0, 0x10): 'movups', (0, 0x11): 'movups.st', (0x66, 0x7f): 'movdqa.st', (0xf3, 0x7f): 'movdqu.st', (0, 0x29): 'movaps.st', (0x66, 0x29): 'movapd.st', (0x66, 0x10): 'movupd', (0x66, 0x11): 'movupd.st', (0x66, 0x74): 'pcmpeqb', (0x66, 0xdb): 'pand',
       (0x66, 0xeb): 'por', (0x66, 0x6c): 'punpcklqdq', (0x66, 0x58): 'addpd', (0x66, 0x5e): 'divpd'}


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
        if o2 == 0x7e and pre == 0xf3:
            reg, e = modrm(64)
            return done('movq', ('x', reg | r << 3), fin(e, True))
        if o2 == 0x7e and pre == 0x66:
            reg, e = modrm(64 if w else 32)
            return done('movq.r' if w else 'movd.r', fin(e), ('x', reg | r << 3))
        if o2 == 0xd7 and pre == 0x66:
            reg, e = modrm(128)
            return done('pmovmskb', ('r', reg | r << 3, 32), fin(e, True))
        if o2 == 0x73 and pre == 0x66:
            reg, e = modrm(128)
            if reg != 2:
                raise ValueError(f'0f 73 /{reg} at {va:#x}')
            return done('psrlq', fin(e, True), ('i', imm(1) & 255))
        if o2 == 0xc6 and pre == 0x66:
            reg, e = modrm(128)
            return done('shufpd', ('x', reg | r << 3), fin(e, True), ('i', imm(1) & 255))
        if o2 == 0xd6 and pre == 0x66:
            reg, e = modrm(64)
            return done('movsd.st', ('x', reg | r << 3), fin(e, True))
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
        if reg == 6:
            return done('div', fin(e))
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
        if reg == 6:
            return done('push', fin(e))
        if reg == 4 and e[0] == 'R':
            return done('jmpr', fin(e))
        if reg == 4 and e[0] == 'RIP':
            return done('jmpm', fin(e))
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
    if op == 0x34:
        v = imm(1)
        return done('xor', ('r', 0, 8), ('i', v & 255))
    if op == 0x3c:
        v = imm(1)
        return done('cmp', ('r', 0, 8), ('i', v & 255))
    if op == 0x6a:
        return done('push', ('i', imm(1) & M64))
    if op == 0xd1:
        reg, e = modrm(bits)
        if reg not in (4, 5, 7):
            raise ValueError(f'd1 /{reg} at {va:#x}')
        return done({4: 'shl', 5: 'shr', 7: 'sar'}[reg], fin(e), ('i', 1))
    if op in (0x05, 0x0d, 0x25, 0x2d, 0x35):
        v = imm(4)
        return done(ALU[op & 0xf8], ('r', 0, bits), ('i', v & ((1 << bits) - 1)))
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
                v = self.get(a[0])
                self.r[4] -= 8
                self.store(self.r[4], v.to_bytes(8, 'little'))
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
                res = self.get(a[0]) >> a[1][1]
                self.zf = res == 0
                self.put(a[0], res)
            elif op == 'div':
                bits = a[0][2] if a[0][0] == 'r' else a[0][-1]
                d = self.get(a[0])
                n = self.r[0] & ((1 << bits) - 1) | (self.r[2] & ((1 << bits) - 1)) << bits
                if d == 0 or n // d >> bits:
                    raise Panic('divide error', i.va)
                self.put(('r', 0, bits), n // d)
                self.put(('r', 2, bits), n % d)
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
            elif op == 'jmpm':
                if not self.hook(a[0][1], self):
                    raise ValueError(f'unmodelled jump at {i.va:#x}')
                self.r[4] += 8
                pc = int.from_bytes(self.load(self.r[4] - 8, 8), 'little')
            elif op == 'movsxd':
                self.put(a[0], sx(self.get(a[1]), 32) & M64)
            elif op == 'bswap':
                n = a[0][2] // 8
                self.put(a[0], int.from_bytes(self.get(a[0]).to_bytes(n, 'little'), 'big'))
            elif op[0] == 'j':
                if self.cond(op[1:]):
                    pc = a[0][1]
            elif op == 'call':
                target = self.r[a[0][1]] if a[0][0] == 'r' else self.get(a[0]) if a[0][0] == 'm' else a[0][1]
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
            elif op == 'por':
                u, v = self.x[a[0][1]], self.x128(a[1])
                self.x[a[0][1]] = [u[0] | v[0], u[1] | v[1]]
            elif op == 'punpcklqdq':
                u, v = self.x[a[0][1]], self.x128(a[1])
                self.x[a[0][1]] = [u[0], v[0]]
            elif op == 'psrlq':
                u = self.x[a[0][1]]
                self.x[a[0][1]] = [u[0] >> a[1][1], u[1] >> a[1][1]]
            elif op == 'shufpd':
                u, v = self.x[a[0][1]], self.x128(a[1])
                self.x[a[0][1]] = [u[a[2][1] & 1], v[a[2][1] >> 1 & 1]]
            elif op in ('addpd', 'divpd'):
                u, v = self.x[a[0][1]], self.x128(a[1])
                if op == 'addpd':
                    self.x[a[0][1]] = [f2i(i2f(u[0]) + i2f(v[0])), f2i(i2f(u[1]) + i2f(v[1]))]
                else:
                    self.x[a[0][1]] = [f2i(i2f(u[0]) / i2f(v[0])), f2i(i2f(u[1]) / i2f(v[1]))]
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
    ('handler', 0x1e6442e, 'cmp [rcx+0x3ac8]:8,0x0', 'spot flag at exchange +0x3ac8 read first'),
    ('handler', 0x1e64437, 'mov [rbx+0x8]:16,0xf9', 'status 0xf9 before any account lookup'),
    ('handler', 0x1e6445c, 'call 0x2755400', 'class row of the signer'),
    ('handler', 0x1e64461, 'cmp [rax+0x3c]:8,0x3', 'class byte +0x3c, above 3 and equal to 3 split'),
    ('handler', 0x1e64469, 'cmp [r15+0x5b1]:8,0x0', 'class 3 reads +0x5b1'),
    ('handler', 0x1e64475, 'cmp [r15+0x5b0]:8,0x0', 'class above 3 reads +0x5b0'),
    ('handler', 0x1e6447f, 'mov raxd,[r14+0x40]:32', 'sub-account address at action +0x30'),
    ('handler', 0x1e64496, 'call 0x2755400', 'class row of the sub-account'),
    ('handler', 0x1e6449b, 'cmp [rax+0x3c]:8,0x3', 'same class test for the second address'),
    ('handler', 0x1e644b0, 'mov [rbx+0x8]:16,0x16f', 'status 0x16f'),
    ('handler', 0x1e644b6, 'mov raxb,0xe', 'tag 0xe for every failure'),
    ('handler', 0x1e644df, 'call 0x2717a70', 'sub-account step'),
    ('handler', 0x1e644e4, 'cmp [rsp]:16,0x186', '390 from the step'),
    ('handler', 0x1e644ec, 'mov raxb,0xd', 'tag 0xd'),
    ('map', 0x2717a99, 'cmp [rcx+0x44]:8,0x0', 'is_deposit byte at action +0x44'),
    ('map', 0x2717aa5, 'cmovne rcx,rdx', 'flag set: from is the signer'),
    ('map', 0x2717aa9, 'cmove rax,rdx', 'flag clear: to is the signer'),
    ('map', 0x2717ad0, 'cmp [rsi+0x3828]:64,0x0', 'row count at exchange +0x3828'),
    ('map', 0x2717ad8, 'je 0x2717c06', 'no rows fails at once'),
    ('map', 0x2717af1, 'call 0x399c7a0', 'address hash'),
    ('map', 0x2717afd, 'mov rcx,[r15+0x3810]:64', 'control bytes at +0x3810'),
    ('map', 0x2717b04, 'mov rdx,[r15+0x3818]:64', 'bucket mask at +0x3818'),
    ('map', 0x2717b1d, 'lea rsi,[rcx-0x28]:64', 'row stride 0x28: control minus 0x28'),
    ('map', 0x2717b4f, 'lea r9,[r9+r9*4]:64', 'row index times 5'),
    ('map', 0x2717b53, 'movdqu xmm3,[rsi+r9*8]:128', 'stride 8 on the 5x index'),
    ('map', 0x2717bae, 'movdqu xmm0,[rcx+r9*8-0x14]:128', 'master bytes at row +0x14'),
    ('map', 0x2717bca, 'movdqu xmm1,[r12]:128', 'signer compared with the master'),
    ('map', 0x2717c04, 'je 0x2717c6e', 'equal goes on'),
    ('map', 0x2717c55, 'mov [rbx]:16,0xda', 'status 0xda: from and to in the payload'),
    ('map', 0x2717c94, 'mov r9,[r14+0x10]:64', 'token string length'),
    ('map', 0x2717c98, 'cmp r9,0x65', 'limit: below 0x65'),
    ('map', 0x2717c9e, 'mov [rbx]:16,0x143', 'status 0x143'),
    ('map', 0x2717ca3, 'mov [rbx+0x8]:64,r14', 'pointer word only on the token branch'),
    ('map', 0x2717ca9, 'cmp [r14+0x28]:64,0x65', 'amount string length at action +0x28'),
    ('map', 0x2717cd7, 'mov [rbx]:16,0x143', 'status 0x143, no pointer word'),
    ('map', 0x2717cc8, 'push 0x0', 'Option word 0 on the stack'),
    ('map', 0x2717ccc, 'call 0x2714570', 'parse step'),
    ('parse', 0x2714587, 'cmp [rsi+0x3ac8]:8,0x0', 'spot flag again'),
    ('parse', 0x2714590, 'mov raxw,0xf9', 'status 0xf9'),
    ('parse', 0x27145d3, 'call [0x5774a28]:64', 'token by name through a slot'),
    ('parse', 0x27145db, 'je 0x2714741', 'miss'),
    ('parse', 0x27145fc, 'call [0x57731d8]:64', 'decimal text parse through a slot'),
    ('parse', 0x2714602, 'movzx raxd,[rsp+0x98]:16', 'status of the text parse'),
    ('parse', 0x271460a, 'cmp raxd,0x186', '390'),
    ('parse', 0x2714625, 'cmp r12,[r14+0x218]:64', 'token bound'),
    ('parse', 0x2714639, 'imul3 rcx,r12,0xe8', 'token row stride 0xe8'),
    ('parse', 0x2714640, 'movzx rcxd,[rax+rcx*1+0x49]:8', 'wei decimals at row +0x49'),
    ('parse', 0x2714655, 'mov rdxd,0x1', 'edx 1'),
    ('parse', 0x271465a, 'call [0x5773848]:64', 'decimal to scaled u64'),
    ('parse', 0x27146bb, 'mov [rsp+0xb8]:64,r12', 'record +0x20 token'),
    ('parse', 0x27146c3, 'mov [rsp+0xc0]:64,rdx', 'record +0x28 amount'),
    ('parse', 0x27146cb, 'mov [rsp+0x148]:8,0x0', 'record +0xb0 cleared'),
    ('parse', 0x27146d3, 'mov [rsp+0x98]:64,rcx', 'record +0 Option word'),
    ('parse', 0x27146db, 'mov [rsp+0xa0]:64,rax', 'record +8 value'),
    ('parse', 0x27146e3, 'mov [rsp+0xc8]:64,0x0', 'record +0x30 cleared'),
    ('parse', 0x27146ef, 'mov [rsp+0xa8]:64,0x3', 'record +0x10 kind 3'),
    ('parse', 0x271470b, 'call 0x2712ce0', 'transfer core'),
    ('parse', 0x2714855, 'mov raxw,0xf8', 'status 0xf8, token text cloned'),
    ('spot', 0x1f660ca, 'cmp rdx,0x65', 'dest length gate'),
    ('spot', 0x1f660d0, 'mov [rbx+0x8]:16,0x143', 'status 0x143'),
    ('spot', 0x1f660e3, 'call [0x576e840]:64', 'address text parse'),
    ('spot', 0x1f660f9, 'mov [rbx+0x8]:16,0xb6', 'status 0xb6'),
    ('spot', 0x1f66123, 'mov r9,[r14+0x28]:64', 'token length'),
    ('spot', 0x1f66137, 'cmp [r14+0x40]:64,0x65', 'amount length'),
    ('spot', 0x1f66156, 'push [r14+0x68]:64', 'time pushed'),
    ('spot', 0x1f6615a, 'push 0x1', 'Option word 1'),
    ('core', 0x2712e22, 'mov rcxw,0xf9', 'status 0xf9'),
    ('core', 0x2712e26, 'cmp [r12+0x3ac8]:8,0x0', 'spot flag a third time'),
    ('core', 0x2712e65, 'cmp raxd,0xffff', 'from equal to to'),
    ('core', 0x2712f67, 'mov rcxw,0xde', 'status 0xde'),
    ('core', 0x2712ea2, 'mov rax,[r12+0x8d0]:64', 'vault tree root, exchange +0x8d0'),
    ('core', 0x2712eb8, 'mov rcx,[r12+0x8d8]:64', 'vault tree height'),
    ('core', 0x2712ed4, 'lea rsi,[rax+0x798]:64', 'vault key array +0x798'),
    ('core', 0x2712ee0, 'movzx raxd,[rax+0x876]:16', 'vault node length +0x876'),
    ('core', 0x2712f09, 'mov rdxd,0x14', '20-byte key compare'),
    ('core', 0x2712f5a, 'mov rax,[rax+rbp*8+0x878]:64', 'vault tree edge +0x878'),
    ('core', 0x2712f36, 'jmp 0x27130c7', 'hit fails'),
    ('core', 0x2712f79, 'pcmpeqb xmm0,[0x206610]:128', 'last four bytes against ffffffff'),
    ('core', 0x2712f85, 'pcmpeqb xmm1,[rsp+0xa0]:128', 'first sixteen bytes against 0xff'),
    ('core', 0x2712f9b, 'je 0x27130c7', 'twenty 0xff bytes fail as a vault'),
    ('core', 0x27130c7, 'mov rcxw,0x1c', 'status 0x1c'),
    ('core', 0x2712fa8, 'test [rsp+0x70]:8,0x1', 'record +0xb0 bit 0 skips both block checks'),
    ('core', 0x2712fd7, 'cmp rsi,[r12+0x218]:64', 'token bound'),
    ('core', 0x2712ff4, 'cmp [rax+rcx*1+0x10]:32,0x1', 'token row +0x10 Option tag 1'),
    ('core', 0x2713002, 'mov rdx,[rax+0x18]:64', 'block set root +0x18'),
    ('core', 0x2713012, 'mov rax,[rax+0x20]:64', 'block set height +0x20'),
    ('core', 0x271302a, 'lea rsi,[rcx+0x8]:64', 'block key array +8'),
    ('core', 0x2713033, 'movzx raxd,[rcx+0xe6]:16', 'block node length +0xe6'),
    ('core', 0x2713096, 'jmp 0x27132d8', 'sender hit'),
    ('core', 0x27132d8, 'mov rcxw,0x158', 'status 0x158'),
    ('core', 0x2713142, 'call [0x5774a08]:64', 'destination block test through a slot'),
    ('core', 0x2713148, 'mov rcxw,0x158', 'status 0x158'),
    ('core', 0x2713166, 'add rax,0xfffffffffffffffd', 'kind minus 3'),
    ('core', 0x271316f, 'cmp rax,0x2', 'kinds 3 and 4 only'),
    ('core', 0x271317d, 'call [0x5773198]:64', 'token class word'),
    ('core', 0x2713191, 'mov [rbx]:16,0x15b', 'status 0x15b'),
    ('core', 0x271319b, 'cmp [r12+0x80]:32,0x1', 'state +0x80 tag 1'),
    ('core', 0x27131a6, 'cmp rsi,[r12+0x88]:64', 'special token index +0x88'),
    ('core', 0x27131b0, 'movdqa xmm0,[0x203c60]:128', '0x22 fill'),
    ('core', 0x27131da, 'bswap r15', 'big-endian token index'),
    ('core', 0x27131f4, 'mov [rsp+0x120]:8,0x20', 'first byte 0x20'),
    ('core', 0x2713289, 'call [0x5774a10]:64', 'system range test'),
    ('core', 0x2713292, 'setne rcxb', 'record +0x30 word present'),
    ('core', 0x2713299, 'mov rdxd,0x14a', 'status 0x14a'),
    ('core', 0x271329e, 'mov raxd,0x15b', 'status 0x15b'),
    ('core', 0x27132ba, 'je 0x2713346', 'token 0 to the own system address'),
    ('core', 0x271336b, 'call [0x5773170]:64', 'balance row of the system address'),
    ('core', 0x271337e, 'call [0x5774770]:64', 'three-word read'),
    ('core', 0x2713390, 'add rcx,[rsp+0x10]:64', 'total plus amount'),
    ('core', 0x2713395, 'jb 0x27132aa', 'carry fails'),
    ('core', 0x271339b, 'cmp rcx,[r12+0x3a48]:64', 'USDC limit at exchange +0x3a48'),
    ('core', 0x27133a9, 'cmp [r12+0x31a2]:8,0x0', 'off flag at exchange +0x31a2'),
    ('core', 0x271338c, 'mov raxw,0x26', 'status 0x26'),
    ('core', 0x2713325, 'call 0x27101a0', 'gas quote, sender not the system address'),
    ('core', 0x27133c6, 'call 0x27101a0', 'gas quote, sender is the system address'),
    ('core', 0x27133df, 'cmp [r12+0x758]:64,0x0', 'destination row count at +0x758'),
    ('core', 0x27133f9, 'call 0x2840fb0', 'hash of the unused lookup'),
    ('core', 0x2713490, 'je 0x27134bd', 'a hit goes to the same label'),
    ('core', 0x27134ab, 'jne 0x27134bd', 'a miss goes to the same label'),
    ('core', 0x27134c1, 'mov raxb,0x2', 'route 2'),
    ('core', 0x2713339, 'mov [rsp+0x3c]:32,0x0', 'route 0'),
    ('core', 0x27132c0, 'mov raxb,0x1', 'route 1'),
    ('core', 0x2713516, 'call [0x5774a18]:64', 'free balance test'),
    ('core', 0x271362c, 'mov [rbx]:16,0xf7', 'status 0xf7'),
    ('core', 0x271356a, 'cmp [r12+0x8f2]:8,0x3', 'chain byte 3 skips the map'),
    ('core', 0x2713590, 'cmp [rax+0xbc]:8,0x1', 'token 0 record +0xbc tag'),
    ('core', 0x27135c6, 'cmp raxd,0x1', 'route 1 adds'),
    ('core', 0x27135df, 'call 0x284b9f0', 'map find, sender'),
    ('core', 0x2713603, 'lea rsi,[0x56dfd90]:64', 'overflow location'),
    ('core', 0x2713617, 'mov rax,0xffffffffffffffff', 'saturates'),
    ('core', 0x2713667, 'pmovmskb raxd,xmm0', 'route 0 needs from equal to the EVM word'),
    ('core', 0x27136a5, 'pmovmskb raxd,xmm0', 'route 2 skips when to equals the EVM word'),
    ('core', 0x27136c0, 'call 0x284b9f0', 'map find, destination'),
    ('core', 0x27136cd, 'sub rax,[rsp+0x10]:64', 'checked subtract'),
    ('core', 0x27136d9, 'mov [rbx]:16,0x164', 'status 0x164'),
    ('core', 0x27136de, 'mov [rbx+0x8]:64,0x0', 'payload word 0'),
    ('core', 0x2713743, 'test rbpb,rbpb', 'route 0 charges gas'),
    ('core', 0x27137b2, 'call 0x2711a80', 'gas step'),
    ('core', 0x2713845, 'cmp rbpb,0x2', 'gas class 2 and up'),
    ('core', 0x271386d, 'call 0x270f6f0', 'follow-up step'),
    ('core', 0x27138e7, 'call 0x2711440', 'recipient step'),
    ('core', 0x2713bf3, 'call 0x2715320', 'own system address send'),
    ('core', 0x2713c9d, 'call 0x284c640', 'map insert after the send'),
    ('core', 0x2713cd3, 'call [0x5774730]:64', 'second word raised'),
    ('core', 0x2714011, 'mov [rbx]:16,0xf7', 'status 0xf7'),
    ('core', 0x2713cfa, 'call [0x5774910]:64', 'USDC price of the token'),
    ('core', 0x2713d08, 'cmp [rsp+0x68]:64,0x2', 'kinds 3 and 4 cost word'),
    ('core', 0x2713d14, 'cmovae r13,[rsp+0x260]:64', 'cost selector'),
    ('core', 0x2713d30, 'mov r13,[rsp+0x278]:64', 'kind 2 uses record +0x18'),
    ('core', 0x2713d4a, 'call [0x5774a20]:64', 'USDC value'),
    ('core', 0x2713d56, 'js 0x2714469', 'sign bit panics'),
    ('core', 0x2713d88, 'mov rcxd,0x1', 'ecx 1'),
    ('core', 0x2713d95, 'call 0x371d120', 'debit'),
    ('core', 0x2713da0, 'jae 0x2713ddc', 'tally only for kinds 3 and 4'),
    ('core', 0x2713da5, 'neg rdx', 'negative value'),
    ('core', 0x2713dd7, 'call 0x2712a00', 'tally'),
    ('core', 0x2713ea7, 'call 0x2716f90', 'credit side'),
    ('core', 0x2713f37, 'call 0x2712af0', 'merge'),
    ('core', 0x2713f3c, 'cmp [rsp+0x260]:32,0x3', 'event only for kind 3'),
    ('core', 0x2713f63, 'mov rdid,0x28', 'two addresses'),
    ('core', 0x2713fdd, 'cmp [r14]:32,0x1', 'block hash when state tag is 1'),
    ('core', 0x271427b, 'lea rcx,[0x584b08]:64', 'power of ten table'),
    ('core', 0x27142dc, 'subpd xmm0,[0x204c30]:128', 'u64 to f64'),
    ('core', 0x271432c, 'shufpd xmm2,[0x204900]:128,0x2', '1e6 from the second double'),
    ('core', 0x271433e, 'divpd xmm0,xmm2', 'amount over 10^decimals, value over 1e6'),
    ('core', 0x27142ff, 'cmp [r14+0x78]:8,0x0', 'state +0x78 replaces the word'),
    ('core', 0x2714306, 'mov rcx,[r14+0x50]:64', 'state +0x50'),
    ('core', 0x27143c4, 'mov rax,0x800000000000000f', 'ledger event tag'),
    ('core', 0x27143f6, 'call [0x5774738]:64', 'ledger event'),
    ('core', 0x2714424, 'mov [rbx]:16,0x186', 'status 390'),
    ('sysrange', 0x37e511e, 'pcmpeqb xmm1,[0x203fc0]:128', 'last four bytes of the 0x22 address'),
    ('sysrange', 0x37e5126, 'pcmpeqb xmm0,[0x203c60]:128', 'first sixteen bytes'),
    ('sysrange', 0x37e514e, 'mov [rsp+0xc]:8,0x20', 'first byte 0x20'),
    ('sysrange', 0x37e5171, 'js 0x37e51be', 'below 0x20 00..00 is out'),
    ('sysrange', 0x37e5189, 'mov rax,0xf27000000000000', 'upper bound word'),
    ('sysrange', 0x37e51ad, 'setle raxb', 'at most 0x20 00..27 0f'),
    ('block', 0x375fc3e, 'cmp rdx,[rdi+0x188]:64', 'token bound'),
    ('block', 0x375fc59, 'cmp [rax+rcx*1+0x10]:32,0x1', 'Option tag'),
    ('block', 0x375fc6b, 'test rcx,rcx', 'root'),
    ('debit', 0x371b8aa, 'call [0x5773170]:64', 'balance row through a slot'),
    ('debit', 0x371b8b0, 'mov rcx,[rax+0x10]:64', 'tree root'),
    ('debit', 0x371b8bf, 'movzx rdid,[rcx+0x16a]:16', 'node length +0x16a'),
    ('debit', 0x371b923, 'mov rax,[rcx+r8*1+0x48]:64', 'first word of the value'),
    ('debit', 0x371b928, 'mov rcx,[rcx+r8*1+0x50]:64', 'second word of the value'),
    ('debit', 0x371b933, 'add rbx,rcx', 'amount plus second word'),
    ('debit', 0x371b936, 'cmp rbx,rcx', 'no carry'),
    ('debit', 0x371b93c, 'cmp rbx,rax', 'at most first word'),
    ('raise', 0x371b14e, 'cmp rdx,[rdi+0x198]:64', 'token bound'),
    ('raise', 0x371b15d, 'test rcx,rcx', 'amount 0 returns true'),
    ('raise', 0x371b245, 'mov [rsp+0x8]:16,0xea', 'status 0xea'),
    ('raise', 0x371b26f, 'mov rsi,[rdx+r13*1-0x30]:64', 'row +0x28 tree'),
    ('raise', 0x371b345, 'call 0x33bb560', 'entry'),
    ('raise', 0x371b351, 'add r14,rdx', 'amount plus second word'),
    ('raise', 0x371b359, 'jb 0x371b258', 'carry fails'),
    ('raise', 0x371b35f, 'cmp r14,[rcx]:64', 'above first word fails'),
    ('raise', 0x371b368, 'mov [rcx+0x8]:64,r14', 'second word stored'),
    ('value', 0x371fcc8, 'test rsi,rsi', 'token 0 branch'),
    ('value', 0x371fd5c, 'shr r15,0x2', 'divide by 100'),
    ('value', 0x371fd60, 'mov rcx,0x28f5c28f5c28f5c3', '0x28f5c28f5c28f5c3'),
    ('value', 0x371fce3, 'je 0x371fd7d', 'price 0 gives 0'),
    ('value', 0x371fcf8, 'call [0x57738b0]:64', 'product and divide'),
    ('value', 0x371fd0a, 'cmp rbx,0x1', 'token 1 has no cap'),
    ('value', 0x371fd27, 'cmp [rcx+rdx*1+0x40]:64,0x4', 'name length 4'),
    ('value', 0x371fd3a, 'cmp [rcx]:32,0x45505948', 'HYPE word'),
    ('value', 0x371fd42, 'mov rcx,0x2386f26fc10000', 'cap 1e16'),
    ('merge', 0x2712b07, 'ucomisd xmm0,xmm3', 'first part positive keeps its name'),
    ('merge', 0x2712b5f, 'call [0x57746b8]:64', 'token name for the second part'),
    ('merge', 0x2712b99, 'cmp [rsi]:32,0x45505948', 'HYPE keeps both parts apart'),
    ('merge', 0x2712bb8, 'call [0x576e378]:64', 'name compare'),
    ('merge', 0x2712c26, 'addsd xmm1,xmm2', 'equal names add'),
    ('merge', 0x2712c0a, 'movupd xmm0,[r14]:128', 'second name replaces an empty first'),
    ('credit', 0x2716fc9, 'cmp [rsi+0x10]:8,0x2', 'route 2 and up'),
    ('credit', 0x2716fd3, 'mov r15,[rsi+0x18]:64', 'record +0x18 gas quote'),
    ('credit', 0x2716fd7, 'test [rsi+0x20]:8,0x1', 'record +0x20 bit 0'),
    ('credit', 0x271702b, 'mov [rax+0x3d]:8,0x1', 'row byte +0x3d set'),
    ('credit', 0x2717040, 'mov rax,[rbx+0x2e0]:64', 'gas tree at state +0x2e0'),
    ('credit', 0x2717057, 'movzx rsid,[rax+0x62]:16', 'gas node length +0x62'),
    ('credit', 0x27170a9, 'mov rax,[rax+rdx*8+0x70]:64', 'gas node edge +0x70'),
    ('credit', 0x2717271, 'cmp [rax+rdx*1+0x64]:8,0x1', 'gas node byte +0x64'),
    ('credit', 0x2717278, 'mov rbpw,0xfb', 'status 0xfb'),
    ('credit', 0x271727c, 'cmp [rbx+0x80]:8,0x0', 'state +0x80 tag byte'),
    ('credit', 0x2717289, 'mov rbpw,0xea', 'status 0xea'),
    ('credit', 0x271728d, 'cmp r14,[rbx+0x88]:64', 'special token only'),
    ('credit', 0x27172ad, 'mov rbpw,0x160', 'status 0x160'),
    ('credit', 0x27172c0, 'call [0x5774548]:64', 'gas price'),
    ('credit', 0x27172c6, 'mov rbpw,0x13f', 'status 0x13f'),
    ('credit', 0x27172ca, 'mov rcx,0x68db8bac710cb', '100x gate 0x68db8bac710cb'),
    ('credit', 0x27172d9, 'imul3 rdi,r15,0x64', 'gas times 100'),
    ('credit', 0x27172ea, 'call 0x333e310', 'token amount of the value'),
    ('credit', 0x27172fd, 'cmp rdx,r8', 'fee at or above the amount'),
    ('credit', 0x2717302, 'mov [rsp+0x8]:64,rdx', 'fee kept'),
    ('credit', 0x2717333, 'call [0x5774a48]:64', 'sink'),
    ('credit', 0x27170d9, 'call 0x371d120', 'credit, ecx 0'),
    ('credit', 0x2717138, 'mov rax,rbx', 'value / 10000 added to row +0x10'),
    ('credit', 0x271716a, 'call 0x2716bc0', 'post-credit step'),
    ('credit', 0x27171ad, 'call [0x5774730]:64', 'raise on the receiver'),
    ('credit', 0x27171ec, 'call 0x371d120', 'debit of the fee'),
    ('credit', 0x2717342, 'shr r13,0x2', 'token 0 divides by 100'),
    ('credit', 0x27173ad, 'cmovae r15,rax', 'cap 1e16'),
    ('credit', 0x27173f9, 'add rax,rdx', 'fee value / 10000 subtracted'),
    ('credit', 0x2717537, 'mov rax,0x8000000000000012', 'event tag 0x8000000000000012'),
    ('credit', 0x2717566, 'lea rax,[rbx+0x420]:64', 'token total at state +0x420'),
    ('credit', 0x2717584, 'movzx rdid,[rcx+0xba]:16', 'total node length +0xba'),
    ('credit', 0x27175d6, 'mov rcx,[rcx+rsi*8+0xc0]:64', 'total node edge +0xc0'),
    ('credit', 0x2717633, 'mov [rax]:64,rcx', 'total plus fee'),
    ('credit', 0x2717656, 'divsd xmm0,[r12+rax*8]:64', 'fee in token units returned in xmm0'),
    ('callers', 0x1e5fdd5, 'mov [rsp+0x90]:64,0x3', 'kind 3 at 0x1e5fcf0'),
    ('callers', 0x235d17b, 'mov [rsp+0x140]:64,0x3', 'kind 3 at 0x2355f40'),
    ('callers', 0x27199b2, 'xor raxd,raxd', 'kind 0 at 0x27196e0'),
    ('callers', 0x27199b8, 'mov raxd,0x2', 'kind 2 at 0x27196e0'),
    ('callers', 0x27199c2, 'mov raxd,0x1', 'kind 1 at 0x27196e0'),
    ('callers', 0x2719a1b, 'mov [rsp+0x50]:64,rax', 'kind word at 0x27196e0'),
    ('callers', 0x2719a20, 'mov [rsp+0x58]:64,rdx', 'word +0x18 at 0x27196e0'),
    ('callers', 0x272c154, 'mov [rsp+0x340]:64,0x4', 'kind 4 at 0x272bd60'),
    ('callers', 0x275121e, 'mov [rsp+0xd0]:64,0x3', 'kind 3 at 0x2750e60'),
    ('callers', 0x27511e4, 'mov [rsp+0x170]:8,0x1', 'record +0xb0 = 1 at 0x2750e60, the one caller that skips the block set'),
    ('callers', 0x27511f4, 'movups.st xmm0,[rsp+0x171]:128', 'twenty bytes at record +0xb1'),
    ('callers', 0x2751206, 'mov [rsp+0xc0]:64,0x0', 'Option word 0'),
]
LAYOUT_ROWS = [
    ('action', 0x10, 8, 0x2717c94, '[r14+0x10]:64', 'token string length'),
    ('action', 0x28, 8, 0x2717ca9, '[r14+0x28]:64', 'amount string length'),
    ('action', 0x44, 1, 0x2717a99, '[rcx+0x44]:8', 'is_deposit'),
    ('action', 0x30, 16, 0x2717a90, '[rcx+0x30]:128', 'sub-account address'),
    ('exchange', 0x3ac8, 1, 0x1e6442e, '[rcx+0x3ac8]:8', 'spot disabled'),
    ('exchange', 0x5b1, 1, 0x1e64469, '[r15+0x5b1]:8', 'class 3 allowed'),
    ('exchange', 0x5b0, 1, 0x1e64475, '[r15+0x5b0]:8', 'class above 3 allowed'),
    ('exchange', 0x3828, 8, 0x2717ad0, '[rsi+0x3828]:64', 'sub-account rows'),
    ('exchange', 0x3810, 8, 0x2717afd, '[r15+0x3810]:64', 'sub-account control bytes'),
    ('exchange', 0x3818, 8, 0x2717b04, '[r15+0x3818]:64', 'sub-account mask'),
    ('exchange', 0x8d0, 8, 0x2712ea2, '[r12+0x8d0]:64', 'vault tree root'),
    ('exchange', 0x8d8, 8, 0x2712eb8, '[r12+0x8d8]:64', 'vault tree height'),
    ('exchange', 0x218, 8, 0x2712fd7, '[r12+0x218]:64', 'token count'),
    ('exchange', 0x210, 8, 0x2712fe5, '[r12+0x210]:64', 'token rows'),
    ('exchange', 0x80, 4, 0x271319b, '[r12+0x80]:32', 'special token tag'),
    ('exchange', 0x88, 8, 0x27131a6, '[r12+0x88]:64', 'special token index'),
    ('exchange', 0x3a48, 8, 0x271339b, '[r12+0x3a48]:64', 'USDC into EVM limit'),
    ('exchange', 0x31a2, 1, 0x27133a9, '[r12+0x31a2]:8', 'USDC into EVM off'),
    ('exchange', 0x8f2, 1, 0x271356a, '[r12+0x8f2]:8', 'chain byte'),
    ('exchange', 0x2e0, 8, 0x2717040, '[rbx+0x2e0]:64', 'gas tree root'),
    ('exchange', 0x2e8, 8, 0x2717050, '[rbx+0x2e8]:64', 'gas tree height'),
    ('exchange', 0x420, 8, 0x271756d, '[rbx+0x420]:64', 'token fee total root'),
    ('exchange', 0x428, 8, 0x271757d, '[rbx+0x428]:64', 'token fee total height'),
    ('record', 0x10, 8, 0x2712dcc, '[r13+0x10]:64', 'kind'),
    ('record', 0x18, 8, 0x2712dd8, '[r13+0x18]:64', 'word used by kind 2'),
    ('record', 0xb0, 1, 0x2712d34, '[r13+0xb0]:8', 'skip block checks in bit 0'),
    ('transfer_core_record', 0x88, 16, 0x2712d04, '[rdx+0x88]:128', 'from'),
]
GATES = [
    ('1', 'handler', '249', '0x1e64437', 'mov [rbx+0x8]:16,0xf9', 'exchange +0x3ac8 nonzero'),
    ('2', 'handler', '367', '0x1e644b0', 'mov [rbx+0x8]:16,0x16f', 'signer class 3 with +0x5b1 clear or above 3 with +0x5b0 clear'),
    ('3', 'handler', '367', '0x1e644b0', 'mov [rbx+0x8]:16,0x16f', 'sub-account same test'),
    ('4', 'map', '218', '0x2717c55', 'mov [rbx]:16,0xda', 'no row, or row master differs from the signer'),
    ('5', 'map', '323', '0x2717c9e', 'mov [rbx]:16,0x143', 'token text at or above 101 bytes'),
    ('6', 'map', '323', '0x2717cd7', 'mov [rbx]:16,0x143', 'amount text at or above 101 bytes'),
    ('7', 'parse', '249', '0x2714590', 'mov raxw,0xf9', 'exchange +0x3ac8 nonzero'),
    ('8', 'parse', '248', '0x2714855', 'mov raxw,0xf8', 'no token of that name'),
    ('9', 'parse', 'text', '0x2714602', 'movzx raxd,[rsp+0x98]:16', 'status of the decimal text parse'),
    ('10', 'parse', 'text', '0x2714660', 'movzx raxd,[rsp+0x98]:16', 'status of the scale step'),
    ('11', 'core', '249', '0x2712e22', 'mov rcxw,0xf9', 'exchange +0x3ac8 nonzero'),
    ('12', 'core', '222', '0x2712f67', 'mov rcxw,0xde', 'from equals to'),
    ('13', 'core', '28', '0x27130c7', 'mov rcxw,0x1c', 'to is in the vault tree or is twenty 0xff bytes'),
    ('14', 'core', '344', '0x27132d8', 'mov rcxw,0x158', 'from in the token block set'),
    ('15', 'core', '344', '0x2713148', 'mov rcxw,0x158', 'to in the token block set'),
    ('16', 'core', '347', '0x2713191', 'mov [rbx]:16,0x15b', 'kinds 3 and 4: token class word nonzero'),
    ('17', 'core', '330', '0x2713299', 'mov rdxd,0x14a', 'to is another system address'),
    ('18', 'core', '347', '0x271329e', 'mov raxd,0x15b', 'record payload with a user destination'),
    ('19', 'core', '38', '0x271338c', 'mov raxw,0x26', 'token 0 into its system address: over limit, carry or off flag'),
    ('20', 'core', '247', '0x271362c', 'mov [rbx]:16,0xf7', 'free balance short'),
    ('21', 'core', '356', '0x27136d9', 'mov [rbx]:16,0x164', 'map value short on a USDC leave'),
    ('22', 'core', 'stub', '0x27139d7', 'movzx rcxd,[rsp+0x166]:16', 'gas step status'),
    ('23', 'core', 'stub', '0x2714183', 'movzx rcxd,[rsp+0x166]:16', 'follow-up status'),
    ('24', 'core', 'stub', '0x27140ce', 'mov rcx,[rsp+0xb0]:64', 'recipient status'),
    ('25', 'core', 'stub', '0x2714051', 'movzx rcxd,[rsp+0xa6]:16', 'system send status'),
    ('26', 'core', '247', '0x2714011', 'mov [rbx]:16,0xf7', 'second word raise fails'),
]


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
    """Byte census of e8 and ff 15/25 sites that land on a path function."""
    rel = img.relative()
    base, body = text_body(img)
    size = len(body)
    targets = {va for va, _ in FUNCS[:5]}
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



OK = 390
SENT = 0x10
SP = 0x7f00000
HEAP = 0x8000000
EX = 0x7900000
OUT = 0x7820000
ACT = 0x7830000
KEYS = 0x7840000
ERRFN = 0x7fff0
FF = b'\xff' * 20
TWOS = b'\x22' * 20
LOW = b'\x20' + bytes(19)
HIGH = b'\x20' + bytes(17) + b'\x27\x0f'
HYPE = b'HYPE'
BLOCK_TREE = dict(key=8, key_len=20, val=0, val_len=0, len=0xe6, edge=0xe8, parent=0, pidx=0xe4, size=0x150)
GAS_TREE = dict(key=8, key_len=8, val=0x64, val_len=1, len=0x62, edge=0x70, parent=0, pidx=0x60, size=0xd0)
FEE_TREE = dict(key=8, key_len=8, val=0, val_len=0, len=0xba, edge=0xc0, parent=0, pidx=0xb8, size=0x120)
VAULT_TREE = dict(key=0x798, key_len=20, val=0, val_len=0xb0, len=0x876, edge=0x878, parent=0x790, pidx=0x874, size=0x8e0)
TOKEN_TREE = dict(key=8, key_len=8, val=0x60, val_len=0x18, len=0x16a, edge=0x170, parent=0, pidx=0x168, size=0x1d0)
FUNCS = [(0x1e64420, 'subAccountSpotTransfer handler, arm 148: spot flag and two class gates'),
         (0x2717a70, 'sub-account map check and two length gates'),
         (0x2714570, 'token and amount parse into the transfer record'),
         (0x2712ce0, 'shared spot transfer core'),
         (0x1f66070, 'spotSend handler, arm 144, second caller of the parse step'),
         (0x375fc30, 'destination test against the token block set'),
         (0x37e5110, 'system address range test'),
         (0x371b8a0, 'free balance test: second word plus amount at most first word'),
         (0x3724e80, 'three-word token row read'),
         (0x371b140, 'raises the second word of the sender token row'),
         (0x371fcc0, 'USDC value of an amount'),
         (0x2712af0, 'merge of the two labelled fee parts'),
         (0x2716f90, 'credit side: gas taken from a receiver of a system address send')]
STUBS = [(0x2755400, 'account class row lookup, 35 callers'), (0x399c7a0, 'address hash, 255 callers'), (0x2840fb0, 'address hash of the unused destination lookup'),
         (0x5774a28, 'token by name'), (0x57731d8, 'decimal string parse'), (0x5773848, 'Decimal to scaled u64, open PR #94'),
         (0x5773198, 'token class word, evaluated by open PR #475'), (0x5773170, 'balance row, 0x371b3a0'),
         (0x5774910, 'USDC price of a token, 0x371cf40'), (0x57738b0, 'product and divide'), (0x371d120, 'ledger update, 65 callers'),
         (0x2712a00, 'USDC volume tally, open PR #38'), (0x27101a0, 'gas quote, open PR #438'), (0x2711a80, 'gas charge step'),
         (0x270f6f0, 'follow-up of gas class 2 and up'), (0x2711440, 'recipient side after gas'), (0x2715320, 'send into a system address'),
         (0x1f849b0, 'per-address row at state +0x740, 30 callers'), (0x5774548, 'gas price of a token'), (0x333e310, 'token amount of a USDC value, open PR #910'),
         (0x277eba0, 'status drop'), (0x2716bc0, 'post-credit step'), (0x5774a48, 'sink for an amount that is not credited'), (0x2878f60, 'token total entry at state +0x420'), (0x284b9f0, 'map find, evaluated by open PR #567'), (0x284c640, 'map insert'),
         (0x33bb560, 'token row entry'), (0x5773788, 'balance map reserve'), (0x57746b8, 'token name'), (0x3987cb0, 'event hash, 114 callers'),
         (0x576e0d0, 'string clone'), (0x5774738, 'ledger event record'), (0x576e840, 'address text parse'), (0x5773190, 'overflow recorder'),
         (0x576e378, 'memory compare'), (0x576e488, 'memory compare'), (0x576dfd8, 'allocate'), (0x576e010, 'free'), (0x576dfe0, 'memory copy'),
         (0x576dfb8, 'allocation failure'), (0x576e020, 'allocation failure'), (0x576e048, 'unwrap panic'), (0x576e470, 'index panic')]
LOCATIONS = [(0x56c7388, 'unwrap of the USDC value in the core'), (0x56dfd90, 'saturating add of the map value'), (0x56f21f0, 'token index bound'), (0x5715ef8, 'volume tally add')]
REAL = {0x5774a08: 0x375fc30, 0x5774a10: 0x37e5110, 0x5774770: 0x3724e80, 0x5774a18: 0x371b8a0, 0x5774730: 0x371b140, 0x5774a20: 0x371fcc0}
for t, _ in FUNCS:
    REAL[t] = t


class World:
    """One fixture: a Machine, its bump heap and the named stubs.  Every stub adds a row to self.log."""

    def __init__(self, img, c):
        self.img, self.c = img, c
        self.m = Machine(img.rd, img.rd, self.hook)
        self.m.cache = img.cache
        self.m.real_map = dict(REAL)
        self.m.r[4] = SP
        self.heap = HEAP
        self.log = []
        self.rdx = None
        self.xmm0 = None
        self.entry_ptr = None
        self.fee_ptr = None
        self.addr_rows = {}
        self.stubs = {0x2755400: self.profile, 0x399c7a0: self.hash, 0x2840fb0: self.hash, 0x5774a28: self.token_by_name, 0x57731d8: self.parse, 0x5773848: self.scale,
                      0x5773198: self.klass, 0x5773170: self.book, 0x5774910: self.price, 0x57738b0: self.muldiv, 0x371d120: self.apply, 0x2712a00: self.tally,
                      0x27101a0: self.gas, 0x2711a80: self.gas_step, 0x270f6f0: self.gas_follow, 0x2711440: self.recipient, 0x2715320: self.into_system,
                      0x1f849b0: self.row, 0x5774548: self.fee_price, 0x333e310: self.fee_quote, 0x277eba0: self.status, 0x2716bc0: self.after_credit, 0x5774a48: self.sink, 0x2878f60: self.fee_row,
                      0x284b9f0: self.map_get, 0x284c640: self.map_put, 0x33bb560: self.entry, 0x5773788: self.reserve, 0x57746b8: self.name, 0x3987cb0: self.event_hash,
                      0x576e0d0: self.clone, 0x5774738: self.event, 0x576e840: self.addr_parse, 0x5773190: self.recorder, 0x576e378: self.memcmp, 0x576e488: self.memcmp,
                      0x576dfd8: self.malloc, 0x576e010: lambda *a: 0, 0x576dfe0: self.memcpy, 0x576dfb8: self.alloc_fail, 0x576e020: self.alloc_fail,
                      0x576e048: self.panic_unwrap, 0x576e470: self.panic_rdi, ERRFN: lambda *a: 0}
        q(self.m, 0x576e488, 0x576e488)
        q(self.m, 0x5786348, 0)
        self.m.store(0x5786308, bytes(0x40))

    def alloc(self, n):
        a = self.heap
        self.heap += (n + 63) & ~15
        self.m.store(a, bytes(n))
        return a

    def hook(self, target, m):
        f = self.stubs.get(target)
        if f is None:
            return False
        self.rdx = self.xmm0 = None
        ret = f(m, m.r[7], m.r[6], m.r[2], m.r[1], m.r[8], m.r[9])
        for i in (1, 2, 6, 7, 8, 9, 10, 11):
            m.r[i] = 0xdead0000dead0000
        for i in range(16):
            m.x[i] = [0x7ff8dead00000000, 0x7ff8dead00000000]
        m.r[0] = (ret or 0) & M64
        if self.rdx is not None:
            m.r[2] = self.rdx
        if self.xmm0 is not None:
            m.x[0] = [self.xmm0, 0]
        return True

    def text(self, p, n):
        return self.m.load(p, n)

    def profile(self, m, ex, key, *_):
        k = m.load(key, 20)
        self.log.append(('profile', k.hex()))
        p = self.alloc(0x48)
        m.store(p + 0x3c, bytes((self.c['classes'].get(k, 0),)))
        return p

    def hash(self, m, st, key, *_):
        return swiss_hash(m.load(key, 20))

    def token_by_name(self, m, p, n, *_):
        s = m.load(p, n)
        self.log.append(('token', s.decode('latin-1')))
        i = next((i for i, t in enumerate(self.c['tokens']) if t['name'] == s), None)
        self.rdx = i or 0
        return int(i is not None)

    def parse(self, m, out, p, n, *_):
        self.log.append(('parse', m.load(p, n).decode('latin-1')))
        m.store(out, bytes(0x60))
        st = self.c.get('parse_status', OK)
        m.store(out, st.to_bytes(2, 'little'))
        if st == OK:
            m.store(out + 4, b'decimal-bytes-16')
        else:
            m.store(out + 2, err_pattern(st)[2:0x60])

    def scale(self, m, out, dec, flag, decimals, *_):
        self.log.append(('scale', m.load(dec, 16).decode(), flag & 0xffffffff, decimals & 255))
        m.store(out, bytes(0x60))
        st = self.c.get('scale_status', OK)
        m.store(out, st.to_bytes(2, 'little'))
        if st == OK:
            q(m, out + 8, self.c['wei'])
        else:
            m.store(out + 2, err_pattern(st)[2:0x60])

    def klass(self, m, meta, token, *_):
        self.log.append(('class', token))
        return self.c.get('klass', 0)

    def book(self, m, st, key, *_):
        k = m.load(key, 20)
        self.log.append(('book', k.hex()))
        return self.rows[k] + 0x18 if k in self.rows else 0x5786308

    def price(self, m, st, token, *_):
        self.log.append(('price', token))
        return self.c.get('price', 0)

    def muldiv(self, m, wei, token, price, flag, *_):
        self.log.append(('muldiv', wei, token, price))
        self.rdx = self.c.get('usd', (0, 0))[1]
        return self.c.get('usd', (0, 0))[0]

    def apply(self, m, st, key, token, one, wei, cost):
        self.log.append(('apply', m.load(key, 20).hex(), token, one, wei, cost))

    def tally(self, m, ex, key, value, flag, other, *_):
        self.log.append(('tally', m.load(key, 20).hex(), value, flag & 255, other))

    def gas(self, m, ex, a, b, *_):
        self.log.append(('gas', m.load(a, 20).hex(), m.load(b, 20).hex()))
        g = self.c.get('gas', (0, 0))
        self.rdx = g[1]
        return g[0]

    def gas_step(self, m, out, ex, a, amount, flag, wei):
        token = rq(m, m.r[4])
        self.log.append(('gas_step', m.load(a, 20).hex(), amount, flag & 255, wei, token))
        st = self.c.get('gas_status', OK)
        if st != OK:
            m.store(out, err_pattern(st)[:0x60])
            m.store(out, st.to_bytes(2, 'little'))
            return
        g = self.c.get('gas_class', (0, 0, 0, 0))
        m.store(out, bytes(0x60))
        m.store(out, OK.to_bytes(2, 'little'))
        m.store(out + 8, bytes((g[0],)) + b'\x31\x32\x33\x34\x35\x36\x37')
        q(m, out + 0x10, g[1])
        q(m, out + 0x18, 0x1111)
        q(m, out + 0x20, 0x2222)
        m.store(out + 0x28, bytes((g[2],)))

    def gas_follow(self, m, out, ex, a, key, flag, *_):
        self.log.append(('gas_follow', a, m.load(key, 20).hex(), flag & 255))
        st = self.c.get('follow_status', OK)
        if st != OK:
            m.store(out, err_pattern(st)[:0x60])
            m.store(out, st.to_bytes(2, 'little'))
            return
        m.store(out, OK.to_bytes(2, 'little'))

    def recipient(self, m, out, ex, a, b, rec, flag):
        self.log.append(('recipient', m.load(a, 20).hex(), m.load(b, 20).hex(), m.load(rec, 8).hex(), rq(m, rec + 8), rq(m, rec + 0x10), rq(m, rec + 0x18), flag & 255))
        st = self.c.get('recipient_status', OK)
        if st != OK:
            m.store(out, err_pattern(st)[:0x60])
            m.store(out, st.to_bytes(2, 'little'))
            return
        s = self.c.get('gas_name', b'USDC')
        p = self.alloc(max(1, len(s)))
        m.store(p, s)
        m.store(out, OK.to_bytes(2, 'little'))
        q(m, out + 8, f2i(self.c.get('gas_part', 0.0)))
        q(m, out + 0x10, len(s))
        q(m, out + 0x18, p)
        q(m, out + 0x20, len(s))

    def into_system(self, m, out, ex, rec, *_):
        self.log.append(('into_system', rq(m, rec), rq(m, rec + 8), m.load(rec + 0x68, 20).hex(), m.load(rec + 0x7c, 20).hex(), m.load(rec + 0x90, 20).hex(), m.load(rec + 0xa4, 1)[0],
                         int(rq(m, rec + 0x10) != 0), rq(m, rec + 0x18), rq(m, rec + 0x20), m.load(rec + 0xa5, 20).hex()))
        st = self.c.get('system_status', OK)
        if st != OK:
            m.store(out, err_pattern(st)[:0x60])
            m.store(out, st.to_bytes(2, 'little'))
            return
        s = self.c.get('system_name', b'')
        p = self.alloc(max(1, len(s)))
        m.store(p, s)
        m.store(out, OK.to_bytes(2, 'little'))
        q(m, out + 8, f2i(self.c.get('system_part', 0.0)))
        q(m, out + 0x10, len(s))
        q(m, out + 0x18, p)
        q(m, out + 0x20, len(s))

    def row(self, m, mp, key, *_):
        k = m.load(key, 20)
        self.log.append(('row', k.hex()))
        if k not in self.addr_rows:
            p = self.alloc(0x48)
            q(m, p + 0x10, self.c.get('rows', {}).get(k, 0))
            self.addr_rows[k] = p
        return self.addr_rows[k]

    def fee_price(self, m, meta, token, *_):
        self.log.append(('fee_price', token))
        return self.c.get('fee_price', 0)

    def fee_quote(self, m, value, token, price, flag, meta, *_):
        self.log.append(('fee_quote', value, token, price, flag & 0xffffffff))
        ok, v = self.c.get('fee_quote', (0, 0))
        self.rdx = v
        return ok

    def status(self, m, p, *_):
        self.log.append(('status', int.from_bytes(m.load(p, 2), 'little')))

    def after_credit(self, m, ex, key, *_):
        self.log.append(('after_credit', m.load(key, 20).hex()))

    def sink(self, m, st, key, token, wei, *_):
        self.log.append(('sink', m.load(key, 20).hex(), token, wei))

    def fee_row(self, m, h, *_):
        self.log.append(('fee_row', int(rq(m, h) == 0)))
        p = self.alloc(8)
        q(m, p, self.c.get('fee_total', {}).get(self.c['token'], 0))
        self.fee_ptr = p
        return p

    def map_get(self, m, mp, key, *_):
        k = m.load(key, 20)
        self.log.append(('map_get', k.hex()))
        if k not in self.c.get('map', {}):
            return 0
        p = self.alloc(8)
        q(m, p, self.c['map'][k])
        return p

    def map_put(self, m, mp, key, value, *_):
        self.log.append(('map_put', m.load(key, 20).hex(), value))

    def entry(self, m, h, *_):
        self.entry_ptr = rq(m, h + 8) + 0x60 + rq(m, h + 0x18) * 0x18 if rq(m, h) == 0 else self.alloc(0x18)
        return self.entry_ptr

    def reserve(self, m, *_):
        self.log.append(('reserve',))

    def name(self, m, out, token, *_):
        self.log.append(('name', token))
        s = self.c['tokens'][token]['name']
        p = self.alloc(max(1, len(s)))
        m.store(p, s)
        q(m, out, len(s) + 1)
        q(m, out + 8, p)
        q(m, out + 16, len(s))

    def event_hash(self, m, out, chain, tx, block, flag, *_):
        self.log.append(('event_hash', chain & 255, tx, block, flag & 255))
        m.store(out, b'hash-32-bytes-of-the-fixture-tx!')

    def clone(self, m, out, src, *_):
        n = rq(m, src + 16)
        p = self.alloc(max(1, n))
        m.store(p, m.load(rq(m, src + 8), n))
        q(m, out, n)
        q(m, out + 8, p)
        q(m, out + 16, n)

    def event(self, m, rec, users, stamp, hsh, ev, *_):
        p, n = rq(m, users + 8), rq(m, users + 16)
        if rq(m, ev) == 0x8000000000000012:
            self.log.append(('fee_event', rec - EX, rq(m, users), n, m.load(p, n * 20).hex(), m.load(stamp, 12).hex(), m.load(hsh, 8).hex(),
                             m.load(rq(m, ev + 0x10), rq(m, ev + 0x18)).decode('latin-1'), i2f(rq(m, ev + 0x20))))
            return
        self.log.append(('event', rec - EX, rq(m, users), n, m.load(p, n * 20).hex(), m.load(stamp, 12).hex(), m.load(hsh, 8).hex(), rq(m, ev), rq(m, ev + 8), rq(m, ev + 0x10),
                         m.load(rq(m, ev + 0x20), rq(m, ev + 0x28)).decode('latin-1'), m.load(rq(m, ev + 0x38), rq(m, ev + 0x40)).decode('latin-1'),
                         i2f(rq(m, ev + 0x48)), i2f(rq(m, ev + 0x50)), rq(m, ev + 0x58), rq(m, ev + 0x60), m.load(ev + 0x68, 20).hex(), m.load(ev + 0x7c, 20).hex()))

    def addr_parse(self, m, out, p, n, *_):
        self.log.append(('addr_parse', m.load(p, n).decode('latin-1')))
        d = self.c.get('dest')
        if d is None:
            obj = self.alloc(16)
            vt = self.alloc(16)
            q(m, obj, vt)
            q(m, vt, ERRFN)
            m.store(out, b'\x01')
            q(m, out + 8, obj)
        else:
            m.store(out, b'\0' + d)

    def recorder(self, m, a, b, *_):
        self.log.append(('recorder', a, b))

    def memcmp(self, m, a, b, n, *_):
        x, y = m.load(a, n), m.load(b, n)
        return ((x > y) - (x < y)) & M64

    def malloc(self, m, n, *_):
        return self.alloc(n)

    def memcpy(self, m, a, b, n, *_):
        m.store(a, m.load(b, n))
        return a

    def alloc_fail(self, m, *_):
        raise Panic('alloc')

    def panic_unwrap(self, m, msg, n, payload, vt, loc, *_):
        raise Panic('unwrap', loc)

    def panic_rdi(self, m, loc, *_):
        raise Panic('index', loc)


def call(w, fn, *args):
    m = w.m
    m.r[4] -= 8
    q(m, m.r[4], SENT)
    for reg, v in zip((7, 6, 2, 1, 8, 9), args):
        m.r[reg] = v
    m.run(fn, {SENT}, 2000000)


def err_pattern(st):
    return bytes((st + 3 * i + 1) & 255 for i in range(0x60))


def swiss_hash(key):
    return int.from_bytes(hashlib.sha256(key).digest()[:8], 'little')


def swiss(w, rows, stride):
    """Write (key, row bytes) rows into a 32-bucket swiss table and return its control pointer."""
    m = w.m
    n = 32
    ctrl = w.alloc(stride * n + n + 16 + 64) + stride * n
    tags = [255] * n
    place = {}
    for key, body in rows:
        h = swiss_hash(key)
        i = h & (n - 1)
        while tags[i] != 255:
            i = (i + 1) & (n - 1)
        tags[i] = (h >> 57) & 127
        m.store(ctrl - (i + 1) * stride, body)
        place[key] = ctrl - (i + 1) * stride
    m.store(ctrl, bytes(tags) + bytes(tags[:16]))
    return ctrl, n - 1, place


def tree(w, items, g):
    """Sorted (key, value) items as a B-tree, three-way above the leaves, returned as (root, height)."""
    m = w.m

    def node(rows, edges):
        n = w.alloc(g['size'])
        for i, (k, v) in enumerate(rows):
            m.store(n + g['key'] + i * g['key_len'], k)
            if g['val_len']:
                m.store(n + g['val'] + i * g['val_len'], v)
        m.store(n + g['len'], len(rows).to_bytes(2, 'little'))
        for i, e in enumerate(edges):
            q(m, n + g['edge'] + i * 8, e)
        return n

    def build(rows, height):
        if height == 0:
            return node(rows, ())
        cut = max(1, len(rows) // 3)
        left, sep, mid, sep2, right = rows[:cut], rows[cut], rows[cut + 1:2 * cut + 1], rows[2 * cut + 1], rows[2 * cut + 2:]
        return node([sep, sep2], [build(left, height - 1), build(mid, height - 1), build(right, height - 1)])

    height = 0
    n = len(items)
    while n > 11:
        height += 1
        n = (n - 2) // 3 + 1
    return build(items, height), height


def system_address(c, token):
    if c.get('special') == token:
        return TWOS
    return b'\x20' + bytes(11) + token.to_bytes(8, 'big')


def exchange(w, c):
    m = w.m
    m.store(EX + 0x3ac8, bytes((c.get('disabled', 0),)))
    m.store(EX + 0x5b0, bytes((c.get('allow_high', 0), c.get('allow_three', 0))))
    # sub-account map: 20-byte key, 20-byte master
    subs = sorted(c.get('subs', {}).items())
    q(m, EX + 0x3828, len(subs))
    if subs:
        ctrl, mask, _ = swiss(w, [(k, k + v) for k, v in subs], 0x28)
        q(m, EX + 0x3810, ctrl)
        q(m, EX + 0x3818, mask)
    # vaults
    vaults = sorted(c.get('vaults', ()))
    if vaults:
        root, height = tree(w, [(k, bytes(0xb0)) for k in vaults], VAULT_TREE)
        q(m, EX + 0x8d0, root)
        q(m, EX + 0x8d8, height)
    # tokens
    tokens = c['tokens']
    base = w.alloc(0xe8 * max(len(tokens), 1))
    q(m, EX + 0x210, base)
    q(m, EX + 0x218, len(tokens))
    for i, t in enumerate(tokens):
        r = base + i * 0xe8
        block = t.get('block')
        if block is not None:
            m.store(r + 0x10, (1).to_bytes(4, 'little'))
            if block:
                root, height = tree(w, [(k, b'') for k in sorted(block)], BLOCK_TREE)
                q(m, r + 0x18, root)
                q(m, r + 0x20, height)
        p = w.alloc(max(1, len(t['name'])))
        m.store(p, t['name'])
        q(m, r + 0x30, len(t['name']))
        q(m, r + 0x38, p)
        q(m, r + 0x40, len(t['name']))
        m.store(r + 0x49, bytes((t['dec'],)))
        if t.get('evm') is not None:
            m.store(r + 0xbc, b'\x01' + t['evm'])
    if c.get('special') is not None:
        m.store(EX + 0x80, (1).to_bytes(4, 'little'))
        q(m, EX + 0x88, c['special'])
    # balances: 0x58-byte rows, tree at row +0x28
    rows = []
    for k, toks in sorted(c.get('books', {}).items()):
        items = [(t.to_bytes(8, 'little'), struct.pack('<QQQ', *v)) for t, v in sorted(toks.items())]
        body = bytearray(0x58)
        body[:20] = k
        if items:
            root, height = tree(w, items, TOKEN_TREE)
            body[0x28:0x38] = struct.pack('<QQ', root, height)
        rows.append((k, bytes(body)))
    ctrl, mask, place = swiss(w, rows, 0x58)
    q(m, EX + 0x318, ctrl)
    q(m, EX + 0x320, mask)
    q(m, EX + 0x328, c.get('growth', 1))
    q(m, EX + 0x330, len(rows))
    w.rows = place
    # the destination lookup whose result 0x2712ce0 drops
    q(m, EX + 0x758, c.get('dead_rows', 0))
    ctrl, mask, _ = swiss(w, [(k, k + bytes(0x44)) for k in c.get('dead', ())], 0x58)
    q(m, EX + 0x740, ctrl)
    q(m, EX + 0x748, mask)
    gas_tree = c.get('gas_tree', {})
    if gas_tree:
        root, height = tree(w, [(k.to_bytes(8, 'little'), bytes((v,))) for k, v in sorted(gas_tree.items())], GAS_TREE)
        q(m, EX + 0x2e0, root)
        q(m, EX + 0x2e8, height)
    totals = c.get('fee_total', {})
    if totals:
        root, height = tree(w, [(k.to_bytes(8, 'little'), b'') for k in sorted(totals)], FEE_TREE)
        q(m, EX + 0x420, root)
        q(m, EX + 0x428, height)
    q(m, EX + 0x3a48, c.get('limit', 0))
    m.store(EX + 0x31a2, bytes((c.get('system_off', 0),)))
    m.store(EX + 0x8f2, bytes((c.get('chain', 0),)))
    q(m, EX + 0x60, 0x51525354)
    q(m, EX + 0x68, 0x61626364)
    q(m, EX + 0x50, 0x7a7a7a)
    m.store(EX + 0x78, bytes((c.get('override', 0),)))
    if c.get('block_hash'):
        m.store(EX, (1).to_bytes(4, 'little'))
        q(m, EX + 8, 0x7777)
        q(m, EX + 0x28, 0x8888)


def record(w, c):
    """The 0xd0-byte transfer record 0x2712ce0 reads."""
    m = w.m
    r = w.alloc(0xd0)
    q(m, r, c.get('opt', (0, 0))[0])
    q(m, r + 8, c.get('opt', (0, 0))[1])
    q(m, r + 0x10, c.get('kind', 3))
    q(m, r + 0x18, c.get('word18', 0))
    q(m, r + 0x20, c['token'])
    q(m, r + 0x28, c['wei'])
    if c.get('payload'):
        vt = w.alloc(0x28)
        q(m, vt + 0x20, 0x576e010)
        q(m, r + 0x30, vt)
        q(m, r + 0x38, 0x1234)
        q(m, r + 0x40, 0x5678)
    m.store(r + 0x88, c['from'])
    m.store(r + 0x9c, c['to'])
    m.store(r + 0xb0, bytes((c.get('skip', 0),)) + c.get('extra', bytes(20)))
    return r


def outcome(w, out):
    m = w.m
    st = int.from_bytes(m.load(out, 2), 'little')
    return st, m.load(out + 2, 0x5e).hex()


def run_core(img, c):
    w = World(img, c)
    exchange(w, c)
    r = record(w, c)
    try:
        call(w, 0x2712ce0, OUT, EX, r)
    except Panic as p:
        return dict(panic=p.args[0], log=w.log)
    st, rest = outcome(w, OUT)
    d = dict(status=st, log=w.log)
    m = w.m
    if st == OK:
        d['name'] = m.load(rq(m, OUT + 0x10), rq(m, OUT + 0x18)).decode('latin-1')
        d['first'], d['second'] = rq(m, OUT + 0x20), rq(m, OUT + 0x28)
        if w.entry_ptr is not None:
            d['hold'] = rq(m, w.entry_ptr + 8)
        d['rows'] = {k: (rq(m, p + 0x10), m.load(p + 0x3d, 1)[0]) for k, p in w.addr_rows.items()}
        if w.fee_ptr is not None:
            d['fee_total'] = rq(m, w.fee_ptr)
    elif st == 356:
        d['zero'] = int(rq(m, OUT + 8) == 0)
    elif st not in PLAIN:
        d['result'] = rest
    return d


def action(w, c):
    m = w.m
    a = w.alloc(0x50)
    for off, s in ((0, c['token_text']), (0x18, c['amount_text'])):
        p = w.alloc(max(1, len(s)))
        m.store(p, s)
        q(m, a + off, len(s))
        q(m, a + off + 8, p)
        q(m, a + off + 16, len(s))
    m.store(a + 0x30, c['sub'])
    m.store(a + 0x44, bytes((c['deposit'],)))
    return a


def spot_action(w, c):
    m = w.m
    a = w.alloc(0x80)
    for off, s in ((0, c['dest_text']), (0x18, c['token_text']), (0x30, c['amount_text'])):
        p = w.alloc(max(1, len(s)))
        m.store(p, s)
        q(m, a + off, len(s))
        q(m, a + off + 8, p)
        q(m, a + off + 16, len(s))
    q(m, a + 0x68, c['time'])
    return a


def run_handler(img, c, spot=False):
    w = World(img, c)
    exchange(w, c)
    m = w.m
    m.store(KEYS, c['signer'])
    a = (spot_action if spot else action)(w, c)
    try:
        call(w, 0x1f66070 if spot else 0x1e64420, OUT, a, KEYS, EX)
    except Panic as p:
        return dict(panic=p.args[0], log=w.log)
    tag = m.load(OUT, 1)[0]
    d = dict(tag=tag, log=strip(w.log))
    if tag == 14:
        st = int.from_bytes(m.load(OUT + 8, 2), 'little')
        d['status'] = st
        if st == 218:
            d['a'], d['b'] = m.load(OUT + 10, 20).hex(), m.load(OUT + 30, 20).hex()
        elif st == 248:
            d['name'] = m.load(rq(m, OUT + 0x18), rq(m, OUT + 0x20)).decode('latin-1')
    return d


def strip(log):
    """Uninitialised record words are not compared through the wrappers."""
    return [e[:7] if e[0] == 'into_system' else e for e in log]


def in_system_range(a):
    return a == TWOS or LOW <= a <= HIGH


def blocked(t, who):
    return bool(t.get('block')) and who in t['block']


def balance(c, who, token):
    return c.get('books', {}).get(who, {}).get(token, (0, 0, 0))


def usd_value(c, log, token, wei):
    if token == 0:
        return wei // 100
    log.append(('price', token))
    p = c.get('price', 0)
    if p == 0:
        return 0
    log.append(('muldiv', wei, token, p))
    flag, v = c.get('usd', (0, 0))
    v = v if flag & 1 else 0
    if token == 1 or c['tokens'][token]['name'] == HYPE:
        return v
    return min(v, 10 ** 16)


def merge(c, log, token, x0, x1, x2, n1, n2):
    """0x2712af0.  Returns (name, first, second)."""
    name = n1
    if x0 > 0:
        x1 = x0
    elif f2i(x1) == 0:
        x1 = 0.0
    else:
        log.append(('name', token))
        name = c['tokens'][token]['name']
    if f2i(x2) == 0:
        return name, x1, x2
    if n2 == HYPE:
        return name, x1, x2
    if name == n2:
        return name, x1 + x2, 0.0
    if f2i(x1) != 0:
        return name, x1, 0.0
    return n2, x2, 0.0


def row_touch(c, log, state, to):
    log.append(('row', to.hex()))
    return state['rows'].setdefault(to, (c.get('rows', {}).get(to, 0), 0))


def sat_add(c, log, value, delta):
    res = sx(value, 64) + delta
    if -(1 << 63) <= res < 1 << 63:
        return res & M64
    log.append(('recorder', 0, 0x5715ef8))
    return (M64 >> 1 if res > 0 else 1 << 63) & M64


def credit(c, log, state, kind, mode, gas, gas_flag, t, wei, a, cost, b, to):
    """0x2716f90.  Returns the f64 fee part, or None for the unwrap panic."""
    tokens = c['tokens']
    fee = 0
    if mode >= 2:
        if gas_flag & 1:
            state['rows'][to] = (row_touch(c, log, state, to)[0], 1)
        if gas:
            v = c.get('gas_tree', {}).get(t)
            err = None
            price = 0
            if v is not None and v != 1:
                log.append(('fee_price', t))
                price = c.get('fee_price', 0)
            elif c.get('special') is None:
                err = 251
            elif t != c['special']:
                err = 234
            elif a == 0:
                err = 352
            else:
                price = a
            take = False
            if err is None:
                if gas > 0x68db8bac710cb:
                    err = 319
                else:
                    log.append(('fee_quote', gas * 100, t, price, 0))
                    ok, val = c.get('fee_quote', (0, 0))
                    if not ok & 1:
                        err = 319
                    elif val < wei:
                        fee, take = val, True
            if err is not None:
                log.append(('status', err))
            if not take:
                log.append(('sink', to.hex(), t, wei))
                return 0.0
    log.append(('apply', to.hex(), t, 0, wei, cost))
    if kind in (3, 4):
        w, f = row_touch(c, log, state, to)
        state['rows'][to] = (sat_add(c, log, w, b // 10000), f)
    log.append(('after_credit', to.hex()))
    if not fee:
        return 0.0
    tot, hold, _ = balance(c, to, t)
    if to in c.get('books', {}):
        state['hold'] = hold if t in c['books'][to] else 0
    elif not c.get('growth', 1):
        log.append(('reserve',))
    if hold + fee > M64 or hold + fee > tot or to not in c.get('books', {}):
        return 0.0
    state['hold'] = hold + fee
    log.append(('apply', to.hex(), t, 1, fee, a))
    if t == 0:
        b2 = fee // 100
    else:
        log.append(('price', t))
        p = c.get('price', 0)
        if p == 0:
            b2 = 0
        else:
            log.append(('muldiv', fee, t, p))
            flag, v = c.get('usd', (0, 0))
            b2 = v if flag & 1 else 0
            if t == 1 or tokens[t]['name'] == HYPE:
                if b2 >> 63:
                    return None
            else:
                b2 = min(b2, 10 ** 16)
    w, f = row_touch(c, log, state, to)
    state['rows'][to] = (sat_add(c, log, w, -(b2 // 10000)), f)
    log.append(('name', t))
    if c.get('block_hash'):
        log.append(('event_hash', c.get('chain', 0), 0x8888, 0x7777, 0))
        hsh = b'hash-32-'
    else:
        hsh = bytes(8)
    log.append(('fee_event', 0x8f3, 1, 1, to.hex(), struct.pack('<QI', 0x51525354, 0x61626364).hex(), hsh.hex(), tokens[t]['name'].decode('latin-1'), float(fee) / 10.0 ** tokens[t]['dec']))
    log.append(('fee_row', int(t in c.get('fee_total', {}))))
    total = c.get('fee_total', {}).get(t, 0) + fee
    if total > M64:
        log.append(('recorder', 0, 0x56dfd78))
        total = M64
    state['fee_total'] = total
    return float(fee) / 10.0 ** tokens[t]['dec']


def want_core(c):
    log = []
    t, wei, frm, to = c['token'], c['wei'], c['from'], c['to']
    tokens, kind, payload = c['tokens'], c.get('kind', 3), bool(c.get('payload'))
    if c.get('disabled'):
        return dict(status=249, log=log)
    if frm == to:
        return dict(status=222, log=log)
    if to in c.get('vaults', ()) or to == FF:
        return dict(status=28, log=log)
    if not c.get('skip', 0) & 1:
        if t >= len(tokens):
            return dict(panic='index', log=log)
        if blocked(tokens[t], frm) or blocked(tokens[t], to):
            return dict(status=344, log=log)
    if kind in (3, 4):
        log.append(('class', t))
        if c.get('klass', 0) & 255:
            return dict(status=347, log=log)
    sysa = system_address(c, t)
    if to != sysa:
        r = in_system_range(to)
        if r:
            return dict(status=330, log=log)
        if payload:
            return dict(status=347, log=log)
        log.append(('gas', frm.hex(), to.hex()))
        g, gf = c.get('gas', (0, 0))
        gf &= 1
        mode, plain = (2, False) if frm == sysa else (0, True)
    else:
        g, gf = 0, 0
        plain = False
        mode = 1
        if t == 0:
            log.append(('book', to.hex()))
            total = balance(c, to, 0)[0]
            if total + wei > M64 or total + wei > c.get('limit', 0) or c.get('system_off', 0):
                return dict(status=38, log=log)
    log.append(('book', frm.hex()))
    tot, hold, entry = balance(c, frm, t)
    if hold + wei > M64 or hold + wei > tot:
        return dict(status=247, log=log)
    put = None
    if t == 0 and c.get('chain', 0) != 3:
        evm = tokens[0].get('evm')
        if evm is not None:
            m = c.get('map', {})
            if mode == 1:
                log.append(('map_get', frm.hex()))
                v = m.get(frm, 0) + wei
                if v > M64:
                    log.append(('recorder', 0, 0x56dfd90))
                    v = M64
                put = (frm, v)
            elif (mode == 0 and frm == evm) or (mode == 2 and to != evm):
                log.append(('map_get', to.hex()))
                if to not in m or m[to] < wei:
                    return dict(status=356, log=log, zero=1)
                put = (to, m[to] - wei)
    x0, x2, n1, n2 = 0.0, 0.0, b'', b''
    if plain:
        log.append(('gas_step', frm.hex(), g, gf, wei, t))
        st = c.get('gas_status', OK)
        if st != OK:
            return dict(status=st, log=log, result=err_pattern(st)[2:0x60].hex())
        cls, word, last, _ = c.get('gas_class', (0, 0, 0, 0))
        if cls >= 2:
            log.append(('gas_follow', word, frm.hex(), 1))
            st = c.get('follow_status', OK)
            if st != OK:
                return dict(status=st, log=log, result=err_pattern(st)[2:0x60].hex())
        log.append(('recipient', frm.hex(), to.hex(), (bytes((cls,)) + b'\x31\x32\x33\x34\x35\x36\x37').hex(), word, 0x1111, 0x2222, last))
        st = c.get('recipient_status', OK)
        if st != OK:
            return dict(status=st, log=log, result=err_pattern(st)[2:0x60].hex())
        x0, n1 = c.get('gas_part', 0.0), c.get('gas_name', b'USDC')
    elif mode == 1:
        log.append(system_row(c, t, sysa))
        st = c.get('system_status', OK)
        if st != OK:
            return dict(status=st, log=log, result=err_pattern(st)[2:0x60].hex())
        x2, n2 = c.get('system_part', 0.0), c.get('system_name', b'')
    if put:
        log.append(('map_put', put[0].hex(), put[1]))
    log.append(('price', t))
    a = c.get('price', 0)
    cost = 0 if kind == 0 else c.get('word18', 0) if kind == 2 else a
    b = usd_value(c, log, t, wei)
    if b >> 63:
        return dict(panic='unwrap', log=log)
    log.append(('apply', frm.hex(), t, 1, wei, cost))
    if kind in (3, 4):
        log.append(('tally', frm.hex(), -b & M64, 1, 0))
    state = dict(hold=hold + wei if wei else None, rows={})
    x1 = credit(c, log, state, kind, mode, g, gf, t, wei, a, cost, b, to)
    if x1 is None:
        return dict(panic='unwrap', log=log)
    name, first, second = merge(c, log, t, x0, x1, x2, n1, n2)
    if kind == 3:
        if c.get('block_hash'):
            log.append(('event_hash', c.get('chain', 0), 0x8888, 0x7777, 0))
            hsh = b'hash-32-'
        else:
            hsh = bytes(8)
        log.append(('name', t))
        word = 0x7a7a7a if c.get('override') else (c.get('opt', (0, 0))[1] if c.get('opt', (0, 0))[0] else 0)
        log.append(('event', 0x8f3, 2, 2, (frm + to).hex(), struct.pack('<QI', 0x51525354, 0x61626364).hex(), hsh.hex(), 0x800000000000000f, 1, word,
                    tokens[t]['name'].decode('latin-1'), name.decode('latin-1'), float(wei) / 10.0 ** tokens[t]['dec'], float(b) / 1e6, f2i(first), f2i(second), frm.hex(), to.hex()))
    d = dict(status=OK, log=log, name=name.decode('latin-1'), first=f2i(first), second=f2i(second), rows=state['rows'])
    if state['hold'] is not None:
        d['hold'] = state['hold']
    if 'fee_total' in state:
        d['fee_total'] = state['fee_total']
    return d


def system_row(c, t, sysa):
    p = bool(c.get('payload'))
    return ('into_system', t, c['wei'], c['from'].hex(), c['to'].hex(), sysa.hex(), c.get('skip', 0), int(p), 0x1234 if p else 0, 0x5678 if p else 0, c.get('extra', bytes(20)).hex())


def want_handler(c, spot=False):
    log = []
    signer = c['signer']
    if not spot and c.get('disabled'):
        return dict(tag=14, status=249, log=log)

    def gate(who):
        log.append(('profile', who.hex()))
        k = c['classes'].get(who, 0)
        return (k < 3) or (k == 3 and c.get('allow_three')) or (k > 3 and c.get('allow_high'))

    if not gate(signer):
        return dict(tag=14, status=367, log=log)
    if spot:
        if len(c['dest_text']) > 100:
            return dict(tag=14, status=323, log=log)
        log.append(('addr_parse', c['dest_text'].decode('latin-1')))
        if c.get('dest') is None:
            return dict(tag=14, status=182, log=log)
        frm, to = signer, c['dest']
        opt = (1, c['time'])
    else:
        if not gate(c['sub']):
            return dict(tag=14, status=367, log=log)
        frm, to = (signer, c['sub']) if c['deposit'] else (c['sub'], signer)
        if c.get('subs', {}).get(c['sub']) != signer:
            return dict(tag=14, status=218, log=log, a=frm.hex(), b=to.hex())
        opt = (0, 0)
    if len(c['token_text']) > 100:
        return dict(tag=14, status=323, log=log)
    if len(c['amount_text']) > 100:
        return dict(tag=14, status=323, log=log)
    if c.get('disabled'):
        return dict(tag=14, status=249, log=log)
    log.append(('token', c['token_text'].decode('latin-1')))
    i = next((i for i, t in enumerate(c['tokens']) if t['name'] == c['token_text']), None)
    if i is None:
        return dict(tag=14, status=248, log=log, name=c['token_text'].decode('latin-1'))
    log.append(('parse', c['amount_text'].decode('latin-1')))
    st = c.get('parse_status', OK)
    if st != OK:
        return dict(tag=14, status=st, log=log)
    log.append(('scale', 'decimal-bytes-16', 1, c['tokens'][i]['dec']))
    st = c.get('scale_status', OK)
    if st != OK:
        return dict(tag=14, status=st, log=log)
    core = dict(c, token=i, kind=3, opt=opt, payload=0, skip=0, word18=0, to=to)
    core['from'] = frm
    core.pop('extra', None)
    r = want_core(core)
    d = dict(log=log + strip(r['log']))
    if 'panic' in r:
        d['panic'] = r['panic']
    elif r['status'] == OK:
        d['tag'] = 13
    else:
        d['tag'], d['status'] = 14, r['status']
    return d


PLAIN = (249, 222, 28, 344, 347, 330, 38, 247, 356)


ADDRS = [addr(i) for i in range(1, 9)]
NAMES = [b'USDC', b'PURR', b'HYPE', b'HFUN', b'JEFF', b'LONGERNAME']
AMOUNTS = [0, 1, 5, 99, 100, 1000000, 123456789, 10 ** 12, 10 ** 16, 10 ** 18 + 7, (1 << 63) - 1, 1 << 63, M64 - 3, M64]
FLOATS = [0.0, -0.0, 1.5, 0.25, -2.0, 1e-9, 1234.5]


def token_table(s):
    n = 3 + s.u(4)
    out = []
    for i in range(n):
        t = dict(name=NAMES[i], dec=s.pick((0, 2, 6, 8, 18)))
        k = s.u(5)
        if k == 0:
            t['block'] = []
        elif k == 1:
            t['block'] = sorted(s.pick(ADDRS) for _ in range(1 + s.u(14)))
        out.append(t)
    if s.u(2):
        out[0]['evm'] = s.pick((addr(7), addr(1), addr(20)))
    return out


def world_knobs(s, c):
    tokens = c['tokens']
    c['vaults'] = sorted({s.pick(ADDRS) for _ in range(s.u(4) * s.u(8))} | ({addr(40 + j) for j in range(s.u(30))} if s.u(2) else set())) if s.u(2) else []
    if s.u(3) == 0:
        c['special'] = s.u(len(tokens))
    c['chain'] = s.pick((0, 1, 2, 3))
    c['limit'] = s.pick(AMOUNTS)
    c['system_off'] = int(s.u(5) == 0)
    c['override'] = int(s.u(4) == 0)
    c['block_hash'] = int(s.u(2) == 0)
    c['gas'] = (s.pick((0, 0, 7, 1000)), s.u(4))
    c['gas_class'] = (s.u(4), s.pick(AMOUNTS), s.u(2), 0)
    c['price'] = s.pick((0, 0, 3, 1000000))
    c['usd'] = (s.u(4), s.pick(AMOUNTS))
    c['klass'] = s.pick((0, 0, 0, 0, 1, 2, 0x100))
    c['fee_quote'] = (s.u(4), s.pick((0, 1, 7, 1000, 10 ** 12, M64)))
    c['fee_price'] = s.pick((0, 5, 123))
    c['rows'] = {a: s.pick((0, 77777, M64 >> 1, 1 << 63, (1 << 63) + 3)) for a in ADDRS if s.u(2)}
    if s.u(2):
        c['gas_tree'] = {j: s.pick((0, 1, 2)) for j in sorted({s.u(len(tokens)) for _ in range(3)} | {100 + 3 * i for i in range(s.u(16))})}
    if s.u(2):
        c['fee_total'] = {j: s.pick((0, 5, M64 - 1)) for j in sorted({s.u(len(tokens))} | {100 + 3 * i for i in range(s.u(15))})}
    c['gas_part'] = s.pick(FLOATS)
    c['system_part'] = s.pick(FLOATS)
    c['gas_name'] = s.pick((b'USDC', b'PURR', b'', b'HYPE'))
    c['system_name'] = s.pick((b'USDC', b'HYPE', b'', b'PURR', b'XY'))
    for key, code in (('gas_status', 501), ('follow_status', 502), ('recipient_status', 503), ('system_status', 504)):
        if s.u(9) == 0:
            c[key] = code
    if s.u(3) == 0:
        c['dead_rows'] = 1
        c['dead'] = [s.pick(ADDRS)]
    if s.u(2):
        c['map'] = {a: s.pick(AMOUNTS) for a in ADDRS if s.u(2)}


def fund(s, c, who, token, wei):
    k = s.u(6)
    tot = wei + s.pick((0, 0, 1, 5000)) if k else s.pick(AMOUNTS)
    hold = 0 if k < 3 else min(tot - wei, s.u(50)) if k < 5 and tot >= wei else s.pick(AMOUNTS)
    tot = min(tot, M64)
    rows = {token: (tot, min(hold, M64), 9)}
    for i in range(s.u(16)):
        rows[100 + 2 * i] = (1, 0, 0)
    c.setdefault('books', {})[who] = rows


def core_cases(n):
    s = Stream('core')
    out = []
    for i in range(n):
        tokens = token_table(s)
        c = dict(tokens=tokens, classes={}, token=s.pick((0, 0, 1, 2, len(tokens) - 1)), wei=s.pick(AMOUNTS))
        world_knobs(s, c)
        sysa = system_address(c, c['token'])
        frm, to = s.pick(ADDRS), s.pick(ADDRS)
        k = s.u(12)
        if k == 0:
            to = sysa
        elif k == 1:
            to = FF
        elif k == 2:
            to = s.pick((LOW, HIGH, TWOS, b'\x20' + bytes(17) + b'\x27\x10', b'\x1f' + b'\xff' * 19, b'\x20' + bytes(18) + b'\x07'))
        elif k in (3, 7, 8, 9):
            frm = sysa
            if s.u(2):
                c['gas'] = (s.pick((1, 7, 1000, 0x68db8bac710cb, 0x68db8bac710cc)), s.u(4))
        elif k == 4:
            to = sysa
            c['token'] = 0
            sysa = system_address(c, 0)
            to = sysa
        elif k == 5 and tokens[0].get('evm'):
            frm = tokens[0]['evm']
            c['token'] = 0
        elif k == 6 and tokens[0].get('evm'):
            to = tokens[0]['evm']
            c['token'] = 0
            frm = system_address(c, 0)
        c['from'], c['to'] = frm, to
        c['kind'] = s.pick((3, 3, 3, 4, 0, 1, 2, 5))
        c['word18'] = s.pick((0, 11, 4096))
        c['opt'] = s.pick(((0, 0), (0, 99), (1, 1234), (1, 0)))
        c['payload'] = int(s.u(4) == 0)
        c['skip'] = s.pick((0, 0, 0, 1, 3, 2))
        c['extra'] = s.pick((bytes(20), addr(9)))
        c['disabled'] = int(s.u(20) == 0)
        fund(s, c, frm, c['token'], c['wei'])
        if s.u(2) or k in (3, 7, 8, 9):
            fund(s, c, to, c['token'], s.pick(AMOUNTS))
        if k in (7, 8) and to in ADDRS:
            c['gas'] = (s.pick((1, 7, 1000)), s.u(2))
            c['gas_tree'] = {c['token']: s.pick((0, 2))}
            c['fee_price'] = 5
            c['fee_quote'] = (1, s.pick((1, 5, c['wei'] // 2)))
            c['books'][to] = {c['token']: (s.pick((10 ** 13, M64)), 0, 0)}
        if s.u(30) == 0:
            c['token'] = len(tokens) + s.u(3)
            c['skip'] = 0
        out.append(c)
    return out


def account_knobs(s, c):
    c['allow_high'], c['allow_three'] = s.u(2), s.u(2)
    if s.u(2):
        c['classes'] = {a: s.pick((0, 1, 2, 3, 4, 5, 255)) for a in ADDRS if s.u(3) == 0}
    c['token_text'] = s.pick([t['name'] for t in c['tokens']] + [b'NOPE', b'x' * 100, b'x' * 101])
    c['amount_text'] = s.pick((b'1', b'0.5', b'', b'9' * 100, b'9' * 101))
    if s.u(8) == 0:
        c['parse_status'] = s.pick((356, 511))
    elif s.u(8) == 0:
        c['scale_status'] = s.pick((356, 512))


def handler_cases(n):
    s = Stream('handler')
    out = []
    for i in range(n):
        tokens = token_table(s)
        c = dict(tokens=tokens, classes={}, wei=s.pick(AMOUNTS), signer=s.pick(ADDRS), sub=s.pick(ADDRS), deposit=s.pick((0, 1, 1, 2)))
        world_knobs(s, c)
        c['vaults'] = [a for a in c['vaults'] if s.u(3) == 0]
        account_knobs(s, c)
        c['subs'] = {a: s.pick(ADDRS) for a in ADDRS if s.u(4) == 0}
        if s.u(5):
            c['subs'][c['sub']] = c['signer']
        c['disabled'] = int(s.u(15) == 0)
        i_tok = next((j for j, t in enumerate(tokens) if t['name'] == c['token_text']), 0)
        fund(s, c, c['signer'] if c['deposit'] else c['sub'], i_tok, c['wei'])
        out.append(c)
    return out


def spot_cases(n):
    s = Stream('spot')
    out = []
    for i in range(n):
        tokens = token_table(s)
        c = dict(tokens=tokens, classes={}, wei=s.pick(AMOUNTS), signer=s.pick(ADDRS), time=1700000000000 + s.u(1000))
        world_knobs(s, c)
        account_knobs(s, c)
        c['dest'] = s.pick((addr(2), addr(3), None, s.pick(ADDRS)))
        c['dest_text'] = s.pick((b'0xabc', b'y' * 100, b'y' * 101))
        c['disabled'] = int(s.u(15) == 0)
        i_tok = next((j for j, t in enumerate(tokens) if t['name'] == c['token_text']), 0)
        fund(s, c, c['signer'], i_tok, c['wei'])
        out.append(c)
    return out


def same(got, want):
    if got.get('log') != want.get('log'):
        return False
    return all(got.get(k) == want.get(k) for k in ('panic', 'status', 'tag', 'name', 'first', 'second', 'hold', 'zero', 'result', 'a', 'b', 'rows', 'fee_total'))


def label(d):
    if 'panic' in d:
        return 'panic ' + d['panic']
    names = {e[0] for e in d['log']}
    if d.get('status', OK) == OK:
        route = 'receiver fee' if 'fee_event' in names else 'sink' if 'sink' in names else 'into system' if 'into_system' in names else 'gas step' if 'gas_step' in names else 'system sender'
        return f"status 390 {route}"
    return f"status {d['status']}"


def evaluate(img, n=400):
    counts = {}
    bad = []

    def note(kind, got, want):
        key = (kind, label(want))
        counts[key] = counts.get(key, 0) + 1
        if not same(got, want):
            bad.append((kind, got, want))

    for c in core_cases(n):
        note('core', run_core(img, c), want_core(c))
    for c in handler_cases(n):
        note('subAccountSpotTransfer', run_handler(img, c), want_handler(c))
    for c in spot_cases(n // 2):
        note('spotSend', run_handler(img, c, True), want_handler(c, True))
    return counts, bad


def base_case(**k):
    t = [dict(name=b'USDC', dec=8), dict(name=b'PURR', dec=5), dict(name=b'HYPE', dec=8)]
    a, b = addr(1), addr(2)
    c = dict(tokens=t, classes={}, token=1, wei=1000, to=b, kind=3, books={a: {0: (5000, 0, 0), 1: (5000, 0, 0)}}, limit=0)
    c['from'] = a
    c.update(k)
    return c


def named_cases(img):
    a, b = addr(1), addr(2)
    rows = []
    zero = system_address({}, 0)

    def core(name, **k):
        c = base_case(**k)
        got, want = run_core(img, c), want_core(c)
        rows.append(('core', name, label(got), 'same' if same(got, want) else 'differs'))

    def hand(name, **k):
        t = [dict(name=b'USDC', dec=8), dict(name=b'PURR', dec=5)]
        c = dict(tokens=t, classes={}, wei=1000, signer=a, sub=b, deposit=1, token_text=b'PURR', amount_text=b'1', subs={b: a}, books={a: {1: (5000, 0, 0)}, b: {1: (5000, 0, 0)}})
        c.update(k)
        got, want = run_handler(img, c), want_handler(c)
        rows.append(('subAccountSpotTransfer', name, f"tag {got.get('tag')} {label(got)}", 'same' if same(got, want) else 'differs'))

    core('plain transfer')
    core('spot disabled', disabled=1)
    core('same address', to=a)
    core('destination is a vault', vaults=[b])
    core('sender is a vault', vaults=[a])
    core('destination is twenty 0xff bytes', to=FF)
    core('sender in the token block set', tokens=[dict(name=b'USDC', dec=8), dict(name=b'PURR', dec=5, block=[a])])
    core('destination in the token block set', tokens=[dict(name=b'USDC', dec=8), dict(name=b'PURR', dec=5, block=[b])])
    core('block set skipped by record +0xb0 bit 0', tokens=[dict(name=b'USDC', dec=8), dict(name=b'PURR', dec=5, block=[b])], skip=1)
    core('kind 3 with a nonzero class word', klass=1)
    core('kind 5 ignores the class word', klass=1, kind=5)
    core('payload with a user destination', payload=1)
    core('foreign system address 0x20..07', to=system_address({}, 7))
    core('system range top 9999', to=HIGH)
    core('one above the system range', to=b'\x20' + bytes(17) + b'\x27\x10')
    core('0x2222 address when not this token', to=TWOS)
    core('own system address', to=system_address({}, 1), system_name=b'PURR', system_part=2.0)
    core('own system address, token 2 is the special token', to=TWOS, token=2, special=2, books={a: {2: (5000, 0, 0)}})
    core('USDC to system at the limit', token=0, to=zero, limit=1000)
    core('USDC to system over the limit', token=0, to=zero, limit=999)
    core('USDC to system with the off flag', token=0, to=zero, limit=9000, system_off=1)
    core('free balance one short', books={a: {1: (1000, 1, 0)}})
    core('free balance exact', books={a: {1: (1000, 0, 0)}})
    core('hold word overflow', books={a: {1: (M64, M64, 0)}})
    core('sender system address, USDC map debit short', token=0, **{'from': zero}, books={zero: {0: (5000, 0, 0)}}, tokens=[dict(name=b'USDC', dec=8, evm=addr(7)), dict(name=b'PURR', dec=5)])
    core('sender system address, USDC map debit', token=0, **{'from': zero}, books={zero: {0: (5000, 0, 0)}}, tokens=[dict(name=b'USDC', dec=8, evm=addr(7)), dict(name=b'PURR', dec=5)], map={b: 1500})
    core('USDC into system, map add saturates', token=0, to=zero, limit=9000, tokens=[dict(name=b'USDC', dec=8, evm=addr(7)), dict(name=b'PURR', dec=5)], map={a: M64 - 1})
    core('chain byte 3 skips the map', token=0, to=zero, limit=9000, chain=3, tokens=[dict(name=b'USDC', dec=8, evm=addr(7)), dict(name=b'PURR', dec=5)])
    core('value above i64 panics', token=2, price=5, usd=(1, 1 << 63), books={a: {2: (5000, 0, 0)}})
    core('value cap 1e16 on a plain token', price=5, usd=(1, 10 ** 17))
    core('token 1 keeps the value uncapped', price=5, usd=(1, 10 ** 17))
    sa = system_address({}, 1)
    fr = {'from': sa}
    bk = {sa: {1: (5000, 0, 0)}, b: {1: (500, 0, 0)}}
    core('system sender, no gas quote', **fr, books=bk)
    core('system sender, flag bit marks the row', **fr, books=bk, gas=(0, 1))
    core('gas quote, token not in the gas tree and no special token', **fr, books=bk, gas=(7, 0))
    core('gas quote, tree byte 1 and another special token', **fr, books=bk, gas=(7, 0), gas_tree={1: 1}, special=2)
    tw = {'from': TWOS}
    bt = {TWOS: {1: (5000, 0, 0)}, b: {1: (5000, 0, 0)}}
    core('gas quote, special token with zero price', **tw, books=bt, gas=(7, 0), gas_tree={1: 1}, special=1)
    core('gas quote, special token uses the transfer price', **tw, books=bt, gas=(7, 0), gas_tree={1: 1}, special=1, price=9, fee_quote=(1, 10), usd=(1, 80000))
    core('gas quote above the 100x gate', **fr, books=bk, gas=(0x68db8bac710cc, 0), gas_tree={1: 0}, fee_price=5)
    core('gas quote at the 100x gate', **fr, books=bk, gas=(0x68db8bac710cb, 0), gas_tree={1: 0}, fee_price=5, fee_quote=(1, 1000))
    core('fee quote fails', **fr, books=bk, gas=(7, 0), gas_tree={1: 0}, fee_price=5, fee_quote=(0, 3))
    core('fee at or above the amount goes to the sink', **fr, books=bk, gas=(7, 0), gas_tree={1: 0}, fee_price=5, fee_quote=(1, 1000))
    core('fee taken from the receiver', **fr, books={sa: {1: (5000, 0, 0)}, b: {1: (5000, 0, 0)}}, gas=(7, 0), gas_tree={1: 0}, fee_price=5, fee_quote=(1, 999), price=3, usd=(1, 80000))
    core('fee above the receiver first word, no fee event', **fr, books={sa: {1: (5000, 0, 0)}, b: {1: (10, 0, 0)}}, gas=(7, 0), gas_tree={1: 0}, fee_price=5, fee_quote=(1, 999))
    core('the unused destination lookup hits', **{'from': system_address({}, 1)}, books={system_address({}, 1): {1: (5000, 0, 0)}}, dead_rows=1, dead=[b], gas=(7, 1))
    hand('deposit moves signer to sub')
    hand('withdraw moves sub to signer', deposit=0)
    hand('spot disabled', disabled=1)
    hand('signer class 3 gated', classes={a: 3})
    hand('sub class 4 gated', classes={b: 4})
    hand('sub class 4 allowed', classes={b: 4}, allow_high=1)
    hand('no sub-account rows', subs={})
    hand('sub-account of another master', subs={b: addr(5)})
    hand('master equals sub, row maps to self', sub=a, subs={a: a})
    hand('token name 101 bytes', token_text=b'x' * 101)
    hand('amount 101 bytes', amount_text=b'9' * 101)
    hand('unknown token', token_text=b'NOPE')
    hand('sub is a vault', vaults=[b])
    return rows


TEXT_TABLE = 0x59a8d0
PLAIN_ARM = bytes.fromhex('488b3e488b4608488b4018488d35')
STATUS_LIST = (28, 38, 182, 218, 222, 234, 247, 248, 249, 251, 319, 323, 330, 344, 347, 352, 356, 367)


def status_rows(img):
    """Display text of each status.  Plain arms: rsi text, edx length.  Format arms: rdx piece bytes up to a zero byte."""
    rows = []
    for st in STATUS_LIST:
        arm = TEXT_TABLE + struct.unpack('<i', img.rd(TEXT_TABLE + 4 * st, 4))[0]
        body = img.rd(arm, 112)
        if body.startswith(PLAIN_ARM):
            d = struct.unpack_from('<i', body, 14)[0]
            if body[18] != 0xba:
                raise ValueError(f'status {st}: arm shape at {arm:#x}')
            n = struct.unpack_from('<I', body, 19)[0]
            text = img.rd(arm + 18 + d, n).decode()
            shape = 'plain'
        else:
            x = body.find(b'\x48\x8d\x15')
            if x < 0:
                raise ValueError(f'status {st}: no format at {arm:#x}')
            p = arm + x + 7 + struct.unpack_from('<i', body, x + 3)[0]
            raw = img.rd(p, 96).split(b'\0')[0]
            text = re.sub('[^ -~]+', '{}', raw.decode('latin-1'))
            shape = 'format'
        rows.append((str(st), f'{st:#x}', f'{arm:#x}', shape, text))
    return rows


def twin_rows(table):
    """FDE rows with the same byte size as a path function of 1000 bytes or more.  Same size only: the bytes are not compared."""
    sizes = {}
    for s_, e_ in table:
        sizes.setdefault(e_ - s_, []).append(s_)
    rows = []
    for va, _ in FUNCS:
        s_, e_ = extent(table, va)
        if e_ - s_ >= 1000:
            rows.append((f'{va:#x}', str(e_ - s_), ' '.join(f'{x:#x}' for x in sizes[e_ - s_] if x != va) or '-'))
    return rows


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
    locs = location_rows(img)
    write_tsv(out / 'functions.tsv', ('start', 'end', 'bytes', 'sha256', 'role'), funcs)
    write_tsv(out / 'stubs.tsv', ('site', 'kind', 'target', 'fde_start', 'fde_end', 'role'), stubs)
    write_tsv(out / 'callers.tsv', ('function', 'site', 'kind', 'site_fde'), callers)
    write_tsv(out / 'pins.tsv', ('group', 'va', 'instruction', 'meaning'), pins)
    write_tsv(out / 'layout.tsv', ('struct', 'offset', 'width', 'va', 'instruction', 'meaning'), layout)
    write_tsv(out / 'locations.tsv', ('record', 'path', 'line', 'column', 'use'), locs)
    write_tsv(out / 'outcomes.tsv', ('family', 'class', 'vectors'), [(k[0], k[1], v) for k, v in sorted(counts.items())])
    write_tsv(out / 'cases.tsv', ('family', 'scenario', 'result', 'model'), named)
    write_tsv(out / 'gate-order.tsv', ('step', 'function', 'status', 'site', 'instruction', 'condition'), GATES)
    texts, twins = status_rows(img), twin_rows(table)
    write_tsv(out / 'status-text.tsv', ('status', 'hex', 'arm', 'shape', 'text'), texts)
    write_tsv(out / 'same-size-fdes.tsv', ('function', 'bytes', 'other_fde_starts'), twins)
    evidence = {'binary': BINARY, 'sha256': SHA256, 'pins': len(pins), 'layout_rows': len(layout), 'functions': len(funcs),
                'function_bytes': sum(int(r[2]) for r in funcs), 'stubs': len(stubs), 'caller_sites': len(callers), 'locations': len(locs),
                'named_cases': len(named), 'vectors': sum(counts.values()), 'vector_disagreements': 0, 'distinct_outcomes': len(counts), 'gates': len(GATES), 'status_texts': len(texts)}
    (out / 'evidence.json').write_text(json.dumps(evidence, indent=1, sort_keys=True) + '\n', encoding='ascii')


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--out', required=True)
    generate(ap.parse_args().out)


if __name__ == '__main__':
    main()
