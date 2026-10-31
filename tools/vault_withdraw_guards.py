#!/usr/bin/env python3
"""vaults: node #94 vault withdraw guards: the HLP daily floor inputs and the position reduction loop.

This tool reads ELF bytes only.  It decodes pinned instructions with a small fail-closed x86-64 subset
decoder and evaluates the listed function bodies in Python, with their other calls replaced by named
stubs.  Each result is compared with a plain model over deterministic vectors.  Nothing from the binary runs.

    python3 tools/vault_withdraw_guards.py --out <dir>
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
        if o2 == 0x7e and pre == 0xf3:
            reg, e = modrm(64)
            return done('movq', ('x', reg | r << 3), fin(e, True))
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
    ('vote', 0x2357731, 'ucomisd xmm1,xmm0', 'fraction below 0 refused'),
    ('vote', 0x2357735, 'ja 0x235b84b', 'jump to code 271'),
    ('vote', 0x235773b, 'ucomisd xmm0,[0x20a730]:64', 'fraction above 1 refused'),
    ('vote', 0x2357743, 'ja 0x235b84b', 'jump to code 271'),
    ('vote', 0x2357749, 'movsd.st xmm0,[r13+0x39c8]:64', 'store of max_hlp_withdraw_fraction_per_day'),
    ('vote', 0x235b84f, 'mov [rax]:16,0x10f', 'code 271 (0x10f)'),
    ('begin_block', 0x222a0fa, 'mov raxd,[r14+0x8]:32', 'previous time word kept by the caller'),
    ('begin_block', 0x222a10a, 'lea rsi,[rsp+0x20]:64', 'previous time pointer'),
    ('begin_block', 0x222a112, 'call 0x2702e80', 'snapshot step in the begin block list'),
    ('snapshot', 0x2702e91, 'mov raxd,[rsi]:32', 'date word of the previous block'),
    ('snapshot', 0x2702e93, 'cmp raxd,[rdi+0x60]:32', 'compare with the date word of the block time at +0x60'),
    ('snapshot', 0x2702e96, 'jge 0x2703022', 'same or later: nothing to do'),
    ('snapshot', 0x2702e9c, 'movzx raxd,[rdi+0x8f2]:8', 'chain byte'),
    ('snapshot', 0x2702ea3, 'cmp raxd,0x2', 'below 2: nothing to do'),
    ('snapshot', 0x2702eae, 'movups xmm0,[0x3ef9dc]:128', 'chain 2 address bytes'),
    ('snapshot', 0x2702eba, 'mov [rsp+0x20]:32,0xa0b0eafa', 'chain 2 address tail'),
    ('snapshot', 0x2702ed3, 'movups xmm0,[0x3ef9f0]:128', 'chain above 2 address bytes'),
    ('snapshot', 0x2702edf, 'mov [rsp+0x20]:32,0x3f30de1', 'chain above 2 address tail'),
    ('snapshot', 0x2702fba, 'cmp [r14+0x5c8]:64,0x0', 'clearinghouse count, read only after the vault is found'),
    ('snapshot', 0x2703001, 'call [0x5774968]:64', 'total equity through its slot'),
    ('snapshot', 0x2703007, 'xor rcxd,rcxd', 'floor at 0'),
    ('snapshot', 0x270300c, 'cmovg rcx,rax', 'floor at 0'),
    ('snapshot', 0x2703010, 'mov [r14+0xbb0]:64,0x1', 'Option tag'),
    ('snapshot', 0x270301b, 'mov [r14+0xbb8]:64,rcx', 'Option value'),
    ('entry', 0x26f7297, 'cmp [rdi+0x5c8]:64,0x0', 'clearinghouse count before any work'),
    ('entry', 0x26f72f3, 'call [0x57748c8]:64', 'row producer through its slot, fraction in xmm0'),
    ('entry', 0x26f7301, 'neg rax', 'none word: neg overflows on 0x8000000000000000'),
    ('entry', 0x26f7304, 'jo 0x26f7b7f', 'none word returns at once'),
    ('entry', 0x26f732f, 'add rbx,0x60', 'oracle table from clearinghouse +0x60'),
    ('entry', 0x26f733e, 'call 0x27ae040', 'oracle table'),
    ('entry', 0x26f7343, 'cmp [rbp]:32,0x1', 'flag word 1 computes the 32-byte hash'),
    ('entry', 0x26f7351, 'movzx rsid,[rbp+0x8f2]:8', 'chain byte passed to the hash'),
    ('entry', 0x26f7363, 'call 0x3987cb0', 'hash'),
    ('row', 0x26f7399, 'add [rax+0x7f048d4b]:8,raxb', 'row stride 0x18: len times 3'),
    ('row', 0x26f73a4, 'lea rax,[r14+rax*8]:64', 'row stride 0x18: end pointer'),
    ('row', 0x26f740b, 'movzx raxd,[r14+0x8]:8', 'side byte'),
    ('row', 0x26f7410, 'cmp raxb,0x2', 'side byte 2 ends the walk'),
    ('row', 0x26f7437, 'mov rbx,rdx', 'asset / 10000: 0x346dc5d63886594b'),
    ('row', 0x26f743e, 'imul3 rax,rbx,0x2710', 'asset modulo 10000'),
    ('row', 0x26f7448, 'cmp r13,rsi', 'oracle row bound'),
    ('row', 0x26f7474, 'mul [rcx+rdx*1+0x20]:64', 'size times oracle value, 64 x 64'),
    ('row', 0x26f747f, 'cmp r14,[rsp+0x1a0]:64', 'above 0x7ffffffffffffffe acts'),
    ('row', 0x26f7492, 'cmp [rbp+0x5c8]:64,0x0', 'clearinghouse count checked for a small row'),
    ('row', 0x26f74af, 'cmp r14,0x98967f', 'notional floor 9,999,999'),
    ('row', 0x26f74b6, 'ja 0x26f7520', 'above the floor acts'),
    ('book', 0x26f7520, 'cmp rbx,[rbp+0x3378]:64', 'dex bound'),
    ('book', 0x26f752d, 'imul3 r14,rbx,0x138', 'dex stride 0x138'),
    ('book', 0x26f7578, 'cmp r13,[r14+0x10]:64', 'book bound'),
    ('book', 0x26f758b, 'imul3 r15,r13,0xd8', 'book stride 0xd8'),
    ('book', 0x26f75b3, 'mov rbp,[r14+r15*1+0xb0]:64', 'book asset +0xb0'),
    ('book', 0x26f75cf, 'cmp rdx,[rcx+0x5c8]:64', 'asset of the book over 10000 against the clearinghouse count'),
    ('book', 0x26f7604, 'lea rsi,[r14+0x80]:64', 'book +0x80 for the best keys'),
    ('book', 0x26f7613, 'call 0x23973d0', 'best keys'),
    ('price', 0x26f7641, 'shr rax,0x1', 'midpoint: (a & b) + ((a ^ b) >> 1)'),
    ('price', 0x26f7650, 'jne 0x26f7680', 'no price branch'),
    ('price', 0x26f765c, 'lea rax,[rcx+0xa]:64', 'no price word 0x800000000000000a'),
    ('price', 0x26f7695, 'movsd xmm2,[0x20ac58]:64', 'sell factor 0.97'),
    ('price', 0x26f769d, 'test [rsp+0x7]:8,0x1', 'side byte bit 0 picks 0.97'),
    ('price', 0x26f76a4, 'movsd xmm2,[0x20a770]:64', 'buy factor 1.03'),
    ('price', 0x26f76bc, 'call [0x576f6d8]:64', 'round'),
    ('price', 0x26f76c6, 'maxsd xmm0,xmm1', 'floor at 0'),
    ('price', 0x26f7732, 'cmp r12,0x1', 'zero price becomes 1'),
    ('price', 0x26f7736, 'adc r12,0x0', 'zero price becomes 1'),
    ('price', 0x26f7743, 'call 0x230b390', 'tick'),
    ('price', 0x26f7775, 'inc rdx', 'quotient plus one'),
    ('price', 0x26f7787, 'cmove rdx,rax', 'buy keeps the quotient'),
    ('price', 0x26f778e, 'mul rcx', 'quotient times tick'),
    ('price', 0x26f7794, 'cmp rax,0x1', 'zero limit becomes 1'),
    ('price', 0x26f7798, 'adc rax,0x0', 'zero limit becomes 1'),
    ('record', 0x26f78aa, 'mov [rsp+0x50]:64,0x1', 'record word 0'),
    ('record', 0x26f78b3, 'mov [rsp+0x58]:64,r12', 'record size'),
    ('record', 0x26f78b8, 'mov [rsp+0xc0]:64,0x6', 'record +0x70 tag 6'),
    ('record', 0x26f78c4, 'mov [rsp+0xd0]:64,rsi', 'record limit'),
    ('record', 0x26f78cc, 'mov [rsp+0xd8]:64,rcx', 'record time in ms'),
    ('record', 0x26f78d4, 'mov [rsp+0xe0]:16,0x1', 'record +0x90'),
    ('record', 0x26f78de, 'mov [rsp+0xf2]:8,rbpb', 'record side byte'),
    ('record', 0x26f78fa, 'movupd.st xmm0,[rcx]:128', 'record user: the vault address'),
    ('record', 0x26f78fe, 'mov [rsp+0x11c]:8,0x1', 'record +0xcc: 1'),
    ('record', 0x26f7929, 'call 0x26ebdc0', 'order insert'),
    ('after', 0x26f7937, 'cmp rbx,[rax+0x5c8]:64', 'clearinghouse count for the row dex'),
    ('after', 0x26f7980, 'cmp rcx,rax', 'first word 0x8000000000000000 means error'),
    ('after', 0x26f7a0e, 'call 0x26f4cd0', 'post-insert step'),
    ('after', 0x26f7a24, 'imul3 rsi,r15,0x238', 'filled buffer 0x238 per row'),
    ('after', 0x26f7aa1, 'jle 0x26f73d5', 'error capacity not positive: nothing to free'),
    ('after', 0x26f73f4, 'call 0x24fb610', 'final step on every path'),
    ('exit', 0x26f7b61, 'lea rsi,[r12+r12*2]:64', 'rows freed'),
    ('exit', 0x26f7b7a, 'call 0x2782940', 'oracle table dropped'),
    ('host', 0x2736934, 'mov rdi,[r13+0xbb8]:64', 'hlp_start_of_day_account_value in the vaultTransfer body'),
    ('host', 0x273693b, 'movq xmm0,[r13+0x39c8]:64', 'max_hlp_withdraw_fraction_per_day in the vaultTransfer body'),
    ('host', 0x2736944, 'call 0x26f6050', 'floor = value * (1 - fraction), helper 0x26f6050'),
    ('host', 0x2736a85, 'je 0x2736a9e', 'validation flag gates the reduction loop'),
    ('host', 0x2736a99, 'call 0x26f7280', 'reduction loop'),
]

LAYOUT_ROWS = [
    ('exchange_a', 0x60, 12, 0x2702e93, '[rdi+0x60]:32', 'block time'),
    ('exchange_a', 0x5c8, 8, 0x2702fba, '[r14+0x5c8]:64', 'clearinghouse count'),
    ('exchange_a', 0x8d0, 8, 0x2702ec2, '[rdi+0x8d0]:64', 'vault map root'),
    ('exchange_a', 0x8f2, 1, 0x2702e9c, '[rdi+0x8f2]:8', 'chain byte'),
    ('exchange_a', 0xbb0, 8, 0x2703010, '[r14+0xbb0]:64', 'hlp_start_of_day_account_value tag'),
    ('exchange_a', 0xbb8, 8, 0x270301b, '[r14+0xbb8]:64', 'hlp_start_of_day_account_value value'),
    ('exchange_a', 0x39c8, 8, 0x2357749, '[r13+0x39c8]:64', 'max_hlp_withdraw_fraction_per_day'),
    ('exchange_b', 0x1048, 8, 0x4cf026a, '[r14+0x1048]:64', 'clearinghouse count'),
    ('exchange_b', 0x1350, 8, 0x4cf0172, '[rdi+0x1350]:64', 'vault map root'),
    ('exchange_b', 0x1372, 1, 0x4cf014c, '[rdi+0x1372]:8', 'chain byte'),
    ('exchange_b', 0x1630, 8, 0x4cf02c0, '[r14+0x1630]:64', 'hlp_start_of_day_account_value tag'),
    ('exchange_b', 0x1638, 8, 0x4cf02cb, '[r14+0x1638]:64', 'hlp_start_of_day_account_value value'),
    ('exchange', 0x0, 4, 0x26f7343, '[rbp]:32', 'flag word that enables the hash'),
    ('exchange', 0x8, 8, 0x26f7349, '[rbp+0x8]:64', 'hash input'),
    ('exchange', 0x28, 8, 0x26f734d, '[rbp+0x28]:64', 'hash input'),
    ('exchange', 0x60, 12, 0x26f77a8, '[r9+0x60]:32', 'block time'),
    ('exchange', 0x5c0, 8, 0x26f72ab, '[rdi+0x5c0]:64', 'clearinghouse list'),
    ('exchange', 0x5c8, 8, 0x26f7297, '[rdi+0x5c8]:64', 'clearinghouse count'),
    ('exchange', 0x8f2, 1, 0x26f7351, '[rbp+0x8f2]:8', 'chain byte'),
    ('exchange', 0x3370, 8, 0x26f7534, '[rbp+0x3370]:64', 'dex collections, stride 0x138'),
    ('exchange', 0x3378, 8, 0x26f7520, '[rbp+0x3378]:64', 'dex collection count'),
    ('row', 0x0, 8, 0x26f741c, '[r14]:64', 'asset'),
    ('row', 0x8, 1, 0x26f740b, '[r14+0x8]:8', 'side byte'),
    ('row', 0x10, 8, 0x26f7456, '[r14+0x10]:64', 'size'),
    ('dex', 0x8, 8, 0x26f7587, '[r14+0x8]:64', 'book array'),
    ('dex', 0x10, 8, 0x26f7578, '[r14+0x10]:64', 'book count'),
    ('book', 0xb0, 8, 0x26f75b3, '[r14+r15*1+0xb0]:64', 'asset'),
    ('clearinghouse', 0x68, 8, 0x26f79f8, '[r13+0x68]:64', 'first post-insert argument'),
    ('clearinghouse', 0x70, 8, 0x26f79fc, '[r13+0x70]:64', 'second post-insert argument'),
]

FIELDS = [
    (0x275b33b, 0x275b345, 'max_hlp_withdraw_fraction_per_day', 0x275b332, '[r14+0x39c8]'),
    (0x275b1d9, 0x275b1e3, 'last_hlp_cancel_time', 0x275b1d2, '[r14+0x3a98]'),
    (0x3753aee, 0x3753af8, 'hlp_start_of_day_account_value', 0x3753ae0, '[r14+0xbb0]'),
    (0x3753aee, 0x3753af8, 'hlp_start_of_day_account_value', 0x3753ae7, '[r14+0xbb8]'),
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
    """Byte census of e8 and ff 15/25 sites that land on a path function or a held sub-account helper."""
    rel = img.relative()
    base, body = text_body(img)
    size = len(body)
    targets = {va for va, _ in FUNCS}
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


LOCATIONS = [(0x56e9af8, 'clearinghouse unwrap at entry and after each row'), (0x56e9ae0, 'clearinghouse unwrap for the notional floor and the book asset'), (0x56e9b28, 'dex unwrap of a large row'),
             (0x56bb478, 'book index unwrap'), (0x56bd1a8, 'oracle row bounds')]

FUNCS = [(0x26f7280, 'vault withdraw position reduction loop'), (0x2702e80, 'HLP start of day snapshot, layout A'), (0x4cf0130, 'HLP start of day snapshot, layout B'),
         (0x4cf0330, 'HLP start of day snapshot, layout A second copy')]

STUBS = [(0x5774968, 'total vault equity, 0x3957bc0, in the views packet'), (0x576e488, 'memcmp'), (0x57748c8, 'row producer, 0x37052b0, in open PR #197'), (0x27ae040, 'oracle row table'), (0x3987cb0, '32-byte hash'), (0x23973d0, 'best bid and ask keys'),
         (0x576f6d8, 'round half away from zero, 0x565f410'), (0x230b390, 'tick, in open PR #948'), (0x26ebdc0, 'order insert, in several open PRs'), (0x26f4cd0, 'post-insert step'),
         (0x286ada0, 'filled list iterator'), (0x24fb610, 'final step of each row'), (0x2782940, 'oracle table drop'), (0x3379490, 'drop of a code value'), (0x576e010, 'free'),
         (0x576e8b8, 'Once call')]

I64MAX, I64MIN = (1 << 63) - 1, -(1 << 63)
SENT = 0x10
SP = 0x7f00000
HEAP = 0x8000000
EX = 0x7900000
CH = 0x7a00000
USER = 0x7830000
ORACLE = 0x7c00000
DEXES = 0x7d00000
BOOKS = 0x7e00000
BOOK_N = 0xd8
NONE_ROWS = 0x8000000000000000
NO_PRICE = 0x800000000000000a
FLOOR = 0x98967f


class World:
    """One fixture: a Machine, its bump heap and the named stubs."""

    def __init__(self, img, c):
        self.img, self.c = img, c
        self.m = Machine(img.rd, img.rd, self.hook)
        self.m.cache = img.cache
        self.m.r[4] = SP
        self.heap = HEAP
        self.log = []
        self.xret = None
        self.stubs = {0x57748c8: self.producer, 0x27ae040: self.oracle, 0x3987cb0: self.hash32, 0x23973d0: self.best, 0x576f6d8: self.round_, 0x230b390: self.tick,
                      0x26ebdc0: self.insert, 0x26f4cd0: self.post, 0x286ada0: self.drain, 0x24fb610: self.final, 0x2782940: self.ctx_drop, 0x3379490: lambda *a: 0,
                      0x576e010: self.free, 0x576e048: self.panic_unwrap, 0x576e470: self.panic_rdi, 0x576dfc8: self.panic_bounds, 0x576e8b8: self.once}

    def alloc(self, n):
        a = self.heap
        self.heap += (n + 63) & ~15
        return a

    def hook(self, target, m):
        f = self.stubs.get(target)
        if f is None:
            return False
        self.xret = None
        ret = f(m, m.r[7], m.r[6], m.r[2], m.r[1], m.r[8], m.r[9])
        for i in (1, 2, 6, 7, 8, 9, 10, 11):
            m.r[i] = 0xdead0000dead0000
        for i in range(16):
            m.x[i] = [0x7ff8dead00000000, 0x7ff8dead00000000]
        if self.xret is not None:
            m.x[0][0] = self.xret
        m.r[0] = (ret or 0) & M64
        return True

    def producer(self, m, out, ch, user, *_):
        self.log.append(('producer', ch - CH, m.load(user, 20).hex(), m.x[0][0]))
        rows = self.c['rows']
        if rows is None:
            q(m, out, NONE_ROWS)
            return
        p = self.alloc(max(len(rows), 1) * 0x18)
        for i, (asset, side, size) in enumerate(rows):
            q(m, p + i * 0x18, asset)
            m.store(p + i * 0x18 + 8, bytes((side,)))
            q(m, p + i * 0x18 + 0x10, size)
        q(m, out, max(len(rows), self.c.get('rows_cap', 0)))
        q(m, out + 8, p)
        q(m, out + 16, len(rows))

    def oracle(self, m, out, row, *_):
        self.log.append(('oracle', row - CH))
        q(m, out, 0x55)
        q(m, out + 8, ORACLE)
        q(m, out + 16, len(self.c['prices']))
        for i, p in enumerate(self.c['prices']):
            q(m, ORACLE + i * 0x60 + 0x20, p)

    def hash32(self, m, out, a, b, c, d, *_):
        self.log.append(('hash', a & 0xff, b, c, d))
        m.store(out, bytes(range(0x90, 0xb0)))

    def best(self, m, out, key, *_):
        a, b = self.c['best'][(key - 0x80 - BOOKS) // BOOK_N % 0x1000 if False else self.book_index(key)]
        q(m, out, a)
        q(m, out + 8, b)

    def book_index(self, key):
        return (key - 0x80 - BOOKS) // BOOK_N

    def round_(self, m, *_):
        self.xret = f2i(round_away(i2f(m.x[0][0])))

    def tick(self, m, ch, asset, px, *_):
        self.log.append(('tick', ch - CH, asset, px))
        return self.c['tick']

    def insert(self, m, out, book, rec, flag, r8, ex, *_):
        sp = m.r[4]
        vec = rq(m, sp)
        r = m.load(rec, 0xd0)
        word = struct.unpack_from('<Q', r, 0)[0]
        fields = dict(word0=word, size=struct.unpack_from('<Q', r, 8)[0], w10=struct.unpack_from('<Q', r, 0x10)[0], w20=struct.unpack_from('<Q', r, 0x20)[0], w30=struct.unpack_from('<Q', r, 0x30)[0],
                      w38=struct.unpack_from('<Q', r, 0x38)[0], w70=struct.unpack_from('<Q', r, 0x70)[0], limit=struct.unpack_from('<Q', r, 0x80)[0], ms=struct.unpack_from('<Q', r, 0x88)[0],
                      w90=struct.unpack_from('<H', r, 0x90)[0], side=r[0xa2], wa8=struct.unpack_from('<Q', r, 0xa8)[0], user=r[0xb8:0xcc].hex(), tif=r[0xcc])
        self.log.append(('insert', (book - BOOKS) // BOOK_N, fields, flag & 0xffffffff, ex - EX, rq(m, vec), rq(m, vec + 16)))
        kind = self.c.get('result', 'ok')
        if kind == 'err':
            q(m, out, NONE_ROWS)
            q(m, out + 8, 24)
            q(m, out + 16, 0x4444)
        elif kind == 'err0':
            q(m, out, NONE_ROWS)
            q(m, out + 8, 0)
        else:
            q(m, out, 3 if kind == 'filled' else 0)
            q(m, out + 8, 0x9000)
            q(m, out + 16, 1)
            q(m, out + 24, 2 if kind == 'filled' else 0)
            q(m, out + 32, 0x9100)
            q(m, out + 40, 2)

    def post(self, m, a, b, c, d, e, r9, *_):
        sp = m.r[4]
        self.log.append(('post', a, b, c, d, m.load(e, 1).hex(), m.load(e + 1, 32).hex(), r9 & 0xffffffff, rq(m, sp)))

    def drain(self, m, out, *_):
        self.log.append(('drain',))
        q(m, out, 0)

    def final(self, m, vec, dex, ex, *_):
        self.log.append(('final', dex, ex - EX))

    def ctx_drop(self, m, ctx, *_):
        self.log.append(('ctx_drop', rq(m, ctx)))

    def free(self, m, p, n, *_):
        self.log.append(('free', n))

    def once(self, m, *_):
        self.log.append(('once',))

    def panic_unwrap(self, m, msg, n, payload, vt, loc, *_):
        raise Panic('unwrap', loc)

    def panic_rdi(self, m, loc, *_):
        raise Panic('panic', loc)

    def panic_bounds(self, m, i, n, loc, *_):
        raise Panic('bounds', loc)


def round_away(x):
    if x != x or abs(x) >= 2.0 ** 52:
        return x
    f = math.floor(abs(x))
    if abs(x) - f >= 0.5:
        f += 1
    return math.copysign(f, x)


def days_ms(t):
    word, secs, nanos = t
    y = sx(word & 0xffffffff, 32) >> 13
    ordinal = (word >> 4) & 0x1ff
    shift = 0
    y1 = y - 1
    if y <= 0:
        k = (1 - y) // 400 + 1
        y1 += k * 400
        shift = -k * 146097
    days = ordinal + shift + (1461 * y1 >> 2) - y1 // 100 + (y1 // 100 >> 2) - 719163
    return max(days * 86400000 + secs * 1000 + nanos // 1000000, 0)


def date_word(year, ordinal, flags=3):
    return (year << 13 | ordinal << 4 | flags) & 0xffffffff


def fixture(w, c):
    m = w.m
    q(m, EX, c.get('flag', 1))
    q(m, EX + 8, 0x1111)
    q(m, EX + 0x28, 0x2222)
    m.store(EX + 0x60, struct.pack('<III', *c['now']))
    m.store(EX + 0x8f2, bytes((c.get('chain', 3),)))
    q(m, EX + 0x5c0, CH)
    q(m, EX + 0x5c8, c.get('chs', 1))
    q(m, EX + 0x3370, DEXES)
    q(m, EX + 0x3378, c.get('dexes', 1))
    for i in range(4):
        q(m, CH + i * 0x2f0 + 0x68, 0xa000 + i)
        q(m, CH + i * 0x2f0 + 0x70, 0xb000 + i)
    for d in range(c.get('dexes', 1)):
        q(m, DEXES + d * 0x138 + 8, BOOKS)
        q(m, DEXES + d * 0x138 + 0x10, len(c['best']))
    for i, asset in enumerate(c['book_assets']):
        q(m, BOOKS + i * BOOK_N + 0xb0, asset)
    m.store(USER, c['user'])
    m.store(0x577ab98, bytes(4))
    q(m, 0x576e010, 0x576e010)


def run_close(img, c):
    w = World(img, c)
    m = w.m
    fixture(w, c)
    m.x[0][0] = f2i(c['fraction'])
    m.r[4] -= 8
    q(m, m.r[4], SENT)
    m.r[7], m.r[6] = EX, USER
    try:
        m.run(0x26f7280, {SENT}, 200000)
    except Panic as e:
        return {'panic': e.args[0], 'loc': e.args[1], 'log': w.log}
    return {'log': w.log}


def limit_of(a, b, side, tick):
    mid = (a & b) + ((a ^ b) >> 1)
    x = float(mid >> 32) * 4294967296.0 + float(mid & 0xffffffff)
    x = round_away(x * (0.97 if side & 1 else 1.03))
    x = max(x, 0.0)
    p = 0 if x <= 0 else M64 if x > 1.844674407370955e19 else int(x)
    p = max(p, 1)
    d = p // tick
    if side & 1:
        d = min(d + 1, M64)
    v = d * tick
    return p, M64 if v > M64 else max(v, 1)


def model_close(c):
    log = [('producer', 0, c['user'].hex(), f2i(c['fraction']))]
    res = {'log': log}

    def stop(kind, loc):
        return {'panic': kind, 'loc': loc, 'log': log}

    if c.get('chs', 1) == 0:
        return {'panic': 'unwrap', 'loc': 0x56e9af8, 'log': []}
    rows = c['rows']
    if rows is None:
        return res
    log.append(('oracle', 0x60))
    if c.get('flag', 1) == 1:
        log.append(('hash', c.get('chain', 3), 0x2222, 0x1111, 0))
    ms = days_ms(c['now'])
    dexes = c.get('dexes', 1)
    for asset, side, size in rows:
        if side == 2:
            break
        dex, local = asset // 10000, asset % 10000
        if local >= len(c['prices']):
            return stop('bounds', 0x56bd1a8)
        n = size * c['prices'][local]
        low = n & M64
        if n >> 64 == 0 and low <= 0x7ffffffffffffffe and low <= FLOOR:
            continue
        if dex >= dexes:
            return stop('unwrap', 0x56e9b28)
        if local >= len(c['best']):
            return stop('unwrap', 0x56bb478)
        book_asset = c['book_assets'][local]
        bdex = book_asset // 10000
        if bdex >= c.get('chs', 1):
            return stop('unwrap', 0x56e9ae0)
        a, b = c['best'][local]
        word = NO_PRICE
        if a and b:
            px, limit = limit_of(a, b, side, c['tick'])
            log.append(('tick', bdex * 0x2f0, book_asset, px))
            log.append(('insert', local, dict(word0=1, size=size, w10=0, w20=0, w30=0, w38=8, w70=6, limit=limit, ms=ms, w90=1, side=side, wa8=0, user=c['user'].hex(), tif=1), 0, 0, 0, 0))
            word = None
        if dex >= c.get('chs', 1):
            return stop('unwrap', 0x56e9af8)
        kind = c.get('result', 'ok')
        if word is None and kind in ('ok', 'filled'):
            log.append(('post', 0xa000 + dex, 0xb000 + dex, 0x9000, 1, '01', bytes(range(0x90, 0xb0)).hex() if c.get('flag', 1) == 1 else bytes(32).hex(), 0, 0))
            if kind == 'filled':
                log.append(('free', 3 * 0x238))
            log.append(('drain',))
        elif word is None and kind == 'err':
            log.append(('free', 24))
        log.append(('final', dex, 0))
    if rows or c.get('rows_cap'):
        log.append(('free', max(len(rows), c.get('rows_cap', 0)) * 0x18))
    log.append(('ctx_drop', 0x55))
    return res



SNAP = {0x2702e80: 'A', 0x4cf0130: 'B', 0x4cf0330: 'A'}
SPECIAL = {2: (0x3ef9dc, 0xa0b0eafa), 3: (0x3ef9f0, 0x3f30de1)}
SPECIAL_B = {2: (0x714cb6, 0xa0b0eafa), 3: (0x714cca, 0x3f30de1)}
LAYOUT = {'A': dict(ch=0x5c0, vaults=0x8d0, chain=0x8f2, snap=0xbb0), 'B': dict(ch=0x1040, vaults=0x1350, chain=0x1372, snap=0x1630)}
TIME = 0x7850000
VAULT_TREE = dict(key=0x798, key_len=20, val=0, val_len=0xb0, len=0x876, edge=0x878, size=0x8e0)


class SnapWorld:
    """Fixture of the snapshot step: the total equity call is a stub here."""

    def __init__(self, img, c):
        self.c = c
        self.m = Machine(img.rd, img.rd, self.hook)
        self.m.cache = img.cache
        self.m.r[4] = SP
        self.heap = HEAP
        self.log = []
        self.stubs = {0x5774968: self.total, 0x576e488: self.memcmp, 0x3379490: lambda *a: 0, 0x576e048: self.panic_unwrap}
        q(self.m, 0x576e488, 0x576e488)

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

    def total(self, m, value, ctx, *_):
        self.log.append((m.load(value + 0x84, 20).hex(), rq(m, ctx), rq(m, ctx + 8), rq(m, ctx + 16)))
        return self.c['total']

    def memcmp(self, m, a, b, n, *_):
        x, y = m.load(a, n), m.load(b, n)
        return ((x > y) - (x < y)) & M64

    def panic_unwrap(self, m, msg, n, payload, vt, loc, *_):
        raise Panic('unwrap', loc, m.load(payload, 2))


def map_tree(w, keys):
    """Write sorted vault keys as a map of height 0 or 1 and return (root, height)."""
    m = w.m
    g = VAULT_TREE

    def node(rows, edges=()):
        n = w.alloc(g['size'])
        m.store(n, bytes(g['size']))
        for i, k in enumerate(rows):
            m.store(n + g['key'] + i * 20, k)
            m.store(n + g['val'] + i * g['val_len'] + 0x84, k)
        m.store(n + g['len'], len(rows).to_bytes(2, 'little'))
        for i, e in enumerate(edges):
            q(m, n + g['edge'] + i * 8, e)
        return n
    if len(keys) <= 11:
        return node(keys), 0
    mid = len(keys) // 2
    return node(keys[mid:mid + 1], [node(keys[:mid]), node(keys[mid + 1:])]), 1


def special_address(img, chain, layout='A'):
    p, tail = (SPECIAL if layout == 'A' else SPECIAL_B)[2 if chain == 2 else 3]
    return img.rd(p, 16) + tail.to_bytes(4, 'little')


def run_snapshot(img, c):
    fn = c['fn']
    g = LAYOUT[SNAP[fn]]
    w = SnapWorld(img, c)
    m = w.m
    now = c.get('now', (date_word(2026, 300), 0, 0))
    m.store(EX + 0x60, struct.pack('<III', *now))
    q(m, EX + g['ch'], CH)
    q(m, EX + g['ch'] + 8, c.get('chs', 1))
    m.store(EX + g['chain'], bytes((c.get('chain', 3),)))
    q(m, EX + g['snap'], c.get('snap', (0, 0))[0])
    q(m, EX + g['snap'] + 8, c.get('snap', (0, 0))[1])
    if c['keys']:
        root, height = map_tree(w, sorted(set(c['keys'])))
        q(m, EX + g['vaults'], root)
        q(m, EX + g['vaults'] + 8, height)
    m.store(TIME, struct.pack('<III', *c['prev']))
    m.r[4] -= 8
    q(m, m.r[4], SENT)
    m.r[7], m.r[6] = EX, TIME
    try:
        m.run(fn, {SENT}, 200000)
    except Panic as e:
        return {'panic': e.args[0], 'loc': e.args[1], 'code': int.from_bytes(e.args[2], 'little')}
    return {'snap': (rq(m, EX + g['snap']), rq(m, EX + g['snap'] + 8)), 'calls': w.log}


def want_snapshot(img, c):
    layout = SNAP[c['fn']]
    now = c.get('now', (date_word(2026, 300), 0, 0))
    res = {'snap': c.get('snap', (0, 0)), 'calls': []}
    if sx(c['prev'][0] & 0xffffffff, 32) >= sx(now[0] & 0xffffffff, 32) or c.get('chain', 3) < 2:
        return res
    sp = special_address(img, c.get('chain', 3), layout)
    if sp not in c['keys']:
        return res
    if c.get('chs', 1) == 0:
        return {'panic': 'unwrap', 'loc': 0x56e9ae0, 'code': 0x141}
    return {'snap': (1, max(i64(c['total']), 0) & M64), 'calls': [(sp.hex(), CH, EX + 0x80, EX + 0x498)]}


def snapshot_cases(img, n):
    s = Stream('vault-snapshot')
    for i in range(n):
        fn = (0x2702e80, 0x4cf0130, 0x4cf0330)[i % 3]
        chain = s.pick([0, 1, 2, 3, 3, 4, 255])
        sp = special_address(img, chain if chain >= 2 else 3, SNAP[fn])
        keys = [addr(30 + j) for j in range(s.pick([0, 1, 3, 12]))] + ([sp] if s.u(4) else [])
        prev = s.pick([(date_word(2026, 299), 86399, 0), (date_word(2026, 299), 0, 0), (date_word(2026, 300), 0, 0), (date_word(2026, 301), 0, 0), (date_word(2025, 365), 0, 0), (date_word(2026, 300, 0), 0, 0), (date_word(2026, 300, 2), 0, 0)])
        yield dict(fn=fn, chain=chain, keys=keys, now=(date_word(2026, 300), 7, 9), prev=prev, total=s.pick([0, 1, 5000000, -5, 1 << 62, I64MAX]) & M64, snap=s.pick([(0, 0), (1, 77)]), chs=0 if s.u(16) == 0 else 1)


def field_rows(img):
    rows = []
    for lea, ln, name, off_va, operand in FIELDS:
        i, j = decode(img.rd, lea), decode(img.rd, ln)
        key = img.rd(i.args[1][1], j.args[1][1]).decode('ascii')
        if key != name:
            raise ValueError(f'field at {lea:#x}: {key}')
        text = decode(img.rd, off_va).text()
        if operand not in text:
            raise ValueError(f'field operand at {off_va:#x}: {text}')
        rows.append((f'{lea:#x}', key, str(j.args[1][1]), f'{off_va:#x}', text))
    return rows


def same(got, want):
    """The stack pointer word of the post step is the vector frame; it is compared by presence only."""
    def norm(row):
        return row[:-1] + (0,) if row[0] == 'post' else row
    g, w = dict(got), dict(want)
    g['log'] = [norm(r) for r in got['log']]
    w['log'] = [norm(r) for r in want['log']]
    return g == w


def book_set(s, n):
    return [s.pick([(1000000, 1000100), (1000001, 1000100), (0, 5), (5, 0), (2500000, 2500000), (1, 1), (1 << 62, 1 << 63), (M64, M64), (M64 >> 1, M64 >> 1)]) for _ in range(n)]


def cases(n):
    s = Stream('vault-close')
    for _ in range(n):
        count = s.pick([2, 3])
        prices = [s.pick([1, 10, 5000000, 1 << 40]) for _ in range(count)]
        best = book_set(s, count)
        assets = [s.pick([i, i, 10000 + i, 30000 + i]) if s.u(8) == 0 else i for i in range(count)]
        rows = []
        for _ in range(s.pick([0, 1, 2, 3])):
            dex = s.pick([0, 0, 0, 1, 7])
            rows.append((dex * 10000 + s.u(count + (s.u(8) == 0)), s.pick([0, 1, 0, 1, 1, 2]) if s.u(4) == 0 else s.u(2),
                         s.pick([1, 1999, 2000, 9999999, 10000000, 1 << 62, M64])))
        r = None if s.u(12) == 0 else rows
        yield dict(fraction=s.pick([0.5, 0.2, 1e-9]), user=addr(1), rows=r, prices=prices, best=best, book_assets=assets, tick=s.pick([1, 100, 7, 1 << 40]), flag=s.u(2), chain=s.pick([1, 2, 3]),
                   chs=s.pick([0, 1, 1, 1, 2, 2]), dexes=s.pick([1, 1, 2]), result=s.pick(['ok', 'ok', 'filled', 'err', 'err0']), now=s.pick([(date_word(2026, 300), 7, 999999), (date_word(1969, 300), 0, 0), (date_word(2026, 1, 7), 86399, 1999999999)]),
                   rows_cap=s.pick([0, 0, 8]))


def evaluate(img, n=1200):
    counts = {}
    bad = []
    for c in snapshot_cases(img, n // 2):
        got, want = run_snapshot(img, c), want_snapshot(img, c)
        key = ('snapshot', SNAP[c['fn']], 'panic' if 'panic' in got else 'written' if got.get('calls') else 'kept')
        counts[key] = counts.get(key, 0) + 1
        if got != want:
            bad.append(('snapshot', got, want))
    for c in cases(n):
        got, want = run_close(img, c), model_close(c)
        ok = same(got, want)
        label = got.get('panic') or 'return'
        key = ('close', label, f"inserts={min(sum(1 for r in got['log'] if r[0] == 'insert'), 2)}")
        counts[key] = counts.get(key, 0) + 1
        if not ok:
            bad.append(('close', got, want))
    return counts, bad


def base(**k):
    c = dict(fraction=0.5, user=addr(1), rows=[(0, 1, 2000)], prices=[5000], best=[(1000000, 1000100)], book_assets=[0], tick=100, flag=1, chain=3, chs=1, dexes=1, result='ok', now=(date_word(2026, 300), 7, 9000000))
    c.update(k)
    return c


def named_cases(img):
    rows = []
    sp = special_address(img, 3)
    day, nxt = date_word(2026, 299), date_word(2026, 300)

    def snap(name, **k):
        c = dict(fn=0x2702e80, chain=3, keys=[sp], now=(nxt, 7, 9), prev=(day, 86399, 0), total=5000000, snap=(0, 0))
        c.update(k)
        got, want = run_snapshot(img, c), want_snapshot(img, c)
        rows.append(('snapshot: ' + name, got.get('panic', 'return'), json.dumps(got.get('snap')), json.dumps([r[0] for r in got.get('calls', [])]), 'same' if got == want else 'DIFF'))

    snap('first block of a new date stores Some(total)')
    snap('same date: stored value kept', prev=(nxt, 0, 0), snap=(1, 77))
    snap('previous date later than now: kept', prev=(date_word(2026, 301), 0, 0), snap=(1, 77))
    snap('chain byte 1: no compare, kept', chain=1, snap=(1, 77))
    snap('no HLP vault: kept', keys=[addr(2)], snap=(1, 77))
    snap('negative total stores Some(0)', total=(-5) & M64)
    snap('no clearinghouse: panic only after the vault is found', chs=0)

    def n(name, **k):
        c = base(**k)
        got, want = run_close(img, c), model_close(c)
        ins = [r[2] for r in got['log'] if r[0] == 'insert']
        rows.append((name, got.get('panic', 'return'), json.dumps([(i['side'], i['size'], i['limit']) for i in ins]), json.dumps([r[0] for r in got['log']]), 'same' if same(got, want) else 'DIFF'))

    n('sell at 0.97 of the midpoint, plus one tick')
    n('sell on an exact multiple still adds a tick', best=[(2500000, 2500000)])
    n('buy at 1.03 of the midpoint, down to a tick', rows=[(0, 0, 2000)])
    n('price below one tick on a buy: limit becomes 1', rows=[(0, 0, 2000)], best=[(1, 1)])
    n('notional 9999999 skipped', rows=[(0, 1, 1999)], prices=[5000])
    n('notional 10000000 acts', rows=[(0, 1, 2000)], prices=[5000])
    n('notional past 64 bits acts', rows=[(0, 1, 1 << 62)], prices=[1 << 40])
    n('no bid or no ask: no order, final step still runs', best=[(0, 5)])
    n('side byte 2 ends the walk', rows=[(0, 2, 2000), (0, 1, 2000)])
    n('producer none: returns before the oracle table', rows=None)
    n('insert error: no post step, buffer freed', result='err')
    n('insert error with capacity 0: nothing freed', result='err0')
    n('filled rows are drained after the post step', result='filled')
    n('flag word not 1: hash stays zero', flag=0)
    n('no clearinghouse: panic before the producer', chs=0)
    n('oracle index past the table: bounds panic', rows=[(1, 1, 2000)])
    n('dex past the collection: panic only for a large row', rows=[(70000, 1, 2000)])
    n('dex past the collection, small row: skipped', rows=[(70000, 1, 1)])
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
    fields = field_rows(img)
    write_tsv(out / 'state-fields.tsv', ('lea', 'name', 'length', 'va', 'instruction'), fields)
    write_tsv(out / 'functions.tsv', ('start', 'end', 'bytes', 'sha256', 'role'), funcs)
    write_tsv(out / 'stubs.tsv', ('site', 'kind', 'target', 'fde_start', 'fde_end', 'role'), stubs)
    write_tsv(out / 'callers.tsv', ('function', 'site', 'kind', 'site_fde'), callers)
    write_tsv(out / 'pins.tsv', ('group', 'va', 'instruction', 'meaning'), pins)
    write_tsv(out / 'layout.tsv', ('struct', 'offset', 'width', 'va', 'instruction', 'meaning'), layout)
    write_tsv(out / 'locations.tsv', ('record', 'path', 'line', 'column', 'use'), locs)
    write_tsv(out / 'outcomes.tsv', ('family', 'result', 'class', 'vectors'), [(k[0], k[1], k[2], v) for k, v in sorted(counts.items())])
    write_tsv(out / 'cases.tsv', ('scenario', 'result', 'orders', 'calls', 'model'), named)
    constants = [('sell factor', 0x20ac58, i2f(int.from_bytes(img.rd(0x20ac58, 8), 'little'))), ('buy factor', 0x20a770, i2f(int.from_bytes(img.rd(0x20a770, 8), 'little')))]
    evidence = {'binary': BINARY, 'sha256': SHA256, 'pins': len(pins), 'layout_rows': len(layout), 'functions': len(funcs), 'function_bytes': sum(int(r[2]) for r in funcs), 'stubs': len(stubs),
                'caller_sites': len(callers), 'locations': len(locs), 'named_cases': len(named), 'vectors': sum(counts.values()), 'vector_disagreements': 0, 'distinct_outcomes': len(counts),
                'factors': {n: {'va': hex(va), 'value': repr(v)} for n, va, v in constants}, 'notional_floor': FLOOR, 'state_fields': len(fields),
                'hlp_vault': {'chain_2': special_address(img, 2).hex(), 'chain_3': special_address(img, 3).hex()}}
    (out / 'evidence.json').write_text(json.dumps(evidence, indent=1, sort_keys=True) + '\n', encoding='ascii')


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--out', required=True)
    generate(ap.parse_args().out)


if __name__ == '__main__':
    main()
