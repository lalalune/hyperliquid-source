#!/usr/bin/env python3
"""vaults: the node #94 vault lifecycle paths: create, vote modify, deposit and share rewrite.

Create is 0x2732e60 -> 0x395af60 -> 0x395b3a0.  Vote modify is 0x2704b60 -> 0x3959900.
Deposit is 0x27362b0 -> 0x395b3a0 -> 0x395a2c0, with 0x3955e80 (account equity), two
address lists and one record reader.  This tool reads ELF bytes only.  It decodes the pinned
instructions with a small fail-closed x86-64 subset decoder and evaluates seven call-free
byte spans plus the create and modify bodies in Python binary64 arithmetic, with their
calls replaced by named stubs.  Each is compared with a plain formula over deterministic
vectors.  Nothing from the binary runs.

    python3 tools/vault_lifecycle_path.py --out <dir>

writes evidence.json, functions.tsv, callers.tsv, callees.tsv, pins.tsv, layout.tsv,
vault_fields.tsv, address_lists.tsv, locations.tsv, vectors.tsv and outcomes.tsv.
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
RECORDER = 0x358dcd0
GRID = 512
STORES = {'mov', 'add', 'sub', 'and', 'or', 'xor', 'inc', 'dec'}

M64 = (1 << 64) - 1
SCRATCH = 0x7000000
REGS = ['rax', 'rcx', 'rdx', 'rbx', 'rsp', 'rbp', 'rsi', 'rdi', 'r8', 'r9', 'r10', 'r11', 'r12', 'r13', 'r14', 'r15']
ALU = {0x00: 'add', 0x08: 'or', 0x20: 'and', 0x28: 'sub', 0x30: 'xor', 0x38: 'cmp'}
GRP1 = ['add', 'or', 'adc', 'sbb', 'and', 'sub', 'xor', 'cmp']
CC = ['o', 'no', 'b', 'ae', 'e', 'ne', 'be', 'a', 's', 'ns', 'p', 'np', 'l', 'ge', 'le', 'g']
SSE = {(0xf2, 0x10): 'movsd', (0xf2, 0x11): 'movsd.st', (0xf2, 0x59): 'mulsd', (0xf2, 0x5e): 'divsd', (0xf2, 0x58): 'addsd',
       (0xf2, 0x5c): 'subsd', (0xf2, 0x5f): 'maxsd', (0xf2, 0x5d): 'minsd', (0x66, 0x2e): 'ucomisd', (0x66, 0xef): 'pxor',
       (0, 0x57): 'xorps', (0x66, 0x57): 'xorpd', (0x66, 0x6f): 'movdqa', (0x66, 0x28): 'movapd', (0, 0x28): 'movaps',
       (0x66, 0x62): 'punpckldq', (0x66, 0x5c): 'subpd', (0x66, 0x15): 'unpckhpd', (0xf3, 0x6f): 'movdqu',
       (0, 0x10): 'movups', (0, 0x11): 'movups.st', (0x66, 0x7f): 'movdqa.st', (0xf3, 0x7f): 'movdqu.st', (0, 0x29): 'movaps.st', (0x66, 0x29): 'movapd.st', (0x66, 0x10): 'movupd', (0x66, 0x11): 'movupd.st', (0x66, 0x74): 'pcmpeqb', (0x66, 0xdb): 'pand'}


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
        s = REGS[a[1]]
        if a[2] is not None:
            s += f'+{REGS[a[2]]}*{a[3]}'
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
                raise ValueError(f'unsupported SIB at {va:#x}')
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
        if reg != 0:
            raise ValueError(f'f6 /{reg} at {va:#x}')
        return done('test', fin(e), ('i', imm(1) & 255))
    if op == 0xf7:
        reg, e = modrm(bits)
        if reg == 3:
            return done('neg', fin(e))
        if reg != 4:
            raise ValueError(f'f7 /{reg} at {va:#x}')
        return done('mul', fin(e))
    if op == 0x90:
        return done('nop')
    if op == 0xff:
        reg, e = modrm(64)
        if reg == 2:
            return done('call', fin(e))
        if reg in (0, 1):
            return done(('inc', 'dec')[reg], fin(e))
        raise ValueError(f'ff /{reg} at {va:#x}')
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
        if reg not in (4, 5, 7):
            raise ValueError(f'c1 /{reg} at {va:#x}')
        return done({4: 'shl', 5: 'shr', 7: 'sar'}[reg], fin(e), ('i', v & 255))
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
    def __init__(self, code, rodata, hook):
        self.code, self.rodata, self.hook = code, rodata, hook
        self.r = [0] * 16
        self.x = [[0, 0] for _ in range(16)]
        self.mem = {}
        self.cf = self.zf = self.sf = self.of = self.pf = False
        self.records = []

    def ea(self, a):
        if a[0] == 'rip':
            return a[1]
        return (self.r[a[1]] + (self.r[a[2]] * a[3] if a[2] is not None else 0) + a[4]) & M64

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
            i = decode(self.code, pc)
            trace.append(pc)
            pc += i.size
            op, a = i.op, i.args
            if op == 'mov' or op == 'movzx':
                self.put(a[0], self.get(a[1]))
            elif op == 'lea':
                self.put(a[0], self.ea(a[1]))
            elif op in ('add', 'sub', 'cmp', 'and', 'xor', 'or', 'test'):
                bits = a[0][2] if a[0][0] == 'r' else a[0][-1]
                m = (1 << bits) - 1
                u, v = self.get(a[0]), self.get(a[1])
                if op == 'add':
                    res = (u + v) & m
                    self.cf = u + v > m
                    self.of = bool((~(u ^ v) & (u ^ res)) >> (bits - 1) & 1)
                elif op in ('sub', 'cmp'):
                    res = (u - v) & m
                    self.cf = u < v
                    self.of = bool(((u ^ v) & (u ^ res)) >> (bits - 1) & 1)
                else:
                    res = {'and': u & v, 'test': u & v, 'xor': u ^ v, 'or': u | v}[op]
                    self.flags_logic(res, bits)
                self.zf = res == 0
                self.sf = bool(res >> (bits - 1) & 1)
                if op not in ('cmp', 'test'):
                    self.put(a[0], res)
            elif op == 'push':
                self.r[4] -= 8
                self.store(self.r[4], self.get(a[0]).to_bytes(8, 'little'))
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
                v = sx(self.get(a[0]), 64) >> a[1][1]
                self.put(a[0], v & M64)
            elif op == 'shl':
                self.put(a[0], self.get(a[0]) << a[1][1])
            elif op == 'shr':
                self.put(a[0], self.get(a[0]) >> a[1][1])
            elif op == 'mul':
                res = self.r[0] * self.get(a[0])
                self.r[0], self.r[2] = res & M64, res >> 64
            elif op.startswith('set'):
                self.put(a[0], int(self.cond(op[3:])))
            elif op.startswith('cmov'):
                if self.cond(op[4:]):
                    self.put(a[0], self.get(a[1]))
                elif a[0][2] == 32:
                    self.put(a[0], self.get(a[0]))
            elif op == 'jmp':
                pc = a[0][1]
            elif op[0] == 'j':
                if self.cond(op[1:]):
                    pc = a[0][1]
            elif op == 'call':
                if a[0][0] not in ('rip', 't') or not self.hook(a[0][1], self):
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


PINS = [
    ('entry', 0x2736738, 'cmp [rsp+0x7]:8,0x0', 'byte is_deposit test in the transfer host'),
    ('entry', 0x2736742, 'je 0x273675c', 'zero byte leaves for the withdraw arm'),
    ('entry', 0x2736744, 'cmp r14,0x4c4b40', 'deposit minimum 5000000 raw units'),
    ('entry', 0x273674b, 'jae 0x27367b4', 'at or above the minimum continues to the deposit call'),
    ('entry', 0x2736752, 'mov [rax]:16,0x29', 'below the minimum stores code 41'),
    ('entry', 0x2736815, 'xor r9d,r9d', 'deposit from the transfer host passes flag 0'),
    ('entry', 0x2736819, 'call [0x5774b48]:64', 'call through the slot of 0x395b3a0'),
    ('entry', 0x4d42684, 'cmp r14,0x4c4b40', 'same minimum in the second transfer host copy'),
    ('entry', 0x4d42692, 'mov [rax]:16,0x29', 'second copy stores code 41'),
    ('entry', 0x4d42758, 'xor r9d,r9d', 'second copy passes flag 0'),
    ('entry', 0x4d4275c, 'call [0x5774b48]:64', 'second copy calls 0x395b3a0'),
    ('entry', 0x4d465c4, 'cmp r14,0x4c4b40', 'same minimum in the third transfer host copy'),
    ('entry', 0x4d465d2, 'mov [rax]:16,0x29', 'third copy stores code 41'),
    ('entry', 0x4d46695, 'xor r9d,r9d', 'third copy passes flag 0'),
    ('entry', 0x4d46699, 'call [0x5774b48]:64', 'third copy calls 0x395b3a0'),
    ('entry', 0x395b1d6, 'mov r9d,0x1', 'create-vault deposit passes flag 1'),
    ('entry', 0x395b1dc, 'call [0x5774b48]:64', '0x395af60 calls 0x395b3a0'),
    ('g1', 0x395b3c0, 'cmp r15,0x1', 'relationship tag compared with 1 (child)'),
    ('g1', 0x395b3c4, 'jne 0x395b403', 'other tags skip gate 1'),
    ('g1', 0x395b3f1, 'cmp raxd,0xffff', '20-byte compare of depositor with leader +0x98'),
    ('g1', 0x395b3f6, 'je 0x395b403', 'leader passes gate 1'),
    ('g1', 0x395b3f8, 'mov [rdi+0x8]:16,0x16', 'child vault and depositor not leader: code 22'),
    ('g2', 0x395b403, 'cmp [r14+0xad]:8,0x0', 'allow_deposits compared with 0'),
    ('g2', 0x395b40b, 'jne 0x395b44a', 'deposits on passes gate 2'),
    ('g2', 0x395b43d, 'je 0x395b44a', 'leader passes gate 2'),
    ('g2', 0x395b43f, 'mov [rdi+0x8]:16,0x17', 'deposits off and depositor not leader: code 23'),
    ('total', 0x395b494, 'lea rsi,[r14+0x84]:64', 'vault address +0x84'),
    ('total', 0x395b4a8, 'call 0x3955e80', 'equity of the vault address'),
    ('total', 0x395b4b0, 'cmp r15d,0x2', 'tag below 2 skips the child walk'),
    ('total', 0x395b4c2, 'jb 0x395b749', 'branch past the child walk'),
    ('total', 0x395b6cc, 'call 0x3955e80', 'equity of one child, saturating sum in r12'),
    ('g3', 0x395b74c, 'test r12,r12', 'sign of the summed total'),
    ('g3', 0x395b74f, 'jns 0x395b764', 'total >= 0 passes gate 3'),
    ('g3', 0x395b756, 'call [0x5773230]:64', 'negative total asks list A (0x37e4e50) about the vault address'),
    ('g3', 0x395b75e, 'je 0x395bb3f', 'not on list A leaves for code 9'),
    ('g3', 0x395bb44, 'mov [rdi+0x8]:16,0x9', 'negative total and vault not on list A: code 9'),
    ('g4', 0x395b764, 'cmp [rsp+0x8]:8,0x0', 'flag argument (saved r9b)'),
    ('g4', 0x395b771, 'je 0x395b7ee', 'flag 0 runs the exemption tests, flag 1 goes straight to the balance check'),
    ('g4', 0x395b829, 'cmp [rsp+0x20]:32,0x1', 'child vault skips the leader share gate'),
    ('g4', 0x395b82e, 'je 0x395b773', 'branch to balance check'),
    ('g4', 0x395b838, 'je 0x395b773', 'depositor equal to leader skips the leader share gate'),
    ('g4', 0x395b843, 'call [0x5773228]:64', 'list B (0x37e4fb0) about the vault address'),
    ('g4', 0x395b84b, 'jne 0x395b773', 'on list B skips the leader share gate'),
    ('g4', 0x395b858, 'je 0x395bc04', 'empty record map: code 2'),
    ('g4', 0x395b90a, 'jb 0x395bc04', 'leader has no record: code 2'),
    ('g4', 0x395b8f2, 'jmp 0x395bb4f', 'leader record found, go to the share arithmetic'),
    ('g4', 0x395bb57, 'mulsd xmm0,[r15]:64', 'leader equity = total as f64 * share'),
    ('g4', 0x395bbd7, 'divsd xmm2,[0x20ae60]:64', 'equity / 1e6'),
    ('g4', 0x395bbe9, 'add rax,r13', 'u64 add of max(total, 0) and amount'),
    ('g4', 0x395bbec, 'jb 0x395bcf1', 'carry goes to the saturating recorder arm'),
    ('g4', 0x395bbfe, 'jbe 0x395bd2c', 'equity at or above 1e-7 continues'),
    ('g4', 0x395bc09, 'mov [rdi+0x8]:16,0x2', 'leader share gate failure: code 2'),
    ('g4', 0x395bd61, 'ja 0x395bc04', 'denominator below 1e-15: code 2'),
    ('g4', 0x395bd67, 'divsd xmm2,xmm0', 'equity / new total'),
    ('g4', 0x395bd6b, 'movsd xmm0,[0x20a4c0]:64', 'constant 0.05'),
    ('g4', 0x395bd73, 'ucomisd xmm0,xmm2', 'compare 0.05 with the fraction'),
    ('g4', 0x395bd77, 'jbe 0x395b773', 'fraction >= 0.05 (or unordered) continues'),
    ('g5', 0x395b7af, 'call [0x5774660]:64', 'available balance of the depositor (0x36f7560)'),
    ('g5', 0x395b7b8, 'js 0x395bd9c', 'amount with the sign bit set panics at qtys/mod.rs:843'),
    ('g5', 0x395b7be, 'cmp rax,r13', 'compare available with amount'),
    ('g5', 0x395b7c1, 'jae 0x395b922', 'enough balance continues'),
    ('g5', 0x395b7c7, 'mov [rsp+0x90]:16,0x33', 'payload tag 51 for the logged error'),
    ('g5', 0x395b7d9, 'call 0x3999770', 'hand the logged error to 0x3999770'),
    ('g5', 0x395b7e3, 'mov [rdi+0x8]:16,0x2c', 'insufficient balance: code 44'),
    ('move', 0x395b932, 'call [0x57749d8]:64', 'debit depositor (0x370a3d0)'),
    ('move', 0x395b942, 'sub rax,r13', 'subtract amount from context +0x238'),
    ('move', 0x395b950, 'mov [rbx+0x238]:64,rax', 'store context +0x238'),
    ('move', 0x395b981, 'call 0x36ff4f0', 'credit vault address (0x36ff4f0)'),
    ('move', 0x395b990, 'add rax,r13', 'add amount back to context +0x238'),
    ('move', 0x395b99e, 'mov [rcx+0x238]:64,rax', 'store context +0x238'),
    ('share', 0x395b9db, 'mov rdx,r13', 'delta = amount'),
    ('share', 0x395b9de, 'mov rcx,r12', 'old total = r12, the sum taken before the debit'),
    ('share', 0x395b9e6, 'call 0x395a2c0', 'redistribute shares'),
    ('post', 0x395bd8f, 'lea rdi,[0x570da30]:64', 'depositor record missing after the update panics at vault/mod.rs:407:58'),
    ('post', 0x395baaf, 'add rax,r15', 'record +0x08: u64 add of amount'),
    ('post', 0x395bab2, 'jb 0x395bc91', 'carry goes to the recorder arm (qtys/mod.rs:829)'),
    ('post', 0x395bab8, 'mov [rbx]:64,rax', 'store record +0x08'),
    ('post', 0x395bac2, 'add rax,r15', 'record +0x10: i64 add of amount'),
    ('post', 0x395baca, 'jo 0x395bcb3', 'overflow goes to the recorder arm (qtys/mod.rs:830)'),
    ('post', 0x395bad0, 'mov [rbx+0x8]:64,rax', 'store record +0x10'),
    ('post', 0x395bad9, 'mov [rbx+0x24]:32,raxd', 'store record +0x2c dword of the 12-byte time'),
    ('post', 0x395bae0, 'mov [rbx+0x1c]:64,rax', 'store record +0x24 qword of the 12-byte time'),
    ('post', 0x395baf1, 'movups.st xmm0,[rdi+0x10]:128', 'receipt +0x10: vault address'),
    ('post', 0x395bb1c, 'divsd xmm1,[0x20ae60]:64', 'receipt amount / 1e6'),
    ('post', 0x395bb2e, 'add rax,0xffffffffffffffeb', 'tag 0x8000000000000019 - 0x15'),
    ('post', 0x395bb32, 'mov [rdi]:64,rax', 'store receipt tag 0x8000000000000004'),
    ('post', 0x395bb35, 'movsd.st xmm1,[rdi+0x8]:64', 'store receipt +0x08'),
    ('rebalance', 0x395a2ea, 'add r13,rdx', 'new total = old total + delta'),
    ('rebalance', 0x395a2ed, 'jo 0x395ae9e', 'overflow goes to the recorder arm (qtys/impl_ntl.rs:62)'),
    ('rebalance', 0x395a2f8, 'cmovg rax,r13', 'clamp new total to >= 0'),
    ('rebalance', 0x395a303, 'jle 0x395a5b8', 'delta <= 0 skips the recomputed sum'),
    ('rebalance', 0x395a326, 'call 0x3955e80', 'delta > 0 recomputes vault equity'),
    ('rebalance', 0x395a336, 'mov r15,rax', 'recomputed sum lives in r15 only'),
    ('rebalance', 0x395a5a9, 'mov rcx,[rsp+0x8]:64', 'rcx is reloaded from the saved caller value'),
    ('rebalance', 0x395a5ae, 'mov r13,[rsp+0x18]:64', 'r13 is reloaded from the saved new total'),
    ('rebalance', 0x395a5b3, 'mov rax,[rsp+0x20]:64', 'rax is reloaded from the saved clamp'),
    ('rebalance', 0x395a5bb, 'jle 0x395a5cf', 'new total <= 0 gives denominator 0.0'),
    ('rebalance', 0x395a5c5, 'divsd xmm0,[0x20ae60]:64', 'denominator = clamp / 1e6'),
    ('rebalance', 0x395a5dc, 'cvtsi2sd xmm0,rcx', 'old equity uses the caller rcx'),
    ('rebalance', 0x395a5e1, 'divsd xmm0,[0x20ae60]:64', 'old_usd = rcx / 1e6'),
    ('rebalance', 0x395a65e, 'lea rax,[rsp+0xe8]:64', 'closure captures the address of old_usd'),
    ('rebalance', 0x395a66e, 'lea r15,[rsp+0xb8]:64', 'r15 is overwritten; the recomputed sum has no reader'),
    ('rebalance', 0x395a681, 'call 0x3316bf0', 'collect records into a temporary address->f64 map'),
    ('rebalance', 0x3be61fc, 'mulsd xmm0,[rcx]:64', 'collect closure: share * old_usd'),
    ('rebalance', 0x395a79e, 'call 0x33baed0', 'temporary entry for the depositor, inserted at 0.0 when missing'),
    ('rebalance', 0x395a7ab, 'divsd xmm0,[0x20ae60]:64', 'delta / 1e6'),
    ('rebalance', 0x395a7b3, 'addsd xmm0,[rax]:64', 'add delta to the temporary equity'),
    ('rebalance', 0x395a7b7, 'movsd.st xmm0,[rax]:64', 'store the temporary equity'),
    ('rebalance', 0x395a831, 'ucomisd xmm0,[rsp+0x20]:64', 'compare 1e-15 with the denominator'),
    ('rebalance', 0x395a841, 'jbe 0x395aa30', 'denominator >= 1e-15 takes the division loop'),
    ('rebalance', 0x395a9c3, 'mov [rdx]:64,rax', 'new record: first 12-byte time at +0x18'),
    ('rebalance', 0x395a9cf, 'mov [rdx+0xc]:64,rax', 'new record: second 12-byte time at +0x24'),
    ('rebalance', 0x395a9de, 'call 0x33be930', 'entry insert with the default record'),
    ('rebalance', 0x395a9e3, 'mov [rax]:64,0x0', 'zero arm stores share 0.0 only'),
    ('rebalance', 0x395aa54, 'movsd xmm0,[rax+rdx*8+0x8]:64', 'read temporary equity'),
    ('rebalance', 0x395aa7e, 'ucomisd xmm1,xmm0', 'compare 1e-7 with equity'),
    ('rebalance', 0x395aa82, 'ja 0x395aa8e', 'equity below 1e-7 keeps share 0.0'),
    ('rebalance', 0x395aa84, 'divsd xmm0,[rsp+0x20]:64', 'share = equity / denominator'),
    ('rebalance', 0x395abee, 'call 0x33be930', 'entry insert with the default record'),
    ('rebalance', 0x395abf9, 'movsd.st xmm0,[rax]:64', 'division arm stores share only'),
    ('rebalance', 0x395ac57, 'mov rcx,[r12+0x50]:64', 'after the drain, a walk over every record that stores nothing'),
    ('rebalance', 0x395ae4b, 'add rsp,0x188', 'function epilogue'),
    ('equity', 0x3955ed8, 'call [0x5773178]:64', 'margin summary reader (0x37d79e0) over the clearinghouse state'),
    ('equity', 0x3955ede, 'mov r12,[rsp+0x60]:64', 'first output qword is the perp value'),
    ('equity', 0x3955efd, 'call [0x5773170]:64', 'user entry in the context+8 spot ledger (0x371b3a0)'),
    ('equity', 0x3955f83, 'mov r13,[rcx+rdi*1+0x48]:64', 'value of token key 0'),
    ('equity', 0x3955f8c, 'mov rax,[rbx+0x100]:64', 'context+0x10 +0x100 address map'),
    ('equity', 0x395620e, 'mov rcx,0x5af3107a3fff', 'divisor 1e14 limit'),
    ('equity', 0x3956269, 'mov rcx,0x5af3107a4000', 'u128 / 1e14 path'),
    ('equity', 0x3956222, 'add rcx,r13', 'sum of token value and scaled second term'),
    ('equity', 0x3956233, 'shr rcx,0x2', 'unsigned sum >> 2'),
    ('equity', 0x3956237, 'mov rdx,0x28f5c28f5c28f5c3', 'reciprocal of 25 in the /100 sequence'),
    ('equity', 0x395624e, 'add rax,rdx', 'signed add to the perp value'),
    ('equity', 0x3956251, 'jo 0x39562f8', 'overflow goes to the recorder arm (qtys/impl_ntl.rs:62)'),
    ('create', 0x395af95, 'cmp rax,r11', 'initial compared with the 0xccc cut'),
    ('create', 0x395af98, 'jae 0x395afb6', 'at or above the cut stores code 319'),
    ('create', 0x395af9a, 'cmp rax,0x5f5e0ff', 'initial compared with 99999999'),
    ('create', 0x395afa2, 'mov [rbx+0x8]:16,0x1', 'initial at or below 99999999: code 1'),
    ('create', 0x395afa8, 'mov [rbx]:64,0x3', 'error result tag 3'),
    ('create', 0x395afb6, 'mov [rbx+0x8]:16,0x13f', 'code 319'),
    ('create', 0x395b000, 'cmp r12,0x65', 'name length compared with 101'),
    ('create', 0x395b029, 'mov [rbx+0x8]:16,0x143', 'code 323 for a name of 101 or more'),
    ('create', 0x395b03b, 'cmp r12,0x3', 'name length compared with 3'),
    ('create', 0x395b04e, 'cmp r12,0x33', 'name length compared with 51'),
    ('create', 0x395b095, 'mov [rbx+0x8]:16,r11w', 'name length code 3 or 4'),
    ('create', 0x395b069, 'cmp r13,0xfb', 'description length compared with 251'),
    ('create', 0x395b083, 'mov [rbx+0x8]:16,0x143', 'code 323 for a description of 251 or more'),
    ('create', 0x395b0ce, 'cmp r13,0x9', 'description length compared with 10'),
    ('create', 0x395b293, 'mov [rbx+0x8]:16,0x5', 'description below 10: code 5'),
    ('create', 0x395b0ea, 'cmp rdxb,0x3', 'chain byte compared with 3'),
    ('create', 0x395b0f1, 'lea rdx,[0x2069c0]:64', 'lockup table 20.0, 86400.0'),
    ('create', 0x395b0f8, 'movsd xmm0,[rdx+rbp*8]:64', 'load lockup by chain test'),
    ('create', 0x395b134, 'test rdxb,rdxb', 'child flag test'),
    ('create', 0x395b138, 'movsd xmm1,[0x20a880]:64', 'non-child commission 0.1'),
    ('create', 0x395b1ac, 'mov [rsp+0x78]:64,rdx', 'relationship tag = zero-extended child flag'),
    ('create', 0x395b1b1, 'mov [rsp+0x124]:32,0x100', 'is_closed 0, allow_deposits 1, always_close 0, s 0'),
    ('create', 0x395b245, 'jne 0x395b2ae', 'tag other than 0x8000000000000019 is a deposit success'),
    ('create', 0x395b27d, 'mov [rbx]:64,0x3', 'deposit failure leaves Result tag 3'),
    ('create', 0x395b366, 'mov rdxd,0xb0', 'success copies 0xb0 bytes of Vault into the result'),
    ('createhost', 0x2732f5a, 'test r12b,r12b', 'action byte test'),
    ('createhost', 0x2732f5d, 'je 0x2733222', 'byte 0 runs the reserve gates'),
    ('createhost', 0x2733247, 'call [0x5774660]:64', 'available balance of the leader'),
    ('createhost', 0x273324d, 'mov rcx,0x2540be400', 'reserve 10000000000'),
    ('createhost', 0x273325f, 'lea rdx,[rdi+rcx*1]:64', 'first amount plus reserve'),
    ('createhost', 0x2733270, 'jae 0x2733e7c', 'add would overflow: code 190'),
    ('createhost', 0x2733276, 'cmp rax,rdx', 'available compared with amount plus reserve'),
    ('createhost', 0x2733280, 'mov [rax]:16,0x145', 'too little available: code 325'),
    ('createhost', 0x273329d, 'cmp r15,rcx', 'second amount compared with reserve'),
    ('createhost', 0x27332ab, 'mov [rax]:16,0x146', 'below the reserve: code 326'),
    ('createhost', 0x27333c6, 'mov [rcx]:16,0x0', 'vault key already present: code 0 with the address'),
    ('createhost', 0x2733594, 'call [0x5774b08]:64', 'call 0x395af60'),
    ('createhost', 0x2733606, 'cmp rax,0x3', 'result tag 3 means error'),
    ('modifyhost', 0x2704b8e, 'je 0x2704cb2', 'empty vault map: code 7'),
    ('modifyhost', 0x2704c33, 'jb 0x2704cb2', 'vault not found: code 7'),
    ('modifyhost', 0x2704cd4, 'mov [r15]:16,0x7', 'code 7 with the address'),
    ('modifyhost', 0x2704caa, 'call [0x5774978]:64', 'call 0x3959900'),
    ('modify', 0x3959958, 'cmp raxd,0xffff', 'action address compared with vault +0x84'),
    ('modify', 0x395995d, 'je 0x39599b6', 'same address continues'),
    ('modify', 0x395995f, 'mov [r12]:16,0x186', 'other exits store code 390'),
    ('modify', 0x3959a13, 'cmp [rdx+0x64]:8,0x0', 'make-parent byte test'),
    ('modify', 0x3959a1d, 'cmp [rsi]:64,0x0', 'tag other than 0 leaves with code 390'),
    ('modify', 0x3959aab, 'call [0x5773178]:64', 'margin summary of the vault address'),
    ('modify', 0x3959ab1, 'cmp [rsp+0x70]:64,0x0', 'output +0x10 compared with 0'),
    ('modify', 0x3959adc, 'jne 0x395995f', 'non-zero leaves with code 390'),
    ('modify', 0x3959ae7, 'mov [rsi]:64,0x2', 'tag becomes 2, parent'),
    ('modify', 0x3959b10, 'cmp rbx,r14', 'name option test'),
    ('modify', 0x3959b6d, 'cmp rbp,0x65', 'name length compared with 101'),
    ('modify', 0x3959b9a, 'mov [r12]:16,0x143', 'code 323'),
    ('modify', 0x3959ba7, 'cmp rbp,0x32', 'name length compared with 51'),
    ('modify', 0x3959bb1, 'cmp rbp,0x3', 'name length compared with 3'),
    ('modify', 0x3959bb7, 'mov [r12]:16,raxw', 'name code 3 or 4'),
    ('modify', 0x3959c68, 'cmp rcx,0xfb', 'description length compared with 251'),
    ('modify', 0x3959c9c, 'cmp rcx,0xa', 'description length compared with 10'),
    ('modify', 0x3959ca2, 'mov [r12]:16,0x5', 'description below 10: code 5'),
    ('modify', 0x3959b22, 'cmp [rsp+0x98]:64,0x0', 'lockup option test'),
    ('modify', 0x3959b4f, 'cmp rax,0x3d0900', 'lockup compared with 4000000'),
    ('modify', 0x3959b55, 'ja 0x3959e19', 'above 4000000 leaves with code 390'),
    ('modify', 0x3959b63, 'movsd.st xmm0,[rsi+0x70]:64', 'store lockup_duration'),
    ('modify', 0x3959d2c, 'cmp [rsp+0x90]:64,0x0', 'commission option test'),
    ('modify', 0x3959d51, 'cmp rax,0x3e8', 'commission compared with 1000'),
    ('modify', 0x3959d65, 'divsd xmm0,[0x20a830]:64', 'commission / 10000'),
    ('modify', 0x3959d6d, 'movsd.st xmm0,[rsi+0x68]:64', 'store leader_commission'),
    ('modify', 0x3959d8c, 'mov [r12]:16,0x13f', 'code 319'),
    ('modify', 0x3959d9d, 'mov [rsi+0xad]:8,raxb', 'store allow_deposits'),
    ('modify', 0x3959da9, 'mov [rsi+0xae]:8,r11b', 'store always_close_on_withdraw'),
    ('modify', 0x3959dba, 'cmp [rsi]:32,0x1', 'tag compared with 1, child'),
    ('modify', 0x3959dbd, 'jne 0x3959e19', 'other tags leave with code 390'),
    ('modify', 0x3959df8, 'call [0x5773170]:64', 'ledger of the vault address (0x371b3a0)'),
    ('modify', 0x395a015, 'call [0x5773e58]:64', 'second ledger of the vault address (0x373acd0)'),
    ('modify', 0x395a212, 'mov [r13+0xaf]:8,raxb', 'store field s'),
    ('modify', 0x3999ced, 'cmp [rbx]:32,0x2', 'Vault drop tests tag against 2 before freeing the child set'),
    ('reader', 0x395988f, 'mov rax,[r14]:64', 'read stored 12-byte time (record +0x24)'),
    ('reader', 0x395989c, 'movsd xmm0,[rax+0x70]:64', 'vault +0x70 f64'),
    ('reader', 0x39598ad, 'call [0x576efb8]:64', 'time + seconds helper (0x1459ca0)'),
    ('reader', 0x39598b5, 'mov rdid,0xaf93b', 'missing record path: day count 719163'),
    ('reader', 0x39598ba, 'call [0x576e890]:64', 'date-from-days helper (0x151f6f0)'),
]

FUNCTIONS = [
    (0x27362b0, 'transfer host; deposit minimum, then 0x395b3a0 or the withdraw pair'),
    (0x4d421f0, 'second copy of the transfer host'),
    (0x4d46130, 'third copy of the transfer host'),
    (0x395af60, 'create-vault body; calls 0x395b3a0 with flag 1'),
    (0x395b3a0, 'deposit body'),
    (0x395a2c0, 'share rewrite'),
    (0x3955e80, 'equity of one address'),
    (0x37e4e50, 'list A: eight 20-byte compares'),
    (0x37e4fb0, 'list B: eight 20-byte compares'),
    (0x36f7560, 'available balance (callee, not mapped here)'),
    (0x370a3d0, 'debit (callee, not mapped here)'),
    (0x36ff4f0, 'credit (callee, not mapped here)'),
    (0x358dcd0, 'overflow recorder taking a Location; returns to the caller'),
    (0x3316bf0, 'temporary map collect'),
    (0x3be61a0, 'collect loop holding the share * old_usd closure'),
    (0x33baed0, 'temporary map entry insert'),
    (0x33be930, 'stored record map entry insert'),
    (0x33b0800, 'temporary map draining iterator'),
    (0x39597b0, 'reader: record +0x24 time plus vault +0x70 seconds'),
    (0x2732e60, 'create host; reserve gates, name scan, then 0x395af60'),
    (0x2704b60, 'vote modify host; vault lookup, code 7, then 0x3959900'),
    (0x3959900, 'vote modify body'),
    (0x2340b70, 'Vault JSON serializer that pairs field names with offsets'),
    (0x3999cb0, 'Vault drop; frees the child set only for tag >= 2'),
]

# Shared helpers have hundreds of callers; the census covers the functions this path owns.
CALLER_SCOPE = {0x3959900, 0x2704b60, 0x395b3a0, 0x395a2c0, 0x3955e80, 0x395af60, 0x39597b0, 0x37e4e50, 0x37e4fb0, 0x3316bf0, 0x3be61a0}

LAYOUT = [
    ('vault', 0x00, 8, 0x395b3bd, '[rsi]:64', 'relationship tag: 0 normal, 1 child, 2 parent'),
    ('vault', 0x08, 8, 0x3959aee, '[rsi+0x8]:64', 'parent variant: child set root, cleared when a vault becomes parent'),
    ('vault', 0x18, 8, 0x3959af6, '[rsi+0x18]:64', 'parent variant: child set length'),
    ('vault', 0x20, 8, 0x3959c42, '[rsi+0x20]:64', 'name capacity'),
    ('vault', 0x28, 8, 0x3959c46, '[rsi+0x28]:64', 'name pointer'),
    ('vault', 0x30, 8, 0x3959c4a, '[rsi+0x30]:64', 'name length'),
    ('vault', 0x38, 8, 0x3959d0f, '[rsi+0x38]:64', 'description capacity'),
    ('vault', 0x40, 8, 0x3959d13, '[rsi+0x40]:64', 'description pointer'),
    ('vault', 0x48, 8, 0x3959d17, '[rsi+0x48]:64', 'description length'),
    ('vault', 0x68, 8, 0x3959d6d, '[rsi+0x68]:64', 'leader_commission f64'),
    ('vault', 0xaf, 1, 0x395a212, '[r13+0xaf]:8', 'field named s'),
    ('vault', 0xae, 1, 0x3959da9, '[rsi+0xae]:8', 'always_close_on_withdraw'),
    ('action', 0x00, 8, 0x39599c3, '[rdx]:64', 'commission option tag, 0 is None'),
    ('action', 0x08, 8, 0x39599ce, '[rdx+0x8]:64', 'commission value'),
    ('action', 0x10, 8, 0x39599da, '[rdx+0x10]:64', 'lockup option tag, 0 is None'),
    ('action', 0x18, 8, 0x39599e6, '[rdx+0x18]:64', 'lockup value'),
    ('action', 0x20, 8, 0x395991e, '[rdx+0x20]:64', 'name capacity, 1 << 63 is None'),
    ('action', 0x38, 8, 0x3959926, '[rdx+0x38]:64', 'description capacity, 1 << 63 is None'),
    ('action', 0x50, 16, 0x395992e, '[rdx+0x50]:128', 'vault address head'),
    ('action', 0x64, 1, 0x3959a13, '[rdx+0x64]:8', 'make-parent byte'),
    ('action', 0x65, 1, 0x39599f2, '[rdx+0x65]:8', 'allow_deposits option, 2 is None'),
    ('action', 0x66, 1, 0x39599fa, '[rdx+0x66]:8', 'always_close_on_withdraw option, 2 is None'),
    ('action', 0x67, 1, 0x39599ff, '[rdx+0x67]:8', 's option, 2 is None'),
    ('vault', 0x08, 8, 0x395b4c8, '[r14+0x8]:64', 'child address set root'),
    ('vault', 0x10, 8, 0x395b4ea, '[r14+0x10]:64', 'child address set height'),
    ('vault', 0x18, 8, 0x395b4cc, '[r14+0x18]:64', 'child address set length'),
    ('vault', 0x50, 8, 0x395a5f2, '[r12+0x50]:64', 'record map root'),
    ('vault', 0x58, 8, 0x395a5f7, '[r12+0x58]:64', 'record map height'),
    ('vault', 0x60, 8, 0x395a609, '[r12+0x60]:64', 'record map length'),
    ('vault', 0x70, 8, 0x395989c, '[rax+0x70]:64', 'lockup_duration, f64 seconds added to record +0x24'),
    ('vault', 0x84, 20, 0x395b494, '[r14+0x84]', 'vault address, argument of the equity helper'),
    ('vault', 0x98, 16, 0x395b3ca, '[r14+0x98]:128', 'leader address head'),
    ('vault', 0xa8, 4, 0x395b3dc, '[r14+0xa8]:32', 'leader address tail'),
    ('vault', 0xad, 1, 0x395b403, '[r14+0xad]:8', 'allow_deposits'),
    ('record', 0x00, 8, 0x395abf9, '[rax]:64', 'f64 share'),
    ('record', 0x08, 8, 0x395baa4, '[rbx]:64', 'u64 running sum, rbx = record + 8'),
    ('record', 0x10, 8, 0x395babb, '[rbx+0x8]:64', 'i64 running sum'),
    ('record', 0x18, 12, 0x395a9c3, '[rdx]:64', '12-byte time, written only when the record is created'),
    ('record', 0x24, 12, 0x395bae0, '[rbx+0x1c]:64', '12-byte time, rewritten by each deposit'),
    ('node', 0x210, 8, 0x395ad80, '[rsi+0x210]:64', 'parent pointer, stored map'),
    ('node', 0x218, 220, 0x395ba08, '[r14+0x218]', 'keys, 20 bytes each, after 11 values of 48 bytes'),
    ('node', 0x2f6, 2, 0x395ba0f, '[r14+0x2f6]:16', 'length'),
    ('node', 0x2f8, 96, 0x395ba97, '[r14+rbp*8+0x2f8]:64', 'edges'),
    ('receipt', 0x00, 8, 0x395bb32, '[rdi]:64', 'tag'),
    ('receipt', 0x08, 8, 0x395bb35, '[rdi+0x8]:64', 'amount as f64 / 1e6; code u16 on the error tag'),
    ('receipt', 0x10, 16, 0x395baf1, '[rdi+0x10]', 'vault address head'),
    ('receipt', 0x20, 4, 0x395bb05, '[rdi+0x20]:32', 'vault address tail'),
    ('context', 0x238, 8, 0x395b950, '[rbx+0x238]:64', 'i64 total; debit and credit legs cancel here'),
]

LOCATIONS = [(0x570d988, 'i64 add or sub saturation'), (0x570d9e8, 'i64 sum of equities'),
             (0x56f1cf8, 'context +0x238 subtract'), (0x56f1c50, 'context +0x238 add'),
             (0x5714d18, 'new total u64 add in the leader gate'), (0x5714d30, 'record +0x08 add'),
             (0x5714d88, 'record +0x10 add'), (0x570da30, 'depositor record missing after the update'),
             (0x56f1ce0, 'amount with the sign bit set'), (0x56e9fe8, 'B-tree next_unchecked'),
             (0x56e8b20, 'B-tree first leaf')]

REJECTS = {0x395bbfe: 'equity<1e-7', 0x395bd26: 'equity<1e-7', 0x395bd61: 'total<1e-15', 0x395bd7d: 'fraction<0.05'}


class Image:
    def __init__(self, data):
        self.data = data
        self.secs = sections(data)
        self.mapped = sorted(((s['address'], s['size'], s['offset'], s['name']) for s in self.secs
                              if s['type'] != 8 and s['address']), key=lambda s: s[0])
        self.starts = [s[0] for s in self.mapped]

    def rd(self, va, n):
        i = bisect.bisect_right(self.starts, va) - 1
        if i < 0 or va >= self.mapped[i][0] + self.mapped[i][1]:
            raise ValueError(f'{va:#x} is outside file-backed sections')
        addr, size, off, _ = self.mapped[i]
        return self.data[off + va - addr:off + va - addr + min(n, addr + size - va)]

    def section(self, name):
        return next(s for s in self.secs if s['name'] == name)

    def relative(self):
        out = {}
        s = self.section('.rela.dyn')
        for pos in range(s['offset'], s['offset'] + s['size'], 24):
            where, info, addend = struct.unpack_from('<QQq', self.data, pos)
            if info & 0xffffffff == 8:
                out[where] = addend
        return out


def load():
    data = (ROOT / BINARY).read_bytes()
    if hashlib.sha256(data).hexdigest() != SHA256:
        raise SystemExit('hl-node SHA-256 mismatch')
    return data


def machine(img, rel):
    def hook(target, m):
        if rel.get(target) == RECORDER:
            m.records.append(m.r[6])
            return True
        return False
    return Machine(img.rd, img.rd, hook)


def stack(m):
    m.r[4] = 0x7000000
    return m.r[4]


def q(m, addr, value):
    m.store(addr, (value & M64).to_bytes(8, 'little'))


def d(m, addr, value):
    q(m, addr, f2i(value))


def rq(m, addr):
    return int.from_bytes(m.load(addr, 8), 'little')


def rf(m, addr):
    return i2f(rq(m, addr))


def sat_cast(x):
    """f64 -> i64 sequence: non-finite input becomes 0, then clamp and truncate."""
    if x != x or abs(x) == math.inf:
        return 0
    y = min(max(x, -2.0 ** 63), 2.0 ** 63)
    if y > 9223372036854774784.0:
        return (1 << 63) - 1
    return int(y)


def i64(v):
    return sx(v & M64, 64)


# The seven byte spans.  Each returns the observed result of the real instructions.

def span_gate(img, rel, total, amount, share):
    m = machine(img, rel)
    sp = stack(m)
    q(m, sp + 0x70, 0x7200000)
    d(m, 0x7100000, share)
    m.r[15], m.r[12], m.r[13] = 0x7100000, total & M64, amount & M64
    q(m, sp + 0x28, 0x7300000)
    exit_pc, trace = m.run(0x395bb4f, {0x395bc04, 0x395b773})
    if exit_pc == 0x395b773:
        return 'pass', m.records
    return REJECTS[trace[-1]], m.records


def span_new_total(img, rel, old, delta):
    m = machine(img, rel)
    stack(m)
    m.r[1], m.r[2], m.r[14] = old & M64, delta & M64, delta & M64
    m.run(0x395a2e7, {0x395a2fc})
    return i64(m.r[13]), i64(m.r[0]), m.records


def span_usd(img, rel, old, new_total, clamp, poison):
    m = machine(img, rel)
    sp = stack(m)
    q(m, sp, 0x7200000)
    q(m, sp + 8, old)
    q(m, sp + 0x18, new_total)
    q(m, sp + 0x20, clamp)
    q(m, 0x7200000 + 0x50, 0)
    q(m, 0x7200000 + 0x58, 0)
    m.r[15] = poison & M64
    m.run(0x395a5a5, {0x395a5f2})
    return rf(m, sp + 0x20), rf(m, sp + 0xe8)


def span_share(img, rel, equity, denominator):
    m = machine(img, rel)
    sp = stack(m)
    d(m, sp + 0x20, denominator)
    m.x[0][0] = f2i(equity)
    m.run(0x395aa72, {0x395aa96})
    return i2f(m.x[2][0])


def span_branch(img, rel, denominator):
    m = machine(img, rel)
    sp = stack(m)
    d(m, sp + 0x20, denominator)
    exit_pc, _ = m.run(0x395a829, {0x395a847, 0x395aa30})
    return 'divide' if exit_pc == 0x395aa30 else 'zero'


def span_hundredth(img, rel, perp, value):
    m = machine(img, rel)
    stack(m)
    m.r[12], m.r[1] = perp & M64, value & M64
    m.run(0x3956233, {0x3956257})
    return i64(m.r[0]), m.records


def span_record(img, rel, deposited, net, amount):
    m = machine(img, rel)
    sp = stack(m)
    rec = 0x7400000
    q(m, rec, deposited)
    q(m, rec + 8, net)
    q(m, sp + 0x40, amount)
    q(m, sp + 0x48, 0x7500000)
    q(m, 0x7500000, 0x1122334455667788)
    m.store(0x7500008, b'\x99\xaa\xbb\xcc')
    m.r[3] = rec
    m.run(0x395baa4, {0x395bae4})
    return rq(m, rec), i64(rq(m, rec + 8)), m.load(rec + 0x1c, 12).hex(), m.records


def span_receipt(img, rel, amount):
    m = machine(img, rel)
    stack(m)
    m.r[15], m.r[7] = amount & M64, 0x7600000
    m.run(0x395baf8, {0x395bc1c})
    return rq(m, 0x7600000), rf(m, 0x7600008)


# The create and modify bodies, with every call replaced by a named stub.

FREE_SLOT, SUMMARY_SLOT, LEDGER_A_SLOT, LEDGER_B_SLOT = 0x576e010, 0x5773178, 0x5773170, 0x5773e58
USER_STATE = 0x36f57f0
CUT = 0x0ccccccccccccccc
NONE_CAP = 1 << 63


def create_action(m, base, name_len, desc_len, initial):
    q(m, base + 0x10, 32)
    q(m, base + 0x18, 0x7c10000)
    q(m, base + 0x20, name_len)
    q(m, base + 0x28, 32)
    q(m, base + 0x30, 0x7c20000)
    q(m, base + 0x38, desc_len)
    q(m, base + 0x40, initial)


def run_create(img, name_len, desc_len, initial, chain, child):
    def hook(target, m):
        return target == FREE_SLOT
    m = Machine(img.rd, img.rd, hook)
    sp = stack(m) + 0x10000
    m.r[4] = sp
    action, out, vault_addr, leader, when = 0x7800000, 0x7810000, 0x7820000, 0x7830000, 0x7840000
    create_action(m, action, name_len, desc_len, initial)
    m.store(vault_addr, bytes(range(0x40, 0x54)))
    m.store(leader, bytes(range(0x60, 0x74)))
    m.store(when, bytes(range(0x80, 0x8c)))
    m.r[7], m.r[6], m.r[2], m.r[1], m.r[8], m.r[9] = out, vault_addr, chain, leader, child, action
    q(m, sp + 8, when)
    q(m, sp + 0x10, 0x7850000)
    exit_pc, _ = m.run(0x395af60, {0x395afe7, 0x395b1dc})
    if exit_pc == 0x395afe7:
        return {'code': int.from_bytes(m.load(out + 8, 2), 'little'), 'tag': rq(m, out)}
    v = m.r[4] + 0x78
    return {'code': 'deposit', 'tag': rq(m, v), 'name_len': rq(m, v + 0x30), 'desc_len': rq(m, v + 0x48),
            'root': rq(m, v + 0x50), 'len': rq(m, v + 0x60), 'commission': rf(m, v + 0x68), 'lockup': rf(m, v + 0x70),
            'time': m.load(v + 0x78, 12).hex(), 'vault': m.load(v + 0x84, 20).hex(), 'leader': m.load(v + 0x98, 20).hex(),
            'flags': m.load(v + 0xac, 4).hex(), 'flag_arg': m.r[9] & 0xffffffff, 'amount': m.r[1],
            'set_slot_stores': sum(v + i in m.mem for i in range(8, 0x20))}


def model_create(name_len, desc_len, initial, chain, child):
    if initial >= CUT:
        return {'code': 0x13f, 'tag': 3}
    if initial <= 99_999_999:
        return {'code': 1, 'tag': 3}
    if name_len >= 101:
        return {'code': 0x143, 'tag': 3}
    if name_len < 3:
        return {'code': 3, 'tag': 3}
    if name_len >= 51:
        return {'code': 4, 'tag': 3}
    if desc_len >= 251:
        return {'code': 0x143, 'tag': 3}
    if desc_len <= 9:
        return {'code': 5, 'tag': 3}
    return {'code': 'deposit', 'tag': child, 'name_len': name_len, 'desc_len': desc_len, 'root': 0, 'len': 0,
            'commission': 0.0 if child else 0.1, 'lockup': 86400.0 if chain == 3 else 20.0,
            'time': bytes(range(0x80, 0x8c)).hex(), 'vault': bytes(range(0x40, 0x54)).hex(),
            'leader': bytes(range(0x60, 0x74)).hex(), 'flags': '00010000', 'flag_arg': 1, 'amount': initial, 'set_slot_stores': 0}


def vault_state(tag=0):
    return {'tag': tag, 'root': 0x11, 'count': 0x22, 'name_cap': 8, 'name_len': 7, 'desc_cap': 8, 'desc_len': 7,
            'commission': 0.05, 'lockup': 86400.0, 'allow': 1, 'always': 0, 's': 0}


FIELDS = {'tag': 0, 'root': 8, 'count': 0x18, 'name_cap': 0x20, 'name_len': 0x30, 'desc_cap': 0x38, 'desc_len': 0x48}


def run_modify(img, st, act, positions, busy_a, busy_b):
    """act: name and desc are None or a length; commission and lockup are None or a value."""
    vault, action, ctx, out = 0x7800000, 0x7810000, 0x7820000, 0x7830000
    fake_a, fake_b, node_a, node_b = 0x7840000, 0x7850000, 0x7860000, 0x7870000

    def hook(target, m):
        if target == USER_STATE:
            m.r[0] = 0x7880000
        elif target == SUMMARY_SLOT:
            q(m, m.r[7] + 0x10, positions)
        elif target == LEDGER_A_SLOT:
            m.r[0] = fake_a
        elif target == LEDGER_B_SLOT:
            m.r[0] = fake_b
        else:
            return target == FREE_SLOT
        return True
    m = Machine(img.rd, img.rd, hook)
    m.r[4] = stack(m) + 0x10000
    for name, offset in FIELDS.items():
        q(m, vault + offset, st[name])
    q(m, vault + 0x28, 0x7890000)
    q(m, vault + 0x40, 0x78a0000)
    d(m, vault + 0x68, st['commission'])
    d(m, vault + 0x70, st['lockup'])
    m.store(vault + 0x84, bytes(range(0x40, 0x54)))
    m.store(vault + 0xad, bytes([st['allow'], st['always'], st['s']]))
    q(m, action, 0 if act['commission'] is None else 1)
    q(m, action + 8, act['commission'] or 0)
    q(m, action + 0x10, 0 if act['lockup'] is None else 1)
    q(m, action + 0x18, act['lockup'] or 0)
    q(m, action + 0x20, NONE_CAP if act['name'] is None else 64)
    q(m, action + 0x28, 0x78b0000)
    q(m, action + 0x30, act['name'] or 0)
    q(m, action + 0x38, NONE_CAP if act['desc'] is None else 64)
    q(m, action + 0x40, 0x78c0000)
    q(m, action + 0x48, act['desc'] or 0)
    m.store(action + 0x50, bytes(range(0x40, 0x53)) + bytes([0x53 if act['same_vault'] else 0x54]))
    m.store(action + 0x64, bytes([act['make_parent'], act['allow'], act['always'], act['s']]))
    q(m, ctx, 0x78d0000)
    q(m, ctx + 8, fake_a)
    q(m, ctx + 0x10, fake_b)
    if busy_a is not None:
        q(m, fake_a + 0x10, node_a)
        q(m, fake_a + 0x20, 1)
        m.store(node_a + 0x16a, b'\x01\0')
        q(m, node_a + 0x60, busy_a)
    if busy_b is not None:
        q(m, fake_b + 0x18, node_b)
        q(m, fake_b + 0x28, 1)
        m.store(node_b + 0x1c2, b'\x01\0')
        q(m, node_b + 8, busy_b)
    m.r[7], m.r[6], m.r[2], m.r[1] = out, vault, action, ctx
    m.run(0x3959900, {0x39599a1})
    result = {name: rq(m, vault + offset) for name, offset in FIELDS.items()}
    result.update(commission=rf(m, vault + 0x68), lockup=rf(m, vault + 0x70), allow=m.load(vault + 0xad, 1)[0],
                  always=m.load(vault + 0xae, 1)[0], s=m.load(vault + 0xaf, 1)[0])
    return int.from_bytes(m.load(out, 2), 'little'), result


def model_modify(st, act, positions, busy_a, busy_b):
    """Returns (code, final state).  Stores made before a late return stay in place."""
    v = dict(st)
    if not act['same_vault']:
        return 0x186, v
    if act['make_parent']:
        if v['tag'] != 0 or positions != 0:
            return 0x186, v
        v.update(tag=2, root=0, count=0)
    if act['name'] is not None:
        n = act['name']
        if n >= 0x65:
            return 0x143, v
        if n > 0x32:
            return 4, v
        if n < 3:
            return 3, v
        v.update(name_cap=64, name_len=n)
    if act['desc'] is not None:
        n = act['desc']
        if n >= 0xfb:
            return 0x143, v
        if n < 10:
            return 5, v
        v.update(desc_cap=64, desc_len=n)
    if act['lockup'] is not None:
        if act['lockup'] >= CUT:
            return 0x13f, v
        if act['lockup'] > 4_000_000:
            return 0x186, v
        v['lockup'] = float(act['lockup'])
    if act['commission'] is not None:
        if act['commission'] >= CUT:
            return 0x13f, v
        if act['commission'] > 1000:
            return 0x186, v
        v['commission'] = float(act['commission']) / 10000.0
    if act['allow'] != 2:
        v['allow'] = act['allow']
    if act['always'] != 2:
        v['always'] = act['always']
    if act['s'] != 2:
        if v['tag'] != 1 or busy_a or busy_b:
            return 0x186, v
        v['s'] = act['s']
    return 0x186, v


def pick(stream, options):
    return options[next(stream) % len(options)]


def life_checks(img, n=GRID * 2):
    out = {}
    s = counter(b'create')
    good = 0
    outcomes = {}
    for _ in range(n):
        args = (pick(s, (0, 2, 3, 4, 50, 51, 100, 101, 102, 5000)), pick(s, (0, 9, 10, 11, 250, 251, 252, 5000)),
                pick(s, (99_999_999, 100_000_000, 100_000_000, 100_000_001, 10_000_000_000, CUT - 1, CUT, 1 << 63)),
                pick(s, (0, 1, 2, 3)), pick(s, (0, 1)))
        got = run_create(img, *args)
        good += got == model_create(*args)
        key = str(got['code'])
        outcomes[key] = outcomes.get(key, 0) + 1
    out['create_body'] = {'vectors': n, 'agree': good, 'outcomes': dict(sorted(outcomes.items()))}
    s = counter(b'modify')
    good = 0
    outcomes = {}
    for _ in range(n):
        st = vault_state(pick(s, (0, 0, 1, 2)))
        act = {'same_vault': pick(s, (True, True, True, False)), 'make_parent': pick(s, (0, 0, 1)),
               'name': pick(s, (None, None, None, 0, 2, 3, 50, 51, 100, 101)),
               'desc': pick(s, (None, None, None, 9, 10, 250, 251)),
               'lockup': pick(s, (None, None, 0, 4_000_000, 4_000_001, CUT - 1, CUT)),
               'commission': pick(s, (None, None, 0, 1000, 1001, CUT)),
               'allow': pick(s, (0, 1, 2, 2)), 'always': pick(s, (0, 1, 2, 2)), 's': pick(s, (0, 1, 2, 2))}
        extra = pick(s, (0, 0, 5)), pick(s, (None, None, 0, 7)), pick(s, (None, None, 0, 9))
        got = run_modify(img, st, act, *extra)
        good += got == model_modify(st, act, *extra)
        key = str(got[0])
        outcomes[key] = outcomes.get(key, 0) + 1
    out['modify_body'] = {'vectors': n, 'agree': good, 'outcomes': dict(sorted(outcomes.items()))}
    return out


def outcome_rows(img):
    rows = []
    base = run_create(img, 10, 20, 100_000_000, 3, 0)
    rows.append(('create', 'name 10, description 20, initial 100000000, chain byte 3, child 0',
                 f"deposit call: tag {base['tag']} commission {base['commission']!r} lockup {base['lockup']!r} flags {base['flags']}"))
    other = run_create(img, 10, 20, 100_000_000, 2, 1)
    rows.append(('create', 'name 10, description 20, initial 100000000, chain byte 2, child 1',
                 f"deposit call: tag {other['tag']} commission {other['commission']!r} lockup {other['lockup']!r} flags {other['flags']}"))
    for label, args in (('initial 99999999', (10, 20, 99_999_999, 3, 0)), ('initial at the 0xccc cut', (10, 20, CUT, 3, 0)),
                        ('name 101', (101, 20, 100_000_000, 3, 0)), ('name 51', (51, 20, 100_000_000, 3, 0)),
                        ('name 2', (2, 20, 100_000_000, 3, 0)), ('description 251', (10, 251, 100_000_000, 3, 0)),
                        ('description 9', (10, 9, 100_000_000, 3, 0))):
        got = run_create(img, *args)
        rows.append(('create', label, f"code {got['code']}, result tag {got['tag']}"))
    plain = {'same_vault': True, 'make_parent': 0, 'name': None, 'desc': None, 'lockup': None, 'commission': None,
             'allow': 2, 'always': 2, 's': 2}
    for label, change, tag, extra in (
            ('other vault address', {'same_vault': False}, 0, (0, None, None)),
            ('make parent, normal, no positions', {'make_parent': 1}, 0, (0, None, None)),
            ('make parent, normal, positions', {'make_parent': 1}, 0, (5, None, None)),
            ('make parent, child', {'make_parent': 1}, 1, (0, None, None)),
            ('name 51', {'name': 51}, 0, (0, None, None)), ('name 101', {'name': 101}, 0, (0, None, None)),
            ('description 9', {'desc': 9}, 0, (0, None, None)),
            ('lockup 4000000', {'lockup': 4_000_000}, 0, (0, None, None)),
            ('lockup 4000001 after a name change', {'lockup': 4_000_001, 'name': 10}, 0, (0, None, None)),
            ('commission 1000', {'commission': 1000}, 0, (0, None, None)),
            ('commission 1001', {'commission': 1001}, 0, (0, None, None)),
            ('s on a child, empty ledgers', {'s': 1}, 1, (0, None, None)),
            ('s on a child, ledger A value', {'s': 1}, 1, (0, 7, None)),
            ('s on a child, ledger B value', {'s': 1}, 1, (0, None, 9)),
            ('s on a normal vault', {'s': 1}, 0, (0, None, None))):
        st = vault_state(tag)
        act = dict(plain, **change)
        code, after = run_modify(img, st, act, *extra)
        moved = {k: v for k, v in sorted(after.items()) if st[k] != v}
        rows.append(('modify', label, f'code {code}, changed {json.dumps(moved, sort_keys=True)}'))
    return rows


VAULT_KEYS = [(0x2340bc6, 0x2340bc2), (0x2340bf4, 0x2340bf0), (0x2340c1e, 0x2340c3f), (0x2340c9b, 0x2340cbc),
              (0x2340d2f, 0x2340d28), (0x23d1054, 0x2340d4e), (0x2340d74, 0x2340d70), (0x2340da5, 0x2340d9e),
              (0x2340dd3, 0x2340dcf), (0x2340e04, 0x2340dfd), (0x23d28f4, 0x2340e24), (0x2340e3f, 0x2340e38),
              (0x23d2394, 0x2340e5a)]
STRUCT_TEXTS = (b'struct Vault with 13 elements', b'struct VoteGlobalVaultModification with 9 elements',
                b'struct CreateVaultAction with 5 elements', b'enum VaultRelationship')


def vault_fields(img):
    rows = []
    for index, (lea, offset_site) in enumerate(VAULT_KEYS):
        key = decode(img.rd, lea)
        if key.op != 'lea' or key.args[1][0] != 'rip':
            raise ValueError(f'no key pointer at {lea:#x}')
        pc, length = lea + key.size, None
        for _ in range(4):
            insn = decode(img.rd, pc)
            pc += insn.size
            if insn.op == 'mov' and insn.args[0] == ('r', 2, 32) and insn.args[1][0] == 'i':
                length = insn.args[1][1]
                break
        if length is None:
            raise ValueError(f'no key length after {lea:#x}')
        name = img.rd(key.args[1][1], length).decode('ascii')
        rows.append((index, name, f'{lea:#x}', f'{offset_site:#x}', decode(img.rd, offset_site).text()))
    return rows


def variant_rows(img, rel):
    table = 0x56a0cc0
    rows = []
    for i in range(3):
        slot = table + 16 * i
        length = struct.unpack('<Q', img.rd(slot + 8, 8))[0]
        rows.append((i, img.rd(rel[slot], length).decode('ascii'), f'{slot:#x}'))
    return rows


# Plain formulas written from the pins.  Agreement over the grid is the check.

def model_gate(total, amount, share):
    equity = sat_cast(float(total) * share) / 1e6
    new_total = min(max(total, 0) + amount, (1 << 64) - 1)
    if 1e-7 > equity:
        return 'equity<1e-7'
    usd = float(new_total) / 1e6
    if 1e-15 > usd:
        return 'total<1e-15'
    return 'fraction<0.05' if 0.05 > equity / usd else 'pass'


def sat_add(a, b):
    return max(-(1 << 63), min((1 << 63) - 1, a + b))


def model_new_total(old, delta):
    new = sat_add(old, delta)
    return new, max(new, 0)


def model_usd(old, new_total, clamp):
    return (float(clamp) / 1e6 if new_total > 0 else 0.0), float(old) / 1e6


def model_share(equity, denominator):
    return 0.0 if 1e-7 > equity else equity / denominator


def model_hundredth(perp, value):
    return sat_add(perp, value // 100)


def model_record(deposited, net, amount):
    return min(deposited + amount, (1 << 64) - 1), sat_add(net, sx(amount, 64))


def counter(tag):
    n = 0
    while True:
        block = hashlib.sha256(tag + struct.pack('<Q', n)).digest()
        n += 1
        for i in range(0, 32, 8):
            yield struct.unpack_from('<Q', block, i)[0]


def scaled(stream, signed=True):
    v = next(stream) >> (next(stream) % 64)
    return i64(v * (-1 if signed and next(stream) & 1 else 1)) if signed else v


def grid_checks(img, rel, n=GRID):
    """Compare the byte spans with the formulas; returns per-span agreement counts."""
    out = {}
    s = counter(b'gate')
    hit = {}
    good = 0
    for _ in range(n):
        total, amount = scaled(s), next(s) >> (40 + next(s) % 24)
        share = (next(s) >> 11) / 2.0 ** 53 * (0.2 if next(s) & 1 else 1.0)
        got = span_gate(img, rel, total, amount, share)[0]
        hit[got] = hit.get(got, 0) + 1
        good += got == model_gate(total, amount, share)
    out['gate'] = {'vectors': n, 'agree': good, 'outcomes': dict(sorted(hit.items()))}
    s = counter(b'new_total')
    good = 0
    for _ in range(n):
        old, delta = scaled(s), scaled(s)
        good += span_new_total(img, rel, old, delta)[:2] == model_new_total(old, delta)
    out['new_total'] = {'vectors': n, 'agree': good}
    s = counter(b'usd')
    good = 0
    for _ in range(n):
        old, new = scaled(s), scaled(s)
        clamp = max(new, 0)
        expect = model_usd(old, new, clamp)
        good += span_usd(img, rel, old, new, clamp, next(s)) == expect
    out['usd_ignores_r15'] = {'vectors': n, 'agree': good}
    s = counter(b'share')
    good = 0
    for _ in range(n):
        equity = float(scaled(s)) / 1e13
        denominator = float(next(s) >> (next(s) % 64)) / 1e6 + 1e-15
        good += span_share(img, rel, equity, denominator) == model_share(equity, denominator)
    out['share'] = {'vectors': n, 'agree': good}
    s = counter(b'hundredth')
    good = 0
    for _ in range(n):
        perp, value = scaled(s), next(s)
        good += span_hundredth(img, rel, perp, value)[0] == model_hundredth(perp, value)
    out['hundredth'] = {'vectors': n, 'agree': good}
    s = counter(b'record')
    good = 0
    for _ in range(n):
        deposited, net, amount = next(s), scaled(s), next(s) >> (next(s) % 16)
        got = span_record(img, rel, deposited, net, amount)
        good += got[:2] == model_record(deposited, net, amount)
    out['record'] = {'vectors': n, 'agree': good}
    s = counter(b'receipt')
    good = 0
    for _ in range(n):
        amount = next(s) >> (next(s) % 64)
        good += span_receipt(img, rel, amount) == (0x8000000000000004, float(amount) / 1e6)
    out['receipt'] = {'vectors': n, 'agree': good}
    return out


def named_vectors(img, rel):
    rows = []

    def row(span, args, result, note):
        rows.append((span, args, result, note))

    for total, amount, share, note in (
            (1000_000000, 5_000000, 0.1, 'share well above the bound'),
            (100_000000, 5_000000, 0.0525, 'exactly 5.25 / 105 = 0.05 passes'),
            (100_000000, 5_000000, 0.0524999, 'just below 5 percent'),
            (1000_000000, 1000_000000, 0.1, 'deposit halves the leader fraction to 5 percent'),
            (1000_000000, 1000_000000, 0.0999999, 'same deposit, slightly smaller share'),
            (1000_000000, 5_000000, 0.0, 'leader record with share 0'),
            (-5_000000, 5_000000, 0.1, 'negative total gives negative equity'),
            (0, 5_000000, 0.1, 'zero total gives zero equity'),
            (1000_000000, (1 << 64) - 1, 0.5, 'u64 carry saturates through the recorder')):
        got, rec = span_gate(img, rel, total, amount, share)
        row('leader_gate', f'total={total} amount={amount} share={share!r}',
            got + (f' records={rec[0]:#x}' if rec else ''), note)
    for old, delta, note in ((10, 5, 'plain add'), (10, -20, 'negative new total clamps to 0'),
                             ((1 << 63) - 1, 1, 'saturates through the recorder')):
        new, clamp, rec = span_new_total(img, rel, old, delta)
        row('new_total', f'old={old} delta={delta}', f'new={new} clamp={clamp}' + (f' records={rec[0]:#x}' if rec else ''), note)
    for poison, note in ((0, 'recomputed sum 0'), (5_000_000_000, 'recomputed sum 5e9 changes nothing')):
        den, usd = span_usd(img, rel, 1_000_000_000, 1_005_000_000, 1_005_000_000, poison)
        row('usd', f'old=1000000000 new=1005000000 r15={poison}', f'denominator={den!r} old_usd={usd!r}', note)
    for equity, den, note in ((9.9e-8, 10.0, 'below 1e-7: share 0'), (1e-7, 10.0, 'exactly 1e-7 divides'),
                              (5.0, 10.0, 'plain division')):
        row('share', f'equity={equity!r} denominator={den!r}', repr(span_share(img, rel, equity, den)), note)
    for den in (0.0, 9.9e-16, 1e-15, 1.0):
        arm = span_branch(img, rel, den)
        row('branch', f'denominator={den!r}', arm, 'every entry gets share 0.0' if arm == 'zero' else 'entries use the share span')
    return rows


def lists(img):
    rows = []
    for name, start, end in (('A', 0x37e4e50, 0x37e4fab), ('B', 0x37e4fb0, 0x37e510b)):
        pc, tail, n = start, None, 0
        body = img.rd(start, end - start)
        for m in re.finditer(rb'\x66\x0f\x74([\x05\x0d])(....)', body, re.S):
            target = start + m.end() + struct.unpack('<i', m[2])[0]
            if m[1] == b'\x0d':
                tail = target
                continue
            head16, tail16 = img.rd(target, 16), img.rd(tail, 16)
            if any(tail16[4:]):
                raise ValueError('tail constant has non-zero padding')
            n += 1
            rows.append((name, n, '0x' + (head16 + tail16[:4]).hex(), f'{target:#x}', f'{tail:#x}'))
    return rows


def fde_index(img):
    records = eh_frame_records(img.data, img.secs)
    fdes = records[1]
    pairs = sorted((f['start'], f['end']) for f in fdes)
    return pairs, [p[0] for p in pairs]


def host(pairs, starts, va):
    i = bisect.bisect_right(starts, va) - 1
    return pairs[i][0] if i >= 0 and pairs[i][0] <= va < pairs[i][1] else None


def call_sites(img, pairs, starts, rel, names):
    """Byte census: e8 rel32 and ff 15/25 rip slots that land exactly on a named function."""
    text = img.section('.text')
    base, blob = text['address'], img.data[text['offset']:text['offset'] + text['size']]
    slots = {slot: value for slot, value in rel.items() if value in names}
    rows = []
    for m in re.finditer(rb'[\xe8\xe9]', blob):
        pos = m.start()
        if pos + 5 <= len(blob):
            target = base + pos + 5 + struct.unpack_from('<i', blob, pos + 1)[0]
            if target in names:
                rows.append((target, base + pos, host(pairs, starts, base + pos), 'direct', ''))
    for m in re.finditer(rb'\xff[\x15\x25]', blob):
        pos = m.start()
        if pos + 6 <= len(blob):
            slot = base + pos + 6 + struct.unpack_from('<i', blob, pos + 2)[0]
            if slot in slots:
                rows.append((slots[slot], base + pos, host(pairs, starts, base + pos), 'slot', f'{slot:#x}'))
    return sorted(rows, key=lambda r: (r[0], r[1]))


def callees(img, pairs, starts, rel, function):
    end = pairs[bisect.bisect_left(starts, function)][1]
    body = img.rd(function, end - function)
    found = {}
    start_set = set(starts)
    for m in re.finditer(rb'\xe8(....)', body, re.S):
        target = function + m.end() + struct.unpack('<i', m[1])[0]
        if target in start_set:
            found.setdefault(target, []).append(function + m.start())
    for m in re.finditer(rb'\xff\x15(....)', body, re.S):
        slot = function + m.end() + struct.unpack('<i', m[1])[0]
        if slot in rel:
            found.setdefault(rel[slot], []).append(function + m.start())
    return sorted((function, target, len(sites), sites[0]) for target, sites in found.items())


def location(img, rel, va):
    pointer = rel.get(va)
    if pointer is None:
        raise ValueError(f'no relocation at {va:#x}')
    length, line, column = struct.unpack('<QII', img.rd(va + 8, 16))
    path = img.rd(pointer, length).decode('ascii')
    path = re.sub(r'^.*/hl/code_Mainnet/', '', path)
    return re.sub(r'^/rustc/[0-9a-f]+/', 'rustc/', path), line, column


def check_pins(img):
    rows = []
    for group, va, text, note in PINS:
        got = decode(img.rd, va).text()
        if got != text:
            raise ValueError(f'pin {va:#x}: {got} != {text}')
        rows.append((group, f'{va:#x}', text, note))
    return rows


def check_layout(img):
    rows = []
    for owner, offset, width, site, needle, note in LAYOUT:
        text = decode(img.rd, site).text()
        if needle not in text:
            raise ValueError(f'layout {site:#x}: {needle} not in {text}')
        rows.append((owner, f'{offset:#x}', width, f'{site:#x}', text, note))
    return rows


def linear(img, start, end):
    pc, out = start, []
    while pc < end:
        insn = decode(img.rd, pc)
        out.append(insn)
        pc += insn.size
    if pc != end:
        raise ValueError(f'linear decode overran {end:#x}')
    return out


def is_store(insn):
    if insn.op.endswith('.st'):
        return insn.args[1][0] != 'x'
    return insn.op in STORES and insn.args[0][0] == 'm'


def uses(arg, reg):
    return arg[0] == 'r' and arg[1] == reg or arg[0] == 'm' and reg in (arg[1], arg[2])


def walks(img):
    """Linear byte decodes behind two claims: the post-drain walk writes nothing, and the
    recomputed sum in r15 is never stored before r15 is overwritten at 0x395a66e."""
    tail = linear(img, 0x395ac57, 0x395ae4b)
    span = linear(img, 0x395a336, 0x395a66e)
    leaks = [i for i in span if is_store(i) and len(i.args) > 1 and i.args[1][0] == 'r' and i.args[1][1] == 15]
    reads = [i for i in span if any(uses(a, 15) for a in i.args[1:])]
    kept = [i for i in span[1:] if i.args and i.args[0][:2] == ('r', 15) and i.op not in ('add', 'cmovo')]
    return {
        'post_drain_walk': {'start': '0x395ac57', 'end': '0x395ae4b', 'instructions': len(tail),
                            'memory_stores': sum(is_store(i) for i in tail),
                            'calls': sum(i.op == 'call' for i in tail)},
        'recomputed_sum': {'start': '0x395a336', 'end': '0x395a66e', 'instructions': len(span),
                           'stores_of_r15': len(leaks), 'r15_source_sites': [f'{i.va:#x}' for i in reads],
                           'other_r15_writes': [f'{i.va:#x}' for i in kept]},
    }


def tsv(path, header, rows):
    lines = ['\t'.join(header)] + ['\t'.join(str(c) for c in row) for row in rows]
    path.write_text('\n'.join(lines) + '\n', encoding='ascii')


def build(data):
    img = Image(data)
    rel = img.relative()
    pairs, starts = fde_index(img)
    names = {va for va, _ in FUNCTIONS if va in CALLER_SCOPE}
    fn_rows = []
    for va, role in FUNCTIONS:
        i = bisect.bisect_left(starts, va)
        if i == len(starts) or starts[i] != va:
            raise ValueError(f'no FDE starts at {va:#x}')
        end = pairs[i][1]
        fn_rows.append((f'{va:#x}', f'{end:#x}', end - va, hashlib.sha256(img.rd(va, end - va)).hexdigest(), role))
    sites = call_sites(img, pairs, starts, rel, names)
    site_rows = [(f'{t:#x}', f'{a:#x}', f'{h:#x}' if h else 'none', k, s) for t, a, h, k, s in sites]
    callee_rows = []
    for fn in (0x395b3a0, 0x395a2c0, 0x3955e80):
        callee_rows += [(f'{f:#x}', f'{t:#x}', n, f'{a:#x}') for f, t, n, a in callees(img, pairs, starts, rel, fn)]
    pins = check_pins(img)
    layout = check_layout(img)
    address_rows = lists(img)
    loc_rows = []
    for va, note in LOCATIONS:
        path, line, column = location(img, rel, va)
        loc_rows.append((f'{va:#x}', path, line, column, note))
    grid = grid_checks(img, rel)
    for name, row in grid.items():
        if row['agree'] != row['vectors']:
            raise ValueError(f'span {name}: {row["agree"]}/{row["vectors"]}')
    vectors = named_vectors(img, rel)
    walk = walks(img)
    bodies = life_checks(img)
    for name, row in bodies.items():
        if row['agree'] != row['vectors']:
            raise ValueError(f'body {name}: {row["agree"]}/{row["vectors"]}')
    outcomes = outcome_rows(img)
    field_rows = vault_fields(img)
    variants = variant_rows(img, rel)
    summary = {
        'target': BINARY, 'sha256': SHA256, 'coordinate_system': 'ELF virtual addresses',
        'functions': len(fn_rows), 'call_sites': len(site_rows), 'callee_rows': len(callee_rows),
        'pins': len(pins), 'layout_rows': len(layout), 'list_addresses': len(address_rows),
        'locations': len(loc_rows), 'named_vectors': len(vectors), 'grid': grid, 'walks': walk,
        'bodies': bodies, 'vault_fields': len(field_rows), 'relationship_variants': [r[1] for r in variants],
        'struct_texts': {t.decode(): img.data.count(t) for t in STRUCT_TEXTS},
        'relative_relocations': len(rel), 'fdes': len(pairs),
    }
    return {
        'functions.tsv': (('start', 'end', 'size', 'sha256', 'role'), fn_rows),
        'callers.tsv': (('callee', 'site', 'host_fde', 'kind', 'slot'), site_rows),
        'callees.tsv': (('function', 'callee', 'sites', 'first_site'), callee_rows),
        'pins.tsv': (('group', 'site', 'decoded', 'meaning'), pins),
        'layout.tsv': (('owner', 'offset', 'width', 'site', 'decoded', 'note'), layout),
        'address_lists.tsv': (('list', 'index', 'address', 'head_constant', 'tail_constant'), address_rows),
        'locations.tsv': (('record', 'file', 'line', 'column', 'use'), loc_rows),
        'vectors.tsv': (('span', 'input', 'result', 'note'), vectors),
        'outcomes.tsv': (('body', 'input', 'result'), outcomes),
        'vault_fields.tsv': (('index', 'key', 'key_site', 'offset_site', 'offset_decoded'), field_rows),
    }, summary


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument('--out', required=True, type=Path)
    args = parser.parse_args(argv)
    tables, summary = build(load())
    args.out.mkdir(parents=True, exist_ok=True)
    for name, (header, rows) in tables.items():
        tsv(args.out / name, header, rows)
    (args.out / 'evidence.json').write_text(json.dumps(summary, indent=2, sort_keys=True) + '\n', encoding='ascii')
    return 0


if __name__ == '__main__':
    sys.exit(main())
