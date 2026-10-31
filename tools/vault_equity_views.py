#!/usr/bin/env python3
"""vaults: node #94 vault equity read path: total, user equity, userVaultEquities and vaultSummaries rows.

This tool reads ELF bytes only.  It decodes pinned instructions with a small fail-closed x86-64 subset
decoder and evaluates the listed function bodies in Python, with their other calls replaced by named
stubs.  Each result is compared with a plain model over deterministic vectors.  Nothing from the binary runs.

    python3 tools/vault_equity_views.py --out <dir>
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
    ('total', 0x3957bd4, 'lea rsi,[rdi+0x84]:64', 'vault address at +0x84'),
    ('total', 0x3957be6, 'cmp [r15]:32,0x1', 'tag 2 and up walk the child set'),
    ('total', 0x3957bf0, 'mov rax,[r15+0x8]:64', 'child set root'),
    ('total', 0x3957bf4, 'mov r13,[r15+0x18]:64', 'child set length'),
    ('total', 0x3957ded, 'jo 0x3957e1e', 'overflow branch'),
    ('total', 0x3957e2f, 'add r14,rax', 'saturating add'),
    ('total', 0x3957e32, 'cmovo r14,rcx', 'saturating add'),
    ('total', 0x3957e3f, 'call [0x5773190]:64', 'recorder'),
    ('user', 0x3957ea8, 'mov rcx,[rdi+0x50]:64', 'follower map root'),
    ('user', 0x3957eaf, 'je 0x395825a', 'no map: 0'),
    ('user', 0x3957ecd, 'lea rsi,[rcx+0x218]:64', 'key array'),
    ('user', 0x3957ee0, 'lea r15,[rcx-0x30]:64', 'value array'),
    ('user', 0x3957f6b, 'movsd xmm0,[r15]:64', 'share is the first f64 of the row'),
    ('user', 0x3957f92, 'cmp [r15]:32,0x2', 'tag 2 and up walk the child set'),
    ('user', 0x3958208, 'cvtsi2sd xmm0,r14', 'total as f64'),
    ('user', 0x3958213, 'mulsd xmm2,xmm0', 'share times total'),
    ('user', 0x3958237, 'cmp rax,rdx', 'non-finite gives 0'),
    ('user', 0x3958273, 'ucomisd xmm0,[0x20a2c8]:64', 'high clamp'),
    ('user', 0x3958285, 'cmovp rax,rcx', 'NaN gives 0'),
    ('user', 0x395828c, 'cmovle rax,rcx', 'not positive gives 0'),
    ('list', 0x2581459, 'cmp [rbx+0x1048]:64,0x0', 'clearinghouse count'),
    ('list', 0x25814ac, 'call [0x5774678]:64', 'user equity'),
    ('list', 0x25814b2, 'test rax,rax', 'zero equity is skipped'),
    ('list', 0x25814e1, 'call [0x5774680]:64', 'lockup end time'),
    ('list', 0x25815c1, 'divsd xmm0,[0x20ae60]:64', 'equity over 1e6'),
    ('list', 0x25815d0, 'mov [rax+0x20]:32,rdxd', 'row vault address tail'),
    ('list', 0x25815dc, 'movsd.st xmm0,[rax]:64', 'row equity'),
    ('list', 0x25815e0, 'mov [rax+0x8]:64,rcx', 'row locked until'),
    ('list', 0x258153b, 'mov rdid,0xa0', 'first allocation, 4 rows of 0x28'),
    ('list', 0x25819d7, 'mov r8d,0x28', 'growth stride'),
    ('summary', 0x2a35f57, 'movzx raxd,[rsi+0xac]:8', 'closed byte'),
    ('summary', 0x2a35f62, 'mov r12d,[rsi+0x78]:32', 'creation date'),
    ('summary', 0x2a35fc0, 'call [0x5774968]:64', 'total equity through its slot'),
    ('summary', 0x2a35fc9, 'cmp r13,0x2', 'tag 2 and up copy the child set'),
    ('summary', 0x2a35fef, 'call 0x2a0d090', 'child set clone'),
    ('summary', 0x2a360d5, 'divsd xmm0,[0x20ae60]:64', 'total over 1e6'),
    ('summary', 0x2a360bd, 'imul3 rcx,rcx,0x3e8', 'seconds to milliseconds'),
    ('summary', 0x2a360cc, 'cmovg rdx,rcx', 'time clamp at 0'),
    ('summary', 0x2a36115, 'movsd.st xmm0,[rbx+0x38]:64', 'tvl word'),
    ('summary', 0x2a3611f, 'mov [rbx+0x70]:8,raxb', 'closed word'),
    ('summary', 0x26b2d7e, 'call [0x57746d0]:64', 'row builder through its slot'),
    ('summary', 0x26b2d8c, 'imul3 rax,r8,0x78', 'row stride 0x78'),
    ('query', 0x27cf90a, 'lea rax,[r12+0x570]:64', 'exchange at state +0x570'),
    ('query', 0x27cf924, 'mov rcx,[r12+0x18c0]:64', 'vault map root in the state frame'),
    ('query', 0x27cf996, 'call 0x25813f0', 'row builder'),
    ('query', 0x27cf0d7, 'lea rax,[r13+0x570]:64', 'exchange at state +0x570'),
    ('query', 0x27cf0de, 'mov rcx,[r13+0x18c0]:64', 'vault map root in the state frame'),
    ('query', 0x27cf144, 'imul3 rsi,r14,0x78', 'one row of 0x78 per vault, no leader test on the way'),
    ('query', 0x27cf1cb, 'call 0x26b2b00', 'summary loop'),
]

LAYOUT_ROWS = [
    ('vault_value', 0x0, 4, 0x3957be6, '[r15]:32', 'relationship tag: 0 normal, 1 child, 2 parent'),
    ('vault_value', 0x8, 8, 0x3957bf0, '[r15+0x8]:64', 'child set root'),
    ('vault_value', 0x18, 8, 0x3957bf4, '[r15+0x18]:64', 'child set length'),
    ('vault_value', 0x28, 8, 0x2a35f78, '[rsi+0x28]:64', 'name pointer'),
    ('vault_value', 0x30, 8, 0x2a35f7c, '[rsi+0x30]:64', 'name length'),
    ('vault_value', 0x50, 8, 0x3957ea8, '[rdi+0x50]:64', 'follower map root'),
    ('vault_value', 0x78, 12, 0x2a35f62, '[rsi+0x78]:32', 'creation time: date, seconds, nanoseconds'),
    ('vault_value', 0x84, 20, 0x3957bd4, '[rdi+0x84]', 'vault address'),
    ('vault_value', 0x98, 20, 0x2a360ff, '[r15+0x98]:128', 'leader'),
    ('vault_value', 0xac, 1, 0x2a35f57, '[rsi+0xac]:8', 'closed'),
    ('exchange_b', 0x1048, 8, 0x2581459, '[rbx+0x1048]:64', 'clearinghouse count'),
    ('exchange_b', 0x1040, 8, 0x258146a, '[rbx+0x1040]:64', 'clearinghouse list'),
    ('exchange_b', 0x80, 8, 0x2581413, '[rbx+0x80]', 'second context word'),
    ('exchange_b', 0x498, 8, 0x258141f, '[rbx+0x498]', 'third context word'),
]

KEYS = [
    (0x2a367d0, 0x2a36842, 0x2a3684c, 0x10, 'vaultAddress'),
    (0x2a367d0, 0x2a3685b, 0x2a36865, 0x0, 'equity'),
    (0x2a367d0, 0x2a3687b, 0x2a36885, 0x8, 'lockedUntilTimestamp'),
    (0x2a36180, 0x2a361f2, 0x2a361fc, 0x20, 'name'),
    (0x2a36180, 0x2a36213, 0x2a3621d, 0x48, 'vaultAddress'),
    (0x2a36180, 0x2a36234, 0x2a3623e, 0x5c, 'leader'),
    (0x2a36180, 0x2a36251, 0x2a3625b, 0x38, 'tvl'),
    (0x2a36180, 0x2a3626e, 0x2a36278, 0x70, 'isClosed'),
    (0x2a36180, 0x2a36287, 0x2a36291, 0x0, 'relationship'),
    (0x2a36180, 0x2a362a7, 0x2a362b1, 0x40, 'createTimeMillis'),
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
    targets = {va for va, _ in FUNCS[:3]}
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


LOCATIONS = [(0x570d9e8, 'saturating add in total and user equity'), (0x56e9ae0, 'clearinghouse unwrap on the view and snapshot paths'),
             (0x56e8b20, 'child set iterator unwrap'), (0x56e9fe8, 'child set ascend unwrap'), (0x56c37f0, 'vault iterator unwrap'), (0x56c5540, 'vault map ascend unwrap')]

FUNCS = [(0x3957bc0, 'total vault equity: own address plus each child'), (0x3957e90, 'user equity in one vault'),
         (0x26b1430, 'fold: user equity per vault into a Vec'), (0x25677f0, 'Vec wrapper of the fold'), (0x2570c00, 'second Vec wrapper of the fold'),
         (0x27e1210, 'vault map iterator next'), (0x25813f0, 'userVaultEquities row builder'), (0x26b2b00, 'vaultSummaries loop'), (0x2a35f40, 'one vaultSummaries row'),
         (0x2a367d0, 'UserVaultEquity serializer'), (0x2a36180, 'VaultSummary serializer'), (0x27cf850, 'userVaultEquities query under the state read lock'),
         (0x27ceff0, 'vaultSummaries query under the state read lock')]

STUBS = [(0x3955e80, 'account equity of one address, in open PR #873'), (0x5774680, 'lockup end time, 0x39597b0, in open PR #873'), (0x5773190, 'overflow recorder'),
         (0x576e488, 'memcmp'), (0x3379490, 'drop of a code value'), (0x576dfd8, 'allocate'), (0x576dfe0, 'memcpy'), (0x576dfb8, 'allocation failure'),
         (0x2a0d090, 'child set clone'), (0x251b070, 'Vec growth')]

I64MAX, I64MIN = (1 << 63) - 1, -(1 << 63)
SENT = 0x10
SP = 0x7f00000
HEAP = 0x8000000
EX = 0x7900000
CH = 0x7a00000
OUT = 0x7820000
USER = 0x7830000
CTX = 0x7840000
TIME = 0x7850000
ITER = 0x7860000
KEY = 0x7870000


class World:
    """One fixture: a Machine, its bump heap and the named stubs."""

    def __init__(self, img):
        self.img = img
        self.m = Machine(img.rd, img.rd, self.hook)
        self.m.cache = img.cache
        self.m.real_map = dict(REAL)
        self.m.r[4] = SP
        self.heap = HEAP
        self.recorded = []
        self.equity = {}
        self.equity_calls = []
        self.lock = {}
        self.stubs = {0x3955e80: self.equity_stub, 0x5774680: self.lockup, 0x5773190: self.recorder, 0x576e488: self.memcmp, 0x3379490: lambda *a: 0,
                      0x576dfd8: self.malloc, 0x576dfe0: self.memcpy, 0x576dfb8: self.alloc_fail, 0x2a0d090: self.clone_set, 0x251b070: self.grow,
                      0x576e048: self.panic_unwrap, 0x576e470: self.panic_rdi}
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
        for i in range(16):
            m.x[i] = [0x7ff8dead00000000, 0x7ff8dead00000000]
        m.r[0] = (ret or 0) & M64
        return True

    def equity_stub(self, m, ctx, key, *_):
        k = m.load(key, 20)
        self.equity_calls.append((k.hex(), ctx - CTX if ctx >= CTX else ctx))
        self.last_ctx = (rq(m, ctx), rq(m, ctx + 8), rq(m, ctx + 16))
        return self.equity.get(k, 0)

    def lockup(self, m, out, value, user, *_):
        v, u = m.load(value + 0x84, 20), m.load(user, 20)
        m.store(out, struct.pack('<III', *self.lock.get((v, u), (0, 0, 0))))

    def recorder(self, m, a, b, *_):
        self.recorded.append(b)

    def malloc(self, m, n, *_):
        return self.alloc(n)

    def memcpy(self, m, a, b, n, *_):
        m.store(a, m.load(b, n))
        return a

    def memcmp(self, m, a, b, n, *_):
        x, y = m.load(a, n), m.load(b, n)
        return ((x > y) - (x < y)) & M64

    def alloc_fail(self, m, *_):
        raise Panic('alloc')

    def clone_set(self, m, out, root, height, *_):
        q(m, out, 0xc10e0000 + (root & 0xffff))
        q(m, out + 8, height)
        q(m, out + 16, 0x77)

    def grow(self, m, vec, length, extra, align, size, *_):
        cap = rq(m, vec)
        p = self.alloc(2 * cap * size + size * 4)
        m.store(p, m.load(rq(m, vec + 8), length * size))
        q(m, vec, 2 * cap + 4)
        q(m, vec + 8, p)

    def panic_unwrap(self, m, msg, n, payload, vt, loc, *_):
        raise Panic('unwrap', loc, m.load(payload, 2))

    def panic_rdi(self, m, loc, *_):
        raise Panic('panic', loc)


REAL = {0x5774968: 0x3957bc0, 0x5774678: 0x3957e90, 0x57746d0: 0x2a35f40}
for t, _ in FUNCS:
    REAL[t] = t


def call(w, fn, *args, xmm0=None):
    m = w.m
    m.r[4] -= 8
    q(m, m.r[4], SENT)
    for reg, v in zip((7, 6, 2, 1, 8, 9), args):
        m.r[reg] = v
    m.run(fn, {SENT}, 2000000)


def tree(w, items, g):
    """Write sorted (key, value) items as a B-tree of the wanted height, with parent links, and return (root, height)."""
    m = w.m
    key_len, val_len = g['key_len'], g['val_len']

    def node(rows, edges):
        n = w.alloc(g['size'])
        m.store(n, bytes(g['size']))
        for i, (k, v) in enumerate(rows):
            m.store(n + g['key'] + i * key_len, k)
            if val_len:
                m.store(n + g['val'] + i * val_len, v)
        m.store(n + g['len'], len(rows).to_bytes(2, 'little'))
        for i, e in enumerate(edges):
            q(m, n + g['edge'] + i * 8, e)
            q(m, e + g['parent'], n)
            m.store(e + g['pidx'], i.to_bytes(2, 'little'))
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


VAULT_TREE = dict(key=0x798, key_len=20, val=0, val_len=0xb0, len=0x876, edge=0x878, parent=0x790, pidx=0x874, size=0x8e0)
USER_TREE = dict(key=0x218, key_len=20, val=0, val_len=0x30, len=0x2f6, edge=0x2f8, parent=0x210, pidx=0x2f4, size=0x360)
SET_TREE = dict(key=8, key_len=20, val=0, val_len=0, len=0xe6, edge=0xe8, parent=0, pidx=0xe4, size=0x150)


def time_bytes(t):
    return struct.pack('<III', *t)


def date_word(year, ordinal, flags=3):
    return (year << 13 | ordinal << 4 | flags) & 0xffffffff


def vault_bytes(w, v):
    b = bytearray(0xb0)
    struct.pack_into('<Q', b, 0, v['tag'])
    if v.get('children'):
        root, height = tree(w, [(k, b'') for k in sorted(set(v['children']))], SET_TREE)
        struct.pack_into('<QQQ', b, 8, root, height, len(set(v['children'])))
    if 'name' in v:
        p = w.alloc(max(len(v['name']), 1))
        w.m.store(p, v['name'])
        struct.pack_into('<QQ', b, 0x28, p, len(v['name']))
    if v.get('users'):
        root, height = tree(w, [(k, struct.pack('<d', s) + bytes(0x28)) for k, s in sorted(v['users'].items())], USER_TREE)
        struct.pack_into('<QQ', b, 0x50, root, height)
    struct.pack_into('<III', b, 0x78, *v.get('created', (0, 0, 0)))
    b[0x84:0x98] = v['user']
    b[0x98:0xac] = v.get('leader', addr(99))
    b[0xac] = v.get('closed', 0)
    return bytes(b)


def vault(user, **k):
    v = dict(user=user, tag=0)
    v.update(k)
    return v


def exchange(w, c):
    m = w.m
    g = dict(ch=0x1040, vaults=0x1350)
    now = c.get('now', (date_word(2026, 300), 0, 0))
    m.store(EX + 0x60, time_bytes(now))
    q(m, EX + g['ch'], CH)
    q(m, EX + g['ch'] + 8, c.get('chs', 1))
    vs = c.get('vaults', {})
    if vs:
        root, height = tree(w, [(k, vault_bytes(w, v)) for k, v in sorted(vs.items())], VAULT_TREE)
        q(m, EX + g['vaults'], root)
        q(m, EX + g['vaults'] + 8, height)
        return root, height
    return 0, 0


def sat_cast(x):
    """f64 to i64 with the shared clamp: non-finite gives 0, values past the ends saturate."""
    if x != x or abs(x) == math.inf:
        return 0
    y = min(max(x, -2.0 ** 63), 2.0 ** 63)
    return I64MAX if y > 9223372036854774784.0 else int(y)


def model_total(v, eq):
    total = eq.get(v['user'], 0)
    calls = [v['user']]
    rec = 0
    if v['tag'] >= 2 and v.get('children'):
        for k in sorted(set(v['children'])):
            calls.append(k)
            s = total + eq.get(k, 0)
            if not I64MIN <= s <= I64MAX:
                rec += 1
                s = I64MAX if s > 0 else I64MIN
            total = s
    return total, calls, rec


def model_user(v, u, eq):
    if u not in v.get('users', {}):
        return 0, [], 0
    total, calls, rec = model_total(v, eq)
    return max(sat_cast(v['users'][u] * float(total)), 0), calls, rec


def days_ms(t):
    """chrono NaiveDateTime parts to Unix milliseconds, clamped at 0."""
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


# Evaluated paths


def run_total(img, c):
    w = World(img)
    w.equity = c['eq']
    p = w.alloc(0xb0)
    w.m.store(p, vault_bytes(w, c['vault']))
    q(w.m, CTX, 0x1234)
    try:
        call(w, 0x3957bc0, p, CTX)
    except Panic as e:
        return {'panic': e.args[0], 'loc': e.args[1]}
    return {'total': i64(w.m.r[0]), 'calls': [k for k, _ in w.equity_calls], 'recorded': sorted(set(w.recorded)), 'n': len(w.recorded)}


def want_total(c):
    t, calls, rec = model_total(c['vault'], c['eq'])
    return {'total': t, 'calls': [k.hex() for k in calls], 'recorded': [0x570d9e8] if rec else [], 'n': rec}


def run_user(img, c):
    w = World(img)
    w.equity = c['eq']
    p = w.alloc(0xb0)
    w.m.store(p, vault_bytes(w, c['vault']))
    w.m.store(USER, c['u'])
    q(w.m, CTX, 0x1234)
    try:
        call(w, 0x3957e90, p, USER, CTX)
    except Panic as e:
        return {'panic': e.args[0], 'loc': e.args[1]}
    return {'equity': i64(w.m.r[0]), 'calls': [k for k, _ in w.equity_calls], 'n': len(w.recorded)}


def want_user(c):
    e, calls, rec = model_user(c['vault'], c['u'], c['eq'])
    return {'equity': e, 'calls': [k.hex() for k in calls], 'n': rec}


def iter_args(w, root, height, count, a, b):
    m = w.m
    for i, v in enumerate((1 if root else 0, 0, root, height, 1 if root else 0, 0, root, height, count, a, b)):
        q(m, ITER + i * 8, v)


def run_fold(img, c):
    w = World(img)
    w.equity = c['eq']
    root, height = exchange(w, c)
    w.m.store(USER, c['u'])
    q(w.m, CTX, CH)
    q(w.m, CTX + 8, 0x11)
    q(w.m, CTX + 16, 0x22)
    iter_args(w, root, height, len(c['vaults']), USER, CTX)
    call(w, c['fn'], OUT, ITER)
    cap, ptr, n = rq(w.m, OUT), rq(w.m, OUT + 8), rq(w.m, OUT + 16)
    return {'cap': cap, 'rows': [i64(rq(w.m, ptr + 8 * i)) for i in range(n)]}


def want_fold(c):
    rows = [model_user(v, c['u'], c['eq'])[0] for k, v in sorted(c['vaults'].items())]
    return {'cap': len(rows), 'rows': rows}


def run_list(img, c):
    w = World(img)
    w.equity = c['eq']
    w.lock = c['lock']
    root, height = exchange(w, c)
    w.m.store(USER, c['u'])
    iter_args(w, root, height, len(c['vaults']), USER, EX)
    try:
        call(w, 0x25813f0, OUT, ITER)
    except Panic as e:
        return {'panic': e.args[0], 'loc': e.args[1]}
    ptr, n = rq(w.m, OUT + 8), rq(w.m, OUT + 16)
    rows = []
    for i in range(n):
        r = w.m.load(ptr + i * 0x28, 0x24)
        rows.append((struct.unpack('<d', r[:8])[0], i64(int.from_bytes(r[8:16], 'little')), r[16:36].hex()))
    return {'rows': rows, 'ctx': w.last_ctx if w.equity_calls else None}


def want_list(c):
    if c['vaults'] and c.get('chs', 1) == 0:
        return {'panic': 'unwrap', 'loc': 0x56e9ae0}
    rows = []
    calls = 0
    for k, v in sorted(c['vaults'].items()):
        e, cc, _ = model_user(v, c['u'], c['eq'])
        calls += len(cc)
        if e != 0:
            rows.append((e / 1000000.0, days_ms(c['lock'].get((k, c['u']), (0, 0, 0))), k.hex()))
    return {'rows': rows, 'ctx': (CH, EX + 0x80, EX + 0x498) if calls else None}


def run_summary(img, c):
    w = World(img)
    w.equity = c['eq']
    root, height = exchange(w, c)
    iter_args(w, root, height, len(c['vaults']), EX, 0)
    buf = w.alloc(0x78 * max(len(c['vaults']), 1))
    q(w.m, OUT, 0)
    q(w.m, CTX, OUT)
    q(w.m, CTX + 8, 0)
    q(w.m, CTX + 16, buf)
    try:
        call(w, 0x26b2b00, ITER, CTX)
    except Panic as e:
        return {'panic': e.args[0], 'loc': e.args[1]}
    rows = []
    for i in range(rq(w.m, OUT)):
        r = w.m.load(buf + i * 0x78, 0x78)
        word = struct.unpack_from('<Q', r, 0)[0]
        name = w.m.load(struct.unpack_from('<Q', r, 0x28)[0], struct.unpack_from('<Q', r, 0x30)[0])
        rows.append(dict(tag=word, child=struct.unpack_from('<QQQ', r, 8) if word >= 2 else None, cap=struct.unpack_from('<Q', r, 0x20)[0], name=name.hex(),
                         tvl=struct.unpack_from('<d', r, 0x38)[0], created=struct.unpack_from('<q', r, 0x40)[0], vault=r[0x48:0x5c].hex(), leader=r[0x5c:0x70].hex(), closed=r[0x70]))
    return {'rows': rows}


def want_summary(c):
    if c['vaults'] and c.get('chs', 1) == 0:
        return {'panic': 'unwrap', 'loc': 0x56e9ae0}
    rows = []
    for k, v in sorted(c['vaults'].items()):
        t = model_total(v, c['eq'])[0]
        child = None
        if v['tag'] >= 2:
            child = 'set' if v.get('children') else 'empty'
        rows.append(dict(tag=v['tag'], child=child, cap=len(v.get('name', b'')), name=v.get('name', b'').hex(), tvl=t / 1000000.0, created=days_ms(v.get('created', (0, 0, 0))),
                         vault=v['user'].hex(), leader=v.get('leader', addr(99)).hex(), closed=v.get('closed', 0)))
    return {'rows': rows}


def same_summary(got, want):
    if 'panic' in want or 'panic' in got:
        return got == want
    if len(got['rows']) != len(want['rows']):
        return False
    for g, x in zip(got['rows'], want['rows']):
        for k in x:
            if k == 'child' and x[k] == 'set':
                if g[k] is None or g[k][2] != 0x77:
                    return False
            elif k == 'child' and x[k] == 'empty':
                if g[k] is None or g[k][0] != 0 or g[k][2] != 0:
                    return False
            elif g[k] != x[k]:
                return False
    return True


# Vectors


AMOUNTS = [0, 1, -1, 999999, 1000000, 123456789012, -5000000, I64MAX, I64MIN, I64MAX - 3]


def child_list(s):
    return [addr(100 + i) for i in range(s.pick([0, 1, 2, 11, 12, 40]))]


def make_vault(s, key):
    kids = child_list(s)
    v = vault(key, tag=s.pick([0, 1, 2, 2, 3]), children=kids)
    return v


def total_cases(n):
    s = Stream('vault-total')
    for _ in range(n):
        v = make_vault(s, addr(2))
        eq = {k: s.pick(AMOUNTS) for k in [v['user']] + v['children']}
        yield dict(vault=v, eq=eq)


SHARES = [0.0, 1.0, 0.5, 0.25, 1e-9, 1.5, -0.5, float('inf'), float('nan'), 1e300]


def user_cases(n):
    s = Stream('vault-user')
    for _ in range(n):
        v = make_vault(s, addr(2))
        u = addr(1)
        users = {addr(200 + i): 0.5 for i in range(s.pick([0, 3, 11, 12, 13, 50]))}
        if s.u(5):
            users[u] = s.pick(SHARES)
        v['users'] = users
        eq = {k: s.pick(AMOUNTS) for k in [v['user']] + v['children']}
        yield dict(vault=v, u=u, eq=eq)


def fleet(s, img, n, want=None):
    vs = {}
    for i in range(n):
        k = addr(30 + i)
        vs[k] = make_vault(s, k)
    if want:
        vs[want] = make_vault(s, want)
    return vs


def view_fleet(s, img, u):
    vs = fleet(s, img, s.pick([0, 1, 2, 11, 12, 13, 30]))
    eq = {}
    lock = {}
    for k, v in vs.items():
        for x in [v['user']] + v['children']:
            eq[x] = s.pick(AMOUNTS[:7] + [5000000, 5000000])
        if s.u(2):
            v['users'] = {u: s.pick([0.0, 1.0, 0.5, 1e-9, -0.5]), addr(201): 0.1}
            lock[(k, u)] = s.pick([(date_word(2026, 300), 7, 999999), (date_word(1970, 1), 0, 0), (date_word(1969, 365), 0, 0), (date_word(-3, 10), 1, 1), (date_word(2100, 366, 7), 86399, 1999999999)])
    return vs, eq, lock


def fold_cases(img, n):
    s = Stream('vault-fold')
    for i in range(n):
        u = addr(1)
        vs, eq, _ = view_fleet(s, img, u)
        yield dict(fn=(0x25677f0, 0x2570c00)[i % 2], vaults=vs, eq=eq, u=u)


def list_cases(img, n):
    s = Stream('vault-list')
    for _ in range(n):
        u = addr(1)
        vs, eq, lock = view_fleet(s, img, u)
        yield dict(vaults=vs, eq=eq, u=u, lock=lock, chs=0 if s.u(16) == 0 else 1)


def summary_cases(img, n):
    s = Stream('vault-summary')
    for _ in range(n):
        u = addr(1)
        vs, eq, _ = view_fleet(s, img, u)
        for k, v in vs.items():
            v['name'] = bytes(range(65, 65 + s.pick([0, 1, 5, 50])))
            v['created'] = s.pick([(date_word(2024, 40), 5, 7000000), (date_word(1970, 1), 0, 0), (date_word(1969, 300), 3, 3), (date_word(0, 10), 0, 0), (date_word(-500, 10), 0, 0)])
            v['leader'] = addr(70 + s.u(5))
            v['closed'] = s.u(2)
        yield dict(vaults=vs, eq=eq, chs=0 if s.u(16) == 0 else 1)


def evaluate(img, n=240):
    counts = {}
    bad = []

    def note(kind, got, ok, want, label):
        key = (kind, label)
        counts[key] = counts.get(key, 0) + 1
        if not ok:
            bad.append((kind, got, want))

    for c in total_cases(n):
        got, want = run_total(img, c), want_total(c)
        note('total', got, got == want, want, f"tag{min(c['vault']['tag'], 2)} recorded={min(got.get('n', 0), 1)}")
    for c in user_cases(n):
        got, want = run_user(img, c), want_user(c)
        note('user', got, got == want, want, 'zero' if got.get('equity') == 0 else 'positive')
    for c in fold_cases(img, n):
        got, want = run_fold(img, c), want_fold(c)
        note('fold', got, got == want, want, 'rows' if got['rows'] else 'empty')
    for c in list_cases(img, n):
        got, want = run_list(img, c), want_list(c)
        note('list', got, got == want, want, 'panic' if 'panic' in got else f"rows={min(len(got['rows']), 5)}")
    for c in summary_cases(img, n):
        got, want = run_summary(img, c), want_summary(c)
        note('summary', got, same_summary(got, want), want, 'panic' if 'panic' in got else 'rows' if got['rows'] else 'empty')
    return counts, bad


def named_cases(img):
    """Named scenarios a reader can follow; each row is the observed result of the real bytes."""
    rows = []
    a, b = addr(2), addr(3)

    def total(name, v, eq):
        c = dict(vault=v, eq=eq)
        got, want = run_total(img, c), want_total(c)
        rows.append(('total', name, json.dumps(got.get('total')), 'same' if got == want else 'DIFF'))

    total('two children sum', vault(a, tag=2, children=[b, addr(4)]), {a: 1, b: 2, addr(4): 3})
    total('overflow saturates and records, then the walk goes on', vault(a, tag=2, children=[b, addr(4)]), {a: I64MAX, b: 1, addr(4): -5})

    def user(name, share, amount):
        c = dict(vault=vault(a, users={addr(1): share}), u=addr(1), eq={a: amount})
        got, want = run_user(img, c), want_user(c)
        rows.append(('user', name, json.dumps(got.get('equity')), 'same' if got == want else 'DIFF'))

    user('half of 3000001 truncates', 0.5, 3000001)
    user('negative total gives 0', 0.5, -3000000)
    user('NaN share gives 0', float('nan'), 3000000)
    user('infinite product gives 0', float('inf'), 3000000)
    user('2^64 share cast saturates at i64 max', 2.0, I64MAX)

    def lst(name, vs, eq, lock):
        c = dict(vaults=vs, eq=eq, u=addr(1), lock=lock)
        got, want = run_list(img, c), want_list(c)
        rows.append(('list', name, json.dumps(got.get('rows')), 'same' if got == want else 'DIFF'))

    lst('zero equity row dropped, order by vault key', {a: vault(a, users={addr(1): 0.5}), b: vault(b, users={addr(1): 0.5})}, {a: 0, b: 2000000}, {(b, addr(1)): (date_word(2026, 300), 7, 999999)})
    lst('lockup before 1970 clamps at 0', {a: vault(a, users={addr(1): 0.5})}, {a: 2000000}, {(a, addr(1)): (date_word(1969, 365), 0, 0)})

    def summ(name, v, eq):
        c = dict(vaults={v['user']: v}, eq=eq)
        got, want = run_summary(img, c), want_summary(c)
        r = got['rows'][0]
        rows.append(('summary', name, json.dumps([r['tag'], r['tvl'], r['created'], r['closed']]), 'same' if same_summary(got, want) else 'DIFF'))

    summ('normal vault: tvl is total over 1e6, tag at +0x00', vault(a, name=b'one', created=(date_word(2024, 40), 5, 7000000), closed=1), {a: 2500000})
    summ('parent vault carries its child set', vault(a, tag=2, name=b'two', children=[b], created=(date_word(2024, 40), 0, 0)), {a: 1, b: 2})
    summ('parent vault with no children: empty set words', vault(a, tag=2, name=b'', created=(date_word(1969, 300), 0, 0)), {a: 1})
    return rows


def key_rows(img):
    rows = []
    for fn, lea, ln, off, note in KEYS:
        i, j = decode(img.rd, lea), decode(img.rd, ln)
        n = j.args[1][1]
        key = img.rd(i.args[1][1], n).decode('ascii')
        if key != note:
            raise ValueError(f'key at {lea:#x}: {key}')
        rows.append((f'{fn:#x}', f'{lea:#x}', key, str(n), f'{off:#x}'))
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
    keys = key_rows(img)
    write_tsv(out / 'functions.tsv', ('start', 'end', 'bytes', 'sha256', 'role'), funcs)
    write_tsv(out / 'stubs.tsv', ('site', 'kind', 'target', 'fde_start', 'fde_end', 'role'), stubs)
    write_tsv(out / 'callers.tsv', ('function', 'site', 'kind', 'site_fde'), callers)
    write_tsv(out / 'pins.tsv', ('group', 'va', 'instruction', 'meaning'), pins)
    write_tsv(out / 'layout.tsv', ('struct', 'offset', 'width', 'va', 'instruction', 'meaning'), layout)
    write_tsv(out / 'locations.tsv', ('record', 'path', 'line', 'column', 'use'), locs)
    write_tsv(out / 'outcomes.tsv', ('family', 'class', 'vectors'), [(k[0], k[1], v) for k, v in sorted(counts.items())])
    write_tsv(out / 'cases.tsv', ('family', 'scenario', 'result', 'model'), named)
    write_tsv(out / 'json-keys.tsv', ('serializer', 'lea', 'key', 'length', 'row_offset'), keys)
    evidence = {'binary': BINARY, 'sha256': SHA256, 'pins': len(pins), 'layout_rows': len(layout), 'functions': len(funcs),
                'function_bytes': sum(int(r[2]) for r in funcs), 'stubs': len(stubs), 'caller_sites': len(callers), 'locations': len(locs),
                'named_cases': len(named), 'vectors': sum(counts.values()), 'vector_disagreements': 0, 'distinct_outcomes': len(counts),
                'json_keys': len(keys)}
    (out / 'evidence.json').write_text(json.dumps(evidence, indent=1, sort_keys=True) + '\n', encoding='ascii')


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--out', required=True)
    generate(ap.parse_args().out)


if __name__ == '__main__':
    main()
