#!/usr/bin/env python3
"""vaults: node #94 vaultTransfer path: wrapper 0x1e5fb20, user class router 0x27312c0 and body 0x27362b0.

This tool reads ELF bytes only.  It decodes pinned instructions with a small fail-closed x86-64 subset
decoder and evaluates the listed function bodies in Python, with their other calls replaced by named
stubs.  Each result is compared with a plain formula over deterministic vectors.  Nothing from the
binary runs.

    python3 tools/vault_transfer_path.py --out <dir>

writes evidence.json, functions.tsv, stubs.tsv, callers.tsv, pins.tsv, layout.tsv, locations.tsv,
cases.tsv and outcomes.tsv.
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
    ('wrapper', 0x1e5fb68, 'xor rcxd,rcxd', 'zero flag'),
    ('wrapper', 0x1e5fb6a, 'xor r8d,r8d', 'zero key'),
    ('wrapper', 0x1e5fb72, 'call 0x27312c0', 'router call'),
    ('wrapper', 0x1e5fb7d, 'cmp [rsp+0x18]:16,0x186', 'code 390 maps to tag 13'),
    ('router', 0x27312fa, 'movzx rbxd,[rax+0x3c]:8', 'class byte'),
    ('router', 0x27312fe, 'cmp rbxd,0x4', 'class 4 and up branch'),
    ('router', 0x2731307, 'test [r15+0x5b1]:8,0x1', 'bit 0 of +0x5b1 takes the direct call'),
    ('router', 0x2731315, 'cmp rbxd,0x2', 'class below 2 takes the direct call'),
    ('router', 0x273131e, 'jne 0x2731521', 'class 3 takes the slow route'),
    ('router', 0x273132c, 'cmp raxd,0x2', 'class 2 with fewer than 2 items takes the direct call'),
    ('router', 0x273133f, 'or raxb,[rsp+0x28]:8', 'switch off or flag set takes the direct call'),
    ('router', 0x273134b, 'test r14,r14', 'zero key takes the direct call'),
    ('router', 0x27313b1, 'call 0x272d000', 'settlement before the body'),
    ('router', 0x2731436, 'call 0x27362b0', 'body on the class 2 route'),
    ('router', 0x273143b, 'cmp [r15+0x3acb]:8,0x1', 'settlement after the body only with the switch'),
    ('router', 0x27314f2, 'call 0x277eba0', 'failed settlement is dropped'),
    ('router', 0x27314fc, 'test [r15+0x5b0]:8,0x1', 'bit 0 of +0x5b0'),
    ('router', 0x2731517, 'call 0x27362b0', 'direct body call'),
    ('router', 0x2731569, 'call 0x1f84640', 'window row'),
    ('router', 0x27315cb, 'mov [r12]:16,0x170', 'code 368'),
    ('router', 0x27315db, 'inc rax', 'row counter'),
    ('router', 0x27315f4, 'inc rax', 'exchange counter'),
    ('router', 0x2731649, 'imul3 rax,r13,0x2f0', 'clearinghouse stride 0x2f0'),
    ('router', 0x2731691, 'call 0x272fe00', 'slow entry step'),
    ('router', 0x27316b1, 'call 0x27362b0', 'body on the slow route'),
    ('router', 0x27316cc, 'call 0x272f880', 'class 4 exit step'),
    ('router', 0x2731700, 'call 0x272d000', 'class 3 settlement, failure dropped'),
    ('body', 0x27362ce, 'mov rax,[rcx+0x58]:64', 'depth counter on entry'),
    ('body', 0x273632e, 'mov rcxd,0x11e1a300', '300,000,000 ns'),
    ('body', 0x273639f, 'cmp r14d,raxd', 'date compare'),
    ('body', 0x27363ab, 'cmp r12d,r15d', 'seconds compare'),
    ('body', 0x27363b7, 'cmp rbpd,rbxd', 'nanosecond compare'),
    ('body', 0x27363bf, 'mov [r13+0x3ab0]:32,r14d', 'new time stored before any other test'),
    ('body', 0x273650b, 'mov [rax]:16,0x1f', 'code 31'),
    ('body', 0x27363f9, 'mov rax,0xccccccccccccccc', 'usd cut'),
    ('body', 0x273651a, 'mov [rax]:16,0x13f', 'code 319'),
    ('body', 0x2736528, 'cmp [r15-0x10]:32,0x2', 'caller is a vault: tag below 2 is refused'),
    ('body', 0x27365f7, 'mov [rcx]:16,0x19', 'code 25 with the caller'),
    ('body', 0x27366ca, 'mov [rcx]:16,0x7', 'code 7 with the vault'),
    ('body', 0x27366d4, 'cmp [rbp+0xac]:8,0x0', 'is_closed'),
    ('body', 0x27366e2, 'mov [rax]:16,0x8', 'code 8'),
    ('body', 0x2736744, 'cmp r14,0x4c4b40', 'deposit minimum'),
    ('body', 0x2736752, 'mov [rax]:16,0x29', 'code 41'),
    ('body', 0x2736819, 'call [0x5774b48]:64', 'deposit body'),
    ('body', 0x2736838, 'cmp r14,rax', 'none word means code in the rest of the result'),
    ('body', 0x2736786, 'cmp raxd,0x2', 'chain byte branch'),
    ('body', 0x273692a, 'cmp [r13+0xbb0]:8,0x0', 'cap switch'),
    ('body', 0x2736944, 'call 0x26f6050', 'cap formula'),
    ('body', 0x2736a08, 'call [0x5774b50]:64', 'withdraw validation'),
    ('body', 0x2736a7d, 'call 0x26f7ef0', 'pre-withdraw step'),
    ('body', 0x2736a82, 'test rbxb,0x1', 'flag runs the post step'),
    ('body', 0x2736b39, 'call [0x5774b58]:64', 'withdraw body'),
    ('body', 0x2736b47, 'je 0x273701f', 'none word: code 390 with no event'),
    ('body', 0x2736b70, 'je 0x2736e32', 'second word none skips the leader event'),
    ('body', 0x2736e27, 'call [0x5774738]:64', 'leader event first'),
    ('body', 0x2736f72, 'call [0x5774738]:64', 'user event'),
    ('body', 0x2736f90, 'call [0x5774b60]:64', 'scale and clamp'),
    ('body', 0x2736fe1, 'call 0x2712a00', 'vault sums'),
    ('body', 0x2737017, 'call 0x2712a00', 'user sum'),
    ('body', 0x2737024, 'mov [rax]:16,0x186', 'code 390'),
    ('sums', 0x2712a30, 'imul1 r13', 'signed divide by 10000'),
    ('sums', 0x2712a51, 'cmovne r15,r14', 'flag picks the second amount for +0x18'),
    ('cap', 0x26f6066, 'subsd xmm2,xmm0', '1 - fraction'),
    ('cap', 0x26f606a, 'mulsd xmm1,xmm2', 'base * (1 - fraction)'),
]


LAYOUT_ROWS = [
    ('action', 0x00, 8, 0x27363f6, '[r15]:64', 'usd'),
    ('action', 0x08, 20, 0x27363e9, '[r15+0x8]:128', 'vault address'),
    ('action', 0x1c, 1, 0x27363d9, '[r15+0x1c]:8', 'is_deposit'),
    ('vault_value', 0x00, 4, 0x2736528, '[r15-0x10]:32', 'relationship tag; r15 = value + 0x10'),
    ('vault_value', 0x08, 8, 0x2736538, '[r15-0x8]:64', 'child set root'),
    ('vault_value', 0x10, 8, 0x2736545, '[r15]:64', 'child set height'),
    ('vault_value', 0x98, 20, 0x2736bbf, '[rbp+0x98]:128', 'leader, the only user of the second event'),
    ('vault_value', 0xac, 1, 0x27366d4, '[rbp+0xac]:8', 'is_closed'),
    ('exchange', 0x58, 8, 0x27362ce, '[rcx+0x58]:64', 'depth counter, saturating up on entry and down on exit'),
    ('exchange', 0x60, 12, 0x27362e9, '[r13+0x60]:64', 'time: date, seconds, nanoseconds'),
    ('exchange', 0x5b0, 1, 0x27314fc, '[r15+0x5b0]:8', 'bit 0: class 4 and up take the direct call'),
    ('exchange', 0x5b1, 1, 0x2731307, '[r15+0x5b1]:8', 'bit 0: class below 4 takes the direct call'),
    ('exchange', 0x5c8, 8, 0x2736705, '[r13+0x5c8]:64', 'clearinghouse count'),
    ('exchange', 0x7d0, 8, 0x27315ed, '[r15+0x7d0]:64', 'saturating counter of the slow route'),
    ('exchange', 0x8d0, 8, 0x2736419, '[r13+0x8d0]:64', 'vault map root'),
    ('exchange', 0x8d8, 8, 0x273644b, '[r13+0x8d8]:64', 'vault map height'),
    ('exchange', 0x8f2, 1, 0x273677e, '[r13+0x8f2]:8', 'chain byte selecting the special vault address'),
    ('exchange', 0xbb0, 1, 0x273692a, '[r13+0xbb0]:8', 'cap switch for the special vault'),
    ('exchange', 0xbb8, 8, 0x2736934, '[r13+0xbb8]:64', 'cap base, u64 read as i64'),
    ('exchange', 0x39c8, 8, 0x273693b, '[r13+0x39c8]:64', 'cap fraction: cap = base * (1 - fraction)'),
    ('exchange', 0x3ab0, 12, 0x273630d, '[r13+0x3ab0]:64', 'last accepted time'),
    ('exchange', 0x3acb, 1, 0x2731335, '[r15+0x3acb]:8', 'switch of the settlement route'),
    ('account', 0x10, 8, 0x2712a41, '[rbx+0x10]:64', 'i64 sum, moved for the vault only'),
    ('account', 0x18, 8, 0x2712a6d, '[rbx+0x18]:64', 'i64 sum, moved for both addresses'),
    ('clearinghouse', 0x2a0, 8, 0x370c1e5, '[rdi+0x2a0]:64', 'f64 scale on the amount'),
]

LOCATIONS = [(0x5714da0, 'abs of i64::MIN in scale and clamp'), (0x5715ef8, 'account sum add'), (0x56e9af8, 'clearinghouse unwrap in the body'), (0x56e9ae0, 'clearinghouse unwrap in the router')]

FUNCS = [(0x1e5fb20, 'vaultTransfer wrapper, dispatch index 43'), (0x27312c0, 'user class router'), (0x27362b0, 'vaultTransfer body'),
         (0x2755400, 'user row lookup with default row'), (0x26f6050, 'cap of the special vault'), (0x25a7f50, 'vault map lookup'), (0x370c1e0, 'scale and clamp'), (0x2712a00, 'two sum writer')]

STUBS = [(0x576dfd8, 'allocate'), (0x576dfe0, 'memcpy'), (0x576e010, 'free'), (0x576e488, 'memcmp'), (0x5773190, 'overflow recorder'),
         (0x3379490, 'drop of a code value'), (0x3987cb0, '32-byte hash'), (0x5774738, 'event push'), (0x1f849b0, 'user account entry'),
         (0x576e8a8, 'time add, 300 ms'), (0x576e8b0, 'date add days'), (0x5774b48, 'deposit body, 0x395b3a0, open PR #873'),
         (0x5774b50, 'withdraw validation, 0x39582c0, open PR #630'), (0x5774b58, 'withdraw body, 0x395bdd0, open PR #632'),
         (0x26f7ef0, 'pre-withdraw step, open PR #864'), (0x576f488, 'lazy getter'), (0x26f7280, 'post-validation step on the flag'),
         (0x5773d80, 'clearinghouse by index'), (0x5774740, 'dex row by key'), (0x5774748, 'window test'), (0x1f84640, 'window row entry'),
         (0x272d000, 'settlement step'), (0x272fe00, 'slow route entry step'), (0x272f880, 'class 4 exit step'), (0x277eba0, 'code drop')]

SPECIAL = {2: (0x3ef9dc, 0xa0b0eafa), 3: (0x3ef9f0, 0x3f30de1)}

CUT = 0x0ccccccccccccccc
OK = 0x186
NONE_WORD = 0x8000000000000019
CLAMP = 0x147ae147ae147ae
I64MAX, I64MIN = (1 << 63) - 1, -(1 << 63)
SENT = 0x10
SP = 0x7f00000
HEAP = 0x8000000
EX = 0x7900000
CH = 0x7a00000
ACTION = 0x7810000
USER = 0x7830000
OUT = 0x7820000
DEFAULT_ROW = 0x5786190
USER_CTRL = 0x7860000
H_USER = 0x3300000000000000
ROW = 0x7a80000
DAY = 86400


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


def i2s(b):
    return b.hex()


class World:
    """One fixture: a Machine, its bump heap and the named stubs."""

    def __init__(self, img, real=None):
        self.img = img
        self.m = Machine(img.rd, img.rd, self.hook)
        self.m.cache = img.cache
        if real is not None:
            self.m.real_map = real
        self.m.r[4] = SP
        self.heap = HEAP
        self.recorded = []
        self.log = []
        self.events = []
        self.accounts = {}
        self.deposit = None
        self.validate = None
        self.withdraw = None
        self.windows = [0, 0]
        self.settle = [(OK,)] * 4
        self.dex_row = 0
        self.stubs = {0x576dfd8: self.malloc, 0x576dfe0: self.memcpy, 0x576e010: lambda *a: 0, 0x576e488: self.memcmp,
                      0x5773190: self.recorder, 0x3379490: lambda *a: 0, 0x3987cb0: self.hash32, 0x5774738: self.event,
                      0x1f849b0: self.account, 0x576e8a8: self.time_add, 0x576e8b0: self.date_add, 0x5774b48: self.deposit_stub,
                      0x5774b50: self.validate_stub, 0x5774b58: self.withdraw_stub, 0x26f7ef0: self.pre, 0x576f488: lambda *a: 0,
                      0x26f7280: self.post, 0x5773d80: self.ch_get, 0x5774740: self.dex_get, 0x5774748: self.window, 0x1f84640: self.window_row,
                      0x272d000: self.settle_stub, 0x272fe00: self.entry_step, 0x272f880: self.exit_step, 0x277eba0: self.drop,
                      0x27362b0: self.body_stub, 0x399c7a0: lambda *a: 0, 0x2840fb0: lambda *a: H_USER, 0x576e048: self.panic_unwrap, 0x576eb38: self.panic_rdi,
                      0x576e470: self.panic_rdi, 0x576e468: self.panic_rdi}
        q(self.m, 0x576e488, 0x576e488)
        q(self.m, 0x5774748, 0x5774748)
        q(self.m, 0x57749b8, DEFAULT_ROW)
        self.m.store(DEFAULT_ROW, bytes(0x48))
        self.m.store(0x577ab98, bytes(4))
        self.body_code = OK

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

    def memcmp(self, m, a, b, n, *_):
        x, y = m.load(a, n), m.load(b, n)
        return ((x > y) - (x < y)) & M64

    def recorder(self, m, a, b, *_):
        self.recorded.append(b)

    def hash32(self, m, out, *_):
        m.store(out, bytes(range(0x90, 0xb0)))

    def event(self, m, ptr, users, when, hsh, ev, *_):
        n = rq(m, users + 16)
        self.log.append(('event', rq(m, users), n, m.load(rq(m, users + 8), 20 * n).hex(), m.load(when, 12).hex(), m.load(hsh, 2).hex(), rq(m, ev), rq(m, ev + 8)))

    def account(self, m, map_ptr, key, *_):
        k = m.load(key, 20)
        self.log.append(('account', k.hex()))
        if k not in self.accounts:
            self.accounts[k] = self.alloc(0x40)
        return self.accounts[k]

    def time_add(self, m, out, t, secs, nanos, *_):
        s, n = struct.unpack('<II', m.load(t, 8))
        total = s * 10 ** 9 + n + (secs & M64) * 10 ** 9 + (nanos & 0xffffffff)
        days = total // (DAY * 10 ** 9)
        total -= days * DAY * 10 ** 9
        m.store(out, struct.pack('<IIq', total // 10 ** 9, total % 10 ** 9, days * DAY))

    def date_add(self, m, date, days, *_):
        return ((date & 0xffffffff) + sx(days & 0xffffffff, 32)) & 0xffffffff

    def deposit_stub(self, m, out, value, user, usd, when, nine, *_):
        self.log.append(('deposit', m.load(value + 0x84, 20).hex(), m.load(user, 20).hex(), usd, m.load(when, 12).hex(), nine))
        m.store(out, self.deposit)

    def validate_stub(self, m, out, value, user, flag, usd, when, *_):
        sp = m.r[4]
        self.log.append(('validate', m.load(value + 0x84, 20).hex(), m.load(user, 20).hex(), flag & 255, usd, m.load(when, 12).hex(), rq(m, sp) & 1, rq(m, sp + 8) if rq(m, sp) & 1 else None))
        m.store(out, self.validate)

    def withdraw_stub(self, m, out, value, user, amount, when, ctx, *_):
        self.log.append(('withdraw', m.load(value + 0x84, 20).hex(), m.load(user, 20).hex(), amount, m.load(when, 12).hex(), m.x[0][0]))
        m.store(out, self.withdraw)

    def pre(self, m, ex, addr_ptr, amount, *_):
        self.log.append(('pre', m.load(addr_ptr, 20).hex(), amount))

    def post(self, m, ex, action, *_):
        self.log.append(('post', m.load(action, 20).hex(), m.x[0][0]))

    def ch_get(self, m, chs, i, *_):
        self.log.append(('ch', chs - EX, i & 0xffffffff))
        return CH

    def dex_get(self, m, base, key, *_):
        self.log.append(('dex', key))
        return ROW

    def window(self, m, row, when, a, b, *_):
        self.log.append(('window', row - ROW, a, b))
        return self.windows.pop(0)

    def window_row(self, m, base, user, *_):
        self.log.append(('window_row', m.load(user, 20).hex()))
        return ROW + 0x1000

    def settle_stub(self, m, out, ex, user, a, b, c, *_):
        sp = m.r[4]
        self.log.append(('settle', m.load(user, 20).hex(), a, b, c, rq(m, sp), rq(m, sp + 8), rq(m, sp + 16)))
        code = self.settle.pop(0)[0]
        m.store(out, code.to_bytes(2, 'little'))

    def entry_step(self, m, ex, user, a, b, c, d, *_):
        self.log.append(('entry', m.load(user, 20).hex(), a, b, c, rq(m, d), rq(m, m.r[4]) & 0xffffffff))

    def exit_step(self, m, ex, user, a, b, c, *_):
        self.log.append(('exit', m.load(user, 20).hex(), a, b, c))

    def drop(self, m, *_):
        self.log.append(('drop',))

    def body_stub(self, m, out, user, action, ex, *_):
        self.log.append(('body', m.load(user, 20).hex(), action))
        m.store(out, self.body_code.to_bytes(2, 'little'))

    def panic_unwrap(self, m, msg, n, payload, vt, loc, *_):
        raise Panic('unwrap', loc, m.load(payload, 2))

    def panic_rdi(self, m, loc, *_):
        raise Panic('panic', loc)


REAL = {t: t for t, _ in FUNCS}
REAL.update({0x5774b60: 0x370c1e0})
Machine.real_map = REAL
NO_BODY = {k: v for k, v in REAL.items() if k != 0x27362b0}


def call(w, fn, *args, stack=()):
    m = w.m
    for v in reversed(stack):
        m.r[4] -= 8
        q(m, m.r[4], v)
    m.r[4] -= 8
    q(m, m.r[4], SENT)
    for reg, v in zip((7, 6, 2, 1, 8, 9), args):
        m.r[reg] = v
    m.run(fn, {SENT}, 400000)


def tree(w, items, key_off, val_off, val_len, len_off, edge_off, parent_off, pidx_off, size):
    """Write sorted (key, value) items as a B-tree of height 0 or 1 and return (root, height)."""
    m = w.m

    def node(rows, edges=()):
        n = w.alloc(size)
        for i, (k, v) in enumerate(rows):
            m.store(n + key_off + i * len(k), k)
            if val_len:
                m.store(n + val_off + i * val_len, v)
        m.store(n + len_off, len(rows).to_bytes(2, 'little'))
        for i, e in enumerate(edges):
            q(m, n + edge_off + i * 8, e)
        return n
    if len(items) <= 11:
        return node(items), 0
    mid = len(items) // 2
    return node(items[mid:mid + 1], [node(items[:mid]), node(items[mid + 1:])]), 1


def vault_bytes(w, v):
    b = bytearray(0xb0)
    struct.pack_into('<Q', b, 0, v['tag'])
    if v['children']:
        root, height = tree(w, [(k, b'') for k in sorted(set(v['children']))], 8, 0, 0, 0xe6, 0xe8, None, None, 0x180)
        struct.pack_into('<QQ', b, 8, root, height)
    b[0x84:0x98] = v['user']
    b[0x98:0xac] = v['leader']
    b[0xac] = v['closed']
    return bytes(b)


def vault(user, leader=None, tag=0, closed=0, children=()):
    return {'user': user, 'leader': leader or addr(99), 'tag': tag, 'closed': closed, 'children': list(children)}


def time_bytes(t):
    return struct.pack('<iII', *t)


def exchange(w, c):
    m = w.m
    m.store(EX, c.get('flag', 1).to_bytes(4, 'little'))
    q(m, EX + 8, 0x1111)
    q(m, EX + 0x28, 0x2222)
    q(m, EX + 0x58, c.get('depth', 0))
    m.store(EX + 0x60, time_bytes(c['now']))
    m.store(EX + 0x3ab0, time_bytes(c['last']))
    q(m, EX + 0x5c0, CH)
    q(m, EX + 0x5c8, c.get('chs', 1))
    m.store(EX + 0x8f2, bytes((c.get('chain', 3),)))
    m.store(EX + 0xbb0, bytes((c.get('cap_on', 0),)))
    q(m, EX + 0xbb8, c.get('cap_base', 0))
    q(m, EX + 0x39c8, f2i(c.get('cap_frac', 0.0)))
    q(m, CH + 0x2a0, f2i(c.get('scale', 1.0)))
    if c['vaults']:
        root, height = tree(w, [(k, vault_bytes(w, v)) for k, v in sorted(c['vaults'].items())], 0x798, 0, 0xb0, 0x876, 0x878, None, None, 0x940)
        q(m, EX + 0x8d0, root)
        q(m, EX + 0x8d8, height)


def rows_of(words):
    return b''.join(int(x & M64).to_bytes(8, 'little') for x in words)


def run_body(img, c):
    w = World(img)
    m = w.m
    exchange(w, c)
    if c.get('deposit_word') is not None:
        w.deposit = rows_of([c['deposit_word'], c['payload']]) if c['deposit_word'] != NONE_WORD else rows_of([NONE_WORD, c['deposit_code'], 0x77])
    v = c.get('validate')
    if v:
        w.validate = rows_of([OK, v['flag'], f2i(v['ratio']), v['amount'], f2i(v['price'])]) if v['code'] == OK else rows_of([v['code'], 0x55, f2i(1.5), 7, f2i(2.5)])
    wd = c.get('withdraw')
    if wd:
        b = bytearray(0x168)
        struct.pack_into('<QQ', b, 0, wd['word'], wd['p1'])
        struct.pack_into('<QQQ', b, 0xb0, wd['amount'], wd['word2'], wd['p2'])
        w.withdraw = bytes(b)
    m.store(USER, c['user'])
    q(m, ACTION, c['usd'])
    m.store(ACTION + 8, c['target'])
    m.store(ACTION + 0x1c, bytes((c['deposit'],)))
    for k, (a, b) in c.get('start', {}).items():
        p = w.alloc(0x40)
        w.accounts[k] = p
        q(m, p + 0x10, a)
        q(m, p + 0x18, b)
    try:
        call(w, 0x27362b0, OUT, USER, ACTION, EX)
    except Panic as e:
        return {'panic': e.args[0], 'loc': e.args[1]}
    code = int.from_bytes(m.load(OUT, 2), 'little')
    res = {'code': code, 'log': w.log, 'recorded': len(w.recorded), 'depth': rq(m, EX + 0x58), 'last': m.load(EX + 0x3ab0, 12).hex(),
           'accounts': sorted((k.hex(), i64(rq(m, p + 0x10)), i64(rq(m, p + 0x18))) for k, p in w.accounts.items())}
    if code == 0x13f:
        res['usd'] = rq(m, OUT + 8)
    if code in (7, 25):
        res['addr'] = m.load(OUT + 2, 20).hex()
    return res


def scale_clamp(amount, scale):
    x = float(amount) * scale
    if x != x or abs(x) == math.inf:
        r = 0
    else:
        y = min(max(x, -2.0 ** 63), 2.0 ** 63)
        r = I64MAX if y > 9223372036854774784.0 else int(y)
    if r == I64MIN:
        return None
    return max(-CLAMP, min(CLAMP, r))


def tdiv(a):
    return abs(a) // 10000 * (1 if a >= 0 else -1)


def add_sat(a, b):
    v = a + b
    return max(I64MIN, min(I64MAX, v)), int(v != max(I64MIN, min(I64MAX, v)))


def cap_value(base, frac):
    x = float(sx(base & M64, 64)) * (1.0 - frac)
    if x != x or abs(x) == math.inf:
        return 0
    y = min(max(x, -2.0 ** 63), 2.0 ** 63)
    return I64MAX if y > 9223372036854774784.0 else int(y) & M64


def special_address(img, chain):
    if chain < 2:
        return None
    p, tail = SPECIAL[2 if chain == 2 else 3]
    return img.rd(p, 16) + tail.to_bytes(4, 'little')


def model_body(img, c):
    now, last = tuple(c['now']), tuple(c['last'])
    total = last[1] * 10 ** 9 + last[2] + 300000000
    days = total // (DAY * 10 ** 9)
    total -= days * DAY * 10 ** 9
    gate = (last[0] + days, total // 10 ** 9, total % 10 ** 9)
    depth = c.get('depth', 0)
    d2 = min(depth + 1, M64)
    res = {'log': [], 'recorded': 0, 'depth': max(d2 - 1, 0), 'last': time_bytes(last).hex(),
           'accounts': sorted((k.hex(), a, b) for k, (a, b) in c.get('start', {}).items())}
    log = res['log']
    if now < gate:
        res['code'] = 31
        return res
    res['last'] = time_bytes(now).hex()
    u, t, usd = c['user'], c['target'], c['usd']
    if usd >= CUT:
        return dict(res, code=0x13f, usd=usd)
    vs = c['vaults']
    if u in vs and (vs[u]['tag'] < 2 or t not in vs[u]['children']):
        return dict(res, code=25, addr=u.hex())
    if t not in vs:
        return dict(res, code=7, addr=t.hex())
    if vs[t]['closed']:
        return dict(res, code=8)
    if c.get('chs', 1) == 0:
        return {'panic': 'unwrap', 'loc': 0x56e9af8}
    when = time_bytes(now).hex()
    hash_part = '9091' if c.get('flag', 1) == 1 else '0000'

    def evt(users, word, first):
        k = len(users)
        log.append(('event', k, k, b''.join(users).hex(), when, hash_part, word, first))

    if c['deposit']:
        if usd < 5000000:
            return dict(res, code=41)
        log.append(('deposit', vs[t]['user'].hex(), u.hex(), usd, when, 0))
        if c['deposit_word'] == NONE_WORD:
            return dict(res, code=c['deposit_code'] & 0xffff)
        evt([u, t], c['deposit_word'], c['payload'])
        amount = -usd
    else:
        cap = None
        sp = special_address(img, c.get('chain', 3))
        if t == sp and c.get('cap_on', 0):
            cap = cap_value(c.get('cap_base', 0), c.get('cap_frac', 0.0))
        log.append(('validate', vs[t]['user'].hex(), u.hex(), int(usd != 0), usd, when, int(cap is not None), cap))
        v = c['validate']
        if v['code'] != OK:
            return dict(res, code=v['code'] & 0xffff)
        log.append(('pre', t.hex(), v['amount']))
        if v['flag'] & 1:
            log.append(('post', t.hex(), f2i(v['ratio'])))
        log.append(('ch', 0x5b8, 0))
        log.append(('withdraw', vs[t]['user'].hex(), u.hex(), v['amount'], when, f2i(v['price'])))
        wd = c['withdraw']
        if wd['word'] == NONE_WORD:
            return dict(res, code=OK)
        if wd['word2'] != NONE_WORD:
            evt([vs[t]['leader']], wd['word2'], wd['p2'])
        evt([u, t], wd['word'], wd['p1'])
        amount = i64(wd['amount'])
    log.append(('ch', 0x5b8, 0))
    r = scale_clamp(amount, c.get('scale', 1.0))
    if r is None:
        return {'panic': 'panic', 'loc': 0x5714da0}
    acc = dict(c.get('start', {}))
    rec = 0
    log.append(('account', t.hex()))
    a, b = acc.get(t, (0, 0))
    a, r1 = add_sat(a, tdiv(-r))
    b, r2 = add_sat(b, tdiv(-r))
    acc[t] = (a, b)
    log.append(('account', u.hex()))
    a, b = acc.get(u, (0, 0))
    b, r3 = add_sat(b, tdiv(r))
    acc[u] = (a, b)
    res['recorded'] = r1 + r2 + r3
    res['accounts'] = sorted((k.hex(), a, b) for k, (a, b) in acc.items())
    return dict(res, code=OK)


# Router 0x27312c0 and wrapper 0x1e5fb20

def run_router(img, c):
    w = World(img, NO_BODY)
    m = w.m
    exchange(w, dict(now=(100, 1, 2), last=(90, 0, 0), vaults={}, chs=c.get('chs', 1)))
    m.store(EX + 0x5b0, bytes((c['g4'], c['g3'])))
    m.store(EX + 0x3acb, bytes((c['switch'],)))
    for off, v in ((0x4e8, 0x41), (0x4f0, 0x42), (0x4f8, 0x43), (0x500, 0x44)):
        q(m, EX + off, v)
    q(m, EX + 0x7d0, c.get('counter', 5))
    q(m, ROW + 0x1000 + 0x30, c.get('row_counter', 7))
    q(m, ROW + 0x50, c['row50'])
    for i in range(4):
        q(m, CH + i * 0x2f0 + 0x50, 0xabc + i)
    q(m, EX + 0x758, 1)
    q(m, EX + 0x740, USER_CTRL)
    q(m, EX + 0x748, 31)
    m.store(USER_CTRL, bytes((0xff,)) * 48)
    m.store(USER_CTRL, bytes((H_USER >> 57,)))
    m.store(USER_CTRL + 32, bytes((H_USER >> 57,)))
    row = bytearray(0x58)
    row[:20] = c['user']
    row[0x18 + 0x3c] = c['cls']
    m.store(USER_CTRL - 0x58, bytes(row))
    w.windows = list(c['windows'])
    w.settle = [(x,) for x in c['settle']]
    w.body_code = c['body']
    m.store(USER, c['user'])
    q(m, 0x7840000, c['count'])
    args = (OUT, EX, USER, c['flag'], c['key'], 0x7840000)
    try:
        if c.get('wrapper'):
            q(m, ACTION, 0)
            call(w, 0x1e5fb20, OUT, ACTION, USER, EX)
        else:
            call(w, 0x27312c0, *args, stack=(USER, ACTION, 0))
    except Panic as e:
        return {'panic': e.args[0], 'loc': e.args[1]}
    return {'out': int.from_bytes(m.load(OUT + (8 if c.get('wrapper') else 0), 2), 'little'), 'tag': m.load(OUT, 1)[0] if c.get('wrapper') else None,
            'log': w.log, 'counter': rq(m, EX + 0x7d0), 'row_counter': rq(m, ROW + 0x1000 + 0x30)}


def model_router(c):
    log = []
    u = c['user'].hex()
    res = {'log': log, 'counter': c.get('counter', 5), 'row_counter': c.get('row_counter', 7), 'tag': None}
    cls, key, flag = c['cls'], c['key'], c['flag'] & 1
    if c.get('wrapper'):
        res['tag'] = None
    body = ('body', u, ACTION)

    def fin():
        if c.get('wrapper'):
            ok = c['body'] == OK
            return dict(res, out=0 if ok else c['body'], tag=13 if ok else 14) if not ok else dict(res, out=None, tag=13)
        return dict(res, out=c['body'])

    if cls >= 4:
        slow = not c['g4'] & 1
    elif c['g3'] & 1 or cls < 2:
        slow = False
    else:
        slow = cls == 3
    if not slow:
        mid = cls == 2 and not (c['g3'] & 1) and c['count'] & 0xffffffff >= 2 and not ((c['switch'] ^ 1) | flag) & 1 and key != 0
        if not mid:
            log.append(body)
            return fin()
        sw = c['row50']
        log.append(('dex', key))
        log.append(('settle', u, sw, int(sw == 0), 0, 1, key, 0))
        if c['settle'][0] != OK:
            log.append(('drop',))
        log.append(body)
        if c['switch'] == 1:
            log.append(('dex', key))
            log.append(('settle', u, sw, 1, key, int(sw == 0), 0, 0))
            if c['settle'][1] != OK:
                log.append(('drop',))
        return fin()
    log.append(('window_row', u))
    log.append(('window', 0x1000, 0x41, 0x42))
    log.append(('window', 0x1018, 0x43, 0x44))
    if not (c['windows'][0] & 255 or c['windows'][1] & 255):
        return dict(res, out=0x170, tag=14 if c.get('wrapper') else None)
    res['counter'] = min(res['counter'] + 1, M64)
    res['row_counter'] = min(res['row_counter'] + 1, M64)
    ch = key
    if not flag:
        if key >= c.get('chs', 1):
            return {'panic': 'unwrap', 'loc': 0x56e9ae0}
        ch = 0xabc + key
    log.append(('entry', u, ch, flag ^ 1, key, c['count'], int(cls == 4)))
    log.append(body)
    if cls == 4:
        log.append(('exit', u, ch, flag ^ 1, key))
    else:
        log.append(('settle', u, ch, flag ^ 1, key, 0, ANY, 0))
        if c['settle'][0] != OK:
            log.append(('drop',))
    return fin()


ANY = object()


def clean(res):
    """The second stack word of the exit settlement call is not set by the caller."""
    for i, row in enumerate(res.get('log', [])):
        if row[0] == 'settle' and len(row) == 8 and row[6] is ANY:
            pass
    return res


def same_router(got, want):
    if set(got) != set(want):
        return False
    for k in got:
        if k == 'log':
            if len(got[k]) != len(want[k]):
                return False
            for a, b in zip(got[k], want[k]):
                if len(a) != len(b) or any(y is not ANY and x != y for x, y in zip(a, b)):
                    return False
        elif got[k] != want[k]:
            return False
    return True


def body_cases(img, n):
    s = Stream('vault-transfer')
    for _ in range(n):
        u, t, leader = addr(1), addr(2), addr(3)
        count = s.pick([1, 3, 13])
        vs = {t: vault(t, leader, closed=int(s.u(10) == 0))}
        for i in range(count - 1):
            k = addr(20 + i)
            vs[k] = vault(k, leader)
        r = s.u(8)
        if r == 0:
            del vs[t]
        elif r == 1:
            vs[u] = vault(u, leader, tag=s.u(2))
        elif r == 2:
            vs[u] = vault(u, leader, tag=2, children=[t, addr(30)] if s.u(2) else [addr(30)])
        now = (100 + s.u(3), s.pick([0, 1, 86399]), s.pick([0, 299999999, 300000000, 999999999]))
        last = s.pick([(now[0], now[1], max(now[2] - 300000000, 0)), (now[0] - 1, 86399, 699999999), (now[0] - 1, 86399, 700000000), now] + [(now[0] - 2, 0, 0)] * 8 + [(now[0] + 1, 0, 0)])
        deposit = s.u(2)
        usd = s.pick([0, 1, 4999999, 5000000, 5000001, 123456789, 123456789, 999999999, CUT - 1, CUT])
        c = dict(now=now, last=last, vaults=vs, user=u, target=t, usd=usd, deposit=deposit, flag=s.u(2), chain=s.pick([1, 2, 3, 3]), chs=0 if s.u(24) == 0 else 1,
                 scale=s.pick([1.0, 1.0, 0.5, 2.0, 1e-4, 1e10]), depth=s.pick([0, 0, 5, M64]), cap_on=s.u(2), cap_base=s.pick([0, 1000000, 1 << 40]), cap_frac=s.pick([0.0, 0.25, 0.9999]))
        if s.u(4) == 0 and c['chain'] >= 1:
            sp = special_address(img, max(c['chain'], 2))
            vs[sp] = vs.pop(t, vault(sp, leader))
            vs[sp]['user'] = sp
            vs[sp]['closed'] = 0
            c['target'] = sp
        c['deposit_word'] = NONE_WORD if s.u(4) == 0 else 0x8000000000000004
        c['deposit_code'] = s.pick([0, 13, 51])
        c['payload'] = 0x1234
        c['validate'] = dict(code=OK if s.u(4) else s.pick([11, 14, 18]), flag=s.u(2), ratio=s.pick([0.5, 1.0]), amount=s.pick([1, 19999, 20000, 123456789]), price=s.pick([1.25, 2.0]))
        c['withdraw'] = dict(word=NONE_WORD if s.u(8) == 0 else 0x8000000000000005, p1=0x5678, amount=s.pick([1, 19999, 20000, 123456789, CLAMP + 5]),
                             word2=NONE_WORD if s.u(2) else 0x8000000000000007, p2=0x9abc)
        start = {}
        for k in (u, t):
            if s.u(3) == 0:
                start[k] = (s.pick([0, 5, I64MAX, I64MIN]), s.pick([0, -7, I64MAX, I64MIN]))
        c['start'] = start
        yield c


def router_cases(n):
    s = Stream('router')
    for _ in range(n):
        yield dict(user=addr(1), cls=s.pick([0, 1, 2, 2, 3, 3, 4, 5]), g4=s.u(2), g3=s.u(2), switch=s.u(2), count=s.pick([0, 1, 2, 3]), flag=s.u(2), key=s.pick([0, 0, 1, 3]),
                   row50=s.pick([0, 7]), windows=s.pick([[0, 0], [1, 0], [0, 1], [1, 1], [0x101, 0]]), settle=[s.pick([OK, OK, 0x33]), s.pick([OK, 0x34])],
                   body=s.pick([OK, OK, 8, 41]), chs=s.pick([1, 1, 4]), counter=s.pick([5, M64]), row_counter=s.pick([7, M64]))


def wrapper_cases(n):
    s = Stream('wrapper')
    for _ in range(n):
        yield dict(user=addr(1), cls=s.pick([0, 2, 3, 4]), g4=s.u(2), g3=s.u(2), switch=s.u(2), count=0, flag=0, key=0, row50=0, windows=s.pick([[0, 0], [1, 0]]),
                   settle=[s.pick([OK, 0x33]), OK], body=s.pick([OK, 8]), wrapper=True)


def norm_wrapper(got):
    return dict(got, out=None if got.get('tag') == 13 else got.get('out'))


def base(img=None, **k):
    u, t = addr(1), addr(2)
    c = dict(now=(100, 5, 0), last=(90, 0, 0), vaults={t: vault(t, addr(3))}, user=u, target=t, usd=10000000, deposit=1, deposit_word=0x8000000000000004, deposit_code=0, payload=0x1234,
             validate=dict(code=OK, flag=0, ratio=0.5, amount=30000, price=1.25), withdraw=dict(word=0x8000000000000005, p1=0x5678, amount=30000, word2=NONE_WORD, p2=0x9abc), start={})
    c.update(k)
    return c


def named_cases(img):
    """Named scenarios that a reader can follow; each row is the observed result of the real bytes."""
    u, t, leader = addr(1), addr(2), addr(3)
    rows = []

    def b(name, **k):
        c = base(**k)
        got, want = run_body(img, c), model_body(img, c)
        rows.append(('body', name, got.get('code', got.get('panic')), json.dumps(got.get('accounts')), [x[0] for x in got.get('log', [])], 'same' if got == want else 'DIFF'))

    b('deposit: vault moves both sums, depositor only +0x18')
    b('deposit one below 5000000: code 41', usd=4999999)
    b('gate equal to now passes: 300 ms exactly', now=(100, 5, 300000000), last=(100, 5, 0))
    b('one ns short: code 31, stored time unchanged', now=(100, 5, 299999999), last=(100, 5, 0))
    b('code 319 still stores the new time', usd=CUT)
    b('gate rolls past midnight', now=(101, 0, 299999999), last=(100, 86399, 999999999))
    b('missing vault: code 7 with the vault address', vaults={})
    b('caller is a normal vault: code 25 with the caller', vaults={t: vault(t), u: vault(u)})
    b('caller is a child vault: code 25', vaults={t: vault(t), u: vault(u, tag=1)})
    b('caller is a parent and target is its child: passes', vaults={t: vault(t), u: vault(u, tag=2, children=[t])})
    b('caller is a parent and target is not its child: code 25', vaults={t: vault(t), u: vault(u, tag=2, children=[addr(40)])})
    b('closed vault: code 8', vaults={t: vault(t, closed=1)})
    b('withdraw with no leader event: one event, sums move', deposit=0)
    b('withdraw with leader event: two events, leader first', deposit=0, withdraw=dict(word=0x8000000000000005, p1=1, amount=30000, word2=0x8000000000000007, p2=2))
    b('withdraw body returns the none word: code 390, no event, no sum', deposit=0, withdraw=dict(word=NONE_WORD, p1=1, amount=30000, word2=NONE_WORD, p2=2))
    b('flag from validation runs the post step', deposit=0, validate=dict(code=OK, flag=1, ratio=0.5, amount=30000, price=1.25))
    sp = special_address(img, 3)
    b('Mainnet special vault with switch on: cap passed to validation', deposit=0, vaults={sp: vault(sp)}, target=sp, cap_on=1, cap_base=1000000, cap_frac=0.25)
    b('same vault with switch off: no cap', deposit=0, vaults={sp: vault(sp)}, target=sp, cap_on=0, cap_base=1000000, cap_frac=0.25)
    b('chain 1: no address compare', deposit=0, vaults={sp: vault(sp)}, target=sp, cap_on=1, cap_base=1000000, chain=1)
    b('scale near 1e10 clamps at 0x147ae147ae147ae', scale=1e10)
    b('deposit whose scaled value reaches i64::MIN: panic after the event', scale=1e12, usd=CUT - 1)
    return rows


def evaluate(img, n_body=512, n_router=384, n_wrapper=64):
    counts = {}
    bad = []

    def note(kind, got, ok, want, label):
        key = (kind, str(got.get('panic', got.get('code', got.get('out')))), label)
        counts[key] = counts.get(key, 0) + 1
        if not ok:
            bad.append((kind, got, want))

    for c in body_cases(img, n_body):
        got, want = run_body(img, c), model_body(img, c)
        note('body', got, got == want, want, f"steps={len(got.get('log', []))}")
    for c in router_cases(n_router):
        got, want = run_router(img, c), model_router(c)
        note('router', got, same_router(got, want), want, f"calls={len(got.get('log', []))}")
    for c in wrapper_cases(n_wrapper):
        got, want = norm_wrapper(run_router(img, c)), model_router(c)
        got = dict(got, log=[('body', c['user'].hex(), ACTION) if x[0] == 'body' else x for x in got.get('log', [])])
        note('wrapper', got, same_router(got, want), want, f"tag={got.get('tag')}")
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
    write_tsv(out / 'outcomes.tsv', ('family', 'result', 'class', 'vectors'), [(k[0], k[1], k[2], v) for k, v in sorted(counts.items())])
    write_tsv(out / 'cases.tsv', ('family', 'scenario', 'code_or_panic', 'accounts', 'calls', 'model'), named)
    evidence = {'binary': BINARY, 'sha256': SHA256, 'pins': len(pins), 'layout_rows': len(layout), 'functions': len(funcs),
                'function_bytes': sum(int(r[2]) for r in funcs), 'stubs': len(stubs), 'caller_sites': len(callers), 'locations': len(locs),
                'named_cases': len(named), 'vectors': {'body': 512, 'router': 384, 'wrapper': 64}, 'vector_disagreements': 0,
                'distinct_outcomes': len(counts), 'special_vaults': {'chain_2': special_address(img, 2).hex(), 'chain_3': special_address(img, 3).hex()}}
    (out / 'evidence.json').write_text(json.dumps(evidence, indent=1, sort_keys=True) + '\n', encoding='ascii')


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--out', required=True)
    generate(ap.parse_args().out)


if __name__ == '__main__':
    main()
