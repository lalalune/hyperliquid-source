#!/usr/bin/env python3
"""vaults: node #94 leader and parent actions: vaultModify, vaultDistribute and NetChildVaultPositions.

vaultModify is 0x22c5fd0 -> 0x26f6a80.  vaultDistribute is 0x1e60020 -> 0x26f6110; the distribution
body is a stub here.  NetChildVaultPositions is 0x27e8cb0 -> 0x26f6c30 -> 0x3707c20 -> 0x3c188f0.
This tool reads ELF bytes only.  It decodes pinned instructions with a small fail-closed x86-64
subset decoder and evaluates the listed function bodies in Python, with their other calls replaced
by named stubs.  Each result is compared with a plain formula over deterministic vectors.  Nothing
from the binary runs.

    python3 tools/vault_parent_actions.py --out <dir>

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
    ('modify', 0x22c5fdb, 'mov raxd,[rsi+0x12]:32', 'copy the 20-byte address tail from action +0x12'),
    ('modify', 0x22c5feb, 'movzx raxd,[rsi]:16', 'copy the two flag bytes'),
    ('modify', 0x22c6003, 'call 0x26f6a80', 'wrapper calls the body'),
    ('modify', 0x22c6008, 'mov raxb,0xd', 'tag 13 by default'),
    ('modify', 0x22c600a, 'cmp [rsp+0x20]:16,0x186', 'body code 390 keeps tag 13'),
    ('modify', 0x22c6049, 'mov raxb,0xe', 'other codes give tag 14'),
    ('modify', 0x26f6aa8, 'test rax,rax', 'empty vault map'),
    ('modify', 0x26f6b28, 'inc rbx', 'key index rises while memcmp says greater'),
    ('modify', 0x26f6b53, 'jb 0x26f6bf8', 'height exhausted: vault missing'),
    ('modify', 0x26f6b6b, 'movdqu xmm0,[r13+0x14]:128', 'found: r13 = value + 0x84, start of vault_user'),
    ('modify', 0x26f6b76, 'movdqu xmm1,[rax]:128', 'leader compare reads the caller'),
    ('modify', 0x26f6b95, 'mov rsiw,0x11', 'code 17 prepared'),
    ('modify', 0x26f6ba4, 'jne 0x26f6c12', 'caller is not the leader'),
    ('modify', 0x26f6bab, 'movdqu xmm0,[rdi+0x2]:128', 'action address'),
    ('modify', 0x26f6bb0, 'movdqu xmm1,[r13]:128', 'stored vault_user'),
    ('modify', 0x26f6bd1, 'mov rsiw,0x186', 'code 390 is prepared before the vault_user compare'),
    ('modify', 0x26f6bdb, 'jne 0x26f6c12', 'vault_user mismatch: success with no store'),
    ('modify', 0x26f6be4, 'cmp rdxb,0x2', 'allow_deposits value 2 keeps the byte'),
    ('modify', 0x26f6be9, 'mov [r13+0x29]:8,rdxb', 'store allow_deposits at vault +0xad'),
    ('modify', 0x26f6bed, 'cmp rcxb,0x2', 'always_close value 2 keeps the byte'),
    ('modify', 0x26f6bf2, 'mov [r13+0x2a]:8,rcxb', 'store always_close_on_withdraw at vault +0xae'),
    ('modify', 0x26f6c0e, 'mov rsiw,0x7', 'vault missing: code 7, address echoed at +0x02'),
    ('distribute', 0x1e6003d, 'mov rax,0xccccccccccccccc', 'cut 0x0ccccccccccccccc'),
    ('distribute', 0x1e60047, 'cmp r8,rax', 'usd compared with the cut'),
    ('distribute', 0x1e60077, 'mov [rbx+0x8]:16,0x13f', 'at or above the cut: code 319'),
    ('distribute', 0x1e6005a, 'call 0x26f6110', 'wrapper calls the host'),
    ('distribute', 0x1e6005f, 'cmp [rsp+0x20]:16,0x186', 'host code 390 gives tag 13'),
    ('distribute', 0x1e600b9, 'mov [rbx]:8,0xe', 'any other code gives tag 14'),
    ('distribute', 0x26f61f2, 'cmp [r13+0x14]:8,0x0', 'is_closed at vault +0xac: r13 = value + 0x98'),
    ('distribute', 0x26f61fe, 'mov [rax]:16,0x8', 'closed: code 8'),
    ('distribute', 0x26f6221, 'mov [rcx]:16,0x7', 'vault missing: code 7'),
    ('distribute', 0x26f6261, 'mov [rax]:16,0x11', 'caller is not the leader: code 17'),
    ('distribute', 0x26f6278, 'cmp [rsp+0x20]:64,0x0', 'usd compared with zero'),
    ('distribute', 0x26f62da, 'call [0x5774660]:64', 'available balance of the vault address'),
    ('distribute', 0x26f62e0, 'mov rbpd,0x1', 'usd != 0 passes flag 1 to the body'),
    ('distribute', 0x26f62e5, 'cmp [rsp+0x20]:64,rax', 'usd compared with available'),
    ('distribute', 0x26f62ef, 'mov [rax]:16,0x12', 'usd above available: code 18'),
    ('distribute', 0x26f62f9, 'xor rbpd,rbpd', 'usd == 0 passes flag 0 and skips the balance test'),
    ('distribute', 0x26f6310, 'add r13,0xffffffffffffff68', 'r13 back to the Vault base'),
    ('distribute', 0x26f6373, 'call [0x57748b8]:64', 'distribution body through its slot'),
    ('distribute', 0x26f6383, 'jne 0x26f6883', 'other body codes are copied out'),
    ('apply', 0x26f64e8, 'mov rbx,[rax+rcx*8+0x8]:64', 'value of the address -> i64 change map'),
    ('apply', 0x26f6536, 'cvtsi2sd xmm0,rbx', 'change as i64 to f64'),
    ('apply', 0x26f653b, 'mulsd xmm0,[r14+0x2a0]:64', 'multiply by clearinghouse 0 +0x2a0'),
    ('apply', 0x26f6567, 'jg 0x26f658d', 'non-finite product leaves 0.0'),
    ('apply', 0x26f6597, 'cvttsd2si r12,xmm1', 'truncating cast, not a rounding step'),
    ('apply', 0x26f65dd, 'je 0x26f695e', 'i64::MIN goes to the abs panic'),
    ('apply', 0x26f65b1, 'mov rcx,0x147ae147ae147ae', 'clamp 0x147ae147ae147ae'),
    ('apply', 0x26f65f8, 'mov rax,0xfeb851eb851eb852', 'lower clamp'),
    ('apply', 0x26f665b, 'je 0x26f66f0', 'address equal to the vault takes the two-sum arm'),
    ('apply', 0x26f6688, 'call 0x1f849b0', 'user account entry'),
    ('apply', 0x26f66a6, 'shr rax,0x3f', 'reciprocal sequence for signed / 10000'),
    ('apply', 0x26f66b1, 'mov r14,[r13+0x18]:64', 'other addresses change only +0x18'),
    ('apply', 0x26f66bb, 'jno 0x26f6764', 'i64 add without overflow'),
    ('apply', 0x26f66ca, 'call [0x5773190]:64', 'overflow recorder, then saturate'),
    ('apply', 0x26f6740, 'mov r14,[r13+0x10]:64', 'vault address changes +0x10 too'),
    ('apply', 0x26f6750, 'mov [r13+0x10]:64,rbx', 'store +0x10'),
    ('apply', 0x26f676d, 'call [0x576dfd8]:64', 'allocate a one-address Vec for the event'),
    ('apply', 0x26f67c7, 'cmp [r15]:32,0x1', 'exchange +0 selects the hash'),
    ('apply', 0x26f6431, 'neg rax', 'abs of the clamped amount, not of the raw change'),
    ('apply', 0x26f6440, 'divsd xmm0,[0x20ae60]:64', 'event amount / 1e6'),
    ('apply', 0x26f6476, 'add rax,0x6', 'event tag 0x8000000000000006'),
    ('apply', 0x26f64a1, 'call [0x5774738]:64', 'event push'),
    ('apply', 0x26f690b, 'mov [rax]:16,0x186', 'all changes done: code 390'),
    ('nethost', 0x27e8cda, 'cmp r12,0x2711', 'asset length limit 10001'),
    ('nethost', 0x27e8ce7, 'mov [rbx+0x8]:16,0x143', 'too many assets: code 323, payload points at action +0x18'),
    ('nethost', 0x27e8ea7, 'mov rsid,[rcx+rdx*4+0x8]:32', 'next u32 asset from the BTreeSet'),
    ('nethost', 0x27e8ec0, 'call [0x5773950]:64', 'classifier through its slot'),
    ('nethost', 0x27e8ed0, 'jne 0x27e8fad', 'classifier failure is copied out'),
    ('nethost', 0x27e8ed6, 'cmp [rsp+0x30]:32,0x1', 'kind 1 is spot'),
    ('nethost', 0x27e900e, 'mov [rbx+0x8]:16,0x15e', 'spot: code 350'),
    ('nethost', 0x27e8f02, 'cmp rbx,[rax+0x5c8]:64', 'dex index against the clearinghouse count'),
    ('nethost', 0x27e8f09, 'jae 0x27e9163', 'past the count: unwrap panic with code 321, not a stored code'),
    ('nethost', 0x27e8f27, 'imul3 rax,rbx,0x2f0', 'clearinghouse stride 0x2f0'),
    ('nethost', 0x27e8f2e, 'cmp [r15+rax*1+0x230]:8,0x3', 'byte +0x230 must be 3'),
    ('nethost', 0x27e901a, 'mov [rbx+0x8]:16,0x61', 'not ready: code 97 with the asset'),
    ('nethost', 0x27e8f47, 'call 0x284cc30', 'insert the u64 asset'),
    ('nethost', 0x27e8f90, 'cmp r12,0x2711', 'child length limit 10001, tested after the assets'),
    ('nethost', 0x27e8fa1, 'mov [rbx+0x8]:16,0x143', 'too many children: code 323, payload points at the action'),
    ('nethost', 0x27e90e9, 'call 0x26f6c30', 'call the core'),
    ('nethost', 0x27e90f5, 'jne 0x27e9103', 'other core codes are copied out'),
    ('netcore', 0x26f6c62, 'je 0x26f6e5d', 'empty vault map'),
    ('netcore', 0x26f6d2b, 'mov raxw,0x18', 'code 24 prepared'),
    ('netcore', 0x26f6d2f, 'cmp [rbp-0x10]:32,0x2', 'relationship tag'),
    ('netcore', 0x26f6d33, 'jb 0x26f6ecc', 'below 2: code 24'),
    ('netcore', 0x26f6d53, 'je 0x26f6e78', 'empty child list skips the set walk'),
    ('netcore', 0x26f6d65, 'je 0x26f6ec8', 'empty stored set: code 27'),
    ('netcore', 0x26f6e29, 'sub rbp,0x1', 'key greater than the node: descend or stop'),
    ('netcore', 0x26f6ec8, 'mov raxw,0x1b', 'child outside the set: code 27'),
    ('netcore', 0x26f6e72, 'mov raxw,0x7', 'vault missing: code 7'),
    ('netcore', 0x26f6ea2, 'jne 0x26f6f14', 'exchange +0 selects the hash'),
    ('netcore', 0x26f6f27, 'cmp [r14+0x5c8]:64,0x0', 'clearinghouse count zero panics'),
    ('netcore', 0x26f6f35, 'mov r13,[r14+0x5c0]:64', 'clearinghouse 0 only'),
    ('netcore', 0x26f6f55, 'movzx rdxd,[r14+0x8f2]:8', 'chain byte argument'),
    ('netcore', 0x26f6f9f, 'call [0x57748c0]:64', 'scan through its slot'),
    ('netcore', 0x26f7043, 'je 0x26f70ce', 'no next asset entry ends the loop'),
    ('netcore', 0x26f7089, 'mov rdi,[r13+0x68]:64', 'oracle rows of clearinghouse 0'),
    ('netcore', 0x26f70a0, 'push 0x50005', 'stack flag 0x50005'),
    ('netcore', 0x26f70a5, 'call 0x26f4cd0', 'fill rows for one asset'),
    ('netcore', 0x26f717a, 'call 0x24fb610', 'post step over the rows'),
    ('netcore', 0x26f7184, 'mov [rbx]:16,0x186', 'success code 390'),
    ('scan', 0x3707c3b, 'cmp r8,0x1', 'length compared with 1'),
    ('scan', 0x3707c3f, 'ja 0x3707ca7', 'more than one child runs the scan'),
    ('scan', 0x3707c41, 'mov [rbp]:64,0x0', 'one or zero children: empty map, success'),
    ('scan', 0x3707d3c, 'cvtsi2sd xmm0,r14', 'n as i64 to f64'),
    ('scan', 0x3707dad, 'movsd xmm1,[0x20a730]:64', 'constant 1.0'),
    ('scan', 0x3707db5, 'divsd xmm1,xmm0', 'weight = 1.0 / n'),
    ('scan', 0x3707e88, 'cmp [r13+0x110]:64,0x0', 'empty user table reads as size 0'),
    ('scan', 0x3707e40, 'mov rbx,[rax+rdi*1-0x30]:64', 'position +0x10 size'),
    ('scan', 0x3707e48, 'add rbp,rbx', 'i64 sum over every child, first included'),
    ('scan', 0x3707e4b, 'jo 0x37081de', 'overflow recorder, then saturate'),
    ('scan', 0x3708278, 'mulsd xmm0,[rsp+0x70]:64', 'sum * weight, not sum / n'),
    ('scan', 0x37082e8, 'cvttsd2si rax,xmm1', 'truncating cast'),
    ('scan', 0x3708310, 'mov [rsp+0x50]:64,rcx', 'target size'),
    ('scan', 0x3708339, 'sub rdi,rax', 'asset % 10000'),
    ('scan', 0x370833f, 'jae 0x3708a6a', 'oracle row bound'),
    ('scan', 0x3708351, 'mov rax,[rax+rcx*1+0x20]:64', 'oracle row +0x20'),
    ('scan', 0x37083be, 'test r15,r15', 'first child never moves on its own'),
    ('scan', 0x37083c1, 'je 0x3708390', 'index 0 is skipped'),
    ('scan', 0x37083c8, 'cmp [rsp+0x1c]:8,0x2', 'chain byte 2 enables the perp_meta test'),
    ('scan', 0x37083e7, 'jne 0x3708a5b', 'dex test, perp_meta.rs:194'),
    ('scan', 0x3708410, 'cmp [rcx+rax*1+0x28]:8,0x2', 'perp_meta row +0x28'),
    ('scan', 0x3708415, 'je 0x3708390', 'byte 2 skips this child'),
    ('scan', 0x37085e8, 'sub rbp,[rsp+0x50]:64', 'size minus target'),
    ('scan', 0x37085ed, 'jno 0x3708605', 'no overflow'),
    ('scan', 0x3708610, 'je 0x3708390', 'zero change skips the child'),
    ('scan', 0x3708619, 'cmp raxd,0x1', 'side from the sign'),
    ('scan', 0x370868a, 'call 0x3c188f0', 'closure builds the candidate'),
    ('scan', 0x3708695, 'cmovs r12,rbp', 'absolute size'),
    ('scan', 0x370869e, 'mul r12', 'price * size'),
    ('scan', 0x37086b0, 'cmp rax,rdx', 'limit i64::MAX'),
    ('scan', 0x37086b8, 'je 0x3708390', 'overflow or at the limit skips the child, ids already spent'),
    ('scan', 0x37086f8, 'je 0x3708390', 'tag 2 skip; the closure in this path always writes 1'),
    ('scan', 0x370878c, 'call [0x5774558]:64', 'margin test of both sides'),
    ('scan', 0x3708797, 'test raxd,0x101', 'both low bits must be set'),
    ('scan', 0x370879c, 'jne 0x3708390', 'refusal skips the child'),
    ('scan', 0x37087ed, 'call [0x5774868]:64', 'apply the fill now, inside the scan'),
    ('scan', 0x37088d3, 'call 0x33bd860', 'map entry for the asset'),
    ('scan', 0x370837b, 'call [0x576dfe0]:64', 'push 0x238 bytes on the asset Vec'),
    ('closure', 0x3c1890c, 'mov rax,[rsi+rax*8+0x8]:64', 'side 0: first address is the child; side 1: the first child'),
    ('closure', 0x3c1894a, 'call 0x36f57f0', 'user table entry'),
    ('closure', 0x3c189c6, 'mov rbp,[rcx+rdi*1-0x30]:64', 'first side position size'),
    ('closure', 0x3c189ee, 'mov [r12+0x38]:64,rax', 'id counter +1, saturating'),
    ('closure', 0x3c189fa, 'sete raxb', 'second side is the other address'),
    ('closure', 0x3c18ac2, 'mov [r12+0x38]:64,rdx', 'id counter +1 again'),
    ('closure', 0x3c18ac7, 'mov [rbx]:64,0x1', 'tag 1 in the first slot'),
    ('closure', 0x3c18aea, 'mov [rbx+0x58]:64,0x2', 'field +0x58 = 2'),
    ('closure', 0x3c18b05, 'mov [rbx+0x100]:64,0x1', 'second side tag'),
]


LAYOUT_ROWS = [
    ('modify_action', 0x00, 1, 0x26f6bdd, '[rdi]:8', 'allow_deposits tri-state; 2 keeps the stored byte'),
    ('modify_action', 0x01, 1, 0x26f6be0, '[rdi+0x1]:8', 'always_close_on_withdraw tri-state; 2 keeps the stored byte'),
    ('modify_action', 0x02, 20, 0x26f6bab, '[rdi+0x2]:128', 'vault address'),
    ('distribute_action', 0x00, 8, 0x1e6003a, '[rsi]:64', 'usd'),
    ('distribute_action', 0x08, 20, 0x1e60032, '[rsi+0x8]:128', 'vault address'),
    ('net_action', 0x08, 8, 0x27e904b, '[rax+0x8]:64', 'child address Vec pointer'),
    ('net_action', 0x10, 8, 0x27e8f8c, '[rax+0x10]:64', 'child address Vec length, 20-byte items'),
    ('net_action', 0x18, 8, 0x27e8d02, '[rsi+0x18]:64', 'asset BTreeSet root'),
    ('net_action', 0x20, 8, 0x27e8d0e, '[rsi+0x20]:64', 'asset BTreeSet height'),
    ('net_action', 0x28, 8, 0x27e8cd6, '[rsi+0x28]:64', 'asset BTreeSet length'),
    ('asset_set_node', 0x08, 4, 0x27e8ea7, '[rcx+rdx*4+0x8]:32', 'u32 keys'),
    ('asset_set_node', 0x34, 2, 0x27e8e20, '[rbp+0x34]:16', 'parent index'),
    ('asset_set_node', 0x36, 2, 0x27e8d68, '[rbp+0x36]:16', 'length'),
    ('asset_set_node', 0x38, 8, 0x27e8dc0, '[rbp+0x38]:64', 'first edge'),
    ('vault_map_node', 0x798, 20, 0x26f6ac4, '[rax+0x798]:64', 'keys, 20 bytes each, after 11 values of 0xb0 bytes'),
    ('vault_map_node', 0x876, 2, 0x26f6acb, '[rax+0x876]:16', 'length'),
    ('vault_map_node', 0x878, 8, 0x26f6b5e, '[rax+rbx*8+0x878]:64', 'edges'),
    ('child_set_node', 0x08, 20, 0x26f6dbf, '[rax+0x8]:64', 'address keys'),
    ('child_set_node', 0xe6, 2, 0x26f6dc8, '[rax+0xe6]:16', 'length'),
    ('child_set_node', 0xe8, 8, 0x26f6e50, '[rax+r12*8+0xe8]:64', 'edges'),
    ('exchange', 0x00, 4, 0x26f67c7, '[r15]:32', 'equal to 1 selects a real hash from 0x3987cb0, otherwise 32 zero bytes'),
    ('exchange', 0x38, 8, 0x3c189d6, '[r12+0x38]:64', 'id counter; the closure takes two ids per candidate'),
    ('exchange', 0x60, 12, 0x3707cbe, '[rcx+0x60]:64', 'time copied into each record'),
    ('exchange', 0x5c0, 8, 0x26f6295, '[r15+0x5c0]:64', 'clearinghouses.rs array pointer, stride 0x2f0'),
    ('exchange', 0x5c8, 8, 0x26f6280 + 4, '[r15+0x5c8]:64', 'clearinghouse count; zero panics with code 321 in the Err payload'),
    ('exchange', 0x740, 16, 0x26f63e3, '[r15+0x740]', 'user account map argument of 0x1f849b0'),
    ('exchange', 0x8d0, 8, 0x26f6aa1, '[rsi+0x8d0]:64', 'vault map root'),
    ('exchange', 0x8d8, 8, 0x26f6ab1, '[rsi+0x8d8]:64', 'vault map height'),
    ('exchange', 0x8f2, 1, 0x26f6f55, '[r14+0x8f2]:8', 'chain byte passed to the scan'),
    ('clearinghouse', 0x08, 8, 0x3708404, '[r13+0x8]:64', 'perp_meta rows, stride 0x30'),
    ('clearinghouse', 0x10, 8, 0x37083fa, '[r13+0x10]:64', 'perp_meta row count'),
    ('clearinghouse', 0x30, 8, 0x37083e3, '[r13+0x30]:64', 'dex index of this clearinghouse'),
    ('clearinghouse', 0x68, 8, 0x3708345, '[r13+0x68]:64', 'oracle rows, stride 0x60'),
    ('clearinghouse', 0x70, 8, 0x370831a, '[r13+0x70]:64', 'oracle row count'),
    ('clearinghouse', 0xf8, 8, 0x3708010, '[r13+0xf8]:64', 'user table control bytes, bucket 0x78'),
    ('clearinghouse', 0x100, 8, 0x3708017, '[r13+0x100]:64', 'user table mask'),
    ('clearinghouse', 0x110, 8, 0x3707e88, '[r13+0x110]:64', 'user table item count'),
    ('clearinghouse', 0x118, 16, 0x3707ea1, '[r13+0x118]:128', 'user table SipHash keys'),
    ('clearinghouse', 0x2a0, 8, 0x26f653b, '[r14+0x2a0]:64', 'f64 scale on distribution amounts'),
    ('user_bucket', 0x20, 8, 0x3708139, '[rbp+0x8]:64', 'position map root; rbp = bucket + 0x18'),
    ('user_bucket', 0x28, 8, 0x3708146, '[rbp+0x10]:64', 'position map height'),
    ('position_node', 0x2c8, 8, 0x3708175, '[rax+rdx*8+0x2d0]:64', 'u64 asset keys; rdx starts at -1'),
    ('position_node', 0x322, 2, 0x370814a, '[rax+0x322]:16', 'length'),
    ('position_node', 0x328, 8, 0x37081b9, '[rax+rdx*8+0x328]:64', 'edges'),
    ('position_value', 0x10, 8, 0x3707e40, '[rax+rdi*1-0x30]:64', 'signed size; values are 0x40 bytes and rdi is (index+1)*0x40'),
    ('account', 0x10, 8, 0x26f6740, '[r13+0x10]:64', 'i64 sum, changed only for the vault address'),
    ('account', 0x18, 8, 0x26f66b1, '[r13+0x18]:64', 'i64 sum, changed for every address'),
    ('fill', 0x08, 8, 0x3c18ace, '[rbx+0x8]:64', 'first side position size'),
    ('fill', 0xd0, 8, 0x3c18af7, '[rbx+0xd0]:64', 'first side id'),
    ('fill', 0xd8, 20, 0x3c1892b, '[rdi+0xd8]', 'first side address'),
    ('fill', 0x108, 8, 0x3c18b10, '[rbx+0x108]:64', 'second side position size'),
    ('fill', 0x1d0, 8, 0x3c18b43, '[rbx+0x1d0]:64', 'second side id'),
    ('fill', 0x1d8, 20, 0x3c18a1c, '[rbx+0x1d8]', 'second side address'),
    ('fill', 0x200, 8, 0x3708726, '[rsp+0x778]:64', 'oracle price'),
    ('fill', 0x208, 8, 0x370872e, '[rsp+0x780]:64', 'asset'),
    ('fill', 0x210, 8, 0x3708736, '[rsp+0x788]:64', 'absolute size change'),
    ('fill', 0x218, 8, 0x3708743, '[rsp+0x790]:64', 'price * size'),
    ('fill', 0x220, 8, 0x370874b, '[rsp+0x798]:64', 'stored as zero'),
    ('fill', 0x228, 12, 0x3708764, '[rcx+0x220]:64', 'time; rcx = record + 8'),
    ('fill', 0x234, 1, 0x370877a, '[rsp+0x7ac]:8', 'side byte: 1 when the child is above the target'),
]

LOCATIONS = [(0x5714d60, 'i64 sum of child sizes'), (0x56ee598, 'size minus target'), (0x56f1cb0, 'oracle row index'),
             (0x56f21c0, 'perp_meta dex check on chain byte 2'), (0x5715ef8, 'account sum add'),
             (0x5714da0, 'abs of i64::MIN'), (0x56e9af8, 'clearinghouse unwrap'), (0x56e9ae0, 'clearinghouse unwrap, net host'),
             (0x56c5540, 'B-tree next_unchecked'), (0x56c37f0, 'B-tree first leaf')]

FUNCS = [(0x22c5fd0, 'vaultModify wrapper, dispatch index 42'), (0x26f6a80, 'vaultModify body'),
         (0x1e60020, 'vaultDistribute wrapper, dispatch index 41'), (0x26f6110, 'vaultDistribute host'),
         (0x27e8cb0, 'NetChildVaultPositions wrapper, dispatch index 13'), (0x26f6c30, 'NetChildVaultPositions core'),
         (0x3707c20, 'equal-size scan'), (0x3c188f0, 'fill candidate closure')]

STUBS = [(0x576e488, 'memcmp'), (0x576dfd8, 'allocate'), (0x576dfe0, 'memcpy'), (0x576e010, 'free'),
         (0x5773190, 'overflow recorder'), (0x3379490, 'drop of a code value'), (0x3987cb0, '32-byte hash'),
         (0x5774660, 'available balance'), (0x57748b8, 'distribution body, address held by an open PR'),
         (0x5774738, 'event push'), (0x2869350, 'iterator next over address -> i64'), (0x2869ad0, 'iterator next over asset -> Vec'),
         (0x1f849b0, 'user account entry'), (0x5773950, 'wire asset classifier, address held by an open PR'),
         (0x284cc30, 'BTreeSet<u64> insert'), (0x28aa700, 'BTreeSet<u64> drop'), (0x33b9210, 'BTreeSet<u64> next'),
         (0x3a00700, 'SipHash absorb'), (0x399c7a0, 'hash of a 20-byte address'), (0x36f57f0, 'user table entry'),
         (0x33bd860, 'BTreeMap entry or insert'), (0x5774558, 'margin test of both sides'), (0x5774868, 'fill apply'),
         (0x26f4cd0, 'fill row writer per asset'), (0x24fb610, 'row list post step')]

CUT = 0x0ccccccccccccccc
OK = 0x186
I64MAX, I64MIN = (1 << 63) - 1, -(1 << 63)
CLAMP = 0x147ae147ae147ae
SENT = 0x10
SP = 0x7f00000
HEAP = 0x8000000
ZERO = 0x7d00000


class Image:
    def __init__(self, data):
        self.data = data
        self.secs = sections(data)
        self.mapped = sorted(((s['address'], s['size'], s['offset'], s['name']) for s in self.secs
                              if s['type'] != 8 and s['address']), key=lambda s: s[0])
        self.starts = [s[0] for s in self.mapped]
        self.cache = {}
        self._rel = None
        self._hash = None

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


def sat_cast(x):
    """f64 -> i64 sequence: non-finite input becomes 0, then clamp and truncate."""
    if x != x or abs(x) == math.inf:
        return 0
    y = min(max(x, -2.0 ** 63), 2.0 ** 63)
    if y > 9223372036854774784.0:
        return I64MAX
    return int(y)


def i64(v):
    return sx(v & M64, 64)


def sat(v):
    return max(I64MIN, min(I64MAX, v))


def addr(n):
    """Twenty distinct bytes for one fixture address."""
    return bytes((n * 37 + 11 + i * 5) & 255 for i in range(20))


class World:
    """One fixture: a Machine, its bump heap and the named stubs."""

    def __init__(self, img):
        self.img = img
        self.m = Machine(img.rd, img.rd, self.hook)
        self.m.cache = img.cache
        self.m.r[4] = SP
        self.heap = HEAP
        self.recorded = []
        self.events = []
        self.accounts = {}
        self.asset_queue = None
        self.fills = []
        self.row_calls = []
        self.post_calls = 0
        self.free_calls = 0
        self.set_values = set()
        self.set_next = None
        self.map = {}
        self.drain = None
        self.pairs = []
        self.margin = [0x101]
        self.margin_i = 0
        self.positions = {}
        self.buckets = {}
        self.balance = 0
        self.body = (OK, 0)
        self.body_args = None
        self.classify = {}
        self.balance_args = None
        self.stubs = {0x576e488: self.memcmp, 0x576dfd8: self.malloc, 0x576dfe0: self.memcpy, 0x576e010: self.free,
                      0x5773190: self.recorder, 0x3379490: lambda *a: 0, 0x3987cb0: self.hash32, 0x5774660: self.avail,
                      0x57748b8: self.distribution, 0x5774738: self.event, 0x2869350: self.next_pair, 0x2869ad0: self.next_asset,
                      0x1f849b0: self.account, 0x5773950: self.classifier, 0x284cc30: self.set_insert, 0x28aa700: lambda *a: 0,
                      0x33b9210: self.set_iter, 0x3a00700: lambda *a: 0, 0x399c7a0: lambda m, *a: table_hash(self.img),
                      0x36f57f0: self.user_entry, 0x33bd860: self.map_entry, 0x5774558: self.margin_test, 0x5774868: self.apply,
                      0x26f4cd0: self.rows, 0x24fb610: self.post, 0x576e048: self.panic_unwrap, 0x576eb38: self.panic_rdi,
                      0x576e470: self.panic_rdi, 0x576dfc8: self.panic_bounds}
        for slot in (0x576e488, 0x576e010):
            q(self.m, slot, slot)
        self.m.store(0x5786300, bytes(8))
        self.m.store(0x57862a0, bytes(0x60))

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

    def memcmp(self, m, a, b, n, *_):
        x, y = m.load(a, n), m.load(b, n)
        return (x > y) - (x < y)

    def malloc(self, m, n, *_):
        return self.alloc(n)

    def memcpy(self, m, a, b, n, *_):
        m.store(a, m.load(b, n))
        return a

    def free(self, m, *_):
        self.free_calls += 1

    def recorder(self, m, a, b, *_):
        self.recorded.append(b)

    def hash32(self, m, out, *_):
        m.store(out, bytes(range(0x90, 0xb0)))

    def avail(self, m, ch, key, *_):
        self.balance_args = (ch, m.load(key, 20))
        return self.balance

    def distribution(self, m, out, vault, flag, usd, ctx, *_):
        self.body_args = (vault, flag & 255, usd, rq(m, ctx), rq(m, ctx + 8), rq(m, ctx + 16))
        code, payload = self.body
        m.store(out, code.to_bytes(2, 'little'))
        q(m, out + 8, payload if code != OK else 1)

    def event(self, m, ptr, users, when, hsh, ev, *_):
        self.events.append((ptr, rq(m, users), rq(m, users + 16), m.load(rq(m, users + 8), 20), m.load(when, 12), m.load(hsh, 32),
                            rq(m, ev), rq(m, ev + 8), m.load(ev + 0x10, 20)))

    def next_pair(self, m, out, *_):
        if not self.pairs:
            q(m, out, 0)
            return
        key, value = self.pairs.pop(0)
        node = self.alloc(0x200)
        q(m, node + 8 + 16, value)
        m.store(node + 0x60 + 2 * 20, key)
        q(m, out, node)
        q(m, out + 0x10, 2)

    def next_asset(self, m, out, *_):
        if self.drain is None:
            self.drain = sorted(self.map.items())
        if not self.drain:
            q(m, out, 0)
            return
        key, vec = self.drain.pop(0)
        node = self.alloc(0x200)
        q(m, node + 0x60, rq(m, vec))
        q(m, node + 0x68, rq(m, vec + 8))
        q(m, node + 0x70, rq(m, vec + 16))
        q(m, out, node)
        q(m, out + 0x10, 0)

    def account(self, m, map_ptr, key, *_):
        k = m.load(key, 20)
        if k not in self.accounts:
            self.accounts[k] = self.alloc(0x40)
        return self.accounts[k]

    def classifier(self, m, out, wire, *_):
        code, kind, value = self.classify[wire & 0xffffffff]
        m.store(out, code.to_bytes(2, 'little'))
        q(m, out + 8, kind)
        q(m, out + 0x10, value)

    def set_insert(self, m, s, value, *_):
        self.set_values.add(value)
        q(m, s, 1)

    def set_iter(self, m, out, *_):
        if self.set_next is None:
            self.set_next = sorted(self.set_values)
        if not self.set_next:
            q(m, out, 0)
            return
        node = self.alloc(0x40)
        q(m, node + 8, self.set_next.pop(0))
        q(m, out, node)
        q(m, out + 0x10, 0)

    def user_entry(self, m, table, key, *_):
        b = self.buckets.get(m.load(key, 20))
        return b + 0x18 if b else ZERO

    def map_entry(self, m, ent, *_):
        if rq(m, ent) == 0:
            node, idx = rq(m, ent + 8), rq(m, ent + 0x18)
            key = rq(m, node + 8 + idx * 8)
        else:
            key = rq(m, ent + 8)
            root = rq(m, ent)
            node = rq(m, root)
            if node == 0:
                node = self.alloc(0x400)
                q(m, root, node)
                q(m, root + 8, 0)
            keys = sorted(self.map) + [key]
            for i, k in enumerate(sorted(keys)):
                q(m, node + 8 + i * 8, k)
            m.store(node + 0x16a, len(keys).to_bytes(2, 'little'))
        if key not in self.map:
            vec = self.alloc(32)
            q(m, vec, 64)
            q(m, vec + 8, self.alloc(0x238 * 64))
            q(m, vec + 16, 0)
            self.map[key] = vec
        return self.map[key]

    def margin_test(self, m, ch, rec, *_):
        v = self.margin[self.margin_i % len(self.margin)]
        self.margin_i += 1
        return v

    def apply(self, m, ch, chain, rec, tail, *_):
        a, b = m.load(rec + 0xd8, 20), m.load(rec + 0x1d8, 20)
        asset, sz = rq(m, rec + 0x208), rq(m, rec + 0x210)
        self.fills.append((a.hex(), b.hex(), rq(m, rec + 0x200), asset, sz, rq(m, rec + 0x218), rq(m, rec + 0x220),
                           m.load(rec + 0x228, 12).hex(), m.load(rec + 0x234, 1)[0], rq(m, rec + 0xd0), rq(m, rec + 0x1d0),
                           i64(rq(m, rec + 8)), i64(rq(m, rec + 0x108)), rq(m, rec), chain & 255, tail))
        for who, sign in ((a, 1), (b, -1)):
            p = self.positions.get((who, asset))
            if p is not None:
                q(m, p, i64(rq(m, p)) + sign * i64(sz))

    def rows(self, m, a, b, c, d, r8, r9):
        sp = m.r[4]
        self.row_calls.append((a, b, d, m.load(r8, 1)[0], m.load(r8 + 1, 32).hex(), r9 & 0xffffffff, rq(m, sp), rq(m, sp + 8)))

    def post(self, m, *_):
        self.post_calls += 1

    def panic_unwrap(self, m, a, b, c, d, loc, *_):
        raise Panic('unwrap', loc)

    def panic_rdi(self, m, loc, *_):
        raise Panic('panic', loc)

    def panic_bounds(self, m, a, b, loc, *_):
        raise Panic('bounds', loc)


def q(m, a, v):
    m.store(a, (v & M64).to_bytes(8, 'little'))


def rq(m, a):
    return int.from_bytes(m.load(a, 8), 'little')


def rf(m, a):
    return i2f(rq(m, a))


REAL = {0x26f6a80: 0x26f6a80, 0x26f6110: 0x26f6110, 0x26f6c30: 0x26f6c30, 0x3c188f0: 0x3c188f0, 0x57748c0: 0x3707c20}
Machine.real_map = REAL


def call(w, fn, *args):
    m = w.m
    m.r[4] -= 8
    q(m, m.r[4], SENT)
    for reg, v in zip((7, 6, 2, 1, 8, 9), args):
        m.r[reg] = v
    m.run(fn, {SENT}, 400000)


def table_hash(img):
    """The hash of any key when the absorb stub keeps state and keys at zero: the real rounds give one constant."""
    if img._hash is None:
        w = World(img)
        m = w.m
        ch = 0x7a00000
        m.r[13], m.r[5], m.r[0] = ch, 0x7a10000, 0
        m.run(0x3707e96, {0x3708009}, 400)
        img._hash = m.r[6]
    return img._hash


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
            if parent_off is not None:
                q(m, e + parent_off, n)
                m.store(e + pidx_off, i.to_bytes(2, 'little'))
        return n
    if len(items) <= 11:
        return node(items), 0
    mid = len(items) // 2
    return node(items[mid:mid + 1], [node(items[:mid]), node(items[mid + 1:])]), 1


def vault_bytes(w, v):
    b = bytearray(0xb0)
    struct.pack_into('<Q', b, 0, v['tag'])
    if v['tag'] >= 2:
        root, height = child_set(w, v['children'])
        struct.pack_into('<QQQ', b, 8, root, height, len(v['children']))
    b[0x84:0x98] = v['user']
    b[0x98:0xac] = v['leader']
    b[0xac], b[0xad], b[0xae] = v['closed'], v['allow'], v['always']
    return bytes(b)


def child_set(w, keys):
    if not keys:
        return 0, 0
    return tree(w, [(k, b'') for k in sorted(set(keys))], 8, 0, 0, 0xe6, 0xe8, 0, 0xe4, 0x180)


def exchange(w, vaults, chain=3, flag=1, chs=2):
    m = w.m
    e = 0x7900000
    ch = 0x7a00000
    if vaults:
        root, height = tree(w, [(k, vault_bytes(w, v)) for k, v in sorted(vaults.items())], 0x798, 0, 0xb0, 0x876, 0x878, None, None, 0x940)
        q(m, e + 0x8d0, root)
        q(m, e + 0x8d8, height)
    m.store(e, flag.to_bytes(4, 'little'))
    q(m, e + 8, 0x1111)
    q(m, e + 0x28, 0x2222)
    q(m, e + 0x60, 0x0807060504030201)
    m.store(e + 0x68, bytes((9, 10, 11, 12)))
    q(m, e + 0x5c0, ch)
    q(m, e + 0x5c8, chs)
    m.store(e + 0x8f2, bytes((chain,)))
    return e, ch


def vault(user, leader, tag=0, closed=0, allow=1, always=0, children=()):
    return {'user': user, 'leader': leader, 'tag': tag, 'closed': closed, 'allow': allow, 'always': always, 'children': list(children)}


# vaultModify: 0x22c5fd0 -> 0x26f6a80

def run_modify(img, vaults, caller, target, allow, always):
    w = World(img)
    m = w.m
    e, _ = exchange(w, vaults)
    action, out, who = 0x7810000, 0x7820000, 0x7830000
    m.store(action, bytes((allow, always)) + target)
    m.store(who, caller)
    call(w, 0x22c5fd0, out, action, who, e)
    tag = m.load(out, 1)[0]
    code = int.from_bytes(m.load(out + 8, 2), 'little') if tag == 14 else OK
    res = {'tag': tag, 'code': code, 'echo': m.load(out + 10, 20).hex() if code == 7 else ''}
    res['flags'] = find_flags(w, e, target)
    return res


def find_flags(w, e, key):
    m = w.m
    node, height = rq(m, e + 0x8d0), rq(m, e + 0x8d8)
    while node:
        n = int.from_bytes(m.load(node + 0x876, 2), 'little')
        keys = [m.load(node + 0x798 + i * 20, 20) for i in range(n)]
        if key in keys:
            i = keys.index(key)
            return m.load(node + i * 0xb0 + 0xad, 2).hex()
        if not height:
            return ''
        i = sum(k < key for k in keys)
        node, height = rq(m, node + 0x878 + i * 8), height - 1
    return ''


def model_modify(vaults, caller, target, allow, always):
    v = vaults.get(target)
    flags = ''
    if v is None:
        return {'tag': 14, 'code': 7, 'echo': target.hex(), 'flags': ''}
    keep = bytes((v['allow'], v['always'])).hex()
    if v['leader'] != caller:
        return {'tag': 14, 'code': 17, 'echo': '', 'flags': keep}
    if v['user'] != target:
        return {'tag': 13, 'code': OK, 'echo': '', 'flags': keep}
    flags = bytes((v['allow'] if allow == 2 else allow, v['always'] if always == 2 else always)).hex()
    return {'tag': 13, 'code': OK, 'echo': '', 'flags': flags}


# vaultDistribute: 0x1e60020 -> 0x26f6110, with the body at the held address as a stub

def run_distribute(img, vaults, caller, target, usd, balance, body, changes, scale, start, flag=1, chs=2):
    w = World(img)
    m = w.m
    e, ch = exchange(w, vaults, flag=flag, chs=chs)
    action, out, who = 0x7810000, 0x7820000, 0x7830000
    q(m, action, usd)
    m.store(action + 8, target)
    m.store(who, caller)
    q(m, ch + 0x2a0, f2i(scale))
    w.balance, w.body, w.pairs = balance, body, list(changes)
    for k, (a, b) in start.items():
        w.accounts[k] = w.alloc(0x40)
        q(m, w.accounts[k] + 0x10, a)
        q(m, w.accounts[k] + 0x18, b)
    res = {}
    try:
        call(w, 0x1e60020, out, action, who, e)
    except Panic as p:
        res = {'panic': p.args[0], 'loc': hex(p.args[1])}
    res['events'] = [(ev[6], f2i_hex(ev[7]), ev[3].hex(), ev[8].hex(), ev[5].hex()) for ev in w.events]
    res['accounts'] = sorted((k.hex(), i64(rq(m, a + 0x10)), i64(rq(m, a + 0x18))) for k, a in w.accounts.items())
    res['recorded'] = list(w.recorded)
    if 'panic' not in res:
        tag = m.load(out, 1)[0]
        res['tag'] = tag
        res['code'] = int.from_bytes(m.load(out + 8, 2), 'little') if tag == 14 else OK
        res['payload'] = rq(m, out + 0x10) if tag == 14 and res['code'] in (0x13f,) else None
        if tag == 14 and res['code'] == 7:
            res['payload'] = m.load(out + 10, 20).hex()
        if tag == 14 and res['code'] not in (0x13f, 7, 8, 17, 18):
            res['payload'] = rq(m, out + 0x10)
    res['body'] = None if w.body_args is None else w.body_args[1:3]
    return res


def f2i_hex(v):
    return f'{v:016x}'


def add_sat(a, b, rec):
    if not I64MIN <= a + b <= I64MAX:
        rec.append(0x5715ef8)
    return sat(a + b)


def model_distribute(vaults, caller, target, usd, balance, body, changes, scale, start, flag=1, chs=2):
    base = {'events': [], 'recorded': [], 'body': None, 'accounts': sorted((k.hex(), a, b) for k, (a, b) in start.items())}
    if usd >= CUT:
        return dict(base, tag=14, code=0x13f, payload=usd)
    v = vaults.get(target)
    if v is None:
        return dict(base, tag=14, code=7, payload=target.hex())
    if v['closed']:
        return dict(base, tag=14, code=8, payload=None)
    if v['leader'] != caller:
        return dict(base, tag=14, code=17, payload=None)
    if chs == 0:
        return dict(base, panic='unwrap', loc=hex(0x56e9af8))
    if usd and usd > balance:
        return dict(base, tag=14, code=18, payload=None)
    base['body'] = (int(usd != 0), usd)
    if body[0] != OK:
        return dict(base, tag=14, code=body[0], payload=body[1])
    acc = dict(start)
    rec = base['recorded']
    hsh = bytes(range(0x90, 0xb0)).hex() if flag == 1 else '00' * 32
    for key, value in changes:
        r = sat_cast(float(i64(value)) * scale)
        if r == I64MIN:
            base['accounts'] = sorted((k.hex(), a, b) for k, (a, b) in acc.items())
            return dict(base, panic='panic', loc=hex(0x5714da0))
        if abs(r) > CLAMP:
            r = max(-CLAMP, min(CLAMP, r))
        step = int(abs(r) // 10000) * (1 if r >= 0 else -1)
        a, b = acc.get(key, (0, 0))
        if key == target:
            a = add_sat(a, step, rec)
        b = add_sat(b, step, rec)
        acc[key] = (a, b)
        base['events'].append((0x8000000000000006, f2i_hex(f2i(abs(r) / 1e6)), key.hex(), target.hex(), hsh))
    base['accounts'] = sorted((k.hex(), a, b) for k, (a, b) in acc.items())
    return dict(base, tag=13, code=OK, payload=None)


# NetChildVaultPositions: 0x27e8cb0 -> 0x26f6c30 -> 0x3707c20 -> 0x3c188f0

def setup_table(w, ch, users, positions):
    m = w.m
    h = table_hash(w.img)
    q(m, ch + 0x110, len(users))
    if not users:
        return
    q(m, ch + 0x100, 15)
    ctrl = w.alloc(0x78 * 16 + 64) + 0x78 * 16
    q(m, ch + 0xf8, ctrl)
    bytes_ = bytearray(b'\xff' * 32)
    start = h & 15
    for i, u in enumerate(users):
        idx = (start + i) & 15
        bytes_[idx] = bytes_[idx + 16] = h >> 57
        bucket = ctrl - 0x78 * (idx + 1)
        m.store(bucket, u)
        rows = sorted((a, s) for (who, a), s in positions.items() if who == u)
        val = []
        for a, s in rows:
            v = bytearray(0x40)
            struct.pack_into('<q', v, 0x10, s)
            val.append((a.to_bytes(8, 'little'), bytes(v)))
        root, height = tree(w, val, 0x2c8, 0, 0x40, 0x322, 0x328, None, None, 0x400) if val else (0, 0)
        q(m, bucket + 0x20, root)
        q(m, bucket + 0x28, height)
        w.buckets[u] = bucket
        for a, s in rows:
            w.positions[(u, a)] = find_position(m, root, height, a)
    m.store(ctrl, bytes(bytes_))


def find_position(m, node, height, asset):
    while True:
        n = int.from_bytes(m.load(node + 0x322, 2), 'little')
        keys = [rq(m, node + 0x2c8 + i * 8) for i in range(n)]
        if asset in keys:
            return node + keys.index(asset) * 0x40 + 0x10
        i = sum(k < asset for k in keys)
        node, height = rq(m, node + 0x328 + i * 8), height - 1


def run_net(img, case):
    w = World(img)
    m = w.m
    e, ch = exchange(w, case['vaults'], chain=case['chain'], flag=case['flag'])
    action, out, who = 0x7810000, 0x7820000, 0x7830000
    m.store(who, case['caller'])
    children = case['children']
    cptr = 0x7840000
    m.store(cptr, b''.join(children))
    q(m, action, len(children))
    q(m, action + 8, cptr)
    q(m, action + 0x10, case.get('child_len', len(children)))
    wires = sorted(case['wires'])
    if wires:
        root, height = tree(w, [(x.to_bytes(4, 'little'), b'') for x in wires], 8, 0, 0, 0x36, 0x38, 0, 0x34, 0x98)
        q(m, action + 0x18, root)
        q(m, action + 0x20, height)
    q(m, action + 0x28, case.get('wire_len', len(wires)))
    w.classify = case['classify']
    q(m, e + 0x38, case['tid'])
    q(m, e + 0x5c8, case['n_ch'])
    for i, b in enumerate(case['ready']):
        m.store(ch + i * 0x2f0 + 0x230, bytes((b,)))
    q(m, ch + 0x30, case['dex'])
    oracle = w.alloc(0x60 * max(1, len(case['oracle'])))
    q(m, ch + 0x68, oracle)
    q(m, ch + 0x70, len(case['oracle']))
    for i, p in enumerate(case['oracle']):
        q(m, oracle + i * 0x60 + 0x20, p)
    perp = w.alloc(0x30 * max(1, len(case['perp'])))
    q(m, ch + 8, perp)
    q(m, ch + 0x10, len(case['perp']))
    for i, b in enumerate(case['perp']):
        m.store(perp + i * 0x30 + 0x28, bytes((b,)))
    setup_table(w, ch, case['users'], case['positions'])
    w.margin = case['margin']
    res = {}
    try:
        call(w, 0x27e8cb0, out, action, who, e)
    except Panic as p:
        res = {'panic': p.args[0], 'loc': hex(p.args[1])}
    res['fills'] = list(w.fills)
    res['recorded'] = list(w.recorded)
    res['tid'] = rq(m, e + 0x38)
    if 'panic' in res:
        return res
    tag = m.load(out, 1)[0]
    res['tag'] = tag
    res['code'] = int.from_bytes(m.load(out + 8, 2), 'little') if tag == 14 else OK
    if tag == 14:
        res['payload'] = {0x143: rq(m, out + 0x10) - action if res['code'] == 0x143 else None, 7: m.load(out + 10, 20).hex(),
                          97: rq(m, out + 0x10), 0x15e: None, 24: None, 27: None}.get(res['code'], rq(m, out + 0x10))
    res['rows'] = [(r[2], r[3], r[4], r[5], r[6]) for r in w.row_calls]
    res['post'] = w.post_calls
    return res


def model_net(case):
    children, wires, caller = case['children'], sorted(case['wires']), case['caller']
    cl = case.get('child_len', len(children))
    wl = case.get('wire_len', len(wires))
    res = {'fills': [], 'recorded': [], 'tid': case['tid']}
    if wl >= 10001:
        return dict(res, tag=14, code=0x143, payload=0x18, rows=[], post=0)
    seen = set()
    for wire in wires:
        code, kind, value = case['classify'][wire]
        if code != OK:
            return dict(res, tag=14, code=code, payload=kind, rows=[], post=0)
        if kind == 1:
            return dict(res, tag=14, code=0x15e, payload=None, rows=[], post=0)
        d = value // 10000
        if d >= case['n_ch']:
            return dict(res, panic='unwrap', loc=hex(0x56e9ae0))
        if case['ready'][d] != 3:
            return dict(res, tag=14, code=97, payload=value, rows=[], post=0)
        seen.add(value)
    if cl >= 10001:
        return dict(res, tag=14, code=0x143, payload=0, rows=[], post=0)
    v = case['vaults'].get(caller)
    if v is None:
        return dict(res, tag=14, code=7, payload=caller.hex(), rows=[], post=0)
    if v['tag'] < 2:
        return dict(res, tag=14, code=24, payload=None, rows=[], post=0)
    for c in children:
        if c not in v['children']:
            return dict(res, tag=14, code=27, payload=None, rows=[], post=0)
    if case['n_ch'] == 0:
        return dict(res, panic='unwrap', loc=hex(0x56e9af8))
    out = scan_model(case, sorted(seen), res)
    if out is not None:
        return out
    hsh = bytes(range(0x90, 0xb0)).hex() if case['flag'] == 1 else '00' * 32
    per = {}
    for f in res['fills']:
        per[f[3]] = per.get(f[3], 0) + 1
    res['rows'] = [(per[a], 1, hsh, 0, 0x50005) for a in sorted(per)]
    return dict(res, tag=13, code=OK, post=1)


def scan_model(case, assets, res):
    children = case['children']
    n = len(children)
    pos = {k: v for k, v in case['positions'].items() if k[0] in case['users']}
    tid = case['tid']
    margin_i = 0
    fills, rec = res['fills'], res['recorded']
    when = '0102030405060708' + '090a0b0c'
    if n <= 1:
        return None
    weight = 1.0 / float(n)
    for asset in assets:
        total = 0
        for c in children:
            s = pos.get((c, asset), 0)
            if not I64MIN <= total + s <= I64MAX:
                rec.append(0x5714d60)
            total = sat(total + s)
        target = sat_cast(float(total) * weight)
        idx = asset % 10000
        if idx >= len(case['oracle']):
            res['tid'] = tid
            return dict(res, panic='bounds', loc=hex(0x56f1cb0))
        px = case['oracle'][idx]
        for i, c in enumerate(children):
            if i == 0:
                continue
            if case['chain'] == 2:
                if asset // 10000 != case['dex'] or idx >= len(case['perp']):
                    res['tid'] = tid
                    return dict(res, panic='panic', loc=hex(0x56f21c0))
                if case['perp'][idx] == 2:
                    continue
            cur = pos.get((c, asset), 0)
            if not I64MIN <= cur - target <= I64MAX:
                rec.append(0x56ee598)
            d = sat(cur - target)
            if d == 0:
                continue
            side = int(d > 0)
            a, b = (children[0], c) if side else (c, children[0])
            pa, pb = pos.get((a, asset), 0), pos.get((b, asset), 0)
            ta, tb = tid, min(tid + 1, M64)
            tid = min(tb + 1, M64)
            sz = abs(d)
            ntl = px * sz
            if ntl >= 1 << 64 or ntl >= I64MAX:
                continue
            mv = case['margin'][margin_i % len(case['margin'])]
            margin_i += 1
            if mv & 0x101 != 0x101:
                continue
            fills.append((a.hex(), b.hex(), px, asset, sz, ntl, 0, when, side, ta, tb, pa, pb, 1, case['chain'], 0x7a005d0 - 0x7a00000 + 0x7900000))
            if (a, asset) in pos:
                pos[(a, asset)] = i64(pos[(a, asset)] + sz)
            if (b, asset) in pos:
                pos[(b, asset)] = i64(pos[(b, asset)] - sz)
    res['tid'] = tid
    return None


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


def modify_cases(n):
    s = Stream('modify')
    for _ in range(n):
        count = s.pick([1, 2, 5, 14])
        keys = [addr(i * 2 + 1) for i in range(count)]
        leader = addr(100)
        vaults = {}
        for k in keys:
            vaults[k] = vault(k if s.u(8) else addr(101), leader if s.u(4) else addr(102), allow=s.u(2), always=s.u(2))
        target = s.pick(keys) if s.u(6) else addr(200)
        caller = leader if s.u(5) else addr(103)
        yield vaults, caller, target, s.u(3), s.u(3)


USD = [0, 1, 9999999, 10000000, 123456789, CUT - 1, CUT, 1 << 63]
DELTA = [1, 9999, 10000, 10001, 123456789, -1, -9999, -123456789, CLAMP, CLAMP + 1, -CLAMP - 1, I64MAX, I64MIN + 1]
SCALE = [1.0, 0.5, 2.0, 1.0000000001, 1e-4, 1e10]


def distribute_cases(n):
    s = Stream('distribute')
    for _ in range(n):
        key, leader, other = addr(1), addr(2), addr(3)
        vaults = {key: vault(key, leader, closed=int(s.u(8) == 0)), addr(7): vault(addr(7), leader)}
        target = key if s.u(10) else addr(9)
        caller = leader if s.u(8) else addr(4)
        usd = s.pick(USD)
        balance = s.pick([0, 1, 10000000, 123456789, CUT])
        body = (OK, 0) if s.u(6) else (s.pick([14, 19, 51, 0x13f]), 0x1234)
        count = s.u(5)
        changes = sorted({addr(10 + s.u(4)) if s.u(3) else key: s.pick(DELTA) & M64 for _ in range(count)}.items())
        scale = s.pick(SCALE)
        start = {}
        for i in range(s.u(3)):
            start[addr(10 + i) if i else key] = (s.pick([0, 5, I64MAX, I64MIN, I64MAX - 2]), s.pick([0, -7, I64MAX, I64MIN, I64MIN + 2]))
        yield vaults, caller, target, usd, balance, body, changes, scale, start, s.u(2)


def net_base(children, positions, assets):
    parent = addr(50)
    vaults = {parent: vault(parent, addr(51), tag=2, children=children)}
    users = sorted({u for (u, _) in positions} | set(children))
    return {'vaults': vaults, 'caller': parent, 'children': children, 'wires': assets, 'chain': 3, 'flag': 1, 'tid': 1000, 'n_ch': 2,
            'ready': [3, 3], 'dex': 0, 'oracle': [50000000, 3000000, 7, 1 << 40], 'perp': [0, 2, 0, 0],
            'users': users, 'positions': positions, 'margin': [0x101],
            'classify': {a: (OK, 0, a) for a in assets}}


SIZES = [0, 1, -1, 2, 3, -3, 100, 101, -100, 7777, -123456, 1 << 40, -(1 << 41)]


def net_cases(n):
    s = Stream('net')
    for _ in range(n):
        count = s.pick([0, 1, 2, 2, 3, 3, 4, 5, 7])
        children = [addr(60 + i) for i in range(count)]
        if count >= 3 and s.u(8) == 0:
            children[s.u(count - 1) + 1] = children[s.u(count - 1)]
        assets = sorted({s.pick([0, 1, 2, 3, 10001]) for _ in range(s.u(4))})
        positions = {}
        for c in sorted(set(children)):
            for a in assets:
                if s.u(5):
                    positions[(c, a)] = s.pick(SIZES)
        case = net_base(children, positions, assets)
        case['flag'] = s.u(2)
        case['chain'] = s.pick([3, 3, 2, 0])
        case['margin'] = s.pick([[0x101], [0x101], [0x101, 1], [0x100, 0x101], [0]])
        case['oracle'] = s.pick([[50000000, 3000000, 7, 1 << 40], [1 << 62, 1 << 61, 3, 4], [1, 1, 1, 1], [50000000]])
        case['tid'] = s.pick([1000, M64 - 2, M64])
        r = s.u(24)
        if r == 0:
            case['caller'] = addr(52)
        elif r == 1:
            case['vaults'][case['caller']]['tag'] = s.u(2)
        elif r == 2 and children:
            case['vaults'][case['caller']]['children'] = children[1:]
        elif r == 3:
            case['ready'] = [2, 2]
        elif r == 4 and assets:
            case['classify'][assets[0]] = (OK, 1, assets[0])
        elif r == 5 and assets:
            case['classify'][assets[0]] = (41, 0x77, 0)
        elif r == 6:
            case['n_ch'] = 1
        elif r == 7:
            case['users'] = case['users'][:1]
        yield case


def named_cases(img):
    """Named scenarios that a reader can follow; each row is the observed result of the real bytes."""
    a, b, c, d = addr(60), addr(61), addr(62), addr(63)
    rows = []

    def net(name, case):
        got, want = run_net(img, case), model_net(case)
        fills = [(f[8], f[3], f[4], f[5], f[9], f[10]) for f in got['fills']]
        rows.append(('net', name, got.get('tag', 'panic'), got.get('code', got.get('loc')), json.dumps(fills), 'same' if got == want else 'DIFF'))

    k = net_base([a, b, c], {(a, 0): 300, (b, 0): 0, (c, 0): 0}, [0])
    net('3 children, first holds all: both others buy 100 from it', k)
    k = net_base([a, b, c], {(a, 0): 0, (b, 0): 301, (c, 0): 0}, [0])
    net('sum 301 of 3: target 100 by truncation, first keeps the odd unit', k)
    k = net_base([a, b, c], {(a, 0): 0, (b, 0): 100, (c, 0): 201}, [0])
    net('first child takes every other side', k)
    k = net_base([a], {(a, 0): 300}, [0])
    net('single child: no fill, still success', k)
    k = net_base([], {}, [0])
    net('no child: no fill, still success', k)
    k = net_base([a, b], {(a, 0): 10, (b, 0): -10}, [0])
    net('opposite positions net to zero', k)
    k = net_base([a, b], {(a, 0): 3, (b, 0): -4}, [0])
    net('negative sum -1 of 2: target trunc(-0.5) = 0', k)
    k = net_base([a, b], {(a, 0): 10, (b, 0): -10}, [0])
    k['margin'] = [0x001]
    net('margin refuses one side: child skipped, ids spent, success', k)
    k = net_base([a, b], {(a, 2): 10, (b, 2): -10}, [2])
    k['oracle'] = [1, 1, 1 << 62, 1]
    net('price * size at or past i64::MAX: child skipped, ids spent', k)
    k = net_base([a, b, c, d], {(a, 0): 1, (b, 0): 2, (c, 0): 3, (d, 0): 4}, [0])
    k['chain'] = 2
    k['perp'] = [2, 2, 2, 2]
    net('chain byte 2 and perp_meta byte 2: every child skipped', k)
    wires = list(range(13))
    k = net_base([a, b], {(u, x): 10 if u == a else 0 for u in (a, b) for x in wires}, wires)
    k['oracle'], k['perp'] = [7] * 13, [0] * 13
    net('13 assets: asset set and position maps at height 1', k)
    k = net_base([a, b], {(a, 0): I64MAX, (b, 0): I64MAX}, [0])
    k['oracle'] = [1]
    net('sizes at i64::MAX: sum saturates, recorder runs', k)
    k = net_base([a, b, c, d], {(a, 0): I64MAX, (b, 0): I64MAX, (c, 0): I64MIN, (d, 0): I64MAX}, [0])
    k['oracle'] = [1]
    net('size minus target overflows: saturates, recorder runs, notional skip', k)
    k = net_base([a, b], {(a, 7): 10, (b, 7): 0}, [7])
    net('asset past the oracle rows: bounds panic', k)
    k = net_base([a, b], {}, [0])
    k['ready'] = [3, 3]
    k['wires'], k['classify'] = [99999], {99999: (OK, 0, 20000)}
    net('dex index past the clearinghouse list: unwrap panic with code 321', k)
    k = net_base([a, b], {}, [])
    k['wire_len'] = 10001
    net('10001 assets: code 323', k)
    k = net_base([a, b], {}, [])
    k['child_len'] = 10001
    net('10001 children: code 323', k)
    k = net_base([a, b], {}, [0])
    k['vaults'][k['caller']]['tag'] = 1
    net('child vault as caller: code 24', k)
    k = net_base([a, b], {}, [0])
    k['vaults'][k['caller']]['children'] = [a]
    net('child outside the stored set: code 27', k)
    return rows


def evaluate(img, n_modify=512, n_distribute=512, n_net=256):
    counts = {}
    bad = []

    def note(kind, got, want, label):
        key = (kind, str(got.get('panic', got.get('code'))), label)
        counts[key] = counts.get(key, 0) + 1
        if got != want:
            bad.append((kind, got, want))

    for v, caller, t, al, ac in modify_cases(n_modify):
        got, want = run_modify(img, v, caller, t, al, ac), model_modify(v, caller, t, al, ac)
        note('modify', got, want, 'stored' if t in v and got.get('flags') != bytes((v[t]['allow'], v[t]['always'])).hex() else 'unchanged')
    for args in distribute_cases(n_distribute):
        got, want = run_distribute(img, *args), model_distribute(*args)
        note('distribute', got, want, f"events={min(len(got['events']), 3)}")
    for case in net_cases(n_net):
        got, want = run_net(img, case), model_net(case)
        note('net', got, want, f"fills={min(len(got['fills']), 3)}")
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


def caller_rows(img, table):
    """Byte census of e8 and ff 15/25 sites that land on a path function."""
    rel = img.relative()
    text = img.section('.text')
    base, off, size = text['address'], text['offset'], text['size']
    body = img.data[off:off + size]
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
    write_tsv(out / 'outcomes.tsv', ('action', 'result', 'class', 'vectors'),
              [(k[0], k[1], k[2], v) for k, v in sorted(counts.items())])
    write_tsv(out / 'cases.tsv', ('action', 'scenario', 'tag', 'code_or_panic', 'fills_side_asset_size_notional_ids', 'model'), named)
    evidence = {'binary': BINARY, 'sha256': SHA256, 'pins': len(pins), 'layout_rows': len(layout), 'functions': len(funcs),
                'stubs': len(stubs), 'caller_sites': len(callers), 'locations': len(locs), 'named_cases': len(named),
                'vectors': {'modify': 512, 'distribute': 512, 'net': 256}, 'vector_disagreements': 0,
                'distinct_outcomes': len(counts), 'table_hash_constant': f'{table_hash(img):#x}',
                'constants': {'one': struct.unpack('<d', img.rd(0x20a730, 8))[0], 'usd_scale': struct.unpack('<d', img.rd(0x20ae60, 8))[0]}}
    (out / 'evidence.json').write_text(json.dumps(evidence, indent=1, sort_keys=True) + '\n', encoding='ascii')


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--out', required=True)
    generate(ap.parse_args().out)


if __name__ == '__main__':
    main()
