#!/usr/bin/env python3
"""Node115 blst 384-bit modular helpers: byte-driven x86-64 subset interpreter vs. integer models.

The target is never run.  Instruction bytes of each function are read from the ELF
.text section, decoded by the small interpreter below and executed on a private
byte-array memory.  Every result is compared with an independent big-integer model.
"""
import argparse
import hashlib
import json
from pathlib import Path
import random
import struct
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
from elf_index import sections
from fde_extents import eh_frame_records

ROOT = Path(__file__).resolve().parents[1]
TARGET = ROOT / 'artifacts/node/115/hl-node'
SHA256 = 'a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301'
M64 = (1 << 64) - 1
BLS_P = int('1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab', 16)
MEM_BASE, MEM_SIZE = 0x10000, 0x1000
STACK_TOP = MEM_BASE + 0xf00
SENTINEL = 0xdead0000
RET_OFF, A_OFF, B_OFF, MOD_OFF = 0x100, 0x300, 0x400, 0x500
STEP_LIMIT = 4000


class Fault(Exception):
    pass


def require(cond, msg):
    if not cond:
        raise ValueError(msg)


def digest(data):
    return hashlib.sha256(data).hexdigest()


class Image:
    def __init__(self, data):
        require(digest(data) == SHA256, 'input is not node #115')
        self.data = bytes(data)
        secs = sections(self.data)
        text = [s for s in secs if s['name'] == '.text' and s['type'] != 8]
        require(len(text) == 1, 'need one .text')
        self.text = text[0]
        _, fdes = eh_frame_records(self.data, secs)
        self.fde = {f['start']: f['end'] for f in fdes}

    def byte(self, va):
        off = va - self.text['address']
        if not 0 <= off < self.text['size']:
            raise Fault('fetch outside .text')
        return self.data[self.text['offset'] + off]

    def window(self, va, n):
        return bytes(self.byte(va + i) for i in range(n))

    def extent(self, va):
        require(va in self.fde, 'address is not an FDE start')
        return va, self.fde[va]


# ---------------------------------------------------------------- interpreter
ALU = ['add', 'or', 'adc', 'sbb', 'and', 'sub', 'xor', 'cmp']
CC = ['o', 'no', 'b', 'ae', 'e', 'ne', 'be', 'a', 's', 'ns', 'p', 'np', 'l', 'ge', 'le', 'g']


def mask(size):
    return (1 << size) - 1


def sx(value, bits, size):
    value &= mask(bits)
    if value >> (bits - 1):
        value -= 1 << bits
    return value & mask(size)


class Cpu:
    def __init__(self, image, patches=None):
        self.image = image
        self.patches = patches or {}
        self.cache = {}
        self.reset()

    def reset(self):
        self.regs = [0] * 16
        self.cf = self.zf = self.sf = self.of = 0
        self.mem = bytearray(MEM_SIZE)
        self.executed = set()
        self.steps = 0
        self.ip = 0

    def fetch(self, va):
        return self.patches.get(va, None) if va in self.patches else self.image.byte(va)

    # -- memory
    def addr(self, ea):
        off = ea - MEM_BASE
        return off

    def load(self, ea, size):
        off = ea - MEM_BASE
        n = size // 8
        if not 0 <= off <= MEM_SIZE - n:
            raise Fault('load outside private memory')
        return int.from_bytes(self.mem[off:off + n], 'little')

    def store(self, ea, size, value):
        off = ea - MEM_BASE
        n = size // 8
        if not 0 <= off <= MEM_SIZE - n:
            raise Fault('store outside private memory')
        self.mem[off:off + n] = (value & mask(size)).to_bytes(n, 'little')

    # -- decode
    def decode(self, va):
        pos = va
        p66 = pf3 = False
        rex = 0
        while True:
            b = self.fetch(pos)
            if b == 0x66:
                p66 = True
            elif b == 0xf3:
                pf3 = True
            elif b in (0x2e, 0x3e):
                pass
            else:
                break
            pos += 1
        if 0x40 <= b <= 0x4f:
            rex = b
            pos += 1
            b = self.fetch(pos)
        pos += 1
        w, rr, rx, rb = (rex >> 3) & 1, (rex >> 2) & 1, (rex >> 1) & 1, rex & 1
        osz = 64 if w else 16 if p66 else 32

        def u8():
            nonlocal pos
            v = self.fetch(pos)
            pos += 1
            return v

        def imm(n):
            nonlocal pos
            v = 0
            for i in range(n):
                v |= self.fetch(pos + i) << (8 * i)
            pos += n
            return v

        def modrm():
            m = u8()
            mod, reg, rm = m >> 6, ((m >> 3) & 7) | (rr << 3), m & 7
            if mod == 3:
                return reg, ('r', rm | (rb << 3)), (m >> 3) & 7
            base, index, scale = None, None, 1
            if rm == 4:
                sib = u8()
                scale = 1 << (sib >> 6)
                idx = ((sib >> 3) & 7) | (rx << 3)
                index = None if idx == 4 else idx
                bs = sib & 7
                if bs == 5 and mod == 0:
                    base = None
                    disp = sx(imm(4), 32, 64)
                else:
                    base = bs | (rb << 3)
                    disp = 0
            else:
                require(not (rm == 5 and mod == 0), 'rip-relative form not supported')
                base, disp = rm | (rb << 3), 0
            if mod == 1:
                disp = sx(imm(1), 8, 64)
            elif mod == 2:
                disp = sx(imm(4), 32, 64)
            return reg, ('m', base, index, scale, disp), (m >> 3) & 7

        def done(name, *ops):
            return (pos - va, name, ops)

        if b == 0x0f:
            c = u8()
            if c == 0x1e:
                require(pf3 and u8() == 0xfa, 'only endbr64')
                return done('nop')
            if c == 0x1f:
                modrm()
                return done('nop')
            if 0x40 <= c <= 0x4f:
                reg, rm, _ = modrm()
                return done('cmov', c & 15, ('r', reg), rm, osz)
            if 0x80 <= c <= 0x8f:
                d = sx(imm(4), 32, 64)
                return done('jcc', c & 15, (pos + d) & M64)
            if c in (0xa4, 0xac):
                reg, rm, _ = modrm()
                return done('shd', c == 0xa4, rm, ('r', reg), ('i', imm(1)), osz)
            if c in (0xa5, 0xad):
                reg, rm, _ = modrm()
                return done('shd', c == 0xa5, rm, ('r', reg), ('r', 1), osz)
            raise Fault('unsupported 0f opcode %02x' % c)
        if b < 0x40 and (b & 7) < 6:
            op, form = b >> 3, b & 7
            size = 8 if form % 2 == 0 else osz
            require(size != 8 or form in (4,), 'byte ALU forms not supported')
            if form == 1:
                reg, rm, _ = modrm()
                return done('alu', ALU[op], rm, ('r', reg), osz)
            if form == 3:
                reg, rm, _ = modrm()
                return done('alu', ALU[op], ('r', reg), rm, osz)
            if form == 5:
                return done('alu', ALU[op], ('r', 0), ('i', sx(imm(4), 32, osz)), osz)
            raise Fault('unsupported ALU form')
        if 0x50 <= b <= 0x57:
            return done('push', ('r', (b & 7) | (rb << 3)))
        if 0x58 <= b <= 0x5f:
            return done('pop', ('r', (b & 7) | (rb << 3)))
        if 0x70 <= b <= 0x7f:
            d = sx(imm(1), 8, 64)
            return done('jcc', b & 15, (pos + d) & M64)
        if b in (0x81, 0x83):
            _, rm, ext = modrm()
            v = sx(imm(4), 32, osz) if b == 0x81 else sx(imm(1), 8, osz)
            return done('alu', ALU[ext], rm, ('i', v), osz)
        if b == 0x85:
            reg, rm, _ = modrm()
            return done('test', rm, ('r', reg), osz)
        if b == 0x87:
            reg, rm, _ = modrm()
            return done('xchg', rm, ('r', reg), osz)
        if b == 0x89:
            reg, rm, _ = modrm()
            return done('mov', rm, ('r', reg), osz)
        if b == 0x8b:
            reg, rm, _ = modrm()
            return done('mov', ('r', reg), rm, osz)
        if b == 0x8d:
            reg, rm, _ = modrm()
            require(rm[0] == 'm', 'lea needs memory form')
            return done('lea', ('r', reg), rm, osz)
        if b == 0x90:
            return done('nop')
        if 0xb8 <= b <= 0xbf:
            v = imm(8) if w else imm(4)
            return done('mov', ('r', (b & 7) | (rb << 3)), ('i', v), osz)
        if b in (0xc1, 0xd1, 0xd3):
            _, rm, ext = modrm()
            cnt = ('i', imm(1)) if b == 0xc1 else ('i', 1) if b == 0xd1 else ('r', 1)
            return done('shift', {4: 'shl', 5: 'shr', 7: 'sar'}[ext], rm, cnt, osz)
        if b == 0xc3:
            return done('ret')
        if b == 0xc7:
            _, rm, ext = modrm()
            require(ext == 0, 'c7 /0 only')
            return done('mov', rm, ('i', sx(imm(4), 32, osz)), osz)
        if b == 0xe8:
            d = sx(imm(4), 32, 64)
            return done('call', (pos + d) & M64)
        if b == 0xe9:
            d = sx(imm(4), 32, 64)
            return done('jmp', (pos + d) & M64)
        if b == 0xeb:
            d = sx(imm(1), 8, 64)
            return done('jmp', (pos + d) & M64)
        if b == 0xf7:
            _, rm, ext = modrm()
            if ext == 0:
                return done('test', rm, ('i', sx(imm(4), 32, osz)), osz)
            if ext == 2:
                return done('not', rm, osz)
            if ext == 3:
                return done('neg', rm, osz)
            raise Fault('unsupported f7 /%d' % ext)
        if b == 0xff:
            _, rm, ext = modrm()
            require(ext in (0, 1), 'ff /0 /1 only')
            return done('incdec', ext == 1, rm, osz)
        raise Fault('unsupported opcode %02x' % b)

    # -- operands
    def ea(self, op):
        _, base, index, scale, disp = op
        v = disp
        if base is not None:
            v += self.regs[base]
        if index is not None:
            v += self.regs[index] * scale
        return v & M64

    def get(self, op, size):
        kind = op[0]
        if kind == 'r':
            return self.regs[op[1]] & mask(size)
        if kind == 'i':
            return op[1] & mask(size)
        return self.load(self.ea(op), size)

    def put(self, op, size, value):
        value &= mask(size)
        if op[0] == 'r':
            self.regs[op[1]] = value if size in (32, 64) else (self.regs[op[1]] & ~mask(size)) | value
        elif op[0] == 'm':
            self.store(self.ea(op), size, value)
        else:
            raise Fault('store to immediate')

    def setszf(self, r, size):
        self.zf = int(r == 0)
        self.sf = (r >> (size - 1)) & 1

    def cond(self, c):
        base = c >> 1
        if base == 0:
            r = self.of
        elif base == 1:
            r = self.cf
        elif base == 2:
            r = self.zf
        elif base == 3:
            r = self.cf | self.zf
        elif base == 4:
            r = self.sf
        elif base == 6:
            r = self.sf ^ self.of
        elif base == 7:
            r = self.zf | (self.sf ^ self.of)
        else:
            raise Fault('parity condition not supported')
        return bool(r ^ (c & 1))

    def alu(self, name, a, b, size):
        m = mask(size)
        top = size - 1
        if name in ('add', 'adc'):
            c = self.cf if name == 'adc' else 0
            r = a + b + c
            self.cf = int(r > m)
            r &= m
            self.of = ((a ^ r) & (b ^ r)) >> top & 1
        elif name in ('sub', 'sbb', 'cmp'):
            c = self.cf if name == 'sbb' else 0
            r = a - b - c
            self.cf = int(r < 0)
            r &= m
            self.of = ((a ^ b) & (a ^ r)) >> top & 1
        else:
            r = {'and': a & b, 'or': a | b, 'xor': a ^ b}[name]
            self.cf = self.of = 0
        self.setszf(r, size)
        return r

    def step(self):
        ip = self.ip
        ins = self.cache.get(ip)
        if ins is None:
            ins = self.decode(ip)
            self.cache[ip] = ins
        length, name, ops = ins
        self.executed.add(ip)
        self.ip = nxt = (ip + length) & M64
        r = self.regs
        if name == 'nop':
            pass
        elif name == 'mov':
            self.put(ops[0], ops[2], self.get(ops[1], ops[2]))
        elif name == 'alu':
            op, dst, src, size = ops
            res = self.alu(op, self.get(dst, size), self.get(src, size), size)
            if op != 'cmp':
                self.put(dst, size, res)
        elif name == 'lea':
            self.put(ops[0], ops[2], self.ea(ops[1]))
        elif name == 'cmov':
            if self.cond(ops[0]):
                self.put(ops[1], ops[3], self.get(ops[2], ops[3]))
            elif ops[3] == 32:
                self.put(ops[1], 32, self.get(ops[1], 32))
        elif name == 'push':
            r[4] = (r[4] - 8) & M64
            self.store(r[4], 64, r[ops[0][1]])
        elif name == 'pop':
            r[ops[0][1]] = self.load(r[4], 64)
            r[4] = (r[4] + 8) & M64
        elif name == 'call':
            r[4] = (r[4] - 8) & M64
            self.store(r[4], 64, nxt)
            self.ip = ops[0]
        elif name == 'ret':
            self.ip = self.load(r[4], 64)
            r[4] = (r[4] + 8) & M64
        elif name == 'jmp':
            self.ip = ops[0]
        elif name == 'jcc':
            if self.cond(ops[0]):
                self.ip = ops[1]
        elif name == 'test':
            size = ops[2]
            res = self.get(ops[0], size) & self.get(ops[1], size)
            self.cf = self.of = 0
            self.setszf(res, size)
        elif name == 'xchg':
            size = ops[2]
            x, y = self.get(ops[0], size), self.get(ops[1], size)
            self.put(ops[0], size, y)
            self.put(ops[1], size, x)
        elif name == 'not':
            self.put(ops[0], ops[1], ~self.get(ops[0], ops[1]))
        elif name == 'neg':
            size = ops[1]
            v = self.get(ops[0], size)
            res = (-v) & mask(size)
            self.cf = int(v != 0)
            self.of = int(v == 1 << (size - 1))
            self.setszf(res, size)
            self.put(ops[0], size, res)
        elif name == 'incdec':
            dec, dst, size = ops
            v = self.get(dst, size)
            cf = self.cf
            res = self.alu('sub' if dec else 'add', v, 1, size)
            self.cf = cf
            self.put(dst, size, res)
        elif name == 'shift':
            kind, dst, cnt, size = ops
            n = self.get(cnt, 8) & (63 if size == 64 else 31)
            if n:
                v = self.get(dst, size)
                if kind == 'shl':
                    res = (v << n) & mask(size)
                    self.cf = (v >> (size - n)) & 1 if n <= size else 0
                elif kind == 'shr':
                    res = v >> n
                    self.cf = (v >> (n - 1)) & 1
                else:
                    sv = v - (1 << size) if v >> (size - 1) else v
                    res = (sv >> n) & mask(size)
                    self.cf = (sv >> (n - 1)) & 1
                self.of = 0
                self.setszf(res, size)
                self.put(dst, size, res)
        elif name == 'shd':
            left, dst, src, cnt, size = ops
            n = self.get(cnt, 8) & (63 if size == 64 else 31)
            if n:
                d, s = self.get(dst, size), self.get(src, size)
                if left:
                    res = ((d << n) | (s >> (size - n))) & mask(size)
                    self.cf = (d >> (size - n)) & 1
                else:
                    res = ((d >> n) | (s << (size - n))) & mask(size)
                    self.cf = (d >> (n - 1)) & 1
                self.of = 0
                self.setszf(res, size)
                self.put(dst, size, res)
        else:
            raise Fault('unhandled ' + name)

    def call(self, va, args, mem, rsp=STACK_TOP):
        """Run function at va with SysV integer args; mem is {offset: bytes}."""
        self.reset()
        self.mem[:] = b'\xa5' * MEM_SIZE
        for off, blob in mem.items():
            self.mem[off:off + len(blob)] = blob
        for reg, val in zip((7, 6, 2, 1, 8, 9), args):
            self.regs[reg] = val & M64
        saved = (0x1111111111111111, 0x2222222222222222, 0x3333333333333333, 0x4444444444444444,
                 0x5555555555555555, 0x6666666666666666)
        for reg, val in zip((3, 5, 12, 13, 14, 15), saved):
            self.regs[reg] = val
        self.regs[4] = rsp - 8
        self.store(rsp - 8, 64, SENTINEL)
        self.ip = va
        while self.ip != SENTINEL:
            self.steps += 1
            if self.steps > STEP_LIMIT:
                raise Fault('step limit')
            self.step()
        callee_ok = all(self.regs[reg] == val for reg, val in zip((3, 5, 12, 13, 14, 15), saved))
        return self.regs[0], self.regs[4] == rsp, callee_ok


# ---------------------------------------------------------------- models
def le(value, n=48):
    return value.to_bytes(n, 'little')


def half(a, mod):
    return (a + (mod if a & 1 else 0)) >> 1


def sgn0(a, mod):
    return (a & 1) | (2 if 2 * a >= mod else 0)


def sgn0x(re, im, mod):
    bit0 = (im & 1) if re == 0 else (re & 1)
    bit1 = sgn0(im, mod) & 2 if im != 0 else sgn0(re, mod) & 2
    return bit0 | bit1


def cneg(a, flag, mod, mut=None):
    if flag == 0 or (mut == 'flag-bit0' and flag & 1 == 0):
        return a
    if a == 0 and mut != 'no-zero':
        return 0
    return mod - a


# name, entry VA, model kind, internal helper (no callee-saved contract)
SPECS = [
    ('add_mod_384', 0x5d24a80, 'add', False),
    ('__add_mod_384', 0x5d24ac0, 'add', True),
    ('add_mod_384x', 0x5d24b60, 'addx', False),
    ('rshift_mod_384', 0x5d24be0, 'rsh', False),
    ('div_by_2_mod_384', 0x5d24d00, 'div2', False),
    ('lshift_mod_384', 0x5d24d80, 'lsh', False),
    ('mul_by_3_mod_384', 0x5d24ec0, 'mul3', False),
    ('mul_by_8_mod_384', 0x5d24f20, 'mul8', False),
    ('mul_by_3_mod_384x', 0x5d24fa0, 'mul3x', False),
    ('mul_by_8_mod_384x', 0x5d25040, 'mul8x', False),
    ('cneg_mod_384', 0x5d25100, 'cneg', False),
    ('sub_mod_384', 0x5d251e0, 'sub', False),
    ('sub_mod_384x', 0x5d252c0, 'subx', False),
    ('mul_by_1_plus_i_mod_384x', 0x5d25340, 'opi', False),
    ('sgn0_pty_mod_384', 0x5d254e0, 'sgn0', False),
    ('sgn0_pty_mod_384x', 0x5d25560, 'sgn0x', False),
]


def pick_mod(rng):
    t = rng.random()
    if t < 0.3:
        return BLS_P
    if t < 0.55:
        return rng.getrandbits(381) | (1 << 380) | 1
    if t < 0.75:
        return rng.getrandbits(384) | (1 << 383) | 1
    if t < 0.88:
        return (1 << 384) - rng.choice([1, 3, 5, 17, 189, 1 << 20 | 1])
    if t < 0.95:
        return rng.getrandbits(rng.choice([65, 130, 255, 300])) | 1
    return rng.getrandbits(380) | (1 << 379)


def pick_val(rng, mod):
    t = rng.random()
    edges = [0, 1, 2, mod - 1, mod - 2, (mod - 1) // 2, (mod + 1) // 2, (mod + 1) // 2 - 1, mod // 2, mod // 2 + 1,
             (1 << 64) % mod, (1 << 128) % mod, (1 << 383) % mod]
    if t < 0.3:
        return rng.choice(edges) % mod
    if t < 0.4:
        return rng.getrandbits(64) % mod
    return rng.randrange(mod)


def is_wide(kind):
    return kind.endswith('x') or kind == 'opi' or kind == 'sgn0x'


def gen_cases(kind, rng, n):
    for _ in range(n):
        mod = pick_mod(rng)
        case = {'mod': mod}
        wide = is_wide(kind)
        case['a'] = [pick_val(rng, mod), pick_val(rng, mod)] if wide else [pick_val(rng, mod)]
        if kind == 'sgn0x' and rng.random() < 0.3:
            case['a'][0] = 0
        if kind in ('sgn0', 'sgn0x') and rng.random() < 0.15:
            half_mod = rng.getrandbits(rng.choice([70, 200, 380])) | 1
            case['mod'] = 2 * half_mod
            case['a'][-1] = half_mod
        if kind in ('add', 'addx', 'sub', 'subx'):
            case['b'] = [pick_val(rng, mod), pick_val(rng, mod)] if wide else [pick_val(rng, mod)]
            if rng.random() < 0.2:
                case['b'] = [mod - 1 - x for x in case['a']]
        if kind in ('rsh', 'lsh'):
            case['n'] = rng.choice([1, 1, 2, 3, 4, 5, 8, 17, rng.randrange(1, 40)])
        if kind == 'cneg':
            case['flag'] = rng.choice([0, 1, 1, 2, 0xff, 1 << 32, 1 << 63, M64, rng.getrandbits(64)])
        yield case


def expected(kind, c, mut=None):
    mod, a = c['mod'], c['a']
    if kind == 'add':
        return [(a[0] + c['b'][0]) % mod if mut != 'no-reduce' else a[0] + c['b'][0]], None
    if kind == 'addx':
        return [(a[0] + c['b'][0]) % mod, (a[1] + c['b'][1]) % mod if mut != 'x-im-skip' else a[1]], None
    if kind == 'sub':
        return [(a[0] - c['b'][0]) % mod if mut != 'sub-as-add' else (a[0] + c['b'][0]) % mod], None
    if kind == 'subx':
        return [(a[0] - c['b'][0]) % mod, (a[1] - c['b'][1]) % mod if mut != 'x-im-skip' else a[1]], None
    if kind == 'rsh':
        v, count = a[0], c['n'] - 1 if mut == 'n-1' else c['n']
        for _ in range(count):
            v = half(v, mod) if mut != 'ignore-parity' else v >> 1
        return [v], None
    if kind == 'div2':
        return [half(a[0], mod) if mut != 'always-add' else (a[0] + mod) >> 1], None
    if kind == 'lsh':
        count = c['n'] + 1 if mut == 'n+1' else c['n']
        return [(a[0] << count) % mod], None
    if kind == 'mul3':
        return [(3 * a[0]) % mod if mut != 'times2' else (2 * a[0]) % mod], None
    if kind == 'mul8':
        return [(8 * a[0]) % mod if mut != 'times7' else (7 * a[0]) % mod], None
    if kind == 'mul3x':
        return [(3 * a[0]) % mod, (3 * a[1]) % mod if mut != 'x-im-skip' else a[1]], None
    if kind == 'mul8x':
        return [(8 * a[0]) % mod, (8 * a[1]) % mod if mut != 'x-im-skip' else a[1]], None
    if kind == 'cneg':
        flag = c['flag'] & 0xffffffff if mut == 'flag-32' else c['flag']
        return [cneg(a[0], flag, mod, mut)], None
    if kind == 'opi':
        if mut == 'swap':
            return [(a[1] - a[0]) % mod, (a[0] + a[1]) % mod], None
        return [(a[0] - a[1]) % mod, (a[0] + a[1]) % mod], None
    if kind == 'sgn0':
        v = a[0]
        if mut == 'parity-only':
            return [], v & 1
        if mut == 'gt':
            return [], (v & 1) | (2 if 2 * v > mod else 0)
        return [], sgn0(v, mod)
    if kind == 'sgn0x':
        if mut == 're-only':
            return [], sgn0(a[0], mod)
        if mut == 'bit1-re':
            return [], (sgn0x(a[0], a[1], mod) & 1) | (sgn0(a[0], mod) & 2)
        return [], sgn0x(a[0], a[1], mod)
    raise ValueError(kind)


def stage(kind, c):
    mem = {A_OFF: b''.join(le(x) for x in c['a']), MOD_OFF: le(c['mod'])}
    ret, a, mod = MEM_BASE + RET_OFF, MEM_BASE + A_OFF, MEM_BASE + MOD_OFF
    b = MEM_BASE + B_OFF
    if 'b' in c:
        mem[B_OFF] = b''.join(le(x) for x in c['b'])
    if kind in ('add', 'addx', 'sub', 'subx'):
        args = (ret, a, b, mod)
    elif kind in ('rsh', 'lsh'):
        args = (ret, a, c['n'], mod)
    elif kind == 'cneg':
        args = (ret, a, c['flag'], mod)
    elif kind in ('div2', 'mul3', 'mul8', 'mul3x', 'mul8x', 'opi'):
        args = (ret, a, mod)
    else:
        args = (a, mod)
    return mem, args


def run_case(cpu, va, kind, c, internal, mut=None):
    """(matches model, steps); an interpreter fault counts as no match"""
    mem, args = stage(kind, c)
    try:
        rax, rsp_ok, saved_ok = cpu.call(va, args, mem)
    except Fault:
        return False, cpu.steps
    outs, rv = expected(kind, c, mut)
    want = bytearray(b'\xa5' * MEM_SIZE)
    for off, blob in mem.items():
        want[off:off + len(blob)] = blob
    for i, v in enumerate(outs):
        want[RET_OFF + 48 * i:RET_OFF + 48 * i + 48] = le(v & ((1 << 384) - 1))
    lo, hi = STACK_TOP - 0x100 - MEM_BASE, STACK_TOP - MEM_BASE
    ok = cpu.mem[:lo] == want[:lo] and cpu.mem[hi:] == want[hi:] and rsp_ok and (saved_ok or internal)
    if rv is not None:
        ok = ok and rax == rv
    return ok, cpu.steps


def fmt_op(op):
    if op[0] == 'r':
        return 'r%d' % op[1]
    if op[0] == 'i':
        return '#%x' % op[1]
    disp = op[4] if op[4] < 1 << 63 else op[4] - (1 << 64)
    return '[%s%s%+d]' % ('r%d' % op[1] if op[1] is not None else '', '+r%d*%d' % (op[2], op[3]) if op[2] is not None else '', disp)


def fmt_ins(ins):
    _, name, ops = ins
    parts = []
    for o in ops:
        if isinstance(o, tuple):
            parts.append(fmt_op(o))
        elif isinstance(o, bool):
            parts.append('L' if o else 'R')
        elif isinstance(o, int):
            parts.append('%x' % o)
        else:
            parts.append(str(o))
    return name + ' ' + ' '.join(parts)


# ---------------------------------------------------------------- driver
CASES_PER_FUNCTION = 1000
SEED = 20261108


def sweep(image, patches=None, mut=None, only=None, count=CASES_PER_FUNCTION, collect=None):
    """run all (or one) functions; yields (name, cases, bad, min_steps, max_steps, executed set)"""
    for name, va, kind, internal in SPECS:
        if only and name != only:
            continue
        cpu = Cpu(image, patches)
        rng = random.Random('%s:%s' % (SEED, name))
        n = bad = 0
        lo, hi = 10 ** 9, 0
        seen = set()
        sample = []
        for c in gen_cases(kind, rng, count):
            ok, steps = run_case(cpu, va, kind, c, internal, mut)
            n += 1
            bad += not ok
            lo, hi = min(lo, steps), max(hi, steps)
            seen |= cpu.executed
            if collect is not None and len(sample) < 6:
                sample.append((c, ok, steps))
        if collect is not None:
            collect[name] = (cpu, sample)
        yield name, n, bad, lo, hi, seen


def hexs(c):
    parts = ['m=%x' % c['mod']] + ['a%d=%x' % (i, x) for i, x in enumerate(c['a'])]
    parts += ['b%d=%x' % (i, x) for i, x in enumerate(c.get('b', []))]
    if 'n' in c:
        parts.append('n=%d' % c['n'])
    if 'flag' in c:
        parts.append('flag=%x' % c['flag'])
    return ' '.join(parts)


def controls(image):
    """(id, description, detected) for every negative control"""
    out = []
    mutants = [
        ('add_mod_384', 'no-reduce'), ('add_mod_384x', 'x-im-skip'), ('sub_mod_384', 'sub-as-add'),
        ('sub_mod_384x', 'x-im-skip'), ('rshift_mod_384', 'n-1'), ('rshift_mod_384', 'ignore-parity'),
        ('div_by_2_mod_384', 'always-add'), ('lshift_mod_384', 'n+1'), ('mul_by_3_mod_384', 'times2'),
        ('mul_by_8_mod_384', 'times7'), ('mul_by_3_mod_384x', 'x-im-skip'), ('mul_by_8_mod_384x', 'x-im-skip'),
        ('cneg_mod_384', 'flag-32'), ('cneg_mod_384', 'flag-bit0'), ('cneg_mod_384', 'no-zero'),
        ('mul_by_1_plus_i_mod_384x', 'swap'), ('sgn0_pty_mod_384', 'parity-only'), ('sgn0_pty_mod_384', 'gt'),
        ('sgn0_pty_mod_384x', 're-only'), ('sgn0_pty_mod_384x', 'bit1-re'),
    ]
    for name, mut in mutants:
        bad = sum(r[2] for r in sweep(image, mut=mut, only=name, count=300))
        out.append(('model-mutant', '%s:%s' % (name, mut), bad > 0))
    # one-bit flips of executed instruction bytes (opcode/modrm/displacement/immediate)
    flips = [('add_mod_384', 3, 0), ('add_mod_384x', 5, 0), ('rshift_mod_384', 4, 0), ('div_by_2_mod_384', 6, 0),
             ('lshift_mod_384', 5, 0), ('mul_by_3_mod_384', 3, 0), ('mul_by_8_mod_384', 6, 0), ('cneg_mod_384', 10, 0),
             ('cneg_mod_384', 30, 0), ('sub_mod_384', 4, 0), ('sub_mod_384x', 7, 0), ('mul_by_1_plus_i_mod_384x', 9, 0),
             ('sgn0_pty_mod_384', 12, 0), ('sgn0_pty_mod_384x', 40, 0), ('mul_by_3_mod_384x', 6, 0)]
    base = {}
    for name, count_, _ in flips:
        if name not in base:
            col = {}
            list(sweep(image, only=name, count=30, collect=col))
            cpu = col[name][0]
            base[name] = sorted(cpu.cache) if False else sorted(a for a in col[name][0].cache)
    for name, nth, bit in flips:
        addrs = [a for a in base[name]]
        va = addrs[nth % len(addrs)]
        length = Cpu(image).decode(va)[0]
        target = va + length - 1
        patches = {target: image.byte(target) ^ (1 << bit)}
        bad = sum(r[2] for r in sweep(image, patches=patches, only=name, count=200))
        out.append(('byte-flip', '%s@%x+%d bit%d' % (name, va, length - 1, bit), bad > 0))
    # out-of-range inputs and structural rejections
    bad_image = bytearray(image.data)
    bad_image[len(bad_image) // 2] ^= 1
    try:
        Image(bytes(bad_image))
        out.append(('range', 'corrupted binary hash', False))
    except ValueError:
        out.append(('range', 'corrupted binary hash', True))
    try:
        image.extent(0x5d24a81)
        out.append(('range', 'non-FDE address accepted', False))
    except ValueError:
        out.append(('range', 'non-FDE address accepted', True))
    cpu = Cpu(image)
    mod = BLS_P
    unreduced = {'mod': (1 << 65) + 13, 'a': [3 * ((1 << 65) + 13)], 'b': [0]}
    ok, _ = run_case(cpu, 0x5d24a80, 'add', unreduced, False)
    out.append(('range', 'unreduced operand a=3*mod', not ok))
    unreduced = {'mod': mod, 'a': [mod + 5], 'b': [mod + 7]}
    ok, _ = run_case(cpu, 0x5d24a80, 'add', unreduced, False)
    out.append(('range', 'unreduced operands above mod', not ok))
    zero_shift = {'mod': mod, 'a': [3], 'n': 0}
    ok, _ = run_case(cpu, 0x5d24d80, 'lsh', zero_shift, False)
    out.append(('range', 'lshift count 0 loops', not ok))
    ok, _ = run_case(cpu, 0x5d24be0, 'rsh', zero_shift, False)
    out.append(('range', 'rshift count 0 loops', not ok))
    try:
        cpu.call(0x5d24a80, (1, 2, 3, 4), {})
        out.append(('range', 'pointers outside private memory', False))
    except Fault:
        out.append(('range', 'pointers outside private memory', True))
    try:
        Cpu(image).call(0x10, (0, 0, 0, 0), {})
        out.append(('range', 'entry outside .text', False))
    except Fault:
        out.append(('range', 'entry outside .text', True))
    try:
        Cpu(image, {0x5d24a80: 0xcc}).call(0x5d24a80, (0, 0, 0, 0), {})
        out.append(('range', 'unsupported opcode patched in', False))
    except Fault:
        out.append(('range', 'unsupported opcode patched in', True))
    return out


def generate(out):
    image = Image(TARGET.read_bytes())
    out = Path(out)
    out.mkdir(parents=True, exist_ok=True)
    rows, samples, listing = [], [], []
    total = 0
    collected = {}
    for (name, n, bad, lo, hi, seen), (_, va, kind, internal) in zip(sweep(image, collect=collected), SPECS):
        start, end = image.extent(va)
        cpu, sample = collected[name]
        insns = sorted(cpu.cache)
        executed_bytes = sum(cpu.cache[a][0] for a in insns if a in seen)
        rows.append('\t'.join(map(str, [name, '0x%x' % va, '0x%x' % end, end - start, kind, n, bad, lo, hi, len(seen), executed_bytes,
                                        digest(image.window(start, end - start))])))
        total += n
        for c, ok, steps in sample:
            samples.append('\t'.join([name, hexs(c), str(steps), 'match' if ok else 'MISMATCH']))
        for a in sorted(seen):
            listing.append('%s\t0x%x\t%d\t%s' % (name, a, cpu.cache[a][0], fmt_ins(cpu.cache[a])))
    require(all(r.split('\t')[6] == '0' for r in rows), 'a function disagrees with its model')
    ctl = controls(image)
    detected = sum(1 for c in ctl if c[2])
    head = 'function\tentry_va\tfde_end\tbytes\tmodel\tcases\tmismatches\tmin_steps\tmax_steps\tinstructions_executed\tbytes_executed\tbody_sha256\n'
    (out / 'functions.tsv').write_text(head + '\n'.join(rows) + '\n')
    (out / 'sample-cases.tsv').write_text('function\tcase\tsteps\tresult\n' + '\n'.join(samples) + '\n')
    (out / 'executed-instructions.tsv').write_text('function\tva\tlength\tdecoded\n' + '\n'.join(listing) + '\n')
    (out / 'negative-controls.tsv').write_text('kind\tcontrol\tdetected\n' + '\n'.join('%s\t%s\t%d' % (k, d, int(x)) for k, d, x in ctl) + '\n')
    (out / 'measure.json').write_text(json.dumps({'cases': total, 'negative_controls': len(ctl), 'negative_detected': detected,
                                                  'functions': len(SPECS), 'seed': SEED}, indent=1, sort_keys=True) + '\n')
    return total, len(ctl), detected


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--out', required=True)
    args = ap.parse_args()
    total, nctl, det = generate(args.out)
    print('cases=%d controls=%d detected=%d' % (total, nctl, det))


if __name__ == '__main__':
    main()
