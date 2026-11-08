#!/usr/bin/env python3
"""Node115 blst 256/384-bit field helpers: instruction-level reconstruction check.

Decodes the helper bodies from the node #115 image bytes, executes them in a
private integer x86-64 interpreter and compares every result with an
independent arithmetic model.  The node binary itself is never executed.
"""
import argparse
import hashlib
import json
from pathlib import Path
import struct
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
from elf_index import sections

ROOT = Path(__file__).resolve().parents[1]
TARGET = ROOT / 'artifacts/node/115/hl-node'
TARGET_SHA256 = 'a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301'

M64 = (1 << 64) - 1
M32 = (1 << 32) - 1
CODE_BASE = 0x5d24000
CODE_END = 0x5d2b600
SENTINEL = 0x7fff0000
STEP_LIMIT = 6000
REGS = ('rax', 'rcx', 'rdx', 'rbx', 'rsp', 'rbp', 'rsi', 'rdi', 'r8', 'r9', 'r10', 'r11', 'r12', 'r13', 'r14', 'r15')
ALU = ('add', 'or', 'adc', 'sbb', 'and', 'sub', 'xor', 'cmp')
SHIFT = {4: 'shl', 5: 'shr', 7: 'sar'}
CONDS = ('o', 'no', 'b', 'ae', 'e', 'ne', 'be', 'a', 's', 'ns', 'p', 'np', 'l', 'ge', 'le', 'g')


class Fault(Exception):
    pass


class Memory:
    """Sparse windows of bytes; any access outside a window is a fault."""

    def __init__(self):
        self.windows = []

    def add(self, base, size, fill=0):
        self.windows.append([base, bytearray([fill]) * size])

    def _find(self, addr, n):
        for base, buf in self.windows:
            if base <= addr and addr + n <= base + len(buf):
                return buf, addr - base
        raise Fault('memory access outside the model at 0x%x+%d' % (addr, n))

    def read(self, addr, n):
        buf, off = self._find(addr, n)
        return bytes(buf[off:off + n])

    def write(self, addr, data):
        buf, off = self._find(addr, len(data))
        buf[off:off + len(data)] = data

    def load(self, addr, size):
        return int.from_bytes(self.read(addr, size), 'little')

    def store(self, addr, size, value):
        self.write(addr, (value & ((1 << (8 * size)) - 1)).to_bytes(size, 'little'))


def load_text_window(data, sections):
    """Return the bytes of the executable region used by the helpers (file bytes, no NOBITS)."""
    for sec in sections:
        if sec['type'] != 8 and sec['flags'] & 4 and sec['address'] <= CODE_BASE and CODE_END <= sec['address'] + sec['size']:
            start = sec['offset'] + (CODE_BASE - sec['address'])
            return data[start:start + (CODE_END - CODE_BASE)]
    raise ValueError('code window is not inside one file-backed executable section')


class Decoded:
    __slots__ = ('addr', 'length', 'text', 'op', 'args')

    def __init__(self, addr, length, text, op, args):
        self.addr, self.length, self.text, self.op, self.args = addr, length, text, op, args


def _sx(value, bits):
    return value - (1 << bits) if value >> (bits - 1) else value


def decode(code, addr):
    """Decode one instruction at VA addr from the code window; returns Decoded."""
    pos = addr - CODE_BASE
    if not 0 <= pos < len(code):
        raise Fault('fetch outside the code window at 0x%x' % addr)
    start = pos

    def byte():
        nonlocal pos
        if pos >= len(code):
            raise Fault('truncated instruction at 0x%x' % addr)
        pos += 1
        return code[pos - 1]

    rep = False
    b = byte()
    if b == 0xf3:
        rep = True
        b = byte()
    rex = 0
    if 0x40 <= b <= 0x4f:
        rex = b
        b = byte()
    w = 64 if rex & 8 else 32
    rr, rx, rb = (rex >> 2) & 1, (rex >> 1) & 1, rex & 1

    def modrm():
        m = byte()
        mod, reg, rm = m >> 6, ((m >> 3) & 7) | (rr << 3), m & 7
        if mod == 3:
            return mod, reg, ('r', rm | (rb << 3))
        base = index = None
        scale = 1
        disp = 0
        if rm == 4:
            sib = byte()
            scale = 1 << (sib >> 6)
            idx = ((sib >> 3) & 7) | (rx << 3)
            bs = (sib & 7) | (rb << 3)
            if idx != 4:
                index = idx
            if (sib & 7) == 5 and mod == 0:
                raise Fault('absolute SIB form is outside the subset')
            base = bs
        else:
            if rm == 5 and mod == 0:
                raise Fault('rip-relative form is outside the subset')
            base = rm | (rb << 3)
        if mod == 1:
            disp = _sx(byte(), 8)
        elif mod == 2:
            disp = _sx(int.from_bytes(bytes(byte() for _ in range(4)), 'little'), 32)
        return mod, reg, ('m', base, index, scale, disp)

    def imm(n):
        v = int.from_bytes(bytes(byte() for _ in range(n)), 'little')
        return _sx(v, 8 * n)

    def fmt_rm(rm, bits):
        return rname(rm[1], bits) if rm[0] == 'r' else mtext(rm)

    def rname(i, bits):
        n = REGS[i]
        if bits == 64:
            return '%' + n
        return '%' + (n.replace('r', 'e', 1) if i < 8 else n + 'd')

    def mtext(rm):
        _, base, index, scale, disp = rm
        s = ('%#x' % disp if disp >= 0 else '-%#x' % -disp) if disp else ''
        inner = '%' + REGS[base]
        if index is not None:
            inner += ',%' + REGS[index] + ',%d' % scale
        return s + '(' + inner + ')'

    op = args = text = None
    if rep and b == 0xc3 and not rex:
        op, args, text = 'ret', (), 'repz ret'
    elif rep and b == 0x0f:
        if byte() != 0x1e or byte() != 0xfa:
            raise Fault('unsupported f3 0f sequence at 0x%x' % addr)
        op, args, text = 'nop', (), 'endbr64'
    elif rep:
        raise Fault('unsupported rep prefix at 0x%x' % addr)
    elif b == 0xc3:
        op, args, text = 'ret', (), 'ret'
    elif b < 0x40 and (b & 7) in (1, 3) and (b >> 3) <= 7:
        mod, reg, rm = modrm()
        name = ALU[b >> 3]
        if b & 7 == 1:
            op, args, text = 'alu', (name, 'rm_r', rm, reg, w), '%s %s,%s' % (name, rname(reg, w), fmt_rm(rm, w))
        else:
            op, args, text = 'alu', (name, 'r_rm', rm, reg, w), '%s %s,%s' % (name, fmt_rm(rm, w), rname(reg, w))
    elif b in (0x81, 0x83):
        mod, reg, rm = modrm()
        name = ALU[reg & 7]
        v = imm(4 if b == 0x81 else 1)
        op, args, text = 'alu', (name, 'rm_i', rm, v, w), '%s $%#x,%s' % (name, v & M64 if v < 0 else v, fmt_rm(rm, w))
    elif b == 0x85:
        mod, reg, rm = modrm()
        op, args, text = 'test', (rm, reg, w), 'test %s,%s' % (rname(reg, w), fmt_rm(rm, w))
    elif b == 0x89:
        mod, reg, rm = modrm()
        op, args, text = 'mov', ('rm_r', rm, reg, w), 'mov %s,%s' % (rname(reg, w), fmt_rm(rm, w))
    elif b == 0x8b:
        mod, reg, rm = modrm()
        op, args, text = 'mov', ('r_rm', rm, reg, w), 'mov %s,%s' % (fmt_rm(rm, w), rname(reg, w))
    elif b == 0x8d:
        mod, reg, rm = modrm()
        if rm[0] != 'm':
            raise Fault('lea with a register operand')
        op, args, text = 'lea', (rm, reg, w), 'lea %s,%s' % (mtext(rm), rname(reg, w))
    elif b == 0xc7:
        mod, reg, rm = modrm()
        if reg & 7:
            raise Fault('c7 with a non-zero reg field')
        v = imm(4)
        op, args, text = 'mov', ('rm_i', rm, v, w), 'mov $%#x,%s' % (v & M64 if v < 0 else v, fmt_rm(rm, w))
    elif 0xb8 <= b <= 0xbf:
        r = (b & 7) | (rb << 3)
        v = int.from_bytes(bytes(byte() for _ in range(8 if rex & 8 else 4)), 'little')
        op, args, text = 'mov', ('rm_i', ('r', r), v, w), 'mov $%#x,%s' % (v, rname(r, w))
    elif b in (0xc1, 0xd1):
        mod, reg, rm = modrm()
        if (reg & 7) not in SHIFT:
            raise Fault('unsupported shift group member')
        n = byte() if b == 0xc1 else 1
        op, args, text = 'shift', (SHIFT[reg & 7], rm, n, w), '%s $%#x,%s' % (SHIFT[reg & 7], n, fmt_rm(rm, w))
    elif b == 0xf7:
        mod, reg, rm = modrm()
        if (reg & 7) not in (2, 3):
            raise Fault('unsupported f7 group member')
        nm = 'not' if (reg & 7) == 2 else 'neg'
        op, args, text = 'unary', (nm, rm, w), '%s %s' % (nm, fmt_rm(rm, w))
    elif b == 0xff:
        mod, reg, rm = modrm()
        if (reg & 7) not in (0, 1):
            raise Fault('unsupported ff group member')
        nm = 'inc' if (reg & 7) == 0 else 'dec'
        op, args, text = 'unary', (nm, rm, w), '%s %s' % (nm, fmt_rm(rm, w))
    elif 0x50 <= b <= 0x57:
        r = (b & 7) | (rb << 3)
        op, args, text = 'push', (r,), 'push %' + REGS[r]
    elif 0x58 <= b <= 0x5f:
        r = (b & 7) | (rb << 3)
        op, args, text = 'pop', (r,), 'pop %' + REGS[r]
    elif b == 0x0f:
        b2 = byte()
        if 0x40 <= b2 <= 0x4f:
            mod, reg, rm = modrm()
            cc = b2 & 15
            op, args, text = 'cmov', (cc, rm, reg, w), 'cmov%s %s,%s' % (CONDS[cc], fmt_rm(rm, w), rname(reg, w))
        elif 0x80 <= b2 <= 0x8f:
            rel = imm(4)
            op, args, text = 'jcc', (b2 & 15, addr + (pos - start) + rel), 'j%s %#x' % (CONDS[b2 & 15], addr + (pos - start) + rel)
        else:
            raise Fault('unsupported 0f opcode %#x at 0x%x' % (b2, addr))
    elif 0x70 <= b <= 0x7f:
        rel = imm(1)
        tgt = addr + (pos - start) + rel
        op, args, text = 'jcc', (b & 15, tgt), 'j%s %#x' % (CONDS[b & 15], tgt)
    elif b == 0xe8:
        rel = imm(4)
        tgt = addr + (pos - start) + rel
        op, args, text = 'call', (tgt,), 'call %#x' % tgt
    elif b in (0xe9, 0xeb):
        rel = imm(4 if b == 0xe9 else 1)
        tgt = addr + (pos - start) + rel
        op, args, text = 'jmp', (tgt,), 'jmp %#x' % tgt
    else:
        raise Fault('unsupported opcode %#x at 0x%x' % (b, addr))
    return Decoded(addr, pos - start, text, op, args)


class Cpu:
    def __init__(self, code, mem):
        self.code, self.mem = code, mem
        self.regs = [0] * 16
        self.cf = self.zf = self.sf = self.of = 0
        self.rip = 0
        self.steps = 0
        self.executed = set()
        self._cache = {}

    def fetch(self, addr):
        d = self._cache.get(addr)
        if d is None:
            d = self._cache[addr] = decode(self.code, addr)
        return d

    # operand helpers
    def ea(self, rm):
        _, base, index, scale, disp = rm
        v = self.regs[base] + disp
        if index is not None:
            v += self.regs[index] * scale
        return v & M64

    def get(self, rm, w):
        if rm[0] == 'r':
            v = self.regs[rm[1]]
            return v if w == 64 else v & M32
        return self.mem.load(self.ea(rm), w // 8)

    def put(self, rm, w, v):
        if rm[0] == 'r':
            self.regs[rm[1]] = v & M64 if w == 64 else v & M32
        else:
            self.mem.store(self.ea(rm), w // 8, v)

    def setreg(self, r, w, v):
        self.regs[r] = v & M64 if w == 64 else v & M32

    def flags_logic(self, r, w):
        self.cf = self.of = 0
        self.zf = int(r == 0)
        self.sf = r >> (w - 1) & 1

    def alu(self, name, a, b, w):
        mask = (1 << w) - 1
        top = w - 1
        if name in ('add', 'adc'):
            cin = self.cf if name == 'adc' else 0
            full = a + b + cin
            r = full & mask
            self.cf = full >> w
            self.of = ((a ^ r) & (b ^ r)) >> top & 1
        elif name in ('sub', 'sbb', 'cmp'):
            cin = self.cf if name == 'sbb' else 0
            full = a - b - cin
            r = full & mask
            self.cf = int(a < b + cin)
            self.of = ((a ^ b) & (a ^ r)) >> top & 1
        else:
            r = {'and': a & b, 'or': a | b, 'xor': a ^ b}[name]
            self.flags_logic(r, w)
            return r
        self.zf = int(r == 0)
        self.sf = r >> top & 1
        return r

    def cond(self, cc):
        base = cc >> 1
        if base == 0:
            t = self.of
        elif base == 1:
            t = self.cf
        elif base == 2:
            t = self.zf
        elif base == 3:
            t = self.cf | self.zf
        elif base == 4:
            t = self.sf
        elif base == 6:
            t = self.sf ^ self.of
        elif base == 7:
            t = self.zf | (self.sf ^ self.of)
        else:
            raise Fault('parity condition is outside the subset')
        return bool(t) != bool(cc & 1)

    def push(self, v):
        self.regs[4] = (self.regs[4] - 8) & M64
        self.mem.store(self.regs[4], 8, v)

    def pop(self):
        v = self.mem.load(self.regs[4], 8)
        self.regs[4] = (self.regs[4] + 8) & M64
        return v

    def step(self):
        d = self.fetch(self.rip)
        self.executed.add(self.rip)
        nxt = self.rip + d.length
        op, a = d.op, d.args
        if op == 'nop':
            pass
        elif op == 'alu':
            name, form, rm, x, w = a
            if form == 'rm_r':
                r = self.alu(name, self.get(rm, w), self.regs[x] & ((1 << w) - 1), w)
                if name != 'cmp':
                    self.put(rm, w, r)
            elif form == 'r_rm':
                r = self.alu(name, self.regs[x] & ((1 << w) - 1), self.get(rm, w), w)
                if name != 'cmp':
                    self.setreg(x, w, r)
            else:
                r = self.alu(name, self.get(rm, w), x & ((1 << w) - 1), w)
                if name != 'cmp':
                    self.put(rm, w, r)
        elif op == 'test':
            rm, reg, w = a
            self.flags_logic(self.get(rm, w) & self.regs[reg] & ((1 << w) - 1), w)
        elif op == 'mov':
            if a[0] == 'rm_r':
                self.put(a[1], a[3], self.regs[a[2]])
            elif a[0] == 'r_rm':
                self.setreg(a[2], a[3], self.get(a[1], a[3]))
            else:
                self.put(a[1], a[3], a[2])
        elif op == 'lea':
            self.setreg(a[1], a[2], self.ea(a[0]))
        elif op == 'shift':
            name, rm, n, w = a
            v = self.get(rm, w)
            n &= 63 if w == 64 else 31
            if n:
                if name == 'shl':
                    full = v << n
                    self.cf = full >> w & 1
                    r = full & ((1 << w) - 1)
                elif name == 'shr':
                    self.cf = v >> (n - 1) & 1
                    r = v >> n
                else:
                    sv = _sx(v, w)
                    self.cf = sv >> (n - 1) & 1
                    r = (sv >> n) & ((1 << w) - 1)
                self.zf = int(r == 0)
                self.sf = r >> (w - 1) & 1
                self.of = 0
                self.put(rm, w, r)
        elif op == 'unary':
            name, rm, w = a
            v, mask = self.get(rm, w), (1 << w) - 1
            if name == 'not':
                self.put(rm, w, ~v & mask)
            elif name == 'neg':
                r = (-v) & mask
                self.cf = int(v != 0)
                self.zf = int(r == 0)
                self.sf = r >> (w - 1) & 1
                self.of = int(v == 1 << (w - 1))
                self.put(rm, w, r)
            else:
                r = (v + (1 if name == 'inc' else -1)) & mask
                self.of = int(r == (1 << (w - 1))) if name == 'inc' else int(r == (1 << (w - 1)) - 1)
                self.zf = int(r == 0)
                self.sf = r >> (w - 1) & 1
                self.put(rm, w, r)
        elif op == 'push':
            self.push(self.regs[a[0]])
        elif op == 'pop':
            self.regs[a[0]] = self.pop()
        elif op == 'cmov':
            cc, rm, reg, w = a
            v = self.get(rm, w)
            if self.cond(cc):
                self.setreg(reg, w, v)
            elif w == 32:
                self.regs[reg] &= M32
        elif op == 'jcc':
            if self.cond(a[0]):
                nxt = a[1]
        elif op == 'jmp':
            nxt = a[0]
        elif op == 'call':
            self.push(nxt)
            nxt = a[0]
        elif op == 'ret':
            nxt = self.pop()
        else:
            raise Fault('internal: unknown operation ' + op)
        self.rip = nxt
        self.steps += 1

    def call(self, entry, **regs):
        self.regs = [0] * 16
        for k, v in regs.items():
            self.regs[REGS.index(k)] = v & M64
        self.cf = self.zf = self.sf = self.of = 0
        top = self.regs[4]
        self.push(SENTINEL)
        self.rip = entry
        start = self.steps
        while self.rip != SENTINEL:
            if self.steps - start > STEP_LIMIT:
                raise Fault('step limit exceeded')
            self.step()
        return self.regs[0]


# ---------------------------------------------------------------------------
# function table: (name, entry VA, window length, operand kind, width bits, fp2/wide shape)
# kinds: bin (ret,a,b,p) un (ret,a,p) k (ret,a,k,p) chk (a,p)
# ---------------------------------------------------------------------------
FUNCS = (
    ('add_mod_256', 0x5d2b040, 122, 'bin', 256, 1),
    ('mul_by_3_mod_256', 0x5d2b0c0, 60, 'un', 256, 1),
    ('lshift_mod_256', 0x5d2b160, 68, 'k', 256, 1),
    ('rshift_mod_256', 0x5d2b1c0, 159, 'k', 256, 1),
    ('cneg_mod_256', 0x5d2b260, 140, 'k', 256, 1),
    ('sub_mod_256', 0x5d2b300, 114, 'bin', 256, 1),
    ('check_mod_256', 0x5d2b380, 69, 'chk', 256, 1),
    ('add_n_check_mod_256', 0x5d2b3e0, 142, 'bin', 256, 1),
    ('sub_n_check_mod_256', 0x5d2b480, 134, 'bin', 256, 1),
    ('rshift_mod_384', 0x5d24be0, 107, 'k', 384, 1),
    ('div_by_2_mod_384', 0x5d24d00, 106, 'un', 384, 1),
    ('lshift_mod_384', 0x5d24d80, 196, 'k', 384, 1),
    ('mul_by_3_mod_384', 0x5d24ec0, 92, 'un', 384, 1),
    ('mul_by_8_mod_384', 0x5d24f20, 119, 'un', 384, 1),
    ('mul_by_3_mod_384x', 0x5d24fa0, 145, 'un', 384, 2),
    ('mul_by_8_mod_384x', 0x5d25040, 183, 'un', 384, 2),
    ('cneg_mod_384', 0x5d25100, 217, 'k', 384, 1),
    ('mul_by_1_plus_i_mod_384x', 0x5d25340, 393, 'un', 384, 2),
    ('sgn0_pty_mod_384', 0x5d254e0, 98, 'chk', 384, 1),
    ('sgn0_pty_mod_384x', 0x5d25560, 273, 'chk', 384, 2),
    ('add_mod_384x384', 0x5d25e20, 268, 'bin', 384, 0),
    ('sub_mod_384x384', 0x5d25f40, 258, 'bin', 384, 0),
)
# internal helpers reached by call instructions: entry VA, name (length found by decoding to the first ret)
HELPERS = (
    ('__lshift_mod_256', 0x5d2b100, 68),
    ('__rshift_mod_384', 0x5d24c60, 153),
    ('__lshift_mod_384', 0x5d24e60, 96),
)
RET, A, B, P = 0x100200, 0x100400, 0x100600, 0x100800
DATA_BASE, DATA_SIZE, STACK_BASE, STACK_SIZE = 0x100000, 0x1000, 0x200000, 0x1000
GUARD = 0xa5


class Rng:
    """splitmix64: deterministic, independent of the interpreter's random module."""

    def __init__(self, seed):
        self.s = seed & M64

    def next(self):
        self.s = (self.s + 0x9e3779b97f4a7c15) & M64
        z = self.s
        z = ((z ^ (z >> 30)) * 0xbf58476d1ce4e5b9) & M64
        z = ((z ^ (z >> 27)) * 0x94d049bb133111eb) & M64
        return z ^ (z >> 31)

    def bits(self, n):
        v = 0
        for _ in range((n + 63) // 64):
            v = (v << 64) | self.next()
        return v & ((1 << n) - 1)

    def below(self, n):
        return self.bits(n.bit_length() + 8) % n

    def pick(self, seq):
        return seq[self.next() % len(seq)]


def gen_modulus(rng, width):
    style = rng.next() % 10
    if style < 6:
        p = rng.bits(width) | (1 << (width - 1)) | 1
    elif style < 9:
        p = rng.bits(width - rng.next() % 70) | 1
        p |= 1 << (p.bit_length() - 1) if p.bit_length() > 2 else 0
    else:
        p = rng.pick((3, 5, 7, (1 << 64) + 13, (1 << 128) - 159, (1 << (width - 1)) + 1, (1 << width) - 189 if width == 256 else (1 << width) - 317))
    return p | 1


def gen_element(rng, p):
    style = rng.next() % 10
    edges = (0, 1, 2, p - 1, p - 2, (p - 1) // 2, (p + 1) // 2, (1 << (p.bit_length() - 1)) % p, p // 3)
    if style < 5:
        return rng.below(p)
    if style < 8:
        return rng.pick(edges) % p
    return p - 1 - rng.below(min(p, 1 << 64))


def to_bytes(v, n):
    return v.to_bytes(n, 'little')


def mask(width):
    return (1 << width) - 1


def inv2k(p, k):
    return pow(2, -k, p)


def fp2_split(v, width):
    return v & mask(width), v >> width


def fp2_join(x, y, width):
    return x | (y << width)


def ref_model(name, kind, width, parts, p, a, b, k):
    """Independent arithmetic model; returns (ret int or None, rax int or None)."""
    w = width
    if name.endswith('384x384'):
        total = (a + b) if name.startswith('add') else (a - b)
        if name.startswith('sub') and total < 0:
            total += p << w
        lo, hi = total & mask(w), total >> w
        if name.startswith('add') and hi >= p:
            hi -= p
        return lo | (hi << w), None
    if name.startswith('add_mod') or name.startswith('add_n_check'):
        r = (a + b) % p
        return r, (int(r != 0) if 'check' in name else None)
    if name.startswith('sub_mod') or name.startswith('sub_n_check'):
        r = (a - b) % p
        return r, (int(r != 0) if 'check' in name else None)
    if name.startswith('check_mod'):
        return None, int(0 < a < p)
    if name.startswith('sgn0'):
        if parts == 1:
            return None, (a & 1) | (2 if 2 * a >= p else 0)
        a0, a1 = fp2_split(a, w)
        par = (a0 & 1) if a0 else (a1 & 1)
        lex = (2 if 2 * a1 >= p else 0) if a1 else (2 if 2 * a0 >= p else 0)
        return None, par | lex
    if name.startswith('cneg'):
        return ((p - a) % p if k else a), None
    if name.startswith('lshift'):
        return (a << k) % p, None
    if name.startswith('rshift'):
        return (a * inv2k(p, k)) % p, None
    if name.startswith('div_by_2'):
        return (a * inv2k(p, 1)) % p, None
    mul = {'mul_by_3': 3, 'mul_by_8': 8}
    for key, m in mul.items():
        if name.startswith(key):
            if parts == 1:
                return (a * m) % p, None
            a0, a1 = fp2_split(a, w)
            return fp2_join((a0 * m) % p, (a1 * m) % p, w), None
    if name.startswith('mul_by_1_plus_i'):
        a0, a1 = fp2_split(a, w)
        return fp2_join((a0 - a1) % p, (a0 + a1) % p, w), None
    raise ValueError('no model for ' + name)


def gen_case(rng, spec):
    name, va, length, kind, width, parts = spec
    p = gen_modulus(rng, width)
    if parts == 0:
        a = rng.bits(width) | (gen_element(rng, p) << width)
        b = rng.bits(width) | (gen_element(rng, p) << width)
        if rng.next() % 6 == 0:
            a = (a & ~mask(width)) | mask(width)
        if rng.next() % 6 == 0:
            b &= ~mask(width)
    else:
        a = fp2_join(*[gen_element(rng, p) for _ in range(parts)], width) if parts == 2 else gen_element(rng, p)
        b = gen_element(rng, p)
    if kind == 'bin' and parts == 1:
        pick = rng.next() % 12
        if pick == 0:
            b = a
        elif pick == 1:
            b = (p - a) % p
    k = 0
    if name.startswith('cneg'):
        k = rng.pick((0, 1, 1 << 32, 1 << 63, M64, rng.next()))
    elif kind == 'k':
        k = 1 + rng.next() % 12 if rng.next() % 4 else 1 + rng.next() % 3
    return p, a, b, k


def operand_bytes(spec):
    return (spec[4] // 8) * (spec[5] if spec[5] else 2)


def make_memory(spec, p, a, b):
    mem = Memory()
    mem.add(DATA_BASE, DATA_SIZE, GUARD)
    mem.add(STACK_BASE, STACK_SIZE, 0)
    n, wb = operand_bytes(spec), spec[4] // 8
    mem.write(A, to_bytes(a, n))
    mem.write(B, to_bytes(b, n))
    mem.write(P, to_bytes(p, wb))
    return mem


def call_args(spec, k):
    kind = spec[3]
    if kind == 'bin':
        return dict(rdi=RET, rsi=A, rdx=B, rcx=P)
    if kind == 'un':
        return dict(rdi=RET, rsi=A, rdx=P)
    if kind == 'k':
        return dict(rdi=RET, rsi=A, rdx=k, rcx=P)
    return dict(rdi=A, rsi=P)


CALLEE_SAVED = (3, 5, 12, 13, 14, 15)


def run_case(cpu, spec, p, a, b, k):
    """Execute the function bytes on one input; returns (ret int|None, rax, problems list)."""
    mem = make_memory(spec, p, a, b)
    cpu.mem = mem
    for i in range(16):
        cpu.regs[i] = 0
    saved = {i: (0x1111111111111111 * (i + 1)) & M64 for i in CALLEE_SAVED}
    sp = STACK_BASE + STACK_SIZE - 0x100
    regs = call_args(spec, k)
    regs['rsp'] = sp
    for i, v in saved.items():
        regs[REGS[i]] = v
    before = bytes(mem.windows[0][1])
    rax = cpu.call(spec[1], **regs)
    problems = []
    if cpu.regs[4] != sp:
        problems.append('rsp')
    for i, v in saved.items():
        if cpu.regs[i] != v:
            problems.append('callee-saved ' + REGS[i])
    after = bytes(mem.windows[0][1])
    n = operand_bytes(spec)
    has_ret = spec[3] != 'chk'
    for off in range(DATA_SIZE):
        if after[off] != before[off]:
            ad = DATA_BASE + off
            if not (has_ret and RET <= ad < RET + n):
                problems.append('stray write at 0x%x' % ad)
                break
    ret = int.from_bytes(after[RET - DATA_BASE:RET - DATA_BASE + n], 'little') if has_ret else None
    return ret, rax, problems


def verify_case(cpu, spec, p, a, b, k, model=ref_model):
    ret, rax, problems = run_case(cpu, spec, p, a, b, k)
    want_ret, want_rax = model(spec[0], spec[3], spec[4], spec[5], p, a, b, k)
    ok = not problems
    if want_ret is not None and ret != want_ret:
        ok = False
    if want_rax is not None and rax != want_rax:
        ok = False
    return ok, ret, rax


def static_decode(code, entry, length=None):
    """Linear decode from entry; with length None stops after the first ret."""
    out, addr = [], entry
    while True:
        d = decode(code, addr)
        out.append(d)
        addr += d.length
        if length is None and d.op == 'ret':
            return out
        if length is not None and addr - entry >= length:
            if addr - entry != length:
                raise Fault('decode does not tile the window')
            return out


def build_context(binary_path):
    data = Path(binary_path).read_bytes()
    check_image(data)
    secs = sections(data)
    code = bytearray(load_text_window(data, secs))
    del data
    return code


HELPERS = HELPERS + (('__add_mod_384', 0x5d24adb, None),)
CASES_PER_FUNCTION = 1000
CONTROL_BATCH = 120


def check_image(data):
    if hashlib.sha256(data).hexdigest() != TARGET_SHA256:
        raise SystemExit('input binary SHA-256 does not match node #115')


def spec_by_name(name):
    return next(s for s in FUNCS if s[0] == name)


# ---------------------------------------------------------------------------
# negative controls: deliberately wrong models, corrupted bytes, out-of-range inputs
# ---------------------------------------------------------------------------
def _mutant_models():
    m = {
        'add_mod_256': lambda p, a, b, k: ((a + b), None),
        'sub_mod_256': lambda p, a, b, k: ((a - b) & mask(256), None),
        'mul_by_3_mod_256': lambda p, a, b, k: ((a * 4) % p, None),
        'lshift_mod_256': lambda p, a, b, k: ((a << (k - 1)) % p, None),
        'rshift_mod_256': lambda p, a, b, k: (a >> k, None),
        'cneg_mod_256': lambda p, a, b, k: ((p - a) if k else a, None),
        'check_mod_256': lambda p, a, b, k: (None, int(0 <= a < p)),
        'add_n_check_mod_256': lambda p, a, b, k: ((a + b) % p, int((a + b) % p == 0)),
        'sub_n_check_mod_256': lambda p, a, b, k: ((a - b) % p, 1),
        'rshift_mod_384': lambda p, a, b, k: (a >> k, None),
        'div_by_2_mod_384': lambda p, a, b, k: ((a // 2) % p, None),
        'lshift_mod_384': lambda p, a, b, k: ((a << k) & mask(384), None),
        'mul_by_3_mod_384': lambda p, a, b, k: ((a * 4) % p, None),
        'mul_by_8_mod_384': lambda p, a, b, k: ((a * 8) & mask(384), None),
        'mul_by_3_mod_384x': lambda p, a, b, k: (fp2_join((fp2_split(a, 384)[1] * 3) % p, (fp2_split(a, 384)[0] * 3) % p, 384), None),
        'mul_by_8_mod_384x': lambda p, a, b, k: (fp2_join((fp2_split(a, 384)[0] * 8) % p, (fp2_split(a, 384)[1] * 3) % p, 384), None),
        'cneg_mod_384': lambda p, a, b, k: (((p - a) % p if k & M32 else a), None),
        'mul_by_1_plus_i_mod_384x': lambda p, a, b, k: (fp2_join((fp2_split(a, 384)[0] + fp2_split(a, 384)[1]) % p, (fp2_split(a, 384)[0] - fp2_split(a, 384)[1]) % p, 384), None),
        'sgn0_pty_mod_384': lambda p, a, b, k: (None, a & 1),
        'sgn0_pty_mod_384x': lambda p, a, b, k: (None, (fp2_split(a, 384)[1] & 1) | (2 if 2 * fp2_split(a, 384)[0] >= p else 0)),
        'add_mod_384x384': lambda p, a, b, k: (((a + b) & mask(384)) % p | (((a + b) >> 384) % p << 384), None),
        'sub_mod_384x384': lambda p, a, b, k: ((a - b) & mask(768), None),
    }
    return m


def _opcode_offset(code, addr):
    pos = addr - CODE_BASE
    if code[pos] == 0xf3:
        pos += 1
    if 0x40 <= code[pos] <= 0x4f:
        pos += 1
    return pos


def _find(code, spec, pred):
    for d in static_decode(code, spec[1], spec[2]):
        if pred(d):
            return d
    raise ValueError('mutation site not found in ' + spec[0])


def _alu(name, form=None):
    return lambda d: d.op == 'alu' and d.args[0] == name and (form is None or d.args[1] == form)


def _cmov(cc):
    return lambda d: d.op == 'cmov' and d.args[0] == cc


BYTE_MUTATIONS = (
    ('add_mod_256', 'adc-to-sbb', _alu('adc', 'r_rm'), lambda c, d: (_opcode_offset(c, d.addr), 0x1b)),
    ('sub_mod_256', 'sbb-to-adc', _alu('sbb', 'r_rm'), lambda c, d: (_opcode_offset(c, d.addr), 0x13)),
    ('add_mod_256', 'cmovb-to-cmovae', _cmov(2), lambda c, d: (_opcode_offset(c, d.addr) + 1, 0x43)),
    ('cneg_mod_256', 'cmove-to-cmovne', _cmov(4), lambda c, d: (_opcode_offset(c, d.addr) + 1, 0x45)),
    ('add_mod_256', 'sbb-imm-0-to-1', lambda d: d.op == 'alu' and d.args[:2] == ('sbb', 'rm_i'), lambda c, d: (d.addr - CODE_BASE + d.length - 1, 1)),
    ('rshift_mod_256', 'shl-imm-63-to-62', lambda d: d.op == 'shift' and d.args[0] == 'shl', lambda c, d: (d.addr - CODE_BASE + d.length - 1, 62)),
    ('add_mod_384x384', 'add-to-sub', _alu('add', 'r_rm'), lambda c, d: (_opcode_offset(c, d.addr), 0x2b)),
    ('sub_mod_384x384', 'disp-0x38-to-0x30', lambda d: d.op == 'mov' and d.args[0] == 'r_rm' and d.args[1][0] == 'm' and d.args[1][4] == 0x38, lambda c, d: (d.addr - CODE_BASE + d.length - 1, 0x30)),
    ('check_mod_256', 'top-limb-sbb-to-adc', lambda d: d.op == 'alu' and d.args[0] == 'sbb' and d.args[1] == 'r_rm' and d.args[2][4] == 0x18, lambda c, d: (_opcode_offset(c, d.addr), 0x13)),
    ('sgn0_pty_mod_384', 'not-to-neg', lambda d: d.op == 'unary' and d.args[0] == 'not', lambda c, d: (d.addr - CODE_BASE + d.length - 1, 0xd8)),
    ('lshift_mod_384', 'jne-to-je', lambda d: d.op == 'jcc' and d.args[0] == 5, lambda c, d: (_opcode_offset(c, d.addr), 0x74)),
    ('div_by_2_mod_384', 'helper-shr-to-shl', lambda d: d.op == 'shift' and d.args[0] == 'shr', lambda c, d: (d.addr - CODE_BASE + d.length - 1, 0xe0), ('__rshift_mod_384', 0x5d24c60, 153)),
    ('cneg_mod_384', 'and-to-or', _alu('and'), lambda c, d: (_opcode_offset(c, d.addr), 0x09)),
    ('check_mod_256', 'cmovne-to-cmove', _cmov(5), lambda c, d: (_opcode_offset(c, d.addr) + 1, 0x44)),
    ('mul_by_1_plus_i_mod_384x', 'sub-to-add', _alu('sub', 'r_rm'), lambda c, d: (_opcode_offset(c, d.addr), 0x03)),
)


def _batch_detects(code, spec, model=ref_model, seed=0):
    """True when at least one of CONTROL_BATCH cases disagrees, faults or breaks the ABI."""
    cpu = Cpu(code, None)
    rng = Rng(0xc0de + seed + sum(map(ord, spec[0])))
    for _ in range(CONTROL_BATCH):
        case = gen_case(rng, spec)
        try:
            ok, _, _ = verify_case(cpu, spec, *case, model=model)
        except Fault:
            return True
        if not ok:
            return True
    return False


def run_controls(code):
    results = []
    for name, fn in _mutant_models().items():
        spec = spec_by_name(name)
        wrong = (lambda f: (lambda n, kind, w, parts, p, a, b, k: f(p, a, b, k)))(fn)
        results.append(('model:' + name, 'wrong-model', _batch_detects(code, spec, wrong)))
    for fname, label, pred, edit, *site in BYTE_MUTATIONS:
        spec = spec_by_name(fname)
        bad = bytearray(code)
        d = _find(bad, (site[0] if site else spec), pred)
        off, val = edit(bad, d)
        bad[off] = val
        results.append(('bytes:%s:%s@%#x' % (fname, label, CODE_BASE + off), 'corrupt-bytes', _batch_detects(bad, spec)))
    cpu = Cpu(code, None)
    # out-of-range inputs, each outside the documented precondition of the helper
    spec = spec_by_name('lshift_mod_256')
    try:
        run_case(cpu, spec, (1 << 200) + 7, 5, 0, 0)
        hit = False
    except Fault:
        hit = True
    results.append(('range:lshift_mod_256:count-0-runs-away', 'out-of-range', hit))
    p = (1 << 200) + 7
    for fname, a, b, k in (('add_mod_256', 3 * p, p, 0), ('sub_mod_256', 0, 2 * p, 0), ('cneg_mod_384', 2 * p, 0, 1)):
        spec = spec_by_name(fname)
        ok, _, _ = verify_case(cpu, spec, p, a, b, k)
        results.append(('range:%s:operand-not-below-modulus' % fname, 'out-of-range', not ok))
    # a single conditional subtraction cannot canonicalise a high half of 5p
    spec = spec_by_name('add_mod_384x384')
    ret, _, _ = run_case(cpu, spec, p, (5 * p) << 384, 0, 0)
    results.append(('range:add_mod_384x384:high-half-not-below-modulus', 'out-of-range', ret >> 384 >= p))
    spec = spec_by_name('add_mod_256')
    try:
        mem = make_memory(spec, 7, 1, 2)
        cpu.mem = mem
        cpu.call(spec[1], rdi=0x300000, rsi=A, rdx=B, rcx=P, rsp=STACK_BASE + STACK_SIZE - 0x100)
        hit = False
    except Fault:
        hit = True
    results.append(('range:add_mod_256:unmapped-destination', 'out-of-range', hit))
    try:
        cpu.mem = make_memory(spec, 7, 1, 2)
        cpu.call(spec[1], rdi=RET, rsi=A, rdx=B, rcx=P, rsp=STACK_BASE + 16)
        hit = False
    except Fault:
        hit = True
    results.append(('range:add_mod_256:stack-too-small', 'out-of-range', hit))
    # decoder and image checks
    for label, thunk in (
        ('decode:undefined-opcode', lambda: decode(bytearray(b'\x0f\x0b'), CODE_BASE)),
        ('decode:truncated-instruction', lambda: decode(bytearray(b'\x48\x8b'), CODE_BASE)),
        ('decode:window-length-off-by-one', lambda: static_decode(code, spec_by_name('add_mod_256')[1], 121)),
        ('decode:fetch-outside-window', lambda: decode(code, CODE_END + 4)),
        ('image:wrong-digest', lambda: check_image(b'not the node image')),
    ):
        try:
            thunk()
            hit = False
        except (Fault, SystemExit):
            hit = True
        results.append((label, 'input-check', hit))
    return results


# ---------------------------------------------------------------------------
# evidence generation
# ---------------------------------------------------------------------------
def collect(code):
    """Yield per-function evidence while keeping only counters in memory."""
    rows = []
    cpu = Cpu(code, None)
    samples = []
    total_cases = 0
    for spec in FUNCS:
        rng = Rng(0x115 * 1000003 + sum(map(ord, spec[0])))
        cpu.executed = set()
        passed = rax_checked = 0
        steps0 = cpu.steps
        for i in range(CASES_PER_FUNCTION):
            case = gen_case(rng, spec)
            ok, ret, rax = verify_case(cpu, spec, *case)
            passed += ok
            if i < 2:
                samples.append((spec[0], case, ret, rax))
        static = static_decode(code, spec[1], spec[2])
        addrs = {d.addr for d in static}
        covered = len(cpu.executed & addrs)
        rows.append((spec, passed, covered, len(static), cpu.steps - steps0, set(cpu.executed)))
        total_cases += CASES_PER_FUNCTION
    return rows, samples, total_cases


def hexval(v):
    return '-' if v is None else '%#x' % v


def write_evidence(out, code):
    out = Path(out)
    out.mkdir(parents=True, exist_ok=True)
    rows, samples, total_cases = collect(code)
    helper_exec = set()
    for r in rows:
        helper_exec |= r[5]
    lines = ['function\tva\tlength\tinstructions\tbody_sha256']
    dec = ['function\tva\tlength\tbytes\ttext']
    for spec in FUNCS:
        body = bytes(code[spec[1] - CODE_BASE:spec[1] - CODE_BASE + spec[2]])
        ds = static_decode(code, spec[1], spec[2])
        lines.append('%s\t%#x\t%d\t%d\t%s' % (spec[0], spec[1], spec[2], len(ds), hashlib.sha256(body).hexdigest()))
        for d in ds:
            dec.append('%s\t%#x\t%d\t%s\t%s' % (spec[0], d.addr, d.length, bytes(code[d.addr - CODE_BASE:d.addr - CODE_BASE + d.length]).hex(), d.text))
    helper_rows = []
    for name, va, length in HELPERS:
        ds = static_decode(code, va, length)
        size = sum(d.length for d in ds)
        body = bytes(code[va - CODE_BASE:va - CODE_BASE + size])
        lines.append('%s\t%#x\t%d\t%d\t%s' % (name, va, size, len(ds), hashlib.sha256(body).hexdigest()))
        for d in ds:
            dec.append('%s\t%#x\t%d\t%s\t%s' % (name, d.addr, d.length, bytes(code[d.addr - CODE_BASE:d.addr - CODE_BASE + d.length]).hex(), d.text))
        helper_rows.append((name, len({d.addr for d in ds} & helper_exec), len(ds)))
    res = ['function\toperand_kind\tbits\tcases\tmatched\tinstructions_executed_in_body\tinstructions_in_body\tsteps']
    matched_total = 0
    for spec, passed, covered, nstatic, steps, _ in rows:
        res.append('%s\t%s\t%d\t%d\t%d\t%d\t%d\t%d' % (spec[0], spec[3], spec[4], CASES_PER_FUNCTION, passed, covered, nstatic, steps))
        matched_total += passed
    for name, covered, nstatic in helper_rows:
        res.append('%s\thelper\t-\t-\t-\t%d\t%d\t-' % (name, covered, nstatic))
    controls = run_controls(code)
    ctl = ['control\tkind\tdetected'] + ['%s\t%s\t%d' % (n, k, int(d)) for n, k, d in controls]
    smp = ['function\tp\ta\tb\tk\tret\trax']
    for name, (p, a, b, k), ret, rax in samples:
        smp.append('%s\t%#x\t%#x\t%#x\t%d\t%s\t%s' % (name, p, a, b, k, hexval(ret), hexval(rax)))
    measure = {
        'cases': total_cases,
        'negative_controls': len(controls),
        'negative_detected': sum(1 for c in controls if c[2]),
        'cases_matched': matched_total,
        'functions': len(FUNCS),
        'helpers': len(HELPERS),
    }
    files = {
        'windows.tsv': lines, 'decoded.tsv': dec, 'results.tsv': res, 'controls.tsv': ctl, 'sample_cases.tsv': smp,
    }
    for fname, content in files.items():
        (out / fname).write_text('\n'.join(content) + '\n')
    (out / 'measure.json').write_text(json.dumps(measure, indent=1, sort_keys=True) + '\n')
    return measure


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--out', required=True, help='directory that receives the evidence files')
    ap.add_argument('--binary', default=str(TARGET))
    args = ap.parse_args()
    code = build_context(args.binary)
    print(json.dumps(write_evidence(args.out, code), sort_keys=True))


if __name__ == '__main__':
    main()
