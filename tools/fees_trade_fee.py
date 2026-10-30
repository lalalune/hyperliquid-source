#!/usr/bin/env python3
"""fees: node #94 trade fee computation for one fill, perp and spot, from bytes alone.

Static, no execution of the node.  0x37130b0 (perp) and 0x3742460 (spot), with their three helpers
0x3743df0 (rate row), 0x3743020 (discount) and 0x3742070 (window sum), are decoded from ELF bytes by
the table decoder below, which must land exactly on each FDE end, and interpreted in Python on every
vector.  The hash 0x399c7a0, the overflow recorder and the panic entries are stubs.  Each outcome
is compared with a separate closed-form model, then every conditional is flipped to test the
vectors.

    python3 tools/fees_trade_fee.py --out <dir>

writes evidence.json, vectors.tsv, mutations.tsv, instructions.tsv and reference-diff.tsv.  Section
and FDE parsing come from tools/elf_index.py and tools/fde_extents.py.  Only the standard library
is used: no objdump, readelf or other external program runs, so the results cannot depend on a
binutils version.
"""

import argparse
import bisect
import hashlib
import json
import math
import struct
import sys
from fractions import Fraction
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))

from elf_index import sections as elf_sections  # noqa: E402
from fde_extents import eh_frame_records  # noqa: E402

BINARY = 'artifacts/node/94/hl-node'
SHA256 = '3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f'
U64 = (1 << 64) - 1

R = dict(rax=0, rcx=1, rdx=2, rbx=3, rsp=4, rbp=5, rsi=6, rdi=7, r8=8, r9=9, r10=10, r11=11, r12=12, r13=13,
         r14=14, r15=15)
NAMES64 = list(R)
CC = ('o', 'no', 'b', 'ae', 'e', 'ne', 'be', 'a', 's', 'ns', 'p', 'np', 'l', 'ge', 'le', 'g')
ALU = ('add', 'or', 'adc', 'sbb', 'and', 'sub', 'xor', 'cmp')


class EvidenceError(Exception):
    pass


class Unmodelled(Exception):
    """The evaluator met something it does not model; never treated as a result."""


def check_digest(data, expected=SHA256):
    got = hashlib.sha256(data).hexdigest()
    if got != expected:
        raise EvidenceError(f'sha256 mismatch: {got} != {expected}')
    return got


def sections(data):
    return {s['name']: (s['address'], s['offset'], s['size'], s['type']) for s in elf_sections(data)}


class Image:
    """ELF bytes by virtual address.  `patches` maps VA -> byte for negative controls."""

    def __init__(self, data, patches=None):
        self.data = data
        self.sec = sections(data)
        self.patches = patches or {}

    def off(self, va, size=1):
        for addr, off, sz, typ in self.sec.values():
            if addr and typ != 8 and addr <= va and va + size <= addr + sz:
                return off + va - addr
        raise EvidenceError(f'VA {va:#x} is outside every allocated section')

    def read(self, va, size):
        o = self.off(va, size)
        out = bytearray(self.data[o:o + size])
        for k, v in self.patches.items():
            if va <= k < va + size:
                out[k - va] = v
        return bytes(out)

    def f64(self, va):
        return struct.unpack('<d', self.read(va, 8))[0]

    def u64(self, va):
        return struct.unpack('<Q', self.read(va, 8))[0]

    def in_rodata(self, va, size):
        addr, _, sz, _ = self.sec['.rodata']
        return addr <= va and va + size <= addr + sz

    def relative(self, slot):
        """Addend of the R_X86_64_RELATIVE that fills pointer slot `slot`."""
        _, off, size, _ = self.sec['.rela.dyn']
        data = self.data
        needle = struct.pack('<QQ', slot, 8)
        i = data.find(needle, off, off + size)
        while i != -1 and (i - off) % 24:
            i = data.find(needle, i + 1, off + size)
        if i == -1:
            raise EvidenceError(f'no RELATIVE relocation fills {slot:#x}')
        return struct.unpack_from('<Q', data, i + 16)[0]


class Fdes:
    """FDE ranges from the shared .eh_frame parser; build it once, it walks every record."""

    def __init__(self, data):
        _, fdes = eh_frame_records(data)
        self.by_start = {f['start']: f for f in fdes}

    def range_of(self, start):
        fde = self.by_start.get(start)
        if fde is None:
            raise EvidenceError(f'no FDE starts at {start:#x}')
        return {'start': fde['start'], 'end': fde['end'], 'fde': fde['fde']}


class Insn:
    __slots__ = ('va', 'size', 'op', 'ops', 'width', 'raw')

    def __init__(self, va, size, op, ops, width, raw):
        self.va, self.size, self.op, self.ops, self.width, self.raw = va, size, op, ops, width, raw


def signed(val, bits):
    return val - (1 << bits) if val >> (bits - 1) & 1 else val


def decode_one(code, i, va):
    """Decode the instruction at code[i]; raise EvidenceError on any unlisted encoding."""
    start = i
    p66 = rep = seg = False
    while code[i] in (0x66, 0xf2, 0xf3, 0x2e, 0x64, 0xf0):
        p66 |= code[i] == 0x66
        seg |= code[i] == 0x64
        rep = {0xf2: 'f2', 0xf3: 'f3'}.get(code[i], rep)
        i += 1
    rex = code[i] if code[i] & 0xf0 == 0x40 else 0
    i += 1 if rex else 0
    w, rr, rx, rb = rex >> 3 & 1, rex >> 2 & 1, rex >> 1 & 1, rex & 1
    width = 64 if w else 16 if p66 else 32

    def gpr(idx, bits):
        if bits == 8 and not rex and idx >= 4:
            raise EvidenceError(f'{va:#x}: high byte register')
        return ('r', idx, bits)

    def modrm(bits, xmm_rm=False):
        nonlocal i
        b = code[i]
        i += 1
        mod, reg, rm = b >> 6, b >> 3 & 7, b & 7
        if mod == 3:
            return reg, (('x', rm | rb << 3) if xmm_rm else gpr(rm | rb << 3, bits))
        base, index, scale, rip, nobase = None, None, 1, False, False
        if rm == 4:
            sib = code[i]
            i += 1
            scale = 1 << (sib >> 6)
            idx = sib >> 3 & 7 | rx << 3
            index = None if idx == 4 else idx
            base = sib & 7 | rb << 3
            if sib & 7 == 5 and mod == 0:
                base = None
                nobase = True
        elif rm == 5 and mod == 0:
            rip = True
        else:
            base = rm | rb << 3
        disp = 0
        if mod == 1:
            disp = signed(code[i], 8)
            i += 1
        elif mod == 2 or rip or nobase:
            disp = struct.unpack_from('<i', code, i)[0]
            i += 4
        return reg, ('m', base, index, scale, disp, rip, bits)

    def imm(n):
        nonlocal i
        v = int.from_bytes(code[i:i + n], 'little', signed=True)
        i += n
        return ('i', v)

    def done(op, ops, bits=None):
        ops = tuple(fix_rip(o, va + (i - start)) for o in ops)
        return Insn(va, i - start, 'fs_' + op if seg else op, ops, bits or width, bytes(code[start:i]))

    b = code[i]
    i += 1
    if b == 0x0f:
        b2 = code[i]
        i += 1
        sse = {(0x10, False): 'movups', (0x10, True): 'movupd', (0x28, False): 'movaps', (0x28, True): 'movapd'}
        if b2 in (0x10, 0x11, 0x28, 0x29):
            reg, rm = modrm(64 if rep else 128, True)
            name = 'movsd' if rep == 'f2' else sse[b2 & 0xfe, p66]
            x = ('x', reg | rr << 3)
            return done(name, (x, rm) if not b2 & 1 else (rm, x), 64 if rep else 128)
        if b2 == 0x1f:
            reg, rm = modrm(width)
            return done('nop', ())
        if b2 == 0x2a and rep == 'f2':
            reg, rm = modrm(width)
            return done('cvtsi2sd', (('x', reg | rr << 3), rm))
        if b2 == 0x2c and rep == 'f2':
            reg, rm = modrm(64, True)
            return done('cvttsd2si', (gpr(reg | rr << 3, width), rm))
        if b2 == 0x2e and p66:
            reg, rm = modrm(64, True)
            return done('ucomisd', (('x', reg | rr << 3), rm), 64)
        if b2 == 0x0b:
            return done('ud2', ())
        if b2 in (0x13, 0x15, 0x16) and p66:
            reg, rm = modrm(64, True)
            x = ('x', reg | rr << 3)
            if b2 == 0x13:
                return done('movlpd', (rm, x), 64)
            return done('unpckhpd' if b2 == 0x15 else 'movhpd', (x, rm), 64)
        if b2 in (0x54, 0x55, 0x56) and p66:
            reg, rm = modrm(128, True)
            return done({0x54: 'andpd', 0x55: 'andnpd', 0x56: 'orpd'}[b2], (('x', reg | rr << 3), rm), 128)
        if b2 == 0x57:
            reg, rm = modrm(128, True)
            return done('xorpd' if p66 else 'xorps', (('x', reg | rr << 3), rm), 128)
        if b2 in (0x58, 0x5c) and rep == 'f2':
            reg, rm = modrm(64, True)
            return done('addsd' if b2 == 0x58 else 'subsd', (('x', reg | rr << 3), rm), 64)
        if b2 == 0x5c and p66:
            reg, rm = modrm(128, True)
            return done('subpd', (('x', reg | rr << 3), rm), 128)
        if b2 == 0x14 and not p66 and not rep:
            reg, rm = modrm(128, True)
            return done('unpcklps', (('x', reg | rr << 3), rm), 128)
        if b2 == 0xef and p66:
            reg, rm = modrm(128, True)
            return done('pxor', (('x', reg | rr << 3), rm), 128)
        if b2 == 0xd6 and p66:
            reg, rm = modrm(64, True)
            return done('movq', (rm, ('x', reg | rr << 3)), 64)
        if b2 in (0x60, 0x62, 0x74, 0x76, 0xdb) and p66:
            reg, rm = modrm(128, True)
            name = {0x60: 'punpcklbw', 0x62: 'punpckldq', 0x74: 'pcmpeqb', 0x76: 'pcmpeqd', 0xdb: 'pand'}[b2]
            return done(name, (('x', reg | rr << 3), rm), 128)
        if b2 == 0x70 and (p66 or rep == 'f2'):
            reg, rm = modrm(128, True)
            return done('pshufd' if p66 else 'pshuflw', (('x', reg | rr << 3), rm, imm(1)), 128)
        if b2 == 0x6f and (p66 or rep == 'f3'):
            reg, rm = modrm(128, True)
            return done('movdqa' if p66 else 'movdqu', (('x', reg | rr << 3), rm), 128)
        if b2 == 0x7f and rep == 'f3':
            reg, rm = modrm(128, True)
            return done('movdqu_store', (rm, ('x', reg | rr << 3)), 128)
        if b2 == 0xb1:
            reg, rm = modrm(width)
            return done('cmpxchg', (rm, gpr(reg | rr << 3, width)))
        if b2 == 0x6e and p66:
            reg, rm = modrm(64 if w else 32)
            return done('movq' if w else 'movd', (('x', reg | rr << 3), rm), 64 if w else 32)
        if b2 == 0x7e and rep == 'f3':
            reg, rm = modrm(64, True)
            return done('movq', (('x', reg | rr << 3), rm), 64)
        if b2 == 0xd7 and p66:
            reg, rm = modrm(128, True)
            return done('pmovmskb', (gpr(reg | rr << 3, 32), rm), 32)
        if b2 == 0xbc and rep == 'f3':
            reg, rm = modrm(width)
            return done('tzcnt', (gpr(reg | rr << 3, width), rm))
        if b2 == 0xc2 and rep == 'f2':
            reg, rm = modrm(64, True)
            pred = imm(1)[1] & 0xff
            if pred not in (1, 3, 5):
                raise EvidenceError(f'{va:#x}: unlisted cmpsd predicate {pred}')
            return done({1: 'cmpltsd', 3: 'cmpunordsd', 5: 'cmpnltsd'}[pred], (('x', reg | rr << 3), rm), 64)
        if b2 in (0x59, 0x5d, 0x5e, 0x5f) and rep == 'f2':
            reg, rm = modrm(64, True)
            return done({0x59: 'mulsd', 0x5d: 'minsd', 0x5e: 'divsd', 0x5f: 'maxsd'}[b2],
                        (('x', reg | rr << 3), rm), 64)
        if b2 == 0x7e and p66 and w:
            reg, rm = modrm(64)
            return done('movq', (rm, ('x', reg | rr << 3)), 64)
        if b2 & 0xf0 == 0x40:
            reg, rm = modrm(width)
            return done('cmov' + CC[b2 & 15], (gpr(reg | rr << 3, width), rm))
        if b2 & 0xf0 == 0x80:
            rel = imm(4)[1]
            return done('j' + CC[b2 & 15], (('t', va + (i - start) + rel),))
        if b2 & 0xf0 == 0x90:
            reg, rm = modrm(8)
            return done('set' + CC[b2 & 15], (rm,), 8)
        if b2 in (0xb6, 0xb7):
            reg, rm = modrm(8 if b2 == 0xb6 else 16)
            return done('movzx', (gpr(reg | rr << 3, width), rm))
        raise EvidenceError(f'{va:#x}: unlisted opcode 0f {b2:02x}')
    if b < 0x40 and b & 7 in (4, 5):
        bits = 8 if b & 7 == 4 else width
        return done(ALU[b >> 3], (gpr(0, bits), imm(1 if bits == 8 else 2 if bits == 16 else 4)), bits)
    if b < 0x40 and b & 7 <= 3:
        bits = 8 if not b & 1 else width
        reg, rm = modrm(bits)
        g = gpr(reg | rr << 3, bits)
        return done(ALU[b >> 3], (rm, g) if not b & 2 else (g, rm), bits)
    if 0x50 <= b <= 0x5f:
        return done('push' if b < 0x58 else 'pop', (gpr(b & 7 | rb << 3, 64),), 64)
    if b == 0x63:
        reg, rm = modrm(32)
        return done('movsxd', (gpr(reg | rr << 3, width), rm))
    if b in (0x69, 0x6b):
        reg, rm = modrm(width)
        v = imm(4 if b == 0x69 else 1)
        return done('imul', (gpr(reg | rr << 3, width), rm, v))
    if 0x70 <= b <= 0x7f:
        rel = imm(1)[1]
        return done('j' + CC[b & 15], (('t', va + (i - start) + rel),))
    if b in (0x80, 0x81, 0x83):
        bits = 8 if b == 0x80 else width
        reg, rm = modrm(bits)
        v = imm(1 if b != 0x81 else 2 if width == 16 else 4)
        return done(ALU[reg], (rm, v), bits)
    if b in (0x84, 0x85):
        bits = 8 if b == 0x84 else width
        reg, rm = modrm(bits)
        return done('test', (rm, gpr(reg | rr << 3, bits)), bits)
    if b in (0x88, 0x89, 0x8a, 0x8b):
        bits = 8 if not b & 1 else width
        reg, rm = modrm(bits)
        g = gpr(reg | rr << 3, bits)
        return done('mov', (rm, g) if not b & 2 else (g, rm), bits)
    if b == 0x8d:
        reg, rm = modrm(width)
        return done('lea', (gpr(reg | rr << 3, width), rm))
    if b == 0x90:
        return done('nop', ())
    if 0xb0 <= b <= 0xb7:
        v = imm(1)
        return done('mov', (gpr(b & 7 | rb << 3, 8), ('i', v[1] & 0xff)), 8)
    if 0xb8 <= b <= 0xbf:
        v = imm(8 if w else 2 if p66 else 4)
        val = v[1] & (U64 if w else 0xffff if p66 else 0xffffffff)
        return done('mov', (gpr(b & 7 | rb << 3, width), ('i', val)))
    if b == 0xc1:
        reg, rm = modrm(width)
        v = imm(1)
        if reg not in (4, 5, 7):
            raise EvidenceError(f'{va:#x}: unlisted shift /{reg}')
        return done({4: 'shl', 5: 'shr', 7: 'sar'}[reg], (rm, ('i', v[1] & 0xff)))
    if b == 0xd1:
        reg, rm = modrm(width)
        if reg not in (4, 5, 7):
            raise EvidenceError(f'{va:#x}: unlisted shift /{reg}')
        return done({4: 'shl', 5: 'shr', 7: 'sar'}[reg], (rm, ('i', 1)))
    if b == 0xc3:
        return done('ret', ())
    if b == 0xcc:
        return done('int3', ())
    if b == 0xc6:
        reg, rm = modrm(8)
        if reg:
            raise EvidenceError(f'{va:#x}: unlisted c6 /{reg}')
        return done('mov', (rm, imm(1)), 8)
    if b == 0xc7:
        reg, rm = modrm(width)
        if reg:
            raise EvidenceError(f'{va:#x}: unlisted c7 /{reg}')
        return done('mov', (rm, imm(2 if width == 16 else 4)))
    if b in (0xe8, 0xe9):
        rel = imm(4)[1]
        return done('call' if b == 0xe8 else 'jmp', (('t', va + (i - start) + rel),))
    if b == 0x98:
        return done('cdqe' if w else 'cwde', ())
    if b == 0x99:
        return done('cqo' if w else 'cdq', ())
    if b == 0xeb:
        rel = imm(1)[1]
        return done('jmp', (('t', va + (i - start) + rel),))
    if b == 0xa8:
        return done('test', (gpr(0, 8), imm(1)), 8)
    if b == 0xf6:
        reg, rm = modrm(8)
        if reg:
            raise EvidenceError(f'{va:#x}: unlisted f6 /{reg}')
        return done('test', (rm, imm(1)), 8)
    if b == 0xf7:
        reg, rm = modrm(width)
        if reg == 0:
            return done('test', (rm, imm(4)))
        if reg not in (2, 3, 4, 5):
            raise EvidenceError(f'{va:#x}: unlisted f7 /{reg}')
        return done({2: 'not', 3: 'neg', 4: 'mul', 5: 'imul1'}[reg], (rm,))
    if b == 0xff:
        reg, rm = modrm(width)
        if reg in (0, 1):
            return done('dec' if reg else 'inc', (rm,))
        if reg == 2:
            return done('call', (rm,), 64)
        if reg == 4:
            return done('jmpr', (rm,), 64)
        raise EvidenceError(f'{va:#x}: unlisted ff /{reg}')
    raise EvidenceError(f'{va:#x}: unlisted opcode {b:02x}')


def fix_rip(op, next_va):
    """A rip operand becomes an absolute one, using the end of the instruction."""
    if op[0] == 'm' and op[5]:
        return ('m', None, None, 1, next_va + op[4], False, op[6])
    return op


def decode_range(img, start, end):
    code = img.read(start, end - start) + b'\x90' * 16
    insns, i = [], 0
    while start + i < end:
        ins = decode_one(code, i, start + i)
        insns.append(ins)
        i += ins.size
    if start + i != end:
        raise EvidenceError(f'decoding overran the FDE end: {start + i:#x} != {end:#x}')
    return insns


def show_op(o):
    if o[0] == 'r':
        return NAMES64[o[1]] if o[2] == 64 else f'{NAMES64[o[1]]}:{o[2]}'
    if o[0] == 'x':
        return f'xmm{o[1]}'
    if o[0] in ('i', 't'):
        return hex(o[1]) if o[1] >= 0 else f'-{-o[1]:#x}'
    _, base, index, scale, disp, _, bits = o
    terms = []
    if base is not None:
        terms.append(NAMES64[base])
    if index is not None:
        terms.append(f'{NAMES64[index]}*{scale}')
    if disp or not terms:
        terms.append(f'{disp:#x}' if disp >= 0 else f'-{-disp:#x}')
    return f'[{"+".join(terms)}]:{bits}'


def show(ins):
    return f"{ins.op} {','.join(show_op(o) for o in ins.ops)}".strip()


def f2b(x):
    return struct.unpack('<Q', struct.pack('<d', x))[0]


def fdiv(a, b):
    """IEEE division; a Python float division refuses a zero divisor."""
    if b != 0.0:
        return a / b
    if a == 0.0 or a != a:
        return math.nan
    return math.copysign(math.inf, a) * math.copysign(1.0, b)


def b2f(x):
    return struct.unpack('<d', struct.pack('<Q', x))[0]


class Arena:
    """One region of modelled memory.  A strict arena faults on reading unset bytes."""

    def __init__(self, base, size, strict=True):
        self.base, self.size, self.strict = base, size, strict
        self.mem = bytearray(size)
        self.valid = bytearray(b'\1' * size if not strict else size)


class Machine:
    def __init__(self, img, insns):
        self.img = img
        self.code = {i.va: i for i in insns}
        self.arenas = []
        self.last = None
        self.next_base = 0x7000_0000_0000
        self.regs = [0] * 16
        self.xmm = [[0, 0] for _ in range(16)]
        self.cf = self.zf = self.sf = self.of = self.pf = False
        self.stubs = {}
        self.real = {}
        self.got = {}
        self.seen = set()
        self.taken = {}
        self.hooks = {}
        self.race = None
        self.cur = None
        self.loose = ()
        self.slots = {}

    def arena(self, size, strict=True):
        a = Arena(self.next_base, size, strict)
        self.next_base += (size + 0xffff) & ~0xfff
        self.arenas.append(a)
        return a

    def find(self, addr, size):
        a = self.last
        if a is not None and a.base <= addr and addr + size <= a.base + a.size:
            return a
        for a in self.arenas:
            if a.base <= addr and addr + size <= a.base + a.size:
                self.last = a
                return a
        return None

    def load(self, addr, size):
        if addr in self.got:
            return self.got[addr]
        a = self.find(addr, size)
        if a is None:
            if self.img.in_rodata(addr, size):
                return int.from_bytes(self.img.read(addr, size), 'little')
            raise Unmodelled(f'load {addr:#x}')
        o = addr - a.base
        if a.strict and not all(a.valid[o:o + size]) and self.cur not in self.loose:
            raise Unmodelled(f'read of unset bytes at {addr:#x}')
        return int.from_bytes(a.mem[o:o + size], 'little')

    def store(self, addr, size, val):
        a = self.find(addr, size)
        if a is None:
            raise Unmodelled(f'store {addr:#x}')
        o = addr - a.base
        a.mem[o:o + size] = (val & ((1 << size * 8) - 1)).to_bytes(size, 'little')
        a.valid[o:o + size] = b'\1' * size

    def ea(self, o):
        _, base, index, scale, disp, _, _ = o
        v = disp
        if base is not None:
            v += self.regs[base]
        if index is not None:
            v += self.regs[index] * scale
        return v & U64

    def rd(self, o):
        if o[0] == 'r':
            return self.regs[o[1]] & ((1 << o[2]) - 1)
        if o[0] == 'i':
            return o[1]
        if o[0] == 'm':
            return self.load(self.ea(o), o[6] // 8)
        raise Unmodelled(f'read operand {o}')

    def wr(self, o, val):
        if o[0] == 'r':
            bits = o[2]
            val &= (1 << bits) - 1
            if bits == 64 or bits == 32:
                self.regs[o[1]] = val
            else:
                self.regs[o[1]] = self.regs[o[1]] & ~((1 << bits) - 1) | val
        elif o[0] == 'm':
            self.store(self.ea(o), o[6] // 8, val)
        else:
            raise Unmodelled(f'write operand {o}')

    def nz(self, res, bits):
        res &= (1 << bits) - 1
        self.zf = res == 0
        self.sf = bool(res >> (bits - 1))
        self.pf = bin(res & 0xff).count('1') % 2 == 0

    def cond(self, name):
        t = {'o': self.of, 'b': self.cf, 'e': self.zf, 'be': self.cf or self.zf, 's': self.sf, 'p': self.pf,
             'l': self.sf != self.of, 'le': self.zf or self.sf != self.of}
        if name in t:
            return t[name]
        if name == 'ae':
            return not self.cf
        if name == 'a':
            return not (self.cf or self.zf)
        if name == 'ge':
            return self.sf == self.of
        if name == 'g':
            return not self.zf and self.sf == self.of
        return not t[name[1:]]

    def alu(self, op, ins):
        bits = ins.width
        mask = (1 << bits) - 1
        a = self.rd(ins.ops[0])
        b = self.rd(ins.ops[1]) & mask
        if op in ('add', 'adc'):
            c = self.cf if op == 'adc' else 0
            full = a + b + c
            res = full & mask
            self.cf = full > mask
            self.of = bool((~(a ^ b) & (a ^ res)) >> (bits - 1) & 1)
        elif op in ('sub', 'sbb', 'cmp'):
            c = self.cf if op == 'sbb' else 0
            res = (a - b - c) & mask
            self.cf = a < b + c
            self.of = bool(((a ^ b) & (a ^ res)) >> (bits - 1) & 1)
        else:
            res = {'and': a & b, 'or': a | b, 'xor': a ^ b}[op]
            self.cf = self.of = False
        self.nz(res, bits)
        if op != 'cmp':
            self.wr(ins.ops[0], res)

    def x128(self, o):
        if o[0] == 'x':
            return self.xmm[o[1]][0] | self.xmm[o[1]][1] << 64
        return self.load(self.ea(o), 8) | self.load(self.ea(o) + 8, 8) << 64

    def setx(self, o, v):
        self.xmm[o[1]] = [v & U64, v >> 64 & U64]

    def xrd64(self, o):
        return self.xmm[o[1]][0] if o[0] == 'x' else self.load(self.ea(o), 8)

    def do_sse(self, ins):
        op, ops = ins.op, ins.ops
        if op in ('movups', 'movupd', 'movaps', 'movapd'):
            if op.startswith('mova'):
                for o in ops:
                    if o[0] == 'm' and self.ea(o) % 16:
                        raise Unmodelled(f'{ins.va:#x}: misaligned {op}')
            src, dst = ops[1], ops[0]
            v = list(self.xmm[src[1]]) if src[0] == 'x' else [self.load(self.ea(src), 8),
                                                               self.load(self.ea(src) + 8, 8)]
            if dst[0] == 'x':
                self.xmm[dst[1]] = v
            else:
                self.store(self.ea(dst), 8, v[0])
                self.store(self.ea(dst) + 8, 8, v[1])
        elif op == 'movsd':
            if ops[0][0] == 'x' and ops[1][0] == 'm':
                self.xmm[ops[0][1]] = [self.load(self.ea(ops[1]), 8), 0]
            elif ops[0][0] == 'm' and ops[1][0] == 'x':
                self.store(self.ea(ops[0]), 8, self.xmm[ops[1][1]][0])
            else:
                raise Unmodelled(f'{ins.va:#x}: movsd form')
        elif op in ('xorps', 'xorpd'):
            if ops[0] != ops[1]:
                raise Unmodelled(f'{ins.va:#x}: xor of two registers')
            self.xmm[ops[0][1]] = [0, 0]
        elif op in ('addsd', 'subsd'):
            a, b = b2f(self.xmm[ops[0][1]][0]), b2f(self.xrd64(ops[1]))
            self.xmm[ops[0][1]][0] = f2b(a + b if op == 'addsd' else a - b)
        elif op in ('andpd', 'andnpd', 'orpd'):
            src = ops[1]
            lo, hi = self.xmm[src[1]] if src[0] == 'x' else (self.load(self.ea(src), 8),
                                                             self.load(self.ea(src) + 8, 8))
            dst = self.xmm[ops[0][1]]
            if op == 'andpd':
                dst[0], dst[1] = dst[0] & lo, dst[1] & hi
            elif op == 'orpd':
                dst[0], dst[1] = dst[0] | lo, dst[1] | hi
            else:
                dst[0], dst[1] = ~dst[0] & lo & U64, ~dst[1] & hi & U64
        elif op == 'movhpd':
            self.xmm[ops[0][1]][1] = self.load(self.ea(ops[1]), 8)
        elif op == 'movlpd':
            self.store(self.ea(ops[0]), 8, self.xmm[ops[1][1]][0])
        elif op == 'unpckhpd':
            hi = self.xmm[ops[1][1]][1] if ops[1][0] == 'x' else self.load(self.ea(ops[1]) + 8, 8)
            self.xmm[ops[0][1]] = [self.xmm[ops[0][1]][1], hi]
        elif op in ('cmpltsd', 'cmpnltsd', 'cmpunordsd'):
            a, b = b2f(self.xmm[ops[0][1]][0]), b2f(self.xrd64(ops[1]))
            hit = {'cmpltsd': a < b, 'cmpnltsd': not a < b, 'cmpunordsd': math.isnan(a) or math.isnan(b)}[op]
            self.xmm[ops[0][1]][0] = U64 if hit else 0
        elif op == 'unpcklps':
            a, b = self.x128(ops[0]), self.x128(ops[1])
            self.setx(ops[0], sum(((a >> 32 * k & 0xffffffff) | (b >> 32 * k & 0xffffffff) << 32) << 64 * k for k in range(2)))
        elif op == 'subpd':
            a, b = self.x128(ops[0]), self.x128(ops[1])
            x = [f2b(b2f(a >> 64 * k & U64) - b2f(b >> 64 * k & U64)) for k in range(2)]
            self.setx(ops[0], x[0] | x[1] << 64)
        elif op == 'pxor':
            self.setx(ops[0], self.x128(ops[0]) ^ self.x128(ops[1]))
        elif op == 'cvtsi2sd':
            self.xmm[ops[0][1]][0] = f2b(float(signed(self.rd(ops[1]), ins.width)))
        elif op == 'movq':
            if ops[0][0] == 'x':
                self.setx(ops[0], self.rd(ops[1]) if ops[1][0] != 'x' else self.xmm[ops[1][1]][0])
            else:
                self.wr(ops[0], self.xmm[ops[1][1]][0])
        elif op == 'movd':
            self.setx(ops[0], self.rd(ops[1]))
        elif op == 'movdqu_store':
            v = self.xmm[ops[1][1]]
            self.store(self.ea(ops[0]), 8, v[0])
            self.store(self.ea(ops[0]) + 8, 8, v[1])
        elif op in ('movdqu', 'movdqa'):
            if op == 'movdqa' and ops[1][0] == 'm' and self.ea(ops[1]) % 16:
                raise Unmodelled(f'{ins.va:#x}: misaligned {op}')
            self.setx(ops[0], self.x128(ops[1]))
        elif op == 'pcmpeqb':
            a, b = self.x128(ops[0]), self.x128(ops[1])
            self.setx(ops[0], sum(0xff << 8 * k for k in range(16) if a >> 8 * k & 0xff == b >> 8 * k & 0xff))
        elif op == 'pcmpeqd':
            a, b = self.x128(ops[0]), self.x128(ops[1])
            self.setx(ops[0], sum(0xffffffff << 32 * k for k in range(4)
                                  if a >> 32 * k & 0xffffffff == b >> 32 * k & 0xffffffff))
        elif op == 'pand':
            self.setx(ops[0], self.x128(ops[0]) & self.x128(ops[1]))
        elif op == 'punpcklbw':
            a, b = self.x128(ops[0]), self.x128(ops[1])
            self.setx(ops[0], sum((a >> 8 * k & 0xff) << 16 * k | (b >> 8 * k & 0xff) << (16 * k + 8) for k in range(8)))
        elif op == 'pshuflw':
            a, n = self.x128(ops[1]), ops[2][1] & 0xff
            lo = sum((a >> 16 * (n >> 2 * k & 3) & 0xffff) << 16 * k for k in range(4))
            self.setx(ops[0], a >> 64 << 64 | lo)
        elif op == 'pshufd':
            a, n = self.x128(ops[1]), ops[2][1] & 0xff
            self.setx(ops[0], sum((a >> 32 * (n >> 2 * k & 3) & 0xffffffff) << 32 * k for k in range(4)))
        elif op == 'pmovmskb':
            a = self.x128(ops[1])
            self.wr(ops[0], sum((a >> (8 * k + 7) & 1) << k for k in range(16)))
        elif op == 'mulsd':
            self.xmm[ops[0][1]][0] = f2b(b2f(self.xmm[ops[0][1]][0]) * b2f(self.xrd64(ops[1])))
        elif op == 'divsd':
            self.xmm[ops[0][1]][0] = f2b(fdiv(b2f(self.xmm[ops[0][1]][0]), b2f(self.xrd64(ops[1]))))
        elif op in ('maxsd', 'minsd'):
            a, b = b2f(self.xmm[ops[0][1]][0]), b2f(self.xrd64(ops[1]))
            keep = a > b if op == 'maxsd' else a < b
            if not keep:
                self.xmm[ops[0][1]][0] = f2b(b)
        elif op == 'ucomisd':
            a, b = b2f(self.xmm[ops[0][1]][0]), b2f(self.xrd64(ops[1]))
            un = math.isnan(a) or math.isnan(b)
            self.zf = un or a == b
            self.pf = un
            self.cf = un or a < b
            self.of = self.sf = False
        elif op == 'cvttsd2si':
            x = b2f(self.xrd64(ops[1]))
            big = math.isnan(x) or math.isinf(x) or not -(2.0 ** 63) <= x < 2.0 ** 63
            self.wr(ops[0], 1 << 63 if big else int(x) & U64)
        else:
            raise Unmodelled(f'{ins.va:#x}: {op}')

    def clobber(self, ret=None):
        """A stub keeps the callee-saved registers and spoils the rest."""
        for r in (R['rcx'], R['rdx'], R['rsi'], R['rdi'], R['r8'], R['r9'], R['r10'], R['r11']):
            self.regs[r] = 0xdead_0000_0000 + r
        self.regs[0] = ret if ret is not None else 0xdead_0000_0000
        for x in self.xmm:
            x[0], x[1] = 0x7ff8dead00000000, 0x7ff8dead00000000

    def call(self, ins):
        o = ins.ops[0]
        target = o[1] if o[0] == 't' else self.rd(o) if o[0] == 'r' else self.slots[self.ea(o)]
        if target in self.real:
            self.regs[4] -= 8
            self.store(self.regs[4], 8, ins.va + ins.size)
            self.run(self.real[target])
            self.cur = ins.va
            return
        stub = self.stubs.get(target)
        if stub is None:
            raise Unmodelled(f'{ins.va:#x}: call {target:#x}')
        stub()

    def run(self, entry, limit=400000):
        rip = entry
        for _ in range(limit):
            ins = self.code.get(rip)
            if ins is None:
                raise Unmodelled(f'no instruction at {rip:#x}')
            if rip in self.hooks:
                self.hooks[rip]()
            self.seen.add(rip)
            self.cur = rip
            nxt = rip + ins.size
            op, ops = ins.op, ins.ops
            if op == 'mov':
                self.wr(ops[0], self.rd(ops[1]))
            elif op in ('add', 'adc', 'sub', 'sbb', 'cmp', 'and', 'or', 'xor'):
                self.alu(op, ins)
            elif op == 'test':
                res = self.rd(ops[0]) & self.rd(ops[1])
                self.cf = self.of = False
                self.nz(res, ins.width)
            elif op[0] == 'j' and op not in ('jmp', 'jmpr'):
                go = self.cond(op[1:])
                self.taken.setdefault(rip, set()).add(go)
                if go:
                    nxt = ops[0][1]
            elif op == 'jmp':
                nxt = ops[0][1]
            elif op == 'jmpr':
                nxt = self.rd(ops[0])
            elif op == 'ud2':
                raise Unmodelled(f'{rip:#x}: ud2 reached')
            elif op.startswith('cmov'):
                val = self.rd(ops[1])
                if self.cond(op[4:]):
                    self.wr(ops[0], val)
                elif ins.width == 32:
                    self.wr(ops[0], self.rd(ops[0]))
            elif op.startswith('set'):
                self.wr(ops[0], int(self.cond(op[3:])))
            elif op == 'lea':
                self.wr(ops[0], self.ea(ops[1]))
            elif op == 'movzx':
                self.wr(ops[0], self.rd(ops[1]))
            elif op == 'push':
                self.regs[4] -= 8
                self.store(self.regs[4], 8, self.rd(ops[0]))
            elif op == 'pop':
                self.wr(ops[0], self.load(self.regs[4], 8))
                self.regs[4] += 8
            elif op == 'ret':
                self.regs[4] += 8
                return
            elif op == 'nop':
                pass
            elif op == 'mul':
                bits = ins.width
                full = self.rd(ops[0]) * (self.regs[0] & ((1 << bits) - 1))
                self.regs[0] = full & U64
                self.regs[2] = full >> 64
                self.cf = self.of = self.regs[2] != 0
            elif op == 'imul':
                v = signed(self.rd(ops[1]), ins.width) * ops[2][1]
                self.wr(ops[0], v)
                self.cf = self.of = v != signed(v & ((1 << ins.width) - 1), ins.width)
            elif op == 'imul1':
                full = signed(self.rd(ops[0]), 64) * signed(self.regs[0], 64)
                self.regs[0] = full & U64
                self.regs[2] = (full >> 64) & U64
                self.cf = self.of = full != signed(full & U64, 64)
            elif op == 'not':
                self.wr(ops[0], ~self.rd(ops[0]))
            elif op == 'cdqe':
                self.regs[0] = signed(self.regs[0] & 0xffffffff, 32) & U64
            elif op == 'cqo':
                self.regs[2] = U64 if self.regs[0] >> 63 else 0
            elif op == 'cdq':
                self.regs[2] = 0xffffffff if self.regs[0] >> 31 & 1 else 0
            elif op == 'neg':
                a = self.rd(ops[0])
                res = -a & ((1 << ins.width) - 1)
                self.cf = a != 0
                self.of = a == 1 << (ins.width - 1)
                self.nz(res, ins.width)
                self.wr(ops[0], res)
            elif op == 'movsxd':
                self.wr(ops[0], signed(self.rd(ops[1]), 32))
            elif op in ('inc', 'dec'):
                a = self.rd(ops[0])
                res = (a + (1 if op == 'inc' else -1)) & ((1 << ins.width) - 1)
                self.of = a == ((1 << (ins.width - 1)) - 1 if op == 'inc' else 1 << (ins.width - 1))
                self.nz(res, ins.width)
                self.wr(ops[0], res)
            elif op in ('shl', 'shr', 'sar'):
                n = ops[1][1] & 63
                a = self.rd(ops[0])
                if op == 'sar':
                    res = (signed(a, ins.width) >> n) & ((1 << ins.width) - 1)
                else:
                    res = (a << n if op == 'shl' else a >> n) & ((1 << ins.width) - 1)
                self.nz(res, ins.width)
                self.wr(ops[0], res)
            elif op == 'call':
                self.call(ins)
            elif op == 'cmpxchg':
                if self.race is not None:
                    self.store(self.ea(ops[0]), 8, self.race)
                    self.race = None
                cur = self.rd(ops[0])
                self.zf = cur == self.regs[0]
                if self.zf:
                    self.wr(ops[0], self.rd(ops[1]))
                else:
                    self.regs[0] = cur
            elif op == 'tzcnt':
                a = self.rd(ops[1])
                res = (a & -a).bit_length() - 1 if a else ins.width
                self.cf, self.zf = a == 0, res == 0
                self.wr(ops[0], res)
            else:
                self.do_sse(ins)
            rip = nxt
        raise Unmodelled('step limit')


PERP, SPOT, RATES, DISCOUNT, WINDOW = 0x37130b0, 0x3742460, 0x3743df0, 0x3743020, 0x3742070
DECODED = (PERP, SPOT, RATES, DISCOUNT, WINDOW)
HASH, RECORD, PANIC_LOC, PANIC_UNWRAP = 0x399c7a0, 0x358dcd0, 0x157a9f0, 0x157aa10
SLOTS = {0x5773190: RECORD, 0x576e470: PANIC_LOC, 0x576e048: PANIC_UNWRAP, 0x5774890: PERP,
         0x57748f8: RATES, 0x5774ef8: DISCOUNT}
LOC_TOTAL, LOC_NET_A, LOC_NET_B, LOC_SUM = 0x56f1de8, 0x56f1cf8, 0x57145c0, 0x56f2138
LOC_ASSET, LOC_UNWRAP, LOC_EMPTY_A = 0x56f21c0, 0x56f1ce0, 0x56e9fe8
SCALE_TABLE = 0x204350
FF_ADDR, FE_ADDR = b'\xff' * 20, b'\xfe' * 20
WINDOW_LIMIT = 100000000000
DISCOUNT_LIMIT = 2500000000
STRIDE = 0xe8
GROUPS = 32
NODE = 0x2d8
# Option None payload copies read stack words nobody set; only these eight loads may do that.
LOOSE = (0x3713c8f, 0x3713c9b, 0x3713cb4, 0x3713cbd, 0x3742f6b, 0x3742f77, 0x3742f90, 0x3742f9b)
CONSTANTS = (('half', 0x20a940), ('one', 0x20a730), ('scale_second', SCALE_TABLE + 8), ('hundred_thousand', 0x20a9e8), ('five', 0x20a890))
IMMEDIATES = ((PERP, 0x3713940, 'window limit'), (SPOT, 0x3742b1e, 'window limit'), (DISCOUNT, 0x3743378, 'discount limit'))
UNEXECUTED = (
    (0x37135bf, 0x37135c3, 'builder +inf or NaN arm: a finite u64 / 100000 times a finite i64 is finite'),
    (0x374297b, 0x374297f, 'the same arm in the spot copy'),
    (0x3713d35, 0x3713d84, 'referrer net overflow recorder: fee > 0 and amount >= 0, so fee - amount cannot overflow'),
    (0x3742fd5, 0x3742ff4, 'the same recorder in the spot copy'),
    (0x37433a2, 0x37433b3, 'ud2 and the None unwrap of the first item: root null never enters the walk'),
    (0x3742442, 0x3742453, 'the same two in the window helper'),
)


COPY_START, COPY_END, COPY_BASE = 0x3711118, 0x371118d, 0x230
IMM_1E9 = bytes.fromhex('b900ca9a3b')
CLAMP = 'clamp before a conversion: cvttsd2si gives i64::MIN out of range and the next cmova gives i64::MAX, so the clamp changes nothing'
EQUIVALENT = {va: CLAMP for va in (0x371345f, 0x3713469, 0x37134d8, 0x37134e2, 0x3713583, 0x371358d, 0x37137a3, 0x37137b1, 0x3713aae,
                                   0x3713ab8, 0x3713c33, 0x3713c3d, 0x3742808, 0x3742812, 0x3742880, 0x374288a, 0x374295d, 0x3742967,
                                   0x3742d99, 0x3742da3, 0x3742ec6, 0x3742ed0)}
EQUIVALENT.update({
    0x3713c04: 'share 0 or a share from a zero or NaN sum: then fee and net are 0, and t of 0 times any share is 0',
    0x3713d35: 'inside the listed dead recorder of the referrer net',
    0x3713d4b: 'inside the listed dead recorder of the referrer net',
    0x3742529: 'both arms load the first rate and apply the same bucket and multiplier steps, so the value is the same',
    0x3742695: 'only reached with al and side both set, so the branch is never taken',
    0x374274d: 'both multiplier words are equal on this path, so both arms multiply by the same value',
})
REFERENCE_ROWS = (
    ('not found', 'l1/fees/compute.rs', 'side fields are read as inputs; no producer', 'perp 0x37130b0 and spot 0x3742460 compute them'),
    ('supported', 'l1/fees/compute.rs TradeSideFeeInfo', 'primary_recipient with a recipient and an amount', 'side +0x58 tag, +0x60 amount, +0x68 address are output +0x00, +0x08, +0x10: the referrer'),
    ('supported', 'l1/fees/compute.rs TradeSideFeeInfo', 'secondary_recipient with a recipient and an amount', 'side +0x80 tag, +0x88 amount, +0x90 address are output +0x28, +0x30, +0x38: the builder'),
    ('differs', 'l1/fees/compute.rs TradeSideFeeInfo', 'protocol_component at the third amount', 'that word is output +0x60, the excess of the previous rates over the current rates; the deployer and remainder words are +0x68 and +0x70'),
    ('differs', 'l1/exchange/handlers/55_start_fee_trial.rs FeeTrialRuntime', 'records_by_user is a BTreeMap', 'read from one hash table of 0xe8-byte buckets that also holds the referrer binding and the window map'),
    ('supported', 'l1/exchange/handlers/55_start_fee_trial.rs FeeTrialRecord', 'effective_rates, volume_anchor, requested_rates, previous_rates, trial_end_day, carried_discount_multiplier', 'row words +0x00, +0x20, +0x28, +0x48, +0x68 (u32), +0x70 in that order; requested rates at +0x28 are not read here'),
    ('supported', 'l1/exchange/handlers/55_start_fee_trial.rs resolve_volume_discount', 'last tier with min_volume_anchor <= anchor', 'the scan over ctx +0x38/+0x40 16-byte rows gives the same row'),
    ('differs', 'l1/exchange/handlers/55_start_fee_trial.rs FeeRates', 'the active flag is one bool', 'the row reader tests the low byte of the tag, the window helper compares the 32-bit word with 1'),
    ('differs', 'l1/exchange/handlers/55_start_fee_trial.rs FeeTrialDefaults', 'defaults carry volume_anchor and carried_discount_multiplier', 'the default row writes constants 0.0 and 1.0; ctx +0x68 and +0x70 are the discount and the fixed share'),
    ('supported', 'l1/exchange/handlers/25_set_referrer.rs UserReferrerBinding', 'user to referrer binding in an address hash table', 'flag at bucket end -0x1c, 20-byte referrer at bucket end -0x1b'),
    ('not found', 'references/can1357-hl/l1', 'no deployer split, no 0.5 cap, no 1e11 or 2.5e9 limit in a fee path', 'all three are in the bytes'),
)


class Panic(Exception):
    pass


def to_i64(x):
    """The repeated conversion: NaN and both infinities give 0, otherwise truncate and saturate."""
    if x != x or x in (math.inf, -math.inf):
        return 0
    if x <= -(2.0 ** 63):
        return -(1 << 63)
    if x >= 2.0 ** 63:
        return (1 << 63) - 1
    return int(x)


def fmax(a, b):
    """maxsd a, b: the second operand unless a > b."""
    return a if a > b else b


def fmin(a, b):
    return a if a < b else b


def key_hash(key):
    return int.from_bytes(hashlib.sha256(key).digest()[:8], 'little')


def addr(n):
    """A 20-byte test address."""
    return hashlib.sha256(b'addr' + str(n).encode()).digest()[:20]


# ---- closed-form model, written from the semantics and independent of the machine


class Row:
    def __init__(self, v):
        self.v = v
        self.f = v['ctx']
        self.hashes = []
        self.records = []

    def live(self):
        return self.f['entries_on'] and (self.v['entries'] or self.v.get('decoys'))

    def entry(self, who):
        if not self.live():
            return None
        self.hashes.append(who)
        return self.v['entries'].get(who)

    def rates(self, who):
        """0x3743df0: (first pairs, key, flag, second pairs)."""
        if who in (FF_ADDR, FE_ADDR):
            return dict(p=(0.0, 0.0), s=(0.0, 0.0), key=0.0, d=0, p2=None, s2=None)
        f = self.f
        e = self.entry(who)
        if e is None or not e['tag'] & 0xff:
            return dict(p=f['base'][:2], s=f['base'][2:], key=0.0, d=0, p2=None, s2=None)
        return dict(p=e['rates'][:2], s=e['rates'][2:], key=e['key'], d=e['d'], p2=e['over'][:2] if e['d'] else None,
                    s2=e['over'][2:] if e['d'] else None)

    def window_sum(self, e):
        """In-order sum of the first `len` map values, saturating, one record per overflow."""
        total = 0
        claim = e.get('claim', len(e['values']))
        if not e['values'] and not e.get('rooted'):
            return 0
        for i in range(claim):
            if i >= len(e['values']):
                raise Panic('tree_end')
            total += e['values'][i]
            if total > U64:
                total = U64
                self.records.append(LOC_SUM)
        return total

    def discount(self, who):
        """0x3743020."""
        e = self.entry(who)
        if e is None or e['flag'] != 1:
            return 0.0
        return self.f['discount'] if self.window_sum(e) < DISCOUNT_LIMIT else 0.0

    def window(self, who):
        """0x3742070: (sum, key, weight)."""
        e = self.entry(who)
        if e is None:
            return 0, 0.0, 1.0
        total = self.window_sum(e)
        return (total, e['key'], e['w70']) if e['tag'] == 1 else (total, 0.0, 1.0)

    def step(self, k):
        """Value of the last row whose threshold is not above k, scanning up from the second row."""
        t = self.f['table']
        i = 1
        while i < len(t) and not t[i][0] > k:
            i += 1
        return t[i - 1][1]

    def below_first(self, k):
        t = self.f['table']
        return not t or t[0][0] > k


def legs(row, v, rate, full, user):
    """One rate through the deployer scale, the asset scale, the trial multiplier and the discount."""
    x, f = v['x_used'], row.f
    u = row.scale[0 if full else 1]
    if 0.0 > rate:
        s = fmin(fdiv(x, x + 1.0), 0.5)
        a, b = s * rate, (1.0 - s) * rate
        m = 1.0
        if v['trial']:
            m = f['f90'] if v['b4c'] else f['f98']
    else:
        a, b = x * rate, fmax(x, 1.0) * rate
        m = f['f90'] if v['trial'] and v['b4c'] else 1.0
    p = m * b * u
    a = a * u
    if not (0.0 > a) and not (0.0 > p):
        d = row.discount(user)
        a, p = a * (1.0 - d), p * (1.0 - d)
    return a, p


def builder_part(v, ntli, gross, row):
    tenths, _ = v['builder']
    b = max(to_i64(float(tenths) / 100000.0 * float(ntli)), 0)
    total = b + gross
    if total > U64:
        row.records.append(LOC_TOTAL)
        total = U64
    return b, total


def referrer_share(row, v, entry, user, flag):
    total, key, weight = row.window(user)
    if total >= WINDOW_LIMIT:
        return 0.0
    if flag:
        return row.f['share']
    k = row.rates(entry['referrer'])['key']
    if row.below_first(k):
        return 0.0
    top = row.step(k)
    if not top > 0.0:
        return 0.0
    low = 0.0 if row.below_first(key) else row.step(key)
    return fmax(weight * (top - low), 0.0)


def builder_gain(row, v, user, baddr, fee):
    """The builder tier path; 0 when it adds nothing."""
    k = row.rates(baddr)['key']
    if row.below_first(k):
        return 0
    top = row.step(k)
    if top == 0.0:
        return 0
    _, key, weight = row.window(user)
    low = 0.0 if row.below_first(key) else row.step(key)
    return max(to_i64(float(fee) * (weight * fmax(top - low, 0.0))), 0)


def referral(row, v, user, fee, flag):
    """(referrer, amount) or None."""
    if not row.live():
        return None
    e = row.entry(user)
    if e is None or not e['flag'] & 1:
        return None
    return e['referrer'], max(to_i64(float(fee) * referrer_share(row, v, e, user, flag)), 0)


def perp_model(v, scale):
    row = Row(v)
    row.scale = scale
    x = 0.0 if v['dep_tag'] == 3 else v['x']
    v = dict(v, x_used=x)
    asset, dex = v['asset'] // 10000, v['asset'] % 10000
    if asset != v['dex'] or dex >= v['assets']:
        return dict(exit='panic_asset', records=[], hashes=[])
    user = v['user']
    full = v['full'] != 0
    pick = 0 if v['b4c'] else 1
    r = row.rates(user)
    a1 = p1 = None
    if r['d']:
        a1, p1 = legs(row, v, r['p2'][pick], full, user)
    a2, p2 = legs(row, v, r['p'][pick], full, user)
    ntli = v['ntli']
    if ntli < 0:
        return dict(exit='panic_neg', records=row.records, hashes=row.hashes)
    n = float(ntli)
    rate = p2 + a2
    fee = to_i64(rate * n)
    gross = max(fee, 0)
    extra = 0
    if r['d']:
        extra = max(to_i64(fmax(p1 + a1 - rate, 0.0) * n), 0)
    gross += extra
    bamt, btag = None, 0
    total = gross
    if v['builder']:
        btag = 1
        bamt, total = builder_part(v, ntli, gross, row)
    net, tag, ref, referrer = fee, 0, None, None
    done = fee <= 0
    if not done and v['builder'] and not v['flag']:
        g = builder_gain(row, v, user, v['builder'][1], fee)
        if g > 0:
            net = fee - g
            bamt += g
            done = True
    if not done:
        got = referral(row, v, user, fee, v['flag'])
        if got:
            referrer, ref = got
            net = fee - ref
            tag = 1
    share = fdiv(a2, rate) if rate != 0.0 else 0.0
    dep = to_i64(float(net) * share)
    prot = net - dep
    if prot > (1 << 63) - 1 or prot < -(1 << 63):
        row.records.append(LOC_NET_B)
        prot = (1 << 63) - 1 if prot > 0 else -(1 << 63)
    return dict(exit='ok', records=row.records, hashes=row.hashes, tag=tag, ref=ref, referrer=referrer, btag=btag,
                bamt=bamt, baddr=v['builder'][1] if v['builder'] else None, gross=total, rebate=-fee if fee <= 0 else 0,
                extra=extra, deployer=dep, protocol=prot)


def spot_rate(row, v, base, second, user):
    """One spot rate: bucket scale, trial multiplier by sign, discount on a positive result."""
    cat, f = v['cat'], row.f
    if cat == 0:
        y = base
    elif (cat == 1) if second else (cat != 2):
        y = base / 5.0
    else:
        y = fmax(base, 0.0) * v['weight']
    tk, al = v['tk'], v['al']
    m1 = f['f90'] if al and tk else 1.0
    m2 = f['f98'] if al and not tk else m1
    y *= m2 if y < 0.0 else m1
    if y > 0.0:
        y *= 1.0 - row.discount(user)
    return y


def spot_model(v):
    row = Row(v)
    user = v['user']
    pick = 0 if v['tk'] else 1
    r = row.rates(user)
    s = spot_rate(row, v, r['s2'][pick], True, user) if r['d'] else None
    if r['d'] and not v['bpl']:
        p = s
    else:
        p = spot_rate(row, v, r['s'][pick], False, user)
    ntli = v['ntli']
    if ntli < 0:
        return dict(exit='panic_neg', records=row.records, hashes=row.hashes)
    n = float(ntli)
    fee = to_i64(p * n)
    gross = max(fee, 0)
    rebate = -fee if fee <= 0 else 0
    if not v['bpl']:
        return dict(exit='ok', records=row.records, hashes=row.hashes, tag=0, ref=None, referrer=None, btag=0,
                    bamt=None, baddr=None, gross=gross, rebate=rebate, extra=0)
    extra = max(to_i64(fmax(s - p, 0.0) * n), 0) if r['d'] else 0
    gross += extra
    bamt, btag, total = None, 0, gross
    if v['builder']:
        btag = 1
        bamt, total = builder_part(v, ntli, gross, row)
    tag, ref, referrer = 0, None, None
    done = fee <= 0
    if not done and v['builder'] and not v['flag']:
        g = builder_gain(row, v, user, v['builder'][1], fee)
        if g > 0:
            bamt += g
            done = True
    if not done:
        got = referral(row, v, user, fee, v['flag'])
        if got:
            referrer, ref = got
            tag = 1
    return dict(exit='ok', records=row.records, hashes=row.hashes, tag=tag, ref=ref, referrer=referrer, btag=btag,
                bamt=bamt, baddr=v['builder'][1] if v['builder'] else None, gross=total, rebate=rebate, extra=extra)


# ---- scenario memory


def put(m, a, off, size, val):
    m.store(a.base + off, size, val)


def put_f(m, a, off, x):
    m.store(a.base + off, 8, f2b(x))


def put_bytes(m, a, off, raw):
    for i, b in enumerate(raw):
        m.store(a.base + off + i, 1, b)


def build_tree(m, values, height, leaf=11):
    """A B-tree shape: value words at node + 0x30*i, parent +0x210, parent index +0x270, length +0x272,
    children +0x278.  Only the first `len(values)` in-order items are ever walked, so the tree is built
    lazily: a tall spine with a few items stands for a full tree of that height."""
    nodes, left = [], list(values)

    def node(level, parent, pidx):
        i = len(nodes)
        nodes.append(dict(level=level, parent=parent, pidx=pidx, vals=[], kids=[]))
        n = nodes[i]
        if level == 0:
            take = min(len(left), leaf)
            n['vals'] = [left.pop(0) for _ in range(take)] or [None]
            return i
        n['kids'].append(node(level - 1, i, 0))
        while True:
            n['vals'].append(left.pop(0) if left else None)
            n['kids'].append(node(level - 1, i, len(n['kids'])))
            if not left or len(n['vals']) == leaf:
                break
        return i

    root = node(height, None, 0)
    a = m.arena(NODE * len(nodes) + 16)
    va = [a.base + 8 + i * NODE for i in range(len(nodes))]
    for i, n in enumerate(nodes):
        b = va[i]
        for j, x in enumerate(n['vals']):
            if x is not None:
                m.store(b + 0x30 * j, 8, x)
        m.store(b + 0x210, 8, 0 if n['parent'] is None else va[n['parent']])
        m.store(b + 0x270, 2, n['pidx'])
        m.store(b + 0x272, 2, len(n['vals']))
        for j, k in enumerate(n['kids']):
            m.store(b + 0x278 + 8 * j, 8, va[k])
    return va[root]


def build_table(m, entries, decoys):
    """A hashbrown table of 32 buckets: control bytes after the bucket area, 0xe8-byte buckets below."""
    a = m.arena(STRIDE * GROUPS + GROUPS + 16 + 32)
    ctrl_off = STRIDE * GROUPS + 16
    ctrl = [0xff] * GROUPS
    keys = {}

    def place(key):
        h = key_hash(key)
        pos = h & (GROUPS - 1)
        while True:
            for k in range(16):
                i = (pos + k) & (GROUPS - 1)
                if ctrl[i] == 0xff:
                    ctrl[i] = h >> 57
                    return i
            pos += 16

    for k in decoys:
        i = place(k)
        put_bytes(m, a, ctrl_off - (i + 1) * STRIDE, k)
    for k, e in entries.items():
        i = place(k)
        keys[k] = i
        end = ctrl_off - i * STRIDE
        put_bytes(m, a, end - STRIDE, k)
        put(m, a, end - 0xd0, 4, e['tag'])
        if e['tag'] & 0xff:
            for j, x in enumerate(e['rates']):
                put_f(m, a, end - 0xc8 + 8 * j, x)
            put_f(m, a, end - 0xa8, e['key'])
            put(m, a, end - 0x60, 4, e['d'])
            put_f(m, a, end - 0x58, e['w70'])
            if e['d']:
                for j in range(4):
                    put_f(m, a, end - 0xa0 + 8 * j, 0.0)
                for j, x in enumerate(e['over']):
                    put_f(m, a, end - 0x80 + 8 * j, x)
        put(m, a, end - 0x1c, 1, e['flag'])
        if e['flag'] & 1:
            put_bytes(m, a, end - 0x1b, e['referrer'])
        if e['values'] or e.get('height') or e.get('rooted'):
            put(m, a, end - 0x38, 8, build_tree(m, e['values'], e.get('height', 0), e.get('leaf', 11)))
            put(m, a, end - 0x30, 8, e.get('height', 0))
        else:
            put(m, a, end - 0x38, 8, 0)
        put(m, a, end - 0x28, 8, e.get('claim', len(e['values'])))
    for i in range(GROUPS + 16):
        put(m, a, ctrl_off + i, 1, ctrl[i % GROUPS])
    return a.base + ctrl_off


def build_ctx(m, v):
    f = v['ctx']
    a = m.arena(0x100)
    t = f['table']
    ta = m.arena(max(16 * len(t), 8))
    for i, (x, y) in enumerate(t):
        put_f(m, ta, 16 * i, x)
        put_f(m, ta, 16 * i + 8, y)
    put(m, a, 0x38, 8, ta.base)
    put(m, a, 0x40, 8, len(t))
    for i, x in enumerate(f['base']):
        put_f(m, a, 0x48 + 8 * i, x)
    put_f(m, a, 0x68, f['discount'])
    put_f(m, a, 0x70, f['share'])
    put_f(m, a, 0x90, f['f90'])
    put_f(m, a, 0x98, f['f98'])
    put(m, a, 0xd8, 8, len(v['entries']) + len(v.get('decoys', ())) if f['entries_on'] else 0)
    if f['entries_on']:
        put(m, a, 0xc0, 8, build_table(m, v['entries'], v.get('decoys', ())))
        put(m, a, 0xc8, 8, GROUPS - 1)
    return a


def machine(img, code):
    m = Machine(img, ())
    m.code = code
    m.loose = LOOSE
    for t in DECODED:
        m.real[t] = t
    m.log = []
    m.hashes = []
    return m


def install(m, ctx_base):
    def do_hash():
        if m.regs[R['rdi']] != ctx_base + 0xe0:
            raise Unmodelled('hash of another table')
        key = bytes(m.load(m.regs[R['rsi']] + i, 1) for i in range(20))
        m.hashes.append(key)
        m.clobber(key_hash(key))

    def record():
        if m.regs[R['rdi']] != 0:
            raise Unmodelled('recorder first argument')
        m.log.append(m.regs[R['rsi']])
        m.clobber()

    def panic_loc():
        raise Panic(('loc', m.regs[R['rdi']]))

    def panic_unwrap():
        raise Panic(('unwrap', m.regs[R['r8']], m.regs[R['rsi']]))

    m.stubs[HASH] = do_hash
    m.stubs[RECORD] = record
    m.stubs[PANIC_LOC] = panic_loc
    m.stubs[PANIC_UNWRAP] = panic_unwrap


def relocated_calls(m):
    """Call through a slot: the operand is memory holding the target, resolved from .rela.dyn."""
    m.slots = dict(SLOTS)


def run_fee(img, code, v):
    m = machine(img, code)
    relocated_calls(m)
    stack = m.arena(0x4000)
    top = stack.base + 0x3f08
    ctx = build_ctx(m, v)
    install(m, ctx.base)
    out = m.arena(0x80)
    rec = m.arena(0x100)
    tenths, baddr = v['builder'] if v['builder'] else (None, None)
    put(m, rec, 0, 8, 1 if v['builder'] else 0)
    if v['builder']:
        put(m, rec, 8, 8, tenths)
        put_bytes(m, rec, 0x10, baddr)
    else:
        put(m, rec, 8, 8, 0)
        put_bytes(m, rec, 0x10, b'\0' * 20)
    if v['side'] == 'perp':
        st = m.arena(0x240)
        assets = m.arena(48 * max(v['assets'], 1))
        dep = m.arena(0x80)
        put(m, st, 0x08, 8, assets.base)
        put(m, st, 0x10, 8, v['assets'])
        put(m, st, 0x30, 8, v['dex'])
        put(m, st, 0x58, 1, v['trial'])
        put(m, st, 0x208, 8, dep.base)
        put(m, st, 0x230, 1, v['dep_tag'])
        put_f(m, dep, 0x60, v['x'])
        for i in range(v['assets']):
            put(m, assets, 48 * i + 0x29, 1, v['full'])
        put(m, rec, 0x28, 8, ctx.base)
        put(m, rec, 0x30, 8, v['asset'])
        put_bytes(m, rec, 0x38, v['user'])
        put(m, rec, 0x4c, 1, v['b4c'])
        put(m, rec, 0x4e, 1, v['flag'])
        args = (st.base, rec.base, v['ntli'] & U64)
        entry = PERP
    else:
        put_f(m, rec, 0x28, v['weight'])
        put(m, rec, 0x30, 1, v['cat'])
        put(m, rec, 0x31, 1, v['bpl'])
        put(m, rec, 0x38, 8, v['ntli'] & U64)
        put_bytes(m, rec, 0x40, v['user'])
        put(m, rec, 0x54, 1, v['tk'])
        put(m, rec, 0x55, 1, v['al'])
        put(m, rec, 0x56, 1, v['flag'])
        args = (ctx.base, rec.base, 0xdead)
        entry = SPOT
    m.regs[R['rsp']] = top
    m.store(top, 8, 0xfeedface)
    m.regs[R['rdi']] = out.base
    m.regs[R['rsi']] = args[0]
    m.regs[R['rdx']] = args[1]
    m.regs[R['rcx']] = args[2]
    for r in ('rbx', 'rbp', 'r12', 'r13', 'r14', 'r15'):
        m.regs[R[r]] = 0xc0de0000 + R[r]
    try:
        m.run(entry)
        res = dict(exit='ok', out=out, m=m)
    except Panic as exc:
        how = exc.args[0]
        names = {('loc', LOC_ASSET): 'panic_asset', ('loc', LOC_EMPTY_A): 'panic_tree_end'}
        res = dict(exit='panic_neg' if how[0] == 'unwrap' else names.get(how, 'panic'), how=how, m=m)
    return m, res


def model(v, scale):
    try:
        return perp_model(v, scale) if v['side'] == 'perp' else spot_model(v)
    except Panic as exc:
        return dict(exit='panic_' + exc.args[0], records=None, hashes=None)


def compare(m, res, want):
    """Empty when the machine and the model agree on every defined word."""
    if res['exit'] != want['exit']:
        return f"exit {res['exit']} != {want['exit']}"
    if want['records'] is None:
        return ''
    if m.log != want['records']:
        return f"records {[hex(x) for x in m.log]} != {[hex(x) for x in want['records']]}"
    if m.hashes != want['hashes']:
        return 'hash key sequence'
    if want['exit'] != 'ok':
        return ''
    base = res['out'].base

    def word(off):
        return m.load(base + off, 8)

    bad = []

    def check(name, off, value):
        if word(off) != value & U64:
            bad.append(f'{name} {word(off):#x} != {value & U64:#x}')

    check('tag', 0, want['tag'])
    check('btag', 0x28, want['btag'])
    check('gross', 0x50, want['gross'])
    check('rebate', 0x58, want['rebate'])
    check('extra', 0x60, want['extra'])
    if want['tag']:
        check('ref', 8, want['ref'])
        got = bytes(m.load(base + 0x10 + i, 1) for i in range(20))
        if got != want['referrer']:
            bad.append('referrer')
    if want['btag']:
        check('bamt', 0x30, want['bamt'])
        got = bytes(m.load(base + 0x38 + i, 1) for i in range(20))
        if got != want['baddr']:
            bad.append('baddr')
    if 'deployer' in want:
        check('deployer', 0x68, want['deployer'])
        check('protocol', 0x70, want['protocol'])
    for r in ('rbx', 'rbp', 'r12', 'r13', 'r14', 'r15'):
        if m.regs[R[r]] != 0xc0de0000 + R[r]:
            bad.append(f'callee saved {r}')
    return '; '.join(bad)


# ---- vectors


class Lcg:
    def __init__(self, seed):
        self.s = seed

    def next(self):
        self.s = (self.s * 6364136223846793005 + 1442695040888963407) & U64
        return self.s >> 16

    def pick(self, seq):
        return seq[self.next() % len(seq)]


RATE_PICKS = (0.0, 1e-4, 3.5e-4, 7e-4, -1e-5, -3e-5, 2e-4, 1.5e-3, -2e-4, 5e-3, 1e-2)
X_PICKS = (0.0, 0.25, 0.5, 1.0, 1.5, 2.0, 3.0, 0.999, 1e-3)
NTLI_PICKS = (0, 1, 999, 1000, 10 ** 6, 123456789, 10 ** 9, 10 ** 12, 10 ** 15, 10 ** 18, (1 << 63) - 1, 12345678901)
TENTHS = (0, 1, 10, 100, 1000, 12345, 100000, 10 ** 6)
SUMS = (0, 1, 999, DISCOUNT_LIMIT - 1, DISCOUNT_LIMIT, DISCOUNT_LIMIT + 1, WINDOW_LIMIT - 1, WINDOW_LIMIT, WINDOW_LIMIT + 1)
TABLES = ((), ((0.0, 0.1),), ((0.0, 0.0), (10.0, 0.1), (100.0, 0.2), (1000.0, 0.3)), ((5.0, 0.05), (50.0, 0.0), (500.0, 0.4)),
          ((0.0, 0.05), (10.0, 0.1), (10.0, 0.15), (1e6, 0.5)))
KEYS = (0.0, 1.0, 5.0, 9.0, 10.0, 50.0, 99.0, 100.0, 500.0, 1000.0, 1e7)
WEIGHTS = (0.0, 0.5, 1.0, 1.5)


def ctx_row(rng, entries_on=True):
    return dict(entries_on=entries_on, table=rng.pick(TABLES), base=tuple(rng.pick(RATE_PICKS) for _ in range(4)),
                discount=rng.pick((0.0, 0.04, 0.1, 0.25)), share=rng.pick((0.0, 0.1, 0.05)),
                f90=rng.pick((1.0, 0.5, 0.25, 0.0)), f98=rng.pick((1.0, 2.0, 0.5)))


def entry_row(rng, referrer=None):
    tag = rng.pick((0, 1, 1, 1, 2, 0x100))
    d = rng.pick((0, 0, 1, 5))
    n = rng.pick((0, 1, 2, 3, 11, 14))
    total = rng.pick(SUMS)
    values = []
    if n:
        values = [total // n] * n
        values[0] += total - sum(values)
    return dict(tag=tag, rates=tuple(rng.pick(RATE_PICKS) for _ in range(4)), key=rng.pick(KEYS), d=d,
                over=tuple(rng.pick(RATE_PICKS) for _ in range(4)), w70=rng.pick(WEIGHTS), flag=rng.pick((0, 1, 1, 2, 3)),
                referrer=referrer or addr(rng.next() % 5 + 100), values=values, height=1 if n > 11 else 0)


def base_vector(rng, side, group):
    user, referrer, b = addr(1), addr(2), addr(3)
    entries = {}
    if rng.next() % 8:
        entries[user] = entry_row(rng, referrer)
    if rng.next() % 3:
        entries[referrer] = entry_row(rng)
    if rng.next() % 3:
        entries[b] = entry_row(rng)
    v = dict(group=group, side=side, user=user, ntli=rng.pick(NTLI_PICKS), flag=rng.next() % 2,
             builder=(rng.pick(TENTHS), b) if rng.next() % 2 else None, ctx=ctx_row(rng, bool(rng.next() % 8)),
             entries=entries)
    if side == 'perp':
        dex, loc = rng.pick((0, 1, 2)), rng.pick((0, 3, 7))
        v.update(dex=dex, assets=8, asset=dex * 10000 + loc, full=rng.pick((0, 1, 1)), trial=rng.pick((0, 0, 1)),
                 dep_tag=rng.pick((0, 3)), x=rng.pick(X_PICKS), b4c=rng.next() % 2)
    else:
        v.update(cat=rng.pick((0, 1, 2, 3)), weight=rng.pick((0.0, 0.5, 1.0, 2.0)), bpl=rng.pick((0, 1, 1)), tk=rng.next() % 2,
                 al=rng.next() % 2)
    return v


def edge_vectors(side):
    rng = Lcg(0xed6e if side == 'perp' else 0xed70)
    out = []
    for i in range(400):
        out.append(base_vector(rng, side, 'random'))
    for tweak, group in (
        (lambda v: v.update(user=FF_ADDR), 'system_ff'),
        (lambda v: v.update(user=FE_ADDR), 'system_fe'),
        (lambda v: v.update(ntli=-1), 'negative'),
        (lambda v: v.update(ntli=-(1 << 63)), 'negative'),
        (lambda v: v.update(builder=(U64, addr(3)), ntli=(1 << 63) - 1), 'builder_saturate'),
        (lambda v: v.update(builder=(1 << 63, addr(3)), ntli=10 ** 18), 'builder_big'),
    ):
        for i in range(24):
            v = base_vector(rng, side, group)
            tweak(v)
            out.append(v)
    return out


def scale_of(img):
    return struct.unpack('<2d', img.read(SCALE_TABLE, 16))


def perp_groups():
    """Directed cases, one path each, with a fee large enough to round well."""
    out = []
    user, referrer, b = addr(1), addr(2), addr(3)

    def v0(**kw):
        ctx = dict(entries_on=True, table=((0.0, 0.05), (10.0, 0.1), (100.0, 0.2)), base=(7e-4, 2e-4, 3e-4, 1e-4), discount=0.04,
                   share=0.1, f90=0.5, f98=2.0)
        ctx.update(kw.pop('ctx', {}))
        v = dict(side='perp', group=kw.pop('group'), user=user, ntli=10 ** 12, flag=0, builder=None, ctx=ctx, entries={},
                 dex=0, assets=8, asset=3, full=1, trial=0, dep_tag=0, x=0.0, b4c=1)
        v.update(kw)
        return v

    def e(**kw):
        d = dict(tag=1, rates=(7e-4, 2e-4, 3e-4, 1e-4), key=0.0, d=0, over=(1e-3, 5e-4, 2e-3, 1e-3), w70=1.0, flag=1,
                 referrer=referrer, values=[1000], height=0)
        d.update(kw)
        return d

    out.append(v0(group='plain'))
    out.append(v0(group='plain', b4c=0))
    out.append(v0(group='plain', ctx=dict(entries_on=False)))
    out.append(v0(group='asset_panic', asset=10003))
    out.append(v0(group='asset_panic', asset=8))
    out.append(v0(group='asset_panic', asset=2 * 10000 + 3, dex=1))
    for x in (0.0, 0.25, 0.5, 1.0, 1.5, 2.0):
        for rate in (7e-4, -3e-5, 0.0):
            for trial in (0, 1):
                for b4c in (0, 1):
                    for full in (0, 1):
                        out.append(v0(group='deployer', x=x, trial=trial, b4c=b4c, full=full, ctx=dict(base=(rate, rate, 0.0, 0.0))))
    out.append(v0(group='deployer', x=1.0, dep_tag=3))
    for lim in (DISCOUNT_LIMIT - 1, DISCOUNT_LIMIT, DISCOUNT_LIMIT + 1, 0):
        for flag in (0, 1, 2, 3):
            out.append(v0(group='discount', entries={user: e(values=[lim] if lim else [], flag=flag)}))
    for lim in (WINDOW_LIMIT - 1, WINDOW_LIMIT, WINDOW_LIMIT + 1, 0, 1):
        for flag in (0, 1):
            for own in (True, False):
                ent = {user: e(values=[lim] if lim else [], key=5.0, w70=0.5)}
                if own:
                    ent[referrer] = e(flag=0, key=50.0, values=[])
                out.append(v0(group='referrer', entries=ent, flag=flag))
    for key in (0.0, 9.0, 10.0, 99.0, 100.0, 1e6):
        for rkey in (0.0, 5.0, 10.0, 100.0):
            ent = {user: e(values=[7], key=key, w70=0.75), referrer: e(flag=0, key=rkey, values=[])}
            out.append(v0(group='referrer_tier', entries=ent))
            out.append(v0(group='referrer_tier', entries=ent, ctx=dict(table=((20.0, 0.1), (200.0, 0.3)))))
            out.append(v0(group='referrer_tier', entries=ent, ctx=dict(table=())))
            out.append(v0(group='referrer_tier', entries=ent, ctx=dict(table=((0.0, 0.0), (20.0, -0.1)))))
    for key in (0.0, 9.0, 100.0):
        for bkey in (0.0, 5.0, 10.0, 100.0):
            for tenths in (0, 10, 1000):
                ent = {user: e(values=[7], key=key, w70=0.5), b: e(flag=0, key=bkey, values=[])}
                out.append(v0(group='builder_tier', entries=ent, builder=(tenths, b)))
                out.append(v0(group='builder_tier', entries=ent, builder=(tenths, b), flag=1))
                out.append(v0(group='builder_tier', entries=ent, builder=(tenths, b), ctx=dict(table=((20.0, 0.1), (200.0, 0.3)))))
                out.append(v0(group='builder_tier', entries=ent, builder=(tenths, b), ctx=dict(table=((0.0, 0.0), (20.0, 0.0)))))
                out.append(v0(group='builder_tier', entries=ent, builder=(tenths, b), ctx=dict(table=())))
    for d in (1, 7):
        for over in ((1e-3, 5e-4, 2e-3, 1e-3), (1e-4, 5e-5, 0.0, 0.0), (-1e-4, -1e-4, 0.0, 0.0)):
            for x in (0.0, 0.5, 2.0):
                ent = {user: e(d=d, over=over, values=[7])}
                out.append(v0(group='second_pair', entries=ent, x=x))
                out.append(v0(group='second_pair', entries=ent, x=x, b4c=0))
    for tag in (0, 1, 2, 0x100, 0x101):
        out.append(v0(group='tag', entries={user: e(tag=tag, key=5.0, w70=0.5)}))
    for b4c in (0, 1):
        for trial in (0, 1):
            for over in ((-1e-4, -2e-4, 0.0, 0.0), (1e-4, 2e-4, 0.0, 0.0)):
                out.append(v0(group='second_trial', entries={user: e(d=1, over=over)}, b4c=b4c, trial=trial, x=0.5))
    return out


def probe_vectors(side, base):
    """Hash paths: colliding h2 bytes, full groups, tall trees, a sum overflow."""
    out = []
    rng = Lcg(0x9b0e)
    colliding = []
    want = key_hash(addr(1)) >> 57
    i = 0
    while len(colliding) < 3 and i < 200000:
        k = addr(1000 + i)
        if key_hash(k) >> 57 == want:
            colliding.append(k)
        i += 1
    start = key_hash(addr(1)) & (GROUPS - 1)
    same_group, twin = [], []
    i = 0
    while (len(same_group) < 16 or not twin) and i < 400000:
        k = addr(300000 + i)
        if key_hash(k) & (GROUPS - 1) == start:
            if key_hash(k) >> 57 == want:
                twin.append(k)
            elif len(same_group) < 16:
                same_group.append(k)
        i += 1
    row = dict(tag=1, rates=(7e-4, 2e-4, 3e-4, 1e-4), key=9.0, d=0, over=(0.0,) * 4, w70=0.5, flag=1, referrer=addr(2), values=[1], height=0)

    def with_user(v, group, decoys=(), **kw):
        return dict(v, group=group, decoys=decoys, entries=dict(v['entries'], **{}) | {addr(1): dict(row, **kw)})

    for height in (0, 1, 2, 3, 8, 9):
        for extra in (0, 1):
            for v in base[:6]:
                n = rng.pick((1, 3, 12, 13, 40)) if height else rng.pick((1, 3, 11))
                out.append(with_user(v, 'tree', colliding if extra else (), values=[10 ** 7] * n, height=height))
    for v in base[:3]:
        out.append(with_user(v, 'tree_tall', values=[1] * 300, height=9, leaf=1))
        out.append(with_user(v, 'tree_tall', values=[1] * 300, height=10, leaf=1))
        out.append(with_user(v, 'tree_empty', values=[], rooted=True))
        out.append(with_user(v, 'tree_bad', values=[], claim=1))
        out.append(with_user(v, 'tree_bad', values=[5, 6], claim=3))
        out.append(with_user(v, 'tree_bad', values=[5, 6], claim=3, flag=3))
        out.append(with_user(v, 'twin', twin[:1], values=[5]))
        out.append(with_user(v, 'twin', twin[:1], values=[WINDOW_LIMIT], flag=1))
    for v in base[:6]:
        w = with_user(v, 'full_group', same_group[:16])
        out.append(w)
        out.append(dict(w, entries={}, group='miss_full_group'))
        out.append(with_user(v, 'sum_overflow', values=[U64, 5, U64, 9]))
    return out


def extreme_vectors(side):
    """Clamps and overflow branches: huge rates, tiers above 1, negative scales."""
    out = []
    rng = Lcg(0xe7e)
    user, referrer, b = addr(1), addr(2), addr(3)
    big = (1 << 63) - 1
    for rate, over in ((1e4, 2e4), (-1e4, -1e4), (1e4, 1e4), (2.0, 5.0), (-3.0, 1.0)):
        for x in (-2.0, -0.5, 0.5, 3.0):
            for tier in (0.5, 3.0, -3.0):
                for flag in (0, 1):
                    for bld in (None, (U64, b)):
                        e = dict(tag=1, rates=(rate,) * 4, key=500.0, d=1, over=(over,) * 4, w70=2.0, flag=1, referrer=referrer,
                                 values=[5])
                        ent = {user: dict(e, key=0.0), referrer: dict(e, flag=0), b: dict(e, flag=0)}
                        ctx = dict(entries_on=True, table=((0.0, 0.0), (100.0, tier)), base=(rate,) * 4, discount=0.0, share=2.0,
                                   f90=1.0, f98=1.0)
                        v = dict(group='extreme', side=side, user=user, ntli=big, flag=flag, builder=bld, ctx=ctx, entries=ent)
                        if side == 'perp':
                            v.update(dex=0, assets=8, asset=3, full=1, trial=0, dep_tag=0, x=x, b4c=1)
                        else:
                            v.update(cat=0, weight=1.0, bpl=1, tk=1, al=0)
                        out.append(v)
    for flag in (0, 1):
        for y in (0.5, 0.0):
            # both words of gross at i64::MAX plus a saturated builder part: the carry branch, then the shares
            e = dict(tag=1, rates=(1e4,) * 4, key=500.0, d=1, over=(2.5e4,) * 4, w70=1.0, flag=1, referrer=referrer, values=[5])
            ent = {user: dict(e, key=0.0), referrer: dict(e, flag=0), b: dict(e, flag=0)}
            ctx = dict(entries_on=True, table=((0.0, 0.0), (100.0, y)), base=(1e4,) * 4, discount=0.0, share=0.25, f90=1.0, f98=1.0)
            v = dict(group='carry', side=side, user=user, ntli=big, flag=flag, builder=(U64, b), ctx=ctx, entries=ent)
            if side == 'perp':
                v.update(dex=0, assets=8, asset=3, full=1, trial=0, dep_tag=0, x=0.0, b4c=1)
            else:
                v.update(cat=0, weight=1.0, bpl=1, tk=1, al=0)
            out.append(v)
    return out


def spot_groups():
    out = []
    user, referrer, b = addr(1), addr(2), addr(3)

    def v0(**kw):
        ctx = dict(entries_on=True, table=((0.0, 0.05), (10.0, 0.1), (100.0, 0.2)), base=(7e-4, 2e-4, 5e-4, 1e-4), discount=0.04,
                   share=0.1, f90=0.5, f98=2.0)
        ctx.update(kw.pop('ctx', {}))
        v = dict(side='spot', group=kw.pop('group'), user=user, ntli=10 ** 12, flag=0, builder=None, ctx=ctx, entries={}, cat=0,
                 weight=1.0, bpl=1, tk=1, al=0)
        v.update(kw)
        return v

    def e(**kw):
        d = dict(tag=1, rates=(7e-4, 2e-4, 5e-4, 1e-4), key=0.0, d=0, over=(1e-3, 5e-4, 2e-3, 1e-3), w70=1.0, flag=1,
                 referrer=referrer, values=[1000], height=0)
        d.update(kw)
        return d

    for cat in (0, 1, 2, 3, 9):
        for bpl in (0, 1):
            for tk in (0, 1):
                for al in (0, 1):
                    for d in (0, 1):
                        for rate in (5e-4, -1e-4, 0.0):
                            ent = {user: e(rates=(0.0, 0.0, rate, rate), d=d, over=(0.0, 0.0, rate * 2, rate * 2), values=[])}
                            out.append(v0(group='rate', cat=cat, bpl=bpl, tk=tk, al=al, entries=ent, weight=0.25))
    for lim in (DISCOUNT_LIMIT - 1, DISCOUNT_LIMIT, 0):
        for d in (0, 1):
            for bpl in (0, 1):
                out.append(v0(group='discount', bpl=bpl, entries={user: e(values=[lim] if lim else [], d=d)}))
    for lim in (WINDOW_LIMIT - 1, WINDOW_LIMIT, 0):
        for flag in (0, 1):
            ent = {user: e(values=[lim] if lim else [], key=5.0, w70=0.5), referrer: e(flag=0, key=50.0, values=[])}
            out.append(v0(group='referrer', entries=ent, flag=flag))
    for key in (0.0, 9.0, 10.0, 99.0, 100.0):
        for rkey in (0.0, 5.0, 10.0, 100.0):
            ent = {user: e(values=[7], key=key, w70=0.75), referrer: e(flag=0, key=rkey, values=[])}
            out.append(v0(group='referrer_tier', entries=ent))
            out.append(v0(group='referrer_tier', entries=ent, ctx=dict(table=((20.0, 0.1), (200.0, 0.3)))))
            out.append(v0(group='referrer_tier', entries=ent, ctx=dict(table=())))
            out.append(v0(group='referrer_tier', entries=ent, ctx=dict(table=((0.0, 0.0), (20.0, -0.1)))))
    for key in (0.0, 9.0, 100.0):
        for bkey in (0.0, 5.0, 10.0, 100.0):
            for tenths in (0, 10, 1000):
                ent = {user: e(values=[7], key=key, w70=0.5), b: e(flag=0, key=bkey, values=[])}
                for ctx in ({}, dict(table=((20.0, 0.1), (200.0, 0.3))), dict(table=((0.0, 0.0), (20.0, 0.0))), dict(table=())):
                    out.append(v0(group='builder_tier', entries=ent, builder=(tenths, b), ctx=ctx))
                out.append(v0(group='builder_tier', entries=ent, builder=(tenths, b), flag=1))
    return out


def late_vectors():
    """Survey gaps, kept last so that the sampled set of the earlier groups does not move."""
    user = addr(1)
    ctx = dict(entries_on=True, table=(), base=(0.0,) * 4, discount=0.0, share=0.0, f90=0.5, f98=2.0)
    e = dict(tag=1, rates=(-5e-4,) * 4, key=0.0, d=1, over=(-1e-4, -2e-4, 0.0, 0.0), w70=1.0, flag=0, referrer=addr(2), values=[], height=0)
    out = []
    for b4c in (0, 1):
        for x in (0.0, 0.5):
            out.append(dict(side='perp', group='second_rebate', user=user, ntli=10 ** 12, flag=0, builder=None, ctx=ctx, entries={user: e},
                            dex=0, assets=8, asset=3, full=1, trial=1, dep_tag=0, x=x, b4c=b4c))
    row = dict(e, rates=(0.0, 0.0, 5e-4, 5e-4), over=(0.0, 0.0, 1e-3, 1e-3))
    for bpl in (0, 1):
        out.append(dict(side='spot', group='second_bucket', user=user, ntli=10 ** 12, flag=0, builder=None, ctx=ctx, entries={user: row},
                        cat=1, weight=1.0, bpl=bpl, tk=1, al=1))
    return out


def all_vectors():
    perp = perp_groups()
    spot = spot_groups()
    perp += edge_vectors('perp') + probe_vectors('perp', perp[:6]) + extreme_vectors('perp')
    live = [v for v in spot if v['group'] == 'discount' and v['bpl']][:6]
    spot += edge_vectors('spot') + probe_vectors('spot', live) + extreme_vectors('spot')
    return perp + spot + late_vectors()


def run_vectors(img, code, vecs, scale, seen=None, stop=False):
    bad = []
    for i, v in enumerate(vecs):
        want = model(v, scale)
        m, res = run_fee(img, code, v)
        msg = compare(m, res, want)
        if seen is not None:
            seen |= m.seen
        if msg:
            bad.append((i, v['group'], msg))
            if stop:
                break
    return bad


# ---- mutations


def conditional_sites(listing):
    out = []
    for ins in listing:
        if ins.op[0] == 'j' and ins.op not in ('jmp', 'jmpr'):
            at = ins.va + (1 if ins.raw[0] == 0x0f else 0)
            out.append((ins.va, at, ins.raw[at - ins.va] ^ 1, ins.op))
        elif ins.op.startswith('cmov') or ins.op.startswith('set'):
            i = ins.raw.index(0x0f)
            out.append((ins.va, ins.va + i + 1, ins.raw[i + 1] ^ 1, ins.op))
    return out


def code_of(img, starts):
    code = {}
    for s in starts:
        code.update({i.va: i for i in decode_range(img, s, FDE_END[s])})
    return code


def sample(vecs):
    """The survey set: about 40 vectors of each (side, group), 100 of the extreme group, chosen by a
    hash of the index so that the choice does not alias with the nested loops of a group."""
    kept, count = [], {}
    for v in vecs:
        k = (v['side'], v['group'])
        count[k] = count.get(k, 0) + 1
    for i, v in enumerate(vecs):
        k = (v['side'], v['group'])
        cap = 100 if v['group'] == 'extreme' else 40
        if hashlib.sha256(str(i).encode()).digest()[0] * count[k] < 256 * cap:
            kept.append(v)
    return kept


def constant_sites(img, listing):
    """Constant bytes that the model states, each changed by one bit in its top byte or immediate."""
    out = []
    for name, va in CONSTANTS:
        raw = img.read(va, 8)
        out.append(dict(kind='constant', fn=None, va=va, op=name, patch={va + 6: raw[6] ^ 0x10}))
    for fn, va, name in IMMEDIATES:
        ins = next(i for i in listing[fn] if i.va == va)
        at = va + ins.size - 3
        out.append(dict(kind='immediate', fn=fn, va=va, op=name, patch={at: ins.raw[ins.size - 3] ^ 0x01}))
    return out


def survey(data, img, code, listing, vecs, scale):
    sites = []
    for fn in DECODED:
        sites += [dict(kind='flip', fn=fn, va=s[0], op=s[3], patch={s[1]: s[2]}) for s in conditional_sites(listing[fn])]
    sites += constant_sites(img, listing)
    picked = sample(vecs)
    pools = {PERP: [v for v in picked if v['side'] == 'perp'], SPOT: [v for v in picked if v['side'] == 'spot']}
    want = {id(v): model(v, scale) for v in picked}
    rows = []
    for s in sites:
        mimg = Image(data, s['patch'])
        mcode = code
        if s['fn'] is not None:
            mcode = dict(code)
            mcode.update({i.va: i for i in decode_range(mimg, s['fn'], FDE_END[s['fn']])})
        pool = pools.get(s['fn'], picked)
        killed = None
        for pos, v in enumerate(pool):
            try:
                m, res = run_fee(mimg, mcode, v)
                bad = compare(m, res, want[id(v)])
            except (Unmodelled, EvidenceError, KeyError, OverflowError, ValueError, TypeError) as exc:
                bad = f'fault {type(exc).__name__}'
            if bad:
                killed = (v['side'] + ':' + v['group'], bad[:60])
                pool.insert(0, pool.pop(pos))
                break
        rows.append(dict(s, killed=killed))
    return rows


FDE_END = {}


def bind_fdes(data):
    fdes = Fdes(data)
    for s in DECODED:
        FDE_END[s] = fdes.range_of(s)['end']
    return fdes


def build(data):
    check_digest(data)
    fdes = bind_fdes(data)
    img = Image(data)
    return img, code_of(img, DECODED), fdes


def location(img, slot):
    target = img.relative(slot)
    size, line, col = struct.unpack('<QII', img.read(slot + 8, 16))
    path = img.read(target, size).decode()
    for mark in ('l1/src/', 'library/'):
        if mark in path:
            path = path[path.index(mark):]
            break
    return dict(slot=hex(slot), path=path, line=line, col=col, length=size)


def text_blob(img):
    addr, off, size, _ = img.sec['.text']
    return addr, off, size


def slot_sites(img, slot, starts):
    """`call [rip+d]` sites of one pointer slot, with the enclosing FDE and the 1e9 immediate test."""
    addr, off, size = text_blob(img)
    blob, out = img.data, []
    i = blob.find(b'\xff\x15', off, off + size)
    while i != -1:
        va = addr + i - off
        if va + 6 + struct.unpack_from('<i', blob, i + 2)[0] == slot:
            k = bisect.bisect_right(starts, va) - 1
            before = blob[i - 16:i]
            out.append(dict(site=hex(va), function=hex(starts[k]), notional='1e9 immediate' if IMM_1E9 in before else 'register'))
        i = blob.find(b'\xff\x15', i + 1, off + size)
    return out


def direct_sites(img, target, starts):
    addr, off, size = text_blob(img)
    blob, out = img.data, []
    i = blob.find(b'\xe8', off, off + size)
    pack = struct.Struct('<i').unpack_from
    while i != -1 and i + 5 <= off + size:
        va = addr + i - off
        if va + 5 + pack(blob, i + 1)[0] == target:
            out.append(dict(site=hex(va), function=hex(starts[bisect.bisect_right(starts, va) - 1])))
        i = blob.find(b'\xe8', i + 1, off + size)
    return out


def fill_copy(img):
    """The copy of the output record into the side block after the real fill call, by decoded operands."""
    regs, pairs = {}, []
    for ins in decode_range(img, COPY_START, COPY_END):
        dst, src = ins.ops[0], ins.ops[1] if len(ins.ops) > 1 else None
        if ins.op == 'mov' and src is not None and dst[0] == 'm' and dst[1] == R['rdx'] and src[0] == 'r':
            pairs.append((dst[4], regs[('r', src[1])], 8))
        elif ins.op == 'mov' and dst[0] == 'r' and src[0] == 'm' and src[1] == R['rsp']:
            regs[('r', dst[1])] = src[4]
        elif ins.op in ('movups', 'movdqu') and dst[0] == 'x' and src[0] == 'm' and src[1] == R['rsp']:
            regs[('x', dst[1])] = src[4]
        elif ins.op in ('movups', 'movdqu_store') and dst[0] == 'm' and dst[1] == R['rdx']:
            pairs.append((dst[4], regs[('x', src[1])], 16))
        else:
            raise EvidenceError(f'{ins.va:#x}: not a copy step')
    rows = []
    for side, stack, size in sorted(pairs):
        rows.append(dict(side_block=hex(side), output=hex(stack - COPY_BASE), bytes=size))
    return rows


def facts(img, listing):
    def imm(fn, va):
        return next(i for i in listing[fn] if i.va == va).ops[1][1]

    out = dict(
        window_shift=imm(PERP, 0x3713934), window_cmp=hex(imm(PERP, 0x3713940)), spot_window_shift=imm(SPOT, 0x3742b12),
        spot_window_cmp=hex(imm(SPOT, 0x3742b1e)), discount_shift=imm(DISCOUNT, 0x3743374), discount_cmp=hex(imm(DISCOUNT, 0x3743378)),
        scale=list(scale_of(img)), half=img.f64(0x20a940), hundred_thousand=img.f64(0x20a9e8), five=img.f64(0x20a890),
        one=img.f64(0x20a730), exempt_ff=img.read(0x59c0e4, 16).hex() + img.read(0x59c0f4, 4).hex(),
        exempt_fe=img.read(0x59c0f8, 16).hex() + img.read(0x59c108, 4).hex(), rate_call_stride=hex(STRIDE))
    if (int(out['window_cmp'], 16) + 1) << out['window_shift'] != WINDOW_LIMIT:
        raise EvidenceError('window limit')
    if (int(out['spot_window_cmp'], 16) + 1) << out['spot_window_shift'] != WINDOW_LIMIT:
        raise EvidenceError('spot window limit')
    if (int(out['discount_cmp'], 16) + 1) << out['discount_shift'] != DISCOUNT_LIMIT:
        raise EvidenceError('discount limit')
    if out['exempt_ff'] != FF_ADDR.hex() or out['exempt_fe'] != FE_ADDR.hex():
        raise EvidenceError('exempt addresses')
    return out


def example_vectors():
    user, referrer, b = addr(1), addr(2), addr(3)
    base = (1e-4, 3.5e-4, 2.5e-4, 7e-4)
    ctx = dict(entries_on=False, table=(), base=base, discount=0.04, share=0.1, f90=1.0, f98=1.0)
    perp = dict(side='perp', user=user, ntli=10 ** 12, flag=0, builder=None, ctx=ctx, entries={}, dex=0, assets=8, asset=3, full=1,
                trial=0, dep_tag=0, x=0.0, b4c=0, group='example')
    row = dict(tag=1, rates=base, key=0.0, d=0, over=(0.0,) * 4, w70=1.0, flag=1, referrer=referrer, values=[1000], height=0)
    live = dict(ctx, entries_on=True)
    spot = dict(side='spot', user=user, ntli=10 ** 12, flag=0, builder=None, ctx=ctx, entries={}, cat=0, weight=1.0, bpl=1, tk=0, al=0,
                group='example')
    return (
        ('taker, default row', dict(perp)),
        ('maker, default row', dict(perp, b4c=1)),
        ('asset byte clear', dict(perp, full=0)),
        ('deployer scale 0.5', dict(perp, x=0.5)),
        ('deployer scale 2', dict(perp, x=2.0)),
        ('negative rate, scale 1', dict(perp, x=1.0, b4c=1, ctx=dict(ctx, base=(-2e-5, 3.5e-4, 0.0, 0.0)))),
        ('referred, flag side', dict(perp, flag=1, ctx=live, entries={user: row})),
        ('builder 10 units', dict(perp, builder=(10, b))),
        ('exempt address', dict(perp, user=FE_ADDR)),
        ('spot, taker', dict(spot)),
        ('spot, bucket 1', dict(spot, cat=1)),
        ('spot, bucket 2 weight 0.25', dict(spot, cat=2, weight=0.25)),
        ('spot, no quote leg', dict(spot, bpl=0)),
    )


def digest_of(v):
    return hashlib.sha256(repr(sorted((k, repr(x)) for k, x in v.items())).encode()).hexdigest()[:16]


def generate(data, out_dir, with_survey=True):
    img, code, fdes = build(data)
    listing = {s: decode_range(img, s, FDE_END[s]) for s in DECODED}
    scale = scale_of(img)
    vecs = all_vectors()
    seen = set()
    bad = run_vectors(img, code, vecs, scale, seen)
    if bad:
        raise EvidenceError(f'mismatches {bad[:5]}')
    missing = []
    padding = 0
    for fn in DECODED:
        for ins in listing[fn]:
            if ins.va in seen:
                continue
            if ins.op == 'nop':
                padding += 1
            elif not any(a <= ins.va < b for a, b, _ in UNEXECUTED):
                missing.append(hex(ins.va))
    if missing:
        raise EvidenceError(f'unlisted unexecuted instructions {missing[:12]}')
    rows = survey(data, img, code, listing, vecs, scale) if with_survey else []
    survivors = {r['va'] for r in rows if not r['killed']}
    if survivors - set(EQUIVALENT) or (rows and set(EQUIVALENT) - survivors):
        raise EvidenceError(f'survivors {sorted(hex(s) for s in survivors ^ set(EQUIVALENT))}')
    starts = sorted(f['start'] for f in eh_frame_records(data)[1])
    examples = []
    for name, v in example_vectors():
        want = model(v, scale)
        m, res = run_fee(img, code, v)
        msg = compare(m, res, want)
        if msg:
            raise EvidenceError(f'example {name}: {msg}')
        examples.append(dict(name=name, gross=want['gross'], rebate=want['rebate'], deployer=want.get('deployer'),
                             protocol=want.get('protocol'), referrer_amount=want['ref'], builder_amount=want['bamt']))
    exits, groups = {}, {}
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    with open(out / 'vectors.tsv', 'w', newline='\n') as f:
        f.write('side\tgroup\tinput_digest\tntli\texit\treferrer_tag\treferrer_amount\tbuilder_tag\tbuilder_amount\tgross\trebate\textra\tdeployer\tprotocol\thash_calls\trecords\n')
        for v in vecs:
            w = model(v, scale)
            exits[f"{v['side']}:{w['exit']}"] = exits.get(f"{v['side']}:{w['exit']}", 0) + 1
            groups[f"{v['side']}:{v['group']}"] = groups.get(f"{v['side']}:{v['group']}", 0) + 1
            cells = [v['side'], v['group'], digest_of(v), str(v['ntli']), w['exit']]
            cells += ['' if w.get(k) is None else str(w[k]) for k in ('tag', 'ref', 'btag', 'bamt', 'gross', 'rebate', 'extra', 'deployer', 'protocol')]
            cells += ['' if w['hashes'] is None else str(len(w['hashes'])), '' if w['records'] is None else ','.join(hex(x) for x in w['records'])]
            f.write('\t'.join(cells) + '\n')
    with open(out / 'mutations.tsv', 'w', newline='\n') as f:
        f.write('kind\tfunction\tva\tinstruction\tresult\tvector\treason\n')
        for r in rows:
            k = r['killed']
            fn = hex(r['fn']) if r['fn'] else ''
            f.write(f"{r['kind']}\t{fn}\t{r['va']:#x}\t{r['op']}\t{'killed' if k else 'equivalent'}\t{k[0] if k else ''}\t{k[1] if k else EQUIVALENT[r['va']]}\n")
    with open(out / 'instructions.tsv', 'w', newline='\n') as f:
        f.write('function\tva\tsize\tbytes\tdecoded\texecuted\n')
        for fn in DECODED:
            for i in listing[fn]:
                f.write(f'{fn:#x}\t{i.va:#x}\t{i.size}\t{i.raw.hex()}\t{show(i)}\t{int(i.va in seen)}\n')
    with open(out / 'reference-diff.tsv', 'w', newline='\n') as f:
        f.write('verdict\treference\treference_says\tbytes_say\n')
        for r in REFERENCE_ROWS:
            f.write('\t'.join(r) + '\n')
    per = {}
    for fn in DECODED:
        ex = sum(i.va in seen for i in listing[fn])
        per[hex(fn)] = dict(end=hex(FDE_END[fn]), fde=hex(fdes.range_of(fn)['fde']), instructions=len(listing[fn]), executed=ex)
    evidence = dict(
        binary=BINARY, sha256=SHA256, functions=per, facts=facts(img, listing), slots={hex(k): hex(img.relative(k)) for k in sorted(SLOTS)},
        perp_callers=slot_sites(img, 0x5774890, starts), spot_callers=direct_sites(img, SPOT, starts), fill_copy=fill_copy(img),
        locations={k: location(img, v) for k, v in (('builder_total', LOC_TOTAL), ('net_referrer', LOC_NET_A), ('net_split', LOC_NET_B),
                                                    ('window_sum', LOC_SUM), ('asset', LOC_ASSET), ('unwrap', LOC_UNWRAP), ('tree_end', LOC_EMPTY_A))},
        vectors=len(vecs), mismatches=0, groups=groups, exits=exits, examples=examples, padding_not_executed=padding,
        unexecuted=[dict(start=hex(a), end=hex(b), why=w) for a, b, w in UNEXECUTED],
        mutants=len(rows), killed=sum(1 for r in rows if r['killed']), survey_vectors=len(sample(vecs)),
        equivalent={hex(k): v for k, v in sorted(EQUIVALENT.items())},
    )
    with open(out / 'evidence.json', 'w', newline='\n') as f:
        json.dump(evidence, f, indent=1, sort_keys=True)
        f.write('\n')
    return evidence


def main():
    ap = argparse.ArgumentParser(description=__doc__.split('\n')[0])
    ap.add_argument('--out', required=True)
    args = ap.parse_args()
    data = (ROOT / BINARY).read_bytes()
    ev = generate(data, args.out)
    print(json.dumps(dict(vectors=ev['vectors'], mutants=ev['mutants'], killed=ev['killed']), sort_keys=True))


if __name__ == '__main__':
    main()
