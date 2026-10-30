#!/usr/bin/env python3
"""fees: node #94 fee rate grid behind the schedule update, from bytes alone.

Static, no execution of the node.  0x36e2d90 is decoded from its ELF bytes by the table decoder
below, which must land exactly on the FDE end, and interpreted in Python on every vector, with
the formatter, the free and the overflow recorder as stubs.  The chain above it (0x3404030,
0x343a460, 0x3b7ef60, 0x3bc9050, 0x343d230 and the floors 0x3c05c30) runs the same way, with a
worker stub that keeps every rayon split on the leaf path.  Each outcome is compared with a
separate closed-form model, then every conditional is flipped to test the vectors.

    python3 tools/fees_rate_grid.py --out <dir>

writes evidence.json, vectors.tsv, chain.tsv, mutations.tsv, instructions.tsv and
reference-diff.tsv.  Section and FDE parsing come from tools/elf_index.py and
tools/fde_extents.py.  Only the standard library is used: no objdump, readelf or other external
program runs, so the results cannot depend on a binutils version.
"""

import argparse
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
            if pred not in (1, 3):
                raise EvidenceError(f'{va:#x}: unlisted cmpsd predicate {pred}')
            return done('cmpltsd' if pred == 1 else 'cmpunordsd', (('x', reg | rr << 3), rm), 64)
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
        if a.strict and not all(a.valid[o:o + size]):
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
        elif op in ('cmpltsd', 'cmpunordsd'):
            a, b = b2f(self.xmm[ops[0][1]][0]), b2f(self.xrd64(ops[1]))
            hit = a < b if op == 'cmpltsd' else math.isnan(a) or math.isnan(b)
            self.xmm[ops[0][1]][0] = U64 if hit else 0
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
            d = b2f(self.xrd64(ops[1]))
            if d == 0.0:
                raise Unmodelled(f'{ins.va:#x}: division by zero')
            self.xmm[ops[0][1]][0] = f2b(b2f(self.xmm[ops[0][1]][0]) / d)
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
        target = o[1] if o[0] == 't' else self.rd(o) if o[0] == 'r' else self.ea(o)
        if target in self.real:
            self.regs[4] -= 8
            self.store(self.regs[4], 8, ins.va + ins.size)
            self.run(self.real[target])
            return
        stub = self.stubs.get(target)
        if stub is None:
            raise Unmodelled(f'{ins.va:#x}: call {target:#x}')
        stub()

    def run(self, entry, limit=30000000):
        rip = entry
        for _ in range(limit):
            ins = self.code.get(rip)
            if ins is None:
                raise Unmodelled(f'no instruction at {rip:#x}')
            if rip in self.hooks:
                self.hooks[rip]()
            self.seen.add(rip)
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

POINT, RANGE_LEAF, RANGE, SCALE_LEAF, SCALE_BRIDGE, ENTRY, FLOORS = (0x36e2d90, 0x343d230, 0x3bc9050, 0x3b7ef60,
                                                                     0x343a460, 0x3404030, 0x3c05c30)
DECODED = (POINT, RANGE_LEAF, RANGE, SCALE_LEAF, SCALE_BRIDGE, ENTRY, FLOORS)
OTHER_CALLERS = (0x383a464, 0x38c0930)
WORKER_TLS = 0x4e17630
SLOT_FORMAT, SLOT_UNWRAP, SLOT_FREE, SLOT_RECORD, SLOT_FMA, SLOT_ONCE = (0x576e040, 0x576e048, 0x576e010, 0x5773190,
                                                                        0x576f6e0, 0x576e8b8)
ONCE_WORD = 0x577ab98
FMT_ARGS, FMT_F64, FMT_I64 = 0x36e10f0, 0x36e0760, 0x36e0dc0
LOC_NTLI, LOC_SUM, LOC_TRY = 0x56f1f60, 0x56f2098, 0x56f1ce0
TEXT_FEE, TEXT_MAX, TEXT_NTLI, TEXT_ROUND = 0x1f9085, 0x1ef89e, 0x1e571d, 0x1fb3f0
ONE_ADDR, LOW_ADDR, HIGH_ADDR, BELOW_ADDR = 0x20a730, 0x20acb8, 0x20a7f0, 0x20a2c8
BOUND_SITE, FIRST_SITE = 0x3b7f0cc, 0x3b7f0c3
BOUND = 10000000
SCALES = (1.0, 0.2, 6.0, 0.1)
LOW, HIGH, BELOW = -(2.0 ** 63), 2.0 ** 63, 9223372036854774784.0
I64MAX, I64MIN = (1 << 63) - 1, -(1 << 63)
AT = chr(0x40)
FLOOR = 5e-06
ENV_NAMES = ('cross_low', 'referral', 'keep', 'args', 'add_low', 'first_cross')

# Exit name -> (format text, variant, display of the 2nd and 3rd arguments)
EXITS = {'discounted_fee': (TEXT_FEE, 0, ('k', 'd')), 'max_fee': (TEXT_MAX, 0, ('k', 'f')),
         'ntli': (TEXT_NTLI, 1, ('n', 'm')), 'rounding': (TEXT_ROUND, 1, ('n', 'm'))}

# Unexecuted by the point vectors: only the unwind cleanup at the end of the FDE, and padding.
UNEXECUTED = (
    (0x36e3571, 0x36e3586, 'ud2 after the panic call, then the unwind cleanup'),
)
# Branches whose flip changes nothing the vectors can see; each has its reason.
CLAMP_LOW = 'clamp below: unclamped, cvttsd2si gives the integer indefinite, which is already i64::MIN'
CLAMP_HIGH = 'clamp above: unclamped, the cmova on the next compare already gives i64::MAX'
EQUIVALENT = {
    0x36e2e34: CLAMP_LOW, 0x36e2e3e: CLAMP_HIGH, 0x36e2ea8: CLAMP_LOW, 0x36e2eb2: CLAMP_HIGH, 0x36e2f25: CLAMP_LOW,
    0x36e2f33: CLAMP_HIGH, 0x36e3071: CLAMP_LOW, 0x36e307b: CLAMP_HIGH, 0x36e30f4: CLAMP_LOW, 0x36e30fe: CLAMP_HIGH,
    LOW_ADDR: 'same as the clamp below: a lower limit changes nothing the conversion does not already do',
    HIGH_ADDR: 'same as the clamp above',
}
REFERENCE_ROWS = (
    ('absent', 'l1/fees/compute.rs', 'no rate grid', 'the reference has no text of the four rejects and no ntli loop'),
    ('agree', 'l1/fees/compute.rs:369', 'clamp_float_to_i64: non-finite gives 0, clamp, then truncate',
     'all five conversions in 0x36e2d90 have this shape; the reference uses it for fees, here it guards a schedule'),
    ('differ', 'l1/fees/compute.rs:263', 'fee_units_for_notional divides by 10000',
     'no division here: rates are plain fractions of ntli and every product is truncated once'),
    ('differ', 'l1/action/vote_global.rs:202', 'FeeSchedule fields as u64 bps',
     'the grid reads f64 fractions'),
)


class Panic(Exception):
    pass


def to_i64(x):
    """The saturating conversion repeated five times in the grid point."""
    if math.isnan(x) or math.isinf(x):
        return 0
    if x < LOW or x > HIGH:
        x = min(HIGH, max(x, LOW))
    return I64MAX if x > BELOW else int(x)


def point_model(v):
    """Closed form of the grid point for one (rates, scale, ntli); returns a dict of named words."""
    n, m = v['n'], v['m']
    if n >> 63:
        return dict(exit='panic', recorded=[])
    nf = float(n)
    rec = []
    d = to_i64((1.0 - v['r']) * v['L'] * m * nf)
    keep = to_i64(float(d) * v['k'])
    out = dict(d=d, keep=keep, recorded=rec)
    if keep < 0:
        return dict(out, exit='discounted_fee')
    a = to_i64(v['a'] * m * nf)
    out['a'] = a
    net = d - keep
    if not I64MIN <= net <= I64MAX:
        rec.append(LOC_NTLI)
        net = I64MAX if net > 0 else I64MIN
    total = net + a
    if not I64MIN <= total <= I64MAX:
        rec.append(LOC_NTLI)
        total = I64MAX if total > 0 else I64MIN
    out['net'] = total
    if total < 0:
        return dict(out, exit='ntli')
    f = to_i64(m * v['c'] * nf)
    fk = to_i64(float(f) * v['k'])
    out.update(f=f, fk=fk)
    if fk < 0:
        return dict(out, exit='max_fee')
    whole = fk + max(f, 0) + abs(a)
    if whole > U64:
        rec.append(LOC_SUM)
        whole = U64
    out['whole'] = whole
    return dict(out, exit='rounding' if whole >= n else 'ok')


def fold_model(v):
    """What the rayon find folder does with a reject: 'keep' the old item or 'take' the new one."""
    tag, pos, cur, boundary, race = v['tag'], v['pos'], v['best'], v['boundary'], v['race']
    if tag != 2 and not pos:
        return 'keep', cur
    while True:
        better = boundary > cur if pos else boundary < cur
        if better:
            if race is not None:
                cur, race = race, None
                continue
            return 'take', boundary
        return ('take', cur) if cur == boundary else ('keep', cur)


class Heap:
    """String blocks of the format stub; every block must be freed once with its size."""

    def __init__(self, m):
        self.m, self.live, self.freed = m, {}, 0

    def block(self, size):
        a = self.m.arena(max(size, 8))
        self.live[a.base] = size
        return a.base

    def free(self):
        m = self.m
        ptr, size = m.regs[R['rdi']], m.regs[R['rsi']]
        if self.live.pop(ptr, None) != size:
            raise Unmodelled(f'free of {ptr:#x} size {size}')
        self.freed += 1
        m.clobber()


def machine(img, code, rsp_top=0x7000):
    m = Machine(img, ())
    m.code = code
    stack = m.arena(0x10000, False)
    stack.mem[:] = b'\xa5' * len(stack.mem)
    m.regs[4] = stack.base + rsp_top - 8
    m.heap = Heap(m)
    m.formats, m.recorded = [], []

    def record():
        m.recorded.append(m.regs[R['rsi']])
        m.clobber()

    def fmt():
        rdi, pieces, args = m.regs[R['rdi']], m.regs[R['rsi']], m.regs[R['rdx']]
        pairs = [(m.load(args + 16 * i, 8), m.load(args + 16 * i + 8, 8)) for i in range(3)]
        words = [m.load(m.load(p, 8), 8) if fn != FMT_ARGS else m.load(p, 8) for p, fn in pairs]
        m.formats.append((pieces, tuple(fn for _, fn in pairs), tuple(words)))
        size = 16 + len(m.formats)
        base = m.heap.block(size)
        m.store(rdi, 8, size)
        m.store(rdi + 8, 8, base)
        m.store(rdi + 16, 8, size)
        m.clobber()

    def unwrap():
        raise Panic('unwrap')

    m.stubs.update({SLOT_RECORD: record, SLOT_FORMAT: fmt, SLOT_FREE: m.heap.free, SLOT_UNWRAP: unwrap})
    return m


def f64_cell(m, x):
    a = m.arena(8)
    m.store(a.base, 8, f2b(x))
    return a.base


def make_env(m, v):
    """The six pointers of the closure; the argument block is a strict arena nobody may read."""
    env = m.arena(0x30)
    args = m.arena(8)
    m.args = args.base
    cells = (v['L'], v['r'], v['k'], None, v['a'], v['c'])
    for i, x in enumerate(cells):
        m.store(env.base + 8 * i, 8, args.base if x is None else f64_cell(m, x))
    return env.base


OLD_LEN = 7


def run_point(img, code, v):
    m = machine(img, code)
    env = make_env(m, v)
    folder = m.arena(0x48)
    best = m.arena(8)
    out = m.arena(0x48)
    m.store(best.base, 8, v['best'])
    old_ptr = m.heap.block(v['cap']) if v['tag'] != 2 and v['cap'] else 0x1111
    words = (v['tag'], v['cap'], old_ptr, OLD_LEN, 0x2222, best.base, v['boundary'])
    for i, w in enumerate(words):
        m.store(folder.base + 8 * i, 8, w)
    m.store(folder.base + 0x38, 8, 0x77665544332200 | v['pos'])
    m.store(folder.base + 0x40, 8, env)
    m.regs[R['rdi']], m.regs[R['rsi']], m.regs[R['rdx']] = out.base, folder.base, v['n']
    m.xmm[0][0] = f2b(v['m'])
    m.race = v['race']
    want = point_model(v)
    try:
        m.run(POINT)
    except Panic:
        return m, dict(exit='panic', mismatch=None if want['exit'] == 'panic' else 'unexpected panic')
    got = dict(exit='ok' if not m.formats else None)
    bad = compare_point(m, v, want, got, out.base, folder.base, best.base, env, old_ptr)
    return m, dict(got, mismatch=bad)


def compare_point(m, v, want, got, out, folder, best, env, old_ptr):
    rax = m.regs[0]
    if rax != out:
        return 'return register'
    if m.recorded != want['recorded']:
        return f'recorder {[hex(x) for x in m.recorded]}'
    in_words = [m.load(folder + 8 * i, 8) for i in range(8)]
    out_words = [m.load(out + 8 * i, 8) for i in range(9)]
    if want['exit'] == 'ok':
        if m.formats:
            return 'format on a pass'
        if out_words[:8] != in_words or out_words[8] != env:
            return 'pass changed the folder'
        return None
    if len(m.formats) != 1:
        return 'no format on a reject'
    pieces, fns, words = m.formats[0]
    text, variant, labels = EXITS[want['exit']]
    got['exit'] = next((k for k, e in EXITS.items() if e[0] == pieces), None)
    if got['exit'] != want['exit']:
        return f'exit {got["exit"]}'
    vals = dict(k=f2b(v['k']), n=v['n'], m=f2b(v['m']), d=want.get('d', 0) & U64, f=want.get('f', 0) & U64)
    if words != (m.args, vals[labels[0]], vals[labels[1]]):
        return 'format arguments'
    types = (FMT_ARGS, FMT_F64 if labels[0] == 'k' else FMT_I64, FMT_I64 if labels[0] == 'k' else FMT_F64)
    if fns != types:
        return 'format functions'
    how, final = fold_model(v)
    if m.load(best, 8) != final & U64:
        return 'best word'
    if how == 'keep':
        if out_words[:8] != in_words or out_words[8] != env:
            return 'keep changed the folder'
        if m.heap.freed != 1 or v['tag'] != 2 and v['cap'] and old_ptr not in m.heap.live:
            return 'keep must free only the new text'
        return None
    if out_words[0] != variant or out_words[4:8] != in_words[4:] or out_words[8] != env:
        return 'take'
    if out_words[1] != out_words[3] or out_words[2] not in m.heap.live:
        return 'new text'
    old_freed = v['tag'] != 2 and v['cap'] != 0
    if m.heap.freed != int(old_freed):
        return 'old text not dropped'
    return None


def vec(L=1e-4, r=0.1, k=0.25, a=-1e-5, c=7e-4, m=1.0, n=1000, tag=2, cap=0, pos=0, best=U64, boundary=9, race=None,
        group='base'):
    return dict(L=L, r=r, k=k, a=a, c=c, m=m, n=n, tag=tag, cap=cap, pos=pos, best=best, boundary=boundary, race=race,
                group=group)


class Lcg:
    def __init__(self, seed):
        self.x = seed

    def next(self):
        self.x = (self.x * 6364136223846793005 + 1442695040888963407) & U64
        return self.x >> 11

    def pick(self, seq):
        return seq[self.next() % len(seq)]


def point_vectors():
    out = []
    ns = (1, 2, 3, 7, 10, 99, 100, 101, 1000, 4999, 5000, 5001, 65536, 999999, BOUND, BOUND + 1, (1 << 53) + 1,
          1 << 62, I64MAX)
    rates = (dict(), dict(L=0.0, c=0.0, a=0.0), dict(a=1e-3), dict(r=1.0), dict(k=0.0), dict(k=1.0), dict(L=1e-3, c=1e-3),
             dict(a=-9e-5, k=0.05))
    for m in SCALES:
        for n in ns:
            for p in rates:
                out.append(vec(m=m, n=n, group='ladder', **p))
    # each reject, and the border around it
    for n in (1, 3, 4, 5, 39, 40, 41, 10000, 10001, BOUND):
        out += [vec(L=-0.1, k=0.5, n=n, group='reject_d'), vec(L=-1.0, k=0.25, n=n, group='reject_d'),
                vec(L=0.1, k=-0.5, n=n, group='reject_d'), vec(L=1e-4, a=-1.0, k=0.0, n=n, group='reject_net'),
                vec(L=0.5, a=-0.4, k=0.5, n=n, group='reject_net'), vec(c=-0.5, k=0.5, a=0.0, n=n, group='reject_f'),
                vec(c=0.4, k=0.5, a=-0.0, n=n, group='reject_round'), vec(c=0.5, k=1.0, a=0.0, n=n, group='reject_round'),
                vec(c=0.2, k=1.0, a=0.6, n=n, group='reject_round'), vec(c=0.3, k=1.0, a=0.399, n=n, group='reject_round')]
    # truncation toward zero and the sign of a zero
    for x in (0.9999999, 1.0, 1.0000001, 1.9999999, 2.0):
        for n in (1, 2, 5):
            out += [vec(L=x / n, r=0.0, k=0.5, a=0.0, c=0.0, n=n, group='trunc'),
                    vec(L=x / n, r=0.0, k=0.0, a=-x / n, c=0.0, n=n, group='trunc'),
                    vec(L=0.0, r=0.0, k=0.0, a=x / n, c=x / n, n=n, group='trunc')]
    # the clamp of each conversion, the saturating sums and the unsigned whole
    big = (1e15, 2.0 ** 62, 2.0 ** 63, 1e19, 1e300, -1e300, -1e19, -(2.0 ** 63))
    for x in big:
        for y in big:
            out += [vec(L=x, r=0.0, k=-1.0, a=y, c=1e-3, m=1.0, n=1 << 20, group='saturate'),
                    vec(L=x, r=0.0, k=0.5, a=y, c=1.0, m=1.0, n=1 << 20, group='saturate'),
                    vec(L=1.0, r=0.0, k=0.5, a=x, c=y, m=1.0, n=1 << 20, group='saturate'),
                    vec(L=1e12, r=0.0, k=0.5, a=x, c=y, m=1.0, n=I64MAX, group='saturate')]
    out += [vec(L=-9.3e18, r=0.0, k=-0.5, a=0.0, n=1, group='saturate'),
            vec(L=-9.3e18, r=0.0, k=-0.5, a=-9.3e18, n=1, group='saturate'),
            vec(L=9.3e18, r=0.0, k=0.0, a=9.3e18, c=1.0, n=1, group='saturate'),
            vec(L=9.3e18, r=0.0, k=0.0, a=9.3e18, c=9.3e18, n=1, group='saturate'),
            vec(L=9.3e18, r=0.0, k=0.0, a=-9.3e18, c=9.3e18, n=1, group='saturate'),
            vec(L=9.3e18, r=0.0, k=1.0, a=-9.3e18, c=9.3e18, n=I64MAX, group='saturate'),
            vec(L=9.3e18, r=0.0, k=1.0, a=9.3e18, c=9.3e18, n=I64MAX, group='saturate'),
            vec(L=1e18, r=0.0, k=1.0, a=-1.0, c=1.0, n=1 << 62, group='saturate'),
            vec(L=9e18, r=0.0, k=1.5, a=0.0, c=1.0, n=1, group='saturate'),
            vec(L=-9e18, r=0.0, k=1.5, a=0.0, c=1.0, n=1, group='saturate'),
            vec(L=1.0, r=0.0, k=1.5, a=0.0, c=9e18, n=1, group='saturate'),
            vec(L=1.0, r=0.0, k=1.5, a=0.0, c=-9e18, n=1, group='saturate'),
            vec(L=9e18, r=0.0, k=-1.5, a=0.0, c=1.0, n=1, group='saturate'),
            vec(L=1.0, r=0.0, k=-1.5, a=0.0, c=9e18, n=1, group='saturate'),
            vec(L=9e18, r=0.0, k=float('inf'), a=0.0, c=1.0, n=1, group='saturate'),
            vec(L=1.0, r=0.0, k=float('inf'), a=0.0, c=9e18, n=1, group='saturate')]
    nan, inf = float('nan'), float('inf')
    for field in ('L', 'r', 'k', 'a', 'c'):
        for x in (nan, inf, -inf):
            for n in (1, 1000):
                out.append(vec(n=n, group='non_finite', **{field: x}))
    out.append(vec(m=nan, group='non_finite'))
    out.append(vec(m=inf, group='non_finite'))
    out += [vec(n=1 << 63, group='panic'), vec(n=U64, group='panic')]
    # reject with each folder state
    fail = dict(L=-1.0, k=0.25, n=1000)
    for reject in (fail, dict(a=-1.0, k=0.0, n=1000), dict(c=-0.5, a=0.0, n=1000), dict(c=0.5, k=1.0, a=0.0, n=1000)):
        for tag in (2, 0, 1):
            for cap in (0, 24):
                if tag == 2 and cap:
                    continue
                for pos in (0, 1):
                    for best in (5, 9, 13):
                        for race in (None, 3, 9, 15):
                            out.append(vec(tag=tag, cap=cap, pos=pos, best=best, boundary=9, race=race, group='folder',
                                           **reject))
    out += [vec(tag=t, cap=c, pos=p, group='folder_pass') for t in (2, 0, 1) for c in (0, 24) for p in (0, 1)
            if t != 2 or not c]
    rng = Lcg(0x94fee)
    pool = (0.0, -0.0, 1e-5, 1e-4, 3e-4, 7e-4, 1e-3, 0.01, 0.1, 0.25, 0.5, 1.0, 2.0, -1e-5, -1e-4, -1e-3, -0.25, -1.0)
    for _ in range(1200):
        v = vec(L=rng.pick(pool), r=rng.pick((0.0, 0.04, 0.1, 0.5, 1.0, 1.5)), k=rng.pick((0.0, 0.1, 0.25, 0.5, 1.0, 1.5)),
                a=rng.pick(pool), c=rng.pick(pool), m=rng.pick(SCALES), n=1 + rng.next() % (BOUND * 3), group='random')
        out.append(v)
    return out


def run_vectors(img, code, vecs, seen=None, stop=False):
    rows = []
    for v in vecs:
        m, res = run_point(img, code, v)
        if seen is not None:
            seen |= m.seen
        rows.append(res)
        if res['mismatch']:
            if stop:
                return rows
            raise EvidenceError(f'{v}: {res}')
    return rows


# ---- the chain above the point


def worker_arena(m, threads):
    """A worker slot whose registry reports `threads`; 0 keeps every rayon split on the leaf path."""
    registry = m.arena(0x210)
    m.store(registry.base + 0x208, 8, threads)
    worker = m.arena(0x118)
    m.store(worker.base + 0x110, 8, registry.base)
    slot = m.arena(8)
    m.store(slot.base, 8, worker.base)

    def tls():
        m.clobber(slot.base)

    m.stubs[WORKER_TLS] = tls


def point_log(m):
    log = []

    def hook():
        log.append((b2f(m.xmm[0][0]), m.regs[R['rdx']]))

    m.hooks[POINT] = hook
    return log


def chain_real(m):
    for start in (POINT, RANGE_LEAF, RANGE, SCALE_LEAF, SCALE_BRIDGE, ENTRY):
        m.real[start] = start


def chain_tag(m, out):
    tag = m.load(out, 8)
    return tag, (m.load(out + 8, 8), m.load(out + 16, 8)) if tag != 2 else None


def run_range(img, code, v, start, end, exhausted=0):
    """0x3bc9050 alone: the inclusive range, one scale."""
    m = machine(img, code)
    m.race = None
    chain_real(m)
    worker_arena(m, 0)
    log = point_log(m)
    env = make_env(m, v)
    best = m.arena(8)
    m.store(best.base, 8, U64)
    rng = m.arena(0x18, False)
    m.store(rng.base, 8, start)
    m.store(rng.base + 8, 8, end)
    m.store(rng.base + 16, 1, exhausted)
    cons = m.arena(0x38)
    for i, w in enumerate((f64_cell(m, v['m']), env, 0x3333, best.base, 0, U64)):
        m.store(cons.base + 8 * i, 8, w)
    m.store(cons.base + 0x30, 8, 0)
    out = m.arena(0x48)
    m.regs[R['rdi']], m.regs[R['rsi']], m.regs[R['rdx']] = out.base, rng.base, cons.base
    m.run(RANGE)
    return log, m.load(out.base, 8)


def run_entry(img, code, v):
    """0x3404030 with the real scale list: rates in, Some/None out."""
    m = machine(img, code)
    m.race = None
    chain_real(m)
    worker_arena(m, 0)
    log = point_log(m)
    env = make_env(m, v)
    best = m.arena(8)
    m.store(best.base, 8, U64)
    scales = m.arena(0x20)
    for i, x in enumerate(SCALES):
        m.store(scales.base + 8 * i, 8, f2b(x))
    cons = m.arena(0x40)
    for i, w in enumerate((4, scales.base, env, 0x3333, best.base, 0, U64)):
        m.store(cons.base + 8 * i, 8, w)
    m.store(cons.base + 0x38, 8, 0)
    out = m.arena(0x48)
    m.regs[R['rdi']], m.regs[R['rsi']], m.regs[R['rdx']], m.regs[R['rcx']] = out.base, cons.base, scales.base, 4
    m.run(ENTRY)
    tag, text = chain_tag(m, out.base)
    return dict(log=log, tag=tag, machine=m, text=text)


def grid_model(v, bound):
    """First failure in the order of the chain, or None."""
    for m in SCALES:
        for n in range(1, bound + 1):
            res = point_model(dict(v, m=m, n=n))
            if res['exit'] != 'ok':
                return dict(m=m, n=n, exit=res['exit'])
    return None


def fma(x, y, z):
    return float(Fraction(x) * Fraction(y) + Fraction(z))


def run_floors(img, code, f):
    """The real float floors 0x3c05c30 calling the real chain, from its argument block."""
    m = machine(img, code)
    m.race = None
    chain_real(m)
    m.real[FLOORS] = FLOORS
    worker_arena(m, 0)
    log = point_log(m)
    m.got[ONCE_WORD] = 0
    envs = []

    def fma_stub():
        keep = f2b(fma(b2f(m.xmm[0][0]), b2f(m.xmm[1][0]), b2f(m.xmm[2][0])))
        m.clobber()
        m.xmm[0][0] = keep

    def env_hook():
        if not envs:
            env = m.load(m.regs[R['rsi']] + 0x40, 8)
            envs.append(tuple(b2f(m.load(m.load(env + 8 * i, 8), 8)) if i != 3 else 0.0 for i in range(6)))

    m.stubs[SLOT_FMA] = fma_stub
    m.got[SLOT_FMA] = SLOT_FMA
    m.hooks[POINT] = lambda: (env_hook(), log.append((b2f(m.xmm[0][0]), m.regs[R['rdx']])))
    block = m.arena(0x60)

    def vec_of(xs):
        a = m.arena(max(8, 8 * len(xs)))
        for i, x in enumerate(xs):
            m.store(a.base + 8 * i, 8, f2b(x))
        h = m.arena(0x18)
        m.store(h.base, 8, len(xs))
        m.store(h.base + 8, 8, a.base)
        m.store(h.base + 16, 8, len(xs))
        return h.base

    m.store(block.base, 8, vec_of(f['add']))
    m.store(block.base + 8, 8, vec_of(f['mm_add']))
    m.store(block.base + 16, 8, vec_of(f['cross']))
    words = (f['add'][0], f['cross'][0], f['r'], f['stake'], f['k'], f['k'], f['word90'], f['word98'], 0.0)
    for i, x in enumerate(words):
        m.store(block.base + 0x18 + 8 * i, 8, f2b(x))
    m.regs[R['rdi']] = block.base
    m.run(FLOORS)
    return dict(ok=m.regs[0] & 0xff, log=log, env=envs[0] if envs else None, machine=m)


def floors_view(f):
    """The grid inputs the model derives from a floors argument block."""
    last_add, last_mm = f['add'][-1], f['mm_add'][-1]
    low = last_mm if last_mm < last_add else last_add
    add_low = f['word98'] * low if low < 0.0 else low
    return dict(L=f['word90'] * f['cross'][-1], r=f['r'], k=f['k'], a=add_low, c=f['cross'][0])


def floors_vectors():
    good = dict(cross=[7e-4, 4e-4, 2.4e-4], add=[3e-4, 1e-4, 0.0], mm_add=[3e-4, -1e-5, -3e-5], r=0.04, stake=0.3, k=0.1,
                word90=0.8, word98=1.5)
    return (('accepted', good, 40),
            ('zero_keep', dict(good, k=0.0), 40),
            ('negative_word90', dict(good, cross=[1e-3, 1e-3], add=[1e-3, 1e-3], mm_add=[1e-3, 1e-3], r=0.0, k=1.0, stake=0.0,
                                     word90=-1.0, word98=1.0), None),
            ('negative_word90_half_keep', dict(good, cross=[1e-3, 1e-3], add=[1e-3, 1e-3], mm_add=[1e-3, 1e-3], r=0.0, k=0.5,
                                               stake=0.0, word90=-1.0, word98=1.0), None),
            ('negative_word90_no_keep', dict(good, cross=[1e-3, 1e-3], add=[1e-3, 1e-3], mm_add=[1e-3, 1e-3], r=0.0, k=0.0,
                                             stake=0.0, word90=-0.5, word98=1.0), 40),
            ('wide_rate', dict(good, cross=[0.7, 2e-4], mm_add=[3e-4, 0.0], stake=0.0, k=0.5), None))


def chain_vectors():
    good = vec()
    return (('pass', good, 6), ('zero_rates', dict(good, L=0.0, a=0.0, c=0.0), 3),
            ('fail_first_scale', dict(good, L=-1.0, k=0.25), None),
            ('fail_first_scale_late', dict(good, L=-1e-3, k=1.0, a=0.0), None),
            ('fail_third_scale', dict(good, L=0.0, a=0.0, k=0.0, c=0.18), 5),
            ('fail_third_scale_late', dict(good, L=0.0, a=0.0, k=1.0, c=0.0845), 12))


def patched_bound(data, bound):
    return {BOUND_SITE + 5 + i: (bound >> (8 * i)) & 0xff for i in range(4)}


def chain_results(data, code, ctx_img):
    rows = []
    for name, v, bound in chain_vectors():
        img = Image(data, patched_bound(data, bound)) if bound else ctx_img
        c = decode_all(img) if bound else code
        res = run_entry(img, c, v)
        limit = bound or 2000
        want = grid_model(v, limit)
        if bound is None and want is None:
            raise EvidenceError(f'{name}: the unpatched vector must fail early')
        order = [(m, n) for m in SCALES for n in range(1, limit + 1)]
        if want is not None:
            order = order[:order.index((want['m'], want['n'])) + 1]
        if res['log'] != order:
            raise EvidenceError(f'{name}: call order {res["log"][:4]}')
        if res['tag'] != (2 if want is None else EXITS[want['exit']][1]):
            raise EvidenceError(f'{name}: tag {res["tag"]}')
        rows.append(dict(name=name, bound=bound or BOUND, patched=bool(bound), calls=len(res['log']), tag=res['tag'],
                         first_failure=None if want is None else want['exit'],
                         last_call=None if not res['log'] else f"{res['log'][-1][0]}/{res['log'][-1][1]}"))
    return rows


def floors_results(data, code, ctx_img):
    rows = []
    for name, f, bound in floors_vectors():
        img = Image(data, patched_bound(data, bound)) if bound else ctx_img
        c = decode_all(img) if bound else code
        res = run_floors(img, c, f)
        view = floors_view(f)
        got = dict(zip(ENV_NAMES, res['env']))
        for key, name2 in (('L', 'cross_low'), ('r', 'referral'), ('k', 'keep'), ('a', 'add_low'), ('c', 'first_cross')):
            if got[name2] != view[key]:
                raise EvidenceError(f'{name}: env {name2} {got[name2]} != {view[key]}')
        limit = bound or 3000
        want = grid_model(dict(vec(), **view), limit)
        if bound is None and want is None:
            raise EvidenceError(f'{name}: the unpatched vector must fail early')
        if res['ok'] != (1 if want is None else 0):
            raise EvidenceError(f'{name}: floors returned {res["ok"]}')
        if res['machine'].heap.live:
            raise EvidenceError(f'{name}: text not freed')
        last = res['log'][-1]
        if want is None and len(res['log']) != 4 * limit:
            raise EvidenceError(f'{name}: {len(res["log"])} calls')
        if want is not None and last != (want['m'], want['n']):
            raise EvidenceError(f'{name}: last call {last}')
        rows.append(dict(name=name, bound=bound or BOUND, patched=bool(bound), calls=len(res['log']), accepted=bool(res['ok']),
                         first_failure=None if want is None else want['exit'], last_call=f'{last[0]}/{last[1]}'))
    return rows


def range_results(code, img):
    v = vec()
    rows = []
    for start, end, flag, want in ((BOUND - 9, BOUND, 0, list(range(BOUND - 9, BOUND + 1))), (BOUND, BOUND, 0, [BOUND]),
                                   (5, 4, 0, []), (5, 7, 1, [])):
        log, tag = run_range(img, code, v, start, end, flag)
        if [n for _, n in log] != want or tag != 2:
            raise EvidenceError(f'range {start}..={end}: {log} {tag}')
        rows.append(dict(start=start, end=end, exhausted=flag, calls=len(log), last=want[-1] if want else None))
    return rows


# ---- study of what the grid can add to the rest of the ladder


def margin_inputs(rng, margin):
    """Rates that satisfy every condition of the claim except, when margin < 0, the keep margin."""
    c = rng.pick((1e-3, 7e-4, 4.5e-4, 3e-4, 1.5e-4, 1e-4, 3.3e-5))
    word = rng.pick((1.0, 0.9, 0.5, 0.25))
    last = c * rng.pick((1.0, 0.75, 0.5, 0.1))
    L = word * last
    r = rng.pick((0.0, 0.01, 0.04, 0.1, 0.33, 0.5, 0.9))
    k = rng.pick((0.0, 0.05, 0.1, 0.25, 1.0 / 3.0, 0.5, 0.75, 0.9))
    keep_net = (1.0 - k) * ((1.0 - r) * L)
    a = rng.pick((1e-3, 1e-4, 0.0)) if rng.next() % 4 == 0 else FLOOR - keep_net + margin
    return dict(L=L, r=r, k=k, a=a, c=c)


def hot_ns(v, m):
    """ntli just below, at and above each multiple of a unit of each product, plus a dense head."""
    out = set(range(1, 321))
    for unit in ((1.0 - v['r']) * v['L'] * m, abs(v['a'] * m), v['c'] * m):
        if unit > 0.0:
            for j in range(1, 60):
                base = int(j / unit)
                out.update(x for x in (base - 1, base, base + 1, base + 2) if 1 <= x <= BOUND)
    out.add(BOUND)
    return sorted(out)


def study(rounds=2000):
    """Claim side: no failure.  Control side: the same search fails at once without the margin."""
    rows = dict(claim_rates=0, claim_points=0, claim_failures=0, control_rates=0, control_points=0, control_failures={})
    rng = Lcg(0x94f10)
    for _ in range(rounds):
        v = margin_inputs(rng, 0.0)
        if (1.0 - v['k']) * (1.0 - v['r']) * v['L'] + v['a'] < FLOOR:
            continue
        if not (-1e-3 <= v['a'] <= 1e-3):
            continue
        rows['claim_rates'] += 1
        for m in SCALES:
            for n in hot_ns(v, m):
                rows['claim_points'] += 1
                if point_model(dict(v, m=m, n=n))['exit'] != 'ok':
                    rows['claim_failures'] += 1
    rng = Lcg(0x94f11)
    for _ in range(rounds // 10):
        v = margin_inputs(rng, -1.5 * 2e-4)
        rows['control_rates'] += 1
        hit = None
        for m in SCALES:
            for n in hot_ns(v, m):
                rows['control_points'] += 1
                ex = point_model(dict(v, m=m, n=n))['exit']
                if ex != 'ok':
                    hit = ex
                    break
            if hit:
                break
        if hit:
            rows['control_failures'][hit] = rows['control_failures'].get(hit, 0) + 1
    return rows


def ladder_gap(img, code):
    """A negative word at floors +0x48: first failing ntli by bisection, both sides run from the bytes."""
    v = vec(L=-0.01 * 3e-4, r=0.04, k=0.25, a=1e-4, c=4.5e-4, m=1.0)
    low, high = 1, BOUND
    while high - low > 1:
        mid = (low + high) // 2
        if point_model(dict(v, n=mid))['exit'] == 'ok':
            low = mid
        else:
            high = mid
    rows = {}
    for n in (low, high):
        _, res = run_point(img, code, dict(v, n=n))
        if res['mismatch']:
            raise EvidenceError(f'gap {n}: {res}')
        rows[str(n)] = res['exit']
    if rows != {str(low): 'ok', str(high): 'discounted_fee'}:
        raise EvidenceError(f'gap {rows}')
    return dict(word=-0.01, last_cross=3e-4, referral=0.04, keep=0.25, add_low=1e-4, scale=1.0, last_pass=low, first_reject=high,
                exits=rows)


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


def survey(data, listing, vecs, img):
    sites = [dict(kind='flip', va=s[0], op=s[3], patch={s[1]: s[2]}) for s in conditional_sites(listing)]
    for va, what in ((ONE_ADDR, 'one'), (LOW_ADDR, 'low'), (HIGH_ADDR, 'high'), (BELOW_ADDR, 'below')):
        raw = img.read(va, 8)
        sites.append(dict(kind='constant', va=va, op=what, patch={va + 6: raw[6] ^ 0x10}))
    order = list(range(len(vecs)))
    rows, survivors = [], []
    for s in sites:
        mimg = Image(data, s['patch'])
        code = code_of(mimg, (POINT,))
        killed = None
        for pos, idx in enumerate(order):
            try:
                _, res = run_point(mimg, code, vecs[idx])
                bad = res['mismatch']
            except (Unmodelled, EvidenceError, KeyError, OverflowError, ValueError, Panic) as exc:
                bad = f'fault {type(exc).__name__}'
            if bad:
                killed = (idx, bad)
                order.insert(0, order.pop(pos))
                break
        rows.append(dict(s, killed=killed))
        if killed is None:
            survivors.append(s['va'])
    return rows, survivors


def code_of(img, starts):
    code = {}
    for s in starts:
        code.update({i.va: i for i in decode_range(img, s, FDE_END[s])})
    return code


def decode_all(img):
    return code_of(img, DECODED)


FDE_END = {}


def bind_fdes(data):
    fdes = Fdes(data)
    for s in DECODED:
        FDE_END[s] = fdes.range_of(s)['end']
    return fdes


def format_row(img, name, va):
    """The literal pieces: <len><text>, 0xc0 placeholder, next length; ends with 0x00."""
    raw = img.read(va, 160)
    i, parts = 0, []
    while raw[i]:
        n = raw[i]
        i += 1
        if n == 0xc0:
            n = raw[i]
            i += 1
            parts.append('{}')
            if n == 0:
                break
        parts.append(raw[i:i + n].decode())
        i += n
    text = ''.join(parts)
    return dict(exit=name, va=hex(va), text=text.replace(AT, '[at]'), bytes=hex(i), variant=EXITS[name][1])


def location(img, slot):
    target = img.relative(slot)
    size, line, col = struct.unpack('<QII', img.read(slot + 8, 16))
    path = img.read(target, size).decode()
    return dict(slot=hex(slot), path=path[path.index('l1/src/'):], line=line, col=col, length=size)


def callers(img, targets):
    """Direct `call rel32` sites of each target, from the bytes of .text."""
    addr, off, size, _ = img.sec['.text']
    blob, found = img.data, {t: [] for t in targets}
    i = blob.find(b'\xe8', off, off + size)
    pack = struct.Struct('<i').unpack_from
    while i != -1 and i + 5 <= off + size:
        va = addr + i - off
        t = va + 5 + pack(blob, i + 1)[0]
        if t in found:
            found[t].append(va)
        i = blob.find(b'\xe8', i + 1, off + size)
    return found


def facts(img, listing_scale):
    """Immediates of the inclusive range, by decoded instruction."""
    words = {}
    for ins in listing_scale:
        if ins.op == 'mov' and ins.ops[0][0] == 'm' and ins.ops[0][1] == R['rsp'] and ins.ops[1][0] == 'i':
            words[ins.ops[0][4]] = (ins.va, ins.ops[1][1], ins.ops[0][6])
    return {k: v for k, v in words.items() if k in (0x38, 0x40, 0x48)}


def scale_list(img, listing):
    """The two movupd of the list in the floors, read from .rodata."""
    loads = [i for i in listing if i.op == 'movupd' and i.ops[0][0] == 'x' and i.ops[1][0] == 'm' and i.ops[1][1] is None]
    return [(hex(i.va), hex(i.ops[1][4]), struct.unpack('<2d', img.read(i.ops[1][4], 16))) for i in loads]


def build(data):
    check_digest(data)
    bind_fdes(data)
    img = Image(data)
    code = decode_all(img)
    return img, code


def fnum(x):
    return x.hex() if isinstance(x, float) else str(x)


def generate(data, out_dir):
    img, code = build(data)
    listing = {s: decode_range(img, s, FDE_END[s]) for s in DECODED}
    vecs = point_vectors()
    seen = set()
    res = run_vectors(img, code, vecs, seen)
    if any(i.va not in seen and not any(a <= i.va < b for a, b, _ in UNEXECUTED) for i in listing[POINT]):
        missing = [hex(i.va) for i in listing[POINT] if i.va not in seen]
        raise EvidenceError(f'unlisted unexecuted instructions {missing[:12]}')
    if any(not any(a <= i.va < b for a, b, _ in UNEXECUTED) and i.va not in seen for i in listing[POINT]):
        raise EvidenceError('coverage')
    chain = chain_results(data, code, img)
    floors = floors_results(data, code, img)
    ranges = range_results(code, img)
    rows, survivors = survey(data, listing[POINT], vecs, img)
    if set(survivors) - set(EQUIVALENT):
        raise EvidenceError(f'survivors {[hex(s) for s in survivors]}')
    gap = ladder_gap(img, code)
    st = study()
    if st['claim_failures'] or not st['control_failures']:
        raise EvidenceError(f'study {st}')
    seen_exit = {}
    groups = {}
    for v, r in zip(vecs, res):
        want = point_model(v)
        seen_exit[want['exit']] = seen_exit.get(want['exit'], 0) + 1
        groups[v['group']] = groups.get(v['group'], 0) + 1
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    with open(out / 'vectors.tsv', 'w', newline='\n') as f:
        f.write('group\tL\tr\tk\ta\tc\tm\tn\ttag\tcap\tpos\tbest\tboundary\trace\texit\td\tkeep\ta_int\tnet\tf\tfk\twhole\trecorded\n')
        for v in vecs:
            w = point_model(v)
            cells = [v['group']] + [fnum(v[x]) for x in ('L', 'r', 'k', 'a', 'c', 'm')]
            cells += [str(v[x]) for x in ('n', 'tag', 'cap', 'pos', 'best', 'boundary', 'race')]
            cells += [w['exit']] + [str(w.get(x, '')) for x in ('d', 'keep', 'a', 'net', 'f', 'fk', 'whole')]
            cells.append(','.join(hex(x) for x in w['recorded']))
            f.write('\t'.join(cells) + '\n')
    with open(out / 'chain.tsv', 'w', newline='\n') as f:
        f.write('level\tname\tbound\tpatched_bound\tpoint_calls\tresult\tfirst_failure\tlast_call\n')
        for r in chain:
            f.write(f"entry\t{r['name']}\t{r['bound']}\t{r['patched']}\t{r['calls']}\ttag={r['tag']}\t{r['first_failure']}\t{r['last_call']}\n")
        for r in floors:
            f.write(f"floors\t{r['name']}\t{r['bound']}\t{r['patched']}\t{r['calls']}\taccepted={r['accepted']}\t{r['first_failure']}\t{r['last_call']}\n")
    with open(out / 'mutations.tsv', 'w', newline='\n') as f:
        f.write('kind\tva\tinstruction\tresult\tvector\treason\n')
        for r in rows:
            k = r['killed']
            f.write(f"{r['kind']}\t{r['va']:#x}\t{r['op']}\t{'killed' if k else 'equivalent'}\t{k[0] if k else ''}\t{k[1] if k else EQUIVALENT[r['va']]}\n")
    with open(out / 'instructions.tsv', 'w', newline='\n') as f:
        f.write('va\tsize\tbytes\tdecoded\texecuted\n')
        for i in listing[POINT]:
            f.write(f'{i.va:#x}\t{i.size}\t{i.raw.hex()}\t{show(i)}\t{int(i.va in seen)}\n')
    with open(out / 'reference-diff.tsv', 'w', newline='\n') as f:
        f.write('verdict\treference\treference_says\tbytes_say\n')
        for r in REFERENCE_ROWS:
            f.write('\t'.join(r) + '\n')
    calls = callers(img, (POINT, ENTRY, SCALE_BRIDGE, SCALE_LEAF, RANGE, RANGE_LEAF))
    evidence = dict(
        binary=BINARY, sha256=SHA256,
        functions={hex(s): dict(end=hex(FDE_END[s]), instructions=len(listing[s])) for s in DECODED},
        callers={hex(k): [hex(x) for x in v] for k, v in calls.items()},
        bound={str(k): dict(va=hex(v[0]), value=v[1], bits=v[2]) for k, v in sorted(facts(img, listing[SCALE_LEAF]).items())},
        scale_list=scale_list(img, listing[FLOORS]),
        range_runs=ranges,
        formats=[format_row(img, name, EXITS[name][0]) for name in EXITS],
        locations=dict(ntli_sum=location(img, LOC_NTLI), whole=location(img, LOC_SUM), try_from=location(img, LOC_TRY)),
        constants={k: img.read(v, 8)[::-1].hex() for k, v in (('one', ONE_ADDR), ('low', LOW_ADDR), ('high', HIGH_ADDR),
                                                              ('below', BELOW_ADDR))},
        vectors=len(vecs), groups=groups, exits=seen_exit,
        point_instructions=len(listing[POINT]), point_executed=sum(i.va in seen for i in listing[POINT]),
        unexecuted=[dict(start=hex(a), end=hex(b), why=w) for a, b, w in UNEXECUTED],
        mutants=len(rows), killed=sum(1 for r in rows if r['killed']), equivalent={hex(k): v for k, v in EQUIVALENT.items()},
        study=st, ladder_gap=gap,
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
    print(json.dumps(dict(vectors=ev['vectors'], mutants=ev['mutants'], killed=ev['killed'], study=ev['study']), sort_keys=True))


if __name__ == '__main__':
    main()
