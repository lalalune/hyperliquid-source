#!/usr/bin/env python3
"""fees: node #94 open order cap gate, from bytes alone.

Static, no execution of the node.  Six functions start with the same gate: 0x271b220,
0x271bb40, 0x4d19d40, 0x4d1a670, 0x4d1afa0 and 0x4d1b8b0.  They are decoded from their ELF
bytes by the table decoder below, which must land exactly on each FDE end.  The gate is
interpreted in Python from the function entry up to the first instruction after the gate,
with the real count lookup, the real volume lookups and the real address predicate.  The
hash function, the clock, the overflow recorder and the observer are stubs.  Each outcome
is compared with a separate closed-form model, then every conditional branch and every
gate constant is mutated to test the vectors.

    python3 tools/fees_open_order_cap.py --out <dir>

writes evidence.json, copies.tsv, addresses.tsv, instructions.tsv, mutations.tsv,
reference-diff.tsv and vectors.tsv.  Section and FDE parsing come from tools/elf_index.py
and tools/fde_extents.py.  Only the standard library is used: no objdump, readelf or other
external program runs, so the results cannot depend on a binutils version.
"""

import argparse
import bisect
import hashlib
import json
import math
import struct
import sys
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


class Stop(Exception):
    """The run reached the first instruction after the gate."""

    def __init__(self, va):
        super().__init__(va)
        self.va = va


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
    p66 = rep = False
    while code[i] in (0x66, 0xf2, 0xf3, 0x2e):
        p66 |= code[i] == 0x66
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
        return Insn(va, i - start, op, ops, bits or width, bytes(code[start:i]))

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
        self.stops = frozenset()

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

    def run(self, entry, limit=60000):
        rip = entry
        for _ in range(limit):
            ins = self.code.get(rip)
            if ins is None:
                raise Unmodelled(f'no instruction at {rip:#x}')
            if rip in self.stops:
                raise Stop(rip)
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
            elif op == 'tzcnt':
                a = self.rd(ops[1])
                res = (a & -a).bit_length() - 1 if a else ins.width
                self.cf, self.zf = a == 0, res == 0
                self.wr(ops[0], res)
            else:
                self.do_sse(ins)
            rip = nxt
        raise Unmodelled('step limit')


CAP_LOW, CAP_FLAGGED, CAP_STEP, CAP_BONUS = 1000, 10000, 500000000, 4000
TAG_TOO_MANY, TAG_OK = 0xc3, 0x186
DISPLAY_TABLE = 0x59a8d0
STRIDE_DEX, DEX_MAP, BASE_MAP = 0x2f0, 0xf8, 0x80
SLOT_ENABLED, SLOT_FREE, SLOT_ONCE = 0x576e8f8, 0x576e010, 0x576e8b8
SLOT_BASE, SLOT_RECORD, SLOT_FLAGGED, SLOT_ID = 0x5773170, 0x5773190, 0x5773228, 0x576e890
CLOCK_NOW, CLOCK_DIFF = 0x4ee3800, 0x4ee3730
DEX_LOOKUP, BASE_LOOKUP, FLAGGED = 0x36f57f0, 0x371b3a0, 0x37e4fb0
GOT_COUNT_DEFAULT = 0x57749b8
DEX_DEFAULT, BASE_DEFAULT = 0x57862a0, 0x5786308
LOC_DEX, LOC_SCALED, LOC_RAW = 0x5715e68, 0x56eb3e8, 0x56eb430
MAGIC, MAGIC_SHIFT = 0x44b82fa09b5a53, 75
DEX_SPLIT_MAGIC = 0x346dc5d63886594b
OTHER_BONUS_COMPARES = [0x3261c40]  # compares a different value, see the README

# entry, first instruction after the gate, count lookup, counter, volume Vec, observer, reject payload
COPIES = (
    dict(entry=0x271b220, stop=0x271b45d, lookup=0x2755400, counter=0x888, vec=0x5c0, obs=0x3a88, payload=False),
    dict(entry=0x271bb40, stop=0x271bd55, lookup=0x2755400, counter=0x888, vec=0x5c0, obs=0x3a88, payload=True),
    dict(entry=0x4d19d40, stop=0x4d19f91, lookup=0x46f2e60, counter=0x1308, vec=0x1040, obs=0x4508, payload=False),
    dict(entry=0x4d1a670, stop=0x4d1a8c1, lookup=0x46f2fe0, counter=0x888, vec=0x5c0, obs=0x3a88, payload=False),
    dict(entry=0x4d1afa0, stop=0x4d1b0e8, lookup=0x46f2fe0, counter=0x888, vec=0x5c0, obs=0x3a88, payload=True),
    dict(entry=0x4d1b8b0, stop=0x4d1b9f8, lookup=0x46f2e60, counter=0x1308, vec=0x1040, obs=0x4508, payload=True),
)
HELPERS = (DEX_LOOKUP, BASE_LOOKUP, FLAGGED, 0x2755400, 0x46f2e60, 0x46f2fe0)
HASHES = (0x2840fb0, 0x473bf50, 0x399c7a0)

REFERENCE_ROWS = (
    ('agree', 'l1/scaled_vlm.rs:40', 'bounds 1000 and 10000, step 5e8, bonus 4000',
     'same numbers at all six sites; the step is a shift by 8, a multiply and a shift by 75, proved for every u64'),
    ('agree', 'l1/exchange/impl_trading.rs:26', 'STATUS_ACTION_CAP = 195',
     'same tag 0xc3; its Display arm prints the text in evidence.json, so the name "action cap" is the part that differs'),
    ('agree', 'l1/exchange/impl_trading.rs:125', 'expanded bound needs order_kind == 2 and not reduce_only',
     'byte +0x19 must be 2 and bit 0 of byte +0x31 clear, tested only from 1000 up; the two names stay the reference labels'),
    ('agree', 'l1/exchange/impl_trading.rs:506', 'submitted_order_count saturating add before the check',
     'a word in the state (attempts_word in copies.tsv) goes up by one with saturation before the count is read'),
    ('agree', 'l1/scaled_vlm.rs:277', 'per-dex entries first, then the base entry, saturating',
     'same order and saturation; per-dex adds report to one Location, base adds to scaled_vlm.rs:15:21 and raw_vlm.rs:17:21; the raw sum is checked and then unused'),
    ('differ', 'l1/exchange/impl_trading.rs:1033', 'is_vault_privileged: user[0] != 0 and user[19] == 0',
     'the 10000 bound comes from 0x37e4fb0, a byte compare with the fixed list in addresses.tsv; addresses of the reference shape outside the list stay on the volume bound (vectors)'),
    ('differ', 'l1/exchange/impl_trading.rs:741', 'the check inserts current + 1 into user_action_count',
     'the gate writes one word, the attempts counter; the count map and all other watched state stay byte identical on both routes (checked on every evaluation)'),
    ('differ', 'l1/exchange/impl_trading.rs:762', 'total_scaled_vlm_for_user adds base, main, alt and per_dex maps',
     'the gate adds the per-dex entries and one map at state +0x80, no other map is read: strict state bytes fault on any other read'),
)


def lookup_offsets(listing):
    """`cmp [rdi+items],0` then `mov rcx,[r14+ctrl]` and `mov rsi,[r14+mask]`."""
    items = ctrl = mask = None
    for ins in listing:
        ops = ins.ops
        if items is None and ins.op == 'cmp' and ops[0][0] == 'm' and ops[0][1] == R['rdi']:
            items = ops[0][4]
        if ins.op == 'mov' and ops[1][0] == 'm' and ops[1][1] == R['r14']:
            if ops[0] == ('r', R['rcx'], 64):
                ctrl = ops[1][4]
            elif ops[0] == ('r', R['rsi'], 64):
                mask = ops[1][4]
    if None in (items, ctrl, mask):
        raise EvidenceError('count lookup shape changed')
    return dict(items=items, ctrl=ctrl, mask=mask)


class Context:
    """Everything decoded once; evaluations share it."""

    def __init__(self, data, fdes, patches=None):
        self.img = Image(data, patches)
        self.ranges, self.lists = {}, {}
        for fn in [c['entry'] for c in COPIES] + list(HELPERS):
            r = fdes.range_of(fn)
            self.ranges[fn] = (r['start'], r['end'])
            self.lists[fn] = decode_range(self.img, r['start'], r['end'])
        self.helper_code = {}
        for fn in HELPERS:
            self.helper_code.update({i.va: i for i in self.lists[fn]})
        self.code = {}
        for c in COPIES:
            merged = dict(self.helper_code)
            merged.update({i.va: i for i in self.lists[c['entry']]})
            self.code[c['entry']] = merged
        self.offsets = {fn: lookup_offsets(self.lists[fn]) for fn in (0x2755400, 0x46f2e60, 0x46f2fe0)}
        self.count_default = self.img.relative(GOT_COUNT_DEFAULT)
        self.addresses = address_table(self.lists[FLAGGED], self.img)
        self.default_words = {}
        self.default_rows = []
        for static, once_off, offs in ((self.count_default, 0x40, (0x20,)), (DEX_DEFAULT, 0x60, (0x40, 0x48)),
                                       (BASE_DEFAULT, 0x40, (0, 8))):
            init = self.img.relative(static)
            r = fdes.range_of(init)
            vals = run_default(self.img, decode_range(self.img, r['start'], r['end']), init, offs)
            self.default_words[static + once_off] = [(static + o, val) for o, val in zip(offs, vals)]
            self.default_rows.append(dict(static=hex(static), init=hex(init), once_word=hex(static + once_off),
                                          words={hex(o): val for o, val in zip(offs, vals)}))


def run_default(img, listing, init, offs):
    """Run a lazy default's constructor; the id allocator it calls is a stub."""
    m = Machine(img, listing)
    stack = m.arena(0x400, strict=False)
    out = m.arena(0x60)
    m.regs[R['rsp']] = stack.base + 0x300
    m.regs[R['rdi']] = out.base
    m.stubs[SLOT_ID] = lambda: m.clobber(7)
    m.run(init)
    return [m.load(out.base + o, 8) for o in offs]


def address_table(listing, img):
    """The predicate: each block is movdqu, movd, pcmpeqb, pcmpeqb, pand, pmovmskb, cmp, je."""
    out = []
    for i, ins in enumerate(listing):
        if ins.op == 'pcmpeqb' and ins.ops[1][0] == 'm' and ins.ops[0] == ('x', 1):
            nxt = listing[i + 1]
            if nxt.op != 'pcmpeqb' or nxt.ops[0] != ('x', 0) or nxt.ops[1][0] != 'm':
                raise EvidenceError(f'{ins.va:#x}: predicate block shape changed')
            tail = img.read(ins.ops[1][4], 16)
            if tail[4:] != bytes(12):
                raise EvidenceError(f'{ins.va:#x}: upper bytes of the last word are not zero')
            out.append(img.read(nxt.ops[1][4], 16) + tail[:4])
    if not out:
        raise EvidenceError('no address blocks in the predicate')
    return out


def reachable(listing, code, stop):
    """Instructions reachable from the entry without passing the stop."""
    seen, work = set(), [listing[0].va]
    while work:
        va = work.pop()
        if va in seen or va == stop:
            continue
        ins = code.get(va)
        if ins is None:
            raise EvidenceError(f'walk left the decoded range at {va:#x}')
        seen.add(va)
        if ins.op in ('ret', 'ud2'):
            continue
        if ins.op == 'jmp':
            work.append(ins.ops[0][1])
            continue
        if ins.op == 'jmpr':
            raise EvidenceError(f'{va:#x}: indirect jump inside the gate')
        if ins.op[0] == 'j':
            work.append(ins.ops[0][1])
        work.append(va + ins.size)
    return seen


def division_proof():
    """floor((x >> 8) * MAGIC / 2^75) == floor(x / 5e8) for every u64, exact arithmetic."""
    odd = CAP_STEP >> 8
    if CAP_STEP != odd << 8 or odd & 1 == 0:
        raise EvidenceError('step is not 2^8 times an odd number')
    excess = MAGIC * odd - (1 << MAGIC_SHIFT)
    if excess <= 0:
        raise EvidenceError('multiplier is not above the inverse')
    limit = 1 << 56
    # n * MAGIC / 2^75 == n / odd + n * excess / (odd * 2^75): the error stays below 1 / odd
    holds = (limit - 1) * excess < 1 << MAGIC_SHIFT
    return dict(odd_divisor=odd, excess=excess, top_error_times_2_75=(limit - 1) * excess, holds=holds)


def table(m, stride, key, words, kind):
    """A real swiss table.  Returns (ctrl address, mask, hash, items)."""
    size = 32 if kind == 'next' else 16
    h2, idx = 0x2a, 0
    if kind == 'empty':
        return None, None, h2 << 57, 0
    a = m.arena(size * stride + size + 16)
    base = a.base + size * stride
    for o in range(size + 16):
        m.store(base + o, 1, 0xff)

    def put(i, name, payload):
        ctrl_byte = h2 if name is not None else 0x11
        m.store(base + i, 1, ctrl_byte)
        if i < 16:
            m.store(base + size + i, 1, ctrl_byte)
        if name is None:
            return
        at = base - (i + 1) * stride
        for j, b in enumerate(name):
            m.store(at + j, 1, b)
        for off, val in payload.items():
            m.store(at + off, 8, val)

    if kind == 'direct':
        put(idx, key, words)
    elif kind == 'decoy':
        put(idx, bytes(b ^ 0x5a for b in key), {})
        put(idx + 1, key, words)
    elif kind == 'next':
        for i in range(16):
            put(i, None, {})
        put(16, key, words)
    elif kind != 'missing':
        raise EvidenceError(f'unknown table kind {kind}')
    return base, size - 1, h2 << 57 | idx, 1


def expected_clock_calls(outcome, timing):
    return (2 if timing else 1) + (1 if timing and outcome == 'reject' else 0)


def model(v):
    """The closed form, written from the reading, with no reference to the evaluator."""
    events = [('hash', 'count')] if v['count_kind'] != 'empty' else []
    counter = min(v['counter'] + 1, U64)
    count = v['count'] if v['count_kind'] not in ('missing', 'empty') else 0
    outcome, limit = 'pass', None
    if count >= CAP_LOW:
        if v['b31'] & 1 or v['b19'] != 2:
            outcome = 'reject'
        else:
            if v['user'] in v['flagged_set']:
                limit = CAP_FLAGGED
            else:
                scaled = raw = 0
                for i, (s, r, kind) in enumerate(v['dex']):
                    if kind != 'empty':
                        events.append(('hash', f'dex{i}'))
                    if kind in ('missing', 'empty'):
                        s = r = 0
                    if scaled + s > U64:
                        events.append(('record', LOC_DEX))
                    scaled = min(scaled + s, U64)
                    if raw + r > U64:
                        events.append(('record', LOC_DEX))
                    raw = min(raw + r, U64)
                s, r, kind = v['base']
                if kind != 'empty':
                    events.append(('hash', 'base'))
                if kind in ('missing', 'empty'):
                    s = r = 0
                if scaled + s > U64:
                    events.append(('record', LOC_SCALED))
                scaled = min(scaled + s, U64)
                if raw + r > U64:
                    events.append(('record', LOC_RAW))
                limit = CAP_LOW + min(scaled // CAP_STEP, CAP_BONUS)
            if count >= limit:
                outcome = 'reject'
    if outcome == 'reject':
        if v['tag'] < 2 and v['cap']:
            events.append(('free', VEC_PTR, v['cap'] * 72, 0))
        if v['observer']:
            events.append(('observe', v['user'], TAG_TOO_MANY))
    return outcome, limit, counter, events


VEC_PTR = 0x6100_0000_0040
SAVED = {R[k]: 0x5a5a_0000_0000 + R[k] for k in ('rbx', 'rbp', 'r12', 'r13', 'r14', 'r15')}


def evaluate(ctx, copy, v, code=None):
    """Run one copy from its entry.  Returns outcome, counter, events, clock calls, seen."""
    img = ctx.img
    m = Machine(img, ())
    m.code = code if code is not None else ctx.code[copy['entry']]
    m.stops = frozenset((copy['stop'],))
    m.real = {DEX_LOOKUP: DEX_LOOKUP, copy['lookup']: copy['lookup'], SLOT_BASE: BASE_LOOKUP, SLOT_FLAGGED: FLAGGED}
    stack = m.arena(0x2000, strict=False)
    stack.mem[:] = b'\xa5' * 0x2000
    out = m.arena(0x60)
    state = m.arena(0x5000)
    user = m.arena(0x14)
    for i, b in enumerate(v['user']):
        m.store(user.base + i, 1, b)
    order = m.arena(0x48)
    for i in range(0x48):
        m.store(order.base + i, 1, (0x31 * i + 7) & 0xff)
    m.store(order.base + 0x19, 1, v['b19'])
    m.store(order.base + 0x31, 1, v['b31'])
    vec = m.arena(0x18)
    m.store(vec.base, 8, v['cap'])
    m.store(vec.base + 8, 8, VEC_PTR)
    m.store(vec.base + 16, 8, 3)
    arg7 = m.arena(0x28)
    m.store(arg7.base, 8, v['tag'])
    for off in (8, 0x10, 0x18, 0x20):
        m.store(arg7.base + off, 8, 0x1111 * off)
    m.store(state.base + copy['counter'], 8, v['counter'])

    # the lazy defaults: strict bytes, so a read before its Once has run faults
    m.arenas.append(Arena(0x5786000, 0x1000))
    m.got[GOT_COUNT_DEFAULT] = ctx.count_default
    words = ctx.default_words

    def fill(once_at):
        for at, val in words[once_at]:
            m.store(at, 8, val)

    for once_at in words:
        m.store(once_at, 4, 3 if v['lazy'] else 0)
        if not v['lazy']:
            fill(once_at)

    def install(map_addr, items_off, ctrl_off, mask_off, stride, words, kind):
        base, mask, h, items = table(m, stride, v['user'], words, kind)
        m.store(map_addr + items_off, 8, items)
        if items:
            m.store(map_addr + ctrl_off, 8, base)
            m.store(map_addr + mask_off, 8, mask)
        return h

    offs = ctx.offsets[copy['lookup']]
    count_hash = install(state.base, offs['items'], offs['ctrl'], offs['mask'], 0x58, {0x38: v['count']},
                         v['count_kind'])
    hash_for = {state.base + offs['items'] + 8: (count_hash, 'count')}
    base_hash = install(state.base + BASE_MAP, 0x2b0, 0x298, 0x2a0, 0x58,
                        {0x18: v['base'][0], 0x20: v['base'][1]}, v['base'][2])
    hash_for[state.base + BASE_MAP + 0x2b8] = (base_hash, 'base')
    m.store(state.base + copy['vec'] + 8, 8, len(v['dex']))
    if v['dex']:
        dex = m.arena(STRIDE_DEX * len(v['dex']))
        m.store(state.base + copy['vec'], 8, dex.base)
        for i, (s, r, kind) in enumerate(v['dex']):
            at = dex.base + i * STRIDE_DEX + DEX_MAP
            hash_for[at + 0x20] = (install(at, 0x18, 0, 8, 0x78, {0x58: s, 0x60: r}, kind), f'dex{i}')
    observer = m.arena(0x40)
    m.store(state.base + copy['obs'], 8, observer.base if v['observer'] else 0)
    if v['observer']:
        m.store(state.base + copy['obs'] + 8, 8, observer.base)

    events, clock = [], [0]

    def hash_stub():
        key = bytes(m.load(m.regs[R['rsi']] + i, 1) for i in range(20))
        if key != v['user']:
            raise Unmodelled('hash of a key that is not the user')
        hit = hash_for.get(m.regs[R['rdi']])
        if hit is None:
            raise Unmodelled(f"hash of unknown state {m.regs[R['rdi']]:#x}")
        events.append(('hash', hit[1]))
        m.clobber(hit[0])

    def enabled():
        m.clobber(1 if v['timing'] else 0)

    def clock_now():
        if m.regs[R['rdi']] != 1:
            raise Unmodelled('clock id')
        clock[0] += 1
        m.clobber(1000 + clock[0])
        m.regs[R['rdx']] = 5

    def clock_diff():
        m.clobber()

    def record():
        if m.regs[R['rdi']] & 0xffffffff:
            raise Unmodelled('recorder first argument')
        events.append(('record', m.regs[R['rsi']]))
        m.clobber()

    def free():
        events.append(('free', m.regs[R['rdi']], m.regs[R['rsi']], m.regs[R['rdx']]))
        m.clobber()

    def once():
        fill(m.regs[R['rdi']])
        m.store(m.regs[R['rdi']], 4, 0)
        m.clobber()

    def observe():
        if m.regs[R['rdi']] != observer.base:
            raise Unmodelled('observer object')
        key = bytes(m.load(m.regs[R['rsi']] + i, 1) for i in range(20))
        events.append(('observe', key, m.load(m.regs[R['rdx']], 2)))
        m.clobber()

    m.stubs = {h: hash_stub for h in HASHES}
    m.stubs.update({SLOT_ENABLED: enabled, CLOCK_NOW: clock_now, CLOCK_DIFF: clock_diff, SLOT_RECORD: record,
                    SLOT_FREE: free, SLOT_ONCE: once, observer.base + 0x30: observe})
    watched = [a for a in m.arenas if a not in (stack, out)]
    before = [bytes(a.mem) for a in watched]
    rsp = stack.base + 0x1800 - 8
    m.store(rsp, 8, 0xfeed_0000_0000)
    m.store(rsp + 8, 8, arg7.base)
    m.store(rsp + 0x10, 4, 0x77)
    m.store(rsp + 0x18, 4, 0x88)
    m.regs[R['rsp']] = rsp
    for r, val in SAVED.items():
        m.regs[r] = val
    m.regs[R['rdi']], m.regs[R['rsi']], m.regs[R['rdx']] = out.base, state.base, order.base
    m.regs[R['rcx']], m.regs[R['r8']], m.regs[R['r9']] = user.base, 0x1234, vec.base
    try:
        m.run(copy['entry'])
    except Stop:
        if any(out.valid):
            raise Unmodelled('the pass route wrote the output')
        outcome = 'pass'
    else:
        outcome = 'reject'
        if m.regs[0] != out.base or m.regs[R['rsp']] != rsp + 8:
            raise Unmodelled('return value or stack')
        for r, val in SAVED.items():
            if m.regs[r] != val:
                raise Unmodelled('saved register changed')
        if m.load(out.base, 2) != TAG_TOO_MANY:
            raise Unmodelled(f'reject tag {m.load(out.base, 2):#x}')
        if copy['payload'] and m.load(out.base + 8, 8) != m.load(order.base + 0x28, 8):
            raise Unmodelled('reject payload is not the word at +0x28')
    counter = m.load(state.base + copy['counter'], 8)
    m.store(state.base + copy['counter'], 8, v['counter'])
    for a, old in zip(watched, before):
        if a.base == 0x5786000:
            continue
        if bytes(a.mem) != old:
            raise Unmodelled(f'the gate wrote the arena at {a.base:#x}')
    return outcome, counter, events, clock[0], m.seen


def mismatch(ctx, copy, v, code=None, seen=None):
    """None when the bytes and the model agree, otherwise the reason."""
    want, _, counter, ev = model(v)
    try:
        got, ctr, events, clock, ran = evaluate(ctx, copy, v, code)
    except (Unmodelled, EvidenceError) as e:
        return f'fault: {e}'
    if seen is not None:
        seen |= ran
    if got != want:
        return f'outcome {got} != {want}'
    if ctr != counter:
        return f'counter {ctr} != {counter}'
    if events != ev:
        return f'events {events} != {ev}'
    if clock != expected_clock_calls(want, v['timing']):
        return f'clock calls {clock}'
    return None


class Lcg:
    def __init__(self, seed):
        self.x = seed

    def next(self):
        self.x = (self.x * 6364136223846793005 + 1442695040888963407) & U64
        return self.x >> 11 ^ self.x

    def below(self, n):
        return self.next() % n


PLAIN_USER = bytes(range(0x40, 0x54))
BASE_VECTOR = dict(count=1000, b19=2, b31=0, user=PLAIN_USER, dex=(), base=(0, 0, 'direct'), count_kind='direct',
                   tag=2, cap=0, observer=False, timing=False, lazy=False, counter=0)


def vec(flagged, **kw):
    v = dict(BASE_VECTOR)
    v['flagged_set'] = flagged
    v.update(kw)
    return v


def vectors(addresses):
    flagged = frozenset(addresses)
    out = []

    def add(**kw):
        out.append(vec(flagged, **kw))

    # count boundaries at no volume, and the field bytes
    for c in (0, 999, 1000, 1001, 4999, 5000, 9999, 10000, U64):
        for b19 in (0, 1, 2, 3, 0xff):
            for b31 in (0, 1, 2, 0xff):
                add(count=c, b19=b19, b31=b31)
    # bound boundaries, three ways of splitting the volume
    for k in (0, 1, 2, 3, 999, 1000, 3999, 4000, 4001, 5000, 1 << 20, 1 << 30):
        for d in (-1, 0, 1):
            s = max(k * CAP_STEP + d, 0)
            limit = CAP_LOW + min(s // CAP_STEP, CAP_BONUS)
            for c in (limit - 1, limit, limit + 1):
                add(count=c, base=(s, 0, 'direct'))
                add(count=c, dex=((s, 0, 'direct'),), base=(0, 0, 'direct'))
                add(count=c, dex=((s // 3, 1, 'direct'), (s // 3, 2, 'direct'), (s - 2 * (s // 3), 3, 'direct')),
                    base=(0, 4, 'direct'))
                add(count=c, dex=((s // 2, 0, 'direct'),), base=(s - s // 2, 0, 'direct'))
    # overflow in each position, scaled and raw, at the bound and past it
    top = U64
    for c in (1000, 4999, 5000, 5001):
        add(count=c, dex=((top, 0, 'direct'), (1, 0, 'direct')))
        add(count=c, dex=((top, 0, 'direct'), (top, 0, 'direct'), (5, 0, 'direct')))
        add(count=c, dex=((0, top, 'direct'), (0, 1, 'direct')))
        add(count=c, dex=((0, top, 'direct'), (0, top, 'direct'), (0, 5, 'direct')))
        add(count=c, dex=((top, top, 'direct'), (top, top, 'direct')))
        add(count=c, dex=((top, 0, 'direct'),), base=(1, 0, 'direct'))
        add(count=c, dex=((0, top, 'direct'),), base=(0, 1, 'direct'))
        add(count=c, dex=((top, top, 'direct'),), base=(top, top, 'direct'))
        add(count=c, base=(top, top, 'direct'))
        add(count=c, dex=((top - 1, 0, 'direct'),), base=(1, 0, 'direct'))
        add(count=c, dex=((0, top - 1, 'direct'),), base=(0, 1, 'direct'))
        add(count=c, dex=((top, top, 'direct'), (0, 0, 'direct')), base=(0, 0, 'direct'))
    # flagged addresses: every address, then near misses of the first and last one
    for a in addresses:
        for c in (999, 1000, 9999, 10000, 10001):
            add(count=c, user=a)
        add(count=5000, user=a, b19=1)
        add(count=5000, user=a, b31=1)
    for a in (addresses[0], addresses[-1]):
        for i in range(20):
            miss = a[:i] + bytes((a[i] ^ 1,)) + a[i + 1:]
            add(count=9999, user=miss)
    # the reference's privileged shape, outside the list
    shaped = bytes((1,)) + PLAIN_USER[1:19] + bytes(1)
    for user in (shaped, bytes((0xff,)) + bytes(19)):
        for c in (999, 1000, 1001, 5000, 9999):
            add(count=c, user=user)
            add(count=c, user=user, base=(4000 * CAP_STEP, 0, 'direct'))
    # the lookups: every shape of table, at each of the three maps
    kinds = ('direct', 'decoy', 'next', 'missing', 'empty')
    for k in kinds:
        add(count=1500, count_kind=k)
        add(count=1500, base=(600 * CAP_STEP, 3, k))
        add(count=1500, dex=((600 * CAP_STEP, 3, k),))
        add(count=1500, dex=((600 * CAP_STEP, 3, k), (600 * CAP_STEP, 3, 'direct')), base=(0, 0, k))
        for lazy in (False, True):
            add(count=1500, count_kind=k, lazy=lazy)
            add(count=1500, base=(1, 1, k), dex=((1, 1, k),), lazy=lazy)
    # the reject route: drop, observer, clock
    for tag in (0, 1, 2, 3, U64):
        for cap in (0, 1, 3, 1 << 20):
            for observer in (False, True):
                add(count=5000, tag=tag, cap=cap, observer=observer)
                add(count=5000, b31=1, tag=tag, cap=cap, observer=observer)
    for timing in (False, True):
        for observer in (False, True):
            add(count=999, timing=timing, observer=observer)
            add(count=5000, timing=timing, observer=observer)
            add(count=1000, b19=0, timing=timing, observer=observer, tag=1, cap=2)
    # the attempt counter saturates
    for counter in (0, 7, U64 - 1, U64):
        add(count=999, counter=counter)
        add(count=5000, counter=counter)
    rng = Lcg(0x94)
    for _ in range(300):
        n = rng.below(4)
        pick = lambda: (rng.next() >> rng.below(64), rng.next() >> rng.below(64), kinds[rng.below(5)])
        dex = tuple(pick() for _ in range(n))
        add(count=rng.below(11000), b19=(2, 2, 2, rng.below(4))[rng.below(4)], b31=(0, 0, 0, rng.below(4))[rng.below(4)],
            user=addresses[rng.below(len(addresses))] if rng.below(10) == 0 else PLAIN_USER, dex=dex, base=pick(),
            tag=rng.below(4), cap=rng.below(3), observer=rng.below(2) == 1, timing=rng.below(2) == 1,
            lazy=rng.below(2) == 1, counter=rng.next())
    return out


def run_all(ctx, vecs):
    """Every vector on every copy.  Returns failures and the seen set per copy."""
    seen = {c['entry']: set() for c in COPIES}
    bad = []
    for c in COPIES:
        for n, v in enumerate(vecs):
            why = mismatch(ctx, c, v, seen=seen[c['entry']])
            if why:
                bad.append((c['entry'], n, why))
    return bad, seen


def killed_by(ctx, copy, vecs, code, hot):
    """Vectors that killed before go first, then newest first.  `hot` makes it deterministic and fast."""
    for n in hot + [n for n in range(len(vecs) - 1, -1, -1) if n not in hot]:
        why = mismatch(ctx, copy, vecs[n], code)
        if why:
            if n not in hot:
                hot.append(n)
            return n, why
    return None


def patched_insn(ins, raw):
    return decode_one(bytes(raw) + b'\x90' * 16, 0, ins.va)


def flip_raw(ins):
    raw = bytearray(ins.raw)
    i = 0
    while raw[i] in (0x66, 0xf2, 0xf3, 0x2e):
        i += 1
    if raw[i] & 0xf0 == 0x70:
        raw[i] ^= 1
    elif raw[i] == 0x0f and raw[i + 1] & 0xf0 == 0x80:
        raw[i + 1] ^= 1
    else:
        raise EvidenceError(f'{ins.va:#x}: not a conditional jump')
    return raw


GATE_IMMS = {0x3e8: 'low bound', 0x2710: 'flagged bound', 0xfa0: 'bonus cap', 0xc3: 'tag', MAGIC: 'multiplier',
             8: 'pre-shift', 0xb: 'post-shift', 2: 'field value', 0x2f0: 'dex stride', 0xf8: 'dex map', 0x80: 'base map'}


def imm_mutation(ins):
    """Flip bit 0 of the immediate, which every listed gate instruction keeps as its last byte(s)."""
    ops = [o for o in ins.ops if o[0] == 'i']
    if len(ops) != 1 or ins.op in ('sub', 'push') or ops[0][1] & U64 not in GATE_IMMS:
        return None
    val = ops[0][1] & U64
    raw = bytearray(ins.raw)
    size = next((n for n in (1, 2, 4, 8) if int.from_bytes(raw[-n:], 'little') == val), None)
    if size is None:
        raise EvidenceError(f'{ins.va:#x}: immediate not at the end of the instruction')
    # bit 0 of the compare would give 0xfa1, which the cmov after it makes equivalent: x = 4000 picks 4000 either way
    raw[-size] ^= 2 if val == 0xfa0 and ins.op == 'cmp' else 1
    return raw, GATE_IMMS[val]


def survey(ctx, vecs, hot):
    """Flip every conditional jump and every gate constant of the gate, on every copy."""
    rows = []
    for c in COPIES:
        entry = c['entry']
        code = ctx.code[entry]
        gate = reachable(ctx.lists[entry], code, c['stop'])
        for va in sorted(gate):
            ins = code[va]
            muts = []
            if ins.op[0] == 'j' and ins.op not in ('jmp', 'jmpr'):
                muts.append((flip_raw(ins), 'branch'))
            else:
                got = imm_mutation(ins)
                if got:
                    muts.append(got)
            for raw, label in muts:
                new = dict(code)
                new[va] = patched_insn(ins, raw)
                hit = killed_by(ctx, c, vecs, new, hot)
                rows.append((entry, va, label, show(ins), hit))
    return rows


def helper_survey(ctx, vecs, hot):
    """The same flips in the lookups and the predicate, through the copies that call them."""
    rows = []
    for fn, c in ((0x2755400, COPIES[0]), (0x46f2e60, COPIES[2]), (0x46f2fe0, COPIES[3]), (DEX_LOOKUP, COPIES[0]),
                  (BASE_LOOKUP, COPIES[0]), (FLAGGED, COPIES[0])):
        code = ctx.code[c['entry']]
        for ins in ctx.lists[fn]:
            if ins.op[0] == 'j' and ins.op not in ('jmp', 'jmpr'):
                new = dict(code)
                new[ins.va] = patched_insn(ins, flip_raw(ins))
                rows.append((fn, ins.va, 'branch', show(ins), killed_by(ctx, c, vecs, new, hot)))
    return rows


def too_many_text(img):
    """Tag 0xc3 in the Display jump table, then the `lea rsi` and `mov edx` of that arm."""
    off = struct.unpack('<i', img.read(DISPLAY_TABLE + 4 * TAG_TOO_MANY, 4))[0]
    arm = DISPLAY_TABLE + off
    raw = img.read(arm, 0x17)
    want = bytes.fromhex('488b3e488b4608488b4018488d35')
    if raw[:14] != want or raw[18] != 0xba:
        raise EvidenceError(f'{arm:#x}: Display arm shape changed')
    disp = struct.unpack_from('<i', raw, 14)[0]
    size = struct.unpack_from('<I', raw, 19)[0]
    text = img.read(arm + 18 + disp, size)
    return arm, arm + 18 + disp, text.decode('ascii')


def location(img, slot):
    """A Rust Location: pointer word (via .rela.dyn), length, line, column."""
    ptr = img.relative(slot)
    size, line, col = struct.unpack('<QII', img.read(slot + 8, 16))
    text = img.read(ptr, size).decode('ascii')
    cut = text.find('l1/src/')
    return dict(slot=hex(slot), file=text[cut:] if cut >= 0 else text[text.find('library/'):], byte_length=size,
                line=line, column=col)


def callers(data, img, starts, ends, targets):
    """Pattern scan: e8 rel32 landing on a target, inside a known FDE."""
    t_va, t_off, t_size, _ = img.sec['.text']
    code = data[t_off:t_off + t_size]
    found = {t: [] for t in targets}
    i = code.find(b'\xe8')
    limit = len(code) - 5
    unpack = struct.Struct('<i').unpack_from
    while i != -1 and i <= limit:
        target = t_va + i + 5 + unpack(code, i + 1)[0]
        if target in found:
            found[target].append(t_va + i)
        i = code.find(b'\xe8', i + 1)
    out = {}
    for t, sites in found.items():
        rows = []
        for s in sites:
            k = bisect.bisect_right(starts, s) - 1
            rows.append((s, starts[k] if k >= 0 and s < ends[k] else None))
        out[t] = rows
    return out


def location_sites(img, data, slots):
    """Pattern scan: 48/4c 8d modrm(mod 0, rm 5) disp32 landing on a Location record."""
    t_va, t_off, t_size, _ = img.sec['.text']
    code = data[t_off:t_off + t_size]
    found = dict.fromkeys(slots, 0)
    i = code.find(b'\x8d', 1)
    limit = len(code) - 6
    unpack = struct.Struct('<i').unpack_from
    while i != -1 and i <= limit:
        if code[i + 1] & 0xc7 == 5 and code[i - 1] in (0x48, 0x4c):
            target = t_va + i + 6 + unpack(code, i + 2)[0]
            if target in found:
                found[target] += 1
        i = code.find(b'\x8d', i + 1)
    return found


def bonus_sites(img, data, starts, ends):
    """Pattern scan: REX.W cmp r64, 4000 in .text, and the FDE that holds each hit."""
    t_va, t_off, t_size, _ = img.sec['.text']
    code = data[t_off:t_off + t_size]
    out = []
    i = code.find(b'\xa0\x0f\x00\x00')
    while i != -1:
        if code[i - 3] in (0x48, 0x49) and code[i - 2] == 0x81 and code[i - 1] & 0xf8 == 0xf8:
            va = t_va + i - 3
            k = bisect.bisect_right(starts, va) - 1
            out.append((va, starts[k] if k >= 0 and va < ends[k] else None))
        i = code.find(b'\xa0\x0f\x00\x00', i + 1)
    return out


def build(data):
    check_digest(data)
    fdes = Fdes(data)
    ctx = Context(data, fdes)
    return fdes, ctx


def reason_kind(why):
    """The first word of a failure, without run-specific addresses."""
    return why.split(':')[0].split(' ')[0]


def write_tsv(path, header, rows):
    with open(path, 'w', encoding='ascii', newline='\n') as f:
        f.write('\t'.join(header) + '\n')
        for r in rows:
            f.write('\t'.join(str(x) for x in r) + '\n')


def vector_row(n, v):
    outcome, limit, _, events = model(v)
    dex = '|'.join(f'{s}:{r}:{k}' for s, r, k in v['dex']) or '-'
    return (n, v['count'], v['count_kind'], v['b19'], v['b31'], v['user'].hex(), int(v['user'] in v['flagged_set']), dex,
            f"{v['base'][0]}:{v['base'][1]}:{v['base'][2]}", v['tag'], v['cap'], int(v['observer']), int(v['timing']),
            int(v['lazy']), v['counter'], outcome, limit if limit is not None else '-',
            sum(1 for e in events if e[0] == 'record'), sum(1 for e in events if e[0] == 'hash'))


def generate(data, out_dir):
    fdes, ctx = build(data)
    img = ctx.img
    vecs = vectors(ctx.addresses)
    bad, seen = run_all(ctx, vecs)
    if bad:
        raise EvidenceError(f'{len(bad)} mismatches, first {bad[:3]}')
    copies, listing = [], []
    for c in COPIES:
        entry = c['entry']
        code = ctx.code[entry]
        gate = reachable(ctx.lists[entry], code, c['stop'])
        missed = sorted(gate - seen[entry])
        if missed:
            raise EvidenceError(f'{entry:#x}: unexecuted gate instructions {[hex(x) for x in missed[:12]]}')
        split = any(o == ('i', DEX_SPLIT_MAGIC) for i in ctx.lists[entry] for o in i.ops)
        copies.append(dict(c, end=ctx.ranges[entry][1], insns=len(ctx.lists[entry]), gate=len(gate), split=split))
        listing.extend((entry, va, code[va].raw.hex(), show(code[va])) for va in sorted(gate))
    helper_rows = []
    for fn in HELPERS:
        lst = ctx.lists[fn]
        ran = {i.va for i in lst} & set().union(*seen.values())
        idle = [i for i in lst if i.va not in ran]
        if any(i.op != 'nop' for i in idle):
            raise EvidenceError(f'{fn:#x}: unexecuted code {[show(i) for i in idle]}')
        helper_rows.append((fn, ctx.ranges[fn][1], len(lst), len(ran), [hex(i.va) for i in idle]))
    hot = []
    rows = survey(ctx, vecs, hot) + helper_survey(ctx, vecs, hot)
    survivors = [r for r in rows if r[4] is None]
    if survivors:
        raise EvidenceError(f'{len(survivors)} surviving mutants, first {[(hex(r[0]), hex(r[1]), r[2], r[3]) for r in survivors[:20]]}')
    starts = sorted(fdes.by_start)
    ends = [fdes.by_start[s]['end'] for s in starts]
    calls = callers(data, img, starts, ends, [c['entry'] for c in COPIES])
    sites = location_sites(img, data, (LOC_DEX, LOC_SCALED, LOC_RAW))
    compares = bonus_sites(img, data, starts, ends)
    extra = [f for _, f in compares if f not in {c['entry'] for c in COPIES}]
    if extra != OTHER_BONUS_COMPARES or len(compares) != len(COPIES) + len(extra):
        raise EvidenceError(f'4000 compares changed: {compares}')
    arm, text_va, text = too_many_text(img)
    proof = division_proof()
    if not proof['holds']:
        raise EvidenceError('division proof failed')
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    write_tsv(out / 'copies.tsv', ('entry', 'fde_end', 'insns', 'gate_insns', 'after_gate', 'count_lookup', 'attempts_word',
                                   'volume_vec_word', 'observer_word', 'reject_writes_word_28', 'divides_by_10000_after_gate',
                                   'call_sites'),
              [(hex(c['entry']), hex(c['end']), c['insns'], c['gate'], hex(c['stop']), hex(c['lookup']), hex(c['counter']),
                hex(c['vec']), hex(c['obs']), int(c['payload']), int(c['split']),
                ' '.join(f"{s:#x}/{(f or 0):#x}" for s, f in calls[c['entry']])) for c in copies])
    write_tsv(out / 'addresses.tsv', ('index', 'address', 'reference_shape'),
              [(i, '0x' + a.hex(), int(a[0] != 0 and a[19] == 0)) for i, a in enumerate(ctx.addresses)])
    write_tsv(out / 'instructions.tsv', ('copy', 'va', 'bytes', 'decoded'), [(hex(a), hex(b), r, s) for a, b, r, s in listing])
    write_tsv(out / 'mutations.tsv', ('function', 'va', 'kind', 'decoded', 'killed_by_vector', 'reason'),
              [(hex(f), hex(va), k, s, h[0], reason_kind(h[1])) for f, va, k, s, h in rows])
    write_tsv(out / 'reference-diff.tsv', ('verdict', 'reference', 'reference_says', 'bytes_say'), REFERENCE_ROWS)
    write_tsv(out / 'vectors.tsv', ('n', 'count', 'count_table', 'byte_19', 'byte_31', 'user', 'listed', 'dex', 'base', 'word_0',
                                    'cap', 'observer', 'timing', 'lazy', 'attempts', 'outcome', 'bound', 'records', 'lookups'),
              [vector_row(n, v) for n, v in enumerate(vecs)])
    outcomes = [model(v)[0] for v in vecs]
    entries = {c['entry'] for c in COPIES}
    evidence = dict(
        target=dict(path=BINARY, sha256=SHA256),
        copies=len(COPIES), vectors=len(vecs), evaluations=len(vecs) * len(COPIES), mismatches=0,
        outcomes=dict(passed=outcomes.count('pass'), rejected=outcomes.count('reject')),
        gate_insns=sum(c['gate'] for c in copies), gate_insns_executed=sum(c['gate'] for c in copies),
        helpers=[dict(function=hex(f), fde_end=hex(e), insns=n, executed=x, unexecuted_padding_nops=p)
                 for f, e, n, x, p in helper_rows],
        count_lookup_offsets={hex(k): {a: hex(b) for a, b in v.items()} for k, v in ctx.offsets.items()},
        lazy_defaults=ctx.default_rows,
        constants=dict(low_bound=CAP_LOW, flagged_bound=CAP_FLAGGED, step=CAP_STEP, bonus_cap=CAP_BONUS,
                       multiplier=hex(MAGIC), pre_shift=8, total_shift=MAGIC_SHIFT),
        division_proof=dict(proof, holds=True, scope='every u64 scaled total'),
        listed_addresses=len(ctx.addresses), list_function=hex(FLAGGED), list_slot=hex(SLOT_FLAGGED),
        reject=dict(tag=hex(TAG_TOO_MANY), display_arm=hex(arm), text_va=hex(text_va), text=text),
        locations=dict(per_dex=location(img, LOC_DEX), base_scaled=location(img, LOC_SCALED), base_raw=location(img, LOC_RAW)),
        location_lea_sites=dict(per_dex=sites[LOC_DEX], base_scaled=sites[LOC_SCALED], base_raw=sites[LOC_RAW]),
        compares_with_4000=[dict(va=hex(a), function=hex(f)) for a, f in compares],
        mutants=dict(total=len(rows), killed=len(rows), gate=sum(1 for r in rows if r[0] in entries),
                     helpers=sum(1 for r in rows if r[0] not in entries)),
    )
    with open(out / 'evidence.json', 'w', encoding='ascii', newline='\n') as f:
        json.dump(evidence, f, indent=1, sort_keys=True)
        f.write('\n')
    return evidence


def main():
    ap = argparse.ArgumentParser(description=__doc__.split('\n')[0])
    ap.add_argument('--out', required=True)
    args = ap.parse_args()
    data = (ROOT / BINARY).read_bytes()
    ev = generate(data, args.out)
    print(json.dumps(dict(vectors=ev['vectors'], evaluations=ev['evaluations'], mutants=ev['mutants']), sort_keys=True))


if __name__ == '__main__':
    main()
