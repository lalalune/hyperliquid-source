#!/usr/bin/env python3
"""fees: node #94 per-token ledger of one fill, the consumer of the fee record, from bytes alone.

Static, no execution of the node.  0x3745a60 and its table entry path 0x3596da0 and 0x379a610 are
decoded from ELF bytes by the table decoder below, which must land exactly on each FDE end, and
interpreted in Python on every vector.  The hash, the overflow recorder, the byte compare, the table
reserve and the B-tree entry helpers are stubs; the entry stubs read back the handle the search built
and act on real node memory.  Each outcome is compared with a separate closed-form model, then every
conditional and every record or value field offset is mutated to test the vectors.

    python3 tools/fees_fill_ledger.py --out <dir>

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
        if b2 == 0x7f and (rep == 'f3' or p66):
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
            raise Unmodelled(f'read of unset bytes at {addr:#x} by {self.cur:#x}')
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


LEDGER, ENTRY, FIND = 0x3745a60, 0x3596da0, 0x379a610
DECODED = (LEDGER, ENTRY, FIND)
TOKEN_SERIALIZER, TRACKER_SERIALIZER = 0x37497d0, 0x23382e0
HASH, RECORD = 0x399c7a0, 0x358dcd0
TREE_ENTRY, INNER_ENTRY, OUTER_INSERT, RESERVE = 0x33bcd10, 0x33bc720, 0x33c0590, 0x357d310
COMPARE = 1  # the slot 0x576e488 is an import, not a RELATIVE relocation; this stands for its target
SLOTS = {0x5773190: RECORD, 0x576e488: COMPARE, 0x5773680: RESERVE}
LOC_ADD, LOC_SUB = 0x56dfd78, 0x56dfd90
PERP_CALLER, SPOT_CALLER = 0x37153f0, 0x372faa0
STRIDE = 0xe8
LEAF, BRANCH = 0x278, 0x2d8
CAP = 11
V, U, C, r_, F, T = range(6)
FIELD_NAMES = ('V', 'U', 'C', 'r', 'F', 'T')
# Reads of stack bytes nobody wrote: the padding after a 20-byte key and an unused map height.
LOOSE = (0x3745df6, 0x37461c7, 0x3596e79, 0x3596dcc)
UNEXECUTED = ()
TAG_COMPARES = (0x3745b52, 0x3745ba6)
EQUIVALENT = {}
REFERENCE_ROWS = (
    ('shape differs', 'l1/fees/compute.rs apply_builder_vault_fee_split', 'per_user totals keyed by user, per_recipient[recipient][user]',
     'one tree per user keyed by a 64-bit key; a recipient is credited in word U of its own value, plus map [builder][key] at FeeTracker +0x150'),
    ('differs', 'l1/fees/compute.rs secondary_paid_100x', 'the second amount is added to a total of the paying user',
     'the builder step changes no word of the paying user'),
    ('differs', 'l1/fees/compute.rs net_after_rebate_100x', 'checked_sub, and no add and no diagnostic on underflow',
     'each of the two subtractions floors at 0 and calls the recorder; the stored value is the same'),
    ('differs', 'l1/fees/compute.rs add_recipient_amount', 'always adds the amount',
     'a builder amount of 0 skips both maps; a referrer amount of 0 still creates the bucket and the value'),
    ('differs', 'l1/fees/compute.rs add_external_volume', 'second key is a day, current_day_bucket',
     'perp key [state+0x50]; spot key the word at +8 of a 32-byte pair entry, so no date; the string after V U C is token_to_state'),
    ('names', 'l1/fees/compute.rs UserSplitTotals', 'builder_paid, net_after_rebate, protocol_component',
     'serde keys r, F, T; record +0 is the referrer tag and +0x28 the builder tag in the fee output'),
    ('absent', 'l1/raw_vlm.rs, l1/scaled_vlm.rs', 'per-user and per-day volume only', 'the six-word value is not modelled; only V is a volume'),
)
# name lea, field lea (None when the field is the record itself), and the field order is the VA order.
TRACKER_FIELDS = ((0x2338331, None), (0x2338396, 0x23383b4), (0x23383ff, 0x233841d), (0x2338468, 0x2338486),
                  (0x23384fa, 0x23384f3), (0x2338528, 0x2338521), (0x2338556, 0x233854f), (0x2338590, 0x2338589))
# The two fields whose name is written inside a callee: name lea in the callee, field lea here.
TRACKER_CALLEE_FIELDS = ((0x23d2604, 0x23384d1), (0x23d0f84, 0x233856f))
# Exact bytes of the caller lines the record table rests on; (va, bytes, meaning).
PINNED = (
    (0x3715712, '4d8b6e50', 'perp key: r13 = [state+0x50]'),
    (0x3715802, '4803442410', 'perp: scaled volume added to the first word V'),
    (0x371583c, '4d8b9780000000', 'perp: builder tag = [side+0x80]'),
    (0x3715835, '498b87a8000000', 'perp: gross = [side+0xa8]'),
    (0x371586b, '498b9fb0000000', 'perp: rebate = [side+0xb0]'),
    (0x3715872, '498b8fb8000000', 'perp: extra = [side+0xb8]'),
    (0x37158a9, '41bb64000000', 'perp: multiplier 100'),
    (0x37302c9, '48034c2410', 'spot: scaled volume added to the first word V'),
    (0x3730094, '4f8b7c3e08', 'spot key: r15 = [pairs + index*32 + 8]'),
    (0x37302d7, '4d8bac24b0000000', 'spot: gross = [side+0xb0]'),
    (0x373033f, '498bb424b8000000', 'spot: rebate = [side+0xb8]'),
    (0x3730347, '498b9424c0000000', 'spot: extra = [side+0xc0]'),
    (0x373030f, '498bbc2488000000', 'spot: builder tag = [side+0x88]'),
    (0x26ffda4, '48c7432800000000', 'settlement: T = 0'),
    (0x26ffdac, '4589ac24b0000000', 'settlement: end-day word at entry +0xb0'),
)


def key_hash(key):
    return int.from_bytes(hashlib.sha256(key).digest()[:8], 'little')


def addr(n):
    """A 20-byte test address."""
    return hashlib.sha256(b'addr' + str(n).encode()).digest()[:20]


# ---- closed-form model, written from the semantics and independent of the machine


def apply_model(v):
    """Returns (buckets, builders, records): the final maps and the recorder calls, in order."""
    tables = {a: {k: list(w) for k, w in t.items()} for a, t in v['tables'].items()}
    builders = {a: dict(t) for a, t in v['builders'].items()}
    records, key = [], v['key']

    order = []

    def value(who):
        if who not in tables:
            order.append(who)
        return tables.setdefault(who, {}).setdefault(key, [0] * 6)

    def add(words, i, amount):
        words[i] += amount
        if words[i] > U64:
            records.append(LOC_ADD)
            words[i] = U64

    def less(a, b):
        if a < b:
            records.append(LOC_SUB)
            return 0
        return a - b

    rec = v['rec']
    mine = value(v['user'])
    add(mine, T, rec['extra'])
    if rec['tag'] & 0xffffffff == 1:
        add(mine, F, less(less(rec['gross'], rec['rebate']), rec['extra']))
        add(mine, r_, rec['ref'])
        add(value(rec['ref_addr']), U, rec['ref'])
    if rec['btag'] & 0xff and rec['bamt']:
        who = rec['b_addr']
        add(value(who), U, rec['bamt'])
        inner = builders.setdefault(who, {})
        total = inner.get(key, 0) + rec['bamt']
        if total > U64:
            records.append(LOC_ADD)
            total = U64
        inner[key] = total
    return tables, builders, records, order


def free_slot(ctrl, h):
    """Hashbrown's first free slot from the probe of hash `h`, written from its documented rules."""
    size = len(ctrl)
    full = list(ctrl) + [0xff] * max(0, 16 - size) + list(ctrl)
    full = full[:size + 16] if size >= 16 else full[:16 + size]
    pos, step = h & (size - 1), 0
    while True:
        group = [full[(pos + k) % len(full)] if pos + k < len(full) else full[pos + k - len(full)] for k in range(16)]
        hits = [k for k, c in enumerate(group) if c & 0x80]
        if hits:
            slot = (pos + hits[0]) & (size - 1)
            if ctrl[slot] & 0x80:
                return slot
            return next(k for k in range(16) if ctrl[k] & 0x80)
        step += 16
        pos = (pos + step) & (size - 1)


def insert_plan(ctrl, growth, order):
    """Slots, reserve calls and final growth_left for the new buckets, in order."""
    ctrl, slots, reserves = list(ctrl), [], 0
    for key in order:
        if growth == 0:
            reserves += 1
            growth += RESERVE_GROWTH
        h = key_hash(key)
        slot = free_slot(ctrl, h)
        growth -= ctrl[slot] & 1
        ctrl[slot] = h >> 57
        slots.append(slot)
    return slots, reserves, growth


# ---- memory shapes


def put(m, a, off, size, val):
    m.store(a.base + off, size, val)


def put_bytes(m, a, off, raw):
    for i, b in enumerate(raw):
        m.store(a.base + off + i, 1, b)


def chunks(items, height):
    """Split sorted items into leaf runs and separators for a tree of height 0 or 1."""
    if height == 0:
        return list(items), []
    step = max(1, min(CAP - 1, (len(items) + 2) // 3))
    leaves, seps, i = [], [], 0
    while True:
        leaves.append(items[i:i + step])
        i += step
        if i >= len(items):
            break
        if i == len(items) - 1:
            leaves[-1].append(items[i])
            break
        seps.append(items[i])
        i += 1
    if not seps:
        raise EvidenceError('a tree of height 1 needs a separator')
    return leaves, seps


class Layout:
    """Rust B-tree node offsets of one map type."""

    def __init__(self, val, val_size, parent, keys, key_size, pidx, length, edges, size):
        self.val, self.val_size, self.parent, self.keys, self.key_size = val, val_size, parent, keys, key_size
        self.pidx, self.len, self.edges, self.size = pidx, length, edges, size


TOKEN = Layout(0, 0x30, 0x210, 0x218, 8, 0x270, 0x272, 0x278, BRANCH)
INNER = Layout(0x60, 8, 0, 8, 8, 0xb8, 0xba, 0xc0, 0xc0 + 8 * 12)
OUTER = Layout(8, 0x18, 0, 0x110, 20, 0x1ec, 0x1ee, 0x1f0, 0x1f0 + 8 * 12)


def write_node(m, lay, base, items, parent, pidx, put_val):
    for i, (k, val) in enumerate(items):
        m.store(base + lay.keys + i * lay.key_size, lay.key_size, k) if lay.key_size == 8 else \
            [m.store(base + lay.keys + i * 20 + j, 1, b) for j, b in enumerate(k)]
        put_val(base + lay.val + i * lay.val_size, val)
    m.store(base + lay.parent, 8, parent)
    m.store(base + lay.pidx, 2, pidx)
    m.store(base + lay.len, 2, len(items))


def build_map(m, lay, pairs, height, put_val):
    """Real node shape of a map of height 0 or 1; returns the root VA or 0 for an empty map."""
    items = sorted(pairs)
    if not items:
        return 0
    a = m.arena(lay.size * (CAP + 2) + 16)
    if height == 0:
        write_node(m, lay, a.base, items, 0, 0, put_val)
        return a.base
    leaves, seps = chunks(items, 1)
    root = a.base
    write_node(m, lay, root, seps, 0, 0, put_val)
    for i, run in enumerate(leaves):
        child = root + lay.size * (i + 1)
        write_node(m, lay, child, run, root, i, put_val)
        m.store(root + lay.edges + 8 * i, 8, child)
    return root


def read_map(m, lay, root, height, get_val):
    out = {}

    def walk(node, level):
        n = m.load(node + lay.len, 2)
        for i in range(n + 1):
            if level:
                walk(m.load(node + lay.edges + 8 * i, 8), level - 1)
            if i < n:
                if lay.key_size == 8:
                    k = m.load(node + lay.keys + 8 * i, 8)
                else:
                    k = bytes(m.load(node + lay.keys + 20 * i + j, 1) for j in range(20))
                if k in out:
                    raise EvidenceError('duplicate key in a map')
                out[k] = get_val(node + lay.val + i * lay.val_size)
    if root:
        walk(root, height)
    return out


def put_words(m):
    def go(at, words):
        for i, w in enumerate(words):
            m.store(at + 8 * i, 8, w)
    return go


def get_words(m):
    return lambda at: [m.load(at + 8 * i, 8) for i in range(6)]


def build_table(m, v):
    """A hashbrown table: `size` buckets, control bytes after the bucket area, 0xe8-byte buckets below."""
    size = v.get('size', 32)
    a = m.arena(STRIDE * size + 16 + size + 16 + 16)
    ctrl_off = STRIDE * size + 16
    ctrl = [0xff] * size

    def place(key):
        h = key_hash(key)
        pos = h & (size - 1)
        step = 0
        while True:
            for k in range(min(16, size)):
                i = (pos + k) & (size - 1)
                if ctrl[i] == 0xff:
                    ctrl[i] = h >> 57
                    return i
            step += 16
            pos += step

    for dead in v.get('tombstones', ()):
        ctrl[dead] = 0x80
    for key in v.get('decoys', ()):
        i = place(key)
        put_bytes(m, a, ctrl_off - (i + 1) * STRIDE, key)
    for key, tree in v['tables'].items():
        i = place(key)
        end = ctrl_off - i * STRIDE
        put_bytes(m, a, end - STRIDE, key)
        height = v['heights'].get(key, 0) if tree else 0
        root = build_map(m, TOKEN, list(tree.items()), height, put_words(m))
        put(m, a, end - 0x38, 8, root)
        put(m, a, end - 0x30, 8, height)
        put(m, a, end - 0x28, 8, len(tree))
    for i in range(size):
        put(m, a, ctrl_off + i, 1, ctrl[i])
    for i in range(16):
        put(m, a, ctrl_off + size + i, 1, ctrl[i] if size >= 16 and i < size else 0xff)
    if size < 16:
        for i in range(size):
            put(m, a, ctrl_off + 16 + i, 1, ctrl[i])
    m.ctrl0 = list(ctrl)
    return a.base + ctrl_off, size


def build_ctx(m, v):
    a = m.arena(0x170)
    ctrl, size = build_table(m, v)
    put(m, a, 0xc0, 8, ctrl)
    put(m, a, 0xc8, 8, size - 1)
    put(m, a, 0xd0, 8, v.get('growth', 4))
    put(m, a, 0xd8, 8, len(v['tables']) + len(v.get('decoys', ())))

    def put_inner(at, pair):
        root = build_map(m, INNER, list(pair[0].items()), pair[1], lambda x, y: m.store(x, 8, y))
        m.store(at, 8, root)
        m.store(at + 8, 8, pair[1])
        m.store(at + 16, 8, len(pair[0]))

    pairs = [(k, (t, v['inner_heights'].get(k, 0) if t else 0)) for k, t in v['builders'].items()]
    height = v.get('outer_height', 0) if pairs else 0
    put(m, a, 0x150, 8, build_map(m, OUTER, pairs, height, put_inner))
    put(m, a, 0x158, 8, height)
    put(m, a, 0x160, 8, len(pairs))
    return a


def machine(img, code):
    m = Machine(img, ())
    m.code = code
    m.loose = LOOSE
    for t in DECODED:
        m.real[t] = t
    m.log = []
    m.hashes = []
    m.slots = dict(SLOTS)
    return m


def insert(m, lay, node, idx, key, cell_len):
    """Open slot `idx` in a leaf with room, as a real leaf insert does; the split path is out of scope."""
    n = m.load(node + lay.len, 2)
    if n >= CAP:
        raise Unmodelled('leaf split is outside this packet')
    if not 0 <= idx <= n:
        raise Unmodelled('insert index out of range')
    keys = [m.load(node + lay.keys + i * 8, 8) for i in range(n)]
    if (idx and keys[idx - 1] >= key) or (idx < n and keys[idx] <= key):
        raise Unmodelled('insert out of order')
    for i in range(n, idx, -1):
        m.store(node + lay.keys + i * 8, 8, keys[i - 1])
        for j in range(0, lay.val_size, 8):
            m.store(node + lay.val + i * lay.val_size + j, 8, m.load(node + lay.val + (i - 1) * lay.val_size + j, 8))
    m.store(node + lay.keys + idx * 8, 8, key)
    for j in range(0, lay.val_size, 8):
        m.store(node + lay.val + idx * lay.val_size + j, 8, 0)
    m.store(node + lay.len, 2, n + 1)
    m.store(cell_len, 8, m.load(cell_len, 8) + 1)
    return node + lay.val + idx * lay.val_size


def new_leaf(m, lay, parent_cell):
    a = m.arena(lay.size + 16)
    m.store(a.base + lay.parent, 8, 0)
    m.store(a.base + lay.len, 2, 0)
    m.store(parent_cell, 8, a.base)
    m.store(parent_cell + 8, 8, 0)
    m.store(parent_cell + 16, 8, 0)
    return a.base


def entry_stub(m, lay):
    def go():
        h = m.regs[R['rdi']]
        if m.load(h, 8) == 0:
            node, idx = m.load(h + 8, 8), m.load(h + 0x18, 8)
            m.clobber(node + lay.val + idx * lay.val_size)
            return
        cell, key, node = m.load(h, 8), m.load(h + 8, 8), m.load(h + 0x10, 8)
        if node == 0:
            node = new_leaf(m, lay, cell)
            idx = 0
        else:
            if m.load(h + 0x18, 8) != 0:
                raise Unmodelled('vacant handle above a leaf')
            idx = m.load(h + 0x20, 8)
        m.clobber(insert(m, lay, node, idx, key, cell + 16))
    return go


def outer_insert_stub(m, ctx):
    def go():
        out, h, val = m.regs[R['rdi']], m.regs[R['rsi']], m.regs[R['rdx']]
        if m.load(h, 8) != ctx.base + 0x150:
            raise Unmodelled('outer handle cell')
        if m.load(val, 8) != 0 or m.load(val + 16, 8) != 0:
            raise Unmodelled('outer insert of a non-empty map')
        key = bytes(m.load(h + 0x20 + j, 1) for j in range(20))
        node = m.load(h + 8, 8)
        if node == 0:
            node, idx = new_leaf(m, OUTER, ctx.base + 0x150), 0
        else:
            idx = m.load(h + 0x18, 8)
        n = m.load(node + OUTER.len, 2)
        if n >= CAP:
            raise Unmodelled('leaf split is outside this packet')
        keys = [bytes(m.load(node + OUTER.keys + i * 20 + j, 1) for j in range(20)) for i in range(n)]
        if (idx and keys[idx - 1] >= key) or (idx < n and keys[idx] <= key):
            raise Unmodelled('outer insert out of order')
        for i in range(n, idx, -1):
            for j, b in enumerate(keys[i - 1]):
                m.store(node + OUTER.keys + i * 20 + j, 1, b)
            for j in range(0, 0x18, 8):
                m.store(node + OUTER.val + i * 0x18 + j, 8, m.load(node + OUTER.val + (i - 1) * 0x18 + j, 8))
        for j, b in enumerate(key):
            m.store(node + OUTER.keys + idx * 20 + j, 1, b)
        for j in range(0, 0x18, 8):
            m.store(node + OUTER.val + idx * 0x18 + j, 8, 0)
        m.store(node + OUTER.len, 2, n + 1)
        m.store(ctx.base + 0x160, 8, m.load(ctx.base + 0x160, 8) + 1)
        m.store(out, 8, node)
        m.store(out + 8, 8, 0)
        m.store(out + 0x10, 8, idx)
        m.clobber()
    return go


def install(m, ctx):
    def do_hash():
        if m.regs[R['rdi']] != ctx.base + 0xe0:
            raise Unmodelled('hash of another table')
        key = bytes(m.load(m.regs[R['rsi']] + i, 1) for i in range(20))
        m.hashes.append(key)
        m.clobber(key_hash(key))

    def record():
        if m.regs[R['rdi']] != 0:
            raise Unmodelled('recorder first argument')
        m.log.append(m.regs[R['rsi']])
        m.clobber()

    def memcmp():
        a, b, n = m.regs[R['rdi']], m.regs[R['rsi']], m.regs[R['rdx']]
        x = bytes(m.load(a + i, 1) for i in range(n))
        y = bytes(m.load(b + i, 1) for i in range(n))
        m.clobber(0 if x == y else (1 if x > y else 0xffffffffffffffff))

    def reserve():
        if m.regs[R['rdi']] != ctx.base + 0xc0 or m.regs[R['rdx']] != ctx.base + 0xe0:
            raise Unmodelled('reserve arguments')
        if m.regs[R['rsi']] != 1 or m.regs[R['rcx']] != 1:
            raise Unmodelled('reserve size')
        m.reserved += 1
        m.store(ctx.base + 0xd0, 8, m.load(ctx.base + 0xd0, 8) + RESERVE_GROWTH)
        m.clobber()

    m.reserved = 0
    m.stubs.update({HASH: do_hash, RECORD: record, COMPARE: memcmp, RESERVE: reserve, TREE_ENTRY: entry_stub(m, TOKEN),
                    INNER_ENTRY: entry_stub(m, INNER), OUTER_INSERT: outer_insert_stub(m, ctx)})


RESERVE_GROWTH = 8


def run_ledger(img, code, v):
    m = machine(img, code)
    stack = m.arena(0x4000)
    top = stack.base + 0x3f08
    ctx = build_ctx(m, v)
    install(m, ctx)
    user = m.arena(20)
    put_bytes(m, user, 0, v['user'])
    rec = m.arena(0x68)
    r = v['rec']
    put(m, rec, 0, 8, r['tag'])
    put(m, rec, 8, 8, r['ref'])
    put_bytes(m, rec, 0x10, r['ref_addr'])
    put(m, rec, 0x28, 8, r['btag'])
    put(m, rec, 0x30, 8, r['bamt'])
    put_bytes(m, rec, 0x38, r['b_addr'])
    put(m, rec, 0x50, 8, r['gross'])
    put(m, rec, 0x58, 8, r['rebate'])
    put(m, rec, 0x60, 8, r['extra'])
    m.regs[R['rsp']] = top
    m.store(top, 8, 0xfeedface)
    m.regs[R['rdi']] = ctx.base
    m.regs[R['rsi']] = user.base
    m.regs[R['rdx']] = v['key']
    m.regs[R['rcx']] = rec.base
    for name in ('rbx', 'rbp', 'r12', 'r13', 'r14', 'r15'):
        m.regs[R[name]] = 0xc0de0000 + R[name]
    m.run(LEDGER)
    return m, ctx


def read_table(m, ctx, decoys=()):
    """Walk the control bytes; every live key must be reachable by a probe from its own hash."""
    ctrl, mask = m.load(ctx.base + 0xc0, 8), m.load(ctx.base + 0xc8, 8)
    size = mask + 1
    tables = {}
    for i in range(size):
        c = m.load(ctrl + i, 1)
        if c >= 0x80:
            continue
        key = bytes(m.load(ctrl - (i + 1) * STRIDE + j, 1) for j in range(20))
        if c != key_hash(key) >> 57:
            raise EvidenceError('control byte does not match the key')
        mirror = ((i - 16) & mask) + 16
        if m.load(ctrl + mirror, 1) != c:
            raise EvidenceError('control mirror byte differs')
        if key in decoys:
            continue
        end = ctrl - i * STRIDE
        root = m.load(end - 0x38, 8)
        height = m.load(end - 0x30, 8) if root else 0
        tree = read_map(m, TOKEN, root, height, get_words(m))
        if root and m.load(end - 0x28, 8) != len(tree):
            raise EvidenceError('map length word differs')
        tables[key] = tree
    return tables


def read_builders(m, ctx):
    root, height = m.load(ctx.base + 0x150, 8), m.load(ctx.base + 0x158, 8)

    def inner(at):
        r = m.load(at, 8)
        if not r:
            return {}
        out = read_map(m, INNER, r, m.load(at + 8, 8), lambda x: m.load(x, 8))
        if m.load(at + 16, 8) != len(out):
            raise EvidenceError('inner length word differs')
        return out

    return read_map(m, OUTER, root, height, inner)


def compare(m, ctx, v, want):
    tables, builders, records, order = want
    decoys = set(v.get('decoys', ()))
    got = read_table(m, ctx, decoys)
    slots, reserves, growth = insert_plan(m.ctrl0, v.get('growth', 4), order)
    if m.reserved != reserves:
        return f'reserve calls {m.reserved} != {reserves}'
    if m.load(ctx.base + 0xd0, 8) != growth:
        return 'growth_left differs'
    base = m.load(ctx.base + 0xc0, 8)
    for key, slot in zip(order, slots):
        if bytes(m.load(base - (slot + 1) * STRIDE + j, 1) for j in range(20)) != key:
            return f'new bucket not at slot {slot}'
    if got != tables:
        return f'tables differ: {sorted(k.hex()[:6] for k in got)} {sorted(k.hex()[:6] for k in tables)}'
    if read_builders(m, ctx) != builders:
        return 'builder map differs'
    if m.log != records:
        return f'recorder calls {m.log} != {records}'
    fresh = sum(1 for k in tables if k not in v['tables'])
    if m.load(ctx.base + 0xd8, 8) != len(v['tables']) + len(decoys) + fresh:
        return 'items count differs'
    for reg in ('rbx', 'rbp', 'r12', 'r13', 'r14', 'r15'):
        if m.regs[R[reg]] != 0xc0de0000 + R[reg]:
            return f'callee-saved {reg} changed'
    return None


# ---- vectors


class Lcg:
    def __init__(self, seed):
        self.x = seed

    def next(self):
        self.x = (self.x * 0x5851f42d4c957f2d + 0x14057b7ef767814f) & U64
        return self.x

    def pick(self, seq):
        return seq[(self.next() >> 33) % len(seq)]


def words(rng, near=False):
    """Six words that are all different, so a swapped field shows."""
    if near:
        return [U64 - (rng.next() >> 40) for _ in range(6)]
    return [rng.next() >> 8 for _ in range(6)]


def vector(group, **kw):
    v = dict(group=group, user=addr(1), key=0x168, tables={}, heights={}, builders={}, inner_heights={})
    v['rec'] = dict(tag=0, ref=0, ref_addr=b'\0' * 20, btag=0, bamt=0, b_addr=b'\0' * 20, gross=0, rebate=0, extra=0)
    rec = kw.pop('rec', {})
    v.update(kw)
    v['rec'] = dict(v['rec'], **rec)
    return v


KEYS = (0, 1, 150, 0x168, 0x169, 1000, 0xffffffff, 1 << 32, U64 - 1, U64)
AMOUNTS = (0, 1, 2, 99, 100, 123456789, 10 ** 12, 10 ** 15, 1 << 40, (1 << 63) + 77, U64 - 3, U64)


def filler(rng, size, skip=()):
    keys = set()
    while len(keys) < size:
        k = rng.next() >> 16
        if k not in skip:
            keys.add(k)
    return {k: words(rng) for k in keys}


def tree_cases(rng, key):
    """(tree, height) shapes around one search key: empty, leaf hit, leaf miss, branch hit, branch miss."""
    around = filler(rng, 7, (key,))
    hit = dict(around)
    hit[key] = words(rng)
    small = dict(list(around.items())[:3])
    near = {(key + d) & U64: words(rng) for d in (1, 3) if (key + d) & U64 != key}
    small_hit = dict(small)
    small_hit[key] = words(rng)
    low = {(key - d) & U64: words(rng) for d in (1, 3) if key >= d}
    return (({}, 0), (small, 0), (small_hit, 0), (hit, 1), (around, 1), (near, 0), ({key: words(rng)}, 0), (low, 0))


def shapes_group():
    """Every tree shape for the user and the referrer, with and without builder."""
    out = []
    rng = Lcg(11)
    who, ref, bld = addr(1), addr(2), addr(3)
    for key in (0x168, 150):
        for i, (tree, height) in enumerate(tree_cases(rng, key)):
            for j, (rtree, rh) in enumerate(tree_cases(rng, key)):
                tables = {who: tree, ref: rtree}
                heights = {who: height, ref: rh}
                gross = rng.next() >> 12
                rebate = rng.next() >> 16
                extra = rng.next() >> 20
                rec = dict(tag=1, ref=rng.next() >> 14, ref_addr=ref, gross=gross, rebate=rebate, extra=extra)
                if (i + j) % 3 == 0:
                    rec.update(btag=1, bamt=rng.next() >> 18, b_addr=bld)
                out.append(vector('shapes', key=key, tables=tables, heights=heights, rec=rec))
    return out


def plain_group():
    out = []
    rng = Lcg(22)
    for key in KEYS:
        for extra in AMOUNTS:
            tree = filler(rng, 4, (key,))
            out.append(vector('plain', key=key, tables={addr(1): tree}, rec=dict(extra=extra)))
            out.append(vector('plain', key=key, tables={}, rec=dict(extra=extra)))
    return out


def tags_group():
    """The tag widths: the referrer tag is a 32-bit compare with 1, the builder tag a byte."""
    out = []
    rng = Lcg(33)
    for tag in (0, 1, 2, 3, 0x100, 1 << 32, (1 << 32) + 1, U64):
        for btag in (0, 1, 2, 0xff, 0x100, 0x101):
            rec = dict(tag=tag, ref=rng.next() >> 20, ref_addr=addr(2), btag=btag, bamt=rng.next() >> 20, b_addr=addr(3),
                       gross=rng.next() >> 10, rebate=rng.next() >> 30, extra=rng.next() >> 30)
            out.append(vector('tags', tables={addr(1): {0x168: words(rng)}, addr(2): {0x168: words(rng)}}, rec=rec))
    return out


def subtraction_group():
    """gross - rebate - extra at every ordering, both recorder sites and the double-floor case."""
    out = []
    rng = Lcg(44)
    for gross, rebate, extra in ((100, 30, 20), (100, 80, 20), (100, 80, 21), (100, 100, 0), (100, 101, 0), (0, 0, 0), (0, 1, 0), (0, 0, 1),
                                 (0, 1, 1), (50, 60, 70), (U64, 0, 0), (U64, U64, U64), (U64, 1, U64), (10 ** 15, 1, 10 ** 12)):
        rec = dict(tag=1, ref=7, ref_addr=addr(2), gross=gross, rebate=rebate, extra=extra)
        out.append(vector('subtraction', tables={addr(1): {0x168: words(rng)}, addr(2): {}}, rec=rec))
        out.append(vector('subtraction', tables={}, rec=dict(rec, ref_addr=addr(5))))
    return out


def saturation_group():
    """Each add site alone at its carry edge."""
    out = []
    rng = Lcg(55)
    for field, name in ((T, 'extra'), (F, 'gross'), (r_, 'ref')):
        for gap in (0, 1, 2, 1000):
            base = words(rng)
            base[field] = U64 - gap
            for amount in (gap, gap + 1, gap + 2):
                rec = dict(tag=1, ref=3, ref_addr=addr(2), gross=9, rebate=0, extra=4)
                rec[name] = amount
                if name == 'extra':
                    rec['gross'] = amount
                out.append(vector('saturation', tables={addr(1): {0x168: base}}, rec=rec))
    for gap in (0, 1, 2, 1000):
        base = words(rng)
        base[U] = U64 - gap
        for amount in (gap, gap + 1, gap + 2):
            out.append(vector('saturation', tables={addr(2): {0x168: base}}, rec=dict(tag=1, ref=amount, ref_addr=addr(2))))
            out.append(vector('saturation', tables={addr(3): {0x168: base}}, rec=dict(btag=1, bamt=amount, b_addr=addr(3))))
            out.append(vector('saturation', builders={addr(3): {0x168: U64 - gap}}, rec=dict(btag=1, bamt=amount, b_addr=addr(3))))
    near = words(rng, True)
    out.append(vector('saturation', tables={addr(1): {0x168: near}}, rec=dict(tag=1, ref=U64, ref_addr=addr(1), gross=U64, extra=1)))
    return out


def alias_group():
    """User, referrer and builder overlap: the same value word is added twice in one call."""
    out = []
    rng = Lcg(66)
    who, other = addr(1), addr(2)
    for ref_addr, b_addr in ((who, who), (who, other), (other, who), (other, other), (other, addr(3))):
        for present in (True, False):
            tables = {who: {0x168: words(rng)}, other: {0x168: words(rng)}} if present else {}
            rec = dict(tag=1, ref=rng.next() >> 20, ref_addr=ref_addr, btag=1, bamt=rng.next() >> 20, b_addr=b_addr,
                       gross=rng.next() >> 10, rebate=rng.next() >> 30, extra=rng.next() >> 30)
            out.append(vector('alias', tables=tables, rec=rec))
    return out


def builder_group():
    """The token map of a builder and the outer map of collected builder fees, in every shape."""
    out = []
    rng = Lcg(77)
    bld = addr(3)
    others = [addr(i) for i in range(10, 16)]
    inner_cases = (({}, 0), ({0x168: 5}, 0), ({0x167: 1, 0x169: 2}, 0), ({i: i * 3 + 1 for i in range(0x160, 0x170)}, 1),
                   ({i * 2 + 1: i for i in range(0xb0, 0xc0)}, 1), ({0x100: 9, 0x167: 4}, 0), ({0x169: 1}, 0))
    outer_cases = (((), 0), (others[:3], 0), (others, 1))
    for keys, height in outer_cases:
        for present in (True, False):
            for inner, ih in inner_cases:
                for amount in (0, 1, rng.next() >> 20):
                    builders = {k: {7: 8} for k in keys}
                    heights = {}
                    if present:
                        builders[bld] = inner
                        heights[bld] = ih
                    if keys == () and not present:
                        height = 0
                    if height and len(builders) < 3:
                        continue
                    rec = dict(btag=1, bamt=amount, b_addr=bld)
                    out.append(vector('builder', tables={bld: filler(rng, 3)}, builders=builders, inner_heights=heights,
                                      outer_height=height, rec=rec))
    for tree, height in tree_cases(rng, 0x168):
        rec = dict(btag=1, bamt=rng.next() >> 20, b_addr=bld)
        out.append(vector('builder', tables={bld: tree}, heights={bld: height}, rec=rec))
    return out


def probe_group():
    """Table layouts: decoys in the group, tombstones, a full table, a small table and the reserve path."""
    out = []
    rng = Lcg(88)
    who, ref = addr(1), addr(2)
    decoys = [addr(100 + i) for i in range(40)]
    for count in (0, 1, 8, 15, 20):
        for present in (True, False):
            tables = {who: {0x168: words(rng)}}
            if present:
                tables[ref] = {0x168: words(rng)}
            rec = dict(tag=1, ref=rng.next() >> 20, ref_addr=ref, gross=1000, rebate=1, extra=2)
            out.append(vector('probe', tables=tables, decoys=decoys[:count], rec=rec))
    for growth in (0, 1):
        for size in (4, 32):
            for missing in ('user', 'ref', 'both', 'none'):
                tables = {}
                if missing in ('ref', 'none'):
                    tables[who] = {0x168: words(rng)}
                if missing in ('user', 'none'):
                    tables[ref] = {0x168: words(rng)}
                rec = dict(tag=1, ref=rng.next() >> 20, ref_addr=ref, gross=1000, rebate=1, extra=2)
                out.append(vector('probe', tables=tables, size=size, growth=growth, rec=rec))
    for dead in (range(0, 32), range(0, 8), range(8, 24)):
        rec = dict(tag=1, ref=11, ref_addr=ref, gross=1000, rebate=1, extra=2)
        out.append(vector('probe', tables={}, tombstones=tuple(dead)[:24], growth=0, rec=rec))
        out.append(vector('probe', tables={}, tombstones=tuple(dead)[:24], growth=3, rec=rec))
    return out


def same_slot(target, n, match_tag, mask=31):
    """Addresses that probe from the slot of `target`, with its tag byte when `match_tag`."""
    want, found, i = key_hash(target), [], 0
    while len(found) < n:
        i += 1
        k = addr(1000 + i)
        h = key_hash(k)
        if h & mask == want & mask and (not match_tag or h >> 57 == want >> 57):
            found.append(k)
    return found


def collision_group():
    """Tag collisions inside a group and a full first group, for the user and for the referrer."""
    out = []
    rng = Lcg(111)
    who, ref = addr(1), addr(2)
    for target in (who, ref):
        for present in (True, False):
            tables = {who: {0x168: words(rng)}}
            if present:
                tables[ref] = {0x168: words(rng)}
            for decoys in (same_slot(target, 3, True), same_slot(target, 18, False)):
                rec = dict(tag=1, ref=rng.next() >> 20, ref_addr=ref, gross=1000, rebate=1, extra=2)
                out.append(vector('collision', tables=tables, decoys=decoys, rec=rec))
                out.append(vector('collision', tables={k: t for k, t in tables.items() if k != who}, decoys=decoys, rec=rec))
    # Two full groups: the empty-slot search needs a third round.
    for present in (who, ref):
        tables = {present: {0x168: words(rng)}}
        absent = ref if present == who else who
        rec = dict(tag=1, ref=rng.next() >> 20, ref_addr=ref, gross=1000, rebate=1, extra=2)
        out.append(vector('collision', tables=tables, decoys=same_slot(absent, 34, False, 63), size=64, rec=rec))
    # A four-bucket table: the group wraps into mirrored empties, so the first free slot is read from the start.
    for absent in (who, ref):
        other = ref if absent == who else who
        pos = key_hash(absent) & 3
        pick = [pos]
        taken = [k for k in (addr(2000 + i) for i in range(400))]
        decoys = []
        for slot in (pos, (pos + 1) & 3, (pos + 2) & 3):
            decoys.append(next(k for k in taken if key_hash(k) & 3 == slot and k not in decoys))
        rec = dict(tag=1, ref=rng.next() >> 20, ref_addr=ref, gross=1000, rebate=1, extra=2)
        out.append(vector('collision', tables={}, decoys=decoys[:3], size=4, growth=1, user=absent, rec=dict(rec, tag=0)))
        out.append(vector('collision', tables={other: {0x168: words(rng)}}, decoys=decoys[:2], size=4, growth=1, rec=rec))
    return out


def random_group():
    out = []
    rng = Lcg(99)
    people = [addr(i) for i in range(1, 7)]
    for _ in range(300):
        key = rng.pick(KEYS[:6])
        tables, heights = {}, {}
        for p in people:
            if rng.next() >> 60 < 10:
                tree = filler(rng, (rng.next() >> 61), (key,))
                if rng.next() >> 62 == 0:
                    tree[key] = words(rng)
                tables[p] = tree
        rec = dict(tag=rng.next() >> 63, ref=rng.next() >> 16, ref_addr=rng.pick(people), btag=rng.next() >> 63, bamt=rng.next() >> 18,
                   b_addr=rng.pick(people), gross=rng.next() >> 8, rebate=rng.next() >> 12, extra=rng.next() >> 14)
        out.append(vector('random', user=rng.pick(people), key=key, tables=tables, rec=rec))
    return out


def all_vectors():
    out = []
    for group in (shapes_group, plain_group, tags_group, subtraction_group, saturation_group, alias_group, builder_group, probe_group,
                  collision_group, random_group):
        out += group()
    return out


def run_vectors(img, code, vecs, seen=None):
    bad = []
    for i, v in enumerate(vecs):
        m, ctx = run_ledger(img, code, v)
        msg = compare(m, ctx, v, apply_model(v))
        if seen is not None:
            seen |= m.seen
        if msg:
            bad.append((i, v['group'], msg))
    return bad


# ---- mutations


FDE_END = {}


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


def field_sites(listing):
    """Reads and writes of record and tree-value fields: disp8 is the last byte, and the mutant adds 8."""
    out = []
    bases = (R['rbp'], R['r13'], R['rax'], R['rdx'], R['rbx'])
    for ins in listing:
        if ins.op not in ('mov', 'add', 'sub', 'movups', 'movdqu', 'lea'):
            continue
        mem = [o for o in ins.ops if o[0] == 'm' and o[1] in bases and o[2] is None]
        if not mem or any(o[0] == 'i' for o in ins.ops):
            continue
        disp = mem[0][4]
        if 0 < disp < 0x7f and ins.raw[-1] == disp:
            out.append(dict(kind='field', fn=LEDGER, va=ins.va, op=f'{ins.op} +{disp:#x}', patch={ins.va + ins.size - 1: disp ^ 8}))
    return out


def sample(vecs):
    """The survey set: about 60 vectors of each group, chosen by a hash of the index."""
    kept, count = [], {}
    for v in vecs:
        count[v['group']] = count.get(v['group'], 0) + 1
    for i, v in enumerate(vecs):
        if hashlib.sha256(str(i).encode()).digest()[0] * count[v['group']] < 256 * 60:
            kept.append(v)
    return kept


def survey(data, img, code, listing, vecs):
    sites = []
    for fn in DECODED:
        sites += [dict(kind='flip', fn=fn, va=s[0], op=s[3], patch={s[1]: s[2]}) for s in conditional_sites(listing[fn])]
    sites += field_sites(listing[LEDGER])
    for va in TAG_COMPARES:
        ins = next(i for i in listing[LEDGER] if i.va == va)
        sites.append(dict(kind='immediate', fn=LEDGER, va=va, op='referrer tag compare', patch={va + ins.size - 1: ins.raw[-1] ^ 2}))
    picked = sample(vecs)
    want = {id(v): apply_model(v) for v in picked}
    rows = []
    for s in sites:
        mimg = Image(data, s['patch'])
        mcode = dict(code)
        mcode.update({i.va: i for i in decode_range(mimg, s['fn'], FDE_END[s['fn']])})
        killed = None
        for pos, v in enumerate(picked):
            try:
                m, ctx = run_ledger(mimg, mcode, v)
                bad = compare(m, ctx, v, want[id(v)])
            except (Unmodelled, EvidenceError, KeyError, OverflowError, ValueError, TypeError) as exc:
                bad = f'fault {type(exc).__name__}'
            if bad:
                killed = (v['group'], bad[:60])
                picked.insert(0, picked.pop(pos))
                break
        rows.append(dict(s, killed=killed))
    return rows


def bind_fdes(data):
    fdes = Fdes(data)
    for s in DECODED + (TOKEN_SERIALIZER,):
        FDE_END[s] = fdes.range_of(s)['end']
    return fdes


def build(data):
    check_digest(data)
    fdes = bind_fdes(data)
    img = Image(data)
    code = {}
    for s in DECODED:
        code.update({i.va: i for i in decode_range(img, s, FDE_END[s])})
    return img, code, fdes


def location(img, slot):
    target = img.relative(slot)
    size, line, col = struct.unpack('<QII', img.read(slot + 8, 16))
    path = img.read(target, size).decode()
    for mark in ('l1/src/', 'library/'):
        if mark in path:
            path = path[path.index(mark):]
            break
    return dict(slot=hex(slot), path=path, line=line, col=col, length=size)


def direct_sites(img, target, starts):
    addr_, off, size = img.sec['.text'][:3]
    blob, out = img.data, []
    i = blob.find(b'\xe8', off, off + size)
    pack = struct.Struct('<i').unpack_from
    while i != -1 and i + 5 <= off + size:
        va = addr_ + i - off
        if va + 5 + pack(blob, i + 1)[0] == target:
            out.append(dict(site=hex(va), function=hex(starts[bisect.bisect_right(starts, va) - 1])))
        i = blob.find(b'\xe8', i + 1, off + size)
    return out


def token_keys(img):
    """Key letter and field offset of the six-word value, from the decoded serializer 0x37497d0."""
    listing = decode_range(img, TOKEN_SERIALIZER, FDE_END[TOKEN_SERIALIZER])
    home, spill = {}, {}
    order = []
    last = None
    for ins in listing:
        ops = ins.ops
        if ins.op == 'mov' and ops[0][0] == 'r' and ops[1][0] == 'm':
            if ops[1][1] == R['rsi'] and ops[1][2] is None:
                home[ops[0][1]] = ops[1][4]
            elif ops[1][1] == R['rsp'] and ops[1][4] in spill:
                home[ops[0][1]] = spill[ops[1][4]]
        elif ins.op == 'mov' and ops[0][0] == 'm' and ops[0][1] == R['rsp'] and ops[1][0] == 'r' and ops[1][1] in home:
            spill[ops[0][4]] = home[ops[1][1]]
        elif ins.op == 'test' and ops[0][0] == 'r' and ops[0][1] in home:
            last = home[ops[0][1]]
        elif ins.op == 'cmp' and ops[0][0] == 'm' and ops[0][1] == R['rsp'] and ops[0][4] in spill:
            last = spill[ops[0][4]]
        elif ins.op == 'lea' and ops[1][0] == 'm' and ops[1][1] is None and ops[0][1] == R['rsi']:
            order.append((chr(img.read(ops[1][4], 1)[0]), last))
    return order


def rip_lea(img, va):
    raw = img.read(va, 7)
    if raw[0] not in (0x48, 0x4c) or raw[1] != 0x8d or raw[2] & 0xc7 != 5:
        raise EvidenceError(f'no rip-relative lea at {va:#x}')
    return va + 7 + struct.unpack('<i', raw[3:])[0]


def field_offset(img, va):
    raw = img.read(va, 7)
    if raw[:3] == b'\x48\x81\xc3':
        return struct.unpack('<i', raw[3:])[0]
    if raw[:2] not in (b'\x48\x8d', b'\x4c\x8d') or raw[2] & 0xc7 != 0x83:
        raise EvidenceError(f'no field offset at {va:#x}')
    return struct.unpack('<i', raw[3:])[0]


def field_name(img, va):
    target = rip_lea(img, va)
    tail = img.read(va + 7, 8)
    at = tail.index(0xba)
    return img.read(target, struct.unpack('<I', tail[at + 1:at + 5])[0]).decode()


def tracker_fields(img):
    """Serde names and FeeTracker offsets, each read at a pinned instruction of 0x23382e0 or its callee."""
    out = [dict(name=field_name(img, n), offset=hex(0 if f is None else field_offset(img, f))) for n, f in TRACKER_FIELDS]
    out += [dict(name=field_name(img, n), offset=hex(field_offset(img, f))) for n, f in TRACKER_CALLEE_FIELDS]
    return sorted(out, key=lambda e: int(e['offset'], 16))


def pinned(img):
    out = []
    for va, raw, meaning in PINNED:
        got = img.read(va, len(raw) // 2).hex()
        if got != raw:
            raise EvidenceError(f'bytes at {va:#x} are {got}, not {raw}')
        out.append(dict(va=hex(va), bytes=raw, meaning=meaning))
    return out


def digest_of(v):
    return hashlib.sha256(repr(sorted((k, repr(x)) for k, x in v.items())).encode()).hexdigest()[:16]


def example_vectors():
    who, ref, bld = addr(1), addr(2), addr(3)
    seed = [101, 202, 303, 404, 505, 606]
    return (
        ('no referrer, no builder', vector('example', tables={who: {0x168: list(seed)}}, rec=dict(gross=1000, extra=30))),
        ('referrer', vector('example', tables={who: {0x168: list(seed)}}, rec=dict(tag=1, ref=100, ref_addr=ref, gross=1000, rebate=50, extra=30))),
        ('builder', vector('example', tables={who: {0x168: list(seed)}}, rec=dict(btag=1, bamt=25, b_addr=bld, gross=1000, extra=30))),
        ('referrer is the user', vector('example', tables={who: {0x168: list(seed)}}, rec=dict(tag=1, ref=100, ref_addr=who, gross=1000, extra=30))),
    )


def generate(data, out_dir, with_survey=True):
    img, code, fdes = build(data)
    listing = {s: decode_range(img, s, FDE_END[s]) for s in DECODED}
    vecs = all_vectors()
    seen = set()
    bad = run_vectors(img, code, vecs, seen)
    if bad:
        raise EvidenceError(f'mismatches {len(bad)}: {bad[:5]}')
    missing, padding = [], 0
    for fn in DECODED:
        for ins in listing[fn]:
            if ins.va in seen:
                continue
            if ins.op == 'nop':
                padding += 1
            elif not any(a <= ins.va < b for a, b, _ in UNEXECUTED):
                missing.append(hex(ins.va))
    if missing:
        raise EvidenceError(f'unlisted unexecuted instructions {len(missing)}: {missing[:30]}')
    rows = survey(data, img, code, listing, vecs) if with_survey else []
    survivors = {r['va'] for r in rows if not r['killed']}
    if survivors - set(EQUIVALENT) or (rows and set(EQUIVALENT) - survivors):
        raise EvidenceError(f'survivors {sorted(hex(s) for s in survivors ^ set(EQUIVALENT))}')
    starts = sorted(f['start'] for f in eh_frame_records(data)[1])
    examples = []
    for name, v in example_vectors():
        want = apply_model(v)
        m, ctx = run_ledger(img, code, v)
        msg = compare(m, ctx, v, want)
        if msg:
            raise EvidenceError(f'example {name}: {msg}')
        tables, builders = want[:2]
        examples.append(dict(name=name, values={a.hex()[:8]: dict(zip(FIELD_NAMES, t[0x168])) for a, t in sorted(tables.items())},
                             builders={a.hex()[:8]: t for a, t in sorted(builders.items())}))
    exits, groups = {}, {}
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    with open(out / 'vectors.tsv', 'w', newline='\n') as f:
        f.write('group\tinput_digest\tkey\ttag\treferrer_amount\tbuilder_tag\tbuilder_amount\tgross\trebate\textra\tbuckets_after\trecords\thash_calls\n')
        for v in vecs:
            tables, builders, records, _ = apply_model(v)
            r = v['rec']
            groups[v['group']] = groups.get(v['group'], 0) + 1
            m, ctx = run_ledger(img, code, v)
            cells = [v['group'], digest_of(v), str(v['key'])] + [str(r[k]) for k in ('tag', 'ref', 'btag', 'bamt', 'gross', 'rebate', 'extra')]
            cells += [str(len(tables)), ','.join(hex(x) for x in records), str(len(m.hashes))]
            f.write('\t'.join(cells) + '\n')
    with open(out / 'mutations.tsv', 'w', newline='\n') as f:
        f.write('kind\tfunction\tva\tinstruction\tresult\tvector\treason\n')
        for r in rows:
            k = r['killed']
            f.write(f"{r['kind']}\t{r['fn']:#x}\t{r['va']:#x}\t{r['op']}\t{'killed' if k else 'equivalent'}\t{k[0] if k else ''}\t{k[1] if k else EQUIVALENT[r['va']]}\n")
    with open(out / 'instructions.tsv', 'w', newline='\n') as f:
        f.write('function\tva\tsize\tbytes\tdecoded\texecuted\n')
        for fn in DECODED:
            for i in listing[fn]:
                f.write(f'{fn:#x}\t{i.va:#x}\t{i.size}\t{i.raw.hex()}\t{show(i)}\t{int(i.va in seen)}\n')
    with open(out / 'reference-diff.tsv', 'w', newline='\n') as f:
        f.write('verdict\treference\treference_says\tbytes_say\n')
        for row in REFERENCE_ROWS:
            f.write('\t'.join(row) + '\n')
    per = {}
    for fn in DECODED:
        ex = sum(i.va in seen for i in listing[fn])
        per[hex(fn)] = dict(end=hex(FDE_END[fn]), fde=hex(fdes.range_of(fn)['fde']), instructions=len(listing[fn]), executed=ex)
    evidence = dict(
        binary=BINARY, sha256=SHA256, functions=per, callers=direct_sites(img, LEDGER, starts), tree_entry_callers=direct_sites(img, TREE_ENTRY, starts),
        bucket_entry_callers=direct_sites(img, ENTRY, starts), slots={hex(k): hex(img.relative(k)) for k in sorted(SLOTS) if k != 0x576e488},
        token_value_keys=[dict(key=k, offset=hex(o)) for k, o in token_keys(img)], fee_tracker_fields=tracker_fields(img), pinned=pinned(img),
        locations={k: location(img, va) for k, va in (('add', LOC_ADD), ('sub', LOC_SUB))}, vectors=len(vecs), mismatches=0, groups=groups,
        examples=examples, padding_not_executed=padding, unexecuted=[dict(start=hex(a), end=hex(b), why=w) for a, b, w in UNEXECUTED],
        mutants=len(rows), killed=sum(1 for r in rows if r['killed']), survey_vectors=len(sample(vecs)),
        equivalent={hex(k): w for k, w in sorted(EQUIVALENT.items())},
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
