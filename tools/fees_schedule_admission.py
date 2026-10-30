#!/usr/bin/env python3
"""fees: node #94 FeeSchedule admission, from bytes alone.

Static, no execution of the node.  0x3744550 (schedule update), 0x3c02dc0 (admission ladder)
and 0x3c05c30 (float floors) are decoded from their ELF bytes by the table decoder below,
which must land exactly on each FDE end.  The decoded instructions and the real iterators
they call are interpreted in Python; the allocator, Vec growth, fused multiply-add, the
rate grid and the drop glue are stubs.  Each outcome is compared with a separate
closed-form model, then every conditional branch is flipped to test the vectors.

    python3 tools/fees_schedule_admission.py --out <dir>

writes evidence.json, checks.tsv, fields.tsv, instructions.tsv, reference-diff.tsv and
vectors.tsv.  Section and FDE parsing come from tools/elf_index.py and tools/fde_extents.py.
Only the standard library is used: no objdump, readelf or other external program runs, so
the results cannot depend on a binutils version.
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


class Panic(Exception):
    def __init__(self, location):
        super().__init__(location)
        self.location = location


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

    def text(self):
        addr, off, size, _ = self.sec['.text']
        return addr, bytes(self.data[off:off + size])

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
        v = imm(8 if w else 4)
        val = v[1] & (U64 if w else 0xffffffff)
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
        self.marks = frozenset()
        self.hits = []
        self.prev = 0

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
            self.wr(ops[0], self.xmm[ops[1][1]][0])
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
            self.seen.add(rip)
            if rip in self.marks:
                self.hits.append((self.prev, rip))
            self.prev = rip
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
            else:
                self.do_sse(ins)
            rip = nxt
        raise Unmodelled('step limit')


UPDATE, LADDER, FLOORS = 0x3744550, 0x3c02dc0, 0x3c05c30
BTREE_NEXT, CHAIN_NEXT = 0x330fed0, 0x3c1d310
RESERVE, GRID = 0x32d6a00, 0x3404030
GROW_SLOTS = (0x5773a70, 0x5775738)
ALLOC_SLOT, FREE_SLOT, OOM_SLOT, FMA_SLOT, ONCE_SLOT = 0x576dfd8, 0x576e010, 0x576e020, 0x576f6e0, 0x576e8b8
ONCE_WORD, ONCE_ARG = 0x577ab98, 0x577ab80
FMA_DISPATCH_SLOT, FMA_NATIVE = 0x57882e8, 0x565fd20
FMA_NATIVE_BYTES = bytes.fromhex('c4e2f1a9c2')
LOUD, SILENT, FLOOR_FAIL = 0x3c03dc8, 0x3c03dd6, 0x3c05de4
ONCE_PASSAGES = (0x3c03dd0, 0x3c03f4b)
UPDATE_SLOT, TAG_REJECT, TAG_ACCEPT = 0x5773e40, 0x9d, 0x186
UPDATE_CALL, UPDATE_ACCEPT_SITE, UPDATE_REJECT_SITE = 0x3744a64, 0x3744a9c, 0x3744c0a
UPDATE_CALLERS = (0x235acd9, 0x4caf5e4, 0x4cb7f74)
MEMCPY_SLOT, CAPACITY_SLOT, UNWRAP_SLOT = 0x576dfe0, 0x576dfb8, 0x576e470
UPDATE_CLONE, UPDATE_DYING_NEXT, UPDATE_DROP = 0x33e29e0, 0x33b0800, 0x37634e0
DISPLAY_TABLE, REJECT_ARM, REJECT_LEA, REJECT_TEXT = 0x59a8d0, 0x38019d2, 0x38019dd, 'Invalid fees'

CONSTANTS = dict(one=(0x20a730, 1.0), zero_sum=(0x20a910, -0.0), bps_cap=(0x20a890, 5.0),
                 discount_cap=(0x20a940, 0.5), rate_cap=(0x20afb8, 0.001), floor=(0x20a840, 5e-06),
                 fifth=(0x20a768, 0.2), six=(0x20a2b0, 6.0), tenth=(0x20a880, 0.1),
                 scale0=(0x20c100, 1.0), scale1=(0x20c108, 0.2), scale2=(0x20c110, 6.0), scale3=(0x20c118, 0.1))
ONE, BPS_CAP, DISCOUNT_CAP, RATE_CAP, FLOOR = 1.0, 5.0, 0.5, 0.001, 5e-06
SCALES = (1.0, 0.2, 6.0, 0.1)

VIP_STRIDE, MM_STRIDE, STAKE_STRIDE, CANDIDATE_SIZE = 0x30, 0x10, 0x10, 0xc0
NODE_PARENT, NODE_VALS, NODE_PARENT_IDX, NODE_LEN, NODE_EDGES, NODE_SIZE, NODE_CAP = 0, 8, 0x13c, 0x13e, 0x140, 0x140, 11

# label -> (va of the instruction that leaves for a failure exit, function, exit kind, condition)
LADDER_SITES = (
    ('cross_order', 0x3c035c8, 'loud', 'cross[i] > cross[i-1], list seeded with +0x48'),
    ('add_order', 0x3c03608, 'loud', 'add[i] > add[i-1], list seeded with +0x50'),
    ('spot_cross_order', 0x3c03648, 'loud', 'spot_cross[i] > spot_cross[i-1], list seeded with +0x58'),
    ('spot_add_order', 0x3c0368c, 'loud', 'spot_add[i] > spot_add[i-1], list seeded with +0x60'),
    ('mm_add_order', 0x3c0373c, 'loud', 'mm add[i] > mm add[i-1], list seeded with +0x50'),
    ('spot_mm_add_order', 0x3c037e8, 'loud', 'mm add[i] > mm add[i-1], list seeded with +0x60'),
    ('ntl_order', 0x3c03816, 'loud', 'ntl[i-1] >= ntl[i] unsigned, list seeded with 0'),
    ('maker_fraction_order', 0x3c03837, 'loud', 'cutoff[i-1] >= cutoff[i], list seeded with 0.0'),
    ('vip_word5_order', 0x3c03862, 'loud', 'word5[i] > word5[i-1], list seeded with 1.0'),
    ('stake_bps_order', 0x3c0388f, 'loud', 'bps[i] <= bps[i-1], previous starts at 0.0'),
    ('stake_discount_order', 0x3c038b0, 'loud', 'discount[i] <= discount[i-1], previous starts at 0.0'),
    ('stake_bps_cap', 0x3c038bd, 'loud', 'last bps > 5.0'),
    ('stake_discount_cap', 0x3c038cb, 'loud', 'last discount > 0.5'),
    ('keep_high', 0x3c03a7e, 'silent', '+0x70 > 1.0'),
    ('referral_low', 0x3c03a8e, 'silent', '0.0 > +0x68'),
    ('referral_high', 0x3c03aa2, 'silent', '+0x68 > 1.0'),
    ('keep_low', 0x3c03ab2, 'silent', '0.0 > +0x70'),
    ('discount_high', 0x3c03b73, 'silent', 'last discount > 1.0 (never reached, see limits)'),
    ('discount_low', 0x3c03b83, 'silent', '0.0 > last discount (never reached, see limits)'),
    ('extra_sum', 0x3c03b97, 'silent', 'sum of +0x78 map values > 1.0, sum starts at -0.0'),
    ('aligned0_high', 0x3c03bae, 'loud', '+0x90 > 1.0'),
    ('aligned1_low', 0x3c03bcd, 'loud', '1.0 > +0x98'),
    ('aligned2_low', 0x3c03bdc, 'loud', '1.0 > +0xa0'),
    ('perp_floors', 0x3c03c9a, 'silent', '0x3c05c30 false for cross, add, mm add'),
    ('spot_floors', 0x3c03d58, 'silent', '0x3c05c30 false for spot cross, spot add, mm add'),
    ('cross_negative', 0x3c03db4, 'silent', '0.0 > x over cross then spot cross lists'),
    ('cross_cap', 0x3c03dc6, 'silent', 'x > 0.001 over cross then spot cross lists'),
    ('add_cap', 0x3c04115, 'silent', '|x| > 0.001 over add, mm add, spot add, spot mm add lists'),
)
FLOOR_SITES = (
    ('net_plain', 0x3c05d6a, 'floor > net + add_low'),
    ('net_fifth', 0x3c05dac, 'floor > fma(net, 0.2, add_low * 0.2)'),
    ('net_six', 0x3c05de2, 'floor > fma(net, 6.0, add_low * 6.0)'),
    ('keep_tenth', 0x3c05ea8, 'floor > fma(keep_net, 0.1, add_low * 0.1)'),
    ('keep_six', 0x3c05eb4, 'floor > fma(keep_net, 6.0, add_low * 6.0)'),
    ('keep_fifth', 0x3c05ec0, 'floor > fma(keep_net, 0.2, add_low * 0.2)'),
    ('keep_plain', 0x3c05ed4, 'floor > keep_net + add_low'),
    ('net_tenth', 0x3c05ee0, 'floor > fma(net, 0.1, add_low * 0.1)'),
)
SITE = {k: v for k, v, _, _ in LADDER_SITES}
FLOOR_SITE = {k: v for k, v, _ in FLOOR_SITES}

# (offset in the schedule, field, proof).  'serde' rows are read from the serializer bytes in fields().
SERDE_ROWS = (
    (0x2a3c7fe, 0x48, 'cross', 'FeeSchedule'), (0x2a3c81f, 0x50, 'add', 'FeeSchedule'),
    (0x2a3c840, 0x58, 'spotCross', 'FeeSchedule'), (0x2a3c85d, 0x60, 'spotAdd', 'FeeSchedule'),
    (0x2a3c896, 0x68, 'referralDiscount', 'FeeSchedule'),
)
SERDE_ADD_ROWS = (
    (0x2a3c8b3, 0x30, 'stakingDiscountTiers', 'FeeSchedule'),
    (0x2a3bf6a, 0x08, 'add', 'mm tier'), (0x2a3ce6a, 0x08, 'discount', 'stake tier'),
)
SERDE_FIRST_ROWS = ((0x2a3bf4e, 'makerFractionCutoff', 'mm tier'), (0x2a3ce4e, 'bpsOfMaxSupply', 'stake tier'))
LAYOUT_ROWS = (
    (0x00, 'vip Vec (cap, ptr, len)', 'ptr +0x08 and len +0x10 read at 0x3c02fc4, stride 0x30'),
    (0x18, 'mm Vec (cap, ptr, len)', 'ptr +0x20 and len +0x28 read at 0x3c0328a, stride 0x10'),
    (0x30, 'stake Vec (cap, ptr, len)', 'ptr +0x38 and len +0x40 read at 0x3c03867, stride 0x10'),
    (0x70, 'unnamed f64 in [0, 1], used as the keep share in 0x3c05c30', 'range checked at 0x3c03a7e, 0x3c03ab2'),
    (0x78, 'BTreeMap<[u8; 20], f64> (root, height, len)', 'node layout read by 0x330fed0; sum at 0x3c03b59'),
    (0x90, 'three f64 words', 'range checked at 0x3c03bae, 0x3c03bcd, 0x3c03bdc'),
)

REFERENCE_ROWS = (
    ('l1/action/vote_global.rs:200', 'FeeSchedule is nine u64 bps fields',
     'the patch has nine optional parts, but they are four f64 rates, two f64, Vec tiers, a map, a stake Vec, three f64, 20 bytes and a byte'),
    ('info_server/abci_state_info_handler.rs:603', 'FeeSchedule has cross, add, spot_cross, spot_add and tiers, as strings',
     'serializer bytes read the four rates from f64 words at +0x48..+0x60 and go on with tiers, referralDiscount and stakingDiscountTiers'),
    ('info_server/abci_state_info_handler.rs:614', 'FeeTier has five fields',
     'the admission reads six words per vip tier, stride 0x30: four non-increasing f64, a strictly increasing u64, one more non-increasing f64 that starts at 1.0'),
    ('l1/spot_meta.rs:174', 'AlignedQuoteTokenConfig holds three u64 scale fields',
     'if the three words at +0x90..+0xa0 are that struct, they are f64: SSE loads compared with 1.0; the link is an inference'),
    ('l1/fees/compute.rs', 'no admission rule for rates',
     'node #94 has the ladder in checks.tsv; the file models the trade fee update only'),
)

# Reached by a corrupt build only, or padding: the tool fails if anything else stays unexecuted.
UNEXECUTED_LADDER = (
    (0x3c032b1, 0x3c032bc, 'mm list has capacity 1 and length 1 here, so a non-empty mm always takes the reserve path'),
    (0x3c03904, 0x3c03909, 'jump after a call that does not return'),
    (0x3c03919, 0x3c0391e, 'jump after a call that does not return'),
    (0x3c0392e, 0x3c03933, 'jump after a call that does not return'),
    (0x3c03943, 0x3c03948, 'jump after a call that does not return'),
    (0x3c03958, 0x3c0395d, 'jump after a call that does not return'),
    (0x3c0396d, 0x3c0396f, 'jump after a call that does not return'),
    (0x3c0397f, 0x3c03981, 'jump after a call that does not return'),
    (0x3c039d8, 0x3c039dd, 'reserve runs only for a non-empty mm, which clears the flag tested here'),
    (0x3c041cd, 0x3c041d2, 'capacity of the ntl list is at least 1, so its free always runs'),
    (0x3c041d2, 0x3c042ee, 'unwind cleanup after a panic'),
)
UNEXECUTED_FLOORS = (
    (0x3c05d14, 0x3c05d1e, 'cross list is empty: the ladder seeds every list, so the length is at least 1'),
)
UNEXECUTED_UPDATE = (
    (0x3744597, 0x374459c, 'jump after a call that does not return'),
    (0x374466c, 0x3744671, 'jump after a call that does not return'),
    (0x374483e, 0x3744843, 'jump after a call that does not return'),
    (0x37446d0, 0x37446d9, 'mm byte size is non-zero here, so the length cannot be zero'),
    (0x3744d38, 0x3744ea2, 'unwind cleanup after a panic'),
)
UNEXECUTED_FILL = {'nop', 'ud2'}


def fma(x, y, z):
    """Exact fused multiply-add, rounded once: Fraction to float rounds to nearest even."""
    return float(Fraction(x) * Fraction(y) + Fraction(z))


# ---------------------------------------------------------------- closed-form model


def lists_of(s):
    vip, mm = s['vip'], s['mm']
    return dict(cross=[s['base'][0]] + [t[0] for t in vip], add=[s['base'][1]] + [t[1] for t in vip],
                spot_cross=[s['base'][2]] + [t[2] for t in vip], spot_add=[s['base'][3]] + [t[3] for t in vip],
                ntl=[0] + [t[4] for t in vip], word5=[1.0] + [t[5] for t in vip],
                mm_add=[s['base'][1]] + [m[1] for m in mm], spot_mm_add=[s['base'][3]] + [m[1] for m in mm],
                cutoff=[0.0] + [m[0] for m in mm])


def floors_model(cross, add, mm_add, s):
    """(failed label or None, grid inputs) for one rate set."""
    a0, a1 = s['aligned'][0], s['aligned'][1]
    add_last, mm_last = add[-1], mm_add[-1]
    m = mm_last if mm_last < add_last else add_last
    add_low = a1 * m if m < 0.0 else m
    cross_low = a0 * cross[-1]
    after_referral = (1.0 - s['referral']) * cross_low
    stake = s['stake'][-1][1] if s['stake'] else 0.0
    net = (1.0 - s['keep']) * ((1.0 - stake) * after_referral)
    keep_net = (1.0 - s['keep']) * after_referral
    grid = dict(cross_low=cross_low, add_low=add_low, first_cross=cross[0], referral=s['referral'], keep=s['keep'],
                stake=stake)
    if FLOOR > net + add_low:
        return 'net_plain', grid
    if FLOOR > fma(net, 0.2, add_low * 0.2):
        return 'net_fifth', grid
    if FLOOR > fma(net, 6.0, add_low * 6.0):
        return 'net_six', grid
    if FLOOR > fma(keep_net, 0.1, add_low * 0.1):
        return 'keep_tenth', grid
    if FLOOR > fma(keep_net, 6.0, add_low * 6.0):
        return 'keep_six', grid
    if FLOOR > fma(keep_net, 0.2, add_low * 0.2):
        return 'keep_fifth', grid
    if FLOOR > keep_net + add_low:
        return 'keep_plain', grid
    if FLOOR > fma(net, 0.1, add_low * 0.1):
        return 'net_tenth', grid
    return None, grid


def model(s):
    """Returns (accepted, label, floor label, grid calls, inputs of each grid call)."""
    k = lists_of(s)

    def no(label, floor=None, grids=()):
        return False, label, floor, tuple(grids)

    for name, label in (('cross', 'cross_order'), ('add', 'add_order'), ('spot_cross', 'spot_cross_order'),
                        ('spot_add', 'spot_add_order'), ('mm_add', 'mm_add_order'),
                        ('spot_mm_add', 'spot_mm_add_order')):
        x = k[name]
        if any(x[i] > x[i - 1] for i in range(1, len(x))):
            return no(label)
    if any(k['ntl'][i - 1] >= k['ntl'][i] for i in range(1, len(k['ntl']))):
        return no('ntl_order')
    if any(k['cutoff'][i - 1] >= k['cutoff'][i] for i in range(1, len(k['cutoff']))):
        return no('maker_fraction_order')
    x = k['word5']
    if any(x[i] > x[i - 1] for i in range(1, len(x))):
        return no('vip_word5_order')
    pa = pb = 0.0
    for a, b in s['stake']:
        if a <= pa:
            return no('stake_bps_order')
        if b <= pb:
            return no('stake_discount_order')
        pa, pb = a, b
    if pa > BPS_CAP:
        return no('stake_bps_cap')
    if pb > DISCOUNT_CAP:
        return no('stake_discount_cap')
    if s['keep'] > ONE:
        return no('keep_high')
    if 0.0 > s['referral']:
        return no('referral_low')
    if s['referral'] > ONE:
        return no('referral_high')
    if 0.0 > s['keep']:
        return no('keep_low')
    total = -0.0
    for v in s['extra']:
        total += v
    if total > ONE:
        return no('extra_sum')
    if s['aligned'][0] > ONE:
        return no('aligned0_high')
    if ONE > s['aligned'][1]:
        return no('aligned1_low')
    if ONE > s['aligned'][2]:
        return no('aligned2_low')
    grids = []
    for cross, add, mm_add, label, index in ((k['cross'], k['add'], k['mm_add'], 'perp_floors', 0),
                                             (k['spot_cross'], k['spot_add'], k['spot_mm_add'], 'spot_floors', 1)):
        floor, grid = floors_model(cross, add, mm_add, s)
        if floor:
            return no(label, floor, grids)
        grids.append(grid)
        if s['grid'][index] != 'ok':
            return no(label, None, grids)
    for x in k['cross'] + k['spot_cross']:
        if 0.0 > x:
            return no('cross_negative', None, grids)
        if x > RATE_CAP:
            return no('cross_cap', None, grids)
    for x in k['add'] + k['mm_add'] + k['spot_add'] + k['spot_mm_add']:
        if abs(x) > RATE_CAP:
            return no('add_cap', None, grids)
    return True, None, None, tuple(grids)


# ---------------------------------------------------------------- evaluation of the bytes


def store_f64(m, addr, v):
    m.store(addr, 8, f2b(v))


def make_map(m, values, empty_root):
    """Fills a BTreeMap<[u8; 20], f64>; keys stay unset, so reading one faults."""
    if not values and not empty_root:
        return 0, 0

    def leaf(vals, parent, idx):
        a = m.arena(NODE_SIZE)
        m.store(a.base + NODE_PARENT, 8, parent)
        m.store(a.base + NODE_PARENT_IDX, 2, idx)
        m.store(a.base + NODE_LEN, 2, len(vals))
        for i, v in enumerate(vals):
            store_f64(m, a.base + NODE_VALS + 8 * i, v)
        return a.base

    if len(values) <= NODE_CAP:
        return leaf(values, 0, 0), 0
    root = m.arena(NODE_SIZE + 8 * (NODE_CAP + 1))
    m.store(root.base + NODE_PARENT, 8, 0)
    m.store(root.base + NODE_PARENT_IDX, 2, 0)
    chunks, seps, i = [], [], 0
    while len(values) - i > NODE_CAP:
        chunks.append(values[i:i + 6])
        seps.append(values[i + 6])
        i += 7
    chunks.append(values[i:])
    m.store(root.base + NODE_LEN, 2, len(seps))
    for k, v in enumerate(seps):
        store_f64(m, root.base + NODE_VALS + 8 * k, v)
    for k, c in enumerate(chunks):
        m.store(root.base + NODE_EDGES + 8 * k, 8, leaf(c, root.base, k))
    return root.base, 1


def fill_vec(m, ptr_at, len_at, rows, stride, words, high=False):
    """A strict arena of rows; words = [(offset, 'f'|'u', index in row)]."""
    if high:
        m.next_base += 0x1000_0000_0000
    a = m.arena(max(len(rows), 1) * stride)
    if high:
        m.next_base -= 0x1000_0000_0000
    for r, row in enumerate(rows):
        for off, kind, idx in words:
            m.store(a.base + r * stride + off, 8, f2b(row[idx]) if kind == 'f' else row[idx])
    m.store(ptr_at, 8, a.base)
    m.store(len_at, 8, len(rows))
    return a


def install(m, s, cand):
    for i, v in enumerate(s['base']):
        store_f64(m, cand + 0x48 + 8 * i, v)
    store_f64(m, cand + 0x68, s['referral'])
    store_f64(m, cand + 0x70, s['keep'])
    for i, v in enumerate(s['aligned']):
        store_f64(m, cand + 0x90 + 8 * i, v)
    fill_vec(m, cand + 0x08, cand + 0x10, s['vip'], VIP_STRIDE,
             [(0, 'f', 0), (8, 'f', 1), (0x10, 'f', 2), (0x18, 'f', 3), (0x20, 'u', 4), (0x28, 'f', 5)])
    fill_vec(m, cand + 0x20, cand + 0x28, s['mm'], MM_STRIDE, [(0, 'f', 0), (8, 'f', 1)], s.get('mm_high', False))
    fill_vec(m, cand + 0x38, cand + 0x40, s['stake'], STAKE_STRIDE, [(0, 'f', 0), (8, 'f', 1)])
    root, height = make_map(m, list(s['extra']), s.get('empty_root', False))
    m.store(cand + 0x78, 8, root)
    m.store(cand + 0x80, 8, height)
    if root:
        m.store(cand + 0x88, 8, len(s['extra']))


class Heap:
    """Allocator, Vec growth and frees; every block must be freed once with its size."""

    def __init__(self, m, fail_at=0):
        self.m, self.live, self.count, self.fail_at, self.frees = m, {}, 0, fail_at, 0

    def alloc(self):
        m = self.m
        size = m.regs[R['rdi']]
        self.count += 1
        if self.count == self.fail_at:
            m.clobber(0)
            return
        a = m.arena(size)
        self.live[a.base] = size
        m.clobber(a.base)

    def free(self):
        m = self.m
        ptr, size = m.regs[R['rdi']], m.regs[R['rsi']]
        if self.live.get(ptr) != size or m.regs[R['rdx']] & 0xffffffff:
            raise Unmodelled(f'bad free {ptr:#x} {size:#x}')
        del self.live[ptr]
        self.frees += 1
        m.clobber()

    def grow(self, vec, need, elem):
        m = self.m
        cap, ptr = m.load(vec, 8), m.load(vec + 8, 8)
        new = max(cap * 2, need, 4)
        old = self.live.pop(ptr, None)
        if old != cap * elem:
            raise Unmodelled('grow of an unknown block')
        a = m.arena(new * elem)
        for i in range(m.load(vec + 16, 8)):
            m.store(a.base + i * elem, elem, m.load(ptr + i * elem, elem))
        self.live[a.base] = new * elem
        m.store(vec, 8, new)
        m.store(vec + 8, 8, a.base)

    def grow_one(self):
        m = self.m
        self.grow(m.regs[R['rdi']], m.load(m.regs[R['rdi']] + 16, 8) + 1, 8)
        m.clobber()

    def reserve(self):
        m = self.m
        rdi, rsi, rdx, rcx, r8 = (m.regs[R[x]] for x in ('rdi', 'rsi', 'rdx', 'rcx', 'r8'))
        if (rcx, r8) != (8, 8):
            raise Unmodelled('reserve with a new element layout')
        self.grow(rdi, rsi + rdx, 8)
        m.clobber()


def fresh_machine(img, code):
    m = Machine(img, ())
    m.code = code
    stack = m.arena(0x8000, False)
    stack.mem[:] = b'\xa5' * len(stack.mem)
    m.regs[4] = stack.base + 0x7000
    m.got[GROW_SLOTS[0]] = img.relative(GROW_SLOTS[0])
    m.got[GROW_SLOTS[1]] = img.relative(GROW_SLOTS[1])
    m.got[FMA_SLOT] = FMA_SLOT
    m.real = {BTREE_NEXT: BTREE_NEXT, CHAIN_NEXT: CHAIN_NEXT, FLOORS: FLOORS}
    return m


def bind_grid(m, s, heap, calls):
    def grid():
        rdi, rsi, rdx, rcx = (m.regs[R[x]] for x in ('rdi', 'rsi', 'rdx', 'rcx'))
        if rcx != 4 or m.load(rsi, 8) != 4 or m.load(rsi + 8, 8) != rdx:
            raise Unmodelled('grid arguments')
        scales = [b2f(m.load(rdx + 8 * i, 8)) for i in range(4)]
        env = m.load(rsi + 16, 8)
        args = m.load(env + 0x18, 8)
        row = dict(scales=tuple(scales), cross_low=b2f(m.load(m.load(env, 8), 8)),
                   referral=b2f(m.load(m.load(env + 8, 8), 8)), keep=b2f(m.load(m.load(env + 0x10, 8), 8)),
                   add_low=b2f(m.load(m.load(env + 0x20, 8), 8)), first_cross=b2f(m.load(m.load(env + 0x28, 8), 8)),
                   stake=b2f(m.load(args + 0x30, 8)))
        how = s['grid'][len(calls)]
        calls.append(row)
        if how == 'ok':
            m.store(rdi, 8, 2)
        elif how == 'fail_text':
            a = m.arena(8)
            heap.live[a.base] = 8
            m.store(rdi, 8, 1)
            m.store(rdi + 8, 8, 8)
            m.store(rdi + 16, 8, a.base)
        else:
            m.store(rdi, 8, 0)
            m.store(rdi + 8, 8, 0)
        m.clobber()
    return grid


def bind_common(m, s, heap, calls, once):
    def oom():
        raise Panic('alloc')

    def fma_stub():
        m.xmm[0][0] = f2b(fma(b2f(m.xmm[0][0]), b2f(m.xmm[1][0]), b2f(m.xmm[2][0])))
        keep = m.xmm[0][0]
        m.clobber()
        m.xmm[0][0] = keep

    def once_stub():
        if (m.regs[R['rdi']], m.regs[R['rsi']]) != (ONCE_WORD, 1):
            raise Unmodelled('one-time initialiser arguments')
        once.append(1)
        m.clobber()

    m.stubs.update({ALLOC_SLOT: heap.alloc, FREE_SLOT: heap.free, OOM_SLOT: oom, FMA_SLOT: fma_stub,
                    ONCE_SLOT: once_stub, m.got[GROW_SLOTS[0]]: heap.grow_one, GROW_SLOTS[1]: heap.grow_one,
                    RESERVE: heap.reserve, GRID: bind_grid(m, s, heap, calls)})
    m.got[ONCE_WORD] = s.get('once', 0)


def evaluate(img, code, s):
    """Runs the ladder on one schedule; returns everything the model predicts plus the heap state."""
    m = fresh_machine(img, code)
    heap = Heap(m, s.get('alloc_fail', 0))
    calls, once = [], []
    bind_common(m, s, heap, calls, once)
    m.marks = frozenset((LOUD, SILENT, FLOOR_FAIL))
    cand = m.arena(CANDIDATE_SIZE)
    install(m, s, cand.base)
    saved = {r: 0x1111_0000 + r for r in (R['rbx'], R['rbp'], R['r12'], R['r13'], R['r14'], R['r15'])}
    for r, v in saved.items():
        m.regs[r] = v
    m.regs[R['rdi']] = cand.base
    entry = m.regs[4]
    m.regs[4] -= 8
    m.store(m.regs[4], 8, 0xfeedfacecafe)
    try:
        m.run(LADDER)
    except Panic as p:
        return dict(panic=p.location, seen=m.seen, taken=m.taken)
    if m.regs[4] != entry or any(m.regs[r] != v for r, v in saved.items()):
        raise Unmodelled('callee-saved state not restored')
    if heap.live:
        raise Unmodelled(f'leak of {len(heap.live)} blocks')
    hits = [h for h in m.hits if h[0] not in ONCE_PASSAGES]
    return dict(accepted=bool(m.regs[0] & 0xff), hits=hits, calls=calls, once=len(once), seen=m.seen, taken=m.taken,
                frees=heap.frees)


def outcome_mismatch(s, got):
    """None when bytes and model agree, else a short reason."""
    if s.get('alloc_fail'):
        return None if got.get('panic') == 'alloc' else 'expected an allocation failure'
    if 'panic' in got:
        return f"panic {got['panic']}"
    accepted, label, floor, grids = model(s)
    if got['accepted'] != accepted:
        return f"accepted {got['accepted']} != {accepted}"
    want = []
    if floor:
        want.append((FLOOR_SITE[floor], FLOOR_FAIL))
    if label:
        kind = next(k for n, _, k, _ in LADDER_SITES if n == label)
        want.append((SITE[label], LOUD if kind == 'loud' else SILENT))
    if got['hits'] != want:
        return f"hits {got['hits']} != {want}"
    if len(got['calls']) != len(grids):
        return f"grid calls {len(got['calls'])} != {len(grids)}"
    for row, g in zip(got['calls'], grids):
        if row['scales'] != SCALES or any(row[k] != g[k] and not (row[k] == 0.0 and g[k] == 0.0) for k in g):
            return f'grid inputs {row} != {g}'
    want_once = int(s.get('once', 0) != 0 and bool(label) and
                    (next(k for n, _, k, _ in LADDER_SITES if n == label) == 'loud'))
    want_once += int(s.get('once', 0) != 0 and bool(floor))
    if got['once'] != want_once:
        return f"once {got['once']} != {want_once}"
    return None


# ---------------------------------------------------------------- vectors


def base_schedule():
    return dict(base=(4.5e-4, 1.5e-4, 7e-4, 4e-4), referral=0.04, keep=0.25,
                vip=[(4e-4, 1.2e-4, 6e-4, 3e-4, 5 * 10**14, 1.0), (3.5e-4, 8e-5, 5e-4, 2e-4, 25 * 10**14, 0.5),
                     (3e-4, 4e-5, 4e-4, 1e-4, 125 * 10**14, 0.25)],
                mm=[(0.005, 2e-5), (0.015, 1e-5), (0.03, 5e-6)],
                stake=[(1e-4, 0.05), (1e-2, 0.15), (1.0, 0.4)], extra=[0.01, 0.02],
                aligned=(0.8, 1.25, 1.5), grid=('ok', 'ok'))


def with_(s, **kw):
    t = dict(s)
    t.update(kw)
    return t


def bump(x, k=1):
    for _ in range(abs(k)):
        x = math.nextafter(x, math.inf if k > 0 else -math.inf)
    return x


SEEDED = 500


class Lcg:
    """Fixed generator: the same vectors on every Python version."""

    def __init__(self, seed):
        self.x = seed

    def next(self):
        self.x = (self.x * 6364136223846793005 + 1442695040888963407) & U64
        return self.x >> 33

    def pick(self, seq):
        return seq[self.next() % len(seq)]

    def below(self, n):
        return self.next() % n


def replace_row(rows, i, col, v):
    out = list(rows)
    row = list(out[i])
    row[col] = v
    out[i] = tuple(row)
    return out


def vectors():
    b = base_schedule()
    out = [('base', b), ('base_once', with_(b, once=1))]

    def add(name, **kw):
        out.append((name, with_(b, **kw)))

    # every list relation at the boundary: equal, one ulp past, far past
    rate_names = ('cross', 'add', 'spot_cross', 'spot_add')
    for col, name in enumerate(rate_names):
        for i in range(3):
            prev = b['vip'][i - 1][col] if i else b['base'][col]
            add(f'vip{i}_{name}_equal', vip=replace_row(b['vip'], i, col, prev))
            add(f'vip{i}_{name}_ulp_over', vip=replace_row(b['vip'], i, col, bump(prev)))
            add(f'vip{i}_{name}_over', vip=replace_row(b['vip'], i, col, prev * 2))
    for i in range(3):
        prev = b['vip'][i - 1][4] if i else 0
        add(f'vip{i}_ntl_equal', vip=replace_row(b['vip'], i, 4, prev))
        add(f'vip{i}_ntl_one_over', vip=replace_row(b['vip'], i, 4, prev + 1))
        if i:
            add(f'vip{i}_ntl_below', vip=replace_row(b['vip'], i, 4, prev - 1))
        prev = b['vip'][i - 1][5] if i else 1.0
        add(f'vip{i}_word5_equal', vip=replace_row(b['vip'], i, 5, prev))
        add(f'vip{i}_word5_ulp_over', vip=replace_row(b['vip'], i, 5, bump(prev)))
        prev = b['mm'][i - 1][1] if i else b['base'][3]
        add(f'mm{i}_add_equal_spot', mm=replace_row(b['mm'], i, 1, prev))
        add(f'mm{i}_add_ulp_over_spot', mm=replace_row(b['mm'], i, 1, bump(prev)))
        if i == 0:
            add('mm0_add_equal_perp', mm=replace_row(b['mm'], 0, 1, b['base'][1]))
            add('mm0_add_ulp_over_perp', mm=replace_row(b['mm'], 0, 1, bump(b['base'][1])))
        prev = b['mm'][i - 1][0] if i else 0.0
        add(f'mm{i}_cutoff_equal', mm=replace_row(b['mm'], i, 0, prev))
        add(f'mm{i}_cutoff_ulp_over', mm=replace_row(b['mm'], i, 0, bump(prev)))
        if i:
            add(f'mm{i}_cutoff_below', mm=replace_row(b['mm'], i, 0, bump(prev, -1)))
        prev = b['stake'][i - 1][0] if i else 0.0
        add(f'stake{i}_bps_equal', stake=replace_row(b['stake'], i, 0, prev))
        add(f'stake{i}_bps_ulp_over', stake=replace_row(b['stake'], i, 0, bump(prev)))
        prev = b['stake'][i - 1][1] if i else 0.0
        add(f'stake{i}_discount_equal', stake=replace_row(b['stake'], i, 1, prev))
        add(f'stake{i}_discount_ulp_over', stake=replace_row(b['stake'], i, 1, bump(prev)))
    # the spot seed below the perp seed: only the spot mm list can fail
    swapped = (4.5e-4, 4e-4, 7e-4, 1.5e-4)
    add('spot_mm_equal', base=swapped, vip=[], mm=[(0.005, 1.5e-4), (0.01, 1e-5)])
    add('spot_mm_ulp_over', base=swapped, vip=[], mm=[(0.005, bump(1.5e-4)), (0.01, 1e-5)])
    add('spot_mm_over', base=swapped, vip=[], mm=[(0.005, 2e-4), (0.01, 1e-5)])
    # later rows are checked after earlier ones: two faults in one list and across lists
    add('two_faults_cross_then_ntl', vip=replace_row(replace_row(b['vip'], 1, 0, 1e-3), 2, 4, 1))
    add('two_faults_add_then_cross', vip=replace_row(replace_row(b['vip'], 1, 1, 1e-3), 2, 0, 1e-3))
    add('two_faults_word5_then_stake', vip=replace_row(b['vip'], 2, 5, 2.0), stake=[(1.0, 0.0)])
    # stake caps and absolute ranges
    add('stake_bps_at_cap', stake=[(5.0, 0.4)])
    add('stake_bps_over_cap', stake=[(bump(5.0), 0.4)])
    add('stake_discount_at_cap', stake=[(1.0, 0.5)])
    add('stake_discount_over_cap', stake=[(1.0, bump(0.5))])
    add('stake_both_over', stake=[(6.0, 0.6)])
    add('stake_empty', stake=[])
    add('stake_one', stake=[(1.0, 0.1)])
    add('stake_four', stake=[(1e-4, 0.01), (1e-3, 0.02), (1e-2, 0.03), (1e-1, 0.04)])
    for name, v in (('zero', 0.0), ('one', 1.0), ('over', bump(1.0)), ('under', bump(0.0, -1)), ('half', 0.5)):
        add(f'referral_{name}', referral=v)
        add(f'keep_{name}', keep=v)
    add('keep_and_referral_bad', keep=1.5, referral=-0.5)
    # map sums, in leaf and two-level shapes
    add('extra_none', extra=[])
    add('extra_empty_root', extra=[], empty_root=True)
    add('extra_one', extra=[0.5])
    add('extra_at_one', extra=[0.5, 0.25, 0.25])
    add('extra_over_one', extra=[0.5, 0.25, bump(0.25)])
    add('extra_eleven', extra=[0.05] * 11)
    add('extra_twelve', extra=[0.05] * 12)
    add('extra_twenty_at_one', extra=[0.0625] * 16)
    add('extra_forty', extra=[0.02] * 40)
    add('extra_forty_over', extra=[0.03] * 40)
    add('extra_negative_entry', extra=[1.5, -0.75])
    add('extra_negative_total', extra=[-1.0])
    # aligned words
    for name, v in (('at_one', 1.0), ('ulp_over', bump(1.0)), ('ulp_under', bump(1.0, -1)), ('half', 0.5), ('two', 2.0)):
        add(f'aligned0_{name}', aligned=(v, 1.25, 1.5))
        add(f'aligned1_{name}', aligned=(0.8, v, 1.5))
        add(f'aligned2_{name}', aligned=(0.8, 1.25, v))
    add('aligned_order', aligned=(2.0, 0.5, 0.5))
    # grid outcomes, in both rate sets
    for name, g in (('perp_fail', ('fail', 'ok')), ('perp_text', ('fail_text', 'ok')), ('spot_fail', ('ok', 'fail')),
                    ('spot_text', ('ok', 'fail_text'))):
        add(f'grid_{name}', grid=g)
        add(f'grid_{name}_once', grid=g, once=1)
    # range checks after the floors
    add('cross_base_at_cap', base=(RATE_CAP, 1.5e-4, 7e-4, 4e-4))
    add('cross_base_over_cap', base=(bump(RATE_CAP), 1.5e-4, 7e-4, 4e-4))
    add('spot_cross_base_over_cap', base=(4.5e-4, 1.5e-4, bump(RATE_CAP), 4e-4))
    add('spot_cross_base_at_cap', base=(4.5e-4, 1.5e-4, RATE_CAP, 4e-4))
    add('cross_last_negative', vip=replace_row(b['vip'], 2, 0, -1e-4), keep=0.0)
    add('spot_cross_last_negative', vip=replace_row(b['vip'], 2, 2, -1e-4))
    wide = dict(base=(1e-3, 3e-4, 1e-3, 3e-4), mm=[], stake=[], aligned=(1.0, 1.0, 1.0), referral=0.0, keep=0.0)
    add('cross_negative_wide_add', vip=[(-1e-5, 2e-4, 5e-4, 2e-4, 10, 1.0)], **wide)
    add('spot_cross_negative_wide_add', vip=[(5e-4, 2e-4, -1e-5, 2e-4, 10, 1.0)], **wide)
    add('cross_zero_wide_add', vip=[(0.0, 2e-4, 0.0, 2e-4, 10, 1.0)], **wide)
    add('cross_base_negative', base=(-1e-4, -2e-4, -1e-4, -2e-4), vip=[], mm=[], stake=[])
    add('add_base_at_cap', base=(1e-3, 1e-3, 1e-3, 1e-3), vip=[], mm=[])
    add('add_base_over_cap', base=(1e-3, bump(RATE_CAP), 7e-4, 4e-4), vip=[], mm=[])
    add('spot_add_base_over_cap', base=(1e-3, 1.5e-4, 7e-4, bump(RATE_CAP)), vip=[], mm=[])
    add('mm_negative_at_cap', mm=[(0.005, -1e-3)], base=(1e-3, 1.5e-4, 1e-3, 4e-4), vip=[], aligned=(1.0, 1.0, 1.0),
        referral=0.0, keep=0.0, stake=[])
    add('mm_negative_over_cap', mm=[(0.005, bump(-1e-3, -1))], base=(1e-3, 1.5e-4, 1e-3, 4e-4), vip=[],
        aligned=(1.0, 1.0, 1.0), referral=0.0, keep=0.0, stake=[])
    add('vip_add_negative_cap', vip=[(9e-4, -1.5e-3, 9e-4, -2e-4, 10, 1.0)], base=(1e-3, 1.5e-4, 1e-3, 4e-4),
        mm=[], aligned=(1.0, 1.0, 1.0), referral=0.0, keep=0.0, stake=[])
    add('spot_vip_add_negative_cap', vip=[(9e-4, 1e-4, 9e-4, -1.5e-3, 10, 1.0)], base=(1e-3, 1.5e-4, 1e-3, 4e-4),
        mm=[], aligned=(1.0, 1.0, 1.0), referral=0.0, keep=0.0, stake=[])
    # list shapes, including each copy loop of the compiled mm append
    for n in (0, 1, 2, 3, 4, 5, 7, 8, 9, 16, 17, 18, 19, 20, 21, 37, 38, 39, 40, 41, 43, 44):
        mm = [(0.0001 * (k + 1), 1e-5 - 1e-7 * k) for k in range(n)]
        add(f'mm_len_{n}', mm=mm)
        add(f'mm_len_{n}_high', mm=mm, mm_high=True)
    for n in (0, 1, 2, 3, 4, 5, 6, 9):
        vip = [(4e-4 - 1e-5 * k, 1.2e-4 - 1e-6 * k, 6e-4 - 1e-5 * k, 3e-4 - 1e-5 * k, 10**6 * (k + 1), 1.0 - 0.01 * k)
               for k in range(n)]
        add(f'vip_len_{n}', vip=vip)
    add('all_lists_empty', vip=[], mm=[], stake=[], extra=[])
    # floors: positive and negative add side, min picks either list, boundaries by bisection
    out.extend(floor_vectors(b))
    # allocation failures: one vector per call site
    for n in range(1, 10):
        add(f'alloc_fail_{n}', alloc_fail=n)
    # seeded edits near the boundaries
    rng = Lcg(0x94f33)
    for n in range(SEEDED):
        s = dict(b)
        for _ in range(1 + rng.below(3)):
            s = random_edit(rng, s)
        out.append((f'seeded_{n}', s))
    return out


def random_edit(rng, s):
    pick = rng.below(9)
    bumps = (-2, -1, 1, 2)
    if pick == 0:
        i, j = rng.below(4), rng.below(3)
        vip = s['vip']
        if not vip:
            return s
        i %= 4
        j %= len(vip)
        prev = vip[j - 1][i] if j else s['base'][i]
        return with_(s, vip=replace_row(vip, j, i, rng.pick((prev, bump(prev, rng.pick(bumps)), vip[j][i]))))
    if pick == 1:
        mm = s['mm']
        if not mm:
            return s
        j = rng.below(len(mm))
        col = rng.below(2)
        prev = (mm[j - 1][col] if j else (0.0 if col == 0 else s['base'][1 + 2 * rng.below(2)]))
        return with_(s, mm=replace_row(mm, j, col, rng.pick((prev, bump(prev, rng.pick(bumps)), mm[j][col]))))
    if pick == 2:
        st = s['stake']
        if not st:
            return s
        j = rng.below(len(st))
        col = rng.below(2)
        prev = st[j - 1][col] if j else 0.0
        return with_(s, stake=replace_row(st, j, col, rng.pick((prev, bump(prev, rng.pick(bumps)), st[j][col], 0.5, 5.0))))
    if pick == 3:
        return with_(s, referral=rng.pick((0.0, 1.0, bump(1.0), bump(0.0, -1), 0.5, s['referral'])))
    if pick == 4:
        return with_(s, keep=rng.pick((0.0, 1.0, bump(1.0), bump(0.0, -1), 0.5, 0.9, s['keep'])))
    if pick == 5:
        a = list(s['aligned'])
        k = rng.below(3)
        a[k] = rng.pick((1.0, bump(1.0), bump(1.0, -1), 0.5, 1.5, a[k]))
        return with_(s, aligned=tuple(a))
    if pick == 6:
        return with_(s, extra=rng.pick(([], [0.5, 0.5], [0.5, bump(0.5)], [0.1] * 12, s['extra'])))
    if pick == 7:
        return with_(s, grid=rng.pick((('ok', 'ok'), ('fail', 'ok'), ('ok', 'fail_text'))), once=rng.below(2))
    v = list(s['vip'])
    if v:
        j = rng.below(len(v))
        v = replace_row(v, j, 4, (v[j - 1][4] if j else 0) + rng.below(3))
    return with_(s, vip=v)


def first_passing(fn, lo, hi):
    """Smallest float in [lo, hi] with fn true, for a monotonic fn; hi must pass and lo must fail."""
    for _ in range(4000):
        mid = (lo + hi) / 2
        if mid in (lo, hi):
            return hi
        if fn(mid):
            hi = mid
        else:
            lo = mid
    return hi


def floor_vectors(b):
    out = []

    def label_of(s):
        return model(s)[2]

    plain = with_(b, vip=[], mm=[], stake=[], extra=[], referral=0.0, keep=0.0, aligned=(1.0, 1.0, 1.0))

    def add(name, s):
        out.append((name, s))

    # last cross rate decides net; walk it across the floor with a zero and a negative add side
    for name, add_rate, mm in (('zero_add', 0.0, []), ('neg_mm', 1e-4, [(0.1, -1e-5)]), ('pos_add', 1e-5, []),
                               ('neg_vip_add', -1e-5, []), ('tie_add_mm', 1e-5, [(0.1, 1e-5)])):
        def schedule(rate):
            return with_(plain, base=(1e-3, max(add_rate, 1e-4), 1e-3, max(add_rate, 1e-4)),
                         vip=[(rate, add_rate, rate, add_rate, 10, 1.0)], mm=mm)
        for keep, stake in ((0.0, []), (0.3, [(1.0, 0.3)]), (0.5, []), (0.0, [(1.0, 0.5)])):
            def full(rate):
                return with_(schedule(rate), keep=keep, stake=stake)
            at = first_passing(lambda r: model(full(r))[0], 1e-9, 1e-3)
            for k in (-2, -1, 0, 1):
                add(f'floor_{name}_keep{keep}_stake{len(stake)}_edge{k}', full(bump(at, k)))
            # the first check alone: well under every floor
            add(f'floor_{name}_keep{keep}_stake{len(stake)}_low', full(at / 8))
            add(f'floor_{name}_keep{keep}_stake{len(stake)}_mid', full(at * 0.75))
    # keep_tenth first: net is high enough for the 0.2 floor while keep_net + add sits under 5e-5
    kt = with_(plain, base=(1e-3, 2e-5, 1e-3, 2e-5), vip=[(4.5e-5, 2e-5, 4.5e-5, 2e-5, 10, 1.0)])
    add('floor_keep_tenth_first', with_(kt, keep=0.05))
    # net_tenth last: keep_net clears the 0.1 floor, net does not
    nt = with_(plain, base=(1e-3, 1e-5, 1e-3, 1e-5), vip=[(4e-5, 1e-5, 4e-5, 1e-5, 10, 1.0)], stake=[(1.0, 0.1)])
    add('floor_net_tenth_last', nt)
    add('floor_net_tenth_keep_ok', with_(nt, vip=[(4.4e-5, 1e-5, 4.4e-5, 1e-5, 10, 1.0)], stake=[(1.0, 0.15)]))
    # spot set only: perp rates pass, spot rates fail
    add('floor_spot_only', with_(plain, base=(1e-3, 1e-4, 1e-3, 1e-4),
                                 vip=[(5e-4, 1e-4, 1e-6, 0.0, 10, 1.0)]))
    return out


# ---------------------------------------------------------------- the update wrapper 0x3744550


def old_shapes():
    row = lambda k: (4e-4 - k * 1e-5, 1e-4 - k * 1e-6, 5e-4 - k * 1e-5, 2e-4 - k * 1e-5, 10 + k, 1.0 - k / 16)
    return dict(
        a=dict(vip=[row(0), row(1)], mm=[(0.01, 1e-5)], stake=[(1.0, 0.1)], map=(0xa000, 1, 2)),
        b=dict(vip=[], mm=[], stake=[], map=(0, 0, 0)),
        c=dict(vip=[row(k) for k in range(5)], mm=[(0.01 * (k + 1), 1e-5 - k * 1e-6) for k in range(5)],
               stake=[(1.0, 0.1), (2.0, 0.2)], map=(0xa000, 0, 0)),
        d=dict(vip=[row(0)], mm=[(0.01, 1e-5), (0.02, 5e-6), (0.03, 1e-6)], stake=[], map=(0xa000, 2, 90)),
        e=dict(vip=[row(0)], mm=[(0.01, 1e-5), (0.02, 5e-6)], stake=[], map=(0, 0, 0)),
        f=dict(vip=[], mm=[(0.01 * (k + 1), 1e-5 - k * 1e-6) for k in range(4)], stake=[(1.0, 0.1)],
               map=(0xa000, 1, 4)))


PATCH_PARTS = ('rates', 'referral', 'keep', 'extra', 'aligned', 'tiers', 'stake', 'address', 'flag')
OLD_SCALARS = dict(rates=(1.0, 2.0, 3.0, 4.0), referral=0.5, keep=0.25, aligned=(0.5, 1.5, 2.5),
                   address=bytes(range(1, 21)), flag=1)
NEW_SCALARS = dict(rates=(5.0, 6.0, 7.0, 8.0), referral=0.75, keep=0.125, aligned=(0.25, 1.25, 2.25),
                   address=bytes(range(101, 121)), flag=0,
                   vip=[(9e-4, 9e-5, 8e-4, 8e-5, 77, 0.5), (8e-4, 8e-5, 7e-4, 7e-5, 88, 0.25), (1e-4, 1e-5, 1e-4, 1e-5, 99, 0.125)],
                   mm=[(0.5, 1e-6), (0.75, 5e-7)], stake=[(3.0, 0.3)], map=(0xc000, 3, 7))
ALL_PARTS = (1 << len(PATCH_PARTS)) - 1


def vip_words(row):
    return [f2b(row[0]), f2b(row[1]), f2b(row[2]), f2b(row[3]), row[4], f2b(row[5])]


def pair_words(row):
    return [f2b(row[0]), f2b(row[1])]


def put_words(m, heap, rows, stride, words, align=8):
    """A Vec buffer in the tracked heap: (cap, ptr, len).  An empty Vec keeps a dangling pointer."""
    if not rows:
        return 0, align, 0
    a = m.arena(len(rows) * stride)
    heap.live[a.base] = len(rows) * stride
    for r, row in enumerate(rows):
        for k, w in enumerate(words(row)):
            m.store(a.base + r * stride + 8 * k, 8, w)
    return len(rows), a.base, len(rows)


def put_old(m, heap, p, shape):
    for at, rows, stride, words in ((0, shape['vip'], VIP_STRIDE, vip_words), (0x18, shape['mm'], MM_STRIDE, pair_words),
                                    (0x30, shape['stake'], STAKE_STRIDE, pair_words)):
        cap, ptr, n = put_words(m, heap, rows, stride, words)
        for k, v in enumerate((cap, ptr, n)):
            m.store(p + at + 8 * k, 8, v)
    for k, v in enumerate(OLD_SCALARS['rates'] + (OLD_SCALARS['referral'], OLD_SCALARS['keep'])):
        store_f64(m, p + 0x48 + 8 * k, v)
    for k, v in enumerate(shape['map']):
        m.store(p + 0x78 + 8 * k, 8, v)
    for k, v in enumerate(OLD_SCALARS['aligned']):
        store_f64(m, p + 0x90 + 8 * k, v)
    m.store(p + 0xa8, 20, int.from_bytes(OLD_SCALARS['address'], 'little'))
    m.store(p + 0xbc, 1, OLD_SCALARS['flag'])


def put_patch(m, heap, p, mask, big_lists=False):
    has = {name: bool(mask >> i & 1) for i, name in enumerate(PATCH_PARTS)}
    n = NEW_SCALARS
    m.store(p, 8, int(has['rates']))
    if has['rates']:
        for k, v in enumerate(n['rates']):
            store_f64(m, p + 8 + 8 * k, v)
    for at, name in ((0x28, 'referral'), (0x38, 'keep')):
        m.store(p + at, 8, int(has[name]))
        if has[name]:
            store_f64(m, p + at + 8, n[name])
    m.store(p + 0x48, 8, int(has['extra']))
    if has['extra']:
        for k, v in enumerate(n['map']):
            m.store(p + 0x50 + 8 * k, 8, v)
    m.store(p + 0x68, 8, int(has['aligned']))
    if has['aligned']:
        for k, v in enumerate(n['aligned']):
            store_f64(m, p + 0x70 + 8 * k, v)
    m.store(p + 0x88, 8, 1 << 63)
    if has['tiers']:
        cap, ptr, ln = put_words(m, heap, n['vip'], VIP_STRIDE, vip_words)
        cap2, ptr2, ln2 = put_words(m, heap, n['mm'], MM_STRIDE, pair_words)
        for k, v in enumerate((cap, ptr, ln, cap2, ptr2, ln2)):
            m.store(p + 0x88 + 8 * k, 8, v)
    m.store(p + 0xb8, 8, 1 << 63)
    if has['stake']:
        cap, ptr, ln = put_words(m, heap, n['stake'], STAKE_STRIDE, pair_words)
        for k, v in enumerate((cap, ptr, ln)):
            m.store(p + 0xb8 + 8 * k, 8, v)
    m.store(p + 0xd0, 1, int(has['address']))
    if has['address']:
        m.store(p + 0xd1, 20, int.from_bytes(n['address'], 'little'))
    m.store(p + 0xe5, 1, n['flag'] if has['flag'] else 2)


def snapshot(m, p):
    def rows(at, stride, words):
        n = m.load(p + at + 16, 8)
        ptr = m.load(p + at + 8, 8)
        return [tuple(m.load(ptr + r * stride + 8 * k, 8) for k in range(words)) for r in range(n)]

    root = m.load(p + 0x78, 8)
    return dict(vip=rows(0, VIP_STRIDE, 6), mm=rows(0x18, MM_STRIDE, 2), stake=rows(0x30, STAKE_STRIDE, 2),
                rates=tuple(m.load(p + 0x48 + 8 * k, 8) for k in range(4)), referral=m.load(p + 0x68, 8),
                keep=m.load(p + 0x70, 8), map=(root, m.load(p + 0x80, 8) if root else 0, m.load(p + 0x88, 8)),
                aligned=tuple(m.load(p + 0x90 + 8 * k, 8) for k in range(3)), address=m.load(p + 0xa8, 20),
                flag=m.load(p + 0xbc, 1))


def merged(shape, mask, clone_root):
    """The schedule a patch gives, from the shape and the mask alone, in snapshot form."""
    has = {name: bool(mask >> i & 1) for i, name in enumerate(PATCH_PARTS)}
    n, o = NEW_SCALARS, OLD_SCALARS
    root, height, count = shape['map']
    return dict(vip=[tuple(vip_words(r)) for r in (n['vip'] if has['tiers'] else shape['vip'])],
                mm=[tuple(pair_words(r)) for r in (n['mm'] if has['tiers'] else shape['mm'])],
                stake=[tuple(pair_words(r)) for r in (n['stake'] if has['stake'] else shape['stake'])],
                rates=tuple(f2b(v) for v in (n if has['rates'] else o)['rates']),
                referral=f2b((n if has['referral'] else o)['referral']), keep=f2b((n if has['keep'] else o)['keep']),
                map=n['map'] if has['extra'] else ((clone_root, height, count) if count else (0, 0, 0)),
                aligned=tuple(f2b(v) for v in (n if has['aligned'] else o)['aligned']),
                address=int.from_bytes((n if has['address'] else o)['address'], 'little'),
                flag=(n if has['flag'] else o)['flag'])


def original(shape):
    out = merged(shape, 0, shape['map'][0])
    out['map'] = shape['map']
    return out


def evaluate_update(img, code, u):
    m = fresh_machine(img, code)
    heap = Heap(m, u.get('alloc_fail', 0))
    log = dict(cand=None, drops=[], iters=[], clones=[])
    clone_root = 0xb000

    def memcpy():
        dst, src, n = m.regs[R['rdi']], m.regs[R['rsi']], m.regs[R['rdx']]
        if n:
            a, b = m.find(src, n), m.find(dst, n)
            if a is None or b is None:
                raise Unmodelled('memcpy outside the arenas')
            so, do = src - a.base, dst - b.base
            b.mem[do:do + n] = a.mem[so:so + n]
            b.valid[do:do + n] = a.valid[so:so + n]
        m.clobber(dst)

    def clone():
        out, root, height = m.regs[R['rdi']], m.regs[R['rsi']], m.regs[R['rdx']]
        log['clones'].append((root, height))
        m.store(out, 8, clone_root)
        m.store(out + 8, 8, height)
        m.store(out + 16, 8, u['shape']['map'][2])
        m.clobber()

    def dying_next():
        it = m.regs[R['rsi']]
        tag = m.load(it, 8)
        log['iters'].append((tag, m.load(it + 0x10, 8) if tag else 0, m.load(it + 0x40, 8)))
        m.store(m.regs[R['rdi']], 8, 0)
        m.clobber()

    def ladder():
        log['cand'] = snapshot(m, m.regs[R['rdi']])
        m.clobber(int(u['accept']))

    def drop_schedule():
        p = m.regs[R['rdi']]
        for at, stride in ((0, VIP_STRIDE), (0x18, MM_STRIDE), (0x30, STAKE_STRIDE)):
            cap, ptr = m.load(p + at, 8), m.load(p + at + 8, 8)
            if cap:
                if heap.live.get(ptr) != cap * stride:
                    raise Unmodelled('drop of an unknown block')
                del heap.live[ptr]
        log['drops'].append(m.load(p + 0x78, 8))
        m.clobber()

    def panic(name):
        def stub():
            raise Panic(name)
        return stub

    m.stubs.update({ALLOC_SLOT: heap.alloc, FREE_SLOT: heap.free, MEMCPY_SLOT: memcpy, UPDATE_CLONE: clone,
                    UPDATE_DYING_NEXT: dying_next, LADDER: ladder, UPDATE_DROP: drop_schedule,
                    CAPACITY_SLOT: panic('capacity'), UNWRAP_SLOT: panic('unwrap')})
    state = m.arena(CANDIDATE_SIZE)
    patch = m.arena(0xe8, False)
    patch.mem[:] = b'\xa5' * len(patch.mem)
    out = m.arena(2)
    put_old(m, heap, state.base, u['shape'])
    put_patch(m, heap, patch.base, u['mask'])
    if 'fake_len' in u:
        at, n = u['fake_len']
        m.store(state.base + at, 8, n)
    m.regs[R['rdi']], m.regs[R['rsi']], m.regs[R['rdx']] = out.base, state.base, patch.base
    entry = m.regs[4]
    m.regs[4] -= 8
    m.store(m.regs[4], 8, 0xfeedfacecafe)
    try:
        m.run(UPDATE)
    except Panic as p:
        return dict(panic=p.location, seen=m.seen, taken=m.taken)
    if m.regs[4] != entry:
        raise Unmodelled('stack not restored')
    final = snapshot(m, state.base)
    return dict(tag=m.load(out.base, 2), cand=log['cand'], final=final, live=dict(heap.live), log=log, seen=m.seen,
                taken=m.taken, clone_root=clone_root)


def update_mismatch(u, got):
    if 'expect_panic' in u:
        return None if got.get('panic') == u['expect_panic'] else f"expected {u['expect_panic']}"
    if 'panic' in got:
        return f"panic {got['panic']}"
    want = merged(u['shape'], u['mask'], got['clone_root'])
    if got['cand'] != want:
        return 'candidate differs from the merge'
    count, has_extra = u['shape']['map'][2], u['mask'] >> PATCH_PARTS.index('extra') & 1
    log = got['log']
    if log['clones'] != ([u['shape']['map'][:2]] if count else []):
        return f"clones {log['clones']}"
    if log['iters'] != ([(1, got['clone_root'], count) if count else (0, 0, 0)] if has_extra else []):
        return f"map drop {log['iters']}"
    if log['drops'] != [u['shape']['map'][0] if u['accept'] else want['map'][0]]:
        return f"schedule drops {log['drops']}"
    tag = TAG_ACCEPT if u['accept'] else TAG_REJECT
    if got['tag'] != tag:
        return f"tag {got['tag']:#x}"
    final = want if u['accept'] else original(u['shape'])
    if got['final'] != final:
        return 'state after the call differs'
    if len(got['live']) != sum(1 for part in (final['vip'], final['mm'], final['stake']) if part):
        return 'heap blocks left do not match the final schedule'
    return None


def update_vectors():
    shapes = old_shapes()
    out = []
    for name, shape in shapes.items():
        for mask in range(ALL_PARTS + 1):
            if name != 'a' and mask % 5:
                continue
            for accept in (True, False):
                out.append((f'update_{name}_{mask}_{"yes" if accept else "no"}', dict(shape=shape, mask=mask, accept=accept)))
    a = shapes['a']
    for name, at, n in (('vip', 0x10, 1 << 58), ('mm', 0x28, 1 << 60), ('stake', 0x40, 1 << 60)):
        out.append((f'update_capacity_{name}', dict(shape=a, mask=0, accept=True, fake_len=(at, n), expect_panic='capacity')))
    out.append(('update_map_without_root', dict(shape=dict(a, map=(0, 0, 3)), mask=0, accept=True, expect_panic='unwrap')))
    for k in range(1, 4):
        out.append((f'update_alloc_fail_{k}', dict(shape=a, mask=0, accept=True, alloc_fail=k, expect_panic='capacity')))
    return out


# ---------------------------------------------------------------- runs and surveys


def decode_all(img, fdes):
    code, listing = {}, {}
    for start in (UPDATE, LADDER, FLOORS, BTREE_NEXT, CHAIN_NEXT):
        r = fdes.range_of(start)
        insns = decode_range(img, r['start'], r['end'])
        listing[start] = insns
        for i in insns:
            code[i.va] = i
    return code, listing


def run_vectors(img, code, vecs, stop_on_first=False):
    seen, taken, rows, bad = set(), {}, [], []
    for name, s in vecs:
        try:
            got = evaluate(img, code, s)
            why = outcome_mismatch(s, got)
        except (Unmodelled, EvidenceError, OverflowError, ZeroDivisionError) as e:
            got, why = None, f'{type(e).__name__}: {e}'
        if why:
            bad.append((name, why))
            if stop_on_first:
                return dict(bad=bad)
            continue
        seen |= got['seen']
        for k, v in got['taken'].items():
            taken.setdefault(k, set()).update(v)
        rows.append((name, s, got))
    return dict(bad=bad, seen=seen, taken=taken, rows=rows)


def run_update(img, code, vecs, stop_on_first=False):
    seen, taken, bad = set(), {}, []
    for name, u in vecs:
        try:
            got = evaluate_update(img, code, u)
            why = update_mismatch(u, got)
        except (Unmodelled, EvidenceError, OverflowError, ZeroDivisionError) as e:
            got, why = None, f'{type(e).__name__}: {e}'
        if why:
            bad.append((name, why))
            if stop_on_first:
                break
            continue
        seen |= got['seen']
        for k, v in got['taken'].items():
            taken.setdefault(k, set()).update(v)
    return dict(bad=bad, seen=seen, taken=taken)


def branches(listing):
    return [i for start in (UPDATE, LADDER, FLOORS) for i in listing[start]
            if i.op[0] == 'j' and i.op not in ('jmp', 'jmpr')]


def flip_patch(ins):
    """Inverts one condition: the low bit of the condition code."""
    k = 1 if ins.raw[0] == 0x0f else 0
    return {ins.va + k: ins.raw[k] ^ 1}


def survey(data, listing, vecs, update_vecs):
    """Flips every conditional branch; a survivor must be a listed equivalent."""
    plain = {x.va: x for insns in listing.values() for x in insns}
    scopes = dict(none=[], shapes=[v for v in vecs if v[0].startswith(('mm_len_', 'vip_len_', 'stake_', 'base'))],
                  hand=[v for v in vecs if not v[0].startswith('seeded_')])
    out = []
    for ins in branches(listing):
        img = Image(data, flip_patch(ins))
        code = dict(plain)
        start = next(s for s in (UPDATE, LADDER, FLOORS) if LISTING_RANGE[s][0] <= ins.va < LISTING_RANGE[s][1])
        for x in decode_range(img, *LISTING_RANGE[start]):
            code[x.va] = x
        if start == UPDATE:
            res = run_update(img, code, [] if ins.va in EQUIVALENT_FLIPS else update_vecs, True)
        else:
            res = run_vectors(img, code, scopes[EQUIVALENT_FLIPS[ins.va][0]] if ins.va in EQUIVALENT_FLIPS else vecs, True)
        out.append((ins.va, ins.op, res['bad'][0] if res['bad'] else None))
    return out


LISTING_RANGE = {}

# va -> (scope of vectors re-run, why the flip cannot change an outcome)
_COPY = 'selects the copy loop or an overlap guard; both arms copy the same words'
_CLEAN = 'in the unwind cleanup, which no vector reaches'
EQUIVALENT_FLIPS = {
    0x3c032ba: ('none', 'in the block listed as unexecuted: a non-empty mm always takes the reserve path'),
    0x3c032e4: ('shapes', _COPY), 0x3c032f7: ('shapes', _COPY), 0x3c03308: ('shapes', _COPY),
    0x3c03440: ('shapes', _COPY), 0x3c03453: ('shapes', _COPY), 0x3c03464: ('shapes', _COPY),
    0x3c03a41: ('shapes', _COPY), 0x3c03a59: ('shapes', _COPY),
    0x3c04133: ('hand', 'pointer of a seeded list is never null'),
    0x3c0413d: ('hand', 'the fourth list holds the seed of the third and the rows of the second, already tested'),
    0x3c041e2: ('none', _CLEAN), 0x3c04209: ('none', _CLEAN), 0x3c04229: ('none', _CLEAN),
    0x3c04249: ('none', _CLEAN), 0x3c04269: ('none', _CLEAN),
    0x3744d90: ('none', _CLEAN), 0x3744dc5: ('none', _CLEAN), 0x3744e15: ('none', _CLEAN),
    0x3744e47: ('none', _CLEAN), 0x3744e5a: ('none', _CLEAN), 0x3744e77: ('none', _CLEAN),
}


def unexecuted(listing, seen):
    out = []
    for start, allowed in ((UPDATE, UNEXECUTED_UPDATE), (LADDER, UNEXECUTED_LADDER), (FLOORS, UNEXECUTED_FLOORS)):
        for ins in listing[start]:
            if ins.va in seen or ins.op in UNEXECUTED_FILL:
                continue
            if any(a <= ins.va < b for a, b, _ in allowed):
                continue
            out.append(ins.va)
    return out


def constants_check(img):
    out = {}
    for name, (va, want) in CONSTANTS.items():
        got = img.f64(va)
        if struct.pack('<d', got) != struct.pack('<d', want):
            raise EvidenceError(f'constant {name} at {va:#x}: {got!r} != {want!r}')
        out[name] = dict(va=hex(va), value=repr(got), bits=hex(f2b(got)))
    return out


def string_at(img, va, n):
    return img.read(va, n).decode('ascii')


def serde_row(img, at, off, name):
    """Checks lea/add r14 then lea rsi,name then mov edx,len at `at`; returns the bound row."""
    code = img.read(at, 40) + b'\x90' * 16
    i = 0
    first = decode_one(code, i, at)
    i += first.size
    if first.op == 'lea':
        got = first.ops[1]
        if got[1] != R['r14'] or got[4] != off:
            raise EvidenceError(f'{at:#x}: operand is not r14+{off:#x}')
    elif first.op == 'add':
        if first.ops[0][:2] != ('r', R['r14']) or first.ops[1][1] != off:
            raise EvidenceError(f'{at:#x}: operand is not r14+{off:#x}')
    else:
        raise EvidenceError(f'{at:#x}: unexpected {first.op}')
    second = decode_one(code, i, at + i)
    i += second.size
    if second.op != 'lea' or second.ops[0][1] != R['rsi']:
        raise EvidenceError(f'{at:#x}: no name operand')
    name_va = second.ops[1][4]
    third = decode_one(code, i, at + i)
    i += third.size
    fourth = decode_one(code, i, at + i)
    size = third if third.op == 'mov' and third.ops[0] == ('r', R['rdx'], 32) else fourth
    if size.op != 'mov' or size.ops[0] != ('r', R['rdx'], 32):
        raise EvidenceError(f'{at:#x}: no length operand')
    text = string_at(img, name_va, size.ops[1][1])
    if text != name:
        raise EvidenceError(f'{at:#x}: name {text!r} != {name!r}')
    return dict(site=hex(at), offset=hex(off), name=text, name_va=hex(name_va))


def serde_first(img, at, name):
    code = img.read(at, 24) + b'\x90' * 16
    lea = decode_one(code, 0, at)
    if lea.op != 'lea' or lea.ops[0][1] != R['rsi']:
        raise EvidenceError(f'{at:#x}: no name operand')
    mov = decode_one(code, lea.size, at + lea.size)
    size = decode_one(code, lea.size + mov.size, at + lea.size + mov.size)
    if size.ops[0] != ('r', R['rdx'], 32) or string_at(img, lea.ops[1][4], size.ops[1][1]) != name:
        raise EvidenceError(f'{at:#x}: name mismatch')
    return dict(site=hex(at), offset='0x0', name=name, name_va=hex(lea.ops[1][4]))


def fields(img):
    rows = []
    for at, off, name, owner in SERDE_ROWS + SERDE_ADD_ROWS:
        row = serde_row(img, at, off, name)
        row['owner'] = owner
        rows.append(row)
    for at, name, owner in SERDE_FIRST_ROWS:
        row = serde_first(img, at, name)
        row['owner'] = owner
        rows.append(row)
    return sorted(rows, key=lambda r: (r['owner'], int(r['offset'], 16)))


def fma_binding(img):
    plt = img.relative(FMA_SLOT)
    native = img.read(FMA_NATIVE, len(FMA_NATIVE_BYTES))
    if native != FMA_NATIVE_BYTES:
        raise EvidenceError('native fused multiply-add target changed')
    return dict(slot=hex(FMA_SLOT), stub=hex(plt), dispatch_slot=hex(FMA_DISPATCH_SLOT),
                dispatch=hex(img.relative(FMA_DISPATCH_SLOT)), native=hex(FMA_NATIVE), native_bytes=native.hex())


def anchors(img):
    """The caller and result tags around the ladder; not evaluated, only read."""
    if img.relative(UPDATE_SLOT) != UPDATE:
        raise EvidenceError('update slot does not name 0x3744550')
    for va in UPDATE_CALLERS:
        ins = decode_one(img.read(va, 6) + b'\x90' * 16, 0, va)
        if ins.op != 'call' or ins.ops[0][0] != 'm' or ins.ops[0][4] != UPDATE_SLOT:
            raise EvidenceError(f'{va:#x} does not call through the update slot')
    call = decode_one(img.read(UPDATE_CALL, 5) + b'\x90' * 16, 0, UPDATE_CALL)
    if call.op != 'call' or call.ops[0] != ('t', LADDER):
        raise EvidenceError('0x3744a64 does not call the ladder')
    rows = []
    for va, tag in ((UPDATE_ACCEPT_SITE, TAG_ACCEPT), (UPDATE_REJECT_SITE, TAG_REJECT)):
        ins = decode_one(img.read(va, 6) + b'\x90' * 16, 0, va)
        if ins.op != 'mov' or ins.width != 16 or ins.ops[1] != ('i', tag):
            raise EvidenceError(f'{va:#x}: result tag is not {tag:#x}')
        rows.append(dict(site=hex(va), tag=hex(tag)))
    arm = DISPLAY_TABLE + struct.unpack('<i', img.read(DISPLAY_TABLE + 4 * TAG_REJECT, 4))[0]
    if arm != REJECT_ARM:
        raise EvidenceError(f'display arm of the reject tag is {arm:#x}')
    lea = decode_one(img.read(REJECT_LEA, 7) + b'\x90' * 16, 0, REJECT_LEA)
    size = decode_one(img.read(REJECT_LEA + 7, 5) + b'\x90' * 16, 0, REJECT_LEA + 7)
    text = string_at(img, lea.ops[1][4], size.ops[1][1])
    if text != REJECT_TEXT:
        raise EvidenceError(f'reject text is {text!r}')
    return dict(update_slot=hex(UPDATE_SLOT), update=hex(UPDATE), callers=[hex(v) for v in UPDATE_CALLERS],
                ladder_call=hex(UPDATE_CALL), tags=rows,
                reject_display_arm=hex(arm), reject_text=text)


def build(data):
    check_digest(data)
    img = Image(data)
    fdes = Fdes(data)
    code, listing = decode_all(img, fdes)
    for start in (UPDATE, LADDER, FLOORS):
        r = fdes.range_of(start)
        LISTING_RANGE[start] = (r['start'], r['end'])
    return img, fdes, code, listing, vectors()


def generate(data, out_dir):
    img, fdes, code, listing, vecs = build(data)
    res = run_vectors(img, code, vecs)
    update_vecs = update_vectors()
    upd = run_update(img, code, update_vecs)
    if res['bad'] or upd['bad']:
        raise EvidenceError(f"vector mismatches, first {(res['bad'] + upd['bad'])[0]}")
    res['seen'] |= upd['seen']
    for k, v in upd['taken'].items():
        res['taken'].setdefault(k, set()).update(v)
    res['update_total'] = len(update_vecs)
    missing = unexecuted(listing, res['seen'])
    if missing:
        raise EvidenceError(f'unexecuted instructions outside the listed ranges: {[hex(v) for v in missing[:12]]}')
    flips = survey(data, listing, vecs, update_vecs)
    unknown = [(hex(v), o) for v, o, why in flips if why is None and v not in EQUIVALENT_FLIPS]
    if unknown:
        raise EvidenceError(f'surviving branch flips: {unknown}')
    return write_outputs(img, listing, vecs, res, flips, out_dir)


def write_outputs(img, listing, vecs, res, flips, out_dir):
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    rows = res['rows']
    labels = {}
    tsv = ['id\tname\taccepted\tlabel\tfloor\tgrid_calls\tfirst_exit\n']
    for k, (name, s, got) in enumerate(rows):
        if s.get('alloc_fail'):
            lab, floor, acc, calls, hit = 'alloc_failure', '', '', '', ''
        else:
            acc, lab, floor, grids = model(s)
            calls = len(grids)
            hit = hex(got['hits'][0][0]) if got['hits'] else ''
            lab, floor = lab or '', floor or ''
        key = lab or 'accepted'
        labels[key] = labels.get(key, 0) + 1
        tsv.append(f'{k}\t{name}\t{acc}\t{lab}\t{floor}\t{calls}\t{hit}\n')
    (out / 'vectors.tsv').write_text(''.join(tsv))
    checks = ['order\tfunction\tsite\tlabel\texit\tcondition\tvectors\n']
    for k, (name, va, kind, cond) in enumerate(LADDER_SITES, 1):
        checks.append(f'{k}\t0x3c02dc0\t{va:#x}\t{name}\t{kind}\t{cond}\t{labels.get(name, 0)}\n')
    floor_counts = {}
    for _, s, got in rows:
        if not s.get('alloc_fail') and model(s)[2]:
            floor_counts[model(s)[2]] = floor_counts.get(model(s)[2], 0) + 1
    for k, (name, va, cond) in enumerate(FLOOR_SITES, 1):
        checks.append(f'{k}\t0x3c05c30\t{va:#x}\t{name}\tfloor\t{cond}\t{floor_counts.get(name, 0)}\n')
    (out / 'checks.tsv').write_text(''.join(checks))
    bound = fields(img)
    field_rows = ['owner\toffset\tname\tserializer_site\tname_va\n']
    for r in bound:
        field_rows.append(f"{r['owner']}\t{r['offset']}\t{r['name']}\t{r['site']}\t{r['name_va']}\n")
    field_rows.append('layout rows follow: offset, reading, proof\n')
    for off, what, proof in LAYOUT_ROWS:
        field_rows.append(f'layout\t{off:#x}\t{what}\t{proof}\t\n')
    (out / 'fields.tsv').write_text(''.join(field_rows))
    ins_rows = ['function\tva\tsize\tbytes\toperation\texecuted\n']
    for start in (UPDATE, LADDER, FLOORS):
        for i in listing[start]:
            ins_rows.append(f"{start:#x}\t{i.va:#x}\t{i.size}\t{i.raw.hex()}\t{show(i)}\t{int(i.va in res['seen'])}\n")
    (out / 'instructions.tsv').write_text(''.join(ins_rows))
    ref = ['reference\tclaim\tbinary\n']
    for row in REFERENCE_ROWS:
        ref.append('\t'.join(row) + '\n')
    (out / 'reference-diff.tsv').write_text(''.join(ref))
    func = {}
    for start in (UPDATE, LADDER, FLOORS):
        r = LISTING_RANGE[start]
        ins = listing[start]
        run = sum(1 for i in ins if i.va in res['seen'])
        func[hex(start)] = dict(end=hex(r[1]), size=r[1] - r[0], instructions=len(ins), executed=run)
    one_way = sorted(hex(i.va) for i in branches(listing) if len(res['taken'].get(i.va, ())) == 1)
    never = sorted(hex(i.va) for i in branches(listing) if i.va not in res['taken'])
    evidence = dict(
        binary=BINARY, sha256=SHA256, functions=func, constants=constants_check(img), fused_multiply_add=fma_binding(img),
        caller=anchors(img),
        vectors=dict(total=len(vecs), compared=len(rows), mismatches=len(res['bad']), by_outcome=dict(sorted(labels.items()))),
        update_vectors=dict(total=res['update_total'], mismatches=0, patch_parts=list(PATCH_PARTS),
                            old_shapes=sorted(old_shapes())),
        floor_vectors=dict(sorted(floor_counts.items())),
        branch_survey=dict(branches=len(flips), killed=sum(1 for f in flips if f[2]),
                           equivalent=[dict(va=hex(f[0]), scope=EQUIVALENT_FLIPS[f[0]][0], why=EQUIVALENT_FLIPS[f[0]][1])
                                       for f in flips if f[2] is None]),
        unexecuted_ranges=[dict(start=hex(a), end=hex(b), why=w)
                           for a, b, w in UNEXECUTED_UPDATE + UNEXECUTED_LADDER + UNEXECUTED_FLOORS],
        one_way_branches=one_way, unreached_branches=never)
    (out / 'evidence.json').write_text(json.dumps(evidence, indent=1, sort_keys=True) + '\n')
    return evidence


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--out', required=True)
    args = p.parse_args()
    data = (ROOT / BINARY).read_bytes()
    ev = generate(data, args.out)
    print(json.dumps(dict(vectors=ev['vectors'], survey=ev['branch_survey']['branches']), sort_keys=True))


if __name__ == '__main__':
    main()
