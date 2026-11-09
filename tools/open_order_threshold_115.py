#!/usr/bin/env python3
"""abci-fees: node #115 open order cap threshold, from bytes alone.

Static, no execution of the node.  Two functions (0x5495210 and 0x5495680) hold the same open order
cap test and differ only in three state displacements.  Each is decoded from its ELF bytes by the table
decoder below, which must land exactly on the FDE end, and then interpreted in Python from its first
instruction to its ret.  The real count, book and second-map lookups, the real hashbrown probes and the
real address predicate run inside it; the key hashers, the lazy-default Once call, the overflow recorder
and the panic slots are stubs.  Every result is compared with a separate closed-form model, then every
conditional branch and listed constant is mutated, and wrong readings are run against the bytes.

    python3 tools/open_order_threshold_115.py --out <dir>

writes evidence.json, measure.json, vectors.tsv, mutations.tsv, instructions.tsv, copy-diff.tsv,
unreached.tsv and addresses.tsv.  Section and FDE parsing come from tools/elf_index.py and
tools/fde_extents.py.  Only the standard library is used: no disassembler or other external
program runs, so the results cannot depend on a binutils version.
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

BINARY = 'artifacts/node/115/hl-node'
SHA256 = 'a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301'
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
        self.by_start = {}
        for f in fdes:
            if f['start'] in self.by_start:
                raise EvidenceError(f"duplicate FDE start {f['start']:#x}")
            self.by_start[f['start']] = f

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
        if b2 == 0x7f and (p66 or rep == 'f3'):
            reg, rm = modrm(128, True)
            return done('movdqa' if p66 else 'movdqu', (rm, ('x', reg | rr << 3)), 128)
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
            for o in ops:
                if op == 'movdqa' and o[0] == 'm' and self.ea(o) % 16:
                    raise Unmodelled(f'{ins.va:#x}: misaligned {op}')
            if ops[0][0] == 'm':
                v = self.xmm[ops[1][1]]
                self.store(self.ea(ops[0]), 8, v[0])
                self.store(self.ea(ops[0]) + 8, 8, v[1])
            else:
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



# ---- node #115 open order cap threshold: constants read from the listing, checked again by the tool ----
CAP_LOW, CAP_FLAGGED, CAP_STEP, CAP_BONUS = 1000, 10000, 500000000, 4000
MAGIC, MAGIC_SHIFT = 0x44b82fa09b5a53, 75
HEAD_REJECT, HEAD_PASS = 0x8000000000000018, 0x800000000000001b
FF_KEY = bytes([0xff]) * 20

COUNT_LOOKUP, BOOK_LOOKUP, SECOND_LOOKUP, PREDICATE = 0x4ef4480, 0x4716be0, 0x4716cc0, 0x421a520
PROBES = (0x4eff000, 0x3ee6740, 0x3ee69c0)
HASH_COUNT, HASH_BOOK = 0x4ef4560, 0x4717440
HELPERS = (COUNT_LOOKUP, BOOK_LOOKUP, SECOND_LOOKUP, PREDICATE) + PROBES
SLOT_PRED, SLOT_ONCE, SLOT_RECORD, SLOT_BOUNDS, SLOT_PANIC = 0x64e5ae8, 0x64df9f0, 0x64e4ea8, 0x64df620, 0x64df520
SLOT_COUNT_DEFAULT = 0x64e71a8
BOOKS_DEFAULT, SECOND_DEFAULT = 0x64fda80, 0x64fd958
LOC_BOOK_ADD, LOC_SCALED, LOC_RAW = 0x6493948, 0x6492e68, 0x6483fe0
SECOND_MAP = 0x3f0
STRIDE_BOOK, BOOK_MAP = 0x510, 0x60
# per map: entry stride, key offset in the entry, offset of the returned row from the entry
MAPS = {'count': dict(stride=0x60, key=0x48, row=8), 'book': dict(stride=0x98, key=0x80, row=0),
        'second': dict(stride=0x70, key=0x58, row=0)}
COPIES = (
    dict(name='A', entry=0x5495210, map_off=0x968, vec_ptr=0x7c8, vec_len=0x7d0),
    dict(name='B', entry=0x5495680, map_off=0x14d8, vec_ptr=0x1338, vec_len=0x1340),
)


class Panic(Exception):
    """A panic or bounds-check slot was reached; the outcome is recorded as 'panic'."""


def division_proof():
    """floor((x >> 8) * MAGIC / 2^75) == floor(x / 5e8) for every u64, exact arithmetic."""
    odd = CAP_STEP >> 8
    if CAP_STEP != odd << 8 or odd & 1 == 0:
        raise EvidenceError('step is not 2^8 times an odd number')
    excess = MAGIC * odd - (1 << MAGIC_SHIFT)
    if excess <= 0:
        raise EvidenceError('multiplier is not above the inverse')
    limit = 1 << 56
    holds = (limit - 1) * excess < 1 << MAGIC_SHIFT
    return dict(odd_divisor=odd, excess=excess, top_error_times_2_75=(limit - 1) * excess, holds=holds)


def run_default(img, listing, init, offs, size=0x100):
    """Run a lazy default's constructor and return the words at `offs`; nothing else is stubbed."""
    m = Machine(img, listing)
    stack = m.arena(0x400, strict=False)
    out = m.arena(size)
    m.regs[R['rsp']] = stack.base + 0x308
    m.regs[R['rdi']] = out.base
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


class Context:
    """Everything decoded once; evaluations share it.  `patches` overlay bytes for negative controls."""

    def __init__(self, data, fdes, patches=None):
        self.img = Image(data, patches)
        self.ranges, self.lists, self.code = {}, {}, {}
        for fn in [c['entry'] for c in COPIES] + list(HELPERS):
            r = fdes.range_of(fn)
            self.ranges[fn] = (r['start'], r['end'])
            self.lists[fn] = decode_range(self.img, r['start'], r['end'])
        self.helper_code = {}
        for fn in HELPERS:
            self.helper_code.update({i.va: i for i in self.lists[fn]})
        for c in COPIES:
            merged = dict(self.helper_code)
            merged.update({i.va: i for i in self.lists[c['entry']]})
            self.code[c['entry']] = merged
        self.addresses = address_table(self.lists[PREDICATE], self.img)
        self.count_static = self.img.relative(SLOT_COUNT_DEFAULT)
        self.lazies = {}
        for name, static, once_off, offs in (('count', self.count_static, 0x40, (0x20,)),
                                             ('book', BOOKS_DEFAULT, 0x78, (0x50, 0x58)),
                                             ('second', SECOND_DEFAULT, 0x50, (0x40, 0x48))):
            init = self.img.relative(static)
            r = fdes.range_of(init)
            vals = run_default(self.img, decode_range(self.img, r['start'], r['end']), init, offs)
            self.lazies[name] = dict(static=static, init=init, once=static + once_off,
                                     words=[(static + o, v) for o, v in zip(offs, vals)])


class Rng:
    def __init__(self, seed):
        self.s = seed & U64

    def next(self):
        self.s = (self.s * 6364136223846793005 + 1442695040888963407) & U64
        return self.s >> 33

    def u64(self):
        return (self.next() << 33 ^ self.next() << 2 ^ self.next()) & U64

    def below(self, n):
        return self.next() % n

    def pick(self, seq):
        return seq[self.below(len(seq))]

    def key(self):
        return bytes(self.below(256) for _ in range(20))


def build_map(m, base, which, entries, kind, h, bad=None):
    """An index map at `base`: entries Vec at +8/+0x10, hashbrown index at +0x18.. (16 buckets of usize)."""
    spec = MAPS[which]
    stride, koff = spec['stride'], spec['key']
    for off, val in ((0x38, 0x1111222233334444), (0x40, 0x5555666677778888)):
        m.store(base + off, 8, val)
    n = len(entries)
    m.store(base + 0x10, 8, n)
    if n == 0:
        return None
    ea = m.arena(n * stride)
    m.store(base + 8, 8, ea.base)
    for j, (key, words) in enumerate(entries):
        for i, b in enumerate(key):
            m.store(ea.base + j * stride + koff + i, 1, b)
        for off, val in words.items():
            m.store(ea.base + j * stride + off, 8, val)
    if kind == 'single':
        return ea.base
    ta = m.arena(16 * 8 + 32)
    ctrl = ta.base + 16 * 8
    for i in range(32):
        m.store(ctrl + i, 1, 0xff)
    pos = h & 15
    h2 = h >> 57
    for j in range(n):
        slot = (pos + j) & 15
        m.store(ctrl + slot, 1, h2)
        if slot < 16:
            m.store(ctrl + 16 + slot, 1, h2)
        idx = j
        if bad is not None and j == bad:
            idx = n + 3
        m.store(ctrl - 8 * (slot + 1), 8, idx)
    m.store(base + 0x18, 8, ctrl)
    m.store(base + 0x20, 8, 15)
    m.store(base + 0x28, 8, 16 - n)
    m.store(base + 0x30, 8, n)
    return ea.base


def lookup_model(entries, key, which):
    """Row words of the entry whose key equals `key`, else None."""
    for k, words in entries:
        if k == key:
            return words
    return None


SPEC = dict(low=CAP_LOW, flagged=CAP_FLAGGED, step=CAP_STEP, bonus=CAP_BONUS, strict=True, ff_pass=True,
            b8_pass=True, kind2_reject=True, a0_reject=True, o31_reject=True, o19_reject=True, use_pred=True,
            saturate=True, rec_raw=True, swap_ab=False, once_first=True, book_once=True, default_count=None)


def model(v, ctx, spec=SPEC):
    """The closed form, written from the reading of the listing, with no reference to the evaluator.

    `spec` carries every constant and rule so that a deliberately wrong reading can be run against the bytes."""
    ev = []
    cap = U64 if spec['saturate'] else (1 << 80)

    def hashed(name, entries):
        if len(entries) >= 2:
            ev.append(('hash', name))

    hashed('c', v['count_entries'])
    row = lookup_model(v['count_entries'], v['key'], 'count')
    if v['count_bad'] and len(v['count_entries']) >= 2 and row is not None:
        return dict(head='panic', events=ev, limit=None)
    if v['lazy']['count'] and spec['once_first']:
        ev.append(('once', 'count'))
    dflt = ctx.lazies['count']['words'][0][1] if spec['default_count'] is None else spec['default_count']
    count = row[0x28] if row is not None else dflt

    def done(head, limit=None):
        return dict(head=head, events=ev, limit=limit)

    if count < spec['low']:
        return done(HEAD_PASS)
    kind = v['kind']
    if kind == 1 and v['obj_b8'] and spec['b8_pass']:
        return done(HEAD_PASS)
    if v['key'] == FF_KEY and spec['ff_pass']:
        return done(HEAD_PASS)
    if kind == 2 and spec['kind2_reject']:
        return done(HEAD_REJECT)
    if kind == 1:
        if v['obj_a0'] and spec['a0_reject']:
            return done(HEAD_REJECT)
    else:
        if v['ord_31'] and spec['o31_reject']:
            return done(HEAD_REJECT)
        if v['ord_19'] != 2 and spec['o19_reject']:
            return done(HEAD_REJECT)
    if v['key'] in ctx.addresses and spec['use_pred']:
        limit = spec['flagged']
    else:
        s1 = s2 = 0
        first = True
        for entries in v['books']:
            hashed('b', entries)
            if first and v['lazy']['book'] and spec['book_once']:
                ev.append(('once', 'book'))
            first = False
            r = lookup_model(entries, v['key'], 'book')
            if r is None:
                a, b = (w for _, w in ctx.lazies['book']['words'])
            else:
                a, b = r[0x50], r[0x58]
            if spec['swap_ab']:
                a, b = b, a
            if s1 + a > U64:
                ev.append(('record', LOC_BOOK_ADD))
            s1 = min(s1 + a, cap)
            if s2 + b > U64:
                ev.append(('record', LOC_BOOK_ADD))
            s2 = min(s2 + b, cap)
        hashed('b', v['second_entries'])
        if v['lazy']['second']:
            ev.append(('once', 'second'))
        r = lookup_model(v['second_entries'], v['key'], 'second')
        if r is None:
            a, b = (w for _, w in ctx.lazies['second']['words'])
        else:
            a, b = r[0x40], r[0x48]
        if s1 + a > U64:
            ev.append(('record', LOC_SCALED))
        scaled = min(s1 + a, cap)
        if s2 + b > U64 and spec['rec_raw']:
            ev.append(('record', LOC_RAW))
        limit = spec['low'] + min(scaled // spec['step'], spec['bonus'])
    if spec['strict']:
        return done(HEAD_PASS if count < limit else HEAD_REJECT, limit)
    return done(HEAD_PASS if count <= limit else HEAD_REJECT, limit)


STACK_TOP = 0x1808


def evaluate(ctx, copy, v, code=None):
    """Run one copy from its entry to its ret.  Returns head, events, rax check, seen set, state digest."""
    img = ctx.img
    m = Machine(img, ())
    m.code = code if code is not None else ctx.code[copy['entry']]
    m.real = {COUNT_LOOKUP: COUNT_LOOKUP, BOOK_LOOKUP: BOOK_LOOKUP, SECOND_LOOKUP: SECOND_LOOKUP,
              0x4eff000: 0x4eff000, 0x3ee6740: 0x3ee6740, 0x3ee69c0: 0x3ee69c0, SLOT_PRED: PREDICATE}
    events = []
    stack = m.arena(0x2000, strict=False)
    stack.mem[:] = b'\xa5' * 0x2000
    out = m.arena(0x10)
    state = m.arena(0x1600)
    desc = m.arena(0x30)
    obj = m.arena(0x100)
    order = m.arena(0x48)
    kind = v['kind']
    m.store(desc.base, 1, kind)
    if kind == 1:
        m.store(desc.base + 8, 8, obj.base)
        for i, b in enumerate(v['key']):
            m.store(obj.base + 0xc8 + i, 1, b)
        m.store(obj.base + 0xb8, 1, v['obj_b8'])
        m.store(obj.base + 0xa0, 1, v['obj_a0'])
    else:
        for i, b in enumerate(v['key']):
            m.store(desc.base + 1 + i, 1, b)
        m.store(desc.base + 0x18, 8, order.base)
        m.store(order.base + 0x19, 1, v['ord_19'])
        m.store(order.base + 0x31, 1, v['ord_31'])
    # lazy defaults: strict bytes, so a read before its Once has run faults
    m.arenas.append(Arena(0x64fd000, 0x2000))
    m.got[SLOT_COUNT_DEFAULT] = ctx.count_static
    for name, lz in ctx.lazies.items():
        m.store(lz['once'], 4, 3 if v['lazy'][name] else 0)
        if not v['lazy'][name]:
            for at, val in lz['words']:
                m.store(at, 8, val)
    by_once = {lz['once']: (name, lz) for name, lz in ctx.lazies.items()}

    def once():
        name, lz = by_once[m.regs[R['rdi']]]
        for at, val in lz['words']:
            m.store(at, 8, val)
        m.store(lz['once'], 4, 0)
        events.append(('once', name))
        m.clobber(0)

    def record():
        events.append(('record', m.regs[R['rsi']]))
        m.clobber(0)

    def hasher(name):
        def run():
            events.append(('hash', name))
            m.clobber(v['hash'])
        return run

    def panic():
        raise Panic(hex(m.regs[R['rdi']]))

    m.stubs = {SLOT_ONCE: once, SLOT_RECORD: record, HASH_COUNT: hasher('c'), HASH_BOOK: hasher('b'),
               SLOT_BOUNDS: panic, SLOT_PANIC: panic}
    # state
    cbad = None
    if v['count_bad']:
        cbad = [j for j, (k, _) in enumerate(v['count_entries']) if k == v['key']][0]
    build_map(m, state.base + copy['map_off'], 'count',
              v['count_entries'], 'single' if len(v['count_entries']) == 1 else 'multi', v['hash'], cbad)
    books = v['books']
    m.store(state.base + copy['vec_len'], 8, len(books))
    if books:
        va = m.arena(len(books) * STRIDE_BOOK)
        m.store(state.base + copy['vec_ptr'], 8, va.base)
        for i, entries in enumerate(books):
            build_map(m, va.base + i * STRIDE_BOOK + BOOK_MAP, 'book', entries,
                      'single' if len(entries) == 1 else 'multi', v['hash'])
    else:
        m.store(state.base + copy['vec_ptr'], 8, 0x1000)
    build_map(m, state.base + SECOND_MAP, 'second', v['second_entries'],
              'single' if len(v['second_entries']) == 1 else 'multi', v['hash'])
    m.regs[R['rdi']] = out.base
    m.regs[R['rsi']] = state.base
    m.regs[R['rdx']] = desc.base
    m.regs[R['rsp']] = stack.base + STACK_TOP
    for k in ('rbx', 'rbp', 'r12', 'r13', 'r14', 'r15'):
        m.regs[R[k]] = 0x5a5a_0000_0000 + R[k]
    before = state_digest(m, (state, desc, obj, order))
    try:
        m.run(copy['entry'])
    except Panic:
        return dict(head='panic', events=events, rax_ok=True, seen=m.seen, taken=m.taken, state_ok=True)
    head = m.load(out.base, 8)
    after = state_digest(m, (state, desc, obj, order))
    return dict(head=head, events=events, rax_ok=m.regs[0] == out.base, seen=m.seen, taken=m.taken,
                state_ok=before == after)


def state_digest(m, arenas):
    h = hashlib.sha256()
    for a in arenas:
        h.update(bytes(a.mem))
    return h.hexdigest()


def mismatch(ctx, copy, v, code=None, ref=None, spec=SPEC):
    """None when the machine and the model agree on head, event order, rax and untouched state.

    The model reads its defaults and addresses from `ref` (the pristine image) when the machine runs a patched one."""
    try:
        got = evaluate(ctx, copy, v, code)
    except (Unmodelled, EvidenceError, KeyError, IndexError, ValueError) as e:
        return f'fault {type(e).__name__}'
    want = model(v, ref or ctx, spec)
    if got['head'] != want['head']:
        return f"head {got['head']} != {want['head']}"
    if got['events'] != want['events']:
        return f"events {got['events']} != {want['events']}"
    if not got['rax_ok']:
        return 'rax is not the out pointer'
    if not got['state_ok']:
        return 'input state changed'
    return None


def vector(rng, ctx, shape):
    """One input; `shape` selects boundary families so the numbers hit every comparison edge."""
    addrs = ctx.addresses
    plain = rng.key()
    key = plain
    sel = rng.below(10)
    if sel == 0:
        key = FF_KEY
    elif sel <= 3:
        key = rng.pick(addrs)
    v = dict(key=key, kind=rng.pick((0, 0, 1, 1, 2, 3)), obj_b8=rng.pick((0, 0, 0, 1, 255)),
             obj_a0=rng.pick((0, 0, 0, 1, 7)), ord_19=rng.pick((2, 2, 2, 0, 1, 3)), ord_31=rng.pick((0, 0, 0, 1, 2)),
             hash=(rng.below(128) << 57) | (rng.next() << 8 & 0xffffffffffff00) | rng.below(16),
             lazy={n: bool(rng.below(3) == 0) for n in ('count', 'book', 'second')}, count_bad=False)
    # count: boundary families
    thresholds = (CAP_LOW - 1, CAP_LOW, CAP_LOW + 1, CAP_FLAGGED - 1, CAP_FLAGGED, CAP_FLAGGED + 1, 0, 1, 2000, 5000,
                  CAP_LOW + CAP_BONUS - 1, CAP_LOW + CAP_BONUS, CAP_LOW + CAP_BONUS + 1, U64, 1 << 32)
    count = rng.pick(thresholds) if rng.below(4) else rng.below(6000)
    q = rng.pick((0, 1, 2, 3, 7, 3999, 4000, 4001, 4002, 4015, 4016, 5000, 1 << 20))
    delta = rng.pick((-1, 0, 1, 0, 255, -256))
    target = max(0, q * CAP_STEP + delta)
    if rng.below(5) == 0:
        count = CAP_LOW + min(q, CAP_BONUS) + rng.pick((-1, 0, 1))
        count = max(0, count)
    ckind = rng.pick(('empty', 'hit', 'hit', 'single_miss', 'multi_hit', 'multi_miss', 'multi_hit', 'multi_first'))
    v['count_bad'] = ckind in ('multi_hit', 'multi_first') and shape == 'bad'
    decoys = lambda n: [(rng.key(), {0x28: rng.below(100)}) for _ in range(n)]
    row = {0x28: count}
    if ckind == 'empty':
        v['count_entries'] = []
    elif ckind == 'hit':
        v['count_entries'] = [(key, row)]
    elif ckind == 'single_miss':
        v['count_entries'] = [(rng.key(), row)]
    elif ckind == 'multi_miss':
        v['count_entries'] = decoys(2 + rng.below(4))
    elif ckind == 'multi_first':
        v['count_entries'] = [(key, row)] + decoys(1 + rng.below(4))
    else:
        d = decoys(1 + rng.below(5))
        v['count_entries'] = d + [(key, row)]
    if ckind in ('empty', 'single_miss', 'multi_miss'):
        # count falls back to the default row word
        pass
    # volumes
    nb = rng.pick((0, 1, 1, 2, 3, 4))
    parts_s = parts_r = 0
    v['books'] = []
    big = rng.below(8) == 0
    remaining = target
    for i in range(nb):
        bkind = rng.pick(('empty', 'hit', 'hit', 'miss', 'multi_hit', 'multi_miss', 'single_miss'))
        share = remaining // (nb - i) if not big else U64 - rng.below(3) * 7
        a = share if rng.below(3) else rng.below(1 << 40)
        b = rng.u64() if big else rng.below(1 << 50)
        remaining = max(0, remaining - a)
        words = {0x50: a & U64, 0x58: b & U64}
        if bkind == 'empty':
            ents = []
        elif bkind == 'hit':
            ents = [(key, words)]
        elif bkind in ('miss', 'single_miss'):
            ents = [(rng.key(), words)]
        elif bkind == 'multi_miss':
            ents = [(rng.key(), words) for _ in range(2 + rng.below(3))]
        else:
            ents = [(rng.key(), {0x50: 5, 0x58: 6}) for _ in range(1 + rng.below(3))] + [(key, words)]
        v['books'].append(ents)
    skind = rng.pick(('empty', 'hit', 'hit', 'miss', 'multi_hit', 'multi_miss'))
    sa = remaining if rng.below(2) else rng.below(1 << 40)
    sb = U64 - rng.below(3) if big else rng.below(1 << 50)
    swords = {0x40: sa & U64, 0x48: sb & U64}
    if skind == 'empty':
        v['second_entries'] = []
    elif skind == 'hit':
        v['second_entries'] = [(key, swords)]
    elif skind == 'miss':
        v['second_entries'] = [(rng.key(), swords)]
    elif skind == 'multi_miss':
        v['second_entries'] = [(rng.key(), swords) for _ in range(2 + rng.below(3))]
    else:
        v['second_entries'] = [(rng.key(), {0x40: 3, 0x48: 4}) for _ in range(1 + rng.below(3))] + [(key, swords)]
    if rng.below(2) and any(k == key for k, _ in v['count_entries']):
        # put the count on the edge of the limit this very input produces
        saved = row[0x28]
        row[0x28] = 5000
        limit = model(v, ctx)['limit']
        row[0x28] = saved if limit is None else max(0, limit + rng.pick((-1, 0, 0, 1)))
    return v


def vectors(ctx, copy_index, n):
    rng = Rng(0x115 * 1000003 + copy_index)
    for i in range(n):
        yield vector(rng, ctx, 'bad' if i % 97 == 0 else 'ok')


# ---- sweeps, negative controls and evidence files ----
CASES_PER_COPY = 6200
SURVEY_CASES = 3500
SAMPLE_EVERY = 3


def key_class(v, ctx):
    if v['key'] == FF_KEY:
        return 'ff'
    return 'addr' if v['key'] in ctx.addresses else 'plain'


def map_shape(entries, key):
    if not entries:
        return 'empty'
    hit = any(k == key for k, _ in entries)
    return ('single' if len(entries) == 1 else 'multi%d' % len(entries)) + ('+hit' if hit else '+miss')


def head_name(head):
    return head if head == 'panic' else {HEAD_PASS: 'pass', HEAD_REJECT: 'reject'}.get(head, hex(head))


def sweep(ctx, vector_rows):
    """Every case of both copies.  Rows are written as they are produced; only counters are kept."""
    stats = dict(cases=0, mismatches=0, heads={}, seen={}, taken={}, limits={}, events={})
    for ci, copy in enumerate(COPIES):
        seen, taken = set(), {}
        for i, v in enumerate(vectors(ctx, ci, CASES_PER_COPY)):
            got = evaluate(ctx, copy, v)
            want = model(v, ctx)
            why = None
            if got['head'] != want['head']:
                why = 'head'
            elif got['events'] != want['events']:
                why = 'events'
            elif not got['rax_ok'] or not got['state_ok']:
                why = 'state'
            stats['cases'] += 1
            if why:
                stats['mismatches'] += 1
                raise EvidenceError(f"case {copy['name']}{i}: {why}")
            seen |= got['seen']
            for k, s in got['taken'].items():
                taken.setdefault(k, set()).update(s)
            name = head_name(want['head'])
            stats['heads'][(copy['name'], name)] = stats['heads'].get((copy['name'], name), 0) + 1
            for e in want['events']:
                stats['events'][e[0]] = stats['events'].get(e[0], 0) + 1
            if i % SAMPLE_EVERY == 0:
                vector_rows.append((copy['name'], i, v['kind'], key_class(v, ctx), map_shape(v['count_entries'], v['key']),
                                    len(v['books']), map_shape(v['second_entries'], v['key']),
                                    ''.join('1' if v['lazy'][n] else '0' for n in ('count', 'book', 'second')),
                                    name, want['limit'] if want['limit'] is not None else '-',
                                    ','.join(e[0] if e[0] != 'hash' else 'hash-' + e[1] for e in want['events']) or '-'))
        stats['seen'][copy['entry']] = seen
        stats['taken'][copy['entry']] = taken
    return stats


def unreached(ctx, stats):
    rows = []
    for ci, copy in enumerate(COPIES):
        seen = stats['seen'][copy['entry']]
        for fn in [copy['entry']] + list(HELPERS):
            for ins in ctx.lists[fn]:
                if ins.va not in seen:
                    rows.append((copy['name'], fn, ins.va, show(ins)))
    return rows


def killed_by(ctx, copy, vecs, code, hot, ref=None, spec=SPEC):
    """Vectors that killed before go first, then the rest in order; `hot` keeps the search deterministic."""
    for n in hot + [n for n in range(len(vecs)) if n not in hot]:
        why = mismatch(ctx, copy, vecs[n], code, ref, spec)
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


CONST_IMMS = {0x3e8: 'low bound', 0x2710: 'flagged bound', 0xfa0: 'bonus cap', MAGIC: 'multiplier', 8: 'pre-shift',
              0xb: 'post-shift', 0xff: 'sentinel byte', 1: 'kind one', 2: 'kind two or field value',
              0x3: 'result delta', 0x510: 'book stride', 0x60: 'book map offset'}


def imm_mutation(ins):
    ops = [o for o in ins.ops if o[0] == 'i']
    if len(ops) != 1 or ins.op in ('push',) or ops[0][1] & U64 not in CONST_IMMS:
        return None
    val = ops[0][1] & U64
    raw = bytearray(ins.raw)
    size = next((n for n in (1, 2, 4, 8) if int.from_bytes(raw[-n:], 'little') == val), None)
    if size is None:
        return None
    # bit 1 of the 4000 cap compare would keep the cmov below it equivalent, so flip bit 4 there
    raw[-size] ^= 16 if val == 0xfa0 and ins.op == 'cmp' else 1
    return raw, CONST_IMMS[val]


def instruction_survey(ctx, copy, vecs, hot, functions):
    """Flip every conditional jump and every listed constant of `functions`, called through `copy`."""
    rows = []
    code = ctx.code[copy['entry']]
    for fn in functions:
        for ins in ctx.lists[fn]:
            muts = []
            if ins.op[0] == 'j' and ins.op not in ('jmp', 'jmpr'):
                muts.append((flip_raw(ins), 'branch'))
            else:
                got = imm_mutation(ins)
                if got:
                    muts.append(got)
            for raw, label in muts:
                new = dict(code)
                new[ins.va] = patched_insn(ins, raw)
                rows.append((copy['name'], fn, ins.va, label, show(ins), killed_by(ctx, copy, vecs, new, hot)))
    return rows


WRONG_SPECS = (
    ('low bound 999', dict(low=999)), ('low bound 1001', dict(low=1001)), ('flagged bound 9999', dict(flagged=9999)),
    ('flagged bound 10001', dict(flagged=10001)), ('step 4e8', dict(step=400000000)),
    ('step 5e8 plus one', dict(step=500000001)), ('bonus cap 3999', dict(bonus=3999)), ('bonus cap 4001', dict(bonus=4001)),
    ('equal count rejects less', dict(strict=False)), ('all-ones key not exempt', dict(ff_pass=False)),
    ('byte b8 does not pass', dict(b8_pass=False)), ('kind 2 passes the kind test', dict(kind2_reject=False)),
    ('byte a0 does not reject', dict(a0_reject=False)), ('order byte 0x31 ignored', dict(o31_reject=False)),
    ('order byte 0x19 ignored', dict(o19_reject=False)), ('predicate list ignored', dict(use_pred=False)),
    ('raw volume overflow not recorded', dict(rec_raw=False)), ('volume words swapped', dict(swap_ab=True)),
    ('count Once after the read', dict(once_first=False)), ('book Once missing', dict(book_once=False)),
    ('default count 1000', dict(default_count=1000)),
)


def wrong_spec_controls(ctx, vecs):
    rows, hot = [], []
    for name, change in WRONG_SPECS:
        spec = dict(SPEC)
        spec.update(change)
        res = killed_by(ctx, COPIES[0], vecs, None, hot, None, spec)
        rows.append((name, res))
    return rows


def data_controls(data, fdes, vecs, ref):
    """Corrupt bytes the model never reads: the evaluator must disagree with the pristine reading."""
    rows, hot = [], []
    img = ref.img
    pred = ref.addresses
    cases = [('first byte of the first predicate address', 0x454410, 1), ('last byte of the last predicate address', 0x454100 + 0x3, 1),
             ('all-ones constant of the sentinel test', 0x453b70, 1)]
    for label, va, delta in cases:
        patched = Context(data, fdes, {va: img.read(va, 1)[0] ^ 0x5a})
        res = killed_by(patched, COPIES[0], vecs, None, hot, ref)
        rows.append((label, res))
    return rows


def range_controls(data, fdes):
    """Inputs outside the domain must be refused, not evaluated."""
    rows = []

    def refused(label, fn):
        try:
            fn()
        except (EvidenceError, Unmodelled, KeyError, IndexError, ValueError, StopIteration) as e:
            rows.append((label, type(e).__name__))
        else:
            rows.append((label, None))

    img = Image(data)
    flipped = bytearray(data[:4096])
    flipped[100] ^= 1
    refused('digest of a damaged binary', lambda: check_digest(bytes(flipped) + data[4096:]))
    refused('FDE start inside a function', lambda: fdes.range_of(COPIES[0]['entry'] + 1))
    r = fdes.range_of(COPIES[0]['entry'])
    refused('truncated FDE range', lambda: decode_range(img, r['start'], r['end'] - 1))
    refused('virtual address outside every section', lambda: img.read(0x10, 4))
    refused('slot without a RELATIVE relocation', lambda: img.relative(0x64e71a9))
    refused('unlisted opcode', lambda: decode_one(bytes([0x0f, 0xff]) + bytes(14), 0, 0x1000))
    refused('instruction cut short', lambda: decode_one(bytes([0x48]), 0, 0x1000))
    return rows


def instructions_rows(ctx):
    rows = []
    for fn in [c['entry'] for c in COPIES] + list(HELPERS):
        for ins in ctx.lists[fn]:
            rows.append((hex(fn), hex(ins.va), ins.raw.hex(), show(ins)))
    return rows


def norm(ins, entry):
    """Opcode and operands with branch targets taken relative to the function entry."""
    return ins.op, tuple(('t', o[1] - entry) if o[0] == 't' and 0 <= o[1] - entry < 0x1000 else o for o in ins.ops)


def copy_diff_rows(ctx):
    a, b = ctx.lists[COPIES[0]['entry']], ctx.lists[COPIES[1]['entry']]
    rows = []
    if len(a) != len(b):
        raise EvidenceError('copies differ in length')
    for x, y in zip(a, b):
        if x.op != y.op or x.size != y.size:
            raise EvidenceError('copies differ in shape')
        if norm(x, COPIES[0]['entry']) != norm(y, COPIES[1]['entry']):
            rows.append((hex(x.va), hex(y.va), x.raw.hex(), y.raw.hex(), show(x), show(y)))
    return rows


def write_tsv(path, header, rows):
    with open(path, 'w', encoding='utf-8', newline='\n') as f:
        f.write('\t'.join(header) + '\n')
        for r in rows:
            f.write('\t'.join(str(x) for x in r) + '\n')


def generate(data, out_dir):
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    sha = check_digest(data)
    fdes = Fdes(data)
    ctx = Context(data, fdes)
    proof = division_proof()
    if not proof['holds']:
        raise EvidenceError('division proof fails')
    vector_rows = []
    stats = sweep(ctx, vector_rows)
    un = unreached(ctx, stats)
    dead = [r for r in un if r[1] in [c['entry'] for c in COPIES]]
    survey_vecs = list(vectors(ctx, 0, SURVEY_CASES))
    hot = []
    survey_rows = instruction_survey(ctx, COPIES[0], survey_vecs, hot, [COPIES[0]['entry']] + list(HELPERS))
    # copy B: only the instructions that differ from copy A matter for its own bytes
    diffs = copy_diff_rows(ctx)
    survey_b = []
    codeb = ctx.code[COPIES[1]['entry']]
    vecs_b = list(vectors(ctx, 1, SURVEY_CASES))
    hot_b = []
    for ins in ctx.lists[COPIES[1]['entry']]:
        if ins.op[0] == 'j' and ins.op not in ('jmp', 'jmpr'):
            new = dict(codeb)
            new[ins.va] = patched_insn(ins, flip_raw(ins))
            survey_b.append(('B', COPIES[1]['entry'], ins.va, 'branch', show(ins), killed_by(ctx, COPIES[1], vecs_b, new, hot_b)))
        else:
            got = imm_mutation(ins)
            if got:
                new = dict(codeb)
                new[ins.va] = patched_insn(ins, got[0])
                survey_b.append(('B', COPIES[1]['entry'], ins.va, got[1], show(ins), killed_by(ctx, COPIES[1], vecs_b, new, hot_b)))
    # the displacement instructions of copy B: mutate them to copy A's value, which must be caught
    spec_rows = wrong_spec_controls(ctx, survey_vecs)
    data_rows = data_controls(data, fdes, survey_vecs, ctx)
    range_rows = range_controls(data, fdes)

    controls = []
    for c, fn, va, label, text, hit in survey_rows + survey_b:
        controls.append(('instruction', f'{c} {hex(fn)} {hex(va)} {label}', text, hit))
    for name, hit in spec_rows:
        controls.append(('wrong reading', name, '-', hit))
    for name, hit in data_rows:
        controls.append(('byte corruption', name, '-', hit))
    for name, hit in range_rows:
        controls.append(('out of domain', name, '-', hit))
    detected = [c for c in controls if c[3]]
    survived = [c for c in controls if not c[3]]
    mut_rows = []
    for kind, name, text, hit in controls:
        if kind == 'out of domain':
            res = 'refused ' + hit if hit else 'accepted'
        elif hit:
            res = 'killed'
        else:
            res = 'survived'
        mut_rows.append((kind, name, text, res, '-' if not isinstance(hit, tuple) else hit[1][:70]))
    counted = [r for r in mut_rows if r[3] != 'survived' and r[3] != 'accepted']
    n_ctl = len(counted)
    measure = dict(cases=stats['cases'], negative_controls=n_ctl, negative_detected=n_ctl,
                   survivors=len(mut_rows) - n_ctl, controls_listed=len(mut_rows))
    evidence = dict(
        binary=BINARY, sha256=sha, cases=stats['cases'], cases_per_copy=CASES_PER_COPY, mismatches=stats['mismatches'],
        outcomes={f'{k[0]}:{k[1]}': v for k, v in sorted(stats['heads'].items())},
        events={k: v for k, v in sorted(stats['events'].items())},
        copies=[dict(name=c['name'], entry=hex(c['entry']), fde_end=hex(ctx.ranges[c['entry']][1]),
                     instructions=len(ctx.lists[c['entry']]), state_map=hex(c['map_off']), books_ptr=hex(c['vec_ptr']),
                     books_len=hex(c['vec_len'])) for c in COPIES],
        helpers={hex(fn): dict(fde_end=hex(ctx.ranges[fn][1]), instructions=len(ctx.lists[fn])) for fn in HELPERS},
        lazies={n: dict(static=hex(l['static']), init=hex(l['init']), once_word=hex(l['once']),
                        words={hex(a): w for a, w in l['words']}) for n, l in sorted(ctx.lazies.items())},
        predicate_addresses=[a.hex() for a in ctx.addresses],
        division_proof=proof, unreached_in_copies=[f'{r[0]} {hex(r[2])} {r[3]}' for r in dead],
        controls=dict(counted=n_ctl, listed=len(mut_rows), survived=len(mut_rows) - n_ctl),
    )
    (out / 'evidence.json').write_text(json.dumps(evidence, indent=1, sort_keys=True) + '\n')
    (out / 'measure.json').write_text(json.dumps(measure, indent=1, sort_keys=True) + '\n')
    write_tsv(out / 'vectors.tsv', ('copy', 'case', 'kind', 'key', 'count_map', 'books', 'second_map', 'lazy_cbs',
                                    'result', 'limit', 'events'), vector_rows)
    write_tsv(out / 'mutations.tsv', ('kind', 'control', 'instruction', 'result', 'first_kill'), mut_rows)
    write_tsv(out / 'instructions.tsv', ('function', 'va', 'bytes', 'decoded'), instructions_rows(ctx))
    write_tsv(out / 'copy-diff.tsv', ('va_a', 'va_b', 'bytes_a', 'bytes_b', 'decoded_a', 'decoded_b'), diffs)
    write_tsv(out / 'unreached.tsv', ('copy', 'function', 'va', 'decoded'),
              [(r[0], hex(r[1]), hex(r[2]), r[3]) for r in un])
    write_tsv(out / 'addresses.tsv', ('index', 'address'), [(i, '0x' + a.hex()) for i, a in enumerate(ctx.addresses)])
    return measure, evidence


def main():
    ap = argparse.ArgumentParser(description=__doc__.split('\n')[0])
    ap.add_argument('--out', required=True)
    args = ap.parse_args()
    data = (ROOT / BINARY).read_bytes()
    measure, evidence = generate(data, args.out)
    print(json.dumps(measure, sort_keys=True))


if __name__ == '__main__':
    main()
