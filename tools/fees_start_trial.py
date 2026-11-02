#!/usr/bin/env python3
"""fees: node #94 start fee trial writer 0x3744020 and its row builder 0x37463f0, from bytes alone.

Static, no execution of the node.  The writer, the row builder, the row reader, the date helpers, the
action validator and the table entry path are decoded from ELF bytes by the table decoder below, which
must land exactly on each FDE end, and interpreted in Python on every vector.  The hash, the decimal
parser, its conversion and the table reserve are stubs.  Each outcome is compared with a separate
closed-form model byte by byte over the table, then every conditional, field offset and comparison of
the subject functions is mutated to test the vectors.

    python3 tools/fees_start_trial.py --out <dir>

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
        if b2 == 0x14 and p66:
            reg, rm = modrm(128, True)
            return done('unpcklpd', (('x', reg | rr << 3), rm), 128)
        if b2 in (0x59, 0x5d, 0x5f) and p66:
            reg, rm = modrm(128, True)
            return done({0x59: 'mulpd', 0x5d: 'minpd', 0x5f: 'maxpd'}[b2], (('x', reg | rr << 3), rm), 128)
        if b2 == 0xc2 and p66:
            reg, rm = modrm(128, True)
            pred = imm(1)[1] & 0xff
            if pred not in (1, 3, 4):
                raise EvidenceError(f'{va:#x}: unlisted cmppd predicate {pred}')
            return done({1: 'cmpltpd', 3: 'cmpunordpd', 4: 'cmpneqpd'}[pred], (('x', reg | rr << 3), rm), 128)
        if b2 == 0xc6 and not p66 and not rep:
            reg, rm = modrm(128, True)
            return done('shufps', (('x', reg | rr << 3), rm, imm(1)), 128)
        if b2 == 0x50 and not p66 and not rep:
            reg, rm = modrm(32, True)
            return done('movmskps', (gpr(reg | rr << 3, 32), rm), 32)
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
        elif op in ('mulpd', 'maxpd', 'minpd', 'cmpltpd', 'cmpneqpd', 'cmpunordpd'):
            a, b = self.x128(ops[0]), self.x128(ops[1])
            res = 0
            for k in range(2):
                x, y = a >> 64 * k & U64, b >> 64 * k & U64
                p, q = b2f(x), b2f(y)
                if op == 'mulpd':
                    w = f2b(p * q)
                elif op == 'maxpd':
                    w = x if p > q else y
                elif op == 'minpd':
                    w = x if p < q else y
                elif op == 'cmpltpd':
                    w = U64 if p < q else 0
                elif op == 'cmpneqpd':
                    w = U64 if p != q else 0
                else:
                    w = U64 if p != p or q != q else 0
                res |= w << 64 * k
            self.setx(ops[0], res)
        elif op == 'unpcklpd':
            a, b = self.x128(ops[0]), self.x128(ops[1])
            self.setx(ops[0], a & U64 | (b & U64) << 64)
        elif op == 'shufps':
            a, b, n = self.x128(ops[0]), self.x128(ops[1]), ops[2][1] & 0xff
            self.setx(ops[0], (a >> 32 * (n & 3) & 0xffffffff) | (a >> 32 * (n >> 2 & 3) & 0xffffffff) << 32
                      | (b >> 32 * (n >> 4 & 3) & 0xffffffff) << 64 | (b >> 32 * (n >> 6 & 3) & 0xffffffff) << 96)
        elif op == 'movmskps':
            a = self.x128(ops[1])
            self.wr(ops[0], sum((a >> (32 * k + 31) & 1) << k for k in range(4)))
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


WRITER, BUILD, ROW, ADD, CHECKED, VALIDATE, WRAP, ENTRY, FIND = (
    0x3744020, 0x37463f0, 0x3743df0, 0x1450810, 0x151f870, 0x3c058f0, 0x374fe60, 0x3596da0, 0x379a610)
DECODED = (WRITER, BUILD, ROW, ADD, CHECKED, VALIDATE, WRAP, ENTRY, FIND)
# Conditionals of these are mutated; the others have their own packets or are a library date helper.
SUBJECTS = (WRITER, BUILD, ADD, VALIDATE, WRAP)
HASH, RESERVE, PARSE, TO_F64, DROP, PANIC = 0x399c7a0, 0x357d310, 0x3799510, 0x4ead680, 0x3762510, 0x157a9b0
SLOTS = {0x57748f8: ROW, 0x5775e28: BUILD, 0x576f6b8: ADD, 0x576e8b0: CHECKED, 0x5773328: WRAP, 0x57731d8: PARSE,
         0x5773968: TO_F64, 0x576e468: PANIC, 0x5773680: RESERVE}
WRITER_SLOT = 0x5773920
HANDLER, CALLERS = 0x21e00b0, (0x21e0306, 0x46777d6, 0x4677a96)
HANDLER_COPIES = (0x4677580, 0x4677840)
STRIDE = 0xe8
OK, DISABLED, ACTIVE, NO_RATE, NO_EFFECT, COOLDOWN = 0x186, 0x138, 0x134, 0x135, 0x136, 0x137
LONG, CONVERT = 0x143, 0xab
TRIAL_DAYS, COOLDOWN_DAYS = 14, 90
MAX_LEN = 100
HEAD = 13  # test string header: kind, tag, word, total length
ALL_FF, ALL_FE = b'\xff' * 20, b'\xfe' * 20
MAX_YEAR, MIN_YEAR = 262142, -262143
# Reads of stack bytes nobody wrote: key padding, the row hole, and error payloads with no payload.
LOOSE = (0x3596dcc, 0x3596e79, 0x3744519, 0x3746536, 0x374653b, 0x3746540, 0x3746545, 0x374413c, 0x3744149, 0x374414e,
         0x3744163, 0x374416f, 0x374417b, 0x3744184, 0x3c05b28, 0x3c05b2d, 0x3c05b35, 0x3c05b3d, 0x3c05b55)
UNEXECUTED = (
    (0x151f969, 0x151f9bb, 'date helper, result in the first part of a 365-day estimate: only a negative or a very long add lands there; 14 or 90 days reach the slow path only across a year end and end in January to March'),
    (0x151fa4e, 0x151fa9c, 'five panics of the date helper: internal invariants, no input date reaches them'),
)
EQUIVALENT = {}
REFERENCE_ROWS = (
    ('differs', 'handlers/55_start_fee_trial.rs add_days', 'u32 day counter, checked_add',
     'packed chrono date (year, ordinal, flags), first word of the 12-byte time at exchange +0x60; calendar add through the helper with the text `NaiveDate + TimeDelta` overflowed'),
    ('differs', 'FeeTrialDefaults', 'volume anchor and multiplier are runtime fields',
     'only the four rates come from the tracker (+0x48); the row helper writes constants 0.0 and 1.0 for the other two'),
    ('differs', 'FeeTrialRecord.trial_end_day and the cooldown test', 'one field: stored as today + 14, read back for + 90',
     'two fields: the writer stores value +0x70 and the cooldown reads value +0xb0, which the writer never writes'),
    ('differs', 'FeeTrialRecord.active', 'one flag gates both the active error and the current profile',
     'value +0 selects the row; the active error needs a non-zero date at value +0x70'),
    ('differs', 'FeeTrialRecord layout', 'requested_rates and previous_rates are plain fields',
     'the reader copies them only when the date is non-zero, so the date is an Option niche for them'),
    ('differs', 'build_trial_record no-effect test', 'effective == current',
     'any(current[i] - scaled[i] > 0); differs only for a NaN current rate'),
    ('differs', 'resolve_volume_discount', 'a NaN volume stops at the first tier',
     'a NaN volume keeps walking and takes the last discount'),
    ('agrees', 'apply_start_fee_trial', 'disabled, active, template, cooldown, no effect, write linked users and sender',
     'same order; the row is built first, and parse errors sit between active and template'),
    ('agrees', 'is_supported_fee_trial', 'four rates of one template, or two add rates plus one override for both cross rates',
     'same; both add rates must match inside one template row before an override counts'),
    ('agrees', 'handler gates', 'status 141 for byte 3 at +0x8f2, then status 219 for a sub account', 'same at 0x21e00be and 0x21e02bd'),
    ('absent', 'handlers/55_start_fee_trial.rs', 'the two fixed addresses are not modelled',
     'all-0xff and all-0xfe senders get a zero row with multiplier 0, so only a negative requested rate has an effect'),
)
PINNED = (
    (0x21e00be, '80b9f208000003', 'handler: compare byte +0x8f2 with 3'),
    (0x21e02de, '498db424d0050000', 'handler: tracker is exchange +0x5d0'),
    (0x21e02e6, '418b442468', 'handler: third word of the time at exchange +0x68'),
    (0x21e02ef, '498b442460', 'handler: first two words of the time at exchange +0x60'),
    (0x46777ae, '498db424d0050000', 'second copy: tracker is exchange +0x5d0'),
    (0x4677a6e, '498db42450100000', 'third copy: tracker is exchange +0x1050'),
    (0x3744203, '418b6d00', 'writer: date is the first word of the time argument'),
    (0x37442fe, '428b7c09e0', 'writer: cooldown date is bucket end -0x20, entry +0xc8, value +0xb0'),
    (0x3744488, '44896870', 'writer: linked users get the date at value +0x70'),
    (0x37444c4, '48c70001000000', 'writer: sender value +0 = 1'),
    (0x374431f, 'be0e000000', 'writer: 14 days'),
    (0x3744307, 'be5a000000', 'writer: 90 days'),
    (0x1450813, '4869c080510100', 'day helper: 86400 seconds a day'),
)
ACTION_FIELDS = 0x3d2da0


class Panicked(Exception):
    """The node would panic here; a modelled outcome, unlike Unmodelled."""


def key_hash(key):
    return int.from_bytes(hashlib.sha256(key).digest()[:8], 'little')


def addr(n):
    """A 20-byte test address."""
    return hashlib.sha256(b'addr' + str(n).encode()).digest()[:20]


# ---- calendar model, written from the documented chrono packing and independent of the machine


def days_from_civil(y, m, d):
    y -= m <= 2
    era = y // 400
    yoe = y - era * 400
    doy = (153 * (m + (-3 if m > 2 else 9)) + 2) // 5 + d - 1
    return era * 146097 + yoe * 365 + yoe // 4 - yoe // 100 + doy - 719468


def civil_year(z):
    z += 719468
    era = z // 146097
    doe = z - era * 146097
    yoe = (doe - doe // 1460 + doe // 36524 - doe // 146096) // 365
    doy = doe - (365 * yoe + yoe // 4 - yoe // 100)
    return yoe + era * 400 + (doy >= 306)


def is_leap(y):
    return y % 4 == 0 and (y % 100 != 0 or y % 400 == 0)


def year_flags(y):
    sunday_zero = (days_from_civil(y, 1, 1) + 4) % 7
    return (sunday_zero + 4) % 7 + 1 | (0 if is_leap(y) else 8)


def pack_day(z):
    y = civil_year(z)
    ordinal = z - days_from_civil(y, 1, 1) + 1
    return (y << 13 | ordinal << 4 | year_flags(y)) & 0xffffffff


def date(y, m, d):
    return pack_day(days_from_civil(y, m, d))


def unpack_day(p):
    return days_from_civil(signed(p, 32) >> 13, 1, 1) + (p >> 4 & 0x1ff) - 1


def add_days(p, n):
    z = unpack_day(p) + n
    if z > days_from_civil(MAX_YEAR, 12, 31):
        return None
    return pack_day(z)


# ---- closed-form model of one call


def discount(tiers, vol):
    if not tiers or tiers[0][0] > vol:
        return 0.0
    i = 1
    while i < len(tiers) and not tiers[i][0] > vol:
        i += 1
    return tiers[i - 1][1]


def fmin(cur, scaled):
    if scaled != scaled:
        return cur
    return cur if cur < scaled else scaled


def row_of(v):
    """(rates, volume, date, multiplier) of the sender, as the row helper resolves it."""
    if v['sender'] in (ALL_FF, ALL_FE):
        return (0.0, 0.0, 0.0, 0.0), 0.0, 0, 0.0
    e = v['users'].get(v['sender'])
    if e is None or not e.get('tag', 1):
        return tuple(v['defaults']), 0.0, 0, 1.0
    return tuple(e['rates']), e['vol'], e.get('end', 0), e['mult']


def validate(v):
    """(error, parse calls, word); error None when all four strings pass."""
    calls = 0
    for pos in range(4):
        a = v['action'][pos]
        if a['pad'] > MAX_LEN - HEAD:
            return LONG, calls, None
        calls += 1
        if a.get('tag') is not None:
            return a['tag'], calls, a['word']
        if a.get('fail'):
            # only the out-of-line fourth step keeps the parsed value behind the status
            return CONVERT, calls, f2b(a['rate']) if pos == 3 else None
    return None, calls, None


def supported(v, req):
    add_hit = False
    for t in v['templates']:
        if t[0] == req[0] and t[2] == req[2]:
            add_hit = True
            if t[1] == req[1] and t[3] == req[3]:
                return True
    if add_hit:
        return any(o[1] == req[1] and o[1] == req[3] for o in v['overrides'])
    return False


def apply_model(v):
    out = dict(status=None, word=None, parses=0, panic=False, writes=(), row=None)
    rates, vol, end, mult = row_of(v)
    if v['disabled']:
        out['status'] = DISABLED
        return out
    if end:
        out['status'] = ACTIVE
        return out
    err, out['parses'], out['word'] = validate(v)
    if err is not None:
        out['status'] = err
        return out
    req = tuple(a['rate'] for a in v['action'])
    if not supported(v, req):
        out['status'] = NO_RATE
        return out
    e = v['users'].get(v['sender'])
    if e is not None and e.get('base'):
        until = add_days(e['base'], COOLDOWN_DAYS)
        if until is None:
            out['panic'] = True
            return out
        if signed(until, 32) > signed(v['date'], 32):
            out['status'] = COOLDOWN
            return out
    stop = add_days(v['date'], TRIAL_DAYS)
    if stop is None:
        out['panic'] = True
        return out
    keep = 1.0 - discount(v['tiers'], vol)
    scaled = [r * keep if 0.0 < r else r for r in req]
    if not any(c - s > 0.0 for c, s in zip(rates, scaled)):
        out['status'] = NO_EFFECT
        return out
    out['status'] = OK
    out['row'] = dict(rates=tuple(fmin(c, s) for c, s in zip(rates, scaled)), vol=vol, req=req, prev=rates, end=stop, mult=mult)
    out['writes'] = tuple(v['linked'] or ()) + (v['sender'],)
    return out


# ---- memory shapes


def put(m, a, off, size, val):
    m.store(a.base + off, size, val)


def put_bytes(m, a, off, raw):
    for i, b in enumerate(raw):
        m.store(a.base + off + i, 1, b)


def put_f(m, a, off, x):
    m.store(a.base + off, 8, f2b(x))


def group_at(ctrl, size, pos):
    """The 16 control bytes a probe at `pos` reads, with the trailing mirror."""
    full = list(ctrl) + (list(ctrl[:16]) if size >= 16 else [0xff] * (16 - size) + list(ctrl))
    return [full[pos + k] for k in range(16)]


def free_slot(ctrl, h):
    """Hashbrown's first free slot from the probe of hash `h`, written from its documented rules."""
    size = len(ctrl)
    pos, step = h & (size - 1), 0
    while True:
        group = group_at(ctrl, size, pos)
        hits = [k for k, c in enumerate(group) if c & 0x80]
        if hits:
            slot = (pos + hits[0]) & (size - 1)
            if ctrl[slot] & 0x80:
                return slot
            return next(k for k in range(16) if ctrl[k] & 0x80)
        step += 16
        pos = (pos + step) & (size - 1)


def build_table(m, v):
    """A hashbrown table: `size` buckets, control bytes after the bucket area, 0xe8-byte buckets below."""
    size = v['size']
    a = m.arena(STRIDE * size + 16 + max(size, 16) + 16 + 16)
    ctrl_off = STRIDE * size + 16
    ctrl = [0xff] * size

    def place(key):
        h = key_hash(key)
        pos, step = h & (size - 1), 0
        while True:
            for k in range(16):
                i = (pos + k) & (size - 1)
                if ctrl[i] == 0xff:
                    ctrl[i] = h >> 57
                    return i
            step += 16
            pos += step

    for dead in v['tombstones']:
        ctrl[dead] = 0x80
    for key in v['decoys']:
        i = place(key)
        fill_entry(m, a, ctrl_off - (i + 1) * STRIDE, key, None)
    for key, e in v['users'].items():
        i = place(key)
        fill_entry(m, a, ctrl_off - (i + 1) * STRIDE, key, e)
    for i in range(size):
        put(m, a, ctrl_off + i, 1, ctrl[i])
    tail = ctrl[:16] if size >= 16 else [0xff] * (16 - size) + ctrl
    for i, c in enumerate(tail):
        put(m, a, ctrl_off + size + i, 1, c)
    m.ctrl0 = list(ctrl)
    m.table, m.ctrl_off = a, ctrl_off
    return a.base + ctrl_off, size


def fill_entry(m, a, at, key, e):
    """One bucket; every byte is set, so a stray read or write of a neighbour field shows."""
    for off in range(0, STRIDE, 8):
        put(m, a, at + off, 8, 0xa5a5a5a500000000 | off)
    put_bytes(m, a, at, key)
    e = e or dict(tag=0, rates=(9.0, 9.0, 9.0, 9.0), vol=9.0, mult=9.0, base=0, end=0)
    put(m, a, at + 0x18, 8, e.get('tag', 1))
    for i, x in enumerate(e['rates']):
        put_f(m, a, at + 0x20 + 8 * i, x)
    put_f(m, a, at + 0x40, e['vol'])
    for i, x in enumerate(e.get('req', (5.0, 6.0, 7.0, 8.0))):
        put_f(m, a, at + 0x48 + 8 * i, x)
    for i, x in enumerate(e.get('prev', (1.5, 2.5, 3.5, 4.5))):
        put_f(m, a, at + 0x68 + 8 * i, x)
    put(m, a, at + 0x88, 4, e.get('end', 0))
    put_f(m, a, at + 0x90, e['mult'])
    put(m, a, at + 0xc8, 4, e.get('base', 0))


def build_tracker(m, v):
    a = m.arena(0x170)
    for off in range(0, 0x170, 8):
        put(m, a, off, 8, 0x5a5a5a5a00000000 | off)
    tmpl = m.arena(max(len(v['templates']), 1) * 0x30)
    for i, t in enumerate(v['templates']):
        for k, x in enumerate(t):
            put_f(m, tmpl, i * 0x30 + 8 * k, x)
    over = m.arena(max(len(v['overrides']), 1) * 0x10)
    for i, o in enumerate(v['overrides']):
        put_f(m, over, i * 0x10, o[0])
        put_f(m, over, i * 0x10 + 8, o[1])
    tiers = m.arena(max(len(v['tiers']), 1) * 0x10)
    for i, o in enumerate(v['tiers']):
        put_f(m, tiers, i * 0x10, o[0])
        put_f(m, tiers, i * 0x10 + 8, o[1])
    put(m, a, 8, 8, tmpl.base)
    put(m, a, 0x10, 8, len(v['templates']))
    put(m, a, 0x20, 8, over.base)
    put(m, a, 0x28, 8, len(v['overrides']))
    put(m, a, 0x38, 8, tiers.base)
    put(m, a, 0x40, 8, len(v['tiers']))
    for i, x in enumerate(v['defaults']):
        put_f(m, a, 0x48 + 8 * i, x)
    ctrl, size = build_table(m, v)
    put(m, a, 0xc0, 8, ctrl)
    put(m, a, 0xc8, 8, size - 1)
    put(m, a, 0xd0, 8, v['growth'])
    put(m, a, 0xd8, 8, len(v['users']) + len(v['decoys']))
    put(m, a, 0x168, 1, 1 if v['disabled'] else 0)
    return a


def build_action(m, v):
    a = m.arena(0x60)
    for pos, cell in enumerate((0x18, 0, 0x48, 0x30)):
        spec = v['action'][pos]
        raw = struct.pack('<BHQH', 2 if spec.get('fail') else 1 if spec.get('tag') is not None else 0, spec.get('tag') or 0,
                          spec.get('word') or f2b(spec['rate']), HEAD + spec['pad']) + b'x' * spec['pad']
        s = m.arena(len(raw))
        put_bytes(m, s, 0, raw)
        put(m, a, cell, 8, len(raw))
        put(m, a, cell + 8, 8, s.base)
        put(m, a, cell + 16, 8, len(raw))
    return a


def payload(tag, word):
    """An error value with a different byte at each offset, so a shifted copy shows."""
    raw = bytearray((off * 7 + tag) & 0xff for off in range(0x70))
    raw[0:2] = struct.pack('<H', tag)
    raw[8:16] = struct.pack('<Q', word)
    return bytes(raw)


def machine(img, code):
    m = Machine(img, ())
    m.code = code
    m.loose = LOOSE
    for t in DECODED:
        m.real[t] = t
    m.slots = dict(SLOTS)
    return m


def install(m, ctx):
    def do_hash():
        if m.regs[R['rdi']] != ctx.base + 0xe0:
            raise Unmodelled('hash of another table')
        key = bytes(m.load(m.regs[R['rsi']] + i, 1) for i in range(20))
        m.clobber(key_hash(key))

    def reserve():
        if m.regs[R['rdi']] != ctx.base + 0xc0 or m.regs[R['rdx']] != ctx.base + 0xe0:
            raise Unmodelled('reserve arguments')
        if m.regs[R['rsi']] != 1 or m.regs[R['rcx']] != 1:
            raise Unmodelled('reserve size')
        m.reserved += 1
        m.store(ctx.base + 0xd0, 8, m.load(ctx.base + 0xd0, 8) + RESERVE_GROWTH)
        m.clobber()

    def parse():
        at, n, out = m.regs[R['rsi']], m.regs[R['rdx']], m.regs[R['rdi']]
        kind, tag, word, total = struct.unpack('<BHQH', bytes(m.load(at + i, 1) for i in range(HEAD)))
        if n != total:
            raise Unmodelled('parse length')
        m.parses += 1
        for off, b in enumerate(payload(tag, word)):
            m.store(out + off, 1, b)
        if kind != 1:
            m.store(out, 2, OK)
            m.store(out + 4, 4, 0 if kind == 2 else 1)
            m.store(out + 8, 8, word)
        m.clobber()

    def to_f64():
        at = m.regs[R['rdi']]
        flag, word = m.load(at, 4), m.load(at + 4, 8)
        m.clobber(flag)
        m.xmm[0] = [word, 0]

    def drop():
        if m.load(m.regs[R['rdi']], 2) != CONVERT:
            raise Unmodelled('drop of an unexpected value')
        m.clobber()

    def panic():
        raise Panicked()

    m.reserved = 0
    m.parses = 0
    m.stubs.update({HASH: do_hash, RESERVE: reserve, PARSE: parse, TO_F64: to_f64, DROP: drop, PANIC: panic})


RESERVE_GROWTH = 8


def run_writer(img, code, v):
    m = machine(img, code)
    stack = m.arena(0x4000)
    top = stack.base + 0x3f08
    ctx = build_tracker(m, v)
    install(m, ctx)
    sender = m.arena(20)
    put_bytes(m, sender, 0, v['sender'])
    now = m.arena(12)
    put(m, now, 0, 4, v['date'])
    action = build_action(m, v)
    out = m.arena(0x80, strict=False)
    linked = 0
    if v['linked'] is not None:
        cells = m.arena(max(len(v['linked']), 1) * 0x40)
        for i, key in enumerate(v['linked']):
            put_bytes(m, cells, i * 0x40 + 0x18, key)
        head = m.arena(0x18)
        put(m, head, 8, 8, cells.base)
        put(m, head, 0x10, 8, len(v['linked']))
        linked = head.base
    m.snap_table, m.snap_ctx = bytes(m.table.mem), bytes(ctx.mem)
    m.regs[R['rsp']] = top
    m.store(top, 8, 0xfeedface)
    m.regs[R['rdi']], m.regs[R['rsi']], m.regs[R['rdx']] = out.base, ctx.base, sender.base
    m.regs[R['rcx']], m.regs[R['r8']], m.regs[R['r9']] = now.base, action.base, linked
    for name in ('rbx', 'rbp', 'r12', 'r13', 'r14', 'r15'):
        m.regs[R[name]] = 0xc0de0000 + R[name]
    m.panicked = False
    try:
        m.run(WRITER)
    except Panicked:
        m.panicked = True
    return m, ctx, out


def want_table(m, v, want):
    """Expected table bytes, expected don't-care ranges, final growth and reserve count."""
    if want['status'] != OK:
        return m.snap_table, [], v['growth'], 0, len(v['users']) + len(v['decoys'])
    size, off = v['size'], m.ctrl_off
    exp = bytearray(m.snap_table)
    ctrl = list(m.ctrl0)
    slot_of = {}
    for i in range(size):
        if ctrl[i] < 0x80:
            at = off - (i + 1) * STRIDE
            slot_of[bytes(exp[at:at + 20])] = i
    growth, reserves, loose = v['growth'], 0, []
    items = len(v['users']) + len(v['decoys'])
    row = want['row']
    for key in want['writes']:
        if key not in slot_of:
            if growth == 0:
                reserves += 1
                growth += RESERVE_GROWTH
            h = key_hash(key)
            slot = free_slot(ctrl, h)
            growth -= ctrl[slot] & 1
            ctrl[slot] = h >> 57
            exp[off + slot] = h >> 57
            exp[off + ((slot - 16) & (size - 1)) + 16] = h >> 57
            at = off - (slot + 1) * STRIDE
            exp[at:at + 20] = key
            for start, n in ((0x18, 8), (0x98, 8), (0xa8, 16), (0xc0, 13)):
                exp[at + start:at + start + n] = bytes(n)
            loose.append((at + 0xa0, 8))
            slot_of[key] = slot
            items += 1
        at = off - (slot_of[key] + 1) * STRIDE
        exp[at + 0x18:at + 0x20] = struct.pack('<Q', 1)
        words = row['rates'] + (row['vol'],) + row['req'] + row['prev']
        exp[at + 0x20:at + 0x88] = struct.pack('<13Q', *(f2b(x) for x in words))
        exp[at + 0x88:at + 0x8c] = struct.pack('<I', row['end'])
        exp[at + 0x90:at + 0x98] = struct.pack('<Q', f2b(row['mult']))
        loose.append((at + 0x8c, 4))
    return bytes(exp), loose, growth, reserves, items


def compare(m, ctx, out, v, want):
    if m.panicked != want['panic']:
        return f'panic {m.panicked} != {want["panic"]}'
    if m.parses != want['parses']:
        return f'parse calls {m.parses} != {want["parses"]}'
    if m.panicked:
        return None
    tag = m.load(out.base, 2)
    if tag != want['status']:
        return f'status {tag:#x} != {want["status"]:#x}'
    if want['word'] is not None:
        exp = bytearray(payload(0 if tag == CONVERT else tag, want['word']))
        if tag == CONVERT:
            exp[4:8] = bytes(4)
        if bytes(out.mem[2:0x60]) != bytes(exp[2:0x60]):
            return 'error payload differs'
    exp, loose, growth, reserves, items = want_table(m, v, want)
    got = bytearray(m.table.mem)
    exp = bytearray(exp)
    for at, n in loose:
        got[at:at + n] = exp[at:at + n]
    if got != exp:
        at = next(i for i in range(len(exp)) if got[i] != exp[i])
        return f'table byte {at:#x}'
    if m.reserved != reserves:
        return f'reserves {m.reserved} != {reserves}'
    cur = bytearray(ctx.mem)
    snap = bytearray(m.snap_ctx)
    snap[0xd0:0xe0] = struct.pack('<QQ', growth, items)
    if cur != snap:
        return f'tracker byte {next(i for i in range(len(snap)) if cur[i] != snap[i]):#x}'
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


def act(*rates, pad=0):
    return [dict(rate=r, pad=pad) for r in rates]


BASE_RATE = (0.00045, 0.0007, 0.0002, 0.0004)
LOW = (0.0001, 0.0002, 0.00005, 0.0003)
TODAY = date(2026, 10, 30)


def template(rates, x=7.0, y=8.0):
    return tuple(rates) + (x, y)


def vector(group, **kw):
    v = dict(group=group, disabled=False, templates=[template(LOW)], overrides=[], tiers=[], defaults=BASE_RATE, users={},
             size=32, growth=8, decoys=(), tombstones=(), sender=addr(1), linked=None, date=TODAY, action=act(*LOW))
    v.update(kw)
    return v


def user(**kw):
    e = dict(tag=1, rates=BASE_RATE, vol=0.0, mult=1.0, end=0, base=0)
    e.update(kw)
    return e


def gate_group():
    who = addr(1)
    out = []
    for disabled in (False, True):
        for end in (0, TODAY):
            for tag in (0, 1):
                out.append(vector('gates', disabled=disabled, users={who: user(tag=tag, end=end)}))
                out.append(vector('gates', disabled=disabled, users={who: user(tag=tag, end=end)}, action=act(*LOW, pad=200)))
        out.append(vector('gates', disabled=disabled))
    # the row is read before the flag, so a reject leaves everything alone
    out.append(vector('gates', disabled=True, templates=[]))
    out.append(vector('gates', users={who: user(end=1)}, action=act(*LOW, pad=200)))
    return out


def action_group():
    out = []
    for pos in range(4):
        for tag, word in ((0x77, 0x1234), (0x9d, 1 << 60), (0x186 + 1, 3)):
            spec = act(*LOW)
            spec[pos].update(tag=tag, word=word)
            out.append(vector('action', action=spec))
        spec = act(*LOW)
        spec[pos]['fail'] = True
        out.append(vector('action', action=spec))
        for pad in (MAX_LEN - HEAD - 1, MAX_LEN - HEAD, MAX_LEN - HEAD + 1, 300):
            spec = act(*LOW)
            spec[pos]['pad'] = pad
            out.append(vector('action', action=spec))
        for later in range(pos + 1, 4):
            spec = act(*LOW)
            spec[pos]['fail'] = True
            spec[later]['pad'] = 300
            out.append(vector('action', action=spec))
            spec = act(*LOW)
            spec[pos]['pad'] = 300
            spec[later].update(tag=0x77, word=9)
            out.append(vector('action', action=spec))
    return out


def template_group():
    out = []
    near = 0.00011
    table = [template((0.3, 0.3, 0.3, 0.3)), template(LOW), template((0.2, 0.2, 0.2, 0.2))]
    out.append(vector('templates', templates=table))
    out.append(vector('templates', templates=[]))
    out.append(vector('templates', templates=[], overrides=[(0.0, LOW[1])]))
    out.append(vector('templates', templates=[template((0.3, 0.3, 0.3, 0.3))]))
    for pos in range(4):
        wrong = list(LOW)
        wrong[pos] = near
        out.append(vector('templates', action=act(*wrong)))
        out.append(vector('templates', templates=table, action=act(*wrong)))
        out.append(vector('templates', action=act(*[math.nan if k == pos else LOW[k] for k in range(4)])))
        bad = list(LOW)
        bad[pos] = math.nan
        out.append(vector('templates', templates=[template(bad)]))
        out.append(vector('templates', templates=[template(bad), template(LOW)]))
    zero = (0.0, 0.0, 0.0, 0.0)
    out.append(vector('templates', templates=[template(zero)], action=act(-0.0, 0.0, -0.0, 0.0)))
    out.append(vector('templates', templates=[template((1.0, 0.25, 0.5, 0.25))], action=act(1.0, 0.25, 0.5, 0.25), defaults=(2.0, 2.0, 2.0, 2.0)))
    return out


def override_group():
    out = []
    x, y = 0.00031, 0.00037
    add = (LOW[0], 0.9, LOW[2], 0.8)
    other = (0.7, 0.7, 0.7, 0.7)
    for table in ([template(add)], [template(add), template(other)], [template(other), template(add)],
                  [template(other), template(add), template(other)]):
        for over in ([(0.0, x)], [(1.0, y), (2.0, x)], [(1.0, x), (2.0, y)], [(1.0, y)], [(1.0, y), (2.0, 0.1)], []):
            out.append(vector('overrides', templates=table, overrides=over, action=act(LOW[0], x, LOW[2], x)))
    over = [(0.0, x), (0.0, y)]
    for a, b in ((x, y), (y, x), (x, x), (y, y), (x, 0.1), (0.1, x)):
        out.append(vector('overrides', templates=[template(add)], overrides=over, action=act(LOW[0], a, LOW[2], b)))
    for pos, wrong in ((0, 0.1), (2, 0.1)):
        spec = [LOW[0], x, LOW[2], x]
        spec[pos] = wrong
        out.append(vector('overrides', templates=[template(add)], overrides=over, action=act(*spec)))
    # a perp add from one row and a spot add from another is no add hit
    out.append(vector('overrides', templates=[template((LOW[0], 1.0, 0.6, 1.0)), template((0.6, 1.0, LOW[2], 1.0))],
                      overrides=over, action=act(LOW[0], x, LOW[2], x)))
    # the override key word at +0 is not read
    out.append(vector('overrides', templates=[template(add)], overrides=[(x, 0.5)], action=act(LOW[0], x, LOW[2], x)))
    out.append(vector('overrides', templates=[template(add)], overrides=[(math.nan, x)], action=act(LOW[0], x, LOW[2], x)))
    nan_over = [(0.0, math.nan)]
    out.append(vector('overrides', templates=[template(add)], overrides=nan_over, action=act(LOW[0], x, LOW[2], x)))
    return out


def cooldown_group():
    who = addr(1)
    day = unpack_day(TODAY)
    out = []
    for back in (0, 1, 2, 76, 88, 89, 90, 91, 92, 104, 366, 400, 10000):
        base = pack_day(day - back)
        out.append(vector('cooldown', users={who: user(base=base)}))
        out.append(vector('cooldown', users={who: user(base=base, tag=0)}))
        out.append(vector('cooldown', users={who: user(base=base, tag=0)}, linked=[addr(2)]))
    for ahead in (1, 100):
        out.append(vector('cooldown', users={who: user(base=pack_day(day + ahead))}))
    out.append(vector('cooldown', users={who: user(base=0)}))
    out.append(vector('cooldown', users={addr(2): user(base=TODAY)}))
    out.append(vector('cooldown', users={who: user(base=TODAY)}, disabled=True))
    out.append(vector('cooldown', users={who: user(base=TODAY)}, action=act(0.9, 0.9, 0.9, 0.9)))
    # the end date in the row is a different word from the cooldown date
    old = pack_day(day - 500)
    out.append(vector('cooldown', users={who: user(base=old, req=LOW, prev=BASE_RATE)}))
    for pair in ((0, 1), (1, 0)):
        out.append(vector('cooldown', users={who: user(base=TODAY)}, size=16, tombstones=pair))
    out.append(vector('cooldown', users={who: user(base=TODAY, tag=0)}, action=act(*LOW)))
    return out


def tier_group():
    who = addr(1)
    out = []
    ladder = [(10.0, 0.1), (20.0, 0.2), (30.0, 0.5)]
    for n in range(4):
        for vol in (0.0, 5.0, 10.0, 15.0, 20.0, 25.0, 30.0, 35.0, -1.0, math.inf, math.nan):
            out.append(vector('tiers', tiers=ladder[:n], users={who: user(vol=vol)}))
            out.append(vector('tiers', tiers=ladder[:n], users={who: user(vol=vol, rates=(LOW[0] * 0.6, 1.0, 1.0, 1.0))}))
    # a volume of 0 from the default row still walks the tiers
    out.append(vector('tiers', tiers=[(0.0, 0.25)]))
    out.append(vector('tiers', tiers=[(-1.0, 0.25), (0.0, 0.5), (1.0, 0.75)]))
    out.append(vector('tiers', tiers=[(math.nan, 0.25), (1.0, 0.5)], users={who: user(vol=5.0)}))
    out.append(vector('tiers', tiers=[(1.0, 0.25), (math.nan, 0.5), (3.0, 0.75)], users={who: user(vol=2.0)}))
    out.append(vector('tiers', tiers=[(0.0, math.nan)]))
    out.append(vector('tiers', tiers=[(0.0, 1.0)]))
    out.append(vector('tiers', tiers=[(0.0, 2.0)]))
    out.append(vector('tiers', tiers=[(0.0, -0.5)]))
    return out


def effect_group():
    who = addr(1)
    out = []
    grid = (-0.5, -0.0, 0.0, 0.25, 0.5, 1.0)
    for pos in range(4):
        for req in grid:
            for cur in grid:
                spec = [1.0, 1.0, 1.0, 1.0]
                spec[pos] = req
                rates = [0.5, 0.5, 0.5, 0.5]
                rates[pos] = cur
                t = template(spec)
                out.append(vector('effect', templates=[t], action=act(*spec), users={who: user(rates=tuple(rates), mult=0.75)}))
                out.append(vector('effect', templates=[t], action=act(*spec), tiers=[(0.0, 0.5)], users={who: user(rates=tuple(rates), vol=1.0)}))
    for cur in ((math.nan, 1.0, 1.0, 1.0), (1.0, 1.0, 1.0, math.nan), (math.inf, 1.0, 1.0, 1.0), (-math.inf, 1.0, 1.0, 1.0)):
        out.append(vector('effect', users={who: user(rates=cur)}))
        out.append(vector('effect', templates=[template((2.0, 2.0, 2.0, 2.0))], action=act(2.0, 2.0, 2.0, 2.0), users={who: user(rates=cur)}))
    for d in (ALL_FF, ALL_FE):
        out.append(vector('effect', sender=d))
        neg = (-0.0001, 0.0002, 0.00005, 0.0003)
        out.append(vector('effect', sender=d, templates=[template(neg)], action=act(*neg)))
        out.append(vector('effect', sender=d, disabled=True))
        out.append(vector('effect', sender=d, users={d: user(rates=(9.0,) * 4, end=TODAY)}, templates=[template(neg)], action=act(*neg)))
        out.append(vector('effect', sender=d, users={d: user(base=TODAY)}, templates=[template(neg)], action=act(*neg)))
    for near in (ALL_FF[:19] + b'\xfe', ALL_FE[:19] + b'\xff', ALL_FE[:15] + b'\xff' + ALL_FE[16:], ALL_FF[:15] + b'\xfe' + ALL_FF[16:]):
        out.append(vector('effect', sender=near))
    # after a trial ended: the row keeps its rates, volume and multiplier and the requested words are stale
    out.append(vector('effect', users={who: user(rates=(0.0002, 0.0003, 0.0002, 0.0003), vol=7.0, mult=0.5, req=(1.0,) * 4, prev=(2.0,) * 4)}))
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


def write_group():
    who = addr(1)
    a, b, c = addr(2), addr(3), addr(4)
    old = user(rates=(1.0, 1.0, 1.0, 1.0), vol=3.0, mult=0.5, req=(4.0,) * 4, prev=(5.0,) * 4)
    out = []
    for linked in (None, [], [a], [a, b], [a, b, c], [a, a], [who], [a, who], [who, a, who]):
        out.append(vector('writes', linked=linked))
        out.append(vector('writes', linked=linked, users={who: user()}))
        out.append(vector('writes', linked=linked, users={a: user(end=TODAY, base=TODAY)}))
        out.append(vector('writes', linked=linked, users={a: dict(old), b: dict(old, tag=0)}))
        out.append(vector('writes', linked=linked, growth=0))
        out.append(vector('writes', linked=linked, growth=1))
        out.append(vector('writes', linked=linked, decoys=(addr(50), addr(51))))
    # a linked user keeps its own cooldown date and end date only until it is overwritten
    out.append(vector('writes', linked=[a], users={a: user(rates=(0.1,) * 4, end=TODAY, base=date(2026, 1, 1), mult=0.25, vol=2.0)}))
    # a rejected call writes nobody
    out.append(vector('writes', linked=[a, b], action=act(0.9, 0.9, 0.9, 0.9)))
    out.append(vector('writes', linked=[a, b], templates=[template((1.0,) * 4)], action=act(1.0, 1.0, 1.0, 1.0)))
    for dead in ((0,), (3, 4), tuple(range(8))):
        out.append(vector('writes', tombstones=dead, linked=[a, b]))
        out.append(vector('writes', tombstones=dead, growth=0, linked=[a]))
    others = same_slot(who, 3, True)
    out.append(vector('writes', decoys=tuple(others), linked=[a]))
    out.append(vector('writes', decoys=tuple(others), users={who: user(base=TODAY)}))
    out.append(vector('writes', decoys=tuple(others), users={who: user(end=TODAY)}))
    miss = same_slot(who, 3, False)
    out.append(vector('writes', decoys=tuple(miss), linked=[a]))
    wrap = same_slot(who, 20, False)
    out.append(vector('writes', decoys=tuple(wrap), size=32, growth=4, users={who: user(base=TODAY)}))
    out.append(vector('writes', decoys=tuple(wrap), size=32, growth=4, users={who: user()}))
    out.append(vector('writes', decoys=tuple(wrap), size=32, growth=4, linked=[a]))
    fill = tuple(addr(200 + i) for i in range(27))
    out.append(vector('writes', decoys=fill, size=32, growth=4, linked=[a, b]))
    near = who[:19] + bytes([who[19] ^ 1])
    for k in range(20):
        twin = bytearray(who)
        twin[k] ^= 0x40
        out.append(vector('writes', decoys=(bytes(twin),), users={who: user(base=TODAY)}) if k % 2 else vector('writes', users={bytes(twin): user(base=TODAY)}))
    out.append(vector('writes', users={near: user(end=TODAY)}))
    return out


def date_group():
    who = addr(1)
    out = []
    days = ((2026, 12, 17), (2026, 12, 18), (2026, 12, 31), (2027, 1, 1), (2024, 2, 15), (2024, 2, 16), (2024, 2, 29), (2023, 2, 14), (2023, 2, 15),
            (2024, 12, 18), (2024, 12, 31), (2000, 2, 29), (1900, 2, 15), (2100, 2, 15), (2400, 12, 25), (1, 1, 1), (0, 12, 25), (-1, 12, 25), (-4, 2, 20),
            (-400, 12, 30), (-262143, 1, 1), (262142, 12, 1), (262142, 12, 17), (262142, 12, 18), (262142, 12, 31))
    for y, mo, d in days:
        p = date(y, mo, d)
        out.append(vector('dates', date=p))
        out.append(vector('dates', date=p, users={who: user(base=p)}))
        out.append(vector('dates', date=p, users={who: user(base=pack_day(unpack_day(p) - 90))}))
        out.append(vector('dates', date=p, users={who: user(base=pack_day(unpack_day(p) - 89))}))
        out.append(vector('dates', date=p, users={who: user(base=date(262142, 12, 31))}))
        out.append(vector('dates', date=date(2026, 6, 1), users={who: user(base=p)}))
    return out


def random_group():
    rng = Lcg(0x5eed2050)
    rates = (0.0, 0.0001, 0.0002, 0.0003, 0.0004, 0.0007, -0.0001, -0.0002, 1.0)
    keys = [addr(300 + i) for i in range(12)]
    out = []
    day = unpack_day(TODAY)
    for _ in range(600):
        pick = [rng.pick(rates) for _ in range(4)]
        temps = [template([rng.pick(rates) for _ in range(4)]) for _ in range(rng.next() >> 33 & 3)]
        if rng.next() >> 40 & 3:
            temps.insert(rng.next() >> 33 & 1 if temps else 0, template(pick))
        over = [(0.0, rng.pick(rates)) for _ in range(rng.next() >> 33 & 3)]
        tiers = sorted((rng.pick((0.0, 1.0, 2.0, 3.0, 4.0)), rng.pick((0.0, 0.1, 0.25, 0.5))) for _ in range(rng.next() >> 33 & 3))
        users = {}
        for k in keys[:rng.next() >> 33 & 7]:
            users[k] = user(tag=rng.pick((0, 1, 1)), rates=tuple(rng.pick(rates) for _ in range(4)), vol=rng.pick((0.0, 1.5, 3.0, 9.0)), mult=rng.pick((1.0, 0.5, 0.25)),
                            end=rng.pick((0, 0, 0, TODAY)), base=rng.pick((0, 0, pack_day(day - 90), pack_day(day - 89), pack_day(day - 10))))
        linked = rng.pick((None, [], keys[:2], keys[3:6], [keys[7], keys[7]]))
        sender = rng.pick(keys[:6])
        out.append(vector('random', disabled=(rng.next() >> 33) % 17 == 0, templates=temps, overrides=over, tiers=tiers, users=users, sender=sender,
                          linked=linked, growth=rng.pick((0, 1, 4, 8)), action=act(*pick)))
    return out


def all_vectors():
    out = []
    for fn in (gate_group, action_group, template_group, override_group, cooldown_group, tier_group, effect_group, write_group, date_group, random_group,
               sweep_group, probe_group):
        out += fn()
    return out


def run_vectors(img, code, vecs, seen=None):
    bad = []
    for i, v in enumerate(vecs):
        want = apply_model(v)
        m, ctx, out = run_writer(img, code, v)
        msg = compare(m, ctx, out, v, want)
        if seen is not None:
            seen |= m.seen
        if msg:
            bad.append((i, v['group'], msg))
    return bad


def sweep_group():
    """Year ends over a whole 400-year cycle: every branch of the calendar add, and the 14-day and 90-day dates."""
    out = []
    who = addr(1)
    for y in range(2000, 2401):
        for mo, d in ((12, 31), (12, 20)):
            out.append(vector('sweep', date=date(y, mo, d)))
        out.append(vector('sweep', date=date(y, 3, 1), users={who: user(base=date(y - 1, 12, 1))}))
    return out


def probe_group():
    """Small tables and long probes of the table entry path."""
    who, a = addr(1), addr(2)
    out = []
    for size in (4, 8):
        out.append(vector('probe', size=size, growth=2))
        out.append(vector('probe', size=size, growth=1, linked=[a]))
        out.append(vector('probe', size=size, growth=0, users={who: user(base=date(2020, 1, 1))}))
        out.append(vector('probe', size=size, growth=2, decoys=(addr(60),), linked=[a]))
        out.append(vector('probe', size=size, growth=2, decoys=tuple(addr(60 + k) for k in range(size // 2)), linked=[a]))
        for k in range(1, size):
            for n in range(4):
                out.append(vector('probe', size=size, growth=1, sender=addr(70 + n), decoys=tuple(addr(80 + i) for i in range(k))))
    same = tuple(same_slot(who, 34, False, 63))
    out.append(vector('probe', size=64, growth=8, decoys=same))
    out.append(vector('probe', size=64, growth=8, decoys=same[:32], users={who: user(base=TODAY)}))
    out.append(vector('probe', size=64, growth=8, decoys=same[:32], users={who: user(end=TODAY)}))
    out.append(vector('probe', size=64, growth=8, decoys=same, users={who: user()}))
    out.append(vector('probe', size=64, growth=8, decoys=same, users={who: user(base=TODAY)}))
    out.append(vector('probe', size=64, growth=8, decoys=same, users={who: user(end=TODAY)}))
    return out


# ---- mutations


FDE_END = {}
BOUND = 'the day count only feeds a TimeDelta range check; 14 and 90 stay well inside it, and this byte is in `pinned` or `bytes` of instructions.tsv'
EQUIVALENT.update({
    0x37464f9: 'x != x and unordered(x, x) are the same predicate on one register',
    0x3746512: 'x != x and unordered(x, x) are the same predicate on one register',
    0x1450813: BOUND,
    0x145081a: BOUND,
    0x1450827: BOUND,
    0x1450850: 'length of the panic text; the outcome is the panic, and test_date_panic_text reads this byte',
})
SWAPS = {'subsd': (0x5c, 0x58), 'subpd': (0x5c, 0x59), 'mulpd': (0x59, 0x5c), 'maxpd': (0x5f, 0x5d), 'minpd': (0x5d, 0x5f),
         'andpd': (0x54, 0x56), 'orpd': (0x56, 0x54), 'andnpd': (0x55, 0x54)}
PREDS = {1: 4, 3: 4, 4: 1}


def conditional_sites(fn, listing):
    out = []
    for ins in listing:
        if ins.op[0] == 'j' and ins.op not in ('jmp', 'jmpr'):
            at = ins.va + (1 if ins.raw[0] == 0x0f else 0)
            out.append(dict(kind='flip', fn=fn, va=ins.va, op=ins.op, patch={at: ins.raw[at - ins.va] ^ 1}))
        elif ins.op.startswith('cmov') or ins.op.startswith('set'):
            i = ins.raw.index(0x0f)
            out.append(dict(kind='flip', fn=fn, va=ins.va, op=ins.op, patch={ins.va + i + 1: ins.raw[i + 1] ^ 1}))
    return out


def disp_size(ins, mem):
    raw, disp = ins.raw, mem[4]
    packed = struct.pack('<b', disp) if -128 <= disp < 128 else struct.pack('<i', disp)
    tail = 0
    imm = [o for o in ins.ops if o[0] == 'i']
    if imm:
        tail = imm_size(ins, imm[0])
    at = len(raw) - tail - len(packed)
    if raw[at:at + len(packed)] != packed:
        return None
    return at


def imm_size(ins, o):
    for n in (1, 2, 4, 8):
        if int.from_bytes(ins.raw[-n:], 'little', signed=True) == signed(o[1] & ((1 << n * 8) - 1), n * 8):
            if n == 1 and ins.raw[0] in (0xb8, 0xbf):
                continue
            return n
    return 0


def field_sites(fn, listing):
    """Every memory operand with a displacement, except stack spills outside the success copy."""
    out = []
    for ins in listing:
        mem = [o for o in ins.ops if o[0] == 'm' and o[1] is not None and not o[5]]
        if not mem or ins.op == 'lea' and mem[0][1] == R['rsp']:
            continue
        o = mem[0]
        if o[4] == 0 or o[1] == R['rsp'] and not (fn == WRITER and 0x374438a <= ins.va <= 0x3744527):
            continue
        at = disp_size(ins, o)
        if at is None:
            continue
        out.append(dict(kind='field', fn=fn, va=ins.va, op=show(ins), patch={ins.va + at: ins.raw[at] ^ 8}))
    return out


def imm_sites(fn, listing):
    out = []
    for ins in listing:
        imm = [o for o in ins.ops if o[0] == 'i']
        if not imm or ins.op in ('pshufd', 'pshuflw', 'shufps', 'cmpltpd', 'cmpneqpd', 'cmpunordpd'):
            continue
        if ins.ops[0] == ('r', R['rsp'], 64):
            continue
        n = imm_size(ins, imm[0])
        if not n:
            continue
        at = ins.va + ins.size - n
        out.append(dict(kind='immediate', fn=fn, va=ins.va, op=show(ins), patch={at: ins.raw[-n] ^ 1}))
    return out


def sse_sites(fn, listing):
    out = []
    for ins in listing:
        if ins.op in ('cmpltpd', 'cmpneqpd', 'cmpunordpd'):
            out.append(dict(kind='predicate', fn=fn, va=ins.va, op=ins.op, patch={ins.va + ins.size - 1: PREDS[ins.raw[-1]]}))
        elif ins.op in SWAPS:
            old, new = SWAPS[ins.op]
            at = next(i for i in range(len(ins.raw) - 1) if ins.raw[i] == 0x0f and ins.raw[i + 1] == old) + 1
            out.append(dict(kind='swap', fn=fn, va=ins.va, op=ins.op, patch={ins.va + at: new}))
    return out


def sample(vecs):
    """The survey set: about 40 vectors of each group, chosen by a hash of the index."""
    kept, count = [], {}
    for v in vecs:
        count[v['group']] = count.get(v['group'], 0) + 1
    for i, v in enumerate(vecs):
        if hashlib.sha256(str(i).encode()).digest()[0] * count[v['group']] < 256 * 40:
            kept.append(v)
    return kept


def try_kill(mimg, mcode, picked, want):
    for pos, v in enumerate(picked):
        try:
            m, ctx, out = run_writer(mimg, mcode, v)
            bad = compare(m, ctx, out, v, want[id(v)])
        except (Unmodelled, EvidenceError, KeyError, OverflowError, ValueError, TypeError, struct.error) as exc:
            bad = f'fault {type(exc).__name__}'
        if bad:
            picked.insert(0, picked.pop(pos))
            return (v['group'], bad[:60])
    return None


def survey(data, code, listing, vecs):
    sites = []
    for fn in SUBJECTS:
        sites += conditional_sites(fn, listing[fn]) + field_sites(fn, listing[fn])
        sites += imm_sites(fn, listing[fn]) + sse_sites(fn, listing[fn])
    picked = sample(vecs)
    everything = list(vecs)
    want = {id(v): apply_model(v) for v in vecs}
    rows = []
    for s in sites:
        mimg = Image(data, s['patch'])
        mcode = dict(code)
        try:
            mcode.update({i.va: i for i in decode_range(mimg, s['fn'], FDE_END[s['fn']])})
        except EvidenceError as exc:
            rows.append(dict(s, killed=('decoder', str(exc)[:60])))
            continue
        killed = try_kill(mimg, mcode, picked, want)
        if killed is None and s['va'] not in EQUIVALENT:
            killed = try_kill(mimg, mcode, everything, want)
        rows.append(dict(s, killed=killed))
    return rows


# ---- static facts


def bind_fdes(data):
    fdes = Fdes(data)
    for s in DECODED:
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


def status_text(img, tag):
    """Display text of a status: table of i32 offsets at 0x59a8d0, then a lea and a length in the case body."""
    base = 0x59a8d0
    target = base + struct.unpack('<i', img.read(base + 4 * tag, 4))[0]
    raw = img.read(target, 40) + b'\x90' * 16
    i, at, size = 0, None, None
    for _ in range(6):
        ins = decode_one(raw, i, target + i)
        i += ins.size
        if ins.op == 'lea' and ins.ops[0][1] == R['rsi'] and ins.ops[1][1] is None:
            at = ins.ops[1][4]
        if ins.op == 'mov' and ins.ops[0] == ('r', R['rdx'], 32) and ins.ops[1][0] == 'i':
            size = ins.ops[1][1]
    if at is None or size is None:
        raise EvidenceError(f'no text in the case of status {tag:#x}')
    return img.read(at, size).decode()


def calendar_tables(img):
    """The two tables the date helper reads, against the leap rule and the weekday rule alone."""
    flags, deltas = img.read(0x2504e5, 400), img.read(0x250354, 401)
    bad_flags = [y for y in range(400) if flags[y] != year_flags(y)]
    lead, bad_deltas = 0, []
    for y in range(401):
        if deltas[y] != lead:
            bad_deltas.append(y)
        lead += is_leap(y)
    if bad_flags or bad_deltas:
        raise EvidenceError(f'calendar tables differ: {bad_flags[:5]} {bad_deltas[:5]}')
    return dict(flags=dict(va='0x2504e5', entries=400, sha256=hashlib.sha256(flags).hexdigest()),
                deltas=dict(va='0x250354', entries=401, sha256=hashlib.sha256(deltas).hexdigest()), mismatches=0)


def panic_text(img):
    raw = img.read(0x1450842, 7)
    if raw[:3] != b'\x48\x8d\x3d':
        raise EvidenceError('no panic text lea')
    at = 0x1450842 + 7 + struct.unpack('<i', raw[3:])[0]
    size = img.read(0x1450850, 5)
    if size[0] != 0xbe:
        raise EvidenceError('no panic text length')
    return img.read(at, struct.unpack('<I', size[1:])[0]).decode()


def field_names(img):
    raw = img.read(ACTION_FIELDS, 0x90)
    names = [b'perpAddBaseRate', b'perpCrossBaseRate', b'spotAddBaseRate', b'spotCrossBaseRate', b'struct StartFeeTrialAction with 4 elements']
    at, out = raw.index(b'perpCrossBaseRate') - len(names[0]), []
    for n in names:
        if not raw[at:].startswith(n):
            raise EvidenceError(f'field name {n!r} is not next')
        out.append(n.decode())
        at += len(n)
    return out


def slot_sites(img, slot, starts):
    """Calls through `slot`: ff 15 rel32 in .text."""
    addr_, off, size = img.sec['.text'][:3]
    blob, out = img.data, []
    i = blob.find(b'\xff\x15', off, off + size)
    pack = struct.Struct('<i').unpack_from
    while i != -1 and i + 6 <= off + size:
        va = addr_ + i - off
        if va + 6 + pack(blob, i + 2)[0] == slot:
            out.append(dict(site=hex(va), function=hex(starts[bisect.bisect_right(starts, va) - 1])))
        i = blob.find(b'\xff\x15', i + 1, off + size)
    return out


def handler_copies(img, fdes):
    """The three handler bodies, instruction by instruction, after rip targets are made absolute."""
    def body(start):
        end = fdes.range_of(start)['end']
        listing = decode_range(img, start, end)

        def text(ins):
            ops = [('t', o[1] - start) if o[0] == 't' and start <= o[1] < end else o for o in ins.ops]
            return ins.op, tuple(ops)
        return listing, [text(i) for i in listing]

    first, first_text = body(HANDLER)
    out = []
    for copy in HANDLER_COPIES:
        other, other_text = body(copy)
        if len(other) != len(first):
            raise EvidenceError(f'{copy:#x} has {len(other)} instructions, not {len(first)}')
        rows = []
        for a, b, ta, tb in zip(first, other, first_text, other_text):
            if ta == tb:
                continue
            da = [o[4] for o in a.ops if o[0] == 'm']
            db = [o[4] for o in b.ops if o[0] == 'm']
            if a.op != b.op or len(da) != 1 or len(db) != 1:
                raise EvidenceError(f'{a.va:#x} and {b.va:#x} differ in more than a displacement')
            rows.append(dict(va=hex(b.va), first=show(a), here=show(b), delta=hex(db[0] - da[0])))
        out.append(dict(start=hex(copy), instructions=len(other), differs=rows))
    return out


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


def show_date(p):
    z = unpack_day(p)
    y = civil_year(z)
    return dict(packed=hex(p), year=y, ordinal=z - days_from_civil(y, 1, 1) + 1)


def date_examples(img, code):
    """Real evaluation of the day helper, beside the plain integer add the reference assumes."""
    out = []
    for y, mo, d, n in ((2026, 12, 18, TRIAL_DAYS), (2024, 2, 15, TRIAL_DAYS), (2026, 12, 1, COOLDOWN_DAYS)):
        m = machine(img, code)
        m.stubs[PANIC] = None
        stack = m.arena(0x1000)
        m.regs[R['rsp']] = stack.base + 0xf08
        m.store(stack.base + 0xf08, 8, 0xfeedface)
        p = date(y, mo, d)
        m.regs[R['rdi']], m.regs[R['rsi']] = p, n
        m.run(ADD)
        got = m.regs[0] & 0xffffffff
        if got != add_days(p, n):
            raise EvidenceError('date example differs from the calendar model')
        out.append(dict(start=show_date(p), days=n, end=show_date(got), plain_integer_add=hex(p + n)))
    return out


def example_vectors():
    who, a = addr(1), addr(2)
    return (
        ('fresh user, one linked user', vector('example', linked=[a], tiers=[(0.0, 0.1)], users={who: user(vol=1.0, rates=(0.00045, 0.00015, 0.0002, 0.0004))})),
        ('rates already met', vector('example', users={who: user(rates=(0.00001, 0.00001, 0.00001, 0.00001))})),
        ('ended trial, cooldown day 90', vector('example', users={who: user(rates=LOW, base=pack_day(unpack_day(TODAY) - 90))},
                                                templates=[template((0.00005,) * 4)], action=act(*(0.00005,) * 4))),
        ('ended trial, cooldown day 89', vector('example', users={who: user(rates=LOW, base=pack_day(unpack_day(TODAY) - 89))},
                                                templates=[template((0.00005,) * 4)], action=act(*(0.00005,) * 4))),
        ('end date set, cooldown word 0', vector('example', users={who: user(end=TODAY)})),
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
    rows = survey(data, code, listing, vecs) if with_survey else []
    survivors = {r['va'] for r in rows if not r['killed']}
    if survivors - set(EQUIVALENT) or (rows and set(EQUIVALENT) - survivors):
        raise EvidenceError(f'survivors {sorted(hex(s) for s in survivors ^ set(EQUIVALENT))}')
    starts = sorted(f['start'] for f in eh_frame_records(data)[1])
    examples = []
    for name, v in example_vectors():
        want = apply_model(v)
        m, ctx, out = run_writer(img, code, v)
        msg = compare(m, ctx, out, v, want)
        if msg:
            raise EvidenceError(f'example {name}: {msg}')
        row = want['row']
        examples.append(dict(name=name, status=hex(want['status']), row=row and dict(rates=list(row['rates']), end=hex(row['end']))))
    groups, outcomes = {}, {}
    out_path = Path(out_dir)
    out_path.mkdir(parents=True, exist_ok=True)
    with open(out_path / 'vectors.tsv', 'w', newline='\n') as f:
        f.write('group\tinput_digest\tstatus\tparse_calls\twrites\tend_date\trates\n')
        for v in vecs:
            w = apply_model(v)
            groups[v['group']] = groups.get(v['group'], 0) + 1
            name = 'panic' if w['panic'] else hex(w['status'])
            outcomes[name] = outcomes.get(name, 0) + 1
            row = w['row']
            cells = [v['group'], digest_of(v), name, str(w['parses']), str(len(w['writes'])), hex(row['end']) if row else '',
                     ','.join(f'{f2b(x):016x}' for x in row['rates']) if row else '']
            f.write('\t'.join(cells) + '\n')
    with open(out_path / 'mutations.tsv', 'w', newline='\n') as f:
        f.write('kind\tfunction\tva\tinstruction\tresult\tvector\treason\n')
        for r in rows:
            k = r['killed']
            f.write(f"{r['kind']}\t{r['fn']:#x}\t{r['va']:#x}\t{r['op']}\t{'killed' if k else 'equivalent'}\t{k[0] if k else ''}\t{k[1] if k else EQUIVALENT[r['va']]}\n")
    with open(out_path / 'instructions.tsv', 'w', newline='\n') as f:
        f.write('function\tva\tsize\tbytes\tdecoded\texecuted\n')
        for fn in DECODED:
            for i in listing[fn]:
                f.write(f'{fn:#x}\t{i.va:#x}\t{i.size}\t{i.raw.hex()}\t{show(i)}\t{int(i.va in seen)}\n')
    with open(out_path / 'reference-diff.tsv', 'w', newline='\n') as f:
        f.write('verdict\treference\treference_says\tbytes_say\n')
        for row in REFERENCE_ROWS:
            f.write('\t'.join(row) + '\n')
    per = {}
    for fn in DECODED:
        ex = sum(i.va in seen for i in listing[fn])
        per[hex(fn)] = dict(end=hex(FDE_END[fn]), fde=hex(fdes.range_of(fn)['fde']), instructions=len(listing[fn]), executed=ex)
    evidence = dict(
        binary=BINARY, sha256=SHA256, functions=per, subjects=[hex(s) for s in SUBJECTS], stubs=[hex(s) for s in (HASH, RESERVE, PARSE, TO_F64, DROP, PANIC)],
        writer_callers=slot_sites(img, WRITER_SLOT, starts), slots={hex(k): hex(img.relative(k)) for k in sorted(SLOTS)}, writer_slot=hex(img.relative(WRITER_SLOT)),
        status_text={hex(t): status_text(img, t) for t in (DISABLED, ACTIVE, NO_RATE, NO_EFFECT, COOLDOWN, LONG, CONVERT, 0x8d, 0xdb)},
        date_panic_text=panic_text(img), calendar_tables=calendar_tables(img), date_examples=date_examples(img, code), action_fields=field_names(img),
        handler_copies=handler_copies(img, fdes), pinned=pinned(img), vectors=len(vecs), mismatches=0, groups=groups, outcomes=outcomes, examples=examples, padding_not_executed=padding,
        unexecuted=[dict(start=hex(a), end=hex(b), why=w) for a, b, w in UNEXECUTED], mutants=len(rows), killed=sum(1 for r in rows if r['killed']),
        survey_vectors=len(sample(vecs)), equivalent={hex(k): w for k, w in sorted(EQUIVALENT.items())},
    )
    with open(out_path / 'evidence.json', 'w', newline='\n') as f:
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
