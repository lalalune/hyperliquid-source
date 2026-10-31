#!/usr/bin/env python3
"""fees: node #94 fee tier selection at the head of the 3 fee row builders, from bytes alone.

Static, no execution of the node.  The range of each of the row builders 0x26fbab0, 0x4ce19c0 and 0x4ce3360 from its
entry to the stake stage, and the whole day sum 0x3425a20, are decoded from ELF bytes by the table decoder below,
which must land exactly on each FDE end or range stop.  All of it is interpreted in Python on every vector and
compared with a separate closed-form model, then every conditional, field offset, immediate and read constant of
0x26fbab0 and 0x3425a20 is mutated to test the vectors.  The address hash, the volume row lookup, the date add, the
tracker read, the lazy default row and the overflow recorder are stubs that check their arguments.

    python3 tools/fees_tier_select.py --out <dir>

writes evidence.json, vectors.tsv, mutations.tsv, instructions.tsv and reference-diff.tsv.  Section and FDE parsing
come from tools/elf_index.py and tools/fde_extents.py.  Only the standard library is used: no objdump, readelf or
other external program runs, so the results cannot depend on a binutils version.
"""


import argparse
import bisect
import hashlib
import json
import math
import multiprocessing
import random
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
SHIFTS = {0: 'rol', 1: 'ror', 4: 'shl', 5: 'shr', 7: 'sar'}


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
        if b2 == 0xbc and rep == 'f3':
            reg, rm = modrm(width)
            return done('tzcnt', (gpr(reg | rr << 3, width), rm))
        if b2 == 0xaf:
            reg, rm = modrm(width)
            return done('imul2', (gpr(reg | rr << 3, width), rm))
        if b2 == 0xbd and rep == 'f3':
            reg, rm = modrm(width)
            return done('lzcnt', (gpr(reg | rr << 3, width), rm))
        if b2 in (0xa4, 0xac):
            reg, rm = modrm(width)
            v = imm(1)
            return done('shld' if b2 == 0xa4 else 'shrd', (rm, gpr(reg | rr << 3, width), ('i', v[1] & 0xff)))
        if b2 in (0xa5, 0xad):
            reg, rm = modrm(width)
            return done('shldcl' if b2 == 0xa5 else 'shrdcl', (rm, gpr(reg | rr << 3, width)))
        if b2 == 0xa3:
            reg, rm = modrm(width)
            return done('bt', (rm, gpr(reg | rr << 3, width)))
        if b2 == 0xba:
            reg, rm = modrm(width)
            if reg != 4:
                raise EvidenceError(f'{va:#x}: unlisted 0f ba /{reg}')
            return done('bt', (rm, ('i', imm(1)[1] & 0xff)))
        if b2 in (0xbe, 0xbf):
            reg, rm = modrm(8 if b2 == 0xbe else 16)
            return done('movsx', (gpr(reg | rr << 3, width), rm), width)
        if b2 == 0xbc:
            reg, rm = modrm(width)
            return done('bsf', (gpr(reg | rr << 3, width), rm))
        if b2 == 0xbd:
            reg, rm = modrm(width)
            return done('bsr', (gpr(reg | rr << 3, width), rm))
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
        if b2 == 0x13 and not p66 and not rep:
            reg, rm = modrm(64, True)
            return done('movq', (rm, ('x', reg | rr << 3)), 64)
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
    if b == 0x6a:
        return done('push', (imm(1),), 64)
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
        return done(SHIFTS[reg], (rm, ('i', v[1] & 0xff)))
    if b == 0xd1:
        reg, rm = modrm(width)
        return done(SHIFTS[reg], (rm, ('i', 1)))
    if b == 0xc0:
        reg, rm = modrm(8)
        v = imm(1)
        return done(SHIFTS[reg], (rm, ('i', v[1] & 0xff)), 8)
    if b == 0xd3:
        reg, rm = modrm(width)
        return done(SHIFTS[reg], (rm, ('r', 1, 8)))
    if b == 0xd0:
        reg, rm = modrm(8)
        return done(SHIFTS[reg], (rm, ('i', 1)), 8)
    if b == 0xd2:
        reg, rm = modrm(8)
        return done(SHIFTS[reg], (rm, ('r', 1, 8)), 8)
    if b == 0xa9:
        return done('test', (gpr(0, width), imm(4)))
    if b == 0xfe:
        reg, rm = modrm(8)
        if reg > 1:
            raise EvidenceError(f'{va:#x}: unlisted fe /{reg}')
        return done('dec' if reg else 'inc', (rm,), 8)
    if b == 0x86 or b == 0x87:
        bits = 8 if b == 0x86 else width
        reg, rm = modrm(bits)
        return done('xchg', (rm, gpr(reg | rr << 3, bits)), bits)
    if 0x91 <= b <= 0x97:
        return done('xchg', (gpr(0, width), gpr(b & 7 | rb << 3, width)))
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
        if reg == 0:
            return done('test', (rm, imm(1)), 8)
        if reg not in (2, 3, 4, 6):
            raise EvidenceError(f'{va:#x}: unlisted f6 /{reg}')
        return done({2: 'not', 3: 'neg', 4: 'mul8', 6: 'div8'}[reg], (rm,), 8)
    if b == 0xf7:
        reg, rm = modrm(width)
        if reg == 0:
            return done('test', (rm, imm(4)))
        if reg not in (2, 3, 4, 5, 6):
            raise EvidenceError(f'{va:#x}: unlisted f7 /{reg}')
        return done({2: 'not', 3: 'neg', 4: 'mul', 5: 'imul1', 6: 'div'}[reg], (rm,))
    if b == 0xff:
        reg = code[i] >> 3 & 7
        reg, rm = modrm(64 if reg in (2, 4, 6) else width)
        if reg in (0, 1):
            return done('dec' if reg else 'inc', (rm,))
        if reg == 2:
            return done('call', (rm,), 64)
        if reg == 4:
            return done('jmpr', (rm,), 64)
        if reg == 6:
            return done('push', (rm,), 64)
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
        elif op == 'punpckldq':
            a, b = self.x128(ops[0]), self.x128(ops[1])
            self.setx(ops[0], sum((a >> 32 * k & 0xffffffff) << 64 * k | (b >> 32 * k & 0xffffffff) << (64 * k + 32) for k in range(2)))
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
                val = self.rd(ops[0])
                self.regs[4] -= 8
                self.store(self.regs[4], 8, val)
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
                mask = (1 << bits) - 1
                self.regs[0] = full & mask
                self.regs[2] = full >> bits
                self.cf = self.of = self.regs[2] != 0
            elif op == 'div':
                bits = ins.width
                d = self.rd(ops[0])
                if d == 0:
                    raise Unmodelled(f'{rip:#x}: division by zero')
                mask = (1 << bits) - 1
                full = (self.regs[2] & mask) << bits | self.regs[0] & mask
                if full // d > mask:
                    raise Unmodelled(f'{rip:#x}: quotient overflow')
                self.regs[0], self.regs[2] = full // d, full % d
            elif op == 'mul8':
                full = self.rd(ops[0]) * (self.regs[0] & 0xff)
                self.regs[0] = self.regs[0] & ~0xffff | full
                self.cf = self.of = full > 0xff
            elif op == 'div8':
                d = self.rd(ops[0])
                if d == 0:
                    raise Unmodelled(f'{rip:#x}: division by zero')
                full = self.regs[0] & 0xffff
                if full // d > 0xff:
                    raise Unmodelled(f'{rip:#x}: quotient overflow')
                self.regs[0] = self.regs[0] & ~0xffff | (full % d) << 8 | full // d
            elif op == 'imul2':
                bits = ins.width
                v = signed(self.rd(ops[0]), bits) * signed(self.rd(ops[1]), bits)
                self.wr(ops[0], v)
                self.cf = self.of = v != signed(v & ((1 << bits) - 1), bits)
            elif op == 'movsx':
                self.wr(ops[0], signed(self.rd(ops[1]), ops[1][2] if ops[1][0] == 'r' else ops[1][6]))
            elif op == 'xchg':
                a, b = self.rd(ops[0]), self.rd(ops[1])
                self.wr(ops[0], b)
                self.wr(ops[1], a)
            elif op in ('rol', 'ror'):
                bits = ins.width
                n = self.rd(ops[1]) & (63 if bits == 64 else 31)
                n %= bits
                a = self.rd(ops[0])
                if op == 'ror':
                    n = (bits - n) % bits
                res = (a << n | a >> (bits - n)) & ((1 << bits) - 1)
                self.wr(ops[0], res)
                self.cf = bool(res & 1) if op == 'rol' else bool(res >> (bits - 1))
            elif op in ('shld', 'shldcl', 'shrd', 'shrdcl'):
                bits = ins.width
                n = (ops[2][1] if op in ('shld', 'shrd') else self.regs[1]) & (63 if bits == 64 else 31)
                if n:
                    a, b = self.rd(ops[0]), self.rd(ops[1])
                    mask = (1 << bits) - 1
                    if op.startswith('shld'):
                        res = (a << n | b >> (bits - n)) & mask
                        self.cf = bool(a >> (bits - n) & 1)
                    else:
                        res = (a >> n | b << (bits - n)) & mask
                        self.cf = bool(a >> (n - 1) & 1)
                    self.nz(res, bits)
                    self.wr(ops[0], res)
            elif op == 'bt':
                self.cf = bool(self.rd(ops[0]) >> (self.rd(ops[1]) & (ins.width - 1)) & 1)
            elif op in ('bsf', 'bsr'):
                a = self.rd(ops[1])
                self.zf = a == 0
                if a:
                    self.wr(ops[0], (a & -a).bit_length() - 1 if op == 'bsf' else a.bit_length() - 1)
            elif op == 'lzcnt':
                a = self.rd(ops[1])
                res = ins.width - a.bit_length()
                self.cf, self.zf = a == 0, res == 0
                self.wr(ops[0], res)
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
                self.wr(ops[0], ~self.rd(ops[0]) & ((1 << ins.width) - 1))
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
                n = self.rd(ops[1]) & (63 if ins.width == 64 else 31)
                a = self.rd(ops[0])
                if op == 'sar':
                    res = (signed(a, ins.width) >> n) & ((1 << ins.width) - 1)
                else:
                    res = (a << n if op == 'shl' else a >> n) & ((1 << ins.width) - 1)
                if n:
                    self.nz(res, ins.width)
                    self.cf = bool(a >> (n - 1) & 1) if op != 'shl' else bool(a >> (ins.width - n) & 1) if n <= ins.width else False
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


# ---- subjects


def word(a, off, size, val):
    a.mem[off:off + size] = (val & ((1 << size * 8) - 1)).to_bytes(size, 'little')


def read(blob, off, size=8):
    return int.from_bytes(blob[off:off + size], 'little')


FILLS = {}


def fill_bytes(n, seed):
    """A position-dependent pattern, so a shifted read or a stray write shows."""
    if (n, seed) not in FILLS:
        FILLS[n, seed] = bytes((i * 11 + seed + (i >> 8)) & 0xff for i in range(n))
    return FILLS[n, seed]


HEAD_MAIN = 0x26fbab0
HEAD_A = 0x4ce19c0
HEAD_B = 0x4ce3360
DAYS = 0x3425a20
HASH = 0x399c7a0
SLOT_TRACKER = 0x57748f8
SLOT_ROW = 0x5773170
SLOT_DATE = 0x576e8b0
SLOT_OVERFLOW = 0x5773190
SLOT_PANIC = 0x576e468
SLOT_ONCE = 0x576e8b8
DEFAULT_ROW = 0x57862a0
ONCE_WORD = 0x5786300
ONCE_VTABLE = 0x56f2288
ONCE_LOCATION = 0x56f22b0
QTY_LOCATION = 0x5715e68
BOTH_LOCATION = 0x56eb3e8
PANIC_TEXT = 0x219cb3
PANIC_LOCATION = 0x566aa98
ONE = 0x20a730
TWO63 = 0x20a7f0
CAP_HIGH = 0x20a218
CAP_MM = 0x20a510
ALLOWED = (0, 18, 44, 53, 55, 58, 59, 108, 109)
SHAPES = (dict(blocked=0x3810, links=0x37e0, tracker=0x5d0, double=0x68c, dex=0x5c0, mode=0x8f2, rates=0x618, vip=0x5d8, mm=0x5f0),
          dict(blocked=0x4290, links=0x4260, tracker=0x1050, double=0x110c, dex=0x1040, mode=0x1372, rates=0x1098, vip=0x1058, mm=0x1070))
VOLUME = 0x80
DATE = 0x60
COPIES = {
    HEAD_MAIN: dict(start=0x26fbab0, stop=0x26fc542, hit=0x26fd230, shape=0, inputs=(0xd8, 0x98, 0xd0, 0x80), scale=0x18, spill=0x30, keep='rbx', tag=0x178, out=0x158, tracker=0x188),
    HEAD_A: dict(start=0x4ce19c0, stop=0x4ce2452, hit=0x4ce31e0, shape=0, inputs=(0x158, 0x98, 0x150, 0x80), scale=0x18, spill=0x20, keep='r14', tag=0x1d8, out=0x160, tracker=0x1e8),
    HEAD_B: dict(start=0x4ce3360, stop=0x4ce3df2, hit=0x4ce4b80, shape=1, inputs=(0x158, 0x98, 0x150, 0x80), scale=0x18, spill=0x20, keep='r14', tag=0x1d8, out=0x160, tracker=0x1e8),
}
SEEN = None
MAX_CALLS = 400


class Panicked(Exception):
    pass


class Stop(Exception):
    pass


def user(n, last=0):
    return bytes([n]) + bytes((n * 3 + k * 37) & 0xff for k in range(1, 19)) + bytes([last or n])


# ---- closed-form model


def is_nan(bits):
    return bits & 0x7fffffffffffffff > 0x7ff0000000000000


def rust_min(row, cur):
    """Rust f64::min on bits: a not-a-number on one side gives the other side."""
    if is_nan(cur):
        return row
    if is_nan(row):
        return cur
    return row if b2f(row) < b2f(cur) else cur


def sat_add(x, y, tally):
    if x + y > U64:
        tally[0] += 1
        return U64
    return x + y


def sat_double(x, tally):
    if x >> 63:
        tally[0] += 1
        return U64
    return x + x


def day_sum(rows, date, count, tally):
    a = b = 0
    table = {d: (x, y) for d, x, y in rows}
    for k in range(1, count + 1):
        d = signed((date - k) & 0xffffffff, 32)
        if d == 0:
            raise Panicked('date')
        if d in table:
            a = sat_add(table[d][0], a, tally)
            b = sat_add(table[d][1], b, tally)
    return a, b


def f64_of_u64(x):
    """The cvtsi2sd-free conversion of a u64 at the start of the fraction loop."""
    hi, lo = x >> 32, x & 0xffffffff
    return float(hi) * 4294967296.0 + float(lo)


def mm_bound(fraction_bits, pool):
    """fraction * pool as f64, not finite gives 0, then saturating to u64 through the clamp."""
    x = b2f(fraction_bits) * f64_of_u64(pool)
    if not math.isfinite(x) or x <= 0.0:
        return 0
    if x >= 2.0 ** 64:
        return U64
    return int(x)


def tier_rule(v):
    tally = [0]
    w = dict(tracker=0, rows=0, hashes=0, panic=False, once=0, empty=False, both_hooks=0)
    if v['blocked_items']:
        w['hashes'] += 1
    if v['blocked_items'] and v['user'] in v['blocked']:
        w['empty'] = True
        return w
    w['tracker'] = 1
    if v['link_items']:
        w['hashes'] += 1
    owners = [v['user']] + list(v['links'].get(v['user'], ()) if v['link_items'] else ())
    total_a = total_b = 0
    once_cold = v['once'] != 0
    try:
        for o in owners:
            w['rows'] += 1
            a, b = day_sum(v['rows'].get(o, v['row_default']), v['date'], 14, tally)
            if v['double']:
                a, b = sat_double(a, tally), sat_double(b, tally)
            for dex in v['dexes']:
                if v['mode'] == 2 and dex['word'] not in ALLOWED:
                    continue
                if dex['items']:
                    w['hashes'] += 1
                if once_cold:
                    once_cold = False
                    w['once'] = 1
                rows = dex['rows'][o] if dex['items'] and o in dex['rows'] else v['default_tree']
                x, y = day_sum(rows, v['date'], 14, tally)
                a = sat_add(x, a, tally)
                b = sat_add(y, b, tally)
            total_a = sat_add(a, total_a, tally)
            total_b = sat_add(b, total_b, tally)
    except Panicked:
        w['panic'] = True
        return w
    w['a'], w['b'] = total_a, total_b
    both = total_a + total_b
    rates = list(v['rates'])
    scale = f2b(1.0)
    hit = None
    for k in range(len(v['vip']) - 1, -1, -1):
        if both > U64:
            w['both_hooks'] += 1
        if min(both, U64) >= v['vip'][k][1] // 10000:
            hit = k
            break
    last = rates[3]
    if hit is not None:
        row = v['vip'][hit]
        rates[0], rates[1], rates[2] = rust_min(row[3], rates[0]), rust_min(row[4], rates[1]), rust_min(row[5], rates[2])
        last = rust_min(row[0], rates[3])
        scale = row[2]
    w['vip'] = hit
    w['mm'] = None
    for k in range(len(v['mm']) - 1, -1, -1):
        if total_a >= mm_bound(v['mm'][k][0], v['pool']):
            w['mm'] = k
            rate = v['mm'][k][1]
            rates[1] = rust_min(rate, rates[1])
            last = rust_min(rate, last)
            break
    rates[3] = last
    w['rates'], w['scale'], w['hooks'] = rates, scale, tally[0]
    return w


def outcome_name(v):
    w = tier_rule(v)
    if w['empty']:
        return 'no rows'
    if w['panic']:
        return 'date panic'
    return f"vip {'none' if w['vip'] is None else 'row'}, mm {'none' if w['mm'] is None else 'row'}"


# ---- harness


def hash_of(v, key):
    forced = v.get('hash')
    if forced is not None:
        return forced
    h = 0xcbf29ce484222325
    for b in key:
        h = (h ^ b) * 0x100000001b3 & U64
    return h ^ h >> 29


def placement(buckets, h, used):
    """First empty bucket on the triangular probe of 16-byte groups, as the insert would pick it."""
    pos, step = h & buckets - 1, 0
    while True:
        for k in range(16):
            p = pos + k & buckets - 1
            if p not in used:
                return p
        step += 16
        pos = pos + step & buckets - 1


def table(m, v, stride, rows, buckets, dead=()):
    """rows: (key, writer).  Returns the control pointer of a hashbrown table with the mirror group."""
    while buckets < 2 * len(rows) + 2 and not v.get('hash_full'):
        buckets *= 2
    a = m.arena(buckets * stride + buckets + 16)
    ctrl = a.base + buckets * stride
    tags = bytearray(b'\xff' * buckets)
    for p in dead:
        tags[p] = 0x80
    used = set(dead)
    for key, write in rows:
        h = hash_of(v, key)
        p = placement(buckets, h, used)
        used.add(p)
        tags[p] = h >> 57 & 0x7f
        at = ctrl - (p + 1) * stride
        m.store_bytes(at, key)
        if write:
            write(at)
    m.store_bytes(ctrl, bytes(tags) + bytes(tags[:16]))
    return ctrl, buckets - 1


def tree_node(m, rows, height, spread):
    size = 0xe8 + (0x60 if height else 0)
    a = m.arena(size)
    at = a.base
    if height == 0:
        take, kids = rows, []
    elif len(rows) < 2:
        take, kids = rows, [[] for _ in rows] + [[]]
    else:
        n = min(spread, len(rows) - 1)
        step = len(rows) // (n + 1) or 1
        idx = [step * (k + 1) - 1 for k in range(n)]
        take = [rows[k] for k in idx]
        kids, lo = [], 0
        for k in idx + [len(rows)]:
            kids.append(rows[lo:k])
            lo = k + 1
    m.store(at + 0xe6, 2, len(take))
    for k, (d, x, y) in enumerate(take):
        m.store(at + 0xb8 + k * 4, 4, d)
        m.store(at + k * 16, 8, x)
        m.store(at + k * 16 + 8, 8, y)
    for k, sub in enumerate(kids):
        m.store(at + 0xe8 + k * 8, 8, tree_node(m, sub, height - 1, spread))
    return at


def fits(n, height, spread):
    if height == 0:
        return n <= 11
    k = min(spread, n - 1) if n >= 2 else 0
    if k == 0:
        return True
    return fits(n // (k + 1) * 1 + (n - (n // (k + 1)) * (k + 1)) + 1, height - 1, spread)


def tree(m, rows, height=0, spread=2, null_empty=True):
    """(root, height): an empty tree is the null root unless the vector asks for an empty node."""
    rows = sorted(rows)
    if not rows and null_empty:
        return 0, 0
    while not fits(len(rows), height, spread):
        height += 1
    return tree_node(m, rows, height, spread), height


def place_tree(m, at, rows, height):
    root, h = tree(m, rows, height)
    m.store(at, 8, root)
    if root:
        m.store(at + 8, 8, h)


def machine(ctx):
    img, code, slots, got = ctx
    m = Machine(img, ())
    if SEEN is not None:
        m.seen = SEEN
    m.code = code
    m.slots = slots
    m.got = dict(got)
    m.real[DAYS] = DAYS
    stack = m.arena(0x8000, strict=False)
    stack.mem[:] = fill_bytes(0x8000, 0x35)
    m.stack = stack
    m.top = stack.base + 0x7f08
    return m


def bytes_at(self, addr, size):
    return bytes(self.load(addr + k, 1) for k in range(size))


def store_bytes(self, addr, blob):
    for k, b in enumerate(blob):
        self.store(addr + k, 1, b)


Machine.bytes_at = bytes_at
Machine.store_bytes = store_bytes


def common_stubs(m, v, calls):
    s = m.slots

    def date():
        q = m.regs
        base, step = signed(q[R['rdi']] & 0xffffffff, 32), signed(q[R['rsi']] & 0xffffffff, 32)
        if base != v['date']:
            raise Unmodelled('date base')
        calls['dates'] += 1
        calls['steps'] = calls.get('steps', ()) + (step,)
        if calls['dates'] > MAX_CALLS * 8:
            raise Unmodelled('date calls')
        m.clobber((base + step) & 0xffffffff)

    def overflow():
        q = m.regs
        if q[R['rdi']] != 0 or q[R['rsi']] not in (QTY_LOCATION, BOTH_LOCATION):
            raise Unmodelled('overflow arguments')
        calls['hooks' if q[R['rsi']] == QTY_LOCATION else 'both_hooks'] += 1
        m.clobber()

    def panic():
        q = m.regs
        if q[R['rdi']] != PANIC_TEXT or q[R['rsi']] != 0x22 or q[R['rdx']] != PANIC_LOCATION:
            raise Unmodelled('panic arguments')
        raise Panicked('date')

    m.stubs.update({s[SLOT_DATE]: date, s[SLOT_OVERFLOW]: overflow, s[SLOT_PANIC]: panic})


def check_head(ctx, v):
    m = machine(ctx)
    c = COPIES[v['copy']]
    shape = SHAPES[c['shape']]
    w = tier_rule(v)
    ex = m.arena(0x4700)
    calls = dict(tracker=0, rows=0, hashes=0, once=0, dates=0, hooks=0, both_hooks=0, sums=None)

    def link_row(owners):
        def write(at):
            area = m.arena(max(len(owners), 1) * 0x40)
            for k, o in enumerate(owners):
                m.store_bytes(area.base + k * 0x40 + 0x18, o)
            m.store(at + 0x20, 8, area.base)
            m.store(at + 0x28, 8, len(owners))
        return write

    def put_map(at, stride, rows, items, buckets=16, dead=()):
        ctrl, mask = table(m, v, stride, rows, buckets, dead)
        m.store(ex.base + at, 8, ctrl)
        m.store(ex.base + at + 8, 8, mask)
        m.store(ex.base + at + 0x18, 8, items)

    put_map(shape['blocked'], 0x28, [(k, None) for k in v['blocked']], v['blocked_items'], v.get('buckets', 16), v.get('dead', ()))
    put_map(shape['links'], 0x30, [(k, link_row(o)) for k, o in v['links'].items()], v['link_items'], v.get('buckets', 16), v.get('dead', ()))
    m.store(ex.base + DATE, 4, v['date'])
    m.store(ex.base + shape['double'], 1, v['double'])
    m.store(ex.base + shape['mode'], 1, v['mode'])
    dexes = m.arena(max(len(v['dexes']), 1) * 0x2f0)

    def tree_writer(rows, height):
        return lambda at: place_tree(m, at + 0x40, rows, height)

    for k, dex in enumerate(v['dexes']):
        base = dexes.base + k * 0x2f0
        m.store(base + 0x30, 8, dex['word'])
        ctrl, mask = table(m, v, 0x78, [(o, tree_writer(r, v.get('height', 0))) for o, r in dex['rows'].items()], v.get('buckets', 16), v.get('dead', ()))
        m.store(base + 0xf8, 8, ctrl)
        m.store(base + 0x100, 8, mask)
        m.store(base + 0x110, 8, dex['items'])
    m.store(ex.base + shape['dex'], 8, dexes.base)
    m.store(ex.base + shape['dex'] + 8, 8, len(v['dexes']))
    for k, x in enumerate(v['rates']):
        m.store(ex.base + shape['rates'] + k * 8, 8, x)
    vip = m.arena(max(len(v['vip']), 1) * 0x30)
    for k, (rate, need, sc, r0, r1, r2) in enumerate(v['vip']):
        m.store(vip.base + k * 0x30, 8, r0)
        m.store(vip.base + k * 0x30 + 8, 8, r1)
        m.store(vip.base + k * 0x30 + 0x10, 8, r2)
        m.store(vip.base + k * 0x30 + 0x18, 8, rate)
        m.store(vip.base + k * 0x30 + 0x20, 8, need)
        m.store(vip.base + k * 0x30 + 0x28, 8, sc)
    m.store(ex.base + shape['vip'], 8, vip.base)
    m.store(ex.base + shape['vip'] + 8, 8, len(v['vip']))
    mm = m.arena(max(len(v['mm']), 1) * 0x10)
    for k, (frac, rate) in enumerate(v['mm']):
        m.store(mm.base + k * 0x10, 8, frac)
        m.store(mm.base + k * 0x10 + 8, 8, rate)
    m.store(ex.base + shape['mm'], 8, mm.base)
    m.store(ex.base + shape['mm'] + 8, 8, len(v['mm']))
    rows_at = {}
    for o, rows in v['rows'].items():
        a = m.arena(0x38)
        place_tree(m, a.base + 0x28, rows, v.get('height', 0))
        rows_at[o] = a.base
    other = m.arena(0x38)
    place_tree(m, other.base + 0x28, v['row_default'], 0)
    root, h = tree(m, v['default_tree'], 0)
    m.got[DEFAULT_ROW + 0x28] = root
    m.got[DEFAULT_ROW + 0x30] = h
    m.got[ONCE_WORD] = v['once']
    who = m.arena(20)
    m.store_bytes(who.base, v['user'])
    out = m.arena(0x18)
    keep = m.arena(16)
    common_stubs(m, v, calls)
    s = m.slots

    def hasher():
        q = m.regs
        at = q[R['rdi']] - ex.base
        if not (at in (shape['blocked'] + 0x20, shape['links'] + 0x20)) and not (dexes.base + 0x118 <= q[R['rdi']] < dexes.base + len(v['dexes']) * 0x2f0 and (q[R['rdi']] - dexes.base - 0x118) % 0x2f0 == 0):
            raise Unmodelled('hasher state')
        calls['hashes'] += 1
        if calls['hashes'] > MAX_CALLS:
            raise Unmodelled('hash calls')
        m.clobber(hash_of(v, m.bytes_at(q[R['rsi']], 20)))

    def tracker():
        q = m.regs
        if q[R['rsi']] != ex.base + shape['tracker'] or m.bytes_at(q[R['rdx']], 20) != v['user'] or q[R['rdi']] != q[R['rsp']] + 0x240:
            raise Unmodelled('tracker arguments')
        calls['tracker'] += 1
        m.clobber()

    def row():
        q = m.regs
        if q[R['rdi']] != ex.base + VOLUME:
            raise Unmodelled('row state')
        calls['rows'] += 1
        if calls['rows'] > MAX_CALLS // 16:
            raise Unmodelled('row calls')
        m.clobber(rows_at.get(m.bytes_at(q[R['rsi']], 20), other.base))

    def once():
        q = m.regs
        if q[R['rdi']] != ONCE_WORD or q[R['rsi']] & 0xffffffff != 1 or q[R['rcx']] != ONCE_VTABLE or q[R['r8']] != ONCE_LOCATION:
            raise Unmodelled('once arguments')
        if m.load(m.load(q[R['rdx']], 8), 8) != DEFAULT_ROW:
            raise Unmodelled('once closure')
        calls['once'] += 1
        m.got[ONCE_WORD] = 0
        m.clobber()

    def sums():
        calls['sums'] = (m.regs[R['rcx']], m.regs[R['rdx']])

    def stop():
        raise Stop()

    m.stubs.update({HASH: hasher, s[SLOT_TRACKER]: tracker, s[SLOT_ROW]: row, s[SLOT_ONCE]: once})
    m.hooks[c['stop']] = stop
    m.hooks[c['sums']] = sums
    if v.get('zero_stack'):
        m.stack.mem[:] = bytes(len(m.stack.mem))
    r = m.regs
    r[R['rsp']] = m.top
    m.store(m.top, 8, 0xfeedface)
    m.store(m.top + 8, 8, v['stack_word'])
    for k in range(16):
        if k != R['rsp']:
            r[k] = 0xbad0_0000 + k
    for name_ in ('rbx', 'rbp', 'r12', 'r13', 'r14', 'r15'):
        r[R[name_]] = 0xc0de0000 + R[name_]
    r[R['rdi']], r[R['rsi']], r[R['rdx']], r[R['rcx']], r[R['r8']], r[R['r9']] = out.base, ex.base, who.base, v.get('ecx', 0x77770001), v['pool'], 0x88880001
    stopped = False
    try:
        m.run(c['start'])
    except Stop:
        stopped = True
    except Panicked:
        if not w['panic']:
            return 'panic not modelled'
        return None
    if w['panic']:
        return 'panic missing'
    if (calls['tracker'], calls['rows'], calls['hashes'], calls['once']) != (w['tracker'], w['rows'], w['hashes'], w['once']):
        return f"calls {calls['tracker'], calls['rows'], calls['hashes'], calls['once']}"
    if w['empty']:
        if stopped:
            return 'ran on past the block map'
        if r[R['rsp']] != m.top + 8:
            return 'stack'
        for name_ in ('rbx', 'rbp', 'r12', 'r13', 'r14', 'r15'):
            if r[R[name_]] != 0xc0de0000 + R[name_]:
                return 'callee-saved'
        if (m.load(out.base, 8), m.load(out.base + 8, 8), m.load(out.base + 16, 8)) != (0, 8, 0):
            return 'empty vector'
        return None
    if not stopped:
        return 'returned early'
    if calls['sums'] != (w['a'], w['b']):
        return 'sums'
    if (calls['hooks'], calls['both_hooks']) != (w['hooks'], w['both_hooks']):
        return f"hooks {calls['hooks']}"
    rsp = r[R['rsp']]
    if r[R['r15']] != w['a']:
        return 'first sum'
    if r[R[c['keep']]] != v['stack_word']:
        return 'stack word'
    if m.load(rsp + c['scale'], 8) != w['scale']:
        return 'scale'
    if (m.load(rsp + 0x68, 8), m.load(rsp + 0x70, 8), m.load(rsp + 0x78, 8)) != (0, 8, 0):
        return 'row vector'
    if m.load(rsp + c['spill'], 8) != ex.base or m.load(rsp + c['pool'], 8) != v['pool']:
        return 'spills'
    if (m.load(rsp + c['tag'], 8), m.load(rsp + c['out'], 8), m.load(rsp + 0x14, 4), m.load(rsp + c['tracker'], 8)) != (0x88880001, out.base, v.get('ecx', 0x77770001), ex.base + shape['tracker']):
        return 'argument spills'
    for k, at in enumerate(c['inputs']):
        if m.load(rsp + at, 8) != w['rates'][k]:
            return f'rate {k}'
    return None


def check_days(ctx, v):
    """0x3425a20 called directly: any tree, any count."""
    m = machine(ctx)
    calls = dict(dates=0, hooks=0, both_hooks=0)
    common_stubs(m, v, calls)
    holder = m.arena(16)
    root, h = tree(m, v['tree'], v.get('height', 0), v.get('spread', 2), v.get('null', True))
    m.store(holder.base, 8, root)
    if root or v.get('height_set'):
        m.store(holder.base + 8, 8, h)
    tally = [0]
    try:
        want = day_sum(v['tree'], v['date'], v['count'], tally)
    except Panicked:
        want = None
    r = m.regs
    r[R['rsp']] = m.top
    m.store(m.top, 8, 0xfeedface)
    for name_ in ('rbx', 'rbp', 'r12', 'r13', 'r14', 'r15'):
        r[R[name_]] = 0xc0de0000 + R[name_]
    r[R['rdi']], r[R['rsi']], r[R['rdx']] = holder.base, v['date'] & 0xffffffff, v['count'] | 0x5555555500000000
    try:
        m.run(DAYS)
    except Panicked:
        return None if want is None else 'panic not modelled'
    if want is None:
        return 'panic missing'
    if r[R['rsp']] != m.top + 8:
        return 'stack'
    for name_ in ('rbx', 'rbp', 'r12', 'r13', 'r14', 'r15'):
        if r[R[name_]] != 0xc0de0000 + R[name_]:
            return 'callee-saved'
    if (r[0], r[R['rdx']]) != want:
        return f'sum {r[0]:#x} {r[R["rdx"]]:#x}'
    if calls['hooks'] != tally[0]:
        return f"hooks {calls['hooks']}"
    if calls.get('steps', ()) != tuple(-k for k in range(1, v['count'] + 1)):
        return 'date steps'
    return None


def range_allows(k):
    """TimeDelta::days(k) on the u32 loop counter: the test at the head of both loops."""
    return k <= 1 << 31


def check_range(ctx, v):
    """One pass over the day range test with a preset counter, entered past the loop head."""
    m = machine(ctx)
    calls = dict(dates=0, hooks=0, both_hooks=0)
    common_stubs(m, v, calls)
    r = m.regs
    rsp = m.stack.base + 0x1000
    r[R['rsp']] = rsp
    m.store(rsp + 0x14, 4, v['date'])
    for reg in ('r13', 'r15'):
        r[R[reg]] = v['k']
    r[R['rbx']] = 0xffffffff
    m.store(rsp + 0x10, 4, 0xffffffff)
    m.store(rsp + 0x18, 8, 0)
    m.store(rsp + 0x20, 8, 0)
    r[R['rbp']] = v['k']
    r[R['r10']] = 0

    def stop():
        raise Stop()

    m.hooks[v['after']] = stop
    try:
        m.run(v['start'])
    except Stop:
        return None if range_allows(v['k']) else 'passed'
    except Panicked:
        return 'refused' if range_allows(v['k']) else None
    return 'ran on'


def check(ctx, v):
    return {'head': check_head, 'days': check_days, 'range': check_range}[v['kind']](ctx, v)


# ---- vectors


D0 = 20000
U = user(0x21)
L1 = user(0x32)
L2 = user(0x43)
L3 = user(0x54)
HIGH = 1 << 63
TOP = U64
RATES = (0.00045, 0.00015, 0.0007, 0.0002)
NAN = 0x7ff8000000000123
TIERS = ((0.0004, 5 * 10 ** 10, 0.8), (0.00035, 25 * 10 ** 10, 0.7), (0.0003, 100 * 10 ** 10, 0.6), (0.00025, 500 * 10 ** 10, 0.5))
MM = ((0.005, -0.00001), (0.015, -0.00002), (0.03, -0.00003))


def fl(*xs):
    return [f2b(x) for x in xs]


def vip_rows(rows=TIERS):
    return [(f2b(r), n, f2b(s)) for r, n, s in rows]


def mm_rows(rows=MM):
    return [(f2b(f), f2b(r)) for f, r in rows]


def days(*vals, date=D0):
    """(k, a, b) rows, k days before the date."""
    return [(date - k, a, b) for k, a, b in vals]


def dex(word_, rows=None, items=None):
    rows = rows or {}
    return dict(word=word_, rows=rows, items=len(rows) if items is None else items)


def head(group, copy, **kw):
    v = dict(kind='head', group=group, copy=copy, user=U, blocked=[], blocked_items=0, links={}, link_items=0, date=D0, double=0, mode=0, dexes=[], rows={U: days((1, 100, 7))},
             row_default=[], default_tree=[], once=0, rates=fl(*RATES), vip=[], mm=[], pool=10 ** 12, stack_word=0x1122334455667788)
    v.update(kw)
    v['vip'] = [row if len(row) == 6 else row + tuple(f2b(RATES[j] * (0.55 + 0.1 * k + 0.01 * j)) for j in range(3)) for k, row in enumerate(v['vip'])]
    return v


def decoy(k):
    b = bytearray(U)
    b[k % 20] ^= (k // 20) * 2 + 1
    return bytes(b)


def group_vectors(copy):
    out = []
    add = out.append
    # block map
    add(head('block', copy, blocked=[U], blocked_items=1))
    add(head('block', copy, blocked=[U], blocked_items=0))
    add(head('block', copy, blocked=[L1], blocked_items=1))
    add(head('block', copy, blocked=[decoy(0), decoy(15), decoy(16), decoy(19)], blocked_items=4, hash=0x5a00000000001234))
    add(head('block', copy, blocked=[decoy(k) for k in range(40)] + [U], blocked_items=41, hash=0x5a00000000001234, buckets=128))
    add(head('block', copy, blocked=[decoy(k) for k in range(32)] + [U], blocked_items=33, hash=0x5a00000000001234, buckets=128))
    add(head('block', copy, blocked=[decoy(k) for k in range(40)], blocked_items=40, hash=0x5a00000000001234, buckets=128))
    add(head('block', copy, blocked=[decoy(0), U], blocked_items=2, hash=0x5a00000000001234, dead=(4, 5)))
    add(head('block', copy, blocked=[decoy(0), decoy(15), decoy(19), U], blocked_items=4, hash=0x5a00000000001234))
    # links
    add(head('link', copy, links={U: [L1]}, link_items=1, rows={U: days((1, 3, 4)), L1: days((2, 50, 60))}))
    add(head('link', copy, links={U: [L1, L2, L3]}, link_items=3, rows={U: days((1, 3, 4)), L1: days((2, 50, 60)), L2: days((3, 700, 800)), L3: days((14, 9000, 1000))}))
    add(head('link', copy, links={U: []}, link_items=1, rows={U: days((1, 3, 4))}))
    add(head('link', copy, links={U: [L1]}, link_items=0, rows={U: days((1, 3, 4)), L1: days((2, 50, 60))}))
    add(head('link', copy, links={L1: [L2]}, link_items=1, rows={U: days((1, 3, 4)), L2: days((2, 50, 60))}))
    add(head('link', copy, links={decoy(0): [L1], decoy(15): [L1], decoy(16): [L1], decoy(19): [L2]}, link_items=4, hash=0x3300000000005678, rows={U: days((1, 3, 4)), L1: days((2, 50, 60)), L2: days((2, 51, 61))}))
    add(head('link', copy, links={**{decoy(k): [L1] for k in range(40)}, U: [L2]}, link_items=41, hash=0x3300000000005678, buckets=128, rows={U: days((1, 3, 4)), L1: days((2, 50, 60)), L2: days((2, 51, 61))}))
    add(head('link', copy, links={**{decoy(k): [L1] for k in range(32)}, U: [L2]}, link_items=33, hash=0x3300000000005678, buckets=128, rows={U: days((1, 3, 4)), L1: days((2, 50, 60)), L2: days((2, 51, 61))}))
    add(head('link', copy, links={decoy(k): [L1] for k in range(40)}, link_items=40, hash=0x3300000000005678, buckets=128, rows={U: days((1, 3, 4)), L1: days((2, 50, 60))}))
    add(head('link', copy, links={decoy(0): [L1], decoy(15): [L1], decoy(19): [L1], U: [L2]}, link_items=4, hash=0x3300000000005678, rows={U: days((1, 3, 4)), L2: days((2, 51, 61))}))
    add(head('link', copy, links={U: [L1, U]}, link_items=1, rows={U: days((1, 3, 4)), L1: days((2, 50, 60))}))
    add(head('link', copy, links={U: [L1, L2]}, link_items=1, rows={U: days((1, 3, 4))}, row_default=days((5, 11, 13))))
    # the 14-day window
    for k in (0, 1, 2, 7, 13, 14, 15, 16, 30):
        add(head('window', copy, rows={U: days((k, 1000 + k, 2000 + k))}))
    for h in (0, 1, 2, 3):
        add(head('window', copy, height=h, rows={U: days(*[(k, 10 ** k, 3 ** k) for k in range(0, 18)])}))
        add(head('window', copy, height=h, dexes=[dex(0, {U: days(*[(k, 7 ** k, 5 ** k) for k in range(0, 18)])})]))
    # double flag
    for dbl in (0, 1, 2):
        add(head('double', copy, double=dbl, rows={U: days((1, 6, 8))}, dexes=[dex(0, {U: days((1, 30, 50))})]))
        add(head('double', copy, double=dbl, rows={U: days((1, HIGH, 8))}, dexes=[dex(0, {U: days((1, 30, 50))})]))
        add(head('double', copy, double=dbl, rows={U: days((1, 5, HIGH + 2))}))
        add(head('double', copy, double=dbl, rows={U: days((1, HIGH - 1, HIGH - 2))}))
        add(head('double', copy, double=dbl, rows={U: days((1, 3, 4)), L1: days((1, 30, 40))}, links={U: [L1]}, link_items=1))
    # dex rows, filter words
    for word_ in list(range(0, 62)) + [105, 106, 107, 108, 109, 110, 111, 172, 173, 1 << 32, (1 << 32) + 18, (1 << 63) + 108, 0xffffffffffffff94, 0xffffffffffffff95, 0xffffffffffffff93]:
        for mode in (2, 1):
            add(head('filter', copy, mode=mode, dexes=[dex(word_, {U: days((1, 30, 50))})]))
    for mode in (0, 3):
        add(head('filter', copy, mode=mode, dexes=[dex(77, {U: days((1, 30, 50))})]))
    add(head('filter', copy, mode=2, dexes=[dex(77, {U: days((1, 30, 50))}), dex(0, {U: days((1, 31, 51))}), dex(78, {U: days((1, 32, 52))}), dex(109, {U: days((2, 33, 53))})]))
    add(head('filter', copy, mode=2, links={U: [L1]}, link_items=1, rows={U: days((1, 3, 4)), L1: days((1, 30, 40))},
             dexes=[dex(77, {U: days((1, 30, 50))}), dex(0, {U: days((1, 31, 51)), L1: days((3, 34, 54))})]))
    add(head('dex', copy, dexes=[dex(0, {L1: days((1, 30, 50))})]))
    add(head('dex', copy, dexes=[dex(0, {U: days((1, 30, 50))}, items=0)], default_tree=days((4, 1, 2))))
    add(head('dex', copy, dexes=[dex(0, {decoy(0): days((1, 30, 50)), decoy(15): days((1, 30, 50)), decoy(16): days((1, 31, 50)), decoy(19): days((1, 32, 50))})], hash=0x4400000000009abc, default_tree=days((6, 900, 901))))
    add(head('dex', copy, dexes=[dex(0, {**{decoy(k): days((1, 30, 50)) for k in range(40)}, U: days((2, 7, 8))})], hash=0x4400000000009abc, buckets=128))
    add(head('dex', copy, dexes=[dex(0, {**{decoy(k): days((1, 30, 50)) for k in range(32)}, U: days((2, 7, 8))})], hash=0x4400000000009abc, buckets=128))
    add(head('dex', copy, dexes=[dex(0, {decoy(k): days((1, 30, 50)) for k in range(40)})], hash=0x4400000000009abc, buckets=128, default_tree=days((6, 900, 901))))
    add(head('dex', copy, dexes=[dex(0, {decoy(0): days((1, 30, 50)), U: days((2, 8, 9))})], hash=0x4400000000009abc, dead=(0xc, 0xd)))
    add(head('dex', copy, dexes=[dex(0, {decoy(0): days((1, 30, 50)), decoy(15): days((1, 31, 50)), decoy(19): days((1, 32, 50)), U: days((2, 8, 9))})], hash=0x4400000000009abc))
    for once in (0, 3):
        add(head('default', copy, once=once, dexes=[dex(0)], default_tree=days((6, 900, 901))))
        add(head('default', copy, once=once, dexes=[dex(0), dex(1)], default_tree=days((6, 900, 901))))
        add(head('default', copy, once=once, dexes=[dex(0, {U: days((1, 5, 6))}), dex(1, {U: days((2, 7, 8))})]))
        add(head('default', copy, once=once, dexes=[dex(0, {U: days((1, 5, 6))}), dex(1)], default_tree=days((6, 900, 901))))
    add(head('default', copy, once=1, dexes=[dex(0)], default_tree=days((3, 100, 200))))
    add(head('default', copy, rows={}, row_default=days((3, 100, 200))))
    # saturation at each add
    add(head('saturate', copy, rows={U: days((1, TOP, 5), (2, 2, 6))}))
    add(head('saturate', copy, rows={U: days((1, 5, TOP), (2, 6, 2))}))
    add(head('saturate', copy, rows={U: days((1, TOP, TOP), (2, TOP, TOP), (3, 1, 1))}))
    add(head('saturate', copy, rows={U: days((1, TOP - 1, 5))}, dexes=[dex(0, {U: days((1, 2, 5))})]))
    add(head('saturate', copy, rows={U: days((1, 5, TOP - 1))}, dexes=[dex(0, {U: days((1, 5, 2))})]))
    add(head('saturate', copy, rows={U: days((1, TOP - 1, TOP - 1))}, dexes=[dex(0, {U: days((1, 2, 2))}), dex(1, {U: days((1, 3, 3))})]))
    add(head('saturate', copy, rows={U: days((1, TOP - 1, 5)), L1: days((2, 2, 6))}, links={U: [L1]}, link_items=1))
    add(head('saturate', copy, rows={U: days((1, 5, TOP - 1)), L1: days((2, 6, 2))}, links={U: [L1]}, link_items=1))
    add(head('saturate', copy, rows={U: days((1, TOP, TOP)), L1: days((2, TOP, TOP)), L2: days((3, 1, 1))}, links={U: [L1, L2]}, link_items=2, vip=vip_rows()))
    # vip rows
    add(head('vip', copy, vip=vip_rows(), rows={U: days((1, 0, 0))}))
    for need, _r in ((5 * 10 ** 6, 0), (25 * 10 ** 6, 1), (100 * 10 ** 6, 2), (500 * 10 ** 6, 3)):
        for delta in (-1, 0, 1):
            add(head('vip', copy, vip=vip_rows(), rows={U: days((1, (need + delta) // 3, need + delta - (need + delta) // 3))}))
    add(head('vip', copy, vip=[(f2b(0.0003), 123456789, f2b(0.5))], rows={U: days((1, 12345, 0))}))
    add(head('vip', copy, vip=[(f2b(0.0003), 123456789, f2b(0.5))], rows={U: days((1, 12344, 0))}))
    add(head('vip', copy, vip=[(f2b(0.0003), 123459999, f2b(0.5))], rows={U: days((1, 12345, 0))}))
    add(head('vip', copy, vip=[(f2b(0.0003), 123460000, f2b(0.5))], rows={U: days((1, 12345, 0))}))
    add(head('vip', copy, vip=[(f2b(0.0003), 123460000, f2b(0.5))], rows={U: days((1, 0, 12346))}))
    add(head('vip', copy, vip=[(f2b(0.0003), 0, f2b(0.5))], rows={U: days((1, 0, 0))}))
    add(head('vip', copy, vip=[(f2b(0.0003), TOP, f2b(0.5))], rows={U: days((1, TOP // 10000 - 1, 0))}))
    add(head('vip', copy, vip=[(f2b(0.0003), TOP, f2b(0.5))], rows={U: days((1, TOP // 10000, 0))}))
    add(head('vip', copy, vip=vip_rows(), rows={U: days((1, HIGH, HIGH + 5))}))
    add(head('vip', copy, vip=[(f2b(0.0003), TOP, f2b(0.5))] * 3, rows={U: days((1, HIGH, HIGH + 5))}))
    add(head('vip', copy, vip=[(f2b(0.0003), TOP, f2b(0.5))], rows={U: days((1, HIGH, HIGH + 5))}, zero_stack=True))
    add(head('vip', copy, vip=vip_rows(), rows={U: days((1, HIGH, HIGH + 5))}, zero_stack=True))
    add(head('vip', copy, vip=[(f2b(0.0003), TOP, f2b(0.5))], rows={U: days((1, HIGH, HIGH + 5))}, zero_stack=True, ecx=0))
    add(head('vip', copy, vip=[(f2b(0.0003), TOP, f2b(0.5)), (f2b(0.0002), 9 * 10 ** 18, f2b(0.25))], rows={U: days((1, TOP - 3, 2))}))
    add(head('vip', copy, vip=[(f2b(0.0003), 10 ** 6, f2b(0.5)), (f2b(0.0002), 10 ** 12, f2b(0.25)), (f2b(0.0001), 10 ** 7, f2b(0.125))], rows={U: days((1, 500, 0))}))
    for high in (f2b(0.1), f2b(0.0), f2b(-0.0), NAN, f2b(float('inf'))):
        add(head('vip', copy, vip=[(high, 100, f2b(0.5))], rates=fl(0.1, 0.2, 0.3, 0.0002), rows={U: days((1, 9, 9))}))
        add(head('vip', copy, vip=[(f2b(0.0003), 100, f2b(0.5))], rates=fl(0.1, 0.2, 0.3)+[high], rows={U: days((1, 9, 9))}))
        add(head('vip', copy, vip=[(NAN, 100, high)], rates=fl(0.1, 0.2, 0.3)+[high], rows={U: days((1, 9, 9))}))
    for slot in range(3):
        for mine in (f2b(0.1), f2b(0.00001), NAN, f2b(-0.0), f2b(0.0)):
            for cur in (f2b(0.05), NAN, f2b(0.0), f2b(-0.0)):
                row = [f2b(0.2), f2b(0.2), f2b(0.2)]
                row[slot] = mine
                now = fl(0.3, 0.3, 0.3, 0.3)
                now[slot] = cur
                add(head('vip', copy, vip=[(f2b(0.25), 100, f2b(0.5), row[0], row[1], row[2])], rates=now, rows={U: days((1, 9, 9))}))
    # mm rows
    add(head('mm', copy, mm=mm_rows(), pool=10 ** 6, rows={U: days((1, 0, 9))}))
    for bound in (5000, 15000, 30000):
        for delta in (-1, 0, 1):
            add(head('mm', copy, mm=mm_rows(), pool=10 ** 6, rows={U: days((1, bound + delta, 9))}))
    for pool in (0, 1, 3, 1 << 32, (1 << 32) + 1, (1 << 53) + 1, HIGH, HIGH + (1 << 40), HIGH + (1 << 12) + 1, TOP, TOP - 2047):
        for frac in (1.0, 0.5, 0.25, 1.5, 3.0, 1e-9):
            x = fl(frac, 0.0)[0]
            v = head('mm', copy, mm=[(x, f2b(-0.00001))], pool=pool, rows={U: days((1, mm_bound(x, pool), 9))})
            add(v)
            if mm_bound(x, pool):
                add(head('mm', copy, mm=[(x, f2b(-0.00001))], pool=pool, rows={U: days((1, mm_bound(x, pool) - 1, 9))}))
    for frac in (-0.5, -0.0, 0.0, float('inf'), float('-inf'), 1e300, 2.0 ** 11, 2.0 ** 12):
        add(head('mm', copy, mm=[(f2b(frac), f2b(-0.00001))], pool=1 << 53, rows={U: days((1, 0, 9))}))
        add(head('mm', copy, mm=[(f2b(frac), f2b(-0.00001))], pool=1 << 53, rows={U: days((1, 1 << 62, 9))}))
        add(head('mm', copy, mm=[(f2b(frac), f2b(-0.00001))], pool=1 << 53, rows={U: days((1, TOP, 9))}))
        add(head('mm', copy, mm=[(f2b(frac), f2b(-0.00001))], pool=1 << 53, rows={U: days((1, TOP - 1, 9))}))
    add(head('mm', copy, mm=[(NAN, f2b(-0.00001))], pool=7, rows={U: days((1, 0, 9))}))
    add(head('mm', copy, mm=[(f2b(1.7976931348623157e308), f2b(-0.00001))], pool=1, rows={U: days((1, 0, 9))}))
    add(head('mm', copy, mm=[(f2b(-1.7976931348623157e308), f2b(-0.00001))], pool=1, rows={U: days((1, 0, 9))}))
    add(head('mm', copy, mm=[(f2b(1.0), f2b(-0.00001))], pool=TOP, rows={U: days((1, TOP - 1, 0))}))
    add(head('mm', copy, mm=[(f2b(1.0), f2b(-0.00001))], pool=TOP, rows={U: days((1, TOP, 0))}))
    add(head('mm', copy, mm=[(f2b(0.9999999999999999), f2b(-0.00001))], pool=TOP, rows={U: days((1, TOP - 2047, 0))}))
    add(head('mm', copy, mm=[(f2b(0.9999999999999999), f2b(-0.00001))], pool=TOP, rows={U: days((1, 18446744073709549568, 0))}))
    add(head('mm', copy, mm=[(f2b(0.9999999999999999), f2b(-0.00001))], pool=TOP, rows={U: days((1, 18446744073709549567, 0))}))
    add(head('mm', copy, mm=[(f2b(0.5), f2b(-0.00001)), (f2b(0.25), f2b(-0.00002)), (f2b(0.75), f2b(-0.00003))], pool=1000, rows={U: days((1, 300, 0))}))
    for rate in (f2b(0.1), f2b(0.0), f2b(-0.0), NAN):
        for cur in (f2b(0.05), f2b(-0.0), f2b(0.0), NAN):
            add(head('mm', copy, mm=[(f2b(0.0), rate)], rates=fl(0.1, 0.2)[:1] + [cur] + fl(0.3) + [cur], pool=5))
            add(head('mm', copy, mm=[(f2b(0.0), rate)], rates=fl(0.1, 0.2, 0.3) + [cur], pool=5))
            add(head('mm', copy, mm=[(f2b(0.0), rate)], rates=fl(0.1) + [cur] + fl(0.3, 0.7), pool=5))
            add(head('mm', copy, vip=[(cur, 0, f2b(0.5))], mm=[(f2b(0.0), rate)], rates=fl(0.1, 0.2, 0.3, 0.6), pool=5))
    # no date
    add(head('date', copy, date=5, rows={U: days((1, 3, 4), date=5)}))
    add(head('date', copy, date=14, rows={U: days((1, 3, 4), date=14)}))
    add(head('date', copy, date=15, rows={U: days((14, 3, 4), date=15)}))
    add(head('date', copy, date=-5, rows={U: days((1, 3, 4), (9, 5, 6), date=-5)}))
    # a seeded mix of everything above
    rng = random.Random(0x94 + copy)
    owners = [U, L1, L2, L3]
    for k in range(120):
        def some_days():
            return days(*[(k_, rng.getrandbits(rng.choice((8, 40, 64))), rng.getrandbits(rng.choice((8, 40, 64)))) for k_ in sorted(rng.sample(range(17), rng.randint(0, 9)))])
        links_ = rng.sample(owners[1:], rng.randint(0, 3))
        rows_ = {o: some_days() for o in owners if rng.random() < 0.8}
        dex_ = [dex(rng.choice((0, 18, 44, 53, 77, 109, 200)), {o: some_days() for o in owners if rng.random() < 0.5}) for _ in range(rng.randint(0, 4))]
        vips = sorted((rng.randint(0, 10 ** 12) for _ in range(rng.randint(0, 4))))
        mms = sorted(rng.random() / 20 for _ in range(rng.randint(0, 3)))
        add(head('mix', copy, height=rng.randint(0, 2), double=rng.getrandbits(1), mode=rng.choice((0, 1, 2)), once=rng.choice((0, 3)), links={U: links_}, link_items=1, rows=rows_, dexes=dex_,
                 row_default=some_days(), default_tree=some_days(), vip=[(f2b(rng.random() / 1000), n * 10000, f2b(rng.random())) for n in vips],
                 mm=[(f2b(f), f2b(-rng.random() / 1000)) for f in mms], pool=rng.getrandbits(rng.choice((20, 40, 64))), stack_word=rng.getrandbits(64)))
    return out


def day_vectors():
    out = []

    def add(group, **kw):
        v = dict(kind='days', group=group, copy=DAYS, date=D0, count=14, tree=[])
        v.update(kw)
        out.append(v)

    add('count', count=0, tree=days((1, 3, 4)))
    add('count', count=0)
    for n in (1, 2, 3, 14, 15, 40):
        add('count', count=n, tree=days(*[(k, 2 ** k, 3 ** k) for k in range(0, 41)]))
        add('count', count=n)
        add('count', count=n, tree=[], null=False)
    for h in range(0, 5):
        add('tree', height=h, tree=days(*[(k, k + 1, k + 2) for k in range(0, 30)]))
        add('tree', height=h, spread=4, tree=days(*[(k, k + 1, k + 2) for k in range(0, 60, 2)]))
        add('tree', height=h, spread=11, tree=days(*[(k, k * 5, k * 7) for k in range(0, 40, 3)]))
    add('tree', height=1, tree=[], null=False, height_set=True)
    for d in (D0, -D0, 9, -3, 100, 2 ** 31 - 1, 15, 16, -(2 ** 31) + 20):
        add('sign', date=d, tree=[(d - k, 1 << k, 1 << 2 * k) for k in range(0, 16) if d - k >= -(2 ** 31)], height=1)
        add('sign', date=d, tree=[(d - k, 1 << k, 1 << 2 * k) for k in range(0, 16) if d - k >= -(2 ** 31)], height=0, count=3)
    add('sign', date=4, count=3, tree=[(-5, 1, 2), (-1, 3, 4), (1, 5, 6), (2, 7, 8), (3, 9, 10), (4, 11, 12)], height=0)
    add('panic', date=3, count=2, tree=days((1, 1, 1), date=3))
    add('panic', date=3, count=3, tree=days((1, 1, 1), date=3))
    add('panic', date=3, count=4, tree=days((1, 1, 1), date=3))
    add('panic', date=3, count=3)
    add('panic', date=3, count=2)
    add('panic', date=1, count=1)
    add('panic', date=1, count=1, tree=days((1, 1, 1), date=1))
    add('panic', date=2, count=1)
    add('saturate', tree=days((1, TOP, 3), (2, 5, 4)))
    add('saturate', tree=days((1, 3, TOP), (2, 4, 5)))
    add('saturate', tree=days((1, TOP, TOP), (2, TOP, TOP), (3, TOP, TOP)))
    add('saturate', tree=days((1, TOP - 1, TOP - 2), (2, 1, 2)))
    add('saturate', tree=days((1, TOP - 1, TOP - 2), (2, 1, 1), (3, 0, 1)))
    for k in (0, 1, 2, 14, 1 << 20, (1 << 31) - 1, 1 << 31, (1 << 31) + 1, (1 << 31) + 2, 0xffffffff, 0xa0000000):
        out.append(dict(kind='range', group='range', copy=DAYS, date=D0, k=k, start=0x3425a80, after=0x3425abd))
        out.append(dict(kind='range', group='range', copy=DAYS, date=D0, k=k, start=0x3425c40, after=0x3425c75))
    return out


def all_vectors():
    out = day_vectors()
    for c in COPIES:
        out += group_vectors(c)
    return out


# ---- binding


FDE_END = {}
RANGES = {}


def tail_pieces(img, rows, lo, hi):
    """Blocks outside the range that the range jumps to: linear decode from each target to its jump back."""
    known, out, todo = {i.va for i in rows}, [], [i.ops[0][1] for i in rows if i.op[0] == 'j' and i.op != 'jmpr' and not lo <= i.ops[0][1] < hi]
    while todo:
        va = todo.pop()
        if va in known:
            continue
        start = va
        while True:
            ins = decode_one(img.read(va, 16) + b'\x90' * 16, 0, va)
            known.add(va)
            va += ins.size
            if ins.op[0] == 'j' and not lo <= ins.ops[0][1] < hi:
                todo.append(ins.ops[0][1])
            if ins.op in ('jmp', 'ret'):
                break
        out.append((start, va))
    return sorted(out)


def bind(data):
    fdes = Fdes(data)
    img = Image(data)
    FDE_END[DAYS] = fdes.range_of(DAYS)['end']
    RANGES[DAYS] = ((DAYS, FDE_END[DAYS]),)
    for s, c in COPIES.items():
        FDE_END[s] = fdes.range_of(s)['end']
        end = c['stop'] + decode_one(img.read(c['stop'], 16) + b'\x90' * 16, 0, c['stop']).size
        rows = decode_range(img, c['start'], end)
        jump = next(k for k, i in enumerate(rows) if i.op == 'jmpr')
        base = rows[jump - 3].ops[1][4]
        entries = [base + struct.unpack('<i', img.read(base + 4 * k, 4))[0] for k in range(4)]
        if entries[3] >= end or not entries[0] < entries[1] < entries[2] < FDE_END[s]:
            raise EvidenceError(f'jump table of {s:#x}')
        c['table'] = base
        c['entries'] = entries
        RANGES[s] = ((c['start'], end),) + tuple(tail_pieces(img, rows, c['start'], end)) + ((entries[0], FDE_END[s]),)
    return fdes, img


def decode_subject(img, s):
    out = []
    for a, b in RANGES[s]:
        out += decode_range(img, a, b)
    return out


def scan_slots(img, code):
    """Pointer cells read by the code: RELATIVE ones hold a function, the others stand for themselves."""
    out, got = {}, {}
    for ins in code.values():
        for o in ins.ops:
            if o[0] == 'm' and o[1] is None and o[2] is None and not img.in_rodata(o[4], 1):
                try:
                    out[o[4]] = img.relative(o[4])
                except EvidenceError:
                    out[o[4]] = o[4]
                got[o[4]] = out[o[4]]
    return out, got


def bind_copies(listing):
    """Each copy's sum hook, stack slots and held register, read from its own instructions."""
    for s, c in COPIES.items():
        shape = SHAPES[c['shape']]
        rows = listing[s]
        hits = [i.va for i in rows if i.op == 'mov' and i.ops[1][0] == 'm' and i.ops[1][4] == shape['rates']]
        if len(hits) != 1:
            raise EvidenceError(f'sum hook of {s:#x}: {hits}')
        c['sums'] = hits[0]
        pools = [i.ops[0][4] for i in rows if i.op == 'mov' and i.ops[1] == ('r', R['r8'], 64) and i.ops[0][0] == 'm' and i.ops[0][1] == R['rsp'] and i.va < s + 0x20]
        if len(pools) != 1:
            raise EvidenceError(f'pool slot of {s:#x}: {pools}')
        c['pool'] = pools[0]


def build(data):
    check_digest(data)
    fdes, img = bind(data)
    listing = {s: decode_subject(img, s) for s in RANGES}
    bind_copies(listing)
    code = {}
    for rows in listing.values():
        code.update({i.va: i for i in rows})
    slots, got = scan_slots(img, code)
    return img, code, fdes, slots, got, listing


# ---- mutation survey


NO_PANIC = 'unreachable: follows a call that does not return'
UNWIND = 'unwind clean-up after a panic in a callee, not a modelled outcome'
NOT_TAKEN = 'r15 is r13 + 1 here and r13 < rbx, so the jbe above always jumps'
GAPS = ((0x3425b90, 0x3425b92, NOT_TAKEN), (0x3425c92, 0x3425c97, NOT_TAKEN), (0x26fc368, 0x26fc399, UNWIND), (0x4ce2278, 0x4ce22a9, UNWIND), (0x4ce3c18, 0x4ce3c49, UNWIND))


def gaps():
    return list(GAPS)


SUBJECTS = (HEAD_MAIN, DAYS)
NOT_MUTATED = (HEAD_A, HEAD_B)
SAME_DWORD = 'the same key dword already sits in this slot and the displaced store lands on a stack word nothing reads in the range'
SAME_BYTES = 'all 4 dwords of the source are equal, so the changed selector gives the same register'
CLAMP = 'a value outside 0..2^64 gives the same u64 without the clamp: the 2 compares after the convert decide it, and a value inside is unchanged by the clamp'
EQUIVALENT = {
    0x26fbb5e: SAME_BYTES, 0x26fbcad: SAME_BYTES, 0x26fbf88: SAME_BYTES,
    0x26fbc0e: SAME_DWORD, 0x26fbc51: SAME_DWORD, 0x26fbf27: SAME_DWORD,
    0x26fbd95: 'the state byte is 0 or 2 here and both values reach 0x26fbde0 with the same list words',
    0x26fbdbc: 'on the first pass the list cursor r8 is 0, so the spilled end pointer is never compared',
    0x26fbe22: 'state values 0 and 2 take the same path on the next pass',
    0x26fc2c7: 'cutoff / 10000 is below 2^51, so a saturated sum of 2^64 - 1 or 2^64 - 2 passes every row alike',
    0x26fc416: 'bit 32 of the mantissa cannot move a finite value above the bound or an infinity or NaN below it',
    0x26fc42a: 'for x in 2^63..2^64 the truncation of x - 2^64 in two complement is x, and the or with r9 sets a bit already set',
    0x26fc478: 'r9 is negative only for x >= 2^63, a multiple of 2048, so bit 0 that a 62-bit shift clears is already 0',
    0x26fc4d0: CLAMP, 0x26fc4d6: CLAMP,
    0x3425a9e: 'the sum x + C lands in 0..0xa8c000000000 or above 0xffff574000000000 for every u32 counter, so a flip of bit 32 of this limit changes no compare',
    0x3425b97: 'writes back the value loaded one instruction before; the mutant store lands on a word nothing reads',
    0x3425c5d: 'the sum x + C lands in 0..0xa8c000000000 or above 0xffff574000000000 for every u32 counter, so a flip of bit 32 of this limit changes no compare',
    0x3425c88: 'every exit of this loop passes the xor of r10 at 0x3425c04, so the value here is never returned',
}


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


def imm_size(ins, o):
    for n in (1, 2, 4, 8):
        if int.from_bytes(ins.raw[-n:], 'little', signed=True) == signed(o[1] & ((1 << n * 8) - 1), n * 8):
            if n == 1 and ins.raw[0] in (0xb8, 0xbf):
                continue
            return n
    return 0


def disp_at(ins, mem):
    raw, disp = ins.raw, mem[4]
    packed_ = struct.pack('<b', disp) if -128 <= disp < 128 else struct.pack('<i', disp)
    tail = 0
    imm = [o for o in ins.ops if o[0] == 'i']
    if imm:
        tail = imm_size(ins, imm[0])
    at = len(raw) - tail - len(packed_)
    return at if raw[at:at + len(packed_)] == packed_ else None


def field_sites(fn, listing):
    """Every memory operand with a displacement, spills included; lea of a stack slot is a pointer, not a field."""
    out = []
    for ins in listing:
        mem = [o for o in ins.ops if o[0] == 'm' and o[1] is not None and not o[5]]
        if not mem or mem[0][4] == 0 or ins.op == 'nop':
            continue
        at = disp_at(ins, mem[0])
        if at is None:
            continue
        out.append(dict(kind='field', fn=fn, va=ins.va, op=show(ins), patch={ins.va + at: ins.raw[at] ^ 8}))
    return out


def imm_sites(fn, listing):
    out = []
    for ins in listing:
        imm = [o for o in ins.ops if o[0] == 'i']
        if not imm or ins.ops[0] == ('r', R['rsp'], 64):
            continue
        n = 4 if 0xc7 in ins.raw[:2] and ins.ops[0][0] == 'm' and ins.raw[0] != 0x66 else imm_size(ins, imm[0])
        if not n:
            continue
        at = ins.size - n + (4 if n == 8 else 0)  # the low byte of a 64-bit constant is lost in the f64 conversion
        out.append(dict(kind='immediate', fn=fn, va=ins.va, op=show(ins), patch={ins.va + at: ins.raw[at] ^ 1}))
    return out


def constant_sites(fn, listing, img):
    """Bytes of each .rodata constant a subject reads: the top byte of the f64 mantissa side."""
    out = []
    for ins in listing:
        for o in ins.ops:
            if o[0] == 'm' and o[1] is None and o[2] is None and img.in_rodata(o[4], 8) and ins.op in ('ucomisd', 'mulsd', 'movsd'):
                out.append(dict(kind='constant', fn=fn, va=ins.va, op=show(ins), patch={o[4] + 6: img.read(o[4] + 6, 1)[0] ^ 0x10}))
    return out


def try_kill(mctx, picked):
    for pos, v in enumerate(picked):
        try:
            bad = check(mctx, v)
        except (Unmodelled, Panicked, EvidenceError, KeyError, OverflowError, ValueError, TypeError, struct.error, IndexError, MemoryError, ZeroDivisionError, StopIteration, AttributeError) as exc:
            bad = f'fault {type(exc).__name__}'
        if bad:
            picked.insert(0, picked.pop(pos))
            return (v['group'], bad[:60].replace('\t', ' ').replace('\n', ' '))
    return None


def survey_part(args):
    data, code, slots, got, sites, vecs = args
    rows = []
    picked = {HEAD_MAIN: [v for v in vecs if v['copy'] == HEAD_MAIN], DAYS: [v for v in vecs if v['copy'] in (DAYS, HEAD_MAIN)]}
    for s_ in sites:
        mimg = Image(data, s_['patch'])
        mcode = dict(code)
        fn = s_['fn']
        try:
            mcode.update({i.va: i for i in decode_subject(mimg, fn)})
        except (EvidenceError, Unmodelled, IndexError, struct.error) as exc:
            rows.append(dict(s_, killed=('decoder', str(exc)[:60].replace('\t', ' '))))
            continue
        rows.append(dict(s_, killed=try_kill((mimg, mcode, slots, got), picked[fn])))
        if PROGRESS and not rows[-1]['killed']:
            print('survivor', hex(fn), hex(s_['va']), s_['kind'], s_['op'], flush=True)
    return rows


WORKERS = 3
PROGRESS = False


def all_sites(listing, img):
    sites = []
    for fn in SUBJECTS:
        rows = listing[fn]
        sites += conditional_sites(fn, rows) + field_sites(fn, rows) + imm_sites(fn, rows) + constant_sites(fn, rows, img)
    g = gaps()
    stops = {c['stop'] for c in COPIES.values()}
    return [x for x in sites if x['va'] not in stops and not any(a <= x['va'] < b for a, b, _ in g)]


def survey(data, code, slots, got, listing, vecs, img):
    sites = all_sites(listing, img)
    parts = [sites[i::WORKERS] for i in range(WORKERS)]
    jobs = [(data, code, slots, got, p, vecs) for p in parts]
    with multiprocessing.get_context('fork').Pool(WORKERS) as pool:
        got_rows = pool.map(survey_part, jobs)
    rows = [r for part in got_rows for r in part]
    rows.sort(key=lambda r: (SUBJECTS.index(r['fn']), r['va'], r['kind']))
    return rows


# ---- static facts


def slot_users(img, slot, starts):
    """FF 15 call and FF 25 jump sites through `slot`, by byte scan of .text."""
    addr_, off, size = img.sec['.text'][:3]
    blob, out = img.data, []
    for head, kind in ((b'\xff\x15', 'call'), (b'\xff\x25', 'jump')):
        i = blob.find(head, off, off + size)
        while i != -1:
            va = addr_ + i - off
            if va + 6 + struct.unpack_from('<i', blob, i + 2)[0] == slot:
                out.append(dict(kind=kind, site=hex(va), function=hex(starts[bisect.bisect_right(starts, va) - 1])))
            i = blob.find(head, i + 1, off + size)
    return out


def direct_sites(img, targets, starts):
    """Calls to each of `targets`: e8 rel32 in .text, one pass."""
    addr_, off, size = img.sec['.text'][:3]
    blob = img.data
    out = {t: [] for t in targets}
    pack = struct.Struct('<i').unpack_from
    i = blob.find(b'\xe8', off, off + size)
    while i != -1 and i + 5 <= off + size:
        va = addr_ + i - off
        t = va + 5 + pack(blob, i + 1)[0]
        if t in out:
            out[t].append(dict(site=hex(va), function=hex(starts[bisect.bisect_right(starts, va) - 1])))
        i = blob.find(b'\xe8', i + 1, off + size)
    return out


def slots_holding(img, value):
    _, off, size, _ = img.sec['.rela.dyn']
    out = []
    for i in range(0, size - 23, 24):
        slot, info, add = struct.unpack_from('<QQQ', img.data, off + i)
        if info == 8 and add == value:
            out.append(hex(slot))
    return out


def location(img, va):
    """Panic Location: keep the path from `l1/src/` only, plus its full length."""
    start = img.relative(va)
    length = struct.unpack('<Q', img.read(va + 8, 8))[0]
    line, col = struct.unpack('<II', img.read(va + 16, 8))
    path = img.read(start, length).decode('ascii')
    for mark in ('l1/src/', 'chrono-'):
        if mark in path:
            path = path[path.index(mark):]
    return dict(path=path, path_bytes=length, line=line, column=col)


def digest_of(v):
    return hashlib.sha256(repr(sorted((k, repr(x)) for k, x in v.items())).encode()).hexdigest()[:16]


def copy_rows(listing, a, b):
    """Two copies by decoded instruction with code addresses taken out; the rows that differ."""
    def shape(rows, base):
        out = []
        for i in rows:
            parts = []
            for o in i.ops:
                if o[0] == 'm' and o[1] is None and o[2] is None:
                    parts.append('rip')
                elif o[0] == 't':
                    parts.append('target')
                else:
                    parts.append(o)
            out.append((i.va - base, i.op, tuple(parts)))
        return out
    x, y = shape(listing[a], listing[a][0].va), shape(listing[b], listing[b][0].va)
    if len(x) != len(y):
        raise EvidenceError('copy length')
    return [dict(offset=hex(p[0]), a=show(listing[a][k]), b=show(listing[b][k])) for k, (p, q) in enumerate(zip(x, y)) if p != q]


def pinned(img):
    """Constants the model relies on, re-read; any change stops the tool."""
    got_ = dict(one=img.f64(ONE), two63=img.f64(TWO63), mm_cap=img.f64(CAP_MM), high=img.f64(CAP_HIGH))
    if got_ != dict(one=1.0, two63=2.0 ** 63, mm_cap=2.0 ** 64, high=2.0 ** 64 - 2048):
        raise EvidenceError(f'constants {got_}')
    pins = []
    for label, va, text in PINS:
        want = bytes.fromhex(text.replace(' ', ''))
        if img.read(va, len(want)) != want:
            raise EvidenceError(f'pin {label}')
        pins.append(dict(what=label, va=hex(va), bytes=want.hex()))
    return got_, pins


PINS = (
    ('sum of 14 days', 0x26fbe7f, 'ba0e000000'),
    ('sum of 14 days on a dex row', 0x26fc08d, 'ba0e000000'),
    ('dex filter mask', 0x26fbef9, '48b90100040000 10a00c'),
    ('dex filter second range', 0x26fbf09, '4883c094'),
    ('row stride of the dex list', 0x26fbecb, '4869c0f0020000'),
    ('division by 10000', 0x26fc2dc, '49be4b598638d6c56d34'),
)
NAMES = (
    (0x3afa71, 'ntl_cutoff'), (0x3afa7b, 'rates'), (0x3afa80, 'staking_keep_frac_for_referrer'), (0x3afa9e, 'struct VipFees with 3 elements'),
    (0x3af8a7, 'maker_fraction_cutoff'), (0x3af8bc, 'add'), (0x3af8bf, 'struct MmFees with 2 elements'),
    (0x3afb6f, 'vip'), (0x3afb72, 'mm'), (0x3afb74, 'struct FeeTiers with 2 elements'),
    (0x3afd88, 'stake_discount_tiers'), (0x3afd9c, 'weigh_spot_volume_double'), (0x3afdb4, 'aligned_quote_token_config'), (0x3afdce, 'struct FeeSchedule with 9 elements'),
)


def name_rows(img):
    out = []
    for va, want in NAMES:
        text = img.read(va, len(want)).decode('ascii')
        if text != want:
            raise EvidenceError(f'name at {va:#x}')
        out.append(dict(va=hex(va), text=text))
    return out


REFERENCE_ROWS = (
    ('absent', 'references/can1357-hl/l1/fees/compute.rs', 'no tier selection, no vip or mm row', 'the head of 3 row builders picks a vip row and an mm row from 14 prior days of volume'),
    ('partial', 'info_server/abci_state_info_handler.rs FeeTier', 'ntl_cutoff, cross, add, spot_cross, spot_add', 'a vip row is 0x30 bytes: 4 f64 at +0..+0x18, the cutoff at +0x20, then one more f64 at +0x28 that the reference type lacks'),
    ('differs', 'info_server/abci_state_info_handler.rs FeeSchedule', 'one list tiers: Vec<FeeTier>', '2 lists: vip rows at state +0x5d8 and mm rows at +0x5f0; .rodata names struct FeeTiers with fields vip and mm'),
    ('absent', 'references/can1357-hl', 'no MmFees, no maker_fraction_cutoff, no weigh_spot_volume_double', 'all three strings are in .rodata; mm rows are (fraction, rate) pairs read at +0 and +8'),
    ('unverified', 'l1/action/vote_global.rs FeeSchedule', '9 u64 bps fields', 'the node .rodata also says 9 elements but names tiers, referral_discount and other fields; the action decoder was not read here'),
)


def facts_and_files(data, out_dir, img, fdes, listing, vecs, rows, seen, padding, slots):
    constants, pins = pinned(img)
    starts = sorted(f['start'] for f in eh_frame_records(data)[1])
    out_path = Path(out_dir)
    out_path.mkdir(parents=True, exist_ok=True)
    groups, outcomes = {}, {}
    with open(out_path / 'vectors.tsv', 'w', newline='\n') as f:
        f.write('copy\tgroup\tstate\toutcome\n')
        for v in vecs:
            groups[v['group']] = groups.get(v['group'], 0) + 1
            name = outcome_name(v) if v['kind'] == 'head' else v['kind']
            outcomes[name] = outcomes.get(name, 0) + 1
            f.write(f"{v['copy']:#x}\t{v['group']}\t{digest_of(v)}\t{name}\n")
    with open(out_path / 'mutations.tsv', 'w', newline='\n') as f:
        f.write('kind\tfunction\tva\tinstruction\tresult\tvector\treason\n')
        for r in rows:
            k = r['killed']
            f.write(f"{r['kind']}\t{r['fn']:#x}\t{r['va']:#x}\t{r['op']}\t{'killed' if k else 'equivalent'}\t{k[0] if k else ''}\t{k[1] if k else EQUIVALENT[r['va']]}\n")
    with open(out_path / 'instructions.tsv', 'w', newline='\n') as f:
        f.write('function\tva\tsize\tbytes\tdecoded\texecuted\n')
        for fn in listing:
            for i in listing[fn]:
                f.write(f'{fn:#x}\t{i.va:#x}\t{i.size}\t{i.raw.hex()}\t{show(i)}\t{int(i.va in seen)}\n')
    with open(out_path / 'reference-diff.tsv', 'w', newline='\n') as f:
        f.write('verdict\treference\treference_says\tbytes_say\n')
        for row_ in REFERENCE_ROWS:
            f.write('\t'.join(row_) + '\n')
    per = {}
    for fn in listing:
        per[hex(fn)] = dict(pieces=[[hex(a), hex(b)] for a, b in RANGES[fn]], instructions=len(listing[fn]), executed=sum(i.va in seen for i in listing[fn]), fde=hex(fdes.range_of(fn)['fde']), fde_end=hex(FDE_END[fn]))
    targets = (HEAD_MAIN, HEAD_A, HEAD_B, DAYS)
    calls = direct_sites(img, targets, starts)
    evidence = dict(
        binary=BINARY, sha256=SHA256, functions=per, constants=constants, pins=pins, names=name_rows(img),
        copies={f'{a:#x} {b:#x}': len(copy_rows_loose(listing, a, b)) for a, b in ((HEAD_MAIN, HEAD_A), (HEAD_A, HEAD_B))},
        callers={hex(t): calls[t] for t in targets}, allowed_dex_words=list(ALLOWED),
        jump_tables={hex(s): dict(table=hex(c['table']), entries=[hex(x) for x in c['entries']]) for s, c in COPIES.items()},
        slots={hex(s): hex(slots[s]) for s in (SLOT_TRACKER, SLOT_ROW, SLOT_DATE, SLOT_OVERFLOW, SLOT_ONCE, SLOT_PANIC)},
        overflow_location=location(img, QTY_LOCATION), both_location=location(img, BOTH_LOCATION), date_location=location(img, PANIC_LOCATION), panic_text=img.read(PANIC_TEXT, 0x22).decode('ascii'),
        vectors=len(vecs), mismatches=0, groups=groups, outcomes=outcomes, padding_not_executed=padding,
        unexecuted=[dict(start=hex(a), end=hex(b), why=w) for a, b, w in gaps()], not_mutated=[hex(x) for x in NOT_MUTATED],
        mutants=len(rows), killed=sum(1 for r in rows if r['killed']), equivalent={hex(k): w for k, w in sorted(EQUIVALENT.items())},
    )
    with open(out_path / 'evidence.json', 'w', newline='\n') as f:
        json.dump(evidence, f, indent=1, sort_keys=True)
        f.write('\n')
    return evidence


def copy_rows_loose(listing, a, b):
    """Decoded rows of two copies, aligned by operation order, that differ with code addresses taken out."""
    def form(i):
        return (i.op, tuple('rip' if o[0] == 'm' and o[1] is None and o[2] is None else 'target' if o[0] == 't' else o for o in i.ops))
    x, y = [form(i) for i in listing[a]], [form(i) for i in listing[b]]
    return [p for p in set(x) ^ set(y)]


def run_vectors(ctx, vecs):
    for v in vecs:
        try:
            msg = check(ctx, v)
        except (Unmodelled, EvidenceError, KeyError) as exc:
            msg = f'fault {type(exc).__name__} {exc}'
        if msg:
            raise EvidenceError(f"mismatch in {v['group']} {v['copy']:#x}: {msg}: {repr(v)[:400]}")


def generate(data, out_dir, with_survey=True):
    global SEEN
    img, code, fdes, slots, got, listing = build(data)
    ctx = (img, code, slots, got)
    vecs = all_vectors()
    seen = SEEN = set()
    try:
        run_vectors(ctx, vecs)
    finally:
        SEEN = None
    missing, padding = [], 0
    g = gaps()
    stops = {c['stop'] for c in COPIES.values()}
    for fn in listing:
        for ins in listing[fn]:
            if ins.va in seen or ins.va in stops:
                continue
            if ins.op in ('nop', 'int3'):
                padding += 1
            elif not any(a <= ins.va < b for a, b, _ in g):
                missing.append(hex(ins.va))
    if missing:
        raise EvidenceError(f'unlisted unexecuted instructions {len(missing)}: {missing}')
    rows = survey(data, code, slots, got, listing, vecs, img) if with_survey else []
    survivors = {r['va'] for r in rows if not r['killed']}
    if survivors - set(EQUIVALENT) or (rows and set(EQUIVALENT) - survivors):
        raise EvidenceError(f'survivors {sorted(hex(s_) for s_ in survivors ^ set(EQUIVALENT))} of {len(rows)}')
    return facts_and_files(data, out_dir, img, fdes, listing, vecs, rows, seen, padding, slots)


def main():
    ap = argparse.ArgumentParser(description=__doc__.split('\n')[0])
    ap.add_argument('--out', required=True)
    args = ap.parse_args()
    data = (ROOT / BINARY).read_bytes()
    ev = generate(data, args.out)
    print(json.dumps(dict(vectors=ev['vectors'], mutants=ev['mutants'], killed=ev['killed']), sort_keys=True))


if __name__ == '__main__':
    main()
