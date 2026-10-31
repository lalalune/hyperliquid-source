#!/usr/bin/env python3
"""fees: node #94 referral state of one user: needToTrade, needToCreateCode or ready, from bytes alone.

Static, no execution of the node.  The stage builder, the row walker, the row lookup, the B-tree iterators, the row
sort, the 5000 row cap, the approved builder list and the 2 parallel folders are decoded from ELF bytes by the table
decoder below and interpreted in Python on every vector.  Hash, allocator, row core and the long sort are stubs that
check their arguments.  Each outcome is compared with a separate closed-form model, then conditionals, field offsets,
immediates and read constants are mutated.

    python3 tools/fees_referral_state.py --out <dir>

writes evidence.json, vectors.tsv, mutations.tsv, instructions.tsv, reference-diff.tsv and call-sites.tsv.  Section and
FDE parsing come from tools/elf_index.py and tools/fde_extents.py.  Only the standard library is used: no objdump,
readelf or other external program runs, so the results cannot depend on a binutils version.
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
        if b2 in (0x58, 0x5e, 0x6c, 0xeb) and p66:
            reg, rm = modrm(128, True)
            name = {0x58: 'addpd', 0x5e: 'divpd', 0x6c: 'punpcklqdq', 0xeb: 'por'}[b2]
            return done(name, (('x', reg | rr << 3), rm), 128)
        if b2 == 0x73 and p66 and code[i] >> 3 & 7 == 2:
            reg, rm = modrm(128, True)
            return done('psrlq', (rm, imm(1)), 128)
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
        if b2 == 0xc1:
            reg, rm = modrm(width)
            return done('xadd', (rm, gpr(reg | rr << 3, width)))
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
        elif op == 'por':
            self.setx(ops[0], self.x128(ops[0]) | self.x128(ops[1]))
        elif op == 'psrlq':
            a, n = self.x128(ops[0]), ops[1][1] & 0xff
            self.setx(ops[0], sum(((a >> 64 * k & U64) >> n) << 64 * k for k in range(2)))
        elif op == 'punpcklqdq':
            a, b = self.x128(ops[0]), self.x128(ops[1])
            self.setx(ops[0], a & U64 | (b & U64) << 64)
        elif op in ('addpd', 'divpd'):
            a, b = self.x128(ops[0]), self.x128(ops[1])
            res = 0
            for k in range(2):
                p, q = b2f(a >> 64 * k & U64), b2f(b >> 64 * k & U64)
                res |= f2b(p + q if op == 'addpd' else fdiv(p, q)) << 64 * k
            self.setx(ops[0], res)
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
            elif op == 'xadd':
                old, add_ = self.rd(ops[0]), self.rd(ops[1])
                self.wr(ops[0], old + add_)
                self.wr(ops[1], old)
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

def machine(ctx):
    img, code, slots, got = ctx
    m = Machine(img, ())
    if SEEN is not None:
        m.seen = SEEN
    m.code = code
    m.slots = slots
    m.got = dict(got)
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


def need(ok, what):
    if not ok:
        raise Unmodelled(what)



SAVED = ('rbx', 'rbp', 'r12', 'r13', 'r14', 'r15')


def start(m, args):
    r = m.regs
    r[R['rsp']] = m.top
    m.store(m.top, 8, 0xfeedface)
    for name_ in SAVED:
        r[R[name_]] = 0xc0de0000 + R[name_]
    for reg in ('rdi', 'rsi', 'rdx', 'rcx', 'r8', 'r9'):
        r[R[reg]] = 0x5151515151515100 + R[reg]
    for reg, val in args.items():
        r[R[reg]] = val


def finished(m):
    r = m.regs
    return r[R['rsp']] != m.top + 8 or any(r[R[n]] != 0xc0de0000 + R[n] for n in SAVED)



SEEN = None
GOLD = {}

OK_TAG = 1 << 63
TAG_TRADE = OK_TAG
TAG_CREATE = OK_TAG + 1
NICHE = OK_TAG + 2
LIMIT = 1000000
CENTS = 100.0
DEFAULT_REQUIRED = 10000.0
CAP = 5000
ROW_SIZE = 0x50
SMALL_SORT = 0x15
STRIDE = 0xe8
STAGE = 0x2a2b0a0
WALK = 0x2a10940
ROW_GET = 0x2a2c6c0
NEXT = 0x2a0a030
NEXT_TOKEN = 0x330ed70
SORT = 0x2a1ff20
TAKE = 0x2a39bd0
LIST = 0x2a2b5f0
NEXT_LIST = 0x2a0a440
FOLDS = {0x251bf90: dict(tree=0x6d8, tracker=0x5d0), 0x251c680: dict(tree=0x1158, tracker=0x1050)}
WHOLE = (STAGE, WALK, ROW_GET, NEXT, NEXT_TOKEN, SORT, TAKE, LIST, NEXT_LIST) + tuple(FOLDS)
HASH = 0x2a39350
ROW_CORE = 0x2a2a9f0
SLOT_ROW = 0x5775378
SLOT_BIG_SORT = 0x5775380
BIG_SORT = 0x2a40430
SLOT_STAGE = 0x5774598
SLOT_LIST = 0x5774f30
SLOT_GROW = 0x57745a0
GROW_FOLD = 0x454ec40
GROW = 0x2a1e950
DROP_ROW = 0x2a0f200
DROP_ITER = 0x2a25360
SLOT_RECORD = 0x5773190
LOC_ADD = 0x56f2138
SLOT_FREE = 0x576e010
SLOT_ALLOC = 0x576dfd8
SLOT_MOVE = 0x576dfe0
SLOT_NONE = 0x576e470
SLOT_ALLOC_ERR = 0x576dfb8
GOT_MEMCMP = 0x576e488
NORETURN = (SLOT_ALLOC_ERR, SLOT_NONE)
OUTER = dict(key=0x320, key_size=20, val=8, val_size=0x48, parent=0, idx=0x3fc, count=0x3fe, kids=0x400, size=0x400)
JOINED = dict(key=8, key_size=20, val=0xe4, val_size=12, parent=0, idx=0x168, count=0x16a, kids=0x170, size=0x170)
TOKENS = dict(key=0x218, key_size=8, val=0, val_size=0x30, parent=0x210, idx=0x270, count=0x272, kids=0x278, size=0x278)
BUILDERS = dict(key=0x60, key_size=20, val=8, val_size=8, parent=0, idx=0x13c, count=0x13e, kids=0x140, size=0x140)


class Panicked(Exception):
    """The node would panic here; a modelled outcome, unlike Unmodelled."""


def bytes_fast(self, addr, size):
    a = self.find(addr, size)
    if a is None or not size:
        return bytes(self.load(addr + k, 1) for k in range(size))
    o = addr - a.base
    if a.strict and not all(a.valid[o:o + size]):
        raise Unmodelled(f'read of unset bytes at {addr:#x}')
    return bytes(a.mem[o:o + size])


def store_fast(self, addr, blob):
    a = self.find(addr, max(len(blob), 1))
    if a is None:
        raise Unmodelled(f'store {addr:#x}')
    o = addr - a.base
    a.mem[o:o + len(blob)] = blob
    a.valid[o:o + len(blob)] = b'\1' * len(blob)


Machine.bytes_at = bytes_fast
Machine.store_bytes = store_fast


def filled(m, size, seed):
    a = m.arena(size)
    a.mem[:] = fill_bytes(size, seed)
    a.valid[:] = b'\1' * size
    return a


# ---- model, written from the observed rules and independent of the machine


def order_key(bits):
    """f64 total order as an unsigned key: a set sign bit inverts, a clear one sets the top bit."""
    return bits ^ U64 if bits >> 63 else bits | 1 << 63


def rank(rows):
    """Stable, largest total-order value first.  Rows are (key bits, payload)."""
    return sorted(rows, key=lambda r: order_key(r[0]), reverse=True)


def volume(words):
    """Saturating sum in key order, and how many adds overflowed."""
    total, carries = 0, 0
    for w in words:
        if total + w > U64:
            carries += 1
            total = U64
        else:
            total += w
    return total, carries


def stage_rule(v):
    """-> dict(tag=..): the three stages, with `required` as an f64 for needToTrade."""
    user = v['user']
    if user in v['profiles']:
        p = v['profiles'][user]
        rows = [(v['sort_keys'][a], a) for a, _ in sorted(p['joined']) if a in v['rows']]
        ordered = rank(rows)
        kept = ordered[:CAP] if v['flag'] & 0xff else ordered
        return dict(tag='ready', code=p['code'], rows=[a for _, a in kept], total=len(rows))
    if user not in v['rows']:
        return dict(tag='trade', required=DEFAULT_REQUIRED, carries=0)
    total, carries = volume(v['rows'][user])
    if total >= LIMIT:
        return dict(tag='create', carries=carries)
    return dict(tag='trade', required=(LIMIT - total) / CENTS, carries=carries)


def list_rule(v):
    return sorted(v['builders'].get(v['user'], ())) if v['user'] in v['rows'] else []


def key_hash(key):
    x = int.from_bytes(key[:8], 'little') * 0x9e3779b97f4a7c15 & U64
    x ^= int.from_bytes(key[8:16], 'little') * 0xc2b2ae3d27d4eb4f & U64
    x = (x ^ x >> 31) * 0xff51afd7ed558ccd & U64
    return x ^ x >> 29


def addr(seed):
    return bytes((seed * 37 + i * 19 + 5 + (seed >> 3) * i) & 0xff for i in range(20))


def time_of(a):
    return bytes(x ^ 0x5c for x in a[:12])


# ---- table and tree builders; they lay out what the code reads and share nothing with the model above


def tree(m, lay, items, height, seed, parent=0, slot=0, stale=None):
    """A node of `lay`.  A node with too few items for two children has no key and one child, so any height is thin."""
    if height == 0:
        seps, kids = items, []
    elif len(items) < 3:
        seps, kids = [], [items]
    else:
        mid = len(items) // 2
        seps, kids = [items[mid]], [items[:mid], items[mid + 1:]]
    if len(seps) > 11:
        raise EvidenceError('leaf too long')
    a = filled(m, lay['size'] + (0x60 if height else 0), seed & 0xff)
    word(a, lay['parent'], 8, parent)
    word(a, lay['idx'], 2, slot)
    word(a, lay['count'], 2, len(seps))
    for i, (k, val) in enumerate(seps):
        a.mem[lay['key'] + i * lay['key_size']:lay['key'] + (i + 1) * lay['key_size']] = k
        a.mem[lay['val'] + i * lay['val_size']:lay['val'] + (i + 1) * lay['val_size']] = val
    if stale is not None and len(seps) < 11:
        i = len(seps)
        a.mem[lay['key'] + i * lay['key_size']:lay['key'] + (i + 1) * lay['key_size']] = stale[0]
        a.mem[lay['val'] + i * lay['val_size']:lay['val'] + (i + 1) * lay['val_size']] = stale[1]
    for i, c in enumerate(kids):
        word(a, lay['kids'] + i * 8, 8, tree(m, lay, c, height - 1, seed + i + 1, a.base, i).base)
    return a


def leaves_needed(items):
    return max(1, (len(items) + 10) // 11)


def height_for(items, want):
    """`want` when the items fit, more when a single spine would overflow a leaf."""
    h = want
    while len(items) > 11 * 2 ** h + 2 ** h - 1:
        h += 1
    return h


def write_tree(m, row, off, lay, items, height, seed, length=None, stale=None):
    """root, height, length at row+off; a null root when there are no items and no height."""
    if not items and not height:
        word(row, off, 8, 0)
        word(row, off + 8, 8, 0x5a5a)
        word(row, off + 0x10, 8, 0)
        return None
    h = height_for(items, height)
    root = tree(m, lay, sorted(items), h, seed, stale=stale)
    word(row, off, 8, root.base)
    word(row, off + 8, 8, h)
    word(row, off + 0x10, 8, len(items) if length is None else length)
    return root


def write_table(m, tracker, keys, decoys, seed, first=False, size=32):
    """hashbrown table at tracker +0xc0: ctrl, mask, growth, items; 0xe8-byte items below ctrl; tombstones in empty slots."""
    n = size
    while n * 7 // 8 <= len(keys) + len(decoys) + 1:
        n *= 2
    ctrl = bytearray(b'\xff' * (n + 16))
    block = filled(m, n * STRIDE + n + 16, seed)
    at = block.base + n * STRIDE
    ends = {}
    own = [(k, None) for k in keys]
    for key, clash in list(decoys) + own if first else own + list(decoys):
        h = key_hash(clash if clash is not None else key)
        pos, step = h & (n - 1), 0
        while True:
            free = [(pos + k) & (n - 1) for k in range(16) if ctrl[(pos + k) & (n - 1)] & 0x80]
            if free:
                break
            step += 16
            pos = (pos + step) & (n - 1)
        i = free[0]
        ctrl[i] = h >> 57
        if i < 16:
            ctrl[n + i] = h >> 57
        slot = n * STRIDE - (i + 1) * STRIDE
        block.mem[slot:slot + 20] = key
        ends[key] = slot + STRIDE
    for i in range(n):
        if ctrl[i] == 0xff and i % 5 == 3:
            ctrl[i] = 0x80
            if i < 16:
                ctrl[n + i] = 0x80
    block.mem[n * STRIDE:n * STRIDE + n + 16] = ctrl
    word(tracker, 0xc0, 8, at)
    word(tracker, 0xc8, 8, n - 1)
    word(tracker, 0xd8, 8, len(keys) + len(decoys))
    return block, ends, at


# ---- machine set-up


def base_machine(ctx):
    m = machine(ctx)
    slots = ctx[2]
    m.freed = []
    m.moved = []
    m.alloc = []
    m.carries = 0
    m.fail_alloc = None
    m.failed = None
    r = m.regs

    def memcmp():
        need(r[R['rdx']] == 20, 'memcmp length')
        a, b = m.bytes_at(r[R['rdi']], 20), m.bytes_at(r[R['rsi']], 20)
        m.clobber(0 if a == b else (1 if a > b else U64))

    def alloc():
        size = r[R['rdi']]
        need(0 < size < 1 << 24, 'allocation size')
        m.alloc.append(size)
        if m.fail_alloc == size:
            m.clobber(0)
            return
        m.clobber(m.arena(size).base)

    def move():
        d, s, n = r[R['rdi']], r[R['rsi']], r[R['rdx']]
        need(n < 1 << 24, 'move size')
        if n:
            m.store_bytes(d, m.bytes_at(s, n))
        m.moved.append(n)
        m.clobber(d)

    def no_value():
        raise Panicked('none')

    def alloc_failed():
        m.failed = (r[R['rdi']], r[R['rsi']])
        raise Panicked('allocation')

    def record():
        need(r[R['rdi']] == 0 and r[R['rsi']] == LOC_ADD, 'recorder arguments')
        m.carries += 1
        m.clobber()

    for slot, stub in ((GOT_MEMCMP, memcmp), (SLOT_ALLOC, alloc), (SLOT_MOVE, move), (SLOT_NONE, no_value), (SLOT_ALLOC_ERR, alloc_failed), (SLOT_RECORD, record)):
        if slot in slots:
            m.stubs[slots[slot]] = stub
    return m


def add_hash(m, tracker):
    r = m.regs

    def hash_stub():
        need(r[R['rdi']] == tracker.base + 0xe0, 'hasher state')
        m.clobber(key_hash(m.bytes_at(r[R['rsi']], 20)))

    m.stubs[HASH] = hash_stub


def row_bytes(a, bits):
    blob = bytearray(fill_bytes(ROW_SIZE, a[0] & 0x7f))
    blob[8:16] = bits.to_bytes(8, 'little')
    blob[0x38:0x4c] = a
    return bytes(blob)


def run_call(m, fn):
    m.run(fn)
    if finished(m):
        raise Unmodelled('stack or saved registers not restored')


def grow_vec(m, holder, length, size):
    """Doubling reserve: cap, ptr at holder, old bytes moved."""
    cap = m.load(holder, 8)
    need(cap == length, 'grow below capacity')
    new = max(cap * 2, 4)
    fresh = m.arena(new * size)
    if cap:
        m.store_bytes(fresh.base, m.bytes_at(m.load(holder + 8, 8), length * size))
    m.store(holder, 8, new)
    m.store(holder + 8, 8, fresh.base)


def write_state(m, v, seed):
    """tracker with row table and referrer tree, token table of the row core, user cell."""
    tracker = filled(m, 0x180, seed)
    spot = filled(m, 0x40, seed + 1)
    rows = sorted(v['rows'])
    block, ends, at = write_table(m, tracker, rows, v.get('decoys', ()), seed + 2, v.get('first', False), v.get('table_n', 32)) if rows or v.get('decoys') else (None, {}, 0)
    if not rows and not v.get('decoys'):
        word(tracker, 0xd8, 8, 0)
    bad = v.get('short')
    for i, a in enumerate(rows):
        e = ends[a]
        write_tree(m, block, e - 0x38, TOKENS, [(k.to_bytes(8, 'little'), w.to_bytes(8, 'little') + fill_bytes(0x28, 0x21)) for k, w in zip(v.get('token_keys') or range(1, 1 + len(v['rows'][a])), v['rows'][a])], v.get('token_height', 0), (seed + i + 7) & 0xff, length=len(v['rows'][a]) + (bad or 0))
        write_tree(m, block, e - 0x50, BUILDERS, [(b, bytes(8)) for b in v.get('builders', {}).get(a, ())], v.get('builder_height', 0), (seed + i + 9) & 0xff, length=v.get('builder_length'))
    outer = []
    for a, p in sorted(v['profiles'].items()):
        val = bytearray(fill_bytes(0x48, 0x41))
        blob = m.arena(max(len(p['code']), 1))
        blob.mem[:len(p['code'])] = p['code']
        blob.valid[:] = b'\1' * blob.size
        word_at = dict(ptr=8, len=0x10)
        val[word_at['ptr']:word_at['ptr'] + 8] = blob.base.to_bytes(8, 'little')
        val[word_at['len']:word_at['len'] + 8] = len(p['code']).to_bytes(8, 'little')
        holder = filled(m, 0x48, 0x43)
        write_tree(m, holder, 0x20, JOINED, [(u, time_of(u)) for u, _ in sorted(p['joined'])], p.get('height', 0), (seed + 11) & 0xff, length=len(p['joined']) + (bad or 0))
        val[0x20:0x38] = bytes(holder.mem[0x20:0x38])
        outer.append((a, bytes(val)))
    return tracker, spot, block, ends, outer, at


def check_stage(ctx, v):
    m = base_machine(ctx)
    seed = 0x31 + len(v['group'])
    tracker, spot, block, ends, outer, at = write_state(m, v, seed)
    write_tree(m, tracker, 0x108, OUTER, outer, v.get('outer_height', 0), seed + 13, stale=(v['user'], fill_bytes(0x48, 0x45)) if v.get('stale') else None)
    word(tracker, 0x118, 8, 0x5a5a)
    add_hash(m, tracker)
    cell = m.arena(20)
    cell.mem[:] = v['user']
    cell.valid[:] = b'\1' * 20
    out = filled(m, 0x38, 0x6d)
    m.fail_alloc = v.get('fail_alloc')
    r = m.regs
    made, dropped, drops = [], [], []
    keys = v['sort_keys']

    def core():
        need(r[R['rcx']] == block.base + ends[m.bytes_at(r[R['rdx']], 20)] - 0xe8 + 0x18, 'row core bucket')
        need(r[R['r8']] == spot.base, 'row core context')
        a = m.bytes_at(r[R['rdx']], 20)
        need(m.bytes_at(r[R['rsi']], 12) == time_of(a), 'row core time')
        m.store_bytes(r[R['rdi']], row_bytes(a, keys[a]))
        made.append(a)
        m.clobber()

    def big_sort():
        p, n = r[R['rdi']], r[R['rsi']]
        need(n >= SMALL_SORT and r[R['rdx']] == r[R['rsp']] + 0x50, 'big sort arguments')
        rows = [m.bytes_at(p + i * ROW_SIZE, ROW_SIZE) for i in range(n)]
        pairs = rank([(int.from_bytes(x[8:16], 'little'), x) for x in rows])
        m.store_bytes(p, b''.join(x for _, x in pairs))
        m.clobber()

    def grow():
        need((r[R['rdx']], r[R['rcx']], r[R['r8']]) == (1, 8, ROW_SIZE), 'grow arguments')
        grow_vec(m, r[R['rdi']], r[R['rsi']], ROW_SIZE)
        m.clobber()

    def fast_walk():
        """Group cap: the row vector comes ready made, so the cap runs without thousands of tree steps."""
        n = v['wide']
        base = m.arena(n * ROW_SIZE)
        for i in range(n):
            base.mem[i * ROW_SIZE:(i + 1) * ROW_SIZE] = bytes(ROW_SIZE)
            word(base, i * ROW_SIZE + 8, 8, 0x4000000000000000 - i)
            word(base, i * ROW_SIZE, 8, i)
        base.valid[:] = b'\1' * base.size
        w = r[R['rdi']]
        m.store(w, 8, n)
        m.store(w + 8, 8, base.base)
        m.store(w + 0x10, 8, n)
        m.clobber(w)
        m.wide = base

    def drop_row():
        drops.append(r[R['rdi']])
        m.clobber()

    def drop_iter():
        dropped.append(r[R['rdi']])
        m.clobber()

    m.stubs[ctx[2].get(SLOT_ROW, ROW_CORE)] = core
    m.stubs[ROW_CORE] = core
    m.stubs[BIG_SORT] = big_sort
    m.stubs[GROW] = grow
    m.stubs[DROP_ROW] = drop_row
    m.stubs[DROP_ITER] = drop_iter
    m.real = {ROW_GET: ROW_GET, NEXT: NEXT, NEXT_TOKEN: NEXT_TOKEN, SORT: SORT, TAKE: TAKE, WALK: WALK}
    if 'wide' in v:
        del m.real[WALK]
        m.stubs[WALK] = fast_walk
    start(m, dict(rdi=out.base, rsi=tracker.base, rdx=cell.base, rcx=spot.base, r8=0xa5a50000 | v['flag']))
    want = stage_rule(v)
    if v.get('short') or 'fail_alloc' in v:
        try:
            run_call(m, STAGE)
        except Panicked:
            return None if m.failed == v.get('fail_args') else f'allocation report {m.failed}'
        return 'no panic'
    run_call(m, STAGE)
    if m.regs[0] != out.base:
        return f'return value {m.regs[0]:#x}'
    if want['tag'] != 'ready' and m.carries != want['carries']:
        return f"recorder calls {m.carries} {want['carries']}"
    w0, w1 = read(out.mem, 0), read(out.mem, 8)
    pattern = fill_bytes(0x38, 0x6d)
    if want['tag'] == 'trade':
        if w0 != TAG_TRADE or w1 != f2b(want['required']):
            return f'stage trade {w0:#x} {w1:#x}'
        if bytes(out.mem[0x10:]) != pattern[0x10:]:
            return 'trade wrote past its field'
        return None
    if want['tag'] == 'create':
        if w0 != TAG_CREATE or bytes(out.mem[8:]) != pattern[8:]:
            return f'stage create {w0:#x}'
        return None
    code = want['code']
    if w0 != len(code) or read(out.mem, 0x10) != len(code):
        return f'code words {w0:#x}'
    if m.bytes_at(w1, len(code)) != code or (not code and w1 != 1):
        return 'code bytes'
    if m.moved != [len(code)] and code:
        return f'moves {m.moved}'
    cap, ptr, ln, total = read(out.mem, 0x18), read(out.mem, 0x20), read(out.mem, 0x28), read(out.mem, 0x30)
    if 'wide' in v:
        n = min(v['wide'], CAP) if v['flag'] & 0xff else v['wide']
        if (ln, total, cap) != (n, v['wide'], v['wide']):
            return f'cap words {ln} {total} {cap}'
        if ptr != m.wide.base or read(m.wide.mem, (n - 1) * ROW_SIZE) != n - 1:
            return 'capped rows'
        if drops != [m.wide.base + i * ROW_SIZE + 0x20 for i in range(n, v['wide'])] if v['flag'] & 0xff else drops:
            return 'dropped rows'
        if bool(v['flag'] & 0xff) != bool(dropped):
            return 'iterator drop'
        return None
    rows = want['rows']
    if (ln, total) != (len(rows), want['total']):
        return f'row counts {ln} {total}'
    if not total and (cap, ptr) != (0, 8):
        return f'empty vector {cap} {ptr:#x}'
    if total:
        if cap < total or ptr == 8:
            return f'vector capacity {cap}'
        if m.bytes_at(ptr, len(rows) * ROW_SIZE) != b''.join(row_bytes(a, keys[a]) for a in rows):
            return 'row order or bytes'
    if sorted(made) != sorted(a for a, _ in v['profiles'][v['user']]['joined'] if a in v['rows']):
        return 'row core calls'
    return None


def check_list(ctx, v):
    m = base_machine(ctx)
    tracker, _, block, ends, _, _ = write_state(m, v, 0x37)
    add_hash(m, tracker)
    cell = m.arena(20)
    cell.mem[:] = v['user']
    cell.valid[:] = b'\1' * 20
    out = filled(m, 0x18, 0x6e)
    m.fail_alloc = v.get('fail_alloc')
    m.real = {NEXT_LIST: NEXT_LIST}
    start(m, dict(rdi=out.base, rsi=tracker.base, rdx=cell.base))
    if 'fail_alloc' in v or v.get('builder_length', 0) > 1 << 40 or v['group'] == 'short':
        try:
            run_call(m, LIST)
        except Panicked:
            return None if m.failed == v.get('fail_args') else f'allocation report {m.failed}'
        return 'no panic'
    run_call(m, LIST)
    want = list_rule(v)
    cap, ptr, ln = read(out.mem, 0), read(out.mem, 8), read(out.mem, 0x10)
    if m.regs[0] != out.base or cap != len(want) or ln != len(want):
        return f'list words {cap} {ln}'
    if not want and ptr != 1:
        return f'empty list {ptr:#x}'
    if m.alloc != ([len(want) * 20] if want else []):
        return f'list allocation {m.alloc}'
    if want and m.bytes_at(ptr, len(want) * 20) != b''.join(want):
        return 'list bytes'
    return None


def check_sort(ctx, v):
    m = base_machine(ctx)
    n = len(v['keys'])
    a = m.arena(max(n * ROW_SIZE, 1))
    rows = [(k, bytes(fill_bytes(ROW_SIZE, i * 3 + 1))) for i, k in enumerate(v['keys'])]
    for i, (k, b) in enumerate(rows):
        a.mem[i * ROW_SIZE:(i + 1) * ROW_SIZE] = b
        word(a, i * ROW_SIZE + 8, 8, k)
    a.valid[:] = b'\1' * a.size
    start(m, dict(rdi=a.base, rsi=n, rdx=1, rcx=0x7777))
    run_call(m, SORT)
    want = rank([(k, i) for i, (k, _) in enumerate(rows)])
    for pos, (k, i) in enumerate(want):
        blob = bytearray(rows[i][1])
        blob[8:16] = k.to_bytes(8, 'little')
        if bytes(a.mem[pos * ROW_SIZE:(pos + 1) * ROW_SIZE]) != bytes(blob):
            return f'sorted row {pos}'
    return None


def check_take(ctx, v):
    m = base_machine(ctx)
    n, k, skip = v['n'], v['take'], v.get('skip', 0)
    a = m.arena(max(n * ROW_SIZE, 1))
    for i in range(n):
        a.mem[i * ROW_SIZE:(i + 1) * ROW_SIZE] = fill_bytes(ROW_SIZE, i * 5 + 3)
    a.valid[:] = b'\1' * a.size
    it = filled(m, 0x28, 0x71)
    cap = n + v.get('spare', 0)
    for off, val in ((0, a.base), (8, a.base + skip * ROW_SIZE), (0x10, cap), (0x18, a.base + n * ROW_SIZE), (0x20, k)):
        word(it, off, 8, val)
    out = filled(m, 0x18, 0x72)
    dropped, drops = [], []
    r = m.regs

    def drop_row():
        drops.append(r[R['rdi']])
        m.clobber()

    def drop_iter():
        dropped.append(r[R['rdi']])
        m.clobber()

    m.stubs[DROP_ROW] = drop_row
    m.stubs[DROP_ITER] = drop_iter
    start(m, dict(rdi=out.base, rsi=it.base))
    run_call(m, TAKE)
    kept = min(n - skip, k)
    if m.regs[0] != out.base or (read(out.mem, 0), read(out.mem, 8), read(out.mem, 0x10)) != (cap, a.base, kept):
        return 'take result'
    if drops != [a.base + i * ROW_SIZE + 0x20 for i in range(skip + kept, n)]:
        return f'take drops {len(drops)}'
    if dropped != [it.base]:
        return 'take iterator'
    if [read(it.mem, o) for o in (0, 8, 0x10, 0x18)] != [8, 8, 0, 8]:
        return 'take left the source'
    for i in range(kept):
        if bytes(a.mem[i * ROW_SIZE:(i + 1) * ROW_SIZE]) != fill_bytes(ROW_SIZE, (i + skip) * 5 + 3):
            return 'take row bytes'
    return None


def check_fold(ctx, v):
    m = base_machine(ctx)
    d = FOLDS[v['fn']]
    state = filled(m, d['tree'] + 0x40, 0x73)
    outer = [(a, fill_bytes(0x48, 0x41)) for a in v['members']]
    write_tree(m, state, d['tree'], OUTER, outer, v.get('outer_height', 0), 0x51)
    p1 = m.arena(8)
    word(p1, 0, 8, state.base)
    p1.valid[:] = b'\1' * 8
    p2 = m.arena(8)
    word(p2, 0, 8, p1.base)
    p2.valid[:] = b'\1' * 8
    items = filled(m, max(len(v['users']), 1) * 0x10, 0x74)
    cells = []
    for i, u in enumerate(v['users']):
        c = m.arena(20)
        c.mem[:] = u
        c.valid[:] = b'\1' * 20
        cells.append(c)
        word(items, i * 0x10, 8, c.base)
    fold = filled(m, 0x20, 0x75)
    start_ptr = 8
    word(fold, 0, 8, 0)
    word(fold, 8, 8, start_ptr)
    word(fold, 0x10, 8, 0)
    word(fold, 0x18, 8, p2.base)
    out = filled(m, 0x20, 0x76)
    r = m.regs
    calls = []

    def stage_stub():
        u = m.bytes_at(r[R['rdx']], 20)
        need(r[R['rsi']] == state.base + d['tracker'] and r[R['rcx']] == state.base + 0x90, 'stage arguments')
        need(r[R['r8']] & 0xffffffff == 0, 'stage flag')
        calls.append(u)
        p = r[R['rdi']]
        m.store(p, 8, NICHE if u in v.get('none', ()) else u[0] + 1)
        for i in range(6):
            m.store(p + 8 + i * 8, 8, int.from_bytes(u[i:i + 8], 'little'))
        m.clobber()

    def grow():
        grow_vec(m, r[R['rdi']], m.load(r[R['rdi']] + 0x10, 8), ROW_SIZE)
        m.clobber()

    m.stubs[ctx[2].get(SLOT_STAGE, SLOT_STAGE)] = stage_stub
    m.stubs[ctx[2].get(SLOT_GROW, SLOT_GROW)] = grow
    start(m, dict(rdi=out.base, rsi=items.base, rdx=len(v['users']), rcx=fold.base))
    run_call(m, v['fn'])
    want_calls = [u for u in v['users'] if u in v['members']]
    if calls != want_calls:
        return f'stage calls {len(calls)}'
    kept = [u for u in want_calls if u not in v.get('none', ())]
    if m.regs[0] != out.base or read(out.mem, 0x10) != len(kept) or read(out.mem, 0x18) != p2.base:
        return f'fold words {read(out.mem, 0x10)}'
    ptr = read(out.mem, 8)
    if not kept:
        return None if ptr == 8 else 'empty fold'
    for i, u in enumerate(kept):
        at = ptr + i * ROW_SIZE
        if m.bytes_at(at, 20) != u or m.load(at + 0x18, 8) != u[0] + 1:
            return f'fold row {i}'
        for k in range(6):
            if m.load(at + 0x20 + k * 8, 8) != int.from_bytes(u[k:k + 8], 'little'):
                return f'fold word {i} {k}'
    return None


CHECKS = dict(stage=check_stage, list=check_list, sort=check_sort, take=check_take, fold=check_fold)


def check(ctx, v):
    return CHECKS[v['kind']](ctx, v)


# ---- vectors


A = addr(1)
PROBES = (2, 3, 14, 15, 16, 17, 30, 31, 32, 33, 46, 47, 48, 49)
PRIMES = (0x4059000000000000, 0x4024000000000000, 0xc024000000000000, 0, 1 << 63, 0x7ff0000000000000, 0xfff0000000000000, 0x7ff8000000000000, 0xfff8000000000000, 1, 0x8000000000000001, 0x3ff0000000000000)


def spread(n, seed=0):
    return sorted({addr(seed * 977 + i * 3 + 5) for i in range(n)})


def stage(group, user=A, rows=None, profiles=None, flag=0, sort_keys=None, **kw):
    return dict(kind='stage', group=group, user=user, rows=rows or {}, profiles=profiles or {}, flag=flag, sort_keys=sort_keys or {}, **kw)


def ready(group, n, seed=1, have=None, flag=0, height=0, outer=None, code=b'CODE7', keyset=None, outer_height=0, **kw):
    users = spread(n, seed)
    outer = outer or []
    joined = [(u, 0) for u in users]
    rows = {u: [5] for u in users if have is None or have(users.index(u))}
    keys = {u: (keyset or PRIMES)[i % len(keyset or PRIMES)] for i, u in enumerate(users)}
    profiles = {A: dict(code=code, joined=joined, height=height)}
    for o in outer:
        profiles[o] = dict(code=b'x', joined=[], height=0)
    return stage(group, rows=rows, profiles=profiles, flag=flag, sort_keys=keys, outer_height=outer_height, **kw)


def stage_vectors():
    joined_one = spread(1, 1)[0]
    out = [stage('no_table'), stage('no_table', rows={addr(2): [1]})]
    for w in (0, 1, 2, 99, 100, 101, 999998, 999999, 1000000, 1000001, 1 << 40, U64):
        out.append(stage('one_word', rows={A: [w]}))
    for n in (0, 1, 2, 3, 7, 8, 9, 11):
        out.append(stage('many_words', rows={A: [10 * (i + 1) for i in range(n)]}))
    for ws in ([500000, 499999], [500000, 500000], [999999, 1], [U64, 1], [U64, 1, 1], [U64 - 1, 1], [U64, U64, 5], [1, U64], [0, 0, 0]):
        for h in (0, 1):
            out.append(stage('sum_edges', rows={A: ws}, token_height=h))
    for h in (1, 2, 3, 7, 8, 9, 10, 16, 17):
        out.append(stage('token_height', rows={A: [1000 + i for i in range(5)]}, token_height=h))
        out.append(stage('token_height', rows={A: [400000, 300000, 300001]}, token_height=h))
    decoys = [(addr(300 + i), A) for i in range(34)]
    out.append(stage('clash', rows={A: [7]}, decoys=decoys))
    out.append(stage('clash', rows={}, decoys=decoys))
    out.append(stage('clash', rows={A: [7]}, decoys=[(addr(401), None), (addr(402), None)]))
    for i in range(8):
        out.append(stage('clash', user=addr(500 + i), rows={A: [1]}, decoys=[(addr(600 + k), addr(500 + i)) for k in range(4 + i * 7)]))
    other = spread(6, 9)
    for h in (0, 1, 2, 5):
        out.append(stage('outer_miss', rows={A: [3]}, profiles={u: dict(code=b'y', joined=[], height=0) for u in other}, outer_height=h))
    for n in (0, 1, 2, 3, 4, 5, 6, 8, 9, 12, 16, 17, 20):
        out.append(ready('ready_count', n))
    for n in (21, 22, 33):
        out.append(ready('big_sort', n))
    for h in (1, 2, 3, 4, 7, 8, 9, 10, 15, 16, 17):
        out.append(ready('joined_height', 9, height=h))
        out.append(ready('joined_height', 3, height=h, have=lambda i: i != 0))
    for h in (0, 1, 3):
        for mask in (1, 2, 3, 5):
            out.append(ready('holes', 8, height=h, have=lambda i, q=mask: i % (q + 1) != 0))
    out.append(ready('holes', 6, have=lambda i: False))
    out.append(ready('holes', 4, have=lambda i: i == 0))
    out.append(ready('holes', 7, have=lambda i: i < 6))
    out.append(ready('holes', 5, have=lambda i: i < 4, height=1))
    joined = spread(3, 1)
    out.append(ready('clash', 3, decoys=[(addr(700 + i), joined[i % 3]) for i in range(40)]))
    out.append(ready('clash', 3, decoys=[(addr(760 + i), joined[0]) for i in range(40)], have=lambda i: i != 0))
    for code in (b'', b'a', b'R' * 20, bytes(range(1, 40))):
        out.append(ready('code', 2, code=code))
    side = spread(6, 11)
    for h in (1, 2, 4):
        out.append(ready('outer_hit', 3, outer=[x for x in side], outer_height=h))
    for flag in (1, 2, 0x80, 0x100, 0xff00):
        out.append(ready('flag', 4, flag=flag))
        out.append(ready('flag', 24, flag=flag))
    for wide, flag in ((4999, 1), (5000, 1), (5001, 1), (5002, 1), (5001, 0), (5001, 0x100), (6000, 3)):
        k = stage('cap', rows={}, profiles={A: dict(code=b'wide', joined=[], height=0)}, flag=flag, wide=wide)
        out.append(k)
    out.append(ready('short', 3, short=1))
    out.append(ready('short', 5, short=1, height=2))
    out.append(ready('short', 1, short=2, height=1))
    out.append(ready('short', 0, short=1, height=1))
    out.append(stage('short', rows={A: [1, 2]}, short=1))
    out.append(stage('short', rows={A: [1, 2, 3, 4]}, short=2, token_height=1))
    out.append(ready('alloc', 1, fail_alloc=0x140, fail_args=(8, 0x140)))
    out.append(ready('alloc', 1, code=b'abcdef', fail_alloc=6, fail_args=(1, 6)))
    high = bytes(range(200, 220))
    low = sorted(u for u in spread(200, 5) if u < high)
    for n in (1, 2, 5, 10):
        out.append(stage('stale', user=high, rows={high: [3]}, profiles={u: dict(code=b'y', joined=[], height=0) for u in low[:n]}, stale=True))
    out.append(ready('two', 2, keyset=(1, 1 << 62)))
    out.append(ready('two', 2, keyset=(1 << 62, 1)))
    for c in PROBES:
        out.append(stage('probe', rows={A: [7]}, decoys=[(addr(900 + i), A) for i in range(c)], first=True, table_n=128))
        out.append(ready('probe', 1, decoys=[(addr(1000 + i), joined_one) for i in range(c)], first=True, table_n=128))
    return out


def list_vectors():
    out = [dict(kind='list', group='no_table', user=A, rows={}, profiles={}, builders={})]
    b = spread(40, 3)
    out.append(dict(kind='list', group='miss', user=A, rows={addr(2): [1]}, profiles={}, builders={addr(2): b[:3]}))
    for n in (0, 1, 2, 3, 5, 7, 8, 9, 11, 12, 23):
        out.append(dict(kind='list', group='count', user=A, rows={A: [1]}, profiles={}, builders={A: b[:n]}))
    for h in (1, 2, 3, 4, 7, 8, 9, 10, 15, 16, 17):
        out.append(dict(kind='list', group='height', user=A, rows={A: [1]}, profiles={}, builders={A: b[:7]}, builder_height=h))
    out.append(dict(kind='list', group='clash', user=A, rows={A: [1]}, profiles={}, builders={A: b[:2]}, decoys=[(addr(300 + i), A) for i in range(34)]))
    out.append(dict(kind='list', group='clash', user=A, rows={}, profiles={}, builders={}, decoys=[(addr(300 + i), A) for i in range(34)]))
    out.append(dict(kind='list', group='alloc', user=A, rows={A: [1]}, profiles={}, builders={A: b[:3]}, fail_alloc=60, fail_args=(1, 60)))
    for n in (60, 61):
        out.append(dict(kind='list', group='overflow', user=A, rows={A: [1]}, profiles={}, builders={A: b[:3]}, builder_length=1 << n, fail_args=(0, ((1 << n) * 20) & U64)))
    out.append(dict(kind='list', group='short', user=A, rows={A: [1]}, profiles={}, builders={A: b[:2]}, builder_length=3))
    out.append(dict(kind='list', group='short', user=A, rows={A: [1]}, profiles={}, builders={A: b[:3]}, builder_length=5, builder_height=1))
    for c in PROBES:
        out.append(dict(kind='list', group='probe', user=A, rows={A: [1]}, profiles={}, builders={A: b[:2]}, decoys=[(addr(1100 + i), A) for i in range(c)], first=True, table_n=128))
    return out


def sort_vectors():
    out = []
    rng = random.Random(0x5041)
    for n in (1, 2, 3, 4, 5, 8, 20):
        for _ in range(6):
            out.append(dict(kind='sort', group='random', keys=[PRIMES[rng.randrange(len(PRIMES))] for _ in range(n)]))
    for keys in (list(PRIMES), list(reversed(PRIMES)), sorted(PRIMES), [0, 1 << 63], [1 << 63, 0], [5, 5, 5], [0x4059000000000000] * 3):
        out.append(dict(kind='sort', group='edges', keys=keys))
    for _ in range(8):
        out.append(dict(kind='sort', group='bits', keys=[rng.getrandbits(64) for _ in range(9)]))
    return out


def take_vectors():
    out = []
    for n, k in ((0, 0), (0, 3), (1, 0), (1, 1), (1, 2), (2, 1), (3, 2), (3, 3), (3, 5), (9, 4), (9, 8), (9, 9), (9, 10), (6, 1)):
        out.append(dict(kind='take', group='take', n=n, take=k))
        out.append(dict(kind='take', group='take_spare', n=n, take=k, spare=7))
    for n, k, skip in ((3, 2, 1), (3, 1, 2), (4, 9, 1), (5, 0, 1), (3, 3, 3)):
        out.append(dict(kind='take', group='take_skip', n=n, take=k, skip=skip))
    return out


def fold_vectors():
    out = []
    u = spread(24, 2)
    for fn in FOLDS:
        for n in (0, 1, 2, 3, 7, 8, 9, 15, 16, 17):
            out.append(dict(kind='fold', group='no_tree', fn=fn, users=u[:n], members=[]))
        out.append(dict(kind='fold', group='none', fn=fn, users=u[:3], members=u[:3], none=[u[1]]))
        out.append(dict(kind='fold', group='none', fn=fn, users=u[:3], members=u[:3], none=list(u[:3])))
        out.append(dict(kind='fold', group='none', fn=fn, users=u[:7], members=u[:7], none=[u[0], u[6]]))
        for h in (0, 1, 2, 3):
            out.append(dict(kind='fold', group='members', fn=fn, users=u[:10], members=u[::2], outer_height=h))
            out.append(dict(kind='fold', group='members', fn=fn, users=u[:10], members=u[1::3], outer_height=h))
            out.append(dict(kind='fold', group='members', fn=fn, users=u, members=u, outer_height=max(h, 1)))
        out.append(dict(kind='fold', group='members', fn=fn, users=[u[0], u[0], u[1]], members=u[:1]))
        out.append(dict(kind='fold', group='members', fn=fn, users=u[:6], members=u[6:9]))
    return out


def all_vectors():
    return stage_vectors() + list_vectors() + sort_vectors() + take_vectors() + fold_vectors()


# ---- image set-up


FDE_END = {}
RANGES = {}


def bind_fdes(data):
    fdes = Fdes(data)
    for s in WHOLE:
        FDE_END[s] = fdes.range_of(s)['end']
        RANGES[s] = ((s, FDE_END[s]),)
    return fdes


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


def decode_subject(img, s):
    out = []
    for a, b in RANGES[s]:
        out += decode_range(img, a, b)
    return out


def build(data):
    check_digest(data)
    fdes = bind_fdes(data)
    img = Image(data)
    code = {}
    for s in RANGES:
        code.update({i.va: i for i in decode_subject(img, s)})
    slots, got = scan_slots(img, code)
    return img, code, fdes, slots, got


# ---- mutation survey


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
        out.append(dict(kind='immediate', fn=fn, va=ins.va, op=show(ins), patch={ins.va + ins.size - n: ins.raw[-n] ^ 1}))
    return out


def constant_sites(fn, listing, img):
    """Bytes of each .rodata f64 a subject reads: the top byte of the mantissa side."""
    out = []
    for ins in listing:
        for o in ins.ops:
            if o[0] == 'm' and o[1] is None and o[2] is None and img.in_rodata(o[4], 8) and ins.op in ('movq', 'movsd', 'divsd'):
                out.append(dict(kind='constant', fn=fn, va=ins.va, op=show(ins), patch={o[4] + 6: img.read(o[4] + 6, 1)[0] ^ 0x10}))
    return out


SUBJECTS = WHOLE
PAD = 'landing pad of an unwind; no vector panics through a live frame here'
AFTER = 'code after a call that does not return'
DEAD_JUMP = 'jump after a test that cannot fail: a non-zero height with low 3 bits clear is at least 8'
_R = (
    (0x251c297, 0x251c2d8, PAD), (0x251c987, 0x251c9c8, PAD), (0x2a2b5b6, 0x2a2b5ef, PAD), (0x2a2b827, 0x2a2b851, PAD), (0x2a39d11, 0x2a39d5c, PAD), (0x2a10e28, 0x2a10e6e, PAD),
    (0x2a0a208, 0x2a0a20d, DEAD_JUMP), (0x2a0a60c, 0x2a0a611, DEAD_JUMP), (0x330ef55, 0x330ef5a, DEAD_JUMP),
    (0x2a0a21a, 0x2a0a22b, AFTER), (0x2a0a229, 0x2a0a22b, AFTER), (0x2a0a61e, 0x2a0a62f, AFTER), (0x330ef67, 0x330ef78, AFTER), (0x2a10e05, 0x2a10e07, AFTER), (0x2a10e14, 0x2a10e16, AFTER), (0x2a10e26, 0x2a10e28, AFTER), (0x2a2b59e, 0x2a2b5a0, AFTER),
    (0x2a0a21c, 0x2a0a229, 'front handle is always set: the walker builds a tag of 1'), (0x2a0a620, 0x2a0a62d, 'front handle is always set: the walker builds a tag of 1'), (0x330ef69, 0x330ef76, 'front handle is always set: the caller builds a tag of 1'),
    (0x2a10b20, 0x2a10bbb, 'lazy descent of the walker loop: the first next call already set the leaf handle'), (0x2a10cee, 0x2a10d00, 'second half of the lazy descent above'), (0x2a10e07, 0x2a10e14, 'front handle is always set after the first next call'),
    (0x2a20083, 0x2a20085, 'offset 0 or past the end: the only caller passes 1 with a length of at least 2'),
    (0x2a2b4f0, 0x2a2b4f2, 'the iterator hands a value pointer with every key'), (0x2a2b4fb, 0x2a2b4fb, ''),
)
UNEXECUTED = {i: r for i, r in enumerate(x for x in _R if x[2])}
BROADCAST = 'the low 8 bytes of the register are equal bytes, so dword 0 and dword 1 are the same'
BACK_HALF = 'the back end of the range iterator: a forward walk never reads it'
CLOSURE = 'the comparator closure pointer: the short sort ignores it and the comparator holds no state'
LOW_BITS = 'the path holds a height with low 3 bits set, so 8 and 9 give the same branch'
KEY_POINTER = 'the key pointer of the iterator is only tested against 0'
UNWIND = 'drop guard or source progress for an unwind; overwritten or unread on a normal return'
REPEAT = 'the main loop tests the same root again and skips every item, so the early test only saves time'
DRAIN = 'item skip loop of an empty tree: the pointer it moves is not read afterwards'
EQUIVALENT = {x: BROADCAST for x in (0x2a2b205, 0x2a2c71b, 0x2a2b64e)}
EQUIVALENT.update({x: BACK_HALF for x in (0x2a2b2e3, 0x2a2b2eb, 0x2a2b2f7, 0x2a2b44b, 0x2a2b450, 0x2a2b459, 0x2a2b461, 0x2a2b7bd, 0x2a2b7c2, 0x2a2b7cb, 0x2a2b7d0, 0x2a10a8b, 0x2a10a90)})
EQUIVALENT.update({x: CLOSURE for x in (0x2a2b333, 0x2a2b338, 0x2a2b576)})
EQUIVALENT.update({x: LOW_BITS for x in (0x2a10c28, 0x2a0a095, 0x2a0a16b, 0x330edd5, 0x330eebb, 0x2a0a4a5, 0x2a0a578)})
EQUIVALENT[0x330ef25] = KEY_POINTER
EQUIVALENT.update({x: UNWIND for x in (0x2a39c19, 0x2a39c7f, 0x2a39c84)})
EQUIVALENT.update({x: REPEAT for x in (0x251bfd8, 0x251c6c8)})
EQUIVALENT.update({x: DRAIN for x in (0x251bfe6, 0x251c009, 0x251c019, 0x251c6d6, 0x251c6f9, 0x251c709)})
WORKERS = 4
PROGRESS = False


def all_sites(listing, img):
    sites = []
    for fn in SUBJECTS:
        rows = listing[fn]
        sites += conditional_sites(fn, rows) + field_sites(fn, rows) + imm_sites(fn, rows) + constant_sites(fn, rows, img)
    return [x for x in sites if not any(a <= x['va'] < b for a, b, _ in UNEXECUTED.values())]


def try_kill(mctx, picked):
    for pos, v in enumerate(picked):
        try:
            bad = check(mctx, v)
        except (Unmodelled, Panicked, EvidenceError, KeyError, OverflowError, ValueError, TypeError, struct.error, IndexError, MemoryError, ZeroDivisionError, StopIteration, AttributeError, RecursionError) as exc:
            bad = f'fault {type(exc).__name__}'
        if bad:
            picked.insert(0, picked.pop(pos))
            return (v['group'], bad[:60].replace('\t', ' ').replace('\n', ' '))
    return None


def survey_part(args):
    data, code, slots, got, sites, want_scope = args
    rows = []
    for s_ in sites:
        picked = list(want_scope[s_['fn']])
        mimg = Image(data, s_['patch'])
        mcode = dict(code)
        try:
            mcode.update({i.va: i for i in decode_subject(mimg, s_['fn'])})
        except (EvidenceError, Unmodelled, IndexError, struct.error) as exc:
            rows.append(dict(s_, killed=('decoder', str(exc)[:60].replace('\t', ' '))))
            continue
        rows.append(dict(s_, killed=try_kill((mimg, mcode, slots, got), picked)))
        if PROGRESS and not rows[-1]['killed']:
            print('survivor', hex(s_['fn']), hex(s_['va']), s_['kind'], s_['op'], flush=True)
    return rows


def scope_of(fn, vecs):
    if fn == TAKE:
        return [v for v in vecs if v['kind'] == 'take'] + [v for v in vecs if 'wide' in v and v['flag'] & 0xff]
    if fn == SORT:
        return [v for v in vecs if v['kind'] == 'sort'] + [v for v in vecs if v['group'] in ('ready_count', 'flag', 'code')]
    if fn in (LIST, NEXT_LIST):
        return [v for v in vecs if v['kind'] == 'list']
    if fn in FOLDS:
        return [v for v in vecs if v['kind'] == 'fold' and v['fn'] == fn]
    light = [v for v in vecs if v['kind'] == 'stage' and 'wide' not in v]
    return light + [v for v in vecs if 'wide' in v] if fn == STAGE else light


def survey(data, code, slots, got, listing, vecs, img):
    sites = all_sites(listing, img)
    scoped = {fn: scope_of(fn, vecs) for fn in SUBJECTS}
    parts = [sites[i::WORKERS] for i in range(WORKERS)]
    jobs = [(data, code, slots, got, p, scoped) for p in parts]
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
    """Calls to each of `targets`: e8 rel32 in .text."""
    addr_, off, size = img.sec['.text'][:3]
    blob, out = img.data, []
    pack = struct.Struct('<i').unpack_from
    i = blob.find(b'\xe8', off, off + size)
    while i != -1 and i + 5 <= off + size:
        va = addr_ + i - off
        t = va + 5 + pack(blob, i + 1)[0]
        if t in targets:
            out.append((t, va, starts[bisect.bisect_right(starts, va) - 1]))
        i = blob.find(b'\xe8', i + 1, off + size)
    return sorted(out)


def location(img, va):
    """Panic Location: keep the path from `l1/src/` only, plus its full length."""
    start_ = img.relative(va)
    length = struct.unpack('<Q', img.read(va + 8, 8))[0]
    line, col = struct.unpack('<II', img.read(va + 16, 8))
    path = img.read(start_, length).decode('ascii')
    if 'l1/src/' in path:
        path = path[path.index('l1/src/'):]
    return dict(path=path, path_bytes=length, line=line, column=col)


def digest_of(v):
    return hashlib.sha256(repr(sorted((k, repr(x)) for k, x in v.items())).encode()).hexdigest()[:16]


def outcome_name(v):
    if v['kind'] == 'stage':
        if v.get('short') or 'fail_alloc' in v:
            return 'panic'
        w = stage_rule(v)
        return w['tag'] if w['tag'] != 'trade' else f"trade {w['required']}"
    if v['kind'] == 'list':
        if 'fail_alloc' in v or v.get('builder_length', 0) > 1 << 40 or v['group'] == 'short':
            return 'panic'
        return f'list {len(list_rule(v))}'
    if v['kind'] == 'fold':
        return f"fold {len([u for u in v['users'] if u in v['members'] and u not in v.get('none', ())])}"
    return v['kind']


REFERENCE_ROWS = (
    ('same', 'exchange/handlers/15_register_referrer.rs MIN_REFERRER_ELIGIBILITY_RAW', '1_000_000', 'cmp r13,0xf4240 at 0x2a2b514 and mov eax,0xf4240 at 0x2a2b531'),
    ('absent', 'l1 (no text hit of needToTrade, cumRewardedFeesSinceReferred or nReferrals)', 'no model of the referral view', 'whole path in this packet'),
)
PINS = (
    (0x2a2b3b7, '48c78424c800000088130000', 'cap: mov qword [rsp+0xc8], 5000, the take count of the rows', 'mov', 0),
    (0x2a2b514, '4981fd40420f00', 'cmp r13, 1000000: sum at or above gives needToCreateCode', 'cmp', 0),
    (0x2a2b531, 'b840420f00', 'mov eax, 1000000: the shortfall base', 'mov', 0),
    (0x2a2b541, 'f20f5e0517f47dfd', 'divsd by the constant at 0x20a960 (100.0)', 'div', 0),
    (0x2a2b1b9, 'f30f7e056ff67dfd', 'movq xmm0 from 0x20a830 (10000.0): required with no row', 'movq', 0),
    (0x2a2b4a2, 'f20f100586f37dfd', 'the same constant on a table miss', 'movsd', 0),
    (0x2a2b3f6, '4c897330', 'store r14 at result +0x30: count before the cap', 'mov', 0),
    (0x251c1aa, '4531c0', 'xor r8d, r8d: folder 0x251bf90 passes flag 0', 'xor', 0),
    (0x251c89a, '4531c0', 'xor r8d, r8d: folder 0x251c680 passes flag 0', 'xor', 0),
    (0x251c175, '488db1d0050000', 'lea rsi, state +0x5d0: tracker of folder 0x251bf90', 'lea', 0),
    (0x251c865, '488db150100000', 'lea rsi, state +0x1050: tracker of folder 0x251c680', 'lea', 0),
    (0x22cec61, '488d35500c11fe', 'row key at result +0', 'lea', 6),
    (0x22cecc6, '488d35f10b11fe', 'row key next', 'lea', 28),
    (0x22cece4, '488d7b08', 'lea rdi, row +8: value of the key above', 'lea', 0),
    (0x22ced2c, '488d35a70b11fe', 'row key next', 'lea', 25),
    (0x22ced4a, '488d7b10', 'lea rdi, row +0x10: value of the key above', 'lea', 0),
    (0x22ced8e, '488d4b18', 'lea rcx, row +0x18: value of the key below', 'lea', 0),
    (0x22ced92, '488d355a0b11fe', 'row key', 'lea', 10),
    (0x22cedb1, '488d4b38', 'lea rcx, row +0x38: value of the key below', 'lea', 0),
    (0x22cedb5, '488d3500b1f3fd', 'row key', 'lea', 4),
    (0x23d17d4, '488d3522e100fe', 'map key of the row', 'lea', 12),
    (0x22cf428, '488d35e80411fe', 'stage key, variant 1', 'lea', 5),
    (0x22cf446, '488d357354f3fd', 'value of variant 1', 'lea', 16),
    (0x22cf4b3, '488d35620411fe', 'value of variant 0', 'lea', 11),
    (0x22cf56b, '488d35b50311fe', 'value of variant 2', 'lea', 5),
    (0x22cf680, '488d35fda6f3fd', 'key of variant 2, text at result +8 and +0x10', 'lea', 4),
    (0x22cf6b6, '4d8b6730', 'mov r12, [r15+0x30]: value of the key below', 'mov', 0),
    (0x22cf6c1, '488d353c1511fe', 'key of variant 2', 'lea', 10),
    (0x22cf6fa, '488d350d1511fe', 'key of variant 2', 'lea', 14),
    (0x22cf714, '4983c718', 'add r15, 0x18: the vector of the key above', 'add', 0),
)


def pins(img):
    out = []
    for va, want, meaning, kind, length in PINS:
        got_ = img.read(va, len(want) // 2).hex()
        if got_ != want:
            raise EvidenceError(f'pin {va:#x} {got_}')
        row = dict(va=hex(va), bytes=got_, meaning=meaning)
        if length:
            at = va + 7 + struct.unpack('<i', bytes.fromhex(want[6:]))[0]
            row['key'] = img.read(at, length).decode('ascii')
        out.append(row)
    return out


def generate(data, out_dir, with_survey=True):
    global SEEN
    img, code, fdes, slots, got = build(data)
    ctx = (img, code, slots, got)
    listing = {s_: decode_subject(img, s_) for s_ in RANGES}
    vecs = all_vectors()
    seen = SEEN = set()
    try:
        for v in vecs:
            try:
                msg = check(ctx, v)
            except (Unmodelled, EvidenceError, Panicked, KeyError) as exc:
                msg = f'fault {type(exc).__name__} {exc}'
            if msg:
                raise EvidenceError(f"mismatch in {v['group']}: {msg}"[:900])
    finally:
        SEEN = None
    missing, padding = [], 0
    for fn in listing:
        for ins in listing[fn]:
            if ins.va in seen:
                continue
            if ins.op in ('nop', 'int3'):
                padding += 1
            elif not any(a <= ins.va < b for a, b, _ in UNEXECUTED.values()):
                missing.append(hex(ins.va))
    if missing:
        raise EvidenceError(f'unlisted unexecuted instructions {len(missing)}: {missing}')
    rows = survey(data, code, slots, got, listing, vecs, img) if with_survey else []
    survivors = {r['va'] for r in rows if not r['killed']}
    if survivors - set(EQUIVALENT) or (rows and set(EQUIVALENT) - survivors):
        raise EvidenceError(f'survivors {sorted(hex(s_) for s_ in survivors ^ set(EQUIVALENT))} of {len(rows)}')
    return facts_and_files(data, out_dir, img, fdes, listing, vecs, rows, seen, padding)


def facts_and_files(data, out_dir, img, fdes, listing, vecs, rows, seen, padding):
    starts = sorted(f['start'] for f in eh_frame_records(data)[1])
    out_path = Path(out_dir)
    out_path.mkdir(parents=True, exist_ok=True)
    groups, outcomes = {}, {}
    with open(out_path / 'vectors.tsv', 'w', newline='\n') as f:
        f.write('kind\tgroup\tstate\toutcome\n')
        for v in vecs:
            groups[v['group']] = groups.get(v['group'], 0) + 1
            name = outcome_name(v)
            outcomes[name] = outcomes.get(name, 0) + 1
            f.write(f"{v['kind']}\t{v['group']}\t{digest_of(v)}\t{name}\n")
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
    calls = direct_sites(img, set(DIRECT), starts)
    used = {SLOT_STAGE: slot_users(img, SLOT_STAGE, starts), SLOT_LIST: slot_users(img, SLOT_LIST, starts), SLOT_ROW: slot_users(img, SLOT_ROW, starts), SLOT_BIG_SORT: slot_users(img, SLOT_BIG_SORT, starts)}
    with open(out_path / 'call-sites.tsv', 'w', newline='\n') as f:
        f.write('callee\tvia\tsite\tfunction\n')
        for t, va, fn in calls:
            f.write(f'{t:#x}\tdirect\t{va:#x}\t{fn:#x}\n')
        for slot, us in sorted(used.items()):
            for u in us:
                f.write(f"{img.relative(slot):#x}\tslot {slot:#x}\t{u['site']}\t{u['function']}\n")
    per = {hex(fn): dict(instructions=len(listing[fn]), executed=sum(i.va in seen for i in listing[fn]), fde=hex(fdes.range_of(fn)['fde']), end=hex(FDE_END[fn])) for fn in RANGES}
    evidence = dict(
        binary=BINARY, sha256=SHA256, functions=per, pins=pins(img),
        constants=dict(required_default=img.f64(0x20a830), required_divisor=img.f64(0x20a960), limit=LIMIT, cap=CAP, small_sort_below=SMALL_SORT, row_bytes=ROW_SIZE),
        stubs=dict(hash=hex(HASH), row_core=hex(ROW_CORE), big_sort=hex(BIG_SORT), grow=hex(GROW), fold_grow=hex(GROW_FOLD), drop_row=hex(DROP_ROW), drop_iterator=hex(DROP_ITER)),
        location=location(img, LOC_ADD), vectors=len(vecs), mismatches=0, groups=groups, outcomes=outcomes, padding_not_executed=padding,
        unexecuted=[dict(start=hex(a), end=hex(b), why=w) for a, b, w in UNEXECUTED.values()], swept=[hex(s) for s in SUBJECTS],
        mutants=len(rows), killed=sum(1 for r in rows if r['killed']), equivalent={hex(k): w for k, w in sorted(EQUIVALENT.items())},
    )
    with open(out_path / 'evidence.json', 'w', newline='\n') as f:
        json.dump(evidence, f, indent=1, sort_keys=True)
        f.write('\n')
    return evidence


DIRECT = (0x251bf90, 0x251c680, 0x228dcb0, 0x228bf00, 0x27dca30, 0x258a0b0, WALK, TAKE, NEXT_LIST, HASH, ROW_GET)


def main():
    ap = argparse.ArgumentParser(description=__doc__.split('\n')[0])
    ap.add_argument('--out', required=True)
    args = ap.parse_args()
    data = (ROOT / BINARY).read_bytes()
    ev = generate(data, args.out)
    print(json.dumps(dict(vectors=ev['vectors'], mutants=ev['mutants'], killed=ev['killed']), sort_keys=True))


if __name__ == '__main__':
    main()
