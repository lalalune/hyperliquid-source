#!/usr/bin/env python3
"""fees: node #94 who may name a perp dex fee recipient and a token deployer fee share, from bytes alone.

Static, no execution of the node.  The setFeeRecipient path through the 3 copies of the perp deploy action, the deployer
gate 0x3719030, the address map search, the abstraction test, the deployer trading fee share setter and its action arm
are decoded from ELF bytes by the table decoder below, and interpreted in Python on every vector.  The lookups, hash,
row get, allocator, free and the text parser are stubs that check their arguments.  Each outcome is compared with a
separate closed-form model, then conditionals, field offsets, immediates and read constants are mutated.

    python3 tools/fees_deployer_recipient.py --out <dir>

writes evidence.json, vectors.tsv, mutations.tsv, instructions.tsv, reference-diff.tsv, variants.tsv and
recipient-sites.tsv.  Section and FDE parsing come from tools/elf_index.py and tools/fde_extents.py.  Only the standard
library is used: no objdump, readelf or other external program runs, so the results cannot depend on a binutils version.
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

    def run(self, entry, limit=20000):
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
OK = 0x186
TOO_LONG = 0x143
UNKNOWN_DEX = 0x141
BAD_STATUS = 0x162
BAD_RECIPIENT = 0x163
BAD_DEPLOYER = 0xe4
GONE = 0xe3
TEXT_ERR = 0xdf
MESSAGE = 0xe0
BAD_TOKEN = 0xea
OUTER_OK = 0xd
OUTER_ERR = 0xe
VARIANT = 5
KIND = 3
KIND_OWNER = 0xe
NAME_MAX = 100
LEGACY_LAST = 0xc3
SHARE_MAX = 100000
MAINNET = 3
ROW = 0x2f0
TOKEN = 0xe8
SHARE_F = 0xa8
GATE = 0x3719030
SLOT_GATE = 0x5774bb8
SLOT_KNOWN = 0x5774bc0
KNOWN = 0x3721c10
SLOT_FIRST = 0x5774708
FIRST = 0x3332270
SLOT_SECOND = 0x5773eb8
SECOND = 0x3332380
SLOT_PARSE = 0x5773168
PARSE = 0x3364cd0
HASH = 0x399c7a0
SLOT_FREE = 0x576e010
SLOT_ALLOC = 0x576dfd8
SLOT_NONE = 0x576e470
SLOT_ALLOC_ERR = 0x576dfb8
GOT_MEMCMP = 0x576e488
LOC_TOKEN = 0x56f2208
STATUS_TABLE = 0x59a8d0
TEXT_OVER = (0x599833, 0x33)
TEXT_RESET = (0x599a06, 0x23)
TEXT_RAISE = (0x599a29, 0x2a)
TEXT_ABSTRACT = (0x3efcdb, 0x24)
ROW_GET = 0x2755400
# the 3 copies of the perp deploy action; +0xa80 shape reads the registry words and the set shifted
ACTIONS = {
    0x273e080: dict(gbuf=0x50, buf=0xc0, inner=0x273f39f, shift=0, find=0x284bc20, abstraction=0x2745eb0, row_get=ROW_GET),
    0x4d50130: dict(gbuf=0x60, buf=0xd0, inner=0x4d514c9, shift=0, find=0x4927a10, abstraction=0x4d5fdc0, row_get=None),
    0x4d55b50: dict(gbuf=0x60, buf=0xd0, inner=0x4d56ee9, shift=0xa80, find=0x4927a10, abstraction=0x4d5fe60, row_get=None),
}
SETTERS = {0x27512f0: 0x8f2, 0x4d75ad0: 0x8f2, 0x4d75a00: 0x1372}
SHARE_ARMS = {
    0x23e8066: dict(host=0x23e7d10, setter=0x27512f0),
    0x4ad7c06: dict(host=0x4ad78b0, setter=0x4d75ad0),
    0x4ad8536: dict(host=0x4ad81e0, setter=0x4d75a00),
}
FINDS = (0x284bc20, 0x4927a10)
ABSTRACTIONS = (0x2745eb0, 0x4d5fdc0, 0x4d5fe60)
WHOLE = (GATE,) + FINDS + ABSTRACTIONS + tuple(SETTERS)
VARIANTS = ('registerAsset', 'registerAsset2', 'setOracle', 'haltTrading', 'insertMarginTable', 'setFeeRecipient', 'setMarginTableIds', 'setOpenInterestCaps', 'setFundingMultipliers',
            'setFundingInterestRates', 'setSubDeployers', 'setMarginModes', 'setFeeScale', 'setGrowthModes', 'disableDex', 'setPerpAnnotation')
KINDS = ('registerAsset', 'setOracle', 'insertMarginTable', 'setFeeRecipient', 'haltTrading', 'setMarginTableIds', 'setOpenInterestCaps', 'setFundingMultipliers', 'setMarginModes',
         'setFeeScale', 'setGrowthModes', 'setFundingInterestRates', 'disableDex', 'setPerpAnnotation')
TABLE_DISPATCH = 0x3ed800
TABLE_KIND = 0x3ed840
TABLE_ARM = 0x3ed880


class Panicked(Exception):
    """The node would panic here; a modelled outcome, unlike Unmodelled."""


class Stop(Exception):
    """A run of an action arm reached the end of the arm."""


def filled(m, size, seed):
    a = m.arena(size)
    a.mem[:] = fill_bytes(size, seed)
    a.valid[:] = b'\1' * size
    return a


# ---- model, written from the observed rules and independent of the machine


def gate_rule(status, deployer, subs, kind, sender):
    """status byte, deployer address, kind -> addresses map, action kind, sender -> tag."""
    if status == 3:
        return GONE if kind == KIND_OWNER else BAD_DEPLOYER
    if sender == deployer:
        return OK
    if kind == KIND_OWNER:
        return GONE
    return OK if sender in subs.get(kind, ()) else BAD_DEPLOYER


def action_rule(v):
    """Steps in order; stage names how the outcome is carried."""
    if len(v['name']) > NAME_MAX:
        return dict(status=TOO_LONG, stage='length', frees=False)
    if v['first'] is not None:
        return dict(status=v['first'], stage='forward', frees=False)
    d = v['dexes'][v['hit']]
    if d['status'] not in (0, 3):
        return dict(status=BAD_STATUS, stage='plain', frees=False)
    t = gate_rule(d['status'], d['deployer'], d['subs'], KIND, v['sender'])
    if t != OK:
        return dict(status=t, stage='gate', frees=False)
    a = v['addr']
    if not any(a in x['users'] for x in v['dexes'][:v.get('scan', len(v['dexes']))]) and not v['known']:
        return dict(status=BAD_RECIPIENT, stage='plain', frees=True)
    if a in v['vaults']:
        return dict(status=BAD_RECIPIENT, stage='plain', frees=True)
    mode = v['mode']
    if mode > 3:
        passed = v['f0'] == 1
    else:
        passed = mode < 2 or v['f1'] != 0
    if not passed:
        return dict(status=MESSAGE, stage='text', frees=True)
    if v['second'] is not None:
        return dict(status=v['second'], stage='forward', frees=True)
    return dict(status=OK, stage='write', frees=True, row=v['hit'])


def share_rule(token, count, mode, old, share):
    """-> ('panic',) or (tag, text or None, written)."""
    if token >= count:
        return ('panic',)
    if share > SHARE_MAX:
        return (TEXT_ERR, TEXT_OVER, False)
    if token <= LEGACY_LAST and mode == MAINNET:
        if old == 0:
            return (OK, None, True)
        if old <= share:
            return (TEXT_ERR, TEXT_RAISE, False)
        if share != 0:
            return (OK, None, True)
        return (TEXT_ERR, TEXT_RESET, False)
    if old <= share:
        return (TEXT_ERR, TEXT_RAISE, False)
    return (OK, None, True)


def key_hash(key):
    x = int.from_bytes(key[:8], 'little') * 0x9e3779b97f4a7c15 & U64
    x ^= int.from_bytes(key[8:16], 'little') * 0xc2b2ae3d27d4eb4f & U64
    x = (x ^ x >> 31) * 0xff51afd7ed558ccd & U64
    return x ^ x >> 29


def addr(seed):
    return bytes((seed * 37 + i * 19 + 5 + (seed >> 3) * i) & 0xff for i in range(20))


# ---- table and tree builders; they lay out what the code reads and share nothing with the model above


def write_table(m, row, off, users, decoys, seed, placed=()):
    """hashbrown table at row+off: ctrl, mask, growth, items; items 0x78 bytes below ctrl; tombstones in empty slots."""
    n = 128 if placed else 32
    while n * 7 // 8 <= len(users) + len(decoys) + 1:
        n *= 2
    ctrl = bytearray(b'\xff' * (n + 16))
    block = filled(m, n * 0x78 + n + 16, seed)
    at = block.base + n * 0x78
    for key, clash, skip in placed:
        h = key_hash(clash if clash is not None else key)
        home = h & (n - 1)
        for k in range(skip):
            i = (home + k) & (n - 1)
            if ctrl[i] == 0xff:
                ctrl[i] = 0x80
                if i < 16:
                    ctrl[n + i] = 0x80
        i = (home + skip) & (n - 1)
        ctrl[i] = h >> 57
        if i < 16:
            ctrl[n + i] = h >> 57
        slot = n * 0x78 - (i + 1) * 0x78
        block.mem[slot:slot + 20] = key
    for key, clash in [(k, None) for k in users] + list(decoys):
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
        slot = n * 0x78 - (i + 1) * 0x78
        block.mem[slot:slot + 20] = key
    for i in range(n):
        if ctrl[i] == 0xff and i % 5 == 3:
            ctrl[i] = 0x80
            if i < 16:
                ctrl[n + i] = 0x80
    block.mem[n * 0x78:n * 0x78 + n + 16] = ctrl
    word(row, off, 8, at)
    word(row, off + 8, 8, n - 1)
    word(row, off + 0x18, 8, len(users) + len(decoys) + len(placed))


def tree_split(items):
    step = max(1, (len(items) + 1) // 4)
    seps, kids, start = [], [], 0
    i = step - 1
    while i < len(items) and len(seps) < 11:
        seps.append(items[i])
        kids.append(items[start:i])
        start = i + 1
        i += step
    kids.append(items[start:])
    return seps, kids


def inner_tree(m, items, height, seed, stale=None):
    """address set: keys +8 stride 20, length u16 +0xe6, children +0xe8.  `stale` is a key just past the length."""
    if height == 0:
        seps, kids = items, []
    else:
        seps, kids = tree_split(items)
    a = filled(m, 0xe8 + (0x60 if height else 0), seed)
    if len(seps) > 11:
        raise EvidenceError('leaf too long')
    for i, k in enumerate(seps):
        a.mem[8 + i * 20:8 + (i + 1) * 20] = k
    word(a, 0xe6, 2, len(seps))
    if stale is not None:
        a.mem[8 + len(seps) * 20:8 + (len(seps) + 1) * 20] = stale
    for i, c in enumerate(kids):
        word(a, 0xe8 + i * 8, 8, inner_tree(m, c, height - 1, seed + i + 1).base)
    return a


def write_subs(m, meta, subs, outer, heights, seed, stale_inner=None, stale_kinds=()):
    """kind tree at meta +0x48: keys u8 +0x114, length u16 +0x112, values 0x18 at +8, children +0x120."""
    items = sorted(subs)
    if not items:
        word(meta, 0x48, 8, 0)
        word(meta, 0x50, 8, 0x5a5a)
        return
    n = [seed]

    def node(rows, height):
        n[0] += 7
        seps, kids = (rows, []) if height == 0 else tree_split(rows)
        a = filled(m, 0x120 + (0x60 if height else 0), n[0] & 0xff)
        word(a, 0x112, 2, len(seps))
        for q, (kind_, who) in enumerate(stale_kinds):
            at_ = len(seps) + q
            a.mem[0x114 + at_] = kind_
            word(a, 8 + at_ * 0x18, 8, inner_tree(m, who, 0, 0x33 + q).base)
            word(a, 0x10 + at_ * 0x18, 8, 0)
        for i, k in enumerate(seps):
            a.mem[0x114 + i] = k
            members = sorted(subs[k])
            h = heights.get(k, 0)
            if members or h == 0 and k in heights:
                root = inner_tree(m, members, h, (n[0] + i) & 0xff, stale_inner)
                word(a, 8 + i * 0x18, 8, root.base)
            else:
                word(a, 8 + i * 0x18, 8, 0)
            word(a, 0x10 + i * 0x18, 8, h)
            word(a, 0x18 + i * 0x18, 8, len(members))
        for i, c in enumerate(kids):
            word(a, 0x120 + i * 8, 8, node(c, height - 1).base)
        return a

    word(meta, 0x48, 8, node(items, outer).base)
    word(meta, 0x50, 8, outer)


def vault_tree(m, items, height, seed):
    """address map: values 0xb0 at +0, keys +0x798 stride 20, length u16 +0x876, children +0x878."""
    seps, kids = (items, []) if height == 0 else tree_split(items)
    a = filled(m, 0x878 + (0x60 if height else 0), seed)
    for i, k in enumerate(seps):
        a.mem[0x798 + i * 20:0x798 + (i + 1) * 20] = k
    word(a, 0x876, 2, len(seps))
    for i, c in enumerate(kids):
        word(a, 0x878 + i * 8, 8, vault_tree(m, c, height - 1, (seed + i + 3) & 0xff).base)
    return a


def write_vaults(m, ex, off, items, height, seed):
    if not items:
        word(ex, off, 8, 0)
        word(ex, off + 8, 8, 0x5a5a)
        return None
    root = vault_tree(m, sorted(items), height, seed)
    word(ex, off, 8, root.base)
    word(ex, off + 8, 8, height)
    return root


# ---- machine set-up


def base_machine(ctx):
    m = machine(ctx)
    slots = ctx[2]
    m.freed = []
    m.calls = []

    def memcmp():
        r = m.regs
        need(r[R['rdx']] == 20, 'memcmp length')
        a, b = m.bytes_at(r[R['rdi']], 20), m.bytes_at(r[R['rsi']], 20)
        m.clobber(0 if a == b else (1 if a > b else U64))

    m.stubs[slots[GOT_MEMCMP]] = memcmp
    return m


def run_call(m, fn):
    m.run(fn)
    if finished(m):
        raise Unmodelled('stack or saved registers not restored')


def write_action(m, v):
    action = filled(m, 0x30, 0x5b)
    name = filled(m, max(len(v['name']), 1), 0x13)
    name.mem[:len(v['name'])] = v['name']
    action.mem[0] = VARIANT
    action.mem[1:0x15] = v['addr']
    word(action, 0x18, 8, v['cap'])
    word(action, 0x20, 8, name.base)
    word(action, 0x28, 8, len(v['name']))
    return action, name


def check_action(ctx, v):
    m = base_machine(ctx)
    s = ACTIONS[v['copy']]
    shift = s['shift']
    slots = ctx[2]
    w = action_rule(v)
    r = m.regs
    n = len(v['dexes'])
    tab = filled(m, max(n, 1) * ROW, 0x31)
    metas = []
    for i, d in enumerate(v['dexes']):
        off = i * ROW
        meta = filled(m, 0xc0, 0x43 + i)
        meta.mem[0x74:0x88] = d['deployer']
        meta.mem[0x9d] = d['old'][0]
        meta.mem[0x9e:0xb2] = d['old'][1]
        write_subs(m, meta, d['subs'], d.get('outer', 0), d.get('heights', {}), 0x61 + i * 5, d.get('stale_inner'), d.get('stale_kinds', ()))
        metas.append(meta)
        word(tab, off + 0x208, 8, meta.base)
        tab.mem[off + 0x230] = d['status']
        if d['users'] or d['decoys'] or d.get('placed'):
            write_table(m, tab, off + 0xf8, [k for k in d['users'] if k not in [x[0] for x in d.get('placed', ())]], d['decoys'], 0x21 + i, d.get('placed', ()))
        else:
            word(tab, off + 0xf8, 8, 0xbad0000)
            word(tab, off + 0x110, 8, 0)
    ex = filled(m, 0x1400, 0x41)
    word(ex, 0x5c0 + shift, 8, tab.base)
    word(ex, 0x5c8 + shift, 8, v.get('scan', n))
    ex.mem[0x5b0] = v['f0']
    ex.mem[0x5b1] = v['f1']
    write_vaults(m, ex, 0x8d0 + shift, v['vaults'], v.get('vault_height', 0), 0x72)
    # the row get is a stub; its row holds the abstraction byte
    profile = filled(m, 0x58, 0x29)
    profile.mem[0x3c] = v['mode']
    action, name = write_action(m, v)
    sender = filled(m, 20, 0x19)
    sender.mem[:20] = v['sender']
    out = m.arena(0x80, strict=False)
    fresh = fill_bytes(0x80, 0x63)
    out.mem[:] = fresh
    m.buffer = None
    box = dict(alloc=None)
    start(m, dict(rdi=out.base, rsi=ex.base, rdx=sender.base, rcx=action.base))

    def lookup(result, want_slot):
        def run():
            need((r[R['rsi']], r[R['rdx']], r[R['rcx']]) == (ex.base + 0x5b8 + shift, name.base, len(v['name'])), want_slot)
            at = r[R['rdi']]
            if result is None:
                m.store(at, 2, OK)
                m.store(at + 8, 8, tab.base + v['hit'] * ROW)
            else:
                m.store_bytes(at, fill_bytes(0x60, 0x77))
                m.store(at, 2, result)
                m.buffer = m.bytes_at(at, 0x60)
            m.calls.append(want_slot)
            m.clobber()
        return run

    def known():
        need(r[R['rdi']] == ex.base + 0x80, 'known argument')
        need(m.bytes_at(r[R['rsi']], 20) == v['addr'], 'known key')
        m.calls.append('known')
        m.clobber(int(v['known']))

    def hash_stub():
        row = (r[R['rdi']] - 0x118 - tab.base)
        need(row % ROW == 0 and 0 <= row < n * ROW, 'hash keys')
        key = m.bytes_at(r[R['rsi']], 20)
        need(key == v['addr'], 'hash key')
        m.clobber(key_hash(key))

    def free():
        need((r[R['rdi']], r[R['rsi']], r[R['rdx']]) == (name.base, v['cap'], 0), 'free arguments')
        m.freed.append('name')
        m.clobber()

    def alloc():
        need(r[R['rdi']] == 0x24 and box['alloc'] is None, 'alloc size')
        box['alloc'] = m.arena(0x24, strict=False)
        m.clobber(box['alloc'].base)

    def row_get():
        need(r[R['rdi']] == ex.base, 'row argument')
        need(m.bytes_at(r[R['rsi']], 20) == v['addr'], 'row key')
        m.clobber(profile.base)

    m.stubs.update({slots[SLOT_FIRST]: lookup(v['first'], 'first'), slots[SLOT_SECOND]: lookup(v['second'], 'second'), slots[SLOT_KNOWN]: known, HASH: hash_stub,
                    slots[SLOT_FREE]: free, slots[SLOT_ALLOC]: alloc, ROW_TARGET[v['copy']]: row_get})
    m.real.update({GATE: GATE, s['find']: s['find'], s['abstraction']: s['abstraction']})
    for va in STOPS[v['copy']]:
        m.hooks[va] = stopper
    before = (bytes(ex.mem), bytes(tab.mem), [bytes(x.mem) for x in metas], bytes(action.mem), bytes(name.mem))
    try:
        m.run(v['copy'])
    except Stop:
        pass
    else:
        raise Unmodelled('action returned')
    if m.freed != (['name'] if w['frees'] and v['cap'] else []):
        return f'freed {m.freed}'
    if w['status'] == OK:
        if out.mem[0] != OUTER_OK or bytes(out.mem[1:]) != fresh[1:]:
            return 'outer tag'
    else:
        if out.mem[0] != OUTER_ERR:
            return 'outer tag'
        if read(out.mem, 8, 2) != w['status']:
            return f'status {read(out.mem, 8, 2):#x} not {w["status"]:#x}'
        if w['stage'] == 'length' and read(out.mem, 0x10) != action.base + 0x18:
            return 'pointer word'
        if w['stage'] == 'forward' and bytes(out.mem[8:0x68]) != m.buffer:
            return 'forwarded bytes'
        if w['stage'] == 'gate':
            at = r[R['rsp']] + s['gbuf'] - m.stack.base
            if bytes(out.mem[8:0x68]) != bytes(m.stack.mem[at:at + 0x60]):
                return 'forwarded frame bytes'
        if w['stage'] == 'text':
            if (read(out.mem, 0x10), read(out.mem, 0x20)) != (0x24, 0x24) or read(out.mem, 0x18) != box['alloc'].base:
                return 'text words'
            if bytes(box['alloc'].mem) != ctx[0].read(*TEXT_ABSTRACT):
                return 'text bytes'
            at = r[R['rsp']] + s['buf'] - m.stack.base
            if bytes(out.mem[8:0x68]) != bytes(m.stack.mem[at:at + 0x60]):
                return 'forwarded stack bytes'
    if bytes(ex.mem) != before[0] or bytes(tab.mem) != before[1] or bytes(action.mem) != before[3] or bytes(name.mem) != before[4]:
        return 'state written'
    for i, x in enumerate(metas):
        want = bytearray(before[2][i])
        if w['stage'] == 'write' and i == w['row']:
            want[0x9d] = 1
            want[0x9e:0xb2] = v['addr']
        if bytes(x.mem) != bytes(want):
            return 'meta bytes'
    gold = GOLD.get(id(v))
    if gold is not None and bytes(out.mem) != gold:
        return 'bytes differ from the unmodified run'
    v['_out'] = bytes(out.mem)
    return None


def stopper():
    raise Stop()


def check_gate(ctx, v):
    m = base_machine(ctx)
    d = v['dex']
    tab = filled(m, ROW, 0x31)
    meta = filled(m, 0xc0, 0x43)
    meta.mem[0x74:0x88] = d['deployer']
    write_subs(m, meta, d['subs'], d.get('outer', 0), d.get('heights', {}), 0x61, d.get('stale_inner'), d.get('stale_kinds', ()))
    word(tab, 0x208, 8, meta.base)
    tab.mem[0x230] = d['status']
    sender = filled(m, 20, 0x19)
    sender.mem[:20] = v['sender']
    out = m.arena(0x20, strict=False)
    out.mem[:] = fill_bytes(0x20, 0x63)
    before = (bytes(meta.mem), bytes(tab.mem))
    start(m, dict(rdi=out.base, rsi=tab.base, rdx=v['kind_byte'] | 0x5a00, rcx=sender.base))
    run_call(m, GATE)
    want = gate_rule(d['status'], d['deployer'], d['subs'], v['kind_byte'], v['sender'])
    if m.regs[0] != out.base:
        return 'result register'
    if read(out.mem, 0, 2) != want:
        return f'tag {read(out.mem, 0, 2):#x} not {want:#x}'
    if bytes(out.mem[2:]) != fill_bytes(0x20, 0x63)[2:]:
        return 'bytes after the tag'
    if (bytes(meta.mem), bytes(tab.mem)) != before:
        return 'state written'
    return None


def check_find(ctx, v):
    m = base_machine(ctx)
    ex = filled(m, 0x10, 0x41)
    root = write_vaults(m, ex, 0, v['items'], v['height'], 0x72)
    key = filled(m, 20, 0x19)
    key.mem[:20] = v['key']
    start(m, dict(rdi=ex.base, rsi=key.base))
    run_call(m, v['fn'])
    got_ = m.regs[0]
    want = None
    if v['key'] in v['items']:
        want = locate(m, root, v['key'], v['height'])
    if got_ != (want or 0):
        return f'pointer {got_:#x}'
    return None


def locate(m, node, key, height):
    n = read(node.mem, 0x876, 2)
    for i in range(n):
        k = bytes(node.mem[0x798 + i * 20:0x798 + (i + 1) * 20])
        if k == key:
            return node.base + i * 0xb0
        if key < k:
            return locate(m, arena_at(m, read(node.mem, 0x878 + i * 8)), key, height - 1)
    return locate(m, arena_at(m, read(node.mem, 0x878 + n * 8)), key, height - 1)


def arena_at(m, base):
    return m.find(base, 1)


def share_state(m, v, mode_off):
    tokens = filled(m, v['count'] * TOKEN if v['count'] else 8, 0x31)
    for i in range(v['count']):
        word(tokens, i * TOKEN + SHARE_F, 8, v['old'] if i == v['token'] else v['old'] ^ 0x1111)
    ex = filled(m, 0x1400, 0x41)
    word(ex, 0x210, 8, tokens.base)
    word(ex, 0x218, 8, v['count'])
    ex.mem[mode_off] = v['mode']
    return tokens, ex


def tail_ok(ctx, w, out, base, tokens, before, v):
    fresh_out = out
    if bytes(tokens.mem) != before[0]:
        want = bytearray(before[0])
        if w[0] == OK:
            want[v['token'] * TOKEN + SHARE_F:v['token'] * TOKEN + SHARE_F + 8] = struct.pack('<Q', v['share'])
        if bytes(tokens.mem) != bytes(want):
            return 'token bytes'
    elif w[0] == OK and v['old'] != v['share']:
        return 'not written'
    return None


def check_setter(ctx, v):
    m = base_machine(ctx)
    tokens, ex = share_state(m, v, SETTERS[v['fn']])
    slots = ctx[2]

    def none():
        need(m.regs[R['rdi']] == LOC_TOKEN, 'panic location')
        raise Panicked('token')

    m.stubs[slots[SLOT_NONE]] = none
    out = m.arena(0x40, strict=False)
    fresh = fill_bytes(0x40, 0x63)
    out.mem[:] = fresh
    before = (bytes(tokens.mem), bytes(ex.mem))
    start(m, dict(rdi=out.base, rsi=ex.base, rdx=v['token'], rcx=v['share']))
    w = share_rule(v['token'], v['count'], v['mode'], v['old'], v['share'])
    try:
        run_call(m, v['fn'])
    except Panicked:
        if w[0] != 'panic':
            return 'panic not wanted'
        return None
    if w[0] == 'panic':
        return 'no panic'
    if m.regs[0] != out.base:
        return 'result register'
    if read(out.mem, 0, 2) != w[0]:
        return f'tag {read(out.mem, 0, 2):#x}'
    if w[1] is None:
        if bytes(out.mem[2:]) != fresh[2:]:
            return 'bytes after tag'
    elif (read(out.mem, 8), read(out.mem, 0x10)) != w[1] or bytes(out.mem[2:8]) != fresh[2:8] or bytes(out.mem[0x18:]) != fresh[0x18:]:
        return 'text words'
    if bytes(ex.mem) != before[1]:
        return 'exchange written'
    return tail_ok(ctx, w, out, None, tokens, before, v)


def check_share_arm(ctx, v):
    m = base_machine(ctx)
    a = SHARE_ARMS[v['arm']]
    tokens, ex = share_state(m, v, SETTERS[a['setter']])
    slots = ctx[2]
    r = m.regs
    action = filled(m, 0x30, 0x5b)
    text = filled(m, max(len(v['text']), 1), 0x17)
    text.mem[:len(v['text'])] = v['text']
    word(action, 0x10, 8, text.base)
    word(action, 0x18, 8, len(v['text']))
    word(action, 0x20, 8, v['token'])
    out = m.arena(0x80, strict=False)
    fresh = fill_bytes(0x80, 0x63)
    out.mem[:] = fresh
    frame = m.stack.base + 0x1000
    r[R['rsp']] = frame
    r[R['rbx']], r[R['r14']], r[R['r15']] = out.base, ex.base, action.base
    for name_ in ('rbp', 'r12', 'r13'):
        r[R[name_]] = 0xc0de0000 + R[name_]
    box = dict(buf=None)

    def parse():
        need((r[R['rdi']], r[R['rsi']], r[R['rdx']]) == (frame + 0x20, text.base, len(v['text'])), 'parser arguments')
        at = r[R['rdi']]
        if v['parsed'] is None:
            m.store_bytes(at, fill_bytes(0x60, 0x77))
            m.store(at, 2, 0xab)
            box['buf'] = m.bytes_at(at, 0x60)
        else:
            m.store(at, 2, OK)
            m.store(at + 8, 8, v['parsed'])
        m.calls.append('parse')
        m.clobber()

    m.stubs[slots[SLOT_PARSE]] = parse
    m.stubs[slots[SLOT_NONE]] = lambda: (_ for _ in ()).throw(Unmodelled('panic in the arm'))
    m.real[a['setter']] = a['setter']
    for va in ARM_STOPS[v['arm']]:
        m.hooks[va] = stopper
    before = (bytes(tokens.mem), bytes(ex.mem), bytes(action.mem), bytes(text.mem))
    try:
        m.run(v['arm'])
    except Stop:
        pass
    else:
        raise Unmodelled('arm returned')
    if v['token'] >= v['count']:
        want = (BAD_TOKEN, None)
    elif len(v['text']) > NAME_MAX:
        want = (TOO_LONG, None)
    elif v['parsed'] is None:
        want = (0xab, None)
    else:
        rule = share_rule(v['token'], v['count'], v['mode'], v['old'], v['parsed'])
        want = rule[:2]
    if want[0] == OK:
        if out.mem[0] != OUTER_OK or bytes(out.mem[1:]) != fresh[1:]:
            return 'outer tag'
    else:
        if out.mem[0] != OUTER_ERR or read(out.mem, 8, 2) != want[0]:
            return f'status {read(out.mem, 8, 2):#x} not {want[0]:#x}'
        if want[0] == BAD_TOKEN and read(out.mem, 0x10) != v['token']:
            return 'token word'
        if want[0] == TOO_LONG and read(out.mem, 0x10) != action.base + 8:
            return 'pointer word'
        if want[0] == 0xab and bytes(out.mem[8:0x68]) != box['buf']:
            return 'forwarded bytes'
        if want[1] is not None:
            if (read(out.mem, 0x10), read(out.mem, 0x18)) != want[1]:
                return 'text words'
            o = frame + 0x80 - m.stack.base
            if bytes(out.mem[8:0x68]) != bytes(m.stack.mem[o:o + 0x60]):
                return 'forwarded stack bytes'
    if m.calls != (['parse'] if v['token'] < v['count'] and len(v['text']) <= NAME_MAX else []):
        return 'parser calls'
    if bytes(ex.mem) != before[1] or bytes(action.mem) != before[2] or bytes(text.mem) != before[3]:
        return 'state written'
    wv = dict(v, share=v['parsed'] if v['parsed'] is not None else 0)
    if want[0] != OK and bytes(tokens.mem) != before[0]:
        return 'token bytes'
    if want[0] == OK:
        return tail_ok(ctx, (OK,), out, None, tokens, before, wv)
    return None


def check(ctx, v):
    return {'action': check_action, 'gate': check_gate, 'find': check_find, 'setter': check_setter, 'share_arm': check_share_arm}[v['kind']](ctx, v)


# ---- vectors


A = addr(1)
DEPLOYER = addr(2)
OTHER = addr(3)


def dex(**kw):
    d = dict(status=0, deployer=DEPLOYER, subs={}, users=[], decoys=[], old=(0, addr(90)))
    d.update(kw)
    return d


def act(copy, group, **kw):
    v = dict(kind='action', copy=copy, group=group, name=b'alpha', cap=16, sender=DEPLOYER, addr=A, dexes=[dex(users=[A])], hit=0, first=None, second=None, known=False, vaults=[], mode=0, f0=0, f1=0)
    v.update(kw)
    return v


def flip(b, i):
    out = bytearray(b)
    out[i] ^= 0x40
    return bytes(out)


def spread(n, seed=0):
    return sorted(addr(200 + seed + i * 3) for i in range(n))


def action_vectors(copy):
    out = []
    for n in (0, 1, 5, 99, 100, 101, 102, 356):
        out.append(act(copy, 'name', name=bytes(0x61 + i % 26 for i in range(n)), cap=n))
    out.append(act(copy, 'first', first=UNKNOWN_DEX))
    out.append(act(copy, 'first', first=0x77))
    for st in (1, 2, 3, 4, 0x80, 0xff):
        out.append(act(copy, 'status', dexes=[dex(users=[A], status=st)]))
        out.append(act(copy, 'status', sender=OTHER, dexes=[dex(users=[A], status=st, subs={KIND: [OTHER]})]))
    for i in (0, 7, 8, 15, 16, 19):
        out.append(act(copy, 'gate', sender=flip(DEPLOYER, i)))
    group = spread(9)
    cases = [
        dict(subs={KIND: [OTHER]}), dict(subs={KIND - 1: [OTHER]}), dict(subs={KIND + 1: [OTHER]}), dict(subs={}), dict(subs={KIND: []}), dict(subs={KIND: []}, heights={KIND: 0}),
        dict(subs={KIND: sorted(group[:4] + [OTHER])}), dict(subs={KIND: group}), dict(subs={0: group, 1: [OTHER], 2: group, KIND: sorted(group + [OTHER]), 9: [OTHER]}),
        dict(subs={k: [OTHER] for k in range(14)}, outer=1), dict(subs={k: ([OTHER] if k != KIND else group) for k in range(14)}, outer=1),
        dict(subs={KIND: sorted(spread(30) + [OTHER])}, heights={KIND: 1}), dict(subs={KIND: sorted(spread(90, 7) + [OTHER])}, heights={KIND: 2}), dict(subs={KIND: spread(90, 7)}, heights={KIND: 2}),
    ]
    for c in cases:
        out.append(act(copy, 'gate', sender=OTHER, dexes=[dex(users=[A], **c)]))
    late = dex(users=[A])
    for rows in ([dex(users=[A])], [dex(), dex(users=[A])], [dex(users=[addr(40)]), dex(), dex(users=[addr(41), A])], [dex(users=[addr(40)]), dex(users=[addr(41)])], [dex(), dex()]):
        for k in (False, True):
            out.append(act(copy, 'found', dexes=rows, known=k))
    out.append(act(copy, 'found', dexes=[late], scan=0, known=True))
    out.append(act(copy, 'found', dexes=[late], scan=0, known=False))
    out.append(act(copy, 'found', dexes=[dex(), dex(users=[A])], hit=1))
    for count in (1, 3, 15, 16, 17, 34, 49):
        for pos in (0, 8, 15, 16, 19):
            out.append(act(copy, 'probe', dexes=[dex(decoys=[(addr(300 + i), A) if i else (flip(A, pos), A) for i in range(count)], users=[])], known=False))
            out.append(act(copy, 'probe', dexes=[dex(decoys=[(addr(300 + i), A) if i else (flip(A, pos), A) for i in range(count)], users=[A])], known=False))
    for skip in (3, 5, 14, 16, 48):
        out.append(act(copy, 'probe', dexes=[dex(users=[A], placed=((A, None, skip),))]))
    out.append(act(copy, 'probe', dexes=[dex(users=[A], placed=((flip(A, 9), A, 3), (A, None, 6)))]))
    out.append(act(copy, 'probe', dexes=[dex(users=[], placed=((flip(A, 9), A, 3),))]))
    for pos in (0, 15, 16, 19):
        out.append(act(copy, 'vault', vaults=[flip(A, pos)]))
    out.append(act(copy, 'vault', vaults=[A]))
    out.append(act(copy, 'vault', vaults=sorted([A] + spread(10))))
    out.append(act(copy, 'vault', vaults=sorted([A] + spread(30)), vault_height=1))
    out.append(act(copy, 'vault', vaults=spread(30), vault_height=1))
    out.append(act(copy, 'vault', vaults=sorted([A] + spread(90, 11)), vault_height=2))
    for mode in range(7):
        for f0 in (0, 1, 2):
            for f1 in (0, 1, 2):
                out.append(act(copy, 'abstraction', mode=mode, f0=f0, f1=f1))
    out.append(act(copy, 'second', second=UNKNOWN_DEX))
    out.append(act(copy, 'second', second=0x77, cap=0))
    out.append(act(copy, 'abstraction', mode=3, cap=0))
    out.append(act(copy, 'found', dexes=[dex()], cap=0))
    for old in ((0, addr(90)), (1, addr(91)), (2, addr(92))):
        out.append(act(copy, 'write', dexes=[dex(users=[A], old=old)]))
        out.append(act(copy, 'write', dexes=[dex(), dex(users=[A], old=old), dex()], hit=1))
    out.append(act(copy, 'write', sender=OTHER, dexes=[dex(users=[A], subs={KIND: [OTHER]})]))
    out.append(act(copy, 'write', known=True, dexes=[dex()]))
    return out


def gate_vectors():
    out = []
    group = spread(9)
    configs = [dict(subs={}), dict(subs={k: [OTHER] for k in (1, 3, 5)}), dict(subs={k: [OTHER] for k in range(14)}, outer=1), dict(subs={k: sorted(group + [OTHER]) for k in (0, 7, 13)}),
               dict(subs={2: [], 4: []}, heights={2: 0}), dict(subs={k: sorted(spread(30) + [OTHER]) for k in (3, 9)}, heights={3: 1, 9: 1}), dict(subs={k: group for k in (3,)})]
    high = b'\xff' * 19 + b'\xfe'
    for who, sets, h in ((high, spread(30) + [high], 1), (high, spread(90, 7) + [high], 2)):
        out.append(dict(kind='gate', group='gate tree', dex=dex(subs={3: sorted(sets)}, heights={3: h}), kind_byte=3, sender=who))
    out.append(dict(kind='gate', group='gate stale', dex=dex(subs={3: group[:3]}, stale_inner=high), kind_byte=3, sender=high))
    out.append(dict(kind='gate', group='gate stale', dex=dex(subs={1: [DEPLOYER]}, stale_kinds=((3, [OTHER]),)), kind_byte=3, sender=OTHER))
    out.append(dict(kind='gate', group='gate stale', dex=dex(subs={1: [DEPLOYER]}, stale_kinds=((0, [DEPLOYER]), (3, [OTHER]))), kind_byte=3, sender=OTHER))
    for c in configs:
        for st in (0, 1, 2, 3):
            for k in range(16):
                for who in (DEPLOYER, OTHER, addr(77)):
                    out.append(dict(kind='gate', group='gate', dex=dex(status=st, **c), kind_byte=k, sender=who))
    return out


def find_vectors():
    out = []
    shapes = ((0, 0), (1, 0), (5, 0), (11, 0), (30, 1), (80, 2))
    for fn in FINDS:
        for n, h in shapes:
            items = spread(n, h)
            keys = list(items[:3] + items[-2:] + items[len(items) // 2:len(items) // 2 + 1]) + [b'\0' * 20, b'\xff' * 20, addr(13)]
            keys += [flip(k, 19) for k in items[:2]]
            for k in keys:
                out.append(dict(kind='find', group='find', fn=fn, items=items, height=h, key=k))
    return out


COUNT = 0xc8
SHARES = (0, 1, 50000, 99999, 100000, 100001, 1 << 63, U64)
OLDS = (0, 1, 50000, 99999, 100000)


def setter_vectors():
    out = []
    for fn in SETTERS:
        for tok in (0, 1, 0xc2, 0xc3, 0xc4, 0xc5, COUNT - 1):
            for mode in (0, 1, 2, 3, 4):
                for old in OLDS:
                    for sh in SHARES:
                        out.append(dict(kind='setter', group='setter', fn=fn, token=tok, count=COUNT, mode=mode, old=old, share=sh))
        for tok, n in ((COUNT, COUNT), (COUNT + 1, COUNT), (0, 0), (U64, COUNT)):
            out.append(dict(kind='setter', group='bounds', fn=fn, token=tok, count=n, mode=3, old=0, share=0))
    return out


def share_arm_vectors():
    out = []
    for arm in SHARE_ARMS:
        for tok, n in ((COUNT, COUNT), (COUNT + 7, COUNT)):
            out.append(dict(kind='share_arm', group='share bounds', arm=arm, token=tok, count=n, mode=3, old=0, text=b'1%', parsed=5))
        for ln in (0, 1, 100, 101, 102):
            out.append(dict(kind='share_arm', group='share text', arm=arm, token=3, count=COUNT, mode=0, old=7, text=b'1' * ln, parsed=5))
        out.append(dict(kind='share_arm', group='share parse', arm=arm, token=3, count=COUNT, mode=0, old=7, text=b'nope', parsed=None))
        for tok in (0, 0xc3, 0xc4):
            for mode in (0, 3):
                for old in (0, 7, 100000):
                    for sh in (0, 6, 7, 8, 100000, 100001):
                        out.append(dict(kind='share_arm', group='share', arm=arm, token=tok, count=COUNT, mode=mode, old=old, text=b'9%', parsed=sh))
    return out


def all_vectors():
    out = []
    for copy in ACTIONS:
        out += action_vectors(copy)
    return out + gate_vectors() + find_vectors() + setter_vectors() + share_arm_vectors()


# ---- decoding of the paths

FDE_END = {}
RANGES = {}
STOPS = {}
ARM_STOPS = {}
ROW_TARGET = {}
NORETURN = (0x576dfb8, 0x576e470, 0x576e048, 0x576eb38)


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


def table_jump(img, found, va):
    """The lea of an i32 jump table sits a few instructions before `jmp reg`; entry 5 is this variant."""
    for back in range(1, 48):
        ins = found.get(va - back)
        if ins is not None and ins.op == 'lea' and ins.ops[1][0] == 'm' and ins.ops[1][1] is None and img.in_rodata(ins.ops[1][4], 4):
            t = ins.ops[1][4]
            return t + struct.unpack('<i', img.read(t + 4 * VARIANT, 4))[0]
    raise EvidenceError(f'no table before {va:#x}')


def walk(img, entry, end_tags, may_jump, inner=None):
    """Instructions of one path, following both ways of each branch.  It ends at the drop of the action (movzx eax,
    byte [rbp+0]) and after the byte store of an outer tag.  Calls that do not return end a branch."""
    found, stops, todo = {}, set(), [entry]
    while todo:
        va = todo.pop()
        if va in found or va in stops:
            continue
        code = img.read(va, 16)
        if code.startswith(b'\x0f\xb6\x45\x00') and va != inner:
            stops.add(va)
            continue
        ins = decode_one(code + b'\x90' * 16, 0, va)
        found[va] = ins
        nxt = va + ins.size
        if ins.op == 'jmp':
            todo.append(ins.ops[0][1])
            continue
        if ins.op == 'jmpr':
            if not may_jump:
                raise EvidenceError(f'indirect jump at {va:#x}')
            todo.append(table_jump(img, found, va))
            continue
        if ins.op in ('ret', 'ud2', 'int3'):
            raise EvidenceError(f'path reached {ins.op} at {va:#x}')
        if ins.op == 'call' and ins.ops[0][0] == 'm' and ins.ops[0][4] in NORETURN:
            continue
        if ins.op[0] == 'j':
            todo.append(ins.ops[0][1])
        if ins.op == 'mov' and ins.ops[0][0] == 'm' and ins.ops[0][6] == 8 and ins.ops[1][0] == 'i' and ins.ops[1][1] in end_tags:
            stops.add(nxt)
            continue
        todo.append(nxt)
    return [found[k] for k in sorted(found)], sorted(stops)


def walk_action(img, entry):
    return walk(img, entry, (OUTER_OK,), True, ACTIONS[entry]['inner'])


def walk_share(img, entry):
    return walk(img, entry, (OUTER_OK, OUTER_ERR), False)


def build(data):
    check_digest(data)
    fdes = bind_fdes(data)
    img = Image(data)
    code = {}
    for s in RANGES:
        code.update({i.va: i for i in decode_subject(img, s)})
    for copy, s in ACTIONS.items():
        calls = [i.ops[0][1] for i in decode_subject(img, s['abstraction']) if i.op == 'call' and i.ops[0][0] == 't']
        ROW_TARGET[copy] = calls[0]
    arms = {}
    for e in ACTIONS:
        rows, stops = walk_action(img, e)
        arms[e] = rows
        STOPS[e] = stops
        code.update({i.va: i for i in rows})
    for e in SHARE_ARMS:
        rows, stops = walk_share(img, e)
        arms[e] = rows
        ARM_STOPS[e] = stops
        code.update({i.va: i for i in rows})
    for va in sorted({x for t in (STOPS, ARM_STOPS) for e in t for x in t[e]}):
        code[va] = decode_one(img.read(va, 16) + b'\x90' * 16, 0, va)
    slots, got = scan_slots(img, code)
    return img, code, fdes, slots, got, arms


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
    """Bytes of each .rodata constant a subject reads: the top byte of the f64 mantissa side."""
    out = []
    for ins in listing:
        for o in ins.ops:
            if o[0] == 'm' and o[1] is None and o[2] is None and img.in_rodata(o[4], 8) and ins.op in ('ucomisd', 'mulsd', 'movsd'):
                out.append(dict(kind='constant', fn=fn, va=ins.va, op=show(ins), patch={o[4] + 6: img.read(o[4] + 6, 1)[0] ^ 0x10}))
    return out



SWEPT_ACTION = 0x273e080
SUBJECTS = (SWEPT_ACTION, GATE) + FINDS + ABSTRACTIONS + tuple(SETTERS) + tuple(SHARE_ARMS)
NO_ALLOC = 'allocator failure, a panic not modelled here'
NO_LIST = 'the asset name list of the action: empty for this variant, r15 = 0 at the join'
NO_THREE = 'status 3 after a passed gate: the gate never passes on status 3'
NO_SECOND = 'second name length test: the first test at the head already refused a name over 100 bytes'
_R = (
    (0x2745f3f, 0x2745f4f, NO_ALLOC), (0x4d5fe4f, 0x4d5fe5f, NO_ALLOC), (0x4d5feef, 0x4d5feff, NO_ALLOC),
    (0x273efd9, 0x273f05c, NO_LIST), (0x273f073, 0x273f080, NO_LIST), (0x273f26a, 0x273f2e6, NO_LIST), (0x273f2f4, 0x273f300, NO_LIST), (0x273f317, 0x273f339, NO_THREE), (0x2740cc7, 0x2740cef, NO_SECOND),
    (0x4d510d9, 0x4d51160, NO_LIST), (0x4d5117a, 0x4d51184, NO_LIST), (0x4d5138b, 0x4d51412, NO_LIST), (0x4d51420, 0x4d5142a, NO_LIST), (0x4d51441, 0x4d51463, NO_THREE), (0x4d52e50, 0x4d52e79, NO_SECOND),
    (0x4d56af9, 0x4d56b80, NO_LIST), (0x4d56b9a, 0x4d56ba4, NO_LIST), (0x4d56dab, 0x4d56e32, NO_LIST), (0x4d56e40, 0x4d56e4a, NO_LIST), (0x4d56e61, 0x4d56e83, NO_THREE), (0x4d58870, 0x4d58899, NO_SECOND),
)
UNEXECUTED = {i: r for i, r in enumerate(_R)}
UNWIND_FLAG = 'a spill or drop flag that this variant never reads on any evaluated exit; the value matters to unwind clean-up or other variants'
EMPTY_LIST = 'set-up of the asset name list loop; the list of this variant is empty, so the value is never used'
OVERWRITTEN = 'overwritten before any read on this path'
OWNER_FRAME = 'copy of the deployer address into the frame for other variants; this variant never reads it'
NEVER_3 = 'status 3 cannot reach this test: the gate refuses it first, so the byte read is never 3'
SAME_KEY = 'the same 20 key bytes are already in this slot from the store before the dex walk'
BROADCAST = 'the low 8 bytes of the register are equal bytes, so dword 0 and dword 1 are the same'
STACK_COPY = 'a stack copy of the deployer that nothing reads'
EQUIVALENT = {
    0x273e0b9: OVERWRITTEN, 0x273e0e6: UNWIND_FLAG, 0x273e0fc: UNWIND_FLAG, 0x273e0fe: UNWIND_FLAG, 0x273e107: UNWIND_FLAG, 0x273e109: UNWIND_FLAG, 0x273e10d: UNWIND_FLAG, 0x273e113: UNWIND_FLAG, 0x273e115: UNWIND_FLAG,
    0x273e119: UNWIND_FLAG, 0x273e11c: UNWIND_FLAG, 0x273e11f: UNWIND_FLAG, 0x273e121: UNWIND_FLAG,
    0x273e142: EMPTY_LIST, 0x273ef66: EMPTY_LIST, 0x273efa1: EMPTY_LIST, 0x273efa6: EMPTY_LIST, 0x273efb2: EMPTY_LIST, 0x273efb6: EMPTY_LIST, 0x273efbb: EMPTY_LIST,
    0x273f30a: NEVER_3, 0x27413c3: NEVER_3,
    0x273f344: OWNER_FRAME, 0x273f348: OWNER_FRAME, 0x273f34d: OWNER_FRAME, 0x273f350: OWNER_FRAME, 0x273f354: OWNER_FRAME, 0x273f358: OWNER_FRAME, 0x273f35e: OWNER_FRAME, 0x273f365: OWNER_FRAME, 0x273f36c: OWNER_FRAME,
    0x273f371: OWNER_FRAME, 0x273f375: OWNER_FRAME, 0x273f37c: OWNER_FRAME, 0x273f384: OWNER_FRAME, 0x273f38c: OWNER_FRAME, 0x273f393: OWNER_FRAME, 0x273f397: OWNER_FRAME,
    0x27400cf: BROADCAST, 0x274012a: SAME_KEY, 0x3719067: STACK_COPY, 0x3719073: STACK_COPY,
}
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
        except (Unmodelled, Panicked, EvidenceError, KeyError, OverflowError, ValueError, TypeError, struct.error, IndexError, MemoryError, ZeroDivisionError, StopIteration, Stop, AttributeError, RecursionError) as exc:
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
            if s_['fn'] in ACTIONS:
                mcode.update({i.va: i for i in walk_action(mimg, s_['fn'])[0]})
            elif s_['fn'] in SHARE_ARMS:
                mcode.update({i.va: i for i in walk_share(mimg, s_['fn'])[0]})
            else:
                mcode.update({i.va: i for i in decode_subject(mimg, s_['fn'])})
        except (EvidenceError, Unmodelled, IndexError, struct.error) as exc:
            rows.append(dict(s_, killed=('decoder', str(exc)[:60].replace('\t', ' '))))
            continue
        rows.append(dict(s_, killed=try_kill((mimg, mcode, slots, got), picked)))
        if PROGRESS and not rows[-1]['killed']:
            print('survivor', hex(s_['fn']), hex(s_['va']), s_['kind'], s_['op'], flush=True)
    return rows


def scope_of(fn, vecs):
    if fn in ACTIONS:
        return [v for v in vecs if v['kind'] == 'action' and v['copy'] == fn]
    if fn == GATE:
        return [v for v in vecs if v['kind'] == 'gate']
    if fn in FINDS:
        return [v for v in vecs if v['kind'] == 'find' and v['fn'] == fn]
    if fn in ABSTRACTIONS:
        copy = [c for c, s in ACTIONS.items() if s['abstraction'] == fn][0]
        return [v for v in vecs if v['kind'] == 'action' and v['copy'] == copy and v['group'] == 'abstraction']
    if fn in SETTERS:
        return [v for v in vecs if v['kind'] == 'setter' and v['fn'] == fn]
    return [v for v in vecs if v['kind'] == 'share_arm' and v['arm'] == fn]


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


def direct_sites(img, target, starts):
    """Calls to `target`: e8 rel32 in .text."""
    addr_, off, size = img.sec['.text'][:3]
    blob, out = img.data, []
    pack = struct.Struct('<i').unpack_from
    i = blob.find(b'\xe8', off, off + size)
    while i != -1 and i + 5 <= off + size:
        va = addr_ + i - off
        if va + 5 + pack(blob, i + 1)[0] == target:
            out.append(dict(site=hex(va), function=hex(starts[bisect.bisect_right(starts, va) - 1])))
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


def status_arm(img, tag):
    return STATUS_TABLE + struct.unpack('<i', img.read(STATUS_TABLE + 4 * tag, 4))[0]


def status_text(img, tag):
    """A plain arm is mov rdi/mov rax/mov rax+0x18/lea rsi,[rip]/mov edx,len; its text comes straight from the bytes."""
    arm = status_arm(img, tag)
    b = img.read(arm, 26)
    if b[:11] != bytes.fromhex('488b3e488b4608488b4018') or b[11:14] != b'\x48\x8d\x35' or b[18] != 0xba:
        raise EvidenceError(f'status arm shape {tag:#x}')
    text = arm + 18 + struct.unpack('<i', b[14:18])[0]
    return img.read(text, struct.unpack('<I', b[19:23])[0]).decode('ascii')


def format_pieces(img, va):
    """Compact format string: length byte, text, 0xc0 placeholder, and 0 at the end."""
    out, i = [], va
    while True:
        n = img.read(i, 1)[0]
        if n == 0:
            return out
        if n == 0xc0:
            out.append(None)
            i += 1
            continue
        out.append(img.read(i + 1, n).decode('ascii'))
        i += 1 + n


def status_format(img, tag):
    """A format arm takes `lea rdx,[rip+pieces]` near its head; returns the VA of the pieces."""
    arm = status_arm(img, tag)
    b = img.read(arm, 48)
    i = b.find(b'\x48\x8d\x15')
    return arm + i + 7 + struct.unpack('<i', b[i + 3:i + 7])[0]


def location(img, va):
    """Panic Location: keep the path from `l1/src/` or `src/` only, plus its full length."""
    start = img.relative(va)
    length = struct.unpack('<Q', img.read(va + 8, 8))[0]
    line, col = struct.unpack('<II', img.read(va + 16, 8))
    path = img.read(start, length).decode('ascii')
    for mark in ('l1/src/', 'chrono-'):
        if mark in path:
            path = path[path.index(mark):]
    return dict(path=path, path_bytes=length, line=line, column=col)



def digest_of(v):
    return hashlib.sha256(repr(sorted((k, repr(x)) for k, x in v.items() if k != '_out')).encode()).hexdigest()[:16]


def outcome_name(v):
    if v['kind'] == 'action':
        w = action_rule(v)
        return f"{w['stage']} {w['status']:#x}"
    if v['kind'] == 'gate':
        d = v['dex']
        return f"gate {gate_rule(d['status'], d['deployer'], d['subs'], v['kind_byte'], v['sender']):#x}"
    if v['kind'] == 'find':
        return 'found' if v['key'] in v['items'] else 'absent'
    if v['kind'] == 'setter':
        w = share_rule(v['token'], v['count'], v['mode'], v['old'], v['share'])
        return 'panic' if w[0] == 'panic' else f"setter {w[0]:#x}" + (f" text {w[1][0]:#x}" if w[1] else '')
    if v['token'] >= v['count']:
        return f'arm {BAD_TOKEN:#x}'
    if len(v['text']) > NAME_MAX:
        return f'arm {TOO_LONG:#x}'
    if v['parsed'] is None:
        return 'arm parse error'
    w = share_rule(v['token'], v['count'], v['mode'], v['old'], v['parsed'])
    return f"arm {w[0]:#x}" + (f" text {w[1][0]:#x}" if w[1] else '')


REFERENCE_ROWS = (
    ('differs', 'exchange/handlers/26_spot_deploy.rs set_deployer_trading_fee_share', 'share > 100000 fails, else the token field is written', 'the setter also refuses any share >= the stored one (cannot increase), so an unset share of 0 can only stay 0 outside the legacy rule'),
    ('differs', 'exchange/handlers/26_spot_deploy.rs SetDeployerTradingFeeShare', 'no legacy rule', 'token <= 0xc3 with byte +0x8f2 == 3: a stored 0 may be set to any allowed value, a stored value may not go to 0 (cannot reset legacy token fee share)'),
    ('differs', 'exchange/handlers/26_spot_deploy.rs SpotDeployAction::SetDeployerTradingFeeShare', 'action holds share: u64', 'the action holds text at +0x10, +0x18 (at most 100 bytes) and the arm calls 0x3364cd0 on it; token at +0x20'),
    ('differs', 'dex_registry/perp_dex.rs PerpDexError::InvalidFeeRecipient', 'only the tag and text; no rule', 'tag 0x163 comes from 2 tests: the address has no row in any dex table nor in the map behind 0x3721c10, or it is in the map at exchange +0x8d0'),
    ('differs', 'asset/pdi.rs PdiStatus::DisableUnauthorized', 'status 227 means an unauthorized disable', 'tag 0xe3 text is Invalid perp deployer; the gate gives it to kind 0xe from a non-deployer, tag 0xe4 to others'),
    ('same', 'dex_registry/perp_dex.rs perp_dex_error', 'InvalidFeeRecipient 355, text Invalid perp DEX fee recipient', 'tag 0x163 and the Display arm text'),
    ('same', 'spot_meta.rs MAX_DEPLOYER_TRADING_FEE_SHARE', '100000', 'cmp rcx,0x186a0 in the 3 setters'),
)
# bytes that tie names to offsets; each row is va, hex, meaning.  The tool refuses other bytes.
PINS = (
    (0x233b4ec, '488d352e460afe', 'key lea, oracle_updater', 'lea', 14),
    (0x233b50a, '4180be8800000001', 'cmp byte +0x88, 1: option of oracle_updater', 'cmp', 0),
    (0x233b514, '498d9689000000', 'lea rdx, +0x89: address of oracle_updater', 'lea', 0),
    (0x233b56e, '488d35ba450afe', 'key lea, fee_recipient', 'lea', 13),
    (0x233b588, '4180be9d00000001', 'cmp byte +0x9d, 1: option of fee_recipient', 'cmp', 0),
    (0x233b592, '498d969e000000', 'lea rdx, +0x9e: address of fee_recipient', 'lea', 0),
    (0x233b460, '498d5674', 'lea rdx, +0x74: address after the key deployer', 'lea', 0),
    (0x3706807, '488d4874', 'credit: lea rcx, meta +0x74', 'lea', 0),
    (0x370680b, 'f6809d00000001', 'credit: test byte meta +0x9d, 1', 'test', 0),
    (0x3706812, '488d809e000000', 'credit: lea rax, meta +0x9e', 'lea', 0),
    (0x3706819, '480f45c8', 'credit: cmovne rcx, rax, so the set option wins', 'cmov', 0),
    (0x276838a - 3, '41f6809d00000001', 'abstraction guard reads the same option', 'test', 0),
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


def variant_rows(img):
    """Variant -> dispatch target, sub-deployer kind byte.  Kind entries are `mov al, imm8`, or the join with eax = 0."""
    a = ''.join(VARIANTS).encode()
    b = ''.join(KINDS).encode()
    if not text_hits(img, a) or not text_hits(img, b):
        raise EvidenceError('variant names')
    rows = []
    for i, name_ in enumerate(VARIANTS):
        d = TABLE_DISPATCH + struct.unpack('<i', img.read(TABLE_DISPATCH + 4 * i, 4))[0]
        k = TABLE_KIND + struct.unpack('<i', img.read(TABLE_KIND + 4 * i, 4))[0]
        arm = TABLE_ARM + struct.unpack('<i', img.read(TABLE_ARM + 4 * i, 4))[0]
        code = img.read(k, 2)
        kind = code[1] if code[0] == 0xb0 else 0
        rows.append((i, name_, d, k, kind, KINDS[kind] if kind < len(KINDS) else 'deployer only', arm))
    return rows


def text_hits(img, needle):
    addr_, off, size, _ = img.sec['.rodata']
    blob, out = img.data, []
    i = blob.find(needle, off, off + size)
    while i != -1:
        out.append(addr_ + i - off)
        i = blob.find(needle, i + 1, off + size)
    return out


def recipient_sites(img, starts):
    """Byte census of the option word: test or cmp of byte +0x9d with 1, or a store of 1 to it."""
    addr_, off, size = img.sec['.text'][:3]
    blob, out = img.data, []
    i = blob.find(b'\x9d\x00\x00\x00', off, off + size)
    while i != -1:
        m_ = blob[i - 1]
        if m_ & 0xc0 == 0x80 and m_ & 7 != 4 and blob[i + 4] == 1:
            what = {0xf6: 'test' if m_ >> 3 & 7 == 0 else None, 0x80: 'cmp' if m_ >> 3 & 7 == 7 else None, 0xc6: 'store' if m_ >> 3 & 7 == 0 else None}.get(blob[i - 2])
            if what:
                va = addr_ + i - off - 2
                out.append((va, what, starts[bisect.bisect_right(starts, va) - 1]))
        i = blob.find(b'\x9d\x00\x00\x00', i + 1, off + size)
    return out


def generate(data, out_dir, with_survey=True):
    global SEEN
    GOLD.clear()
    img, code, fdes, slots, got, arms = build(data)
    ctx = (img, code, slots, got)
    listing = {s_: decode_subject(img, s_) for s_ in RANGES}
    listing.update(arms)
    vecs = all_vectors()
    seen = SEEN = set()
    try:
        for v in vecs:
            try:
                msg = check(ctx, v)
            except (Unmodelled, EvidenceError, KeyError) as exc:
                msg = f'fault {type(exc).__name__} {exc}'
            if msg:
                raise EvidenceError(f"mismatch in {v['group']}: {msg}: {[(k, x) for k, x in v.items() if k != '_out']}"[:900])
    finally:
        SEEN = None
    for v in vecs:
        if '_out' in v:
            GOLD[id(v)] = v.pop('_out')
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
    return facts_and_files(data, out_dir, img, fdes, listing, vecs, rows, seen, padding, slots)


def facts_and_files(data, out_dir, img, fdes, listing, vecs, rows, seen, padding, slots):
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
    variants = variant_rows(img)
    with open(out_path / 'variants.tsv', 'w', newline='\n') as f:
        f.write('variant\tname\tdispatch\tkind_entry\tkind\tkind_name\tarm\n')
        for i, n, d, k, kind, kn, arm in variants:
            f.write(f'{i}\t{n}\t{d:#x}\t{k:#x}\t{kind:#x}\t{kn}\t{arm:#x}\n')
    sites = recipient_sites(img, starts)
    with open(out_path / 'recipient-sites.tsv', 'w', newline='\n') as f:
        f.write('site\tuse\tfunction\n')
        for va, what, fn in sites:
            f.write(f'{va:#x}\t{what}\t{fn:#x}\n')
    per = {hex(fn): dict(instructions=len(listing[fn]), executed=sum(i.va in seen for i in listing[fn]), fde=hex(fdes.range_of(fn)['fde']), end=hex(FDE_END[fn])) for fn in RANGES}
    paths = {hex(e): dict(instructions=len(listing[e]), executed=sum(i.va in seen for i in listing[e]), ends=[hex(x) for x in (STOPS.get(e) or ARM_STOPS[e])]) for e in list(ACTIONS) + list(SHARE_ARMS)}
    status = {hex(t): dict(arm=hex(status_arm(img, t)), text=status_text(img, t)) for t in (BAD_RECIPIENT, GONE, BAD_DEPLOYER, BAD_STATUS, TOO_LONG, 0x15)}
    evidence = dict(
        binary=BINARY, sha256=SHA256, functions=per, paths=paths, pins=pins(img),
        copies={hex(c): dict(shift=hex(s['shift']), find=hex(s['find']), abstraction=hex(s['abstraction']), row_get=hex(ROW_TARGET[c])) for c, s in ACTIONS.items()},
        setters={hex(k): dict(mode_byte=hex(x)) for k, x in SETTERS.items()},
        share_arms={hex(k): dict(host=hex(a['host']), setter=hex(a['setter'])) for k, a in SHARE_ARMS.items()},
        gate_slot=dict(slot=hex(SLOT_GATE), value=hex(img.relative(SLOT_GATE)), users=slot_users(img, SLOT_GATE, starts)),
        slots=dict(first=hex(img.relative(SLOT_FIRST)), second=hex(img.relative(SLOT_SECOND)), known=hex(img.relative(SLOT_KNOWN)), parse=hex(img.relative(SLOT_PARSE))),
        names=dict(variants=[hex(x) for x in text_hits(img, ''.join(VARIANTS).encode())], kinds=[hex(x) for x in text_hits(img, ''.join(KINDS).encode())]), status=status, texts=dict(over=img.read(*TEXT_OVER).decode('ascii'), reset=img.read(*TEXT_RESET).decode('ascii'), up=img.read(*TEXT_RAISE).decode('ascii'), abstraction=img.read(*TEXT_ABSTRACT).decode('ascii')),
        location=location(img, LOC_TOKEN), vectors=len(vecs), mismatches=0, groups=groups, outcomes=outcomes, padding_not_executed=padding,
        unexecuted=[dict(start=hex(a), end=hex(b), why=w) for a, b, w in UNEXECUTED.values()], swept=[hex(s) for s in SUBJECTS],
        mutants=len(rows), killed=sum(1 for r in rows if r['killed']), equivalent={hex(k): w for k, w in sorted(EQUIVALENT.items())},
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
