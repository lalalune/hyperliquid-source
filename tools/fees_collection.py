#!/usr/bin/env python3
"""fees: node #94 fee collection path, from bytes alone: dex credit 0x37067b0 and the spot fee sweep in 3 copies.

Static, no execution of the node.  Four functions are decoded from ELF bytes by the table decoder below, each of which
must land exactly on its FDE end.  They are interpreted in Python on every vector and compared with a separate
closed-form model; each byte mutant is then run against the vectors.  Row lookup, set edits, key collection, price,
spot credit, the overflow recorder and panics are stubs that check their arguments.

    python3 tools/fees_collection.py --out <dir>

writes evidence.json, vectors.tsv, mutations.tsv, instructions.tsv, credit-sites.tsv, tree-sites.tsv and
reference-diff.tsv.  Section and FDE parsing come from tools/elf_index.py and tools/fde_extents.py.  Only the standard
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



CREDIT = 0x37067b0
SWEEP_A, SWEEP_B, SWEEP_C = 0x26fe810, 0x4ce76a0, 0x4ce7b90
SWEEPS = (SWEEP_A, SWEEP_B, SWEEP_C)
LAYOUT = {
    SWEEP_A: dict(gate=0x3ac8, dex=0x5c0, tracker=0x5d0, fees=0x710, spot=0x718),
    SWEEP_B: dict(gate=0x4548, dex=0x1040, tracker=0x1050, fees=0x1190, spot=0x1198),
    SWEEP_C: dict(gate=0x3ac8, dex=0x5c0, tracker=0x5d0, fees=0x710, spot=0x718),
}
ROW_GET = 0x3596940
MARK = 0x339b590
UNMARK = 0x33acfe0
KEYS = 0x3bac6e0
DROP = 0x3379490
PRICE = 0x32814c0
SPOT_CREDIT = 0x371d120
SLOT_CREDIT = 0x5774918
SLOT_PX = 0x5774548
SLOT_RECORD = 0x5773190
SLOT_FREE = 0x576e010
SLOT_UNWRAP = 0x576e048
SLOT_NONE = 0x576e470
SLOT_NEG = 0x576eb38
SLOT_ABORT = 0x576e128
NONE_LOCATION = 0x56e9fe8
NEG_LOCATION = 0x5714da0
LOC_TOTAL = 0x570b4f8
LOC_ADD = 0x56f1c50
LOC_SUB = 0x56f1cf8
WIDE = 0x206be0
MIN_F, MAX_F, TOP_F = 0x20acb8, 0x20a7f0, 0x20a2c8
FE = b'\xfe' * 20
I64MAX = (1 << 63) - 1
I64MIN = -(1 << 63)
LIMIT = 0x28f5c28f5c28f5c
CLAMP = 0x147ae147ae147ae
UNWRAP_TEXT = 0x58c079
TWO63 = 2.0 ** 63
MODE_FEE = 3
TREE_FIELD = 0x420
SEEN = None


class Panicked(Exception):
    pass


def addr(n):
    """Distinct bytes, so a shifted read shows."""
    return bytes((n * 37 + k * 11 + 1) & 0xff for k in range(20))


def to_u(x):
    return x & U64


def to_s(x):
    return signed(x & U64, 64)


def sadd(a, b):
    r = a + b
    if r > I64MAX:
        return I64MAX, True
    if r < I64MIN:
        return I64MIN, True
    return r, False


def ssub(a, b):
    r = a - b
    if r > I64MAX:
        return I64MAX, True
    if r < I64MIN:
        return I64MIN, True
    return r, False


def uadd(a, b):
    r = a + b
    return (U64, True) if r > U64 else (r, False)


def trunc(x):
    """The float to integer step: non-finite 0, clamp to 2^63, a top value above 2^63 - 1024 gives i64::MAX."""
    if x != x or x in (math.inf, -math.inf):
        return 0
    y = max(-TWO63, min(TWO63, x))
    return I64MAX if y >= TWO63 else int(y)


def as_float(b):
    return b2f(b)


class Book:
    """The expected ledger of one credit."""

    def __init__(self, v):
        self.bal = dict(v.get('bal', {}))
        self.words = dict(v.get('word', {}))
        self.flip = dict(v.get('flip', {}))
        self.log = []

    def add(self, who, amount):
        self.log.append(('row', who))
        old = self.words.get(who, 0)
        self.log.append(('mark', who))
        new = self.flip.get(who, old)
        self.words[who] = new
        res, over = sadd(to_s(self.bal.get(who, 0)), amount)
        if over:
            self.log.append(('rec', LOC_ADD))
        self.bal[who] = res
        if old and not new:
            self.log.append(('unmark', who))
        elif new and not old:
            self.log.append(('insert', who))


def credit_model(v):
    book = Book(v)
    a, b = v['a'], v['b']
    total, over = sadd(a, b)
    if over:
        book.log.append(('rec', LOC_TOTAL))
    mode = v['mode']
    if mode != MODE_FEE and a >= 0 and b >= 0:
        book.add(v['recipient'] if v.get('flag', 0) & 1 else v['deployer'], a)
        rem = b
    else:
        rem = total
    if mode == MODE_FEE:
        rows = v.get('extra', ())
        n = v.get('len', len(rows))
        if rows and n:
            base = float(rem)
            for k in range(n):
                if k >= len(rows):
                    return dict(book=book, panic='none')
                who, share = rows[k]
                part = trunc(as_float(share) * base)
                rem, over = ssub(rem, part)
                if over:
                    book.log.append(('rec', LOC_SUB))
                book.add(who, part)
        dest = v['dest']
    else:
        dest = FE
    book.add(dest, rem)
    usd = trunc(float(total) * as_float(v['scale']))
    if usd == I64MIN:
        return dict(book=book, panic='neg')
    if abs(usd) > CLAMP:
        usd = CLAMP if usd > 0 else -CLAMP
    res, over = sadd(to_s(v.get('fees', 0)), usd)
    if over:
        book.log.append(('rec', LOC_ADD))
    return dict(book=book, panic=None, fees=res)


def sweep_model(v):
    """Log of one sweep, final words, or the panic that stops it."""
    fn = v['fn']
    log, tree = [], dict(v.get('tree', {}))
    state = dict(fees=to_s(v.get('fees', 0)), spot=to_u(v.get('spot', 0)), dex238=to_s(v.get('dex238', 0)))
    state.update(log=log, tree=tree, panic=None, credits=[])
    if v.get('gate'):
        return state
    log.append(('keys',))
    root = v.get('tree_root', bool(tree))
    prices = v.get('prices', {})
    for t in v['tokens']:
        if not root or t not in tree:
            continue
        val = tree[t]
        if t == 0:
            if val < 100:
                continue
            q = val // 100
            tree[0] = val - q * 100
            if not v.get('dexes', True):
                state['panic'] = 'unwrap'
                return state
            log.append(('drop',))
            state['spot'], over = uadd(state['spot'], q)
            if over:
                log.append(('rec', 'spot token 0'))
            state['dex238'], over = sadd(state['dex238'], q)
            if over:
                log.append(('rec', 'dex'))
            state['credits'].append(q)
            sub = credit_model(dict(v, a=0, b=q, fees=state['fees']))
            log.extend(sub['book'].log)
            state['book'] = sub['book']
            if sub['panic']:
                state['panic'] = sub['panic']
                return state
            state['fees'] = sub['fees']
            continue
        tree[t] = 0
        if t in prices:
            px = prices[t]
        else:
            px = to_u(v.get('default_px', 1) + t)
            log.append(('px', t))
        flag, got = v.get('price', {}).get(t, (1, val))
        log.append(('price', val, t, px))
        use = got if flag & 1 and got < LIMIT else val
        u = use // 100
        state['fees'], over = sadd(state['fees'], u if u <= I64MAX else u - (1 << 64))
        if over:
            log.append(('rec', 'fees'))
        state['spot'], over = uadd(state['spot'], u)
        if over:
            log.append(('rec', 'spot other'))
        log.append(('spot', t, val))
        if v.get('clear'):
            root = False
    return state


def tree64(m, rows, height):
    """BTreeMap<u64, u64>: key +8, value +0x60, count +0xba, edges +0xc0.  Returns the root and every value slot."""
    slots_ = {}

    def build(part, h):
        a = m.arena(0xc0 + (0x60 if h else 0))
        at = a.base
        if h == 0:
            take, kids = part, []
        else:
            cut = min(2, max(1, len(part) - 1))
            step = max(1, len(part) // (cut + 1))
            idx = [min(step * (k + 1) - 1, len(part) - 1) for k in range(cut)] if part else []
            idx = sorted(set(idx))
            take = [part[k] for k in idx]
            kids, lo = [], 0
            for k in idx + [len(part)]:
                kids.append(part[lo:k])
                lo = k + 1
        m.store(at + 0xba, 2, len(take))
        for k, (key, val) in enumerate(take):
            m.store(at + 8 + k * 8, 8, key)
            m.store(at + 0x60 + k * 8, 8, val)
            slots_[key] = at + 0x60 + k * 8
        for k, sub in enumerate(kids):
            m.store(at + 0xc0 + k * 8, 8, build(sub, h - 1))
        return at

    return build(sorted(rows), height), slots_


def tree_extra(m, rows, height):
    """BTreeMap<address, f64> with parent links: parent +0, value +8, key +0x60 stride 20, index +0x13c, count +0x13e."""

    def build(part, h, parent, pos):
        a = m.arena(0x140 + (0x60 if h else 0))
        at = a.base
        if h == 0:
            take, kids = part, []
        else:
            cut = min(2, max(1, len(part) - 1))
            step = max(1, len(part) // (cut + 1))
            idx = sorted({min(step * (k + 1) - 1, len(part) - 1) for k in range(cut)}) if part else []
            take = [part[k] for k in idx]
            kids, lo = [], 0
            for k in idx + [len(part)]:
                kids.append(part[lo:k])
                lo = k + 1
        m.store(at, 8, parent)
        m.store(at + 0x13c, 2, pos)
        m.store(at + 0x13e, 2, len(take))
        for k, (who, share) in enumerate(take):
            m.store_bytes(at + 0x60 + k * 20, who)
            m.store(at + 8 + k * 8, 8, share)
        for k, sub in enumerate(kids):
            m.store(at + 0x140 + k * 8, 8, build(sub, h - 1, at, k))
        return at

    return build(list(rows), height, 0, 0)


def snapshot(*arenas):
    return [bytes(a.mem) for a in arenas]


def set_dex(m, v):
    """A dex row with only the fields the credit reads."""
    d = m.arena(0x2a8)
    row = m.arena(0xb2)
    m.store_bytes(row.base + 0x74, v['deployer'])
    m.store(row.base + 0x9d, 1, v.get('flag', 0))
    m.store_bytes(row.base + 0x9e, v['recipient'])
    m.store(d.base + 0x208, 8, row.base)
    m.store(d.base + 0x230, 1, v['mode'])
    m.store(d.base + 0x2a0, 8, v['scale'])
    return d, row


def set_tracker(m, v, at):
    m.store(at + 0x140, 8, to_u(v.get('fees', 0)))
    if v['mode'] != MODE_FEE:
        return
    m.store_bytes(at + 0xa8, v['dest'])
    rows = v.get('extra', ())
    m.store(at + 0x78, 8, tree_extra(m, rows, v.get('height', 0)) if rows else 0)
    m.store(at + 0x80, 8, v.get('height', 0))
    m.store(at + 0x88, 8, v.get('len', len(rows)))


def credit_stubs(m, v, base, tracker_at, ledger, log):
    s, q = m.slots, m.regs

    def row_of(who):
        if who not in ledger:
            a = m.arena(0x28)
            a.mem[:] = fill_bytes(0x28, 0x71)
            m.store(a.base, 8, to_u(v.get('bal', {}).get(who, 0)))
            m.store(a.base + 0x20, 8, v.get('word', {}).get(who, 0))
            ledger[who] = a
        return ledger[who]

    def spent(at):
        """The address is passed by a pointer to a temporary, which the callee owns: spoil it."""
        m.store_bytes(at, b'\xa5' * 20)

    def get():
        need(q[R['rdi']] == base + 0xf8, 'row map')
        who = m.bytes_at(q[R['rsi']], 20)
        spent(q[R['rsi']])
        log.append(('row', who))
        m.clobber(row_of(who).base)

    def mark():
        who = m.bytes_at(q[R['rsi']], 20)
        spent(q[R['rsi']])
        if q[R['rdi']] == base + 0x188:
            log.append(('mark', who))
            if who in v.get('flip', {}):
                m.store(row_of(who).base + 0x20, 8, v['flip'][who])
        else:
            need(q[R['rdi']] == base + 0x158, 'set field')
            log.append(('insert', who))
        m.clobber()

    def unmark():
        need(q[R['rdi']] == base + 0x158, 'set field')
        log.append(('unmark', m.bytes_at(q[R['rsi']], 20)))
        spent(q[R['rsi']])
        m.clobber()

    def none():
        need(q[R['rdi']] == NONE_LOCATION, 'None location')
        raise Panicked('none')

    def neg():
        need(q[R['rdi']] == NEG_LOCATION, 'negate location')
        raise Panicked('neg')

    m.stubs.update({ROW_GET: get, MARK: mark, UNMARK: unmark, s[SLOT_NONE]: none, s[SLOT_NEG]: neg})


def check_credit(ctx, v):
    m = machine(ctx)
    log, ledger = [], {}
    d, row = set_dex(m, v)
    t = m.arena(0x148)
    set_tracker(m, v, t.base)
    credit_stubs(m, v, d.base, t.base, ledger, log)

    def record():
        need(q[R['rdi']] & 0xff == 0, 'recorder flag')
        log.append(('rec', q[R['rsi']]))
        m.clobber()

    q = m.regs
    m.stubs[m.slots[SLOT_RECORD]] = record
    before = snapshot(d, row, t)
    want = credit_model(v)
    start(m, dict(rdi=d.base, rsi=to_u(v['a']), rdx=to_u(v['b']), rcx=t.base))
    try:
        m.run(CREDIT)
    except Panicked as exc:
        if want['panic'] != str(exc):
            return f'panic {exc}'
    else:
        if want['panic']:
            return 'panic missing'
        if finished(m):
            return 'registers'
        if to_s(m.load(t.base + 0x140, 8)) != want['fees']:
            return 'fees total'
    if log != want['book'].log:
        return 'call log'
    for who, a in ledger.items():
        if to_s(m.load(a.base, 8)) != to_s(want['book'].bal.get(who, 0)):
            return 'balance'
        if m.load(a.base + 0x20, 8) != want['book'].words.get(who, 0):
            return 'row word'
        if bytes(a.mem[8:0x20]) != fill_bytes(0x28, 0x71)[8:0x20]:
            return 'row fill'
    if set(ledger) != {x[1] for x in want['book'].log if x[0] == 'row'}:
        return 'rows touched'
    after = snapshot(d, row, t)
    if after[0] != before[0] or after[1] != before[1]:
        return 'dex row changed'
    if not want['panic']:
        ok = bytearray(before[2])
        ok[0x140:0x148] = after[2][0x140:0x148]
        if bytes(ok) != after[2]:
            return 'tracker changed'
    return None


def check_sweep(ctx, v):
    fn = v['fn']
    lay = LAYOUT[fn]
    m = machine(ctx)
    m.real = {CREDIT: CREDIT}
    q = m.regs
    log, ledger, freed, credits = [], {}, [], []
    s_ = m.arena(0x4600)
    b = s_.base
    m.store(b + lay['gate'], 1, v.get('gate', 0))
    if v.get('dexes', True):
        d, row = set_dex(m, v)
        m.store(d.base + 0x238, 8, to_u(v.get('dex238', 0)))
        m.store(b + lay['dex'], 8, d.base)
        m.store(b + lay['dex'] + 8, 8, 1)
    else:
        d = None
        m.store(b + lay['dex'] + 8, 8, 0)
    m.store(b + lay['spot'], 8, to_u(v.get('spot', 0)))
    set_tracker(m, v, b + lay['tracker'])
    tokens = list(v['tokens'])
    root_words = v.get('keys_root', 0x1234000 if tokens else 0)
    m.store(b + 0x2e0, 8, root_words)
    m.store(b + 0x2e8, 8, 0x77)
    if root_words:
        m.store(b + 0x2f0, 8, 0x55)
    rows = sorted(v.get('tree', {}).items())
    h = v.get('tree_height', 0)
    root = v.get('tree_root', bool(rows))
    vals = {}
    if root:
        r, vals = tree64(m, rows, h)
        m.store(b + 0x420, 8, r)
        m.store(b + 0x428, 8, h)
    else:
        m.store(b + 0x420, 8, 0)
    px_rows = sorted(v.get('prices', {}).items())
    if px_rows:
        r, _ = tree64(m, px_rows, v.get('px_height', 0))
        m.store(b + 0x250, 8, r)
        m.store(b + 0x258, 8, v.get('px_height', 0))
    else:
        m.store(b + 0x250, 8, 0)
    if d is not None:
        credit_stubs(m, v, d.base, b + lay['tracker'], ledger, log)
    leas = [i.ops[1][4] for i in m_listing(ctx, fn) if i.op == 'lea' and i.ops[1][1] is None and i.ops[0] == ('r', R['rsi'], 64)]
    end = FDE_END[fn]

    def record():
        need(q[R['rdi']] & 0xff == 0, 'recorder flag')
        at = q[R['rsi']]
        if fn <= m.cur < end and at in leas:
            log.append(('rec', ('fees', 'spot other', 'spot token 0', 'dex')[leas.index(at)]))
        else:
            log.append(('rec', at))
        m.clobber()

    def keys():
        log.append(('keys',))
        it = q[R['rsi']]
        has = 1 if root_words else 0
        got = tuple(m.load(it + k * 8, 8) for k in range(2)) + (m.load(it + 0x10, 8), m.load(it + 0x18, 8))
        need(got == (has, 0, root_words, 0x77), 'key iterator head')
        got = tuple(m.load(it + 0x20 + k * 8, 8) for k in range(5))
        need(got == (has, 0, root_words, 0x77, 0x55 if has else 0), 'key iterator tail')
        out = q[R['rdi']]
        cap = v.get('cap', len(tokens))
        a = m.arena(max(cap, 1) * 8)
        for k, t in enumerate(tokens):
            m.store(a.base + k * 8, 8, t)
        m.store(out, 8, cap)
        m.store(out + 8, 8, a.base if cap else 8)
        m.store(out + 0x10, 8, len(tokens))
        m.keys_at = a.base
        m.clobber()

    def drop():
        need(m.load(q[R['rdi']], 2) == 0x141, 'status tag')
        log.append(('drop',))
        m.clobber()

    def free():
        freed.append((q[R['rdi']], q[R['rsi']], q[R['rdx']]))
        m.clobber()

    def px():
        need(q[R['rdi']] == b + 0x90, 'price map')
        t = q[R['rsi']]
        log.append(('px', t))
        m.clobber(to_u(v.get('default_px', 1) + t))

    def price():
        need(q[R['rcx']] == b + 0x90, 'price arguments')
        val, t, p = q[R['rdi']], q[R['rsi']], q[R['rdx']]
        log.append(('price', val, t, p))
        flag, got = v.get('price', {}).get(t, (1, val))
        m.clobber(flag)
        q[2] = got

    def spot():
        need(q[R['rdi']] == b + 0x80 and q[R['rcx']] == 0 and q[R['r9']] == 0, 'spot credit arguments')
        need(m.bytes_at(q[R['rsi']], 20) == FE, 'spot credit address')
        log.append(('spot', q[R['rdx']], q[R['r8']]))
        if v.get('clear'):
            m.store(b + 0x420, 8, 0)
        m.clobber()

    def unwrap():
        need(q[R['rdi']] == UNWRAP_TEXT and q[R['rsi']] == 0x2b and m.load(q[R['rdx']], 2) == 0x141, 'unwrap arguments')
        raise Panicked('unwrap')

    s = m.slots
    m.stubs.update({s[SLOT_RECORD]: record, KEYS: keys, DROP: drop, s[SLOT_FREE]: free, s[SLOT_PX]: px, PRICE: price, SPOT_CREDIT: spot, s[SLOT_UNWRAP]: unwrap})
    want = sweep_model(v)
    arenas = [s_] + ([d, row] if d is not None else [])
    before = snapshot(*arenas)
    start(m, dict(rdi=b))
    try:
        m.run(fn)
    except Panicked as exc:
        if want['panic'] != str(exc):
            return f'panic {exc}'
    else:
        if want['panic']:
            return 'panic missing'
        if finished(m):
            return 'registers'
    if log != want['log']:
        return 'call log'
    if not want['panic'] and to_s(m.load(b + lay['fees'], 8)) != want['fees']:
        return 'fees word'
    if m.load(b + lay['spot'], 8) != to_u(want['spot']):
        return 'spot word'
    if d is not None and to_s(m.load(d.base + 0x238, 8)) != want['dex238']:
        return 'dex word'
    for key, at in vals.items():
        if m.load(at, 8) != want['tree'][key]:
            return 'tree value'
    book = want.get('book')
    for who, a in ledger.items():
        if to_s(m.load(a.base, 8)) != to_s(book.bal.get(who, 0)) or m.load(a.base + 0x20, 8) != book.words.get(who, 0):
            return 'balance'
    if not want['panic']:
        after = snapshot(*arenas)
        ok = bytearray(before[0])
        for at, n in [(lay['fees'], 8), (lay['spot'], 8)] + ([(0x420, 8)] if v.get('clear') else []):
            ok[at:at + n] = after[0][at:at + n]
        if bytes(ok) != after[0]:
            return 'state changed'
        if d is not None:
            ok = bytearray(before[1])
            ok[0x238:0x240] = after[1][0x238:0x240]
            if bytes(ok) != after[1] or before[2] != after[2]:
                return 'dex changed'
    if want['panic']:
        return None
    wanted = [(m.keys_at, v.get('cap', len(tokens)) * 8, 0)] if not v.get('gate') and v.get('cap', len(tokens)) else []
    if freed != wanted:
        return 'free'
    return None


LISTINGS = {}


def m_listing(ctx, fn):
    code = ctx[1]
    key = id(code), fn
    if key not in LISTINGS:
        if len(LISTINGS) > 8:
            LISTINGS.clear()
        ends = FDE_END[fn]
        LISTINGS[key] = [i for a, i in sorted(code.items()) if fn <= a < ends]
    return LISTINGS[key]


def check(ctx, v):
    return check_credit(ctx, v) if v['kind'] == 'credit' else check_sweep(ctx, v)


# ---- vectors


NAN = 0x7ff8000000000123
INF = f2b(math.inf)
BIG = (0, 1, 7, 1000, 1 << 40, -1, -5, I64MAX, I64MIN)


def cv(group, **kw):
    v = dict(kind='credit', group=group, a=11, b=22, mode=0, scale=f2b(1.0), deployer=addr(1), recipient=addr(2), dest=addr(3))
    v.update(kw)
    return v


def share_rows(n, base=0.03):
    return tuple((addr(10 + k), f2b(base * (k + 1))) for k in range(n))


def credit_vectors():
    out = []
    for mode in (0, 1, 2, 3):
        for a in BIG:
            for b in BIG:
                out.append(cv('grid', a=a, b=b, mode=mode))
    for mode in (0, 3):
        for s in (0.0, 1e-9, 0.5, 1.0, 1e9, 1e30, -1.0, -1e30, 1.7976931348623157e308):
            out.append(cv('scale', a=5000, b=7000, mode=mode, scale=f2b(s)))
        for s in (NAN, INF, f2b(-math.inf)):
            out.append(cv('scale bits', a=5000, b=7000, mode=mode, scale=s))
    for total in (CLAMP - 1, CLAMP, CLAMP + 1, CLAMP + 5000, -(CLAMP - 1), -CLAMP, -CLAMP - 1, -CLAMP - 5000, 1 << 62, -(1 << 62)):
        out.append(cv('clamp', a=0, b=total))
        out.append(cv('clamp', a=total, b=0, mode=3))
    for x in (I64MAX, I64MIN, -(1 << 62), (1 << 62)):
        for s in (2.0, 4.0, 1e30, -2.0, -4.0, -1e30):
            out.append(cv('float limits', a=x, b=0, scale=f2b(s)))
    for s in (1.0, 0.9999999999999999, 1.0000000000000002):
        out.append(cv('top', a=I64MAX, b=0, scale=f2b(s)))
        out.append(cv('top', a=I64MAX - 511, b=0, scale=f2b(s)))
        out.append(cv('top', a=I64MAX - 1024, b=0, scale=f2b(s)))
    for fees in (I64MAX, I64MAX - 5, I64MIN, I64MIN + 5, 1 << 62):
        for a, b in ((3, 4), (-3, -4), (0, 0), (CLAMP, CLAMP)):
            out.append(cv('fees word', a=a, b=b, fees=fees))
            out.append(cv('fees word', a=a, b=b, fees=fees, mode=3))
    who = addr(1)
    for bal in (I64MAX, I64MAX - 2, I64MIN, I64MIN + 2, 77):
        out.append(cv('balance', a=5, b=6, bal={who: bal}))
        out.append(cv('balance', a=5, b=6, flag=1, bal={addr(2): bal}))
        out.append(cv('balance', a=5, b=6, bal={FE: bal}))
        out.append(cv('balance', a=-5, b=6, bal={FE: bal}))
        out.append(cv('balance', a=-5, b=-6, bal={FE: bal}))
        out.append(cv('balance', a=5, b=6, mode=3, bal={addr(3): bal}))
        out.append(cv('balance', a=5, b=6, mode=3, extra=share_rows(2), bal={addr(10): bal}))
    for flag in (0, 1, 2, 3, 0xfe, 0xff):
        out.append(cv('flag', flag=flag))
    for mode in (0, 2, 3, 4, 7, 0xff, 0x83):
        out.append(cv('mode', mode=mode, extra=share_rows(2) if mode == 3 else ()))
    for old in (0, 5):
        for new in (0, 5, 9):
            for who, kw in ((addr(1), {}), (FE, {}), (addr(3), dict(mode=3)), (addr(10), dict(mode=3, extra=share_rows(2)))):
                out.append(cv('flag word', word={who: old}, flip={who: new}, **kw))
    for n in range(1, 13):
        for h in (0, 1, 2) if n < 12 else (1, 2):
            out.append(cv('list', a=4000, b=9000, mode=3, extra=share_rows(n), height=h))
            out.append(cv('list', a=-4000, b=-9000, mode=3, extra=share_rows(n), height=h))
    for s in (0.0, 1.0, 1.5, -0.5, 1e300, -1e300, 1e-300):
        out.append(cv('share', a=0, b=1 << 40, mode=3, extra=((addr(10), f2b(s)), (addr(11), f2b(0.25)))))
        out.append(cv('share', a=0, b=-(1 << 40), mode=3, extra=((addr(10), f2b(s)), (addr(11), f2b(0.25)))))
    for s in (NAN, INF, f2b(-math.inf)):
        out.append(cv('share bits', a=0, b=1 << 40, mode=3, extra=((addr(10), s), (addr(11), f2b(0.25)))))
    out.append(cv('share floor', a=0, b=1000, mode=3, extra=((addr(10), f2b(0.3333)), (addr(11), f2b(0.3333)), (addr(12), f2b(0.3333)))))
    out.append(cv('share floor', a=0, b=-1000, mode=3, extra=((addr(10), f2b(0.3333)), (addr(11), f2b(0.3333)), (addr(12), f2b(0.3333)))))
    out.append(cv('rest overflow', a=0, b=I64MIN + 10, mode=3, extra=((addr(10), f2b(-1.0)), (addr(11), f2b(2.0)))))
    out.append(cv('rest overflow', a=0, b=I64MAX - 10, mode=3, extra=((addr(10), f2b(-1.0)), (addr(11), f2b(2.0)))))
    out.append(cv('rest overflow', a=0, b=I64MAX, mode=3, extra=((addr(10), f2b(-1e300)), )))
    out.append(cv('list words', a=0, b=1000, mode=3, extra=(), len=5))
    out.append(cv('list words', a=0, b=1000, mode=3, extra=share_rows(3), len=0))
    out.append(cv('list words', a=0, b=1000, mode=3, extra=share_rows(3), len=2))
    for h in (0, 1, 2):
        out.append(cv('list panic', a=0, b=1000, mode=3, extra=share_rows(3), len=4, height=h))
    out.append(cv('same address', a=5, b=6, mode=3, extra=((addr(3), f2b(0.5)), (addr(10), f2b(0.25)))))
    out.append(cv('same address', a=5, b=6, deployer=FE))
    out.append(cv('same address', a=5, b=6, flag=1, recipient=FE))
    for n in range(1, 13):
        out.append(cv('flag word list', a=0, b=8000, mode=3, extra=share_rows(n), height=1, word={addr(10 + n - 1): 3}, flip={addr(10 + n - 1): 0}))
        out.append(cv('flag word list', a=0, b=8000, mode=3, extra=share_rows(n), height=2, flip={addr(10 + n - 1): 4}))
    top = 1.7976931348623157e308
    for x in (top, -top, 1.7e308, -1.7e308):
        out.append(cv('near infinity', a=0, b=1, scale=f2b(x)))
        out.append(cv('near infinity', a=0, b=1, mode=3, extra=((addr(10), f2b(x)),)))
    for s_ in (0.75, 0.5, 0.25, -0.75):
        out.append(cv('large part', a=0, b=1 << 62, mode=3, extra=((addr(10), f2b(s_)),)))
    out.append(cv('large part', a=0, b=I64MAX, mode=3, extra=((addr(10), f2b(0.75)),)))
    out.append(cv('large part', a=0, b=I64MAX, mode=3, extra=((addr(10), f2b(0.9)),)))
    for h in (3, 7, 8, 9, 10, 16, 17):
        out.append(cv('tall', a=0, b=8000, mode=3, extra=share_rows(3), height=h))
        out.append(cv('tall', a=0, b=8000, mode=3, extra=share_rows(5), height=h))
    for bal in (I64MAX, I64MIN):
        for b in (1 << 40, -(1 << 40)):
            out.append(cv('balance list', a=0, b=b, mode=3, extra=share_rows(2), bal={addr(10): bal}))
            out.append(cv('balance list', a=0, b=b, mode=3, extra=share_rows(2), bal={addr(11): bal}))
    return out


def sv(fn, group, **kw):
    v = dict(kind='sweep', fn=fn, group=f'{fn:#x} {group}', mode=0, scale=f2b(1.0), deployer=addr(1), recipient=addr(2), dest=addr(3), tokens=(0,), tree={0: 1000})
    v.update(kw)
    return v


def sweep_vectors():
    out = []
    keys11 = {k * 7 + 1: 1000 + k for k in range(11)}
    for fn in SWEEPS:
        s = lambda g, **kw: out.append(sv(fn, g, **kw))
        s('gate', gate=1)
        s('gate', gate=2)
        s('gate', gate=0xff, tokens=(0, 5), tree={0: 500, 5: 9})
        s('no keys', tokens=(), keys_root=0)
        s('no keys', tokens=(), keys_root=0x77, cap=0)
        s('no keys', tokens=(), keys_root=0x77, cap=3)
        s('no tree', tokens=(0, 5), tree={}, cap=2)
        s('no tree', tokens=(5,), tree={5: 300}, tree_root=False)
        s('miss', tokens=(9,), tree={0: 1000})
        s('miss', tokens=(1, 2, 3), tree={5: 100, 7: 200})
        s('miss', tokens=(100,), tree=keys11)
        s('miss', tokens=(100,), tree=keys11, tree_height=1)
        s('miss', tokens=(100,), tree=keys11, tree_height=2)
        for val in (0, 1, 99, 100, 101, 199, 200, 12345, 1 << 40, I64MAX, U64):
            s('token 0', tree={0: val})
            s('token 0 mode 3', tree={0: val}, mode=3, extra=share_rows(2))
        s('token 0 spot word', tree={0: 1000}, spot=U64 - 3)
        s('token 0 spot word', tree={0: 1000}, spot=U64 - 10)
        s('token 0 dex word', tree={0: 1000}, dex238=I64MAX - 3)
        s('token 0 dex word', tree={0: 1000}, dex238=I64MAX - 10)
        s('token 0 dex word', tree={0: 1000}, dex238=I64MIN + 2, fees=9)
        s('token 0 fees word', tree={0: 1000}, fees=I64MAX - 2)
        s('no dex', dexes=False)
        s('no dex', dexes=False, tree={0: 99})
        s('no dex', dexes=False, tree={0: 5000, 4: 77}, tokens=(4, 0), spot=9)
        s('list panic', tree={0: 1000}, mode=3, extra=share_rows(3), len=5)
        for val in (0, 1, 99, 100, 1000, 1 << 40, I64MAX, U64):
            s('other', tokens=(5,), tree={5: val}, prices={5: 3})
            s('other no price', tokens=(5,), tree={5: val}, default_px=40)
        for flag in (0, 1, 2, 3, 0xff):
            for got in (0, 99, 100, 5000, LIMIT - 1, LIMIT, LIMIT + 1, U64):
                s('price flag', tokens=(5,), tree={5: 2000}, prices={5: 3}, price={5: (flag, got)})
        s('other fees word', tokens=(5,), tree={5: 2000}, fees=I64MAX - 3)
        s('other fees word', tokens=(5,), tree={5: 2000}, fees=I64MAX - 30)
        s('other fees word', tokens=(5,), tree={5: 2000}, fees=I64MIN)
        s('other spot word', tokens=(5,), tree={5: 2000}, spot=U64 - 3)
        s('other spot word', tokens=(5,), tree={5: 2000}, spot=U64 - 30)
        s('both words', tokens=(5,), tree={5: 2000}, spot=U64 - 3, fees=I64MAX - 3)
        s('order', tokens=(3, 0, 7), tree={0: 950, 3: 400, 7: 700}, prices={3: 2, 7: 8})
        s('order', tokens=(7, 3, 0), tree={0: 950, 3: 400, 7: 700}, prices={3: 2})
        s('repeat', tokens=(0, 0, 5, 5), tree={0: 950, 5: 400}, prices={5: 2})
        s('repeat', tokens=(0, 0), tree={0: 100})
        s('wide', tokens=(U64, 1 << 63, 1), tree={U64: 300, 1 << 63: 400, 1: 500}, prices={U64: 1, 1: 7})
        s('wide', tokens=(U64,), tree={U64: 300, 1 << 63: 400, 1: 500}, prices={1 << 63: 7})
        for h in (0, 1, 2):
            s('trees', tokens=tuple(sorted(keys11)), tree=keys11, tree_height=h, prices={k: k + 1 for k in keys11 if k % 2}, px_height=h)
            s('trees', tokens=tuple(sorted(keys11)), tree=keys11, tree_height=h, prices={k: k + 1 for k in keys11 if k % 2 == 0}, px_height=h)
            s('px miss', tokens=(8,), tree={8: 500}, prices={k: k + 1 for k in keys11 if k != 8}, px_height=h)
        s('root cleared', tokens=(5, 6, 7), tree={5: 300, 6: 400, 7: 500}, prices={5: 1, 6: 1, 7: 1}, clear=True)
        s('cap', tokens=(0, 5), tree={0: 500, 5: 600}, prices={5: 1}, cap=9)
    return out


def all_vectors():
    return credit_vectors() + sweep_vectors()


# ---- binding


FDE_END = {}
RANGES = {}
SUBJECTS = (CREDIT,) + SWEEPS


def build(data):
    check_digest(data)
    fdes = Fdes(data)
    img = Image(data)
    listing, code = {}, {}
    for fn in SUBJECTS:
        FDE_END[fn] = fdes.range_of(fn)['end']
        RANGES[fn] = ((fn, FDE_END[fn]),)
        rows = decode_range(img, fn, FDE_END[fn])
        listing[fn] = rows
        code.update({i.va: i for i in rows})
    slots, got = scan_slots(img, code)
    return img, code, fdes, slots, got, listing


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
        at = ins.size - n + (4 if n == 8 else 0)
        out.append(dict(kind='immediate', fn=fn, va=ins.va, op=show(ins), patch={ins.va + at: ins.raw[at] ^ 1}))
    return out


def constant_sites(fn, listing, img):
    """Bytes of each .rodata constant the function reads: the top byte of the f64 mantissa side."""
    out = []
    for ins in listing:
        for o in ins.ops:
            if o[0] == 'm' and o[1] is None and o[2] is None and img.in_rodata(o[4], 8) and ins.op in ('ucomisd', 'mulsd', 'movsd', 'divsd'):
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
    picked = list(vecs)
    for s_ in sites:
        mimg = Image(data, s_['patch'])
        mcode = dict(code)
        fn = s_['fn']
        try:
            mcode.update({i.va: i for i in decode_subject(mimg, fn)})
        except (EvidenceError, Unmodelled, IndexError, struct.error) as exc:
            rows.append(dict(s_, killed=('decoder', str(exc)[:60].replace('\t', ' '))))
            continue
        rows.append(dict(s_, killed=try_kill((mimg, mcode, slots, got), picked)))
        if PROGRESS and not rows[-1]['killed']:
            print('survivor', hex(s_['va']), s_['kind'], s_['op'], flush=True)
    return rows


WORKERS = 3
PROGRESS = False
NO_RETURN = 'unreachable: follows a call that does not return'
UNWIND = 'unwind clean-up after a panic in a callee, not a modelled outcome'
DEAD_JUMP = 'unreachable: the count is non-zero and a multiple of 8 here, so the jae before this jump is always taken'
GAPS = ((0x3706d6d, 0x3706d72, DEAD_JUMP), (0x3706d7f, 0x3706d84, DEAD_JUMP), (0x3706fef, 0x3706ff1, NO_RETURN), (0x3706ffe, 0x3707000, NO_RETURN),
        (0x26fecc0, 0x26fecc2, NO_RETURN), (0x26fecc2, 0x26fecfe, UNWIND), (0x4ce7b50, 0x4ce7b52, NO_RETURN), (0x4ce7b52, 0x4ce7b8e, UNWIND),
        (0x4ce8040, 0x4ce8042, NO_RETURN), (0x4ce8042, 0x4ce807e, UNWIND))
SITE_STEP = 1
CLAMP_JUMP = 'skipping the clamp changes nothing: cvttsd2si gives i64::MIN below -2^63 and the top compare gives i64::MAX above'
LOW_BOUND = 'the mutant bound is -2^64; values between it and -2^63 convert to i64::MIN either way'
HIGH_BOUND = 'the mutant bound is 2^64; values between it and 2^63 still pass the top compare and give i64::MAX'
ODD_COUNT = 'this path has a non-zero low 3 bits, so the count is never 8 and 8 and 9 divide it the same way'
NEVER_NAN = 'the value is 0 for non-finite input and clamped otherwise, so the parity branch never keeps this register'
EQUIVALENT = {
    0x3706c08: CLAMP_JUMP, 0x3706c12: CLAMP_JUMP, 0x3706ee4: CLAMP_JUMP, 0x3706eee: CLAMP_JUMP,
    0x3706bfc: LOW_BOUND, 0x3706c20: LOW_BOUND, 0x3706ed8: LOW_BOUND,
    0x3706c0a: HIGH_BOUND, 0x3706c2c: HIGH_BOUND, 0x3706ee6: HIGH_BOUND, 0x3706efa: HIGH_BOUND,
    0x3706a85: ODD_COUNT, 0x3706b58: ODD_COUNT, 0x3706c50: NEVER_NAN,
}


def gaps():
    return list(GAPS)


def all_sites(listing, img):
    sites = []
    for fn in SUBJECTS:
        rows = listing[fn]
        sites += conditional_sites(fn, rows) + field_sites(fn, rows) + imm_sites(fn, rows) + constant_sites(fn, rows, img)
    g = gaps()
    return [x for x in sites if not any(a <= x['va'] < b for a, b, _ in g)][::SITE_STEP]


def survey(data, code, slots, got, listing, vecs, img):
    sites = all_sites(listing, img)
    parts = [sites[i::WORKERS] for i in range(WORKERS)]
    jobs = [(data, code, slots, got, p, vecs) for p in parts]
    with multiprocessing.get_context('fork').Pool(WORKERS) as pool:
        got_rows = pool.map(survey_part, jobs)
    rows = [r for part in got_rows for r in part]
    rows.sort(key=lambda r: (r['va'], r['kind'], sorted(r['patch'])))
    return rows


def section_range(img):
    addr_, off, size = img.sec['.text'][:3]
    return addr_, off, size


def direct_sites(img, targets, starts):
    """Calls to each of `targets`: e8 rel32 in .text, one pass."""
    addr_, off, size = section_range(img)
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


def slot_sites(img, slot, starts):
    """`call [rip+d]` through `slot`: ff 15 rel32 in .text."""
    addr_, off, size = section_range(img)
    blob, out = img.data, []
    i = blob.find(b'\xff\x15', off, off + size)
    while i != -1 and i + 6 <= off + size:
        va = addr_ + i - off
        if va + 6 + struct.unpack_from('<i', blob, i + 2)[0] == slot:
            out.append(dict(site=hex(va), function=hex(starts[bisect.bisect_right(starts, va) - 1])))
        i = blob.find(b'\xff\x15', i + 1, off + size)
    return out


def slots_holding(img, value):
    _, off, size, _ = img.sec['.rela.dyn']
    out = []
    for i in range(0, size - 23, 24):
        slot, info, add = struct.unpack_from('<QQQ', img.data, off + i)
        if info == 8 and add == value:
            out.append(slot)
    return out


def tree_sites(img, spot_calls, starts):
    """`lea r64, [r64 + 0x420]` in functions with a direct call of the spot balance writer."""
    addr_, off, size = section_range(img)
    blob = img.data
    hosts = {x['function'] for x in spot_calls}
    needle = struct.pack('<I', TREE_FIELD)
    calls_at = {int(x['site'], 16) for x in spot_calls}
    out = []
    i = blob.find(needle, off, off + size)
    while i != -1:
        va = addr_ + i - off
        if blob[i - 2] == 0x8d and blob[i - 3] in (0x48, 0x49, 0x4c, 0x4d) and blob[i - 1] >> 6 == 2 and blob[i - 1] & 7 != 4:
            fn = hex(starts[bisect.bisect_right(starts, va) - 1])
            if fn in hosts:
                at = va - 3
                out.append(dict(site=hex(at), function=fn, bytes=blob[i - 3:i + 4].hex(), after_spot_call=at - 5 in calls_at))
        i = blob.find(needle, i + 1, off + size)
    return out


def location(img, va):
    """Panic Location: keep the path from `l1/src/` only, plus its full length."""
    start_ = img.relative(va)
    length = struct.unpack('<Q', img.read(va + 8, 8))[0]
    line, col = struct.unpack('<II', img.read(va + 16, 8))
    path = img.read(start_, length).decode('ascii')
    for mark in ('l1/src/', 'chrono-', 'library/'):
        if mark in path:
            path = path[path.index(mark):]
    return dict(path=path, path_bytes=length, line=line, column=col)


PINS = (
    ('credit: mode compare', 0x37067df, '3c03'),
    ('credit: recipient flag and second address', 0x370680b, 'f6809d00000001488d809e000000'),
    ('credit: 20 bytes of 0xfe', 0x3706dd9, '660f2805fffdaffc'),
    ('sweep: token 0 keeps below 100', 0x26fea54, '4883fd64'),
    ('sweep: tree value read', 0x26fe990, '488b6cf160'),
    ('sweep: tree value cleared', 0x26fe99e, '48c744f16000000000'),
    ('sweep: limit', 0x26feb21, '48b95c8fc2f5285c8f02'),
    ('sweep: status tag', 0x26fea86, '66c74424304101'),
    ('schedule: destination offset', 0x1e87642, '488d8ba8000000'),
    ('schedule: destination key', 0x1e87649, '488d35ec8153fe'),
    ('schedule: fractions offset', 0x1e87668, '488d7378'),
    ('schedule: fractions key', 0x1ebd6e4, '488d35252450fe'),
    ('tracker: total_fees_collected offset', 0x2338521, '488d8b40010000'),
    ('tracker: total_spot_fees_collected offset', 0x233854f, '488d8b48010000'),
)
KEYS_TEXT = (
    ('destination', 0x3bf83c, 'fee schedule +0xa8, serializer 0x1e87500'),
    ('extra_destination_fractions', 0x3bfb10, 'fee schedule +0x78, field writer 0x1ebd6d0'),
    ('total_fees_collected', 0x3dffcb, 'tracker +0x140, serializer 0x23382e0'),
    ('total_spot_fees_collected', 0x3dffdf, 'tracker +0x148, serializer 0x23382e0'),
)
FIELD_ROWS = (
    ('dex +0x230', 'byte, compared with 3 only', 'not named here'),
    ('dex +0x2a0', 'f64 multiplier of the total', 'usdc_ntl_scale in usdc-ntl-scale work'),
    ('dex +0x238', 'signed word, token 0 sweep adds q', 'not named here'),
    ('dex +0x208', 'pointer to a row: address +0x74, flag +0x9d, address +0x9e', 'not named here'),
    ('tracker +0x78', 'B-tree address to f64', 'extra_destination_fractions'),
    ('tracker +0xa8', '20 bytes, the rest goes here in mode 3', 'destination'),
    ('tracker +0x140', 'signed, adds the clamped total of every credit', 'total_fees_collected'),
    ('tracker +0x148', 'unsigned, adds q or u in the sweep', 'total_spot_fees_collected'),
    ('state +0x420', 'B-tree token to u64, swept each step', 'not named here'),
    ('state +0x250', 'B-tree token to u64, read as the third price argument', 'not named here'),
    ('state +gate', 'byte, non-zero skips the whole sweep', 'not named here'),
)
REFERENCE_ROWS = (
    ('absent', 'references/can1357-hl/l1/fees/compute.rs', 'gross, rebate and protocol inputs, recipient maps by user', 'no credit to a deployer, destination or 0xfe row'),
    ('absent', 'whole reference tree', 'no text extra_destination', 'tracker +0x78 B-tree splits the protocol amount by f64 fractions'),
    ('absent', 'whole reference tree', 'no 20-byte 0xfe constant', 'the rest in modes other than 3 and all other-token fees go to that address'),
    ('absent', 'references/can1357-hl/l1/raw_vlm.rs and scaled_vlm.rs', 'no fee total word', 'tracker +0x140 and +0x148 move only here among the sites scanned'),
)


def pinned(img):
    """Constants the model relies on, re-read; any change stops the tool."""
    got_ = dict(min=img.f64(MIN_F), max=img.f64(MAX_F), top=img.f64(TOP_F), wide=img.read(WIDE, 16).hex())
    if got_ != dict(min=-TWO63, max=TWO63, top=TWO63 - 1024, wide='fe' * 16):
        raise EvidenceError(f'constants {got_}')
    pins = []
    for label, va, text in PINS:
        want = bytes.fromhex(text.replace(' ', ''))
        if img.read(va, len(want)) != want:
            raise EvidenceError(f'pin {label}')
        pins.append(dict(what=label, va=hex(va), bytes=want.hex()))
    keys = []
    for text, va, where in KEYS_TEXT:
        if img.read(va, len(text)) != text.encode():
            raise EvidenceError(f'key {text}')
        keys.append(dict(text=text, va=hex(va), where=where))
    return got_, pins, keys


def facts_and_files(data, out_dir, img, fdes, listing, vecs, rows, seen, padding, slots):
    constants, pins, keys = pinned(img)
    starts = sorted(f['start'] for f in eh_frame_records(data)[1])
    out_path = Path(out_dir)
    out_path.mkdir(parents=True, exist_ok=True)
    groups, outcomes = {}, {}
    with open(out_path / 'vectors.tsv', 'w', newline='\n') as f:
        f.write('kind\tgroup\tstate\toutcome\n')
        for v in vecs:
            key = v['kind'] + ' ' + v['group']
            groups[key] = groups.get(key, 0) + 1
            name = outcome_of(v)
            outcomes[name] = outcomes.get(name, 0) + 1
            f.write(f"{v['kind']}\t{v['group']}\t{digest_of(v)}\t{name}\n")
    with open(out_path / 'mutations.tsv', 'w', newline='\n') as f:
        f.write('kind\tva\tinstruction\tresult\tvector\treason\n')
        for r in rows:
            k = r['killed']
            if k:
                f.write(f"{r['kind']}\t{r['va']:#x}\t{r['op']}\tkilled\t{k[0]}\t{k[1]}\n")
            elif r['va'] in EQUIVALENT:
                f.write(f"{r['kind']}\t{r['va']:#x}\t{r['op']}\tequivalent\t\t{EQUIVALENT[r['va']]}\n")
            else:
                f.write(f"{r['kind']}\t{r['va']:#x}\t{r['op']}\tunclassified\t\tsurvived every vector, not reviewed\n")
    with open(out_path / 'instructions.tsv', 'w', newline='\n') as f:
        f.write('function\tva\tsize\tbytes\tdecoded\texecuted\n')
        for fn in SUBJECTS:
            for i in listing[fn]:
                f.write(f'{fn:#x}\t{i.va:#x}\t{i.size}\t{i.raw.hex()}\t{show(i)}\t{int(i.va in seen)}\n')
    with open(out_path / 'reference-diff.tsv', 'w', newline='\n') as f:
        f.write('verdict\treference\treference_says\tbytes_say\n')
        for row_x in REFERENCE_ROWS:
            f.write('\t'.join(row_x) + '\n')
    credit_calls = slot_sites(img, SLOT_CREDIT, starts)
    with open(out_path / 'credit-sites.tsv', 'w', newline='\n') as f:
        f.write('site\tfunction\n')
        for x in credit_calls:
            f.write(f"{x['site']}\t{x['function']}\n")
    direct = direct_sites(img, SWEEPS + (SPOT_CREDIT,), starts)
    trees = tree_sites(img, direct[SPOT_CREDIT], starts)
    with open(out_path / 'tree-sites.tsv', 'w', newline='\n') as f:
        f.write('site\tfunction\tbytes\tafter_spot_call\n')
        for x in trees:
            f.write(f"{x['site']}\t{x['function']}\t{x['bytes']}\t{int(x['after_spot_call'])}\n")
    funcs = []
    for fn in SUBJECTS:
        funcs.append(dict(start=hex(fn), end=hex(FDE_END[fn]), fde=hex(fdes.range_of(fn)['fde']), instructions=len(listing[fn]), executed=sum(i.va in seen for i in listing[fn])))
    recorders = {}
    for fn in SWEEPS:
        leas = [i.ops[1][4] for i in listing[fn] if i.op == 'lea' and i.ops[1][1] is None and i.ops[0] == ('r', R['rsi'], 64)]
        recorders[hex(fn)] = [dict(zip(('adds',), (n,)), **location(img, at), location=hex(at)) for n, at in zip(('fees', 'spot other', 'spot token 0', 'dex'), leas)]
    evidence = dict(
        binary=BINARY, sha256=SHA256, functions=funcs, constants=constants, pins=pins, keys=keys, layout={hex(k): x for k, x in sorted(LAYOUT.items())},
        fields=[dict(zip(('at', 'seen', 'name'), x)) for x in FIELD_ROWS], credit_slots=[hex(x) for x in slots_holding(img, CREDIT)], credit_calls=len(credit_calls),
        sweep_callers={hex(k): direct[k] for k in SWEEPS}, spot_credit_calls=len(direct[SPOT_CREDIT]), tree_sites=len(trees), tree_sites_after_spot_call=sum(1 for x in trees if x['after_spot_call']),
        credit_recorders={'total': location(img, LOC_TOTAL), 'add': location(img, LOC_ADD), 'sub': location(img, LOC_SUB)}, sweep_recorders=recorders,
        panics={'none': location(img, NONE_LOCATION), 'negate': location(img, NEG_LOCATION), 'unwrap_text': img.read(UNWRAP_TEXT, 0x2b).decode('ascii')},
        slots={hex(s): hex(slots[s]) for s in (SLOT_CREDIT, SLOT_PX, SLOT_RECORD, SLOT_FREE, SLOT_UNWRAP, SLOT_NONE, SLOT_NEG)},
        vectors=len(vecs), mismatches=0, groups=groups, outcomes=outcomes, padding_not_executed=padding,
        unexecuted=[dict(start=hex(a), end=hex(b), why=w) for a, b, w in gaps()],
        mutants=len(rows), killed=sum(1 for r in rows if r['killed']), unclassified=sum(1 for r in rows if not r['killed'] and r['va'] not in EQUIVALENT), site_step=SITE_STEP, equivalent={hex(k): w for k, w in sorted(EQUIVALENT.items()) if any(r['va'] == k for r in rows)},
    )
    with open(out_path / 'evidence.json', 'w', newline='\n') as f:
        json.dump(evidence, f, indent=1, sort_keys=True)
        f.write('\n')
    return evidence


def outcome_of(v):
    if v['kind'] == 'credit':
        w = credit_model(v)
        if w['panic']:
            return 'panic ' + w['panic']
        return 'mode 3' if v['mode'] == MODE_FEE else 'deployer' if v['a'] >= 0 and v['b'] >= 0 else 'all to fe'
    w = sweep_model(v)
    if w['panic']:
        return 'panic ' + w['panic']
    return 'skipped' if v.get('gate') else f"swept {sum(1 for x in w['log'] if x[0] == 'spot') + (1 if w['credits'] else 0)}"


def digest_of(v):
    return hashlib.sha256(repr(sorted((k, repr(sorted(x.items()) if isinstance(x, dict) else x)) for k, x in v.items())).encode()).hexdigest()[:16]


def run_vectors(ctx, vecs):
    for v in vecs:
        try:
            msg = check(ctx, v)
        except (Unmodelled, EvidenceError, KeyError) as exc:
            msg = f'fault {type(exc).__name__} {exc}'
        if msg:
            raise EvidenceError(f"mismatch in {v['kind']} {v['group']}: {msg} {sorted((k, x) for k, x in v.items() if k not in ('deployer', 'recipient', 'dest', 'kind', 'group'))!r}"[:400])


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
    for fn in SUBJECTS:
        for ins in listing[fn]:
            if ins.va in seen:
                continue
            if ins.op in ('nop', 'int3'):
                padding += 1
            elif not any(a <= ins.va < b for a, b, _ in g):
                missing.append(hex(ins.va))
    if missing:
        raise EvidenceError(f'unlisted unexecuted instructions {len(missing)}: {missing}')
    rows = survey(data, code, slots, got, listing, vecs, img) if with_survey else []
    survivors = {r['va'] for r in rows if not r['killed']}
    tried = {r['va'] for r in rows}
    if (set(EQUIVALENT) & tried) - survivors:
        raise EvidenceError(f'killed but listed equivalent: {sorted(hex(s_) for s_ in (set(EQUIVALENT) & tried) - survivors)}')
    return facts_and_files(data, out_dir, img, fdes, listing, vecs, rows, seen, padding, slots)


def main():
    ap = argparse.ArgumentParser(description=__doc__.split('\n')[0])
    ap.add_argument('--out', required=True)
    args = ap.parse_args()
    data = (ROOT / BINARY).read_bytes()
    ev = generate(data, args.out)
    print(json.dumps(dict(vectors=ev['vectors'], mutants=ev['mutants'], killed=ev['killed'], unclassified=ev['unclassified']), sort_keys=True))


if __name__ == '__main__':
    main()
