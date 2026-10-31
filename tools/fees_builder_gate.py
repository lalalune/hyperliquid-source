#!/usr/bin/env python3
"""fees: node #94 builder fee admission in the two order parsers, from bytes alone.

Static, no execution of the node.  The 6 parser copies, both B-tree lookup copies and the master account lookup
0x36f3ed0 are decoded from ELF bytes by the table decoder below, which must land exactly on each FDE end, and
interpreted in Python on every vector.  Everything else they call is a stub that checks its arguments.  Each outcome
is compared with a separate closed-form model, then every conditional, field offset and immediate of the gate ranges
of 0x1ea3140 and 0x1ea3f60, of the lookup 0x284b9f0 and of the master lookup is mutated to test the vectors.

    python3 tools/fees_builder_gate.py --out <dir>

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


PERP = 0x1ea3140
SPOT = 0x1ea3f60
PERP_B = 0x4322ca0
PERP_C = 0x43255e0
SPOT_B = 0x4323b40
SPOT_C = 0x4324890
TREE_FIND = 0x284b9f0
TREE_FIND_B = 0x4927d70
MASTER = 0x36f3ed0
ENTRIES = (PERP, SPOT, PERP_B, PERP_C, SPOT_B, SPOT_C)
PERP_LIKE = (PERP, PERP_B, PERP_C)
WHOLE = ENTRIES + (TREE_FIND, TREE_FIND_B, MASTER)
SHIFT = 0xa80
HASH_A = 0x2840fb0
HASH_B = 0x473bf50
DRAIN_A = 0x2876550
DRAIN_B = 0x494ff90
SHAPE = {
    PERP: dict(spot=False, base=0, row=0x21f7c40, notional=0x2511900, amount=0x27240b0, hash=HASH_A, drain=DRAIN_A),
    SPOT: dict(spot=True, base=0, row=0x21f8520, notional=0x2510e90, amount=0x2723c70, hash=HASH_A, drain=DRAIN_A),
    PERP_B: dict(spot=False, side_slot=True, base=SHIFT, row=0x4c18b40, notional=0x486dd90, amount=0x4d29bf0, hash=HASH_B, drain=DRAIN_B),
    PERP_C: dict(spot=False, side_slot=True, base=0, row=0x4c18260, notional=0x486b3e0, amount=0x4d29720, hash=HASH_B, drain=DRAIN_B),
    SPOT_B: dict(spot=True, base=0, row=0x4c17b10, notional=0x4484790, amount=0x4d2a0c0, hash=HASH_B, drain=DRAIN_B),
    SPOT_C: dict(spot=True, base=SHIFT, row=0x4c19420, notional=0x4484d50, amount=0x4d2a0c0, hash=HASH_B, drain=DRAIN_B),
}
COLLECT = 0x3bb57f0
GROUPING = 0x3978840
HASH_MASTER = 0x399c7a0
SLOT_GROW_PERP = 0x5773240
SLOT_GROW_SPOT = 0x5773250
SLOT_MASTER = 0x5773220
SLOT_LIMIT = 0x5773248
SLOT_FREE = 0x576e010
GOT_MEMCMP = 0x576e488
STATUS_TABLE = 0x59a8d0
OK = 0x186
NOT_APPROVED = 0x128
TOO_HIGH = 0x129
BAD_PRIORITY = 0xb2
NO_ORDERS = 0x6a
NOT_ENABLED = 0xf5
OVER_LIMIT = 0xb4
SIDE = 0x6b
REDUCE = 0x6c
COUNT = 0x6d
MAIN = 0x6e
TRIGGER_KIND = 0x6f
ASSET = 0x70
STATUS_TEXT = {0x128: (0x59e13c, 0x22), 0x129: (0x59e15e, 0x18), 0xb4: (0x59d6a4, 0x33), 0x6a: (0x59cfe7, 0x11), 0x6b: (0x59cff8, 0x22), 0x6c: (0x59d01a, 0x21),
               0x6d: (0x59d03b, 0x24), 0x6e: (0x59d05f, 0x23), 0x6f: (0x59d082, 0x22), 0x70: (0x59d0a4, 0x2e)}
TEXT_TPSL = (0x3c24ff, 5)
TEXT_TRIGGER = (0x3c2504, 0x16)
TEXT_AT = {SPOT: 0x3c24ff, SPOT_B: 0x6f0dc6, SPOT_C: 0x6f0dc6}
CAP = {e: 1000 if SHAPE[e]['spot'] else 100 for e in ENTRIES}
MAX_PRIORITY = 100000000
LIMIT_ROW = 2
MASTERS_F = 0x3810
APPROVED_F = 0x690
HASH_OFF = 0x20
STRIDE_MASTER = 0x28
STRIDE_ROW = 0xe8
ROW_TREE = 0x98
STATE_SIZE = 0x4380
LIMIT_F = 0x8f8
CONFIG_F = 0x3660
OFF_VALS = 8
OFF_KEYS = 0x60
OFF_LEN = 0x13e
OFF_EDGES = 0x140
OUT_SIZE = 0x70
STACK_FILL = bytes((i * 5 + 3) & 0xff | 1 for i in range(0x8000))
TOP = 0x7f08
SEEN = None
GOLD = {}


class Panicked(Exception):
    """The node would panic here; a modelled outcome, unlike Unmodelled."""


def key_hash(key):
    return int.from_bytes(hashlib.sha256(key).digest()[:8], 'little')


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


def addr(n):
    return hashlib.sha256(b'addr' + str(n).encode()).digest()[:20]


def filled(m, size, seed):
    a = m.arena(size)
    a.mem[:] = fill_bytes(size, seed)
    a.valid[:] = b'\1' * size
    return a


# ---- model, written from the observed rules and independent of the machine


def group_rule(kind, rows):
    """Order grouping checks of the perp parser, after the builder gate.  kind 1 keeps a main order, kind 2 does not."""
    if kind in (0, 3):
        return None
    if kind == 1:
        if rows[0]['type'] != LIMIT_ROW:
            return MAIN
        want, rest = rows[0]['side'] ^ 1, rows[1:]
    else:
        want, rest = rows[0]['side'], rows
    asset = rows[0]['asset']
    for r in rest:
        if r['type'] == LIMIT_ROW:
            return TRIGGER_KIND
        if r['side'] != want:
            return SIDE
        if r['reduce'] != 1:
            return REDUCE
        if r['asset'] != asset:
            return ASSET
    return None if 1 <= len(rest) <= 2 else COUNT


def resolved(v):
    return v['user'] if v.get('masters_empty') else v['masters'].get(v['user'], v['user'])


def builder_rule(v):
    """None when the builder fee is admitted, else the status."""
    if v['rate'] > CAP[v['entry']]:
        return TOO_HIGH
    who = resolved(v)
    if v['items'] == 0 or who not in v['rows']:
        return NOT_APPROVED
    if v['rate'] == 0:
        return None
    limits = v['rows'][who]
    if limits is None or v['builder'] not in limits or v['rate'] > limits[v['builder']]:
        return NOT_APPROVED
    return None


def model(v):
    """status, forwarded bytes seed, list of freed blocks, notional calls."""
    w = dict(status=None, forward=None, freed=[], text=None, calls=[])
    cap = v['cap']
    if v['group_tag'] != OK:
        w.update(status=v['group_tag'], forward='group')
        if cap:
            w['freed'].append(('input', cap * 0x38, 0))
        return w
    rows = []
    for r in v['orders']:
        if r.get('none'):
            break
        if r.get('err') is not None:
            w.update(status=r['err'], forward='row')
            break
        rows.append(r)
    if cap:
        w['freed'].append(('input', cap * 0x38, 0))
    vec_cap = 0
    while vec_cap < len(rows):
        vec_cap = 4 if vec_cap == 0 else vec_cap * 2
    w['rows'] = rows
    w['vec_cap'] = vec_cap

    def free_vec():
        if vec_cap:
            w['freed'].append(('vec', vec_cap * 0x48, 0))

    if w['status'] is not None:
        free_vec()
        return w
    kind, index, entry = v['kind'], v['index'], v['entry']
    if kind == 3 and index >= MAX_PRIORITY + 1:
        w['status'] = BAD_PRIORITY
        free_vec()
        return w
    if not rows:
        w['status'] = NO_ORDERS
        return w
    if SHAPE[entry]['spot']:
        if kind in (1, 2):
            w.update(status=NOT_ENABLED, text=TEXT_TPSL)
            free_vec()
            return w
        if any(r['type'] != LIMIT_ROW for r in rows):
            w.update(status=NOT_ENABLED, text=TEXT_TRIGGER)
            free_vec()
            return w
    if v['flag'] & 1:
        bad = builder_rule(v)
        if bad is not None:
            w['status'] = bad
            free_vec()
            return w
    if kind == 3 and index != 0:
        w['calls'].append('notional')
        if v['notional_tag'] != OK:
            w.update(status=v['notional_tag'], forward='notional')
            if SHAPE[entry].get('side_slot') and v['notional_cap']:
                w['freed'].append(('notional', v['notional_cap'] * 16, 0))
            free_vec()
            return w
        w['calls'].append('amount')
        if v['notional_cap']:
            w['freed'].append(('notional', v['notional_cap'] * 16, 0))
        if v['amount_tag'] != OK:
            w.update(status=v['amount_tag'], forward='amount')
            free_vec()
            return w
        w['calls'].append('limit')
        if v['amount'] > v['limit']:
            w['status'] = OVER_LIMIT
            free_vec()
            return w
    if not SHAPE[entry]['spot']:
        bad = group_rule(kind, rows)
        if bad is not None:
            w['status'] = bad
            free_vec()
            return w
    w['status'] = OK
    return w


# ---- state writers


def set_ctrl(ctrl, mask, i, val):
    ctrl[i] = val
    ctrl[((i - 16) & mask) + 16] = val


def free_slot(ctrl, mask, h):
    pos, step = h & mask, 0
    while True:
        for i in range(16):
            if ctrl[pos + i] & 0x80:
                slot = (pos + i) & mask
                if ctrl[slot] & 0x80:
                    return slot
                return next(k for k in range(16) if ctrl[k] & 0x80)
        step += 16
        pos = (pos + step) & mask


def variant(key, off):
    """A key with the same hash byte that differs in one byte: the first for odd offsets, the last for even."""
    b = bytearray(key)
    b[0 if off & 1 else 19] ^= 0x40
    return bytes(b)


def write_table(m, owner, field, keys, spec, seed, stride, target):
    """A hash table of 20-byte keys.  `wall` puts decoys with the hash byte of `target` on offsets from its hash."""
    size = spec.get('size', 16)
    mask = size - 1
    a = m.arena(stride * size + size + 32)
    a.mem[:] = fill_bytes(len(a.mem), seed)
    a.valid[:] = b'\1' * len(a.mem)
    ctrl_off = stride * size + 16
    ctrl = [0xff] * (size + 16)
    h = key_hash(target)
    walled = []
    for off in spec.get('wall', ()):
        i = (h + off) & mask
        set_ctrl(ctrl, mask, i, h >> 57)
        at = ctrl_off - (i + 1) * stride
        a.mem[at:at + 20] = variant(target, off)
        walled.append(i)
    places = {}
    for key in keys:
        hk = key_hash(key)
        slot = free_slot(ctrl, mask, hk)
        set_ctrl(ctrl, mask, slot, hk >> 57)
        at = ctrl_off - (slot + 1) * stride
        a.mem[at:at + 20] = key
        places[key] = at
    for i in walled[:spec.get('deleted', 0)]:
        set_ctrl(ctrl, mask, i, 0x80)
    a.mem[ctrl_off:ctrl_off + size + 16] = bytes(ctrl)
    word(owner, field, 8, a.base + ctrl_off)
    word(owner, field + 8, 8, mask)
    word(owner, field + 0x10, 8, 3)
    word(owner, field + 0x18, 8, len(keys))
    return a, places


def tree_node(m, keys, limits, level, seed):
    a = filled(m, OFF_EDGES + 12 * 8, 0x70 + seed)
    if level == 0:
        here, parts = keys, ()
    else:
        mid = len(keys) // 2
        here = keys[mid:mid + 1]
        parts = (keys[:mid], keys[mid + 1:])
    word(a, OFF_LEN, 2, len(here))
    for i, k in enumerate(here):
        a.mem[OFF_KEYS + 20 * i:OFF_KEYS + 20 * (i + 1)] = k
        word(a, OFF_VALS + 8 * i, 8, limits[k])
    if level:
        edges = list(parts) if here else [keys]
        for i, part in enumerate(edges):
            word(a, OFF_EDGES + 8 * i, 8, tree_node(m, part, limits, level - 1, seed + i + 1).base)
    return a


def write_rows(m, ex, v):
    keys = sorted(v['rows'])
    tab, places = write_table(m, ex, APPROVED_F + v['base'], keys, v.get('row_table', {}), 0x17, STRIDE_ROW, resolved(v))
    for key in keys:
        at = places[key] + ROW_TREE
        limits = v['rows'][key]
        if limits is None:
            word(tab, at, 8, 0)
            word(tab, at + 8, 8, 0)
        else:
            root = tree_node(m, sorted(limits), limits, v['height'], 0)
            word(tab, at, 8, root.base)
            word(tab, at + 8, 8, v['height'])
    word(ex, APPROVED_F + v['base'] + 0x18, 8, v['items'])
    return tab


def write_masters(m, ex, v):
    keys = sorted(v['masters'])
    spec = v.get('master_table', {})
    tab, places = write_table(m, ex, MASTERS_F + v['base'], keys, spec, 0x25, STRIDE_MASTER, v['user'])
    for key in keys:
        tab.mem[places[key] + 20:places[key] + 40] = v['masters'][key]
    word(ex, MASTERS_F + v['base'] + 0x18, 8, 0 if v.get('masters_empty') else max(len(keys), 1 if spec else 0))
    return tab


def row_in(i):
    return bytes((i * 3 + j * 7 + 1) & 0xff for j in range(0x38))


def row_out(r, i):
    b = bytearray(fill_bytes(0x48, 0x31 + i))
    b[0x19] = r['type']
    word_ = r['asset'].to_bytes(8, 'little')
    b[0x28:0x30] = word_
    b[0x30] = r['side']
    b[0x31] = r['reduce']
    return bytes(b)


def machine(ctx, v):
    img, code, slots, got = ctx
    m = Machine(img, ())
    if SEEN is not None:
        m.seen = SEEN
    m.code = code
    m.slots = slots
    m.got = got
    for fn in WHOLE:
        m.real[fn] = fn
    stack = m.arena(0x8000, strict=False)
    stack.mem[:] = STACK_FILL
    m.stack = stack
    m.top = stack.base + TOP
    m.freed = []
    m.calls = []
    m.vec = None
    entry = v['entry']
    shape = SHAPE[entry]
    base = shape['base']
    ex = filled(m, STATE_SIZE, 0x41)
    masters = write_masters(m, ex, v)
    rows_tab = write_rows(m, ex, v)
    action = filled(m, 0x48, 0x5b)
    orders = filled(m, max(v['cap'], 1) * 0x38, 0x4f)
    for i, r in enumerate(v['orders']):
        orders.mem[i * 0x38:(i + 1) * 0x38] = row_in(i)
        orders.mem[i * 0x38 + 0x36] = 2 if r.get('none') else i & 1
    action.mem[0] = v['flag']
    word(action, 8, 8, v['rate'])
    action.mem[0x10:0x24] = v['builder']
    word(action, 0x28, 8, v['cap'])
    word(action, 0x30, 8, orders.base)
    word(action, 0x38, 8, len(v['orders']))
    word(action, 0x40, 4, v['kind'])
    word(action, 0x44, 4, v['index'])
    who = m.arena(20)
    who.mem[:] = v['user']
    who.valid[:] = b'\1' * 20
    out = m.arena(OUT_SIZE, strict=False)
    out.mem[:] = fill_bytes(OUT_SIZE, 0x63)
    m.parts = dict(ex=ex, masters=masters, rows=rows_tab, action=action, orders=orders, who=who, out=out)
    m.collected = None
    m.row_i = 0
    m.drained = [0, 0]
    m.drain_at = 0

    def key_at(at):
        return bytes(m.load(at + k, 1) for k in range(20))

    def memcmp():
        r = m.regs
        if r[R['rdx']] != 20:
            raise Unmodelled('compare length')
        left, right = key_at(r[R['rdi']]), key_at(r[R['rsi']])
        m.clobber(0 if left == right else 1 if left > right else 0xffffffff)

    def hash_master():
        r = m.regs
        if r[R['rdi']] != ex.base + MASTERS_F + base + HASH_OFF or key_at(r[R['rsi']]) != v['user']:
            raise Unmodelled('master hash')
        m.clobber(key_hash(v['user']))

    def hash_row():
        r = m.regs
        if r[R['rdi']] != ex.base + APPROVED_F + base + HASH_OFF or key_at(r[R['rsi']]) != resolved(v):
            raise Unmodelled('row hash')
        m.clobber(key_hash(resolved(v)))

    def collect():
        r = m.regs
        if r[R['rsi']] != orders.base or r[R['rdx']] != orders.base + len(v['orders']) * 0x38:
            raise Unmodelled('collect arguments')
        m.collected = r[R['rdi']]
        for k in range(3):
            m.store(r[R['rdi']] + k * 8, 8, 0x1234500 + k)
        m.clobber()

    def grouping():
        r = m.regs
        at = r[R['rdi']]
        if r[R['rdx']] != m.collected or r[R['rsi']] & 0xffffffff != (v['index'] if v['kind'] == 3 else 0):
            raise Unmodelled('grouping arguments')
        if bytes(m.load(r[R['rcx']] + k, 1) for k in range(0x18)) != bytes(ex.mem[CONFIG_F + base:CONFIG_F + base + 0x18]):
            raise Unmodelled('grouping config')
        m.store(at, 2, v['group_tag'])
        if v['group_tag'] != OK:
            for k in range(2, 0x60):
                m.store(at + k, 1, fill_bytes(0x60, 0x77)[k])
        else:
            for k, (n, root) in enumerate(zip(v['trees'], (0x4100, 0x4200))):
                m.store(at + 0x10 + 0x18 * k, 8, (root if n else 0))
                m.store(at + 0x18 + 0x18 * k, 8, 7 + k)
                m.store(at + 0x20 + 0x18 * k, 8, n)
        m.clobber()

    def drain():
        r = m.regs
        it = r[R['rsi']]
        k = m.drain_at
        n = v['trees'][k]
        want = (1, 0, 0x4100 + 0x100 * k, 7 + k, 1, 0, 0x4100 + 0x100 * k, 7 + k, n) if n else (0, None, None, None, 0, None, None, None, 0)
        for j, w in enumerate(want):
            if w is not None and m.load(it + j * 8, 8) != w:
                raise Unmodelled(f'drain word {j}')
        if m.drained[k] < n:
            m.drained[k] += 1
            m.store(r[R['rdi']], 8, 1)
        else:
            m.store(r[R['rdi']], 8, 0)
            m.drain_at += 1
        m.clobber()

    def order_row():
        r = m.regs
        i = m.row_i
        if bytes(m.load(r[R['rsi']] + k, 1) for k in range(0x36)) != row_in(i)[:0x36] or m.load(r[R['rsi']] + 0x37, 1) != row_in(i)[0x37]:
            raise Unmodelled('row copy')
        if m.load(r[R['rsi']] + 0x36, 1) != i & 1:
            raise Unmodelled('row byte')
        if key_at(r[R['rdx']]) != v['user'] or r[R['rcx']] != ex.base:
            raise Unmodelled('row arguments')
        o = v['orders'][i]
        at = r[R['rdi']]
        if o.get('err') is not None:
            m.store(at, 2, o['err'])
            for k in range(2, 0x60):
                m.store(at + k, 1, fill_bytes(0x60, 0x79)[k])
        else:
            m.store(at, 2, OK)
            blob = row_out(o, i)
            for k in range(0x48):
                m.store(at + 8 + k, 1, blob[k])
        m.row_i += 1
        m.clobber()

    def grow():
        at = m.regs[R['rdi']]
        cap, ptr = m.load(at, 8), m.load(at + 8, 8)
        new = 4 if cap == 0 else cap * 2
        if (cap == 0) != (ptr == 8):
            raise Unmodelled('grow state')
        a = m.arena(new * 0x48, strict=False)
        if cap:
            old = m.find(ptr, 1)
            a.mem[:cap * 0x48] = old.mem[:cap * 0x48]
        m.store(at, 8, new)
        m.store(at + 8, 8, a.base)
        m.vec = a
        m.clobber()

    def free():
        r = m.regs
        ptr, size, al = r[R['rdi']], r[R['rsi']], r[R['rdx']]
        name_ = 'input' if ptr == orders.base else 'vec' if m.vec is not None and ptr == m.vec.base else 'notional' if ptr == 0x9000 else hex(ptr)
        m.freed.append((name_, size, al))
        m.clobber()

    def stream():
        return m.load(m.regs[R['rsi']], 8), m.load(m.regs[R['rsi']] + 8, 8)

    def forward(at, seed):
        for k in range(2, 0x60):
            m.store(at + k, 1, fill_bytes(0x60, seed)[k])

    def notional():
        r = m.regs
        a, b = stream()
        third = m.load(r[R['rsi']] + 0x10, 8)
        n = len(m.want_rows)
        if (a, b) != (m.vec.base, m.vec.base + n * 0x48) or third != ex.base:
            raise Unmodelled('notional arguments')
        m.calls.append('notional')
        at = r[R['rdi']]
        if shape.get('side_slot'):
            slot = m.load(r[R['rsi']] + 0x18, 8)
            if m.load(slot, 2) != OK:
                raise Unmodelled('side slot')
            if v['notional_tag'] != OK:
                m.store(slot, 2, v['notional_tag'])
                forward(slot, 0x7b)
            m.store(at, 8, v['notional_cap'])
            m.store(at + 8, 8, 0x9000)
            m.store(at + 0x10, 8, 3)
        else:
            m.store(at, 2, v['notional_tag'])
            if v['notional_tag'] != OK:
                forward(at, 0x7b)
            else:
                m.store(at + 8, 8, v['notional_cap'])
                m.store(at + 0x10, 8, 0x9000)
                m.store(at + 0x18, 8, 3)
        m.clobber()

    def amount():
        r = m.regs
        if (r[R['rsi']], r[R['rdx']], r[R['rcx']], r[R['r8']] & 0xffffffff) != (ex.base, 0x9000, 3, v['index']):
            raise Unmodelled('amount arguments')
        m.calls.append('amount')
        m.store(r[R['rdi']], 2, v['amount_tag'])
        if v['amount_tag'] != OK:
            forward(r[R['rdi']], 0x7d)
        else:
            m.store(r[R['rdi']] + 8, 8, v['amount'])
        m.clobber()

    def limit():
        r = m.regs
        if r[R['rdi']] != ex.base + LIMIT_F + base or key_at(r[R['rsi']]) != resolved(v):
            raise Unmodelled('limit arguments')
        m.calls.append('limit')
        m.clobber(v['limit'])

    m.want_rows = [o for o in v['orders']]
    grow_slot = SLOT_GROW_SPOT if shape['spot'] else SLOT_GROW_PERP
    m.stubs.update({HASH_MASTER: hash_master, shape['hash']: hash_row, COLLECT: collect, GROUPING: grouping, shape['drain']: drain, shape['row']: order_row,
                    slots[grow_slot]: grow, slots[SLOT_FREE]: free, slots[GOT_MEMCMP]: memcmp, shape['notional']: notional, shape['amount']: amount,
                    slots[SLOT_LIMIT]: limit})
    return m


def enter(m, fn, *args):
    m.regs[R['rsp']] = m.top
    m.store(m.top, 8, 0xfeedface)
    for name_, val in zip(('rdi', 'rsi', 'rdx', 'rcx', 'r8', 'r9'), args):
        m.regs[R[name_]] = val
    for name_ in ('rbx', 'rbp', 'r12', 'r13', 'r14', 'r15'):
        m.regs[R[name_]] = 0xc0de0000 + R[name_]
    m.run(fn)
    if m.regs[R['rsp']] != m.top + 8:
        raise Unmodelled('stack not balanced')
    for name_ in ('rbx', 'rbp', 'r12', 'r13', 'r14', 'r15'):
        if m.regs[R[name_]] != 0xc0de0000 + R[name_]:
            raise Unmodelled(f'{name_} not restored')


def check(ctx, v):
    m = machine(ctx, v)
    p = m.parts
    out = p['out']
    w = model(v)
    m.want_rows = w.get('rows', [])
    before = [bytes(p[k].mem) for k in ('ex', 'masters', 'rows', 'action', 'orders', 'who')]
    enter(m, v['entry'], out.base, p['action'].base, p['who'].base, p['ex'].base)
    if m.regs[0] != out.base:
        return 'result pointer'
    status = read(out.mem, 0, 2)
    if status != w['status']:
        return f'status {status:#x} not {w["status"]:#x}'
    if [bytes(p[k].mem) for k in ('ex', 'masters', 'rows', 'action', 'orders', 'who')] != before:
        return 'state written'
    if m.freed != w['freed']:
        return f'freed {m.freed}'
    if m.calls != w['calls']:
        return f'calls {m.calls}'
    if m.row_i != sum(1 for _ in w.get('rows', ())) + (w['forward'] == 'row'):
        return 'row count'
    if v['group_tag'] == OK and (tuple(m.drained) != tuple(v['trees']) or m.drain_at != 2):
        return 'drain count'
    if w['forward']:
        seed = dict(group=0x77, row=0x79, notional=0x7b, amount=0x7d)[w['forward']]
        if bytes(out.mem[2:0x60]) != fill_bytes(0x60, seed)[2:]:
            return 'forwarded bytes'
    elif status == OK:
        if bytes(out.mem[8:0x30]) != bytes(p['action'].mem[:0x28]):
            return 'builder copy'
        n = len(w['rows'])
        if (read(out.mem, 0x30), read(out.mem, 0x40)) != (w['vec_cap'], n):
            return 'vec words'
        if read(out.mem, 0x48, 4) != v['kind'] or read(out.mem, 0x4c, 4) != v['index']:
            return 'kind words'
        got_ = bytes(m.vec.mem[:n * 0x48]) if n else b''
        if read(out.mem, 0x38) != m.vec.base or got_ != b''.join(row_out(r, i) for i, r in enumerate(w['rows'])):
            return 'rows'
    elif w['text'] is not None:
        here = TEXT_AT[v['entry']] + w['text'][0] - TEXT_TPSL[0]
        if (read(out.mem, 8), read(out.mem, 0x10), read(out.mem, 0x18)) != (here, w['text'][1], 0):
            return 'text'
    if bytes(out.mem[0x60:]) != fill_bytes(OUT_SIZE, 0x63)[0x60:]:
        return 'bytes past the result'
    gold = GOLD.get(id(v))
    if gold is not None and bytes(out.mem) != gold:
        return 'bytes differ from the unmodified run'
    v['_out'] = bytes(out.mem)
    return None


# ---- vectors


ME = addr(1)
BOSS = addr(2)
CODER = addr(3)
OTHER = addr(4)
LIMIT = dict(type=LIMIT_ROW, asset=7, side=1, reduce=0)


def trig(side=0, reduce=1, asset=7, kind=0):
    return dict(type=kind, asset=asset, side=side, reduce=reduce)


def vec(group, entry, **kw):
    v = dict(group=group, entry=entry, base=SHAPE[entry]['base'], flag=1, rate=0, builder=CODER, user=ME, masters={}, rows={ME: {CODER: 1000}}, items=None, height=0, kind=0, index=0, group_tag=OK,
             trees=(0, 0), orders=[LIMIT], cap=1, notional_tag=OK, notional_cap=0, amount_tag=OK, amount=0, limit=0)
    v.update(kw)
    if v['items'] is None:
        v['items'] = len(v['rows'])
    return v


def rate_vectors():
    out = []
    edges = (0, 1, 2, 9, 10, 99, 100, 101, 102, 228, 256, 356, 999, 1000, 1001, 1002, 1256, 0x10000, 1 << 32, (1 << 32) + 100, 1 << 63, U64)
    for e in ENTRIES:
        for r in edges:
            for lim in sorted({0, 1, max(r - 1, 0), r, min(r + 1, U64), 100, 1000, U64}):
                out.append(vec('rate', e, rate=r, rows={ME: {CODER: lim}}))
    return out


def approval_vectors():
    out = []
    names = [addr(100 + i) for i in range(24)]
    for e in ENTRIES:
        for r in (0, 5):
            out.append(vec('no_row', e, rate=r, rows={}))
            out.append(vec('no_row', e, rate=r, rows={OTHER: {CODER: 50}}))
            out.append(vec('no_row', e, rate=r, rows={OTHER: {CODER: 50}}, items=0))
            out.append(vec('items_zero', e, rate=r, rows={ME: {CODER: 50}}, items=0))
            out.append(vec('empty_tree', e, rate=r, rows={ME: None}))
            out.append(vec('other_builder', e, rate=r, rows={ME: {OTHER: 50}}))
            out.append(vec('flag', e, rate=r, flag=0, rows={}))
            out.append(vec('flag', e, rate=r, flag=2, rows={}))
            out.append(vec('flag', e, rate=r, flag=3, rows={}))
        for n in (1, 2, 5, 11):
            for pick in range(n):
                keys = sorted(names[:n])
                lim = {k: 20 + i for i, k in enumerate(keys)}
                for r in (lim[keys[pick]], lim[keys[pick]] + 1):
                    out.append(vec('leaf', e, rate=r, builder=keys[pick], rows={ME: lim}))
            below = sorted(names[:n])[0]
            lim = {k: 50 for k in names[:n]}
            for gone in (bytes(19) + b'\1', b'\xff' * 20, below[:19] + bytes([below[19] ^ 1])):
                if gone not in lim:
                    out.append(vec('leaf', e, rate=1, builder=gone, rows={ME: lim}))
        for h, n in ((1, 3), (1, 12), (2, 7), (2, 15), (3, 15), (9, 24)):
            keys = sorted(names[:n])
            lim = {k: 200 + i for i, k in enumerate(keys)}
            for k in keys[::max(n // 5, 1)] + keys[-1:]:
                out.append(vec('deep', e, rate=lim[k] % CAP[e], builder=k, rows={ME: lim}, height=h))
                out.append(vec('deep', e, rate=CAP[e], builder=k, rows={ME: lim}, height=h))
                out.append(vec('deep', e, rate=3, builder=k[:19] + bytes([k[19] ^ 1]), rows={ME: lim}, height=h))
    return out


def master_vectors():
    out = []
    for e in ENTRIES:
        for r in (0, 7):
            good = {BOSS: {CODER: 9}}
            out.append(vec('master', e, rate=r, masters={ME: BOSS}, rows=good))
            out.append(vec('master', e, rate=r, masters={ME: BOSS}, rows={ME: {CODER: 9}}))
            out.append(vec('master', e, rate=r, masters={OTHER: BOSS}, rows={ME: {CODER: 9}}))
            out.append(vec('master', e, rate=r, masters={OTHER: BOSS, CODER: ME}, rows=good))
            out.append(vec('master', e, rate=r, masters={ME: BOSS}, masters_empty=True, rows=good))
            out.append(vec('master', e, rate=r, masters={ME: BOSS}, masters_empty=True, rows={ME: {CODER: 9}}))
            out.append(vec('master', e, rate=r, masters={}, rows={ME: {CODER: 9}}, master_table=dict(wall=(0, 1))))
            for spec in (dict(wall=(3,)), dict(wall=(9, 10)), dict(wall=(0,)), dict(wall=(0, 1)), dict(wall=(1, 2, 3)), dict(wall=tuple(range(5, 20)), size=128), dict(wall=tuple(range(0, 16)), size=128),
                         dict(wall=tuple(range(0, 36)), size=128), dict(wall=tuple(range(0, 16)), size=128, deleted=4), dict(wall=tuple(range(5, 36)), size=128)):
                out.append(vec('master_table', e, rate=r, masters={ME: BOSS}, rows=good, master_table=spec))
                out.append(vec('master_table', e, rate=r, masters={}, rows={ME: {CODER: 9}}, master_table=spec))
                out.append(vec('row_table', e, rate=r, rows={ME: {CODER: 9}}, row_table=spec))
                out.append(vec('row_table', e, rate=r, rows={OTHER: {CODER: 9}}, row_table=spec))
    return out


def prefix_vectors():
    out = []
    for e in ENTRIES:
        for tag in (0, 0x30, 0x185, 0x187):
            for cap in (0, 1, 3):
                out.append(vec('group_tag', e, group_tag=tag, cap=cap, orders=[LIMIT] * min(cap, 1)))
        for trees in ((0, 0), (1, 0), (0, 1), (3, 2)):
            out.append(vec('trees', e, trees=trees))
        for n in (1, 2, 4, 5, 8, 9, 17):
            out.append(vec('rows', e, orders=[LIMIT] * n, cap=n, rate=1))
            out.append(vec('rows', e, orders=[LIMIT] * n, cap=n + 2, flag=0))
        for n in (0, 1, 4, 5):
            for tag in (0x30, 0x185, 0x187):
                out.append(vec('row_err', e, orders=[LIMIT] * n + [dict(err=tag)] + [LIMIT], cap=n + 2))
            out.append(vec('row_none', e, orders=[LIMIT] * n + [dict(none=True)] + [LIMIT], cap=n + 2))
        out.append(vec('row_none', e, orders=[dict(none=True)], cap=1, rows={}))
        out.append(vec('empty', e, orders=[], cap=0))
        out.append(vec('empty', e, orders=[], cap=5))
        out.append(vec('empty', e, orders=[], cap=0, rate=U64, rows={}))
    return out


def kind_vectors():
    out = []
    for e in ENTRIES:
        for k in (0, 1, 2, 3):
            for flag, rate, rows in ((1, 5, {ME: {CODER: 9}}), (1, 5, {}), (0, 5, {}), (1, 1100, {})):
                for n in (0, 1, 2, 3):
                    out.append(vec('kind', e, kind=k, flag=flag, rate=rate, rows=rows, orders=[LIMIT] * n, cap=n))
                out.append(vec('kind', e, kind=k, flag=flag, rate=rate, rows=rows, orders=[LIMIT, trig()], cap=2))
                out.append(vec('kind', e, kind=k, flag=flag, rate=rate, rows=rows, orders=[trig(), LIMIT], cap=2))
                out.append(vec('kind', e, kind=k, flag=flag, rate=rate, rows=rows, orders=[LIMIT, LIMIT, trig(kind=1)], cap=3))
                out.append(vec('kind', e, kind=k, flag=flag, rate=rate, rows=rows, orders=[trig(), trig(kind=1)], cap=2))
    main = dict(type=LIMIT_ROW, asset=7, side=1, reduce=0)
    for k, head in ((1, [main]), (2, [])):
        for side in (0, 1):
            for tail in ([], [trig(side=side)], [trig(side=side), trig(side=side)], [trig(side=side)] * 3, [trig(side=side, reduce=0)], [trig(side=side, reduce=2)],
                         [trig(side=side, asset=8)], [trig(side=side), trig(side=side, asset=8)], [trig(side=side), LIMIT], [trig(side=side), trig(side=side ^ 1)],
                         [trig(side=side), trig(side=side, reduce=0)], [trig(side=side, kind=1)]):
                orders = head + tail
                if orders:
                    for e in PERP_LIKE:
                        out.append(vec('groups', e, kind=k, orders=orders, cap=len(orders), flag=0))
                        out.append(vec('groups', e, kind=k, orders=orders, cap=len(orders), rate=4))
    return out


def priority_vectors():
    out = []
    for e in ENTRIES:
        for idx in (0, 1, 2, MAX_PRIORITY - 1, MAX_PRIORITY, MAX_PRIORITY + 1, MAX_PRIORITY + 2, 0xffffffff):
            for flag in (0, 1):
                for rows in ({ME: {CODER: 9}}, {}):
                    out.append(vec('priority', e, kind=3, index=idx, flag=flag, rate=3, rows=rows, amount=5, limit=6))
                    out.append(vec('priority', e, kind=0, index=idx, flag=flag, rate=3, rows=rows))
                    out.append(vec('priority', e, kind=3, index=idx, flag=flag, rate=3, rows=rows, orders=[], cap=0))
        for a, b in ((0, 0), (5, 5), (5, 6), (6, 5), (U64, U64), (U64, U64 - 1), (1 << 32, 1), (1, 1 << 32)):
            for cap in (0, 2):
                out.append(vec('limit', e, kind=3, index=3, flag=0, amount=a, limit=b, notional_cap=cap))
                out.append(vec('limit', e, kind=3, index=3, flag=1, rate=2, masters={ME: BOSS}, rows={BOSS: {CODER: 9}}, amount=a, limit=b, notional_cap=cap))
        for cap in (0, 2):
            for tag in (0x30, 0x185, 0x187):
                out.append(vec('notional', e, kind=3, index=3, flag=0, notional_tag=tag, notional_cap=cap))
                out.append(vec('amount', e, kind=3, index=3, flag=0, amount_tag=tag, notional_cap=cap))
                out.append(vec('amount', e, kind=3, index=3, flag=1, rate=1, amount_tag=tag, notional_cap=cap))
                out.append(vec('notional', e, kind=3, index=3, flag=1, rate=1, notional_tag=tag, notional_cap=cap))
        for m_, u in (({ME: BOSS}, ME), ({}, ME), ({OTHER: BOSS}, ME)):
            for spec in ({}, dict(wall=(3,)), dict(wall=(9, 10)), dict(wall=(0, 1)), dict(wall=tuple(range(0, 36)), size=128), dict(wall=tuple(range(5, 36)), size=128)):
                out.append(vec('priority_master', e, kind=3, index=3, flag=0, masters=m_, user=u, master_table=spec, amount=1, limit=1))
            out.append(vec('priority_master', e, kind=3, index=3, flag=0, masters=m_, user=u, masters_empty=True, amount=1, limit=1))
    return out


def all_vectors():
    return rate_vectors() + approval_vectors() + master_vectors() + prefix_vectors() + kind_vectors() + priority_vectors()


# ---- image binding


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


SUBJECTS = (PERP, SPOT, TREE_FIND, MASTER)
UNWIND = 'unwind clean-up after a panic in a callee or the capacity panic call, not a modelled outcome'
DEAD_ARM = 'grouping arms of kinds 1 and 2 in a spot parser: reached only through rows 1 and 2 of the jump table, and the kind test before it (0x1ea448e in 0x1ea3f60) sends both kinds to tag 0xf5 first'
UNEXECUTED = (
    (0x1ea3e9f, 0x1ea3f55, UNWIND), (0x1ea4aaa, 0x1ea4b1a, DEAD_ARM), (0x1ea4b9f, 0x1ea4ba8, DEAD_ARM), (0x1ea4bc8, 0x1ea4bf9, DEAD_ARM), (0x1ea4bf9, 0x1ea4caf, UNWIND),
    (0x4323a60, 0x4323b3e, UNWIND), (0x43263a0, 0x432647e, UNWIND),
    (0x432468a, 0x43246fa, DEAD_ARM), (0x432477f, 0x4324788, DEAD_ARM), (0x43247a8, 0x43247d9, DEAD_ARM), (0x43247d9, 0x432488f, UNWIND),
    (0x43253da, 0x432544a, DEAD_ARM), (0x43254cf, 0x43254d8, DEAD_ARM), (0x43254f8, 0x4325529, DEAD_ARM), (0x4325529, 0x43255df, UNWIND),
)
SAME_TAIL = 'stores the last 4 bytes of the user in a second stack word; the slot it normally writes already holds the same bytes from the row loop, which ran at least once here'
SAME_DWORD = 'pshufd 0x44 to 0x45 picks dword 1 in place of dword 0 of a register whose low two dwords are equal after pshuflw'
EQUIVALENT = {
    **dict.fromkeys((0x1ea3678, 0x1ea38ca, 0x1ea46a1, 0x1ea48c7), SAME_TAIL),
    **dict.fromkeys((0x1ea36e9, 0x1ea393f, 0x1ea3a87, 0x1ea4781, 0x36f3f11), SAME_DWORD),
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
        out.append(dict(kind='immediate', fn=fn, va=ins.va, op=show(ins), patch={ins.va + ins.size - n: ins.raw[-n] ^ 1}))
    return out


SCOPE = {PERP: (PERP,), SPOT: (SPOT,), TREE_FIND: (PERP, SPOT), MASTER: (SPOT,)}


def try_kill(mctx, picked):
    for pos, v in enumerate(picked):
        try:
            bad = check(mctx, v)
        except (Unmodelled, Panicked, EvidenceError, KeyError, OverflowError, ValueError, TypeError, struct.error, IndexError, MemoryError, ZeroDivisionError, StopIteration) as exc:
            bad = f'fault {type(exc).__name__}'
        if bad:
            picked.insert(0, picked.pop(pos))
            return (v['group'], bad[:60].replace('\t', ' ').replace('\n', ' '))
    return None


def gate_range(fn, listing):
    """From the test of the builder bit to the `ja` after the tree lookup, the part of a parser that is mutated."""
    tests = [i for i in listing if i.op == 'test' and i.ops[0][0] == 'm' and i.ops[1] == ('i', 1)]
    calls = [k for k, i in enumerate(listing) if i.op == 'call' and i.ops[0][0] == 't' and i.ops[0][1] in (TREE_FIND, TREE_FIND_B)]
    if len(tests) != 1 or len(calls) != 1:
        raise EvidenceError(f'gate range of {fn:#x}')
    last = next(i for i in listing[calls[0]:] if i.op == 'ja')
    return tests[0].va, last.va + last.size


def all_sites(listing):
    sites = []
    for fn in SUBJECTS:
        rows = listing[fn]
        if fn in (PERP, SPOT):
            a, b = gate_range(fn, rows)
            rows = [i for i in rows if a <= i.va < b]
        sites += conditional_sites(fn, rows) + field_sites(fn, rows) + imm_sites(fn, rows)
    return [x for x in sites if not any(a <= x['va'] < b for a, b, _ in UNEXECUTED)]


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
            print('survivor', hex(s_['fn']), hex(s_['va']), s_['op'], flush=True)
    return rows


WORKERS = 3
PROGRESS = False


def survey(data, code, slots, got, listing, vecs):
    sites = all_sites(listing)
    scoped = {fn: [v for v in vecs if v['entry'] in SCOPE[fn]] for fn in SUBJECTS}
    parts = [sites[i::WORKERS] for i in range(WORKERS)]
    jobs = [(data, code, slots, got, p, scoped) for p in parts]
    with multiprocessing.get_context('fork').Pool(WORKERS) as pool:
        got_rows = pool.map(survey_part, jobs)
    rows = [r for part in got_rows for r in part]
    rows.sort(key=lambda r: (SUBJECTS.index(r['fn']), r['va'], r['kind']))
    return rows


# ---- static facts


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


def tag_scan(img, starts, tag):
    """Byte hits in .text of `mov r16, tag` (66 [41] b8+r imm16); a hit may fall inside another instruction."""
    addr_, off, size = img.sec['.text'][:3]
    blob, out = img.data, []
    imm = struct.pack('<H', tag)
    i = blob.find(imm, off, off + size)
    while i != -1:
        for back in (2, 3):
            head = blob[i - back:i]
            if (back == 2 and head[0] == 0x66 and 0xb8 <= head[1] <= 0xbf) or (back == 3 and head[0] == 0x66 and head[1] == 0x41 and 0xb8 <= head[2] <= 0xbf):
                va = addr_ + i - back - off
                out.append(dict(site=hex(va), function=hex(starts[bisect.bisect_right(starts, va) - 1])))
        i = blob.find(imm, i + 1, off + size)
    return out


def gate_pairs(img, starts):
    """Hits of tag 0x129 with a hit of tag 0x128 at most 24 bytes later, and the cmp immediate right after the first."""
    low = tag_scan(img, starts, NOT_APPROVED)
    out, alone = [], []
    for row_ in tag_scan(img, starts, TOO_HIGH):
        site = int(row_['site'], 16)
        pair = [x for x in low if 0 < int(x['site'], 16) - site <= 24]
        if not pair:
            alone.append(row_)
            continue
        size = 4 if img.read(site, 1)[0] == 0x66 and img.read(site + 1, 1)[0] != 0x41 else 5
        b = img.read(site + size, 7)
        if b[1] == 0x83:
            cap = b[3]
        elif b[1] == 0x81:
            cap = struct.unpack('<I', b[3:7])[0]
        else:
            raise EvidenceError(f'no cmp after {site:#x}')
        out.append(dict(row_, not_approved=pair[0]['site'], cap=cap))
    return out, alone


def digest_of(v):
    return hashlib.sha256(repr(sorted((k, repr(x)) for k, x in v.items() if k != '_out')).encode()).hexdigest()[:16]


REFERENCE_ROWS = (
    ('differs', '14_order.rs validate_main_perp_like', 'validated.len() > 100 gives a builder order count error', 'the compared word is action +8, the builder fee rate; the order count is action +0x38; rate 101 with one order gives 0x129 at 0x1ea3a32'),
    ('differs', '14_order.rs validate_spot_or_extended', 'validated.len() > 1000 gives a builder order count error', 'same word at 0x1ea4727 with 1000'),
    ('differs', '14_order.rs STATUS_BUILDER_ORDER_COUNT_TOO_LARGE', 'name of the status', 'tag 0x129 Display text is Builder fee is too high.'),
    ('differs', '14_order.rs validate_main_perp_like comment', 'approval failure sits inside the ExtendedNa branch', 'the approval lookup runs for any kind when the builder flag is set; kind 3 only adds the 0x2511900 path after it'),
    ('same', '14_order.rs comment on 0x1EA3F60', 'approval lookup failure reports 296', '0x128 = 296, written at 0x1ea4734'),
    ('differs', '14_order.rs comment on 0x1EA3F60', 'cap overflow reports 180', 'that is 0xb4, whose text is about the delegatable balance for a priority order, not a builder cap'),
    ('same', '14_order.rs comment on 0x1EA3F60', 'l1_sub_account__lookup_master collapses subaccounts onto their master', '0x36f3ed0 through slot 0x5773220, table +0x3810 of the exchange state'),
    ('differs', '14_order.rs comment on 0x1EA3140', 'resolve the master account when needed', 'same table read inline, in both the builder path and the kind 3 path, with no separate condition'),
    ('differs', '14_order.rs validate_spot_or_extended', 'kinds 1 and 2 reach validate_grouping', 'kinds 1 and 2 stop at tag 0xf5 with TP/SL before any grouping arm, so the arms at 0x1ea4aaa and 0x1ea4ac5 cannot run'),
)


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
            except (Unmodelled, EvidenceError, KeyError) as exc:
                msg = f'fault {type(exc).__name__} {exc}'
            if msg:
                raise EvidenceError(f"mismatch in {v['group']} at {v['entry']:#x}: {msg}")
    finally:
        SEEN = None
    for v in vecs:
        GOLD[id(v)] = v.pop('_out')
    missing, padding = [], 0
    for fn in RANGES:
        for ins in listing[fn]:
            if ins.va in seen:
                continue
            if ins.op in ('nop', 'int3'):
                padding += 1
            elif not any(a <= ins.va < b for a, b, _ in UNEXECUTED):
                missing.append(hex(ins.va))
    if missing:
        raise EvidenceError(f'unlisted unexecuted instructions {len(missing)}: {missing}')
    rows = survey(data, code, slots, got, listing, vecs) if with_survey else []
    survivors = {r['va'] for r in rows if not r['killed']}
    if survivors - set(EQUIVALENT) or (rows and set(EQUIVALENT) - survivors):
        raise EvidenceError(f'survivors {sorted(hex(s_) for s_ in survivors ^ set(EQUIVALENT))} of {len(rows)}')
    fde_list = eh_frame_records(data)[1]
    starts = sorted(f['start'] for f in fde_list)
    pairs, alone = gate_pairs(img, starts)
    if sorted(int(p['function'], 16) for p in pairs) != sorted(ENTRIES) or any(p['cap'] != CAP[int(p['function'], 16)] for p in pairs):
        raise EvidenceError(f'gate copies {pairs}')
    out_path = Path(out_dir)
    out_path.mkdir(parents=True, exist_ok=True)
    groups, outcomes = {}, {}
    with open(out_path / 'vectors.tsv', 'w', newline='\n') as f:
        f.write('group\tentry\tstate\toutcome\n')
        for v in vecs:
            groups[v['group']] = groups.get(v['group'], 0) + 1
            name = f"{model(v)['status']:#x}"
            outcomes[name] = outcomes.get(name, 0) + 1
            f.write(f"{v['group']}\t{v['entry']:#x}\t{digest_of(v)}\t{name}\n")
    with open(out_path / 'mutations.tsv', 'w', newline='\n') as f:
        f.write('kind\tfunction\tva\tinstruction\tresult\tvector\treason\n')
        for r in rows:
            k = r['killed']
            f.write(f"{r['kind']}\t{r['fn']:#x}\t{r['va']:#x}\t{r['op']}\t{'killed' if k else 'equivalent'}\t{k[0] if k else ''}\t{k[1] if k else EQUIVALENT[r['va']]}\n")
    with open(out_path / 'instructions.tsv', 'w', newline='\n') as f:
        f.write('function\tva\tsize\tbytes\tdecoded\texecuted\n')
        for fn in RANGES:
            for i in listing[fn]:
                f.write(f'{fn:#x}\t{i.va:#x}\t{i.size}\t{i.raw.hex()}\t{show(i)}\t{int(i.va in seen)}\n')
    with open(out_path / 'reference-diff.tsv', 'w', newline='\n') as f:
        f.write('verdict\treference\treference_says\tbytes_say\n')
        for row_ in REFERENCE_ROWS:
            f.write('\t'.join(row_) + '\n')
    per = {hex(fn): dict(instructions=len(listing[fn]), executed=sum(i.va in seen for i in listing[fn]), fde=hex(fdes.range_of(fn)['fde']), end=hex(FDE_END[fn])) for fn in RANGES}
    status = {hex(t): dict(arm=hex(STATUS_TABLE + struct.unpack('<i', img.read(STATUS_TABLE + 4 * t, 4))[0]), text_va=hex(a), text=img.read(a, n).decode('ascii'))
              for t, (a, n) in sorted(STATUS_TEXT.items())}
    evidence = dict(
        binary=BINARY, sha256=SHA256, functions=per, whole=[hex(s_) for s_ in WHOLE],
        slots=dict(master=hex(img.relative(SLOT_MASTER)), limit=hex(img.relative(SLOT_LIMIT)), grow_perp=hex(img.relative(SLOT_GROW_PERP)), grow_spot=hex(img.relative(SLOT_GROW_SPOT))),
        callers={hex(s_): direct_sites(img, s_, starts) for s_ in ENTRIES + (TREE_FIND, TREE_FIND_B)},
        gate_pairs=pairs, tag_hits_without_a_pair=alone,
        status=status, spot_texts=[img.read(a, n).decode('ascii') for a, n in (TEXT_TPSL, TEXT_TRIGGER)],
        spot_format_tail=img.read(0x1e4233, 36).decode('ascii'),
        gate_ranges={hex(e): [hex(x) for x in gate_range(e, listing[e])] for e in (PERP, SPOT)}, mutated=[hex(s_) for s_ in SUBJECTS],
        caps={hex(e): CAP[e] for e in ENTRIES}, state_shift={hex(e): hex(SHAPE[e]['base']) for e in ENTRIES},
        vectors=len(vecs), mismatches=0, groups=groups, outcomes=outcomes, padding_not_executed=padding,
        unexecuted=[dict(start=hex(a), end=hex(b), why=w) for a, b, w in UNEXECUTED], mutants=len(rows), killed=sum(1 for r in rows if r['killed']),
        equivalent={hex(k): w for k, w in sorted(EQUIVALENT.items())},
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
