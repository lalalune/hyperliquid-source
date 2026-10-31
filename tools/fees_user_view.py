#!/usr/bin/env python3
"""fees: node #94 userFees view builder 0x27d7fe0, from bytes alone.

Static, no execution of the node.  The whole function is decoded from ELF bytes by the table decoder below, which must
land exactly on the FDE end.  It is interpreted in Python on every vector and compared with a separate closed-form
model, then every conditional, field offset, immediate and read constant is mutated to test the vectors.  The clock,
lock slow paths, daily volume list, address hash, rate row, schedule copy, discount, date add, memcpy, memcmp and sleep
are stubs that check their arguments and the call order.

    python3 tools/fees_user_view.py --out <dir>

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




ENTRY = 0x27d7fe0
SLOT_ROW = 0x57748f8
SLOT_SCHEDULE = 0x5774ef0
SLOT_DISCOUNT = 0x5774ef8
SLOT_DATE = 0x576e8b0
SLOT_MEMCMP = 0x576e488
SLOT_MEMCPY = 0x576dfe0
SLOT_LOCK = 0x576f5e8
SLOT_UNLOCK = 0x576f5f8
SLOT_SLEEP = 0x576e8f8
SLOT_INDEX = 0x576e470
SLOT_PANIC = 0x576e468
NOW = 0x4ee3800
SINCE = 0x4ee3730
DAILY = 0x25806a0
HASH = 0x2840fb0
LIST_LOCATION = 0x56f21f0
DATE_TEXT = 0x219c91
DATE_LOCATION = 0x566aa80
POWERS = 0x584b08
ONE_E9 = 0x20a220
SERIALIZER = 0x2a3c4e0
OUTER = 0x2586ae0
LOCK, DATE, TOKENS, LADDER, CTRL, ITEMS, LINKS = 0x568, 0x5d0, 0x780, 0x15f8, 0x1680, 0x1698, 0x4a08
TRACKER, EXCHANGE, HASHER = 0x15c0, 0x570, 0x16a0
OUT_SIZE = 0x130
SEEN = None


class Panicked(Exception):
    pass


def user(n):
    return bytes((n * 37 + k * 11 + 1) & 0xff for k in range(20))


def is_nan(bits):
    return bits & 0x7ff0000000000000 == 0x7ff0000000000000 and bits & 0xfffffffffffff != 0


def packed(year, ordinal, flags=5):
    return (year << 13 | ordinal << 4 | flags) & 0xffffffff


def millis(d):
    """Packed chrono date to Unix milliseconds, floored at 0."""
    s = signed(d, 32)
    year, ordinal = s >> 13, s >> 4 & 0x1ff
    y, shift = year - 1, 0
    if year <= 0:
        c = (1 - year) // 400 + 1
        y += 400 * c
        shift = -146097 * c
    days = ordinal + shift + (y * 1461 >> 2) - y // 100 + (y // 100 >> 2) - 719163
    return max(days * 86400000, 0)


def seconds(g):
    """A Duration result as f64, 0.0 for the error tag."""
    if g[0]:
        return 0.0
    return g[2] / 1e9 + float(g[1])


def ladder_pick(rows, share):
    """rows: (cutoff bits, discount bits).  0.0 below the first row, else the row before the first cutoff above."""
    if not rows:
        return 0
    s = b2f(share)

    def above(bits):
        a = b2f(bits)
        return not is_nan(bits) and not is_nan(share) and a > s
    if above(rows[0][0]):
        return 0
    k = 1
    while k < len(rows) and not above(rows[k][0]):
        k += 1
    return rows[k - 1][1]


def expected(v):
    """Closed form of the 0x130-byte result: [(offset, size, value)], or a panic name."""
    row = v['row']
    present = v.get('value')
    escrow = 0
    next_tag, next_ms = 0, None
    if present is not None:
        word = present.get('escrow')
        if word is not None:
            if not v.get('tokens'):
                return 'list'
            d = v['tokens'][0]
            escrow = f2b(float(word) / 10.0 ** d)
        if present.get('date', 0):
            if v['after90'] == 0:
                return 'date'
            next_tag, next_ms = 1, millis(v['after90'])
    f = [(0x30, 8, next_tag), (0x40, 8, v['daily'][0]), (0x48, 8, v['daily'][1]), (0x50, 8, v['daily'][2]),
         (0xe8, 8, v['discount']), (0xf0, 8, escrow), (0xf8, 8, row['share']), (0x100, 8, ladder_pick(v.get('ladder', ()), row['share'])),
         (0x120, 8, f2b(seconds(v['gaps'][0]))), (0x128, 8, f2b(seconds(v['gaps'][1])))]
    if next_ms is not None:
        f.append((0x38, 8, next_ms))
    f.append((0, 8, 1 if row['end'] else 0))
    if row['end']:
        f.append((0x28, 8, millis(row['end'])))
    for k in range(4):
        f.append((0xc8 + k * 8, 8, row['rates'][k]))
    link = next((x for x in v.get('links', ()) if x[0] == v['user']), None)
    f.append((0x108, 1, link[1] if link else 3))
    if link:
        f.append((0x109, 20, int.from_bytes(link[2], 'little')))
    return f


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


def node(m, rows, height, shape):
    """B-tree node of `shape` (size, key, key stride, count, edge, value writer)."""
    size, key_at, stride, count_at, edge_at, put = shape
    a = m.arena(size + (0x60 if height else 0))
    at = a.base
    if height == 0:
        take, kids = rows, []
    else:
        cut = max(1, min(len(rows) - 1, 2)) if len(rows) > 1 else len(rows)
        step = max(1, len(rows) // (cut + 1))
        idx = [step * (k + 1) - 1 for k in range(cut)] if len(rows) > 1 else list(range(len(rows)))
        take = [rows[k] for k in idx]
        kids, lo = [], 0
        for k in idx + [len(rows)]:
            kids.append(rows[lo:k])
            lo = k + 1
    m.store(at + count_at, 2, len(take))
    for k, row in enumerate(take):
        m.store_bytes(at + key_at + k * stride, row[0])
        put(at, k, row)
    for k, sub in enumerate(kids):
        m.store(at + edge_at + k * 8, 8, node(m, sub, height - 1, shape))
    return at


def link_tree(m, rows, height):
    def put(at, k, row):
        m.store(at + 0xe8 + k * 21, 1, row[1])
        m.store_bytes(at + 0xe9 + k * 21, row[2])
    return node(m, sorted(rows), height, (0x1d0, 8, 20, 0xe6, 0x1d0, put))


def token_tree(m, rows, height):
    """rows: (key u64, escrow word).  Key bytes are stored little-endian, the compare is on the word."""
    def put(at, k, row):
        for w in range(5):
            m.store(at + k * 0x30 + w * 8, 8, 0x6a6a000000000000 + k * 8 + w)
        m.store(at + k * 0x30 + 0x28, 8, row[1])
    keyed = [(k.to_bytes(8, 'little'), w) for k, w in sorted(rows)]
    return node(m, keyed, height, (0x278, 0x218, 8, 0x272, 0x278, put))


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


def build_state(m, v):
    s = m.arena(0x4b00)
    b = s.base
    m.store(b + LOCK, 8, v.get('lock', 0x40))
    m.store(b + DATE, 4, v['date'])
    m.store(b + ITEMS, 8, 0)
    links = sorted(v.get('links', ()))
    root = link_tree(m, links, v.get('link_height', 0)) if links else 0
    m.store(b + LINKS, 8, root)
    if root:
        m.store(b + LINKS + 8, 8, v.get('link_height', 0))
    rows = []
    for k in v.get('decoys', ()):
        rows.append((k, lambda at: None))
    if 'value' in v and v['value'] is not None:
        val = v['value']

        def fill(at):
            base = at + 0x18
            tree_rows = val.get('tree', ())
            if val.get('escrow') is not None:
                tree_rows = tuple(tree_rows) + ((0, val['escrow']),)
            h = val.get('height', 0)
            r = token_tree(m, tree_rows, h) if tree_rows else 0
            m.store(base + 0x98, 8, r)
            if r:
                m.store(base + 0xa0, 8, h)
            m.store(base + 0xb0, 4, val.get('date', 0))
        rows.append((v['user'], fill))
    if rows or v.get('table'):
        ctrl, mask = table(m, v, 0xe8, rows, v.get('buckets', 16), v.get('dead', ()))
        m.store(b + CTRL, 8, ctrl)
        m.store(b + CTRL + 8, 8, mask)
        m.store(b + ITEMS, 8, len(rows))
    if v.get('value') is not None and v['value'].get('escrow') is not None:
        m.store(b + TOKENS + 8, 8, len(v.get('tokens', ())))
        if v.get('tokens'):
            t = m.arena(0x50 * len(v['tokens']))
            for k, d in enumerate(v['tokens']):
                m.store(t.base + k * 0x50 + 0x49, 1, d)
            m.store(b + TOKENS, 8, t.base)
    ladder = v.get('ladder', ())
    m.store(b + LADDER + 8, 8, len(ladder))
    if ladder:
        a = m.arena(16 * len(ladder))
        for k, (x, y) in enumerate(ladder):
            m.store(a.base + k * 16, 8, x)
            m.store(a.base + k * 16 + 8, 8, y)
        m.store(b + LADDER, 8, a.base)
    return b


def stubs(m, v, b, calls):
    s, q = m.slots, m.regs
    locked = v.get('lock', 0x40) + 0x10 & U64
    clocks = list(v['clocks'])
    row = v['row']

    def need(ok, what):
        if not ok:
            raise Unmodelled(what)

    def is_locked():
        need(m.load(b + LOCK, 8) == locked, 'lock not held')

    def now():
        need(q[R['rdi']] == 1, 'clock id')
        need(calls['now'] < 3, 'clock calls')
        c = clocks[calls['now']]
        calls['now'] += 1
        calls['order'].append('now')
        m.clobber(c[0])
        q[R['rdx']] = c[1]

    def since():
        k = calls['since']
        need(k < 2, 'since calls')
        la, ea = q[R['rsi']], q[R['rdx']]
        need((m.load(la, 8), m.load(la + 8, 4)) == clocks[k + 1], 'later clock')
        need((m.load(ea, 8), m.load(ea + 8, 4)) == clocks[k], 'earlier clock')
        g = v['gaps'][k]
        out = q[R['rdi']]
        m.store(out, 1, g[0])
        if not g[0]:
            m.store(out + 8, 8, g[1])
            m.store(out + 0x10, 4, g[2])
        calls['since'] += 1
        calls['order'].append('since')
        m.clobber()

    def lock():
        need(q[R['rdi']] == b + LOCK and q[R['rsi']] & 0xffffffff == 0 and q[R['rcx']] & 0xffffffff == 1000000000, 'lock arguments')
        m.store(b + LOCK, 8, m.load(b + LOCK, 8) + 0x10)
        calls['order'].append('slow lock')
        m.clobber()

    def unlock():
        need(q[R['rdi']] == b + LOCK, 'unlock argument')
        calls['order'].append('slow unlock')
        m.clobber()

    def daily():
        is_locked()
        c = q[R['rsi']]
        need(m.load(m.load(c, 8), 4) == v['date'], 'daily date')
        need(m.load(c + 8, 8) == b + EXCHANGE, 'daily state')
        need(m.bytes_at(m.load(c + 0x10, 8), 20) == v['user'], 'daily user')
        need(m.load(c + 0x18, 8) == 0xe00000000 and m.load(c + 0x20, 1) == 0, 'daily range')
        out = q[R['rdi']]
        for k in range(3):
            m.store(out + k * 8, 8, v['daily'][k])
        calls['order'].append('daily')
        m.clobber()

    def hash_():
        is_locked()
        need(q[R['rdi']] == b + HASHER, 'hasher')
        key = m.bytes_at(q[R['rsi']], 20)
        need(key == v['user'], 'hash key')
        calls['order'].append('hash')
        m.clobber(hash_of(v, key))

    def rate_row():
        is_locked()
        need(q[R['rsi']] == b + TRACKER and m.bytes_at(q[R['rdx']], 20) == v['user'], 'row arguments')
        out = q[R['rdi']]
        m.store_bytes(out, fill_bytes(0x80, 0x71))
        for k in range(4):
            m.store(out + k * 8, 8, row['rates'][k])
        m.store(out + 0x20, 8, row['share'])
        m.store(out + 0x68, 4, row['end'])
        calls['order'].append('row')
        m.clobber()

    def schedule():
        is_locked()
        need(q[R['rsi']] == b + TRACKER, 'schedule argument')
        m.store_bytes(q[R['rdi']], fill_bytes(0x70, 0x93))
        calls['order'].append('schedule')
        m.clobber()

    def discount():
        is_locked()
        need(q[R['rdi']] == b + TRACKER and m.bytes_at(q[R['rsi']], 20) == v['user'], 'discount arguments')
        calls['order'].append('discount')
        m.clobber()
        m.xmm[0][0] = v['discount']

    def date():
        need(q[R['rdi']] & 0xffffffff == v['value']['date'] and q[R['rsi']] & 0xffffffff == 90, 'date arguments')
        calls['order'].append('date')
        m.clobber(v['after90'])

    def memcmp():
        need(q[R['rdx']] == 20, 'memcmp size')
        x, y = m.bytes_at(q[R['rdi']], 20), m.bytes_at(q[R['rsi']], 20)
        m.clobber(0 if x == y else 0x7fffff01 if x > y else 0xffffff01)

    def memcpy():
        d, c, n = q[R['rdi']], q[R['rsi']], q[R['rdx']]
        if n > 0x1000:
            raise Unmodelled('copy size')
        for k in range(n):
            a = m.find(c + k, 1)
            if a is None:
                raise Unmodelled('copy source')
            m.store(d + k, 1, a.mem[c + k - a.base])
        m.clobber(d)

    def sleep():
        need(q[R['rdi']] & 0xffffffff == 50, 'sleep argument')
        calls['order'].append('sleep')
        m.clobber()

    def index():
        need(q[R['rdi']] == LIST_LOCATION, 'list panic')
        raise Panicked('list')

    def panic():
        need(q[R['rdi']] == DATE_TEXT and q[R['rsi']] == 0x22 and q[R['rdx']] == DATE_LOCATION, 'date panic')
        raise Panicked('date')

    m.stubs.update({NOW: now, SINCE: since, DAILY: daily, HASH: hash_, s[SLOT_ROW]: rate_row, s[SLOT_SCHEDULE]: schedule, s[SLOT_DISCOUNT]: discount,
                    s[SLOT_DATE]: date, s[SLOT_MEMCMP]: memcmp, s[SLOT_MEMCPY]: memcpy, s[SLOT_LOCK]: lock, s[SLOT_UNLOCK]: unlock, s[SLOT_SLEEP]: sleep,
                    s[SLOT_INDEX]: index, s[SLOT_PANIC]: panic})


def check(ctx, v):
    m = machine(ctx)
    calls = dict(now=0, since=0, order=[])
    b = build_state(m, v)
    stubs(m, v, b, calls)
    want = expected(v)
    u = m.arena(20)
    m.store_bytes(u.base, v['user'])
    out = m.arena(OUT_SIZE, strict=False)
    out.mem[:] = fill_bytes(OUT_SIZE, 0xc3)
    r = m.regs
    r[R['rsp']] = m.top
    m.store(m.top, 8, 0xfeedface)
    m.store(m.top + 8, 8, 0x5a5a5a5a5a5a5a00 | v.get('sleep', 0))
    saved = ('rbx', 'rbp', 'r12', 'r13', 'r14', 'r15')
    for name_ in saved:
        r[R[name_]] = 0xc0de0000 + R[name_]
    r[R['rdi']], r[R['rsi']], r[R['rdx']], r[R['rcx']] = out.base, 0x5151515151515151, b, u.base
    r[R['r8']], r[R['r9']] = 0x5252525252525252, 0x5353535353535353
    try:
        m.run(ENTRY)
    except Panicked as exc:
        return None if want == str(exc) else f'panic {exc}'
    if isinstance(want, str):
        return 'panic missing'
    if r[R['rsp']] != m.top + 8 or any(r[R[n]] != 0xc0de0000 + R[n] for n in saved):
        return 'registers'
    if r[0] != out.base:
        return 'return value'
    if m.load(b + LOCK, 8) != v.get('lock', 0x40):
        return 'lock word'
    blob = bytes(out.mem)
    for off, size, val in want:
        if read(blob, off, size) != val:
            return f'field {off:#x}: {read(blob, off, size):#x} not {val:#x}'
    if blob[8:0x28] != fill_bytes(0x80, 0x71)[0x28:0x48]:
        return 'trial words'
    if blob[0x58:0xc8] != fill_bytes(0x70, 0x93):
        return 'schedule bytes'
    tail = (['date'] if v.get('value') is not None and v['value'].get('date', 0) else [])
    order = ['now'] + (['slow lock'] if v.get('slow') else []) + ['now', 'since', 'daily'] + (['hash'] if v.get('decoys') or v.get('value') is not None else []) + ['row', 'schedule', 'discount'] + tail
    order += (['slow unlock'] if v.get('last') else []) + ['now', 'since'] + (['sleep'] if v.get('sleep') else [])
    if calls['order'] != order:
        return 'call order'
    return None


# ---- vectors


U = user(3)
ROW = dict(rates=(f2b(0.00045), f2b(0.00015), f2b(0.0007), f2b(0.0002)), share=f2b(3.5), end=0)
CLOCKS = ((1000, 11), (1002, 222), (1005, 3333))
GAPS_OK = ((0, 2, 500000000), (0, 3, 250000000))
D0 = packed(2026, 300)
BASE = dict(user=U, date=D0, row=ROW, clocks=CLOCKS, gaps=GAPS_OK, daily=(14, 0x1234567800, 15), discount=f2b(0.04), after90=0)
TIERS = tuple((f2b(a), f2b(b)) for a, b in ((0.0, 0.05), (0.01, 0.1), (0.1, 0.15), (1.0, 0.2), (5.0, 0.3), (50.0, 0.4)))
NAN = 0x7ff8000000000123


def vec(group, **kw):
    v = dict(BASE, group=group)
    v.update(kw)
    return v


def row_(**kw):
    return dict(ROW, **kw)


def decoy(k):
    return user(100 + k)


def vectors():
    out = [vec('none')]
    # clock results and the lock
    for g in (((1, 0, 0), (0, 1, 2)), ((0, 1, 2), (1, 0, 0)), ((1, 0, 0), (1, 0, 0)), ((0, 0, 999999999), (0, 2 ** 53 + 1, 1)), ((0, 2 ** 63 + 2 ** 11, 0), (0, U64, 999999999)), ((0, 0xffffffff, 7), (0, 0x100000000, 9))):
        out.append(vec('clock', gaps=g))
    for name_, lock_, slow in (('reader', 0x10, False), ('free', 0, False), ('writer bit', 0x8, True), ('writer bit 2', 0x18, True), ('top', 0xffffffffffffffe0, False), ('top 2', 0xffffffffffffffef, True), ('high', 0xfffffffffffffff0, True), ('flags', 0x7, False), ('parked', 0x2, False)):
        last = (lock_ + 0x10 & U64 & 0xfffffffffffffff2) == 0x12
        out.append(vec('lock ' + name_, lock=lock_, slow=slow, last=last))
    out.append(vec('sleep', sleep=1))
    out.append(vec('sleep bit', sleep=1, gaps=((1, 0, 0), (0, 7, 8))))
    # table probes
    for n in (1, 3, 8, 15, 20, 40):
        out.append(vec('decoys', decoys=[decoy(k) for k in range(n)], buckets=32))
        out.append(vec('decoys value', decoys=[decoy(k) for k in range(n)], buckets=32, value=dict(escrow=999), tokens=(6,), hash=None))
    for k in (0, 4, 15, 16, 19):
        w = bytearray(U)
        w[k] ^= 0x80
        h = 0x0300000000000011
        out.append(vec('near key', decoys=[bytes(w)], value=dict(escrow=999), tokens=(6,), hash=h))
        out.append(vec('near key absent', decoys=[bytes(w)], hash=h))
    for k in (1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 31, 32, 33, 48, 60, 100):
        out.append(vec('probe wall', decoys=[decoy(j) for j in range(k)], value=dict(escrow=999), tokens=(6,), hash=0x0700000000000005, buckets=128))
        out.append(vec('probe wall absent', decoys=[decoy(j) for j in range(k)], hash=0x0700000000000005, buckets=128))
    # trial end dates
    for d in (packed(2026, 301), packed(1970, 1), packed(1970, 2), packed(1969, 365), packed(1, 1), packed(0, 1), packed(-1, 1), packed(-400, 1), packed(-401, 360), packed(-262000, 1), packed(262000, 365), packed(2000, 366), packed(1900, 59), packed(2100, 61), packed(400, 100), packed(2026, 300, 0), packed(2001, 1), packed(2101, 40), packed(2401, 366), packed(1901, 2), packed(10001, 7)):
        out.append(vec('trial end', row=row_(end=d)))
        out.append(vec('next trial', value=dict(date=packed(2026, 1)), after90=d))
    out.append(vec('both dates', row=row_(end=packed(2026, 310)), value=dict(date=packed(2026, 2)), after90=packed(2026, 92)))
    out.append(vec('date add panic', value=dict(date=packed(262142, 300)), after90=0))
    # escrow
    for d in range(0, 11):
        out.append(vec('escrow', value=dict(escrow=123456789012345), tokens=(d, 99)))
    for w in (0, 1, 2 ** 53 + 1, 2 ** 63 + 2049, U64, 2 ** 32, 2 ** 32 - 1):
        out.append(vec('escrow word', value=dict(escrow=w), tokens=(8,)))
    out.append(vec('escrow no token', value=dict(escrow=5), tokens=()))
    out.append(vec('no escrow no token', value=dict(), tokens=()))
    for h in (0, 1, 2, 3):
        for n in (0, 1, 3, 10):
            rows = tuple((k + 1, 1000 + k) for k in range(n))
            out.append(vec('token tree', value=dict(escrow=777 + h, tree=rows, height=h), tokens=(6,)))
            out.append(vec('token tree absent', value=dict(tree=rows + ((99, 5),), height=h), tokens=()))
    # value + date mix
    out.append(vec('value all', value=dict(escrow=5000000000, date=packed(2026, 200)), tokens=(8,), after90=packed(2026, 290), row=row_(end=packed(2026, 310))))
    # ladder
    for s in (-1.0, 0.0, 0.005, 0.01, 0.0100001, 0.1, 0.5, 1.0, 4.99, 5.0, 49.0, 50.0, 1e9):
        out.append(vec('ladder', ladder=TIERS, row=row_(share=f2b(s))))
    for rows in (TIERS[:1], TIERS[:2], TIERS[1:], TIERS[2:4]):
        for s in (0.0, 0.05, 2.0, 100.0):
            out.append(vec('ladder short', ladder=rows, row=row_(share=f2b(s))))
    nan_rows = ((f2b(0.0), f2b(0.1)), (NAN, f2b(0.2)), (f2b(1.0), f2b(0.3)))
    out.append(vec('ladder nan row', ladder=nan_rows, row=row_(share=f2b(0.5))))
    out.append(vec('ladder nan row', ladder=nan_rows, row=row_(share=f2b(2.0))))
    out.append(vec('ladder nan first', ladder=((NAN, f2b(0.1)), (f2b(1.0), f2b(0.3))), row=row_(share=f2b(0.5))))
    out.append(vec('ladder nan share', ladder=TIERS, row=row_(share=NAN)))
    out.append(vec('ladder empty', ladder=(), row=row_(share=f2b(9.0))))
    # staking link tree
    for h in (0, 1, 2):
        for n in (1, 5, 10):
            rows = [(user(40 + k), k % 3, user(70 + k)) for k in range(n)]
            out.append(vec('link absent', links=rows, link_height=h))
            for at in sorted({0, n // 2, n - 1}):
                who = rows[at]
                out.append(vec('link', links=rows, user=who[0], link_height=h))
    out.append(vec('link head byte', links=[(bytes([U[0] ^ 1]) + U[1:], 1, user(9))]))
    out.append(vec('link tail byte', links=[(U[:19] + bytes([U[19] ^ 1]), 1, user(9))]))
    for t in (0, 1, 2):
        out.append(vec('link tag', links=[(U, t, user(50 + t))]))
    return out


GROUPS_BY_SIZE = None


def all_vectors():
    return vectors()


# ---- binding


FDE_END = {}
RANGES = {}
SUBJECTS = (ENTRY,)


def build(data):
    check_digest(data)
    fdes = Fdes(data)
    img = Image(data)
    FDE_END[ENTRY] = fdes.range_of(ENTRY)['end']
    RANGES[ENTRY] = ((ENTRY, FDE_END[ENTRY]),)
    rows = decode_range(img, ENTRY, FDE_END[ENTRY])
    listing = {ENTRY: rows}
    code = {i.va: i for i in rows}
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


NO_PANIC = 'unreachable: follows a call that does not return'
UNWIND = 'unwind clean-up after a panic in a callee, not a modelled outcome'
GAPS = ((0x27d89d7, 0x27d89d9, NO_PANIC), (0x27d89f2, 0x27d8ada, UNWIND))
SAME_BIT = 'the result is only tested for zero, and bit 3 alone decides it: and 9 then shift 3, or and 8 then shift 2, stay zero or non-zero together'
FLOOR = 'years up to 0 end more than 700000 days before 1970 for every value this constant can produce, so the floor at 0 returns 0 either way'
POSITIVE = 'the sign word is 0: the year - 1 here is never negative, a year up to 0 gets 400-year cycles added first'
UNWIND_ONLY = 'these words are read only by the unwind blocks that free the list; on a normal return the list moves into the result'
EQUIVALENT = {
    0x27d8024: SAME_BIT, 0x27d8027: SAME_BIT,
    0x27d81b8: 'all 16 bytes of the source are the same tag, so the changed selector gives the same register',
    0x27d8437: UNWIND_ONLY, 0x27d843c: UNWIND_ONLY,
    0x27d8445: 'the same user dword was stored in this slot at 0x27d833b and the displaced store lands on a stack word nothing reads',
    0x27d84a3: FLOOR, 0x27d84aa: FLOOR, 0x27d84b1: FLOOR, 0x27d84b7: FLOOR, 0x27d84bf: FLOOR,
    0x27d84e7: POSITIVE,
    0x27d8555: 'key 0 is the smallest u64, so a non-empty node stops at its first key and the scan bound matters only at count 0, where 0 shifted is 0',
    0x27d8654: FLOOR, 0x27d865b: FLOOR, 0x27d8662: FLOOR, 0x27d8668: FLOOR, 0x27d8670: FLOOR,
    0x27d8696: POSITIVE,
    0x27d894e: 'the one extra copied byte is the first byte of +0x120, stored again by the next instruction pair',
}


def gaps():
    return list(GAPS)


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


def all_sites(listing, img):
    sites = []
    for fn in SUBJECTS:
        rows = listing[fn]
        sites += conditional_sites(fn, rows) + field_sites(fn, rows) + imm_sites(fn, rows) + constant_sites(fn, rows, img)
    g = gaps()
    return [x for x in sites if not any(a <= x['va'] < b for a, b, _ in g)]


def survey(data, code, slots, got, listing, vecs, img):
    sites = all_sites(listing, img)
    parts = [sites[i::WORKERS] for i in range(WORKERS)]
    jobs = [(data, code, slots, got, p, vecs) for p in parts]
    with multiprocessing.get_context('fork').Pool(WORKERS) as pool:
        got_rows = pool.map(survey_part, jobs)
    rows = [r for part in got_rows for r in part]
    rows.sort(key=lambda r: (r['va'], r['kind'], sorted(r['patch'])))
    return rows


# ---- static facts


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
    for mark in ('l1/src/', 'chrono-', 'library/'):
        if mark in path:
            path = path[path.index(mark):]
    return dict(path=path, path_bytes=length, line=line, column=col)


def field_map(img, end):
    """Serializer 0x2a3c4e0: JSON key and struct offset of each field, read from its own instructions."""
    out, off, name_va, size_ = [], None, None, 0
    held = 0
    for ins in decode_range(img, SERIALIZER, end):
        a = ins.ops
        if ins.op == 'lea' and a[0] == ('r', R['rcx'], 64) and a[1][1] == R['r14']:
            off = a[1][4]
        elif ins.op == 'mov' and a[0] == ('r', R['rcx'], 64) and a[1] == ('r', R['r14'], 64):
            off = held
        elif ins.op == 'add' and a[0] == ('r', R['r14'], 64) and a[1][0] == 'i':
            held = a[1][1]
        elif ins.op == 'lea' and a[0] == ('r', R['rsi'], 64) and a[1][1] is None:
            name_va = a[1][4]
        elif ins.op == 'mov' and a[0][:2] == ('r', R['rdx']) and a[1][0] == 'i' and name_va:
            size_ = a[1][1]
        elif ins.op == 'call' and name_va and ins.va != SERIALIZER + 0x14:
            out.append(dict(offset=off, text=img.read(name_va, size_).decode('ascii'), va=hex(name_va)))
            name_va = None
    return out


def pinned(img):
    """Constants the model relies on, re-read; any change stops the tool."""
    got_ = dict(one_e9=img.f64(ONE_E9), powers=[img.f64(POWERS + k * 8) for k in range(11)])
    if got_ != dict(one_e9=1e9, powers=[10.0 ** k for k in range(11)]):
        raise EvidenceError(f'constants {got_}')
    pins = []
    for label, va, text in PINS:
        want = bytes.fromhex(text.replace(' ', ''))
        if img.read(va, len(want)) != want:
            raise EvidenceError(f'pin {label}')
        pins.append(dict(what=label, va=hex(va), bytes=want.hex()))
    return got_, pins


PINS = (
    ('14 day range word', 0x27d8122, '48b9000000000e000000'),
    ('90 days', 0x27d8633, 'be5a000000'),
    ('millis per day', 0x27d8501, '4869c0005c2605'),
    ('days to 1970', 0x27d84fa, '05c506f5ff'),
    ('hold 50', 0x27d897e, 'bf32000000'),
    ('result size', 0x27d8991, 'ba30010000'),
)
FIELD_ROWS = (
    ('+0x00 trial tag', 'row +0x68 date dword non-zero', 'trial'),
    ('+0x08..+0x27', 'row +0x28..+0x47, 32 bytes', 'trial body'),
    ('+0x28', 'row +0x68 as Unix ms', 'trial end'),
    ('+0x30, +0x38', 'value +0xb0 date plus 90 days, as Unix ms', 'nextTrialAvailableTimestamp'),
    ('+0x40', 'list from 0x25806a0', 'dailyUserVlm'),
    ('+0x58..+0xc7', '0x70 bytes from 0x2a3bb60', 'feeSchedule'),
    ('+0xc8..+0xe0', 'row +0, +8, +0x10, +0x18', 'userCrossRate, userAddRate, userSpotCrossRate, userSpotAddRate'),
    ('+0xe8', 'xmm0 of 0x3743020', 'activeReferralDiscount'),
    ('+0xf0', 'word +0x28 under key 0 of the tree at value +0x98, over 10^byte', 'feeTrialEscrow'),
    ('+0xf8, +0x100', 'row +0x20, then ladder pick', 'activeStakingDiscount'),
    ('+0x108..+0x11c', 'tag byte and 20 bytes from the tree at state +0x4a08', 'stakingLink'),
    ('+0x120, +0x128', 'seconds waited for the lock, seconds held', 'not serialized by 0x2a3c4e0'),
)
REFERENCE_ROWS = (
    ('differs', 'info_server/abci_state_info_handler.rs UserFeesResponse', 'active_referral_discount: Option<String>', 'an f64 at +0xe8 with no tag, always written'),
    ('differs', 'info_server/abci_state_info_handler.rs UserFeesResponse', 'fee_trial_escrow: Option<String>', 'an f64 at +0xf0 with no tag, 0.0 when nothing is held'),
    ('differs', 'info_server/abci_state_info_handler.rs UserFeesResponse', 'active_staking_discount: Option<String>', '2 f64 at +0xf8 and +0x100 with no tag: the stake share and the ladder pick; the serializer is a separate one, unread'),
    ('differs', 'info_server/abci_state_info_handler.rs UserFeesResponse', 'staking_link: Option<Address>', 'a tag byte with values 0, 1, 2 beside 20 address bytes; tag 3 is none'),
    ('agrees', 'info_server/abci_state_info_handler.rs UserFeesResponse', 'trial, next_trial_available_timestamp: Option', 'both have a tag word: +0 and +0x30'),
    ('absent', 'references/can1357-hl/l1/fees/compute.rs', 'no user view path', 'one read lock over the whole read, 2 Durations stored behind the view, 14-day list'),
)


def facts_and_files(data, out_dir, img, fdes, listing, vecs, rows, seen, padding, slots):
    constants, pins = pinned(img)
    starts = sorted(f['start'] for f in eh_frame_records(data)[1])
    out_path = Path(out_dir)
    out_path.mkdir(parents=True, exist_ok=True)
    groups, outcomes = {}, {}
    with open(out_path / 'vectors.tsv', 'w', newline='\n') as f:
        f.write('group\tstate\toutcome\n')
        for v in vecs:
            groups[v['group']] = groups.get(v['group'], 0) + 1
            w = expected(v)
            name = 'panic ' + w if isinstance(w, str) else 'result'
            outcomes[name] = outcomes.get(name, 0) + 1
            f.write(f"{v['group']}\t{digest_of(v)}\t{name}\n")
    with open(out_path / 'mutations.tsv', 'w', newline='\n') as f:
        f.write('kind\tva\tinstruction\tresult\tvector\treason\n')
        for r in rows:
            k = r['killed']
            f.write(f"{r['kind']}\t{r['va']:#x}\t{r['op']}\t{'killed' if k else 'equivalent'}\t{k[0] if k else ''}\t{k[1] if k else EQUIVALENT[r['va']]}\n")
    with open(out_path / 'instructions.tsv', 'w', newline='\n') as f:
        f.write('va\tsize\tbytes\tdecoded\texecuted\n')
        for i in listing[ENTRY]:
            f.write(f'{i.va:#x}\t{i.size}\t{i.raw.hex()}\t{show(i)}\t{int(i.va in seen)}\n')
    with open(out_path / 'reference-diff.tsv', 'w', newline='\n') as f:
        f.write('verdict\treference\treference_says\tbytes_say\n')
        for row_x in REFERENCE_ROWS:
            f.write('\t'.join(row_x) + '\n')
    fn = ENTRY
    per = dict(start=hex(fn), end=hex(FDE_END[fn]), fde=hex(fdes.range_of(fn)['fde']), instructions=len(listing[fn]), executed=sum(i.va in seen for i in listing[fn]))
    calls = direct_sites(img, (ENTRY, SERIALIZER, NOW, DAILY), starts)
    ser_end = fdes.range_of(SERIALIZER)['end']
    evidence = dict(
        binary=BINARY, sha256=SHA256, function=per, constants=constants, pins=pins, serializer_fields=field_map(img, ser_end), result_fields=[dict(zip(('result', 'source', 'name'), x)) for x in FIELD_ROWS],
        callers={hex(ENTRY): calls[ENTRY], hex(SERIALIZER): calls[SERIALIZER]},
        slots={hex(s): hex(slots[s]) for s in (SLOT_ROW, SLOT_SCHEDULE, SLOT_DISCOUNT, SLOT_DATE, SLOT_LOCK, SLOT_UNLOCK, SLOT_SLEEP, SLOT_INDEX, SLOT_PANIC)},
        list_location=location(img, LIST_LOCATION), date_location=location(img, DATE_LOCATION), date_text=img.read(DATE_TEXT, 0x22).decode('ascii'),
        vectors=len(vecs), mismatches=0, groups=groups, outcomes=outcomes, padding_not_executed=padding,
        unexecuted=[dict(start=hex(a), end=hex(b), why=w) for a, b, w in gaps()],
        mutants=len(rows), killed=sum(1 for r in rows if r['killed']), equivalent={hex(k): w for k, w in sorted(EQUIVALENT.items())},
    )
    with open(out_path / 'evidence.json', 'w', newline='\n') as f:
        json.dump(evidence, f, indent=1, sort_keys=True)
        f.write('\n')
    return evidence


def digest_of(v):
    return hashlib.sha256(repr(sorted((k, repr(x)) for k, x in v.items())).encode()).hexdigest()[:16]


def run_vectors(ctx, vecs):
    for v in vecs:
        try:
            msg = check(ctx, v)
        except (Unmodelled, EvidenceError, KeyError) as exc:
            msg = f'fault {type(exc).__name__} {exc}'
        if msg:
            raise EvidenceError(f"mismatch in {v['group']}: {msg}")


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
    for ins in listing[ENTRY]:
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
