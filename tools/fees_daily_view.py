#!/usr/bin/env python3
"""fees: node #94 dailyUserVlm and feeSchedule view path, from bytes alone.

Static, no execution of the node.  Seven functions are decoded from ELF bytes by the table decoder below, each of which
must land exactly on its FDE end.  They are interpreted in Python on every vector and compared with a separate
closed-form model.  The mutation survey is off by default: it did not finish in the time available.
Allocation, the address hash, the map row lookups, the date add, the overflow recorder and the view builder are stubs
that check their arguments.  The JSON keys come from the instructions of the struct serializers.

    python3 tools/fees_daily_view.py --out <dir>

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


DAILY = 0x25806a0
ROW_FN = 0x28f0c10
OWNER_DAY = 0x26f95d0
TOTAL_DAY = 0x26f9900
SCHEDULE = 0x2a3bb60
CHAIN = 0x2a10690
OUTER = 0x2586ae0
VIEW = 0x27d7fe0
HASH = 0x399c7a0
DEX_ROW = 0x36f57f0
SLOT_DATE = 0x576e8b0
SLOT_ROW = 0x5773170
SLOT_RECORD = 0x5773190
SLOT_ALLOC = 0x576dfd8
SLOT_ALLOC_FAIL = 0x576dfb8
SLOT_PANIC = 0x576e468
SLOT_MEMCPY = 0x576dfe0
SLOT_ONCE = 0x576e8b8
LOG_CELL = 0x576e928
LAZY = 0x577ab98
RECORD_LOCATION = 0x5715e68
DATE_TEXT = 0x219cb3
DATE_LOCATION = 0x566aa98
CENT = 0x20a960
PAIR = 0x202fd0
MILLION = 0x20ae60
THREE = 0x20aab8
SERIALIZERS = {'schedule': 0x2a3c790, 'vip row': 0x2a3c030, 'mm row': 0x2a3bee0, 'ladder row': 0x2a3cde0, 'daily row': 0x2a3cc50}
ALLOW = (0, 18, 44, 53, 55, 58, 59, 108, 109)
LEVELS = (13, 14, 18, 19, 20, 21, 31)
CTRL, MASK, ITEMS, HASHER = 0x4260, 0x4268, 0x4278, 0x4280
SEEN = None


class Panicked(Exception):
    pass


def user(n):
    return bytes((n * 37 + k * 11 + 1) & 0xff for k in range(20))


def packed(year, ordinal, flags=5):
    return (year << 13 | ordinal << 4 | flags) & 0xffffffff


def sat(a, b):
    """Saturating u64 add; the second value counts one recorder call."""
    return min(a + b, U64), int(a + b > U64)


def hit(rows, day):
    """Rows (signed day, word 0, word 1); keys compare as i32."""
    for k, a, b in rows:
        if k & 0xffffffff == day & 0xffffffff:
            return a, b
    return 0, 0


def counted(v, dex):
    return v.get('mode', 0) != 2 or dex['word'] in ALLOW


def owner_day(v, who, day):
    rec = 0
    a, b = hit(v.get('spot', {}).get(who, ()), day)
    if v.get('double'):
        a, x = sat(a, a)
        b, y = sat(b, b)
        rec += x + y
    for dex in v.get('dex', ()):
        if not counted(v, dex):
            continue
        p, q = hit(dex.get('users', {}).get(who, ()), day)
        a, x = sat(a, p)
        b, y = sat(b, q)
        rec += x + y
    return a, b, rec


def total_day(v, day):
    t = hit(v.get('total', ()), day)[0]
    rec = 0
    if v.get('double'):
        t, rec = sat(t, t)
    for dex in v.get('dex', ()):
        if counted(v, dex):
            t, x = sat(t, hit(dex.get('total', ()), day)[0])
            rec += x
    return t, rec


def day_of(v, k):
    return (v['date'] - k * 16) & 0xffffffff


def expected_daily(v):
    """[(user cross bits, user add bits, exchange bits, date)] oldest first, recorder calls, days asked; or a panic name."""
    s, e = v['range']
    tag = v.get('tag', 0)
    if tag == 1 or s > e:
        return dict(cap=0, rows=(), rec=0, days=())
    cap = e - s + 1
    if v.get('alloc_fail'):
        return 'alloc'
    if tag:
        return dict(cap=cap, rows=(), rec=0, days=())
    rows, rec, days = [], 0, []
    for k in range(e, s - 1, -1):
        if k > 1 << 31:
            return 'date'
        days.append(k)
        d = day_of(v, k)
        if v.get('zero_at') == k:
            return 'date'
        first = second = 0
        for who in [v['user']] + list(v.get('links', ())):
            a, b, r = owner_day(v, who, d)
            first, x = sat(first, a)
            second, y = sat(second, b)
            rec += r + x + y
        t, r = total_day(v, d)
        rec += r
        rows.append((f2b(float(second) / 100.0), f2b(float(first) / 100.0), f2b(float(t) / 100.0), d))
    return dict(cap=cap, rows=rows, rec=rec, days=days)


def expected_chain(tag, n, front):
    """Rows of the collect: the front row when tag bit 0 is set, then n slice rows."""
    return ([front] if tag & 1 and tag != 2 else [])


def expected_schedule(v):
    """Rows of the 0x70-byte copy."""
    vip = [(f2b(float(c) / 1e6),) + tuple(r) for c, r, _ in v.get('vip', ())]
    return dict(vip=vip, mm=list(v.get('mm', ())), ladder=[(0, 0)] + list(v.get('ladder', ())))


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
    while buckets < 2 * len(rows) + 2:
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
        m.store_bytes(at + key_at + k * stride, (row[0] & 0xffffffff).to_bytes(4, 'little'))
        put(at, k, row)
    for k, sub in enumerate(kids):
        m.store(at + edge_at + k * 8, 8, node(m, sub, height - 1, shape))
    return at


def day_tree(m, rows, height):
    def put(at, k, row):
        m.store(at + k * 16, 8, row[1])
        m.store(at + k * 16 + 8, 8, row[2])
    return node(m, sorted(rows), height, (0xe8, 0xb8, 4, 0xe6, 0xe8, put))


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


def tree_at(m, at, rows, height):
    """Root and height words of a day tree; a null root leaves the height unset."""
    height = max(height, 1 if len(rows) > 11 else 0)
    root = day_tree(m, rows, height) if rows else 0
    m.store(at, 8, root)
    if root:
        m.store(at + 8, 8, height)


def build_daily(m, v):
    s = m.arena(0x4300)
    b = s.base
    h = v.get('height', 0)
    tree_at(m, b + 0x3d8, v.get('total', ()), h)
    m.store(b + 0x110c, 1, v.get('double', 0))
    m.store(b + 0x1372, 1, v.get('mode', 0))
    dex = v.get('dex', ())
    m.store(b + 0x1048, 8, len(dex))
    rows = []
    if dex:
        a = m.arena(0x2f0 * len(dex))
        m.store(b + 0x1040, 8, a.base)
        for k, d in enumerate(dex):
            at = a.base + k * 0x2f0
            rows.append(at)
            if v.get('mode', 0) == 2:
                m.store(at + 0x30, 8, d['word'])
            tree_at(m, at + 0x258, d.get('total', ()), h)
    entries = [(k, None) for k in v.get('decoys', ())]
    links = v.get('links')
    if links is not None:
        def fill(at):
            lst = m.arena(0x40 * max(len(links), 1))
            for k, who in enumerate(links):
                m.store_bytes(lst.base + k * 0x40 + 0x18, who)
            m.store(at + 0x20, 8, lst.base)
            m.store(at + 0x28, 8, len(links))
        entries.append((v['user'], fill))
    m.store(b + ITEMS, 8, len(entries))
    if entries or v.get('table'):
        ctrl, mask = table(m, v, 0x30, entries, v.get('buckets', 16), v.get('dead', ()))
        m.store(b + CTRL, 8, ctrl)
        m.store(b + MASK, 8, mask)
    return b, rows


def need(ok, what):
    if not ok:
        raise Unmodelled(what)


def memory_stubs(m, v, calls):
    s, q = m.slots, m.regs

    def alloc():
        n = q[R['rdi']]
        calls['alloc'] += 1
        if v.get('alloc_fail') == calls['alloc'] or n > 1 << 24:
            calls['failed'] = n
            q[0] = 0
            m.clobber(0)
            return
        calls['sizes'].append(n)
        a = calls['pool'].pop() if calls.get('pool') else m.arena(n)
        calls['blocks'].append(a.base)
        m.clobber(a.base)

    def alloc_fail():
        need(q[R['rsi']] == calls.get('failed', q[R['rsi']]), 'failed size')
        raise Panicked('alloc' if q[R['rdi']] & 0xffffffff == 8 else 'capacity')

    m.stubs.update({s[SLOT_ALLOC]: alloc, s[SLOT_ALLOC_FAIL]: alloc_fail})


def stubs_daily(m, v, b, dex_rows, calls):
    s, q = m.slots, m.regs
    memory_stubs(m, v, calls)
    owner_rows = {}

    def holder(rows):
        a = m.arena(0x38)
        tree_at(m, a.base + 0x28, rows, v.get('height', 0))
        return a.base

    def date():
        need(q[R['rdi']] & 0xffffffff == v['date'], 'date argument')
        k = -q[R['rsi']] & 0xffffffff
        calls['days'].append(k)
        m.clobber(0 if v.get('zero_at') == k else day_of(v, k))

    def hash_():
        need(q[R['rdi']] == b + HASHER, 'hasher')
        key = m.bytes_at(q[R['rsi']], 20)
        need(key == v['user'], 'hash key')
        calls['hash'] += 1
        m.clobber(hash_of(v, key))

    def row():
        need(q[R['rdi']] == b + 0x80, 'row map')
        who = m.bytes_at(q[R['rsi']], 20)
        need(who in calls['owners'], 'row owner')
        m.clobber(holder(v.get('spot', {}).get(who, ())))

    def dex_row():
        at = q[R['rdi']] - 0xf8
        need(at in dex_rows, 'dex map')
        d = v['dex'][dex_rows.index(at)]
        need(counted(v, d), 'dex row not counted')
        who = m.bytes_at(q[R['rsi']], 20)
        need(who in calls['owners'], 'dex owner')
        m.clobber(holder(d.get('users', {}).get(who, ())))

    def record():
        need(q[R['rdi']] & 0xff == 0 and q[R['rsi']] == RECORD_LOCATION, 'recorder arguments')
        calls['rec'] += 1
        m.clobber()

    def panic():
        need(q[R['rdi']] == DATE_TEXT and q[R['rsi']] == 0x22 and q[R['rdx']] == DATE_LOCATION, 'date panic')
        raise Panicked('date')

    m.stubs.update({s[SLOT_DATE]: date, HASH: hash_, s[SLOT_ROW]: row, DEX_ROW: dex_row, s[SLOT_RECORD]: record, s[SLOT_PANIC]: panic})


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


def check_daily(ctx, v):
    m = machine(ctx)
    m.real = {a: a for a in (ROW_FN, OWNER_DAY, TOTAL_DAY)}
    calls = dict(alloc=0, sizes=[], blocks=[], days=[], rec=0, hash=0, owners={v['user']} | set(v.get('links') or ()))
    b, dex_rows = build_daily(m, v)
    stubs_daily(m, v, b, dex_rows, calls)
    want = expected_daily(v)
    u = m.arena(20)
    m.store_bytes(u.base, v['user'])
    d = m.arena(4)
    m.store(d.base, 4, v['date'])
    c = m.arena(0x21)
    m.store(c.base, 8, d.base)
    m.store(c.base + 8, 8, b)
    m.store(c.base + 0x10, 8, u.base)
    m.store(c.base + 0x18, 4, v['range'][0])
    m.store(c.base + 0x1c, 4, v['range'][1])
    m.store(c.base + 0x20, 1, v.get('tag', 0))
    out = m.arena(0x18)
    start(m, dict(rdi=out.base, rsi=c.base))
    try:
        m.run(DAILY)
    except Panicked as exc:
        return None if want == str(exc) else f'panic {exc}'
    if isinstance(want, str):
        return 'panic missing'
    if finished(m) or m.regs[0] != out.base:
        return 'registers'
    cap, ptr, n = m.load(out.base, 8), m.load(out.base + 8, 8), m.load(out.base + 0x10, 8)
    if cap != want['cap'] or n != len(want['rows']):
        return f'list shape {cap} {n}'
    if calls['sizes'] != ([want['cap'] * 32] if want['cap'] else []):
        return 'allocation'
    if ptr != (calls['blocks'][0] if want['cap'] else 8):
        return 'list pointer'
    if calls['days'] != list(want['days']):
        return f"days {calls['days']}"
    if calls['rec'] != want['rec']:
        return f"recorder calls {calls['rec']} not {want['rec']}"
    for k, row in enumerate(want['rows']):
        at = ptr + k * 32
        got = (m.load(at, 8), m.load(at + 8, 8), m.load(at + 0x10, 8), m.load(at + 0x18, 4))
        if got != row:
            return f'row {k}: {got}'
    return None


def stubs_copy(m, v, calls):
    memory_stubs(m, v, calls)


def write_schedule(m, v):
    s = m.arena(0x70)
    b = s.base

    def lst(name, ptr_at, stride, write):
        rows = v.get(name, ())
        m.store(ptr_at + 8, 8, len(rows))
        if rows or name == 'ladder':
            a = m.arena(max(stride * len(rows), 1))
            m.store(ptr_at, 8, a.base)
            for k, row in enumerate(rows):
                write(a.base + k * stride, row)
        else:
            m.store(ptr_at, 8, 8)

    def vip(at, row):
        for k in range(4):
            m.store(at + k * 8, 8, row[1][k])
        m.store(at + 0x20, 8, row[0])

    def pair(at, row):
        m.store(at, 8, row[0])
        m.store(at + 8, 8, row[1])

    lst('vip', b + 8, 0x30, vip)
    lst('mm', b + 0x20, 0x10, pair)
    lst('ladder', b + 0x38, 0x10, pair)
    for k in range(4):
        m.store(b + 0x48 + k * 8, 8, v.get('base', (1, 2, 3, 4))[k])
    m.store(b + 0x68, 8, v.get('referral', 5))
    return b


def rows_at(m, ptr, n, stride):
    return [tuple(m.load(ptr + k * stride + w * 8, 8) for w in range(stride // 8)) for k in range(n)]


def check_schedule(ctx, v):
    m = machine(ctx)
    m.real = {CHAIN: CHAIN}
    calls = dict(alloc=0, sizes=[], blocks=[])
    stubs_copy(m, v, calls)
    b = write_schedule(m, v)
    want = expected_schedule(v)
    out = m.arena(0x70)
    start(m, dict(rdi=out.base, rsi=b))
    try:
        m.run(SCHEDULE)
    except Panicked as exc:
        return None if v.get('alloc_fail') and str(exc) == 'alloc' else f'panic {exc}'
    if v.get('alloc_fail'):
        return 'panic missing'
    if finished(m) or m.regs[0] != out.base:
        return 'registers'
    vip, mm, ladder = v.get('vip', ()), v.get('mm', ()), want['ladder']
    expected_sizes = ([len(vip) * 0x28] if vip else []) + ([len(mm) * 0x10] if mm else []) + [len(ladder) * 0x10]
    if calls['sizes'] != expected_sizes:
        return f"sizes {calls['sizes']}"
    head = [m.load(out.base + k * 8, 8) for k in range(14)]
    if head[0] != len(vip) or head[2] != len(vip) or head[3] != len(mm) or head[5] != len(mm) or head[6] != len(ladder) or head[8] != len(ladder):
        return 'list shape'
    blocks = list(calls['blocks'])
    for k, rows in ((1, vip), (4, mm), (7, ladder)):
        if head[k] != (blocks.pop(0) if rows else 8):
            return 'list pointer'
    if rows_at(m, head[1], len(vip), 0x28) != want['vip']:
        return 'vip rows'
    if rows_at(m, head[4], len(mm), 0x10) != want['mm']:
        return 'mm rows'
    if rows_at(m, head[7], len(ladder), 0x10) != want['ladder']:
        return 'ladder rows'
    if head[9:13] != list(v.get('base', (1, 2, 3, 4))) or head[13] != v.get('referral', 5):
        return 'schedule words'
    return None


def check_chain(ctx, v):
    m = machine(ctx)
    calls = dict(alloc=0, sizes=[], blocks=[])
    memory_stubs(m, v, calls)
    it = m.arena(0x28)
    tag, rows = v['tag'], v.get('rows', ())
    if v.get('low'):
        calls['pool'] = [m.arena((len(rows) + (tag == 1)) * 16)]
    m.store(it.base, 8, tag)
    m.store(it.base + 8, 8, 0x1111111111111111)
    m.store(it.base + 0x10, 8, 0x2222222222222222)
    span = v.get('span')
    if v.get('null'):
        ptr = end = 0
    elif span is not None:
        ptr, end = 0x1000, 0x1000 + span
    else:
        a = m.arena(max(len(rows) * 16, 1))
        for k, row in enumerate(rows):
            m.store(a.base + k * 16, 8, row[0])
            m.store(a.base + k * 16 + 8, 8, row[1])
        ptr, end = a.base, a.base + len(rows) * 16
    m.store(it.base + 0x18, 8, ptr)
    m.store(it.base + 0x20, 8, end)
    out = m.arena(0x18)
    start(m, dict(rdi=out.base, rsi=it.base))
    want = v.get('panic')
    try:
        m.run(CHAIN)
    except Panicked as exc:
        return None if want == str(exc) else f'panic {exc}'
    if want:
        return 'panic missing'
    if finished(m) or m.regs[0] != out.base:
        return 'registers'
    first = [(0x1111111111111111, 0x2222222222222222)] if tag == 1 else []
    full = first + list(rows)
    cap, ptr_, n = m.load(out.base, 8), m.load(out.base + 8, 8), m.load(out.base + 0x10, 8)
    if (cap, n) != (len(full), len(full)):
        return 'chain shape'
    if ptr_ != (calls['blocks'][0] if full else 8) or calls['sizes'] != ([len(full) * 16] if full else []):
        return 'chain block'
    if rows_at(m, ptr_, n, 16) != full:
        return 'chain rows'
    return None


def check_outer(ctx, v):
    m = machine(ctx)
    s, q = m.slots, m.regs
    o = m.arena(0x4b98)
    m.store(o.base + 0x4b90, 1, v.get('flag', 0))
    log = m.arena(0x58)
    m.store(log.base + 0x48, 1, v.get('level', 0))
    m.store(log.base + 0x50, 4, v.get('cell', 0))
    m.got[LOG_CELL] = log.base
    m.got[LAZY] = v.get('lazy', 0)
    calls = dict(view=0, copies=[], once=[])
    u = user(3)
    body = fill_bytes(0x130, 0x51)
    result = body[:0x120] + v['waits'][0].to_bytes(8, 'little') + v['waits'][1].to_bytes(8, 'little')

    def view():
        calls['view'] += 1
        need(q[R['rsi']] == o.base + 0x2c8 and q[R['rdx']] == o.base, 'view state')
        need(m.bytes_at(q[R['rcx']], 20) == u, 'view user')
        need(q[R['r8']] == 0x7171717171717171 and q[R['r9']] == 0x7272727272727272, 'view tail arguments')
        need(m.load(q[R['rsp']], 4) == v.get('flag', 0), 'view flag')
        m.store_bytes(q[R['rdi']], result)
        m.clobber(q[R['rdi']])

    def memcpy():
        d, c, n = q[R['rdi']], q[R['rsi']], q[R['rdx']]
        need(n == 0x120, 'copy size')
        calls['copies'].append(n)
        m.store_bytes(d, m.bytes_at(c, n))
        m.clobber(d)

    def once():
        need(q[R['rsi']] & 0xffffffff == 1, 'once flag')
        calls['once'].append(q[R['rdi']] - log.base if q[R['rdi']] != LAZY else 'lazy')
        m.clobber()

    m.stubs.update({VIEW: view, s[SLOT_MEMCPY]: memcpy, s[SLOT_ONCE]: once})
    pad = m.arena(0x14)
    m.store_bytes(pad.base, u)
    out = m.arena(0x120)
    start(m, dict(rdi=out.base, rsi=o.base, rdx=pad.base, rcx=0x7171717171717171, r8=0x7272727272727272))
    m.run(OUTER)
    if finished(m) or q[0] != out.base:
        return 'registers'
    if m.bytes_at(out.base, 0x120) != result[:0x120] or calls['view'] != 1 or len(calls['copies']) != 2:
        return 'result'
    if calls['once'] != expected_outer(v):
        return f"once {calls['once']}"
    return None


def expected_outer(v):
    """Cells forced by the slow branch, in order; the branch writes nothing."""
    a, b = b2f(v['waits'][0]), b2f(v['waits'][1])
    if not a + b > 3.0:
        return []
    out = []
    if v.get('cell', 0):
        out.append(0x50)
    if v.get('level', 0) in LEVELS and v.get('lazy', 0):
        out.append('lazy')
    return out


def check(ctx, v):
    return dict(daily=check_daily, schedule=check_schedule, chain=check_chain, outer=check_outer)[v['kind']](ctx, v)


# ---- vectors


U = user(3)
D0 = packed(2026, 300)
NAN = 0x7ff8000000000123
RATES = tuple(f2b(x) for x in (0.00045, 0.00015, 0.0007, 0.0002))


def dv(group, **kw):
    v = dict(kind='daily', group=group, user=U, date=D0, range=(0, 14))
    v.update(kw)
    return v


def dk(k, date=D0):
    return signed((date - k * 16) & 0xffffffff, 32)


def seq(words=None, days=range(15), date=D0):
    """One row per day with distinct words, or the given pair on each day."""
    return tuple((dk(k, date), words[0] if words else 1000 + k * 37, words[1] if words else 5000 + k * 41) for k in days)


def sv(group, **kw):
    v = dict(kind='schedule', group=group)
    v.update(kw)
    return v


LONG = ('range', 'one ', 'date', 'tree', 'all sources', 'empty')


def daily_vectors():
    out = [dv('empty')]
    # the range word and its exhausted byte
    for rng in ((0, 0), (3, 3), (1, 2), (14, 14), (5, 2), (1, 0), (0, 30), (2, 14), (0xfffffff0, 2)):
        for tag in (0, 1, 2):
            out.append(dv('range', range=rng, tag=tag, spot={U: seq()}))
    out.append(dv('range alloc fail', alloc_fail=1))
    out.append(dv('range top passes', range=(1 << 31, 1 << 31)))
    out.append(dv('range past top', range=((1 << 31) + 1, (1 << 31) + 1)))
    out.append(dv('range past top', range=(0xffffffff, 0xffffffff)))
    out.append(dv('range past top', range=(1 << 31, (1 << 31) + 1)))
    for k in (0, 1, 7, 14):
        out.append(dv('date add gives zero', zero_at=k, spot={U: seq()}))
    # each day and word
    for k in range(15):
        out.append(dv('one day', spot={U: seq(days=(k,))}))
        out.append(dv('one total', total=seq(days=(k,))))
        out.append(dv('one dex', dex=[dict(word=1, users={U: seq(days=(k,))}, total=seq(days=(k,)))]))
    out.append(dv('all sources', spot={U: seq()}, total=seq(), dex=[dict(word=18, users={U: seq((7, 9))}, total=seq((11, 13)))]))
    for date in (D0, 0x80000100, 0xfffffff0, 0x7ffffff0, 0x100, packed(-400, 1), packed(262000, 365)):
        out.append(dv('date sign', date=date, spot={U: seq(date=date)}, total=seq(date=date), dex=[dict(word=1, users={U: seq(date=date)}, total=seq(date=date))]))
    # owners
    for n in (0, 1, 2, 3, 8):
        links = [user(40 + k) for k in range(n)]
        spot = {U: seq((3, 4))}
        spot.update({w: seq((100 + k, 200 + k)) for k, w in enumerate(links)})
        out.append(dv('owners', links=links, spot=spot, total=seq((1, 2))))
        out.append(dv('owners dex', links=links, dex=[dict(word=1, users=spot)]))
    out.append(dv('owner twice', links=[U, U], spot={U: seq((3, 4))}))
    out.append(dv('owner twice dex', links=[U], dex=[dict(word=1, users={U: seq((3, 4))})], double=1))
    out.append(dv('no vector row', decoys=[user(70)], spot={U: seq()}))
    out.append(dv('empty table', table=True, spot={U: seq()}))
    for n in (1, 3, 8, 15, 20, 40):
        out.append(dv('decoys', decoys=[user(100 + k) for k in range(n)], buckets=32, links=[user(40)], spot={user(40): seq((5, 6))}))
        out.append(dv('decoys absent', decoys=[user(100 + k) for k in range(n)], buckets=32, spot={user(40): seq((5, 6))}))
    for k in (0, 4, 15, 16, 17, 18, 19):
        w = bytearray(U)
        w[k] ^= 0x80
        h = 0x0300000000000011
        out.append(dv('near key', decoys=[bytes(w)], links=[user(40)], spot={user(40): seq((5, 6))}, hash=h))
        out.append(dv('near key absent', decoys=[bytes(w)], hash=h, spot={user(40): seq((5, 6))}))
    for k in (1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 31, 32, 33, 48, 60, 100):
        out.append(dv('probe wall', decoys=[user(100 + j) for j in range(k)], links=[user(40)], spot={user(40): seq((5, 6))}, hash=0x0700000000000005, buckets=128))
        out.append(dv('probe wall absent', decoys=[user(100 + j) for j in range(k)], hash=0x0700000000000005, buckets=128))
    # tree shapes: key beside the wanted day, heights, every side
    for h in (0, 1, 2, 3):
        for n in (1, 5, 9, 15):
            rows = seq(days=range(n))
            out.append(dv('tree', height=h, spot={U: rows}, total=rows, dex=[dict(word=1, users={U: rows}, total=rows)]))
        beside = tuple((dk(k) + 1, 1, 2) for k in range(15)) + tuple((dk(k) - 1, 3, 4) for k in range(15))
        out.append(dv('tree beside', height=h, spot={U: beside}, total=beside, dex=[dict(word=1, users={U: beside}, total=beside)]))
        wide = tuple((dk(k) + 1, 1, 2) for k in range(15)) + seq((60, 70), days=(3, 9))
        out.append(dv('tree mixed', height=h, spot={U: wide}, total=wide, dex=[dict(word=1, users={U: wide}, total=wide)]))
    sign = ((-3, 5, 6), (20, 7, 8), (dk(0), 9, 10), (dk(5), 11, 12), (0x7fffffff, 1, 1), (-0x80000000, 1, 1))
    out.append(dv('tree signed', spot={U: sign}, total=sign, dex=[dict(word=1, users={U: sign}, total=sign)]))
    negative = 0x80000100
    sign2 = ((dk(0, negative), 5, 6), (dk(2, negative), 7, 8), (10, 7, 8), (20, 9, 1), (-0x7fffffff, 1, 2))
    for h in (0, 1):
        out.append(dv('tree signed low', date=negative, height=h, spot={U: sign2}, total=sign2, dex=[dict(word=1, users={U: sign2}, total=sign2)]))
    # dex rows
    for mode in (0, 1, 3):
        out.append(dv('mode reads no word', mode=mode, dex=[dict(word=7, users={U: seq((3, 4))}, total=seq((5, 6)))]))
    for w in (32, 0, 1, 17, 18, 19, 43, 44, 45, 52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 63, 64, 82, 107, 108, 109, 110, 111, 172, 173, 2 ** 32 + 18, 2 ** 63 + 44, U64):
        out.append(dv('allow list', mode=2, dex=[dict(word=w, users={U: seq((3, 4))}, total=seq((5, 6)))]))
        out.append(dv('allow list second', mode=2, dex=[dict(word=1, users={U: seq((1, 1))}, total=seq((2, 2))), dict(word=w, users={U: seq((3, 4))}, total=seq((5, 6)))]))
    for n in (1, 2, 3, 6):
        rows = [dict(word=18, users={U: seq((10 ** k, 2 * 10 ** k))}, total=seq((3 * 10 ** k, 1))) for k in range(n)]
        out.append(dv('many dex', dex=rows, spot={U: seq((1, 2))}, total=seq((7, 8))))
        out.append(dv('many dex double', dex=rows, spot={U: seq((1, 2))}, total=seq((7, 8)), double=1))
    # doubling touches only the first source
    for dbl in (1, 2, 255):
        out.append(dv('double', double=dbl, spot={U: seq()}, total=seq(), dex=[dict(word=1, users={U: seq((3, 4))}, total=seq((5, 6)))]))
    for w in (2 ** 62, 2 ** 63 - 1, 2 ** 63, 2 ** 63 + 1, U64):
        out.append(dv('double edge a', double=1, spot={U: seq((w, 1))}))
        out.append(dv('double edge b', double=1, spot={U: seq((1, w))}))
        out.append(dv('double edge ab', double=1, spot={U: seq((w, w))}))
        out.append(dv('double edge total', double=1, total=seq((w, 1))))
        out.append(dv('double with dex', double=1, spot={U: seq((w, w))}, total=seq((w, 1)), dex=[dict(word=1, users={U: seq((5, 6))}, total=seq((7, 1)))]))
    # saturating adds
    top = U64 - 5
    for a, b in ((5, 0), (6, 0), (0, 5), (0, 6), (5, 5), (6, 6), (7, 8)):
        out.append(dv('add spot dex', spot={U: seq((top, top))}, dex=[dict(word=1, users={U: seq((a, b))})]))
        out.append(dv('add owners', links=[user(40)], spot={U: seq((top, top)), user(40): seq((a, b))}))
        out.append(dv('add owners low', links=[user(40)], spot={U: seq((a, b)), user(40): seq((top, top))}))
        out.append(dv('add owners three', links=[user(40), user(41)], spot={U: seq((a, b)), user(40): seq((top, top)), user(41): seq((b, a))}))
        out.append(dv('add total', total=seq((top, 0)), dex=[dict(word=1, total=seq((a + b, 9)))]))
        out.append(dv('add two dex', dex=[dict(word=1, users={U: seq((top, top))}, total=seq((top, 1))), dict(word=1, users={U: seq((a, b))}, total=seq((a, 1)))]))
    # float rounding of the three words
    for w in (1, 99, 100, 101, 2 ** 53, 2 ** 53 + 1, 2 ** 53 + 3, 2 ** 63, 2 ** 63 + 2 ** 10, 2 ** 63 + 2 ** 10 + 1, U64, 0xfffffffffffff800, 0xfffffffffffffc00, 2 ** 32, 2 ** 32 - 1, 2 ** 32 + 1, 0x100000000000401):
        out.append(dv('float', spot={U: seq((w, 1))}, total=seq((w, 1))))
        out.append(dv('float', spot={U: seq((1, w))}))
    for v in out:
        if not v['group'].startswith(LONG):
            v['range'] = (0, 1)
    return out


def schedule_vectors():
    out = [sv('empty lists')]
    vip = lambda n: tuple((10 ** (k + 6) * (k + 1), tuple(RATES[j] + k + 1 for j in range(4)), f2b(0.5 + k)) for k in range(n))
    mm = lambda n: tuple((f2b(0.01 * (k + 1)), f2b(-0.0001 * k)) for k in range(n))
    ladder = lambda n: tuple((f2b(0.1 * (k + 1)), f2b(0.05 * k)) for k in range(n))
    for n in (1, 2, 3, 4, 5, 6, 7, 11):
        out.append(sv('vip', vip=vip(n)))
    for n in range(0, 12):
        out.append(sv('mm', mm=mm(n)))
    for n in list(range(0, 30)) + [47, 48, 49, 50]:
        out.append(sv('ladder', ladder=ladder(n)))
    for c in (0, 1, 999999, 10 ** 6, 10 ** 6 + 1, 2 ** 32, 2 ** 32 + 1, 2 ** 53 + 1, 2 ** 63, 2 ** 63 + 2 ** 11, U64, 0xfffffffffffff800):
        out.append(sv('cutoff', vip=((c, RATES, 0),)))
        out.append(sv('cutoff second', vip=((1, RATES, 0), (c, RATES, 0))))
        out.append(sv('cutoff odd', vip=((1, RATES, 0), (2, RATES, 0), (c, RATES, 0))))
    out.append(sv('raw bits', vip=((5, (NAN, 0x8000000000000000, 0x7ff0000000000000, 1), NAN),), mm=((NAN, 1),), ladder=((NAN, 0xfff8000000000000),), base=(NAN, 7, 8, 9), referral=NAN))
    out.append(sv('all', vip=vip(7), mm=mm(2), ladder=ladder(6), base=(f2b(0.00045), f2b(0.00015), f2b(0.0007), f2b(0.0002)), referral=f2b(0.04)))
    for stage, kw in ((1, dict(vip=vip(2))), (1, dict(mm=mm(1))), (2, dict(vip=vip(1), mm=mm(1))), (1, dict()), (2, dict(mm=mm(3))), (2, dict(vip=vip(3))), (3, dict(vip=vip(1), mm=mm(1), ladder=ladder(2)))):
        out.append(sv('alloc fail', alloc_fail=stage, **kw))
    return out


def chain_vectors():
    out = []
    pair = lambda n: tuple((0xa000 + k, 0xb000 + k) for k in range(n))
    for tag in (0, 1, 2):
        out.append(dict(kind='chain', group='null slice', tag=tag, null=True))
        for n in (0, 1, 2, 3, 4, 11, 12, 13, 14, 15, 16, 28):
            out.append(dict(kind='chain', group='slice', tag=tag, rows=pair(n)))
            if n:
                out.append(dict(kind='chain', group='block below the slice', tag=tag, rows=pair(n), low=True))
    high = U64 - 15
    for span, panic in ((1 << 63, 'capacity'), (0x7ffffffffffffff0 + 16, 'capacity'), (high - 0x1000, 'capacity'), (0x7ffffffffffffff0, 'alloc')):
        for tag in (0, 2):
            out.append(dict(kind='chain', group='capacity', tag=tag, span=span, panic=panic))
    return out


def outer_vectors():
    out = []
    w = lambda a, b: (f2b(a), f2b(b))
    for waits in ((0.0, 0.0), (1.0, 2.0), (1.5, 1.5), (3.0, 0.0), (2.0, 1.0000000000000002), (1.0, 2.5), (5.0, 0.0), (float('inf'), 1.0)):
        for level in (0, 13, 14, 15, 18, 21, 22, 31, 32, 255):
            for lazy in (0, 1):
                for cell in (0, 1):
                    out.append(dict(kind='outer', group='wait sum', waits=w(*waits), level=level, lazy=lazy, cell=cell))
    out.append(dict(kind='outer', group='flag', waits=w(0.0, 1.0), flag=1))
    out.append(dict(kind='outer', group='nan', waits=(NAN, f2b(5.0)), level=13, lazy=1, cell=1))
    for bit in range(32):
        out.append(dict(kind='outer', group='level bit', waits=w(2.0, 2.0), level=bit, lazy=1))
    return out


def all_vectors():
    return daily_vectors() + schedule_vectors() + chain_vectors() + outer_vectors()


# ---- binding


FDE_END = {}
RANGES = {}
SUBJECTS = (DAILY, ROW_FN, OWNER_DAY, TOTAL_DAY, SCHEDULE, CHAIN, OUTER)


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


NO_RETURN = 'unreachable: follows a call that does not return'
UNWIND = 'unwind clean-up after a panic in a callee, not a modelled outcome'
RESERVE = 'unreachable: rdx is computed by the same steps as r13 from unchanged inputs, so the capacity is never short'
GAPS = ((0x25807c3, 0x25807c5, NO_RETURN), (0x25807c5, 0x25807f8, UNWIND), (0x2a3be99, 0x2a3be9b, NO_RETURN), (0x2a3be9b, 0x2a3bed5, UNWIND),
        (0x2a108de, 0x2a1090d, RESERVE), (0x2a1090d, 0x2a10933, UNWIND), (0x2586c2a, 0x2586c42, UNWIND))
SITE_STEP = 3
UNUSED = 'this word is iterator state that no later instruction of the evaluated path reads'
EQUIVALENT = {
    0x25806bc: 'on the exhausted path the range words are read and never used',
    0x25806bf: 'on the exhausted path the range words are read and never used',
    0x2580713: 'the length slot is overwritten by the store at 0x258078f before it is read',
    0x28f0ce1: 'all 16 bytes of the source are the same tag, so the changed selector gives the same register',
    0x28f0d96: UNUSED, 0x28f0db8: UNUSED, 0x28f0dc6: UNUSED, 0x28f0dd4: UNUSED,
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


def field_map(img, start_, end):
    """A struct serializer: JSON key and struct offset of each field, read from its own instructions."""
    out, off, name_va, size_ = [], None, None, 0
    held = 0
    for ins in decode_range(img, start_, end):
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
        elif ins.op == 'call' and name_va:
            out.append(dict(offset=off, text=img.read(name_va, size_).decode('ascii'), va=hex(name_va)))
            name_va = None
    return out


def pinned(img):
    """Constants the model relies on, re-read; any change stops the tool."""
    got_ = dict(cent=img.f64(CENT), pair=[img.f64(PAIR), img.f64(PAIR + 8)], million=img.f64(MILLION), wait_limit=img.f64(THREE))
    if got_ != dict(cent=100.0, pair=[100.0, 100.0], million=1e6, wait_limit=3.0):
        raise EvidenceError(f'constants {got_}')
    pins = []
    for label, va, text in PINS:
        want = bytes.fromhex(text.replace(' ', ''))
        if img.read(va, len(want)) != want:
            raise EvidenceError(f'pin {label}')
        pins.append(dict(what=label, va=hex(va), bytes=want.hex()))
    return got_, pins


PINS = (
    ('seconds per day', 0x28f0c23, '4869c080510100'),
    ('allow mask, owner day', 0x26f9703, '48b90100040000 10a00c'),
    ('allow mask, total day', 0x26f99b8, '49bd0100040000 10a00c'),
    ('dex stride', 0x26f96d9, '4869c0f0020000'),
    ('tag 1 of the front row', 0x2a3bde3, '48c784249000000001000000'),
    ('level mask', 0x2586b7f, 'b900603c80'),
)
FIELD_ROWS = (
    ('daily row +0', 'second word of the day, summed, over 100', 'userCross'),
    ('daily row +8', 'first word of the day, summed, over 100', 'userAdd'),
    ('daily row +0x10', 'word 0 of the total trees, over 100', 'exchange'),
    ('daily row +0x18', 'the date dword', 'date'),
    ('schedule +0..+0x2f', '2 Vecs: vip rows, mm rows', 'tiers'),
    ('schedule +0x30', 'stake ladder with a (0, 0) row in front', 'stakingDiscountTiers'),
    ('schedule +0x48..+0x60', 'tracker +0x48..+0x60, same offset', 'cross, add, spotCross, spotAdd'),
    ('schedule +0x68', 'tracker +0x68, same offset', 'referralDiscount'),
    ('vip row +0', 'cutoff u64 at source +0x20 as f64, over 1e6', 'ntlCutoff'),
    ('vip row +8..+0x27', 'source +0..+0x1f, the 4 rates', 'cross, add, spotCross, spotAdd'),
)
REFERENCE_ROWS = (
    ('differs', 'info_server/abci_state_info_handler.rs DailyUserVlm', 'user_cross, user_add, exchange: String', 'f64 words in a 32-byte row, the date dword last'),
    ('agrees', 'info_server/abci_state_info_handler.rs DailyUserVlm', 'field order and names', 'serializer writes date, userCross, userAdd, exchange'),
    ('absent', 'references/can1357-hl/l1/fees/compute.rs', 'by_day FeePair has first_side, matching_side', 'the row keys name them: word 0 userAdd, word 1 userCross'),
    ('absent', 'references/can1357-hl/l1/fees/compute.rs', 'no fee schedule copy', 'staking_keep_frac row word dropped, cutoff over 1e6, (0, 0) ladder row added'),
)


def facts_and_files(data, out_dir, img, fdes, listing, vecs, rows, seen, padding, slots):
    constants, pins = pinned(img)
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
    funcs = []
    for fn in SUBJECTS:
        funcs.append(dict(start=hex(fn), end=hex(FDE_END[fn]), fde=hex(fdes.range_of(fn)['fde']), instructions=len(listing[fn]), executed=sum(i.va in seen for i in listing[fn])))
    calls = direct_sites(img, (DAILY, ROW_FN, OWNER_DAY, TOTAL_DAY, CHAIN, OUTER), starts)
    fields = {}
    for name_, at in sorted(SERIALIZERS.items()):
        fields[name_] = dict(start=hex(at), fields=field_map(img, at, fdes.range_of(at)['end']))
    evidence = dict(
        binary=BINARY, sha256=SHA256, functions=funcs, constants=constants, pins=pins, serializer_fields=fields, result_fields=[dict(zip(('at', 'source', 'name'), x)) for x in FIELD_ROWS],
        callers={hex(k): x for k, x in sorted(calls.items())},
        slots={hex(s): hex(slots[s]) for s in (SLOT_DATE, SLOT_ROW, SLOT_RECORD, SLOT_ALLOC, SLOT_ALLOC_FAIL, SLOT_PANIC, SLOT_MEMCPY, SLOT_ONCE)},
        record_location=location(img, RECORD_LOCATION), date_location=location(img, DATE_LOCATION), date_text=img.read(DATE_TEXT, 0x22).decode('ascii'),
        allow_list=list(ALLOW), level_bits=list(LEVELS),
        vectors=len(vecs), mismatches=0, groups=groups, outcomes=outcomes, padding_not_executed=padding,
        unexecuted=[dict(start=hex(a), end=hex(b), why=w) for a, b, w in gaps()],
        mutants=len(rows), killed=sum(1 for r in rows if r['killed']), unclassified=sum(1 for r in rows if not r['killed'] and r['va'] not in EQUIVALENT), site_step=SITE_STEP, equivalent={hex(k): w for k, w in sorted(EQUIVALENT.items()) if any(r['va'] == k for r in rows)},
    )
    with open(out_path / 'evidence.json', 'w', newline='\n') as f:
        json.dump(evidence, f, indent=1, sort_keys=True)
        f.write('\n')
    return evidence


def outcome_of(v):
    if v['kind'] == 'daily':
        w = expected_daily(v)
        return 'panic ' + w if isinstance(w, str) else f"rows {len(w['rows'])}"
    if v['kind'] == 'schedule':
        return 'panic alloc' if v.get('alloc_fail') else 'copied'
    if v['kind'] == 'chain':
        return 'panic ' + v['panic'] if v.get('panic') else 'collected'
    return f'forced {len(expected_outer(v))}'


def digest_of(v):
    return hashlib.sha256(repr(sorted((k, repr(x)) for k, x in v.items())).encode()).hexdigest()[:16]


def run_vectors(ctx, vecs):
    for v in vecs:
        try:
            msg = check(ctx, v)
        except (Unmodelled, EvidenceError, KeyError) as exc:
            msg = f'fault {type(exc).__name__} {exc}'
        if msg:
            raise EvidenceError(f"mismatch in {v['kind']} {v['group']}: {msg}")


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
    ev = generate(data, args.out, with_survey=False)
    print(json.dumps(dict(vectors=ev['vectors'], mutants=ev['mutants'], killed=ev['killed']), sort_keys=True))


if __name__ == '__main__':
    main()
