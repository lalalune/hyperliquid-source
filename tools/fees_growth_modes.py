#!/usr/bin/env python3
"""fees: node #94 growth mode setter, from bytes alone.

Static, no execution of the node.  The setter 0x273b4b0 with its 2 copies, the name split 0x3332080, the dex search
0x3332270, the asset id search 0x374a1a0 and the real time add are decoded from ELF bytes by the table decoder below,
which must land exactly on each FDE end, and interpreted in Python on every vector.  The map iterator, the set of dex
numbers, the allocator, the format call and the free call are stubs that check their arguments.  Each outcome is
compared with a separate closed-form model, then every conditional, field offset, immediate and read constant of the
first copy and the 3 helpers is mutated to test the vectors.

    python3 tools/fees_growth_modes.py --out <dir>

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


def filled(m, size, seed):
    a = m.arena(size)
    a.mem[:] = fill_bytes(size, seed)
    a.valid[:] = b'\1' * size
    return a


SETTER = 0x273b4b0
SETTER_B = 0x4d4b020
SETTER_C = 0x4d4b910
SPLIT = 0x3332080
FIND = 0x3332270
ASSET_ID = 0x374a1a0
TIME_ADD = 0x1459ca0
TIME_SIGNED = 0x15206e0
DATE_DAYS = 0x151f870
DROP = 0x3379490
FORMAT = 0x1344760
FLOAT_SHOW = 0x1571d50
FREE = 0x54c8cb0
PANIC_ADD = 0x157b480
PANIC_MUL = 0x157b4a0
PANIC_EXPECT = 0x157a9b0
SLOT_FREE = 0x576e010
SLOT_FORMAT = 0x576e040
SLOT_UNWRAP = 0x576e048
SLOT_ADD = 0x576e118
SLOT_MUL = 0x576e1b0
SLOT_EXPECT = 0x576e468
SLOT_BOUNDS = 0x576e470
SLOT_CAPACITY = 0x576dfb8
SLOT_ALLOC = 0x576dfd8
SLOT_COPY = 0x576dfe0
SLOT_BCMP = 0x576e378
SLOT_SPLIT = 0x5773ec8
SLOT_ASSET_ID = 0x5773318
SLOT_FIND = 0x5774708
SLOT_TIME = 0x576efb8
SLOT_SHOW = 0x576ea18
SLOT_GROW = 0x5774b80
LOC_ASSET = 0x56f1f18
LOC_TIME = 0x566af18
LOC_BOUNDS = 0x56f21c0
LOC_ADD = 0x56bdf70
LOC_UNWRAP_SETTER = 0x56e9af8
LOC_UNWRAP_FIND = 0x56e9ae0
TEXT_TIME = (0x21a01f, 0x26)
PIECES = 0x1fe732
ARG_30 = 0x20a1a0
SCALE_FREE = 0x20a730
COOLDOWNS = 0x208d90
READER_SITE = 0x3713146
READER_TEST = 0x3713225
READER_BYTES = bytes.fromhex('4584ed0f94c0')
FACTOR_TABLE = 0x204350
STATUS_TABLE = 0x59a8d0
OK = 0x186
TOO_LONG = 0x143
UNKNOWN_DEX = 0x141
UNKNOWN_ASSET = 0x64
ASSET_LOST = 0x60
BLOCKED = 0xe6
BAD_BYTE = 0xe7
TOO_SOON = 0xe0
LIMIT_NAME = 100
NICHE = 1 << 63
ROW = 0x2f0
ASSET = 0x30
META = 0x80
NODE = 0x120
STACK_TOP = 0x7f08
FRAME = STACK_TOP - 0x30 - 0x198
OUT_SIZE = 0x80
STACK_FILL = fill_bytes(0x8000, 0x35)
WHOLE = (SETTER, SETTER_B, SETTER_C, SPLIT, FIND, ASSET_ID, TIME_ADD, TIME_SIGNED, DATE_DAYS)
COPIES = {SETTER: dict(mode=0x8f2, registry=0x5b8), SETTER_B: dict(mode=0x8f2, registry=0x5b8), SETTER_C: dict(mode=0x1372, registry=0x1038)}
FORWARD_AT = 0x594
LONG_AT = 0x5ff
SEEN = None


# ---- model, written from the observed rules and independent of the machine


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


def unpack_day(p):
    return days_from_civil(signed(p, 32) >> 13, 1, 1) + (p >> 4 & 0x1ff) - 1


MIN_DAY = days_from_civil(-262143, 1, 1)
MAX_DAY = days_from_civil(262142, 12, 31)


def stamp(y, mo, d, secs=0, frac=0):
    return (pack_day(days_from_civil(y, mo, d)), secs, frac)


def time_add(t, seconds):
    """Rule of 0x1459ca0 for the two waits; a date past the range is a panic."""
    total = unpack_day(t[0]) * 86400 * 10 ** 9 + t[1] * 10 ** 9 + t[2] + int(seconds) * 10 ** 9
    secs, frac = divmod(total, 10 ** 9)
    day, secs = divmod(secs, 86400)
    if not MIN_DAY <= day <= MAX_DAY:
        return None
    return (pack_day(day), secs, frac)


def time_key(t):
    return (signed(t[0], 32), t[1], t[2])


def shift_time(t, nanos):
    secs, frac = divmod(unpack_day(t[0]) * 86400 * 10 ** 9 + t[1] * 10 ** 9 + t[2] + nanos, 10 ** 9)
    day, secs = divmod(secs, 86400)
    return (pack_day(day), secs, frac)


def bits(x):
    return struct.unpack('<Q', struct.pack('<d', x))[0]


def wait_of(mode):
    return 2592000 if mode == 3 else 60


def find_row(rows, name):
    """Returns row position, 'none' or 'panic'; the row part of a name ends at its first colon."""
    cut = name.find(b':')
    dex = name[:cut] if cut >= 0 else b''
    if not dex:
        return (0, True) if rows else ('panic', True)
    for i, r in enumerate(rows):
        if r['status'] != 3 and r['name'] == dex:
            return (i, False)
    return ('none', False)


def find_asset(row_, name):
    assets = row_['assets']
    if not assets:
        return None
    base = row_['index'] * 10000
    if base > U64:
        return 'mul'
    for i, a in enumerate(assets):
        if base + i > U64:
            return 'add'
        if a['name'] == name:
            return base + i
    return None


def rule(v):
    """Whole outcome: status or panic, the entry that failed, the pending list, lost and written assets."""
    rows, out = v['rows'], dict(status=None, panic=None, at=None, plan=[], lost=[], writes=[], drops=0)
    if v.get('claimed') is not None:
        c = v['claimed']
        if c >= 1 << 59:
            return dict(out, panic='capacity')
        if v.get('oom'):
            return dict(out, panic='oom')
    done = set()
    for k, e in enumerate(v['entries']):
        name, flag = e['name'], e['flag']
        out['at'] = k
        if e['cap'] == NICHE:
            out['stop'] = k
            break
        if len(name) > LIMIT_NAME:
            return dict(out, status=TOO_LONG)
        pos, empty = find_row(rows, name)
        if pos == 'panic':
            return dict(out, panic='unwrap-find')
        if pos == 'none':
            return dict(out, status=UNKNOWN_DEX)
        out['drops'] += empty
        r = rows[pos]
        hit = find_asset(r, name)
        if hit is None:
            return dict(out, status=UNKNOWN_ASSET)
        if hit in ('mul', 'add'):
            return dict(out, panic=hit + '-asset')
        d, i = hit // 10000, hit % 10000
        if d != r['index'] or i >= len(r['assets']):
            return dict(out, panic='bounds')
        a = r['assets'][i]
        if a['byte'] > 1:
            return dict(out, status=BAD_BYTE)
        new = flag ^ 1
        if a['byte'] != new and a['last'][0]:
            after = time_add(a['last'], wait_of(v['mode']))
            if after is None:
                return dict(out, panic='time')
            if time_key(after) > time_key(v['now']):
                return dict(out, status=TOO_SOON)
        if flag:
            if r['status'] != 3 and r['scale'] > 1.0:
                return dict(out, status=BLOCKED)
            if d not in done:
                done.add(d)
                for j, x in enumerate(r['assets']):
                    if d * 10000 + j > U64:
                        return dict(out, panic='add-scan')
                    if x['byte'] >= 2:
                        return dict(out, status=BAD_BYTE)
        out['plan'].append((hit, new))
    out['at'] = None
    for hit, new in out['plan']:
        d, i = hit // 10000, hit % 10000
        if d >= len(rows):
            return dict(out, panic='unwrap-setter')
        out['drops'] += 1
        r = rows[d]
        if r['index'] != d or i >= len(r['assets']):
            out['lost'].append(hit)
            continue
        if r['assets'][i]['byte'] != new:
            out['writes'].append((d, i, new))
    return dict(out, status=OK)


def outcome_name(v):
    w = rule(v)
    return f"{w['status']:#x}" if w['status'] else f"panic {w['panic']}"


# ---- machine set-up


class Panicked(Exception):
    """The node would panic here; a modelled outcome, unlike Unmodelled."""


def time_bytes(t):
    return struct.pack('<III', *t)


def exact(m, blob, shift=0):
    """Bytes in a strict arena of their own, so a read one past the end faults."""
    a = m.arena(max(len(blob) + shift, 1))
    a.mem[shift:shift + len(blob)] = blob
    a.valid[shift:shift + len(blob)] = b'\1' * len(blob)
    return a.base + shift


def write_rows(m, rows):
    tab = filled(m, max(len(rows), 1) * ROW, 0x31)
    metas, tables = [], []
    for i, r in enumerate(rows):
        off = i * ROW
        meta = filled(m, META, 0x43 + i)
        word(meta, 8, 8, exact(m, r['name']))
        word(meta, 0x10, 8, len(r['name']))
        meta.mem[0x60:0x68] = struct.pack('<Q', r['scale_bits'])
        t = filled(m, max(len(r['assets']), 1) * ASSET, 0x55 + i)
        shared = exact(m, b''.join(a['name'] for a in r['assets'])) if len(r['assets']) > 16 else None
        for k, a in enumerate(r['assets']):
            word(t, k * ASSET + 8, 8, shared + k * len(a['name']) if shared else exact(m, a['name']))
            word(t, k * ASSET + 0x10, 8, len(a['name']))
            t.mem[k * ASSET + 0x1c:k * ASSET + 0x28] = time_bytes(a['last'])
            t.mem[k * ASSET + 0x29] = a['byte']
        word(tab, off + 8, 8, t.base)
        word(tab, off + 0x10, 8, len(r['assets']))
        word(tab, off + 0x18, 8, 0)
        word(tab, off + 0x30, 8, r['index'])
        word(tab, off + 0x208, 8, meta.base)
        tab.mem[off + 0x230] = r['status']
        metas.append(meta)
        tables.append(t)
    return tab, metas, tables


def write_map(m, entries, claimed):
    """The BTreeMap the setter owns: one leaf of 11 keys after another; the stub of `next` walks them."""
    items = []
    names = []
    for k in range(0, len(entries), 11):
        node = filled(m, NODE, 0x21 + k)
        for i, e in enumerate(entries[k:k + 11]):
            at = exact(m, e['name'], e.get('shift', 0))
            word(node, 8 + i * 24, 8, e['cap'])
            word(node, 0x10 + i * 24, 8, at)
            word(node, 0x18 + i * 24, 8, len(e['name']))
            node.mem[0x114 + i] = e['flag']
            items.append((node.base, i))
            names.append((at, e['cap']))
    root = items[0][0] if items else 0
    head = filled(m, 0x18, 0x19)
    word(head, 0, 8, root)
    word(head, 8, 8, 2 if root else 0x1234)
    word(head, 0x10, 8, claimed if claimed is not None else len(entries))
    return head, items, names


def machine(ctx, v):
    img, code, slots, got, callees = ctx
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
    m.top = stack.base + STACK_TOP
    m.freed = []
    m.calls = []
    m.lost = []
    m.done = set()
    m.pos = 0
    m.allocs = []
    m.vec = None
    m.forward = None
    frame = m.top - 0x30 - 0x198
    head_at = frame + 0x138
    c = callees[v['copy']]

    def panic_add():
        loc = m.regs[R['rdi']]
        raise Panicked({LOC_ASSET: 'add-asset', c['loc_add']: 'add-scan'}[loc])

    def panic_mul():
        if m.regs[R['rdi']] != LOC_ASSET:
            raise Unmodelled('mul location')
        raise Panicked('mul-asset')

    def panic_expect():
        r = m.regs
        if (r[R['rdi']], r[R['rsi']], r[R['rdx']]) != (TEXT_TIME[0], TEXT_TIME[1], LOC_TIME):
            raise Unmodelled('expect arguments')
        raise Panicked('time')

    def panic_bounds():
        if m.regs[R['rdi']] != c['loc_bounds']:
            raise Unmodelled('bounds location')
        raise Panicked('bounds')

    def panic_unwrap():
        r = m.regs
        if r[R['rsi']] != 0x2b or m.load(r[R['rdx']], 2) != UNKNOWN_DEX:
            raise Unmodelled('unwrap arguments')
        raise Panicked({c['loc_unwrap']: 'unwrap-setter', LOC_UNWRAP_FIND: 'unwrap-find'}[r[R['r8']]])

    def panic_capacity():
        r = m.regs
        size = (v['claimed'] << 4) & U64
        if r[R['rdi']] == 0 and r[R['rsi']] == size:
            raise Panicked('capacity')
        if r[R['rdi']] == 8 and r[R['rsi']] == size:
            raise Panicked('oom')
        raise Unmodelled('capacity arguments')

    def show():
        r = m.regs
        args = r[R['rdx']]
        if r[R['rsi']] != PIECES or m.load(args, 8) != ARG_30 or m.load(args + 8, 8) != FLOAT_SHOW:
            raise Unmodelled('format arguments')
        m.store(r[R['rdi']], 8, 0x111)
        m.store(r[R['rdi']] + 8, 8, 0x222)
        m.store(r[R['rdi']] + 16, 8, 0x333)
        m.calls.append('format')
        m.clobber()

    def bcmp():
        r = m.regs
        n = r[R['rdx']]
        same = all(m.load(r[R['rdi']] + k, 1) == m.load(r[R['rsi']] + k, 1) for k in range(n))
        m.clobber(0 if same else 1)

    def drop():
        if m.load(m.regs[R['rdi']], 2) != UNKNOWN_DEX:
            raise Unmodelled('drop argument')
        m.calls.append('drop')
        m.clobber()

    def drop_lost():
        r = m.regs
        if r[R['rdi']] != frame + 0x58 or m.load(r[R['rdi']], 2) != ASSET_LOST:
            raise Unmodelled('lost argument')
        m.lost.append(m.load(r[R['rdi']] + 8, 8))
        m.clobber()

    def alloc():
        size = m.regs[R['rdi']]
        if v.get('oom') and not m.allocs:
            m.allocs.append(size)
            m.clobber(0)
            return
        if size > 0x10000:
            raise Unmodelled('alloc size')
        a = m.arena(size)
        m.allocs.append(size)
        if m.vec is None:
            m.vec = a
        m.clobber(a.base)

    def copy():
        r = m.regs
        for k in range(r[R['rdx']]):
            m.store(r[R['rdi']] + k, 1, m.load(r[R['rsi']] + k, 1))
        m.clobber(r[R['rdi']])

    def free():
        r = m.regs
        if r[R['rdx']] != 0:
            raise Unmodelled('free flags')
        if m.vec is not None and r[R['rdi']] == m.vec.base:
            m.vec_free = r[R['rsi']]
            m.freed.append('list')
            m.vec_bytes = bytes(m.vec.mem)
        else:
            m.freed.append((r[R['rdi']], r[R['rsi']]))
        m.clobber()

    def iter_next():
        r = m.regs
        if r[R['rdi']] != frame + 0x58 or r[R['rsi']] != head_at:
            raise Unmodelled('next arguments')
        if m.pos == 0 and not m.calls.count('next'):
            words = [m.load(head_at + 8 * k, 8) for k in range(9)]
            root, height, size = m.map_words
            if words != [int(root != 0), 0, root, height, int(root != 0), 0, root, height, size if root else 0]:
                raise Unmodelled('iterator words')
        m.calls.append('next')
        if m.pos < len(m.items):
            node, i = m.items[m.pos]
            m.pos += 1
            m.store(r[R['rdi']], 8, node)
            m.store(r[R['rdi']] + 8, 8, 0x4444)
            m.store(r[R['rdi']] + 0x10, 8, i)
        else:
            m.store(r[R['rdi']], 8, 0)
        m.clobber()

    def insert():
        r = m.regs
        if r[R['rdi']] != frame + 0xc8:
            raise Unmodelled('set argument')
        if not m.done and (m.load(frame + 0xc8, 8) != 0 or m.load(frame + 0xd8, 8) != 0):
            raise Unmodelled('set not empty')
        key = r[R['rsi']]
        present = key in m.done
        m.done.add(key)
        m.clobber(int(present))

    def set_drop():
        if m.regs[R['rdi']] != frame + 0xc8:
            raise Unmodelled('set drop argument')
        m.calls.append('set drop')
        m.clobber()

    def grow():
        raise Unmodelled('list grew')

    m.stubs.update({slots[SLOT_ADD]: panic_add, slots[SLOT_MUL]: panic_mul, slots[SLOT_EXPECT]: panic_expect, slots[SLOT_BOUNDS]: panic_bounds, slots[SLOT_UNWRAP]: panic_unwrap,
                    slots[SLOT_CAPACITY]: panic_capacity, slots[SLOT_FORMAT]: show, slots[SLOT_BCMP]: bcmp, DROP: drop, slots[SLOT_FREE]: free, slots[SLOT_ALLOC]: alloc, slots[SLOT_COPY]: copy,
                    slots[SLOT_GROW]: grow})
    m.stubs.update({c['next']: iter_next, c['insert']: insert, c['set_drop']: set_drop, c['drop_lost']: drop_lost})
    return m


def enter(m, fn, *args):
    m.regs[R['rsp']] = m.top
    m.store(m.top, 8, 0xfeedface)
    for name_, val in zip(('rdi', 'rsi', 'rdx'), args):
        m.regs[R[name_]] = val
    for name_ in ('rbx', 'rbp', 'r12', 'r13', 'r14', 'r15'):
        m.regs[R[name_]] = 0xc0de0000 + R[name_]
    m.run(fn)
    if m.regs[R['rsp']] != m.top + 8:
        raise Unmodelled('stack not balanced')
    for name_ in ('rbx', 'rbp', 'r12', 'r13', 'r14', 'r15'):
        if m.regs[R[name_]] != 0xc0de0000 + R[name_]:
            raise Unmodelled(f'{name_} not restored')


def stack_at(m, off, size):
    o = m.regs[R['rsp']] + off - m.stack.base
    return bytes(m.stack.mem[o:o + size])


def out_ok(m, out, w, v, names):
    fresh = fill_bytes(OUT_SIZE, 0x63)
    status = read(out, 0, 2)
    if status != w['status']:
        return f'status {status:#x} not {w["status"]:#x}'
    if status in (TOO_LONG, UNKNOWN_DEX, UNKNOWN_ASSET):
        if m.forward is None or bytes(out[2:0x60]) != m.forward[2:]:
            return 'forwarded bytes'
        if bytes(out[0x60:]) != fresh[0x60:]:
            return 'bytes past the result'
    elif status == TOO_SOON:
        if bytes(out[2:8]) != struct.pack('<Q', ARG_30)[:6]:
            return 'bytes before the text'
        if (read(out, 8), read(out, 0x10), read(out, 0x18)) != (0x111, 0x222, 0x333):
            return 'text words'
        if bytes(out[0x20:]) != fresh[0x20:]:
            return 'bytes past the result'
    elif bytes(out[2:]) != fresh[2:]:
        return 'bytes past the result'
    if status == UNKNOWN_ASSET:
        name = v['entries'][w['at']]['name']
        if read(out, 8) != len(name) or read(out, 0x18) != len(name) or (name and bytes(m.load(read(out, 0x10) + k, 1) for k in range(len(name))) != name):
            return 'name in the result'
        if not name and read(out, 0x10) != 1:
            return 'empty name pointer'
    if m.calls.count('format') != (status == TOO_SOON):
        return 'format count'
    return None


def state_ok(m, tab, metas, tables, before, w, v):
    if bytes(tab.mem) != before[0] or [bytes(x.mem) for x in metas] != before[1]:
        return 'row bytes'
    want = [bytearray(x) for x in before[2]]
    for d, i, new in w['writes'] if w['status'] == OK else ():
        at = i * ASSET
        want[d][at + 0x29] = new
        want[d][at + 0x1c:at + 0x28] = time_bytes(v['now'])
    if [bytes(x.mem) for x in tables] != [bytes(x) for x in want]:
        return 'asset bytes'
    return None


def frees_ok(m, names, w, v):
    want = [(a, c) for a, c in names if c and c != NICHE] + ['list'] * bool(names or v.get('claimed'))
    if m.freed != want:
        return f'freed {len(m.freed)} not {len(want)}'
    if 'list' in want:
        if m.vec_free != len(m.vec.mem):
            return 'list size'
        plan = w['plan']
        for k, (hit, new) in enumerate(plan):
            if read(m.vec_bytes, k * 16) != hit or m.vec_bytes[k * 16 + 8] != new:
                return 'list row'
    if m.calls.count('set drop') != 1:
        return 'set drop count'
    if m.calls.count('drop') != w['drops']:
        return 'drop count'
    if m.lost != w['lost']:
        return 'lost list'
    if len(m.allocs) != int(bool(names or v.get('claimed'))) + (w['status'] == UNKNOWN_ASSET and bool(v['entries'][w['at']]['name'])):
        return 'alloc count'
    return None


def check(ctx, v):
    m = machine(ctx, v)
    w = rule(v)
    s = COPIES[v['copy']]
    tab, metas, tables = write_rows(m, v['rows'])
    ex = filled(m, 0x1400, 0x41)
    ex.mem[0x60:0x6c] = time_bytes(v['now'])
    ex.mem[s['mode']] = v['mode']
    word(ex, s['registry'] + 8, 8, tab.base)
    word(ex, s['registry'] + 0x10, 8, len(v['rows']))
    head, m.items, names = write_map(m, v['entries'], v.get('claimed'))
    m.map_words = (read(head.mem, 0), read(head.mem, 8), read(head.mem, 0x10))
    out = m.arena(OUT_SIZE, strict=False)
    out.mem[:] = fill_bytes(OUT_SIZE, 0x63)
    before = (bytes(tab.mem), [bytes(x.mem) for x in metas], [bytes(x.mem) for x in tables])
    ex_before = bytes(ex.mem)

    def forward():
        m.forward = stack_at(m, 0x58, 0x60)

    def too_long():
        m.forward = b'\0\0' + stack_at(m, 8, 4) + stack_at(m, 0xc, 2) + m.regs[R['r13']].to_bytes(8, 'little') + m.regs[R['rbp']].to_bytes(8, 'little') + stack_at(m, 0xf0, 0x48)

    m.hooks[v['copy'] + FORWARD_AT] = forward
    m.hooks[v['copy'] + LONG_AT] = too_long
    try:
        enter(m, v['copy'], out.base, ex.base, head.base)
    except Panicked as exc:
        return None if w['panic'] == str(exc) else f'panic {exc} not {w["panic"]}'
    if w['panic']:
        return f'no panic, wanted {w["panic"]}'
    return out_ok(m, out.mem, w, v, names) or state_ok(m, tab, metas, tables, before, w, v) or frees_ok(m, names, w, v) or (None if bytes(ex.mem) == ex_before else 'exchange bytes')


# ---- vectors


NOW = stamp(2026, 6, 1, 3600, 5)
OLD = stamp(2025, 1, 1)
NONE = (0, 0, 0)
NAN = float('nan')
INF = float('inf')


def asset(name, byte=0, last=NONE):
    return dict(name=name, byte=byte, last=last)


def dex(name, index, assets, status=1, scale=0.5):
    return dict(name=name, index=index, assets=assets, status=status, scale=scale, scale_bits=bits(scale))


def entry(name, flag, cap=None, shift=0):
    return dict(name=name, flag=flag, cap=len(name) + 3 if cap is None else cap, shift=shift)


def fixture():
    return [dex(b'', 0, [asset(b'BTC'), asset(b'ETH', 1)]), dex(b'abc', 1, [asset(b'abc:X'), asset(b'abc:Y', 1), asset(b'abc:Z')]), dex(b'dead', 2, [asset(b'dead:Q')], status=3)]


def vec(group, entries, rows=None, mode=0, now=NOW, **kw):
    return dict(kind='setter', copy=SETTER, group=group, entries=entries, rows=fixture() if rows is None else rows, mode=mode, now=now, **kw)


def gate_vectors():
    out = []
    lasts = [('none', NONE), ('old', OLD)]
    for mode in (0, 1, 2, 3, 4, 0xff):
        w = wait_of(mode) * 10 ** 9
        for label, delta in (('equal', 0), ('ns over', 1), ('ns under', -1), ('s over', 10 ** 9), ('day over', 86400 * 10 ** 9), ('day under', -86400 * 10 ** 9), ('60 s', w - 60 * 10 ** 9), ('30 d', w - 2592000 * 10 ** 9)):
            lasts.append((f'{mode} {label}', shift_time(NOW, delta - w)))
    for mode in (0, 3):
        for label, last in lasts:
            for name in (b'BTC', b'abc:X'):
                for flag in (0, 1):
                    for byte in (0, 1):
                        rows = fixture()
                        pos = 0 if name == b'BTC' else 1
                        rows[pos]['assets'][0].update(byte=byte, last=last)
                        out.append(vec('gate', [entry(name, flag)], rows, mode))
    # the three words of the time compare one at a time: a later word must not rule once an earlier one has decided
    for mode in (0, 3):
        w = wait_of(mode)
        for d_day, d_sec, d_ns in ((1, -3600, 0), (-1, 3600, 0), (0, 1, -5), (0, -1, 5), (1, 0, -5), (-1, 0, 5)):
            after = (pack_day(unpack_day(NOW[0]) + d_day), NOW[1] + d_sec, NOW[2] + d_ns)
            for flag in (0, 1):
                rows = fixture()
                rows[0]['assets'][0].update(byte=flag, last=shift_time(after, -w * 10 ** 9))
                out.append(vec('time words', [entry(b'BTC', flag)], rows, mode))
    # signed day word, a date before year 0 against one after it
    for now, last in ((stamp(1, 1, 1, 30), stamp(-1, 12, 31, 86399)), (stamp(-1, 6, 1), stamp(1, 6, 1)), (stamp(-1, 6, 2), stamp(-1, 6, 1))):
        rows = fixture()
        rows[0]['assets'][0].update(byte=1, last=last)
        out.append(vec('signed day', [entry(b'BTC', 1)], rows, 0, now))
    rows = fixture()
    rows[0]['assets'][0].update(byte=1, last=stamp(262142, 12, 31, 86399))
    out.append(vec('date range', [entry(b'BTC', 1)], rows, 0))
    rows = fixture()
    rows[0]['assets'][0].update(byte=1, last=(0, 7, 9))
    out.append(vec('zero day', [entry(b'BTC', 1)], rows, 0))
    return out


def scale_vectors():
    out = []
    for scale in (0.0, 0.5, 1.0, math.nextafter(1.0, 2.0), 3.0, INF, NAN, -1.0):
        for status in (0, 1, 2, 3):
            for flag in (0, 1):
                for name, pos in ((b'BTC', 0), (b'abc:X', 1)):
                    rows = fixture()
                    rows[pos].update(scale=scale, scale_bits=bits(scale), status=status)
                    rows[pos]['assets'][0]['byte'] = flag
                    out.append(vec('scale', [entry(name, flag)], rows))
    return out


def byte_vectors():
    out = []
    for byte in (0, 1, 2, 3, 0x7f, 0x80, 0xff):
        for flag in (0, 1):
            for at in range(3):
                for target in range(3):
                    rows = fixture()
                    rows[1]['assets'][at]['byte'] = byte
                    out.append(vec('asset byte', [entry(b'abc:' + b'XYZ'[target:target + 1], flag)], rows))
    return out


def list_vectors():
    out = []
    pairs = [(b'BTC', 0), (b'ETH', 1), (b'abc:X', 1), (b'abc:Y', 0), (b'abc:Z', 0)]
    out.append(vec('many', [entry(n, f) for n, f in sorted(pairs)]))
    out.append(vec('many', [entry(n, f ^ 1) for n, f in sorted(pairs)]))
    out.append(vec('empty map', []))
    out.append(vec('no capacity', [entry(b'BTC', 1, cap=0), entry(b'abc:X', 0, cap=0)]))
    out.append(vec('capacity text', [entry(b'', 1, cap=0)]))
    out.append(vec('claimed length', [], claimed=3))
    for bad in ((b'abc:Q', 0), (b'zzz:X', 1), (b'dead:Q', 1), (b'x' * 101, 0)):
        for tail in ((), ((b'zz', 1),)):
            good = [(b'BTC', 1), (b'ETH', 1)]
            items = sorted(good + [bad] + list(tail))
            out.append(vec('later failure', [entry(n, f) for n, f in items]))
    rows = fixture()
    rows[1]['assets'][1]['byte'] = 2
    out.append(vec('blocked after first', [entry(b'BTC', 0), entry(b'abc:X', 1), entry(b'abc:Z', 1)], rows))
    rows = fixture()
    rows[1]['scale'], rows[1]['scale_bits'] = 2.0, bits(2.0)
    out.append(vec('second entry scale', [entry(b'BTC', 0), entry(b'abc:X', 0), entry(b'abc:Z', 1)], rows))
    rows = fixture()
    out.append(vec('same dex twice', [entry(b'abc:X', 1), entry(b'abc:Y', 1), entry(b'abc:Z', 1)], rows))
    big = [dex(b'', 0, [asset(b'c%02d' % i, i & 1) for i in range(30)])]
    out.append(vec('map over nodes', [entry(b'c%02d' % i, i % 3 & 1) for i in range(30)], big))
    big = [dex(b'', 0, [asset(b'c%02d' % i, 0) for i in range(30)])]
    out.append(vec('map over nodes', [entry(b'c%02d' % i, 0) for i in range(12)] + [entry(b'miss', 1)] + [entry(b'zz%d' % i, 1) for i in range(12)], big))
    # a key whose capacity word is the Option niche ends the first loop: the rest are freed with no test
    out.append(vec('niche key', [entry(b'BTC', 1), entry(b'x', 0, cap=NICHE), entry(b'nope', 1), entry(b'zero', 1, cap=0), entry(b'zz', 1), entry(b'zzz', 0)]))
    out.append(vec('niche key', [entry(b'x', 0, cap=NICHE)]))
    for claimed, oom in ((1 << 60, False), (1 << 59, False), ((1 << 59) - 1, True), (1 << 63, False)):
        out.append(vec('capacity', [], claimed=claimed, oom=oom))
    out.append(vec('alloc null', [entry(b'BTC', 1)], claimed=1, oom=True))
    return out


def name_vectors():
    out = []
    for n in (0, 1, 3, 99, 100, 101, 102, 4096):
        for prefix in (b'', b'abc:'):
            name = prefix + b'n' * max(n - len(prefix), 0)
            rows = fixture()
            rows[1]['assets'].append(asset(name))
            rows[0]['assets'].append(asset(name))
            out.append(vec('length', [entry(name, 0)], rows))
    for name in (b'', b':', b':BTC', b'abc', b'abc:', b'abd:X', b'ab:X', b'abcd:X', b'dead:Q', b'abc:X:Y', b'BT', b'BTCC', b'BTD', b'abc:x'):
        for flag in (0, 1):
            out.append(vec('names', [entry(name, flag, cap=len(name))]))
            rows = fixture()
            rows[0]['status'] = 3
            out.append(vec('names', [entry(name, flag, cap=len(name))], rows))
    out.append(vec('empty table', [entry(b'BTC', 0)], []))
    out.append(vec('empty table', [entry(b'abc:X', 0)], []))
    out.append(vec('no assets', [entry(b'abc:X', 0)], [dex(b'abc', 0, [])]))
    out.append(vec('no assets', [entry(b'', 0, cap=0)], [dex(b'abc', 0, [])]))
    out.append(vec('second row name', [entry(b'abc:X', 0)], [dex(b'abc', 0, [], status=3), dex(b'abc', 1, [asset(b'abc:X')])]))
    # the search for the first colon has a byte loop, an aligned 16-byte loop and a tail loop
    for shift in range(8):
        for size in range(0, 42, 3 if shift else 1):
            name = b'q' * size
            out.append(vec('no colon', [entry(name, 0, shift=shift)]))
            for cut in range(0, size, 5 if shift else 1):
                n = name[:cut] + b':' + name[cut + 1:]
                rows = [dex(b'', 0, []), dex(n[:cut] if cut else b'zz', 1, [asset(n)])]
                out.append(vec('colon', [entry(n, 0, shift=shift)], rows))
    return out


def shape_vectors():
    out = []
    # row position and row index disagree: rows of a healthy table never do, these reach the apply branches
    two = [dex(b'', 1, [asset(b'a0'), asset(b'a1'), asset(b'a2')]), dex(b'r', 0, [asset(b'r:x')])]
    out.append(vec('index shape', [entry(b'a0', 0)], two))
    out.append(vec('index shape', [entry(b'a0', 1), entry(b'r:x', 1)], two))
    three = [dex(b'', 5, [asset(b'a0')])]
    out.append(vec('index shape', [entry(b'a0', 0)], three))
    four = [dex(b'', 1, [asset(b'a0'), asset(b'a1'), asset(b'a2')]), dex(b'r', 1, [asset(b'r:x')])]
    out.append(vec('index shape', [entry(b'a2', 0)], four))
    out.append(vec('index shape', [entry(b'a2', 0), entry(b'r:x', 1)], four))
    wide = [dex(b'', 0, [asset(b'w%05d' % i) for i in range(10002)])]
    out.append(vec('row of 10002', [entry(b'w09999', 0)], wide))
    out.append(vec('row of 10002', [entry(b'w10000', 0)], wide))
    top = (U64 // 10000)
    edge = [dex(b'', top, [asset(b'x%04d' % i, 1) for i in range(1700)])]
    out.append(vec('sum wraps', [entry(b'x0000', 0)], edge))
    out.append(vec('sum wraps', [entry(b'x1615', 0)], edge))
    out.append(vec('sum wraps', [entry(b'x1616', 0)], edge))
    out.append(vec('sum wraps', [entry(b'x0000', 1)], [dex(b'', top, [asset(b'x%04d' % i, 1) for i in range(1617)])]))
    out.append(vec('large index', [entry(b'big', 1)], [dex(b'', 100000, [asset(b'big', 1)])]))
    out.append(vec('product wraps', [entry(b'x', 0)], [dex(b'', top + 1, [asset(b'x')])]))
    return out


def all_vectors():
    a = gate_vectors() + scale_vectors() + byte_vectors() + list_vectors() + name_vectors() + shape_vectors()
    b = [dict(v, copy=c) for c in (SETTER_B, SETTER_C) for v in a]
    return a + b


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
    return decode_range(img, *RANGES[s][0])


def direct_calls(rows):
    return [(i.va - rows[0].va, i.ops[0][1]) for i in rows if i.op == 'call' and i.ops[0][0] == 't']


def bind_callees(listing):
    """Direct callees of each copy, named by their place in copy A: the three copies call their own copies of them."""
    out = {}
    for s in COPIES:
        calls = dict(direct_calls(listing[s]))
        by = {i.va - s: i for i in listing[s]}
        out[s] = dict(next=calls[0x16f], insert=calls[0x30a], drop_lost=calls[0x4b1], set_drop=calls[0x58a], loc_bounds=by[0x7a8].ops[1][4], loc_add=by[0x7c6].ops[1][4], loc_unwrap=by[0x7ea].ops[1][4])
    return out


def build(data):
    check_digest(data)
    fdes = bind_fdes(data)
    img = Image(data)
    code = {}
    for s in RANGES:
        code.update({i.va: i for i in decode_subject(img, s)})
    slots, got = scan_slots(img, code)
    listing = {s_: decode_subject(img, s_) for s_ in RANGES}
    return img, code, fdes, slots, got, listing, bind_callees(listing)


# ---- mutation survey


UNWIND = 'unwind clean-up after a panic in a callee, not a modelled outcome'
AFTER_PANIC = 'unreachable: follows a call that does not return'
NO_GROW = 'the list is reserved with the map length and takes at most one row per key, so the grow call never runs'
NO_MUL = 'the same product passed in 0x374a1a0 for this row before the scan starts'
NO_ALLOC = 'name clone: allocation failure and a length above isize::MAX; names here are at most 100 bytes'


def copy_gaps(base):
    return (
        (base + 0x48, base + 0x4d, AFTER_PANIC), (base + 0x31f, base + 0x32a, NO_GROW), (base + 0x7b5, base + 0x7b7, AFTER_PANIC),
        (base + 0x7b7, base + 0x7c6, NO_MUL), (base + 0x7d3, base + 0x7d5, AFTER_PANIC), (base + 0x801, base + 0x803, AFTER_PANIC), (base + 0x810, FDE_END[base], UNWIND),
    )


def gaps():
    out = []
    for s in COPIES:
        out += copy_gaps(s)
    out += [(0x3332220, 0x3332234, 'the search stops only on a colon inside the name, so the at-end branch of its caller loop never runs')]
    out += [(0x333234e, 0x3332354, 'panic stub call site already counted'), (0x3332354, 0x3332371, UNWIND)]
    out += [(0x374a238, 0x374a243, NO_ALLOC), (0x374a24e + 6, 0x374a258, 'plain move after the allocation, jump over the empty case'), (0x374a2ae, 0x374a2bc, NO_ALLOC)]
    return out


SUBJECTS = (SETTER, FIND, ASSET_ID, SPLIT)
NOT_MUTATED = (SETTER_B, SETTER_C, TIME_ADD, TIME_SIGNED, DATE_DAYS)
HINT = 'the word test only says where the byte loop should look; any change here adds a stop or moves the byte loop, and that loop finds the same first colon'
EQUIVALENT = {
    0x3332207: 'the search stops only on a colon inside the name, so r8 is never past the end and the byte read is always a colon; both ways of the branch reach 0x3332234',
    0x33320d2: 'with no colon the dex name has length 0 and its pointer is never read',
    0x33321b0: 'with no colon the dex name has length 0 and its pointer is never read',
    0x333223e: 'the byte at the stop is a colon, so the cmove at 0x3332244 always replaces this value',
    0x3332110: HINT, 0x3332115: HINT, 0x33320cc: HINT, 0x33320b5: HINT, 0x33320a1: HINT,
    0x273b53c: 'the pointer of an empty list is never read: no row is written and the free needs a non-zero capacity',
    0x273ba44: 'at +0x56 the top bytes of the list length replace the top bytes of the node pointer at +0x5e; both are zero on any 48-bit address and list of under 2^48 rows',
    0x273b7c8: 'the compare guards the grow call, which never runs; with a pointer in place of the capacity word it still never matches',
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


def constant_sites(fn, listing, img):
    """Bytes of each .rodata constant a subject reads: the top byte of the f64 mantissa side."""
    out = []
    for ins in listing:
        for o in ins.ops:
            if o[0] == 'm' and o[1] is None and o[2] is None and img.in_rodata(o[4], 8) and ins.op in ('ucomisd', 'mulsd', 'movsd'):
                out.append(dict(kind='constant', fn=fn, va=ins.va, op=show(ins), patch={o[4] + 6: img.read(o[4] + 6, 1)[0] ^ 0x10}))
    return out


def table_sites():
    return [dict(kind='constant', fn=SETTER, va=COOLDOWNS + k * 8, op='wait table', patch={COOLDOWNS + k * 8 + 6: b}) for k, b in ((0, 0x4e ^ 0x10), (1, 0x43 ^ 0x10))]


def all_sites(listing, img):
    sites = []
    for fn in SUBJECTS:
        rows = listing[fn]
        sites += conditional_sites(fn, rows) + field_sites(fn, rows) + imm_sites(fn, rows) + constant_sites(fn, rows, img)
    sites += table_sites()
    g = gaps()
    return [x for x in sites if not any(a <= x['va'] < b for a, b, _ in g)]


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
    data, code, slots, got, callees, sites, vecs = args
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
        rows.append(dict(s_, killed=try_kill((mimg, mcode, slots, got, callees), picked)))
        if PROGRESS and not rows[-1]['killed']:
            print('survivor', hex(fn), hex(s_['va']), s_['kind'], s_['op'], flush=True)
    return rows


WORKERS = 3
PROGRESS = False


def survey(data, code, slots, got, callees, listing, vecs, img):
    sites = all_sites(listing, img)
    picked = [v for v in vecs if v['copy'] == SETTER]
    parts = [sites[i::WORKERS] for i in range(WORKERS)]
    jobs = [(data, code, slots, got, callees, p, picked) for p in parts]
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
        return None
    text = arm + 18 + struct.unpack('<i', b[14:18])[0]
    return img.read(text, struct.unpack('<I', b[19:23])[0]).decode('ascii')


def status_format(img, tag):
    """A format arm takes `lea rdx,[rip+pieces]` near its head; returns the VA of the pieces."""
    arm = status_arm(img, tag)
    b = img.read(arm, 90)
    i = b.find(b'\x48\x8d\x15')
    return arm + i + 7 + struct.unpack('<i', b[i + 3:i + 7])[0]


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
    return hashlib.sha256(repr(sorted((k, repr(x)) for k, x in v.items())).encode()).hexdigest()[:16]


def text_hits(img, needle):
    addr_, off, size, _ = img.sec['.rodata']
    blob, out = img.data, []
    i = blob.find(needle, off, off + size)
    while i != -1:
        out.append(addr_ + i - off)
        i = blob.find(needle, i + 1, off + size)
    return out


def copies_compare(listing):
    """Copies, compared by decoded instruction with code addresses taken out; the list of the rows that differ."""
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
    a = shape(listing[SETTER], SETTER)
    out = {}
    for c in (SETTER_B, SETTER_C):
        b = shape(listing[c], c)
        if len(a) != len(b):
            raise EvidenceError('copy length')
        out[hex(c)] = [dict(offset=hex(x[0]), a=show(listing[SETTER][k]), b=show(listing[c][k])) for k, (x, y) in enumerate(zip(a, b)) if x != y]
    return out


REFERENCE_ROWS = (
    ('absent', 'asset/pdi.rs PdiAction', 'no growth mode action, no setter', '0x273b4b0 + 2 copies take a BTreeMap of names to booleans and hold 2 passes: test every key, then write'),
    ('differs', 'perp_meta.rs GrowthMode', 'serde names normal, allowHip3, frozen', 'serializer 0x37585e0 prints enabled, disabled, blocked for bytes 0, 1, any other'),
    ('differs', 'perp_meta.rs last_growth_mode_change_time', 'Option of u64', 'asset row +0x1c holds 3 dwords of a chrono time; a zero first dword is None (0x273b723), the other two are then ignored'),
    ('differs', 'asset/pdi.rs growth_mode_allowed', 'a bool on the asset, false blocks a fee scale above 1', 'the same byte +0x29 holds the mode; values 0, 1 pass and 2 or above gives tag 0xe7 Growth mode blocked by validators'),
    ('same', 'asset/pdi.rs PdiStatus', 'FeeScaleGrowthModeBlocked = 230', 'tag 0xe6, used here in the other direction: mode true is refused while the dex scale is above 1'),
    ('same', 'asset/pdi.rs find_by_dex_name_or_first_mut', 'empty name takes a row with no name', '0x3332270 takes row 0 for an empty name with no status test; 0x273b78b then skips the scale test for a status 3 row'),
    ('same', 'fees/compute.rs line 195', 'multiply by 0.1 when the asset byte at +0x29 is clear', 'sete at 0x3713228 picks table row 1 = 0.1 for byte 0, row 0 = 1.0 otherwise; read here only as a pin, 0x37130b0 is not evaluated by this tool'),
    ('unverified', 'perp_meta.rs GrowthMode::Frozen', 'byte 2 is frozen', 'no writer of byte 2 was found; text 0xe7 names validators, so a vote path is a guess'),
)


def generate(data, out_dir, with_survey=True):
    global SEEN
    img, code, fdes, slots, got, listing, callees = build(data)
    ctx = (img, code, slots, got, callees)
    vecs = all_vectors()
    seen = SEEN = set()
    try:
        for v in vecs:
            try:
                msg = check(ctx, v)
            except (Unmodelled, EvidenceError, KeyError) as exc:
                msg = f'fault {type(exc).__name__} {exc} at {getattr(exc, "va", 0)}'
            if msg:
                raise EvidenceError(f"mismatch in {v['group']}: {msg}: {repr({k: x for k, x in v.items() if k != 'rows'})[:400]} rule {rule(v)}")
    finally:
        SEEN = None
    missing, padding = [], 0
    g = gaps()
    for fn in listing:
        if fn in (TIME_ADD, TIME_SIGNED, DATE_DAYS):
            continue
        for ins in listing[fn]:
            if ins.va in seen:
                continue
            if ins.op in ('nop', 'int3'):
                padding += 1
            elif not any(a <= ins.va < b for a, b, _ in g):
                missing.append(hex(ins.va))
    if missing:
        raise EvidenceError(f'unlisted unexecuted instructions {len(missing)}: {missing}')
    rows = survey(data, code, slots, got, callees, listing, vecs, img) if with_survey else []
    survivors = {r['va'] for r in rows if not r['killed']}
    if survivors - set(EQUIVALENT) or (rows and set(EQUIVALENT) - survivors):
        raise EvidenceError(f'survivors {sorted(hex(s_) for s_ in survivors ^ set(EQUIVALENT))} of {len(rows)}')
    return facts_and_files(data, out_dir, img, fdes, listing, vecs, rows, seen, padding, slots)


def pinned(img):
    """Constants the model hard-codes, re-read from .rodata; any change stops the tool."""
    got_ = dict(scale_free=img.f64(SCALE_FREE), wait_other=img.f64(COOLDOWNS), wait_mode_3=img.f64(COOLDOWNS + 8), text_days=img.f64(ARG_30), factor_other=img.f64(FACTOR_TABLE), factor_byte_0=img.f64(FACTOR_TABLE + 8))
    want = dict(scale_free=1.0, wait_other=60.0, wait_mode_3=2592000.0, text_days=30.0, factor_other=1.0, factor_byte_0=0.1)
    if got_ != want:
        raise EvidenceError(f'constants {got_}')
    for slot, value in ((SLOT_SPLIT, SPLIT), (SLOT_FIND, FIND), (SLOT_ASSET_ID, ASSET_ID), (SLOT_TIME, TIME_ADD), (0x576e8a8, TIME_SIGNED), (0x576e8b0, DATE_DAYS), (SLOT_FORMAT, FORMAT),
                        (SLOT_SHOW, FLOAT_SHOW), (SLOT_FREE, FREE), (SLOT_ADD, PANIC_ADD), (SLOT_MUL, PANIC_MUL), (SLOT_EXPECT, PANIC_EXPECT)):
        if img.relative(slot) != value:
            raise EvidenceError(f'slot {slot:#x}')
    return got_


# (site, length) of the three texts in serializer 0x37585e0: lea at the site, then the length from `mov edx, imm` on the way out
SERIALIZER = 0x37585e0
SERIALIZER_TEXTS = (('byte 0', 0x598224, 7), ('byte 1', 0x20b0d0, 8), ('other byte', 0x5982ec, 7))


def serializer_facts(img):
    out = []
    for label, va, size in SERIALIZER_TEXTS:
        out.append(dict(byte=label, va=hex(va), text=img.read(va, size).decode('ascii')))
    if [x['text'] for x in out] != ['enabled', 'disabled', 'blocked']:
        raise EvidenceError(f'serializer texts {out}')
    head = img.read(SERIALIZER, 16).hex()
    return dict(entry=hex(SERIALIZER), head=head, texts=out)


def facts_and_files(data, out_dir, img, fdes, listing, vecs, rows, seen, padding, slots):
    constants = pinned(img)
    starts = sorted(f['start'] for f in eh_frame_records(data)[1])
    out_path = Path(out_dir)
    out_path.mkdir(parents=True, exist_ok=True)
    groups, outcomes = {}, {}
    with open(out_path / 'vectors.tsv', 'w', newline='\n') as f:
        f.write('copy\tgroup\tstate\toutcome\n')
        for v in vecs:
            groups[v['group']] = groups.get(v['group'], 0) + 1
            name = outcome_name(v)
            outcomes[name] = outcomes.get(name, 0) + 1
            f.write(f"{v['copy']:#x}\t{v['group']}\t{digest_of(v)}\t{name}\n")
    with open(out_path / 'mutations.tsv', 'w', newline='\n') as f:
        f.write('kind\tfunction\tva\tinstruction\tresult\tvector\treason\n')
        for r in rows:
            k = r['killed']
            f.write(f"{r['kind']}\t{r['fn']:#x}\t{r['va']:#x}\t{r['op']}\t{'killed' if k else 'equivalent'}\t{k[0] if k else ''}\t{k[1] if k else EQUIVALENT[r['va']]}\n")
    with open(out_path / 'instructions.tsv', 'w', newline='\n') as f:
        f.write('function\tva\tsize\tbytes\tdecoded\texecuted\n')
        for fn in (SETTER, SETTER_B, SETTER_C, SPLIT, FIND, ASSET_ID):
            for i in listing[fn]:
                f.write(f'{fn:#x}\t{i.va:#x}\t{i.size}\t{i.raw.hex()}\t{show(i)}\t{int(i.va in seen)}\n')
    with open(out_path / 'reference-diff.tsv', 'w', newline='\n') as f:
        f.write('verdict\treference\treference_says\tbytes_say\n')
        for row_ in REFERENCE_ROWS:
            f.write('\t'.join(row_) + '\n')
    per = {hex(fn): dict(instructions=len(listing[fn]), executed=sum(i.va in seen for i in listing[fn]), fde=hex(fdes.range_of(fn)['fde']), end=hex(FDE_END[fn])) for fn in (SETTER, SETTER_B, SETTER_C, SPLIT, FIND, ASSET_ID)}
    status = {hex(t): dict(arm=hex(status_arm(img, t)), text=status_text(img, t)) for t in (BAD_BYTE, BLOCKED, UNKNOWN_DEX, TOO_LONG)}
    pieces = format_pieces(img, PIECES)
    if img.read(READER_TEST, len(READER_BYTES)) != READER_BYTES:
        raise EvidenceError('reader bytes')
    evidence = dict(
        binary=BINARY, sha256=SHA256, functions=per, constants=constants, copies=copies_compare(listing),
        callers={hex(fn): direct_sites(img, fn, starts) for fn in COPIES}, slots_holding={hex(fn): slots_holding(img, fn) for fn in COPIES},
        reader=dict(load=hex(READER_SITE), load_bytes=img.read(READER_SITE, 6).hex(), test=hex(READER_TEST), test_bytes=READER_BYTES.hex(), factor_table=hex(FACTOR_TABLE)),
        serializer=serializer_facts(img), status=status, status_formats={hex(t): dict(arm=hex(status_arm(img, t)), pieces=hex(status_format(img, t)), parts=format_pieces(img, status_format(img, t))) for t in (ASSET_LOST, UNKNOWN_ASSET, TOO_SOON)}, format_pieces=hex(PIECES), format_parts=pieces,
        locations=dict(asset=location(img, LOC_ASSET), time=location(img, LOC_TIME), bounds=location(img, LOC_BOUNDS), scan=location(img, LOC_ADD)),
        field_names={w: [hex(a) for a in text_hits(img, w.encode())] for w in ('growthMode', 'lastGrowthModeChangeTime', 'setGrowthModes')},
        vectors=len(vecs), mismatches=0, groups=groups, outcomes=outcomes, padding_not_executed=padding,
        unexecuted=[dict(start=hex(a), end=hex(b), why=w) for a, b, w in gaps()], not_mutated=[hex(x) for x in NOT_MUTATED],
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
