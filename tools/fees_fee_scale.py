#!/usr/bin/env python3
"""fees: node #94 deployer fee scale setter, from bytes alone.

Static, no execution of the node.  The setter 0x3718e30, its time add 0x1459ca0 with the two real chrono helpers, the
dex lookup 0x3332380 and the action arm in the 3 copies of the perp deploy function are decoded from ELF bytes by the
table decoder below, which must land exactly on each FDE end, and interpreted in Python on every vector.  The text
parser, the format call and the free call are stubs that check their arguments.  Each outcome is compared with a
separate closed-form model, then every conditional, field offset, immediate and read constant of those bodies except
the chrono helpers is mutated to test the vectors.

    python3 tools/fees_fee_scale.py --out <dir>

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


class Stop(Exception):
    """A run of an action arm reached the end of the arm."""


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


SETTER = 0x3718e30
TIME_ADD = 0x1459ca0
LOOKUP = 0x3332380
TIME_SIGNED = 0x15206e0
DATE_DAYS = 0x151f870
DROP = 0x3379490
PARSER = 0x374fe60
FORMAT = 0x1344760
FLOAT_SHOW = 0x1571d50
FREE = 0x54c8cb0
PANIC_ADD = 0x157b480
PANIC_MUL = 0x157b4a0
PANIC_EXPECT = 0x157a9b0
PANIC_UNWRAP_SLOT = 0x576e048
SLOT_SETTER = 0x5774bd0
SLOT_LOOKUP = 0x5773eb8
SLOT_PARSER = 0x5773328
GOT_BCMP = 0x576e378
LOC_ASSET = 0x56f1f18
LOC_TIME = 0x566af18
TEXT_TIME = (0x21a01f, 0x26)
PIECES = 0x1ead97
ARG_30 = 0x20a1a0
SCALE_MAX = 0x20aab8
SCALE_FREE = 0x20a730
COOLDOWNS = 0x208d90
NS_FACTOR = 0x20a220
NEG_LIMIT = 0x20acb8
POS_LIMIT = 0x20a7f0
TOP_BELOW = 0x20a2c8
STATUS_TABLE = 0x59a8d0
OK = 0x186
TOO_LONG = 0x143
UNKNOWN_DEX = 0x141
BAD_SCALE = 0xe5
GONE = 0xe3
TOO_SOON = 0xe0
BLOCKED = 0xe6
PARSE_ERR = 0xab
OUTER_OK = 0xd
OUTER_ERR = 0xe
LIMIT_TEXT = 100
WHOLE = (SETTER, TIME_ADD, LOOKUP, TIME_SIGNED, DATE_DAYS)
# entry of the arm in each of the 3 action functions and the frame words that differ between them
ARMS = {
    0x273f6ee: dict(fn=0x273e080, buf=0xc0, text=0x50, now=0x380, out=8, ex=0x10, mode=0x8f2, registry=0x5b8),
    0x4d51822: dict(fn=0x4d50130, buf=0xd0, text=0x60, now=0x390, out=0x20, ex=8, mode=0x8f2, registry=0x5b8),
    0x4d57242: dict(fn=0x4d55b50, buf=0xd0, text=0x60, now=0x390, out=0x20, ex=8, mode=0x1372, registry=0x1038),
}
ROW = 0x2f0
ASSET = 0x30
META = 0x80
STACK_TOP = 0x7008
FRAME = 0x1000
OUT_SIZE = 0x80
FILL_TEXT = fill_bytes(0x60, 0x77)
SEEN = None
GOLD = {}


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


def date(y, m, d):
    return pack_day(days_from_civil(y, m, d))


def unpack_day(p):
    return days_from_civil(signed(p, 32) >> 13, 1, 1) + (p >> 4 & 0x1ff) - 1


MIN_DAY = days_from_civil(-262143, 1, 1)
MAX_DAY = days_from_civil(262142, 12, 31)


def stamp(y, mo, d, secs=0, frac=0):
    return (date(y, mo, d), secs, frac)


def nanos_of(seconds):
    x = seconds * 1e9
    if math.isnan(x) or math.isinf(x):
        return 0
    x = max(min(x, 2.0 ** 63), -2.0 ** 63)
    return (1 << 63) - 1 if x == 2.0 ** 63 else int(x)


def time_add(t, seconds):
    """Rule of 0x1459ca0: seconds x 1e9, truncated and saturated; a date past the range panics."""
    total = unpack_day(t[0]) * 86400 * 10 ** 9 + t[1] * 10 ** 9 + t[2] + nanos_of(seconds)
    secs, frac = divmod(total, 10 ** 9)
    day, secs = divmod(secs, 86400)
    if not MIN_DAY <= day <= MAX_DAY:
        return None
    return (pack_day(day), secs, frac)


def time_key(t):
    return (signed(t[0], 32), t[1], t[2])


def bits(x):
    return struct.unpack('<Q', struct.pack('<d', x))[0]


def setter_rule(v):
    """Returns dict(status, write, panic); `scale` and rows come straight from the vector."""
    scale = v['scale']
    if scale < 0 or scale > 3:
        return dict(status=BAD_SCALE, write=False)
    if v['status'] == 3:
        return dict(status=GONE, write=False)
    after = time_add(v['last'], 2592000.0 if v['mode'] == 3 else 60.0)
    if after is None:
        return dict(status=None, panic='time', write=False)
    if time_key(after) > time_key(v['now']):
        return dict(status=TOO_SOON, write=False)
    if scale > 1:
        base = v['index'] * 10000
        n = len(v['flags'])
        if base > U64:
            if n:
                return dict(status=None, panic='mul', write=False)
        else:
            for i in range(n):
                if base + i > U64:
                    return dict(status=None, panic='add', write=False)
                if not v['flags'][i]:
                    return dict(status=BLOCKED, write=False)
    if math.isnan(v['old']) or math.isnan(scale) or v['old'] != scale:
        return dict(status=OK, write=True)
    return dict(status=OK, write=False)


def lookup_rule(rows, name):
    """Index of the row found, 'none' or 'panic'."""
    if not name:
        return 0 if rows else 'panic'
    for i, r in enumerate(rows):
        if r['status'] != 3 and r['name'] == name:
            return i
    return 'none'


def arm_rule(v):
    name_free, text_free = ['name'] if v['name_cap'] else [], ['text'] if v['text_cap'] else []
    if len(v['text']) > LIMIT_TEXT:
        return dict(stage='text', status=TOO_LONG, frees=text_free + name_free)
    if v['parsed'] is None:
        return dict(stage='parse', status=PARSE_ERR, frees=text_free + name_free)
    if len(v['name']) > LIMIT_TEXT:
        return dict(stage='name', status=TOO_LONG, frees=name_free + text_free)
    hit = lookup_rule(v['rows'], v['name'])
    if hit == 'none':
        return dict(stage='lookup', status=UNKNOWN_DEX, frees=name_free + text_free)
    if hit == 'panic':
        return dict(stage='panic', panic='unwrap', status=None, frees=[])
    r = v['rows'][hit]
    one = dict(scale=v['parsed'], status=r['status'], mode=v['mode'], last=r['last'], now=v['now'], index=r['index'], flags=r['flags'], old=r['old'])
    out = setter_rule(one)
    return dict(out, stage='setter', hit=hit, frees=name_free + text_free)


def row(name=b'alpha', status=1, index=1, flags=(1,), old=1.0, last=None):
    return dict(name=name, status=status, index=index, flags=tuple(flags), old=old, last=last or stamp(2025, 1, 1))


NOW = stamp(2026, 6, 1, 3600, 5)


# ---- machine set-up


STACK_FILL = fill_bytes(0x8000, 0x35)


def time_bytes(t):
    return struct.pack('<III', *t)


def write_rows(m, rows):
    n = max(len(rows), 1)
    tab = filled(m, n * ROW, 0x31)
    metas = []
    assets = []
    for i, r in enumerate(rows):
        off = i * ROW
        name = m.arena(max(len(r['name']), 1))
        name.mem[:len(r['name'])] = r['name']
        name.valid[:len(r['name'])] = b'\1' * len(r['name'])
        meta = filled(m, META, 0x43 + i)
        word(meta, 8, 8, name.base)
        word(meta, 0x10, 8, len(r['name']))
        meta.mem[0x60:0x68] = struct.pack('<Q', r['old_bits']) if 'old_bits' in r else struct.pack('<d', r['old'])
        meta.mem[0x68:0x74] = time_bytes(r['last'])
        rows_a = filled(m, max(len(r['flags']), 1) * ASSET, 0x55 + i)
        for k, f in enumerate(r['flags']):
            rows_a.mem[k * ASSET + 0x29] = f
        word(tab, off + 8, 8, rows_a.base)
        word(tab, off + 0x10, 8, len(r['flags']))
        word(tab, off + 0x30, 8, r['index'])
        word(tab, off + 0x208, 8, meta.base)
        tab.mem[off + 0x230] = r['status']
        metas.append(meta)
        assets.append(rows_a)
    return tab, metas, assets


def machine(ctx):
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
    m.top = stack.base + STACK_TOP
    m.freed = []
    m.calls = []
    m.parts = {}
    m.text_out = None

    def panic_add():
        if m.regs[R['rdi']] != LOC_ASSET:
            raise Unmodelled('add location')
        raise Panicked('add')

    def panic_mul():
        if m.regs[R['rdi']] != LOC_ASSET:
            raise Unmodelled('mul location')
        raise Panicked('mul')

    def panic_expect():
        r = m.regs
        if (r[R['rdi']], r[R['rsi']], r[R['rdx']]) != (TEXT_TIME[0], TEXT_TIME[1], LOC_TIME):
            raise Unmodelled('expect arguments')
        raise Panicked('time')

    def panic_unwrap():
        if m.regs[R['rsi']] != 0x2b or m.load(m.regs[R['rdx']], 2) != UNKNOWN_DEX:
            raise Unmodelled('unwrap arguments')
        raise Panicked('unwrap')

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

    def free():
        r = m.regs
        name_ = {m.parts.get('name_at'): 'name', m.parts.get('text_at'): 'text'}.get(r[R['rdi']], hex(r[R['rdi']]))
        want = m.parts.get(name_ + '_cap')
        if r[R['rdx']] != 0 or r[R['rsi']] != want:
            raise Unmodelled('free arguments')
        m.freed.append(name_)
        m.clobber()

    m.stubs.update({slots[0x576e118]: panic_add, slots[0x576e1b0]: panic_mul, slots[0x576e468]: panic_expect, slots[PANIC_UNWRAP_SLOT]: panic_unwrap,
                    slots[0x576e040]: show, slots[GOT_BCMP]: bcmp, DROP: drop, slots[0x576e010]: free})
    return m


def enter(m, fn, *args, scale=None):
    m.regs[R['rsp']] = m.top
    m.store(m.top, 8, 0xfeedface)
    for name_, val in zip(('rdi', 'rsi', 'rdx', 'rcx', 'r8', 'r9'), args):
        m.regs[R[name_]] = val
    if scale is not None:
        m.xmm[0][0] = scale
    for name_ in ('rbx', 'rbp', 'r12', 'r13', 'r14', 'r15'):
        m.regs[R[name_]] = 0xc0de0000 + R[name_]
    m.run(fn)
    if m.regs[R['rsp']] != m.top + 8:
        raise Unmodelled('stack not balanced')
    for name_ in ('rbx', 'rbp', 'r12', 'r13', 'r14', 'r15'):
        if m.regs[R[name_]] != 0xc0de0000 + R[name_]:
            raise Unmodelled(f'{name_} not restored')


def panic_of(fn):
    try:
        return fn()
    except Panicked as exc:
        return exc


def setter_out_ok(m, out, w):
    status = read(out, 0, 2)
    if status != w['status']:
        return f'status {status:#x} not {w["status"]:#x}'
    if status == BAD_SCALE and read(out, 8) != bits(3.0):
        return 'limit payload'
    if status == TOO_SOON:
        if bytes(out[2:8]) != struct.pack('<Q', ARG_30)[:6]:
            return 'bytes before the text'
        if (read(out, 8), read(out, 0x10), read(out, 0x18)) != (0x111, 0x222, 0x333):
            return 'text words'
        if m.calls.count('format') != 1:
            return 'format count'
    elif 'format' in m.calls:
        return 'format call'
    return None


def state_ok(meta, rows_tab, assets, before, w, v):
    want = bytearray(before[0])
    if w.get('write'):
        want[0x60:0x68] = struct.pack('<Q', v['scale_bits'])
        want[0x68:0x74] = time_bytes(v['now'])
    if bytes(meta.mem) != bytes(want):
        return 'meta bytes'
    if bytes(rows_tab.mem) != before[1] or [bytes(a.mem) for a in assets] != before[2]:
        return 'row bytes'
    return None


def check_setter(ctx, v):
    m = machine(ctx)
    r = dict(name=b'x', status=v['status'], index=v['index'], flags=v['flags'], old=v['old'], last=v['last'])
    if 'old_bits' in v:
        r['old_bits'] = v['old_bits']
    tab, metas, assets = write_rows(m, [r])
    now = m.arena(12)
    now.mem[:12] = time_bytes(v['now'])
    now.valid[:12] = b'\1' * 12
    out = m.arena(OUT_SIZE, strict=False)
    out.mem[:] = fill_bytes(OUT_SIZE, 0x63)
    w = setter_rule(v)
    before = (bytes(metas[0].mem), bytes(tab.mem), [bytes(a.mem) for a in assets])
    got_ = panic_of(lambda: enter(m, SETTER, out.base, tab.base, v['mode'] | 0x7700, now.base, scale=v['scale_bits']))
    if isinstance(got_, Panicked):
        if w.get('panic') != str(got_):
            return f'panic {got_} not {w.get("panic")}'
    elif w.get('panic'):
        return f'no panic, wanted {w["panic"]}'
    else:
        if m.regs[0] != out.base:
            return 'result pointer'
        msg = setter_out_ok(m, out.mem, w)
        if msg:
            return msg
        size = dict([(BAD_SCALE, 0x10), (TOO_SOON, 0x20)]).get(w['status'], 2)
        if bytes(out.mem[size:]) != fill_bytes(OUT_SIZE, 0x63)[size:]:
            return 'bytes past the result'
    msg = state_ok(metas[0], tab, assets, before, w, v)
    if msg:
        return msg
    gold = GOLD.get(id(v))
    if gold is not None and bytes(out.mem) != gold:
        return 'bytes differ from the unmodified run'
    v['_out'] = bytes(out.mem)
    return None


def check_time(ctx, v):
    m = machine(ctx)
    t = m.arena(12)
    t.mem[:12] = time_bytes(v['start'])
    t.valid[:12] = b'\1' * 12
    out = m.arena(0x20, strict=False)
    out.mem[:] = fill_bytes(0x20, 0x63)
    want = time_add(v['start'], struct.unpack('<d', struct.pack('<Q', v['secs_bits']))[0])
    got_ = panic_of(lambda: enter(m, TIME_ADD, out.base, t.base, scale=v['secs_bits']))
    if isinstance(got_, Panicked):
        if want is not None or str(got_) != 'time':
            return f'panic {got_}'
        return None
    if want is None:
        return 'no panic'
    if m.regs[0] != out.base:
        return 'result pointer'
    if bytes(out.mem[:12]) != time_bytes(want):
        return 'time bytes'
    if bytes(out.mem[12:]) != fill_bytes(0x20, 0x63)[12:]:
        return 'bytes past the result'
    return None


def check_lookup(ctx, v):
    m = machine(ctx)
    tab, _, _ = write_rows(m, v['rows'])
    reg = filled(m, 0x20, 0x29)
    word(reg, 8, 8, tab.base)
    word(reg, 0x10, 8, len(v['rows']))
    name = m.arena(max(len(v['name']), 1))
    name.mem[:len(v['name'])] = v['name']
    name.valid[:len(v['name'])] = b'\1' * len(v['name'])
    out = m.arena(0x20, strict=False)
    out.mem[:] = fill_bytes(0x20, 0x63)
    want = lookup_rule(v['rows'], v['name'])
    got_ = panic_of(lambda: enter(m, LOOKUP, out.base, reg.base, name.base, len(v['name'])))
    if isinstance(got_, Panicked):
        return None if want == 'panic' and str(got_) == 'unwrap' else f'panic {got_}'
    if want == 'panic':
        return 'no panic'
    if m.regs[0] != out.base:
        return 'result pointer'
    if want == 'none':
        return None if read(out.mem, 0, 2) == UNKNOWN_DEX and bytes(out.mem[2:]) == fill_bytes(0x20, 0x63)[2:] else 'none result'
    if read(out.mem, 0, 2) != OK or read(out.mem, 8) != tab.base + want * ROW:
        return 'row pointer'
    if bytes(out.mem[2:8]) != fill_bytes(0x20, 0x63)[2:8] or bytes(out.mem[0x10:]) != fill_bytes(0x20, 0x63)[0x10:]:
        return 'bytes past the result'
    if m.calls != (['drop'] if not v['name'] and v['rows'] else []):
        return 'drop count'
    return None


def check_arm(ctx, v):
    m = machine(ctx)
    s = ARMS[v['arm']]
    w = arm_rule(v)
    tab, metas, assets = write_rows(m, v['rows'])
    ex = filled(m, 0x1400, 0x41)
    word(ex, 0x60, 8, read(time_bytes(v['now']), 0))
    word(ex, 0x68, 4, v['now'][2])
    ex.mem[s['mode']] = v['mode']
    word(ex, s['registry'] + 8, 8, tab.base)
    word(ex, s['registry'] + 0x10, 8, len(v['rows']))
    action = filled(m, 0x38, 0x5b)
    name, text = v['name'], v['text']
    name_a, text_a = filled(m, max(len(name), 1), 0x13), filled(m, max(len(text), 1), 0x17)
    name_a.mem[:len(name)] = name
    text_a.mem[:len(text)] = text
    word(action, 8, 8, v['name_cap'])
    word(action, 0x10, 8, name_a.base)
    word(action, 0x18, 8, len(name))
    word(action, 0x20, 8, v['text_cap'])
    word(action, 0x28, 8, text_a.base)
    word(action, 0x30, 8, len(text))
    m.parts.update(name_at=name_a.base, text_at=text_a.base, name_cap=v['name_cap'], text_cap=v['text_cap'])
    out = m.arena(OUT_SIZE + 0x10, strict=False)
    out.mem[:] = fill_bytes(OUT_SIZE + 0x10, 0x63)
    frame = m.stack.base + FRAME
    m.store(frame + s['out'], 8, out.base)
    m.store(frame + s['ex'], 8, ex.base)
    m.regs[R['rsp']] = frame
    m.regs[R['rbp']] = action.base
    for name_ in ('rbx', 'r12', 'r13', 'r14', 'r15'):
        m.regs[R[name_]] = 0xc0de0000 + R[name_]
    m.buffer = None

    def parser():
        r = m.regs
        if r[R['rsi']] != frame + s['text'] or r[R['rdi']] != frame + s['buf']:
            raise Unmodelled('parser arguments')
        if (m.load(frame + s['text'], 8), m.load(frame + s['text'] + 8, 8), m.load(frame + s['text'] + 16, 8)) != (v['text_cap'], text_a.base, len(text)):
            raise Unmodelled('parser string')
        at = r[R['rdi']]
        if v['parsed'] is None:
            for k in range(0x60):
                m.store(at + k, 1, FILL_TEXT[k])
            m.store(at, 2, PARSE_ERR)
            m.buffer = bytes(m.stack.mem[at - m.stack.base:at - m.stack.base + 0x60])
        else:
            m.store(at, 2, OK)
            m.store(at + 8, 8, v['parsed_bits'])
        m.calls.append('parse')
        m.clobber()

    m.stubs[ctx[2][SLOT_PARSER]] = parser
    for va in STOPS[v['arm']]:
        m.hooks[va] = stopper
    before = (bytes(tab.mem), [bytes(a.mem) for a in assets], [bytes(x.mem) for x in metas], bytes(ex.mem), bytes(action.mem))
    for va in AFTER_SETTER[v['arm']]:
        m.hooks[va] = lambda: capture(m, frame + s['buf'])
    got_ = panic_of(lambda: run_arm(m, v['arm']))
    if isinstance(got_, Panicked):
        return None if w.get('panic') == str(got_) else f'panic {got_}'
    if w.get('panic'):
        return f'no panic, wanted {w["panic"]}'
    if m.freed != w['frees']:
        return f'freed {m.freed}'
    outer = out.mem[0]
    if w['status'] == OK:
        if outer != OUTER_OK:
            return 'outer tag'
        if bytes(out.mem[1:]) != fill_bytes(OUT_SIZE + 0x10, 0x63)[1:]:
            return 'bytes after the outer tag'
    else:
        if outer != OUTER_ERR:
            return 'outer tag'
        if read(out.mem, 8, 2) != w['status']:
            return f'status {read(out.mem, 8, 2):#x} not {w["status"]:#x}'
        if w['stage'] in ('text', 'name'):
            size = 0x18 if w['stage'] == 'text' else 0x28
            if w['stage'] == 'text' and read(out.mem, 0x10) != frame + s['text']:
                return 'pointer word'
            if w['stage'] == 'name' and read(out.mem, 0x20) != len(name):
                return 'length word'
            skip = (0x10, 0x18) if w['stage'] == 'text' else (0x20, 0x28)
            fresh = fill_bytes(OUT_SIZE + 0x10, 0x63)
            if bytes(out.mem[10:skip[0]]) != fresh[10:skip[0]] or bytes(out.mem[skip[1]:]) != fresh[skip[1]:]:
                return 'bytes around the payload'
        else:
            if bytes(out.mem[8:0x68]) != m.buffer:
                return 'forwarded bytes'
    if bytes(ex.mem) != before[3] or bytes(action.mem) != before[4] or bytes(tab.mem) != before[0] or [bytes(a.mem) for a in assets] != before[1]:
        return 'state written'
    for i, x in enumerate(metas):
        want = bytearray(before[2][i])
        if w.get('hit') == i and w.get('write'):
            want[0x60:0x68] = struct.pack('<Q', v['parsed_bits'])
            want[0x68:0x74] = time_bytes(v['now'])
        if bytes(x.mem) != bytes(want):
            return 'meta bytes'
    gold = GOLD.get(id(v))
    if gold is not None and bytes(out.mem) != gold:
        return 'bytes differ from the unmodified run'
    v['_out'] = bytes(out.mem)
    return None


def stopper():
    raise Stop()


def capture(m, at):
    o = at - m.stack.base
    m.buffer = bytes(m.stack.mem[o:o + 0x60])


def run_arm(m, entry):
    try:
        m.run(entry)
    except Stop:
        return
    raise Unmodelled('arm returned')


def check(ctx, v):
    return {'setter': check_setter, 'time': check_time, 'lookup': check_lookup, 'arm': check_arm}[v['kind']](ctx, v)


# ---- vectors


def setter_vec(group, scale, **kw):
    v = dict(kind='setter', group=group, scale=scale, scale_bits=bits(scale), status=1, mode=0, last=stamp(2025, 1, 1), now=NOW, index=1, flags=(1,), old=0.5)
    v.update(kw)
    return v


NAN = float('nan')
INF = float('inf')
ABOVE_3 = math.nextafter(3.0, 4.0)
ABOVE_1 = math.nextafter(1.0, 2.0)
BELOW_0 = -5e-324
GRID = (0.0, -0.0, 5e-324, 0.1, 0.5, 1.0, ABOVE_1, 1.5, 2.0, math.nextafter(3.0, 0.0), 3.0)


def range_vectors():
    out = []
    for scale in GRID + (ABOVE_3, 3.5, 1e300, INF, BELOW_0, -1.0, -3.0, -INF, NAN):
        for mode in (0, 1, 2, 3, 4, 255):
            for status in (0, 1, 2, 3, 4):
                for old in (0.5, scale):
                    out.append(setter_vec('range', scale, mode=mode, status=status, old=old))
    return out


def cooldown_vectors():
    out = []
    for mode, gap in ((0, 60), (1, 60), (2, 60), (3, 2592000), (4, 60), (255, 60)):
        for last in (stamp(2025, 1, 1, 0, 0), stamp(2024, 2, 29, 86399, 999999999), stamp(1969, 12, 31, 43200, 7), stamp(-1, 12, 31, 86399, 0), stamp(-400, 3, 1, 1, 1), stamp(1, 1, 1)):
            pure = time_add(last, float(gap))
            for now in (pure, (pure[0], pure[1], pure[2] + 1), (pure[0], pure[1] + 1, pure[2]), time_add(pure, 86400.0)):
                out.append(setter_vec('cooldown', 0.5, mode=mode, last=last, now=now))
            for delta in (-1e-9, -1.0, -86400.0, -86399.0):
                earlier = time_add(pure, delta)
                out.append(setter_vec('cooldown', 0.5, mode=mode, last=last, now=earlier))
                out.append(setter_vec('cooldown', 0.5, mode=mode, last=last, now=earlier, old=0.5))
            if pure[2]:
                out.append(setter_vec('cooldown', 0.5, mode=mode, last=last, now=(pure[0], pure[1], pure[2] - 1)))
                out.append(setter_vec('cooldown', 0.5, mode=mode, last=last, now=(pure[0], pure[1] + 1, pure[2] - 1)))
            if pure[1]:
                out.append(setter_vec('cooldown', 0.5, mode=mode, last=last, now=(pure[0], pure[1] - 1, pure[2] + 1)))
            out.append(setter_vec('cooldown', 0.5, mode=mode, last=last, now=(pure[0], pure[1] + 1, 0)))
            day = pack_day(unpack_day(pure[0]) + 1)
            out.append(setter_vec('cooldown', 0.5, mode=mode, last=last, now=(day, 0, 0)))
            day = pack_day(unpack_day(pure[0]) - 1)
            out.append(setter_vec('cooldown', 0.5, mode=mode, last=last, now=(day, 86399, 999999999)))
    last = stamp(262142, 12, 31, 86399)
    for mode in (0, 3):
        out.append(setter_vec('cooldown', 0.5, mode=mode, last=last, now=last))
        out.append(setter_vec('cooldown', 5.0, mode=mode, last=last, now=last))
        out.append(setter_vec('cooldown', 0.5, mode=mode, last=last, now=last, status=3))
    near = stamp(262142, 11, 30, 86399)
    for mode in (0, 3):
        out.append(setter_vec('cooldown', 0.5, mode=mode, last=near, now=near))
    out.append(setter_vec('cooldown', 2.0, mode=0, last=stamp(1, 1, 1), now=stamp(2026, 1, 1), flags=(0,)))
    out.append(setter_vec('cooldown', 2.0, mode=3, last=stamp(2026, 1, 1), now=stamp(2026, 1, 2), flags=(0,)))
    return out


def growth_vectors():
    out = []
    for scale in (1.0, ABOVE_1, 2.0, 3.0, 0.5):
        for flags in ((), (1,), (0,), (1, 1), (1, 0), (0, 1), (1, 1, 1, 1, 0), (2, 1), (255,), (1, 1, 1, 1, 1)):
            for index in (0, 1, 7):
                out.append(setter_vec('growth', scale, flags=flags, index=index))
    top = U64 // 10000
    room = U64 - top * 10000
    for scale in (1.0, 2.0):
        for index in (top, top + 1, top + 2, 1 << 60, U64, 1844674407370956):
            for flags in ((), (1,), (0,), (1,) * 3, (1,) * (room + 1), (1,) * (room + 2), (1,) * room + (0,), (1,) * (room + 1) + (0,), (1,) * (room + 2) + (0,)):
                out.append(setter_vec('growth', scale, flags=flags, index=index))
    return out


def write_vectors():
    out = []
    for old, scale in ((0.5, 0.5), (0.0, -0.0), (-0.0, 0.0), (3.0, 3.0), (1.0, ABOVE_1), (ABOVE_1, 1.0), (0.25, 0.75), (2.0, 1.0), (1.0, 2.0), (0.0, 1.0)):
        out.append(setter_vec('write', scale, old=old))
        out.append(setter_vec('write', scale, old=old, mode=3))
    for old, scale in ((NAN, 0.5), (NAN, NAN), (0.5, NAN), (NAN, 0.0)):
        out.append(setter_vec('write', scale, old=old))
    return out


def top_input():
    """An input whose product with 1e9 is exactly the largest finite f64."""
    s_ = sys.float_info.max / 1e9
    for _ in range(8):
        if s_ * 1e9 == sys.float_info.max:
            return s_
        s_ = math.nextafter(s_, INF if s_ * 1e9 < sys.float_info.max else 0.0)
    raise EvidenceError('no input reaches the largest f64')


TOP_INPUT = top_input()


def time_vec(secs, start):
    return dict(kind='time', group='time', start=start, secs_bits=bits(secs))


def time_vectors():
    out = []
    starts = (stamp(2025, 1, 1, 0, 0), stamp(2024, 2, 29, 86399, 999999999), stamp(1970, 1, 1, 1, 1), stamp(-262143, 1, 1, 0, 0), stamp(262142, 12, 31, 86399, 999999999), stamp(1, 1, 1, 43200, 500000000))
    secs = (0.0, -0.0, 1e-10, 1e-9, 2.5e-9, -1e-9, -2.5e-9, 0.5, -0.5, 1.0, -1.0, 60.0, 2592000.0, -2592000.0, 86399.0, 86400.0, -86400.0, 1e6, -1e6, 1e9, -1e9, 9.2e9, -9.2e9,
            9223372036.0, -9223372036.0, 9223372036.854775, 9223372037.0, -9223372037.0, 1e10, -1e10, 1e300, -1e300, INF, -INF, NAN, -NAN, 5e-324, 1.5e-7, 1.7976931348623157e308)
    for s_ in secs + (TOP_INPUT,):
        for st in starts:
            out.append(time_vec(s_, st))
    return out


def lookup_vec(rows, name):
    return dict(kind='lookup', group='lookup', rows=rows, name=name)


def lookup_vectors():
    a, b, c = row(b'alpha'), row(b'bravo'), row(b'alpha', index=2)
    gone = row(b'alpha', status=3)
    other = row(b'alphb')
    longer = row(b'alpha1')
    out = [lookup_vec([], b''), lookup_vec([], b'alpha')]
    for rows in ([a], [b], [a, b], [b, a], [a, c], [gone], [gone, a], [gone, c, a], [other, a], [longer, a], [b, other, longer], [gone, gone], [row(b'', status=1)], [row(b'alpha', status=2)], [row(b'alpha', status=0), b]):
        for name in (b'', b'alpha', b'bravo', b'alph', b'alphaa', b'zzzzz'):
            out.append(lookup_vec(rows, name))
    return out


def arm_vec(arm, group, **kw):
    v = dict(kind='arm', group=group, arm=arm, name=b'alpha', name_cap=9, text=b'0.5', text_cap=7, parsed=0.5, parsed_bits=bits(0.5), rows=[row()], mode=0, now=NOW)
    v.update(kw)
    if v['parsed'] is not None:
        v['parsed_bits'] = bits(v['parsed'])
    return v


def arm_vectors():
    out = []
    a, b = row(b'alpha', old=0.5), row(b'bravo', old=0.5, status=2)
    for arm in ARMS:
        for tlen, nlen in ((3, 5), (100, 5), (101, 5), (3, 100), (3, 101), (100, 100), (101, 101), (65535, 3), (3, 65535)):
            name = b'alpha' if nlen == 5 else bytes(0x61 + i % 26 for i in range(nlen))
            for ncap, tcap in ((9, 7), (0, 7), (9, 0), (0, 0)):
                out.append(arm_vec(arm, 'lengths', text=b'0' * tlen, name=name, name_cap=ncap, text_cap=tcap, rows=[row(name, old=0.25)]))
                out.append(arm_vec(arm, 'lengths', text=b'0' * tlen, name=name, name_cap=ncap, text_cap=tcap, parsed=None))
        for ncap, tcap in ((9, 7), (0, 7), (9, 0), (0, 0)):
            out.append(arm_vec(arm, 'lookup', name=b'zulu', name_cap=ncap, text_cap=tcap))
            out.append(arm_vec(arm, 'setter', parsed=4.0, name_cap=ncap, text_cap=tcap))
        for rows, name in (([a, b], b'bravo'), ([a, b], b'alpha'), ([b, a], b'alpha'), ([a, b], b''), ([row(b'alpha', status=3), a], b''), ([row(b'alpha', status=3), a], b'alpha'), ([], b''), ([], b'alpha')):
            for parsed in (0.5, 0.25, 1.5, 4.0):
                out.append(arm_vec(arm, 'lookup', rows=rows, name=name, parsed=parsed, name_cap=len(name), text_cap=7))
        for parsed in (-1.0, 0.0, 0.5, 1.0, 2.0, 3.0, ABOVE_3):
            for mode in (0, 2, 3, 1):
                for last in (stamp(2025, 1, 1), time_add(NOW, -60.0), time_add(NOW, -59.0), time_add(NOW, -2592000.0), time_add(NOW, -2591999.0)):
                    for flags in ((1,), (0,)):
                        out.append(arm_vec(arm, 'setter', parsed=parsed, mode=mode, rows=[row(old=0.75, last=last, flags=flags)]))
        out.append(arm_vec(arm, 'setter', parsed=2.0, rows=[row(index=U64, old=0.75)]))
    return out


def all_vectors():
    return range_vectors() + cooldown_vectors() + growth_vectors() + write_vectors() + time_vectors() + lookup_vectors() + arm_vectors()


# ---- image binding


FDE_END = {}
RANGES = {}
STOPS = {}
AFTER_SETTER = {}


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


def walk_arm(img, entry):
    """Instructions of one action arm, following both ways of each branch.  The arm ends at the drop of the action
    (movzx eax, byte [rbp+0]) and at the instruction after the byte store of the success tag."""
    found, stops, todo = {}, set(), [entry]
    while todo:
        va = todo.pop()
        if va in found or va in stops:
            continue
        code = img.read(va, 16)
        if code.startswith(b'\x0f\xb6\x45\x00'):
            stops.add(va)
            continue
        ins = decode_one(code + b'\x90' * 16, 0, va)
        found[va] = ins
        nxt = va + ins.size
        if ins.op == 'jmp':
            todo.append(ins.ops[0][1])
            continue
        if ins.op in ('ret', 'jmpr', 'ud2'):
            raise EvidenceError(f'arm reached {ins.op} at {va:#x}')
        if ins.op[0] == 'j':
            todo.append(ins.ops[0][1])
        if ins.op == 'mov' and ins.ops[0][0] == 'm' and ins.ops[0][6] == 8 and ins.ops[1] == ('i', OUTER_OK):
            stops.add(nxt)
            continue
        todo.append(nxt)
    return [found[k] for k in sorted(found)], sorted(stops)


def setter_call(listing):
    calls = [i for i in listing if i.op == 'call' and i.ops[0][0] == 'm' and i.ops[0][4] == SLOT_SETTER]
    if len(calls) != 1:
        raise EvidenceError('arm without one setter call')
    return calls[0]


def build(data):
    check_digest(data)
    fdes = bind_fdes(data)
    img = Image(data)
    code = {}
    for s in RANGES:
        code.update({i.va: i for i in decode_subject(img, s)})
    arms = {}
    for e in ARMS:
        rows, stops = walk_arm(img, e)
        arms[e] = rows
        STOPS[e] = stops
        setter_call(rows)
        for va in stops:
            ins = decode_one(img.read(va, 16) + b'\x90' * 16, 0, va)
            code[va] = ins
        AFTER_SETTER[e] = tuple(i.va + i.size for i in rows if i.op == 'call' and i.ops[0][0] == 'm' and i.ops[0][4] in (SLOT_SETTER, SLOT_LOOKUP))
        code.update({i.va: i for i in rows})
    slots, got = scan_slots(img, code)
    return img, code, fdes, slots, got, arms


# ---- mutation survey


SUBJECTS = (SETTER, TIME_ADD, LOOKUP) + tuple(ARMS)
UNWIND = 'unwind clean-up after a panic in a callee, not a modelled outcome'
UNEXECUTED = {'lookup tail': (0x3332464, 0x3332481, UNWIND)}
SAME_CLAMP = 'the clamp branch returns x for any x inside the limits, and cvttsd2si of anything past them gives i64::MIN, which equals the low clamp and which the cmova at 0x1459d1e turns into i64::MAX on the high side'
DAY_GATE = 'the gate tests whole-day seconds against 2^31 days, and no f64 input can get there: nanoseconds saturate at i64::MAX, about 9.2e9 seconds; flipping the jb is killed on ordinary inputs, these two constants only move the far edge'
LOW_BIT = 'a lower reciprocal gives quotient k-1 and remainder 1e9 at exact multiples; negative multiples normalise back and the chrono add carries a frac of 1e9 once, so the sum is the same for every frac below 1e9'
EQUIVALENT = {
    0x1459ce3: SAME_CLAMP, 0x1459cef: SAME_CLAMP, 0x1459cf1: SAME_CLAMP, 0x1459cf9: SAME_CLAMP, 0x1459d05: SAME_CLAMP,
    0x1459d2c: LOW_BIT, 0x1459d57: 'sar by 0x3e in place of 0x3f on a remainder below 1e9 in size gives the same sign mask',
    0x1459d7b: DAY_GATE, 0x1459d88: DAY_GATE,
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


def all_sites(listing, img):
    sites = []
    for fn in SUBJECTS:
        rows = listing[fn]
        sites += conditional_sites(fn, rows) + field_sites(fn, rows) + imm_sites(fn, rows) + constant_sites(fn, rows, img)
    return [x for x in sites if not any(a <= x['va'] < b for a, b, _ in UNEXECUTED.values())]


SCOPE = {SETTER: ('setter',), TIME_ADD: ('time', 'setter'), LOOKUP: ('lookup',)}


def try_kill(mctx, picked):
    for pos, v in enumerate(picked):
        try:
            bad = check(mctx, v)
        except (Unmodelled, Panicked, EvidenceError, KeyError, OverflowError, ValueError, TypeError, struct.error, IndexError, MemoryError, ZeroDivisionError, StopIteration, Stop) as exc:
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
            if s_['fn'] in ARMS:
                mcode.update({i.va: i for i in walk_arm(mimg, s_['fn'])[0]})
            else:
                mcode.update({i.va: i for i in decode_subject(mimg, s_['fn'])})
        except (EvidenceError, Unmodelled, IndexError, struct.error) as exc:
            rows.append(dict(s_, killed=('decoder', str(exc)[:60].replace('\t', ' '))))
            continue
        rows.append(dict(s_, killed=try_kill((mimg, mcode, slots, got), picked)))
        if PROGRESS and not rows[-1]['killed']:
            print('survivor', hex(s_['fn']), hex(s_['va']), s_['kind'], s_['op'], flush=True)
    return rows


WORKERS = 3
PROGRESS = False


def survey(data, code, slots, got, listing, vecs, img):
    sites = all_sites(listing, img)
    scoped = {}
    for fn in SUBJECTS:
        if fn in ARMS:
            scoped[fn] = [v for v in vecs if v['kind'] == 'arm' and v['arm'] == fn]
        else:
            scoped[fn] = [v for v in vecs if v['kind'] in SCOPE[fn]]
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
    if v['kind'] == 'setter':
        w = setter_rule(v)
        return f"{w['status']:#x}" if w['status'] else f"panic {w['panic']}"
    if v['kind'] == 'time':
        return 'panic' if time_add(v['start'], struct.unpack('<d', struct.pack('<Q', v['secs_bits']))[0]) is None else 'time'
    if v['kind'] == 'lookup':
        return f"row {lookup_rule(v['rows'], v['name'])}"
    w = arm_rule(v)
    return f"{w['stage']} {w['status']:#x}" if w['status'] else f"panic {w['panic']}"


REFERENCE_ROWS = (
    ('differs', 'asset/pdi.rs apply_fee_scale_update', 'cooldown is 60 s when mode_tag == 3, else 2592000 s', 'sete at 0x3718e8f picks row 1 of the table at 0x208d90 when dl == 3: 2592000 s for mode 3, 60 s for any other byte'),
    ('differs', 'asset/pdi.rs apply_fee_scale_update', 'checked_add_seconds_f64 and skip the wait test on None', 'the add has no None: 0x1459df1 panics with chrono text; 0x3718ed2 reads the 12 result bytes with no tag'),
    ('differs', 'asset/pdi.rs apply_fee_scale_update', '!(0.0..=3.0).contains rejects NaN', 'two ucomisd + ja tests let NaN pass at 0x3718e43 and 0x3718e4d, and it is stored; the only caller gets its value through the decimal parser 0x374fe60'),
    ('differs', 'asset/pdi.rs apply_fee_scale_update', 'message: fee scale must be between 0 and 3', 'tag 0xe5 holds f64 3.0 at +8; its Display parts are Fee scale cannot be negative or greater than, the number, and a full stop'),
    ('differs', 'asset/pdi.rs apply_fee_scale_update', 'message: can only change fee scale once every 30.0 days', 'the argument is f64 30.0 shown by 0x1571d50 with min precision 0 (xor edx,edx at 0x1571d6b), so the digits are 30 by inference; tag 0xe0 Display adds the prefix Error deploying perp'),
    ('differs', 'asset/pdi.rs PdiStatus::DisableUnauthorized', 'status 227 means an unauthorized disable', 'tag 0xe3 text is Invalid perp deployer, returned here for dex byte +0x230 == 3'),
    ('differs', 'asset/pdi.rs find_by_dex_name_or_first_mut', 'empty name takes the first lookup-visible dex, none gives UnknownDex', 'an empty name takes row 0 with no status test at 0x3332406, and panics by unwrap at 0x333245e on an empty table'),
    ('differs', 'asset/pdi.rs find_by_dex_name_or_first_mut', 'name length bound is inside the lookup', '0x3332380 has no length test; the arm tests name length after the text and its parser, and tests text length first'),
    ('differs', 'asset/pdi.rs PdiAction::SetFeeScale', 'action holds fee_scale: f64', 'the action holds a String at +0x20 (at most 100 bytes) that 0x374fe60 turns into f64 at run time'),
    ('differs', 'asset/pdi.rs apply_fee_scale_update', 'dex.assets.iter().any has no arithmetic', 'the loop forms asset number dex index x 10000 + i: both overflows panic at l1/src/asset/pdi.rs:30:14'),
    ('same', 'asset/pdi.rs apply_fee_scale_update', 'order: range, status, wait, assets, write', 'same order in 0x3718e30'),
    ('same', 'asset/pdi.rs apply_fee_scale_update', 'time and value change together only when the value differs', 'jne + jnp at 0x3718f2b; an equal value keeps the time and returns 0x186'),
    ('same', 'asset/pdi.rs PdiStatus', 'InvalidFeeScale 229, FeeScaleGrowthModeBlocked 230, ExplicitMessage 224, UnknownDex 321, Bounds 323, Ok 390', 'tags 0xe5, 0xe6, 0xe0, 0x141, 0x143, 0x186'),
    ('unverified', 'asset/pdi.rs growth_mode_allowed', 'asset field name', 'byte +0x29 of a 0x30 row: zero blocks a scale above 1; tag 0xe6 text speaks of setting growth mode, so the reference name is not established'),
)


def generate(data, out_dir, with_survey=True):
    global SEEN
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
                raise EvidenceError(f"mismatch in {v['group']}: {msg}: {[(k, x) for k, x in v.items() if k != '_out']}")
    finally:
        SEEN = None
    for v in vecs:
        if '_out' in v:
            GOLD[id(v)] = v.pop('_out')
    missing, padding = [], 0
    for fn in listing:
        if fn in (TIME_SIGNED, DATE_DAYS):
            continue
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


# loads of meta +0x60 right after a load of row +0x208, seen with a byte search while writing this tool; not a census
READERS = ((0x37130de, 0x37130b0), (0x273b79c, 0x273b4b0), (0x4d4b30c, 0x4d4b020), (0x4d4bbfc, 0x4d4b910))


def pinned(img):
    """Constants the model hard-codes, re-read from .rodata; any change stops the tool."""
    got_ = dict(scale_max=img.f64(SCALE_MAX), scale_free=img.f64(SCALE_FREE), cooldown_other=img.f64(COOLDOWNS), cooldown_mode_3=img.f64(COOLDOWNS + 8), text_days=img.f64(ARG_30),
                ns_factor=img.f64(NS_FACTOR), negative_limit=img.f64(NEG_LIMIT), positive_limit=img.f64(POS_LIMIT), top_below=img.f64(TOP_BELOW))
    want = dict(scale_max=3.0, scale_free=1.0, cooldown_other=60.0, cooldown_mode_3=2592000.0, text_days=30.0, ns_factor=1e9, negative_limit=-2.0 ** 63, positive_limit=2.0 ** 63,
                top_below=2.0 ** 63 - 1024)
    if got_ != want:
        raise EvidenceError(f'constants {got_}')
    for slot, value in ((SLOT_SETTER, SETTER), (SLOT_LOOKUP, LOOKUP), (SLOT_PARSER, PARSER), (0x576efb8, TIME_ADD), (0x576e8a8, TIME_SIGNED), (0x576e8b0, DATE_DAYS), (0x576e040, FORMAT),
                        (0x576ea18, FLOAT_SHOW), (0x576e010, FREE), (0x576e118, PANIC_ADD), (0x576e1b0, PANIC_MUL), (0x576e468, PANIC_EXPECT)):
        if img.relative(slot) != value:
            raise EvidenceError(f'slot {slot:#x}')
    return got_


def facts_and_files(data, out_dir, img, fdes, listing, vecs, rows, seen, padding, slots):
    constants = pinned(img)
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
    per = {hex(fn): dict(instructions=len(listing[fn]), executed=sum(i.va in seen for i in listing[fn]), fde=hex(fdes.range_of(fn)['fde']), end=hex(FDE_END[fn])) for fn in RANGES}
    arm_facts = {hex(e): dict(function=hex(s['fn']), instructions=len(listing[e]), executed=sum(i.va in seen for i in listing[e]), ends=[hex(x) for x in STOPS[e]],
                              frame=dict(buffer=hex(s['buf']), text=hex(s['text']), now=hex(s['now']), out=hex(s['out']), exchange=hex(s['ex'])),
                              exchange=dict(mode=hex(s['mode']), registry=hex(s['registry']), now='0x60')) for e, s in ARMS.items()}
    status = {hex(t): dict(arm=hex(status_arm(img, t)), text=status_text(img, t)) for t in (GONE, BLOCKED, UNKNOWN_DEX, TOO_LONG, PARSE_ERR)}
    formats = {hex(t): dict(arm=hex(status_arm(img, t)), pieces=hex(status_format(img, t)), parts=format_pieces(img, status_format(img, t))) for t in (TOO_SOON, BAD_SCALE)}
    names = {w: [hex(a) for a in text_hits(img, w.encode())] for w in ('deployerFeeScale', 'lastDeployerFeeScaleChangeTime')}
    readers = []
    for site, fn in READERS:
        if img.read(site, 5) != bytes.fromhex('f20f104060') or img.read(site - 7, 3)[1] != 0x8b:
            raise EvidenceError(f'reader {site:#x}')
        readers.append(dict(site=hex(site), function=hex(fn), load=img.read(site - 7, 12).hex(), next=img.read(site + 5, 8).hex()))
    evidence = dict(
        binary=BINARY, sha256=SHA256, functions=per, arms=arm_facts, constants=constants,
        setter_slot=dict(slot=hex(SLOT_SETTER), value=hex(img.relative(SLOT_SETTER)), slots_holding_setter=slots_holding(img, SETTER), users=slot_users(img, SLOT_SETTER, starts), direct_calls=direct_sites(img, SETTER, starts)),
        slots=dict(lookup=hex(img.relative(SLOT_LOOKUP)), parser=hex(img.relative(SLOT_PARSER)), time_add=hex(img.relative(0x576efb8)), time_signed=hex(img.relative(0x576e8a8)), date_days=hex(img.relative(0x576e8b0)), format=hex(img.relative(0x576e040)), float_show=hex(img.relative(0x576ea18))),
        float_show_body=img.read(FLOAT_SHOW, 52).hex(), format_pieces=hex(PIECES), format_parts=format_pieces(img, PIECES), panic_text=img.read(*TEXT_TIME).decode('ascii'),
        status=status, status_formats=formats, readers=readers, locations=dict(asset=location(img, LOC_ASSET), time=location(img, LOC_TIME)), field_names=names,
        vectors=len(vecs), mismatches=0, groups=groups, outcomes=outcomes, padding_not_executed=padding,
        unexecuted=[dict(start=hex(a), end=hex(b), why=w) for a, b, w in UNEXECUTED.values()], not_mutated=[hex(TIME_SIGNED), hex(DATE_DAYS)],
        mutants=len(rows), killed=sum(1 for r in rows if r['killed']), equivalent={hex(k): w for k, w in sorted(EQUIVALENT.items())},
    )
    with open(out_path / 'evidence.json', 'w', newline='\n') as f:
        json.dump(evidence, f, indent=1, sort_keys=True)
        f.write('\n')
    return evidence


def text_hits(img, needle):
    addr_, off, size, _ = img.sec['.rodata']
    blob, out = img.data, []
    i = blob.find(needle, off, off + size)
    while i != -1:
        out.append(addr_ + i - off)
        i = blob.find(needle, i + 1, off + size)
    return out


def main():
    ap = argparse.ArgumentParser(description=__doc__.split('\n')[0])
    ap.add_argument('--out', required=True)
    args = ap.parse_args()
    data = (ROOT / BINARY).read_bytes()
    ev = generate(data, args.out)
    print(json.dumps(dict(vectors=ev['vectors'], mutants=ev['mutants'], killed=ev['killed']), sort_keys=True))


if __name__ == '__main__':
    main()
