#!/usr/bin/env python3
"""fees: node #94 approveBuilderFee path, from bytes alone.

Static, no execution of the node.  The two entries 0x1e60a90 and 0x1e64620, the text parser 0x3364cd0 and
its Decimal and f64 helpers, the gate 0x2758330, the writer 0x37459e0 and the table and map code are decoded
from ELF bytes by the table decoder below, which must land exactly on each FDE end, and interpreted in
Python on every vector.  The book lookup, the margin summary, the hash, drops and allocation are stubs.
Each outcome is compared with a separate closed-form model, then every conditional, field offset and
immediate of the subject functions is mutated to test the vectors.

    python3 tools/fees_approve_builder.py --out <dir>

writes evidence.json, vectors.tsv, mutations.tsv, instructions.tsv and reference-diff.tsv.  Section and FDE
parsing come from tools/elf_index.py and tools/fde_extents.py.  Only the standard library is used: no
objdump, readelf or other external program runs, so the results cannot depend on a binutils version.
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

PARSER = 0x3364cd0
ENTRY_USER = 0x1e60a90
ENTRY_SYSTEM = 0x1e64620
GATE = 0x2758330
WRITER = 0x37459e0
WRAP = 0x3799510
SCALE = 0x3750350
FROM_STR = 0x4eacd00
FLOAT_PARSE = 0x15756d0
FROM_PARTS = 0x4eac740
MAP_INSERT = 0x339df50
MAP_REMOVE = 0x33aacd0
HELPERS = (FROM_STR, 0x4eab4d0, 0x4eab570, 0x4eaae70, 0x4eaad60, 0x4eac520, 0x4eac680, 0x4eac4a0, 0x4eaad00, 0x4eac4b0, 0x4eaafc0,
           0x4eaad20, 0x4eac640, 0x4eaadb0, 0x4eab330, 0x4eac450, 0x4eab3e0, 0x4eaaf80, 0x4eab0b0, 0x4eac500, 0x4eab9d0, 0x4eabac0, 0x4eaaec0,
           FLOAT_PARSE, FROM_PARTS, 0x4eadc80, 0x4eacde0, 0x4ead3d0, 0x4eaf760, 0x4eadb90,
           0x3596da0, 0x379a610, MAP_INSERT, MAP_REMOVE, 0x2fd6c00, 0x2fc2ab0, 0x2f7a510,
           0x4eafa20, 0x4eac200, 0x4eae070, 0x1575c90, 0x4eaae00, 0x4eaaf10, 0x4eab220, 0x4eab660, 0x4eab7f0, 0x4eab8f0, 0x4eac0d0,
           0x4eac170, 0x4eac250, 0x4eac2c0, 0x4eac330, 0x4eac380, 0x4eac3f0, 0x4eac4c0, 0x4eac4e0, 0x4eac5e0, 0x4eac600, 0x4eac620,
           0x4eac660, 0x4eada30, 0x4eae530, 0x4eaeee0, 0x4eaef40, 0x4eaf180, 0x15751f0, 0x1574860, 0x1574ad0, 0x1574cc0, 0x1574db0)
DECODED = (ENTRY_USER, ENTRY_SYSTEM, PARSER, WRAP, SCALE, GATE, WRITER) + HELPERS
SUBJECTS = (ENTRY_USER, ENTRY_SYSTEM, PARSER, WRAP, GATE, WRITER)
DROP_ERROR = 0x3379490
DROP_FAIL = 0x3762510
SUMMARY = 0x37d79e0
BOOK = 0x36f57f0
HASH = 0x399c7a0
RESERVE = 0x357d310
MALLOC = 0x54c06b0
FREE = 0x54c8cb0
PANICS = (0x157b7f0, 0x157b810, 0x157a9f0, 0x157aa10, 0x157b63b, 0x157b4a0, 0x157b480, 0x157b64f, 0x157b440, 0x157b4c0, 0x157b520, 0x1345e2a, 0x14385c0)
GOT_ALLOC = 0x576dfd8
GOT_MEMCPY = 0x576dfe0
GOT_MEMMOVE = 0x576e0e0
GOT_FREE = 0x576e010
GOT_MEMSET = 0x576e1f8
GOT_MEMCMP = 0x576e488
GOT_PANIC = 0x576e048
GOT_PANIC2 = 0x576e128
PARSER_SLOT = 0x5773168
WRAP_SLOT = 0x57731d8
SCALE_SLOT = 0x5773848
SUMMARY_SLOT = 0x5773178
WRITER_SLOT = 0x5774d30
FROM_STR_SLOT = 0x5775968
FLOAT_SLOT = 0x576eae8
OK = 0x186
TOO_SMALL = 0x127
BAD_RATE = 0x12a
TOO_MANY = 0x12b
FEE_LIMIT = 0x13f
NO_DEX = 0x141
TOO_LONG = 0x143
SCALE_ERROR = 0xa8
PARSE_ERROR = 0xac
TAG_OK = 13
TAG_ERR = 14
MAX_TEXT = 100
SYSTEM_LIMIT = 0xccccccccccccccc
MIN_VALUE = 100000000
MAX_BUILDERS = 11
MAX_MILLIS = (1 << 63) - 2
MANTISSA_LIMIT = 1 << 96
STRIDE = 0xe8
BUCKETS = 32
LEAF_LEN = 0x13e
LEAF_KEYS = 0x60
LEAF_VALUES = 8
ROW_ROOT = 0x80
ROW_HEIGHT = 0x88
ROW_LEN = 0x90
EXCHANGE_SIZE = 0x6c0
TRACKER = 0x5d0
TABLE = TRACKER + 0xc0
UNWRAP_TEXT = b'called `Result::unwrap()` on an `Err` value'
PINNED = (
    (0x1e60aa8, '4883fa65', 'user entry: length below 0x65 passes'),
    (0x1e60aae, '66c7430843 01'.replace(' ', ''), 'user entry: tag 0x143'),
    (0x1e60add, '418b4750', 'user entry: last word of the address at action +0x50'),
    (0x1e60ae5, '410f104740', 'user entry: first words of the address at action +0x40'),
    (0x1e6463d, '48b8cccccccccccccc0c', 'system entry: limit 0x0ccc...cc'),
    (0x3364cd8, '807c16ff25', 'parser: last byte is 0x25'),
    (0x3364d19, '31d2', 'parser: mode 0 for the scaled conversion'),
    (0x3364d1b, 'b903000000', 'parser: 3 decimal digits for the scaled conversion'),
    (0x2758350, '4883be c805000000'.replace(' ', ''), 'gate: length word at exchange +0x5c8'),
    (0x27583ca, '48817c2410ffe0f505', 'gate: signed compare of the first word with 99999999'),
    (0x27583e2, '4881c6d0050000', 'gate: fee tracker is exchange +0x5d0'),
    (0x37459f2, '488dbec0000000', 'writer: table is tracker +0xc0'),
    (0x3745a0a, '4883b8900000000a', 'writer: compare the map length at value +0x90 with 10'),
    (0x3745a14, '4883e880', 'writer: map at value +0x80'),
    (0x339df8a, '410fb784243e010000', 'map insert: node length at +0x13e'),
)
GATE_COPIES = (0x4d80fb0, 0x4d81120)
ENTRY_COPIES = (0x46bba70, 0x46bbb90)
SYSTEM_COPIES = (0x4c03940, 0x4c039e0)
REFERENCE_FILES = ('handlers/54_approve_builder_fee.rs', 'handlers/70_system_approve_builder_fee.rs')


STACK_FILL = bytes((i * 5 + 3) & 0xff | 1 for i in range(0x8000))


class Panicked(Exception):
    """The node would panic here; a modelled outcome, unlike Unmodelled."""


def key_hash(key):
    return int.from_bytes(hashlib.sha256(key).digest()[:8], 'little')


def addr(n):
    """A 20-byte test address."""
    return hashlib.sha256(b'addr' + str(n).encode()).digest()[:20]


# ---- model, written from the observed rules and independent of the machine


def decimal_text(body):
    """The Decimal text path: (negative, mantissa, scale), or None when it refuses the text."""
    n = len(body)
    if not n:
        return None
    i, negative = 0, False
    if body[0] in b'+-':
        negative = body[0] == 0x2d
        i = 1
        if i == n:
            return None
    first = body[i]
    if first == 0x2e:
        if i + 1 == n or not 0x30 <= body[i + 1] <= 0x39:
            return None
    elif not 0x30 <= first <= 0x39:
        return None
    data, scale, point = 0, 0, False
    while i < n:
        byte = body[i]
        i += 1
        if 0x30 <= byte <= 0x39:
            if point and scale >= 28:
                return None
            data = data * 10 + byte - 0x30
            scale += point
            if data >= MANTISSA_LIMIT:
                return None
        elif byte == 0x2e and not point:
            point = True
        elif byte == 0x5f:
            if point and scale >= 28:
                return None
        else:
            return None
    return negative, data, scale


def float_shape(body):
    """Rust's f64 text grammar for finite numbers; inf and nan are refused later anyway."""
    i, n = 0, len(body)
    if i < n and body[i] in b'+-':
        i += 1
    start = i
    while i < n and 0x30 <= body[i] <= 0x39:
        i += 1
    whole = i - start
    frac = 0
    if i < n and body[i] == 0x2e:
        i += 1
        start = i
        while i < n and 0x30 <= body[i] <= 0x39:
            i += 1
        frac = i - start
    if not whole and not frac:
        return False
    if i < n and body[i] in b'eE':
        i += 1
        if i < n and body[i] in b'+-':
            i += 1
        start = i
        while i < n and 0x30 <= body[i] <= 0x39:
            i += 1
        if start == i:
            return False
    return i == n


def from_f64(x):
    """(negative, mantissa, scale) of the f64 conversion: exact digits cut to about 15 places, then None when too large."""
    if x == 0:
        return math.copysign(1.0, x) < 0, 0, 0
    bits = f2b(x)
    negative = bool(bits >> 63)
    field, mant = bits >> 52 & 0x7ff, bits & ((1 << 52) - 1)
    if field:
        mant |= 1 << 52
        exp2 = field - 1075
    else:
        exp2 = -1074
    five, ten = -exp2, exp2
    mask = (1 << 96) - 1
    while five > 0:
        five -= 1
        if not mant & 1:
            ten += 1
            mant >>= 1
        elif mant * 5 <= mask:
            mant *= 5
        else:
            ten += 1
            mant >>= 1
    while five < 0:
        five += 1
        if mant >> 95:
            mant //= 5
        else:
            ten -= 1
            mant <<= 1
    while ten > 0:
        if mant * 10 > mask:
            return None
        mant *= 10
        ten -= 1
    while ten < -28:
        mant, rem = divmod(mant, 10)
        ten += 1
        if mant == 0:
            ten = 0
        elif rem >= 5:
            mant += 1
    while ten < 0 and mant >> 52:
        mant, rem = divmod(mant, 10)
        ten += 1
        if rem >= 5:
            mant += 1
    while ten < 0 and mant % 10 == 0:
        mant //= 10
        ten += 1
    return negative, mant, -ten


def parse_model(text):
    """Status and millis of the parser for the full text with its percent sign."""
    if not text or text[-1] != 0x25:
        return BAD_RATE, None
    body = text[:-1]
    got = decimal_text(body)
    if got is None:
        if not float_shape(body):
            return BAD_RATE, None
        x = float(body.decode('ascii'))
        if x != x or x in (math.inf, -math.inf):
            return BAD_RATE, None
        got = from_f64(x)
        if got is None:
            return BAD_RATE, None
    negative, mant, scale = got
    num, den = mant * 1000, 10 ** scale
    if num % den or (negative and num):
        return BAD_RATE, None
    millis = num // den
    if millis > MAX_MILLIS:
        return BAD_RATE, None
    return OK, millis


def reference_parse(text):
    """The reference claim for the text path: suffix %, no sign, digits, one point, at most 3 places, no exponent."""
    if len(text) >= 101 or not text or text[-1] != 0x25:
        return None
    body = text[:-1]
    head, dot, tail = body.partition(b'.')
    if not head + tail or not (head + tail).isdigit() or len(tail) > 3:
        return None
    value = int(head or b'0') * 1000 + int((tail + b'000')[:3] or b'0')
    return value if value < 1 << 64 and int(head or b'0') < 1 << 64 else None


class World:
    """Model state: per-user builder map, plus the set of users that have a row."""

    def __init__(self):
        self.maps = {}

    def apply(self, step, dex=True):
        """Outcome of one step: status, word kind, panic."""
        if step['kind'] == 'user':
            text = step['text']
            if len(text) > MAX_TEXT:
                return dict(status=TOO_LONG, word='action')
            status, fee = parse_model(text)
            if status != OK:
                return dict(status=status, word=None)
        else:
            fee = step['fee']
            if fee >= SYSTEM_LIMIT:
                return dict(status=FEE_LIMIT, word=fee)
        if fee:
            if not dex:
                return dict(panic=True)
            if signed(step['value'], 64) < MIN_VALUE:
                return dict(status=TOO_SMALL, word=None)
        row = self.maps.setdefault(step['user'], {})
        if not fee:
            row.pop(step['builder'], None)
            return dict(status=OK, word=None)
        if len(row) >= MAX_BUILDERS:
            return dict(status=TOO_MANY, word=None)
        row[step['builder']] = fee
        return dict(status=OK, word=None)


# ---- evaluator set-up


FDE_END = {}


def bind_fdes(data):
    fdes = Fdes(data)
    for s in DECODED:
        FDE_END[s] = fdes.range_of(s)['end']
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


def build(data):
    check_digest(data)
    fdes = bind_fdes(data)
    img = Image(data)
    code = {}
    for s in DECODED:
        code.update({i.va: i for i in decode_range(img, s, FDE_END[s])})
    slots, got = scan_slots(img, code)
    return img, code, fdes, slots, got


def put(m, a, off, size, val):
    m.store(a.base + off, size, val)


def put_bytes(m, a, off, raw):
    for i, b in enumerate(raw):
        m.store(a.base + off + i, 1, b)


def payload(tag):
    """An error value with a different byte at each offset, so a shifted copy shows."""
    raw = bytearray((off * 7 + tag) & 0xff for off in range(0x70))
    raw[0:2] = struct.pack('<H', tag)
    return bytes(raw)


def machine(img, code, slots, got):
    m = Machine(img, ())
    m.code = code
    m.slots = slots
    m.got = got
    for t in DECODED:
        m.real[t] = t
    stack = m.arena(0x8000, strict=False)
    stack.mem[:] = STACK_FILL
    top = stack.base + 0x7f08
    m.top = top

    m.live = {}

    def alloc():
        a = m.arena(max(m.regs[R['rdi']], 1))
        m.live[a.base] = m.regs[R['rdi']]
        m.clobber(a.base)

    def release():
        if m.live.pop(m.regs[R['rdi']], None) != m.regs[R['rsi']]:
            raise Unmodelled('free of another block')
        m.clobber()

    def memcpy():
        d, s, n = m.regs[R['rdi']], m.regs[R['rsi']], m.regs[R['rdx']]
        blob = bytes(m.load(s + k, 1) for k in range(n))
        for k, b in enumerate(blob):
            m.store(d + k, 1, b)
        m.clobber(d)

    def memset():
        d, c, n = m.regs[R['rdi']], m.regs[R['rsi']], m.regs[R['rdx']]
        for k in range(n):
            m.store(d + k, 1, c)
        m.clobber(d)

    def memcmp():
        a, b, n = m.regs[R['rdi']], m.regs[R['rsi']], m.regs[R['rdx']]
        x = bytes(m.load(a + k, 1) for k in range(n))
        y = bytes(m.load(b + k, 1) for k in range(n))
        m.clobber(0 if x == y else 1 if x > y else (1 << 32) - 1)

    def nothing():
        m.clobber()

    def drop():
        tag = m.load(m.regs[R['rdi']], 2)
        if tag not in m.droppable:
            raise Unmodelled(f'drop of {tag:#x}')
        m.drops.append(tag)
        m.dropped = bytes(m.load(m.regs[R['rdi']] + k, 1) for k in range(0x60)) if m.droppable[-1] == tag else None
        m.clobber()

    def fail():
        if m.load(m.regs[R['rdi']], 2) != PARSE_ERROR:
            raise Unmodelled('drop of another failure')
        m.clobber()

    def panic():
        raise Panicked()

    def unwrap():
        r = m.regs
        text = bytes(m.load(r[R['rdi']] + k, 1) for k in range(r[R['rsi']]))
        if text != UNWRAP_TEXT or m.load(r[R['rdx']], 2) != NO_DEX:
            raise Unmodelled('unwrap panic arguments')
        raise Panicked()

    m.droppable = (NO_DEX, SCALE_ERROR, PARSE_ERROR)
    m.drops = []
    m.stubs.update({DROP_ERROR: drop, DROP_FAIL: fail, MALLOC: alloc, FREE: nothing})
    for t in PANICS:
        m.stubs[t] = panic
    for s, fn in ((GOT_ALLOC, alloc), (GOT_MEMCPY, memcpy), (GOT_MEMMOVE, memcpy), (GOT_FREE, release), (GOT_MEMSET, memset), (GOT_MEMCMP, memcmp), (GOT_PANIC, unwrap),
                  (GOT_PANIC2, panic)):
        m.stubs[slots[s]] = fn
    return m


def enter(m, fn, *args):
    m.regs[R['rsp']] = m.top
    m.store(m.top, 8, 0xfeedface)
    for name, val in zip(('rdi', 'rsi', 'rdx', 'rcx', 'r8', 'r9'), args):
        m.regs[R[name]] = val
    for name in ('rbx', 'rbp', 'r12', 'r13', 'r14', 'r15'):
        m.regs[R[name]] = 0xc0de0000 + R[name]
    m.run(fn)
    if m.regs[R['rsp']] != m.top + 8:
        raise Unmodelled('stack not balanced')
    for name in ('rbx', 'rbp', 'r12', 'r13', 'r14', 'r15'):
        if m.regs[R[name]] != 0xc0de0000 + R[name]:
            raise Unmodelled(f'{name} not restored')


def run_text(img, code, slots, got, text):
    m = machine(img, code, slots, got)
    raw = m.arena(max(len(text), 1))
    put_bytes(m, raw, 0, text)
    out = m.arena(0x80, strict=False)
    enter(m, PARSER, out.base, raw.base, len(text))
    if m.live:
        raise Unmodelled('block not freed')
    tag = m.load(out.base, 2)
    return tag, m.load(out.base + 8, 8) if tag == OK else None


def check_text(img, code, slots, got, v):
    tag, word = run_text(img, code, slots, got, v['text'])
    want = parse_model(v['text'])
    if (tag, word) != want:
        return f'parser {tag:#x} {word} != {want[0]:#x} {want[1]}'
    return None


def table_of(m, decoys):
    size = BUCKETS
    a = m.arena(STRIDE * size + 16 + size + 16 + 16, strict=False)
    ctrl_off = STRIDE * size + 16
    ctrl = [0xff] * size
    for key in decoys:
        h = key_hash(key)
        pos = h & (size - 1)
        while ctrl[pos] != 0xff:
            pos = (pos + 1) & (size - 1)
        ctrl[pos] = h >> 57
        at = ctrl_off - (pos + 1) * STRIDE
        for off in range(0, STRIDE, 8):
            put(m, a, at + off, 8, 0xa5a5a5a500000000 | off)
        put_bytes(m, a, at, key)
        for off in (0x18 + ROW_ROOT, 0x18 + ROW_HEIGHT, 0x18 + ROW_LEN):
            put(m, a, at + off, 8, 0)
    for i in range(size):
        put(m, a, ctrl_off + i, 1, ctrl[i])
    for i in range(16):
        put(m, a, ctrl_off + size + i, 1, ctrl[i])
    m.table, m.ctrl_off = a, ctrl_off
    return a.base + ctrl_off


def exchange_of(m, v):
    a = m.arena(EXCHANGE_SIZE)
    for off in range(0, EXCHANGE_SIZE, 8):
        put(m, a, off, 8, 0x5a5a5a5a00000000 | off)
    dex = m.arena(0x200)
    for off in range(0, 0x200, 8):
        put(m, dex, off, 8, 0x3c3c3c3c00000000 | off)
    put(m, a, 0x5c0, 8, dex.base)
    put(m, a, 0x5c8, 8, 1 if v.get('dex', True) else 0)
    put(m, a, TABLE, 8, table_of(m, v.get('decoys', ())))
    put(m, a, TABLE + 8, 8, BUCKETS - 1)
    put(m, a, TABLE + 0x10, 8, 24)
    put(m, a, TABLE + 0x18, 8, len(v.get('decoys', ())))
    m.dex = dex
    return a


def install(m, a):
    row = m.arena(8)

    def book():
        if m.regs[R['rdi']] != m.dex.base + 0xf8:
            raise Unmodelled('book of another base')
        key = bytes(m.load(m.regs[R['rsi']] + k, 1) for k in range(20))
        if key != m.step['builder']:
            raise Unmodelled('book of another address')
        m.clobber(row.base)

    def summary():
        r = m.regs
        if r[R['rsi']] != row.base or r[R['rdx']] & 0xff != 1 or r[R['rcx']] & 0xff != 1 or r[R['r9']] != m.dex.base + 0x60:
            raise Unmodelled('summary arguments')
        if m.load(r[R['rsp']], 8) != m.dex.base:
            raise Unmodelled('summary stack argument')
        m.store(r[R['rdi']], 8, m.step['value'])
        m.clobber()

    def do_hash():
        if m.regs[R['rdi']] != a.base + TABLE + 0x20:
            raise Unmodelled('hash of another table')
        m.clobber(key_hash(bytes(m.load(m.regs[R['rsi']] + i, 1) for i in range(20))))

    def reserve():
        raise Unmodelled('table growth')

    m.stubs.update({BOOK: book, SUMMARY: summary, HASH: do_hash, RESERVE: reserve})


def run_step(m, a, step):
    m.step = step
    out = m.arena(0x70, strict=False)
    user = m.arena(20)
    put_bytes(m, user, 0, step['user'])
    if step['kind'] == 'user':
        act = m.arena(0x58)
        raw = m.arena(max(len(step['text']), 1))
        put_bytes(m, raw, 0, step['text'])
        for off in range(0, 0x58, 8):
            put(m, act, off, 8, 0x1212121200000000 | off)
        put(m, act, 8, 8, raw.base)
        put(m, act, 0x10, 8, len(step['text']))
        put_bytes(m, act, 0x40, step['builder'])
        fn = ENTRY_USER
    else:
        act = m.arena(0x1c)
        put(m, act, 0, 8, step['fee'])
        put_bytes(m, act, 8, step['builder'])
        fn = ENTRY_SYSTEM
    m.action = act
    a2 = (out.base, act.base, user.base, a.base)
    enter(m, fn, *a2)
    return out


def tree_items(m, value):
    root = m.load(value + ROW_ROOT, 8)
    size = m.load(value + ROW_LEN, 8)
    if not root:
        if size:
            raise Unmodelled('map length without a root')
        return []
    if m.load(value + ROW_HEIGHT, 8):
        raise Unmodelled('map is not one leaf')
    n = m.load(root + LEAF_LEN, 2)
    if n != size:
        return [('length', n, size)]
    return [(bytes(m.load(root + LEAF_KEYS + 20 * i + k, 1) for k in range(20)), m.load(root + LEAF_VALUES + 8 * i, 8)) for i in range(n)]


def state_of(m):
    """Key -> sorted builder map, from the table bytes."""
    a, off = m.table, m.ctrl_off
    got = {}
    for i in range(BUCKETS):
        if a.mem[off + i] < 0x80:
            at = off - (i + 1) * STRIDE
            key = bytes(a.mem[at:at + 20])
            got[key] = at
    return got


def check_sequence(img, code, slots, got, v):
    m = machine(img, code, slots, got)
    a = exchange_of(m, v)
    install(m, a)
    snap = bytes(a.mem)
    decoys = {k: bytes(m.table.mem[at:at + STRIDE]) for k, at in state_of(m).items()}
    world = World()
    for pos, step in enumerate(v['steps']):
        want = world.apply(step, v.get('dex', True))
        try:
            out = run_step(m, a, step)
        except Panicked:
            if want.get('panic'):
                continue
            return f'step {pos}: panic'
        if want.get('panic'):
            return f'step {pos}: no panic'
        tag, status = m.load(out.base, 1), m.load(out.base + 8, 2)
        if want['status'] == OK:
            if tag != TAG_OK:
                return f'step {pos}: tag {tag} status {status:#x} != ok'
        else:
            if tag != TAG_ERR or status != want['status']:
                return f'step {pos}: tag {tag} status {status:#x} != {want["status"]:#x}'
            if want['word'] == 'action' and m.load(out.base + 0x10, 8) != m.action.base:
                return f'step {pos}: word'
            if isinstance(want['word'], int) and m.load(out.base + 0x10, 8) != want['word']:
                return f'step {pos}: word'
        rows = state_of(m)
        if set(rows) - set(decoys) != set(world.maps) - set(decoys):
            return f'step {pos}: rows'
        for key, inner in world.maps.items():
            value = m.table.base + rows[key] + 0x18
            items = tree_items(m, value)
            if items != sorted(inner.items()):
                return f'step {pos}: map differs'
        for key, raw in decoys.items():
            if key not in world.maps and bytes(m.table.mem[rows[key]:rows[key] + STRIDE]) != raw:
                return f'step {pos}: decoy row'
        now, base = bytearray(a.mem), bytearray(snap)
        now[TABLE + 0x10:TABLE + 0x20] = base[TABLE + 0x10:TABLE + 0x20]
        if now != base:
            return f'step {pos}: exchange byte'
        if m.load(a.base + TABLE + 0x18, 8) != len(rows):
            return f'step {pos}: item count'
    return None


COPY_CASES = (
    ('user entry, parser error', ENTRY_USER, PARSER, 0x155, 8),
    ('user entry, gate error', ENTRY_USER, GATE, 0x156, 8),
    ('system entry, gate error', ENTRY_SYSTEM, GATE, 0x157, 8),
    ('gate, writer error', GATE, WRITER, 0x158, 0),
    ('parser, decimal error', PARSER, WRAP, 0x159, 0),
    ('parser, scale error', PARSER, SCALE, 0x15a, 0),
)


def check_copy(img, code, slots, got, v):
    """A callee stub writes a positional error; the caller must pass it on at the fixed shift."""
    fn, callee, tag, shift = v['fn'], v['callee'], v['tag'], v['shift']
    m = machine(img, code, slots, got)
    m.droppable = m.droppable + (tag,)
    a = exchange_of(m, dict(decoys=()))
    install(m, a)
    m.step = dict(builder=addr(2), value=MIN_VALUE)
    del m.real[callee]

    def stub():
        for off, b in enumerate(payload(tag)[:0x60]):
            m.store(m.regs[R['rdi']], 1, b) if off == 0 else m.store(m.regs[R['rdi']] + off, 1, b)
        m.clobber(m.regs[R['rdi']])
    m.stubs[callee] = stub

    def ok_wrap():
        out = m.regs[R['rdi']]
        m.store(out, 2, OK)
        m.store(out + 4, 8, 1)
        m.store(out + 12, 8, 0)
        m.clobber(out)
    if callee == SCALE:
        m.stubs[WRAP] = ok_wrap
        del m.real[WRAP]
    out = m.arena(0x70, strict=False)
    user = m.arena(20)
    put_bytes(m, user, 0, addr(1))
    if fn == PARSER:
        text = m.arena(2)
        put_bytes(m, text, 0, b'1%')
        enter(m, PARSER, out.base, text.base, 2)
        want = bytearray(payload(tag)[:0x60])
        want[0:2] = struct.pack('<H', BAD_RATE)
        if m.drops != [tag] or m.dropped != payload(tag)[:0x60]:
            return 'error not dropped whole, once'
    elif fn == GATE:
        builder = m.arena(20)
        put_bytes(m, builder, 0, addr(2))
        enter(m, GATE, out.base, a.base, user.base, builder.base, 7)
        want = bytearray(payload(tag)[:0x60])
    elif fn == ENTRY_USER:
        act = m.arena(0x58)
        raw = m.arena(2)
        put_bytes(m, raw, 0, b'1%')
        for off in range(0, 0x58, 8):
            put(m, act, off, 8, 0x1212121200000000 | off)
        put(m, act, 8, 8, raw.base)
        put(m, act, 0x10, 8, 2)
        if callee == GATE:
            m.stubs[PARSER] = None
            m.real[PARSER] = PARSER
        enter(m, ENTRY_USER, out.base, act.base, user.base, a.base)
        want = bytearray(payload(tag)[:0x60])
    else:
        act = m.arena(0x1c)
        for off in range(0, 0x18, 8):
            put(m, act, off, 8, 7)
        put(m, act, 0x18, 4, 7)
        enter(m, ENTRY_SYSTEM, out.base, act.base, user.base, a.base)
        want = bytearray(payload(tag)[:0x60])
    got_raw = bytes(out.mem[shift:shift + 0x60])
    if got_raw != bytes(want):
        return f'copy byte {next(i for i in range(0x60) if got_raw[i] != want[i]):#x}'
    if shift and out.mem[0] != TAG_ERR:
        return 'outer tag'
    return None


def check(img, code, slots, got, v):
    kind = v['type']
    if kind == 'text':
        return check_text(img, code, slots, got, v)
    if kind == 'copy':
        return check_copy(img, code, slots, got, v)
    return check_sequence(img, code, slots, got, v)


# ---- vectors


class Lcg:
    def __init__(self, seed):
        self.x = seed

    def next(self):
        self.x = (self.x * 6364136223846793005 + 1442695040888963407) & U64
        return self.x >> 33

    def pick(self, seq):
        return seq[self.next() % len(seq)]


CURATED = (
    b'', b'%', b'1', b'1%%', b'%1', b' 1%', b'1 %', b'0%', b'00%', b'0.0%', b'0.000%', b'0.0000%', b'-0%', b'+0%', b'-0.0%', b'-.0%', b'1%', b'+1%', b'-1%', b'01%',
    b'0.001%', b'0.0010%', b'0.0001%', b'0.0015%', b'0.1%', b'.5%', b'5.%', b'+.5%', b'-.5%', b'.%', b'+%', b'-%', b'+-1%', b'++1%', b'1.2.3%',
    b'1_0%', b'1_%', b'1__0%', b'_1%', b'1._5%', b'._5%', b'1_.5%', b'1.5_%', b'0.000_1%', b'0._1%', b'+_1%', b'1e1%', b'1E1%', b'1e+1%', b'1e-1%', b'1e-3%', b'1e-4%', b'1E2%',
    b'0e0%', b'-0e0%', b'0e99%', b'1e%', b'e1%', b'1e1e1%', b'1.e1%', b'.1e1%', b'.e1%', b'+1e1%', b'-1e1%', b'-1e-400%', b'1e-400%', b'1e400%', b'-1e400%',
    b'1.5e-1%', b'0.1e-2%', b'0.3e-2%', b'0.29e-2%', b'1.1e-2%', b'1.23e-1%', b'1.234e0%', b'1.2345e0%', b'3e-3%', b'0.1234e1%', b'1e-30%', b'1e15%', b'1e16%', b'9.2e15%', b'9.3e15%', b'7.9e28%', b'1e27%', b'1e28%', b'1e29%',
    b'inf%', b'INF%', b'Inf%', b'infinity%', b'+inf%', b'-inf%', b'nan%', b'NaN%', b'-nan%', b'abc%', b'0x10%', b'1,5%',
    b'9223372036854775.806%', b'9223372036854775.807%', b'9223372036854775.8069%', b'922337203685477580%', b'9223372036854775%', b'9223372036854776%',
    b'1.0000000000000000000000000000%', b'1.000000000000000000000000000%', b'1.00000000000000000000000000000%', b'1.000000000000000000000000000000%',
    b'1.0000000000000000000000000001%', b'1.00000000000000000000000000005%', b'1.00000000000000000000000000049%', b'0.00100000000000000000000000000%',
    b'0.00100000000000000000000000000x%', b'1.0000000000000000000000000000x%', b'1.00000000000000000000000000004xyz%', b'1.0000000000000000000000000000_5%',
    b'1.0000000000000000000000000000_%', b'0.0000000000000000000000000000%', b'0.00000000000000000000000000000%', b'-0.0000000000000000000000000001%', b'-0.00000000000000000000000000001%',
    b'0.0000000000000000000000000005%', b'0.00000000000000000000000000005%', b'79228162514264337593543950335%', b'79228162514264337593543950336%', b'7.9228162514264337593543950335%', b'7.9228162514264337593543950336%',
    b'0.79228162514264337593543950335%', b'0.79228162514264337593543950336%', b'0.123456789012345678901234567890%', b'0.' + b'0' * 28 + b'1%', b'1' + b'0' * 97 + b'%', b'0' * 99 + b'%', b'0' * 98 + b'1%',
    b'1e-310%', b'4.9e-324%', b'-1e-320%', b'2.2e-308%', b'123456.789e0%', b'1234567890.125e0%', b'99999999999.999e0%', b'1234567890123.125e0%',
    b'12345678901234.5e0%', b'0.1234567890123e3%', b'1.7976931348623157e308%', b'3.5e15%', b'-5e-1%', b'-0.0e5%',
)


def text_vectors():
    out = [dict(type='text', group='curated', text=t) for t in CURATED]
    r = Lcg(94)
    alpha = b'00112359..+-__eE'
    for _ in range(1500):
        n = 1 + r.next() % 10
        out.append(dict(type='text', group='shape', text=bytes(r.pick(alpha) for _ in range(n)) + b'%'))
    for _ in range(500):
        whole = b''.join(bytes((r.pick(b'0123456789'),)) for _ in range(r.next() % 12))
        tail = b''.join(bytes((r.pick(b'0012345'),)) for _ in range(r.next() % 6))
        out.append(dict(type='text', group='digits', text=whole + b'.' + tail + b'%'))
    for _ in range(500):
        k = r.next() % 100000
        e = r.pick((-8, -6, -5, -4, -3, -2, -1, 0, 1, 2, 3))
        out.append(dict(type='text', group='exponent', text=b'%d.%03de%d%%' % (k // 1000, k % 1000, e)))
    for _ in range(300):
        n = 26 + r.next() % 8
        body = bytes(r.pick(b'0000123459') for _ in range(n))
        cut = r.next() % 3
        tail = bytes(r.pick(b'0123456789_x') for _ in range(r.next() % 4))
        out.append(dict(type='text', group='long', text=bytes((0x30 + cut,)) + b'.' + body + tail + b'%'))
    return out


def seq(group, steps, **kw):
    return dict(type='sequence', group=group, steps=steps, **kw)


def u(user, builder, text, value=MIN_VALUE):
    return dict(kind='user', user=addr(user), builder=addr(builder), text=text, value=value)


def s(user, builder, fee, value=MIN_VALUE):
    return dict(kind='system', user=addr(user), builder=addr(builder), fee=fee, value=value)


def sequence_vectors():
    out = []
    for value in (-(1 << 63), -1, 0, 1, MIN_VALUE - 1, MIN_VALUE, MIN_VALUE + 1, (1 << 63) - 1):
        val = value & U64
        out.append(seq('gate', [u(1, 2, b'1%', _v(value)), s(1, 3, 1, _v(value)), u(1, 2, b'0%', _v(value)), s(1, 3, 0, _v(value))]))
    fill = [s(1, 10 + i, 1 + i) for i in range(MAX_BUILDERS)]
    out.append(seq('cap', fill + [s(1, 40, 7), s(1, 10, 9), u(1, 10, b'2%'), s(1, 10, 0), s(1, 40, 7), s(1, 41, 8), u(1, 40, b'0%'), u(1, 40, b'0%'), s(1, 40, 3)]))
    out.append(seq('cap', fill + [s(2, 40, 7), u(2, 40, b'-0%'), u(2, 41, b'0.5%'), s(1, 41, 0), s(1, 41, 5)]))
    out.append(seq('cap', fill[:10] + [s(1, 10, 99), s(1, 40, 1), s(1, 41, 1)]))
    out.append(seq('cap', [s(1, 20 - i, 1 + i) for i in range(MAX_BUILDERS)] + [s(1, 20, 0), s(1, 30, 1)]))
    for fee in (SYSTEM_LIMIT - 1, SYSTEM_LIMIT, SYSTEM_LIMIT + 1, U64, 1 << 63):
        out.append(seq('limit', [s(1, 2, fee), s(1, 2, fee, MIN_VALUE - 1)]))
    out.append(seq('text', [u(1, 2, b'0' * 99 + b'%', 0), u(1, 2, b'0' * 98 + b'1%'), u(1, 2, b'0' * 99 + b'1%'), u(1, 2, b'0' * 100 + b'1%', 0), u(1, 3, b'x' * 200),
                            u(1, 2, b'abc%', 0), u(1, 2, b'1', 0), u(1, 2, b'1%', 0), u(1, 2, b'9223372036854775.806%'), u(1, 3, b'9223372036854775.807%')]))
    out.append(seq('no-dex', [u(1, 2, b'0%', 0)], dex=False))
    out.append(seq('no-dex', [s(1, 2, 0, 0)], dex=False))
    out.append(seq('no-dex', [s(1, 2, SYSTEM_LIMIT, 0)], dex=False))
    out.append(seq('no-dex', [u(1, 2, b'bad%', 0)], dex=False))
    out.append(seq('no-dex', [u(1, 2, b'1%', MIN_VALUE)], dex=False))
    out.append(seq('no-dex', [s(1, 2, 1, 0)], dex=False))
    r = Lcg(1994)
    texts = (b'1%', b'0%', b'0.1%', b'-0%', b'+2%', b'1e-1%', b'0.0001%', b'x%', b'3')
    for i in range(80):
        steps = []
        for _ in range(4 + r.next() % 16):
            who, b = 1 + r.next() % 3, 10 + r.next() % 14
            value = r.pick((MIN_VALUE, MIN_VALUE, MIN_VALUE + 5, MIN_VALUE - 1, 0))
            steps.append(u(who, b, r.pick(texts), value) if r.next() % 2 else s(who, b, r.pick((0, 0, 1, 5, 1000, SYSTEM_LIMIT - 1, SYSTEM_LIMIT)), value))
        out.append(seq('random', steps, decoys=(addr(1000 + i), addr(1), addr(5000 + i)) if i % 3 == 0 else ()))
    return out


def _v(value):
    return value & U64


def copy_vectors():
    return [dict(type='copy', group='copy', name=n, fn=f, callee=c, tag=t, shift=sh) for n, f, c, t, sh in COPY_CASES]


def all_vectors():
    return copy_vectors() + sequence_vectors() + text_vectors()


# ---- mutation survey


SUBNORMAL = 'every subnormal f64 scales to mantissa 0 at 28 places, so this path and the zero path give the same Decimal'
ZERO_FLAGS = 'flag word of a zero Decimal: the mantissa stays 0 through the scale, so the result is 0 either way'
EQUIVALENT = {
    0x37995eb: SUBNORMAL, 0x37995f1: SUBNORMAL, 0x37995f5: SUBNORMAL, 0x37995ed: SUBNORMAL, 0x37995f9: SUBNORMAL, 0x3799601: SUBNORMAL,
    0x3799643: ZERO_FLAGS, 0x379963c: ZERO_FLAGS, 0x3799640: ZERO_FLAGS,
    0x3799691: 'dead store: nothing reads this stack copy after the drop, the same value goes to the output on the next line',
    0x379958a: 'clears bit 0 of the compare only: the parser returns no NaN whose payload is that bit alone',
    0x3799597: 'the bound moves past inf, then inf reaches 0x4eac740 with exponent 972, which refuses it with the same status',
    0x37995b1: 'only the word above bit 32 of this mask is used, and the low byte is below it',
    0x37996a5: 'the bound moves to tag 5, which this text parser does not return',
    0x27583f7: 'taking the error copy keeps tag 0x186 in the output, and callers read only that tag',
}
UNEXECUTED = (
    (0x37996d8, 0x3799703, 'unwind landing pad of the f64 path: needs a panic inside the Decimal conversion'),
    (0x275847d, 0x275849a, 'ud2 after the unwrap panic, unwind landing pad and the trap after it'),
)
SWAPS = {}
SKIP_IMM = ()


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
    packed = struct.pack('<b', disp) if -128 <= disp < 128 else struct.pack('<i', disp)
    tail = 0
    imm = [o for o in ins.ops if o[0] == 'i']
    if imm:
        tail = imm_size(ins, imm[0])
    at = len(raw) - tail - len(packed)
    return at if raw[at:at + len(packed)] == packed else None


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
        n = imm_size(ins, imm[0])
        if not n:
            continue
        out.append(dict(kind='immediate', fn=fn, va=ins.va, op=show(ins), patch={ins.va + ins.size - n: ins.raw[-n] ^ 1}))
    return out


def sample(vecs):
    """The survey set: every state vector, about 40 of each text group, chosen by a hash of the index."""
    kept, count = [], {}
    for v in vecs:
        count[v['group']] = count.get(v['group'], 0) + 1
    for i, v in enumerate(vecs):
        if v['type'] != 'text' or v['group'] == 'curated' or hashlib.sha256(str(i).encode()).digest()[0] * count[v['group']] < 256 * 40:
            kept.append(v)
    return kept


def try_kill(mimg, mcode, slots, got, picked):
    for pos, v in enumerate(picked):
        try:
            bad = check(mimg, mcode, slots, got, v)
        except (Unmodelled, Panicked, EvidenceError, KeyError, OverflowError, ValueError, TypeError, struct.error, IndexError) as exc:
            bad = f'fault {type(exc).__name__}'
        if bad:
            picked.insert(0, picked.pop(pos))
            return (v['group'], bad[:60])
    return None


def all_sites(listing):
    sites = []
    for fn in SUBJECTS:
        sites += conditional_sites(fn, listing[fn]) + field_sites(fn, listing[fn]) + imm_sites(fn, listing[fn])
    return [x for x in sites if not any(a <= x['va'] < b for a, b, _ in UNEXECUTED)]


def survey_part(args):
    data, code, slots, got, sites, vecs, everything = args
    picked = sample(vecs) if not everything else list(vecs)
    rows = []
    for s_ in sites:
        mimg = Image(data, s_['patch'])
        mcode = dict(code)
        try:
            mcode.update({i.va: i for i in decode_range(mimg, s_['fn'], FDE_END[s_['fn']])})
        except EvidenceError as exc:
            rows.append(dict(s_, killed=('decoder', str(exc)[:60])))
            continue
        killed = try_kill(mimg, mcode, slots, got, picked)
        if killed is None and s_['va'] not in EQUIVALENT:
            killed = try_kill(mimg, mcode, slots, got, list(vecs))
        rows.append(dict(s_, killed=killed))
    return rows


WORKERS = 4


def survey(data, code, slots, got, listing, vecs):
    sites = all_sites(listing)
    parts = [sites[i::WORKERS] for i in range(WORKERS)]
    jobs = [(data, code, slots, got, p, vecs, False) for p in parts]
    with multiprocessing.get_context('fork').Pool(WORKERS) as pool:
        got_rows = pool.map(survey_part, jobs)
    rows = [r for part in got_rows for r in part]
    rows.sort(key=lambda r: (SUBJECTS.index(r['fn']), r['va'], r['kind']))
    return rows


# ---- static facts


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
        return None
    return img.read(at, size).decode('utf8', 'replace')


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


def pinned(img):
    out = []
    for va, raw, meaning in PINNED:
        got = img.read(va, len(raw) // 2).hex()
        if got != raw:
            raise EvidenceError(f'bytes at {va:#x} are {got}, not {raw}')
        out.append(dict(va=hex(va), bytes=raw, meaning=meaning))
    return out


def body_of(img, fdes, start):
    end = fdes.range_of(start)['end']
    listing = decode_range(img, start, end)

    def text(ins):
        return ins.op, tuple(('t', o[1] - start) if o[0] == 't' and start <= o[1] < end else o for o in ins.ops)
    return listing, [text(i) for i in listing]


def copy_rows(img, fdes, first, copies):
    """Other copies, instruction by instruction, after rip targets are made absolute."""
    base, base_text = body_of(img, fdes, first)
    out = []
    for copy in copies:
        other, other_text = body_of(img, fdes, copy)
        if len(other) != len(base):
            raise EvidenceError(f'{copy:#x} has {len(other)} instructions, not {len(base)}')
        rows = []
        for a, b, ta, tb in zip(base, other, base_text, other_text):
            if ta != tb:
                if a.op != b.op:
                    raise EvidenceError(f'{a.va:#x} and {b.va:#x} are different instructions')
                rows.append(dict(va=hex(b.va), first=show(a), here=show(b)))
        out.append(dict(start=hex(copy), of=hex(first), instructions=len(other), differs=rows))
    return out


def path_of(text):
    """Which path takes the text in the model."""
    if len(text) and text[-1] == 0x25 and decimal_text(text[:-1]) is not None:
        return 'decimal'
    return 'float' if len(text) and text[-1] == 0x25 and float_shape(text[:-1]) else 'none'


def reference_rows(vecs):
    """Count where the reference text rule and the bytes disagree, split by what the text holds."""
    rows = {}
    for v in vecs:
        if v['type'] != 'text':
            continue
        t = v['text']
        status, millis = parse_model(t)
        ref = reference_parse(t)
        got = millis if status == OK else None
        if got == ref:
            continue
        body = t[:-1]
        if 0x5f in body:
            kind = 'underscore'
        elif body[:1] == b'+':
            kind = 'plus sign'
        elif body[:1] == b'-':
            kind = 'minus sign with zero value'
        elif b'e' in body or b'E' in body:
            kind = 'exponent'
        elif len(body.partition(b'.')[2]) > 28:
            kind = 'more than 28 places, f64 fallback'
        elif len(body.partition(b'.')[2]) > 3:
            kind = 'more than 3 places with zero tail'
        else:
            kind = 'other'
        row = rows.setdefault(kind, dict(count=0, first=t.decode('ascii', 'replace'), bytes=got, reference=ref))
        row['count'] += 1
    return rows


def digest_of(v):
    return hashlib.sha256(repr(sorted((k, repr(x)) for k, x in v.items())).encode()).hexdigest()[:16]


REFERENCE_ROWS = (
    ('differs', 'MIN_SIGNED_ACCOUNT_VALUE_EXCLUSIVE_RAW doc', "the caller's aggregate margin summary", 'the gate looks up the builder address: rsi of 0x36f57f0 is a copy of the rcx argument, the row of the user comes later in 0x37459e0 from rdx'),
    ('differs', 'parse_unsigned_decimal_millis', 'no plus sign, no underscore, no exponent, at most 3 places', 'Decimal text first, then f64 text, then an exact scale by 10^3; see text-rule rows in evidence.json'),
    ('differs', 'apply_approve_builder_fee_raw order', 'no failure when the first dex is missing', 'a non-zero fee panics (Result::unwrap on status 0x141) when exchange +0x5c8 is 0'),
    ('differs', '54 summary doc', 'aggregate_position_margin_summary(..., false, true)', 'edx = 1 and ecx = 1 at 0x27583c1 (the file 70 text says true, true)'),
    ('same', 'STATUS_ACCOUNT_VALUE_TOO_SMALL and limit', '295 when value <= 99999999', 'tag 0x127, signed compare at 0x27583ca'),
    ('same', 'MAX_TRACKED_BUILDER_FEES_BEFORE_INSERT', 'reject when the count is above 10', 'tag 0x12b at 0x3745a0a, an overwrite of a known builder is refused too'),
    ('same', 'system raw limit', 'reject 0x0ccccccccccccccc and above with 319', 'tag 0x13f at 0x1e64647, before the gate, carries the fee'),
    ('same', 'length limit', 'reject 101 bytes and more', 'tag 0x143, but in 0x1e60aa8 and not in the parser; word = action pointer'),
    ('same', 'status 298', 'invalid fee rate', 'tag 0x12a for every parser failure'),
)


def generate(data, out_dir, with_survey=True):
    img, code, fdes, slots, got = build(data)
    listing = {s_: decode_range(img, s_, FDE_END[s_]) for s_ in DECODED}
    vecs = all_vectors()
    seen = set()
    for v in vecs:
        real_run = Machine.run

        def run(self, entry, limit=400000):
            try:
                return real_run(self, entry, limit)
            finally:
                seen.update(self.seen)
        Machine.run = run
        try:
            try:
                msg = check(img, code, slots, got, v)
            finally:
                Machine.run = real_run
        except (Unmodelled, Panicked, EvidenceError, KeyError) as exc:
            msg = f'fault {type(exc).__name__} {exc}'
        if msg:
            raise EvidenceError(f"mismatch in {v['group']}: {v.get('text', v.get('name', ''))}: {msg}")
    missing, padding = [], 0
    for fn in SUBJECTS:
        for ins in listing[fn]:
            if ins.va in seen:
                continue
            if ins.op == 'nop':
                padding += 1
            elif not any(a <= ins.va < b for a, b, _ in UNEXECUTED):
                missing.append(hex(ins.va))
    if missing:
        raise EvidenceError(f'unlisted unexecuted instructions {len(missing)}: {missing[:60]}')
    rows = survey(data, code, slots, got, listing, vecs) if with_survey else []
    survivors = {r['va'] for r in rows if not r['killed']}
    if survivors - set(EQUIVALENT) or (rows and set(EQUIVALENT) - survivors):
        raise EvidenceError(f'survivors {sorted(hex(s_) for s_ in survivors ^ set(EQUIVALENT))}')
    starts = sorted(f['start'] for f in eh_frame_records(data)[1])
    out_path = Path(out_dir)
    out_path.mkdir(parents=True, exist_ok=True)
    groups, outcomes, paths = {}, {}, {}
    with open(out_path / 'vectors.tsv', 'w', newline='\n') as f:
        f.write('group\ttype\tinput\tstatus\tmillis\tpath\treference_millis\n')
        for v in vecs:
            groups[v['group']] = groups.get(v['group'], 0) + 1
            if v['type'] == 'text':
                status, millis = parse_model(v['text'])
                name = hex(status)
                outcomes[name] = outcomes.get(name, 0) + 1
                path = path_of(v['text'])
                paths[path] = paths.get(path, 0) + 1
                ref = reference_parse(v['text'])
                cells = [v['group'], 'text', v['text'].hex(), name, '' if millis is None else str(millis), path, '' if ref is None else str(ref)]
            else:
                cells = [v['group'], v['type'], digest_of(v), '', '', '', '']
            f.write('\t'.join(cells) + '\n')
    with open(out_path / 'mutations.tsv', 'w', newline='\n') as f:
        f.write('kind\tfunction\tva\tinstruction\tresult\tvector\treason\n')
        for r in rows:
            k = r['killed']
            f.write(f"{r['kind']}\t{r['fn']:#x}\t{r['va']:#x}\t{r['op']}\t{'killed' if k else 'equivalent'}\t{k[0] if k else ''}\t{k[1] if k else EQUIVALENT[r['va']]}\n")
    with open(out_path / 'instructions.tsv', 'w', newline='\n') as f:
        f.write('function\tva\tsize\tbytes\tdecoded\texecuted\n')
        for fn in SUBJECTS:
            for i in listing[fn]:
                f.write(f'{fn:#x}\t{i.va:#x}\t{i.size}\t{i.raw.hex()}\t{show(i)}\t{int(i.va in seen)}\n')
    with open(out_path / 'reference-diff.tsv', 'w', newline='\n') as f:
        f.write('verdict\treference\treference_says\tbytes_say\n')
        for row in REFERENCE_ROWS:
            f.write('\t'.join(row) + '\n')
    per, helper_total, helper_seen = {}, 0, 0
    for fn in DECODED:
        ex = sum(i.va in seen for i in listing[fn])
        if fn in SUBJECTS:
            per[hex(fn)] = dict(end=hex(FDE_END[fn]), fde=hex(fdes.range_of(fn)['fde']), instructions=len(listing[fn]), executed=ex)
        else:
            helper_total += len(listing[fn])
            helper_seen += ex
    examples = []
    for t in (b'1%', b'+1%', b'-0%', b'1_0%', b'.5%', b'5.%', b'0.0010%', b'0.0001%', b'1e-3%', b'1E2%', b'0.1e-2%', b'0.29e-2%', b'1.00000000000000000000000000049%', b'9223372036854775.806%', b'9223372036854775.807%', b'inf%', b'-1%'):
        status, millis = run_text(img, code, slots, got, t)
        examples.append(dict(text=t.decode(), status=hex(status), millis=millis, path=path_of(t), reference=reference_parse(t)))
    evidence = dict(
        binary=BINARY, sha256=SHA256, functions=per, subjects=[hex(s_) for s_ in SUBJECTS], helpers=dict(functions=len(HELPERS) + 1, instructions=helper_total, executed=helper_seen),
        stubs=dict(book=hex(BOOK), summary=hex(SUMMARY), hash=hex(HASH), reserve=hex(RESERVE), drop_error=hex(DROP_ERROR), drop_failure=hex(DROP_FAIL), malloc=hex(MALLOC), free=hex(FREE)),
        gate_callers=direct_sites(img, GATE, starts), parser_callers=slot_sites(img, PARSER_SLOT, starts), writer_callers=slot_sites(img, WRITER_SLOT, starts),
        slots={hex(k): hex(img.relative(k)) for k in (PARSER_SLOT, WRAP_SLOT, SCALE_SLOT, SUMMARY_SLOT, WRITER_SLOT, FROM_STR_SLOT, FLOAT_SLOT)},
        status_text={hex(t): status_text(img, t) for t in (TOO_SMALL, BAD_RATE, TOO_MANY, FEE_LIMIT, NO_DEX, TOO_LONG, SCALE_ERROR, PARSE_ERROR)},
        copies=copy_rows(img, fdes, GATE, GATE_COPIES) + copy_rows(img, fdes, ENTRY_USER, ENTRY_COPIES) + copy_rows(img, fdes, ENTRY_SYSTEM, SYSTEM_COPIES),
        gate_copy_callers={hex(c): direct_sites(img, c, starts) for c in GATE_COPIES}, pinned=pinned(img), vectors=len(vecs), mismatches=0, groups=groups, text_outcomes=outcomes, text_paths=paths, examples=examples, text_rule_rows=reference_rows(vecs),
        padding_not_executed=padding, unexecuted=[dict(start=hex(a), end=hex(b), why=w) for a, b, w in UNEXECUTED], mutants=len(rows), killed=sum(1 for r in rows if r['killed']),
        survey_vectors=len(sample(vecs)), equivalent={hex(k): w for k, w in sorted(EQUIVALENT.items())}, copy_cases=[c[0] for c in COPY_CASES],
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
