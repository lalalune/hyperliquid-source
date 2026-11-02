#!/usr/bin/env python3
"""fees: node #94 request budget, from bytes alone.

Static, no execution of the node.  The handler 0x2758ae0 of reserveRequestWeight and its copies 0x4d82190,
0x4d82320, the view 0x21e2910 with its volume sum 0x275f500 and row lookup 0x2755580, the weight function
0x33632e0 with 0x3a1b6c0, and the row get-or-insert pieces 0x1f849b0, 0x27c3c90, 0x47d7ca0 are decoded from ELF
bytes by the table decoder below, which must land exactly on each FDE end, and interpreted in Python on every
vector.  Three counter writers inside larger functions (0x2208580, 0x27584a0, 0x24bcae0) are decoded and run as
listed address ranges only.  Hashes, byte compare, the once call, balance, debit, credit and drop helpers are
stubs that check their arguments.  Each outcome is compared with a separate closed-form model, then every
conditional, field offset and immediate of the subjects is mutated to test the vectors.

    python3 tools/fees_request_budget.py --out <dir>

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

HANDLER = 0x2758ae0
COPY_A = 0x4d82190
COPY_B = 0x4d82320
VIEW = 0x21e2910
SUM = 0x275f500
WEIGHT = 0x33632e0
NESTED = 0x3a1b6c0
ROW_GET = 0x1f849b0
ROW_FIND = 0x27c3c90
ROW_GET_B = 0x47d7ca0
LOOKUP = 0x2755580
CHRONO = 0x151f6f0
FRAG_ENTRY = 0x2208580
FRAG_INNER = 0x27584a0
FRAG_BATCH = 0x24bcae0
WRAPPER = 0x27d0780
WHOLE = (HANDLER, COPY_A, COPY_B, VIEW, SUM, WEIGHT, NESTED, ROW_GET, ROW_FIND, ROW_GET_B, LOOKUP)
HELPERS = (CHRONO,)
FRAGMENTS = {
    FRAG_ENTRY: ((0x220863e, 0x2208778), (0x220880b, 0x2208879), (0x2208dd2, 0x2208dde)),
    FRAG_INNER: ((0x2758577, 0x27585fc), (0x275864d, 0x2758655), (0x27587d5, 0x27587e1)),
    FRAG_BATCH: ((0x24bccc3, 0x24bce05), (0x24bcf8d, 0x24bcf99)),
}
CLOCK_ENTRY = 0x22086f9
CLOCK_BATCH = 0x24bcd62
STOPS = {0x2208773: 'expired', 0x2208871: 'charged', 0x27585f4: 'charged', 0x275864d: 'other',
         0x24bcdf0: 'expired', 0x24bce00: 'other'}
ENTRY_AT = {FRAG_ENTRY: 0x220863e, FRAG_INNER: 0x2758577, FRAG_BATCH: 0x24bccc3}
HASH_ROW = 0x2840fb0
HASH_ROW_B = 0x473bf50
DROP = 0x3379490
DROP_B = 0x277eba0
DROP_C = 0x4daf4a0
BALANCE = 0x36f7560
DEBIT = 0x370a3d0
CREDIT = 0x37067b0
DEX_ROW = 0x36f57f0
BASE_ROW = 0x371b3a0
RECORDER = 0x358dcd0
GROW = 0x357a0f0
UNWRAP = 0x157aa10
GOT_MEMCMP = 0x576e488
GOT_ONCE = 0x576e8b8
SLOT_BALANCE = 0x5774660
SLOT_DEBIT = 0x57749d8
SLOT_CREDIT = 0x5774918
SLOT_WEIGHT = 0x57739c0
SLOT_NESTED = 0x5775c68
SLOT_ROW_CELL = 0x57749b8
SLOT_TREE_CELL = 0x5773960
ROW_CELL = 0x5786190
TREE_CELL = 0x5786388
WEIGHT_TABLE = 0x5896dc
WEIGHT_FIRST = 0x74
STATUS_TABLE = 0x59a8d0
STATUS_TEXT = {0x13f: (0x59e415, 0x14), 0x34: (0x59c8ea, 0x2f), 0xca: (0x59d798, 0x16)}
ALLOWED_RECORDS = (0x5715e68, 0x56eb3e8, 0x56eb430)
OK = 0x186
LIMIT_LOW = 0x34
LIMIT_COST = 0x13f
EXPIRED = 0xca
UNIT_COST = 500
COST_CAP = 0xccccccccccccccc
EPOCH_DAYS = 719163
EPOCH_FLAGS = 0xa
ROW_STRIDE = 0x58
ROW_VALUE = 0x18
USED = 8
RESERVED = 0x28
STAMP = 0x30
NOW = 0x60
ROOT_F = 0x4450
LEN_F = 0x246
KEYS_F = 0x168
EDGES_F = 0x248
DEX_STRIDE = 0x2f0
STACK_FILL = bytes((i * 5 + 3) & 0xff | 1 for i in range(0x8000))
TOP = 0x7f08
FRAME = 0x4000
SHAPES = {
    HANDLER: dict(list=0x5c0, credit=0x5d0, rows=0x740, hash=HASH_ROW, drop=DROP_B),
    COPY_A: dict(list=0x1040, credit=0x1050, rows=0x11c0, hash=HASH_ROW_B, drop=DROP_C),
    COPY_B: dict(list=0x5c0, credit=0x5d0, rows=0x740, hash=HASH_ROW_B, drop=DROP_C),
}
PINNED = (
    (0x2758b23, 'b9 f4 01 00 00', 'unit cost 500'),
    (0x2758b48, '48 b8 cc cc cc cc cc cc cc 0c', 'cost cap immediate'),
    (0x21e2ab8, '48 b9 c3 f5 28 5c 8f c2 f5 28', 'reciprocal of 100 in the cap'),
    (0x21e2ac9, '48 81 c2 10 27 00 00', 'cap base 10000'),
    (0x27d085b, 'e8 b0 20 a1 ff', 'the wrapper calls the view'),
    (0x27d0972, 'f2 0f 5e 1d e6 9f a3 fd', 'cumVlm f64 = scaled / 100.0 (constant at 0x20a960)'),
    (0x22086d8, '48 69 f6 80 51 01 00', 'seconds a day in the expiry test'),
    (0x220871d, 'b9 05 00 00 00', 'expired action: weight times 5'),
    (0x27585ab, '49 c1 e4 02', 'inner expired result: weight times 4'),
    (0x24bcd92, '49 c1 e6 02', 'batch expired row: weight times 4'),
    (0x34d71a4, 'bf 3b f9 0a 00', 'row default cell: date from day 719163, the other words 0'),
    (0x3790ee4, 'bf 3b f9 0a 00', 'tree default cell: same date, the other words 0'),
)
SEEN = None


class Panicked(Exception):
    """The node would panic here; a modelled outcome, unlike Unmodelled."""


class Stop(Exception):
    """A fragment reached a listed end address."""

    def __init__(self, va):
        Exception.__init__(self, hex(va))
        self.va = va


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


def sat(x):
    return min(x, U64)


def sum_model(v):
    """(scaled, raw, overflow records): dex rows in order, then the base row, each add saturating."""
    a, b, hooks = 0, 0, 0
    for s, r in list(v['dexes']) + [v['base']]:
        hooks += (a + s > U64) + (b + r > U64)
        a, b = sat(a + s), sat(b + r)
    return a, b, hooks


def stamp_key(t):
    return (signed(t['date'] & 0xffffffff, 32), t['secs'], t['frac'])


def view_model(v):
    scaled = sum_model(v)[0]
    row = v['row_cell'] if v.get('items') == 0 else v['rows'].get(v['user'], v['row_cell'])
    used, reserved = row['t'], row['r']
    tree = v['tree'] or {}
    other = tree.get(v['user'], v['tree_cell'])
    # the tree time wins a tie, and the two are then the same bytes
    best = row['time'] if stamp_key(other) < stamp_key(row['time']) else other
    return dict(scaled=scaled, used=max(used - reserved, 0), cap=scaled // 100 + 10000,
                surplus=max(reserved - used, 0), time=best)


def weight_model(a):
    tag = a['tag']
    if tag in (0x76, 0x77, 0x78):
        return max(a['f18'], 1)
    if tag == 0x82:
        return max(a['f40'], 1)
    if tag == 0x8b:
        return a['f18'] // 20 + 1
    if tag == 0xa8:
        return sat(weight_model(a['inner']) * max(a['f18'], 1))
    if tag == 0xb8:
        return a['f20'] // 20 + 1 if a['b8'] == 2 else 1
    return 1


def handler_model(v):
    """(status, payload or None, row delta applies, drops)."""
    cost = v['weight'] * UNIT_COST
    if not v['list']:
        return dict(panic=True)
    if cost > U64:
        return dict(status=LIMIT_COST, payload=None, charge=None, drops=[0x141])
    if cost >= COST_CAP:
        return dict(status=LIMIT_COST, payload=cost, charge=None, drops=[0x141, 0x13f])
    if v['balance'] < cost:
        return dict(status=LIMIT_LOW, payload=None, charge=None, drops=[0x141, 0x13f, 0x33])
    return dict(status=OK, payload=None, charge=cost, drops=[0x141, 0x13f])


def days_from_epoch(year, ordinal):
    y = year - 1
    return 365 * y + y // 4 - y // 100 + y // 400 + ordinal - EPOCH_DAYS


def raw_ms(t):
    """Milliseconds of a packed date, seconds, nanoseconds triple."""
    word_ = signed(t['date'] & 0xffffffff, 32)
    return (days_from_epoch(word_ >> 13, (word_ >> 4) & 0x1ff) * 86400 + t['secs']) * 1000 + t['frac'] // 1000000


def now_ms(t):
    return max(raw_ms(t), 0)


def date_word(year, ordinal, flags=EPOCH_FLAGS):
    return ((year << 13) | (ordinal << 4) | flags) & 0xffffffff


FRESH_TIME = dict(date=date_word(1970, 1), secs=0, frac=0)


def entry_model(v):
    """Charge of the entry gate of 0x2208580: (stop, weight added to the used count)."""
    w = weight_model(v['action'])
    if v['option'] == 1 and v['expires'] < now_ms(v['now']):
        return 'expired', sat(w * 5)
    return 'charged', w


def inner_model(v):
    w = weight_model(v['action'])
    if v['first'] == 0xf and v['inner_tag'] == EXPIRED:
        return 'charged', sat(w * 4)
    return 'other', None


def batch_model(v):
    w = weight_model(v['action'])
    if v['flag'] & 1 and v['expires'] < now_ms(v['now']):
        return 'expired', sat(w * 4)
    return 'other', None


# ---- state writers


def free_slot(ctrl, mask, h):
    """Insert position by the rules of the table, from the control bytes alone."""
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


def set_ctrl(ctrl, mask, i, val):
    ctrl[i] = val
    ctrl[((i - 16) & mask) + 16] = val


def write_table(m, owner, field, keys, spec, seed):
    """A hash table of 20-byte keys: control, mask, room, items, then the hash state at +0x20."""
    size = spec.get('size', 16)
    mask = size - 1
    stride = ROW_STRIDE
    a = m.arena(stride * size + size + 32)
    a.mem[:] = fill_bytes(len(a.mem), seed)
    a.valid[:] = b'\1' * len(a.mem)
    ctrl_off = stride * size + 16
    ctrl = [0xff] * (size + 16)
    places = {}
    for k, h2 in spec.get('decoys', ()):
        i = k & mask
        if ctrl[i] == 0xff:
            set_ctrl(ctrl, mask, i, h2)
            at = ctrl_off - (i + 1) * stride
            a.mem[at:at + 20] = bytes((j * 7 + k) & 0xff for j in range(20))
    for key in keys:
        h = key_hash(key)
        slot = free_slot(ctrl, mask, h)
        set_ctrl(ctrl, mask, slot, h >> 57)
        at = ctrl_off - (slot + 1) * stride
        a.mem[at:at + 20] = key
        places[key] = at
    for i in spec.get('deleted', ()):
        if ctrl[i & mask] == 0xff:
            set_ctrl(ctrl, mask, i & mask, 0x80)
    a.mem[ctrl_off:ctrl_off + size + 16] = bytes(ctrl)
    word(owner, field, 8, a.base + ctrl_off)
    word(owner, field + 8, 8, mask)
    word(owner, field + 0x10, 8, spec.get('room', 3))
    word(owner, field + 0x18, 8, len(keys))
    return a, places, ctrl, ctrl_off, mask


def write_stamp(a, at, t):
    word(a, at, 4, t['date'])
    word(a, at + 4, 4, t['secs'])
    word(a, at + 8, 4, t['frac'])


def write_rows(m, ex, field, v):
    keys = sorted(v['rows'])
    tab = write_table(m, ex, field, keys, v.get('table', {}), 0x17)
    for key in keys:
        at = tab[1][key] + ROW_VALUE
        row = v['rows'][key]
        word(tab[0], at + USED, 8, row['t'])
        word(tab[0], at + RESERVED, 8, row['r'])
        write_stamp(tab[0], at + STAMP, row['time'])
    return tab


def after_rows(tab, ex, field, v, room, user, change):
    """The row table bytes and the owner words a correct run leaves.  `change(row bytes)` edits one row value."""
    a, places, ctrl, ctrl_off, mask = tab
    want = bytearray(room['snap'])
    owner = bytearray(room['owner'])
    pad = None
    if user in places:
        at = places[user] + ROW_VALUE
    else:
        h = key_hash(user)
        slot = free_slot(ctrl, mask, h)
        was = ctrl[slot]
        c2 = list(ctrl)
        set_ctrl(c2, mask, slot, h >> 57)
        want[ctrl_off:ctrl_off + mask + 1 + 16] = bytes(c2)
        base = ctrl_off - (slot + 1) * ROW_STRIDE
        want[base:base + 20] = user
        at = base + ROW_VALUE
        want[at:at + 0x3e] = bytes(0x3e)
        want[at + STAMP:at + STAMP + 4] = FRESH_TIME['date'].to_bytes(4, 'little')
        pad = base + 20
        before = int.from_bytes(owner[field + 0x10:field + 0x18], 'little')
        if before == 0:
            before = GROWN_ROOM
        owner[field + 0x10:field + 0x18] = (before - (was & 1)).to_bytes(8, 'little')
        items = int.from_bytes(owner[field + 0x18:field + 0x20], 'little') + 1
        owner[field + 0x18:field + 0x20] = items.to_bytes(8, 'little')
    change(want, at)
    return want, owner, pad


GROWN_ROOM = 2


def machine(ctx):
    img, code, slots, got = ctx
    m = Machine(img, ())
    if SEEN is not None:
        m.seen = SEEN
    m.code = code
    m.slots = slots
    m.got = got
    for fn in WHOLE + HELPERS:
        m.real[fn] = fn
    stack = m.arena(0x8000, strict=False)
    stack.mem[:] = STACK_FILL
    m.stack = stack
    m.top = stack.base + TOP
    m.log = []
    m.drops = []
    m.hooked = 0
    m.once = 0
    m.user = None
    m.rows_at = None

    def key_at(at):
        return bytes(m.load(at + k, 1) for k in range(20))

    def memcmp():
        r = m.regs
        if r[R['rdx']] != 20:
            raise Unmodelled('compare length')
        left, right = key_at(r[R['rdi']]), key_at(r[R['rsi']])
        m.clobber(0 if left == right else 1 if left > right else 0xffffffff)

    def hash_row():
        r = m.regs
        if r[R['rdi']] != m.rows_at + 0x20:
            raise Unmodelled('row hash state')
        key = key_at(r[R['rsi']])
        if key != m.user:
            raise Unmodelled('row hash key')
        m.clobber(key_hash(key))

    def once():
        r = m.regs
        want = {ROW_CELL + 0x40: (ROW_CELL, 0x56bdfb8), TREE_CELL + 0x20: (TREE_CELL, 0x56bdff8)}.get(r[R['rdi']])
        if r[R['rsi']] != 1 or want is None or (r[R['rcx']], r[R['r8']]) != (want[1], 0x56bdfe0):
            raise Unmodelled('once arguments')
        if m.load(m.load(r[R['rdx']], 8), 8) != want[0]:
            raise Unmodelled('once closure')
        m.once += 1
        m.store(r[R['rdi']], 4, 0)
        m.clobber()

    def drop(which):
        def run_drop():
            if which != DROP and which != m.shape_drop:
                raise Unmodelled('drop helper')
            if (which == DROP) != (m.load(m.regs[R['rdi']], 2) == 0x141):
                raise Unmodelled('drop helper for this tag')
            m.drops.append(m.load(m.regs[R['rdi']], 2))
            m.clobber()
        return run_drop

    def unwrap():
        if m.regs[R['rsi']] != 0x2b or m.load(m.regs[R['rdx']], 2) != 0x141:
            raise Unmodelled('unwrap message')
        raise Panicked('unwrap')

    def recorder():
        if m.regs[R['rdi']] != 0 or m.regs[R['rsi']] not in ALLOWED_RECORDS:
            raise Unmodelled('record')
        m.hooked += 1
        m.clobber()

    def grow():
        r = m.regs
        if (r[R['rdi']], r[R['rsi']], r[R['rcx']]) != (m.rows_at, 1, 1) or r[R['rdx']] != m.rows_at + 0x20:
            raise Unmodelled('grow arguments')
        m.store(m.rows_at + 0x10, 8, GROWN_ROOM)
        m.log.append('grow')
        m.clobber()

    m.stubs.update({HASH_ROW: hash_row, HASH_ROW_B: hash_row, DROP: drop(DROP), DROP_B: drop(DROP_B), DROP_C: drop(DROP_C),
                    UNWRAP: unwrap, RECORDER: recorder, GROW: grow,
                    slots.get(GOT_MEMCMP, GOT_MEMCMP): memcmp, slots.get(GOT_ONCE, GOT_ONCE): once})
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


def user_arena(m, user):
    a = m.arena(20)
    a.mem[:] = user
    a.valid[:] = b'\1' * 20
    return a


def check_table(m, tab, ex, field, v, snap, user, change):
    want, owner, pad = after_rows(tab, ex, field, v, snap, user, change)
    got_ = bytearray(tab[0].mem)
    if pad is not None:
        got_[pad:pad + 4] = want[pad:pad + 4]
    if got_ != want:
        return 'row table bytes'
    if bytes(ex.mem) != bytes(owner):
        return 'owner bytes'
    return None


def run_handler(ctx, v):
    m = machine(ctx)
    entry = v['entry']
    shape = SHAPES[entry]
    m.shape_drop = shape['drop']
    user = v['user']
    m.user = user
    ex = filled(m, 0x1300, 0x41)
    tab = write_rows(m, ex, shape['rows'], v)
    m.rows_at = ex.base + shape['rows']
    lst = filled(m, 0x40, 0x29)
    word(ex, shape['list'], 8, lst.base)
    word(ex, shape['list'] + 8, 8, v['list'])
    who = user_arena(m, user)
    out = m.arena(0x40, strict=False)
    out.mem[:] = fill_bytes(0x40, 0x63)
    snap = dict(snap=bytes(tab[0].mem), owner=bytes(ex.mem))
    out0 = bytes(out.mem)

    def key_arg():
        return bytes(m.load(m.regs[R['rsi']] + k, 1) for k in range(20))

    def balance():
        if m.regs[R['rdi']] != lst.base or key_arg() != user:
            raise Unmodelled('balance arguments')
        m.log.append('balance')
        m.clobber(v['balance'])

    def debit():
        if m.regs[R['rdi']] != lst.base or key_arg() != user:
            raise Unmodelled('debit arguments')
        m.log.append(('debit', m.regs[R['rdx']]))
        m.clobber()

    def credit():
        r = m.regs
        if r[R['rdi']] != lst.base or r[R['rsi']] & 0xffffffff != 0 or r[R['rcx']] != ex.base + shape['credit']:
            raise Unmodelled('credit arguments')
        m.log.append(('credit', r[R['rdx']]))
        m.clobber()

    m.stubs.update({BALANCE: balance, DEBIT: debit, CREDIT: credit})
    enter(m, entry, out.base, ex.base, who.base, v['weight'])
    want = handler_model(v)
    if m.regs[0] != out.base:
        return 'result pointer'
    status = read(out.mem, 0, 2)
    if status != want['status']:
        return f'status {status:#x}'
    if bytes(out.mem[2:8]) != out0[2:8]:
        return 'bytes after status'
    if want['payload'] is None:
        if bytes(out.mem[8:]) != out0[8:]:
            return 'payload written'
    elif read(out.mem, 8) != want['payload'] or bytes(out.mem[16:]) != out0[16:]:
        return 'payload'
    if m.drops != want['drops']:
        return 'drops'
    log = [x for x in m.log if x != 'grow']
    if want['charge'] is None:
        if log != ['balance'] * (status == LIMIT_LOW):
            return 'calls on a reject'
        if bytes(tab[0].mem) != snap['snap'] or bytes(ex.mem) != snap['owner']:
            return 'state on a reject'
        return None
    if log != ['balance', ('debit', want['charge']), ('credit', want['charge'])]:
        return 'calls'
    if ('grow' in m.log) != (user not in v['rows'] and v.get('table', {}).get('room', 3) == 0):
        return 'grow'

    def change(blob, at):
        old = read(blob, at + RESERVED)
        blob[at + RESERVED:at + RESERVED + 8] = sat(old + v['weight']).to_bytes(8, 'little')
    return check_table(m, tab, ex, shape['rows'], v, snap, user, change)


def write_view_state(m, ex, v):
    user = v['user']
    lst = filled(m, max(DEX_STRIDE * len(v['dexes']), 8), 0x29)
    word(ex, 0x1040, 8, lst.base)
    word(ex, 0x1048, 8, len(v['dexes']))
    rows = {}
    for i, (s, r) in enumerate(v['dexes']):
        a = filled(m, 0x50, 0x31 + i)
        word(a, 0x40, 8, s)
        word(a, 0x48, 8, r)
        rows[lst.base + DEX_STRIDE * i + 0xf8] = a.base
    base = filled(m, 0x10, 0x53)
    word(base, 0, 8, v['base'][0])
    word(base, 8, 8, v['base'][1])

    def key_arg():
        return bytes(m.load(m.regs[R['rsi']] + k, 1) for k in range(20))

    def dex_row():
        at = rows.get(m.regs[R['rdi']])
        if at is None or key_arg() != user:
            raise Unmodelled('dex row arguments')
        m.visits.append(m.regs[R['rdi']])
        m.clobber(at)

    def base_row():
        if m.regs[R['rdi']] != ex.base + 0x80 or key_arg() != user:
            raise Unmodelled('base row arguments')
        m.clobber(base.base)

    m.visits = []
    m.stubs.update({DEX_ROW: dex_row, BASE_ROW: base_row})


def run_sum(ctx, v):
    m = machine(ctx)
    ex = filled(m, 0x1300, 0x41)
    m.user = v['user']
    write_view_state(m, ex, v)
    who = user_arena(m, v['user'])
    snap = bytes(ex.mem)
    enter(m, SUM, ex.base, who.base)
    scaled, raw, hooks = sum_model(v)
    if (m.regs[0], m.regs[2]) != (scaled, raw):
        return f'sum {m.regs[0]:#x},{m.regs[2]:#x}'
    if m.hooked != hooks:
        return 'record count'
    if len(m.visits) != len(v['dexes']) or len(set(m.visits)) != len(m.visits):
        return 'dex rows visited'
    if bytes(ex.mem) != snap:
        return 'state written'
    return None


def node(m, keys, level, tree, height_seed, blank=None):
    a = filled(m, EDGES_F + 12 * 8, 0x70 + height_seed)
    if blank is not None:
        a.mem[KEYS_F:KEYS_F + 220] = bytes([blank]) * 220
    if level == 0:
        here, parts = keys, ()
    else:
        mid = len(keys) // 2
        here = keys[mid:mid + 1]
        parts = (keys[:mid], keys[mid + 1:])
    word(a, LEN_F, 2, len(here))
    for i, k in enumerate(here):
        a.mem[KEYS_F + 20 * i:KEYS_F + 20 * (i + 1)] = k
        write_stamp(a, 0x20 * i + 0x10, tree[k])
    if level:
        edges = list(parts) if here else [keys]
        for i, part in enumerate(edges):
            word(a, EDGES_F + 8 * i, 8, node(m, part, level - 1, tree, height_seed + i + 1, blank).base)
    return a


def run_view(ctx, v):
    m = machine(ctx)
    user = v['user']
    m.user = user
    ex = filled(m, ROOT_F + 0x10, 0x41)
    write_view_state(m, ex, v)
    tab = write_rows(m, ex, 0x11c0, v)
    m.rows_at = ex.base + 0x11c0
    for items, field in ((v.get('items'), 0x11d8),):
        if items is not None:
            word(ex, field, 8, items)
    if v['tree'] is None:
        word(ex, ROOT_F, 8, 0)
        word(ex, ROOT_F + 8, 8, 0)
    else:
        keys = sorted(v['tree'])
        root = node(m, keys, v['height'], v['tree'], 0, v.get('blank'))
        word(ex, ROOT_F, 8, root.base)
        word(ex, ROOT_F + 8, 8, v['height'])
    cell = Arena(ROW_CELL, 0x48)
    m.arenas.append(cell)
    cell.mem[:] = fill_bytes(0x48, 0x65)
    cell.valid[:] = b'\1' * 0x48
    word(cell, USED, 8, v['row_cell']['t'])
    word(cell, RESERVED, 8, v['row_cell']['r'])
    write_stamp(cell, STAMP, v['row_cell']['time'])
    word(cell, 0x40, 4, v.get('row_once', 0))
    cell2 = Arena(TREE_CELL, 0x28)
    m.arenas.append(cell2)
    cell2.mem[:] = fill_bytes(0x28, 0x67)
    cell2.valid[:] = b'\1' * 0x28
    write_stamp(cell2, 0x10, v['tree_cell'])
    word(cell2, 0x20, 4, v.get('tree_once', 0))
    who = user_arena(m, user)
    out = m.arena(0x40, strict=False)
    out.mem[:] = fill_bytes(0x40, 0x63)
    out0 = bytes(out.mem)
    snap = bytes(ex.mem), bytes(tab[0].mem), bytes(who.mem)
    enter(m, VIEW, out.base, ex.base, who.base)
    if m.regs[0] != out.base:
        return 'result pointer'
    want = view_model(v)
    for off, name_ in ((0, 'scaled'), (8, 'used'), (0x10, 'cap'), (0x18, 'surplus')):
        if read(out.mem, off) != want[name_]:
            return f'{name_} {read(out.mem, off):#x}'
    t = want['time']
    if (read(out.mem, 0x20, 4), read(out.mem, 0x24, 4), read(out.mem, 0x28, 4)) != (t['date'] & 0xffffffff, t['secs'], t['frac']):
        return 'time'
    if bytes(out.mem[0x2c:]) != out0[0x2c:]:
        return 'bytes after the record'
    if (bytes(ex.mem), bytes(tab[0].mem), bytes(who.mem)) != snap:
        return 'state written'
    want_once = (v.get('row_once', 0) != 0) + (v.get('tree_once', 0) != 0)
    if m.once != want_once:
        return 'once count'
    return None


def write_action(m, a, seed=0):
    size = 0x48
    blob = filled(m, size, 0x80 + seed)
    word(blob, 0, 8, a['tag'])
    word(blob, 8, 1, a.get('b8', 0))
    word(blob, 0x18, 8, a.get('f18', 0))
    word(blob, 0x20, 8, a.get('f20', 0))
    word(blob, 0x40, 8, a.get('f40', 0))
    if a['tag'] == 0xa8:
        word(blob, 0x20, 8, write_action(m, a['inner'], seed + 1).base)
    return blob


def action(tag, **kw):
    a = dict(tag=tag, f18=0, f20=0, f40=0, b8=0)
    a.update(kw)
    return a


def run_weight(ctx, v):
    m = machine(ctx)
    blob = write_action(m, v['action'])
    enter(m, WEIGHT, blob.base)
    if m.regs[0] != weight_model(v['action']):
        return f'weight {m.regs[0]:#x}'
    return None


def run_fragment(ctx, v):
    m = machine(ctx)
    frag = v['entry']
    user = v['user']
    m.user = user
    ex = filled(m, 0x800, 0x41)
    tab = write_rows(m, ex, 0x740, v)
    m.rows_at = ex.base + 0x740
    write_stamp(ex, NOW, v['now'])
    who = user_arena(m, user)
    blob = write_action(m, v['action'])
    rsp = m.stack.base + FRAME
    r = m.regs
    for i in range(16):
        r[i] = 0xc0de0000 + i
    r[R['rsp']] = rsp
    out = m.arena(0x80, strict=False)
    out.mem[:] = fill_bytes(0x80, 0x63)
    out0 = bytes(out.mem)
    stamp_blob = None
    if frag == FRAG_ENTRY:
        rec = filled(m, 0x10, 0x90)
        word(rec, 0, 4, v['option'])
        word(rec, 8, 8, v['expires'])
        # the action record follows the two option words
        joined = m.arena(0x10 + len(blob.mem))
        joined.mem[:] = bytes(rec.mem) + bytes(blob.mem)
        joined.valid[:] = b'\1' * len(joined.mem)
        r[R['r15']], r[R['r12']], r[R['rbx']] = joined.base, ex.base, out.base
        m.store(rsp + 0x18, 8, who.base)
        for k in range(20):
            m.store(rsp + 0x120 + k, 1, user[k])
    elif frag == FRAG_INNER:
        word(m.stack, FRAME + 0x70, 1, v['first'])
        word(m.stack, FRAME + 0x78, 2, v['inner_tag'])
        r[R['r12']], r[R['r15']], r[R['r14']] = blob.base, who.base, ex.base
    else:
        r[R['rbp']] = v['flag']
        r[R['r15']], r[R['r14']] = ex.base, blob.base
        stamp_blob = filled(m, 0x10, 0x95)
        write_stamp(stamp_blob, 0, v['stamp'])
        m.store(rsp + 0x68, 8, v['expires'])
        m.store(rsp + 0x58, 8, ex.base + 0x740)
        m.store(rsp + 0x50, 8, stamp_blob.base)
        for k in range(20):
            m.store(rsp + 0x30 + k, 1, user[k])
    snap = dict(snap=bytes(tab[0].mem), owner=bytes(ex.mem))

    def stop_at(va):
        def stop():
            raise Stop(va)
        return stop

    for va in STOPS:
        m.hooks[va] = stop_at(va)

    def clock(reg):
        def note():
            m.clock = signed(m.regs[R[reg]], 64)
        return note

    m.clock = None
    if frag == FRAG_ENTRY:
        m.hooks[CLOCK_ENTRY] = clock('rdx')
    elif frag == FRAG_BATCH:
        m.hooks[CLOCK_BATCH] = clock('rax')
    where = None
    try:
        m.run(ENTRY_AT[frag])
    except Stop as hit:
        where = hit.va
    if where is None:
        return 'no stop'
    want, add = {FRAG_ENTRY: entry_model, FRAG_INNER: inner_model, FRAG_BATCH: batch_model}[frag](v)
    if STOPS[where] != want:
        return f'stop {STOPS[where]}'
    if m.clock is not None and m.clock != raw_ms(v['now']):
        return 'clock before the floor'
    if where == 0x2208871 and m.load(rsp + 0x108, 8) != joined.base:
        return 'record spill'
    if add is None:
        if bytes(tab[0].mem) != snap['snap'] or bytes(ex.mem) != snap['owner']:
            return 'state on no charge'
        return None
    if want == 'expired' and frag == FRAG_ENTRY:
        if out.mem[0] != 0xe or read(out.mem, 8, 2) != EXPIRED:
            return 'expired record'
        if bytes(out.mem[1:8]) != out0[1:8] or bytes(out.mem[10:]) != out0[10:]:
            return 'bytes around the status'
    elif frag == FRAG_ENTRY and bytes(out.mem) != out0:
        return 'output written'
    if want == 'expired' and frag == FRAG_BATCH and m.load(rsp + 0x158, 2) != EXPIRED:
        return 'batch status'
    stamp = v['stamp'] if frag == FRAG_BATCH else v['now']

    def change(b, at):
        old = read(b, at + USED)
        b[at + USED:at + USED + 8] = sat(old + add).to_bytes(8, 'little')
        b[at + STAMP:at + STAMP + 4] = (stamp['date'] & 0xffffffff).to_bytes(4, 'little')
        b[at + STAMP + 4:at + STAMP + 8] = stamp['secs'].to_bytes(4, 'little')
        b[at + STAMP + 8:at + STAMP + 12] = stamp['frac'].to_bytes(4, 'little')
    return check_table(m, tab, ex, 0x740, v, snap, user, change)


RUNNERS = dict(handler=run_handler, view=run_view, sum=run_sum, weight=run_weight, fragment=run_fragment)


def check(ctx, v):
    """None when the machine and the model agree, else a short reason."""
    try:
        msg = RUNNERS[v['kind']](ctx, v)
    except Panicked:
        return None if v['kind'] == 'handler' and handler_model(v).get('panic') else 'panicked'
    if v['kind'] == 'handler' and handler_model(v).get('panic'):
        return 'no panic'
    return msg


# ---- vectors


class Lcg:
    def __init__(self, seed):
        self.x = seed

    def next(self, n):
        self.x = (self.x * 0x5851f42d4c957f2d + 0x14057b7ef767814f) & U64
        return (self.x >> 33) % n


ME = addr(1)
YOU = addr(2)
THEM = addr(3)
TIME_A = dict(date=date_word(2025, 200), secs=4000, frac=5000000)


def row(t=0, r=0, time=None):
    return dict(t=t, r=r, time=time or TIME_A)


def near(a):
    return [x for x in (a - 2, a - 1, a, a + 1, a + 2) if 0 <= x <= U64]


def vec(group, **kw):
    v = dict(group=group, user=ME, rows={})
    v.update(kw)
    return v


def spread(items):
    """Each copy takes the same values, so a mutant of any copy meets them."""
    return [dict(v, entry=e) for v in items for e in (HANDLER, COPY_A, COPY_B)]


def handler_vectors():
    out = []
    mk = lambda group, **kw: vec(group, kind='handler', list=kw.pop('list', 1), **kw)
    top = (U64 + 1) // UNIT_COST
    cap = COST_CAP // UNIT_COST
    for w in near(0) + near(1000) + near(cap) + near(cap + 1) + near(top) + [U64, 1 << 63]:
        for bal in (0, w * UNIT_COST % (1 << 64), U64):
            out.append(mk('reserve weight', weight=w, balance=bal, rows={ME: row(t=5, r=7)}))
    for w in (1, 3, 1000, cap):
        cost = w * UNIT_COST
        for bal in near(cost):
            out.append(mk('reserve balance', weight=w, balance=bal, rows={ME: row(r=9)}))
    out.append(mk('empty list', weight=1, balance=U64, list=0))
    for r in near(U64)[:3] + [U64 - 1000, U64 - 1001, 0]:
        out.append(mk('reserved saturates', weight=1000, balance=U64, rows={ME: row(r=r)}))
    for w in (0, 1, 2):
        out.append(mk('zero or small', weight=w, balance=0, rows={}))
        out.append(mk('zero or small', weight=w, balance=U64, rows={YOU: row(r=4)}))
    h = key_hash(ME)
    for size in (4, 8, 16, 32, 128):
        mask = size - 1
        home = h & mask
        same = h >> 57
        other = same ^ 0x35
        out.append(mk('new row', weight=4, balance=U64, table=dict(size=size)))
        out.append(mk('new row', weight=4, balance=U64, table=dict(size=size, room=0)))
        out.append(mk('new row', weight=4, balance=U64, table=dict(size=size, deleted=[home])))
        out.append(mk('new row', weight=4, balance=U64, table=dict(size=size, deleted=[home], room=0)))
        out.append(mk('new row', weight=4, balance=U64, table=dict(size=size, decoys=[(home, same)])))
        out.append(mk('new row', weight=4, balance=U64, table=dict(size=size, decoys=[(home, other), (home + 1, same)])))
        if size >= 32:
            group = [((home + i) & mask, other if i % 3 else same) for i in range(16)]
            out.append(mk('new row', weight=4, balance=U64, table=dict(size=size, decoys=group)))
            out.append(mk('old row after a full group', weight=4, balance=U64, rows={ME: row(r=1)}, table=dict(size=size, decoys=group)))
        if size == 4:
            ends = [(i, other) for i in range(1, 4)]
            out.append(mk('new row', weight=4, balance=U64, table=dict(size=size, decoys=[(mask, other)])))
            out.append(mk('new row', weight=4, balance=U64, table=dict(size=size, decoys=ends)))
        if size == 16:
            many = [(home, same), ((home + 1) & mask, other), ((home + 2) & mask, other)]
            out.append(mk('old row after a decoy', weight=4, balance=U64, rows={ME: row(r=1)}, table=dict(size=size, decoys=many)))
            pack = [((home + i) & mask, other) for i in range(1, 6)]
            out.append(mk('new row', weight=4, balance=U64, table=dict(size=size, decoys=pack, deleted=[home])))
    for n in range(4, 60):
        who = addr(n)
        h = key_hash(who)
        if 2 <= h & 7 <= 6:
            full = sorted(set(range(h & 7, 8)) | {0})
            out.append(mk('new row', user=who, weight=4, balance=U64, table=dict(size=8, decoys=[(i, 1) for i in full])))
            out.append(mk('new row', user=who, weight=4, balance=U64, table=dict(size=8, decoys=[(i, 1) for i in full if i != 0])))
            break
    wall = [((h + i) & 63, (h >> 57) ^ 0x35) for h in (key_hash(ME),) for i in range(32)]
    out.append(mk('new row', weight=4, balance=U64, table=dict(size=64, decoys=wall)))
    out.append(mk('old row after a full group', weight=4, balance=U64, rows={ME: row(r=1)}, table=dict(size=64, decoys=wall)))
    rng = Lcg(0x77)
    for _ in range(60):
        w = rng.next(1 << 20)
        out.append(mk('random', weight=w, balance=rng.next(1 << 31), rows={ME: row(t=rng.next(99), r=rng.next(1 << 30))} if rng.next(2) else {YOU: row()}))
    return spread(out)


def sum_vectors():
    out = []
    mk = lambda group, dexes, base: vec(group, kind='sum', entry=SUM, dexes=dexes, base=base)
    out.append(mk('sum', [], (0, 0)))
    out.append(mk('sum', [], (7, 9)))
    out.append(mk('sum', [(1, 2)], (3, 4)))
    out.append(mk('sum', [(1, 2), (10, 20), (100, 200)], (1000, 2000)))
    high = U64 - 1
    out += [mk('sum saturates', [(high, 1), (1, 1)], (0, 0)), mk('sum saturates', [(high, 1), (2, 1)], (0, 0)),
            mk('sum saturates', [(1, high), (1, 2)], (0, 0)), mk('sum saturates', [(1, high), (1, 1)], (0, 0)),
            mk('sum saturates', [(high, high), (5, 5), (5, 5)], (5, 5)), mk('sum saturates', [(5, 1)], (U64, 0)),
            mk('sum saturates', [(1, 5)], (0, U64)), mk('sum saturates', [(5, 5)], (U64, U64)),
            mk('sum saturates', [(U64, 0)], (0, 0)), mk('sum saturates', [(0, U64)], (0, 0)),
            mk('sum saturates', [], (U64, U64))]
    return out


def view_vectors():
    out = []
    t1 = dict(date=date_word(2025, 10), secs=5, frac=9)
    cell = row(t=0, r=0, time=dict(date=date_word(1970, 1), secs=3, frac=4))
    tcell = dict(date=date_word(1960, 2), secs=1, frac=2)
    old = dict(date=date_word(1965, 3), secs=1, frac=1)

    def mk(group, **kw):
        kw.setdefault('dexes', [])
        kw.setdefault('base', (0, 0))
        kw.setdefault('tree', None)
        kw.setdefault('height', 0)
        kw.setdefault('row_cell', cell)
        kw.setdefault('tree_cell', tcell)
        return vec(group, kind='view', entry=VIEW, **kw)

    rows = {ME: row(t=5, r=2)}
    for s in near(0)[:3] + near(99) + near(100) + near(101) + near(1 << 40) + [U64, U64 - 99, U64 - 100]:
        out.append(mk('cap', base=(s, 7), rows=rows))
        out.append(mk('cap', dexes=[(s, 3)], base=(0, 7), rows=rows))
    for t, r in ((0, 0), (1, 0), (0, 1), (5, 5), (6, 5), (5, 6), (U64, 0), (0, U64), (U64, U64), (U64, 1), (1 << 63, (1 << 63) + 1)):
        out.append(mk('used and surplus', base=(1234567, 0), rows={ME: row(t=t, r=r)}))
    out.append(mk('no row', base=(100, 0), rows={YOU: row(t=9, r=9)}))
    out.append(mk('no row', base=(100, 0), rows={}))
    out.append(mk('no row', base=(100, 0), rows={}, row_cell=row(t=3, r=1), row_once=1))
    out.append(mk('no row', base=(100, 0), rows={YOU: row()}, row_cell=row(t=3, r=8), row_once=1))
    out.append(mk('rows counted empty', base=(100, 0), rows={ME: row(t=8, r=1)}, items=0))
    h = key_hash(ME)
    home = h & 15
    other = (h >> 57) ^ 0x11
    out.append(mk('row table walk', rows={ME: row(t=8)}, table=dict(decoys=[(home, h >> 57)])))
    out.append(mk('row table walk', rows={}, table=dict(decoys=[(home, h >> 57)])))
    out.append(mk('row table walk', rows={}, table=dict(size=32, decoys=[((home + i) & 31, other) for i in range(16)])))
    out.append(mk('row table walk', rows={ME: row(t=8, r=2)}, table=dict(size=32, decoys=[((h + i) & 31, other) for i in range(16)])))
    out.append(mk('row table walk', rows={ME: row(t=8, r=2)}, table=dict(size=32, decoys=[((h + i) & 31, h >> 57 if i == 3 else other) for i in range(16)])))
    wall = [((h + i) & 63, other) for i in range(32)]
    out.append(mk('row table walk', rows={ME: row(t=8, r=2)}, table=dict(size=64, decoys=wall)))
    d0 = date_word(2025, 100)
    late = [dict(date=date_word(2026, 1), secs=0, frac=0), dict(date=d0, secs=9, frac=0), dict(date=d0, secs=8, frac=9),
            dict(date=d0, secs=8, frac=8), dict(date=d0, secs=8, frac=7), dict(date=d0, secs=7, frac=9),
            dict(date=date_word(2024, 366), secs=99, frac=99), dict(date=date_word(-5, 1), secs=9, frac=9)]
    pivot = dict(date=d0, secs=8, frac=8)
    bigs = [dict(date=d0, secs=0x80000000, frac=8), dict(date=d0, secs=8, frac=0x80000000)]
    for t in late + bigs:
        out.append(mk('time order', rows={ME: row(time=pivot)}, tree={ME: t}))
        out.append(mk('time order', rows={ME: row(time=t)}, tree={ME: pivot}))
        out.append(mk('time order', rows={}, row_cell=row(time=pivot), tree={ME: t}))
        out.append(mk('time order', rows={ME: row(time=t)}, tree={YOU: pivot}, tree_cell=pivot))
    for tree in ({YOU: t1}, {ME: t1}, {THEM: t1, ME: TIME_A}, {THEM: t1, YOU: TIME_A}):
        out.append(mk('tree walk', rows={ME: row(time=old)}, tree=tree))
    keys = sorted(addr(10 + i) for i in range(14))
    many = {k: dict(date=date_word(2020, 1 + i), secs=i, frac=i) for i, k in enumerate(keys)}
    for i in (0, 3, 6, 7, 13):
        out.append(mk('tree walk', user=keys[i], tree={k: x for k, x in many.items() if k != keys[3]}, height=1, rows={keys[i]: row(time=old)}))
    out.append(mk('tree walk', user=ME, tree={k: x for k, x in list(many.items())[:11]}, rows={ME: row(time=old)}))
    deep = {k: x for k, x in list(many.items())[:7]}
    for k in sorted(deep)[:7]:
        out.append(mk('tree walk', user=k, tree=deep, height=2, rows={k: row(time=old)}))
    for blank in (0, 0xff):
        for i in (0, 1, 3, 6, 7, 11, 13):
            out.append(mk('tree walk', user=keys[i], tree={k: x for k, x in many.items() if k != keys[3]}, height=1, blank=blank, rows={keys[i]: row(time=old)}))
            out.append(mk('tree walk', user=keys[i], tree={k: x for k, x in list(many.items())[:11]}, blank=blank, rows={keys[i]: row(time=old)}))
    out.append(mk('tree walk', tree={}, rows={ME: row(time=old)}))
    out.append(mk('tree walk', tree={}, height=1, rows={ME: row(time=old)}))
    out.append(mk('tree walk', tree={ME: t1}, tree_once=1, tree_cell=dict(date=date_word(2030, 1), secs=0, frac=0), rows={ME: row(time=old)}))
    out.append(mk('tree walk', tree={YOU: t1}, tree_once=1, tree_cell=dict(date=date_word(2030, 1), secs=0, frac=0), rows={ME: row(time=old)}))
    return out


def weight_vectors():
    out = []
    mk = lambda group, a: vec(group, kind='weight', entry=WEIGHT, action=a)
    for tag in range(0, WEIGHT_FIRST + 200):
        if tag > WEIGHT_FIRST + 69 and tag not in range(WEIGHT_FIRST + 70, WEIGHT_FIRST + TABLE_ROWS):
            break
        if tag == 0xa8:
            out.append(mk('tags', action(tag, f18=3, inner=action(0x76, f18=5))))
            continue
        out.append(mk('tags', action(tag, f18=41, f20=61, f40=83, b8=2)))
        out.append(mk('tags', action(tag, f18=0, f20=0, f40=0, b8=1)))
    for n in (0, 1, 2, 19, 20, 21, 39, 40, 41, U64):
        for tag in (0x76, 0x77, 0x78, 0x82, 0x8b):
            out.append(mk('fields', action(tag, f18=n, f20=U64 - n, f40=n, b8=2)))
            out.append(mk('fields', action(tag, f18=U64 - n, f20=n, f40=U64 - n, b8=2)))
        for b in (0, 1, 2, 3, 0x82):
            out.append(mk('fields', action(0xb8, b8=b, f20=n, f18=U64 - n, f40=U64 - n)))
    for count in (0, 1, 2, 7, 1 << 32, U64):
        for inner in (action(0x74), action(0x76, f18=0), action(0x76, f18=9), action(0x82, f40=1 << 33), action(0x8b, f18=100), action(0xb8, b8=2, f20=45), action(0x77, f18=U64),
                      action(0xa8, f18=3, inner=action(0x78, f18=4))):
            out.append(mk('nested', action(0xa8, f18=count, inner=inner)))
    return out


TABLE_ROWS = 70


def frag_vectors():
    out = []
    n0 = dict(date=date_word(2025, 250), secs=4000, frac=7654321)
    ms = now_ms(n0)
    a7 = action(0x76, f18=7)
    mk = lambda group, frag, **kw: vec(group, kind='fragment', entry=frag, **kw)
    r0 = {ME: row(t=11, r=2)}
    for e in near(ms) + [0, U64, ms - 1000, ms + 1000]:
        out.append(mk('entry gate', FRAG_ENTRY, option=1, expires=e, now=n0, action=a7, rows=r0))
        out.append(mk('entry gate', FRAG_ENTRY, option=0, expires=e, now=n0, action=a7, rows=r0))
    for opt in (2, 3, 0x100, 0x10001):
        out.append(mk('entry option', FRAG_ENTRY, option=opt, expires=0, now=n0, action=a7, rows=r0))
    for year, o, secs, frac in ((1970, 1, 0, 0), (1969, 365, 86399, 999999999), (1969, 365, 86399, 1000000), (1970, 1, 0, 999999), (1970, 1, 0, 1000000), (2024, 366, 86399, 999999999),
                                (2000, 60, 1, 1), (1900, 60, 1, 1), (1600, 1, 0, 0), (2400, 366, 0, 0), (1, 1, 0, 0), (0, 1, 0, 0), (-1, 1, 0, 0), (-400, 1, 0, 0), (-401, 366, 0, 0), (-802, 2, 0, 0), (9999, 365, 0, 0),
                                (2025, 1, 0xffffffff, 0xffffffff), (262000, 1, 0, 0), (-262000, 1, 0, 0), (2001, 1, 5, 5), (1901, 1, 5, 5), (101, 1, 5, 5), (2401, 1, 5, 5), (-399, 1, 5, 5), (-799, 1, 5, 5)):
        t = dict(date=date_word(year, o), secs=secs, frac=frac)
        for e in near(now_ms(t)) + [0, 1]:
            out.append(mk('clock', FRAG_ENTRY, option=1, expires=e, now=t, action=a7, rows=r0))
    for frac in (2500000, 999999, 1000000, 1000000000, 0xffffffff, 3000000, 7000000):
        out.append(mk('clock', FRAG_ENTRY, option=1, expires=0, now=dict(date=date_word(2020, 5), secs=1, frac=frac), action=a7, rows=r0))
    for w, t in ((3, 0), (1 << 61, 0), (U64, 0), ((1 << 62) - 1, 5), (U64 // 5, 0), (U64 // 5 + 1, 0), (U64 // 5, 6), (1, U64), (1, U64 - 4), (1, U64 - 5)):
        a = action(0x76, f18=w)
        rows = {ME: row(t=t)}
        out.append(mk('entry charge', FRAG_ENTRY, option=1, expires=0, now=n0, action=a, rows=rows))
        out.append(mk('entry charge', FRAG_ENTRY, option=0, expires=0, now=n0, action=a, rows=rows))
        out.append(mk('inner charge', FRAG_INNER, first=0xf, inner_tag=EXPIRED, now=n0, action=a, rows=rows))
        out.append(mk('batch charge', FRAG_BATCH, flag=1, expires=0, now=n0, stamp=TIME_A, action=a, rows=rows))
    for w, t in ((1 << 62, 0), ((1 << 62) - 1, 0), ((1 << 62) - 1, 4), ((1 << 62) - 1, 3), (U64, 9)):
        a = action(0x76, f18=w)
        out.append(mk('inner charge', FRAG_INNER, first=0xf, inner_tag=EXPIRED, now=n0, action=a, rows={ME: row(t=t)}))
        out.append(mk('batch charge', FRAG_BATCH, flag=1, expires=0, now=n0, stamp=TIME_A, action=a, rows={ME: row(t=t)}))
    for first, tag in ((0xe, EXPIRED), (0xf, EXPIRED + 1), (0xf, EXPIRED - 1), (0xf, EXPIRED + 0x100), (0xf, 0x4ca), (0x7, EXPIRED), (0x8f, EXPIRED), (0xf, 0)):
        out.append(mk('inner gate', FRAG_INNER, first=first, inner_tag=tag, now=n0, action=a7, rows=r0))
    for e in near(ms):
        for flag in (0, 1, 2, 3, 0x100):
            out.append(mk('batch gate', FRAG_BATCH, flag=flag, expires=e, now=n0, stamp=TIME_A, action=a7, rows=r0))
    for year, o in ((1970, 1), (1969, 365), (-1, 1), (-400, 1), (0, 1), (2024, 366), (2400, 366), (1, 1), (-401, 366), (-802, 2), (-262000, 1), (262000, 1), (1900, 60), (2001, 1), (1901, 1), (101, 1), (2401, 1), (-399, 1), (-799, 1)):
        for frac in (0, 2500000, 999999, 1000000, 1000000000, 0xffffffff, 3000000):
            t = dict(date=date_word(year, o), secs=3, frac=frac)
            for e in near(now_ms(t)) + [0]:
                out.append(mk('batch clock', FRAG_BATCH, flag=1, expires=e, now=t, stamp=TIME_A, action=a7, rows=r0))
    for frag, extra in ((FRAG_ENTRY, dict(option=1, expires=0)), (FRAG_ENTRY, dict(option=0, expires=0)), (FRAG_INNER, dict(first=0xf, inner_tag=EXPIRED)), (FRAG_BATCH, dict(flag=1, expires=0, stamp=TIME_A))):
        out.append(mk('new row', frag, now=n0, action=a7, rows={}, **extra))
        out.append(mk('new row', frag, now=n0, action=a7, rows={YOU: row()}, table=dict(room=0), **extra))
        out.append(mk('new row', frag, now=n0, action=action(0x74), rows={}, table=dict(size=4), **extra))
    return out


def all_vectors():
    return handler_vectors() + view_vectors() + sum_vectors() + weight_vectors() + frag_vectors()


# ---- image binding


FDE_END = {}
RANGES = {}


def bind_fdes(data):
    fdes = Fdes(data)
    for s in WHOLE + HELPERS:
        FDE_END[s] = fdes.range_of(s)['end']
        RANGES[s] = ((s, FDE_END[s]),)
    RANGES.update(FRAGMENTS)
    for s in FRAGMENTS:
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


SUBJECTS = WHOLE + tuple(FRAGMENTS)
AFTER_PANIC = 'unwind clean-up after the panic call, not a modelled outcome'
NEVER_NONE = 'panic if the date helper refuses 719163, which it cannot: FRESH_TIME holds its result'
UNEXECUTED = (
    (0x2758c49, 0x2758c66, AFTER_PANIC), (0x4d822f9, 0x4d82316, AFTER_PANIC), (0x4d82489, 0x4d824a6, AFTER_PANIC),
    (0x1f84b15, 0x1f84b22, NEVER_NONE), (0x47d7ee0, 0x47d7eed, NEVER_NONE),
)
CAP_BYTE = 'cost is a multiple of 500 and 0xccccccccccccccc is 80 above one, so a cap one higher splits no cost'
STALE = 'stores the key tail at rsp+0x18 in place of rsp+0x10; the first copy of the same bytes is still at rsp+0x10'
SAME_ROW = 'rows 0 and 20 and 21 of the jump table are the same arm, so tag 0x74 and a smaller tag still get weight 1'
ZERO_BYTES = 'copies from the zeroed stack block 8 bytes lower; both hold 0'
SAME_DWORD = 'pshufd 0x44 to 0x45 picks dword 1 in place of dword 0 of a register whose low two dwords are equal after pshuflw'
CYCLES = 'years at or below 0 are lifted by a count of 400-year cycles and the days taken back; any count that leaves a year counter >= 0 gives the same days, within the chrono year range'
LIFTED = 'the year counter is >= 0 here, so this sign term of the division by 100 is 0'
UNREAD = 'the found path of 0x27c3c90 stores the table pointer; 0x1f849b0 never reads that word'
EQUIVALENT = {
    **dict.fromkeys((0x2758b48, 0x4d821f8, 0x4d82388), CAP_BYTE),
    0x21e2948: STALE,
    **dict.fromkeys((0x33632e7, 0x33632eb), SAME_ROW),
    **dict.fromkeys((0x1f84a8c, 0x1f84a91, 0x1f84aa5, 0x47d7e3d, 0x47d7e43, 0x47d7e5b), ZERO_BYTES),
    **dict.fromkeys((0x27c3ccb, 0x47d7cde, 0x27555cc), SAME_DWORD),
    0x27c3d75: UNREAD,
    **dict.fromkeys((0x220866e, 0x2208677, 0x220867e, 0x24bccdf, 0x24bcce6, 0x24bcced), CYCLES),
    **dict.fromkeys((0x22086ba, 0x24bcd25), LIFTED),
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


SCOPE = {HANDLER: (HANDLER,), COPY_A: (COPY_A,), COPY_B: (COPY_B,), VIEW: (VIEW,), SUM: (SUM, VIEW), WEIGHT: (WEIGHT,), NESTED: (WEIGHT,),
         ROW_GET: (HANDLER, FRAG_ENTRY, FRAG_INNER, FRAG_BATCH), ROW_FIND: (HANDLER, FRAG_ENTRY), ROW_GET_B: (COPY_A, COPY_B), LOOKUP: (VIEW,),
         FRAG_ENTRY: (FRAG_ENTRY,), FRAG_INNER: (FRAG_INNER,), FRAG_BATCH: (FRAG_BATCH,)}


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


def all_sites(listing):
    sites = []
    for fn in SUBJECTS:
        rows = [i for i in listing[fn] if i.va not in STOPS]
        sites += conditional_sites(fn, rows) + field_sites(fn, rows) + imm_sites(fn, rows)
    return [x for x in sites if not any(a <= x['va'] < b for a, b, _ in UNEXECUTED)]


def survey_part(args):
    data, code, slots, got, sites, vecs, want_scope = args
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
    jobs = [(data, code, slots, got, p, vecs, scoped) for p in parts]
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


def location(img, record):
    """Panic Location record: (path pointer through a RELATIVE, length, line, column); path kept from l1/ or library/."""
    ptr = img.relative(record)
    size = img.u64(record + 8)
    line, col = struct.unpack('<II', img.read(record + 0x10, 8))
    text = img.read(ptr, size).decode('utf8', 'replace')
    for mark in ('l1/src/', 'library/'):
        at = text.find(mark)
        if at >= 0:
            text = text[at:]
            break
    else:
        text = text.rsplit(chr(0x2f), 1)[-1]
    return dict(path=text, length=size, line=line, column=col)


def pinned(img):
    out = []
    for va, raw, meaning in PINNED:
        want = raw.replace(' ', '')
        got = img.read(va, len(want) // 2).hex()
        if got != want:
            raise EvidenceError(f'bytes at {va:#x} are {got}, not {want}')
        out.append(dict(va=hex(va), bytes=want, meaning=meaning))
    return out


def cap_scan(img, starts, ends):
    """Every copy of the u64 reciprocal of 100 in .text, and those with the bytes of 10000 near them."""
    addr_, off, size = img.sec['.text'][:3]
    blob = img.data
    pat = bytes.fromhex('c3f5285c8fc2f528')
    funcs, near_ = set(), []
    i = blob.find(pat, off, off + size)
    while i != -1:
        va = addr_ + i - off
        at = bisect.bisect_right(starts, va) - 1
        funcs.add(starts[at])
        if blob.find(b'\x10\x27\x00\x00', i - 80, i + 120) != -1:
            near_.append(dict(site=hex(va), function=hex(starts[at])))
        i = blob.find(pat, i + 1, off + size)
    return dict(functions_with_constant=len(funcs), near_10000=near_, window='80 bytes before to 120 bytes after the constant')


def charge_sites(img, starts):
    """Calls of a row get-or-insert followed at once by `add disp(%rax),reg` with disp 8 or 0x28."""
    out = []
    for target in (ROW_GET, ROW_GET_B):
        for row_ in direct_sites(img, target, starts):
            site = int(row_['site'], 16)
            b = img.read(site + 5, 4)
            if b[0] in (0x48, 0x49, 0x4c, 0x4d) and b[1] == 3 and b[2] & 0xc7 == 0x40 and b[3] in (8, 0x28):
                out.append(dict(row_, target=hex(target), add_va=hex(site + 5), field=hex(b[3])))
    return dict(calls=[len(direct_sites(img, t, starts)) for t in (ROW_GET, ROW_GET_B)], sites=out)


def weight_table(img):
    """Arms of the jump table of 0x33632e0, until a row leaves the function."""
    rows, end = [], FDE_END[WEIGHT]
    i = 0
    while True:
        t = WEIGHT_TABLE + struct.unpack('<i', img.read(WEIGHT_TABLE + 4 * i, 4))[0]
        if not WEIGHT <= t < end:
            break
        rows.append(t)
        i += 1
    counts = {}
    for t in rows:
        counts[t] = counts.get(t, 0) + 1
    other = sorted(WEIGHT_FIRST + k for k, t in enumerate(rows) if t != 0x3363309)
    return dict(rows=len(rows), tag_first=hex(WEIGHT_FIRST), default_row=0x14, arms={hex(k): n for k, n in sorted(counts.items())}, special_tags=[hex(t) for t in other],
                special_arms={hex(t): hex(rows[t - WEIGHT_FIRST]) for t in other})


def digest_of(v):
    return hashlib.sha256(repr(sorted((k, repr(x)) for k, x in v.items())).encode()).hexdigest()[:16]


def outcome(v):
    k = v['kind']
    if k == 'handler':
        w = handler_model(v)
        return 'panic' if w.get('panic') else f"{w['status']:#x}"
    if k == 'view':
        return 'view'
    if k == 'sum':
        return 'sum'
    if k == 'weight':
        return 'weight'
    fn = {FRAG_ENTRY: entry_model, FRAG_INNER: inner_model, FRAG_BATCH: batch_model}[v['entry']]
    return fn(v)[0]


REFERENCE_ROWS = (
    ('differs', 'scaled_vlm.rs ACCOUNT_PRIORITY_BASE, account_priority', 'scaled / 100 + 10000 is an account priority or tier seed', 'the third word of the record the wrapper 0x27d0780 returns, the slot of nRequestsCap; 0x21e2ac9 is the only site found by cap_scan'),
    ('same', 'scaled_vlm.rs user_scaled_and_raw_vlm', 'dex rows then the base row, each add saturating, value +0x40 and +0x48', '0x275f500 reads list +0x1040 stride 0x2f0, then +0x80'),
    ('differs', 'scaled_vlm.rs user_scaled_and_raw_vlm', 'overflow takes one saturating path', 'each of the 4 add sites records through 0x358dcd0 before it saturates, so the count of records is a result too'),
    ('same', 'abci_state_info_handler.rs UserRateLimit', 'cum_vlm, n_requests_used, n_requests_cap, n_requests_surplus', 'view words in the same order: scaled, used, cap, surplus, plus a 12-byte time the struct lacks'),
    ('differs', 'abci_state_info_handler.rs UserRateLimit.cum_vlm', 'a String', 'the wrapper stores an f64 at +0 (scaled / 100.0); string form is not shown here'),
    ('same', 'impl_execute_action.rs ReserveRequestWeight', 'tag 66 handler at 0x2758AE0', 'the address has the cost test and the row add; a dispatch table row was not rechecked here'),
)


def generate(data, out_dir, with_survey=True):
    global SEEN, TABLE_ROWS
    img, code, fdes, slots, got = build(data)
    ctx = (img, code, slots, got)
    listing = {s_: decode_subject(img, s_) for s_ in RANGES}
    table = weight_table(img)
    TABLE_ROWS = table['rows']
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
    missing, padding = [], 0
    for fn in RANGES:
        if fn in HELPERS:
            continue
        for ins in listing[fn]:
            if ins.va in seen or ins.va in STOPS:
                continue
            if ins.op == 'nop':
                padding += 1
            elif not any(a <= ins.va < b for a, b, _ in UNEXECUTED):
                missing.append(hex(ins.va))
    if missing:
        raise EvidenceError(f'unlisted unexecuted instructions {len(missing)}: {missing[:80]}')
    rows = survey(data, code, slots, got, listing, vecs) if with_survey else []
    survivors = {r['va'] for r in rows if not r['killed']}
    if survivors - set(EQUIVALENT) or (rows and set(EQUIVALENT) - survivors):
        raise EvidenceError(f'survivors {sorted(hex(s_) for s_ in survivors ^ set(EQUIVALENT))} of {len(rows)}')
    fde_list = eh_frame_records(data)[1]
    starts = sorted(f['start'] for f in fde_list)
    ends = sorted(f['end'] for f in fde_list)
    out_path = Path(out_dir)
    out_path.mkdir(parents=True, exist_ok=True)
    groups, outcomes = {}, {}
    with open(out_path / 'vectors.tsv', 'w', newline='\n') as f:
        f.write('group\tentry\tstate\toutcome\n')
        for v in vecs:
            groups[v['group']] = groups.get(v['group'], 0) + 1
            name = outcome(v)
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
    per = {}
    for fn in RANGES:
        d = dict(instructions=len(listing[fn]), executed=sum(i.va in seen for i in listing[fn]), fde=hex(fdes.range_of(fn)['fde']), end=hex(FDE_END[fn]))
        if fn in FRAGMENTS:
            d['ranges'] = [[hex(a), hex(b)] for a, b in FRAGMENTS[fn]]
        per[hex(fn)] = d
    status = {hex(t): dict(arm=hex(STATUS_TABLE + struct.unpack('<i', img.read(STATUS_TABLE + 4 * t, 4))[0]), text_va=hex(a), text=img.read(a, n).decode('ascii'))
              for t, (a, n) in sorted(STATUS_TEXT.items())}
    evidence = dict(
        binary=BINARY, sha256=SHA256, functions=per, whole=[hex(s_) for s_ in WHOLE], fragments=[hex(s_) for s_ in FRAGMENTS], real_helpers=[hex(s_) for s_ in HELPERS],
        slots=dict(balance=hex(img.relative(SLOT_BALANCE)), debit=hex(img.relative(SLOT_DEBIT)), credit=hex(img.relative(SLOT_CREDIT)), weight=hex(img.relative(SLOT_WEIGHT)), nested=hex(img.relative(SLOT_NESTED)),
                   row_cell=hex(img.relative(SLOT_ROW_CELL)), tree_cell=hex(img.relative(SLOT_TREE_CELL))),
        callers={hex(WRAPPER): direct_sites(img, WRAPPER, starts), hex(VIEW): direct_sites(img, VIEW, starts), hex(SUM): direct_sites(img, SUM, starts), hex(LOOKUP): direct_sites(img, LOOKUP, starts)},
        shapes={hex(e): {k: hex(x) for k, x in s_.items()} for e, s_ in SHAPES.items()},
        status=status, records=[dict(location(img, r), record=hex(r)) for r in ALLOWED_RECORDS],
        weight_table=table, cap_scan=cap_scan(img, starts, ends), charge_sites=charge_sites(img, starts),
        strings={t: img.data.count(t.encode()) for t in ('nRequestsUsed', 'nRequestsCap', 'nRequestsSurplus', 'cumVlm', 'reserveRequestWeight', 'userRateLimit', 'Too many cumulative')},
        epoch_word=hex(FRESH_TIME['date']), pinned=pinned(img),
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
