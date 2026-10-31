#!/usr/bin/env python3
"""fees: node #94 staking link and the stake share behind the fee discount, from bytes alone.

Static, no execution of the node.  The linkStakingUser action 0x1e60770 and its 2 copies, the request gate 0x2769ff0,
the 2 map writers 0x3b45f40 and 0x3b462a0, the action 0x1e648c0 with its 2 copies and the tree search 0x2fdcad0 are
decoded from ELF bytes by the table decoder below, which must land exactly on each FDE end.  One range of each of the
3 fee row builders 0x26fbab0, 0x4ce19c0 and 0x4ce3360 is decoded the same way: link row, stake share, ladder, rates.
All of it is interpreted in Python on every vector and compared with a separate closed-form model, then every
conditional, field offset, immediate and read constant of the subjects is mutated to test the vectors.  The B-tree
insert, the set insert, the stake lookup and the requirement list are stubs that check their arguments.

    python3 tools/fees_staking_link.py --out <dir>

writes evidence.json, vectors.tsv, mutations.tsv, instructions.tsv, link-readers.tsv and reference-diff.tsv.  Section
and FDE parsing come from tools/elf_index.py and tools/fde_extents.py.  Only the standard library is used: no objdump,
readelf or other external program runs, so the results cannot depend on a binutils version.
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


REQUEST_GATE = 0x2769ff0
WRAP = 0x1e60770
WRAP_B = 0x46ba6c0
WRAP_C = 0x46ba4d0
REQUEST = 0x3b45f40
FINAL = 0x3b462a0
CHECK = 0x1e648c0
CHECK_B = 0x46bd7a0
CHECK_C = 0x46bd5a0
SEARCH = 0x2fdcad0
SERIALIZER = 0x3b46760
INSERT = 0x339feb0
SET_INSERT = 0x284f810
HEAD_MAIN = 0x26fbab0
HEAD_A = 0x4ce19c0
HEAD_B = 0x4ce3360
DEPLOYER = 0x2751b30
SLOT_MEMCMP = 0x576e488
SLOT_ALLOC = 0x576dfd8
SLOT_CAPACITY = 0x576dfb8
SLOT_FREE = 0x576e010
SLOT_REQUEST = 0x5774df0
SLOT_FINAL = 0x5773150
SLOT_STAKE = 0x5774900
SLOT_OVERFLOW = 0x5773190
STATUS_TABLE = 0x59a8d0
OK = 0x186
TEXT = 0x159
DEPLOYER_LINK = 0x109
DEPLOYER_VOLUME = 0x10a
TAG_OK = 0xd
TAG_ERR = 0xe
TEXTS = dict(no_stake=(0x3f01d9, 31), itself=(0x5b676b, 36), trading_set=(0x5b6740, 43), staking_set=(0x5b6715, 43), first=(0x5b678f, 45), not_linked=(0x3bf92c, 40))
SCALE = 0x20a830
ONE = 0x20a730
MAX_STAKE = 10 ** 17
SHAPES = (dict(link=0x3a18, staked=0xaf0, marks=0x8b8, mode=0x8f2, stake=0xa60, ladder=0x608),
          dict(link=0x4498, staked=0x1570, marks=0x1338, mode=0x1372, stake=0x14e0, ladder=0x1088))
ACTIONS = {WRAP: 0, WRAP_B: 0, WRAP_C: 1}
CHECKS = {CHECK: 0, CHECK_B: 0, CHECK_C: 1}
FORWARD = {WRAP: (0x50,), WRAP_B: (0x5a, 0x14e), WRAP_C: (0x5a, 0x14e)}
VIEWS = {
    HEAD_MAIN: dict(start=0x26fc542, stop=0x26fcba6, shape=0, base='r12', keep='rbx', spill=0x30, ratio=0x20, some=0x178, a=0x30, b=0x50, inputs=(0xd8, 0x98, 0xd0, 0x80), style='out', call=0x2512770, drop=0x277eba0),
    HEAD_A: dict(start=0x4ce2452, stop=0x4ce2b66, shape=0, base='rbx', keep='r14', spill=0x20, ratio=0x30, some=0x1d8, a=0x20, b=0x50, inputs=(0x158, 0x98, 0x150, 0x80), style='slot', call=0x4889850, drop=0x4daf4a0),
    HEAD_B: dict(start=0x4ce3df2, stop=0x4ce4506, shape=1, base='rbx', keep='r14', spill=0x20, ratio=0x30, some=0x1d8, a=0x20, b=0x50, inputs=(0x158, 0x98, 0x150, 0x80), style='slot', call=None, drop=None),
}
WHOLE = (WRAP, WRAP_B, WRAP_C, REQUEST_GATE, REQUEST, FINAL, CHECK, CHECK_B, CHECK_C, SEARCH)
LINK = dict(keys=8, count=0xe6, vals=0xe8, vstep=21, kids=0x1d0, size=0x230)
STAKED = dict(keys=0x110, count=0x1ee, vals=8, vstep=24, kids=0x1f0, size=0x250)
SEEN = None


class Panicked(Exception):
    pass


class Stop(Exception):
    pass


def user(n, last=0):
    return bytes([n]) + bytes((n * 3 + k * 37) & 0xff for k in range(1, 19)) + bytes([last or n])


# ---- closed-form model


def link_rule(v):
    """Rows named as map key -> (tag, other address)."""
    rows, payload, signer = v['links'], v['payload'], v['signer']
    if v['finalize']:
        staking, trading = signer, payload
        row = rows.get(trading)
        if row is None or row[0] != 0 or row[1] != staking:
            return dict(text='first', inserts=[])
        return dict(text=None, inserts=[(trading, 1, staking), (staking, 2, trading)])
    staking, trading = payload, signer
    if staking not in v['staked']:
        return dict(text='no_stake', inserts=[])
    if staking == trading:
        return dict(text='itself', inserts=[])
    row = rows.get(trading)
    if row is not None and row[0] != 0:
        return dict(text='trading_set', inserts=[])
    row = rows.get(staking)
    if row is not None and row[0] != 0:
        return dict(text='staking_set', inserts=[])
    return dict(text=None, inserts=[(trading, 0, staking)])


def check_rule(v):
    row = v['links'].get(v['payload'])
    if row is None or row[0] != 1 or row[1] != v['signer']:
        return dict(text='not_linked', marks=[])
    return dict(text=None, marks=[v['payload']])


def owner_of(v):
    """The address whose stake counts, or None when the user's row is the staking side."""
    row = v['links'].get(v['user'])
    if row is not None and row[0] > 1:
        return None
    if row is not None and row[0] == 1:
        return row[1]
    return v['user']


def view_rule(v):
    """Stake share in basis points, the ladder discount and the 4 rates after it."""
    out = dict(share=0.0, owner=None, stake_calls=0, list_calls=0, hooks=0, drops=0)
    owner = owner_of(v)
    if owner is not None and v['some']:
        out['owner'] = owner
        out['stake_calls'] = 1
        held = v['stakes'].get(owner, 0)
        if held:
            out['list_calls'] = 1
            if v['list_error']:
                out['drops'] = 1
            else:
                total = 0
                for x in v['list']:
                    if total + x > U64:
                        out['hooks'] += 1
                        total = U64
                    else:
                        total += x
                row = v['staked'].get(owner)
                excess = max(total - (row[0] if row else 0), 0)
                supply = MAX_STAKE if v['mode'] == 2 else v['supply']
                if held >= excess and supply:
                    out['share'] = fdiv(float(held - excess), float(supply)) * 10000.0
    cut = 0.0
    rows = v['ladder']
    if rows and not rows[0][0] > out['share']:
        k = 1
        while k < len(rows) and not rows[k][0] > out['share']:
            k += 1
        cut = rows[k - 1][1]
    out['cut'] = cut
    keep = 1.0 - cut
    out['rates'] = [r * keep if 0.0 < r else r for r in v['rates']]
    return out


def outcome_name(v):
    if v['kind'] == 'link':
        return link_rule(v)['text'] or ('finalize' if v['finalize'] else 'request')
    if v['kind'] == 'check':
        return check_rule(v)['text'] or 'mark'
    w = view_rule(v)
    if w['owner'] is None:
        return 'share 0 no owner'
    return 'share above 0' if w['share'] > 0 else 'share 0'


# ---- harness


def node(m, shape, rows, height, wide):
    """A B-tree node with the map's own layout: keys, value bytes, count and children only; other bytes stay unset."""
    a = m.arena(shape['size'])
    m.nodes.append(a)
    if height == 0:
        seps, kids = rows, []
        if len(rows) > 11:
            raise EvidenceError('leaf too long')
    else:
        n = min(11, max(1, len(rows) // 3)) if wide else 1
        n = min(n, len(rows))
        step = (len(rows) + 1) // (n + 1) if n else 1
        places = [step * (k + 1) - 1 for k in range(n)]
        seps = [rows[p] for p in places]
        cut = [-1] + places + [len(rows)]
        kids = [rows[cut[k] + 1:cut[k + 1]] for k in range(n + 1)]
    for k, (key, val) in enumerate(seps):
        m.store_bytes(a.base + shape['keys'] + 20 * k, key)
        m.store_bytes(a.base + shape['vals'] + shape['vstep'] * k, val)
    m.store(a.base + shape['count'], 2, len(seps))
    for k, part in enumerate(kids):
        m.store(a.base + shape['kids'] + 8 * k, 8, node(m, shape, part, height - 1, wide))
    return a.base


def map_words(m, ex, at, shape, rows, height, wide):
    if rows is None:
        m.store(ex.base + at, 8, 0)
        return
    m.store(ex.base + at, 8, node(m, shape, sorted(rows), height, wide))
    m.store(ex.base + at + 8, 8, height)


def link_rows(links):
    return [(k, bytes([t]) + o) for k, (t, o) in links.items()]


def staked_rows(staked):
    return [(k, struct.pack('<QQQ', *x)) for k, x in staked.items()]


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
    m.real[slots[SLOT_REQUEST]] = slots[SLOT_REQUEST]
    m.real[slots[SLOT_FINAL]] = slots[SLOT_FINAL]
    stack = m.arena(0x8000, strict=False)
    stack.mem[:] = fill_bytes(0x8000, 0x35)
    m.stack = stack
    m.top = stack.base + 0x7f08
    m.nodes = []
    m.inserts = []
    m.marks = []
    m.allocs = []
    m.oom = False

    def memcmp():
        r = m.regs
        if r[R['rdx']] != 20:
            raise Unmodelled('compare length')
        x, y = m.bytes_at(r[R['rdi']], 20), m.bytes_at(r[R['rsi']], 20)
        diff = next((p - q for p, q in zip(x, y) if p != q), 0)
        m.clobber(diff & 0xffffffff | 0xdead << 32)

    def alloc():
        size = m.regs[R['rdi']]
        m.allocs.append(size)
        if m.oom:
            m.clobber(0)
            return
        m.clobber(m.arena(size).base)

    def capacity():
        r = m.regs
        if r[R['rdi']] != 1 or r[R['rsi']] != m.allocs[-1]:
            raise Unmodelled('capacity arguments')
        raise Panicked('out of memory')

    m.stubs.update({slots[SLOT_MEMCMP]: memcmp, slots[SLOT_ALLOC]: alloc, slots[SLOT_CAPACITY]: capacity})
    return m


def bytes_at(self, addr, size):
    return bytes(self.load(addr + k, 1) for k in range(size))


def store_bytes(self, addr, blob):
    for k, b in enumerate(blob):
        self.store(addr + k, 1, b)


Machine.bytes_at = bytes_at
Machine.store_bytes = store_bytes


def enter(m, fn, *args):
    m.regs[R['rsp']] = m.top
    m.store(m.top, 8, 0xfeedface)
    for name_, val in zip(('rdi', 'rsi', 'rdx', 'rcx'), args):
        m.regs[R[name_]] = val
    for name_ in ('rbx', 'rbp', 'r12', 'r13', 'r14', 'r15'):
        m.regs[R[name_]] = 0xc0de0000 + R[name_]
    m.run(fn)
    if m.regs[R['rsp']] != m.top + 8:
        raise Unmodelled('stack not balanced')
    for name_ in ('rbx', 'rbp', 'r12', 'r13', 'r14', 'r15'):
        if m.regs[R[name_]] != 0xc0de0000 + R[name_]:
            raise Unmodelled(f'{name_} not restored')


OUT_SIZE = 0x90
OUT_FILL = fill_bytes(OUT_SIZE, 0x63)


def action_args(m, v, shape):
    ex = m.arena(0x4700)
    map_words(m, ex, shape['link'], LINK, None if v.get('no_links') else link_rows(v['links']), v.get('height', 0), v.get('wide', False))
    map_words(m, ex, shape['staked'], STAKED, None if v.get('no_staked') else staked_rows(v['staked']), v.get('staked_height', 0), v.get('wide', False))
    action = m.arena(0x40)
    m.store_bytes(action.base + 0x28, v['payload'] + bytes(1))
    m.store(action.base + 0x3d, 1, int(v['finalize']) * v.get('truth', 1))
    signer = m.arena(20)
    m.store_bytes(signer.base, v['signer'])
    out = m.arena(OUT_SIZE, strict=False)
    out.mem[:] = OUT_FILL
    return ex, action, signer, out


def failure_ok(m, out, text):
    va, size = TEXTS[text]
    mem = bytes(out.mem)
    if mem[0] != TAG_ERR or mem[1:8] != OUT_FILL[1:8]:
        return 'result tag'
    if read(mem, 8, 2) != TEXT:
        return f'status {read(mem, 8, 2):#x}'
    if read(mem, 0x10) != size or read(mem, 0x20) != size:
        return 'text size words'
    if m.allocs != [size]:
        return 'alloc size'
    if m.bytes_at(read(mem, 0x18), size) != m.img.read(va, size):
        return 'text bytes'
    return None


def check_link(ctx, v):
    m = machine(ctx)
    m.oom = v.get('oom', False)
    shape = SHAPES[ACTIONS[v['copy']]]
    w = link_rule(v)
    ex, action, signer, out = action_args(m, v, shape)
    before = bytes(ex.mem), [bytes(a.mem) for a in m.nodes], bytes(action.mem)
    m.forward = None

    def forward():
        at = m.regs[R['rsp']] + 0x30 - m.stack.base
        m.forward = bytes(m.stack.mem[at:at + 0x60])

    def insert():
        r = m.regs
        if r[R['rsi']] != ex.base + shape['link']:
            raise Unmodelled('map argument')
        slot = (0x83,) if not v['finalize'] else (0xb3, 0x5b)
        if r[R['rdi']] != r[R['rsp']] + slot[len(m.inserts)]:
            raise Unmodelled('old value slot')
        val = m.bytes_at(r[R['rcx']], 21)
        m.inserts.append((m.bytes_at(r[R['rdx']], 20), val[0], val[1:]))
        m.clobber()

    m.stubs[INSERT] = insert
    for off in FORWARD[v['copy']]:
        m.hooks[v['copy'] + off] = forward
    try:
        enter(m, v['copy'], out.base, action.base, signer.base, ex.base)
    except Panicked as exc:
        return None if v.get('oom') and w['text'] else f'panic {exc}'
    if v.get('oom') and w['text']:
        return 'no panic'
    if m.inserts != w['inserts']:
        return 'map writes'
    if (bytes(ex.mem), [bytes(a.mem) for a in m.nodes], bytes(action.mem)) != before:
        return 'state bytes'
    if w['text'] is None:
        if bytes(out.mem) != bytes([TAG_OK]) + OUT_FILL[1:] or m.allocs:
            return 'success result'
        return None
    bad = failure_ok(m, out, w['text'])
    if bad:
        return bad
    mem = bytes(out.mem)
    if m.forward is None or mem[8:0x68] != m.forward:
        return 'forwarded bytes'
    return None if mem[0x68:] == OUT_FILL[0x68:] else 'bytes past the result'


def check_mark(ctx, v):
    m = machine(ctx)
    m.oom = v.get('oom', False)
    shape = SHAPES[CHECKS[v['copy']]]
    w = check_rule(v)
    ex, action, signer, out = action_args(m, v, shape)
    before = bytes(ex.mem), [bytes(a.mem) for a in m.nodes], bytes(action.mem)

    def mark():
        r = m.regs
        if r[R['rdi']] != ex.base + shape['marks']:
            raise Unmodelled('set argument')
        m.marks.append(m.bytes_at(r[R['rsi']], 20))
        m.clobber()

    m.stubs[SET_CALL[v['copy']]] = mark
    try:
        enter(m, v['copy'], out.base, action.base, signer.base, ex.base)
    except Panicked as exc:
        return None if v.get('oom') and w['text'] else f'panic {exc}'
    if v.get('oom') and w['text']:
        return 'no panic'
    if m.marks != w['marks']:
        return 'set writes'
    if (bytes(ex.mem), [bytes(a.mem) for a in m.nodes], bytes(action.mem)) != before:
        return 'state bytes'
    if w['text'] is None:
        return None if bytes(out.mem) == bytes([TAG_OK]) + OUT_FILL[1:] and not m.allocs else 'success result'
    bad = failure_ok(m, out, w['text'])
    if bad:
        return bad
    mem = bytes(out.mem)
    return None if mem[0xa:0x10] == OUT_FILL[0xa:0x10] and mem[0x28:] == OUT_FILL[0x28:] else 'bytes past the result'


def ladder_arena(m, rows):
    a = m.arena(max(len(rows), 1) * 16)
    for k, (limit, cut) in enumerate(rows):
        m.store(a.base + k * 16, 8, f2b(limit))
        m.store(a.base + k * 16 + 8, 8, f2b(cut))
    return a


def check_view(ctx, v):
    m = machine(ctx)
    c = VIEWS[v['copy']]
    shape = SHAPES[c['shape']]
    w = view_rule(v)
    ex = m.arena(0x4700)
    map_words(m, ex, shape['link'], LINK, None if v.get('no_links') else link_rows(v['links']), v.get('height', 0), v.get('wide', False))
    map_words(m, ex, shape['staked'], STAKED, None if v.get('no_staked') else staked_rows(v['staked']), v.get('staked_height', 0), v.get('wide', False))
    m.store(ex.base + shape['mode'], 1, v['mode'])
    lad = ladder_arena(m, v['ladder'])
    m.store(ex.base + shape['ladder'], 8, lad.base)
    m.store(ex.base + shape['ladder'] + 8, 8, len(v['ladder']))
    who = m.arena(20)
    m.store_bytes(who.base, v['user'])
    rsp = m.stack.base + 0x1000
    r = m.regs
    r[R['rsp']] = rsp
    for k in range(16):
        if k != R['rsp']:
            r[k] = 0xbad0_0000 + k
    r[R[c['base']]] = ex.base
    r[R[c['keep']]] = v['supply']
    m.store(rsp + c['spill'], 8, ex.base)
    m.store(rsp + 0x60, 8, who.base)
    m.store(rsp + c['some'], 8, v['some'] | 0xabcdef00)
    m.store(rsp + 0x2f0, 8, v['supply'])
    for at, x in zip(c['inputs'], v['inputs']):
        m.store(rsp + at, 8, x)
    calls = dict(stake=0, sums=0, hooks=0, drops=0, freed=[])
    list_area = m.arena(max(len(v['list']), 1) * 8)
    for k, x in enumerate(v['list']):
        m.store(list_area.base + k * 8, 8, x)
    cap = v['list_cap']
    area_size = cap * 8
    bad_blob = fill_bytes(0x60, 0x71)

    def stake():
        q = m.regs
        if q[R['rdi']] != ex.base + shape['stake'] or m.bytes_at(q[R['rsi']], 20) != w['owner']:
            raise Unmodelled('stake arguments')
        calls['stake'] += 1
        m.clobber(v['stakes'].get(w['owner'], 0))

    def sums():
        q = m.regs
        cl = q[R['rsi']]
        out = q[R['rdi']]
        if m.load(m.load(cl, 8), 1) != 4 or m.load(cl + 8, 8) != ex.base or m.load(m.load(cl + 0x18, 8), 1) != 1 or m.bytes_at(m.load(cl + 0x10, 8), 20) != w['owner']:
            raise Unmodelled('list closure')
        if m.load(cl + 0x20, 8) or m.load(cl + 0x28, 8):
            raise Unmodelled('list closure words')
        calls['sums'] += 1
        if c['style'] == 'slot':
            status = m.load(cl + 0x30, 8)
            if m.load(status, 2) != OK:
                raise Unmodelled('status word')
            m.store(out, 8, cap)
            m.store(out + 8, 8, list_area.base)
            m.store(out + 0x10, 8, len(v['list']))
            if v['list_error']:
                m.store_bytes(status + 2, bad_blob[2:])
                m.store(status, 2, 0x1234)
        elif v['list_error']:
            m.store_bytes(out + 2, bad_blob[2:])
            m.store(out, 2, 0x1234)
        else:
            m.store(out, 2, OK)
            m.store(out + 8, 8, cap)
            m.store(out + 0x10, 8, list_area.base)
            m.store(out + 0x18, 8, len(v['list']))
        m.clobber()

    def drop():
        q = m.regs
        at = q[R['rdi']]
        if m.load(at, 2) != 0x1234 or m.bytes_at(at + 2, 0x5e) != bad_blob[2:]:
            raise Unmodelled('drop argument')
        calls['drops'] += 1
        m.clobber()

    def free():
        q = m.regs
        if q[R['rdx']] != 0:
            raise Unmodelled('free flags')
        calls['freed'].append((q[R['rdi']], q[R['rsi']]))
        m.clobber()

    def hook():
        q = m.regs
        if q[R['rdi']] != 0 or q[R['rsi']] != c['location']:
            raise Unmodelled('overflow arguments')
        calls['hooks'] += 1
        m.clobber()

    def stop():
        raise Stop()

    s = ctx[2]
    m.stubs.update({s[SLOT_STAKE]: stake, c['call']: sums, c['drop']: drop, s[SLOT_FREE]: free, s[SLOT_OVERFLOW]: hook})
    m.hooks[c['stop']] = stop
    try:
        m.run(c['start'])
    except Stop:
        pass
    else:
        return 'ran to a return'
    if (calls['stake'], calls['sums'], calls['hooks'], calls['drops']) != (w['stake_calls'], w['list_calls'], w['hooks'], w['drops']):
        return f'calls {calls}'
    want_free = [(list_area.base, area_size)] if cap and w['list_calls'] and (c['style'] == 'slot' or not w['drops']) else []
    if calls['freed'] != want_free:
        return 'list free'
    mem = lambda at: m.load(rsp + at, 8)
    if mem(c['ratio']) != f2b(w['share']):
        return f"share {b2f(mem(c['ratio']))} not {w['share']}"
    got_ = [mem(c['a']), mem(c['a'] + 8), mem(c['b']), mem(c['b'] + 8)]
    want = [f2b(x) if x == x else f2b(x) for x in w['rates']]
    for k, (g, x, src) in enumerate(zip(got_, want, v['inputs'])):
        if v['rates'][k] != v['rates'][k]:
            if g != src:
                return 'not-a-number rate changed'
        elif g != x:
            return f'rate {k}'
    return None


def check(ctx, v):
    return {'link': check_link, 'check': check_mark, 'view': check_view}[v['kind']](ctx, v)


# ---- vectors


A, B, C, D = user(0x20), user(0x40), user(0x60), user(0x80)
LAST = user(0xf0)
NEAR_LOW = user(0x40, 0x3f)
NEAR_HIGH = user(0x40, 0x41)
PAD = {user(0x10 + k * 0xb, 3): (0, user(0x11 + k * 0xb, 5)) for k in range(14)}
PAD_STAKE = {user(0x13 + k * 0xb, 9): (k + 5, 7, 8) for k in range(14)}


def rows_of(*pairs):
    return dict(pairs)


def bit_flips(base):
    """The same address with one byte changed, at each of the 20 places."""
    return [base[:k] + bytes([base[k] ^ (1 << (k % 8))]) + base[k + 1:] for k in range(20)]


def act(group, copy, finalize, signer, payload, links, staked, **kw):
    return dict(kind='link', group=group, copy=copy, finalize=finalize, signer=signer, payload=payload, links=links, staked=staked, **kw)


def mark(group, copy, signer, payload, links, **kw):
    return dict(kind='check', group=group, copy=copy, finalize=False, signer=signer, payload=payload, links=links, staked={}, **kw)


def link_vectors():
    out = []
    S = {B: (1, 2, 3)}
    tags = (None, 0, 1, 2, 3, 0xff)
    for copy in ACTIONS:
        # request table: trading row and staking row each absent or any tag
        for t in tags:
            for s in tags:
                links = {}
                if t is not None:
                    links[A] = (t, C)
                if s is not None:
                    links[B] = (s, D)
                out.append(act('request rows', copy, False, A, B, links, S))
        out.append(act('request no maps', copy, False, A, B, {}, {}, no_links=True, no_staked=True))
        out.append(act('request no stake', copy, False, A, B, {A: (1, C)}, {C: (1, 2, 3)}))
        out.append(act('request no stake', copy, False, A, B, {}, {NEAR_LOW: (1, 2, 3), NEAR_HIGH: (1, 2, 3)}))
        out.append(act('request self', copy, False, B, B, {B: (1, C)}, S))
        out.append(act('request self no maps', copy, False, B, B, {}, S, no_links=True))
        for x in bit_flips(B):
            out.append(act('request one byte', copy, False, x, B, {}, S))
            out.append(act('request one byte', copy, False, A, x, {}, S))
            out.append(act('request one byte', copy, False, A, B, {x: (1, C)}, S))
        out.append(act('request staked value ignored', copy, False, A, B, {}, {B: (0, 0, 0)}))
        for kw in (dict(height=1), dict(height=2), dict(height=1, wide=True), dict(height=2, wide=True)):
            for t in (None, 1):
                links = dict(PAD)
                if t is not None:
                    links[A] = (t, C)
                out.append(act('request tall maps', copy, False, A, B, links, S, **kw))
                links = dict(PAD)
                if t is not None:
                    links[B] = (t, C)
                staked = dict(PAD_STAKE)
                staked.update(S)
                out.append(act('request tall maps', copy, False, A, B, links, staked, staked_height=kw['height'], **kw))
            staked = dict(PAD_STAKE)
            out.append(act('request tall maps', copy, False, A, B, dict(PAD), staked, staked_height=kw['height'], **kw))
        for name in ('no_stake',):
            out.append(act('request out of memory', copy, False, A, B, {}, {}, oom=True))
        out.append(act('request out of memory', copy, False, B, B, {}, S, oom=True))
        out.append(act('request out of memory', copy, False, A, B, {A: (1, C)}, S, oom=True))
        out.append(act('request out of memory', copy, False, A, B, {B: (1, C)}, S, oom=True))
        # finalize table: signer is the staking user, payload the trading user
        for t in tags:
            for other in (B, C):
                links = {} if t is None else {A: (t, other)}
                out.append(act('finalize rows', copy, True, B, A, links, {}))
                links = dict(links)
                links[B] = (2, D)
                out.append(act('finalize rows', copy, True, B, A, links, {}))
        out.append(act('finalize no map', copy, True, B, A, {}, {}, no_links=True))
        for x in bit_flips(B):
            out.append(act('finalize one byte', copy, True, B, A, {A: (0, x)}, {}))
            out.append(act('finalize one byte', copy, True, x, A, {A: (0, B)}, {}))
        for x in bit_flips(A):
            out.append(act('finalize one byte', copy, True, B, x, {A: (0, B)}, {}))
        for truth in (1, 2, 0xff):
            out.append(act('finalize flag byte', copy, True, B, A, {A: (0, B)}, {}, truth=truth))
        for kw in (dict(height=1), dict(height=2), dict(height=1, wide=True), dict(height=2, wide=True)):
            links = dict(PAD)
            links[A] = (0, B)
            out.append(act('finalize tall map', copy, True, B, A, links, {}, **kw))
            out.append(act('finalize tall map', copy, True, B, A, dict(PAD), {}, **kw))
        out.append(act('finalize out of memory', copy, True, B, A, {}, {}, oom=True))
    for copy in CHECKS:
        for t in (None, 0, 1, 2, 3, 0xff):
            for other in (B, C):
                links = {} if t is None else {A: (t, other)}
                out.append(mark('mark rows', copy, B, A, links))
        out.append(mark('mark no map', copy, B, A, {}, no_links=True))
        for x in bit_flips(B):
            out.append(mark('mark one byte', copy, B, A, {A: (1, x)}))
            out.append(mark('mark one byte', copy, x, A, {A: (1, B)}))
        for x in bit_flips(A):
            out.append(mark('mark one byte', copy, B, x, {A: (1, B)}))
        for kw in (dict(height=1), dict(height=2), dict(height=1, wide=True), dict(height=2, wide=True)):
            links = dict(PAD)
            links[A] = (1, B)
            out.append(mark('mark tall map', copy, B, A, links, **kw))
            out.append(mark('mark tall map', copy, B, A, dict(PAD), **kw))
        out.append(mark('mark out of memory', copy, B, A, {}, oom=True))
    return out


TIERS = [(1.0, 0.05), (10.0, 0.1), (100.0, 0.15), (500.0, 0.2), (1000.0, 0.3), (5000.0, 0.4)]
RATES = (0.00045, 0.00015, -0.00002, 0.0007)


def view(group, copy, **kw):
    v = dict(kind='view', group=group, copy=copy, user=A, links={}, staked={}, stakes={A: 10 ** 12}, some=1, mode=0, supply=10 ** 15, ladder=TIERS, rates=RATES, list=(), list_cap=0, list_error=False)
    v.update(kw)
    v['rates'] = tuple(v['rates'])
    v['inputs'] = tuple(f2b(x) for x in v['rates'])
    return v


def view_vectors():
    out = []
    S = {A: 3 * 10 ** 12, B: 7 * 10 ** 13, C: 11 * 10 ** 11}
    cases = (('no map', dict(no_links=True)), ('no row', dict(links={B: (1, C)})), ('requested', dict(links={A: (0, B)})), ('trading', dict(links={A: (1, B)})),
             ('staking', dict(links={A: (2, B)})), ('tag 3', dict(links={A: (3, B)})), ('tag 255', dict(links={A: (0xff, B)})), ('trading to self', dict(links={A: (1, A)})))
    for copy in VIEWS:
        for name, kw in cases:
            for some in (0, 1):
                for mode in (0, 1, 2, 3):
                    for held in ('own', 'none'):
                        stakes = dict(S) if held == 'own' else {A: 0, B: 0}
                        out.append(view(f'link {name}', copy, some=some, mode=mode, stakes=stakes, **kw))
        for name, kw in cases:
            for h in (dict(height=1), dict(height=2), dict(height=1, wide=True), dict(height=2, wide=True)):
                links = dict(PAD)
                links.update(kw.get('links', {}))
                out.append(view(f'tall {name}', copy, stakes=S, links=links, **h))
        for x in bit_flips(A):
            out.append(view('link key one byte', copy, stakes=S, links={x: (1, B)}))
        for x in bit_flips(B):
            out.append(view('link value one byte', copy, stakes={A: 3, B: 5, x: 7 * 10 ** 12}, links={A: (1, x)}))
        for held in (1, 2, 10 ** 8, 10 ** 12 - 1, 10 ** 12, 2 ** 53 + 1, 2 ** 63, 2 ** 64 - 1):
            for supply in (0, 1, 3, 10 ** 15, 10 ** 17, 2 ** 53 + 1, 2 ** 63 + 1025, 2 ** 64 - 1):
                out.append(view('share', copy, stakes={A: held}, supply=supply, mode=(supply + held) % 3))
        for lst, cap in (((), 0), ((), 4), ((5,), 1), ((5, 6, 7), 4), ((10 ** 12,), 1), ((10 ** 12 - 1,), 2), ((10 ** 12 + 1,), 2), ((2 ** 64 - 1, 1), 2), ((2 ** 64 - 1, 5, 7), 3), ((2 ** 63, 2 ** 63, 2 ** 63), 3), ((2 ** 64 - 1, 0), 2)):
            for row in (None, (0, 1, 2), (4, 1, 2), (10 ** 12, 0, 0), (2 ** 64 - 1, 9, 9)):
                staked = {} if row is None else {A: row}
                out.append(view('reserved', copy, staked=staked, list=lst, list_cap=cap))
                staked = dict(PAD_STAKE)
                if row is not None:
                    staked[A] = row
                for h in (dict(staked_height=1), dict(staked_height=2, wide=True)):
                    out.append(view('reserved tall', copy, staked=staked, list=lst, list_cap=cap, **h))
        for row in (None, (10 ** 11, 1, 2)):
            out.append(view('no staked map', copy, staked={}, no_staked=True, list=(10 ** 10,), list_cap=1))
            staked = {B: row} if row else {}
            out.append(view('owner row', copy, links={A: (1, B)}, stakes=S, staked=staked, list=(10 ** 11, 5), list_cap=2))
            staked = {A: row} if row else {}
            out.append(view('owner row', copy, links={A: (1, B)}, stakes=S, staked=staked, list=(10 ** 11, 5), list_cap=2))
        for x in bit_flips(A):
            out.append(view('staked key one byte', copy, staked={x: (7, 8, 9)}, list=(5,), list_cap=1))
        for h in (1, 2):
            links = dict(PAD)
            staked = dict(PAD_STAKE)
            out.append(view('past every key', copy, user=LAST, stakes={LAST: 10 ** 12}, links=links, staked=staked, list=(5,), list_cap=1, height=h, staked_height=h))
            links[LAST] = (1, B)
            staked[B] = (3, 4, 5)
            out.append(view('past every key', copy, user=LAST, stakes={B: 10 ** 12}, links=links, staked=staked, list=(5,), list_cap=1, height=h, staked_height=h))
        for cap in (0, 3):
            for kw in (dict(), dict(links={A: (1, B)}, stakes=S)):
                out.append(view('list error', copy, list_error=True, list_cap=cap, **kw))
        unit = 10 ** 11
        for limit, _ in TIERS + [(0.0, 0)]:
            for delta in (-1, 0, 1):
                held = int(limit) * unit + delta * unit // 10
                out.append(view('ladder step', copy, stakes={A: max(held, 1)}))
        for rows in ([], [(0.0, 0.5)], [(1.0, 0.5)], [(1e9, 0.5)], [(1e9, 0.5), (0.0, 0.25)], [(0.0, 0.1), (1e9, 0.5), (0.0, 0.25)], [(0.0, 1.5)], [(0.0, -0.5)], [(math.nan, 0.5)], [(0.0, 0.1), (math.nan, 0.5)], [(0.0, 0.5), (0.0, 0.25), (0.0, 0.125)],
                     [(0.0, 0.01 * k) for k in range(1, 13)]):
            out.append(view('ladder shape', copy, ladder=rows))
            out.append(view('ladder shape', copy, ladder=rows, some=0))
        for r in ((1.0, 2.0, 4.0, 8.0), (-1.0, -2.0, -4.0, -8.0), (0.0, -0.0, 1e-300, -1e-300), (math.inf, -math.inf, 3.0, 5.0), (3.0, 5.0, math.inf, -math.inf), (math.nan, 1.0, 1.0, 1.0), (1.0, math.nan, 1.0, 1.0), (1.0, 1.0, math.nan, 1.0), (1.0, 1.0, 1.0, math.nan)):
            out.append(view('rates', copy, rates=r))
            out.append(view('rates', copy, rates=r, ladder=[(0.0, 1.0)]))
            out.append(view('rates', copy, rates=r, ladder=[(0.0, 2.0)]))
    return out


def all_vectors():
    return link_vectors() + view_vectors()


# ---- binding


FDE_END = {}
RANGES = {}
SET_CALL = {}


def tail_pieces(img, rows, lo, hi):
    """Blocks outside the range that the range jumps to: linear decode from each target to its jump back."""
    known, out, todo = {i.va for i in rows}, [], [i.ops[0][1] for i in rows if i.op[0] == 'j' and i.op != 'jmpr' and not lo <= i.ops[0][1] < hi]
    while todo:
        va = todo.pop()
        if va in known:
            continue
        start = va
        while True:
            ins = decode_one(img.read(va, 16) + b'\x90' * 16, 0, va)
            known.add(va)
            va += ins.size
            if ins.op[0] == 'j' and not lo <= ins.ops[0][1] < hi:
                todo.append(ins.ops[0][1])
            if ins.op in ('jmp', 'ret'):
                break
        out.append((start, va))
    return sorted(out)


def bind(data):
    fdes = Fdes(data)
    img = Image(data)
    for s in WHOLE + (SERIALIZER,):
        FDE_END[s] = fdes.range_of(s)['end']
    for s in WHOLE:
        RANGES[s] = ((s, FDE_END[s]),)
    for s, c in VIEWS.items():
        fdes.range_of(s)
        end = c['stop'] + decode_one(img.read(c['stop'], 16) + b'\x90' * 16, 0, c['stop']).size
        rows = decode_range(img, c['start'], end)
        RANGES[s] = ((c['start'], end),) + tuple(tail_pieces(img, rows, c['start'], end))
    return fdes, img


def decode_subject(img, s):
    out = []
    for a, b in RANGES[s]:
        out += decode_range(img, a, b)
    return out


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


def bind_view_calls(listing):
    """Each copy's list call, drop and overflow Location, read from its own instructions."""
    for s in CHECKS:
        calls = [i.ops[0][1] for i in listing[s] if i.op == 'call' and i.ops[0][0] == 't']
        if len(calls) != 1:
            raise EvidenceError(f'calls of {s:#x}: {calls}')
        SET_CALL[s] = calls[0]
    for s, c in VIEWS.items():
        calls = [i.ops[0][1] for i in listing[s] if i.op == 'call' and i.ops[0][0] == 't']
        if len(calls) != 2:
            raise EvidenceError(f'calls of {s:#x}: {calls}')
        c['call'], c['drop'] = calls
        locs = [i.ops[1][4] for i in listing[s] if i.op == 'lea' and i.ops[1][1] is None and i.ops[1][2] is None and i.ops[0][1] == R['rsi']]
        if len(set(locs)) != 1:
            raise EvidenceError(f'locations of {s:#x}: {locs}')
        c['location'] = locs[0]


def build(data):
    check_digest(data)
    fdes, img = bind(data)
    listing = {s: decode_subject(img, s) for s in RANGES}
    bind_view_calls(listing)
    code = {}
    for rows in listing.values():
        code.update({i.va: i for i in rows})
    slots, got = scan_slots(img, code)
    return img, code, fdes, slots, got, listing


# ---- mutation survey


NO_PANIC = 'unreachable: follows a call that does not return'
UNWIND = 'unwind clean-up after a panic in a callee, not a modelled outcome'


def gaps():
    return []


SUBJECTS = (WRAP, WRAP_B, REQUEST_GATE, REQUEST, FINAL, CHECK, SEARCH, HEAD_A)
NOT_MUTATED = (WRAP_C, CHECK_B, CHECK_C, HEAD_MAIN, HEAD_B)
BACK = 'writes back the bytes this slot already holds, on the error path to the drop'
DEAD = 'a spill of the value row that nothing reads again on any path'
OUT_WORDS = 'the only caller reads the first dword of the result; these words stay in a buffer it drops'
EQUIVALENT = {
    0x1e649d3: DEAD, 0x1e649dd: DEAD,
    0x2fdcb9e: OUT_WORDS, 0x2fdcba2: OUT_WORDS, 0x2fdcba6: OUT_WORDS,
    0x4ce26ad: 'the store at 0x4ce2670 already put the same dword of the same key at this slot',
    0x4ce295d: BACK, 0x4ce296c: BACK, 0x4ce29bb: BACK, 0x4ce29cb: BACK,
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
        at = ins.size - n + (4 if n == 8 else 0)  # the low byte of a 64-bit constant is lost in the f64 conversion
        out.append(dict(kind='immediate', fn=fn, va=ins.va, op=show(ins), patch={ins.va + at: ins.raw[at] ^ 1}))
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
    g = gaps()
    stops = {c['stop'] for c in VIEWS.values()}
    return [x for x in sites if x['va'] not in stops and not any(a <= x['va'] < b for a, b, _ in g)]


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
    groups = {WRAP: 'link', WRAP_B: 'link', REQUEST_GATE: 'link', REQUEST: 'link', FINAL: 'link', CHECK: 'check', SEARCH: 'link', HEAD_A: 'view'}
    copies = {WRAP: WRAP, WRAP_B: WRAP_B, REQUEST_GATE: WRAP, REQUEST: WRAP, FINAL: WRAP, CHECK: CHECK, SEARCH: WRAP_B, HEAD_A: HEAD_A}
    picked = {fn: [v for v in vecs if v['kind'] == groups[fn] and v['copy'] == copies[fn]] for fn in groups}
    for s_ in sites:
        mimg = Image(data, s_['patch'])
        mcode = dict(code)
        fn = s_['fn']
        try:
            mcode.update({i.va: i for i in decode_subject(mimg, fn)})
        except (EvidenceError, Unmodelled, IndexError, struct.error) as exc:
            rows.append(dict(s_, killed=('decoder', str(exc)[:60].replace('\t', ' '))))
            continue
        rows.append(dict(s_, killed=try_kill((mimg, mcode, slots, got), picked[fn])))
        if PROGRESS and not rows[-1]['killed']:
            print('survivor', hex(fn), hex(s_['va']), s_['kind'], s_['op'], flush=True)
    return rows


WORKERS = 3
PROGRESS = False


def survey(data, code, slots, got, listing, vecs, img):
    sites = all_sites(listing, img)
    parts = [sites[i::WORKERS] for i in range(WORKERS)]
    jobs = [(data, code, slots, got, p, vecs) for p in parts]
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


def location(img, va):
    """Panic Location: keep the path from `l1/src/` only, plus its full length."""
    start = img.relative(va)
    length = struct.unpack('<Q', img.read(va + 8, 8))[0]
    line, col = struct.unpack('<II', img.read(va + 16, 8))
    path = img.read(start, length).decode('ascii')
    if 'l1/src/' in path:
        path = path[path.index('l1/src/'):]
    return dict(path=path, path_bytes=length, line=line, column=col)


def digest_of(v):
    return hashlib.sha256(repr(sorted((k, repr(x)) for k, x in v.items())).encode()).hexdigest()[:16]


def copy_rows(listing, a, b):
    """Two copies by decoded instruction with code addresses taken out; the rows that differ."""
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
    x, y = shape(listing[a], listing[a][0].va), shape(listing[b], listing[b][0].va)
    if len(x) != len(y):
        raise EvidenceError('copy length')
    return [dict(offset=hex(p[0]), a=show(listing[a][k]), b=show(listing[b][k])) for k, (p, q) in enumerate(zip(x, y)) if p != q]


def map_sites(img, starts):
    """Byte scan of .text for offset +0x3a18 or +0x4498: a mod 2 memory operand of lea/mov, or add reg, imm32."""
    addr_, off, size = img.sec['.text'][:3]
    blob = img.data
    out = []
    for shape in SHAPES:
        needle = struct.pack('<I', shape['link'])
        i = blob.find(needle, off, off + size)
        while i != -1:
            head = blob[i - 4:i]
            rex, op, mod = head[1], head[2], head[3]
            kind = None
            if rex & 0xf0 == 0x40 and op in (0x8b, 0x8d) and mod >> 6 == 2 and mod & 7 != 4:
                kind = {0x8b: 'load', 0x8d: 'address'}[op]
            elif head[0] & 0xf0 == 0x40 and head[1] in (0x8b, 0x8d) and head[2] >> 6 == 2 and head[2] & 7 == 4 and head[3] == 0x24:
                kind = {0x8b: 'load', 0x8d: 'address'}[head[1]]
            elif rex & 0xf0 == 0x40 and op == 0x81 and mod >> 6 == 3 and mod >> 3 & 7 == 0:
                kind = 'add'
            if kind:
                va = addr_ + i - off
                out.append((hex(starts[bisect.bisect_right(starts, va) - 1]), hex(va), hex(shape['link']), kind))
            i = blob.find(needle, i + 1, off + size)
    return sorted(out, key=lambda r: int(r[1], 16))


PINS = (
    ('deployer gate: link row present stores 0x109', 0x2751c31, '66c70309 01'),
    ('deployer gate: volume above 1e8 stores 0x10a', 0x2751db9, '66c7030a 01'),
    ('deployer gate: cmp rax, 100000000', 0x2751daf, '483d00e1f505'),
    ('row builder A: share stored at row +0x28', 0x4ce3174, 'f20f11440828'),
    ('row builder B: share stored at row +0x28', 0x4ce4b14, 'f20f11440828'),
    ('caller of 0x26fbab0: option pair, tag to r9, value to the stack word', 0x251cc89, '4c8b08488b4008 48890424'),
    ('caller of 0x4ce19c0: option pair', 0x476bb59, '4c8b08488b4008 48890424'),
    ('caller of 0x4ce3360: option pair', 0x47679a9, '4c8b08488b4008 48890424'),
    ('builder A: supply word loaded into r14 before the range', 0x4ce235d, '4c8bb424f0020000'),
    ('builder B: supply word loaded into r14 before the range', 0x4ce3cfd, '4c8bb424f0020000'),
    ('builder main: supply word loaded into rbx before the range', 0x26fc44f, '488b9c24f0020000'),
    ('builder A: exchange spilled to rsp+0x20', 0x4ce1c8e, '4c89642420'),
    ('builder main: exchange spilled to rsp+0x30', 0x26fbd7e, '4c89642430'),
    ('builder A: option tag spilled to rsp+0x1d8', 0x4ce19d1, '4c898c24d8010000'),
    ('builder main: option tag spilled to rsp+0x178', 0x26fbac1, '4c898c2478010000'),
)
NAMES = (('tag 0', 0x3b465a1, 9, 'Requested'), ('tag 1', 0x3b46530, 11, 'TradingUser'), ('other tag', 0x3b4660e, 11, 'StakingUser'), ('field of tags 0, 1', 0x3b466a4, 12, 'staking_user'), ('field of other tag', 0x3b466ce, 12, 'trading_user'))


def name_rows(img):
    out = []
    for label, site, size, want in NAMES:
        b = img.read(site, 7)
        if b[:3] != b'\x48\x8d\x35':
            raise EvidenceError(f'name site {site:#x}')
        va = site + 7 + struct.unpack('<i', b[3:])[0]
        text = img.read(va, size).decode('ascii')
        if text != want:
            raise EvidenceError(f'name {text}')
        out.append(dict(tag=label, lea=hex(site), va=hex(va), text=text))
    return out


def pinned(img):
    """Constants and bytes the model and the text rely on, re-read; any change stops the tool."""
    got_ = dict(scale=img.f64(SCALE), one=img.f64(ONE))
    if got_ != dict(scale=10000.0, one=1.0):
        raise EvidenceError(f'constants {got_}')
    for slot, value in ((SLOT_REQUEST, REQUEST), (SLOT_FINAL, FINAL)):
        if img.relative(slot) != value:
            raise EvidenceError(f'slot {slot:#x}')
    pins = []
    for label, va, text in PINS:
        want = bytes.fromhex(text.replace(' ', ''))
        if img.read(va, len(want)) != want:
            raise EvidenceError(f'pin {label}')
        pins.append(dict(what=label, va=hex(va), bytes=want.hex()))
    return got_, pins


def view_constant(listing, fn):
    hits = [hex(i.ops[1][1]) for i in listing[fn] if i.op == 'mov' and i.ops[1][0] == 'i' and i.ops[1][1] == MAX_STAKE]
    if len(hits) != 1:
        raise EvidenceError('supply constant')
    return dict(function=hex(fn), value=hits[0], decimal=MAX_STAKE)


REFERENCE_ROWS = (
    ('same', 'handlers/11_link_staking_user.rs request_link', 'staked, self, trading established, staking established, then a pending row', '4 tests in that order; 0x2769ff0 does the first and the slot 0x5774df0 writer the other 3 and the insert'),
    ('same', 'handlers/11_link_staking_user.rs finalize_link', 'row must be pending and name the signer; 2 rows written', '0x3b462a0 writes the trading row, then the staking row, and tests nothing about the staking row'),
    ('differs', 'handlers/11 LinkRelationship', 'PendingRequest, TradingLinked, StakingLinked', 'the decoder at 0x3b464e0 names the tags Requested, TradingUser, StakingUser, fields staking_user and trading_user'),
    ('differs', 'handlers/11 staking_users_with_staked_hype', 'a set of addresses', 'state +0xaf0 is a map of address to 24 bytes; 0x2769ff0 tests the key only, but the row builders read value word 0'),
    ('differs', 'handlers/11 gate of 0x2769ff0', 'the index means the user has staked HYPE', 'the test is presence of a key: a row with value words 0 still passes, and the amount is not read'),
    ('absent', 'references/can1357-hl/l1', 'no text or handler for action 0x1e648c0', 'it tests that the row of the payload is TradingUser of the signer and inserts the payload in the set at +0x8b8'),
    ('absent', 'references/can1357-hl/l1/fees', 'no stake share and no ladder at +0x608', '3 row builders compute the share in basis points and scale positive rates'),
    ('same', 'info_server/abci_state_info_handler.rs', 'response fields staking_link and active_staking_discount', 'field names only; no path from those fields to these functions was traced'),
    ('unverified', 'exchange/stake_requirement.rs available_delegated_stake', 'requirement against delegated stake', 'the list call takes bytes 4 and 1 and is a stub here; the name is a lead only'),
)


def facts_and_files(data, out_dir, img, fdes, listing, vecs, rows, seen, padding, slots):
    constants, pins = pinned(img)
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
        for fn in listing:
            for i in listing[fn]:
                f.write(f'{fn:#x}\t{i.va:#x}\t{i.size}\t{i.raw.hex()}\t{show(i)}\t{int(i.va in seen)}\n')
    readers = map_sites(img, starts)
    with open(out_path / 'link-readers.tsv', 'w', newline='\n') as f:
        f.write('function\tsite\toffset\tform\n')
        for row_ in readers:
            f.write('\t'.join(row_) + '\n')
    with open(out_path / 'reference-diff.tsv', 'w', newline='\n') as f:
        f.write('verdict\treference\treference_says\tbytes_say\n')
        for row_ in REFERENCE_ROWS:
            f.write('\t'.join(row_) + '\n')
    per = {}
    for fn in listing:
        if fn in VIEWS:
            per[hex(fn)] = dict(pieces=[[hex(a), hex(b)] for a, b in RANGES[fn]], instructions=len(listing[fn]), executed=sum(i.va in seen for i in listing[fn]), fde=hex(fdes.range_of(fn)['fde']), fde_end=hex(fdes.range_of(fn)['end']))
        else:
            per[hex(fn)] = dict(instructions=len(listing[fn]), executed=sum(i.va in seen for i in listing[fn]), fde=hex(fdes.range_of(fn)['fde']), end=hex(FDE_END[fn]))
    targets = (WRAP, WRAP_B, WRAP_C, REQUEST_GATE, CHECK, CHECK_B, CHECK_C, SEARCH, INSERT, DEPLOYER) + tuple(VIEWS)
    calls = direct_sites(img, targets, starts)
    evidence = dict(
        binary=BINARY, sha256=SHA256, functions=per, constants=constants, pins=pins,
        supply_constant=[view_constant(listing, fn) for fn in VIEWS],
        copies={f'{a:#x} {b:#x}': copy_rows(listing, a, b) for a, b in ((WRAP_B, WRAP_C), (CHECK, CHECK_B), (CHECK, CHECK_C), (HEAD_A, HEAD_B))},
        callers={hex(t): calls[t] for t in targets}, slots_holding={hex(fn): slots_holding(img, fn) for fn in (REQUEST, FINAL)},
        slot_users={hex(s): slot_users(img, s, starts) for s in (SLOT_REQUEST, SLOT_FINAL)},
        status={hex(t): dict(arm=hex(status_arm(img, t)), text=status_text(img, t)) for t in (DEPLOYER_LINK, DEPLOYER_VOLUME)},
        texts={k: dict(va=hex(a), text=img.read(a, n).decode('ascii')) for k, (a, n) in TEXTS.items()},
        names=name_rows(img), overflow_location={hex(fn): location(img, VIEWS[fn]['location']) for fn in VIEWS},
        map_sites=len(readers), vectors=len(vecs), mismatches=0, groups=groups, outcomes=outcomes, padding_not_executed=padding,
        unexecuted=[dict(start=hex(a), end=hex(b), why=w) for a, b, w in gaps()], not_mutated=[hex(x) for x in NOT_MUTATED],
        mutants=len(rows), killed=sum(1 for r in rows if r['killed']), equivalent={hex(k): w for k, w in sorted(EQUIVALENT.items())},
    )
    with open(out_path / 'evidence.json', 'w', newline='\n') as f:
        json.dump(evidence, f, indent=1, sort_keys=True)
        f.write('\n')
    return evidence


def generate(data, out_dir, with_survey=True):
    global SEEN
    img, code, fdes, slots, got, listing = build(data)
    ctx = (img, code, slots, got)
    vecs = all_vectors()
    seen = SEEN = set()
    try:
        for v in vecs:
            try:
                msg = check(ctx, v)
            except (Unmodelled, EvidenceError, KeyError) as exc:
                msg = f'fault {type(exc).__name__} {exc}'
            if msg:
                raise EvidenceError(f"mismatch in {v['group']} {v['copy']:#x}: {msg}: {repr(v)[:300]}")
    finally:
        SEEN = None
    missing, padding = [], 0
    g = gaps()
    stops = {c['stop'] for c in VIEWS.values()}
    for fn in listing:
        for ins in listing[fn]:
            if ins.va in seen or ins.va in stops:
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
