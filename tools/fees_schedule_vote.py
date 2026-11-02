"""fees: node #94 FeeSchedule vote payload: JSON wire form of the 9-part patch, from bytes alone.

Static, no execution of the node.  The decoder 0x1b2c4e0, the struct visitors and the option wrappers it calls, and
the JSON reader they use are decoded from ELF bytes by the table decoder below and interpreted in Python on every
vector.  Allocator, memory copy, text formatting and the message error builder are stubs that track every heap block.
Each outcome (patch fields, or error kind, line and column) is compared with a separate reading of the wire form,
then conditionals, field offsets and immediates of the schedule code are mutated.

    python3 tools/fees_schedule_vote.py --out <dir>

writes evidence.json, vectors.tsv, mutations.tsv, instructions.tsv, schedule-schema.tsv, reference-diff.tsv and
call-sites.tsv.  Section and FDE parsing come from tools/elf_index.py and tools/fde_extents.py.  Only the standard
library is used: no objdump, readelf or other external program runs, so the results cannot depend on a binutils version.
"""
import argparse
import bisect
import hashlib
import json
import math
import multiprocessing
import random
import re
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
            if ops[0] == ops[1]:
                self.xmm[ops[0][1]] = [0, 0]
            else:
                x = self.xmm[ops[0][1]]
                if ops[1][0] == 'm':
                    a = self.ea(ops[1])
                    y = [self.load(a, 8), self.load(a + 8, 8)]
                else:
                    y = self.xmm[ops[1][1]]
                self.xmm[ops[0][1]] = [x[0] ^ y[0], x[1] ^ y[1]]
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
        target = o[1] if o[0] == 't' else self.rd(o) if o[0] == 'r' else self.slots.get(self.ea(o)) or self.load(self.ea(o), 8)
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
                stub = self.stubs.get(rip)
                if stub is None:
                    raise Unmodelled(f'no instruction at {rip:#x}')
                stub()
                self.regs[4] += 8
                return
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
RSEEN = None

SLOT_ALLOC = 0x54c06b0
REALLOC = 0x54c5620
FREE = 0x54c8cb0
GOT_MOVE = 0x576dfe0
GOT_MEMCMP = 0x576e488
FORMAT = 0x1344760
MAKE_ERROR = 0x4ebc460
STR_DISPLAY = 0x21b7390
DECODE_A = 0x1b2c4e0
DECODE_B = 0x43a3c90
TOP = 0x1cfe930
KEYS = 0x1e6e3d0
TIERS = 0x1cfcdf0
STAKE = 0x1cd0790
VIP = 0x1cc48f0
MM = 0x1c89bd0
STAKE_ROW = 0x1c5e220
ALIGNED = 0x1c55870
OPTIONS = (0x251f690, 0x2520f40, 0x2526910, 0x2523800, 0x2522870, 0x2524090, 0x25259d0, 0x251eee0)
WHOLE = (DECODE_A, TOP, KEYS, TIERS, STAKE, VIP, MM, STAKE_ROW, ALIGNED) + OPTIONS
WRITE_ARGS = 0x1571d90
GOT_MOVE2 = 0x576e0e0
STOPS = {SLOT_ALLOC, REALLOC, FREE, 0x54c2670, 0x54c5610, FORMAT, MAKE_ERROR, WRITE_ARGS}
DEPTH_SITE_A = 0x1b2c527
CODES = {2: 'eof list', 3: 'eof object', 4: 'eof string', 5: 'eof value', 6: 'expected colon', 7: 'expected list comma or end',
         8: 'expected object comma or end', 9: 'expected ident', 10: 'expected value', 11: 'expected quote', 12: 'invalid escape',
         13: 'invalid number', 14: 'number out of range', 16: 'control character', 17: 'key must be a string', 21: 'trailing comma',
         22: 'trailing characters', 24: 'recursion limit'}
NAMES = {v: k for k, v in CODES.items()}
TOP_FIELDS = ('rates', 'tiers', 'referralDiscount', 'referrerKeep', 'destination', 'extraDestinationFractions', 'stakeDiscountTiers', 'weighSpotVolumeDouble', 'alignedQuoteTokenConfig')
POW10 = tuple(float('1e%d' % k) for k in range(309))


# ---- model: an independent reading of the wire form, written from the field table, not from the code


class Bad(Exception):
    def __init__(self, what, at):
        Exception.__init__(self, what)
        self.what, self.at = what, at


class Custom(Exception):
    """A visitor error with no position yet: the enclosing container closes first, then stamps its index."""

    def __init__(self, what):
        Exception.__init__(self, what)
        self.what = what


class Reader:
    def __init__(self, blob, depth=128):
        self.b, self.i, self.depth = blob, 0, depth

    def peek(self):
        return self.b[self.i] if self.i < len(self.b) else None

    def ws(self):
        while self.peek() in (0x20, 0x0a, 0x0d, 0x09):
            self.i += 1
        return self.peek()

    def fail(self, what):
        return Bad(what, self.i)

    def peek_fail(self, what):
        return Bad(what, min(self.i + 1, len(self.b)))

    def ident(self, rest):
        for c in rest:
            if self.i >= len(self.b):
                raise Bad('eof value', self.i)
            got = self.b[self.i]
            self.i += 1
            if got != c:
                raise Bad('expected ident', self.i)

    def string(self):
        out = bytearray()
        while True:
            if self.i >= len(self.b):
                raise self.fail('eof string')
            c = self.b[self.i]
            if c == 0x22:
                self.i += 1
                return bytes(out)
            if c == 0x5c:
                self.i += 1
                if self.i >= len(self.b):
                    raise self.fail('eof string')
                e = self.b[self.i]
                self.i += 1
                if e in b'"\\/':
                    out.append(e)
                elif e in b'bfnrt':
                    out.append({0x62: 8, 0x66: 12, 0x6e: 10, 0x72: 13, 0x74: 9}[e])
                elif e == 0x75:
                    out += chr(int(self.b[self.i:self.i + 4], 16)).encode()
                    self.i += 4
                else:
                    raise self.fail('invalid escape')
            elif c < 0x20:
                self.i += 1
                raise self.fail('control character')
            else:
                out.append(c)
                self.i += 1

    def digits_tail(self, positive, significand, exponent):
        """After the integer or fraction digits: the optional exponent."""
        if self.peek() in (0x65, 0x45):
            return self.exponent(positive, significand, exponent)
        return self.from_parts(positive, significand, exponent)

    def exponent(self, positive, significand, start):
        self.i += 1
        sign = True
        if self.peek() == 0x2b:
            self.i += 1
        elif self.peek() == 0x2d:
            self.i += 1
            sign = False
        c = self.peek()
        if c is None:
            raise self.peek_fail('eof value')
        if not 0x30 <= c <= 0x39:
            self.i += 1
            raise self.fail('invalid number')
        self.i += 1
        e = c - 0x30
        while self.peek() is not None and 0x30 <= self.peek() <= 0x39:
            d = self.peek() - 0x30
            self.i += 1
            if e > 214748364 or (e == 214748364 and d > 7):
                if significand != 0 and sign:
                    raise self.fail('number out of range')
                while self.peek() is not None and 0x30 <= self.peek() <= 0x39:
                    self.i += 1
                return ('float', -0.0 if not positive else 0.0)
            e = e * 10 + d
        return self.from_parts(positive, significand, start + e if sign else start - e)

    def from_parts(self, positive, significand, exponent):
        f = float(significand)
        while True:
            a = abs(exponent)
            if a <= 308:
                if exponent >= 0:
                    f *= POW10[a]
                    if f == math.inf:
                        raise self.fail('number out of range')
                else:
                    f /= POW10[a]
                break
            if f == 0.0:
                break
            if exponent >= 0:
                raise self.fail('number out of range')
            f /= 1e308
            exponent += 308
        return ('float', f if positive else -f)

    def fraction(self, positive, significand, before):
        self.i += 1
        after = 0
        while self.peek() is not None and 0x30 <= self.peek() <= 0x39:
            d = self.peek() - 0x30
            if significand > 1844674407370955161 or (significand == 1844674407370955161 and d > 5):
                while self.peek() is not None and 0x30 <= self.peek() <= 0x39:
                    self.i += 1
                return self.digits_tail(positive, significand, before + after)
            self.i += 1
            significand = significand * 10 + d
            after -= 1
        if after == 0:
            if self.peek() is None:
                raise self.peek_fail('eof value')
            self.i += 1
            raise self.fail('invalid number')
        return self.digits_tail(positive, significand, before + after)

    def number(self, positive):
        c = self.peek()
        if c is None:
            raise self.peek_fail('eof value')
        self.i += 1
        if not 0x30 <= c <= 0x39:
            raise self.fail('invalid number')
        significand = c - 0x30
        if c == 0x30:
            n = self.peek()
            if n is not None and 0x30 <= n <= 0x39:
                raise self.peek_fail('invalid number')
        else:
            while self.peek() is not None and 0x30 <= self.peek() <= 0x39:
                d = self.peek() - 0x30
                if significand > 1844674407370955161 or (significand == 1844674407370955161 and d > 5):
                    extra = 0
                    while self.peek() is not None and 0x30 <= self.peek() <= 0x39:
                        self.i += 1
                        extra += 1
                    if self.peek() == 0x2e:
                        return self.fraction(positive, significand, extra)
                    return self.digits_tail(positive, significand, extra)
                self.i += 1
                significand = significand * 10 + d
        if self.peek() == 0x2e:
            return self.fraction(positive, significand, 0)
        if self.peek() in (0x65, 0x45):
            return self.exponent(positive, significand, 0)
        if positive:
            return ('uint', significand)
        neg = -significand
        if significand and neg >= -(1 << 63):
            return ('int', neg)
        return ('float', -float(significand))

    def wrong_type(self):
        """Eat a scalar of the wrong type; containers stay unread."""
        c = self.peek()
        if c == 0x6e:
            self.i += 1
            self.ident(b'ull')
        elif c == 0x74:
            self.i += 1
            self.ident(b'rue')
        elif c == 0x66:
            self.i += 1
            self.ident(b'alse')
        elif c == 0x2d:
            self.i += 1
            self.number(False)
        elif c is not None and 0x30 <= c <= 0x39:
            self.number(True)
        elif c == 0x22:
            self.i += 1
            self.string()
        elif c not in (0x5b, 0x7b):
            raise self.peek_fail('expected value')
        return Bad('invalid type', self.i)

    def end_seq(self):
        c = self.ws()
        if c == 0x5d:
            self.i += 1
            return None
        if c == 0x2c:
            self.i += 1
            return self.peek_fail('trailing comma' if self.ws() == 0x5d else 'trailing characters')
        return self.peek_fail('trailing characters' if c is not None else 'eof list')

    def end_map(self):
        c = self.ws()
        if c == 0x7d:
            self.i += 1
            return None
        if c == 0x2c:
            return self.peek_fail('trailing comma')
        return self.peek_fail('trailing characters' if c is not None else 'eof object')

    def enter(self):
        self.depth -= 1
        if self.depth == 0:
            raise self.peek_fail('recursion limit')

    def scoped(self, body, closer):
        """Body of a container: the closer runs whatever the body did, a custom error takes the index after it."""
        self.enter()
        self.i += 1
        try:
            out = body()
        except Custom as exc:
            self.depth += 1
            closer()
            raise Bad(exc.what, self.i)
        self.depth += 1
        bad = closer()
        if bad:
            raise bad
        return out

    def has_element(self, first):
        c = self.ws()
        if c == 0x5d:
            return False
        if c == 0x2c and not first:
            self.i += 1
            c = self.ws()
            if c == 0x5d:
                raise self.peek_fail('trailing comma')
            if c is None:
                raise self.peek_fail('eof value')
            return True
        if c is None:
            raise self.peek_fail('eof list')
        if not first:
            raise self.peek_fail('expected list comma or end')
        return True

    def next_key(self, first):
        c = self.ws()
        if c == 0x7d:
            return None
        if c == 0x2c and not first:
            self.i += 1
            c = self.ws()
            if c is None:
                raise self.peek_fail('eof value')
        elif c is None:
            raise self.peek_fail('eof object')
        elif not first:
            raise self.peek_fail('expected object comma or end')
        if c == 0x22:
            self.i += 1
            return self.string()
        if c == 0x7d:
            raise self.peek_fail('trailing comma')
        if c is None:
            raise self.peek_fail('eof object')
        raise self.peek_fail('key must be a string')

    def colon(self):
        c = self.ws()
        if c == 0x3a:
            self.i += 1
            return
        raise self.peek_fail('expected colon' if c is not None else 'eof object')

    def skip(self):
        """A well formed value of any shape; no depth count on this path."""
        c = self.ws()
        if c is None:
            raise self.peek_fail('eof value')
        if c == 0x5b:
            self.i += 1
            first = True
            while True:
                n = self.ws()
                if n == 0x5d:
                    self.i += 1
                    return
                if n == 0x2c and not first:
                    self.i += 1
                self.skip()
                first = False
        if c == 0x7b:
            self.i += 1
            first = True
            while True:
                n = self.ws()
                if n == 0x7d:
                    self.i += 1
                    return
                if n == 0x2c and not first:
                    self.i += 1
                    self.ws()
                self.i += 1
                self.string()
                self.colon()
                self.skip()
                first = False
        if c in (0x6e, 0x74, 0x66, 0x2d, 0x22) or 0x30 <= c <= 0x39:
            bad = self.wrong_type()
            if isinstance(bad, Bad):
                return
        raise self.peek_fail('expected value')


def spec_f64(r):
    c = r.ws()
    if c is None:
        raise r.peek_fail('eof value')
    if c == 0x2d:
        r.i += 1
        kind, val = r.number(False)
    elif 0x30 <= c <= 0x39:
        kind, val = r.number(True)
    else:
        raise r.wrong_type()
    return float(val)


def spec_ntl(r):
    """Any shape reaches this visitor: a one item array is a value, an object is a type error after its closer."""
    c = r.ws()
    if c is None:
        raise r.peek_fail('eof value')
    if c == 0x5b:
        def body():
            if not r.has_element(True):
                raise Custom('invalid length')
            return spec_ntl(r)
        return r.scoped(body, r.end_seq)
    if c == 0x7b:
        def body():
            raise Custom('invalid type')
        return r.scoped(body, r.end_map)
    if c == 0x2d:
        r.i += 1
        kind, val = r.number(False)
    elif 0x30 <= c <= 0x39:
        kind, val = r.number(True)
    else:
        raise r.wrong_type()
    if kind == 'float':
        raise Bad('invalid type', r.i)
    if kind == 'int':
        raise Bad('invalid value {} for NtlPriv when visiting i64', r.i)
    return val


def tuple_of(n, item):
    def spec(r):
        c = r.ws()
        if c is None:
            raise r.peek_fail('eof value')
        if c != 0x5b:
            raise r.wrong_type()

        def body():
            out = []
            for k in range(n):
                if not r.has_element(k == 0):
                    raise Custom('invalid length')
                out.append(item(r))
            return out
        return r.scoped(body, r.end_seq)
    return spec


def seq_of(item):
    def spec(r):
        c = r.ws()
        if c is None:
            raise r.peek_fail('eof value')
        if c != 0x5b:
            raise r.wrong_type()

        def body():
            out, first = [], True
            while r.has_element(first):
                out.append(item(r))
                first = False
            return out
        return r.scoped(body, r.end_seq)
    return spec


def struct_of(fields, defaults=None):
    """fields: (key, spec); keys not listed are skipped, as this path does for every nested struct."""
    names = [f[0] for f in fields]
    defaults = defaults or {}

    def spec(r):
        c = r.ws()
        if c is None:
            raise r.peek_fail('eof value')
        if c == 0x5b:
            def body():
                out = {}
                for k, (name, item) in enumerate(fields):
                    if not r.has_element(k == 0):
                        if name in defaults:
                            out[name] = defaults[name]
                            continue
                        raise Custom('invalid length')
                    out[name] = item(r)
                return out
            return r.scoped(body, r.end_seq)
        if c != 0x7b:
            raise r.wrong_type()

        def body():
            out, first = {}, True
            while True:
                key = r.next_key(first)
                first = False
                if key is None:
                    break
                try:
                    name = key.decode()
                except UnicodeDecodeError:
                    name = ''
                if name in names:
                    if name in out:
                        raise Custom('duplicate field `%s`' % name)
                    r.colon()
                    out[name] = dict(fields)[name](r)
                else:
                    r.colon()
                    r.skip()
            for name in names:
                if name not in out:
                    if name not in defaults:
                        raise Custom('missing field `%s`' % name)
                    out[name] = defaults[name]
            return out
        return r.scoped(body, r.end_map)
    return spec


def spec_address(r):
    c = r.ws()
    if c is None:
        raise r.peek_fail('eof value')
    if c != 0x22:
        raise r.wrong_type()
    r.i += 1
    s = r.string()
    if s[:2] == b'0x':
        s = s[2:]
    if len(s) != 40:
        raise Bad('invalid length', r.i)
    for ch in s:
        if ch not in b'0123456789abcdefABCDEF':
            raise Bad('', r.i)
    return bytes.fromhex(s.decode())


def spec_bool(r):
    c = r.ws()
    if c is None:
        raise r.peek_fail('eof value')
    if c == 0x74:
        r.i += 1
        r.ident(b'rue')
        return True
    if c == 0x66:
        r.i += 1
        r.ident(b'alse')
        return False
    raise r.wrong_type()


def spec_map(r):
    c = r.ws()
    if c is None:
        raise r.peek_fail('eof value')
    twice = []
    if c == 0x5b:
        def body():
            out, first = {}, True
            while r.has_element(first):
                first = False
                r.ws()
                pair = pair_spec(r)
                if pair[0] in out:
                    twice.append(pair[0])
                out[pair[0]] = pair[1]
            if twice:
                raise Custom('duplicate key')
            return out
        return r.scoped(body, r.end_seq)
    if c == 0x7b:
        def body():
            out, first = {}, True
            while True:
                k = r.ws()
                if k == 0x7d:
                    if twice:
                        raise Custom('duplicate key')
                    return out
                if k == 0x2c and not first:
                    r.i += 1
                    k = r.ws()
                elif k is None:
                    raise r.peek_fail('eof object')
                elif not first:
                    raise r.peek_fail('expected object comma or end')
                if k == 0x7d:
                    raise r.peek_fail('trailing comma')
                if k is None:
                    raise r.peek_fail('eof object')
                if k != 0x22:
                    raise r.peek_fail('key must be a string')
                first = False
                addr = spec_address(r)
                r.colon()
                if addr in out:
                    twice.append(addr)
                out[addr] = spec_f64(r)
        return r.scoped(body, r.end_map)
    raise r.wrong_type()


def pair_spec(r):
    c = r.ws()
    if c is None:
        raise r.peek_fail('eof value')
    if c != 0x5b:
        raise r.wrong_type()

    def body():
        if not r.has_element(True):
            raise Custom('invalid length')
        a = spec_address(r)
        if not r.has_element(False):
            raise Custom('invalid length')
        return (a, spec_f64(r))
    return r.scoped(body, r.end_seq)


def optional(item):
    def spec(r):
        if r.ws() == 0x6e:
            r.i += 1
            r.ident(b'ull')
            return None
        return item(r)
    return spec


SPEC_VIP = struct_of((('ntl_cutoff', spec_ntl), ('rates', tuple_of(4, spec_f64)), ('staking_keep_frac_for_referrer', spec_f64)), dict(staking_keep_frac_for_referrer=0.0))
SPEC_MM = struct_of((('maker_fraction_cutoff', spec_f64), ('add', spec_f64)))
SPEC_TIERS = struct_of((('vip', seq_of(SPEC_VIP)), ('mm', seq_of(SPEC_MM))))
SPEC_STAKE_ROW = struct_of((('boms', spec_f64), ('discount', spec_f64)))
SPEC_STAKE = struct_of((('tiers', seq_of(SPEC_STAKE_ROW)),))
SPEC_ALIGNED = struct_of((('cross_scale', spec_f64), ('add_rebate_scale', spec_f64), ('vlm_contribution_scale', spec_f64)))
SPEC_TOP = dict(rates=tuple_of(4, spec_f64), tiers=SPEC_TIERS, referralDiscount=spec_f64, referrerKeep=spec_f64, destination=spec_address,
                extraDestinationFractions=spec_map, stakeDiscountTiers=SPEC_STAKE, weighSpotVolumeDouble=spec_bool, alignedQuoteTokenConfig=SPEC_ALIGNED)


def model_top(r):
    c = r.ws()
    if c is None:
        raise r.peek_fail('eof value')
    if c == 0x5b:
        def body():
            out = {}
            for k, name in enumerate(TOP_FIELDS):
                if not r.has_element(k == 0):
                    raise Custom('invalid length')
                out[name] = optional(SPEC_TOP[name])(r)
            return out
        return r.scoped(body, r.end_seq)
    if c != 0x7b:
        raise r.wrong_type()

    def body():
        out, first = {}, True
        while True:
            key = r.next_key(first)
            first = False
            if key is None:
                return out
            try:
                name = key.decode()
            except UnicodeDecodeError:
                name = ''
            if name not in TOP_FIELDS:
                raise Custom('unknown field `%s`, expected {}' % key.decode('latin-1'))
            if name in out:
                raise Custom('duplicate field `%s`' % name)
            r.colon()
            out[name] = optional(SPEC_TOP[name])(r)
    return r.scoped(body, r.end_map)


def position(blob, i):
    start = blob.rfind(b'\n', 0, i) + 1
    return (1 + blob.count(b'\n', 0, start), i - start)


def model(blob, depth=128):
    """(what, line, column) of the rejection, or the dict of fields."""
    r = Reader(blob, depth)
    try:
        out = model_top(r)
        if r.ws() is not None:
            raise r.peek_fail('trailing characters')
    except Bad as exc:
        return (exc.what,) + position(blob, exc.at)
    return out


# ---- evaluation of the bytes


class Panicked(Exception):
    pass


def bytes_fast(self, addr, size):
    if not size:
        return b''
    a = self.find(addr, size)
    if a is None:
        return bytes(self.load(addr + k, 1) for k in range(size))
    o = addr - a.base
    if a.strict and not all(a.valid[o:o + size]):
        raise Unmodelled(f'read of unset bytes at {addr:#x}')
    return bytes(a.mem[o:o + size])


Machine.bytes_at = bytes_fast
_load = Machine.load


def load_image(self, addr, size):
    """.data.rel.ro: a relocated pointer, or the file bytes."""
    try:
        return _load(self, addr, size)
    except Unmodelled as exc:
        if not str(exc).startswith('load'):
            raise
        if size == 8:
            try:
                return self.img.relative(addr)
            except EvidenceError:
                pass
        return int.from_bytes(self.img.read(addr, size), 'little')


Machine.load = load_image


def base_machine(ctx):
    m = machine(ctx[:4])
    m.real = ctx[4]
    m.live = {}
    m.freed = 0
    r = m.regs

    def heap(size):
        need(0 < size < 1 << 24, 'allocation size')
        a = m.arena(size)
        m.live[a.base] = size
        return a.base

    def alloc():
        m.clobber(heap(r[R['rdi']]))

    def realloc():
        old, size = r[R['rdi']], r[R['rsi']]
        need(old in m.live, 'realloc of an unknown block')
        new = heap(size)
        n = min(size, m.live.pop(old))
        src = m.find(old, n)
        m.store_bytes(new, bytes(src.mem[old - src.base:old - src.base + n]))
        m.clobber(new)

    def free():
        ptr, size = r[R['rdi']], r[R['rsi']]
        need(m.live.pop(ptr, None) == size, 'free of a block with another size')
        m.freed += 1
        m.clobber()

    def move():
        d, s, n = r[R['rdi']], r[R['rsi']], r[R['rdx']]
        need(n < 1 << 24, 'move size')
        if n:
            src = m.find(s, n)
            m.store_bytes(d, bytes(src.mem[s - src.base:s - src.base + n]) if src else m.bytes_at(s, n))
        m.clobber(d)

    def memcmp():
        n = r[R['rdx']]
        a, b = m.bytes_at(r[R['rdi']], n), m.bytes_at(r[R['rsi']], n)
        m.clobber(0 if a == b else (1 if a > b else U64))

    def text():
        out, p, args = r[R['rdi']], r[R['rsi']], r[R['rdx']]
        txt, k = b'', 0
        for _ in range(40):
            n = m.load(p, 1)
            p += 1
            if n == 0:
                break
            if n == 0xc0:
                piece = b'{}'
                if m.load(args + k * 16 + 8, 8) == STR_DISPLAY:
                    s = m.load(args + k * 16, 8)
                    piece = m.bytes_at(m.load(s, 8), m.load(s + 8, 8))
                txt += piece
                k += 1
            else:
                need(n < 0x80, 'format piece')
                txt += m.bytes_at(p, n)
                p += n
        base = heap(max(len(txt), 1))
        m.store_bytes(base, txt)
        m.store(out, 8, len(txt))
        m.store(out + 8, 8, base)
        m.store(out + 16, 8, len(txt))
        m.clobber(out)

    def make_error():
        s = r[R['rdi']]
        ptr, n = m.load(s + 8, 8), m.load(s + 16, 8)
        box = heap(0x28)
        for i, w in enumerate((0, ptr, n, 0, 0)):
            m.store(box + i * 8, 8, w)
        m.clobber(box)

    def stop():
        raise Panicked(f'call to {m.cur:#x}')

    m.stubs.update({SLOT_ALLOC: alloc, REALLOC: realloc, FREE: free, GOT_MOVE: move, GOT_MEMCMP: memcmp, GOT_MOVE2: move, WRITE_ARGS: lambda: m.clobber(0), FORMAT: text, MAKE_ERROR: make_error})
    for t in ctx[5]:
        m.stubs.setdefault(t, stop)
    return m


def run_decode(ctx, blob, depth=128, root=DECODE_A):
    m = base_machine(ctx)
    inp = m.arena(max(len(blob), 1))
    inp.mem[:len(blob)] = blob
    inp.valid[:len(blob)] = b'\1' * len(blob)
    arg = m.arena(0x30)
    for i, w in enumerate((inp.base, len(blob), 0, 0, inp.base, len(blob))):
        m.store(arg.base + i * 8, 8, w)
    res = m.arena(0x100, strict=False)
    res.mem[:] = fill_bytes(0x100, 0x17)
    if depth != 128:
        m.hooks[DEPTH_SITE_A] = lambda: m.store(m.regs[R['rsp']] + 0x50, 1, depth)
    start(m, dict(rdi=res.base, rsi=arg.base))
    m.run(root, 2000000)
    if finished(m):
        raise Unmodelled('stack or saved registers not restored')
    if m.regs[R['rax']] != res.base:
        raise Unmodelled('result pointer')
    return m, res


def tree_items(m, root, height, length):
    """The map as (key, bits) pairs in order, and the nodes it owns."""
    out, nodes = [], []

    def walk(node, h):
        nodes.append(node)
        n = m.load(node + 0x13e, 2)
        for k in range(n + 1):
            if h:
                walk(m.load(node + 0x140 + k * 8, 8), h - 1)
            if k < n:
                out.append((m.bytes_at(node + 0x60 + k * 20, 20), m.load(node + 8 + k * 8, 8)))
    if length:
        walk(root, height)
    return out, nodes


def f64s(m, a, n):
    return [m.load(a + k * 8, 8) for k in range(n)]


def observe(m, res):
    """What the bytes built: a rejection triple, or (fields, heap blocks the result owns)."""
    w = [int.from_bytes(res.mem[k:k + 8], 'little') for k in range(0, 0xe8, 8)]
    if w[0] == 2:
        e = [m.load(w[1] + k * 8, 8) for k in range(5)]
        if e[0]:
            what = CODES[e[0]]
        else:
            what = m.bytes_at(e[1], e[2]).decode('latin-1')
            for short in ('invalid type', 'invalid length'):
                if what.startswith(short):
                    what = short
        return (what, e[3], e[4]), {w[1], e[1]} if not e[0] and e[2] else {w[1]}
    out, owned = {}, set()
    if w[0] & 1:
        out['rates'] = w[1:5]
    if w[5]:
        out['referralDiscount'] = w[6]
    if w[7]:
        out['referrerKeep'] = w[8]
    if w[9] & 1:
        items, nodes = tree_items(m, w[10], w[11], w[12])
        need(len(items) == w[12], 'map length')
        out['extraDestinationFractions'] = items
        owned.update(nodes)
    if w[13] & 1:
        out['alignedQuoteTokenConfig'] = w[14:17]
    if w[17] != 1 << 63:
        need(w[17] >= w[19] and w[20] >= w[22], 'vector capacity')
        vip = [dict(rates=f64s(m, w[18] + k * 0x30, 4), ntl=m.load(w[18] + k * 0x30 + 0x20, 8), keep=m.load(w[18] + k * 0x30 + 0x28, 8)) for k in range(w[19])]
        mm = [f64s(m, w[21] + k * 0x10, 2) for k in range(w[22])]
        out['tiers'] = (vip, mm)
        owned.update(x for x, cap in ((w[18], w[17]), (w[21], w[20])) if cap)
    if w[23] != 1 << 63:
        need(w[23] >= w[25], 'vector capacity')
        out['stakeDiscountTiers'] = [f64s(m, w[24] + k * 0x10, 2) for k in range(w[25])]
        if w[23]:
            owned.add(w[24])
    if res.mem[0xd0] & 1:
        out['destination'] = bytes(res.mem[0xd1:0xe5])
    if res.mem[0xe5] != 2:
        out['weighSpotVolumeDouble'] = bool(res.mem[0xe5])
    return out, owned


def expected(value):
    """The model dict in the shape of `observe`: None and absent are the same patch."""
    out = {}
    for name, x in value.items():
        if x is None:
            continue
        if name == 'rates':
            x = [f2b(q) for q in x]
        elif name in ('referralDiscount', 'referrerKeep'):
            x = f2b(x)
        elif name == 'extraDestinationFractions':
            x = [(k, f2b(x[k])) for k in sorted(x)]
        elif name == 'alignedQuoteTokenConfig':
            x = [f2b(x[k]) for k in ('cross_scale', 'add_rebate_scale', 'vlm_contribution_scale')]
        elif name == 'tiers':
            vip = [dict(rates=[f2b(q) for q in row['rates']], ntl=row['ntl_cutoff'], keep=f2b(row['staking_keep_frac_for_referrer'])) for row in x['vip']]
            x = (vip, [[f2b(row['maker_fraction_cutoff']), f2b(row['add'])] for row in x['mm']])
        elif name == 'stakeDiscountTiers':
            x = [[f2b(row['boms']), f2b(row['discount'])] for row in x['tiers']]
        out[name] = x
    return out


def check(ctx, v):
    blob = v['doc'].encode('latin-1')
    m, res = run_decode(ctx, blob, v.get('depth', 128), v.get('root', DECODE_A))
    got, owned = observe(m, res)
    want = model(blob, v.get('depth', 128))
    if isinstance(want, tuple):
        if v.get('root') == DECODE_B:
            want = (re.sub('`[^`]*`', '`{}`', want[0]),) + want[1:]
        if got != want:
            return f'rejection {got} model {want}'
    elif isinstance(got, tuple):
        return f'bytes reject {got}, model accepts'
    elif got != expected(want):
        return f'value {got} model {expected(want)}'
    if set(m.live) != owned:
        return f'heap {len(m.live)} live blocks, result owns {len(owned)}'
    return None


# ---- vectors


A1 = '0x0102030405060708090a0b0c0d0e0f1011121314'
A2 = '0xa1b2c3d4e5f60718293a4b5c6d7e8f9001122334'
ROW = '{"ntl_cutoff":7,"rates":[0.25,0.5,0.75,1.25],"staking_keep_frac_for_referrer":0.125}'
ROW_S = '[7,[0.25,0.5,0.75,1.25],0.125]'
MMROW = '{"maker_fraction_cutoff":0.375,"add":0.625}'
STAKE_R = '{"boms":0.0625,"discount":0.1875}'
GOOD = dict(rates='[1.5,2.5,3.5,4.5]', tiers='{"vip":[%s],"mm":[%s]}' % (ROW, MMROW), referralDiscount='0.5', referrerKeep='0.25',
            destination='"%s"' % A1, extraDestinationFractions='{"%s":0.5}' % A1, stakeDiscountTiers='{"tiers":[%s]}' % STAKE_R,
            weighSpotVolumeDouble='true', alignedQuoteTokenConfig='{"cross_scale":1.5,"add_rebate_scale":2.5,"vlm_contribution_scale":3.5}')
FORMS = ('null', 'true', 'false', '0', '1', '-1', '-0', '1.5', '-1.5', '1e2', '""', '"x"', '[]', '{}', '[1]', '{"a":1}', 'nul', 'tru', 'fals', '+', ']', '}', ',')


def obj(d):
    return '{' + ','.join('"%s":%s' % kv for kv in d.items()) + '}'


def full():
    return obj(GOOD)


def seq():
    return '[' + ','.join(GOOD[k] for k in TOP_FIELDS) + ']'


def vip_doc(row):
    return obj(dict(tiers='{"vip":[%s],"mm":[]}' % row))


def mm_doc(row):
    return obj(dict(tiers='{"vip":[],"mm":[%s]}' % row))


def stake_doc(row):
    return obj(dict(stakeDiscountTiers='{"tiers":[%s]}' % row))


def aligned_doc(body):
    return obj(dict(alignedQuoteTokenConfig=body))


def struct_docs(wrap, keys, good):
    """Every field dropped, doubled, moved, of a wrong form; unknown keys; positional forms of each length."""
    out = []
    vals = [good[k] for k in keys]
    body = lambda ks: '{' + ','.join('"%s":%s' % (k, good[k]) for k in ks) + '}'
    out.append(wrap(body(keys)))
    out.append(wrap(body(reversed(keys))))
    for k in keys:
        out.append(wrap(body([x for x in keys if x != k])))
        out.append(wrap(body(list(keys) + [k])))
        out.append(wrap(body([k] + list(keys))))
        for f in FORMS[::2]:
            out.append(wrap('{' + ','.join('"%s":%s' % (x, f if x == k else good[x]) for x in keys) + '}'))
        for bad in (k[:-1], k + 'x', k.upper(), 'x' + k[1:], k[:-1] + 'x', k[1:], '', 'zzzzzzzz'):
            out.append(wrap(body([x for x in keys if x != k]).replace('{', '{"%s":1,' % bad, 1)))
    for n in range(len(keys) + 2):
        out.append(wrap('[' + ','.join(vals[:n] + ['0'] * (n - len(vals))) + ']'))
    out.append(wrap('[' + ','.join(vals) + ',]'))
    out.append(wrap('[' + ','.join(vals) + ' 1]'))
    for f in ('null', '1', '"x"', 'true'):
        out.append(wrap(f))
    out.append(wrap('{"unknown":{"a":[1,{"b":null}],"c":"x"},' + body(keys)[1:]))
    return out


def number_texts():
    rnd = random.Random(94)
    out = ['0', '-0', '0.0', '-0.0', '0e0', '0e400', '1e-400', '1e308', '1.8e308', '1e309', '-1e309', '1e-320', '5e-324', '0.1', '0.2', '0.3', '1.7976931348623157e308',
           '4.9e-324', '123456789012345678901234567890', '18446744073709551615', '18446744073709551616', '-9223372036854775808', '-9223372036854775809', '9007199254740993',
           '0.1234567890123456789012345', '1.00000000000000011102230246251565', '184467440737095516150', '18446744073709551615.5', '1844674407370955161.6', '0.18446744073709551616', '1E5', '1e+5', '1e-5',
           '1e', '1e+', '1e-', '1.', '.5', '01', '-', '-a', '1.e5', '1ex', '1.5x', '00', '-01', '1e2147483647', '12345678901234567890123e-5', '0.000000000000000000000000001e27']
    for _ in range(8):
        a, b, c = rnd.randrange(1 << rnd.randrange(1, 64)), rnd.randrange(10 ** rnd.randrange(1, 18)), rnd.randrange(-330, 310)
        out.append(rnd.choice(('%d', '-%d')) % a)
        out.append('%d.%d' % (a, b))
        out.append('%d.%de%d' % (a % 1000, b, c))
    return out


def key_docs():
    out = []
    for k in TOP_FIELDS:
        for bad in (k[:-1], k + 'x', k[:-1] + chr(ord(k[-1]) ^ 1), chr(ord(k[0]) ^ 1) + k[1:], k[:len(k) // 2] + chr(ord(k[len(k) // 2]) ^ 1) + k[len(k) // 2 + 1:], k.lower(), k.upper()):
            out.append(obj({bad: 'null'}))
        out.append('{"%s":null,"%s":null}' % (k, k))
        out.append('{"%s":%s,"%s":null}' % (k, GOOD[k], k))
    for n in range(0, 28):
        out.append('{"%s":1}' % ('k' * n))
    for k in TOP_FIELDS[:2]:
        for i in range(len(k)):
            out.append('{"%s":1}' % (k[:i] + chr(ord(k[i]) ^ 4) + k[i + 1:]))
    return out


def list_docs():
    out = []
    for n in (0, 1, 2, 3, 4, 5, 8, 9, 17):
        out.append(vip_doc(','.join(ROW.replace(':7,', ':%d,' % (k + 1)) for k in range(n))))
        out.append(mm_doc(','.join(MMROW.replace('0.375', '0.%d' % (k + 1)) for k in range(n))))
        out.append(stake_doc(','.join(STAKE_R.replace('0.0625', '0.%d' % (k + 1)) for k in range(n))))
    for bad in ('1', '[]', '{}', 'null', '"x"'):
        for n in (1, 2, 5):
            good = ','.join([ROW] * n)
            out.append(vip_doc(good + ',' + bad))
            out.append(obj(dict(tiers='{"vip":[%s],"mm":[%s,%s]}' % (good, MMROW, bad))))
            out.append(stake_doc(','.join([STAKE_R] * n) + ',' + bad))
    out.append(vip_doc(ROW + ROW))
    out.append(vip_doc(ROW + ','))
    out.append(mm_doc(MMROW + ','))
    out.append(stake_doc(STAKE_R + ','))
    out.append(obj(dict(tiers='{"mm":[%s,%s],"vip":[%s,%s]}' % (MMROW, MMROW, ROW, ROW))))
    out.append(obj(dict(tiers='{"mm":[%s],"vip":1}' % MMROW)))
    out.append(obj(dict(tiers='{"mm":[%s],"mm":[]}' % MMROW)))
    out.append(obj(dict(tiers='{"vip":[%s],"vip":[]}' % ROW)))
    out.append(obj(dict(tiers='[[%s],[%s]]' % (ROW, MMROW))))
    out.append(obj(dict(tiers='[[%s],1]' % ROW)))
    out.append(obj(dict(tiers='[[%s]]' % ROW)))
    out.append(obj(dict(stakeDiscountTiers='{"tiers":[%s],"tiers":[]}' % STAKE_R)))
    out.append(obj(dict(stakeDiscountTiers='[[%s]]' % STAKE_R)))
    out.append(obj(dict(stakeDiscountTiers='{"x":1,"tiers":[]}')))
    out.append(obj(dict(stakeDiscountTiers='{"tiers":[],"x":{"y":[1,2]}}')))
    return out


def map_docs():
    rnd = random.Random(19)
    out = []
    addrs = ['0x' + bytes(rnd.randrange(256) for _ in range(20)).hex() for _ in range(40)]
    for n in (0, 1, 2, 3, 11, 12, 13, 24, 25, 40):
        ks = addrs[:n]
        out.append(obj(dict(extraDestinationFractions='{' + ','.join('"%s":0.%d' % (k, i + 1) for i, k in enumerate(ks)) + '}')))
        out.append(obj(dict(extraDestinationFractions='[' + ','.join('["%s",0.%d]' % (k, i + 1) for i, k in enumerate(ks)) + ']')))
        ks2 = sorted(ks)
        out.append(obj(dict(extraDestinationFractions='[' + ','.join('["%s",%d.5]' % (k, i) for i, k in enumerate(ks2)) + ']')))
    d = addrs[0]
    out.append(obj(dict(extraDestinationFractions='{"%s":0.5,"%s":0.25}' % (d, d))))
    out.append(obj(dict(extraDestinationFractions='[["%s",0.5],["%s",0.25]]' % (d, d))))
    out.append(obj(dict(extraDestinationFractions='{"%s":0.5,"%s":0.25,"%s":0.125}' % (d, addrs[1], d))))
    for bad in ('[["%s"]]', '[["%s",1,2]]', '[["%s",null]]', '[[1,2]]', '[1]', '[null]', '["%s"]', '{"%s"}', '{"%s":null}', '{"%s":1,}', '{1:2}', '{"zz":1}', '{"%s":1 "%s":2}', '[["%s",1] ["%s",2]]', '[["%s",1],]', '[[]]'):
        t = bad.replace('%s', d)
        out.append(obj(dict(extraDestinationFractions=t)))
    return out


def address_docs():
    h = A1[2:]
    out = []
    for s in (A1, h, h.upper(), '0x' + h.upper(), '0X' + h, '0x', '', h[:-1], h[:-2], h + '00', h + '0', '0x0' + h, 'zz' + h[2:], h[:20] + 'g' + h[21:], h[:-1] + 'g', '0x' + h[:-1] + 'G', 'x' + h):
        out.append(obj(dict(destination='"%s"' % s)))
    for s in ('1', 'null', 'true', '[]', '{}'):
        out.append(obj(dict(destination=s)))
    return out


def text_docs():
    out = []
    f = full()
    for doc in (obj(dict(rates='[1,2,3,4]', referrerKeep='0.5')),
                ' {\n  "rates" : [ 1 , 2 ,\r\n 3 ,\t4 ] ,\n "referrerKeep" : 0.5\n } \n',
                '\n\n{"rates":[1,2,3],\n"x":1}', '{\n"rates":\n[1,2,3,4,5]\n}', '{\n"nope":1}\n', '\n1', '{"rates"\n1}', '{"rates":[1,2,3,4]\n"x"', '{} {}', '{}\n\nx', '', ' ', '\n', '{', '[', '"', 'n', 't', 'f', '-', '1', 'nu', 'null', 'true', 'false', '[]', '[null', '[null,', '[null,]', '[null null]', '{,}', '{"rates"', '{"rates":', '{"rates",', '{1', '{"rates":null,', '{"rates":null,}', '{"rates":null "x"', '{"\\u0072ates":[1,2,3,4]}', '{"r\\nates":1}', '{"r\\qates":1}', '{"r\x01ates":1}', '{"rates\\', '{"rates\\"', '{"a\\"b":1}'):
        out.append(doc)
    for cut in range(0, len(f), 9):
        out.append(f[:cut])
    s = seq()
    for cut in range(0, len(s), 19):
        out.append(s[:cut])
    return out


def all_vectors():
    docs = []
    add = lambda group, items: docs.extend((group, x) for x in items)
    add('text', text_docs())
    add('key', key_docs())
    add('whole', [full(), seq(), '{}', '[null,null,null,null,null,null,null,null,null]'])
    for k in TOP_FIELDS:
        add('field', [obj({k: GOOD[k]}), obj({k: 'null'})])
        add('forms', [obj({k: f}) for f in FORMS])
        add('forms', [full().replace('"%s":%s' % (k, GOOD[k]), '"%s":%s' % (k, f)) for f in FORMS[:4]])
        add('order', [obj({k: GOOD[k], j: GOOD[j]}) for j in TOP_FIELDS[:3] if j != k])
    add('number', [obj(dict(referralDiscount=x)) for x in number_texts()])
    add('number', [obj(dict(tiers='{"vip":[%s],"mm":[]}' % ROW.replace(':7,', ':%s,' % x))) for x in number_texts()[:40]])
    rates = dict(ntl_cutoff='7', rates='[0.25,0.5,0.75,1.25]', staking_keep_frac_for_referrer='0.125')
    add('vip', struct_docs(vip_doc, ('ntl_cutoff', 'rates', 'staking_keep_frac_for_referrer'), rates))
    add('mm', struct_docs(mm_doc, ('maker_fraction_cutoff', 'add'), dict(maker_fraction_cutoff='0.375', add='0.625')))
    add('stake row', struct_docs(stake_doc, ('boms', 'discount'), dict(boms='0.0625', discount='0.1875')))
    add('aligned', struct_docs(aligned_doc, ('cross_scale', 'add_rebate_scale', 'vlm_contribution_scale'), dict(cross_scale='1.5', add_rebate_scale='2.5', vlm_contribution_scale='3.5')))
    add('tiers', struct_docs(lambda b: obj(dict(tiers=b)), ('vip', 'mm'), dict(vip='[%s]' % ROW, mm='[%s]' % MMROW)))
    add('stake', struct_docs(lambda b: obj(dict(stakeDiscountTiers=b)), ('tiers',), dict(tiers='[%s]' % STAKE_R)))
    add('list', list_docs())
    add('map', map_docs())
    add('address', address_docs())
    out, seen = [], set()
    for group, doc in docs:
        if doc not in seen:
            seen.add(doc)
            out.append(dict(kind='decode', group=group, doc=doc))
    for depth in range(1, 8):
        for doc in (full(), seq(), '[[1,2,3,4]]', obj(dict(tiers='[[%s],[]]' % ROW_S)), obj(dict(stakeDiscountTiers='[[[1,2]]]')), obj(dict(extraDestinationFractions='[["%s",1]]' % A1))):
            out.append(dict(kind='decode', group='depth', doc=doc, depth=depth))
    copies = [v for i, v in enumerate(out) if i % 13 == 0 and 'depth' not in v]
    out += [dict(v, group='copy ' + v['group'], root=DECODE_B) for v in copies]
    return out


# ---- binding


FDE_END = {}
RANGES = {}
EXTRA_ROOTS = (0x1eb32d0, 0x1eb33e0, 0x32d5860, 0x32d5a20, 0x32d6740)


def closure(img, fdes, roots):
    """Functions the roots reach by direct and slot calls and tail jumps, stopping at the stubbed ones."""
    code, real, seen, stops = {}, {}, set(), set()
    queue = list(roots)
    while queue:
        s = queue.pop()
        if s in seen or s in stops:
            continue
        if s in STOPS or s not in fdes.by_start or s < 0x1400000 or s >= 0x4f00000 or 0x1570000 <= s < 0x1580000:
            stops.add(s)
            continue
        seen.add(s)
        end = fdes.range_of(s)['end']
        real[s] = s
        for ins in decode_range(img, s, end):
            code[ins.va] = ins
            o = ins.ops[0] if ins.ops else None
            if ins.op == 'call' and o[0] == 't':
                queue.append(o[1])
            elif ins.op == 'call' and o[0] == 'm' and o[1] is None and o[2] is None:
                try:
                    queue.append(img.relative(o[4]))
                except EvidenceError:
                    pass
            elif ins.op[0] == 'j' and ins.op != 'jmpr' and o[0] == 't' and not s <= o[1] < end:
                queue.append(o[1])
    return code, real, stops


def bind_fdes(data):
    fdes = Fdes(data)
    for s in WHOLE:
        FDE_END[s] = fdes.range_of(s)['end']
        RANGES[s] = ((s, FDE_END[s]),)
    return fdes


def scan_slots(img, code):
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
    code, real, stops = closure(img, fdes, (DECODE_A, DECODE_B) + EXTRA_ROOTS)
    slots, got = scan_slots(img, code)
    return img, code, fdes, slots, got, real, stops


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


SUBJECTS = WHOLE
WORKERS = 3
SWEEP_LIMIT = 400000


def all_sites(listing):
    sites = []
    for fn in SUBJECTS:
        rows = listing[fn]
        sites += conditional_sites(fn, rows) + field_sites(fn, rows) + imm_sites(fn, rows)
    return [x for x in sites if hashlib.sha256(b'%d %s' % (x['va'], x['kind'].encode())).digest()[0] % SITE_STEP == 0]


def try_kill(mctx, picked):
    for pos, v in enumerate(picked):
        try:
            bad = check(mctx, v)
        except (Unmodelled, Panicked, EvidenceError, KeyError, OverflowError, ValueError, TypeError, struct.error, IndexError, MemoryError, ZeroDivisionError, StopIteration, AttributeError, RecursionError, UnicodeDecodeError) as exc:
            bad = f'fault {type(exc).__name__}'
        if bad:
            picked.insert(0, picked.pop(pos))
            return (v['group'], bad[:60].replace('\t', ' ').replace('\n', ' '))
    return None


def survey_part(args):
    data, code, slots, got, real, stops, sites, vecs, reach = args
    rows = []
    for s_ in sites:
        here = reach.get(s_['va'], ())
        picked = [vecs[i] for i in here[::max(1, len(here) // SWEEP_CAP)]]
        mimg = Image(data, s_['patch'])
        mcode = dict(code)
        try:
            mcode.update({i.va: i for i in decode_subject(mimg, s_['fn'])})
        except (EvidenceError, Unmodelled, IndexError, struct.error) as exc:
            rows.append(dict(s_, killed=('decoder', str(exc)[:60].replace('\t', ' '))))
            continue
        rows.append(dict(s_, killed=try_kill((mimg, mcode, slots, got, real, stops), picked)))
    return rows


SWEEP_CAP = 25
SITE_STEP = 6
SURVIVED = 'not killed by the vectors that reach this address, capped; not proved equivalent'


def survey(data, code, slots, got, real, stops, listing, vecs, reach):
    sites = all_sites(listing)
    jobs = [(data, code, slots, got, real, stops, sites[i::WORKERS], vecs, reach) for i in range(WORKERS)]
    with multiprocessing.get_context('fork').Pool(WORKERS) as pool:
        got_rows = pool.map(survey_part, jobs)
    rows = [r for part in got_rows for r in part]
    rows.sort(key=lambda r: (SUBJECTS.index(r['fn']), r['va'], r['kind']))
    return rows


# ---- static facts


def direct_sites(img, targets, starts):
    addr_, off, size = img.sec['.text'][:3]
    blob, out = img.data, []
    pack = struct.Struct('<i').unpack_from
    i = blob.find(b'\xe8', off, off + size)
    while i != -1 and i + 5 <= off + size:
        va = addr_ + i - off
        t = va + 5 + pack(blob, i + 1)[0]
        if t in targets:
            out.append((t, va, starts[bisect.bisect_right(starts, va) - 1]))
        i = blob.find(b'\xe8', i + 1, off + size)
    return sorted(out)


def digest_of(v):
    return hashlib.sha256(repr(sorted((k, repr(x)) for k, x in v.items())).encode()).hexdigest()[:16]


def outcome_name(v):
    want = model(v['doc'].encode('latin-1'), v.get('depth', 128))
    if isinstance(want, tuple):
        return want[0].split('`')[0].strip()
    return 'patch ' + str(len([k for k, x in want.items() if x is not None]))


def key_table(img):
    out = []
    for struct_name, key, va, position_, kind, required, unknown in KEY_ROWS:
        if img.read(va, len(key)).decode('ascii') != key:
            raise EvidenceError(f'key {key} at {va:#x}')
        out.append((struct_name, str(position_), key, hex(va), kind, required, unknown))
    return out


def generate(data, out_dir, with_survey=True):
    global SEEN
    img, code, fdes, slots, got, real, stops = build(data)
    ctx = (img, code, slots, got, real, stops)
    listing = {s_: decode_subject(img, s_) for s_ in RANGES}
    subject_vas = {i.va for rows in listing.values() for i in rows}
    vecs = all_vectors()
    seen, reach = set(), {}
    outcomes = {}
    for pos, v in enumerate(vecs):
        SEEN = set()
        try:
            msg = check(ctx, v)
        except (Unmodelled, EvidenceError, Panicked, KeyError) as exc:
            msg = f'fault {type(exc).__name__} {exc}'
        if msg:
            SEEN = None
            raise EvidenceError(f"mismatch in {v['group']} {v['doc'][:90]!r}: {msg}"[:900])
        here = SEEN & subject_vas
        seen |= here
        for va in here:
            reach.setdefault(va, []).append(pos)
    SEEN = None
    missing, padding = [], 0
    for fn in listing:
        for ins in listing[fn]:
            if ins.va in seen:
                continue
            if ins.op in ('nop', 'int3'):
                padding += 1
            elif not any(a <= ins.va < b for a, b, _ in UNEXECUTED.values()):
                missing.append(ins.va)
    rows = survey(data, code, slots, got, real, stops, listing, vecs, reach) if with_survey else []
    return facts_and_files(data, out_dir, img, fdes, listing, vecs, rows, seen, padding, len(real), stops)


def facts_and_files(data, out_dir, img, fdes, listing, vecs, rows, seen, padding, helpers, stops):
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
            f.write(f"{r['kind']}\t{r['fn']:#x}\t{r['va']:#x}\t{r['op']}\t{'killed' if k else 'survived'}\t{k[0] if k else ''}\t{k[1] if k else SURVIVED}\n")
    with open(out_path / 'instructions.tsv', 'w', newline='\n') as f:
        f.write('function\tva\tsize\tbytes\tdecoded\texecuted\n')
        for fn in listing:
            for i in listing[fn]:
                f.write(f'{fn:#x}\t{i.va:#x}\t{i.size}\t{i.raw.hex()}\t{show(i)}\t{int(i.va in seen)}\n')
    with open(out_path / 'unexecuted.tsv', 'w', newline='\n') as f:
        f.write('function\tstart\tend\tinstructions\n')
        for fn in listing:
            run = []
            for i in listing[fn] + [None]:
                if i is not None and i.va not in seen and i.op not in ('nop', 'int3'):
                    run.append(i)
                elif run:
                    f.write(f'{fn:#x}\t{run[0].va:#x}\t{run[-1].va + run[-1].size:#x}\t{len(run)}\n')
                    run = []
    with open(out_path / 'schedule-schema.tsv', 'w', newline='\n') as f:
        f.write('struct\tposition\tkey\tkey_va\tvalue\trequired\tunknown_keys\n')
        for row_ in key_table(img):
            f.write('\t'.join(row_) + '\n')
    with open(out_path / 'reference-diff.tsv', 'w', newline='\n') as f:
        f.write('verdict\treference\treference_says\tbytes_say\n')
        for row_ in REFERENCE_ROWS:
            f.write('\t'.join(row_) + '\n')
    calls = direct_sites(img, {DECODE_A, DECODE_B, TOP}, starts)
    with open(out_path / 'call-sites.tsv', 'w', newline='\n') as f:
        f.write('callee\tvia\tsite\tfunction\n')
        for t, va, fn in calls:
            f.write(f'{t:#x}\tdirect\t{va:#x}\t{fn:#x}\n')
    per = {hex(fn): dict(instructions=len(listing[fn]), executed=sum(i.va in seen for i in listing[fn]), fde=hex(fdes.range_of(fn)['fde']), end=hex(FDE_END[fn])) for fn in RANGES}
    evidence = dict(
        binary=BINARY, sha256=SHA256, functions=per, pins=pins(img), helpers_interpreted=helpers, stubs=sorted(hex(x) for x in stops),
        vectors=len(vecs), mismatches=0, groups=groups, outcomes=outcomes, padding_not_executed=padding,
        swept=[hex(s) for s in SUBJECTS], sweep_cap=SWEEP_CAP, site_step=SITE_STEP,
        mutants=len(rows), killed=sum(1 for r in rows if r['killed']), survived=sum(1 for r in rows if not r['killed']),
    )
    with open(out_path / 'evidence.json', 'w', newline='\n') as f:
        json.dump(evidence, f, indent=1, sort_keys=True)
        f.write('\n')
    return evidence


def pins(img):
    out = []
    for va, want, meaning in PINS:
        got_ = img.read(va, len(want) // 2).hex()
        if got_ != want:
            raise EvidenceError(f'pin {va:#x} {got_}')
        out.append(dict(va=hex(va), bytes=got_, meaning=meaning))
    return out


UNEXECUTED = {}
EQUIVALENT = {}
PINS = (
    (0x1b2c522, 'c644245080', 'mov byte [rsp+0x50], 0x80: reader depth budget 128'),
    (0x1b2c5a8, '48c744245816000000', 'mov qword [rsp+0x58], 0x16: non space after the value is trailing characters'),
    (0x2355f9a, '483d10270000', 'cmp rax, 10000: payload length limit of the vote arm, longer gives tag 0x143'),
    (0x2359cb1, 'e82a287dff', 'call 0x1b2c4e0: the only direct call of the decoder'),
    (0x2359cce, '66c701bd00', 'mov word [rcx], 0xbd: tag of a decode failure'),
    (0x4cae559, 'e83257 6fff'.replace(' ', ''), 'call 0x43a3c90 in copy 0x4caa870'),
)
KEY_ROWS = (
    ('NewFeeSchedule', 'rates', 0x3b785c, 0, '[f64; 4] array only: cross, add, spotCross, spotAdd', 'no, null same', 'rejected'),
    ('NewFeeSchedule', 'tiers', 0x3b7b2b, 1, 'FeeTiers', 'no, null same', 'rejected'),
    ('NewFeeSchedule', 'referralDiscount', 0x202f20, 2, 'f64', 'no, null same', 'rejected'),
    ('NewFeeSchedule', 'referrerKeep', 0x3b7dc3, 3, 'f64', 'no, null same', 'rejected'),
    ('NewFeeSchedule', 'destination', 0x3b7ac9, 4, 'address text', 'no, null same', 'rejected'),
    ('NewFeeSchedule', 'extraDestinationFractions', 0x3b7dcf, 5, 'map address to f64, or array of pairs', 'no, null same', 'rejected'),
    ('NewFeeSchedule', 'stakeDiscountTiers', 0x3b7de8, 6, 'StakeDiscountTiers', 'no, null same', 'rejected'),
    ('NewFeeSchedule', 'weighSpotVolumeDouble', 0x3b7dfa, 7, 'bool', 'no, null same', 'rejected'),
    ('NewFeeSchedule', 'alignedQuoteTokenConfig', 0x3b7e0f, 8, 'aligned quote row', 'no, null same', 'rejected'),
    ('FeeTiers', 'vip', 0x3b7950, 0, 'array of VipFees', 'yes', 'skipped'),
    ('FeeTiers', 'mm', 0x3b7953, 1, 'array of MmFees', 'yes', 'skipped'),
    ('VipFees', 'ntl_cutoff', 0x3b7852, 0, 'u64, or a one item array of it; negative refused by text', 'yes', 'skipped'),
    ('VipFees', 'rates', 0x3b785c, 1, '[f64; 4] array only', 'yes', 'skipped'),
    ('VipFees', 'staking_keep_frac_for_referrer', 0x3b7861, 2, 'f64', 'no, default 0.0', 'skipped'),
    ('MmFees', 'maker_fraction_cutoff', 0x3b768b, 0, 'f64', 'yes', 'skipped'),
    ('MmFees', 'add', 0x3b76a0, 1, 'f64', 'yes', 'skipped'),
    ('StakeDiscountTiers', 'tiers', 0x3b7b2b, 0, 'array of StakeDiscount', 'yes', 'skipped'),
    ('StakeDiscount', 'boms', 0x209e00, 0, 'f64', 'yes', 'skipped'),
    ('StakeDiscount', 'discount', 0x20a928, 1, 'f64', 'yes', 'skipped'),
    ('aligned quote row', 'cross_scale', 0x3b84d4, 0, 'f64', 'yes', 'skipped'),
    ('aligned quote row', 'add_rebate_scale', 0x206fa0, 1, 'f64', 'yes', 'skipped'),
    ('aligned quote row', 'vlm_contribution_scale', 0x3b84df, 2, 'f64', 'yes', 'skipped'),
)
REFERENCE_ROWS = (
    ('wrong', 'action/vote_global.rs struct FeeSchedule', 'nine u64 words: base_fee_bps, max_maker_rebate_bps and so on', 'a JSON text of at most 10000 bytes, nine optional parts, see schedule-schema.tsv; f64 rates, two tier arrays, a map, a bool'),
    ('absent', 'l1 (no text hit of referrerKeep, weighSpotVolumeDouble, alignedQuoteTokenConfig)', 'no model of the wire form', 'whole key table in schedule-schema.tsv'),
    ('wrong', 'l1/fees/compute.rs MmFees and VipFees field casing', 'no row type', 'top keys are camelCase, nested keys snake_case, in one payload'),
)


def main():
    ap = argparse.ArgumentParser(description=__doc__.split('\n')[0])
    ap.add_argument('--out', required=True)
    args = ap.parse_args()
    data = (ROOT / BINARY).read_bytes()
    ev = generate(data, args.out)
    print(json.dumps(dict(vectors=ev['vectors'], mutants=ev['mutants'], killed=ev['killed']), sort_keys=True))


if __name__ == '__main__':
    main()
