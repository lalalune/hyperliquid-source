#!/usr/bin/env python3
"""fees: node #94 referral code registration, from bytes alone.

Static, no execution of the node.  The wrapper 0x27e30a0 and the helper 0x3744eb0 are decoded from ELF bytes
by the table decoder below, which must land exactly on each FDE end, and interpreted in Python on every
vector, in both modes of the stack flag.  The hash, the B-tree entry helpers, the overflow recorder and
allocation are stubs that check their arguments.  Each outcome is compared with a separate closed-form model,
then every conditional, field offset and immediate of the two functions is mutated to test the vectors.

    python3 tools/fees_register_referrer.py --out <dir>

writes evidence.json, vectors.tsv, mutations.tsv, instructions.tsv and reference-diff.tsv.  Section and FDE
parsing come from tools/elf_index.py and tools/fde_extents.py.  Only the standard library is used: no
objdump, readelf or other external program runs, so the results cannot depend on a binutils version.
"""


import argparse
import bisect
import hashlib
import json
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

WRAPPER = 0x27e30a0
HELPER = 0x3744eb0
DECODED = (WRAPPER, HELPER)
# flag 1 arm inside 0x2355f40: read action, length and limit tests; the error store; the call
ARM = 0x2356a11
ARM_END = 0x2356a99
ARM_ERROR = 0x23599c7
ARM_ERROR_END = 0x23599de
ARM_CALL = 0x235a776
ARM_CALL_END = 0x235a7b0
ARM_PIECES = ((ARM, ARM_END), (ARM_ERROR, ARM_ERROR_END), (ARM_CALL, ARM_CALL_END))
ARM_DONE = 0x2359a2f
ARM_FAILED = 0x235b25c
ARM_FLAG_SITES = (0x235a799, 0x4caf0ba, 0x4cb7a4a)
SUBJECTS = DECODED + tuple(a for a, _ in ARM_PIECES)
WRAPPER_COPIES = (0x46ba8b0, 0x46ba950)
HELPER_SLOT = 0x5773e28
RECORDER_SLOT = 0x5773190
HASH = 0x399c7a0
RECORDER = 0x358dcd0
CODE_REMOVE = 0x33adba0
CODE_INSERT = 0x339a090
PROFILE_VACANT = 0x33c2c80
CODE_VACANT = 0x33bfa30
GOT_ALLOC = 0x576dfd8
GOT_MEMCPY = 0x576dfe0
GOT_FREE = 0x576e010
GOT_MEMCMP = 0x576e488
GOT_ALLOC_ERROR = 0x576dfb8
GOT_NONE = 0x576e470
OVERFLOW_LOCATION = 0x56f2138
NONE_LOCATION = 0x56e9fe8
OK = 0x186
TOO_LONG_HELPER = 0xa0
CODE_TAKEN = 0xa3
USER_TAKEN = 0xa4
LOW_VOLUME = 0xa5
TOO_LONG_ENTRY = 0x143
BAD_NUMBER = 0x13f
STATUSES = (OK, TOO_LONG_HELPER, CODE_TAKEN, USER_TAKEN, LOW_VOLUME, TOO_LONG_ENTRY, BAD_NUMBER)
ARM_LIMIT = 0xccccccccccccccc
TAG_OK = 13
TAG_ERR = 14
MAX_CODE = 100
MIN_VOLUME = 1000000
SATURATED = U64
STRIDE = 0xe8
TRACKER_SIZE = 0x200
EXCHANGE_TRACKER = 0x5d0
TABLE = 0xc0
ROW_ROOT = 0xb0
ROW_HEIGHT = 0xb8
ROW_LEN = 0xc0
PROFILES = 0x108
CODES = 0x120
PROFILE_SIZE = 0x48
PROFILE_KEPT = (0x18, 0x38)
PINNED = (
    (0x27e30ac, '4983f865', 'wrapper: compare the code length with 0x65'),
    (0x27e30b2, '66c743084301', 'wrapper: tag 0x143'),
    (0x27e30be, '4881c1d0050000', 'wrapper: tracker is exchange +0x5d0'),
    (0x27e30c9, 'c7042400000000', 'wrapper: stack flag 0'),
    (0x27e30db, '4531c9', 'wrapper: r9 = 0'),
    (0x3744ecc, '80bc247001000000', 'helper: stack flag test'),
    (0x3744edb, '4983f864', 'helper: length limit 100'),
    (0x3744ee5, '66 41c70424a000'.replace(' ', ''), 'helper: tag 0xa0'),
    (0x37454e0, '4881f940420f00', 'helper: volume threshold 1000000'),
    (0x37454f3, '6641c70424a500', 'helper: tag 0xa5'),
)
REFERENCE_FILE = 'handlers/15_register_referrer.rs'
STACK_FILL = bytes((i * 5 + 3) & 0xff | 1 for i in range(0x8000))


SEEN = None


class Panicked(Exception):
    """The node would panic here; a modelled outcome, unlike Unmodelled."""


def addr(n):
    """A 20-byte test address."""
    return hashlib.sha256(b'addr' + str(n).encode()).digest()[:20]


def key_hash(key):
    return int.from_bytes(hashlib.sha256(key).digest()[:8], 'little')


# ---- model, written from the observed rules and independent of the machine


def saturating_sum(values):
    """Sum with a stop at the top of u64; the count is of additions that overflowed."""
    total, over = 0, 0
    for x in values:
        if total + x > U64:
            total, over = U64, over + 1
        else:
            total += x
    return total, over


def model(v):
    """Status and effect of one call.  The effect names the code entries and the profile touched."""
    code, user = v['code'], v['user']
    if v['entry'] != 'helper' and len(code) > MAX_CODE:
        return dict(status=TOO_LONG_ENTRY, effect=(), overflows=0)
    if v['entry'] == 'arm' and v['tag'] and v['value'] >= ARM_LIMIT:
        return dict(status=BAD_NUMBER, effect=(), overflows=0)
    over = 0
    profiles, codes = v['profiles'], v['codes']
    extra = {'wrapper': 0, 'helper': v['extra'], 'arm': v['value'] if v.get('tag') else 0}[v['entry']]
    if v['flag']:
        if len(code) > MAX_CODE:
            return dict(status=TOO_LONG_HELPER, effect=(), overflows=0)
        if user in profiles:
            owner = codes.get(code)
            if owner is not None and owner != user:
                return dict(status=CODE_TAKEN, effect=(), overflows=0)
            return dict(status=OK, effect=(('remove', profiles[user]), ('insert', code, user), ('profile', user, code, extra, True)), overflows=0)
    else:
        if v['volume'] is None or not v['volume'] or v.get('items') == 0 or 'root_zero' in v or v.get('length') == 0:
            return dict(status=LOW_VOLUME, effect=(), overflows=0)
        total, over = saturating_sum(v['volume'])
        if total < MIN_VOLUME:
            return dict(status=LOW_VOLUME, effect=(), overflows=over)
        if len(code) > MAX_CODE:
            return dict(status=TOO_LONG_HELPER, effect=(), overflows=over)
        if user in profiles:
            return dict(status=USER_TAKEN, effect=(), overflows=over)
    if code in codes:
        return dict(status=CODE_TAKEN, effect=(), overflows=over)
    return dict(status=OK, effect=(('profile', user, code, extra, False), ('insert', code, user)), overflows=over)


# ---- B-tree nodes, written by this tool in the three layouts the helper reads


class Layout:
    def __init__(self, leaf_size, items, stride, parent, parent_index, length, edges):
        self.leaf_size, self.items, self.stride = leaf_size, items, stride
        self.parent, self.parent_index, self.length, self.edges = parent, parent_index, length, edges


# value at +0 (stride 0x30), parent +0x210, parent index +0x270, length +0x272, edges +0x278
TOKENS = Layout(0x278, 0, 0x30, 0x210, 0x270, 0x272, 0x278)
# parent +0, value +8 (0x48), key +0x320 (20), parent index +0x3fc, length +0x3fe, edges +0x400
PROFILE_NODE = Layout(0x400, 8, PROFILE_SIZE, 0, 0x3fc, 0x3fe, 0x400)
# parent +0, key +8 (String), value +0x110 (20), parent index +0x1ec, length +0x1ee, edges +0x1f0
CODE_NODE = Layout(0x1f0, 8, 0x18, 0, 0x1ec, 0x1ee, 0x1f0)


def split_shape(n, height, fan):
    """Sizes of the children of a node holding n items: keys of this node plus children are n."""
    room = 12 ** height - 1
    keys = min(fan, 11, max(n - 1, 1))
    while (keys + 1) * room + keys < n:
        keys += 1
    rest = n - keys
    base, extra = rest // (keys + 1), rest % (keys + 1)
    return [base + (i < extra) for i in range(keys + 1)]


def tree_height(n, fan):
    """Height that holds n items at this fan; a fan of 1 gives a tall thin tree."""
    h, room = 0, 11
    width = min(fan, 11) + 1
    while room < n:
        h += 1
        room = room * width + width - 1
    return h


class Tree:
    """Nodes in one arena.  `fill` writes item i at the slot address, a pattern fills the gaps."""

    def __init__(self, m, layout, items, fan, fill, pattern, height=None):
        self.m, self.lay, self.items, self.fan, self.fill = m, layout, items, fan, fill
        self.height = tree_height(len(items), fan) if height is None else height
        self.places = {}
        size = self.count(len(items), self.height)
        self.arena = m.arena(max(size, 8))
        self.arena.mem[:] = fill_bytes(len(self.arena.mem), pattern)
        self.arena.valid[:] = b'\1' * len(self.arena.mem)
        self.top = 0
        self.root = self.node(0, len(items), self.height, 0, 0) if items else 0

    def count(self, n, h):
        if h == 0:
            return self.lay.leaf_size
        return self.lay.leaf_size + 96 + sum(self.count(c, h - 1) for c in split_shape(n, h, self.fan))

    def word(self, at, size, val):
        self.arena.mem[at:at + size] = val.to_bytes(size, 'little')

    def node(self, first, n, h, parent, slot):
        lay = self.lay
        at = self.top
        self.top += lay.leaf_size + (96 if h else 0)
        base = self.arena.base + at
        self.word(at + lay.parent, 8, parent)
        self.word(at + lay.parent_index, 2, slot)
        if h == 0:
            self.word(at + lay.length, 2, n)
            for i in range(n):
                self.place(first + i, at, i)
            return base
        sizes = split_shape(n, h, self.fan)
        self.word(at + lay.length, 2, len(sizes) - 1)
        i = first
        for pos, c in enumerate(sizes):
            kid = self.node(i, c, h - 1, base, pos)
            self.word(at + lay.edges + 8 * pos, 8, kid)
            i += c
            if pos < len(sizes) - 1:
                self.place(i, at, pos)
                i += 1
        return base

    def place(self, i, at, pos):
        self.places[i] = (at, pos)
        self.fill(self, at, pos, self.items[i])

    def snapshot(self):
        return bytes(self.arena.mem)


FILLS = {}


def fill_bytes(n, seed):
    """A position-dependent pattern, so a shifted read or a stray write shows."""
    if (n, seed) not in FILLS:
        FILLS[n, seed] = bytes((i * 11 + seed + (i >> 8)) & 0xff for i in range(n))
    return FILLS[n, seed]


def fill_token(tree, at, pos, value):
    tree.word(at + 0x30 * pos, 8, value)


def tracker_of(m, v):
    a = m.arena(TRACKER_SIZE)
    a.mem[:] = fill_bytes(TRACKER_SIZE, 0x41)
    a.valid[:] = b'\1' * TRACKER_SIZE
    return a


def word(a, off, size, val):
    a.mem[off:off + size] = val.to_bytes(size, 'little')


def table_of(m, v, tr):
    """One hash table.  v['decoys'] lists (key, hash); the user's row comes from v['volume'].  With 'third' the
    table has 128 slots and the row sits at the third probe, 48 slots on, so the probe step shows."""
    size = 128 if 'third' in v else 32
    rows = list(v.get('decoys', ()))
    at_user = None
    if v['volume'] is not None:
        rows.append((v['user'], m.hashes.get(v['user'], key_hash(v['user']))))
        at_user = len(rows) - 1
    a = m.arena(STRIDE * size + size + 32)
    a.mem[:] = fill_bytes(len(a.mem), 0x17)
    a.valid[:] = b'\1' * len(a.mem)
    ctrl_off = STRIDE * size + 16
    ctrl = [0xff] * size
    placed = {}
    for i, (key, h) in enumerate(rows):
        pos = h & (size - 1)
        if i == at_user and 'third' in v:
            pos = (pos + 48) & (size - 1)
        while ctrl[pos] != 0xff:
            pos = (pos + 1) & (size - 1)
        ctrl[pos] = h >> 57
        row = ctrl_off - (pos + 1) * STRIDE
        placed[i] = row
        a.mem[row:row + 20] = key
        if i != at_user:
            for off in (ROW_ROOT, ROW_HEIGHT, ROW_LEN):
                word(a, row + off, 8, 0)
    for i in range(size):
        a.mem[ctrl_off + i] = ctrl[i]
    for i in range(16):
        a.mem[ctrl_off + size + i] = ctrl[i]
    word(tr, TABLE, 8, a.base + ctrl_off)
    word(tr, TABLE + 8, 8, size - 1)
    word(tr, TABLE + 0x10, 8, 2)
    word(tr, TABLE + 0x18, 8, v.get('items', len(rows)))
    if at_user is not None:
        row = placed[at_user]
        tree = Tree(m, TOKENS, v['volume'], v.get('fan', 11), fill_token, 0x33, v.get('height'))
        m.tokens = tree
        word(a, row + ROW_ROOT, 8, tree.root)
        word(a, row + ROW_HEIGHT, 8, tree.height)
        word(a, row + ROW_LEN, 8, v.get('length', len(v['volume'])))
        if 'root_zero' in v:
            word(a, row + ROW_ROOT, 8, 0)
        m.row = row
    return a


def string_at(m, tree, at, text):
    """A heap String with spare capacity, so a free with the wrong size shows."""
    if not text:
        tree.word(at, 8, 0)
        tree.word(at + 8, 8, 1)
        tree.word(at + 0x10, 8, 0)
        return None
    cap = len(text) + 3
    block = m.arena(cap)
    block.mem[:len(text)] = text
    block.valid[:len(text)] = b'\1' * len(text)
    m.live[block.base] = cap
    tree.word(at, 8, cap)
    tree.word(at + 8, 8, block.base)
    tree.word(at + 0x10, 8, len(text))
    return block


def fill_profile(tree, at, pos, item):
    key, text = item
    base = at + 8 + PROFILE_SIZE * pos
    string_at(tree.m, tree, base, text)
    tree.arena.mem[at + 0x320 + 20 * pos:at + 0x334 + 20 * pos] = key
    tree.m.profile_places[key] = base


def fill_code(tree, at, pos, item):
    text, owner = item
    string_at(tree.m, tree, at + 8 + 0x18 * pos, text)
    tree.arena.mem[at + 0x110 + 20 * pos:at + 0x124 + 20 * pos] = owner


def machine(img, code, slots, got):
    m = Machine(img, ())
    if SEEN is not None:
        m.seen = SEEN
    m.code = code
    m.slots = slots
    m.got = got
    m.real[WRAPPER] = WRAPPER
    m.real[HELPER] = HELPER
    stack = m.arena(0x8000, strict=False)
    stack.mem[:] = STACK_FILL
    m.stack = stack
    m.top = stack.base + 0x7f08
    m.live = {}
    m.hashes = {}
    m.calls = []
    m.overflows = 0
    m.profile_places = {}
    m.alloc_left = None
    m.user = m.code_ptr = m.tracker = None
    m.key_blocks = []

    def alloc():
        if m.alloc_left is not None:
            m.alloc_left -= 1
            if m.alloc_left < 0:
                return m.clobber(0)
        if m.regs[R['rdi']] != m.code_size:
            raise Unmodelled('allocation size')
        a = m.arena(m.regs[R['rdi']])
        m.live[a.base] = m.regs[R['rdi']]
        return m.clobber(a.base)

    def release():
        if m.live.pop(m.regs[R['rdi']], None) != m.regs[R['rsi']] or m.regs[R['rdx']] != 0:
            raise Unmodelled('free of another block')
        m.clobber()

    def memcpy():
        d, s, n = m.regs[R['rdi']], m.regs[R['rsi']], m.regs[R['rdx']]
        blob = bytes(m.load(s + k, 1) for k in range(n))
        for k, b in enumerate(blob):
            m.store(d + k, 1, b)
        m.clobber(d)

    def memcmp():
        a, b, n = m.regs[R['rdi']], m.regs[R['rsi']], m.regs[R['rdx']]
        x = bytes(m.load(a + k, 1) for k in range(n))
        y = bytes(m.load(b + k, 1) for k in range(n))
        m.clobber(0 if x == y else (1 if x > y else (1 << 32) - 1) * (m.memcmp_scale or 1) & 0xffffffff)

    def hash_stub():
        if m.regs[R['rdi']] != m.tracker + 0xe0:
            raise Unmodelled('hash state')
        key = bytes(m.load(m.regs[R['rsi']] + k, 1) for k in range(20))
        m.clobber(m.hashes.get(key, key_hash(key)))

    def recorder():
        if m.regs[R['rdi']] != 0 or m.regs[R['rsi']] != OVERFLOW_LOCATION:
            raise Unmodelled('overflow recorder arguments')
        m.overflows += 1
        m.clobber()

    def bytes_of(ptr, n):
        return bytes(m.load(ptr + k, 1) for k in range(n))

    def string(ptr):
        return bytes_of(m.load(ptr + 8, 8), m.load(ptr + 0x10, 8))

    def frame(off):
        return m.regs[R['rsp']] + off

    def code_remove():
        r = m.regs
        if r[R['rsi']] != m.tracker + CODES or r[R['rdi']] != frame(0x50):
            raise Unmodelled('remove map')
        m.calls.append(('remove', string(r[R['rdx']])))
        m.clobber()

    def code_insert():
        r = m.regs
        if r[R['rsi']] != m.tracker + CODES or r[R['rdi']] != frame(0x118) or r[R['rdx']] != frame(0x50):
            raise Unmodelled('insert map')
        at = r[R['rdx']]
        cap, ptr, n = m.load(at, 8), m.load(at + 8, 8), m.load(at + 0x10, 8)
        if cap != n or (n == 0 and ptr != 1):
            raise Unmodelled('insert key shape')
        m.calls.append(('insert', bytes_of(ptr, n), bytes_of(r[R['rcx']], 20)))
        m.live.pop(ptr, None)
        m.clobber()

    def profile_vacant():
        r = m.regs
        e, val = r[R['rsi']], r[R['rdx']]
        if m.load(e, 8) != m.tracker + PROFILES or m.load(e + 0x10, 8) != 0 or e != frame(0x98) or val != frame(0xd0) or r[R['rdi']] != frame(0x50):
            raise Unmodelled('profile entry')
        got_at = m.load(e + 8, 8), m.load(e + 0x18, 8)
        if got_at != m.want_profile and not (got_at[0] == 0 and m.want_profile == 0):
            raise Unmodelled('profile place')
        cap, ptr, n = m.load(val, 8), m.load(val + 8, 8), m.load(val + 0x10, 8)
        if cap != n or (n == 0 and ptr != 1):
            raise Unmodelled('profile string')
        for off in (0x18, 0x20, 0x30, 0x38):
            if m.load(val + off, 8):
                raise Unmodelled(f'profile word {off:#x}')
        m.calls.append(('profile', bytes_of(e + 0x20, 20), bytes_of(ptr, n), m.load(val + 0x40, 8), False))
        m.live.pop(ptr, None)
        m.clobber()

    def code_vacant():
        r = m.regs
        e = r[R['rsi']]
        cap, ptr, n = m.load(e, 8), m.load(e + 8, 8), m.load(e + 0x10, 8)
        if cap != n or (n == 0 and ptr != 1) or m.load(e + 0x18, 8) != m.tracker + CODES or m.load(e + 0x28, 8) != 0 or e != frame(0x50) or r[R['rdi']] != frame(0x118):
            raise Unmodelled('code entry')
        got_at = m.load(e + 0x20, 8), m.load(e + 0x30, 8)
        if got_at != m.want_code and not (got_at[0] == 0 and m.want_code == 0):
            raise Unmodelled('code place')
        m.calls.append(('insert', bytes_of(ptr, n), bytes_of(r[R['rdx']], 20)))
        m.live.pop(ptr, None)
        m.clobber()

    def alloc_error():
        if m.regs[R['rdi']] != 1 or m.regs[R['rsi']] != m.code_size:
            raise Unmodelled('alloc error arguments')
        raise Panicked('allocation')

    def none_panic():
        if m.regs[R['rdi']] != NONE_LOCATION:
            raise Unmodelled('unwrap location')
        raise Panicked('none')

    m.memcmp_scale = 1
    m.stubs.update({HASH: hash_stub, RECORDER: recorder, CODE_REMOVE: code_remove, CODE_INSERT: code_insert, PROFILE_VACANT: profile_vacant, CODE_VACANT: code_vacant})
    for s, fn in ((GOT_ALLOC, alloc), (GOT_MEMCPY, memcpy), (GOT_FREE, release), (GOT_MEMCMP, memcmp), (GOT_ALLOC_ERROR, alloc_error), (GOT_NONE, none_panic)):
        m.stubs[slots[s]] = fn
    return m


def enter(m, fn, flag, *args):
    m.regs[R['rsp']] = m.top
    m.store(m.top, 8, 0xfeedface)
    m.store(m.top + 8, 8, 0xabcdef0012345600 | flag)
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


def place_of(tree, want):
    """Leaf and index where a missing key belongs, by a walk over the written node bytes."""
    if not tree.root:
        return 0
    lay = tree.lay
    at, h = tree.root - tree.arena.base, tree.height
    mem = tree.arena.mem
    while True:
        n = int.from_bytes(mem[at + lay.length:at + lay.length + 2], 'little')
        pos = 0
        while pos < n and tree.key_at(at, pos) < want:
            pos += 1
        if h == 0:
            return tree.arena.base + at, pos
        at = int.from_bytes(mem[at + lay.edges + 8 * pos:at + lay.edges + 8 * pos + 8], 'little') - tree.arena.base
        h -= 1


def profile_key(tree, at, pos):
    return bytes(tree.arena.mem[at + 0x320 + 20 * pos:at + 0x334 + 20 * pos])


def code_key(tree, at, pos):
    m = tree.m
    cap_at = at + 8 + 0x18 * pos
    ptr = int.from_bytes(tree.arena.mem[cap_at + 8:cap_at + 16], 'little')
    n = int.from_bytes(tree.arena.mem[cap_at + 16:cap_at + 24], 'little')
    return bytes(m.load(ptr + k, 1) for k in range(n))


def run(img, code, slots, got, v):
    """One call on a fresh state.  Returns status, overflow count, stub calls, machine and state."""
    m = machine(img, code, slots, got)
    m.alloc_left = v.get('alloc')
    m.code_size = len(v['code'])
    m.memcmp_scale = v.get('scale', 1)
    tr = tracker_of(m, v)
    m.tracker = tr.base
    table = table_of(m, v, tr)
    profiles = Tree(m, PROFILE_NODE, sorted(v['profiles'].items()), v.get('fan', 11), fill_profile, 0x55)
    profiles.key_at = lambda at, pos: profile_key(profiles, at, pos)
    codes = Tree(m, CODE_NODE, sorted(v['codes'].items()), v.get('fan', 11), fill_code, 0x77)
    codes.key_at = lambda at, pos: code_key(codes, at, pos)
    word(tr, PROFILES, 8, profiles.root)
    word(tr, PROFILES + 8, 8, profiles.height)
    word(tr, PROFILES + 0x10, 8, len(v['profiles']))
    word(tr, CODES, 8, codes.root)
    word(tr, CODES + 8, 8, codes.height)
    word(tr, CODES + 0x10, 8, len(v['codes']))
    m.want_profile = place_of(profiles, v['user'])
    m.want_code = place_of(codes, v['code'])
    snap = (bytes(tr.mem), bytes(table.mem), profiles.snapshot(), codes.snapshot())
    user = m.arena(20)
    user.mem[:] = v['user']
    user.valid[:] = b'\1' * 20
    text = m.arena(max(len(v['code']), 1))
    text.mem[:len(v['code'])] = v['code']
    text.valid[:len(v['code'])] = b'\1' * len(v['code'])
    before = dict(m.live)
    if v['entry'] == 'wrapper':
        action = m.arena(0x18)
        action.mem[:] = struct.pack('<QQQ', 0x4444444444444444, text.base, len(v['code']))
        action.valid[:] = b'\1' * 0x18
        out = m.arena(0x70, strict=False)
        out.mem[:] = fill_bytes(0x70, 0x21)
        # the wrapper adds 0x5d0: a pointer below the tracker lands on it
        enter(m, WRAPPER, 0, out.base, action.base, user.base, tr.base - EXCHANGE_TRACKER)
        tag = out.mem[0]
        if m.regs[0] != out.base:
            raise Unmodelled('return value')
        if tag == TAG_OK:
            status = OK
            if bytes(out.mem[1:]) != fill_bytes(0x70, 0x21)[1:]:
                raise Unmodelled('success wrote the output')
        elif tag == TAG_ERR:
            status = int.from_bytes(out.mem[8:10], 'little')
            if status == OK:
                raise Unmodelled('error tag with the success status')
            if status == TOO_LONG_ENTRY:
                if int.from_bytes(out.mem[0x10:0x18], 'little') != action.base or bytes(out.mem[0x18:]) != fill_bytes(0x70, 0x21)[0x18:]:
                    raise Unmodelled('action pointer word')
            else:
                frame = m.top - 8 - 0x70 + 0x10 - m.stack.base
                if bytes(out.mem[8:0x68]) != bytes(m.stack.mem[frame:frame + 0x60]):
                    raise Unmodelled('error copy')
        else:
            raise Unmodelled(f'outer tag {tag}')
    elif v['entry'] == 'arm':
        status = run_arm(m, v, tr, text, len(v['code']))
    else:
        out = m.arena(0x10, strict=False)
        enter(m, HELPER, v['flag'], out.base, tr.base, user.base, text.base, len(v['code']), v['extra'])
        status = int.from_bytes(out.mem[0:2], 'little')
        if m.regs[0] != out.base:
            raise Unmodelled('return value')
    return status, m, (tr, table, profiles, codes), snap, before


class ArmStop(Exception):
    pass


def run_arm(m, v, tr, text, size):
    """The flag 1 arm from 0x2356a11 up to the first address past it.  Returns the status it left."""
    action = m.arena(0x48)
    action.mem[:] = fill_bytes(0x48, 0x63)
    action.valid[:] = b'\1' * 0x48
    word(action, 8, 8, v['tag'])
    word(action, 0x10, 8, v['value'])
    word(action, 0x18, 8, 0x4444444444444444)
    word(action, 0x20, 8, text.base)
    word(action, 0x28, 8, size)
    action.mem[0x30:0x44] = v['user']
    out = m.arena(0x10, strict=False)
    out.mem[:] = fill_bytes(0x10, 0x29)
    rsp = m.stack.base + 0x1800
    m.store(rsp, 8, out.base)
    for name, val in (('r15', action.base), ('r13', tr.base - EXCHANGE_TRACKER), ('rsp', rsp)):
        m.regs[R[name]] = val

    def stop(va):
        def at():
            raise ArmStop(va)
        return at
    for va in (ARM_DONE, ARM_FAILED, ARM_CALL_END):
        m.hooks[va] = stop(va)
    try:
        m.run(ARM)
    except ArmStop as exc:
        where = exc.args[0]
    else:
        raise Unmodelled('arm returned')
    if m.regs[R['rsp']] != rsp:
        raise Unmodelled('stack not balanced')
    if where == ARM_CALL_END:
        if m.load(rsp + 0x20, 2) != OK:
            raise Unmodelled('success path with a failure')
        return OK
    if where == ARM_FAILED:
        status = m.load(rsp + 0x20, 2)
        if status == OK:
            raise Unmodelled('failure path with success')
        return status
    if where != ARM_DONE:
        raise Unmodelled('arm end')
    status = int.from_bytes(out.mem[0:2], 'little')
    want = {TOO_LONG_ENTRY: rsp + 0x130, BAD_NUMBER: v['value']}.get(status)
    if status == TOO_LONG_ENTRY and (m.load(rsp + 0x138, 8), m.load(rsp + 0x140, 8)) != (text.base, size):
        raise Unmodelled('arm string copy')
    if int.from_bytes(out.mem[8:16], 'little') != want:
        raise Unmodelled('arm error word')
    head = bytes(out.mem[2:8])
    if head != (bytes(6) if status == BAD_NUMBER else fill_bytes(0x10, 0x29)[2:8]):
        raise Unmodelled('arm error head')
    return status


def check(img, code, slots, got, v):
    want = None if 'panic' in v else model(v)
    try:
        status, m, parts, snap, before = run(img, code, slots, got, v)
    except Panicked as exc:
        if v.get('panic') == str(exc):
            return None
        raise
    if 'panic' in v:
        return f"no {v['panic']} panic"
    if status != want['status']:
        return f"status {status:#x} != {want['status']:#x}"
    if m.overflows != want['overflows']:
        return f"overflows {m.overflows} != {want['overflows']}"
    tr, table, profiles, codes = parts
    if bytes(tr.mem) != snap[0] or bytes(table.mem) != snap[1] or codes.snapshot() != snap[3]:
        return 'state moved outside the entries'
    row_change = None
    effect = list(want['effect'])
    if effect and effect[-1][0] == 'profile' and effect[-1][4]:
        row_change = effect.pop()
    if m.calls != effect:
        return f'entry helper calls differ: {len(m.calls)} and {len(effect)}'
    now = profiles.snapshot()
    if row_change is None:
        if now != snap[2]:
            return 'profile node changed'
    else:
        base = m.profile_places[v['user']]
        old = bytearray(snap[2])
        size = len(row_change[2])
        ptr = int.from_bytes(now[base + 8:base + 16], 'little')
        kept = old[base + PROFILE_KEPT[0]:base + PROFILE_KEPT[1]]
        if now[base + PROFILE_KEPT[0]:base + PROFILE_KEPT[1]] != kept:
            return 'kept profile words moved'
        new = struct.pack('<QQQ', size, ptr, size)
        tail = struct.pack('<QQ', 0, row_change[3])
        old[base:base + 0x18] = new
        old[base + 0x38:base + 0x48] = tail
        if bytes(old) != now:
            return 'profile row'
        if (size == 0 and ptr != 1) or (size and bytes(m.load(ptr + k, 1) for k in range(size)) != row_change[2]):
            return 'profile code bytes'
        if size:
            m.live.pop(ptr, None)
    left = dict(before)
    if row_change is not None:
        old_ptr = int.from_bytes(snap[2][m.profile_places[v['user']] + 8:m.profile_places[v['user']] + 16], 'little')
        left.pop(old_ptr, None)
    if m.live != left:
        return 'leaked or lost a block'
    return None


# ---- vectors


class Lcg:
    def __init__(self, seed):
        self.s = seed

    def next(self, n):
        self.s = (self.s * 6364136223846793005 + 1442695040888963407) & U64
        return (self.s >> 33) % n


def vec(group, entry='helper', flag=0, user=None, code=b'abc', profiles=None, codes=None, volume=(MIN_VOLUME,), extra=0, **kw):
    return dict(group=group, entry=entry, flag=flag, user=user or addr(1), code=code, profiles=dict(profiles or {}), codes=dict(codes or {}),
                volume=None if volume is None else list(volume), extra=extra, **kw)


def pair(n, text):
    """A consistent state of n other users."""
    return {addr(100 + i): text + b'%d' % i for i in range(n)}, {text + b'%d' % i: addr(100 + i) for i in range(n)}


def length_vectors():
    out = []
    for n in (0, 1, 2, 7, 8, 99, 100, 101, 102, 255, 4096):
        code = bytes(0x41 + i % 26 for i in range(n))
        for entry, flag in (('wrapper', 0), ('helper', 0), ('helper', 1)):
            for volume in ((MIN_VOLUME,), (MIN_VOLUME - 1,), None):
                out.append(vec('length', entry, flag, code=code, volume=volume))
            ps, cs = pair(3, b'other')
            out.append(vec('length', entry, flag, code=code, profiles=ps, codes=cs))
        p = {addr(1): b'mine'}
        c = {b'mine': addr(1)}
        out.append(vec('length', 'helper', 1, code=code, profiles=p, codes=c))
        out.append(vec('length', 'helper', 0, code=code, profiles=p, codes=c))
    return out


def threshold_vectors():
    out = []
    t = MIN_VOLUME
    lists = ((0,), (1,), (t - 1,), (t,), (t + 1,), (t // 2, t // 2), (t // 2, t // 2 - 1), (t - 1, 1), (1, t - 2), (U64,), (U64, 0), (U64, 1), (1, U64), (U64, U64), (U64, U64, 0, 5, 0),
             (1 << 63, 1 << 63), ((1 << 63) - 1, 1 << 63), (1 << 63, (1 << 63) - 1, 1), (1 << 32, 0), (0, 0, 0, t), (t, 0, 0, 0))
    for entry in ('wrapper', 'helper'):
        for x in lists:
            out.append(vec('threshold', entry, volume=x))
    for n in (2, 11, 12, 13, 23, 24, 25, 144, 145, 200):
        for total in (t - 1, t, t + 7):
            each = [total // n] * n
            each[n // 2] += total - sum(each)
            out.append(vec('threshold', volume=each))
            out.append(vec('threshold', volume=each, fan=1))
    # a saturated sum stays at the top; every later non-zero value overflows again
    for n in (3, 12, 30):
        over = [U64 - i if i % 3 == 0 else 0 for i in range(n)]
        out.append(vec('threshold', volume=over, fan=2))
    return out


def tall_vectors():
    """Thin trees with a height up to 9 walk every arm of the unrolled descents."""
    out = []
    t = MIN_VOLUME
    for height in range(1, 10):
        for n in (2 ** (height + 1) - 1, 2 ** (height + 1) + 6):
            each = [t // n] * n
            each[-1] += t - sum(each)
            out.append(vec('tall', volume=each, fan=1, height=height))
            each2 = list(each)
            each2[0] -= 1
            out.append(vec('tall', volume=each2, fan=1, height=height))
    for n in (40, 150, 400):
        out.append(vec('tall', volume=[t // n + 1] * n, fan=3))
        out.append(vec('tall', volume=[1] * n, fan=5))
    return out


def table_vectors():
    out = []
    u = addr(1)
    h = key_hash(u)
    near = [bytes(u[:i]) + bytes([u[i] ^ 1]) + bytes(u[i + 1:]) for i in (0, 7, 15, 16, 19)]
    same = [(k, h) for k in near]
    out.append(vec('table', volume=None))
    out.append(vec('table', volume=None, decoys=same))
    out.append(vec('table', volume=None, decoys=same, items=0))
    out.append(vec('table', decoys=same))
    out.append(vec('table', items=0))
    for k in near:
        out.append(vec('table', volume=None, decoys=[(k, h)]))
        out.append(vec('table', decoys=[(k, h)]))
    # the top seven bits are the same at other start positions, and the low bits are the same with other top bits
    other = [(addr(200 + i), (h & ~(0x1f)) | ((h + i) & 0x1f)) for i in range(1, 6)]
    tops = [(addr(300 + i), (h & ((1 << 57) - 1)) | (((h >> 57) + i + 1) & 0x7f) << 57) for i in range(1, 6)]
    out += [vec('table', decoys=other), vec('table', decoys=tops), vec('table', volume=None, decoys=other), vec('table', volume=None, decoys=tops)]
    # a run past one group: the row is reached after a probe step, or the walk ends at a later empty slot
    for n in (15, 16, 17, 20, 24, 28, 31):
        run_ = [(addr(400 + i), h) for i in range(n)]
        out.append(vec('table', decoys=run_))
        out.append(vec('table', volume=None, decoys=run_))
    for n in (16, 24):
        run_ = [(addr(500 + i), (h & ~((0x7f << 57) | 0x1f)) | (h & 0x1f) | ((h >> 57) + 1 & 0x7f) << 57) for i in range(n)]
        out.append(vec('table', decoys=run_))
        out.append(vec('table', volume=None, decoys=run_))
    wall = [(addr(800 + i), h) for i in range(32)]
    out.append(vec('table', decoys=wall, third=1))
    out.append(vec('table', decoys=wall, third=1, volume=(MIN_VOLUME - 1,)))
    out.append(vec('table', root_zero=1))
    out.append(vec('table', length=0))
    out.append(vec('table', volume=()))
    out.append(vec('table', volume=(), fan=1))
    return out


def map_vectors():
    out = []
    r = Lcg(94)
    for n in (0, 1, 2, 5, 11, 12, 13, 23, 40, 150):
        for fan in (11, 3, 1):
            ps, cs = pair(n, b'code')
            for flag in (0, 1):
                out.append(vec('maps', flag=flag, profiles=ps, codes=cs, fan=fan))
                out.append(vec('maps', flag=flag, profiles=ps, codes=cs, fan=fan, code=b'zzz'))
                out.append(vec('maps', flag=flag, profiles=ps, codes=cs, fan=fan, code=b''))
                if n:
                    keys = sorted(cs)
                    for k in (keys[0], keys[n // 2], keys[-1]):
                        out.append(vec('maps', flag=flag, profiles=ps, codes=cs, fan=fan, code=k))
                        out.append(vec('maps', flag=flag, profiles=ps, codes=cs, fan=fan, code=k[:-1]))
                        out.append(vec('maps', flag=flag, profiles=ps, codes=cs, fan=fan, code=k + b'x'))
                    users = sorted(ps)
                    for u in (users[0], users[n // 2], users[-1]):
                        out.append(vec('maps', flag=flag, user=u, profiles=ps, codes=cs, fan=fan))
                        out.append(vec('maps', flag=flag, user=u, profiles=ps, codes=cs, fan=fan, code=ps[u]))
                        out.append(vec('maps', flag=flag, user=u, profiles=ps, codes=cs, fan=fan, code=ps[u] + b'!'))
                        low = bytes(u[:19]) + bytes([u[19] - 1 & 0xff])
                        out.append(vec('maps', flag=flag, user=low, profiles=ps, codes=cs, fan=fan))
    for i in range(160):
        n = r.next(30)
        ps = {addr(600 + r.next(60)): b'' for _ in range(n)}
        ps = {k: bytes(0x61 + r.next(3) for _ in range(1 + r.next(6))) + b'%d' % j for j, k in enumerate(sorted(ps))}
        cs = {t_: k for k, t_ in ps.items()}
        users = sorted(ps) or [addr(1)]
        user = users[r.next(len(users))] if r.next(2) else addr(1)
        texts = sorted(cs) or [b'x']
        code = texts[r.next(len(texts))] if r.next(2) else bytes(0x61 + r.next(3) for _ in range(r.next(4)))
        out.append(vec('maps', 'wrapper' if i % 7 == 0 else 'helper', 0 if i % 7 == 0 else r.next(2), user=user, code=code, profiles=ps, codes=cs, fan=(11, 2, 1)[r.next(3)], extra=(0, 5, U64)[r.next(3)], scale=(1, 17)[r.next(2)]))
    return out


def update_vectors():
    out = []
    me, you = addr(1), addr(2)
    for old in (b'', b'a', b'old', b'x' * 100):
        for new in (b'', b'a', b'new', old, old + b'z', b'y' * 100):
            p, c = {me: old, you: b'yours'}, {old: me, b'yours': you}
            for extra in (0, 1, 7, U64):
                out.append(vec('update', flag=1, code=new, profiles=p, codes=c, extra=extra))
        out.append(vec('update', flag=1, code=b'yours', profiles={me: old, you: b'yours'}, codes={old: me, b'yours': you}))
    # an old code that is missing from the code map, and a code held by the user under another text
    out.append(vec('update', flag=1, code=b'b', profiles={me: b'a'}, codes={}))
    out.append(vec('update', flag=1, code=b'b', profiles={me: b'a'}, codes={b'b': me}))
    out.append(vec('update', flag=1, code=b'b', profiles={}, codes={b'b': me}))
    out.append(vec('update', flag=0, code=b'b', profiles={}, codes={b'b': me}))
    out.append(vec('update', flag=1, code=b'b', extra=9))
    out.append(vec('update', flag=0, code=b'b', extra=9))
    return out


def arm_vectors():
    out = []
    me, you = addr(1), addr(2)
    long_text = b'q' * 101
    states = (({}, {}), ({me: b'old'}, {b'old': me}), ({you: b'new'}, {b'new': you}), ({me: b'old', you: b'new'}, {b'old': me, b'new': you}))
    for ps, cs in states:
        for code in (b'', b'new', b'old', b'q' * 100, long_text):
            for tag, value in ((0, 0), (0, 5), (0, U64), (1, 0), (1, 1), (1, ARM_LIMIT - 1), (1, ARM_LIMIT), (1, ARM_LIMIT + 1), (1, U64), (2, 7), (1 << 63, 9), (1 << 32, ARM_LIMIT)):
                out.append(vec('arm', 'arm', 1, code=code, profiles=ps, codes=cs, volume=None, tag=tag, value=value))
    return out


def failure_vectors():
    out = []
    me = addr(1)
    for code in (b'a', b'abc'):
        out.append(vec('failure', flag=1, code=code, alloc=0, panic='allocation'))
        out.append(vec('failure', flag=1, code=code, alloc=1, panic='allocation'))
        out.append(vec('failure', flag=1, code=code, alloc=0, panic='allocation', profiles={addr(9): b'q'}, codes={b'q': addr(9)}))
        out.append(vec('failure', flag=1, code=code, alloc=1, panic='allocation', profiles={addr(9): b'q'}, codes={b'q': addr(9)}))
        out.append(vec('failure', flag=1, code=code, alloc=0, panic='allocation', profiles={me: b'q'}, codes={b'q': me}))
        out.append(vec('failure', flag=1, code=code, alloc=1, panic='allocation', profiles={me: b'q'}, codes={b'q': me}))
    for n in (1, 5, 13, 30):
        out.append(vec('failure', volume=[1] * n, length=n + 1, panic='none'))
        out.append(vec('failure', volume=[1] * n, length=n + 1, panic='none', fan=2))
    return out


def sequence_vectors():
    """A chain of calls, each on the state the model left behind."""
    out = []
    r = Lcg(7)
    users = [addr(700 + i) for i in range(6)]
    texts = [b'', b'a', b'ab', b'b', b'code', b'z' * 100, b'z' * 101]
    for chain in range(40):
        profiles, codes = {}, {}
        for step in range(12):
            flag = r.next(2)
            v = vec('sequence', flag=flag, user=users[r.next(6)], code=texts[r.next(7)], profiles=profiles, codes=codes, volume=((MIN_VOLUME - 1 + r.next(2),) if r.next(4) else None))
            out.append(v)
            want = model(v)
            profiles, codes = dict(v['profiles']), dict(v['codes'])
            for e in want['effect']:
                if e[0] == 'remove':
                    codes.pop(e[1], None)
                elif e[0] == 'insert':
                    codes[e[1]] = e[2]
                else:
                    profiles[e[1]] = e[2]
    return out


def all_vectors():
    return length_vectors() + threshold_vectors() + tall_vectors() + table_vectors() + map_vectors() + update_vectors() + arm_vectors() + failure_vectors() + sequence_vectors()


# ---- static facts


def bind_fdes(data):
    fdes = Fdes(data)
    for s in DECODED:
        FDE_END[s] = fdes.range_of(s)['end']
    FDE_END.update(ARM_PIECES)
    return fdes


FDE_END = {}


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
    for s in SUBJECTS:
        code.update({i.va: i for i in decode_range(img, s, FDE_END[s])})
    # first instructions past the arm, present so the hooks can stop there
    for va in (ARM_DONE, ARM_FAILED, ARM_CALL_END):
        code[va] = decode_one(img.read(va, 16), 0, va)
    slots, got = scan_slots(img, code)
    return img, code, fdes, slots, got


# ---- mutation survey


EQUIVALENT = {
    0x3745428: 'this path has a non-zero remainder of the height mod 8, so rax is never 8 and 8 and 9 give the same branch',
    0x3745345: 'this path has a non-zero remainder of the height mod 8, so rbp is never 8 and 8 and 9 give the same branch',
    0x3744f3a: 'the shuffle picks dword 1 in place of dword 0 of a register whose low two dwords are equal',
    0x374564c: 'copies the four bytes past the 20-byte key into padding of the entry; the entry stub reads 20 bytes, and 0x33c2c80 is not run',
    0x37456a3: 'empty code: the destination of a zero-byte copy',
    0x37456a8: 'empty code: the source of a zero-byte copy',
    0x3745464: 'r9 is read again only by a second 8-step round of the descent, at a height of 16 or more; a real tree of that height does not fit in memory, and no vector has it',
    0x27e30c9: 'the mutated byte is the top of the flag dword, and the helper compares only the low byte',
}
UNEXECUTED = (
    (0x3745664, 0x374566f, 'capacity overflow of a clone: the length is at most 100 here'),
    (0x374597f, 0x374598e, 'trap jump after the no-return call, and the unwrap of the first-edge state: dl is 1 on every loop entry, so the test never fails'),
    (0x37459af, 0x37459d3, 'trap after the no-return calls, and the unwind landing pad'),
)


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
    """The survey set: curated groups whole, about 120 of each generated group, chosen by a hash of the index."""
    count, kept = {}, []
    for v in vecs:
        count[v['group']] = count.get(v['group'], 0) + 1
    for i, v in enumerate(vecs):
        if hashlib.sha256(str(i).encode()).digest()[0] * count[v['group']] < 256 * 120:
            kept.append(v)
    return kept


def try_kill(mimg, mcode, slots, got, picked):
    for pos, v in enumerate(picked):
        try:
            bad = check(mimg, mcode, slots, got, v)
        except (Unmodelled, Panicked, EvidenceError, KeyError, OverflowError, ValueError, TypeError, struct.error, IndexError, MemoryError) as exc:
            bad = f'fault {type(exc).__name__}'
        if bad:
            picked.insert(0, picked.pop(pos))
            return (v['group'], bad[:60].replace('\t', ' ').replace('\n', ' '))
    return None


def all_sites(listing):
    sites = []
    for fn in SUBJECTS:
        sites += conditional_sites(fn, listing[fn]) + field_sites(fn, listing[fn]) + imm_sites(fn, listing[fn])
    return [x for x in sites if not any(a <= x['va'] < b for a, b, _ in UNEXECUTED)]


def survey_part(args):
    data, code, slots, got, sites, vecs = args
    picked = sample(vecs)
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


WORKERS = 3


def survey(data, code, slots, got, listing, vecs):
    sites = all_sites(listing)
    parts = [sites[i::WORKERS] for i in range(WORKERS)]
    jobs = [(data, code, slots, got, p, vecs) for p in parts]
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


def site_facts(img, site):
    """Stack flag, r9 clear and tracker offset of one call of the helper, from fixed byte patterns before it."""
    raw = img.read(site - 40, 40)
    if raw.endswith(b'\x6a\x01'):
        flag = 1
    elif raw.endswith(b'\x45\x31\xc9') and b'\xc7\x04\x24\x00\x00\x00\x00' in raw:
        flag = 0
    else:
        raise EvidenceError(f'no flag pattern before {site:#x}')
    tracker = None
    for op in (b'\x48\x81\xc1', b'\x49\x81\xc5', b'\x48\x81\xc6'):
        i = raw.rfind(op)
        if i != -1:
            tracker = struct.unpack_from('<I', raw, i + 3)[0]
    return dict(flag=flag, xor_r9_before_call=b'\x45\x31\xc9' in raw, tracker=hex(tracker) if tracker else None)


def arm_copy(img, site, starts):
    """The limit test of one flag 1 caller: movabs of the limit, cmp r9, then jb to the join just after xor r9d,r9d."""
    fn = starts[bisect.bisect_right(starts, site) - 1]
    needle = b'\x48\xb8' + struct.pack('<Q', ARM_LIMIT) + b'\x49\x39\xc1\x0f\x82'
    addr_, off, _ = img.sec['.text'][:3]
    lo, hi = fn - addr_ + off, site - addr_ + off
    found = []
    i = img.data.find(needle, lo, hi)
    while i != -1:
        va = addr_ + i - off
        rel = struct.unpack_from('<i', img.data, i + len(needle))[0]
        target = va + len(needle) + 4 + rel
        if target < site and site - target < 40 and img.read(target - 3, 3) == b'\x45\x31\xc9':
            found.append(dict(limit_test=hex(va), join=hex(target)))
        i = img.data.find(needle, i + 1, hi)
    if len(found) != 1:
        raise EvidenceError(f'{len(found)} limit tests before {site:#x}')
    return dict(site=hex(site), function=hex(fn), **found[0])


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


def digest_of(v):
    return hashlib.sha256(repr(sorted((k, repr(x)) for k, x in v.items())).encode()).hexdigest()[:16]


REFERENCE_ROWS = (
    ('differs', 'register_referrer doc: shared helper, user path a7 = 0', 'only the a7 = 0 path is described', 'three of six callers push 1; that mode has no volume test, tests the length first, and replaces the code of a user who has a profile'),
    ('differs', 'ReferrerProfile n_per_bucket = 0', 'always 0 on this path', 'true for the three flag 0 callers; the flag 1 arm passes a caller value in r9, stored at profile +0x40'),
    ('differs', 'ReferrerProfile stats_0 and stats_1 as two u128 fields', 'two zero-initialized 128-bit fields', 'the new profile writes +0x18, +0x20, +0x30, +0x38 as zero and leaves +0x28 unwritten'),
    ('differs', 'UserEligibilityState eligibility_total_raw', 'one stored u64 on the user', 'a sum over the token tree at row +0xb0, first word of each 0x30-byte value, saturating, with one call to the recorder per overflow'),
    ('differs', 'users lookup', 'a HashMap of users', 'an empty table (item word 0), a missing row, a null root and a tree length of 0 all give 0xa5'),
    ('differs', 'CodeTooLongInHelper doc', 'unreachable through the user wrapper', 'true for the wrapper; with flag 0 the test still comes after the volume test, and with flag 1 it comes first, but the arm itself stops 101 bytes with 0x143 before the call'),
    ('differs', 'status::DUPLICATE_CODE comments', 'another referrer owns this code', 'with flag 1 and no profile, a code held by the same address also gives 0xa3'),
    ('same', 'MAX_REFERRER_CODE_LEN', '100', 'cmp r8,0x65 with jb at 0x27e30ac, cmp r8,0x64 at 0x3744edb and 0x374550f'),
    ('same', 'MIN_REFERRER_ELIGIBILITY_RAW', '1000000, at least', 'cmp rcx,0xf4240 with jae at 0x37454e0'),
    ('same', 'status numbers', '390, 160, 163, 164, 165, 323', 'tags 0x186, 0xa0, 0xa3, 0xa4, 0xa5, 0x143'),
    ('same', 'order with flag 0', 'volume, owner, code', 'the same, with the length test between volume and owner'),
)


def generate(data, out_dir, with_survey=True):
    global SEEN
    img, code, fdes, slots, got = build(data)
    listing = {s_: decode_range(img, s_, FDE_END[s_]) for s_ in SUBJECTS}
    vecs = all_vectors()
    seen = SEEN = set()
    try:
        for v in vecs:
            try:
                msg = check(img, code, slots, got, v)
            except (Unmodelled, Panicked, EvidenceError, KeyError) as exc:
                msg = f'fault {type(exc).__name__} {exc}'
            if msg:
                raise EvidenceError(f"mismatch in {v['group']} flag {v['flag']} code {v['code'][:20]!r}: {msg}")
    finally:
        SEEN = None
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
    sites = slot_sites(img, HELPER_SLOT, starts)
    for s_ in sites:
        s_.update(site_facts(img, int(s_['site'], 16)))
    out_path = Path(out_dir)
    out_path.mkdir(parents=True, exist_ok=True)
    groups, outcomes = {}, {}
    with open(out_path / 'vectors.tsv', 'w', newline='\n') as f:
        f.write('group\tentry\tflag\tcode_length\tstate\tstatus\toverflows\n')
        for v in vecs:
            groups[v['group']] = groups.get(v['group'], 0) + 1
            if 'panic' in v:
                name, over = 'panic ' + v['panic'], ''
            else:
                want = model(v)
                name, over = hex(want['status']), want['overflows']
            outcomes[name] = outcomes.get(name, 0) + 1
            f.write(f"{v['group']}\t{v['entry']}\t{v['flag']}\t{len(v['code'])}\t{digest_of(v)}\t{name}\t{over}\n")
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
    per = {}
    for fn in SUBJECTS:
        per[hex(fn)] = dict(end=hex(FDE_END[fn]), fde=hex(fdes.range_of(fn)['fde']) if fn in DECODED else None, instructions=len(listing[fn]), executed=sum(i.va in seen for i in listing[fn]))
    evidence = dict(
        binary=BINARY, sha256=SHA256, functions=per, subjects=[hex(s_) for s_ in SUBJECTS],
        stubs=dict(hash=hex(HASH), recorder=hex(RECORDER), code_remove=hex(CODE_REMOVE), code_insert=hex(CODE_INSERT), profile_vacant=hex(PROFILE_VACANT), code_vacant=hex(CODE_VACANT)),
        helper_slot=hex(HELPER_SLOT), recorder_slot=hex(RECORDER_SLOT), recorder=hex(img.relative(RECORDER_SLOT)), helper_callers=sites,
        wrapper_callers={hex(c): direct_sites(img, c, starts) for c in (WRAPPER,) + WRAPPER_COPIES}, wrapper_copies=copy_rows(img, fdes, WRAPPER, WRAPPER_COPIES),
        arm_copies=[arm_copy(img, site, starts) for site in ARM_FLAG_SITES],
        status_text={hex(t): status_text(img, t) for t in STATUSES if t != OK}, overflow_location=location(img, OVERFLOW_LOCATION), none_location=location(img, NONE_LOCATION),
        pinned=pinned(img), vectors=len(vecs), mismatches=0, groups=groups, outcomes=outcomes, padding_not_executed=padding,
        unexecuted=[dict(start=hex(a), end=hex(b), why=w) for a, b, w in UNEXECUTED], mutants=len(rows), killed=sum(1 for r in rows if r['killed']),
        survey_vectors=len(sample(vecs)), equivalent={hex(k): w for k, w in sorted(EQUIVALENT.items())},
        layouts=dict(profile=dict(leaf=hex(PROFILE_NODE.leaf_size), value=hex(PROFILE_SIZE), key=20), code=dict(leaf=hex(CODE_NODE.leaf_size), key=hex(0x18), value=20), token=dict(leaf=hex(TOKENS.leaf_size), value=hex(0x30))),
    )
    with open(out_path / 'evidence.json', 'w', newline='\n') as f:
        json.dump(evidence, f, indent=1, sort_keys=True)
        f.write('\n')
    return evidence


def location(img, va):
    """Panic Location record: pointer, length, line, column.  Only the tail of the path is kept."""
    ptr = img.relative(va)
    size, line, col = struct.unpack('<QII', img.read(va + 8, 16))
    text = img.read(ptr, size).decode('ascii', 'replace')
    i = text.find('l1/src/')
    if i == -1:
        i = text.find('library/')
    return dict(path=text[max(i, 0):], bytes=size, line=line, column=col)


def main():
    ap = argparse.ArgumentParser(description=__doc__.split('\n')[0])
    ap.add_argument('--out', required=True)
    args = ap.parse_args()
    data = (ROOT / BINARY).read_bytes()
    ev = generate(data, args.out)
    print(json.dumps(dict(vectors=ev['vectors'], mutants=ev['mutants'], killed=ev['killed']), sort_keys=True))


if __name__ == '__main__':
    main()
