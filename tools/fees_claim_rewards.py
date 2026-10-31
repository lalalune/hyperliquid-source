#!/usr/bin/env python3
"""fees: node #94 claimRewards path, from bytes alone.

Static, no execution of the node.  The handler 0x2710e30, the ledger writer 0x3743930 and three small helpers
0x333e310, 0x32815f0, 0x375fb50 are decoded from ELF bytes by the table decoder below, which must land exactly on
each FDE end, and interpreted in Python on every vector.  The hash, the balance update, the mark lookup, the account
lookup, the block record, the token name, the event push, the overflow recorder, vector growth and allocation are
stubs that check their arguments.  Each outcome is compared with a separate closed-form model, then every
conditional, field offset and immediate of the two subjects is mutated to test the vectors.

    python3 tools/fees_claim_rewards.py --out <dir>

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

HANDLER = 0x2710e30
WRITER = 0x3743930
FLOOR = 0x333e310
VALUE = 0x32815f0
UNIT = 0x375fb50
SUBJECTS = (HANDLER, WRITER)
HELPERS = (FLOOR, VALUE, UNIT)
WRITER_SLOT = 0x57749f0
HASH = 0x399c7a0
APPLY = 0x371d120
MARK = 0x371cf40
ACCOUNT = 0x1f849b0
BLOCK = 0x3987cb0
GOT_ALLOC = 0x576dfd8
GOT_FREE = 0x576e010
GOT_ALLOC_ERROR = 0x576e020
GOT_UDIV = 0x576e1a8
GOT_PANIC = 0x576e470
GOT_SUB_PANIC = 0x576e150
GOT_UNWRAP = 0x576e048
STATUS_ARM = 0x3800161
STATUS_FORMAT = 0x1f1184
SLOT_NAME = 0x57746b8
SLOT_EVENT = 0x5774738
SLOT_REPORT = 0x5773190
SLOT_GROW = 0x57749f8
OK = 0x186
NOTHING = 0xa6
TOO_SMALL = 0xa7
TAG_OK = 13
TAG_ERR = 14
USD = 100000000
CAP = 10 ** 16
HYPE = b'HYPE'
EVENT_TAG = 0x8000000000000011
POWERS = 0x584b08
STRIDE = 0xe8
SPOT_STRIDE = 0xe8
LEDGER_VALUE = 0x30
EXCHANGE_SIZE = 0x3400
TRACKER = 0x5d0
TABLE = TRACKER + 0xc0
HASH_STATE = TRACKER + 0xe0
META = 0x90
TOKENS = META + 0x180
SCALES = META + 0x1c0
BOOKS = 0x80
ACCOUNTS = 0x740
EVENTS = 0x8f3
MARK_ARG = 0x3380
TIME_AT = 0x60
ROW_ROOT = 0xb0
STACK_FILL = bytes((i * 5 + 3) & 0xff | 1 for i in range(0x8000))
TOP = 0x7f08
FRAME = TOP - 0x30 - 0x188
PINNED = (
    (0x3743946, '48 83 be d8 00 00 00 00', 'empty table goes straight to status 0xa6'),
    (0x3743c93, 'bf 00 e1 f5 05', 'floor notional 100000000'),
    (0x3743cc5, '49 c7 44 24 08 00 00 00 00', 'value +8 is zeroed before the add into +0x10'),
    (0x3743d8c, '0d a6 00 00 00', 'status is 0xa6 or the seen bit'),
    (0x27110c5, '3b 05 49 8d af fd', 'compare of the 4-byte token name with HYPE'),
    (0x27110cd, '48 b8 00 00 c1 6f f2 86 23 00', 'cap 1e16 on the value'),
    (0x2711112, '48 b9 4b 59 86 38 d6 c5 6d 34', 'reciprocal of 10000 in the unit credit'),
    (0x271127a, '48 b8 11 00 00 00 00 00 00 80', 'event variant'),
)
SEEN = None


class Panicked(Exception):
    """The node would panic here; a modelled outcome, unlike Unmodelled."""


def addr(n):
    """A 20-byte test address."""
    return hashlib.sha256(b'addr' + str(n).encode()).digest()[:20]


def key_hash(key):
    return int.from_bytes(hashlib.sha256(key).digest()[:8], 'little')


# ---- model, written from the observed rules and independent of the machine


def tenth(n):
    """10^n in 64 bits: 20 and above, up to the 8-bit difference, ends in the panic path."""
    if n >= 20:
        raise Panicked('bound')
    return 10 ** n


def unit_price(meta, token):
    """10^(wei decimals of token 0 - size decimals of the token)."""
    if not meta or token >= len(meta):
        raise Panicked('bound')
    diff = meta[0]['wei'] - meta[token]['sz']
    if diff < 0:
        raise Panicked('subtract')
    return tenth(diff)


def scale_of(meta, token):
    diff = meta[token]['wei'] - meta[token]['sz']
    if diff < 0:
        raise Panicked('bound')
    return tenth(diff)


def floor_of(meta, token):
    """Least claimable wei; None when the quotient leaves 64 bits."""
    px = unit_price(meta, token)
    got = USD * scale_of(meta, token) // px
    return got if got >> 64 == 0 else None


def writer_model(v):
    """Status, the claimed list, and the (token, U, C) words after the call, in key order."""
    ledger = v['ledger']
    meta = v['meta']
    found = (v['user'], 'ledger') in v['rows']
    if not found or not ledger:
        return dict(status=NOTHING, claimed=[], ledger=[tuple(x[:3]) for x in ledger], reports=0)
    out, seen, reports, after = [], False, 0, []
    for token, u, c, *_ in ledger:
        if u == 0:
            after.append((token, u, c))
            continue
        need = floor_of(meta, token)
        seen = True
        if need is None or u < need:
            after.append((token, u, c))
            continue
        total = c + u
        if total >> 64:
            reports += 1
            total = U64
        after.append((token, 0, total))
        out.append((token, u))
    if out:
        return dict(status=OK, claimed=out, ledger=after, reports=reports)
    return dict(status=TOO_SMALL if seen else NOTHING, claimed=[], ledger=after, reports=reports)


def usd_of(wei, token, px, meta):
    """(fits, value) of wei at price px: floor(wei * px / (10^k * 100))."""
    div = scale_of(meta, token) * 100
    q = wei * px // div
    return q >> 64 == 0 and q < 0x28f5c28f5c28f5c, q & U64


def pay_model(v, claimed):
    """One row per claimed token: price passed on, value, units, new running word, overflow."""
    meta, rows = v['meta'], []
    word_ = v.get('account', 0)
    for token, wei in claimed:
        if token == 0:
            px, usd = 0, wei // 100
        else:
            px = v['scales'].get(token)
            px = unit_price(meta, token) if px is None else px
            mark = v['marks'].get(token, 0)
            if mark == 0:
                usd = 0
            else:
                fits, q = usd_of(wei, token, mark, meta)
                usd = q if fits else 0
                if token != 1 and meta[token]['name'] != HYPE:
                    usd = min(usd, CAP)
        units = usd // 10000
        raw = word_ + units
        over = raw >= 1 << 63
        word_ = (1 << 63) - 1 if over else raw
        rows.append(dict(token=token, wei=wei, px=px, usd=usd, units=units, word=word_, over=over))
    return rows


# ---- node and table writers


class Layout:
    def __init__(self, leaf_size, parent, parent_index, length, edges):
        self.leaf_size = leaf_size
        self.parent, self.parent_index, self.length, self.edges = parent, parent_index, length, edges


# value +0 (0x30 each), parent +0x210, key +0x218, parent index +0x270, length +0x272, edges +0x278
LEDGER_NODE = Layout(0x278, 0x210, 0x270, 0x272, 0x278)
# parent +0, key +8, value +0x60, parent index +0xb8, length +0xba, edges +0xc0
SCALE_NODE = Layout(0xc0, 0, 0xb8, 0xba, 0xc0)


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

    def __init__(self, m, layout, items, fan, fill, pattern, places=None, height=None):
        self.m, self.lay, self.items, self.fan, self.fill = m, layout, items, fan, fill
        self.places = places
        self.height = tree_height(len(items), fan) if height is None else height
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
                self.fill(self, at, i, self.items[first + i])
            return base
        sizes = split_shape(n, h, self.fan)
        self.word(at + lay.length, 2, len(sizes) - 1)
        i = first
        for pos, c in enumerate(sizes):
            kid = self.node(i, c, h - 1, base, pos)
            self.word(at + lay.edges + 8 * pos, 8, kid)
            i += c
            if pos < len(sizes) - 1:
                self.fill(self, at, pos, self.items[i])
                i += 1
        return base

    def snapshot(self):
        return bytes(self.arena.mem)


FILLS = {}


def fill_bytes(n, seed):
    """A position-dependent pattern, so a shifted read or a stray write shows."""
    if (n, seed) not in FILLS:
        FILLS[n, seed] = bytes((i * 11 + seed + (i >> 8)) & 0xff for i in range(n))
    return FILLS[n, seed]


def word(a, off, size, val):
    a.mem[off:off + size] = val.to_bytes(size, 'little')


def read(blob, off, size=8):
    return int.from_bytes(blob[off:off + size], 'little')


def fill_ledger(tree, at, pos, item):
    token, u, c, *rest = item
    base = at + LEDGER_VALUE * pos
    tree.word(at + 0x218 + 8 * pos, 8, token)
    tree.word(base + 8, 8, u)
    tree.word(base + 0x10, 8, c)
    tree.places[token] = base
    for k, off in enumerate((0, 0x18, 0x20, 0x28)):
        if k < len(rest):
            tree.word(base + off, 8, rest[k])


def fill_scale(tree, at, pos, item):
    token, px = item
    tree.word(at + 8 + 8 * pos, 8, token)
    tree.word(at + 0x60 + 8 * pos, 8, px)


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


def write_table(m, size, rows, hashes, deleted):
    """A hash table of `size` buckets; rows lists (key, ledger items or None for an empty tree)."""
    mask = size - 1
    a = m.arena(STRIDE * size + size + 32)
    a.mem[:] = fill_bytes(len(a.mem), 0x17)
    a.valid[:] = b'\1' * len(a.mem)
    ctrl_off = STRIDE * size + 16
    ctrl = [0xff] * (size + 16)
    places = {}
    for key, items in rows:
        h = hashes.get(key, key_hash(key))
        slot = free_slot(ctrl, mask, h)
        set_ctrl(ctrl, mask, slot, h >> 57)
        at = ctrl_off - (slot + 1) * STRIDE
        a.mem[at:at + 20] = key
        places[key] = at
    for i in deleted:
        if ctrl[i & mask] == 0xff:
            set_ctrl(ctrl, mask, i & mask, 0x80)
    a.mem[ctrl_off:ctrl_off + size + 16] = bytes(ctrl)
    word(m.ex, TABLE, 8, a.base + ctrl_off)
    word(m.ex, TABLE + 8, 8, mask)
    word(m.ex, TABLE + 0x10, 8, 0)
    word(m.ex, TABLE + 0x18, 8, len(rows))
    m.table = dict(arena=a, places=places)


def write_tokens(m, meta):
    a = m.arena(max(SPOT_STRIDE * len(meta), 8))
    a.mem[:] = fill_bytes(len(a.mem), 0x29)
    a.valid[:] = b'\1' * len(a.mem)
    blocks = {}
    for i, t_ in enumerate(meta):
        at = SPOT_STRIDE * i
        name = t_['name']
        block = blocks.get(name)
        if block is None:
            block = blocks[name] = m.arena(max(len(name), 1))
            block.mem[:len(name)] = name
            block.valid[:len(name)] = b'\1' * len(name)
        word(a, at + 0x30, 8, len(name))
        word(a, at + 0x38, 8, block.base)
        word(a, at + 0x40, 8, len(name))
        a.mem[at + 0x48] = t_['sz']
        a.mem[at + 0x49] = t_['wei']
    word(m.ex, TOKENS, 8, a.base)
    word(m.ex, TOKENS + 8, 8, len(meta))


def machine(img, code, slots, got):
    m = Machine(img, ())
    if SEEN is not None:
        m.seen = SEEN
    m.code = code
    m.slots = slots
    m.got = got
    for fn in SUBJECTS + HELPERS:
        m.real[fn] = fn
    stack = m.arena(0x8000, strict=False)
    stack.mem[:] = STACK_FILL
    m.stack = stack
    m.top = stack.base + TOP
    m.calls = []
    m.live = {}
    m.reports = 0

    def alloc():
        n = m.regs[R['rdi']]
        if n != 20:
            raise Unmodelled('allocation size')
        if m.no_alloc:
            return m.clobber(0)
        a = m.arena(20)
        m.live[a.base] = 20
        m.clobber(a.base)

    def alloc_error():
        if (m.regs[R['rdi']], m.regs[R['rsi']]) != (1, 20):
            raise Unmodelled('alloc error arguments')
        raise Panicked('allocation')

    def free():
        at, size, flag = m.regs[R['rdi']], m.regs[R['rsi']], m.regs[R['rdx']]
        if m.live.pop(at, None) != size or flag != 0:
            raise Unmodelled('free of another block')
        m.clobber()

    def grow():
        at = m.regs[R['rdi']]
        if at != m.vec_at():
            raise Unmodelled('grow of another vector')
        cap, ptr, n = m.load(at, 8), m.load(at + 8, 8), m.load(at + 0x10, 8)
        if cap != n:
            raise Unmodelled('grow of a vector with room')
        new = max(cap * 2, 4)
        a = m.arena(new * 16)
        if cap:
            if ptr not in m.live or m.live.pop(ptr) != cap * 16:
                raise Unmodelled('old buffer')
            for i in range(n * 16):
                m.store(a.base + i, 1, m.load(ptr + i, 1))
        m.live[a.base] = new * 16
        m.store(at, 8, new)
        m.store(at + 8, 8, a.base)
        m.clobber()

    def udiv():
        r = m.regs
        a = r[R['rdi']] | r[R['rsi']] << 64
        b = r[R['rdx']] | r[R['rcx']] << 64
        if b == 0:
            raise Unmodelled('division by zero')
        q = a // b
        m.clobber(q & U64)
        r[R['rdx']] = q >> 64

    def hash_stub():
        if m.regs[R['rdi']] != m.ex.base + HASH_STATE:
            raise Unmodelled('hash state')
        key = bytes(m.load(m.regs[R['rsi']] + k, 1) for k in range(20))
        m.clobber(m.hashes.get(key, key_hash(key)))

    def panic():
        raise Panicked('bound')

    def sub_panic():
        raise Panicked('subtract')

    def unwrap():
        raise Panicked('unwrap')

    def report():
        if m.regs[R['rdi']] != 0:
            raise Unmodelled('report argument')
        m.reports += 1
        m.calls.append(('report', m.regs[R['rsi']]))
        m.clobber()

    def apply_():
        r = m.regs
        if (r[R['rdi']], r[R['rcx']]) != (m.ex.base + BOOKS, 0):
            raise Unmodelled('apply arguments')
        key = bytes(m.load(r[R['rsi']] + k, 1) for k in range(20))
        m.calls.append(('apply', key, r[R['rdx']], r[R['r8']], r[R['r9']]))
        m.clobber()

    def mark():
        r = m.regs
        if (r[R['rdi']], r[R['rdx']]) != (m.ex.base + BOOKS, m.ex.base + MARK_ARG):
            raise Unmodelled('mark arguments')
        m.calls.append(('mark', r[R['rsi']]))
        m.clobber(m.vec['marks'].get(r[R['rsi']], 0))

    def account():
        r = m.regs
        if r[R['rdi']] != m.ex.base + ACCOUNTS:
            raise Unmodelled('account map')
        key = bytes(m.load(r[R['rsi']] + k, 1) for k in range(20))
        m.calls.append(('account', key))
        m.clobber(m.account.base)

    def block():
        r = m.regs
        ex = m.ex
        args = (r[R['rsi']], r[R['rdx']], r[R['rcx']], r[R['r8']])
        if args != (ex.mem[0x8f2], read(ex.mem, 0x28), read(ex.mem, 8), 0) or r[R['rdi']] != r[R['rsp']] + 0x80:
            raise Unmodelled('block arguments')
        for i in range(4):
            m.store(r[R['rdi']] + 8 * i, 8, 0x1111000000000000 + i)
        m.calls.append(('block',))
        m.clobber()

    def name():
        r = m.regs
        if r[R['rdx']] != m.ex.base + META or r[R['rdi']] != r[R['rsp']] + 0x170:
            raise Unmodelled('name arguments')
        tok = r[R['rsi']]
        for i, x in enumerate((0x2222000000000000 + tok, 0x3333000000000000 + tok, 0x4444000000000000 + tok)):
            m.store(r[R['rdi']] + 8 * i, 8, x)
        m.calls.append(('name', tok))
        m.clobber()

    def event():
        r = m.regs
        sp = r[R['rsp']]
        if (r[R['rdi']], r[R['rsi']], r[R['rdx']], r[R['rcx']], r[R['r8']]) != (m.ex.base + EVENTS, sp + 0xa8, sp + 0x70, sp + 0x80, sp + 0xc0):
            raise Unmodelled('event arguments')
        cap, ptr, n = (m.load(sp + 0xa8 + k, 8) for k in (0, 8, 0x10))
        who = bytes(m.load(ptr + k, 1) for k in range(20))
        if (cap, n) != (1, 1) or m.live.pop(ptr, None) != 20:
            raise Unmodelled('event user list')
        when = tuple(m.load(sp + 0x70 + k, 4) for k in (0, 4, 8))
        blk = tuple(m.load(sp + 0x80 + 8 * k, 8) for k in range(4))
        body = tuple(m.load(sp + 0xc0 + 8 * k, 8) for k in range(5))
        m.calls.append(('event', who, when, blk, body))
        m.clobber()

    m.stubs.update({HASH: hash_stub, APPLY: apply_, MARK: mark, ACCOUNT: account, BLOCK: block})
    for s, fn in ((GOT_ALLOC, alloc), (GOT_FREE, free), (GOT_ALLOC_ERROR, alloc_error), (GOT_UDIV, udiv), (GOT_PANIC, panic),
                  (GOT_SUB_PANIC, sub_panic), (GOT_UNWRAP, unwrap), (SLOT_NAME, name), (SLOT_EVENT, event), (SLOT_REPORT, report), (SLOT_GROW, grow)):
        if s in slots:
            m.stubs[slots[s]] = fn
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


def run(img, code, slots, got, v):
    """One call on a fresh state.  Returns the first 0x60 bytes of the result and the machine."""
    m = machine(img, code, slots, got)
    m.vec = v
    m.no_alloc = v.get('no_alloc', False)
    ex = m.arena(EXCHANGE_SIZE)
    ex.mem[:] = fill_bytes(EXCHANGE_SIZE, 0x41)
    ex.valid[:] = b'\1' * EXCHANGE_SIZE
    m.ex = ex
    m.tracker = ex.base + TRACKER
    m.hashes = dict(v.get('hashes', {}))
    if v.get('block') is not None:
        word(ex, 0, 4, 1)
        ex.mem[0x8f2] = v['block']
    else:
        word(ex, 0, 4, 0)
    ledger = Tree(m, LEDGER_NODE, v['ledger'], v.get('fan', 11), fill_ledger, 0x55, places={}, height=v.get('height'))
    scales = Tree(m, SCALE_NODE, sorted(v['scales'].items()), v.get('scale_fan', 11), fill_scale, 0x77, places={})
    write_table(m, v.get('size', 32), v['rows'], m.hashes, v.get('deleted', ()))
    tab = m.table
    for key, want in v['rows']:
        at = tab['places'][key]
        if want == 'ledger':
            word(tab['arena'], at + ROW_ROOT, 8, ledger.root)
            word(tab['arena'], at + ROW_ROOT + 8, 8, ledger.height)
            word(tab['arena'], at + ROW_ROOT + 0x10, 8, len(v['ledger']) + v.get('length_lie', 0))
        elif want == 'no-root':
            word(tab['arena'], at + ROW_ROOT, 8, 0)
        elif want == 'no-items':
            word(tab['arena'], at + ROW_ROOT, 8, ledger.root)
            word(tab['arena'], at + ROW_ROOT + 8, 8, ledger.height)
            word(tab['arena'], at + ROW_ROOT + 0x10, 8, 0)
    write_tokens(m, v['meta'])
    word(ex, SCALES, 8, scales.root)
    word(ex, SCALES + 8, 8, scales.height)
    word(ex, 0x60, 12, int.from_bytes(struct.pack('<III', 0x100, 0x200, 0x300), 'little'))
    ex.mem[0x60:0x6c] = struct.pack('<III', 0x7e54321, 3600, 5000)
    m.account = m.arena(0x40)
    m.account.mem[:] = fill_bytes(0x40, 0x33)
    m.account.valid[:] = b'\1' * 0x40
    word(m.account, 0x10, 8, v.get('account', 0) & U64)
    m.parts = ledger, scales
    m.snap = dict(ex=bytes(ex.mem), table=bytes(tab['arena'].mem), ledger=ledger.snapshot(), scales=scales.snapshot(), account=bytes(m.account.mem))
    user = m.arena(20)
    user.mem[:] = v['user']
    user.valid[:] = b'\1' * 20
    res = m.arena(0x60, strict=False)
    res.mem[:] = bytes((i * 3 + 0x81) & 0xff for i in range(0x60))
    if v.get('entry', 'handler') == 'handler':
        m.vec_at = lambda: m.frame_vec
        m.frame_vec = FRAME_VEC(m)
        enter(m, HANDLER, res.base, ex.base, user.base)
    else:
        m.vec_at = lambda: m.top - 0x30 - 0x38
        tok_meta = ex.base + META
        enter(m, WRITER, res.base, m.tracker, user.base, tok_meta)
    m.res = res
    if m.regs[R['rax']] != res.base:
        raise Unmodelled('result pointer not returned')
    return bytes(res.mem), m


def FRAME_VEC(m):
    """Frame of the writer when called from the handler: return, 6 pushes, 0x38."""
    return m.stack.base + FRAME - 8 - 0x30 - 0x38


def ledger_words(tree):
    """(token, U, C) in key order, read back from node bytes."""
    out = []

    def walk(at, h):
        n = read(tree.arena.mem, at + 0x272, 2)
        for i in range(n + 1):
            if h:
                walk(read(tree.arena.mem, at + 0x278 + 8 * i) - tree.arena.base, h - 1)
            if i < n:
                base = at + LEDGER_VALUE * i
                out.append((read(tree.arena.mem, at + 0x218 + 8 * i), read(tree.arena.mem, base + 8), read(tree.arena.mem, base + 0x10)))
    if tree.root:
        walk(tree.root - tree.arena.base, tree.height)
    return out


def changed(blob, before, skip):
    """Offsets that moved, outside the listed [start, end) ranges."""
    return [i for i in range(len(blob)) if blob[i] != before[i] and not any(a <= i < b for a, b in skip)]


def outcome(v):
    """(model result, None), or (None, panic kind) when the vector or the model says the node panics."""
    if 'panic' in v:
        return None, v['panic']
    try:
        return writer_model(v), None
    except Panicked as exc:
        return None, str(exc)


def blank(blob, spans):
    out = bytearray(blob)
    for a, b in spans:
        out[a:b] = bytes(b - a)
    return bytes(out)


def check(img, code, slots, got, v):
    """Compare one call with the model.  Returns None, or a reason without raw bytes."""
    want, panic = outcome(v)
    try:
        res, m = run(img, code, slots, got, v)
    except Panicked as exc:
        if str(exc) == panic:
            return None
        return f'panic {exc}'
    if panic is not None:
        return 'no panic'
    status = read(res, 0, 2)
    if status != want['status']:
        return f'status {status:#x}'
    ledger, scales = m.parts
    if ledger_words(ledger) != want['ledger']:
        return 'ledger words'
    if bytes(m.ex.mem) != m.snap['ex'] and v.get('entry', 'handler') == 'writer':
        return 'exchange block'
    if bytes(m.table['arena'].mem) != m.snap['table']:
        return 'table bytes'
    if scales.snapshot() != m.snap['scales']:
        return 'scale tree'
    allowed = []
    for key, base in ledger.places.items():
        allowed.append((base + 8, base + 0x18))
    if blank(ledger.snapshot(), allowed) != blank(m.snap['ledger'], allowed):
        return 'ledger bytes outside U and C'
    return check_handler(m, res, v, want) if v.get('entry', 'handler') == 'handler' else check_writer(m, res, want)


def check_writer(m, res, want):
    """Direct call: returned vector words, buffer content, overflow reports."""
    if m.reports != want['reports'] or [c for c in m.calls if c[0] != 'report']:
        return 'writer calls'
    pattern = bytes((i * 3 + 0x81) & 0xff for i in range(0x60))
    if want['status'] != OK:
        if m.live:
            return 'block left'
        return None if res[2:] == pattern[2:] else 'error result bytes'
    cap, ptr, n = read(res, 8), read(res, 0x10), read(res, 0x18)
    if n != len(want['claimed']) or m.live.get(ptr) != cap * 16:
        return 'vector words'
    if len(m.live) != 1:
        return 'block left'
    for i, (token, wei) in enumerate(want['claimed']):
        if (m.load(ptr + 16 * i, 8), m.load(ptr + 16 * i + 8, 8)) != (token, wei):
            return 'vector item'
    return None if res[2:8] == pattern[2:8] and res[0x20:] == pattern[0x20:] else 'result padding'


def f64_of(wei, decimals):
    return b2f(f2b(float(wei))) / 10.0 ** decimals if decimals <= 22 else None


def check_handler(m, res, v, want):
    if m.live:
        return 'block left'
    if want['status'] != OK:
        frame = bytes(m.stack.mem[FRAME + 0xc0:FRAME + 0xc0 + 0x60])
        if res[2:] != frame[2:] or m.calls:
            return 'error copy'
        return None
    pattern = bytes((i * 3 + 0x81) & 0xff for i in range(0x60))
    if res[2:] != pattern[2:]:
        return 'ok result bytes'
    rows = pay_model(v, want['claimed'])
    calls = list(m.calls)
    i = 0
    writer_reports = [c for c in calls if c[0] == 'report']
    over = sum(r['over'] for r in rows)
    if len(writer_reports) != want['reports'] + over:
        return 'report count'
    calls = [c for c in calls if c[0] != 'report']
    when = struct.unpack('<III', bytes(m.snap['ex'][0x60:0x6c]))
    blk = tuple(0x1111000000000000 + k for k in range(4)) if v.get('block') is not None else (0, 0, 0, 0)
    user = v['user']
    meta = v['meta']
    for r in rows:
        tok = r['token']
        seq = [('apply', user, tok, r['wei'], r['px'])]
        if tok:
            seq.append(('mark', tok))
        seq.append(('account', user))
        if v.get('block') is not None:
            seq.append(('block',))
        seq.append(('name', tok))
        amount = fdiv(float(r['wei']), m.img.f64(POWERS + 8 * meta[tok]['wei']))
        seq.append(('event', user, when, blk, (EVENT_TAG, 0x2222000000000000 + tok, 0x3333000000000000 + tok, 0x4444000000000000 + tok, f2b(amount))))
        if calls[i:i + len(seq)] != seq:
            return f'call sequence {tok}'
        i += len(seq)
    if i != len(calls):
        return 'extra calls'
    if read(m.account.mem, 0x10) != (rows[-1]['word'] if rows else v.get('account', 0)) & U64:
        return 'account word'
    if changed(bytes(m.account.mem), m.snap['account'], [(0x10, 0x18)]):
        return 'account bytes'
    if bytes(m.ex.mem) != m.snap['ex']:
        return 'exchange block'
    return None


# ---- vectors


class Lcg:
    def __init__(self, seed):
        self.s = seed

    def next(self, n):
        self.s = (self.s * 6364136223846793005 + 1442695040888963407) & U64
        return (self.s >> 33) % n


ME = addr(1)
YOU = addr(2)
USDC = dict(name=b'USDC', sz=2, wei=8)
HYPE_T = dict(name=HYPE, sz=2, wei=8)
PURR = dict(name=b'PURR', sz=0, wei=5)
FAKE = dict(name=b'FAKE', sz=2, wei=8)
LONG = dict(name=b'HYPEX', sz=3, wei=6)
BASE_META = (USDC, HYPE_T, PURR, FAKE, LONG, dict(name=HYPE, sz=4, wei=18), dict(name=b'HYP', sz=0, wei=8), dict(name=b'Z', sz=1, wei=8))


def vec(group, ledger=(), rows=None, user=ME, meta=BASE_META, scales=None, marks=None, **kw):
    ledger = [tuple(x) for x in ledger]
    if rows is None:
        rows = [(user, 'ledger'), (YOU, None)]
    return dict(kw, group=group, ledger=ledger, rows=rows, user=user, meta=meta, scales=scales or {}, marks=marks or {})


def both(group, *a, **kw):
    return [vec(group, *a, entry='writer', **kw), vec(group, *a, entry='handler', **kw)]


def with_h2(h, top):
    return h & ~(0x7f << 57) | (top & 0x7f) << 57


def row_vectors():
    out = both('rows', [(0, 3 * USD, 5)], rows=[])
    out += both('rows', [(0, 3 * USD, 5)], rows=[(YOU, 'ledger')])
    out += both('rows', [], rows=[(ME, 'no-root')])
    out += both('rows', [(0, 1, 2)], rows=[(ME, 'no-items')])
    out += both('rows', [(0, USD, 0)])
    same = key_hash(ME)
    near = YOU[:16] + ME[16:]
    other = ME[:16] + YOU[16:]
    out += both('rows', [(0, USD, 0)], rows=[(near, None), (other, None), (ME, 'ledger')], hashes={near: same, other: same})
    many = [(addr(i + 10), None) for i in range(40)]
    hashes = {addr(i + 10): same & ~(0x7f << 57) | (same >> 57 & 0x7f) << 57 for i in range(40)}
    out += both('rows', [(0, USD, 0)], rows=many + [(ME, 'ledger')], hashes=hashes, size=64)
    out += both('rows', [(0, USD, 0)], rows=many, hashes=hashes, size=64)
    out += both('rows', [(0, USD, 0)], rows=many[:32] + [(ME, 'ledger')], hashes=hashes, size=64)
    out += both('rows', [(0, USD, 0)], rows=many[:16] + [(ME, 'ledger')], hashes=hashes, size=64)
    mixed = {addr(i + 60): with_h2(same, (same >> 57) ^ (i + 1)) for i in range(6)}
    mixed.update({addr(70): same, addr(71): same})
    out += both('rows', [(0, USD, 0)], rows=[(k, None) for k in mixed] + [(ME, 'ledger')], hashes=mixed, size=64)
    near_ = {addr(60): with_h2(same, (same >> 57) ^ 1), addr(61): with_h2(same, (same >> 57) ^ 2), addr(70): same}
    out += both('rows', [(0, USD, 0)], rows=[(k, None) for k in near_] + [(ME, 'ledger')], hashes=near_, size=64)
    out += both('rows', [(0, USD, 0)], rows=[(ME, 'ledger')], deleted=[same + i for i in range(8)], size=16)
    wrap = (same & ~15) | 13
    out += both('rows', [(0, USD, 0)], rows=[(ME, 'ledger')], hashes={ME: wrap}, size=16)
    return out


def floor_vectors():
    out = []
    for tok, m in enumerate(BASE_META):
        need = USD * 10 ** (m['wei'] - m['sz']) // 10 ** (BASE_META[0]['wei'] - m['sz'])
        for u in (need - 1, need, need + 1, need * 7 + 3):
            if u > 0 and u <= U64:
                out += both('floor', [(tok, u, 11)], marks={tok: 1000})
    return out


def decimals_vectors():
    out = []
    for w0 in (6, 8, 9):
        for wt in range(0, 20):
            for st in (0, 1, 3, 6):
                if st > min(w0, wt):
                    continue
                meta = (dict(name=b'USDC', sz=2, wei=w0), dict(name=b'T', sz=st, wei=wt))
                need = USD * 10 ** (wt - st) // 10 ** (w0 - st)
                if 0 < need <= U64:
                    out.append(vec('decimals', [(1, need, 0)], meta=meta, marks={1: 7}, entry='writer'))
                    out.append(vec('decimals', [(1, need - 1, 0)] if need > 1 else [(1, 0, 0)], meta=meta, entry='writer'))
                else:
                    out.append(vec('decimals', [(1, U64, 0)], meta=meta, entry='writer'))
    big = (dict(name=b'USDC', sz=2, wei=8), dict(name=b'T', sz=0, wei=31))
    out += both('decimals', [(1, U64, 0)], meta=big)
    big2 = (dict(name=b'USDC', sz=0, wei=8), dict(name=b'T', sz=0, wei=24), dict(name=b'V', sz=0, wei=16))
    out += both('decimals', [(1, U64, 0), (2, 10 ** 16, 0)], meta=big2, marks={2: 3})
    wide = (dict(name=b'USDC', sz=0, wei=16), dict(name=b'T', sz=0, wei=16))
    out += both('decimals', [(0, USD, 0), (1, USD, 0)], meta=wide, marks={1: 5})
    wide = (dict(name=b'USDC', sz=0, wei=16), dict(name=b'T', sz=0, wei=8))
    out += both('decimals', [(1, USD, 0)], meta=wide, marks={1: 5})
    return out


def panic_vectors():
    out = []
    out.append(vec('panics', [(99, USD, 0)], panic='bound', entry='writer'))
    out.append(vec('panics', [(99, USD, 0)], panic='bound', entry='handler'))
    out.append(vec('panics', [(0, USD, 0)], meta=(), panic='bound', entry='writer'))
    bad = (dict(name=b'USDC', sz=2, wei=8), dict(name=b'T', sz=9, wei=9))
    out.append(vec('panics', [(1, USD, 0)], meta=bad, panic='subtract', entry='writer'))
    bad = (dict(name=b'USDC', sz=2, wei=8), dict(name=b'T', sz=3, wei=2))
    out.append(vec('panics', [(1, USD, 0)], meta=bad, panic='bound', entry='writer'))
    bad = (dict(name=b'USDC', sz=2, wei=40), dict(name=b'T', sz=2, wei=8))
    out.append(vec('panics', [(1, USD, 0)], meta=bad, panic='bound', entry='writer'))
    bad = (dict(name=b'USDC', sz=2, wei=8), dict(name=b'T', sz=0, wei=40))
    out.append(vec('panics', [(1, U64, 0)], meta=bad, panic='bound', entry='writer'))
    out.append(vec('panics', [(0, USD, 0)], length_lie=1, panic='bound', entry='writer'))
    out.append(vec('panics', [(0, USD, 0)], no_alloc=True, panic='allocation', entry='handler'))
    return out


def status_vectors():
    out = []
    out += both('status', [(0, 0, 9)])
    out += both('status', [(0, 0, 9), (1, 0, 8), (2, 0, 7)])
    out += both('status', [(0, USD - 1, 9)])
    out += both('status', [(0, 0, 1), (1, USD - 1, 2)], marks={1: 5})
    out += both('status', [(0, USD - 1, 1), (1, USD, 2)], marks={1: 5})
    out += both('status', [(0, USD, 1), (1, USD - 1, 2), (2, 0, 3), (3, 2 * USD, 4)], marks={3: 9})
    out += both('status', [(0, USD - 1, 1), (1, USD - 1, 2)])
    return out


def add_vectors():
    out = []
    for c in (0, 1, U64 - USD - 1, U64 - USD, U64 - USD + 1, U64):
        out += both('claimed-add', [(0, USD, c)])
    for c, u in ((U64, U64), (U64 - 1, U64), (1, U64)):
        out += both('claimed-add', [(1, u, c), (3, u, c)], marks={1: 2})
    out += both('claimed-add', [(i, USD + i * 3, i + 5) for i in (0, 1, 3)], marks={3: 4})
    return out


def value_vectors():
    out = []
    for tok in (1, 3, 4, 5, 6, 7):
        m = BASE_META[tok]
        need = USD * 10 ** (m['wei'] - m['sz']) // 10 ** (8 - m['sz'])
        for mark in (0, 1, 7, 100, 20000, 10 ** 6, 10 ** 8, 10 ** 12, 10 ** 15, U64):
            for wei in (need, need * 3 + 1, min(need * 10 ** 4 + 7, U64), min(need * 10 ** 7, U64)):
                out.append(vec('value', [(tok, wei, 0)], marks={tok: mark}, entry='handler'))
    edge = 0x28f5c28f5c28f5c
    for q in (CAP - 1, CAP, CAP + 1, edge - 1, edge, edge + 1):
        for tok in (1, 3, 5):
            div = 10 ** (BASE_META[tok]['wei'] - BASE_META[tok]['sz']) * 100
            need = USD * 10 ** (BASE_META[tok]['wei'] - BASE_META[tok]['sz']) // 10 ** (8 - BASE_META[tok]['sz'])
            wei = max(need, 10 ** 12) if need <= 10 ** 12 else need
            mark = q * div // wei + 1
            while mark * wei // div > q and mark > 1:
                mark -= 1
            out.append(vec('value', [(tok, wei, 0)], marks={tok: mark}, entry='handler'))
            out.append(vec('value', [(tok, wei + 1, 0)], marks={tok: mark}, entry='handler'))
    for wei in (USD, 10 ** 8 + 99, 10 ** 10, 10 ** 14, U64):
        out.append(vec('value', [(0, wei, 0)], entry='handler'))
    other = (USDC, FAKE)
    for mark in (10 ** 7, 10 ** 8, 10 ** 9):
        out.append(vec('value', [(1, 10 ** 16, 0)], meta=other, marks={1: mark}, entry='handler'))
    return out


def account_vectors():
    out = []
    top = (1 << 63) - 1
    for start in (0, 5, top - 1000, top - 100, top - 99, top, -5, -(1 << 63)):
        out.append(vec('account', [(0, 10 ** 9, 0)], account=start, entry='handler'))
        out.append(vec('account', [(0, 10 ** 9, 0), (1, 10 ** 12, 0)], marks={1: 3 * 10 ** 6}, account=start, entry='handler'))
    return out


def scale_vectors():
    out = []
    tokens = list(range(1, 8))
    for tok in tokens:
        out.append(vec('scale', [(tok, 10 ** 19, 0)], scales={tok: 12345 + tok}, entry='handler'))
        out.append(vec('scale', [(tok, 10 ** 19, 0)], scales={k: 7 + k for k in tokens if k != tok}, entry='handler'))
        out.append(vec('scale', [(tok, 10 ** 19, 0)], scales={k: 7 + k for k in tokens}, scale_fan=1, entry='handler'))
    many = {k: 100 + k for k in range(1, 200) if k % 2}
    meta = tuple(dict(name=b'T', sz=0, wei=8) for _ in range(220))
    for tok in (1, 2, 3, 57, 58, 199, 200):
        out.append(vec('scale', [(tok, 10 ** 12, 0)], scales=many, meta=meta, entry='handler'))
        out.append(vec('scale', [(tok, 10 ** 12, 0)], scales=many, meta=meta, scale_fan=2, entry='handler'))
    out.append(vec('scale', [(0, USD, 0)], scales={0: 77}, entry='handler'))
    return out


def tree_vectors():
    out = []
    meta = tuple(dict(name=b'T', sz=0, wei=8) for _ in range(3000))
    for n in (1, 2, 11, 12, 13, 24, 100, 134, 300):
        for fan in (11, 3, 1):
            items = [(i * 3 + 1, USD + i if i % 5 else USD - 1 if i % 2 else 0, i) for i in range(n)]
            out.append(vec('tree', items, meta=meta, fan=fan, entry='writer'))
    for h in range(1, 10):
        for extra in (0, 3):
            items = [(i + 1, USD + i, 0) for i in range(2 ** (h + 1) - 1 + extra)]
            out.append(vec('tree', items, meta=meta, fan=1, height=h, entry='writer'))
    items = [(i + 1, USD, 0) for i in range(5)]
    out.append(vec('tree', items, meta=meta, fan=11, entry='handler', marks={3: 11}))
    items = [(i + 1, USD, 0) for i in range(30)]
    out.append(vec('tree', items, meta=meta, fan=2, entry='handler', marks={3: 11}))
    return out


def event_vectors():
    out = []
    for flag in (0, 1, 2, 200):
        out.append(vec('event', [(0, USD, 0), (1, USD * 2 + 1, 0)], block=flag, marks={1: 9}, entry='handler'))
    for wei in (USD, USD + 1, 12345678912345, U64, 1 << 63, (1 << 63) + 1025):
        out.append(vec('event', [(0, wei, 0)], entry='handler'))
    meta = tuple(dict(name=b'T', sz=0, wei=w) for w in (8, 0, 1, 2, 5, 9, 15, 18))
    for tok in range(1, 8):
        out.append(vec('event', [(tok, 10 ** 19 + tok, 0)], meta=meta, marks={tok: 3}, entry='handler'))
    return out


def random_vectors():
    rng = Lcg(0x94)
    out = []
    for i in range(600):
        n = 1 + rng.next(14)
        toks = sorted({rng.next(8) for _ in range(n)})
        items = []
        marks, scales = {}, {}
        for t_ in toks:
            m = BASE_META[t_]
            need = USD * 10 ** (m['wei'] - m['sz']) // 10 ** (8 - m['sz'])
            kind = rng.next(5)
            u = (0, need - 1, need, need + rng.next(1 << 40), min(need * 3 + 5, U64))[kind]
            c = (0, rng.next(1 << 60), U64 - rng.next(1 << 40))[rng.next(3)]
            items.append((t_, max(u, 0), c))
            if rng.next(4):
                marks[t_] = 1 + rng.next(10 ** (1 + rng.next(14)))
            if rng.next(3) == 0:
                scales[t_] = 1 + rng.next(1 << 30)
        out.append(vec('random', items, marks=marks, scales=scales, account=rng.next(1 << 40), block=rng.next(3) if rng.next(2) else None,
                       entry='handler' if rng.next(4) else 'writer', fan=(11, 5, 2)[rng.next(3)]))
    return out


def all_vectors():
    return (row_vectors() + status_vectors() + floor_vectors() + decimals_vectors() + add_vectors() + value_vectors() + account_vectors()
            + scale_vectors() + event_vectors() + tree_vectors() + panic_vectors() + random_vectors())


# ---- image


FDE_END = {}


def bind_fdes(data):
    fdes = Fdes(data)
    for s in SUBJECTS + HELPERS:
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
    for s in SUBJECTS + HELPERS:
        code.update({i.va: i for i in decode_range(img, s, FDE_END[s])})
    slots, got = scan_slots(img, code)
    return img, code, fdes, slots, got


# ---- mutation survey


EQUIVALENT = {
    0x2711095: 'the bound compare reads a table pointer in place of the count; the writer already passed each token through the same count, so the bound never fires either way',
    0x27111e3: 'the bound compare reads a table pointer in place of the count; the writer already passed each token through the same count, so the bound never fires either way',
    0x27110e8: 'the store goes 8 bytes up; the dword at rsp+0xd0 already holds the same user bytes from 0x2710fe9 and the balance stub leaves it',
    0x3743995: 'the shuffle picks dword 1 in place of dword 0 of a register whose low two dwords are equal',
    0x3743a4a: 'the dangling pointer of an empty vector is never read: capacity 0 grows without it and is never freed',
    0x3743b25: 'cmp with 9 in place of 8 then jae: this branch has rbx & 7 not zero, so rbx is never 8',
    0x3743c08: 'cmp with 9 in place of 8 then jae: this branch has rax & 7 not zero, so rax is never 8',
    0x3743c44: 'not reachable: the value is read only on a second pass of the 8-step descent, at height 16 or more, and a B-tree that tall holds over 6^16 items',
}
UNEXECUTED = (
    (0x2711065, 0x271106a, 'jump to the unwrap panic: 0x32815f0 reports success only below 0x28f5c28f5c28f5c, and failure leaves 0, so the sign test always passes'),
    (0x271139f, 0x2711434, 'two token bound panics (the writer already passed the token through the same bound), the unwrap panic, unwind cleanup'),
    (0x3743d0d, 0x3743d12, 'jump after cmp rax,8: rax is a non-zero multiple of 8 here, so the jae above always goes'),
    (0x3743da2, 0x3743db5, 'free of an empty vector: capacity only grows just before a push, so length 0 means capacity 0'),
    (0x3743dc2, 0x3743deb, 'ud2 after a panic call and unwind cleanup'),
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


def sample(vecs):
    """The survey set: curated groups whole, about 80 of each generated group, chosen by a hash of the index."""
    count, kept = {}, []
    for v in vecs:
        count[v['group']] = count.get(v['group'], 0) + 1
    for i, v in enumerate(vecs):
        if hashlib.sha256(str(i).encode()).digest()[0] * count[v['group']] < 256 * 80:
            kept.append(v)
    return kept


def try_kill(mimg, mcode, slots, got, picked):
    for pos, v in enumerate(picked):
        try:
            bad = check(mimg, mcode, slots, got, v)
        except (Unmodelled, Panicked, EvidenceError, KeyError, OverflowError, ValueError, TypeError, struct.error, IndexError, MemoryError, ZeroDivisionError, StopIteration) as exc:
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


def format_text(img, at):
    """Format pieces: <len><text>, 0xc0 is a placeholder, then the next literal length, 0x00 ends."""
    out, cursor = [], at
    while True:
        n = img.read(cursor, 1)[0]
        cursor += 1
        if n == 0:
            return ''.join(out)
        if n == 0xc0:
            out.append('{}')
            continue
        if n > 0x7f:
            raise EvidenceError(f'format byte {n:#x} at {cursor - 1:#x}')
        out.append(img.read(cursor, n).decode('utf8'))
        cursor += n


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


def pinned(img):
    out = []
    for va, raw, meaning in PINNED:
        want = raw.replace(' ', '')
        got = img.read(va, len(want) // 2).hex()
        if got != want:
            raise EvidenceError(f'bytes at {va:#x} are {got}, not {want}')
        out.append(dict(va=hex(va), bytes=want, meaning=meaning))
    return out


def powers_table(img):
    """f64 divisors at 0x584b08 up to the first entry that is not 10^i."""
    out = []
    for i in range(64):
        x = img.f64(POWERS + 8 * i)
        if x != 10.0 ** i:
            break
        out.append(i)
    return dict(start=hex(POWERS), exact_powers=len(out), next_word=hex(img.u64(POWERS + 8 * len(out))))


def digest_of(v):
    return hashlib.sha256(repr(sorted((k, repr(x)) for k, x in v.items())).encode()).hexdigest()[:16]


REFERENCE_ROWS = (
    ('differs', 'claimable_reward_rows, staking wording', 'per-user staking reward rows', 'the writer reads the token tree at row +0xb0 of FeeTracker user_states (tracker +0xc0, exchange +0x5d0); no staking state is read'),
    ('differs', 'order of the loop', 'one loop: consume, balance, unit credit, event per token', 'the writer 0x3743930 finishes every token first, then the handler loops over the returned vector'),
    ('differs', 'quote_notional_usdc_8dp passed to the balance update', 'the balance update takes the notional', 'r9 at 0x371d120 is the scale tree value at meta +0x1c0, else the unit price of 0x375fb50, and 0 for token 0'),
    ('differs', 'ClaimRewardEvent', 'user, asset id, wei, notional', 'event variant 0x11 holds a name string from 0x3c0d6e0 and an f64 wei / 10^wei decimals; the user is a one-item list argument, with time and block arguments'),
    ('same', 'minimum_claim_wei', '100000000 raw notional and spot metadata', 'edi 0x5f5e100 at 0x3743c93, price from metadata only; no market price enters the floor'),
    ('same', 'dust skip', 'zero skipped, below floor skipped, seen flag before the floor test', 'the same at 0x3743c74, 0x3743cac, 0x3743cb9'),
    ('same', 'status numbers', '390, 166, 167', 'tags 0x186, 0xa6, 0xa7; the seen flag is the low bit of the status'),
    ('same', 'consume_reward', 'zero claimable, saturating add into claimed', 'value +8 zeroed at 0x3743cc5, value +0x10 saturating at 0x3743cd3..0x3743d2b'),
    ('same', 'units divide', '/ 10000', 'reciprocal at 0x2711112 with shr 0xb'),
)


def generate(data, out_dir, with_survey=True):
    global SEEN
    img, code, fdes, slots, got = build(data)
    listing = {s_: decode_range(img, s_, FDE_END[s_]) for s_ in SUBJECTS + HELPERS}
    vecs = all_vectors()
    seen = SEEN = set()
    try:
        for v in vecs:
            try:
                msg = check(img, code, slots, got, v)
            except (Unmodelled, Panicked, EvidenceError, KeyError) as exc:
                msg = f'fault {type(exc).__name__} {exc}'
            if msg:
                raise EvidenceError(f"mismatch in {v['group']}: {msg}")
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
        raise EvidenceError(f'survivors {sorted(hex(s_) for s_ in survivors ^ set(EQUIVALENT))} of {len(rows)}')
    starts = sorted(f['start'] for f in eh_frame_records(data)[1])
    sites = slot_sites(img, WRITER_SLOT, starts)
    copies = [int(x['function'], 16) for x in sites if int(x['function'], 16) != HANDLER]
    arm = img.read(STATUS_ARM, 10)
    if arm != bytes.fromhex('48b8000000000000f03f'):
        raise EvidenceError('status 0xa7 arm')
    out_path = Path(out_dir)
    out_path.mkdir(parents=True, exist_ok=True)
    groups, outcomes = {}, {}
    with open(out_path / 'vectors.tsv', 'w', newline='\n') as f:
        f.write('group\tentry\ttokens\tstate\tstatus\tclaimed\n')
        for v in vecs:
            groups[v['group']] = groups.get(v['group'], 0) + 1
            want, kind = outcome(v)
            if kind is not None:
                name, n = 'panic ' + kind, ''
            else:
                name, n = hex(want['status']), len(want['claimed'])
            outcomes[name] = outcomes.get(name, 0) + 1
            f.write(f"{v['group']}\t{v.get('entry', 'handler')}\t{len(v['ledger'])}\t{digest_of(v)}\t{name}\t{n}\n")
    with open(out_path / 'mutations.tsv', 'w', newline='\n') as f:
        f.write('kind\tfunction\tva\tinstruction\tresult\tvector\treason\n')
        for r in rows:
            k = r['killed']
            f.write(f"{r['kind']}\t{r['fn']:#x}\t{r['va']:#x}\t{r['op']}\t{'killed' if k else 'equivalent'}\t{k[0] if k else ''}\t{k[1] if k else EQUIVALENT[r['va']]}\n")
    with open(out_path / 'instructions.tsv', 'w', newline='\n') as f:
        f.write('function\tva\tsize\tbytes\tdecoded\texecuted\n')
        for fn in SUBJECTS + HELPERS:
            for i in listing[fn]:
                f.write(f'{fn:#x}\t{i.va:#x}\t{i.size}\t{i.raw.hex()}\t{show(i)}\t{int(i.va in seen)}\n')
    with open(out_path / 'reference-diff.tsv', 'w', newline='\n') as f:
        f.write('verdict\treference\treference_says\tbytes_say\n')
        for row in REFERENCE_ROWS:
            f.write('\t'.join(row) + '\n')
    per = {}
    for fn in SUBJECTS + HELPERS:
        per[hex(fn)] = dict(end=hex(FDE_END[fn]), fde=hex(fdes.range_of(fn)['fde']), instructions=len(listing[fn]), executed=sum(i.va in seen for i in listing[fn]))
    evidence = dict(
        binary=BINARY, sha256=SHA256, functions=per, subjects=[hex(s_) for s_ in SUBJECTS], real_helpers=[hex(s_) for s_ in HELPERS],
        stubs=dict(hash=hex(HASH), apply=hex(APPLY), mark=hex(MARK), account=hex(ACCOUNT), block=hex(BLOCK), name=hex(slots[SLOT_NAME]), event=hex(slots[SLOT_EVENT]), report=hex(slots[SLOT_REPORT]), grow=hex(slots[SLOT_GROW])),
        writer_slot=hex(WRITER_SLOT), writer_target=hex(img.relative(WRITER_SLOT)), writer_callers=sites, handler_copies=copy_rows(img, fdes, HANDLER, copies),
        copy_callers={hex(c): direct_sites(img, c, starts) for c in copies},
        handler_callers=direct_sites(img, HANDLER, starts), floor_callers=direct_sites(img, FLOOR, starts),
        locations={'claimed_add': location(img, 0x56dfd78), 'account_add': location(img, 0x5715ef8), 'tree_end': location(img, 0x56f2388), 'unwrap': location(img, 0x56c7388)},
        hype_name=img.read(0x209e14, 4).decode(), powers=powers_table(img),
        status_text={hex(NOTHING): status_text(img, NOTHING)},
        status_arm=dict(tag=hex(TOO_SMALL), target=hex(STATUS_ARM), table_target=hex(0x59a8d0 + struct.unpack('<i', img.read(0x59a8d0 + 4 * TOO_SMALL, 4))[0]), argument_f64=struct.unpack('<d', arm[2:])[0], format=format_text(img, STATUS_FORMAT)),
        pinned=pinned(img), vectors=len(vecs), mismatches=0, groups=groups, outcomes=outcomes, padding_not_executed=padding,
        unexecuted=[dict(start=hex(a), end=hex(b), why=w) for a, b, w in UNEXECUTED], mutants=len(rows), killed=sum(1 for r in rows if r['killed']),
        survey_vectors=len(sample(vecs)), equivalent={hex(k): w for k, w in sorted(EQUIVALENT.items())},
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
