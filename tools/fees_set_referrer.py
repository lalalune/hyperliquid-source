#!/usr/bin/env python3
"""fees: node #94 setReferrer path, from bytes alone.

Static, no execution of the node.  The wrapper 0x27de270, the helper 0x37433c0, the bucket step 0x394b7e0
and the log insert 0x33a2400 are decoded from ELF bytes by the table decoder below, which must land exactly
on each FDE end, and interpreted in Python on every vector.  The hash, table growth, the status drop, the
vacant B-tree insert and allocation are stubs that check their arguments.  Each outcome is compared with a
separate closed-form model, then every conditional, field offset and immediate is mutated to test the vectors.

    python3 tools/fees_set_referrer.py --out <dir>

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

WRAPPER = 0x27de270
HELPER = 0x37433c0
BUCKET = 0x394b7e0
LOG_INSERT = 0x33a2400
SUBJECTS = (WRAPPER, HELPER, BUCKET, LOG_INSERT)
HELPER_SLOT = 0x5774f38
HASH = 0x399c7a0
DROP = 0x3999770
DROP_TABLE = 0x5a49f0
DROP_FIRST = 0x3a
DROP_PLAIN = 0x399993e
LOG_VACANT = 0x2f23c60
AFTER_LOG = 0x394b91e
BEFORE_CLAMP = 0x394b89b
RESERVE_SLOT = 0x5773680
GOT_ALLOC = 0x576dfd8
GOT_MEMCMP = 0x576e488
GOT_ALLOC_ERROR = 0x576e020
OK = 0x186
SELF_CODE = 0x9e
ALREADY_SET = 0x9f
NO_ROOM = 0xa1
UNKNOWN_CODE = 0xa2
TOO_LONG_ENTRY = 0x143
STATUSES = (OK, SELF_CODE, ALREADY_SET, NO_ROOM, UNKNOWN_CODE, TOO_LONG_ENTRY)
TAG_OK = 13
TAG_ERR = 14
MAX_CODE = 100
MIN_REFRESH = 1000
STRIDE = 0xe8
EXCHANGE_SIZE = 0x800
TIME_AT = 0x60
TRACKER = 0x5d0
TABLE = TRACKER + 0xc0
PROFILES = TRACKER + 0x108
CODES = TRACKER + 0x120
BUCKET_MS = TRACKER + 0x138
PROFILE_SIZE = 0x48
LOG_LEAF = 0x170
LOG_VALUE = 0xe4
ROW_FLAG = 0xcc
ROW_OWNER = 0xcd
DAY_SECONDS = 86400
EPOCH_DAYS = 719163
PINNED = (
    (0x27de278, '8b4168', 'wrapper: time word at exchange +0x68'),
    (0x27de27f, '488b4160', 'wrapper: time words at exchange +0x60'),
    (0x27de28b, '4983f865', 'wrapper: compare the code length with 0x65'),
    (0x27de291, '66c743084301', 'wrapper: tag 0x143'),
    (0x27de29d, '4881c1d0050000', 'wrapper: tracker is exchange +0x5d0'),
    (0x3743479, '4983c414', 'helper: value stride of the code tree is 20 bytes'),
    (0x37434cb, '418b442410', 'helper: last 4 of the 20 owner bytes, there is no further word'),
    (0x37435fa, '66c700a200', 'helper: tag 0xa2'),
    (0x374360a, '418079e401', 'helper: row flag at row end -0x1c, row +0xcc'),
    (0x3743618, '6641c7069f00', 'helper: tag 0x9f'),
    (0x3743628, '66c7009e00', 'helper: tag 0x9e'),
    (0x374383b, 'c641e401', 'helper: row flag set only after the bucket step'),
    (0x3743845, 'f30f7f41e5', 'helper: first 16 owner bytes at row +0xcd'),
    (0x374384e, '8941f5', 'helper: last 4 owner bytes at row +0xdd'),
    (0x394b82b, '66b9a100', 'bucket: tag 0xa1 prepared'),
    (0x394b82f, '4d85c0', 'bucket: zero width test'),
    (0x394b871, '05c506f5ff', 'bucket: days to 1970'),
    (0x394b89d, '4885d2', 'bucket: test of the signed time'),
    (0x394b8a0, '480f4fc2', 'bucket: clamp at 0'),
    (0x394b8de, '483de9030000', 'bucket: compare the configured word with 0x3e9'),
    (0x394b8e4, '41bde8030000', 'bucket: floor 1000'),
)
STACK_FILL = bytes((i * 5 + 3) & 0xff | 1 for i in range(0x8000))
TOP = 0x7f08


SEEN = None


class Panicked(Exception):
    """The node would panic here; a modelled outcome, unlike Unmodelled."""


def addr(n):
    """A 20-byte test address."""
    return hashlib.sha256(b'addr' + str(n).encode()).digest()[:20]


def key_hash(key):
    return int.from_bytes(hashlib.sha256(key).digest()[:8], 'little')


# ---- model, written from the observed rules and independent of the machine


def raw_millis(t):
    """Signed milliseconds of (packed date, seconds, nanoseconds) since 1970, floor arithmetic."""
    date, secs, frac = t
    year = signed(date, 32) >> 13
    ordinal = date >> 4 & 0x1ff
    y = year - 1
    days = 365 * y + y // 4 - y // 100 + y // 400 + ordinal - EPOCH_DAYS
    return (days * DAY_SECONDS + secs) * 1000 + frac // 1000000


def millis(t):
    return max(raw_millis(t), 0)


def packed(year, ordinal, flags=0):
    return (year << 13 | ordinal << 4 | flags) & 0xffffffff


def model(v):
    """Status and effect of one call.  `insert`: a new empty row.  `bind`: the owner stored in the row.
    `profile`: (owner, remaining, bucket, new log key)."""
    out = dict(insert=False, bind=None, profile=None)
    code, user = v['code'], v['user']
    if v['entry'] == 'wrapper' and len(code) > MAX_CODE:
        return dict(out, status=TOO_LONG_ENTRY)
    owner = v['codes'].get(code)
    if owner is None:
        return dict(out, status=UNKNOWN_CODE)
    if owner == user:
        return dict(out, status=SELF_CODE)
    rows = {k: o for k, _, o in v['rows']}
    if user in rows:
        if rows[user] is not None:
            return dict(out, status=ALREADY_SET)
    else:
        out['insert'] = True
    p = v['profiles'].get(owner)
    if p is None:
        return dict(out, status=OK)
    if v['bucket_ms'] == 0:
        return dict(out, status=NO_ROOM)
    bucket = millis(v['time']) // v['bucket_ms']
    if bucket == p['bucket']:
        left = p['remaining']
        if left == 0:
            return dict(out, status=NO_ROOM)
    else:
        left = max(p['configured'], MIN_REFRESH)
    return dict(out, status=OK, bind=owner, profile=(owner, left - 1, bucket, user not in p['log']))


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


# ---- B-tree nodes, written by this tool in the three layouts the path reads


class Layout:
    def __init__(self, leaf_size, parent, parent_index, length, edges):
        self.leaf_size = leaf_size
        self.parent, self.parent_index, self.length, self.edges = parent, parent_index, length, edges


# parent +0, value +8 (0x48), key +0x320 (20), parent index +0x3fc, length +0x3fe, edges +0x400
PROFILE_NODE = Layout(0x400, 0, 0x3fc, 0x3fe, 0x400)
# parent +0, key +8 (String), value +0x110 (20), parent index +0x1ec, length +0x1ee, edges +0x1f0
CODE_NODE = Layout(0x1f0, 0, 0x1ec, 0x1ee, 0x1f0)
# parent +0, key +8 (20), value +0xe4 (12), parent index +0x168, length +0x16a, edges +0x170
LOG_NODE = Layout(LOG_LEAF, 0, 0x168, 0x16a, 0x170)


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

    def __init__(self, m, layout, items, fan, fill, pattern):
        self.m, self.lay, self.items, self.fan, self.fill = m, layout, items, fan, fill
        self.height = tree_height(len(items), fan)
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


def time_bytes(t):
    return struct.pack('<III', *t)


def fill_log(tree, at, pos, item):
    key, t = item
    tree.arena.mem[at + 8 + 20 * pos:at + 28 + 20 * pos] = key
    tree.arena.mem[at + LOG_VALUE + 12 * pos:at + LOG_VALUE + 12 + 12 * pos] = time_bytes(t)


def log_key(tree, at, pos):
    return bytes(tree.arena.mem[at + 8 + 20 * pos:at + 28 + 20 * pos])


def fill_profile(tree, at, pos, item):
    key, p = item
    m = tree.m
    base = at + 8 + PROFILE_SIZE * pos
    tree.arena.mem[at + 0x320 + 20 * pos:at + 0x334 + 20 * pos] = key
    log = Tree(m, LOG_NODE, sorted(p['log'].items()), p.get('fan', 11), fill_log, 0x66)
    log.key_at = lambda at_, pos_: log_key(log, at_, pos_)
    m.logs[key] = log
    m.profile_places[key] = base
    tree.word(base + 0x18, 8, p['remaining'])
    tree.word(base + 0x20, 8, log.root)
    if log.root:
        tree.word(base + 0x28, 8, log.height)
    tree.word(base + 0x30, 8, len(p['log']))
    tree.word(base + 0x38, 8, p['bucket'])
    tree.word(base + 0x40, 8, p['configured'])


def fill_code(tree, at, pos, item):
    text, owner = item
    m = tree.m
    slot = at + 8 + 0x18 * pos
    if text:
        block = m.arena(len(text) + 3)
        block.mem[:len(text)] = text
        block.valid[:len(text)] = b'\1' * len(text)
    tree.word(slot, 8, len(text) + 3 if text else 0)
    tree.word(slot + 8, 8, block.base if text else 1)
    tree.word(slot + 0x10, 8, len(text))
    tree.arena.mem[at + 0x110 + 20 * pos:at + 0x124 + 20 * pos] = owner


def place_of(tree, want):
    """Leaf and index where a missing key belongs, by a walk over the written node bytes."""
    lay = tree.lay
    at, h = tree.root - tree.arena.base, tree.height
    mem = tree.arena.mem
    while True:
        n = read(mem, at + lay.length, 2)
        pos = 0
        while pos < n and tree.key_at(at, pos) < want:
            pos += 1
        if h == 0:
            return tree.arena.base + at, pos
        at = read(mem, at + lay.edges + 8 * pos) - tree.arena.base
        h -= 1


def set_ctrl(ctrl, mask, i, val):
    ctrl[i] = val
    ctrl[((i - 16) & mask) + 16] = val


def write_table(m, size, rows, deleted, growth, items, fill=None):
    """A hash table of `size` buckets.  rows lists (key, hash, stored owner or None), in insert order."""
    mask = size - 1
    a = m.arena(STRIDE * size + size + 32)
    a.mem[:] = fill_bytes(len(a.mem), 0x17) if fill is None else bytes([fill]) * len(a.mem)
    a.valid[:] = b'\1' * len(a.mem)
    ctrl_off = STRIDE * size + 16
    ctrl = [0xff] * (size + 16)
    for key, h, owner in rows:
        slot = free_slot(ctrl, mask, h)
        set_ctrl(ctrl, mask, slot, h >> 57)
        row = ctrl_off - (slot + 1) * STRIDE
        a.mem[row:row + 20] = key
        a.mem[row + ROW_FLAG] = 0 if owner is None else 1
        if owner is not None:
            a.mem[row + ROW_OWNER:row + ROW_OWNER + 20] = owner
    for i in deleted:
        if ctrl[i & mask] == 0xff:
            set_ctrl(ctrl, mask, i & mask, 0x80)
    a.mem[ctrl_off:ctrl_off + size + 16] = bytes(ctrl)
    word(m.ex, TABLE, 8, a.base + ctrl_off)
    word(m.ex, TABLE + 8, 8, mask)
    word(m.ex, TABLE + 0x10, 8, growth)
    word(m.ex, TABLE + 0x18, 8, items)
    m.table = dict(arena=a, ctrl_off=ctrl_off, size=size, rows=rows)


def v_fill(m):
    return m.fill


def machine(img, code, slots, got):
    m = Machine(img, ())
    if SEEN is not None:
        m.seen = SEEN
    m.code = code
    m.slots = slots
    m.got = got
    for fn in (WRAPPER, HELPER, BUCKET, LOG_INSERT):
        m.real[fn] = fn
    stack = m.arena(0x8000, strict=False)
    stack.mem[:] = STACK_FILL
    m.stack = stack
    m.top = stack.base + TOP
    m.live = {}
    m.hashes = {}
    m.calls = []
    m.logs = {}
    m.profile_places = {}
    m.alloc_left = None
    m.snap = {}

    def alloc():
        if m.regs[R['rdi']] != LOG_LEAF:
            raise Unmodelled('allocation size')
        if m.alloc_left is not None:
            m.alloc_left -= 1
            if m.alloc_left < 0:
                return m.clobber(0)
        a = m.arena(LOG_LEAF)
        m.live[a.base] = LOG_LEAF
        return m.clobber(a.base)

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

    def drop():
        at = m.regs[R['rdi']]
        if at != m.regs[R['rsp']] or m.load(at, 2) != NO_ROOM:
            raise Unmodelled('drop of another value')
        m.calls.append(('drop',))
        m.clobber()

    def reserve():
        """Grows to twice the buckets and drops tombstones, so a caller holding old table words is caught."""
        r = m.regs
        if (r[R['rdi']], r[R['rsi']], r[R['rdx']], r[R['rcx']]) != (m.tracker + 0xc0, 1, m.tracker + 0xe0, 1):
            raise Unmodelled('reserve arguments')
        t = m.table
        old_rows, items = t['rows'], read(m.ex.mem, TABLE + 0x18)
        size = t['size'] * 2
        write_table(m, size, old_rows, (), size * 7 // 8 - items, items, v_fill(m))
        m.snap['table'] = bytes(m.table['arena'].mem)
        for off in (0, 8, 0x10, 0x18):
            lo = TABLE + off
            m.snap['ex'] = m.snap['ex'][:lo] + bytes(m.ex.mem[lo:lo + 8]) + m.snap['ex'][lo + 8:]
        m.calls.append(('reserve',))
        m.clobber()

    def log_vacant():
        r = m.regs
        at = r[R['rsp']]
        got_args = (r[R['rdi']], r[R['rsi']], r[R['rdx']], r[R['rcx']], r[R['r8']], r[R['r9']])
        if got_args != (at + 0xb0, at + 0x90, at + 0x70, m.time_ptr, at + 0x38, at + 0x6c):
            raise Unmodelled('log entry arguments')
        leaf, h, pos = (m.load(at + 0x90 + k, 8) for k in (0, 8, 0x10))
        key = bytes(m.load(at + 0x70 + k, 1) for k in range(20))
        log = m.logs[m.owner]
        if h != 0 or (leaf, pos) != place_of(log, key):
            raise Unmodelled('log place')
        m.calls.append(('log', key, bytes(m.load(m.time_ptr + k, 1) for k in range(12))))
        m.clobber()

    def alloc_error():
        if (m.regs[R['rdi']], m.regs[R['rsi']]) != (8, LOG_LEAF):
            raise Unmodelled('alloc error arguments')
        raise Panicked('allocation')

    def log_result():
        at = m.regs[R['rsp']]
        m.log_result = bytes(m.load(at + k, 1) for k in range(12))

    def raw_time():
        m.raw_ms = signed(m.regs[R['rdx']], 64)

    m.hooks[BEFORE_CLAMP] = raw_time
    m.raw_ms = None
    m.hooks[AFTER_LOG] = log_result
    m.log_result = None
    m.memcmp_scale = 1
    m.stubs.update({HASH: hash_stub, DROP: drop, LOG_VACANT: log_vacant})
    for s, fn in ((GOT_ALLOC, alloc), (GOT_MEMCMP, memcmp), (GOT_ALLOC_ERROR, alloc_error), (RESERVE_SLOT, reserve)):
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


def helper_entry(m, wrapped):
    """Stack pointer at the helper's first instruction, reached from the wrapper or called directly."""
    return m.top - 0x80 if wrapped else m.top


def run(img, code, slots, got, v):
    """One call on a fresh state.  Returns status and the machine."""
    m = machine(img, code, slots, got)
    m.alloc_left = v.get('alloc')
    m.memcmp_scale = v.get('scale', 1)
    m.fill = v.get('fill')
    m.owner = v['codes'].get(v['code'])
    ex = m.arena(EXCHANGE_SIZE)
    ex.mem[:] = fill_bytes(EXCHANGE_SIZE, 0x41)
    ex.valid[:] = b'\1' * EXCHANGE_SIZE
    m.ex = ex
    m.tracker = ex.base + TRACKER
    ex.mem[TIME_AT:TIME_AT + 12] = time_bytes(v['time'])
    word(ex, BUCKET_MS, 8, v['bucket_ms'])
    rows = [(k, key_hash(k) if h is None else h, o) for k, h, o in v['rows']]
    m.hashes = {k: h for k, h, _ in rows}
    if 'user_hash' in v:
        m.hashes[v['user']] = v['user_hash']
    write_table(m, v.get('size', 32), rows, [m.hashes.get(v['user'], key_hash(v['user'])) + i for i in v.get('deleted', ())], v.get('growth', 2), len(rows), v.get('fill'))
    profiles = Tree(m, PROFILE_NODE, sorted(v['profiles'].items()), v.get('fan', 11), fill_profile, 0x55)
    codes = Tree(m, CODE_NODE, sorted(v['codes'].items()), v.get('fan', 11), fill_code, 0x77)
    word(ex, PROFILES, 8, profiles.root)
    word(ex, PROFILES + 8, 8, profiles.height)
    word(ex, PROFILES + 0x10, 8, len(v['profiles']))
    word(ex, CODES, 8, codes.root)
    word(ex, CODES + 8, 8, codes.height)
    word(ex, CODES + 0x10, 8, len(v['codes']))
    m.parts = profiles, codes
    m.snap = dict(ex=bytes(ex.mem), table=bytes(m.table['arena'].mem), profiles=profiles.snapshot(), codes=codes.snapshot(), logs={k: t.snapshot() for k, t in m.logs.items()})
    m.before = dict(m.live)
    user = m.arena(20)
    user.mem[:] = v['user']
    user.valid[:] = b'\1' * 20
    text = m.arena(max(len(v['code']), 1))
    text.mem[:len(v['code'])] = v['code']
    text.valid[:len(v['code'])] = b'\1' * len(v['code'])
    wrapped = v['entry'] == 'wrapper'
    m.wrapped = wrapped
    if wrapped:
        action = m.arena(0x18)
        action.mem[:] = struct.pack('<QQQ', 0x4444444444444444, text.base, len(v['code']))
        action.valid[:] = b'\1' * 0x18
        out = m.arena(0x70, strict=False)
        out.mem[:] = fill_bytes(0x70, 0x21)
        m.time_ptr = m.top - 8 - 0x70
        enter(m, WRAPPER, out.base, action.base, user.base, ex.base)
        if m.regs[0] != out.base:
            raise Unmodelled('return value')
        tag = out.mem[0]
        if tag == TAG_OK:
            status = OK
            if bytes(out.mem[1:]) != fill_bytes(0x70, 0x21)[1:]:
                raise Unmodelled('success wrote the output')
        elif tag == TAG_ERR:
            status = read(out.mem, 8, 2)
            if status == OK:
                raise Unmodelled('error tag with the success status')
            if status == TOO_LONG_ENTRY:
                if read(out.mem, 0x10) != action.base or bytes(out.mem[0x18:]) != fill_bytes(0x70, 0x21)[0x18:]:
                    raise Unmodelled('action pointer word')
            else:
                frame = m.top - 8 - 0x70 + 0x10 - m.stack.base
                if bytes(out.mem[8:0x68]) != bytes(m.stack.mem[frame:frame + 0x60]):
                    raise Unmodelled('error copy')
        else:
            raise Unmodelled(f'outer tag {tag}')
    else:
        stamp = m.arena(12)
        stamp.mem[:] = time_bytes(v['time'])
        stamp.valid[:] = b'\1' * 12
        out = m.arena(0x60, strict=False)
        out.mem[:] = fill_bytes(0x60, 0x29)
        m.time_ptr = stamp.base
        enter(m, HELPER, out.base, m.tracker, user.base, text.base, len(v['code']), stamp.base)
        if m.regs[0] != out.base:
            raise Unmodelled('return value')
        status = read(out.mem, 0, 2)
        if status == NO_ROOM:
            frame = m.top - 0x128 + 0x98 - m.stack.base
            if bytes(out.mem) != bytes(m.stack.mem[frame:frame + 0x60]):
                raise Unmodelled('error copy')
        elif bytes(out.mem[2:]) != fill_bytes(0x60, 0x29)[2:]:
            raise Unmodelled('output past the status')
    return status, m


def expected_table(m, v, want):
    """Whole table bytes and the four table words the call must leave."""
    t = m.table
    a, ctrl_off, size = t['arena'], t['ctrl_off'], t['size']
    mask = size - 1
    old = bytearray(m.snap['table'])
    ctrl = list(old[ctrl_off:ctrl_off + size + 16])
    growth, items = read(m.snap['ex'], TABLE + 0x10), read(m.snap['ex'], TABLE + 0x18)
    user = v['user']
    if want['insert']:
        h = m.hashes.get(user, key_hash(user))
        slot = free_slot(ctrl, mask, h)
        growth -= ctrl[slot] & 1
        items += 1
        set_ctrl(ctrl, mask, slot, h >> 57)
        old[ctrl_off:ctrl_off + size + 16] = bytes(ctrl)
        row = ctrl_off - (slot + 1) * STRIDE
        old[row:row + 20] = user
        for off, n in ((0x18, 8), (0x98, 8), (0xa8, 8), (0xb0, 8), (0xc0, 8), (0xc8, 4), (ROW_FLAG, 1)):
            old[row + off:row + off + n] = bytes(n)
        hold = helper_entry(m, m.wrapped) - 0xa8 - m.stack.base
        old[row + 0xa0:row + 0xa8] = bytes(m.stack.mem[hold:hold + 8])
    else:
        row = None
        for i in range(size):
            at = ctrl_off - (i + 1) * STRIDE
            if not ctrl[i] & 0x80 and bytes(old[at:at + 20]) == user:
                row = at
    if want['bind'] is not None:
        old[row + ROW_FLAG] = 1
        old[row + ROW_OWNER:row + ROW_OWNER + 20] = want['bind']
    return bytes(old), growth, items


def expected_trees(m, v, want):
    """Profile tree and owner log bytes after the call; a null log root is checked apart."""
    profiles = bytearray(m.snap['profiles'])
    if want['profile'] is None:
        return bytes(profiles), None
    owner, left, bucket, fresh = want['profile']
    base = m.profile_places[owner]
    log = m.logs[owner]
    logs = bytearray(m.snap['logs'][owner])
    profiles[base + 0x18:base + 0x20] = left.to_bytes(8, 'little')
    profiles[base + 0x38:base + 0x40] = bucket.to_bytes(8, 'little')
    profiles[base + 0x30:base + 0x38] = (read(profiles, base + 0x30) + int(fresh)).to_bytes(8, 'little')
    if not fresh:
        i = log_index(log, v['user'])
        logs[i:i + 12] = time_bytes(v['time'])
    return bytes(profiles), bytes(logs)


def log_index(log, key):
    """Offset of the value of a stored key, by a walk over the snapshot nodes."""
    lay = log.lay
    at, h = log.root - log.arena.base, log.height
    mem = log.arena.mem
    while True:
        n = read(mem, at + lay.length, 2)
        pos = 0
        while pos < n and log.key_at(at, pos) < key:
            pos += 1
        if pos < n and log.key_at(at, pos) == key:
            return at + LOG_VALUE + 12 * pos
        at = read(mem, at + lay.edges + 8 * pos) - log.arena.base
        h -= 1


def check(img, code, slots, got, v):
    want = None if 'panic' in v else model(v)
    try:
        status, m = run(img, code, slots, got, v)
    except Panicked as exc:
        if v.get('panic') == str(exc):
            return None
        raise
    if 'panic' in v:
        return f"no {v['panic']} panic"
    if status != want['status']:
        return f"status {status:#x} != {want['status']:#x}"
    if m.raw_ms is not None and m.raw_ms != raw_millis(v['time']):
        return 'signed time before the clamp'
    table, growth, items = expected_table(m, v, want)
    if bytes(m.table['arena'].mem) != table:
        return 'table bytes'
    ex = bytearray(m.snap['ex'])
    ex[TABLE + 0x10:TABLE + 0x18] = growth.to_bytes(8, 'little')
    ex[TABLE + 0x18:TABLE + 0x20] = items.to_bytes(8, 'little')
    if bytes(m.ex.mem) != bytes(ex):
        return 'exchange bytes'
    profiles, codes = m.parts
    if codes.snapshot() != m.snap['codes']:
        return 'code tree moved'
    calls = [c for c in m.calls if c[0] != 'reserve']
    want_calls = []
    new_root = None
    p = want['profile']
    if p is not None:
        want_calls.append(('drop',))
        if p[3]:
            if v['profiles'][p[0]]['log']:
                want_calls.append(('log', v['user'], time_bytes(v['time'])))
            else:
                new_root = p[0]
    if calls != want_calls:
        return f'helper calls differ: {len(calls)} and {len(want_calls)}'
    expect_profiles, expect_log = expected_trees(m, v, want)
    now = profiles.snapshot()
    if new_root is not None:
        base = m.profile_places[new_root]
        node = read(now, base + 0x20)
        if read(now, base + 0x28) != 0:
            return 'height of a new root'
        expect_profiles = bytearray(expect_profiles)
        expect_profiles[base + 0x20:base + 0x30] = now[base + 0x20:base + 0x30]
        expect_profiles = bytes(expect_profiles)
        if m.live.get(node) != LOG_LEAF:
            return 'new root block'
        if m.load(node, 8) != 0 or m.load(node + 0x16a, 2) != 1:
            return 'new root words'
        if bytes(m.load(node + 8 + k, 1) for k in range(20)) != v['user']:
            return 'new root key'
        if bytes(m.load(node + LOG_VALUE + k, 1) for k in range(12)) != time_bytes(v['time']):
            return 'new root value'
        m.live.pop(node)
    if now != expect_profiles:
        return 'profile node changed'
    for key, log in m.logs.items():
        keep = expect_log if p is not None and key == p[0] and expect_log is not None else m.snap['logs'][key]
        if log.snapshot() != keep:
            return 'log node changed'
    if p is not None:
        old = v['profiles'][p[0]]['log'].get(v['user'])
        if old is not None and m.log_result != time_bytes(old):
            return 'old time of the log insert'
        if old is None and m.log_result[:4] != bytes(4):
            return 'empty result of the log insert'
    if m.live != m.before:
        return 'leaked or lost a block'
    return None


# ---- vectors


class Lcg:
    def __init__(self, seed):
        self.s = seed

    def next(self, n):
        self.s = (self.s * 6364136223846793005 + 1442695040888963407) & U64
        return (self.s >> 33) % n


ME, YOU = addr(1), addr(2)
DAY_MS = DAY_SECONDS * 1000
NOW = (packed(2026, 304, 6), 3600, 500000000)
NOW_MS = millis(NOW)


def prof(remaining=5, bucket=0, configured=0, log=None, **kw):
    return dict(remaining=remaining, bucket=bucket, configured=configured, log=dict(log or {}), **kw)


def vec(group, entry='helper', user=None, code=b'abc', codes=None, profiles=None, rows=(), bucket_ms=DAY_MS, time=NOW, **kw):
    return dict(group=group, entry=entry, user=user or ME, code=code, codes={b'abc': YOU} if codes is None else dict(codes),
                profiles={YOU: prof()} if profiles is None else dict(profiles), rows=list(rows), bucket_ms=bucket_ms, time=time, **kw)


def length_vectors():
    out = []
    for n in (0, 1, 2, 7, 8, 15, 16, 17, 99, 100, 101, 102, 255, 4096):
        text = bytes(0x41 + i % 26 for i in range(n))
        for entry in ('wrapper', 'helper'):
            out.append(vec('length', entry, code=text, codes={text: YOU}))
            out.append(vec('length', entry, code=text, codes={b'other': YOU}))
            out.append(vec('length', entry, code=text, codes={text: ME}))
            out.append(vec('length', entry, code=text, codes={text + b'x': YOU}))
            if n:
                out.append(vec('length', entry, code=text, codes={text[:-1]: YOU}))
    return out


def order_vectors():
    """Each pair of gates with both failing, so the order shows."""
    out = []
    long_text = b'x' * 101
    set_row = [(ME, None, YOU)]
    clear_row = [(ME, None, None)]
    for entry in ('wrapper', 'helper'):
        out.append(vec('order', entry, code=long_text, codes={long_text: ME}))
        out.append(vec('order', entry, code=long_text, codes={long_text: YOU}, rows=set_row))
        for rows in ((), clear_row, set_row):
            for owner in (ME, YOU, addr(3)):
                for profiles in ({}, {YOU: prof()}, {ME: prof()}, {YOU: prof(remaining=0)}, {YOU: prof(), ME: prof(), addr(3): prof()}):
                    for bucket in (0, DAY_MS):
                        out.append(vec('order', entry, codes={b'abc': owner}, rows=rows, profiles=profiles, bucket_ms=bucket))
                        out.append(vec('order', entry, code=b'abd', codes={b'abc': owner}, rows=rows, profiles=profiles, bucket_ms=bucket))
        # the code's owner differs in one byte from the user
        for i in (0, 7, 8, 15, 16, 19):
            near = ME[:i] + bytes([ME[i] ^ 0x80]) + ME[i + 1:]
            out.append(vec('order', entry, codes={b'abc': near}, profiles={near: prof()}))
            out.append(vec('order', entry, user=near, codes={b'abc': ME}, profiles={ME: prof()}))
    return out


def table_vectors():
    out = []
    h = key_hash(ME)
    near = [bytes(ME[:i]) + bytes([ME[i] ^ 1]) + bytes(ME[i + 1:]) for i in (0, 7, 8, 15, 16, 19)]
    for key in near:
        out.append(vec('table', rows=[(key, h, None)]))
        out.append(vec('table', rows=[(key, h, YOU)]))
        out.append(vec('table', rows=[(key, h, None), (ME, h, None)]))
        out.append(vec('table', rows=[(key, h, YOU), (ME, h, YOU)]))
    other = [(addr(200 + i), (h & ~0x1f) | ((h + i) & 0x1f), None) for i in range(1, 6)]
    tops = [(addr(300 + i), (h & ((1 << 57) - 1)) | (((h >> 57) + i + 1) & 0x7f) << 57, None) for i in range(1, 6)]
    for rows in (other, tops):
        out += [vec('table', rows=rows), vec('table', rows=rows + [(ME, h, None)]), vec('table', rows=rows + [(ME, h, YOU)])]
    for n in (15, 16, 17, 20, 24, 28, 31):
        same = [(addr(400 + i), h, None) for i in range(n)]
        out.append(vec('table', rows=same))
        out.append(vec('table', rows=same + [(ME, h, None)]))
        out.append(vec('table', rows=same + [(ME, h, YOU)]))
    for n in (16, 24):
        apart = [(addr(500 + i), (h & ~((0x7f << 57) | 0x1f)) | (h & 0x1f) | ((h >> 57) + 1 & 0x7f) << 57, None) for i in range(n)]
        out.append(vec('table', rows=apart))
        out.append(vec('table', rows=apart + [(ME, h, YOU)]))
    wall = [(addr(800 + i), h, None) for i in range(32)]
    out.append(vec('table', rows=wall, size=128))
    out.append(vec('table', rows=wall + [(ME, h, None)], size=128))
    out.append(vec('table', rows=wall + [(ME, h, YOU)], size=128))
    # tombstones: the walk passes them, an insert takes the first one and keeps growth_left
    for deleted in ((0,), (1,), (0, 1, 2), (5,), (15,), tuple(range(16))):
        out.append(vec('table', deleted=deleted))
        out.append(vec('table', deleted=deleted, growth=1))
        out.append(vec('table', deleted=deleted, profiles={}))
    # growth_left 0: reserve, then the slot comes from the new table words
    out.append(vec('table', fill=1))
    out.append(vec('table', fill=1, growth=0))
    out.append(vec('table', fill=1, profiles={}))
    for size in (4, 8, 16, 32):
        out.append(vec('table', size=size, growth=0))
        out.append(vec('table', size=size, growth=0, profiles={}))
        out.append(vec('table', size=size, growth=0, deleted=(0,)))
        out.append(vec('table', size=size, growth=0, rows=[(addr(30), None, None), (addr(31), None, YOU)]))
        out.append(vec('table', size=size, growth=0, rows=[(ME, None, None)]))
        out.append(vec('table', size=size, growth=0, rows=[(ME, None, YOU)]))
    # small tables: the group ends in the mirror, so the free position wraps onto a full slot
    for size, start in ((8, 6), (8, 7), (8, 5), (4, 2), (4, 3), (4, 1), (2, 1)):
        base = (0x2a << 57) | start
        fill = size - 2 if size > 2 else 1
        rows = [(addr(40 + i), base + (i + 1 << 58), None) for i in range(fill)]
        out.append(vec('table', size=size, user_hash=base, rows=rows, growth=1))
        out.append(vec('table', size=size, user_hash=base, rows=rows, growth=1, profiles={}))
        out.append(vec('table', size=size, user_hash=base, rows=rows + [(ME, base, None)], growth=1))
        out.append(vec('table', size=size, user_hash=base, rows=rows, growth=0))
    return out


def tree_vectors():
    """Code and profile trees of many shapes, the wanted key at both ends and the middle, and just beside it."""
    out = []
    for n in (1, 2, 5, 11, 12, 13, 23, 40, 150):
        for fan in (11, 3, 1):
            texts = [b'code%03d' % i for i in range(n)]
            owners = [addr(100 + i) for i in range(n)]
            codes = dict(zip(texts, owners))
            profiles = {o: prof() for o in owners}
            for i in (0, n // 2, n - 1):
                out.append(vec('tree', code=texts[i], codes=codes, profiles=profiles, fan=fan))
                out.append(vec('tree', code=texts[i] + b'x', codes=codes, profiles=profiles, fan=fan))
                out.append(vec('tree', code=texts[i][:-1], codes=codes, profiles=profiles, fan=fan))
                short = dict(profiles)
                del short[owners[i]]
                out.append(vec('tree', code=texts[i], codes=codes, profiles=short, fan=fan))
                out.append(vec('tree', 'wrapper', code=texts[i], codes=codes, profiles=profiles, fan=fan, scale=17))
                out.append(vec('tree', user=owners[i], code=texts[i], codes=codes, profiles=profiles, fan=fan))
            out.append(vec('tree', code=b'', codes=codes, profiles=profiles, fan=fan))
            out.append(vec('tree', code=b'zzz', codes=codes, profiles=profiles, fan=fan))
    return out


def bucket_vectors():
    out = []
    widths = (0, 1, 2, 999, 1000, 3600000, DAY_MS, 7 * DAY_MS, (1 << 32) - 1, 1 << 32, (1 << 32) + 1, 1 << 40, 1 << 63, U64, NOW_MS, NOW_MS + 1)
    for width in widths:
        now = NOW_MS // width if width else 0
        for stored in (now, now + 1, now - 1 if now else 1, 0, U64, now ^ (1 << 40)):
            for left in (0, 1, 2, 7):
                for configured in (0, 999, 1000, 1001, 5000):
                    out.append(vec('bucket', bucket_ms=width, profiles={YOU: prof(left, stored, configured)}))
    for configured in (0, 1, 999, 1000, 1001, 1 << 32, 0xccccccccccccccb, U64):
        for left in (0, 1, U64):
            out.append(vec('bucket', 'wrapper', profiles={YOU: prof(left, 1, configured)}))
            out.append(vec('bucket', 'wrapper', profiles={YOU: prof(left, NOW_MS // DAY_MS, configured)}))
    # both division paths: time and width below 2^32, then one word above it
    for ms_secs in (0, 1, 86399):
        early = (packed(1970, 1), ms_secs, 123000000)
        for width in (1, 1000, 86400000, (1 << 32) - 1, 1 << 32):
            ms = millis(early)
            out.append(vec('bucket', time=early, bucket_ms=width, profiles={YOU: prof(3, ms // width, 0)}))
            out.append(vec('bucket', time=early, bucket_ms=width, profiles={YOU: prof(3, ms // width + 1, 0)}))
    # 2^32 ms is day 49, 61367.296 s: a time word on each side of the 32-bit division test, and one near 2^33
    for secs, frac in ((61367, 295000000), (61367, 296000000), (61367, 297000000)):
        t = (packed(1970, 50), secs, frac)
        for width in (1, 1000, 7):
            out.append(vec('bucket', time=t, bucket_ms=width, profiles={YOU: prof(3, millis(t) // width, 0)}))
            out.append(vec('bucket', time=t, bucket_ms=width, profiles={YOU: prof(3, millis(t) // width + 1, 0)}))
    t = (packed(1970, 100), 0, 0)
    out.append(vec('bucket', time=t, bucket_ms=3, profiles={YOU: prof(3, millis(t) // 3, 0)}))
    out.append(vec('bucket', time=(packed(1970, 1), 1, 0), bucket_ms=(1 << 32) + 3, profiles={YOU: prof(3, 1, 0)}))
    return out


def clock_vectors():
    """Dates with a stored bucket of `ms` under a width of 1, so any error in the clock changes the path."""
    out = []
    years = (-262143, -262000, -146097, -2001, -1600, -801, -800, -401, -400, -399, -1, 0, 1, 2, 3, 4, 100, 101, 400, 401, 1600, 1601, 1900, 1901, 1969, 1970, 1971, 2000, 2001, 2024, 2026, 2100, 2101, 2201, 2401, 100000, 262142)
    for year in years:
        for ordinal in (1, 2, 59, 60, 61, 365, 366):
            for secs, frac in ((0, 0), (1, 999999), (43200, 1000000), (86399, 999999999), (86399, 1999999999)):
                t = (packed(year, ordinal, (year + ordinal) & 15), secs, frac)
                ms = millis(t)
                out.append(vec('clock', time=t, bucket_ms=1, profiles={YOU: prof(0 if ms else 1, ms, 0)}))
                out.append(vec('clock', 'wrapper', time=t, bucket_ms=DAY_MS, profiles={YOU: prof(0 if ms else 1, ms // DAY_MS, 0)}))
    return out


def log_vectors():
    out = []
    for n in (0, 1, 2, 5, 11, 12, 13, 23, 40, 150):
        users = [addr(1000 + i) for i in range(n)]
        for fan in (11, 3, 1):
            log = {u: (packed(2020, 1 + i % 300), i, i) for i, u in enumerate(users)}
            out.append(vec('log', profiles={YOU: prof(log=log, fan=fan)}))
            out.append(vec('log', 'wrapper', profiles={YOU: prof(log=log, fan=fan)}, scale=17))
            order = sorted(users)
            for i in (0, n // 2, n - 1):
                if n:
                    out.append(vec('log', user=order[i], profiles={YOU: prof(log=log, fan=fan)}))
                    out.append(vec('log', user=order[i], profiles={YOU: prof(remaining=0, bucket=NOW_MS // DAY_MS, log=log, fan=fan)}))
                    out.append(vec('log', user=order[i][:19] + bytes([order[i][19] ^ 1]), profiles={YOU: prof(log=log, fan=fan)}))
    out.append(vec('log', alloc=0, panic='allocation'))
    out.append(vec('log', 'wrapper', alloc=0, panic='allocation'))
    return out


def sequence_vectors():
    """A chain of calls, each on the state the model left behind."""
    out = []
    r = Lcg(94)
    users = [addr(700 + i) for i in range(6)]
    texts = [b'a', b'b', b'missing']
    for chain in range(40):
        codes = {b'a': users[0], b'b': users[1]}
        profiles = {users[0]: prof(remaining=2, configured=(0, 1001)[chain % 2])}
        rows = []
        day = 304
        for step in range(14):
            day += r.next(3) == 0
            t = (packed(2026, min(day, 365)), 60 * step, 0)
            v = vec('sequence', ('helper', 'wrapper')[r.next(2)], user=users[r.next(6)], code=texts[r.next(3)], codes=codes, profiles=profiles, rows=rows, time=t, size=64)
            out.append(v)
            want = model(v)
            rows = list(rows)
            if want['insert']:
                rows.append((v['user'], None, None))
            if want['bind'] is not None:
                rows = [(k, h, want['bind'] if k == v['user'] else o) for k, h, o in rows]
            if want['profile'] is not None:
                o, left, bucket, _ = want['profile']
                profiles = dict(profiles)
                p = dict(profiles[o])
                p.update(remaining=left, bucket=bucket, log=dict(p['log']))
                p['log'][v['user']] = t
                profiles[o] = p
    return out


def all_vectors():
    return length_vectors() + order_vectors() + table_vectors() + tree_vectors() + bucket_vectors() + clock_vectors() + log_vectors() + sequence_vectors()


# ---- static facts


def bind_fdes(data):
    fdes = Fdes(data)
    for s in SUBJECTS:
        FDE_END[s] = fdes.range_of(s)['end']
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
    slots, got = scan_slots(img, code)
    return img, code, fdes, slots, got


# ---- mutation survey


EQUIVALENT = {
    0x3743549: 'the shuffle picks dword 1 in place of dword 0 of a register whose low two dwords are equal',
    0x394b809: 'years at or below 0 only: the count of 400-year cycles is 1 lower at most, and the shifted year stays at or above 0, so days are the same (signed time hook, clock group; test_cycle_count_mutants_keep_days walks every year)',
    0x394b810: 'years at or below 0 only: the count of 400-year cycles is 1 lower at most on an exact multiple of 400, then year + 400 k is still at or above 0, so days are the same (signed time hook, clock group; test_cycle_count_mutants_keep_days walks every year)',
    0x394b817: 'years at or below 0 only: the mutated shift about doubles the count of 400-year cycles, year and day offset move together, so days are the same (signed time hook, clock group; test_cycle_count_mutants_keep_days walks every year)',
    0x394b853: 'adds the sign bit of the year, and the year is at or above 0 here on both branches; 0x3e and 0x3f give 0 alike',
    0x394b8de: 'cmp with 0x3e8 in place of 0x3e9 then cmovae: a word of 1000 selects 1000 either way',
    0x33a255d: 'copies the four bytes past the 20-byte key into padding of the entry; the entry stub reads 20 bytes, and 0x2f23c60 is not run',
    0x33a25fd: 'the node was allocated just above with length 0, so 0 is below 0xa as well as 0xb',
}
UNEXECUTED = (
    (0x33a266e, 0x33a2687, 'panic of a full node: the node was allocated just above with length 0, so the cmp 0xb never passes'),
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


def drop_case(img, tag):
    """Jump table entry of the status drop for one tag."""
    return DROP_TABLE + struct.unpack('<i', img.read(DROP_TABLE + 4 * (tag - DROP_FIRST), 4))[0]


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
    ('differs', 'ReferrerCodeEntry owner_tag', 'owner address plus one trailing u32', 'the code tree value is 20 bytes: stride 0x14 at 0x3743479, and the last dword at 0x37434cb is bytes 16 to 19 of the address compared with the user at 0x37434f1'),
    ('differs', 'UserReferrerBinding referrer_tag', 'a u32 after the 20-byte referrer', 'the row takes 20 bytes at +0xcd: 16 at 0x3743845, 4 at 0x374384e'),
    ('differs', 'row creation in set_referrer', 'row made only on the missing profile branch; an Err from the bucket step leaves none', 'the row is made before the flag test at 0x3743632..0x3743722, so a first call refused with 0xa1 keeps a new empty row'),
    ('differs', 'binding_by_user', 'a map of bindings only', 'tracker +0xc0, stride 0xe8; a new row also writes zero at +0x18, +0x98, +0xa8, +0xb0, +0xc0, +0xc8, and +0xa0 takes eight unset stack bytes'),
    ('differs', 'ReferredUserLog and referred_users', 'a Vec of (user, at_ms), push on each success', 'a B-tree keyed by user with the raw 12-byte time words as value; a user already there has the value replaced, the length stays, and the remaining count still drops'),
    ('differs', 'now_ms u64', 'an unsigned time', 'the signed time from the date words is clamped at 0 (0x394b8a0), so a time before 1970 is bucket 0'),
    ('same', 'MAX_REFERRER_CODE_LEN', '100', 'cmp r8,0x65 with jb at 0x27de28b; the helper has no length test'),
    ('same', 'MIN_NEW_USERS_PER_BUCKET', '1000', 'cmp rax,0x3e9 and floor 1000 at 0x394b8de, 0x394b8e4'),
    ('same', 'status numbers', '390, 323, 158, 159, 161, 162', 'tags 0x186, 0x143, 0x9e, 0x9f, 0xa1, 0xa2'),
    ('same', 'order', 'code, self, already set, profile, width, count', 'the same, with the row made between self and already set'),
    ('same', 'missing profile', 'status 390, binding not written', 'the same at 0x3743851; the row stays with flag 0'),
    ('same', 'bucket', 'now / width, refresh on change, refuse at 0, then decrement', 'the same; 32-bit and 64-bit divide give one result'),
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
                raise EvidenceError(f"mismatch in {v['group']} code {v['code'][:20]!r}: {msg}")
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
    copies = [int(s_['function'], 16) for s_ in sites if int(s_['function'], 16) != WRAPPER]
    out_path = Path(out_dir)
    out_path.mkdir(parents=True, exist_ok=True)
    groups, outcomes = {}, {}
    with open(out_path / 'vectors.tsv', 'w', newline='\n') as f:
        f.write('group\tentry\tcode_length\tstate\tstatus\trow_inserted\tbound\tremaining\n')
        for v in vecs:
            groups[v['group']] = groups.get(v['group'], 0) + 1
            if 'panic' in v:
                name, ins_, bound, left = 'panic ' + v['panic'], '', '', ''
            else:
                want = model(v)
                name, ins_, bound = hex(want['status']), int(want['insert']), int(want['bind'] is not None)
                left = want['profile'][1] if want['profile'] else ''
            outcomes[name] = outcomes.get(name, 0) + 1
            f.write(f"{v['group']}\t{v['entry']}\t{len(v['code'])}\t{digest_of(v)}\t{name}\t{ins_}\t{bound}\t{left}\n")
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
        per[hex(fn)] = dict(end=hex(FDE_END[fn]), fde=hex(fdes.range_of(fn)['fde']), instructions=len(listing[fn]), executed=sum(i.va in seen for i in listing[fn]))
    evidence = dict(
        binary=BINARY, sha256=SHA256, functions=per, subjects=[hex(s_) for s_ in SUBJECTS],
        stubs=dict(hash=hex(HASH), drop=hex(DROP), log_vacant=hex(LOG_VACANT), reserve=hex(img.relative(RESERVE_SLOT))),
        helper_slot=hex(HELPER_SLOT), helper_callers=sites, wrapper_copies=copy_rows(img, fdes, WRAPPER, copies),
        wrapper_callers={hex(c): direct_sites(img, c, starts) for c in (WRAPPER,) + tuple(copies)},
        bucket_callers=direct_sites(img, BUCKET, starts), log_insert_callers=direct_sites(img, LOG_INSERT, starts),
        drop_case=dict(tag=hex(NO_ROOM), target=hex(drop_case(img, NO_ROOM)), plain_return=hex(DROP_PLAIN)),
        status_text={hex(t): status_text(img, t) for t in STATUSES if t != OK},
        pinned=pinned(img), vectors=len(vecs), mismatches=0, groups=groups, outcomes=outcomes, padding_not_executed=padding,
        unexecuted=[dict(start=hex(a), end=hex(b), why=w) for a, b, w in UNEXECUTED], mutants=len(rows), killed=sum(1 for r in rows if r['killed']),
        survey_vectors=len(sample(vecs)), equivalent={hex(k): w for k, w in sorted(EQUIVALENT.items())},
        layouts=dict(profile=dict(leaf=hex(PROFILE_NODE.leaf_size), value=hex(PROFILE_SIZE), key=20), code=dict(leaf=hex(CODE_NODE.leaf_size), key=hex(0x18), value=20), log=dict(leaf=hex(LOG_LEAF), key=20, value=12, value_at=hex(LOG_VALUE))),
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
