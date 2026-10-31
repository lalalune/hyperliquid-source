#!/usr/bin/env python3
"""fees: node #94 transfer gas amount, from bytes alone.

Static, no execution of the node.  The three copies 0x27101a0, 0x4d00b00, 0x4d00ea0 of the gas amount function,
the address range test 0x37e51d0 and the three row lookups 0x2755400, 0x46f2e60, 0x46f2fe0 are decoded from ELF
bytes by the table decoder below, which must land exactly on each FDE end, and interpreted in Python on every
vector.  The two hashes, the byte compare, the once call and the panic are stubs that check their arguments.
Each outcome is compared with a separate closed-form model, then every conditional, field offset and immediate
of the four subjects is mutated to test the vectors.

    python3 tools/fees_transfer_gas.py --out <dir>

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

GAS = 0x27101a0
COPY_A = 0x4d00b00
COPY_B = 0x4d00ea0
SPECIAL = 0x37e51d0
ROW = 0x2755400
ROW_A = 0x46f2e60
ROW_B = 0x46f2fe0
HASH_ROW = 0x2840fb0
HASH_ROW_B = 0x473bf50
HASH_ADDR = 0x399c7a0
BUILDER = 0x34d71a0
SUBJECTS = (GAS, COPY_A, COPY_B, SPECIAL)
HELPERS = (ROW, ROW_A, ROW_B)
GOT_MEMCMP = 0x576e488
GOT_PANIC = 0x576e470
GOT_ONCE = 0x576e8b8
SLOT_DEFAULT = 0x57749b8
SLOT_SPECIAL = 0x57749e0
TOKEN_BOUND = 0x56f21f0
DEFAULT_CELL = 0x5786190
ONCE_WORD = 0x40
ALL_22_BLOCK = 0x59c10c
GAS_FORMAT = 0x1f57b9
CONSUMER = 0x27137b2
GAS_UNITS = 1000000
DEX_STRIDE = 0x2f0
EXCHANGE_SIZE = 0x1400
STACK_FILL = bytes((i * 5 + 3) & 0xff | 1 for i in range(0x8000))
TOP = 0x7f08
SHAPES = {
    GAS: dict(row=ROW, hash_row=HASH_ROW, dexes=0x5c0, rows=0x740),
    COPY_A: dict(row=ROW_A, hash_row=HASH_ROW_B, dexes=0x1040, rows=0x11c0),
    COPY_B: dict(row=ROW_B, hash_row=HASH_ROW_B, dexes=0x5c0, rows=0x740),
}
ENTRIES = (GAS, COPY_A, COPY_B)
SPOT_TABLE = 0x318
TOKENS = 0x210
DEX_TABLE = 0xf8
ROW_STRIDE = 0x58
ROW_VALUE = 0x18
DEX_STRIDE_ROW = 0x78
SPOT_ROW = 0x58
FLAG = 0x3d
TOKEN_STRIDE = 0xe8
TOKEN_TAG = 0xbc
TOKEN_ADDR = 0xbd
# (first byte, big-endian tail in the last 8 bytes) of the literal blocks compared through memcmp
LITERALS = ((0x20, 0), (0x20, 9999), (0x30, 0), (0x30, 20000), (0x31, 0), (0x31, 10000), (0x32, 0), (0x32, 9999))
PINNED = (
    (0x27101e8, 'b8 40 42 0f 00', 'gas 1000000 is the only non-zero result'),
    (0x27101ed, '48 0f 45 c2', 'the sender test makes it 0'),
    (0x27104cc, '80 b8 bc 00 00 00 01', 'token 0 row: byte +0xbc must be 1'),
    (0x271050d, 'b2 01', 'second result 1 with gas 0'),
    (0x2710493, '48 b8 00 00 00 00 00 00 27 0f', 'tail 0x270f of the 0x20 block, read big-endian'),
    (0x37e5221, '48 b8 00 00 00 00 00 00 4e 20', 'tail 0x4e20 of the 0x30 block'),
    (0x37e529b, '48 b8 00 00 00 00 00 00 27 10', 'tail 0x2710 of the 0x31 block'),
    (0x37e5311, '48 b8 00 00 00 00 00 00 27 0f', 'tail 0x270f of the 0x32 block'),
    (0x37e5335, '0f 9e c0', 'setle: the 0x32 top is included'),
    (0x34d71cc, '66 c7 43 3c 00 00', 'default row: bytes +0x3c and +0x3d are 0'),
    (0x27133c6, 'e8 d5 cd ff ff', 'one of two calls from 0x2712ce0'),
    (0x27133cb, '48 89 44 24 30', 'gas is stored at rsp+0x30'),
    (0x27137a8, '48 8b 4c 24 30', 'and passed in rcx to the next call'),
)
SEEN = None


class Panicked(Exception):
    """The node would panic here; a modelled outcome, unlike Unmodelled."""


def key_hash(key):
    return int.from_bytes(hashlib.sha256(key).digest()[:8], 'little')


def word(a, off, size, val):
    a.mem[off:off + size] = val.to_bytes(size, 'little')


def read(blob, off, size=8):
    return int.from_bytes(blob[off:off + size], 'little')


FILLS = {}


def fill_bytes(n, seed):
    """A position-dependent pattern, so a shifted read or a stray write shows."""
    if (n, seed) not in FILLS:
        FILLS[n, seed] = bytes((i * 11 + seed + (i >> 8)) & 0xff for i in range(n))
    return FILLS[n, seed]


def synth(first, tail):
    """An address with `first` in byte 0 and the 8-byte big-endian `tail` in bytes 12..20."""
    return bytes([first]) + bytes(11) + tail.to_bytes(8, 'big')


def addr(n):
    """A 20-byte test address outside every range below (first byte 0xa0 or more)."""
    raw = hashlib.sha256(b'addr' + str(n).encode()).digest()[:20]
    return bytes([raw[0] | 0xa0]) + raw[1:]


# ---- model, written from the observed rules and independent of the machine


def special_model(a):
    return (synth(0x30, 0) <= a < synth(0x30, 20000) or synth(0x31, 0) <= a < synth(0x31, 10000)
            or synth(0x32, 0) <= a <= synth(0x32, 9999))


def sender_flag(v):
    row = v['rows'].get(v['sender'])
    return row is not None and v.get('row_items', None) != 0 and row != 0


def gas_model(v):
    """(gas, second result), or 'panic' when the token list is empty."""
    sender, dest = v['sender'], v['dest']
    if special_model(dest):
        return 0, 0
    if not sender_flag(v):
        if any(dest in dex['keys'] and dex.get('items', 1) != 0 for dex in v['dexes']):
            return 0, 0
        if dest in v['spot']['keys'] and v['spot'].get('items', 1) != 0:
            return 0, 0
        if dest == bytes([0x22]) * 20 or synth(0x20, 0) <= dest <= synth(0x20, 9999):
            return 0, 0
        if v['tokens'] == 0:
            return 'panic'
        if v['tag'] == 1 and v['first'] == sender:
            return 0, 1
    return (0, 0) if special_model(sender) else (GAS_UNITS, 0)


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


def write_table(m, owner, field, stride, keys, spec, seed):
    """A hash table of 20-byte keys.  `field` holds control, mask, room, items, then the hash state."""
    size = spec.get('size', 16)
    mask = size - 1
    a = m.arena(stride * size + size + 32)
    a.mem[:] = fill_bytes(len(a.mem), seed)
    a.valid[:] = b'\1' * len(a.mem)
    ctrl_off = stride * size + 16
    ctrl = [0xff] * (size + 16)
    places = {}
    for k, h2 in spec.get('decoys', ()):
        # a full bucket that holds another key under a chosen top hash
        i = k & mask
        if ctrl[i] == 0xff:
            set_ctrl(ctrl, mask, i, h2)
            at = ctrl_off - (i + 1) * stride
            a.mem[at:at + 20] = bytes((j * 7 + k) & 0xff for j in range(20))
    for key in keys:
        h = m.hashes.get(key, key_hash(key))
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
    word(owner, field + 0x10, 8, 0)
    word(owner, field + 0x18, 8, spec.get('items', len(keys) or 1) if spec.get('items', None) is not None else len(keys))
    return a, places


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
    cell = Arena(DEFAULT_CELL, 0x48)
    m.arenas.append(cell)
    m.cell = cell
    m.compares = []
    m.once = 0

    def key_at(at):
        return bytes(m.load(at + k, 1) for k in range(20))

    def memcmp():
        r = m.regs
        if r[R['rdx']] != 20:
            raise Unmodelled('compare length')
        left, right = key_at(r[R['rdi']]), key_at(r[R['rsi']])
        if (right[0], int.from_bytes(right[12:], 'big')) not in LITERALS or any(right[1:12]):
            raise Unmodelled('compare block')
        if left not in (m.dest, m.sender):
            raise Unmodelled('compare subject')
        m.compares.append((right[0], int.from_bytes(right[12:], 'big')))
        m.clobber(0 if left == right else 1 if left > right else 0xffffffff)

    def hash_row():
        r = m.regs
        if r[R['rdi']] != m.ex.base + m.shape['rows'] + 0x20:
            raise Unmodelled('row hash state')
        key = key_at(r[R['rsi']])
        if key != m.sender:
            raise Unmodelled('row hash key')
        m.clobber(m.hashes.get(key, key_hash(key)))

    def hash_addr():
        r = m.regs
        if r[R['rdi']] not in m.states:
            raise Unmodelled('address hash state')
        key = key_at(r[R['rsi']])
        if key != m.dest:
            raise Unmodelled('address hash key')
        m.clobber(m.hashes.get(key, key_hash(key)))

    def once():
        r = m.regs
        if (r[R['rdi']], r[R['rsi']]) != (DEFAULT_CELL + ONCE_WORD, 1):
            raise Unmodelled('once arguments')
        m.once += 1
        word(cell, ONCE_WORD, 4, 0)
        m.clobber()

    def panic():
        if m.regs[R['rdi']] != TOKEN_BOUND:
            raise Unmodelled('panic record')
        raise Panicked('bound')

    m.stubs.update({HASH_ROW: hash_row, HASH_ROW_B: hash_row, HASH_ADDR: hash_addr})
    for s, fn in ((GOT_MEMCMP, memcmp), (GOT_PANIC, panic), (GOT_ONCE, once)):
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
    """One call on a fresh state.  Returns (rax, rdx, machine, frozen arenas)."""
    m = machine(img, code, slots, got)
    m.vec = v
    m.sender, m.dest = v['sender'], v['dest']
    m.hashes = dict(v.get('hashes', {}))
    entry = v['entry']
    m.shape = shape = SHAPES[entry]
    ex = m.arena(EXCHANGE_SIZE)
    ex.mem[:] = fill_bytes(EXCHANGE_SIZE, 0x41)
    ex.valid[:] = b'\1' * EXCHANGE_SIZE
    m.ex = ex
    m.states = set()
    frozen = [ex]
    rows, places = write_table(m, ex, shape['rows'], ROW_STRIDE, sorted(v['rows']), dict(v.get('row_table', {}), items=v.get('row_items')), 0x17)
    for key, flag in v['rows'].items():
        rows.mem[places[key] + ROW_VALUE + FLAG] = flag
    frozen.append(rows)
    d = m.arena(max(DEX_STRIDE * len(v['dexes']), 8))
    d.mem[:] = fill_bytes(len(d.mem), 0x29)
    d.valid[:] = b'\1' * len(d.mem)
    frozen.append(d)
    word(ex, shape['dexes'], 8, d.base)
    word(ex, shape['dexes'] + 8, 8, len(v['dexes']))
    for i, dex in enumerate(v['dexes']):
        at = DEX_STRIDE * i
        tab, _ = write_table(m, d, at + DEX_TABLE, DEX_STRIDE_ROW, dex['keys'], dex, 0x31 + i)
        frozen.append(tab)
        m.states.add(d.base + at + DEX_TABLE + 0x20)
    spot, _ = write_table(m, ex, SPOT_TABLE, SPOT_ROW, v['spot']['keys'], v['spot'], 0x53)
    frozen.append(spot)
    m.states.add(ex.base + SPOT_TABLE + 0x20)
    t = m.arena(max(TOKEN_STRIDE * max(v['tokens'], 1), 8))
    t.mem[:] = fill_bytes(len(t.mem), 0x5b)
    t.valid[:] = b'\1' * len(t.mem)
    t.mem[TOKEN_TAG] = v['tag']
    t.mem[TOKEN_ADDR:TOKEN_ADDR + 20] = v['first']
    frozen.append(t)
    word(ex, TOKENS, 8, t.base)
    word(ex, TOKENS + 8, 8, v['tokens'])
    m.cell.mem[:] = fill_bytes(0x48, 0x63)
    m.cell.valid[:] = b'\1' * 0x48
    m.cell.mem[0x3c:0x3e] = bytes((0x77, v.get('default_flag', 0)))
    word(m.cell, ONCE_WORD, 4, v.get('once', 0))
    if m.cell.mem[0x3d] != v.get('default_flag', 0):
        raise Unmodelled('cell')
    sender_at = m.arena(20)
    sender_at.mem[:] = m.sender
    sender_at.valid[:] = b'\1' * 20
    dest_at = m.arena(20)
    dest_at.mem[:] = m.dest
    dest_at.valid[:] = b'\1' * 20
    frozen += [sender_at, dest_at]
    snap = [bytes(a.mem) for a in frozen]
    enter(m, entry, ex.base, sender_at.base, dest_at.base)
    m.frozen = frozen, snap
    return m.regs[0], m.regs[2], m


def check(img, code, slots, got, v):
    """None when the machine and the model agree, else a short reason."""
    want = gas_model(v)
    try:
        rax, rdx, m = run(img, code, slots, got, v)
    except Panicked:
        return None if want == 'panic' else 'panicked'
    if want == 'panic':
        return 'no panic'
    if (rax, rdx & 0xff) != want:
        return f'result {rax:#x},{rdx:#x} not {want[0]:#x},{want[1]:#x}'
    frozen, snap = m.frozen
    for a, b in zip(frozen, snap):
        if bytes(a.mem) != b:
            return 'state written'
    if m.once != (1 if v.get('once', 0) and not special_model(v['dest']) else 0):
        return 'once count'
    return None


# ---- vectors


class Lcg:
    def __init__(self, seed):
        self.x = seed

    def next(self, n):
        self.x = (self.x * 0x5851f42d4c957f2d + 0x14057b7ef767814f) & U64
        return (self.x >> 33) % n


ME = addr(1)
YOU = addr(2)
OTHER = addr(3)
EMPTY = dict(keys=())


def vec(group, **kw):
    v = dict(group=group, sender=ME, dest=YOU, rows={ME: 0}, dexes=[dict(keys=(OTHER,))], spot=dict(keys=(OTHER,)), tokens=2, tag=0, first=OTHER)
    v.update(kw)
    return v


def spread(items):
    """Each vector once on every copy."""
    out = []
    for v in items:
        for e in ENTRIES:
            out.append(dict(v, entry=e))
    return out


def near(a):
    """a - 1, a, a + 1 as 160-bit numbers."""
    n = int.from_bytes(a, 'big')
    return [(n + k).to_bytes(20, 'big') for k in (-1, 0, 1)]


def edges(first, tail):
    out = near(synth(first, tail))
    for i in (1, 11, 12, 18, 19):
        raw = bytearray(synth(first, tail))
        raw[i] ^= 1
        out.append(bytes(raw))
    return out


def range_vectors():
    out = []
    for first, tail in LITERALS:
        if first == 0x20:
            continue
        for a in edges(first, tail):
            out.append(vec('special-dest', dest=a))
            out.append(vec('special-sender', sender=a, rows={a: 0}))
            out.append(vec('special-sender-flag', sender=a, rows={a: 1}))
    for first in (0x2f, 0x33, 0x40, 0x10):
        out.append(vec('special-dest', dest=synth(first, 5)))
        out.append(vec('special-sender', sender=synth(first, 5), rows={synth(first, 5): 0}))
    return out


def reserved_vectors():
    out = []
    for first, tail in LITERALS:
        if first != 0x20:
            continue
        for a in edges(first, tail):
            out.append(vec('block-20', dest=a))
            out.append(vec('block-20-flag', dest=a, rows={ME: 1}))
            out.append(vec('block-20-sender', sender=a, rows={a: 0}))
    all22 = bytes([0x22]) * 20
    out.append(vec('all-22', dest=all22))
    out.append(vec('all-22-flag', dest=all22, rows={ME: 1}))
    for i in range(20):
        raw = bytearray(all22)
        raw[i] ^= 1
        out.append(vec('all-22', dest=bytes(raw)))
        raw[i] ^= 0x81
        out.append(vec('all-22', dest=bytes(raw)))
    return out


def flag_vectors():
    out = []
    for flag in (0, 1, 2, 0x80, 0xff):
        out.append(vec('flag', rows={ME: flag}))
        out.append(vec('flag', rows={ME: flag}, spot=dict(keys=(YOU,))))
        out.append(vec('flag', rows={ME: flag}, dexes=[dict(keys=(YOU,))]))
        out.append(vec('flag', rows={ME: flag, YOU: 0}, tag=1, first=ME))
        out.append(vec('flag', rows={ME: flag, YOU: 1, OTHER: 1}))
    out.append(vec('flag-other', rows={OTHER: 1, YOU: 1}))
    out.append(vec('flag-items', rows={ME: 1}, row_items=0))
    out.append(vec('flag-items', rows={ME: 1}, row_items=0, once=1))
    out.append(vec('flag-items', rows={}, row_items=0))
    out.append(vec('flag-absent', rows={OTHER: 1}))
    out.append(vec('flag-absent', rows={OTHER: 1}, once=1))
    out.append(vec('flag-absent', rows={OTHER: 1}, once=3))
    out.append(vec('flag-present', rows={ME: 1}, once=1))
    out.append(vec('flag-present', rows={ME: 0}, once=1))
    for h2 in range(0, 0x7f, 17):
        h = h2 << 57 | 5
        out.append(vec('flag-probe', rows={ME: 1}, hashes={ME: h}, row_table=dict(decoys=((5, h2), (6, h2)))))
        out.append(vec('flag-probe', rows={ME: 1}, hashes={ME: h}, row_table=dict(deleted=(5, 6, 7))))
        out.append(vec('flag-probe', rows={OTHER: 1}, hashes={ME: h, OTHER: h}, row_table=dict(decoys=((6, h2),))))
    out.append(vec('flag-probe', rows={addr(i): 1 for i in range(100, 124)} | {ME: 1}, row_table=dict(size=32)))
    out.append(vec('flag-probe', rows={addr(i): 0 for i in range(100, 127)} | {ME: 1}, row_table=dict(size=32), hashes={ME: 3 | 7 << 57, **{addr(i): 3 | 7 << 57 for i in range(100, 127)}}))
    wall = tuple((k, 9) for k in range(5, 21))
    for present in (ME, OTHER):
        out.append(vec('flag-probe', rows={present: 1}, hashes={ME: 5 | 3 << 57, OTHER: 5 | 3 << 57}, row_table=dict(size=32, decoys=wall)))
        out.append(vec('flag-probe', rows={present: 1}, hashes={ME: 5 | 9 << 57, OTHER: 5 | 9 << 57}, row_table=dict(size=32, decoys=wall)))
    return out


def table_vectors():
    out = []
    many = [addr(i) for i in range(200, 222)]
    for n in (1, 2, 3, 5):
        for at in range(n):
            dexes = [dict(keys=(OTHER,)) for _ in range(n)]
            dexes[at] = dict(keys=(YOU,))
            out.append(vec('dex', dexes=dexes))
            out.append(vec('dex', dexes=dexes, tag=1, first=ME))
            hollow = [dict(d) for d in dexes]
            hollow[at] = dict(keys=(YOU,), items=0)
            out.append(vec('dex-items', dexes=hollow))
            empty = [dict(keys=()) for _ in range(n)]
            out.append(vec('dex-empty', dexes=empty))
    out.append(vec('dex', dexes=[]))
    out.append(vec('dex', dexes=[], tag=1, first=ME))
    out.append(vec('spot', spot=dict(keys=(YOU,))))
    out.append(vec('spot', spot=dict(keys=(YOU,)), tag=1, first=ME))
    out.append(vec('spot', spot=dict(keys=(YOU,), items=0)))
    out.append(vec('spot', spot=dict(keys=())))
    out.append(vec('spot-after-dex', spot=dict(keys=(YOU,)), dexes=[dict(keys=(OTHER,)), dict(keys=())]))
    for h2 in range(0, 0x7f, 11):
        h = h2 << 57 | 9
        for which in ('dex', 'spot'):
            for present in (0, 1):
                spec = dict(keys=(YOU,) if present else (OTHER,), decoys=((9, h2), (10, h2)))
                hashes = {YOU: h, OTHER: h}
                if which == 'dex':
                    out.append(vec('probe', dexes=[dict(spec)], hashes=hashes))
                else:
                    out.append(vec('probe', spot=spec, hashes=hashes))
            del_spec = dict(keys=(YOU,), deleted=(9, 10, 11))
            if which == 'dex':
                out.append(vec('probe', dexes=[del_spec], hashes={YOU: h}))
            else:
                out.append(vec('probe', spot=del_spec, hashes={YOU: h}))
    same = 3 | 7 << 57
    hashes = {k: same for k in many + [YOU]}
    out.append(vec('probe-long', dexes=[dict(keys=many[:20] + [YOU], size=32)], hashes=hashes))
    out.append(vec('probe-long', spot=dict(keys=many[:20] + [YOU], size=32), hashes=hashes))
    out.append(vec('probe-long', dexes=[dict(keys=many[:20], size=32)], hashes=hashes))
    out.append(vec('probe-long', spot=dict(keys=many[:20], size=32), hashes=hashes))
    for hit in (YOU, OTHER):
        one = tuple((k, 9) for k in range(5, 21))
        two = tuple((k, 9) for k in range(5, 37))
        h = {YOU: 5 | 3 << 57, OTHER: 5 | 3 << 57}
        for wall, size in ((one, 32), (two, 128)):
            out.append(vec('probe-wall', dexes=[dict(keys=(hit,), size=size, decoys=wall)], hashes=h))
            out.append(vec('probe-wall', spot=dict(keys=(hit,), size=size, decoys=wall), hashes=h))
    return out


def token_vectors():
    out = []
    for tag in (0, 1, 2, 0xff):
        out.append(vec('token', tag=tag, first=ME))
        out.append(vec('token', tag=tag, first=OTHER))
    for i in range(20):
        raw = bytearray(ME)
        raw[i] ^= 1
        out.append(vec('token-byte', tag=1, first=bytes(raw)))
        raw[i] ^= 0x81
        out.append(vec('token-byte', tag=1, first=bytes(raw)))
    out.append(vec('token', tag=1, first=YOU))
    out.append(vec('token-one', tokens=1, tag=1, first=ME))
    out.append(vec('token-one', tokens=1, tag=0, first=ME))
    special = synth(0x31, 7)
    out.append(vec('token-special', sender=special, rows={special: 0}, tag=1, first=special))
    out.append(vec('token-special', sender=special, rows={special: 0}, tag=1, first=OTHER))
    for kw in (dict(), dict(tag=1, first=ME)):
        out.append(vec('no-tokens', tokens=0, **kw))
        out.append(vec('no-tokens', tokens=0, spot=dict(keys=(YOU,)), **kw))
        out.append(vec('no-tokens', tokens=0, dexes=[dict(keys=(YOU,))], **kw))
        out.append(vec('no-tokens', tokens=0, rows={ME: 1}, **kw))
        out.append(vec('no-tokens', tokens=0, dest=synth(0x31, 1), **kw))
        out.append(vec('no-tokens', tokens=0, dest=bytes([0x22]) * 20, **kw))
        out.append(vec('no-tokens', tokens=0, dest=synth(0x20, 1), **kw))
    return out


def random_vectors():
    out = []
    g = Lcg(0x94)
    pool = [ME, YOU, OTHER, synth(0x20, 5), synth(0x30, 19999), synth(0x31, 9999), synth(0x32, 9999), synth(0x32, 10000), bytes([0x22]) * 20, addr(9)]
    for _ in range(600):
        sender = pool[g.next(len(pool))]
        dest = pool[g.next(len(pool))]
        rows = {}
        for _r in range(g.next(4)):
            rows[pool[g.next(len(pool))]] = (0, 1, 2)[g.next(3)]
        dexes = [dict(keys=tuple(sorted({pool[g.next(len(pool))] for _k in range(g.next(3))}))) for _d in range(g.next(3))]
        spot = dict(keys=tuple(sorted({pool[g.next(len(pool))] for _k in range(g.next(3))})))
        tag = (0, 1, 1, 2)[g.next(4)]
        first = pool[g.next(len(pool))]
        tokens = (0, 1, 2, 2, 2, 2)[g.next(6)]
        out.append(vec('random', sender=sender, dest=dest, rows=rows, dexes=dexes, spot=spot, tag=tag, first=first, tokens=tokens, once=(0, 0, 0, 1)[g.next(4)]))
    return out


def all_vectors():
    return spread(range_vectors() + reserved_vectors() + flag_vectors() + table_vectors() + token_vectors() + random_vectors())


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


SAME_DWORD = 'pshufd 0x44 to 0x45 picks dword 1 in place of dword 0 of a register whose low two dwords are equal after pshuflw'
SAME_BYTE = 'the low byte of this dword store is overwritten by the next movq, which covers it, so the literal is unchanged'
SAME_FIRST = 'a store of the first literal byte moved 8 down; the slot already holds that byte from the first block of the same range, and the compare stub leaves the stack'
EQUIVALENT = {
    **dict.fromkeys((0x271030d, 0x271037d, 0x4d00c7d, 0x4d00ced, 0x4d0101d, 0x4d0108d), SAME_DWORD),
    **dict.fromkeys((0x271044b, 0x271047e, 0x4d00dbb, 0x4d00dee, 0x4d0115b, 0x4d0118e, 0x37e51d8, 0x37e520b, 0x37e524f, 0x37e5285, 0x37e52c5, 0x37e52fb), SAME_BYTE),
    **dict.fromkeys((0x37e521c, 0x37e5296, 0x37e530c), SAME_FIRST),
}
UNEXECUTED = ()


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
    """The survey set: every curated vector on the first copy, plus a hash-chosen part of the rest."""
    count, kept = {}, []
    for v in vecs:
        count[v['group']] = count.get(v['group'], 0) + 1
    for i, v in enumerate(vecs):
        if hashlib.sha256(str(i).encode()).digest()[0] * count[v['group']] < 256 * 90:
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
    rows = []
    for s_ in sites:
        scope = vecs if s_['fn'] == SPECIAL else [v for v in vecs if v['entry'] == s_['fn']]
        picked = sample(scope)
        mimg = Image(data, s_['patch'])
        mcode = dict(code)
        try:
            mcode.update({i.va: i for i in decode_range(mimg, s_['fn'], FDE_END[s_['fn']])})
        except EvidenceError as exc:
            rows.append(dict(s_, killed=('decoder', str(exc)[:60])))
            continue
        killed = try_kill(mimg, mcode, slots, got, picked)
        if killed is None and s_['va'] not in EQUIVALENT:
            killed = try_kill(mimg, mcode, slots, got, list(scope))
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


def pinned(img):
    out = []
    for va, raw, meaning in PINNED:
        want = raw.replace(' ', '')
        got = img.read(va, len(want) // 2).hex()
        if got != want:
            raise EvidenceError(f'bytes at {va:#x} are {got}, not {want}')
        out.append(dict(va=hex(va), bytes=want, meaning=meaning))
    return out

def digest_of(v):
    return hashlib.sha256(repr(sorted((k, repr(x)) for k, x in v.items())).encode()).hexdigest()[:16]



REFERENCE_ROWS = (
    ('differs', 'synthetic_addr layout', 'tail in bytes 8..16', 'the big-endian tail ends at byte 19: literal bytes 12..20 (movabs at 0x37e5221 stores from block +0xc, which is byte 12)'),
    ('differs', 'range tops for 0x30 and 0x31', 'address <= ceiling', 'strictly below 0x4e20 and 0x2710 (js at 0x37e5249, 0x37e52c3); only the 0x32 top is included (setle at 0x37e5335)'),
    ('differs', 'range top for 0x32', '999999', 'tail 0x270f = 9999 at 0x37e5311'),
    ('differs', 'fee_exempt_sender', 'one exempt sender gives fee 0 inside the exemption list', 'a separate outcome: gas 0 with second result 1 (0x271050d); the caller keeps that second result; byte +0xbc of token row 0 must be 1'),
    ('differs', 'order of the sender test', 'exempt sender tested with the destination lists', 'all the same order, except a flagged sender skips every destination list and the token row, as the reference says; a destination in the 0x20 block is not in the reference gas test at all'),
    ('differs', 'block 0x20', 'one address, rejected when a policy flag is set', 'in this function a whole block 0x20..00 to 0x20..270f gives gas 0 and no reject'),
    ('differs', 'empty token list', 'no such case', 'panic at spot_meta.rs:113:33 after every destination test passed (0x2710516)'),
    ('differs', 'number of functions', 'one', 'three bodies; 0x4d00b00 reads the lists at +0x1040 and the row table at +0x11c0'),
    ('same', 'FIRST_DEX_FEE_USD6', '1000000', 'immediate at 0x27101e8'),
    ('same', 'force_fee_sender_profiles', 'sender profile byte +61', 'byte +0x3d of the row from the helper, tested at 0x27101d5'),
    ('same', 'destination tests', 'tables at exchange+1472 and +792 and the all-0x22 address', 'dex list +0x5c0 (table +0xf8 of each row), table +0x318, block 0x59c10c'),
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
            except (Unmodelled, EvidenceError, KeyError) as exc:
                msg = f'fault {type(exc).__name__} {exc}'
            if msg:
                raise EvidenceError(f"mismatch in {v['group']} at {v['entry']:#x}: {msg}")
    finally:
        SEEN = None
    missing, padding = [], 0
    for fn in SUBJECTS + HELPERS:
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
    out_path = Path(out_dir)
    out_path.mkdir(parents=True, exist_ok=True)
    groups, outcomes = {}, {}
    with open(out_path / 'vectors.tsv', 'w', newline='\n') as f:
        f.write('group\tentry\tstate\toutcome\n')
        for v in vecs:
            groups[v['group']] = groups.get(v['group'], 0) + 1
            want = gas_model(v)
            name = want if want == 'panic' else f'{want[0]},{want[1]}'
            outcomes[name] = outcomes.get(name, 0) + 1
            f.write(f"{v['group']}\t{v['entry']:#x}\t{digest_of(v)}\t{name}\n")
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
        stubs=dict(row_hash=[hex(HASH_ROW), hex(HASH_ROW_B)], address_hash=hex(HASH_ADDR), compare=hex(slots[GOT_MEMCMP]), panic=hex(slots[GOT_PANIC]), once=hex(slots[GOT_ONCE])),
        special_slot=hex(SLOT_SPECIAL), special_target=hex(img.relative(SLOT_SPECIAL)), default_slot=hex(SLOT_DEFAULT), default_cell=hex(img.relative(SLOT_DEFAULT)), default_builder=hex(img.relative(DEFAULT_CELL)),
        callers={hex(e): direct_sites(img, e, starts) for e in ENTRIES}, special_sites=slot_sites(img, SLOT_SPECIAL, starts),
        shapes={hex(e): {k: hex(x) for k, x in s_.items()} for e, s_ in SHAPES.items()},
        locations={'empty_tokens': location(img, TOKEN_BOUND)},
        gas_status=dict(tag=hex(0xf6), table_target=hex(0x59a8d0 + struct.unpack('<i', img.read(0x59a8d0 + 4 * 0xf6, 4))[0]), format=format_text(img, GAS_FORMAT)),
        consumer=dict(site=hex(CONSUMER), target=hex(CONSUMER + 5 + struct.unpack('<i', img.read(CONSUMER + 1, 4))[0])),
        all_22_block=img.read(ALL_22_BLOCK, 20).hex(), literals=[dict(first=hex(a), tail=b) for a, b in LITERALS], pinned=pinned(img),
        vectors=len(vecs), mismatches=0, groups=groups, outcomes=outcomes, padding_not_executed=padding,
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
