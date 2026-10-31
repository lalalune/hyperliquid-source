#!/usr/bin/env python3
"""fees: node #94 conversion and accumulation path at 0x37153f0, from bytes alone.

Static, no execution of the node.  The function that holds the only panic record
naming l1/src/fees/compute.rs is decoded from its ELF bytes by the small table
decoder below, which must land exactly on the FDE end.  The decoded instructions
are then interpreted in Python with every callee replaced by a stub, and each
outcome is compared with a separate closed-form model and with the reference.

    python3 tools/fees_unit_conversion.py --out <dir>

writes evidence.json, instructions.tsv, vectors.tsv and reference-diff.tsv.  Only
the standard library is used: no objdump, readelf or other external program runs,
so the results cannot depend on a binutils version.
"""

import argparse
import bisect
import hashlib
import json
import math
import struct
import sys
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
BINARY = 'artifacts/node/94/hl-node'
SHA256 = '3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f'

FN = 0x37153f0
POINTER_SLOT = 0x5774560
ONE_VA, TENTH_VA = 0x20a730, 0x20a880
LOW_VA, HIGH_VA, BIG_VA = 0x20acb8, 0x20a7f0, 0x20a2c8
DIV_MAGIC, DIV_SHIFT, DIVISOR = 0x346dc5d63886594b, 11, 10_000
RATE_LIMIT = 0x28f5c28f5c28f5c      # input above this skips the rate multiply
CLAMP = 0x147ae147ae147ae           # bound on the product after the rate multiply
CLAMP_NEG = 0xfeb851eb851eb852
REFERENCE_CLAMP = 0x14_7ae1_47ae_147a  # MAX_POST_RATE_PRODUCT in the reference tree
I64_MIN, I64_MAX = -(1 << 63), (1 << 63) - 1
U64 = (1 << 64) - 1

LOCATIONS = {'asset_or_dex': 0x56f21c0, 'mul_100': 0x570b510, 'abs': 0x5714da0, 'add': 0x5715e68,
             'unwrap': 0x5714c10}
OVERFLOW_HOOK_SLOT = 0x5773190
PANIC_SLOTS = (0x576e470, 0x576e048, 0x576eb38)
MUL_100_PANIC = 0x3715bd6
EXT_ENTRY, EXT_ADD = 0x3596da0, 0x33bcd10
USER_ENTRY, DAY_ADD, TOTAL_ADD = 0x3596940, 0x33bc210, 0x33bb180
SPLIT, SET_ADD, SET_REMOVE = 0x3745a60, 0x339b590, 0x33acfe0

R = dict(rax=0, rcx=1, rdx=2, rbx=3, rsp=4, rbp=5, rsi=6, rdi=7, r8=8, r9=9, r10=10, r11=11, r12=12, r13=13,
         r14=14, r15=15)
NAMES64 = list(R)
CC = ('o', 'no', 'b', 'ae', 'e', 'ne', 'be', 'a', 's', 'ns', 'p', 'np', 'l', 'ge', 'le', 'g')
ALU = ('add', 'or', 'adc', 'sbb', 'and', 'sub', 'xor', 'cmp')


class EvidenceError(Exception):
    pass


class Unmodelled(Exception):
    """The evaluator met something it does not model; never treated as a result."""


class Panic(Exception):
    def __init__(self, location):
        super().__init__(location)
        self.location = location


def check_digest(data, expected=SHA256):
    got = hashlib.sha256(data).hexdigest()
    if got != expected:
        raise EvidenceError(f'sha256 mismatch: {got} != {expected}')
    return got


def sections(data):
    if data[:6] != b'\x7fELF\x02\x01':
        raise EvidenceError('not an ELF64 little-endian file')
    shoff = struct.unpack_from('<Q', data, 0x28)[0]
    shentsize, shnum, shstrndx = struct.unpack_from('<HHH', data, 0x3a)
    raw = [struct.unpack_from('<IIQQQQIIQQ', data, shoff + i * shentsize) for i in range(shnum)]
    stroff = raw[shstrndx][4]
    out = {}
    for name, typ, _flags, addr, off, size, *_ in raw:
        end = data.index(b'\0', stroff + name)
        out[data[stroff + name:end].decode()] = (addr, off, size, typ)
    return out


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

    def text(self):
        addr, off, size, _ = self.sec['.text']
        return addr, bytes(self.data[off:off + size])

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


def uleb(buf, i):
    val = shift = 0
    while True:
        if i >= len(buf):
            raise EvidenceError('truncated ULEB128')
        b = buf[i]
        i += 1
        if shift >= 64 or (shift == 63 and b & 0x7e):
            raise EvidenceError('ULEB128 exceeds 64 bits')
        val |= (b & 0x7f) << shift
        shift += 7
        if b < 0x80:
            return val, i


def read_enc(img, va, enc):
    fmt = enc & 0x0f
    size, code = {0x03: (4, '<I'), 0x0b: (4, '<i'), 0x04: (8, '<Q'), 0x0c: (8, '<q')}[fmt]
    val = struct.unpack(code, img.read(va, size))[0]
    if enc & 0x70 == 0x10:
        val += va
    elif enc & 0x70 != 0x00:
        raise EvidenceError(f'unsupported pointer encoding {enc:#x}')
    return val & U64, size


class Fdes:
    """Binary-search table from .eh_frame_hdr; ranges from each FDE body."""

    def __init__(self, img):
        self.img = img
        hdr = img.sec['.eh_frame_hdr'][0]
        version, ptr_enc, cnt_enc, tbl_enc = img.read(hdr, 4)
        if (version, cnt_enc, tbl_enc) != (1, 0x03, 0x3b):
            raise EvidenceError('unexpected .eh_frame_hdr encodings')
        _, n = read_enc(img, hdr + 4, ptr_enc)
        count = struct.unpack('<I', img.read(hdr + 4 + n, 4))[0]
        table = img.read(hdr + 8 + n, count * 8)
        self.starts, self.fde = [], []
        for i in range(count):
            loc, fde = struct.unpack_from('<ii', table, i * 8)
            self.starts.append(hdr + loc)
            self.fde.append(hdr + fde)
        if any(b <= a for a, b in zip(self.starts, self.starts[1:])):
            raise EvidenceError('.eh_frame_hdr table not strictly increasing')
        self.count = count

    def cie_r_encoding(self, cie):
        img = self.img
        body = img.read(cie + 4, 64)
        if struct.unpack_from('<I', body, 0)[0] != 0:
            raise EvidenceError('CIE id is not zero')
        version = body[4]
        end = body.index(b'\0', 5)
        aug = body[5:end].decode()
        i = end + 1
        _, i = uleb(body, i)
        _, i = uleb(body, i)
        if version == 1:
            i += 1
        else:
            _, i = uleb(body, i)
        if not aug.startswith('z'):
            raise EvidenceError('CIE without z augmentation')
        _, i = uleb(body, i)
        for ch in aug[1:]:
            if ch == 'R':
                return body[i]
            if ch == 'L':
                i += 1
            elif ch == 'P':
                penc = body[i]
                i += 1 + {0x03: 4, 0x0b: 4, 0x04: 8, 0x0c: 8}[penc & 0x0f]
            else:
                raise EvidenceError(f'unsupported augmentation {aug!r}')
        raise EvidenceError('CIE has no R augmentation')

    def range_of(self, va):
        k = bisect.bisect_right(self.starts, va) - 1
        if k < 0:
            raise EvidenceError(f'{va:#x} precedes every FDE')
        fde = self.fde[k]
        cie_ptr = struct.unpack('<I', self.img.read(fde + 4, 4))[0]
        enc = self.cie_r_encoding(fde + 4 - cie_ptr)
        first, n = read_enc(self.img, fde + 8, enc)
        length, _ = read_enc(self.img, fde + 8 + n, enc & 0x0f)
        if first != self.starts[k]:
            raise EvidenceError(f'FDE {fde:#x} start disagrees with .eh_frame_hdr')
        if not first <= va < first + length:
            raise EvidenceError(f'{va:#x} is outside FDE [{first:#x},{first + length:#x})')
        return {'start': first, 'end': first + length, 'fde': fde, 'hdr_index': k}


class Insn:
    __slots__ = ('va', 'size', 'op', 'ops', 'width', 'raw')

    def __init__(self, va, size, op, ops, width, raw):
        self.va, self.size, self.op, self.ops, self.width, self.raw = va, size, op, ops, width, raw


def signed(val, bits):
    return val - (1 << bits) if val >> (bits - 1) & 1 else val


def decode_one(code, i, va):
    """Decode the instruction at code[i]; raise EvidenceError on any unlisted encoding."""
    start = i
    p66 = rep = False
    while code[i] in (0x66, 0xf2, 0xf3, 0x2e):
        p66 |= code[i] == 0x66
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
        base, index, scale, rip = None, None, 1, False
        if rm == 4:
            sib = code[i]
            i += 1
            scale = 1 << (sib >> 6)
            idx = sib >> 3 & 7 | rx << 3
            index = None if idx == 4 else idx
            base = sib & 7 | rb << 3
            if sib & 7 == 5 and mod == 0:
                raise EvidenceError(f'{va:#x}: SIB without base')
        elif rm == 5 and mod == 0:
            rip = True
        else:
            base = rm | rb << 3
        disp = 0
        if mod == 1:
            disp = signed(code[i], 8)
            i += 1
        elif mod == 2 or rip:
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
        return Insn(va, i - start, op, ops, bits or width, bytes(code[start:i]))

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
        if b2 == 0x2a and rep == 'f2':
            reg, rm = modrm(width)
            return done('cvtsi2sd', (('x', reg | rr << 3), rm))
        if b2 == 0x2c and rep == 'f2':
            reg, rm = modrm(64, True)
            return done('cvttsd2si', (gpr(reg | rr << 3, width), rm))
        if b2 == 0x2e and p66:
            reg, rm = modrm(64, True)
            return done('ucomisd', (('x', reg | rr << 3), rm), 64)
        if b2 == 0x57:
            reg, rm = modrm(128, True)
            return done('xorpd' if p66 else 'xorps', (('x', reg | rr << 3), rm), 128)
        if b2 in (0x59, 0x5d, 0x5f) and rep == 'f2':
            reg, rm = modrm(64, True)
            return done({0x59: 'mulsd', 0x5d: 'minsd', 0x5f: 'maxsd'}[b2], (('x', reg | rr << 3), rm), 64)
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
    if b < 0x40 and b & 7 <= 3:
        bits = 8 if not b & 1 else width
        reg, rm = modrm(bits)
        g = gpr(reg | rr << 3, bits)
        return done(ALU[b >> 3], (rm, g) if not b & 2 else (g, rm), bits)
    if 0x50 <= b <= 0x5f:
        return done('push' if b < 0x58 else 'pop', (gpr(b & 7 | rb << 3, 64),), 64)
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
        v = imm(4 if b == 0x81 else 1)
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
    if b == 0x90 and p66:
        return done('nop', ())
    if 0xb8 <= b <= 0xbf:
        v = imm(8 if w else 4)
        val = v[1] & (U64 if w else 0xffffffff)
        return done('mov', (gpr(b & 7 | rb << 3, width), ('i', val)))
    if b == 0xc1:
        reg, rm = modrm(width)
        v = imm(1)
        if reg not in (4, 5):
            raise EvidenceError(f'{va:#x}: unlisted shift /{reg}')
        return done('shl' if reg == 4 else 'shr', (rm, ('i', v[1] & 0xff)))
    if b == 0xc3:
        return done('ret', ())
    if b == 0xc7:
        reg, rm = modrm(width)
        if reg:
            raise EvidenceError(f'{va:#x}: unlisted c7 /{reg}')
        return done('mov', (rm, imm(4)))
    if b in (0xe8, 0xe9):
        rel = imm(4)[1]
        return done('call' if b == 0xe8 else 'jmp', (('t', va + (i - start) + rel),))
    if b == 0xeb:
        rel = imm(1)[1]
        return done('jmp', (('t', va + (i - start) + rel),))
    if b == 0xf6:
        reg, rm = modrm(8)
        if reg:
            raise EvidenceError(f'{va:#x}: unlisted f6 /{reg}')
        return done('test', (rm, imm(1)), 8)
    if b == 0xf7:
        reg, rm = modrm(width)
        if reg not in (3, 4):
            raise EvidenceError(f'{va:#x}: unlisted f7 /{reg}')
        return done('neg' if reg == 3 else 'mul', (rm,))
    if b == 0xff:
        reg, rm = modrm(width)
        if reg == 0:
            return done('inc', (rm,))
        if reg == 2:
            return done('call', (rm,), 64)
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
        self.next_base = 0x7000_0000_0000
        self.regs = [0] * 16
        self.xmm = [[0, 0] for _ in range(16)]
        self.cf = self.zf = self.sf = self.of = self.pf = False
        self.stubs = {}
        self.slots = {}
        self.seen = set()
        self.trace = None

    def arena(self, size, strict=True):
        a = Arena(self.next_base, size, strict)
        self.next_base += (size + 0xffff) & ~0xfff
        self.arenas.append(a)
        return a

    def find(self, addr, size):
        for a in self.arenas:
            if a.base <= addr and addr + size <= a.base + a.size:
                return a
        return None

    def load(self, addr, size):
        a = self.find(addr, size)
        if a is None:
            if self.img.in_rodata(addr, size):
                return int.from_bytes(self.img.read(addr, size), 'little')
            raise Unmodelled(f'load {addr:#x}')
        o = addr - a.base
        if a.strict and not all(a.valid[o:o + size]):
            raise Unmodelled(f'read of unset bytes at {addr:#x}')
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
            else:
                raise Unmodelled(f'{ins.va:#x}: movsd form')
        elif op in ('xorps', 'xorpd'):
            if ops[0] != ops[1]:
                raise Unmodelled(f'{ins.va:#x}: xor of two registers')
            self.xmm[ops[0][1]] = [0, 0]
        elif op == 'cvtsi2sd':
            self.xmm[ops[0][1]][0] = f2b(float(signed(self.rd(ops[1]), 64)))
        elif op == 'movq':
            self.wr(ops[0], self.xmm[ops[1][1]][0])
        elif op == 'mulsd':
            self.xmm[ops[0][1]][0] = f2b(b2f(self.xmm[ops[0][1]][0]) * b2f(self.xrd64(ops[1])))
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
        target = o[1] if o[0] == 't' else self.ea(o)
        if o[0] != 't' and target in PANIC_SLOTS:
            loc = self.regs[R['r8']] if target == 0x576e048 else self.regs[R['rdi']]
            raise Panic(loc)
        stub = self.stubs.get(target)
        if stub is None:
            raise Unmodelled(f'{ins.va:#x}: call {target:#x}')
        stub()

    def run(self, entry, limit=5000):
        rip = entry
        for _ in range(limit):
            ins = self.code.get(rip)
            if ins is None:
                raise Unmodelled(f'no instruction at {rip:#x}')
            self.seen.add(rip)
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
            elif op[0] == 'j' and op != 'jmp':
                if self.cond(op[1:]):
                    nxt = ops[0][1]
            elif op == 'jmp':
                nxt = ops[0][1]
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
                self.regs[4] -= 8
                self.store(self.regs[4], 8, self.rd(ops[0]))
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
                self.regs[0] = full & U64
                self.regs[2] = full >> 64
                self.cf = self.of = self.regs[2] != 0
            elif op == 'imul':
                v = signed(self.rd(ops[1]), ins.width) * ops[2][1]
                self.wr(ops[0], v)
                self.cf = self.of = v != signed(v & ((1 << ins.width) - 1), ins.width)
            elif op == 'neg':
                a = self.rd(ops[0])
                res = -a & ((1 << ins.width) - 1)
                self.cf = a != 0
                self.of = a == 1 << (ins.width - 1)
                self.nz(res, ins.width)
                self.wr(ops[0], res)
            elif op == 'inc':
                a = self.rd(ops[0])
                res = (a + 1) & ((1 << ins.width) - 1)
                self.of = a == (1 << (ins.width - 1)) - 1
                self.nz(res, ins.width)
                self.wr(ops[0], res)
            elif op in ('shl', 'shr'):
                n = ops[1][1] & 63
                a = self.rd(ops[0])
                res = (a << n if op == 'shl' else a >> n) & ((1 << ins.width) - 1)
                self.nz(res, ins.width)
                self.wr(ops[0], res)
            elif op == 'call':
                self.call(ins)
            else:
                self.do_sse(ins)
            rip = nxt
        raise Unmodelled('step limit')


def tree_nodes(m, kind, keys, deep):
    """A fake B-tree root for `keys`; `deep` hangs each key's gap on a child leaf.

    Returns (root, height).  Offsets are the ones the search loops read.
    """
    layout = {'u64': (0x218, 8, 0x272, 0x278), 'i32': (0xb8, 4, 0xe6, 0xe8)}[kind]
    key_off, key_size, len_off, edge_off = layout

    def node(ks, edges):
        a = m.arena(0x300)
        for i, k in enumerate(ks):
            m.store(a.base + key_off + i * key_size, key_size, k)
        m.store(a.base + len_off, 2, len(ks))
        for i, e in enumerate(edges):
            m.store(a.base + edge_off + i * 8, 8, e)
        return a.base

    if not keys:
        return 0, 0
    if not deep:
        return node(keys, []), 0
    mid = keys[len(keys) // 2:len(keys) // 2 + 1]
    left = [k for k in keys if k < mid[0]]
    right = [k for k in keys if k > mid[0]]
    return node(mid, [node(left, []), node(right, [])]), 1


def scenario(**kw):
    s = dict(ntli=0, asset=7, dex=0, assets_len=16, flag29=1, trial=0, trial_m=1.0, rate=1.0, side=0, tag=0, day=20,
             ext_day=19, mode=2, secondary=0, primary_amt=0, secondary_amt=0, gross=0, rebate=0, protocol=0,
             ext=0, paid_s=0, paid_u=0, day_pair=(0, 0), total_pair=(0, 0), day_keys=(), ext_keys=(),
             total_keys=(), deep=False, flip_active=0, active=0)
    s.update(kw)
    return s


def evaluate(img, insns, s):
    """Run the real bytes on scenario `s` and report what they did."""
    m = Machine(img, insns)
    stack = m.arena(0x4000, strict=False)
    state = m.arena(0x300)
    inp = m.arena(0x300)
    rt = m.arena(0x100)
    table = m.arena(0x30 * 16)
    rec = m.arena(0x60)
    ext_map = m.arena(0xb0)
    cell = {'ext': m.arena(8), 'day': m.arena(16), 'total': m.arena(16)}
    calls = []

    def st(a, off, size, val):
        m.store(a.base + off, size, val)

    st(state, 0x8, 8, table.base)
    st(state, 0x10, 8, s['assets_len'])
    st(state, 0x30, 8, s['dex'])
    st(state, 0x50, 8, s['ext_day'])
    st(state, 0x58, 1, s['trial'])
    st(state, 0x2a0, 8, f2b(s['rate']))
    total_root, total_h = tree_nodes(m, 'i32', [k for k in s['total_keys']], s['deep'])
    st(state, 0x258, 8, total_root)
    st(state, 0x260, 8, total_h)
    st(rt, 0xa0, 8, f2b(s['trial_m']))
    st(inp, 0x208, 8, s['asset'])
    st(inp, 0x218, 8, s['ntli'] & U64)
    st(inp, 0x228, 4, s['day'])
    st(inp, 0x234, 1, s['tag'])
    for side in (0, 1):
        o = side << 8
        for k in range(20):
            st(inp, 0xd8 + o + k, 1, 0xa0 + side + k)
        st(inp, 0x58 + o, 8, s['mode'])
        st(inp, 0x60 + o, 8, s['primary_amt'])
        for k in range(20):
            st(inp, 0x68 + o + k, 1, 0xb0 + k)
            st(inp, 0x90 + o + k, 1, 0xc0 + k)
        st(inp, 0x80 + o, 8, s['secondary'])
        st(inp, 0x88 + o, 8, s['secondary_amt'])
        st(inp, 0xa8 + o, 8, s['gross'])
        st(inp, 0xb0 + o, 8, s['rebate'])
        st(inp, 0xb8 + o, 8, s['protocol'])
    for k in range(16):
        st(table, 0x29 + k * 0x30, 1, s['flag29'])
    st(rec, 0x20, 8, s['active'])
    day_root, day_h = tree_nodes(m, 'i32', [k for k in s['day_keys']], s['deep'])
    st(rec, 0x28, 8, day_root)
    st(rec, 0x30, 8, day_h)
    st(rec, 0x40, 8, s['paid_s'])
    st(rec, 0x48, 8, s['paid_u'])
    ext_root, ext_h = tree_nodes(m, 'u64', [k for k in s['ext_keys']], s['deep'])
    st(ext_map, 0x98, 8, ext_root)
    st(ext_map, 0xa0, 8, ext_h)
    st(cell['ext'], 0, 8, s['ext'])
    st(cell['day'], 0, 8, s['day_pair'][0])
    st(cell['day'], 8, 8, s['day_pair'][1])
    st(cell['total'], 0, 8, s['total_pair'][0])
    st(cell['total'], 8, 8, s['total_pair'][1])

    def arg(name):
        return m.regs[R[name]]

    def user_at(ptr):
        return bytes(m.load(ptr + k, 1) for k in range(20))

    def ext_entry():
        calls.append(('ext_entry', user_at(arg('rsi')), arg('rdi') - rt.base))
        m.clobber(ext_map.base)

    def ext_add():
        calls.append(('ext_add', entry_slot(arg('rdi'), 'ext')))
        m.clobber(cell['ext'].base)

    def user_entry():
        calls.append(('user_entry', user_at(arg('rsi')), arg('rdi') - state.base))
        m.clobber(rec.base)

    def day_add():
        calls.append(('day_add', entry_slot(arg('rdi'), 'i32')))
        if s['flip_active']:
            st(rec, 0x20, 8, 0 if s['active'] else 1)
        m.clobber(cell['day'].base)

    def total_add():
        calls.append(('total_add', entry_slot(arg('rdi'), 'i32')))
        m.clobber(cell['total'].base)

    def entry_slot(e, kind):
        """Read back the entry handle: found -> (key, 'found'), vacant -> (key, 'vacant', node, slot)."""
        tag = m.load(e, 8)
        if kind == 'ext':
            if tag == 0:
                node, _, idx = m.load(e + 8, 8), m.load(e + 16, 8), m.load(e + 24, 8)
                return (m.load(node + 0x218 + idx * 8, 8), 'found')
            key, node = m.load(e + 8, 8), m.load(e + 16, 8)
            return (key, 'vacant', m.load(e + 32, 8) if node else None)
        if tag == 0:
            node, _, idx = m.load(e + 8, 8), m.load(e + 16, 8), m.load(e + 24, 8)
            return (m.load(node + 0xb8 + idx * 4, 4), 'found')
        node = m.load(e + 8, 8)
        return (m.load(e + 32, 4), 'vacant', m.load(e + 24, 8) if node else None)

    def split():
        a = arg('rcx')
        calls.append(('split', user_at(arg('rsi')), arg('rdx'), {
            'primary': (m.load(a, 8), m.load(a + 8, 8) if m.load(a, 8) else None,
                        user_at(a + 0x10) if m.load(a, 8) else None),
            'secondary': (m.load(a + 0x28, 8), m.load(a + 0x30, 8) if m.load(a + 0x28, 8) else None,
                          user_at(a + 0x38) if m.load(a + 0x28, 8) else None),
            'gross': m.load(a + 0x50, 8), 'rebate': m.load(a + 0x58, 8), 'protocol': m.load(a + 0x60, 8)}))
        m.clobber()

    def set_add():
        calls.append(('set_add', user_at(arg('rsi'))))
        m.clobber()

    def set_remove():
        calls.append(('set_remove', user_at(arg('rsi'))))
        m.clobber()

    def hook():
        calls.append(('overflow_hook', arg('rsi')))
        m.clobber()

    m.stubs = {EXT_ENTRY: ext_entry, EXT_ADD: ext_add, USER_ENTRY: user_entry, DAY_ADD: day_add, TOTAL_ADD: total_add,
               SPLIT: split, SET_ADD: set_add, SET_REMOVE: set_remove, OVERFLOW_HOOK_SLOT: hook}
    m.regs[4] = stack.base + 0x3000 + 8     # rsp+8 is 16-byte aligned on entry
    m.regs[R['rbx']], m.regs[R['rbp']], m.regs[R['r12']], m.regs[R['r13']], m.regs[R['r14']], m.regs[R['r15']] = (
        0x1111, 0x2222, 0x3333, 0x4444, 0x5555, 0x6666)
    saved = list(m.regs)
    m.regs[R['rdi']], m.regs[R['rsi']], m.regs[R['rdx']], m.regs[R['rcx']] = state.base, inp.base, s['side'], rt.base
    out = {'calls': calls}
    try:
        m.run(FN)
        out['status'] = 'ok'
        if m.regs[4] != saved[4] + 8:
            raise Unmodelled('stack not balanced')
        for r in ('rbx', 'rbp', 'r12', 'r13', 'r14', 'r15'):
            if m.regs[R[r]] != saved[R[r]]:
                raise Unmodelled(f'{r} not restored')
    except Panic as p:
        out['status'] = f'panic:{p.location:#x}'
    out['ext'] = m.load(cell['ext'].base, 8)
    out['paid_s'], out['paid_u'] = m.load(rec.base + 0x40, 8), m.load(rec.base + 0x48, 8)
    out['day'] = (m.load(cell['day'].base, 8), m.load(cell['day'].base + 8, 8))
    out['total'] = (m.load(cell['total'].base, 8), m.load(cell['total'].base + 8, 8))
    out['seen'] = m.seen
    return out


def to_i64(x):
    """All three conversion blocks: non-finite gives 0, else clamp and truncate."""
    if math.isnan(x) or math.isinf(x):
        return 0
    if x <= -(2.0 ** 63):
        return I64_MIN
    if x >= 2.0 ** 63:
        return I64_MAX
    return int(x)


def rate_step(value, rate, clamp=CLAMP):
    """`value` is non-negative and at most RATE_LIMIT."""
    x = to_i64(float(value) * rate)
    if x == I64_MIN:
        raise Panic(LOCATIONS['abs'])
    return max(max(-clamp, min(clamp, x)), 0)


def sat(a, b):
    return min(a + b, U64)


def model(s):
    """Closed form of the function, written from the semantics, not from the evaluator."""
    out = {'status': 'ok', 'hooks': 0}

    def add(a, b):
        out['hooks'] += a + b > U64
        return sat(a, b)

    keep = {'ext': s['ext'], 'paid_s': s['paid_s'], 'paid_u': s['paid_u'], 'day': s['day_pair'],
            'total': s['total_pair']}
    out.update(keep)
    asset = s['asset']
    if asset // DIVISOR != s['dex'] or asset % DIVISOR >= s['assets_len']:
        out['status'] = f"panic:{LOCATIONS['asset_or_dex']:#x}"
        return out
    n = s['ntli']
    if n < 0:
        out['status'] = f"panic:{LOCATIONS['unwrap']:#x}"
        return out
    m = s['trial_m'] if s['trial'] else 1.0
    if not s['flag29']:
        m *= 0.1
    v = to_i64(m * float(n))
    try:
        rated = max(v, 0) if v > RATE_LIMIT else rate_step(max(v, 0), s['rate'])
        unrated = n if n > RATE_LIMIT else rate_step(n, s['rate'])
    except Panic as p:
        out['status'] = f'panic:{p.location:#x}'
        return out
    scaled, unscaled = rated // DIVISOR, unrated // DIVISOR
    out['scaled'], out['unscaled'] = scaled, unscaled
    if s['mode'] != 2:
        out['ext'] = add(s['ext'], scaled)
        amounts = [s['gross'], s['rebate']]
        if s['mode'] & 1:
            amounts.append(s['primary_amt'])
        if s['secondary']:
            amounts.append(s['secondary_amt'])
        amounts.append(s['protocol'])
        if any(a * 100 > U64 for a in amounts):
            out['status'] = f"panic:{LOCATIONS['mul_100']:#x}"
            return out
    out['paid_s'] = add(s['paid_s'], scaled)
    out['paid_u'] = add(s['paid_u'], unscaled)
    i = int(s['tag'] == s['side'])
    day = list(s['day_pair'])
    day[i] = add(day[i], scaled)
    out['day'] = tuple(day)
    if s['side']:
        out['total'] = (add(s['total_pair'][0], scaled), add(s['total_pair'][1], unscaled))
    return out


def compare(s, got, want):
    bad = [k for k in ('status', 'ext', 'paid_s', 'paid_u', 'day', 'total') if got[k] != want[k]]
    if got['status'] == 'ok' and sum(c[0] == 'overflow_hook' for c in got['calls']) != want['hooks']:
        bad.append('hooks')
    if got['status'] != 'ok':
        return bad
    names = [c[0] for c in got['calls'] if c[0] != 'overflow_hook']
    expect = (['ext_entry', 'ext_add', 'split'] if s['mode'] != 2 else []) + ['user_entry', 'day_add']
    expect += (['set_add'] if s['flip_active'] and not s['active'] else
               ['set_remove'] if s['flip_active'] and s['active'] else [])
    expect += ['total_add'] if s['side'] else []
    if names != expect:
        bad.append('call-order')
    user = bytes(0xa0 + s['side'] + k for k in range(20))
    for c in got['calls']:
        if c[0] in ('ext_entry', 'user_entry', 'split', 'set_add', 'set_remove') and c[1] != user:
            bad.append('user')
        if c[0] == 'ext_add' and not entry_ok(c[1], s['ext_day'], s['ext_keys'], s['deep']):
            bad.append('ext-entry')
        if c[0] == 'day_add' and not entry_ok(c[1], s['day'], s['day_keys'], s['deep']):
            bad.append('day-entry')
        if c[0] == 'total_add' and not entry_ok(c[1], s['day'], s['total_keys'], s['deep']):
            bad.append('total-entry')
        if c[0] == 'split':
            d = c[3]
            if c[2] != s['ext_day'] or d['gross'] != s['gross'] * 100 or d['rebate'] != s['rebate'] * 100 \
                    or d['protocol'] != s['protocol'] * 100:
                bad.append('split-args')
            want_p = (1, s['primary_amt'] * 100, bytes(0xb0 + k for k in range(20))) if s['mode'] & 1 else \
                (0, None, None)
            want_q = (1, s['secondary_amt'] * 100, bytes(0xc0 + k for k in range(20))) if s['secondary'] else \
                (0, None, None)
            if d['primary'] != want_p or d['secondary'] != want_q:
                bad.append('split-options')
    return bad


def entry_ok(handle, key, keys, deep):
    if handle[0] != key:
        return False
    if key in keys:
        return handle[1] == 'found'
    if handle[1] != 'vacant':
        return False
    if not keys:
        return handle[2] is None
    if deep:
        mid = list(keys)[len(keys) // 2]
        leaf = [k for k in keys if (k < mid) == (key < mid) and k != mid]
    else:
        leaf = list(keys)
    return handle[2] == sum(k < key for k in leaf)


def double_neighbours(value):
    """The two doubles on either side of `value`, which itself has no exact double."""
    near = f2b(float(value))
    pair = sorted(int(b2f(near + k)) for k in (-1, 0, 1))
    below = max(v for v in pair if v < value)
    above = min(v for v in pair if v > value)
    if value in pair:
        raise EvidenceError(f'{value:#x} is an exact double')
    return below, above


DOUBLE_BELOW_LIMIT, DOUBLE_ABOVE_LIMIT = double_neighbours(RATE_LIMIT)
NTLIS = (0, 1, 9999, 10000, 19999, 20000, 10 ** 6, 10 ** 12, (1 << 53) + 1, 5764607523040000, CLAMP - 1, CLAMP,
         CLAMP + 1, DOUBLE_BELOW_LIMIT, RATE_LIMIT - 1, RATE_LIMIT, RATE_LIMIT + 1, DOUBLE_ABOVE_LIMIT, RATE_LIMIT * 2,
         I64_MAX)
RATES = (0.0, 5e-6, 0.00035, 0.1, 0.5, 0.5000000001, 1.0, 2.0, 10000.0, 1e300, -1.0, -1e300, math.inf, -math.inf,
         math.nan)
MULTIPLIERS = ((0, 1.0, 1), (0, 1.0, 0), (1, 1.0, 1), (1, 0.5, 1), (1, 0.5, 0), (1, 3.0, 1), (1, 0.0, 1), (1, -1.0, 1),
               (1, 1e300, 1), (1, math.inf, 1), (1, math.nan, 1))


def rate_grid():
    for n in NTLIS:
        for rate in RATES:
            for trial, tm, flag in MULTIPLIERS:
                yield 'rate', scenario(ntli=n, rate=rate, trial=trial, trial_m=tm, flag29=flag)


def admission_grid():
    yield 'admit', scenario(ntli=-1)
    yield 'admit', scenario(ntli=I64_MIN)
    yield 'admit', scenario(asset=10007)
    yield 'admit', scenario(asset=10007, dex=1, ntli=5)
    yield 'admit', scenario(asset=9999 + 10000, dex=1, ntli=5)
    yield 'admit', scenario(asset=16)
    yield 'admit', scenario(asset=15, ntli=5)
    yield 'admit', scenario(asset=0, ntli=5)
    yield 'admit', scenario(asset=(1 << 64) - 1)
    yield 'admit', scenario(ntli=1, rate=-1e300)
    yield 'admit', scenario(ntli=RATE_LIMIT + 1, rate=-1e300, trial=1, trial_m=1e-3)
    yield 'admit', scenario(ntli=RATE_LIMIT + 1, rate=-1e300)


def saturation_grid():
    top = U64 - 3
    base = dict(ntli=10 ** 9, rate=1.0)
    for side in (0, 1):
        for tag in (0, 1):
            for keys in ({}, dict(paid_s=top), dict(paid_u=top), dict(day_pair=(top, top)), dict(total_pair=(top, top)),
                         dict(ext=top, mode=0), dict(paid_s=top, paid_u=top, day_pair=(top, top),
                                                     total_pair=(top, top), ext=top, mode=1, gross=1)):
                yield 'saturate', scenario(side=side, tag=tag, **base, **keys)


def split_grid():
    limit = U64 // 100
    for mode in (0, 1):
        for secondary in (0, 1):
            for field in (None, 'gross', 'rebate', 'protocol', 'primary_amt', 'secondary_amt'):
                for bump in (0, 1):
                    amounts = dict(gross=5, rebate=6, protocol=7, primary_amt=8, secondary_amt=9)
                    if field:
                        amounts[field] = limit + bump
                    yield 'split', scenario(ntli=10 ** 8, mode=mode, secondary=secondary, **amounts)


def tree_grid():
    for side in (0, 1):
        for deep in (False, True):
            for day in (5, 20, 21, 40):
                for keys in ((), (10, 20, 30), (5, 40), (-3, 20)):
                    if deep and len(keys) < 3:
                        continue
                    yield 'tree', scenario(ntli=10 ** 9, side=side, day=day & 0xffffffff, day_keys=keys,
                                           total_keys=keys, ext_keys=tuple(k for k in keys if k >= 0),
                                           ext_day=day, deep=deep, mode=0)


def transition_grid():
    for active in (0, 1):
        for flip in (0, 1):
            for side in (0, 1):
                yield 'active', scenario(ntli=10 ** 9, active=active, flip_active=flip, side=side)


def all_vectors():
    for grid in (rate_grid, admission_grid, saturation_grid, split_grid, tree_grid, transition_grid):
        yield from grid()


def reference_units(n, rate):
    """fee_units_for_notional from the reference tree, with its constant."""
    if n <= RATE_LIMIT:
        v = to_i64(float(n) * rate)
        rated = 0 if v <= 0 else min(v, REFERENCE_CLAMP)
    else:
        rated = n
    return rated // DIVISOR


def binary_units(img, insns, n, rate):
    got = evaluate(img, insns, scenario(ntli=n, rate=rate))
    return got['status'], got['paid_u']


def reference_rows(img, insns):
    first = (REFERENCE_CLAMP // DIVISOR + 1) * DIVISOR
    rows = []
    for name, n, rate in (('below reference clamp', REFERENCE_CLAMP, 1.0),
                          ('first n that differs at rate 1', first, 1.0),
                          ('one below that', first - 1, 1.0),
                          ('binary clamp at rate 1', CLAMP, 1.0),
                          ('binary clamp + 1 at rate 1', CLAMP + 1, 1.0),
                          ('largest rated input', RATE_LIMIT, 1.0),
                          ('rate skipped', RATE_LIMIT + 1, 1.0),
                          ('half rate below limit', RATE_LIMIT, 0.5),
                          ('half rate above limit', RATE_LIMIT + 1, 0.5),
                          ('i64::MIN product', 1, -1e300)):
        status, got = binary_units(img, insns, n, rate)
        ref = reference_units(n, rate)
        rows.append((name, n, rate, status, got, ref, 'same' if status == 'ok' and got == ref else 'differs'))
    return rows


def division_exact(magic, shift, divisor):
    """`mul magic; shr rdx,shift` equals floor(n / divisor) for every u64 n.

    Round-up reciprocal test: with k = 64 + shift, magic must be the ceiling of
    2**k / divisor and e = magic * divisor - 2**k must satisfy 0 < e <= 2**shift.
    """
    k = 64 + shift
    e = magic * divisor - (1 << k)
    return magic == -(-(1 << k) // divisor) and 0 < e <= (1 << shift)


def path_suffix(raw):
    """Keep the part of a panic path below the build root."""
    for mark in (b'/l1/src/', b'/library/'):
        k = raw.find(mark)
        if k != -1:
            return raw[k + 1:].decode()
    raise EvidenceError(f'unexpected path {raw[-24:]!r}')


def decode_location(img, va):
    path = img.relative(va)
    size = img.u64(va + 8)
    line, col = struct.unpack('<II', img.read(va + 16, 8))
    return {'va': hex(va), 'path': path_suffix(img.read(path, size)), 'path_bytes': size, 'line': line, 'column': col}


def records_naming(img, va):
    """Copies of the panic path of record `va`, and RELATIVE relocations that point at it."""
    path = img.relative(va)
    raw = img.read(path, img.u64(va + 8))
    _, off, size, _ = img.sec['.rodata']
    rodata = img.data[off:off + size]
    copies, i = 0, rodata.find(raw)
    while i != -1:
        copies += 1
        i = rodata.find(raw, i + 1)
    _, off, size, _ = img.sec['.rela.dyn']
    needle = struct.pack('<QQ', 8, path)
    pointers, i = 0, img.data.find(needle, off, off + size)
    while i != -1:
        pointers += (i - off) % 24 == 8
        i = img.data.find(needle, i + 1, off + size)
    return {'string_copies': copies, 'relative_relocations_to_it': pointers}


def constants(img):
    c = {'one': img.f64(ONE_VA), 'tenth': img.f64(TENTH_VA), 'low': img.f64(LOW_VA), 'high': img.f64(HIGH_VA),
         'big': img.f64(BIG_VA)}
    if (c['one'], c['tenth']) != (1.0, 0.1):
        raise EvidenceError(f'multiplier constants {c}')
    if (c['low'], c['high']) != (-(2.0 ** 63), 2.0 ** 63) or img.u64(BIG_VA) != 0x43dfffffffffffff:
        raise EvidenceError(f'conversion constants {c}')
    return c


def immediates(insns):
    """Every 64-bit immediate load in the function, by value."""
    out = Counter()
    for i in insns:
        if i.op == 'mov' and i.ops[1][0] == 'i' and i.size == 10:
            out[i.ops[1][1]] += 1
    return out


def check_immediates(insns):
    got = immediates(insns)
    want = {DIV_MAGIC: 1, 0x7fffffffffffffff: 1, 0x7fefffffffffffff: 1, RATE_LIMIT: 1, CLAMP: 2, CLAMP_NEG: 2}
    if dict(got) != want:
        raise EvidenceError(f'64-bit immediates differ: { {hex(k): v for k, v in got.items()} }')


def sites(insns):
    """Hook calls and multiply-by-100 panic branches, from decoded operands only."""
    hooks, mul100 = [], []
    for k, ins in enumerate(insns):
        if ins.op == 'call' and ins.ops[0][0] == 'm' and ins.ops[0][1] is None and ins.ops[0][4] == OVERFLOW_HOOK_SLOT:
            lea = next((x for x in reversed(insns[max(0, k - 4):k]) if x.op == 'lea' and x.ops[0][1] == R['rsi']), None)
            if lea is None or lea.ops[1][4] != LOCATIONS['add']:
                raise EvidenceError(f'{ins.va:#x}: hook without the add location')
            hooks.append(ins.va)
        if ins.op == 'jo' and ins.ops[0][1] == MUL_100_PANIC:
            if insns[k - 1].op != 'mul':
                raise EvidenceError(f'{ins.va:#x}: panic branch not after mul')
            mul100.append(ins.va)
    if len(hooks) != 6 or len(mul100) != 5:
        raise EvidenceError(f'site counts: {len(hooks)} hooks, {len(mul100)} multiplications')
    return hooks, mul100


def slot_users(img, fdes):
    """`call [rip+d]` (ff 15) and `jmp [rip+d]` (ff 25) byte patterns through the pointer slot."""
    text_va, text = img.text()
    out = []
    for prefix, kind in ((b'\xff\x15', 'call'), (b'\xff\x25', 'jmp')):
        i = text.find(prefix)
        while i != -1:
            if i + 6 <= len(text) and text_va + i + 6 + struct.unpack_from('<i', text, i + 2)[0] == POINTER_SLOT:
                r = fdes.range_of(text_va + i)
                out.append({'kind': kind, 'va': hex(text_va + i), 'function': hex(r['start'])})
            i = text.find(prefix, i + 1)
    return sorted(out, key=lambda row: row['va'])


def row_text(group, s, got):
    return '\t'.join(str(v) for v in (group, s['ntli'], repr(s['rate']), s['trial'], repr(s['trial_m']), s['flag29'],
                                      got['status'], got['paid_s'], got['paid_u']))


def analyse(data, patches=None, vectors=all_vectors):
    digest = check_digest(data)
    img = Image(data, patches)
    fdes = Fdes(img)
    r = fdes.range_of(FN)
    if r['start'] != FN:
        raise EvidenceError('function is not an FDE start')
    if img.relative(POINTER_SLOT) != FN:
        raise EvidenceError('pointer slot does not name the function')
    insns = decode_range(img, r['start'], r['end'])
    c = constants(img)
    check_immediates(insns)
    hooks, mul100 = sites(insns)
    if not division_exact(DIV_MAGIC, DIV_SHIFT, DIVISOR):
        raise EvidenceError('division constant is not exact')
    if RATE_LIMIT != U64 // 100 or CLAMP != I64_MAX // 100 or CLAMP_NEG != (1 << 64) - CLAMP:
        raise EvidenceError('limit constants do not have the expected relation')
    seen, rows, groups, failures = set(), [], Counter(), []
    statuses = Counter()
    for group, s in vectors():
        got = evaluate(img, insns, s)
        want = model(s)
        bad = compare(s, got, want)
        groups[group] += 1
        statuses[got['status']] += 1
        seen |= got['seen']
        if bad:
            failures.append({'group': group, 'fields': bad, 'ntli': s['ntli'], 'rate': repr(s['rate'])})
        rows.append(row_text(group, s, got))
    if failures:
        raise EvidenceError(f'{len(failures)} vectors disagree; first {failures[0]}')
    missed = [i for i in insns if i.va not in seen]
    result = {
        'component': 'fees', 'binary': BINARY, 'sha256': digest, 'coordinates': 'virtual addresses (ELF VA)',
        'question': 'conversion and accumulation path at 0x37153f0',
        'fde_table_entries': fdes.count,
        'function': {'start': hex(r['start']), 'end': hex(r['end']), 'fde': hex(r['fde']),
                     'size': r['end'] - r['start'], 'instructions': len(insns), 'pointer_slot': hex(POINTER_SLOT)},
        'constants': {'one': c['one'], 'tenth': c['tenth'], 'conversion_low': c['low'], 'conversion_high': c['high'],
                      'conversion_big': c['big'], 'division_magic': hex(DIV_MAGIC), 'division_shift': DIV_SHIFT,
                      'divisor': DIVISOR, 'rate_limit': hex(RATE_LIMIT), 'clamp': hex(CLAMP),
                      'clamp_negative': hex(CLAMP_NEG), 'reference_clamp': hex(REFERENCE_CLAMP),
                      'reference_clamp_is_clamp_shifted_right_4': REFERENCE_CLAMP == CLAMP >> 4,
                      'scaled_branch_limit_neighbours_in_double': [hex(DOUBLE_BELOW_LIMIT), hex(DOUBLE_ABOVE_LIMIT)],
                      'rate_limit_is_u64_max_div_100': True, 'clamp_is_i64_max_div_100': True,
                      'division_exact_for_all_u64': True},
        'immediates_64': {hex(k): v for k, v in sorted(immediates(insns).items())},
        'overflow_hook_calls': [hex(v) for v in hooks],
        'mul_100_panic_branches': [hex(v) for v in mul100],
        'locations': {k: decode_location(img, v) for k, v in LOCATIONS.items()},
        'compute_rs_path': records_naming(img, LOCATIONS['mul_100']),
        'slot_users': slot_users(img, fdes),
        'evaluation': {'vectors': sum(groups.values()), 'groups': dict(sorted(groups.items())),
                       'status': dict(sorted(statuses.items())), 'mismatches': 0,
                       'instructions_executed': len(insns) - len(missed),
                       'instructions_not_executed': [{'va': hex(i.va), 'op': i.op} for i in missed]},
    }
    result['summary'] = {'instructions': len(insns), 'vectors': sum(groups.values()), 'mismatches': 0,
                         'instructions_not_executed': len(missed), 'hook_calls': len(hooks),
                         'mul_100_branches': len(mul100)}
    return result, img, insns, rows


def write(out, result, img, insns, rows):
    out.mkdir(parents=True, exist_ok=True)
    (out / 'evidence.json').write_text(json.dumps(result, indent=2, sort_keys=True) + '\n')
    lines = ['va\tsize\tbytes\tdecoded']
    lines += [f'{i.va:#x}\t{i.size}\t{i.raw.hex()}\t{show(i)}' for i in insns]
    (out / 'instructions.tsv').write_text('\n'.join(lines) + '\n')
    head = 'group\tntli\trate\ttrial\ttrial_multiplier\tflag29\tstatus\tscaled_total\tunscaled_total'
    (out / 'vectors.tsv').write_text('\n'.join([head] + rows) + '\n')
    lines = ['case\tnotional\trate\tbinary_status\tbinary_units\treference_units\tcompared']
    lines += ['\t'.join(str(v) for v in row) for row in reference_rows(img, insns)]
    (out / 'reference-diff.tsv').write_text('\n'.join(lines) + '\n')


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument('--out', required=True, type=Path)
    ap.add_argument('--binary', type=Path, default=ROOT / BINARY)
    args = ap.parse_args(argv)
    try:
        data = args.binary.read_bytes()
        result, img, insns, rows = analyse(data)
    except (EvidenceError, Unmodelled, OSError) as exc:
        print(f'error: {exc}', file=sys.stderr)
        return 1
    write(args.out, result, img, insns, rows)
    print(json.dumps(result['summary'], sort_keys=True))
    return 0


if __name__ == '__main__':
    sys.exit(main())
