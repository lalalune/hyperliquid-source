#!/usr/bin/env python3
"""fees: node #115 fee credit distribution, from bytes alone.

Static, no execution of the node.  The credit distribution 0x3c1ae50, the credit 0x3c1a250 and the extra credit
0x3c1a3f0 are decoded from ELF bytes by the table decoder below, which must land exactly on each FDE end, and
interpreted in Python on every vector.  The hash, hash-table find, entry and cell helpers are argument-checking
stubs.  Each outcome is compared with a separate closed-form model; then one-byte mutants of the subjects, wrong
models and corrupted inputs are all required to be caught.

    python3 tools/fees_credit_distribution_115.py --out <dir>

writes evidence.json, instructions.tsv, vectors.tsv, controls.tsv and measure.json.  Only the standard library is
used: no objdump, readelf or other external program runs, so the results cannot depend on a binutils version.
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
BINARY = 'artifacts/node/115/hl-node'
SHA256 = 'a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301'
I64_MIN, I64_MAX = -(1 << 63), (1 << 63) - 1
U64 = (1 << 64) - 1
PANIC_SLOTS = ()

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
        nobase = False
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
        if b2 in (0x58, 0x59, 0x5c, 0x5d, 0x5e, 0x5f) and rep == 'f2':
            reg, rm = modrm(64, True)
            names = {0x58: 'addsd', 0x59: 'mulsd', 0x5c: 'subsd', 0x5d: 'minsd', 0x5e: 'divsd', 0x5f: 'maxsd'}
            return done(names[b2], (('x', reg | rr << 3), rm), 64)
        if b2 == 0x5c and p66:
            reg, rm = modrm(128, True)
            return done('subpd', (('x', reg | rr << 3), rm), 128)
        if b2 == 0x15 and p66:
            reg, rm = modrm(128, True)
            return done('unpckhpd', (('x', reg | rr << 3), rm), 128)
        if b2 == 0x14 and not p66:
            reg, rm = modrm(128, True)
            return done('unpcklps', (('x', reg | rr << 3), rm), 128)
        if b2 == 0x62 and p66:
            reg, rm = modrm(128, True)
            return done('punpckldq', (('x', reg | rr << 3), rm), 128)
        if b2 == 0x6e and p66 and w:
            reg, rm = modrm(64)
            return done('movq', (('x', reg | rr << 3), rm), 64)
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
    if 0xb0 <= b <= 0xb7:
        v = imm(1)
        return done('mov', (gpr(b & 7 | rb << 3, 8), ('i', v[1] & 0xff)), 8)
    if b in (0xa8, 0x3c):
        v = imm(1)
        return done('test' if b == 0xa8 else 'cmp', (('r', 0, 8), ('i', v[1])), 8)
    if b == 0x98 and w:
        return done('cdqe', ())
    if 0xb8 <= b <= 0xbf:
        v = imm(8 if w else 4)
        val = v[1] & (U64 if w else 0xffffffff)
        return done('mov', (gpr(b & 7 | rb << 3, width), ('i', val)))
    if b == 0xc1:
        reg, rm = modrm(width)
        v = imm(1)
        if reg not in (4, 5, 7):
            raise EvidenceError(f'{va:#x}: unlisted shift /{reg}')
        return done({4: 'shl', 5: 'shr', 7: 'sar'}[reg], (rm, ('i', v[1] & 0xff)))
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

    def xrd128(self, o):
        if o[0] == 'x':
            return list(self.xmm[o[1]])
        a = self.ea(o)
        return [self.load(a, 8), self.load(a + 8, 8)]

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
        elif op == 'movq' and ops[0][0] == 'x':
            self.xmm[ops[0][1]] = [self.rd(ops[1]), 0]
        elif op == 'movq':
            self.wr(ops[0], self.xmm[ops[1][1]][0])
        elif op in ('punpckldq', 'unpcklps'):
            d = self.xmm[ops[0][1]]
            s = self.xrd128(ops[1])
            self.xmm[ops[0][1]] = [d[0] & 0xffffffff | (s[0] & 0xffffffff) << 32,
                                   d[0] >> 32 | (s[0] >> 32) << 32]
        elif op == 'subpd':
            d = self.xmm[ops[0][1]]
            s = self.xrd128(ops[1])
            self.xmm[ops[0][1]] = [f2b(b2f(d[0]) - b2f(s[0])), f2b(b2f(d[1]) - b2f(s[1]))]
        elif op == 'unpckhpd':
            d = self.xmm[ops[0][1]]
            s = self.xrd128(ops[1])
            self.xmm[ops[0][1]] = [d[1], s[1]]
        elif op in ('addsd', 'subsd', 'divsd', 'mulsd'):
            a, b = b2f(self.xmm[ops[0][1]][0]), b2f(self.xrd64(ops[1]))
            if op == 'divsd':
                r = (math.nan if a == 0 or math.isnan(a) or math.isnan(b) or (math.isinf(a) and math.isinf(b)) else
                     math.copysign(math.inf, a) * (math.copysign(1.0, b))) if b == 0 else a / b
            else:
                r = {'addsd': lambda: a + b, 'subsd': lambda: a - b, 'mulsd': lambda: a * b}[op]()
            self.xmm[ops[0][1]][0] = f2b(r)
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
        if stub is None and o[0] == 't' and target in self.code:
            self.regs[4] -= 8
            self.run(target)
            return
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
            elif op in ('shl', 'shr', 'sar'):
                n = ops[1][1] & 63
                a = self.rd(ops[0])
                if op == 'sar':
                    res = signed(a, ins.width) >> n
                else:
                    res = a << n if op == 'shl' else a >> n
                res &= (1 << ins.width) - 1
                self.nz(res, ins.width)
                self.wr(ops[0], res)
            elif op == 'call':
                self.call(ins)
            else:
                self.do_sse(ins)
            rip = nxt
        raise Unmodelled('step limit')


# ---------------------------------------------------------------------------------------------------------
# Subjects and addresses of node #115 (ELF virtual addresses)
# ---------------------------------------------------------------------------------------------------------
F_CREDIT, F_EXT, F_DIST = 0x3c1a250, 0x3c1a3f0, 0x3c1ae50
SUBJECTS = (F_CREDIT, F_EXT, F_DIST)
S_HASH, S_FIND, S_ENTRY, S_ENTRY_KEYED = 0x4717440, 0x3ee6280, 0x4717c50, 0x4718060
S_INNER, S_CELL, S_SUB, S_SUBROW, S_SUBINNER, S_SCELL = 0x3cd7aa0, 0x3f14bc0, 0x3cd5840, 0x3f171d0, 0x3cd0da0, 0x3f14f20
HOOK_SLOT = 0x64e4ea8
LOC_ADD, LOC_SUB, LOC_EXT = 0x6487460, 0x6487478, 0x6493948
CONST = {'one_e5': 0x459510, 'cutoff': 0x4590b8, 'two64': 0x459090, 'two64_minus_2048': 0x458d58,
         'two63': 0x459360, 'inf': 0x459010, 'punpck': 0x451210, 'subpd': 0x450170}
NONE = 1 << 63                      # niche word: Option<Vec> is None
U64 = (1 << 64) - 1
USERS = 10
GROUND = 'artifacts/node/115/hl-node'


def addr_of(uid):
    return bytes((0x40 + uid * 7 + k) & 0xff for k in range(20))


ADDR_UID = {addr_of(u): u for u in range(USERS)}
ENTRY_BUCKET = 0x6000_0000_0000


def sat(a, b):
    return min(a + b, U64)


# ---------------------------------------------------------------------------------------------------------
# Harness: the real bytes of the three subjects, with the hash/entry helpers as argument-checking stubs
# ---------------------------------------------------------------------------------------------------------
def default_init(kind, uid, key, off):
    return 1000 + off * 3 + uid * 17 + (key % 97) + (500 if kind == 'S' else 0)


def scenario(**kw):
    s = dict(fn='dist', key=5, user=0, amt=0, flag=0, addr1=1, gross=0, rebate=0, prot=0, cap_none=True, elems=(),
             sec=0, addr2=2, known=frozenset(), init=(), hk=(0x1234, 0x5678))
    s.update(kw)
    return s


class World:
    """Lazily created cells; every cell word starts at `default_init` unless the scenario overrides it."""

    def __init__(self, m, s):
        self.m, self.s = m, s
        self.override = dict(s['init'])
        self.cells, self.rows, self.subs, self.touch = {}, {}, {}, []
        self.hooks, self.log, self.bad = [], [], []

    def value(self, kind, uid, key, off):
        return self.override.get((kind, uid, key, off), default_init(kind, uid, key, off))

    def cell(self, kind, uid, key):
        k = (kind, uid, key)
        if k not in self.cells:
            size = 0x30 if kind == 'L' else 8
            a = self.m.arena(size)
            for off in range(0, size, 8):
                self.m.store(a.base + off, 8, self.value(kind, uid, key, off))
            self.cells[k] = a
        return self.cells[k]


def uid_at(m, ptr):
    raw = bytes(m.load(ptr + k, 1) for k in range(20))
    if raw not in ADDR_UID:
        raise Unmodelled(f'unknown address bytes {raw.hex()}')
    return ADDR_UID[raw]


def evaluate(img, insns, s):
    """Run the subject chosen by `s['fn']` on scenario `s`; returns the observed effects."""
    m = Machine(img, insns)
    stack = m.arena(0x4000, strict=False)
    state = m.arena(0x200)
    w = World(m, s)
    st = lambda a, off, size, val: m.store(a.base + off, size, val)       # noqa: E731
    st(state, 0xe8, 8, s['hk'][0])
    st(state, 0xf0, 8, s['hk'][1])
    for k in range(16):
        st(state, 0xb8 + k, 1, 0x90 + k)
    arg = lambda name: m.regs[R[name]]                                     # noqa: E731

    def hash_stub():
        if (arg('rdi'), arg('rsi')) != tuple(s['hk']):
            w.bad.append('hasher words')
        u = uid_at(m, arg('rdx'))
        w.log.append(('hash', u))
        m.clobber(0x1000 + addr_of(u)[0])

    def find_stub():
        probe = arg('rdx')
        u = uid_at(m, m.load(probe, 8))
        if arg('rdi') != state.base + 0xc8 or arg('rsi') != 0x1000 + addr_of(u)[0]:
            w.bad.append('find args')
        if bytes(m.load(probe + 8 + k, 1) for k in range(16)) != bytes(0x90 + k for k in range(16)):
            w.bad.append('find ctx')
        found = u in s['known']
        w.log.append(('find', u, found))
        m.clobber(ENTRY_BUCKET + addr_of(u)[0] if found else 0)

    def entry_stub(keyed):
        def run():
            e = arg('rdi')
            tag, mp, third = m.load(e, 8), m.load(e + 8, 8), m.load(e + 16, 8)
            if mp != state.base + 0xb0:
                w.bad.append('entry map')
            if tag == 0:
                u = ADDR_UID[addr_of(0)[:0] + bytes([0x40 + 0])] if False else None
                first = third - ENTRY_BUCKET
                u = next(x for x in range(USERS) if addr_of(x)[0] == first)
                if u not in s['known']:
                    w.bad.append('occupied entry for unknown user')
                w.log.append(('entry', u, 'occupied'))
            else:
                if tag != state.base + 0xc8:
                    w.bad.append('vacant tag')
                u = uid_at(m, e + 0x18)
                if third != 0x1000 + addr_of(u)[0] or u in s['known']:
                    w.bad.append('vacant entry')
                w.log.append(('entry', u, 'vacant'))
            if keyed and uid_at(m, arg('rsi')) != u:
                w.bad.append('keyed entry user')
            if u not in w.rows:
                w.rows[u] = m.arena(0x100)
                w.subs[u] = m.arena(0x40)
            m.clobber(w.rows[u].base)
        return run

    def inner_stub():
        row = arg('rsi') - 0xa0
        u = next(x for x, a in w.rows.items() if a.base == row)
        key = arg('rdx')
        a = w.cell('L', u, key)
        m.store(arg('rdi'), 8, a.base)
        w.log.append(('inner', u, key))
        w.touch.append(('L', u, key))
        m.clobber()

    def cell_stub():
        base = m.load(arg('rdi'), 8)
        m.clobber(base)

    def sub_stub():
        if arg('rsi') != state.base + 0x138:
            w.bad.append('sub map')
        u = uid_at(m, arg('rdx'))
        if u not in w.subs:
            w.rows.setdefault(u, m.arena(0x100))
            w.subs[u] = m.arena(0x40)
        m.store(arg('rdi'), 8, w.subs[u].base)
        w.log.append(('sub', u))
        m.clobber()

    def subrow_stub():
        base = m.load(arg('rdi'), 8)
        m.clobber(base)

    def subinner_stub():
        u = next(x for x, a in w.subs.items() if a.base == arg('rsi'))
        key = arg('rdx')
        a = w.cell('S', u, key)
        m.store(arg('rdi'), 8, a.base)
        w.log.append(('subinner', u, key))
        w.touch.append(('S', u, key))
        m.clobber()

    def hook_stub():
        if arg('rdi') != 0:
            w.bad.append('hook rdi')
        w.hooks.append(arg('rsi'))
        m.clobber()

    m.stubs = {S_HASH: hash_stub, S_FIND: find_stub, S_ENTRY: entry_stub(False), S_ENTRY_KEYED: entry_stub(True),
               S_INNER: inner_stub, S_CELL: cell_stub, S_SUB: sub_stub, S_SUBROW: subrow_stub,
               S_SUBINNER: subinner_stub, S_SCELL: cell_stub, HOOK_SLOT: hook_stub}
    m.regs[4] = stack.base + 0x3000 + 8
    for r, v in zip(('rbx', 'rbp', 'r12', 'r13', 'r14', 'r15'), (0x1111, 0x2222, 0x3333, 0x4444, 0x5555, 0x6666)):
        m.regs[R[r]] = v
    saved = list(m.regs)
    user = m.arena(0x20)
    for k, b in enumerate(addr_of(s['user'])):
        m.store(user.base + k, 1, b)
    m.regs[R['rdi']], m.regs[R['rsi']], m.regs[R['rdx']] = state.base, user.base, s['key']
    if s['fn'] == 'dist':
        out = m.arena(0x80)
        vec = m.arena(max(32 * len(s['elems']), 32))
        rec = FeeRecord.from_scenario(s)
        for off, raw in rec.words().items():
            for k, b in enumerate(raw):
                st(out, off + k, 1, b)
        if rec.rows is not None:
            st(out, 0x30, 8, vec.base)
            for i, (numer, addr) in enumerate(rec.rows):
                st(vec, 32 * i, 8, numer)
                for k, b in enumerate(addr):
                    st(vec, 32 * i + 8 + k, 1, b)
        m.regs[R['rcx']] = out.base
        entry = F_DIST
    else:
        m.regs[R['rcx']] = s['amt']
        entry = F_EXT if s['fn'] == 'ext' else F_CREDIT
    res = {'hooks': w.hooks, 'touch': w.touch, 'bad': w.bad}
    try:
        m.run(entry)
        res['status'] = 'ok'
        if m.regs[4] != saved[4] + 8:
            raise Unmodelled('stack not balanced')
        for r in ('rbx', 'rbp', 'r12', 'r13', 'r14', 'r15'):
            if m.regs[R[r]] != saved[R[r]]:
                raise Unmodelled(f'{r} not restored')
    except Panic as p:
        res['status'] = f'panic:{p.location:#x}'
    cells = {}
    for (kind, u, key), a in w.cells.items():
        for off in range(0, a.size, 8):
            cells[(kind, u, key, off)] = m.load(a.base + off, 8)
    res['cells'] = cells
    res['seen'] = m.seen
    return res


# ---------------------------------------------------------------------------------------------------------
# Closed-form model
# ---------------------------------------------------------------------------------------------------------
def f64_u64(x):
    """`(double)u64` for a non-negative integer, correctly rounded."""
    return float(x)


def u64_of_double(prod):
    """The three-step conversion of the distribution loop: inf and NaN give 0, then clamp at 2^64."""
    if math.isnan(prod) or prod == math.inf:
        prod = 0.0
    if prod > 2.0 ** 64:
        prod = 2.0 ** 64
    if prod < 0.0:
        return 0
    if prod > b2f(0x43efffffffffffff):
        return U64
    return int(prod)


SPEC = {'cutoff': 1.01, 'divisor': 100000.0, 'skip_over': True, 'sub_hooks': 2, 'order': 'LS', 'gate': 1,
        'remainder': True, 'zero_gate': True, 'saturate': True, 'ext_loc': LOC_EXT, 'ledger_order': 'pa'}


def model(s):
    out = {'status': 'ok', 'bad': []}
    mem = dict(s['init'])
    cells, touch, hooks = {}, [], []

    def get(kind, uid, key, off):
        k = (kind, uid, key, off)
        return cells[k] if k in cells else mem.get(k, default_init(kind, uid, key, off))

    def add(kind, uid, key, off, v, loc):
        old = get(kind, uid, key, off)
        if old + v > U64:
            hooks.append(loc)
        cells[(kind, uid, key, off)] = sat(old, v) if SPEC['saturate'] else (old + v) & U64

    def touch_cell(kind, uid, key):
        touch.append((kind, uid, key))
        for off in range(0, 0x30 if kind == 'L' else 8, 8):
            cells.setdefault((kind, uid, key, off), get(kind, uid, key, off))

    def credit(uid, key, amount):
        if amount == 0 and SPEC['zero_gate']:
            return
        if SPEC['order'] == 'SL':
            touch_cell('S', uid, key)
            add('S', uid, key, 0, amount, LOC_ADD)
        touch_cell('L', uid, key)
        add('L', uid, key, 8, amount, LOC_ADD)
        if SPEC['order'] == 'LS':
            touch_cell('S', uid, key)
            add('S', uid, key, 0, amount, LOC_ADD)

    key = s['key']
    if s['fn'] == 'credit':
        credit(s['user'], key, s['amt'])
    elif s['fn'] == 'ext':
        touch_cell('L', s['user'], key)
        add('L', s['user'], key, 0, s['amt'], SPEC['ext_loc'])
    else:
        touch_cell('L', s['user'], key)
        add('L', s['user'], key, 0x28, s['prot'], LOC_ADD)
        if s['flag'] == SPEC['gate']:
            t = s['gross'] - s['rebate']
            if t < 0:
                hooks.append(LOC_SUB)
                t = 0
            if t - s['prot'] < 0:
                if SPEC['sub_hooks'] == 2:
                    hooks.append(LOC_SUB)
                t = 0
            else:
                t -= s['prot']
            add('L', s['user'], key, 0x20, t, LOC_ADD)
            add('L', s['user'], key, 0x18, s['amt'], LOC_ADD)
            touch_cell('L', s['addr1'], key)
            add('L', s['addr1'], key, 8, s['amt'], LOC_ADD)
        if not s['cap_none'] and s['sec'] != 0:
            total = s['sec']
            remaining = total
            total_d = f64_u64(total)
            for numer, uid in s['elems']:
                frac = f64_u64(numer) / SPEC['divisor']
                if not frac <= SPEC['cutoff']:
                    continue
                amount = u64_of_double(frac * total_d)
                if amount > remaining and SPEC['skip_over']:
                    continue
                credit(uid, key, amount)
                remaining -= amount
            if SPEC['remainder']:
                credit(s['addr2'], key, remaining)
    out['cells'] = cells
    out['touch'] = touch
    out['hooks'] = hooks
    return out


def compare(s, got, want):
    bad = list(got['bad'])
    if got['status'] != want['status']:
        bad.append('status')
        return bad
    if got['cells'] != want['cells']:
        bad.append('cells')
    if got['hooks'] != want['hooks']:
        bad.append('hooks')
    if got['touch'] != want['touch']:
        bad.append('touch')
    return bad


# ---------------------------------------------------------------------------------------------------------
# Vectors
# ---------------------------------------------------------------------------------------------------------
SEC_AMOUNTS = (0, 1, 2, 3, 99, 100, 12345, 10 ** 5, 10 ** 6, (1 << 53) + 1, 10 ** 18, U64 - 1, U64)
NUMERS = ((), (0,), (100000,), (50000, 50000), (60000, 60000), (101000,), (101001,), (1,), (99999, 1),
          (33333, 33333, 33333), (U64,), (100000, 100000, 100000), (25000, 25000, 25000, 25000),
          (0, 0, 50000), (101000, 101000))
KEYS = (0, 5, U64)
KNOWN = (frozenset(), frozenset(range(USERS)), frozenset({0, 2, 4, 6}))
LEDGERS = ((0, 0, 0, 0, 0, 1), (1, 100, 30, 10, 77, 1), (1, 10, 30, 0, 5, 1), (1, 100, 30, 80, 6, 1))


def elems_for(numers, base=3):
    return tuple((n, base + i) for i, n in enumerate(numers))


def dist_grid():
    for key in KEYS:
        for known in KNOWN:
            for sec in SEC_AMOUNTS:
                for numers in NUMERS:
                    flag, gross, rebate, prot, amt, _ = LEDGERS[(sec + len(numers)) % len(LEDGERS)]
                    yield 'dist', scenario(key=key, known=known, sec=sec, cap_none=False, elems=elems_for(numers),
                                           flag=flag, gross=gross, rebate=rebate, prot=prot, amt=amt)


def ledger_grid():
    big = U64 - 3
    for flag in (0, 1):
        for gross, rebate, prot in ((0, 0, 0), (5, 2, 1), (5, 5, 0), (5, 6, 0), (5, 2, 4), (5, 2, 3), (5, 2, 9),
                                    (U64, 0, 0), (U64, U64, 0), (0, 0, U64), (7, 3, 4), (7, 3, 5)):
            for cap_none in (True, False):
                for amt in (0, 9):
                    yield 'ledger', scenario(flag=flag, gross=gross, rebate=rebate, prot=prot, amt=amt,
                                             cap_none=cap_none, sec=1000, elems=elems_for((70000, 20000)),
                                             known=frozenset({0, 1}))
    for off in (0x28, 0x20, 0x18, 8):
        for kind_user in (0, 1):
            init = ((('L', kind_user, 5, off), big),)
            yield 'saturate', scenario(flag=1, gross=100, rebate=1, prot=1, amt=50, init=init, cap_none=True)
            yield 'saturate', scenario(flag=1, gross=100, rebate=1, prot=1, amt=50, init=init, cap_none=True,
                                       known=frozenset({0, 1}))


def credit_grid():
    big = U64 - 3
    for fn in ('credit', 'ext'):
        for key in KEYS:
            for known in KNOWN:
                for amt in (0, 1, 3, 4, 5, U64):
                    for init in ((), ((('L', 0, key, 8), big),), ((('L', 0, key, 0), big),), ((('S', 0, key, 0), big),)):
                        yield fn, scenario(fn=fn, key=key, known=known, amt=amt, init=init)


def sweep_grid():
    """Dense sweep of one split: every fraction numerator near the cut-off against a few totals."""
    for total in (1000, 7, 10 ** 7, U64):
        for numer in list(range(0, 12)) + [99999, 100000, 100001, 100999, 101000, 101001, 101002, 200000, 2 ** 40]:
            for second in (0, 40000):
                yield 'sweep', scenario(sec=total, cap_none=False, elems=((numer, 3), (second, 4)),
                                        known=frozenset({3}))


class Lcg:
    """Small deterministic generator, so the vector list never depends on the interpreter's random module."""

    def __init__(self, seed):
        self.x = seed

    def next(self, n):
        self.x = (self.x * 6364136223846793005 + 1442695040888963407) & U64
        return (self.x >> 33) % n

    def pick(self, seq):
        return seq[self.next(len(seq))]


INTERESTING = (0, 1, 2, 3, 49999, 50000, 99999, 100000, 100001, 100999, 101000, 101001, 123456, 2 ** 32, 2 ** 40,
               2 ** 53 + 1, U64 // 3, U64 - 1, U64)
TOTALS = (0, 1, 2, 5, 17, 999, 100000, 12345678, 10 ** 12, 2 ** 53 + 1, 10 ** 18, 2 ** 63, 2 ** 64 - 4096, U64 - 1, U64)
RANDOM_COUNT = 7700


def random_grid(count=RANDOM_COUNT):
    g = Lcg(20261108)
    for _ in range(count):
        kind = g.next(10)
        key = g.pick(KEYS)
        user = g.next(USERS)
        known = frozenset(u for u in range(USERS) if g.next(3) == 0)
        init = []
        if g.next(4) == 0:
            who = g.next(USERS)
            if g.next(2):
                init.append((('L', who, key, g.pick((0, 8, 0x18, 0x20, 0x28))), U64 - g.next(6)))
            else:
                init.append((('S', who, key, 0), U64 - g.next(6)))
        if kind >= 8:
            fn = 'credit' if kind == 8 else 'ext'
            yield fn, scenario(fn=fn, key=key, user=user, known=known, amt=g.pick(INTERESTING + TOTALS),
                               init=tuple(init))
            continue
        n = g.pick((0, 1, 1, 2, 2, 3, 4, 5))
        elems = tuple((g.pick(INTERESTING) if g.next(3) else g.next(150000), g.next(USERS)) for _ in range(n))
        flag = g.next(2)
        yield 'random', scenario(key=key, user=user, known=known, init=tuple(init), flag=flag, addr1=g.next(USERS),
                                 gross=g.pick(INTERESTING), rebate=g.pick(INTERESTING), prot=g.pick(INTERESTING),
                                 amt=g.pick(INTERESTING + TOTALS), cap_none=g.next(5) == 0, elems=elems,
                                 sec=g.pick(TOTALS), addr2=g.next(USERS))


def all_vectors():
    for grid in (dist_grid, ledger_grid, credit_grid, sweep_grid, random_grid):
        yield from grid()


# ---------------------------------------------------------------------------------------------------------
# Static facts
# ---------------------------------------------------------------------------------------------------------
def path_tail(raw):
    k = raw.find(b'l1/src/')
    if k == -1:
        raise EvidenceError(f'unexpected path {raw[-24:]!r}')
    return raw[k:].decode()


def decode_location(img, va):
    path = img.relative(va)
    size = img.u64(va + 8)
    line, col = struct.unpack('<II', img.read(va + 16, 8))
    return {'va': hex(va), 'path': path_tail(img.read(path, size)), 'line': line, 'column': col}


def callers(img, fdes, target):
    """Functions with a direct `call rel32` (e8) to `target`, from the byte pattern."""
    text_va, text = img.text()
    out, i = set(), text.find(b'\xe8')
    while i != -1:
        if i + 5 <= len(text) and text_va + i + 5 + struct.unpack_from('<i', text, i + 1)[0] == target:
            try:
                out.add(fdes.range_of(text_va + i)['start'])
            except EvidenceError:
                pass
        i = text.find(b'\xe8', i + 1)
    return sorted(out)


def slot_callers(img, fdes, slot):
    text_va, text = img.text()
    out, i = set(), text.find(b'\xff\x15')
    while i != -1:
        if i + 6 <= len(text) and text_va + i + 6 + struct.unpack_from('<i', text, i + 2)[0] == slot:
            out.add(fdes.range_of(text_va + i)['start'])
        i = text.find(b'\xff\x15', i + 1)
    return sorted(out)


def decode_all(img, fdes):
    insns = []
    for fn in SUBJECTS:
        r = fdes.range_of(fn)
        if r['start'] != fn:
            raise EvidenceError(f'{fn:#x} is not an FDE start')
        insns += decode_range(img, r['start'], r['end'])
    return insns


def constants(img):
    c = {k: img.f64(v) for k, v in CONST.items() if k not in ('punpck',)}
    if (c['one_e5'], c['cutoff'], c['two64'], c['two63']) != (100000.0, 1.01, 2.0 ** 64, 2.0 ** 63):
        raise EvidenceError(f'constants differ: {c}')
    if img.u64(CONST['two64_minus_2048']) != 0x43efffffffffffff or img.u64(CONST['punpck']) != 0x4530000043300000:
        raise EvidenceError('conversion constants differ')
    if img.u64(CONST['subpd']) != 0x4330000000000000 or img.u64(CONST['subpd'] + 8) != 0x4530000000000000:
        raise EvidenceError('subpd constants differ')
    return c


def sites(insns):
    """Hook calls (indirect through the slot) and the location lea before each, from decoded operands."""
    out = []
    for k, ins in enumerate(insns):
        if ins.op == 'call' and ins.ops[0][0] == 'm' and ins.ops[0][1] is None and ins.ops[0][4] == HOOK_SLOT:
            lea = next((x for x in reversed(insns[max(0, k - 6):k]) if x.op == 'lea' and x.ops[0][1] == R['rsi']), None)
            if lea is None:
                raise EvidenceError(f'{ins.va:#x}: hook without location')
            out.append((ins.va, lea.ops[1][4]))
    return out


# ---------------------------------------------------------------------------------------------------------
# Controls: byte mutants of the subjects, a wrong model, corrupted inputs
# ---------------------------------------------------------------------------------------------------------
def mutant_patches(insns):
    """Deterministic one-byte changes to the subjects: inverted conditions, bumped immediates and displacements."""
    out = []
    for ins in insns:
        raw = ins.raw
        if ins.op[0] == 'j' and ins.op != 'jmp':
            at = raw.index(0x0f) + 1 if raw[0] in (0x0f, 0x66) else 0
            out.append((f'invert {ins.op} at {ins.va:#x}', {ins.va + at: raw[at] ^ 1}))
        elif ins.op.startswith('cmov'):
            at = raw.index(0x0f) + 1
            out.append((f'invert {ins.op} at {ins.va:#x}', {ins.va + at: raw[at] ^ 1}))
        elif ins.op in ('add', 'sub', 'cmp') and raw[0] in (0x48, 0x49, 0x4c, 0x4d, 0x83) and ins.ops[1][0] == 'i' \
                and 0x83 in raw[:2] and len(raw) in (4, 5):
            out.append((f'bump immediate of {ins.op} at {ins.va:#x}', {ins.va + len(raw) - 1: (raw[-1] + 1) & 0xff}))
        elif ins.op in ('mov', 'add', 'sub', 'cmp', 'lea') and ins.ops and not any(o[0] == 'i' for o in ins.ops):
            mems = [o for o in ins.ops if o[0] == 'm' and o[1] is not None and -128 <= o[4] < 128 and o[4] != 0]
            if mems and (mems[0][4] & 0xff) == raw[-1] and raw[-2] >> 6 in (1, 0x40 >> 6) or \
                    (mems and (mems[0][4] & 0xff) == raw[-1] and (raw[-2] & 0xc0) == 0x40):
                out.append((f'displacement of {ins.op} at {ins.va:#x}', {ins.va + len(raw) - 1: (raw[-1] + 8) & 0xff}))
    return out


def run_subset(img, insns, vectors):
    for group, s in vectors:
        try:
            got = evaluate(img, insns, s)
            if compare(s, got, model(s)):
                return group
        except (Unmodelled, EvidenceError, StopIteration, KeyError):
            return group
    return None


# ---------------------------------------------------------------------------------------------------------
# Reconstruction: the same behaviour as plain Python objects, written from the decoded instructions
# ---------------------------------------------------------------------------------------------------------
def bits_to_double(bits):
    return struct.unpack('<d', struct.pack('<Q', bits))[0]


def double_to_bits(x):
    return struct.unpack('<Q', struct.pack('<d', x))[0]


def u64_to_double(x):
    """`(double)u64` as the code computes it: punpckldq with 0x4330000045300000, subpd with (2^52, 2^84), addsd."""
    lo = bits_to_double(0x4330000000000000 | (x & 0xffffffff))
    hi = bits_to_double(0x4530000000000000 | (x >> 32))
    return (hi - 2.0 ** 84) + (lo - 2.0 ** 52)


def truncate_to_i64(x):
    """cvttsd2si r64, xmm: the indefinite value 0x8000000000000000 for NaN and out-of-range input."""
    if math.isnan(x) or math.isinf(x) or not -(2.0 ** 63) <= x < 2.0 ** 63:
        return 1 << 63
    return int(x) & U64


def double_to_u64(p):
    """The conversion of the distribution loop, step by step as the instructions do it."""
    if p == math.inf or math.isnan(p):
        p = 0.0
    if p > 2.0 ** 64:
        p = 2.0 ** 64
    first = truncate_to_i64(p)
    mask = U64 if first >> 63 else 0                           # sar r9, 63
    second = truncate_to_i64(p - 2.0 ** 63)
    out = (second & mask) | first
    if p < 0.0 or math.isnan(p):
        out = 0
    if p > bits_to_double(0x43efffffffffffff):
        out = U64
    return out


class FeeRecord:
    """The 0x78-byte record read by 0x3c1ae50; absent parts stay unwritten in the byte form."""

    def __init__(self, flag, amount, recipient, rows, total, destination, gross, rebate, protocol):
        self.flag, self.amount, self.recipient = flag, amount, recipient
        self.rows, self.total, self.destination = rows, total, destination
        self.gross, self.rebate, self.protocol = gross, rebate, protocol

    def from_scenario(s):                       # called on the class, never on an instance
        rows = None if s['cap_none'] else [(n, addr_of(u)) for n, u in s['elems']]
        return FeeRecord(s['flag'], s['amt'] if s['flag'] == 1 else None,
                         addr_of(s['addr1']) if s['flag'] == 1 else None, rows,
                         None if rows is None else s['sec'], None if rows is None else addr_of(s['addr2']),
                         s['gross'], s['rebate'], s['prot'])

    def parse(read, base):                      # called on the class, never on an instance
        """Rebuild a record from memory through `read(address, size)`, touching only the parts the code reads."""
        word = lambda off: int.from_bytes(read(base + off, 8), 'little')      # noqa: E731
        flag = word(0)
        amount = recipient = None
        if flag == 1:
            amount, recipient = word(8), read(base + 0x10, 20)
        rows = total = destination = None
        if word(0x28) != NONE:
            count, pointer = word(0x38), word(0x30)
            rows = [(int.from_bytes(read(pointer + 32 * i, 8), 'little'), read(pointer + 32 * i + 8, 20))
                    for i in range(count)]
            total, destination = word(0x40), read(base + 0x48, 20)
        return FeeRecord(flag, amount, recipient, rows, total, destination, word(0x60), word(0x68), word(0x70))

    def same_as(self, other):
        return all(getattr(self, k) == getattr(other, k) for k in
                   ('flag', 'amount', 'recipient', 'rows', 'total', 'destination', 'gross', 'rebate', 'protocol'))

    def words(self):
        """Offset -> bytes of the parts that exist; the list pointer is filled by the caller."""
        out = {0x00: self.flag.to_bytes(8, 'little'), 0x60: self.gross.to_bytes(8, 'little'),
               0x68: self.rebate.to_bytes(8, 'little'), 0x70: self.protocol.to_bytes(8, 'little')}
        if self.flag == 1:
            out[0x08] = self.amount.to_bytes(8, 'little')
            out[0x10] = self.recipient
        out[0x28] = (NONE if self.rows is None else len(self.rows)).to_bytes(8, 'little')
        if self.rows is not None:
            out[0x38] = len(self.rows).to_bytes(8, 'little')
            out[0x40] = self.total.to_bytes(8, 'little')
            out[0x48] = self.destination
        return out


class Ledger:
    """Rows keyed by address, cells keyed by (address, key), second map of u64 totals; saturating adds with hooks."""

    def __init__(self, init):
        self.init, self.cells, self.totals, self.touch, self.hooks = dict(init), {}, {}, [], []
        self.steps = []

    def word(self, kind, addr, key, off):
        uid = ADDR_UID[addr]
        return self.init.get((kind, uid, key, off), default_init(kind, uid, key, off))

    def cell(self, addr, key):
        k = ('L', ADDR_UID[addr], key)
        if k not in self.cells:
            self.cells[k] = {off: self.word('L', addr, key, off) for off in range(0, 0x30, 8)}
        self.touch.append(k)
        return self.cells[k]

    def total(self, addr, key):
        k = ('S', ADDR_UID[addr], key)
        if k not in self.totals:
            self.totals[k] = {0: self.word('S', addr, key, 0)}
        self.touch.append(k)
        return self.totals[k]

    def add(self, words, off, value, location):
        total = words[off] + value
        if total > U64:
            self.hooks.append(location)
        words[off] = min(total, U64)
        self.steps.append((off, value, words[off], total > U64))

    def credit(self, addr, key, amount):
        if amount == 0:
            return
        self.add(self.cell(addr, key), 8, amount, LOC_ADD)
        self.add(self.total(addr, key), 0, amount, LOC_ADD)

    def extra_credit(self, addr, key, amount):
        self.add(self.cell(addr, key), 0, amount, LOC_EXT)

    def distribute(self, user, key, rec):
        mine = self.cell(user, key)
        self.add(mine, 0x28, rec.protocol, LOC_ADD)
        if rec.flag == 1:
            net = rec.gross
            for taken in (rec.rebate, rec.protocol):
                if net < taken:
                    self.hooks.append(LOC_SUB)
                    net = 0
                else:
                    net -= taken
            self.add(mine, 0x20, net, LOC_ADD)
            self.add(mine, 0x18, rec.amount, LOC_ADD)
            self.add(self.cell(rec.recipient, key), 8, rec.amount, LOC_ADD)
        if rec.rows is None or rec.total == 0:
            return
        remaining = rec.total
        scale = u64_to_double(rec.total)
        for numerator, addr in rec.rows:
            fraction = u64_to_double(numerator) / 100000.0
            if not fraction <= 1.01:
                continue
            amount = double_to_u64(fraction * scale)
            if amount > remaining:
                continue
            self.credit(addr, key, amount)
            remaining -= amount
        self.credit(rec.destination, key, remaining)


def ledger_result(s):
    """Run the reconstruction on scenario `s`; same shape as model()."""
    led = Ledger(s['init'])
    user, key = addr_of(s['user']), s['key']
    if s['fn'] == 'credit':
        led.credit(user, key, s['amt'])
    elif s['fn'] == 'ext':
        led.extra_credit(user, key, s['amt'])
    else:
        led.distribute(user, key, FeeRecord.from_scenario(s))
    cells = {}
    for (kind, uid, k), words in list(led.cells.items()) + list(led.totals.items()):
        for off, v in words.items():
            cells[(kind, uid, k, off)] = v
    return {'cells': cells, 'touch': led.touch, 'hooks': led.hooks}


def explain(s):
    """Plain-language steps of the reconstruction for scenario `s`, one line per ledger word written."""
    led = Ledger(s['init'])
    user, key = addr_of(s['user']), s['key']
    if s['fn'] == 'credit':
        led.credit(user, key, s['amt'])
    elif s['fn'] == 'ext':
        led.extra_credit(user, key, s['amt'])
    else:
        led.distribute(user, key, FeeRecord.from_scenario(s))
    lines = []
    for off, value, new, carried in led.steps:
        lines.append(f'word +{off:#x} += {value} -> {new}' + (' (carry: hook, then u64::MAX)' if carried else ''))
    lines += [f'borrow hook at {loc:#x}' for loc in led.hooks if loc == LOC_SUB]
    return lines


WRONG_SPECS = (
    ('cutoff 1.02', {'cutoff': 1.02}), ('cutoff 1.0', {'cutoff': 1.0}), ('divisor 1e6', {'divisor': 1e6}),
    ('divisor 1e4', {'divisor': 1e4}), ('credit sees amounts over the remainder', {'skip_over': False}),
    ('one borrow hook', {'sub_hooks': 1}), ('sub-map credited first', {'order': 'SL'}),
    ('ledger gate on flag 0', {'gate': 0}), ('remainder not credited', {'remainder': False}),
    ('zero amounts credited', {'zero_gate': False}), ('wrapping adds', {'saturate': False}),
    ('wrong hook location for the extra credit', {'ext_loc': LOC_ADD}),
)


def sample(vectors, step, offset=0):
    return [v for i, v in enumerate(vectors) if i % step == offset]


def control_set(vectors):
    """Vectors used for the controls: every 9th of the standard set plus all edge-case groups."""
    edge = [v for v in vectors if v[0] in ('saturate', 'sweep', 'ledger')]
    return edge + sample(vectors, 9)


def survey(data, vectors):
    """Run byte mutants; returns rows (name, outcome) with outcome 'killed:<group>' or 'survived'."""
    img0 = Image(data)
    fdes = Fdes(img0)
    insns = decode_all(img0, fdes)
    rows = []
    extra = [(f'flip a mantissa bit of constant {k} at {v:#x}', {v + 6: data[img0.off(v + 6)] ^ 1})
             for k, v in sorted(CONST.items(), key=lambda kv: kv[1]) if k != 'inf']
    extra += [(f'flip a bit of the second half of constant {k} at {v + 8:#x}', {v + 14: data[img0.off(v + 14)] ^ 1})
              for k, v in sorted(CONST.items()) if k in ('punpck', 'subpd')]
    for name, patch in mutant_patches(insns) + extra:
        img = Image(data, patch)
        try:
            mut = decode_all(img, fdes)
        except (EvidenceError, IndexError):
            rows.append((name, 'killed:decode'))
            continue
        hit = run_subset(img, mut, vectors)
        rows.append((name, f'killed:{hit}' if hit else 'survived'))
    return rows


def wrong_spec_rows(img, insns, vectors):
    rows = []
    for name, change in WRONG_SPECS:
        old = {k: SPEC[k] for k in change}
        SPEC.update(change)
        try:
            hit = None
            for group, s in vectors:
                got = evaluate(img, insns, s)
                if compare(s, got, model(s)):
                    hit = group
                    break
        finally:
            SPEC.update(old)
        rows.append((name, f'killed:{hit}' if hit else 'survived'))
    return rows


def input_control_rows(data):
    """Corrupted inputs that must be refused: wrong digest, wrong FDE start, out of image, bad opcode, bad pointer."""
    rows = []

    def refused(name, fn):
        try:
            fn()
        except (EvidenceError, Unmodelled, IndexError, KeyError, struct.error):
            rows.append((name, 'killed:refused'))
        else:
            rows.append((name, 'survived'))

    bad = bytearray(data)
    bad[-1] ^= 1
    refused('one byte flipped at the end of the file', lambda: check_digest(bytes(bad)))
    refused('digest of an empty input', lambda: check_digest(b''))
    img = Image(data)
    fdes = Fdes(img)
    refused('subject is not an FDE start', lambda: decode_all_one(img, fdes, F_CREDIT + 4))
    refused('address outside every section', lambda: img.read(0x10, 4))
    refused('address in .bss', lambda: img.read(img.sec['.bss'][0] + 8, 8) if '.bss' in img.sec else (_ for _ in ()).throw(EvidenceError('no .bss')))
    refused('relocation slot not present', lambda: img.relative(0x10))
    refused('unlisted opcode', lambda: decode_one(b'\x06\x00\x00\x00\x00\x00\x00\x00\x00', 0, 0x1000))
    refused('truncated ULEB128', lambda: uleb(b'\x80', 0))
    refused('wrong constant: cutoff patched', lambda: constants(Image(data, {CONST['cutoff'] + 6: 0xf1})))
    refused('wrong constant: divisor patched', lambda: constants(Image(data, {CONST['one_e5'] + 5: 0x00})))
    refused('conversion constant patched', lambda: constants(Image(data, {CONST['two64_minus_2048']: 0x00})))
    return rows


def decode_all_one(img, fdes, va):
    r = fdes.range_of(va)
    if r['start'] != va:
        raise EvidenceError('not an FDE start')


def analyse(data, patches=None, vectors=all_vectors, controls=True):
    digest = check_digest(data)
    img = Image(data, patches)
    fdes = Fdes(img)
    insns = decode_all(img, fdes)
    c = constants(img)
    hooks = sites(insns)
    rows, groups, failures, statuses = [], Counter(), [], Counter()
    seen = set()
    vec_list = []
    for group, s in vectors():
        got = evaluate(img, insns, s)
        want = model(s)
        bad = compare(s, got, want)
        alt = ledger_result(s)
        if (alt['cells'], alt['touch'], alt['hooks']) != (got['cells'], got['touch'], got['hooks']):
            bad.append('reconstruction')
        groups[group] += 1
        statuses[got['status']] += 1
        seen |= got['seen']
        if bad:
            failures.append({'group': group, 'fields': bad, 'key': s['key']})
        vec_list.append((group, s))
        rows.append(row_text(group, s, got, len(vec_list) - 1))
    if failures:
        raise EvidenceError(f'{len(failures)} vectors disagree; first {failures[0]}')
    missed = [i for i in insns if i.va not in seen]
    result = {
        'component': 'fees', 'binary': GROUND, 'sha256': digest, 'coordinates': 'virtual addresses (ELF VA)',
        'question': 'fee credit distribution 0x3c1ae50, credit 0x3c1a250, extra credit 0x3c1a3f0',
        'fde_table_entries': fdes.count,
        'subjects': {hex(f): {'start': hex(fdes.range_of(f)['start']), 'end': hex(fdes.range_of(f)['end']),
                              'size': fdes.range_of(f)['end'] - fdes.range_of(f)['start'],
                              'direct_callers': [hex(x) for x in callers(img, fdes, f)],
                              'slot_callers': []} for f in SUBJECTS},
        'helpers_stubbed': {hex(v): n for n, v in (('hash', S_HASH), ('find', S_FIND), ('entry', S_ENTRY),
                                                  ('entry_keyed', S_ENTRY_KEYED), ('inner', S_INNER),
                                                  ('cell', S_CELL), ('sub', S_SUB), ('subrow', S_SUBROW),
                                                  ('subinner', S_SUBINNER), ('scell', S_SCELL))},
        'hook_slot': hex(HOOK_SLOT),
        'hook_slot_callers_in_subjects': [{'va': hex(v), 'location': hex(loc)} for v, loc in hooks],
        'locations': {hex(v): decode_location(img, v) for v in (LOC_ADD, LOC_SUB, LOC_EXT)},
        'constants': {k: (c[k] if k != 'inf' else 'inf') for k in sorted(c)},
        'instructions': len(insns),
        'evaluation': {'vectors': sum(groups.values()), 'groups': dict(sorted(groups.items())),
                       'status': dict(sorted(statuses.items())), 'mismatches': 0,
                       'instructions_executed': len(insns) - len(missed),
                       'instructions_not_executed': [{'va': hex(i.va), 'op': i.op} for i in missed],
                       'all_rows_sha256': hashlib.sha256('\n'.join(rows).encode()).hexdigest()},
    }
    ctl = []
    if controls:
        sub = control_set(vec_list)
        ctl = survey(data, sub) + wrong_spec_rows(img, insns, sub) + input_control_rows(data)
    EQUIVALENT = {
        'flip a mantissa bit of constant two64 at 0x459090':
            'equivalent: the clamp value only matters above 2^64 - 2048, where the next compare returns u64::MAX anyway',
        'flip a bit of the second half of constant punpck at 0x451218':
            'equivalent: punpckldq reads only the low 8 bytes of its memory operand',
    }
    ctl = [(n, EQUIVALENT.get(n, o) if o == 'survived' else o) for n, o in ctl]
    unexplained = [n for n, o in ctl if o == 'survived']
    if unexplained:
        raise EvidenceError(f'unexplained survivors: {unexplained}')
    result['controls'] = {
        'mutant_vectors': len(control_set(vec_list)) if controls else 0,
        'killed': sum(o.startswith('killed') for _, o in ctl), 'equivalent_survivors': sum(o.startswith('equivalent') for _, o in ctl),
    }
    return result, img, insns, rows, ctl


def row_text(group, s, got, index):
    cells = got['cells']
    digest = hashlib.sha256(repr(sorted(cells.items())).encode()).hexdigest()[:12]
    return '\t'.join(str(v) for v in (index, group, s['fn'] if group in ('credit', 'ext') else 'dist', s['key'],
                                      s['sec'], len(s['elems']), got['status'], len(got['hooks']),
                                      len(got['touch']), digest))


def write(out, result, img, insns, rows, ctl):
    out.mkdir(parents=True, exist_ok=True)
    (out / 'evidence.json').write_text(json.dumps(result, indent=2, sort_keys=True) + '\n')
    lines = ['va\tsize\tbytes\tdecoded'] + [f'{i.va:#x}\t{i.size}\t{i.raw.hex()}\t{show(i)}' for i in insns]
    (out / 'instructions.tsv').write_text('\n'.join(lines) + '\n')
    head = 'index\tgroup\tfn\tkey\tsecondary_total\tfractions\tstatus\thooks\tcell_touches\tfinal_cells_sha12'
    keep = [r for r in rows if int(r.split('\t')[0]) % 7 in (0, 3)]
    (out / 'vectors.tsv').write_text('\n'.join([head] + keep) + '\n')
    lines = ['control\toutcome'] + [f'{n}\t{o}' for n, o in ctl]
    (out / 'controls.tsv').write_text('\n'.join(lines) + '\n')
    killed = sum(o.startswith('killed') for _, o in ctl)
    survivors = sum(o.startswith('equivalent') for _, o in ctl)
    measure = {'cases': result['evaluation']['vectors'], 'negative_controls': killed,
               'negative_detected': killed, 'equivalent_survivors_listed_apart': survivors}
    (out / 'measure.json').write_text(json.dumps(measure, indent=2, sort_keys=True) + '\n')


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument('--out', required=True, type=Path)
    ap.add_argument('--binary', type=Path, default=ROOT / GROUND)
    args = ap.parse_args(argv)
    try:
        data = args.binary.read_bytes()
        result, img, insns, rows, ctl = analyse(data)
    except (EvidenceError, Unmodelled, OSError) as exc:
        print(f'error: {exc}', file=sys.stderr)
        return 1
    write(args.out, result, img, insns, rows, ctl)
    print(json.dumps({'vectors': result['evaluation']['vectors'], 'instructions': result['instructions'],
                      'controls': result['controls']}, sort_keys=True))
    return 0


if __name__ == '__main__':
    sys.exit(main())
