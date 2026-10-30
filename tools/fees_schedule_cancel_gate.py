#!/usr/bin/env python3
"""fees: node #94 gate behind the scaled_vlm.rs and raw_vlm.rs overflow records, from bytes alone.

Static, no execution of the node.  Three copies of one function are decoded from their
ELF bytes by the small table decoder below, which must land exactly on each FDE end.
The decoded instructions, the real chrono helpers they call and the real map entry
insert are interpreted in Python; only the volume lookups, the overflow hook, memcmp,
the allocator, the node insert and the formatter are stubs.  Each outcome is compared
with a separate closed-form model.

    python3 tools/fees_schedule_cancel_gate.py --out <dir>

writes evidence.json, instructions.tsv and vectors.tsv.  Only the standard library is
used: no objdump, readelf or other external program runs, so the results cannot depend
on a binutils version.
"""

import argparse
import bisect
import hashlib
import json
import math
import re
import struct
import sys
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
BINARY = 'artifacts/node/94/hl-node'
SHA256 = '3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f'
U64 = (1 << 64) - 1

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
        v = imm(8 if w else 4)
        val = v[1] & (U64 if w else 0xffffffff)
        return done('mov', (gpr(b & 7 | rb << 3, width), ('i', val)))
    if b == 0xc1:
        reg, rm = modrm(width)
        v = imm(1)
        if reg not in (4, 5, 7):
            raise EvidenceError(f'{va:#x}: unlisted shift /{reg}')
        return done({4: 'shl', 5: 'shr', 7: 'sar'}[reg], (rm, ('i', v[1] & 0xff)))
    if b == 0xd1:
        reg, rm = modrm(width)
        if reg not in (4, 5, 7):
            raise EvidenceError(f'{va:#x}: unlisted shift /{reg}')
        return done({4: 'shl', 5: 'shr', 7: 'sar'}[reg], (rm, ('i', 1)))
    if b == 0xc3:
        return done('ret', ())
    if b == 0xcc:
        return done('int3', ())
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
        if reg:
            raise EvidenceError(f'{va:#x}: unlisted f6 /{reg}')
        return done('test', (rm, imm(1)), 8)
    if b == 0xf7:
        reg, rm = modrm(width)
        if reg == 0:
            return done('test', (rm, imm(4)))
        if reg not in (2, 3, 4, 5):
            raise EvidenceError(f'{va:#x}: unlisted f7 /{reg}')
        return done({2: 'not', 3: 'neg', 4: 'mul', 5: 'imul1'}[reg], (rm,))
    if b == 0xff:
        reg, rm = modrm(width)
        if reg in (0, 1):
            return done('dec' if reg else 'inc', (rm,))
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
        self.real = {}
        self.got = {}
        self.seen = set()
        self.taken = {}

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
        if addr in self.got:
            return self.got[addr]
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
            elif ops[0][0] == 'm' and ops[1][0] == 'x':
                self.store(self.ea(ops[0]), 8, self.xmm[ops[1][1]][0])
            else:
                raise Unmodelled(f'{ins.va:#x}: movsd form')
        elif op in ('xorps', 'xorpd'):
            if ops[0] != ops[1]:
                raise Unmodelled(f'{ins.va:#x}: xor of two registers')
            self.xmm[ops[0][1]] = [0, 0]
        elif op == 'cvtsi2sd':
            self.xmm[ops[0][1]][0] = f2b(float(signed(self.rd(ops[1]), ins.width)))
        elif op == 'movq':
            self.wr(ops[0], self.xmm[ops[1][1]][0])
        elif op == 'mulsd':
            self.xmm[ops[0][1]][0] = f2b(b2f(self.xmm[ops[0][1]][0]) * b2f(self.xrd64(ops[1])))
        elif op == 'divsd':
            d = b2f(self.xrd64(ops[1]))
            if d == 0.0:
                raise Unmodelled(f'{ins.va:#x}: division by zero')
            self.xmm[ops[0][1]][0] = f2b(b2f(self.xmm[ops[0][1]][0]) / d)
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
        target = o[1] if o[0] == 't' else self.rd(o) if o[0] == 'r' else self.ea(o)
        if target in self.real:
            self.regs[4] -= 8
            self.store(self.regs[4], 8, ins.va + ins.size)
            self.run(self.real[target])
            return
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
                go = self.cond(op[1:])
                self.taken.setdefault(rip, set()).add(go)
                if go:
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
            elif op == 'imul1':
                full = signed(self.rd(ops[0]), 64) * signed(self.regs[0], 64)
                self.regs[0] = full & U64
                self.regs[2] = (full >> 64) & U64
                self.cf = self.of = full != signed(full & U64, 64)
            elif op == 'not':
                self.wr(ops[0], ~self.rd(ops[0]))
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
                n = ops[1][1] & 63
                a = self.rd(ops[0])
                if op == 'sar':
                    res = (signed(a, ins.width) >> n) & ((1 << ins.width) - 1)
                else:
                    res = (a << n if op == 'shl' else a >> n) & ((1 << ins.width) - 1)
                self.nz(res, ins.width)
                self.wr(ops[0], res)
            elif op == 'call':
                self.call(ins)
            else:
                self.do_sse(ins)
            rip = nxt
        raise Unmodelled('step limit')



GATE_A = 0x2721260
HOOK_SLOT = 0x5773190
BASE_LOOKUP_SLOT = 0x5773170
DEX_LOOKUP = 0x36f57f0
FROM_DAYS_SLOT, TIME_ADD_SLOT, DATE_ADD_SLOT = 0x576e890, 0x576e8a8, 0x576e8b0
ERR_HELPER = 0x14509a0
MEMCMP_SLOT = 0x576e488
ALLOC_SLOT = 0x576dfd8
PANIC_SLOT = 0x576e468
FORMAT_SLOT, ERR_BOX = 0x576e040, 0x14b5530
ERR_ARG_SLOT = 0x576ea30
ADD_LOCATION, SCALED_LOCATION, RAW_LOCATION, TIME_LOCATION = 0x5715e68, 0x56eb3e8, 0x56eb430, 0x566af18
ONE_HUNDRED_VA = 0x20a960
PANIC_TEXT_VA, PANIC_TEXT_LEN = 0x21a01f, 0x26
RANGE_TEXT_VA = 0x1e1152
DISPLAY_FN, DISPLAY_TABLE = 0x37ffd40, 0x59a8d0

THRESHOLD = 100_000_000
STEP_SECONDS = 5
COUNT_LIMIT = 9
WRAPPER_MAX = 0xccccccccccccccb
MS_DIV_1000 = (0x20c49ba5e353f7cf, 3, 4)
MS_DIV_DAY = (0x31b5d43afe99ef, 10, 6)
SEC_DIV_DAY = (0x308b91419ca253, 0, 6)
DAYS_LIMIT = 0x7ff506c5
CE_OFFSET = 719163
SECONDS_DIV_DAY = 0x1845c8a0ce512957
TAG_RANGE, TAG_EARLY, TAG_COUNT, TAG_VOLUME, TAG_OK, TAG_WRAPPER = 0x85, 0x10c, 0x10d, 0x10e, 0x186, 0x13f
RESULT_OK, RESULT_ERR = 0xd, 0xe

CHAINS = {
    'a': dict(wrapper=0x1e5fc40, gate=0x2721260, insert=0x2878880, dex_ptr=0x5c0, dex_len=0x5c8, map=0x39a8),
    'b': dict(wrapper=0x4bffbc0, gate=0x4d260c0, insert=0x49560c0, dex_ptr=0x5c0, dex_len=0x5c8, map=0x39a8),
    'c': dict(wrapper=0x4bffc70, gate=0x4d266c0, insert=0x49560c0, dex_ptr=0x1040, dex_len=0x1048, map=0x4428),
}
DEX_STRIDE, DEX_MAP = 0x2f0, 0xf8
BASE_MAP = 0x80
DEX_SCALED, DEX_RAW = 0x40, 0x48
NOW = 0x60
NODE_VALS, NODE_KEYS, NODE_PARENT, NODE_LEN, NODE_EDGES = 8, 0x110, 0x1ec, 0x1ee, 0x1f0
VAL_SIZE, KEY_SIZE, NODE_CAP = 0x18, 0x14, 11
USERS = [bytes([0x10 * k + 1]) + bytes(19) for k in range(1, 15)]
ME = bytes([0x41]) + bytes(19)
COUNT_LIMIT_ARG_VA = 0x20ac78

REFERENCE_ROWS = (
    ('l1/scaled_vlm.rs:55', 'DAILY_UPDATE_DELAY_DAYS = 5, a five-day chrono delta',
     '5 is the seconds field of the TimeDelta in edx; a deadline must be later than now + 5 s'),
    ('l1/scaled_vlm.rs:51', 'MAX_DAILY_SCALED_VLM_ENTRIES = 10, len of a per-user date map',
     'compare is on the first u64 of one map value keyed by a 20-byte user; this function never writes that u64'),
    ('l1/scaled_vlm.rs:47', 'MIN_DAILY_UPDATE_SCALED_VLM = 100000000, a daily-volume update gate',
     'same number; the gated action is scheduleCancel and the message prints Required: $ with 1000000.0'),
    ('l1/scaled_vlm.rs:156', 'shortfall value (scaled as i32 as f64) / 100.0',
     'cvtsi2sd is 64-bit; no reachable difference because the value is below 100000000'),
    ('l1/scaled_vlm.rs:409', 'clear_user clears the per-user date map',
     'only the date dword of the entry becomes 0; the entry, its count and its time fields stay'),
    ('l1/exchange/handlers/18_schedule_cancel.rs:138', 'rejects when deadline_ms <= now_ms',
     'rejects when the deadline is not later than now + 5 s'),
    ('l1/exchange/handlers/18_schedule_cancel.rs:148', 'stores the raw deadline in two u32 words',
     'stores chrono date dword, seconds of day and nanoseconds'),
    ('l1/exchange/handlers/18_schedule_cancel.rs:160', 'representable when day >= 2146764485 and <= u32 max',
     'days below 0x7ff506c5 pass the guard and the real date helper then limits them to 262142-12-31'),
    ('l1/exchange/handlers/18_schedule_cancel.rs:20', 'result codes 390, 319, 268, 269, 270, 133',
     'same six values; 319 prints Invalid input number and 133 prints Cannot create Time from input'),
)

# Reached only if the helper at ERR_HELPER returned tag 0: it has no branch and always writes 1.
UNREACHED_GATE = ((0x592, 0x59c, 'caller of ERR_HELPER: the tag-0 arm; the helper is linear and always writes tag 1'),)
UNREACHED_INSERT = ((0x145, 0x16e, 'allocation failure and full-node panic in the empty-map arm'),)


def tree_walk(m, node, height):
    """Every (key, value bytes) in order, read back from arena memory without the code under test."""
    out = []
    n = m.load(node + NODE_LEN, 2)
    for k in range(n + 1):
        if height:
            out += tree_walk(m, m.load(node + NODE_EDGES + 8 * k, 8), height - 1)
        if k < n:
            key = m.load(node + NODE_KEYS + KEY_SIZE * k, KEY_SIZE).to_bytes(KEY_SIZE, 'little')
            base = node + NODE_VALS + VAL_SIZE * k
            out.append((key, (m.load(base, 8), m.load(base + 8, 4), m.load(base + 12, 4), m.load(base + 16, 4))))
    return out


def make_node(m, height, keys, vals, edges):
    a = m.arena(NODE_EDGES + (8 * (NODE_CAP + 1) if height else 0))
    m.store(a.base + NODE_LEN, 2, len(keys))
    for k, (key, val) in enumerate(zip(keys, vals)):
        m.store(a.base + NODE_KEYS + KEY_SIZE * k, KEY_SIZE, int.from_bytes(key, 'little'))
        base = a.base + NODE_VALS + VAL_SIZE * k
        for off, size, v in ((0, 8, val[0]), (8, 4, val[1]), (12, 4, val[2]), (16, 4, val[3])):
            m.store(base + off, size, v)
    for k, e in enumerate(edges):
        m.store(a.base + NODE_EDGES + 8 * k, 8, e)
    return a.base


def make_tree(m, spec, val_of):
    """spec: None, a list of keys (leaf) or a tuple (keys, [child specs]). Returns (root, height)."""
    if spec is None:
        return 0, 0
    if isinstance(spec, list):
        return make_node(m, 0, spec, [val_of(k) for k in spec], ()), 0
    keys, kids = spec
    made = [make_tree(m, c, val_of) for c in kids]
    height = made[0][1] + 1
    return make_node(m, height, keys, [val_of(k) for k in keys], [r for r, _ in made]), height


def spec_keys(spec):
    if spec is None:
        return []
    if isinstance(spec, list):
        return list(spec)
    keys, kids = spec
    out = []
    for k, c in enumerate(kids):
        out += spec_keys(c)
        if k < len(keys):
            out.append(keys[k])
    return out


def run_real(m, target):
    m.regs[4] -= 8
    m.store(m.regs[4], 8, 0xfeedfacecafe)
    m.run(target)


def pack_date(img, code, ce):
    m = Machine(img, ())
    m.code = code
    m.regs[4] = m.arena(0x1000, False).base + 0x800
    m.regs[R['rdi']] = ce
    run_real(m, FN_FROM_DAYS(img))
    return m.regs[0] & 0xffffffff


def FN_FROM_DAYS(img):
    return img.relative(FROM_DAYS_SLOT)


def scenario(**kw):
    s = dict(dex=(), base=(0, 0), flag=1, ms=0, now_date=0, now_secs=0, now_frac=0, tree=None, count=0, cmp=1)
    s.update(kw)
    return s


def evaluate(img, code, chain, s):
    c = CHAINS[chain]
    m = Machine(img, ())
    m.code = code
    stack = m.arena(0x4000, False)
    stack.mem[:] = b'\xa5' * len(stack.mem)
    m.regs[4] = stack.base + 0x3000
    state = m.arena(0x4800)
    out = m.arena(0x80, False)
    user = m.arena(KEY_SIZE)
    action = m.arena(16)
    m.store(user.base, KEY_SIZE, int.from_bytes(ME, 'little'))
    m.store(action.base, 8, s['flag'])
    m.store(action.base + 8, 8, s['ms'])
    for off, size, v in ((NOW, 4, s['now_date']), (NOW + 4, 4, s['now_secs']), (NOW + 8, 4, s['now_frac'])):
        m.store(state.base + off, size, v)
    dex = m.arena(max(len(s['dex']), 1) * DEX_STRIDE)
    m.store(state.base + c['dex_len'], 8, len(s['dex']))
    m.store(state.base + c['dex_ptr'], 8, dex.base)
    root, height = make_tree(m, s['tree'], lambda k: s['vals'].get(k, (0, 0, 0, 0)))
    m.store(state.base + c['map'], 8, root)
    m.store(state.base + c['map'] + 8, 8, height)
    m.store(state.base + c['map'] + 16, 8, len(spec_keys(s['tree'])))
    log = []

    def key_is(ptr):
        if m.load(ptr, KEY_SIZE) != int.from_bytes(ME, 'little'):
            raise Unmodelled('lookup key is not the user')

    def lookup_dex():
        k = (m.regs[R['rdi']] - dex.base - DEX_MAP) / DEX_STRIDE
        if k != int(k) or not 0 <= k < len(s['dex']):
            raise Unmodelled('dex lookup outside the vector')
        key_is(m.regs[R['rsi']])
        v = m.arena(0x60)
        m.store(v.base + DEX_SCALED, 8, s['dex'][int(k)][0])
        m.store(v.base + DEX_RAW, 8, s['dex'][int(k)][1])
        log.append(('dex', int(k)))
        m.clobber(v.base)

    def lookup_base():
        if m.regs[R['rdi']] != state.base + BASE_MAP:
            raise Unmodelled('base lookup argument')
        key_is(m.regs[R['rsi']])
        v = m.arena(16)
        m.store(v.base, 8, s['base'][0])
        m.store(v.base + 8, 8, s['base'][1])
        log.append(('base',))
        m.clobber(v.base)

    def hook():
        if m.regs[R['rdi']] & 0xffffffff:
            raise Unmodelled('hook first argument')
        log.append(('hook', m.regs[R['rsi']]))
        m.clobber()

    def memcmp():
        a = m.load(m.regs[R['rdi']], KEY_SIZE).to_bytes(KEY_SIZE, 'little')
        b = m.load(m.regs[R['rsi']], KEY_SIZE).to_bytes(KEY_SIZE, 'little')
        if m.regs[R['rdx']] != KEY_SIZE:
            raise Unmodelled('memcmp length')
        m.clobber(((a > b) - (a < b)) * s['cmp'] & 0xffffffff)

    def alloc():
        if m.regs[R['rdi']] != NODE_EDGES:
            raise Unmodelled('allocation size')
        log.append(('alloc',))
        m.clobber(m.arena(NODE_EDGES).base)

    def leaf_insert():
        place, ptr_key, ptr_val, res = m.regs[R['rsi']], m.regs[R['rdx']], m.regs[R['rcx']], m.regs[R['rdi']]
        node, height_now, idx = m.load(place, 8), m.load(place + 8, 8), m.load(place + 16, 8)
        n = m.load(node + NODE_LEN, 2)
        if height_now or n >= NODE_CAP:
            raise Unmodelled('vector needs a node split')
        for k in range(n, idx, -1):
            m.store(node + NODE_KEYS + KEY_SIZE * k, KEY_SIZE, m.load(node + NODE_KEYS + KEY_SIZE * (k - 1), KEY_SIZE))
            for off, size in ((0, 8), (8, 4), (12, 4), (16, 4)):
                m.store(node + NODE_VALS + VAL_SIZE * k + off, size,
                        m.load(node + NODE_VALS + VAL_SIZE * (k - 1) + off, size))
        m.store(node + NODE_KEYS + KEY_SIZE * idx, KEY_SIZE, m.load(ptr_key, KEY_SIZE))
        raw = bytes(m.find(ptr_val, VAL_SIZE).mem[ptr_val - m.find(ptr_val, VAL_SIZE).base:][:VAL_SIZE])
        a = m.find(node, NODE_EDGES)
        o = node + NODE_VALS + VAL_SIZE * idx - a.base
        a.mem[o:o + VAL_SIZE] = raw
        a.valid[o:o + VAL_SIZE] = b'\1' * VAL_SIZE
        m.store(node + NODE_LEN, 2, n + 1)
        log.append(('leaf_insert', idx))
        for off, v in ((0, node), (8, 0), (16, idx)):
            m.store(res + off, 8, v)
        m.clobber(res)

    def fmt():
        m.store(m.regs[R['rdi']], 8, 0x1234)
        m.clobber()

    def err_box():
        m.clobber(0xe770000000000b0c)

    def panic():
        raise Panic(m.regs[R['rdx']])

    m.got = {MEMCMP_SLOT: 0xbeef0001, ERR_ARG_SLOT: 0xbeef0002}
    m.stubs = {DEX_LOOKUP: lookup_dex, BASE_LOOKUP_SLOT: lookup_base, HOOK_SLOT: hook, 0xbeef0001: memcmp,
               ALLOC_SLOT: alloc, insert_callee(code, c['insert']): leaf_insert, FORMAT_SLOT: fmt,
               ERR_BOX: err_box, PANIC_SLOT: panic}
    m.real = {FROM_DAYS_SLOT: img.relative(FROM_DAYS_SLOT), TIME_ADD_SLOT: img.relative(TIME_ADD_SLOT),
              DATE_ADD_SLOT: img.relative(DATE_ADD_SLOT), ERR_HELPER: ERR_HELPER, c['gate']: c['gate'],
              c['insert']: c['insert']}
    m.regs[R['rdi']], m.regs[R['rsi']], m.regs[R['rdx']], m.regs[R['rcx']] = out.base, action.base, user.base, state.base
    entry_sp = m.regs[4]
    panic_at = None
    try:
        run_real(m, c['wrapper'])
    except Panic as p:
        panic_at = p.location
    if panic_at is None and m.regs[4] != entry_sp:
        raise Unmodelled('stack not balanced')
    res = {'seen': m.seen, 'taken': m.taken, 'log': log, 'panic': panic_at}
    if panic_at is None:
        res['result'] = out.mem[0]
        res['tag'] = int.from_bytes(out.mem[8:10], 'little')
        res['payload'] = bytes(out.mem[16:24])
        res['rax'] = m.regs[0] == out.base
    r2, h2 = m.load(state.base + c['map'], 8), m.load(state.base + c['map'] + 8, 8)
    res['map'] = tree_walk(m, r2, h2) if r2 else []
    res['map_len'] = m.load(state.base + c['map'] + 16, 8)
    return res


def insert_callee(code, insert, size=0x16e):
    """Target of the single direct call inside the entry-insert function."""
    calls = [i.ops[0][1] for va, i in code.items() if insert <= va < insert + size and i.op == 'call'
             and i.ops[0][0] == 't']
    if len(calls) != 1:
        raise EvidenceError(f'{len(calls)} direct calls in the insert function')
    return calls[0]


# Separate closed-form model.  It shares nothing with the evaluator above.

def days_before_year(y):
    return 365 * y + y // 4 - y // 100 + y // 400


def is_leap(y):
    return y % 4 == 0 and (y % 100 != 0 or y % 400 == 0)


def ce_from_civil(y, ordinal):
    """Days from 0001-01-01 counting that day as 1, as NaiveDate::from_num_days_from_ce names them."""
    return days_before_year(y - 1) + ordinal


def civil_from_ce(ce):
    y = (ce - 1) * 400 // 146097 + 1
    while ce_from_civil(y, 1) > ce:
        y -= 1
    while ce_from_civil(y + 1, 1) <= ce:
        y += 1
    return y, ce - ce_from_civil(y, 1) + 1


def date_ce(packed):
    """Year above bit 13 (signed 32-bit word), ordinal in bits 4-12, as read from the stored dword."""
    return ce_from_civil(signed(packed, 32) >> 13, packed >> 4 & 0x1ff)


MAX_CE = ce_from_civil(262142, 365)


def civil(ms):
    return ms // 86_400_000 + CE_OFFSET, ms // 1000 % 86400, ms % 1000 * 1_000_000


def plus_step(ce, secs, frac):
    """Date, second and nanosecond of (ce, secs, frac) + 5 seconds, with a leap frac dropped."""
    if frac >= 1_000_000_000:
        frac -= 1_000_000_000
    secs += STEP_SECONDS
    if secs >= 86400:
        ce, secs = ce + 1, secs - 86400
    return ce, secs, frac


def model(s):
    want = {'log': [], 'map': {k: s['vals'].get(k, (0, 0, 0, 0)) for k in spec_keys(s['tree'])}, 'panic': None}
    flag, ms = s['flag'] & 0xff, s['ms']
    if flag & 1 and ms > WRAPPER_MAX:
        want.update(result=RESULT_ERR, tag=TAG_WRAPPER, payload=struct.pack('<Q', 1))
        return want
    scaled, raw, log = 0, 0, want['log']

    def add(a, b, location):
        total = a + b
        if total > U64:
            log.append(('hook', location))
            return U64
        return total

    for k, (sv, rv) in enumerate(s['dex']):
        log.append(('dex', k))
        scaled = add(scaled, sv, ADD_LOCATION)
        raw = add(raw, rv, ADD_LOCATION)
    log.append(('base',))
    scaled = add(scaled, s['base'][0], SCALED_LOCATION)
    add(raw, s['base'][1], RAW_LOCATION)
    if scaled < THRESHOLD:
        want.update(result=RESULT_ERR, tag=TAG_VOLUME, payload=struct.pack('<d', scaled / 100.0))
        return want
    me = want['map'].get(ME)
    if not flag & 1:
        if me is not None:
            want['map'][ME] = (me[0], 0, me[2], me[3])
        want.update(result=RESULT_OK, tag=None, payload=None)
        return want
    ce, secs, frac = civil(ms)
    if ce > MAX_CE:
        want.update(result=RESULT_ERR, tag=TAG_RANGE, payload=struct.pack('<Q', 0xe770000000000b0c))
        return want
    now = date_ce(s['now_date']), s['now_secs'], s['now_frac']
    earliest = plus_step(*now)
    if earliest[0] > MAX_CE:
        want['panic'] = TIME_LOCATION
        return want
    if not (ce, secs, frac) > earliest:
        want.update(result=RESULT_ERR, tag=TAG_EARLY, payload=None)
        return want
    if me is None:
        keys = spec_keys(s['tree'])
        if keys:
            log.append(('leaf_insert', leaf_index(s['tree'], ME)))
        else:
            log.append(('alloc',))
        me = (0, 0, 0, 0)
    if me[0] > COUNT_LIMIT:
        want.update(result=RESULT_ERR, tag=TAG_COUNT, payload=None)
        return want
    want['map'][ME] = ('kept', ce, secs, frac)
    want['count'] = me[0]
    want.update(result=RESULT_OK, tag=None, payload=None)
    return want


def leaf_index(spec, key):
    while not isinstance(spec, list):
        keys, kids = spec
        k = sum(1 for x in keys if x < key)
        spec = kids[k]
    return sum(1 for x in spec if x < key)


def compare(s, got, want):
    bad = []
    if got['panic'] != want['panic']:
        bad.append(('panic', got['panic'], want['panic']))
    if got['log'] != want['log']:
        bad.append(('log', got['log'], want['log']))
    if want['panic'] is None:
        for f in ('result', 'tag', 'payload'):
            if want.get(f) is not None and got.get(f) != want[f]:
                bad.append((f, got.get(f), want[f]))
        if not got.get('rax'):
            bad.append(('rax', got.get('rax')))
    expect = dict(want['map'])
    have = dict(got['map'])
    if len(got['map']) != len(have) or got['map_len'] != len(have):
        bad.append(('map_len', got['map_len'], len(have)))
    keys = [k for k, _ in got['map']]
    if keys != sorted(keys):
        bad.append(('order', keys))
    if set(expect) != set(have):
        bad.append(('keys', sorted(have), sorted(expect)))
    else:
        for k, v in expect.items():
            h = have[k]
            if v[0] == 'kept':
                v = (want['count'], v[1], v[2], v[3])
                h = (h[0], date_ce(h[1]), h[2], h[3])
            if h != v:
                bad.append(('value', h, v))
    return bad


def milli(y, ordinal, secs=0, ms=0):
    return (ce_from_civil(y, ordinal) - CE_OFFSET) * 86_400_000 + secs * 1000 + ms


HEAVY = (THRESHOLD, 0)


def groups(pack):
    """All vectors as (group, scenario).  `pack` gives a stored date dword for a day number."""
    noon = milli(2026, 300, 43200)
    ce0, secs0, frac0 = civil(noon)
    base = dict(base=HEAVY, now_date=pack(ce0), now_secs=secs0, now_frac=frac0, vals={})
    far = noon + 3_600_000
    out = []

    # Volume sum and threshold; `time` absent and present, so both arms sit behind the gate.
    edge = (0, 1, 2, THRESHOLD - 1, THRESHOLD, THRESHOLD + 1, 10 ** 12, U64 - 1, U64)
    raws = (0, 1, U64)
    for flag, ms in ((0, 0), (1, far)):
        for a in edge:
            for r in raws:
                out.append(('sum_base', dict(base, base=(a, r), flag=flag, ms=ms)))
        for a in edge:
            for b in edge:
                out.append(('sum_one_dex', dict(base, dex=((a, 1),), base=(b, 2), flag=flag, ms=ms)))
                out.append(('sum_three_dex', dict(base, dex=((a, U64), (b, 2), (1, 0)), base=(THRESHOLD - 1, U64),
                                                  flag=flag, ms=ms)))
        for n in range(1, 6):
            part = THRESHOLD // n
            for extra in (-1, 0, 1):
                out.append(('sum_split', dict(base, dex=tuple((part, k) for k in range(n)),
                                              base=(max(THRESHOLD - part * n + extra, 0), 0), flag=flag, ms=ms)))

    # Raw total overflows at the base step, below and at the threshold.
    for sv in (0, 5, THRESHOLD - 1, THRESHOLD, U64):
        for flag, ms in ((0, 0), (1, far)):
            out.append(('raw_overflow', dict(base, dex=((0, U64),), base=(sv, U64), flag=flag, ms=ms)))
            out.append(('raw_overflow', dict(base, dex=((0, U64 - 1), (0, 1)), base=(sv, 1), flag=flag, ms=ms)))
            out.append(('raw_overflow', dict(base, dex=((0, U64), (0, 2)), base=(sv, 1), flag=flag, ms=ms)))

    # Deadline against now + 5 seconds.
    for delta in (-86_400_000, -1, 0, 1, 1000, 4000, 4999, 5000, 5001, 5999, 6000, 86_400_000, 5 * 86_400_000,
                  432_000_000 - 1, 432_000_001):
        out.append(('deadline', dict(base, ms=noon + delta)))
    for nanos in (0, 1, 999_999, 1_000_000, 1_000_001, 999_999_999):
        for delta in (4999, 5000, 5001, 5002):
            out.append(('deadline_nanos', dict(base, now_frac=nanos, ms=noon + delta)))
    for secs in (86394, 86395, 86396, 86399):
        now_ms = milli(2024, 366, secs)
        ce, sec, frac = civil(now_ms)
        for delta in (4999, 5000, 5001, 86_400_000):
            out.append(('deadline_midnight', dict(base, now_date=pack(ce), now_secs=sec, now_frac=frac,
                                                  ms=now_ms + delta)))
    for frac in (1_000_000_000, 1_500_000_000):
        for delta in (4000, 5000, 5500, 6000):
            out.append(('deadline_leap_frac', dict(base, now_frac=frac, ms=noon + delta)))

    # Conversion range.  The wrapper bound comes first, then the day guard, then the date helper.
    top = (MAX_CE - CE_OFFSET) * 86_400_000
    for ms in (0, 1, 999, 1000, 86_399_999, 86_400_000, noon, top - 1, top, top + 86_399_999, top + 86_400_000,
               (DAYS_LIMIT - 1) * 86_400_000, DAYS_LIMIT * 86_400_000, DAYS_LIMIT * 86_400_000 + 1,
               (DAYS_LIMIT + 1) * 86_400_000, WRAPPER_MAX - 1, WRAPPER_MAX, WRAPPER_MAX + 1, 1 << 62, 1 << 63, U64):
        out.append(('conversion', dict(base, ms=ms)))
        out.append(('conversion_early', dict(base, ms=ms, now_date=pack(CE_OFFSET), now_secs=0, now_frac=0)))
    for flag in (0, 2, 0x100, 0xff, 1):
        out.append(('flag_bit', dict(base, flag=flag, ms=WRAPPER_MAX + 1)))
        out.append(('flag_bit', dict(base, flag=flag, ms=far)))

    # now + 5 seconds leaves the date range: the expect panic.
    last = pack(MAX_CE)
    for secs in (86394, 86395, 86399):
        out.append(('date_overflow', dict(base, now_date=last, now_secs=secs, now_frac=0, ms=top + 86_399_999)))

    # The per-user map.
    a, b, c, d, e, f = [bytes([x]) + bytes(19) for x in (0x11, 0x22, 0x33, 0x55, 0x66, 0x77)]
    d2 = bytes([0x55, 1]) + bytes(18)
    shapes = {'empty': None, 'leaf_low': [a, b], 'leaf_high': [d, e], 'leaf_mid': [b, d],
              'leaf_hit': [a, ME, d], 'leaf_only_hit': [ME],
              'node_hit': ([ME], [[a, b], [d, e]]), 'node_left': ([d], [[a, b], [e]]),
              'node_right': ([c], [[a, b], [d]]), 'child_hit': ([b], [[a], [ME, d]]),
              'node_mid': ([b, d], [[a], [c, ME], [e]]), 'node_mid_miss': ([b, d], [[a], [c], [e]]),
              'deep_hit': ([d], [([b], [[a], [ME]]), ([e], [[d2], [f]])]),
              'deep_miss': ([d], [([b], [[a], [c]]), ([e], [[d2], [f]])])}
    armed = (ce0 + 1, 0, 0)
    for name, spec in shapes.items():
        for count in (0, 1, 9, 10, 11, U64):
            vals = {k: (0x70 + k[0], pack(ce0 + k[0]), k[0], k[0] + 1) for k in spec_keys(spec)}
            if ME in vals:
                vals[ME] = (count, pack(armed[0]), 7, 9)
            for flag, ms in ((1, far), (0, 0), (1, noon)):
                out.append(('map_' + name, dict(base, tree=spec, vals=vals, count=count, flag=flag, ms=ms)))
                out.append(('map_low_volume', dict(base, tree=spec, vals=vals, count=count, flag=flag, ms=ms,
                                                   base=(THRESHOLD - 1, 0))))
    for cmpv in (1, 7, 0x7fffffff):
        out.append(('memcmp_value', dict(base, tree=shapes['node_mid'], vals={}, cmp=cmpv, ms=far)))
        out.append(('memcmp_value', dict(base, tree=shapes['leaf_hit'], vals={}, cmp=cmpv, ms=0, flag=0)))
    return out


def fde_of(fdes, va):
    r = fdes.range_of(va)
    if r['start'] != va:
        raise EvidenceError(f'{va:#x} is not an FDE start')
    return r


def load_code(img, fdes):
    code, sizes, lists = {}, {}, {}
    fns = set()
    for c in CHAINS.values():
        fns |= {c['wrapper'], c['gate'], c['insert']}
    fns |= {img.relative(FROM_DAYS_SLOT), img.relative(TIME_ADD_SLOT), img.relative(DATE_ADD_SLOT), ERR_HELPER}
    for fn in sorted(fns):
        r = fde_of(fdes, fn)
        insns = decode_range(img, r['start'], r['end'])
        lists[fn] = insns
        sizes[fn] = {'start': hex(r['start']), 'end': hex(r['end']), 'fde': hex(r['fde']), 'size': r['end'] - r['start'],
                     'instructions': len(insns)}
        for i in insns:
            code[i.va] = i
    return code, sizes, lists


def tree_operands(ins):
    return ins.op, tuple(('t',) if o[0] == 't' else o for o in ins.ops)


def copy_diff(lists):
    """Instruction-by-instruction comparison of the gate copies, branch targets ignored."""
    base = lists[CHAINS['a']['gate']]
    rows = {}
    for name in ('b', 'c'):
        other = lists[CHAINS[name]['gate']]
        if len(other) != len(base):
            raise EvidenceError('gate copies differ in length')
        offs, calls, rest = [], 0, 0
        for x, y in zip(base, other):
            if x.size != y.size:
                raise EvidenceError('gate copies differ in instruction size')
            if tree_operands(x) == tree_operands(y):
                continue
            if x.op == y.op == 'call':
                calls += 1
            elif x.op == y.op and [o[:4] for o in x.ops if o[0] == 'r'] == [o[:4] for o in y.ops if o[0] == 'r']:
                dx = [o[4] for o in x.ops if o[0] == 'm']
                dy = [o[4] for o in y.ops if o[0] == 'm']
                if len(dx) != 1 or len(dy) != 1:
                    raise EvidenceError('unexpected operand difference')
                offs.append((hex(dx[0]), hex(dy[0])))
            else:
                rest += 1
        if rest:
            raise EvidenceError(f'{rest} unexplained instruction differences')
        rows[name] = {'instructions': len(other), 'field_offset_differences': sorted(set(offs)),
                      'field_offset_instructions': len(offs), 'call_target_differences': calls}
    return rows


def calls_of(insns):
    out = Counter()
    for i in insns:
        if i.op == 'call':
            o = i.ops[0]
            out[hex(o[1]) if o[0] == 't' else f'[{o[4]:#x}]' if o[0] == 'm' else 'register'] += 1
    return dict(sorted(out.items()))


def check_gate_constants(lists):
    """Facts the claims rest on, from decoded operands of the first copy, for every copy."""
    for name, c in CHAINS.items():
        ins = lists[c['gate']]
        imm64 = Counter(i.ops[1][1] for i in ins if i.op == 'mov' and i.ops[1][0] == 'i' and i.size == 10)
        want = {MS_DIV_1000[0], MS_DIV_DAY[0], SEC_DIV_DAY[0], SECONDS_DIV_DAY}
        if not want <= set(imm64):
            raise EvidenceError('division constants missing')
        cmps = {i.ops[1][1] for i in ins if i.op == 'cmp' and i.ops[1][0] == 'i'}
        if THRESHOLD not in cmps or COUNT_LIMIT not in cmps:
            raise EvidenceError('threshold constants missing')
        step = [i for i in ins if i.op == 'mov' and i.ops[0] == ('r', 2, 32) and i.ops[1] == ('i', STEP_SECONDS)]
        if len(step) != 1:
            raise EvidenceError('no 5 in edx before the time add')
        tags = sorted(i.ops[1][1] for i in ins if i.op == 'mov' and i.ops[0][0] == 'm' and i.ops[0][6] == 16)
        if tags != sorted((TAG_OK, TAG_RANGE, TAG_EARLY, TAG_COUNT, TAG_VOLUME)):
            raise EvidenceError(f'result tags {tags}')
        conv = [i for i in ins if i.op == 'cvtsi2sd']
        if len(conv) != 1 or conv[0].width != 64:
            raise EvidenceError('volume conversion is not 64-bit')
        wr = lists[c['wrapper']]
        if not any(i.op == 'mov' and i.ops[1] == ('i', WRAPPER_MAX) and i.size == 10 for i in wr):
            raise EvidenceError('wrapper bound missing')
    return True


def error_arm(img, tag):
    """Display arm of an error tag: the literal or format pieces it loads, by table decoding."""
    d = struct.unpack('<i', img.read(DISPLAY_TABLE + 4 * tag, 4))[0]
    va = DISPLAY_TABLE + d
    code = img.read(va, 160) + b'\x90' * 16
    i, prior = 0, []
    for _ in range(24):
        ins = decode_one(code, i, va + i)
        i += ins.size
        prior.append(ins)
        if ins.op == 'lea' and ins.ops[0] == ('r', 6, 64) and ins.ops[1][1] is None:
            nxt = decode_one(code, i, va + i)
            if nxt.op == 'mov' and nxt.ops[0] == ('r', 2, 32):
                return {'arm': hex(va), 'kind': 'literal', 'va': hex(ins.ops[1][4]),
                        'text': img.read(ins.ops[1][4], nxt.ops[1][1]).decode()}
        if ins.op == 'lea' and ins.ops[0] == ('r', 2, 64) and ins.ops[1][1] is None:
            return {'arm': hex(va), 'kind': 'format', 'va': hex(ins.ops[1][4]),
                    'pieces': format_pieces(img, ins.ops[1][4]),
                    'immediates_64': [hex(p.ops[1][1]) for p in prior if p.op == 'mov' and p.size == 10]}
    raise EvidenceError(f'no text found for tag {tag:#x}')


def format_pieces(img, va):
    out = []
    while True:
        n = img.read(va, 1)[0]
        va += 1
        if n == 0:
            return out
        if n == 0xc0:
            out.append(None)
        elif n < 0x80:
            out.append(img.read(va, n).decode())
            va += n
        else:
            raise EvidenceError(f'format byte {n:#x}')


def path_suffix(raw):
    for mark in (b'/l1/src/', b'/library/', b'/src/'):
        k = raw.find(mark)
        if k != -1:
            return raw[k + 1:].decode()
    raise EvidenceError(f'unexpected path {raw[-24:]!r}')


def decode_location(img, va):
    path = img.relative(va)
    size = img.u64(va + 8)
    line, col = struct.unpack('<II', img.read(va + 16, 8))
    return {'va': hex(va), 'path': path_suffix(img.read(path, size)), 'path_bytes': size, 'line': line, 'column': col}


def location_sites(img, fdes):
    """`lea r64,[rip+d]` byte patterns naming the two volume records, with their functions."""
    text_va, text = img.text()
    want = {SCALED_LOCATION: [], RAW_LOCATION: []}
    for m in re.finditer(rb'[\x48\x4c]\x8d[\x05\x0d\x15\x1d\x25\x2d\x35\x3d]', text):
        i = m.start()
        if i + 7 <= len(text):
            target = text_va + i + 7 + struct.unpack_from('<i', text, i + 3)[0]
            if target in want:
                want[target].append(text_va + i)
    scaled = sorted({fdes.range_of(v)['start'] for v in want[SCALED_LOCATION]})
    raw = sorted({fdes.range_of(v)['start'] for v in want[RAW_LOCATION]})
    if not set(raw) <= set(scaled) or GATE_A not in raw:
        raise EvidenceError('raw record sites are not inside scaled record functions')
    return {'scaled_sites': len(want[SCALED_LOCATION]), 'scaled_functions': [hex(v) for v in scaled],
            'raw_sites': len(want[RAW_LOCATION]), 'raw_functions': [hex(v) for v in raw]}


def lookups(img, fdes):
    """Both volume lookups: bytes that fix the stride and value offset of each hash map."""
    out = {}
    for name, fn, size, back in (('dex', DEX_LOOKUP, b'\x4d\x6b\xd2\x78', b'\x48\x8d\x5a\xa0'),
                                 ('base', img.relative(BASE_LOOKUP_SLOT), b'\x4d\x6b\xd2\x58', b'\x48\x8d\x5a\xc0')):
        r = fde_of(fdes, fn)
        body = img.read(r['start'], r['end'] - r['start'])
        if body.count(size) != 1 or body.count(back) != 1:
            raise EvidenceError(f'{name} lookup bytes')
        out[name] = {'start': hex(r['start']), 'end': hex(r['end']), 'entry_size': size[-1],
                     'value_offset_in_entry': size[-1] - (0x100 - back[-1])}
    return out


def unexecuted(lists, seen):
    out = {}
    for fn, insns in lists.items():
        missed = [i for i in insns if i.va not in seen]
        out[fn] = missed
    return out


def check_unreached(lists, seen):
    for name, c in CHAINS.items():
        for fn, listed in ((c['gate'], UNREACHED_GATE), (c['insert'], UNREACHED_INSERT)):
            allowed = {i.va for i in lists[fn] for lo, hi, _ in listed if fn + lo <= i.va < fn + hi}
            missed = {i.va for i in lists[fn] if i.va not in seen and i.op not in ('nop', 'int3')}
            if missed != allowed:
                raise EvidenceError(f'chain {name} {fn:#x}: unexpected unexecuted code '
                                    f'{sorted(hex(v) for v in missed ^ allowed)[:12]}')
        wrap = [i for i in lists[c['wrapper']] if i.va not in seen and i.op not in ('nop', 'int3')]
        if wrap:
            raise EvidenceError(f'wrapper {c["wrapper"]:#x}: unexecuted {[hex(i.va) for i in wrap][:8]}')


def branch_gaps(lists, taken, seen):
    """Conditional branches of the gate that only ever went one way, per copy."""
    out = {}
    for name, c in CHAINS.items():
        rows = []
        for i in lists[c['gate']]:
            if i.op[0] == 'j' and i.op != 'jmp' and i.va in seen:
                both = taken.get(i.va, set())
                if len(both) != 2:
                    rows.append((hex(i.va), i.op, 'taken' if True in both else 'fall-through'))
        out[name] = rows
    return out


def row_text(group, chain, s, got):
    hooks = ','.join(hex(e[1]) for e in got['log'] if e[0] == 'hook') or '-'
    me = dict(got['map']).get(ME)
    stored = '-' if me is None else f'{me[0]}/{date_ce(me[1]) if me[1] else 0}/{me[2]}/{me[3]}'
    pay = '-'
    if got['panic'] is None and got['tag'] == TAG_VOLUME and got['result'] == RESULT_ERR:
        pay = repr(struct.unpack('<d', got['payload'])[0])
    status = 'panic' if got['panic'] else ('ok' if got['result'] == RESULT_OK else hex(got['tag']))
    vol = ','.join(str(v[0]) for v in s['dex']) or '-'
    return '\t'.join(str(v) for v in (group, chain, vol, s['base'][0], s['flag'], s['ms'], date_ce(s['now_date']),
                                      s['now_secs'], s['now_frac'], status, pay, hooks, stored, len(got['map'])))


def analyse(data, patches=None, vectors=groups, chains=tuple(CHAINS)):
    digest = check_digest(data)
    img = Image(data, patches)
    fdes = Fdes(img)
    code, sizes, lists = load_code(img, fdes)
    check_gate_constants(lists)
    if img.f64(ONE_HUNDRED_VA) != 100.0:
        raise EvidenceError('divisor constant')
    if img.u64(COUNT_LIMIT_ARG_VA) != COUNT_LIMIT + 1:
        raise EvidenceError('count limit argument')
    for magic, shift, divisor in ((MS_DIV_1000[0], MS_DIV_1000[1] + 4, 1000), (MS_DIV_DAY[0], MS_DIV_DAY[1] + 6, 86_400_000),
                                  (SEC_DIV_DAY[0], 6, 86400)):
        if not division_covers(magic, shift, divisor):
            raise EvidenceError('division constant is not exact')
    cached = {}

    def pack(ce):
        if ce not in cached:
            cached[ce] = pack_date(img, code, ce)
        return cached[ce]

    seen, taken, rows, counts, status, failures = set(), {}, [], Counter(), Counter(), []
    vs = vectors(pack)
    for group, kw in vs:
        s = scenario(**kw)
        want = model(s)
        for chain in chains:
            got = evaluate(img, code, chain, s)
            bad = compare(s, got, want)
            counts[group] += 1
            label = 'panic' if got['panic'] else ('ok' if got['result'] == RESULT_OK else hex(got['tag']))
            status[label] += 1
            seen |= got['seen']
            for k, v in got['taken'].items():
                taken.setdefault(k, set()).update(v)
            if bad:
                failures.append((group, chain, s['ms'], bad[:2]))
            if chain == 'a':
                rows.append(row_text(group, chain, s, got))
    if failures:
        c = Counter((f[0], str(f[3][0][0])) for f in failures)
        raise EvidenceError(f'{len(failures)} vectors disagree; {c.most_common(12)}; first {failures[0]}')
    full = vectors is groups and chains == tuple(CHAINS)
    if full:
        check_unreached(lists, seen)
    missed = unexecuted(lists, seen)
    result = {
        'component': 'fees', 'binary': BINARY, 'sha256': digest, 'coordinates': 'virtual addresses (ELF VA)',
        'question': 'what the gate reached from the l1/src/scaled_vlm.rs and raw_vlm.rs overflow records decides',
        'fde_table_entries': fdes.count,
        'functions': {hex(k): v for k, v in sorted(sizes.items())},
        'chains': {n: {k: hex(v) for k, v in c.items()} for n, c in CHAINS.items()},
        'leaf_insert_targets': {n: hex(insert_callee(code, c['insert'])) for n, c in CHAINS.items()},
        'gate_calls': {n: calls_of(lists[c['gate']]) for n, c in CHAINS.items()},
        'copy_comparison_against_a': copy_diff(lists),
        'slots': {'from_num_days': hex(img.relative(FROM_DAYS_SLOT)), 'time_add': hex(img.relative(TIME_ADD_SLOT)),
                  'date_add': hex(img.relative(DATE_ADD_SLOT)), 'base_lookup': hex(img.relative(BASE_LOOKUP_SLOT)),
                  'hook': hex(img.relative(HOOK_SLOT))},
        'lookups': lookups(img, fdes),
        'constants': {'threshold': THRESHOLD, 'seconds_in_edx': STEP_SECONDS, 'count_compare': COUNT_LIMIT,
                      'count_message_argument': img.u64(COUNT_LIMIT_ARG_VA),
                      'wrapper_bound': hex(WRAPPER_MAX), 'days_guard': hex(DAYS_LIMIT), 'ce_offset': CE_OFFSET,
                      'divisor_100_0': img.f64(ONE_HUNDRED_VA), 'max_ce_day': MAX_CE, 'max_ms': (MAX_CE - CE_OFFSET + 1) * 86_400_000 - 1,
                      'panic_text': img.read(PANIC_TEXT_VA, PANIC_TEXT_LEN).decode(),
                      'range_text_pieces': format_pieces(img, RANGE_TEXT_VA)},
        'locations': {k: decode_location(img, v) for k, v in (('per_dex_add', ADD_LOCATION), ('scaled', SCALED_LOCATION),
                                                              ('raw', RAW_LOCATION), ('time_add', TIME_LOCATION))},
        'error_arms': {hex(t): error_arm(img, t) for t in (TAG_RANGE, TAG_EARLY, TAG_COUNT, TAG_VOLUME, TAG_WRAPPER)},
        'evaluation': {'vectors_per_chain': len(vs), 'evaluations': sum(counts.values()), 'mismatches': 0,
                       'groups': dict(sorted(counts.items())), 'status': dict(sorted(status.items())),
                       'not_executed': {hex(fn): {'instructions': len(v),
                                                  'non_padding': sum(i.op not in ('nop', 'int3') for i in v)}
                                        for fn, v in sorted(missed.items())},
                       'blocks_not_executed_gate_relative': [{'start': hex(a), 'end': hex(b), 'why': w}
                                                             for a, b, w in UNREACHED_GATE],
                       'blocks_not_executed_insert_relative': [{'start': hex(a), 'end': hex(b), 'why': w}
                                                               for a, b, w in UNREACHED_INSERT],
                       'one_way_branches': branch_gaps(lists, taken, seen)},
    }
    if full:
        result['location_sites'] = location_sites(img, fdes)
    result['summary'] = {'chains': len(chains), 'vectors': len(vs), 'evaluations': sum(counts.values()), 'mismatches': 0,
                         'gate_instructions': len(lists[CHAINS['a']['gate']]),
                         'gate_instructions_not_executed': len(missed[CHAINS['a']['gate']])}
    return result, img, lists, rows


def reference_rows():
    return ['reference\tclaim\tobserved'] + ['\t'.join(r) for r in REFERENCE_ROWS]


def division_covers(magic, shift, divisor):
    k = 64 + shift
    return magic * divisor >= 1 << k or -(-(1 << k) // divisor) >= magic


def write(out, result, img, lists, rows):
    out.mkdir(parents=True, exist_ok=True)
    (out / 'evidence.json').write_text(json.dumps(result, indent=2, sort_keys=True) + '\n')
    lines = ['va\tsize\tbytes\tdecoded']
    fns = [CHAINS['a']['wrapper'], CHAINS['a']['gate'], CHAINS['a']['insert']]
    for fn in fns:
        lines += [f'{i.va:#x}\t{i.size}\t{i.raw.hex()}\t{show(i)}' for i in lists[fn]]
    (out / 'instructions.tsv').write_text('\n'.join(lines) + '\n')
    (out / 'reference-diff.tsv').write_text('\n'.join(reference_rows()) + '\n')
    head = 'group\tchain\tdex_scaled\tbase_scaled\tflag\tms\tnow_ce_day\tnow_secs\tnow_frac\tstatus\tvolume_payload\thooks\tstored\tmap_len'
    (out / 'vectors.tsv').write_text('\n'.join([head] + rows) + '\n')


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument('--out', required=True, type=Path)
    ap.add_argument('--binary', type=Path, default=ROOT / BINARY)
    args = ap.parse_args(argv)
    try:
        data = args.binary.read_bytes()
        result, img, lists, rows = analyse(data)
    except (EvidenceError, Unmodelled, OSError) as exc:
        print(f'error: {exc}', file=sys.stderr)
        return 1
    write(args.out, result, img, lists, rows)
    print(json.dumps(result['summary'], sort_keys=True))
    return 0


if __name__ == '__main__':
    sys.exit(main())
