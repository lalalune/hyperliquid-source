#!/usr/bin/env python3
"""fees: node #94 volume path at 0x372faa0, evaluated from bytes alone.

Static, no execution of the node.  The function in the pointer slot after the one
of 0x37153f0 is decoded from its ELF bytes by the small table decoder below, which
must land exactly on the FDE end.  The decoded instructions are then interpreted
in Python with every callee replaced by a stub, and each outcome is compared with
a separate closed-form model.

    python3 tools/fees_spot_volume.py --out <dir>

writes evidence.json, instructions.tsv and vectors.tsv.  Only the standard library
is used: no objdump, readelf or other external program runs, so the results cannot
depend on a binutils version.
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

FN = 0x372faa0
POINTER_SLOT = 0x5774578
LOW_VA, HIGH_VA, BIG_VA = 0x20acb8, 0x20a7f0, 0x20a2c8
FIVE_MAGIC = 0xcccccccccccccccd
MILLION_MAGIC = 0x431bde82d7b634db
SCALE = 1_000_000
MUL_MAX = 0x7ffffffffffffffe        # a larger product is replaced by 0
LIMIT = 0x28f5c28f5c28f5c           # a converted value at or above this is ignored
I64_MIN, I64_MAX = -(1 << 63), (1 << 63) - 1
U64 = (1 << 64) - 1

LOCATIONS = {'table_index': 0x56f1fd8, 'table_index_again': 0x5714c70, 'unwrap_a': 0x56f1ce0, 'unwrap_b': 0x5714c10,
             'add': 0x5715e68}
OVERFLOW_HOOK_SLOT = 0x5773190
PRICE_SLOT, PRED_SLOT = 0x5774548, 0x5773198
BOUNDS_SLOT, UNWRAP_SLOT = 0x576dfc8, 0x576e048
HOOK_CALLS = 8
EXT_ENTRY, EXT_ADD = 0x3596da0, 0x33bcd10
USER_ENTRY, DAY_ADD, TOTAL_ADD = 0x35964f0, 0x33bc210, 0x33bb180
SPLIT, CONVERT = 0x3745a60, 0x32814c0

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
        if reg not in (4, 5):
            raise EvidenceError(f'{va:#x}: unlisted shift /{reg}')
        return done('shl' if reg == 4 else 'shr', (rm, ('i', v[1] & 0xff)))
    if b == 0xc3:
        return done('ret', ())
    if b == 0xcc:
        return done('int3', ())
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
    if b == 0xa8:
        return done('test', (gpr(0, 8), imm(1)), 8)
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
            elif ops[0][0] == 'm' and ops[1][0] == 'x':
                self.store(self.ea(ops[0]), 8, self.xmm[ops[1][1]][0])
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
        if o[0] != 't' and target in (BOUNDS_SLOT, UNWRAP_SLOT):
            raise Panic(self.regs[R['rdx' if target == BOUNDS_SLOT else 'r8']])
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


LAYOUTS = {'u64': (0x218, 8, 0x272, 0x278), 'i32': (0xb8, 4, 0xe6, 0xe8), 'set': (8, 8, 0x62, 0x68),
           'price': (8, 8, 0xba, 0xc0), 'flag': (0x218, 8, 0x272, 0x278), 'five': (8, 8, 0x62, 0x70)}


def tree_nodes(m, kind, keys, deep, values=None):
    """A fake B-tree root for `keys`; `deep` hangs each key's gap on a child leaf.

    Returns (root, height).  Offsets are the ones the search loops read.  `values`
    maps key -> u64 for 'price' and key -> byte for 'flag'.
    """
    key_off, key_size, len_off, edge_off = LAYOUTS[kind]

    def node(ks, edges):
        a = m.arena(0x300)
        for i, k in enumerate(ks):
            m.store(a.base + key_off + i * key_size, key_size, k)
            if kind == 'price':
                m.store(a.base + 0x60 + i * 8, 8, values[k])
            if kind == 'flag':
                m.store(a.base + i * 0x30 + 0x2c, 1, values[k])
        m.store(a.base + len_off, 2, len(ks))
        for i, e in enumerate(edges):
            m.store(a.base + edge_off + i * 8, 8, e)
        return a.base

    keys = sorted(keys)
    if not keys:
        return 0, 0
    if not deep:
        return node(keys, []), 0
    mid = keys[len(keys) // 2]
    return node([mid], [node([k for k in keys if k < mid], []), node([k for k in keys if k > mid], [])]), 1


X_ID, Q_ID = 300, 77
UNREACHED = ((0x37309c9, 0x37309d9, 'second table bound; the length would have to change in a callee'),
             (0x3730af3, 0x3730b18, 'sign panic; the raw value is at most 0x7ffffffffffffffe'),
             (0x3730b18, 0x3730b3d, 'sign panic; the scaled value is 0 or more'))


def scenario(**kw):
    s = dict(t=2, table_len=4, x=X_ID, q=Q_ID, a=3 * 10 ** 7, b=10 ** 7, m=1.0, weight=1.0, t1=(), t3=(), t2={}, t4={},
             t5=(), pred=0, default_price=11 * 10 ** 7, conv=(0, 0), side=0, tag=0, day=20, mode=2, secondary=0,
             primary_amt=0, secondary_amt=0, gross=0, second=0, third=0, deep=False, day_keys=(), total_keys=(),
             ext_keys=(), start=None)
    s.update(kw)
    return s


USER_BYTES = {0: bytes(0xa0 + k for k in range(20)), 1: bytes(0xd0 + k for k in range(20))}


def evaluate(img, insns, s):
    """Run the real bytes on scenario `s` and report what they did."""
    m = Machine(img, insns)
    stack = m.arena(0x4000, strict=False)
    state = m.arena(0x380)
    rec_in = m.arena(0x230)
    rt = m.arena(0x100)
    table = m.arena(32 * s['table_len'] or 32)
    calls = []
    users = {}
    start = s['start'] or {}

    def user_cells(user):
        if user not in users:
            rec, ext_map, ext_cell, day_cell = m.arena(0x60), m.arena(0xb0), m.arena(8), m.arena(16)
            b = start.get(user, {})
            m.store(rec.base, 8, b.get('scaled', 0))
            m.store(rec.base + 8, 8, b.get('raw', 0))
            root, h = tree_nodes(m, 'i32', s['day_keys'], s['deep'])
            m.store(rec.base + 0x28, 8, root)
            m.store(rec.base + 0x30, 8, h)
            root, h = tree_nodes(m, 'u64', s['ext_keys'], s['deep'])
            m.store(ext_map.base + 0x98, 8, root)
            m.store(ext_map.base + 0xa0, 8, h)
            m.store(ext_cell.base, 8, b.get('ext', 0))
            m.store(day_cell.base, 8, b.get('day', (0, 0))[0])
            m.store(day_cell.base + 8, 8, b.get('day', (0, 0))[1])
            users[user] = dict(rec=rec, ext_map=ext_map, ext=ext_cell, day=day_cell)
        return users[user]

    total_cell = m.arena(16)
    m.store(total_cell.base, 8, start.get('total', (0, 0))[0])
    m.store(total_cell.base + 8, 8, start.get('total', (0, 0))[1])

    def st(a, off, size, val):
        m.store(a.base + off, size, val)

    def tree(off, kind, keys, values=None):
        root, h = tree_nodes(m, kind, keys, s['deep'], values)
        st(state, off, 8, root)
        st(state, off + 8, 8, h)

    st(state, 0x150, 8, f2b(s['weight']))
    st(state, 0x178, 8, table.base)
    st(state, 0x180, 8, s['table_len'])
    tree(0x1d0, 'price', s['t2'], s['t2'])
    tree(0x1e8, 'set', s['t3'])
    tree(0x230, 'flag', s['t4'], s['t4'])
    tree(0x248, 'set', s['t1'])
    tree(0x260, 'five', s['t5'])
    tree(0x358, 'i32', s['total_keys'])
    for i in range(s['table_len']):
        st(table, i * 32, 8, s['x'] if i == s['t'] else 0x7777)
        st(table, i * 32 + 8, 8, s['q'] if i == s['t'] else 0x7777)
    st(rt, 0xa0, 8, f2b(s['m']))
    st(rec_in, 0x1f0, 8, s['a'])
    st(rec_in, 0x1f8, 8, s['t'])
    st(rec_in, 0x200, 8, s['b'])
    st(rec_in, 0x218, 4, s['day'])
    st(rec_in, 0x224, 1, s['tag'])
    for side in (0, 1):
        o = side * 0xf8
        for k in range(20):
            st(rec_in, 0xd0 + o + k, 1, USER_BYTES[side][k])
            st(rec_in, 0x70 + o + k, 1, 0xb0 + k)
            st(rec_in, 0x98 + o + k, 1, 0xc0 + k)
        st(rec_in, 0x60 + o, 8, s['mode'])
        st(rec_in, 0x68 + o, 8, s['primary_amt'])
        st(rec_in, 0x88 + o, 8, s['secondary'])
        st(rec_in, 0x90 + o, 8, s['secondary_amt'])
        st(rec_in, 0xb0 + o, 8, s['gross'])
        st(rec_in, 0xb8 + o, 8, s['second'])
        st(rec_in, 0xc0 + o, 8, s['third'])

    def arg(name):
        return m.regs[R[name]]

    def user_at(ptr):
        return bytes(m.load(ptr + k, 1) for k in range(20))

    def entry_slot(e, kind):
        """Read back the entry handle: found -> (key, 'found'), vacant -> (key, 'vacant', slot)."""
        tag = m.load(e, 8)
        if kind == 'ext':
            if tag == 0:
                node, idx = m.load(e + 8, 8), m.load(e + 24, 8)
                return (m.load(node + 0x218 + idx * 8, 8), 'found')
            key, node = m.load(e + 8, 8), m.load(e + 16, 8)
            return (key, 'vacant', m.load(e + 32, 8) if node else None)
        if tag == 0:
            node, idx = m.load(e + 8, 8), m.load(e + 24, 8)
            return (m.load(node + 0xb8 + idx * 4, 4), 'found')
        node = m.load(e + 8, 8)
        return (m.load(e + 32, 4), 'vacant', m.load(e + 24, 8) if node else None)

    current = {}

    def ext_entry():
        user = user_at(arg('rsi'))
        calls.append(('ext_entry', user, arg('rdi') - rt.base))
        current['ext'] = user
        m.clobber(user_cells(user)['ext_map'].base)

    def ext_add():
        calls.append(('ext_add', entry_slot(arg('rdi'), 'ext')))
        m.clobber(user_cells(current['ext'])['ext'].base)

    def user_entry():
        user = user_at(arg('rsi'))
        calls.append(('user_entry', user, arg('rdi') - state.base))
        current['user'] = user
        m.clobber(user_cells(user)['rec'].base)

    def day_add():
        calls.append(('day_add', entry_slot(arg('rdi'), 'i32')))
        m.clobber(user_cells(current['user'])['day'].base)

    def total_add():
        calls.append(('total_add', entry_slot(arg('rdi'), 'i32')))
        m.clobber(total_cell.base)

    def split():
        a = arg('rcx')
        p, q = m.load(a, 8), m.load(a + 0x28, 8)
        calls.append(('split', user_at(arg('rsi')), arg('rdx'), {
            'primary': (p, m.load(a + 8, 8) if p else None, user_at(a + 0x10) if p else None),
            'secondary': (q, m.load(a + 0x30, 8) if q else None, user_at(a + 0x38) if q else None),
            'gross': m.load(a + 0x50, 8), 'second': m.load(a + 0x58, 8), 'third': m.load(a + 0x60, 8)}))
        m.clobber()

    def hook():
        calls.append(('overflow_hook', arg('rsi')))
        m.clobber()

    def price():
        calls.append(('default_price', arg('rdi') - state.base, arg('rsi')))
        m.clobber(s['default_price'])

    def pred():
        calls.append(('pred', arg('rdi') - state.base, arg('rsi')))
        m.clobber(0xdead_0000_0000 | s['pred'])

    def conv():
        calls.append(('conv', arg('rdi'), arg('rsi'), arg('rdx'), arg('rcx') - state.base))
        m.clobber(0xdead_0000_0000 | s['conv'][0])
        m.regs[R['rdx']] = s['conv'][1]

    m.stubs = {EXT_ENTRY: ext_entry, EXT_ADD: ext_add, USER_ENTRY: user_entry, DAY_ADD: day_add, TOTAL_ADD: total_add,
               SPLIT: split, OVERFLOW_HOOK_SLOT: hook, PRICE_SLOT: price, PRED_SLOT: pred, CONVERT: conv}
    m.regs[4] = stack.base + 0x3000 + 8     # rsp+8 is 16-byte aligned on entry
    m.regs[R['rbx']], m.regs[R['rbp']], m.regs[R['r12']], m.regs[R['r13']], m.regs[R['r14']], m.regs[R['r15']] = (
        0x1111, 0x2222, 0x3333, 0x4444, 0x5555, 0x6666)
    saved = list(m.regs)
    m.regs[R['rdi']], m.regs[R['rsi']], m.regs[R['rdx']], m.regs[R['rcx']] = state.base, rec_in.base, s['side'], rt.base
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
    out['users'] = {}
    for user, c in users.items():
        out['users'][user] = dict(scaled=m.load(c['rec'].base, 8), raw=m.load(c['rec'].base + 8, 8),
                                  ext=m.load(c['ext'].base, 8),
                                  day=(m.load(c['day'].base, 8), m.load(c['day'].base + 8, 8)))
    out['total'] = (m.load(total_cell.base, 8), m.load(total_cell.base + 8, 8))
    out['seen'] = m.seen
    return out


def to_i64(x):
    """Conversion blocks: non-finite gives 0, else clamp and truncate."""
    if math.isnan(x) or math.isinf(x):
        return 0
    if x <= -(2.0 ** 63):
        return I64_MIN
    if x >= 2.0 ** 63:
        return I64_MAX
    return int(x)


def product(a, b):
    """u64 product; overflow or a value above MUL_MAX gives 0."""
    v = a * b
    return 0 if v > U64 or v > MUL_MAX else v


def weighted(value, factor):
    return max(to_i64(float(value) * factor), 0)


def raw_notional(s):
    """The value before any scaling, with its route."""
    if s['q'] == 0 or s['q'] in s['t1']:
        n = product(s['a'], s['b'])
        ok, value = s['conv']
        return (value if ok & 1 and value < LIMIT else n), 'direct'
    if s['x'] in s['t3']:
        return product(s['t2'].get(s['x'], s['default_price']), s['b']), 'priced'
    return 0, 'none'


def model(s):
    """Closed form of the function, written from the semantics, not from the evaluator."""
    out = {'status': 'ok', 'hooks': 0, 'users': {}, 'total': (s['start'] or {}).get('total', (0, 0))}
    start = s['start'] or {}

    def add(a, b):
        out['hooks'] += a + b > U64
        return min(a + b, U64)

    def user(u):
        b = start.get(u, {})
        return out['users'].setdefault(u, dict(scaled=b.get('scaled', 0), raw=b.get('raw', 0), ext=b.get('ext', 0),
                                               day=b.get('day', (0, 0))))

    if s['t'] >= s['table_len']:
        out['status'] = f"panic:{LOCATIONS['table_index']:#x}"
        return out
    raw, route = raw_notional(s)
    if raw > MUL_MAX:
        raise EvidenceError(f'raw value {raw:#x} would reach a sign panic')
    scaled = raw
    if s['t4'].get(s['q']) == 1:
        scaled = weighted(raw, s['m'])
    if s['x'] in s['t5']:
        scaled //= 5
    elif s['pred']:
        scaled = weighted(scaled, s['weight'])
    raw_u, scaled_u = raw // SCALE, scaled // SCALE
    out.update(raw=raw, scaled=scaled, route=route, raw_units=raw_u, scaled_units=scaled_u)
    own, other = USER_BYTES[s['side']], USER_BYTES[1 - s['side']]
    if s['mode'] == 2:
        if s['pred']:
            return out
        rows = [(own, s['tag'] == s['side'])]
    else:
        if s['pred'] and s['gross']:
            user(other)['ext'] = add(user(other)['ext'], scaled_u)
        if not s['pred'] or s['gross']:
            user(own)['ext'] = add(user(own)['ext'], scaled_u)
        if s['pred'] and not s['gross']:
            return out
        rows = [(own, s['tag'] == s['side'])]
        if s['pred']:
            rows.append((other, s['tag'] != s['side']))
    for u, match in rows:
        r = user(u)
        if scaled > SCALE - 1:
            r['scaled'] = add(r['scaled'], scaled_u)
            r['raw'] = add(r['raw'], raw_u)
            day = list(r['day'])
            day[int(match)] = add(day[int(match)], scaled_u)
            r['day'] = tuple(day)
        else:
            r['raw'] = add(r['raw'], raw_u)
    if len(rows) == 2 or s['side']:
        out['total'] = (add(out['total'][0], scaled_u), add(out['total'][1], raw_u))
    return out


def tree_ok(handle, key, keys, deep):
    keys = sorted(keys)
    if handle[0] & 0xffffffff != key & 0xffffffff:
        return False
    if key in keys:
        return handle[1] == 'found'
    if handle[1] != 'vacant':
        return False
    if not keys:
        return handle[2] is None
    if deep:
        mid = keys[len(keys) // 2]
        keys = [k for k in keys if k != mid and (k < mid) == (key < mid)]
    return handle[2] == sum(k < key for k in keys)


def expected_calls(s, want):
    """Stub call order, overflow hooks left out, as far as the model decides it."""
    if want['status'] != 'ok':
        return None
    own, other = USER_BYTES[s['side']], USER_BYTES[1 - s['side']]
    names = []
    if s['mode'] != 2:
        if s['pred'] and s['gross']:
            names += [('ext_entry', other), ('ext_add',), ('ext_entry', own), ('ext_add',)]
        elif not s['pred']:
            names += [('ext_entry', own), ('ext_add',)]
        names.append(('split', own))
        if s['pred'] and not s['gross']:
            return names
    elif s['pred']:
        return names
    rows = [own, other] if s['pred'] else [own]
    for u in rows:
        names.append(('user_entry', u))
        if want['scaled'] > SCALE - 1:
            names.append(('day_add',))
    if len(rows) == 2 or s['side']:
        names.append(('total_add',))
    return names


def compare(s, got, want):
    bad = [k for k in ('status',) if got[k] != want[k]]
    if got['status'] != 'ok' or bad:
        return bad
    if got['users'] != want['users']:
        bad.append('users')
    if got['total'] != want['total']:
        bad.append('total')
    if sum(c[0] == 'overflow_hook' for c in got['calls']) != want['hooks']:
        bad.append('hooks')
    keep = ('ext_entry', 'ext_add', 'split', 'user_entry', 'day_add', 'total_add')
    seq = [c[:2] if c[0] in ('ext_entry', 'split', 'user_entry') else c[:1] for c in got['calls'] if c[0] in keep]
    if seq != expected_calls(s, want):
        bad.append('call-order')
    for c in got['calls']:
        if c[0] == 'ext_add' and not tree_ok(c[1], s['q'], s['ext_keys'], s['deep']):
            bad.append('ext-entry')
        if c[0] == 'day_add' and not tree_ok(c[1], s['day'], s['day_keys'], s['deep']):
            bad.append('day-entry')
        if c[0] == 'total_add' and not tree_ok(c[1], s['day'], s['total_keys'], s['deep']):
            bad.append('total-entry')
        if c[0] == 'pred' and c[2] != s['x']:
            bad.append('pred-key')
        if c[0] == 'conv':
            key = s['q']
            price = s['t2'].get(key, s['default_price'])
            if c[1:4] != (product(s['a'], s['b']), key, price) or c[4] != 0x10:
                bad.append('conv-args')
        if c[0] == 'split':
            d = c[3]
            if c[2] != s['q'] or (d['gross'], d['second'], d['third']) != (s['gross'], s['second'], s['third']):
                bad.append('split-args')
            p = (1, s['primary_amt'], bytes(0xb0 + k for k in range(20))) if s['mode'] & 1 else (0, None, None)
            q = (1, s['secondary_amt'], bytes(0xc0 + k for k in range(20))) if s['secondary'] else (0, None, None)
            if d['primary'] != p or d['secondary'] != q:
                bad.append('split-options')
    return bad


ROUTES = (dict(q=0), dict(t1=(Q_ID,)), dict(t1=(Q_ID, 500), t2={Q_ID: 9 * 10 ** 7}), dict(t3=()),
          dict(t3=(X_ID,)), dict(t3=(X_ID, 5), t2={X_ID: 4 * 10 ** 7}), dict(t1=(5,), t3=(X_ID, 9), t2={5: 1}))
CONVERSIONS = ((0, 5 * 10 ** 9), (1, 5 * 10 ** 9), (1, LIMIT - 1), (1, LIMIT))
WEIGHTS = (dict(), dict(t5=(X_ID,)), dict(pred=1), dict(t5=(X_ID, 9), pred=1), dict(t5=(1, 2)))
FLAGS = (dict(), dict(t4={Q_ID: 0}), dict(t4={Q_ID: 1}), dict(t4={Q_ID: 2}), dict(t4={0: 1}), dict(t4={1000: 1}))


def route_grid():
    for route in ROUTES:
        for conv in CONVERSIONS:
            for weight in WEIGHTS:
                for flag in FLAGS:
                    yield 'route', scenario(conv=conv, m=0.5, weight=0.25, **route, **weight, **flag)


def arithmetic_grid():
    for price, b in ((MUL_MAX, 1), (MUL_MAX + 1, 1), (1, MUL_MAX), (1 << 32, 1 << 32), (U64, 2), (10 ** 7, 3)):
        yield 'arith', scenario(t3=(X_ID,), default_price=price, b=b)
        yield 'arith', scenario(t3=(X_ID,), t2={X_ID: price}, b=b, side=1)
    edge = int(MUL_MAX // 3)
    for a, b in ((0, 5), (1, MUL_MAX), (1, MUL_MAX + 1), (3, edge), (3, edge + 1), (1 << 32, 1 << 31),
                 (1 << 32, 1 << 32), (U64, 2), (2, 1 << 63), (U64, U64), (10 ** 6, 1), (999999, 1), (5 * 10 ** 6, 1),
                 (4999999, 1)):
        for m_ in (1.0, 0.5, 0.0, -1.0, 2.0, 1e300, math.inf, math.nan):
            for extra in (dict(), dict(t4={Q_ID: 1})):
                yield 'arith', scenario(a=a, b=b, m=m_, t1=(Q_ID,), weight=m_, pred=1 if extra else 0, **extra)
                yield 'arith', scenario(a=a, b=b, m=m_, t1=(Q_ID,), t5=(X_ID,), side=1, **extra)


def dispatch_grid():
    for mode in (2, 0, 1):
        for pred in (0, 1):
            for gross in (0, 3):
                for side in (0, 1):
                    for tag in (0, 1):
                        for a in (3 * 10 ** 7, 1):
                            for second in (0, 1):
                                yield 'dispatch', scenario(a=a, mode=mode, pred=pred, gross=gross, side=side, tag=tag,
                                                           t1=(Q_ID,), secondary=second, primary_amt=8,
                                                           secondary_amt=9, second=6, third=7)


def saturation_grid():
    top = U64 - 3
    full = dict(scaled=top, raw=top, ext=top, day=(top, top))
    for side in (0, 1):
        for tag in (0, 1):
            for mode, pred, gross in ((2, 0, 0), (0, 0, 0), (1, 1, 3)):
                for small in (False, True):
                    start = {USER_BYTES[0]: full, USER_BYTES[1]: full, 'total': (top, top)}
                    yield 'saturate', scenario(a=(10 ** 6 if small else 3 * 10 ** 10), b=(1 if small else 10 ** 7),
                                               t1=(Q_ID,), side=side, tag=tag, mode=mode, pred=pred, gross=gross,
                                               start=start)
                    yield 'saturate', scenario(a=999999, b=1, t1=(Q_ID,), side=side, tag=tag, mode=mode, pred=pred,
                                               gross=gross, start=start)
                    yield 'saturate', scenario(a=3 * 10 ** 10, b=10 ** 7, t1=(Q_ID,), t4={Q_ID: 1}, m=0.0, side=side,
                                               tag=tag, mode=mode, pred=pred, gross=gross, start=start)


def tree_grid():
    for deep in (False, True):
        for keys in ((), (10, 20, 30), (5, 40, 77), (-3, 20, 90)):
            if deep and len(keys) < 3:
                continue
            ukeys = tuple(k for k in keys if k >= 0)
            for q in (5, 15, 25, 77, 90, 95):
                yield 'tree', scenario(q=q, deep=deep, t1=(q,), t2={k: 5 * 10 ** 7 + k for k in ukeys}, conv=(1, 10 ** 12))
            for day in (5, 20, 21, 40):
                for side, mode, pred, gross in ((0, 2, 0, 0), (1, 0, 0, 0), (1, 1, 1, 3)):
                    yield 'tree', scenario(a=3 * 10 ** 10, side=side, day=day, day_keys=keys, total_keys=keys,
                                           ext_keys=ukeys, deep=deep, mode=mode, pred=pred, gross=gross,
                                           t1=(Q_ID,))
            for x, q in ((77, 5), (5, 77), (10, 90), (90, 10), (40, 41)):
                for use in ('t1', 't3', 't5', 't4', 't2'):
                    extra = {'t2': {k: 5 * 10 ** 7 + k for k in ukeys}} if use == 't2' else \
                        {'t4': {k: 1 for k in ukeys}} if use == 't4' else {use: ukeys}
                    yield 'tree', scenario(x=x, q=q, deep=deep, m=0.5, conv=(1, 10 ** 12), pred=1 if use == 't5' else 0,
                                           **extra)
                yield 'tree', scenario(x=x, q=q, deep=deep, t3=ukeys, t2={k: 5 * 10 ** 7 + k for k in ukeys})


def admission_grid():
    yield 'admit', scenario(t=4)
    yield 'admit', scenario(t=3)
    yield 'admit', scenario(t=U64)
    yield 'admit', scenario(t=0, table_len=0)


def all_vectors():
    for grid in (route_grid, arithmetic_grid, dispatch_grid, saturation_grid, tree_grid, admission_grid):
        yield from grid()


def constants(img):
    c = {'low': img.f64(LOW_VA), 'high': img.f64(HIGH_VA), 'big': img.f64(BIG_VA)}
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
    want = {FIVE_MAGIC: 1, MILLION_MAGIC: 1, 0x7fffffffffffffff: 2, 0x7fefffffffffffff: 2, LIMIT: 1, MUL_MAX: 2}
    if dict(got) != want:
        raise EvidenceError(f'64-bit immediates differ: { {hex(k): v for k, v in got.items()} }')


def division_exact(magic, shift, divisor):
    """`mul magic; shr rdx,shift` equals floor(n / divisor) for every u64 n."""
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


def sites(insns):
    """Calls through the overflow hook slot, from decoded operands only."""
    hooks = [i.va for i in insns if i.op == 'call' and i.ops[0][0] == 'm' and i.ops[0][1] is None
             and i.ops[0][4] == OVERFLOW_HOOK_SLOT]
    if len(hooks) != HOOK_CALLS:
        raise EvidenceError(f'{len(hooks)} hook calls')
    return hooks


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


def row_text(group, s, got, want):
    return '\t'.join(str(v) for v in (group, want.get('route', '-'), s['a'], s['b'], repr(s['m']), repr(s['weight']),
                                      s['pred'], s['mode'], s['side'], got['status'], want.get('raw', '-'),
                                      want.get('scaled', '-'), want.get('raw_units', '-'), want.get('scaled_units', '-')))


def check_unreached(insns, seen):
    """Only padding and the three listed blocks may stay unexecuted."""
    missed = {i.va for i in insns if i.va not in seen and i.op != 'nop'}
    listed = {i.va for i in insns for lo, hi, _ in UNREACHED if lo <= i.va < hi}
    if missed != listed:
        raise EvidenceError(f'unexpected unexecuted code {sorted(hex(v) for v in missed ^ listed)}')


def analyse(data, patches=None, vectors=all_vectors):
    full = vectors is all_vectors
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
    hooks = sites(insns)
    if not division_exact(FIVE_MAGIC, 2, 5) or not division_exact(MILLION_MAGIC, 18, SCALE):
        raise EvidenceError('division constant is not exact')
    if LIMIT != U64 // 100:
        raise EvidenceError('limit constant does not have the expected relation')
    seen, rows, groups, failures = set(), [], Counter(), []
    statuses, routes = Counter(), Counter()
    for group, s in vectors():
        got = evaluate(img, insns, s)
        want = model(s)
        bad = compare(s, got, want)
        groups[group] += 1
        statuses[got['status']] += 1
        routes[want.get('route', 'panic')] += 1
        seen |= got['seen']
        if bad:
            failures.append({'group': group, 'fields': bad, 'a': s['a'], 'b': s['b'], 'mode': s['mode'],
                             'pred': s['pred'], 'side': s['side']})
        rows.append(row_text(group, s, got, want))
    if failures:
        raise EvidenceError(f'{len(failures)} vectors disagree; first {failures[0]}')
    missed = [i for i in insns if i.va not in seen]
    if full:
        check_unreached(insns, seen)
    result = {
        'component': 'fees', 'binary': BINARY, 'sha256': digest, 'coordinates': 'virtual addresses (ELF VA)',
        'question': 'volume path at 0x372faa0, the sibling of 0x37153f0',
        'fde_table_entries': fdes.count,
        'function': {'start': hex(r['start']), 'end': hex(r['end']), 'fde': hex(r['fde']),
                     'size': r['end'] - r['start'], 'instructions': len(insns), 'pointer_slot': hex(POINTER_SLOT)},
        'constants': {'conversion_low': c['low'], 'conversion_high': c['high'], 'conversion_big': c['big'],
                      'five_magic': hex(FIVE_MAGIC), 'million_magic': hex(MILLION_MAGIC), 'million_shift': 18,
                      'product_max': hex(MUL_MAX), 'limit': hex(LIMIT), 'threshold': SCALE - 1,
                      'limit_is_u64_max_div_100': True, 'divisions_exact_for_all_u64': True},
        'immediates_64': {hex(k): v for k, v in sorted(immediates(insns).items())},
        'overflow_hook_calls': [hex(v) for v in hooks],
        'locations': {k: decode_location(img, v) for k, v in LOCATIONS.items()},
        'slot_users': slot_users(img, fdes),
        'evaluation': {'vectors': sum(groups.values()), 'groups': dict(sorted(groups.items())),
                       'routes': dict(sorted(routes.items())),
                       'status': dict(sorted(statuses.items())), 'mismatches': 0,
                       'instructions_executed': len(insns) - len(missed),
                       'padding_nops_not_executed': sum(i.op == 'nop' for i in missed),
                       'blocks_not_executed': [{'start': hex(lo), 'end': hex(hi), 'why': why}
                                               for lo, hi, why in UNREACHED]},
    }
    result['summary'] = {'instructions': len(insns), 'vectors': sum(groups.values()), 'mismatches': 0,
                         'instructions_not_executed': len(missed), 'hook_calls': len(hooks),
                         'blocks_not_executed': len(UNREACHED)}
    return result, img, insns, rows


def write(out, result, img, insns, rows):
    out.mkdir(parents=True, exist_ok=True)
    (out / 'evidence.json').write_text(json.dumps(result, indent=2, sort_keys=True) + '\n')
    lines = ['va\tsize\tbytes\tdecoded']
    lines += [f'{i.va:#x}\t{i.size}\t{i.raw.hex()}\t{show(i)}' for i in insns]
    (out / 'instructions.tsv').write_text('\n'.join(lines) + '\n')
    head = ('group\troute\ta\tb\tm\tweight\tpred\tmode\tside\tstatus\traw\tscaled\traw_units\tscaled_units')
    (out / 'vectors.tsv').write_text('\n'.join([head] + rows) + '\n')


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
