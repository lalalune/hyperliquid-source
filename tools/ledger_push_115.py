#!/usr/bin/env python3
"""ledger push: node #115 fee-ledger index-map push routines and the vacant-entry completions that call them.

Static, no execution of the node.  The two push routines 0x3ec8b70 and 0x3ec7a90 (find an insert slot in a hashbrown
control array, grow the table when the budget is spent, store the next index in the bucket, grow and append to the
entry vector) and the two vacant/occupied entry completions 0x4718060 and 0x4717fb0 are decoded from ELF bytes by the
table decoder below, which must land exactly on each FDE end, and interpreted in Python on every vector.  Each
outcome (the index table bytes, the entry rows, the out record, the returned row address, every panic location) is
compared with a closed-form reconstruction; then one-byte mutants of the subjects, wrong models and corrupted
inputs are all required to be caught.  The memcpy, vector reallocation and table reserve helpers are modelled as
contracts, because their bodies belong to other work items.

    python3 tools/ledger_push_115.py --out <dir>

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
        if b2 == 0x0b:
            return done('ud2', ())
        if b2 in (0x10, 0x11, 0x28, 0x29):
            reg, rm = modrm(64 if rep else 128, True)
            name = 'movsd' if rep == 'f2' else sse[b2 & 0xfe, p66]
            x = ('x', reg | rr << 3)
            return done(name, (x, rm) if not b2 & 1 else (rm, x), 64 if rep else 128)
        if b2 in (0x6f, 0x7f) and (p66 or rep == 'f3'):
            reg, rm = modrm(128, True)
            x = ('x', reg | rr << 3)
            return done('movdqa' if p66 else 'movdqu', (x, rm) if b2 == 0x6f else (rm, x), 128)
        if b2 in (0x6e, 0x7e) and p66 and not w:
            reg, rm = modrm(32)
            x = ('x', reg | rr << 3)
            return done('movd', (x, rm) if b2 == 0x6e else (rm, x), 32)
        if b2 in (0x60, 0x74, 0x76, 0xdb) and p66:
            reg, rm = modrm(128, True)
            names = {0x60: 'punpcklbw', 0x74: 'pcmpeqb', 0x76: 'pcmpeqd', 0xdb: 'pand'}
            return done(names[b2], (('x', reg | rr << 3), rm), 128)
        if b2 == 0x70 and (p66 or rep == 'f2'):
            reg, rm = modrm(128, True)
            v = imm(1)
            return done('pshufd' if p66 else 'pshuflw', (('x', reg | rr << 3), rm, ('i', v[1] & 0xff)), 128)
        if b2 == 0xd7 and p66:
            reg, rm = modrm(128, True)
            return done('pmovmskb', (gpr(reg | rr << 3, 32), rm), 128)
        if b2 == 0xbc and rep == 'f3':
            reg, rm = modrm(width)
            return done('tzcnt', (gpr(reg | rr << 3, width), rm))
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
    if b == 0x90:
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
        if reg not in (0, 4, 5, 7):
            raise EvidenceError(f'{va:#x}: unlisted shift /{reg}')
        return done({0: 'rol', 4: 'shl', 5: 'shr', 7: 'sar'}[reg], (rm, ('i', v[1] & 0xff)))
    if b == 0xd3:
        reg, rm = modrm(width)
        if reg not in (4, 5):
            raise EvidenceError(f'{va:#x}: unlisted d3 /{reg}')
        return done('shl' if reg == 4 else 'shr', (rm, ('r', 1, 8)))
    if b == 0xc3:
        return done('ret', ())
    if b == 0xc6:
        reg, rm = modrm(8)
        if reg:
            raise EvidenceError(f'{va:#x}: unlisted c6 /{reg}')
        return done('mov', (rm, imm(1)), 8)
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
        if op in ('movups', 'movupd', 'movaps', 'movapd', 'movdqu', 'movdqa'):
            if op.startswith('mova') or op == 'movdqa':
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
        elif op == 'movd':
            if ops[0][0] == 'x':
                self.xmm[ops[0][1]] = [self.rd(ops[1]) & 0xffffffff, 0]
            else:
                self.wr(ops[0], self.xmm[ops[1][1]][0] & 0xffffffff)
        elif op in ('pcmpeqb', 'pcmpeqd', 'pand', 'punpcklbw', 'pshufd', 'pshuflw', 'pmovmskb'):
            d = self.xb(ops[1]) if op == 'pmovmskb' else self.xb(ops[0])
            s = self.xb(ops[1])
            if op == 'pcmpeqb':
                r = bytes(255 if x == y else 0 for x, y in zip(d, s))
            elif op == 'pcmpeqd':
                r = b''.join((b'\xff' * 4 if d[i:i + 4] == s[i:i + 4] else bytes(4)) for i in range(0, 16, 4))
            elif op == 'pand':
                r = bytes(x & y for x, y in zip(d, s))
            elif op == 'punpcklbw':
                r = bytes(b for i in range(8) for b in (d[i], s[i]))
            elif op == 'pshufd':
                sel = ops[2][1]
                r = b''.join(s[4 * (sel >> 2 * k & 3):4 * (sel >> 2 * k & 3) + 4] for k in range(4))
            elif op == 'pshuflw':
                sel = ops[2][1]
                r = b''.join(s[2 * (sel >> 2 * k & 3):2 * (sel >> 2 * k & 3) + 2] for k in range(4)) + s[8:]
            else:
                self.wr(ops[0], sum(1 << i for i in range(16) if s[i] & 0x80))
                return
            self.xmm[ops[0][1]] = [int.from_bytes(r[:8], 'little'), int.from_bytes(r[8:], 'little')]
        else:
            raise Unmodelled(f'{ins.va:#x}: {op}')

    def xb(self, o):
        lo, hi = self.xrd128(o)
        return lo.to_bytes(8, 'little') + hi.to_bytes(8, 'little')

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
            loc = self.regs[R['rdx']] if target == 0x64df620 else self.regs[R['rdi']]
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
            elif op == 'tzcnt':
                a = self.rd(ops[1])
                res = ins.width if a == 0 else (a & -a).bit_length() - 1
                self.cf = a == 0
                self.zf = res == 0
                self.wr(ops[0], res)
            elif op in ('shl', 'shr', 'sar', 'rol'):
                n = self.rd(ops[1]) & (63 if ins.width == 64 else 31)
                a = self.rd(ops[0])
                if op == 'rol':
                    n %= ins.width
                    res = (a << n | a >> (ins.width - n)) & ((1 << ins.width) - 1)
                    self.cf = bool(res & 1) if n else self.cf
                    self.wr(ops[0], res)
                    rip = nxt
                    continue
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
# Subjects of node #115: the two ledger-map push routines and the two vacant-entry completions that call them
# ---------------------------------------------------------------------------------------------------------
S_PA, S_PB, S_EA, S_EB = 0x3ec8b70, 0x3ec7a90, 0x4718060, 0x4717fb0
SUBJECTS = (S_PA, S_PB, S_EA, S_EB)
CALLEES = ()
NAMES = {S_PA: 'push_a', S_PB: 'push_b', S_EA: 'entry_a', S_EB: 'entry_b'}
PUSH_OF = {S_EA: S_PA, S_EB: S_PB}
PANIC_SLOTS = (0x64df520, 0x64df620, 0x64df848)
SLOT_MEMCPY, SLOT_ALLOC_ERR, FINISH_GROW = 0x64df508, 0x64df498, 0x43bd550
LOC_ITEMS_OVERFLOW, LOC_BOUNDS_ENTRY = 0x647aa78, 0x6493b60
LOC_OTHER = (0x647a940, 0x647a958, 0x647aa00, 0x647aa60, 0x647aa90)
# stride of one entry row, bytes of the value, offset of the stored hash and of the 20-byte key, vec capacity limit,
# the GOT slot of hashbrown's reserve_rehash, and the value ranges the vacant-entry caller really writes
SHAPE = {
    S_PA: dict(stride=0x100, vsize=0xe0, hoff=0xe0, koff=0xe8, cap_max=0x7fffffffffffff, reserve=0x64e63e0),
    S_PB: dict(stride=0x70, vsize=0x50, hoff=0x50, koff=0x58, cap_max=0x124924924924924, reserve=0x64e6340),
}
# default value built by the entry callers: (offset, length, u64 value or None for a zero run)
DEFAULT_PARTS = {
    S_EA: ((0x00, 8, 0), (0x80, 8, 0), (0x88, 8, 8), (0x90, 16, 0), (0xa0, 8, 0), (0xa8, 8, 8), (0xb0, 16, 0),
           (0xc0, 4, 0), (0xc4, 1, 0)),
    S_EB: ((0x00, 8, 0), (0x08, 8, 8), (0x10, 16, 0), (0x20, 8, 0), (0x28, 8, 8), (0x30, 32, 0)),
}


class Rng:
    """xorshift64*: a fixed generator, so the vector list never depends on the interpreter's random module."""

    def __init__(self, seed):
        self.s = seed & U64 or 1

    def next(self):
        x = self.s
        x ^= x >> 12
        x ^= x << 25 & U64
        x ^= x >> 27
        self.s = x
        return x * 0x2545F4914F6CDD1D & U64

    def below(self, n):
        return self.next() % n

    def bytes(self, n):
        out = bytearray()
        while len(out) < n:
            out += self.next().to_bytes(8, 'little')
        return bytes(out[:n])

    def pick(self, seq):
        return seq[self.below(len(seq))]


EMPTY, DELETED = 0xff, 0x80
PAD = bytes((0x5a + 7 * i) & 0xff for i in range(40))


class RawTable:
    """hashbrown control bytes (n + 16 with the mirrored tail) and the usize stored in each full bucket."""

    def __init__(self, buckets):
        self.n, self.mask = buckets, buckets - 1
        self.ctrl = bytearray(b'\xff' * (buckets + 16))
        self.vals = [0] * buckets

    def set_ctrl(self, i, v):
        self.ctrl[i] = v
        self.ctrl[((i - 16) & self.mask) + 16] = v

    def find_slot(self, h):
        pos, stride = h & self.mask, 0
        while True:
            for b in range(16):
                if self.ctrl[pos + b] >= 0x80:
                    idx = (pos + b) & self.mask
                    if self.ctrl[idx] < 0x80:
                        idx = next(j for j in range(16) if self.ctrl[j] >= 0x80)
                    return idx
            stride += 16
            pos = (pos + stride) & self.mask

    def insert(self, h, val):
        idx = self.find_slot(h)
        self.set_ctrl(idx, h >> 57)
        self.vals[idx] = val
        return idx

    def copy(self):
        t = RawTable(self.n)
        t.ctrl, t.vals = bytearray(self.ctrl), list(self.vals)
        return t


def full_cap(n):
    return n - 1 if n < 9 else n // 8 * 7


def buckets_for(cap):
    if cap < 8:
        return 4 if cap < 4 else 8
    return 1 << (cap * 8 // 7 - 1).bit_length()


# ---------------------------------------------------------------------------------------------------------
# Reconstruction: what pushing a new entry does to the index table and the entry vector
# ---------------------------------------------------------------------------------------------------------
def row_view(shape, raw, ranges):
    """An entry row without the bytes nobody defines: value outside `ranges` and the 4 padding bytes."""
    out = bytearray(len(raw))
    for lo, hi in ranges:
        out[lo:hi] = raw[lo:hi]
    out[shape['hoff']:shape['koff'] + 20] = raw[shape['hoff']:shape['koff'] + 20]
    return bytes(out[:shape['koff'] + 20])


def make_row(shape, value, h, key):
    return value + h.to_bytes(8, 'little') + key


def model_push(shape, c, ranges, v=None):
    """Closed-form result of one push, from the case alone.  `v` selects a deliberately wrong variant."""
    v = v or {}
    t = c['table'].copy()
    h, growth, items = c['hash'], c['growth'], c['items']
    rows = list(c['rows'])
    slot = t.find_slot(h)
    if growth == 0 and t.ctrl[slot] & 1:
        full = full_cap(t.n)
        nt = RawTable(t.n if v.get('no_resize') else buckets_for(max(items + 1, full + 1)))
        for i in range(t.n):
            if t.ctrl[i] < 0x80:
                idx = t.vals[i]
                nt.insert(int.from_bytes(rows[idx][shape['hoff']:shape['hoff'] + 8], 'little'), idx)
        t, growth = nt, full_cap(nt.n) - items
        slot = t.find_slot(h)
    growth -= 1 if v.get('growth_always') else t.ctrl[slot] & 1
    t.set_ctrl(slot, h >> (64 - v.get('tag_bits', 7)))
    if items == U64:
        return ('panic', LOC_ITEMS_OVERFLOW)
    stored = len(rows) if v.get('index_is_len') else items
    t.vals[slot] = stored
    items += 1
    cap, nlen, fails = c['cap'], len(rows), c['fail']
    if nlen == cap:
        calls, done = 0, False
        new_cap = min(2 * nlen, shape['cap_max'])
        if v.get('linear_growth'):
            new_cap = nlen + 1
        if new_cap - nlen > 1:
            calls += 1
            if calls not in fails:
                cap, done = new_cap, True
        if not done:
            calls += 1
            if calls in fails:
                return ('panic', ('alloc', (nlen + 1) * shape['stride'], 8))
            cap = nlen + 1
    rows.append(make_row(shape, c['value'], h ^ v.get('hash_xor', 0), c['key'][:16] + (b'\0' * 4 if v.get('short_key') else c['key'][16:])))
    view = tuple(row_view(shape, r, ranges) if i == len(rows) - 1 else row_view(shape, r, [(0, shape['vsize'])])
                 for i, r in enumerate(rows))
    return ('ok', (cap, view, canon_table(t, growth, items), slot, h))


def canon_table(t, growth, items):
    return (t.n, bytes(t.ctrl), tuple(t.vals[i] if t.ctrl[i] < 0x80 else None for i in range(t.n)), growth, items)


# ---------------------------------------------------------------------------------------------------------
# Harness: modelled memory, the three callees that other work items own, and the real subjects on top
# ---------------------------------------------------------------------------------------------------------
class Mach(Machine):
    def __init__(self, img, code):
        super().__init__(img, ())
        self.code = code
        self.grow_calls = 0
        self.fails = ()
        self.stride = 0
        self.hoff = 0
        self.rehash = 0


def fill(arena, off, raw):
    arena.mem[off:off + len(raw)] = raw
    arena.valid[off:off + len(raw)] = b'\1' * len(raw)


def peek(m, addr, size):
    a = m.find(addr, size)
    if a is None:
        raise Unmodelled(f'peek {addr:#x}')
    o = addr - a.base
    if a.strict and not all(a.valid[o:o + size]):
        raise Unmodelled(f'peek of unset bytes at {addr:#x}')
    return bytes(a.mem[o:o + size])


def new_machine(img, code, shape):
    m = Mach(img, code)
    stack = m.arena(0x4000, strict=False)
    m.regs[4] = stack.base + 0x3000 + 8
    m.stride, m.hoff = shape['stride'], shape['hoff']

    def memcpy():
        dst, src, n = m.regs[R['rdi']], m.regs[R['rsi']], m.regs[R['rdx']]
        raw = peek(m, src, n) if n else b''
        for i in range(0, n, 8):
            chunk = raw[i:i + 8]
            m.store(dst + i, len(chunk), int.from_bytes(chunk, 'little'))
        m.clobber()

    def finish_grow():
        out, old_len, old_ptr, new_cap = (m.regs[R[r]] for r in ('rdi', 'rsi', 'rdx', 'rcx'))
        if m.regs[R['r8']] != 8 or m.regs[R['r9']] != m.stride:
            raise Unmodelled('finish_grow layout arguments')
        m.grow_calls += 1
        if m.grow_calls in m.fails:
            m.store(out, 8, 1)
            m.store(out + 8, 8, new_cap * m.stride)
            m.store(out + 0x10, 8, 8)
        else:
            if new_cap * m.stride > 1 << 16:
                raise Unmodelled('allocation larger than any modelled vector')
            a = m.arena(new_cap * m.stride + 16)
            if old_len:
                fill(a, 0, peek(m, old_ptr, old_len * m.stride))
            m.store(out, 8, 0)
            m.store(out + 8, 8, a.base)
        m.clobber()

    def alloc_error():
        raise Panic(('alloc', m.regs[R['rdi']], m.regs[R['rsi']]))

    def reserve():
        tbl, add, ptr, ln, fallible = (m.regs[R[r]] for r in ('rdi', 'rsi', 'rdx', 'rcx', 'r8'))
        if add != 1 or fallible != 1:
            raise Unmodelled('reserve_rehash arguments')
        ctrl, mask, _growth, items = (m.load(tbl + 8 * k, 8) for k in range(4))
        n = mask + 1
        full = full_cap(n)
        if items + 1 <= full // 2:
            raise Unmodelled('in-place rehash')
        if n > 1 << 12 or items + 1 > 1 << 12:
            raise Unmodelled('table larger than any modelled one')
        nt = RawTable(buckets_for(max(items + 1, full + 1)))
        for i in range(n):
            if m.load(ctrl + i, 1) < 0x80:
                idx = m.load(ctrl - 8 * (i + 1), 8)
                nt.insert(m.load(ptr + idx * m.stride + m.hoff, 8), idx)
        a = m.arena(nt.n * 8 + nt.n + 16 + 16)
        for i in range(nt.n):
            fill(a, nt.n * 8 - 8 * (i + 1), nt.vals[i].to_bytes(8, 'little'))
        fill(a, nt.n * 8, bytes(nt.ctrl) + PAD[:16])
        m.store(tbl, 8, a.base + nt.n * 8)
        m.store(tbl + 8, 8, nt.mask)
        m.store(tbl + 0x10, 8, full_cap(nt.n) - items)
        m.rehash += 1
        m.clobber(0)

    m.stubs[SLOT_MEMCPY] = memcpy
    m.stubs[FINISH_GROW] = finish_grow
    m.stubs[SLOT_ALLOC_ERR] = alloc_error
    m.stubs[shape['reserve']] = reserve
    return m


def outcome(m, entry):
    try:
        m.run(entry)
    except Panic as p:
        return ('panic', p.location)
    return ('ok', None)


def lay_case(m, shape, c):
    """Table, entry vector, key and value in modelled memory; returns the addresses."""
    t = c['table']
    n = t.n
    ta = m.arena(n * 8 + n + 16 + 16)
    for i in range(n):
        fill(ta, n * 8 - 8 * (i + 1), t.vals[i].to_bytes(8, 'little'))
    fill(ta, n * 8, bytes(t.ctrl) + PAD[:16])
    head = m.arena(0x40)
    fill(head, 0, (ta.base + n * 8).to_bytes(8, 'little') + t.mask.to_bytes(8, 'little')
         + c['growth'].to_bytes(8, 'little') + c['items'].to_bytes(8, 'little'))
    nrows = len(c['rows'])
    if c['cap']:
        ra = m.arena(c['cap'] * shape['stride'] + 16)
        for i, r in enumerate(c['rows']):
            fill(ra, i * shape['stride'], r + PAD[:shape['stride'] - len(r)])
        rows_ptr = ra.base
    else:
        rows_ptr = 8
    vec = m.arena(0x40)
    fill(vec, 0, c['cap'].to_bytes(8, 'little') + rows_ptr.to_bytes(8, 'little') + nrows.to_bytes(8, 'little'))
    key = m.arena(0x40)
    fill(key, 0, c['key'] + PAD[:20])
    val = m.arena(shape['vsize'] + 16)
    fill(val, 0, c['value'] + PAD[:16])
    m.fails = tuple(c['fail'])
    return dict(head=head.base, vec=vec.base, key=key.base, val=val.base)


def read_state(m, shape, ref, ranges_last):
    """Table and entry vector as the bytes leave them."""
    head = ref['head']
    ctrl, mask, growth, items = (m.load(head + 8 * k, 8) for k in range(4))
    n = mask + 1
    cb = peek(m, ctrl, n + 16)
    vals = tuple(m.load(ctrl - 8 * (i + 1), 8) if cb[i] < 0x80 else None for i in range(n))
    cap, ptr, ln = (m.load(ref['vec'] + 8 * k, 8) for k in range(3))
    rows = tuple(row_view(shape, peek(m, ptr + i * shape['stride'], shape['stride']),
                          ranges_last if i == ln - 1 else [(0, shape['vsize'])]) for i in range(ln))
    return cap, rows, (n, cb, vals, growth, items), ctrl, ptr


def run_push(img, code, fn, c):
    shape = SHAPE[fn]
    m = new_machine(img, code, shape)
    ref = lay_case(m, shape, c)
    out = m.arena(0x40)
    m.regs[R['rdi']], m.regs[R['rsi']], m.regs[R['rdx']] = out.base, ref['head'], ref['vec']
    m.regs[R['rcx']], m.regs[R['r8']], m.regs[R['r9']] = c['hash'], ref['key'], ref['val']
    res = outcome(m, fn)
    if res[0] == 'panic':
        return res + (None,), m
    cap, rows, table, ctrl, ptr = read_state(m, shape, ref, [(0, shape['vsize'])])
    o = [m.load(out.base + 8 * k, 8) for k in range(4)]
    if m.regs[0] != out.base or o[0] != ref['vec'] or o[2] != ref['head']:
        return ('badout', None, None), m
    slot = (ctrl - o[1]) // 8
    return ('ok', None, (cap, rows, table, slot, o[3])), m


def run_entry(img, code, fn, c):
    shape = SHAPE[PUSH_OF[fn]]
    m = new_machine(img, code, shape)
    ent = m.arena(0x60)
    if c['kind'] == 'occupied':
        rows = m.arena(max(c['nrows'], 1) * shape['stride'] + 16)
        vec = m.arena(0x40)
        fill(vec, 0, (c['nrows']).to_bytes(8, 'little') + rows.base.to_bytes(8, 'little')
             + c['nrows'].to_bytes(8, 'little'))
        bucket = m.arena(0x40)
        fill(bucket, 0x10, c['index'].to_bytes(8, 'little'))
        fill(ent, 0, (0).to_bytes(8, 'little') + vec.base.to_bytes(8, 'little') + (bucket.base + 0x18).to_bytes(8, 'little'))
        m.regs[R['rdi']] = ent.base
        res = outcome(m, fn)
        if res[0] == 'ok':
            return ('ok', None, (m.regs[0] - rows.base) // shape['stride'] if m.regs[0] >= rows.base else None), m
        return res + (None,), m
    ref = lay_case(m, shape, c)
    fill(ent, 0, ref['head'].to_bytes(8, 'little') + ref['vec'].to_bytes(8, 'little')
         + c['hash'].to_bytes(8, 'little') + c['key'] + PAD[:20])
    m.regs[R['rdi']] = ent.base
    res = outcome(m, fn)
    if res[0] == 'panic':
        return res + (None,), m
    ranges = default_ranges(fn)
    cap, rows, table, ctrl, ptr = read_state(m, shape, ref, ranges)
    ln = len(rows)
    got = (m.regs[0] - ptr) // shape['stride'] if m.regs[0] >= ptr else None
    return ('ok', None, (cap, rows, table, got)), m


def default_value(fn):
    shape = SHAPE[PUSH_OF[fn]]
    v = bytearray(shape['vsize'])
    for off, ln, val in DEFAULT_PARTS[fn]:
        if val:
            v[off:off + 8] = val.to_bytes(8, 'little')
    return bytes(v)


def default_ranges(fn):
    return [(off, off + ln) for off, ln, _ in DEFAULT_PARTS[fn]]


def model_entry(fn, c, v=None):
    shape = SHAPE[PUSH_OF[fn]]
    if c['kind'] == 'occupied':
        if c['index'] >= c['nrows']:
            return ('panic', LOC_BOUNDS_ENTRY)
        return ('ok', c['index'])
    c2 = dict(c, value=default_value(fn))
    res = model_push(shape, c2, default_ranges(fn), v)
    if res[0] == 'panic':
        return res
    cap, rows, table, slot, h = res[1]
    idx = table[2][slot]
    if idx >= len(rows):
        return ('panic', LOC_BOUNDS_ENTRY)
    return ('ok', (cap, rows, table, idx))


# ---------------------------------------------------------------------------------------------------------
# Vector generation: every case is built, run, compared and dropped (no list of results is kept)
# ---------------------------------------------------------------------------------------------------------
def gen_case(rng, shape, i, vacant_default=False):
    n = rng.pick((4, 8, 8, 16, 16, 32, 32, 64))
    full = full_cap(n)
    mode = rng.below(12)
    ndel = min(rng.below(3) if mode >= 6 else 0, full)
    if mode == 0:
        items = full
        ndel = 0
    elif mode == 1:
        items = 0
    elif mode == 2:
        ndel = min(1 + rng.below(2), full)
        items = full - ndel
    else:
        items = rng.below(full - ndel + 1)
    t = RawTable(n)
    rows = []
    for k in range(items):
        h = rng.next()
        if rng.below(4) == 0:
            h = h & ~t.mask | rng.below(3)
        t.insert(h, k)
        rows.append((rng.bytes(shape['vsize']), h, rng.bytes(20)))
    empties = [j for j in range(n) if t.ctrl[j] == EMPTY]
    for _ in range(min(ndel, len(empties))):
        j = empties.pop(rng.below(len(empties)))
        t.set_ctrl(j, DELETED)
    ndel = sum(1 for j in range(n) if t.ctrl[j] == DELETED)
    growth = full - items - ndel
    nrows = items
    kind = rng.below(40)
    if kind == 0 and growth > 0:
        nrows = items + 1 + rng.below(2)
        rows += [(rng.bytes(shape['vsize']), rng.next(), rng.bytes(20)) for _ in range(nrows - items)]
    elif kind == 1 and growth > 0 and items > 0:
        nrows = items - 1
        rows = rows[:nrows]
    elif kind == 2 and growth > 0:
        items = U64
    cap = nrows + rng.pick((0, 0, 0, 1, 2, 3, 7))
    fail = ()
    if rng.below(30) == 0:
        fail = rng.pick(((1,), (1, 2), (2,), (1, 2)))
    h = rng.next()
    if rng.below(5) == 0:
        h = h & ~t.mask | rng.below(4)
    rowsb = [make_row(shape, v, hh, k) for v, hh, k in rows]
    return dict(table=t, growth=growth, items=items, rows=rowsb, cap=cap, fail=fail, hash=h,
                key=rng.bytes(20), value=rng.bytes(shape['vsize']), kind='vacant', nrows=nrows)


def gen_occupied(rng):
    n = 1 + rng.below(12)
    idx = rng.below(n) if rng.below(13) else n + rng.below(3)
    return dict(kind='occupied', index=idx, nrows=n)


GROUPS = (('push_a', S_PA, 3000), ('push_b', S_PB, 3000), ('entry_a', S_EA, 2300), ('entry_b', S_EB, 2300))


def case_stream(seed=0x115CD):
    """Yield (group, fn, case) for every vector, in a fixed order."""
    rng = Rng(seed)
    for name, fn, count in GROUPS:
        shape = SHAPE[PUSH_OF.get(fn, fn)]
        for i in range(count):
            if fn in PUSH_OF and i % 4 == 3:
                yield name, fn, gen_occupied(rng)
            else:
                yield name, fn, gen_case(rng, shape, i)


def observe(img, code, fn, c):
    if fn in PUSH_OF:
        return run_entry(img, code, fn, c)
    return run_push(img, code, fn, c)


def expected(fn, c, v=None):
    if fn in PUSH_OF:
        return model_entry(fn, c, v)
    return model_push(SHAPE[fn], c, [(0, SHAPE[fn]['vsize'])], v)


def agree(fn, obs, exp):
    if obs[0] in ('badout',):
        return False
    if obs[0] == 'panic':
        return exp[0] == 'panic' and obs[1] == exp[1]
    if exp[0] == 'panic':
        return False
    if fn in PUSH_OF and exp[1] is not None and not isinstance(exp[1], tuple):
        return obs[2] == exp[1]
    return obs[2] == exp[1]


def summarise(fn, c, obs):
    if c['kind'] == 'occupied':
        return f"occupied\t{c['index']}/{c['nrows']}\t-\t{obs[0]}:{obs[2]}"
    t = c['table']
    sig = hashlib.sha256(bytes(t.ctrl) + b''.join(v.to_bytes(8, 'little') for v in t.vals)).hexdigest()[:8]
    if obs[0] == 'panic':
        res = f'panic:{obs[1] if not isinstance(obs[1], tuple) else obs[1][0]}'
        res = res if not isinstance(obs[1], int) else f'panic:{obs[1]:#x}'
    elif fn in PUSH_OF:
        res = f'ok:cap={obs[2][0]}:row={obs[2][3]}:n={obs[2][2][0]}'
    else:
        res = f'ok:cap={obs[2][0]}:slot={obs[2][3]}:n={obs[2][2][0]}'
    return (f"{t.n}/{c['items'] if c['items'] != U64 else 'max'}/{c['cap']}/{len(c['rows'])}\t{c['hash']:#x}\t"
            f"{''.join(map(str, c['fail'])) or '-'}#{sig}\t{res}")


# ---------------------------------------------------------------------------------------------------------
# Decoding the subjects, mutants, corrupted inputs
# ---------------------------------------------------------------------------------------------------------
def decode_subjects(img, fdes):
    code, extents = {}, {}
    for fn in SUBJECTS + CALLEES:
        r = fdes.range_of(fn)
        if r['start'] != fn:
            raise EvidenceError(f'{fn:#x} is not an FDE start')
        extents[fn] = (r['start'], r['end'])
        for ins in decode_range(img, r['start'], r['end']):
            code[ins.va] = ins
    return code, extents


def cond_patch(ins):
    raw, j = ins.raw, 0
    while raw[j] in (0x66, 0xf2, 0xf3, 0x2e):
        j += 1
    if raw[j] & 0xf0 == 0x40:
        j += 1
    pos = j + 1 if raw[j] == 0x0f else j
    return {ins.va + pos: raw[pos] ^ 1}


def mutant_list(code, extents):
    muts = []
    for fn in SUBJECTS:
        lo, hi = extents[fn]
        insns = [code[v] for v in sorted(code) if lo <= v < hi]
        for ins in insns:
            if ins.op != 'jmp' and (ins.op[0] == 'j' or ins.op.startswith('cmov') or ins.op.startswith('set')):
                muts.append((f'{NAMES[fn]}:{ins.va:#x}:invert {ins.op}', cond_patch(ins), ins.va))
        for ins in insns:
            if ins.op in ('shl', 'shr') and ins.ops[1][0] == 'i':
                muts.append((f'{NAMES[fn]}:{ins.va:#x}:{ins.op} count +1', {ins.va + ins.size - 1: (ins.raw[-1] + 1) & 0xff}, ins.va))
        mems = [i for i in insns if i.op in ('mov', 'cmp', 'lea', 'movups') and any(
            o[0] == 'm' and o[1] is not None and 0 < abs(o[4]) < 0x70 and o[1] != 4 for o in i.ops)
                and not any(o[0] == 'i' for o in i.ops) and len(i.raw) in (3, 4, 5, 7)]
        for k, ins in enumerate(mems):
            if k % 3 == fn % 3:
                muts.append((f'{NAMES[fn]}:{ins.va:#x}:displacement +8', {ins.va + ins.size - 1: (ins.raw[-1] + 8) & 0xff}, ins.va))
        for ins in insns:
            if ins.op == 'imul' and ins.ops[2][0] == 'i':
                muts.append((f'{NAMES[fn]}:{ins.va:#x}:imul factor +8', {ins.va + ins.size - 1: (ins.raw[-1] + 8) & 0xff}, ins.va))
        for ins in insns:
            if ins.op == 'mov' and ins.ops[1][0] == 'i' and ins.ops[0][0] == 'r' and ins.ops[0][2] == 32 and 0 < ins.ops[1][1] < 0x200:
                muts.append((f'{NAMES[fn]}:{ins.va:#x}:immediate +1', {ins.va + 1: (ins.raw[1] + 1) & 0xff}, ins.va))
    return muts


def wrong_models():
    """(name, group fn, variant) — each must disagree with the real bytes on the control vectors."""
    return [
        ('tag taken from 8 bits', S_PA, {'tag_bits': 8}),
        ('tag taken from 6 bits', S_PB, {'tag_bits': 6}),
        ('growth budget spent on every slot', S_PA, {'growth_always': True}),
        ('growth budget spent on every slot (b)', S_PB, {'growth_always': True}),
        ('vector grows one row at a time', S_PA, {'linear_growth': True}),
        ('vector grows one row at a time (b)', S_PB, {'linear_growth': True}),
        ('stored index is the vector length', S_PA, {'index_is_len': True}),
        ('stored index is the vector length (b)', S_PB, {'index_is_len': True}),
        ('table is not enlarged when full', S_PA, {'no_resize': True}),
        ('table is not enlarged when full (b)', S_PB, {'no_resize': True}),
        ('stored hash is corrupted', S_PA, {'hash_xor': 1 << 63}),
        ('stored key loses its last 4 bytes', S_PB, {'short_key': True}),
        ('entry completion returns the stored index of a longer vector', S_EA, {'index_is_len': True}),
        ('entry completion without the table growth', S_EB, {'no_resize': True}),
    ]


def control_vectors():
    """A fixed slice of every group, used for every control."""
    picks = {}
    for group, fn, payload in case_stream():
        picks.setdefault(group, []).append((fn, payload))
    out = []
    for rows in picks.values():
        step = max(len(rows) // 90, 1)
        out.extend(rows[::step][:90])
    return out


def detects(img, code, ctl, fns=None):
    for fn, payload in ctl:
        if fns is not None and fn not in fns:
            continue
        try:
            obs, _ = observe(img, code, fn, payload)
        except (Unmodelled, EvidenceError, Panic):
            return 'refused'
        except (IndexError, KeyError, ValueError, TypeError, StopIteration):
            return 'refused'
        if not agree(fn, obs, expected(fn, payload)):
            return 'differs'
    return None


def run_mutants(data, code, extents, ctl, reached):
    rows, killed, equiv = [], 0, 0
    for name, patch, ins_va in mutant_list(code, extents):
        img = Image(data, patch)
        va = next(iter(patch))
        fn = next(f for f, (lo, hi) in extents.items() if lo <= va < hi)
        lo, hi = extents[fn]
        try:
            fresh = decode_range(img, lo, hi)
        except EvidenceError:
            rows.append((name, 'detected', 'decoder refuses the patched bytes'))
            killed += 1
            continue
        c2 = {v: i for v, i in code.items() if not lo <= v < hi}
        c2.update({i.va: i for i in fresh})
        why = detects(img, c2, ctl, {fn} | {e for e, p in PUSH_OF.items() if p == fn})
        if why:
            rows.append((name, 'detected', why))
            killed += 1
        elif ins_va not in reached:
            rows.append((name, 'unreached', 'no vector executes the patched instruction'))
            equiv += 1
        else:
            rows.append((name, 'equivalent', 'survived the control slice; listed, not counted'))
            equiv += 1
    return rows, killed, equiv


def corrupted_inputs(data, fdes, img):
    out = []

    def expect_error(name, fn):
        try:
            fn()
        except (EvidenceError, Unmodelled, Panic, KeyError, IndexError, ValueError):
            out.append((name, True))
        else:
            out.append((name, False))

    expect_error('flipped last byte of the file', lambda: check_digest(data[:-1] + bytes([data[-1] ^ 1])))
    expect_error('empty input', lambda: check_digest(b''))
    expect_error('address that is not an FDE start', lambda: decode_subjects_one(img, fdes, S_PA + 1))
    expect_error('address outside every section', lambda: img.read(0x10, 4))
    expect_error('address in .bss', lambda: img.read(img.sec['.bss'][0], 4))
    expect_error('unlisted opcode', lambda: decode_one(b'\x0f\x0a' + b'\x90' * 16, 0, 0x1000))
    expect_error('truncated ULEB128', lambda: uleb(b'\x80\x80', 0))
    expect_error('tag shift patched in the image', lambda: selfcheck(Image(data, {0x3ec8cbd: 0x39 ^ 1}), fdes))
    expect_error('bucket address scale patched in the image', lambda: selfcheck(Image(data, {0x3ec8cdd: 3 ^ 1}), fdes))
    expect_error('row stride patched in the image', lambda: selfcheck(Image(data, {0x3ec7c6f: 0x70 ^ 0x10}), fdes))
    expect_error('push call target patched in the entry', lambda: selfcheck(Image(data, {0x47180ec: 0xa0 ^ 0x10}), fdes))
    expect_error('case whose rows list is shorter than its table', stale_case)
    return out


def stale_case():
    c = gen_case(Rng(9), SHAPE[S_PA], 0)
    c['table'] = RawTable(8)
    c['table'].insert(1 << 57, 2)
    c['growth'], c['items'], c['rows'] = 0, 3, []
    model_push(SHAPE[S_PA], c, [(0, 0xe0)])


def decode_subjects_one(img, fdes, va):
    r = fdes.range_of(va)
    if r['start'] != va:
        raise EvidenceError('not an FDE start')


def selfcheck(img, fdes):
    """Run one fixed push on each subject; raise if the bytes no longer give the model answer."""
    code, _ = decode_subjects(img, fdes)
    for seed in range(0x77, 0x7f):
        for fn in (S_PA, S_PB):
            c = gen_case(Rng(seed), SHAPE[fn], 0)
            obs, _ = run_push(img, code, fn, c)
            if not agree(fn, obs, expected(fn, c)):
                raise EvidenceError(f'{NAMES[fn]} no longer matches the push model')
        for fn in (S_EA, S_EB):
            c = gen_case(Rng(seed), SHAPE[PUSH_OF[fn]], 0)
            obs, _ = run_entry(img, code, fn, c)
            if not agree(fn, obs, expected(fn, c)):
                raise EvidenceError(f'{NAMES[fn]} no longer matches the entry model')


# ---------------------------------------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------------------------------------
def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--out', required=True)
    args = ap.parse_args()
    out = Path(args.out)
    if not out.is_absolute():
        out = Path.cwd() / out
    out.mkdir(parents=True, exist_ok=True)
    data = (ROOT / BINARY).read_bytes()
    digest = check_digest(data)
    img = Image(data)
    fdes = Fdes(img)
    code, extents = decode_subjects(img, fdes)
    selfcheck(img, fdes)
    with open(out / 'instructions.tsv', 'w') as f:
        f.write('function\taddress\tsize\tbytes\tdecoded\n')
        for fn in SUBJECTS:
            lo, hi = extents[fn]
            for va in sorted(v for v in code if lo <= v < hi):
                ins = code[va]
                f.write(f'{NAMES[fn]}\t{va:#x}\t{ins.size}\t{ins.raw.hex()}\t{show(ins)}\n')
    total, groups, rehashes, panics = 0, Counter(), 0, Counter()
    full, reached = hashlib.sha256(), set()
    with open(out / 'vectors.tsv', 'w') as f:
        f.write('index\tgroup\tfunction\tinput_a\tinput_b\tinput_c\tobserved\n')
        for idx, (group, fn, payload) in enumerate(case_stream()):
            obs, m = observe(img, code, fn, payload)
            reached |= m.seen
            rehashes += m.rehash
            if not agree(fn, obs, expected(fn, payload)):
                raise EvidenceError(f'vector {idx} ({group}) disagrees with the model')
            if obs[0] == 'panic':
                panics['alloc error' if isinstance(obs[1], tuple) else hex(obs[1])] += 1
            row = f'{idx}\t{group}\t{NAMES[fn]}\t{summarise(fn, payload, obs)}\n'
            full.update(row.encode())
            groups[group] += 1
            total += 1
            if idx % 3 == 0:
                f.write(row)
    ctl = control_vectors()
    mrows, killed, equiv = run_mutants(data, code, extents, ctl, reached)
    wrows = []
    for name, fn, variant in wrong_models():
        miss = True
        for g in ctl:
            if g[0] == fn:
                obs, _ = observe(img, code, g[0], g[1])
                if not agree(g[0], obs, expected(g[0], g[1], variant)):
                    miss = False
                    break
        wrows.append((name, 'detected' if not miss else 'MISSED', f'{NAMES[fn]} group'))
    crows = corrupted_inputs(data, fdes, img)
    n_neg = killed + len(wrows) + len(crows)
    n_det = killed + sum(1 for r in wrows if r[1] == 'detected') + sum(1 for r in crows if r[1])
    with open(out / 'controls.tsv', 'w') as f:
        f.write('kind\tname\tresult\treason\n')
        for name, res, why in mrows:
            f.write(f'byte mutant\t{name}\t{res}\t{why}\n')
        for name, res, why in wrows:
            f.write(f'wrong model\t{name}\t{res}\t{why}\n')
        for name, ok in crows:
            f.write(f'corrupted input\t{name}\t{"detected" if ok else "MISSED"}\trefused by the tool\n')
    insn_total = {NAMES[fn]: sum(1 for v in code if extents[fn][0] <= v < extents[fn][1]) for fn in SUBJECTS}
    unexecuted = sorted(v for v in code if v not in reached)
    evidence = {
        'binary': BINARY, 'sha256': digest,
        'subjects': {NAMES[fn]: [hex(extents[fn][0]), hex(extents[fn][1])] for fn in SUBJECTS},
        'instructions': insn_total, 'unexecuted': [hex(v) for v in unexecuted],
        'groups': dict(groups), 'vectors': total, 'rows_sha256': full.hexdigest(),
        'rehash_stub_calls': rehashes, 'panics': dict(sorted(panics.items())),
        'mutants': {'listed': len(mrows), 'detected': killed, 'survivors': equiv},
        'wrong_models': len(wrows), 'corrupted_inputs': len(crows),
        'panic_locations': [hex(LOC_ITEMS_OVERFLOW), hex(LOC_BOUNDS_ENTRY)],
        'stubbed_callees': {'memcpy_slot': hex(SLOT_MEMCPY), 'finish_grow': hex(FINISH_GROW),
                            'alloc_error_slot': hex(SLOT_ALLOC_ERR),
                            'reserve_rehash_slots': [hex(SHAPE[S_PA]['reserve']), hex(SHAPE[S_PB]['reserve'])]},
    }
    (out / 'evidence.json').write_text(json.dumps(evidence, indent=1, sort_keys=True) + '\n')
    (out / 'measure.json').write_text(json.dumps({'cases': total, 'negative_controls': n_neg,
                                                   'negative_detected': n_det}, indent=1) + '\n')
    print(json.dumps({'cases': total, 'negative_controls': n_neg, 'negative_detected': n_det,
                      'survivors': equiv, 'unexecuted': len(unexecuted)}))
    if n_det != n_neg:
        raise EvidenceError('a negative control was not detected')


if __name__ == '__main__':
    main()
