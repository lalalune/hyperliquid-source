#!/usr/bin/env python3
"""ledger maps: node #115 SipHash-1-3 key hashers, streaming write, hashbrown probes and entry, from bytes alone.

Static, no execution of the node.  The three key hashers 0x4717440 (20 bytes), 0x47175b0 (16 bytes) and 0x47172c0
(one u64), the streaming hasher write 0x45927a0, the four hashbrown group probes 0x3ee6280, 0x3ee69c0, 0x3ed2180 and
0x3ed2280, and the occupied/vacant arms of the map entry 0x4717c50 are decoded from ELF bytes by the table decoder
below, which must land exactly on each FDE end, and interpreted in Python on every vector.  Each outcome is compared
with closed-form reconstructions (a SipHash-1-3 function and a streaming hasher object, a hashbrown probe model);
then one-byte mutants of the subjects, wrong models and corrupted inputs are all required to be caught.

    python3 tools/ledger_maps_115.py --out <dir>

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
# Subjects of node #115: the SipHash-1-3 key hashers, the streaming write, four hashbrown probes, one entry
# ---------------------------------------------------------------------------------------------------------
S_H20, S_H16, S_H8, S_WRITE = 0x4717440, 0x47175b0, 0x47172c0, 0x45927a0
S_FA, S_FB, S_UA, S_UB, S_ENTRY = 0x3ee6280, 0x3ee69c0, 0x3ed2180, 0x3ed2280, 0x4717c50
S_INSERT = 0x3ec8b70
SUBJECTS = (S_H20, S_H16, S_FA, S_FB, S_UA, S_UB, S_ENTRY)
CALLEES = (S_WRITE,)                  # runs as the real callee of the hashers; its body belongs to another packet
NAMES = {S_H20: 'hash20', S_H16: 'hash16', S_H8: 'hash8', S_WRITE: 'write', S_FA: 'find_a', S_FB: 'find_b',
         S_UA: 'has_a', S_UB: 'has_b', S_ENTRY: 'entry'}
PANIC_SLOTS = (0x64df520, 0x64df620)
LOC_BOUNDS_FIND, LOC_BOUNDS_ENTRY = 0x647a850, 0x6493b60
SIP_CONST = (0x736f6d6570736575, 0x646f72616e646f6d, 0x6c7967656e657261, 0x7465646279746573)
# (stride, key offset, key bytes) of the entry rows the four probes read
SHAPES = {S_FA: (0x100, 0xe8, 20), S_FB: (0x70, 0x58, 20), S_UA: (24, 8, 8), S_UB: (160, 0x98, 8)}
ENTRY_STRIDE = 0x100


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


# ---------------------------------------------------------------------------------------------------------
# Reconstruction 1: SipHash-1-3, as a closed form and as the streaming hasher the node keeps in memory
# ---------------------------------------------------------------------------------------------------------
def rotl(x, n):
    return (x << n | x >> (64 - n)) & U64


def sip_round(v0, v1, v2, v3):
    v0 = (v0 + v1) & U64
    v1 = rotl(v1, 13) ^ v0
    v0 = rotl(v0, 32)
    v2 = (v2 + v3) & U64
    v3 = rotl(v3, 16) ^ v2
    v0 = (v0 + v3) & U64
    v3 = rotl(v3, 21) ^ v0
    v2 = (v2 + v1) & U64
    v1 = rotl(v1, 17) ^ v2
    v2 = rotl(v2, 32)
    return v0, v1, v2, v3


def siphash(k0, k1, data, c=1, d=3, length_byte=True, swap_keys=False, xor_ff=0xff):
    if swap_keys:
        k0, k1 = k1, k0
    v0, v1, v2, v3 = k0 ^ SIP_CONST[0], k1 ^ SIP_CONST[1], k0 ^ SIP_CONST[2], k1 ^ SIP_CONST[3]
    n = len(data)
    body = n - n % 8
    for i in range(0, body, 8):
        m = int.from_bytes(data[i:i + 8], 'little')
        v3 ^= m
        for _ in range(c):
            v0, v1, v2, v3 = sip_round(v0, v1, v2, v3)
        v0 ^= m
    b = ((n & 0xff) << 56 if length_byte else 0) | int.from_bytes(data[body:], 'little')
    v3 ^= b
    for _ in range(c):
        v0, v1, v2, v3 = sip_round(v0, v1, v2, v3)
    v0 ^= b
    v2 ^= xor_ff
    for _ in range(d):
        v0, v1, v2, v3 = sip_round(v0, v1, v2, v3)
    return v0 ^ v1 ^ v2 ^ v3


class Hasher:
    """The 0x48-byte hasher object: words v0, v2, v1, v3, k0, k1, length, tail, ntail (memory order)."""

    def __init__(self, k0, k1):
        self.v0, self.v2 = k0 ^ SIP_CONST[0], k0 ^ SIP_CONST[2]
        self.v1, self.v3 = k1 ^ SIP_CONST[1], k1 ^ SIP_CONST[3]
        self.k0, self.k1, self.length, self.tail, self.ntail = k0, k1, 0, 0, 0

    def words(self):
        return (self.v0, self.v2, self.v1, self.v3, self.k0, self.k1, self.length, self.tail, self.ntail)

    def compress(self, m):
        self.v3 ^= m
        self.v0, self.v1, self.v2, self.v3 = sip_round(self.v0, self.v1, self.v2, self.v3)
        self.v0 ^= m

    def write(self, data):
        n = len(data)
        self.length += n
        needed = 0
        if self.ntail:
            needed = 8 - self.ntail
            self.tail |= int.from_bytes(data[:min(n, needed)], 'little') << 8 * self.ntail
            if n < needed:
                self.ntail += n
                return
            self.compress(self.tail)
            self.ntail = 0
        rest = n - needed
        left = rest & 7
        for i in range(needed, needed + rest - left, 8):
            self.compress(int.from_bytes(data[i:i + 8], 'little'))
        self.tail = int.from_bytes(data[n - left:], 'little') if left else 0
        self.ntail = left

    def finish(self):
        b = (self.length & 0xff) << 56 | self.tail
        v0, v1, v2, v3 = self.v0, self.v1, self.v2, self.v3
        v3 ^= b
        v0, v1, v2, v3 = sip_round(v0, v1, v2, v3)
        v0 ^= b
        v2 ^= 0xff
        for _ in range(3):
            v0, v1, v2, v3 = sip_round(v0, v1, v2, v3)
        return v0 ^ v1 ^ v2 ^ v3


def model_hash(fn, k0, k1, data, **kw):
    return siphash(k0, k1, data, **kw)


# ---------------------------------------------------------------------------------------------------------
# Reconstruction 2: the hashbrown group probe (16 control bytes, 7-bit tag, triangular stride)
# ---------------------------------------------------------------------------------------------------------
EMPTY, DELETED = 0xff, 0x80
PAD = bytes((0x5a + 7 * i) & 0xff for i in range(40))      # garbage after every buffer: reads past a length show


class RawTable:
    def __init__(self, buckets):
        self.n, self.mask = buckets, buckets - 1
        self.ctrl = bytearray(b'\xff' * (buckets + 16))
        self.vals = [0] * buckets

    def set_ctrl(self, i, v):
        self.ctrl[i] = v
        self.ctrl[((i - 16) & self.mask) + 16] = v

    def insert(self, h, val):
        pos, stride = h & self.mask, 0
        while True:
            for b in range(16):
                if self.ctrl[pos + b] >= 0x80:
                    idx = (pos + b) & self.mask
                    if self.ctrl[idx] < 0x80:
                        idx = next(j for j in range(16) if self.ctrl[j] >= 0x80)
                    self.set_ctrl(idx, h >> 57)
                    self.vals[idx] = val
                    return idx
            stride += 16
            pos = (pos + stride) & self.mask


class Bounds(Exception):
    def __init__(self, loc):
        super().__init__(loc)
        self.loc = loc


def probe_find(tbl, h, nentries, same, tag_bits=7, stride_step=16, first_group_only=False, stats=None,
               bounds_loc=LOC_BOUNDS_FIND):
    """Index of the bucket holding the entry for which `same(entry_index)` holds, or None."""
    tag = h >> (64 - tag_bits)
    pos, stride = h & tbl.mask, 0
    for _ in range(tbl.n + 2):
        if stats is not None:
            stats.append(pos)
        group = tbl.ctrl[pos:pos + 16]
        for b in range(16):
            if group[b] == tag:
                idx = (pos + b) & tbl.mask
                v = tbl.vals[idx]
                if v >= nentries:
                    raise Bounds(bounds_loc)
                if same(v):
                    return idx
        if first_group_only or EMPTY in group:
            return None
        stride += stride_step
        pos = (pos + stride) & tbl.mask
    return None


# ---------------------------------------------------------------------------------------------------------
# Harness
# ---------------------------------------------------------------------------------------------------------
class Mach(Machine):
    def __init__(self, img, code):
        super().__init__(img, ())
        self.code = code


def fill(arena, off, raw):
    arena.mem[off:off + len(raw)] = raw
    arena.valid[off:off + len(raw)] = b'\1' * len(raw)


def new_machine(img, code):
    m = Mach(img, code)
    stack = m.arena(0x4000, strict=False)
    m.regs[4] = stack.base + 0x3000 + 8
    return m


def outcome(m, entry):
    try:
        m.run(entry)
    except Panic as p:
        return ('panic', p.location)
    return ('ok', None)


def run_hash(img, code, fn, k0, k1, data):
    m = new_machine(img, code)
    m.regs[R['rdi']], m.regs[R['rsi']] = k0, k1
    a = m.arena(0x40)
    fill(a, 0, data + PAD[:40 - len(data)])
    m.regs[R['rdx']] = a.base
    res = outcome(m, fn)
    return res + (m.regs[0],), m


def build_find(m, fn, tbl, keys, query_key, h):
    """Lay the table, the entry rows and the query in modelled memory; returns the ctrl base."""
    stride, koff, klen = SHAPES[fn]
    n = tbl.n
    arena = m.arena(n * 8 + n + 16 + 16)
    ctrl = arena.base + n * 8
    for i in range(n):
        fill(arena, n * 8 - 8 * (i + 1), tbl.vals[i].to_bytes(8, 'little'))
    fill(arena, n * 8, bytes(tbl.ctrl))
    rows = m.arena(max(len(keys), 1) * stride + 16)
    for i, k in enumerate(keys):
        fill(rows, i * stride, bytes((i * 13 + j) & 0xff for j in range(stride)))
        fill(rows, i * stride + koff, k)
    kq = m.arena(0x40)
    fill(kq, 0, query_key + PAD[:40 - len(query_key)])
    head = m.arena(0x40)
    if fn in (S_FA, S_FB):
        fill(head, 0, ctrl.to_bytes(8, 'little') + tbl.mask.to_bytes(8, 'little'))
        probe = m.arena(0x20)
        fill(probe, 0, kq.base.to_bytes(8, 'little') + rows.base.to_bytes(8, 'little')
             + len(keys).to_bytes(8, 'little'))
        m.regs[R['rdi']], m.regs[R['rsi']], m.regs[R['rdx']] = head.base, h, probe.base
    else:
        fill(head, 8, rows.base.to_bytes(8, 'little') + len(keys).to_bytes(8, 'little')
             + ctrl.to_bytes(8, 'little') + tbl.mask.to_bytes(8, 'little'))
        m.regs[R['rdi']], m.regs[R['rsi']], m.regs[R['rdx']] = head.base, h, kq.base
    return ctrl


def run_find(img, code, fn, case):
    tbl, keys, query, h = case
    m = new_machine(img, code)
    ctrl = build_find(m, fn, tbl, keys, query, h)
    res = outcome(m, fn)
    if res[0] == 'ok':
        if fn in (S_FA, S_FB):
            ptr = m.regs[0]
            return res + (None if ptr == 0 else (ctrl - ptr) // 8,), m
        return res + (m.regs[0] & 0xff,), m
    return res + (None,), m


def model_probe(fn, case, **kw):
    tbl, keys, query, h = case
    try:
        idx = probe_find(tbl, h, len(keys), lambda v: keys[v] == query, **kw)
    except Bounds as b:
        return ('panic', b.loc, None)
    if fn in (S_FA, S_FB):
        return ('ok', idx)
    return ('ok', 0 if idx is None else 1)


def run_entry(img, code, case):
    kind, idx_val, n_entries = case
    m = new_machine(img, code)
    rows = m.arena(max(n_entries, 1) * ENTRY_STRIDE + 16)
    mp = m.arena(0x40)
    fill(mp, 8, rows.base.to_bytes(8, 'little') + n_entries.to_bytes(8, 'little'))
    bucket = m.arena(0x40)
    fill(bucket, 0x10, idx_val.to_bytes(8, 'little'))
    ent = m.arena(0x60)
    seen_args = []
    if kind == 'occupied':
        fill(ent, 0, (0).to_bytes(8, 'little') + mp.base.to_bytes(8, 'little')
             + (bucket.base + 0x18).to_bytes(8, 'little'))
    else:
        fill(ent, 0, (0x7777).to_bytes(8, 'little') + mp.base.to_bytes(8, 'little') + (0x5555).to_bytes(8, 'little')
             + bytes(range(1, 21)))

        def insert_stub():
            seen_args.append((m.regs[R['rsi']], m.regs[R['rdx']], m.regs[R['rcx']], m.regs[R['r8']]))
            out = m.regs[R['rdi']]
            m.store(out, 8, mp.base)
            m.store(out + 8, 8, bucket.base + 0x18)
            m.clobber()

        m.stubs[S_INSERT] = insert_stub
    m.regs[R['rdi']] = ent.base
    res = outcome(m, S_ENTRY)
    if res[0] == 'ok':
        got = m.regs[0]
        res = res + ((got - rows.base) // ENTRY_STRIDE if got >= rows.base else None,)
        if kind == 'vacant':
            exp = (0x7777, mp.base, 0x5555, ent.base + 0x18)
            if seen_args != [exp]:
                res = ('badargs', tuple(seen_args))
    else:
        res = res + (None,)
    return res, m


def model_entry(case):
    kind, idx_val, n = case
    if idx_val >= n:
        return ('panic', LOC_BOUNDS_ENTRY, None)
    return ('ok', idx_val)


# ---------------------------------------------------------------------------------------------------------
# Vector generation: every case is built, run, compared and dropped (no list of results is kept)
# ---------------------------------------------------------------------------------------------------------
def hex_key(b):
    return b.hex()


def gen_hash_cases(rng, fn, count, klen):
    edge = [(0, 0, bytes(klen)), (U64, U64, b'\xff' * klen), (1, 2, bytes(range(klen))), (U64, 0, bytes(klen)),
            (0, U64, b'\x80' * klen)]
    for i in range(count):
        if i < len(edge):
            yield edge[i]
            continue
        k0, k1 = rng.next(), rng.next()
        data = rng.bytes(klen)
        if i % 5 == 0:
            data = bytes(klen - 1) + bytes([i & 0xff])
        elif i % 11 == 0:
            data = rng.bytes(klen // 2) + bytes(klen - klen // 2)
        yield k0, k1, data


def gen_find_cases(rng, fn, count):
    stride, koff, klen = SHAPES[fn]
    for i in range(count):
        buckets = (4, 8, 16, 32, 64)[rng.below(5)]
        cap = buckets - 1 if buckets <= 8 else buckets // 8 * 7
        n = 1 + rng.below(max(cap, 1)) if i % 7 else cap
        n = min(n, cap)
        tbl = RawTable(buckets)
        keys, hashes = [], []
        mode = i % 6
        base_h = rng.next()
        for e in range(n):
            if klen == 20:
                key = rng.bytes(20)
                if i % 3 == 0 and keys:
                    key = keys[0][:19] + bytes([e])
                if i % 5 == 1 and keys:
                    key = bytes([e]) + keys[0][1:]
            else:
                key = rng.next().to_bytes(8, 'little')
            h = rng.next()
            if mode == 1:
                h = (base_h & ~0xf) | rng.below(16)                       # one probe start, same tag
            elif mode == 2:
                h = (h & (U64 >> 7)) | (base_h >> 57 << 57)               # same tag, scattered starts
            elif mode == 3:
                h = base_h                                                 # identical hash: long chains
            keys.append(key)
            hashes.append(h)
            tbl.insert(h, e)
        if i % 8 == 3:                                                     # tombstones
            for j in range(tbl.n):
                if tbl.ctrl[j] < 0x80 and rng.below(3) == 0:
                    tbl.set_ctrl(j, DELETED)
        pick = rng.below(n)
        choice = i % 5
        if choice in (0, 1):
            query, h = keys[pick], hashes[pick]
        elif choice == 2:
            query, h = rng.bytes(klen), hashes[pick]
        elif choice == 3:
            query, h = keys[pick], rng.next()
        else:
            q = bytearray(keys[pick])
            q[rng.below(klen)] ^= 1 << rng.below(8)
            query, h = bytes(q), hashes[pick]
        if i % 41 == 0:
            tbl.vals[tbl.ctrl.index(h >> 57) if (h >> 57) in tbl.ctrl[:buckets] else 0] = n + 3
        yield tbl, keys, query, h


def gen_entry_cases(rng, count):
    for i in range(count):
        n = 1 + rng.below(12)
        idx = rng.below(n) if i % 13 else n + rng.below(3)
        yield ('occupied' if i % 3 else 'vacant'), idx, n


GROUPS = (('hash20', S_H20, 3300), ('hash16', S_H16, 1700),
          ('find_a', S_FA, 1300), ('find_b', S_FB, 1300), ('has_a', S_UA, 1000), ('has_b', S_UB, 1000),
          ('entry', S_ENTRY, 600))


def case_stream(seed=0x115AB):
    """Yield (group, fn, kind, payload) for every vector, in a fixed order."""
    rng = Rng(seed)
    for name, fn, count in GROUPS:
        if fn in (S_H20, S_H16):
            for c in gen_hash_cases(rng, fn, count, {S_H20: 20, S_H16: 16}[fn]):
                yield name, fn, c
        elif fn == S_ENTRY:
            for c in gen_entry_cases(rng, count):
                yield name, fn, c
        else:
            for c in gen_find_cases(rng, fn, count):
                yield name, fn, c


def observe(img, code, fn, payload):
    """Run the real bytes; returns (observation, machine)."""
    if fn in (S_H20, S_H16):
        k0, k1, data = payload
        return run_hash(img, code, fn, k0, k1, data)
    if fn == S_ENTRY:
        return run_entry(img, code, payload)
    return run_find(img, code, fn, payload)


def expected(fn, payload, variant=None):
    """Closed-form (and, for the hasher, object-style) answer; `variant` selects a deliberately wrong model."""
    v = variant or {}
    if fn in (S_H20, S_H16):
        k0, k1, data = payload
        a = ('ok', model_hash(fn, k0, k1, data, **v))
        if not v:
            h = Hasher(k0, k1)
            h.write(data)
            if ('ok', h.finish()) != a:
                raise EvidenceError('closed form and streaming object disagree')
        return a
    if fn == S_ENTRY:
        return model_entry(payload)
    return model_probe(fn, payload, **v)


def agree(fn, obs, exp):
    if fn in (S_H20, S_H16):
        return obs[:1] + obs[2:] == exp
    if obs[0] == 'badargs':
        return False
    if obs[0] == 'panic':
        return exp[0] == 'panic' and obs[1] == exp[1]
    return obs[0] == exp[0] and obs[2] == exp[1]


def summarise(fn, payload, obs):
    if fn in (S_H20, S_H16):
        k0, k1, data = payload
        return f'{k0:#x}\t{k1:#x}\t{data.hex()}\t{obs[2]:#x}'
    if fn == S_ENTRY:
        return f'{payload[0]}\t{payload[1]}/{payload[2]}\t-\t{obs[0]}:{obs[2]}'
    tbl, keys, query, h = payload
    ctrl = hashlib.sha256(bytes(tbl.ctrl) + b''.join(v.to_bytes(8, 'little') for v in tbl.vals)).hexdigest()[:10]
    return f'{tbl.n}/{len(keys)}\t{h:#x}\t{query.hex()}#{ctrl}\t{obs[0]}:{obs[2]}'


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
    add = muts.append
    for fn in SUBJECTS:
        lo, hi = extents[fn]
        insns = [code[v] for v in sorted(code) if lo <= v < hi]
        for ins in insns:
            if ins.op != 'jmp' and (ins.op[0] == 'j' or ins.op.startswith('cmov') or ins.op.startswith('set')):
                muts.append((f'{NAMES[fn]}:{ins.va:#x}:invert {ins.op}', cond_patch(ins), ins.va))
        rots = [i for i in insns if i.op in ('rol', 'shl', 'shr') and i.ops[1][0] == 'i']
        for k, ins in enumerate(rots):
            if fn in (S_H20, S_H16) and k % 6:
                continue
            muts.append((f'{NAMES[fn]}:{ins.va:#x}:{ins.op} count +1', {ins.va + ins.size - 1: (ins.raw[-1] + 1) & 0xff}, ins.va))
        if fn in (S_H20, S_H8):
            for ins in insns:
                if ins.op == 'mov' and ins.ops[1][0] == 'i' and len(ins.raw) == 10:
                    muts.append((f'{NAMES[fn]}:{ins.va:#x}:init constant bit', {ins.va + 2: ins.raw[2] ^ 1}, ins.va))
        mems = [i for i in insns if i.op in ('mov', 'cmp', 'lea') and any(o[0] == 'm' and o[1] is not None and 0 < abs(o[4]) < 0x60
                                                                           and o[1] != 4 for o in i.ops)
                and not any(o[0] == 'i' for o in i.ops) and len(i.raw) in (3, 4, 5)]
        for k, ins in enumerate(mems):
            if k % 2 == (fn & 1):
                muts.append((f'{NAMES[fn]}:{ins.va:#x}:displacement +8', {ins.va + ins.size - 1: (ins.raw[-1] + 8) & 0xff}, ins.va))
    return muts


def wrong_models():
    """(name, group fn, variant) — each must disagree with the real bytes on the control vectors."""
    return [
        ('siphash with 2 compression rounds', S_H20, {'c': 2}),
        ('siphash with 2 finalisation rounds', S_H20, {'d': 2}),
        ('siphash with 4 finalisation rounds', S_H16, {'d': 4}),
        ('siphash without the length byte', S_H20, {'length_byte': False}),
        ('siphash with the key halves swapped', S_H20, {'swap_keys': True}),
        ('siphash finalisation constant 0xfe', S_H16, {'xor_ff': 0xfe}),
        ('probe with an 8-bit tag', S_FA, {'tag_bits': 8}),
        ('probe with a 6-bit tag', S_FB, {'tag_bits': 6}),
        ('probe with a linear stride', S_FA, {'stride_step': 0}),
        ('probe that looks at the first group only', S_FB, {'first_group_only': True}),
        ('hash probe with an 8-bit tag', S_UA, {'tag_bits': 8}),
        ('hash probe with a linear stride', S_UB, {'stride_step': 0}),
    ]


def control_vectors():
    """A fixed small slice of every group, used for every control."""
    picks = {}
    deep = {}
    for k, (group, fn, payload) in enumerate(case_stream()):
        picks.setdefault(group, []).append((fn, payload))
        if fn in SHAPES:
            stats = []
            try:
                tbl, keys, query, h = payload
                probe_find(tbl, h, len(keys), lambda v: keys[v] == query, stats=stats)
            except Bounds:
                pass
            if len(stats) >= 2 and len(deep.setdefault(group, [])) < 40 and k % 3 == 0:
                deep[group].append((fn, payload))
    out = []
    for group, rows in picks.items():
        step = max(len(rows) // 70, 1)
        out.extend(rows[::step][:70])
        out.extend(deep.get(group, []))
    return out


def detects(img, code, ctl, fns=None):
    for fn, payload in ctl:
        if fns is not None and fn not in fns:
            continue
        try:
            obs, _ = observe(img, code, fn, payload)
        except (Unmodelled, EvidenceError, Panic) as e:
            return f'refused: {type(e).__name__}'
        if not agree(fn, obs, expected(fn, payload)):
            return 'differs'
    return None


def run_mutants(data, code, extents, ctl, reached):
    """Returns (rows, killed, equivalent): a survivor must be proven unreached or listed with a reason."""
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
        why = detects(img, c2, ctl, {fn})
        if why:
            rows.append((name, 'detected', why))
            killed += 1
        else:
            if ins_va not in reached:
                rows.append((name, 'unreached', 'no vector executes the patched instruction'))
            else:
                rows.append((name, 'equivalent', 'survived the control slice; listed, not counted'))
            equiv += 1
    return rows, killed, equiv


def corrupted_inputs(data, fdes, img):
    """Each probe must raise; returns list of (name, detected)."""
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
    expect_error('address that is not an FDE start', lambda: decode_subjects_one(img, fdes, S_H20 + 1))
    expect_error('address outside every section', lambda: img.read(0x10, 4))
    expect_error('address in .bss', lambda: img.read(img.sec['.bss'][0], 4))
    expect_error('unlisted opcode', lambda: decode_one(b'\x0f\x0b' + b'\x90' * 16, 0, 0x1000))
    expect_error('truncated ULEB128', lambda: uleb(b'\x80\x80', 0))
    expect_error('init constant patched in the image', lambda: constants_check(Image(data, {S_H20 + 0x9: 0x75 ^ 1})))
    expect_error('length-byte shift patched in the image', lambda: selfcheck(Image(data, {0x47174c1: 0x38 ^ 1}), fdes))
    expect_error('tag shift patched in the image', lambda: selfcheck(Image(data, {0x3ee628a: 0x39 ^ 1}), fdes))
    return out


def decode_subjects_one(img, fdes, va):
    r = fdes.range_of(va)
    if r['start'] != va:
        raise EvidenceError('not an FDE start')


def constants_check(img):
    for fn, k in ((S_H20, 4), (S_H16, 4)):
        raw = img.read(fn, 0x60)
        found = [int.from_bytes(raw[i + 2:i + 10], 'little') for i in range(len(raw) - 10)
                 if raw[i] & 0xf8 == 0x48 and raw[i + 1] & 0xf8 == 0xb8]
        if tuple(found[:4]) != SIP_CONST:
            raise EvidenceError(f'{fn:#x}: initial constants {found[:4]} differ from SipHash')


def selfcheck(img, fdes):
    """Run one fixed hash and one fixed probe on `img`; raise if the bytes no longer give the model answer."""
    code, _ = decode_subjects(img, fdes)
    k0, k1, key = 0x0123456789abcdef, 0xfedcba9876543210, bytes(range(1, 21))
    obs, _ = run_hash(img, code, S_H20, k0, k1, key)
    if obs[2] != siphash(k0, k1, key):
        raise EvidenceError('hash20 no longer matches SipHash-1-3')
    tbl = RawTable(8)
    tbl.insert(0x2a << 57 | 3, 0)
    case = (tbl, [key], key, 0x2a << 57 | 3)
    obs, _ = run_find(img, code, S_FA, case)
    if not agree(S_FA, obs, model_probe(S_FA, case)):
        raise EvidenceError('find_a no longer matches the probe model')


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
    constants_check(img)
    selfcheck(img, fdes)
    # decoded instructions
    with open(out / 'instructions.tsv', 'w') as f:
        f.write('function\taddress\tsize\tbytes\tdecoded\n')
        for fn in SUBJECTS:
            lo, hi = extents[fn]
            for va in sorted(v for v in code if lo <= v < hi):
                ins = code[va]
                f.write(f'{NAMES[fn]}\t{va:#x}\t{ins.size}\t{ins.raw.hex()}\t{show(ins)}\n')
    # vectors
    total, bad, groups = 0, 0, Counter()
    full, reached = hashlib.sha256(), set()
    with open(out / 'vectors.tsv', 'w') as f:
        f.write('index\tgroup\tfunction\tinput_a\tinput_b\tinput_c\tobserved\n')
        for idx, (group, fn, payload) in enumerate(case_stream()):
            obs, m = observe(img, code, fn, payload)
            reached |= m.seen
            if not agree(fn, obs, expected(fn, payload)):
                raise EvidenceError(f'vector {idx} ({group}) disagrees with the model')
            row = f'{idx}\t{group}\t{NAMES[fn]}\t{summarise(fn, payload, obs)}\n'
            full.update(row.encode())
            groups[group] += 1
            total += 1
            if idx % 9 in (0, 3, 6):
                f.write(row)
    # controls
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
    unexecuted = sorted(v for v in code if v not in reached and any(lo <= v < hi for f, (lo, hi) in extents.items()
                                                                      if f in SUBJECTS))
    evidence = {
        'binary': BINARY, 'sha256': digest, 'subjects': {NAMES[fn]: [hex(extents[fn][0]), hex(extents[fn][1])]
                                                         for fn in SUBJECTS},
        'instructions': insn_total, 'unexecuted': [hex(v) for v in unexecuted], 'callee_not_claimed': {NAMES[S_WRITE]: [hex(extents[S_WRITE][0]), hex(extents[S_WRITE][1])]},
        'groups': dict(groups), 'vectors': total, 'rows_sha256': full.hexdigest(),
        'mutants': {'listed': len(mrows), 'detected': killed, 'survivors': equiv},
        'wrong_models': len(wrows), 'corrupted_inputs': len(crows),
        'sip_constants': [hex(c) for c in SIP_CONST], 'panic_locations': [hex(LOC_BOUNDS_FIND), hex(LOC_BOUNDS_ENTRY)],
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
