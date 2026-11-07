#!/usr/bin/env python3
"""Reconstruct the node #115 order value gate (min $100, max $5,000,000) from ELF bytes.

The target is read as bytes and never executed. A small x86-64 evaluator in this
file runs the real instruction bytes of the gate with recorded stubs for every
host call, and each run is compared with the pure-Python rule in `spec`. The
evaluator is the one proven on the earlier #94 packets; it is copied here (with
the AL-immediate ALU forms added) so the tool needs no disassembler.

Usage: python3 tools/order_value_gate_115.py --out <folder>
"""
import argparse
import bisect
import collections
import hashlib
import json
import pathlib
import re
import struct
import sys

SHA256 = "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301"
ROOT = pathlib.Path(__file__).resolve().parents[1]
TARGET = ROOT / "artifacts" / "node" / "115" / "hl-node"

U64 = (1 << 64) - 1
U32 = (1 << 32) - 1
DEX_STRIDE = 0x510
MAX_STEPS = 4000
MAX_PIECES = 200000
STACK = 0x6f00_0000
RETURN_MARK = 0x6000_0000
RAX, RCX, RDX, RBX, RSP, RBP, RSI, RDI = range(8)
R12, R13, R14, R15 = 12, 13, 14, 15
CALLER_SAVED = (RAX, RCX, RDX, RSI, RDI, 8, 9, 10, 11)


class ToolError(Exception):
    pass


def fail(message):
    raise ToolError(message)


class Split(Exception):
    """The current interval must be cut before `at`."""

    def __init__(self, at):
        super().__init__(at)
        self.at = at


class Done(Exception):
    def __init__(self, how, where):
        super().__init__(how)
        self.how, self.where = how, where


class Image:
    """Section map and FDE extents of one ELF image."""

    def __init__(self, data):
        if data[:5] != b"\x7fELF\x02":
            fail("not ELF64")
        self.data = data
        shoff = struct.unpack_from("<Q", data, 0x28)[0]
        entsize, count, strndx = struct.unpack_from("<HHH", data, 0x3a)
        rows = [struct.unpack_from("<IIQQQQIIQQ", data, shoff + i * entsize) for i in range(count)]
        strings = rows[strndx][4]
        self.sections = {}
        for row in rows:
            if row[1] == 8:  # SHT_NOBITS occupies no file bytes; mapping its VAs would
                continue  # return unrelated file bytes as if they lived there.
            end = data.index(b"\0", strings + row[0])
            name = data[strings + row[0]:end].decode()
            if name in self.sections:
                fail(f"duplicate section name {name}")
            self.sections[name] = (row[3], row[4], row[5])
        self.text_va, self.text_off, self.text_size = self.sections[".text"]
        self.fdes = self._fdes()
        self.starts = [row[0] for row in self.fdes]
        self.cache = {}

    def file_offset(self, va):
        for addr, off, size in self.sections.values():
            if addr and addr <= va < addr + size:
                return va - addr + off
        fail(f"address {va:#x} is outside every section")

    def _fdes(self):
        addr, off, _ = self.sections[".eh_frame_hdr"]
        if self.data[off + 3] != 0x3b:
            fail("unexpected .eh_frame_hdr table encoding")
        count = struct.unpack_from("<I", self.data, off + 8)[0]
        rows = []
        for i in range(count):
            start, fde = struct.unpack_from("<ii", self.data, off + 12 + 8 * i)
            start += addr
            fde_off = self.file_offset(fde + addr)
            begin, size = struct.unpack_from("<iI", self.data, fde_off + 8)
            if begin + fde + addr + 8 != start:
                fail(f"FDE at {fde + addr:#x} disagrees with the search table")
            rows.append((start, start + size))
        rows.sort()
        return rows

    def fde_of(self, va):
        i = bisect.bisect_right(self.starts, va) - 1
        if i < 0 or not self.fdes[i][0] <= va < self.fdes[i][1]:
            fail(f"{va:#x} is outside every FDE")
        return self.fdes[i]

    def fetch(self, va):
        insn = self.cache.get(va)
        if insn is None:
            if not self.text_va <= va < self.text_va + self.text_size:
                fail(f"fetch outside .text at {va:#x}")
            insn = decode(self.data, va - self.text_va + self.text_off, va)
            self.cache[va] = insn
        return insn


def modrm_length(data, p):
    modrm = data[p]
    mod, rm = modrm >> 6, modrm & 7
    length = 1
    if mod == 3:
        return length
    if rm == 4:
        length += 1
        if mod == 0 and data[p + 1] & 7 == 5:
            length += 4
    if mod == 0 and rm == 5:
        length += 4
    elif mod == 1:
        length += 1
    elif mod == 2:
        length += 4
    return length


MODRM_ONE = (set(range(0x00, 0x04)) | set(range(0x08, 0x0c)) | set(range(0x10, 0x14)) | set(range(0x18, 0x1c))
             | set(range(0x20, 0x24)) | set(range(0x28, 0x2c)) | set(range(0x30, 0x34)) | set(range(0x38, 0x3c))
             | set(range(0x84, 0x90)) | set(range(0xd8, 0xe0)) | {0x63, 0xd0, 0xd1, 0xd2, 0xd3, 0xfe, 0xff})
PLAIN_ONE = (set(range(0x50, 0x60)) | set(range(0x90, 0xa0))
             | {0xa4, 0xa5, 0xa6, 0xa7, 0xaa, 0xab, 0xac, 0xad, 0xae, 0xaf, 0xc3, 0xc9, 0xcb, 0xcc, 0xcf,
                0xf4, 0xf5, 0xf8, 0xf9, 0xfa, 0xfb, 0xfc, 0xfd})
PLAIN_TWO = {0x05, 0x06, 0x08, 0x09, 0x0b, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x77, 0xa0, 0xa1, 0xa2, 0xa8,
             0xa9, 0xaa} | set(range(0xc8, 0xd0))
PREFIXES = {0x66, 0x67, 0xf2, 0xf3, 0x2e, 0x36, 0x3e, 0x26, 0x64, 0x65, 0xf0}


class Insn:
    """One decoded instruction: position, opcode key, REX byte and ModRM offset."""

    __slots__ = ("va", "off", "size", "key", "rex", "modrm", "target", "body", "wide16")

    def __init__(self, va, off, size, key, rex, modrm, target, body, wide16):
        self.va, self.off, self.size, self.key = va, off, size, key
        self.rex, self.modrm, self.target, self.body, self.wide16 = rex, modrm, target, body, wide16


def decode(data, off, va):
    """Decode the length of one 64-bit instruction, or raise on an unknown form."""
    p = off
    wide16 = False
    while data[p] in PREFIXES:
        wide16 = wide16 or data[p] == 0x66
        p += 1
    rex = 0
    if 0x40 <= data[p] <= 0x4f:
        rex = data[p]
        p += 1
    body = p
    op = data[p]
    p += 1
    iz = 2 if wide16 else 4

    def done(end, key, modrm=None, rel=None):
        size = end - off
        target = None if rel is None else va + size + rel
        return Insn(va, off, size, key, rex, modrm, target, body, wide16)

    if op in (0xc4, 0xc5, 0x62):
        if op == 0xc5:
            space = 1
            p += 1
        elif op == 0xc4:
            space = data[p] & 0x1f
            p += 2
        else:
            space = data[p] & 7
            p += 3
        code = data[p]
        p += 1
        if space == 1 and code == 0x77:
            return done(p, ("vex", code))
        p += modrm_length(data, p)
        if space == 3 or (space == 1 and code in (0x70, 0x71, 0x72, 0x73, 0xc2, 0xc4, 0xc5, 0xc6)):
            p += 1
        return done(p, ("vex", code))
    if op == 0x0f:
        two = data[p]
        p += 1
        if two in (0x38, 0x3a):
            three = data[p]
            p += 1
            modrm = p
            p += modrm_length(data, p) + (1 if two == 0x3a else 0)
            return done(p, (0x0f, two, three), modrm)
        if 0x80 <= two <= 0x8f:
            return done(p + 4, (0x0f, two), rel=struct.unpack_from("<i", data, p)[0])
        if two in PLAIN_TWO:
            return done(p, (0x0f, two))
        modrm = p
        p += modrm_length(data, p)
        if two in (0x70, 0x71, 0x72, 0x73, 0xa4, 0xac, 0xba, 0xc2, 0xc4, 0xc5, 0xc6):
            p += 1
        return done(p, (0x0f, two), modrm)
    if op in MODRM_ONE:
        modrm = p
        return done(p + modrm_length(data, p), op, modrm)
    if op in (0x69, 0x81, 0xc7):
        modrm = p
        return done(p + modrm_length(data, p) + iz, op, modrm)
    if op in (0x6b, 0x80, 0x83, 0xc0, 0xc1, 0xc6):
        modrm = p
        return done(p + modrm_length(data, p) + 1, op, modrm)
    if op in (0xf6, 0xf7):
        modrm = p
        imm = 0
        if (data[p] >> 3) & 7 in (0, 1):
            imm = 1 if op == 0xf6 else iz
        return done(p + modrm_length(data, p) + imm, op, modrm)
    if (op < 0x40 and op & 7 == 4) or op in (0xa8, 0x6a, 0xcd) or 0xb0 <= op <= 0xb7:
        return done(p + 1, op)
    if (op < 0x40 and op & 7 == 5) or op in (0xa9, 0x68):
        return done(p + iz, op)
    if op in PLAIN_ONE:
        return done(p, op)
    if 0xb8 <= op <= 0xbf:
        return done(p + (8 if rex & 8 else iz), op)
    if 0x70 <= op <= 0x7f or op in (0xeb, 0xe0, 0xe1, 0xe2, 0xe3):
        return done(p + 1, op, rel=struct.unpack_from("<b", data, p)[0])
    if op in (0xe8, 0xe9):
        return done(p + 4, op, rel=struct.unpack_from("<i", data, p)[0])
    if op == 0xc2:
        return done(p + 2, op)
    if op in (0xa0, 0xa1, 0xa2, 0xa3):
        return done(p + 8, op)
    fail(f"unknown opcode {op:#x} at {va:#x}")


def sweep(image, start, end):
    """Linear sweep of one FDE range. Must stop exactly on the FDE end."""
    rows = []
    va = start
    delta = image.text_off - image.text_va
    while va < end:
        insn = decode(image.data, va + delta, va)
        rows.append(insn)
        va += insn.size
    if va != end:
        fail(f"sweep of {start:#x} ended at {va:#x}, FDE ends at {end:#x}")
    return rows


class V:
    """A value: ((a*x + c) mod 2^64) >> k. a == 0 means the constant c."""

    __slots__ = ("a", "c", "k", "v")

    def __init__(self, a, c, k, v):
        self.a, self.c, self.k, self.v = a, c, k, v


def const(value):
    return V(0, value & U64, 0, value & U64)


COND = {0: lambda f: f[3], 1: lambda f: not f[3], 2: lambda f: f[0], 3: lambda f: not f[0],
        4: lambda f: f[1], 5: lambda f: not f[1], 6: lambda f: f[0] or f[1], 7: lambda f: not (f[0] or f[1]),
        8: lambda f: f[2], 9: lambda f: not f[2], 12: lambda f: f[2] != f[3], 13: lambda f: f[2] == f[3],
        14: lambda f: f[1] or f[2] != f[3], 15: lambda f: not f[1] and f[2] == f[3]}


class Machine:
    """Evaluator over one input interval. Unknown values are None."""

    def __init__(self, image, lo, hi):
        self.image, self.lo, self.hi = image, lo, hi
        self.regs = [None] * 16
        self.low8 = {}
        self.regs[RSP] = const(STACK)
        self.mem = {}
        self.tags = {}
        self.regions = []
        self.xmm = {}
        self.flags = None
        self.stubs = {}
        self.stop_at = set()
        self.pc = 0

    def input(self):
        return self.form(1, 0)

    def form(self, a, c, k=0):
        c &= U64
        if a == 0:
            return const(c >> k)
        base = (a * self.lo + c) & U64
        top = base + a * (self.hi - self.lo)
        if top > U64:
            raise Split(self.lo + (U64 + 1 - base + a - 1) // a)
        return V(a, c, k, base >> k)

    def cross(self, value, points):
        """Cut the interval where the value reaches any of the points."""
        if value is None or value.a == 0:
            return
        base = (value.a * self.lo + value.c) & U64
        cuts = []
        for point in points:
            target = point << value.k
            if target > base:
                at = self.lo + (target - base + value.a - 1) // value.a
                if at <= self.hi:
                    cuts.append(at)
        if cuts:
            raise Split(min(cuts))

    def plain(self, value):
        """Force a shifted value to be one constant on this interval."""
        if value is None or value.k == 0 or value.a == 0:
            return value
        self.cross(value, [value.v + 1])
        return const(value.v)

    def trunc(self, value, bits):
        if value is None:
            return None
        if bits == 64:
            return value
        if value.a == 0:
            return const(value.v & ((1 << bits) - 1))
        value = self.plain(value)
        if value.a == 0:
            return const(value.v & ((1 << bits) - 1))
        if bits != 32:
            return None
        base = (value.a * self.lo + value.c) & U64
        block = base >> 32
        if (base + value.a * (self.hi - self.lo)) >> 32 != block:
            return None
        return self.form(value.a, value.c - (block << 32))

    def get(self, reg, bits):
        if bits == 8:
            if self.regs[reg] is None:
                low = self.low8.get(reg)
                return None if low is None else const(low)
            return self.trunc(self.regs[reg], 8)
        return self.trunc(self.regs[reg], bits)

    def put(self, reg, bits, value):
        self.low8.pop(reg, None)
        if bits >= 32:
            self.regs[reg] = value
            return
        old = self.regs[reg]
        if value is None or value.a:
            self.regs[reg] = None
            return
        mask = (1 << bits) - 1
        if old is None or old.a:
            self.regs[reg] = None
            if bits == 8:
                self.low8[reg] = value.v & mask
            return
        self.regs[reg] = const((old.v & ~mask) | (value.v & mask))

    def operand(self, insn):
        data = self.image.data
        modrm = data[insn.modrm]
        mod, rm = modrm >> 6, modrm & 7
        rexb, rexx = (insn.rex & 1) << 3, (insn.rex & 2) << 2
        if mod == 3:
            return ("r", rm | rexb)
        p = insn.modrm + 1
        base, index, scale = None, None, 1
        if rm == 4:
            sib = data[p]
            p += 1
            scale = 1 << (sib >> 6)
            if ((sib >> 3) & 7) | rexx != 4:
                index = ((sib >> 3) & 7) | rexx
            if sib & 7 == 5 and mod == 0:
                return ("m", None, index, scale, struct.unpack_from("<i", data, p)[0])
            base = (sib & 7) | rexb
        elif mod == 0 and rm == 5:
            return ("m", None, None, 1, insn.va + insn.size + struct.unpack_from("<i", data, p)[0])
        else:
            base = rm | rexb
        disp = 0
        if mod == 1:
            disp = struct.unpack_from("<b", data, p)[0]
        elif mod == 2:
            disp = struct.unpack_from("<i", data, p)[0]
        return ("m", base, index, scale, disp)

    def address(self, operand):
        _, base, index, scale, disp = operand
        return self.linear([(base, 1), (index, scale)], disp)

    def linear(self, terms, disp):
        a, c = 0, disp
        for reg, scale in terms:
            if reg is None:
                continue
            value = self.plain(self.regs[reg])
            if value is None:
                return None
            a += value.a * scale
            c += value.c * scale
        return self.form(a, c)

    def load(self, address, size):
        if address is None:
            fail(f"load through an unknown address at {self.pc:#x}")
        at = address.v
        for start, end, reader in self.regions:
            if start <= at and at + size <= end:
                if address.a:
                    last = at + address.a * (self.hi - self.lo)
                    if last + size > end:
                        fail(f"affine load leaves its region at {self.pc:#x}")
                    if address.a % DEX_STRIDE and address.a % 32:
                        fail(f"affine load has an unknown stride at {self.pc:#x}")
                return const(reader(at - start))
        if address.a:
            fail(f"affine load outside every region at {self.pc:#x}")
        tag = self.tags.get(at)
        if tag is not None and tag[0] == size:
            return tag[1]
        chunk = [self.mem.get(at + i) for i in range(size)]
        if None in chunk:
            return None
        return const(int.from_bytes(bytes(chunk), "little"))

    def store(self, address, size, value):
        if address is None or address.a:
            fail(f"store through a non-constant address at {self.pc:#x}")
        at = address.v
        for i in range(at - 7, at + size):
            self.tags.pop(i, None)
        for i in range(size):
            self.mem.pop(at + i, None)
        if value is None:
            return
        if value.a:
            self.tags[at] = (size, value)
            return
        for i, byte in enumerate((value.v & ((1 << (8 * size)) - 1)).to_bytes(size, "little")):
            self.mem[at + i] = byte

    def poke(self, at, size, value):
        self.store(const(at), size, const(value))

    def read(self, operand, bits):
        if operand[0] == "r":
            return self.get(operand[1], bits)
        return self.load(self.address(operand), bits // 8)

    def write(self, operand, bits, value):
        if operand[0] == "r":
            self.put(operand[1], bits, value)
        else:
            self.store(self.address(operand), bits // 8, value)

    def set_flags(self, left, right, result, bits, subtract):
        mask = (1 << bits) - 1
        sign = 1 << (bits - 1)
        res = result & mask
        carry = left < right if subtract else left + right > mask
        if subtract:
            over = bool((left ^ right) & (left ^ res) & sign)
        else:
            over = bool(~(left ^ right) & (left ^ res) & sign)
        self.flags = [carry, res == 0, bool(res & sign), over]

    def compare(self, left, right, bits):
        """Flags of left-right, with cuts at every value that can change them."""
        if left is None or right is None:
            self.flags = None
            return
        sign = 1 << (bits - 1)
        if left.a and right.a:
            if left.a != right.a or left.k or right.k:
                fail(f"compare of two different input forms at {self.pc:#x}")
        elif left.a:
            self.cross(left, [right.v, right.v + 1, (right.v + sign) & ((1 << bits) - 1)])
        elif right.a:
            self.cross(right, [left.v, left.v + 1, (left.v + sign) & ((1 << bits) - 1)])
        self.set_flags(left.v, right.v, left.v - right.v, bits, True)

    def add(self, left, right, bits):
        if left is None or right is None:
            self.flags = None
            return None
        left, right = self.plain(left), self.plain(right)
        mask = (1 << bits) - 1
        sign = 1 << (bits - 1)
        for one, other in ((left, right), (right, left)):
            if one.a and not other.a:
                self.cross(one, [(mask + 1 - other.v) & mask, ((mask + 1 - other.v) & mask) + 1,
                                 (sign - other.v) & mask, mask + 1 - other.v, ((sign - other.v) & mask) + sign])
        self.set_flags(left.v, right.v, left.v + right.v, bits, False)
        return self.trunc(self.form(left.a + right.a, left.c + right.c), bits)

    def sub(self, left, right, bits):
        self.compare(left, right, bits)
        if left is None or right is None:
            return None
        left, right = self.plain(left), self.plain(right)
        if right.a:
            if left.a != right.a:
                fail(f"subtract of an input form at {self.pc:#x}")
            return const((left.c - right.c) & ((1 << bits) - 1))
        return self.trunc(self.form(left.a, left.c - right.c), bits)

    def logic(self, kind, left, right, bits):
        if left is None or right is None:
            self.flags = None
            return None
        if left.a or right.a:
            fail(f"logic on an input form at {self.pc:#x}")
        value = {"and": left.v & right.v, "or": left.v | right.v, "xor": left.v ^ right.v}[kind]
        self.flags = [False, value == 0, bool(value >> (bits - 1)), False]
        return const(value)

    def test(self, left, right, bits):
        if left is None or right is None:
            self.flags = None
            return
        if left.a or right.a:
            if left.a != right.a or left.c != right.c or left.k != right.k:
                fail(f"test on an input form at {self.pc:#x}")
            self.cross(left, [1, 1 << (bits - 1)])
        value = left.v & right.v
        self.flags = [False, value == 0, bool(value >> (bits - 1)), False]

    def shift(self, value, kind, count, bits):
        if value is None:
            self.flags = None
            return None
        if kind == 5 and bits == 64:
            if value.a:
                result = self.form(value.a, value.c, value.k + count)
                self.cross(result, [1])
                self.flags = [None, result.v == 0, False, None]
                return result
            result = value.v >> count
        elif kind == 4:
            value = self.plain(value)
            if value.a:
                self.flags = None
                return self.trunc(self.form(value.a << count, value.c << count), bits)
            result = (value.v << count) & ((1 << bits) - 1)
        else:
            fail(f"shift form {kind} width {bits} at {self.pc:#x}")
        self.flags = [None, result == 0, bool(result >> (bits - 1)), None]
        return const(result)

    def multiply(self, left, right, bits):
        left, right = self.plain(left), self.plain(right)
        if left is None or right is None:
            return None
        if left.a and right.a:
            fail(f"product of two input forms at {self.pc:#x}")
        return self.trunc(self.form(left.a * right.v + right.a * left.v, left.c * right.c), bits)

    def wide_multiply(self, operand):
        one, two = self.regs[RAX], self.read(operand, 64)
        one, two = self.plain(one), self.plain(two)
        if one is None or two is None:
            fail(f"mul of an unknown value at {self.pc:#x}")
        if one.a and two.a:
            fail(f"mul of two input forms at {self.pc:#x}")
        if one.a or two.a:
            scale, form = (two.v, one) if one.a else (one.v, two)
            base = (form.a * self.lo + form.c) & U64
            if base * scale > U64:
                self.regs[RAX], self.regs[RDX] = None, None
                self.flags = [True, None, None, True]
                return
            top = (base + form.a * (self.hi - self.lo)) * scale
            if top > U64:
                raise Split(self.lo + (U64 + 1 - base * scale + form.a * scale - 1) // (form.a * scale))
            self.regs[RAX] = self.form(form.a * scale, form.c * scale)
            self.regs[RDX] = const(0)
            self.flags = [False, None, None, False]
            return
        product = one.v * two.v
        self.regs[RAX], self.regs[RDX] = const(product & U64), const(product >> 64)
        self.flags = [product >> 64 != 0, None, None, product >> 64 != 0]

    def condition(self, code):
        if self.flags is None:
            return None
        if code not in COND:
            fail(f"condition {code} at {self.pc:#x} is not modelled")
        return COND[code](self.flags)

    def immediate(self, insn, size):
        data = self.image.data
        at = insn.off + insn.size - size
        fmt = {1: "<b", 2: "<h", 4: "<i"}[size]
        return struct.unpack_from(fmt, data, at)[0]

    def call(self, target, where):
        if target not in self.stubs:
            fail(f"call to {target:#x} at {where:#x} has no stub")
        returned = self.stubs[target](self) or {}
        for reg in CALLER_SAVED:
            self.put(reg, 64, returned.get(reg))
        self.flags = None

    def run(self, start):
        self.pc = start
        for _ in range(MAX_STEPS):
            if self.pc in self.stop_at:
                raise Done("stop", self.pc)
            self.step()
        fail(f"no stop from {start:#x}")

    def step(self):
        insn = self.image.fetch(self.pc)
        data = self.image.data
        key = insn.key
        here = self.pc
        following = here + insn.size
        bits = 64 if insn.rex & 8 else 16 if insn.wide16 else 32
        rexr = (insn.rex & 4) << 1
        self.pc = following
        if key == 0x90 or key == (0x0f, 0x1f):
            return
        if isinstance(key, tuple):
            self.two_byte(insn, key, bits, rexr, here)
            return
        if 0x50 <= key <= 0x57:
            sp = (self.regs[RSP].v - 8) & U64
            self.regs[RSP] = const(sp)
            self.store(const(sp), 8, self.regs[(key & 7) | ((insn.rex & 1) << 3)])
            return
        if 0x58 <= key <= 0x5f:
            sp = self.regs[RSP].v
            self.regs[(key & 7) | ((insn.rex & 1) << 3)] = self.load(const(sp), 8)
            self.regs[RSP] = const(sp + 8)
            return
        if key in (0x89, 0x8b, 0x88, 0x8a):
            width = bits if key in (0x89, 0x8b) else 8
            operand = self.operand(insn)
            reg = ((data[insn.modrm] >> 3) & 7) | rexr
            if key in (0x89, 0x88):
                self.write(operand, width, self.get(reg, width))
            else:
                self.put(reg, width, self.read(operand, width))
            return
        if key in (0xc7, 0xc6):
            width = bits if key == 0xc7 else 8
            size = 2 if width == 16 else 1 if width == 8 else 4
            self.write(self.operand(insn), width, const(self.immediate(insn, size)))
            return
        if 0xb8 <= key <= 0xbf:
            reg = (key & 7) | ((insn.rex & 1) << 3)
            size = insn.size - (insn.body - insn.off) - 1
            value = int.from_bytes(data[insn.off + insn.size - size:insn.off + insn.size], "little")
            self.put(reg, 64 if size == 8 else 32 if size == 4 else 16, const(value))
            return
        if 0xb0 <= key <= 0xb7:
            self.put((key & 7) | ((insn.rex & 1) << 3), 8, const(data[insn.off + insn.size - 1]))
            return
        if key == 0x8d:
            operand = self.operand(insn)
            if operand[0] != "m":
                fail(f"lea with a register at {here:#x}")
            value = self.address(operand)
            self.put(((data[insn.modrm] >> 3) & 7) | rexr, bits, self.trunc(value, bits))
            return
        if key in (0x81, 0x83, 0x80):
            operand = self.operand(insn)
            width = 8 if key == 0x80 else bits
            size = 4 if key == 0x81 and width != 16 else 2 if key == 0x81 else 1
            imm = const(self.immediate(insn, size))
            imm = self.trunc(imm, width)
            self.group(operand, width, (data[insn.modrm] >> 3) & 7, imm, here)
            return
        if key in (0x04, 0x0c, 0x24, 0x2c, 0x34, 0x3c):
            imm = self.trunc(const(self.immediate(insn, 1) & 0xff), 8)
            self.group(("r", RAX), 8, key >> 3, imm, here)
            return
        if key in (0x05, 0x0d, 0x25, 0x2d, 0x35):
            imm = self.trunc(const(self.immediate(insn, 4)), bits)
            self.group(("r", RAX), bits, key >> 3, imm, here)
            return
        if key < 0x40 and key & 7 < 4:
            width = bits if key & 1 else 8
            operand = self.operand(insn)
            reg = ("r", ((data[insn.modrm] >> 3) & 7) | rexr)
            first, second = (operand, reg) if key & 7 < 2 else (reg, operand)
            if key >> 3 == 6 and first == second:
                self.write(first, width, const(0))
                self.flags = [False, True, False, False]
                return
            self.group(first, width, key >> 3, self.read(second, width), here)
            return
        if key == 0x3d:
            imm = self.trunc(const(self.immediate(insn, 4)), bits)
            self.group(("r", RAX), bits, 7, imm, here)
            return
        if key in (0x84, 0x85):
            width = bits if key == 0x85 else 8
            operand = self.operand(insn)
            self.test(self.read(operand, width), self.get(((data[insn.modrm] >> 3) & 7) | rexr, width), width)
            return
        if key == 0xa8:
            self.test(self.get(RAX, 8), const(data[insn.off + insn.size - 1]), 8)
            return
        if key in (0xc1, 0xd1):
            count = data[insn.off + insn.size - 1] if key == 0xc1 else 1
            operand = self.operand(insn)
            kind = (data[insn.modrm] >> 3) & 7
            self.write(operand, bits, self.shift(self.read(operand, bits), kind, count, bits))
            return
        if key in (0x69, 0x6b):
            operand = self.operand(insn)
            imm = const(self.immediate(insn, 4 if key == 0x69 else 1))
            self.put(((data[insn.modrm] >> 3) & 7) | rexr, bits, self.multiply(self.read(operand, bits), imm, bits))
            self.flags = None
            return
        if key == 0xf7 or key == 0xf6:
            self.unary(insn, key, bits, here)
            return
        if key == 0xff:
            kind = (data[insn.modrm] >> 3) & 7
            operand = self.operand(insn)
            if kind == 2 and operand[0] == "m" and operand[1] is None and operand[2] is None:
                self.call(operand[4], here)
                return
            fail(f"indirect form {kind} at {here:#x}")
        if key == 0xe8:
            self.call(insn.target, here)
            return
        if key in (0xeb, 0xe9):
            self.pc = insn.target
            return
        if 0x70 <= key <= 0x7f:
            self.jump(key - 0x70, insn, here)
            return
        if key == 0xc3:
            sp = self.regs[RSP].v
            mark = self.load(const(sp), 8)
            if mark is None or mark.v != RETURN_MARK:
                fail(f"return at {here:#x} without the return mark")
            raise Done("ret", here)
        fail(f"instruction {key:#x} at {here:#x} is not modelled")

    def group(self, operand, width, kind, right, here):
        left = self.read(operand, width)
        if kind == 0:
            self.write(operand, width, self.add(left, right, width))
        elif kind == 5:
            self.write(operand, width, self.sub(left, right, width))
        elif kind == 7:
            self.compare(left, right, width)
        elif kind in (1, 4, 6):
            if kind == 6 and operand[0] == "r" and left is None:
                fail(f"xor of an unknown register at {here:#x}")
            self.write(operand, width, self.logic({1: "or", 4: "and", 6: "xor"}[kind], left, right, width))
        else:
            fail(f"group form {kind} at {here:#x}")

    def unary(self, insn, key, bits, here):
        kind = (self.image.data[insn.modrm] >> 3) & 7
        operand = self.operand(insn)
        if key == 0xf7 and kind == 4 and bits == 64:
            self.wide_multiply(operand)
            return
        if kind == 0:
            width = 8 if key == 0xf6 else bits
            imm = self.image.data[insn.off + insn.size - 1] if key == 0xf6 else self.immediate(insn, 4)
            self.test(self.read(operand, width), const(imm), width)
            return
        fail(f"unary form {kind} at {here:#x}")

    def jump(self, code, insn, here):
        taken = self.condition(code)
        if taken is None:
            fail(f"branch on unknown flags at {here:#x}")
        if taken:
            self.pc = insn.target

    def two_byte(self, insn, key, bits, rexr, here):
        data = self.image.data
        two = key[1]
        if 0x80 <= two <= 0x8f:
            self.jump(two - 0x80, insn, here)
            return
        if 0x40 <= two <= 0x4f:
            reg = ((data[insn.modrm] >> 3) & 7) | rexr
            taken = self.condition(two - 0x40)
            src = self.read(self.operand(insn), bits)
            old = self.get(reg, bits)
            self.put(reg, bits, None if taken is None else src if taken else old)
            return
        if 0x90 <= two <= 0x9f:
            taken = self.condition(two - 0x90)
            self.write(self.operand(insn), 8, None if taken is None else const(int(taken)))
            return
        if two in (0xb6, 0xb7):
            value = self.read(self.operand(insn), 8 if two == 0xb6 else 16)
            self.put(((data[insn.modrm] >> 3) & 7) | rexr, bits, value)
            return
        if two == 0xaf:
            reg = ((data[insn.modrm] >> 3) & 7) | rexr
            self.put(reg, bits, self.multiply(self.get(reg, bits), self.read(self.operand(insn), bits), bits))
            self.flags = None
            return
        if two in (0x10, 0x28, 0x6f, 0x11, 0x29, 0x7f):
            reg = ((data[insn.modrm] >> 3) & 7) | rexr
            operand = self.operand(insn)
            if operand[0] != "m":
                fail(f"xmm register move at {here:#x}")
            at = self.address(operand)
            if two in (0x10, 0x28, 0x6f):
                self.xmm[reg] = [self.mem.get(at.v + i) for i in range(16)]
            else:
                for i, byte in enumerate(self.xmm.get(reg, [None] * 16)):
                    self.mem.pop(at.v + i, None)
                    if byte is not None:
                        self.mem[at.v + i] = byte
            return
        fail(f"instruction {key} at {here:#x} is not modelled")




# ---------------------------------------------------------------------------
# The order value gate.
#
# Three copies, 0x4ea bytes each, identical except for call targets and the
# state layout (copy 3 moves five state fields by 0xb70).
# ---------------------------------------------------------------------------
GATES = (0x22e5c90, 0x57ca550, 0x57caa40)
GATE_SIZE = 0x4ea
TAG_OK = 0x1a2
OUT = 0x7000_0000
STATE = 0x7100_0000
ORDER = 0x7200_0000
KEY = 0x7300_0000
RECORD = 0x7400_0000
ELEMENTS = 0x7500_0000
KEY_BYTES = bytes(0xa0 + i for i in range(20))
MIN_VALUE = 10 ** 10          # 0x9502f9 << 10
MAX_VALUE = 0x1c6bf52634000   # 5 * 10**14
PRODUCT_CAP = 0x1999999999999999
ID_LOW, ID_HIGH = 5, 10080    # asset ids that pass the first gate
HEAD_MARK = 0x8000000000000001
MIN_PAYLOAD = 0x4059000000000000   # 100.0
MAX_PAYLOAD = 0x415312d000000000   # 5000000.0
TAG_NOT_ENABLED, TAG_BAD_ID, TAG_PRODUCT, TAG_NO_MARKET, TAG_SUM = 0xdd, 0xd1, 0x6d, 0xdc, 0xd2
TAG_TOO_SMALL, TAG_TOO_LARGE, TAG_REJECT = 0xd7, 0xd8, 0x78

# (offset inside the function, size of the instruction field start, layout name)
LAYOUT_FIELDS = (("enabled", 0x11 + 2), ("market", 0x219 + 2), ("lea_addr", 0xd8 + 3),
                 ("set_obj", 0x275 + 3), ("count", 0x29c + 3), ("base", 0x2a8 + 3))
# Roles of the 17 call sites, in address order.
ROLES = ("resolve", "market_check", "price_of", "kind_of", "margin_check", "set_total", "element_total",
         "drop_tag", "text_of_min", "alloc_min", "copy_min", "text_of_max", "panic_negative",
         "reject_kind", "alloc_max", "copy_max", "panic_alloc")


class Case:
    __slots__ = ("copy", "enabled", "market", "ident", "t_resolve", "t_check", "price", "size", "head",
                 "t_margin", "kind", "b8", "b9", "count", "total0", "elements", "limit", "reject",
                 "text_len", "alloc", "key")

    def __init__(self, **kw):
        for name in self.__slots__:
            setattr(self, name, kw.get(name, 0))


def read_layout(image, start):
    data = image.data
    out = {}
    for name, rel in LAYOUT_FIELDS:
        out[name] = struct.unpack_from("<I", data, image.file_offset(start + rel))[0]
    return out


def call_sites(image, start):
    """(address, target-or-slot, kind) of every call, in address order."""
    extent = image.fde_of(start)
    rows = []
    for insn in sweep(image, *extent):
        if insn.key == 0xe8:
            rows.append((insn.va, insn.target, "direct"))
        elif insn.key == 0xff and (image.data[insn.modrm] >> 3) & 7 == 2:
            operand = Machine(image, 0, 0).operand(insn)
            if operand[0] == "m" and operand[1] is None and operand[2] is None:
                rows.append((insn.va, operand[4], "slot"))
    return rows


def spec(case, flaw=None):
    """The reconstructed gate. Returns the outcome tuple the evaluator must match."""
    if not case.enabled:
        return ("tag", TAG_NOT_ENABLED)
    if not ID_LOW <= case.ident <= ID_HIGH:
        return ("tag", TAG_BAD_ID, case.ident)
    if case.t_resolve != TAG_OK:
        return ("tag", case.t_resolve)
    if case.t_check != TAG_OK:
        return ("tag", case.t_check)
    product = case.price * case.size
    if flaw == "product_wrap":
        product &= U64
    if product > U64 or product > PRODUCT_CAP:
        return ("tag", TAG_PRODUCT)
    if case.head != HEAD_MARK:
        if not case.market:
            return ("tag", TAG_NO_MARKET)
        if case.t_margin != TAG_OK:
            return ("tag", case.t_margin)
    if case.kind == 4:
        skip = case.b8 != 0
    else:
        skip = case.kind < 3 or case.b9 != 0
    if flaw == "kind3_skips":
        skip = skip or case.kind == 3
    if flaw == "no_skip":
        skip = False
    if not skip:
        total = case.total0
        for i in range(case.count):
            total = min(U64, total + case.elements[i])
        if flaw == "sum_strict":
            reject = total > case.limit
        elif flaw == "sum_wrap":
            reject = (case.total0 + sum(case.elements[:case.count])) & U64 >= case.limit
        else:
            reject = total >= case.limit
        if reject:
            return ("tag", TAG_SUM)
    small = product < MIN_VALUE if flaw != "min_inclusive" else product <= MIN_VALUE
    if small or product > MAX_VALUE or flaw == "max_inclusive" and product == MAX_VALUE:
        tag, payload = (TAG_TOO_SMALL, MIN_PAYLOAD) if small else (TAG_TOO_LARGE, MAX_PAYLOAD)
        if flaw == "swap_payloads":
            payload = MAX_PAYLOAD if tag == TAG_TOO_SMALL else MIN_PAYLOAD
        if case.text_len < 0:
            return ("panic", "negative text length")
        if case.text_len > 0 and case.alloc == 0:
            return ("panic", "allocation failed")
        return ("tag", tag, payload)
    if case.reject == 2 or flaw == "reject_any":
        return ("tag", TAG_OK)
    return ("tag", TAG_REJECT, case.reject)


def fill(machine, at, size, byte=0x5a):
    for i in range(size):
        machine.mem[at + i] = byte


def build_world(image, case, start):
    """Poke one case into a machine and bind a stub to every call site."""
    layout = read_layout(image, start)
    sites = call_sites(image, start)
    if len(sites) != len(ROLES):
        fail(f"{start:#x} has {len(sites)} call sites, not {len(ROLES)}")
    machine = Machine(image, 0, 0)
    start_frame(machine)
    machine.regs[RDI] = const(OUT)
    machine.regs[RSI] = const(ORDER)
    machine.regs[RDX] = const(KEY)
    machine.regs[RCX] = const(STATE)
    fill(machine, OUT, 0x80)
    machine.poke(STATE + layout["enabled"], 1, case.enabled)
    machine.poke(STATE + layout["market"], 1, case.market)
    machine.poke(STATE + 0x780, 8, case.limit)
    machine.poke(STATE + 0x7b8, 1, case.b8)
    machine.poke(STATE + 0x7b9, 1, case.b9)
    machine.poke(STATE + layout["count"], 8, case.count)
    machine.poke(STATE + layout["base"], 8, ELEMENTS)
    machine.poke(ORDER, 8, case.head)
    machine.poke(ORDER + 0x38, 8, 0x1111_2222_3333_4444)
    machine.poke(ORDER + 0x40, 8, 0x5555_6666_7777_8888)
    machine.poke(ORDER + 0x48, 8, case.ident)
    machine.poke(ORDER + 0x50, 1, 1 if case.market == 2 else 0)
    machine.poke(ORDER + 0x51, 1, 1 if case.market == 3 else 0)
    flag50 = machine.mem[ORDER + 0x50]
    flag51 = machine.mem[ORDER + 0x51]
    for i, byte in enumerate(KEY_BYTES):
        machine.mem[KEY + i] = byte
    machine.poke(RECORD + 0x3c, 1, case.kind)
    seen = []

    def expect(name, machine, wanted):
        for reg, value in wanted.items():
            got = machine.regs[reg]
            if got is None or got.v != value & U64:
                fail(f"{name} saw register {reg} = {None if got is None else hex(got.v)}, wanted {value:#x}")

    def key_at(machine, reg):
        at = machine.regs[reg]
        if at is None or bytes(machine.mem.get(at.v + i, 256) for i in range(20)) != KEY_BYTES:
            fail("a stub saw a key copy that differs from the caller key")

    def resolve(m):
        expect("resolve", m, {RSI: 0x5555_6666_7777_8888, RDX: 0x1111_2222_3333_4444, RCX: STATE + 0x90})
        seen.append("resolve")
        buffer = m.regs[RDI].v
        fill(m, buffer, 0x70, 0x5a)
        m.poke(buffer, 2, case.t_resolve)
        m.poke(buffer + 8, 8, case.size)

    def market_check(m):
        expect("market_check", m, {RSI: STATE + 0x80, RDX: KEY, RCX: 0x1111_2222_3333_4444,
                                    8: case.size, 9: flag51})
        stacked = m.load(const(m.regs[RSP].v), 8)
        if stacked is None or stacked.v != STATE:
            fail("market_check did not receive the state on the stack")
        seen.append("market_check")
        buffer = m.regs[RDI].v
        fill(m, buffer, 0x70, 0x5a)
        m.poke(buffer, 2, case.t_check)

    def price_of(m):
        expect("price_of", m, {RDI: STATE + 0x80, RSI: 0x1111_2222_3333_4444, RDX: STATE + layout["lea_addr"]})
        seen.append("price_of")
        return {RAX: const(case.price)}

    def kind_of(m):
        expect("kind_of", m, {RDI: STATE})
        key_at(m, RSI)
        seen.append("kind_of")
        return {RAX: const(RECORD)}

    def margin_check(m):
        expect("margin_check", m, {RSI: ORDER, RDX: 0x1111_2222_3333_4444, RCX: flag50 ^ 1, 8: case.price,
                                    9: STATE + 0x90})
        seen.append("margin_check")
        buffer = m.regs[RDI].v
        fill(m, buffer, 0x70, 0x5a)
        m.poke(buffer, 2, case.t_margin)

    def set_total(m):
        expect("set_total", m, {RDI: STATE + layout["set_obj"]})
        key_at(m, RSI)
        seen.append("set_total")
        return {RAX: const(case.total0)}

    def element_total(m):
        index = sum(1 for name in seen if name == "element_total")
        expect("element_total", m, {RDI: ELEMENTS + 0x188 + 0x200 * index})
        key_at(m, RSI)
        seen.append("element_total")
        return {RAX: const(case.elements[index])}

    def drop_tag(m):
        seen.append("drop_tag")

    by_pc = {va + (6 if kind == "slot" else 5): role for (va, _, kind), role in zip(sites, ROLES)}

    def text_of(m):
        name = by_pc[m.pc]
        expect(name, m, {RDI: STATE + 0x90, RSI: 0x1111_2222_3333_4444})
        seen.append(name)
        return {RAX: const(0x7600_0000), RDX: const(case.text_len)}

    def alloc(m):
        name = by_pc[m.pc]
        expect(name, m, {RDI: case.text_len})
        seen.append(name)
        return {RAX: const(case.alloc)}

    def copy(m):
        name = by_pc[m.pc]
        expect(name, m, {RSI: 0x7600_0000, RDX: case.text_len})
        seen.append(name)

    def panic_site(m):
        reason = "negative text length" if m.regs[RDI].v == 0 else "allocation failed"
        raise Done("panic " + reason, m.pc)

    def reject_kind(m):
        expect("reject_kind", m, {RDI: STATE})
        seen.append("reject_kind")
        return {RAX: const(case.reject)}

    table = {"resolve": resolve, "market_check": market_check, "price_of": price_of, "kind_of": kind_of,
             "margin_check": margin_check, "set_total": set_total, "element_total": element_total,
             "drop_tag": drop_tag, "text_of_min": text_of, "alloc_min": alloc,
             "copy_min": copy, "text_of_max": text_of,
             "panic_negative": panic_site, "reject_kind": reject_kind, "alloc_max": alloc,
             "copy_max": copy, "panic_alloc": panic_site}
    for (address, target, _), role in zip(sites, ROLES):
        machine.stubs[target] = table[role]
    return machine, seen


def outcome_of(machine, case, how):
    if how != "ret":
        return ("panic", how[len("panic "):])
    tag = machine.load(const(OUT), 2).v
    if tag == TAG_BAD_ID:
        return ("tag", tag, machine.load(const(OUT + 8), 8).v)
    if tag in (TAG_TOO_SMALL, TAG_TOO_LARGE):
        return ("tag", tag, machine.load(const(OUT + 8), 8).v)
    if tag == TAG_REJECT:
        return ("tag", tag, machine.load(const(OUT + 2), 1).v)
    return ("tag", tag)


def run_case(image, case, start):
    machine, seen = build_world(image, case, start)
    how = "ret"
    try:
        machine.run(start)
    except Done as done:
        how = done.how
    return outcome_of(machine, case, how), tuple(seen)


# ---------------------------------------------------------------------------
# Deterministic case generation.
# ---------------------------------------------------------------------------
class Lcg:
    def __init__(self, seed):
        self.state = seed & U64

    def next(self):
        self.state = (self.state * 6364136223846793005 + 1442695040888963407) & U64
        return self.state >> 33

    def pick(self, items):
        return items[self.next() % len(items)]


TARGETS = (0, 1, 999_999_999, 9_999_999_999, 10 ** 10, 10 ** 10 + 1, 10 ** 10 + 1023, 2 ** 40,
           MAX_VALUE - 1, MAX_VALUE, MAX_VALUE + 1, 10 ** 15, PRODUCT_CAP - 1, PRODUCT_CAP, PRODUCT_CAP + 1,
           2 ** 63, U64)
PAIRS = ((1, 1), (2 ** 32, 2 ** 32), (2 ** 63, 2), (U64, U64), (0, U64), (U64, 0), (PRODUCT_CAP, 1),
         (PRODUCT_CAP + 1, 1), (0xccccccccccccccc, 2), (0xccccccccccccccd, 2), (3, 0x5555555555555555),
         (3, 0x5555555555555556), (10 ** 5, 10 ** 5), (10 ** 5 + 1, 10 ** 5 - 1), (7, 0))
SIZES = (1, 2, 3, 10, 100, 12345)
IDENTS = (5, 10080, 4, 10081, 0, U64, 6000, 7777, 2 ** 32 + 6000, 10079, 6)
TOTALS = (0, 5, U64 - 3, 2 ** 63, U64)
ELEMENT_VALUES = (0, 1, 7, 2 ** 63, U64, 2 ** 40)


def make_case(rng, copy):
    case = Case(copy=copy)
    case.enabled = rng.pick((1, 1, 1, 1, 1, 0))
    case.market = rng.pick((1, 1, 1, 0, 2, 3))
    case.ident = rng.pick(IDENTS) if rng.next() % 4 == 0 else rng.pick((5, 10080, 6000, 7777))
    case.t_resolve = rng.pick((TAG_OK,) * 6 + (0x77,))
    case.t_check = rng.pick((TAG_OK,) * 6 + (0x99,))
    if rng.next() % 3 == 0:
        case.price, case.size = rng.pick(PAIRS)
    else:
        case.size = rng.pick(SIZES)
        target = rng.pick(TARGETS)
        case.price = target // case.size if rng.next() % 4 else rng.next() % (2 ** 33)
    case.head = rng.pick((HEAD_MARK, HEAD_MARK, 7, 0))
    case.t_margin = rng.pick((TAG_OK,) * 5 + (0x55,))
    case.kind = rng.pick((0, 1, 2, 3, 4, 5, 9, 255))
    case.b8, case.b9 = rng.pick((0, 1)), rng.pick((0, 1))
    case.count = rng.pick((0, 1, 2, 3, 5))
    case.total0 = rng.pick(TOTALS)
    case.elements = tuple(rng.pick(ELEMENT_VALUES) for _ in range(5))
    total = case.total0
    for i in range(case.count):
        total = min(U64, total + case.elements[i])
    mode = rng.next() % 5
    case.limit = (max(0, total - 1), total, min(U64, total + 1), rng.next() * rng.next() & U64, 0)[mode]
    case.reject = rng.pick((2, 2, 0, 1, 3, 255))
    case.text_len = rng.pick((0, 1, 5, -1, -(2 ** 63)))
    case.alloc = rng.pick((0x7700_0000,) * 4 + (0,))
    return case


def cases_for(copy, count):
    rng = Lcg(0x5eed0000 + copy)
    for _ in range(count):
        yield make_case(rng, copy)


def case_detail(case):
    return (f"en={case.enabled} mk={case.market} id={case.ident} tr={case.t_resolve:#x} tc={case.t_check:#x} "
            f"px={case.price} sz={case.size} hd={case.head:#x} tm={case.t_margin:#x} kd={case.kind} "
            f"b8={case.b8} b9={case.b9} n={case.count} t0={case.total0} lim={case.limit} "
            f"rj={case.reject} tl={case.text_len} al={case.alloc:#x}")


def predict_calls(case):
    """The host calls the rule says must happen, in order (panics add no entry)."""
    if not case.enabled or not ID_LOW <= case.ident <= ID_HIGH:
        return []
    calls = ["resolve"]
    if case.t_resolve != TAG_OK:
        return calls
    calls.append("market_check")
    if case.t_check != TAG_OK:
        return calls
    calls.append("price_of")
    product = case.price * case.size
    if product > PRODUCT_CAP:
        return calls
    if case.head != HEAD_MARK:
        if not case.market:
            return calls
        calls.append("margin_check")
        if case.t_margin != TAG_OK:
            return calls
    calls.append("kind_of")
    if case.kind == 4:
        skip = case.b8 != 0
    else:
        skip = case.kind < 3 or case.b9 != 0
    if not skip:
        calls.append("set_total")
        calls.extend(["element_total"] * case.count)
        total = case.total0
        for i in range(case.count):
            total = min(U64, total + case.elements[i])
        if total >= case.limit:
            return calls
    calls.append("drop_tag")
    if product < MIN_VALUE or product > MAX_VALUE:
        suffix = "min" if product < MIN_VALUE else "max"
        calls.append("text_of_" + suffix)
        if case.text_len > 0:
            calls.append("alloc_" + suffix)
            if case.alloc:
                calls.append("copy_" + suffix)
        return calls
    calls.append("reject_kind")
    return calls


# ---------------------------------------------------------------------------
# Running every case, controls and the evidence files.
# ---------------------------------------------------------------------------
CASES_PER_COPY = 4200
CONTROL_CASES = 1200
SAMPLE_EVERY = 5


class Trace:
    """What one copy was seen to do across all its cases."""

    def __init__(self):
        self.executed = set()
        self.edges = set()
        self.state_reads = collections.Counter()
        self.order_reads = collections.Counter()
        self.writes = collections.Counter()


def is_conditional(key):
    return (isinstance(key, int) and 0x70 <= key <= 0x7f) or (isinstance(key, tuple) and 0x80 <= key[1] <= 0x8f)


class Tracer(Machine):
    trace = None

    def step(self):
        here = self.pc
        insn = self.image.fetch(here)
        self.trace.executed.add(here)
        super().step()
        if is_conditional(insn.key):
            self.trace.edges.add((here, self.pc != here + insn.size))

    def load(self, address, size):
        if address is not None and address.a == 0:
            if STATE <= address.v < STATE + 0x10000:
                self.trace.state_reads[(address.v - STATE, size)] += 1
            elif ORDER <= address.v < ORDER + 0x100:
                self.trace.order_reads[(address.v - ORDER, size)] += 1
        return super().load(address, size)

    def store(self, address, size, value):
        if address is not None and address.a == 0:
            at = address.v
            if STATE <= at < STATE + 0x10000 or ORDER <= at < ORDER + 0x100 or KEY <= at < KEY + 0x100:
                self.trace.writes[at] += 1
        super().store(address, size, value)


def run_case_traced(image, case, start, trace):
    machine, seen = build_world(image, case, start)
    machine.__class__ = Tracer
    machine.trace = trace
    how = "ret"
    try:
        machine.run(start)
    except Done as done:
        how = done.how
    return outcome_of(machine, case, how), tuple(seen)


def outcome_text(outcome):
    return " ".join(str(part) if not isinstance(part, int) else hex(part) for part in outcome)


def verify_copies(image, count=CASES_PER_COPY):
    """Run every case on every copy against the spec. Streams, keeps counters only."""
    digest = hashlib.sha256()
    histogram = collections.Counter()
    sequences = collections.Counter()
    samples = []
    traces = {start: Trace() for start in GATES}
    totals = collections.Counter()
    for copy, start in enumerate(GATES):
        for index, case in enumerate(cases_for(copy, count)):
            outcome, seen = run_case_traced(image, case, start, traces[start])
            wanted = spec(case)
            if outcome != wanted:
                fail(f"copy {copy} case {index}: bytes gave {outcome_text(outcome)}, rule says "
                     f"{outcome_text(wanted)} for {case_detail(case)}")
            if list(seen) != predict_calls(case):
                fail(f"copy {copy} case {index}: stub calls {list(seen)} differ from the rule's "
                     f"{predict_calls(case)} for {case_detail(case)}")
            label = outcome_text(outcome[:2]) if outcome[0] == "tag" else outcome_text(outcome)
            digest.update(f"{copy} {index} {outcome_text(outcome)} {' '.join(seen)}\n".encode())
            histogram[(copy, label)] += 1
            sequences[(label, " ".join(seen))] += 1
            totals["cases"] += 1
            if index % SAMPLE_EVERY == 0:
                samples.append([copy, index, case_detail(case), outcome_text(outcome), len(seen)])
    for start, trace in traces.items():
        if trace.writes:
            fail(f"gate {start:#x} wrote into the state, order or key blocks")
    return {"digest": digest.hexdigest(), "histogram": histogram, "samples": samples, "sequences": sequences,
            "traces": traces, "cases": totals["cases"]}


AGREE_CASES = 1500


def agree_copies(image):
    """The same case through all three copies: same outcome and same stub-call sequence."""
    rows = []
    for index, case in enumerate(cases_for(7, AGREE_CASES)):
        results = [run_case(image, case, start) for start in GATES]
        if not results[0] == results[1] == results[2]:
            fail(f"copies disagree on agreement case {index}: {results}")
        if results[0][0] != spec(case):
            fail(f"agreement case {index} differs from the rule")
        if index % 5 == 0:
            rows.append([index, case_detail(case), outcome_text(results[0][0]), " ".join(results[0][1])])
    return rows


def first_mismatch(image, cases, start, flaw=None):
    """Index of the first case where the bytes and the (possibly flawed) rule disagree, else None."""
    for index, case in enumerate(cases):
        try:
            outcome, _ = run_case(image, case, start)
        except (ToolError, Done) as error:
            return index, "refused: " + str(error)[:60]
        except Exception as error:  # an evaluator stop on mutated bytes is a refusal too
            return index, "stopped: " + type(error).__name__
        if outcome != spec(case, flaw):
            return index, "output differs"
    return None


def patch(image, va, new):
    off = image.file_offset(va)
    before = bytes(image.data[off:off + len(new)])
    image.data[off:off + len(new)] = new
    image.cache.clear()
    return before


def mutation_sites(image, start, size=GATE_SIZE):
    """Single-byte edits on the first copy: (kind, address, new byte)."""
    sites = []
    for insn in sweep(image, start, start + size):
        key, va = insn.key, insn.va
        data = image.data
        if isinstance(key, tuple) and 0x80 <= key[1] <= 0x8f:
            sites.append(("branch inverted", va + 1, data[image.file_offset(va + 1)] ^ 1))
        elif isinstance(key, int) and 0x70 <= key <= 0x7f:
            sites.append(("branch inverted", va, data[image.file_offset(va)] ^ 1))
        elif key == 0xc7 and insn.wide16:
            sites.append(("tag constant", va + insn.size - 2, data[image.file_offset(va + insn.size - 2)] ^ 1))
        elif isinstance(key, int) and 0xb8 <= key <= 0xbf and insn.size == 10:
            sites.append(("wide constant", va + 2, data[image.file_offset(va + 2)] ^ 1))
        elif key == 0x81 and (data[insn.modrm] >> 3) & 7 == 7:
            sites.append(("compare constant", va + insn.size - 4, data[image.file_offset(va + insn.size - 4)] ^ 1))
        elif key in (0x80, 0x83) and (data[insn.modrm] >> 3) & 7 == 7 and data[insn.modrm] >> 6 in (1, 2):
            sites.append(("compare constant", va + insn.size - 1, data[image.file_offset(va + insn.size - 1)] ^ 1))
        elif isinstance(key, int) and key in (0x3c,):
            sites.append(("compare constant", va + 1, data[image.file_offset(va + 1)] ^ 1))
        elif key in (0x8b, 0x89, 0x8a, 0x88, 0xc6, 0x80, (0x0f, 0xb6)):
            mod, rm = data[insn.modrm] >> 6, data[insn.modrm] & 7
            if mod == 1 and rm != 4:
                where = insn.modrm + 1
                sites.append(("field offset", va + (where - insn.off), data[where] ^ 8))
    return sites


FLAWS = ("product_wrap", "kind3_skips", "no_skip", "sum_strict", "sum_wrap", "min_inclusive", "max_inclusive",
         "swap_payloads", "reject_any")


def controls(image, start, cases, label=""):
    rows = []
    survivors = []
    for kind, va, byte in mutation_sites(image, start):
        before = patch(image, va, bytes([byte]))
        try:
            hit = first_mismatch(image, cases, start)
        finally:
            patch(image, va, before)
        row = [label + kind, hex(va), before.hex(), bytes([byte]).hex(), "no" if hit is None else "yes",
               "" if hit is None else hit[0], "" if hit is None else hit[1]]
        (survivors if hit is None else rows).append(row)
    for flaw in (FLAWS if not label else ()):
        hit = first_mismatch(image, cases, start, flaw)
        rows.append(["wrong rule", flaw, "", "", "no" if hit is None else "yes", "" if hit is None else hit[0],
                     "" if hit is None else hit[1]])
        if hit is None:
            fail(f"wrong rule {flaw} is not caught")
    return rows, survivors


def damaged_inputs(data):
    """Corrupt inputs the tool must refuse: bad digest, truncated file, wrong address."""
    refused = []
    for name, blob in (("flipped byte", bytes([data[0] ^ 1]) + data[1:]), ("truncated", data[:4096]),
                       ("empty", b"")):
        try:
            check_target(blob)
        except ToolError:
            refused.append([name, "refused"])
        else:
            fail(f"{name} input was accepted")
    image = Image(bytearray(data))
    for name, va in (("address in .bss gap", 0x7fff_ffff), ("address below text", 0x1000)):
        try:
            image.fetch(va)
        except ToolError:
            refused.append([name, "refused"])
        else:
            fail(f"{name} was accepted")
    return refused


def reach_rows(image, traces):
    rows = []
    for copy, start in enumerate(GATES):
        insns = sweep(image, start, start + GATE_SIZE)
        executed = traces[start].executed
        missing = [insn.va - start for insn in insns if insn.va not in executed]
        rows.append([copy, hex(start), len(insns), len(insns) - len(missing),
                     " ".join(hex(x) for x in missing)])
    return rows


def edge_rows(image, traces):
    """Every conditional branch of every copy with the directions seen."""
    rows = []
    for copy, start in enumerate(GATES):
        for insn in sweep(image, start, start + GATE_SIZE):
            if is_conditional(insn.key):
                taken = (insn.va, True) in traces[start].edges
                fell = (insn.va, False) in traces[start].edges
                rows.append([copy + 1, hex(insn.va - start), hex(insn.target - start), int(taken), int(fell)])
    return rows


def field_rows(traces):
    rows = []
    for copy, start in enumerate(GATES):
        for name, counter in (("state", traces[start].state_reads), ("order", traces[start].order_reads)):
            for (offset, size), count in sorted(counter.items()):
                rows.append([copy + 1, name, hex(offset), size, count])
    return rows


def diff_rows(image):
    """How copies 2 and 3 differ from copy 1, instruction by instruction."""
    data = image.data
    base = GATES[0]
    rows = []
    sweeps = [sweep(image, start, start + GATE_SIZE) for start in GATES]
    for copy in (1, 2):
        for first, other in zip(sweeps[0], sweeps[copy]):
            a = bytes(data[first.off:first.off + first.size])
            b = bytes(data[other.off:other.off + other.size])
            if a == b:
                continue
            rel = first.va - base
            if first.size != other.size:
                fail("copies differ in instruction length")
            if first.key == 0xe8:
                kind = "call target"
            elif first.key == 0xff:
                kind = "call slot"
            else:
                names = [name for name, position in LAYOUT_FIELDS if rel <= position < rel + first.size]
                kind = "layout offset " + ",".join(names)
            rows.append([copy + 1, hex(rel), kind, a.hex(), b.hex()])
    return rows


def caller_rows(image):
    data = image.data
    text = bytes(data[image.text_off:image.text_off + image.text_size])
    slots = {}
    addr, off, size = image.sections[".rela.dyn"]
    for pos in range(off, off + size, 24):
        offset, info, addend = struct.unpack_from("<QQq", data, pos)
        if info & 0xffffffff == 8 and addend in GATES:
            slots[offset] = addend
    rows = []
    swept = {}
    for match in re.finditer(rb"\xff\x15|\xe8", text):
        p = match.start()
        va = image.text_va + p
        if text[p] == 0xe8:
            if p + 5 > len(text):
                continue
            target = va + 5 + struct.unpack_from("<i", text, p + 1)[0]
            kind = "direct"
            gate = target if target in GATES else None
        else:
            if p + 6 > len(text):
                continue
            slot = va + 6 + struct.unpack_from("<i", text, p + 2)[0]
            gate = slots.get(slot)
            kind = "slot"
        if gate is None:
            continue
        extent = image.fde_of(va)
        starts = swept.setdefault(extent, {insn.va for insn in sweep(image, *extent)})
        if va in starts:
            rows.append([hex(gate), kind, hex(va), hex(extent[0])])
    return rows, {hex(slot): hex(gate) for slot, gate in sorted(slots.items())}


TABLE = {
    "calls.tsv": ["copy", "index", "role", "call", "kind", "target_or_slot"],
    "layouts.tsv": ["copy", "field", "value"],
    "copy-diff.tsv": ["copy", "offset", "class", "copy1_bytes", "this_bytes"],
    "outcomes.tsv": ["copy", "outcome", "cases"],
    "cases-sample.tsv": ["copy", "index", "inputs", "outcome", "stub_calls"],
    "reach.tsv": ["copy", "function", "instructions", "executed", "unexecuted_offsets"],
    "branch-edges.tsv": ["copy", "branch_offset", "target_offset", "taken_seen", "fallthrough_seen"],
    "fields-read.tsv": ["copy", "block", "offset", "size", "reads"],
    "call-sequences.tsv": ["outcome", "stub_calls", "cases"],
    "copy-agreement.tsv": ["index", "inputs", "outcome", "stub_calls"],
    "mutations.tsv": ["kind", "address", "before", "after", "detected", "first_case", "how"],
    "survivors.tsv": ["kind", "address", "before", "after", "detected", "first_case", "how"],
    "damaged-inputs.tsv": ["input", "result"],
    "callers.tsv": ["gate", "kind", "call", "function"],
}


def tsv(header, rows):
    return "\n".join("\t".join(str(cell) for cell in row) for row in [header] + rows) + "\n"


def analyse(data):
    image = Image(bytearray(data))
    result = {"image": image}
    result["extents"] = {hex(g): [hex(x) for x in image.fde_of(g)] for g in GATES}
    for g in GATES:
        if image.fde_of(g)[1] - g != GATE_SIZE:
            fail(f"gate {g:#x} is not {GATE_SIZE:#x} bytes")
    result["layouts"] = {copy: read_layout(image, g) for copy, g in enumerate(GATES)}
    result["sites"] = {copy: call_sites(image, g) for copy, g in enumerate(GATES)}
    result["verify"] = verify_copies(image)
    result["agree"] = agree_copies(image)
    cases = list(cases_for(0, CONTROL_CASES))
    result["mutations"], result["survivors"] = controls(image, GATES[0], cases)
    for copy in (1, 2):
        rows, skipped = controls(image, GATES[copy], cases[:600], label=f"copy{copy + 1} ")
        result["mutations"].extend(rows)
        result["survivors"].extend(skipped)
    result["damaged"] = damaged_inputs(data)
    result["diff"] = diff_rows(image)
    result["callers"], result["slots"] = caller_rows(image)
    return result


def summarise(result):
    verify = result["verify"]
    mutations, survivors = result["mutations"], result["survivors"]
    detected = sum(1 for row in mutations if row[4] == "yes")
    kinds = collections.Counter(row[0] for row in mutations)
    skipped = collections.Counter(row[0] for row in survivors)
    reach = reach_rows(result["image"], verify["traces"])
    return {
        "target_sha256": SHA256,
        "function_extents": result["extents"],
        "layouts": {str(copy): layout for copy, layout in sorted(result["layouts"].items())},
        "call_sites_per_copy": {str(copy): len(rows) for copy, rows in sorted(result["sites"].items())},
        "cases": verify["cases"] + AGREE_CASES,
        "cases_per_copy": CASES_PER_COPY,
        "case_digest": verify["digest"],
        "control_cases": CONTROL_CASES,
        "mutants_detected": detected,
        "mutants_by_kind": dict(sorted(kinds.items())),
        "mutants_surviving": dict(sorted(skipped.items())),
        "damaged_inputs_refused": len(result["damaged"]),
        "agreement_cases": AGREE_CASES,
        "branch_directions_seen": sum(row[3] + row[4] for row in edge_rows(result["image"], verify["traces"])),
        "branch_directions_total": 2 * len(edge_rows(result["image"], verify["traces"])),
        "writes_to_state_order_key": 0,
        "instructions_executed": {row[1]: [row[3], row[2]] for row in reach},
        "gate_constants": {"min_value": MIN_VALUE, "max_value": MAX_VALUE, "product_cap": PRODUCT_CAP,
                           "min_shift_form": 0x9502f9 << 10, "min_payload": hex(MIN_PAYLOAD),
                           "max_payload": hex(MAX_PAYLOAD)},
        "callers": len(result["callers"]), "reloc_slots": result["slots"],
    }


def generate(data):
    result = analyse(data)
    summary = summarise(result)
    verify = result["verify"]
    sites = []
    for copy, rows in sorted(result["sites"].items()):
        for index, (va, target, kind) in enumerate(rows):
            sites.append([copy + 1, index, ROLES[index], hex(va), kind, hex(target)])
    layouts = [[copy + 1, name, hex(value)] for copy, layout in sorted(result["layouts"].items())
               for name, value in layout.items()]
    outcomes = [[copy + 1, text, count] for (copy, text), count in sorted(verify["histogram"].items())]
    samples = [[row[0] + 1] + row[1:] for row in verify["samples"]]
    mutations = result["mutations"]
    detected = sum(1 for row in mutations if row[4] == "yes")
    controls_total = len(mutations) + len(result["damaged"])
    measure = {"cases": verify["cases"] + AGREE_CASES, "negative_controls": controls_total,
               "negative_detected": detected + len(result["damaged"]),
               "mutants_surviving": len(result["survivors"])}
    return {
        "evidence.json": json.dumps(summary, indent=1, sort_keys=True) + "\n",
        "measure.json": json.dumps(measure, indent=1, sort_keys=True) + "\n",
        "calls.tsv": tsv(TABLE["calls.tsv"], sites),
        "layouts.tsv": tsv(TABLE["layouts.tsv"], layouts),
        "copy-diff.tsv": tsv(TABLE["copy-diff.tsv"], result["diff"]),
        "outcomes.tsv": tsv(TABLE["outcomes.tsv"], outcomes),
        "cases-sample.tsv": tsv(TABLE["cases-sample.tsv"], samples),
        "reach.tsv": tsv(TABLE["reach.tsv"], reach_rows(result["image"], verify["traces"])),
        "branch-edges.tsv": tsv(TABLE["branch-edges.tsv"], edge_rows(result["image"], verify["traces"])),
        "fields-read.tsv": tsv(TABLE["fields-read.tsv"], field_rows(verify["traces"])),
        "call-sequences.tsv": tsv(TABLE["call-sequences.tsv"],
                                  [[o, s, n] for (o, s), n in sorted(verify["sequences"].items())]),
        "copy-agreement.tsv": tsv(TABLE["copy-agreement.tsv"], result["agree"]),
        "mutations.tsv": tsv(TABLE["mutations.tsv"], mutations),
        "survivors.tsv": tsv(TABLE["survivors.tsv"], result["survivors"]),
        "damaged-inputs.tsv": tsv(TABLE["damaged-inputs.tsv"], result["damaged"]),
        "callers.tsv": tsv(TABLE["callers.tsv"], result["callers"]),
    }


def check_target(data):
    digest = hashlib.sha256(data).hexdigest()
    if digest != SHA256:
        fail(f"target hash {digest} is not {SHA256}")


def start_frame(machine):
    sp = machine.regs[RSP].v - 8
    machine.regs[RSP] = const(sp)
    machine.poke(sp, 8, RETURN_MARK)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", required=True)
    parser.add_argument("--binary", default=str(TARGET))
    args = parser.parse_args()
    data = pathlib.Path(args.binary).read_bytes()
    check_target(data)
    files = generate(data)
    out = pathlib.Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    for name, text in files.items():
        (out / name).write_text(text)
    print(f"wrote {len(files)} files to {out}")


if __name__ == "__main__":
    try:
        main()
    except ToolError as error:
        print(f"error: {error}", file=sys.stderr)
        sys.exit(1)
