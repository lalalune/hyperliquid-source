#!/usr/bin/env python3
"""Prove the node #94 wire asset id decoder and encoder from ELF bytes.

A small x86-64 evaluator in this file runs the real instruction bytes. Each run
covers one interval of inputs: values derived from the input are kept as
a*x+c (optionally >>k), and every compare on such a value splits the interval
exactly where its result can change. A run that finishes without a split has one
path and one output form for every input in its interval, so the union of the
intervals is a proof over the whole domain, not a sample. No disassembler is
called and the target is never executed.

Usage: python3 tools/wire_asset_codec.py --out <folder>
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

SHA256 = "3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f"
ROOT = pathlib.Path(__file__).resolve().parents[1]
TARGET = ROOT / "artifacts" / "node" / "94" / "hl-node"

DECODER = 0x3c0cc70
HELPER = 0x3c0c990
ENCODER = 0x3c0cea0
LOOP_ENCODER = 0x3bfd1d0
ARRAY_ENCODER = 0x3bfd7a0
FAMILY = (LOOP_ENCODER, ARRAY_ENCODER, HELPER, DECODER, ENCODER)
SLOT_DECODER = 0x5773950
SLOT_TOKEN_SIDE = 0x57738c8
SLOT_PREDICATE = 0x5773198
SLOT_BOUNDS_PANIC = 0x576dfc8
SLOT_PANIC = 0x576e470
FN_DROP_ERROR = 0x3c1ada0
FN_DROP_DEX_ERROR = 0x3379490
FN_MAP_HASH = 0x399c4a0
LOOP_WINDOW = (0x3bfd274, 0x3bfd2d2)
ARRAY_WINDOW = (0x3bfda0c, 0x3bfda7d)
TAIL_WINDOW = (0x3c0cb87, 0x3c0cbc8)
HELPER_DIVIDE = 0x3c0c9e0

SPOT_BASE = 10000
PERP_OFFSET = 100000
SPOT_LIMIT = 110000
OUTCOME_BASE = 100000000
PERP_CAP = 99899999
DEX_STRIDE = 0x2f0
DEX_SIZE = 10000
SENTINEL = 0xffffffff
TAG_OK = 0x186
TAG_PERP_ERROR = 0x60
TAG_SPOT_ERROR = 0x17f
TAG_DROPPED = 0x141
MAX_Q = (SENTINEL - OUTCOME_BASE) // 10
U64 = (1 << 64) - 1
U32 = (1 << 32) - 1
# A vector of 32-byte entries cannot hold more than this many.
TOKEN_LIMIT = 1 << 58
LITERALS = (SPOT_LIMIT, -SPOT_LIMIT, -PERP_OFFSET, -PERP_OFFSET - 1, 0x7fff3ca, 0x7fff3cb)
MAX_STEPS = 4000
MAX_PIECES = 200000

OUT = 0x7000_0000
META = 0x7100_0000
DEXES = 0x7200_0000
DEX_TABLE = 0x7300_0000
TOKEN_TABLE = 0x7f00_0000
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
            end = data.index(b"\0", strings + row[0])
            self.sections[data[strings + row[0]:end].decode()] = (row[3], row[4], row[5])
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


def refine(run_one, first, last, seeds=()):
    """Run on [first,last], cutting until every piece runs without a split."""
    cuts = sorted(set(s for s in seeds if first < s <= last))
    pending = []
    edges = [first] + cuts + [last + 1]
    for i in range(len(edges) - 2, -1, -1):
        pending.append((edges[i], edges[i + 1] - 1))
    pieces = []
    rounds = 0
    while pending:
        rounds += 1
        if rounds > MAX_PIECES:
            fail("too many interval pieces")
        lo, hi = pending.pop()
        try:
            outcome = run_one(lo, hi)
        except Split as split:
            if not lo < split.at <= hi:
                fail(f"split at {split.at} is outside [{lo},{hi}]")
            pending.append((split.at, hi))
            pending.append((lo, split.at - 1))
            continue
        pieces.append((lo, hi, outcome))
    return pieces


def merge(pieces):
    """Join neighbours with one output form. Keeps the piece count per row."""
    rows = []
    for lo, hi, outcome in pieces:
        if rows and rows[-1][2] == outcome and rows[-1][1] + 1 == lo:
            rows[-1][1] = hi
            rows[-1][3] += 1
        else:
            rows.append([lo, hi, outcome, 1])
    return rows


def form_of(value, lo, hi):
    """(a, c) of a final output. A constant has a == 0."""
    if value is None:
        fail("output is unknown")
    if value.k:
        fail("output is a shifted form")
    return (value.a, value.c)


def form_text(form):
    a, c = form
    if a == 0:
        return f"{c:#x}"
    signed = c - (1 << 64) if c >> 63 else c
    head = "x" if a == 1 else f"{a}*x"
    return head if signed == 0 else f"{head}{signed:+d}"


def outcome_text(outcome):
    kind = outcome[0]
    if kind == "ok":
        return f"ok asset_kind={outcome[1]} value={form_text(outcome[2])}"
    if kind == "error":
        tail = "" if outcome[2] is None else f" value={form_text(outcome[2])}"
        return f"tag {outcome[1]:#x}{tail}"
    if kind == "value":
        return form_text(outcome[1])
    return kind


class World:
    """Host state seen by the decoder and encoder."""

    def __init__(self, lens, token_count, spot_ok=True, table_id=None, side=2, q=0):
        self.lens, self.token_count = lens, token_count
        self.spot_ok, self.table_id, self.side, self.q = spot_ok, table_id, side, q

    def install(self, machine):
        machine.poke(META + 0x170, 8, self.token_count)
        machine.poke(META + 0x168, 8, TOKEN_TABLE)
        machine.poke(DEXES + 0x10, 8, len(self.lens))
        machine.poke(DEXES + 8, 8, DEX_TABLE)
        lens = self.lens

        def dex_field(offset):
            if offset % DEX_STRIDE != 0x10:
                fail(f"dex table read at offset {offset:#x}")
            return lens[offset // DEX_STRIDE]

        def token_field(offset):
            if offset % 32:
                fail(f"token table read at offset {offset:#x}")
            return 0x77

        machine.regions.append((DEX_TABLE, DEX_TABLE + DEX_STRIDE * len(lens), dex_field))
        machine.regions.append((TOKEN_TABLE, TOKEN_TABLE + 32 * self.token_count, token_field))
        machine.stubs[FN_DROP_ERROR] = lambda m: None
        machine.stubs[FN_DROP_DEX_ERROR] = lambda m: None
        machine.stubs[HELPER] = self.helper
        machine.stubs[SLOT_TOKEN_SIDE] = self.token_side
        machine.stubs[SLOT_BOUNDS_PANIC] = lambda m: panic("bounds", m)

    def helper(self, machine):
        wanted = machine.regs[RDI]
        machine.cross(wanted, [OUTCOME_BASE, self.token_count])
        if wanted.v >= OUTCOME_BASE:
            if self.table_id is None:
                return {RAX: const(0), RDX: wanted}
            return {RAX: const(1), RDX: const(self.table_id)}
        return {RAX: const(int(self.spot_ok and wanted.v < self.token_count)), RDX: wanted}

    def token_side(self, machine):
        out = machine.regs[RDI]
        q = self.q if isinstance(self.q, V) else const(self.q)
        machine.store(out, 8, q)
        machine.store(const(out.v + 8), 1, const(self.side))


def panic(name, machine):
    raise Done("panic " + name, machine.pc)


def start_frame(machine):
    sp = machine.regs[RSP].v - 8
    machine.regs[RSP] = const(sp)
    machine.poke(sp, 8, RETURN_MARK)


def decode_id(image, world, lo, hi):
    machine = Machine(image, lo, hi)
    world.install(machine)
    start_frame(machine)
    machine.regs[RDI] = const(OUT)
    machine.regs[RSI] = machine.input()
    machine.regs[RDX] = const(DEXES)
    machine.regs[RCX] = const(META)
    try:
        machine.run(DECODER)
    except Done as done:
        if done.how != "ret":
            return (done.how, )
    tag = machine.load(const(OUT), 2)
    if tag is None:
        fail(f"no tag written for [{lo},{hi}]")
    if tag.v == TAG_OK:
        return ("ok", machine.load(const(OUT + 8), 8).v, form_of(machine.load(const(OUT + 16), 8), lo, hi))
    if tag.v == TAG_PERP_ERROR:
        return ("error", tag.v, form_of(machine.load(const(OUT + 8), 8), lo, hi))
    return ("error", tag.v, None)


def encode_id(image, world, flag, lo, hi, q_input=False, index=3):
    machine = Machine(image, lo, hi)
    world.install(machine)
    start_frame(machine)
    machine.regs[RDI] = const(flag)
    machine.regs[RSI] = const(index) if q_input else machine.input()
    machine.regs[RDX] = const(META)
    if q_input:
        world.q = machine.input()
    try:
        machine.run(ENCODER)
    except Done as done:
        if done.how != "ret":
            return (done.how, )
    return ("value", form_of(machine.get(RAX, 32), lo, hi))


def window(image, span, reg, result_reg, lo, hi):
    machine = Machine(image, lo, hi)
    machine.regs[reg] = machine.input()
    machine.stop_at = {span[1]}
    try:
        machine.run(span[0])
    except Done as done:
        if done.how != "stop":
            fail(f"window {span[0]:#x} ended with {done.how}")
    return ("value", form_of(machine.get(result_reg, 32), lo, hi))


def want_decode(x, lens, token_count=100000, spot_ok=True):
    if x < SPOT_BASE:
        if lens and x < lens[0]:
            return ("ok", 0, (1, 0))
        return ("error", TAG_PERP_ERROR, (1, 0))
    if x < SPOT_LIMIT:
        if spot_ok and x - SPOT_BASE < token_count:
            return ("ok", 1, (1, -SPOT_BASE & U64))
        return ("error", TAG_SPOT_ERROR, None)
    if x < OUTCOME_BASE:
        packed = x - PERP_OFFSET
        dex, local = packed // DEX_SIZE, packed % DEX_SIZE
        if dex < len(lens) and local < lens[dex]:
            return ("ok", 0, (1, -PERP_OFFSET & U64))
        return ("error", TAG_PERP_ERROR, (1, -PERP_OFFSET & U64))
    return ("error", TAG_SPOT_ERROR, None)


def want_perp(x):
    if x < SPOT_BASE:
        return ("value", (1, 0))
    if x <= PERP_CAP:
        return ("value", (1, PERP_OFFSET))
    return ("value", (0, SENTINEL))


def want_spot(x):
    if x >= TOKEN_LIMIT:
        return ("panic bounds", )
    if x < PERP_OFFSET:
        return ("value", (1, SPOT_BASE))
    if OUTCOME_BASE <= x <= U32:
        return ("value", (1, 0))
    return ("value", (0, SENTINEL))


def want_outcome(side):
    def rule(x):
        if x <= MAX_Q:
            return ("value", (10, OUTCOME_BASE + side))
        return ("value", (0, SENTINEL))
    return rule


def check_rows(name, rows, rule):
    for lo, hi, outcome, _ in rows:
        for x in (lo, hi):
            if rule(x) != outcome:
                fail(f"{name}: [{lo},{hi}] gave {outcome_text(outcome)}, rule at {x} says {rule(x)}")


FULL_LENS = [DEX_SIZE] * 9990
PARTIAL_LENS = [7, 0, 3]
CUTS_32 = (1 << 32,)


def decoder_tables(image, full=True):
    tables = {}

    def table(name, world, rule):
        rows = merge(refine(lambda lo, hi: decode_id(image, world, lo, hi), 0, U32))
        check_rows(name, rows, rule)
        tables[name] = rows

    if full:
        table("decoder full-registry side-2", World(FULL_LENS, 100000), lambda x: want_decode(x, FULL_LENS))
    table("decoder partial-registry", World(PARTIAL_LENS, 100000), lambda x: want_decode(x, PARTIAL_LENS))
    table("decoder empty-registry", World([], 100000), lambda x: want_decode(x, []))
    table("decoder spot-lookup-miss", World(PARTIAL_LENS, 100000, spot_ok=False),
          lambda x: want_decode(x, PARTIAL_LENS, spot_ok=False))
    table("decoder table-hit side-2", World(PARTIAL_LENS, 100000, table_id=5), lambda x: want_decode(x, PARTIAL_LENS))
    table("decoder short-token-table", World(PARTIAL_LENS, 3, table_id=5),
          lambda x: ("panic bounds", ) if x >= OUTCOME_BASE else want_decode(x, PARTIAL_LENS, token_count=3))
    for side, q in ((0, 12), (1, 12), (0, MAX_Q), (1, MAX_Q)):
        match = OUTCOME_BASE + 10 * q + side
        table(f"decoder outcome q={q} side={side}", World(PARTIAL_LENS, 100000, table_id=5, side=side, q=q),
              lambda x, m=match: want_decode_outcome(x, m))
    return tables


def want_decode_outcome(x, match):
    """With side<2 and a fixed table id, only the matching id can be ok."""
    if SPOT_BASE <= x < SPOT_LIMIT:
        return ("error", TAG_SPOT_ERROR, None)
    if x < OUTCOME_BASE:
        return want_decode(x, PARTIAL_LENS)
    return ("ok", 1, (0, 5)) if x == match else ("error", TAG_SPOT_ERROR, None)


def encoder_tables(image):
    world = World([], TOKEN_LIMIT)
    tables = {}
    rows = merge(refine(lambda lo, hi: encode_id(image, world, 0, lo, hi), 0, U64, CUTS_32))
    check_rows("encoder perp", rows, want_perp)
    tables["encoder perp"] = rows
    for side in (2, 3):
        name = f"encoder token side={side}"
        spot_world = World([], TOKEN_LIMIT, side=side)
        rows = merge(refine(lambda lo, hi: encode_id(image, spot_world, 1, lo, hi), 0, U64, CUTS_32))
        check_rows(name, rows, want_spot)
        tables[name] = rows
    for side in (0, 1):
        name = f"encoder outcome side={side}"
        side_world = World([], TOKEN_LIMIT, side=side)
        rows = merge(refine(lambda lo, hi: encode_id(image, side_world, 1, lo, hi, q_input=True), 0, U64, CUTS_32))
        check_rows(name, rows, want_outcome(side))
        tables[name] = rows
    return tables


def inline_tables(image):
    tables = {}
    for name, span, reg, result in (("inline loop copy", LOOP_WINDOW, RAX, RDX),
                                    ("inline array copy", ARRAY_WINDOW, RBX, R13)):
        seeds = (1 << 32, (1 << 32) - PERP_OFFSET)
        rows = merge(refine(lambda lo, hi: window(image, span, reg, result, lo, hi), 0, U64, seeds))
        check_rows(name, rows, want_perp)
        tables[name] = rows
    return tables


def find_row(rows, x):
    for row in rows:
        if row[0] <= x <= row[1]:
            return row
    fail(f"{x} is in no row")


def compose(outer, a, c):
    """(a2, c2) of outer(a*x+c)."""
    return (outer[0] * a, (outer[0] * c + outer[1]) & U64)


def round_trips(tables):
    """Join the decoder and encoder rows and show each ok id comes back."""
    decoded = tables["decoder full-registry side-2"]
    perp, spot = tables["encoder perp"], tables["encoder token side=2"]
    forward = 0
    covered = 0
    for lo, hi, outcome, _ in decoded:
        if outcome[0] != "ok":
            continue
        a, c = outcome[2]
        rows = perp if outcome[1] == 0 else spot
        first, last = (a * lo + c) & U64, (a * hi + c) & U64
        row = find_row(rows, first)
        if not row[0] <= last <= row[1]:
            fail(f"decoder row at {lo} spans two encoder rows")
        if compose(row[2][1], a, c) != (1, 0):
            fail(f"decoder row at {lo} does not return to x")
        forward += 1
        covered += hi - lo + 1
    backward = 0
    for name, rows, kind in (("perp", perp, 0), ("token", spot, 1)):
        for lo, hi, outcome, _ in rows:
            if outcome[0] != "value" or outcome[1][0] == 0:
                continue
            a, c = outcome[1]
            first, last = a * lo + c, a * hi + c
            if first >= OUTCOME_BASE:
                continue
            row = find_row(decoded, first)
            if not row[0] <= last <= row[1] or row[2][0] != "ok" or row[2][1] != kind:
                fail(f"encoder {name} row at {lo} does not decode as ok")
            if compose(row[2][2], a, c) != (1, 0):
                fail(f"encoder {name} row at {lo} does not return to x")
            backward += 1
    return {"forward_rows": forward, "ids_proved_ok_and_returning": covered, "backward_rows": backward}


def reciprocal(image):
    """The /10 inside the helper, for every 64-bit value."""
    data = image.data
    off = image.file_offset(HELPER_DIVIDE)
    want = bytes.fromhex("4881c3001f0afa" "48b9cdcccccccccccccc")
    if bytes(data[off:off + len(want)]) != want:
        fail("helper divide bytes changed")
    tail = bytes(data[off + len(want):off + len(want) + 13])
    if tail != bytes.fromhex("4889d848f7e14989d649c1ee03"):
        fail("helper divide tail changed")
    m = struct.unpack_from("<Q", data, off + 9)[0]
    n = 64 + 3
    excess = m * 10 - (1 << n)
    if excess <= 0 or excess * U64 >= 1 << n:
        fail("reciprocal bound fails")
    return {"multiplier": hex(m), "shift": n, "excess": excess}


def run_helper(image, x, token_count, predicate, map_count):
    machine = Machine(image, x, x)
    start_frame(machine)
    machine.regs[RDI] = const(x)
    machine.regs[RSI] = const(META)
    machine.poke(META + 0x170, 8, token_count)
    machine.poke(META + 0x168, 8, TOKEN_TABLE)
    machine.poke(META + 0xe8, 8, map_count)
    machine.regions.append((TOKEN_TABLE, TOKEN_TABLE + 32 * token_count, lambda offset: 0x77))
    machine.stubs[SLOT_PREDICATE] = lambda m: {RAX: const(predicate)}
    machine.stubs[FN_DROP_ERROR] = lambda m: None

    def probe(m):
        raise Done("probe", m.pc)

    machine.stubs[FN_MAP_HASH] = probe
    try:
        machine.run(HELPER)
    except Done as done:
        if done.how == "probe":
            q = machine.regs[R14]
            side = machine.regs[RBX]
            return ("probe", q.v, side.v)
        if done.how != "ret":
            return (done.how, )
    if machine.get(RAX, 8).v & 1:
        return ("some", machine.regs[RDX].v)
    return ("none", )


def want_helper(x, token_count, predicate, map_count):
    if x < OUTCOME_BASE:
        if x >= token_count or predicate:
            return ("none", )
        return ("some", x)
    q, r = divmod(x - OUTCOME_BASE, 10)
    if r > 1 or map_count == 0:
        return ("none", )
    return ("probe", q, 0 if r == 0 else 0x28)


def helper_vectors(image):
    rows = []
    points = [0, 1, 6, 7, 8, OUTCOME_BASE - 1]
    for y in (0, 1, 2, 3, 9, 10, 11, 12, 19, 20, 21, SENTINEL - OUTCOME_BASE - 5, SENTINEL - OUTCOME_BASE - 4,
              SENTINEL - OUTCOME_BASE, 10 * MAX_Q, 10 * MAX_Q + 1, U64 - OUTCOME_BASE):
        points.append(y + OUTCOME_BASE)
    for x in points:
        for predicate in (0, 1):
            for map_count in (0, 1):
                got = run_helper(image, x, 7, predicate, map_count)
                if got != want_helper(x, 7, predicate, map_count):
                    fail(f"helper at {x}: {got}")
                rows.append([x, predicate, map_count, " ".join(str(part) for part in got)])
    return rows


def run_tail(image, side, count, index, limit):
    machine = Machine(image, 0, 0)
    entry = 0x7500_0000
    table = 0x7600_0000
    list_ptr = 0x7700_0000
    machine.regs[R13] = const(entry)
    machine.regs[RDI] = const(0)
    machine.regs[RBX] = const(side)
    machine.regs[RDX] = const(META)
    machine.poke(entry + side - 0x68, 8, index)
    machine.poke(META + 0x188, 8, limit)
    machine.poke(META + 0x180, 8, table)
    machine.poke(table + 0xe8 * index + 0x60, 8, count)
    machine.poke(table + 0xe8 * index + 0x58, 8, list_ptr)
    machine.poke(list_ptr, 8, 0x1234)
    machine.stop_at = {TAIL_WINDOW[1]}
    machine.stubs[SLOT_PANIC] = lambda m: panic("bounds", m)
    try:
        machine.run(TAIL_WINDOW[0])
    except Done as done:
        if done.how != "stop":
            return (done.how, )
    return ("ok", machine.get(RAX, 8).v, machine.regs[RBX].v)


def tail_vectors(image):
    rows = []
    for side in (0, 0x28):
        for count in (0, 1, 2):
            for index, limit in ((0, 1), (2, 3), (3, 3)):
                got = run_tail(image, side, count, index, limit)
                if index >= limit:
                    want = ("panic bounds", )
                elif count == 1:
                    want = ("ok", 1, 0x1234)
                else:
                    want = ("ok", 0, side)
                if got != want:
                    fail(f"tail side={side} count={count}: {got}")
                rows.append([side, count, index, limit, " ".join(str(part) for part in got)])
    return rows


def literal_census(image):
    """Every occurrence of the family literals in .text, with its role."""
    data = image.data
    text = bytes(data[image.text_off:image.text_off + image.text_size])
    rows = []
    swept = {}
    for literal in LITERALS:
        needle = struct.pack("<i", literal)
        for match in re.finditer(re.escape(needle), text):
            va = image.text_va + match.start()
            extent = image.fde_of(va)
            insns = swept.setdefault(extent, sweep(image, *extent))
            index = bisect.bisect_right([insn.va for insn in insns], va) - 1
            insn = insns[index]
            if va + 4 > insn.va + insn.size:
                role = "straddles instructions"
            elif insn.key in (0xe8, 0xe9) or (isinstance(insn.key, tuple) and 0x80 <= insn.key[1] <= 0x8f):
                role = "branch displacement"
            elif insn.modrm is not None and data[insn.modrm] & 0xc7 == 5:
                role = "rip displacement"
            elif va + 4 == insn.va + insn.size and (insn.key != 0x8d):
                role = "immediate"
            else:
                role = "displacement"
            rows.append([hex(literal & U32), hex(va), hex(extent[0]), role])
    rows.sort(key=lambda row: (int(row[1], 16), row[0]))
    for row in rows:
        if row[3] in ("immediate", "displacement") and int(row[2], 16) not in FAMILY:
            fail(f"literal {row[0]} at {row[1]} is used outside the family")
    return rows


def caller_rows(image):
    data = image.data
    text = bytes(data[image.text_off:image.text_off + image.text_size])
    rows = []
    swept = {}
    for match in re.finditer(rb"\xff\x15|\xe8", text):
        p = match.start()
        va = image.text_va + p
        if text[p] == 0xe8:
            if p + 5 > len(text):
                continue
            target = va + 5 + struct.unpack_from("<i", text, p + 1)[0]
            if target != ENCODER:
                continue
            kind = "direct encoder"
        else:
            if p + 6 > len(text):
                continue
            slot = va + 6 + struct.unpack_from("<i", text, p + 2)[0]
            if slot != SLOT_DECODER:
                continue
            kind = "slot decoder"
        extent = image.fde_of(va)
        starts = swept.setdefault(extent, {insn.va for insn in sweep(image, *extent)})
        if va in starts:
            rows.append([kind, hex(va), hex(extent[0])])
    return rows


def slot_target(image, slot):
    addr, off, size = image.sections[".rela.dyn"]
    wanted = struct.pack("<Q", slot)
    data = image.data
    for pos in range(off, off + size, 24):
        if data[pos:pos + 8] == wanted:
            return struct.unpack_from("<q", data, pos + 16)[0]
    fail(f"no relocation for slot {slot:#x}")


TABLE_HEADER = ["table", "first", "last", "result", "pieces"]


def tsv(header, rows):
    return "\n".join("\t".join(str(cell) for cell in row) for row in [header] + rows) + "\n"


def table_rows(tables):
    rows = []
    for name in sorted(tables):
        for lo, hi, outcome, pieces in tables[name]:
            rows.append([name, lo, hi, outcome_text(outcome), pieces])
    return rows


def analyse(data, parts=("decoder", "encoder", "inline", "helper", "tail", "census")):
    image = Image(data)
    extents = {hex(fn): [hex(x) for x in image.fde_of(fn)] for fn in FAMILY}
    result = {"image": image, "extents": extents, "tables": {}}
    if "decoder" in parts:
        result["tables"].update(decoder_tables(image))
    if "decoder-small" in parts:
        result["tables"].update(decoder_tables(image, full=False))
    if "encoder" in parts:
        result["tables"].update(encoder_tables(image))
    if "inline" in parts:
        result["tables"].update(inline_tables(image))
    if "helper" in parts:
        result["reciprocal"] = reciprocal(image)
        result["helper"] = helper_vectors(image)
    if "tail" in parts:
        result["tail"] = tail_vectors(image)
    if "census" in parts:
        result["literals"] = literal_census(image)
        result["callers"] = caller_rows(image)
    return result


def outcome_checks(tables):
    """Direct-pair checks on the outcome ids, from proved rows."""
    rows = []
    for side in (0, 1):
        encoded = tables[f"encoder outcome side={side}"]
        for q in (12, MAX_Q):
            row = find_row(encoded, q)
            a, c = row[2][1]
            value = a * q + c
            decoded = tables[f"decoder outcome q={q} side={side}"]
            hit = find_row(decoded, value)
            if hit[0] != value or hit[1] != value or hit[2][0] != "ok":
                fail(f"outcome id {value} is not ok alone")
            rows.append({"q": q, "side": side, "id": value})
    return rows


def summarise(result):
    tables = result["tables"]
    literal_roles = collections.Counter(row[3] for row in result["literals"])
    callers = collections.Counter(row[0] for row in result["callers"])
    last_id = OUTCOME_BASE + 10 * MAX_Q + 1
    dropped = [row for rows in tables.values() for row in rows if "tag 0x141" in outcome_text(row[2])]
    if dropped:
        fail("a decoder path returned the temporary tag")
    return {
        "target_sha256": SHA256,
        "function_extents": result["extents"],
        "slots": {hex(slot): hex(slot_target(result["image"], slot))
                  for slot in (SLOT_DECODER, SLOT_TOKEN_SIDE, SLOT_PREDICATE)},
        "constants": {"spot_base": SPOT_BASE, "spot_limit": SPOT_LIMIT, "perp_offset": PERP_OFFSET,
                      "outcome_base": OUTCOME_BASE, "perp_cap": PERP_CAP, "sentinel": hex(SENTINEL),
                      "ok_tag": hex(TAG_OK), "perp_error_tag": hex(TAG_PERP_ERROR),
                      "spot_error_tag": hex(TAG_SPOT_ERROR), "temporary_tag_not_returned": hex(TAG_DROPPED)},
        "proved_tables": {name: len(rows) for name, rows in sorted(tables.items())},
        "pieces_total": sum(row[3] for rows in tables.values() for row in rows),
        "round_trip": round_trips(tables),
        "outcome_pairs": outcome_checks(tables),
        "largest_outcome_id": last_id,
        "sentinel_remainder_mod_10": (SENTINEL - OUTCOME_BASE) % 10,
        "reciprocal": result["reciprocal"],
        "helper_vectors": len(result["helper"]),
        "tail_vectors": len(result["tail"]),
        "literal_roles": dict(sorted(literal_roles.items())),
        "callers": dict(sorted(callers.items())),
        "caller_functions": len({row[2] for row in result["callers"]}),
    }


def generate(data):
    result = analyse(data)
    summary = summarise(result)
    return {
        "evidence.json": json.dumps(summary, indent=1, sort_keys=True) + "\n",
        "intervals.tsv": tsv(TABLE_HEADER, table_rows(result["tables"])),
        "helper-vectors.tsv": tsv(["x", "predicate", "map_count", "result"], result["helper"]),
        "tail-vectors.tsv": tsv(["side_offset", "list_len", "index", "limit", "result"], result["tail"]),
        "literals.tsv": tsv(["literal", "address", "function", "role"], result["literals"]),
        "callers.tsv": tsv(["kind", "call", "function"], result["callers"]),
    }


def check_target(data):
    digest = hashlib.sha256(data).hexdigest()
    if digest != SHA256:
        fail(f"target hash {digest} is not {SHA256}")


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
