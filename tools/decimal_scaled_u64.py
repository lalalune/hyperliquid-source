"""Shared ELF/instruction helpers retained for the node #115 validators.

Extracted from the historical research module; no retired-target entry point.
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






U64 = (1 << 64) - 1


MAX_STEPS = 400000


INPUT = 0x7100_0000


STACK = 0x6f00_0000


RETURN_MARK = 0x6000_0000


RAX, RCX, RDX, RBX, RSP, RBP, RSI, RDI = range(8)


R8, R9, R10, R11, R12, R13, R14, R15 = range(8, 16)


CALLER_SAVED = (RAX, RCX, RDX, RSI, RDI, R8, R9, R10, R11)


class ToolError(Exception):
    pass


def fail(message):
    raise ToolError(message)


class Done(Exception):
    def __init__(self, how, where):
        super().__init__(how)
        self.how, self.where = how, where


class Image:
    """Section map, FDE extents and relocated slots of one ELF image."""

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
            try:
                name = data[strings + row[0]:end].decode()
            except UnicodeDecodeError:
                fail("section name is not valid UTF-8")
            if name in self.sections:
                fail(f"duplicate section name {name}")
            self.sections[name] = (row[3], row[4], row[5])
        self.text_va, self.text_off, self.text_size = self.sections[".text"]
        self.rodata = self.sections[".rodata"]
        self.fdes = self._fdes()
        self.starts = [row[0] for row in self.fdes]
        self.slots = self._slots()
        self.note_target = None
        self.panic_targets = set()
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

    def _slots(self):
        _, off, size = self.sections[".rela.dyn"]
        slots = {}
        for addr, info, add in struct.iter_unpack("<QQq", self.data[off:off + size]):
            if info & 0xffffffff == 8:
                slots[addr] = add
        return slots

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

    def read_only(self, va):
        addr, off, size = self.rodata
        if addr <= va < addr + size:
            return self.data[va - addr + off]
        return None


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

    __slots__ = ("va", "off", "size", "key", "rex", "modrm", "target", "wide16", "rep")

    def __init__(self, va, off, size, key, rex, modrm, target, wide16, rep):
        self.va, self.off, self.size, self.key = va, off, size, key
        self.rex, self.modrm, self.target, self.wide16, self.rep = rex, modrm, target, wide16, rep


def decode(data, off, va):
    """Decode the length of one 64-bit instruction, or raise on an unknown form."""
    p = off
    wide16 = False
    rep = 0
    while data[p] in PREFIXES:
        wide16 = wide16 or data[p] == 0x66
        if data[p] in (0xf2, 0xf3):
            rep = data[p]
        p += 1
    rex = 0
    if 0x40 <= data[p] <= 0x4f:
        rex = data[p]
        p += 1
    op = data[p]
    p += 1
    iz = 2 if wide16 else 4

    def done(end, key, modrm=None, rel=None):
        size = end - off
        target = None if rel is None else va + size + rel
        return Insn(va, off, size, key, rex, modrm, target, wide16, rep)

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


COND = {0: lambda f: f[3], 1: lambda f: not f[3], 2: lambda f: f[0], 3: lambda f: not f[0],
        4: lambda f: f[1], 5: lambda f: not f[1], 6: lambda f: f[0] or f[1], 7: lambda f: not (f[0] or f[1]),
        8: lambda f: f[2], 9: lambda f: not f[2], 12: lambda f: f[2] != f[3], 13: lambda f: f[2] == f[3],
        14: lambda f: f[1] or f[2] != f[3], 15: lambda f: not f[1] and f[2] == f[3]}


USES = {0: (3,), 1: (3,), 2: (0,), 3: (0,), 4: (1,), 5: (1,), 6: (0, 1), 7: (0, 1), 8: (2,), 9: (2,),
        12: (2, 3), 13: (2, 3), 14: (1, 2, 3), 15: (1, 2, 3)}


class Machine:
    """Concrete evaluator. Registers carry a known-bit mask; anything unknown stays unknown."""

    def __init__(self, image):
        self.image = image
        self.regs = [0] * 16
        self.known = [0] * 16
        self.mem = {}
        self.xmm = [None] * 16
        self.flags = [None, None, None, None]
        self.pc = 0
        self.notes = 0
        self.seen = set()
        self.steps = 0

    def set_reg(self, reg, value):
        self.regs[reg] = value & U64
        self.known[reg] = U64

    def get(self, reg, bits, rex=1):
        if bits == 8 and not rex and 4 <= reg <= 7:
            reg -= 4
            if self.known[reg] & 0xff00 != 0xff00:
                return None
            return (self.regs[reg] >> 8) & 0xff
        mask = (1 << bits) - 1
        if self.known[reg] & mask != mask:
            return None
        return self.regs[reg] & mask

    def put(self, reg, bits, value, rex=1):
        """Write a value, or unknown when value is None."""
        if bits == 8 and not rex and 4 <= reg <= 7:
            reg -= 4
            mask = 0xff00
            self.known[reg] &= ~mask & U64
            if value is not None:
                self.regs[reg] = (self.regs[reg] & ~mask) | ((value & 0xff) << 8)
                self.known[reg] |= mask
            return
        if bits >= 32:
            full = U64 if bits == 64 else 0xffffffff
            self.known[reg] = 0
            if value is not None:
                self.regs[reg] = value & full
                self.known[reg] = U64
            return
        mask = (1 << bits) - 1
        self.known[reg] &= ~mask & U64
        if value is not None:
            self.regs[reg] = (self.regs[reg] & ~mask) | (value & mask)
            self.known[reg] |= mask

    def move_reg(self, dest, src, bits):
        """A full-width move keeps partly known registers partly known."""
        mask = U64 if bits == 64 else 0xffffffff
        self.regs[dest] = self.regs[src] & mask
        self.known[dest] = self.known[src] & mask
        if bits == 32:
            self.known[dest] |= U64 ^ 0xffffffff

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
        total = disp
        for reg, factor in ((base, 1), (index, scale)):
            if reg is None:
                continue
            value = self.get(reg, 64)
            if value is None:
                fail(f"address uses an unknown register at {self.pc:#x}")
            total += value * factor
        return total & U64

    def load(self, at, size):
        out = 0
        for i in range(size):
            byte = self.mem.get(at + i)
            if byte is None:
                byte = self.image.read_only(at + i)
            if byte is None:
                return None
            out |= byte << (8 * i)
        return out

    def store(self, at, size, value):
        if value is None:
            for i in range(size):
                self.mem.pop(at + i, None)
            return
        for i in range(size):
            self.mem[at + i] = (value >> (8 * i)) & 0xff

    def spill(self, at, reg, size):
        """Store a register byte by byte, so partly known registers stay partly known."""
        for i in range(size):
            if (self.known[reg] >> (8 * i)) & 0xff == 0xff:
                self.mem[at + i] = (self.regs[reg] >> (8 * i)) & 0xff
            else:
                self.mem.pop(at + i, None)

    def reload(self, reg, at, size):
        """Load a register byte by byte. A 32-bit load clears the top half."""
        value, known = 0, U64 << (8 * size) & U64
        for i in range(size):
            byte = self.mem.get(at + i)
            if byte is None:
                byte = self.image.read_only(at + i)
            if byte is not None:
                value |= byte << (8 * i)
                known |= 0xff << (8 * i)
        self.regs[reg], self.known[reg] = value, known

    def read(self, operand, bits, rex=1):
        if operand[0] == "r":
            return self.get(operand[1], bits, rex)
        return self.load(self.address(operand), bits // 8)

    def write(self, operand, bits, value, rex=1):
        if operand[0] == "r":
            self.put(operand[1], bits, value, rex)
        else:
            self.store(self.address(operand), bits // 8, value)

    def alu(self, kind, left, right, bits):
        """kind: 0 add 1 or 2 adc 3 sbb 4 and 5 sub 6 xor 7 cmp. Returns the result."""
        if left is None or right is None:
            self.flags = [None, None, None, None]
            return None
        mask = (1 << bits) - 1
        sign = 1 << (bits - 1)
        carry = 0
        if kind in (2, 3):
            carry = self.flags[0]
            if carry is None:
                fail(f"carry is unknown at {self.pc:#x}")
            carry = int(carry)
        if kind in (0, 2):
            full = left + right + carry
            res = full & mask
            self.flags = [full > mask, res == 0, bool(res & sign), bool(~(left ^ right) & (left ^ res) & sign)]
            return res
        if kind in (3, 5, 7):
            full = left - right - carry
            res = full & mask
            self.flags = [full < 0, res == 0, bool(res & sign), bool((left ^ right) & (left ^ res) & sign)]
            return res
        res = {1: left | right, 4: left & right, 6: left ^ right}[kind]
        self.flags = [False, res == 0, bool(res & sign), False]
        return res

    def logic_flags(self, res, bits):
        self.flags = [False, res == 0, bool(res >> (bits - 1)), False]

    def shift(self, kind, value, count, bits):
        if value is None or count is None:
            self.flags = [None, None, None, None]
            return None
        count &= 63 if bits == 64 else 31
        if count == 0:
            return value
        mask = (1 << bits) - 1
        if kind == 4:
            res = (value << count) & mask
            carry = bool((value >> (bits - count)) & 1) if count <= bits else False
        elif kind == 5:
            res = value >> count
            carry = bool((value >> (count - 1)) & 1)
        elif kind == 7:
            signed = value - (1 << bits) if value >> (bits - 1) else value
            res = (signed >> count) & mask
            carry = bool((signed >> (count - 1)) & 1)
        else:
            fail(f"rotate kind {kind} at {self.pc:#x} is not modelled")
        self.flags = [carry, res == 0, bool(res >> (bits - 1)), None]
        return res

    def condition(self, code):
        if code not in COND:
            fail(f"condition {code} at {self.pc:#x} is not modelled")
        if any(self.flags[i] is None for i in USES[code]):
            return None
        return COND[code](self.flags)

    def immediate(self, insn, size, bits):
        at = insn.off + insn.size - size
        value = struct.unpack_from({1: "<b", 2: "<h", 4: "<i"}[size], self.image.data, at)[0]
        return value & ((1 << bits) - 1)

    def call(self, target, where):
        if target == self.image.note_target:
            self.notes += 1
            for reg in CALLER_SAVED:
                self.put(reg, 64, None)
            self.flags = [None, None, None, None]
            return
        if target in self.image.panic_targets:
            raise Done("panic", where)
        sp = self.get(RSP, 64) - 8
        self.set_reg(RSP, sp)
        self.store(sp, 8, where + self.image.fetch(where).size)
        self.pc = target

    def run(self, start):
        self.pc = start
        while True:
            self.steps += 1
            if self.steps > MAX_STEPS:
                fail(f"no stop from {start:#x}")
            self.step()

    def step(self):
        insn = self.image.fetch(self.pc)
        self.seen.add(self.pc)
        data = self.image.data
        key = insn.key
        here = self.pc
        bits = 64 if insn.rex & 8 else 16 if insn.wide16 else 32
        rexr = (insn.rex & 4) << 1
        rex = insn.rex
        self.pc = here + insn.size
        if isinstance(key, tuple):
            self.two_byte(insn, key, bits, rexr, here)
            return
        if key == 0x90 and not insn.rex & 1:
            return
        if 0x50 <= key <= 0x57:
            reg = (key & 7) | ((rex & 1) << 3)
            sp = self.get(RSP, 64) - 8
            self.set_reg(RSP, sp)
            self.spill(sp, reg, 8)
            return
        if 0x58 <= key <= 0x5f:
            reg = (key & 7) | ((rex & 1) << 3)
            sp = self.get(RSP, 64)
            self.reload(reg, sp, 8)
            self.set_reg(RSP, sp + 8)
            return
        if key in (0x89, 0x8b, 0x88, 0x8a):
            width = bits if key in (0x89, 0x8b) else 8
            operand = self.operand(insn)
            reg = ((data[insn.modrm] >> 3) & 7) | rexr
            if operand[0] == "r" and width >= 32:
                if key == 0x89:
                    self.move_reg(operand[1], reg, width)
                else:
                    self.move_reg(reg, operand[1], width)
            elif operand[0] == "m" and width >= 32:
                if key == 0x89:
                    self.spill(self.address(operand), reg, width // 8)
                else:
                    self.reload(reg, self.address(operand), width // 8)
            elif key in (0x89, 0x88):
                self.write(operand, width, self.get(reg, width, rex), rex)
            else:
                self.put(reg, width, self.read(operand, width, rex), rex)
            return
        if key in (0xc7, 0xc6):
            width = bits if key == 0xc7 else 8
            size = 2 if width == 16 else 1 if width == 8 else 4
            self.write(self.operand(insn), width, self.immediate(insn, size, width), rex)
            return
        if 0xb8 <= key <= 0xbf:
            reg = (key & 7) | ((rex & 1) << 3)
            size = 8 if rex & 8 else 2 if insn.wide16 else 4
            value = int.from_bytes(data[insn.off + insn.size - size:insn.off + insn.size], "little")
            self.put(reg, size * 8, value)
            return
        if 0xb0 <= key <= 0xb7:
            self.put((key & 7) | ((rex & 1) << 3), 8, data[insn.off + insn.size - 1], rex)
            return
        if key == 0x8d:
            operand = self.operand(insn)
            if operand[0] != "m":
                fail(f"lea with a register at {here:#x}")
            self.put(((data[insn.modrm] >> 3) & 7) | rexr, bits, self.address(operand) & ((1 << bits) - 1))
            return
        if key == 0x63:
            value = self.read(self.operand(insn), 32)
            if value is not None and value >> 31:
                value -= 1 << 32
            self.put(((data[insn.modrm] >> 3) & 7) | rexr, bits, None if value is None else value & U64)
            return
        if key in (0x81, 0x83, 0x80):
            operand = self.operand(insn)
            width = 8 if key == 0x80 else bits
            size = 4 if key == 0x81 and width != 16 else 2 if key == 0x81 else 1
            kind = (data[insn.modrm] >> 3) & 7
            res = self.alu(kind, self.read(operand, width, rex), self.immediate(insn, size, width), width)
            if kind != 7:
                self.write(operand, width, res, rex)
            return
        if key < 0x40 and key & 7 < 4:
            width = bits if key & 1 else 8
            operand = self.operand(insn)
            reg = ("r", ((data[insn.modrm] >> 3) & 7) | rexr)
            first, second = (operand, reg) if key & 7 < 2 else (reg, operand)
            kind = key >> 3
            if kind == 6 and first == second:
                self.write(first, width, 0, rex)
                self.flags = [False, True, False, False]
                return
            res = self.alu(kind, self.read(first, width, rex), self.read(second, width, rex), width)
            if kind != 7:
                self.write(first, width, res, rex)
            return
        if key < 0x40 and key & 7 in (4, 5):
            width = bits if key & 1 else 8
            size = 1 if width == 8 else 2 if width == 16 else 4
            kind = key >> 3
            res = self.alu(kind, self.get(RAX, width), self.immediate(insn, size, width), width)
            if kind != 7:
                self.put(RAX, width, res)
            return
        if key in (0x84, 0x85):
            width = bits if key == 0x85 else 8
            left = self.read(self.operand(insn), width, rex)
            right = self.get(((data[insn.modrm] >> 3) & 7) | rexr, width, rex)
            if left is None or right is None:
                self.flags = [None, None, None, None]
            else:
                self.logic_flags(left & right, width)
            return
        if key in (0xa8, 0xa9):
            width = 8 if key == 0xa8 else bits
            imm = self.immediate(insn, 1 if width == 8 else 4, width)
            left = self.get(RAX, width)
            if left is None:
                self.flags = [None, None, None, None]
            else:
                self.logic_flags(left & imm, width)
            return
        if key in (0xc1, 0xd1, 0xd3, 0xc0, 0xd0, 0xd2):
            width = 8 if key in (0xc0, 0xd0, 0xd2) else bits
            operand = self.operand(insn)
            kind = (data[insn.modrm] >> 3) & 7
            if key in (0xc1, 0xc0):
                count = data[insn.off + insn.size - 1]
            elif key in (0xd1, 0xd0):
                count = 1
            else:
                count = self.get(RCX, 8)
            self.write(operand, width, self.shift(kind, self.read(operand, width, rex), count, width), rex)
            return
        if key in (0x69, 0x6b):
            operand = self.operand(insn)
            imm = self.immediate(insn, 4 if key == 0x69 else 1, bits)
            self.signed_multiply(((data[insn.modrm] >> 3) & 7) | rexr, self.read(operand, bits), imm, bits)
            return
        if key in (0xf7, 0xf6):
            self.unary(insn, key, bits, here)
            return
        if key in (0xff, 0xfe):
            kind = (data[insn.modrm] >> 3) & 7
            operand = self.operand(insn)
            width = 8 if key == 0xfe else bits
            if kind in (0, 1):
                carry = self.flags[0]
                res = self.alu(0 if kind == 0 else 5, self.read(operand, width, rex), 1, width)
                self.write(operand, width, res, rex)
                self.flags[0] = carry
                return
            if key == 0xff and kind == 2:
                if operand[0] == "m" and operand[1] is None and operand[2] is None:
                    target = self.image.slots.get(operand[4])
                    if target is None:
                        fail(f"call through unknown slot {operand[4]:#x} at {here:#x}")
                    self.call(target, here)
                    return
                fail(f"indirect call at {here:#x}")
            if key == 0xff and kind == 4 and operand[0] == "r":
                target = self.get(operand[1], 64)
                if target is None:
                    fail(f"jump through unknown register at {here:#x}")
                self.pc = target
                return
            fail(f"group 5 form {kind} at {here:#x}")
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
            sp = self.get(RSP, 64)
            mark = self.load(sp, 8)
            if mark is None:
                fail(f"return to an unknown address at {here:#x}")
            self.set_reg(RSP, sp + 8)
            if mark == RETURN_MARK:
                raise Done("ret", here)
            self.pc = mark
            return
        if key == 0xcc:
            fail(f"int3 reached at {here:#x}")
        fail(f"instruction {key:#x} at {here:#x} is not modelled")

    def signed_multiply(self, reg, left, right, bits):
        if left is None or right is None:
            self.put(reg, bits, None)
            self.flags = [None, None, None, None]
            return
        sign = 1 << bits
        a = left - sign if left >> (bits - 1) else left
        b = right - sign if right >> (bits - 1) else right
        full = a * b
        res = full & (sign - 1)
        wide = res - sign if res >> (bits - 1) else res
        self.put(reg, bits, res)
        self.flags = [wide != full, None, None, wide != full]

    def unary(self, insn, key, bits, here):
        kind = (self.image.data[insn.modrm] >> 3) & 7
        operand = self.operand(insn)
        width = 8 if key == 0xf6 else bits
        value = self.read(operand, width, insn.rex)
        if kind == 0:
            imm = self.immediate(insn, 1 if width == 8 else 4, width)
            if value is None:
                self.flags = [None, None, None, None]
            else:
                self.logic_flags(value & imm, width)
            return
        if kind == 2:
            self.write(operand, width, None if value is None else ~value & ((1 << width) - 1), insn.rex)
            return
        if kind == 3:
            res = self.alu(5, 0, value, width)
            self.write(operand, width, res, insn.rex)
            return
        if width < 32:
            fail(f"narrow multiply or divide at {here:#x}")
        low = self.get(RAX, width)
        if kind == 4:
            if low is None or value is None:
                fail(f"mul of an unknown value at {here:#x}")
            full = low * value
            mask = (1 << width) - 1
            self.put(RAX, width, full & mask)
            self.put(RDX, width, full >> width)
            self.flags = [full >> width != 0, None, None, full >> width != 0]
            return
        if kind == 6:
            high = self.get(RDX, width)
            if low is None or value is None or high is None:
                fail(f"div of an unknown value at {here:#x}")
            if value == 0:
                fail(f"divide by zero at {here:#x}")
            q, r = divmod((high << width) | low, value)
            if q >> width:
                fail(f"divide overflow at {here:#x}")
            self.put(RAX, width, q)
            self.put(RDX, width, r)
            self.flags = [None, None, None, None]
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
        rex = insn.rex
        if len(key) == 3:
            fail(f"instruction {key} at {here:#x} is not modelled")
        if 0x80 <= two <= 0x8f:
            self.jump(two - 0x80, insn, here)
            return
        if two == 0x1f:
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
            self.write(self.operand(insn), 8, None if taken is None else int(taken), rex)
            return
        if two in (0xb6, 0xb7):
            value = self.read(self.operand(insn), 8 if two == 0xb6 else 16, rex)
            self.put(((data[insn.modrm] >> 3) & 7) | rexr, bits, value)
            return
        if two == 0xaf:
            reg = ((data[insn.modrm] >> 3) & 7) | rexr
            self.signed_multiply(reg, self.get(reg, bits), self.read(self.operand(insn), bits), bits)
            return
        if two in (0xa4, 0xa5, 0xac, 0xad):
            operand = self.operand(insn)
            reg = ((data[insn.modrm] >> 3) & 7) | rexr
            count = data[insn.off + insn.size - 1] if two in (0xa4, 0xac) else self.get(RCX, 8)
            value, fill = self.read(operand, bits), self.get(reg, bits)
            if value is None or fill is None or count is None:
                fail(f"double shift of an unknown value at {here:#x}")
            count &= 63 if bits == 64 else 31
            if count:
                mask = (1 << bits) - 1
                if two in (0xa4, 0xa5):
                    res = ((value << count) | (fill >> (bits - count))) & mask
                else:
                    res = ((value >> count) | (fill << (bits - count))) & mask
                self.write(operand, bits, res)
                self.flags = [None, res == 0, bool(res >> (bits - 1)), None]
            return
        if two == 0xbd or two == 0xbc:
            value = self.read(self.operand(insn), bits)
            reg = ((data[insn.modrm] >> 3) & 7) | rexr
            if value is None:
                fail(f"bit scan of an unknown value at {here:#x}")
            if insn.rep == 0xf3:
                count = bits if value == 0 else bits - value.bit_length() if two == 0xbd else (value & -value).bit_length() - 1
                self.put(reg, bits, count)
                self.flags = [value == 0, count == 0, False, False]
                return
            if value == 0:
                # 0x4eae576 presets the destination, so a zero source keeps it.
                self.flags = [None, True, None, None]
                return
            self.put(reg, bits, value.bit_length() - 1 if two == 0xbd else (value & -value).bit_length() - 1)
            self.flags = [None, False, None, None]
            return
        if two in (0x10, 0x11, 0x28, 0x29, 0x6f, 0x7f, 0x57):
            if two in (0x6f, 0x7f) and not (insn.wide16 or insn.rep == 0xf3):
                fail(f"mmx move at {here:#x}")
            if two in (0x10, 0x11) and insn.rep:
                fail(f"scalar float move at {here:#x}")
            reg = ((data[insn.modrm] >> 3) & 7) | rexr
            operand = self.operand(insn)
            if two == 0x57:
                if operand != ("r", reg):
                    fail(f"xor of two xmm registers at {here:#x}")
                self.xmm[reg] = bytes(16)
                return
            if operand[0] == "r":
                if two in (0x10, 0x28, 0x6f):
                    self.xmm[reg] = self.xmm[operand[1]]
                else:
                    self.xmm[operand[1]] = self.xmm[reg]
                return
            at = self.address(operand)
            if two in (0x10, 0x28, 0x6f):
                low, high = self.load(at, 8), self.load(at + 8, 8)
                self.xmm[reg] = None if low is None or high is None else struct.pack("<QQ", low, high)
            else:
                value = self.xmm[reg]
                if value is None:
                    self.store(at, 8, None)
                    self.store(at + 8, 8, None)
                else:
                    low, high = struct.unpack("<QQ", value)
                    self.store(at, 8, low)
                    self.store(at + 8, 8, high)
            return
        fail(f"instruction {key} at {here:#x} is not modelled")


