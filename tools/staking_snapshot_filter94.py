#!/usr/bin/env python3
"""Extract and evaluate node #94 validator stake snapshot filtering.

The x86 subset interpreter below is adapted from this repository's MIT-licensed
staking_stake_accounting.py; the staking fixtures and assertions are independent.
"""

import argparse
import bisect
import collections
import copy
import datetime
import csv
import itertools
import fractions
import hashlib
import json
import math
import multiprocessing
import pathlib
import re
import struct
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))

from elf_index import sections  # noqa: E402
from fde_extents import eh_frame_records  # noqa: E402

BINARY = ROOT / "artifacts" / "node" / "94" / "hl-node"
SHA256 = "3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f"

RAX, RCX, RDX, RBX, RSP, RBP, RSI, RDI = range(8)
R8, R9, R10, R11, R12, R13, R14, R15 = range(8, 16)
VOLATILE = (RCX, RSI, RDI, R8, R9, R10, R11)
CALLEE_SAVED = (RBX, RBP, R12, R13, R14, R15)
MASK = {1: 0xFF, 2: 0xFFFF, 4: 0xFFFFFFFF, 8: 0xFFFFFFFFFFFFFFFF}
SIGN = {1: 0x80, 2: 0x8000, 4: 0x80000000, 8: 0x8000000000000000}
STACK_MARK = 0xA5
STACK_TOP = 0x7FF000000
STACK_SIZE = 0x8000
HEAP_BASE = 0x600000000
HEAP_SIZE = 0x400000
RETURN_SENTINEL = 0xDEAD0000
POISON = 0xA5A5A5A5A5A5A5A5
STEP_LIMIT = 200000
MUTANT_STEP_LIMIT = 120000


class EvidenceError(Exception):
    pass


class Halt(Exception):
    pass


class Panicked(Exception):
    pass


class Image:
    """Section, relocation and FDE views of one ELF byte string, through the shared parsers."""

    def __init__(self, blob):
        self.blob = blob
        self.relative_map = None
        self.sections = sections(blob)
        # SHT_NOBITS sections have no file bytes, so they never resolve an address.
        self.mapped = sorted((s for s in self.sections if s["type"] != 8 and s["address"] and s["size"]),
                             key=lambda s: s["address"])
        self.named = {s["name"]: s for s in self.sections}
        _, fdes = eh_frame_records(blob, self.sections)
        ends = {}
        for row in fdes:
            if row["start"] in ends:
                raise EvidenceError("duplicate FDE start: %#x" % row["start"])
            ends[row["start"]] = row["end"]
        self.fde_ends = ends
        self.starts = sorted(ends)

    def offset(self, va):
        for section in self.mapped:
            if section["address"] <= va < section["address"] + section["size"]:
                return va - section["address"] + section["offset"]
        raise EvidenceError("address outside file-backed sections: %#x" % va)

    def fde(self, va):
        index = bisect.bisect_right(self.starts, va) - 1
        if index < 0 or va >= self.fde_ends[self.starts[index]]:
            raise EvidenceError("address outside every FDE: %#x" % va)
        return self.starts[index], self.fde_ends[self.starts[index]]

    def exact_fde(self, va):
        start, end = self.fde(va)
        if start != va:
            raise EvidenceError("not an FDE start: %#x" % va)
        return start, end

    def text_bytes(self):
        text = self.named[".text"]
        return text["address"], bytes(self.blob[text["offset"]:text["offset"] + text["size"]])

    def relocations(self):
        """Yield (slot, type, addend, symbol index) for .rela.dyn."""
        rela = self.named[".rela.dyn"]
        for at in range(rela["offset"], rela["offset"] + rela["size"], 24):
            slot, info, addend = struct.unpack_from("<QQq", self.blob, at)
            yield slot, info & 0xFFFFFFFF, addend, info >> 32

    def relative(self):
        if self.relative_map is None:
            self.relative_map = {slot: addend for slot, kind, addend, _ in self.relocations() if kind == 8}
        return self.relative_map

    def location(self, slot, relative):
        """Decode one Location record; the path is kept only below the crate or std root."""
        size, line, column = struct.unpack_from("<QII", self.blob, self.offset(slot) + 8)
        start = self.offset(relative[slot])
        path = bytes(self.blob[start:start + size]).decode()
        for marker in ("/l1/", "/library/"):
            if marker in path:
                path = path[path.rindex(marker) + 1:]
                break
        return path, line, column


def load_image(path=BINARY, expected=SHA256):
    blob = pathlib.Path(path).read_bytes()
    digest = hashlib.sha256(blob).hexdigest()
    if digest != expected:
        raise EvidenceError("binary SHA-256 mismatch: %s" % digest)
    return Image(blob)


def fdiv(left, right):
    return left / right


def to_float(bits):
    return struct.unpack("<d", struct.pack("<Q", bits & MASK[8]))[0]


def to_bits(value):
    return struct.unpack("<Q", struct.pack("<d", value))[0]


class Insn:
    __slots__ = ("va", "size", "op", "a", "b", "width", "cc", "target", "next", "imm_at", "imm_size", "rip_at", "data")

    def __init__(self, va, size, op, a=None, b=None, width=8, cc=None, target=None, imm=None, rip_at=None):
        self.va, self.size, self.op, self.a, self.b = va, size, op, a, b
        self.width, self.cc, self.target = width, cc, target
        self.next = va + size
        self.imm_at, self.imm_size = imm if imm else (None, None)
        self.rip_at = rip_at


GROUP1 = ("add", "or", "adc", "sbb", "and", "sub", "xor", "cmp")
SHIFTS = {0: "rol", 1: "ror", 4: "shl", 5: "shr", 7: "sar"}


def decode(read, va):
    """Decode one instruction at va; read(va, n) returns n code bytes."""
    window = read(va, 16)
    pos, rex, opsize, rep, repne = 0, 0, False, False, False
    while True:
        byte = window[pos]
        if byte == 0x66:
            opsize = True
        elif byte == 0xF3:
            rep = True
        elif byte == 0xF2:
            repne = True
        elif byte == 0xF0:
            pass
        elif byte != 0x2E:
            break
        pos += 1
    if 0x40 <= window[pos] <= 0x4F:
        rex = window[pos]
        pos += 1
    wide = bool(rex & 8)
    width = 8 if wide else (2 if opsize else 4)
    byte = window[pos]
    pos += 1
    imm = None
    rip_at = None

    def modrm(vector=False):
        nonlocal pos, rip_at
        mod_rm = window[pos]
        pos += 1
        mod, reg, rm = mod_rm >> 6, ((mod_rm >> 3) & 7) | ((rex & 4) << 1), mod_rm & 7
        if mod == 3:
            return reg, ("x" if vector else "r", rm | ((rex & 1) << 3))
        base, index, scale, rip = None, None, 1, False
        if rm == 4:
            sib = window[pos]
            pos += 1
            scale = 1 << (sib >> 6)
            index = ((sib >> 3) & 7) | ((rex & 2) << 2)
            if index == 4:
                index = None
            base = (sib & 7) | ((rex & 1) << 3)
            if sib & 7 == 5 and mod == 0:
                base = None
                disp = struct.unpack_from("<i", window, pos)[0]
                pos += 4
                return reg, ("m", base, index, scale, disp, False)
        elif rm == 5 and mod == 0:
            rip = True
        else:
            base = rm | ((rex & 1) << 3)
        disp = 0
        if mod == 1:
            disp = struct.unpack_from("<b", window, pos)[0]
            pos += 1
        elif mod == 2 or rip:
            if rip:
                rip_at = pos
            disp = struct.unpack_from("<i", window, pos)[0]
            pos += 4
        return reg, ("m", base, index, scale, disp, rip)

    def immediate(size):
        nonlocal pos, imm
        value = struct.unpack_from({1: "<b", 2: "<h", 4: "<i", 8: "<q"}[size], window, pos)[0]
        imm = (pos, size)
        pos += size
        return value

    def finish(op, a=None, b=None, w=None, cc=None, target=None):
        size = pos
        if (width if w is None else w) == 1 and not rex:
            if op != "mov" and any(operand and operand[0] == "r" and 4 <= operand[1] <= 7 for operand in (a, b)):
                raise EvidenceError("high byte register at %#x" % va)
            if a and a[0] == "r" and 4 <= a[1] <= 7:
                a = ("h", a[1] - 4)
            if b and b[0] == "r" and 4 <= b[1] <= 7:
                b = ("h", b[1] - 4)

        def fix(operand):
            if operand and operand[0] == "m" and operand[5]:
                return ("m", None, None, 1, va + size + operand[4], False)
            return operand
        return Insn(va, size, op, fix(a), fix(b), width if w is None else w, cc, target, imm, rip_at)

    if 0x50 <= byte <= 0x57:
        return finish("push", ("r", (byte & 7) | ((rex & 1) << 3)), w=8)
    if 0x58 <= byte <= 0x5F:
        return finish("pop", ("r", (byte & 7) | ((rex & 1) << 3)), w=8)
    if byte < 0x40 and byte & 7 < 4:
        name = GROUP1[byte >> 3]
        w = 1 if not byte & 1 else width
        reg, rm = modrm()
        if byte & 2:
            return finish(name, ("r", reg), rm, w)
        return finish(name, rm, ("r", reg), w)
    if byte < 0x40 and byte & 7 in (4, 5):
        w = 1 if byte & 7 == 4 else width
        value = immediate(1 if w == 1 else 2 if w == 2 else 4)
        return finish(GROUP1[byte >> 3], ("r", RAX), ("i", value), w)
    if byte == 0x63 and wide:
        reg, rm = modrm()
        return finish("movsxd", ("r", reg), rm, 8)
    if 0x70 <= byte <= 0x7F:
        rel = immediate(1)
        return finish("jcc", cc=byte & 15, target=va + pos + rel)
    if byte in (0x80, 0x81, 0x83):
        reg, rm = modrm()
        w = 1 if byte == 0x80 else width
        value = immediate(4 if byte == 0x81 and w != 2 else 2 if byte == 0x81 else 1)
        return finish(GROUP1[reg & 7], rm, ("i", value), w)
    if byte in (0x84, 0x85):
        reg, rm = modrm()
        return finish("test", rm, ("r", reg), 1 if byte == 0x84 else width)
    if byte in (0x88, 0x89, 0x8A, 0x8B):
        reg, rm = modrm()
        w = 1 if not byte & 1 else width
        if byte & 2:
            return finish("mov", ("r", reg), rm, w)
        return finish("mov", rm, ("r", reg), w)
    if byte == 0x8D:
        reg, rm = modrm()
        return finish("lea", ("r", reg), rm, width)
    if byte == 0x90:
        return finish("nop")
    if byte == 0x6A:
        value = immediate(1)
        return finish("pushi", ("i", value), w=8)
    if byte == 0x98:
        return finish("cdqe" if wide else "cwde")
    if byte == 0xA9:
        value = immediate(4)
        return finish("test", ("r", RAX), ("i", value), width)
    if byte == 0xA8:
        value = immediate(1)
        return finish("test", ("r", RAX), ("i", value), 1)
    if 0xB0 <= byte <= 0xB7:
        reg = (byte & 7) | ((rex & 1) << 3)
        value = immediate(1)
        return finish("mov", ("r", reg), ("i", value & 0xFF), 1)
    if 0xB8 <= byte <= 0xBF:
        reg = (byte & 7) | ((rex & 1) << 3)
        value = immediate(8 if wide else 2 if opsize else 4)
        return finish("mov", ("r", reg), ("i", value & MASK[width]), width)
    if byte == 0x69:
        reg, rm = modrm()
        value = immediate(4)
        return finish("imul3", ("r", reg), rm, width, target=value)
    if byte == 0x6B:
        reg, rm = modrm()
        value = immediate(1)
        return finish("imul3", ("r", reg), rm, width, target=value)
    if byte == 0xD3:
        reg, rm = modrm()
        if reg & 7 not in SHIFTS:
            raise EvidenceError("unsupported shift at %#x" % va)
        return finish(SHIFTS[reg & 7], rm, ("r", RCX), width)
    if byte in (0xD1, 0xD0):
        reg, rm = modrm()
        if reg & 7 not in SHIFTS:
            raise EvidenceError("unsupported shift at %#x" % va)
        return finish(SHIFTS[reg & 7], rm, ("i", 1), 1 if byte == 0xD0 else width)
    if byte in (0xC1, 0xC0):
        reg, rm = modrm()
        if reg & 7 not in SHIFTS:
            raise EvidenceError("unsupported shift at %#x" % va)
        value = immediate(1) & 0xFF
        return finish(SHIFTS[reg & 7], rm, ("i", value), 1 if byte == 0xC0 else width)
    if byte == 0xC3:
        return finish("ret")
    if byte == 0xCC:
        return finish("int3")
    if byte in (0xC6, 0xC7):
        reg, rm = modrm()
        w = 1 if byte == 0xC6 else width
        value = immediate(1 if w == 1 else 2 if w == 2 else 4)
        return finish("mov", rm, ("i", value & MASK[w]), w)
    if byte == 0xE8:
        rel = immediate(4)
        return finish("call", target=va + pos + rel)
    if byte == 0xE9:
        rel = immediate(4)
        return finish("jmp", target=va + pos + rel)
    if byte == 0xEB:
        rel = immediate(1)
        return finish("jmp", target=va + pos + rel)
    if byte in (0xF6, 0xF7):
        reg, rm = modrm()
        w = 1 if byte == 0xF6 else width
        kind = reg & 7
        if kind == 0:
            value = immediate(1 if w == 1 else 4)
            return finish("test", rm, ("i", value), w)
        if kind in (2, 3, 4, 5, 6):
            return finish({2: "not", 3: "neg", 4: "mul", 5: "imul1", 6: "div"}[kind], rm, w=w)
        raise EvidenceError("unsupported group 3 opcode at %#x" % va)
    if byte in (0xFE, 0xFF):
        reg, rm = modrm()
        kind = reg & 7
        w = 1 if byte == 0xFE else width
        if kind in (0, 1):
            return finish("inc" if kind == 0 else "dec", rm, w=w)
        if byte == 0xFF and kind == 2:
            return finish("calli", rm, w=8)
        if byte == 0xFF and kind == 4:
            return finish("jmpi", rm, w=8)
        if byte == 0xFF and kind == 6:
            return finish("pushm", rm, w=8)
        raise EvidenceError("unsupported group 5 opcode at %#x" % va)
    if byte == 0x87:
        reg, rm = modrm()
        return finish("xchg", rm, ("r", reg), width)
    if byte == 0x0F:
        two = window[pos]
        pos += 1
        if two == 0x0B:
            return finish("ud2")
        if 0xC8 <= two <= 0xCF:
            return finish("bswap", ("r", (two & 7) | ((rex & 1) << 3)), w=width)
        if two == 0xC6 and opsize:
            reg, rm = modrm(True)
            value = immediate(1) & 0xFF
            return finish("shufpd", ("x", reg), rm, 16, target=value)
        if two == 0xC2 and opsize:
            reg, rm = modrm(True)
            value = immediate(1) & 0xFF
            return finish("cmppd", ("x", reg), rm, 16, target=value)
        if two == 0x50 and opsize:
            reg, rm = modrm(True)
            return finish("movmskpd", ("r", reg), rm, 4)
        if two == 0x72 and opsize:
            reg, rm = modrm(True)
            if reg & 7 not in (4, 6):
                raise EvidenceError("unsupported vector shift at %#x" % va)
            value = immediate(1) & 0xFF
            return finish("psrad" if reg & 7 == 4 else "pslld", rm, ("i", value), 16)
        if two == 0x73 and opsize:
            reg, rm = modrm(True)
            if reg & 7 != 2:
                raise EvidenceError("unsupported vector shift at %#x" % va)
            value = immediate(1) & 0xFF
            return finish("psrlq", rm, ("i", value), 16)
        if two == 0xAB:
            reg, rm = modrm()
            return finish("btsr", rm, ("r", reg), width)
        if two == 0xA3:
            reg, rm = modrm()
            return finish("btr", rm, ("r", reg), width)
        if two in (0xBE, 0xBF):
            reg, rm = modrm()
            return finish("movsx", ("r", reg), rm, width, cc=1 if two == 0xBE else 2)
        if two == 0xBA:
            reg, rm = modrm()
            if reg & 7 != 4:
                raise EvidenceError("unsupported bit test at %#x" % va)
            value = immediate(1) & 0xFF
            return finish("bt", rm, ("i", value), width)
        if two == 0x1F:
            modrm()
            return finish("nop")
        if two == 0x13:
            reg, rm = modrm(True)
            return finish("movq", rm, ("x", reg), 8)
        if two in (0x10, 0x11) and repne:
            reg, rm = modrm(True)
            if two == 0x10:
                return finish("movsd", ("x", reg), rm, 8)
            return finish("movsd", rm, ("x", reg), 8)
        if two in (0x10, 0x11) and rep:
            reg, rm = modrm(True)
            if rm[0] == "x":
                raise EvidenceError("movss between registers at %#x" % va)
            if two == 0x10:
                return finish("movss", ("x", reg), rm, 4)
            return finish("movss", rm, ("x", reg), 4)
        if two in (0x10, 0x11, 0x28, 0x29, 0x6F, 0x7F):
            reg, rm = modrm(True)
            if two in (0x10, 0x28, 0x6F):
                return finish("movx", ("x", reg), rm, 16)
            return finish("movx", rm, ("x", reg), 16)
        vector = {(0x57, False): "xorps", (0x57, True): "xorps", (0xEF, True): "xorps", (0x15, True): "unpckhpd", (0x5C, True): "subpd",
                  (0x54, True): "andpd", (0xDF, True): "pandn", (0x56, True): "orpd", (0x62, True): "punpckldq", (0x60, True): "punpcklbw",
                  (0x74, True): "pcmpeqb", (0x76, True): "pcmpeqd", (0x14, False): "punpckldq", (0x6C, True): "punpcklqdq",
                  (0xDB, True): "andpd", (0xEB, True): "orpd", (0x58, True): "addpd", (0x5E, True): "divpd"}
        if (two, opsize) in vector:
            reg, rm = modrm(True)
            return finish(vector[(two, opsize)], ("x", reg), rm, 16)
        if two in (0x58, 0x59, 0x5C, 0x5D, 0x5E, 0x5F) and repne:
            reg, rm = modrm(True)
            return finish({0x58: "addsd", 0x59: "mulsd", 0x5C: "subsd", 0x5D: "minsd", 0x5E: "divsd", 0x5F: "maxsd"}[two], ("x", reg), rm, 8)
        if two == 0x2C and repne:
            reg, rm = modrm(True)
            return finish("cvttsd2si", ("r", reg), rm, 8)
        if two == 0x2A and repne:
            reg, rm = modrm()
            return finish("cvtsi2sd", ("x", reg), rm, 8)
        if two == 0x2E and opsize:
            reg, rm = modrm(True)
            return finish("ucomisd", ("x", reg), rm, 8)
        if two == 0x6E and opsize and not wide:
            reg, rm = modrm()
            return finish("movd", ("x", reg), rm, 4)
        if two == 0x70 and (opsize or repne):
            reg, rm = modrm(True)
            value = immediate(1) & 0xFF
            return finish("pshufd" if opsize else "pshuflw", ("x", reg), rm, 16, target=value)
        if two == 0xD7 and opsize:
            reg, rm = modrm(True)
            return finish("pmovmskb", ("r", reg), rm, 4)
        if two == 0xBC and rep:
            reg, rm = modrm()
            return finish("tzcnt", ("r", reg), rm, width)
        if two == 0xD6 and opsize:
            reg, rm = modrm(True)
            return finish("movq", rm, ("x", reg), 8)
        if two == 0x16 and not opsize:
            reg, rm = modrm(True)
            return finish("movhps", ("x", reg), rm, 8)
        if two == 0x12 and not opsize and not rep and not repne:
            reg, rm = modrm(True)
            return finish("movlps", ("x", reg), rm, 8)
        if two == 0x7E and opsize and not wide:
            reg, rm = modrm()
            return finish("movdout", rm, ("x", reg), 4)
        if two == 0x7E and rep:
            reg, rm = modrm(True)
            return finish("movq", ("x", reg), rm, 8)
        if two == 0x6E and opsize and wide:
            reg, rm = modrm()
            return finish("movq", ("x", reg), rm, 8)
        if two == 0x7E and opsize and wide:
            reg, rm = modrm()
            return finish("movq", rm, ("x", reg), 8)
        if 0x40 <= two <= 0x4F:
            reg, rm = modrm()
            return finish("cmov", ("r", reg), rm, width, cc=two & 15)
        if 0x80 <= two <= 0x8F:
            rel = immediate(4)
            return finish("jcc", cc=two & 15, target=va + pos + rel)
        if 0x90 <= two <= 0x9F:
            _, rm = modrm()
            return finish("set", rm, w=1, cc=two & 15)
        if two == 0xAF:
            reg, rm = modrm()
            return finish("imul2", ("r", reg), rm, width)
        if two == 0xBD:
            reg, rm = modrm()
            return finish("bsr", ("r", reg), rm, width)
        if two == 0xA4:
            reg, rm = modrm()
            value = immediate(1) & 0xFF
            return finish("shld", rm, ("r", reg), width, target=value)
        if two == 0xAC:
            reg, rm = modrm()
            value = immediate(1) & 0xFF
            return finish("shrd", rm, ("r", reg), width, target=value)
        if two == 0xB1:
            reg, rm = modrm()
            return finish("cmpxchg", rm, ("r", reg), width)
        if two == 0xAD:
            reg, rm = modrm()
            return finish("shrd", rm, ("r", reg), width)
        if two in (0xB6, 0xB7):
            reg, rm = modrm()
            return finish("movzx", ("r", reg), rm, width, cc=1 if two == 0xB6 else 2)
    raise EvidenceError("undecodable opcode %#x at %#x" % (byte, va))


def decode_range(image, start, end):
    """Decode [start, end) linearly; the last instruction must end exactly at end."""
    base = image.offset(start)
    code = image.blob[base:base + (end - start) + 16]

    def read(va, count):
        return code[va - start:va - start + count]

    rows = []
    va = start
    while va < end:
        row = decode(read, va)
        row.data = bytes(read(va, row.size))
        rows.append(row)
        va = row.next
    if va != end:
        raise EvidenceError("decoder overran FDE end at %#x" % end)
    return rows


class Memory:
    def __init__(self, image):
        self.image = image
        self.stack = bytearray(STACK_SIZE)
        self.heap = bytearray(HEAP_SIZE)
        self.stack_base = STACK_TOP - STACK_SIZE
        self.fresh = (bytes([STACK_MARK]) * STACK_SIZE, bytes([STACK_MARK]) * HEAP_SIZE)
        self.statics = {}

    def reset(self, used=HEAP_SIZE):
        """Refill the stack and the first `used` heap bytes; the rest must still be untouched."""
        self.stack[:] = self.fresh[0]
        self.heap[:used] = memoryview(self.fresh[1])[:used]

    def locate(self, addr, count):
        if self.stack_base <= addr and addr + count <= STACK_TOP:
            return self.stack, addr - self.stack_base
        if HEAP_BASE <= addr and addr + count <= HEAP_BASE + HEAP_SIZE:
            return self.heap, addr - HEAP_BASE
        return None, 0

    def read(self, addr, count):
        return int.from_bytes(self.bytes_at(addr, count), "little")

    def write(self, addr, count, value):
        buffer, at = self.locate(addr, count)
        if buffer is None:
            raise Halt("write outside stack and heap: %#x" % addr)
        buffer[at:at + count] = (value & MASK.get(count, (1 << (8 * count)) - 1)).to_bytes(count, "little")

    def put_bytes(self, addr, data):
        buffer, at = self.locate(addr, len(data))
        if buffer is None:
            raise Halt("write outside stack and heap: %#x" % addr)
        buffer[at:at + len(data)] = data

    def bytes_at(self, addr, count):
        buffer, at = self.locate(addr, count)
        if buffer is not None:
            return bytes(buffer[at:at + count])
        if addr in self.statics:
            return self.statics[addr].to_bytes(count, "little")
        try:
            offset = self.image.offset(addr)
        except EvidenceError:
            raise Halt("read outside every mapping: %#x" % addr)
        return bytes(self.image.blob[offset:offset + count])

    def copy(self, dst, src, count):
        self.put_bytes(dst, self.bytes_at(src, count))

class Machine:
    def __init__(self, image, patches=None):
        self.image = image
        self.patches = patches or {}
        self.memory = Memory(image)
        self.cache = {}
        self.calls = {}
        self.real = frozenset()
        self.slots = {}
        self.regs = [0] * 16
        self.xmm = [POISON | POISON << 64] * 16
        self.cf = self.zf = self.sf = self.of = self.pf = False
        self.seen = set()
        self.branch_edges = {}
        self.steps = 0
        self.keep_rdx = False
        self.step_limit = STEP_LIMIT
        self.xmm_result = None

    def read_code(self, va, count):
        offset = self.image.offset(va)
        data = bytearray(self.image.blob[offset:offset + count])
        for index in range(count):
            if va + index in self.patches:
                data[index] = self.patches[va + index]
        return data

    def address(self, operand):
        _, base, index, scale, disp, _ = operand
        value = disp
        if base is not None:
            value += self.regs[base]
        if index is not None:
            value += self.regs[index] * scale
        return value & MASK[8]

    def get(self, operand, width):
        kind = operand[0]
        if kind == "r":
            return self.regs[operand[1]] & MASK[width]
        if kind == "h":
            return self.regs[operand[1]] >> 8 & 0xFF
        if kind == "i":
            return operand[1] & MASK[width]
        return self.memory.read(self.address(operand), width)

    def put(self, operand, width, value):
        value &= MASK[width]
        if operand[0] == "h":
            self.regs[operand[1]] = (self.regs[operand[1]] & ~0xFF00) | value << 8
            return
        if operand[0] == "r":
            reg = operand[1]
            if width >= 4:
                self.regs[reg] = value
            else:
                self.regs[reg] = (self.regs[reg] & ~MASK[width]) | value
        else:
            self.memory.write(self.address(operand), width, value)

    def condition(self, code):
        result = {
            0: self.of, 1: self.cf, 2: self.zf, 3: self.cf or self.zf, 4: self.sf,
            5: self.pf, 6: self.sf != self.of, 7: self.zf or self.sf != self.of,
        }[code >> 1]
        return bool(result) != bool(code & 1)

    def set_logic(self, result, width):
        self.cf = self.of = False
        self.zf = result & MASK[width] == 0
        self.sf = bool(result & SIGN[width])

    def add_sub(self, left, right, carry, width, subtract):
        mask = MASK[width]
        if subtract:
            result = (left - right - carry) & mask
            self.cf = left < right + carry
            self.of = bool((left ^ right) & (left ^ result) & SIGN[width])
        else:
            total = left + right + carry
            result = total & mask
            self.cf = total > mask
            self.of = bool(~(left ^ right) & (left ^ result) & SIGN[width])
        self.zf = result == 0
        self.sf = bool(result & SIGN[width])
        return result

    def push(self, value):
        self.regs[RSP] -= 8
        self.memory.write(self.regs[RSP], 8, value)

    def pop(self):
        value = self.memory.read(self.regs[RSP], 8)
        self.regs[RSP] += 8
        return value

    def stub(self, hook):
        self.keep_rdx = False
        hook(self)
        for reg in VOLATILE:
            self.regs[reg] = POISON
        if not self.keep_rdx:
            self.regs[RDX] = POISON
        self.xmm = [POISON | POISON << 64] * 16

    def run(self, entry, args, stack=()):
        self.regs = [POISON] * 16
        for reg in CALLEE_SAVED:
            self.regs[reg] = 0x1111111111111100 + reg
        for reg, value in args.items():
            self.regs[reg] = value
        self.regs[RSP] = STACK_TOP - 0x100
        for value in reversed(stack):
            self.push(value)
        self.push(RETURN_SENTINEL)
        saved = {reg: self.regs[reg] for reg in CALLEE_SAVED}
        top = self.regs[RSP]
        pc = entry
        limit = self.step_limit
        cache = self.cache
        while pc != RETURN_SENTINEL:
            limit -= 1
            if limit < 0:
                raise Halt("step limit")
            row = cache.get(pc)
            if row is None:
                row = decode(self.read_code, pc)
                cache[pc] = row
            self.seen.add(pc)
            self.steps += 1
            next_pc = self.step(row)
            if row.op == "jcc":
                self.branch_edges.setdefault(row.va, set()).add(next_pc == row.target)
            pc = next_pc
        if self.regs[RSP] != top + 8:
            raise Halt("unbalanced stack")
        for reg, value in saved.items():
            if self.regs[reg] != value:
                raise Halt("callee-saved register changed")
        return self.regs[RAX]

    def step(self, row):
        op = row.op
        width = row.width
        if op == "mov":
            self.put(row.a, width, self.get(row.b, width))
        elif op == "jcc":
            return row.target if self.condition(row.cc) else row.next
        elif op == "lea":
            self.put(row.a, width, self.address(row.b))
        elif op == "push":
            self.push(self.regs[row.a[1]])
        elif op == "pop":
            self.regs[row.a[1]] = self.pop()
        elif op in ("add", "adc", "sub", "sbb", "cmp"):
            carry = int(self.cf) if op in ("adc", "sbb") else 0
            result = self.add_sub(self.get(row.a, width), self.get(row.b, width), carry, width, op not in ("add", "adc"))
            if op != "cmp":
                self.put(row.a, width, result)
        elif op in ("and", "or", "xor", "test"):
            left, right = self.get(row.a, width), self.get(row.b, width)
            result = left & right if op in ("and", "test") else left | right if op == "or" else left ^ right
            self.set_logic(result, width)
            if op != "test":
                self.put(row.a, width, result)
        elif op == "cmpxchg":
            current = self.get(row.a, width)
            wanted = self.regs[RAX] & MASK[width]
            self.add_sub(wanted, current, 0, width, True)
            if wanted == current:
                self.put(row.a, width, self.get(row.b, width))
            else:
                self.put(("r", RAX), width, current)
        elif op == "xchg":
            first, second = self.get(row.a, width), self.get(row.b, width)
            self.put(row.a, width, second)
            self.put(row.b, width, first)
        elif op == "call":
            self.push(row.next)
            if row.target in self.real:
                return row.target
            hook = self.calls.get(row.target)
            if not hook:
                raise Halt("unmodelled call to %#x at %#x" % (row.target, row.va))
            self.stub(hook)
            return self.pop()
        elif op == "jmp":
            return row.target
        elif op == "jmpi":
            target = self.get(row.a, 8)
            hook = self.slots.get(target)
            if hook:
                self.stub(hook)
                return self.pop()
            return target
        elif op == "pushm":
            self.push(self.get(row.a, 8))
        elif op == "pushi":
            self.push(row.a[1] & MASK[8])
        elif op == "btsr":
            bit = self.get(row.b, width) & (8 * width - 1)
            value = self.get(row.a, width)
            self.cf = bool(value >> bit & 1)
            self.put(row.a, width, value | 1 << bit)
        elif op == "btr":
            self.cf = bool(self.get(row.a, width) >> (self.get(row.b, width) & (8 * width - 1)) & 1)
        elif op == "movsx":
            value = self.get(row.b, row.cc)
            self.put(row.a, width, value - (1 << (8 * row.cc)) if value & SIGN[row.cc] else value)
        elif op == "ror":
            bits = 8 * width
            count = row.b[1] % bits
            value = self.get(row.a, width)
            self.put(row.a, width, (value >> count | value << (bits - count)) & MASK[width])
        elif op == "rol":
            bits = 8 * width
            count = row.b[1] % bits
            value = self.get(row.a, width)
            self.put(row.a, width, (value << count | value >> (bits - count)) & MASK[width])
        elif op == "bt":
            self.cf = bool(self.get(row.a, width) >> (row.b[1] & (8 * width - 1)) & 1)
        elif op == "calli":
            target = self.get(row.a, 8)
            if target in self.real:
                self.push(row.next)
                return target
            hook = self.slots.get(target)
            if not hook:
                raise Halt("unmodelled indirect call at %#x" % row.va)
            self.xmm_result = None
            self.stub(hook)
            if self.xmm_result is not None:
                self.xmm[0] = self.xmm_result
        elif op == "ret":
            return self.pop()
        elif op == "movzx":
            self.put(row.a, width, self.get(row.b, row.cc))
        elif op == "set":
            self.put(row.a, 1, int(self.condition(row.cc)))
        elif op == "cmov":
            value = self.get(row.b, width)
            self.put(row.a, width, value if self.condition(row.cc) else self.get(row.a, width))
        elif op in ("inc", "dec"):
            carry = self.cf
            value = self.add_sub(self.get(row.a, width), 1, 0, width, op == "dec")
            self.cf = carry
            self.put(row.a, width, value)
        elif op == "neg":
            value = self.add_sub(0, self.get(row.a, width), 0, width, True)
            self.put(row.a, width, value)
        elif op == "not":
            self.put(row.a, width, ~self.get(row.a, width))
        elif op == "imul1":
            left, right = self.regs[RAX], self.get(row.a, 8)
            left -= (left >> 63) << 64
            right -= (right >> 63) << 64
            product = left * right
            self.regs[RAX] = product & MASK[8]
            self.regs[RDX] = (product >> 64) & MASK[8]
            self.cf = self.of = not -(1 << 63) <= product < 1 << 63
        elif op == "mul":
            product = self.regs[RAX] * self.get(row.a, 8)
            self.regs[RAX] = product & MASK[8]
            self.regs[RDX] = product >> 64
            self.cf = self.of = self.regs[RDX] != 0
        elif op == "imul3":
            bits = 8 * width
            left, right = self.get(row.b, width), row.target & MASK[width]
            left -= (left >> (bits - 1)) << bits
            right -= (right >> (bits - 1)) << bits
            product = left * right
            self.cf = self.of = not -SIGN[width] <= product < SIGN[width]
            self.put(row.a, width, product)
        elif op in ("shl", "shr", "sar"):
            count = (self.regs[RCX] if row.b[0] == "r" else row.b[1]) & (63 if width == 8 else 31)
            value = self.get(row.a, width)
            if op == "shl":
                result = value << count
            elif op == "shr":
                result = value >> count
            else:
                result = (value - (1 << (8 * width)) if value & SIGN[width] else value) >> count
            if count:
                self.set_logic(result, width)
            self.put(row.a, width, result)
        elif op == "movx":
            if row.a[0] == "x":
                self.xmm[row.a[1]] = self.vector(row.b)
            elif row.b[0] == "x":
                self.memory.write(self.address(row.a), 16, self.xmm[row.b[1]])
            else:
                raise Halt("unmodelled vector move")
        elif op == "xorps":
            self.xmm[row.a[1]] ^= self.vector(row.b)
        elif op == "int3":
            raise Halt("int3 at %#x" % row.va)
        elif op == "cwde":
            self.regs[RAX] = ((self.regs[RAX] & 0xFFFF) ^ 0x8000) - 0x8000 & MASK[4]
        elif op == "cdqe":
            self.regs[RAX] = (self.regs[RAX] & MASK[4]) | (MASK[8] ^ MASK[4] if self.regs[RAX] & SIGN[4] else 0)
        elif op == "imul2":
            bits = 8 * width
            left, right = self.get(row.a, width), self.get(row.b, width)
            left -= (left >> (bits - 1)) << bits
            right -= (right >> (bits - 1)) << bits
            product = left * right
            self.cf = self.of = not -SIGN[width] <= product < SIGN[width]
            self.put(row.a, width, product)
        elif op == "nop":
            pass
        elif op == "bswap":
            self.put(row.a, width, int.from_bytes(self.get(row.a, width).to_bytes(width, "little"), "big"))
        elif op == "bsr":
            source = self.get(row.b, width)
            if source == 0:
                raise Halt("bsr of zero at %#x" % row.va)
            self.put(row.a, width, source.bit_length() - 1)
        elif op in ("shld", "shrd"):
            count = (row.target if row.target is not None else self.regs[RCX]) & 63
            high, low = self.get(row.a, 8), self.get(row.b, 8)
            if op == "shld":
                value = (high << count | low >> (64 - count)) if count else high
            else:
                value = (high >> count | low << (64 - count)) if count else high
            self.put(row.a, 8, value)
        elif op == "div":
            divisor = self.get(row.a, width)
            if divisor == 0:
                raise Halt("division by zero at %#x" % row.va)
            dividend = (self.regs[RDX] & MASK[width]) << (8 * width) | (self.regs[RAX] & MASK[width])
            quotient, remainder = divmod(dividend, divisor)
            if quotient > MASK[width]:
                raise Halt("division overflow at %#x" % row.va)
            self.regs[RAX], self.regs[RDX] = quotient, remainder
        elif op == "movsxd":
            value = self.get(row.b, 4)
            self.put(row.a, 8, value - (1 << 32) if value & SIGN[4] else value)
        else:
            self.step_vector(row, op)
        return row.next

    def low(self, operand):
        if operand[0] == "x":
            return self.xmm[operand[1]] & MASK[8]
        return self.memory.read(self.address(operand), 8)

    def set_low(self, register, bits):
        self.xmm[register] = (self.xmm[register] & ~MASK[8]) | bits

    def step_vector(self, row, op):
        if op == "movss":
            if row.a[0] == "x":
                self.xmm[row.a[1]] = self.memory.read(self.address(row.b), 4)
            else:
                self.memory.write(self.address(row.a), 4, self.xmm[row.b[1]] & MASK[4])
            return
        if op == "movsd":
            if row.a[0] == "x":
                if row.b[0] == "x":
                    self.set_low(row.a[1], self.low(row.b))
                else:
                    self.xmm[row.a[1]] = self.low(row.b)
            else:
                self.memory.write(self.address(row.a), 8, self.xmm[row.b[1]] & MASK[8])
        elif op == "movq":
            if row.a[0] == "x":
                self.xmm[row.a[1]] = self.get(row.b, 8)
            else:
                self.put(row.a, 8, self.xmm[row.b[1]] & MASK[8])
        elif op in ("addsd", "subsd", "mulsd", "divsd", "minsd", "maxsd"):
            left, right = to_float(self.low(row.a)), to_float(self.low(row.b))
            if op == "addsd":
                result = left + right
            elif op == "divsd":
                result = fdiv(left, right)
            elif op == "subsd":
                result = left - right
            elif op == "mulsd":
                result = left * right
            elif op == "minsd":
                result = left if left < right else right
            else:
                result = left if left > right else right
            self.set_low(row.a[1], to_bits(result))
        elif op == "ucomisd":
            left, right = to_float(self.low(row.a)), to_float(self.low(row.b))
            unordered = left != left or right != right
            self.of = self.sf = False
            self.pf = unordered
            self.zf = unordered or left == right
            self.cf = unordered or left < right
        elif op == "cvttsd2si":
            value = to_float(self.low(row.b))
            if value != value or not -9223372036854775808.0 <= value < 9223372036854775808.0:
                self.put(row.a, 8, 1 << 63)
            else:
                self.put(row.a, 8, int(value))
        elif op == "cvtsi2sd":
            value = self.get(row.b, 8)
            self.set_low(row.a[1], to_bits(float(value - (1 << 64) if value & SIGN[8] else value)))
        elif op == "andpd":
            self.xmm[row.a[1]] &= self.vector(row.b)
        elif op == "orpd":
            self.xmm[row.a[1]] |= self.vector(row.b)
        elif op == "subpd":
            right = self.vector(row.b)
            left = self.xmm[row.a[1]]
            low = to_float(left & MASK[8]) - to_float(right & MASK[8])
            high = to_float(left >> 64) - to_float(right >> 64)
            self.xmm[row.a[1]] = to_bits(low) | to_bits(high) << 64
        elif op == "unpckhpd":
            self.xmm[row.a[1]] = self.xmm[row.a[1]] >> 64 | (self.vector(row.b) >> 64) << 64
        elif op == "punpckldq":
            left, right = self.xmm[row.a[1]], self.vector(row.b)
            self.xmm[row.a[1]] = (left & MASK[4]) | (right & MASK[4]) << 32 | ((left >> 32) & MASK[4]) << 64 | ((right >> 32) & MASK[4]) << 96
        elif op == "movd":
            self.xmm[row.a[1]] = self.get(row.b, 4)
        elif op == "punpcklbw":
            left, right = self.xmm[row.a[1]].to_bytes(16, "little"), self.vector(row.b).to_bytes(16, "little")
            self.xmm[row.a[1]] = int.from_bytes(bytes(byte for pair in zip(left[:8], right[:8]) for byte in pair), "little")
        elif op == "pshuflw":
            source = self.vector(row.b)
            words = [(source >> (16 * index)) & 0xFFFF for index in range(4)]
            low = sum(words[(row.target >> (2 * index)) & 3] << (16 * index) for index in range(4))
            self.xmm[row.a[1]] = source >> 64 << 64 | low
        elif op == "pshufd":
            source = self.vector(row.b)
            words = [(source >> (32 * index)) & MASK[4] for index in range(4)]
            self.xmm[row.a[1]] = sum(words[(row.target >> (2 * index)) & 3] << (32 * index) for index in range(4))
        elif op in ("pcmpeqb", "pcmpeqd"):
            size = 1 if op == "pcmpeqb" else 4
            left, right = self.xmm[row.a[1]].to_bytes(16, "little"), self.vector(row.b).to_bytes(16, "little")
            lanes = (b"\xff" * size if left[at:at + size] == right[at:at + size] else bytes(size) for at in range(0, 16, size))
            self.xmm[row.a[1]] = int.from_bytes(b"".join(lanes), "little")
        elif op == "pmovmskb":
            data = self.xmm[row.b[1]].to_bytes(16, "little")
            self.put(row.a, 4, sum((byte >> 7) << index for index, byte in enumerate(data)))
        elif op == "tzcnt":
            source = self.get(row.b, row.width)
            count = (source & -source).bit_length() - 1 if source else row.width * 8
            self.cf = source == 0
            self.zf = count == 0
            self.put(row.a, row.width, count)
        elif op == "movhps":
            self.xmm[row.a[1]] = (self.xmm[row.a[1]] & MASK[8]) | self.get(row.b, 8) << 64
        elif op == "movlps":
            self.xmm[row.a[1]] = self.xmm[row.a[1]] >> 64 << 64 | self.get(row.b, 8)
        elif op == "movdout":
            self.put(row.a, 4, self.xmm[row.b[1]] & MASK[4])
        elif op == "punpcklqdq":
            self.xmm[row.a[1]] = (self.xmm[row.a[1]] & MASK[8]) | (self.vector(row.b) & MASK[8]) << 64
        elif op in ("pslld", "psrad"):
            value, lanes = self.xmm[row.a[1]], 0
            for shift in (0, 32, 64, 96):
                lane = (value >> shift) & MASK[4]
                if op == "pslld":
                    lane = (lane << row.b[1]) & MASK[4]
                else:
                    lane = ((lane - (1 << 32) if lane & SIGN[4] else lane) >> row.b[1]) & MASK[4]
                lanes |= lane << shift
            self.xmm[row.a[1]] = lanes
        elif op == "pandn":
            self.xmm[row.a[1]] = (self.xmm[row.a[1]] ^ ((1 << 128) - 1)) & self.vector(row.b)
        elif op == "psrlq":
            value = self.xmm[row.a[1]]
            self.xmm[row.a[1]] = ((value & MASK[8]) >> row.b[1]) | (((value >> 64) >> row.b[1]) << 64)
        elif op in ("addpd", "divpd"):
            left, right = self.xmm[row.a[1]], self.vector(row.b)
            lanes = []
            for shift in (0, 64):
                one, two = to_float((left >> shift) & MASK[8]), to_float((right >> shift) & MASK[8])
                lanes.append(to_bits(one + two if op == "addpd" else fdiv(one, two)))
            self.xmm[row.a[1]] = lanes[0] | lanes[1] << 64
        elif op == "shufpd":
            left, right = self.xmm[row.a[1]], self.vector(row.b)
            first = (left >> (64 * (row.target & 1))) & MASK[8]
            second = (right >> (64 * ((row.target >> 1) & 1))) & MASK[8]
            self.xmm[row.a[1]] = first | second << 64
        elif op == "cmppd":
            if row.target != 5:
                raise Halt("unmodelled compare predicate at %#x" % row.va)
            left, right = self.xmm[row.a[1]], self.vector(row.b)
            value = 0
            for shift in (0, 64):
                if not to_float((left >> shift) & MASK[8]) < to_float((right >> shift) & MASK[8]):
                    value |= MASK[8] << shift
            self.xmm[row.a[1]] = value
        elif op == "movmskpd":
            value = self.xmm[row.b[1]]
            self.put(row.a, 4, int(bool(value >> 63 & 1)) | int(bool(value >> 127 & 1)) << 1)
        else:
            raise Halt("unmodelled operation %s at %#x" % (op, row.va))

    def vector(self, operand):
        if operand[0] == "x":
            return self.xmm[operand[1]]
        return int.from_bytes(self.memory.bytes_at(self.address(operand), 16), "little")



# These three FDEs form the selected filter. Other functions are hook boundaries.
FILTER = 0x3BCFD70
PREDICATE = 0x33755F0
ITER = 0x330F550
BULK = 0x2FB8DD0
COMPARE = 0x576E488
ALLOC = 0x576DFD8
GROW = 0x32D6A00
LOG_MISSING = 0x3379490
DROP_STATUS = 0x3999770
ROOT_STATE = HEAP_BASE + 0x100
ROOT_ITER = HEAP_BASE + 0x1000
ROOT_POWER = HEAP_BASE + 0x2000
OUT = HEAP_BASE + 0x3000
OUTPUT_MAP = HEAP_BASE + 0x4000
BULK_ITER = HEAP_BASE + 0x5000
HEAP_NODES = HEAP_BASE + 0x10000
MARKER = 0x7700000000

# (key offset, value offset and stride, length, edges, parent, parent slot)
STAKE = (0xB8, 0, 16, 0x196, 0x198, 0xB0, 0x194)
PROFILE = (0x3D0, 0, 0x58, 0x4AE, 0x4B0, 0x3C8, 0x4AC)
POWER = (0x60, 8, 8, 0x13E, 0x140, 0, 0x13C)


def key(n):
    return n.to_bytes(20, 'big')


class SnapshotHarness:
    def __init__(self, image, patches=None):
        self.machine = Machine(image, patches)
        self.machine.real = frozenset((FILTER, PREDICATE, ITER, BULK))
        self.machine.calls = {GROW: self.grow, LOG_MISSING: self.log,
                              DROP_STATUS: self.drop}
        self.machine.memory.statics[COMPARE] = MARKER + COMPARE
        self.machine.memory.statics[ALLOC] = MARKER + ALLOC
        self.machine.slots = {MARKER + COMPARE: self.compare,
                              MARKER + ALLOC: self.allocate_hook}
        for slot, hook in ((0x576DFE0, self.copy_hook), (0x576E0E0, self.copy_hook),
                           (0x576E010, self.free_hook)):
            self.machine.memory.statics[slot] = MARKER + slot
            self.machine.slots[MARKER + slot] = hook
        self.at = HEAP_NODES
        self.logs = []
        self.drops = []
        self.grows = []
        self.requests = []
        self.frees = []
        self.copies = []

    def read(self, p, n=8):
        return self.machine.memory.read(p, n)

    def write(self, p, value, n=8):
        self.machine.memory.write(p, n, value)

    def alloc(self, size):
        if size < 0 or self.at + size > HEAP_BASE + HEAP_SIZE:
            raise Halt('fixture arena exhausted')
        p = self.at
        self.at += (size + 15) & ~15
        self.machine.memory.put_bytes(p, bytes(size))
        return p

    def allocate_hook(self, m):
        self.requests.append(m.regs[RDI])
        m.regs[RAX] = self.alloc(m.regs[RDI])

    def copy_hook(self, m):
        dst, src, n = (m.regs[r] for r in (RDI,RSI,RDX))
        if n > HEAP_SIZE or m.memory.locate(dst,n)[0] is None or m.memory.locate(src,n)[0] is None:
            raise Halt('copy outside fixture memory')
        m.memory.copy(dst,src,n)
        self.copies.append(n)
        m.regs[RAX] = dst

    def free_hook(self, m):
        ptr, size = m.regs[RDI],m.regs[RSI]
        if (size > HEAP_SIZE or m.memory.locate(ptr,size)[0] is None
                or ptr != self.read(OUT+8)):
            raise Halt('free outside owned fixture vector')
        self.frees.append(size)

    def compare(self, m):
        n = m.regs[RDX]
        if n != 20:
            raise Halt('unexpected comparison width')
        a = m.memory.bytes_at(m.regs[RDI], n)
        b = m.memory.bytes_at(m.regs[RSI], n)
        m.regs[RAX] = (a > b) - (a < b) & 0xffffffff

    def log(self, m):
        self.logs.append(self.read(m.regs[RDI], 2))

    def drop(self, m):
        self.drops.append(self.read(m.regs[RDI], 2))

    def grow(self, m):
        p = m.regs[RDI]
        cap, ptr, length = (self.read(p + i) for i in (0,8,16))
        if cap != length or m.regs[RSI] != length or m.regs[RDX] != 1 or m.regs[RCX] != 8 or m.regs[R8] != 32:
            raise Halt('unexpected growth arguments')
        newcap = max(4, 2 * cap)
        q = self.alloc(newcap * 32)
        m.memory.copy(q, ptr, length * 32)
        self.write(p, newcap); self.write(p + 8, q)
        self.grows.append((cap, newcap))

    def build(self, layout, entries, height, root=True):
        k, val, stride, length, edges, parent, pslot = layout
        node = self.alloc(edges + 12 * 8)
        if height:
            lower, upper = 5, 11
            for _ in range(height - 1):
                lower, upper = 5 + 6 * lower, 11 + 12 * upper
            min_children = 2 if root else 6
            choices = [n for n in range(min_children, 13)
                       if n * lower + n - 1 <= len(entries) <= n * upper + n - 1]
            if not choices:
                raise Halt('invalid fixture tree size')
            branches = choices[0]
            child_total = len(entries) - branches + 1
            left, extra = divmod(child_total, branches)
            children, rows, pos = [], [], 0
            for i in range(branches):
                n = left + (i < extra)
                children.append(self.build(layout, entries[pos:pos+n], height-1, root=False)); pos += n
                if i + 1 < branches:
                    rows.append(entries[pos]); pos += 1
            for i, child in enumerate(children):
                self.write(node + edges + i*8, child)
                self.write(child + parent, node)
                self.write(child + pslot, i, 2)
        else:
            rows = entries
        if len(rows) > 11:
            raise Halt('fixture node full')
        self.write(node + length, len(rows), 2)
        for i, (name, value) in enumerate(rows):
            self.machine.memory.put_bytes(node + k + i*20, name)
            self.machine.memory.put_bytes(node + val + i*stride, value)
        return node

    def holder(self, p, layout, entries):
        entries = sorted(entries)
        if (any(len(k) != 20 or len(v) != layout[2] for k,v in entries)
                or len({k for k,_ in entries}) != len(entries)):
            raise Halt('invalid fixture entries')
        if not entries:
            self.write(p, 0); self.write(p+8, 0); self.write(p+16, 0)
            return
        height, limit = 0, 11
        while len(entries) > limit:
            height += 1; limit = 12*limit + 11
        root = self.build(layout, entries, height)
        self.write(p, root); self.write(p+8, height); self.write(p+16, len(entries))

    def check_tree(self, holder, layout, entries):
        k, val, stride, length, edges, parent, pslot = layout
        root, height, count = (self.read(holder+i) for i in (0,8,16))
        if not root:
            if count or entries:
                raise Halt('empty root disagrees with expected entries')
            return
        seen, rows = set(), []
        def walk(node, level, parent_node, index):
            if node in seen or not HEAP_NODES <= node or node + edges + (96 if level else 0) > self.at:
                raise Halt('bad fixture node')
            seen.add(node)
            if self.read(node+parent) != parent_node or (parent_node and self.read(node+pslot,2) != index):
                raise Halt('bad fixture parent')
            n = self.read(node+length,2)
            if n > 11 or (parent_node and n < 5) or (not parent_node and n == 0):
                raise Halt('bad fixture occupancy')
            for i in range(n):
                if level:
                    walk(self.read(node+edges+i*8),level-1,node,i)
                rows.append((self.machine.memory.bytes_at(node+k+i*20,20),
                             self.machine.memory.bytes_at(node+val+i*stride,stride)))
            if level:
                walk(self.read(node+edges+n*8),level-1,node,n)
        walk(root,height,0,0)
        if rows != sorted(entries) or count != len(rows):
            raise Halt('bad fixture ordering or count')
        return [(int.from_bytes(k,'big'),int.from_bytes(v,'little')) for k,v in rows]

    def bulk(self, expected, limit):
        count = self.read(OUT+16)
        if not count:
            return [], None
        vector = self.read(OUT+8)
        capacity = self.read(OUT)
        # The excluded incoming caller creates one empty leaf and an owning
        # iterator. Sorted, unique filter rows require no fixture-side reorder.
        self.write(OUTPUT_MAP,self.alloc(0x140))
        self.write(OUTPUT_MAP+8,0)
        self.write(OUTPUT_MAP+16,0)
        for off,value in ((0,2),(0x28,vector),(0x30,vector),
                          (0x38,capacity),(0x40,vector+count*32)):
            self.write(BULK_ITER+off,value)
        self.machine.step_limit = limit
        self.machine.run(BULK,{RDI:OUTPUT_MAP, RSI:BULK_ITER, RDX:OUTPUT_MAP+16})
        entries = [(key(k),struct.pack('<Q',v)) for k,v in expected]
        rows = self.check_tree(OUTPUT_MAP,POWER,entries)
        if hasattr(self,'input_snapshot'):
            state,power,n,nodes = self.input_snapshot
            self.unchanged = (self.unchanged and
                self.machine.memory.bytes_at(ROOT_STATE,0x300) == state and
                self.machine.memory.bytes_at(ROOT_POWER,24) == power and
                self.machine.memory.bytes_at(HEAP_NODES,n) == nodes)
        return rows,self.read(OUTPUT_MAP+8)

    def run(self, stakes, profiles, power):
        # Distinct input records carry effective and target values; the returned
        # value must come from the executable, not from this fixture builder.
        srows = [(key(k), struct.pack('<QQ', effective, target))
                 for k, effective, target in stakes]
        prows = []
        for validator, signer in profiles:
            v = bytearray(0x58); v[0x40:0x54] = key(signer)
            prows.append((key(validator), bytes(v)))
        self.holder(ROOT_STATE + 0x10, STAKE, srows)
        self.holder(ROOT_STATE + 0x150, PROFILE, prows)
        power_rows = [(key(k), struct.pack('<Q', value)) for k, value in power]
        self.holder(ROOT_POWER, POWER, power_rows)
        self.check_tree(ROOT_STATE + 0x10, STAKE, srows)
        self.check_tree(ROOT_STATE + 0x150, PROFILE, prows)
        self.check_tree(ROOT_POWER, POWER, power_rows)
        root = self.read(ROOT_STATE + 0x10)
        height = self.read(ROOT_STATE + 0x18)
        count = self.read(ROOT_STATE + 0x20)
        for off, value in ((0, int(bool(root))), (8,0), (0x10,root), (0x18,height),
                           (0x20,int(bool(root))), (0x28,0), (0x30,root),
                           (0x38,height), (0x40,count), (0x48,ROOT_STATE), (0x50,ROOT_POWER)):
            self.write(ROOT_ITER + off, value)
        state_before = self.machine.memory.bytes_at(ROOT_STATE, 0x300)
        power_before = self.machine.memory.bytes_at(ROOT_POWER, 24)
        nodes_size = self.at - HEAP_NODES
        nodes_before = self.machine.memory.bytes_at(HEAP_NODES, nodes_size)
        self.input_snapshot = (state_before,power_before,nodes_size,nodes_before)
        self.machine.run(FILTER, {RDI: OUT, RSI: ROOT_ITER})
        # Iterator and output are intentionally changed; compare only the state,
        # power holder and immutable synthetic node arena.
        self.unchanged = (self.machine.memory.bytes_at(ROOT_STATE, 0x300) == state_before
                          and self.machine.memory.bytes_at(ROOT_POWER, 24) == power_before
                          and self.machine.memory.bytes_at(HEAP_NODES, nodes_size) == nodes_before)
        cap, ptr, length = (self.read(OUT + off) for off in (0,8,16))
        if length > cap or length > len(stakes):
            raise Halt('invalid output vector')
        result = []
        for i in range(length):
            at = ptr + i*32
            result.append((int.from_bytes(self.machine.memory.bytes_at(at,20),'big'), self.read(at+24)))
        return result

# Each anchor is an instruction-aligned byte pattern, independently checked
# before constructing the records or interpreting test cases.
PINS = (
    ('first_load_second_word', 0x3BCFDC0, '488b4a08'),
    ('first_predicate_call', 0x3BCFDE7, 'e804587aff'),
    ('first_predicate_accept', 0x3BCFDEE, '7529'),
    ('following_load_second_word', 0x3BD00DB, '488b4608'),
    ('following_profile_root', 0x3BD00F8, '488b8850010000'),
    ('following_missing_profile', 0x3BD0102, '0f84b8010000'),
    ('following_power_cmp', 0x3BD0266, 'ff151ce2b901'),
    ('following_accept', 0x3BD028C, '0f847e010000'),
    ('following_missing_log', 0x3BD02D2, 'e8b9917aff'),
    ('predicate_profile_root', 0x3375607, '4c8ba050010000'),
    ('predicate_profile_missing', 0x3375611, '0f8471010000'),
    ('predicate_signer_copy', 0x33756D7, '8b4510'),
    ('predicate_power_root', 0x33756EC, '4c8b20'),
    ('predicate_power_accept', 0x33757A3, 'b001'),
    ('iterator_value_pointer', 0x330F70F, '48c1e204'),
    ('bulk_initial_height_branch', 0x2FB8DF1, '0f84c8000000'),
    ('bulk_alt_height_branch', 0x2FB8DFE, '0f845c080000'),
    ('bulk_alt_height_compare', 0x2FB9663, '4883f908'),
    ('bulk_alt_height_jump', 0x2FB9667, '0f83d3f7ffff'),
    ('bulk_alt_zero_rejoin', 0x2FB966D, 'e94df8ffff'),
    ('bulk_node_length_write', 0x2FB8F03, '6641898f3e010000'),
    ('bulk_value_write', 0x2FB8F2B, '4d896cc708'),
    ('bulk_total_increment', 0x2FB8F30, '48ff4500'),
    ('bulk_input_tag', 0x2FB8F43, '4883fa02'),
    ('bulk_vector_stride', 0x2FB8F52, '488d5120'),
    ('bulk_key_dword_compare', 0x2FB8FF4, '660f74d1'),
    ('bulk_key_vector_compare', 0x2FB8FF8, '660f74442410'),
    ('bulk_key_compare_join', 0x2FB8FFE, '660fdbc2'),
    ('bulk_key_mask', 0x2FB9002, '660fd7f8'),
    ('bulk_key_all_equal', 0x2FB900B, '81ffffff0000'),
    ('bulk_leaf_full', 0x2FB90F7, '4883f80b'),
)


# Incoming setup sites are contextual byte anchors only. Their enclosing
# function is outside this packet; no coverage claim is made for it.
CONTEXT_PINS = (
    ('state_argument',0x336D5BE,'4989d6'),
    ('power_output_address',0x336D5C6,'4c8dbc2490000000'),
    ('power_output_argument',0x336D5CE,'4c89ff'),
    ('power_stakes_argument',0x336D5D1,'4c89f6'),
    ('power_state_argument',0x336D5D4,'4c89f1'),
    ('power_slot_call',0x336D5D7,'ff154b7b4002'),
    ('stake_root',0x336D5DD,'498b4610'),
    ('stake_height',0x336D5E1,'498b4e18'),
    ('stake_length',0x336D5F2,'498b7620'),
    ('iterator_root',0x336D604,'4889442448'),
    ('iterator_height',0x336D609,'48894c2450'),
    ('iterator_length',0x336D626,'4889742478'),
    ('iterator_state_pointer',0x336D62B,'4c89b42480000000'),
    ('iterator_power_pointer',0x336D633,'4c89bc2488000000'),
    ('filter_output_argument',0x336D63B,'488d7c2420'),
    ('filter_iterator_argument',0x336D640,'488d742438'),
    ('filter_call',0x336D645,'e826278600'),
    ('vector_length',0x336D64A,'4c8b7c2430'),
    ('empty_vector_test',0x336D64F,'4d85ff'),
    ('empty_vector_branch',0x336D652,'0f84a2000000'),
    ('initial_leaf_size',0x336D676,'bf40010000'),
    ('initial_leaf_parent',0x336D68A,'48c70000000000'),
    ('initial_leaf_length',0x336D691,'66c7803e0100000000'),
    ('output_root',0x336D69A,'4889442408'),
    ('output_count',0x336D6A8,'48c744241800000000'),
    ('vector_byte_length',0x336D6B1,'49c1e705'),
    ('bulk_iterator_tag',0x336D6B8,'48c744243802000000'),
    ('bulk_input_start',0x336D6C1,'4c89742460'),
    ('bulk_input_cursor',0x336D6C6,'4c89742468'),
    ('bulk_input_capacity',0x336D6CB,'4c89642470'),
    ('bulk_input_end',0x336D6D0,'4c897c2478'),
    ('bulk_output_argument',0x336D6D5,'488d7c2408'),
    ('bulk_iterator_argument',0x336D6DA,'488d742438'),
    ('bulk_count_argument',0x336D6DF,'488d542418'),
    ('bulk_call',0x336D6E4,'e8e7b6c4ff'),
)


def file_bytes(image, va, size, executable=False):
    if size < 0:
        raise EvidenceError('negative size')
    matches = [sec for sec in image.mapped if sec['address'] <= va
               and va + size <= sec['address'] + sec['size']
               and (not executable or sec['flags'] & 4)]
    if len(matches) != 1:
        raise EvidenceError('address range is not uniquely file backed: %#x+%#x' % (va,size))
    sec = matches[0]
    at = sec['offset'] + va - sec['address']
    return bytes(image.blob[at:at+size])


def checked_records(image):
    table = {}
    expected = {FILTER: 0x3BD0521, PREDICATE: 0x33757B7, ITER: 0x330F758, BULK: 0x2FB975B}
    for start, end in expected.items():
        got = image.exact_fde(start)
        if got != (start,end):
            raise EvidenceError('unexpected FDE extent at %#x' % start)
        file_bytes(image, start, end-start, executable=True)
        table[start] = decode_range(image,start,end)
    boundaries = {row.va for rows in table.values() for row in rows}
    for name, va, pattern in PINS:
        if va not in boundaries or file_bytes(image, va, len(bytes.fromhex(pattern)), True).hex() != pattern:
            raise EvidenceError('instruction anchor mismatch: ' + name)
    for name, va, pattern in CONTEXT_PINS:
        raw = file_bytes(image,va,len(bytes.fromhex(pattern)),True)
        if raw.hex() != pattern:
            raise EvidenceError('context anchor mismatch: ' + name)
    call = decode(lambda at,n:file_bytes(image,at,n,True),0x336D645)
    if call.op != 'call' or call.target != FILTER:
        raise EvidenceError('incoming call target changed')
    bulk_call = decode(lambda at,n:file_bytes(image,at,n,True),0x336D6E4)
    if bulk_call.op != 'call' or bulk_call.target != BULK:
        raise EvidenceError('incoming bulk call target changed')
    return table


def rule(stakes, profiles, power):
    profile = dict(profiles)
    active = dict(power)
    result, logs, drops = [], [], []
    for validator, effective, target in sorted(stakes):
        if validator not in profile:
            logs.append(0x91)
        else:
            drops.append(0x91)
            if profile[validator] in active:
                result.append((validator,target))
    return result, logs, drops


def case(name, stakes, profiles, power):
    return {'name': name, 'stakes': stakes, 'profiles': profiles, 'power': power}


def cases():
    yield case('empty', [], [], [])
    yield case('one-target-zero', [(1,100,0)], [(1,101)], [(101,0)])
    yield case('one-profile-missing', [(1,100,200)], [], [(101,3)])
    yield case('one-signer-missing', [(1,100,200)], [(1,101)], [])
    yield case('duplicate-signer', [(1,111,999),(2,222,888)], [(1,101),(2,101)], [(101,0)])
    yield case('target-u64-max', [(1,0,(1<<64)-1)], [(1,101)], [(101,(1<<64)-1)])
    for n in (4,5,8,11,12,21,60,143,144):
        yield case('tree-%03d'%n, [(i, 1000+i, 2000+i) for i in range(n)],
                   [(i,300+i) for i in range(n)], [(300+i,9000+i) for i in range(n)])
    # Put the first accepted element at different positions in a height-two
    # tree, including an empty result after walking the entire iterator.
    for label, selected in (('first',(0,)),('middle',(71,)),
                            ('cross',(71,143)),('last',(143,)),('none',())):
        yield case('deep-'+label, [(i,1000+i,2000+i) for i in range(144)],
                   [(i,300+i) for i in range(144)], [(300+i,0) for i in selected])
    # Every combination of absent profile, absent signer and present signer for
    # four ordered rows exercises both the first predicate and the inline loop.
    for modes in itertools.product(range(3), repeat=4):
        stakes = [(i,100+i,200+i) for i in range(4)]
        profiles = [(i,1000+i) for i, mode in enumerate(modes) if mode]
        power = [(1000+i,0 if i%2 else 700+i) for i,mode in enumerate(modes) if mode==2]
        yield case('matrix-' + ''.join(map(str,modes)), stakes, profiles, power)
    # A pair that differs only in one byte forces each byte of the 20-byte key
    # to matter to both tree lookups; neither key is a prefix of the other.
    for i in range(20):
        bit = 1 << ((19-i)*8)
        yield case('key-byte-%02d'%i, [(1,4,11),(2,5,22)], [(1,0),(2,bit)], [(bit,1)])
    for i in range(20):
        other = 1 << ((19-i)*8)
        yield case('validator-byte-%02d'%i, [(0,4,11),(other,5,22)], [(other,77)], [(77,1)])
    # Repeat byte-wide controls after a first accepted element so the separately
    # inlined continuation is tested as well as the initial predicate.
    for i in range(20):
        other = 1 << ((19-i)*8)
        yield case('inline-signer-byte-%02d'%i,
                   [(0,1,10),(1,2,20),(2,3,30)],
                   [(0,77),(1,0),(2,other)], [(77,1),(other,1)])
        yield case('inline-validator-byte-%02d'%i,
                   [(0,1,10),(1,2,20),(1+other,3,30)],
                   [(0,77),(1+other,78)], [(77,1),(78,1)])
    # Fixed arithmetic cases, with a mix of sparse and shared signer maps.
    state = 0x12345678
    for c in range(128):
        stakes,profiles,power = [],[],{}
        for i in range(8):
            state = (1664525*state+1013904223) & 0xffffffff
            stakes.append((i, state, state ^ 0xFFFFFFFF))
            if state & 8:
                signer = 100+(state>>8)%7
                profiles.append((i,signer))
                if state & 16:
                    power[signer] = state ^ 0x12345678
        yield case('fixed-%03d'%c, stakes, profiles, sorted(power.items()))


def evaluate(image, item, patches=None, limit=120000):
    harness = SnapshotHarness(image,patches)
    harness.machine.step_limit = limit
    actual = harness.run(item['stakes'],item['profiles'],item['power'])
    requests = list(harness.requests)
    mapped, height = harness.bulk(actual,limit)
    return {'rows':actual, 'mapped_rows':mapped, 'map_height':height,
            'logs':harness.logs, 'drops':harness.drops,
            'unchanged':harness.unchanged, 'grows':harness.grows,
            'allocation_requests':requests, 'bulk_allocations':harness.requests[len(requests):],
            'bulk_frees':harness.frees, 'bulk_copies':harness.copies,
            'seen':harness.machine.seen, 'branches':harness.machine.branch_edges,
            'steps':harness.machine.steps}


def assert_rule(item, outcome):
    rows, logs, drops = rule(item['stakes'], item['profiles'], item['power'])
    if (outcome['rows'],outcome['mapped_rows'],outcome['logs'],outcome['drops'],outcome['unchanged']) != (rows,rows,logs,drops,True):
        raise EvidenceError('oracle mismatch for ' + item['name'])
    cap = outcome['grows'][-1][1] if outcome['grows'] else 4
    if outcome['allocation_requests'] != ([128] if rows else []) or outcome['bulk_frees'] != ([cap*32] if rows else []):
        raise EvidenceError('allocation or owned-vector hook mismatch for ' + item['name'])


def bulk_cases():
    yield {'name':'duplicates-two','input':[(1,11),(1,22)]}
    yield {'name':'duplicates-three','input':[(1,11),(1,22),(1,33),(2,44)]}
    yield {'name':'duplicates-middle','input':[(1,11),(2,22),(2,44),(3,33)]}
    yield {'name':'duplicates-maximum','input':[(1,0),(1,(1<<64)-1)]}
    for pos in range(13):
        rows = [(i,100+i) for i in range(13)]
        rows.insert(pos+1,(pos,900+pos))
        yield {'name':'duplicate-position-%02d'%pos,'input':rows}
    for i in range(20):
        other = 1 << ((19-i)*8)
        yield {'name':'bulk-key-byte-%02d'%i,'input':[(0,9),(other,10),(other,11)]}


def evaluate_bulk(image, item, patches=None, limit=120000):
    rows = item['input']
    if not rows or [k for k,_ in rows] != sorted(k for k,_ in rows):
        raise EvidenceError('bulk controls require nonempty sorted rows')
    harness = SnapshotHarness(image,patches)
    vector = harness.alloc(len(rows)*32)
    for i,(name,value) in enumerate(rows):
        harness.machine.memory.put_bytes(vector+i*32,key(name)+bytes(4)+struct.pack('<Q',value))
    harness.write(OUT,len(rows)); harness.write(OUT+8,vector); harness.write(OUT+16,len(rows))
    expected = sorted(dict(rows).items())
    mapped,height = harness.bulk(expected,limit)
    return {'rows':mapped,'mapped_rows':mapped,'map_height':height,
            'logs':[],'drops':[],'unchanged':True,'grows':[],
            'allocation_requests':[], 'bulk_allocations':harness.requests,
            'bulk_frees':harness.frees,'bulk_copies':harness.copies,
            'seen':harness.machine.seen,'branches':harness.machine.branch_edges,
            'steps':harness.machine.steps}


def evaluate_any(image, item, patches=None, limit=120000):
    return evaluate_bulk(image,item,patches,limit) if 'input' in item else evaluate(image,item,patches,limit)


def json_text(value):
    return json.dumps(value, sort_keys=True, separators=(',',':'))


def write_tsv(out, name, fields, rows):
    with (out/name).open('w',encoding='utf-8',newline='') as fp:
        writer = csv.writer(fp, delimiter='\t', lineterminator='\n')
        writer.writerow(fields); writer.writerows(rows)


def symbol_name(image, index):
    symbols, strings = image.named['.dynsym'], image.named['.dynstr']
    if symbols['type'] != 11 or strings['type'] != 3 or index < 0 or (index+1)*24 > symbols['size']:
        raise EvidenceError('invalid dynamic symbol index')
    at = symbols['offset'] + index*24
    name_at = struct.unpack_from('<I',image.blob,at)[0]
    if name_at >= strings['size']:
        raise EvidenceError('invalid dynamic symbol name')
    begin = strings['offset'] + name_at
    end = image.blob.find(b'\0',begin,strings['offset']+strings['size'])
    if end < 0:
        raise EvidenceError('unterminated dynamic symbol')
    return bytes(image.blob[begin:end]).decode('ascii')


def make_output(image, out):
    table = checked_records(image)
    all_cases = list(cases())
    seen, edges, runs = set(), {}, []
    for item in all_cases:
        outcome = evaluate(image,item)
        assert_rule(item,outcome)
        seen.update(outcome['seen'])
        for addr, values in outcome['branches'].items():
            edges.setdefault(addr,set()).update(values)
        runs.append((item,outcome))
    bulk_runs = []
    for item in bulk_cases():
        outcome = evaluate_bulk(image,item)
        if outcome['mapped_rows'] != sorted(dict(item['input']).items()) or outcome['bulk_frees'] != [len(item['input'])*32]:
            raise EvidenceError('bulk oracle mismatch for ' + item['name'])
        seen.update(outcome['seen'])
        for addr, values in outcome['branches'].items():
            edges.setdefault(addr,set()).update(values)
        bulk_runs.append((item,outcome))
    # Actual selection and status rows are reported; each result was compared
    # with an independently stated rule before this output is written.
    out.mkdir(parents=True, exist_ok=True)
    case_rows = []
    for item, result in runs:
        case_rows.append((item['name'], json_text(item['stakes']), json_text(item['profiles']),
                          json_text(item['power']), json_text(result['rows']), json_text(result['mapped_rows']),
                          '' if result['map_height'] is None else result['map_height'], json_text(result['logs']), json_text(result['drops']),
                          json_text(result['allocation_requests']), json_text(result['grows']),
                          json_text(result['bulk_allocations']), json_text(result['bulk_frees']),
                          json_text(result['bulk_copies']), int(result['unchanged']), result['steps']))
    write_tsv(out,'cases.tsv',('name','stakes_effective_target','profiles','signer_power',
                               'selected_target_rows','stored_target_rows','stored_tree_height','missing_profile_statuses',
                               'dropped_statuses','filter_allocation_requests','filter_hook_growth',
                               'bulk_allocation_requests','bulk_free_sizes','bulk_copy_sizes',
                               'input_unchanged','steps'),case_rows)
    write_tsv(out,'bulk-cases.tsv',('name','sorted_input','stored_rows','tree_height',
                                   'allocations','frees','copies','steps'),
              [(item['name'],json_text(item['input']),json_text(r['mapped_rows']),r['map_height'],
                json_text(r['bulk_allocations']),json_text(r['bulk_frees']),json_text(r['bulk_copies']),r['steps'])
               for item,r in bulk_runs])
    instructions, functions, branches, calls = [], [], [], []
    rel = {loc:(typ,add,sym) for loc,typ,add,sym in image.relocations()}
    power_relocation = rel.get(0x5775128)
    if not power_relocation or power_relocation[:2] != (8,0x3C10FA0):
        raise EvidenceError('incoming power slot relocation changed')
    compare_relocation = rel.get(COMPARE)
    if not compare_relocation or compare_relocation[0] != 6 or symbol_name(image,compare_relocation[2]) != 'memcmp':
        raise EvidenceError('comparator relocation does not resolve to memcmp')
    for start in (FILTER,PREDICATE,ITER,BULK):
        rows = table[start]; end=image.exact_fde(start)[1]
        raw = file_bytes(image,start,end-start,True)
        functions.append((hex(start),hex(end),hex(image.offset(start)),len(raw),
                          hashlib.sha256(raw).hexdigest(),len(rows),
                          sum(r.va in seen for r in rows)))
        for r in rows:
            instructions.append((hex(start),hex(r.va),r.size,r.data.hex(),r.op,
                                 '' if r.target is None else hex(r.target),int(r.va in seen)))
            if r.op=='jcc':
                branches.append((hex(start),hex(r.va),r.data.hex(),hex(r.target),
                                 int(False in edges.get(r.va,())), int(True in edges.get(r.va,()))))
            if r.op in ('call','calli'):
                slot = r.a[4] if r.op == 'calli' and r.a and r.a[0]=='m' and r.a[1] is None else None
                rr = rel.get(slot) if slot is not None else None
                calls.append((hex(start),hex(r.va),r.data.hex(),r.op,
                              hex(r.target) if r.target is not None else '',
                              hex(slot) if slot is not None else '',
                              str(rr[0]) if rr else '',hex(rr[1]) if rr and rr[1]>=0 else '',
                              str(rr[2]) if rr else '', symbol_name(image,rr[2]) if rr and rr[2] else '',int(r.va in seen)))
    write_tsv(out,'functions.tsv',('start_va','end_va','file_offset','bytes','sha256','instructions','reached'),functions)
    write_tsv(out,'instructions.tsv',('function','va','size','bytes','operation','direct_target','reached'),instructions)
    write_tsv(out,'branches.tsv',('function','va','bytes','taken_target','fallthrough_reached','taken_reached'),branches)
    write_tsv(out,'calls.tsv',('function','va','bytes','kind','direct_target','slot_va',
                               'relocation_type','addend','symbol_index','symbol','reached'),calls)
    write_tsv(out,'anchors.tsv',('name','va','bytes'),[(n,hex(a),file_bytes(image,a,len(bytes.fromhex(b)),True).hex()) for n,a,b in PINS])
    # Flip each reached conditional's sense. Small, already passing witnesses
    # are selected by observed branch edge; timeouts and faults are recorded
    # separately from wrong results, and equal outcomes are not called proof.
    mutant_rows = []
    for start in (FILTER,PREDICATE,ITER,BULK):
        for row in table[start]:
            if row.op != 'jcc':
                continue
            offset = 1 if row.data[0] == 0x0f else 0
            if not (0x70 <= row.data[offset] <= 0x7f or 0x80 <= row.data[offset] <= 0x8f):
                raise EvidenceError('unexpected conditional encoding')
            patch_at = row.va + offset
            patched = row.data[offset] ^ 1
            witnesses = [(item,result) for item,result in (runs + bulk_runs)
                         if row.va in result['seen'] and result['steps'] <= 85000]
            selected = []
            for edge in (False, True):
                candidate = next(((item,result) for item,result in witnesses
                                  if edge in result['branches'].get(row.va,())),None)
                if candidate and candidate not in selected:
                    selected.append(candidate)
            for candidate in witnesses:
                if len(selected)>=6:
                    break
                if candidate not in selected:
                    selected.append(candidate)
            verdict, detail, tested = ('unprobed','',0)
            if selected:
                verdict = 'survived'
                for item, baseline in selected:
                    tested += 1
                    try:
                        actual = evaluate_any(image,item,{patch_at:patched},limit=max(25000,2*baseline['steps']))
                    except (Halt, EvidenceError, IndexError, ValueError, KeyError, OverflowError, RecursionError, struct.error) as exc:
                        verdict, detail = 'fault', type(exc).__name__
                        break
                    observable = ('rows','mapped_rows','logs','drops','unchanged','grows',
                                  'allocation_requests','bulk_allocations','bulk_frees','bulk_copies')
                    observed = tuple(actual[k] for k in observable)
                    expected = tuple(baseline[k] for k in observable)
                    if observed != expected:
                        verdict, detail = 'difference', item['name']
                        break
            mutant_rows.append((hex(start),hex(row.va),row.data.hex(),hex(patch_at),
                                '%02x'%patched, tested,verdict,detail))
    write_tsv(out,'branch-mutations.tsv',('function','branch_va','original','patched_va','patched_byte',
                                          'cases_tried','verdict','first_difference_or_fault'),mutant_rows)
    write_tsv(out,'incoming-context.tsv',('name','va','bytes'),
              [(name,hex(va),file_bytes(image,va,len(bytes.fromhex(pattern)),True).hex())
               for name,va,pattern in CONTEXT_PINS])
    write_tsv(out,'incoming-slot.tsv',('slot_va','relocation_type','target_va'),
              [(hex(0x5775128), power_relocation[0], hex(power_relocation[1]))])
    table_va, tag = 0x59A8D0, 0x91
    relative = struct.unpack('<i',file_bytes(image,table_va+4*tag,4))[0]
    arm = table_va + relative
    arm_bytes = file_bytes(image,arm,30,True)
    at = arm_bytes.find(bytes.fromhex('488d35'))
    if at < 0 or arm_bytes[at+7] != 0xba:
        raise EvidenceError('unexpected status text pattern')
    text_va = arm+at+7+struct.unpack_from('<i',arm_bytes,at+3)[0]
    text_len = struct.unpack_from('<I',arm_bytes,at+8)[0]
    status_text = file_bytes(image,text_va,text_len).decode('ascii')
    write_tsv(out,'status.tsv',('tag','table_va','relative_displacement','arm_va','arm_bytes','text_va','length','text'),
              [(hex(tag),hex(table_va),relative,hex(arm),arm_bytes.hex(),hex(text_va),text_len,status_text)])
    summary = {'target_sha256':SHA256, 'cases':len(runs), 'bulk_controls':len(bulk_runs),
               'functions':len(functions), 'instructions':len(instructions),
               'instructions_reached':sum(int(r[-1]) for r in instructions),
               'conditional_branches':len(branches),
               'conditional_with_both_edges':sum(int(r[-1]) and int(r[-2]) for r in branches),
               'conditional_unreached':sum(not int(r[-1]) and not int(r[-2]) for r in branches),
               'mutation_differences':sum(r[-2]=='difference' for r in mutant_rows),
               'mutation_faults':sum(r[-2]=='fault' for r in mutant_rows),
               'mutation_survivors':sum(r[-2]=='survived' for r in mutant_rows),
               'mutation_unprobed':sum(r[-2]=='unprobed' for r in mutant_rows),
               'models_agree':True,
               'limitations':'Synthetic B-trees and hook boundaries; no captured code is executed.'}
    (out/'summary.json').write_text(json.dumps(summary,indent=2,sort_keys=True)+'\n',encoding='utf-8')
    return summary


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out',type=pathlib.Path,required=True)
    args = parser.parse_args(argv)
    image = load_image()
    make_output(image,args.out)


if __name__ == '__main__':
    main()
