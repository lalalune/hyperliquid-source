#!/usr/bin/env python3
"""Recover the validator-state lookup and split insertion from node 94.

The byte decoder and interpreter are adapted from staking_stake_accounting.py.
They read the authenticated ELF as data; no target process is launched.
"""
# MIT License
# 
# Copyright (c) 2026 Hyperliquid Source contributors
# 
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
# 
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
# 
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

import argparse
import bisect
import hashlib
import json
import pathlib
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
            ends[row["start"]] = max(ends.get(row["start"], 0), row["end"])
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
            pc = self.step(row)
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



# These are fixed x86-64 byte signatures, not text produced by a disassembler.
INSERT = 0x2F98850
LOOKUP = 0x33ADDE0
FUNCTIONS = (
    ('insert', INSERT, 0x2F99816, 'a7197d7923701c36fe1781eee590192ac2021d98d7e3b3d7d16ba060d28f6b71'),
    ('lookup', LOOKUP, 0x33ADEBA, 'ec40682ba3318ddab7590a46fab361b9c9b4a0d150acfe583ca5de598770fb95'),
)
PINS = (
    ('state_map_register', 0x3995825, '498db778020000'),
    ('registration_flag_zero', 0x3995838, 'c684249800000000'),
    ('registration_adapter_call', 0x399586F, 'e8dcc2a0ff'),
    ('state_map_change', 0x3995BB6, '488dbb78020000'),
    ('change_lookup_call', 0x3995BC0, 'e81b82a1ff'),
    ('adapter_insert_call', 0x33A1D11, 'e83a6bbfff'),
    ('adapter_count_increment', 0x33A1D9C, '49ff4610'),
    ('leaf_capacity', 0x2F98872, '4883fb0b732d'),
    ('split_six', 0x2F989C1, '4883fb067525'),
    ('lookup_node_len', 0x33ADE10, '0fb7881a020000'),
)
SLOT_ALLOC, SLOT_MEMCPY, SLOT_FREE = 0x576DFD8, 0x576DFE0, 0x576E010
SLOT_MEMMOVE, SLOT_MEMCMP = 0x576E0E0, 0x576E488
STOP_SLOTS = (0x576E470, 0x576E108, 0x576E020, 0x576E2E0)
MARK_BASE = 0x7700000000
ARENA = HEAP_BASE + 0x10000
ARENA_END = HEAP_BASE + 0x3F0000


def read_bytes(image, va, size):
    if size < 0:
        raise EvidenceError('negative byte count')
    matches = [sec for sec in image.sections if sec['type'] != 8 and sec['size']
               and sec['address'] <= va and va + size <= sec['address'] + sec['size']]
    if len(matches) != 1:
        raise EvidenceError('range does not have exactly one file-backed section')
    sec = matches[0]
    pos = sec['offset'] + va - sec['address']
    return bytes(image.blob[pos:pos + size])


def check_image(image):
    for name, start, end, digest in FUNCTIONS:
        if image.exact_fde(start) != (start, end):
            raise EvidenceError('unexpected FDE bounds: ' + name)
        raw = read_bytes(image, start, end - start)
        if hashlib.sha256(raw).hexdigest() != digest:
            raise EvidenceError('unexpected body bytes: ' + name)
    for name, addr, raw in PINS:
        if read_bytes(image, addr, len(bytes.fromhex(raw))) != bytes.fromhex(raw):
            raise EvidenceError('unexpected instruction signature: ' + name)
    for site, dst in ((0x3995BC0, LOOKUP), (0x33A1D11, INSERT)):
        raw = read_bytes(image, site, 5)
        if raw[0] != 0xE8 or site + 5 + struct.unpack_from('<i', raw, 1)[0] != dst:
            raise EvidenceError('call target mismatch')


class TrackedMachine(Machine):
    def __init__(self, image, patches=None):
        super().__init__(image, patches)
        self.edges = set()
        self.last = None

    def step(self, row):
        self.last = row.va
        if row.op == 'jcc':
            self.edges.add((row.va, self.condition(row.cc)))
        return super().step(row)


class Fixture:
    def __init__(self, image, patches=None):
        self.m = TrackedMachine(image, patches)
        self.m.real = frozenset()
        self.m.step_limit = 1000000
        self.m.memory.statics = dict(image.relative())
        table = {SLOT_ALLOC: self.on_alloc, SLOT_FREE: self.on_free,
                 SLOT_MEMCPY: self.on_copy, SLOT_MEMMOVE: self.on_copy,
                 SLOT_MEMCMP: self.on_compare}
        table.update({slot: self.on_stop for slot in STOP_SLOTS})
        for slot, hook in table.items():
            self.m.memory.statics[slot] = MARK_BASE + slot
            self.m.slots[MARK_BASE + slot] = hook
        self.top = ARENA
        self.live = {}
        self.allocated_sizes = []
        self.target_alloc_calls = 0
        self.fail_alloc_at = None

    def reset(self):
        self.m.memory.reset()
        self.m.edges.clear()
        self.m.seen.clear()
        self.m.steps = 0
        self.top = ARENA
        self.live.clear()
        self.allocated_sizes.clear()
        self.target_alloc_calls = 0

    def read(self, va, size=8):
        return self.m.memory.read(va, size)

    def put(self, va, data):
        self.m.memory.put_bytes(va, data)

    def data(self, va, count):
        return self.m.memory.bytes_at(va, count)

    def write(self, va, val, size=8):
        self.m.memory.write(va, size, val)

    def alloc(self, size):
        addr = self.top
        self.top += (size + 15) & ~15
        if size < 0 or self.top > ARENA_END:
            raise Halt('arena exhausted')
        self.live[addr] = size
        self.allocated_sizes.append(size)
        return addr

    def on_alloc(self, m):
        self.target_alloc_calls += 1
        if self.target_alloc_calls == self.fail_alloc_at:
            m.regs[RAX] = 0
        else:
            m.regs[RAX] = self.alloc(m.regs[RDI])

    def on_free(self, m):
        ptr, count = m.regs[RDI], m.regs[RSI]
        if self.live.get(ptr) != count:
            raise Halt('invalid free')
        del self.live[ptr]

    def on_copy(self, m):
        dst, src, count = m.regs[RDI], m.regs[RSI], m.regs[RDX]
        self.put(dst, self.data(src, count))
        m.regs[RAX] = dst

    def on_compare(self, m):
        left = self.data(m.regs[RDI], m.regs[RDX])
        right = self.data(m.regs[RSI], m.regs[RDX])
        m.regs[RAX] = 0 if left == right else 1 if left > right else MASK[4]

    def on_stop(self, m):
        raise Panicked('modeled failure boundary')

    def node(self, height, parent=0, slot=0):
        size = 0x220 if height == 0 else 0x280
        va = self.alloc(size)
        self.put(va, bytes(size))
        self.write(va, parent)
        self.write(va + 0x218, slot, 2)
        return va

    def rows(self, root, height):
        seen = set()
        def visit(node, level, parent, edge, path):
            if node in seen or node not in self.live:
                raise EvidenceError('invalid node graph')
            seen.add(node)
            if self.live[node] != (0x280 if level else 0x220):
                raise EvidenceError('wrong node allocation size')
            if self.read(node) != parent or (parent and self.read(node + 0x218, 2) != edge):
                raise EvidenceError('parent link mismatch')
            n = self.read(node + 0x21a, 2)
            if n > 11:
                raise EvidenceError('too many node entries')
            result = []
            for i in range(n + 1):
                if level:
                    result.extend(visit(self.read(node + 0x220 + 8*i), level - 1,
                                        node, i, path + (i,)))
                if i < n:
                    result.append((self.data(node + 8 + 20*i, 20),
                                   self.data(node + 0xe4 + 28*i, 28), node, i, path))
            return result
        rows = visit(root, height, 0, 0, ())
        keys = [row[0] for row in rows]
        if keys != sorted(set(keys)):
            raise EvidenceError('keys not strictly ordered')
        return rows

    def put_row(self, node, index, key, val):
        self.put(node + 8 + 20*index, key)
        self.put(node + 0xe4 + 28*index, val)


def key_of(n):
    return n.to_bytes(20, 'big')


def value_of(n):
    # Two 12-byte timestamp witnesses and a valid bool byte, plus initialized padding.
    return n.to_bytes(4, 'little') * 6 + bytes((n & 1, 0, 0, 0))


def stable_hash(rows):
    return hashlib.sha256(b''.join(key + val for key, val, *_ in rows)).hexdigest()


def run_insert_case(f, parent_len, child, index):
    f.reset()
    m = f.m
    mp, hold, cur, out, kp, vp = [f.alloc(n) for n in (24, 8, 24, 24, 20, 28)]
    if parent_len is None:
        root = f.node(0)
        n = child
        if not 0 <= index <= n <= 11:
            raise EvidenceError('invalid leaf fixture')
        f.write(root + 0x21a, n, 2)
        for j in range(n):
            v = 2*j + 2
            f.put_row(root, j, key_of(v), value_of(v))
        target = root
        number = 2*index + 1
        height = 0
        count = n
    else:
        n = parent_len
        if not 1 <= n <= 11 or not 0 <= child <= n or not 0 <= index <= 11:
            raise EvidenceError('invalid parent fixture')
        root = f.node(1)
        f.write(root + 0x21a, n, 2)
        for j in range(n):
            v = 100*j + 50
            f.put_row(root, j, key_of(v), value_of(v))
        for j in range(n + 1):
            leaf = f.node(0, root, j)
            f.write(leaf + 0x21a, 11, 2)
            f.write(root + 0x220 + 8*j, leaf)
            for z in range(11):
                v = 100*j + 2*z + 2
                f.put_row(leaf, z, key_of(v), value_of(v))
            if j == child:
                target = leaf
        number = 100*child + 2*index + 1
        height = 1
        count = n + (n + 1)*11
    f.write(mp, root)
    f.write(mp + 8, height)
    f.write(mp + 16, count)
    f.write(hold, mp)
    f.write(cur, target)
    f.write(cur + 8, 0)
    f.write(cur + 16, index)
    f.put(kp, key_of(number))
    f.put(vp, value_of(number))
    before = f.rows(root, height)
    expected = sorted([(k, v) for k, v, *_ in before] + [(key_of(number), value_of(number))])
    alloc_before = len(f.allocated_sizes)
    m.run(INSERT, {RDI: out, RSI: cur, RDX: kp, RCX: vp, R8: hold, R9: 0})
    new_root, new_height = f.read(mp), f.read(mp + 8)
    after = f.rows(new_root, new_height)
    if [(k, v) for k, v, *_ in after] != expected:
        raise EvidenceError('tree content differs from independent sorted model')
    if f.read(mp + 16) != count:
        raise EvidenceError('insertion helper unexpectedly changed map count')
    result = next(row for row in after if row[0] == key_of(number))
    if (f.read(out), f.read(out + 16)) != (result[2], result[3]):
        raise EvidenceError('returned cursor differs from inserted entry')
    cursor_depth = f.read(out + 8)
    if cursor_depth != new_height - len(result[4]):
        raise EvidenceError('returned cursor height differs from tree location')
    m.run(LOOKUP, {RDI: mp, RSI: kp})
    if m.regs[RAX] != result[2] + 0xe4 + 28*result[3]:
        raise EvidenceError('lookup did not return inserted value')
    return {'parent_len': parent_len, 'child': child, 'index': index,
            'old_count': count, 'new_count': len(after), 'old_height': height,
            'new_height': new_height, 'cursor_depth': cursor_depth,
            'cursor_path': list(result[4]), 'cursor_index': result[3],
            'new_alloc_sizes': f.allocated_sizes[alloc_before:],
            'rows_sha256': stable_hash(after), 'steps': m.steps}, after, mp, kp


def run_deep_case(f, first, second, index):
    """Full height-two tree: force a split through both full ancestors."""
    if any(not 0 <= i <= 11 for i in (first, second, index)):
        raise EvidenceError('invalid deep fixture')
    f.reset()
    m = f.m
    mp, hold, cur, out, kp, vp = [f.alloc(n) for n in (24, 8, 24, 24, 20, 28)]
    ordinal = [0]
    leaves = {}
    def make(level, parent, slot, path):
        node = f.node(level, parent, slot)
        f.write(node + 0x21a, 11, 2)
        if level == 0:
            leaves[path] = node
        for i in range(12):
            if level:
                child = make(level - 1, node, i, path + (i,))
                f.write(node + 0x220 + 8*i, child)
            if i < 11:
                ordinal[0] += 1
                value = ordinal[0] * 2
                f.put_row(node, i, key_of(value), value_of(value))
        return node
    root = make(2, 0, 0, ())
    target = leaves[(first, second)]
    anchor = int.from_bytes(f.data(target + 8 + 20*(index if index < 11 else 10), 20), 'big')
    number = anchor - 1 if index < 11 else anchor + 1
    f.write(mp, root); f.write(mp + 8, 2); f.write(mp + 16, ordinal[0]); f.write(hold, mp)
    f.write(cur, target); f.write(cur + 8, 0); f.write(cur + 16, index)
    f.put(kp, key_of(number)); f.put(vp, value_of(number))
    before = f.rows(root, 2)
    expected = sorted([(k, v) for k, v, *_ in before] + [(key_of(number), value_of(number))])
    alloc_before = len(f.allocated_sizes)
    m.run(INSERT, {RDI: out, RSI: cur, RDX: kp, RCX: vp, R8: hold, R9: 0})
    height = f.read(mp + 8)
    rows = f.rows(f.read(mp), height)
    if [(k,v) for k,v,*_ in rows] != expected or f.read(mp + 16) != ordinal[0]:
        raise EvidenceError('deep split tree differs from independent sorted model')
    result = next(row for row in rows if row[0] == key_of(number))
    if (f.read(out), f.read(out + 16)) != (result[2], result[3]):
        raise EvidenceError('deep cursor mismatch')
    m.run(LOOKUP, {RDI: mp, RSI: kp})
    if m.regs[RAX] != result[2] + 0xe4 + 28*result[3]:
        raise EvidenceError('deep lookup mismatch')
    return {'first_child': first, 'second_child': second, 'index': index,
            'old_count': len(before), 'new_count': len(rows),
            'new_height': height, 'cursor_path': list(result[4]),
            'cursor_index': result[3], 'alloc_sizes': f.allocated_sizes[alloc_before:],
            'rows_sha256': stable_hash(rows), 'steps': m.steps}


def allocation_failures(image):
    results = []
    for fail in (1, 2, 3):
        f = Fixture(image)
        f.fail_alloc_at = fail
        try:
            run_insert_case(f, 11, 6, 6)
        except Panicked:
            results.append({'failed_allocation': fail, 'calls': f.target_alloc_calls,
                            'last_instruction': hex(f.m.last), 'failure': 'allocation boundary'})
        else:
            raise EvidenceError('null allocation did not reach a modeled failure boundary')
    return results


def lookup_controls(f):
    f.reset()
    mp, kp = f.alloc(24), f.alloc(20)
    f.put(mp, bytes(24))
    results = []
    f.put(kp, key_of(1))
    f.m.run(LOOKUP, {RDI: mp, RSI: kp})
    if f.m.regs[RAX] != 0:
        raise EvidenceError('null-root lookup returned a value')
    results.append({'name': 'null_root', 'key': key_of(1).hex(), 'found': False})
    keys = []
    for i in range(20):
        k = bytearray(20)
        k[i] = 1
        keys.append(bytes(k))
    keys.sort()
    root, left, right = f.node(1), f.node(0), f.node(0)
    f.write(left, root); f.write(left + 0x218, 0, 2)
    f.write(right, root); f.write(right + 0x218, 1, 2)
    f.write(root + 0x21a, 1, 2)
    f.write(left + 0x21a, 10, 2)
    f.write(right + 0x21a, 9, 2)
    f.write(root + 0x220, left); f.write(root + 0x228, right)
    for i, k in enumerate(keys):
        node, ix = (left, i) if i < 10 else (root, 0) if i == 10 else (right, i - 11)
        f.put_row(node, ix, k, value_of(i + 1))
    f.write(mp, root); f.write(mp + 8, 1); f.write(mp + 16, 20)
    rows = f.rows(root, 1)
    wanted = {k: (val, node + 0xe4 + 28*i) for k, val, node, i, _ in rows}
    queries = [('at_byte_%02d' % (19 - i), k) for i, k in enumerate(keys)]
    queries += [('all_zero', bytes(20)), ('all_ff', bytes([255])*20),
                ('between', keys[4][:-1] + bytes([keys[4][-1] + 1]))]
    for name, key in queries:
        f.put(kp, key)
        f.m.run(LOOKUP, {RDI: mp, RSI: kp})
        got = f.m.regs[RAX]
        want = wanted.get(key)
        if (got != (want[1] if want else 0)) or (want and f.data(got, 28) != want[0]):
            raise EvidenceError('lookup differs from sorted-map fixture: ' + name)
        results.append({'name': name, 'key': key.hex(), 'found': bool(want),
                        'value': want[0].hex() if want else None})
    return results


def specs():
    for n in (0, 1, 5, 10, 11):
        for index in range(n + 1):
            yield None, n, index
    for parent in (1, 5, 10, 11):
        for child in range(parent + 1):
            for index in range(12):
                yield parent, child, index


def table(headings, rows):
    import csv
    import io
    out = io.StringIO(newline='')
    writer = csv.writer(out, delimiter='\t', lineterminator='\n')
    writer.writerow(headings)
    writer.writerows(rows)
    return out.getvalue().encode('utf-8')


def relocation_rows(image):
    """Decode selected ELF64 Rela and dynamic symbols from section bytes."""
    wanted = {SLOT_ALLOC, SLOT_MEMCPY, SLOT_FREE, SLOT_MEMMOVE, SLOT_MEMCMP, *STOP_SLOTS}
    byname = {sec['name']: sec for sec in image.sections}
    rela, dynsym, dynstr = byname['.rela.dyn'], byname['.dynsym'], byname['.dynstr']
    for sec in (rela, dynsym, dynstr):
        if sec['type'] == 8:
            raise EvidenceError('relocation section lacks file bytes')
    if rela['size'] % 24 or dynsym['size'] % 24:
        raise EvidenceError('misaligned relocation or symbol section')
    rows = []
    for pos in range(rela['offset'], rela['offset'] + rela['size'], 24):
        slot, info, addend = struct.unpack_from('<QQq', image.blob, pos)
        if slot not in wanted:
            continue
        typ, index = info & 0xffffffff, info >> 32
        if index >= dynsym['size']//24:
            raise EvidenceError('symbol index out of range')
        sympos = dynsym['offset'] + index*24
        name_off = struct.unpack_from('<I', image.blob, sympos)[0]
        if name_off >= dynstr['size']:
            raise EvidenceError('symbol string offset out of range')
        begin = dynstr['offset'] + name_off
        end = image.blob.find(b'\0', begin, dynstr['offset'] + dynstr['size'])
        if end < 0:
            raise EvidenceError('unterminated symbol')
        symbol = bytes(image.blob[begin:end]).decode('ascii')
        rows.append((slot, typ, index, symbol, addend))
    if len(rows) != len(wanted) or {row[0] for row in rows} != wanted:
        raise EvidenceError('missing or duplicate relocation slot')
    expected_names = {SLOT_MEMCPY: 'memcpy', SLOT_MEMMOVE: 'memmove', SLOT_MEMCMP: 'memcmp'}
    for slot, typ, index, symbol, _ in rows:
        if slot in expected_names and (typ != 6 or symbol != expected_names[slot]):
            raise EvidenceError('unexpected external slot identity')
    return sorted(rows)


def mutation_controls(image, decoded, examples):
    """Invert one conditional opcode and replay already-validated fixture(s)."""
    result = []
    for role in ('insert', 'lookup'):
        for row in decoded[role]:
            if row.op != 'jcc':
                continue
            delta = 1 if row.data[0] == 0x0f else 0
            byte = row.data[delta]
            if not (0x70 <= byte <= 0x7f or 0x80 <= byte <= 0x8f):
                raise EvidenceError('unsupported conditional opcode for mutation')
            candidates = []
            for taken in (False, True):
                case = examples.get((row.va, taken))
                if case is not None and case not in candidates:
                    candidates.append(case)
            killed = False
            failure = ''
            reason = ''
            witness = None
            tried = 0
            for case in candidates:
                f = Fixture(image, {row.va + delta: byte ^ 1})
                f.m.step_limit = 50000
                tried += 1
                try:
                    if case[0] == 'insert':
                        run_insert_case(f, *case[1:])
                    elif case[0] == 'deep':
                        run_deep_case(f, *case[1:])
                    else:
                        lookup_controls(f)
                except (EvidenceError, Halt, Panicked, ValueError, IndexError, OverflowError) as error:
                    killed = True
                    failure = type(error).__name__
                    reason = str(error)
                    witness = case
                    break
            result.append({'role': role, 'va': hex(row.va), 'original_opcode': hex(byte),
                           'changed_opcode': hex(byte ^ 1), 'cases_tried': tried,
                           'outcome': 'killed' if killed else 'survived' if tried else 'unreached',
                           'failure_type': failure, 'reason': reason, 'witness': witness})
    return result


def generate(image):
    check_image(image)
    fdes = {f['start']: f for f in eh_frame_records(image.blob, image.sections)[1]}
    functions, instructions, branches, pins = [], [], [], []
    decoded = {}
    for name, start, end, digest in FUNCTIONS:
        rows = decode_range(image, start, end)
        decoded[name] = rows
        functions.append((name, hex(start), hex(end), hex(fdes[start]['fde']),
                          hex(image.offset(start)), end-start, digest, len(rows)))
        starts = {row.va for row in rows}
        for row in rows:
            if row.op in ('jcc', 'jmp') and start <= row.target < end and row.target not in starts:
                raise EvidenceError('branch into middle of decoded instruction')
            instructions.append((name, hex(row.va), row.data.hex(), row.op,
                                 hex(row.target) if row.op in ('jcc', 'jmp', 'call') else ''))
    for name, va, raw in PINS:
        pins.append((name, hex(va), hex(image.offset(va)), read_bytes(image, va, len(bytes.fromhex(raw))).hex()))
    relocations = relocation_rows(image)
    fixture = Fixture(image)
    cases = []
    edges = set()
    examples = {}
    reached = set()
    split_rows = []
    for parent, child, index in specs():
        case, rows, mp, _ = run_insert_case(fixture, parent, child, index)
        cases.append(case)
        for edge in fixture.m.edges:
            examples.setdefault(edge, ('insert', parent, child, index))
        edges.update(fixture.m.edges)
        reached.update(fixture.m.seen)
        if parent is None and child == 11:
            root = fixture.read(mp)
            left = fixture.read(root + 0x220)
            right = fixture.read(root + 0x228)
            split_rows.append((index, fixture.read(left + 0x21a, 2),
                               fixture.data(root + 8, 20).hex(),
                               fixture.read(right + 0x21a, 2),
                               '/'.join(map(str, case['cursor_path'])), case['cursor_index']))
    deep = []
    for triple in ((i, j, k) for i in range(12) for j in range(12) for k in (0, 5, 6, 11)):
        deep.append(run_deep_case(fixture, *triple))
        for edge in fixture.m.edges:
            examples.setdefault(edge, ('deep', *triple))
        edges.update(fixture.m.edges)
        reached.update(fixture.m.seen)
    failures = allocation_failures(image)
    lookups = lookup_controls(fixture)
    for edge in fixture.m.edges:
        examples.setdefault(edge, ('lookup',))
    edges.update(fixture.m.edges)
    reached.update(fixture.m.seen)
    for name, rows in decoded.items():
        for row in rows:
            if row.op == 'jcc':
                branches.append((name, hex(row.va), row.data.hex(), hex(row.target),
                                 int((row.va, True) in edges), int((row.va, False) in edges)))
    mutations = mutation_controls(image, decoded, examples)
    serial_cases = []
    for case in cases:
        serial_cases.append(('leaf' if case['parent_len'] is None else 'parent',
                             '' if case['parent_len'] is None else case['parent_len'],
                             case['child'], case['index'], case['old_count'], case['new_count'],
                             case['old_height'], case['new_height'], case['cursor_depth'],
                             '/'.join(map(str, case['cursor_path'])), case['cursor_index'],
                             ','.join(map(str, case['new_alloc_sizes'])), case['rows_sha256'], case['steps']))
    instruction_count = sum(len(rows) for rows in decoded.values())
    reached_count = sum(row.va in reached for rows in decoded.values() for row in rows)
    summary = {'artifact_sha256': SHA256, 'functions': len(functions),
               'instructions': instruction_count, 'reached_instructions': reached_count,
               'conditional_branches': len(branches),
               'both_edges_seen': sum(bool(r[4] and r[5]) for r in branches),
               'insertion_cases': len(cases), 'lookup_cases': len(lookups),
               'split_leaf_cases': len(split_rows), 'deep_cases': len(deep),
               'allocation_failure_cases': len(failures),
               'mutations_killed': sum(r['outcome'] == 'killed' for r in mutations),
               'mutations_survived': sum(r['outcome'] == 'survived' for r in mutations),
               'mutations_unreached': sum(r['outcome'] == 'unreached' for r in mutations), 'masks': [],
               'execution': 'bounded Python byte interpreter; target executable is not launched',
               'limitations': 'FDE extents are unwind ranges. Fixture coverage is not whole-function proof.'}
    return {
        'functions.tsv': table(('role','start_va','fde_end_va','fde_va','file_offset','bytes','sha256','instructions'), functions),
        'relocations.tsv': table(('slot_va','type','symbol_index','symbol','addend'),
                                 [(hex(a), t, i, n, hex(v) if v >= 0 else str(v))
                                  for a,t,i,n,v in relocations]),
        'pins.tsv': table(('role','va','file_offset','bytes'), pins),
        'instructions.tsv': table(('role','va','bytes','operation','direct_target'), instructions),
        'branches.tsv': table(('role','va','bytes','taken_va','taken_seen','fallthrough_seen'), branches),
        'insertions.tsv': table(('shape','parent_len','child_or_leaf_len','insert_index','old_count','new_count','old_height','new_height','cursor_height','cursor_path','cursor_index','new_allocation_sizes','rows_sha256','steps'), serial_cases),
        'leaf-splits.tsv': table(('insert_index','left_count','pivot_key_hex','right_count','cursor_path','cursor_index'), split_rows),
        'branch-mutations.json': (json.dumps(mutations, indent=2, sort_keys=True) + '\n').encode(),
        'deep-splits.json': (json.dumps(deep, indent=2, sort_keys=True) + '\n').encode(),
        'allocation-failures.json': (json.dumps(failures, indent=2, sort_keys=True) + '\n').encode(),
        'lookups.json': (json.dumps(lookups, indent=2, sort_keys=True) + '\n').encode(),
        'summary.json': (json.dumps(summary, indent=2, sort_keys=True) + '\n').encode(),
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out', required=True, type=pathlib.Path)
    args = parser.parse_args()
    files = generate(load_image())
    args.out.mkdir(parents=True, exist_ok=True)
    for name, data in sorted(files.items()):
        (args.out / name).write_bytes(data)


if __name__ == '__main__':
    try:
        main()
    except (EvidenceError, Halt, Panicked, ValueError, OSError, struct.error) as error:
        print('staking_validator_state_insert94: ' + str(error), file=sys.stderr)
        raise SystemExit(1)
