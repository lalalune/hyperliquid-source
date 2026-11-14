#!/usr/bin/env python3
"""Reconstruct node 115 reciprocal peer clearing and associated order lookup."""
# Portions of the test-world builder adapt tools/book_peer_links_115.py,
# Copyright (c) 2026 Hyperliquid Source contributors, under the MIT License.
# See LICENSE at the repository root for permission and warranty terms.
import argparse
import collections
import copy
import csv
import json
import bisect
import hashlib
import math
import mmap
import pathlib
import struct
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))

from elf_index import sections  # noqa: E402
from fde_extents import eh_frame_records  # noqa: E402

BINARY = ROOT / "artifacts" / "node" / "115" / "hl-node"
SHA256 = "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301"

RAX, RCX, RDX, RBX, RSP, RBP, RSI, RDI = range(8)
R8, R9, R10, R11, R12, R13, R14, R15 = range(8, 16)
VOLATILE = (RCX, RSI, RDI, R8, R9, R10, R11)
CALLEE_SAVED = (RBX, RBP, R12, R13, R14, R15)
MASK = {1: 0xFF, 2: 0xFFFF, 4: 0xFFFFFFFF, 8: 0xFFFFFFFFFFFFFFFF}
SIGN = {1: 0x80, 2: 0x8000, 4: 0x80000000, 8: 0x8000000000000000}
STACK_MARK = 0xA5
STACK_TOP = 0x7FF000000
STACK_SIZE = 0x10000
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

    def range_offset(self, va, count):
        if count < 0:
            raise EvidenceError("negative byte range")
        matches = [section for section in self.mapped
                   if section["type"] != 8 and section["address"] <= va
                   and va < section["address"] + section["size"]
                   and va + count <= section["address"] + section["size"]]
        if len(matches) != 1:
            raise EvidenceError("range has no unique file-backed section: %#x" % va)
        section = matches[0]
        return va - section["address"] + section["offset"]

    def offset(self, va):
        return self.range_offset(va, 1)

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


OVERLAY_LOW = 0x64EFC80
MARK_BASE = 0x7700000000


def load_image(path=BINARY, expected=SHA256):
    # Stream the identity check, then map the file read-only.  The parsers
    # touch only section metadata and the relevant unwind/code pages.
    with pathlib.Path(path).open("rb") as handle:
        digest = hashlib.sha256()
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
        digest = digest.hexdigest()
        if digest != expected:
            raise EvidenceError("binary SHA-256 mismatch: %s" % digest)
        blob = mmap.mmap(handle.fileno(), 0, access=mmap.ACCESS_READ)
    return Image(blob)


QUIET_BIT = 1 << 51
INDEFINITE = 0xFFF8000000000000


def fdiv(left, right):
    """Double division with the IEEE rules x86 follows: a zero divisor gives a signed infinity or NaN, never an exception."""
    if right == 0:
        if left == 0 or left != left:
            return math.nan
        return math.copysign(math.inf, math.copysign(1.0, left) * math.copysign(1.0, right))
    return left / right


def sse_arith(op, left_bits, right_bits):
    """Scalar double add/sub/mul/div on raw bits: the first NaN operand wins and is quieted, a fresh NaN is the indefinite value."""
    for bits in (left_bits, right_bits):
        if (bits >> 52) & 0x7FF == 0x7FF and bits & ((1 << 52) - 1):
            return bits | QUIET_BIT
    left, right = to_float(left_bits), to_float(right_bits)
    if op == "add":
        result = left + right
    elif op == "sub":
        result = left - right
    elif op == "mul":
        result = left * right
    else:
        result = fdiv(left, right)
    return INDEFINITE if result != result else to_bits(result)


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
        if two == 0x1E and rep and window[pos] == 0xFA:
            pos += 1
            return finish("nop")                                      # endbr64
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
                  (0xDB, True): "andpd", (0xEB, True): "orpd", (0x58, True): "addpd", (0x5E, True): "divpd",
                  (0x14, True): "punpcklqdq", (0x59, True): "mulpd", (0x5F, True): "maxpd", (0x55, True): "andnpd"}
        if (two, opsize) in vector:
            reg, rm = modrm(True)
            return finish(vector[(two, opsize)], ("x", reg), rm, 16)
        if two in (0x58, 0x59, 0x5C, 0x5D, 0x5E, 0x5F) and repne:
            reg, rm = modrm(True)
            return finish({0x58: "addsd", 0x59: "mulsd", 0x5C: "subsd", 0x5D: "minsd", 0x5E: "divsd", 0x5F: "maxsd"}[two], ("x", reg), rm, 8)
        if two == 0xC2 and repne:
            reg, rm = modrm(True)
            if immediate(1) != 0:
                raise EvidenceError("unsupported compare predicate at %#x" % va)
            return finish("cmpeqsd", ("x", reg), rm, 8)
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
    base = image.range_offset(start, (end - start) + 16)
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
        self.overlay = None

    def reset(self, used=HEAP_SIZE):
        """Refill the stack and the first `used` heap bytes; the rest must still be untouched."""
        self.stack[:] = self.fresh[0]
        self.heap[:used] = memoryview(self.fresh[1])[:used]

    def locate(self, addr, count):
        if self.stack_base <= addr and addr + count <= STACK_TOP:
            return self.stack, addr - self.stack_base
        if HEAP_BASE <= addr and addr + count <= HEAP_BASE + HEAP_SIZE:
            return self.heap, addr - HEAP_BASE
        if self.overlay is not None and OVERLAY_LOW <= addr and addr + count <= OVERLAY_LOW + 0x60:
            return self.overlay, addr - OVERLAY_LOW
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
            offset = self.image.range_offset(addr, count)
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
        offset = self.image.range_offset(va, count)
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
            following = self.step(row)
            if row.op == "jcc":
                edge = 1 if following == row.target else 2
                self.branch_edges[pc] = self.branch_edges.get(pc, 0) | edge
            pc = following
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
            count = self.get(row.b, 1) & (bits - 1)
            value = self.get(row.a, width)
            self.put(row.a, width, (value >> count | value << (bits - count)) & MASK[width])
        elif op == "rol":
            bits = 8 * width
            count = self.get(row.b, 1) & (bits - 1)
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
            bits = 8 * width
            count = (row.target if row.target is not None else self.regs[RCX]) & (bits - 1)
            high, low = self.get(row.a, width), self.get(row.b, width)
            if op == "shld":
                value = (high << count | low >> (bits - count)) if count else high
            else:
                value = (high >> count | low << (bits - count)) if count else high
            self.put(row.a, width, value)
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
            if op in ("addsd", "divsd", "subsd", "mulsd"):
                self.set_low(row.a[1], sse_arith(op[:3], self.low(row.a), self.low(row.b)))
                return
            left, right = to_float(self.low(row.a)), to_float(self.low(row.b))
            if op == "minsd":
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
        elif op in ("addpd", "divpd", "mulpd", "maxpd"):
            left, right = self.xmm[row.a[1]], self.vector(row.b)
            lanes = []
            for shift in (0, 64):
                one, two = to_float((left >> shift) & MASK[8]), to_float((right >> shift) & MASK[8])
                if op == "maxpd":
                    lanes.append(to_bits(one if one > two else two))
                else:
                    lanes.append(sse_arith({"addpd": "add", "divpd": "div", "mulpd": "mul"}[op], to_bits(one), to_bits(two)))
            self.xmm[row.a[1]] = lanes[0] | lanes[1] << 64
        elif op == "shufpd":
            left, right = self.xmm[row.a[1]], self.vector(row.b)
            first = (left >> (64 * (row.target & 1))) & MASK[8]
            second = (right >> (64 * ((row.target >> 1) & 1))) & MASK[8]
            self.xmm[row.a[1]] = first | second << 64
        elif op == "cmppd":
            if row.target not in (2, 5):
                raise Halt("unmodelled compare predicate at %#x" % row.va)
            left, right = self.xmm[row.a[1]], self.vector(row.b)
            value = 0
            for shift in (0, 64):
                one, two = to_float((left >> shift) & MASK[8]), to_float((right >> shift) & MASK[8])
                if (one <= two) if row.target == 2 else not one < two:
                    value |= MASK[8] << shift
            self.xmm[row.a[1]] = value
        elif op == "cmpeqsd":
            left, right = to_float(self.low(row.a)), to_float(self.low(row.b))
            self.set_low(row.a[1], MASK[8] if left == right else 0)
        elif op == "andnpd":
            self.xmm[row.a[1]] = (~self.xmm[row.a[1]] & ((1 << 128) - 1)) & self.vector(row.b)
        elif op == "movmskpd":
            value = self.xmm[row.b[1]]
            self.put(row.a, 4, int(bool(value >> 63 & 1)) | int(bool(value >> 127 & 1)) << 1)
        else:
            raise Halt("unmodelled operation %s at %#x" % (op, row.va))

    def vector(self, operand):
        if operand[0] == "x":
            return self.xmm[operand[1]]
        return int.from_bytes(self.memory.bytes_at(self.address(operand), 16), "little")



# book layout read by the bodies
BOOK_INDEX_PTR, BOOK_INDEX_LEN = 0x8, 0x10
BOOK_SLAB_PTR, BOOK_SLAB_LEN = 0x88, 0x90
USERS_CAP, USERS_PTR, USERS_HEAD, USERS_LEN = 0xE8, 0xF0, 0xF8, 0x100
INDEX_STRIDE, INDEX_SLOT = 24, 0x10
SLAB_STRIDE, SLAB_KEY, SLAB_BODY = 0x110, 0xF8, 0x20
USER_STRIDE, USER_BODY = 0x70, 0x18
USER_CAP, USER_PTR_OR_ROOT, USER_HEAD_OR_HEIGHT, USER_LEN = 0x20, 0x28, 0x30, 0x38
ORDER_RING_STRIDE, ORDER_RING_BODY = 0xE0, 8
UNIVERSAL_NICHE = 0x8000000000000000
VACANT = 2
KEY_BYTES = 20
# user B-tree node
UT_KEYS, UT_VALS, UT_VAL_STRIDE, UT_LEN, UT_EDGES = 0x3D0, 0x8, 0x58, 0x4AE, 0x4B0
# order B-tree node
OT_KEYS, OT_VALS, OT_VAL_STRIDE, OT_LEN, OT_EDGES = 0x8, 0x60, 0xD8, 0x9AA, 0x9B0
NODE_CAPACITY = 11
# order body
PARENT_TAG, PARENT_ID, PEER_TAG, PEER_ID, KIDS_PTR, KIDS_LEN = 0x10, 0x18, 0x20, 0x28, 0x38, 0x40
BODY_BYTES = 0x58


def lcg(seed):
    state = (seed * 6364136223846793005 + 1442695040888963407) & MASK[8]
    while True:
        state = (state * 6364136223846793005 + 1442695040888963407) & MASK[8]
        yield state >> 33


class Rng:
    def __init__(self, seed):
        self.gen = lcg(seed)

    def below(self, count):
        return next(self.gen) % count

    def between(self, low, high):
        return low + self.below(high - low + 1)

    def chance(self, percent):
        return self.below(100) < percent

    def pick(self, items):
        return items[self.below(len(items))]

    def blob(self, count):
        gen = self.gen
        data = b"".join(((next(gen) << 31) ^ next(gen)).to_bytes(8, "little") for _ in range((count + 7) // 8))
        return data[:count]

    def key20(self):
        return self.blob(KEY_BYTES)


class Order:
    """One order record: tag dword, then the body (8 bytes on when the tag is the vacant niche)."""

    def __init__(self, oid, tag, parent, peer, kids, junk):
        self.oid, self.tag, self.parent, self.peer, self.kids = oid, tag, parent, peer, list(kids)
        self.junk = junk
        self.body = self.kids_at = self.kids_cap = None


class Node:
    def __init__(self, keys, vals, kids):
        self.keys, self.vals, self.kids = keys, vals, kids
        self.addr = None


class UserRec:
    def __init__(self, key, orders, mode, rng):
        self.key, self.mode = key, mode
        self.orders = orders  # sorted by oid
        self.root = None
        self.height = 0
        self.cap = self.head = 0
        self.ptr = None
        self.pos = {}
        self.body = None


class World:
    """Everything the body can reach for one call."""

    def __init__(self):
        self.users_mode = "ring"
        self.users = []
        self.users_root = None
        self.users_height = 0
        self.users_cap = self.users_head = 0
        self.users_ring = None
        self.user_pos = {}
        self.oid_map = {}
        self.probe_overrides = {}
        self.index_len = 0
        self.index_slots = []
        self.slab = []
        self.slab_ptr = 0
        self.rings = {}
        self.ring_overrides = {}
        self.fault = "none"
        self.book = self.key_at = 0


def compare_value(left, right):
    if left == right:
        return 0
    for a, b in zip(left, right):
        if a != b:
            return a - b
    return 0


def shape(rng, height):
    if height == 0:
        return rng.between(1, NODE_CAPACITY)
    return [shape(rng, height - 1) for _ in range(rng.between(2, 4))]


def count_keys(plan):
    if isinstance(plan, int):
        return plan
    return sum(count_keys(child) for child in plan) + len(plan) - 1


def assemble(plan, items, at):
    if isinstance(plan, int):
        take = items[at[0]:at[0] + plan]
        at[0] += plan
        return Node([k for k, _ in take], [v for _, v in take], [])
    kids, keys, vals = [], [], []
    for number, child in enumerate(plan):
        kids.append(assemble(child, items, at))
        if number < len(plan) - 1:
            keys.append(items[at[0]][0])
            vals.append(items[at[0]][1])
            at[0] += 1
    return Node(keys, vals, kids)


class Builder:
    """Writes the world into the evaluator heap and records every address the specification needs."""

    def __init__(self, machine):
        self.machine = machine
        self.memory = machine.memory
        self.top = HEAP_BASE + 0x40

    def alloc(self, count, align=16):
        self.top = (self.top + align - 1) // align * align
        at = self.top
        self.top += count
        if self.top - HEAP_BASE > HEAP_SIZE - 0x2000:
            raise EvidenceError("world does not fit the heap")
        return at

    def put(self, addr, size, value):
        self.memory.write(addr, size, value)

    def fill(self, addr, count, rng):
        self.memory.put_bytes(addr, rng.blob(count))

    def write_order(self, order, value_at, rng, size, body=None):
        self.fill(value_at, size, rng)
        self.put(value_at, 4, order.tag)
        order.body = body if body is not None else value_at + (8 if order.tag == VACANT else 0)
        self.put(order.body + PARENT_TAG, 8, (1 if order.parent is not None else 0) | order.junk << 32)
        self.put(order.body + PARENT_ID, 8, order.parent if order.parent is not None else order.junk)
        self.put(order.body + PEER_TAG, 8, 1 if order.peer is not None else order.junk << 32)
        self.put(order.body + PEER_ID, 8, order.peer if order.peer is not None else order.junk)
        order.kids_cap = len(order.kids) + rng.below(3)
        order.kids_at = self.alloc(8 * max(order.kids_cap, 1), 8)
        for number, kid in enumerate(order.kids):
            self.put(order.kids_at + 8 * number, 8, kid)
        for number in range(len(order.kids), order.kids_cap):
            self.put(order.kids_at + 8 * number, 8, rng.below(1 << 30) | 1 << 40)
        self.put(order.body + 0x30, 8, order.kids_cap)
        self.put(order.body + KIDS_PTR, 8, order.kids_at)
        self.put(order.body + KIDS_LEN, 8, len(order.kids))

    def write_tree(self, node, user_kind, rng, writer):
        node.addr = self.alloc(0x520 if user_kind else 0xA20, 16)
        self.fill(node.addr, 0x520 if user_kind else 0xA20, rng)
        for number, child in enumerate(node.kids):
            self.write_tree(child, user_kind, rng, writer)
            self.put(node.addr + (UT_EDGES if user_kind else OT_EDGES) + 8 * number, 8, child.addr)
        self.put(node.addr + (UT_LEN if user_kind else OT_LEN), 2, len(node.keys))
        for number, (key, val) in enumerate(zip(node.keys, node.vals)):
            if user_kind:
                self.memory.put_bytes(node.addr + UT_KEYS + KEY_BYTES * number, key)
                writer(val, node.addr + UT_VALS + UT_VAL_STRIDE * number)
            else:
                self.put(node.addr + OT_KEYS + 8 * number, 8, key)
                writer(val, node.addr + OT_VALS + OT_VAL_STRIDE * number)
        if len(node.kids):
            self.put(node.addr + (UT_EDGES if user_kind else OT_EDGES) + 8 * len(node.kids), 8, 0)
        if not user_kind:
            for number in range(len(node.keys), NODE_CAPACITY):
                self.put(node.addr + OT_KEYS + 8 * number, 8, rng.below(5000))


def make_order(rng, oid, ids, tag_percent=20):
    tag = VACANT if rng.chance(tag_percent) else 0
    parent = rng.pick(ids) if ids and rng.chance(55) else None
    peer = rng.pick(ids) if ids and rng.chance(30) else None
    kids = []
    for _ in range(rng.between(0, 9) if rng.chance(70) else 0):
        kids.append(rng.pick(ids) if ids and rng.chance(75) else rng.between(1, 1 << 30))
    return Order(oid, tag, parent, peer, kids, rng.below(1 << 30))


def order_ids(rng, count):
    ids = set()
    boundaries = (0, 1, 2, (1 << 63) - 1, 1 << 63, (1 << 63) + 1,
                  MASK[8] - 1, MASK[8])
    while len(ids) < count:
        roll = rng.below(100)
        if roll < 15:
            value = rng.pick(boundaries)
        elif roll < 80:
            value = rng.between(1, 1 << 40)
        else:
            value = rng.between(1, 200)
        ids.add(value)
    return sorted(ids)


def build_world(machine, rng, plan):
    """Create one world from a plan dict (a few choices) and write it into the evaluator heap."""
    builder = Builder(machine)
    world = World()
    world.builder = builder
    book = builder.alloc(0x120)
    builder.fill(book, 0x120, rng)
    world.book = book
    # users
    user_count = plan["users"]
    key_set = {rng.key20() for _ in range(user_count)}
    if user_count and rng.chance(20):
        key_set.add(rng.pick((b"\x00" * KEY_BYTES, b"\xff" * KEY_BYTES,
                              b"\x00" + b"\xff" * 19,
                              b"\xff" + b"\x00" * 19)))
    keys = sorted(key_set)
    world.absent_keys = [extreme for extreme in (b"\xff" * KEY_BYTES, b"\x00" * KEY_BYTES) if extreme not in keys]
    for near in keys[:3]:
        twin = near[:-1] + bytes([near[-1] ^ 1])
        if twin not in keys and twin not in world.absent_keys:
            world.absent_keys.append(twin)
    while len(world.absent_keys) < 4:
        extra = rng.key20()
        if extra not in keys:
            world.absent_keys.append(extra)
    all_ids = order_ids(rng, plan["orders"] + 6)
    for number, key in enumerate(keys):
        count = plan["orders"] if number == plan["target"] % max(len(keys), 1) else rng.between(0, 5)
        ids = sorted(rng.pick(all_ids) for _ in range(count))
        ids = sorted(set(ids))
        mode = plan["order_mode"] if number == plan["target"] % max(len(keys), 1) else rng.pick(["ring", "tree"])
        orders = [make_order(rng, oid, all_ids) for oid in ids]
        user = UserRec(key, orders, mode, rng)
        world.users.append(user)
    world.ids = all_ids
    # user body writers
    def write_user(user, body):
        user.body = body
        builder.fill(body, BODY_BYTES, rng)
        if user.mode == "tree":
            builder.put(body + USER_CAP, 8, UNIVERSAL_NICHE)
            pairs = [(order.oid, order) for order in user.orders]
            if not pairs:
                user.root, user.height = None, 0
                builder.put(body + USER_PTR_OR_ROOT, 8, 0)
                builder.put(body + USER_HEAD_OR_HEIGHT, 8, rng.below(3))
                return
            user.height = 0
            # split into a height-1 tree when the orders do not fit a single node, or when asked to
            if len(pairs) > NODE_CAPACITY or (plan["order_height"] > 0 and len(pairs) >= 3):
                user.root = split_tree(pairs, rng)
                user.height = tree_height(user.root)
            else:
                user.root = Node([k for k, _ in pairs], [v for _, v in pairs], [])
            builder.write_tree(user.root, False, rng, lambda order, at: builder.write_order(order, at, rng, OT_VAL_STRIDE))
            builder.put(body + USER_PTR_OR_ROOT, 8, user.root.addr)
            builder.put(body + USER_HEAD_OR_HEIGHT, 8, user.height)
        else:
            count = len(user.orders)
            user.cap = count + rng.below(3) + (1 if count == 0 else 0)
            user.head = rng.below(user.cap)
            user.ptr = builder.alloc(ORDER_RING_STRIDE * user.cap, 16)
            builder.fill(user.ptr, ORDER_RING_STRIDE * user.cap, rng)
            builder.put(body + USER_CAP, 8, user.cap)
            builder.put(body + USER_PTR_OR_ROOT, 8, user.ptr)
            builder.put(body + USER_HEAD_OR_HEIGHT, 8, user.head)
            builder.put(body + USER_LEN, 8, count)
            user.pos = {}
            for number, order in enumerate(user.orders):
                at = user.ptr + ((user.head + number) % user.cap) * ORDER_RING_STRIDE
                builder.write_order(order, at + ORDER_RING_BODY, rng, ORDER_RING_STRIDE - ORDER_RING_BODY)
                user.pos[order.oid] = number
            world.rings[body + USER_CAP] = user.pos
    if plan["users_mode"] == "tree":
        world.users_mode = "tree"
        builder.put(book + USERS_CAP, 8, UNIVERSAL_NICHE)
        pairs = [(user.key, user) for user in world.users]
        if not pairs:
            world.users_root = None
            builder.put(book + USERS_PTR, 8, 0)
            builder.put(book + USERS_HEAD, 8, rng.below(3))
        else:
            if len(pairs) > NODE_CAPACITY or (plan["users_height"] > 0 and len(pairs) >= 3):
                world.users_root = split_tree(pairs, rng)
            else:
                world.users_root = Node([k for k, _ in pairs], [v for _, v in pairs], [])
            world.users_height = tree_height(world.users_root)
            builder.write_tree(world.users_root, True, rng, write_user)
            builder.put(book + USERS_PTR, 8, world.users_root.addr)
            builder.put(book + USERS_HEAD, 8, world.users_height)
    else:
        world.users_mode = "ring"
        count = len(world.users)
        world.users_cap = count + rng.below(3) + (1 if count == 0 else 0)
        world.users_head = rng.below(world.users_cap)
        world.users_ring = builder.alloc(USER_STRIDE * world.users_cap, 16)
        builder.fill(world.users_ring, USER_STRIDE * world.users_cap, rng)
        builder.put(book + USERS_CAP, 8, world.users_cap)
        builder.put(book + USERS_PTR, 8, world.users_ring)
        builder.put(book + USERS_HEAD, 8, world.users_head)
        builder.put(book + USERS_LEN, 8, count)
        world.user_pos = {}
        for number, user in enumerate(world.users):
            at = world.users_ring + ((world.users_head + number) % world.users_cap) * USER_STRIDE
            write_user(user, at + USER_BODY)
            world.user_pos[user.key] = number
        world.rings[book + USERS_CAP] = world.user_pos
    # slab and the order-id map
    slab_count = plan["slab"]
    world.slab_ptr = builder.alloc(SLAB_STRIDE * (slab_count + 3), 16)
    builder.put(book + BOOK_SLAB_PTR, 8, world.slab_ptr)
    builder.put(book + BOOK_SLAB_LEN, 8, slab_count)
    builder.fill(world.slab_ptr, SLAB_STRIDE * (slab_count + 3), rng)
    for number in range(slab_count):
        at = world.slab_ptr + number * SLAB_STRIDE
        tag = VACANT if rng.chance(20) else 0
        user_key = rng.pick(keys) if keys and rng.chance(75) else rng.key20()
        order = make_order(rng, 0, all_ids, 0)
        order.tag = tag
        builder.write_order(order, at + SLAB_BODY, rng, 0x58, body=at + SLAB_BODY)
        builder.put(at, 4, tag)
        builder.memory.put_bytes(at + SLAB_KEY, user_key)
        world.slab.append(dict(tag=tag, key=user_key, order=order))
    index_len = plan["index"]
    world.index_len = index_len
    world.index_ptr = builder.alloc(INDEX_STRIDE * max(index_len, 1), 16)
    builder.fill(world.index_ptr, INDEX_STRIDE * max(index_len, 1), rng)
    builder.put(book + BOOK_INDEX_PTR, 8, world.index_ptr)
    builder.put(book + BOOK_INDEX_LEN, 8, index_len)
    for number in range(index_len):
        slot = rng.below(slab_count + 2) if slab_count else rng.below(3)
        world.index_slots.append(slot)
        builder.put(world.index_ptr + number * INDEX_STRIDE + INDEX_SLOT, 8, slot)
    world.oid_map = {}
    return world


def tree_height(node):
    return 0 if not node.kids else 1 + tree_height(node.kids[0])


def split_tree(pairs, rng):
    """A height-1 or height-2 tree over the sorted pairs; every node holds 1..11 keys."""
    count = len(pairs)
    if count <= NODE_CAPACITY and not rng.chance(50):
        return Node([k for k, _ in pairs], [v for _, v in pairs], [])
    for height in (1, 2):
        low = 3 if height == 1 else 7
        high = 4 * NODE_CAPACITY + 3 if height == 1 else 4 * (4 * NODE_CAPACITY + 3) + 3
        if low <= count <= high:
            chosen = height if (height == 1 or count > 4 * NODE_CAPACITY + 3 or rng.chance(35)) else 1
            if chosen == 1 and count > 4 * NODE_CAPACITY + 3:
                chosen = 2
            for attempt in range(60):
                tree_plan = shape(rng, chosen)
                if count_keys(tree_plan) == count:
                    return assemble(tree_plan, pairs, [0])
            return assemble(even_plan(count, chosen), pairs, [0])
    return assemble(even_plan(count, 1 if count <= 4 * NODE_CAPACITY + 3 else 2), pairs, [0])


def even_plan(count, height):
    if height == 0:
        return count
    children = 2
    while True:
        rest = count - (children - 1)
        base, extra = divmod(rest, children)
        sizes = [base + (1 if n < extra else 0) for n in range(children)]
        if height == 1 and all(1 <= s <= NODE_CAPACITY for s in sizes):
            return sizes
        if height == 2 and all(3 <= s <= 4 * NODE_CAPACITY + 3 for s in sizes):
            return [even_plan(s, 1) for s in sizes]
        children += 1
        if children > 5:
            raise EvidenceError("cannot shape tree for %d keys" % count)


class SpecPanic(Exception):
    def __init__(self, index):
        self.index = index


class Spec:
    """Predicts the stub calls, the panic and the byte writes of one call."""

    def __init__(self, world):
        self.world = world
        self.log = []
        self.writes = []
        self.panic = None
        self.ring_calls = collections.Counter()
        self.probe_calls = collections.Counter()
        self.last_probe_status = None

    def probe_result(self, oid):
        occurrence = self.probe_calls[oid]
        self.probe_calls[oid] += 1
        response = self.world.probe_overrides.get((oid, occurrence))
        if response is None:
            index = self.world.oid_map.get(oid)
            response = (0, 0) if index is None else (1, index)
        return response

    def ring_position(self, table, key, default, length):
        occurrence = self.ring_calls[(table, key)]
        self.ring_calls[(table, key)] += 1
        response = self.world.ring_overrides.get((table, key, occurrence))
        if response is None:
            response = (1, 0) if default is None else (0, default)
        status, position = response
        if status & 1 or position >= length:
            return None
        return position

    def walk(self, root, height, key, user_kind):
        node = root
        remaining = height
        if node is None:
            return None
        while True:
            at = len(node.keys)
            for number, node_key in enumerate(node.keys):
                if user_kind:
                    self.log.append(("cmp", key, node_key))
                    # Keep the oracle independent of the hook's memcmp loop.
                    order = (key > node_key) - (key < node_key)
                else:
                    order = (key > node_key) - (key < node_key)
                if order == 0:
                    return node.vals[number]
                if order < 0:
                    at = number
                    break
            if remaining == 0:
                return None
            remaining -= 1
            node = node.kids[at]

    def locate(self, key, oid):
        """Address of the order body, or None."""
        world = self.world
        self.log.append(("oid", oid))
        status, index = self.probe_result(oid)
        self.last_probe_status = status
        if status == 1:
            if index >= world.index_len:
                raise SpecPanic(index)
            slot = world.index_slots[index]
            if slot >= len(world.slab):
                return None
            entry = world.slab[slot]
            if entry["tag"] == VACANT or entry["key"] != key:
                return None
            return entry["order"]
        if world.users_mode == "tree":
            user = self.walk(world.users_root, world.users_height, key, True)
        else:
            self.log.append(("users", key))
            position = self.ring_position(world.book + USERS_CAP, key,
                                          world.user_pos.get(key), len(world.users))
            if position is None:
                return None
            user = world.users[position]
        if user is None:
            return None
        if user.mode == "tree":
            return self.walk(user.root, user.height, oid, False)
        self.log.append(("orders", oid))
        position = self.ring_position(user.body + USER_CAP, oid,
                                      user.pos.get(oid), len(user.orders))
        if position is None:
            return None
        return user.orders[position]

    def store(self, addr, size, value):
        self.writes.append((addr, size, value))


class Harness:
    def __init__(self, image, patches=None):
        self.image = image
        self.machine = Machine(image, patches)
        self.world = None
        self.log = []
        self.used = HEAP_SIZE
        self.hooks = {
            OID_PROBE: self.hook_oid,
            RING_USERS: self.hook_ring,
            RING_ORDERS: self.hook_ring,
        }
        self.machine.calls = dict(self.hooks)
        self.machine.slots = {FAKE_COMPARE: self.hook_compare, FAKE_PANIC: self.hook_panic}
        self.machine.memory.statics[GOT_COMPARE] = FAKE_COMPARE
        self.machine.memory.statics[GOT_PANIC] = FAKE_PANIC

    def hook_oid(self, machine):
        book, oid = machine.regs[RDI], machine.regs[RSI]
        if book != self.world.book:
            raise Halt("probe called with another book")
        self.log.append(("oid", oid))
        occurrence = self.probe_calls[oid]
        self.probe_calls[oid] += 1
        response = self.world.probe_overrides.get((oid, occurrence))
        if response is None:
            index = self.world.oid_map.get(oid)
            response = (0, 0) if index is None else (1, index)
        machine.regs[RAX], machine.regs[RDX] = response
        machine.keep_rdx = True

    def hook_ring(self, machine):
        table = self.world.rings.get(machine.regs[RDI])
        if table is None:
            raise Halt("ring search on an unknown ring")
        if machine.regs[RDI] == self.world.book + USERS_CAP:
            key = bytes(machine.memory.bytes_at(machine.regs[RSI], KEY_BYTES))
            self.log.append(("users", key))
        else:
            key = machine.memory.read(machine.regs[RSI], 8)
            self.log.append(("orders", key))
        table_address = machine.regs[RDI]
        occurrence = self.ring_calls[(table_address, key)]
        self.ring_calls[(table_address, key)] += 1
        response = self.world.ring_overrides.get((table_address, key, occurrence))
        if response is None:
            position = table.get(key)
            response = ((1, sum(1 for other in table if other < key))
                        if position is None else (0, position))
        machine.regs[RAX], machine.regs[RDX] = response
        machine.keep_rdx = True

    def hook_compare(self, machine):
        left = bytes(machine.memory.bytes_at(machine.regs[RDI], KEY_BYTES))
        right = bytes(machine.memory.bytes_at(machine.regs[RSI], KEY_BYTES))
        if machine.regs[RDX] != KEY_BYTES:
            raise Halt("compare length")
        self.log.append(("cmp", left, right))
        machine.regs[RAX] = compare_value(left, right) & MASK[4]

    def hook_panic(self, machine):
        raise Panicked((machine.regs[RDI], machine.regs[RDX]))

    def call(self, entry, world, key, first, second):
        machine = self.machine
        self.log = []
        self.ring_calls = collections.Counter()
        self.probe_calls = collections.Counter()
        key_at = world.builder.alloc(32, 16)
        world.builder.memory.put_bytes(key_at, key)
        before = bytes(machine.memory.heap[:world.builder.top - HEAP_BASE])
        args = {RDI: world.book, RSI: key_at, RDX: first, RCX: second}
        panic = None
        ret = tag = None
        try:
            ret = machine.run(entry, args)
            tag = machine.regs[RDX] & 0xff
        except Panicked as caught:
            panic = caught.args[0]
        after = bytes(machine.memory.heap[:world.builder.top - HEAP_BASE])
        return before, after, panic, ret, tag


def expected_after(before, writes):
    out = bytearray(before)
    for addr, size, value in writes:
        at = addr - HEAP_BASE
        out[at:at + size] = (value & MASK[size]).to_bytes(size, "little")
    return bytes(out)


def make_plan(rng):
    return dict(
        users=rng.pick([0, 1, 1, 1, 2, 3, 5, 8, 12, 20, 40]),
        users_mode=rng.pick(["ring", "tree"]),
        users_height=rng.pick([0, 1, 1, 2]),
        orders=rng.pick([1, 2, 3, 6, 11, 14, 25, 40, 0]),
        order_mode=rng.pick(["ring", "tree"]),
        order_height=rng.pick([0, 1, 1]),
        target=rng.below(1000),
        slab=rng.pick([0, 1, 1, 2, 3, 6, 8]),
        index=rng.pick([0, 1, 2, 3, 4, 4]),
    )


def aim_map(world, rng, key, oid):
    """Let the order-id map answer `oid` from the slab in one of its several ways (or not at all)."""
    roll = rng.below(100)
    if roll < 40 or not world.index_len:
        if roll >= 94 and not world.index_len:
            world.oid_map[oid] = rng.pick((world.index_len, world.index_len + 1, MASK[8]))
        return
    if roll >= 94:
        world.oid_map[oid] = rng.pick((world.index_len, world.index_len + 1, MASK[8]))
        return
    builder = world.builder
    index = rng.below(world.index_len)
    world.oid_map[oid] = index
    if rng.chance(12) or not world.slab:
        slot = rng.pick((len(world.slab), len(world.slab) + 1, MASK[8]))
    else:
        slot = rng.below(len(world.slab))
    world.index_slots[index] = slot
    builder.put(world.index_ptr + index * INDEX_STRIDE + INDEX_SLOT, 8, slot)
    if len(world.slab) <= slot < len(world.slab) + 3:
        # Put a convincing but unreachable entry just beyond the true length.
        at = world.slab_ptr + slot * SLAB_STRIDE
        trap = make_order(rng, 0, world.ids, 0)
        trap.kids = []
        builder.write_order(trap, at + SLAB_BODY, rng, 0x58, body=at + SLAB_BODY)
        builder.put(at, 4, 0)
        builder.memory.put_bytes(at + SLAB_KEY, key)
    if slot < len(world.slab):
        entry = world.slab[slot]
        at = world.slab_ptr + slot * SLAB_STRIDE
        if rng.chance(78):
            entry["key"] = key
        else:
            entry["key"] = bytes([key[0] ^ 1]) + key[1:] if rng.chance(50) else key[:-1] + bytes([key[-1] ^ 0x80])
        builder.memory.put_bytes(at + SLAB_KEY, entry["key"])
        if rng.chance(30):
            entry["tag"] = VACANT
            builder.put(at, 4, VACANT)
        elif entry["tag"] == VACANT:
            entry["tag"] = rng.below(2)
            builder.put(at, 4, entry["tag"])


# Functions in this packet.  Resolver and clearing bodies are distinct FDEs;
# the latter inline the lookup rather than calling the former.
CLEAR = "clear"
LOOKUP = "lookup"
BODIES = (
    {"entry": 0x58E6960, "end": 0x58E6F0B, "op": CLEAR},
    {"entry": 0x58E6F10, "end": 0x58E74BB, "op": CLEAR},
    {"entry": 0x58EBEA0, "end": 0x58EC187, "op": LOOKUP},
    {"entry": 0x58EC190, "end": 0x58EC477, "op": LOOKUP},
)
OID_PROBE = 0x4EF4010
RING_USERS = 0x57F7BD0
RING_ORDERS = 0x57FBF50
GOT_COMPARE = 0x64DFB50
GOT_PANIC = 0x64DF620
PANIC_LOCATION = 0x649E918
FAKE_COMPARE = 0x7E000000
FAKE_PANIC = 0x7E000100
CASES_PER_BODY = 2500
SAMPLE_EVERY = 4


def body_seed(body_index, number):
    """Each fixture is reproducible independently of execution order."""
    return (number + 1) * 2654435761 + body_index * 40503 + 17


def pick_world_input(world, rng, number, operation):
    """Choose a user and ID, then populate both sides of the possible link.

    The ID-probe result is deliberately allowed to be absent, stale, vacant or
    out of range.  These fixtures model the callers' observable register
    contract and do not claim to reconstruct the probe itself.
    """
    users = world.users
    user = rng.pick(users) if users and rng.chance(85) else None
    world.selected_user_mode = user.mode if user else "absent"
    key = user.key if user else rng.pick(world.absent_keys)
    ids = [order.oid for order in user.orders] if user else []
    all_ids = [order.oid for person in users for order in person.orders]
    if ids and rng.chance(75):
        first = rng.pick(ids)
    elif all_ids and rng.chance(50):
        first = rng.pick(all_ids)
    else:
        first = rng.between(1, 1 << 40)
    aim_map(world, rng, key, first)
    try:
        chosen = Spec(world).locate(key, first)
    except SpecPanic:
        chosen = None

    if chosen is not None:
        choice = number % 7
        if choice == 0:
            peer = first
        elif choice == 1 or not ids:
            peer = rng.between(1, 1 << 40)
        else:
            peer = rng.pick(ids)
        tag_low = (1, 1, 1, 1, 2, 1, 0)[choice]
        tag = tag_low | (rng.below(8) << 32)
        world.builder.put(chosen.body + PEER_TAG, 8, tag)
        world.builder.put(chosen.body + PEER_ID, 8, peer)
        if peer != first and rng.chance(38):
            aim_map(world, rng, key, peer)

    # Inject a stubbed search result at, or just beyond, the advertised
    # length.  For second-lookups, select the occurrence after the first
    # lookup when both use the same user-ring key.
    mode = number % 20
    if user is not None and mode in (0, 1, 4, 5, 6, 7):
        if mode in (0, 4, 6) and world.users_mode == "ring":
            position = world.user_pos[key]
            if mode == 0:
                response = (0, (len(world.users), len(world.users) + 1, MASK[8])[(number // 20) % 3])
                world.fault = "first-user-oob"
            else:
                response = (2 if mode == 4 else 3, position)
                world.fault = "first-user-status-" + str(response[0])
            world.oid_map.pop(first, None)
            world.ring_overrides[(world.book + USERS_CAP, key, 0)] = response
        elif mode in (1, 5, 7) and user.mode == "ring":
            position = user.pos.get(first)
            if mode == 1:
                response = (0, (len(user.orders), len(user.orders) + 1, MASK[8])[(number // 20) % 3])
                world.fault = "first-order-oob"
            elif position is not None:
                response = (2 if mode == 5 else 3, position)
                world.fault = "first-order-status-" + str(response[0])
            else:
                response = None
            if response is not None:
                world.oid_map.pop(first, None)
                world.ring_overrides[(user.body + USER_CAP, first, 0)] = response

    if operation == CLEAR and user is not None and mode in (2, 3):
        try:
            chosen = Spec(world).locate(key, first)
        except SpecPanic:
            chosen = None
        is_user = mode == 2 and world.users_mode == "ring"
        is_order = mode == 3 and user.mode == "ring"
        if chosen is not None and (is_user or is_order):
            peer = (first + 0x9e3779b97f4a7c15) & MASK[8]
            while peer in world.ids or peer == first:
                peer = (peer + 1) & MASK[8]
            world.oid_map.pop(peer, None)
            world.builder.put(chosen.body + PEER_TAG, 8, 1)
            world.builder.put(chosen.body + PEER_ID, 8, peer)
            if is_user:
                occurrence = int(first not in world.oid_map)
                response = (0, (len(world.users), len(world.users) + 1, MASK[8])[(number // 20) % 3])
                world.ring_overrides[(world.book + USERS_CAP, key, occurrence)] = response
                world.fault = "second-user-oob"
            else:
                response = (0, (len(user.orders), len(user.orders) + 1, MASK[8])[(number // 20) % 3])
                world.ring_overrides[(user.body + USER_CAP, peer, 0)] = response
                world.fault = "second-order-oob"

    if operation == CLEAR and mode == 8 and world.index_len >= 2 and len(world.slab) >= 2:
        try:
            chosen = Spec(world).locate(key, first)
        except SpecPanic:
            chosen = None
        first_index = world.oid_map.get(first)
        first_slot = (world.index_slots[first_index]
                      if first_index is not None and first_index < world.index_len
                      else None)
        other_index = next((i for i in range(world.index_len) if i != first_index), None)
        other_slot = next((i for i in range(len(world.slab)) if i != first_slot), None)
        if chosen is not None and other_index is not None and other_slot is not None:
            peer = (first + 0x9e3779b97f4a7c15) & MASK[8]
            while peer in world.ids or peer in world.oid_map or peer == first:
                peer = (peer + 1) & MASK[8]
            entry = world.slab[other_slot]
            entry["tag"] = 0
            entry["key"] = bytes((key[0] ^ 1,)) + key[1:]
            slot_at = world.slab_ptr + other_slot * SLAB_STRIDE
            world.builder.put(slot_at, 4, 0)
            world.builder.memory.put_bytes(slot_at + SLAB_KEY, entry["key"])
            world.index_slots[other_index] = other_slot
            world.builder.put(world.index_ptr + other_index * INDEX_STRIDE + INDEX_SLOT,
                              8, other_slot)
            world.oid_map[peer] = other_index
            world.builder.put(chosen.body + PEER_TAG, 8, 1)
            world.builder.put(chosen.body + PEER_ID, 8, peer)
            world.fault = "second-slab-key-mismatch"

    if mode in (9, 10, 11):
        statuses = (2, 0x100000001, MASK[8])
        status = statuses[mode - 9]
        # The map entry would panic if the callee treated any non-1 value,
        # or the low 32-bit value alone, as a successful probe.
        world.oid_map[first] = world.index_len
        world.probe_overrides[(first, 0)] = (status, 0)
        world.fault = "first-probe-status-" + hex(status)
    return key, first


def expected_lookup(spec, key, oid):
    """The low return byte identifies slab, user-store, or absent."""
    try:
        order = spec.locate(key, oid)
    except SpecPanic as error:
        spec.panic = (error.index, PANIC_LOCATION)
        return None, None
    if order is None:
        return 2, None
    return (0 if spec.last_probe_status == 1 else 1), order.body


def expected_clear(spec, key, oid, mutation=None):
    """Clear an option, then resolve its saved target and clear that option."""
    try:
        first = spec.locate(key, oid)
        if first is None:
            return
        mem = spec.world.builder.memory
        old = mem.read(first.body + PEER_TAG, 8)
        other = mem.read(first.body + PEER_ID, 8)
        spec.first_tag, spec.first_peer = old, other
        if mutation != "leave-first":
            spec.store(first.body + PEER_TAG, 8, 0)
        if mutation == "test-all-64":
            present = old == 1
        elif mutation == "nonzero-tag":
            present = (old & 0xffffffff) != 0
        else:
            present = (old & 0xffffffff) == 1
        if not present or mutation == "skip-peer":
            return
        if mutation == "search-self":
            other = oid
        second = spec.locate(key, other)
        if second is not None and mutation != "leave-peer":
            spec.store(second.body + PEER_TAG, 8, 0)
    except SpecPanic as error:
        spec.panic = (error.index, PANIC_LOCATION)


def render_events(events):
    """Encode the ordered, synthetic hook transcript without platform paths."""
    def part(value):
        if isinstance(value, bytes):
            return value.hex()
        if isinstance(value, int):
            return hex(value)
        return str(value)
    return "|".join(",".join(part(item) for item in event) for event in events) or "-"


def render_panic(panic):
    return "-" if panic is None else "%#x@%#x" % panic


def render_writes(writes, final_heap):
    rows = []
    for address, size, value in writes:
        offset = address - HEAP_BASE
        actual = int.from_bytes(final_heap[offset:offset + size], "little")
        rows.append("%#x:%d:%#x:%#x" % (offset, size, value, actual))
    return "|".join(rows) or "-"


def execute_case(harness, body_index, number, mutation=None, capture=False):
    body = BODIES[body_index]
    rng = Rng(body_seed(body_index, number))
    machine = harness.machine
    machine.memory.reset(harness.used)
    machine.steps = 0
    machine.seen.clear()
    machine.branch_edges.clear()
    plan = make_plan(rng)
    world = build_world(machine, rng, plan)
    key, first = pick_world_input(world, rng, number, body["op"])
    harness.world = world
    spec = Spec(world)
    if body["op"] == CLEAR:
        expected_clear(spec, key, first, mutation)
        expected_tag = expected_ptr = None
    else:
        expected_tag, expected_ptr = expected_lookup(spec, key, first)
    before, after, panic, ret, tag = harness.call(body["entry"], world, key, first, 0)
    harness.used = world.builder.top - HEAP_BASE + 64
    expected_heap = expected_after(before, spec.writes)
    result_ok = (after == expected_heap and panic == spec.panic and
                 harness.log == spec.log)
    if body["op"] == LOOKUP and panic is None:
        result_ok = result_ok and tag == expected_tag
        if expected_ptr is not None:
            result_ok = result_ok and ret == expected_ptr
    outcome = {
        "number": number,
        "entry": body["entry"],
        "op": body["op"],
        "users_mode": plan["users_mode"],
        "orders_mode": world.selected_user_mode,
        "probe": "hit" if world.probe_overrides.get(
            (first, 0), (1 if first in world.oid_map else 0, 0))[0] == 1 else "miss",
        "fault": world.fault,
        "calls": len(spec.log),
        "writes": len(spec.writes),
        "panic": bool(spec.panic),
        "result": expected_tag,
        "steps": machine.steps,
        "key": key.hex(),
        "order_id": first,
        "seed": body_seed(body_index, number),
        "first_tag": getattr(spec, "first_tag", None),
        "first_peer": getattr(spec, "first_peer", None),
    }
    if capture:
        outcome["comparison"] = {
            "expected_heap_sha256": hashlib.sha256(expected_heap).hexdigest(),
            "actual_heap_sha256": hashlib.sha256(after).hexdigest(),
            "expected_events": render_events(spec.log),
            "actual_events": render_events(harness.log),
            "writes_expected_actual": render_writes(spec.writes, after),
            "expected_panic": render_panic(spec.panic),
            "actual_panic": render_panic(panic),
            "expected_pointer": "-" if expected_ptr is None else hex(expected_ptr),
            "actual_rax": "-" if ret is None else hex(ret),
            "expected_tag": "-" if expected_tag is None else expected_tag,
            "actual_tag": "-" if body["op"] != LOOKUP or panic is not None else tag,
        }
    return result_ok, outcome


def check_cfg(body, rows):
    if not rows or rows[0].va != body["entry"] or rows[-1].next != body["end"]:
        raise EvidenceError("decoded body does not cover its FDE")
    starts = {row.va for row in rows}
    direct_targets = set()
    for row in rows:
        if row.op in ("jcc", "jmp") and row.target not in starts:
            raise EvidenceError("branch target is not a decoded boundary: %#x" % row.va)
        if row.op == "jcc" and row.next not in starts:
            raise EvidenceError("conditional fallthrough leaves the FDE: %#x" % row.va)
        if row.op == "call":
            direct_targets.add(row.target)
    if direct_targets != {OID_PROBE, RING_USERS, RING_ORDERS}:
        raise EvidenceError("unexpected direct call target in %#x" % body["entry"])


def verify_decoding(image):
    """All requested FDE bounds must match and each byte must decode."""
    result = {}
    for body in BODIES:
        bounds = image.exact_fde(body["entry"])
        if bounds != (body["entry"], body["end"]):
            raise EvidenceError("unexpected FDE extent")
        rows = decode_range(image, *bounds)
        check_cfg(body, rows)
        result[body["entry"]] = rows
    return result

# Each listed mutation is actually constructed and must be detected.  Offsets
# identify decoded conditional branches, not an objdump-generated listing.
BRANCH_OFFSETS = {
    CLEAR: (0x3b, 0x49, 0x65, 0x7e, 0xb5, 0xd2, 0x1b0, 0x1be,
            0x286, 0x290, 0x2df, 0x2f9, 0x307),
    LOOKUP: (0x28, 0x36, 0x55, 0x6e, 0xc6, 0xda, 0x19f, 0x1ad,
             0x1ed, 0x1fa, 0x276, 0x27d),
}
MODEL_MUTATIONS = (
    "leave-first", "test-all-64", "nonzero-tag", "skip-peer",
    "search-self", "leave-peer",
)


def make_controls(image, decoded):
    controls = []
    for index, body in enumerate(BODIES):
        by_va = {row.va: row for row in decoded[body["entry"]]}
        for offset in BRANCH_OFFSETS[body["op"]]:
            va = body["entry"] + offset
            row = by_va.get(va)
            if row is None or row.op != "jcc":
                raise EvidenceError("control is not a conditional branch at %#x" % va)
            opcode_at = va + (1 if row.data[0] == 0x0f else 0)
            original = image.blob[image.offset(opcode_at)]
            controls.append(dict(kind="branch", body=index, va=va,
                                 patches={opcode_at: original ^ 1},
                                 detected=False, witness=None, attempted=0,
                                 traps=0, detail="invert condition"))
    for variant in MODEL_MUTATIONS:
        controls.append(dict(kind="model", body=0, va=0, patches={},
                             variant=variant, detected=False, witness=None,
                             attempted=0, traps=0, detail=variant))
    return controls


def sample_number(number):
    # Rotate the selected residue so the 20-case fault schedule is sampled.
    return (number + number // SAMPLE_EVERY) % SAMPLE_EVERY == 0


def witness_labels(row):
    """Give selected sample cases stable, meaningful boundary labels."""
    labels = []
    if row["op"] == CLEAR:
        labels.append("clear-writes-%d-panic-%d" % (row["writes"], row["panic"]))
        if row["first_tag"] is not None and row["first_tag"] & 0xffffffff == 1:
            if row["first_tag"] >> 32:
                labels.append("present-tag-with-high-bits")
            if (row["first_peer"] == row["order_id"] and
                    row["writes"] == 2 and not row["panic"]):
                labels.append("self-reference-cleared")
    else:
        labels.append("lookup-panic" if row["panic"] else "lookup-tag-%d" % row["result"])
    if row["fault"] != "none":
        labels.append("fault-" + row["fault"])
    if row["order_id"] in (0, 1 << 63, MASK[8]):
        labels.append("id-" + hex(row["order_id"]))
    return labels


def run_cases(image, count, sample_writer=None, witness_writer=None, test_controls=True):
    """Stream one generated world at a time; retain counts and control witnesses."""
    decoded = verify_decoding(image)
    controls = make_controls(image, decoded) if test_controls else []
    grouped = {i: [c for c in controls if c["body"] == i] for i in range(len(BODIES))}
    harness = Harness(image)
    mutant = Harness(image)
    mutant.machine.step_limit = 12000
    tally = collections.Counter()
    boundary_counts = {"order_id": collections.Counter(), "user_key": collections.Counter()}
    boundary_ids = {0, 1, 2, (1 << 63) - 1, 1 << 63, (1 << 63) + 1, MASK[8] - 1, MASK[8]}
    boundary_keys = {(b"\x00" * KEY_BYTES).hex(), (b"\xff" * KEY_BYTES).hex(),
                     (b"\x00" + b"\xff" * 19).hex(), (b"\xff" + b"\x00" * 19).hex()}
    coverage = {body["entry"]: {"instructions": set(), "edges": {}}
                for body in BODIES}
    case_count = 0
    sample_count = 0
    seen_labels = set()
    for body_index, body in enumerate(BODIES):
        for number in range(count):
            capture = sample_writer is not None and sample_number(number)
            ok, row = execute_case(harness, body_index, number, capture=capture)
            if not ok:
                raise EvidenceError("comparison mismatch: %s case %d" %
                                    (hex(body["entry"]), number))
            case_count += 1
            if row["order_id"] in boundary_ids:
                boundary_counts["order_id"][hex(row["order_id"])] += 1
            if row["key"] in boundary_keys:
                boundary_counts["user_key"][row["key"]] += 1
            hits = coverage[body["entry"]]
            hits["instructions"].update(harness.machine.seen)
            for site, arms in harness.machine.branch_edges.items():
                hits["edges"][site] = hits["edges"].get(site, 0) | arms
            outcome = (body["op"], row["users_mode"], row["orders_mode"],
                       row["probe"], row["writes"], row["panic"], row["result"],
                       row["fault"])
            tally[outcome] += 1
            if capture:
                proof = row["comparison"]
                sample_writer.writerow((body_index, hex(body["entry"]), number,
                                        row["seed"], row["key"], row["order_id"],
                                        row["users_mode"], row["orders_mode"],
                                        row["probe"], row["fault"], row["calls"], row["writes"],
                                        int(row["panic"]), row["steps"],
                                        "-" if row["first_tag"] is None else hex(row["first_tag"]),
                                        "-" if row["first_peer"] is None else hex(row["first_peer"]),
                                        proof["expected_tag"], proof["actual_tag"],
                                        proof["expected_pointer"], proof["actual_rax"],
                                        proof["expected_panic"], proof["actual_panic"],
                                        proof["writes_expected_actual"],
                                        proof["expected_heap_sha256"], proof["actual_heap_sha256"],
                                        proof["expected_events"], proof["actual_events"]))
                sample_count += 1
                if witness_writer is not None:
                    for label in witness_labels(row):
                        if label not in seen_labels:
                            seen_labels.add(label)
                            witness_writer.writerow((label, body_index, hex(body["entry"]), number))
            for control in grouped[body_index]:
                if control["detected"]:
                    continue
                if control["kind"] == "branch" and control["va"] not in harness.machine.seen:
                    continue
                control["attempted"] += 1
                mutant.machine.patches = control["patches"]
                mutant.machine.cache.clear()
                try:
                    equal, _ = execute_case(mutant, body_index, number,
                                            control.get("variant"))
                except (Halt, EvidenceError, IndexError, KeyError, ValueError,
                        OverflowError, struct.error):
                    # An interpreter limitation or invalid synthetic address is
                    # not by itself a demonstrated output mismatch.
                    control["traps"] += 1
                    continue
                if not equal:
                    control["detected"] = True
                    control["witness"] = number
    return case_count, sample_count, tally, controls, coverage, boundary_counts

# Previously studied callers are only boundary evidence.  Each site is
# verified against an FDE and the signed relative displacement in the ELF.
CALL_SITES = (
    (0x58E1441, 0x58E1400, 0x58E5B60),
    (0x58E1469, 0x58E1400, 0x58E6F10),
    (0x58E1491, 0x58E1400, 0x58E5510),
    (0x58E1FA9, 0x58E1F40, 0x58E6F10),
    (0x58E2AC1, 0x58E2A80, 0x58E6260),
    (0x58E2AEA, 0x58E2A80, 0x58E6960),
    (0x58E2B13, 0x58E2A80, 0x58E4EC0),
    (0x58E372A, 0x58E36C0, 0x58E6960),
    (0x58F8893, 0x58F87F0, 0x58EC190),
    (0x58F88F1, 0x58F87F0, 0x58EC190),
    (0x58F8DD3, 0x58F8D30, 0x58EBEA0),
    (0x58F8E31, 0x58F8D30, 0x58EBEA0),
)

# Bytes for the register setup immediately preceding each clearing call.
# They are checked literally before an argument-flow claim is made.
ARGUMENT_PREFIXES = {
    0x58E1469: bytes.fromhex("8b4310898424e00000000f10030f298424d0000000"
                           "488db424d00000004c89ff4c89e2"),
    0x58E1FA9: bytes.fromhex("8b4310898424e00000000f10030f298424d0000000"
                           "488db424d00000004c89ff4c89e2"),
    0x58E2AEA: bytes.fromhex("8b4510898424f00100000f1045000f298424e0010000"
                           "488db424e00100004c89f74c89e2"),
    0x58E372A: bytes.fromhex("8b4510898424f00100000f1045000f298424e0010000"
                           "488db424e00100004c89f74c89e2"),
}
ARGUMENT_SAVES = {
    0x58E1469: bytes.fromhex("4889d34989f44989ff"),
    0x58E1FA9: bytes.fromhex("4889d34989f44989ff"),
    0x58E2AEA: bytes.fromhex("4889d54989f44989fe"),
    0x58E372A: bytes.fromhex("4889d54989f44989fe"),
}


def bytes_at(image, va, length):
    if length < 0:
        raise EvidenceError("negative byte range")
    matches = [s for s in image.mapped
               if s["type"] != 8 and s["address"] <= va and
               va + length <= s["address"] + s["size"] and
               va < s["address"] + s["size"]]
    if len(matches) != 1:
        raise EvidenceError("range has no unique file-backed section")
    section = matches[0]
    off = section["offset"] + va - section["address"]
    return bytes(image.blob[off:off + length])


def direct_call(image, va):
    data = bytes_at(image, va, 5)
    if data[0] != 0xe8:
        raise EvidenceError("expected direct call at %#x" % va)
    return va + 5 + struct.unpack_from("<i", data, 1)[0]


def require_equal_bytes(actual, expected):
    if actual != expected:
        raise EvidenceError("call-argument setup mismatch")


def checked_call_sites(image):
    for site, caller, target in CALL_SITES:
        start, end = image.fde(site)
        if start != caller or site + 5 > end or direct_call(image, site) != target:
            raise EvidenceError("call-site identity mismatch at %#x" % site)
        prefix = ARGUMENT_PREFIXES.get(site)
        actual_prefix = bytes_at(image, site - len(prefix), len(prefix)) if prefix else b""
        saved = ARGUMENT_SAVES.get(site)
        actual_saved = bytes_at(image, caller + 0x1e, len(saved)) if saved else b""
        count = 0
        if prefix:
            require_equal_bytes(actual_prefix, prefix)
            require_equal_bytes(actual_saved, saved)
            rows = decode_range(image, caller, site)
            boundaries = {row.va for row in rows}
            if (site - len(prefix) not in boundaries or caller + 0x1e not in boundaries or
                    any(row.op in ("jcc", "jmp", "jmpi", "ret") for row in rows)):
                raise EvidenceError("caller prefix is not straight-line fallthrough")
            count = len(rows)
        yield (hex(site), hex(start), hex(end), hex(target),
               bytes_at(image, site, 5).hex(), actual_prefix.hex() if prefix else "-",
               actual_saved.hex() if saved else "-", count)


def dynamic_symbol(image, index):
    symbols = image.named[".dynsym"]
    strings = image.named[".dynstr"]
    if symbols["type"] == 8 or strings["type"] == 8:
        raise EvidenceError("dynamic symbol section has no file bytes")
    if index < 0 or (index + 1) * 24 > symbols["size"]:
        raise EvidenceError("dynamic symbol index outside section")
    symbol_at = symbols["offset"] + index * 24
    name_offset = struct.unpack_from("<I", image.blob, symbol_at)[0]
    if name_offset >= strings["size"]:
        raise EvidenceError("dynamic symbol name outside string table")
    begin = strings["offset"] + name_offset
    limit = strings["offset"] + strings["size"]
    end = image.blob.find(b"\0", begin, limit)
    if end < 0:
        raise EvidenceError("unterminated dynamic symbol name")
    return bytes(image.blob[begin:end]).decode("ascii")


def require_relocation(slot, kind, index, addend, symbol):
    expected = {
        GOT_PANIC: (8, 0, 0x1680CBF, ""),
        GOT_COMPARE: (6, 12, 0, "memcmp"),
    }
    if slot not in expected or (kind, index, addend, symbol) != expected[slot]:
        raise EvidenceError("unexpected relocation for slot %#x" % slot)


def checked_relocations(image):
    rows = {}
    for slot, kind, addend, index in image.relocations():
        if slot not in (GOT_COMPARE, GOT_PANIC):
            continue
        if slot in rows:
            raise EvidenceError("duplicate relocation for slot %#x" % slot)
        symbol = dynamic_symbol(image, index) if index else ""
        require_relocation(slot, kind, index, addend, symbol)
        rows[slot] = (slot, kind, index, addend, symbol)
    if set(rows) != {GOT_COMPARE, GOT_PANIC}:
        raise EvidenceError("missing required relocation")
    return [rows[slot] for slot in sorted(rows)]


def require_digest(actual, expected):
    if actual != expected:
        raise EvidenceError("input digest mismatch")


def integrity_controls(image):
    """Boundary, body-integrity, and digest checks independent of the emulator."""
    results = []

    def record(label, fn):
        try:
            fn()
        except EvidenceError:
            results.append((label, True))
        else:
            results.append((label, False))

    record("wrong-input-digest", lambda: require_digest("0" * 64, SHA256))
    record("address-outside-file", lambda: image.offset(0))
    record("negative-byte-range", lambda: bytes_at(image, BODIES[0]["entry"], -1))
    for body in BODIES:
        start, end = body["entry"], body["end"]
        record("interior-" + hex(start), lambda start=start: image.exact_fde(start + 1))
        raw = bytes_at(image, start, end - start)
        changed = bytearray(raw)
        changed[len(changed) // 2] ^= 1
        original_hash = hashlib.sha256(raw).hexdigest()
        record("body-byte-" + hex(start),
               lambda changed=changed, original_hash=original_hash:
               require_digest(hashlib.sha256(changed).hexdigest(), original_hash))
    for site, prefix in ARGUMENT_PREFIXES.items():
        actual = bytes_at(image, site - len(prefix), len(prefix))
        changed = bytearray(actual)
        changed[0] ^= 1
        record("caller-prefix-byte-" + hex(site),
               lambda changed=changed, prefix=prefix:
               require_equal_bytes(changed, prefix))
        expected_save = ARGUMENT_SAVES[site]
        caller = next(row[1] for row in CALL_SITES if row[0] == site)
        actual_save = bytes_at(image, caller + 0x1e, len(expected_save))
        changed_save = bytearray(actual_save)
        changed_save[0] ^= 1
        record("caller-save-byte-" + hex(site),
               lambda changed_save=changed_save, expected_save=expected_save:
               require_equal_bytes(changed_save, expected_save))
    for slot, kind, index, addend, symbol in checked_relocations(image):
        record("relocation-type-bit-" + hex(slot),
               lambda slot=slot, kind=kind, index=index, addend=addend, symbol=symbol:
               require_relocation(slot, kind ^ 1, index, addend, symbol))
    for body in BODIES:
        rows = decode_range(image, body["entry"], body["end"])
        for kind in ("jcc", "call"):
            position = next(i for i, row in enumerate(rows) if row.op == kind)
            altered = list(rows)
            altered[position] = copy.copy(rows[position])
            altered[position].target += 1
            record("cfg-" + kind + "-" + hex(body["entry"]),
                   lambda body=body, altered=altered: check_cfg(body, altered))
    return results


def write_table(path, header, rows):
    with pathlib.Path(path).open("w", encoding="utf-8", newline="") as handle:
        writer = csv.writer(handle, delimiter="\t", lineterminator="\n")
        writer.writerow(header)
        for row in rows:
            writer.writerow(row)


def instruction_rows(decoded, coverage):
    labels = {0: "unreached", 1: "taken", 2: "fallthrough", 3: "both"}
    for body_index, body in enumerate(BODIES):
        hit = coverage[body["entry"]]
        for ins in decoded[body["entry"]]:
            arms = labels[hit["edges"].get(ins.va, 0)] if ins.op == "jcc" else "-"
            yield (body_index, hex(body["entry"]), hex(ins.va),
                   hex(ins.va - body["entry"]), ins.data.hex(), ins.op,
                   ins.width, "-" if ins.cc is None else ins.cc,
                   repr(ins.a), repr(ins.b),
                   "-" if ins.target is None else hex(ins.target),
                   int(ins.va in hit["instructions"]), arms)


def scope_rows(image, decoded):
    for body in BODIES:
        start, end = image.exact_fde(body["entry"])
        raw = bytes_at(image, start, end - start)
        yield (body["op"], hex(start), hex(end), hex(image.offset(start)),
               len(raw), len(decoded[start]), hashlib.sha256(raw).hexdigest())


def cfg_rows(decoded):
    for body in BODIES:
        rows = decoded[body["entry"]]
        yield (hex(body["entry"]), len(rows),
               sum(row.op == "jcc" for row in rows),
               sum(row.op == "jmp" for row in rows),
               sum(row.op == "call" for row in rows),
               sum(row.op == "calli" for row in rows),
               "verified")


def outcome_rows(tally):
    def order(row):
        return tuple(str(value) for value in row[0])
    for fields, count in sorted(tally.items(), key=order):
        yield (*("-" if value is None else int(value) if type(value) is bool else value
                 for value in fields), count)


def control_rows(controls, checks):
    for item in controls:
        yield (item["kind"], hex(BODIES[item["body"]]["entry"]),
               "-" if item["va"] == 0 else hex(item["va"]),
               item["detail"], int(item["detected"]),
               "-" if item["witness"] is None else item["witness"],
               item["attempted"], item["traps"])
    for label, detected in checks:
        yield ("integrity", "-", "-", label, int(detected), "-", 1, 0)


def generate(image, folder, cases_per_body=CASES_PER_BODY):
    folder = pathlib.Path(folder)
    folder.mkdir(parents=True, exist_ok=True)
    decoded = verify_decoding(image)
    write_table(folder / "functions.tsv",
                ("operation", "entry", "fde_end", "file_offset",
                 "bytes", "instructions", "sha256"),
                scope_rows(image, decoded))
    write_table(folder / "cfg.tsv",
                ("entry", "instructions", "conditional", "direct_jumps",
                 "direct_calls", "indirect_calls", "boundary_check"),
                cfg_rows(decoded))
    write_table(folder / "caller-sites.tsv",
                ("call_site", "caller_fde_start", "caller_fde_end", "target", "bytes",
                 "argument_prefix", "saved_registers", "linear_instructions"),
                checked_call_sites(image))
    write_table(folder / "relocations.tsv",
                ("slot", "type", "symbol_index", "addend", "symbol"),
                ((hex(slot), kind, index, hex(addend), symbol or "-")
                 for slot, kind, index, addend, symbol in checked_relocations(image)))
    with ((folder / "cases.tsv").open("w", encoding="utf-8", newline="") as handle,
          (folder / "witnesses.tsv").open("w", encoding="utf-8", newline="") as witness_file):
        writer = csv.writer(handle, delimiter="\t", lineterminator="\n")
        witness_writer = csv.writer(witness_file, delimiter="\t", lineterminator="\n")
        writer.writerow(("body", "entry", "case", "seed", "user_key", "order_id",
                         "users_mode", "selected_user_orders_mode", "probe", "fault", "calls", "writes",
                         "panic", "steps", "first_tag", "first_peer", "expected_tag", "actual_tag",
                         "expected_pointer", "actual_rax", "expected_panic", "actual_panic",
                         "writes_expected_actual", "expected_heap_sha256", "actual_heap_sha256",
                         "expected_events", "actual_events"))
        witness_writer.writerow(("boundary", "body", "entry", "case"))
        case_count, sampled, tally, controls, coverage, boundaries = run_cases(
            image, cases_per_body, writer, witness_writer)
    write_table(folder / "instructions.tsv",
                ("body", "entry", "va", "relative", "bytes", "operation",
                 "width", "condition", "operand_a", "operand_b", "target",
                 "reached", "branch_arms"),
                instruction_rows(decoded, coverage))
    checks = integrity_controls(image)
    write_table(folder / "outcomes.tsv",
                ("operation", "users_mode", "selected_user_orders_mode", "probe", "writes",
                 "panic", "result_tag", "fault", "cases"), outcome_rows(tally))
    write_table(folder / "controls.tsv",
                ("kind", "entry", "site", "mutation", "detected", "witness",
                 "attempts", "traps"), control_rows(controls, checks))
    detected = sum(item["detected"] for item in controls) + sum(ok for _, ok in checks)
    control_count = len(controls) + len(checks)
    measure = {"cases": case_count, "negative_controls": control_count,
               "negative_detected": detected, "equivalent": 0}
    (folder / "measure.json").write_text(json.dumps(measure, indent=2, sort_keys=True) + "\n",
                                         encoding="utf-8")
    coverage_stats = []
    for body in BODIES:
        instructions = decoded[body["entry"]]
        hits = coverage[body["entry"]]
        branches = [ins for ins in instructions if ins.op == "jcc"]
        coverage_stats.append({
            "entry": hex(body["entry"]),
            "instructions": len(instructions),
            "instructions_reached": sum(ins.va in hits["instructions"] for ins in instructions),
            "conditional_branches": len(branches),
            "conditional_arms": 2 * len(branches),
            "conditional_arms_reached": sum(hits["edges"].get(ins.va, 0).bit_count()
                                             for ins in branches),
        })
    metadata = {"binary_sha256": SHA256, "case_samples": sampled,
                "cases_per_body": cases_per_body, "function_count": len(BODIES),
                "outcome_classes": len(tally), "sample_every": SAMPLE_EVERY,
                "sample_policy": "(case + case//4) mod 4 == 0",
                "undetected": control_count - detected, "coverage": coverage_stats,
                "boundary_inputs": {group: dict(sorted(counts.items()))
                                    for group, counts in boundaries.items()}}
    (folder / "results.json").write_text(json.dumps(metadata, indent=2, sort_keys=True) + "\n",
                                         encoding="utf-8")
    if detected != control_count:
        raise EvidenceError("%d negative controls were not detected" % (control_count - detected))
    return measure


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=pathlib.Path, required=True)
    args = parser.parse_args(argv)
    image = load_image()
    measure = generate(image, args.out)
    print(json.dumps(measure, sort_keys=True))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (EvidenceError, OSError, struct.error) as error:
        print("book peer clear:", error, file=sys.stderr)
        raise SystemExit(1)
