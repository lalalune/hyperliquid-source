#!/usr/bin/env python3
"""Static byte interpretation and independent model of one node #115 consensus timeout flow."""

import bisect
import argparse
import collections
import hashlib
import itertools
import json
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
TLS_BASE = HEAP_BASE + 0x10000
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


OVERLAY_LOW = 0x64EFC80
MARK_BASE = 0x7700000000


def load_image(path=BINARY, expected=SHA256):
    with pathlib.Path(path).open("rb") as handle:
        digest = hashlib.sha256()
        while True:
            block = handle.read(1024 * 1024)
            if not block:
                break
            digest.update(block)
        if digest.hexdigest() != expected:
            raise EvidenceError("binary SHA-256 mismatch: %s" % digest.hexdigest())
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
    pos, rex, opsize, rep, repne, fs = 0, 0, False, False, False, False
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
        elif byte == 0x64:
            fs = True
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
                operand = ("m", None, None, 1, va + size + operand[4], False)
            if operand and operand[0] == "m" and fs:
                return ("m", operand[1], operand[2], operand[3], operand[4] + TLS_BASE, False)
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
        if two == 0xC1:
            reg, rm = modrm()
            return finish("xadd", rm, ("r", reg), width)
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
            return finish("cvtsi2sd", ("x", reg), rm, 8 if wide else 4)
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
        if two in (0xB0, 0xB1):
            reg, rm = modrm()
            return finish("cmpxchg", rm, ("r", reg), 1 if two == 0xB0 else width)
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
        self.intercepts = {}
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
        intercept = self.intercepts.get(row.va)
        if intercept:
            target = intercept(self, row)
            if target is not None:
                return target
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
        elif op == "xadd":
            first, second = self.get(row.a, width), self.get(row.b, width)
            result = self.add_sub(first, second, 0, width, False)
            self.put(row.a, width, result)
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
            value = self.get(row.b, row.width)
            bits = 8 * row.width
            self.set_low(row.a[1], to_bits(float(value - (1 << bits) if value & SIGN[row.width] else value)))
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


# The rule model below is independent of the interpreter. Its domain is the
# first timer's handler, with external services represented by contracts.
EVENT_HANDLER = 0x2e098e0
VOTE_BUILDER = 0x2e154e0
SELECTOR = 0x2cdca20
OUTER = 0x2af77f0
SIGN_VOTE = 0x2786260
CLONE_RING = 0x24ed2b0
CLONE_TREE = 0x2467470
BUILD_SECOND = 0x2e30150
CLOCK = 0x5c842e0
DIFFERENCE = 0x5c84210
GOT_MEMCPY = 0x64df508
GOT_RESET = 0x64e0840
GOT_OBSERVE = 0x64e8728
GOT_GROW = 0x64e86d8
GOT_PANIC = 0x64df830
GOT_LOG = 0x64df9f0
SENTINEL = 1 << 63
MAX_U64 = (1 << 64) - 1
STATE_AT = HEAP_BASE + 0x20000
OUT_AT = HEAP_BASE + 0x22000
EVENT_AT = HEAP_BASE + 0x22100
DATE_AT = HEAP_BASE + 0x22200
METRIC_AT = HEAP_BASE + 0x23000
TIMER_AT = HEAP_BASE + 0x24000
VECTOR_AT = HEAP_BASE + 0x25000
TREE_AT = HEAP_BASE + 0x28000
FIXTURE_USED = 0x30000
SIGN_INPUT_SIZE = 0x94
MESSAGE_SIZE = 0x170
MESSAGE_STRIDE = 0x178


def qword(data, offset):
    return struct.unpack_from("<Q", data, offset)[0]


def dword(data, offset):
    return struct.unpack_from("<I", data, offset)[0]


def put_qword(data, offset, value):
    struct.pack_into("<Q", data, offset, value & MAX_U64)


def put_dword(data, offset, value):
    struct.pack_into("<I", data, offset, value & 0xffffffff)


def synthetic_message(data, kind):
    """A deterministic service contract, not the node's signature algorithm."""
    material = hashlib.sha256(bytes([kind]) + bytes(data)).digest()
    return (material * ((MESSAGE_SIZE + len(material) - 1) // len(material)))[:MESSAGE_SIZE]


def vote_input(state, representation, tree_words, ring_words):
    """Build the argument image consumed by the external signing boundary."""
    result = bytearray([STACK_MARK] * SIGN_INPUT_SIZE)
    if representation == "tree_empty":
        fields = (SENTINEL, 0, POISON, 0)
    elif representation == "tree":
        fields = (SENTINEL,) + tuple(tree_words)
    elif representation == "ring":
        fields = tuple(ring_words)
    else:
        raise ValueError("unknown representation")
    for index, word in enumerate(fields):
        put_qword(result, 8 * index, word)
    result[0x20:0x48] = state[0x740:0x768]
    result[0x48:0x68] = state[0x768:0x788]
    result[0x68:0x78] = state[0x7d8:0x7e8]
    result[0x78:0x80] = state[0xae0:0xae8]
    result[0x80:0x94] = state[0xbc0:0xbd4]
    return bytes(result)


def timer_sum(seconds, nanos, delta_seconds, delta_nanos):
    """Model the observed two-register arithmetic, including malformed inputs."""
    for name, number, limit in (("seconds", seconds, MAX_U64), ("nanos", nanos, 0xffffffff),
                                ("delta_seconds", delta_seconds, MAX_U64),
                                ("delta_nanos", delta_nanos, 0xffffffff)):
        if not 0 <= number <= limit:
            raise ValueError(name)
    raw = (seconds + delta_seconds) & MAX_U64
    over = bool((~(seconds ^ delta_seconds) & (seconds ^ raw)) & SENTINEL)
    if bool(delta_seconds & SENTINEL) != over:
        return None
    ns = (nanos + delta_nanos) & 0xffffffff
    if ns >= 1_000_000_000:
        ns = (ns - 1_000_000_000) & 0xffffffff
        if raw == (1 << 63) - 1 or ns == 1_000_000_000:
            return None
        raw = (raw + 1) & MAX_U64
    return raw, ns


def initial_state(case):
    """Construct a reproducible, self-contained memory image for the model."""
    state = bytearray(0xbd8)
    put_qword(state, 0x3c0, case["capacity"])
    put_qword(state, 0x3c8, VECTOR_AT)
    put_qword(state, 0x3d0, 0)
    put_qword(state, 0x720, SENTINEL if case["representation"].startswith("tree") else 0)
    put_qword(state, 0x728, TREE_AT if case["representation"] == "tree" else 0)
    put_qword(state, 0x730, case["tree_parameter"])
    put_qword(state, 0x738, int(case["representation"] in ("tree", "tree_bad")))
    for offset in range(0x740, 0x788, 8):
        put_qword(state, offset, (case["seed"] * 0x10001 + offset) & MAX_U64)
    for offset in range(0x7d8, 0x7e8, 8):
        put_qword(state, offset, (case["seed"] * 0x10003 + offset) & MAX_U64)
    put_qword(state, 0x838, SENTINEL + (1 if case["second"] is False else 7))
    put_qword(state, 0x8c8, case["count"])
    state[0x8d0] = case["voted"]
    put_qword(state, 0x9c8, SENTINEL)
    put_qword(state, 0xa88, case["delta_seconds"])
    put_dword(state, 0xa90, case["delta_nanos"])
    put_qword(state, 0xa98, TIMER_AT)
    put_qword(state, 0xaa8, 3)
    put_dword(state, 0xab0, 7)
    put_qword(state, 0xab8, TIMER_AT + 0x100)
    put_qword(state, 0xad0, METRIC_AT)
    put_qword(state, 0xae0, case["seed"] ^ 0x0123456789abcdef)
    for offset in range(20):
        state[0xbc0 + offset] = (case["seed"] + 11 * offset) & 0xff
    return state


def default_case(**changes):
    case = dict(seed=3, count=0, voted=0, second=False, capacity=4,
                representation="tree_empty", tree_parameter=17,
                delta_seconds=2, delta_nanos=5,
                clock=(100, 10), stamp=(29, 86399, 123),
                log_enabled=False, fresh=False, lookup_match=False, elapsed=None)
    case.update(changes)
    return case


def independent_timeout(case):
    """Predict state, outputs and named service calls for event tag SENTINEL+2."""
    state = initial_state(case)
    stamp = case["stamp"]
    put_dword(state, 0xb9c, stamp[0])
    put_dword(state, 0xba0, stamp[1])
    put_dword(state, 0xba4, stamp[2])
    calls = [("clock",), ("log",)] if case["log_enabled"] else [("clock",)]
    count = min(case["count"] + 1, MAX_U64)
    put_qword(state, 0x8c8, count)
    repeats = int(not case["voted"]) + int(count > 1)
    tree_words = (0x1111222233334444, 0x5555666677778888, 0x9999aaaabbbbcccc)
    ring_words = (0x101, 0x202, 0x303, 0x404)
    messages = []
    capacity = case["capacity"]
    for _ in range(repeats):
        if case["representation"] == "tree":
            calls.append(("clone_tree", TREE_AT, case["tree_parameter"]))
        elif case["representation"] == "tree_bad":
            calls.append(("panic",))
            put_qword(state, 0x3d0, len(messages))
            return ("panic", bytes(state), tuple(messages), tuple(calls))
        elif case["representation"] == "ring":
            calls.append(("clone_ring",))
        data = vote_input(state, case["representation"], tree_words, ring_words)
        calls.append(("sign", hashlib.sha256(data).hexdigest(), STATE_AT + 0xaf8))
        state[0x8d0] = 1
        if len(messages) == capacity:
            grown = 4 if capacity == 0 else capacity * 2
            calls.append(("grow", capacity, grown))
            capacity = grown
            put_qword(state, 0x3c0, capacity)
        messages.append((SENTINEL + 2, synthetic_message(data, 1)))
        if case["second"]:
            calls.append(("second",))
            if len(messages) == capacity:
                grown = 4 if capacity == 0 else capacity * 2
                calls.append(("grow", capacity, grown))
                capacity = grown
                put_qword(state, 0x3c0, capacity)
            messages.append((SENTINEL + 3, synthetic_message(b"second", 2)))
    calls.append(("clock",))
    result = timer_sum(case["clock"][0], case["clock"][1],
                       case["delta_seconds"], case["delta_nanos"])
    if result is None:
        calls.append(("panic",))
        put_qword(state, 0x3d0, len(messages))
        return ("panic", bytes(state), tuple(messages), tuple(calls))
    calls.append(("reset", TIMER_AT, result[0], result[1]))
    state[0xaa0] = 1
    elapsed = case["elapsed"]
    elapsed_bits = 0 if elapsed is None else to_bits(float(elapsed[0]) + float(elapsed[1]) / 1_000_000_000.0)
    calls.extend((("clock",), ("difference",), ("observe", 11, elapsed_bits), ("observe", 18, elapsed_bits)))
    put_qword(state, 0x3c0, 0)
    put_qword(state, 0x3c8, 8)
    put_qword(state, 0x3d0, 0)
    return ("return", bytes(state), tuple(messages), tuple(calls))


class TimeoutRun:
    """A byte interpreter with inspectable contracts for external calls."""

    def __init__(self, image, patches=None):
        self.image = image
        self.machine = Machine(image, patches)
        self.memory = self.machine.memory
        self.machine.real = frozenset((VOTE_BUILDER,))
        self.machine.calls = {CLOCK: self.clock, DIFFERENCE: self.difference,
                              SIGN_VOTE: self.sign, CLONE_RING: self.clone_ring,
                              CLONE_TREE: self.clone_tree, BUILD_SECOND: self.second}
        slots = {GOT_MEMCPY: self.copy, GOT_RESET: self.reset_timer,
                 GOT_OBSERVE: self.observe, GOT_PANIC: self.panic,
                 GOT_LOG: self.log_enabled, GOT_GROW: self.grow}
        for slot, function in slots.items():
            fake = MARK_BASE + slot
            self.memory.statics[slot] = fake
            self.machine.slots[fake] = function
        self.calls = []
        self.case = None

    def clock(self, machine):
        self.calls.append(("clock",))
        machine.regs[RAX] = self.case["clock"][0]
        machine.regs[RDX] = self.case["clock"][1]
        machine.keep_rdx = True

    def difference(self, machine):
        self.calls.append(("difference",))
        out = machine.regs[RDI]
        if self.case["elapsed"] is None:
            self.memory.write(out, 1, 1)
        else:
            self.memory.write(out, 1, 0)
            self.memory.write(out + 8, 8, self.case["elapsed"][0])
            self.memory.write(out + 16, 4, self.case["elapsed"][1])

    def sign(self, machine):
        data = self.memory.bytes_at(machine.regs[RSI], SIGN_INPUT_SIZE)
        self.calls.append(("sign", hashlib.sha256(data).hexdigest(), machine.regs[RDX]))
        self.memory.put_bytes(machine.regs[RDI], synthetic_message(data, 1))

    def clone_tree(self, machine):
        self.calls.append(("clone_tree", machine.regs[RSI], machine.regs[RDX]))
        self.memory.put_bytes(machine.regs[RDI],
                              struct.pack("<QQQ", 0x1111222233334444, 0x5555666677778888,
                                          0x9999aaaabbbbcccc))

    def clone_ring(self, machine):
        self.calls.append(("clone_ring",))
        self.memory.put_bytes(machine.regs[RDI], struct.pack("<QQQQ", 0x101, 0x202, 0x303, 0x404))

    def second(self, machine):
        self.calls.append(("second",))
        self.memory.put_bytes(machine.regs[RDI], synthetic_message(b"second", 2))

    def copy(self, machine):
        destination, source, count = (machine.regs[RDI], machine.regs[RSI], machine.regs[RDX])
        self.memory.copy(destination, source, count)
        machine.regs[RAX] = destination

    def reset_timer(self, machine):
        self.calls.append(("reset", machine.regs[RDI], machine.regs[RSI], machine.regs[RDX]))

    def observe(self, machine):
        self.calls.append(("observe", machine.regs[RSI], machine.xmm[0] & MAX_U64))

    def panic(self, machine):
        self.calls.append(("panic",))
        raise Panicked("timeout arithmetic panic")

    def log_enabled(self, machine):
        self.calls.append(("log",))

    def grow(self, machine):
        header = machine.regs[RDI]
        if header != STATE_AT + 0x3c0:
            raise Halt("unexpected vector header")
        capacity = self.memory.read(header, 8)
        grown = 4 if capacity == 0 else capacity * 2
        if grown > 8:
            raise Halt("fixture vector capacity exhausted")
        self.calls.append(("grow", capacity, grown))
        self.memory.write(header, 8, grown)

    def run(self, case):
        self.case = case
        self.calls = []
        self.memory.reset(FIXTURE_USED)
        self.memory.statics[0x64f01d8] = int(case["log_enabled"])
        self.memory.put_bytes(STATE_AT, initial_state(case))
        self.memory.put_bytes(DATE_AT, struct.pack("<III", *case["stamp"]))
        self.memory.write(EVENT_AT, 8, SENTINEL + 2)
        self.memory.put_bytes(METRIC_AT, bytes(64))
        try:
            self.machine.run(EVENT_HANDLER, {RDI: OUT_AT, RSI: STATE_AT,
                                              RDX: DATE_AT, RCX: EVENT_AT})
            status = "return"
            count = self.memory.read(OUT_AT + 16, 8)
        except Panicked:
            status = "panic"
            count = self.memory.read(STATE_AT + 0x3d0, 8)
        state = self.memory.bytes_at(STATE_AT, 0xbd8)
        messages = []
        for index in range(count):
            address = VECTOR_AT + index * MESSAGE_STRIDE
            messages.append((self.memory.read(address, 8), self.memory.bytes_at(address + 8, MESSAGE_SIZE)))
        if self.memory.read(VECTOR_AT + count * MESSAGE_STRIDE, 1) != STACK_MARK:
            raise Halt("write beyond live output records")
        return status, state, tuple(messages), tuple(self.calls)


SELECT_FRAME = HEAP_BASE + 0x30000
SELECT_BITS = HEAP_BASE + 0x30100
SELECT_CONTEXT = HEAP_BASE + 0x30200
SELECT_TIMER_A = HEAP_BASE + 0x30400
SELECT_TIMER_B = HEAP_BASE + 0x30500
SELECT_OUTPUT = HEAP_BASE + 0x30600
SELECT_WAKER = HEAP_BASE + 0x30800
SELECT_START = 0x5ce2080
GOT_POLL = 0x64e0858


def select_case(start=5, first="ready", second="pending", extra_clear=False, poll_first=1, poll_second=1):
    modes = ("ready", "pending", "off", "other", "masked")
    if start not in range(9) or first not in modes or second not in modes:
        raise ValueError("invalid selector fixture")
    if not 0 <= poll_first <= 255 or not 0 <= poll_second <= 255:
        raise ValueError("poll byte outside range")
    return dict(start=start, first=first, second=second, extra_clear=extra_clear,
                poll_first=poll_first, poll_second=poll_second)


def independent_select(case):
    """Predict the two timer arms of the nine-way selector."""
    mask = 0x19f
    if case["extra_clear"]:
        mask &= ~1
    if case["first"] == "masked":
        mask |= 0x20
    if case["second"] == "masked":
        mask |= 0x40
    enabled = [0 if mode == "off" else 2 if mode == "other" else 1
               for mode in (case["first"], case["second"])]
    calls = []
    pending = False
    for delta in range(9):
        index = (case["start"] + delta) % 9
        if index not in (5, 6):
            continue
        k = index - 5
        bit = 0x20 << k
        mode = (case["first"], case["second"])[k]
        if mask & bit:
            continue
        if enabled[k] != 1:
            pending = True
            continue
        calls.append(("poll", k, mode))
        poll_value = 0 if mode == "ready" else (case["poll_first"], case["poll_second"])[k]
        if poll_value != 0:
            pending = True
            continue
        enabled[k] = 0
        mask |= bit
        return SENTINEL + 6 + k, mask, tuple(enabled), tuple(calls)
    return SENTINEL + (11 if pending else 10), mask, tuple(enabled), tuple(calls)


def predicate_case(tag=0x2e, same=True, first_size=0, second_size=0, flip=0):
    if not 0 <= tag <= 255 or not 0 <= flip < 20:
        raise ValueError("invalid result tag or byte")
    return dict(tag=tag, same=same, first_size=first_size, second_size=second_size, flip=flip)


def predicate_payload(case, state):
    """The exact 72-byte record supplied by the external lookup contract."""
    record = bytearray(72)
    record[0] = case["tag"]
    if case["tag"] == 0x2e:
        record[1:21] = state[0xbc0:0xbd4]
        if not case["same"]:
            record[1 + case["flip"]] ^= 1
    else:
        put_qword(record, 8, case["first_size"])
        put_qword(record, 0x10, HEAP_BASE + 0x39000)
        put_qword(record, 0x20, case["second_size"])
        put_qword(record, 0x28, HEAP_BASE + 0x39100)
    return bytes(record)


def independent_predicate(case, state):
    frees = []
    if case["tag"] == 0x10:
        if case["first_size"]:
            frees.append((HEAP_BASE + 0x39000, case["first_size"]))
        if case["second_size"]:
            frees.append((HEAP_BASE + 0x39100, case["second_size"]))
    elif case["tag"] in (0x20, 0x13) and case["first_size"]:
        frees.append((HEAP_BASE + 0x39000, case["first_size"]))
    return int(case["tag"] == 0x2e and case["same"]), tuple(frees)


class PredicateRun:
    def __init__(self, image, patches=None):
        self.machine = Machine(image, patches)
        self.memory = self.machine.memory
        for slot, hook in ((0x64e86f0, self.lookup), (0x64df4a0, self.free)):
            fake = MARK_BASE + slot
            self.memory.statics[slot] = fake
            self.machine.slots[fake] = hook
        self.case = None
        self.state = None
        self.frees = []
        self.arguments = ()

    def lookup(self, machine):
        self.arguments = (machine.regs[RSI], machine.regs[RDX], machine.regs[RCX])
        self.memory.put_bytes(machine.regs[RDI], predicate_payload(self.case, self.state))

    def free(self, machine):
        self.frees.append((machine.regs[RDI], machine.regs[RSI]))

    def run(self, case):
        self.case = case
        self.frees = []
        self.arguments = ()
        self.state = initial_state(default_case())
        self.memory.reset(FIXTURE_USED)
        self.memory.put_bytes(STATE_AT, self.state)
        result = self.machine.run(0x2e1b5a0, {RDI: STATE_AT}) & 0xff
        expected_args = (STATE_AT + 0x788, qword(self.state, 0xae0), qword(self.state, 0x760))
        if self.arguments != expected_args:
            raise Halt("lookup argument mismatch")
        return result, tuple(self.frees)


class SelectRun:
    """Execute the selector with its seven non-timer branches disabled."""
    def __init__(self, image, patches=None):
        self.machine = Machine(image, patches)
        self.memory = self.machine.memory
        self.machine.calls = {SELECT_START: self.random_start}
        fake = MARK_BASE + GOT_POLL
        self.memory.statics[GOT_POLL] = fake
        self.machine.slots[fake] = self.poll
        self.case = None
        self.calls = []

    def random_start(self, machine):
        if self.memory.read(machine.regs[RSI], 4) != 9:
            raise Halt("selector start bound is not nine")
        machine.regs[RAX] = self.case["start"]

    def poll(self, machine):
        if machine.regs[RDI] == TIMER_AT:
            index, mode = 0, self.case["first"]
        elif machine.regs[RDI] == TIMER_AT + 0x100:
            index, mode = 1, self.case["second"]
        else:
            raise Halt("unexpected timer pointer")
        self.calls.append(("poll", index, mode))
        machine.regs[RAX] = 0 if mode == "ready" else (self.case["poll_first"], self.case["poll_second"])[index]

    def run(self, case):
        self.case = case
        self.calls = []
        self.memory.reset(0x31000)
        self.memory.write(TLS_BASE, 8, TLS_BASE)
        self.memory.write(TLS_BASE - 0x1130 + 0x48, 1, 2)
        self.memory.write(SELECT_FRAME, 8, SELECT_BITS)
        self.memory.write(SELECT_FRAME + 8, 8, SELECT_CONTEXT)
        mask = 0x19f | (0x20 if case["first"] == "masked" else 0) | (0x40 if case["second"] == "masked" else 0)
        if case["extra_clear"]:
            mask &= ~1
        self.memory.write(SELECT_BITS, 2, mask)
        self.memory.write(SELECT_CONTEXT, 8, SELECT_TIMER_A)
        self.memory.write(SELECT_CONTEXT + 8, 8, SELECT_TIMER_B)
        self.memory.write(SELECT_TIMER_A + 0x10, 8, TIMER_AT)
        self.memory.write(SELECT_TIMER_B + 0x10, 8, TIMER_AT + 0x100)
        self.memory.write(SELECT_TIMER_A + 0x18, 1, 0 if case["first"] == "off" else 2 if case["first"] == "other" else 1)
        self.memory.write(SELECT_TIMER_B + 0x18, 1, 0 if case["second"] == "off" else 2 if case["second"] == "other" else 1)
        self.machine.run(SELECTOR, {RDI: SELECT_OUTPUT, RSI: SELECT_FRAME, RDX: SELECT_WAKER})
        return (self.memory.read(SELECT_OUTPUT, 8),
                self.memory.read(SELECT_BITS, 2),
                (self.memory.read(SELECT_TIMER_A + 0x18, 1), self.memory.read(SELECT_TIMER_B + 0x18, 1)),
                tuple(self.calls))


ROOT_AT = STATE_AT - 0xca0
QUEUE_AT = HEAP_BASE + 0x35000
REFS_AT = HEAP_BASE + 0x35400
CHUNK_AT = HEAP_BASE + 0x38000
ROOT_CONTEXT = HEAP_BASE + 0x3c000
STAKE_SET = HEAP_BASE + 0x3c100
STAKE_NODE = HEAP_BASE + 0x3c200
GOT_CURRENT_DATE = 0x64e0990
GOT_DATE_CONVERT = 0x64e0f78
GOT_DATE_FINISH = 0x64e0aa0
GOT_NOTICE = 0x64e7508
GOT_THROTTLE = 0x64e0008
GOT_FREE = 0x64df4a0
GOT_FILTER_NOTICE = 0x64e0b20
GOT_STAKES = 0x64e64b0
GOT_MEMCMP = 0x64dfb50
FILTER = 0x2317b10
FILTER_PREDICATE = 0x2e11140
DROP_MESSAGE = 0x230bc90
DROP_RETURNED = 0x2c99f50
VECTOR_DROP = 0x282ad70
SUMMARY = 0x2e19800
QUEUE_CHUNK = 0x2ccf750
INITIAL_PREPARE = 0x2e13ea0
IS_LOCAL = 0x2e1b5a0
GOT_LOOKUP = 0x64e86f0
GOT_MALLOC = 0x64df480
GOT_SEED = 0x64e11d8
STREAM_A = HEAP_BASE + 0x3e000
STREAM_B = HEAP_BASE + 0x3f000


class FlowRun(TimeoutRun):
    """Join the real selector, the root, the timeout arm, and the output loop."""
    def __init__(self, image, patches=None):
        super().__init__(image, patches)
        self.machine.real = frozenset((SELECTOR, EVENT_HANDLER, VOTE_BUILDER, FILTER,
                                       FILTER_PREDICATE, VECTOR_DROP, IS_LOCAL))
        self.machine.calls.update({SELECT_START: self.random_start, SUMMARY: self.summary,
                                   DROP_MESSAGE: self.drop_filtered,
                                   DROP_RETURNED: self.drop_returned, QUEUE_CHUNK: self.queue_chunk,
                                   INITIAL_PREPARE: self.prepare})
        slots = {GOT_POLL: self.poll, GOT_CURRENT_DATE: self.current_date,
                 GOT_DATE_CONVERT: self.date_convert, GOT_DATE_FINISH: self.date_finish,
                 GOT_NOTICE: self.notice, GOT_THROTTLE: self.throttle, GOT_FREE: self.free,
                 GOT_FILTER_NOTICE: self.notice, GOT_LOOKUP: self.lookup,
                 GOT_MALLOC: self.malloc, GOT_SEED: self.seed, GOT_STAKES: self.filter_stakes,
                 GOT_MEMCMP: self.compare_bytes}
        for slot, function in slots.items():
            fake = MARK_BASE + slot
            self.memory.statics[slot] = fake
            self.machine.slots[fake] = function
        self.machine.intercepts[0x2af7c40] = self.poll_boundary
        self.select_calls = 0
        self.routed = []
        self.filtered = []
        self.frees = []
        self.allocations = []
        self.filter_index = 0

    def poll_boundary(self, machine, row):
        self.select_calls += 1
        if self.select_calls == 1:
            return None
        # Subsequent polls depend on the rest of the running scheduler.  The
        # boundary below selects its pending result; the first poll is real.
        self.memory.write(machine.regs[RDI], 8, SENTINEL + 11)
        return row.next

    def random_start(self, machine):
        if self.memory.read(machine.regs[RSI], 4) != 9:
            raise Halt("selector start bound is not nine")
        machine.regs[RAX] = 5

    def poll(self, machine):
        if machine.regs[RDI] != TIMER_AT:
            raise Halt("unexpected timer pointer")
        self.routed.append(("timer_poll", machine.regs[RDI]))
        machine.regs[RAX] = 0

    def current_date(self, machine):
        self.memory.put_bytes(machine.regs[RDI], struct.pack("<III", *self.case["stamp"]))

    def date_convert(self, machine):
        self.memory.put_bytes(machine.regs[RDI], bytes(16))

    def date_finish(self, machine):
        machine.regs[RAX] = 0

    def summary(self, machine):
        self.memory.put_bytes(machine.regs[RDI], bytes(64))

    def filter_stakes(self, machine):
        self.filtered.append(("filter", machine.regs[RDX]))
        pattern = self.case.get("keep_pattern")
        accepted = pattern[self.filter_index % len(pattern)] if pattern else self.case.get("keep", True)
        self.filter_index += 1
        self.memory.write(machine.regs[RDI], 1, 0x2e)
        self.memory.write(machine.regs[RDI] + 8, 8, STAKE_SET)
        self.memory.put_bytes(STAKE_SET, bytes(24))
        self.memory.put_bytes(STAKE_NODE, bytes(0x148))
        self.memory.write(STAKE_SET, 8, SENTINEL)
        if accepted:
            self.memory.write(STAKE_SET + 8, 8, STAKE_NODE)
            self.memory.write(STAKE_NODE + 0x13e, 2, 1)
            self.memory.put_bytes(STAKE_NODE + 0x60, self.memory.bytes_at(STATE_AT + 0xbc0, 20))

    def compare_bytes(self, machine):
        length = machine.regs[RDX]
        left = self.memory.bytes_at(machine.regs[RDI], length)
        right = self.memory.bytes_at(machine.regs[RSI], length)
        result = next((a - b for a, b in zip(left, right) if a != b), 0)
        machine.regs[RAX] = result & 0xffffffff

    def drop_filtered(self, machine):
        self.filtered.append(("drop", self.memory.read(machine.regs[RDI], 8)))

    def notice(self, machine):
        pass

    def throttle(self, machine):
        machine.regs[RAX] = 0

    def drop_returned(self, machine):
        self.routed.append(("closed", self.memory.read(machine.regs[RDI], 8)))

    def queue_chunk(self, machine):
        self.routed.append(("chunk", machine.regs[RSI]))
        machine.regs[RAX] = CHUNK_AT

    def prepare(self, machine):
        self.routed.append(("prepare", machine.regs[RDI]))

    def lookup(self, machine):
        self.routed.append(("lookup", machine.regs[RSI], machine.regs[RDX], machine.regs[RCX]))
        key = bytearray(self.memory.bytes_at(STATE_AT + 0xbc0, 20))
        if not self.case["lookup_match"]:
            key[0] ^= 1
        self.memory.put_bytes(machine.regs[RDI], b"\x2e" + bytes(key))

    def seed(self, machine):
        machine.regs[RAX] = 0x12340000 + len(self.allocations)

    def malloc(self, machine):
        if machine.regs[RDI] != 0xe8 or len(self.allocations) >= 2:
            raise Halt("unexpected allocation")
        address = (STREAM_A, STREAM_B)[len(self.allocations)]
        self.allocations.append(address)
        machine.regs[RAX] = address

    def free(self, machine):
        self.frees.append((machine.regs[RDI], machine.regs[RSI]))

    def run(self, case):
        self.case = case
        self.calls = []
        self.routed = []
        self.filtered = []
        self.frees = []
        self.allocations = []
        self.filter_index = 0
        self.select_calls = 0
        self.memory.reset(0x40000)
        self.memory.statics[0x64f01d8] = int(case["log_enabled"])
        self.memory.put_bytes(ROOT_AT, bytes(0xca0))
        if case["fresh"]:
            self.memory.put_bytes(ROOT_AT, initial_state(case))
            self.memory.write(ROOT_AT + 0xc78, 8, QUEUE_AT)
            self.memory.write(ROOT_AT + 0xc80, 8, REFS_AT)
        else:
            self.memory.put_bytes(STATE_AT, initial_state(case))
        self.memory.put_bytes(ROOT_CONTEXT, bytes(64))
        self.memory.put_bytes(QUEUE_AT, bytes(0x200))
        self.memory.put_bytes(REFS_AT, bytes(0x20))
        self.memory.put_bytes(CHUNK_AT, bytes(0x3000))
        self.memory.put_bytes(METRIC_AT, bytes(64))
        self.memory.write(TLS_BASE, 8, TLS_BASE)
        self.memory.write(TLS_BASE - 0x1130 + 0x48, 1, 2)
        self.memory.write(ROOT_AT + 0x1aca, 1, 0 if case["fresh"] else 3)
        self.memory.write(ROOT_AT + 0x1ab8, 8, SELECT_BITS)
        self.memory.write(ROOT_AT + 0x1ac0, 8, SELECT_CONTEXT)
        self.memory.put_bytes(ROOT_AT + 0x1940, bytes(64))
        self.memory.write(ROOT_AT + 0x1918, 8, QUEUE_AT)
        self.memory.write(ROOT_AT + 0x1920, 8, REFS_AT)
        self.memory.write(QUEUE_AT + 0x1c0, 8, int(case.get("closed", False)))
        self.memory.write(SELECT_BITS, 2, 0x1df)
        self.memory.write(SELECT_CONTEXT, 8, ROOT_AT + 0x1728)
        self.memory.write(ROOT_AT + 0x1740, 1, 1)
        status = self.machine.run(OUTER, {RDI: ROOT_AT, RSI: ROOT_CONTEXT})
        state = self.memory.bytes_at(STATE_AT, 0xbd8)
        count = self.memory.read(QUEUE_AT + 0x88, 8)
        queued = []
        for index in range(count):
            address = CHUNK_AT + index * MESSAGE_STRIDE
            queued.append((self.memory.read(address, 8), self.memory.bytes_at(address + 8, MESSAGE_SIZE)))
        queue_state = (count, self.memory.read(QUEUE_AT + 0x1c0, 8),
                       self.memory.read(QUEUE_AT + 0x110, 8), self.memory.read(REFS_AT + 0x10, 8),
                       self.memory.read(CHUNK_AT + 0x2f10, 8), self.memory.read(ROOT_AT + 0x1ac8, 2),
                       self.select_calls)
        return (status & 0xff, self.memory.read(ROOT_AT + 0x1aca, 1), state,
                tuple(queued), tuple(self.calls), tuple(self.routed), tuple(self.filtered), tuple(self.frees),
                queue_state)


class InvalidEntryRun:
    """Run the invalid resume-state branch until its panic-service boundary."""
    def __init__(self, image, patches=None):
        self.machine = Machine(image, patches)
        self.memory = self.machine.memory
        slot = 0x64e1360
        fake = MARK_BASE + slot
        self.memory.statics[slot] = fake
        self.machine.slots[fake] = self.reject
        self.location = None

    def reject(self, machine):
        self.location = machine.regs[RDI]
        raise Panicked("invalid outer poll state")

    def run(self, state_byte):
        if state_byte in (0, 3) or not 0 <= state_byte <= 255:
            raise ValueError("invalid-state fixture requires another byte")
        self.memory.reset(0x23000)
        self.memory.write(ROOT_AT + 0x1aca, 1, state_byte)
        self.location = None
        try:
            self.machine.run(OUTER, {RDI: ROOT_AT, RSI: ROOT_CONTEXT})
        except Panicked:
            return self.location, self.memory.read(ROOT_AT + 0x1aca, 1)
        raise Halt("invalid state did not panic")


def independent_flow(case):
    status, state, messages, calls = independent_timeout(case)
    if status != "return":
        raise ValueError("the joined success path excludes an unwinding timer")
    pattern = case.get("keep_pattern")
    choices = [pattern[index % len(pattern)] if pattern else case.get("keep", True)
               for index in range(len(messages))]
    accepted = tuple(message for message, keep in zip(messages, choices) if keep)
    kept = accepted if not case.get("closed", False) else ()
    routed = []
    if case["fresh"]:
        prefix = [("clock",), ("reset", TIMER_AT, case["clock"][0] + case["delta_seconds"],
                               case["clock"][1] + case["delta_nanos"]),
                  ("clock",), ("reset", TIMER_AT + 0x100, case["clock"][0] + 3,
                               case["clock"][1] + 7)] if case["lookup_match"] else [
                  ("clock",), ("reset", TIMER_AT, case["clock"][0] + case["delta_seconds"],
                               case["clock"][1] + case["delta_nanos"])]
        prefix[1] = ("reset", TIMER_AT, *timer_sum(*case["clock"], case["delta_seconds"], case["delta_nanos"]))
        if case["lookup_match"]:
            prefix[3] = ("reset", TIMER_AT + 0x100, *timer_sum(*case["clock"], 3, 7))
        calls = tuple(prefix) + calls
        changed = bytearray(state)
        changed[0xac0] = int(case["lookup_match"])
        state = bytes(changed)
        base = initial_state(case)
        routed.extend((("lookup", STATE_AT + 0x788, qword(base, 0xae0), qword(base, 0x760)),
                       ("prepare", STATE_AT)))
    routed.append(("timer_poll", TIMER_AT))
    if case.get("closed", False):
        routed.extend(("closed", tag) for tag, _ in accepted)
    else:
        routed.extend(("chunk", i) for i in range(len(accepted)))
    # The filter sees the first qword 0x48 bytes into each message.
    filtered = []
    for (tag, data), keep in zip(messages, choices):
        filtered.append(("filter", qword(data, 0x40)))
        if not keep:
            filtered.append(("drop", tag))
    if case["log_enabled"]:
        calls += (("log",),) * max(0, choices.count(False) - 1)
    grown = [event[2] for event in calls if event[0] == "grow"]
    capacity = grown[-1] if grown else case["capacity"]
    frees = ((VECTOR_AT, capacity * MESSAGE_STRIDE),) if capacity else ()
    count = len(kept)
    queue_state = (count, 1 if case.get("closed", False) else 2 * count, 0, count,
                   (1 << count) - 1, 0, 2)
    return (1, 3, state, tuple(kept), calls, tuple(routed), tuple(filtered), frees, queue_state)


# Each change below is a counterfactual to one actual instruction byte.
# The witness is part of the record; an undetected mutation is a failure.
MUTATIONS = (
    ("selector-first-mask", "select", 0x2cdcd45, 0x01, {"start": 5}),
    ("selector-first-mask-branch", "select", 0x2cdcd47, 0x01, {"start": 5}),
    ("selector-first-enabled", "select", 0x2cdcd5a, 0x01, {"start": 5}),
    ("selector-first-ready-branch", "select", 0x2cdcd73, 0x01, {"start": 5}),
    ("selector-first-clear", "select", 0x2cddc06, 0x01, {"start": 5}),
    ("selector-first-done-mask", "select", 0x2cddc0e, 0x01, {"start": 5, "extra_clear": True}),
    ("selector-first-output-tag", "select", 0x2cddc1c, 0x01, {"start": 5}),
    ("selector-second-mask", "select", 0x2cdcd81, 0x01, {"start": 6, "first": "masked", "second": "ready"}),
    ("selector-second-mask-branch", "select", 0x2cdcd83, 0x01, {"start": 6, "first": "masked", "second": "ready"}),
    ("selector-second-enabled", "select", 0x2cdcd97, 0x01, {"start": 6, "first": "masked", "second": "ready"}),
    ("selector-second-ready-branch", "select", 0x2cdcdb0, 0x01, {"start": 6, "first": "masked", "second": "ready"}),
    ("selector-second-clear", "select", 0x2cddbd7, 0x01, {"start": 6, "first": "masked", "second": "ready"}),
    ("selector-second-done-mask", "select", 0x2cddbdf, 0x01, {"start": 6, "first": "masked", "second": "ready", "extra_clear": True}),
    ("selector-second-output-tag", "select", 0x2cddbed, 0x01, {"start": 6, "first": "masked", "second": "ready"}),
    ("selector-pending-tag", "select", 0x2cdda51, 0x01, {"start": 5, "first": "pending", "second": "masked"}),
    ("selector-exhausted-tag", "select", 0x2cdda57, 0x01, {"start": 5, "first": "masked", "second": "masked"}),
    ("selector-loop-bound", "select", 0x2cdcb6b, 0x01, {"start": 6, "first": "ready", "second": "pending"}),
    ("counter-operation", "timeout", 0x2e09a03, 0x08, {"count": 0}),
    ("counter-saturation", "timeout", 0x2e09a0d, 0x01, {"count": 0}),
    ("first-vote-branch", "timeout", 0x2e09a2c, 0x01, {"count": 0, "voted": 0}),
    ("repeat-vote-branch", "timeout", 0x2e09a3e, 0x01, {"count": 1, "voted": 1}),
    ("nanos-threshold", "timeout", 0x2e09a91, 0x01, {"clock": (100, 999999995), "delta_nanos": 5}),
    ("nanos-carry-branch", "timeout", 0x2e09a95, 0x01, {"clock": (100, 999999995), "delta_nanos": 5}),
    ("nanos-carry-constant", "timeout", 0x2e09a99, 0x01, {"clock": (100, 999999995), "delta_nanos": 5}),
    ("timer-enabled-flag", "timeout", 0x2e09ad0, 0x01, {"count": 0}),
    ("first-metric-index", "timeout", 0x2e09ad5, 0x01, {"count": 0}),
    ("all-metric-index", "timeout", 0x2e0aca8, 0x01, {"count": 0}),
    ("built-vote-flag", "timeout", 0x2e15697, 0x01, {"count": 0, "voted": 0}),
    ("built-vote-tag", "timeout", 0x2e156a2, 0x01, {"count": 0, "voted": 0}),
    ("second-message-branch", "timeout", 0x2e156fa, 0x01, {"count": 0, "second": False}),
    ("second-message-tag", "timeout", 0x2e15713, 0x01, {"count": 0, "second": True}),
    ("second-message-copy-size", "timeout", 0x2e1574c, 0x08, {"count": 0, "second": True}),
    ("second-message-overrun", "timeout", 0x2e1574c, 0x01, {"count": 0, "second": True}),
    ("outer-resume-tag", "flow", 0x2af817e, 0x01, {}),
    ("outer-poll-result", "flow", 0x2af8180, 0x01, {}),
    ("outer-event-tag", "flow", 0x2af7ed6, 0x01, {}),
    ("outer-resume-compare", "flow", 0x2af7825, 0x01, {}),
    ("outer-resume-branch", "flow", 0x2af7827, 0x01, {}),
    ("filter-provider-result", "flow", 0x2e1116e, 0x01, {}),
    ("filter-empty-tree", "flow", 0x2e111a1, 0x01, {}),
    ("filter-match-result", "flow", 0x2e112a4, 0x01, {}),
    ("local-result-tag", "predicate", 0x2e1b5cf, 0x01, {}),
    ("local-final-equality", "predicate", 0x2e1b611, 0x01, {}),
)


def mutation_result(image, item):
    name, kind, address, flip, changes = item
    original = image.blob[image.offset(address)]
    patches = {address: original ^ flip}
    try:
        if kind == "select":
            case = select_case(**changes)
            subject = SelectRun(image, patches)
            expected = independent_select(case)
        elif kind == "timeout":
            case = default_case(**changes)
            subject = TimeoutRun(image, patches)
            expected = independent_timeout(case)
        elif kind == "flow":
            case = default_case(**changes)
            subject = FlowRun(image, patches)
            expected = independent_flow(case)
        elif kind == "predicate":
            case = predicate_case(**changes)
            subject = PredicateRun(image, patches)
            expected = independent_predicate(case, initial_state(default_case()))
        else:
            raise ValueError(kind)
        subject.machine.step_limit = 10000
        observed = subject.run(case)
        detected = observed != expected
        outcome = "mismatch" if detected else "undetected"
    except (EvidenceError, Halt, Panicked, ValueError, IndexError, struct.error, OverflowError):
        detected, outcome = True, "rejected"
    return (name, kind, address, original, original ^ flip, detected, outcome)


SCOPED = {
    "outer": (OUTER, 0x2af8bd3),
    "selector": (SELECTOR, 0x2cddea5),
    "event-handler": (EVENT_HANDLER, 0x2e11140),
    "vote-builder": (VOTE_BUILDER, 0x2e157b2),
    "filter": (FILTER, 0x2317dae),
    "filter-predicate": (FILTER_PREDICATE, 0x2e112eb),
    "vector-drop": (VECTOR_DROP, 0x282ae32),
    "local-predicate": (IS_LOCAL, 0x2e1b6ad),
}

SLOT_BINDINGS = {
    GOT_MALLOC: (8, 0x6355830, 0),
    GOT_FREE: (8, 0x635de30, 0),
    GOT_RESET: (8, 0x5cf1fc0, 0),
    GOT_POLL: (8, 0x5cf2d30, 0),
    GOT_CURRENT_DATE: (8, 0x1629690, 0),
    GOT_STAKES: (8, 0x595e5c0, 0),
    GOT_GROW: (8, 0x59631f0, 0),
    GOT_LOOKUP: (8, 0x595cb30, 0),
    GOT_OBSERVE: (8, 0x57e73d0, 0),
    GOT_MEMCPY: (6, 0, 7),
    GOT_MEMCMP: (6, 0, 12),
}


def validate_bindings(records):
    selected = {}
    for slot, kind, addend, symbol in records:
        if slot in SLOT_BINDINGS:
            if slot in selected:
                raise EvidenceError("duplicate relocation binding")
            selected[slot] = (kind, addend, symbol)
    if selected != SLOT_BINDINGS:
        raise EvidenceError("relocation bindings do not match the target")
    return selected


def as_json(value):
    if isinstance(value, bytes):
        return value.hex()
    raise TypeError(type(value).__name__)


def comparison_bytes(value):
    return json.dumps(value, default=as_json, sort_keys=True, separators=(",", ":")).encode("ascii")


def timer_cases():
    clocks = ((100, 10, 2, 5), (100, 999999995, 2, 5),
              ((1 << 63) - 1, 0, 0, 1), ((1 << 63) - 1, 1, 0, 999999999))
    elapsed = (None, (0, 0), (1, 500000000), ((1 << 53), 999999999))
    variants = itertools.product((0, 1, 2, MAX_U64 - 1, MAX_U64), (0, 1),
                                 (False, True), ("tree_empty", "tree", "tree_bad", "ring"),
                                 (0, 1, 2, 4), elapsed, clocks)
    for index, (count, voted, second, representation, capacity, duration, clock) in enumerate(variants):
        yield default_case(seed=index & 255, count=count, voted=voted, second=second,
                           representation=representation, capacity=capacity, elapsed=duration,
                           clock=clock[:2], delta_seconds=clock[2], delta_nanos=clock[3],
                           log_enabled=bool(index & 1))
    seconds = (0, 1, (1 << 63) - 1, 1 << 63, MAX_U64)
    nanos = (0, 1, 999999999, 1000000000, 2000000000, 0xffffffff)
    for index, (clock_s, delta_s, clock_n, delta_n) in enumerate(
            itertools.product(seconds, seconds, nanos, (0, 1, 1000000000, 0xffffffff))):
        yield default_case(seed=index & 255, count=0, voted=1,
                           clock=(clock_s, clock_n), delta_seconds=delta_s, delta_nanos=delta_n)


def flow_cases():
    elapsed = (None, (0, 0), (1, 500000000))
    variants = itertools.product(((False, False), (True, False), (True, True)),
                                 (0, 1, MAX_U64), (0, 1), (False, True),
                                 ("tree_empty", "tree", "ring"), (0, 1, 4),
                                 ((True,), (False,), (True, False), (False, True)), (False, True), elapsed)
    for index, (fresh, count, voted, second, representation, capacity, pattern, closed, duration) in enumerate(variants):
        carry = bool(index & 1)
        yield default_case(seed=index & 255, fresh=fresh[0], lookup_match=fresh[1], count=count,
                           voted=voted, second=second, representation=representation,
                           capacity=capacity, keep_pattern=pattern, closed=closed, elapsed=duration,
                           clock=(100, 999999995 if carry else 10), delta_nanos=5,
                           log_enabled=bool((index // 2) & 1))


def predicate_cases():
    for tag, first, second in itertools.product(range(256), (0, 3), (0, 7)):
        yield predicate_case(tag=tag, first_size=first, second_size=second)
    for flip in range(20):
        yield predicate_case(tag=0x2e, same=False, flip=flip)


def select_cases():
    for start, first, second in itertools.product(range(9), ("ready", "pending", "off", "other", "masked"),
                                                   ("ready", "pending", "off", "other", "masked")):
        yield select_case(start, first, second)
    for value in range(256):
        yield select_case(5, "pending", "masked", poll_first=value)
        yield select_case(6, "masked", "pending", poll_second=value)


def validate_scoped(image):
    text = image.named[".text"]
    for label, (start, end) in SCOPED.items():
        if image.exact_fde(start) != (start, end):
            raise EvidenceError("FDE extent mismatch for " + label)
        if not (text["address"] <= start < end <= text["address"] + text["size"]):
            raise EvidenceError("non-executable range for " + label)
        if image.offset(end - 1) != image.offset(start) + end - start - 1:
            raise EvidenceError("non-contiguous file range for " + label)


def jump_targets(image, start, count):
    offset = image.offset(start)
    return tuple(start + struct.unpack_from("<i", image.blob, offset + 4 * index)[0]
                 for index in range(count))


def basic_blocks(rows, extra=()):
    by_addr = {row.va: row for row in rows}
    low, high = rows[0].va, rows[-1].next
    leaders = {low} | {address for address in extra if address in by_addr}
    for row in rows:
        if row.op in ("jcc", "jmp", "jmpi", "ret", "ud2"):
            if row.next in by_addr:
                leaders.add(row.next)
            if row.target is not None and low <= row.target < high and row.target in by_addr:
                leaders.add(row.target)
    groups, group = [], []
    for row in rows:
        if row.va in leaders and group:
            groups.append(group)
            group = []
        group.append(row)
    if group:
        groups.append(group)
    return groups


def generate(out):
    out = pathlib.Path(out)
    out.mkdir(parents=True, exist_ok=True)
    rust_cases = (out / "rust-cases.tsv").open("w", encoding="utf-8", newline="\n")
    rust_cases.write("count\tvoted\tsecond\tseconds\tnanos\tdelta_seconds\tdelta_nanos\tstatus\tout_count\tout_voted\tsign_calls\tmessages\treset_seconds\treset_nanos\n")
    image = load_image()
    validate_scoped(image)
    bindings = validate_bindings(image.relocations())
    runners = {"select": SelectRun(image), "predicate": PredicateRun(image),
               "timeout": TimeoutRun(image), "flow": FlowRun(image),
               "invalid-entry": InvalidEntryRun(image)}
    counts = collections.Counter()
    categories = collections.Counter()
    results_digest = hashlib.sha256()
    examples = []

    def compare(kind, case, expected):
        observed = runners[kind].run(case)
        if observed != expected:
            raise EvidenceError("model mismatch: " + kind + " " + repr(case))
        counts[kind] += 1
        results_digest.update(comparison_bytes((kind, case, observed)))
        if kind == "select":
            categories[(kind, hex(observed[0]))] += 1
            if case["poll_first"] in (0, 1, 2, 127, 255) and case["poll_second"] in (0, 1, 2, 127, 255):
                examples.append((kind, json.dumps(case, sort_keys=True), hex(observed[0]),
                                 hex(observed[1]), repr(observed[2:])))
        elif kind == "predicate":
            categories[(kind, str(observed[0]))] += 1
            if case["first_size"] == 0 and case["second_size"] == 0:
                examples.append((kind, json.dumps(case, sort_keys=True), str(observed[0]), "", repr(observed[1])))
        elif kind == "timeout":
            categories[(kind, observed[0])] += 1
            if counts[kind] % 31 == 0 and case["representation"] != "tree_bad":
                reset = next((item for item in observed[3] if item[0] == "reset"), None)
                rust_cases.write("\t".join(str(value) for value in (
                    case["count"], case["voted"], int(case["second"]), *case["clock"],
                    case["delta_seconds"], case["delta_nanos"], observed[0],
                    qword(observed[1], 0x8c8), observed[1][0x8d0],
                    sum(item[0] == "sign" for item in observed[3]), len(observed[2]),
                    reset[2] if reset else 0, reset[3] if reset else 0)) + "\n")
        elif kind == "flow":
            categories[(kind, "closed" if case["closed"] else "open")] += 1
        else:
            categories[(kind, "panic")] += 1

    for case in select_cases():
        compare("select", case, independent_select(case))
    state = initial_state(default_case())
    for case in predicate_cases():
        compare("predicate", case, independent_predicate(case, state))
    for case in timer_cases():
        compare("timeout", case, independent_timeout(case))
    for case in flow_cases():
        compare("flow", case, independent_flow(case))
    for state_byte in range(256):
        if state_byte not in (0, 3):
            compare("invalid-entry", state_byte, (0x64481d8, state_byte))
    rust_cases.close()

    mutations = [mutation_result(image, item) for item in MUTATIONS]
    if any(not row[5] for row in mutations):
        raise EvidenceError("unexplained surviving mutation")

    with (out / "controls.tsv").open("w", encoding="utf-8", newline="\n") as handle:
        handle.write("name\tentry\taddress\toriginal\tmutated\tdetected\tobservation\n")
        for name, kind, address, before, after, detected, note in mutations:
            handle.write(f"{name}\t{kind}\t{address:#x}\t{before:02x}\t{after:02x}\t{int(detected)}\t{note}\n")
    with (out / "cases.tsv").open("w", encoding="utf-8", newline="\n") as handle:
        handle.write("entry\tinput\tresult\tmask\tstate_or_calls\n")
        for row in examples:
            handle.write("\t".join(row) + "\n")

    full_rows = {}
    with (out / "instructions.tsv").open("w", encoding="utf-8", newline="\n") as handle:
        handle.write("function\tva\tbytes\toperation\twidth\toperand_a\toperand_b\ttarget\n")
        for label, (start, end) in SCOPED.items():
            if label == "event-handler":
                continue
            rows = decode_range(image, start, end)
            full_rows[label] = rows
            for row in rows:
                target = hex(row.target) if row.target is not None else ""
                handle.write(f"{label}\t{row.va:#x}\t{row.data.hex()}\t{row.op}\t{row.width}\t{row.a!r}\t{row.b!r}\t{target}\n")
        handler_seen = sorted(va for runner in runners.values() for va in runner.machine.seen
                              if SCOPED["event-handler"][0] <= va < SCOPED["event-handler"][1])
        for va in sorted(set(handler_seen)):
            row = decode(runners["timeout"].machine.read_code, va)
            data = image.blob[image.offset(va):image.offset(va) + row.size].hex()
            target = hex(row.target) if row.target is not None else ""
            handle.write(f"event-handler-reached\t{va:#x}\t{data}\t{row.op}\t{row.width}\t{row.a!r}\t{row.b!r}\t{target}\n")

    handler_rows = decode_range(image, *SCOPED["event-handler"])
    handler_seen = set(handler_seen)
    extra = jump_targets(image, 0x6160e8, 9) + jump_targets(image, 0x61610c, 8)
    with (out / "handler-blocks.tsv").open("w", encoding="utf-8", newline="\n") as handle:
        handle.write("start\tend\trows\tsha256\tlast_op\ttarget\tseen_in_cases\n")
        for block in basic_blocks(handler_rows, extra):
            data = b"".join(row.data for row in block)
            last = block[-1]
            target = hex(last.target) if last.target is not None else ""
            seen = sum(row.va in handler_seen for row in block)
            handle.write(f"{block[0].va:#x}\t{last.next:#x}\t{len(block)}\t{hashlib.sha256(data).hexdigest()}\t{last.op}\t{target}\t{seen}\n")

    relative = image.relative()
    location = image.location(0x64481d8, relative)
    functions = []
    for label, (start, end) in SCOPED.items():
        offset = image.offset(start)
        functions.append(dict(label=label, start=hex(start), end=hex(end), file_offset=hex(offset),
                              size=end-start, sha256=hashlib.sha256(image.blob[offset:offset+end-start]).hexdigest()))
    evidence = dict(target_sha256=SHA256, source_location=location,
                    source_location_va="0x64481d8", fdes=functions,
                    slot_bindings=[dict(slot=hex(slot), kind=value[0], addend=hex(value[1]), symbol=value[2])
                                   for slot, value in sorted(bindings.items())],
                    selector_table=[hex(x) for x in jump_targets(image, 0x60bec4, 9)],
                    outer_table=[hex(x) for x in jump_targets(image, 0x60433c, 10)],
                    handler_table=[hex(x) for x in jump_targets(image, 0x6160e8, 9)],
                    reached_handler_rows=len(handler_seen),
                    categories=[dict(entry=k[0], outcome=k[1], count=v) for k, v in sorted(categories.items())],
                    comparison_sha256=results_digest.hexdigest())
    (out / "evidence.json").write_text(json.dumps(evidence, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    measure = dict(cases=sum(counts.values()), negative_controls=len(mutations),
                   negative_detected=sum(row[5] for row in mutations), equivalent=0)
    (out / "measure.json").write_text(json.dumps(measure, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    (out / "rust-model.rs.txt").write_text(RUST_MODEL, encoding="utf-8")
    return dict(counts=dict(counts), measure=measure, digest=results_digest.hexdigest(),
                reached_handler=len(handler_seen))


RUST_MODEL = r'''// MIT. Independent projection of one node 115 timer event.
// Signed-message construction, clock acquisition and channel internals are
// caller-provided contracts; their byte-level implementations are not here.

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TimerResult {
    Ready { seconds: u64, nanos: u32 },
    Invalid,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Input {
    pub count: u64,
    pub voted: bool,
    pub second: bool,
    pub seconds: u64,
    pub nanos: u32,
    pub delta_seconds: u64,
    pub delta_nanos: u32,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Transition {
    pub count: u64,
    pub voted: bool,
    pub signing_calls: u8,
    pub messages: u8,
    pub timer: TimerResult,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Entry {
    Start,
    Resume,
    Invalid,
}

pub fn entry(state: u8) -> Entry {
    match state {
        0 => Entry::Start,
        3 => Entry::Resume,
        _ => Entry::Invalid,
    }
}

pub fn timer_sum(seconds: u64, nanos: u32, delta_seconds: u64, delta_nanos: u32) -> TimerResult {
    let (signed, overflow) = (seconds as i64).overflowing_add(delta_seconds as i64);
    if (delta_seconds >> 63 != 0) != overflow {
        return TimerResult::Invalid;
    }
    let mut seconds = signed as u64;
    let mut nanos = nanos.wrapping_add(delta_nanos);
    if nanos >= 1_000_000_000 {
        nanos = nanos.wrapping_sub(1_000_000_000);
        let (_, carry_overflow) = (seconds as i64).overflowing_add(1);
        if carry_overflow || nanos == 1_000_000_000 {
            return TimerResult::Invalid;
        }
        seconds = seconds.wrapping_add(1);
    }
    TimerResult::Ready { seconds, nanos }
}

pub fn on_timeout(input: Input) -> Transition {
    let count = input.count.saturating_add(1);
    let signing_calls = u8::from(!input.voted) + u8::from(count > 1);
    let messages = signing_calls * if input.second { 2 } else { 1 };
    Transition {
        count,
        voted: input.voted || signing_calls != 0,
        signing_calls,
        messages,
        timer: timer_sum(input.seconds, input.nanos, input.delta_seconds, input.delta_nanos),
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Mode {
    Masked,
    Off,
    Pending,
    Ready,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Selection {
    pub tag: u8,
    pub done_mask: u16,
    pub enabled: [bool; 2],
}

pub fn select_timer(start: u8, modes: [Mode; 2]) -> Option<Selection> {
    if start >= 9 {
        return None;
    }
    let mut mask = 0x19f_u16;
    let mut enabled = [modes[0] != Mode::Off, modes[1] != Mode::Off];
    for index in 0..2 {
        if modes[index] == Mode::Masked {
            mask |= 0x20 << index;
        }
    }
    let mut pending = false;
    for step in 0..9 {
        let arm = (start + step) % 9;
        if arm != 5 && arm != 6 {
            continue;
        }
        let index = usize::from(arm - 5);
        if modes[index] == Mode::Masked {
            continue;
        }
        if modes[index] == Mode::Ready {
            enabled[index] = false;
            mask |= 0x20 << index;
            return Some(Selection { tag: 6 + index as u8, done_mask: mask, enabled });
        }
        pending = true;
    }
    Some(Selection { tag: if pending { 11 } else { 10 }, done_mask: mask, enabled })
}

pub fn local_match(tag: u8, local: &[u8; 20], value: &[u8; 20]) -> bool {
    tag == 0x2e && local == value
}

#[cfg(test)]
mod tests {
    use super::*;

    fn number<T: std::str::FromStr>(s: &str) -> T
    where
        T::Err: std::fmt::Debug,
    {
        s.parse().unwrap()
    }

    #[test]
    fn timeout_matches_byte_interpreter_fixtures() {
        let mut checked = 0;
        for line in include_str!("rust-cases.tsv").lines().skip(1) {
            let f: Vec<_> = line.split('\t').collect();
            assert_eq!(f.len(), 14);
            let input = Input {
                count: number(f[0]),
                voted: f[1] != "0",
                second: f[2] != "0",
                seconds: number(f[3]),
                nanos: number(f[4]),
                delta_seconds: number(f[5]),
                delta_nanos: number(f[6]),
            };
            let actual = on_timeout(input);
            assert_eq!(actual.count, number(f[8]));
            assert_eq!(u8::from(actual.voted), number(f[9]));
            assert_eq!(actual.signing_calls, number(f[10]));
            assert_eq!(actual.messages, number(f[11]));
            let expected_timer = if f[7] == "panic" {
                TimerResult::Invalid
            } else {
                TimerResult::Ready { seconds: number(f[12]), nanos: number(f[13]) }
            };
            assert_eq!(actual.timer, expected_timer, "fixture {checked}");
            checked += 1;
        }
        assert!(checked >= 30);
    }

    #[test]
    fn selection_rotation_and_pending_are_distinct() {
        assert_eq!(select_timer(5, [Mode::Ready, Mode::Ready]).unwrap().tag, 6);
        assert_eq!(select_timer(6, [Mode::Ready, Mode::Ready]).unwrap().tag, 7);
        assert_eq!(select_timer(5, [Mode::Pending, Mode::Masked]).unwrap().tag, 11);
        assert_eq!(select_timer(5, [Mode::Masked, Mode::Masked]).unwrap().tag, 10);
        assert_eq!(select_timer(9, [Mode::Ready, Mode::Ready]), None);
    }

    #[test]
    fn local_identity_requires_every_byte_and_the_success_tag() {
        let first = [7; 20];
        assert!(local_match(0x2e, &first, &first));
        assert!(!local_match(0x10, &first, &first));
        for index in 0..20 {
            let mut other = first;
            other[index] ^= 1;
            assert!(!local_match(0x2e, &first, &other));
        }
    }

    #[test]
    fn only_two_outer_states_are_valid() {
        for state in 0..=u8::MAX {
            let expected = match state {
                0 => Entry::Start,
                3 => Entry::Resume,
                _ => Entry::Invalid,
            };
            assert_eq!(entry(state), expected);
        }
    }
}
'''


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--out", required=True)
    args = parser.parse_args()
    print(json.dumps(generate(args.out), sort_keys=True))


if __name__ == "__main__":
    main()


