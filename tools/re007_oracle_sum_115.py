#!/usr/bin/env python3
"""Offline byte interpreter and independent models for a node #115 oracle accumulator."""

import argparse
import bisect
import collections
import json
import hashlib
import math
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


def check_digest(blob, expected):
    digest = hashlib.sha256(blob).hexdigest()
    if digest != expected:
        raise EvidenceError("binary SHA-256 mismatch: %s" % digest)
    return digest


def load_image(path=BINARY, expected=SHA256):
    blob = pathlib.Path(path).read_bytes()
    check_digest(blob, expected)
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


# The subject addresses are ELF virtual addresses, not file offsets.  The FDEs
# and instruction bytes are authenticated before any cases are interpreted.
FOLD = 0x543D4C0
FOLD_SIBLING = 0x543D630
FOLDS = (FOLD, FOLD_SIBLING)
TREE_NEXT = 0x51356D0
UNWRAP_SLOT = 0x64DF830
ITERATOR = HEAP_BASE + 0x100
FIRST = HEAP_BASE + 0x1000
SECOND = HEAP_BASE + 0x5000
NODES = HEAP_BASE + 0x10000
NODE_SIZE = 0x2B0
U64 = (1 << 64) - 1


def saturating_sum(values, initial=0):
    """An independent, unsigned mathematical specification for one fold."""
    if not 0 <= initial <= U64:
        raise ValueError("initial value is outside u64")
    total = initial
    for value in values:
        if not 0 <= value <= U64:
            raise ValueError("row value is outside u64")
        total = min(U64, total + value)
    return total


class Node:
    """A logical tree node; keys are opaque 20-byte identities, not numbers."""

    def __init__(self, entries, children=()):
        self.entries = tuple(entries)
        self.children = tuple(children)
        if not 1 <= len(self.entries) <= 11:
            raise ValueError("node must hold between one and eleven entries")
        if self.children and len(self.children) != len(self.entries) + 1:
            raise ValueError("internal node must have one more child than entry")
        for key, value in self.entries:
            if len(key) != 20 or not 0 <= value <= U64:
                raise ValueError("invalid key or value")


def tree_entries(node):
    """Enumerate a logical tree in order without using iterator state."""
    if node is None:
        return
    for index, entry in enumerate(node.entries):
        if node.children:
            yield from tree_entries(node.children[index])
        yield entry
    if node.children:
        yield from tree_entries(node.children[-1])


def leftmost_leaf(node):
    while node.children:
        node = node.children[0]
    return node


def tree_steps(node):
    """Expected entry and next logical cursor after each successful step."""
    if node is None:
        return
    for index, entry in enumerate(node.entries):
        if node.children:
            yield from tree_steps(node.children[index])
            yield entry, leftmost_leaf(node.children[index + 1]), 0
        else:
            yield entry, node, index + 1
    if node.children:
        yield from tree_steps(node.children[-1])


def node_height(node):
    if node is None:
        return 0
    if not node.children:
        return 0
    heights = [node_height(child) for child in node.children]
    if len(set(heights)) != 1:
        raise ValueError("tree leaves are not at the same height")
    return heights[0] + 1


class Case:
    def __init__(self, name, initial, first=(), second=(), tree=None, tree_mode=False):
        if not 0 <= initial <= U64:
            raise ValueError("initial value is outside u64")
        self.name = name
        self.initial = initial
        self.first = tuple(first)
        self.second = tuple(second)
        self.tree = tree
        self.tree_mode = tree_mode
        if tree_mode and (self.first or self.second):
            raise ValueError("tree and ring inputs cannot be combined")
        for key, value in self.entries():
            if len(key) != 20 or not 0 <= value <= U64:
                raise ValueError("invalid key or value")
        if tree_mode:
            node_height(tree)

    def entries(self):
        if self.tree_mode:
            yield from tree_entries(self.tree)
        else:
            yield from self.first
            yield from self.second

    def expected(self):
        return saturating_sum((value for _key, value in self.entries()), self.initial)


class Arena:
    def __init__(self):
        self.next = NODES

    def allocate(self):
        result = self.next
        self.next += NODE_SIZE
        if self.next > HEAP_BASE + HEAP_SIZE:
            raise Halt("tree exceeds interpreter arena")
        return result


class OracleFoldRig:
    """Lay out independent logical cases as input bytes for both target bodies."""

    def __init__(self, image, patches=None):
        self.machine = Machine(image, patches)
        self.machine.real = frozenset((TREE_NEXT,))
        self.machine.memory.statics[UNWRAP_SLOT] = MARK_BASE + UNWRAP_SLOT
        self.machine.slots[MARK_BASE + UNWRAP_SLOT] = self.unwrap

    @staticmethod
    def unwrap(_machine):
        raise Panicked("iterator unwrap")

    def write_node(self, arena, node, parent=0, parent_index=0):
        memory = self.machine.memory
        address = arena.allocate()
        self.node_addresses[id(node)] = address
        memory.put_bytes(address, bytes(NODE_SIZE))
        memory.write(address + 0x160, 8, parent)
        memory.write(address + 0x244, 2, parent_index)
        memory.write(address + 0x246, 2, len(node.entries))
        for index, (key, value) in enumerate(node.entries):
            memory.put_bytes(address + 0x168 + index * 20, key)
            memory.write(address + 0x18 + index * 32, 8, value)
        for index, child in enumerate(node.children):
            child_address = self.write_node(arena, child, address, index)
            memory.write(address + 0x248 + index * 8, 8, child_address)
        return address

    def write_segment(self, base, entries):
        memory = self.machine.memory
        if len(entries) * 56 > SECOND - FIRST:
            raise ValueError("segment too large")
        for index, (key, value) in enumerate(entries):
            row = base + index * 56
            memory.put_bytes(row, bytes([0xB7]) * 56)
            memory.put_bytes(row, key)
            memory.write(row + 0x30, 8, value)
        return base, base + len(entries) * 56

    def prepare(self, case):
        machine = self.machine
        # Every node and ring row is initialized separately; a full 4 MiB heap
        # refill on every case would dominate both runtime and memory traffic.
        machine.memory.reset(0x10000)
        machine.seen.clear()
        machine.steps = 0
        self.node_addresses = {}
        memory = machine.memory
        memory.put_bytes(ITERATOR, bytes(72))
        if case.tree_mode:
            arena = Arena()
            root = self.write_node(arena, case.tree) if case.tree else 0
            memory.write(ITERATOR, 8, 1)
            memory.write(ITERATOR + 8, 8, 0)
            memory.write(ITERATOR + 0x10, 8, root)
            memory.write(ITERATOR + 0x18, 8, node_height(case.tree))
            memory.write(ITERATOR + 0x40, 8, sum(1 for _ in case.entries()))
            return arena.next - HEAP_BASE
        first_begin, first_end = self.write_segment(FIRST, case.first)
        second_begin, second_end = self.write_segment(SECOND, case.second)
        for offset, value in ((0, 2), (8, first_begin), (16, first_end),
                              (24, second_begin), (32, second_end)):
            memory.write(ITERATOR + offset, 8, value)
        return SECOND - HEAP_BASE + 56 * len(case.second)

    def run_fold(self, case, entry=FOLD):
        if entry not in FOLDS:
            raise ValueError("not a subject fold")
        used = self.prepare(case)
        machine = self.machine
        before = hashlib.sha256(memoryview(machine.memory.heap)[:used]).digest()
        result = machine.run(entry, {RDI: ITERATOR, RSI: case.initial})
        after = hashlib.sha256(memoryview(machine.memory.heap)[:used]).digest()
        if before != after:
            raise Halt("fold modified the input or a container")
        return result

    def run_iterator(self, case):
        if not case.tree_mode:
            raise ValueError("direct iterator cases require a tree")
        used = self.prepare(case)
        machine = self.machine
        memory = machine.memory
        count = sum(1 for _ in case.entries())
        container_hash = hashlib.sha256(memoryview(memory.heap)[NODES - HEAP_BASE:used]).digest()
        for index, (expected, next_node, next_index) in enumerate(tree_steps(case.tree)):
            key_address = machine.run(TREE_NEXT, {RDI: ITERATOR})
            if key_address == 0:
                raise Halt("iterator ended before the declared count")
            value_address = machine.regs[RDX] + 0x18
            actual = memory.bytes_at(key_address, 20), memory.read(value_address, 8)
            if actual != expected:
                raise Halt("iterator returned the wrong key or value")
            if (memory.read(ITERATOR + 8, 8) != self.node_addresses[id(next_node)]
                    or memory.read(ITERATOR + 0x10, 8) != 0
                    or memory.read(ITERATOR + 0x18, 8) != next_index
                    or memory.read(ITERATOR + 0x40, 8) != count - index - 1):
                raise Halt("iterator cursor state differs")
        if machine.run(TREE_NEXT, {RDI: ITERATOR}) != 0:
            raise Halt("iterator did not stop after its declared count")
        after = hashlib.sha256(memoryview(memory.heap)[NODES - HEAP_BASE:used]).digest()
        if after != container_hash:
            raise Halt("iterator modified a tree node")
        return count


class Sequence:
    """A fixed integer stream: no process seed, system clock or random module."""

    def __init__(self, seed):
        self.state = seed & U64
        self.ordinal = 0

    def next(self):
        value = self.state
        value ^= value << 13 & U64
        value ^= value >> 7
        value ^= value << 17 & U64
        self.state = value & U64
        return self.state

    def entry(self):
        key = self.ordinal.to_bytes(20, "big")
        self.ordinal += 1
        value = interesting(self.next())
        return key, value


class SmallSequence:
    """Distinct keys and small values expose skipped or repeated tree rows."""

    def __init__(self):
        self.ordinal = 0

    def entry(self):
        ordinal = self.ordinal
        self.ordinal += 1
        return ordinal.to_bytes(20, "big"), 1 + ordinal % 7


def interesting(value):
    boundaries = (0, 1, 2, 9, 10, 11, 0xFFFFFFFF, 1 << 32,
                  (1 << 63) - 1, 1 << 63, U64 - 2, U64 - 1, U64)
    return boundaries[(value >> 3) % len(boundaries)] if value & 3 else value


def make_tree(height, width, sequence):
    if height < 0 or not 1 <= width <= 3:
        raise ValueError("unsupported tree shape")
    entries = []
    children = []
    for _ in range(width):
        if height:
            children.append(make_tree(height - 1, width, sequence))
        entries.append(sequence.entry())
    if height:
        children.append(make_tree(height - 1, width, sequence))
    return Node(entries, children)


def named_cases():
    def entry(index, value):
        return index.to_bytes(20, "big"), value

    rows = [entry(0, 0), entry(1, 1), entry(2, 5), entry(3, U64 - 1),
            entry(4, U64), entry(5, 2)]
    yield Case("ring-empty", 0)
    yield Case("ring-initial-only", U64 - 1)
    yield Case("ring-first", 2, rows[:3])
    yield Case("ring-second", 0, (), rows[:3])
    yield Case("ring-wrap", 0, rows[:2], rows[2:3])
    yield Case("ring-overflow-first", 2, rows[3:4], rows[1:2])
    yield Case("ring-overflow-second", 0, rows[1:2], rows[4:5])
    yield Case("ring-maximum", U64, rows[1:3], rows[5:6])
    yield Case("empty-tree", 0, tree_mode=True)
    small = SmallSequence()
    yield Case("tree-leaf-eleven", 0, tree=Node([small.entry() for _ in range(11)]), tree_mode=True)
    for height, width in ((0, 1), (0, 3), (1, 1), (1, 3), (2, 1), (3, 1)):
        sequence = Sequence(0x91E10DA5 + height * 13 + width)
        yield Case("tree-h%d-w%d" % (height, width), height,
                   tree=make_tree(height, width, sequence), tree_mode=True)


def deep_cases():
    for height in (8, 9):
        yield Case("tree-deep-%d" % height, 0,
                   tree=make_tree(height, 1, SmallSequence()), tree_mode=True)


def generated_cases(count):
    """Generate cases lazily, each with bounded and independently defined data."""
    sequence = Sequence(0xC409D7E356817A2B)
    for index, case in enumerate(named_cases()):
        if index >= count:
            return
        yield case
    already = index + 1
    for index in range(already, count):
        initial = interesting(sequence.next())
        if index % 4 == 0:
            height = (sequence.next() >> 8) % 3
            width = 1 + (sequence.next() >> 9) % (3 if height < 2 else 2)
            tree = make_tree(height, width, sequence)
            yield Case("tree-%d" % index, initial, tree=tree, tree_mode=True)
        else:
            first_count = (sequence.next() >> 5) % 9
            second_count = (sequence.next() >> 6) % 9
            first = tuple(sequence.entry() for _ in range(first_count))
            second = tuple(sequence.entry() for _ in range(second_count))
            yield Case("ring-%d" % index, initial, first, second)


def body_rows(image):
    result = {}
    for entry in (*FOLDS, TREE_NEXT):
        start, end = image.exact_fde(entry)
        rows = decode_range(image, start, end)
        result[entry] = (start, end, rows)
    return result


def branch_mutations(bodies, reached):
    """Invert every reached conditional branch, once, without masking bytes."""
    for entry, (_start, _end, rows) in bodies.items():
        for row in rows:
            if row.op != "jcc" or row.va not in reached:
                continue
            if 0x70 <= row.data[0] <= 0x7F:
                offset = 0
            elif row.data[0] == 0x0F and 0x80 <= row.data[1] <= 0x8F:
                offset = 1
            else:
                raise EvidenceError("unexpected conditional encoding at %#x" % row.va)
            original = row.data[offset]
            yield entry, row.va, row.va + offset, original, original ^ 1


def baseline_probes(image, cases):
    reached = set()
    rig = OracleFoldRig(image)
    for case in cases:
        for entry in FOLDS:
            actual = rig.run_fold(case, entry)
            if actual != case.expected():
                raise EvidenceError("baseline fold differs for " + case.name)
            reached.update(rig.machine.seen)
        if case.tree_mode:
            count = rig.run_iterator(case)
            if count != sum(1 for _ in case.entries()):
                raise EvidenceError("baseline iterator differs for " + case.name)
            reached.update(rig.machine.seen)
    return reached


def exception_result(error):
    detail = str(error).replace("\t", " ").replace("\n", " ")
    return type(error).__name__ + (": " + detail[:160] if detail else "")


def detect_mutation(image, mutation, cases):
    entry, _instruction, patch, _original, replacement = mutation
    rig = OracleFoldRig(image, {patch: replacement})
    for case in cases:
        if entry == TREE_NEXT and not case.tree_mode:
            continue
        # Deep folds need more interpreter steps than an individual tree step.
        rig.machine.step_limit = 140000 if case.name.startswith("tree-deep") and entry != TREE_NEXT else 5000
        try:
            if entry == TREE_NEXT:
                actual = rig.run_iterator(case)
                expected = sum(1 for _ in case.entries())
            else:
                actual = rig.run_fold(case, entry)
                expected = case.expected()
            if actual != expected:
                return True, case.name, "wrong result"
        except (Halt, EvidenceError, Panicked, IndexError, KeyError,
                ValueError, OverflowError, struct.error) as error:
            return True, case.name, exception_result(error)
    return False, "", "not detected"


def branch_controls(image, bodies):
    # The full trees are deliberately retained as case inputs only; execution
    # results and emulator traces are checked and discarded one at a time.
    cases = tuple(named_cases()) + tuple(deep_cases())
    reached = baseline_probes(image, cases)
    controls = []
    for mutation in branch_mutations(bodies, reached):
        detected, case, reason = detect_mutation(image, mutation, cases)
        controls.append((*mutation, detected, case, reason))
    return controls, reached


# The two nested walkers traverse the same outer 20-byte-key map and two
# variants of the inner u64-key map.  Their surrounding owners have not been
# reconstructed: these types intentionally describe only the observed layout.
NESTED_A = 0x5AB8240
NESTED_B = 0x5AB8BD0
INNER_A = 0x5139A50
INNER_B = 0x5137810
NESTED_WALKERS = (NESTED_A, NESTED_B)
NESTED_STATE = HEAP_BASE + 0x400
NESTED_OUT = HEAP_BASE + 0x700
TREE_MARKER = 1 << 63
SIZE_HINT = 0x5AB9560
HINT_OUT = HEAP_BASE + 0x880


def phase_hint(done, outer_remaining, current_remaining, supplement_remaining):
    """Lower and optional upper bounds for one phase's remaining output."""
    for value in (outer_remaining, current_remaining, supplement_remaining):
        if not 0 <= value <= U64:
            raise ValueError("iterator count outside u64")
    if done:
        return 0, 0
    total = current_remaining + supplement_remaining
    lower = min(total, U64)
    upper = total if outer_remaining == 0 and total <= U64 else None
    return lower, upper


def combine_hints(first, second):
    low_a, high_a = first
    low_b, high_b = second
    lower = min(U64, low_a + low_b)
    if high_a is None or high_b is None or high_a + high_b > U64:
        return lower, None
    return lower, high_a + high_b


def filter_word(inner_key, salt=0):
    """Fixture payload used to make equality and inequality paths observable."""
    return (inner_key ^ (inner_key >> 5) ^ salt) & 7


def terminal_after_call(state):
    """The second phase swaps its empty ring ranges on an exhausted call."""
    if len(state) != 0x210:
        raise ValueError("nested iterator state must be 0x210 bytes")
    result = bytearray(state)
    if int.from_bytes(state[0x108:0x110], "little") == 2:
        first = bytes(result[0x110:0x120])
        second = bytes(result[0x120:0x130])
        result[0x110:0x120] = second
        result[0x120:0x130] = first
    return bytes(result)


class InnerCollection:
    def __init__(self, kind, keys=(), tree=None, capacity=0, head=0, salt=0):
        if kind not in ("ring", "tree"):
            raise ValueError("unknown inner collection kind")
        self.kind = kind
        self.keys = tuple(keys)
        self.tree = tree
        self.capacity = capacity
        self.head = head
        self.salt = salt
        if not 0 <= salt <= U64:
            raise ValueError("fixture salt is outside u64")
        if kind == "tree":
            if self.keys or capacity or head:
                raise ValueError("unexpected ring fields in tree collection")
            node_height(tree)
        elif tree is not None or capacity < len(self.keys) or capacity < 1 or not 0 <= head < capacity:
            raise ValueError("invalid ring layout")
        values = tuple(self.items())
        self._count = len(values)
        if any(not 0 <= value <= U64 for value in values):
            raise ValueError("inner key outside u64")
        if list(values) != sorted(set(values)):
            raise ValueError("inner keys must be strictly increasing")

    def items(self):
        if self.kind == "ring":
            yield from self.keys
        else:
            for key, _ in tree_entries(self.tree):
                yield int.from_bytes(key, "big")

    def count(self):
        return self._count

    def filter_of(self, key):
        return filter_word(key, self.salt)


class OuterCollection:
    def __init__(self, kind, entries=(), tree=None, capacity=0, head=0):
        if kind not in ("ring", "tree"):
            raise ValueError("unknown outer collection kind")
        self.kind = kind
        self.entries = tuple(entries)
        self.tree = tree
        self.capacity = capacity
        self.head = head
        if kind == "tree":
            if capacity or head:
                raise ValueError("unexpected ring fields in tree collection")
            node_height(tree)
            tree_keys = tuple(key for key, _ in tree_entries(tree))
            if tree_keys != tuple(key for key, _ in self.entries):
                raise ValueError("outer tree keys do not match its entries")
        elif tree is not None or capacity < len(self.entries) or capacity < 1 or not 0 <= head < capacity:
            raise ValueError("invalid outer ring layout")
        keys = [key for key, _ in self.entries]
        if any(len(key) != 20 for key in keys) or keys != sorted(set(keys)):
            raise ValueError("outer keys must be distinct 20-byte values in order")
        if any(not isinstance(value, InnerCollection) for _, value in self.entries):
            raise ValueError("outer entries must contain inner collections")


class NestedPhase:
    def __init__(self, outer, supplement, supplement_key):
        if len(supplement_key) != 20:
            raise ValueError("supplement key must contain 20 bytes")
        self.outer = outer
        self.supplement = supplement
        self.supplement_key = supplement_key

    def items(self):
        for key, inner, _group, _index, _supplement in self.events():
            yield key, inner

    def events(self):
        for group, (outer_key, child) in enumerate(self.outer.entries):
            for index, inner_key in enumerate(child.items()):
                yield outer_key, inner_key, group, index, False
        for index, inner_key in enumerate(self.supplement.items()):
            yield self.supplement_key, inner_key, len(self.outer.entries), index, True

    def outer_count(self):
        return sum(child.count() for _, child in self.outer.entries)


class NestedCase:
    def __init__(self, name, first, second):
        self.name = name
        self.phases = (first, second)

    def items(self):
        for phase in self.phases:
            yield from phase.items()

    def events(self):
        for phase_index, phase in enumerate(self.phases):
            for event in phase.events():
                yield phase_index, *event

    def count(self):
        return sum(1 for _ in self.items())


class NestedArena:
    def __init__(self, memory):
        self.memory = memory
        self.next = NODES

    def allocate(self, size):
        address = self.next
        self.next = (address + size + 15) & ~15
        if self.next > HEAP_BASE + HEAP_SIZE:
            raise Halt("nested fixture exceeds interpreter arena")
        self.memory.put_bytes(address, bytes(self.next - address))
        return address


class NestedRig:
    """Materialize both alternative representations and call real byte bodies."""

    def __init__(self, image, patches=None):
        self.machine = Machine(image, patches)
        self.machine.real = frozenset((TREE_NEXT, INNER_A, INNER_B))
        self.machine.memory.statics[UNWRAP_SLOT] = MARK_BASE + UNWRAP_SLOT
        self.machine.slots[MARK_BASE + UNWRAP_SLOT] = OracleFoldRig.unwrap
        self.arena = None
        self.hint_checks = 0

    def write_words(self, address, words):
        for index, word in enumerate(words):
            self.machine.memory.write(address + index * 8, 8, word)

    def inner_node(self, node, phase, salt, parent=0, parent_index=0):
        memory = self.machine.memory
        key_header = 0x428 if phase == 0 else 0x4D8
        children_offset = key_header + 8
        value_stride = 0x58 if phase == 0 else 0x68
        address = self.arena.allocate(children_offset + 12 * 8)
        memory.write(address, 8, parent)
        memory.write(address + key_header, 2, parent_index)
        memory.write(address + key_header + 2, 2, len(node.entries))
        for index, (key, value) in enumerate(node.entries):
            number = int.from_bytes(key, "big")
            memory.write(address + 8 + index * 8, 8, number)
            memory.put_bytes(address + 0x60 + index * value_stride,
                             bytes([value & 0xFF]) * value_stride)
            memory.write(address + 0x60 + index * value_stride + 0x10, 8, filter_word(number, salt))
        for index, child in enumerate(node.children):
            child_addr = self.inner_node(child, phase, salt, address, index)
            memory.write(address + children_offset + index * 8, 8, child_addr)
        return address

    def inner_header(self, collection, phase):
        if collection.kind == "tree":
            root = self.inner_node(collection.tree, phase, collection.salt) if collection.tree else 0
            return TREE_MARKER, root, node_height(collection.tree), collection.count()
        stride = 0x60 if phase == 0 else 0x70
        address = self.arena.allocate(collection.capacity * stride)
        for index, key in enumerate(collection.keys):
            row = address + ((collection.head + index) % collection.capacity) * stride
            self.machine.memory.write(row, 8, key)
            self.machine.memory.write(row + 0x18, 8, collection.filter_of(key))
        return collection.capacity, address, collection.head, len(collection.keys)

    def outer_node(self, node, collection, phase, parent=0, parent_index=0):
        memory = self.machine.memory
        address = self.arena.allocate(NODE_SIZE)
        memory.write(address + 0x160, 8, parent)
        memory.write(address + 0x244, 2, parent_index)
        memory.write(address + 0x246, 2, len(node.entries))
        by_key = dict(collection.entries)
        for index, (key, _value) in enumerate(node.entries):
            memory.put_bytes(address + 0x168 + index * 20, key)
            self.write_words(address + index * 32, self.inner_header(by_key[key], phase))
        for index, child in enumerate(node.children):
            child_addr = self.outer_node(child, collection, phase, address, index)
            memory.write(address + 0x248 + index * 8, 8, child_addr)
        return address

    def outer_header(self, collection, phase):
        if collection.kind == "tree":
            root = self.outer_node(collection.tree, collection, phase) if collection.tree else 0
            return TREE_MARKER, root, node_height(collection.tree), len(collection.entries)
        address = self.arena.allocate(collection.capacity * 56)
        for index, (key, child) in enumerate(collection.entries):
            row = address + ((collection.head + index) % collection.capacity) * 56
            self.machine.memory.put_bytes(row, key)
            self.write_words(row + 0x18, self.inner_header(child, phase))
        return collection.capacity, address, collection.head, len(collection.entries)

    def write_cursor(self, address, header, stride):
        capacity, base, head, count = header
        if capacity == TREE_MARKER:
            tag = int(base != 0)
            self.write_words(address, (tag, 0, base, head, 0, 0, base, head, count if base else 0))
            return
        first_count = min(count, capacity - head)
        second_count = count - first_count
        first = base + head * stride
        first_end = first + first_count * stride
        second = base
        second_end = base + second_count * stride
        self.write_words(address, (2, first, first_end, second, second_end,
                                   0, first_end, second, second_end))

    def cursor_remaining(self, address, stride):
        memory = self.machine.memory
        tag = memory.read(address, 8)
        if tag == 1:
            return memory.read(address + 0x40, 8)
        if tag in (0, 3, 4):
            return 0
        if tag != 2:
            raise Halt("unknown iterator state")
        front = memory.read(address + 8, 8)
        front_end = memory.read(address + 0x10, 8)
        back = memory.read(address + 0x18, 8)
        back_end = memory.read(address + 0x20, 8)
        if front_end < front or back_end < back:
            raise Halt("iterator range is reversed")
        first, second = front_end - front, back_end - back
        if first % stride or second % stride:
            raise Halt("iterator range is not row-aligned")
        return first // stride + second // stride

    def expected_hint(self):
        phases = []
        for index, stride in ((0, 0x60), (1, 0x70)):
            state = NESTED_STATE + index * 0x108
            done = self.machine.memory.read(state, 8) == 4
            phases.append(phase_hint(done, self.cursor_remaining(state, 56),
                                     self.cursor_remaining(state + 0x48, stride),
                                     self.cursor_remaining(state + 0xA8, stride)))
        return combine_hints(*phases)

    def check_hint(self, actual_remaining=None):
        memory = self.machine.memory
        expected_lower, expected_upper = self.expected_hint()
        before = memory.bytes_at(NESTED_STATE, 0x210)
        memory.put_bytes(HINT_OUT, bytes([0xDA]) * 32)
        self.machine.run(SIZE_HINT, {RDI: HINT_OUT, RSI: NESTED_STATE})
        lower = memory.read(HINT_OUT, 8)
        tag = memory.read(HINT_OUT + 8, 8)
        upper = memory.read(HINT_OUT + 16, 8) if tag == 1 else None
        if tag not in (0, 1) or (lower, upper) != (expected_lower, expected_upper):
            raise Halt("size hint differs from the independent bound")
        if memory.bytes_at(HINT_OUT + 24, 8) != bytes([0xDA]) * 8:
            raise Halt("size hint wrote beyond its output")
        if memory.bytes_at(NESTED_STATE, 0x210) != before:
            raise Halt("size hint mutated iterator state")
        if actual_remaining is not None:
            if lower > actual_remaining or (upper is not None and upper != actual_remaining):
                raise Halt("size hint does not bound the logical remaining rows")
        self.hint_checks += 1
        return lower, upper

    def prepare(self, case):
        machine = self.machine
        memory = machine.memory
        memory.reset(0x10000)
        memory.put_bytes(NESTED_STATE, bytes(0x210))
        memory.put_bytes(NESTED_OUT, bytes(0x40))
        machine.seen.clear()
        machine.steps = 0
        self.arena = NestedArena(memory)
        for phase_index, phase in enumerate(case.phases):
            offset = 0x108 * phase_index
            outer_header = self.outer_header(phase.outer, phase_index)
            supplement_header = self.inner_header(phase.supplement, phase_index)
            self.write_cursor(NESTED_STATE + offset, outer_header, 56)
            memory.write(NESTED_STATE + offset + 0x48, 8, 3)
            self.write_cursor(NESTED_STATE + offset + 0xA8, supplement_header,
                              0x60 if phase_index == 0 else 0x70)
            memory.put_bytes(NESTED_STATE + offset + 0xF0, phase.supplement_key)
        return self.arena.next - HEAP_BASE

    def run(self, case, entry=NESTED_A, with_hint=False):
        if entry not in NESTED_WALKERS:
            raise ValueError("not a nested walker")
        used = self.prepare(case)
        machine = self.machine
        memory = machine.memory
        # The sum helper takes a by-value cursor.  Check both initial outer
        # phases and ensure it leaves the caller's iterator state untouched.
        for phase_index, phase in enumerate(case.phases):
            state = NESTED_STATE + phase_index * 0x108
            before = memory.bytes_at(state, 0x48)
            for fold in FOLDS:
                actual = machine.run(fold, {RDI: state, RSI: 0})
                if actual != phase.outer_count():
                    raise Halt("outer count does not match the nested collection")
                if memory.bytes_at(state, 0x48) != before:
                    raise Halt("fold mutated its caller's iterator")
        data_hash = hashlib.sha256(memoryview(memory.heap)[NODES - HEAP_BASE:used]).digest()
        expected_count = case.count()
        for emitted, (phase_index, expected_key, expected_inner, group, index, supplement) in enumerate(case.events()):
            if with_hint:
                self.check_hint(expected_count - emitted)
            memory.put_bytes(NESTED_OUT, bytes([0x9D]) * 0x40)
            machine.run(entry, {RDI: NESTED_OUT, RSI: NESTED_STATE})
            tag = memory.read(NESTED_OUT, 8)
            key = memory.bytes_at(NESTED_OUT + 8, 20)
            inner = memory.read(NESTED_OUT + 0x20, 8)
            if (tag, key, inner) != (1, expected_key, expected_inner):
                raise Halt("nested walker returned an unexpected row")
            phase = case.phases[phase_index]
            state = NESTED_STATE + phase_index * 0x108
            stride = 0x60 if phase_index == 0 else 0x70
            if phase_index == 1:
                if memory.read(NESTED_STATE, 8) != 4:
                    raise Halt("first phase has not completed")
                if self.cursor_remaining(NESTED_STATE + 0xA8, 0x60):
                    raise Halt("first phase supplement has unread rows")
            if supplement:
                if self.cursor_remaining(state, 56):
                    raise Halt("supplement entered before the outer map ended")
                remaining = phase.supplement.count() - index - 1
                if self.cursor_remaining(state + 0xA8, stride) != remaining:
                    raise Halt("supplement cursor differs")
            else:
                remaining_outer = len(phase.outer.entries) - group - 1
                if self.cursor_remaining(state, 56) != remaining_outer:
                    raise Halt("outer cursor differs")
                child = phase.outer.entries[group][1]
                if self.cursor_remaining(state + 0x48, stride) != child.count() - index - 1:
                    raise Halt("inner cursor differs")
                if memory.bytes_at(state + 0x90, 20) != expected_key:
                    raise Halt("cached outer key differs")
        memory.put_bytes(NESTED_OUT, bytes([0x9D]) * 0x40)
        machine.run(entry, {RDI: NESTED_OUT, RSI: NESTED_STATE})
        if memory.read(NESTED_OUT, 8) != 0:
            raise Halt("nested walker failed to terminate")
        if with_hint:
            self.check_hint(0)
        terminal = memory.bytes_at(NESTED_STATE, 0x210)
        memory.put_bytes(NESTED_OUT, bytes([0x9D]) * 0x40)
        machine.run(entry, {RDI: NESTED_OUT, RSI: NESTED_STATE})
        # An exhausted second-phase ring swaps its two empty ranges on each
        # further call.  No row is emitted and all other fields remain fixed.
        expected_terminal = terminal_after_call(terminal)
        if memory.read(NESTED_OUT, 8) != 0 or memory.bytes_at(NESTED_STATE, 0x210) != expected_terminal:
            raise Halt("terminal iterator state differs")
        after = hashlib.sha256(memoryview(memory.heap)[NODES - HEAP_BASE:used]).digest()
        if after != data_hash:
            raise Halt("nested walker modified the source collections")
        return expected_count


class OffsetSequence:
    def __init__(self, base):
        self.base = base
        self.ordinal = 0

    def entry(self):
        value = self.base + self.ordinal
        self.ordinal += 1
        return value.to_bytes(20, "big"), (value % 251) + 1


def inner_fixture(kind, seed, nonempty=False):
    base = (seed & 0xFFFF) * 64
    salt = (seed >> 22) & 7
    if kind == "tree":
        if seed % 7 == 0 and not nonempty:
            return InnerCollection("tree", salt=salt)
        height = (seed >> 3) % 3
        width = 1 if height == 2 else 1 + (seed >> 6) % 2
        return InnerCollection("tree", tree=make_tree(height, width, OffsetSequence(base)), salt=salt)
    count = (seed >> 4) % 6
    if nonempty:
        count = max(1, count)
    keys = tuple(base + 2 * index for index in range(count))
    capacity = max(1, count + 1 + (seed >> 10) % 3)
    head = (seed >> 14) % capacity
    return InnerCollection("ring", keys, capacity=capacity, head=head, salt=salt)


def outer_fixture(kind, seed, child_kind=None, nonempty=False):
    seq = Sequence(seed ^ 0x8752E4B31C9A6D0F)
    if kind == "tree":
        if seed % 11 == 0 and not nonempty:
            return OuterCollection("tree")
        height = (seed >> 8) % 2
        width = 1 + (seed >> 12) % 2
        tree = make_tree(height, width, OffsetSequence((seed & 0xFFFF) * 32))
        entries = []
        for key, _value in tree_entries(tree):
            choice = child_kind or ("tree" if seq.next() & 1 else "ring")
            entries.append((key, inner_fixture(choice, seq.next(), nonempty)))
        return OuterCollection("tree", entries, tree=tree)
    count = (seed >> 9) % 5
    if nonempty:
        count = max(1, count)
    capacity = max(1, count + 1 + (seed >> 15) % 3)
    head = (seed >> 19) % capacity
    entries = []
    for index in range(count):
        key = ((seed & 0xFFFF) * 32 + index).to_bytes(20, "big")
        choice = child_kind or ("tree" if seq.next() & 1 else "ring")
        entries.append((key, inner_fixture(choice, seq.next(), nonempty)))
    return OuterCollection("ring", entries, capacity=capacity, head=head)


def nested_fixture(index, force_matrix=False):
    sequence = Sequence(0x5BC12F4D7788A621 ^ ((index + 1) * 0x9E3779B97F4A7C15 & U64))
    phases = []
    for phase in range(2):
        if force_matrix:
            outer_kind = "tree" if index & (1 << (phase * 3)) else "ring"
            child_kind = "tree" if index & (2 << (phase * 3)) else "ring"
            supplement_kind = "tree" if index & (4 << (phase * 3)) else "ring"
        else:
            outer_kind = "tree" if sequence.next() & 1 else "ring"
            child_kind = None
            supplement_kind = "tree" if sequence.next() & 1 else "ring"
        outer = outer_fixture(outer_kind, sequence.next(), child_kind, force_matrix)
        supplement = inner_fixture(supplement_kind, sequence.next(), force_matrix)
        supplement_key = ((phase + 1) * (1 << 48) + index).to_bytes(20, "big")
        phases.append(NestedPhase(outer, supplement, supplement_key))
    return NestedCase("nested-%d" % index, *phases)


def nested_cases(count):
    for index in range(count):
        yield nested_fixture(index, force_matrix=index < 64)


def deep_nested_cases():
    for phase in (0, 1):
        for height in (8, 9):
            tree = make_tree(height, 1, OffsetSequence(0))
            child = InnerCollection("tree", tree=tree)
            empty_inner = InnerCollection("ring", (), capacity=1)
            active_outer = OuterCollection("ring", ((bytes(20), child),), capacity=1)
            empty_outer = OuterCollection("ring", (), capacity=1)
            active = NestedPhase(active_outer, empty_inner, bytes(20))
            empty = NestedPhase(empty_outer, empty_inner, bytes(20))
            phases = (active, empty) if phase == 0 else (empty, active)
            yield NestedCase("deep-inner-%d-%d" % (phase, height), *phases)


def nested_body_rows(image):
    result = {}
    for entry in (*NESTED_WALKERS, INNER_A, INNER_B):
        start, end = image.exact_fde(entry)
        result[entry] = (start, end, decode_range(image, start, end))
    return result


def nested_baseline_probes(image, cases):
    rig = NestedRig(image)
    reached = set()
    for case in cases:
        for entry in NESTED_WALKERS:
            if rig.run(case, entry) != case.count():
                raise EvidenceError("baseline nested walk differs for " + case.name)
            reached.update(rig.machine.seen)
    return reached


def detect_nested_mutation(image, mutation, cases):
    target, _instruction, patch, _original, replacement = mutation
    entry = target if target in NESTED_WALKERS else NESTED_A
    rig = NestedRig(image, {patch: replacement})
    rig.machine.step_limit = 5000
    for case in cases:
        try:
            if rig.run(case, entry) != case.count():
                return True, case.name, "wrong result"
        except (Halt, EvidenceError, Panicked, IndexError, KeyError,
                ValueError, OverflowError, struct.error) as error:
            return True, case.name, exception_result(error)
    return False, "", "not detected"


def nested_branch_controls(image, bodies):
    cases = tuple(nested_cases(80)) + tuple(deep_nested_cases())
    reached = nested_baseline_probes(image, cases)
    controls = []
    for mutation in branch_mutations(bodies, reached):
        detected, case, reason = detect_nested_mutation(image, mutation, cases)
        controls.append((*mutation, detected, case, reason))
    return controls, reached


# Filtered walkers operate on the first inner-map layout.  The comparison word
# is a field of each value, not its u64 key; it is supplied by the fixture.
FILTERED_A = 0x5ACEC10
FILTERED_B = 0x5ACF070
FILTERED_WALKERS = (FILTERED_A, FILTERED_B)
FILTER_CELL = HEAP_BASE + 0x800


class FilteredCase:
    def __init__(self, name, phase, wanted):
        if not 0 <= wanted <= U64:
            raise ValueError("filter is outside u64")
        self.name = name
        self.phase = phase
        self.wanted = wanted

    def events(self):
        for key, inner, group, index, supplement in self.phase.events():
            collection = self.phase.supplement if supplement else self.phase.outer.entries[group][1]
            if collection.filter_of(inner) == self.wanted:
                yield key, inner, group, index, supplement

    def count(self):
        return sum(1 for _ in self.events())


def filtered_terminal_after_call(state):
    if len(state) != 0x120:
        raise ValueError("filtered iterator state must be 0x120 bytes")
    result = bytearray(state)
    if int.from_bytes(state[:8], "little") == 2:
        first, second = bytes(result[8:24]), bytes(result[24:40])
        result[8:24], result[24:40] = second, first
    return bytes(result)


class FilteredRig(NestedRig):
    def prepare_filtered(self, case):
        machine = self.machine
        memory = machine.memory
        memory.reset(0x10000)
        memory.put_bytes(NESTED_STATE, bytes(0x120))
        memory.put_bytes(NESTED_OUT, bytes(0x40))
        memory.write(FILTER_CELL, 8, case.wanted)
        machine.seen.clear()
        machine.steps = 0
        self.arena = NestedArena(memory)
        phase = case.phase
        outer_header = self.outer_header(phase.outer, 0)
        supplement_header = self.inner_header(phase.supplement, 0)
        self.write_cursor(NESTED_STATE, outer_header, 56)
        memory.write(NESTED_STATE + 0x48, 8, FILTER_CELL)
        memory.write(NESTED_STATE + 0x50, 8, 3)
        self.write_cursor(NESTED_STATE + 0xB8, supplement_header, 0x60)
        memory.write(NESTED_STATE + 0x100, 8, FILTER_CELL)
        memory.put_bytes(NESTED_STATE + 0x108, phase.supplement_key)
        return self.arena.next - HEAP_BASE

    def run_filtered(self, case, entry=FILTERED_A):
        if entry not in FILTERED_WALKERS:
            raise ValueError("not a filtered walker")
        used = self.prepare_filtered(case)
        machine = self.machine
        memory = machine.memory
        data_hash = hashlib.sha256(memoryview(memory.heap)[NODES - HEAP_BASE:used]).digest()
        for expected_key, expected_inner, group, index, supplement in case.events():
            memory.put_bytes(NESTED_OUT, bytes([0xA7]) * 0x40)
            machine.run(entry, {RDI: NESTED_OUT, RSI: NESTED_STATE})
            tag = memory.read(NESTED_OUT, 8)
            key = memory.bytes_at(NESTED_OUT + 8, 20)
            inner = memory.read(NESTED_OUT + 0x20, 8)
            if (tag, key, inner) != (1, expected_key, expected_inner):
                raise Halt("filtered walker returned an unexpected row")
            if supplement:
                if self.cursor_remaining(NESTED_STATE, 56):
                    raise Halt("filtered supplement entered before the outer map ended")
                remaining = case.phase.supplement.count() - index - 1
                if self.cursor_remaining(NESTED_STATE + 0xB8, 0x60) != remaining:
                    raise Halt("filtered supplement cursor differs")
            else:
                remaining_outer = len(case.phase.outer.entries) - group - 1
                if self.cursor_remaining(NESTED_STATE, 56) != remaining_outer:
                    raise Halt("filtered outer cursor differs")
                child = case.phase.outer.entries[group][1]
                if self.cursor_remaining(NESTED_STATE + 0x50, 0x60) != child.count() - index - 1:
                    raise Halt("filtered inner cursor differs")
                if memory.bytes_at(NESTED_STATE + 0xA0, 20) != expected_key:
                    raise Halt("filtered cached outer key differs")
        memory.put_bytes(NESTED_OUT, bytes([0xA7]) * 0x40)
        machine.run(entry, {RDI: NESTED_OUT, RSI: NESTED_STATE})
        if memory.read(NESTED_OUT, 8) != 0:
            raise Halt("filtered walker failed to terminate")
        terminal = memory.bytes_at(NESTED_STATE, 0x120)
        machine.run(entry, {RDI: NESTED_OUT, RSI: NESTED_STATE})
        if (memory.read(NESTED_OUT, 8) != 0
                or memory.bytes_at(NESTED_STATE, 0x120) != filtered_terminal_after_call(terminal)):
            raise Halt("filtered terminal state differs")
        after = hashlib.sha256(memoryview(memory.heap)[NODES - HEAP_BASE:used]).digest()
        if after != data_hash:
            raise Halt("filtered walker modified a source collection")
        return case.count()


def filtered_cases(count):
    for index in range(count):
        case = nested_fixture(index, force_matrix=index < 64)
        # The low half covers every filter value, including absent values.
        wanted = index % 9
        yield FilteredCase("filter-%d" % index, case.phases[index & 1], wanted)


def filtered_body_rows(image):
    result = {}
    for entry in FILTERED_WALKERS:
        start, end = image.exact_fde(entry)
        result[entry] = (start, end, decode_range(image, start, end))
    return result


def filtered_branch_controls(image, bodies):
    cases = tuple(filtered_cases(80))
    baseline = FilteredRig(image)
    reached = set()
    for case in cases:
        for entry in FILTERED_WALKERS:
            if baseline.run_filtered(case, entry) != case.count():
                raise EvidenceError("filtered baseline differs for " + case.name)
            reached.update(baseline.machine.seen)
    controls = []
    for mutation in branch_mutations(bodies, reached):
        entry, _instruction, patch, _original, replacement = mutation
        rig = FilteredRig(image, {patch: replacement})
        rig.machine.step_limit = 5000
        detected, name, reason = False, "", "not detected"
        for case in cases:
            try:
                if rig.run_filtered(case, entry) != case.count():
                    detected, name, reason = True, case.name, "wrong result"
                    break
            except (Halt, EvidenceError, Panicked, IndexError, KeyError,
                    ValueError, OverflowError, struct.error) as error:
                detected, name, reason = True, case.name, exception_result(error)
                break
        controls.append((*mutation, detected, name, reason))
    return controls, reached


class HintCase:
    def __init__(self, name, first, second, ring_modes=(False,) * 6):
        self.name = name
        self.phases = (tuple(first), tuple(second))
        self.ring_modes = tuple(ring_modes)
        if len(self.ring_modes) != 6:
            raise ValueError("hint requires six representation flags")
        for phase in self.phases:
            if len(phase) != 4:
                raise ValueError("hint phase requires four fields")
            phase_hint(*phase)

    def expected(self):
        return combine_hints(*(phase_hint(*phase) for phase in self.phases))


def hint_cases():
    boundaries = (0, 1, U64 - 1, U64)
    index = 0
    for mask in range(16):
        for current_a in boundaries:
            for supplement_a in boundaries:
                for current_b in boundaries:
                    for supplement_b in boundaries:
                        first = (bool(mask & 1), int(bool(mask & 4)), current_a, supplement_a)
                        second = (bool(mask & 2), int(bool(mask & 8)), current_b, supplement_b)
                        yield HintCase("hint-%d" % index, first, second)
                        index += 1


def mixed_hint_cases():
    for mask in range(64):
        for done_mask in range(4):
            for variant in range(4):
                counts = tuple((mask // (index + 1) + variant + index) % 3 for index in range(6))
                first = (bool(done_mask & 1), *counts[:3])
                second = (bool(done_mask & 2), *counts[3:])
                modes = tuple(bool(mask & (1 << index)) for index in range(6))
                yield HintCase("hint-mixed-%d-%d-%d" % (mask, done_mask, variant), first, second, modes)


def prepare_hint(rig, case):
    memory = rig.machine.memory
    memory.reset(0x10000)
    memory.put_bytes(NESTED_STATE, bytes(0x210))
    rig.machine.seen.clear()
    rig.machine.steps = 0
    for index, (done, outer, current, supplement) in enumerate(case.phases):
        state = NESTED_STATE + 0x108 * index
        stride = 0x60 if index == 0 else 0x70
        for field, count, row_size, ring in zip((0, 0x48, 0xA8), (outer, current, supplement),
                                                (56, stride, stride), case.ring_modes[index * 3:index * 3 + 3]):
            cursor = state + field
            if ring:
                if count > 8:
                    raise ValueError("synthetic ring count is too large")
                first = 0x1000 + field
                split = count // 2
                second = 0x3000 + field
                rig.write_words(cursor, (2, first, first + split * row_size, second,
                                         second + (count - split) * row_size, 0, 0, 0, 0))
            else:
                memory.write(cursor, 8, 1)
                memory.write(cursor + 0x40, 8, count)
        if done:
            memory.write(state, 8, 4)


def run_hint_case(rig, case):
    prepare_hint(rig, case)
    expected = case.expected()
    actual = rig.check_hint()
    if actual != expected:
        raise Halt("synthetic size hint differs")
    return actual


def hint_body_rows(image):
    start, end = image.exact_fde(SIZE_HINT)
    return {SIZE_HINT: (start, end, decode_range(image, start, end))}


def hint_branch_controls(image, bodies):
    # One bounded cross-product of counts, overflow boundaries and phase tags.
    cases = tuple(hint_cases()) + tuple(mixed_hint_cases())
    rig = NestedRig(image)
    reached = set()
    for case in cases:
        run_hint_case(rig, case)
        reached.update(rig.machine.seen)
    controls = []
    for mutation in branch_mutations(bodies, reached):
        _entry, _instruction, patch, _original, replacement = mutation
        rig = NestedRig(image, {patch: replacement})
        rig.machine.step_limit = 3000
        detected, name, reason = False, "", "not detected"
        for case in cases:
            try:
                run_hint_case(rig, case)
            except (Halt, EvidenceError, Panicked, IndexError, KeyError,
                    ValueError, OverflowError, struct.error) as error:
                detected, name, reason = True, case.name, exception_result(error)
                break
        controls.append((*mutation, detected, name, reason))
    return controls, reached


def sibling_comparison(image, bodies, left, right):
    """Mask only direct-call displacements after checking their real targets."""
    first = bodies[left][2]
    second = bodies[right][2]
    if len(first) != len(second):
        raise EvidenceError("sibling instruction counts differ")
    masks = []
    normal_a = bytearray()
    normal_b = bytearray()
    for a, b in zip(first, second):
        if a.size != b.size or a.op != b.op:
            raise EvidenceError("sibling instruction layouts differ")
        bytes_a = bytearray(a.data)
        bytes_b = bytearray(b.data)
        if a.op == "call":
            if a.target != b.target or a.imm_size != 4 or b.imm_size != 4:
                raise EvidenceError("sibling direct-call bindings differ")
            if a.imm_at != b.imm_at:
                raise EvidenceError("sibling call encodings differ")
            masks.append(a.va - left + a.imm_at)
            for offset in range(a.imm_at, a.imm_at + 4):
                bytes_a[offset] = bytes_b[offset] = 0
        normal_a.extend(bytes_a)
        normal_b.extend(bytes_b)
    if normal_a != normal_b:
        raise EvidenceError("siblings differ beyond their direct-call operands")
    return hashlib.sha256(normal_a).hexdigest(), masks


def direct_call_target(address, encoded):
    if len(encoded) != 5 or encoded[0] != 0xE8:
        raise EvidenceError("not a rel32 direct call")
    return address + 5 + struct.unpack_from("<i", encoded, 1)[0]


def context_calls(image):
    sites = (
        (0x5A1E78E, FOLD), (0x5A1DC3E, FOLD_SIBLING),
        (0x5B798EC, NESTED_A), (0x5B79A15, NESTED_A),
        (0x5B79900, SIZE_HINT), (0x5B86B0C, NESTED_B),
        (0x5B86B20, SIZE_HINT), (0x5B86C35, NESTED_B),
        (0x5B86C50, SIZE_HINT), (0x5B9074C, FILTERED_A),
        (0x5B907F5, FILTERED_A), (0x5B9190C, FILTERED_B),
        (0x5B919B5, FILTERED_B),
    )
    for address, expected in sites:
        offset = image.offset(address)
        if image.offset(address + 4) != offset + 4:
            raise EvidenceError("call crosses file-backed sections")
        encoded = image.blob[offset:offset + 5]
        if direct_call_target(address, encoded) != expected:
            raise EvidenceError("context call target differs")
        yield address, offset, encoded.hex(), expected


def source_bridge(image):
    """Bind the fold's caller chain to a decoded #115 source-location record."""
    outer_site, inner_site = 0x5AEDABB, 0x5A1E78E
    first_start, first_end = image.fde(outer_site)
    second_start, second_end = image.fde(inner_site)
    first = decode_range(image, first_start, first_end)
    second = decode_range(image, second_start, second_end)
    outer = next((row for row in first if row.va == outer_site), None)
    inner = next((row for row in second if row.va == inner_site), None)
    if (outer is None or outer.op != "call" or outer.target != second_start
            or inner is None or inner.op != "call" or inner.target != FOLD):
        raise EvidenceError("source-context call chain differs")
    relative = image.relative()
    anchors = []
    for row in first:
        if row.op != "lea" or row.rip_at is None or row.b[4] not in relative:
            continue
        slot = row.b[4]
        offset = image.offset(slot)
        size = struct.unpack_from("<Q", image.blob, offset + 8)[0]
        if not 0 < size <= 512:
            continue
        try:
            path, line, column = image.location(slot, relative)
        except (EvidenceError, KeyError, UnicodeError, ValueError, struct.error):
            continue
        if path == "l1/src/clearinghouse/oracle/oracle.rs":
            anchors.append((path, line, column))
    if len(anchors) != 1:
        raise EvidenceError("clearinghouse source-location record is missing or ambiguous")
    return outer_site, outer.data.hex(), inner_site, inner.data.hex(), *anchors[0]


def input_controls(image):
    rows = []
    original = b"synthetic image bytes"
    digest = hashlib.sha256(original).hexdigest()
    tests = (
        ("digest-content-flip", lambda: check_digest(original + b"!", digest), EvidenceError),
        ("digest-wrong-expected", lambda: check_digest(original, "0" * 64), EvidenceError),
        ("address-outside-sections", lambda: image.offset(0), EvidenceError),
        ("nonstart-in-fde", lambda: image.exact_fde(FOLD + 1), EvidenceError),
        ("address-outside-fdes", lambda: image.fde(0), EvidenceError),
        ("call-opcode-corrupted", lambda: direct_call_target(0x1000, b"\xe9\x00\x00\x00\x00"), EvidenceError),
        ("call-truncated", lambda: direct_call_target(0x1000, b"\xe8\x00"), EvidenceError),
    )
    for name, call, error_type in tests:
        try:
            call()
            rows.append((name, False))
        except error_type:
            rows.append((name, True))
    return rows


def evidence_bodies(image):
    bodies = {}
    for subset in (body_rows(image), nested_body_rows(image), filtered_body_rows(image), hint_body_rows(image)):
        bodies.update(subset)
    return dict(sorted(bodies.items()))


def tsv_row(*values):
    return "\t".join(str(value) for value in values) + "\n"


def write_text(path, lines):
    with path.open("w", encoding="utf-8", newline="\n") as stream:
        for line in lines:
            stream.write(line)


def generate(output):
    image = load_image()
    bodies = evidence_bodies(image)
    output = pathlib.Path(output)
    output.mkdir(parents=True, exist_ok=True)

    sibling_rows = []
    for left, right in (FOLDS, NESTED_WALKERS, FILTERED_WALKERS):
        digest, masks = sibling_comparison(image, bodies, left, right)
        sibling_rows.append((left, right, digest, masks))

    reached = set()
    sample = []
    stream_digest = hashlib.sha256()
    counts = collections.Counter()
    fold_rig = OracleFoldRig(image)
    for index, case in enumerate(generated_cases(3000)):
        for entry in FOLDS:
            result = fold_rig.run_fold(case, entry)
            if result != case.expected():
                raise EvidenceError("fold comparison failed for " + case.name)
            reached.update(fold_rig.machine.seen)
            counts["fold"] += 1
            record = tsv_row("fold", index, hex(entry), case.name, len(tuple(case.entries())),
                             hex(case.initial), hex(result))
            stream_digest.update(record.encode())
            if index < 16:
                sample.append(record)
        if case.tree_mode:
            result = fold_rig.run_iterator(case)
            if result != sum(1 for _ in case.entries()):
                raise EvidenceError("tree iteration failed for " + case.name)
            reached.update(fold_rig.machine.seen)
            counts["iterator"] += 1
            stream_digest.update(tsv_row("iterator", index, result).encode())
    for case in deep_cases():
        result = fold_rig.run_iterator(case)
        reached.update(fold_rig.machine.seen)
        counts["iterator"] += 1
        stream_digest.update(tsv_row("iterator", case.name, result).encode())

    nested_rig = NestedRig(image)
    for index, case in enumerate(nested_cases(256)):
        for entry in NESTED_WALKERS:
            result = nested_rig.run(case, entry, with_hint=index < 64)
            reached.update(nested_rig.machine.seen)
            counts["nested"] += 1
            record = tsv_row("nested", index, hex(entry), case.name, result,
                             case.phases[0].outer.kind, case.phases[1].outer.kind)
            stream_digest.update(record.encode())
            if index < 16:
                sample.append(record)
    for case in deep_nested_cases():
        for entry in NESTED_WALKERS:
            result = nested_rig.run(case, entry)
            reached.update(nested_rig.machine.seen)
            counts["nested"] += 1
            stream_digest.update(tsv_row("nested-deep", case.name, hex(entry), result).encode())
    counts["live_hint"] = nested_rig.hint_checks

    filtered_rig = FilteredRig(image)
    for index, case in enumerate(filtered_cases(256)):
        for entry in FILTERED_WALKERS:
            result = filtered_rig.run_filtered(case, entry)
            reached.update(filtered_rig.machine.seen)
            counts["filtered"] += 1
            record = tsv_row("filtered", index, hex(entry), case.name, case.wanted, result)
            stream_digest.update(record.encode())
            if index < 16:
                sample.append(record)

    hint_rig = NestedRig(image)
    for group in (hint_cases(), mixed_hint_cases()):
        for index, case in enumerate(group):
            lower, upper = run_hint_case(hint_rig, case)
            reached.update(hint_rig.machine.seen)
            counts["synthetic_hint"] += 1
            record = tsv_row("hint", index, case.name, lower, "none" if upper is None else upper)
            stream_digest.update(record.encode())
            if index < 16:
                sample.append(record)

    controls = []
    for builder, subset in ((branch_controls, body_rows(image)),
                            (nested_branch_controls, nested_body_rows(image)),
                            (filtered_branch_controls, filtered_body_rows(image)),
                            (hint_branch_controls, hint_body_rows(image))):
        rows, seen = builder(image, subset)
        controls.extend(rows)
        reached.update(seen)
    damages = input_controls(image)
    control_count = len(controls) + len(damages)
    detected_count = sum(bool(row[5]) for row in controls) + sum(detected for _, detected in damages)

    def functions():
        yield tsv_row("entry_va", "end_va", "file_offset", "bytes", "instructions", "sha256")
        for entry, (start, end, rows) in bodies.items():
            offset = image.offset(start)
            digest = hashlib.sha256(image.blob[offset:offset + end - start]).hexdigest()
            yield tsv_row(hex(entry), hex(end), hex(offset), end - start, len(rows), digest)

    def instructions():
        yield tsv_row("entry_va", "instruction_va", "length", "raw_bytes", "operation", "direct_target")
        for entry, (_start, _end, rows) in bodies.items():
            for row in rows:
                target = hex(row.target) if row.op in ("call", "jmp", "jcc") and row.target is not None else ""
                yield tsv_row(hex(entry), hex(row.va), row.size, row.data.hex(), row.op, target)

    def branches():
        yield tsv_row("entry_va", "instruction_va", "taken_target", "reached", "raw_bytes")
        for entry, (_start, _end, rows) in bodies.items():
            for row in rows:
                if row.op == "jcc":
                    yield tsv_row(hex(entry), hex(row.va), hex(row.target), int(row.va in reached), row.data.hex())

    def control_lines():
        yield tsv_row("kind", "entry_va", "instruction_va", "byte_va", "old", "new", "detected", "first_case", "result")
        for entry, instruction, at, old, new, detected, case, result in sorted(controls):
            yield tsv_row("branch-flip", hex(entry), hex(instruction), hex(at), "%02x" % old,
                          "%02x" % new, int(detected), case, result)
        for name, detected in damages:
            yield tsv_row("input", "", "", "", "", "", int(detected), name,
                          "rejected" if detected else "not detected")

    def siblings():
        yield tsv_row("first_va", "second_va", "normalized_sha256", "masked_call_operand_offsets")
        for left, right, digest, masks in sibling_rows:
            yield tsv_row(hex(left), hex(right), digest, ",".join(hex(value) for value in masks))

    def call_sites():
        yield tsv_row("call_va", "file_offset", "raw_bytes", "target_va")
        for address, offset, encoded, target in context_calls(image):
            yield tsv_row(hex(address), hex(offset), encoded, hex(target))

    def source_context():
        yield tsv_row("outer_call_va", "outer_bytes", "inner_call_va", "inner_bytes", "location_path", "line", "column")
        outer, outer_bytes, inner, inner_bytes, path, line, column = source_bridge(image)
        yield tsv_row(hex(outer), outer_bytes, hex(inner), inner_bytes, path, line, column)

    write_text(output / "functions.tsv", functions())
    write_text(output / "instructions.tsv", instructions())
    write_text(output / "branches.tsv", branches())
    write_text(output / "controls.tsv", control_lines())
    write_text(output / "siblings.tsv", siblings())
    write_text(output / "call-sites.tsv", call_sites())
    write_text(output / "source-context.tsv", source_context())
    write_text(output / "samples.tsv", iter(sample))
    total_cases = sum(counts[name] for name in ("fold", "iterator", "nested", "filtered", "synthetic_hint"))
    metrics = {
        "cases": total_cases,
        "negative_controls": control_count,
        "negative_detected": detected_count,
        "equivalent": 0,
        "fold_cases": counts["fold"],
        "iterator_cases": counts["iterator"],
        "nested_cases": counts["nested"],
        "filtered_cases": counts["filtered"],
        "synthetic_hint_cases": counts["synthetic_hint"],
        "live_hint_checks": counts["live_hint"],
        "function_count": len(bodies),
        "instruction_count": sum(len(body[2]) for body in bodies.values()),
        "reached_instructions": sum(row.va in reached for body in bodies.values() for row in body[2]),
        "case_stream_sha256": stream_digest.hexdigest(),
    }
    (output / "measure.json").write_text(json.dumps(metrics, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    if detected_count != control_count:
        raise EvidenceError("one or more created negative controls were not detected")
    return metrics


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", required=True)
    arguments = parser.parse_args()
    print(json.dumps(generate(arguments.out), sort_keys=True))


if __name__ == "__main__":
    main()


