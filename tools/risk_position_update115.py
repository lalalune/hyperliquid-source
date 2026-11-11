#!/usr/bin/env python3
"""Reconstruct the node #115 position update body at 0x448bc30 (qtys saturating arithmetic) and prove it against the ELF bytes.

The body takes a 0x40 byte position record, a price, a signed size delta, a running balance, a floor and a price cap. It updates the record in
place, folds the realized part into the balance and returns a 0x48 byte block (record copy plus the new balance) or an error tag. This tool runs
the real bytes in a small x86-64 interpreter (never the binary itself), compares every outcome with a straight-code rule list for the path, and
checks that deliberately wrong rule lists, damaged instruction bytes and bad addresses are all detected. Standard library plus the shared parsers.

    python3 tools/risk_position_update115.py --out <dir>
"""

import argparse
import json
import bisect
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


def load_image(path=BINARY, expected=SHA256):
    blob = pathlib.Path(path).read_bytes()
    digest = hashlib.sha256(blob).hexdigest()
    if digest != expected:
        raise EvidenceError("binary SHA-256 mismatch: %s" % digest)
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





# ---------------------------------------------------------------------------------------------------------------------------------------------
# Subject: the position update body at 0x448bc30 (FDE 0x448bc30..0x448c925) of node #115.
#
# Calling form read from the bytes: rdi = 0x48 byte result block, rsi = 0x40 byte position record (mutated in place), rdx = price (a u64 that
# must be non-negative as i64), rcx = signed size delta, r8 = signed running balance, r9 = signed floor, the one stack argument = unsigned price cap.
# ---------------------------------------------------------------------------------------------------------------------------------------------

ENTRY = 0x448BC30
SLOT_REPORT = 0x64E4EA8
SLOT_PANIC = 0x64DF6A0
LOC_A = 0x648B9C0
LOC_S = 0x648B9D8
LOC_NEG = 0x648B9F0
LOC_SIZE = 0x648BA08
LOC_QUOT = 0x648BA38
LOC_SUB = 0x648BA50
LOCATIONS = (LOC_A, LOC_S, LOC_NEG, LOC_SIZE, LOC_QUOT, LOC_SUB)
OUT = HEAP_BASE + 0x1000
REC = HEAP_BASE + 0x2000
FAKE_REPORT = 0xF0000001
FAKE_PANIC = 0xF0000002
INT_MAX = (1 << 63) - 1
INT_MIN = -(1 << 63)
U64 = (1 << 64) - 1
FIELDS = ("mode", "divisor", "acc", "size", "f18", "mark", "clear", "f30", "f38")
RECORD = struct.Struct("<IIqqQQQQQ")
NAMES = {ENTRY: "position_update"}
VARIANTS = (
    "wrap-instead-of-saturate", "silent-overflow", "share-rounds", "share-floors", "cap-ignored", "cap-min-on-reduce", "mark-kept", "clear-kept",
    "mode-ignored", "quotient-ceil", "fold-skipped", "shortfall-skipped", "flip-no-reopen", "sign-test-inverted", "share-over-delta", "negative-price-ok",
    "floor-unsigned", "zero-divisor-ignored", "close-uses-max", "equal-size-opens",
)


def panic_args(location):
    """What the panic routine receives at both panic sites: the location record, the message length, the message pointer and the vtable-like record."""
    return location, 0x2B, 0x7D3212, 0x648C598


class Stop(Exception):
    def __init__(self, kind, detail=0):
        Exception.__init__(self, kind)
        self.kind = kind
        self.detail = detail


def sat(value):
    return INT_MIN if value < INT_MIN else INT_MAX if value > INT_MAX else value


def fits(value):
    return INT_MIN <= value <= INT_MAX


def sign(value):
    return (value > 0) - (value < 0)


def to_i64(value):
    value &= U64
    return value - (1 << 64) if value >> 63 else value


def f64_to_i64(value):
    """Rust `as i64` on a double: NaN is 0 and out of range saturates (cvttsd2si, then the compare against 0x43dfffffffffffff)."""
    if value != value:
        return 0
    if value >= 9223372036854775808.0:
        return INT_MAX
    if value <= -9223372036854775808.0:
        return INT_MIN
    return int(value)


class Rules:
    """The #115 rule list for the update body, written as straight code. `variant` names deliberate mistakes used as negative controls."""

    def __init__(self, record, variant=frozenset()):
        self.rec = dict(zip(FIELDS, record))
        self.events = []
        self.v = variant

    def add(self, left, right, where):
        total = left + right
        if not fits(total):
            if "silent-overflow" not in self.v:
                self.events.append(where)
            if "wrap-instead-of-saturate" in self.v:
                return to_i64(total)
            return sat(total)
        return total

    def sub(self, left, right, where):
        total = left - right
        if not fits(total):
            if "silent-overflow" not in self.v:
                self.events.append(where)
            if "wrap-instead-of-saturate" in self.v:
                return to_i64(total)
            return sat(total)
        return total

    @staticmethod
    def mul(left, right):
        total = left * right
        if not fits(total):
            raise Stop("err")
        return total

    def result(self, kind, r9=None, detail=0):
        r = self.rec
        return kind, r9, tuple(r[name] for name in FIELDS), tuple(self.events), detail

    def run(self, px, delta, base, floor, cap):
        try:
            return self.body(px, delta, base, floor, cap)
        except Stop as stop:
            return self.result(stop.kind, None, stop.detail)

    def body(self, px, delta, base, floor, cap):
        r = self.rec
        v = self.v
        if delta == 0:
            return self.result("ok", base)
        if "clear-kept" not in v:
            r["clear"] = 0
        size = r["size"]
        total = size + delta
        if not fits(total):
            if "silent-overflow" not in v:
                self.events.append(LOC_SIZE)
            seen = sat(total)
        else:
            seen = total
        if sign(seen) != sign(size) and "mark-kept" not in v:
            r["mark"] = 0
        if r["mode"] != 1 and "mode-ignored" not in v:
            if not fits(total):
                if "silent-overflow" not in v:
                    self.events.append(LOC_S)
                r["size"] = to_i64(total) if "wrap-instead-of-saturate" in v else sat(total)
            else:
                r["size"] = total
            if px < 0 and "negative-price-ok" not in v:
                raise Stop("err")
            return self.result("ok", self.sub(base, self.mul(px, delta), LOC_SUB))
        if size == 0:
            return self.open_leg(0, delta, base, floor, px, cap)
        if (delta > 0) == (size > 0) and "equal-size-opens" not in v:
            return self.after_close(size, delta, base, floor, px, cap, None)
        abs_size = abs(size)
        abs_delta = abs(delta)
        closed = max(abs_size, abs_delta) if "close-uses-max" in v else min(abs_size, abs_delta)
        if delta < 0:
            if closed == 1 << 63:
                raise Stop("panic", panic_args(LOC_NEG))
            signed = -closed
        else:
            signed = closed
        if px < 0 and "negative-price-ok" not in v:
            raise Stop("err")
        value = self.mul(px, signed)
        acc = r["acc"]
        mark = px * size
        if not fits(mark):
            negative = not size > 0
        else:
            negative = self.add(acc, mark, LOC_SUB) < 0
        if "sign-test-inverted" in v:
            negative = not negative
        if not negative:
            base_after = self.share_leg(acc, closed, abs_size if "share-over-delta" not in v else abs_delta, base, value)
        else:
            r["acc"] = self.sub(acc, value, LOC_SUB)
            moved = self.add(size, signed, LOC_SIZE)
            if abs_size < abs_delta and moved == 0:
                before = r["acc"]
                r["acc"] = 0
                base_after = self.add(base, before, LOC_A)
            else:
                base_after = base
        return self.after_close(size, delta, base_after, floor, px, cap, signed)

    def share_leg(self, acc, closed, denominator, base, value):
        r = self.rec
        ratio = fdiv(float(closed), float(denominator))
        scaled = float(acc) * ratio
        if scaled != scaled or abs(scaled) == math.inf:
            clamped = 0.0
        else:
            clamped = min(9223372036854775808.0, max(-9223372036854775808.0, scaled))
        if "share-rounds" in self.v:
            share = f64_to_i64(float(round(clamped)))
        elif "share-floors" in self.v:
            share = f64_to_i64(float(math.floor(clamped)))
        else:
            share = f64_to_i64(clamped)
        r["acc"] = self.sub(acc, share, LOC_SUB)
        moved = self.add(base, share, LOC_A)
        out = self.sub(moved, value, LOC_SUB)
        if not fits(share - value):
            self.events.append(LOC_SUB)
        return out

    def after_close(self, size, delta, base, floor, px, cap, signed):
        r = self.rec
        if signed is None:
            return self.c028(size, delta, base, floor, px, cap)
        rest = self.sub(delta, signed, LOC_SIZE)
        left = self.add(size, signed, LOC_S)
        r["size"] = left
        if left == 0:
            if rest == 0:
                return self.settle(base, floor, True)
            if "flip-no-reopen" in self.v:
                return self.settle(base, floor, False)
            return self.open_leg(0, rest, base, floor, px, cap)
        return self.c028(left, rest, base, floor, px, cap)

    def c028(self, size, rest, base, floor, px, cap):
        if rest == 0 or (rest > 0) != (size > 0):
            return self.settle(base, floor, False)
        return self.open_leg(size, rest, base, floor, px, cap)

    def open_leg(self, size, rest, base, floor, px, cap):
        r = self.rec
        v = self.v
        unsigned_px = px & U64
        if "cap-ignored" in v:
            bounded = unsigned_px
        elif rest > 0 or "cap-min-on-reduce" in v:
            bounded = min(unsigned_px, cap)
        else:
            bounded = max(unsigned_px, cap)
        if bounded >> 63:
            raise Stop("err")
        worth = self.mul(bounded, rest)
        divisor = r["divisor"]
        if divisor == 0:
            if "zero-divisor-ignored" in v:
                divisor = 1
            else:
                raise Stop("fault")
        quotient = -(-abs(worth) // divisor) if "quotient-ceil" in v else abs(worth) // divisor
        if quotient >> 63:
            raise Stop("panic", panic_args(LOC_QUOT))
        acc = self.add(r["acc"], quotient, LOC_A)
        r["acc"] = acc
        after_fee = self.sub(base, quotient, LOC_SUB)
        if px < 0 and "negative-price-ok" not in v:
            raise Stop("err")
        paid = self.mul(px, rest)
        after_pay = self.sub(after_fee, paid, LOC_SUB)
        left = self.add(size, rest, LOC_S)
        r["size"] = left
        r["acc"] = self.sub(acc, worth, LOC_SUB)
        final = self.add(after_pay, worth, LOC_A)
        return self.settle(final, floor, left == 0)

    def settle(self, balance, floor, fold):
        r = self.rec
        v = self.v
        less = (balance & U64) < (floor & U64) if "floor-unsigned" in v else balance < floor
        if not less:
            out = balance
        else:
            if "shortfall-skipped" not in v:
                short = self.sub(floor, balance, LOC_SUB)
                r["acc"] = self.sub(r["acc"], short, LOC_SUB)
            out = floor
        if fold and "fold-skipped" not in v:
            out = self.add(out, r["acc"], LOC_A)
            r["acc"] = 0
        return self.result("ok", out)


class Case:
    __slots__ = ("name", "args")

    def __init__(self, name, args):
        self.name = name
        self.args = args


def mk(name, mode=1, divisor=10000, acc=0, size=0, f18=0x1111, mark=0x2222, clear=0x3333, f30=0x4444, f38=0x5555, px=100, delta=0, base=0, floor=0, cap=10 ** 12):
    return Case(name, (mode, divisor, acc, size, f18, mark, clear, f30, f38, px, delta, base, floor, cap))


class Harness:
    """Runs the real bytes in the interpreter with the two external slots served by recording stubs."""

    def __init__(self, image, patches=None):
        self.machine = Machine(image, patches)
        self.events = []
        memory = self.machine.memory
        memory.statics[SLOT_REPORT] = FAKE_REPORT
        memory.statics[SLOT_PANIC] = FAKE_PANIC
        self.machine.slots[FAKE_REPORT] = lambda machine: self.events.append(machine.regs[RSI])

        def panic(machine):
            raise Panicked((machine.regs[R8], machine.regs[RSI], machine.regs[RDI], machine.regs[RCX]))

        self.machine.slots[FAKE_PANIC] = panic

    def run(self, case):
        machine = self.machine
        memory = machine.memory
        memory.reset(0x4000)
        del self.events[:]
        args = case.args
        memory.put_bytes(REC, RECORD.pack(*args[:9]))
        px, delta, base, floor, cap = args[9:]
        kind, detail = "ok", 0
        try:
            machine.run(ENTRY, {RDI: OUT, RSI: REC, RDX: px & U64, RCX: delta & U64, R8: base & U64, R9: floor & U64}, stack=(cap,))
        except Panicked as stop:
            kind, detail = "panic", stop.args[0]
        except Halt as stop:
            if "division by zero" not in str(stop):
                raise
            kind = "fault"
        block = memory.bytes_at(OUT, 0x48)
        record = memory.bytes_at(REC, 0x40)
        r9 = None
        if kind == "ok":
            if block[:4] == b"\x02\0\0\0" and block[4:] == b"\xa5" * 0x44:
                kind = "err"
            else:
                if block[:0x40] != record:
                    raise EvidenceError("result block is not a copy of the final record")
                r9 = struct.unpack_from("<q", block, 0x40)[0]
        elif block != b"\xa5" * 0x48:
            raise EvidenceError("result block written before a panic or fault")
        return kind, r9, RECORD.unpack(record), tuple(self.events), detail


def spec_run(case, variant=frozenset()):
    return Rules(case.args[:9], variant).run(*case.args[9:])


def named_cases():
    big = INT_MAX
    low = INT_MIN
    rows = [
        mk("zero delta copies the record", delta=0, base=77, size=5, acc=9),
        mk("zero delta keeps even a bad price", delta=0, px=-5, base=-3),
        mk("flat open long, cap above price", delta=100, px=50, cap=80, base=1000),
        mk("flat open long, cap below price", delta=100, px=50, cap=20, base=1000),
        mk("flat open short, cap above price", delta=-100, px=50, cap=80, base=1000),
        mk("flat open short, cap below price", delta=-100, px=50, cap=20, base=1000),
        mk("flat open, divisor 1", delta=100, px=50, cap=50, divisor=1),
        mk("flat open, divisor 0xffffffff", delta=100, px=50, cap=50, divisor=0xFFFFFFFF),
        mk("flat open, worth past 32 bits", delta=10 ** 6, px=10 ** 7, cap=10 ** 7, divisor=3),
        mk("flat open, zero divisor faults", delta=100, px=50, cap=50, divisor=0),
        mk("flat open, zero worth with zero divisor still faults", delta=100, px=0, cap=0, divisor=0),
        mk("flat open, quotient 2^63 panics", delta=-2, px=1, cap=1 << 62, divisor=1),
        mk("flat open, worth 2^63 - 2 under divisor 1", delta=2, px=1 << 62, cap=1 << 62, divisor=1),
        mk("flat open, cap with the top bit is refused", delta=5, px=10, cap=1 << 63, base=0),
        mk("flat open short, cap with the top bit is the maximum", delta=-5, px=10, cap=(1 << 63) + 1, base=0),
        mk("flat open, negative price", delta=5, px=-1, cap=10),
        mk("flat open, price times delta overflows", delta=big, px=3, cap=big),
        mk("flat open, delta at the minimum", delta=low, px=1, cap=1),
        mk("flat open, balance saturates down", delta=1000, px=big // 1000, cap=big // 1000, base=low + 5, divisor=10 ** 9),
        mk("flat open, accumulator saturates up", delta=100, px=10 ** 6, cap=10 ** 6, acc=big - 3, divisor=1),
        mk("flat open, floor above balance", delta=10, px=10, cap=10, base=5, floor=10 ** 6),
        mk("flat open, floor equal balance", delta=10, px=10, cap=10, base=0, floor=-100 - 0),
        mk("add to long", size=50, delta=25, px=40, cap=45, base=500, acc=1000),
        mk("add to short", size=-50, delta=-25, px=40, cap=30, base=500, acc=-1000),
        mk("add past the top", size=big - 2, delta=10, px=1, cap=1),
        mk("add past the bottom", size=low + 2, delta=-10, px=1, cap=1),
        mk("reduce long, proportional share", size=100, delta=-40, px=60, acc=5000, base=100, cap=10 ** 9),
        mk("reduce short, proportional share", size=-100, delta=40, px=60, acc=5000, base=100, cap=10 ** 9),
        mk("reduce long, negative accumulator", size=100, delta=-40, px=60, acc=-5000, base=100),
        mk("reduce long, value below zero", size=100, delta=-40, px=1, acc=-5000, base=100),
        mk("close long exactly", size=100, delta=-100, px=60, acc=5000, base=100),
        mk("close short exactly", size=-100, delta=100, px=60, acc=-5000, base=100),
        mk("close exactly, floor above", size=100, delta=-100, px=60, acc=5000, base=100, floor=10 ** 9),
        mk("flip long to short", size=100, delta=-150, px=60, acc=5000, base=100, cap=70),
        mk("flip short to long", size=-100, delta=150, px=60, acc=5000, base=100, cap=50),
        mk("flip with value below zero", size=100, delta=-150, px=1, acc=-5000, base=100),
        mk("flip short with value below zero", size=-100, delta=150, px=1, acc=-5000, base=100),
        mk("price times size overflows, long", size=big, delta=-1, px=10, acc=0),
        mk("price times size overflows, short", size=low, delta=1, px=10, acc=0),
        mk("price times size plus accumulator overflows", size=1 << 40, delta=-1, px=1 << 22, acc=big),
        mk("share of a huge accumulator", size=3, delta=-1, px=2, acc=big, base=0),
        mk("share of a huge negative accumulator", size=3, delta=-1, px=2, acc=low, base=0),
        mk("share is exactly the accumulator", size=7, delta=-7, px=2, acc=12345, base=9),
        mk("share minus value overflows", size=10, delta=-5, px=big // 5, acc=low // 3, base=0),
        mk("base plus share overflows", size=10, delta=-5, px=1, acc=big, base=big),
        mk("size sum overflows in mode 1", size=big, delta=big),
        mk("size sum overflows downward in mode 1", size=low, delta=low),
        mk("fold of the accumulator overflows", size=7, delta=-7, px=2, acc=(1 << 62) + 400, base=INT_MAX - 100 - 14 - (1 << 62), divisor=10),
        mk("fold of the accumulator overflows downward", size=-7, delta=7, px=2, acc=-(1 << 62) - 400, base=INT_MIN + 100 + 14 + (1 << 62), divisor=10),
        mk("base plus share saturates, zero value", size=10, delta=-5, px=0, acc=INT_MAX, base=INT_MAX),
        mk("flip, base plus accumulator saturates down", size=3, delta=-5, px=1, acc=-(1 << 62), base=INT_MIN, divisor=0xFFFFFFFF, cap=1, floor=INT_MIN),
        mk("flip short, base plus accumulator saturates down", size=-3, delta=5, px=1, acc=-(1 << 62), base=INT_MIN, divisor=0xFFFFFFFF, cap=1, floor=INT_MIN),
        mk("mark cleared when the sign flips", size=5, delta=-9, px=2, mark=0xABCD),
        mk("mark kept when the sign holds", size=9, delta=-5, px=2, mark=0xABCD),
        mk("mode 0 buys", mode=0, size=10, delta=5, px=7, base=100),
        mk("mode 2 sells", mode=2, size=10, delta=-5, px=7, base=100),
        mk("mode 0xffffffff", mode=0xFFFFFFFF, size=-10, delta=5, px=7, base=100),
        mk("mode 0 size overflows", mode=0, size=big, delta=5, px=7),
        mk("mode 0 size underflows", mode=0, size=low, delta=-5, px=7),
        mk("mode 0 negative price", mode=0, size=1, delta=5, px=-7),
        mk("mode 0 price times delta overflows", mode=0, size=1, delta=big, px=3),
        mk("mode 0 balance saturates", mode=0, size=1, delta=-5, px=big // 5, base=big - 3),
        mk("mode 0 balance saturates below", mode=0, size=1, delta=5, px=big // 5, base=low + 3),
        mk("mode 0 sign flip clears the mark", mode=0, size=3, delta=-8, px=1, mark=5),
    ]
    return rows


def grid_cases():
    sizes = (-7, 0, 7, INT_MAX - 1, INT_MIN + 1)
    deltas = (-9, -7, -3, 0, 3, 7, 9, INT_MAX, INT_MIN)
    accs = (-100, 100, INT_MAX)
    pxs = (3, 50)
    bases = (0, INT_MAX - 5)
    floors = (-1000, INT_MAX)
    index = 0
    for size in sizes:
        for delta in deltas:
            for acc in accs:
                for px in pxs:
                    for base in bases:
                        for floor in floors:
                            yield mk("g%d" % index, divisor=7, acc=acc, size=size, px=px, delta=delta, base=base, floor=floor, cap=20)
                            index += 1


class Stream:
    """A fixed xorshift64* generator, so the case list does not depend on the interpreter version."""

    def __init__(self, seed):
        self.state = seed or 0x9E3779B97F4A7C15

    def bits(self):
        x = self.state
        x ^= x >> 12
        x ^= x << 25 & U64
        x ^= x >> 27
        self.state = x
        return x * 0x2545F4914F6CDD1D & U64

    def below(self, n):
        return self.bits() % n

    def span(self, low, high):
        return low + self.below(high - low)

    def pick(self, seq):
        return seq[self.below(len(seq))]


POOL = (0, 1, -1, 2, -2, 3, 7, -7, 10, 100, -100, 1000, 12345, -12345, 10 ** 6, -10 ** 6, 10 ** 9, -10 ** 9, 10 ** 12, -10 ** 12, 10 ** 15, -10 ** 15,
        2 ** 31, -2 ** 31, 2 ** 32, 2 ** 32 - 1, 2 ** 33, 2 ** 53, -2 ** 53, 2 ** 62, -2 ** 62, INT_MAX, INT_MIN, INT_MAX - 1, INT_MIN + 1, 3 * 10 ** 18, -3 * 10 ** 18)


def clamp64(value):
    return max(INT_MIN, min(INT_MAX, value))


def wild(stream):
    k = stream.below(100)
    if k < 45:
        return stream.pick(POOL)
    if k < 75:
        value = stream.bits() >> (64 - stream.span(1, 64))
        return value if stream.below(2) else -value
    if k < 90:
        return clamp64(stream.pick(POOL) + stream.span(-3, 4))
    return to_i64(stream.bits())


def tame_case(stream, name):
    scale = stream.pick((10 ** 3, 10 ** 6, 10 ** 9, 10 ** 12))
    size = stream.span(-scale, scale) if stream.below(10) else 0
    delta = stream.span(-scale, scale) if stream.below(10) else stream.pick((-size, size, -size - 1, -size + 1, 0))
    px = stream.span(1, 10 ** stream.span(3, 12))
    cap = stream.pick((px, px - 1, px + 1, stream.span(1, 10 ** stream.span(3, 12)), 10 ** 12))
    return Case(name, (1 if stream.below(10) else 2, stream.pick((1, 10, 10 ** 4, 10 ** 6, 3, 999)), stream.span(-scale * 10, scale * 10), size,
                       stream.bits(), stream.bits(), stream.bits(), stream.bits(), stream.bits(), px, delta, stream.span(-10 ** 15, 10 ** 15),
                       stream.span(-10 ** 14, 10 ** 14), cap))


def wild_case(stream, name):
    mode = 1 if stream.below(5) else stream.pick((0, 2, 5, 0xFFFFFFFF))
    divisor = stream.pick((1, 2, 3, 10, 100, 1000, 10000, 10 ** 6, 0xFFFFFFFF, 0, stream.bits() & 0xFFFFFFFF))
    px = clamp64(wild(stream)) if stream.below(2) else abs(wild(stream)) % 10 ** 12
    cap = stream.pick((0, 1, 100, 10 ** 9, INT_MAX, 1 << 63, U64, stream.bits(), stream.bits() & (1 << 40) - 1))
    return Case(name, (mode, divisor, clamp64(wild(stream)), clamp64(wild(stream)), stream.bits(), stream.bits(), stream.bits(), stream.bits(), 0, px,
                       clamp64(wild(stream)), clamp64(wild(stream)), clamp64(wild(stream)), cap))


def vector_cases(count, seed=0x5EED115):
    stream = Stream(seed)
    for index in range(count):
        name = "v%d" % index
        yield tame_case(stream, name) if stream.below(100) < 60 else wild_case(stream, name)


def digest_of(outcome):
    kind, r9, record, events, detail = outcome
    text = "%s|%s|%s|%s|%s" % (kind, r9, ",".join(str(x) for x in record), ",".join("%x" % e for e in events), detail)
    return kind, str(r9), hashlib.sha256(text.encode()).hexdigest()[:16], ",".join("%x" % e for e in events)


def run_stream(harness, cases, rows=None, keep_every=0, cover=None, stats=None):
    """Run each case, compare at once with the rule list, keep sampled rows, first-reach rows and counts only."""
    count = 0
    machine = harness.machine
    for case in cases:
        before = len(machine.seen)
        got = harness.run(case)
        want = spec_run(case)
        if got != want:
            raise EvidenceError("case disagrees with the rule list: %s %r %r" % (case.name, got, want))
        if cover is not None and len(machine.seen) != before:
            for va in sorted(machine.seen):
                if va not in cover:
                    cover[va] = case.name
        if stats is not None:
            stats[got[0]] = stats.get(got[0], 0) + 1
            for event in got[3]:
                stats[event] = stats.get(event, 0) + 1
        if rows is not None and (keep_every == 0 or count % keep_every == 0):
            rows.append((case.name,) + case.args[9:12] + (case.args[0], case.args[1], case.args[2], case.args[3]) + digest_of(got))
        count += 1
    return count


def first_failure(harness, cases, variant=frozenset()):
    for case in cases:
        try:
            if harness.run(case) != spec_run(case, variant):
                return case
        except (Halt, EvidenceError, KeyError, IndexError, ValueError, OverflowError, ZeroDivisionError, struct.error, Panicked, TypeError):
            return case
    return None


def displacement_at(row, data):
    operand = row.a if row.a and row.a[0] == "m" else row.b if row.b and row.b[0] == "m" else None
    if operand is None or operand[5] or operand[1] in (None, RSP) or operand[4] == 0:
        return None
    end = row.size - (row.imm_size or 0)
    value = operand[4]
    if -128 <= value < 128 and data[end - 1] == value & 0xFF:
        return end - 1
    if data[end - 4:end] == struct.pack("<i", value):
        return end - 4
    return None


def edits_for(image, rows, seen):
    edits = []
    for row in rows:
        if row.va not in seen:
            continue
        data = bytes(image.blob[image.offset(row.va):image.offset(row.va) + row.size])
        if row.op == "jcc":
            at = row.size - 5 if row.size >= 6 else 0
            edits.append((row.va, "condition", {row.va + at: data[at] ^ 1}))
            continue
        if row.op in ("cmov", "set"):
            at = next(i for i in range(row.size) if data[i] == 0x0F) + 1
            edits.append((row.va, "condition", {row.va + at: data[at] ^ 1}))
            continue
        if row.imm_at is not None and row.op not in ("call", "jmp"):
            edits.append((row.va, "immediate", {row.va + row.imm_at: data[row.imm_at] ^ 1}))
        at = displacement_at(row, data)
        if at is not None:
            edits.append((row.va, "displacement", {row.va + at: data[at] ^ 8}))
    return edits


def run_mutants(image, rows, seen, cases, explained):
    results = []
    control = Harness(image)
    control.machine.step_limit = MUTANT_STEP_LIMIT
    if first_failure(control, cases) is not None:
        raise EvidenceError("an unedited image fails under the mutant step limit")
    for va, kind, patch in edits_for(image, rows, seen):
        harness = Harness(image, patch)
        harness.machine.step_limit = MUTANT_STEP_LIMIT
        failure = first_failure(harness, cases)
        if failure is not None:
            results.append((va, kind, "killed", failure.name))
        else:
            results.append((va, kind, "survived", explained.get((va, kind), "UNEXPLAINED")))
    return results


def structural_controls(image, sample):
    rows = []
    blob = bytearray(image.blob)
    blob[1000] ^= 1
    changed = hashlib.sha256(bytes(blob)).hexdigest() != SHA256
    rows.append(("one flipped file byte changes the SHA-256", "detected" if changed else "MISSED"))
    for label, va in (("address inside the body", ENTRY + 1), ("address before the body", ENTRY - 1), ("address in .rodata", 0x459230), ("address past the file", 0x7FFFFFFFFF)):
        try:
            image.exact_fde(va)
            rows.append((label + " is refused as a function start", "MISSED"))
        except EvidenceError:
            rows.append((label + " is refused as a function start", "detected"))
    relative = image.relative()
    rows.append(("report slot does not hold the panic target", "detected" if relative.get(SLOT_REPORT) != relative.get(SLOT_PANIC) else "MISSED"))
    rows.append(("panic slot does not hold the report target", "detected" if relative.get(SLOT_PANIC) != REPORT_TARGET else "MISSED"))
    rows.append(("an address outside the relative table has no target", "detected" if relative.get(SLOT_REPORT + 1) is None else "MISSED"))
    harness = Harness(image)
    probe = next(case for case in sample if case.name == "reduce long, proportional share")
    changed_args = list(probe.args)
    changed_args[9] += 1
    moved = Case("moved", tuple(changed_args))
    rows.append(("a moved price gives a different result than the rule list for the original", "detected" if harness.run(moved) != spec_run(probe) else "MISSED"))
    wrong = list(probe.args)
    wrong[0] = 0
    rows.append(("another mode gives a different outcome for the same record", "detected" if harness.run(Case("mode", tuple(wrong))) != harness.run(probe) else "MISSED"))
    return rows


def decode_function(image):
    start, end = image.exact_fde(ENTRY)
    return start, end, decode_range(image, start, end)


def constant_rows(image, rows):
    out = []
    seen = set()
    for row in rows:
        for operand in (row.a, row.b):
            if operand and operand[0] == "m" and row.rip_at is not None and operand[1] is None and operand[2] is None and row.op != "calli":
                va = operand[4]
                if va in seen or va in LOCATIONS:
                    continue
                seen.add(va)
                bits = struct.unpack_from("<Q", image.blob, image.offset(va))[0]
                out.append(("%#x" % row.va, "rip %#x" % va, repr(to_float(bits)), "%#x" % bits))
        if row.op == "mov" and row.size >= 10 and row.data[0] & 0xF8 == 0x48 and 0xB8 <= row.data[1] <= 0xBF:
            value = struct.unpack_from("<Q", row.data, 2)[0]
            out.append(("%#x" % row.va, "movabs", str(value), "%#x" % value))
    return out


def location_rows(image):
    relative = image.relative()
    rows = []
    for va in LOCATIONS:
        offset = image.offset(va)
        pointer = relative[va]
        length = struct.unpack_from("<Q", image.blob, offset + 8)[0]
        line, column = struct.unpack_from("<II", image.blob, offset + 16)
        name = bytes(image.blob[image.offset(pointer):image.offset(pointer) + length]).decode("ascii")
        rows.append(("%#x" % va, "%#x" % pointer, length, name, line, column))
    return rows


def site_rows(image, start, end):
    rows = []
    text_va, text = image.text_bytes()
    for slot in (SLOT_REPORT, SLOT_PANIC):
        sites = []
        at = text.find(b"\xff\x15", start - text_va)
        while 0 <= at < end - text_va:
            if text_va + at + 6 + struct.unpack_from("<i", text, at + 2)[0] == slot:
                sites.append(text_va + at)
            at = text.find(b"\xff\x15", at + 1)
        rows.append(("%#x" % slot, "%#x" % image.relative()[slot], len(sites), " ".join("%#x" % s for s in sites)))
    return rows


def location_use_rows(rows):
    """Which location record each call site hands over: the last `lea` (followed through `mov reg, reg`) into rsi or r8 before the call, from the decoded rows."""
    out = []
    pending = {}
    for row in rows:
        if row.op == "lea" and row.a and row.a[0] == "r" and row.b and row.b[0] == "m" and row.rip_at is not None:
            pending[row.a[1]] = row.b[4]
        elif row.op == "mov" and row.a and row.b and row.a[0] == "r" and row.b[0] == "r":
            pending[row.a[1]] = pending.get(row.b[1], 0)
        elif row.op == "calli":
            slot = row.a[4] if row.a and row.a[0] == "m" else None
            if slot == SLOT_REPORT:
                out.append(("%#x" % row.va, "report", "%#x" % pending.get(RSI, 0)))
            elif slot == SLOT_PANIC:
                out.append(("%#x" % row.va, "panic", "%#x" % pending.get(R8, 0)))
    return out


def caller_rows(image):
    """Direct call sites of the entry (e8 rel32 found by a byte scan of .text) with the function each one sits in."""
    rows = []
    text_va, text = image.text_bytes()
    at = text.find(b"\xe8")
    while at >= 0:
        if at + 5 <= len(text) and text_va + at + 5 + struct.unpack_from("<i", text, at + 1)[0] == ENTRY:
            try:
                start, end = image.fde(text_va + at)
                rows.append(("%#x" % (text_va + at), "%#x" % start, end - start))
            except EvidenceError:
                rows.append(("%#x" % (text_va + at), "-", 0))
        at = text.find(b"\xe8", at + 1)
    return rows


def analyse(image, vectors=9000, mutate=True):
    start, end, rows = decode_function(image)
    harness = Harness(image)
    cover = {}
    stats = {}
    named = named_cases()
    named_rows = []
    run_stream(harness, named, named_rows, cover=cover, stats=stats)
    grid_rows = []
    grid_count = run_stream(harness, grid_cases(), grid_rows, keep_every=5, cover=cover, stats=stats)
    vector_rows = []
    vector_count = run_stream(harness, vector_cases(vectors), vector_rows, keep_every=8, cover=cover, stats=stats)
    seen = set(harness.machine.seen)
    unreached = [row.va for row in rows if row.va not in seen and row.op not in ("int3", "nop")]
    sample = named + list(vector_cases(260, seed=0x77))
    variants = []
    for name in VARIANTS:
        failure = first_failure(harness, sample, frozenset((name,)))
        variants.append((name, "detected" if failure is not None else "MISSED", failure.name if failure else "-"))
    result = dict(rows=rows, start=start, end=end, named=named, named_rows=named_rows, grid_rows=grid_rows, grid_count=grid_count, vector_rows=vector_rows,
                  vector_count=vector_count, cover=cover, stats=stats, unreached=unreached, variants=variants, structural=structural_controls(image, named),
                  constants=constant_rows(image, rows), callers=caller_rows(image), locations=location_rows(image), sites=site_rows(image, start, end), uses=location_use_rows(rows))
    if mutate:
        order = named + list(vector_cases(520, seed=0x99))
        result["mutations"] = run_mutants(image, rows, seen, order, EXPLAINED)
        unexplained = [row for row in result["mutations"] if row[3] == "UNEXPLAINED"]
        if unexplained:
            raise EvidenceError("unexplained survivors: %s" % [(hex(row[0]), row[1]) for row in unexplained])
    return result


SIGN_ONLY = "the saturated value built here is only tested for its sign afterwards, and the edit keeps the sign"
CLAMP_IDEMPOTENT = "the edit sends in-range values through the clamp, which returns them unchanged; no value reaches outside the clamp range"
UNREACHABLE = {
    0x448BE50: "clamp of the scaled accumulator: the product of a 64 bit accumulator and a ratio of at most one never leaves the closed range of 2^63",
    0x448C42D: "remaining delta minus the closed amount: the closed amount has the delta's sign and no more magnitude, so the subtraction cannot overflow",
    0x448C495: "size plus the closed amount: the closed amount has the opposite sign to the size and no more magnitude, so the sum cannot overflow",
    0x448C657: "accumulator minus its share: the share has the accumulator's sign and no more magnitude, so the subtraction cannot overflow",
    0x448C81E: "size plus the closed amount on the negative arm: same opposite-sign argument as the positive arm",
    0x448C900: "negating a closed amount of 2^63: needs a size and a delta of magnitude 2^63 with opposite signs, which no pair of i64 values has",
}


def unreachable_rows(unreached):
    groups = {}
    starts = sorted(UNREACHABLE)
    for va in unreached:
        owner = [start for start in starts if start <= va]
        if not owner:
            raise EvidenceError("unreached row before every known group: %#x" % va)
        groups.setdefault(owner[-1], []).append(va)
    for start in starts:
        if start not in groups:
            raise EvidenceError("a group declared unreachable was reached: %#x" % start)
    return [("%#x" % start, len(groups[start]), "%#x" % groups[start][0], "%#x" % groups[start][-1], UNREACHABLE[start]) for start in starts]


EXPLAINED = {
    (0x448BD75, "immediate"): "threshold for infinity or NaN moves by one bit pattern; the quotient ratio times a 64 bit value never lands on the largest finite double",
    (0x448BD94, "condition"): CLAMP_IDEMPOTENT,
    (0x448BDA2, "condition"): CLAMP_IDEMPOTENT,
    (0x448BEF9, "immediate"): SIGN_ONLY,
    (0x448BEFD, "immediate"): SIGN_ONLY,
    (0x448C5CE, "immediate"): SIGN_ONLY,
    (0x448C5D7, "immediate"): SIGN_ONLY,
}
REPORT_TARGET = 0x4524E40


def render(result):
    files = {}

    def tsv(name, header, rows):
        files[name] = "\n".join(["\t".join(header)] + ["\t".join(str(cell) for cell in row) for row in rows]) + "\n"

    rows = result["rows"]
    tsv("function-rows.tsv", ("address", "size", "bytes", "operation"), [("%#x" % row.va, row.size, row.data.hex(), row.op) for row in rows])
    tsv("row-first-reach.tsv", ("address", "operation", "first_case"), [("%#x" % row.va, row.op, result["cover"].get(row.va, "-")) for row in rows])
    tsv("location-records.tsv", ("record", "file_pointer", "file_length", "file", "line", "column"), result["locations"])
    tsv("external-slots.tsv", ("slot", "relative_target", "call_sites", "sites"), result["sites"])
    tsv("callers.tsv", ("call_site", "caller_function", "caller_bytes"), result["callers"])
    tsv("location-use.tsv", ("call_site", "kind", "location_record"), result["uses"])
    tsv("constants.tsv", ("row", "form", "value", "bits"), result["constants"])
    tsv("outcomes-named.tsv", ("case", "price", "delta", "balance", "mode", "divisor", "acc", "size", "kind", "r9", "digest", "events"), result["named_rows"])
    tsv("outcomes-grid.tsv", ("case", "price", "delta", "balance", "mode", "divisor", "acc", "size", "kind", "r9", "digest", "events"), result["grid_rows"])
    tsv("outcomes-vector.tsv", ("case", "price", "delta", "balance", "mode", "divisor", "acc", "size", "kind", "r9", "digest", "events"), result["vector_rows"])
    tsv("unreached-rows.tsv", ("address",), [("%#x" % va,) for va in result["unreached"]])
    tsv("unreachable-groups.tsv", ("group_start", "rows", "first", "last", "why_no_input_reaches_it"), unreachable_rows(result["unreached"]))
    tsv("model-variants.tsv", ("variant", "outcome", "first_case"), result["variants"])
    tsv("structural-controls.tsv", ("control", "outcome"), result["structural"])
    mutations = result.get("mutations", [])
    if mutations:
        tsv("mutations.tsv", ("address", "kind", "outcome", "detail"), [("%#x" % va, k, o, d) for va, k, o, d in mutations])
    survivors = [row for row in mutations if row[2] == "survived"]
    tsv("equivalent-mutants.tsv", ("mutation", "address", "reason"), [(k, "%#x" % va, d) for va, k, o, d in survivors])
    killed = sum(1 for row in mutations if row[2] == "killed")
    variants_detected = sum(1 for row in result["variants"] if row[1] == "detected")
    structural_detected = sum(1 for row in result["structural"] if row[1] == "detected")
    total_cases = len(result["named"]) + result["grid_count"] + result["vector_count"]
    controls = len(result["variants"]) + len(result["structural"]) + len(mutations)
    detected = variants_detected + structural_detected + killed
    stats = result["stats"]
    summary = {
        "binary": "artifacts/node/115/hl-node", "sha256": SHA256, "entry": "%#x" % ENTRY, "end": "%#x" % result["end"], "bytes": result["end"] - result["start"],
        "instructions": len(rows), "named_cases": len(result["named"]), "grid_cases": result["grid_count"], "vector_cases": result["vector_count"],
        "outcome_counts": {kind: stats.get(kind, 0) for kind in ("ok", "err", "panic", "fault")},
        "location_reports": {"%#x" % va: stats.get(va, 0) for va in LOCATIONS}, "reached_rows": len(rows) - len(result["unreached"]),
        "unreached_rows": len(result["unreached"]), "model_variants": len(result["variants"]), "structural_controls": len(result["structural"]),
    }
    if mutations:
        summary["mutations"] = {"total": len(mutations), "killed": killed, "survived": len(survivors)}
    files["evidence.json"] = json.dumps(summary, indent=1, sort_keys=True) + "\n"
    files["measure.json"] = json.dumps({"cases": total_cases, "negative_controls": controls, "negative_detected": detected, "equivalent": len(survivors)}, indent=1, sort_keys=True) + "\n"
    return files


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.split("\n", 1)[0])
    parser.add_argument("--out", required=True, type=pathlib.Path)
    args = parser.parse_args(argv)
    image = load_image()
    files = render(analyse(image))
    args.out.mkdir(parents=True, exist_ok=True)
    for name, text in files.items():
        (args.out / name).write_text(text, encoding="ascii", newline="\n")
    print(json.dumps({"files": sorted(files)}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
