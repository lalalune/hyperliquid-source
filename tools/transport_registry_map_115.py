#!/usr/bin/env python3
"""Reconstruct the node #115 metrics-registry map path: key hasher 0x477e2b0, entry 0x476f260, reserve_rehash 0x47642d0, record 0x4771f70.

The module holds (1) an offline x86-64 interpreter (the repeated evaluator of the merged tools, plus lock cmpxchg, pcmpgtb), (2) a plain Python
model of the four functions, (3) a rig that writes a model table into interpreter memory, runs the real bytes and compares everything,
(4) deterministic case generators, (5) negative controls and the evidence writer. The binary is never executed.

    python3 tools/transport_registry_map_115.py --out research/work-items/transport-registry-map-115
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
                  (0x74, True): "pcmpeqb", (0x64, True): "pcmpgtb", (0x76, True): "pcmpeqd", (0x14, False): "punpckldq", (0x6C, True): "punpcklqdq",
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
        if two in (0xB0, 0xB1):
            reg, rm = modrm()
            return finish("cmpxchg", rm, ("r", reg), width if two == 0xB1 else 1)
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
        elif op == "pcmpgtb":
            left, right = self.xmm[row.a[1]].to_bytes(16, "little"), self.vector(row.b).to_bytes(16, "little")
            lanes = (b"\xff" if (one - 256 if one & 128 else one) > (two - 256 if two & 128 else two) else b"\x00" for one, two in zip(left, right))
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


# ---------------------------------------------------------------------------------------------------------------------
# Part 2: the reconstruction (plain Python model of the four functions) and the rig that runs the real bytes against it.
# ---------------------------------------------------------------------------------------------------------------------

M32 = 0xFFFFFFFF
M64 = 0xFFFFFFFFFFFFFFFF
HASHER, ENTRY, RESERVE, RECORD = 0x477E2B0, 0x476F260, 0x47642D0, 0x4771F70
HASHER_END, ENTRY_END, RESERVE_END, RECORD_END = 0x477E5B2, 0x476F480, 0x47649A0, 0x47721F0
FUNCTIONS = (("hasher", HASHER, HASHER_END), ("entry", ENTRY, ENTRY_END), ("reserve_rehash", RESERVE, RESERVE_END),
             ("record", RECORD, RECORD_END))

SLOT_ALLOC, SLOT_MEMSET, SLOT_MEMCPY, SLOT_FREE = 0x64DF480, 0x64DF750, 0x64DF568, 0x64DF4A0
SLOT_OOM, SLOT_PANIC_FMT, SLOT_PANIC, SLOT_MEMCMP = 0x64DF490, 0x64DF6B8, 0x64DF4C0, 0x64DF9F8
SLOT_RESERVE, SLOT_LOCK, SLOT_UNLOCK = 0x64EB138, 0x64E01F8, 0x64E0F38
SLOTS = (SLOT_ALLOC, SLOT_MEMSET, SLOT_MEMCPY, SLOT_FREE, SLOT_OOM, SLOT_PANIC_FMT, SLOT_PANIC, SLOT_MEMCMP, SLOT_RESERVE, SLOT_LOCK,
         SLOT_UNLOCK)
MARK_BASE = 0x5000000000

EMPTY, DELETED = 0xFF, 0x80
H2_SHIFT = 57
BUCKET = 48
HASH_C1, HASH_C2, HASH_C3 = 0x243F6A8885A308D3, 0x13198A2E03707344, 0xA4093822299F31D0
HASH_K1, HASH_K2, HASH_K3, HASH_K4 = 0x1427BB2D3769B199, 0xF1357AEA2E62A9C5, 0x1393720A3247E767, 0x9B99C6DE196CC6F8
PLUS_INF_SUM = 0x459090          # address of the f64 the record function stores when a sum reaches +infinity
ALLOC_LIMIT = 1 << 22

# heap layout used by the rig (all inside the machine heap)
MAP_AT = HEAP_BASE + 0x200
MUTEX_AT = HEAP_BASE + 0x400
OUT_AT = HEAP_BASE + 0x700
KEY_AT = HEAP_BASE + 0x800
STR_AT = HEAP_BASE + 0x1000
OLD_AT = HEAP_BASE + 0x4000
BUMP_AT = HEAP_BASE + 0x10000
HEAP_USED = 0x34000
EMPTY_GROUP_AT = HEAP_BASE + 0x300


class Panic(Exception):
    pass


def rol64(value, count):
    return ((value << count) | (value >> (64 - count))) & M64


def fold(left, right):
    product = left * right
    return ((product >> 64) ^ product) & M64


def hash_bytes_state(data):
    """The two 64-bit lanes the hasher builds from the key bytes before the final fold (length handling of the 0x477e2b0 body)."""
    n = len(data)
    if n > 16:
        left, right = HASH_C1, HASH_C2
        chunks = ((n - 17) >> 4) + 1
        pairs, odd = chunks >> 1, chunks & 1
        at = 0
        for _ in range(pairs):
            left = fold(left ^ int.from_bytes(data[at:at + 8], "little"), int.from_bytes(data[at + 8:at + 16], "little") ^ HASH_C3)
            right = fold(right ^ int.from_bytes(data[at + 16:at + 24], "little"), int.from_bytes(data[at + 24:at + 32], "little") ^ HASH_C3)
            at += 32
        if odd:
            mixed = fold(left ^ int.from_bytes(data[at:at + 8], "little"), int.from_bytes(data[at + 8:at + 16], "little") ^ HASH_C3)
            left, right = right, mixed
        return left ^ int.from_bytes(data[n - 16:n - 8], "little"), right ^ int.from_bytes(data[n - 8:n], "little")
    if n >= 8:
        return HASH_C1 ^ int.from_bytes(data[:8], "little"), HASH_C2 ^ int.from_bytes(data[n - 8:], "little")
    if n >= 4:
        return HASH_C1 ^ int.from_bytes(data[:4], "little"), HASH_C2 ^ int.from_bytes(data[n - 4:], "little")
    if n:
        return HASH_C1 ^ data[0], HASH_C2 ^ (data[n - 1] << 8 | data[n >> 1])
    return HASH_C1, HASH_C2


def key_hash(key, strings):
    """Hash of a 24-byte registry key. key[0] != 0: (pointer, length, u32 tag); key[0] == 0: (0, pointer, length) with no tag."""
    if key[0]:
        data, tag = strings[key[0]][:key[1]], key[2] & M32
    else:
        data, tag = strings[key[1]][:key[2]], None
    left, right = hash_bytes_state(data)
    product = left * right
    mixed = ((len(data) ^ (product >> 64) ^ product) & M64) * HASH_K1 & M64
    if tag is None:
        return rol64((mixed + HASH_K4) & M64, 20)
    return rol64(((mixed + tag) * HASH_K2 + HASH_K3) & M64, 20)


def key_bytes(key, strings):
    return (strings[key[0]][:key[1]], key[2] & M32) if key[0] else (strings[key[1]][:key[2]], None)


def keys_equal(bucket_key, probe_key, strings):
    if (bucket_key[0] == 0) != (probe_key[0] == 0):
        return False
    return key_bytes(bucket_key, strings) == key_bytes(probe_key, strings) and (bucket_key[0] != 0 or bucket_key[2] == probe_key[2])


def mask_to_capacity(mask):
    return mask if mask < 8 else (mask + 1) // 8 * 7


def capacity_to_buckets(cap):
    if cap < 8:
        return 4 if cap < 4 else 8
    adjusted = cap * 8 // 7
    return 1 << (adjusted - 1).bit_length()


class Model:
    """A registry table: control bytes, 48-byte buckets (six u64 words) and the allocation bookkeeping the rig mirrors."""

    def __init__(self, strings):
        self.strings = strings
        self.ctrl = bytearray([EMPTY] * 16)
        self.mask = 0
        self.growth = 0
        self.items = 0
        self.slots = {}
        self.ctrl_at = EMPTY_GROUP_AT
        self.bump = BUMP_AT
        self.events = []
        self.fixups = 0

    def copy(self):
        other = Model(self.strings)
        other.ctrl, other.mask, other.growth, other.items = bytearray(self.ctrl), self.mask, self.growth, self.items
        other.slots, other.ctrl_at, other.bump = dict(self.slots), self.ctrl_at, self.bump
        return other

    def set_ctrl(self, index, value):
        self.ctrl[index] = value
        self.ctrl[((index - 16) & self.mask) + 16] = value

    def hash_of(self, index):
        return key_hash(self.slots[index][:3], self.strings)

    def find_insert_slot(self, hashed):
        pos, stride = hashed & self.mask, 0
        while True:
            group = self.ctrl[pos:pos + 16]
            hits = [bit for bit in range(16) if group[bit] & 0x80]
            if hits:
                index = (pos + hits[0]) & self.mask
                if self.ctrl[index] & 0x80:
                    return index
                self.fixups += 1
                return next(bit for bit in range(16) if self.ctrl[bit] & 0x80)
            stride += 16
            pos = (pos + stride) & self.mask

    def find(self, key):
        """Entry probe: ('occupied', index) or ('vacant', hash); growth is handled by the caller."""
        hashed = key_hash(key, self.strings)
        h2 = hashed >> H2_SHIFT
        pos, stride = hashed & self.mask, 0
        while True:
            group = self.ctrl[pos:pos + 16]
            for bit in range(16):
                if group[bit] == h2:
                    index = (pos + bit) & self.mask
                    if index in self.slots and keys_equal(self.slots[index][:3], key, self.strings):
                        return "occupied", index
            if EMPTY in group:
                return "vacant", hashed
            stride += 16
            pos = (pos + stride) & self.mask

    def alloc(self, size):
        if size > ALLOC_LIMIT:
            self.events.append(("alloc-fail", size))
            return None
        pointer = self.bump
        self.bump += (size + 15) & ~15
        self.events.append(("alloc", size, pointer))
        return pointer

    def reserve(self, additional, infallible):
        """reserve_rehash. Returns ('ok',), ('cap',), ('alloc', size) or raises Panic."""
        new_items = self.items + additional
        if new_items > M64:
            return self._fail(infallible, None)
        full = mask_to_capacity(self.mask)
        if new_items <= full // 2:
            self._rehash_in_place()
            return ("ok",)
        wanted = max(new_items, full + 1)
        if wanted > 0x1FFFFFFFFFFFFFFF:
            return self._fail(infallible, None)
        buckets = capacity_to_buckets(wanted)
        data = buckets * BUCKET
        total = data + buckets + 16
        if data > M64 or total > M64 or total > 0x7FFFFFFFFFFFFFEE:
            return self._fail(infallible, None)
        pointer = self.alloc(total)
        if pointer is None:
            if infallible:
                raise Panic(("oom", 16, total))
            return ("alloc", total)
        self._resize(buckets, pointer + data)
        return ("ok",)

    def _fail(self, infallible, size):
        if infallible:
            raise Panic(("capacity-overflow",))
        return ("cap",)

    def _rehash_in_place(self):
        buckets = self.mask + 1
        for index in range(((buckets + 15) // 16) * 16):
            self.ctrl[index] = EMPTY if self.ctrl[index] & 0x80 else DELETED
        if buckets < 16:
            self.ctrl[16:16 + buckets] = self.ctrl[:buckets]
        else:
            self.ctrl[buckets:buckets + 16] = self.ctrl[:16]
        index = 0
        while index <= self.mask:
            if self.ctrl[index] != DELETED:
                index += 1
                continue
            hashed = self.hash_of(index)
            target = self.find_insert_slot(hashed)
            home = hashed & self.mask
            if (((index - home) ^ (target - home)) & self.mask) < 16:
                self.set_ctrl(index, hashed >> H2_SHIFT)
                index += 1
                continue
            previous = self.ctrl[target]
            self.set_ctrl(target, hashed >> H2_SHIFT)
            if previous == EMPTY:
                self.set_ctrl(index, EMPTY)
                self.slots[target] = self.slots.pop(index)
                index += 1
            else:
                self.slots[index], self.slots[target] = self.slots[target], self.slots[index]
        self.growth = mask_to_capacity(self.mask) - self.items

    def _resize(self, buckets, ctrl_at):
        new = Model(self.strings)
        new.ctrl, new.mask, new.ctrl_at, new.bump = bytearray([EMPTY] * (buckets + 16)), buckets - 1, ctrl_at, self.bump
        for index in range(self.mask + 1):
            if self.items and not self.ctrl[index] & 0x80:
                hashed = self.hash_of(index)
                target = new.find_insert_slot(hashed)
                new.set_ctrl(target, hashed >> H2_SHIFT)
                new.slots[target] = self.slots[index]
        old_mask, old_ctrl_at = self.mask, self.ctrl_at
        self.ctrl, self.mask, self.ctrl_at, self.slots = new.ctrl, new.mask, new.ctrl_at, new.slots
        self.growth = mask_to_capacity(self.mask) - self.items
        if old_mask:
            data = (old_mask * BUCKET + 0x3F) & ~0xF
            size = data + old_mask + 0x11
            self.events.append(("free", old_ctrl_at - data, size, 4 if size < 0x10 else 0))

    def entry(self, key):
        """The 0x476f260 body: returns ('occupied', index) or ('vacant', hash); reserves one slot first when the table is full."""
        kind, value = self.find(key)
        if kind == "vacant" and self.growth == 0:
            self.reserve(1, True)
        return kind, value

    def insert_vacant(self, hashed, key):
        index = self.find_insert_slot(hashed)
        previous = self.ctrl[index]
        self.set_ctrl(index, hashed >> H2_SHIFT)
        self.growth -= previous & 1
        self.slots[index] = tuple(key) + (0, 0, 0)
        self.items += 1
        return index


def f64(bits):
    return to_float(bits)


def saturate_sum(total_bits, plus_inf_bits):
    """What record stores as the new running sum: negative, NaN and -inf results become +0.0, +inf becomes the constant, -0.0 stays."""
    magnitude = total_bits & 0x7FFFFFFFFFFFFFFF
    if magnitude == 0x7FF0000000000000:
        return plus_inf_bits if total_bits >> 63 == 0 else 0
    if magnitude > 0x7FF0000000000000:
        return 0
    if total_bits >> 63 and magnitude:
        return 0
    return total_bits


def record_update(slot, value_bits, plus_inf_bits):
    count, total, largest = slot[3], slot[4], slot[5]
    total = saturate_sum(to_bits(f64(total) + f64(value_bits)), plus_inf_bits)
    count = min(count + 1, M64)
    left, right = f64(largest), f64(value_bits)
    largest = largest if left > right else value_bits
    return slot[:3] + (count, total, largest)


def record(model, key, value_bits, plus_inf_bits):
    """The 0x4771f70 body on the model: find or insert the key, then fold the value into (count, saturated sum, maximum)."""
    kind, value = model.entry(key)
    if kind == "vacant":
        index = model.insert_vacant(value, key)
    else:
        index = value
    model.slots[index] = record_update(model.slots[index], value_bits, plus_inf_bits)
    return index



# ---------------------------------------------------------------------------------------------------------------------
# Part 3: the rig. It writes a model table into machine memory, runs the real bytes and reads the result back.
# ---------------------------------------------------------------------------------------------------------------------

class Rng:
    """Small deterministic generator so every case list is reproducible without the random module."""

    def __init__(self, seed):
        self.state = seed & M64

    def next(self):
        self.state = (self.state * 6364136223846793005 + 1442695040888963407) & M64
        value = self.state
        value ^= value >> 29
        return (value * 0xBF58476D1CE4E5B9) & M64 ^ (self.state >> 17)

    def below(self, bound):
        return self.next() % bound

    def pick(self, items):
        return items[self.below(len(items))]

    def chance(self, num, den):
        return self.below(den) < num


class Rig:
    def __init__(self, image, patches=None):
        self.image = image
        machine = Machine(image, patches)
        machine.real = frozenset({HASHER, ENTRY, RESERVE})
        machine.step_limit = 400000
        self.machine = machine
        self.statics = machine.memory.statics
        hooks = {SLOT_ALLOC: self.on_alloc, SLOT_MEMSET: self.on_memset, SLOT_MEMCPY: self.on_memcpy, SLOT_FREE: self.on_free,
                 SLOT_OOM: self.on_oom, SLOT_PANIC_FMT: self.on_panic_fmt, SLOT_PANIC: self.on_panic, SLOT_MEMCMP: self.on_memcmp,
                 SLOT_LOCK: self.on_lock, SLOT_UNLOCK: self.on_unlock}
        for slot, hook in hooks.items():
            self.statics[slot] = MARK_BASE + slot
            machine.slots[MARK_BASE + slot] = hook
        self.statics[SLOT_RESERVE] = RESERVE
        self.bump = BUMP_AT
        self.events = []
        self.covered = set()
        self.last_input = None
        self.strings = {}
        self.plus_inf = int.from_bytes(image.blob[image.offset(PLUS_INF_SUM):image.offset(PLUS_INF_SUM) + 8], "little")

    # ---- hooks (the external functions the four bodies call through the import table) ----
    def on_alloc(self, m):
        size = m.regs[RDI]
        if size > ALLOC_LIMIT:
            self.events.append(("alloc-fail", size))
            m.regs[RAX] = 0
            return
        pointer = self.bump
        self.bump += (size + 15) & ~15
        self.events.append(("alloc", size, pointer))
        m.regs[RAX] = pointer

    def on_memset(self, m):
        pointer, byte, count = m.regs[RDI], m.regs[RSI] & 0xFF, m.regs[RDX]
        m.memory.put_bytes(pointer, bytes([byte]) * count)
        m.regs[RAX] = pointer

    def on_memcpy(self, m):
        pointer, source, count = m.regs[RDI], m.regs[RSI], m.regs[RDX]
        m.memory.put_bytes(pointer, m.memory.bytes_at(source, count))
        m.regs[RAX] = pointer

    def on_free(self, m):
        self.events.append(("free", m.regs[RDI], m.regs[RSI], m.regs[RDX] & M32))

    def on_oom(self, m):
        raise Panic(("oom", m.regs[RDI], m.regs[RSI]))

    def on_panic_fmt(self, m):
        raise Panic(("capacity-overflow",))

    def on_panic(self, m):
        raise Panic(("panic",))

    def on_memcmp(self, m):
        count = m.regs[RDX]
        left, right = m.memory.bytes_at(m.regs[RDI], count), m.memory.bytes_at(m.regs[RSI], count)
        m.regs[RAX] = 0 if left == right else (1 if left > right else M32)

    def on_lock(self, m):
        self.events.append(("lock-slow", m.regs[RDX] & M32))
        m.memory.write(m.regs[RDI], 1, 3 if m.memory.read(m.regs[RDI], 1) == 3 else 1)

    def on_unlock(self, m):
        self.events.append(("unlock-slow", m.regs[RSI] & M32))
        m.memory.write(m.regs[RDI], 1, 0)

    # ---- memory image of a model table ----
    def reset(self):
        self.machine.memory.reset(HEAP_USED)
        self.bump = BUMP_AT
        self.events = []
        self.covered |= self.machine.seen
        self.machine.seen = set()

    def place_strings(self, strings):
        """strings: pointer -> bytes. Written at their pointers."""
        self.strings = strings
        for pointer, data in strings.items():
            self.machine.memory.put_bytes(pointer, data)

    def write_table(self, model, at):
        """Write `model` (control bytes, buckets, header words) with its table header at `at`."""
        memory = self.machine.memory
        if model.mask == 0 and not model.slots:
            ctrl = EMPTY_GROUP_AT
            memory.put_bytes(ctrl, bytes([EMPTY] * 16))
        else:
            buckets = model.mask + 1
            ctrl = model.ctrl_at
            memory.put_bytes(ctrl, bytes(model.ctrl))
            for index, words in model.slots.items():
                memory.put_bytes(ctrl - (index + 1) * BUCKET, b"".join(word.to_bytes(8, "little") for word in words))
            self.bump = max(self.bump, ctrl + buckets + 16)
        model.ctrl_at = ctrl
        for offset, word in ((0, ctrl), (8, model.mask), (0x10, model.growth), (0x18, model.items)):
            memory.write(at + offset, 8, word)

    def read_table(self, at, model_like):
        """Read the header at `at` back into a Model using the same string pool; returns (Model, ctrl bytes)."""
        memory = self.machine.memory
        ctrl, mask, growth, items = (memory.read(at + offset, 8) for offset in (0, 8, 0x10, 0x18))
        out = Model(self.strings)
        out.mask, out.growth, out.items, out.ctrl_at = mask, growth, items, ctrl
        out.ctrl = bytearray(memory.bytes_at(ctrl, mask + 1 + 16 if mask else 16))
        for index in range(mask + 1):
            if not out.ctrl[index] & 0x80:
                words = memory.bytes_at(ctrl - (index + 1) * BUCKET, BUCKET)
                out.slots[index] = tuple(int.from_bytes(words[at:at + 8], "little") for at in range(0, BUCKET, 8))
        return out

    def run(self, entry, args, stack=()):
        self.machine.cache = self.machine.cache
        try:
            return ("ret", self.machine.run(entry, args, stack))
        except Panic as exc:
            return ("panic", exc.args[0])

    def call_hash(self, key, strings):
        self.reset()
        self.last_input = ("hash", key, tuple(len(strings[pointer]) for pointer in sorted(strings)))
        self.place_strings(strings)
        for offset, word in enumerate(key):
            self.machine.memory.write(KEY_AT + 8 * offset, 8, word)
        outcome = self.run(HASHER, {RDI: MAP_AT + 0x20, RSI: KEY_AT})
        return outcome

    def call_reserve(self, model, additional, infallible):
        self.reset()
        self.last_input = ("reserve", model.ctrl.hex(), model.items, model.growth, additional, infallible)
        self.place_strings(model.strings)
        self.write_table(model, MAP_AT)
        outcome = self.run(RESERVE, {RDI: MAP_AT, RSI: additional, RDX: MAP_AT + 0x20, RCX: 1 if infallible else 0})
        result = None
        if outcome[0] == "ret":
            result = (outcome[1], self.machine.regs[RDX])
        return outcome, result, self.read_table(MAP_AT, model)

    def call_entry(self, model, key):
        self.reset()
        self.last_input = ("entry", model.ctrl.hex(), model.items, model.growth, key)
        self.place_strings(model.strings)
        self.write_table(model, MAP_AT)
        for offset, word in enumerate(key):
            self.machine.memory.write(KEY_AT + 8 * offset, 8, word)
        outcome = self.run(ENTRY, {RDI: OUT_AT, RSI: MAP_AT, RDX: KEY_AT})
        out = [self.machine.memory.read(OUT_AT + 8 * at, 8) for at in range(5)]
        return outcome, out, self.read_table(MAP_AT, model)

    def call_record(self, model, key, value_bits, lock_byte):
        self.reset()
        self.last_input = ("record", model.ctrl.hex(), model.items, model.growth, key, value_bits, lock_byte)
        self.place_strings(model.strings)
        self.write_table(model, MUTEX_AT + 0xB8)
        self.machine.memory.write(MUTEX_AT, 1, lock_byte)
        for offset, word in enumerate(key):
            self.machine.memory.write(KEY_AT + 8 * offset, 8, word)
        self.machine.xmm[0] = value_bits
        outcome = self.run(RECORD, {RDI: MUTEX_AT, RSI: KEY_AT})
        lock_after = self.machine.memory.read(MUTEX_AT, 1)
        return outcome, lock_after, self.read_table(MUTEX_AT + 0xB8, model)


def tables_match(actual, expected):
    if (actual.mask, actual.growth, actual.items) != (expected.mask, expected.growth, expected.items):
        return False
    if bytes(actual.ctrl) != bytes(expected.ctrl):
        return False
    if actual.slots != expected.slots:
        return False
    return actual.mask == 0 and not actual.slots or actual.ctrl_at == expected.ctrl_at



# ---------------------------------------------------------------------------------------------------------------------
# Part 4: case generators (all derived from a fixed seed and the function constants) and the per-function comparisons.
# ---------------------------------------------------------------------------------------------------------------------

SPECIAL_VALUES = (0x0000000000000000, 0x8000000000000000, 0x3FF0000000000000, 0xBFF0000000000000, 0x7FF0000000000000, 0xFFF0000000000000,
                  0x7FF8000000000000, 0xFFF8000000000001, 0x7FEFFFFFFFFFFFFF, 0xFFEFFFFFFFFFFFFF, 0x0000000000000001, 0x8000000000000001,
                  0x000FFFFFFFFFFFFF, 0x800FFFFFFFFFFFFF, 0x0010000000000000, 0x8010000000000000, 0x4059000000000000, 0xC059000000000000,
                  0x7FF0000000000001, 0x3FE0000000000000)


def make_strings(rng, count):
    """A pool of byte strings at fixed pointers: mixed lengths, shared prefixes and equal contents at different pointers."""
    strings, pointer, bases = {}, STR_AT, []
    for number in range(count):
        kind = rng.below(5)
        if kind == 0 or not bases:
            size = rng.pick((0, 1, 2, 3, 4, 5, 7, 8, 9, 12, 15, 16, 17, 20, 31, 32, 33, 34, 40, 47, 48, 49, 64, 65, 100))
            data = bytes(rng.below(256) for _ in range(size))
            bases.append(data)
        elif kind == 1:
            data = rng.pick(bases)
        elif kind == 2 and bases:
            data = bytearray(rng.pick(bases))
            if data:
                data[-1] ^= 1 + rng.below(255)
            data = bytes(data)
        elif kind == 3:
            data = bytes(rng.below(256) for _ in range(rng.pick((6, 10, 18, 24, 36))))
        else:
            data = (rng.pick(bases) + bytes([rng.below(256)]))[:150]
        strings[pointer] = data
        pointer += (len(data) + 7) & ~7
        pointer += 8 * rng.below(3)
        if pointer > STR_AT + 0x2F00:
            break
    return strings


def random_key(rng, strings, pointers):
    pointer = rng.pick(pointers)
    size = len(strings[pointer])
    length = size if rng.chance(3, 4) else rng.below(size + 1)
    tag = rng.below(1 << 32) if rng.chance(1, 2) else rng.below(6)
    if rng.chance(1, 8):
        tag |= rng.below(1 << 32) << 32
    if rng.chance(1, 3):
        return (0, pointer, length)
    return (pointer, length, tag)


def build_table(rng, strings, buckets, fill, tombstones, dead=0):
    """A valid model table at OLD_AT: `fill` full buckets, `tombstones` DELETED buckets and growth_left kept consistent."""
    model = Model(strings)
    if buckets == 0:
        return model
    model.mask = buckets - 1
    data = buckets * BUCKET
    model.ctrl_at = OLD_AT + data
    model.ctrl = bytearray([EMPTY] * (buckets + 16))
    capacity = mask_to_capacity(model.mask)
    pointers = sorted(strings)
    tries = 0
    while model.items < min(fill + dead, capacity) and tries < 4 * buckets:
        tries += 1
        key = random_key(rng, strings, pointers)
        kind, hashed = model.find(key)
        if kind == "occupied":
            continue
        index = model.find_insert_slot(hashed)
        model.set_ctrl(index, hashed >> H2_SHIFT)
        model.slots[index] = key + (rng.next(), rng.next(), rng.next())
        model.items += 1
    model.growth = capacity - model.items
    full = sorted(model.slots)
    for index in sorted(rng.pick(full) for _ in range(dead)) if full else ():
        if index in model.slots:
            model.set_ctrl(index, DELETED)
            del model.slots[index]
            model.items -= 1
    full = sorted(model.slots)
    for index in full[:]:
        if tombstones and rng.chance(tombstones, 100) and len(full) > 0:
            model.set_ctrl(index, DELETED if rng.chance(3, 4) else EMPTY)
            del model.slots[index]
            model.items -= 1
            if model.ctrl[index] == EMPTY:
                model.growth += 1
    return model


def add_same_key_run(rng, model, strings, count):
    """`count` copies of one key inserted the way the table would (one long probe chain with identical hashes)."""
    key = random_key(rng, strings, sorted(strings))
    hashed = key_hash(key, strings)
    for _ in range(count):
        if model.growth <= 0:
            break
        index = model.find_insert_slot(hashed)
        model.growth -= model.ctrl[index] & 1
        model.set_ctrl(index, hashed >> H2_SHIFT)
        model.slots[index] = key + (rng.next(), rng.next(), rng.next())
        model.items += 1
    return key


def add_cluster(rng, model, strings, start, length):
    """A run of full buckets starting at `start` (their ctrl bytes follow their own keys), so a probe from there meets no EMPTY."""
    pointers = sorted(strings)
    for step in range(length):
        index = (start + step) & model.mask
        if model.ctrl[index] == EMPTY and model.growth > 0:
            key = random_key(rng, strings, pointers)
            model.set_ctrl(index, key_hash(key, strings) >> H2_SHIFT)
            model.slots[index] = key + (rng.next(), rng.next(), rng.next())
            model.items += 1
            model.growth -= 1


def key_homed_at(rng, model, strings, start, span):
    pointers = sorted(strings)
    for _ in range(400):
        key = random_key(rng, strings, pointers)
        if ((key_hash(key, strings) - start) & model.mask) < span:
            return key
    return key


def table_sizes(rng):
    return rng.pick((0, 4, 4, 8, 8, 8, 8, 16, 16, 32, 32, 64))


def compare_result(label, ok, detail):
    return ok, "%s:%s" % (label, detail)


def check_hash(rig, rng, number, strings):
    pointers = sorted(strings)
    key = random_key(rng, strings, pointers)
    expected = key_hash(key, strings)
    outcome = rig.call_hash(key, strings)
    return outcome == ("ret", expected), "hash"


def clone_with_strings(model, strings):
    other = model.copy()
    other.strings = strings
    return other


def check_reserve(rig, rng, number, strings):
    buckets = table_sizes(rng)
    capacity = mask_to_capacity(buckets - 1) if buckets else 0
    fill = rng.below(capacity + 1) if buckets else 0
    dense = buckets >= 16 and rng.chance(2, 5)
    if dense:
        fill, dead = rng.below(capacity // 2 - 1), rng.below(capacity // 2 + 6)
        model = build_table(rng, strings, buckets, fill, 0, dead)
    else:
        model = build_table(rng, strings, buckets, fill, rng.pick((0, 0, 30, 60, 90)))
    run = buckets >= 32 and rng.chance(1, 5)
    tiny = buckets in (4, 8) and rng.chance(1, 3)
    if run and rng.chance(1, 3):
        buckets = 128
        capacity = mask_to_capacity(buckets - 1)
    if run:
        model = build_table(rng, strings, buckets, rng.below(4), 0)
        add_same_key_run(rng, model, strings, 17 + rng.below(capacity // 2 - 4))
        if rng.chance(1, 2):
            for index in sorted(model.slots)[:rng.below(5)]:
                model.set_ctrl(index, DELETED)
                del model.slots[index]
                model.items -= 1
    if tiny:
        for _ in range(60):                                    # look for a small table whose in-place pass needs the group-0 fixup
            model = build_table(rng, strings, buckets, 0, 0)
            add_same_key_run(rng, model, strings, 1 + rng.below(min(capacity, 4)))
            for index in sorted(model.slots)[:rng.below(3)]:
                model.set_ctrl(index, DELETED)
                del model.slots[index]
                model.items -= 1
            probe = model.copy()
            probe._rehash_in_place()
            if probe.fixups:
                break
    kind = rng.below(12)
    if tiny:
        additional = rng.below(2)
    elif run:
        additional = rng.below(max(1, capacity // 2 - model.items + 3))
    elif dense:
        additional = rng.below(max(1, capacity // 2 - model.items + 2))
    elif kind == 0:
        additional = rng.pick((1 << 20, 1 << 30, 1 << 40, 1 << 62, 1 << 63, M64, 1 << 61, (1 << 61) - 1, 1 << 58, 1 << 57, (1 << 57) + 5, 1 << 59, 1 << 60))
    elif kind == 1:
        additional = rng.below(200)
    else:
        additional = rng.below(max(2, capacity // 2 + 3))
    infallible = rng.chance(1, 2)
    if not buckets:
        additional = max(additional, 1)                        # the shared empty group is never rehashed in place
    expected = model.copy()
    try:
        result = expected.reserve(additional, infallible)
        panic = None
    except Panic as exc:
        result, panic = None, exc.args[0]
    outcome, got, table = rig.call_reserve(model, additional, infallible)
    rig_events = [event for event in rig.events if event[0] in ("alloc", "alloc-fail", "free")]
    if panic is not None:
        return outcome == ("panic", panic) and rig_events == expected.events, "reserve-panic"
    if outcome[0] != "ret":
        return False, "reserve-halt"
    if result[0] == "ok":
        ok = got[0] == 0x8000000000000001
    elif result[0] == "cap":
        ok = got[0] == 0
    else:
        ok = got[0] == 0x10 and got[1] == result[1]
    ok = ok and rig_events == expected.events
    if result[0] in ("ok",):
        ok = ok and tables_match(table, expected)
    else:
        ok = ok and tables_match(table, model)
    return ok, "reserve-" + result[0]


def check_entry(rig, rng, number, strings):
    buckets = table_sizes(rng)
    capacity = mask_to_capacity(buckets - 1) if buckets else 0
    fill = rng.below(capacity + 1) if buckets else 0
    model = build_table(rng, strings, buckets, fill, rng.pick((0, 0, 0, 40)))
    pointers = sorted(strings)
    mode = rng.below(6)
    start = rng.below(buckets) if buckets else 0
    if buckets >= 32 and rng.chance(1, 4):
        add_cluster(rng, model, strings, start, 16 + rng.below(26))
        if mode >= 3:
            mode = 6
    if mode < 2 and model.slots:
        key = rng.pick(sorted(model.slots.values()))[:3]
        if rng.chance(1, 3):                                   # same bytes, other pointer, when the pool has one
            pointer = key[0] or key[1]
            same = [p for p in pointers if strings[p] == strings[pointer]]
            alt = rng.pick(same)
            key = (alt, key[1], key[2] ^ (rng.below(2) << 40)) if key[0] else (0, alt, key[2])
    elif mode == 2 and model.slots:
        base = rng.pick(sorted(model.slots.values()))[:3]
        key = (base[0], base[1], base[2] ^ (1 << rng.below(32))) if base[0] else (0, base[1], base[2] + 1 if base[2] < len(strings[base[1]]) else max(base[2] - 1, 0))
    elif mode == 6:
        key = key_homed_at(rng, model, strings, start, 3)
    else:
        key = random_key(rng, strings, pointers)
    if model.growth and model.mask and rng.chance(1, 4):
        model.growth = 0                                       # force the reserve call on a miss
    expected = model.copy()
    kind, value = expected.entry(key)
    outcome, out, table = rig.call_entry(model, key)
    if outcome[0] != "ret" or outcome[1] != OUT_AT:
        return False, "entry-halt"
    if kind == "occupied":
        ok = out[0] == 0 and out[1] == expected.ctrl_at - value * BUCKET and out[2] == MAP_AT
    else:
        ok = out[0] == MAP_AT and out[1] == value and tuple(out[2:5]) == key
    ok = ok and tables_match(table, expected)
    events = [event for event in rig.events if event[0] in ("alloc", "alloc-fail", "free")]
    return ok and events == expected.events, "entry-" + kind + ("-grow" if events else "")


def check_record(rig, rng, number, strings):
    buckets = table_sizes(rng)
    capacity = mask_to_capacity(buckets - 1) if buckets else 0
    fill = rng.below(capacity + 1) if buckets else 0
    model = build_table(rng, strings, buckets, fill, rng.pick((0, 0, 40)))
    start = rng.below(buckets) if buckets else 0
    clustered = buckets >= 32 and rng.chance(1, 4)
    tiny = buckets in (4, 8) and rng.chance(1, 2)
    if tiny:
        model = build_table(rng, strings, buckets, 0, 0)
        start = model.mask
        add_cluster(rng, model, strings, start, capacity - 1)
    if clustered:
        add_cluster(rng, model, strings, start, 16 + rng.below(26))
    for index, words in list(model.slots.items()):
        pick = rng.below(8)
        count = (M64 - rng.below(2)) if pick == 0 else rng.below(1000)
        model.slots[index] = words[:3] + (count, rng.pick(SPECIAL_VALUES) if rng.chance(1, 2) else to_bits(rng.below(2000) / 8.0),
                                          rng.pick(SPECIAL_VALUES) if rng.chance(1, 2) else to_bits(rng.below(2000) / 8.0))
    pointers = sorted(strings)
    if (clustered or tiny) and rng.chance(1, 2):
        key = key_homed_at(rng, model, strings, start, 1 if tiny else 3)
    elif model.slots and rng.chance(2, 3):
        key = rng.pick(sorted(model.slots.values()))[:3]
    else:
        key = random_key(rng, strings, pointers)
    if model.growth and model.mask and rng.chance(1, 5):
        model.growth = 0
    value_bits = rng.pick(SPECIAL_VALUES) if rng.chance(1, 2) else to_bits((rng.below(4000) - 1500) / 16.0)
    lock = rng.pick((0, 0, 0, 0, 1, 3))
    expected = model.copy()
    record(expected, key, value_bits, rig.plus_inf)
    outcome, lock_after, table = rig.call_record(model, key, value_bits, lock)
    if outcome[0] != "ret":
        return False, "record-halt"
    slow = [event[0] for event in rig.events if event[0].endswith("slow")]
    # an uncontended lock (0) is taken and released inline; bytes 1 and 3 go to the slow acquire (which keeps the parked bit of 3, so
    # the release then also goes to the slow path)
    wanted = (["lock-slow"] if lock else []) + (["unlock-slow"] if lock == 3 else [])
    events = [event for event in rig.events if event[0] in ("alloc", "alloc-fail", "free")]
    ok = lock_after == 0 and slow == wanted and tables_match(table, expected) and events == expected.events
    return ok, "record-" + ("slow" if lock else "inline")



# ---------------------------------------------------------------------------------------------------------------------
# Part 5: suites, negative controls and the evidence writer.
# ---------------------------------------------------------------------------------------------------------------------

SEED = 0x7A11
SUITES = (("hash", check_hash, 3200, 8), ("entry", check_entry, 4000, 5), ("reserve", check_reserve, 4800, 6),
          ("record", check_record, 3600, 5))                      # (name, check, cases, one row in `stride` goes to cases.tsv)
MUTANT_SUITES = (("hash", check_hash, 300), ("entry", check_entry, 1500), ("reserve", check_reserve, 700), ("record", check_record, 500))


def suite_cases(rig, check, count, seed):
    """Yield (index, ok, label, input digest, steps) one case at a time."""
    rng = Rng(seed)
    for index in range(count):
        strings = make_strings(rng, 24)
        before = rig.machine.steps
        ok, label = check(rig, rng, index, strings)
        digest = hashlib.sha256(repr(rig.last_input).encode()).hexdigest()[:12]
        yield index, ok, label, digest, rig.machine.steps - before


def first_divergence(image, patches, suites=MUTANT_SUITES):
    """Run the case lists on an image with `patches` applied; return a description of the first divergence or None."""
    rig = Rig(image, patches)
    rig.machine.step_limit = MUTANT_STEP_LIMIT
    for number, (name, check, count) in enumerate(suites):
        rng = Rng(SEED + number)
        for index in range(count):
            strings = make_strings(rng, 24)
            try:
                ok, label = check(rig, rng, index, strings)
            except (Halt, EvidenceError, KeyError, ValueError, IndexError, OverflowError, struct.error) as exc:
                return "%s#%d %s" % (name, index, type(exc).__name__)
            if not ok:
                return "%s#%d %s" % (name, index, label)
    return None


def byte_mutants(image, covered):
    """Deterministic byte mutants of instructions the cases execute: flipped conditions, changed immediates and constants, two opcodes."""
    mutants = []

    def current(at):
        return image.blob[image.offset(at)]

    for name, lo, hi in FUNCTIONS:
        rows = [row for row in decode_range(image, lo, hi) if row.va in covered]
        flips = [row for row in rows if row.op == "jcc" and row.size in (2, 6)]
        for row in flips[::max(1, len(flips) // 9)][:9]:
            at = row.va + (0 if row.size == 2 else 1)
            mutants.append(("jcc-flip", "%s@%#x" % (name, row.va), at, "condition byte %#x -> %#x" % (current(at), current(at) ^ 1), current(at) ^ 1))
        imms = [row for row in rows if row.imm_at is not None and row.imm_size == 1 and row.op in ("rol", "shr", "shl", "and", "cmp", "add", "sub", "mov", "or", "xor")]
        for row in imms[::max(1, len(imms) // 3)][:3]:
            at = row.va + row.imm_at
            mutants.append(("imm-flip", "%s@%#x" % (name, row.va), at, "%s immediate byte %#x -> %#x" % (row.op, current(at), current(at) ^ 1),
                            current(at) ^ 1))
        for row in [row for row in rows if row.imm_at is not None and row.op == "mov" and row.imm_size == 8 and name != "reserve_rehash"][:2]:
            at = row.va + row.imm_at
            mutants.append(("const-flip", "%s@%#x" % (name, row.va), at, "64-bit constant low byte %#x -> %#x" % (current(at), current(at) ^ 1),
                            current(at) ^ 1))
    for name, va, text, old, new in (("record", 0x4772066, "addsd -> subsd", 0x58, 0x5C), ("record", 0x477213D, "maxsd -> minsd", 0x5F, 0x5D)):
        if current(va + 2) == old and va in covered:
            mutants.append(("opcode", "%s@%#x" % (name, va), va + 2, text, new))
    return mutants


def model_mutants():
    """(name, description, apply) where apply() installs the wrong model and returns a function that restores the right one."""
    def swap_global(name, value):
        def apply():
            old = globals()[name]
            globals()[name] = value
            return lambda: globals().__setitem__(name, old)
        return apply

    def swap_method(cls, name, function):
        def apply():
            old = getattr(cls, name)
            setattr(cls, name, function)
            return lambda: setattr(cls, name, old)
        return apply

    def keys_equal_wide(bucket_key, probe_key, strings):
        if (bucket_key[0] == 0) != (probe_key[0] == 0):
            return False
        return key_bytes(bucket_key, strings) == key_bytes(probe_key, strings) and bucket_key[2] == probe_key[2]

    def sum_without_clamp(total_bits, plus_inf_bits):
        return total_bits

    def record_without_saturation(slot, value_bits, plus_inf_bits):
        total = saturate_sum(to_bits(f64(slot[4]) + f64(value_bits)), plus_inf_bits)
        left, right = f64(slot[5]), f64(value_bits)
        return slot[:3] + (slot[3] + 1, total, slot[5] if left > right else value_bits)

    def record_min(slot, value_bits, plus_inf_bits):
        total = saturate_sum(to_bits(f64(slot[4]) + f64(value_bits)), plus_inf_bits)
        left, right = f64(slot[5]), f64(value_bits)
        return slot[:3] + (min(slot[3] + 1, M64), total, slot[5] if left < right else value_bits)

    def capacity_small(cap):
        if cap < 8:
            return 4 if cap < 5 else 8
        return capacity_to_buckets_real(cap)

    capacity_to_buckets_real = capacity_to_buckets

    def find_without_fixup(self, hashed):
        pos, stride = hashed & self.mask, 0
        while True:
            group = self.ctrl[pos:pos + 16]
            hits = [bit for bit in range(16) if group[bit] & 0x80]
            if hits:
                return (pos + hits[0]) & self.mask
            stride += 16
            pos = (pos + stride) & self.mask

    def rol19(value, count):
        return ((value << 19) | (value >> 45)) & M64

    def insert_ignoring_growth(self, hashed, key):
        index = self.find_insert_slot(hashed)
        self.set_ctrl(index, hashed >> H2_SHIFT)
        self.growth -= 1
        self.slots[index] = tuple(key) + (0, 0, 0)
        self.items += 1
        return index

    return [
        ("model", "hash multiplier K1 low bit flipped", swap_global("HASH_K1", HASH_K1 ^ 1)),
        ("model", "hash tail constant K4 low bit flipped", swap_global("HASH_K4", HASH_K4 ^ 1)),
        ("model", "long-input lane constant C3 low bit flipped", swap_global("HASH_C3", HASH_C3 ^ 1)),
        ("model", "final rotate 19 instead of 20", swap_global("rol64", rol19)),
        ("model", "control byte taken from hash >> 56", swap_global("H2_SHIFT", 56)),
        ("model", "tag compared as 64 bits instead of 32", swap_global("keys_equal", keys_equal_wide)),
        ("model", "sum is not clamped", swap_global("saturate_sum", sum_without_clamp)),
        ("model", "count is not saturating", swap_global("record_update", record_without_saturation)),
        ("model", "maximum keeps the smaller value", swap_global("record_update", record_min)),
        ("model", "small capacity rounds 4 up to 8", swap_global("capacity_to_buckets", capacity_small)),
        ("model", "insert slot without the group-0 fixup", swap_method(Model, "find_insert_slot", find_without_fixup)),
        ("model", "insert always consumes growth", swap_method(Model, "insert_vacant", insert_ignoring_growth)),
        ("model", "capacity of a large table one too small", swap_global("mask_to_capacity", lambda mask: mask if mask < 8 else (mask + 1) // 8 * 7 - 1)),
    ]


def model_mutant_divergence(apply):
    restore = apply()
    try:
        image_rig = Rig(IMAGE_FOR_CONTROLS)
        image_rig.machine.step_limit = MUTANT_STEP_LIMIT
        for number, (name, check, count) in enumerate(MUTANT_SUITES):
            rng = Rng(SEED + number)
            for index in range(count):
                strings = make_strings(rng, 24)
                try:
                    ok, label = check(image_rig, rng, index, strings)
                except (Halt, EvidenceError, KeyError, ValueError, IndexError):
                    return "%s#%d halt" % (name, index)
                if not ok:
                    return "%s#%d %s" % (name, index, label)
        return None
    finally:
        restore()


IMAGE_FOR_CONTROLS = None


def state_controls(image):
    """Corrupt the expectation instead of the code: the comparison itself must reject each corrupted expectation."""
    rig = Rig(image)
    rng = Rng(SEED + 99)
    strings = make_strings(rng, 24)
    model = build_table(rng, strings, 16, 9, 0)
    expected = model.copy()
    expected.reserve(5, False)
    _, _, actual = rig.call_reserve(model, 5, False)
    assert tables_match(actual, expected)
    results = []
    bent = expected.copy()
    bent.ctrl[3] ^= 0x01
    results.append(("state", "one control byte flipped in the expected table", not tables_match(actual, bent)))
    bent = expected.copy()
    index = sorted(bent.slots)[0]
    words = list(bent.slots[index])
    words[5] ^= 1
    bent.slots[index] = tuple(words)
    results.append(("state", "one bucket word flipped in the expected table", not tables_match(actual, bent)))
    bent = expected.copy()
    bent.growth += 1
    results.append(("state", "expected growth_left off by one", not tables_match(actual, bent)))
    bent = expected.copy()
    bent.ctrl_at += 16
    results.append(("state", "expected allocation moved by 16 bytes", not tables_match(actual, bent)))
    return results


def input_controls(image):
    results = []
    try:
        load_image(expected=SHA256[:-1] + ("0" if SHA256[-1] != "0" else "1"))
        results.append(("input", "binary digest differing in the last hex digit", False))
    except EvidenceError:
        results.append(("input", "binary digest differing in the last hex digit", True))
    try:
        decode_range(image, HASHER, HASHER_END - 1)
        results.append(("input", "function range ending one byte early", False))
    except EvidenceError:
        results.append(("input", "function range ending one byte early", True))
    try:
        image.exact_fde(HASHER + 1)
        results.append(("input", "address inside a function is not a function start", False))
    except EvidenceError:
        results.append(("input", "address inside a function is not a function start", True))
    try:
        Machine(image).memory.bytes_at(0x10, 8)
        results.append(("input", "read below every mapping", False))
    except Halt:
        results.append(("input", "read below every mapping", True))
    rig = Rig(image)
    try:
        rig.call_hash((0xDEAD0000000, 24, 1), {})
        results.append(("input", "key pointing outside every mapping", False))
    except Halt:
        results.append(("input", "key pointing outside every mapping", True))
    return results


def write_lines(handle, lines):
    for line in lines:
        handle.write(line + "\n")


def generate(out):
    global IMAGE_FOR_CONTROLS
    image = load_image()
    IMAGE_FOR_CONTROLS = image
    out = pathlib.Path(out)
    out.mkdir(parents=True, exist_ok=True)
    rig = Rig(image)
    totals, classes = {}, {}
    with open(out / "cases.tsv", "w", newline="\n") as handle:
        handle.write("suite\tcase\tclass\tinput_sha256_12\tsteps\n")
        for number, (name, check, count, stride) in enumerate(SUITES):
            for index, ok, label, digest, steps in suite_cases(rig, check, count, SEED + number):
                if not ok:
                    raise EvidenceError("case %s#%d diverges from the model (%s)" % (name, index, label))
                totals[name] = totals.get(name, 0) + 1
                classes[(name, label)] = classes.get((name, label), 0) + 1
                if index % stride == 0:
                    handle.write("%s\t%d\t%s\t%s\t%d\n" % (name, index, label, digest, steps))
    covered = rig.covered | rig.machine.seen
    with open(out / "classes.tsv", "w", newline="\n") as handle:
        handle.write("suite\tclass\tcases\n")
        write_lines(handle, ["%s\t%s\t%d" % (name, label, count) for (name, label), count in sorted(classes.items())])
    with open(out / "coverage.tsv", "w", newline="\n") as handle, open(out / "functions.tsv", "w", newline="\n") as functions:
        handle.write("function\taddress\tsize\top\texecuted\n")
        functions.write("function\tstart\tend\tfde_start\tfde_end\tinstructions\texecuted\n")
        for name, lo, hi in FUNCTIONS:
            rows = [row for row in decode_range(image, lo, hi) if row.op != "int3"]
            hit = sum(1 for row in rows if row.va in covered)
            fde = image.exact_fde(lo)
            functions.write("%s\t%#x\t%#x\t%#x\t%#x\t%d\t%d\n" % (name, lo, hi, fde[0], fde[1], len(rows), hit))
            write_lines(handle, ["%s\t%#x\t%d\t%s\t%d" % (name, row.va, row.size, row.op, 1 if row.va in covered else 0) for row in rows])
    controls = []
    for kind, site, at, detail, new_byte in byte_mutants(image, covered):
        controls.append((kind, site, detail, first_divergence(image, {at: new_byte})))
    for kind, detail, apply in model_mutants():
        controls.append((kind, "model", detail, model_mutant_divergence(apply)))
    for kind, detail, caught in state_controls(image) + input_controls(image):
        controls.append((kind, "comparison", detail, "rejected" if caught else None))
    equivalent = [(number, entry) for number, entry in enumerate(controls) if entry[3] is None and (entry[0], entry[1], entry[2]) in EQUIVALENT]
    with open(out / "controls.tsv", "w", newline="\n") as handle:
        handle.write("control\tkind\ttarget\tchange\tresult\n")
        for number, (kind, site, detail, found) in enumerate(controls):
            if found is None:
                verdict = "equivalent" if (kind, site, detail) in EQUIVALENT else "UNDETECTED"
            else:
                verdict = "detected " + found
            handle.write("c%03d\t%s\t%s\t%s\t%s\n" % (number, kind, site, detail, verdict))
    if equivalent:
        with open(out / "equivalent-mutants.tsv", "w", newline="\n") as handle:
            handle.write("mutant\taddress\treason\n")
            write_lines(handle, ["%s\t%s\t%s" % (entry[2], entry[1], EQUIVALENT[(entry[0], entry[1], entry[2])]) for _, entry in equivalent])
    detected = sum(1 for entry in controls if entry[3] is not None)
    undetected = [entry for entry in controls if entry[3] is None and (entry[0], entry[1], entry[2]) not in EQUIVALENT]
    summary = {"cases": sum(totals.values()), "negative_controls": len(controls), "negative_detected": detected, "equivalent": len(equivalent),
               "undetected_unexplained": len(undetected), "cases_hash": totals["hash"], "cases_entry": totals["entry"],
               "cases_reserve": totals["reserve"], "cases_record": totals["record"]}
    with open(out / "measure.json", "w", newline="\n") as handle:
        handle.write(json.dumps(summary, indent=1, sort_keys=True) + "\n")
    return summary


EQUIVALENT = {
    ("jcc-flip", "reserve_rehash@0x4764652", "condition byte 0x74 -> 0x75"):
        "the odd-group test only matters for an odd group count; table sizes are powers of two, so the flipped branch runs one extra group "
        "that lies in the mirror bytes the next 16-byte copy overwrites",
    ("imm-flip", "reserve_rehash@0x4764447", "cmp immediate byte 0x9 -> 0x8"):
        "the 8-bucket table has capacity 7 by the general formula (8 - 1) and by the small-table rule (mask 7)",
    ("jcc-flip", "record@0x47720a0", "condition byte 0x73 -> 0x72"):
        "both targets leave xmm1 = 0 for a negative sum (xmm1 is already zero) and reach the same compare that sends it on",
    ("jcc-flip", "record@0x47720b8", "condition byte 0x75 -> 0x74"):
        "the branch is reached only for positive subnormals where xmm2 already equals xmm0, so the skipped move changes nothing",
    ("jcc-flip", "record@0x47720c1", "condition byte 0x79 -> 0x78"):
        "xmm1 only reaches memory when the sum is infinite, and this path is entered only for a zero sum",
}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--out", required=True)
    args = parser.parse_args(argv)
    summary = generate(args.out)
    print(json.dumps(summary, sort_keys=True))
    return 0 if summary["undetected_unexplained"] == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
