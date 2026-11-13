#!/usr/bin/env python3
"""Reconstruct the node 115 timed action router at 0x55f99b0 and check it against its own bytes.

The router takes a variant tag word through a 93-entry jump table, optionally consults a feature-flag slot and
arms a latency timer, calls one of 93 arms (19 argument shapes), folds the arm's result into a 128-byte slot, records
the timer pair and copies the slot to the caller. The tool carries (1) an executable pure-Python model of all of that
and (2) an x86-64 interpreter (Image, decode, Memory, Machine) that runs the real bytes with every external callee
replaced by a recording stub. Each case compares the recorded call trace, the argument registers, the stack
snapshots the callees would see and the 128-byte result. Nothing from the binary is executed natively and no other
program is invoked.

    python3 tools/action_timed_router_115.py --out research/work-items/action-dispatch-timed-router-115
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


# ---------------------------------------------------------------------------------------------------------------------
# Packet code: the node #115 timed action router at 0x55f99b0 (93 arms), modelled and compared with its own bytes.
# ---------------------------------------------------------------------------------------------------------------------

ROUTER = 0x55F99B0
TABLE = 0x927B08
COUNT = 92
NOW_FN = 0x5C842E0
RECORD_FN = 0x5C84210
FLAG_SLOT = 0x64E1028
GOT_BASE = 0x7700000000
OUT = HEAP_BASE + 0x1000
TAG = HEAP_BASE + 0x2000
NTAG = HEAP_BASE + 0x2800
DESC = HEAP_BASE + 0x3000
CTX = HEAP_BASE + 0x10000
HEAP_USED = 0x20000
F0 = STACK_TOP - 0x250
FRAME = 0x118
SENTINEL = 0x3B9ACA00
NOT_FOUND = 0x924F14

REAL = dict(base=0x86, default=20, mask=0x501D, maxbit=14, flag_arg=0x32, flag_polarity=True, sentinel=SENTINEL,
            join_word=0x1A2, ok_tag=0xE, err_tag=0xF, nest_add=0x7A, nest_off=0x20, desc_len=20, b9a=0xB9A, w42ad=0x42AD,
            limit=0xCCCCCCCCCCCCCCC, w154=0x154, w91=0x91, w92=0x92, guard_value=3, tail_off=0x28, head_off=8,
            timed_never=False, skip_end=False, swap_record=False, step=8, ctx_a=0x3F08, ctx_b=0xBA0, ctx_c=0xD88,
            tag43_off=0x16, copy43=8, slot_off=0x70, handler_swap=None, nows_one=1, arg_shift=None)

# One skeleton (operation, operands) per arm shape, named after the first arm that carries it.
SHAPE_FIRST = {0: "const_ok", 1: "copy_desc", 5: "noargs_rsp", 9: "plain", 16: "slot_a", 17: "rsp_first", 20: "copy_desc_noadd",
               41: "slot_b", 43: "tag_copy", 47: "desc_f0", 52: "nested", 61: "checked", 62: "rcx_tail", 63: "guard63",
               64: "guard64", 74: "desc_f0", 75: "guard75", 91: "rcx_head"}


def le(value, size):
    return (value & ((1 << (8 * size)) - 1)).to_bytes(size, "little")


class Lcg:
    def __init__(self, seed):
        self.state = seed & 0xFFFFFFFFFFFFFFFF

    def next(self, bound):
        self.state = (self.state * 6364136223846793005 + 1442695040888963407) & 0xFFFFFFFFFFFFFFFF
        return (self.state >> 33) % bound

    def word(self):
        return self.next(1 << 31) << 33 | self.next(1 << 31) << 2 | self.next(4)


def read_code_bytes(image):
    return lambda va, count: image.blob[image.offset(va):image.offset(va) + count]


def arm_table(image):
    """Decode every jump-table target and group the arms by the skeleton of their first basic block."""
    rd = read_code_bytes(image)
    targets = [TABLE + struct.unpack_from("<i", image.blob, image.offset(TABLE) + 4 * i)[0] for i in range(COUNT)]
    skeleton = {}
    arms = []
    for index, start in enumerate(targets):
        rows, pc = [], start
        while True:
            row = decode(rd, pc)
            rows.append(row)
            pc = row.next
            if row.op in ("jmp", "ret") or len(rows) > 16:
                break
        key = tuple((r.op, str(r.a) if r.op not in ("call",) else "", str(r.b) if r.op not in ("call",) else "") for r in rows)
        handler = None
        for r in rows:
            if r.op == "call":
                handler = r.target
                break
            if r.op == "calli":
                handler = r.a[4]
                break
        arms.append(dict(index=index, start=start, key=key, handler=handler, rows=rows))
        skeleton.setdefault(key, []).append(index)
    names = {}
    for key, members in skeleton.items():
        firsts = [i for i in members if i in SHAPE_FIRST]
        if len(firsts) != 1:
            raise EvidenceError("skeleton without exactly one named arm: %r" % (members,))
        names[key] = SHAPE_FIRST[firsts[0]]
    shared = decode(rd, 0x55FA35C)
    if shared.op != "call":
        raise EvidenceError("expected the shared call at 0x55fa35c")
    for arm in arms:
        arm["shape"] = names[arm["key"]]
        if arm["shape"] == "rcx_head":
            arm["handler"] = shared.target
    return arms


def tail_slot_c(image):
    row = decode(read_code_bytes(image), 0x55FAA35)
    if row.op != "calli":
        raise EvidenceError("expected the indirect call of the guarded arm at 0x55faa35")
    return row.a[4]


# ---------------------------------------------------------------------------------------------------------------------
# The model: pure Python, no interpreter. It reads the case heap and produces the call trace and the 128-byte result.
# ---------------------------------------------------------------------------------------------------------------------

class Case:
    """One router input. The 128 KiB heap image is rebuilt from the case number on demand, so cases stay small."""

    def __init__(self, cid, tag, cl, dl, flag, nows, ok_bits, seed, arm, nested=0x10, b9a=0, w42ad=0, tail=0, fixed=None):
        self.cid, self.tag, self.cl, self.dl, self.flag, self.nows = cid, tag, cl, dl, flag, nows
        self.ok_bits, self.seed, self.arm, self.nested = ok_bits, seed, arm, nested
        self.b9a, self.w42ad, self.tail, self.fixed = b9a, w42ad, tail, fixed

    @property
    def heap(self):
        if self.fixed is not None:
            return self.fixed
        heap = bytearray(b"\xa5" * HEAP_USED)

        def put(addr, data):
            at = addr - HEAP_BASE
            heap[at:at + len(data)] = data

        block = hashlib.shake_128(b"router-case-%d" % self.cid).digest(0x4400 + 0x90)
        put(CTX, block[:0x4400])
        put(CTX + 0xB9A, bytes([self.b9a]))
        put(CTX + 0x42AD, bytes([self.w42ad]))
        put(TAG, le(self.tag, 8))
        put(TAG + 8, block[0x4400:0x4440])
        put(TAG + 0x20, le(NTAG, 8))
        put(TAG + 0x28, le(self.tail, 8))
        put(NTAG, le(self.nested, 8))
        put(NTAG + 8, block[0x4440:0x4470])
        put(DESC, block[0x4470:0x4484])
        return bytes(heap)



def fill_bytes(target, seed, callno, count, one_a2):
    data = bytearray((target * 7 + seed * 13 + callno * 29 + i * 31) & 0xFF for i in range(count))
    if one_a2:
        data[0], data[1] = 0xA2, 0x01
    elif data[0] == 0xA2 and data[1] == 0x01:
        data[1] = 0x02
    return data


def norm(value, frame):
    if frame <= value < frame + FRAME:
        return "F+%x" % (value - frame)
    if HEAP_BASE <= value < HEAP_BASE + HEAP_SIZE:
        return "H+%x" % (value - HEAP_BASE)
    return "%x" % value


class Model:
    def __init__(self, params, arms, slot_c, case):
        self.p = params
        self.arms = arms
        self.slot_c = slot_c
        self.case = case
        self.heap = bytearray(case.heap)
        self.trace = []
        self.calls = 0
        self.nows = 0

    def ld(self, addr, size):
        at = addr - HEAP_BASE
        return int.from_bytes(self.heap[at:at + size], "little")

    def bytes_at(self, addr, size):
        at = addr - HEAP_BASE
        return bytes(self.heap[at:at + size])

    def record(self, name, frame, regs, snap_from):
        view = {}
        snaps = {}
        for reg, value in regs.items():
            view[reg] = norm(value, frame["f"])
            if frame["f"] <= value < frame["f"] + FRAME:
                at = value - frame["f"]
                snaps[reg] = bytes(frame["b"][at:at + 0x20]).hex()
        self.trace.append((name, view, snaps))

    def handler_call(self, fr, target, regs, mode):
        if self.p["handler_swap"] and self.p["handler_swap"][0] == target:
            target = self.p["handler_swap"][1]
        self.record(target, fr, regs, None)
        callno = self.calls
        self.calls += 1
        one_a2 = (self.case.ok_bits >> callno) & 1 == 1
        if mode == "buf":
            fr["b"][0:0x70] = fill_bytes(target, self.case.seed, callno, 0x70, one_a2)
        elif mode == "slot":
            fr["b"][0x70:0xF0] = fill_bytes(target, self.case.seed, callno, 0x80, one_a2)

    def join(self, fr):
        p = self.p
        word = int.from_bytes(fr["b"][0:2], "little")
        if word == p["join_word"]:
            fr["b"][0x70] = p["ok_tag"]
        else:
            fr["b"][0x80:0xF0] = fr["b"][0:0x70]
            fr["b"][0x70] = p["err_tag"]

    def run(self, f, cl, dl, tag_ptr, desc, ctx, out_slot):
        """Model one router activation; returns its 128-byte result."""
        p = self.p
        fr = {"f": f, "b": bytearray(b"\xa5" * FRAME)}
        consult = (dl & 0xFF) != 0 or ((cl & 0xFF) <= p["maxbit"] and (p["mask"] >> (cl & 0xFF)) & 1 == 1)
        timed = True
        if consult:
            self.trace.append(("flag", {0: "%x" % p["flag_arg"]}, {}))
            flag = self.case.flag
            timed = (flag != 0) == p["flag_polarity"]
        if p["timed_never"]:
            timed = False
        start = None
        if timed:
            start = self.now()
        tag = self.ld(tag_ptr, 8)
        index = tag - p["base"] if tag >= p["base"] else p["default"]
        arm = self.arms[index % COUNT] if index < COUNT else self.arms[p["default"]]
        self.shape(fr, arm, tag_ptr, desc, ctx, cl)
        if start is not None and start[1] != p["sentinel"] and not p["skip_end"]:
            end = self.now()
            fr["b"][0x108:0x110] = le(end[0], 8)
            fr["b"][0x110:0x114] = le(end[1], 4)
            fr["b"][0xF0:0xF8] = le(start[0], 8)
            fr["b"][0xF8:0xFC] = le(start[1], 4)
            order = (f + 0xF0, f + 0x108) if p["swap_record"] else (f + 0x108, f + 0xF0)
            self.record(RECORD_FN, fr, {0: f, 1: order[0], 2: order[1]}, None)
        return bytes(fr["b"][0x70:0xF0])

    def now(self):
        pair = self.case.nows[min(self.nows, 1)]
        self.nows += 1
        self.trace.append(("now", {0: "%x" % self.p["nows_one"]}, {}))
        return pair

    def shape(self, fr, arm, tag_ptr, desc, ctx, cl):
        p = self.p
        f = fr["f"]
        b = fr["b"]
        h = arm["handler"]
        t = tag_ptr
        name = arm["shape"]
        step = p["step"]
        desc20 = self.bytes_at(desc, p["desc_len"])
        slot = f + p["slot_off"]
        if name == "const_ok":
            b[0x70] = p["ok_tag"]
        elif name == "copy_desc":
            t += step
            b[0:len(desc20)] = desc20
            self.handler_call(fr, h, {0: slot, 1: t, 2: f, 3: ctx}, "slot")
        elif name == "plain":
            t += step
            self.handler_call(fr, h, {0: slot, 1: t, 2: desc, 3: ctx}, "slot")
        elif name == "rsp_first":
            t += step
            self.handler_call(fr, h, {0: f, 1: ctx, 2: desc, 3: t}, "buf")
            self.join(fr)
        elif name == "copy_desc_noadd":
            b[0:len(desc20)] = desc20
            self.handler_call(fr, h, {0: slot, 1: t, 2: f, 3: ctx}, "slot")
        elif name == "noargs_rsp":
            self.handler_call(fr, h, {0: f, 1: ctx, 2: desc}, "buf")
            self.join(fr)
        elif name == "slot_a":
            t += step
            self.handler_call(fr, h, {0: f, 1: ctx + p["ctx_a"], 2: desc, 3: t, 4: self.ld(ctx + p["b9a"], 1)}, "buf")
            self.join(fr)
        elif name == "slot_b":
            t += step
            b[0xF0:0xF0 + len(desc20)] = desc20
            self.handler_call(fr, h, {0: f, 1: ctx + p["ctx_b"], 2: self.ld(ctx + p["b9a"], 1), 3: f + 0xF0, 4: t, 5: ctx + p["ctx_a"]}, "buf")
            self.join(fr)
        elif name == "tag_copy":
            b[0x7E:0x86] = le(self.ld(tag_ptr + p["tag43_off"], 8), 8)
            b[0x70:0x70 + p["copy43"] * 2] = self.bytes_at(tag_ptr + 8, p["copy43"] * 2)
            self.handler_call(fr, h, {0: f, 1: ctx, 2: desc, 3: f + 0x70}, "buf")
            self.join(fr)
        elif name == "desc_f0":
            t += step
            b[0xF0:0xF0 + len(desc20)] = desc20
            self.handler_call(fr, h, {0: f, 1: ctx, 2: f + 0xF0, 3: t}, "buf")
            self.join(fr)
        elif name == "nested":
            inner = self.ld(tag_ptr + p["nest_off"], 8)
            word = self.ld(inner, 8)
            index = (word + p["nest_add"]) & 0xFF if word >= p["base"] else p["default"]
            b[0x70:0xF0] = self.run(f - 0x150, index, 0, inner, desc, ctx, slot)
        elif name in ("checked", "rcx_tail", "rcx_head"):
            off = p["head_off"] if name == "rcx_head" else p["tail_off"]
            value = self.ld(tag_ptr + off, 8)
            if name == "checked" and value >= p["limit"]:
                b[0x80:0x82] = le(p["w154"], 2)
                b[0x88:0x90] = le(value, 8)
                b[0x70] = p["err_tag"]
            else:
                self.handler_call(fr, h, {0: f, 1: ctx, 2: desc, 3: value}, "buf")
                self.join(fr)
        elif name in ("guard63", "guard64"):
            guard = self.ld(ctx + p["b9a"], 1)
            if name == "guard63":
                b[0:len(desc20)] = desc20
            if guard == p["guard_value"]:
                b[0x80:0x82] = le(p["w91"], 2)
                b[0x70] = p["err_tag"]
            elif name == "guard63":
                t += step
                b[0x78:0x7C] = le(self.ld(ctx + 0x68, 4), 4)
                b[0x70:0x78] = le(self.ld(ctx + 0x60, 8), 8)
                self.handler_call(fr, self.slot_c, {0: ctx + p["ctx_c"], 1: slot, 2: guard, 3: f, 4: t}, "none")
                b[0x70] = p["ok_tag"]
            else:
                self.handler_call(fr, h, {0: ctx, 1: NOT_FOUND}, "none")
                b[0x70] = p["ok_tag"]
        elif name == "guard75":
            if self.ld(ctx + p["w42ad"], 1) == 0:
                b[0x80:0x82] = le(p["w92"], 2)
                b[0x70] = p["err_tag"]
            else:
                t += step
                self.handler_call(fr, h, {0: f, 1: ctx, 2: desc, 3: t}, "buf")
                self.join(fr)
        else:
            raise EvidenceError("unknown shape " + name)


# ---------------------------------------------------------------------------------------------------------------------
# The real side: the router's bytes in the interpreter, every external callee served by a recording stub.
# ---------------------------------------------------------------------------------------------------------------------

class Rig:
    def __init__(self, image, arms, slot_c, patches=None):
        self.image = image
        self.arms = arms
        self.machine = Machine(image, patches)
        self.machine.real = frozenset((ROUTER,))
        self.state = {}
        m = self.machine
        slots = set([FLAG_SLOT, slot_c])
        for arm in arms:
            if arm["rows"] and any(r.op == "calli" for r in arm["rows"]):
                slots.add(arm["handler"])
            elif arm["handler"] is not None and arm["handler"] != ROUTER:
                m.calls[arm["handler"]] = self.hook(arm["handler"], True)
        m.calls[NOW_FN] = self.now_hook()
        m.calls[RECORD_FN] = self.hook(RECORD_FN, True, "record")
        for slot in sorted(slots):
            magic = GOT_BASE + slot
            m.memory.statics[slot] = magic
            m.slots[magic] = self.flag_hook() if slot == FLAG_SLOT else self.hook(slot, False)
        self.slot_names = {GOT_BASE + s: s for s in slots}

    def frame_of(self, pushed):
        rsp = self.machine.regs[RSP]
        return rsp + 8 if pushed else rsp

    def snapshot(self, name, pushed):
        m = self.machine
        frame = self.frame_of(pushed)
        view, snaps = {}, {}
        for pos, reg in enumerate((RDI, RSI, RDX, RCX, R8, R9)):
            value = m.regs[reg]
            view[pos] = norm(value, frame)
            if frame <= value < frame + FRAME:
                snaps[pos] = m.memory.bytes_at(value, min(0x20, frame + FRAME - value)).hex()
        self.state["trace"].append((name, view, snaps))
        return frame

    def hook(self, target, pushed, kind="handler"):
        def run(m):
            frame = self.snapshot(target, pushed)
            if kind == "record":
                return
            callno = self.state["calls"]
            self.state["calls"] += 1
            one_a2 = (self.state["case"].ok_bits >> callno) & 1 == 1
            rdi = m.regs[RDI]
            if rdi == frame:
                m.memory.put_bytes(rdi, bytes(fill_bytes(target, self.state["case"].seed, callno, 0x70, one_a2)))
            elif rdi == frame + 0x70:
                m.memory.put_bytes(rdi, bytes(fill_bytes(target, self.state["case"].seed, callno, 0x80, one_a2)))
            m.regs[RAX] = 0
        return run

    def flag_hook(self):
        def run(m):
            self.state["trace"].append(("flag", {0: "%x" % m.regs[RDI]}, {}))
            m.regs[RAX] = self.state["case"].flag
        return run

    def now_hook(self):
        def run(m):
            self.state["trace"].append(("now", {0: "%x" % m.regs[RDI]}, {}))
            pair = self.state["case"].nows[min(self.state["nows"], 1)]
            self.state["nows"] += 1
            m.regs[RAX], m.regs[RDX] = pair
            m.keep_rdx = True
        return run

    def run(self, case):
        m = self.machine
        m.memory.reset(HEAP_USED)
        m.memory.heap[:HEAP_USED] = case.heap
        self.state = {"trace": [], "calls": 0, "nows": 0, "case": case}
        m.seen = set()
        m.run(ROUTER, {RDI: OUT, RSI: CTX, RDX: 0xABCDEF00 | case.dl, RCX: 0x5A5A5A00 | case.cl, R8: TAG, R9: DESC})
        if m.regs[RAX] != OUT:
            raise EvidenceError("router did not return its out pointer")
        return self.state["trace"], bytes(m.memory.bytes_at(OUT, 0x80))


def recursion_names(trace):
    # the real run records the nested activation's own calls inline; the router address itself is a recorded call too
    return trace


def make_cases(per_arm=110, extra=140):
    """Yield the deterministic case list: per_arm cases for every arm, then `extra` for tags below the base."""
    plain_tags = [0x86 + i for i in range(COUNT) if i != 52]
    pointer_edges = [0, 1, 0xCCCCCCCCCCCCCCB, 0xCCCCCCCCCCCCCCC, 0xCCCCCCCCCCCCCCD, 0xFFFFFFFFFFFFFFFF]
    for n in range(COUNT * per_arm + extra):
        rng = Lcg(0x115A55F99B0 + n * 0x9E3779B97F4A7C15)
        if n < COUNT * per_arm:
            arm = n % COUNT
            tag = 0x86 + arm
        else:
            arm = 20
            tag = (0, 1, 0x85, 0x20, 0x7F, 0x84)[rng.next(6)]
        nested = plain_tags[rng.next(len(plain_tags))] if rng.next(5) else (0x10, 0x85)[rng.next(2)]
        index = (tag + 0x7A) & 0xFF if tag >= 0x86 else 20
        cl = index if rng.next(3) else rng.next(256)
        dl = (0, 0, 0, 1, 0x80, 0xFF)[rng.next(6)]
        tail = pointer_edges[rng.next(6)] if rng.next(2) else rng.word()
        guard = (0, 1, 2, 3, 3, 4, 255)[rng.next(7)]
        gate = (0, 1, 0x55)[rng.next(3)]
        nows = ((rng.word() >> 8, rng.next(10 ** 9) if rng.next(9) else SENTINEL), (rng.word() >> 8, rng.next(10 ** 9)))
        yield Case(n, tag, cl, dl, rng.next(2), nows, rng.next(16), rng.next(256), arm, nested, guard, gate, tail)


def compare(trace_real, out_real, model):
    """Return None when the real run agrees with the model, otherwise a short reason."""
    mt = model.trace
    if len(trace_real) != len(mt):
        return "call count %d != %d" % (len(trace_real), len(mt))
    for k, ((name, view, snaps), (mname, mview, msnaps)) in enumerate(zip(trace_real, mt)):
        if name != mname:
            return "call %d target %s != %s" % (k, name, mname)
        for pos, value in mview.items():
            if view.get(pos) != value:
                return "call %d arg %d %s != %s" % (k, pos, view.get(pos), value)
        for pos, value in msnaps.items():
            if snaps.get(pos) != value:
                return "call %d snapshot %d differs" % (k, pos)
    return None


def run_model(params, arms, slot_c, case):
    model = Model(params, arms, slot_c, case)
    out = model.run(F0, case.cl, case.dl, TAG, DESC, CTX, OUT)
    return model, out


def check_case(rig, params, arms, slot_c, case):
    trace, out = rig.run(case)
    model, expect = run_model(params, arms, slot_c, case)
    why = compare(trace, out, model)
    if why is None and out != expect:
        why = "result bytes differ"
    return why, trace, out


# ---------------------------------------------------------------------------------------------------------------------
# Negative controls.
# ---------------------------------------------------------------------------------------------------------------------

MODEL_MUTANTS = [
    ("base 0x86 -> 0x87", dict(base=0x87), None),
    ("default arm 20 -> 21", dict(default=21), None),
    ("gate mask 0x501d -> 0x501c", dict(mask=0x501C), None),
    ("gate mask 0x501d -> 0x5015", dict(mask=0x5015), None),
    ("gate index limit 14 -> 13", dict(maxbit=13), None),
    ("gate index limit 14 -> 15", dict(maxbit=15), "mask bit 15 is clear, so index 15 never consults the flag"),
    ("flag argument 0x32 -> 0x33", dict(flag_arg=0x33), None),
    ("flag polarity inverted", dict(flag_polarity=False), None),
    ("sentinel 1e9 -> 1e9+1", dict(sentinel=SENTINEL + 1), None),
    ("timer never armed", dict(timed_never=True), None),
    ("end record skipped", dict(skip_end=True), None),
    ("record arguments swapped", dict(swap_record=True), None),
    ("join word 0x1a2 -> 0x1a3", dict(join_word=0x1A3), None),
    ("ok tag 0xe -> 0xf", dict(ok_tag=0xF), None),
    ("err tag 0xf -> 0xe", dict(err_tag=0xE), None),
    ("nested index add 0x7a -> 0x7b", dict(nest_add=0x7B), None),
    ("nested tag pointer offset 0x20 -> 0x18", dict(nest_off=0x18), None),
    ("descriptor copy 20 -> 16 bytes", dict(desc_len=16), None),
    ("ctx byte 0xb9a -> 0xb99", dict(b9a=0xB99), None),
    ("ctx byte 0x42ad -> 0x42ac", dict(w42ad=0x42AC), None),
    ("overflow limit 0xccc..c -> 0xccc..d", dict(limit=0xCCCCCCCCCCCCCCD), None),
    ("error word 0x154 -> 0x155", dict(w154=0x155), None),
    ("error word 0x91 -> 0x92", dict(w91=0x92), None),
    ("error word 0x92 -> 0x91", dict(w92=0x91), None),
    ("guard value 3 -> 4", dict(guard_value=4), None),
    ("tail offset 0x28 -> 0x20", dict(tail_off=0x20), None),
    ("head offset 8 -> 0x10", dict(head_off=0x10), None),
    ("payload step 8 -> 16", dict(step=16), None),
    ("ctx offset 0x3f08 -> 0x3f00", dict(ctx_a=0x3F00), None),
    ("ctx offset 0xba0 -> 0xb98", dict(ctx_b=0xB98), None),
    ("ctx offset 0xd88 -> 0xd80", dict(ctx_c=0xD80), None),
    ("tag-copy source offset 0x16 -> 0x14", dict(tag43_off=0x14), None),
    ("tag-copy length 16 -> 8", dict(copy43=4), None),
    ("result slot offset 0x70 -> 0x78", dict(slot_off=0x78), None),
    ("timer clock argument 1 -> 2", dict(nows_one=2), None),
    ("handler of arm 3 swapped for arm 4's", dict(handler_swap="arm3"), None),
]

# (label, byte pattern, occurrence, offset inside the pattern, new byte, equivalence reason or None)
BYTE_MUTANTS = [
    ("sentinel load imm 0x3b9aca00", b"\xbd\x00\xca\x9a\x3b", 0, 3, 0x9B, None),
    ("sentinel compare imm", b"\x81\xfd\x00\xca\x9a\x3b", 0, 3, 0x9B, None),
    ("gate mask imm", b"\xb9\x1d\x50\x00\x00", 0, 1, 0x1C, None),
    ("gate index limit", b"\x80\xf9\x0e", 0, 2, 0x0D, None),
    ("flag argument imm", b"\xbf\x32\x00\x00\x00", 0, 1, 0x33, None),
    ("table base sub imm", b"\x48\x2d\x86\x00\x00\x00", 0, 2, 0x87, None),
    ("default index imm", b"\xb9\x14\x00\x00\x00", 0, 1, 0x15, None),
    ("join word, site 1", b"\x66\x81\x3c\x24\xa2\x01", 0, 4, 0xA3, None),
    ("join word, site 2", b"\x66\x81\x3c\x24\xa2\x01", 1, 4, 0xA3, None),
    ("join word, site 3", b"\x66\x81\x3c\x24\xa2\x01", 2, 4, 0xA3, None),
    ("nested index add imm", b"\x8d\x48\x7a", 0, 2, 0x7B, None),
    ("payload step, copy arm", b"\x49\x83\xc4\x08\x41\x8b\x45\x10", 0, 3, 0x10, None),
    ("payload step, plain arm", b"\x49\x83\xc4\x08\x48\x8d\x7c\x24\x70\x4c", 0, 3, 0x10, None),
    ("payload step, rsp-first arm", b"\x49\x83\xc4\x08\x48\x89\xe7\x4c\x89\xfe", 0, 3, 0x10, None),
    ("error word 0x154", b"\x66\xc7\x84\x24\x80\x00\x00\x00\x54\x01", 0, 8, 0x55, None),
    ("error word 0x91", b"\x66\xc7\x84\x24\x80\x00\x00\x00\x91\x00", 0, 8, 0x92, None),
    ("error word 0x92", b"\x66\xc7\x84\x24\x80\x00\x00\x00\x92\x00", 0, 8, 0x93, None),
    ("guard compare 3 (guard63)", b"\x3c\x03\x0f\x85", 0, 1, 0x04, None),
    ("guard compare 3 (guard64)", b"\x41\x80\xbf\x9a\x0b\x00\x00\x03", 0, 7, 0x04, None),
    ("ctx byte offset in slot arm", b"\x45\x0f\xb6\x87\x9a\x0b\x00\x00", 0, 4, 0x9B, None),
    ("conditional move to below", b"\x48\x0f\x43\xc8", 0, 2, 0x42, None),
    ("timer clock argument", b"\xbf\x01\x00\x00\x00\xe8", 0, 1, 0x02, None),
    ("ok tag in const arm", b"\xc6\x44\x24\x70\x0e", 0, 4, 0x0F, None),
    ("first push of the prologue", b"\x55\x41\x57", 0, 0, 0x53, None),
]


def router_extent(image):
    start, end = image.exact_fde(ROUTER)
    return start, end


def find_all(blob, pattern, lo, hi):
    out, at = [], blob.find(pattern, lo, hi)
    while at != -1:
        out.append(at)
        at = blob.find(pattern, at + 1, hi)
    return out


def evaluate(trial, real_results, cases, arms, slot_c):
    """Return the first reason a (possibly mutated) model disagrees with the cached real results, or None."""
    for case, (trace, out) in zip(cases, real_results):
        model, expect = run_model(trial, arms, slot_c, case)
        why = compare(trace, out, model)
        if why is None and out != expect:
            why = "result bytes differ"
        if why is not None:
            return "case %d: %s" % (case.cid, why)
    return None


def generate(out_dir):
    blob = BINARY.read_bytes()
    if hashlib.sha256(blob).hexdigest() != SHA256:
        raise EvidenceError("input binary digest mismatch")
    image = Image(blob)
    arms = arm_table(image)
    slot_c = tail_slot_c(image)
    start, end = router_extent(image)
    cases = make_cases()
    count = 0
    rig = Rig(image, arms, slot_c)
    out_dir.mkdir(parents=True, exist_ok=True)

    shapes = {}
    for arm in arms:
        shapes.setdefault(arm["shape"], []).append(arm["index"])
    with (out_dir / "arms.tsv").open("w", newline="\n") as fh:
        fh.write("index\ttag\tarm\tshape\thandler\n")
        for arm in arms:
            handler = arm["handler"] if arm["shape"] != "guard63" else slot_c
            fh.write("%d\t0x%x\t0x%x\t%s\t%s\n" % (arm["index"], 0x86 + arm["index"], arm["start"], arm["shape"],
                                                   "-" if handler is None else "0x%x" % handler))
    with (out_dir / "shapes.tsv").open("w", newline="\n") as fh:
        fh.write("shape\tarms\tindices\n")
        for name in sorted(shapes):
            fh.write("%s\t%d\t%s\n" % (name, len(shapes[name]), ",".join(str(i) for i in shapes[name])))

    coverage = {}
    suite = []
    suite_real = []
    failures = []
    shape_cases = {}
    calls_total = 0
    with (out_dir / "cases.tsv").open("w", newline="\n") as fh:
        fh.write("case\ttag\tcl\tdl\tflag\tguard\tcalls\tresult_digest\n")
        for case in cases:
            count += 1
            why, trace, result = check_case(rig, REAL, arms, slot_c, case)
            if why is not None:
                failures.append((case.cid, why))
            for va in rig.machine.seen:
                coverage[va] = coverage.get(va, 0) + 1
            calls_total += len(trace)
            shape = arms[(case.tag - 0x86) if case.tag >= 0x86 else 20]["shape"]
            shape_cases[shape] = shape_cases.get(shape, 0) + 1
            if case.cid % 31 == 0 or (case.cid < COUNT * 110 and case.cid % COUNT in (52, 61, 63, 64, 75)):
                suite.append(case)
                suite_real.append((trace, result))
            guard = case.b9a
            if case.cid % 3:
                continue
            fh.write("%d\t0x%x\t%d\t%d\t%d\t%d\t%d\t%s\n" % (case.cid, case.tag, case.cl, case.dl, case.flag, guard, len(trace),
                                                          hashlib.sha256(result).hexdigest()[:12]))
    if failures:
        raise EvidenceError("model disagrees with the router bytes: %r" % (failures[:3],))

    rows = decode_range(image, start, end)
    with (out_dir / "coverage.tsv").open("w", newline="\n") as fh:
        fh.write("address\top\tcases\n")
        for row in rows:
            fh.write("0x%x\t%s\t%d\n" % (row.va, row.op, coverage.get(row.va, 0)))
    visited = sum(1 for row in rows if coverage.get(row.va))
    boundaries = set(row.va for row in rows)
    past = TABLE + struct.unpack_from("<i", image.blob, image.offset(TABLE) + 4 * COUNT)[0]
    if not all(arm["start"] in boundaries for arm in arms) or past in boundaries:
        raise EvidenceError("table end check failed: entry %d must not be an instruction start" % COUNT)

    controls = []
    equivalent = []
    for label, change, reason in MODEL_MUTANTS:
        trial = dict(REAL)
        if change.get("handler_swap") == "arm3":
            change = dict(handler_swap=(arms[3]["handler"], arms[4]["handler"]))
        trial.update(change)
        try:
            why = evaluate(trial, suite_real, suite, arms, slot_c)
        except Exception as exc:  # a mutated model that crashes is also caught
            why = "model raised %s" % type(exc).__name__
        controls.append(("model", label, why, reason))
    for label, pattern, occurrence, offset, new, reason in BYTE_MUTANTS:
        sites = find_all(blob, pattern, image.offset(start), image.offset(end))
        if occurrence >= len(sites):
            raise EvidenceError("byte pattern for %r not found" % label)
        va = start + (sites[occurrence] - image.offset(start)) + offset
        mutant_rig = Rig(image, arms, slot_c, {va: new})
        why = None
        for case in suite:
            try:
                got = check_case(mutant_rig, REAL, arms, slot_c, case)[0]
            except Exception as exc:
                got = "interpreter raised %s" % type(exc).__name__
            if got is not None:
                why = "case %d: %s" % (case.cid, got)
                break
        controls.append(("bytes@0x%x" % va, label, why, reason))
    detected = sum(1 for c in controls if c[2] is not None)
    equiv = [c for c in controls if c[2] is None and c[3]]
    missed = [c for c in controls if c[2] is None and not c[3]]
    if missed:
        raise EvidenceError("undetected controls without an equivalence reason: %r" % (missed,))
    with (out_dir / "controls.tsv").open("w", newline="\n") as fh:
        fh.write("kind\tcontrol\tresult\n")
        for kind, label, why, reason in controls:
            fh.write("%s\t%s\t%s\n" % (kind, label, "detected: " + why if why else "equivalent"))
    with (out_dir / "equivalent-mutants.tsv").open("w", newline="\n") as fh:
        fh.write("mutant\taddress\treason\n")
        for kind, label, why, reason in equiv:
            fh.write("%s\t%s\t%s\n" % (label, kind, reason))
    summary = {
        "target": "0x%x..0x%x" % (start, end), "arms": COUNT, "shapes": len(shapes), "cases": count,
        "recorded_calls": calls_total, "instructions": len(rows), "instructions_covered": visited,
        "first_entry_past_table": "0x%x" % past, "past_entry_is_instruction_start": past in boundaries,
        "suite_cases": len(suite), "controls": len(controls), "detected": detected, "equivalent": len(equiv),
        "cases_per_shape": {k: shape_cases[k] for k in sorted(shape_cases)},
    }
    (out_dir / "summary.json").write_text(json.dumps(summary, indent=1, sort_keys=True) + "\n")
    (out_dir / "measure.json").write_text(json.dumps({"cases": count, "negative_controls": len(controls),
                                                      "negative_detected": detected, "equivalent": len(equiv)},
                                                     sort_keys=True) + "\n")
    names = sorted(p.name for p in out_dir.iterdir() if p.name not in ("README.md", "MANIFEST.sha256"))
    lines = ["%s  %s\n" % (hashlib.sha256((out_dir / n).read_bytes()).hexdigest(), n) for n in names]
    return summary, lines


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", required=True)
    parser.add_argument("--manifest", action="store_true", help="also write MANIFEST.sha256 (README.md is hashed too if present)")
    args = parser.parse_args(argv)
    out = pathlib.Path(args.out)
    summary, _ = generate(out)
    if args.manifest:
        names = sorted(p.name for p in out.iterdir() if p.name != "MANIFEST.sha256")
        (out / "MANIFEST.sha256").write_text("".join("%s  %s\n" % (hashlib.sha256((out / n).read_bytes()).hexdigest(), n)
                                                    for n in names))
    print(json.dumps(summary, sort_keys=True))


if __name__ == "__main__":
    main()
