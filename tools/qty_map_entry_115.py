#!/usr/bin/env python3
"""Reconstruct the node #115 hybrid quantity map entry 0x3cd7640 and its four ring searches from ELF bytes.

The map under base/l1_map/entry.rs is one of two shapes behind a capacity niche: a sorted VecDeque of rows with 20-byte keys, or a
B-tree of 11-key nodes (niche 0x8000000000000000 in the first word). `entry` demotes a tree with fewer than 0x20 rows, promotes a
ring with at least 0x40 rows when the key is missing, and otherwise returns an occupied or vacant handle. The real bytes of the
entry (0x3cd7640) and the four ring binary searches (0x4554cb0, 0x4555050, 0x4556850, 0x4557ad0) run in a Python interpreter over
memory images built from the layout read out of the bytes; a separately written specification predicts every result. Deliberately
broken specifications and corrupted code bytes (every conditional branch inverted, every immediate flipped) must be caught. The
interpreter below is the shared offline x86-64 evaluator; imported compare, promotion and demotion are recorded host calls. No
objdump or readelf output is parsed and the binary is never executed. Standard library plus the shared elf_index and fde_extents.

    python3 tools/qty_map_entry_115.py --out research/work-items/RE-009-quantities-map-entry-115
"""

import collections
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




# ======================================================================================================================
# Quantity-map entry (base/l1_map/entry.rs) and its ring searches, run on the real bytes of node #115
# ======================================================================================================================

import argparse  # noqa: E402
import bisect as _bisect  # noqa: E402

MIN = 1 << 63                      # capacity niche that marks the B-tree variant of the hybrid map
SLOT_MEMCMP = 0x64DFB50            # imported compare, read through the GOT
SLOT_DEALLOC = 0x64DF4A0
MEMCMP_MARK = 0x7E00000001
PROMOTE_CALL = 0x387CDD0           # ring -> tree bulk build, host call
DEMOTE_CALLS = (0x3DD3F30, 0x3904B80)
ENTRY = 0x3CD7640
DEBIT = 0x42258D0
SLOT_PANIC = 0x64E4EA8
STATE_AT = HEAP_BASE + 0x1400
DEBIT_LAYOUT = (0xB8, 0x196, 0x198, 0x1F8)      # nodes of the balance tree: 16-byte values first, keys at 0xb8
ROW_VALUE = 0x18                                # ring rows are 0x28 bytes: 20-byte key, pad, two words from 0x18
ROOT_HANDLER = 0x3C34FD0
MEMBERS = (0x3C34FD0, 0x3CD7640, 0x4221510, 0x4221F40, 0x42258D0, 0x4554CB0, 0x4556850, 0x4557AD0)
RINGS = (("ring40", 0x4557AD0, 0x28), ("ring48a", 0x4555050, 0x30), ("ring48b", 0x4556850, 0x30), ("ring112", 0x4554CB0, 0x70))
PROMOTE_LEN = 0x40                 # ring maps with more than 0x3f rows are promoted on a missing key
DEMOTE_LEN = 0x20                  # tree maps with fewer than 0x20 rows are demoted on entry
NODE_CAP = 11
NODE_SIZE = 0x250
KEYS_AT, PLEN_AT, EDGES_AT, VALS_STRIDE = 0x110, 0x1EE, 0x1F0, 24
MAP_AT, KEY_AT, OUT_AT, RING_AT, NODE_AT = HEAP_BASE + 0x1000, HEAP_BASE + 0x1100, HEAP_BASE + 0x1200, HEAP_BASE + 0x2000, HEAP_BASE + 0x40000
HEAP_USED = 0x80000
U64 = MASK[8]


class Lcg:
    """Fixed generator so that the case list never depends on the Python build."""

    def __init__(self, start):
        self.state = start & U64 or 1

    def next(self):
        self.state = (self.state * 6364136223846793005 + 1442695040888963407) & U64
        return self.state >> 33

    def below(self, bound):
        return self.next() % bound

    def pick(self, items):
        return items[self.below(len(items))]

    def blob(self, count):
        return bytes(self.below(256) for _ in range(count))


def verify_digest(blob, expected=SHA256):
    digest = hashlib.sha256(blob).hexdigest()
    if digest != expected:
        raise EvidenceError("binary SHA-256 mismatch: %s" % digest)
    return digest


def memcmp_hook(machine):
    a, b, count = machine.regs[RDI], machine.regs[RSI], machine.regs[RDX]
    left, right = machine.memory.bytes_at(a, count), machine.memory.bytes_at(b, count)
    machine.calls_made = getattr(machine, "calls_made", 0) + 1
    result = 0
    for x, y in zip(left, right):
        if x != y:
            result = (x - y) & 0xFFFFFFFF
            break
    machine.regs[RAX] = result


class Reached(Exception):
    """A callee outside the modelled set was reached; the path is recorded, not followed."""

    def __init__(self, target, seen=None):
        super().__init__("reached %#x" % target)
        self.target = target
        self.seen = seen


# ---------------------------------------------------------------- memory images

def make_keys(rng, count, style):
    """count distinct sorted 20-byte keys; style picks how much of the prefix they share."""
    prefix = rng.blob({"wide": 0, "near": 19, "mid": 12, "high": 4}[style])
    seen = set()
    while len(seen) < count:
        tail = rng.blob(20 - len(prefix))
        if style == "high":
            tail = bytes(b | 0x80 if i == 0 else b for i, b in enumerate(tail))
        seen.add(prefix + tail)
    return sorted(seen)


def put_ring(machine, rng, cap, head, keys, stride, at=RING_AT):
    """A VecDeque-shaped map header at MAP_AT and its buffer; rows outside the live window hold noise."""
    mem = machine.memory
    mem.put_bytes(at, rng.blob(cap * stride))
    for index, key in enumerate(keys):
        mem.put_bytes(at + ((head + index) % cap) * stride, key)
    return at


def put_header(machine, words, at=MAP_AT):
    machine.memory.put_bytes(at, struct.pack("<QQQQ", *words))


def build_tree(machine, rng, keys, at, layout=None):
    """Real B-tree node images (11 keys per node); returns (root, height, {key: (node, height, index)}, {node: (keys, children)})."""
    keys_at, plen_at, edges_at, node_size = layout or (KEYS_AT, PLEN_AT, EDGES_AT, NODE_SIZE)
    capacity = [NODE_CAP]
    while capacity[-1] < len(keys):
        capacity.append(capacity[-1] * 12 + 11)
    height = next(h for h, c in enumerate(capacity) if c >= len(keys))
    found, cursor, nodes = {}, [at], {}

    def node(chunk, h):
        base = cursor[0]
        cursor[0] += node_size
        machine.memory.put_bytes(base, rng.blob(node_size))
        if h == 0:
            parts, seps = [], list(chunk)
        else:
            k = next(k for k in range(1, NODE_CAP + 1) if len(chunk) - k <= (k + 1) * capacity[h - 1] and len(chunk) - k >= k + 1)
            share, extra = divmod(len(chunk) - k, k + 1)
            parts, seps, cut = [], [], 0
            for part in range(k + 1):
                size = share + (1 if part < extra else 0)
                parts.append(chunk[cut:cut + size])
                cut += size
                if part < k:
                    seps.append(chunk[cut])
                    cut += 1
        for index, key in enumerate(seps):
            machine.memory.put_bytes(base + keys_at + 20 * index, key)
            found[key] = (base, h, index)
        machine.memory.put_bytes(base + plen_at, struct.pack("<H", len(seps)))
        nodes[base] = (list(seps), [])
        for index, part in enumerate(parts):
            child = node(part, h - 1)
            nodes[base][1].append(child)
            machine.memory.put_bytes(base + edges_at + 8 * index, struct.pack("<Q", child))
        return base

    root = node(list(keys), height)
    return root, height, found, nodes




def new_machine(image, patches=None):
    """One reusable interpreter: compare through the GOT slot, promotion and dealloc as recorded host calls."""
    machine = Machine(image, patches)
    machine.memory.statics[SLOT_MEMCMP] = MEMCMP_MARK
    machine.slots[MEMCMP_MARK] = memcmp_hook
    machine.memory.statics[SLOT_DEALLOC] = MEMCMP_MARK + 1
    machine.slots[MEMCMP_MARK + 1] = lambda m: (_ for _ in ()).throw(Reached(SLOT_DEALLOC))
    machine.memory.statics[SLOT_PANIC] = MEMCMP_MARK + 2
    machine.slots[MEMCMP_MARK + 2] = lambda m: (_ for _ in ()).throw(Reached(SLOT_PANIC))
    machine.promote_tree = None
    machine.promote_args = None
    machine.real = frozenset((0x4556850, 0x4557AD0))

    def promote(m):
        # the ring is handed over by value at rsi (cap, ptr, head, len); the host answers with a tree (root, height, len)
        m.promote_args = bytes(m.memory.bytes_at(m.regs[RSI], 32)) + bytes(m.memory.bytes_at(MAP_AT, 32))
        if m.promote_tree is None:
            raise Reached(PROMOTE_CALL)
        m.memory.put_bytes(m.regs[RDI], struct.pack("<QQQ", *m.promote_tree))

    machine.calls[PROMOTE_CALL] = promote
    def demote(target):
        def hook(m):
            # the tree is handed over as an owning iterator (front and back cursors plus the length) at rsi
            words = struct.unpack("<9Q", m.memory.bytes_at(m.regs[RSI], 72))
            header = struct.unpack("<QQQQ", m.memory.bytes_at(MAP_AT, 32))
            if not words[0]:
                raise Reached(target, (words[0], 0, 0, 0, words[4], 0, 0, 0, words[8], header))   # empty tree: cursors hold stack garbage
            raise Reached(target, tuple(words) + (header,))
        return hook

    for target in DEMOTE_CALLS:
        machine.calls[target] = demote(target)
    return machine


# ---------------------------------------------------------------- specifications (written from the claim)

def spec_search(keys, query, bug=None):
    """Result<usize, usize> of the ring binary search: (0, index) when found, (1, insertion point) otherwise."""
    index = _bisect.bisect_right(keys, query) if bug == "right" else _bisect.bisect_left(keys, query)
    if index < len(keys) and keys[index] == query:
        return (0, index + (1 if bug == "next" else 0))
    return (1, index)


def spec_tree_walk(nodes, root, height, query):
    """Descend the node images the way the entry does; returns the occupied or vacant handle words."""
    node, h = root, height
    while True:
        keys, children = nodes[node]
        index = _bisect.bisect_left(keys, query)
        if index < len(keys) and keys[index] == query:
            return ("occupied", "tree", node, h, index, MAP_AT + 8)
        if h == 0:
            return ("vacant", "tree", MAP_AT + 8, query, node, 0, index)
        node, h = children[index], h - 1


def spec_entry(case, bug=None):
    """(outcome words, final header words, promotion arguments) predicted for one entry case."""
    header, live, query, nodes = case["header"], case["live"], case["query"], case["nodes"]
    cap, second, third, length = header
    if cap == MIN:
        if length < DEMOTE_LEN and bug != "no_demote":
            some = 1 if second else 0
            seen = (some, 0, second, third, some, 0, second, third, length, (MIN, 0, header[2], 0))
            if not second:
                seen = (0, 0, 0, 0, 0, 0, 0, 0, 0, (MIN, 0, header[2], 0))
            return ("reached", DEMOTE_CALLS[0], seen), header, None
        if second == 0:
            return ("vacant", "tree", MAP_AT + 8, query, 0, 0, MIN), header, None
        return spec_tree_walk(nodes, second, third, query), header, None
    result, index = spec_search(live, query, bug)
    limit = PROMOTE_LEN + (1 if bug == "limit" else 0)
    if result == 1 and length >= limit:
        if case["staged"] is None:
            return ("unstaged",), header, None
        root, height, count = case["staged"]
        return spec_tree_walk(case["staged_nodes"], root, height, query), (MIN, root, height, count), struct.pack("<QQQQ", *header) + struct.pack("<QQQQ", 0, 8, 0, 0)
    if result == 0:
        return ("occupied", "ring", MAP_AT, index), header, None
    return ("vacant", "ring", index, query, MAP_AT), header, None


# ---------------------------------------------------------------- runners

def read_outcome(machine):
    """Decode the entry result at OUT_AT into the words the specification predicts (stack garbage bytes are not read)."""
    mem = machine.memory
    tag, second, third, fourth, fifth = struct.unpack("<5Q", mem.bytes_at(OUT_AT, 40))
    if tag == 1:
        if second == 0:
            return ("occupied", "ring", third, fourth)
        return ("occupied", "tree", second, third, fourth, fifth)
    if second == 0:
        return ("vacant", "ring", fourth, bytes(mem.bytes_at(OUT_AT + 0x20, 20)), third)
    return ("vacant", "tree", second, bytes(mem.bytes_at(OUT_AT + 0x28, 20)), third, fourth, fifth)


def search_case(rng):
    count = rng.pick((0, 1, 2, 3, 5, 8, 13, 21, 34, 64))
    style = rng.pick(("wide", "near", "mid", "high"))
    keys = make_keys(rng, count, style)
    cap = max(count, 1) + rng.pick((0, 0, 1, 3, 9))
    head = rng.below(cap) if count else 0
    pick = rng.below(4)
    if count > 2 and rng.below(3) == 0:
        # wrapped window: the back slice starts at physical row 0 and its first row is probed or its neighbours are
        cap = count + rng.pick((0, 1, 4))
        split = 1 + rng.below(count - 1)
        head = cap - split
        probe = rng.pick((0, 0, 1))
        query = keys[split]
        if probe:
            base = bytearray(query)
            base[19] ^= 1
            query = bytes(base)
        return {"keys": keys, "cap": cap, "head": head, "query": query, "seed": rng.next()}
    if keys and pick == 0:
        query = rng.pick(keys)
    elif keys and pick == 1:
        base = bytearray(rng.pick(keys))
        base[19] ^= 1 + rng.below(3)
        query = bytes(base)
    elif pick == 2:
        query = b"\x00" * 20
    else:
        query = make_keys(rng, 1, style)[0]
    return {"keys": keys, "cap": cap, "head": head, "query": query, "seed": rng.next()}


def run_search_case(machine, address, stride, case):
    machine.memory.reset(HEAP_USED)
    rng = Lcg(case["seed"])
    ring = put_ring(machine, rng, case["cap"], case["head"], case["keys"], stride)
    put_header(machine, (case["cap"], ring, case["head"], len(case["keys"])))
    machine.memory.put_bytes(KEY_AT, case["query"])
    machine.run(address, {RDI: MAP_AT, RSI: KEY_AT})
    return machine.regs[RAX] & U64, machine.regs[RDX] & U64


SHAPES = ("ring-small", "ring-small", "ring-edge", "ring-big", "tree-big", "tree-edge", "tree-small", "tree-null", "tree-small-null")


def entry_case(rng):
    """A map shape the entry call distinguishes: ring/tree, around the 0x3f and 0x20 thresholds, key present or absent."""
    shape = rng.pick(SHAPES)
    length = {"ring-small": rng.pick((0, 1, 2, 7, 20, 40, 62)), "ring-edge": rng.pick((62, 63, 63, 64, 64, 65)),
              "ring-big": rng.pick((66, 70, 100)), "tree-big": rng.pick((32, 33, 40, 60, 130)),
              "tree-edge": rng.pick((31, 32, 32)), "tree-small": rng.pick((0, 1, 5, 30)), "tree-null": rng.pick((32, 50)),
              "tree-small-null": rng.pick((0, 3, 31))}[shape]
    style = rng.pick(("wide", "near", "mid", "high"))
    keys = make_keys(rng, length + 1, style)
    present = length > 0 and rng.below(2) == 0
    if present:
        live = keys[:length]
        query = rng.pick(live)
    else:
        query = rng.pick(keys)
        live = [key for key in keys if key != query]
    return {"shape": shape, "live": live, "query": query, "seed": rng.next()}


def build_entry(machine, case):
    """Write the map image of a case into the interpreter and attach what the specification needs."""
    machine.memory.reset(HEAP_USED)
    rng = Lcg(case["seed"])
    live, shape = case["live"], case["shape"]
    case["staged"] = case["staged_nodes"] = case["nodes"] = None
    machine.promote_tree = None
    if shape in ("tree-null", "tree-small-null"):
        case["header"] = (MIN, 0, 0, len(live))
        case["nodes"] = {}
    elif shape.startswith("tree"):
        root, height, found, nodes = build_tree(machine, rng, live, NODE_AT)
        case["header"], case["nodes"] = (MIN, root, height, len(live)), nodes
    else:
        cap = max(len(live), 1) + rng.pick((0, 2, 5))
        head = rng.below(cap) if live else 0
        ring = put_ring(machine, rng, cap, head, live, 0x30)
        case["header"] = (cap, ring, head, len(live))
        if len(live) >= PROMOTE_LEN and case["query"] not in live:
            root, height, found, nodes = build_tree(machine, rng, live, NODE_AT)
            case["staged"], case["staged_nodes"] = (root, height, len(live)), nodes
            machine.promote_tree = case["staged"]
    put_header(machine, case["header"])
    machine.memory.put_bytes(KEY_AT, case["query"])
    machine.memory.put_bytes(OUT_AT, bytes([0xCC]) * 0x48)


def run_entry_case(machine, case):
    build_entry(machine, case)
    machine.promote_args = None
    try:
        machine.run(ENTRY, {RDI: OUT_AT, RSI: MAP_AT, RDX: KEY_AT})
    except Reached as reached:
        return ("reached", reached.target, reached.seen), case["header"], machine.promote_args
    final = struct.unpack("<QQQQ", machine.memory.bytes_at(MAP_AT, 32))
    return read_outcome(machine), final, machine.promote_args


def entry_matches(case, got, bug=None):
    want = spec_entry(case, bug)
    return got[0] == want[0] and tuple(got[1]) == tuple(want[1]) and got[2] == want[2]


# ---------------------------------------------------------------- mutants

def mutation_sites(image, start, end, executed):
    """Every executed conditional branch (condition inverted) and immediate operand (low bit flipped), straight from the decoded bytes."""
    sites = []
    for row in decode_range(image, start, end):
        if row.va not in executed:
            continue
        base = image.offset(row.va)
        window = bytes(image.blob[base:base + row.size])
        if row.op == "jcc":
            at = 0 if window[0] != 0x0F else 1
            sites.append((row.va, "invert-branch", {row.va + at: window[at] ^ 1}))
        elif row.imm_at is not None and row.op not in ("call", "jmp", "jcc") and row.imm_size:
            at = row.imm_at
            sites.append((row.va, "flip-immediate", {row.va + at: window[at] ^ 1}))
    return sites


EQUIVALENT = {
    "short-circuit-one": "a compare against 1 only skips one binary-search round whose step is zero: with one row left the loop body halves "
                         "the count to 0, moves nothing and repeats the same final compare, so every result is unchanged",
    "low-byte-overwrite": "the register is zeroed (or set to 1) and then only its low byte is stored by setne, which replaces bit 0 alone: "
                          "the value 1 differs from 0 only in a bit that the following byte store overwrites",
    "empty-front-slice": "the immediate is the Err flag returned when the front slice is empty; with a non-empty window and head below "
                         "capacity the front slice always holds a row, so the path is not reachable from any valid ring",
}


def classify_equivalent(row, following):
    """Reason key when a surviving immediate flip is provably behaviour-preserving, from the decoded instruction; else None."""
    if row.op == "cmp" and row.a in (("r", R12), ("r", R14), ("r", R15)) and row.b == ("i", 1):
        return "short-circuit-one"
    if row.op == "mov" and row.a == ("r", RAX) and row.b[0] == "i" and row.b[1] == 0 and following and following.op in ("test", "set", "sub", "movzx", "cmp"):
        return "low-byte-overwrite"
    if row.op == "mov" and row.a == ("r", RAX) and row.b == ("i", 1) and following and following.op == "test" and following.a == ("r", R14):
        return "empty-front-slice"
    return None


# ---------------------------------------------------------------- the debit (0x42258d0)

def spec_debit(book, key, amount, bug=None):
    """New book (key -> (limit, total)) after subtracting amount from the total of key, or the string 'panic' on underflow."""
    if key not in book:
        return dict(book)
    limit, total = book[key]
    if total < amount:
        if bug == "saturate":
            total = amount
        else:
            return "panic"
    total -= amount
    new = dict(book)
    new[key] = (limit if bug == "no_clamp" else min(limit, total), total)
    return new


def debit_case(rng):
    shape = rng.pick(("ring", "ring", "tree"))
    count = rng.pick((0, 1, 2, 6, 17, 40)) if shape == "ring" else rng.pick((12, 25, 33, 70, 140))
    keys = make_keys(rng, count + 1, rng.pick(("wide", "near", "mid", "high")))
    present = count > 0 and rng.below(4) != 0
    query = rng.pick(keys[:count]) if present else rng.pick(keys)
    live = keys[:count] if present else [key for key in keys if key != query]
    big = rng.pick((10, 1000, 1 << 40, (1 << 64) - 1))
    book = {key: (rng.below(big + 1), rng.below(big + 1)) for key in live}
    if present:
        limit, total = book[query]
        if rng.below(2):
            book[query] = (rng.pick((limit, total, total + 1, 0)) & U64, total)
    total = book[query][1] if present else 0
    amount = rng.pick((0, 1, total, total + 1, total - 1 if total else 0, rng.below(big + 1), U64)) & U64
    return {"shape": shape, "live": live, "book": book, "query": query, "amount": amount, "seed": rng.next()}


def run_debit_case(machine, case):
    machine.memory.reset(HEAP_USED)
    rng = Lcg(case["seed"])
    book, live = case["book"], case["live"]
    map_at = STATE_AT + 0x10
    if case["shape"] == "tree":
        root, height, found, nodes = build_tree(machine, rng, live, NODE_AT, DEBIT_LAYOUT)
        for key, (node, _, index) in found.items():
            machine.memory.put_bytes(node + 16 * index, struct.pack("<QQ", *book[key]))
        header = (MIN, root, height, len(live))
        spots = {key: node + 16 * index for key, (node, _, index) in found.items()}
    else:
        cap = max(len(live), 1) + rng.pick((0, 2, 5))
        head = rng.below(cap) if live else 0
        ring = put_ring(machine, rng, cap, head, live, 0x28)
        spots = {}
        for index, key in enumerate(live):
            spot = ring + ((head + index) % cap) * 0x28 + ROW_VALUE
            machine.memory.put_bytes(spot, struct.pack("<QQ", *book[key]))
            spots[key] = spot
        header = (cap, ring, head, len(live))
    put_header(machine, header, at=map_at)
    machine.memory.put_bytes(KEY_AT, case["query"])
    try:
        machine.run(DEBIT, {RDI: STATE_AT, RSI: KEY_AT, RDX: case["amount"]})
    except Reached as reached:
        if reached.target != SLOT_PANIC:
            raise
        return "panic"
    if struct.unpack("<QQQQ", machine.memory.bytes_at(map_at, 32)) != header:
        return "header-changed"
    return {key: struct.unpack("<QQ", machine.memory.bytes_at(spot, 16)) for key, spot in spots.items()}


def debit_matches(case, got, bug=None):
    return got == spec_debit(case["book"], case["query"], case["amount"], bug)


def run_battery(image, start, end, runner, cases, patches=None):
    """True when every case still matches; a mutant that halts counts as a difference."""
    machine = new_machine(image, patches)
    for case in cases:
        try:
            if not runner(machine, case):
                return False
        except (Halt, Reached, EvidenceError, KeyError, IndexError, ValueError, struct.error):
            return False
    return True


# ---------------------------------------------------------------- evidence

def call_rows(image, start, end):
    """(va, kind, target) of every direct call, tail jump out of the body and indirect call, from the decoded bytes."""
    rows = []
    for row in decode_range(image, start, end):
        if row.op == "call":
            rows.append((row.va, "call", row.target))
        elif row.op == "calli":
            rows.append((row.va, "calli", None))
        elif row.op == "jmp" and not (start <= row.target < end):
            rows.append((row.va, "tail", row.target))
    return rows


def sha_lines(lines):
    digest = hashlib.sha256()
    for line in lines:
        digest.update(line.encode() + b"\n")
    return digest.hexdigest()


def generate(out, search_cases=2500, entry_cases=4000, battery=220, debit_cases=3000):
    out = pathlib.Path(out)
    out.mkdir(parents=True, exist_ok=True)
    image = load_image()
    files = {}
    controls = []
    ranges = {"entry": image.exact_fde(ENTRY)}
    total_cases = 0

    # 1. function table and call sites
    functions = ["address\tsize\trole"]
    roles = {0x3C34FD0: "root handler", 0x3CD7640: "hybrid map entry", 0x4221510: "callee of root (not reconstructed)", 0x4221F40: "callee of root (not reconstructed)",
             0x42258D0: "balance debit (reconstructed)", 0x4554CB0: "ring search stride 0x70", 0x4556850: "ring search stride 0x30",
             0x4557AD0: "ring search stride 0x28"}
    calls = ["member\tsite\tkind\ttarget"]
    for address in MEMBERS:
        start, end = image.exact_fde(address)
        functions.append("%#x\t%d\t%s" % (start, end - start, roles[address]))
        for va, kind, target in call_rows(image, start, end):
            calls.append("%#x\t%#x\t%s\t%s" % (address, va, kind, "" if target is None else "%#x" % target))
    start, end = image.exact_fde(0x4555050)
    functions.append("%#x\t%d\t%s" % (start, end - start, "ring search stride 0x30 (second copy)"))
    files["functions.tsv"] = functions
    files["calls.tsv"] = calls

    # 2. ring searches on the real bytes
    rng = Lcg(0x5EA7C4)
    cases = [search_case(rng) for _ in range(search_cases)]
    ring_lines = ["function\tcase\tcount\tcap\thead\tquery\tresult\tindex"]
    digests = {}
    search_battery = cases[:battery]
    for name, address, stride in RINGS:
        machine = new_machine(image)
        mismatches, lines = 0, []
        for number, case in enumerate(cases):
            got = run_search_case(machine, address, stride, case)
            want = spec_search(case["keys"], case["query"])
            total_cases += 1
            if got != want:
                mismatches += 1
            lines.append("%s\t%d\t%d\t%d\t%d\t%s\t%d\t%d" % (name, number, len(case["keys"]), case["cap"], case["head"],
                                                             case["query"].hex(), got[0], got[1]))
        if mismatches:
            raise EvidenceError("%s: %d of %d searches differ from the specification" % (name, mismatches, len(cases)))
        digests[name] = sha_lines(lines)
        ring_lines.extend(lines[::6])
        start, end = image.exact_fde(address)
        ranges[name] = (start, end)

        def runner(m, case, address=address, stride=stride):
            return run_search_case(m, address, stride, case) == spec_search(case["keys"], case["query"])

        for va, kind, patch in mutation_sites(image, start, end, machine.seen):
            detected = not run_battery(image, start, end, runner, search_battery, patch)
            controls.append((name, "%#x" % va, kind, detected))
        for bug in ("right", "next"):
            detected = any(run_search_case(machine, address, stride, c) != spec_search(c["keys"], c["query"], bug) for c in search_battery)
            controls.append((name, "spec", "specification-" + bug, detected))
    files["ring-searches.tsv"] = ring_lines

    # 3. the hybrid map entry
    rng = Lcg(0xE17A9)
    machine = new_machine(image)
    entry_list = [entry_case(rng) for _ in range(entry_cases)]
    entry_lines = ["case\tshape\tlen\theader_cap\toutcome\tpromoted\tfinal_cap"]
    tally = collections.Counter()
    all_lines = []
    for number, case in enumerate(entry_list):
        got = run_entry_case(machine, case)
        total_cases += 1
        if not entry_matches(case, got):
            raise EvidenceError("entry case %d (%s) differs from the specification: %r" % (number, case["shape"], got[0]))
        kind = "/".join(str(w) for w in got[0][:2]) if got[0][0] != "reached" else "demote-call"
        if got[0][0] == "reached" and not case["header"][1]:
            kind = "demote-call-empty-root"
        tally[(case["shape"], kind)] += 1
        line = "%d\t%s\t%d\t%#x\t%s\t%d\t%#x" % (number, case["shape"], len(case["live"]), case["header"][0], kind,
                                                  1 if got[2] else 0, got[1][0])
        all_lines.append(line)
    digests["entry"] = sha_lines(all_lines)
    entry_lines.extend(all_lines[::3])
    files["entry-cases.tsv"] = entry_lines
    files["entry-outcomes.tsv"] = ["shape\toutcome\tcases"] + ["%s\t%s\t%d" % (s, k, n) for (s, k), n in sorted(tally.items())]
    start, end = image.exact_fde(ENTRY)
    unexecuted = ["first\tlast\tinstructions"]
    run_start, run_count, previous = None, 0, None
    for row in decode_range(image, start, end):
        if row.va in machine.seen:
            if run_start is not None:
                unexecuted.append("%#x\t%#x\t%d" % (run_start, previous, run_count))
            run_start, run_count = None, 0
        else:
            if run_start is None:
                run_start = row.va
            run_count += 1
            previous = row.va
    if run_start is not None:
        unexecuted.append("%#x\t%#x\t%d" % (run_start, previous, run_count))
    files["entry-unexecuted.tsv"] = unexecuted
    entry_battery = []
    seen = collections.Counter()
    for case in entry_list:
        key = (case["shape"], case["query"] in case["live"])
        if seen[key] < max(1, battery // 20):
            seen[key] += 1
            entry_battery.append(case)

    def entry_runner(m, case):
        return entry_matches(case, run_entry_case(m, case))

    for va, kind, patch in mutation_sites(image, start, end, machine.seen):
        detected = not run_battery(image, start, end, entry_runner, entry_battery, patch)
        controls.append(("entry", "%#x" % va, kind, detected))
    machine = new_machine(image)
    for bug in ("right", "limit", "no_demote"):
        detected = any(not entry_matches(c, run_entry_case(machine, c), bug) for c in entry_battery)
        controls.append(("entry", "spec", "specification-" + bug, detected))

    # 3b. the debit
    rng = Lcg(0xDEB17)
    machine = new_machine(image)
    debit_list = [debit_case(rng) for _ in range(debit_cases)]
    debit_lines = ["case\tshape\trows\tpresent\tamount\toutcome"]
    outcomes = collections.Counter()
    for number, case in enumerate(debit_list):
        got = run_debit_case(machine, case)
        total_cases += 1
        if not debit_matches(case, got):
            raise EvidenceError("debit case %d (%s) differs from the specification" % (number, case["shape"]))
        key = case["query"] in case["book"]
        outcome = "panic" if got == "panic" else ("hit" if key else "miss")
        outcomes[(case["shape"], outcome)] += 1
        debit_lines.append("%d\t%s\t%d\t%d\t%d\t%s" % (number, case["shape"], len(case["live"]), key, case["amount"], outcome))
    digests["debit"] = sha_lines(debit_lines)
    files["debit-cases.tsv"] = debit_lines[:1] + debit_lines[1::4]
    files["debit-outcomes.tsv"] = ["shape\toutcome\tcases"] + ["%s\t%s\t%d" % (a, b, n) for (a, b), n in sorted(outcomes.items())]
    start, end = image.exact_fde(DEBIT)
    ranges["debit"] = (start, end)
    debit_battery = debit_list[:battery]
    for va, kind, patch in mutation_sites(image, start, end, machine.seen):
        detected = not run_battery(image, start, end, lambda m, c: debit_matches(c, run_debit_case(m, c)), debit_battery, patch)
        controls.append(("debit", "%#x" % va, kind, detected))
    machine = new_machine(image)
    for bug in ("saturate", "no_clamp"):
        detected = any(not debit_matches(c, run_debit_case(machine, c), bug) for c in debit_battery)
        controls.append(("debit", "spec", "specification-" + bug, detected))

    # 4. controls, measure, digests
    control_lines = ["function\tsite\tkind\tdetected"] + ["%s\t%s\t%s\t%d" % (n, s, k, d) for n, s, k, d in controls]
    files["controls.tsv"] = control_lines
    equivalent_lines = ["function\tsite\tkind\treason"]
    still_missed = []
    for control in controls:
        if control[3]:
            continue
        name, site, kind, _ = control
        reason = None
        if kind == "flip-immediate":
            start, end = ranges[name]
            rows = decode_range(image, start, end)
            at = next(i for i, r in enumerate(rows) if r.va == int(site, 16))
            reason = classify_equivalent(rows[at], rows[at + 1] if at + 1 < len(rows) else None)
        if reason is None:
            still_missed.append(control)
        else:
            equivalent_lines.append("%s\t%s\t%s\t%s: %s" % (name, site, kind, reason, EQUIVALENT[reason]))
    missed = still_missed
    files["equivalent-mutants.tsv"] = equivalent_lines
    files["digests.tsv"] = ["stream\tsha256"] + ["%s\t%s" % item for item in sorted(digests.items())]
    for name, lines in files.items():
        (out / name).write_text("\n".join(lines) + "\n")
    measure = {"cases": total_cases, "negative_controls": len(controls), "negative_detected": sum(1 for c in controls if c[3]),
               "equivalent": len(equivalent_lines) - 1,
               "missed": ["%s %s %s" % c[:3] for c in missed]}
    (out / "measure.json").write_text(json.dumps(measure, indent=1, sort_keys=True) + "\n")
    return measure


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", required=True)
    args = parser.parse_args(argv)
    measure = generate(args.out)
    print(json.dumps(measure, sort_keys=True))


if __name__ == "__main__":
    main()
