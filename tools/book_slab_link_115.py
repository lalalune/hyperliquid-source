#!/usr/bin/env python3
"""RE-006: replay the node #115 order-slab insert and unlink bodies against a reconstruction.

The book keeps its resting orders in a slab of 0x110 byte entries (vacant entries start with the word 2 and carry the next free index), and
every order is also a node of a doubly linked list per price level whose ends live in a level record. This tool reconstructs, as plain
Python, the six bodies that put an order into the slab and link it (four copies, two journal record sizes) and that take an order out and
unlink it (two copies), runs the real function bytes on generated worlds through a small x86-64 interpreter with every edge stubbed, and
checks that panics, events and every observable byte agree. Deliberately wrong reconstructions and corrupted bytes are replayed as negative
controls. The binary is never executed; only its ELF bytes are read. Standard library plus the shared elf_index and fde_extents parsers.

    python3 tools/book_slab_link_115.py --out research/work-items/RE-006-book-slab-link-115
"""

import hashlib
import pathlib
import struct
import sys
import bisect
import math


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
            self.call_site = row.va
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
            self.call_site = row.va
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




# ----------------------------------------------------------------------------------------------------------------------------------
# Packet body: order slab insert / unlink with the per-level doubly linked list, reconstructed and replayed against the real bytes.
# ----------------------------------------------------------------------------------------------------------------------------------

import argparse
import json
import os
import shutil

FOLDER = "RE-006-book-slab-link-115"
M64 = (1 << 64) - 1
H = HEAP_BASE
SIZE = 0x50000
OFF_S, OFF_J, OFF_O, OFF_T, OFF_L, OFF_OUT = 0x1000, 0x1100, 0x1200, 0x1400, 0x1500, 0x1600
SLAB_AT, JOURNAL_AT, ARENA_AT = 0x10000, 0x30000, 0x40000
ENT = 0x110

REPORT_SLOT = 0x64E4EA8
MEMCPY_SLOT = 0x64DF508
PANIC_LOC_SLOT = 0x64DF830
PANIC_FMT_SLOTS = (0x64DF6B8, 0x64DF6A0)
GROW_SLOTS = (0x64E5A28, 0x64E5A30, 0x64E5A38, 0x64E4F88)
BTREE_CALLEES = {0x4DE02D0: "level-tree-step"}

# family name, entry va, kind
COPIES = (
    ("insert-a1", 0x23CD2D0, "insert"), ("insert-b1", 0x23CD700, "insert"),
    ("insert-a2", 0x58DF360, "insert"), ("insert-b2", 0x58DF790, "insert"),
    ("unlink-b", 0x58DFBC0, "unlink"), ("unlink-a", 0x58DFF20, "unlink"),
)


class Rng:
    """xorshift64* so that case lists never depend on the interpreter's random module."""

    def __init__(self, start):
        self.s = (start * 0x9E3779B97F4A7C15 + 1) & M64 or 1

    def next(self):
        x = self.s
        x ^= x >> 12
        x ^= (x << 25) & M64
        x ^= x >> 27
        self.s = x
        return (x * 0x2545F4914F6CDD1D) & M64

    def below(self, n):
        return (self.next() >> 11) % n

    def pick(self, items):
        return items[self.below(len(items))]

    def raw(self, n):
        out = bytearray()
        while len(out) < n:
            out += self.next().to_bytes(8, "little")
        return bytes(out[:n])


def q(buf, at):
    return int.from_bytes(buf[at:at + 8], "little")


def d(buf, at):
    return int.from_bytes(buf[at:at + 4], "little")


def setq(buf, at, value):
    buf[at:at + 8] = (value & M64).to_bytes(8, "little")


class SpecPanic(Exception):
    pass


def sat_inc(v):
    return M64 if v == M64 else v + 1


def sat_dec0(v):
    return 0 if v == 0 else v - 1


def entry_at(buf, i):
    return q(buf, OFF_S + 8) - H + i * ENT


INSERT_FLAWS = (
    "total-wraps", "level-wraps", "count-wraps", "tag-any", "idx-le", "vacant-found", "jfield-tag", "kind-qword", "no-prev-link",
    "head-for-tail", "reuse-next-kept", "no-occupied-check", "count-skip", "level-count-skip", "return-len", "journal-found-zero",
    "no-idx-store", "report-missing", "grow-journal-missing", "grow-slab-missing", "level-sum-skip", "next-slot-check-skip",
)
UNLINK_FLAWS = (
    "absent-dword", "count-wraps", "free-not-linked", "next-not-updated", "journal-kind2", "total-wraps", "report-missing",
    "cursor-qword", "cursor-any-idx", "tree-always", "tree-never", "sum-wraps", "tag-eq1", "no-neg-check", "flag-plain",
    "skip-prev-bounds", "next-link-swap", "tail-from-next", "level-count-wraps", "cursor-no-copy", "journal-field-shift",
)


def spec_insert(buf, ev, info, a, tag, idx, flaw=""):
    """Put the order record at OFF_O into the slab, link it before slot `idx` (tag 1) or at the tail of the level, journal the event."""
    size = q(buf, OFF_O + 0xE0)
    total = q(buf, OFF_T) + size
    if total > M64:
        if flaw != "report-missing":
            ev.append("report:total-add")
        total = M64 if flaw != "total-wraps" else total & M64
    setq(buf, OFF_T, total)
    found = 0
    prev_kind = q(buf, OFF_L + 0x10)
    prev_idx = q(buf, OFF_L + 0x18)
    jfield = tag
    if (tag == 1) if flaw != "tag-any" else (tag != 0):
        limit = q(buf, OFF_S + 0x10)
        if (idx < limit) if flaw != "idx-le" else (idx <= limit):
            at = entry_at(buf, idx)
            if q(buf, at) != 2 or flaw == "vacant-found":
                found = 1
                prev_kind = q(buf, at)
                prev_idx = q(buf, at + 8)
                jfield = q(buf, at + 0xF0)
            else:
                jfield = (idx * ENT) & M64 if flaw != "jfield-tag" else tag
    ofs = OFF_O
    jrec = {0: 2, 8: found if flaw != "journal-found-zero" else 0, 0x10: jfield, 0x18: size, 0x20: q(buf, ofs + 0xB0), 0x28: a,
            0x30: q(buf, ofs + 0xF0), 0x38: bytes(buf[ofs + 0xF8:ofs + 0x108]), 0x48: d(buf, ofs + 0x108), 0x4C: buf[ofs + 0xD2]}
    push_journal(buf, ev, info, jrec, JELEM[info["copy"]], flaw != "grow-journal-missing")
    setq(buf, ofs, prev_kind)
    setq(buf, ofs + 8, prev_idx)
    setq(buf, ofs + 0x10, found)
    if found:
        if flaw != "no-idx-store":
            setq(buf, ofs + 0x18, idx)
    else:
        info["mask"].append(("O", 0x18, 8))
    next_free = q(buf, OFF_S + 0x20)
    length = q(buf, OFF_S + 0x10)
    if flaw != "count-skip":
        count = q(buf, OFF_S + 0x18)
        setq(buf, OFF_S + 0x18, sat_inc(count) if flaw != "count-wraps" else (count + 1) & M64)
    new = next_free
    if next_free == length:
        if q(buf, OFF_S) == next_free:
            if flaw != "grow-slab-missing":
                ev.append("grow:slab")
            setq(buf, OFF_S, max(2 * next_free, 4))
        at = entry_at(buf, new)
        buf[at:at + ENT] = buf[ofs:ofs + ENT]
        length = new + 1
        setq(buf, OFF_S + 0x10, length)
        setq(buf, OFF_S + 0x20, length)
    elif next_free > length:
        raise SpecPanic("fmt:slab-next-beyond-len")
    else:
        at = entry_at(buf, new)
        if d(buf, at) != 2 and flaw != "no-occupied-check":
            raise SpecPanic("fmt:slab-next-beyond-len")
        if flaw != "reuse-next-kept":
            setq(buf, OFF_S + 0x20, q(buf, at + 8))
        buf[at:at + ENT] = buf[ofs:ofs + ENT]
    if not found:
        info["mask"].append(("E", new, 0x18, 8))
    if found:
        if idx >= length:
            raise SpecPanic("loc:prev-slot-missing")
        at = entry_at(buf, idx)
        if d(buf, at) == 2:
            raise SpecPanic("loc:prev-slot-missing")
        setq(buf, at, 1)
        setq(buf, at + 8, new)
    else:
        tail = OFF_L + 0x10 if flaw != "head-for-tail" else OFF_L
        setq(buf, tail, 1)
        setq(buf, tail + 8, new)
    if ((prev_kind & 0xFFFFFFFF) == 1) if flaw != "kind-qword" else (prev_kind == 1):
        if prev_idx >= q(buf, OFF_S + 0x10) and flaw != "next-slot-check-skip":
            raise SpecPanic("loc:next-slot-missing")
        at = entry_at(buf, prev_idx)
        if d(buf, at) == 2 and flaw != "next-slot-check-skip":
            raise SpecPanic("loc:next-slot-missing")
        if flaw != "no-prev-link":
            setq(buf, at + 0x10, 1)
            setq(buf, at + 0x18, new)
    else:
        setq(buf, OFF_L, 1)
        setq(buf, OFF_L + 8, new)
    if flaw != "level-sum-skip":
        level_sum = q(buf, OFF_L + 0x70) + size
        if level_sum > M64:
            ev.append("report:level-add")
            level_sum = M64 if flaw != "level-wraps" else level_sum & M64
        setq(buf, OFF_L + 0x70, level_sum)
    if flaw != "level-count-skip":
        setq(buf, OFF_L + 0x78, sat_inc(q(buf, OFF_L + 0x78)))
    return new if flaw != "return-len" else length


def push_journal(buf, ev, info, rec, elem, note_grow=True):
    length = q(buf, OFF_J + 0x10)
    if length == q(buf, OFF_J):
        if note_grow:
            ev.append("grow:journal")
        setq(buf, OFF_J, max(2 * length, 4))
    at = q(buf, OFF_J + 8) - H + length * elem
    for off, v in rec.items():
        if isinstance(v, bytes):
            buf[at + off:at + off + len(v)] = v
        elif off == 0x48:
            buf[at + off:at + off + 4] = v.to_bytes(4, "little")
        elif off == 0x4C:
            buf[at + off] = v
        else:
            setq(buf, at + off, v)
    setq(buf, OFF_J + 0x10, length + 1)
    info["jnew"] = length


def spec_unlink(buf, ev, info, a, idx, level, flaw=""):
    """Take slot idx out of the slab, journal it, settle the totals and unlink it from its level list; returns the emptied-level flag."""
    length = q(buf, OFF_S + 0x10)
    outo = OFF_OUT
    absent = idx >= length
    if not absent:
        word = q(buf, entry_at(buf, idx))
        absent = (word & 0xFFFFFFFF) == 2 if flaw == "absent-dword" else word == 2
    if absent:
        setq(buf, outo, 2)
        info["none"] = True
        return None
    at = entry_at(buf, idx)
    orig = bytes(buf[at:at + ENT])
    tag = q(orig, 0)
    freed = q(buf, OFF_S + 0x20)
    setq(buf, at, 2)
    if flaw != "free-not-linked":
        setq(buf, at + 8, freed)
    count = q(buf, OFF_S + 0x18)
    setq(buf, OFF_S + 0x18, sat_dec0(count) if flaw != "count-wraps" else (count - 1) & M64)
    if flaw != "next-not-updated":
        setq(buf, OFF_S + 0x20, idx)
    rec = {0: 2, 8: 3 if flaw != "journal-kind2" else 2, 0x20: q(orig, 0xB0), 0x28: a, 0x30: q(orig, 0xF0), 0x38: orig[0xF8:0x108],
           0x48: d(orig, 0x108), 0x4C: orig[0xD2]}
    if flaw == "journal-field-shift":
        rec[0x20] = q(orig, 0xB8)
    push_journal(buf, ev, info, rec, JELEM[info["copy"]])
    size = q(orig, 0xE0)
    total = q(buf, OFF_T)
    if total < size:
        if flaw != "report-missing":
            ev.append("report:total-sub")
        total = 0 if flaw != "total-wraps" else (total - size) & M64
    else:
        total -= size
    setq(buf, OFF_T, total)
    flag = 0
    if level:
        if (q(orig, 0xB0) >> 63) and flaw != "no-neg-check":
            raise SpecPanic("str:negative-key")
        lo = OFF_L
        kind_word = q(buf, lo + 0x20) if flaw == "cursor-qword" else d(buf, lo + 0x20)
        if kind_word == 1 and (q(buf, lo + 0x28) == idx or flaw == "cursor-any-idx"):
            if flaw != "cursor-no-copy":
                buf[lo + 0x20:lo + 0x30] = orig[0x10:0x20]
        if (orig[0xD8] != 0 or flaw == "tree-always") and flaw != "tree-never":
            ev.append("tree:%x:%x:%x" % (H + lo + 0x50, q(orig, 0xF0), d(orig, 0xDC)))
        s = q(buf, lo + 0x70)
        setq(buf, lo + 0x70, (s - size if s >= size else 0) if flaw != "sum-wraps" else (s - size) & M64)
        cnt = q(buf, lo + 0x78)
        setq(buf, lo + 0x78, sat_dec0(cnt) if flaw != "level-count-wraps" else (cnt - 1) & M64)
        prev_idx = q(orig, 8)
        nk, ni = q(orig, 0x10), q(orig, 0x18)
        if (tag & 1) if flaw != "tag-eq1" else (tag == 1):
            if prev_idx >= length and flaw != "skip-prev-bounds":
                raise SpecPanic("loc:unlink-prev-missing")
            pa = entry_at(buf, prev_idx)
            if d(buf, pa) == 2 and flaw != "skip-prev-bounds":
                raise SpecPanic("loc:unlink-prev-missing")
            setq(buf, pa + 0x10, nk)
            setq(buf, pa + 0x18, ni)
        else:
            setq(buf, lo, nk)
            setq(buf, lo + 8, ni)
        if nk == 0:
            setq(buf, lo + 0x10, tag)
            setq(buf, lo + 0x18, prev_idx if flaw != "tail-from-next" else ni)
        else:
            if ni >= length:
                raise SpecPanic("loc:unlink-next-missing")
            na = entry_at(buf, ni)
            if d(buf, na) == 2:
                raise SpecPanic("loc:unlink-next-missing")
            setq(buf, na, tag)
            setq(buf, na + 8, prev_idx if flaw != "next-link-swap" else ni)
        flag = ((buf[lo + 0x10] ^ 1) if flaw != "flag-plain" else buf[lo + 0x10]) if buf[lo] == 0 else 0
    buf[outo:outo + ENT] = orig
    buf[outo + ENT] = flag
    return flag


JELEM = {}


# ---------------------------------------------------------------------------------------------------------------------------------
# Static facts read from the bytes: frame extents, journal element sizes, call sites and their Location rows.
# ---------------------------------------------------------------------------------------------------------------------------------

def check_blob(blob):
    if hashlib.sha256(blob).hexdigest() != SHA256:
        raise EvidenceError("binary digest mismatch")
    return blob


def load_image_checked():
    return Image(check_blob(BINARY.read_bytes()))


_ROWS = {}


def static_rows(image, va):
    if va not in _ROWS:
        start, end = image.exact_fde(va)
        _ROWS[va] = (start, end, decode_range(image, start, end))
    return _ROWS[va]


def site_table(image, va):
    """Every indirect or direct call in the function: (va, kind, slot or target, Location of the preceding rip-relative lea)."""
    start, end, rows = static_rows(image, va)
    relative = image.relative()
    base_text = image.named[".text"]
    out = []
    recent = []
    for row in rows:
        if row.op == "lea" and row.b[0] == "m" and row.b[1] is None and row.b[2] is None:
            recent = (recent + [row.b[4] & M64])[-3:]
        if row.op == "calli" and row.a[0] == "m":
            slot = row.a[4]
            loc = None
            for target in (reversed(recent) if slot in (REPORT_SLOT, PANIC_LOC_SLOT) + PANIC_FMT_SLOTS else ()):
                if target in relative:
                    try:
                        loc = image.location(target, relative)
                    except Exception:
                        loc = None
                    if loc:
                        break
            out.append((row.va, "slot", slot, loc))
        elif row.op == "calli":
            out.append((row.va, "reg", 0, None))
        elif row.op == "call":
            out.append((row.va, "call", row.target, None))
        if row.op not in ("lea",):
            if row.op in ("calli", "call"):
                recent = []
    return out


def journal_elem(image, va):
    start, end, rows = static_rows(image, va)
    found = set()
    for row in rows:
        if row.op == "imul3" and row.b and row.b[0] == "r" and len(row.data) >= 7:
            imm = int.from_bytes(row.data[-4:], "little")
            if imm in (0x2B8, 0x2C8):
                found.add(imm)
    if len(found) != 1:
        raise EvidenceError("journal element size not unique at %#x" % va)
    return found.pop()


# ---------------------------------------------------------------------------------------------------------------------------------
# Worlds: the byte image the function starts from.
# ---------------------------------------------------------------------------------------------------------------------------------

def build_world(c):
    w = bytearray(bytes([STACK_MARK]) * SIZE)
    s_cap = c["scap"]
    setq(w, OFF_S, s_cap)
    setq(w, OFF_S + 8, H + SLAB_AT)
    setq(w, OFF_S + 0x10, len(c["ents"]))
    setq(w, OFF_S + 0x18, c["count"])
    setq(w, OFF_S + 0x20, c["nxt"])
    for i, raw in enumerate(c["ents"]):
        w[SLAB_AT + i * ENT:SLAB_AT + (i + 1) * ENT] = raw
    setq(w, OFF_J, c["jcap"])
    setq(w, OFF_J + 8, H + JOURNAL_AT)
    setq(w, OFF_J + 0x10, len(c["jents"]))
    for i, raw in enumerate(c["jents"]):
        w[JOURNAL_AT + i * c["jelem"]:JOURNAL_AT + (i + 1) * c["jelem"]] = raw
    w[OFF_O:OFF_O + ENT] = c["O"]
    setq(w, OFF_T, c["T"])
    w[OFF_L:OFF_L + 0x80] = c["L"]
    return w


def snapshot(w, info, jelem):
    """Comparable view of a heap image; bytes the function leaves as stack garbage are masked by `info`."""
    s_len = q(w, OFF_S + 0x10)
    ptr = q(w, OFF_S + 8) - H
    j_len = q(w, OFF_J + 0x10)
    jptr = q(w, OFF_J + 8) - H
    if s_len > 40 or j_len > 40 or not (0 <= ptr < SIZE - 40 * ENT) or not (0 <= jptr < SIZE - 40 * jelem):
        return ("corrupt", s_len, j_len)
    ents = [bytearray(w[ptr + i * ENT:ptr + (i + 1) * ENT]) for i in range(s_len)]
    o = bytearray(w[OFF_O:OFF_O + ENT])
    for m in info["mask"]:
        if m[0] == "O":
            o[m[1]:m[1] + m[2]] = bytes(m[2])
        elif m[0] == "E" and m[1] < len(ents):
            ents[m[1]][m[2]:m[2] + m[3]] = bytes(m[3])
    jents = []
    for i in range(j_len):
        raw = bytes(w[jptr + i * jelem:jptr + (i + 1) * jelem])
        if i == info.get("jnew"):
            raw = b"".join(raw[a:a + n] for a, n in JFIELDS)
        jents.append(raw)
    return (s_len, q(w, OFF_S + 0x18), q(w, OFF_S + 0x20), tuple(bytes(e) for e in ents), j_len, tuple(jents), q(w, OFF_T),
            bytes(w[OFF_L:OFF_L + 0x80]), bytes(o), bytes(w[OFF_OUT:OFF_OUT + 0x118]) if info["kind"] == "unlink" else b"")


# journal fields the functions write: (offset, length)
JFIELDS = ((0, 8), (8, 8), (0x10, 8), (0x18, 8), (0x20, 8), (0x28, 8), (0x30, 8), (0x38, 16), (0x48, 4), (0x4C, 1))
JFIELDS_UNLINK = ((0, 8), (8, 8), (0x20, 8), (0x28, 8), (0x30, 8), (0x38, 16), (0x48, 4), (0x4C, 1))


# ---------------------------------------------------------------------------------------------------------------------------------
# The rig: one machine per binary variant, stubs for the edges the functions call out to.
# ---------------------------------------------------------------------------------------------------------------------------------

class Rig:
    def __init__(self, image, name, va, kind, patches=None):
        self.image, self.name, self.va, self.kind = image, name, va, kind
        self.m = Machine(image, patches)
        self.sites = {}
        self.jelem = JELEM[name]
        self.events = []
        self.bump = 0
        self.panic_label = {}
        self.install()

    def install(self):
        m = self.m
        fake = 0x7F000000
        hooks = {}
        for slot in (REPORT_SLOT, MEMCPY_SLOT, PANIC_LOC_SLOT) + PANIC_FMT_SLOTS + GROW_SLOTS:
            fake += 0x10
            m.memory.statics[slot] = fake
            hooks[slot] = fake
        for row in static_rows(self.image, self.va)[2]:
            pass
        sites = {s[0]: s for s in site_table(self.image, self.va)}
        reports = sorted(v for v, s in sites.items() if s[2] == REPORT_SLOT)
        locs = sorted(v for v, s in sites.items() if s[2] == PANIC_LOC_SLOT)
        fmts = sorted(v for v, s in sites.items() if s[2] in PANIC_FMT_SLOTS)
        names_report = {"insert": ("total-add", "level-add"), "unlink": ("total-sub",)}[self.kind]
        names_loc = {"insert": ("prev-slot-missing", "next-slot-missing"), "unlink": ("unlink-ends",)}[self.kind]
        self.label = {}
        for v, n in zip(reports, names_report):
            self.label[v] = "report:" + n
        for v, n in zip(locs, names_loc):
            self.label[v] = "loc:" + n
        self.label.update({fmts[0]: "fmt:slab-next-beyond-len"} if self.kind == "insert" else {})
        if self.kind == "unlink":
            self.label[fmts[0]] = "str:negative-key"
        self.unlink_locs = locs
        relative = self.image.relative()
        self.unlink_leas = [r.b[4] & M64 for r in static_rows(self.image, self.va)[2]
                            if r.op == "lea" and r.a == ("r", RDI) and r.b[0] == "m" and r.b[1] is None and (r.b[4] & M64) in relative]
        self.sites = sites

        def memcpy(mc):
            mc.memory.copy(mc.regs[RDI], mc.regs[RSI], mc.regs[RDX])

        def report(mc):
            self.events.append(self.label[mc.call_site])

        def panic(mc):
            label = self.label.get(mc.call_site)
            if self.kind == "unlink" and mc.call_site in self.unlink_locs:
                label = "loc:unlink-prev-missing" if mc.regs[RDI] == self.unlink_leas[0] else "loc:unlink-next-missing"
            raise Panicked(label)

        def grow_for(elem, kind):
            def grow(mc):
                vec = mc.regs[RDI]
                cap, ptr, length = (mc.memory.read(vec + k, 8) for k in (0, 8, 0x10))
                new_cap = max(2 * cap, 4)
                dst = H + ARENA_AT + self.bump
                self.bump += (new_cap * elem + 15) & ~15
                mc.memory.copy(dst, ptr, length * elem)
                mc.memory.write(vec, 8, new_cap)
                mc.memory.write(vec + 8, 8, dst)
                self.events.append("grow:" + kind)
            return grow

        self.slots = {hooks[MEMCPY_SLOT]: memcpy, hooks[REPORT_SLOT]: report, hooks[PANIC_LOC_SLOT]: panic}
        for s in PANIC_FMT_SLOTS:
            self.slots[hooks[s]] = panic
        # which grow slot belongs to the journal and which to the slab is read from the instruction that precedes the call
        start, end, rows = static_rows(self.image, self.va)
        slab_call, journal_call = None, None
        for row in rows:
            if row.op == "calli" and row.a[0] == "m" and row.a[4] in GROW_SLOTS:
                reg_before = None
        by_site = {}
        for row in rows:
            if row.op == "calli" and row.a[0] == "m" and row.a[4] in GROW_SLOTS:
                by_site[row.va] = row.a[4]
        self.grow_site = by_site
        for slot in GROW_SLOTS:
            hook_kind = self.grow_kind(slot, rows)
            if hook_kind:
                self.slots[hooks[slot]] = grow_for(ENT if hook_kind == "slab" else self.jelem, hook_kind)
        m.slots = self.slots
        m.calls = {t: self.tree_stub for t in BTREE_CALLEES}

    def grow_kind(self, slot, rows):
        """The slab grow call is the one whose rdi is loaded from the slab argument; classify by the mov that feeds rdi."""
        for i, row in enumerate(rows):
            if row.op == "calli" and row.a[0] == "m" and row.a[4] == slot:
                for back in reversed(rows[max(0, i - 4):i]):
                    if back.op == "mov" and back.a == ("r", RDI):
                        return self.rdi_owner(back, rows)
        return None

    def rdi_owner(self, back, rows):
        src = back.b[1]
        start = rows[0].va
        # r12 / r14 hold the journal / slab pointers; decided from the prologue moves of the arguments
        return self.arg_roles()[src]

    def arg_roles(self):
        """Register that receives the slab (rsi for unlink, rdi for insert) and the journal (rcx for insert, r8 for unlink)."""
        start, end, rows = static_rows(self.image, self.va)
        want = {"insert": {RDI: "slab", RCX: "journal"}, "unlink": {RSI: "slab", R8: "journal"}}[self.kind]
        roles = {}
        for row in rows[:20]:
            if row.op == "mov" and row.a[0] == "r" and row.b[0] == "r" and row.b[1] in want:
                roles[row.a[1]] = want[row.b[1]]
        return roles

    def tree_stub(self, mc):
        ptr = mc.regs[RSI]
        self.events.append("tree:%x:%x:%x" % (mc.regs[RDI], mc.memory.read(ptr, 8), mc.memory.read(ptr + 8, 4)))

    def run(self, c, record=False):
        mc = self.m
        mc.memory.reset(SIZE)
        w = build_world(c)
        mc.memory.heap[0:SIZE] = w
        self.events = []
        self.bump = 0
        if record:
            mc.seen = set()
        panic = None
        ret = None
        try:
            if self.kind == "insert":
                regs = {RDI: H + OFF_S, RSI: H + OFF_O, RDX: c["A"], RCX: H + OFF_J, R8: H + OFF_T, R9: H + OFF_L}
                ret = mc.run(self.va, regs, (c["tag"], c["idx"]))
            else:
                regs = {RDI: H + OFF_OUT, RSI: H + OFF_S, RDX: c["idx"], RCX: c["A"], R8: H + OFF_J, R9: H + OFF_T}
                mc.run(self.va, regs, (H + OFF_L if c["level"] else 0,))
                ret = None
        except Panicked as exc:
            panic = exc.args[0]
        return panic, list(self.events), bytes(mc.memory.heap[0:SIZE]), ret


def spec_run(c, kind, name, flaw=""):
    buf = bytearray(build_world(c))
    ev = []
    info = {"mask": [], "kind": kind, "copy": name}
    panic = None
    ret = None
    try:
        if kind == "insert":
            ret = spec_insert(buf, ev, info, c["A"], c["tag"], c["idx"], flaw)
        else:
            ret = spec_unlink(buf, ev, info, c["A"], c["idx"], c["level"], flaw)
    except SpecPanic as exc:
        panic = exc.args[0]
    return panic, ev, bytes(buf), ret, info


# ---------------------------------------------------------------------------------------------------------------------------------
# Case generation
# ---------------------------------------------------------------------------------------------------------------------------------

def junk_kind(rng, base):
    """A link-kind word; one time in eight it carries high garbage, which the byte/dword/qword tests treat differently."""
    r = rng.below(16)
    if r == 0:
        return base | (1 << 32)
    if r == 1:
        return base | (1 << 63)
    return base


def big_or_small(rng, small=1000):
    r = rng.below(8)
    if r == 0:
        return M64 if rng.below(3) == 0 else M64 - rng.below(40)
    if r == 1:
        return (1 << 63) + rng.below(100)
    return rng.below(small)


def make_entry(rng, prev, nxt, price=None, size=None):
    raw = bytearray(rng.raw(ENT))
    setq(raw, 0, junk_kind(rng, 0 if prev is None else 1))
    setq(raw, 8, rng.below(10) if prev is None else prev)
    setq(raw, 0x10, junk_kind(rng, 0 if nxt is None else 1))
    setq(raw, 0x18, rng.below(10) if nxt is None else nxt)
    setq(raw, 0xB0, price if price is not None else (rng.below(100000) if rng.below(24) else (1 << 63) | rng.below(50)))
    raw[0xD8] = rng.pick((0, 0, 1, 1, 2, 0x80))
    setq(raw, 0xE0, size if size is not None else big_or_small(rng))
    return bytes(raw)


def make_vacant(rng, nxt):
    raw = bytearray(rng.raw(ENT))
    setq(raw, 0, 2 if rng.below(6) else 2 | (1 << 32))
    setq(raw, 8, nxt)
    return bytes(raw)


def gen_world(rng, jelem, kind):
    slen = rng.below(9)
    vac_p = rng.pick((0, 3, 3, 5))
    vacant = [i for i in range(slen) if rng.below(8) < vac_p]
    live = [i for i in range(slen) if i not in vacant]
    order = list(live)
    for i in range(len(order) - 1, 0, -1):
        j = rng.below(i + 1)
        order[i], order[j] = order[j], order[i]
    consistent = rng.below(6) != 0
    ents = [None] * slen
    for pos, i in enumerate(order):
        prev = order[pos - 1] if pos else None
        nxt = order[pos + 1] if pos + 1 < len(order) else None
        if not consistent:
            prev = rng.pick(live) if live and rng.below(3) == 0 else prev
            nxt = rng.pick(live) if live and rng.below(3) == 0 else nxt
        ents[i] = make_entry(rng, prev, nxt)
    free = list(vacant)
    for pos, i in enumerate(free):
        ents[i] = make_vacant(rng, free[pos + 1] if pos + 1 < len(free) else slen)
    nxt_free = free[0] if free else slen
    scenario = rng.below(12)
    if scenario == 0:
        nxt_free = slen + 1 + rng.below(3)
    elif scenario == 1 and live:
        nxt_free = rng.pick(live)
    elif scenario == 2:
        nxt_free = slen
    L = bytearray(rng.raw(0x80))
    head, tail = (order[0], order[-1]) if order else (None, None)
    setq(L, 0, junk_kind(rng, 0 if head is None else 1))
    setq(L, 8, head if head is not None else rng.below(10))
    setq(L, 0x10, junk_kind(rng, 0 if tail is None else 1))
    setq(L, 0x18, tail if tail is not None else rng.below(10))
    if not consistent and rng.below(3) == 0:
        setq(L, 0, rng.below(2))
        setq(L, 0x10, rng.below(2))
    setq(L, 0x20, junk_kind(rng, rng.below(2)))
    setq(L, 0x28, rng.pick(live) if live and rng.below(2) else rng.below(10))
    setq(L, 0x70, big_or_small(rng, 5000))
    setq(L, 0x78, big_or_small(rng, 20))
    jlen = rng.below(5)
    jents = [rng.raw(jelem) for _ in range(jlen)]
    jcap = jlen if rng.below(3) == 0 else jlen + 1 + rng.below(3)
    scap = slen if rng.below(3) == 0 else slen + 1 + rng.below(3)
    return {"scap": scap, "ents": ents, "count": big_or_small(rng, 12), "nxt": nxt_free, "jcap": jcap, "jents": jents, "jelem": jelem,
            "T": big_or_small(rng, 20000), "L": bytes(L), "live": live, "vacant": vacant, "slen": slen, "A": rng.next()}


def gen_insert(rng, jelem):
    c = gen_world(rng, jelem, "insert")
    O = bytearray(rng.raw(ENT))
    setq(O, 0xE0, big_or_small(rng, 3000))
    c["O"] = bytes(O)
    r = rng.below(16)
    live, slen = c["live"], c["slen"]
    if r < 8 and live:
        c["tag"], c["idx"] = 1, rng.pick(live)
    elif r == 8 and c["vacant"]:
        c["tag"], c["idx"] = 1, rng.pick(c["vacant"])
    elif r == 9:
        c["tag"], c["idx"] = 1, slen + rng.below(3)
    elif r == 10:
        c["tag"], c["idx"] = 1, M64 - rng.below(3)
    elif r == 11:
        c["tag"], c["idx"] = 1 | (1 << 32), rng.below(slen + 1)
    elif r == 15 and live:
        victim = rng.pick(live)
        raw = bytearray(c["ents"][victim])
        setq(raw, 0, 2 | (1 << 32))
        c["ents"][victim] = bytes(raw)
        c["tag"], c["idx"] = 1, victim
    else:
        c["tag"], c["idx"] = rng.pick((0, 2, 3, 0x100, 1 << 63, 0)), rng.below(slen + 1)
    c["kind"] = "insert"
    return c


def gen_unlink(rng, jelem):
    c = gen_world(rng, jelem, "unlink")
    c["O"] = bytes(ENT)
    live, slen = c["live"], c["slen"]
    r = rng.below(16)
    if r < 12 and live:
        c["idx"] = rng.pick(live)
        L = bytearray(c["L"])
        if rng.below(3) == 0:
            setq(L, 0x20, 1)
            setq(L, 0x28, c["idx"])
        c["L"] = bytes(L)
    elif r == 12 and c["vacant"]:
        c["idx"] = rng.pick(c["vacant"])
    elif r == 13:
        c["idx"] = slen + rng.below(3)
    elif r == 14:
        c["idx"] = M64 - rng.below(3)
    else:
        c["idx"] = rng.below(slen + 1)
    c["level"] = rng.below(8) != 0
    c["kind"] = "unlink"
    return c


def case_digest(c):
    h = hashlib.sha256()
    for key in sorted(c):
        if key in ("live", "vacant", "slen"):
            continue
        value = c[key]
        if isinstance(value, list):
            value = b"".join(v if isinstance(v, bytes) else repr(v).encode() for v in value)
        h.update(key.encode() + (value if isinstance(value, bytes) else repr(value).encode()))
    return h.hexdigest()[:12]


# ---------------------------------------------------------------------------------------------------------------------------------
# Replay and compare
# ---------------------------------------------------------------------------------------------------------------------------------

def expected(c, kind, name, flaw=""):
    panic, ev, buf, ret, info = spec_run(c, kind, name, flaw)
    jf = JFIELDS if kind == "insert" else JFIELDS_UNLINK
    return panic, ev, snapshot_with(buf, info, JELEM[name], jf, kind, c), ret, info


def snapshot_with(buf, info, jelem, jfields, kind, c):
    global JFIELDS
    saved = JFIELDS
    JFIELDS = jfields
    try:
        info["kind"] = kind
        return snapshot(buf, info, jelem)
    finally:
        JFIELDS = saved


def outcome_class(kind, c, panic, info, ret):
    if panic:
        return panic
    if kind == "insert":
        how = "push" if c["nxt"] == len(c["ents"]) else "reuse"
        where = "before" if c["tag"] == 1 and c["idx"] < len(c["ents"]) and not (q(c["ents"][c["idx"]], 0) == 2) else "tail"
        return "%s-%s" % (how, where)
    if info.get("none"):
        return "absent"
    return "removed-flag%d" % (ret or 0) if c["level"] else "removed-nolevel"


def compare(rig, c, exp):
    """True when the real bytes, run on the case, agree with the reconstruction on panic, events and observable state."""
    panic, ev, snap, ret, info = exp
    got_panic, got_ev, heap, got_ret = rig.run(c)
    if got_panic != panic or got_ev != ev:
        return False
    real = snapshot_with(bytearray(heap), info, rig.jelem, JFIELDS if rig.kind == "insert" else JFIELDS_UNLINK, rig.kind, c)
    if real != snap:
        return False
    if rig.kind == "insert" and not panic and got_ret != ret:
        return False
    return True


# ---------------------------------------------------------------------------------------------------------------------------------
# Negative controls on the real bytes: patches that keep the instruction length and still decode.
# ---------------------------------------------------------------------------------------------------------------------------------

def imm_width(row):
    value = row.b[1] & M64
    for size in (1, 2, 4, 8):
        if len(row.data) > size and row.data[-size:] == (value & ((1 << (8 * size)) - 1)).to_bytes(size, "little"):
            return size
    return 0


def mutant_list(image, va, limit_imm=14, limit_disp=24):
    """(label, va, patch dict) for jcc flips, immediate bit flips and displacement bit flips of one function."""
    start, end, rows = static_rows(image, va)
    jcc, imm, disp = [], [], []
    for row in rows:
        data = row.data
        if row.op == "jcc":
            at = 0 if data[0] != 0x0F else 1
            jcc.append(("jcc-flip", row.va, {row.va + at: data[at] ^ 1}))
        elif row.op in ("cmp", "mov", "test") and isinstance(row.b, tuple) and row.b and row.b[0] == "i" and row.a[0] in ("r", "m") and row.b[1] not in (0,):
            size = imm_width(row)
            if size in (1, 4):
                at = len(data) - size
                imm.append(("imm-bit0", row.va, {row.va + at: data[at] ^ 1}))
        for operand in (row.a, row.b):
            if isinstance(operand, tuple) and operand and operand[0] == "m" and operand[1] not in (None, RSP) and 8 <= abs(operand[4]) < 0x200:
                value = operand[4]
                size = 1 if -128 <= value < 128 else 4
                raw = (value & ((1 << (8 * size)) - 1)).to_bytes(size, "little")
                hits = [p for p in range(1, len(data) - size + 1) if data[p:p + size] == raw]
                if len(hits) == 1:
                    p = hits[0]
                    disp.append(("disp-bit3", row.va, {row.va + p: data[p] ^ 8}))
                break
    def spread(items, limit):
        if len(items) <= limit:
            return items
        return [items[i * len(items) // limit] for i in range(limit)]
    return jcc + spread(imm, limit_imm) + spread(disp, limit_disp)


# ---------------------------------------------------------------------------------------------------------------------------------
# The run: baseline cases, flaw controls, byte controls.
# ---------------------------------------------------------------------------------------------------------------------------------

PER_COPY = 1800
SAMPLE_EVERY = 7


def jfields_for(kind):
    return JFIELDS if kind == "insert" else JFIELDS_UNLINK


def real_snapshot(rig, heap, info, c):
    return snapshot_with(bytearray(heap), info, rig.jelem, jfields_for(rig.kind), rig.kind, c)


def run_all(image, per_copy=PER_COPY, byte_controls=True):
    for name, va, kind in COPIES:
        JELEM[name] = journal_elem(image, va)
    results = {"copies": [], "cases": 0, "digest": hashlib.sha256(), "flaws": [], "mutants": [], "samples": [], "outcomes": []}
    for name, va, kind in COPIES:
        rig = Rig(image, name, va, kind)
        rng = Rng(sum(map(ord, name)))
        gen = gen_insert if kind == "insert" else gen_unlink
        cases, exps, reals = [], [], []
        reach = {}
        classes = {}
        bad = 0
        for n in range(per_copy):
            c = gen(rng, JELEM[name])
            exp = expected(c, kind, name)
            rig.m.seen = set()
            panic, ev, heap, ret = rig.run(c)
            real = (panic, ev, real_snapshot(rig, heap, exp[4], c), ret if kind == "insert" and not panic else exp[3])
            ok = real[0] == exp[0] and real[1] == exp[1] and real[2] == exp[2] and real[3] == exp[3]
            if not ok:
                bad += 1
            for pc in rig.m.seen:
                reach.setdefault(pc, []).append(n)
            cls = outcome_class(kind, c, exp[0], exp[4], exp[3])
            classes[cls] = classes.get(cls, 0) + 1
            snap_hash = hashlib.sha256(repr((exp[0], exp[1], exp[2], exp[3])).encode()).hexdigest()[:10]
            results["digest"].update((name + str(n) + case_digest(c) + cls + snap_hash).encode())
            if n % SAMPLE_EVERY == 0:
                results["samples"].append((name, n, case_digest(c), cls, ",".join(exp[1]) or "-", snap_hash, "match" if ok else "DIFF"))
            cases.append(c)
            exps.append(exp)
            reals.append(real)
        results["cases"] += per_copy
        results["copies"].append({"name": name, "va": va, "kind": kind, "cases": per_copy, "mismatches": bad, "covered": len(reach)})
        for cls, count in sorted(classes.items()):
            results["outcomes"].append((name, cls, count))
        flaws = INSERT_FLAWS if kind == "insert" else UNLINK_FLAWS
        for flaw in flaws:
            first = None
            for n, c in enumerate(cases):
                alt = expected(c, kind, name, flaw)
                r = reals[n]
                if alt[0] != r[0] or alt[1] != r[1] or alt[2] != r[2] or (kind == "insert" and not r[0] and alt[3] != r[3]):
                    first = n
                    break
            results["flaws"].append((name, flaw, first))
        if byte_controls:
            for label, mva, patch in mutant_list(image, va):
                hit = reach.get(mva)
                if not hit:
                    results["mutants"].append((name, label, mva, "unreached", None))
                    continue
                mut = Rig(image, name, va, kind, patch)
                verdict, first = "survived", None
                for n in hit:
                    try:
                        got = mut.run(cases[n])
                        snap = real_snapshot(mut, got[2], exps[n][4], cases[n])
                        same = got[0] == exps[n][0] and got[1] == exps[n][1] and snap == exps[n][2]
                        if kind == "insert" and not got[0] and got[3] != exps[n][3]:
                            same = False
                    except (Halt, EvidenceError, Panicked, KeyError, IndexError, ValueError, OverflowError):
                        same, verdict = False, "crash"
                    if not same:
                        first = n
                        if verdict != "crash":
                            verdict = "mismatch"
                        break
                results["mutants"].append((name, label, mva, verdict, first))
    return results


def write_outputs(image, results, out):
    out = pathlib.Path(out)
    out.mkdir(parents=True, exist_ok=True)
    for old in out.iterdir():
        if old.is_file() and old.name not in ("README.md", "MANIFEST.sha256"):
            old.unlink()

    def tsv(name, header, rows):
        with open(out / name, "w", newline="\n") as handle:
            handle.write("\t".join(header) + "\n")
            for row in rows:
                handle.write("\t".join(str(x) for x in row) + "\n")

    fn_rows, site_rows, decode_rows = [], [], []
    for name, va, kind in COPIES:
        start, end, rows = static_rows(image, va)
        fn_rows.append((name, "%#x" % start, "%#x" % end, end - start, len(rows), "%#x" % JELEM[name], "0x110"))
        for site in site_table(image, va):
            loc = site[3]
            site_rows.append((name, "%#x" % site[0], site[1], "%#x" % site[2] if site[2] else "-", "%s:%d" % (loc[0], loc[1]) if loc else "-"))
        relative = image.relative()
        for row in rows:
            decode_rows.append((name, "%#x" % row.va, row.size, row.op, row.data.hex()))
            if kind == "unlink" and row.op == "lea" and row.a == ("r", RDI) and row.b[0] == "m" and row.b[1] is None and (row.b[4] & M64) in relative:
                loc = image.location(row.b[4] & M64, relative)
                site_rows.append((name, "%#x" % row.va, "lea-rdi", "%#x" % (row.b[4] & M64), "%s:%d" % (loc[0], loc[1])))
    tsv("functions.tsv", ("copy", "start", "end", "bytes", "instructions", "journal_record_bytes", "slab_entry_bytes"), fn_rows)
    tsv("sites.tsv", ("copy", "site", "kind", "slot_or_target", "location"), site_rows)
    tsv("decode.tsv", ("copy", "va", "size", "op", "bytes"), decode_rows)
    tsv("cases-sample.tsv", ("copy", "case", "digest", "outcome", "events", "state_hash", "vs_reconstruction"), results["samples"])
    tsv("outcomes.tsv", ("copy", "outcome", "cases"), results["outcomes"])
    controls = []
    equivalent = []
    for name, flaw, first in results["flaws"]:
        controls.append((name, "reconstruction-flaw", flaw, "-", "detected" if first is not None else "SURVIVED", first if first is not None else "-"))
    for name, label, mva, verdict, first in results["mutants"]:
        if verdict == "unreached":
            continue
        controls.append((name, "byte-" + label, "%#x" % mva, "-", "detected" if verdict in ("mismatch", "crash") else "SURVIVED",
                         ("%s:case-%s" % (verdict, first)) if first is not None else "-"))
    tsv("controls.tsv", ("copy", "kind", "target", "note", "result", "first_case"), controls)
    unreached = [(n, l, "%#x" % v) for n, l, v, vd, f in results["mutants"] if vd == "unreached"]
    tsv("unreached-mutants.tsv", ("copy", "kind", "va"), unreached)
    survived = [c for c in controls if c[4] == "SURVIVED"]
    entry_of = {name: va for name, va, kind in COPIES}
    eq_rows = []
    for c in survived:
        reason = equivalence_reason(image, entry_of[c[0]], c[1][len("byte-"):], int(c[2], 16)) if c[1].startswith("byte-") else None
        if reason:
            eq_rows.append((c[0], c[1], c[2], reason))
    equal_keys = {(r[0], r[1], r[2]) for r in eq_rows}
    survived = [c for c in survived if (c[0], c[1], c[2]) not in equal_keys]
    tsv("equivalent-mutants.tsv", ("copy", "mutation", "address", "same_because"), eq_rows)
    detected = sum(1 for c in controls if c[4] == "detected")
    measure = {"cases": results["cases"], "negative_controls": len(controls), "negative_detected": detected, "equivalent": len(eq_rows),
               "unreached_mutants": len(unreached), "mismatches": sum(c["mismatches"] for c in results["copies"])}
    summary = {"run_digest": results["digest"].hexdigest(), "copies": results["copies"], "binary_sha256": SHA256}
    with open(out / "measure.json", "w", newline="\n") as handle:
        json.dump(measure, handle, indent=1, sort_keys=True)
        handle.write("\n")
    with open(out / "results.json", "w", newline="\n") as handle:
        json.dump(summary, handle, indent=1, sort_keys=True)
        handle.write("\n")
    return measure, survived


def equivalence_reason(image, va, label, mva):
    """Static proof that a surviving byte mutation cannot change any compared byte, or None when the shape is not recognised."""
    start, end, rows = static_rows(image, va)
    at = {r.va: i for i, r in enumerate(rows)}[mva]
    row = rows[at]
    if label == "imm-bit0" and row.op == "mov" and row.a == ("r", RDX) and any(r.op == "calli" for r in rows[at + 1:at + 6]):
        return "copy length one byte longer: the extra byte lands in frame scratch, in the slot after the compared record, or is overwritten by the next store"
    if label == "disp-bit3" and row.op == "lea" and rows[at + 1].op == "mov" and rows[at + 1].a[0] == "m" and rows[at + 1].a[1] == RSP:
        slot = rows[at + 1].a[4]
        last_ret = max(r.va for r in rows if r.op == "ret")
        reads = [r.va for r in rows[at + 2:] if r.op == "mov" and r.b and r.b[0] == "m" and r.b[1] == RSP and r.b[4] == slot]
        if reads and all(v > last_ret for v in reads):
            return "frame slot is read only after the last ret (unwind landing pad), so the stored address is dead on every replayed path"
    return None


def main(argv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument("--out", required=True)
    parser.add_argument("--quick", type=int, default=0)
    args = parser.parse_args(argv)
    image = load_image_checked()
    results = run_all(image, args.quick or PER_COPY)
    measure, survived = write_outputs(image, results, args.out)
    print(json.dumps(measure, sort_keys=True))
    for row in survived:
        print("SURVIVED", row)
    return 0


if __name__ == "__main__":
    sys.exit(main())
