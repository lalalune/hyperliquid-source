#!/usr/bin/env python3
"""Reconstruct the node #115 action dispatcher at 0x50d3530 and run its real bytes against a pure model.

The dispatcher takes an action enum (tag word with a 2^63 niche), a context pointer and a result slot, and has seven
arms chosen by the jump table at 0x91a328. This tool

  * decodes the table, the callee slots (relocation addends) and the byte patterns of every constant the arms use;
  * models each arm as a pure function over memory, with every callee served by a scripted host that logs its
    arguments, and compares status, the 0x70-byte result, the touched records and the callee call log with the
    interpreted bytes for every generated case;
  * runs the bytes of 0x5acc8c0 (asset id vector), 0x446af70 / 0x446b070 (dex search by name) and 0x446b3f0 (dex
    indexing) as real code in a composed mode and compares them with their own pure models;
  * damages the bytes (condition flips, immediates, displacements, shifts) and requires the comparison to notice.

The interpreter below (ELF/FDE views, decoder, Memory, Machine) only reads ELF bytes; nothing is executed natively.

    python3 tools/re004_action_dispatch_115.py --out research/work-items/RE-004-action-dispatch-115
"""

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
# Action dispatcher 0x50d3530 (node #115): flow reconstruction, pure model, emulator comparison, mutation controls.
# ======================================================================================================================

import argparse
import collections
import json

DISPATCH = 0x50D3530
DISPATCH_END = 0x50D3F39
VEC_BUILDER = 0x5ACC8C0
TABLE = 0x91A328
NICHE = 1 << 63
U64 = MASK[8]
OK = 0x1A2
H = HEAP_BASE
OUT, CTX, ACT, STR, REC, VOUT, VARGS, ARENA = (H + 0x1000, H + 0x2000, H + 0x4000, H + 0x5000, H + 0x6000,
                                               H + 0x7000, H + 0x7100, H + 0x8000)
USED = 0x10000
REC_LEN = 0x500
ERR_CODES = (0x156, 0x158, 0xFA, 0x1A1, 0x10, 0x2D, 0x35, 0x77, 0x1A3, 0x0, 0x1FF)

# Slot addresses in .data.rel.ro; their relocation addends are the callee entry points.
SLOTS = {
    "uni_lookup_a": 0x64E6A68, "asset_idx": 0x64E69B8, "name_check": 0x64E4E58, "uni_lookup_b": 0x64E6C18,
    "flag_probe": 0x64E6C20, "ts_div": 0x64E6AD8, "apply_flag": 0x64E6C28, "memcpy": 0x64DF508,
    "dealloc": 0x64DF4A0, "alloc": 0x64DF480, "handle_error": 0x64DF498, "mul_ovf": 0x64DF870, "add_ovf": 0x64DF520,
    "memcmp": 0x64DF9F8, "unwrap_failed": 0x64DF6A0,
}
CALLS = {
    "find": 0x43CD290, "lookup_c": 0x55BD550, "map_entry": 0x4DD59A0, "exec": 0x5397B50,
    "zero_addr_apply": 0x55D1FF0, "indexed_apply": 0x55C1580, "reg": 0x54C9C70, "drop": 0x50F1840,
    "drop_err": 0x44E0810,
}
DEX_BY_NAME_A, DEX_BY_NAME_B, DEX_AT = 0x446AF70, 0x446B070, 0x446B3F0
UNI, NAMES, NAME_BYTES = H + 0xA000, H + 0xD000, H + 0xD400
DEX_STRIDE = 0x510
UNI_LEN = 0x2800
NAME_POOL = (b"", b"xyz", b"abc", b"dex1", b"a", b"abcd", b"flx")
MAGIC10K = 0x346DC5D63886594B
FIND_BYTES = 0x3A0000003A


class ToolError(Exception):
    pass


class ModelPanic(Exception):
    pass


class Lcg:
    def __init__(self, seed):
        self.s = (seed * 2862933555777941757 + 3037000493) & U64

    def next(self):
        self.s = (self.s * 6364136223846793005 + 1442695040888963407) & U64
        return self.s >> 24

    def below(self, n):
        return self.next() % n

    def pick(self, items):
        return items[self.below(len(items))]

    def data(self, n):
        return bytes(self.next() & 255 for _ in range(n))

    def word(self):
        mode = self.below(6)
        if mode == 0:
            return self.next() | (self.next() << 40) & U64
        if mode == 1:
            return U64 - self.below(3)
        if mode == 2:
            return self.below(1000)
        if mode == 3:
            return (U64 >> 1) + self.below(3)
        if mode == 4:
            return self.pick((0, 1, 9999, 10000, 10001, 99999, 100000, 0x5F45A5F, 0x5F45A60, 0xFFFFFFFF, 1 << 32))
        return self.next() << 20 & U64


class Res:
    """A scripted callee answer: 0x70 raw bytes; code at 0, first payload word at 8, second at 0x10."""

    def __init__(self, raw):
        self.raw = bytes(raw)
        self.code = int.from_bytes(raw[0:2], "little")
        self.w1 = int.from_bytes(raw[8:16], "little")
        self.w2 = int.from_bytes(raw[16:24], "little")
        self.b8 = raw[8]


def gen_res(rng, ok_pct, w1=None, w2=None, b8=None):
    raw = bytearray(rng.data(0x70))
    if rng.below(100) < ok_pct:
        raw[0:2] = OK.to_bytes(2, "little")
        if w1 is not None:
            raw[8:16] = (w1 & U64).to_bytes(8, "little")
        if w2 is not None:
            raw[16:24] = (w2 & U64).to_bytes(8, "little")
        if b8 is not None:
            raw[8] = b8
    else:
        raw[0:2] = rng.pick(ERR_CODES).to_bytes(2, "little")
    return Res(raw)


class World:
    """Host side of every callee: records the call, serves the scripted answer. Machine hooks and model share it."""

    def __init__(self, script):
        self.script, self.log, self.count = script, [], collections.Counter()
        self.bump = ARENA

    def call(self, name, args):
        self.log.append((name,) + tuple(args))
        items = self.script.get(name)
        if not items:
            return None
        item = items[self.count[name] % len(items)]
        self.count[name] += 1
        return item

    def memcmp(self, a, b):
        self.log.append(("memcmp", a, b))
        return (a > b) - (a < b)

    def alloc(self, size):
        self.log.append(("alloc", size))
        if size > self.script.get("alloc_limit", 0x1000) or self.script.get("alloc_fail"):
            return 0
        at = self.bump
        self.bump += (size + 15) & ~15
        return at

    def panic(self, name, args):
        self.log.append((name,) + tuple(args))
        raise ModelPanic("%s%r" % (name, tuple(args)))


class Mem:
    def __init__(self, heap):
        self.b = heap

    def u(self, addr, size):
        at = addr - H
        return int.from_bytes(self.b[at:at + size], "little")

    def raw(self, addr, size):
        at = addr - H
        return bytes(self.b[at:at + size])

    def put(self, addr, data):
        at = addr - H
        self.b[at:at + len(data)] = data


# ------------------------------------------------------------------------------------------------ model

def slot_index(tag):
    """Jump-table index the prologue computes: tag - 2^63 - 13 when above 2^63 + 12, else 5."""
    return (tag - NICHE - 13) & U64 if tag > NICHE + 12 else 5


def vec_model(mem, w, rec, start, end):
    """0x5acc8c0: Vec<u64> of 10000 * record[0x50] + start + i for i in 0..(end - start); returns (cap, ptr, items)."""
    n = end - start if end >= start else 0
    size = (n * 8) & U64
    if n >> 61 or size > 0x7FFFFFFFFFFFFFF8:
        w.panic("handle_error", (0, size))
    ptr = 8
    if size:
        ptr = w.alloc(size)
        if ptr == 0:
            w.panic("handle_error", (8, size))
    items = []
    factor = mem.u(rec + 0x50, 8)
    for i in range(n):
        scaled = 10000 * factor
        if scaled > U64:
            w.panic("mul_ovf", (0x64AA638,))
        total = start + scaled + i
        if total > U64:
            w.panic("add_ovf", (0x64AA638,))
        items.append(total)
    return n, ptr, items


def asset_id(index):
    """Arm 0 mapping of a PDI index to the 32-bit id handed to the executor."""
    if index <= 9999:
        return index & 0xFFFFFFFF
    if index <= 0x5F45A5F:
        return (index + 100000) & 0xFFFFFFFF
    return 0xFFFFFFFF


def real_res(code, w1=None):
    raw = bytearray(bytes([STACK_MARK]) * 0x70)
    raw[0:2] = code.to_bytes(2, "little")
    if w1 is not None:
        raw[8:16] = w1.to_bytes(8, "little")
    return Res(raw)


def find_dex(mem, w, uni, ptr, ln):
    """0x446af70 / 0x446b070 (identical twins): first record of a Vec of 0x510-byte records, or a name search."""
    base, count = mem.u(uni + 8, 8), mem.u(uni + 16, 8)
    if ln == 0:
        if count == 0:
            w.panic("unwrap_failed", (0x2B, 0x156))
        w.call("drop_err", (0x156,))
        return real_res(OK, base)
    for i in range(count):
        rec = base + DEX_STRIDE * i
        if mem.u(rec + 0x378, 8) == NICHE:
            continue
        name = mem.u(rec + 0x4A0, 8)
        if mem.u(name + 0x10, 8) != ln:
            continue
        if w.memcmp(mem.raw(mem.u(name + 8, 8), ln), mem.raw(ptr, ln)) == 0:
            return real_res(OK, rec)
    return real_res(0x156)


def dex_at(mem, w, uni, index):
    """0x446b3f0: bounds-checked element address, Result::unwrap failure with Err(0x156) when out of range."""
    if index >= mem.u(uni + 16, 8):
        w.panic("unwrap_failed", (0x2B, 0x156))
    w.call("drop_err", (0x156,))
    return (mem.u(uni + 8, 8) + DEX_STRIDE * index) & U64


def dispatch(mem, action, ctx, w, out):
    """Pure reconstruction of 0x50d3530; mutates `out` (0x70 bytes) and mem (record byte), logs every callee call."""
    def free(cap, ptr):
        if cap:
            w.call("dealloc", (ptr, cap, 0))

    def err(res):
        out[0:0x70] = res.raw

    def code(value):
        out[0:2] = value.to_bytes(2, "little")

    arm = slot_index(mem.u(action, 8))
    if arm == 0:
        cap, ptr, ln = mem.u(action + 8, 8), mem.u(action + 16, 8), mem.u(action + 24, 8)
        if ln >= 0x65:
            free(cap, ptr)
            return code(0x158)
        found, start = w.call("find", (ptr, ln, 0, ln, FIND_BYTES, 1))
        if w.script.get("real"):
            res = find_dex(mem, w, ctx + 0x1330, ptr if found else 1, start if found else 0)
        else:
            res = w.call("uni_lookup_a", (ctx + 0x1330, ptr if found else 1, start if found else 0))
        if res.code != OK:
            err(res)
            return free(cap, ptr)
        res = w.call("asset_idx", (ptr, ln, res.w1))
        if res.code != OK:
            err(res)
            return free(cap, ptr)
        event = (0x35).to_bytes(8, "little") + asset_id(res.w1).to_bytes(4, "little") + b"\x01"
        err(w.call("exec", (ctx, event)))
        return free(cap, ptr)
    if arm == 1:
        event = (0x2D).to_bytes(8, "little") + mem.raw(action + 8, 21)
        return err(w.call("exec", (ctx, event)))
    if arm == 2:
        string = mem.raw(action + 8, 24)
        res = w.call("name_check", (string,))
        if res.code != OK:
            err(res)
            return free(mem.u(action + 8, 8), mem.u(action + 16, 8))
        w.call("map_entry", (ctx + 0x338, string, action + 0x20))
        return code(OK)
    if arm == 3:
        cap, ptr, ln, flag = mem.u(action + 8, 8), mem.u(action + 16, 8), mem.u(action + 24, 8), mem.u(action + 32, 1)
        if ln >= 0x65:
            free(cap, ptr)
            return code(0x158)
        if w.script.get("real"):
            res = find_dex(mem, w, ctx + 0x1330, ptr, ln)
        else:
            res = w.call("uni_lookup_b", (ctx + 0x1330, ptr, ln))
        if res.code != OK:
            err(res)
            return free(cap, ptr)
        rec = res.w1
        if mem.u(rec + 0x378, 8) == NICHE:
            code(0x156)
            return free(cap, ptr)
        if flag == 0:
            mem.put(rec + 0x468, b"\x00")
        else:
            mem.put(rec + 0x468, b"\x02")
            vcap, vptr, items = vec_model(mem, w, rec, 0, mem.u(rec + 0x10, 8))
            for item in items:
                w.call("reg", (ctx, item))
            if vcap:
                w.call("dealloc", (vptr, vcap * 8, 0))
        code(OK)
        return free(cap, ptr)
    if arm == 4:
        string = mem.raw(action + 8, 24)
        cap, ptr, flag = mem.u(action + 8, 8), mem.u(action + 16, 8), mem.u(action + 32, 1)
        res = w.call("lookup_c", (ctx, string))
        if res.code != OK:
            err(res)
            return free(cap, ptr)
        rec, value = res.w1, res.w2
        if mem.u(rec + 0x378, 8) == NICHE:
            code(0x156)
            return free(cap, ptr)
        if mem.u(rec + 0x408, 8) != NICHE + 1:
            code(0x1A1)
            return free(cap, ptr)
        probe = w.call("flag_probe", (rec + 0x378, value)).b8
        need = probe == 2 if flag else probe != 2
        if need:
            quotient = (value * MAGIC10K >> 64) >> 11
            if w.script.get("real"):
                handle = dex_at(mem, w, ctx + 0x1330, quotient)
            else:
                handle = w.call("ts_div", (ctx + 0x1330, quotient))
            res = w.call("apply_flag", (handle, value, 1 if flag else 2))
            if res.code != OK:
                err(res)
                return free(cap, ptr)
        code(OK)
        return free(cap, ptr)
    if arm == 5:
        struct_bytes = mem.raw(action, 0xB0)
        w.call("memcpy", (0xB0,))
        res = w.call("zero_addr_apply", (ctx, bytes(20), struct_bytes))
        if res.code == OK:
            code(OK)
        else:
            err(res)
        w.call("drop", (struct_bytes,))
        return
    if arm == 6:
        index = mem.u(action + 8, 8)
        limit = mem.u(ctx + 0xB8, 8)
        if index >= limit:
            code(0xFA)
            out[8:16] = index.to_bytes(8, "little")
            return
        err(w.call("indexed_apply", (ctx, mem.raw(action + 8, 0x58))))
        return
    raise ToolError("tag outside the seven modelled arms")


# ------------------------------------------------------------------------------------------------ cases

def build_heap(case):
    heap = bytearray(bytes([STACK_MARK]) * USED)
    mem = Mem(heap)
    mem.put(CTX, bytes(0x1400))
    mem.put(CTX + 0xB8, case["limit"].to_bytes(8, "little"))
    mem.put(STR, case["string"].ljust(0x200, b"\x00"))
    mem.put(ACT, case["action"])
    mem.put(REC, case["record"])
    uni = case.get("universe")
    if uni is not None:
        mem.put(CTX + 0x1330, (0).to_bytes(8, "little") + UNI.to_bytes(8, "little") + len(uni).to_bytes(8, "little"))
        for i, (record, name) in enumerate(uni):
            at = UNI + DEX_STRIDE * i
            mem.put(at, record)
            mem.put(NAME_BYTES + 0x40 * i, name)
            mem.put(NAMES + 0x20 * i, (0).to_bytes(8, "little") + (NAME_BYTES + 0x40 * i).to_bytes(8, "little")
                    + len(name).to_bytes(8, "little"))
            mem.put(at + 0x4A0, (NAMES + 0x20 * i).to_bytes(8, "little"))
    return heap


def find_answer(string, ln):
    at = string[:ln].find(b":")
    return (1, at) if at >= 0 else (0, 0)


def make_case(arm, n):
    rng = Lcg(arm * 1000003 + n * 7919 + 17)
    case = {"arm": arm, "n": n, "limit": rng.pick((0, 1, 5, 10, 1000, U64)), "script": {}}
    rec = bytearray(rng.data(REC_LEN))
    count = rng.pick((0, 1, 2, 3, 5, 9, 17, 0, 1 << 61, (1 << 61) - 1, 600, 4000))
    if rng.below(100) < 80:
        count = rng.pick((0, 1, 2, 3, 5, 9, 17))
    factor = rng.pick((0, 1, 2, 9, 10, 77, 1844674407370955, 1844674407370956, U64, 123456789012, 1 << 40))
    rec[0x10:0x18] = count.to_bytes(8, "little")
    rec[0x50:0x58] = factor.to_bytes(8, "little")
    rec[0x378:0x380] = (NICHE if rng.below(100) < 15 else rng.next() & (NICHE - 1)).to_bytes(8, "little")
    rec[0x408:0x410] = (NICHE + 1 if rng.below(100) < 80 else rng.pick((NICHE, NICHE + 2, 0, U64))).to_bytes(8, "little")
    case["record"] = bytes(rec)
    ln = rng.pick((0, 1, 2, 7, 50, 98, 99, 100, 101, 102, 150, 0x1FF, 0x30, 0x12))
    string = bytearray(rng.data(0x200))
    for i in range(0x200):
        string[i] = 0x61 + string[i] % 26
    if rng.below(100) < 50 and ln:
        string[rng.below(ln)] = 0x3A
    case["string"] = bytes(string)
    cap = rng.pick((ln, ln, ln + 1, ln + 40, 0, 1 << 20))
    ptr = STR if rng.below(100) < 90 else STR + 3
    flag = rng.pick((0, 1, 2, 255, 0x80))
    tag = {0: NICHE + 13, 1: NICHE + 14, 2: NICHE + 15, 3: NICHE + 16, 4: NICHE + 17, 6: NICHE + 19}.get(arm)
    action = bytearray(rng.data(0x100))
    if arm == 5:
        tag = rng.pick((rng.next() & (NICHE - 1), 0, NICHE, NICHE + 5, NICHE + 12, NICHE + 18, 1 << 20))
    action[0:8] = tag.to_bytes(8, "little")
    if arm in (0, 2, 3, 4):
        action[8:32] = cap.to_bytes(8, "little") + ptr.to_bytes(8, "little") + ln.to_bytes(8, "little")
        action[32] = flag
    if arm == 6:
        action[8:16] = rng.pick((0, 1, 4, 5, 6, 9, 10, 11, U64, rng.below(12))).to_bytes(8, "little")
    case["action"] = bytes(action)
    s = case["script"]
    ok = rng.pick((60, 85, 95))
    index = rng.word()
    value = rng.word()
    s["find"] = [find_answer(case["string"], ln)]
    s["uni_lookup_a"] = [gen_res(rng, ok, w1=rng.next())]
    s["asset_idx"] = [gen_res(rng, ok, w1=index)]
    s["name_check"] = [gen_res(rng, ok)]
    s["uni_lookup_b"] = [gen_res(rng, ok, w1=REC)]
    s["lookup_c"] = [gen_res(rng, ok, w1=REC, w2=value)]
    s["flag_probe"] = [gen_res(rng, 100, b8=rng.pick((0, 1, 2, 3, 2)))]
    s["ts_div"] = [rng.word()]
    s["apply_flag"] = [gen_res(rng, ok)]
    for name in ("exec", "zero_addr_apply", "indexed_apply"):
        s[name] = [gen_res(rng, ok)]
    s["map_entry"] = [None]
    s["reg"] = [None]
    s["drop"] = [None]
    if arm == 3 and rng.below(100) < 6:
        s["alloc_fail"] = True
    case["origin"] = (arm, n)
    return case


def edge_cases():
    """Arm 0 index table around every threshold, arm 6 index around the bound, string length around 100."""
    rows = []
    for k, idx in enumerate((0, 1, 9998, 9999, 10000, 10001, 99999, 0x5F45A5E, 0x5F45A5F, 0x5F45A60, 0x5F45A61,
                             0xFFFFFFFF, 1 << 32, U64)):
        c = make_case(0, 7000 + k)
        c["script"]["uni_lookup_a"] = [gen_res(Lcg(k), 100, w1=1)]
        c["script"]["asset_idx"] = [gen_res(Lcg(k + 50), 100, w1=idx)]
        c["action"] = bytes(c["action"][:24]) + (5).to_bytes(8, "little") + c["action"][32:]
        c["script"]["find"] = [find_answer(c["string"], 5)]
        rows.append(c)
    for k, value in enumerate((0, 9999, 10000, 10001, 19999, 20000, 123456789 * 10000, 10000 * 1844674407370955,
                               10000 * 1844674407370955 + 9999, U64, U64 - 1, 10000 * 99999 - 1, 10000 * 99999,
                               7 * 10000 + 3, 10000 * 1000003)):
        c = make_case(4, 8000 + k)
        rec = bytearray(c["record"])
        rec[0x378:0x380] = (5).to_bytes(8, "little")
        rec[0x408:0x410] = (NICHE + 1).to_bytes(8, "little")
        c["record"] = bytes(rec)
        action = bytearray(c["action"])
        action[32] = 1
        c["action"] = bytes(action)
        c["script"]["lookup_c"] = [gen_res(Lcg(k + 90), 100, w1=REC, w2=value)]
        c["script"]["flag_probe"] = [gen_res(Lcg(k), 100, b8=2)]
        c["script"]["apply_flag"] = [gen_res(Lcg(k + 7), 100)]
        rows.append(c)
    return rows


def make_real_case(arm, n):
    """Cases for the composed mode: dex lookup and dex indexing run as the real bytes over a record vector."""
    rng = Lcg(arm * 7000003 + n * 104729 + 5)
    case = make_case(arm, n + 100000)
    case["script"]["real"] = True
    count = rng.pick((0, 1, 2, 3, 4, 5, 5))
    uni = []
    for i in range(count):
        rec = bytearray(rng.data(DEX_STRIDE))
        rec[0x378:0x380] = (NICHE if rng.below(100) < 25 else rng.next() & (NICHE - 1)).to_bytes(8, "little")
        rec[0x10:0x18] = rng.pick((0, 1, 2, 3, 6)).to_bytes(8, "little")
        rec[0x50:0x58] = rng.pick((0, 1, 3, 10)).to_bytes(8, "little")
        rec[0x408:0x410] = (NICHE + 1 if rng.below(100) < 80 else 0).to_bytes(8, "little")
        uni.append((bytes(rec), rng.pick(NAME_POOL)))
    case["universe"] = uni
    string = bytearray(case["string"])
    name = rng.pick(NAME_POOL) if rng.below(100) < 85 else rng.data(rng.below(5))
    if arm == 0:
        text = name + (b":COIN" if rng.below(100) < 70 else b"")
    else:
        text = name
    string[:len(text)] = text
    ln = len(text)
    case["string"] = bytes(string)
    action = bytearray(case["action"])
    cap = rng.pick((ln, ln + 1, 0))
    action[8:32] = cap.to_bytes(8, "little") + STR.to_bytes(8, "little") + ln.to_bytes(8, "little")
    case["action"] = bytes(action)
    case["script"]["find"] = [find_answer(case["string"], ln)]
    if arm == 4:
        case["script"]["lookup_c"] = [gen_res(rng, 90, w1=REC, w2=10000 * rng.below(max(count + 1, 1)) + rng.pick((0, 1, 9999)))]
        case["script"]["flag_probe"] = [gen_res(rng, 100, b8=rng.pick((0, 2, 2, 1)))]
        action = bytearray(case["action"])
        action[32] = rng.pick((0, 1, 1))
        case["action"] = bytes(action)
        rec = bytearray(case["record"])
        rec[0x378:0x380] = (5).to_bytes(8, "little")
        rec[0x408:0x410] = (NICHE + 1).to_bytes(8, "little")
        case["record"] = bytes(rec)
    case["origin"] = (arm, n + 100000)
    return case


# ------------------------------------------------------------------------------------------------ machine side

class Holder:
    world = None


def reg_args(m, *names):
    table = {"rdi": RDI, "rsi": RSI, "rdx": RDX, "rcx": RCX}
    return tuple(m.regs[table[n]] for n in names)


def build_machine(image, patches=None, real_lookups=False):
    holder = Holder()
    m = Machine(image, patches)
    rel = image.relative()
    marker = 0x7E000000
    values = {}
    for name, slot in SLOTS.items():
        marker += 1
        value = rel.get(slot, marker)
        m.memory.statics[slot] = value
        values[name] = value

    def write(m, at, data):
        m.memory.put_bytes(at, data)

    def out_hook(name, args):
        def hook(m):
            res = holder.world.call(name, args(m))
            write(m, m.regs[RDI], res.raw)
        return hook

    def bytes_at(m, reg, n):
        return m.memory.bytes_at(m.regs[reg], n)

    def find_hook(m):
        args = struct.unpack("<QQQQQB", bytes_at(m, RSI, 0x29))
        found, start = holder.world.call("find", args)
        write(m, m.regs[RDI], bytes([found]) + bytes(7) + start.to_bytes(8, "little"))

    def exec_hook(m):
        tag = m.memory.read(m.regs[RSI], 8)
        length = {0x2D: 29, 0x35: 13}.get(tag)
        if length is None:
            raise Halt("exec of an unknown event tag")
        res = holder.world.call("exec", (m.regs[RDX], bytes_at(m, RSI, length)))
        write(m, m.regs[RDI], res.raw)

    def map_hook(m):
        holder.world.call("map_entry", (m.regs[RSI], bytes_at(m, RDX, 24), m.regs[RCX]))

    def reg_hook(m):
        holder.world.call("reg", (m.regs[RDI], m.regs[RSI]))

    def drop_hook(m):
        holder.world.call("drop", (bytes_at(m, RDI, 0xB0),))

    def ret_hook(name, args):
        def hook(m):
            m.regs[RAX] = holder.world.call(name, args(m)) & U64
        return hook

    def dealloc_hook(m):
        holder.world.call("dealloc", (m.regs[RDI], m.regs[RSI], m.regs[RDX] & 0xFFFFFFFF))

    def alloc_hook(m):
        m.regs[RAX] = holder.world.alloc(m.regs[RDI])

    def memcpy_hook(m):
        holder.world.call("memcpy", (m.regs[RDX],))
        m.memory.copy(m.regs[RDI], m.regs[RSI], m.regs[RDX])
        m.regs[RAX] = m.regs[RDI]

    def panic_hook(name, args):
        def hook(m):
            try:
                holder.world.panic(name, args(m))
            except ModelPanic as exc:
                raise Panicked(str(exc))
        return hook

    r3 = lambda m: (m.regs[RSI], m.regs[RDX], m.regs[RCX])
    m.calls = {
        CALLS["find"]: find_hook,
        CALLS["lookup_c"]: out_hook("lookup_c", lambda m: (m.regs[RSI], bytes_at(m, RDX, 24))),
        CALLS["map_entry"]: map_hook,
        CALLS["exec"]: exec_hook,
        CALLS["zero_addr_apply"]: out_hook("zero_addr_apply", lambda m: (m.regs[RSI], bytes_at(m, RDX, 20), bytes_at(m, RCX, 0xB0))),
        CALLS["indexed_apply"]: out_hook("indexed_apply", lambda m: (m.regs[RSI], bytes_at(m, RDX, 0x58))),
        CALLS["reg"]: reg_hook,
        CALLS["drop"]: drop_hook,
    }
    m.slots = {
        values["uni_lookup_a"]: out_hook("uni_lookup_a", r3),
        values["asset_idx"]: out_hook("asset_idx", r3),
        values["name_check"]: out_hook("name_check", lambda m: (bytes_at(m, RSI, 24),)),
        values["uni_lookup_b"]: out_hook("uni_lookup_b", r3),
        values["flag_probe"]: out_hook("flag_probe", lambda m: (m.regs[RSI], m.regs[RDX])),
        values["ts_div"]: ret_hook("ts_div", lambda m: (m.regs[RDI], m.regs[RSI])),
        values["apply_flag"]: out_hook("apply_flag", lambda m: (m.regs[RSI], m.regs[RDX], m.regs[RCX] & 0xFFFFFFFF)),
        values["memcpy"]: memcpy_hook,
        values["dealloc"]: dealloc_hook,
        values["alloc"]: alloc_hook,
        values["handle_error"]: panic_hook("handle_error", lambda m: (m.regs[RDI], m.regs[RSI])),
        values["mul_ovf"]: panic_hook("mul_ovf", lambda m: (m.regs[RDI],)),
        values["add_ovf"]: panic_hook("add_ovf", lambda m: (m.regs[RDI],)),
    }
    def memcmp_hook(m):
        a, b = bytes_at(m, RDI, m.regs[RDX]), bytes_at(m, RSI, m.regs[RDX])
        m.regs[RAX] = holder.world.memcmp(a, b) & 0xFFFFFFFF

    def unwrap_hook(m):
        try:
            holder.world.panic("unwrap_failed", (m.regs[RSI], m.memory.read(m.regs[RDX], 2)))
        except ModelPanic as exc:
            raise Panicked(str(exc))

    m.slots[values["memcmp"]] = memcmp_hook
    m.slots[values["unwrap_failed"]] = unwrap_hook
    m.calls[CALLS["drop_err"]] = lambda m: holder.world.call("drop_err", (m.memory.read(m.regs[RDI], 2),))
    m.real = frozenset({VEC_BUILDER})
    if real_lookups:
        for name in ("uni_lookup_a", "uni_lookup_b", "ts_div"):
            del m.slots[values[name]]
        m.real = frozenset({VEC_BUILDER, DEX_BY_NAME_A, DEX_BY_NAME_B, DEX_AT})
    return m, holder


def run_machine(m, holder, case):
    holder.world = World(case["script"])
    heap = build_heap(case)
    m.memory.reset(USED)
    m.memory.heap[:USED] = heap
    m.seen_before = len(m.seen)
    status = "ok"
    try:
        m.run(DISPATCH, {RDI: OUT, RSI: ACT, RDX: CTX})
    except Panicked as exc:
        status = "panic:" + str(exc)
    out = bytes(m.memory.heap[OUT - H:OUT - H + 0x80])
    rec = bytes(m.memory.heap[REC - H:REC - H + REC_LEN]) + bytes(m.memory.heap[UNI - H:UNI - H + UNI_LEN])
    return status, out, rec, holder.world.log


def run_model(case):
    world = World(case["script"])
    heap = build_heap(case)
    mem = Mem(heap)
    out = bytearray(bytes([STACK_MARK]) * 0x80)
    status = "ok"
    try:
        dispatch(mem, ACT, CTX, world, out)
    except ModelPanic as exc:
        status = "panic:" + str(exc)
    return status, bytes(out), mem.raw(REC, REC_LEN) + mem.raw(UNI, UNI_LEN), world.log


def mem_out_preload(m):
    m.memory.heap[OUT - H:OUT - H + 0x80] = bytes([STACK_MARK]) * 0x80


def compare(m, holder, case):
    """Return None when machine and model agree on status, out bytes, record bytes and the callee call log."""
    try:
        mine = run_model(case)
        theirs = run_machine(m, holder, case)
    except (Halt, EvidenceError) as exc:
        return "halt: %s" % exc
    for label, a, b in zip(("status", "out", "record", "log"), mine, theirs):
        if a != b:
            return label
    return None


def digest_of(result):
    status, out, rec, log = result
    h = hashlib.sha256()
    h.update(status.encode())
    h.update(out)
    h.update(rec)
    h.update(repr(log).encode())
    return h.hexdigest()[:16]


# ------------------------------------------------------------------------------------------------ vec builder alone

def vec_case(n):
    rng = Lcg(900000 + n)
    factor = rng.pick((0, 1, 2, 9, 77, 1844674407370955, 1844674407370956, U64, 1 << 40, 5))
    start = rng.pick((0, 0, 1, 3, 100, U64 - 3, 1616, 1 << 62))
    span = rng.pick((0, 1, 2, 3, 5, 8, 20, 40, 1617, 1 << 61, (1 << 61) + 3))
    end = rng.pick((start + span & U64, start + span & U64, start, start - 1 & U64, 0, 7))
    return {"factor": factor, "start": start, "end": end, "alloc_fail": rng.below(100) < 5}


def vec_run(m, holder, case):
    heap = bytearray(bytes([STACK_MARK]) * USED)
    mem = Mem(heap)
    mem.put(REC + 0x50, case["factor"].to_bytes(8, "little"))
    # the builder takes a pointer to a block {record pointer, start, end}
    mem.put(VARGS, REC.to_bytes(8, "little") + case["start"].to_bytes(8, "little") + case["end"].to_bytes(8, "little"))
    world = World({"alloc_fail": case["alloc_fail"], "alloc_limit": 0x4000})
    holder.world = world
    m.memory.reset(USED)
    m.memory.heap[:USED] = heap
    try:
        m.run(VEC_BUILDER, {RDI: VOUT, RSI: VARGS})
    except Panicked as exc:
        return "panic:" + str(exc), None, world.log
    cap, ptr, ln = (m.memory.read(VOUT + 8 * i, 8) for i in range(3))
    items = tuple(m.memory.read(ptr + 8 * i, 8) for i in range(ln)) if ptr >= ARENA else ()
    return "ok", (cap, ptr, ln, items), world.log


def vec_expected(case):
    heap = bytearray(bytes([STACK_MARK]) * USED)
    mem = Mem(heap)
    mem.put(REC + 0x50, case["factor"].to_bytes(8, "little"))
    world = World({"alloc_fail": case["alloc_fail"], "alloc_limit": 0x4000})
    try:
        cap, ptr, items = vec_model(mem, world, REC, case["start"], case["end"])
    except ModelPanic as exc:
        return "panic:" + str(exc), None, world.log
    return "ok", (cap, ptr, len(items), tuple(items) if ptr >= ARENA else ()), world.log


def vec_compare(m, holder, case):
    try:
        return None if vec_expected(case) == vec_run(m, holder, case) else "vec"
    except Exception as exc:  # a damaged body may fail in any way; every failure is a detection
        return "halt: %s" % type(exc).__name__


# ------------------------------------------------------------------------------------------------ evidence

CASES_PER_ARM = 1500
VEC_CASES = 1500
SAMPLE_EVERY = 5
REAL_CASES = 1200
REAL_BATTERY = 30
VEC_SAMPLE_EVERY = 10
BATTERY_PER_ARM = 45
VEC_BATTERY = 80
MUTANT_STEP_CAP = 30000
WATCH_IMM = (0x510, 0x2710, 0x65, 0x270F, 0x5F45A5F, 0x186A0, 0x1A2, 0x156, 0x158, 0x1A1, 0xFA, 0x2D, 0x35, 0xB0, 0x3, 0xB, 0x2, 0x1)
WATCH_DISP = (0x4A0, 0x378, 0x408, 0x468, 0xB8, 0x1330, 0x338)
ARM_LABEL = ("name-to-asset-id", "event-0x2d-forward", "entry-insert", "flag-set-clear", "scale-by-quote-flag",
             "zero-address-apply", "bounded-index-apply")


def tsv(header, rows):
    return "\n".join(["\t".join(header)] + ["\t".join(str(c) for c in row) for row in rows]) + "\n"


def imm_of(row):
    if row.imm_at is None:
        return None
    return int.from_bytes(row.data[row.imm_at:row.imm_at + row.imm_size], "little")


def arm_rows(image):
    base = image.offset(TABLE)
    rows = []
    for index in range(16):
        target = TABLE + struct.unpack_from("<i", image.blob, base + 4 * index)[0]
        inside = DISPATCH <= target < DISPATCH_END
        label = ARM_LABEL[index] if index < 7 else "none"
        rows.append(("%d" % index, "%#x" % target, "yes" if inside else "no", label))
    return rows


def slot_rows(image):
    rel = image.relative()
    rows = []
    for name, slot in sorted(SLOTS.items(), key=lambda kv: kv[1]):
        if slot in rel:
            target = rel[slot]
            try:
                start, end = image.exact_fde(target)
                size = str(end - start)
            except EvidenceError:
                size = "no-fde"
            rows.append((name, "%#x" % slot, "relative", "%#x" % target, size))
        else:
            rows.append((name, "%#x" % slot, "dynamic", "-", "-"))
    for name, target in sorted(CALLS.items(), key=lambda kv: kv[1]):
        start, end = image.exact_fde(target)
        rows.append((name, "-", "direct-call", "%#x" % target, str(end - start)))
    return rows


def site_rows(rows):
    out = []
    for row in rows:
        value = imm_of(row)
        if value in WATCH_IMM and row.op in ("cmp", "mov", "add", "movx"):
            out.append(("%#x" % row.va, row.size, "imm", "%#x" % value, row.data.hex()))
        for disp in WATCH_DISP:
            pat = disp.to_bytes(4, "little")
            at = row.data.find(pat)
            if at >= 1 and value != disp:
                out.append(("%#x" % row.va, row.size, "disp", "%#x" % disp, row.data.hex()))
        if row.data.find(MAGIC10K.to_bytes(8, "little")) >= 0:
            out.append(("%#x" % row.va, row.size, "magic", "%#x" % MAGIC10K, row.data.hex()))
        if row.op == "shr" and row.data[-1] == 0x0B:
            out.append(("%#x" % row.va, row.size, "shift", "0xb", row.data.hex()))
    return out


def mutants_of(rows, region):
    found = []
    for row in rows:
        if row.op == "jcc":
            at = 0 if 0x70 <= row.data[0] <= 0x7F else 1
            found.append((region, "invert-condition", row.va, {row.va + at: row.data[at] ^ 1},
                          "%02x->%02x" % (row.data[at], row.data[at] ^ 1)))
        value = imm_of(row)
        if value in WATCH_IMM and row.op in ("cmp", "mov", "add", "movx"):
            found.append((region, "immediate-plus-one", row.va, {row.va + row.imm_at: (row.data[row.imm_at] + 1) & 255},
                          "%#x" % value))
        if row.op == "cmov":
            at = row.data.find(b"\x0f")
            found.append((region, "invert-cmov", row.va, {row.va + at + 1: row.data[at + 1] ^ 1},
                          "%02x->%02x" % (row.data[at + 1], row.data[at + 1] ^ 1)))
        if region in ("dispatch", "dex-by-name-a", "dex-by-name-b", "dex-at"):
            for disp in WATCH_DISP:
                at = row.data.find(disp.to_bytes(4, "little"))
                if at >= 1 and value != disp:
                    found.append((region, "displacement-plus-8", row.va, {row.va + at: (row.data[at] + 8) & 255},
                                  "%#x" % disp))
        if row.data.find(MAGIC10K.to_bytes(8, "little")) >= 0:
            at = row.data.find(MAGIC10K.to_bytes(8, "little"))
            found.append((region, "magic-low-bit", row.va, {row.va + at: row.data[at] ^ 1}, "%#x" % MAGIC10K))
        if row.op == "shr" and row.data[-1] == 0x0B:
            found.append((region, "shift-plus-one", row.va, {row.va + row.size - 1: 0x0C}, "0xb"))
        if row.op == "shl" and region == "dispatch" and row.data[-1] == 0x03:
            found.append((region, "shift-minus-one", row.va, {row.va + row.size - 1: 0x02}, "0x3"))
    return found


def battery_cases():
    cases = edge_cases()
    for arm in range(7):
        cases.extend(make_case(arm, 5000 + n) for n in range(BATTERY_PER_ARM))
    return cases


def real_battery_cases():
    return [make_real_case(arm, 6000 + n) for arm in (0, 3, 4) for n in range(REAL_BATTERY)]


def run_battery(image, patches, groups, vec_cases):
    """groups: (real_lookups, cases) pairs; every case must agree with the model, any difference or crash detects."""
    for real, cases in groups:
        m, holder = build_machine(image, patches, real)
        m.step_limit = MUTANT_STEP_CAP
        for i, case in enumerate(cases):
            try:
                verdict = compare(m, holder, case)
            except Exception as exc:
                verdict = "crash: %s" % type(exc).__name__
            if verdict:
                return "detected", "%scase %d arm %d: %s" % ("composed " if real else "", i, case["arm"], verdict.split(":")[0])
    if vec_cases:
        m, holder = build_machine(image, patches)
        m.step_limit = MUTANT_STEP_CAP
        for i, case in enumerate(vec_cases):
            verdict = vec_compare(m, holder, case)
            if verdict:
                return "detected", "vec %d: %s" % (i, verdict.split(":")[0])
    return "missed", "-"


def flow_shape(result):
    status, out, rec, log = result
    shape = tuple(entry[0] for entry in log)
    return status.split("(")[0], "%#x" % int.from_bytes(out[:2], "little"), shape


LANDING_PAD = {"dispatch": 0x50D3E65, "vector-builder": 0x5ACC9D6, "dex-by-name-a": 0x446B055,
               "dex-by-name-b": 0x446B155, "dex-at": 0x446B448}


def generate(out):
    image = load_image(BINARY, SHA256)
    root = pathlib.Path(out)
    root.mkdir(parents=True, exist_ok=True)
    rows = decode_range(image, DISPATCH, DISPATCH_END)
    regions = {"dispatch": rows}
    for name, entry in (("vector-builder", VEC_BUILDER), ("dex-by-name-a", DEX_BY_NAME_A),
                        ("dex-by-name-b", DEX_BY_NAME_B), ("dex-at", DEX_AT)):
        start, end = image.exact_fde(entry)
        regions[name] = decode_range(image, start, end)
    m, holder = build_machine(image)
    rm, rholder = build_machine(image, real_lookups=True)
    total = 0
    flows = collections.Counter()
    case_rows = []
    cases = [(m, holder, c, "") for c in edge_cases()]
    for arm in range(7):
        cases.extend((m, holder, make_case(arm, n), "") for n in range(CASES_PER_ARM))
    for arm in (0, 3, 4):
        cases.extend((rm, rholder, make_real_case(arm, n), "r") for n in range(REAL_CASES))
    for i, (mach, hold, case, prefix) in enumerate(cases):
        mine = run_model(case)
        theirs = run_machine(mach, hold, case)
        total += 1
        if mine != theirs:
            raise ToolError("model and bytes disagree on arm %d case %d" % case["origin"])
        shape = flow_shape(theirs)
        flows[(case["arm"], prefix) + shape] += 1
        if i < 29 or i % SAMPLE_EVERY == 0:
            case_rows.append((prefix + "%d.%d" % case["origin"], "%#x" % int.from_bytes(case["action"][:8], "little"),
                              shape[0], shape[1], "+".join(shape[2]) or "-", digest_of(theirs)))
    vec_rows_out = []
    vm, vholder = build_machine(image)
    for n in range(VEC_CASES):
        case = vec_case(n)
        want, got = vec_expected(case), vec_run(vm, vholder, case)
        total += 1
        if want != got:
            raise ToolError("vector builder disagrees with the model on case %d" % n)
        if n % VEC_SAMPLE_EVERY == 0:
            res = got[1]
            vec_rows_out.append((n, "%#x" % case["factor"], "%#x" % case["start"], "%#x" % case["end"],
                                 got[0].split("(")[0], "-" if res is None else res[2],
                                 "-" if res is None else (res[3][0] if res[3] else "-"),
                                 hashlib.sha256(repr(got).encode()).hexdigest()[:12]))
    seen = m.seen | rm.seen | vm.seen
    uncovered = []
    instruction_total = 0
    for region, rws in regions.items():
        instruction_total += len(rws)
        ud2s = {r.va for r in rws if r.op == "ud2"}
        for r in rws:
            if r.va not in seen:
                where = "landing-pad" if r.va >= LANDING_PAD[region] else "body"
                if r.op == "nop":
                    where = "padding"
                if r.op == "ud2" or (r.op == "jmp" and r.target in ud2s):
                    where = "after-diverging-call"
                uncovered.append((region, "%#x" % r.va, r.op, r.data.hex(), where))
    # negative controls
    bat, rbat = battery_cases(), real_battery_cases()
    vbat = [vec_case(10000 + n) for n in range(VEC_BATTERY)]
    controls, equivalent = [], []
    detected = 0
    index = 0
    for region, rws in regions.items():
        for _, kind, addr, patches, desc in mutants_of(rws, region):
            index += 1
            groups = {"dispatch": [(False, bat), (True, rbat)], "vector-builder": [(False, bat[:60]), (True, rbat[:60])]}
            verdict, note = run_battery(image, patches, groups.get(region, [(True, rbat)]),
                                        vbat if region == "vector-builder" else [])
            if verdict == "detected":
                detected += 1
            controls.append(("M%03d" % index, region, kind, "%#x" % addr, desc, verdict, note))
    flow_out = [("%d" % arm, ARM_LABEL[arm] + (" (real lookups)" if prefix else ""), status, code,
                 "+".join(shape) or "-", count)
                for (arm, prefix, status, code, shape), count in sorted(flows.items(), key=lambda kv: str(kv[0]))]
    pad_start = {region: LANDING_PAD[region] for region in regions}
    for c in controls:
        if c[5] == "missed" and int(c[3], 16) >= pad_start[c[1]]:
            equivalent.append((c[0], c[1], c[3], "cleanup block entered only through the unwind tables; "
                               "no modelled callee unwinds, so the mutated instruction cannot execute"))
    files = {
        "arms.tsv": tsv(("index", "target", "inside-fde", "label"), arm_rows(image)),
        "slots.tsv": tsv(("name", "slot", "kind", "target", "fde-bytes"), slot_rows(image)),
        "sites.tsv": tsv(("address", "size", "class", "value", "bytes"),
                         [row for rws in regions.values() for row in site_rows(rws)]),
        "flows.tsv": tsv(("arm", "label", "status", "code", "callee-sequence", "cases"), flow_out),
        "cases.tsv": tsv(("case", "tag", "status", "code", "callees", "digest"), case_rows),
        "vec-cases.tsv": tsv(("case", "factor", "start", "end", "status", "length", "first", "digest"), vec_rows_out),
        "coverage.tsv": tsv(("region", "address", "op", "bytes", "kind"), uncovered),
        "controls.tsv": tsv(("id", "region", "kind", "address", "detail", "verdict", "first-detection"), controls),
        "equivalent-mutants.tsv": tsv(("id", "region", "address", "reason"), equivalent),
        "measure.json": json.dumps({"cases": total, "negative_controls": len(controls), "negative_detected": detected,
                                    "equivalent": len(equivalent), "mismatches": 0,
                                    "instructions_total": instruction_total,
                                    "instructions_uncovered": len(uncovered),
                                    "uncovered_outside_landing_pads": sum(1 for u in uncovered if u[4] == "body")},
                                   indent=1, sort_keys=True) + "\n",
    }
    for name, text in files.items():
        (root / name).write_text(text)
    return json.loads(files["measure.json"])





def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--out", required=True)
    args = parser.parse_args()
    print(json.dumps(generate(args.out), sort_keys=True))


if __name__ == "__main__":
    main()
