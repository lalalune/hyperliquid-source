#!/usr/bin/env python3
"""Reconstruct the node #115 LZ4 block compressor drivers and prove them against the instruction bytes.

Targets (ELF virtual addresses): the 4096 x u16 driver 0x477e950, the 4096 x u32 driver 0x477f040, the match counter 0x477e7c0 and
the last-literals writer 0x477f750 (plus the literal append helper 0x477e5c0 that both call). The drivers are re-implemented as pure
Python functions; every comparison runs the real function bytes through a byte-exact x86-64 interpreter (the binary is never
executed) and demands equal return value, equal appended bytes and equal final hash table, or a panic on both sides.

    python3 tools/transport_lz4_compress_115.py --out research/work-items/transport-lz4-compress-driver-115
"""

import bisect
import hashlib
import json
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
# Packet part: reconstruction of the two compressor drivers, their match counter and their tail writer.
# ---------------------------------------------------------------------------------------------------------------------

SMALL, LARGE = 0x477E950, 0x477F040
COUNT, TAIL, APPEND = 0x477E7C0, 0x477F750, 0x477E5C0
PANIC_SLOTS = (0x64DF570, 0x64DF520, 0x64DF848, 0x64DF620, 0x64DF730, 0x64DF870)
MEMCPY_SLOT = 0x64DF508
FAKE_BASE = 0x7800000000
H0 = HEAP_BASE
SRC_AT, SINK_AT, HOLD_AT, TAB_AT, OUT_AT, CELL_AT = H0 + 0x8000, H0 + 0x100, H0 + 0x200, H0 + 0x2000, H0 + 0x80000, H0 + 0x300
RESET_BYTES = 0x100000
SIG_EXPECT = {SMALL: (0x477E950, 0x477F036), LARGE: (0x477F040, 0x477F746), COUNT: (0x477E7C0, 0x477E941),
              TAIL: (0x477F750, 0x477F8BA), APPEND: (0x477E5C0, 0x477E6D4)}


class ModelPanic(Exception):
    """A branch of the target that ends in a panic slot; the text names the failing check."""


class Flags:
    """Model switches. The defaults are the reconstruction; every other value is a deliberate wrong variant."""

    def __init__(self, **kw):
        self.hash_mul = {SMALL: 0x9E3779B1, LARGE: 0xCF1BBCDCBB000000}
        self.shift = 20
        self.tail_gap = 12
        self.step_shift = 5
        self.step_start = 32
        self.dist_limit = 0x10000
        self.nibble = 15
        self.backward = True
        self.store_first = False
        self.store_back = 2
        self.count_gap = 6
        self.need_pct = 110
        self.need_add = 20
        self.first_zero = True
        self.excess_base = 255
        self.match_skip = 4
        self.__dict__.update(kw)


def hash_cell(kind, src, at, flags):
    if kind == SMALL:
        word = int.from_bytes(src[at:at + 4], "little")
        return ((word * flags.hash_mul[SMALL]) & 0xFFFFFFFF) >> flags.shift
    word = int.from_bytes(src[at:at + 8], "little")
    return ((word * flags.hash_mul[LARGE]) & MASK[8]) >> (flags.shift + 32)


def model_count(src, pos, other, q, flags=None):
    """0x477e7c0: common prefix of src[pos:] and other[q:] bounded by both ends; returns (matched, new_pos)."""
    flags = flags or Flags()
    n, n2 = len(src), len(other)
    wrapped_end = (n - flags.count_gap) & MASK[8]
    if wrapped_end < pos:
        raise ModelPanic("count: end minus six below position")
    if n2 < q:
        raise ModelPanic("count: candidate start beyond its end")
    limit = min(wrapped_end - pos, n2 - q)
    matched = 0
    while matched < limit and src[pos + matched] == other[q + matched]:
        matched += 1
    return matched, pos + matched


def put_excess(out, cap, amount, flags):
    """Length continuation: 255 repeated, then the remainder; a full sink panics before the byte that would not fit."""
    base = flags.excess_base
    for _ in range(amount // base):
        if len(out) >= cap:
            raise ModelPanic("sink full in excess run")
        out.append(255)
    if len(out) >= cap:
        raise ModelPanic("sink full at excess remainder")
    out.append(amount % base)


def put_literals(out, cap, src, origin, count):
    if len(out) + count > cap:
        raise ModelPanic("sink full in literal append")
    out.extend(src[origin:origin + count])


def model_tail(out, cap, src, end, origin, flags=None):
    """0x477f750: token with only the literal nibble, literal excess, literal bytes."""
    flags = flags or Flags()
    if end < origin:
        raise ModelPanic("tail: origin beyond end")
    count = end - origin
    if len(out) >= cap:
        raise ModelPanic("tail: sink full at token")
    out.append(min(count, flags.nibble) << 4 & 0xFF)
    if count >= 15:
        put_excess(out, cap, count - 15, flags)
    put_literals(out, cap, src, origin, count)


def model_compress(kind, src, start, ext, cap, pos0, table, flags=None, arg7=0):
    """Whole driver. `table` is a list of 4096 cells that is updated in place. Returns (status, appended bytes)."""
    flags = flags or Flags()
    n = len(src)
    mask = 0xFFFF if kind == SMALL else 0xFFFFFFFF
    if n < start:
        raise ModelPanic("start beyond input")
    if arg7 != 0:
        raise ModelPanic("unsupported non-zero argument")
    if cap < pos0:
        raise ModelPanic("sink position beyond capacity")
    remaining = n - start
    need = remaining * flags.need_pct
    if need >= 1 << 64:
        raise ModelPanic("size product overflow")
    need = ((need >> 2) // 25) + flags.need_add
    if cap - pos0 < need:
        return 1, b""
    out = bytearray(pos0)
    if remaining <= 12:
        model_tail(out, cap, src, n, start, flags)
        return 0, bytes(out[pos0:])
    limit = n - flags.tail_gap
    origin = start
    nxt = start
    if (start | ext) == 0 and flags.first_zero:
        table[hash_cell(kind, src, 0, flags)] = 0
        nxt = 1
    step = flags.step_start
    while True:
        cur = nxt
        nxt = cur + (step >> flags.step_shift)
        if cur > limit:
            break
        absolute = cur + ext
        cell = hash_cell(kind, src, cur, flags)
        if flags.store_first:
            table[cell] = absolute & mask
            old = table[cell]
        else:
            old = table[cell]
            table[cell] = absolute & mask
        if old > absolute:
            raise ModelPanic("candidate ahead of position")
        distance = absolute - old
        if old < ext or distance >= flags.dist_limit:
            step += 1
            continue
        cand = old - ext
        if cand + 4 > n:
            raise ModelPanic("candidate word beyond input")
        if src[cand:cand + 4] != src[cur:cur + 4]:
            step += 1
            continue
        if flags.backward and cur > origin and cand != 0:
            d = 0
            while True:
                at = cur + d - 1
                if at >= n:
                    raise ModelPanic("backward byte beyond input")
                if src[at] != src[cand + d - 1]:
                    break
                d -= 1
                if at <= origin or cand + d == 0:
                    break
            cur += d
            cand += d
        literals = cur - origin
        if literals < 0:
            raise ModelPanic("negative literal run")
        matched, end = model_count(src, cur + flags.match_skip, src, cand + 4, flags)
        if end < 2 or end + 2 > n:
            raise ModelPanic("seed store outside input")
        table[hash_cell(kind, src, end - flags.store_back, flags)] = (end - 2 + ext) & mask
        if len(out) >= cap:
            raise ModelPanic("sink full at token")
        out.append((min(literals, flags.nibble) << 4 & 0xFF) | min(matched, flags.nibble))
        if literals >= 15:
            put_excess(out, cap, literals - 15, flags)
        put_literals(out, cap, src, origin, literals)
        if len(out) + 2 > cap:
            raise ModelPanic("sink full at offset")
        out.extend((distance & 0xFFFF).to_bytes(2, "little"))
        if matched >= 15:
            put_excess(out, cap, matched - 15, flags)
        origin = end
        nxt = end
        step = flags.step_start
    model_tail(out, cap, src, n, origin, flags)
    return 0, bytes(out[pos0:])


# --------------------------------------------------------------------------------------------------------------------
# Execution harness over the byte-exact interpreter
# --------------------------------------------------------------------------------------------------------------------

def build_machine(image, patches=None):
    machine = Machine(image, patches)
    machine.real = frozenset([SMALL, LARGE, COUNT, TAIL, APPEND])
    for index, slot in enumerate(PANIC_SLOTS):
        fake = FAKE_BASE + 16 * index
        machine.memory.statics[slot] = fake

        def hook(_machine, slot=slot):
            raise Panicked("slot %#x" % slot)
        machine.slots[fake] = hook
    machine.memory.statics[MEMCPY_SLOT] = FAKE_BASE + 0x400

    def memcpy(_machine):
        _machine.memory.copy(_machine.regs[RDI], _machine.regs[RSI], _machine.regs[RDX])
    machine.slots[FAKE_BASE + 0x400] = memcpy
    return machine


def prime(machine, src, cap, table_cells=None):
    memory = machine.memory
    memory.reset(RESET_BYTES)
    memory.put_bytes(SRC_AT, src)
    memory.write(SINK_AT, 8, OUT_AT)
    memory.write(SINK_AT + 8, 8, cap)
    memory.write(HOLD_AT, 8, TAB_AT)
    memory.put_bytes(OUT_AT, bytes(cap))
    machine.steps = 0


def native_compress(machine, kind, src, start, ext, cap, pos0, table, arg7=0):
    prime(machine, src, cap)
    memory = machine.memory
    memory.write(SINK_AT + 16, 8, pos0)
    width = 2 if kind == SMALL else 4
    memory.put_bytes(TAB_AT, b"".join(cell.to_bytes(width, "little") for cell in table))
    try:
        status = machine.run(kind, {RDI: SRC_AT, RSI: len(src), RDX: start, RCX: SINK_AT, R8: HOLD_AT, R9: 0},
                             stack=(arg7, ext)) & 0xFF
    except Panicked as error:
        return "panic", str(error), machine.steps
    raw = memory.bytes_at(TAB_AT, 4096 * width)
    table[:] = [int.from_bytes(raw[i:i + width], "little") for i in range(0, len(raw), width)]
    position = memory.read(SINK_AT + 16, 8)
    return status, bytes(memory.bytes_at(OUT_AT + pos0, position - pos0)), machine.steps


def native_count(machine, src, pos, other, q):
    prime(machine, src, 64)
    memory = machine.memory
    memory.put_bytes(CELL_AT, pos.to_bytes(8, "little"))
    memory.put_bytes(OUT_AT, other)
    try:
        matched = machine.run(COUNT, {RDI: SRC_AT, RSI: len(src), RDX: CELL_AT, RCX: OUT_AT, R8: len(other), R9: q})
    except Panicked as error:
        return "panic", "slot"
    return matched, memory.read(CELL_AT, 8)


def native_tail(machine, src, origin, cap, pos0):
    prime(machine, src, cap)
    memory = machine.memory
    memory.write(SINK_AT + 16, 8, pos0)
    try:
        machine.run(TAIL, {RDI: SINK_AT, RSI: SRC_AT, RDX: len(src), RCX: origin})
    except Panicked as error:
        return "panic", "slot"
    return bytes(memory.bytes_at(OUT_AT + pos0, memory.read(SINK_AT + 16, 8) - pos0))


def compare_compress(machine, kind, src, start, ext, cap, pos0, table, flags=None, arg7=0):
    """Run native and model on the same state; returns (agree, status, native_steps)."""
    native_table = list(table)
    model_table = list(table)
    native = native_compress(machine, kind, src, start, ext, cap, pos0, native_table, arg7)
    try:
        status, produced = model_compress(kind, src, start, ext, cap, pos0, model_table, flags, arg7)
        modelled = (status, produced)
    except (ModelPanic, IndexError):
        modelled = ("panic",)
    if native[0] == "panic":
        return modelled == ("panic",), "panic", native[2]
    if modelled == ("panic",):
        return False, "model-panic", native[2]
    same = native[0] == modelled[0] and native[1] == modelled[1] and (native[0] == 1 or native_table == model_table)
    return same, "ok" if native[0] == 0 else "short", native[2]


# --------------------------------------------------------------------------------------------------------------------
# Deterministic case generation
# --------------------------------------------------------------------------------------------------------------------

class Lcg:
    def __init__(self, seed):
        self.state = seed & MASK[8]

    def next(self):
        self.state = (self.state * 6364136223846793005 + 1442695040888963407) & MASK[8]
        return self.state >> 33

    def below(self, bound):
        return self.next() % bound

    def pick(self, items):
        return items[self.below(len(items))]


def make_input(rng):
    shape = rng.below(7)
    length = rng.pick((0, 1, 5, 11, 12, 13, 14, 17, 20, 31, 32, 33, 40, 64, 90, 140, 260, 300, 600, 700, 1300, 2200))
    length += rng.below(5) if length > 12 else 0
    if shape == 0:
        return bytes(rng.below(256) for _ in range(length))
    if shape == 1:
        alphabet = bytes(rng.below(256) for _ in range(rng.pick((1, 2, 3, 4))))
        return bytes(rng.pick(alphabet) for _ in range(length))
    if shape == 2:
        unit = bytes(rng.below(256) for _ in range(rng.pick((1, 2, 3, 4, 5, 7, 9))))
        return (unit * (length // len(unit) + 1))[:length]
    if shape == 3:
        pool = [bytes(rng.below(256) for _ in range(rng.pick((4, 6, 9, 16)))) for _ in range(3)]
        data = bytearray()
        while len(data) < length:
            data.extend(rng.pick(pool) if rng.below(4) else bytes(rng.below(256) for _ in range(rng.below(20))))
        return bytes(data[:length])
    if shape == 4:
        return bytes(rng.pick(b"ab") if rng.below(9) else rng.below(256) for _ in range(length))
    if shape == 5:
        head = bytes(rng.below(256) for _ in range(rng.pick((8, 16, 32))))
        gap = bytes(rng.below(256) for _ in range(rng.below(600)))
        return (head + gap + head + gap[:rng.below(40)] + head)[:max(length, 20)]
    return bytes(length)


def make_table(rng, src, kind, ext):
    mode = rng.below(4)
    mask = 0xFFFF if kind == SMALL else 0xFFFFFFFF
    if mode == 0:
        return [0] * 4096
    if mode == 1:
        return [rng.below(mask + 1) for _ in range(4096)]
    cells = [0] * 4096
    for _ in range(rng.below(60)):
        cells[rng.below(4096)] = (rng.below(max(len(src), 1)) + ext) & mask
    return cells


def make_state(rng, kind):
    src = make_input(rng)
    start = 0 if rng.below(3) else min(len(src), rng.below(len(src) + 1))
    if rng.below(40) == 0:
        start = len(src) + 1
    ext = 0 if rng.below(3) else rng.pick((1, 7, 100, 4096, 65535, 65536, 70000))
    pos0 = rng.pick((0, 0, 0, 3, 17))
    need = (len(src) - min(start, len(src))) * 110 // 100 + 20
    roll = rng.below(10)
    if roll < 6:
        cap = pos0 + need + len(src) + 8
    elif roll < 8:
        cap = pos0 + need + rng.below(12)
    elif roll == 8:
        cap = pos0 + max(need - 1 - rng.below(4), 0)
    else:
        cap = pos0 + rng.below(need + 1)
    table = make_table(rng, src, kind, ext)
    return src, start, ext, cap, pos0, table


def mutate_bytes(src, rng):
    data = bytearray(src)
    if data:
        data[rng.below(len(data))] ^= 1 + rng.below(255)
    return bytes(data)


def boundary_state(kind, distance, variant):
    """A 66 KB input whose candidate sits exactly `distance` bytes behind the probe position (65534..65537)."""
    rng = Lcg(0xB0DA + distance * 7 + variant)
    probe = 66000
    src = bytearray(rng.below(256) for _ in range(probe + 24))
    cand = probe - distance
    src[probe:probe + 8] = src[cand:cand + 8]
    if variant:
        src[probe + 6] ^= 0x55
    src = bytes(src)
    table = [0] * 4096
    table[hash_cell(kind, src, probe, Flags())] = cand
    return src, probe - 2, 0, len(src) * 2 + 64, 0, table


def literal_state(kind, literals):
    """`literals` random bytes, then a 600-byte block twice: the first match follows a literal run of that length."""
    rng = Lcg(0x11AA + literals)
    block = bytes(rng.below(256) for _ in range(600))
    src = bytes(rng.below(256) for _ in range(literals)) + block + bytes(rng.below(256) for _ in range(30)) + block + b"tail-bytes-xyz"
    return src, 0, 0, len(src) * 2 + 64, 0, [0] * 4096


def special_state(kind, spec):
    if spec[0] == "distance":
        return boundary_state(kind, spec[1], spec[2])
    return literal_state(kind, spec[1])


# --------------------------------------------------------------------------------------------------------------------
# Controls: wrong model variants, corrupted code bytes, out-of-range inputs
# --------------------------------------------------------------------------------------------------------------------

MODEL_MUTANTS = (
    ("hash-multiplier-low-bit", dict(hash_mul={SMALL: 0x9E3779B3, LARGE: 0xCF1BBCDCBB000000})),
    ("hash-shift-19", dict(shift=19)),
    ("large-multiplier-bit", dict(hash_mul={SMALL: 0x9E3779B1, LARGE: 0xCF1BBCDCBB000001})),
    ("tail-gap-11", dict(tail_gap=11)),
    ("tail-gap-13", dict(tail_gap=13)),
    ("step-shift-6", dict(step_shift=6)),
    ("step-shift-4", dict(step_shift=4)),
    ("step-start-16", dict(step_start=16)),
    ("distance-limit-65535", dict(dist_limit=0xFFFF)),
    ("distance-limit-65537", dict(dist_limit=0x10001)),
    ("nibble-cap-14", dict(nibble=14)),
    ("no-backward-extension", dict(backward=False)),
    ("store-before-load", dict(store_first=True)),
    ("seed-store-minus-one", dict(store_back=1)),
    ("seed-store-minus-three", dict(store_back=3)),
    ("count-gap-5", dict(count_gap=5)),
    ("count-gap-7", dict(count_gap=7)),
    ("need-percent-100", dict(need_pct=100)),
    ("need-add-19", dict(need_add=19)),
    ("no-first-zero-seed", dict(first_zero=False)),
    ("excess-base-254", dict(excess_base=254)),
    ("match-skip-3", dict(match_skip=3)),
)

CODE_PATCHES = (
    # (name, [(address, replacement byte)]) -- one immediate or condition byte each; offsets checked against the opcode bytes
    ("small-hash-multiplier", [(0x477EABA, 0xB3)]),
    ("small-hash-shift", [(0x477EAC0, 0x13)]),
    ("small-distance-limit", [(0x477EAE6, 0x02)]),
    ("small-tail-gap-cmp", [(0x477E9DF, 0x0B)]),
    ("small-limit-sub", [(0x477E9EC, 0x0D)]),
    ("small-step-shift", [(0x477EA86, 0x04)]),
    ("small-step-start", [(0x477EA61, 0x10)]),
    ("small-need-percent", [(0x477E99A, 0x64)]),
    ("small-need-add", [(0x477E9C2, 0x13)]),
    ("small-token-literal-cap", [(0x477EC2B, 0x0E)]),
    ("small-token-match-cap", [(0x477EC3A, 0x0E)]),
    ("small-seed-store-back", [(0x477EBCC, 0xFF)]),
    ("small-forward-skip", [(0x477EB9A, 0x03)]),
    ("small-excess-reciprocal", [(0x477EDAC, 0x7F)]),
    ("small-candidate-jump", [(0x477EAFC, 0x84)]),
    ("small-origin-jump", [(0x477EB08, 0x77)]),
    ("large-distance-limit", [(0x477F1E0, 0x02)]),
    ("large-hash-shift", [(0x477F1BC, 0x33)]),
    ("count-gap", [(0x477E7D7, 0xFB)]),
    ("count-word-shift", [(0x477E8C1, 0x02)]),
    ("tail-nibble-shift", [(0x477F777, 0x03)]),
    ("tail-excess-offset", [(0x477F7B4, 0xF3)]),
)


def probe_states(kind, seeds=240):
    for distance in (65535, 65536, 65537):
        yield boundary_state(kind, distance, 0)
    for count in (15, 270, 1035, 1300):
        yield literal_state(kind, count)
    rng = Lcg(0xC0FFEE + kind)
    for _ in range(seeds):
        yield make_state(rng, kind)


def detects_model(kind, flags, seeds=240):
    machine = build_machine(IMAGE)
    for src, start, ext, cap, pos0, table in probe_states(kind, seeds):
        agree, _, _ = compare_compress(machine, kind, src, start, ext, cap, pos0, table, flags)
        if not agree:
            return True
    return False


def detects_patch(image, patches, seeds=160):
    for kind in (SMALL, LARGE):
        machine = build_machine(image, dict(patches))
        for src, start, ext, cap, pos0, table in probe_states(kind, seeds):
            try:
                agree, _, _ = compare_compress(machine, kind, src, start, ext, cap, pos0, table)
            except (Halt, EvidenceError, IndexError, ValueError):
                return True
            if not agree:
                return True
        rng = Lcg(77)
        for _ in range(60):
            src = make_input(rng)
            while len(src) < 6:
                src = make_input(rng)
            other = src[rng.below(len(src) + 1):] + bytes(8)
            pos, q = rng.below(len(src) + 1), rng.below(len(other) + 1)
            try:
                if native_count(machine, src, pos, other, q) != safe_count(src, pos, other, q):
                    return True
                origin = rng.below(len(src) + 1)
                if native_tail(machine, src, origin, 64 + len(src), 0) != safe_tail(src, origin, 64 + len(src), 0):
                    return True
            except (Halt, EvidenceError, IndexError, ValueError):
                return True
    return False


def safe_count(src, pos, other, q):
    try:
        return model_count(src, pos, other, q)
    except ModelPanic:
        return "panic", "slot"


def safe_tail(src, origin, cap, pos0):
    out = bytearray(pos0)
    try:
        model_tail(out, cap, src, len(src), origin)
    except ModelPanic:
        return "panic", "slot"
    return bytes(out[pos0:])


def range_controls():
    """Inputs outside the contract must be refused by the tool itself, not silently modelled."""
    results = []
    for name, action in (
            ("wrong-binary-digest", lambda: load_image_bytes(b"x" * 64)),
            ("entry-not-fde-start", lambda: IMAGE.exact_fde(SMALL + 4)),
            ("address-outside-sections", lambda: IMAGE.offset(0x10)),
            ("address-past-text", lambda: IMAGE.offset(0x7FFFFFFFF)),
            ("start-beyond-input-is-panic", lambda: model_compress(SMALL, b"abc", 4, 0, 99, 0, [0] * 4096)),
            ("sink-position-beyond-cap", lambda: model_compress(SMALL, b"abc", 0, 0, 3, 9, [0] * 4096)),
            ("nonzero-argument-seven", lambda: model_compress(SMALL, b"abc", 0, 0, 99, 0, [0] * 4096, arg7=1)),
            ("tail-origin-beyond-end", lambda: model_tail(bytearray(), 99, b"abc", 3, 4)),
    ):
        try:
            action()
        except (EvidenceError, ModelPanic):
            results.append((name, True))
        else:
            results.append((name, False))
    return results


def load_image_bytes(blob):
    if hashlib.sha256(blob).hexdigest() != SHA256:
        raise EvidenceError("binary SHA-256 mismatch")
    return Image(blob)


# --------------------------------------------------------------------------------------------------------------------
# Evidence production
# --------------------------------------------------------------------------------------------------------------------

IMAGE = None
SPECIALS = tuple(('distance', distance, variant) for distance in (65533, 65534, 65535, 65536, 65537, 65538) for variant in (0, 1)) + tuple(
    ('literal', count) for count in (14, 15, 16, 269, 270, 271, 524, 525, 1034, 1035, 1036, 1290, 1291, 2100))
COMPRESS_CASES = 4000
COUNT_CASES = 1500
TAIL_CASES = 700
KEPT_COMPRESS = 1500
KEPT_COUNT = 500
KEPT_TAIL = 300
CHAIN = hashlib.sha256()


def short(data):
    return hashlib.sha256(data).hexdigest()[:12]


def digest_row(src):
    return "%d:%s" % (len(src), short(src))


def run_cases(handle, summary):
    machine = build_machine(IMAGE)
    handle.write("index\tdriver\tinput\tstart\text\tcap\tpos0\tstatus\tout_len\tout_sha12\tsteps\tagree\n")
    index = 0
    for kind, seed in ((SMALL, 0x5EED01), (LARGE, 0x5EED02)):
        rng = Lcg(seed)
        for number in range(COMPRESS_CASES + len(SPECIALS)):
            if number < len(SPECIALS):
                src, start, ext, cap, pos0, table = special_state(kind, SPECIALS[number])
            else:
                src, start, ext, cap, pos0, table = make_state(rng, kind)
            native_table = list(table)
            native = native_compress(machine, kind, src, start, ext, cap, pos0, native_table)
            agree, label, steps = compare_compress(machine, kind, src, start, ext, cap, pos0, table)
            summary["cases"] += 1
            summary["agree"] += agree
            summary["status_" + label] = summary.get("status_" + label, 0) + 1
            summary["steps"] += steps
            produced = native[1] if native[0] in (0, 1) else b""
            row = "%d\t%#x\t%s\t%d\t%d\t%d\t%d\t%s\t%d\t%s\t%d\t%d\n" % (
                index, kind, digest_row(src), start, ext, cap, pos0, label, len(produced), short(produced), steps, agree)
            CHAIN.update(row.encode())
            if number < KEPT_COMPRESS:
                handle.write(row)
            index += 1
    return machine


def run_helper_cases(handle, summary):
    machine = build_machine(IMAGE)
    handle.write("index\thelper\tinput\targ_a\targ_b\tnative\tmodel\tagree\n")
    rng = Lcg(0xABCD01)
    index = 0
    for _ in range(COUNT_CASES):
        src = make_input(rng)
        while len(src) < 6:
            src = make_input(rng)
        shared = rng.below(len(src) + 1)
        other = bytearray(src[shared:] + bytes(rng.below(30)))
        if other and rng.below(2):
            other[rng.below(len(other))] ^= 1 << rng.below(8)
        other = bytes(other)
        pos = min(len(src), rng.below(len(src) + 2)) if rng.below(8) else len(src) - rng.below(8) if len(src) > 8 else 0
        q = rng.below(len(other) + 2) if rng.below(10) else 0
        native = native_count(machine, src, pos, other, q)
        model = safe_count(src, pos, other, q)
        agree = native == model
        summary["cases"] += 1
        summary["helper_agree"] += agree
        summary["agree"] += agree
        row = "%d\tcount\t%s\t%d\t%d\t%s\t%s\t%d\n" % (index, digest_row(src), pos, q, native, model, agree)
        CHAIN.update(row.encode())
        if index < KEPT_COUNT:
            handle.write(row)
        index += 1
    for _ in range(TAIL_CASES):
        src = make_input(rng)
        origin = rng.below(len(src) + 1) if rng.below(12) else len(src) + 1
        pos0 = rng.pick((0, 0, 5))
        cap = pos0 + len(src) + 4 + rng.below(8) if rng.below(4) else pos0 + rng.below(len(src) + 6)
        native = native_tail(machine, src, origin, cap, pos0)
        model = safe_tail(src, origin, cap, pos0)
        agree = native == model
        native_text = native if isinstance(native, tuple) else "bytes:%d:%s" % (len(native), short(native))
        model_text = model if isinstance(model, tuple) else "bytes:%d:%s" % (len(model), short(model))
        summary["cases"] += 1
        summary["helper_agree"] += agree
        summary["agree"] += agree
        row = "%d\ttail\t%s\t%d\t%d\t%s\t%s\t%d\n" % (index, digest_row(src), origin, cap, native_text, model_text, agree)
        CHAIN.update(row.encode())
        if index - COUNT_CASES < KEPT_TAIL:
            handle.write(row)
        index += 1


def write_signatures(handle):
    handle.write("function\tstart\tend\tbytes\tinstructions\tsha256_12\n")
    for entry in sorted(SIG_EXPECT):
        start, end = IMAGE.exact_fde(entry)
        rows = decode_range(IMAGE, start, end)
        data = IMAGE.blob[IMAGE.offset(start):IMAGE.offset(start) + end - start]
        handle.write("%#x\t%#x\t%#x\t%d\t%d\t%s\n" % (start, start, end, end - start, len(rows), short(bytes(data))))


def write_coverage(handle, machine_seen):
    handle.write("function\tinstructions\texecuted\tunexecuted_ranges\n")
    for entry in sorted(SIG_EXPECT):
        start, end = IMAGE.exact_fde(entry)
        rows = [row for row in decode_range(IMAGE, start, end) if row.op not in ("int3",)]
        seen = [row.va for row in rows if row.va in machine_seen]
        gaps, run = [], None
        for row in rows:
            if row.va in machine_seen:
                if run:
                    gaps.append(run)
                    run = None
            elif run is None:
                run = [row.va, row.va + row.size]
            else:
                run[1] = row.va + row.size
        if run:
            gaps.append(run)
        handle.write("%#x\t%d\t%d\t%s\n" % (entry, len(rows), len(seen), ",".join("%#x-%#x" % tuple(g) for g in gaps)))


def main():
    global IMAGE
    args = sys.argv[1:]
    if len(args) != 2 or args[0] != "--out":
        raise SystemExit("usage: transport_lz4_compress_115.py --out <folder>")
    out = pathlib.Path(args[1])
    out.mkdir(parents=True, exist_ok=True)
    IMAGE = load_image()
    summary = {"cases": 0, "agree": 0, "helper_agree": 0, "steps": 0}
    with open(out / "cases.tsv", "w", newline="\n") as handle:
        machine = run_cases(handle, summary)
    with open(out / "helper-cases.tsv", "w", newline="\n") as handle:
        run_helper_cases(handle, summary)
    seen = set(machine.seen)
    probe = build_machine(IMAGE)
    for kind in (SMALL, LARGE):
        for src, start, ext, cap, pos0, table in probe_states(kind, 120):
            native_compress(probe, kind, src, start, ext, cap, pos0, table)
    seen |= probe.seen
    for entry in sorted(SIG_EXPECT):
        pass
    with open(out / "signatures.tsv", "w", newline="\n") as handle:
        write_signatures(handle)
    with open(out / "coverage.tsv", "w", newline="\n") as handle:
        write_coverage(handle, seen)
    if detects_patch(IMAGE, []) or any(detects_model(kind, Flags()) for kind in (SMALL, LARGE)):
        raise EvidenceError("baseline control: the unmodified model and bytes must never be flagged")
    controls, equivalent = [], []
    for name, change in MODEL_MUTANTS:
        flags = Flags(**change)
        kinds = (LARGE,) if name.startswith("large") else (SMALL, LARGE) if name.startswith("hash-shift") else (SMALL,)
        found = any(detects_model(kind, flags) for kind in kinds)
        controls.append(("model", name, "-", found))
    for name, patches in CODE_PATCHES:
        controls.append(("code-byte", name, ",".join("%#x" % a for a, _ in patches), detects_patch(IMAGE, patches)))
    for name, ok in range_controls():
        controls.append(("range", name, "-", ok))
    with open(out / "controls.tsv", "w", newline="\n") as handle:
        handle.write("kind\tname\taddress\tdetected\n")
        for kind, name, address, found in controls:
            handle.write("%s\t%s\t%s\t%d\n" % (kind, name, address, found))
            if not found:
                equivalent.append((kind, name, address))
    detected = sum(1 for row in controls if row[3])
    with open(out / "equivalent-mutants.tsv", "w", newline="\n") as handle:
        handle.write("mutant\taddress\treason\n")
        for kind, name, address in equivalent:
            handle.write("%s:%s\t%s\t%s\n" % (kind, name, address, EQUIVALENT_REASON.get(name, "UNEXPLAINED")))
    explained = sum(1 for _, name, _ in equivalent if name in EQUIVALENT_REASON)
    summary.update(negative_controls=len(controls), negative_detected=detected, row_chain_sha256_16=CHAIN.hexdigest()[:16])
    with open(out / "summary.json", "w", newline="\n") as handle:
        json.dump(summary, handle, indent=1, sort_keys=True)
        handle.write("\n")
    with open(out / "measure.json", "w", newline="\n") as handle:
        json.dump({"cases": summary["cases"], "negative_controls": len(controls), "negative_detected": detected,
                   "equivalent": explained}, handle, indent=1, sort_keys=True)
        handle.write("\n")
    print(json.dumps(summary, sort_keys=True))


EQUIVALENT_REASON = {
    "small-excess-reciprocal": "the reciprocal only sizes the 4-byte fill prefix of the 255-run; any smaller quotient leaves more bytes to the one-byte loop and the emitted bytes are identical",
    "tail-excess-offset": "the offset only sizes the 4-byte fill prefix of the 255-run; a quotient never above floor((count-15)/255) yields the same emitted bytes",
}

if __name__ == "__main__":
    main()
