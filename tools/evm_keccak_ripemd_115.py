#!/usr/bin/env python3
"""Node #115 Keccak-256 sponge (absorb, pad/squeeze, f1600) and RIPEMD-160 block compression, rebuilt and checked against the captured bytes.

The generator decodes the four target functions straight from the ELF bytes of the authenticated node #115 file, runs each one on an offline
x86-64 interpreter (the node is never executed) over thousands of inputs derived without the binary, and compares every result with an
independent pure-Python reconstruction. It also mutates the reconstruction and the captured bytes on purpose to show the comparison fails.

    python3 tools/evm_keccak_ripemd_115.py --out research/work-items/evm-keccak-ripemd-hash-115

Standard library plus the shared elf_index and fde_extents parsers. The interpreter section below is a copy of the verified shared x86-64
interpreter skeleton, trimmed of its unused members.
"""

import argparse
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




# ---------------------------------------------------------------------------------------------------------------------------------------
# Targets
# ---------------------------------------------------------------------------------------------------------------------------------------

F1600 = 0x5CDA380
ABSORB = 0x5CDA910
SQUEEZE = 0x5CDAD40
RIPEMD = 0x5C3CE60
RC_TABLE = 0x94C518
SLOT_F1600 = 0x64ECB70
SLOT_MEMCPY = 0x64DF508
FAKE_MEMCPY = 0x7800000200
FAKE_PANIC = 0x7800000300
HEAP_STATE = HEAP_BASE + 0x1000
HEAP_BUF = HEAP_BASE + 0x4000
STRUCT_SIZE = 0xE0
M64 = (1 << 64) - 1
M32 = (1 << 32) - 1

FUNCTIONS = (
    ("f1600", F1600, "Keccak-f[1600] permutation over 25 little-endian lanes at rdi, 24 rounds, round constants read from the rodata table"),
    ("absorb", ABSORB, "sponge write: xor input bytes into the rate part, permute through the f1600 slot at every full block"),
    ("squeeze", SQUEEZE, "sponge finalize-and-read on a copy: pad with delimiter and 0x80, permute, copy output blocks"),
    ("ripemd160_compress", RIPEMD, "RIPEMD-160 block compression: five-word state at rdi, 64-byte block at rsi"),
)


class Binary:
    """The authenticated node #115 image plus the decoded rows of the four functions."""

    def __init__(self, path=BINARY):
        self.image = load_image(path)
        self.rows = {}
        for name, start, _ in FUNCTIONS:
            _, end = self.image.exact_fde(start)
            self.rows[name] = decode_range(self.image, start, end)

    def extent(self, name):
        rows = self.rows[name]
        return rows[0].va, rows[-1].next

    def rc_table(self):
        at = self.image.offset(RC_TABLE)
        return struct.unpack_from("<24Q", self.image.blob, at)

    def function_bytes(self, name):
        start, end = self.extent(name)
        at = self.image.offset(start)
        return bytes(self.image.blob[at:at + end - start])


def slot_targets(rows):
    """Absolute slot addresses of the indirect calls in a decoded function (rip-relative operands are already resolved by the decoder)."""
    found = []
    for row in rows:
        if row.op == "calli" and row.a[0] == "m" and row.a[1] is None and row.a[2] is None:
            found.append(row.a[4] & MASK[8])
    return found


# ---------------------------------------------------------------------------------------------------------------------------------------
# Interpreter wiring: indirect slots are filled the way the loader would fill them
# ---------------------------------------------------------------------------------------------------------------------------------------

def hook_memcpy(machine):
    machine.memory.copy(machine.regs[RDI], machine.regs[RSI], machine.regs[RDX])
    machine.regs[RAX] = machine.regs[RDI]


def hook_panic(machine):
    raise Halt("panic")


def make_machine(binary, patches=None, rc_override=None):
    machine = Machine(binary.image, patches)
    machine.step_limit = 400000
    machine.real = frozenset([F1600])
    machine.memory.statics[SLOT_F1600] = F1600
    machine.memory.statics[SLOT_MEMCPY] = FAKE_MEMCPY
    for name in ("absorb", "squeeze"):
        for slot in slot_targets(binary.rows[name]):
            if slot not in (SLOT_F1600, SLOT_MEMCPY):
                machine.memory.statics[slot] = FAKE_PANIC
    machine.slots[FAKE_MEMCPY] = hook_memcpy
    machine.slots[FAKE_PANIC] = hook_panic
    if rc_override is not None:
        for index, value in enumerate(rc_override):
            machine.memory.statics[RC_TABLE + 8 * index] = value
    return machine


class Outcome:
    """Result of one run: either bytes read back or the reason the interpreter stopped."""

    __slots__ = ("value", "stop")

    def __init__(self, value=None, stop=None):
        self.value, self.stop = value, stop

    def key(self):
        return ("stop", self.stop) if self.stop else ("ok", self.value)


def run_guarded(machine, entry, args, reader):
    try:
        machine.run(entry, args)
    except Halt as error:
        return Outcome(stop="panic" if str(error) == "panic" else "halt:" + str(error))
    return Outcome(value=reader(machine))


# --- the four callables as seen from outside ---------------------------------------------------------------------------------------

def emu_f1600(machine, lanes):
    machine.memory.reset(0x8000)
    machine.memory.put_bytes(HEAP_STATE, struct.pack("<25Q", *lanes))
    return run_guarded(machine, F1600, {RDI: HEAP_STATE}, lambda m: struct.unpack("<25Q", m.memory.bytes_at(HEAP_STATE, 200)))


def pack_struct(lanes, pos, rate, delim, flag):
    return struct.pack("<25Q", *lanes) + struct.pack("<QQBB", pos, rate, delim, flag) + bytes(6)


def unpack_struct(blob):
    lanes = struct.unpack_from("<25Q", blob, 0)
    pos, rate, delim, flag = struct.unpack_from("<QQBB", blob, 200)
    return lanes, pos, rate, delim, flag


def emu_absorb(machine, lanes, pos, rate, delim, flag, data):
    machine.memory.reset(0x8000)
    machine.memory.put_bytes(HEAP_STATE, pack_struct(lanes, pos, rate, delim, flag))
    machine.memory.put_bytes(HEAP_BUF, data)
    return run_guarded(machine, ABSORB, {RDI: HEAP_STATE, RSI: HEAP_BUF, RDX: len(data)},
                       lambda m: unpack_struct(m.memory.bytes_at(HEAP_STATE, STRUCT_SIZE)))


def emu_squeeze(machine, lanes, pos, rate, delim, flag, count):
    machine.memory.reset(0x8000)
    machine.memory.put_bytes(HEAP_STATE, pack_struct(lanes, pos, rate, delim, flag))
    out = HEAP_BUF

    def read(m):
        return (bytes(m.memory.bytes_at(out, count)), unpack_struct(m.memory.bytes_at(HEAP_STATE, STRUCT_SIZE)))

    return run_guarded(machine, SQUEEZE, {RDI: HEAP_STATE, RSI: out, RDX: count}, read)


def emu_ripemd(machine, state, block):
    machine.memory.reset(0x8000)
    machine.memory.put_bytes(HEAP_STATE, struct.pack("<5I", *state))
    machine.memory.put_bytes(HEAP_BUF, block)
    return run_guarded(machine, RIPEMD, {RDI: HEAP_STATE, RSI: HEAP_BUF}, lambda m: struct.unpack("<5I", m.memory.bytes_at(HEAP_STATE, 20)))


# ---------------------------------------------------------------------------------------------------------------------------------------
# Reconstruction 1: Keccak-f[1600] and the sponge around it
# ---------------------------------------------------------------------------------------------------------------------------------------

RHO = (0, 1, 62, 28, 27, 36, 44, 6, 55, 20, 3, 10, 43, 25, 39, 41, 45, 15, 21, 8, 18, 2, 61, 56, 14)  # lane index x + 5y


class Panic(Exception):
    pass


def rol64(value, count):
    count %= 64
    return ((value << count) | (value >> (64 - count))) & M64 if count else value


class KeccakVariant:
    """Knobs of the f1600 reconstruction; the defaults are the reconstruction, every other setting is a deliberate wrong variant."""

    def __init__(self, **changes):
        self.rounds = 24
        self.rc = None
        self.rho = RHO
        self.theta_left = 1       # neighbour index of the column parity (x - 1)
        self.theta_rot = 1
        self.pi_mul = (2, 3)      # destination row = (2x + 3y) mod 5
        self.chi_step = (1, 2)
        self.chi_not = True
        self.iota = True
        self.iota_lane = 0
        self.rc_reverse = False
        for key, value in changes.items():
            if not hasattr(self, key):
                raise KeyError(key)
            setattr(self, key, value)


def keccak_f(lanes, rc, variant=None):
    v = variant or KeccakVariant()
    table = tuple(reversed(rc)) if v.rc_reverse else tuple(rc)
    a = list(lanes)
    for rnd in range(v.rounds):
        c = [a[x] ^ a[x + 5] ^ a[x + 10] ^ a[x + 15] ^ a[x + 20] for x in range(5)]
        d = [c[(x - v.theta_left) % 5] ^ rol64(c[(x + 1) % 5], v.theta_rot) for x in range(5)]
        a = [a[i] ^ d[i % 5] for i in range(25)]
        b = [0] * 25
        for x in range(5):
            for y in range(5):
                b[y + 5 * ((v.pi_mul[0] * x + v.pi_mul[1] * y) % 5)] = rol64(a[x + 5 * y], v.rho[x + 5 * y])
        out = [0] * 25
        for y in range(5):
            for x in range(5):
                second = b[(x + v.chi_step[0]) % 5 + 5 * y]
                third = b[(x + v.chi_step[1]) % 5 + 5 * y]
                out[x + 5 * y] = b[x + 5 * y] ^ ((~second & M64 if v.chi_not else second) & third)
        a = out
        if v.iota:
            a[v.iota_lane] ^= table[rnd % 24]
    return tuple(a)


class SpongeVariant:
    def __init__(self, **changes):
        self.pad_at = -1           # offset from rate of the 0x80 byte
        self.delim_on = True
        self.full_block_ge = True  # permute when the block is exactly full
        self.reset_on_squeeze_flag = True
        self.keep_pos_after_reset = False
        self.permute_after_pad = True
        self.permute_between_blocks = True
        self.clone = True
        for key, value in changes.items():
            if not hasattr(self, key):
                raise KeyError(key)
            setattr(self, key, value)


def state_bytes(lanes):
    return bytearray(struct.pack("<25Q", *lanes))


def lanes_of(buf):
    return struct.unpack("<25Q", bytes(buf))


def xor_into(buf, index, value):
    if not 0 <= index < 200:
        raise Panic("index")
    buf[index] ^= value


def sponge_absorb(lanes, pos, rate, delim, flag, data, rc, kv=None, sv=None):
    """Reconstruction of 0x5cda910: returns the 0xe0-byte structure fields after the write. Slice checks fire where the target performs them."""
    sv = sv or SpongeVariant()
    buf = state_bytes(lanes)
    if flag:
        flag = 0
        buf = state_bytes(keccak_f(lanes_of(buf), rc, kv))
        if not sv.keep_pos_after_reset:
            pos = 0
    elif rate < pos:
        raise Panic("range")
    if pos > 200:
        raise Panic("index")
    n = len(data)
    at = 0
    while (n - at) >= (rate - pos) if sv.full_block_ge else (n - at) > (rate - pos):
        take = rate - pos
        for i in range(take):
            xor_into(buf, pos + i, data[at + i])
        at += take
        buf = state_bytes(keccak_f(lanes_of(buf), rc, kv))
        pos = 0
    rest = n - at
    for i in range(rest):
        xor_into(buf, pos + i, data[at + i])
    pos += rest
    return lanes_of(buf), pos, rate, delim, flag


def sponge_squeeze(lanes, pos, rate, delim, flag, count, rc, kv=None, sv=None):
    """Reconstruction of 0x5cdad40: reads `count` bytes from a copy of the structure; returns (bytes, the unchanged original fields)."""
    sv = sv or SpongeVariant()
    original = (tuple(lanes), pos, rate, delim, flag)
    buf = state_bytes(lanes)
    if flag != 1:
        xor_into(buf, pos, delim) if sv.delim_on else None
        if pos >= 200 and not sv.delim_on:
            raise Panic("index")
        if rate == 0:
            raise Panic("underflow")
        xor_into(buf, rate + sv.pad_at, 0x80)
        if sv.permute_after_pad:
            buf = state_bytes(keccak_f(lanes_of(buf), rc, kv))
        pos = 0
    elif rate < pos:
        raise Panic("range")
    if pos > 200:
        raise Panic("index")
    out = bytearray()
    remain = count
    while remain:
        if pos == rate:
            if sv.permute_between_blocks:
                buf = state_bytes(keccak_f(lanes_of(buf), rc, kv))
            pos = 0
        take = min(remain, rate - pos)
        if pos + take > 200:
            raise Panic("index")
        out += buf[pos:pos + take]
        pos += take
        remain -= take
    return bytes(out), original


def keccak256_model(data, rc, kv=None, sv=None, chunks=None):
    lanes, pos, rate, delim, flag = (0,) * 25, 0, 136, 0x01, 0
    parts = chunks or [len(data)]
    at = 0
    for size in parts:
        lanes, pos, rate, delim, flag = sponge_absorb(lanes, pos, rate, delim, flag, data[at:at + size], rc, kv, sv)
        at += size
    out, _ = sponge_squeeze(lanes, pos, rate, delim, flag, 32, rc, kv, sv)
    return out


# ---------------------------------------------------------------------------------------------------------------------------------------
# Reconstruction 2: RIPEMD-160 block compression
# ---------------------------------------------------------------------------------------------------------------------------------------

R_LEFT = (0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 7, 4, 13, 1, 10, 6, 15, 3, 12, 0, 9, 5, 2, 14, 11, 8,
          3, 10, 14, 4, 9, 15, 8, 1, 2, 7, 0, 6, 13, 11, 5, 12, 1, 9, 11, 10, 0, 8, 12, 4, 13, 3, 7, 15, 14, 5, 6, 2,
          4, 0, 5, 9, 7, 12, 2, 10, 14, 1, 3, 8, 11, 6, 15, 13)
R_RIGHT = (5, 14, 7, 0, 9, 2, 11, 4, 13, 6, 15, 8, 1, 10, 3, 12, 6, 11, 3, 7, 0, 13, 5, 10, 14, 15, 8, 12, 4, 9, 1, 2,
           15, 5, 1, 3, 7, 14, 6, 9, 11, 8, 12, 2, 10, 0, 4, 13, 8, 6, 4, 1, 3, 11, 15, 0, 5, 12, 2, 13, 9, 7, 10, 14,
           12, 15, 10, 4, 1, 5, 8, 7, 6, 2, 13, 14, 0, 3, 9, 11)
S_LEFT = (11, 14, 15, 12, 5, 8, 7, 9, 11, 13, 14, 15, 6, 7, 9, 8, 7, 6, 8, 13, 11, 9, 7, 15, 7, 12, 15, 9, 11, 7, 13, 12,
          11, 13, 6, 7, 14, 9, 13, 15, 14, 8, 13, 6, 5, 12, 7, 5, 11, 12, 14, 15, 14, 15, 9, 8, 9, 14, 5, 6, 8, 6, 5, 12,
          9, 15, 5, 11, 6, 8, 13, 12, 5, 12, 13, 14, 11, 8, 5, 6)
S_RIGHT = (8, 9, 9, 11, 13, 15, 15, 5, 7, 7, 8, 11, 14, 14, 12, 6, 9, 13, 15, 7, 12, 8, 9, 11, 7, 7, 12, 7, 6, 15, 13, 11,
           9, 7, 15, 11, 8, 6, 6, 14, 12, 13, 5, 14, 13, 13, 7, 5, 15, 5, 8, 11, 14, 14, 6, 14, 6, 9, 12, 9, 12, 5, 15, 8,
           8, 5, 12, 9, 12, 5, 14, 6, 8, 13, 6, 5, 15, 13, 11, 11)
K_LEFT = (0x00000000, 0x5A827999, 0x6ED9EBA1, 0x8F1BBCDC, 0xA953FD4E)
K_RIGHT = (0x50A28BE6, 0x5C4DD124, 0x6D703EF3, 0x7A6D76E9, 0x00000000)
RIPEMD_IV = (0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0)


def rol32(value, count):
    count %= 32
    return ((value << count) | (value >> (32 - count))) & M32 if count else value


def ripemd_f(round_index, x, y, z):
    if round_index == 0:
        return x ^ y ^ z
    if round_index == 1:
        return (x & y) | (~x & M32 & z)
    if round_index == 2:
        return (x | (~y & M32)) ^ z
    if round_index == 3:
        return (x & z) | (y & ~z & M32)
    return x ^ (y | (~z & M32))


class RipemdVariant:
    def __init__(self, **changes):
        self.r_left = R_LEFT
        self.r_right = R_RIGHT
        self.s_left = S_LEFT
        self.s_right = S_RIGHT
        self.k_left = K_LEFT
        self.k_right = K_RIGHT
        self.right_function_reversed = True
        self.rol10 = 10
        self.combine = (0, 1, 2, 3, 4)    # which finished sum becomes new word i
        self.rounds = 80
        self.add_k = True
        self.swap_lines = False
        for key, value in changes.items():
            if not hasattr(self, key):
                raise KeyError(key)
            setattr(self, key, value)


def ripemd_compress(state, block, variant=None):
    v = variant or RipemdVariant()
    x = struct.unpack("<16I", bytes(block))
    h = list(state)
    al, bl, cl, dl, el = h
    ar, br, cr, dr, er = h
    for j in range(v.rounds):
        rnd = j // 16
        fl = ripemd_f(rnd, bl, cl, dl)
        fr = ripemd_f(4 - rnd if v.right_function_reversed else rnd, br, cr, dr)
        kl = v.k_left[rnd] if v.add_k else 0
        t = (rol32((al + fl + x[v.r_left[j]] + kl) & M32, v.s_left[j]) + el) & M32
        al, el, dl, cl, bl = el, dl, rol32(cl, v.rol10), bl, t
        t = (rol32((ar + fr + x[v.r_right[j]] + v.k_right[rnd]) & M32, v.s_right[j]) + er) & M32
        ar, er, dr, cr, br = er, dr, rol32(cr, v.rol10), br, t
    if v.swap_lines:
        al, bl, cl, dl, el, ar, br, cr, dr, er = ar, br, cr, dr, er, al, bl, cl, dl, el
    parts = (h[1] + cl + dr, h[2] + dl + er, h[3] + el + ar, h[4] + al + br, h[0] + bl + cr)
    return tuple(parts[v.combine[i]] & M32 for i in range(5))


def ripemd160_digest(data, compress):
    """Full RIPEMD-160 over `data`; `compress(state, block)` is either the model or the emulated target."""
    padded = bytes(data) + b"\x80" + bytes((55 - len(data)) % 64) + struct.pack("<Q", 8 * len(data))
    state = RIPEMD_IV
    for at in range(0, len(padded), 64):
        state = tuple(compress(state, padded[at:at + 64]))
    return struct.pack("<5I", *state)


# ---------------------------------------------------------------------------------------------------------------------------------------
# Deterministic input stream (nothing here depends on the binary)
# ---------------------------------------------------------------------------------------------------------------------------------------

class Stream:
    """xorshift64* generator with a fixed seed; the same sequence on every Python version."""

    def __init__(self, seed):
        self.s = (seed * 0x9E3779B97F4A7C15 + 0x1234567) & M64 or 1

    def next64(self):
        s = self.s
        s ^= s >> 12
        s ^= (s << 25) & M64
        s ^= s >> 27
        self.s = s
        return (s * 0x2545F4914F6CDD1D) & M64

    def below(self, n):
        return self.next64() % n

    def data(self, n):
        out = bytearray()
        while len(out) < n:
            out += struct.pack("<Q", self.next64())
        return bytes(out[:n])

    def lanes(self):
        return tuple(self.next64() for _ in range(25))

    def words(self, n):
        return tuple(self.next64() & M32 for _ in range(n))


def digest8(blob):
    return hashlib.sha256(blob).hexdigest()[:16]


# ---------------------------------------------------------------------------------------------------------------------------------------
# Case generators; each yields a tuple whose first item names the family
# ---------------------------------------------------------------------------------------------------------------------------------------

RATES = (72, 104, 136, 144, 168, 200, 1, 8, 64, 100, 199)


def f1600_inputs(count):
    s = Stream(11)
    yield (0,) * 25
    yield (M64,) * 25
    for lane in range(25):
        yield tuple(1 << (lane * 2 % 64) if i == lane else 0 for i in range(25))
    for bit in range(64):
        yield tuple((1 << bit) if i in (0, 24) else 0 for i in range(25))
    produced = 2 + 25 + 64
    while produced < count:
        yield s.lanes()
        produced += 1


def ripemd_inputs(count):
    s = Stream(23)
    zero = bytes(64)
    ones = b"\xff" * 64
    yield RIPEMD_IV, zero
    yield RIPEMD_IV, ones
    yield (0,) * 5, zero
    yield (M32,) * 5, ones
    for word in range(16):
        block = bytearray(64)
        block[4 * word:4 * word + 4] = b"\xff\xff\xff\xff"
        yield RIPEMD_IV, bytes(block)
    for index in range(5):
        state = [0] * 5
        state[index] = M32
        yield tuple(state), zero
    produced = 4 + 16 + 5
    while produced < count:
        yield s.words(5), s.data(64)
        produced += 1


def absorb_inputs(count):
    s = Stream(37)
    produced = 0
    while produced < count:
        rate = RATES[s.below(len(RATES))] if s.below(4) else 136
        pos = s.below(rate + 1) if s.below(8) else 0
        flag = 1 if s.below(5) == 0 else 0
        n = s.below(3 * rate + 40) if s.below(6) else s.below(8)
        if s.below(60) == 0:
            pos = 201 + s.below(40)
        if s.below(80) == 0:
            rate = 201 + s.below(50)
        if s.below(90) == 0 and rate > 1:
            pos = rate + 1 + s.below(3)
        delim = (1, 6, 0x1F, 0x80)[s.below(4)]
        yield s.lanes(), pos, rate, delim, flag, s.data(n)
        produced += 1


def squeeze_inputs(count):
    s = Stream(53)
    produced = 0
    while produced < count:
        rate = RATES[s.below(len(RATES))] if s.below(4) else 136
        pos = s.below(rate + 1) if s.below(3) else 0
        flag = 1 if s.below(3) == 0 else 0
        n = s.below(3 * rate + 40) if s.below(5) else s.below(40)
        if s.below(70) == 0:
            pos = 201 + s.below(30)
        if s.below(90) == 0:
            rate = 201 + s.below(30)
        if s.below(110) == 0:
            rate = 0
        delim = (1, 6, 0x1F, 0x80, 0)[s.below(5)]
        if rate == 0:
            flag = 0
        yield s.lanes(), pos, rate, delim, flag, n
        produced += 1


def hash_messages():
    s = Stream(71)
    for n in list(range(0, 140)) + [191, 192, 193, 255, 256, 257, 271, 272, 273, 408, 409, 1000]:
        yield s.data(n)


KECCAK_VECTORS = (
    (b"", "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470"),
    (b"abc", "4e03657aea45a94fc7d47ba826c8d667c0d1e6e33a64a036ec44f58fa12d6c45"),
    (b"The quick brown fox jumps over the lazy dog", "4d741b6f1eb29cb2a9b9911c82f56fa8d73b04959d3d9d222895df6c0b28aa15"),
)

RIPEMD_VECTORS = (
    (b"", "9c1185a5c5e9fc54612808977ee8f548b2258d31"),
    (b"a", "0bdc9d2d256b3ee9daae347be6f4dc835a467ffe"),
    (b"abc", "8eb208f7e05d987a9b044a8e98c6b087f15a0bfc"),
    (b"message digest", "5d0689ef49d2fae572b881b123a85ffa21595f36"),
    (b"abcdefghijklmnopqrstuvwxyz", "f71c27109c692c1b56bbdceb5b9d2865b3708dbc"),
    (b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq", "12a053384a9c0c88e405a06c27dcf49ada62eb2b"),
    (b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789", "b0e20b6e3116640286ed3a87a5713079b21f5189"),
    (b"1234567890" * 8, "9b752e45573d4b39f4dbd3323cab82bf63326bfb"),
)


# ---------------------------------------------------------------------------------------------------------------------------------------
# Comparison of the reconstruction with the captured bytes
# ---------------------------------------------------------------------------------------------------------------------------------------

CASE_PLAN = (("f1600", 2400), ("ripemd160_compress", 3600), ("absorb", 2200), ("squeeze", 1500))
FLOW_MESSAGES = 164
SAMPLE_EVERY = {"f1600": 4, "ripemd160_compress": 6, "absorb": 4, "squeeze": 3}
SAMPLE_CAP = {"f1600": 140, "ripemd160_compress": 160, "absorb": 160, "squeeze": 160}
KEEP_FOR_MUTANTS = 80


class Mismatch(Exception):
    pass


def model_f1600(rc, lanes):
    return keccak_f(lanes, rc)


def expected_absorb(rc, case, kv=None, sv=None):
    lanes, pos, rate, delim, flag, data = case
    try:
        return Outcome(value=sponge_absorb(lanes, pos, rate, delim, flag, data, rc, kv, sv))
    except Panic:
        return Outcome(stop="panic")


def expected_squeeze(rc, case, kv=None, sv=None):
    lanes, pos, rate, delim, flag, count = case
    try:
        out, original = sponge_squeeze(lanes, pos, rate, delim, flag, count, rc, kv, sv)
    except Panic:
        return Outcome(stop="panic")
    return Outcome(value=(out, original))


def describe(outcome):
    if outcome.stop:
        return "stop:" + outcome.stop
    return digest8(repr(outcome.value).encode())


def run_family(binary, machine, family, count, rc, kept, writer):
    """Run one family; every case must agree. Returns (cases, panics). `kept` receives the first cases for the mutant checks."""
    cases = panics = 0
    sampled = 0
    if family == "f1600":
        gen = f1600_inputs(count)
    elif family == "ripemd160_compress":
        gen = ripemd_inputs(count)
    elif family == "absorb":
        gen = absorb_inputs(count)
    else:
        gen = squeeze_inputs(count)
    for index, case in enumerate(gen):
        if family == "f1600":
            got = emu_f1600(machine, case)
            want = Outcome(value=model_f1600(rc, case))
            label = digest8(struct.pack("<25Q", *case))
        elif family == "ripemd160_compress":
            got = emu_ripemd(machine, case[0], case[1])
            want = Outcome(value=ripemd_compress(case[0], case[1]))
            label = digest8(struct.pack("<5I", *case[0]) + case[1])
        elif family == "absorb":
            got = emu_absorb(machine, *case)
            want = expected_absorb(rc, case)
            label = digest8(pack_struct(*case[:5]) + case[5])
        else:
            got = emu_squeeze(machine, *case)
            want = expected_squeeze(rc, case)
            label = digest8(pack_struct(*case[:5]) + struct.pack("<Q", case[5]))
        if got.key() != want.key():
            raise Mismatch("%s case %d: target %s, reconstruction %s" % (family, index, describe(got), describe(want)))
        cases += 1
        panics += 1 if got.stop else 0
        if len(kept[family]) < KEEP_FOR_MUTANTS and not got.stop:
            kept[family].append((case, got))
        if index % SAMPLE_EVERY[family] == 0 and sampled < SAMPLE_CAP[family]:
            writer.write("%s\t%d\t%s\t%s\t%s\n" % (family, index, label, describe(got), "stop" if got.stop else "match"))
            sampled += 1
    return cases, panics


def emu_keccak256(machine, data, chunks):
    lanes, pos, rate, delim, flag = (0,) * 25, 0, 136, 0x01, 0
    at = 0
    for size in chunks:
        got = emu_absorb(machine, lanes, pos, rate, delim, flag, data[at:at + size])
        if got.stop:
            raise Mismatch("absorb stopped: " + got.stop)
        lanes, pos, rate, delim, flag = got.value
        at += size
    got = emu_squeeze(machine, lanes, pos, rate, delim, flag, 32)
    if got.stop:
        raise Mismatch("squeeze stopped: " + got.stop)
    return got.value[0]


def emu_ripemd160(machine, data):
    def compress(state, block):
        got = emu_ripemd(machine, state, block)
        if got.stop:
            raise Mismatch("ripemd stopped: " + got.stop)
        return got.value

    return ripemd160_digest(data, compress)


def run_flows(machine, rc, writer):
    """Whole-hash flows: the target pieces must reproduce the published digests and the reconstruction on many message lengths."""
    cases = 0
    for data, digest in KECCAK_VECTORS:
        got = emu_keccak256(machine, data, [len(data)])
        if got.hex() != digest or keccak256_model(data, rc) != got:
            raise Mismatch("keccak256 vector %r" % data[:12])
        cases += 1
    for data, digest in RIPEMD_VECTORS:
        if emu_ripemd160(machine, data).hex() != digest:
            raise Mismatch("ripemd160 vector %r" % data[:12])
        cases += 1
    for index, data in enumerate(hash_messages()):
        split = (index * 37) % (len(data) + 1)
        chunks = [split, len(data) - split] if index % 2 else [len(data)]
        got = emu_keccak256(machine, data, chunks)
        if got != keccak256_model(data, rc, chunks=chunks) or got != keccak256_model(data, rc):
            raise Mismatch("keccak256 flow at message %d" % index)
        if emu_ripemd160(machine, data) != ripemd160_digest(data, lambda s, b: ripemd_compress(s, b)):
            raise Mismatch("ripemd160 flow at message %d" % index)
        cases += 2
        if index % 4 == 0:
            writer.write("flow\t%d\t%s\t%s\tmatch\n" % (index, digest8(data), digest8(got)))
    return cases


# ---------------------------------------------------------------------------------------------------------------------------------------
# Negative controls: deliberately wrong reconstructions and corrupted bytes must all be told apart from the target
# ---------------------------------------------------------------------------------------------------------------------------------------

def flip_rho(index, delta):
    rho = list(RHO)
    rho[index] = (rho[index] + delta) % 64
    return tuple(rho)


def swap_rc(rc, index, value):
    table = list(rc)
    table[index] = value
    return tuple(table)


def keccak_mutants(rc):
    return (
        ("keccak-23-rounds", KeccakVariant(rounds=23), rc),
        ("keccak-25-rounds-wraps-constant", KeccakVariant(rounds=25), rc),
        ("keccak-no-iota", KeccakVariant(iota=False), rc),
        ("keccak-iota-on-lane-1", KeccakVariant(iota_lane=1), rc),
        ("keccak-constants-reversed", KeccakVariant(rc_reverse=True), rc),
        ("keccak-first-constant-flipped", KeccakVariant(), swap_rc(rc, 0, rc[0] ^ 1)),
        ("keccak-last-constant-flipped", KeccakVariant(), swap_rc(rc, 23, rc[23] ^ (1 << 63))),
        ("keccak-rho-lane-1", KeccakVariant(rho=flip_rho(1, 1)), rc),
        ("keccak-rho-lane-24", KeccakVariant(rho=flip_rho(24, -1)), rc),
        ("keccak-theta-rotate-2", KeccakVariant(theta_rot=2), rc),
        ("keccak-theta-left-neighbour-2", KeccakVariant(theta_left=2), rc),
        ("keccak-pi-transposed", KeccakVariant(pi_mul=(3, 2)), rc),
        ("keccak-chi-step-2-3", KeccakVariant(chi_step=(2, 3)), rc),
        ("keccak-chi-without-not", KeccakVariant(chi_not=False), rc),
    )


def ripemd_mutants():
    def tweak(table, index, delta, mod):
        out = list(table)
        out[index] = (out[index] + delta) % mod
        return tuple(out)

    return (
        ("ripemd-left-constant-round-2", RipemdVariant(k_left=tweak(K_LEFT, 2, 1, 1 << 32))),
        ("ripemd-right-constant-round-0", RipemdVariant(k_right=tweak(K_RIGHT, 0, 1, 1 << 32))),
        ("ripemd-right-function-not-reversed", RipemdVariant(right_function_reversed=False)),
        ("ripemd-left-selector-step-17", RipemdVariant(r_left=tweak(R_LEFT, 17, 1, 16))),
        ("ripemd-right-selector-step-79", RipemdVariant(r_right=tweak(R_RIGHT, 79, 1, 16))),
        ("ripemd-left-shift-step-0", RipemdVariant(s_left=tweak(S_LEFT, 0, 1, 32))),
        ("ripemd-right-shift-step-63", RipemdVariant(s_right=tweak(S_RIGHT, 63, 1, 32))),
        ("ripemd-rotate-9-not-10", RipemdVariant(rol10=9)),
        ("ripemd-79-steps", RipemdVariant(rounds=79)),
        ("ripemd-lines-swapped", RipemdVariant(swap_lines=True)),
        ("ripemd-combine-rotated", RipemdVariant(combine=(1, 2, 3, 4, 0))),
        ("ripemd-left-constant-dropped", RipemdVariant(add_k=False)),
    )


def sponge_mutants():
    return (
        ("sponge-pad-at-rate-not-last", SpongeVariant(pad_at=0), "squeeze"),
        ("sponge-pad-before-last-byte", SpongeVariant(pad_at=-2), "squeeze"),
        ("sponge-delimiter-ignored", SpongeVariant(delim_on=False), "squeeze"),
        ("sponge-no-permute-after-pad", SpongeVariant(permute_after_pad=False), "squeeze"),
        ("sponge-no-permute-between-blocks", SpongeVariant(permute_between_blocks=False), "squeeze"),
        ("sponge-absorb-strictly-greater", SpongeVariant(full_block_ge=False), "absorb"),
        ("sponge-absorb-keeps-position-after-reset", SpongeVariant(keep_pos_after_reset=True), "absorb"),
    )


class Control:
    def __init__(self, name, kind, detected, evidence):
        self.name, self.kind, self.detected, self.evidence = name, kind, detected, evidence


def differs(machine_results, expected_fn):
    """True when at least one kept case disagrees; machine_results = [(case, outcome), ...]."""
    for case, got in machine_results:
        if got.key() != expected_fn(case).key():
            return True
    return False


def byte_targets(binary):
    """Immediate bytes of rotate instructions in the two large bodies: corrupting one must change the target's answers."""
    picks = []
    for name in ("f1600", "ripemd160_compress"):
        seen = set()
        for row in binary.rows[name]:
            if row.op in ("rol", "ror") and row.imm_at is not None and row.imm_size == 1:
                key = (row.b[1] if row.b and row.b[0] == "i" else None)
                if key in seen:
                    continue
                seen.add(key)
                picks.append((name, row))
    return picks


def corrupt_controls(binary, rc, kept):
    controls = []
    picks = byte_targets(binary)
    chosen = []
    for name in ("f1600", "ripemd160_compress"):
        group = [p for p in picks if p[0] == name]
        step = max(1, len(group) // 5)
        chosen += group[::step][:5]
    for name, row in chosen:
        site = row.va + row.imm_at
        patched = {site: (binary.image.blob[binary.image.offset(site)] ^ 0x01)}
        machine = make_machine(binary, patches=patched)
        family = name
        pool = kept[family][:6]
        found = False
        for case, want in pool:
            got = emu_f1600(machine, case) if family == "f1600" else emu_ripemd(machine, case[0], case[1])
            if got.key() != want.key():
                found = True
                break
        controls.append(Control("byte-xor1-immediate-%s-%x" % (name, site), "corrupted-bytes", found, "va %#x" % site))
    for index in (0, 11, 23):
        machine = make_machine(binary, rc_override=swap_rc(rc, index, rc[index] ^ (1 << 5)))
        found = any(emu_f1600(machine, case).key() != want.key() for case, want in kept["f1600"][:4])
        controls.append(Control("table-constant-%d-bit5" % index, "corrupted-bytes", found, "va %#x" % (RC_TABLE + 8 * index)))
    return controls


def out_of_range_controls(binary, rc, machine):
    """Inputs outside the contract: the reconstruction must classify them like the target does, so asking it with a different class disagrees."""
    controls = []
    lanes = Stream(5).lanes()
    got = emu_absorb(machine, lanes, 201, 136, 1, 0, b"abc")
    controls.append(Control("range-absorb-position-201-is-a-stop", "out-of-range", got.stop == "panic", "stop=%s" % got.stop))
    got = emu_squeeze(machine, lanes, 0, 201, 1, 0, 8)
    controls.append(Control("range-squeeze-rate-201-is-a-stop", "out-of-range", got.stop == "panic", "stop=%s" % got.stop))
    got = emu_absorb(machine, lanes, 100, 136, 0, 0, b"\x01" * 64)
    controls.append(Control("range-model-wrong-stop-class", "out-of-range", got.stop is None and expected_absorb(rc, (lanes, 100, 136, 0, 0, b"\x01" * 64)).stop is None, "ok"))
    return controls


def check_binary_digest(digest_hex):
    return digest_hex == SHA256


def digest_controls(binary):
    controls = []
    blob = memoryview(binary.image.blob)
    for name, at in (("digest-first-byte-flipped", 0), ("digest-code-byte-flipped", binary.image.offset(RIPEMD) + 100)):
        h = hashlib.sha256()
        h.update(blob[:at])
        h.update(bytes([blob[at] ^ 0x01]))
        h.update(blob[at + 1:])
        controls.append(Control(name, "corrupted-bytes", not check_binary_digest(h.hexdigest()), "offset %d" % at))
    h = hashlib.sha256()
    h.update(blob[:-1])
    controls.append(Control("digest-truncated-by-one-byte", "corrupted-bytes", not check_binary_digest(h.hexdigest()), "length-1"))
    return controls


def model_controls(binary, rc, kept):
    controls = []
    f_pool = kept["f1600"][:16]
    for name, variant, table in keccak_mutants(rc):
        found = differs(f_pool, lambda case, v=variant, t=table: Outcome(value=keccak_f(case, t, v)))
        controls.append(Control(name, "wrong-reconstruction", found, "f1600 first %d cases" % len(f_pool)))
    r_pool = kept["ripemd160_compress"][:16]
    for name, variant in ripemd_mutants():
        found = differs(r_pool, lambda case, v=variant: Outcome(value=ripemd_compress(case[0], case[1], v)))
        controls.append(Control(name, "wrong-reconstruction", found, "ripemd first %d cases" % len(r_pool)))
    for name, variant, family in sponge_mutants():
        if family == "absorb":
            pool = kept["absorb"]
            found = differs(pool, lambda case, v=variant: expected_absorb(rc, case, None, v))
        else:
            pool = kept["squeeze"]
            found = differs(pool, lambda case, v=variant: expected_squeeze(rc, case, None, v))
        controls.append(Control(name, "wrong-reconstruction", found, "%s first %d cases" % (family, len(pool))))
    return controls


EQUIVALENT_REASONS = {}


# ---------------------------------------------------------------------------------------------------------------------------------------
# Evidence files
# ---------------------------------------------------------------------------------------------------------------------------------------

def instruction_table(binary, writer):
    writer.write("function\tva\tsize\top\tbytes\n")
    total = 0
    for name, start, _ in FUNCTIONS:
        for row in binary.rows[name]:
            writer.write("%s\t%#x\t%d\t%s\t%s\n" % (name, row.va, row.size, row.op, row.data.hex()))
            total += 1
    return total


def immediate_of(binary, row):
    if row.imm_at is None:
        return None
    at = binary.image.offset(row.va + row.imm_at)
    return int.from_bytes(binary.image.blob[at:at + row.imm_size], "little")


def constants_report(binary, rc):
    rol_counts = {}
    immediates32 = set()
    for name in ("f1600", "ripemd160_compress"):
        counts = {}
        for row in binary.rows[name]:
            if row.op in ("rol", "ror") and row.imm_at is not None:
                key = "%s %d" % (row.op, immediate_of(binary, row))
                counts[key] = counts.get(key, 0) + 1
            value = immediate_of(binary, row)
            if name == "ripemd160_compress" and value is not None and row.imm_size == 4:
                immediates32.add(value)
        rol_counts[name] = dict(sorted(counts.items()))
    expected_k = [k for k in K_LEFT + K_RIGHT if k]
    found = {("%#010x" % k): (k in immediates32) for k in expected_k}
    return {
        "round_constant_table_va": "%#x" % RC_TABLE,
        "round_constants": ["%#018x" % c for c in rc],
        "rotate_immediates": rol_counts,
        "ripemd_constants_found_as_instruction_immediates": found,
        "rho_offsets_reconstruction": list(RHO),
        "ripemd_left_selectors": list(R_LEFT),
        "ripemd_right_selectors": list(R_RIGHT),
        "ripemd_left_shifts": list(S_LEFT),
        "ripemd_right_shifts": list(S_RIGHT),
    }


def check_reconstruction_tables(binary, rc):
    """Cross-checks that do not need execution: the constants the model uses are present in the decoded bytes."""
    report = constants_report(binary, rc)
    if not all(report["ripemd_constants_found_as_instruction_immediates"].values()):
        raise Mismatch("a RIPEMD constant is missing from the decoded immediates")
    if rc[0] != 1 or rc[1] != 0x8082 or rc[23] != 0x8000000080008008:
        raise Mismatch("round constant table is not the expected Keccak table")
    # independent anchor for the model: the NIST SHA3-256 digest of the empty message with the 0x06 delimiter
    anchor = keccak256_model(b"", rc, sv=None)
    if anchor.hex() != KECCAK_VECTORS[0][1]:
        raise Mismatch("model keccak256 of the empty message")
    return report


def tsv_row(*fields):
    return "\t".join(str(f) for f in fields) + "\n"


def generate(out_dir):
    out = pathlib.Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    binary = Binary()
    rc = binary.rc_table()
    report = check_reconstruction_tables(binary, rc)
    machine = make_machine(binary)
    kept = {name: [] for name, _ in CASE_PLAN}
    totals = {}
    panics = {}
    with open(out / "cases.tsv", "w", newline="\n") as cases_file:
        cases_file.write("family\tindex\tinput_digest\tresult_digest\tstatus\n")
        for family, count in CASE_PLAN:
            totals[family], panics[family] = run_family(binary, machine, family, count, rc, kept, cases_file)
        totals["whole-hash flows"] = run_flows(machine, rc, cases_file)
    controls = model_controls(binary, rc, kept) + corrupt_controls(binary, rc, kept) + out_of_range_controls(binary, rc, machine) + digest_controls(binary)
    detected = [c for c in controls if c.detected]
    missed = [c for c in controls if not c.detected]
    unexplained = [c.name for c in missed if c.name not in EQUIVALENT_REASONS]
    if unexplained:
        raise Mismatch("undetected controls without an equivalence argument: %s" % ", ".join(unexplained))
    cases = sum(totals.values())
    with open(out / "negative-controls.tsv", "w", newline="\n") as handle:
        handle.write("control\tkind\tdetected\tevidence\n")
        for c in controls:
            handle.write(tsv_row(c.name, c.kind, "yes" if c.detected else "no", c.evidence))
    with open(out / "equivalent-mutants.tsv", "w", newline="\n") as handle:
        handle.write("mutant\taddress\treason\n")
        for c in missed:
            handle.write(tsv_row(c.name, c.evidence, EQUIVALENT_REASONS[c.name]))
    with open(out / "functions.tsv", "w", newline="\n") as handle:
        handle.write("name\tstart\tend\tbytes\tinstructions\tsha256\trole\n")
        for name, start, role in FUNCTIONS:
            _, end = binary.extent(name)
            body = binary.function_bytes(name)
            handle.write(tsv_row(name, "%#x" % start, "%#x" % end, len(body), len(binary.rows[name]), hashlib.sha256(body).hexdigest(), role))
    with open(out / "decoded-instructions.tsv", "w", newline="\n") as handle:
        rows = instruction_table(binary, handle)
    (out / "constants.json").write_text(json.dumps(report, indent=1, sort_keys=True) + "\n")
    slots = {}
    for name in ("absorb", "squeeze"):
        slots[name] = ["%#x" % s for s in sorted(set(slot_targets(binary.rows[name])))]
    summary = {
        "target_sha256": SHA256,
        "functions": {name: {"start": "%#x" % start, "end": "%#x" % binary.extent(name)[1]} for name, start, _ in FUNCTIONS},
        "cases_by_family": totals,
        "stops_agreed_by_family": panics,
        "decoded_instructions": rows,
        "indirect_call_slots": slots,
        "f1600_slot": "%#x" % SLOT_F1600,
        "memcpy_slot": "%#x" % SLOT_MEMCPY,
        "negative_controls": len(controls),
        "negative_detected": len(detected),
        "equivalent": len(missed),
    }
    (out / "summary.json").write_text(json.dumps(summary, indent=1, sort_keys=True) + "\n")
    (out / "measure.json").write_text(json.dumps({"cases": cases, "negative_controls": len(controls), "negative_detected": len(detected),
                                                   "equivalent": len(missed)}, indent=1, sort_keys=True) + "\n")
    manifest = []
    for path in sorted(out.iterdir()):
        if path.name in ("MANIFEST.sha256", "README.md"):
            continue
        manifest.append("%s  %s\n" % (hashlib.sha256(path.read_bytes()).hexdigest(), path.name))
    (out / "MANIFEST.sha256").write_text("".join(manifest))
    return summary


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--out", required=True)
    args = parser.parse_args()
    summary = generate(args.out)
    print(json.dumps({k: summary[k] for k in ("cases_by_family", "negative_controls", "negative_detected", "equivalent")}, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
