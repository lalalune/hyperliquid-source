#!/usr/bin/env python3
"""Rebuild the node #115 per-asset price-map builder at 0x55be0d0 and prove it on the bytes.

The function takes a market index, looks up the market record (0x510 bytes) and either leaves early
(two option words unset, or a flag set) or walks `n` slots: for each slot key = dex*10000 + i it finds an asset id in a
per-market ring or B-tree, asks a time-dependent price lookup for that asset, scales the price by a clamped f64 factor
(the factor is 1.0 for two four-letter dex-0 names), rounds, saturates to u64 with a floor of one, divides by a power of ten
chosen from the asset's size-decimals byte, converts the f64 to a 96-bit decimal and inserts (key, decimal) into a local map.
The accumulated map goes to the next stage at 0x55c0010 together with the argument map that arrived by value.
The real bytes of the root, the ring search 0x45547e0, the B-tree search 0x35bd660, the f64 to decimal kernel 0x5c43c60 and the
libm-style round at 0x63efe40 run in a Python x86-64 evaluator; the allocator, the drop glue, the price lookup, the map insert,
the next stage and the panic edges are contracts. A separately written specification predicts every outcome, every event and the
decimal payloads; conditions and immediates of the root are then mutated to show the comparison can fail.
No disassembler text is parsed and the binary is never executed. Standard library plus the shared repository parsers.
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



import decimal_from_f64_115 as dec_tool  # noqa: E402

kernel_spec = dec_tool.spec_kernel


# ---- target facts (observations from the bytes) ----

ROOT_FN = 0x55BE0D0
BTREE_SEARCH = 0x35BD660
RING_SEARCH = 0x45547E0
KERNEL = 0x5C43C60
ROUND_FN = 0x63EFE40
INSERT = 0x4DD6150
NEXT_STAGE = 0x55C0010
DROP_A, DROP_B, DROP_C, DROP_VEC = 0x44E0810, 0x5630000, 0x42320D0, 0x5620510
DYING_NEXT = 0x51DA3A0
REAL = frozenset((ROOT_FN, BTREE_SEARCH, RING_SEARCH, KERNEL, ROUND_FN))
DIRECT_STUBS = (DROP_A, DROP_B, DROP_C, DROP_VEC, DYING_NEXT, INSERT, NEXT_STAGE)

SLOT_FREE, SLOT_PRICE, SLOT_ROUND = 0x64DF4A0, 0x64E78B0, 0x64E1890
SLOT_MUL, SLOT_ADD, SLOT_ASSERT, SLOT_INDEX, SLOT_UNWRAP = 0x64DF870, 0x64DF520, 0x64DF830, 0x64DF848, 0x64DF6A0
SLOTS = (SLOT_FREE, SLOT_PRICE, SLOT_ROUND, SLOT_MUL, SLOT_ADD, SLOT_ASSERT, SLOT_INDEX, SLOT_UNWRAP)
PANIC_KIND = {SLOT_MUL: "mul", SLOT_ADD: "add", SLOT_ASSERT: "assert", SLOT_INDEX: "index", SLOT_UNWRAP: "unwrap"}

# call-site return addresses used to name events
SITE_ENTRY_A, SITE_ENTRY_B = 0x55BE119, 0x55BE13F
SITE_FREE, SITE_NEXT, SITE_PRICE = 0x55BE22B, 0x55BE86B, 0x55BE453
SITE_DROP_OK, SITE_INSERT, SITE_DROP_ERR, SITE_FINAL = 0x55BE75D, 0x55BE7A2, 0x55BE338, 0x55BE831

NICHE = 0x8000000000000000
U64 = (1 << 64) - 1
MARKET_SIZE = 0x510
KEY_STRIDE = 10000
ROW_SIZE = 32
HYPE, PURR = 0x45505948, 0x52525550
POW10 = (1.0, 10.0, 100.0, 1000.0, 10000.0, 100000.0, 1000000.0)
ROUND_BIAS = 0.49999999999999994
SAT_LIMIT = 1.844674407370955e19
CLAMP_TOP = 1.8446744073709552e19

H = HEAP_BASE
CTX = H + 0x1000
OUT = H + 0x1800
ARG = H + 0x1840
TAIL = H + 0x1880
MARKETS = H + 0x2000
ROWS = H + 0x3000
NAMES = H + 0x3400
ARG_BUF = H + 0x3600
RING = H + 0x4000
NODES = H + 0x8000
USED = 0x12000
LEAF_KEYS, KEYS_AT, VALUES_AT, LEN_AT, CHILDREN_AT, LEAF_SIZE, NODE_SIZE = 11, 8, 0x60, 0xBA, 0xC0, 0xC0, 0x120


def signed_ok(value):
    return value & U64


def pack_decimal(flags, high, low_mid):
    return struct.pack("<IIQ", flags, high, low_mid)


# ---- memory layout of one case ----


def tree_capacity(height):
    capacity = LEAF_KEYS
    for _ in range(height):
        capacity = 12 * capacity + 11
    return capacity


def tree_minimum(height):
    smallest = 0
    for _ in range(height):
        smallest = 1 + 2 * smallest
    return smallest


def tree_children(count, height):
    for children in range(2, 13):
        spare = count - (children - 1)
        if spare >= children * tree_minimum(height - 1) and -(-spare // children) <= tree_capacity(height - 1):
            return children
    return None


def tree_fits(count, height):
    return count <= LEAF_KEYS if height == 0 else tree_children(count, height) is not None


class Layout:
    def __init__(self, memory):
        self.memory = memory
        self.next = NODES

    def word(self, at, value, size=8):
        self.memory.write(at, size, value & MASK[8])

    def node(self, size):
        at = self.next
        self.next += size
        return at

    def tree(self, items, height):
        if height == 0:
            at = self.node(LEAF_SIZE)
            for slot, (key, value) in enumerate(items):
                self.word(at + KEYS_AT + slot * 8, key)
                self.word(at + VALUES_AT + slot * 8, value)
            self.word(at + LEN_AT, len(items), 2)
            return at
        children = tree_children(len(items), height)
        spare = len(items) - (children - 1)
        at = self.node(NODE_SIZE)
        groups, separators, taken = [], [], 0
        for child in range(children):
            size = spare // children + (1 if child < spare % children else 0)
            groups.append(items[taken:taken + size])
            taken += size
            if child < children - 1:
                separators.append(items[taken])
                taken += 1
        for slot, (key, value) in enumerate(separators):
            self.word(at + KEYS_AT + slot * 8, key)
            self.word(at + VALUES_AT + slot * 8, value)
        self.word(at + LEN_AT, len(separators), 2)
        for slot, group in enumerate(groups):
            self.word(at + CHILDREN_AT + slot * 8, self.tree(group, height - 1))
        return at

    def container(self, at, spec, buffer):
        if spec["kind"] == "tree":
            self.word(at, NICHE)
            root = self.tree(sorted(spec["items"].items()), spec["height"]) if spec["root"] else 0
            self.word(at + 8, root)
            self.word(at + 0x10, spec["height"])
            self.word(at + 0x18, len(spec["items"]))
        else:
            self.word(at, spec["cap"])
            self.word(at + 8, buffer)
            self.word(at + 0x10, spec["head"])
            self.word(at + 0x18, len(spec["items"]))
            for index, (key, value) in enumerate(sorted(spec["items"].items())):
                slot = (spec["head"] + index) % spec["cap"]
                self.word(buffer + slot * 16, key)
                self.word(buffer + slot * 16 + 8, value)


def lookup(spec, key):
    """The value stored under key in a container spec, or None; an empty tree root counts as absent."""
    if spec["kind"] == "tree" and not spec["root"]:
        return None
    return spec["items"].get(key)


# ---- specification (written from the listing, no byte execution) ----


def round_ref(value):
    """x + copysign(0.49999999999999994, x), then truncate toward zero; non-finite values pass through."""
    if math.isnan(value) or math.isinf(value):
        return value
    shifted = value + math.copysign(ROUND_BIAS, value)
    if math.isinf(shifted):
        return shifted
    return math.copysign(float(math.trunc(shifted)), shifted)


def saturate_u64(value):
    if value < 0:
        return 0
    if value > SAT_LIMIT:
        return U64
    return int(value)


def decimal_of(value):
    """Decimal payload of a positive normal f64 through the independent converter specification."""
    bits = to_bits(value)
    exponent = bits >> 52 & 0x7FF
    fraction = bits & ((1 << 52) - 1)
    lo, mid = fraction & 0xFFFFFFFF, (fraction >> 32) | 0x100000
    return kernel_spec(lo, mid, 0, exponent - 1075, int(bits >> 63 == 0), 1, 1)


def scale_factor(case, asset, first):
    base = (case["factor"] - 1.0) + 1.0
    if first["mult"] == 0:
        rows = case["rows"]
        if asset > 9999 or asset >= len(rows) or len(rows[asset][0]) != 4:
            return base
        word = int.from_bytes(rows[asset][0], "little")
        if word in (HYPE, PURR):
            return 1.0
    return base


def spec(case):
    """(outcome, events) for a case; outcome is ("ret", out_tag_or_None) or ("panic", kind)."""
    markets = case["markets"]
    if case["index"] >= len(markets):
        return ("panic", "unwrap"), []
    market, first = markets[case["index"]], markets[0]
    events = [("drop", SITE_ENTRY_A, 0x156), ("drop", SITE_ENTRY_B, 0x156)]

    def release():
        arg = case["arg"]
        if arg["kind"] == "tree":
            root, height, length = arg["words"][1], arg["words"][2], arg["words"][3]
            state = (1, 0, root, height, 1, 0, root, height, length) if root else (0, None, None, None, 0, None, None, None, 0)
            for _ in range(arg["pulls"] + 1):
                events.append(("next",) + state)
        elif arg["cap"]:
            events.append(("free", arg["ptr"], arg["cap"] * 24, 0))

    if market["o378"] == NICHE or market["o408"] == NICHE + 1:
        release()
        return ("ret", 0x19E), events
    if market["flag"]:
        release()
        return ("ret", 0x101), events
    price_table = case["prices"]
    inserted = 0
    for i in range(market["n"]):
        high = KEY_STRIDE * market["mult"]
        if high > U64:
            return ("panic", "mul"), events
        key = high + i
        if key > U64:
            return ("panic", "add"), events
        container = market["lookup"]
        asset = lookup(container, key)
        if asset is None:
            continue
        price = price_table.get(asset, 0)
        events.append(("price", asset, case["p60"], case["p68"], 0))
        if price == 0:
            continue
        scaled = round_ref(float(price) * scale_factor(case, asset, first))
        if not scaled > 0.0:
            scaled = 0.0
        if math.isinf(scaled):
            clamped = 0.0
        else:
            clamped = CLAMP_TOP if scaled > CLAMP_TOP else scaled
        quantity = max(1, saturate_u64(clamped))
        if asset // KEY_STRIDE != first["mult"]:
            return ("panic", "assert"), events
        local = asset - asset // KEY_STRIDE * KEY_STRIDE
        if local >= len(case["rows"]):
            return ("panic", "assert"), events
        decimals = case["rows"][local][1]
        if decimals >= 7:
            return ("panic", "index"), events
        value = float(quantity) / POW10[6 - decimals]
        payload = decimal_of(value)
        events.append(("drop", SITE_DROP_OK if payload else SITE_DROP_ERR, 0xB0))
        if payload:
            events.append(("insert", key, pack_decimal(*payload)))
            inserted += 1
    events.append(("final", case["index"], struct.pack("<4Q", *case["arg"]["words"]), bytes((1,)) + bytes(case["tail"]), struct.pack("<4Q", 0, 8, 0, 0)))
    return ("ret", None), events


# ---- the evaluator harness ----


class Harness:
    def __init__(self, image, patches=None, limit=STEP_LIMIT):
        self.image = image
        self.machine = Machine(image, patches)
        self.machine.step_limit = limit if not patches else MUTANT_STEP_LIMIT
        machine = self.machine
        relative = image.relative()
        for slot in SLOTS:
            machine.memory.statics[slot] = relative[slot]
        machine.slots = {
            relative[SLOT_FREE]: self.on_free, relative[SLOT_PRICE]: self.on_price,
            relative[SLOT_MUL]: self.panic(SLOT_MUL), relative[SLOT_ADD]: self.panic(SLOT_ADD),
            relative[SLOT_ASSERT]: self.panic(SLOT_ASSERT), relative[SLOT_INDEX]: self.panic(SLOT_INDEX),
            relative[SLOT_UNWRAP]: self.panic(SLOT_UNWRAP),
        }
        self.round_target = relative[SLOT_ROUND]
        machine.real = REAL
        machine.calls = {
            DROP_A: self.on_drop, DROP_B: self.on_drop, DROP_C: self.on_drop, DROP_VEC: self.on_drop_vec,
            DYING_NEXT: self.on_next, INSERT: self.on_insert, NEXT_STAGE: self.on_stage,
        }
        self.layout = Layout(machine.memory)
        self.events = []
        self.prices = {}
        self.pulls = 0
        self.pulled = 0

    def site(self, machine):
        return machine.memory.read(machine.regs[RSP], 8)

    def panic(self, slot):
        def hook(machine):
            raise Panicked((PANIC_KIND[slot],))
        return hook

    def on_free(self, machine):
        regs = machine.regs
        self.events.append(("free", regs[RDI], regs[RSI], regs[RDX] & MASK[4]))

    def on_price(self, machine):
        regs, memory = machine.regs, machine.memory
        if regs[RDI] != self.first_container:
            raise Halt("price lookup received an unexpected container pointer")
        asset = regs[RSI]
        self.events.append(("price", asset, memory.read(regs[RDX], 8), memory.read(regs[RDX] + 8, 4), regs[RCX] & MASK[1]))
        regs[RAX] = self.prices.get(asset, 0)

    def on_drop(self, machine):
        self.events.append(("drop", self.site(machine), machine.memory.read(machine.regs[RDI], 2)))

    def on_drop_vec(self, machine):
        self.events.append(("drop-vec", self.site(machine)))

    def on_next(self, machine):
        self.pulled += 1
        words = [machine.memory.read(machine.regs[RSI] + 8 * k, 8) for k in range(9)]
        if words[0] == 0:
            words = [word if k in (0, 4, 8) else None for k, word in enumerate(words)]
        self.events.append(("next",) + tuple(words))
        machine.memory.write(machine.regs[RDI], 8, 1 if self.pulled <= self.pulls else 0)

    def on_insert(self, machine):
        regs, memory = machine.regs, machine.memory
        self.events.append(("insert", regs[RDX], memory.bytes_at(regs[RCX], 16)))

    def on_stage(self, machine):
        regs, memory = machine.regs, machine.memory
        stack_arg = memory.read(regs[RSP] + 8, 8)
        self.events.append(("final", (stack_arg - MARKETS) // MARKET_SIZE if (stack_arg - MARKETS) % MARKET_SIZE == 0 else -1,
                            memory.bytes_at(regs[RCX], 32), memory.bytes_at(regs[R8], 22), memory.bytes_at(regs[R9], 32)))
        self.checks = (regs[RDI] == OUT, regs[RSI] == CTX, regs[RDX] & MASK[4])

    # -- runs --

    def prepare(self, case):
        memory = self.machine.memory
        memory.reset(USED)
        layout = self.layout
        layout.next = NODES
        self.events = []
        self.prices = case["prices"]
        self.pulls, self.pulled = case["arg"]["pulls"], 0
        self.checks = None
        for base, size in ((CTX, 0x800), (MARKETS, 3 * MARKET_SIZE), (ROWS, 0x400)):
            memory.put_bytes(base, bytes((position * 167 + 91 + (position >> 3) * 13) & 0xFF for position in range(size)))
        layout.word(CTX + 0x60, case["p60"])
        layout.word(CTX + 0x68, case["p68"], 4)
        layout.word(CTX + 0x7A0, to_bits(case["factor"]))
        layout.word(CTX + 0x7C8, MARKETS)
        layout.word(CTX + 0x7D0, len(case["markets"]))
        for number, market in enumerate(case["markets"]):
            at = MARKETS + number * MARKET_SIZE
            layout.word(at + 0x10, market["n"])
            layout.word(at + 0x50, market["mult"])
            layout.word(at + 0x58, market["flag"])
            layout.word(at + 0x378, market["o378"])
            layout.word(at + 0x408, market["o408"])
            layout.container(at + 0x428, market["lookup"], RING + number * 0x400)
        first = MARKETS
        layout.word(first + 8, ROWS)
        layout.word(first + 0x10, len(case["rows"]))
        for number, (name, decimals) in enumerate(case["rows"]):
            at = ROWS + number * ROW_SIZE
            layout.word(at + 8, NAMES + number * 8)
            layout.word(at + 0x10, len(name))
            memory.put_bytes(NAMES + number * 8, bytes(name).ljust(8, b"\0"))
            memory.put_bytes(at + 0x1D, bytes((decimals,)))
        self.first_container = first + 0x148
        memory.put_bytes(TAIL, bytes(case["tail"]))
        for number, word in enumerate(case["arg"]["words"]):
            layout.word(ARG + 8 * number, word)

    def run(self, case):
        self.prepare(case)
        machine = self.machine
        args = {RDI: OUT, RSI: CTX, RDX: TAIL, RCX: case["index"], R8: ARG}
        try:
            machine.run(ROOT_FN, args)
        except Panicked as stop:
            return ("panic", stop.args[0][0]), self.events
        written = machine.memory.read(OUT, 2)
        has_final = any(event[0] == "final" for event in self.events)
        return ("ret", None if has_final else written), self.events




# ---- cases ----

NAME_POOL = (b"HYPE", b"PURR", b"USDC", b"HYPD", b"ABCD", b"BTC", b"", b"HYPEX", b"purr", b"PURS", b"HYPE", b"PURR")
DEC_POOL = (0, 1, 2, 3, 4, 5, 6, 6, 5, 3, 0, 7, 9)
PRICE_POOL = (1, 2, 3, 7, 100, 999, 12345, 10 ** 6, 10 ** 7, 10 ** 9, 10 ** 10, 10 ** 12, 10 ** 15, 10 ** 17, 10 ** 18, 2 ** 53 + 1, 2 ** 62,
              2 ** 63, U64, 10 ** 19, 1844674407370955161, 123456789012345, 4503599627370497, 99999, 31415926, 5, 50, 500)
FACTOR_POOL = (1.0, 1.0, 1.0, 0.5, 2.0, 1e-3, 1e-12, 1e6, 1e12, 1e300, 0.0, -1.0, float("nan"), float("inf"), float("-inf"), 1e-300, 3.7, 1e-9, 1.0000001,
               1e18, 1e19, 2.5, 100.0, 0.1, 1e-6, 5e-324)
MULT_POOL = (0, 0, 0, 1, 1, 2, 5, 7, 3)
RARE_MULT = (2 ** 51, 1844674407370955, 1844674407370956, 2 ** 63, U64)


def lcg(seed):
    state = (seed * 6364136223846793005 + 1442695040888963407) & U64

    def draw(bound):
        nonlocal state
        state = (state * 6364136223846793005 + 1442695040888963407) & U64
        return (state >> 33) % bound
    return draw


def pick(draw, pool):
    return pool[draw(len(pool))]


def make_container(draw, base, count, assets):
    items = {}
    for i in range(count):
        if draw(100) < 76:
            items[base + i] = assets[draw(len(assets))]
    for noise in (base - 1 if base else base + 40, base + count, draw(1 << 20) + 20000, 3):
        if draw(100) < 40:
            items[noise & U64] = assets[draw(len(assets))]
    if draw(2):
        capacity = len(items) + pick(draw, (0, 0, 1, 3, 7))
        head = draw(capacity) if capacity else 0
        return dict(kind="ring", items=items, cap=capacity, head=head)
    height = 0 if len(items) <= LEAF_KEYS else 1
    while not tree_fits(len(items), height):
        height += 1
    if len(items) <= 22 and draw(100) < 25 and tree_fits(len(items), 1) and len(items) > 1:
        height = 1
    return dict(kind="tree", items=items, height=height, root=bool(items) or draw(100) < 50)


def make_case(variant, number):
    draw = lcg(variant * 1000003 + number)
    count = pick(draw, (1, 1, 2, 3))
    index = draw(count) if draw(100) >= 3 else count + draw(2)
    dex = pick(draw, (0, 0, 0, 1, 2, 5))
    rows = []
    for _ in range(pick(draw, (0, 1, 2, 3, 4, 6, 8, 8))):
        rows.append((pick(draw, NAME_POOL), pick(draw, DEC_POOL)))
    markets, assets_seen = [], []
    for slot in range(count):
        mult = dex if slot == 0 else pick(draw, MULT_POOL)
        if draw(100) < 3 and slot:
            mult = pick(draw, RARE_MULT)
        n = pick(draw, (0, 1, 2, 3, 4, 5, 6, 3, 4))
        if mult == 1844674407370955 and draw(100) < 40:
            n = 1620
        if slot == 0:
            n = len(rows)
        assets = []
        for _ in range(max(n, 1)):
            roll = draw(100)
            if roll < 8:
                assets.append(pick(draw, (0, 1, 2, 3)) * KEY_STRIDE + draw(5))
            elif roll < 13:
                assets.append(dex * KEY_STRIDE + len(rows) + draw(3))
            else:
                assets.append(dex * KEY_STRIDE + (draw(len(rows)) if rows else 0))
        markets.append(dict(n=n, mult=mult, flag=int(draw(100) < 10), o378=NICHE if draw(100) < 5 else draw(1000),
                            o408=NICHE + 1 if draw(100) < 5 else draw(1000),
                            lookup=make_container(draw, (mult * KEY_STRIDE) & U64, min(n, 40), assets)))
        assets_seen.extend(assets)
    prices = {}
    for asset in assets_seen:
        prices[asset] = 0 if draw(100) < 10 else pick(draw, PRICE_POOL) if draw(100) < 70 else draw(10 ** 9) + 1
    if draw(2):
        arg = dict(kind="tree", root=bool(draw(2)), pulls=draw(4), cap=0, ptr=0)
        arg["words"] = (NICHE, ARG_BUF if arg["root"] else 0, draw(3), draw(40))
    else:
        capacity = pick(draw, (0, 0, 1, 4, 32, 1 << 40))
        arg = dict(kind="vec", root=False, pulls=0, cap=capacity, ptr=H + 0x3800 + draw(16) * 8)
        arg["words"] = (capacity, arg["ptr"], draw(3), draw(5))
    return dict(index=index, markets=markets, rows=rows, factor=pick(draw, FACTOR_POOL), p60=draw(1 << 40) * 977, p68=draw(1 << 32),
                prices=prices, arg=arg, tail=bytes(draw(256) for _ in range(21)))


def simple_case(price, factor, decimals=6, name=b"ABCD", rows=1, asset=0, dex=0, container="ring", arg=None, flag=0, o378=7, o408=9, index=0):
    """One dex market with a single slot whose key maps to `asset`; the building block of the directed cases."""
    table = [(name if number == asset % KEY_STRIDE else b"ABCD", decimals if number == asset % KEY_STRIDE else 6) for number in range(rows)]
    base = dex * KEY_STRIDE
    items = {base: asset}
    look = dict(kind="ring", items=items, cap=1, head=0) if container == "ring" else dict(kind="tree", items=items, height=0, root=True)
    market = dict(n=rows, mult=dex, flag=flag, o378=o378, o408=o408, lookup=look)
    arg = arg or dict(kind="vec", root=False, pulls=0, cap=0, ptr=H + 0x3800, words=(0, H + 0x3800, 0, 0))
    return dict(index=index, markets=[market], rows=table, factor=factor, p60=1234567, p68=89, prices={asset: price}, arg=arg, tail=bytes(range(21)))


def directed():
    cases = []
    for price, factor, decimals in ((U64, 1.0, 6), (1, sys.float_info.max, 0), (10 ** 18, 1e300, 3), (12345678901, 1.0, 3), (987654321987, 1.0, 2),
                                    (7, 3.7, 5), (2 ** 53 + 3, 1.0, 0), (1, float("inf"), 2), (1, float("nan"), 2), (3, -1.0, 4), (1, 0.0, 6),
                                    (2 ** 63, 2.0, 6), (U64, 0.5, 1), (4503599627370497, 1.0, 5), (999999999999, 1.0000001, 4), (31, 0.1, 1), (370378286, 1.0, 4),
                                    (123456789, 0.3333333333333333, 2), (777, 12345.6789, 4)):
        cases.append(simple_case(price, factor, decimals))
    for name in (b"HYPE", b"PURR", b"HYPD", b"USDC"):
        for dex in (0, 1):
            cases.append(simple_case(12345, 7.0, 3, name=name, dex=dex, asset=dex * KEY_STRIDE + 1, rows=3))
    cases.append(simple_case(5, 7.0, 3, asset=3, rows=2))
    cases.append(simple_case(5, 7.0, 9, asset=0))
    cases.append(simple_case(5, 7.0, 3, asset=KEY_STRIDE + 1, rows=2))
    tree_arg = dict(kind="tree", root=True, pulls=2, cap=0, ptr=0, words=(NICHE, ARG_BUF, 1, 17))
    empty_tree = dict(kind="tree", root=False, pulls=0, cap=0, ptr=0, words=(NICHE, 0, 0, 0))
    vec_arg = dict(kind="vec", root=False, pulls=0, cap=5, ptr=H + 0x3808, words=(5, H + 0x3808, 0, 0))
    for flag, o378, o408 in ((1, 7, 9), (0, NICHE, 9), (0, 7, NICHE + 1), (0, NICHE, NICHE + 1)):
        for arg in (tree_arg, empty_tree, vec_arg):
            cases.append(simple_case(5, 1.0, flag=flag, o378=o378, o408=o408, arg=arg))
    cases.append(simple_case(5, 1.0, arg=tree_arg, container="tree"))
    cases.append(simple_case(5, 1.0, index=1))
    overflow = simple_case(5, 1.0)
    overflow["markets"].append(dict(n=1620, mult=1844674407370955, flag=0, o378=7, o408=9, lookup=dict(kind="ring", items={}, cap=0, head=0)))
    overflow["index"] = 1
    cases.append(overflow)
    mul = simple_case(5, 1.0)
    mul["markets"].append(dict(n=2, mult=1844674407370956, flag=0, o378=7, o408=9, lookup=dict(kind="ring", items={}, cap=0, head=0)))
    mul["index"] = 1
    cases.append(mul)
    return cases


def describe(case):
    market = case["markets"][case["index"]] if case["index"] < len(case["markets"]) else None
    if market is None:
        return "index=%d count=%d" % (case["index"], len(case["markets"]))
    look = market["lookup"]
    return "index=%d mult=%d n=%d flag=%d %s/%d" % (case["index"], market["mult"], market["n"], market["flag"], look["kind"], len(look["items"]))


def outcome_label(outcome, events):
    if outcome[0] == "panic":
        return "panic-" + outcome[1]
    if outcome[1] is not None:
        return "early-%#x" % outcome[1]
    inserts = sum(1 for event in events if event[0] == "insert")
    return "map-%d" % min(inserts, 4)


# ---- runner and mutants ----


def judge(harness, case):
    try:
        got = harness.run(case)
    except (Halt, Panicked, EvidenceError, IndexError, KeyError, ValueError, OverflowError) as problem:
        return "evaluator stopped: %s" % (problem.args[0] if problem.args else type(problem).__name__)
    want = spec(case)
    if got != want:
        return "want %r got %r" % (summary_of(want), summary_of(got))
    return None


def summary_of(result):
    outcome, events = result
    return outcome, [event[:3] for event in events[:6]], len(events)


def root_extent(image):
    return image.exact_fde(ROOT_FN)


def mutants(image):
    """Every flippable condition, immediate byte and displacement byte of the root body, as (address, kind, patch)."""
    found = []
    start, end = root_extent(image)
    code = image.blob[image.offset(start):image.offset(start) + (end - start)]
    for insn in decode_range(image, start, end):
        raw = code[insn.va - start:insn.next - start]
        if insn.op == "jcc":
            found.append((insn.va, "jcc", {insn.va + (0 if insn.size == 2 else 1): raw[0 if insn.size == 2 else 1] ^ 1}))
        elif insn.op in ("cmov", "set"):
            at = raw.index(0x0F) + 1
            found.append((insn.va, insn.op, {insn.va + at: raw[at] ^ 1}))
        if insn.imm_at is not None and insn.imm_size and insn.op in ("cmp", "mov", "imul3", "add", "sub", "and", "shl", "shr"):
            found.append((insn.va, "imm", {insn.va + insn.imm_at: raw[insn.imm_at] ^ 1}))
        for operand in (insn.a, insn.b):
            if not (operand and operand[0] == "m" and operand[1] not in (None, RSP) and operand[4]):
                continue
            limit = insn.imm_at if insn.imm_at is not None else len(raw)
            disp = operand[4]
            at = raw.rfind(bytes((disp & 0xFF,)), 0, limit) if -128 <= disp < 128 else raw.find(struct.pack("<i", disp), 0, limit)
            if at > 0:
                found.append((insn.va, "disp", {insn.va + at: raw[at] ^ 8}))
    return found


def kill_mutant(image, patch, pool):
    harness = Harness(image, patch)
    for index, case in enumerate(pool):
        if judge(harness, case):
            return "case-%d" % index
    return None


def write_rows(path, rows):
    with open(path, "w", encoding="utf-8", newline="\n") as handle:
        for row in rows:
            handle.write("\t".join(str(cell) for cell in row) + "\n")


def static_rows(image):
    rows = [("function", "start", "end", "bytes", "instructions", "conditional_jumps", "direct_calls", "indirect_calls")]
    for entry in (ROOT_FN, BTREE_SEARCH, RING_SEARCH, KERNEL, ROUND_FN, INSERT, NEXT_STAGE):
        try:
            start, end = image.exact_fde(entry)
        except EvidenceError:
            rows.append(("%#x" % entry, "%#x" % entry, "-", "-", "-", "-", "-", "-"))
            continue
        body = decode_range(image, start, end)
        rows.append(("%#x" % start, "%#x" % start, "%#x" % end, end - start, len(body), sum(1 for r in body if r.op == "jcc"),
                     sum(1 for r in body if r.op == "call"), sum(1 for r in body if r.op == "calli")))
    return rows


def edge_rows(image):
    relative = image.relative()
    start, end = root_extent(image)
    rows = [("call_site", "kind", "target", "role")]
    roles = {BTREE_SEARCH: "real: B-tree search", RING_SEARCH: "real: ring search", KERNEL: "real: f64 to decimal kernel",
             INSERT: "contract: map insert", NEXT_STAGE: "contract: next stage", DYING_NEXT: "contract: B-tree consume step",
             DROP_A: "contract: drop glue", DROP_B: "contract: drop glue", DROP_C: "contract: drop glue", DROP_VEC: "contract: vec drop"}
    slot_roles = {SLOT_FREE: "contract: deallocate", SLOT_PRICE: "contract: price lookup", SLOT_ROUND: "real: round",
                  SLOT_MUL: "panic: multiply overflow", SLOT_ADD: "panic: add overflow", SLOT_ASSERT: "panic: assertion",
                  SLOT_INDEX: "panic: index", SLOT_UNWRAP: "panic: unwrap", 0x64DF4C0: "unwind resume", 0x64DF4C0 + 0x0: "unwind resume"}
    for insn in decode_range(image, start, end):
        if insn.op == "call":
            rows.append(("%#x" % insn.va, "direct", "%#x" % insn.target, roles.get(insn.target, "unnamed")))
        elif insn.op == "calli" and insn.a[0] == "m" and insn.a[1] is None:
            slot = insn.a[4]
            rows.append(("%#x" % insn.va, "got-slot %#x" % slot, "%#x" % relative[slot], slot_roles.get(slot, "unnamed")))
    return rows


def constant_rows(image):
    memory = Machine(image).memory
    rows = [("name", "address", "u64", "meaning")]
    for name, at, text in (("minus-one", 0x458DC8, "first addend of the scale factor"), ("one", 0x4592B0, "second addend of the scale factor"),
                           ("clamp-top", 0x459090, "2^64 as f64"), ("half-2^63", 0x459360, "2^63 as f64"), ("sat-limit", 0x458D58, "largest f64 below 2^64"),
                           ("round-bias", 0x450E60, "0.49999999999999994 used by the round routine"),
                           ("name-hype", 0x459F10, "HYPE as a little-endian u32"), ("name-purr", 0x45A1E8, "PURR as a little-endian u32")):
        rows.append((name, "%#x" % at, "%#x" % memory.read(at, 8 if "name" not in name else 4), text))
    table = memory.read(0x91B7C0, 8)
    rows.append(("pow10-table", "0x91b7c0", "%#x" % table, repr([to_float(memory.read(0x91B7C0 + 8 * k, 8)) for k in range(7)])))
    return rows


EQUIV_RANGES = (
    (0x55BE8B8, 0x55BE8E6, "the market-count test below already rejected every index at or past the count, so this duplicate unwrap panic is unreachable"),
    (0x55BE8E6, 0x55BE914, "the vector is never empty once the first bounds test passed, so this second unwrap panic is unreachable"),
    (0x55BE923, 0x55BE982, "unwind cleanup pad: the evaluator turns every panic into an exception and never runs pads"),
    (0x55BE29B, 0x55BE340, "error branch for a non-finite quotient: price quotients are at least 1e-6 and below 2^64, never non-finite"),
    (0x55BE6A3, 0x55BE731, "zero and subnormal split of the f64 decomposition: the quotient is at least 1e-6 so it is always a normal number"),
)


def equivalent_reason(address, kind, outcome_map):
    for low, high, text in EQUIV_RANGES:
        if low <= address < high:
            return text
    return outcome_map.get((address, kind))


def build(out, counts, sample):
    image = load_image()
    out.mkdir(parents=True, exist_ok=True)
    harness = Harness(image)
    rows = [("id", "case", "outcome", "events", "inserted")]
    outcomes, failures, pool, total = {}, [], [], 0
    seen = set()
    aimed = directed()
    for variant, count in enumerate(counts, 1):
        for number in range(count):
            case = make_case(variant, number) if variant > 1 or number >= len(aimed) else aimed[number]
            problem = judge(harness, case)
            total += 1
            want = spec(case)
            label = outcome_label(*want)
            outcomes[label] = outcomes.get(label, 0) + 1
            seen |= harness.machine.seen
            if problem:
                failures.append((variant, number, problem))
            if len(pool) < POOL and number % 11 == 0:
                pool.append(case)
            if number % sample == 0:
                inserts = [event for event in want[1] if event[0] == "insert"]
                rows.append(("%d.%d" % (variant, number), describe(case), label, len(want[1]),
                             ";".join("%d:%s" % (event[1], event[2].hex()) for event in inserts[:3])))
    if failures:
        raise EvidenceError("specification and bytes disagree: %r" % (failures[:3],))
    start, end = root_extent(image)
    controls = [("address", "kind", "flipped_byte", "result", "killed_by")]
    equivalent_rows, detected, unexplained = [("address", "kind", "reason")], 0, 0
    pool = directed() + pool
    found = mutants(image)
    for address, kind, patch in found:
        killer = kill_mutant(image, patch, pool)
        flipped = "%#x" % next(iter(patch))
        if killer is not None:
            detected += 1
            controls.append(("%#x" % address, kind, flipped, "detected", killer))
            continue
        reason = equivalent_reason(address, kind, EXTRA_EQUIVALENT)
        controls.append(("%#x" % address, kind, flipped, "equivalent" if reason else "SURVIVED", "-"))
        if reason:
            equivalent_rows.append(("%#x" % address, kind, reason))
        else:
            unexplained += 1
            equivalent_rows.append(("%#x" % address, kind, "UNEXPLAINED"))
    write_rows(out / "functions.tsv", static_rows(image))
    write_rows(out / "edges.tsv", edge_rows(image))
    write_rows(out / "constants.tsv", constant_rows(image))
    write_rows(out / "cases.tsv", rows)
    write_rows(out / "outcomes.tsv", [("outcome", "cases")] + sorted(outcomes.items()))
    covered = sorted(address for address in seen if start <= address < end)
    write_rows(out / "coverage.tsv", [("instructions_reached", "instructions_total")] +
               [(len(covered), len(decode_range(image, start, end)))])
    write_rows(out / "controls.tsv", controls)
    write_rows(out / "equivalent-mutants.tsv", equivalent_rows if len(equivalent_rows) > 1 else equivalent_rows + [("-", "-", "none")])
    summary = dict(cases=total, negative_controls=len(found), negative_detected=detected, equivalent=len(found) - detected - unexplained,
                   unexplained=unexplained)
    with open(out / "measure.json", "w", encoding="utf-8", newline="\n") as handle:
        json.dump(summary, handle, indent=1, sort_keys=True)
        handle.write("\n")
    return summary


REDUNDANT = "re-test of a condition the earlier guard already settled; the displaced field holds fill bytes that give the same answer"
DEAD_STORE = "stored word is overwritten or never read before the next use on every path"
FILL_MASK = "the changed mask or limit only separates bit patterns that no finite positive quotient or product can take"
EXTRA_EQUIVALENT = {
    (0x55BE119, "disp"): REDUNDANT, (0x55BE37E, "disp"): REDUNDANT, (0x55BE38F, "disp"): REDUNDANT, (0x55BE405, "disp"): REDUNDANT,
    (0x55BE783, "imm"): DEAD_STORE,
    (0x55BE4B0, "imm"): FILL_MASK, (0x55BE5CD, "imm"): FILL_MASK, (0x55BE5DA, "imm"): FILL_MASK,
    (0x55BE52C, "imm"): "branch for a negative operand: the value was floored at zero before it, so it never runs",
    (0x55BE533, "jcc"): "branch for a negative operand: the value was floored at zero before it, so it never runs",
    (0x55BE647, "disp"): "a table index past the row count reaches the later local >= length assertion on every path, so the scale choice made here is never observable",
    (0x55BE517, "imm"): "u64::MAX and u64::MAX - 1 both convert to 2^64 as f64, so the quotient and the decimal are unchanged",
    (0x55BE5F7, "imm"): "bit 0 of the fraction mask only touches the low 32 bits, which are copied from the unmasked register and never from the masked copy",
    (0x55BE635, "imm"): "asset 9999 can be a row index only with 10000 rows; the next test sends smaller tables to the same branch",
}
POOL = 70
COUNTS = (3000, 3000, 3000, 3000)
SAMPLE = 3


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--out", required=True, type=pathlib.Path)
    args = parser.parse_args(argv)
    summary = build(args.out, COUNTS, SAMPLE)
    print(json.dumps(summary, sort_keys=True))
    return 1 if summary["unexplained"] else 0


if __name__ == "__main__":
    sys.exit(main())
