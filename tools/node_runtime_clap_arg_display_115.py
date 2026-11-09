#!/usr/bin/env python3
"""Reconstruct the clap argument Display bodies of node #115 and the trait-object method tables around them.

Flag Display 0x165bc20, option Display 0x166e3c0, positional Display 0x1675ad0 and positional name_no_brackets
0x1671fe0, plus the accessor, is_set / set, aliases and value-iterator bodies of the three method tables that follow
the Display slots (0x6405a60, 0x6405b58, 0x6405c50). Pure models are compared on thousands of generated argument
records with the real instruction bytes, run in the offline x86-64 interpreter section of this file (Image, decode,
Memory, Machine). The library routines the code calls (fmt::write, alloc::fmt::format, the allocator, memcpy, panics)
are modelled as stubs; the B-tree value maps are built in interpreter memory. The binary is never executed.

    python3 tools/node_runtime_clap_arg_display_115.py --out research/work-items/node-runtime-clap-arg-display-115
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


# ---------------------------------------------------------------------------
# Packet part: the three clap argument Display bodies of node #115 (flag, option, positional) and the
# Vec<String> collect / join helpers the positional body calls. Everything below the interpreter core is
# specific to this packet.
# ---------------------------------------------------------------------------

import argparse
import json
import os

PACKET_NAME = "node-runtime-clap-arg-display-115"
F_FLAG, F_OPT, F_POS, F_NAME = 0x165BC20, 0x166E3C0, 0x1675AD0, 0x1671FE0
F_COLLECT, F_NEXT, F_JOIN, F_GROW, F_FINISH_GROW = 0x1669660, 0x166B320, 0x1669F00, 0x1660680, 0x1660590
F_DROP_NAMES, F_DROP_VEC = 0x1658910, 0x16755E0
REAL = (F_FLAG, F_OPT, F_POS, F_NAME, F_COLLECT, F_NEXT, F_JOIN, F_GROW, F_FINISH_GROW, F_DROP_NAMES, F_DROP_VEC)
RANGES = {
    "flag_display": (0x165BC20, 0x165BCC8),
    "option_display": (0x166E3C0, 0x166EBC0),
    "positional_display": (0x1675AD0, 0x1675FED),
    "positional_name": (0x1671FE0, 0x1672483),
    "collect_names": (0x1669660, 0x166975F),
    "join": (0x1669F00, 0x166A370),
    "grow": (0x1660680, 0x1660710),
    "is_set_flag": (0x165CCD0, 0x165CD5B),
    "set_flag": (0x165CCB0, 0x165CCC5),
    "aliases_flag": (0x165CD60, 0x165CDE7),
    "values_iter": (0x163B830, 0x163B883),
    "default_value": (0x163B890, 0x163B8DE),
    "collect_visible": (0x16572B0, 0x1657420),
}
# argument formatter code addresses (tiny bodies, shapes checked from the bytes) and the GOT slots the code calls through
ARG_STR, ARG_STR_REF, ARG_STRING = 0x16697C0, 0x16697A0, 0x16717A0
SLOT_NAMES = {
    0x64DF480: "malloc", 0x64DF4A0: "free", 0x64DF588: "realloc", 0x64DF580: "alloc_aligned", 0x64DF590: "alloc_aligned",
    0x64DF498: "alloc_error", 0x64DF508: "memcpy", 0x64DF6B8: "panic", 0x64DF6E8: "format", 0x64DF6F0: "write",
    0x64DF720: "pad", 0x64DF770: "panic", 0x64DF830: "panic", 0x64DF4C0: "panic",
}
CHAR_SLOT, CHAR_FN = 0x64DFEE8, 0x168A370
FAKE = 0x7000000000
WRITE_STR = FAKE + 0x1000
FLAG_MULTIPLE, FLAG_DELIM, FLAG_EQUALS = 0x2, 0x200, 0x2000
NONE_CHAR = 0x110000
STRUCT, FMT_AT, WRITER_AT, VTABLE_AT = HEAP_BASE + 0x1000, HEAP_BASE + 0x980, HEAP_BASE + 0x800, HEAP_BASE + 0x900
TREE_AT, TEXT_AT, ALLOC_AT = HEAP_BASE + 0x4000, HEAP_BASE + 0x40000, HEAP_BASE + 0x100000
USED = 0x180000
COUNTS = {"flag": 1800, "option": 3600, "positional": 3200, "name": 2600}
SAMPLE_LINES = {"flag": 400, "option": 800, "positional": 800, "name": 600}
OUT_AT = HEAP_BASE + 0xA00
MUTANT_CASES = 320
NODE_CAP = 11
SKINNY_SIZES = (5, 7, 9, 11, 13, 15, 17, 19)


class Panic(Exception):
    pass


class ModelPanic(Exception):
    """An unwrap on None; `written` holds the chunks the writer accepted before the panic."""

    def __init__(self, message, written=()):
        super().__init__(message)
        self.written = list(written)


# ------------------------------- pure models --------------------------------

def values_in_order(names):
    return [value for _, value in sorted(names.items())]


def model_flag(arg, mut=None):
    """Chunks the flag Display hands to the writer, or raises ModelPanic."""
    if arg["long"] is not None:
        return ["--", arg["long"]]
    if arg["short"] is None:
        raise ModelPanic("short unwrap")
    return ["-", chr(arg["short"])]


def delimiter_char(arg, mut=None):
    if arg["flags"] & FLAG_DELIM and mut != "ignore_delim_flag":
        if arg["delim"] is None:
            raise ModelPanic("val_delim unwrap")
        return chr(arg["delim"])
    return " "


def model_option(arg, mut=None):
    chunks = []
    separator = "=" if arg["flags"] & FLAG_EQUALS else " "
    if mut == "equals_inverted":
        separator = " " if arg["flags"] & FLAG_EQUALS else "="
    if arg["long"] is not None:
        chunks += ["--", arg["long"], separator]
    elif arg["short"] is None:
        raise ModelPanic("short unwrap")
    else:
        chunks += ["-", chr(arg["short"]), separator]
    multiple = bool(arg["flags"] & FLAG_MULTIPLE)
    names = arg["names"]
    try:
        delim = delimiter_char(arg, mut)
    except ModelPanic as exc:
        raise ModelPanic(str(exc), chunks)
    if names is not None:
        values = values_in_order(names)
        for index, value in enumerate(values):
            chunks += ["<", value, ">"]
            if index + 1 < len(values):
                chunks.append(delim)
        if multiple and len(values) == (1 if mut != "count_two" else 2):
            chunks.append("...")
    elif arg["num"] is not None:
        num = arg["num"]
        for index in range(num):
            chunks += ["<", arg["name"], ">"]
            if index + 1 < num:
                chunks.append(delim)
        if multiple and num == 1:
            chunks.append("...")
    else:
        chunks += ["<", arg["name"], ">", "..." if multiple or mut == "dots_always" else ""]
    return chunks


def model_positional(arg, mut=None):
    delim = delimiter_char(arg, mut)
    multiple = bool(arg["flags"] & FLAG_MULTIPLE)
    names = arg["names"]
    chunks = []
    if names is not None:
        values = values_in_order(names)
        joined = delim.join("<%s>" % value for value in values)
        if mut == "join_no_brackets":
            joined = delim.join(values)
        chunks.append(joined)
        if multiple and len(values) == (1 if mut != "count_two" else 2):
            chunks.append("...")
    else:
        chunks += ["<", arg["name"], ">"]
        if multiple:
            chunks.append("...")
    return chunks


def model_name(arg, mut=None):
    """name_no_brackets: ('borrowed' | 'owned', text); raises ModelPanic on a missing delimiter or an empty map."""
    delim = delimiter_char(arg, mut)
    names = arg["names"]
    if names is None:
        return ("borrowed", arg["name"])
    values = values_in_order(names)
    if len(values) > (1 if mut != "bracket_limit" else 2):
        return ("owned", delim.join("<%s>" % value for value in values))
    if not values:
        raise ModelPanic("empty map")
    return ("borrowed", values[0] if mut != "last_value" else values[-1])


def apply_failure(chunks, fail_at):
    """Writer failure at the fail_at-th write: the earlier chunks were accepted, then the function reports failure."""
    if fail_at is not None and fail_at < len(chunks):
        return 1, chunks[:fail_at]
    return 0, chunks


# ------------------------------ emulator rig --------------------------------

def utf8(text):
    return text.encode("utf-8")


class Rig:
    """One interpreter with the library routines the Display bodies call modelled as stubs."""

    def __init__(self, image, patches=None):
        self.m = Machine(image, patches)
        m = self.m
        m.real = frozenset(REAL)
        for slot, name in SLOT_NAMES.items():
            m.memory.statics[slot] = FAKE + slot
            m.slots[FAKE + slot] = getattr(self, "hook_" + name)
        m.memory.statics[CHAR_SLOT] = CHAR_FN
        m.slots[WRITE_STR] = self.hook_write_str
        self.reset_state()

    def reset_state(self):
        self.chunks = []
        self.writes = 0
        self.fail_at = None
        self.bump = ALLOC_AT
        self.live = {}
        self.allocs = 0
        self.tree_bump = TREE_AT
        self.text_bump = TEXT_AT
        self.skinny_flag = False
        self.shape = None

    # ---- allocator ----
    def take(self, size):
        at = self.bump
        self.bump += (max(size, 1) + 15) & ~15
        if self.bump >= HEAP_BASE + USED:
            raise Halt("allocator exhausted")
        self.live[at] = size
        self.allocs += 1
        return at

    def hook_malloc(self, m):
        m.regs[RAX] = self.take(m.regs[RDI])

    def hook_alloc_aligned(self, m):
        raise Halt("aligned allocation is not expected for byte buffers")

    def hook_realloc(self, m):
        old, size = m.regs[RDI], m.regs[RSI]
        if old not in self.live:
            raise Halt("realloc of an unknown block")
        data = m.memory.bytes_at(old, min(self.live[old], size))
        del self.live[old]
        new = self.take(size)
        m.memory.put_bytes(new, data)
        self.allocs -= 1
        m.regs[RAX] = new

    def hook_free(self, m):
        at = m.regs[RDI]
        if at not in self.live:
            raise Halt("free of an unknown block")
        if m.regs[RSI] != self.live[at]:
            raise Halt("free with the wrong size")
        del self.live[at]

    def hook_memcpy(self, m):
        dst, src, count = m.regs[RDI], m.regs[RSI], m.regs[RDX]
        m.memory.copy(dst, src, count)
        m.regs[RAX] = dst

    def hook_alloc_error(self, m):
        raise Panic("allocation error handler")

    def hook_panic(self, m):
        raise Panic("panic routine")

    # ---- writer ----
    def hook_write_str(self, m):
        data = m.memory.bytes_at(m.regs[RSI], m.regs[RDX])
        index = self.writes
        self.writes += 1
        if self.fail_at is not None and index == self.fail_at:
            m.regs[RAX] = 1
            return
        self.chunks.append(data.decode("utf-8", "backslashreplace"))
        m.regs[RAX] = 0

    def emit(self, data):
        """Hand one chunk to the writer; True when the writer reports failure."""
        m = self.m
        saved = (m.regs[RSI], m.regs[RDX])
        m.regs[RSI] = TEXT_AT - 0x8000
        m.memory.put_bytes(TEXT_AT - 0x8000, data)
        m.regs[RDX] = len(data)
        self.hook_write_str(m)
        failed = m.regs[RAX] != 0
        m.regs[RSI], m.regs[RDX] = saved
        return failed

    def text(self, ptr, size):
        return self.m.memory.bytes_at(ptr, size) if size else b""

    def render(self, template, args):
        """The custom format template: length-prefixed literals, 0xC0 = next argument, 0 = end."""
        mem = self.m.memory
        out, at, arg = [], template, 0
        while True:
            byte = mem.read(at, 1)
            at += 1
            if byte == 0:
                return out
            if byte == 0xC0:
                value, fn = mem.read(args + 16 * arg, 8), mem.read(args + 16 * arg + 8, 8)
                arg += 1
                if fn == ARG_STR:
                    out.append(self.text(mem.read(value, 8), mem.read(value + 8, 8)))
                elif fn == ARG_STR_REF:
                    inner = mem.read(value, 8)
                    out.append(self.text(mem.read(inner, 8), mem.read(inner + 8, 8)))
                elif fn == ARG_STRING:
                    out.append(self.text(mem.read(value + 8, 8), mem.read(value + 16, 8)))
                elif fn == CHAR_FN:
                    code = mem.read(value, 4)
                    if code >= 0x110000 or 0xD800 <= code < 0xE000:
                        raise Halt("invalid character")
                    out.append(utf8(chr(code)))
                else:
                    raise Halt("unknown argument formatter %#x" % fn)
            else:
                out.append(mem.bytes_at(at, byte))
                at += byte

    def hook_write(self, m):
        template, args = m.regs[RDX], m.regs[RCX]
        for piece in self.render(template, args):
            if self.emit(piece):
                m.regs[RAX] = 1
                return
        m.regs[RAX] = 0

    def hook_pad(self, m):
        raise Halt("argument formatters are recognised by address, not executed")

    def hook_format(self, m):
        out, template, args = m.regs[RDI], m.regs[RSI], m.regs[RDX]
        text = b"".join(self.render(template, args))
        mem = m.memory
        at = self.take(len(text)) if text else 1
        mem.put_bytes(at, text)
        mem.write(out, 8, len(text))
        mem.write(out + 8, 8, at)
        mem.write(out + 16, 8, len(text))
        if not text:
            self.allocs += 0

    # ---- fixtures ----
    def string(self, text):
        data = utf8(text)
        at = self.text_bump
        self.text_bump += (len(data) + 16) & ~15
        self.m.memory.put_bytes(at, data)
        return at, len(data)

    def node(self, leaf):
        at = self.tree_bump
        self.tree_bump += 0x120 if leaf else 0x180
        return at

    def build(self, entries, height, rng, parent=0, pidx=0):
        """B-tree node for sorted (key, text) pairs, exactly `height` levels deep (0 = leaf)."""
        mem = self.m.memory
        at = self.node(height == 0)
        mem.write(at + 0xB0, 8, parent)
        mem.write(at + 0x110, 2, pidx)
        if height == 0:
            keep = entries
            kids = []
        else:
            cap = NODE_CAP
            for _ in range(height - 1):
                cap = cap * 12 + NODE_CAP
            low = max(2, -(-(len(entries) + 1) // (cap + 1)))
            high = min(12, (len(entries) + 1) // 2)
            count = low + rng.below(max(1, high - low + 1)) if high >= low else low
            count = max(2, min(count, 12))
            leaves = len(entries) - (count - 1)
            sizes = [max(1, leaves // count)] * count
            for k in range(leaves - sum(sizes)):
                sizes[k % count] += 1
            keep, kids, cursor = [], [], 0
            for size in sizes:
                kids.append(entries[cursor:cursor + size])
                cursor += size
                if cursor < len(entries):
                    keep.append(entries[cursor])
                    cursor += 1
        mem.write(at + 0x112, 2, len(keep))
        for index, (key, text) in enumerate(keep):
            ptr, size = self.string(text)
            mem.write(at + 16 * index, 8, ptr)
            mem.write(at + 16 * index + 8, 8, size)
            mem.write(at + 0xB8 + 8 * index, 8, key)
        for index, part in enumerate(kids):
            child = self.build(part, height - 1, rng, at, index)
            mem.write(at + 0x118 + 8 * index, 8, child)
        return at

    def skinny(self, entries, height, parent=0, pidx=0):
        """Deep B-tree with one key per node: a left spine of `height` internal nodes, each with a key-less chain on its right."""
        mem = self.m.memory
        at = self.node(height == 0)
        mem.write(at + 0xB0, 8, parent)
        mem.write(at + 0x110, 2, pidx)
        mem.write(at + 0x112, 2, 1)
        if height == 0:
            slots = [(0, entries[0])]
            kids = []
        else:
            size = 2 * height - 1
            slots = [(0, entries[size])]
            kids = [self.skinny(entries[:size], height - 1, at, 0), self.chain(entries[size + 1:size + 2], height - 1, at, 1)]
        key, text = slots[0][1]
        ptr, length = self.string(text)
        mem.write(at, 8, ptr)
        mem.write(at + 8, 8, length)
        mem.write(at + 0xB8, 8, key)
        for index, child in enumerate(kids):
            mem.write(at + 0x118 + 8 * index, 8, child)
        return at

    def lay_out(self, shape, entries, parent=0, pidx=0):
        """Node graph for an irregular shape (leaf: ('leaf', n); internal: ('node', [children], n)); entries are taken in order."""
        mem = self.m.memory
        leaf = shape[0] == "leaf"
        at = self.node(leaf)
        mem.write(at + 0xB0, 8, parent)
        mem.write(at + 0x110, 2, pidx)
        count = shape[1] if leaf else shape[2]
        mem.write(at + 0x112, 2, count)
        taken = 0
        for index in range(count + (0 if leaf else 1)):
            if not leaf:
                mem.write(at + 0x118 + 8 * index, 8, self.lay_out(shape[1][index], entries, at, index))
            if index < count:
                key, text = entries.pop(0)
                ptr, length = self.string(text)
                mem.write(at + 16 * index, 8, ptr)
                mem.write(at + 16 * index + 8, 8, length)
                mem.write(at + 0xB8 + 8 * index, 8, key)
                taken += 1
        return at

    def chain(self, entries, height, parent, pidx):
        """Right-hand subtree of the deep tree: key-less internal nodes with one edge down to a one-key leaf."""
        if height == 0:
            return self.skinny(entries, 0, parent, pidx)
        mem = self.m.memory
        at = self.node(False)
        mem.write(at + 0xB0, 8, parent)
        mem.write(at + 0x110, 2, pidx)
        mem.write(at + 0x112, 2, 0)
        mem.write(at + 0x118, 8, self.chain(entries, height - 1, at, 0))
        return at

    def put_names(self, base, names, rng, wide):
        """Option<BTreeMap<usize, &str>> at base: tag, root, height, length."""
        mem = self.m.memory
        mem.write(base, wide, 0 if names is None else 1)
        if names is None:
            return
        entries = sorted(names.items())
        mem.write(base + 0x18, 8, len(entries))
        if not entries:
            mem.write(base + 8, 8, 0)
            mem.write(base + 0x10, 8, 0)
            return
        if self.shape is not None:
            root = self.lay_out(self.shape, list(entries))
            mem.write(base + 8, 8, root)
            mem.write(base + 0x10, 8, shape_height(self.shape))
            return
        if len(entries) in SKINNY_SIZES and len(entries) % 2 == 1 and self.skinny_flag:
            height = (len(entries) - 1) // 2
            root = self.skinny(entries, height)
            mem.write(base + 8, 8, root)
            mem.write(base + 0x10, 8, height)
            return
        height = 0
        cap = NODE_CAP
        while len(entries) > cap:
            height += 1
            cap = cap * 12 + NODE_CAP
        root = self.build(entries, height, rng)
        mem.write(base + 8, 8, root)
        mem.write(base + 0x10, 8, height)

    def prepare(self, arg, kind, rng, fail_at):
        mem = self.m.memory
        mem.reset(USED)
        self.reset_state()
        self.fail_at = fail_at
        self.skinny_flag = bool(arg.get("skinny"))
        self.shape = arg.get("shape")
        mem.write(VTABLE_AT + 0x18, 8, WRITE_STR)
        mem.write(FMT_AT, 8, WRITER_AT)
        mem.write(FMT_AT + 8, 8, VTABLE_AT)
        if kind == "flag":
            mem.write(STRUCT + 0xC8, 8, 0)
            if arg["long"] is not None:
                ptr, size = self.string(arg["long"])
                mem.write(STRUCT + 0xC8, 8, ptr)
                mem.write(STRUCT + 0xD0, 8, size)
            mem.write(STRUCT + 0xE8, 4, NONE_CHAR if arg["short"] is None else arg["short"])
            return
        mem.write(STRUCT + 0x1A0, 4, arg["flags"])
        mem.write(STRUCT + 0xF0, 4, NONE_CHAR if arg["delim"] is None else arg["delim"])
        ptr, size = self.string(arg["name"])
        mem.write(STRUCT + 0x170, 8, ptr)
        mem.write(STRUCT + 0x178, 8, size)
        self.put_names(STRUCT, arg["names"], rng, 8 if kind == "positional" else 1)
        if kind == "option":
            mem.write(STRUCT + 0x1C0, 8, 0)
            if arg["long"] is not None:
                ptr, size = self.string(arg["long"])
                mem.write(STRUCT + 0x1C0, 8, ptr)
                mem.write(STRUCT + 0x1C8, 8, size)
            mem.write(STRUCT + 0x1E0, 4, NONE_CHAR if arg["short"] is None else arg["short"])
            mem.write(STRUCT + 0x20, 1, 0 if arg["num"] is None else 1)
            mem.write(STRUCT + 0x28, 8, arg["num"] or 0)

    def go(self, entry_va):
        try:
            self.m.run(entry_va, {RDI: STRUCT, RSI: FMT_AT})
        except Panic:
            return ("panic", list(self.chunks))
        except Halt as exc:
            return ("halt:" + str(exc), list(self.chunks))
        status = self.m.regs[RAX] & 0xFF
        if status > 1:
            return ("bad-bool", list(self.chunks), len(self.live))
        return ("ok" if status == 0 else "err", list(self.chunks), len(self.live))

    def run_name(self, arg, rng):
        self.prepare(arg, "positional", rng, None)
        try:
            self.m.run(F_NAME, {RDI: OUT_AT, RSI: STRUCT})
        except Panic:
            return ("panic", [])
        except Halt as exc:
            return ("halt:" + str(exc), [])
        mem = self.m.memory
        cap, ptr, size = (mem.read(OUT_AT + 8 * k, 8) for k in range(3))
        try:
            text = self.text(ptr, size).decode("utf-8", "backslashreplace")
        except (Halt, EvidenceError) as exc:
            return ("halt:" + str(exc), [])
        if cap == 0x8000000000000000:
            return ("borrowed", [text], len(self.live))
        return ("owned", [text, "cap=%d" % cap], len(self.live))

    def run(self, arg, kind, rng, fail_at=None):
        if kind == "name":
            return self.run_name(arg, rng)
        self.prepare(arg, kind, rng, fail_at)
        entry = {"flag": F_FLAG, "option": F_OPT, "positional": F_POS}[kind]
        return self.go(entry)


def model_result(kind, arg, fail_at, mut=None):
    """Compare-ready tuple for the model, in the same shape as Rig.run."""
    if kind == "name":
        try:
            style, text = model_name(arg, mut)
        except ModelPanic:
            return ("panic", [])
        if style == "borrowed":
            return ("borrowed", [text], 0)
        return ("owned", [text, "cap=%d" % len(utf8(text))], 1)
    model = {"flag": model_flag, "option": model_option, "positional": model_positional}[kind]
    try:
        chunks = model(arg, mut)
    except ModelPanic as exc:
        status, kept = apply_failure(exc.written, fail_at)
        return ("panic", kept) if status == 0 else ("err", kept, 0)
    status, kept = apply_failure(chunks, fail_at)
    return ("ok" if status == 0 else "err", kept, 0)


# ------------------------------- case streams --------------------------------

class Xorshift:
    def __init__(self, seed):
        self.s = seed & MASK[8] or 1

    def next(self):
        s = self.s
        s ^= s >> 12
        s ^= (s << 25) & MASK[8]
        s ^= s >> 27
        self.s = s
        return (s * 0x2545F4914F6CDD1D) & MASK[8]

    def below(self, n):
        return (self.next() >> 11) % n


WORDS = ("a", "in", "FILE", "path", "chain", "n", "ß", "日本", "x" * 9, "", "<>", "val_1", "é", "😀", "o-p", "name")
CHARS = (0x61, 0x5A, 0x7A, 0xE9, 0x20AC, 0x1F600, 0x3F, 0x2C, 0x7C, 0x3D, 0x7FF, 0x800, 0xFFFF, 0x10000, 0x41, 0x7F, 0x80)


def word(rng):
    return WORDS[rng.below(len(WORDS))]


def name_map(rng, limit):
    count = rng.below(limit + 1)
    if limit > 20 and rng.below(16) == 0:
        count = 144 + rng.below(30)
    keys = set()
    while len(keys) < count:
        keys.add(rng.below(40) if rng.below(4) else rng.next() & 0xFFFF)
    return {key: word(rng) for key in keys}


def shape_height(shape):
    return 0 if shape[0] == "leaf" else 1 + shape_height(shape[1][0])


def shape_count(shape):
    if shape[0] == "leaf":
        return shape[1]
    return shape[2] + sum(shape_count(child) for child in shape[1])


def random_shape(rng, height):
    """Irregular tree: every leaf at the same depth, any node may hold zero keys."""
    count = rng.below(4) if rng.below(3) else 0
    if height == 0:
        return ("leaf", count)
    return ("node", [random_shape(rng, height - 1) for _ in range(count + 1)], count)


def make_arg(rng, kind):
    arg = {"skinny": False, "shape": None, "long": word(rng) if rng.below(2) else None,
           "short": CHARS[rng.below(len(CHARS))] if rng.below(3) else None,
           "flags": 0, "delim": None, "names": None, "num": None, "name": word(rng)}
    if kind == "name" and rng.below(3) == 0:
        arg["names"] = {rng.below(9): word(rng)}
    if kind == "flag":
        if rng.below(9) == 0:
            arg["long"] = None
        if arg["long"] is None and rng.below(6) == 0:
            arg["short"] = None
        return arg
    flags = 0
    if rng.below(3) == 0:
        flags |= FLAG_MULTIPLE
    if rng.below(4) == 0:
        flags |= FLAG_DELIM
    if rng.below(4) == 0:
        flags |= FLAG_EQUALS
    if rng.below(2):
        flags |= rng.below(1 << 20) & ~(FLAG_MULTIPLE | FLAG_DELIM | FLAG_EQUALS)
    arg["flags"] = flags
    if rng.below(5) != 0:
        arg["delim"] = CHARS[rng.below(len(CHARS))]
    shape = rng.below(5)
    if kind in ("positional", "name"):
        if shape < 3:
            limit = 3 if shape < 2 else 26
            arg["names"] = name_map(rng, limit)
            if rng.below(3) == 0:
                arg["names"] = {rng.below(9): word(rng)}
    else:
        if shape == 0:
            arg["names"] = name_map(rng, 4)
        elif shape == 1:
            arg["names"] = name_map(rng, 26) if rng.below(2) == 0 else {rng.below(9): word(rng)}
        elif shape == 2:
            arg["num"] = rng.below(5)
        if arg["long"] is None and arg["short"] is None and rng.below(8):
            arg["short"] = CHARS[rng.below(len(CHARS))]
    if arg["num"] is None and rng.below(6) == 0:
        shape = random_shape(rng, rng.below(5))
        total = shape_count(shape)
        if 0 < total <= 40:
            arg["names"] = {10 * k: word(rng) for k in range(total)}
            arg["shape"] = shape
            return arg
    if arg["num"] is None and rng.below(9) == 0:
        count = SKINNY_SIZES[rng.below(len(SKINNY_SIZES))]
        keys = sorted({rng.below(60) + 100 * k for k in range(count)})
        arg["names"] = {key: word(rng) for key in keys}
        arg["skinny"] = True
    return arg


def fail_point(rng, index, kind, arg):
    """Every third case lets the writer fail at a random write of the model's chunk list (or one past the end)."""
    if index % 3 or kind == "name":
        return None
    try:
        count = len({"flag": model_flag, "option": model_option, "positional": model_positional}[kind](arg))
    except ModelPanic as exc:
        count = len(exc.written)
    return rng.below(count + 2)


BOUNDARY_SHAPES = (
    ("node", [("leaf", 0), ("leaf", 1)], 1),
    ("node", [("leaf", 0), ("leaf", 0)], 0),
    ("node", [("leaf", 2), ("leaf", 0), ("leaf", 1)], 2),
    ("node", [("node", [("leaf", 0), ("leaf", 1)], 1), ("node", [("leaf", 1)], 0)], 1),
    ("node", [("node", [("leaf", 0)], 0)], 0),
)


def boundary_args(kind):
    """Deterministic first cases: deep one-key trees of height 2..9 and trees whose first leaf is empty."""
    out = []
    if kind == "flag":
        return out
    rng = Xorshift(0xB0B)
    for count in SKINNY_SIZES:
        keys = [10 * k for k in range(count)]
        out.append(dict(make_arg(rng, kind), names={key: word(rng) for key in keys}, skinny=True, shape=None, num=None))
    for delim in (0x2C, 0x7F, 0x80, 0xE9, 0x7FF, 0x800, 0x20AC, 0xFFFF, 0x10000, 0x1F600, 0x40000, 0x10FFFF):
        for names in ({1: "a", 2: "bc", 3: ""}, {1: "", 2: "x"}, {1: "a", 2: "", 3: "b"}, {4: "only"}):
            out.append(dict(make_arg(rng, kind), names=names, flags=FLAG_DELIM | (FLAG_MULTIPLE if len(names) % 2 else 0), delim=delim,
                            shape=None, skinny=False, num=None))
    for count in (1, 2, 3):
        out.append(dict(make_arg(rng, kind), names={k: word(rng) for k in range(count)}, flags=FLAG_MULTIPLE, delim=None,
                        shape=None, skinny=False, num=None))
    for shape in BOUNDARY_SHAPES:
        total = shape_count(shape)
        if total:
            out.append(dict(make_arg(rng, kind), names={10 * k: word(rng) for k in range(total)}, shape=shape, skinny=False,
                            num=None))
    return out


def cases(kind, count, seed):
    rng = Xorshift(seed)
    for arg in boundary_args(kind):
        yield arg, None, rng.next() & 0xFFFF
    for index in range(count):
        arg = make_arg(rng, kind)
        yield arg, fail_point(rng, index, kind, arg), rng.next() & 0xFFFF


def label(arg, fail_at):
    parts = ["L=%s" % ("-" if arg["long"] is None else arg["long"]),
             "S=%s" % ("-" if arg["short"] is None else "%x" % arg["short"]),
             "F=%x" % arg["flags"], "D=%s" % ("-" if arg["delim"] is None else "%x" % arg["delim"]),
             "N=%s" % arg["name"]]
    if arg["names"] is not None:
        parts.append("V=" + ";".join("%d:%s" % kv for kv in sorted(arg["names"].items())))
    if arg["num"] is not None:
        parts.append("#=%d" % arg["num"])
    if arg.get("skinny"):
        parts.append("deep")
    if arg.get("shape") is not None:
        parts.append("shape=" + shape_text(arg["shape"]))
    parts.append("fail=%s" % ("-" if fail_at is None else fail_at))
    return " ".join(parts)


def shape_text(shape):
    if shape[0] == "leaf":
        return str(shape[1])
    return "%d[%s]" % (shape[2], ",".join(shape_text(child) for child in shape[1]))


def show(result):
    if result[0] in ("ok", "err", "borrowed", "owned"):
        return "%s|%s|live=%d" % (result[0], "│".join(result[1]), result[2])
    return "%s|%s" % (result[0], "│".join(result[1]))


# --------------------------- static byte evidence ----------------------------

TEMPLATES = (0x432903, 0x43B857, 0x441FFD, 0x444B25, 0x4459DE, 0x447CC2, 0x44AADB)
LITERALS = (0x46D294, 0x46D2F9, 0x46D3D8)
FORMAT_SLOT_ADDENDS = (0x64DF6F0, 0x64DF6E8, 0x64DF720, 0x64DFEE8, 0x64DF480, 0x64DF4A0, 0x64DF588)


def template_text(image, va):
    at = image.offset(va)
    blob, out, pos = image.blob, [], at
    while True:
        byte = blob[pos]
        pos += 1
        if byte == 0:
            return out
        if byte == 0xC0:
            out.append("{}")
        else:
            out.append(bytes(blob[pos:pos + byte]).decode("utf-8"))
            pos += byte


def static_rows(image):
    rows = ["kind\taddress\tvalue\n"]
    for va in TEMPLATES:
        rows.append("template\t%#x\t%s\n" % (va, "|".join(template_text(image, va))))
    for va, size in ((0x46D294, 2), (0x46D2F9, 3), (0x46D3D8, 3)):
        at = image.offset(va)
        rows.append("literal\t%#x\t%s\n" % (va, bytes(image.blob[at:at + size]).decode()))
    relative = image.relative()
    for slot in sorted(SLOT_NAMES) + [CHAR_SLOT]:
        rows.append("got\t%#x\t%s -> %s\n" % (slot, SLOT_NAMES.get(slot, "char_display"),
                                              "%#x" % relative[slot] if slot in relative else "dynamic symbol"))
    for va, size in ((ARG_STR, 19), (ARG_STR_REF, 22), (ARG_STRING, 20)):
        at = image.offset(va)
        rows.append("formatter\t%#x\t%s\n" % (va, bytes(image.blob[at:at + size]).hex()))
    return rows


def extent_rows(image):
    rows = ["function\tstart\tend\tinstructions\n"]
    for name, (lo, hi) in RANGES.items():
        rows.append("%s\t%#x\t%#x\t%d\n" % (name, lo, hi, len(decode_range(image, lo, hi))))
    return rows


# ------------------------------ negative controls -----------------------------

def enumerate_mutants(image):
    """Binary mutants: every conditional jump flipped, plus +1 on byte immediates of compare/test/shift/mov."""
    rows = []
    for name, (lo, hi) in RANGES.items():
        for row in decode_range(image, lo, hi):
            if row.op == "jcc":
                at = row.va + (1 if row.data[0] == 0x0F else 0)
                rows.append(("flip-jcc", name, row.va, at, row.data[at - row.va] ^ 1, row.data[at - row.va]))
            elif (row.imm_at is not None and row.imm_size == 1 and name in IMM_TARGETS
                  and row.op in ("cmp", "and", "shl", "shr", "test", "or", "add", "sub", "mov")
                  and row.a and row.a[0] in ("r", "m") and row.a[1] != RSP):
                old = row.data[row.imm_at]
                rows.append(("imm+1", name, row.va, row.va + row.imm_at, (old + 1) & 0xFF, old))
    return rows


IMM_TARGETS = ("option_display", "positional_display", "positional_name", "join", "is_set_flag", "values_iter",
               "default_value", "aliases_flag")
MODEL_MUTANTS = (("option", "equals_inverted"), ("option", "count_two"), ("option", "dots_always"),
                 ("option", "ignore_delim_flag"), ("positional", "ignore_delim_flag"),
                 ("positional", "join_no_brackets"), ("positional", "count_two"), ("name", "bracket_limit"),
                 ("name", "last_value"), ("name", "ignore_delim_flag"))
ACCESSOR_MUTANTS = ("load", "pair", "nonnull", "tag", "optslice", "fieldptr", "taggedptr")
HOME = {"flag_display": ("flag",), "option_display": ("option",), "positional_display": ("positional",),
        "positional_name": ("name",), "collect_names": ("positional", "name"), "join": ("positional", "name"),
        "grow": ("positional", "name")}


def first_diff(rig, kind, sample, mut=None):
    for index, (arg, fail_at, seed) in enumerate(sample):
        want = model_result(kind, arg, fail_at, mut)
        got = rig.run(arg, kind, Xorshift(seed + 1), fail_at)
        if want != got:
            return index
    return None


HEIGHT_EIGHT = ("reached only when the height or climb count is not a multiple of 8 (the multiple-of-8 case takes the "
                "branch before it), so the compared value is never exactly 8 and 8 -> 9 changes nothing")
LEFTMOST_INDEX = ("the first value is fetched along the leftmost edge chain (edge 0 at every level), so the parent index "
                  "being scaled by 16 is always 0 and 0 << 4 == 0 << 5")
CONST_BOOL = "register holds the constant 1 and is only tested for non-zero afterwards, so 1 -> 2 is the same boolean"
SEPARATOR_LENGTH = ("a char separator is 1..4 bytes: the dispatch only chooses between the specialised copy loops and the generic "
                    "loop at 0x166a25a, which copies the same bytes; length 5 cannot occur")
SHORT_ELEMENT = ("bound check 'bytes left >= separator length' with the threshold raised by one: join is only called here on the "
                 "'<name>' strings, at least 2 bytes each, so the bytes left at every separator copy are at least the "
                 "separator length plus 2 and the raised threshold is never crossed")
EQUIVALENT_SITES = {
    0x166e513: "register eax was just cleared, so testing bit 0 or bit 1 of al is always zero",
    0x166e595: HEIGHT_EIGHT, 0x166e688: HEIGHT_EIGHT, 0x166e8d8: HEIGHT_EIGHT, 0x1672235: HEIGHT_EIGHT,
    0x166e6ea: LEFTMOST_INDEX, 0x16722e6: LEFTMOST_INDEX,
    0x166e724: "this join point is reached with rbx = rbp = 0 only, where both targets (0x166e520 and 0x166e72e) end at 0x166eb13",
    0x166e726: "this join point is reached with rbx = rbp = 0 only, where both targets (0x166e520 and 0x166e72e) end at 0x166eb13",
    0x166e728: "this join point is reached with rbx = rbp = 0 only, where both targets (0x166e520 and 0x166e72e) end at 0x166eb13",
    0x166eaa8: "the mask only feeds the length 3 * (flags >> 1 & 1) and a pointer choice for a zero-length string; bit 0 (required) "
               "changes the pointer of an empty chunk, never its text",
    0x1675b13: CONST_BOOL, 0x167201d: CONST_BOOL,
    0x166a036: SEPARATOR_LENGTH, 0x166a03a: SEPARATOR_LENGTH,
    0x166a0c0: SHORT_ELEMENT, 0x166a130: SHORT_ELEMENT, 0x166a1a0: SHORT_ELEMENT,
    0x165cdd0: "frees the empty temporary Vec only when its capacity is non-zero; 0x16572b0 returns capacity 0 whenever it returns length 0",
    0x1657405: "unwind landing pad after the allocation-error call; the rig's allocation-error stub raises instead of unwinding",
}
MODEL_EQUIVALENT = {("name", "last_value"): "the branch runs only for a map with exactly one entry, where the first and the last value are the same"}


def equivalence_reason(func, va):
    return EQUIVALENT_SITES.get(va)


def body_detected(image, func, va, at, new, rows):
    """Run the checks that exercise `func` on the patched code; True when some case differs."""
    patches = {at: new}
    counters = {"accessor": 0}
    if func in ("is_set_flag", "set_flag"):
        return not check_settings(image, None, counters, AccessorRig(image, patches), limit=1)
    if func in ("values_iter", "default_value"):
        owner = {"values_iter": 0x163B830, "default_value": 0x163B890}[func]
        return not check_bodies(image, None, counters, patches, True, 40, only=owner, rows=rows)
    if func in ("aliases_flag", "collect_visible"):
        return not check_bodies(image, None, counters, patches, True, 60, only=0x165CD60, rows=rows)
    return not check_accessors(image, None, counters, patches, True, 30, only=func, rows=rows)


def accessor_ranges(image, rows):
    seen, out = set(), []
    for kind, index, slot, target, cls, params in rows:
        if cls in BIG or target in seen:
            continue
        seen.add(target)
        out.append((target, image.exact_fde(target)[1]))
    return out


def run_controls(image, sink, equiv_sink, gap_sink):
    samples = {k: list(cases(k, MUTANT_CASES, 0x2115 + n)) for n, k in enumerate(("flag", "option", "positional", "name"))}
    baseline = Rig(image)
    for kind, sample in samples.items():
        for arg, fail_at, seed in sample:
            baseline.run(arg, kind, Xorshift(seed + 1), fail_at)
    executed = baseline.m.seen
    rows = accessor_rows(image)
    state = {"total": 0, "detected": 0, "equivalent": 0}

    def report(style, func, va, at, new, old, found, via):
        state["total"] += 1
        state["detected"] += int(found)
        verdict = "detected" if found else "undetected"
        reason = equivalence_reason(func, va) if not found else None
        if reason:
            verdict = "equivalent"
            state["equivalent"] += 1
            equiv_sink("%s %s %#x\t%#x:%02x->%02x\t%s\n" % (style, func, va, at, old, new, reason))
        sink("%s\t%s\t%#x\t%#x:%02x->%02x\t%s\t%s\n" % (style, func, va, at, old, new, verdict, via if found else "-"))

    for style, func, va, at, new, old in enumerate_mutants(image):
        if func in HOME:
            if va not in executed:
                gap_sink("%s\t%s\t%#x\t%#x:%02x->%02x\n" % (style, func, va, at, old, new))
                continue
            rig = Rig(image, patches={at: new})
            found, via = None, "-"
            for kind in HOME[func]:
                found = first_diff(rig, kind, samples[kind])
                if found is not None:
                    via = "%s case %d" % (kind, found)
                    break
            report(style, func, va, at, new, old, found is not None, via)
        else:
            report(style, func, va, at, new, old, body_detected(image, func, va, at, new, rows), "accessor records")
    for lo, hi in accessor_ranges(image, rows):
        for row in decode_range(image, lo, hi):
            if row.op == "jcc":
                at = row.va + (1 if row.data[0] == 0x0F else 0)
                new, old = row.data[at - row.va] ^ 1, row.data[at - row.va]
                report("flip-jcc", "accessor %#x" % lo, row.va, at, new, old, body_detected(image, lo, row.va, at, new, rows),
                       "accessor records")
            elif row.imm_at is not None and row.imm_size == 1 and row.op == "mov":
                old = row.data[row.imm_at]
                at, new = row.va + row.imm_at, (old + 1) & 0xFF
                report("imm+1", "accessor %#x" % lo, row.va, at, new, old, body_detected(image, lo, row.va, at, new, rows),
                       "accessor records")
    total, detected = state["total"], state["detected"]
    equivalent = state["equivalent"]
    for kind, mut in MODEL_MUTANTS:
        total += 1
        found = first_diff(Rig(image), kind, samples[kind], mut)
        if found is None and (kind, mut) in MODEL_EQUIVALENT:
            equivalent += 1
            equiv_sink("model %s %s\t-\t%s\n" % (kind, mut, MODEL_EQUIVALENT[(kind, mut)]))
            sink("model\t%s\t%s\t-\tequivalent\t-\n" % (kind, mut))
            continue
        detected += found is not None
        sink("model\t%s\t%s\t-\t%s\t%s\n" % (kind, mut, "detected" if found is not None else "undetected",
                                             "case %d" % found if found is not None else "-"))
    counters = {"accessor": 0}
    for cls in ACCESSOR_MUTANTS:
        total += 1
        found = not check_accessors(image, None, counters, None, True, 30, wrong=cls, rows=rows)
        detected += found
        sink("model\taccessor\toffset+8 in %s\t-\t%s\t-\n" % (cls, "detected" if found else "undetected"))
    for mut in ("shift_plus", "xor_mask"):
        total += 1
        found = not check_settings(image, None, counters, None, mut=mut, limit=1)
        detected += found
        sink("model\tsettings\t%s\t-\t%s\t-\n" % (mut, "detected" if found else "undetected"))
    total += 1
    found = not check_bodies(image, None, counters, None, True, 40, only=0x165CD60, mut="all_visible", rows=rows)
    detected += found
    sink("model\taliases\tall_visible\t-\t%s\t-\n" % ("detected" if found else "undetected"))
    for table_va, label_text in ((0x46CF60, "mask table entry 0"), (0x46CF64, "mask table entry 1"),
                                 (0x46CF70, "mask table entry 4")):
        total += 1
        old = int.from_bytes(image.blob[image.offset(table_va):image.offset(table_va) + 4], "little")
        rig = AccessorRig(image)
        rig.m.memory.statics[table_va] = old ^ 0x10
        found = not check_settings(image, None, counters, rig, limit=1)
        detected += found
        sink("table-byte\t%s\t%#x\t%08x->%08x\t%s\t-\n" % (label_text, table_va, old, old ^ 0x10,
                                                         "detected" if found else "undetected"))
    return total, detected, equivalent



# ----------------------- trait-object accessor families ----------------------
#
# Each argument kind (flag, option, positional) has a trait-object method table that follows its Display slot. The
# tiny accessors in those tables are classified from their decoded instructions and every class has an executable
# model that is run against the real bytes on random argument records; the larger bodies (is_set / set through the
# setting tables, visible aliases, value-iterator constructors) have their own models.

ACC_REG = {"flag": 0x6405A60, "option": 0x6405B58, "positional": 0x6405C50}
ACC_RECORD = 0x200
ACC_CASES = 120
ACC_OUT = HEAP_BASE + 0xB00
NICHE = 0x8000000000000000
REAL = REAL + (0x16572B0,)


def method_slots(image, kind):
    """(slot, target) pairs of the method table that follows the Display slot, until a non-function entry."""
    relative, rows = image.relative(), []
    slot = ACC_REG[kind] + 8
    while slot in relative and relative[slot] in image.fde_ends:
        rows.append((slot, relative[slot]))
        slot += 8
    return rows


def is_mem(operand, base=RDI):
    return operand is not None and operand[0] == "m" and operand[1] == base and operand[2] is None


def classify(rows):
    """Class name and parameters of a tiny accessor from its decoded instructions, or None."""
    ops = [r.op for r in rows]
    if ops == ["xor", "ret"] and rows[0].a == ("r", RAX) and rows[0].b == ("r", RAX):
        return "zero", {}
    if ops == ["mov", "ret"] and rows[0].a == ("r", RAX) and rows[0].b[0] == "i":
        return "const", {"value": rows[0].b[1], "width": rows[0].width}
    if ops == ["mov", "ret"] and rows[0].a == ("r", RAX) and is_mem(rows[0].b):
        return "load", {"disp": rows[0].b[4], "width": rows[0].width}
    if ops == ["mov", "mov", "ret"] and rows[0].a == ("r", RAX) and rows[1].a == ("r", RDX) \
            and is_mem(rows[0].b) and is_mem(rows[1].b):
        return "pair", {"first": rows[0].b[4], "second": rows[1].b[4]}
    if ops == ["cmp", "set", "ret"] and is_mem(rows[0].a) and rows[0].b == ("i", 0) and rows[1].cc == 5:
        return "nonnull", {"disp": rows[0].a[4]}
    if ops == ["mov", "mov", "ret"] and rows[0].a == ("r", RAX) and rows[0].b == ("r", RDI) \
            and is_mem(rows[1].a) and rows[1].b[0] == "i":
        return "tag", {"disp": rows[1].a[4], "value": rows[1].b[1]}
    if ops == ["xor", "cmp", "mov", "jcc", "mov", "ret"] and is_mem(rows[1].b) and is_mem(rows[2].b) and is_mem(rows[4].b):
        return "optslice", {"cap": rows[1].b[4], "ptr": rows[4].b[4], "len": rows[2].b[4]}
    if ops == ["mov", "lea", "test", "cmov", "ret"] and is_mem(rows[0].b) and is_mem(rows[1].b) and rows[0].b[4] == rows[1].b[4]:
        return "fieldptr", {"disp": rows[0].b[4]}
    if ops == ["mov", "mov", "mov", "ret"] and rows[0].a == ("r", RAX) and rows[0].b == ("r", RDI) and rows[1].a == ("r", RCX) \
            and rows[1].b[0] == "i" and is_mem(rows[2].a) and rows[2].b == ("r", RCX):
        return "tag", {"disp": rows[2].a[4], "value": rows[1].b[1]}
    if ops == ["xor", "cmp", "lea", "cmov", "ret"] and rows[1].a[0] == "m" and rows[1].a[4] == 0 and rows[1].b == ("i", 0):
        return "taggedptr", {"disp": rows[2].b[4]}
    return None


def le(blob, disp, width):
    return int.from_bytes(blob[disp:disp + width], "little")


def model_accessor(cls, params, record):
    """(rax, rdx or None, record after) for a classified accessor on a record (bytes)."""
    if cls == "zero":
        return 0, None, record
    if cls == "const":
        return params["value"] & MASK[params["width"]], None, record
    if cls == "load":
        return le(record, params["disp"], params["width"]), None, record
    if cls == "pair":
        return le(record, params["first"], 8), le(record, params["second"], 8), record
    if cls == "nonnull":
        return int(le(record, params["disp"], 8) != 0), None, record
    if cls == "tag":
        after = bytearray(record)
        after[params["disp"]:params["disp"] + 8] = (params["value"] & MASK[8]).to_bytes(8, "little")
        return None, None, bytes(after)
    if cls == "optslice":
        cap = le(record, params["cap"], 8)
        return (0 if cap == NICHE else le(record, params["ptr"], 8)), le(record, params["len"], 8), record
    if cls == "taggedptr":
        return (STRUCT + params["disp"] if record[0] else 0), None, record
    if cls == "fieldptr":
        value = le(record, params["disp"], 8)
        return (STRUCT + params["disp"] if value else 0), None, record
    raise EvidenceError("unknown accessor class " + cls)


def random_record(rng, size=ACC_RECORD):
    data = bytearray(size)
    for at in range(0, size, 8):
        data[at:at + 8] = rng.next().to_bytes(8, "little")
    for at in range(0, size, 8):
        roll = rng.below(7)
        if roll == 0:
            data[at:at + 8] = (0).to_bytes(8, "little")
        elif roll == 1:
            data[at:at + 8] = NICHE.to_bytes(8, "little")
        elif roll == 2:
            data[at:at + 8] = (NICHE + 1).to_bytes(8, "little")
    return bytes(data)


class AccessorRig:
    def __init__(self, image, patches=None):
        self.rig = Rig(image, patches)
        self.m = self.rig.m

    def call(self, va, record, rdi_out=False, extra=None):
        rig, mem = self.rig, self.m.memory
        mem.reset(USED)
        rig.reset_state()
        mem.put_bytes(STRUCT, record)
        for at, data in (extra or {}).items():
            mem.put_bytes(at, data)
        mem.put_bytes(ACC_OUT, bytes(0xA5 for _ in range(0x60)))
        args = {RDI: ACC_OUT, RSI: STRUCT} if rdi_out else {RDI: STRUCT, RSI: 0}
        try:
            self.m.run(va, args)
        except Panic:
            return ("panic",)
        except Halt as exc:
            return ("halt:" + str(exc),)
        return ("ok", self.m.regs[RAX], self.m.regs[RDX], mem.bytes_at(STRUCT, len(record)),
                mem.bytes_at(ACC_OUT, 0x60), len(rig.live))


def run_accessor(rig, va, cls, params, record):
    got = rig.call(va, record)
    if got[0] != "ok":
        return got
    rax, rdx, after = got[1], got[2], got[3]
    return (rax, rdx, after)


def expect_accessor(cls, params, record):
    rax, rdx, after = model_accessor(cls, params, record)
    return rax, rdx, after


def accessor_compare(cls, params, got, want):
    """Compare only what the class defines: rax width, rdx when a second value is returned, the record afterwards."""
    if got[0] in ("panic",) or str(got[0]).startswith("halt"):
        return False
    width = {"nonnull": 1, "load": params.get("width", 8), "const": params.get("width", 8)}.get(cls, 8)
    if cls == "tag":
        return got[2] == want[2] and got[0] == got[0]
    ok = (got[0] & MASK[width]) == want[0] and got[2] == want[2]
    if want[1] is not None:
        ok = ok and got[1] == want[1]
    return ok


# --- larger bodies -----------------------------------------------------------

def table_entries(image, fn_lo, fn_hi, table_va):
    out, at = [], image.offset(table_va)
    while True:
        rel = int.from_bytes(image.blob[at:at + 4], "little", signed=True)
        target = table_va + rel
        if not fn_lo <= target < fn_hi:
            return out
        out.append(target)
        at += 4


def lea_rip(image, lo, hi, opcode_tail):
    """Target of the first `lea r64, [rip+rel32]` with the given modrm byte inside [lo, hi)."""
    at = image.offset(lo)
    blob = image.blob
    for k in range(hi - lo - 7):
        if blob[at + k] in (0x48, 0x4C) and blob[at + k + 1] == 0x8D and blob[at + k + 2] == opcode_tail:
            rel = int.from_bytes(blob[at + k + 3:at + k + 7], "little", signed=True)
            return lo + k + 7 + rel
    raise EvidenceError("no rip-relative table load in %#x" % lo)


def shift_bit(image, target):
    at = image.offset(target)
    b = image.blob[at:at + 6]
    if b[0] == 0xD0 and b[1] == 0xE8 and b[2:4] == b"\x24\x01":
        return 1
    if b[0] in (0xC0, 0xC1) and b[1] == 0xE8 and b[3:5] == b"\x24\x01":
        return b[2]
    if b[0:2] == b"\x24\x01":
        return 0
    raise EvidenceError("unrecognised setting test at %#x" % target)


def setting_tables(image, is_set_va, set_va):
    """(flags disp, [bit per setting], [mask per setting]) read from the two setting functions' tables."""
    lo, hi = is_set_va, image.exact_fde(is_set_va)[1]
    jump = lea_rip(image, lo, hi, 0x15)
    bits = [shift_bit(image, t) for t in table_entries(image, lo, hi, jump)]
    at = image.offset(lo)
    disp = int.from_bytes(image.blob[at + 2:at + 6], "little")
    s_lo, s_hi = set_va, image.exact_fde(set_va)[1]
    mask_va = lea_rip(image, s_lo, s_hi, 0x0D)
    mat = image.offset(mask_va)
    masks = [int.from_bytes(image.blob[mat + 4 * k:mat + 4 * k + 4], "little") for k in range(len(bits))]
    return disp, bits, masks


SETTING_FUNCS = {"flag": (0x165CCD0, 0x165CCB0), "option": (0x166F330, 0x166F310), "positional": (0x16760F0, 0x16760D0)}


def model_is_set(disp, bits, record, index, mut=None):
    shift = bits[index] if mut != "shift_plus" else bits[index] + 1
    return (le(record, disp, 4) >> shift) & 1


def model_set(disp, masks, record, index, mut=None):
    after = bytearray(record)
    value = le(record, disp, 4) | masks[index]
    if mut == "xor_mask":
        value = le(record, disp, 4) ^ masks[index]
    after[disp:disp + 4] = value.to_bytes(4, "little")
    return bytes(after)


def check_settings(image, sink, counters, mut_rig=None, mut=None, limit=None):
    """Run is_set / set for every setting index of every kind on random records; True if all agree."""
    rig = mut_rig or AccessorRig(image)
    rng = Xorshift(0x5E77)
    result = []
    for kind, (is_va, set_va) in SETTING_FUNCS.items():
        disp, bits, masks = setting_tables(image, is_va, set_va)
        for index in range(len(bits)):
            for round_ in range(16):
                record = random_record(rng)
                got = rig.call_setting(is_va, record, index)
                want = model_is_set(disp, bits, record, index, mut)
                counters["accessor"] += 1
                if got != ("ok", want):
                    if limit is not None:
                        return False
                    raise EvidenceError("is_set differs: %s %d" % (kind, index))
                got_set = rig.call_setting(set_va, record, index)
                want_set = model_set(disp, masks, record, index, mut)
                counters["accessor"] += 1
                if got_set != ("ok", want_set):
                    if limit is not None:
                        return False
                    raise EvidenceError("set differs: %s %d" % (kind, index))
                if round_ == 0 and sink:
                    sink("setting\t%s\t%d\tbit=%d\tmask=%#x\tis_set=%d\tafter_set=%s\n" % (
                        kind, index, bits[index], masks[index], want, model_set(disp, masks, bytes(ACC_RECORD), index)[disp:disp + 4].hex()))
    return True


def call_setting(self, va, record, index):
    rig, mem = self.rig, self.m.memory
    mem.reset(USED)
    rig.reset_state()
    mem.put_bytes(STRUCT, record)
    try:
        self.m.run(va, {RDI: STRUCT, RSI: index})
    except Panic:
        return ("panic",)
    except Halt as exc:
        return ("halt:" + str(exc),)
    if va in (s[0] for s in SETTING_FUNCS.values()):
        return ("ok", self.m.regs[RAX] & 0xFF)
    return ("ok", mem.bytes_at(STRUCT, len(record)))


AccessorRig.call_setting = call_setting


def mem_disps(rows):
    return [r.b[4] if is_mem(r.b, RSI) else r.a[4] for r in rows if is_mem(r.b, RSI) or (r.a and is_mem(r.a, RSI))]


def model_values_iter(record, params):
    """Option<btree Values> constructor: 9 words written at the output, or only the tag word 2 when the map is absent."""
    out = bytearray(0xA5 for _ in range(0x60))
    if le(record, params[0], 4) != 1:
        out[0:8] = (2).to_bytes(8, "little")
        return bytes(out)
    root, height, length = (le(record, d, 8) for d in params[1:4])
    state = 1 if root else 0
    words = [state, 0, root, height, state, 0, root, height, length if root else root]
    for k, w in enumerate(words):
        out[8 * k:8 * k + 8] = w.to_bytes(8, "little")
    return bytes(out)


def model_default_value(record, params, mut=None):
    """Option<(&str, Option<&..>)>: niche word + 1 means absent, niche word means a value without the trailing reference."""
    out = bytearray(0xA5 for _ in range(0x60))
    tag, first, second = (le(record, d, 8) for d in params)
    if tag == NICHE + 1:
        out[0:8] = bytes(8)
        return bytes(out)
    out[0:8] = first.to_bytes(8, "little")
    out[8:16] = second.to_bytes(8, "little")
    out[16:24] = (STRUCT + params[0] if tag != NICHE else 0).to_bytes(8, "little")
    return bytes(out)


def alias_record(rng, params):
    cap_d, ptr_d, len_d = params
    record = bytearray(random_record(rng))
    count = rng.below(9)
    extra, items = {}, []
    strings = HEAP_BASE + 0x20000
    array = HEAP_BASE + 0x8000
    for k in range(count):
        text = word(rng)
        data = utf8(text)
        extra[strings] = data
        entry = (strings.to_bytes(8, "little") + len(data).to_bytes(8, "little") + bytes([rng.below(2)]) + bytes(7))
        extra[array + 24 * k] = entry
        items.append((text, entry[16]))
        strings += 32
    absent = rng.below(4) == 0
    record[cap_d:cap_d + 8] = (NICHE if absent else count + rng.below(3)).to_bytes(8, "little")
    record[ptr_d:ptr_d + 8] = array.to_bytes(8, "little")
    record[len_d:len_d + 8] = count.to_bytes(8, "little")
    return bytes(record), extra, (None if absent else items)


def model_aliases(items, mut=None):
    """(vec contents or None, capacity) of the visible aliases, capacity as the amortised growth gives it."""
    if items is None:
        return None, 0
    seen = [text for text, visible in items if visible or mut == "all_visible"]
    if not seen:
        return None, 0
    cap = 4
    while cap < len(seen):
        cap *= 2
    return seen, cap


def check_aliases(rig, va, params, rounds, rng_seed, mut=None, sink=None):
    rng = Xorshift(rng_seed)
    for round_ in range(rounds):
        record, extra, items = alias_record(rng, params)
        got = rig.call(va, record, True, extra)
        want, cap = model_aliases(items, mut)
        if got[0] != "ok":
            return False
        out, live = got[4], got[5]
        if want is None:
            ok = out[0:8] == NICHE.to_bytes(8, "little") and live == 0
        else:
            ptr, length = int.from_bytes(out[8:16], "little"), int.from_bytes(out[16:24], "little")
            names = []
            for k in range(length):
                sptr = rig.m.memory.read(ptr + 16 * k, 8)
                slen = rig.m.memory.read(ptr + 16 * k + 8, 8)
                names.append(rig.rig.text(sptr, slen).decode("utf-8", "backslashreplace"))
            ok = names == want and int.from_bytes(out[0:8], "little") == cap and live == 1
        if not ok:
            return False
        if sink and round_ < 2:
            sink("aliases\t%#x\tn=%d\t%s\n" % (va, 0 if items is None else len(items), "-" if want is None else ",".join(want)))
    return True


def accessor_rows(image):
    """(kind, index, slot, target, class, params) for every method-table entry; larger bodies get their own names."""
    named = {0x165CD60: "aliases", 0x166F3C0: "aliases", 0x163B830: "values_iter", 0x163BA80: "values_iter",
             0x163B890: "default_value", 0x163BAE0: "default_value", 0x163B130: "drop_glue", 0x163B200: "drop_glue",
             0x163B020: "drop_glue"}
    for kind, (is_va, set_va) in SETTING_FUNCS.items():
        named[is_va], named[set_va] = "is_set", "set"
    rows = []
    for kind in ("flag", "option", "positional"):
        for index, (slot, target) in enumerate(method_slots(image, kind)):
            if target in named:
                rows.append((kind, index, slot, target, named[target], {}))
                continue
            end = image.exact_fde(target)[1]
            found = classify(decode_range(image, target, end))
            if found is None:
                rows.append((kind, index, slot, target, "unclassified", {}))
            else:
                rows.append((kind, index, slot, target, found[0], found[1]))
    return rows


BIG = ("unclassified", "is_set", "set", "aliases", "values_iter", "default_value", "drop_glue")


def check_accessors(image, sink, counters, patches=None, stop_on_diff=False, per_function=ACC_CASES, only=None,
                    wrong=None, rows=None):
    rig = AccessorRig(image, patches)
    seen = {}
    for kind, index, slot, target, cls, params in (rows or accessor_rows(image)):
        if cls in BIG or (only is not None and target != only):
            continue
        if wrong == cls:
            params = dict(params, **{k: v + 8 for k, v in params.items() if k in ("disp", "first", "second", "cap", "ptr", "len")})
        if target in seen:
            continue
        seen[target] = cls
        rng = Xorshift(0xACC0 + target)
        for round_ in range(per_function):
            record = random_record(rng)
            got = run_accessor(rig, target, cls, params, record)
            want = expect_accessor(cls, params, record)
            counters["accessor"] += 1
            if not accessor_compare(cls, params, got, want):
                if stop_on_diff:
                    return False
                raise EvidenceError("accessor differs: %s %#x %s" % (cls, target, params))
            if sink and round_ == 0:
                sink("accessor\t%s\t%#x\t%s\t%s\n" % (kind, target, cls, ",".join("%s=%#x" % kv for kv in sorted(params.items()))))
    return True


def body_params(image, target):
    """Distinct record offsets a body reads through its second argument, in first-use order."""
    rows = decode_range(image, target, image.exact_fde(target)[1])
    out = []
    for d in mem_disps(rows):
        if d not in out:
            out.append(d)
    return out


def check_bodies(image, sink, counters, patches=None, stop_on_diff=False, rounds=ACC_CASES, only=None, mut=None, rows=None,
                 byte_overrides=None):
    rig = AccessorRig(image, patches)
    for address, value in (byte_overrides or {}).items():
        rig.m.memory.statics[address] = value
    for kind, index, slot, target, cls, params in (rows or accessor_rows(image)):
        if cls not in ("values_iter", "default_value", "aliases") or (only is not None and target != only):
            continue
        disps = body_params(image, target)
        rng = Xorshift(0xB0D1 + target)
        if cls == "aliases":
            try:
                ok = check_aliases(rig, target, disps[:3], rounds, 0xA11A5 + target, mut, sink)
            except (Halt, Panic, EvidenceError):
                ok = False
            counters["accessor"] += rounds
            if not ok:
                if stop_on_diff:
                    return False
                raise EvidenceError("aliases differ at %#x" % target)
            continue
        for round_ in range(rounds):
            record = random_record(rng)
            got = rig.call(target, record, True)
            want = (model_values_iter if cls == "values_iter" else model_default_value)(record, disps)
            counters["accessor"] += 1
            if got[0] != "ok" or got[4] != want:
                if stop_on_diff:
                    return False
                raise EvidenceError("%s differs at %#x" % (cls, target))
            if sink and round_ == 0:
                sink("body\t%s\t%#x\t%s\t%s\n" % (kind, target, cls, ",".join("%#x" % d for d in disps)))
    return True


# ------------------------------------ main ------------------------------------

def stream_checks(image, sink, counters, coverage):
    rig = Rig(image)
    for n, kind in enumerate(("flag", "option", "positional", "name")):
        sampled = 0
        for arg, fail_at, seed in cases(kind, COUNTS[kind], 0x1150 + n):
            want = model_result(kind, arg, fail_at)
            got = rig.run(arg, kind, Xorshift(seed + 1), fail_at)
            counters[kind] += 1
            if want != got:
                raise EvidenceError("model and code differ: %s %s %r %r" % (kind, label(arg, fail_at), want, got))
            if sampled < SAMPLE_LINES[kind]:
                sampled += 1
                sink("%s\t%s\t%s\n" % (kind, label(arg, fail_at), show(got)))
    coverage.update(rig.m.seen)


def build(out):
    image = load_image(BINARY, SHA256)
    os.makedirs(out, exist_ok=True)
    counters = {"flag": 0, "option": 0, "positional": 0, "name": 0, "accessor": 0}
    coverage = set()
    with open(os.path.join(out, "cases.tsv"), "w", newline="\n") as handle:
        handle.write("kind\tinput\tresult\n")
        stream_checks(image, handle.write, counters, coverage)
    rows = accessor_rows(image)
    with open(os.path.join(out, "method-tables.tsv"), "w", newline="\n") as handle:
        handle.write("kind\tindex\tslot\ttarget\tclass\tparameters\n")
        for kind, index, slot, target, cls, params in rows:
            handle.write("%s\t%d\t%#x\t%#x\t%s\t%s\n" % (kind, index, slot, target, cls,
                                                        ",".join("%s=%#x" % kv for kv in sorted(params.items())) or "-"))
    with open(os.path.join(out, "accessor-checks.tsv"), "w", newline="\n") as handle:
        handle.write("check\tkind\ttarget\tclass\tparameters\n")
        check_accessors(image, handle.write, counters, rows=rows)
        check_bodies(image, handle.write, counters, rows=rows)
    with open(os.path.join(out, "settings.tsv"), "w", newline="\n") as handle:
        handle.write("check\tkind\tindex\tbit\tmask\tis_set\tafter_set\n")
        check_settings(image, handle.write, counters)
    with open(os.path.join(out, "static-bytes.tsv"), "w", newline="\n") as handle:
        handle.writelines(static_rows(image))
    with open(os.path.join(out, "function-extents.tsv"), "w", newline="\n") as handle:
        handle.writelines(extent_rows(image))
    with open(os.path.join(out, "controls.tsv"), "w", newline="\n") as handle, \
            open(os.path.join(out, "equivalent-mutants.tsv"), "w", newline="\n") as equiv:
        handle.write("style\ttarget\taddress\tchange\tverdict\tfirst_difference\n")
        equiv.write("mutant\tchange\treason\n")
        with open(os.path.join(out, "coverage-gaps.tsv"), "w", newline="\n") as gaps:
            gaps.write("style\ttarget\taddress\tchange\n")
            total, detected, equivalent = run_controls(image, handle.write, equiv.write, gaps.write)
    summary = {"cases": sum(counters.values()), "negative_controls": total, "negative_detected": detected,
               "equivalent": equivalent, "cases_by_kind": counters, "binary_sha256": SHA256,
               "instructions_executed_distinct": len(coverage)}
    with open(os.path.join(out, "measure.json"), "w", newline="\n") as handle:
        json.dump(summary, handle, indent=1, sort_keys=True)
        handle.write("\n")
    return summary


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", required=True)
    args = parser.parse_args(argv)
    print(json.dumps(build(args.out), sort_keys=True))


if __name__ == "__main__":
    main()
