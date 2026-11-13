#!/usr/bin/env python3
"""Node #115 quantity-name dispatcher 0x2913750: flow model, emulator comparison and mutant controls.

Parts 1-2 (up to the HARNESS marker) are a bounded offline x86-64 interpreter over the ELF bytes; the binary is never executed.
Part 3 rebuilds the dispatcher as a pure Python model and compares it with the interpreter on every generated case.

    python3 tools/quantities_dispatch115.py --out <dir>
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




# ======================================================================================================================================
# HARNESS: quantity-name dispatcher 0x2913750 (FDE 0x2913750..0x2914169, 2585 bytes)
# ======================================================================================================================================

import argparse  # noqa: E402
import collections  # noqa: E402
import json  # noqa: E402
import random  # noqa: E402

FN = 0x2913750
FN_END = 0x2914169
RANGE_FN = 0x22b3160
RANGE_END = 0x22b3298
TABLE = 0x5FD4BC
SENT = 1 << 63
M64 = (1 << 64) - 1
TAG_OK = 0x1A2
IN, OUT, CTX, RO = HEAP_BASE + 0x1000, HEAP_BASE + 0x2000, HEAP_BASE + 0x10000, HEAP_BASE + 0x20000
BUMP0 = HEAP_BASE + 0x100000
RESET_USED = 0x120000
OUT_LEN = 0x70
LIMIT_MASK_ROW = 0x5F45A5F
SMALL_MAX = 0x270F
ID_OFFSET = 100000
STRIDE = 10000
LEN_GATE = 0x65
TAG_LONG, TAG_SENTINEL, TAG_NEXT, TAG_RANGE = 0x158, 0x156, 0x1A1, 0xFA

# call-target names, direct calls first, then the GOT slots reached through `call [rip+disp]`
DIRECT = {0x43CD290: "S", 0x28CD7A0: "W", 0x2C4FCD0: "H", 0x2DC7AD0: "X", 0x2C51AB0: "Y", 0x2C59960: "Z", 0x29330F0: "DROP", 0x2BEE760: "VIS"}
SLOTS = {0x64E6A68: "A", 0x64E69B8: "B", 0x64E4E58: "C", 0x64E6C18: "D", 0x64E6C20: "E", 0x64E6AD8: "F", 0x64E6C28: "G",
         0x64DF508: "MEM", 0x64DF4A0: "FREE", 0x64DF480: "ALLOC", 0x64DF498: "ALLOCERR", 0x64DF870: "MULP", 0x64DF520: "ADDP"}


class Trapped(Exception):
    pass


def u64(buf, at):
    return int.from_bytes(buf[at:at + 8], "little")


def expand(seed, size):
    """Deterministic filler bytes."""
    out, counter = b"", 0
    while len(out) < size:
        out += hashlib.sha256(seed + counter.to_bytes(4, "little")).digest()
        counter += 1
    return out[:size]


def oracle(name, key, ok, payload):
    """Result record an unmodelled callee writes: 0x70 hash-derived bytes, tag word 0x1a2 on success, never 0x1a2 on failure."""
    raw = bytearray(expand(name.encode() + b"|" + key, OUT_LEN))
    if ok:
        raw[0:2] = TAG_OK.to_bytes(2, "little")
        for off, value in payload.items():
            raw[off:off + 8] = (value & M64).to_bytes(8, "little")
    else:
        raw[0:2] = (0x180 + raw[0] % 0x20).to_bytes(2, "little")
    return bytes(raw)


def pk(*words):
    return b"".join((w & M64).to_bytes(8, "little") for w in words)


def asset_id(value):
    """Arm 0 narrowing of the parsed integer: below 10000 as is, up to 0x5f45a5f offset by 100000, otherwise all ones."""
    if value <= SMALL_MAX:
        return value
    if value <= LIMIT_MASK_ROW:
        return (value + ID_OFFSET) & 0xFFFFFFFF
    return 0xFFFFFFFF


def table_targets(image):
    """Jump-table entries 0.. while the target stays near the dispatcher (the table end is not bounds-checked in the code)."""
    rows, index = [], 0
    while True:
        at = image.offset(TABLE + 4 * index)
        entry = struct.unpack("<i", bytes(image.blob[at:at + 4]))[0]
        target = TABLE + entry
        if not 0x2900000 <= target < 0x2930000:
            return rows
        rows.append(target)
        index += 1


def arm_index(tag):
    return (tag - SENT - 13) & M64 if tag > SENT + 12 else 5


# --------------------------------------------------------------------------------------------------------------------------------
# pure model
# --------------------------------------------------------------------------------------------------------------------------------
def model_range(case, log, a=0):
    """22b3160 for the half-open range [a, b) with b = case r_end, over the record word at +0x50. Returns (ids, panic)."""
    n, scale = max(case["r_end"] - a, 0), case["r_scale"]
    if n >> 60:
        log.append(("ALLOCERR", 0, (8 * n) & M64))
        return None, "alloc-error"
    if n == 0:
        return [], None
    log.append(("ALLOC", 8 * n))
    if case["alloc_fail"]:
        log.append(("ALLOCERR", 8, 8 * n))
        return None, "alloc-error"
    ids = []
    for i in range(n):
        product = scale * STRIDE
        if product > M64:
            log.append(("MULP",))
            return None, "mul"
        total = (((a + product) & M64) + i) & M64
        if total < product:
            log.append(("ADDP",))
            return None, "add"
        ids.append(total)
    return ids, None


def model_direct(case):
    """Direct call of the range body: (kind, log, n, ptr, ids)."""
    log = []
    ids, panic = model_range(case, log, case["range_a"])
    if panic:
        return "panic:" + panic, log, 0, 0, []
    return "ret", log, len(ids), BUMP0 if ids else 8, ids


def model(case, targets):
    """Return (kind, expectations, log, r468). Expectations are (offset, size, bytes) over the output record."""
    inp, log, exp, r468 = case["inp"], [], [], None
    tag = u64(inp, 0)
    arm = arm_index(tag)
    script = case["script"]
    ctx_key = 0

    def free(ptr, cap):
        if cap:
            log.append(("FREE", ptr, cap, 0))

    def result(kind="ret"):
        return kind, exp, log, r468

    if arm >= 7:
        if arm < len(targets):
            return "trap:%#x" % targets[arm], exp, log, None
        return "outside-table", exp, log, None
    if arm == 0 or arm == 3:
        cap, ptr, ln = u64(inp, 8), u64(inp, 0x10), u64(inp, 0x18)
        if ln >= LEN_GATE:
            free(ptr, cap)
            exp.append((0, 2, (TAG_LONG).to_bytes(2, "little")))
            if arm == 0:
                exp.append((0x18, 8, ln.to_bytes(8, "little")))
            return result()
    if arm == 0:
        log.append(("S", pk(ptr, ln, 0, ln, 0x3A0000003A) + b"\x01"))
        flag, pos = case["s_flag"], case["s_pos"]
        key = pk(ptr if flag else 1, pos if flag else 0)
        log.append(("A", 0x7C0, ptr if flag else 1, pos if flag else 0))
        out = oracle("A", key, script["A"], {8: case["a_word"]})
        if not script["A"]:
            exp.append((0, OUT_LEN, out))
            free(ptr, cap)
            return result()
        log.append(("B", ptr, ln, case["a_word"]))
        out = oracle("B", pk(ptr, ln, case["a_word"]), script["B"], {8: case["b_value"]})
        if not script["B"]:
            exp.append((0, OUT_LEN, out))
            free(ptr, cap)
            return result()
        ident = asset_id(case["b_value"])
        wkey = pk(0x35) + ident.to_bytes(4, "little") + b"\x01"
        log.append(("W", wkey, ctx_key))
        exp.append((0, OUT_LEN, oracle("W", wkey, case["w_ok"], {})))
        free(ptr, cap)
        return result()
    if arm == 1:
        wkey = pk(0x2D) + inp[8:0x1D]
        log.append(("W", wkey, ctx_key))
        exp.append((0, OUT_LEN, oracle("W", wkey, case["w_ok"], {})))
        return result()
    if arm == 2:
        buf = inp[8:0x20]
        log.append(("C", buf))
        out = oracle("C", buf, script["C"], {})
        if not script["C"]:
            free(u64(buf, 8), u64(buf, 0))
            exp.append((0, OUT_LEN, out))
            return result()
        log.append(("X", 0x338, buf, 0x20))
        exp.append((0, 2, TAG_OK.to_bytes(2, "little")))
        return result()
    if arm == 3:
        flag = inp[0x20]
        log.append(("D", 0x7C0, ptr))
        out = oracle("D", pk(ptr), script["D"], {8: RO})
        if not script["D"]:
            exp.append((0, OUT_LEN, out))
            free(ptr, cap)
            return result()
        if case["r_sent"] == SENT:
            exp.append((0, 2, (TAG_SENTINEL).to_bytes(2, "little")))
            free(ptr, cap)
            return result()
        if flag:
            r468 = 2
            ids, panic = model_range(case, log)
            if panic:
                return "panic:" + panic, exp, log, None
            for ident in ids:
                log.append(("VIS", ident))
            if ids:
                log.append(("FREE", BUMP0, 8 * len(ids), 0))
        else:
            r468 = 0
        exp.append((0, 2, TAG_OK.to_bytes(2, "little")))
        free(ptr, cap)
        return result()
    if arm == 4:
        buf, flag = inp[8:0x20], inp[0x20]
        log.append(("H", buf))
        out = oracle("H", buf, script["H"], {8: RO, 0x10: case["h_word"]})
        if not script["H"]:
            exp.append((0, OUT_LEN, out))
        elif case["r_sent"] == SENT:
            exp.append((0, 2, (TAG_SENTINEL).to_bytes(2, "little")))
        elif case["r_next"] != SENT + 1:
            exp.append((0, 2, (TAG_NEXT).to_bytes(2, "little")))
        else:
            word = case["h_word"]
            log.append(("E", 0x378, word))
            oracle("E", pk(word), True, {8: case["e_al"]})
            al = case["e_al"] & 0xFF
            bpl, call_g = (2, al != 2) if flag == 0 else (1, al == 2)
            if call_g:
                log.append(("F", 0x7C0, word // STRIDE))
                log.append(("G", case["f_rax"], word, bpl))
                gout = oracle("G", pk(case["f_rax"], word, bpl), script["G"], {})
                exp.append((0, OUT_LEN if not script["G"] else 2, gout if not script["G"] else TAG_OK.to_bytes(2, "little")))
            else:
                exp.append((0, 2, TAG_OK.to_bytes(2, "little")))
        free(u64(buf, 8), u64(buf, 0))
        return result()
    if arm == 5:
        log.append(("MEM", 0, 0xB0))
        zkey = bytes(20) + inp[:0xB0]
        log.append(("Z", zkey))
        out = oracle("Z", zkey, script["Z"], {})
        exp.append((0, OUT_LEN, out) if not script["Z"] else (0, 2, TAG_OK.to_bytes(2, "little")))
        log.append(("DROP", inp[:0xB0]))
        return result()
    # arm == 6
    value, limit = u64(inp, 8), case["limit"]
    if value >= limit:
        exp.append((0, 2, (TAG_RANGE).to_bytes(2, "little")))
        exp.append((8, 8, value.to_bytes(8, "little")))
        return result()
    ykey = inp[8:0x60]
    log.append(("Y", ykey))
    exp.append((0, OUT_LEN, oracle("Y", ykey, case["y_ok"], {})))
    return result()


# --------------------------------------------------------------------------------------------------------------------------------
# emulator harness
# --------------------------------------------------------------------------------------------------------------------------------
class Dispatcher(Machine):
    def step(self, row):
        if row.op == "trap":
            raise Trapped(row.va)
        return Machine.step(self, row)


class Harness:
    def __init__(self, image, patches=None, targets=()):
        self.image = image
        self.machine = machine = Dispatcher(image, patches)
        machine.real = frozenset({RANGE_FN})
        self.targets = targets
        for target in targets[7:]:
            machine.cache[target] = Insn(target, 1, "trap")
        for target, name in DIRECT.items():
            machine.calls[target] = getattr(self, "on_" + name)
        statics = machine.memory.statics
        for slot, name in SLOTS.items():
            statics[slot] = MARK_BASE + slot
            machine.slots[MARK_BASE + slot] = getattr(self, "on_" + name)
        self.case = self.log = None
        self.bump = BUMP0

    def reg(self, which):
        return self.machine.regs[which]

    def emit(self, name, key, ok, payload=None):
        self.machine.memory.put_bytes(self.reg(RDI), oracle(name, key, ok, payload or {}))

    def on_S(self, m):
        regs, mem = m.regs, m.memory
        self.log.append(("S", mem.bytes_at(regs[RSI], 0x29)))
        mem.write(regs[RDI], 1, self.case["s_flag"])
        mem.write(regs[RDI] + 8, 8, self.case["s_pos"])

    def on_A(self, m):
        r = m.regs
        self.log.append(("A", r[RSI] - CTX, r[RDX], r[RCX]))
        self.emit("A", pk(r[RDX], r[RCX]), self.case["script"]["A"], {8: self.case["a_word"]})

    def on_B(self, m):
        r = m.regs
        self.log.append(("B", r[RSI], r[RDX], r[RCX]))
        self.emit("B", pk(r[RSI], r[RDX], r[RCX]), self.case["script"]["B"], {8: self.case["b_value"]})

    def on_C(self, m):
        buf = m.memory.bytes_at(m.regs[RSI], 24)
        self.log.append(("C", buf))
        self.emit("C", buf, self.case["script"]["C"])

    def on_D(self, m):
        r = m.regs
        self.log.append(("D", r[RSI] - CTX, r[RDX]))
        self.emit("D", pk(r[RDX]), self.case["script"]["D"], {8: RO})

    def on_E(self, m):
        r = m.regs
        self.log.append(("E", r[RSI] - RO, r[RDX]))
        self.emit("E", pk(r[RDX]), True, {8: self.case["e_al"]})

    def on_F(self, m):
        r = m.regs
        self.log.append(("F", r[RDI] - CTX, r[RSI]))
        r[RAX] = self.case["f_rax"]

    def on_G(self, m):
        r = m.regs
        self.log.append(("G", r[RSI], r[RDX], r[RCX]))
        self.emit("G", pk(r[RSI], r[RDX], r[RCX]), self.case["script"]["G"])

    def on_H(self, m):
        buf = m.memory.bytes_at(m.regs[RDX], 24)
        self.log.append(("H", buf))
        self.emit("H", buf, self.case["script"]["H"], {8: RO, 0x10: self.case["h_word"]})

    def on_W(self, m):
        r = m.regs
        size = 13 if self.is_arm0() else 29
        key = m.memory.bytes_at(r[RSI], size)
        self.log.append(("W", key, r[RDX] - CTX))
        self.emit("W", key, self.case["w_ok"])

    def is_arm0(self):
        return arm_index(u64(self.case["inp"], 0)) == 0

    def on_X(self, m):
        r = m.regs
        self.log.append(("X", r[RSI] - CTX, m.memory.bytes_at(r[RDX], 24), r[RCX] - IN))

    def on_Y(self, m):
        key = m.memory.bytes_at(m.regs[RDX], 0x58)
        self.log.append(("Y", key))
        self.emit("Y", key, self.case["y_ok"])

    def on_Z(self, m):
        r = m.regs
        key = m.memory.bytes_at(r[RDX], 20) + m.memory.bytes_at(r[RCX], 0xB0)
        self.log.append(("Z", key))
        self.emit("Z", key, self.case["script"]["Z"])

    def on_DROP(self, m):
        self.log.append(("DROP", m.memory.bytes_at(m.regs[RDI], 0xB0)))

    def on_VIS(self, m):
        r = m.regs
        if r[RDI] != CTX:
            raise Halt("visit receiver is not the context")
        self.log.append(("VIS", r[RSI]))

    def on_MEM(self, m):
        r = m.regs
        self.log.append(("MEM", r[RSI] - IN, r[RDX]))
        m.memory.copy(r[RDI], r[RSI], r[RDX])

    def on_FREE(self, m):
        r = m.regs
        self.log.append(("FREE", r[RDI], r[RSI], r[RDX]))

    def on_ALLOC(self, m):
        r = m.regs
        self.log.append(("ALLOC", r[RDI]))
        if self.case["alloc_fail"]:
            r[RAX] = 0
            return
        r[RAX] = self.bump
        self.bump = (self.bump + r[RDI] + 15) & ~15
        if self.bump > HEAP_BASE + RESET_USED + 0x20000:
            raise Halt("arena exhausted")

    def on_ALLOCERR(self, m):
        self.log.append(("ALLOCERR", m.regs[RDI], m.regs[RSI]))
        raise Panicked("alloc-error")

    def on_MULP(self, m):
        self.log.append(("MULP",))
        raise Panicked("mul")

    def on_ADDP(self, m):
        self.log.append(("ADDP",))
        raise Panicked("add")

    def execute(self, case):
        return self.run_range(case) if "range_a" in case else self.run(case)

    def run_range(self, case):
        self.case, self.log, self.bump = case, [], BUMP0
        machine, mem = self.machine, self.machine.memory
        mem.reset(RESET_USED)
        mem.put_bytes(RO, expand(b"rec" + case["seed"], 0x100))
        mem.write(RO + 0x50, 8, case["r_scale"])
        mem.write(IN, 8, RO)
        mem.write(IN + 8, 8, case["range_a"])
        mem.write(IN + 16, 8, case["r_end"])
        mem.put_bytes(OUT, b"\xCC" * 0x20)
        try:
            rax = machine.run(RANGE_FN, {RDI: OUT, RSI: IN})
        except Panicked as error:
            return "panic:" + str(error), None, self.log, None, machine.steps
        if rax != OUT:
            raise Halt("returned pointer differs from the out parameter")
        out = bytes(mem.bytes_at(OUT, 0x20))
        count = u64(out, 16)
        ids = [mem.read(u64(out, 8) + 8 * k, 8) for k in range(count)] if count <= 5000 else []
        return "ret", out, self.log, ids, machine.steps

    def run(self, case):
        self.case, self.log, self.bump = case, [], BUMP0
        machine, mem = self.machine, self.machine.memory
        mem.reset(RESET_USED)
        mem.put_bytes(CTX, expand(b"ctx" + case["seed"], 0x1000))
        mem.write(CTX + 0xB8, 8, case["limit"])
        mem.put_bytes(RO, expand(b"rec" + case["seed"], 0x500))
        for off, value in ((0x10, case["r_end"]), (0x50, case["r_scale"]), (0x378, case["r_sent"]), (0x408, case["r_next"])):
            mem.write(RO + off, 8, value)
        r468_before = mem.read(RO + 0x468, 1)
        mem.put_bytes(OUT, b"\xCC" * 0x100)
        mem.put_bytes(IN, case["inp"])
        try:
            rax = machine.run(FN, {RDI: OUT, RSI: IN, RDX: CTX})
        except Panicked as error:
            return "panic:" + str(error), None, self.log, None, machine.steps
        except Trapped as trap:
            return "trap:%#x" % trap.args[0], None, self.log, None, machine.steps
        if rax != OUT:
            raise Halt("returned pointer differs from the out parameter")
        r468 = mem.read(RO + 0x468, 1)
        return "ret", bytes(mem.bytes_at(OUT, 0x100)), self.log, (None if r468 == r468_before else r468), machine.steps


def compare_range(case, run):
    kind, out, log, ids, steps = run
    mkind, mlog, n, ptr, mids = model_direct(case)
    if kind != mkind:
        return "kind %s != model %s" % (kind, mkind)
    if log != mlog:
        return "call log differs"
    if kind == "ret" and (u64(out, 0), u64(out, 8), u64(out, 16)) != (n, ptr, n):
        return "returned triple differs"
    if kind == "ret" and ids != mids:
        return "generated words differ"
    return None


def check(case, harness, targets):
    """Run the case on the emulator and the model; return None on equality, else a reason."""
    return compare(case, harness.execute(case), targets)


def compare(case, run, targets):
    if "range_a" in case:
        return compare_range(case, run)
    kind, out, log, r468, steps = run
    mkind, exp, mlog, mr468 = model(case, targets)
    if kind != mkind:
        return "kind %s != model %s" % (kind, mkind)
    if log != mlog:
        return "call log differs"
    if kind != "ret":
        return None
    for off, size, value in exp:
        if out[off:off + size] != value:
            return "output bytes differ at +%#x" % off
    if r468 != mr468:
        return "record byte +0x468 differs"
    return None


# --------------------------------------------------------------------------------------------------------------------------------
# cases
# --------------------------------------------------------------------------------------------------------------------------------
VALUES = [0, 1, 9999, 10000, 10001, 0x5F45A5E, 0x5F45A5F, 0x5F45A60, 0xFFFFFFFF - 100000, 0xFFFFFFFF, 1 << 32, 1 << 63, M64]
LENS = [0, 1, 2, 50, 99, 100, 101, 102, 1 << 32, 1 << 63, M64]
MAXOK = M64 // 10000
SWEEP = 6000


def build(index, arm, tag, seed, fields=None):
    fields = fields or {}
    rng = random.Random(seed)
    inp = bytearray(expand(b"in%d" % seed, 0xB0))
    inp[0:8] = tag.to_bytes(8, "little")
    for off, value in fields.get("inp", {}).items():
        size = 1 if off == 0x20 else 8
        inp[off:off + size] = value.to_bytes(size, "little")
    case = {"index": index, "arm": arm, "seed": b"%d" % seed, "inp": bytes(inp), "limit": rng.getrandbits(8) + 2,
            "script": {}, "s_flag": rng.getrandbits(1), "s_pos": rng.getrandbits(40), "a_word": rng.getrandbits(48) | 1,
            "b_value": 0, "w_ok": True, "y_ok": True, "e_al": rng.getrandbits(8), "f_rax": rng.getrandbits(48),
            "h_word": rng.getrandbits(60), "r_end": 0, "r_scale": 0, "r_sent": 0x1234, "r_next": 0x4321, "alloc_fail": False}
    for name in "ABCDGHZ":
        case["script"][name] = True
    case.update({k: v for k, v in fields.items() if k != "inp"})
    for name, value in fields.get("script", {}).items():
        case["script"][name] = value
    return case


def generate(targets):
    cases, seed = [], 1000

    def add(arm, tag, **fields):
        nonlocal seed
        seed += 1
        cases.append(build(len(cases), arm, tag, seed, fields))

    for ln in LENS:
        for cap in (0, 7):
            for flag in (0, 1):
                for a_ok in (True, False):
                    for b_ok in (True, False):
                        for value in (VALUES if (a_ok and b_ok) else (5,)):
                            add(0, SENT + 13, inp={8: cap, 0x18: ln}, s_flag=flag, b_value=value, script={"A": a_ok, "B": b_ok}, w_ok=bool(value & 1) or ln > 3)
    for reps in range(60):
        add(1, SENT + 13 + 1, w_ok=reps % 3 != 0)
    for cap in (0, 5):
        for c_ok in (True, False):
            for reps in range(10):
                add(2, SENT + 13 + 2, inp={8: cap}, script={"C": c_ok})
    for ln in (5, 100, 101, M64):
        for cap in (0, 3):
            for flag in (0, 1):
                for d_ok in (True, False):
                    for sent in (SENT, 77):
                        for end in (0, 1, 2, 5):
                            for scale in (0, 1, 0x1234, MAXOK, MAXOK + 1, M64):
                                if ln > 100 and (end, scale) != (0, 0):
                                    continue
                                add(3, SENT + 13 + 3, inp={8: cap, 0x18: ln, 0x20: flag}, script={"D": d_ok}, r_sent=sent, r_end=end, r_scale=scale)
    for end, scale in ((1616, MAXOK), (1617, MAXOK), (1618, MAXOK), (1700, MAXOK), (60, MAXOK + 1), ((1 << 60) - 1, 1), (1 << 60, 1), (1 << 61, 1), (M64, 1), (1 << 61, MAXOK + 1)):
        for fail in (False, True):
            if not fail and 5000 < end < 1 << 60:
                continue
            add(3, SENT + 13 + 3, inp={8: 3, 0x18: 7, 0x20: 1}, r_end=end, r_scale=scale, alloc_fail=fail)
    for flag in (0, 1):
        for h_ok in (True, False):
            for cap in (0, 5):
                for sent in (SENT, 3):
                    for nxt in (SENT + 1, SENT):
                        for al in (0, 1, 2, 3):
                            for g_ok in (True, False):
                                for word in (0, 9999, 10000, 10001, 123456789012, SENT, M64):
                                    add(4, SENT + 13 + 4, inp={8: cap, 0x20: flag}, script={"H": h_ok, "G": g_ok}, r_sent=sent, r_next=nxt, e_al=al, h_word=word)
    for tag in (0, 1, 5, SENT - 1, SENT, SENT + 12):
        for z_ok in (True, False):
            for reps in range(4):
                add(5, tag, script={"Z": z_ok})
    for limit in (0, 1, 5, 200, 255):
        for value in (0, 1, 4, 199, 200, 201, 254, 255, 256, M64):
            for y_ok in (True, False):
                add(6, SENT + 13 + 6, inp={8: value}, limit=limit, y_ok=y_ok)
    for arm in range(7, len(targets)):
        for reps in range(3):
            add(arm, SENT + 13 + arm)
    for tag in (SENT + 12, SENT + 13 + len(targets) - 1):
        add(arm_index(tag), tag)
    rng = random.Random(77)
    for _ in range(SWEEP):
        arm = rng.choice((0, 0, 3, 4, 4, 4, 6))
        bits = rng.choice((8, 14, 20, 28, 33, 48, 64))
        word = rng.getrandbits(bits)
        script = {name: rng.random() < 0.75 for name in "ABCDGHZ"}
        if arm == 0:
            add(0, SENT + 13, inp={8: rng.choice((0, 3)), 0x18: rng.choice((rng.randrange(0, 130), rng.randrange(95, 106)))}, s_flag=rng.getrandbits(1),
                b_value=rng.choice((word, rng.randrange(9990, 10010), 0x5F45A5F + rng.randrange(-2, 3))), script=script, w_ok=rng.random() < 0.8)
        elif arm == 3:
            add(3, SENT + 16, inp={8: rng.choice((0, 3)), 0x18: rng.choice((rng.randrange(0, 4), 100, 101)), 0x20: rng.getrandbits(1)}, script=script,
                r_sent=rng.choice((SENT, SENT, 99)), r_end=rng.randrange(0, 6), r_scale=rng.choice((word, MAXOK - rng.randrange(0, 4), MAXOK + rng.randrange(0, 3))))
        elif arm == 4:
            add(4, SENT + 17, inp={8: rng.choice((0, 3)), 0x20: rng.getrandbits(1)}, script=script, r_sent=rng.choice((SENT, 5, 5, 5, 5)),
                r_next=rng.choice((SENT + 1, SENT + 1, SENT + 1, 9)), e_al=rng.choice((0, 1, 2, 2, 3, rng.getrandbits(8))), h_word=word)
        else:
            add(6, SENT + 19, inp={8: word & 0xFF}, limit=rng.randrange(0, 300), y_ok=rng.random() < 0.8)
    for lo in (0, 1, SENT, M64 - 4, M64 - 2, M64 - 1, M64):
        for hi in (0, 1, 2, 5, SENT, M64 - 4, M64 - 2, M64 - 1, M64):
            for scale in (0, 1, 7, MAXOK, MAXOK + 1, SENT):
                for fail in (False, True):
                    size = hi - lo if hi > lo else 0
                    if (size > 3000 and not size >> 60) or (fail and size == 0):
                        continue
                    seed += 1
                    cases.append({"index": len(cases), "arm": "R", "seed": b"%d" % seed, "range_a": lo, "r_end": hi, "r_scale": scale, "alloc_fail": fail})
    for lo, hi in ((0, (1 << 60) - 1), (5, (1 << 60) + 4), (0, 1 << 61)):
        for fail in (True,):
            seed += 1
            cases.append({"index": len(cases), "arm": "R", "seed": b"%d" % seed, "range_a": lo, "r_end": hi, "r_scale": 1, "alloc_fail": fail})
    order = list(range(len(cases)))
    random.Random(115).shuffle(order)
    return [cases[i] for i in order], cases


# --------------------------------------------------------------------------------------------------------------------------------
# mutants (byte patches over the original instructions; each row is checked against the original bytes)
# --------------------------------------------------------------------------------------------------------------------------------
MUTANTS = [
    (0x29137A8, "4983fd65", "4983fd64", "arm0 name length gate 0x65 -> 0x64"),
    (0x29137AC, "0f83", "0f82", "arm0 length gate jae -> jb"),
    (0x2913818, "498db6c0070000", "498db6c8070000", "arm0 A receiver ctx+0x7c0 -> +0x7c8"),
    (0x291381F, "ba01000000", "ba02000000", "arm0 default split start 1 -> 2"),
    (0x291383E, "81f9a2010000", "81f9a3010000", "arm0 A success tag 0x1a2 -> 0x1a3"),
    (0x2913844, "0f85", "0f84", "arm0 A tag test jne -> je"),
    (0x2913873, "0f85", "0f84", "arm0 B tag test jne -> je"),
    (0x2913879, "483d0f270000", "483d10270000", "arm0 small id bound 9999 -> 10000"),
    (0x291387F, "0f87", "0f83", "arm0 small id branch ja -> jae"),
    (0x2913FAD, "483d5f5af405", "483d5e5af405", "arm0 offset bound 0x5f45a5f -> 0x5f45a5e"),
    (0x2913FAD + 2, "5f5af405", "605af405", "arm0 offset bound 0x5f45a5f -> 0x5f45a60"),
    (0x2913FB3, "0f86", "0f82", "arm0 offset bound jbe -> jb"),
    (0x291408B, "05a0860100", "05a1860100", "arm0 offset 100000 -> 100001"),
    (0x29138D9, "0f85", "0f84", "arm4 sentinel test jne -> je"),
    (0x29138D2, "4c39ae78030000", "4c39ae70030000", "arm4 sentinel word +0x378 -> +0x370"),
    (0x29138DF, "66c7035601", "66c7035701", "arm4 sentinel tag 0x156 -> 0x157"),
    (0x2913D1A, "4c39ae08040000", "4c39ae00040000", "arm4 second word +0x408 -> +0x400"),
    (0x2913D21, "0f85", "0f84", "arm4 second word test jne -> je"),
    (0x2913E9A, "66c703a101", "66c703a201", "arm4 tag 0x1a1 -> 0x1a2"),
    (0x2913D52, "0f84", "0f85", "arm4 flag test je -> jne"),
    (0x2913D5B, "3c02", "3c03", "arm4 flag-set compare 2 -> 3"),
    (0x2913F48, "40b502", "40b503", "arm4 flag-clear mode 2 -> 3"),
    (0x2913F4B, "3c02", "3c03", "arm4 flag-clear compare 2 -> 3"),
    (0x2913F4D, "744f", "754f", "arm4 flag-clear branch je -> jne"),
    (0x2913F4F, "48b94b598638", "48b94a598638", "arm4 reciprocal constant low byte"),
    (0x2913F5F, "48c1ea0b", "48c1ea0c", "arm4 reciprocal shift 11 -> 12"),
    (0x2913F76, "400fb6cd", "400fb6c5", "arm4 mode register bpl -> not passed"),
    (0x2913F98, "0f85", "0f84", "arm4 divide result tag test jne -> je"),
    (0x2913979, "488b4e18", "488b4e10", "arm3 length word +0x18 -> +0x10"),
    (0x291397D, "4883f965", "4883f966", "arm3 length gate 0x65 -> 0x66"),
    (0x2913981, "0f82", "0f83", "arm3 length gate jb -> jae"),
    (0x291399F, "66c7035801", "66c7035901", "arm3 over-length tag 0x158 -> 0x159"),
    (0x2913B18, "0f85", "0f84", "arm3 sentinel test jne -> je"),
    (0x2913B1E, "66c7035601", "66c7035701", "arm3 sentinel tag 0x156 -> 0x157"),
    (0x2913EA7, "0f84", "0f85", "arm3 flag test je -> jne"),
    (0x2913EAD, "c6806804000002", "c6806804000003", "arm3 record byte +0x468 set to 2 -> 3"),
    (0x2913F3C, "c6806804000000", "c6806804000001", "arm3 record byte +0x468 clear 0 -> 1"),
    (0x22B31F0, "b810270000", "b811270000", "range scale 10000 -> 10001"),
    (0x22B3178, "4c29e3", "4c01e3", "range count subtract -> add"),
    (0x22B317B, "480f42d8", "480f43d8", "range count clamp cmovb -> cmovae"),
    (0x22B319E, "0f97c2", "0f93c2", "range size limit seta -> setae"),
    (0x22B31F9, "704c", "714c", "range multiply overflow jo -> jno"),
    (0x22B3202, "4839c2", "4839d0", "range add guard compare operands swapped"),
    (0x22B3205, "724f", "764f", "range add guard jb -> jbe"),
    (0x22B31DD, "7349", "7249", "range empty-loop test jae -> jb"),
    (0x2913A39, "0f85", "0f84", "arm5 Z tag test jne -> je"),
    (0x2913A4D, "493b86b8000000", "493b86c0000000", "arm6 limit word +0xb8 -> +0xc0"),
    (0x2913A54, "0f83", "0f87", "arm6 limit test jae -> ja"),
    (0x2913B49, "66c703fa00", "66c703fb00", "arm6 error tag 0xfa -> 0xfb"),
]


def patch_map(row):
    va, old, new = row[0], bytes.fromhex(row[1]), bytes.fromhex(row[2])
    return {va + i: b for i, b in enumerate(new) if old[i] != b}


def verify_mutants(image):
    for va, old, new, label in MUTANTS:
        if len(old) != len(new):
            raise EvidenceError("mutant length: " + label)
        have = image.blob[image.offset(va):image.offset(va) + len(old) // 2]
        if have != bytes.fromhex(old):
            raise EvidenceError("mutant original bytes differ at %#x: %s" % (va, label))


# --------------------------------------------------------------------------------------------------------------------------------
# evidence
# --------------------------------------------------------------------------------------------------------------------------------
def summarize(case):
    if "range_a" in case:
        return "a=%#x b=%#x scale=%#x fail=%d" % (case["range_a"], case["r_end"], case["r_scale"], case["alloc_fail"])
    parts = ["T=%#x" % u64(case["inp"], 0)]
    arm = case["arm"]
    inp = case["inp"]
    if arm in (0, 3):
        parts += ["cap=%#x" % u64(inp, 8), "len=%#x" % u64(inp, 0x18)]
    if arm in (3, 4):
        parts.append("flag=%d" % inp[0x20])
    parts.append("script=" + "".join(k + ("1" if v else "0") for k, v in sorted(case["script"].items())))
    if arm == 0:
        parts += ["v=%#x" % case["b_value"], "s=%d" % case["s_flag"]]
    if arm == 3:
        parts += ["sent=%d" % (case["r_sent"] == SENT), "end=%#x" % case["r_end"], "scale=%#x" % case["r_scale"], "fail=%d" % case["alloc_fail"]]
    if arm == 4:
        parts += ["sent=%d" % (case["r_sent"] == SENT), "next=%d" % (case["r_next"] == SENT + 1), "al=%d" % (case["e_al"] & 0xFF), "w=%#x" % case["h_word"]]
    if arm == 6:
        parts += ["v=%#x" % u64(inp, 8), "lim=%d" % case["limit"]]
    return " ".join(parts)


def decode_rows(image):
    rows = []
    for start, end in ((RANGE_FN, RANGE_END), (FN, FN_END)):
        rows.extend(decode_range(image, start, end))
    return rows


def run_all(image, out_dir):
    verify_mutants(image)
    targets = table_targets(image)
    ordered, natural = generate(targets)
    harness = Harness(image, None, targets)
    failures, per_arm, kinds = [], collections.Counter(), collections.Counter()
    digest = hashlib.sha256()
    rows = []
    for case in natural:
        run = harness.execute(case)
        reason = compare(case, run, targets)
        kind, out, log, r468, steps = run
        if reason:
            failures.append((case["index"], reason))
        per_arm[case["arm"]] += 1
        kinds[kind.split(":")[0]] += 1
        tag = "-" if out is None or "range_a" in case else "%#06x" % int.from_bytes(out[:2], "little")
        line = "%d\t%s\t%s\t%s\t%s\t%d\t%d\t%s" % (case["index"], case["arm"], summarize(case), kind, tag, len(log), steps,
                                                    hashlib.sha256(repr(log).encode()).hexdigest()[:12])
        rows.append(line)
        digest.update(line.encode())
    if failures:
        raise EvidenceError("model and emulator differ: %r" % failures[:5])
    seen = set(harness.machine.seen)
    # negative controls
    controls, undetected = [], []
    for number, row in enumerate(MUTANTS):
        mutant = Harness(image, patch_map(row), targets)
        first = None
        for tried, case in enumerate(ordered, 1):
            try:
                reason = check(case, mutant, targets)
            except (Halt, EvidenceError, Panicked, Trapped, KeyError, IndexError, ValueError) as error:
                reason = "emulation stopped: %s" % type(error).__name__
            if reason:
                first = (tried, case["index"], reason)
                break
        controls.append((number, row, first))
        if first is None:
            undetected.append((number, row))
    return {"targets": targets, "rows": rows, "digest": digest.hexdigest(), "per_arm": per_arm, "kinds": kinds, "seen": seen,
            "controls": controls, "undetected": undetected, "cases": len(natural)}


SAMPLE_STRIDE = 5


class SparseBlob:
    """Byte view over a few (start, bytes) segments; every other byte reads as zero."""

    def __init__(self, segments):
        self.segments = segments

    def __getitem__(self, key):
        out = bytearray(key.stop - key.start)
        for start, data in self.segments:
            lo, hi = max(start, key.start), min(start + len(data), key.stop)
            if lo < hi:
                out[lo - key.start:hi - key.start] = data[lo - start:hi - start]
        return bytes(out)


class FixtureImage:
    """Image stand-in built from code-bytes.json: virtual address equals the blob offset."""

    def __init__(self, document):
        self.blob = SparseBlob([(part["va"], bytes.fromhex("".join(part["hex"]))) for part in document.values()])

    def offset(self, va):
        return va


CANONICAL = [
    ("arm 0, small id", 0, SENT + 13, {"inp": {8: 3, 0x18: 4}, "s_flag": 1, "b_value": 7}),
    ("arm 0, first offset id", 0, SENT + 13, {"inp": {8: 0, 0x18: 4}, "s_flag": 0, "b_value": 10000}),
    ("arm 0, last offset id", 0, SENT + 13, {"inp": {8: 0, 0x18: 4}, "s_flag": 0, "b_value": 0x5F45A5F}),
    ("arm 0, id out of range", 0, SENT + 13, {"inp": {8: 0, 0x18: 4}, "s_flag": 0, "b_value": 0x5F45A60}),
    ("arm 0, name too long", 0, SENT + 13, {"inp": {8: 9, 0x18: 101}}),
    ("arm 0, first callee fails", 0, SENT + 13, {"inp": {8: 9, 0x18: 4}, "script": {"A": False}}),
    ("arm 1", 1, SENT + 14, {}),
    ("arm 2, success", 2, SENT + 15, {"inp": {8: 5}}),
    ("arm 2, failure", 2, SENT + 15, {"inp": {8: 5}, "script": {"C": False}}),
    ("arm 3, flag set, 3 ids", 3, SENT + 16, {"inp": {8: 3, 0x18: 4, 0x20: 1}, "r_end": 3, "r_scale": 7}),
    ("arm 3, flag clear", 3, SENT + 16, {"inp": {8: 3, 0x18: 4, 0x20: 0}}),
    ("arm 3, sentinel record", 3, SENT + 16, {"inp": {8: 3, 0x18: 4, 0x20: 1}, "r_sent": SENT}),
    ("arm 3, multiply overflow", 3, SENT + 16, {"inp": {8: 0, 0x18: 4, 0x20: 1}, "r_end": 2, "r_scale": MAXOK + 1}),
    ("arm 4, flag clear, mode 2", 4, SENT + 17, {"inp": {8: 5, 0x20: 0}, "e_al": 1, "h_word": 123456}),
    ("arm 4, flag set, selector 2", 4, SENT + 17, {"inp": {8: 0, 0x20: 1}, "e_al": 2, "h_word": 20000}),
    ("arm 4, flag set, selector not 2", 4, SENT + 17, {"inp": {8: 0, 0x20: 1}, "e_al": 1}),
    ("arm 4, second word mismatch", 4, SENT + 17, {"inp": {8: 5, 0x20: 1}, "r_next": 1}),
    ("arm 5", 5, 0, {}),
    ("arm 6, below the limit", 6, SENT + 19, {"inp": {8: 3}, "limit": 4}),
    ("arm 6, at the limit", 6, SENT + 19, {"inp": {8: 4}, "limit": 4}),
    ("arm 7, outside the FDE", 7, SENT + 20, {}),
]


def render(item):
    if isinstance(item, bytes):
        return item[:12].hex() + ("..(%d)" % len(item) if len(item) > 12 else "")
    return "%#x" % item if isinstance(item, int) and item > 9 else str(item)


def flow_report(harness, targets):
    lines = ["# Canonical traces", "", "Each trace is one emulator run of the dispatcher; the model predicts the same call list and output.", ""]
    for number, (title, arm, tag, fields) in enumerate(CANONICAL):
        case = build(number, arm, tag, 9000 + number, fields)
        run = harness.execute(case)
        reason = compare(case, run, targets)
        if reason:
            raise EvidenceError("canonical case %s: %s" % (title, reason))
        out = run[1]
        lines.append("## %s" % title)
        lines.append("")
        lines.append("- input: %s" % summarize(dict(case, arm=arm)))
        for entry in run[2]:
            lines.append("- call %s(%s)" % (entry[0], ", ".join(render(x) for x in entry[1:])))
        shown = "-" if out is None else "tag %#05x" % int.from_bytes(out[:2], "little")
        lines.append("- result: %s, %s" % (run[0], shown))
        lines.append("")
    return "\n".join(lines)


def write_out(out, image):
    result = run_all(image, out)
    out.mkdir(parents=True, exist_ok=True)

    def put(name, text):
        (out / name).write_bytes(text.encode())

    header = "index\tarm\tinput\toutcome\tout_tag\tcalls\tsteps\tcall_log_sha\n"
    put("cases.tsv", header + "\n".join(r for r in result["rows"][::SAMPLE_STRIDE] if "\tR\t" not in r) + "\n")
    put("range-cases.tsv", header + "\n".join(r for r in result["rows"] if "\tR\t" in r) + "\n")
    chunks = {}
    for name, start, end in (("range", RANGE_FN, RANGE_END), ("root", FN, FN_END), ("table", TABLE, TABLE + 4 * 14)):
        raw = image.blob[image.offset(start):image.offset(start) + end - start].hex()
        chunks[name] = {"va": start, "size": end - start, "hex": [raw[i:i + 64] for i in range(0, len(raw), 64)]}
    put("code-bytes.json", json.dumps(chunks, indent=1, sort_keys=True) + "\n")
    table = ["index\ttarget\tin_dispatcher_fde"]
    targets = result["targets"]
    for i, target in enumerate(targets):
        table.append("%d\t%#x\t%d" % (i, target, FN <= target < FN_END))
    flow_harness = Harness(image, None, targets)
    put("canonical-traces.md", flow_report(flow_harness, targets) + "\n")
    put("jump-table.tsv", "\n".join(table) + "\n")
    lines = ["va\tsize\tbytes\top\twidth\ttarget\texecuted"]
    for row in decode_rows(image):
        target = "" if row.target is None else "%#x" % row.target
        lines.append("%#x\t%d\t%s\t%s\t%s\t%s\t%d" % (row.va, row.size, row.data.hex(), row.op, row.width, target, row.va in result["seen"]))
    put("instructions.tsv", "\n".join(lines) + "\n")
    calls = ["site\tkind\ttarget\tname"]
    for row in decode_rows(image):
        if row.op == "call":
            calls.append("%#x\tdirect\t%#x\t%s" % (row.va, row.target, DIRECT.get(row.target, "range" if row.target == RANGE_FN else "other")))
        elif row.op == "calli":
            slot = row.a[4]
            calls.append("%#x\tgot-slot\t%#x\t%s" % (row.va, slot, SLOTS.get(slot, "other")))
    put("call-sites.tsv", "\n".join(calls) + "\n")
    controls = ["id\tva\toriginal\tmutated\tlabel\tdetected\ttried\tfirst_case\treason"]
    detected = 0
    for number, row, first in result["controls"]:
        if first:
            detected += 1
        controls.append("%d\t%#x\t%s\t%s\t%s\t%d\t%s\t%s\t%s" % (number, row[0], row[1], row[2], row[3], first is not None,
                                                                  first[0] if first else "", first[1] if first else "", first[2] if first else ""))
    put("controls.tsv", "\n".join(controls) + "\n")
    eq = ["id\tva\tlabel\treason"]
    for number, row in result["undetected"]:
        eq.append("%d\t%#x\t%s\tno generated case separates the mutant" % (number, row[0], row[3]))
    put("equivalent-mutants.tsv", "\n".join(eq) + "\n")
    rows = decode_rows(image)
    insn = len(rows)
    executed = sum(1 for row in rows if row.va in result["seen"])
    measure = {"cases": result["cases"], "negative_controls": len(MUTANTS), "negative_detected": detected, "equivalent": len(result["undetected"]),
               "per_arm": {str(k): v for k, v in sorted(result["per_arm"].items(), key=lambda kv: str(kv[0]))}, "outcomes": dict(sorted(result["kinds"].items())),
               "instructions_total": insn, "instructions_executed": executed, "cases_sha256": result["digest"],
               "jump_table_entries_near_dispatcher": len(targets)}
    put("measure.json", json.dumps(measure, indent=1, sort_keys=True) + "\n")
    return measure


def main(argv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument("--out", required=True)
    args = parser.parse_args(argv)
    image = load_image()
    print(json.dumps(write_out(pathlib.Path(args.out), image), sort_keys=True))


if __name__ == "__main__":
    main()
