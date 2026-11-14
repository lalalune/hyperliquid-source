#!/usr/bin/env python3
"""Reconstruct and validate the node #115 JSON number tail 0x3ef20f0 (fraction digits, exponent hand-off, f64 scaling).

The module embeds a concrete x86-64 interpreter (Image, decode, Memory, Machine) that reads every code byte, constant and relocation from the
ELF file; the binary is never executed. The tail model below is compared with the real machine code on every case, including the ordered
sequence of boundary calls. Names are inferences from the code shape.

    python3 tools/re19_json_number_tail_115.py --out research/work-items/RE-019-json-number-tail-115
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




# ---------------------------------------------------------------------------------------------
# Packet code: model of the JSON number tail 0x3ef20f0 and its proof against the machine code.
# ---------------------------------------------------------------------------------------------
import argparse
import json
import random

ENTRY = 0x3EF20F0
FINISH = 0x3EF229B
EXPONENT = 0x3EF2820
ERR_AT = 0x3EF1A90
ERR_PEEK = 0x3EF3450
SLOT_SLOW = 0x64E1338
SLOT_TABLE = 0x64E1330
SLOT_PANIC_ADD = 0x64DF520
SLOT_PANIC_OV = 0x64DF848
CONST_SCALE = 0x458EA0
CONST_SIGN = 0x4559C0
CONST_MAGIC_A = 0x451210
CONST_MAGIC_B = 0x450170
FAKE_SLOW = 0x7700002000
FAKE_ADD = 0x7700002100
FAKE_OV = 0x7700002200
M64X = (1 << 64) - 1
M32 = 0xFFFFFFFF
LIMIT = 0x1999999999999998
DE, DATA, OUT = HEAP_BASE + 0x100, HEAP_BASE + 0x400, HEAP_BASE + 0x200
USED = 0x1000
CASES = 14000
FRAGMENT_CASES = 4000
PATCH_CASES = 2500
FRAGMENT_PATCH = 600
SAMPLE = 1800
CASE_SEED = 115
TABLE_LEN = 0x135
DEAD = 0xA5A5A5A5A5A5A5A5


def s64(v):
    v &= M64X
    return v - (1 << 64) if v >> 63 else v


def mix(*values):
    h = 0xCBF29CE484222325
    for v in values:
        h = ((h ^ (v & M64X)) * 0x100000001B3) & M64X
        h ^= h >> 29
    return h


def fbits(x):
    return struct.unpack("<Q", struct.pack("<d", x))[0]


def fval(bits):
    return struct.unpack("<d", struct.pack("<Q", bits & M64X))[0]


def stub_result(kind, acc, scale, positive, extra):
    """Deterministic stand-in for the exponent parser and the slow digit path: (tag, value)."""
    h = mix(kind, acc, scale, positive, extra)
    if h & 3 == 0:
        return 1, 0xE000000000000000 | (h & 0xFFFF)
    return 0, h


def error_word(kind, code, idx):
    return mix(kind, code, idx) | 1 << 63


DEFAULT = dict(
    e_lower_only=False, neg_limit=1 << 63, neg_zero_int=False, limit=LIMIT, last_digit=5, empty_code=0xD, eof_code=5,
    big_threshold=0x135, step=0x134, div_as_mul=False, no_inf_check=False, no_sign=False, no_advance=False,
    no_zero_skip=False, trunc_convert=False, no_abs=False, slow_scale_zero=False, exp_scale_zero=False,
    pos_ignored=False, dot_eof_at_len=False, wrong_peek_code=0xE,
    int_tag_neg=2, neg_float_unsigned=False,
)


def convert(acc, o):
    x = float(acc)
    if o["trunc_convert"] and int(x) > acc:
        x = math.nextafter(x, 0.0)
    return x


def finish_model(acc, e, positive, env, o, trace, state):
    """The scaling tail at 0x3ef229b: eax = e (32-bit signed), xmm0 = acc as f64."""
    x = convert(acc, o)
    e = e & M32
    se = e - (1 << 32) if e >> 31 else e

    def count(v):
        sv = v - (1 << 32) if v >> 31 else v
        return sv if o["no_abs"] and sv < 0 else abs(sv)

    c = count(e)
    guard = 0
    while c >= o["big_threshold"]:
        guard += 1
        if guard > 100000:
            raise EvidenceError("scaling loop does not end")
        if x == 0.0 and not o["no_zero_skip"]:
            return finish_sign(x, positive, o)
        if (e >> 31) == 0:
            trace.append(("peek", 0xE, state["idx"]))
            return 3, error_word(2, o["wrong_peek_code"], state["idx"])
        e = (e + o["step"]) & M32
        if o["div_as_mul"]:
            x = x * env["scale"]
        else:
            x = x / env["scale"]
        c = count(e)
    f = env["table"][c]
    if e >> 31:
        x = x / f
    else:
        x = x * f
        if abs(x) == math.inf and not o["no_inf_check"]:
            trace.append(("peek", 0xE, state["idx"]))
            return 3, error_word(2, o["wrong_peek_code"], state["idx"])
    return finish_sign(x, positive, o)


def finish_sign(x, positive, o):
    if not positive and not o["no_sign"]:
        x = -x
    return 0, fbits(x)


def tail_model(data, idx, acc, dl, env, o=DEFAULT):
    """Returns (tag, payload, final index, trace) for one call of 0x3ef20f0."""
    positive = (dl & 0xFF) != 0
    if o["pos_ignored"]:
        positive = True
    n = len(data)
    trace = []
    state = {"idx": idx}
    byte = data[idx] if idx < n else None
    if byte is not None and idx >= 0 and (byte == 0x2E):
        return fraction_model(data, idx, acc, dl, positive, env, o, trace, state)
    if byte is not None and ((byte == 0x45 and not o["e_lower_only"]) or byte == 0x65):
        scale = 0
        tag, value = stub_result(1, acc, scale, dl & 0xFF, idx)
        trace.append(("exp", acc, scale, dl & 0xFF, idx))
        if tag == 0:
            return 0, value, state["idx"], trace
        return 3, value, state["idx"], trace
    if positive:
        return 1, acc, state["idx"], trace
    if o["neg_zero_int"] and acc == 0:
        return o["int_tag_neg"], 0, state["idx"], trace
    if 0 < acc <= o["neg_limit"]:
        return o["int_tag_neg"], (-acc) & M64X, state["idx"], trace
    x = convert(acc, o)
    bits = fbits(x) | (0 if o["neg_float_unsigned"] else 1 << 63)
    return 0, bits, state["idx"], trace


def fraction_model(data, idx, acc, dl, positive, env, o, trace, state):
    n = len(data)
    state["idx"] = idx + 1
    if idx + 1 >= n and not o["dot_eof_at_len"]:
        trace.append(("at", o["eof_code"], state["idx"]))
        return 3, error_word(1, o["eof_code"], state["idx"]), state["idx"], trace
    k = 0
    position = idx + 2
    while True:
        ch = data[position - 1] if position - 1 < n else 0x37
        digit = ch - 0x30
        if not 0 <= digit < 10:
            break
        if acc > o["limit"]:
            if acc != o["limit"] + 1 or digit > o["last_digit"]:
                scale = 0 if o["slow_scale_zero"] else -k
                tag, value = stub_result(3, acc, scale, dl & 0xFF, position * 256 + ch)
                trace.append(("slow", acc, scale, dl & 0xFF, position, ch))
                return (0 if tag == 0 else 3), value, state["idx"], trace
        if not o["no_advance"]:
            state["idx"] = position
        acc = acc * 10 + digit
        k += 1
        position += 1
        if k == n - idx - 1:
            e = idx - n + 1
            if e & M32 == 0:
                trace.append(("at", o["eof_code"], state["idx"]))
                return 3, error_word(1, o["eof_code"], state["idx"]), state["idx"], trace
            tag, payload = finish_model(acc, e, positive, env, o, trace, state)
            return tag, payload, state["idx"], trace
    if k == 0:
        trace.append(("at", o["empty_code"], state["idx"]))
        return 3, error_word(1, o["empty_code"], state["idx"]), state["idx"], trace
    if (ch | 0x20) == 0x65:
        scale = 0 if o["exp_scale_zero"] else -k
        tag, value = stub_result(1, acc, scale, dl & 0xFF, state["idx"])
        trace.append(("exp", acc, scale, dl & 0xFF, state["idx"]))
        return (0 if tag == 0 else 3), value, state["idx"], trace
    tag, payload = finish_model(acc, -k, positive, env, o, trace, state)
    return tag, payload, state["idx"], trace


# ---------------------------------------------------------------------------------------------
# Machine harness.
# ---------------------------------------------------------------------------------------------

def read_environment(image):
    """Table of powers, scale constant and slot targets, all read from the file bytes."""
    relative = image.relative()
    if SLOT_TABLE not in relative:
        raise EvidenceError("table slot is not a RELATIVE relocation")
    table_va = relative[SLOT_TABLE]
    base = image.offset(table_va)
    table = list(struct.unpack_from("<%dd" % TABLE_LEN, image.blob, base))
    scale = struct.unpack_from("<d", image.blob, image.offset(CONST_SCALE))[0]
    sign = struct.unpack_from("<Q", image.blob, image.offset(CONST_SIGN))[0]
    magic_a = bytes(image.blob[image.offset(CONST_MAGIC_A):image.offset(CONST_MAGIC_A) + 16])
    magic_b = bytes(image.blob[image.offset(CONST_MAGIC_B):image.offset(CONST_MAGIC_B) + 16])
    return dict(table=table, table_va=table_va, scale=scale, sign=sign, magic_a=magic_a, magic_b=magic_b)


def install(machine, env):
    machine.trace = []
    machine.memory.statics[SLOT_TABLE] = env["table_va"]
    machine.memory.statics[SLOT_SLOW] = FAKE_SLOW
    machine.memory.statics[SLOT_PANIC_ADD] = FAKE_ADD
    machine.memory.statics[SLOT_PANIC_OV] = FAKE_OV
    memory = machine.memory

    def exponent(m):
        tmp, de = m.regs[RDI], m.regs[RSI]
        acc, scale, dl = m.regs[RCX], s64(m.regs[R8]), m.regs[RDX] & 0xFF
        idx = memory.read(de + 0x28, 8)
        tag, value = stub_result(1, acc, scale, dl, idx)
        m.trace.append(("exp", acc, scale, dl, idx))
        memory.write(tmp, 1, tag)
        memory.write(tmp + 8, 8, value)
        m.regs[RAX] = tmp

    def slow(m):
        tmp, de = m.regs[RDI], m.regs[RSI]
        acc, scale, dl = m.regs[RCX], s64(m.regs[R8]), m.regs[RDX] & 0xFF
        position, ch = m.regs[R9], m.regs[R15] & 0xFF
        tag, value = stub_result(3, acc, scale, dl, position * 256 + ch)
        m.trace.append(("slow", acc, scale, dl, position, ch))
        memory.write(tmp, 1, tag)
        memory.write(tmp + 8, 8, value)

    def at(m):
        de, code_ptr = m.regs[RDI], m.regs[RSI]
        code = memory.read(code_ptr, 8)
        idx = memory.read(de + 0x28, 8)
        m.trace.append(("at", code, idx))
        m.regs[RAX] = error_word(1, code, idx)

    def peek(m):
        de, code_ptr = m.regs[RDI], m.regs[RSI]
        code = memory.read(code_ptr, 8)
        idx = memory.read(de + 0x28, 8)
        m.trace.append(("peek", code, idx))
        m.regs[RAX] = error_word(2, code, idx)

    def panic_add(m):
        raise Panicked("add overflow")

    def panic_ov(m):
        raise Panicked("decrement overflow")

    machine.calls[EXPONENT] = exponent
    machine.calls[ERR_AT] = at
    machine.calls[ERR_PEEK] = peek
    machine.slots[FAKE_SLOW] = slow
    machine.slots[FAKE_ADD] = panic_add
    machine.slots[FAKE_OV] = panic_ov


def prepare(machine, data, idx):
    memory = machine.memory
    memory.reset(USED)
    memory.write(DE + 0x18, 8, DATA)
    memory.write(DE + 0x20, 8, len(data))
    memory.write(DE + 0x28, 8, idx)
    memory.put_bytes(DATA, bytes(data) + b"\x37")
    memory.write(OUT, 8, DEAD)
    memory.write(OUT + 8, 8, DEAD)
    machine.trace = []


def collect(machine):
    memory = machine.memory
    return (memory.read(OUT, 8), memory.read(OUT + 8, 8), memory.read(DE + 0x28, 8), tuple(machine.trace),
            memory.read(DE + 0x18, 8), memory.read(DE + 0x20, 8))


def run_tail(machine, data, idx, acc, dl):
    prepare(machine, data, idx)
    junk = 0x5A5A5A00
    machine.run(ENTRY, {RDI: OUT, RSI: DE, RDX: junk | (dl & 0xFF), RCX: acc})
    return collect(machine)


def run_frame(machine, entry, regs):
    """Run a fragment that starts after the prologue: the frame is built by hand (0x28 scratch, four saved registers)."""
    machine.regs = [POISON] * 16
    for reg in CALLEE_SAVED:
        machine.regs[reg] = 0x1111111111111100 + reg
    for reg, value in regs.items():
        machine.regs[reg] = value
    machine.regs[RSP] = STACK_TOP - 0x200
    machine.push(RETURN_SENTINEL)
    for reg in (RBP, R15, R14, RBX):
        machine.push(0x1111111111111100 + reg)
    machine.regs[RSP] -= 0x28
    pc = entry
    limit = machine.step_limit
    while pc != RETURN_SENTINEL:
        limit -= 1
        if limit < 0:
            raise Halt("step limit")
        row = machine.cache.get(pc)
        if row is None:
            row = decode(machine.read_code, pc)
            machine.cache[pc] = row
        machine.seen.add(pc)
        pc = machine.step(row)
    if machine.regs[RSP] != STACK_TOP - 0x200:
        raise Halt("unbalanced stack")
    for reg in CALLEE_SAVED:
        if machine.regs[reg] != 0x1111111111111100 + reg:
            raise Halt("callee-saved register changed")


def run_finish(machine, acc, e, dl):
    prepare(machine, b"", 0)
    junk = 0x5A5A5A00
    run_frame(machine, FINISH, {RDI: OUT, RSI: DE, RDX: junk | (dl & 0xFF), RCX: acc, RAX: 0xFFFF000000000000 | (e & M32)})
    return collect(machine)


def agrees(run, want):
    tag, payload, idx, trace, ptr, length = run
    wtag, wpayload, widx, wtrace = want
    if tag != wtag or idx != widx or ptr != DATA:
        return False
    if tuple(trace) != tuple(wtrace):
        return False
    return payload == wpayload


def finish_want(acc, e, dl, env, o=DEFAULT):
    trace = []
    state = {"idx": 0}
    tag, payload = finish_model(acc, e, (dl & 0xFF) != 0, env, o, trace, state)
    return tag, payload, 0, trace


# ---------------------------------------------------------------------------------------------
# Cases.
# ---------------------------------------------------------------------------------------------
NOTABLE = (0, 1, 9, 10, 99, 12345, (1 << 53) - 1, 1 << 53, (1 << 53) + 1, (1 << 63) - 1, 1 << 63, (1 << 63) + 1, (1 << 64) - 1,
           LIMIT, LIMIT + 1, LIMIT - 1, 0x1999999999999997, 0x1999999999999999 * 5, 10 ** 18, 10 ** 19 - 1, 18446744073709551615)
TAILS = (b"", b".", b".0", b".5", b".25", b".x", b"..", b".e", b".E", b".e5", b".5e", b".5E-3", b".5e+7", b".5x", b".00000", b"e", b"E", b"e5",
         b"E+2", b"x", b" ", b",", b"}", b"-", b"0", b"7")


def make_case(rng):
    kind = rng.random()
    digits = "".join(rng.choice("0123456789") for _ in range(rng.choice((0, 1, 1, 2, 3, 5, 8, 12, 17, 19, 20)))).encode()
    if rng.random() < 0.5:
        acc = rng.choice(NOTABLE)
    elif digits:
        acc = int(digits) & M64X
    else:
        acc = rng.getrandbits(rng.choice((8, 32, 53, 63, 64)))
    prefix = rng.choice((b"", b"1", b"-", b"[", b"12", digits[:3]))
    dl = rng.choice((0, 1, 1, 0, 2, 0x80, 0xFF))
    if kind < 0.55:
        count = rng.choice((0, 1, 2, 3, 4, 6, 9, 12, 16, 17, 18, 19, 20, 21, 22, 25, 30, 40, 80, 150, 200, 320, 330))
        fraction = bytes(rng.choice(b"0123456789") if rng.random() < 0.85 else rng.choice(b"0000000005") for _ in range(count))
        tail = b"." + fraction
        end = rng.random()
        if end < 0.25:
            tail += rng.choice((b"e", b"E", b"e5", b"E-7", b"e+3", b"e999"))
        elif end < 0.5:
            tail += rng.choice((b"x", b",", b"}", b" ", b"-", b"+", b"\x00", b"\xb0", b":", b"/"))
    elif kind < 0.8:
        tail = rng.choice(TAILS)
    else:
        tail = bytes(rng.getrandbits(8) for _ in range(rng.choice((0, 1, 2, 5))))
    data = prefix + tail
    idx = len(prefix)
    if rng.random() < 0.06:
        idx = rng.choice((len(data), len(data) + 1, len(data) + 5))
    if rng.random() < 0.3:
        acc = rng.choice(NOTABLE) if rng.random() < 0.5 else rng.getrandbits(64)
    return data, idx, acc, dl


def boundary_cases():
    """Accumulator limit cases: the digit run after the dot is built around the limit."""
    out = []
    for acc in (LIMIT - 1, LIMIT, LIMIT + 1, LIMIT + 2, 0x19999999999999A0, 1 << 63, (1 << 64) - 1, 0x0FFFFFFFFFFFFFFF, 10 ** 18):
        for digits in (b"0", b"4", b"5", b"6", b"9", b"55", b"06", b"99"):
            for dl in (0, 1):
                out.append((b"." + digits, 0, acc, dl))
    for dl in (0, 1):
        for acc in (0, 1, 2, (1 << 63) - 1, 1 << 63, (1 << 63) + 1, (1 << 64) - 1):
            out.append((b"", 0, acc, dl))
            out.append((b"x", 0, acc, dl))
    return out


def fragment_cases(rng, count):
    es = [-1, -2, -17, -308, -309, -0x134, -0x135, -0x136, -0x268, -0x269, -0x26A, -0x3FF, -0x400, -700, -1000, -2000, 0, 1, 17, 308, 309,
          0x134, 0x135, 0x136, 400, 1000, 0x7FFFFFFF - 1, -3000, -0x1D1, -0x1D0, -0x1CF]
    accs = [0, 1, 7, 10, 123456789, (1 << 53) + 1, (1 << 63) + 5, (1 << 64) - 1, 0x1999999999999999, 10 ** 18, 2, 3]
    for _ in range(count):
        e = rng.choice(es) if rng.random() < 0.6 else rng.randint(-4000, 800)
        if e == 0x7FFFFFFF - 1:
            e = 5000
        acc = rng.choice(accs) if rng.random() < 0.7 else rng.getrandbits(rng.choice((8, 20, 40, 64)))
        yield acc, e, rng.choice((0, 1, 1, 3, 0x80))


# ---------------------------------------------------------------------------------------------
# Mutants.
# ---------------------------------------------------------------------------------------------
MUTANTS = (
    ("e-lowercase-only", dict(e_lower_only=True)),
    ("negative-limit-below-2^63", dict(neg_limit=(1 << 63) - 1)),
    ("negative-zero-becomes-integer", dict(neg_zero_int=True)),
    ("accumulator-limit-plus-one", dict(limit=LIMIT + 1)),
    ("accumulator-limit-minus-one", dict(limit=LIMIT - 1)),
    ("last-digit-limit-4", dict(last_digit=4)),
    ("last-digit-limit-6", dict(last_digit=6)),
    ("empty-digits-code-5", dict(empty_code=5)),
    ("eof-code-13", dict(eof_code=0xD)),
    ("scale-threshold-0x134", dict(big_threshold=0x134)),
    ("scale-threshold-0x136", dict(big_threshold=0x136)),
    ("scale-step-0x133", dict(step=0x133)),
    ("scale-step-0x135", dict(step=0x135)),
    ("scale-by-multiply", dict(div_as_mul=True)),
    ("overflow-check-dropped", dict(no_inf_check=True)),
    ("sign-dropped", dict(no_sign=True)),
    ("index-not-advanced", dict(no_advance=True)),
    ("zero-test-dropped", dict(no_zero_skip=True)),
    ("convert-truncates", dict(trunc_convert=True)),
    ("scale-exponent-signed-not-abs", dict(no_abs=True)),
    ("slow-path-scale-zero", dict(slow_scale_zero=True)),
    ("exponent-scale-zero", dict(exp_scale_zero=True)),
    ("sign-flag-ignored", dict(pos_ignored=True)),
    ("negative-float-unsigned", dict(neg_float_unsigned=True)),
    ("negative-tag-1", dict(int_tag_neg=1)),
    ("peek-code-13", dict(wrong_peek_code=0xD)),
)

EQUIVALENT_REASON = {
    "overflow-check-dropped": "the check follows the multiply branch, which needs a non-negative exponent count; the full function only passes the negated digit count, so only the fragment cases can reach it",
    "peek-code-13": "the 0xe error is raised only on the multiply branch (non-negative count), unreachable from the full function",
}


def patch_candidates(image, rows):
    """Byte corruptions from decoded rows: every jcc and cmov inverted, every compare/add immediate and 64-bit constant bumped."""
    out = []
    blob = image.blob
    for row in rows:
        at = image.offset(row.va)
        data = bytes(blob[at:at + row.size])
        if row.op == "jcc":
            where = 1 if data[0] == 0x0F else 0
            out.append(("invert-jcc-%x" % row.va, row.va + where, data[where], data[where] ^ 1))
        elif row.op == "cmov":
            where = data.index(0x0F) + 1
            out.append(("invert-cmov-%x" % row.va, row.va + where, data[where], data[where] ^ 1))
        elif row.op in ("cmp", "add", "sub") and row.b is not None and row.b[0] == "i":
            k = 0
            while data[k] in (0x66, 0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4A, 0x4B, 0x4C, 0x4D, 0x4E, 0x4F):
                k += 1
            opcode = data[k]
            size = 4 if opcode in (0x81, 0x3D, 0x05, 0x2D) else 1
            pos = row.size - size
            out.append(("bump-immediate-%x" % row.va, row.va + pos, data[pos], (data[pos] + 1) & 0xFF))
        elif row.op == "mov" and row.size == 10 and data[0] in (0x48, 0x49):
            out.append(("bump-constant-%x" % row.va, row.va + 2, data[2], (data[2] + 1) & 0xFF))
    return out


def tsv(path, header, lines):
    with open(path, "w", newline="\n") as handle:
        handle.write("\t".join(header) + "\n")
        for line in lines:
            handle.write("\t".join(str(x) for x in line) + "\n")


def outcome(run):
    tag = run[0]
    return {0: "float", 1: "unsigned", 2: "signed", 3: "error"}.get(tag, "tag%d" % tag)


def all_cases(count, seed):
    rng = random.Random(seed)
    for case in boundary_cases():
        yield case
    while True:
        yield make_case(rng)


def prove(image, env, total_cases, fragment_cases_n):
    rows = decode_range(image, *image.exact_fde(ENTRY))
    machine = Machine(image)
    install(machine, env)
    full = []
    gen = all_cases(total_cases, CASE_SEED)
    for _ in range(total_cases):
        full.append(next(gen))
    frag = list(fragment_cases(random.Random(CASE_SEED + 1), fragment_cases_n))
    sample, kinds, mismatches = [], {}, 0
    detected = {}
    union = set()
    for index, (data, idx, acc, dl) in enumerate(full):
        run = run_tail(machine, data, idx, acc, dl)
        want = tail_model(data, idx, acc, dl, env)
        if not agrees(run, want):
            mismatches += 1
            if mismatches < 4:
                raise EvidenceError("model disagrees at case %d: %r %r" % (index, run, want))
        union |= machine.seen
        key = (outcome(run), run[3][-1][0] if run[3] else "-")
        kinds[key] = kinds.get(key, 0) + 1
        if index < SAMPLE:
            sample.append((index, data.hex() or "-", idx, acc, dl, outcome(run), "%#x" % run[1], run[2], ";".join(t[0] for t in run[3]) or "-"))
        for name, change in MUTANTS:
            if name in detected:
                continue
            o = dict(DEFAULT)
            o.update(change)
            try:
                bad = not agrees(run, tail_model(data, idx, acc, dl, env, o))
            except (EvidenceError, IndexError, KeyError):
                bad = True
            if bad:
                detected[name] = index
    fsample = []
    for index, (acc, e, dl) in enumerate(frag):
        run = run_finish(machine, acc, e, dl)
        want = finish_want(acc, e, dl, env)
        if not agrees(run, want):
            raise EvidenceError("finish model disagrees at fragment case %d: %r %r" % (index, run, want))
        union |= machine.seen
        key = ("finish-" + outcome(run), run[3][-1][0] if run[3] else "-")
        kinds[key] = kinds.get(key, 0) + 1
        if index < 400:
            fsample.append((len(full) + index, acc, e, dl, outcome(run), "%#x" % run[1]))
        for name, change in MUTANTS:
            if name in detected:
                continue
            o = dict(DEFAULT)
            o.update(change)
            try:
                bad = not agrees(run, finish_want(acc, e, dl, env, o))
            except (EvidenceError, IndexError, KeyError):
                bad = True
            if bad:
                detected[name] = len(full) + index
    controls, equivalent, negative, found = [], [], 0, 0
    for name, _ in MUTANTS:
        negative += 1
        if name in detected:
            found += 1
            controls.append(("model", name, "-", detected[name]))
        else:
            equivalent.append((name, "-", EQUIVALENT_REASON.get(name, "no case separates it")))
    pfull = full[:PATCH_CASES] + full[-200:]
    pfrag = frag[:FRAGMENT_PATCH]
    for name, at, original, new in patch_candidates(image, rows):
        negative += 1
        if image.blob[image.offset(at)] != original:
            raise EvidenceError("patch site changed: %#x" % at)
        patched = Machine(image, {at: new})
        install(patched, env)
        hit = None
        for index, (data, idx, acc, dl) in enumerate(pfull):
            try:
                bad = not agrees(run_tail(patched, data, idx, acc, dl), tail_model(data, idx, acc, dl, env))
            except (Halt, Panicked, EvidenceError, KeyError, IndexError, ValueError):
                bad = True
            if bad:
                hit = index
                break
        if hit is None:
            for index, (acc, e, dl) in enumerate(pfrag):
                try:
                    bad = not agrees(run_finish(patched, acc, e, dl), finish_want(acc, e, dl, env))
                except (Halt, Panicked, EvidenceError, KeyError, IndexError, ValueError):
                    bad = True
                if bad:
                    hit = len(pfull) + index
                    break
        if hit is None:
            reason = "none of the %d full and %d fragment patch cases separates it from the unmodified bytes" % (len(pfull), len(pfrag))
            if at == 0x3EF2326:
                reason = "the low byte of the absolute-value mask only matters for a NaN payload with a non-zero low byte, which a product of two finite doubles cannot produce; " + reason
            equivalent.append((name, "%#x" % at, reason))
        else:
            found += 1
            controls.append(("bytes", name, "%#x" % at, hit))
    return dict(rows=rows, union=union, sample=sample, fsample=fsample, kinds=kinds, total=len(full) + len(frag), full=len(full), frag=len(frag),
                controls=controls, equivalent=equivalent, negative=negative, found=found)


# ---------------------------------------------------------------------------------------------
# Second function of the same failure path: the type-mismatch peek 0x3ef2ab0.
# ---------------------------------------------------------------------------------------------
PEEK = 0x3EF2AB0
NUMBER_PARSER = 0x3EF2440
FIXUP = 0x4671240
SLOT_UNEXPECTED = 0x64E0900
SLOT_NUMBER = 0x64E1350
SLOT_STRING = 0x64E08F8
JUMP_TABLE = 0x7BEB94
TABLE_FIRST = 0x5B
TABLE_COUNT = 33
FAKE_UNEXPECTED = 0x7700003000
FAKE_NUMBER = 0x7700003100
FAKE_STRING = 0x7700003200
SLOT10 = 0x77
PEEK_CASES = 4000
PEEK_PATCH = 1500
PEEK_SAMPLE = 500
LITERALS = {0x66: (b"alse", 0, 0), 0x74: (b"rue", 0, 1), 0x6E: (b"ull", 7, 0)}
WORD_ACTIONS = {0x3EF2D36: 0xA, 0x3EF2D2D: 0xB}


def table_actions(image):
    """The 33 rel32 jump-table entries of the byte dispatch: byte -> block address."""
    base = image.offset(JUMP_TABLE)
    values = struct.unpack_from("<%di" % TABLE_COUNT, image.blob, base)
    return {TABLE_FIRST + i: JUMP_TABLE + v for i, v in enumerate(values)}


def fixword(err, idx):
    return mix(5, err, idx) | 1 << 62


def install_peek(machine, env):
    memory = machine.memory
    memory.statics[SLOT_UNEXPECTED] = FAKE_UNEXPECTED
    memory.statics[SLOT_NUMBER] = FAKE_NUMBER
    memory.statics[SLOT_STRING] = FAKE_STRING

    def fixup(m):
        err, de = m.regs[RDI], m.regs[RSI]
        idx = memory.read(de + 0x28, 8)
        m.trace.append(("fix", err, idx))
        m.regs[RAX] = fixword(err, idx)

    def number(m):
        out, de, positive = m.regs[RDI], m.regs[RSI], m.regs[RDX] & M32
        idx = memory.read(de + 0x28, 8)
        h = mix(21, positive, idx)
        m.trace.append(("num", positive, idx))
        memory.write(out, 8, h & 3)
        memory.write(out + 8, 8, error_word(3, h, idx) if h & 3 == 3 else h >> 3)

    def unexpected(m):
        ptr = m.regs[RDI]
        tag = memory.read(ptr, 1)
        b1 = memory.read(ptr + 1, 1) if tag == 0 else 0
        q8 = memory.read(ptr + 8, 8) if tag == 5 else 0
        q16 = memory.read(ptr + 16, 8) if tag == 5 else 0
        m.trace.append(("unexp", tag, b1, q8, q16, m.regs[RSI], m.regs[RDX]))
        m.regs[RAX] = mix(6, tag, b1, q8, q16, m.regs[RSI], m.regs[RDX])

    def numeric(m):
        ptr = m.regs[RDI]
        tag, payload = memory.read(ptr, 4), memory.read(ptr + 8, 8)
        m.trace.append(("numexp", tag, payload, m.regs[RSI], m.regs[RDX]))
        m.regs[RAX] = mix(7, tag, payload, m.regs[RSI], m.regs[RDX])

    def string(m):
        out, source, de = m.regs[RDI], m.regs[RSI], m.regs[RDX]
        idx = memory.read(de + 0x28, 8)
        h = mix(31, idx)
        m.trace.append(("str", idx, source - de, memory.read(de + 0x10, 8)))
        memory.write(out, 4, h & 3)
        memory.write(out + 8, 8, error_word(4, h, idx) if h & 3 == 2 else h >> 2)
        memory.write(out + 16, 8, mix(32, idx))

    machine.calls[FIXUP] = fixup
    machine.calls[NUMBER_PARSER] = number
    machine.slots[FAKE_UNEXPECTED] = unexpected
    machine.slots[FAKE_NUMBER] = numeric
    machine.slots[FAKE_STRING] = string


DEFAULT_PEEK = dict(
    false_word=b"alse", true_word=b"rue", null_word=b"ull", null_tag=7, bool_flip=False, seq_tag=0xA, map_tag=0xB, str_tag=5,
    eof_code=5, mismatch_code=9, value_code=0xA, neg_flag=0, pos_flag=1,
    string_clear=True, digit_advance=False, minus_no_advance=False, pass_args=True, fix_numbers=True, error_tag_2=2, error_tag_3=3,
)


def peek_model(data, idx, rsi, rdx, actions, o=DEFAULT_PEEK):
    """Returns (rax, final index, slot10, trace) for one call of 0x3ef2ab0."""
    n = len(data)
    trace = []
    st = {"idx": idx, "slot10": SLOT10}

    def at(code):
        trace.append(("at", code, st["idx"]))
        return error_word(1, code, st["idx"])

    def peek(code):
        trace.append(("peek", code, st["idx"]))
        return error_word(2, code, st["idx"])

    def fix(err):
        trace.append(("fix", err, st["idx"]))
        return fixword(err, st["idx"])

    def unexpected(tag, b1, q8=0, q16=0):
        trace.append(("unexp", tag, b1, q8, q16, rsi if o["pass_args"] else 0, rdx))
        return fix(mix(6, tag, b1, q8, q16, rsi if o["pass_args"] else 0, rdx))

    def literal(word, first):
        letters = word
        st["idx"] += 1
        pos = st["idx"]
        for k, want in enumerate(letters):
            if pos >= n:
                return peek(o["eof_code"])
            got = data[pos]
            pos += 1
            st["idx"] = pos
            if got != want:
                return peek(o["mismatch_code"])
        return None

    def number_path(positive, advance):
        if advance:
            st["idx"] += 1
        h = mix(21, positive, st["idx"])
        trace.append(("num", positive, st["idx"]))
        tag, payload = h & 3, (error_word(3, h, st["idx"]) if h & 3 == 3 else h >> 3)
        if tag == o["error_tag_3"]:
            return payload
        trace.append(("numexp", tag, payload, rsi, rdx))
        err = mix(7, tag, payload, rsi, rdx)
        return fix(err) if o["fix_numbers"] else err

    if idx >= n:
        return fix(at(o["value_code"])), st["idx"], st["slot10"], trace
    ch = data[idx]
    action = actions.get(ch) if 0x5B <= ch <= 0x7B else None
    if action in WORD_ACTIONS:
        tag = o["seq_tag"] if WORD_ACTIONS[action] == 0xA else o["map_tag"]
        return unexpected(tag, 0), st["idx"], st["slot10"], trace
    if action == 0x3EF2AF8:
        r = literal(o["false_word"], 0)
        return (r if r is not None else unexpected(0, 1 if o["bool_flip"] else 0)), st["idx"], st["slot10"], trace
    if action == 0x3EF2BF7:
        r = literal(o["true_word"], 0)
        return (r if r is not None else unexpected(0, 0 if o["bool_flip"] else 1)), st["idx"], st["slot10"], trace
    if action == 0x3EF2C6B:
        r = literal(o["null_word"], 0)
        return (r if r is not None else unexpected(o["null_tag"], 0)), st["idx"], st["slot10"], trace
    if ch == 0x22:
        st["idx"] += 1
        if o["string_clear"]:
            st["slot10"] = 0
        h = mix(31, st["idx"])
        trace.append(("str", st["idx"], 0x18, st["slot10"]))
        tag = h & 3
        payload = error_word(4, h, st["idx"]) if tag == o["error_tag_2"] else h >> 2
        if tag == o["error_tag_2"]:
            return payload, st["idx"], st["slot10"], trace
        q16 = mix(32, st["idx"])
        r = unexpected(o["str_tag"], 0, payload, q16)
        return r, st["idx"], st["slot10"], trace
    if ch == 0x2D:
        return number_path(o["neg_flag"], not o["minus_no_advance"]), st["idx"], st["slot10"], trace
    if 0x30 <= ch <= 0x39:
        return number_path(o["pos_flag"], o["digit_advance"]), st["idx"], st["slot10"], trace
    return fix(at(o["value_code"])), st["idx"], st["slot10"], trace


def run_peek(machine, data, idx, rsi, rdx):
    memory = machine.memory
    prepare(machine, data, idx)
    memory.write(DE + 0x10, 8, SLOT10)
    rax = machine.run(PEEK, {RDI: DE, RSI: rsi, RDX: rdx})
    return rax, memory.read(DE + 0x28, 8), memory.read(DE + 0x10, 8), tuple(machine.trace), memory.read(DE + 0x18, 8)


def peek_agrees(run, want):
    rax, idx, slot10, trace, ptr = run
    wrax, widx, wslot, wtrace = want
    return rax == wrax and idx == widx and slot10 == wslot and tuple(trace) == tuple(wtrace) and ptr == DATA


def peek_cases(rng, count):
    words = (b"false", b"true", b"null")
    for first in range(256):
        for _ in range(3):
            rest = bytes(rng.getrandbits(8) for _ in range(rng.choice((0, 1, 3, 6))))
            yield bytes([first]) + rest, 0, rng.getrandbits(64), rng.getrandbits(64)
    for word in words:
        for cut in range(1, len(word) + 1):
            yield word[:cut], 0, rng.getrandbits(64), rng.getrandbits(64)
        for pos in range(len(word)):
            for bad in (0x00, 0x20, 0x41, 0xFF, word[pos] ^ 1, word[pos] + 1, word[pos] - 1):
                mutated = bytearray(word)
                mutated[pos] = bad
                yield bytes(mutated) + b"x", 0, rng.getrandbits(64), rng.getrandbits(64)
        yield word + b"s", 0, rng.getrandbits(64), rng.getrandbits(64)
        yield b" " + word, 1, rng.getrandbits(64), rng.getrandbits(64)
    for k in range(48):
        yield b" " * k + b"\"" + bytes(rng.getrandbits(8) for _ in range(k % 5)), k, rng.getrandbits(64), rng.getrandbits(64)
    for _ in range(count):
        kind = rng.random()
        if kind < 0.3:
            base = rng.choice(words)
            data = base[:rng.randint(0, len(base))] + bytes(rng.getrandbits(8) for _ in range(rng.randint(0, 3)))
        elif kind < 0.5:
            data = rng.choice((b"[", b"{", b"\"", b"\"abc\"", b"-", b"-1", b"-1.5e3", b"7", b"123", b"0.5", b"9" * 25, b"-" + b"9" * 25, b"-x", b"\"", b" x"))
        else:
            data = bytes(rng.choice(b"[]{}\"-0123456789ftnaelrus, x") for _ in range(rng.randint(0, 6)))
        idx = len(data) if rng.random() < 0.05 else (rng.randint(0, len(data)) if rng.random() < 0.3 else 0)
        yield data, idx, rng.getrandbits(64), rng.getrandbits(64)


PEEK_MUTANTS = (
    ("false-word-typo", dict(false_word=b"alsE")),
    ("true-word-typo", dict(true_word=b"rux")),
    ("null-word-typo", dict(null_word=b"uli")),
    ("bool-flipped", dict(bool_flip=True)),
    ("null-tag-6", dict(null_tag=6)),
    ("sequence-tag-swapped", dict(seq_tag=0xB, map_tag=0xA)),
    ("string-tag-4", dict(str_tag=4)),
    ("eof-code-10", dict(eof_code=0xA)),
    ("mismatch-code-5", dict(mismatch_code=5)),
    ("value-code-5", dict(value_code=5)),
    ("negative-flag-swapped", dict(neg_flag=1, pos_flag=0)),
    ("string-slot-not-cleared", dict(string_clear=False)),
    ("digit-advances", dict(digit_advance=True)),
    ("minus-does-not-advance", dict(minus_no_advance=True)),
    ("visitor-argument-dropped", dict(pass_args=False)),
    ("number-error-not-fixed", dict(fix_numbers=False)),
    ("string-error-tag-3", dict(error_tag_2=3)),
    ("number-error-tag-2", dict(error_tag_3=2)),
)


def prove_peek(image, env, actions, count):
    rows = decode_range(image, *image.exact_fde(PEEK))
    machine = Machine(image)
    install(machine, env)
    install_peek(machine, env)
    cases = list(peek_cases(random.Random(CASE_SEED + 7), count))
    detected, union, kinds, sample = {}, set(), {}, []
    for index, (data, idx, rsi, rdx) in enumerate(cases):
        run = run_peek(machine, data, idx, rsi, rdx)
        want = peek_model(data, idx, rsi, rdx, actions)
        if not peek_agrees(run, want):
            raise EvidenceError("peek model disagrees at case %d: %r %r" % (index, run, want))
        union |= machine.seen
        last = run[3][-1][0] if run[3] else "-"
        kinds[last] = kinds.get(last, 0) + 1
        if index < PEEK_SAMPLE:
            sample.append((index, data.hex() or "-", idx, last, "%#x" % run[0], run[1], ";".join(t[0] for t in run[3]) or "-"))
        for name, change in PEEK_MUTANTS:
            if name in detected:
                continue
            o = dict(DEFAULT_PEEK)
            o.update(change)
            if not peek_agrees(run, peek_model(data, idx, rsi, rdx, actions, o)):
                detected[name] = index
    controls, equivalent, negative, found = [], [], 0, 0
    for name, _ in PEEK_MUTANTS:
        negative += 1
        if name in detected:
            found += 1
            controls.append(("peek-model", name, "-", detected[name]))
        else:
            equivalent.append((name, "-", "no peek case separates it"))
    pcases = cases[:PEEK_PATCH] + cases[-100:]
    for name, at, original, new in patch_candidates(image, rows):
        negative += 1
        if image.blob[image.offset(at)] != original:
            raise EvidenceError("patch site changed: %#x" % at)
        patched = Machine(image, {at: new})
        install(patched, env)
        install_peek(patched, env)
        hit = None
        for index, (data, idx, rsi, rdx) in enumerate(pcases):
            try:
                bad = not peek_agrees(run_peek(patched, data, idx, rsi, rdx), peek_model(data, idx, rsi, rdx, actions))
            except (Halt, Panicked, EvidenceError, KeyError, IndexError, ValueError):
                bad = True
            if bad:
                hit = index
                break
        if hit is None:
            equivalent.append(("peek:" + name, "%#x" % at, "none of the %d peek patch cases separates it from the unmodified bytes" % len(pcases)))
        else:
            found += 1
            controls.append(("peek-bytes", name, "%#x" % at, hit))
    return dict(rows=rows, union=union, kinds=kinds, sample=sample, total=len(cases), controls=controls, equivalent=equivalent, negative=negative, found=found)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--out", required=True)
    args = parser.parse_args()
    out = pathlib.Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    image = load_image()
    env = read_environment(image)
    r = prove(image, env, CASES, FRAGMENT_CASES)
    actions = table_actions(image)
    p = prove_peek(image, env, actions, PEEK_CASES)
    tsv(out / "controls.tsv", ["kind", "mutation", "address", "first_case_detected"], r["controls"] + p["controls"])
    tsv(out / "equivalent-mutants.tsv", ["mutation", "address", "reason"], r["equivalent"] + p["equivalent"])
    tsv(out / "peek-cases-sample.tsv", ["case", "data_hex", "start_index", "last_call", "result", "final_index", "calls"], p["sample"])
    tsv(out / "peek-kinds.tsv", ["last_call", "cases"], sorted(p["kinds"].items()))
    tsv(out / "peek-body.tsv", ["va", "bytes", "op", "executed"],
        [("%#x" % row.va, row.next - row.va, row.op, 1 if row.va in p["union"] else 0) for row in p["rows"]])
    tsv(out / "peek-jump-table.tsv", ["byte", "block"], [("%#x" % b, "%#x" % a) for b, a in sorted(actions.items())])
    tsv(out / "cases-sample.tsv", ["case", "data_hex", "start_index", "accumulator", "dl", "result", "payload", "final_index", "calls"], r["sample"])
    tsv(out / "finish-sample.tsv", ["case", "accumulator", "exponent_count", "dl", "result", "payload"], r["fsample"])
    tsv(out / "body.tsv", ["va", "bytes", "op", "executed"],
        [("%#x" % row.va, row.next - row.va, row.op, 1 if row.va in r["union"] else 0) for row in r["rows"]])
    tsv(out / "kinds.tsv", ["result", "last_call", "cases"], [(k[0], k[1], v) for k, v in sorted(r["kinds"].items())])
    constants = {"scale_constant": repr(env["scale"]), "table_slot": "%#x" % SLOT_TABLE, "table_va": "%#x" % env["table_va"],
                 "table_first": repr(env["table"][0]), "table_last": repr(env["table"][-1]), "table_len": len(env["table"]),
                 "table_is_powers_of_ten": all(env["table"][i] == float("1e%d" % i) for i in range(len(env["table"]))),
                 "sign_mask": "%#x" % env["sign"], "magic_a": env["magic_a"].hex(), "magic_b": env["magic_b"].hex(),
                 "accumulator_limit": "%#x" % LIMIT, "scale_threshold": "%#x" % TABLE_LEN}
    (out / "constants.json").write_text(json.dumps(constants, indent=1, sort_keys=True) + "\n")
    rows = r["rows"]
    summary = {"entry": "%#x" % ENTRY, "finish_entry": "%#x" % FINISH, "body_bytes": rows[-1].next - rows[0].va, "instructions": len(rows),
               "executed": sum(1 for row in rows if row.va in r["union"]), "cases": r["total"], "full_function_cases": r["full"],
               "fragment_cases": r["frag"], "peek_entry": "%#x" % PEEK, "peek_cases": p["total"], "peek_instructions": len(p["rows"]),
               "peek_executed": sum(1 for row in p["rows"] if row.va in p["union"]), "binary_sha256": SHA256}
    (out / "summary.json").write_text(json.dumps(summary, indent=1, sort_keys=True) + "\n")
    measure = {"cases": r["total"] + p["total"], "negative_controls": r["negative"] + p["negative"], "negative_detected": r["found"] + p["found"],
               "equivalent": len(r["equivalent"]) + len(p["equivalent"])}
    (out / "measure.json").write_text(json.dumps(measure, indent=1, sort_keys=True) + "\n")
    print(json.dumps(measure, sort_keys=True))


if __name__ == "__main__":
    main()
