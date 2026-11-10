#!/usr/bin/env python3
"""Reconstruct upsert and remove-by-key of the ring-or-tree ordered record map used by the hl-quantities owners of node #115 (ring representation).

The tool reads the ELF bytes only. A small x86-64 interpreter (Image, decode, Memory, Machine) runs the upsert 0x4dd6150, the remove 0x4ddbf90, the ring
search 0x57f6910, the deque insert 0x57eee80 and the ring copy 0x580dc90 as real code; the memmove slot and the growth slot are documented contracts.
A Python model is compared with the interpreter on every case: return values, the deque handle and the whole record buffers. Single-byte mutations
of the five bodies (ring-representation instructions only) are the negative controls.

    python3 tools/hl_quantities_ring_map_115.py --out research/work-items/RE-009-quantities-ring-map-115
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
            raise Halt("lock prefix before a non-atomic instruction: undefined opcode")
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
                  (0x74, True): "pcmpeqb", (0x64, True): "pcmpgtb", (0x76, True): "pcmpeqd", (0x14, False): "punpckldq", (0x6C, True): "punpcklqdq",
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
        elif op == "pcmpgtb":
            left, right = self.xmm[row.a[1]].to_bytes(16, "little"), self.vector(row.b).to_bytes(16, "little")
            lanes = (b"\xff" if (a - 256 if a & 0x80 else a) > (b - 256 if b & 0x80 else b) else b"\x00" for a, b in zip(left, right))
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



# =============================================================================================
# Ring-or-tree ordered record map (hl-quantities, l1 books/pdi owners): remove-by-key 0x4ddbf90, ring search 0x57f6910, ring copy 0x580dc90
# =============================================================================================
import argparse
import json
import random

SEARCH_FN, REMOVE_FN, WRAP_FN = 0x57F6910, 0x4DDBF90, 0x580DC90
GOT_MEMMOVE = 0x64DF568
FAKE_MEMMOVE = 0x7FFF0090
M64 = (1 << 64) - 1
TREE_NICHE = 1 << 63          # capacity word of the tree representation: i64::MIN
ROW = 24                      # record: u64 key, then two u64 words of value

DQ = HEAP_BASE + 0x1000       # deque handle: capacity, buffer pointer, head, length
KEYCELL = HEAP_BASE + 0x1100  # the u64 key the callers pass by address
OUT = HEAP_BASE + 0x1200      # Option<(u64,u64)>: u32 tag at +0, payload 16 bytes at +4
BUF = HEAP_BASE + 0x2000      # record buffer, capacity * 24 bytes
USED = 0x7400
OUT_LEN = 0x14

# Instruction ranges of 0x4ddbf90 that belong to the ring representation (the tree arm calls 0x51d8900, 0x5b929a0 and 0x51da3a0 and is not modeled)
REMOVE_RING = [(0x4DDBF90, 0x4DDBFAE), (0x4DDBFD8, 0x4DDC0B6), (0x4DDC1DD, 0x4DDC201)]
UPSERT_FN, DEQ_INSERT_FN = 0x4DD6150, 0x57EEE80
GOT_GROW = 0x64E5E18
FAKE_GROW = 0x7FFF00A0
VALCELL = HEAP_BASE + 0x1140  # the 16 value bytes the caller passes by address
BUF2 = HEAP_BASE + 0x2800     # buffer the growth contract hands out

# Ring-representation instruction ranges of the upsert 0x4dd6150 (tree conversion and tree lookup arms are not modeled)
UPSERT_RING = [(0x4DD6150, 0x4DD6196), (0x4DD62BB, 0x4DD62F9), (0x4DD6386, 0x4DD63C5), (0x4DD63E8, 0x4DD6419), (0x4DD64EA, 0x4DD650A), (0x4DD655E, 0x4DD6595)]
SCOPE = {REMOVE_FN: REMOVE_RING, UPSERT_FN: UPSERT_RING}
TRIPLE_FN = 0x5362120
COLLECT_FN, GROW_AMORT_FN, RESERVE_EXACT_FN, DROP_ERR_FN = 0x5B9EBF0, 0x5963A10, 0x5963650, 0x5630000
TREM_FN, PRED_FN, LEAFKV_FN = 0x51D8900, 0x4D33AB0, 0x4D19D30
MERGE_FN, STEAL_LEFT_FN, STEAL_RIGHT_FN = 0x4CA1610, 0x4C958A0, 0x4C96370
TREE_FUNCS = (TREM_FN, PRED_FN, LEAFKV_FN, MERGE_FN, STEAL_LEFT_FN, STEAL_RIGHT_FN)
FUNCTIONS = [(SEARCH_FN, "ring-search"), (REMOVE_FN, "ring-remove"), (WRAP_FN, "ring-copy"), (UPSERT_FN, "ring-upsert"), (DEQ_INSERT_FN, "ring-insert-at"),
             (TRIPLE_FN, "triple-lookup"), (0x5B72670, "range-builder"), (COLLECT_FN, "limit-collector"), (GROW_AMORT_FN, "vec-grow-amortized"), (RESERVE_EXACT_FN, "vec-reserve-exact"),
             (TREM_FN, "tree-remove"), (PRED_FN, "tree-remove-inner"), (LEAFKV_FN, "tree-leaf-remove"), (MERGE_FN, "tree-merge"),
             (STEAL_LEFT_FN, "tree-steal-left"), (STEAL_RIGHT_FN, "tree-steal-right")]
USERS = {SEARCH_FN: ["search", "remove", "upsert", "triple", "range"], REMOVE_FN: ["remove"], WRAP_FN: ["remove", "wrap", "upsert"], UPSERT_FN: ["upsert"],
         DEQ_INSERT_FN: ["upsert"], TRIPLE_FN: ["triple", "range"], 0x5B72670: ["range"], COLLECT_FN: ["collect"], GROW_AMORT_FN: ["collect", "grow"], RESERVE_EXACT_FN: ["collect", "grow"],
         TREM_FN: ["tremove"], PRED_FN: ["tremove", "tpos"], LEAFKV_FN: ["tremove", "tpos"], MERGE_FN: ["tremove", "tpos"],
         STEAL_LEFT_FN: ["tremove", "tpos"], STEAL_RIGHT_FN: ["tremove", "tpos"]}
CASES = dict(search=400, remove=600, wrap=300, upsert=700, triple=700, range=600, collect=500, tremove=2200, grow=600, tpos=1600)
DETECT = dict(search=40, remove=50, wrap=30, upsert=60, triple=60, range=60, collect=50, tremove=130, grow=50, tpos=130)

# triple lookup 0x5362120: context {map1 handle, key address, map2 handle, map3 handle}; the result holds three Option<(u64,u64)> at 0, 0x14 and 0x28
CTX = HEAP_BASE + 0x1180
MAPS = [HEAP_BASE + 0x1400, HEAP_BASE + 0x1440, HEAP_BASE + 0x1480]
REGION = [HEAP_BASE + 0x3000, HEAP_BASE + 0x4400, HEAP_BASE + 0x5800]
NODE = 0x180                  # B-tree node: 11 values of 16 bytes at 0, parent 0xb0, keys 0xb8, parent index 0x110, length u16 0x112, edges 0x118
TRIPLE_OUT = (0, 0x14, 0x28)
MUTANT_STEPS = 6000


class Crash(Exception):
    """A diagnostic the bytes reach (overflow panic, allocation error): kind and payload are compared with the model."""

    def __init__(self, kind, payload=()):
        super().__init__(kind)
        self.kind = kind
        self.payload = tuple(payload)


def phys(cap, head, offset):
    """Physical slot of logical offset `offset` from slot `head` (single conditional subtraction, as in the bytes)."""
    total = head + offset
    return total - cap if total >= cap else total


def bsearch(keys, base, count, key):
    """Branchless lower-bound walk of 0x57f6910 over keys[base:base+count]; returns (found, index within the slice)."""
    lo, n = 0, count
    while n > 1:
        half = n >> 1
        prev = lo
        lo += half
        if keys[base + lo] > key:
            lo = prev
        n -= half
    here = keys[base + lo]
    if here == key:
        return 0, lo
    return 1, lo + (1 if here < key else 0)


def search_model(cap, keys, head, length, key):
    """Result pair (rax, rdx) of the ring search: 0 = present at logical index rdx, 1 = absent, rdx = insertion index."""
    if length == 0:
        return 1, 0
    h = head - cap if head >= cap else head
    first = cap - h
    if length <= first:
        return bsearch(keys, h, length, key)
    rest = length - first
    second = keys[0]
    if second == key:
        return 0, first
    if second > key:
        return bsearch(keys, h, first, key)
    found, index = bsearch(keys, 0, rest, key)
    return found, first + index


def wrap_copy_model(rows, cap, src, dst, count):
    """Ring copy of `count` records from slot src to slot dst with wrap-around; overlap behaves like memmove."""
    if src == dst or count == 0:
        return
    moved = [rows[(src + i) % cap] for i in range(count)]
    for i in range(count):
        rows[(dst + i) % cap] = moved[i]


def remove_model(cap, rows, head, length, key):
    """Pure model of remove-by-key for the ring representation: returns (option, rows, head, length)."""
    found, index = search_model(cap, [r[0] for r in rows], head, length, key)
    if found:
        return None, rows, head, length
    rows = list(rows)
    p = phys(cap, head, index)
    removed = rows[p]
    tail = length - 1 - index
    if tail < index:
        wrap_copy_model(rows, cap, phys(cap, p, 1), p, tail)
    else:
        new_head = phys(cap, head, 1)
        wrap_copy_model(rows, cap, head, new_head, index)
        head = new_head
    return (removed[1], removed[2]), rows, head, length - 1


def row_bytes(row):
    return b"".join(word.to_bytes(8, "little") for word in row)


def make_case(rnd, number, kind):
    if kind == "tremove":
        return make_tremove(rnd, number)
    if kind == "grow":
        return make_grow(rnd, number)
    if kind == "tpos":
        return make_tpos(rnd, number)
    if kind == "triple":
        return make_triple(rnd, number)
    if kind == "range":
        return make_range(rnd, number)
    if kind == "collect":
        return make_collect(rnd, number)
    cap = rnd.choice([1, 2, 3, 4, 5, 6, 7, 8, 9, 12, 16, 17, 24]) if number % 3 else rnd.randint(1, 30)
    length = rnd.choice([0, 1, cap, cap, max(cap - 1, 0), rnd.randint(0, cap)])
    head = rnd.randint(0, cap - 1) if number % 5 else rnd.choice([0, cap - 1, max(cap - length, 0) % cap])
    pool = sorted(rnd.sample(range(0, 4 * cap + 8), length)) if length <= 4 * cap + 8 else []
    if number % 7 == 0:
        pool = sorted(rnd.choice([0, 1, M64, M64 - 1, 1 << 63, (1 << 63) - 1, rnd.getrandbits(64)]) for _ in range(length))
    if number % 11 == 0 and length > 1:
        pool[rnd.randrange(length)] = pool[rnd.randrange(length)]            # duplicate key, order kept below
        pool.sort()
    if number % 13 == 0 and length > 1:
        rnd.shuffle(pool)                                                    # unsorted input: the walk is still deterministic
    keys = list(pool)
    if keys and rnd.random() < 0.55:
        key = rnd.choice(keys)
    else:
        key = rnd.choice([0, 1, M64, 1 << 63, rnd.getrandbits(64), rnd.randint(0, 4 * cap + 8)])
    rows = [(keys[i], rnd.getrandbits(64), rnd.getrandbits(64)) for i in range(length)]
    slots = [(rnd.getrandbits(64), rnd.getrandbits(64), rnd.getrandbits(64)) for _ in range(cap)]
    for i in range(length):
        slots[phys(cap, head, i)] = rows[i]
    case = dict(cap=cap, head=head, length=length, key=key, slots=slots)
    if kind == "upsert":
        case["val"] = (rnd.getrandbits(64), rnd.getrandbits(64))
        if number % 19 == 0:
            case.update(cap=0, head=0, length=0, slots=[])
    if kind == "wrap":
        # the two shifts the remove performs, widened to small distances: the ring distance between source and destination is at most 3
        # and the span stays inside the ring (count + distance <= capacity)
        delta = rnd.randint(1, min(3, max(cap - 1, 1))) * rnd.choice([1, -1])
        src = rnd.randrange(cap)
        case["src"], case["dst"] = src, (src + delta) % cap
        case["count"] = rnd.randint(0, max(cap - abs(delta), 0))
    return case


def build(mem, case):
    mem.reset(USED)
    if "maps" in case or "records" in case:
        mem.write(KEYCELL, 8, case.get("key", 0))
        mem.put_bytes(OUT, bytes([0xCC]) * 0x40)
        if "records" in case:
            build_collect(mem, case)
        elif "asset" in case:
            build_range(mem, case)
        else:
            build_triple(mem, case)
        return
    cap = case["cap"]
    mem.write(DQ, 8, cap)
    mem.write(DQ + 8, 8, BUF)
    mem.write(DQ + 16, 8, case["head"])
    mem.write(DQ + 24, 8, case["length"])
    mem.write(KEYCELL, 8, case["key"])
    mem.write(DQ + 32, 8, 0)                      # the word after the handle is zero, so a bound check that reads it misaligned is visible
    if "val" in case:
        mem.put_bytes(VALCELL, b"".join(w.to_bytes(8, "little") for w in case["val"]))
    mem.put_bytes(OUT, bytes([0xCC]) * 0x20)
    for i, row in enumerate(case["slots"]):
        mem.put_bytes(BUF + ROW * i, row_bytes(row))


def tree_node(mem, addr, items, edges):
    """Write one B-tree node: values, keys, length and (for an inner node) the edge pointers."""
    mem.put_bytes(addr, bytes(NODE))              # unused value and key slots read as zero
    for i, (key, v1, v2) in enumerate(items):
        mem.put_bytes(addr + 16 * i, row_bytes((v1, v2)))
        mem.write(addr + 0xB8 + 8 * i, 8, key)
    if len(items) < 11:
        mem.write(addr + 0xB8 + 8 * len(items), 8, (items[-1][0] + 1) & M64 if items else 1)       # stale key slot right after the last live one
    mem.write(addr + 0x112, 2, len(items))
    for i, edge in enumerate(edges):
        mem.write(addr + 0x118 + 8 * i, 8, edge)


def build_tree(mem, base, items, leaf):
    """Lay out `items` (sorted, distinct) as a one-level or two-level B-tree from `base`; returns (root, height)."""
    if not items:
        return 0, 0
    if len(items) <= leaf:
        tree_node(mem, base, items, [])
        return base, 0
    groups, seps, i = [], [], 0
    while i < len(items):
        groups.append(items[i:i + leaf])
        i += leaf
        if i < len(items):
            seps.append(items[i])
            i += 1
    if len(seps) == len(groups):
        last = seps.pop()                    # a trailing separator has no leaf after it: the previous leaf gives up its last key as separator
        seps.append(groups[-1].pop())
        groups.append([last])
    addrs = [base + NODE * (1 + n) for n in range(len(groups))]
    for addr, group in zip(addrs, groups):
        tree_node(mem, addr, group, [])
    tree_node(mem, base, seps, addrs)
    return base, 1


def build_triple(mem, case):
    mem.write(CTX, 8, MAPS[0])
    mem.write(CTX + 8, 8, KEYCELL)
    mem.write(CTX + 16, 8, MAPS[1])
    mem.write(CTX + 24, 8, MAPS[2])
    for n, spec in enumerate(case["maps"]):
        handle = MAPS[n]
        mem.write(handle + 32, 8, 0)                  # the word after a handle is zero, so a length check that reads it misaligned is visible
        if spec["mode"] == "ring":
            mem.write(handle, 8, spec["cap"])
            mem.write(handle + 8, 8, REGION[n])
            mem.write(handle + 16, 8, spec["head"])
            mem.write(handle + 24, 8, spec["length"])
            for i, row in enumerate(spec["slots"]):
                mem.put_bytes(REGION[n] + ROW * i, row_bytes(row))
        else:
            root, height = build_tree(mem, REGION[n], spec["items"], spec["leaf"])
            mem.write(handle, 8, TREE_NICHE)
            mem.write(handle + 8, 8, root)
            mem.write(handle + 16, 8, height)
            mem.write(handle + 24, 8, len(spec["items"]))


def triple_model(mem, case, out=None):
    """Three independent lookups of the same key; a ring map follows the ring search, a tree map is an ordinary ordered-map get."""
    out = OUT if out is None else out
    for n, spec in enumerate(case["maps"]):
        at = TRIPLE_OUT[n]
        if spec["mode"] == "ring":
            found, index = search_model(spec["cap"], [r[0] for r in spec["slots"]], spec["head"], spec["length"], case["key"])
            hit = None
            if found == 0 and index < spec["length"]:
                hit = spec["slots"][phys(spec["cap"], spec["head"], index)][1:]
        else:
            hit = next(((v1, v2) for key, v1, v2 in spec["items"] if key == case["key"]), None)
        mem.write(out + at, 4, 0 if hit is None else 1)
        if hit is not None:
            mem.put_bytes(out + at + 4, row_bytes(hit))


RANGE_FN = 0x5B72670
ITER = HEAP_BASE + 0x1500       # iterator: asset-context pointer, start, end, map1, map2, map3
ASSET = HEAP_BASE + 0x1540      # asset context; the asset index is the word at +0x50
VECOUT = HEAP_BASE + 0x1600     # result vector: capacity, pointer, length
RANGE_ALLOC = HEAP_BASE + 0x6C00
ELEM = 0x3C
GOT_ALLOC, GOT_ALLOC_ERR, GOT_PANIC_ADD, GOT_PANIC_MUL, GOT_DEALLOC = 0x64DF480, 0x64DF498, 0x64DF520, 0x64DF870, 0x64DF4A0
FAKE_ALLOC, FAKE_ALLOC_ERR, FAKE_PANIC_ADD, FAKE_PANIC_MUL, FAKE_DEALLOC = 0x7FFF0010, 0x7FFF0020, 0x7FFF0030, 0x7FFF0040, 0x7FFF0050
RANGE_LOCATION = 0x64AA638      # the source Location both overflow diagnostics receive
MAX_ELEMS = 0x222222222222222   # largest count whose size in bytes (x 0x3c) stays below 2^63


def make_range(rnd, number):
    asset = rnd.choice([0, 0, 0, 1, 7, 300])
    start = rnd.randint(0, 30)
    count = rnd.choice([0, 1, 2, 3, 4, 5, 6])
    end = start + count if number % 11 else rnd.choice([start - 1 if start else 0, start, start + 1])
    case = dict(asset=asset, start=start, end=end, fail=number % 17 == 0)
    if number % 29 == 0:
        case["asset"] = rnd.choice([1 << 63, M64 // 10000 + 1, M64])        # asset * 10000 overflows
    elif number % 31 == 0:
        case["asset"], case["start"], case["end"] = 1, M64 - 5, M64        # start + asset * 10000 + i wraps
    elif number % 37 == 0:
        case["asset"], case["start"], case["end"] = 0, 0, M64              # count above the largest vector length
    elif number % 43 == 0:
        case["asset"], case["start"], case["end"] = 0, 0, MAX_ELEMS + rnd.choice([1, 2])   # count just above the largest size that fits an isize
    base = min((case["asset"] * 10000 + case["start"]) & M64 if case["asset"] * 10000 <= M64 else 0, M64 - 100)
    sub = make_triple(rnd, number, base)
    case["maps"] = sub["maps"]
    case["key"] = 0
    return case


def build_range(mem, case):
    mem.write(ASSET + 0x50, 8, case["asset"])
    for n, word in enumerate((ASSET, case["start"], case["end"], MAPS[0], MAPS[1], MAPS[2])):
        mem.write(ITER + 8 * n, 8, word)
    build_triple(mem, case)


class RangeWorld:
    """Contracts of the range builder: allocator (fixed block, null on request), overflow diagnostics and the allocation-error handler."""

    def __init__(self, fail):
        self.fail, self.sizes = fail, []

    def alloc(self, size):
        self.sizes.append(size)
        return 0 if self.fail else RANGE_ALLOC


def range_model(mem, case, world, log):
    """Model of 0x5b72670: one triple lookup per index of start..end with key start + asset * 10000 + i; returns a crash tuple or None."""
    count = max(case["end"] - case["start"], 0)
    size = count * ELEM
    if count > MAX_ELEMS:
        return ("alloc_error", (0, size & M64))
    pointer = 4
    if size:
        log.append(("alloc", size))
        pointer = world.alloc(size)
        if pointer == 0:
            return ("alloc_error", (4, size))
    for i in range(count):
        scaled = case["asset"] * 10000
        if scaled > M64:
            return ("panic_mul", (RANGE_LOCATION,))
        key = (case["start"] + scaled + i) & M64
        if key < scaled:
            return ("panic_add", (RANGE_LOCATION,))
        sub = dict(case, key=key)
        triple_model(mem, sub, pointer + ELEM * i)
    mem.write(VECOUT, 8, count)
    mem.write(VECOUT + 8, 8, pointer)
    mem.write(VECOUT + 16, 8, count)
    return None


def mask_range(mem, case):
    for i in range(min(max(case["end"] - case["start"], 0), 8)):
        for at in TRIPLE_OUT:
            if mem.read(RANGE_ALLOC + ELEM * i + at, 4) == 0:
                mem.put_bytes(RANGE_ALLOC + ELEM * i + at + 4, bytes(16))


COLLECT_FN, GROW_AMORT_FN, RESERVE_EXACT_FN, DROP_ERR_FN = 0x5B9EBF0, 0x5963A10, 0x5963650, 0x5630000
SLICE = HEAP_BASE + 0x1700     # records of 0x20 bytes, the u64 at +0x18 is the quantity compared with the limit
ERRSLOT = HEAP_BASE + 0x1B40   # error slot: u16 tag at +0 (0x1a2 = empty, 0x158 = limit exceeded), record pointer at +8
ITER2 = HEAP_BASE + 0x1B80     # slice iterator: start pointer, end pointer, error slot pointer
VOUT2 = HEAP_BASE + 0x1BC0     # result vector: capacity, pointer, length
COLLECT_ALLOC = HEAP_BASE + 0x7000
LIMIT = 0x2711                 # records with a quantity of 0x2711 or more stop the collection
TAG_EMPTY, TAG_LIMIT = 0x1A2, 0x158
GOT_REALLOC, GOT_ALLOC_AL, GOT_REALLOC_AL = 0x64DF588, 0x64DF590, 0x64DF580
FAKE_REALLOC, FAKE_ALLOC_AL, FAKE_REALLOC_AL = 0x7FFF0060, 0x7FFF0070, 0x7FFF0080


class BumpWorld:
    """Allocator contract of the collector: bump pointer with a size registry; the call number in `fail_at` (1-based) returns null."""

    def __init__(self, fail_at):
        self.fail_at, self.calls, self.next, self.sizes = fail_at, 0, COLLECT_ALLOC, {}

    def alloc(self, size):
        self.calls += 1
        if self.fail_at == self.calls or size > 0x400:
            return 0
        pointer = self.next
        self.next = (self.next + size + 0x2F) & ~0xF
        self.sizes[pointer] = size
        return pointer

    def realloc(self, mem, pointer, size):
        old = self.sizes.get(pointer, 0)
        new = self.alloc(size)
        if new:
            mem.put_bytes(new, mem.bytes_at(pointer, min(old, size)))
        return new


def make_collect(rnd, number):
    count = rnd.choice([0, 1, 2, 3, 4, 5, 8, 9, 12, 17])
    quantities = []
    for i in range(count):
        quantities.append(rnd.choice([0, 1, 100, 10000, 10000, 0x2711, 0x2712, M64]) if rnd.random() < 0.18 else rnd.randint(0, 10000))
    if number % 3 == 0:
        quantities = [q if q < LIMIT else 5 for q in quantities]            # nothing stops the collection
    records = [(rnd.getrandbits(64), rnd.getrandbits(64), rnd.getrandbits(64), q) for q in quantities]
    return dict(records=records, tag=rnd.choice([TAG_EMPTY, TAG_EMPTY, TAG_LIMIT, 0x10, 0x1A3]), fail_at=rnd.choice([0, 0, 0, 0, 1, 2, 3]))


def build_collect(mem, case):
    for i, record in enumerate(case["records"]):
        mem.put_bytes(SLICE + 0x20 * i, row_bytes(record))
    n = len(case["records"])
    mem.write(ERRSLOT, 2, case["tag"])
    mem.write(ERRSLOT + 8, 8, 0x1122334455667788)
    for k, word in enumerate((SLICE, SLICE + 0x20 * n, ERRSLOT)):
        mem.write(ITER2 + 8 * k, 8, word)


def collect_model(mem, case, world, log):
    """Model of 0x5b9ebf0: collect record pointers until the first record at or above the limit, which lands in the error slot."""
    records = case["records"]
    if not records:
        mem.write(VOUT2, 8, 0)
        mem.write(VOUT2 + 8, 8, 8)
        mem.write(VOUT2 + 16, 8, 0)
        return None

    def stop(index):
        if mem.read(ERRSLOT, 2) != TAG_EMPTY:
            log.append(("drop", ERRSLOT))
        mem.write(ERRSLOT, 2, TAG_LIMIT)
        mem.write(ERRSLOT + 8, 8, SLICE + 0x20 * index)

    if records[0][3] >= LIMIT:
        stop(0)
        mem.write(VOUT2, 8, 0)
        mem.write(VOUT2 + 8, 8, 8)
        mem.write(VOUT2 + 16, 8, 0)
        return None
    log.append(("alloc", 0x20))
    pointer = world.alloc(0x20)
    if pointer == 0:
        return ("alloc_error", (8, 0x20))
    cap, length = 4, 1
    mem.write(pointer, 8, SLICE)
    for index in range(1, len(records)):
        if records[index][3] >= LIMIT:
            stop(index)
            break
        if length == cap:
            new_cap = max(2 * cap, length + 1, 4)
            log.append(("realloc", new_cap * 8))
            moved = world.realloc(mem, pointer, new_cap * 8)
            if moved == 0:
                return ("alloc_error", (8, new_cap * 8))
            pointer, cap = moved, new_cap
        mem.write(pointer + 8 * length, 8, SLICE + 0x20 * index)
        length += 1
    mem.write(VOUT2, 8, cap)
    mem.write(VOUT2 + 8, 8, pointer)
    mem.write(VOUT2 + 16, 8, length)
    return None


def make_triple(rnd, number, base=0):
    universe = list(range(base, base + 70))
    maps = []
    for n in range(3):
        roll = rnd.random()
        if roll < 0.45:
            cap = rnd.choice([1, 2, 3, 5, 8, 12, 16])
            length = rnd.randint(0, cap)
            head = rnd.randrange(cap)
            keys = sorted(rnd.sample(universe, length))
            if number % 9 == 0 and length > 1:
                rnd.shuffle(keys)
            slots = [(rnd.getrandbits(64), rnd.getrandbits(64), rnd.getrandbits(64)) for _ in range(cap)]
            for i, key in enumerate(keys):
                slots[phys(cap, head, i)] = (key, rnd.getrandbits(64), rnd.getrandbits(64))
            maps.append(dict(mode="ring", cap=cap, head=head, length=length, slots=slots))
        else:
            size = rnd.choice([0, 1, 3, 7, 11, 12, 20, 33, 45]) if roll > 0.55 else rnd.randint(0, 40)
            keys = sorted(rnd.sample(universe, size))
            maps.append(dict(mode="tree", items=[(k, rnd.getrandbits(64), rnd.getrandbits(64)) for k in keys], leaf=rnd.choice([3, 4, 5, 7, 10, 11])))
    pool = [k for m in maps for k in ([r[0] for r in m["slots"][:m["length"]]] if m["mode"] == "ring" else [i[0] for i in m["items"]])]
    key = rnd.choice(pool) if pool and rnd.random() < 0.7 else rnd.choice([0, 69, 70, 71, M64, 1 << 63, rnd.randint(0, 69)])
    if number % 6 == 1 and base == 0:
        tops = [spec["items"][-1][0] for spec in maps if spec["mode"] == "tree" and spec["items"]]
        if tops:
            key = max(tops) + 1                                  # equals the stale key slot behind the last live key of the largest tree
    return dict(key=key, maps=maps)


def read_rows(mem, cap):
    return [tuple(int.from_bytes(mem.bytes_at(BUF + ROW * i + 8 * w, 8), "little") for w in range(3)) for i in range(cap)]


def install(machine, log, case=None):
    mem = machine.memory
    mem.statics[GOT_MEMMOVE] = FAKE_MEMMOVE
    world = RangeWorld(bool(case and case.get("fail")))
    bump = BumpWorld(case.get("fail_at", 0) if case else 0)

    def h_alloc(m):
        log.append(("alloc", m.regs[RDI]))
        if case and "records" in case:
            m.regs[RAX] = bump.alloc(m.regs[RDI])
        else:
            m.regs[RAX] = world.alloc(m.regs[RDI]) if m.regs[RDI] <= 0x1000 else 0

    def h_realloc(m):
        log.append(("realloc", m.regs[RSI]))
        m.regs[RAX] = bump.realloc(mem, m.regs[RDI], m.regs[RSI])

    def h_drop(m):
        log.append(("drop", m.regs[RDI]))

    def h_alloc_err(m):
        raise Crash("alloc_error", (m.regs[RDI], m.regs[RSI]))

    def h_panic_add(m):
        raise Crash("panic_add", (m.regs[RDI],))

    def h_panic_mul(m):
        raise Crash("panic_mul", (m.regs[RDI],))

    def h_dealloc(m):
        log.append(("dealloc", m.regs[RDI], m.regs[RSI]))

    for got, fake, hook in ((GOT_ALLOC, FAKE_ALLOC, h_alloc), (GOT_ALLOC_ERR, FAKE_ALLOC_ERR, h_alloc_err), (GOT_PANIC_ADD, FAKE_PANIC_ADD, h_panic_add),
                            (GOT_PANIC_MUL, FAKE_PANIC_MUL, h_panic_mul), (GOT_DEALLOC, FAKE_DEALLOC, h_dealloc)):
        mem.statics[got] = fake
        machine.slots[fake] = hook
    for got, fake in ((GOT_REALLOC, FAKE_REALLOC), (GOT_REALLOC_AL, FAKE_REALLOC_AL)):
        mem.statics[got] = fake
        machine.slots[fake] = h_realloc
    mem.statics[GOT_ALLOC_AL] = FAKE_ALLOC_AL
    machine.slots[FAKE_ALLOC_AL] = h_alloc
    machine.calls[DROP_ERR_FN] = h_drop

    def h_memmove(m):
        log.append(("memmove", (m.regs[RDI] - BUF) // ROW, (m.regs[RSI] - BUF) // ROW, m.regs[RDX] // ROW))
        if m.regs[RDX] > HEAP_SIZE:
            raise EvidenceError("copy longer than the heap")
        mem.put_bytes(m.regs[RDI], mem.bytes_at(m.regs[RSI], m.regs[RDX]))

    def h_grow(m):
        log.append(("grow", mem.read(m.regs[RDI], 8)))
        grow_contract(mem)

    mem.statics[GOT_GROW] = FAKE_GROW
    machine.slots[FAKE_MEMMOVE] = h_memmove
    machine.slots[FAKE_GROW] = h_grow
    machine.real = frozenset([SEARCH_FN, WRAP_FN, DEQ_INSERT_FN, TRIPLE_FN, GROW_AMORT_FN, RESERVE_EXACT_FN])


def grow_contract(mem):
    """Contract of the growth slot 0x64e5e18 (RawVec grow-one): capacity max(2 * cap, 4), records re-linearized into BUF2 with head 0."""
    cap, buf, head, length = (mem.read(DQ + 8 * i, 8) for i in range(4))
    for i in range(length):
        mem.put_bytes(BUF2 + ROW * i, mem.bytes_at(buf + ROW * phys(cap, head, i), ROW))
    mem.write(DQ, 8, max(2 * cap, 4))
    mem.write(DQ + 8, 8, BUF2)
    mem.write(DQ + 16, 8, 0)


def deque_insert_model(cap, rows, head, length, index, elem):
    """Model of 0x57eee80 once the buffer has room: shift the shorter side, then store the record."""
    tail = length - index
    if tail < index:
        wrap_copy_model(rows, cap, phys(cap, head, index), phys(cap, head, index + 1), tail)
    else:
        new_head = head - 1 if head else cap - 1
        wrap_copy_model(rows, cap, head, new_head, index)
        head = new_head
    rows[phys(cap, head, index)] = elem
    return head


def upsert_model(mem, case):
    """Model of the upsert for the ring representation: the previous value pair on a hit, None after inserting a new record."""
    cap, head, length = case["cap"], case["head"], case["length"]
    rows = read_rows(mem, cap)
    found, index = search_model(cap, [r[0] for r in rows], head, length, case["key"])
    if found == 0:
        slot = phys(cap, head, index)
        mem.write(OUT, 4, 1)
        mem.put_bytes(OUT + 4, row_bytes(rows[slot][1:]))
        mem.put_bytes(BUF + ROW * slot + 8, row_bytes(case["val"]))
        return
    mem.write(OUT, 4, 0)
    if length == cap:
        grow_contract(mem)
        cap = mem.read(DQ, 8)
        head = 0
        rows = [tuple(int.from_bytes(mem.bytes_at(BUF2 + ROW * i + 8 * w, 8), "little") for w in range(3)) for i in range(cap)]
        base = BUF2
    else:
        base = BUF
    head = deque_insert_model(cap, rows, head, length, index, (case["key"],) + case["val"])
    for i, row in enumerate(rows):
        mem.put_bytes(base + ROW * i, row_bytes(row))
    mem.write(DQ + 16, 8, head)
    mem.write(DQ + 24, 8, length + 1)


def drive(machine, image, case, kind, real):
    """One case on the bytes (real) or on the model; returns (outputs, state, log, heap prefix, executed)."""
    if kind == "tremove":
        return drive_tree(machine, image, case, real)
    if kind == "grow":
        return drive_grow(machine, image, case, real)
    if kind == "tpos":
        return drive_pos(machine, image, case, real)
    log, seen = [], set()
    if real:
        mem = machine.memory
        build(mem, case)
        install(machine, log, case)
        machine.seen = set()
        if kind == "collect":
            try:
                rax = machine.run(COLLECT_FN, {RDI: VOUT2, RSI: ITER2})
                outputs = (rax,)
            except Crash as exc:
                outputs = (exc.kind, exc.payload)
        elif kind == "range":
            try:
                rax = machine.run(RANGE_FN, {RDI: VECOUT, RSI: ITER})
                outputs = (rax,)
            except Crash as exc:
                outputs = (exc.kind, exc.payload)
        elif kind == "search":
            rax = machine.run(SEARCH_FN, {RDI: DQ, RSI: KEYCELL})
            outputs = (rax & M64, machine.regs[RDX] & M64)
        elif kind == "remove":
            rax = machine.run(REMOVE_FN, {RDI: OUT, RSI: DQ, RDX: KEYCELL})
            outputs = (rax,)
        elif kind == "upsert":
            rax = machine.run(UPSERT_FN, {RDI: OUT, RSI: DQ, RDX: case["key"], RCX: VALCELL})
            outputs = (rax,)
        elif kind == "triple":
            rax = machine.run(TRIPLE_FN, {RDI: OUT, RSI: CTX})
            outputs = (rax,)
        else:
            machine.run(WRAP_FN, {RDI: case["cap"], RSI: BUF, RDX: case["src"], RCX: case["dst"], R8: case["count"]})
            outputs = ()
        seen = set(machine.seen)
    else:
        mem = Memory(image)
        build(mem, case)
        if kind == "collect":
            crash = collect_model(mem, case, BumpWorld(case["fail_at"]), log)
            outputs = (VOUT2,) if crash is None else crash
            cap, rows, keys = 0, [], []
        elif kind == "range":
            crash = range_model(mem, case, RangeWorld(case["fail"]), log)
            outputs = (VECOUT,) if crash is None else crash
            cap, rows, keys = 0, [], []
        elif kind == "triple":
            triple_model(mem, case)
            cap, rows, keys = 0, [], []
        else:
            cap = case["cap"]
            rows = read_rows(mem, cap)
            keys = [r[0] for r in rows]
        if kind in ("range", "collect"):
            pass
        elif kind == "triple":
            outputs = (OUT,)
        elif kind == "search":
            outputs = search_model(cap, keys, case["head"], case["length"], case["key"])
        elif kind == "remove":
            option, rows, head, length = remove_model(cap, rows, case["head"], case["length"], case["key"])
            if option is None:
                mem.write(OUT, 4, 0)
            else:
                mem.write(OUT, 4, 1)
                mem.put_bytes(OUT + 4, b"".join(w.to_bytes(8, "little") for w in option))
            mem.write(DQ + 16, 8, head)
            mem.write(DQ + 24, 8, length)
            for i, row in enumerate(rows):
                mem.put_bytes(BUF + ROW * i, row_bytes(row))
            outputs = (OUT,)
        elif kind == "upsert":
            upsert_model(mem, case)
            outputs = (OUT,)
        else:
            wrap_copy_model(rows, cap, case["src"], case["dst"], case["count"])
            for i, row in enumerate(rows):
                mem.put_bytes(BUF + ROW * i, row_bytes(row))
            outputs = ()
    if kind in ("remove", "upsert") and mem.read(OUT, 4) == 0:
        mem.put_bytes(OUT + 4, bytes(0x1C))           # the bytes leave the payload of a miss unwritten
    if kind == "range":
        mask_range(mem, case)
    if kind == "triple":
        for at in TRIPLE_OUT:
            if mem.read(OUT + at, 4) == 0:
                mem.put_bytes(OUT + at + 4, bytes(16))   # a miss copies unspecified stack bytes into its payload; only the tag counts
    return outputs, bytes(mem.heap[:USED]), log, seen


def compare(image, machine, case, kind):
    try:
        got = drive(machine, image, case, kind, True)
    except (Halt, EvidenceError) as exc:
        return "halt: %s" % exc, set()
    want = drive(None, image, case, kind, False)
    if got[0] != want[0]:
        return "return %r vs %r" % (got[0], want[0]), got[3]
    if kind in ("range", "collect", "tremove", "grow", "tpos") and got[2] != want[2]:
        return "log %r vs %r" % (got[2][:4], want[2][:4]), got[3]
    if got[1] != want[1]:
        at = next((i for i in range(min(len(got[1]), len(want[1]))) if got[1][i] != want[1][i]), 0)
        return "heap differs at %#x" % at, got[3]
    return None, got[3]


def route(case, kind):
    if kind == "grow":
        result = grow_model(case)
        if isinstance(result[0], str):
            return result[0]
        shape = "first-alloc" if case["cap"] == 0 else "realloc"
        return "%s-%s" % (shape, "min-cap" if result[0] in (4, 8, 1) and case["add"] + case["length"] < result[0] else "doubled-or-required")
    if kind == "tpos":
        root = instantiate(case["spec"], [0])
        events = []
        node, level, idx = locate(root, case["height"], case["key"])
        remove_at(node, level, idx, [], events)
        return "pos-" + "-".join(events[:3]) + ("-inner" if level else "-leaf")
    if kind == "tremove":
        if case["spec"] is None:
            return "empty-map"
        events = tremove_events(case)
        if not events:
            return "miss-h%d" % case["height"]
        return "-".join(events[:3]) if len(events) < 4 else "-".join(events[:2]) + "-chain"
    if kind == "collect":
        records = case["records"]
        stop = next((i for i, r in enumerate(records) if r[3] >= LIMIT), None)
        if case["fail_at"] and records and stop != 0:
            return "alloc-failure-or-ok"
        return "empty" if not records else ("limit-first" if stop == 0 else ("limit-later" if stop else "all-%d" % min(len(records), 9)))
    if kind == "range":
        count = max(case["end"] - case["start"], 0)
        if case["asset"] * 10000 > M64:
            return "mul-overflow" if count else "empty"
        if count > MAX_ELEMS:
            return "count-overflow"
        if case["fail"] and count:
            return "alloc-failure"
        return "empty" if count == 0 else ("wrap" if (case["start"] + case["asset"] * 10000 + count - 1) & M64 < case["asset"] * 10000 or case["start"] + case["asset"] * 10000 + count > M64 else "ok-%d" % min(count, 4))
    if kind == "triple":
        hits = 0
        for spec in case["maps"]:
            if spec["mode"] == "ring":
                found, index = search_model(spec["cap"], [r[0] for r in spec["slots"]], spec["head"], spec["length"], case["key"])
                hits += found == 0 and index < spec["length"]
            else:
                hits += any(item[0] == case["key"] for item in spec["items"])
        return "".join(spec["mode"][0] for spec in case["maps"]) + "-hits%d" % hits
    cap, length, head = case["cap"], case["length"], case["head"]
    wrapped = head + length > cap
    if kind == "search":
        found, _ = search_model(cap, [r[0] for r in case["slots"]], head, length, case["key"])
        return ("empty" if length == 0 else ("hit" if found == 0 else "miss")) + ("-wrapped" if wrapped else "-flat")
    if kind == "wrap":
        return "copy" if case["count"] and case["src"] != case["dst"] else "noop"
    found, index = search_model(cap, [r[0] for r in case["slots"]], head, length, case["key"])
    if kind == "upsert":
        if not found:
            return "replace" + ("-wrapped" if wrapped else "-flat")
        if length == cap:
            return "grow"
        return ("insert-tail-shift" if length - index < index else "insert-head-shift") + ("-wrapped" if wrapped else "-flat")
    if found:
        return "miss"
    tail = length - 1 - index
    return ("tail-shift" if tail < index else "head-shift") + ("-wrapped" if wrapped else "-flat")


def function_rows(image, start):
    return decode_range(image, start, image.exact_fde(start)[1])


def code_bytes(image, row):
    at = image.offset(row.va)
    return bytes(image.blob[at:at + row.size])


def in_scope(va):
    for start, ranges in SCOPE.items():
        if start <= va < start + 0x490:
            return any(low <= va < high for low, high in ranges)
    return True


def mutant_list(image):
    """Single-byte mutations: every condition flip plus immediate and displacement changes at a fixed stride."""
    found = []
    for start, _ in FUNCTIONS:
        users = USERS[start]
        for index, row in enumerate(function_rows(image, start)):
            if not in_scope(row.va) or row.op in ("int3", "nop"):
                continue
            raw = code_bytes(image, row)
            if row.op == "jcc":
                at = 0 if raw[0] != 0x0F else 1
                found.append((row.va, at, raw[at] ^ 1, "condition-flip", users))
                continue
            if row.imm_at is not None and row.op not in ("push", "pop"):
                found.append((row.va, row.imm_at, raw[row.imm_at] ^ 1, "immediate-low-byte", users))
                continue
            if row.op in ("mov", "lea", "add", "cmp", "movx", "movzx", "sub"):
                for operand in (row.a, row.b):
                    if isinstance(operand, tuple) and operand and operand[0] == "m" and operand[1] is not None and 0x08 <= abs(operand[4]) < 0x7F:
                        spots = [i for i, v in enumerate(raw) if v == operand[4] & 0xFF]
                        if len(spots) == 1 and spots[0] != row.imm_at:
                            found.append((row.va, spots[0], raw[spots[0]] ^ 1, "displacement-low-byte", users))
                            break
    return found


def detect(image, case_sets, patch):
    machine = Machine(image, {patch[0] + patch[1]: patch[2]})
    machine.step_limit = MUTANT_STEPS
    for kind in patch[4]:
        for index, case in enumerate(case_sets[kind]):
            result, _ = compare(image, machine, case, kind)
            if result:
                return True, result.split(" ")[0], index
    return False, "", -1


HOLD = 150


def detect_targeted(image, holders, patch):
    machine = Machine(image, {patch[0] + patch[1]: patch[2]})
    machine.step_limit = MUTANT_STEPS
    count = 0
    for kind in patch[4]:
        for index, case in enumerate(holders.get((patch[0], kind), [])):
            count += 1
            result, _ = compare(image, machine, case, kind)
            if result:
                return True, result.split(" ")[0], index, count
    return False, "", -1, count


# =============================================================================================
# Tree representation: remove-by-key front end 0x51d8900, predecessor swap 0x4d33ab0, leaf removal with rebalancing 0x4d19d30 and its three helpers
# =============================================================================================
GOT_MEMCPY, FAKE_MEMCPY = 0x64DF508, 0x7FFF00B0
GOT_PANIC_A, GOT_PANIC_B, GOT_PANIC_C = 0x64DF730, 0x64DF6B8, 0x64DF830
FAKE_PANIC_A, FAKE_PANIC_B, FAKE_PANIC_C = 0x7FFF00C0, 0x7FFF00D0, 0x7FFF00E0
TBASE = HEAP_BASE + 0x8000      # first node of the generated tree, nodes are NODE bytes apart
TUSED = 0x50000
MIN_LEN, CAPACITY = 5, 11
LEAF_SIZE, INNER_SIZE = 0x118, 0x178


class Nd:
    """Model node: keys and values in order, child nodes for an inner node, and the back links the bytes keep (parent address and index)."""

    def __init__(self, addr, keys, vals, kids):
        self.addr, self.keys, self.vals, self.kids = addr, keys, vals, kids
        self.parent, self.pidx = None, 0

    def relink(self, start=0):
        for i in range(start, len(self.kids)):
            self.kids[i].parent, self.kids[i].pidx = self, i


def instantiate(spec, counter):
    """Nested spec (keys, values, kid specs) to model nodes; addresses follow the pre-order position."""
    keys, vals, kids = spec
    node = Nd(TBASE + 2 * NODE * counter[0] + 0x10 * (counter[0] * 5 % 7), list(keys), list(vals), [])
    counter[0] += 1
    node.kids = [instantiate(kid, counter) for kid in kids]
    node.relink()
    return node


def build_nodes(mem, node):
    mem.put_bytes(node.addr, bytes(NODE))
    for i, (key, val) in enumerate(zip(node.keys, node.vals)):
        mem.put_bytes(node.addr + 16 * i, row_bytes(val))
        mem.write(node.addr + 0xB8 + 8 * i, 8, key)
    mem.write(node.addr + 0x112, 2, len(node.keys))
    mem.write(node.addr + 0xB0, 8, node.parent.addr if node.parent else 0)
    mem.write(node.addr + 0x110, 2, node.pidx)
    for i, kid in enumerate(node.kids):
        mem.write(node.addr + 0x118 + 8 * i, 8, kid.addr)
        build_nodes(mem, kid)


def gen_shape(rnd, height, root, low=False):
    if root:
        count = rnd.choice([1, 1, 2, 3, 5, 8, 11]) if height else rnd.choice([0, 1, 2, 4, 5, 6, 9, 10, 11])
    elif low:
        count = rnd.choice([1, 2, 3, 4, 4, 5, 5, 6, 7, 8, 9, 10, 11])      # underfull nodes: the repair arithmetic is generic in the missing count
    else:
        count = rnd.choice([5, 5, 5, 5, 5, 5, 6, 6, 6, 7, 7, 8, 9, 10, 11])
    return [count, [gen_shape(rnd, height - 1, False, low) for _ in range(count + 1)] if height else []]


def total_keys(shape):
    return shape[0] + sum(total_keys(kid) for kid in shape[1])


def fill_spec(shape, source, inner):
    count, kids = shape
    if not kids:
        return ([next(source) for _ in range(count)], [], [])
    keys, subs = [], []
    for i in range(count):
        subs.append(fill_spec(kids[i], source, inner))
        keys.append(next(source))
        inner.append(keys[-1])
    subs.append(fill_spec(kids[count], source, inner))
    return (keys, [None] * count, subs)


def give_values(spec, rnd):
    keys, _, kids = spec
    return (keys, [(rnd.getrandbits(64), rnd.getrandbits(64)) for _ in keys], [give_values(kid, rnd) for kid in kids])


def make_tremove(rnd, number):
    case = make_tremove_shape(rnd, number)
    case["fill"] = rnd.choice([0x00, 0x00, 0xA5, 0xFF, 0x11])       # byte the unused stack starts with: a read of an unwritten slot must not matter
    return case


def make_tremove_shape(rnd, number):
    if number % 41 == 0:
        return dict(spec=None, height=0, key=rnd.getrandbits(64))                 # empty map: the root pointer is null
    if number % 11 == 5:
        return make_deep(rnd, number // 11)
    if number % 7 == 2:
        return make_ancestor(rnd) if number % 3 else make_ancestor3(rnd)
    height = rnd.choice([0, 0, 1, 1, 1, 2, 2, 2])
    low = number % 4 == 3
    shape = gen_shape(rnd, height, True, low)
    total = total_keys(shape)
    base = rnd.choice([0, 1, 1 << 32, 1 << 63, M64 - 4 * total - 40])
    universe = sorted(rnd.sample(range(4 * total + 24), total))
    inner = []
    spec = give_values(fill_spec(shape, iter([base + u for u in universe]), inner), rnd)
    keys = [base + u for u in universe]
    pick = rnd.random()
    if keys and pick < 0.4 and inner:
        key = rnd.choice(inner)
    elif keys and pick < 0.8:
        key = rnd.choice(keys)
    else:
        key = rnd.choice([base + rnd.randrange(4 * total + 24), max(base - 1, 0), min(base + 4 * total + 30, M64), rnd.getrandbits(64)])
    return dict(spec=spec, height=height, key=key, total=total, underfull=low)


def make_ancestor(rnd):
    """Height-2 tree whose target leaf merges with its sibling and leaves an underfull parent, so the ancestor repair steals `5 - length` entries or merges."""
    root_len = rnd.choice([1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11])
    target = rnd.randrange(root_len + 1)
    parts = []
    for i in range(root_len + 1):
        if i == target:
            count = rnd.choice([1, 2, 3, 4, 5, 5, 6])
        elif abs(i - target) == 1 and (i < target or target == 0):
            count = rnd.choice([4, 5, 6, 7, 8, 9, 10, 11])         # the sibling the repair picks
        else:
            count = rnd.choice([5, 6, 8, 11])
        leaves = []
        for j in range(count + 1):
            leaves.append([rnd.choice([5, 5, 6, 7]), []])
        parts.append([count, leaves])
    tleaves = parts[target][1]
    j = rnd.randrange(len(tleaves))
    tleaves[j][0] = 5                                              # the leaf that loses an entry
    sib = j - 1 if j else 1
    if sib < len(tleaves):
        tleaves[sib][0] = rnd.choice([5, 5, 6, 7])
    shape = [root_len, parts]
    total = total_keys(shape)
    base = rnd.choice([0, 1 << 20])
    inner = []
    spec = give_values(fill_spec(shape, iter([base + 3 * i for i in range(total)]), inner), rnd)
    node = instantiate(spec, [0])
    leaf = node.kids[target].kids[j]
    key = rnd.choice(leaf.keys) if rnd.random() < 0.85 else rnd.choice(inner)
    return dict(spec=spec, height=2, key=key, total=total, underfull=True)


def make_ancestor3(rnd):
    """Height-3 tree: the target leaf merges with a sibling, and the repair walks up two levels (parent with a sibling, then the grandparent), so inner nodes of every
    length around the minimum are repaired by steals of every count and by merges."""
    def node(level, count=None):
        if level == 0:
            return [count if count is not None else rnd.choice([5, 5, 6, 7]), []]
        count = count if count is not None else rnd.choice([4, 5, 5, 6, 6, 7])
        return [count, [node(level - 1) for _ in range(count + 1)]]

    root_len = rnd.choice([1, 1, 2, 3])
    a = rnd.randrange(root_len + 1)
    shape = [root_len, [node(2) for _ in range(root_len + 1)]]
    mid = shape[1][a]
    b = rnd.randrange(len(mid[1]))
    mid[1][b] = node(1, rnd.choice([3, 4, 5, 6, 6, 7, 8, 11]))
    if rnd.random() < 0.5:
        mid[1][b][1] = [node(0, 5 if i == 0 else None) for i in range(mid[1][b][0] + 1)]
    parent = mid[1][b]
    c = rnd.randrange(len(parent[1]))
    parent[1][c][0] = 5
    sib = c - 1 if c else 1
    if sib < len(parent[1]):
        parent[1][sib][0] = rnd.choice([4, 5, 5, 6])
    nb = b - 1 if b else 1                                          # the sibling of the middle node
    if nb < len(mid[1]) and rnd.random() < 0.7:
        mid[1][nb] = node(1, rnd.choice([3, 4, 5, 5, 6, 6, 7, 11]))
    if rnd.random() < 0.5:
        mid[0] = len(mid[1]) - 1                                    # keep the counts consistent
    total = total_keys(shape)
    base = rnd.choice([0, 1 << 20])
    inner = []
    spec = give_values(fill_spec(shape, iter([base + 3 * i for i in range(total)]), inner), rnd)
    node_obj = instantiate(spec, [0])
    leaf = node_obj.kids[a].kids[b].kids[c]
    key = rnd.choice(leaf.keys) if rnd.random() < 0.85 else rnd.choice(inner)
    return dict(spec=spec, height=3, key=key, total=total, underfull=True)


def make_tremove_a3(rnd, number):
    case = make_ancestor3(rnd)
    case["fill"] = rnd.choice([0x00, 0xA5, 0xFF])
    return case


def make_deep(rnd, index):
    """Tall skinny tree: a root with one separator whose two subtrees are chains of empty inner nodes ending in a leaf (reaches the unrolled descents)."""
    height = 3 + index % 15
    left, right = rnd.randint(6, 11), rnd.randint(6, 11)
    base = rnd.choice([0, 1 << 40])
    keys = [base + 3 * i for i in range(left + right + 1)]

    def leaf(ks):
        return (ks, [(rnd.getrandbits(64), rnd.getrandbits(64)) for _ in ks], [])

    def chain(node, levels):
        for _ in range(levels):
            node = ([], [], [node])
        return node

    spec = ([keys[left]], [(rnd.getrandbits(64), rnd.getrandbits(64))], [chain(leaf(keys[:left]), height - 1), chain(leaf(keys[left + 1:]), height - 1)])
    key = keys[left] if index % 4 != 3 else rnd.choice([keys[0], keys[left - 1], keys[-1], keys[left + 1], keys[1] + 1])
    return dict(spec=spec, height=height, key=key, total=len(keys), underfull=True)


def build_tremove(mem, case):
    mem.reset(TUSED)
    mem.write(KEYCELL, 8, case["key"])
    mem.put_bytes(OUT, bytes([0xCC]) * 0x20)
    mem.write(DQ, 8, TREE_NICHE)
    if case["spec"] is None:
        mem.write(DQ + 8, 8, 0)
        mem.write(DQ + 16, 8, 0)
        mem.write(DQ + 24, 8, 0)
        return
    root = instantiate(case["spec"], [0])
    build_nodes(mem, root)
    mem.write(DQ + 8, 8, root.addr)
    mem.write(DQ + 16, 8, case["height"])
    mem.write(DQ + 24, 8, case["total"])


def read_view(mem, addr, height, root=True):
    """Whole reachable tree as nested tuples: address, back links, keys, values, children; stale bytes past the length are ignored."""
    length = mem.read(addr + 0x112, 2)
    if length > CAPACITY:
        raise EvidenceError("node length %d" % length)
    keys = tuple(mem.read(addr + 0xB8 + 8 * i, 8) for i in range(length))
    vals = tuple((mem.read(addr + 16 * i, 8), mem.read(addr + 16 * i + 8, 8)) for i in range(length))
    kids = ()
    if height:
        kids = tuple(read_view(mem, mem.read(addr + 0x118 + 8 * i, 8), height - 1, False) for i in range(length + 1))
    return (addr, mem.read(addr + 0xB0, 8), 0 if root else mem.read(addr + 0x110, 2), keys, vals, kids)


def model_view(node, height, root=True):
    kids = tuple(model_view(kid, height - 1, False) for kid in node.kids)
    return (node.addr, node.parent.addr if node.parent else 0, 0 if root else node.pidx, tuple(node.keys), tuple(node.vals), kids)


def merge_children(parent, at, log):
    """Left child, separator at `at` and right child become the left child; the right node is released, the parent loses one separator."""
    left, right = parent.kids[at], parent.kids[at + 1]
    left.keys += [parent.keys.pop(at)] + right.keys
    left.vals += [parent.vals.pop(at)] + right.vals
    left.kids += right.kids
    left.relink()
    del parent.kids[at + 1]
    parent.relink(at + 1)
    log.append(("dealloc", right.addr, INNER_SIZE if right.kids or left.kids else LEAF_SIZE))
    return left


def steal_left(parent, at, count):
    """Move `count` entries from the left sibling (child `at`) through the separator into the child on its right."""
    left, node = parent.kids[at], parent.kids[at + 1]
    keep = len(left.keys) - count
    moved_keys, moved_vals = left.keys[keep + 1:], left.vals[keep + 1:]
    sep = (left.keys[keep], left.vals[keep])
    node.keys[:0] = moved_keys + [parent.keys[at]]
    node.vals[:0] = moved_vals + [parent.vals[at]]
    parent.keys[at], parent.vals[at] = sep
    del left.keys[keep:]
    del left.vals[keep:]
    if left.kids:
        node.kids[:0] = left.kids[keep + 1:]
        del left.kids[keep + 1:]
        node.relink()
        left.relink()


def steal_right(parent, at, count):
    """Move `count` entries from the right sibling (child `at` + 1) through the separator into child `at`."""
    node, right = parent.kids[at], parent.kids[at + 1]
    node.keys += [parent.keys[at]] + right.keys[:count - 1]
    node.vals += [parent.vals[at]] + right.vals[:count - 1]
    parent.keys[at], parent.vals[at] = right.keys[count - 1], right.vals[count - 1]
    del right.keys[:count]
    del right.vals[:count]
    if right.kids:
        node.kids += right.kids[:count]
        del right.kids[:count]
        node.relink()
        right.relink()


def rebalance(node, count, log, events, tracked=None):
    """One step of the underfull repair: merge with or steal from the sibling the parent index picks; returns (node that now holds the entries, merged)."""
    parent = node.parent
    at = node.pidx
    if at:
        left = parent.kids[at - 1]
        if len(left.keys) + len(node.keys) + 1 <= CAPACITY:
            events.append("merge-left")
            return merge_children(parent, at - 1, log), True
        events.append("steal-left")
        steal_left(parent, at - 1, count)
        return node, False
    if not parent.keys:
        raise Crash("empty-internal-node")
    right = parent.kids[1]
    if len(node.keys) + len(right.keys) + 1 <= CAPACITY:
        events.append("merge-right")
        return merge_children(parent, 0, log), True
    events.append("steal-right")
    steal_right(parent, 0, count)
    return node, False


def remove_leaf_kv(leaf, idx, log, events):
    """Model of 0x4d19d30: remove entry idx of a leaf, repair the underfull leaf and its ancestors; returns (key, value, position, root emptied)."""
    key, val = leaf.keys.pop(idx), leaf.vals.pop(idx)
    pos = (leaf, idx)
    emptied = False
    if len(leaf.keys) >= MIN_LEN or leaf.parent is None:
        return key, val, pos, emptied
    at = leaf.pidx
    if at:
        left_len = len(leaf.parent.kids[at - 1].keys)
        merged_node, merged = rebalance(leaf, 1, log, events)
        pos = (merged_node, left_len + 1 + idx) if merged else (leaf, idx + 1)
    else:
        merged_node, merged = rebalance(leaf, 1, log, events)
        pos = (merged_node, idx)
    node = pos[0]
    parent = node.parent
    if parent is not None and len(parent.keys) < MIN_LEN:
        node = parent
        while True:
            if node.parent is None:
                emptied = not node.keys
                break
            node, merged = rebalance(node, MIN_LEN - len(node.keys), log, events)
            if not merged:
                break
            node = node.parent
            if len(node.keys) >= MIN_LEN:
                break
    return key, val, pos, emptied


def locate(root, height, key):
    """Linear key scan per node, as 0x51d8900 does: (node, level, index) of the entry, or None."""
    node, level = root, height
    while True:
        idx = 0
        while idx < len(node.keys) and key > node.keys[idx]:
            idx += 1
        if idx < len(node.keys) and node.keys[idx] == key:
            return node, level, idx
        if level == 0:
            return None
        node, level = node.kids[idx], level - 1


def remove_at(node, level, idx, log, events):
    """Model of 0x4d33ab0: returns ((key, value) pair removed, ...) as (key, (old key, old value), final position, root emptied)."""
    if level == 0:
        key, val, pos, emptied = remove_leaf_kv(node, idx, log, events)
        return key, (key, val), (pos[0], 0, pos[1]), emptied
    leaf = node.kids[idx]
    for _ in range(level - 1):
        leaf = leaf.kids[-1]
    okey, oval, pos, emptied = remove_leaf_kv(leaf, len(leaf.keys) - 1, log, events)
    at, slot = pos
    while slot >= len(at.keys):
        at, slot = at.parent, at.pidx
    old = (at.keys[slot], at.vals[slot])
    at.keys[slot], at.vals[slot] = okey, oval
    if not at.kids:
        return old[0], old, (at, 0, slot + 1), emptied
    nxt = at.kids[slot + 1]
    while nxt.kids:
        nxt = nxt.kids[0]
    return old[0], old, (nxt, 0, 0), emptied


def tremove_model(root, height, length, key, log, events):
    """Model of 0x51d8900: returns (option, root, height, length)."""
    if root is None:
        return None, root, height, length
    found = locate(root, height, key)
    if found is None:
        return None, root, height, length
    node, level, idx = found
    events.append("leaf" if level == 0 else "inner")
    _, val, _, emptied = remove_at(node, level, idx, log, events)
    val = val[1]
    if emptied:
        events.append("pop-root")
        old = root
        root = old.kids[0]
        root.parent = None
        height -= 1
        log.append(("dealloc", old.addr, INNER_SIZE))
    return val, root, height, length - 1


def tremove_events(case):
    log, events = [], []
    root = instantiate(case["spec"], [0]) if case["spec"] else None
    tremove_model(root, case["height"], case.get("total", 0), case["key"], log, events)
    return events


def install_tree(machine, log):
    mem = machine.memory
    mem.statics[GOT_MEMMOVE], mem.statics[GOT_MEMCPY], mem.statics[GOT_DEALLOC] = FAKE_MEMMOVE, FAKE_MEMCPY, FAKE_DEALLOC
    for got, fake in ((GOT_PANIC_A, FAKE_PANIC_A), (GOT_PANIC_B, FAKE_PANIC_B), (GOT_PANIC_C, FAKE_PANIC_C)):
        mem.statics[got] = fake

    def h_copy(m):
        if m.regs[RDX] > 0x1000:
            raise EvidenceError("copy longer than a node")
        mem.put_bytes(m.regs[RDI], mem.bytes_at(m.regs[RSI], m.regs[RDX]))

    def h_dealloc(m):
        log.append(("dealloc", m.regs[RDI], m.regs[RSI]))

    def panic(name):
        def hook(m):
            raise Crash(name)
        return hook

    machine.slots[FAKE_MEMMOVE] = machine.slots[FAKE_MEMCPY] = h_copy
    machine.slots[FAKE_DEALLOC] = h_dealloc
    machine.slots[FAKE_PANIC_A], machine.slots[FAKE_PANIC_B], machine.slots[FAKE_PANIC_C] = panic("panic-a"), panic("panic-b"), panic("panic-c")
    machine.real = frozenset(TREE_FUNCS)


def tree_state(mem, root, height, length, outputs):
    tag = mem.read(OUT, 4)
    payload = (mem.read(OUT + 4, 8), mem.read(OUT + 12, 8)) if tag == 1 else ()
    view = read_view(mem, root, height) if root else None
    return repr((outputs, tag, payload, root, height, length, view)).encode()


def drive_tree(machine, image, case, real):
    log = []
    if real:
        mem = machine.memory
        build_tremove(mem, case)
        mem.stack[:] = bytes([case.get("fill", STACK_MARK)]) * STACK_SIZE
        install_tree(machine, log)
        machine.seen = set()
        try:
            outputs = (machine.run(TREM_FN, {RDI: OUT, RSI: DQ + 8, RDX: KEYCELL}),)
        except Crash as exc:
            outputs = (exc.kind, exc.payload)
        root, height, length = (mem.read(DQ + 8 * i, 8) for i in (1, 2, 3))
        return outputs, tree_state(mem, root, height, length, outputs), log, set(machine.seen)
    mem = Memory(image)
    build_tremove(mem, case)
    root = instantiate(case["spec"], [0]) if case["spec"] else None
    try:
        option, root, height, length = tremove_model(root, case["height"], case.get("total", 0), case["key"], log, [])
    except Crash as exc:
        return (exc.kind, exc.payload), b"crash", log, set()
    mem.write(OUT, 4, 0 if option is None else 1)
    if option is not None:
        mem.put_bytes(OUT + 4, row_bytes(option))
    outputs = (OUT,)
    state = repr((outputs, 0 if option is None else 1, tuple(option) if option else (), root.addr if root else 0, height, length,
                  model_view(root, height) if root else None)).encode()
    return outputs, state, log, set()


# =============================================================================================
# Vector growth 0x5963a10 (grow-amortized) with the exact-size reserve 0x5963650, driven with every element size class and alignment
# =============================================================================================
GROW_VEC = HEAP_BASE + 0x1000      # RawVec: capacity word, buffer pointer
GROW_PTR, GROW_NEW = HEAP_BASE + 0x7000, HEAP_BASE + 0x7800


def grow_block(size):
    """Block address the allocator contract hands out: every third size gets one whose low 32 bits are zero."""
    return 0x700000000 if size % 3 == 0 else GROW_NEW
GROW_MAX_ALLOC = 1 << 20           # the allocator contract refuses larger blocks
ISIZE_TOP = 1 << 63
CAP_WORDS = [0, 1, 2, 3, 4, 5, 7, 8, 9, 16, 100, 1000, 1 << 20, 1 << 32, 1 << 40, 1 << 55, 1 << 60, (1 << 62) + 5]
ADD_WORDS = [0, 1, 2, 3, 5, 100, 4096, 1 << 20, 1 << 40, (1 << 63) - 9, (1 << 63) - 8, (1 << 63) - 7, (1 << 63) - 1, 1 << 63, M64 - 3, M64]
ELEM_WORDS = [0, 1, 1, 2, 3, 4, 8, 8, 16, 24, 60, 1000, 1024, 1025, 1026, 4096, 1 << 20, 1 << 40]
ALIGN_WORDS = [1, 2, 4, 8, 8, 8, 16, 32, 64, 4096]


def make_grow(rnd, number):
    cap = rnd.choice(CAP_WORDS)
    length = cap if number % 3 else rnd.randint(0, min(cap, 50))
    elem = rnd.choice(ELEM_WORDS)
    align = rnd.choice(ALIGN_WORDS)
    add = rnd.choice(ADD_WORDS) if number % 2 else rnd.choice([0, 1, 1, 2, 7])
    if number % 3 == 0:
        elem, align = rnd.choice([1, 1, 2, 4, 8]), rnd.choice([1, 2, 4, 8])
        add = max(((ISIZE_TOP - align) // elem + rnd.choice([-1, 0, 1, 2])) & M64, 0)      # new size lands next to the isize::MAX - align limit
        cap = length = 0
    if number % 17 == 0:
        elem, align = rnd.choice([1, 2, 1024, 1025]), rnd.choice([1, 8, 16, 32])         # the minimum-capacity classes
        cap = length = rnd.choice([0, 0, 1, 2, 3])
        add = rnd.choice([0, 1, 2])
    return dict(cap=cap, ptr=GROW_PTR if cap else align, length=length, add=add, align=align, elem=elem)


def grow_model(case):
    """Contract-level model: returns (new capacity, pointer, call log) or a crash tuple."""
    cap, length, add, align, elem = case["cap"], case["length"], case["add"], case["align"], case["elem"]
    if elem == 0 or length + add > M64:
        return ("capacity-overflow", (), [])
    wanted = max((2 * cap) & M64, length + add)
    floor = 8 if elem == 1 else (4 if elem <= 1024 else 1)
    new_cap = max(wanted, floor)
    size = new_cap * elem
    if size > M64 or size > ISIZE_TOP - align:
        return ("capacity-overflow", (), [])
    use_plain = align <= 16 and align <= size
    shift = (align & -align).bit_length() - 1
    log = []
    if cap == 0:
        if size == 0:
            return new_cap, align, log
        log.append(("alloc", size) if use_plain or shift == 0 else ("alloc-aligned", size, shift))
    else:
        log.append(("realloc", size) if use_plain or shift == 0 else ("realloc-aligned", size, shift))
    if size > GROW_MAX_ALLOC:
        return ("alloc-error", (align, size), log)
    return new_cap, grow_block(size), log


def drive_grow(machine, image, case, real):
    if real:
        mem, log = machine.memory, []
        mem.reset(USED)
        mem.write(GROW_VEC, 8, case["cap"])
        mem.write(GROW_VEC + 8, 8, case["ptr"])

        def h_alloc(m):
            log.append(("alloc", m.regs[RDI]))
            m.regs[RAX] = grow_block(m.regs[RDI]) if m.regs[RDI] <= GROW_MAX_ALLOC else 0

        def h_alloc_al(m):
            log.append(("alloc-aligned", m.regs[RDI], m.regs[RSI]))
            m.regs[RAX] = grow_block(m.regs[RDI]) if m.regs[RDI] <= GROW_MAX_ALLOC else 0

        def h_realloc(m):
            log.append(("realloc", m.regs[RSI]))
            m.regs[RAX] = grow_block(m.regs[RSI]) if m.regs[RSI] <= GROW_MAX_ALLOC else 0

        def h_realloc_al(m):
            log.append(("realloc-aligned", m.regs[RSI], m.regs[RDX]))
            m.regs[RAX] = grow_block(m.regs[RSI]) if m.regs[RSI] <= GROW_MAX_ALLOC else 0

        def h_error(m):
            raise Crash("alloc-error" if m.regs[RDI] else "capacity-overflow", (m.regs[RDI], m.regs[RSI]) if m.regs[RDI] else ())

        for got, fake, hook in ((GOT_ALLOC, FAKE_ALLOC, h_alloc), (GOT_ALLOC_AL, FAKE_ALLOC_AL, h_alloc_al), (GOT_REALLOC, FAKE_REALLOC, h_realloc),
                                (GOT_REALLOC_AL, FAKE_REALLOC_AL, h_realloc_al), (GOT_ALLOC_ERR, FAKE_ALLOC_ERR, h_error)):
            mem.statics[got] = fake
            machine.slots[fake] = hook
        machine.real = frozenset([GROW_AMORT_FN, RESERVE_EXACT_FN])
        machine.seen = set()
        try:
            machine.run(GROW_AMORT_FN, {RDI: GROW_VEC, RSI: case["length"], RDX: case["add"], RCX: case["align"], R8: case["elem"]})
            outputs = (mem.read(GROW_VEC, 8), mem.read(GROW_VEC + 8, 8))
        except Crash as exc:
            outputs = (exc.kind, exc.payload)
        return outputs, repr(outputs).encode(), log, set(machine.seen)
    result = grow_model(case)
    outputs = (result[0], result[1])
    return outputs, repr(outputs).encode(), result[2], set()


# Direct drive of 0x4d33ab0: the removed pair, the position handle it returns and the emptied-root flag
PIN, POUT, FLAGCELL = HEAP_BASE + 0x1300, HEAP_BASE + 0x1340, HEAP_BASE + 0x1380


def make_tpos(rnd, number):
    if number % 24 == 0:
        case = make_deep(rnd, number // 24)
        if number % 48 or case["key"] not in (case["spec"][0][0], case["spec"][0][0] - 3):
            case["key"] = case["spec"][0][0]                          # always an entry that exists: the separator, which takes the predecessor path
        case["fill"] = rnd.choice([0x00, 0xA5, 0xFF])
        return case
    for _ in range(40):
        case = make_tremove(rnd, number + 1 + 11 * _)
        if case["spec"] is None:
            continue
        root = instantiate(case["spec"], [0])
        entries = []

        def walk(node):
            entries.extend(node.keys)
            for kid in node.kids:
                walk(kid)

        walk(root)
        if entries:
            if locate(root, case["height"], case["key"]) is None:
                case["key"] = rnd.choice(entries)
            return case
    raise EvidenceError("no non-empty tree generated")


def drive_pos(machine, image, case, real):
    log, events = [], []
    root = instantiate(case["spec"], [0])
    node, level, idx = locate(root, case["height"], case["key"])
    if real:
        mem = machine.memory
        build_tremove(mem, case)
        mem.stack[:] = bytes([case.get("fill", STACK_MARK)]) * STACK_SIZE
        mem.put_bytes(PIN, b"".join(w.to_bytes(8, "little") for w in (node.addr, level, idx, 0)))
        mem.put_bytes(POUT, bytes([0xCC]) * 0x30)
        mem.write(FLAGCELL, 1, 0)
        install_tree(machine, log)
        machine.seen = set()
        try:
            outputs = (machine.run(PRED_FN, {RDI: POUT, RSI: PIN, RDX: FLAGCELL}),)
        except Crash as exc:
            outputs = (exc.kind, exc.payload)
        words = tuple(mem.read(POUT + 8 * i, 8) for i in range(6))
        state = (outputs, words, mem.read(FLAGCELL, 1), read_view(mem, root.addr, case["height"]))
        return outputs, repr(state).encode(), log, set(machine.seen)
    key, old, pos, emptied = remove_at(node, level, idx, log, events)
    words = (old[0],) + tuple(old[1]) + (pos[0].addr, pos[1], pos[2])
    state = ((POUT,), words, int(emptied), model_view(root, case["height"]))
    return (POUT,), repr(state).encode(), log, set()


def main(argv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument("--out", required=True)
    args = parser.parse_args(argv)
    out = pathlib.Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    image = load_image()
    measure = evidence(image, out)
    (out / "measure.json").write_text(json.dumps(measure, indent=1, sort_keys=True) + "\n")
    return 0


_JOB = None


def _mutant_job(number):
    """One negative control: replay a sample of the cases, then the cases that executed the changed instruction; a pure function of the mutant."""
    image, case_sets, holders, seen_all = _JOB
    patch = mutant_list(image)[number] if _MUTANTS is None else _MUTANTS[number]
    # a byte change inside an instruction no case executes cannot alter any run, so the cases are not replayed for it
    hit, reason, index = detect(image, case_sets, patch) if patch[0] in seen_all else (False, "", -1)
    stage, count = 1, 0
    if not hit and patch[0] in seen_all and patch[0] not in EQUIVALENT:
        hit, reason, index, count = detect_targeted(image, holders, patch)
        stage = 2
    return hit, reason, index, count, stage


_MUTANTS = None


def evidence(image, out):
    total, routes, sample = 0, {}, []
    global _MUTANTS
    mutants = _MUTANTS = mutant_list(image)
    wanted = {patch[0] for patch in mutants}
    case_sets = {kind: [] for kind in CASES}
    holders = {}
    seen_all = set()
    for offset, kind in enumerate(CASES):
        rnd = random.Random(115 + offset)
        machine = Machine(image)
        for number in range(CASES[kind]):
            case = make_case(rnd, number, kind)
            result, seen = compare(image, machine, case, kind)
            if result:
                raise SystemExit("model disagrees with the bytes: %s case %d: %s" % (kind, number, result))
            seen_all |= seen
            for va in seen & wanted:
                held = holders.setdefault((va, kind), [])
                if len(held) < HOLD and (len(held) < 8 or number % 5 == 0):
                    held.append(case)
            total += 1
            if number % (CASES[kind] // DETECT[kind]) == 0 and len(case_sets[kind]) < DETECT[kind]:
                case_sets[kind].append(case)
            name = route(case, kind)
            routes[(kind, name)] = routes.get((kind, name), 0) + 1
            if number < 30:
                run = drive(None, image, case, kind, False)
                sample.append((kind, number, name, hashlib.sha256(run[1]).hexdigest()[:16]))
    with open(out / "body.tsv", "w") as body, open(out / "coverage.tsv", "w") as cover, open(out / "branches.tsv", "w") as branches:
        body.write("function\tva\tsize\tbytes\top\n")
        cover.write("function\tstart\tend\tinstructions\texecuted\n")
        branches.write("function\tva\tcc\ttarget\ttaken_side_executed\tfall_through_executed\n")
        for start, name in FUNCTIONS:
            rows = function_rows(image, start)
            for row in rows:
                body.write("%s\t%#x\t%d\t%s\t%s\n" % (name, row.va, row.size, code_bytes(image, row).hex(), row.op))
                if row.op == "jcc":
                    branches.write("%s\t%#x\t%d\t%#x\t%d\t%d\n" % (name, row.va, row.cc, row.target, row.target in seen_all, row.next in seen_all))
            cover.write("%s\t%#x\t%#x\t%d\t%d\n" % (name, start, image.exact_fde(start)[1], len(rows), sum(1 for r in rows if r.va in seen_all)))
    with open(out / "routes.tsv", "w") as table:
        table.write("case_set\troute\tcases\n")
        for key in sorted(routes):
            table.write("%s\t%s\t%d\n" % (key + (routes[key],)))
    with open(out / "cases-sample.tsv", "w") as table:
        table.write("case_set\tcase\troute\theap_digest\n")
        for row in sample:
            table.write("%s\t%d\t%s\t%s\n" % row)
    with open(out / "layout.tsv", "w") as table:
        table.write("object\toffset\tsize\tmeaning\n")
        for row in LAYOUT:
            table.write("%s\t%#x\t%d\t%s\n" % row)
    detected, missed, tried = 0, [], {}
    global _JOB
    _JOB = (image, case_sets, holders, seen_all)
    try:
        import multiprocessing
        pool = multiprocessing.get_context("fork").Pool(4)
        results = pool.imap(_mutant_job, range(len(mutants)), chunksize=4)
    except (ImportError, ValueError, OSError):
        pool = None
        results = map(_mutant_job, range(len(mutants)))
    with open(out / "controls.tsv", "w") as controls:
        controls.write("va\tbyte\tnew\tkind\tusers\tdetected\treason\tcase\tstage\n")
        for patch, (hit, reason, index, count, stage) in zip(mutants, results):
            if stage == 2:
                tried[patch[0], patch[1]] = count
            controls.write("%#x\t%d\t%#x\t%s\t%s\t%d\t%s\t%d\t%d\n" % (patch[0], patch[1], patch[2], patch[3], "+".join(patch[4]), hit, reason, index, stage))
            if hit:
                detected += 1
            else:
                missed.append(patch)
    if pool is not None:
        pool.close()
        pool.join()
    with open(out / "equivalent-mutants.tsv", "w") as table:
        table.write("va\tbyte\tnew\tkind\treason\n")
        for patch in missed:
            table.write("%#x\t%d\t%#x\t%s\t%s\n" % (patch[0], patch[1], patch[2], patch[3], equivalent_reason(patch, seen_all, tried.get((patch[0], patch[1])))))
    summary = dict(binary_sha256=SHA256, functions={name: hex(start) for start, name in FUNCTIONS}, cases=CASES, detect_cases=DETECT,
                   ring_ranges=[[hex(a), hex(b)] for a, b in REMOVE_RING], routes={"%s/%s" % key: value for key, value in sorted(routes.items())})
    (out / "summary.json").write_text(json.dumps(summary, indent=1, sort_keys=True) + "\n")
    return dict(cases=total, negative_controls=len(mutants), negative_detected=detected, equivalent=len(missed))


LAYOUT = [
    ("deque handle", 0x0, 8, "capacity in records; 0x8000000000000000 marks the tree representation (not modeled)"),
    ("deque handle", 0x8, 8, "buffer pointer, records of 24 bytes"),
    ("deque handle", 0x10, 8, "head slot (physical index of logical element 0)"),
    ("deque handle", 0x18, 8, "length in records"),
    ("record", 0x0, 8, "u64 key, ordered unsigned"),
    ("record", 0x8, 16, "value words, returned by remove"),
    ("remove result", 0x0, 4, "tag: 0 = key absent (the rest is left unwritten), 1 = removed"),
    ("remove result", 0x4, 16, "the two value words of the removed record, unaligned"),
    ("search result", 0x0, 8, "rax: 0 = present, 1 = absent"),
    ("search result", 0x8, 8, "rdx: logical index of the key, or the insertion index when absent"),
]


RING_DOMAIN = "inside the ring representation the compared word is a capacity that never equals i64::MIN, so the changed constant is never reached"
EQUIVALENT = {
    0x57F6965: "length-1 second slice: entering the halving loop with n = 1 adds zero to the base and keeps it, so skipping it or not gives the same base and key",
    0x57F69D9: "length-1 first slice: entering the halving loop with n = 1 adds zero to the base and keeps it, so skipping it or not gives the same base and key",
    0x57F69B3: "empty handle: the jump lands one byte into the next instruction, which decodes as a 32-bit lea into rcx, a register that is dead before the early return",
    0x57F6A0D: "hit exit: the jump lands on the 32-bit form of mov rdx,rdi, equal for every index below 2^32 (indices are bounded by the length)",
    0x4DDC0A3: RING_DOMAIN,
    0x4DD617B: RING_DOMAIN + " (the length word is only used together with that test)",
    0x4DD6188: RING_DOMAIN + " (the length limit 0x20 only matters for the tree representation)",
    0x4DD62BB: RING_DOMAIN,
    0x4DD62E8: "a ring of 0x40 records or more is converted to the tree representation before the insert; every ring case here is shorter, so the limit 0x40 vs 0x41 is not separable",
    0x4DD658A: "dead panic: after a hit or an insert the index is below the length, the message length is never used",
    0x5362379: "the jump re-enters the loop head one byte late and executes mov esi,ebp instead of mov esi,r13d; this path has esi = 0 (set by xor at 0x536236b) and r13 = i64::MIN, whose low half is 0, so r13d = esi and the later mov r13d,esi restores the same value",
    0x5B7279D: "the jump skips xor ebx,ebx; one byte later it lands in a 32-bit load of the capacity word, equal to the 64-bit load for every capacity below 2^32, and the allocation contract refuses blocks above 0x1000 bytes",
    0x5B9ECC5: "grow-amortized is called with additional = 1 or 0 only when length == capacity; max(2 * cap, cap + 1, floor) equals max(2 * cap, cap, floor) for every capacity because the floor is at least 4 when cap = 0 and 2 * cap >= cap + 1 otherwise",
    0x51D896B: "the jump lands one byte late, on the 32-bit form of sub $1 from the remaining height; the carry flag and the value agree for every height below 2^32",
    0x51D8996: "the fourth word of the argument block passed to 0x4d33ab0 is never read there (it reads words 0, 1 and 2), and the misplaced store only overlaps the result block the callee overwrites",
    0x4D33C7A: "the compare is reached only through the branch taken when height & 7 != 0, so height 8 never arrives here; thresholds 8 and 9 give the same branch for every other height",
    0x4D19FEE: "the displacement 0x41 reads the spilled height shifted by one byte: the seven upper bytes of the height word (zero for any height below 256) and the low byte of the next spill; r15 = that word + 1 is at least 1, its only uses are spill slots and the test of r15 + 1 against 2 at 0x4d1a34f, which is never below 2 for either value, and the exit path reloads the height from the spill",
    0x4D1A342: "the 0x119 only reaches the release size when the test at 0x4d1a358 is taken, but that test sees (height + 1) + 1 with a height of at least 1, so it is never below 2; on the other path esi is rewritten at 0x4d1a3e8 or by the panic arm 0x4d1a4d6 before use",
    0x4D1A47A: "reached only when the remainder of (count & 3) is zero and the count is positive, so the count is a positive multiple of 4; the guard compares count - 1 (or count) against 3, true for 4, 8, ... either way",
    0x4D1A47E: "same entry condition as 0x4d1a47a: count - 1 is at least 3 and the threshold 2 gives the same branch",
    0x4CA165A: "the only caller (0x4d19eef) takes the merge only when left + right + 1 is below 12, so the assertion limit 12 vs 13 is never reached",
    0x4CA1888: "the height word in the context built at 0x4d19ea3 comes from the leaf the removal starts on (both callers of 0x4d19d30 sit in 0x4d33ab0 after the descent to a leaf, height 0), so the compared word is below 2 and the thresholds 2 and 3 give the same branch",
    0x4D19E90: "the jump lands one byte late, on the 32-bit form of the load of the leaf-edge index; the index of a root leaf is below 2^32",
    0x4C958BE: "the capacity assertion compares the new length (old length + stolen count) with 12; a repair only runs on a node of at most 4 entries and steals up to 5, so the new length never reaches 12",
    0x4C958ED: "the new length is stored one byte off; the only later read is the compare of that word with 3 in the edge-renumbering branch, and after a repair the length is exactly 5 so the outcome is unchanged",
    0x4C95935: "the value move is twice as long; it only copies stale value slots (the node holds at most 4 entries when the steal runs, so at most 8 slots from the start stay inside the 11 value slots)",
    0x4C95A2F: "one extra byte of the edge move lands in the first stale edge slot past the new edge count, which no later read observes",
    0x4C95A66: "mask on the new edge count 6 (length 5 + 1 after every repair); bit 0 of that count is clear, so the masks 3 and 2 agree",
    0x4C95A69: "the compared word is the new length, which is exactly 5 after every repair, so thresholds 3 and 2 give the same branch",
    0x4C95A9A: "mask on the new edge count 6, whose bit 0 is clear, so the masks 0x3c and 0x3d agree",
    0x4C9638E: "mirror of 0x4c958be in the steal-from-right helper: the new length never reaches 12",
    0x4C96407: "mirror of 0x4c95935 in the steal-from-right helper: only stale value slots are copied",
    0x4C964F9: "mirror of 0x4c95a2f in the steal-from-right helper: the extra byte lands in a stale edge slot",
    0x4C965AF: "mirror of 0x4c95a69 in the steal-from-right helper: the compared length is exactly 5 after every repair",
    0x57EEF72: "dead panic: the upsert only inserts at an index not above the length, the message length is never used",
}


def equivalent_reason(patch, executed, tried=None):
    if patch[0] in EQUIVALENT:
        return EQUIVALENT[patch[0]]
    if patch[0] not in executed:
        return "no case executes this instruction: it is reached only by a handle whose length does not exceed the capacity checks the generator keeps"
    return "OPEN after %d targeted cases: executed by the cases but no case separates the change" % (tried or 0)


if __name__ == "__main__":
    sys.exit(main())
