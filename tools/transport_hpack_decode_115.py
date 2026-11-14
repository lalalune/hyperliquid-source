#!/usr/bin/env python3
"""Reconstruct the HPACK decode path of node #115: decode_int 0x177b320, Huffman decode 0x179d5b0 and decode_string 0x177be90.

The pure models below (model_int, model_huffman, model_string) are compared on thousands of generated inputs with the real
instruction bytes, run in the offline x86-64 interpreter section of this file (Image, decode, Memory, Machine). The library
routines the code calls (BytesMut reserve/put_slice/split, freeze, panics, the log gate) are modelled as stubs. The binary is
never executed.

    python3 tools/transport_hpack_decode_115.py --out research/work-items/transport-hpack-decode-115
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
    if byte in (0xD3, 0xD2):
        reg, rm = modrm()
        if reg & 7 not in SHIFTS:
            raise EvidenceError("unsupported shift at %#x" % va)
        return finish(SHIFTS[reg & 7], rm, ("r", RCX), 1 if byte == 0xD2 else width)
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
        if count == 0:
            return b''
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
# Packet part: HPACK decode path of node #115 (decode_int, Huffman decode, decode_string).
# Everything below the interpreter core is specific to this packet.
# ---------------------------------------------------------------------------

import argparse
import json
import os

PACKET_NAME = "transport-hpack-decode-115"
TABLE_VA = 0x4884A0
TABLE_BYTES = 256 * 16 * 16
F_INT, F_GETU8, F_HUFF, F_STRING, F_FREEZE = 0x177B320, 0x17AB010, 0x179D5B0, 0x177BE90, 0x177E700
RANGES = {
    "decode_int": (0x177B320, 0x177B431),
    "get_u8": (0x17AB010, 0x17AB03A),
    "huffman_decode": (0x179D5B0, 0x179D75A),
    "decode_string": (0x177BE90, 0x177C2CB),
}
# GOT slots -> RELATIVE addend (library routine) the code calls through.
SLOTS = {0x64DFC90: 0x161D1F0, 0x64E0670: 0x161DA20, 0x64E08E8: 0x161D6B0, 0x64DF620: 0x1680CBF,
         0x64DF848: 0x1681E40, 0x64DF898: 0x161DC50, 0x64DF520: 0x1681DA0, 0x64DF760: 0x5CFFDC0}
LOG_FLAG_SLOT, LOG_FLAG_CELL = 0x64DF748, 0x64FEE60
ERR_UNDERFLOW, ERR_STRING_UNDERFLOW, ERR_HUFFMAN, ERR_OVERFLOW = 1, 2, 6, 0xB
USED = 0x80000
DATA = HEAP_BASE + 0x1000
S_AT, C_AT, DEC_AT, OUT_AT = HEAP_BASE + 0x100, HEAP_BASE + 0x200, HEAP_BASE + 0x300, HEAP_BASE + 0x400
BUF_MEM, BUMP_START = HEAP_BASE + 0x20000, HEAP_BASE + 0x30000
BUF_CAP0 = 64
COUNTS = {"int": 4200, "huffman": 4200, "string": 4200}
SAMPLE_LINES = {"int": 260, "huffman": 260, "string": 260}
MUTANT_CASES = 700


class Panic(Exception):
    pass


def read_table(image):
    at = image.offset(TABLE_VA)
    return bytes(image.blob[at:at + TABLE_BYTES])


def entry(table, state, nibble):
    at = (state * 16 + nibble) * 16
    return int.from_bytes(table[at:at + 8], "little"), table[at + 8], table[at + 9]


# ------------------------------- pure models --------------------------------

def model_int(data, pos, prefix, mut=None):
    """decode_int: (status, value-or-error-code, new position)."""
    n = len(data)
    if n <= pos:
        return ("err", ERR_UNDERFLOW, pos)
    mask = (~((0xFF << (prefix & 31)) & 0xFF)) & 0xFF
    if mut == "mask_wide":
        mask = (~((0xFF << (prefix & 31)) & 0xFFFF)) & 0xFFFF
    first = data[pos] & mask
    pos += 1
    if first != mask:
        return ("ok", first, pos)
    value = mask
    for index in range(4 if mut != "max3" else 3):
        if n <= pos:
            return ("err", ERR_UNDERFLOW, pos)
        byte = data[pos]
        pos += 1
        if index == 0:
            value = (byte & 0x7F) + mask
            if mut != "no_wrap":
                value &= 0xFF
        else:
            value += (byte & 0x7F) << ((7 if mut != "shift8" else 8) * index)
        if index == 3 and byte & 0x80:
            return ("err", ERR_OVERFLOW if mut != "overflow_code" else 1, pos)
        if not byte & 0x80:
            return ("ok", value, pos)
    return ("err", ERR_OVERFLOW, pos)


def model_huffman(table, src, initial=b"", mut=None):
    """Huffman decode: (status, bytes-or-code, bytes left in the scratch buffer).

    The scratch buffer is not cleared first: bytes already in it come back in front of the decoded text, and an
    error leaves everything written so far in the buffer."""
    state, last, out = 0, 0, bytearray(initial)
    for byte in src:
        for nibble in (byte >> 4, byte & 15):
            if state >= 256:
                raise Panic("state index")
            nxt, sym, flags = entry(table, state, nibble)
            if flags & 4 and mut != "ignore_error":
                return ("err", ERR_HUFFMAN, len(out))
            if flags & 2:
                out.append(sym)
            state, last = nxt, flags
    if src:
        accepted = state == 0 or bool(last & 1)
        if mut == "no_padding_check":
            accepted = True
        if mut == "state_only":
            accepted = state == 0
        if mut == "flag_only":
            accepted = bool(last & 1)
        if not accepted:
            return ("err", ERR_HUFFMAN, len(out))
    return ("ok", bytes(out), 0 if mut != "keep_buffer" else len(out))


def model_string(table, data, pos, mut=None):
    """decode_string: ('err', code, pos, left) or ('ok', kind, payload, offset, length, pos, left)."""
    n = len(data)
    if n <= pos:
        return ("err", 0, pos, 0)
    first = data[pos]
    status, value, after = model_int(data, pos, 7)
    if status == "err":
        return ("err", value, after, 0)
    length = value
    if length > max(0, n - after) and mut != "no_length_check":
        return ("err", ERR_STRING_UNDERFLOW, after, 0)
    offset = after - pos
    huffman = bool(first & 0x80)
    if mut == "flip_huffman_bit":
        huffman = not huffman
    if not huffman:
        return ("ok", "plain", b"", offset, length, after + length, 0)
    result = model_huffman(table, data[after:after + length])
    new_pos = after if mut == "no_advance_on_error" and result[0] == "err" else after + length
    if result[0] == "err":
        return ("err", result[1], new_pos, result[2])
    return ("ok", "huffman", result[1], offset if mut != "offset_zero" else 0, length, new_pos, 0)


# ------------------------------ emulator rig --------------------------------

class Rig:
    """One interpreter with the library routines the HPACK path calls modelled as stubs."""

    def __init__(self, image, patches=None, byte_overrides=None):
        self.m = Machine(image, patches)
        m = self.m
        m.real = frozenset((F_GETU8, F_INT, F_HUFF))
        m.calls[F_FREEZE] = self.freeze
        for slot, target in SLOTS.items():
            m.memory.statics[slot] = target
        m.memory.statics[LOG_FLAG_SLOT] = LOG_FLAG_CELL
        m.memory.statics[LOG_FLAG_CELL] = 1
        for address, value in (byte_overrides or {}).items():
            m.memory.statics[address] = value
        m.slots = {0x161D1F0: self.reserve, 0x161DA20: self.put_slice, 0x161D6B0: self.split,
                   0x1680CBF: self.panic, 0x1681E40: self.panic, 0x161DC50: self.panic, 0x1681DA0: self.panic,
                   0x5CFFDC0: self.logger}
        self.bump = BUMP_START

    # scratch buffer layout: ptr +0, len +8, cap +0x10, data +0x18
    def reserve(self, m):
        self.ensure(m.regs[RDI], m.regs[RSI])

    def ensure(self, buf, extra):
        mem = self.m.memory
        ptr, length, cap = mem.read(buf, 8), mem.read(buf + 8, 8), mem.read(buf + 16, 8)
        if cap - length >= extra:
            return
        size = max(length + extra, BUF_CAP0)
        new = self.bump
        self.bump += (size + 15) & ~15
        if self.bump >= HEAP_BASE + USED:
            raise Halt("scratch exhausted")
        mem.put_bytes(new, mem.bytes_at(ptr, length))
        mem.write(buf, 8, new)
        mem.write(buf + 16, 8, size)

    def put_slice(self, m):
        buf, src, count = m.regs[RDI], m.regs[RSI], m.regs[RDX]
        mem = m.memory
        self.ensure(buf, count)
        length = mem.read(buf + 8, 8)
        mem.put_bytes(mem.read(buf, 8) + length, mem.bytes_at(src, count))
        mem.write(buf + 8, 8, length + count)

    def split(self, m):
        out, buf, at = m.regs[RDI], m.regs[RSI], m.regs[RDX]
        mem = m.memory
        ptr, length, cap, data = (mem.read(buf + k, 8) for k in (0, 8, 16, 24))
        if at > length:
            raise Panic("split_to beyond len")
        for k, v in enumerate((ptr, at, at, data)):
            mem.write(out + 8 * k, 8, v)
        mem.write(buf, 8, ptr + at)
        mem.write(buf + 8, 8, length - at)
        mem.write(buf + 16, 8, cap - at)

    def freeze(self, m):
        out, src = m.regs[RDI], m.regs[RSI]
        mem = m.memory
        mem.write(out, 8, 0xF1)
        mem.write(out + 8, 8, mem.read(src, 8))
        mem.write(out + 16, 8, mem.read(src + 8, 8))
        mem.write(out + 24, 8, mem.read(src + 24, 8))

    def panic(self, m):
        raise Panic("panic routine")

    def logger(self, m):
        m.regs[RAX] = 0

    def load(self, data, pos=0):
        mem = self.m.memory
        mem.reset(USED)
        self.bump = BUMP_START
        mem.put_bytes(DATA, data)
        mem.write(S_AT, 8, DATA)
        mem.write(S_AT + 8, 8, len(data))
        mem.write(C_AT, 8, S_AT)
        mem.write(C_AT + 8, 8, pos)

    def scratch(self, initial=b""):
        mem = self.m.memory
        mem.put_bytes(BUF_MEM, initial)
        for k, v in enumerate((BUF_MEM, len(initial), max(BUF_CAP0, len(initial)), 1)):
            mem.write(DEC_AT + 0x40 + 8 * k, 8, v)

    def go(self, entry_va, args):
        try:
            self.m.run(entry_va, args)
        except Panic:
            return "panic"
        except (Halt, EvidenceError) as exc:
            return "halt:" + str(exc)
        return None

    def left(self):
        return self.m.memory.read(DEC_AT + 0x48, 8)

    def run_int(self, data, pos, prefix):
        self.load(data, pos)
        bad = self.go(F_INT, {RDI: OUT_AT, RSI: C_AT, RDX: prefix})
        if bad:
            return (bad,)
        mem = self.m.memory
        new_pos = mem.read(C_AT + 8, 8)
        if mem.read(OUT_AT, 1) == 0:
            return ("ok", mem.read(OUT_AT + 8, 8), new_pos)
        return ("err", mem.read(OUT_AT + 1, 1), new_pos)

    def run_huffman(self, src, initial=b""):
        self.load(src)
        self.scratch(initial)
        bad = self.go(F_HUFF, {RDI: OUT_AT, RSI: DATA, RDX: len(src), RCX: DEC_AT + 0x40})
        if bad:
            return (bad,)
        mem = self.m.memory
        if mem.read(OUT_AT, 8) == 0:
            return ("err", mem.read(OUT_AT + 8, 1), self.left())
        return ("ok", mem.bytes_at(mem.read(OUT_AT, 8), mem.read(OUT_AT + 8, 8)), self.left())

    def run_string(self, data, pos):
        self.load(data, pos)
        self.scratch()
        bad = self.go(F_STRING, {RDI: OUT_AT, RSI: DEC_AT, RDX: C_AT})
        if bad:
            return (bad,)
        mem = self.m.memory
        new_pos = mem.read(C_AT + 8, 8)
        if mem.read(OUT_AT, 1) == 1:
            return ("err", mem.read(OUT_AT + 1, 1), new_pos, self.left())
        offset, length = mem.read(OUT_AT + 0x28, 8), mem.read(OUT_AT + 0x30, 8)
        if mem.read(OUT_AT + 8, 8) == 0:
            return ("ok", "plain", b"", offset, length, new_pos, self.left())
        payload = mem.bytes_at(mem.read(OUT_AT + 16, 8), mem.read(OUT_AT + 24, 8))
        return ("ok", "huffman", payload, offset, length, new_pos, self.left())


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

    def data(self, n):
        return bytes(self.below(256) for _ in range(n))


def int_cases(count, seed=0x115A):
    rng = Xorshift(seed)
    for index in range(count):
        prefix = 1 + rng.below(8) if index % 3 else 4 + rng.below(4)
        mask = (~((0xFF << prefix) & 0xFF)) & 0xFF
        length = rng.below(8)
        kind = rng.below(5)
        body = bytearray(rng.data(length))
        if length and kind > 0:
            body[0] = (body[0] & ~mask & 0xFF) | mask
        if kind >= 2:
            for k in range(1, length):
                body[k] = body[k] | 0x80 if rng.below(4) else body[k] & 0x7F
        if kind == 4:
            for k in range(1, length):
                body[k] |= 0x80
        yield bytes(body), rng.below(length + 2), prefix


def huffman_cases(count, seed=0x115B):
    rng = Xorshift(seed)
    for index in range(count):
        length = rng.below(15)
        kind = rng.below(6)
        src = bytearray(rng.data(length))
        if length and kind == 1:
            src[-1] |= 0xFF >> (1 + rng.below(8))
        if length and kind == 2:
            for k in range(length - 1 - rng.below(min(length, 5)), length):
                src[k] = 0xFF
        if length and kind == 3:
            src[rng.below(length)] = 0xFF
        if length and kind == 4:
            src = bytearray(b"\xff" * length)
        initial = rng.data(rng.below(6)) if index % 11 == 0 else b""
        yield bytes(src), initial


def encode_int7(value):
    if value < 127:
        return bytes([value])
    out = bytearray([127])
    value -= 127
    while value >= 128:
        out.append(value & 0x7F | 0x80)
        value >>= 7
    out.append(value)
    return bytes(out)


def string_cases(count, seed=0x115C):
    rng = Xorshift(seed)
    for index in range(count):
        lead = rng.data(rng.below(3))
        body = rng.data(rng.below(20))
        huff = rng.below(2)
        kind = rng.below(8)
        if kind == 0:
            declared = len(body) + 1 + rng.below(3)
        elif kind == 1 and len(body) > 1:
            declared = len(body) - 1
        elif kind == 2:
            declared = 126 + rng.below(4)
            body = rng.data(declared + rng.below(2))
        else:
            declared = len(body)
        header = encode_int7(declared)
        first = (huff << 7 | header[0]) & 0xFF if kind != 7 else rng.below(256)
        data = lead + bytes([first]) + header[1:] + body
        if kind == 6:
            data = data[: max(1, len(data) - 1 - rng.below(3))]
        if kind == 5:
            data = lead
        yield data, len(lead) + (rng.below(2) if kind == 5 else 0)


RFC_VECTORS = (
    ("f1e3c2e5f23a6ba0ab90f4ff", b"www.example.com"),
    ("a8eb10649cbf", b"no-cache"),
    ("25a849e95ba97d7f", b"custom-key"),
    ("25a849e95bb8e8b4bf", b"custom-value"),
)


def fmt(value):
    if isinstance(value, (bytes, bytearray)):
        return value.hex() or "-"
    if isinstance(value, tuple):
        return ",".join(fmt(v) for v in value)
    return str(value)


def stream_checks(image, table, sink, counters, coverage):
    """Run every case through the interpreter and the model; write a sampled tsv line per kind."""
    rig = HdrRig(image)
    brig = NameRig(image)
    drig = DropRig(image)
    sample = {"int": 0, "huffman": 0, "string": 0, "get": 0, "literal": 0, "idx": 0, "name": 0, "drop": 0}

    def check(kind, label, expected, actual):
        counters[kind] += 1
        if expected != actual:
            raise EvidenceError("model and code differ: %s %s %r %r" % (kind, label, expected, actual))
        if sample[kind] < SAMPLE_LINES[kind]:
            sample[kind] += 1
            sink("%s\t%s\t%s\n" % (kind, label, fmt(expected)))

    for data, pos, prefix in int_cases(COUNTS["int"]):
        check("int", "%s@%d/%d" % (data.hex() or "-", pos, prefix), model_int(data, pos, prefix),
              rig.run_int(data, pos, prefix))
    for src, initial in huffman_cases(COUNTS["huffman"]):
        check("huffman", "%s+%s" % (src.hex() or "-", initial.hex() or "-"),
              model_huffman(table, src, initial), rig.run_huffman(src, initial))
    for hexed, plain in RFC_VECTORS:
        check("huffman", "rfc:" + hexed, ("ok", plain, 0), rig.run_huffman(bytes.fromhex(hexed)))
    for data, pos in string_cases(COUNTS["string"]):
        check("string", "%s@%d" % (data.hex() or "-", pos), model_string(table, data, pos), rig.run_string(data, pos))
    for index, ring in get_cases(COUNTS["get"]):
        check("get", "%d/%d,%d,%d" % (index, ring.capacity, ring.head, ring.length), get_expect(index, ring),
              rig.run_get(index, ring))
    for data, pos, arg, ring, tag in literal_cases(COUNTS["literal"]):
        check("literal", "%s@%d/%d/%d,%d,%d/%x" % (data.hex() or "-", pos, arg, ring.capacity, ring.head, ring.length,
                                                  tag),
              model_literal(table, data, pos, arg, ring, tag), rig.run_literal(data, pos, arg, ring, tag))
    for case in idx_cases(COUNTS["idx"]):
        check("idx", idx_label(case), idx_expect(case), brig.run_idx(*case[:3], odd=case[3]))
    for case in idx_oom_cases():
        check("idx", idx_label(case) + "/oom", idx_expect(case, oom=True), brig.run_idx(*case[:3], odd=False, oom=True))
    for case in name_cases(COUNTS["name"]):
        check("name", name_label(case), name_expect(case), brig.run_name(*case[:2], odd=case[2]))
    for case in name_oom_cases():
        check("name", name_label(case) + "/oom", name_expect(case, oom=True), brig.run_name(*case[:2], oom=True))
    for case in drop_cases(COUNTS["drop"]):
        check("drop", fmt(case[:2]) if case[0] in ("raw", "only-method") else case[0] + "/" + fmt(case[1:]),
              model_drop(case), drig.run_drop(case))
    coverage.update(rig.m.seen)
    coverage.update(brig.m.seen)
    coverage.update(drig.m.seen)


# --------------------------- static byte evidence ----------------------------

def table_summary(table):
    flags, syms, high = {}, set(), 0
    for state in range(256):
        for nibble in range(16):
            nxt, sym, flag = entry(table, state, nibble)
            flags[flag] = flags.get(flag, 0) + 1
            high = max(high, nxt)
            if flag & 2:
                syms.add(sym)
    rows = ["metric\tvalue\n", "entries\t%d\n" % (256 * 16), "table_bytes\t%d\n" % len(table),
            "max_next_state\t%d\n" % high, "distinct_emitted_symbols\t%d\n" % len(syms)]
    for flag in sorted(flags):
        rows.append("flags_%02x\t%d\n" % (flag, flags[flag]))
    for state in range(256):
        for nibble in range(16):
            nxt, sym, flag = entry(table, state, nibble)
            if flag & 4:
                rows.append("error_entry\tstate=%d nibble=%d flags=%02x next=%d\n" % (state, nibble, flag, nxt))
    return rows


def call_sites(image, target):
    text = image.named[".text"]
    base, blob = text["address"], image.blob
    start, end = text["offset"], text["offset"] + text["size"]
    sites, i = [], start
    find = blob.find
    while True:
        i = find(b"\xe8", i, end - 4)
        if i < 0:
            break
        rel = int.from_bytes(blob[i + 1:i + 5], "little", signed=True)
        if base + (i - start) + 5 + rel == target:
            sites.append(base + (i - start))
        i += 1
    return sites


def prefix_immediate(image, site, opcode=0xBA):
    """The `mov edx, imm32` (BA imm32) that sets the prefix argument just before a call, if any."""
    at = image.offset(site)
    window = image.blob[at - 16:at]
    for back in range(len(window) - 5, -1, -1):
        if window[back] == opcode and window[back + 2:back + 5] == b"\x00\x00\x00":
            return window[back + 1]
    return None


# ------------------------------ negative controls -----------------------------

def enumerate_mutants(image):
    """Binary mutants: every conditional jump flipped, plus +1 on selected byte immediates."""
    rows = []
    for name, (lo, hi) in RANGES.items():
        for row in decode_range(image, lo, hi):
            if row.op == "jcc":
                at = row.va + (1 if row.data[0] == 0x0F else 0)
                rows.append(("flip-jcc", name, row.va, at, row.data[at - row.va] ^ 1, row.data[at - row.va]))
            elif (name == "table_get" and row.op == "mov" and row.imm_at is not None and row.imm_size in (1, 4)
                  and row.a and row.a[0] == "r"):
                old = row.data[row.imm_at]
                rows.append(("imm+1", name, row.va, row.va + row.imm_at, (old + 1) & 0xFF, old))
            elif (row.imm_at is not None and row.imm_size == 1 and name not in ("decode_string", "table_get")
                  and row.op in ("cmp", "and", "shl", "shr", "test", "or", "add", "sub")
                  and row.a and row.a[0] == "r" and row.a[1] != RSP):
                old = row.data[row.imm_at]
                rows.append(("imm+1", name, row.va, row.va + row.imm_at, (old + 1) & 0xFF, old))
    return rows


MODEL_MUTANTS = (("get", "static_62"), ("get", "wrap_off_by_one"), ("literal", "prefix_plain"),
                 ("literal", "no_rewind"), ("literal", "sel_kind"), ("literal", "plain_keeps_input"), ("literal", "vec_not_advanced"), ("literal", "wide_overflow"), ("int", "mask_wide"), ("int", "max3"), ("int", "no_wrap"), ("int", "shift8"),
                 ("int", "overflow_code"), ("huffman", "ignore_error"), ("huffman", "no_padding_check"),
                 ("huffman", "state_only"), ("huffman", "flag_only"), ("huffman", "keep_buffer"),
                 ("string", "no_length_check"), ("string", "flip_huffman_bit"), ("string", "no_advance_on_error"),
                 ("string", "offset_zero"), ("idx", "ctl_ok"), ("idx", "name_leak"), ("idx", "latin1_ok"),
                 ("idx", "zero_ok"), ("idx", "status_tens"), ("name", "latin1_ok"), ("name", "prefix_only"), ("drop", "value_first"),
                 ("drop", "free_inline"))


def table_mutants(table):
    """Corrupt single table bytes on common paths; the model keeps the original table."""
    picks = []
    first_emit = {}
    emitting = [s for s in range(256) if any(entry(table, s, n)[2] & 2 for n in range(16))]
    for state in emitting[:8]:
        first_emit[state] = next(n for n in range(16) if entry(table, state, n)[2] & 2)
    for state, field in zip(emitting[:8], (8, 9, 8, 9, 8, 9, 8, 9)):
        nibble = first_emit[state]
        old = table[(state * 16 + nibble) * 16 + field]
        picks.append((TABLE_VA + (state * 16 + nibble) * 16 + field, (old ^ 0x10) if field == 8 else (old ^ 2),
                      old, state, nibble, field))
    return picks


def first_diff(cases, expect, run):
    for index, case in enumerate(cases):
        if expect(case) != run(case):
            return index
    return None


def sample_cases(kind):
    if kind == "get":
        return list(get_cases(MUTANT_CASES))
    if kind == "literal":
        return list(literal_cases(MUTANT_CASES))
    if kind == "idx":
        return list(idx_cases(MUTANT_CASES)) + list(idx_oom_cases())
    if kind == "name":
        return list(name_cases(MUTANT_CASES)) + list(name_oom_cases())
    if kind == "drop":
        return list(drop_cases(MUTANT_CASES))
    gen = {"int": int_cases, "huffman": huffman_cases, "string": string_cases}[kind]
    return list(gen(MUTANT_CASES))


def checker(kind, table, rig, mut=None):
    if kind == "int":
        return (lambda c: model_int(*c, mut=mut)), (lambda c: rig.run_int(*c))
    if kind == "get":
        return (lambda c: get_expect(c[0], c[1], mut)), (lambda c: rig.run_get(*c))
    if kind == "drop":
        return (lambda c: model_drop(c, mut)), (lambda c: rig.run_drop(c))
    if kind == "name":
        return (lambda c: name_expect(c, False, mut)), (lambda c: rig.run_name(*c[:2], odd=c[2]))
    if kind == "idx":
        return (lambda c: idx_expect(c, c[4] if len(c) > 4 else False, mut)), \
            (lambda c: rig.run_idx(*c[:3], odd=c[3], oom=c[4] if len(c) > 4 else False))
    if kind == "literal":
        return (lambda c: guarded_literal(table, c, mut)), (lambda c: rig.run_literal(*c))
    if kind == "huffman":
        return (lambda c: model_huffman(table, c[0], c[1], mut=mut)), (lambda c: rig.run_huffman(*c))
    return (lambda c: model_string(table, *c, mut=mut)), (lambda c: rig.run_string(*c))


HOME = {"decode_int": ("int", "string", "literal"), "get_u8": ("int", "string", "literal"),
        "huffman_decode": ("huffman", "string", "literal"), "decode_string": ("string", "literal"),
        "string_take": ("literal",), "cursor_split": ("literal",), "table_get": ("get", "literal"), "header_clone": ("get", "literal"), "decode_literal": ("literal",)}


def equivalence_reason(func, va):
    """Why a flipped jump that no case separates cannot change the observed result (read from the disassembly)."""
    if func == "huffman_decode" and va == 0x179D5E3:
        return ("the spare-capacity test only decides whether reserve runs; put_slice grows the buffer anyway, "
                "so the returned bytes are the same")
    if func == "decode_string" and 0x177BF6F <= va < 0x177C139 or func == "decode_string" and 0x177C200 <= va < 0x177C270:
        return ("log-record branch after the length check failed: every exit stores error 2 at 0x177bf1f, "
                "the gate cell is stubbed closed so the record is never formatted")
    if func == "header_clone" and va >= 0x177EAD9:
        return "unwind landing pad of Header::clone that only runs while a panic unwinds; the rig stops at the panic routine"
    if func == "decode_literal" and va >= 0x177BDEF:
        return "unwind landing pad that only runs while a panic unwinds; the rig stops at the panic routine"
    if func == "decode_string" and va >= 0x177C28A:
        return "unwind landing pad that only runs while a panic unwinds; the rig stops at the panic routine"
    return None


def run_controls(image, table, sink, equiv_sink):
    """Returns (total, detected, equivalent); every mutant is listed, detected or not."""
    samples = {k: sample_cases(k) for k in ("int", "huffman", "string", "get", "literal", "idx", "name", "drop")}
    total = detected = equivalent = 0
    for style, func, va, at, new, old in enumerate_mutants(image):
        total += 1
        rig = (NameRig if func in BUILDER_FUNCS else DropRig if func in DROP_FUNCS else HdrRig)(image, patches={at: new})
        found, via = None, "-"
        for kind in HOME[func]:
            expect, run = checker(kind, table, rig)
            found = first_diff(samples[kind], expect, run)
            if found is not None:
                via = kind
                break
        detected += found is not None
        verdict = "detected" if found is not None else "undetected"
        reason = equivalence_reason(func, va) if found is None else None
        if reason:
            verdict = "equivalent"
            equivalent += 1
            equiv_sink("%s %s %#x\t%#x:%02x->%02x\t%s\n" % (style, func, va, at, old, new, reason))
        sink("%s\t%s\t%#x\t%#x:%02x->%02x\t%s\t%s\n" % (
            style, func, va, at, old, new, verdict,
            "%s case %d" % (via, found) if found is not None else "-"))
    for kind, mut in MODEL_MUTANTS:
        total += 1
        expect, run = checker(kind, table, (NameRig if kind in ("idx", "name") else DropRig if kind == "drop" else HdrRig)(image), mut)
        found = first_diff(samples[kind], expect, run)
        detected += found is not None
        sink("model\t%s\t%s\t-\t%s\t%s\n" % (kind, mut, "detected" if found is not None else "undetected",
                                             "case %d" % found if found is not None else "-"))
    for at, new, old, state, nibble, field in table_mutants(table):
        total += 1
        expect, run = checker("huffman", table, HdrRig(image, byte_overrides={at: new}))
        found = first_diff(samples["huffman"], expect, run)
        detected += found is not None
        sink("table-byte\tstate=%d nibble=%d field=%d\t%#x\t%02x->%02x\t%s\t%s\n" % (
            state, nibble, field, at, old, new, "detected" if found is not None else "undetected",
            "case %d" % found if found is not None else "-"))
    return total, detected, equivalent



# ---------------------------------------------------------------------------
# Widening: Table::get 0x177b6c0, Header::clone 0x177e900 and decode_literal 0x177bb00.
# ---------------------------------------------------------------------------

F_GET, F_CLONE, F_LITERAL = 0x177B6C0, 0x177E900, 0x177BB00
F_TAKE, F_RESERVE = 0x177B570, 0x161D5F0
F_CONV, F_BUILD_IDX, F_BUILD_NEW, F_DROP_HDR, F_BOX_CLONE = 0x177B440, 0x1797E20, 0x17985C0, 0x177DD80, 0x17A06C0
RANGES.update({"table_get": (0x177B6C0, 0x177BAFA), "header_clone": (0x177E900, 0x177EB02),
               "decode_literal": (0x177BB00, 0x177BDEF), "string_take": (0x177B440, 0x177B520),
               "cursor_split": (0x177B570, 0x177B6A4)})
ERR_BAD_INDEX = 5
KIND_ERR = 8
VT_AT = HEAP_BASE + 0x8000
FAKE_CLONE, FAKE_BYTES_DROP = 0x7000000, 0x7000010
RING_AT, PAY_AT = HEAP_BASE + 0x9000, HEAP_BASE + 0xA000
TABLE_AT = DEC_AT + 0x10
HDR_KIND_NAMES = {2: "authority", 4: "scheme", 5: "path"}
GET_COUNT, LITERAL_COUNT = 4000, 4000
SCRATCH_TAG = 1  # data word of the decoder's scratch buffer (rig stub layout)
TAGS = (0, 0, 1, (5 << 5) | 1, (300 << 5) | 3, 2, (((1 << 59) - 2) << 5) | 1, (((1 << 59) - 40) << 5) | 5)
COUNTS.update({"get": GET_COUNT, "literal": LITERAL_COUNT})
SAMPLE_LINES.update({"get": 300, "literal": 300})

# RFC 7541 appendix A static table (index 1..61): (name, value); http crate StandardHeader ids read from the code.
STATIC_ROWS = (
    (":authority", ""), (":method", "GET"), (":method", "POST"), (":path", "/"), (":path", "/index.html"),
    (":scheme", "http"), (":scheme", "https"), (":status", "200"), (":status", "204"), (":status", "206"),
    (":status", "304"), (":status", "400"), (":status", "404"), (":status", "500"), ("accept-charset", ""),
    ("accept-encoding", "gzip, deflate"), ("accept-language", ""), ("accept-ranges", ""), ("accept", ""),
    ("access-control-allow-origin", ""), ("age", ""), ("allow", ""), ("authorization", ""), ("cache-control", ""),
    ("content-disposition", ""), ("content-encoding", ""), ("content-language", ""), ("content-length", ""),
    ("content-location", ""), ("content-range", ""), ("content-type", ""), ("cookie", ""), ("date", ""),
    ("etag", ""), ("expect", ""), ("expires", ""), ("from", ""), ("host", ""), ("if-match", ""),
    ("if-modified-since", ""), ("if-none-match", ""), ("if-range", ""), ("if-unmodified-since", ""),
    ("last-modified", ""), ("link", ""), ("location", ""), ("max-forwards", ""), ("proxy-authenticate", ""),
    ("proxy-authorization", ""), ("range", ""), ("referer", ""), ("refresh", ""), ("retry-after", ""),
    ("server", ""), ("set-cookie", ""), ("strict-transport-security", ""), ("transfer-encoding", ""),
    ("user-agent", ""), ("vary", ""), ("via", ""), ("www-authenticate", ""))
# StandardHeader ids the code stores for the 47 named rows (index 15..61), in row order; read from the bytes.
STATIC_FIELD_IDS = (1, 2, 3, 4, 0, 8, 13, 14, 16, 17, 21, 22, 23, 24, 25, 26, 29, 30, 32, 33, 34, 35, 37, 38, 39, 40,
                    41, 42, 43, 44, 45, 46, 47, 50, 51, 54, 55, 57, 58, 64, 65, 66, 69, 70, 73, 74, 76)
STD_ID = {row[0]: ident for row, ident in zip(STATIC_ROWS[14:], STATIC_FIELD_IDS)}
STD_COUNT = 78


def static_header(index):
    """Normalized static-table header for RFC index 1..61."""
    name, value = STATIC_ROWS[index - 1]
    if name == ":authority":
        return ("authority", value.encode())
    if name == ":method":
        return ("method", {"GET": 1, "POST": 2}[value])
    if name == ":path":
        return ("path", value.encode())
    if name == ":scheme":
        return ("scheme", value.encode())
    if name == ":status":
        return ("status", int(value))
    return ("field", ("std", STD_ID[name]), value.encode())


def clone_events(entry):
    """Bytes values the vtable clone slot is called with, in the order Header::clone calls it."""
    if entry[0] == "field":
        name = entry[1]
        return ([name[1]] if name[0] == "custom" else []) + [entry[2]]
    if entry[0] in ("authority", "scheme", "path"):
        return [entry[1]]
    if entry[0] == "method" and entry[1] >= 10:
        return [entry[2]]
    return []


# ------------------------------- memory images --------------------------------

class Heap:
    def __init__(self, mem):
        self.mem, self.at = mem, PAY_AT

    def blob(self, data):
        at = self.at
        self.mem.put_bytes(at, data)
        self.at += (len(data) + 15) & ~15
        return at


def put_bytes_value(heap, at, data, token):
    mem = heap.mem
    mem.write(at, 8, VT_AT)
    mem.write(at + 8, 8, heap.blob(data) if data else 1)
    mem.write(at + 16, 8, len(data))
    mem.write(at + 24, 8, token)


def put_entry(heap, base, entry):
    mem = heap.mem
    for k in range(9):
        mem.write(base + 8 * k, 8, 0)
    kind = entry[0]
    if kind == "field":
        mem.write(base + 0x40, 1, 0)
        name = entry[1]
        if name[0] == "std":
            mem.write(base + 8, 1, name[1])
        else:
            put_bytes_value(heap, base, name[1], 0x11)
        put_bytes_value(heap, base + 0x20, entry[2], 0x22)
    elif kind in ("authority", "scheme", "path", "protocol"):
        mem.write(base + 0x40, 1, {"authority": 2, "scheme": 4, "path": 5, "protocol": 6}[kind])
        put_bytes_value(heap, base, entry[1], 0x33)
    elif kind == "method":
        mem.write(base + 0x40, 1, 3)
        tag = entry[1]
        mem.write(base, 1, tag)
        if tag == 9:
            mem.write(base + 1, 7, entry[2])
            mem.write(base + 8, 8, entry[3])
            mem.write(base + 16, 8, entry[4])
        elif tag >= 10:
            mem.write(base + 8, 8, heap.blob(entry[2]))
            mem.write(base + 16, 8, len(entry[2]))
    elif kind == "status":
        mem.write(base + 0x40, 1, 7)
        mem.write(base, 2, entry[1])


def load_ring(rig, ring, at):
    """Write a table at `at` the way the decoder keeps it: capacity, slot pointer, head, live length."""
    for slot, entry in enumerate(ring.slots):
        put_entry(rig.heap, RING_AT + 72 * slot, entry)
    mem = rig.m.memory
    for k, v in enumerate((ring.capacity, RING_AT, ring.head, ring.length)):
        mem.write(at + 8 * k, 8, v)


def bytes_value(mem, ptr, length):
    """Bytes content; an empty value must carry the dangling pointer 1, anything else is shown as a marker."""
    if length:
        return mem.bytes_at(ptr, length)
    return b"" if ptr == 1 else b"!%x" % ptr


def read_header(mem, at):
    kind = mem.read(at + 0x40, 1)
    if kind == KIND_ERR:
        return ("err", mem.read(at, 1))
    if kind in (0, 1):
        if mem.read(at, 8) == 0:
            name = ("std", mem.read(at + 8, 1))
        else:
            name = ("custom", bytes_value(mem, mem.read(at + 8, 8), mem.read(at + 16, 8)))
        return ("field", name, bytes_value(mem, mem.read(at + 0x28, 8), mem.read(at + 0x30, 8)))
    if kind in HDR_KIND_NAMES:
        return (HDR_KIND_NAMES[kind], bytes_value(mem, mem.read(at + 8, 8), mem.read(at + 16, 8)))
    if kind == 3:
        tag = mem.read(at, 1)
        if tag < 9:
            return ("method", tag)
        if tag == 9:
            return ("method", tag, mem.read(at + 1, 7), mem.read(at + 8, 8), mem.read(at + 16, 8))
        return ("method", tag, mem.bytes_at(mem.read(at + 8, 8), mem.read(at + 16, 8)))
    if kind == 7:
        return ("status", mem.read(at, 2))
    return ("kind?", kind)


# ---------------------------------- rig ----------------------------------------

class HdrRig(Rig):
    """Rig with Table::get, Header::clone and decode_literal executing for real; their library callees are stubs."""

    def __init__(self, image, patches=None, byte_overrides=None):
        super().__init__(image, patches, byte_overrides)
        m = self.m
        m.real = frozenset(set(m.real) | {F_GET, F_CLONE, F_LITERAL, F_STRING, F_CONV, F_TAKE})
        m.slots[FAKE_CLONE] = self.vt_clone
        m.slots[FAKE_BYTES_DROP] = self.vt_drop
        m.slots[0xF1] = self.vt_drop
        m.calls[F_BOX_CLONE] = self.box_clone
        m.calls[F_RESERVE] = self.panic
        m.calls[F_BUILD_IDX] = self.build_idx
        m.calls[F_BUILD_NEW] = self.build_new
        m.calls[F_DROP_HDR] = self.drop_hdr
        self.events = []
        self.heap = Heap(m.memory)

    def freeze(self, m):
        super().freeze(m)
        m.memory.write(m.regs[RDI], 8, VT_AT)

    def vt_clone(self, m):
        mem = m.memory
        out, data, ptr, length = m.regs[RDI], m.regs[RSI], m.regs[RDX], m.regs[RCX]
        self.events.append(("clone", mem.bytes_at(ptr, length)))
        for k, v in enumerate((VT_AT, ptr, length, data)):
            mem.write(out + 8 * k, 8, v)

    def vt_drop(self, m):
        self.events.append(("bytes-drop",))

    def box_clone(self, m):
        mem = m.memory
        box = m.regs[RDI]
        ptr, length = mem.read(box, 8), mem.read(box + 8, 8)
        self.events.append(("clone", mem.bytes_at(ptr, length)))
        m.regs[RAX], m.regs[RDX] = ptr, length
        m.keep_rdx = True

    def build_idx(self, m):
        mem = m.memory
        out, sel, hdr, value = m.regs[RDI], m.regs[RSI], m.regs[RDX], m.regs[RCX]
        self.events.append(("by-index", sel, read_header(mem, hdr), content(mem, value)))
        mem.write(out, 8, 0xB1)
        mem.write(out + 0x40, 1, 0)

    def build_new(self, m):
        mem = m.memory
        out, name, value = m.regs[RDI], m.regs[RSI], m.regs[RDX]
        self.events.append(("by-name", content(mem, name), content(mem, value)))
        mem.write(out, 8, 0xB2)
        mem.write(out + 0x40, 1, 0)

    def drop_hdr(self, m):
        self.events.append(("drop-header", read_header(m.memory, m.regs[RDI])))

    def prepare(self):
        mem = self.m.memory
        mem.write(VT_AT, 8, FAKE_CLONE)
        mem.write(VT_AT + 0x20, 8, FAKE_BYTES_DROP)
        self.heap.at = PAY_AT

    def run_get(self, index, ring):
        mem = self.m.memory
        self.load(b"")
        self.prepare()
        self.events = []
        load_ring(self, ring, DEC_AT)
        for k in range(0x48):
            mem.write(OUT_AT + k, 1, 0xEE)
        bad = self.go(F_GET, {RDI: OUT_AT, RSI: DEC_AT, RDX: index})
        if bad:
            return (bad,)
        try:
            return (read_header(mem, OUT_AT), tuple(e[1] for e in self.events))
        except (Halt, KeyError) as exc:
            return ("halt:" + str(exc),)

    def run_literal(self, data, pos, arg, ring, tag=0):
        mem = self.m.memory
        self.load(data, pos)
        mem.write(S_AT + 24, 8, tag)
        self.prepare()
        self.scratch()
        self.events = []
        load_ring(self, ring, TABLE_AT)
        for k in range(0x48):
            mem.write(OUT_AT + k, 1, 0xEE)
        bad = self.go(F_LITERAL, {RDI: OUT_AT, RSI: DEC_AT, RDX: C_AT, RCX: arg})
        if bad:
            return (bad,)
        kind = mem.read(OUT_AT + 0x40, 1)
        head = ("err", mem.read(OUT_AT, 1)) if kind == KIND_ERR else ("built", mem.read(OUT_AT, 8))
        return (head, mem.read(C_AT + 8, 8), mem.read(S_AT, 8) - DATA, tuple(self.events))


def content(mem, at):
    """Bytes value stored at `at` as (vtable, ptr, len, data): its content and its data word."""
    return (mem.bytes_at(mem.read(at + 8, 8), mem.read(at + 16, 8)), mem.read(at + 24, 8))


def model_conv(data, base, pos, string, tag=0, mut=None):
    """0x177b440: take a decoded string off the input. Returns (bytes, new base, new cursor position).

    The cursor moves past the length prefix; a Huffman string (already decoded) is returned as is and the cursor also
    moves past its encoded bytes; a plain string is split off the front of the input buffer (cursor back to 0)."""
    left = len(data) - base
    offset, length = string[3], string[4]
    if offset > max(left - pos, 0):
        raise Panic("offset beyond the input")
    pos += offset
    if string[1] == "huffman":
        if length > max(left - pos, 0):
            raise Panic("length beyond the input")
        return (string[2], SCRATCH_TAG), base, pos + length
    if pos + length > left:
        raise Panic("split_to beyond len")
    start = base + pos
    taken = data[start:start + length]
    # the split-off bytes keep the buffer's data word; a vec-backed buffer (bit 0) has its stored offset advanced
    if tag & 1 and ((tag >> 5) + pos) >> (59 if mut != "wide_overflow" else 60):
        raise Panic("stored offset overflows 59 bits")
    word = tag if not tag & 1 else (((tag >> 5) + pos) << 5 | (tag & 0x1F)) & MASK[8]
    if mut == "vec_not_advanced":
        word = tag
    if mut == "plain_keeps_input":
        return (taken, word), base, pos + length
    return (taken, word), base + pos + length, 0


# --------------------------- decode_literal model --------------------------------

def model_literal(table, data, pos, arg, ring, tag=0, mut=None):
    try:
        return model_literal_flow(table, data, pos, arg, ring, tag, mut)
    except Panic:
        return ("panic",)


def model_literal_flow(table, data, pos, arg, ring, tag, mut):
    """decode_literal: (result, final cursor position, consumed input prefix, event trace)."""
    events = []
    prefix = (2 * arg + 4) & 0xFFFFFFFF
    if mut == "prefix_plain":
        prefix = (2 * arg + 3) & 0xFFFFFFFF
    status, value, cur = model_int(data, pos, prefix)
    if status == "err":
        return (("err", value), cur, 0, ())
    if value:
        entry = model_ring_get(value, ring, mut)
        if entry[0] == "err":
            return (("err", entry[1]), cur, 0, ())
        if value >= 62:
            events.extend(("clone", b) for b in clone_events(entry))
        before = cur
        string = model_string(table, data, cur)
        if string[0] == "err":
            events.append(("drop-header", entry))
            return (("err", string[1]), string[2], 0, tuple(events))
        cur = before if mut != "no_rewind" else string[5]
        taken, base, cur = model_conv(data, 0, cur, string, tag, mut)
        kind = {"authority": 2, "method": 3, "scheme": 4, "path": 5, "status": 7}.get(entry[0], 0)
        sel = kind - 1 if kind >= 2 else 0
        if mut == "sel_kind":
            sel = kind
        events.append(("by-index", sel, entry, taken))
        events.append(("drop-header", entry))
        return (("built", 0xB1), cur, base, tuple(events))
    start = cur
    name = model_string(table, data, cur)
    if name[0] == "err":
        return (("err", name[1]), name[2], 0, ())
    cur = name[5]
    val = model_string(table, data, cur)
    if val[0] == "err":
        if name[1] == "huffman":
            events.append(("bytes-drop",))
        return (("err", val[1]), val[2], 0, tuple(events))
    cur = start if mut != "no_rewind" else val[5]
    first, base, cur = model_conv(data, 0, cur, name, tag, mut)
    second, base, cur = model_conv(data, base, cur, val, tag, mut)
    events.append(("by-name", first, second))
    return (("built", 0xB2), cur, base, tuple(events))


# ------------------------------- case streams -------------------------------------

def random_bytes(rng, limit):
    return rng.data(rng.below(limit))


def random_entry(rng):
    kind = rng.below(8)
    if kind == 0:
        return ("field", ("std", rng.below(STD_COUNT)), random_bytes(rng, 6))
    if kind == 1:
        return ("field", ("custom", random_bytes(rng, 6) or b"x"), random_bytes(rng, 6))
    if kind == 2:
        return ("authority", random_bytes(rng, 6))
    if kind == 3:
        return ("scheme", random_bytes(rng, 6))
    if kind == 4:
        return ("path", random_bytes(rng, 6) or b"/")
    if kind == 5:
        tag = rng.below(12)
        if tag < 9:
            return ("method", tag)
        if tag == 9:
            return ("method", 9, rng.next() & ((1 << 56) - 1), rng.next(), rng.next() & 0xF)
        return ("method", tag, random_bytes(rng, 8) or b"M")
    return ("status", 100 + rng.below(500))


def full_ring(rng):
    """(capacity, head, live entries in ring order) with slot contents kept whole for the memory image."""
    capacity = 1 + rng.below(6)
    length = rng.below(capacity + 1)
    head = rng.below(capacity)
    slots = [random_entry(rng) for _ in range(capacity)]
    return capacity, head, length, slots


class Ring:
    """A table image: the ring holds `slots` (always `capacity` of them) and `length` of them are live."""

    def __init__(self, capacity, head, length, slots):
        self.capacity, self.head, self.length, self.slots = capacity, head, length, slots


def model_ring_get(index, ring, mut=None):
    """Table::get over a Ring: live entry k (k = index - 62) sits at slot (head + k) mod capacity."""
    if index == 0:
        return ("err", ERR_BAD_INDEX)
    if index < (62 if mut != "static_62" else 61):
        return static_header(index)
    offset = index - 62
    if offset >= ring.length:
        return ("err", ERR_BAD_INDEX)
    slot = ring.head + offset
    if slot >= ring.capacity:
        slot -= ring.capacity if mut != "wrap_off_by_one" else ring.capacity - 1
    return ring.slots[slot]


def get_cases(count, seed=0x115D):
    rng = Xorshift(seed)
    for index in range(0, 70):
        yield index, Ring(2, 1, 2, [("status", 404), ("authority", b"a.b")])
    for _ in range(count):
        capacity, head, length, slots = full_ring(rng)
        index = rng.below(62 + length + 3) if rng.below(4) else 62 + rng.below(length + 2)
        yield index, Ring(capacity, head, length, slots)


def literal_cases(count, seed=0x115E):
    rng = Xorshift(seed)
    for _ in range(count):
        capacity, head, length, slots = full_ring(rng)
        ring = Ring(capacity, head, length, slots)
        arg = rng.below(3)
        prefix = (2 * arg + 4) & 31
        mask = (1 << prefix) - 1 if prefix < 8 else 0xFF
        kind = rng.below(10)
        if kind < 3:
            index = 0
        elif kind < 5:
            index = 1 + rng.below(61)
        elif kind < 9:
            index = 62 + rng.below(length + 1)
        else:
            index = rng.below(200)
        lead = rng.data(rng.below(2))
        first = rng.below(256) & ~mask & 0xFF
        if index < mask:
            head_bytes = bytes([first | index])
        else:
            head_bytes = bytes([first | mask]) + encode_tail(index - mask)
        strings = b""
        for _ in range(2):
            body = rng.data(rng.below(8))
            huff = rng.below(2)
            declared = len(body) if rng.below(8) else len(body) + 1 + rng.below(2)
            header = encode_int7(declared)
            strings += bytes([(huff << 7 | header[0]) & 0xFF]) + header[1:] + body
        data = lead + head_bytes + strings
        if rng.below(12) == 0:
            data = data[: rng.below(len(data) + 1)]
        yield data, len(lead), arg, ring, TAGS[rng.below(len(TAGS))]


def encode_tail(value):
    out = bytearray()
    while value >= 128:
        out.append(value & 0x7F | 0x80)
        value >>= 7
    out.append(value)
    return bytes(out)


def write_static_rows(image, sink):
    """Every index 0..62 through the real Table::get: raw kind byte, normalized header, RFC 7541 row."""
    rig = HdrRig(image)
    empty = Ring(1, 0, 0, [("status", 200)])
    sink("index\tkind\tbinary_header\trfc_name\trfc_value\tmatches_rfc\n")
    for index in range(0, 63):
        header, _ = rig.run_get(index, empty)
        kind = rig.m.memory.read(OUT_AT + 0x40, 1)
        if 1 <= index <= 61:
            name, value = STATIC_ROWS[index - 1]
            match = "yes" if header == static_header(index) else "NO"
        else:
            name, value, match = "-", "-", "yes" if header == ("err", ERR_BAD_INDEX) else "NO"
        sink("%d\t%d\t%s\t%s\t%s\t%s\n" % (index, kind, fmt(header), name, value or "-", match))


def guarded_literal(table, case, mut):
    try:
        return model_literal(table, case[0], case[1], case[2], case[3], case[4], mut=mut)
    except Panic as exc:
        return ("model-panic", str(exc))


def get_expect(index, ring, mut=None):
    entry = model_ring_get(index, ring, mut)
    if entry[0] == "err":
        return (entry, ())
    return (entry, tuple(clone_events(entry)) if index >= 62 else ())


# ---------------------------------------------------------------------------
# By-index builder 0x1797e20: (selector, table header, value bytes) -> typed header, with the value bytes validated.
# ---------------------------------------------------------------------------

F_UTF8, F_METHOD, F_MALLOC, F_ALLOC_FAIL = 0x16815E0, 0x2E4FE40, 0x6355830, 0x141E264
FAKE_MEMCPY = 0x7000020
RANGES["build_idx"] = (0x1797E20, 0x179821B)
HDR_AT, VAL_AT = HEAP_BASE + 0x500, HEAP_BASE + 0x600
GOT_STATIC = {0x64DF8C0: 0x64040E8, 0x64DF8C8: 0x64040C0}
EMPTY_VT = 0x6403FC0
HDR_KIND_NAMES.update({6: "protocol"})
COUNTS["idx"] = 4200
SAMPLE_LINES["idx"] = 300
HOME["build_idx"] = ("idx",)
ERR_VALUE, ERR_STATUS = 7, 8
STD_METHODS = (b"OPTIONS", b"GET", b"POST", b"PUT", b"DELETE", b"HEAD", b"TRACE", b"CONNECT", b"PATCH")
TOKEN = frozenset(b"!#$%&'*+-.^_`|~0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz")
SEL_KIND = {1: 2, 2: 3, 3: 4, 4: 5, 5: 6, 6: 7}


def method_of(data):
    """Library stub for the method parser 0x2e4fe40: standard methods are tags 0..8, short extensions tag 9, long 10."""
    if not data or any(b not in TOKEN for b in data):
        return None
    if data in STD_METHODS:
        return ("method", STD_METHODS.index(data))
    if len(data) <= 15:
        return ("method", 9, int.from_bytes(data[:7].ljust(7, b"\0"), "little"),
                int.from_bytes(data[7:15].ljust(8, b"\0"), "little"), len(data))
    return ("method", 10, data)


def header_value_ok(data):
    return all(b > 0x1F and b != 0x7F or b == 9 for b in data)


def model_idx(sel, entry, value, odd, mut=None):
    """build-by-index: (header, events). `value` = (vtable word, bytes, data word); `entry` = table header (sel 0)."""
    vt, data, word = value
    events = []
    drop = ("bytes-drop",)
    if sel == 0:
        name = entry[1]
        if name[0] == "custom":
            events.append(("clone", name[1]))
        if not header_value_ok(data) and mut != "ctl_ok":
            if name[0] == "custom" and mut != "name_leak":
                events.append(drop)
            events.append(drop)
            return ("err", ERR_VALUE), tuple(events)
        if data:
            events.append(("alloc", len(data)))
            if odd:
                out_vt, out_word = GOT_STATIC[0x64DF8C8], 0x7100000001
            else:
                out_vt, out_word = GOT_STATIC[0x64DF8C0], 0x7100000000 | 1
            out = ("field", name, data, out_vt, 0 if odd else 1)
        else:
            out = ("field", name, b"", EMPTY_VT, 0)
        events.append(drop)
        return out, tuple(events)
    if sel in (1, 3, 4, 5):
        try:
            data.decode("utf-8")
            good = True
        except UnicodeDecodeError:
            good = False
        if mut == "latin1_ok":
            good = True
        if not good:
            events.append(drop)
            return ("err", ERR_VALUE), tuple(events)
        if vt == 0:
            return ("err", ERR_VALUE), ()
        return (HDR_KIND_NAMES[SEL_KIND[sel]], data, VT_AT, word), ()
    if sel == 2:
        method = method_of(data)
        if method is None:
            return ("err", ERR_VALUE), (drop,)
        return method, (drop,)
    if len(data) != 3 or not (0x31 <= data[0] <= 0x39 if mut != "zero_ok" else 0x30 <= data[0] <= 0x39) \
            or not all(0x30 <= b <= 0x39 for b in data[1:]):
        return ("err", ERR_STATUS), (drop,)
    code = 100 * (data[0] - 48) + 10 * (data[1] - 48) + data[2] - 48
    if mut == "status_tens":
        code = 100 * (data[0] - 48) + 100 * (data[1] - 48) + data[2] - 48
    return ("status", code), (drop,)


class BuildRig(HdrRig):
    """HdrRig with the by-index builder executing for real; allocator, memcpy, UTF-8 check and method parser are stubs."""

    def __init__(self, image, patches=None, byte_overrides=None):
        super().__init__(image, patches, byte_overrides)
        m = self.m
        m.real = frozenset(set(m.real) | {F_BUILD_IDX})
        m.calls.pop(F_BUILD_IDX, None)
        relative = image.relative()
        for slot, target in ((0x64DF480, F_MALLOC), (0x64DFCA8, F_UTF8), (0x64E24C8, F_METHOD), (0x64DF498, F_ALLOC_FAIL),
                             (0x64DF4C0, 0x1680CAB)):
            m.memory.statics[slot] = target
            assert relative[slot] == target or slot in (0x64DF4C0,) or relative[slot] == target
        m.memory.statics[0x64DF508] = FAKE_MEMCPY
        for slot, value in GOT_STATIC.items():
            assert relative[slot] == value
            m.memory.statics[slot] = value
        m.slots.update({F_MALLOC: self.malloc, F_UTF8: self.utf8, F_METHOD: self.method, F_ALLOC_FAIL: self.panic,
                        0x1680CAB: self.panic, FAKE_MEMCPY: self.memcpy})
        self.odd = False
        self.oom = False

    def malloc(self, m):
        size = m.regs[RDI]
        self.events.append(("alloc", size))
        if self.oom:
            m.regs[RAX] = 0
            return
        at = self.bump | (1 if self.odd else 0)
        self.bump += (size + 17) & ~15
        if self.bump >= HEAP_BASE + USED:
            raise Halt("scratch exhausted")
        m.regs[RAX] = at

    def memcpy(self, m):
        m.memory.put_bytes(m.regs[RDI], m.memory.bytes_at(m.regs[RSI], m.regs[RDX]))

    def utf8(self, m):
        try:
            m.memory.bytes_at(m.regs[RSI], m.regs[RDX]).decode("utf-8")
            tag = 0
        except UnicodeDecodeError:
            tag = 1
        m.memory.write(m.regs[RDI], 8, tag)

    def method(self, m):
        mem = m.memory
        out, data = m.regs[RDI], mem.bytes_at(m.regs[RSI], m.regs[RDX])
        method = method_of(data)
        for k in range(3):
            mem.write(out + 8 * k, 8, 0)
        if method is None:
            mem.write(out, 1, 0xB)
        elif method[1] < 9:
            mem.write(out, 1, method[1])
        elif method[1] == 9:
            mem.write(out, 1, 9)
            mem.write(out + 1, 7, method[2])
            mem.write(out + 8, 8, method[3])
            mem.write(out + 16, 8, method[4])
        else:
            mem.write(out, 1, 10)
            mem.write(out + 8, 8, self.heap.blob(data))
            mem.write(out + 16, 8, len(data))

    def run_idx(self, sel, entry, value, odd=False, oom=False):
        mem = self.m.memory
        self.load(b"")
        self.prepare()
        self.events = []
        self.odd, self.oom = odd, oom
        vt, data, word = value
        put_entry(self.heap, HDR_AT, entry if sel == 0 else ("status", 200))
        mem.write(VAL_AT, 8, VT_AT if vt else 0)
        mem.write(VAL_AT + 8, 8, self.heap.blob(data) if data else 1)
        mem.write(VAL_AT + 16, 8, len(data))
        mem.write(VAL_AT + 24, 8, word)
        for k in range(0x48):
            mem.write(OUT_AT + k, 1, 0xEE)
        bad = self.go(F_BUILD_IDX, {RDI: OUT_AT, RSI: sel, RDX: HDR_AT, RCX: VAL_AT})
        if bad:
            return (bad,)
        try:
            built = read_header(mem, OUT_AT)
            kind = mem.read(OUT_AT + 0x40, 1)
            if kind == 0:
                alloc = (mem.read(OUT_AT + 0x38, 8) - mem.read(OUT_AT + 0x28, 8)) & MASK[8] if mem.read(OUT_AT + 0x28, 8) != 1 else 0
                built = built + (mem.read(OUT_AT + 0x20, 8), alloc)
            elif kind in (2, 4, 5, 6):
                built = built + (mem.read(OUT_AT, 8), mem.read(OUT_AT + 0x18, 8))
        except (Halt, KeyError) as exc:
            return ("halt:" + str(exc),)
        events = tuple(e if e[0] in ("alloc", "clone") else ("bytes-drop",) for e in self.events)
        return built, events


def idx_label(case):
    sel, entry, (vt, data, word), odd = case[:4]
    name = "-" if entry is None else fmt(entry[1][1]) if entry[1][0] == "custom" else "std%d" % entry[1][1]
    return "sel%d/%s/vt%d/%s/%x/%d" % (sel, name, vt, data.hex() or "-", word, odd)


def idx_expect(case, oom=False, mut=None):
    sel, entry, value, odd = case[:4]
    if oom and sel == 0 and value[1] and header_value_ok(value[1]):
        events = [("clone", entry[1][1])] if entry[1][0] == "custom" else []
        return ("panic",)
    return model_idx(sel, entry, value, odd, mut)


def idx_oom_cases():
    for name in (("std", 7), ("custom", b"x-a")):
        yield 0, ("field", name, b""), (1, b"value", 9), False
        yield 0, ("field", name, b""), (1, b"v", 9), False


def idx_cases(count, seed=0x115F):
    rng = Xorshift(seed)
    for data in STATUS_EDGES:
        yield 6, None, (1, data, 0x1122334455667788), False
    for sel in range(7):
        for data in (b"", b"a", b"/", b"200", b"099", b"1000", b"GET", b"M\x01", b"\xff", b"x\x7f", b"a\tb", b"q\x1f"):
            yield sel, ("field", ("std", 3), b"") if sel == 0 else None, (1, data, 5), False
    for _ in range(count):
        sel = rng.below(7)
        kind = rng.below(4)
        if sel == 0:
            entry = random_entry(rng)
            while entry[0] != "field":
                entry = random_entry(rng)
            pool = range(256) if kind == 0 else range(0x20, 0x7F)
            data = bytes(rng.below(len(pool)) + pool[0] for _ in range(rng.below(10)))
        elif sel == 6:
            entry = None
            data = bytes(48 + rng.below(10) for _ in range(rng.below(5) if kind else 3))
            if rng.below(6) == 0:
                data = data[:1] + bytes([rng.below(256)]) + data[2:]
        elif sel == 2:
            entry = None
            data = rng.data(rng.below(4)) if kind == 0 else bytes(rng.below(94) + 33 for _ in range(rng.below(20)))
            if rng.below(3) == 0:
                data = STD_METHODS[rng.below(9)]
        else:
            entry = None
            data = rng.data(rng.below(8)) if kind == 0 else "".join(chr(0x20 + rng.below(0x2000)) for _ in range(rng.below(4))).encode(
                "utf-8", "surrogatepass")
        vt = 0 if (rng.below(9) == 0 and sel in (1, 3, 4, 5)) else 1
        if vt == 0:
            try:
                data.decode("utf-8")
            except UnicodeDecodeError:
                data = b"ok"
        yield sel, entry, (vt, data, rng.next() & MASK[8]), bool(rng.below(2))


# ---------------------------------------------------------------------------
# By-name builder 0x17985c0: (name bytes, value bytes) -> pseudo-header or field; the pseudo-header table is read by length.
# ---------------------------------------------------------------------------

F_NAME_PARSE, F_PARSE_STR, F_PARSE_PROTO, F_STATUS = 0x2E51760, 0x1798C00, 0x17A0950, 0x179B360
RANGES.update({"build_name": (0x17985C0, 0x1798A73), "str_parser": (0x1798C00, 0x1798C73),
               "proto_parser": (0x17A0950, 0x17A09E8), "status_parse": (0x179B360, 0x179B3B5)})
VT_NAME_AT, VT_VAL_AT = HEAP_BASE + 0x8100, HEAP_BASE + 0x8200
FAKE_NAME_DROP, FAKE_VAL_DROP = 0x7000030, 0x7000040
NAME_AT = HEAP_BASE + 0x700
ERR_EMPTY_NAME, ERR_UNKNOWN_PSEUDO = 0, 9
PSEUDO = {b":path": "path", b":protocol": "protocol", b":authority": "authority", b":scheme": "scheme",
          b":method": "method", b":status": "status"}
COUNTS["name"] = 4200
SAMPLE_LINES["name"] = 300
BUILDER_FUNCS = ("build_idx", "build_name", "str_parser", "proto_parser", "status_parse")
HOME.update({"build_name": ("name",), "str_parser": ("name",), "proto_parser": ("name",), "status_parse": ("name",)})
HEADER_CHARS = frozenset(b"!#$%&'*+-.^_`|~0123456789abcdefghijklmnopqrstuvwxyz")


STATUS_EDGES = tuple(bytes((a, b, c)) for a in b"/019:" for b in b"/09:" for c in b"/09:")


def name_of(data):
    """Library stub for the header-name parser 0x2e51760: lower-cases, std ids for the static-table names."""
    low = data.lower()
    if not low or any(b not in HEADER_CHARS for b in low):
        return None
    ident = STD_ID.get(low.decode())
    return ("std", ident) if ident is not None else ("custom", low)


def status_of(data):
    if len(data) != 3 or not 0x31 <= data[0] <= 0x39 or not all(0x30 <= b <= 0x39 for b in data[1:]):
        return 0
    return 100 * (data[0] - 48) + 10 * (data[1] - 48) + data[2] - 48


def utf8_ok(data):
    try:
        data.decode("utf-8")
        return True
    except UnicodeDecodeError:
        return False


def model_name_build(name, value, odd, mut=None):
    """build-by-name: (header, events); events are the drops (value, name, produced name), allocations and clones."""
    vt, data, word = value
    vdrop, ndrop = ("value-drop", word, len(data)), ("name-drop", 0x66, len(name))
    if not name:
        return ("err", ERR_EMPTY_NAME), (vdrop, ndrop)
    if name[0] == 0x3A:
        kind = PSEUDO.get(name)
        if mut == "prefix_only" and kind is None and name[:5] == b":path":
            kind = "path"
        if kind is None:
            return ("err", ERR_UNKNOWN_PSEUDO), (vdrop, ndrop)
        if kind == "method":
            method = method_of(data)
            if method is None:
                return ("err", ERR_VALUE), (vdrop, ndrop)
            return method, (vdrop, ndrop)
        if kind == "status":
            code = status_of(data)
            if code == 0:
                return ("err", ERR_VALUE), (vdrop, ndrop)
            return ("status", code), (vdrop, ndrop)
        if not utf8_ok(data) and mut != "latin1_ok":
            return ("err", ERR_VALUE), (vdrop, ndrop)
        if vt == 0:
            return ("err", ERR_VALUE), (ndrop,)
        return (kind, data, VT_VAL_AT, word), (ndrop,)
    parsed = name_of(name)
    if parsed is None:
        return ("err", ERR_VALUE), (vdrop, ndrop)
    events = []
    if not header_value_ok(data):
        if parsed[0] == "custom":
            events.append(("bytes-drop",))
        events += [vdrop, ndrop]
        return ("err", ERR_VALUE), tuple(events)
    if data:
        events.append(("alloc", len(data)))
        out_vt = GOT_STATIC[0x64DF8C8] if odd else GOT_STATIC[0x64DF8C0]
        out = ("field", parsed, data, out_vt, 0 if odd else 1)
    else:
        out = ("field", parsed, b"", EMPTY_VT, 0)
    return out, tuple(events) + (vdrop, ndrop)


class NameRig(BuildRig):
    """BuildRig with the by-name builder, both string parsers and the status parser executing for real."""

    def __init__(self, image, patches=None, byte_overrides=None):
        super().__init__(image, patches, byte_overrides)
        m = self.m
        m.real = frozenset(set(m.real) | {F_BUILD_NEW, F_PARSE_STR, F_PARSE_PROTO, F_STATUS})
        m.calls.pop(F_BUILD_NEW, None)
        relative = image.relative()
        assert relative[0x64E24D0] == F_NAME_PARSE
        m.memory.statics[0x64E24D0] = F_NAME_PARSE
        m.slots[F_NAME_PARSE] = self.name_parse
        m.slots[FAKE_NAME_DROP] = self.name_drop
        m.slots[FAKE_VAL_DROP] = self.val_drop

    def name_drop(self, m):
        self.events.append(("name-drop", m.memory.read(m.regs[RDI], 8), m.regs[RDX]))

    def val_drop(self, m):
        self.events.append(("value-drop", m.memory.read(m.regs[RDI], 8), m.regs[RDX]))

    def name_parse(self, m):
        mem = m.memory
        out, data = m.regs[RDI], mem.bytes_at(m.regs[RSI], m.regs[RDX])
        parsed = name_of(data)
        if parsed is None:
            mem.write(out, 8, 1)
            return
        mem.write(out, 8, 0)
        for k in range(1, 5):
            mem.write(out + 8 * k, 8, 0)
        if parsed[0] == "std":
            mem.write(out + 16, 1, parsed[1])
        else:
            mem.write(out + 8, 8, VT_AT)
            mem.write(out + 16, 8, self.heap.blob(parsed[1]))
            mem.write(out + 24, 8, len(parsed[1]))
            mem.write(out + 32, 8, 0x55)

    def run_name(self, name, value, odd=False, oom=False):
        mem = self.m.memory
        self.load(b"")
        self.prepare()
        mem.write(VT_NAME_AT + 0x20, 8, FAKE_NAME_DROP)
        mem.write(VT_VAL_AT + 0x20, 8, FAKE_VAL_DROP)
        self.events = []
        self.odd, self.oom = odd, oom
        vt, data, word = value
        for at, vtable, blob in ((NAME_AT, VT_NAME_AT, name), (VAL_AT, VT_VAL_AT if vt else 0, data)):
            mem.write(at, 8, vtable)
            mem.write(at + 8, 8, self.heap.blob(blob) if blob else 1)
            mem.write(at + 16, 8, len(blob))
            mem.write(at + 24, 8, word if at == VAL_AT else 0x66)
        for k in range(0x48):
            mem.write(OUT_AT + k, 1, 0xEE)
        bad = self.go(F_BUILD_NEW, {RDI: OUT_AT, RSI: NAME_AT, RDX: VAL_AT})
        if bad:
            return (bad,)
        try:
            built = read_header(mem, OUT_AT)
            kind = mem.read(OUT_AT + 0x40, 1)
            if kind == 0:
                alloc = (mem.read(OUT_AT + 0x38, 8) - mem.read(OUT_AT + 0x28, 8)) & MASK[8] if mem.read(OUT_AT + 0x28, 8) != 1 else 0
                built = built + (mem.read(OUT_AT + 0x20, 8), alloc)
            elif kind in (2, 4, 5, 6):
                built = built + (mem.read(OUT_AT, 8), mem.read(OUT_AT + 0x18, 8))
        except (Halt, KeyError) as exc:
            return ("halt:" + str(exc),)
        events = tuple(e if e[0] in ("alloc", "clone", "name-drop", "value-drop") else ("bytes-drop",)
                       for e in self.events)
        return built, events


def name_cases(count, seed=0x1160):
    rng = Xorshift(seed)
    values = {"path": (b"/", b"/a/b", b"*", b"\xff/"), "protocol": (b"websocket", b"", b"\xc3"),
              "authority": (b"example.com:443", b"", b"\xf0\x28"), "scheme": (b"https", b"h\xe9", b""),
              "method": (b"GET", b"M-SEARCH", b"a b", b"", b"EXTENSIONMETHODNAME"),
              "status": (b"200", b"099", b"1000", b"20", b"2x0", b"")}
    for pseudo, kind in PSEUDO.items():
        for data in values[kind]:
            yield pseudo, (1, data, 7), False
    for data in STATUS_EDGES:
        yield b":status", (1, data, 0x1122334455667788), False
    for name in (b"", b":", b":x", b":paths", b":Path", b":statuS", b":methog", b":scheme2", b":authorit", b"host", b"Host",
                 b"x-custom", b"X Custom", b"\xff", b"content-length"):
        yield name, (1, b"v", 3), False
    for _ in range(count):
        pick = rng.below(8)
        if pick < 3:
            name = list(PSEUDO)[rng.below(6)]
            kind = PSEUDO[name]
            data = values[kind][rng.below(len(values[kind]))]
            if rng.below(3) == 0:
                data = rng.data(rng.below(6))
            if rng.below(7) == 0:
                name = name[:rng.below(len(name))] + bytes([rng.below(256)]) + name[rng.below(len(name)) + 1:]
        elif pick < 5:
            name = list(STD_ID)[rng.below(len(STD_ID))].encode()
            if rng.below(3) == 0:
                name = name.upper()
            data = bytes(rng.below(0x60) + (0x20 if rng.below(9) else 0) for _ in range(rng.below(8)))
        elif pick < 7:
            name = bytes(rng.below(96) + 32 for _ in range(rng.below(9)))
            data = bytes(rng.below(0x60) + (0x20 if rng.below(9) else 0) for _ in range(rng.below(8)))
        else:
            name = b":" + rng.data(rng.below(11))
            data = rng.data(rng.below(5))
        vt = 0 if rng.below(10) == 0 and PSEUDO.get(name) in ("path", "protocol", "authority", "scheme") \
            and utf8_ok(data) else 1
        yield name, (vt, data, rng.next() & MASK[8]), bool(rng.below(2))


def name_label(case):
    name, (vt, data, word), odd = case[:3]
    return "%s/vt%d/%s/%x/%d" % (name.hex() or "-", vt, data.hex() or "-", word, odd)


def name_expect(case, oom=False, mut=None):
    name, value, odd = case[:3]
    if oom and name[:1] != b":" and name_of(name) and header_value_ok(value[1]) and value[1]:
        return ("panic",)
    return model_name_build(name, value, odd, mut)


def name_oom_cases():
    yield b"x-oom", (1, b"value", 9), False
    yield b"host", (1, b"value", 9), False


# ---------------------------------------------------------------------------
# Header drop 0x177dd80 (by kind) and method drop 0x177de60: which owned buffers are released, in which order.
# ---------------------------------------------------------------------------

F_DROP_METHOD, F_FREE = 0x177DE60, 0x635DE30
RANGES.update({"drop_header": (0x177DD80, 0x177DE2F), "drop_method": (0x177DE60, 0x177DE81)})
COUNTS["drop"] = 3000
SAMPLE_LINES["drop"] = 260
HOME.update({"drop_header": ("drop",), "drop_method": ("drop",)})
DROP_FUNCS = ("drop_header", "drop_method")


def model_drop(case, mut=None):
    """Events of dropping a header (case = entry) or a method (case = ('only-method', entry)); ('raw', kind) = unused kinds."""
    if case[0] == "raw":
        return ()
    if case[0] == "only-method":
        entry = case[1]
        tag = entry[1]
        if tag == 0xB or tag < 10 or not len(entry[2]):
            return ()
        return (("free", len(entry[2]), entry[2], 0),)
    kind = case[0]
    if kind == "field":
        events = []
        if case[1][0] == "custom":
            events.append(("bytes-drop", 0x11, len(case[1][1])))
        events.append(("bytes-drop", 0x22, len(case[2])))
        if mut == "value_first":
            events.reverse()
        return tuple(events)
    if kind in ("authority", "scheme", "path", "protocol"):
        return (("bytes-drop", 0x33, len(case[1])),)
    if kind == "method":
        if case[1] >= 10 and len(case[2]):
            return (("free", len(case[2]), case[2], 0),)
        if mut == "free_inline" and case[1] == 9:
            return (("free", 0, b"", 0),)
        return ()
    return ()


class DropRig(HdrRig):
    def __init__(self, image, patches=None, byte_overrides=None):
        super().__init__(image, patches, byte_overrides)
        m = self.m
        m.real = frozenset(set(m.real) | {F_DROP_HDR, F_DROP_METHOD})
        m.calls.pop(F_DROP_HDR, None)
        assert image.relative()[0x64DF4A0] == F_FREE
        m.memory.statics[0x64DF4A0] = F_FREE
        m.slots[F_FREE] = self.free

    def vt_drop(self, m):
        self.events.append(("bytes-drop", m.memory.read(m.regs[RDI], 8), m.regs[RDX]))

    def free(self, m):
        self.events.append(("free", m.regs[RSI], m.memory.bytes_at(m.regs[RDI], m.regs[RSI]), m.regs[RDX]))

    def run_drop(self, case):
        mem = self.m.memory
        self.load(b"")
        self.prepare()
        mem.write(VT_AT + 0x20, 8, FAKE_BYTES_DROP)
        self.events = []
        if case[0] == "raw":
            put_entry(self.heap, HDR_AT, ("status", 200))
            mem.write(HDR_AT + 0x40, 1, case[1])
            target = F_DROP_HDR
        elif case[0] == "only-method":
            put_entry(self.heap, HDR_AT, case[1])
            target = F_DROP_METHOD
        else:
            put_entry(self.heap, HDR_AT, case)
            if case[0] == "protocol":
                mem.write(HDR_AT + 0x40, 1, 6)
            target = F_DROP_HDR
        bad = self.go(target, {RDI: HDR_AT})
        if bad:
            return (bad,)
        return tuple(self.events)


def drop_cases(count, seed=0x1161):
    rng = Xorshift(seed)
    for kind in range(9, 256):
        yield ("raw", kind)
    for tag in range(0, 13):
        yield ("only-method", ("method", tag, b"") if tag >= 10 else ("method", tag, 1, 2, 3))
        yield ("only-method", ("method", tag, b"GRAB") if tag >= 10 else ("method", tag, 1, 2, 3))
    yield ("method", 10, b"")
    yield ("authority", b"")
    yield ("field", ("custom", b""), b"")
    for _ in range(count):
        entry = random_entry(rng)
        pick = rng.below(8)
        if entry[0] == "scheme" and pick == 0:
            entry = ("protocol", entry[1])
        if pick == 1 and entry[0] == "method" and entry[1] < 10:
            entry = ("method", 10, random_bytes(rng, 5))
        if pick == 2 and entry[0] == "method":
            yield ("only-method", entry)
            continue
        yield entry


# ------------------------------------ main ------------------------------------

def build(out):
    image = load_image(BINARY, SHA256)
    table = read_table(image)
    os.makedirs(out, exist_ok=True)
    counters = {"int": 0, "huffman": 0, "string": 0, "get": 0, "literal": 0, "idx": 0, "name": 0, "drop": 0}
    coverage = set()
    with open(os.path.join(out, "cases.tsv"), "w", newline="\n") as handle:
        handle.write("kind\tinput\tresult\n")
        stream_checks(image, table, handle.write, counters, coverage)
    with open(os.path.join(out, "table-summary.tsv"), "w", newline="\n") as handle:
        handle.writelines(table_summary(table))
    with open(os.path.join(out, "static-rows.tsv"), "w", newline="\n") as handle:
        write_static_rows(image, handle.write)
    with open(os.path.join(out, "call-sites.tsv"), "w", newline="\n") as handle:
        handle.write("callee\tcallee_va\tcall_va\tprefix_imm\n")
        for name, va in (("decode_int", F_INT), ("huffman_decode", F_HUFF), ("decode_string", F_STRING),
                         ("table_get", F_GET), ("decode_literal", F_LITERAL), ("header_clone", F_CLONE)):
            for site in call_sites(image, va):
                imm = prefix_immediate(image, site) if name == "decode_int" else None
                if name == "decode_literal":
                    imm = prefix_immediate(image, site, 0xB9)
                handle.write("%s\t%#x\t%#x\t%s\n" % (name, va, site, "-" if imm is None else imm))
    with open(os.path.join(out, "controls.tsv"), "w", newline="\n") as handle, \
            open(os.path.join(out, "equivalent-mutants.tsv"), "w", newline="\n") as equiv:
        handle.write("style\ttarget\taddress\tchange\tverdict\tfirst_difference\n")
        equiv.write("mutant\tchange\treason\n")
        total, detected, equivalent = run_controls(image, table, handle.write, equiv.write)
    cases = sum(counters.values())
    summary = {"cases": cases, "negative_controls": total, "negative_detected": detected, "equivalent": equivalent,
               "cases_by_kind": counters, "binary_sha256": SHA256, "table_va": TABLE_VA,
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
