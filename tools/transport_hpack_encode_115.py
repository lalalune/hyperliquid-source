#!/usr/bin/env python3
"""Replay the HPACK Huffman / string / literal encoders of node #115 (vendored h2 crate) on the real image bytes.

Observed: three function bodies (0x179d760 huffman encode, 0x17acf90 length-prefixed string literal, 0x17ad380 literal with an indexed
name) are interpreted from the ELF bytes by the offline x86-64 interpreter below (Image, decode, Memory, Machine), with only the
BytesMut reserve / put_slice slots and the panic slots modelled. Their output is compared with an independent model of the wire
format for every generated case; code mutants, table mutants and a tampered image are the negative controls.

    python3 tools/transport_hpack_encode_115.py --out research/work-items/transport-hpack-encode-115
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




# ---------------------------------------------------------------------------------------------------------------------------------
# Packet section: HPACK string / literal wire encoders of the vendored h2 crate, replayed on the real node #115 bytes.
# ---------------------------------------------------------------------------------------------------------------------------------

import argparse  # noqa: E402
import json  # noqa: E402
import random  # noqa: E402
from fractions import Fraction  # noqa: E402

WORK_NAME = "transport-hpack-encode-115"
F_HUFFMAN = 0x179D760
F_STRING = 0x17ACF90
F_LITERAL = 0x17AD380
FUNCTIONS = (
    ("huffman_encode", F_HUFFMAN, "append the Huffman code of every source byte to a BytesMut, pad the last byte with ones"),
    ("encode_str", F_STRING, "length-prefixed Huffman string literal: 0x80|len, or 0xff plus a 7-bit continuation varint"),
    ("encode_literal_name_index", F_LITERAL, "literal header field with an indexed name: 4-bit prefix index then encode_str of the value"),
)
TABLE_VA = 0x487490
TABLE_SYMBOLS = 257
SLOT_RESERVE = 0x64DFC90
SLOT_PUT = 0x64E0670
SLOT_PANICS = (0x64DF520, 0x64DF620, 0x64DF840, 0x64DF848, 0x64DF898)
STRUCT_AT = HEAP_BASE + 0x40
SRC_AT = HEAP_BASE + 0x1000
ARENA_AT = HEAP_BASE + 0x40000
ARENA_END = HEAP_BASE + HEAP_SIZE - 0x100

CASE_PLAN = (
    ("huffman-single", 256),
    ("huffman-random", 1900),
    ("string-sweep", 420),
    ("string-boundary", 40),
    ("string-random", 3100),
    ("literal-sweep", 900),
    ("literal-boundary", 120),
    ("literal-random", 3400),
    ("string-huge", 3),
)
SAMPLE_EVERY = 2
SAMPLE_MAX_OUT = 64
PROBE_KINDS = ("huffman-single", "string-sweep", "string-boundary", "literal-boundary", "string-random", "literal-random")
PROBE_STRIDE = 31


class Panic(Exception):
    pass


# ----- reference model (independent of the emulator, written from the wire format) -----

def read_table(image):
    base = image.offset(TABLE_VA)
    return [struct.unpack_from("<QQ", image.blob, base + 16 * index) for index in range(TABLE_SYMBOLS)]


def huffman_ref(table, data):
    accumulator = count = 0
    out = bytearray()
    for byte in data:
        bits, code = table[byte]
        accumulator = accumulator << bits | code
        count += bits
        while count >= 8:
            count -= 8
            out.append(accumulator >> count & 0xFF)
        accumulator &= (1 << count) - 1
    if count:
        out.append((accumulator << (8 - count) | (1 << (8 - count)) - 1) & 0xFF)
    return bytes(out)


def varint_ref(value):
    out = bytearray()
    while value >= 0x80:
        out.append(value & 0x7F | 0x80)
        value >>= 7
    out.append(value)
    return bytes(out)


def string_ref(table, data):
    if not data:
        return b"\x00"
    body = huffman_ref(table, data)
    head = bytes([0x80 | len(body)]) if len(body) < 127 else b"\xff" + varint_ref(len(body) - 127)
    return head + body


def literal_ref(table, index, value, sensitive):
    flag = 0x10 if sensitive else 0x00
    head = bytes([flag | index]) if index <= 14 else bytes([flag | 0x0F]) + varint_ref(index - 15)
    return head + string_ref(table, value)


def expected_bytes(table, case):
    kind = case["kind"]
    if kind.startswith("huffman"):
        return huffman_ref(table, case["data"])
    if kind.startswith("string"):
        return string_ref(table, case["data"])
    return literal_ref(table, case["index"], case["data"], case["sensitive"])


# ----- emulated functions -----

class Harness:
    """The real function bodies run on the image; only the BytesMut slots and the panic slots are modelled."""

    def __init__(self, image, patches=None, table_patch=None):
        self.image = image
        machine = Machine(image, patches)
        self.machine = machine
        machine.real = frozenset({F_HUFFMAN, F_STRING})
        statics = machine.memory.statics
        hooks = [(SLOT_RESERVE, self.on_reserve), (SLOT_PUT, self.on_put)]
        hooks += [(slot, self.on_panic) for slot in SLOT_PANICS]
        for slot, hook in hooks:
            statics[slot] = MARK_BASE + slot
            machine.slots[MARK_BASE + slot] = hook
        for address, value in (table_patch or {}).items():
            statics[address] = value
        self.reserve_calls = self.put_calls = 0
        self.arena = ARENA_AT

    def on_panic(self, machine):
        raise Panic("panic slot")

    def state(self):
        memory = self.machine.memory
        return memory.read(STRUCT_AT, 8), memory.read(STRUCT_AT + 8, 8), memory.read(STRUCT_AT + 16, 8)

    def grow(self, dst, add):
        memory = self.machine.memory
        pointer, length, capacity = memory.read(dst, 8), memory.read(dst + 8, 8), memory.read(dst + 16, 8)
        if capacity - length >= add:
            return
        new_capacity = max(capacity * 2, length + add, 64)
        if self.arena + new_capacity > ARENA_END:
            raise Halt("arena exhausted")
        fresh = self.arena
        self.arena += new_capacity + 16
        memory.put_bytes(fresh, bytes([STACK_MARK]) * new_capacity)
        memory.copy(fresh, pointer, length)
        memory.write(dst, 8, fresh)
        memory.write(dst + 16, 8, new_capacity)

    def on_reserve(self, machine):
        if machine.regs[RDX] != 1:
            raise Halt("reserve slot called with an unmodelled second argument")
        self.reserve_calls += 1
        self.grow(machine.regs[RDI], machine.regs[RSI])
        machine.regs[RAX] = 1

    def on_put(self, machine):
        self.put_calls += 1
        dst, src, count = machine.regs[RDI], machine.regs[RSI], machine.regs[RDX]
        memory = machine.memory
        self.grow(dst, count)
        pointer, length = memory.read(dst, 8), memory.read(dst + 8, 8)
        memory.copy(pointer + length, src, count)
        memory.write(dst + 8, 8, length + count)

    def prepare(self, prefix, spare, data):
        memory = self.machine.memory
        self.arena = ARENA_AT
        capacity = len(prefix) + spare
        pointer = self.arena
        self.arena += capacity + 16
        memory.put_bytes(pointer, prefix + bytes([STACK_MARK]) * spare)
        memory.write(STRUCT_AT, 8, pointer)
        memory.write(STRUCT_AT + 8, 8, len(prefix))
        memory.write(STRUCT_AT + 16, 8, capacity)
        if data:
            memory.put_bytes(SRC_AT, data)

    def run_case(self, case):
        machine = self.machine
        self.prepare(case["prefix"], case["spare"], case["data"])
        machine.step_limit = 6000 + 400 * len(case["data"])
        before = machine.steps
        kind = case["kind"]
        if kind.startswith("huffman"):
            machine.run(F_HUFFMAN, {RDI: SRC_AT, RSI: len(case["data"]), RDX: STRUCT_AT})
        elif kind.startswith("string"):
            machine.run(F_STRING, {RDI: SRC_AT, RSI: len(case["data"]), RDX: STRUCT_AT})
        else:
            machine.run(F_LITERAL, {RDI: case["index"], RSI: SRC_AT, RDX: len(case["data"]), RCX: int(case["sensitive"]), R8: STRUCT_AT})
        pointer, length, _ = self.state()
        out = machine.memory.bytes_at(pointer, length)
        return out[len(case["prefix"]):], out[:len(case["prefix"])], machine.steps - before


# ----- case generation (deterministic) -----

ALPHABETS = (
    b"0123456789",
    b"abcdefghijklmnopqrstuvwxyz",
    b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-._~:/?#[]@!$&'()*+,;=% ",
    bytes(range(256)),
    bytes(range(128, 256)),
    bytes(range(0, 32)),
)


def make_case(kind, data, index=0, sensitive=False, prefix=b"", spare=4096):
    return {"kind": kind, "data": bytes(data), "index": index, "sensitive": sensitive, "prefix": bytes(prefix), "spare": spare}


def random_data(rng, limit):
    alphabet = ALPHABETS[rng.randrange(len(ALPHABETS))]
    return bytes(alphabet[rng.randrange(len(alphabet))] for _ in range(rng.randrange(limit + 1)))


def random_dst(rng):
    prefix = bytes(rng.randrange(256) for _ in range(rng.choice((0, 0, 1, 2, 5, 9))))
    return prefix, rng.choice((0, 0, 1, 2, 7, 33, 4096))


def cases(table):
    """Yield (kind, case) in a fixed order; generation never depends on emulation results."""
    rng = random.Random(1155)
    for symbol in range(256):
        yield make_case("huffman-single", bytes([symbol]), spare=symbol % 3)
    for _ in range(dict(CASE_PLAN)["huffman-random"]):
        prefix, spare = random_dst(rng)
        yield make_case("huffman-random", random_data(rng, 30), prefix=prefix, spare=spare)
    for length in range(dict(CASE_PLAN)["string-sweep"]):
        yield make_case("string-sweep", b"0" * length, spare=(length * 7) % 5)
    boundaries = []
    for target in (125, 126, 127, 128, 129, 253, 254, 255, 256, 257):
        count = 0
        while len(huffman_ref(table, b"0" * count)) < target:
            count += 1
        boundaries += [count, count + 1]
    for count in boundaries[:20]:
        yield make_case("string-boundary", b"0" * count)
    for count in boundaries[:20]:
        yield make_case("string-boundary", b"e" * (count + 3), prefix=b"\xaa\xbb", spare=0)
    for _ in range(dict(CASE_PLAN)["string-random"]):
        prefix, spare = random_dst(rng)
        yield make_case("string-random", random_data(rng, 50), prefix=prefix, spare=spare)
    for index in range(150):
        for sensitive in (False, True):
            for value in (b"", b"www.example.com", bytes(range(index % 200, index % 200 + 4))):
                yield make_case("literal-sweep", value, index=index, sensitive=sensitive, spare=index % 4)
    for index in (14, 15, 16, 142, 143, 144, 145, 16398, 16399, 16400, 2097166, 2097167, 2097168, 1 << 28, (1 << 28) + 15,
                  (1 << 35) + 14, (1 << 35) + 15, (1 << 42) + 16, (1 << 49) + 15, (1 << 56) + 15):
        for sensitive in (False, True):
            for value in (b"", b"no-cache", b"custom-value-" + bytes([index & 0x7F])):
                yield make_case("literal-boundary", value, index=index, sensitive=sensitive, spare=0)
    for _ in range(dict(CASE_PLAN)["literal-random"]):
        prefix, spare = random_dst(rng)
        index = rng.choice((rng.randrange(0, 20), rng.randrange(0, 5000), rng.randrange(1 << 30)))
        yield make_case("literal-random", random_data(rng, 40), index=index, sensitive=bool(rng.randrange(2)), prefix=prefix, spare=spare)
    for first, target in ((b"a", 16510), (b"a", 16511), (b"\xff", 16511)):
        # hlen == target exactly: value = target - 127 sits on the 2-byte / 3-byte varint boundary (0x3fff / 0x4000)
        count = 0
        while -(-(table[first[0]][0] + 5 * count) // 8) < target:
            count += 1
        yield make_case("string-huge", first + b"0" * count, spare=0)


# ----- evaluation -----

def evaluate(image, table, patches=None, table_patch=None, selection=None, stop_on_mismatch=False):
    """Run cases through the emulator. Returns summary dict; a case fails on any difference, exception or halt."""
    harness = Harness(image, patches, table_patch)
    summary = {"cases": 0, "mismatch": 0, "first_bad": None, "steps": 0, "by_kind": {}}
    digest = hashlib.sha256()
    sample = []
    for number, case in enumerate(cases(table)):
        if selection is not None and not selection(number, case):
            continue
        want = expected_bytes(table, case)
        try:
            got, kept, steps = harness.run_case(case)
            ok = got == want and kept == case["prefix"]
        except (Halt, Panic, EvidenceError, struct.error, KeyError, IndexError) as error:
            got, kept, steps, ok = ("error: " + type(error).__name__).encode(), b"", 0, False
        summary["cases"] += 1
        row = summary["by_kind"].setdefault(case["kind"], [0, 0, 0])
        row[0] += 1
        row[1] += steps
        summary["steps"] += steps
        digest.update(b"%d:%s\n" % (number, want.hex().encode()))
        if not ok:
            row[2] += 1
            summary["mismatch"] += 1
            if summary["first_bad"] is None:
                summary["first_bad"] = number
            if stop_on_mismatch:
                break
        elif number % SAMPLE_EVERY == 0 and len(want) <= SAMPLE_MAX_OUT and len(case["data"]) <= 60:
            sample.append((number, case, want, steps))
    summary["digest"] = digest.hexdigest()
    summary["reserve_calls"], summary["put_calls"] = harness.reserve_calls, harness.put_calls
    summary["seen"] = harness.machine.seen
    summary["sample"] = sample
    return summary


def probe_selection(number, case):
    return case["kind"] in PROBE_KINDS and number % PROBE_STRIDE == 0 or case["kind"] in ("string-boundary", "literal-boundary")


def heavy_selection(number, case):
    return case["kind"] in ("string-huge", "string-boundary")


# ----- negative controls -----

def function_rows(image):
    result = {}
    for name, entry, _ in FUNCTIONS:
        result[name] = decode_range(image, entry, image.fde_ends[entry])
    return result


def wide_compare(row, image):
    """A compare against a bound of 0x10000 or more only differs for inputs larger than the 4 MB emulator heap, so it is not mutated."""
    if row.op != "cmp" or row.imm_size is None:
        return False
    value = int.from_bytes(image.blob[image.offset(row.va + row.imm_at):image.offset(row.va + row.imm_at) + row.imm_size], "little", signed=True)
    return abs(value) >= 0x10000


def stack_frame_row(row):
    return row.op in ("sub", "add") and row.a == ("r", RSP)


def mutant_list(image, seen):
    """Single-byte code mutants of executed instructions plus table-entry mutants, in a fixed order."""
    rows = function_rows(image)
    jcc, imm = [], []
    for name, entry, _ in FUNCTIONS:
        for row in rows[name]:
            if row.va not in seen:
                continue
            if row.op == "jcc":
                at = row.va if row.size == 2 else row.va + 1
                jcc.append((name, "jcc-invert", row.va, {at: image.blob[image.offset(at)] ^ 1}))
            elif row.imm_at is not None and not stack_frame_row(row) and row.op not in ("call", "jmp") and not wide_compare(row, image):
                at = row.va + row.imm_at
                imm.append((name, "imm-low-bit", row.va, {at: image.blob[image.offset(at)] ^ 1}))
    stride = max(1, len(imm) // 70)
    mutants = [(n, f, v, p, None) for n, f, v, p in jcc] + [(n, f, v, p, None) for n, f, v, p in imm[::stride]]
    for symbol in (0, 0x30, 0x61, 0x7F, 0x80, 0xFF):
        bits, code = struct.unpack_from("<QQ", image.blob, image.offset(TABLE_VA + 16 * symbol))
        mutants.append(("table", "table-bits+1", TABLE_VA + 16 * symbol, None, {TABLE_VA + 16 * symbol: bits + 1}))
        mutants.append(("table", "table-code^1", TABLE_VA + 16 * symbol + 8, None, {TABLE_VA + 16 * symbol + 8: code ^ 1}))
    return mutants


def run_controls(image, table, seen):
    rows = []
    for name, family, address, patches, table_patch in mutant_list(image, seen):
        verdict = "undetected"
        by = ""
        claimed = (name, family, address) in EQUIVALENT_REASONS
        for label, selection in (("probe", probe_selection),) if claimed else (("probe", probe_selection), ("heavy", heavy_selection)):
            result = evaluate(image, table, patches, table_patch, selection, stop_on_mismatch=True)
            if result["mismatch"]:
                verdict, by = "detected", "%s case %d" % (label, result["first_bad"])
                break
        if verdict == "undetected" and (name, family, address) in EQUIVALENT_REASONS:
            wide = evaluate(image, table, patches, table_patch, lambda number, case: number % WIDE_STRIDE == 0, stop_on_mismatch=True)
            if wide["mismatch"]:
                verdict, by = "detected", "wide case %d" % wide["first_bad"]
            else:
                by = "equivalent: no difference on %d wide cases" % wide["cases"]
        rows.append((name, family, address, patches, table_patch, verdict, by))
    return rows


EQUIVALENT_REASONS = {
    ("huffman_encode", "imm-low-bit", 0x179D7CF): "shift-count guard cmp r12,0x40: r12 = 0x28 - pending bits never exceeds 0x28, so bound 0x40 or 0x41 never fires",
    ("huffman_encode", "imm-low-bit", 0x179D83B): "output-length overflow guard cmp rax,-1: a BytesMut length cannot reach usize::MAX, so -1 or -2 never fires",
    ("huffman_encode", "imm-low-bit", 0x179D855): "flush loop continues while old offset < 0x19 (0x18): a full byte left pending at offset 0x18 is emitted by the next flush or by the final padding step; the 40-bit window still holds 8 + 30 bits",
    ("encode_str", "imm-low-bit", 0x17ACFB0): "the placeholder length byte pushed before the Huffman body is overwritten on every path (0x80|len, or 0xff), so its initial value is never observable",
    ("encode_str", "imm-low-bit", 0x17AD139): "bounds guard for the right shift of the body: lower bound pos+9-k is the first destination index, every destination index is >= it, so a bound one lower never fires",
}
WIDE_STRIDE = 20


# ----- evidence files -----

def table_checks(table):
    kraft = sum(Fraction(1, 1 << bits) for bits, _ in table)
    entries = sorted((code << (32 - bits), bits, symbol) for symbol, (bits, code) in enumerate(table))
    prefix_free = all(not (right[0] >> (32 - left[1]) == left[0] >> (32 - left[1]))
                      for left, right in zip(entries, entries[1:]))
    anchors = {0x30: (5, 0x0), 0x61: (5, 0x3), 0x20: (6, 0x14), 0x00: (13, 0x1FF8), 256: (30, 0x3FFFFFFF)}
    rows = [("kraft_sum", str(kraft), "ok" if kraft == 1 else "FAIL"),
            ("prefix_free_adjacent_sorted", str(prefix_free), "ok" if prefix_free else "FAIL"),
            ("max_bits", str(max(bits for bits, _ in table)), "ok"),
            ("min_bits", str(min(bits for bits, _ in table)), "ok")]
    for symbol, want in sorted(anchors.items()):
        rows.append(("anchor_%d" % symbol, "%d/%#x" % table[symbol], "ok" if table[symbol] == want else "FAIL"))
    return rows


def write_tsv(path, header, rows):
    with open(path, "w", newline="") as handle:
        handle.write("\t".join(header) + "\n")
        for row in rows:
            handle.write("\t".join(str(cell) for cell in row) + "\n")


def build(out):
    out = pathlib.Path(out)
    out.mkdir(parents=True, exist_ok=True)
    image = load_image()
    table = read_table(image)
    summary = evaluate(image, table)
    if summary["mismatch"]:
        raise EvidenceError("emulation differs from the model on %d cases" % summary["mismatch"])
    seen = summary["seen"]
    rows = function_rows(image)
    function_lines, coverage_lines = [], []
    for name, entry, role in FUNCTIONS:
        end = image.fde_ends[entry]
        body = image.blob[image.offset(entry):image.offset(entry) + end - entry]
        executed = sum(1 for row in rows[name] if row.va in seen)
        function_lines.append((name, "%#x" % entry, "%#x" % end, end - entry, hashlib.sha256(body).hexdigest(), len(rows[name]), executed, role))
        for row in rows[name]:
            coverage_lines.append((name, "%#x" % row.va, row.op, row.data.hex(), int(row.va in seen)))
    write_tsv(out / "functions.tsv", ("name", "entry", "fde_end", "bytes", "sha256", "instructions", "executed", "role"), function_lines)
    write_tsv(out / "coverage.tsv", ("function", "va", "op", "bytes", "executed"), coverage_lines)
    write_tsv(out / "huffman-table.tsv", ("symbol", "bits", "code"), [(index, bits, "%#x" % code) for index, (bits, code) in enumerate(table)])
    write_tsv(out / "table-checks.tsv", ("check", "value", "result"), table_checks(table))
    write_tsv(out / "cases-sample.tsv", ("case", "kind", "index", "sensitive", "prefix", "spare", "input", "expected_equals_emulated", "steps"),
              [(number, case["kind"], case["index"], int(case["sensitive"]), case["prefix"].hex(), case["spare"], case["data"].hex(), want.hex(), steps)
               for number, case, want, steps in summary["sample"]])
    write_tsv(out / "digest.tsv", ("kind", "cases", "steps", "mismatches"),
              [(kind, row[0], row[1], row[2]) for kind, row in sorted(summary["by_kind"].items())]
              + [("all", summary["cases"], summary["steps"], summary["mismatch"]), ("expected-digest", summary["digest"], summary["reserve_calls"], summary["put_calls"])])
    controls = run_controls(image, table, seen)
    detected = [row for row in controls if row[5] == "detected"]
    surviving = [row for row in controls if row[5] != "detected"]
    equivalent = [row for row in surviving if (row[0], row[1], row[2]) in EQUIVALENT_REASONS]
    unexplained = [row for row in surviving if (row[0], row[1], row[2]) not in EQUIVALENT_REASONS]
    write_tsv(out / "controls.tsv", ("id", "function", "family", "address", "change", "verdict", "first_difference"),
              [(index, row[0], row[1], "%#x" % row[2], ",".join("%#x=%#04x" % item for item in sorted((row[3] or row[4]).items())), row[5], row[6])
               for index, row in enumerate(controls)])
    write_tsv(out / "equivalent-mutants.tsv", ("function", "family", "address", "reason"),
              [(row[0], row[1], "%#x" % row[2], EQUIVALENT_REASONS[(row[0], row[1], row[2])]) for row in equivalent])
    measure = {"cases": summary["cases"], "negative_controls": len(controls), "negative_detected": len(detected), "equivalent": len(equivalent),
               "unexplained_survivors": [("%s %s %#x" % (row[0], row[1], row[2])) for row in unexplained],
               "steps": summary["steps"], "expected_digest": summary["digest"]}
    (out / "measure.json").write_text(json.dumps(measure, indent=1, sort_keys=True) + "\n")
    return measure


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", required=True, help="work-item folder that receives every generated evidence file")
    args = parser.parse_args(argv)
    measure = build(args.out)
    print(json.dumps({key: measure[key] for key in ("cases", "negative_controls", "negative_detected", "equivalent")}))
    return 0


if __name__ == "__main__":
    sys.exit(main())
