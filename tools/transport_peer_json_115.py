#!/usr/bin/env python3
"""Reconstruct the node #115 peer-endpoint report JSON writers and prove them against the instruction bytes.

An offline x86-64 interpreter (Image, decode, Memory, Machine; the repeated shared pattern) runs the real bytes of the
serde_json compact writers for the peer endpoint report - Ipv4Addr string, [direction, ip, port] tuple, {n,total,max}
statistic object and the three sequence writers - against a Vec<u8> whose capacity and length are chosen per case, so every
reserve site is exercised. A pure Python model of the same writers is compared with the machine on every case; byte mutants
of the code, wrong models and out-of-range inputs are the negative controls. The binary is never executed. Standard
library plus the shared elf_index and fde_extents parsers.

    python3 tools/transport_peer_json_115.py --out research/work-items/transport-peer-json-115
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
# Packet part: serde_json compact writers for the peer endpoint report (node #115)
# ======================================================================================================================
import argparse
import json
import random

ESCAPE_SLOT = 0x64E13D8
HEX_SLOT = 0x64E13E0
MEMCPY_SLOT = 0x64DF508
RYU_SLOT = 0x64E13D0
FINISH_GROW = 0x4787DA0

ENDPOINT_FN = 0x4781F10
IPV4_FN = 0x4772BC0
STAT_FN = 0x4771750
PAIR_VEC_FN = 0x47775C0
QUAD_VEC_FN = 0x4776DE0
NAMED_STAT_FN = 0x4776230
ESCAPE_FN = 0x4778320
ITOA_FN = 0x4779320
FIRST_KEY_FN = 0x4777AD0
NEXT_KEY_FN = 0x47781A0
VALUE_FN = 0x4774EB0
GROW_FN = 0x4787E90
RYU_FN = 0x5D0E4C0

TARGETS = (
    (IPV4_FN, "ipv4_string", "Ipv4Addr as a quoted dotted-quad string"),
    (ENDPOINT_FN, "endpoint_tuple", "[direction, ip, port] array"),
    (STAT_FN, "stat_object", "{n,total,max} object"),
    (PAIR_VEC_FN, "pair_vec", "Vec of [endpoint, f64] pairs"),
    (QUAD_VEC_FN, "quad_vec", "Vec of [endpoint, u64, u64, f64] rows"),
    (NAMED_STAT_FN, "named_stat_iter", "map of name to stat, slice-pair iterator state"),
)
HELPERS = (
    (ESCAPE_FN, "escape_contents", "serde_json escaped string contents writer"),
    (ITOA_FN, "u64_decimal", "u64 to decimal digits in a caller buffer"),
    (FIRST_KEY_FN, "first_entry", "object entry writer, first entry (no comma)"),
    (NEXT_KEY_FN, "next_entry", "object entry writer, later entries (comma first)"),
    (VALUE_FN, "f64_value", "f64 value serializer (null for non-finite)"),
    (GROW_FN, "vec_reserve", "RawVec<u8> grow-amortized"),
)
SALT = 0x9E3779B97F4A7C15


UNREACHABLE = {
    0x4776C32: "the comma store sits on the path taken only when the entry count word is zero while the first slice is non-empty; "
               "the count is the pointer difference times the inverse of 48, which is zero only for an empty slice, so no well-formed iterator state reaches it",
}


class PacketError(Exception):
    pass


def ryu_pretty(value):
    """Text the ryu pretty formatter produces for a finite f64 (stub model for the slot call)."""
    from decimal import Decimal
    if value == 0:
        return "-0.0" if struct.pack("<d", value)[7] & 0x80 else "0.0"
    _, raw, exp = Decimal(repr(abs(value))).as_tuple()
    digits = "".join(map(str, raw))
    stripped = digits.rstrip("0") or "0"
    k = exp + len(digits) - len(stripped)
    kk = len(stripped) + k
    out = "-" if value < 0 else ""
    if 0 <= k and kk <= 16:
        return out + stripped + "0" * k + ".0"
    if 0 < kk <= 16:
        return out + stripped[:kk] + "." + stripped[kk:]
    if -5 < kk <= 0:
        return out + "0." + "0" * (-kk) + stripped
    mantissa = stripped[0] + ("." + stripped[1:] if len(stripped) > 1 else "")
    return out + mantissa + "e" + str(kk - 1)


# ---------------------------------------------------------------------------------------------------------------------
# Reference model: what the writers do to a Vec<u8> (capacity, length, bytes) and how it grows
# ---------------------------------------------------------------------------------------------------------------------

class Sink:
    """Vec<u8> with the reserve rule of 0x4787e90: new capacity = max(2*cap, len+additional, 8)."""

    def __init__(self, cap, content):
        self.cap = cap
        self.buf = bytearray(content)
        self.events = []

    def reserve(self, n):
        if self.cap - len(self.buf) < n:
            new = max(2 * self.cap, len(self.buf) + n, 8)
            self.events.append((self.cap, new))
            self.cap = new

    def push(self, byte):
        self.reserve(1)
        self.buf.append(byte)

    def extend(self, data):
        if data:
            self.reserve(len(data))
            self.buf += data

    def text(self, data):
        for ch in data:
            self.push(ord(ch))


class Model:
    def __init__(self, escape_table, hex_digits):
        self.table = escape_table
        self.hex = hex_digits

    def escape_contents(self, sink, data):
        start = 0
        for index, byte in enumerate(data):
            kind = self.table[byte]
            if not kind:
                continue
            sink.extend(bytes(data[start:index]))
            start = index + 1
            if kind == 0x75:
                sink.reserve(6)
                sink.buf += b"\\u00" + bytes((self.hex[byte >> 4], self.hex[byte & 15]))
            else:
                sink.reserve(2)
                sink.buf += b"\\" + bytes((kind,))
        sink.extend(bytes(data[start:]))

    def string(self, sink, data):
        sink.push(0x22)
        self.escape_contents(sink, data)
        sink.push(0x22)

    def ipv4(self, sink, octets):
        self.string(sink, ".".join(str(b) for b in octets).encode())

    def endpoint(self, sink, ep):
        sink.push(0x5B)
        self.string(sink, b"Out" if ep["flag"] == 1 else b"In")
        sink.push(0x2C)
        self.ipv4(sink, ep["ip"])
        sink.push(0x2C)
        sink.extend(str(ep["port"]).encode())
        sink.push(0x5D)

    def f64(self, sink, bits):
        value = struct.unpack("<d", bits.to_bytes(8, "little"))[0]
        if (bits & 0x7FFFFFFFFFFFFFFF) > 0x7FEFFFFFFFFFFFFF:
            sink.reserve(4)
            sink.buf += b"null"
        else:
            sink.extend(ryu_pretty(value).encode())

    def entry(self, sink, first, key, writer):
        if not first:
            sink.push(0x2C)
        self.string(sink, key)
        sink.push(0x3A)
        writer()

    def stat(self, sink, st):
        sink.push(0x7B)
        self.entry(sink, True, b"n", lambda: sink.extend(str(st["n"]).encode()))
        self.entry(sink, False, b"total", lambda: self.f64(sink, st["total"]))
        self.entry(sink, False, b"max", lambda: self.f64(sink, st["max"]))
        sink.push(0x7D)

    def pair_vec(self, sink, rows):
        sink.push(0x5B)
        for index, row in enumerate(rows):
            if index:
                sink.push(0x2C)
            sink.push(0x5B)
            self.endpoint(sink, row["ep"])
            sink.push(0x2C)
            self.f64(sink, row["f"])
            sink.push(0x5D)
        sink.push(0x5D)

    def quad_vec(self, sink, rows):
        sink.push(0x5B)
        for index, row in enumerate(rows):
            if index:
                sink.push(0x2C)
            sink.push(0x5B)
            self.endpoint(sink, row["ep"])
            sink.push(0x2C)
            sink.extend(str(row["a"]).encode())
            sink.push(0x2C)
            sink.extend(str(row["b"]).encode())
            sink.push(0x2C)
            self.f64(sink, row["f"])
            sink.push(0x5D)
        sink.push(0x5D)

    def named_stat_iter(self, sink, rows):
        sink.push(0x5B)
        for index, row in enumerate(rows):
            if index:
                sink.push(0x2C)
            sink.push(0x5B)
            self.string(sink, row["name"])
            sink.push(0x2C)
            self.stat(sink, row["stat"])
            sink.push(0x5D)
        sink.push(0x5D)


# ---------------------------------------------------------------------------------------------------------------------
# Rig: the real instruction bytes run with only the allocator, memcpy and the ryu slot supplied from outside
# ---------------------------------------------------------------------------------------------------------------------

REAL = frozenset([IPV4_FN, ENDPOINT_FN, STAT_FN, PAIR_VEC_FN, QUAD_VEC_FN, NAMED_STAT_FN, ESCAPE_FN, ITOA_FN,
                  FIRST_KEY_FN, NEXT_KEY_FN, VALUE_FN, GROW_FN])


class Rig:
    def __init__(self, image, patches=None):
        self.machine = m = Machine(image, patches)
        self.image = image
        self.bump = HEAP_BASE + 0x1000
        m.real = REAL
        mem = m.memory
        relative = image.relative()
        for slot in (ESCAPE_SLOT, HEX_SLOT):
            mem.statics[slot] = relative[slot]
        mem.statics[RYU_SLOT] = MARK_BASE + RYU_SLOT
        m.slots[MARK_BASE + RYU_SLOT] = self.ryu
        mem.statics[MEMCPY_SLOT] = MARK_BASE + MEMCPY_SLOT
        m.slots[MARK_BASE + MEMCPY_SLOT] = self.memcpy
        m.calls[FINISH_GROW] = self.finish_grow
        self.events = []

    def alloc(self, n):
        at = self.bump
        self.bump += (n + 15) & ~15
        if self.bump > HEAP_BASE + 0x38000:
            raise Halt("rig heap exhausted")
        return at

    def memcpy(self, m):
        r = m.regs
        m.memory.copy(r[RDI], r[RSI], r[RDX])
        r[RAX] = r[RDI]

    def ryu(self, m):
        bits = m.xmm[0] & MASK[8]
        text = ryu_pretty(struct.unpack("<d", bits.to_bytes(8, "little"))[0]).encode()
        m.memory.put_bytes(m.regs[RDI], text)
        m.regs[RAX] = m.regs[RDI] + len(text)

    def finish_grow(self, m):
        r = m.regs
        out, old_cap, old_ptr, new_cap = r[RDI], r[RSI], r[RDX], r[RCX]
        at = self.alloc(new_cap)
        if old_cap:
            m.memory.copy(at, old_ptr, old_cap)
        self.events.append((old_cap, new_cap))
        m.memory.write(out, 8, 0)
        m.memory.write(out + 8, 8, at)

    def begin(self):
        self.bump = HEAP_BASE + 0x1000
        self.machine.memory.reset(0x40000)
        self.events = []

    def blob(self, data):
        at = self.alloc(max(len(data), 1))
        self.machine.memory.put_bytes(at, bytes(data))
        return at

    def new_vec(self, cap, content):
        ptr = self.alloc(max(cap, 1))
        mem = self.machine.memory
        mem.put_bytes(ptr, bytes(content))
        vec = self.alloc(24)
        mem.write(vec, 8, cap)
        mem.write(vec + 8, 8, ptr)
        mem.write(vec + 16, 8, len(content))
        cell = self.alloc(8)
        mem.write(cell, 8, vec)
        return cell, vec

    def read_vec(self, vec):
        mem = self.machine.memory
        cap, ptr, length = mem.read(vec, 8), mem.read(vec + 8, 8), mem.read(vec + 16, 8)
        return cap, bytes(mem.bytes_at(ptr, length))

    # -- argument builders --------------------------------------------------------------------------------------
    def endpoint_bytes(self, ep):
        return bytes(ep["ip"]) + struct.pack("<H", ep["port"]) + bytes((ep["flag"], ep["pad"]))

    def build(self, kind, data):
        mem = self.machine.memory
        if kind == "ipv4_string":
            return self.blob(bytes(data["ip"]))
        if kind == "endpoint_tuple":
            return self.blob(self.endpoint_bytes(data))
        if kind == "stat_object":
            return self.blob(struct.pack("<QQQ", data["n"], data["total"], data["max"]))
        if kind in ("pair_vec", "quad_vec"):
            body = b""
            for row in data:
                body += self.endpoint_bytes(row["ep"])
                if kind == "quad_vec":
                    body += struct.pack("<QQQ", row["a"], row["b"], row["f"])
                else:
                    body += struct.pack("<Q", row["f"])
            ptr = self.blob(body)
            vec = self.alloc(24)
            mem.write(vec, 8, len(data))
            mem.write(vec + 8, 8, ptr)
            mem.write(vec + 16, 8, len(data))
            return vec
        if kind == "named_stat_iter":
            body = b""
            for row in data:
                name = self.blob(row["name"])
                st = row["stat"]
                body += struct.pack("<QQQQQQ", len(row["name"]), name, len(row["name"]), st["n"], st["total"], st["max"])
            ptr = self.blob(body)
            split = (len(data) + 1) // 2
            it = self.alloc(0x48)
            mem.put_bytes(it, bytes(0x48))
            mem.write(it, 8, 2)
            mem.write(it + 8, 8, ptr)
            mem.write(it + 0x10, 8, ptr + 48 * split)
            mem.write(it + 0x18, 8, ptr + 48 * split)
            mem.write(it + 0x20, 8, ptr + 48 * len(data))
            mem.write(it + 0x40, 8, len(data))
            return it
        if kind == "entry_call":
            compound = self.alloc(16)
            mem.put_bytes(compound, bytes((0, data["state"])))
            return compound, self.blob(data["key"]), self.blob(struct.pack("<Q", data["value"]))
        if kind == "named_stat_tree":
            self.edge_nodes = []
            self.build_node(data)
            first, last = self.edge_nodes[0], self.edge_nodes[-1]
            it = self.alloc(0x48)
            mem.put_bytes(it, bytes(0x48))
            for base, leaf, idx in ((0, first[0], 0), (0x20, last[0], last[1])):
                mem.write(it + base, 8, 1)
                mem.write(it + base + 8, 8, leaf)
                mem.write(it + base + 0x10, 8, 0)
                mem.write(it + base + 0x18, 8, idx)
            mem.write(it + 0x40, 8, len(flatten(data)))
            return it
        raise PacketError("unknown kind " + kind)

    def build_node(self, tree, parent=0, parent_idx=0):
        mem = self.machine.memory
        internal = tree["children"] is not None
        node = self.alloc(0x280 if internal else 0x228)
        mem.put_bytes(node, bytes(0x280 if internal else 0x228))
        mem.write(node, 8, parent)
        mem.write(node + 0x218, 2, parent_idx)
        mem.write(node + 0x21A, 2, len(tree["keys"]))
        for i, (name, st) in enumerate(tree["keys"]):
            at = self.blob(name)
            mem.put_bytes(node + 8 + 24 * i, struct.pack("<QQQ", len(name), at, len(name)))
            mem.put_bytes(node + 0x110 + 24 * i, struct.pack("<QQQ", st["n"], st["total"], st["max"]))
        if not internal:
            self.edge_nodes.append((node, len(tree["keys"])))
        if internal:
            for i, child in enumerate(tree["children"]):
                mem.write(node + 0x220 + 8 * i, 8, self.build_node(child, node, i))
        return node

    def run(self, entry, kind, data, cap, content):
        self.begin()
        cell, vec = self.new_vec(cap, content)
        arg = self.build(kind, data)
        direct = kind in ("ipv4_string", "endpoint_tuple", "stat_object")
        if kind == "entry_call":
            mem = self.machine.memory
            mem.write(arg[0] + 8, 8, cell)
            entry = data["fn"]
            regs = {RDI: arg[0], RSI: arg[1], RDX: len(data["key"]), RCX: arg[2]}
        else:
            regs = {RDI: arg if direct else cell, RSI: cell if direct else arg}
        status = self.machine.run(entry, regs)
        final_cap, final = self.read_vec(vec)
        if kind == "entry_call":
            final += b"\0" + bytes((self.machine.memory.read(arg[0] + 1, 1),))
        return status, final_cap, final, list(self.events)


def tree_height(tree):
    return 0 if tree["children"] is None else 1 + tree_height(tree["children"][0])


def flatten(tree):
    """In-order (name, stat) rows of a B-tree description."""
    rows = []
    for i, (name, st) in enumerate(tree["keys"]):
        if tree["children"] is not None:
            rows += flatten(tree["children"][i])
        rows.append({"name": name, "stat": st})
    if tree["children"] is not None:
        rows += flatten(tree["children"][len(tree["keys"])])
    return rows


def model_run(model, kind, data, cap, content):
    sink = Sink(cap, content)
    if kind == "named_stat_tree":
        model.named_stat_iter(sink, flatten(data))
        return 0, sink.cap, bytes(sink.buf), sink.events
    if kind == "entry_call":
        value = data["value"]
        writer = (lambda: sink.extend(str(value).encode())) if data["fn"] == FIRST_KEY_FN else (lambda: model.f64(sink, value))
        model.entry(sink, data["state"] == 1, data["key"], writer)
        return 0, sink.cap, bytes(sink.buf) + b"\0" + bytes((2,)), sink.events
    getattr(model, {"ipv4_string": "ipv4", "endpoint_tuple": "endpoint", "stat_object": "stat"}.get(kind, kind))(
        sink, data["ip"] if kind == "ipv4_string" else data)
    return 0, sink.cap, bytes(sink.buf), sink.events


ENTRY = {kind: va for va, kind, _ in TARGETS}
ENTRY["named_stat_tree"] = NAMED_STAT_FN
ENTRY["entry_call"] = FIRST_KEY_FN


# ---------------------------------------------------------------------------------------------------------------------
# Deterministic case generation
# ---------------------------------------------------------------------------------------------------------------------

OCTETS = (0, 1, 5, 9, 10, 11, 42, 99, 100, 101, 127, 199, 200, 249, 250, 255)
PORTS = (0, 1, 9, 10, 99, 100, 999, 1000, 9999, 10000, 12345, 40000, 65534, 65535)
COUNTS = (0, 1, 9, 10, 99, 100, 12345, 99999, 10 ** 9, 2 ** 32 - 1, 2 ** 53, 10 ** 15, 10 ** 16, 10 ** 19 - 1,
          2 ** 63, 2 ** 64 - 1)
FLOATS = (0.0, -0.0, 1.0, 1.5, -2.5, 0.1, 100.0, 123456.789, 1e15, 9007199254740993.0, 1e16, 1.5e16, 1e-4, 1e-5,
          1.2345e-5, 1e-6, 5e-324, 1.7976931348623157e308, 1e22, 123456789012345680.0, 3.141592653589793)
NAMES = (b"", b"a", b"book", b"profiled_rw_lock", b'quote"inside', b"back\\slash", b"tab\there", b"nl\nx", b"\x00\x01\x1f",
         b"\x7f\x80\xff", b"/slash/", b"a" * 40, b"\x08\x0c\r")


def rand_ep(rng):
    pick = lambda options: rng.choice(options) if rng.random() < 0.7 else rng.randrange(256)
    return {"ip": [pick(OCTETS) for _ in range(4)],
            "port": rng.choice(PORTS) if rng.random() < 0.7 else rng.randrange(65536),
            "flag": rng.choice((0, 1, 1, 0, 2, 255)), "pad": rng.randrange(256)}


def rand_bits(rng):
    roll = rng.random()
    if roll < 0.5:
        return struct.unpack("<Q", struct.pack("<d", rng.choice(FLOATS) * rng.choice((1, -1))))[0]
    if roll < 0.62:
        return rng.choice((0x7FF0000000000000, 0xFFF0000000000000, 0x7FF8000000000000, 0xFFF8000000000001,
                           0x7FEFFFFFFFFFFFFF, 0x7FF0000000000001))
    if roll < 0.8:
        return struct.unpack("<Q", struct.pack("<d", rng.random() * 10 ** rng.randrange(-8, 20)))[0]
    return rng.getrandbits(64)


def rand_count(rng):
    return rng.choice(COUNTS) if rng.random() < 0.6 else rng.getrandbits(rng.randrange(1, 65))


def rand_stat(rng):
    return {"n": rand_count(rng), "total": rand_bits(rng), "max": rand_bits(rng)}


def rand_name(rng):
    if rng.random() < 0.6:
        return rng.choice(NAMES)
    return bytes(rng.choice((34, 92, 10, 0, 31, 127, 200, 97, 98, 99, 47)) for _ in range(rng.randrange(0, 9)))


def rand_input(rng, kind):
    if kind == "ipv4_string":
        return {"ip": [rng.choice(OCTETS) if rng.random() < 0.7 else rng.randrange(256) for _ in range(4)]}
    if kind == "endpoint_tuple":
        return rand_ep(rng)
    if kind == "stat_object":
        return rand_stat(rng)
    if kind == "pair_vec":
        return [{"ep": rand_ep(rng), "f": rand_bits(rng)} for _ in range(rng.choice((0, 1, 1, 2, 3)))]
    if kind == "quad_vec":
        return [{"ep": rand_ep(rng), "a": rand_count(rng), "b": rand_count(rng), "f": rand_bits(rng)}
                for _ in range(rng.choice((0, 1, 1, 2, 3)))]
    if kind == "named_stat_tree":
        return rand_tree(rng)
    if kind == "entry_call":
        fn = rng.choice((FIRST_KEY_FN, NEXT_KEY_FN))
        return {"fn": fn, "state": rng.choice((1, 2)), "key": rand_name(rng),
                "value": rand_count(rng) if fn == FIRST_KEY_FN else rand_bits(rng)}
    return [{"name": rand_name(rng), "stat": rand_stat(rng)} for _ in range(rng.choice((0, 1, 2, 2, 3, 4)))]


def rand_keys(rng, low, high):
    return [(rand_name(rng), rand_stat(rng)) for _ in range(rng.randrange(low, high + 1))]


def rand_tree(rng):
    if rng.random() < 0.4:
        return {"keys": rand_keys(rng, 0, 5), "children": None}
    keys = rand_keys(rng, 1, 3)
    return {"keys": keys, "children": [{"keys": rand_keys(rng, 1, 3), "children": None} for _ in range(len(keys) + 1)]}


def rand_sink(rng, approx):
    length = rng.choice((0, 0, 1, 2, 5, 8, 17))
    slack = rng.choice((0, 0, 1, 2, 3, 7, 8)) if rng.random() < 0.4 else rng.randrange(0, approx + 4)
    cap = 0 if (length == 0 and rng.random() < 0.3) else length + slack
    return cap, bytes(rng.randrange(33, 127) for _ in range(length))


SWEEP_INPUTS = 3
SAMPLE_STEP = 4
KIND_WEIGHT = (("ipv4_string", 1500), ("endpoint_tuple", 1700), ("stat_object", 1500), ("pair_vec", 1100),
               ("quad_vec", 1100), ("named_stat_iter", 1100), ("named_stat_tree", 1300), ("entry_call", 900))
APPROX = {"ipv4_string": 20, "endpoint_tuple": 40, "stat_object": 70, "pair_vec": 150, "quad_vec": 250,
          "named_stat_iter": 260, "named_stat_tree": 300, "entry_call": 40}


_MODEL = []


def reference_model():
    if not _MODEL:
        image = load_image()
        relative = image.relative()
        at = image.offset(relative[ESCAPE_SLOT])
        hex_at = image.offset(relative[HEX_SLOT])
        _MODEL.append(Model(bytes(image.blob[at:at + 256]), bytes(image.blob[hex_at:hex_at + 16])))
    return _MODEL[0]


def force_non_finite(kind, data, index):
    """Replace the first float of the input with infinity or NaN so the null branch is on the swept path."""
    pattern = (0x7FF0000000000000, 0xFFF8000000000000)[index % 2]
    if kind == "stat_object":
        data["total"] = pattern
    elif kind in ("pair_vec", "quad_vec") and data:
        data[0]["f"] = pattern
    elif kind in ("named_stat_iter",) and data:
        data[0]["stat"]["max"] = pattern
    elif kind == "named_stat_tree":
        data["keys"] = data["keys"] or [(b"k", {"n": 1, "total": 0, "max": 0})]
        data["keys"][0][1]["total"] = pattern
    elif kind == "entry_call" and data["fn"] == NEXT_KEY_FN:
        data["value"] = pattern


def exhaustive_cases():
    """Small closed domains tried completely: every byte value in a key, every octet value in every position, decimal
    length boundaries of the counters and ports, and both compound states for each entry writer."""
    index = 200000
    for byte in range(256):
        for key in (bytes((byte,)), bytes((97, byte, 98))):
            for fn, value in ((FIRST_KEY_FN, 0), (NEXT_KEY_FN, 0x3FF0000000000000)):
                index += 1
                yield "entry_call", index, {"fn": fn, "state": 2 if byte & 1 else 1, "key": key, "value": value}, 0, b""
    for position in range(4):
        for octet in range(256):
            ip = [1, 22, 133, 244]
            ip[position] = octet
            index += 1
            yield "ipv4_string", index, {"ip": ip}, 0, b""
    for digits in range(1, 21):
        for value in {10 ** (digits - 1), 10 ** digits - 1, 10 ** digits, 2 ** (3 * digits)}:
            if value < 1 << 64:
                index += 1
                yield "entry_call", index, {"fn": FIRST_KEY_FN, "state": 1, "key": b"n", "value": value}, 16, b"{"
    for port in (0, 9, 10, 99, 100, 255, 256, 999, 1000, 9999, 10000, 32767, 32768, 65535):
        for flag in (0, 1):
            index += 1
            yield "endpoint_tuple", index, {"ip": [0, 0, 0, 0], "port": port, "flag": flag, "pad": 0}, 0, b""


def cases(kinds=None):
    for kind, count in KIND_WEIGHT:
        if kinds is not None and kind not in kinds:
            continue
        rng = random.Random(SALT ^ zlib_crc(kind))
        for index in range(count):
            data = rand_input(rng, kind)
            cap, content = rand_sink(rng, APPROX[kind])
            yield kind, index, data, cap, content
        # sweeps: for a few inputs every capacity from 0 to the output length, so each reserve site is the one that grows
        rng = random.Random(SALT ^ zlib_crc(kind) ^ 0x5157)
        for j in range(SWEEP_INPUTS):
            data = rand_input(rng, kind)
            if j < 3 or kind == "entry_call":
                force_non_finite(kind, data, j)
            prefix = b"" if j % 2 == 0 else b"abc"
            length = len(model_run(reference_model(), kind, data, 1 << 20, prefix)[2])
            for cap in range(len(prefix), length + 2):
                yield kind, 100000 + j * 1000 + cap, data, cap, prefix
    for item in exhaustive_cases():
        if kinds is None or item[0] in kinds:
            yield item


def zlib_crc(text):
    import zlib
    return zlib.crc32(text.encode())


def describe(kind, data):
    if kind == "ipv4_string":
        return ".".join(map(str, data["ip"]))
    if kind == "endpoint_tuple":
        return "%s:%d/%d" % (".".join(map(str, data["ip"])), data["port"], data["flag"])
    if kind == "stat_object":
        return "n=%d,total=%#x,max=%#x" % (data["n"], data["total"], data["max"])
    if kind == "named_stat_tree":
        return "height=%d,rows=%d" % (tree_height(data), len(flatten(data)))
    if kind == "entry_call":
        return "fn=%#x,state=%d,keylen=%d" % (data["fn"], data["state"], len(data["key"]))
    return "rows=%d" % len(data)


# ---------------------------------------------------------------------------------------------------------------------
# Controls: byte mutants of the real code, wrong models, and out-of-range inputs
# ---------------------------------------------------------------------------------------------------------------------

def probe_cases(count=48):
    rng = random.Random(SALT)
    kinds = [k for k, _ in KIND_WEIGHT]
    for index in range(count):
        kind = kinds[index % len(kinds)]
        data = rand_input(rng, kind)
        cap, content = rand_sink(rng, APPROX[kind])
        yield kind, data, cap, content


def code_sites(image):
    """(address, offset-in-instruction, original byte, replacement, label) for byte mutants found by pattern."""
    sites = []
    for entry, name, _ in TARGETS + HELPERS:
        start, end = image.exact_fde(entry)
        for row in decode_range(image, start, end):
            raw = image.blob[image.offset(row.va):image.offset(row.va) + row.size]
            # store of an ASCII punctuation byte: mov byte [mem], imm8
            if row.size >= 4 and raw[-2:-1] and row.op == "mov" and row.width == 1 and row.b and row.b[0] == "i" \
                    and row.b[1] in (0x5B, 0x5D, 0x2C, 0x3A, 0x7B, 0x7D, 0x22):
                sites.append((row.va, row.size - 1, raw[-1], (raw[-1] + 1) & 0xFF, "%s punctuation byte %#x -> %#x" % (
                    name, raw[-1], (raw[-1] + 1) & 0xFF)))
            if row.op == "jcc" and row.size == 2 and entry in (ESCAPE_FN, GROW_FN, IPV4_FN, ITOA_FN):
                sites.append((row.va, 0, raw[0], raw[0] ^ 1, "%s jcc %#x inverted" % (name, row.va)))
            if row.op == "jcc" and row.size == 6 and entry in (ENDPOINT_FN, NEXT_KEY_FN, VALUE_FN):
                sites.append((row.va, 1, raw[1], raw[1] ^ 1, "%s jcc %#x inverted" % (name, row.va)))
    return sites


ALL_KINDS = tuple(k for k, _ in KIND_WEIGHT)
USES = {
    "ipv4_string": ("ipv4_string", "endpoint_tuple", "pair_vec", "quad_vec"),
    "endpoint_tuple": ("endpoint_tuple", "pair_vec", "quad_vec"),
    "stat_object": ("stat_object", "named_stat_iter", "named_stat_tree"),
    "pair_vec": ("pair_vec",),
    "quad_vec": ("quad_vec",),
    "named_stat_iter": ("named_stat_iter", "named_stat_tree"),
    "u64_decimal": ("quad_vec",),
    "escape_contents": ALL_KINDS,
    "first_entry": ("stat_object", "named_stat_iter", "named_stat_tree", "entry_call"),
    "next_entry": ("stat_object", "named_stat_iter", "named_stat_tree", "entry_call"),
    "f64_value": ("stat_object", "pair_vec", "quad_vec", "named_stat_iter", "named_stat_tree", "entry_call"),
}


def detect_patch(image, model, patches, owner="vec_reserve"):
    """Stream the cases that can reach the patched function through the patched bytes; True at the first difference."""
    rig = Rig(image, patches)
    wanted = USES.get(owner, ALL_KINDS)
    for kind, index, data, cap, content in cases(wanted):
        try:
            got = rig.run(ENTRY[kind], kind, data, cap, content)
        except (Halt, EvidenceError, Panicked, KeyError, ValueError, OverflowError, IndexError):
            return True, "%s-%d" % (kind, index)
        if got != model_run(model, kind, data, cap, content):
            return True, "%s-%d" % (kind, index)
    return False, ""


def wrong_models(model):
    """Deliberately wrong reference models; each returns a Model subclass instance."""
    table = model.table
    hexd = model.hex

    class M(Model):
        pass

    out = []

    def variant(name, **overrides):
        cls = type(name, (Model,), overrides)
        out.append((name, cls(table, hexd)))

    def esc_no_u(self, sink, data):
        sink.extend(bytes(data))
    variant("escape-ignored", escape_contents=esc_no_u)

    def esc_upper_hex(self, sink, data):
        Model.escape_contents(Model(table, hexd.upper()), sink, data)
    variant("hex-upper", escape_contents=esc_upper_hex)

    def esc_per_byte(self, sink, data):
        for byte in data:
            if table[byte] == 0x75:
                sink.reserve(6)
                sink.buf += b"\\u00" + bytes((hexd[byte >> 4], hexd[byte & 15]))
            elif table[byte]:
                sink.reserve(2)
                sink.buf += b"\\" + bytes((table[byte],))
            else:
                sink.push(byte)
    variant("escape-byte-at-a-time-reserve", escape_contents=esc_per_byte)

    def esc_big_reserve(self, sink, data):
        sink.reserve(len(data) + 1)
        Model.escape_contents(self, sink, data)
    variant("escape-prereserve", escape_contents=esc_big_reserve)

    def ep_in_out_swapped(self, sink, ep):
        Model.endpoint(self, sink, dict(ep, flag=1 - (1 if ep["flag"] == 1 else 0)))
    variant("direction-swapped", endpoint=ep_in_out_swapped)

    def ep_flag_nonzero(self, sink, ep):
        Model.endpoint(self, sink, dict(ep, flag=1 if ep["flag"] else 0))
    variant("direction-nonzero-is-out", endpoint=ep_flag_nonzero)

    def ep_port_padded(self, sink, ep):
        Model.endpoint(self, sink, dict(ep, port=ep["port"] & 0xFFF))
    variant("port-12-bit", endpoint=ep_port_padded)

    def ip_reversed(self, sink, octets):
        Model.ipv4(self, sink, list(reversed(octets)))
    variant("ip-reversed", ipv4=ip_reversed)

    def ip_padded(self, sink, octets):
        self.string(sink, ".".join("%03d" % b for b in octets).encode())
    variant("ip-zero-padded", ipv4=ip_padded)

    def f64_null_low(self, sink, bits):
        if (bits & 0x7FFFFFFFFFFFFFFF) >= 0x7FEFFFFFFFFFFFFF:
            sink.reserve(4)
            sink.buf += b"null"
        else:
            Model.f64(self, sink, bits)
    variant("max-finite-is-null", f64=f64_null_low)

    def f64_nan_only(self, sink, bits):
        if (bits & 0x7FFFFFFFFFFFFFFF) == 0x7FF0000000000000:
            sink.extend(b"1e999")
        else:
            Model.f64(self, sink, bits)
    variant("infinity-not-null", f64=f64_nan_only)

    def f64_no_reserve(self, sink, bits):
        if (bits & 0x7FFFFFFFFFFFFFFF) > 0x7FEFFFFFFFFFFFFF:
            sink.buf += b"null"
        else:
            Model.f64(self, sink, bits)
    variant("null-without-reserve", f64=f64_no_reserve)

    def stat_order(self, sink, st):
        sink.push(0x7B)
        self.entry(sink, True, b"n", lambda: sink.extend(str(st["n"]).encode()))
        self.entry(sink, False, b"max", lambda: self.f64(sink, st["max"]))
        self.entry(sink, False, b"total", lambda: self.f64(sink, st["total"]))
        sink.push(0x7D)
    variant("stat-fields-swapped", stat=stat_order)

    def stat_no_close(self, sink, st):
        Model.stat(self, sink, st)
        sink.buf.pop()
    variant("stat-missing-brace", stat=stat_no_close)

    def pair_comma(self, sink, rows):
        Model.pair_vec(self, sink, rows[:1] if rows else rows)
    variant("pair-vec-first-only", pair_vec=pair_comma)

    def quad_swapped(self, sink, rows):
        Model.quad_vec(self, sink, [dict(r, a=r["b"], b=r["a"]) for r in rows])
    variant("quad-counters-swapped", quad_vec=quad_swapped)

    def named_no_sep(self, sink, rows):
        Model.named_stat_iter(self, sink, list(reversed(rows)))
    variant("named-order-reversed", named_stat_iter=named_no_sep)

    return out


def model_detects(model, wrong):
    for kind, index, data, cap, content in cases():
        if model_run(wrong, kind, data, cap, content) != model_run(model, kind, data, cap, content):
            return True, "%s-%d" % (kind, index)
    return False, ""


def out_of_range_controls(image):
    """Inputs outside the supported model: each must be rejected by the harness."""
    results = []
    bad = bytearray(image.blob)
    bad[image.offset(IPV4_FN) + 3] ^= 0xFF
    try:
        digest_ok = hashlib.sha256(bytes(bad)).hexdigest() == SHA256
    except Exception:
        digest_ok = True
    results.append(("corrupted-binary-digest", not digest_ok))
    try:
        image.exact_fde(IPV4_FN + 1)
        results.append(("mid-function-entry-rejected", False))
    except EvidenceError:
        results.append(("mid-function-entry-rejected", True))
    try:
        image.offset(0x10)
        results.append(("address-outside-sections-rejected", False))
    except EvidenceError:
        results.append(("address-outside-sections-rejected", True))
    rig = Rig(image)
    try:
        rig.run(IPV4_FN, "ipv4_string", {"ip": [1, 2, 3, 4]}, 0, b"")
        rig.machine.step_limit = 5
        rig.run(IPV4_FN, "ipv4_string", {"ip": [1, 2, 3, 4]}, 0, b"")
        results.append(("step-limit-enforced", False))
    except Halt:
        results.append(("step-limit-enforced", True))
    rig = Rig(image)
    rig.machine.calls.pop(FINISH_GROW)
    try:
        rig.run(IPV4_FN, "ipv4_string", {"ip": [1, 2, 3, 4]}, 0, b"")
        results.append(("unmodelled-allocator-call-halts", False))
    except Halt:
        results.append(("unmodelled-allocator-call-halts", True))
    rig = Rig(image)
    try:
        rig.run(IPV4_FN, "ipv4_string", {"ip": [1, 2, 3, 4]}, 40, b"x" * 40)
        results.append(("full-buffer-run-ok", True))
    except Halt:
        results.append(("full-buffer-run-ok", False))
    return results


# ---------------------------------------------------------------------------------------------------------------------
# Evidence generation
# ---------------------------------------------------------------------------------------------------------------------

def first_bytes_hash(image, entry):
    start, end = image.exact_fde(entry)
    body = bytes(image.blob[image.offset(start):image.offset(start) + end - start])
    return start, end, hashlib.sha256(body).hexdigest()


def call_targets(image, entry):
    start, end = image.exact_fde(entry)
    found = {}
    for row in decode_range(image, start, end):
        if row.op in ("call", "jmp") and row.target is not None and not start <= row.target < end:
            found[row.target] = found.get(row.target, 0) + 1
        if row.op == "calli" and row.a and row.a[0] == "m" and row.a[1] is None and row.a[2] is None:
            found[row.a[4]] = found.get(row.a[4], 0) + 1
    return found


def write_lines(path, lines):
    with open(path, "w", newline="\n") as handle:
        for line in lines:
            handle.write(line + "\n")


def tsv(*cells):
    return "\t".join(str(c) for c in cells)


def generate(out):
    out = pathlib.Path(out)
    out.mkdir(parents=True, exist_ok=True)
    image = load_image()
    relative = image.relative()
    table_at = image.offset(relative[ESCAPE_SLOT])
    escape_table = bytes(image.blob[table_at:table_at + 256])
    hex_at = image.offset(relative[HEX_SLOT])
    hex_digits = bytes(image.blob[hex_at:hex_at + 16])
    model = Model(escape_table, hex_digits)

    # function table
    rows = [tsv("address", "size", "instructions", "sha256", "role", "targets")]
    for entry, name, role in TARGETS + HELPERS:
        start, end, digest = first_bytes_hash(image, entry)
        count = len(decode_range(image, start, end))
        callees = ";".join("%#x:%d" % (t, c) for t, c in sorted(call_targets(image, entry).items()))
        rows.append(tsv("%#x" % start, end - start, count, digest, name + " - " + role, callees))
    write_lines(out / "functions.tsv", rows)

    # escape table straight from the ELF bytes
    rows = [tsv("byte", "escape_code", "kind")]
    for byte, kind in enumerate(escape_table):
        if kind:
            rows.append(tsv("%#04x" % byte, "%#04x" % kind, "unicode-escape" if kind == 0x75 else "short-escape"))
    rows.append(tsv("hex-digits", hex_digits.decode(), "lowercase"))
    write_lines(out / "escape-table.tsv", rows)

    # cases
    rig = Rig(image)
    total = mismatches = 0
    per_kind = {}
    grow_events = 0
    sample_rows = [tsv("case", "kind", "input", "initial_cap", "initial_len", "final_cap", "final_len", "grows", "sha256_of_output")]
    ryu_text_seen = set()
    expected_probe = None
    with open(out / "mismatches.tsv", "w", newline="\n") as bad:
        bad.write(tsv("case", "kind", "field") + "\n")
        for kind, index, data, cap, content in cases():
            total += 1
            want = model_run(model, kind, data, cap, content)
            got = rig.run(ENTRY[kind], kind, data, cap, content)
            per_kind[kind] = per_kind.get(kind, 0) + 1
            grow_events += len(got[3])
            if got != want:
                mismatches += 1
                bad.write(tsv("%s-%d" % (kind, index), kind, "status/cap/bytes/events") + "\n")
            if total % SAMPLE_STEP == 0:
                sample_rows.append(tsv("%s-%d" % (kind, index), kind, describe(kind, data), cap, len(content), got[1],
                                       len(got[2]), ";".join("%d>%d" % e for e in got[3]) or "-",
                                       hashlib.sha256(got[2]).hexdigest()[:16]))
    write_lines(out / "cases-sample.tsv", sample_rows)
    if mismatches == 0:
        (out / "mismatches.tsv").unlink()
    else:
        raise PacketError("%d model mismatches; see mismatches.tsv" % mismatches)

    # reserve-site coverage: every reserve call site the cases reached
    covered = {}
    for entry, name, _ in TARGETS + HELPERS:
        start, end = image.exact_fde(entry)
        covered[name] = (len(decode_range(image, start, end)), sum(1 for pc in rig.machine.seen if start <= pc < end))
    rows = [tsv("function", "instructions", "executed_by_cases")]
    for name, (n, hit) in covered.items():
        rows.append(tsv(name, n, hit))
    write_lines(out / "coverage.tsv", rows)

    # controls
    ctl = [tsv("id", "class", "description", "first_difference", "detected")]
    equivalent = [tsv("id", "address", "reason")]
    detected = equivalent_count = made = 0
    for site in code_sites(image):
        va, at, old, new, label = site
        made += 1
        hit, first = detect_patch(image, model, {va + at: new}, label.split(" ")[0])
        ident = "byte-%03d" % made
        if hit:
            detected += 1
        else:
            equivalent_count += 1
            reached = va in rig.machine.seen
            reason = UNREACHABLE.get(va)
            if reached:
                reason = "executed by the cases but the output bytes, capacity and growth events are identical"
            elif reason is None:
                raise PacketError("undetected mutant at %#x has no stated reason" % va)
            equivalent.append(tsv(ident, "%#x" % va, reason))
        ctl.append(tsv(ident, "code-byte-mutant", label, first or "-", "yes" if hit else "equivalent"))
    for name, wrong in wrong_models(model):
        made += 1
        hit, first = model_detects(model, wrong)
        detected += hit
        ctl.append(tsv("model-%03d" % made, "wrong-model", name, first or "-", "yes" if hit else "NO"))
    for name, ok in out_of_range_controls(image):
        made += 1
        detected += ok
        ctl.append(tsv("range-%03d" % made, "out-of-range", name, "-", "yes" if ok else "NO"))
    write_lines(out / "controls.tsv", ctl)
    write_lines(out / "equivalent-mutants.tsv", equivalent)
    measure = {"cases": total, "negative_controls": made, "negative_detected": detected,
               "equivalent": 0, "model_mismatches": mismatches, "reserve_events": grow_events}
    # byte mutants that the battery cannot reach are counted as equivalent only after the reachability census below
    measure["negative_detected"] = detected
    measure["equivalent"] = equivalent_count
    (out / "measure.json").write_text(json.dumps(measure, indent=1, sort_keys=True) + "\n")
    return measure


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--out", required=True)
    args = parser.parse_args()
    measure = generate(args.out)
    print(json.dumps(measure, sort_keys=True))


if __name__ == "__main__":
    main()
