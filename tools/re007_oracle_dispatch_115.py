#!/usr/bin/env python3
"""RE-007 node #115: oracle update dispatch root 0x2753b90, update body 0x2d35a80 and the drop glue of its event vector.

Reconstructs, as executable Python models, the path that turns a flat perp asset id into a (clearinghouse, asset) pair, reads
the asset row, builds the update context, calls the oracle update body and flushes the queued events; plus the body's rejection
ladder, its event counter and block-time arithmetic, and the two drop-glue functions (0x2783790, 0x2776870). The models are
compared with the original bytes run on an offline x86-64 interpreter (the interpreter below is a copy of the shared core; the
binary is never executed natively). Standard library plus the shared elf_index and fde_extents parsers.

    python3 tools/re007_oracle_dispatch_115.py --out <dir>
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
# Packet section: oracle update dispatch (root 0x2753b90), update body 0x2d35a80 and the drop glue it leans on.
# ======================================================================================================================

import argparse
import json
import random

NAME = "RE-007-oracle-update-dispatch-115"
SEED = 0x0A11CE
M64 = (1 << 64) - 1
M32 = (1 << 32) - 1
NICHE = 1 << 63  # 0x8000000000000000, the capacity niche of Option<String>-shaped fields

ROOT_FN = 0x2753B90
BODY_FN = 0x2D35A80
FLUSH_FN = 0x2419810
SMALL_DROP = 0x2783790
EVENTS_DROP = 0x2776870
MEMBERS = (0x2419810, 0x2753B90, 0x2776870, 0x277E390, 0x2783790, 0x2D35A80, 0x42320D0)

SLOT_NAMES = {
    0x64DF6A0: "panic_msg", 0x64DF620: "panic_bounds", 0x64DF4A0: "dealloc", 0x64DF508: "memcpy",
    0x64E0F70: "secs_f64", 0x64E0F78: "time_add", 0x64E0AA0: "date_days", 0x64E5A28: "vec_grow",
}
DIRECT_NAMES = {
    0x44E0810: "guard_a", 0x2D35A80: "update_body", 0x2419810: "flush_events", 0x2D357D0: "classify",
    0x294AB40: "ring_count", 0x22E5380: "validate", 0x2A81140: "build_record", 0x2DB23F0: "map_entry",
    0x2421680: "entry_slot", 0x22FCDC0: "event_drop", 0x2D2D960: "apply_update",
}

# Heap layout used by every fixture (offsets from the interpreter heap base).
H = HEAP_BASE
EXS = H + 0x0000      # exchange state (root r15)
DEXV = H + 0x2000     # clearinghouse records, stride 0x510
ORC = H + 0xA000      # per-dex oracle books, stride 0x200
ASSETS = H + 0xC000   # per-dex asset rows, stride 0x60
ARG = H + 0x10000     # the 0x58-byte update argument
KEY = H + 0x10100     # the 0x14-byte key
OUT = H + 0x10200     # the result block
STATE = H + 0x11000   # oracle book (update body r14)
CTX = H + 0x12000
DEXREC = H + 0x13000
EVV = H + 0x14000
EVBUF = H + 0x16000
BUMP = H + 0x1A000
EVBASE = 0
DROPFN = 0x5100000
ENUM_DROP = 0x42320D0
NESTED = (0x4232440, 0x4233F10)  # the nested drop glue the enum drop tail-calls
USED = 0x20000

PANIC_ROOT = {  # (rdi, rcx, r8) literals of the three panic sites, read back from the bytes below
    "dex": (0x7D3212, 0x648C5F8, 0x648B990),
    "book": (0x7C95FA, 0x6484140, 0x6483E08),
    "asset": 0x643B1E8,
}


class Stopped(Exception):
    pass


def u16(b, at):
    return int.from_bytes(b[at:at + 2], "little")


def u32(b, at):
    return int.from_bytes(b[at:at + 4], "little")


def u64(b, at):
    return int.from_bytes(b[at:at + 8], "little")


def p64(v):
    return (v & M64).to_bytes(8, "little")


def p16(v):
    return (v & 0xFFFF).to_bytes(2, "little")


def p32(v):
    return (v & M32).to_bytes(4, "little")


def sext(v, bits):
    v &= (1 << bits) - 1
    return v - (1 << bits) if v >> (bits - 1) else v


class Fixture:
    """A byte image of the first USED heap bytes; both the interpreter and the models read it."""

    def __init__(self):
        self.buf = bytearray(USED)

    def put(self, addr, data):
        self.buf[addr - H:addr - H + len(data)] = data

    def q(self, addr, v):
        self.put(addr, p64(v))

    def d(self, addr, v):
        self.put(addr, p32(v))

    def get(self, addr, n):
        return bytes(self.buf[addr - H:addr - H + n])

    def gq(self, addr):
        return u64(self.buf, addr - H)

    def gd(self, addr):
        return u32(self.buf, addr - H)


# ---------------------------------------------------------------------------------------------------------------------
# Interpreter rig
# ---------------------------------------------------------------------------------------------------------------------

class TailMachine(Machine):
    """Machine that serves a direct tail jump to a nested drop function as a hooked call plus return."""

    tails = {}

    def step(self, row):
        if row.op == "jmp" and row.target in self.tails:
            self.tails[row.target](self)
            return self.pop()
        return super().step(row)


class Rig:
    def __init__(self, image, patches=None):
        self.image = image
        self.m = TailMachine(image, patches)
        self.trace = []
        self.cfg = {}
        self.tables = None
        rel = image.relative()
        for slot, name in SLOT_NAMES.items():
            target = rel.get(slot, 0x5000000 + slot)
            self.m.memory.statics[slot] = target
            self.m.slots[target] = self.slot_hook(name)
        for addr, name in DIRECT_NAMES.items():
            self.m.calls[addr] = self.direct_hook(name)
        for addr in NESTED:
            self.m.calls[addr] = self.nested_hook(addr)
        self.m.tails = {addr: self.nested_hook(addr) for addr in NESTED}
        self.m.slots[DROPFN] = self.dyn_hook()
        self.tables = decode_tables(image)
        self.m.real = frozenset({0x42320D0})  # the result-enum drop glue runs for real (tag 0x156 is its no-op class)

    def snap(self, addr, n):
        return self.m.memory.bytes_at(addr, n)

    def slot_hook(self, name):
        def hook(mm):
            r = mm.regs
            if name in ("panic_msg", "panic_bounds"):
                self.trace.append((name, r[RDI], r[RSI], r[RDX], 0, 0) if name == "panic_bounds" else (name, r[RDI], r[RSI], 0, r[RCX], r[R8]))
                raise Panicked(name)
            if name == "dealloc":
                self.trace.append(("dealloc", r[RDI], r[RSI], r[RDX]))
            elif name == "memcpy":
                self.trace.append(("memcpy", r[RDI] - EVBASE, r[RDX]))
                mm.memory.copy(r[RDI], r[RSI], r[RDX])
            elif name == "vec_grow":
                vec = r[RDI]
                cap = mm.memory.read(vec, 8)
                self.trace.append(("vec_grow", cap))
                mm.memory.write(vec, 8, cap * 2 + 4)
                mm.memory.write(vec + 8, 8, BUMP)
            elif name == "secs_f64":
                self.trace.append(("secs_f64", mm.xmm[0] & M64))
                mm.regs[RAX] = self.cfg["secs"]
                mm.regs[RDX] = self.cfg["nanos"]
                mm.keep_rdx = True
            elif name == "time_add":
                self.trace.append(("time_add", self.snap(r[RSI], 8), r[RDX], r[RCX] & M32))
                mm.memory.put_bytes(r[RDI], self.cfg["time_out"])
            elif name == "date_days":
                self.trace.append(("date_days", r[RDI] & M32, r[RSI] & M32))
                mm.regs[RAX] = self.cfg["days_ret"]
        return hook

    def nested_hook(self, addr):
        def hook(mm):
            self.trace.append(("nested", addr, mm.regs[RDI]))
        return hook

    def dyn_hook(self):
        def hook(mm):
            self.trace.append(("dyn", mm.regs[RDI]))
        return hook

    def direct_hook(self, name):
        def hook(mm):
            r = mm.regs
            cfg = self.cfg
            if name == "guard_a":
                self.trace.append(("guard_a", u16(self.snap(r[RDI], 2), 0)))
            elif name == "update_body":
                ctx = bytearray(self.snap(r[RDX], 0x94))
                ctx[0x70:0x78] = bytes(8)  # a stack address, not part of the contract
                self.trace.append(("update_body", r[RSI], bytes(ctx)))
                mm.memory.put_bytes(r[RDI], cfg["body_out"])
            elif name == "flush_events":
                self.trace.append(("flush_events", self.snap(r[RDI], 0x18), r[RSI], r[RDX]))
            elif name == "classify":
                self.trace.append(("classify", r[RDI], self.snap(r[RSI], 0x14)))
                mm.regs[RAX] = cfg["classify"]
            elif name == "ring_count":
                self.trace.append(("ring_count", self.snap(r[RDI], 0x48), r[RSI]))
                mm.regs[RAX] = cfg["count"]
            elif name == "validate":
                self.trace.append(("validate", self.snap(r[RSI], 0x58), self.snap(r[RDX], 0x14), r[RCX], r[R8]))
                mm.memory.put_bytes(r[RDI], cfg["validate_out"])
            elif name == "build_record":
                blk = bytearray(self.snap(r[RSI], 0x54))
                blk[9:0x10] = bytes(7)
                self.trace.append(("build_record", bytes(blk), r[RDX]))
                mm.memory.put_bytes(r[RDI], cfg["record_out"])
            elif name == "map_entry":
                self.trace.append(("map_entry", elem_defined(self.snap(r[RDI], 0x2B8)), r[RSI], self.snap(r[RDX], 0x14)))
            elif name == "entry_slot":
                self.trace.append(("entry_slot",))
                raise Stopped("tail")
            elif name == "event_drop":
                self.trace.append(("event_drop", r[RDI]))
            elif name == "apply_update":
                self.trace.append(("apply_update", r[RDI], self.snap(r[RSI], 0x6C)))
        return hook

    def run(self, entry, fx, args, cfg):
        """Run one function on a fixture; return (status, rax, trace, memory after)."""
        self.cfg = cfg
        self.trace = []
        mem = self.m.memory
        mem.reset(USED)
        mem.put_bytes(H, bytes(fx.buf))
        try:
            rax = self.m.run(entry, args)
            status = "ret"
        except Panicked as exc:
            rax, status = 0, "panic:" + str(exc)
        except Stopped as exc:
            rax, status = 0, "stop:" + str(exc)
        return status, rax, self.trace, mem.bytes_at(H, USED)


# ---------------------------------------------------------------------------------------------------------------------
# Models (the reconstruction): each returns (status, trace, written fields)
# ---------------------------------------------------------------------------------------------------------------------

def model_root(fx, mut=()):
    """Root 0x2753b90: map the flat asset id to (clearinghouse, asset) and hand the update to the body, then flush events."""
    arg = fx.get(ARG, 0x58)
    key = fx.get(KEY, 0x14)
    index = u64(arg, 0x38)
    divisor = 1000 if "dex_div" in mut else 10000
    dex = index // divisor
    ndex = fx.gq(EXS + 0x7D0)
    nbook = fx.gq(EXS + 0x3AD0)
    stride = 0x500 if "dex_stride" in mut else 0x510
    trace = []
    if (dex > ndex) if "dex_cmp" in mut else (dex >= ndex):
        return "panic:panic_msg", [("panic_msg",) + (PANIC_ROOT["dex"][0], 0x2B, 0) + PANIC_ROOT["dex"][1:]], {}
    rec = fx.gq(EXS + 0x7C8) + dex * stride
    trace.append(("guard_a", 0x156))
    if dex >= nbook:
        return "panic:panic_msg", trace + [("panic_msg", PANIC_ROOT["book"][0], 0x2B, 0, PANIC_ROOT["book"][1], PANIC_ROOT["book"][2])], {}
    local = index - dex * (1000 if "local_mul" in mut else 10000)
    count = fx.gq(rec + 0x158)
    if local >= count:
        return "panic:panic_bounds", trace + [("panic_bounds", local, count, PANIC_ROOT["asset"], 0, 0)], {}
    row = 0x58 if "asset_stride" in mut else 0x60
    price = fx.gq(fx.gq(rec + 0x150) + local * row + (0x28 if "price_off" in mut else 0x20))
    book = fx.gq(EXS + 0x3AC8) + dex * (0x1F8 if "book_stride" in mut else 0x200) + (0x180 if "book_off" in mut else 0x188)
    trace.append(("guard_a", 0x156))
    ctx = arg[:0x58] + p64(price) + p64(rec) + p64(EXS) + b"\0" * 8 + p64(fx.gq(EXS + 0x39D0)) + (key[:0x13] + b"\0" if "key_cut" in mut else key)
    trace.append(("update_body", book, ctx))
    trace.append(("flush_events", p64(0) + p64(8) + p64(0), dex, EXS))
    return "ret", trace, {"dex": dex, "local": local, "price": price}


def model_small_drop(fx, at, mut=()):
    """0x2783790: two Option<String>-shaped fields; the second capacity niche or zero frees nothing."""
    trace = []
    cap1 = fx.gq(at)
    if cap1 == NICHE + 1 and "first_niche1" not in mut:
        return "ret", trace
    if cap1 not in (NICHE, 0):
        trace.append(("dealloc", fx.gq(at + 8), cap1, 0))
    cap2 = fx.gq(at + 0x20)
    if cap2 not in ((0,) if "second_niche_free" in mut else (NICHE, 0)):
        trace.append(("dealloc", fx.gq(at + 0x28), cap2, 0))
    return "ret", trace


def model_events_drop(fx, at, mut=()):
    """0x2776870: drop every 0x2b8-byte event of a Vec in order, then free the buffer when it had capacity."""
    cap, ptr, length = fx.gq(at), fx.gq(at + 8), fx.gq(at + 0x10)
    trace = [("event_drop", ptr + i * (0x2B0 if "event_size" in mut else 0x2B8)) for i in range(length)]
    if cap or "cap_free" in mut:
        trace.append(("dealloc", ptr, cap * 0x2B8, 0))
    return "ret", trace


def ring_descriptor(fx, st):
    """The nine words the body builds on its stack before asking 0x294ab40 for the element count."""
    mode = fx.gq(st + 0x38)
    if mode == NICHE:
        n = fx.gq(st + 0x40)
        flag = int(n != 0)
        return [flag, 0, n, fx.gq(st + 0x48), flag, 0, n, fx.gq(st + 0x48), fx.gq(st + 0x50) if n else n]
    cap, head, length, base = mode, fx.gq(st + 0x48), fx.gq(st + 0x50), fx.gq(st + 0x40)
    if length == 0:
        a = b = c = 0
    else:
        skip = cap if head >= cap else 0
        a = head - skip
        used = cap - a
        c = length - used
        b = cap
        if not length > used:
            b = length + a
            c = 0
    return [2, a * 0x38 + base, b * 0x38 + base, base, c * 0x38 + base, 0, b * 0x38 + base, base, c]


def days_millis(date, secs, nanos, mut=()):
    """The inline NaiveDate-to-milliseconds arithmetic of the non-trading branch (bit-exact with the asm)."""
    year = sext(date, 32) >> 13
    edx = (year - 1) & M32
    esi = 0
    if not year > 0:
        esi = (1 - year) & M32
        esi = (esi * (0x51EB851E if "century_m1" in mut else 0x51EB851F) & M64) >> 0x27
        esi = (esi + 1) & M32
        edi = esi * 0x190 & M32
        edx = (edx + edi) & M32
        esi = esi * 0xFFFDC54F & M32
    edi = ((date >> 4) & 0x1FF) + esi & M32
    esi = sext(edx * 0x5B5 & M32, 32) >> 2 & M32
    rdx = sext(edx, 32) * 0x51EB851F & M64
    r8 = rdx >> 63
    rdx = sext(rdx, 64) >> 0x25 & M64
    edx = (rdx + r8) & M32
    edi = (edi - edx) & M32
    edx = sext(edx, 32) >> 2 & M32
    edi = (edi + esi) & M32
    edx = (edx + edi) & M32
    edx = (edx + (0xFFF506C5 if "epoch" not in mut else 0xFFF506C6)) & M32
    rdx = sext(edx, 32) * 0x15180 & M64
    rdx = (rdx + secs) & M64
    rsi = (nanos * 0x431BDE83 & M64) >> (0x31 if "ms_shift" in mut else 0x32)
    rdx = (rdx * 0x3E8 + rsi) & M64
    if "no_clamp" in mut:
        return rdx
    return rdx if sext(rdx, 64) > 0 else 0


def drop_a(fx, at):
    """Frees of the 0x58-byte argument block's two string-like fields (shared by every exit of the body)."""
    out = []
    cap1 = fx.gq(at)
    if cap1 == NICHE + 1:
        return out
    if cap1 not in (NICHE, 0):
        out.append(("dealloc", fx.gq(at + 8), cap1, 0))
    cap2 = fx.gq(at + 0x20)
    if cap2 not in (NICHE, 0):
        out.append(("dealloc", fx.gq(at + 0x28), cap2, 0))
    return out


def model_body(fx, cfg, mut=()):
    """0x2d35a80: validate the update, bump the event counter, then queue one event or apply a trading-state update."""
    ctx = fx.get(CTX, 0x94)
    key = ctx[0x80:0x94]
    a = ctx[:0x58]
    price, dexrec, ex, events, limit = u64(ctx, 0x58), u64(ctx, 0x60), u64(ctx, 0x68), u64(ctx, 0x70), u64(ctx, 0x78)
    trace = [("classify", STATE, key)]
    wrote = {}
    if cfg["classify"] > (8 if "classify_ge" in mut else 9):
        return "ret", trace + drop_a(fx, CTX), {0: (0xD2).to_bytes(2, "little")}, wrote
    desc = ring_descriptor(fx, STATE)
    trace.append(("ring_count", b"".join(p64(w) for w in desc), 0))
    total = min(fx.gq(STATE + 0x10) + cfg["count"], M64)
    if (total > limit) if "limit_cmp" in mut else (total >= limit):
        return "ret", trace + drop_a(fx, CTX), {0: (0xDE if "limit_code" in mut else 0xDD).to_bytes(2, "little")}, wrote
    date, secs, nanos = fx.gd(ex + 0x60), fx.gd(ex + 0x64), fx.gd(ex + 0x68)
    trace.append(("validate", a, key, price, dexrec))
    res = cfg["validate_out"]
    if u16(res, 0) != (0x1A3 if "ok_tag" in mut else 0x1A2):
        return "ret", trace + drop_a(fx, CTX), {0: bytes(res[:0x70])}, wrote
    head, flag, payload = u64(res, 8), res[0x10], res[0x18:0x40]
    if "flag_mask" in mut:
        flag &= 3
    nonce = fx.gq(ex + 0x48)
    if "wrap" in mut:
        wrote["nonce"] = (nonce + 1) & M64
    else:
        wrote["nonce"] = (nonce + 2 if "nonce_inc2" in mut else nonce + 1) if nonce != M64 else M64
    if flag == 2:
        trace.append(("secs_f64", cfg["f64_bits"]))
        total_ns = min(cfg["secs"] * 1000000000 + cfg["nanos"], 0x7FFFFFFFFFFFFFFE if "f64_total" in mut else 0x7FFFFFFFFFFFFFFF)
        trace.append(("time_add", p32(secs) + p32(nanos), total_ns // 1000000000, total_ns % 1000000000))
        tout = cfg["time_out"]
        b = u64(tout, 8)
        fail = (b + 0xFFDF3B645A1CAC08) & M64 <= 0xFFBE76C8B4395810 or ((b + 0xFFFF574000000000) & M64) < 0xFFFEAE7FFFFEAE81
        piece = cfg["const_default"]
        if not fail:
            hi = (sext(b, 64) * 0x1845C8A0CE512957) >> 64 & M64
            days = ((hi >> 63) + (hi >> 13)) & M32
            trace.append(("date_days", date, days))
            if cfg["days_ret"] & M32:
                piece = p32(cfg["days_ret"]) + tout[:8]
        block = payload + p64(dexrec) + p64(events) + p64(nonce) + p32(date) + p32(secs) + p32(nanos) + piece + key
        trace.append(("apply_update", STATE, block))
        wrote["events_len"] = fx.gq(events + 0x10)
        return "ret", trace + drop_a(fx, CTX), {0: (0x1A2).to_bytes(2, "little"), 8: p64(nonce)}, wrote
    millis = days_millis(date, secs, nanos, mut)
    trace.append(("build_record", p64(head) + bytes([flag & 1]) + bytes(7) + payload + p64(millis) + key, dexrec))
    rec = cfg["record_out"]
    ev = bytearray(0x2B8)
    ev[0:8] = p64(5 if "ev_tag" in mut else 4)
    ev[8:0x80] = rec[:0x78]
    ev[0x80:0x88] = p64(NICHE + 4)
    ev[0x98:0xA0] = p64(nonce)
    ev[0xA0:0xA4] = p32(date)
    ev[0xA4:0xA8] = p32(secs)
    ev[0xA8:0xAC] = p32(nanos)
    ev[0xAC:0xC0] = key
    cap, ptr, length = fx.gq(events), fx.gq(events + 8), fx.gq(events + 0x10)
    if length == cap:
        trace.append(("vec_grow", cap))
        cap, ptr = cap * 2 + 4, BUMP
    trace.append(("memcpy", ptr + length * 0x2B8 - EVBASE, 0x2B8))
    trace.append(("map_entry", elem_defined(bytes(ev)), STATE + 0x38, key))
    trace.append(("entry_slot",))
    wrote.update(millis=millis, events_len=length + 1, events_cap=cap, events_ptr=ptr, event=elem_defined(bytes(ev)))
    return "stop:tail", trace, {}, wrote


def elem_defined(ev):
    return ev[:0x88] + ev[0x98:0xC0]


# ---------------------------------------------------------------------------------------------------------------------
# Fixture generators (seeded, one case at a time)
# ---------------------------------------------------------------------------------------------------------------------

EXB = H + 0x15000


def root_fixture(rnd):
    fx = Fixture()
    nd = rnd.randint(1, 4)
    fx.q(EXS + 0x7C8, DEXV)
    fx.q(EXS + 0x7D0, nd)
    nb = nd if rnd.random() < 0.9 else rnd.randint(0, 3)
    fx.q(EXS + 0x3AD0, nb)
    fx.q(EXS + 0x3AC8, ORC)
    fx.q(EXS + 0x39D0, rnd.getrandbits(64))
    for d in range(nd):
        n = rnd.randint(0, 6)
        fx.q(DEXV + d * 0x510 + 0x150, ASSETS + d * 0x1000)
        fx.q(DEXV + d * 0x510 + 0x158, n)
        for a in range(n):
            fx.q(ASSETS + d * 0x1000 + a * 0x60 + 0x20, rnd.getrandbits(64))
            fx.q(ASSETS + d * 0x1000 + a * 0x60 + 0x28, rnd.getrandbits(64))
    arg = bytearray(rnd.randbytes(0x58))
    dd = rnd.randint(0, nd)
    nn = fx.gq(DEXV + min(dd, nd - 1) * 0x510 + 0x158)
    idx = rnd.choice([rnd.randint(0, nd * 10000 + 3), rnd.randint(0, max(nn, 1)) + 10000 * dd,
                      rnd.randint(0, max(nn - 1, 0)) + 10000 * min(dd, nd - 1),
                      rnd.randint(0, max(nn - 1, 0)) + 10000 * min(dd, nd - 1)])
    arg[0x38:0x40] = p64(idx)
    fx.put(ARG, bytes(arg))
    fx.put(KEY, rnd.randbytes(0x14))
    return fx, {"body_out": rnd.randbytes(0x70)}


def pick_cap(rnd):
    return rnd.choice([0, NICHE, NICHE + 1, 1, 7, 0x40, rnd.getrandbits(40)])


def body_fixture(rnd):
    fx = Fixture()
    fx.q(STATE + 0x10, rnd.choice([0, 1, 2, 3, 3, rnd.getrandbits(3), rnd.getrandbits(3), 100, M64 - 2]))
    mode = rnd.choice([NICHE, 4, 8, 16])
    fx.q(STATE + 0x38, mode)
    if mode == NICHE:
        fx.q(STATE + 0x40, rnd.choice([0, 1, 5]))
        fx.q(STATE + 0x48, rnd.getrandbits(8))
        fx.q(STATE + 0x50, rnd.getrandbits(8))
    else:
        fx.q(STATE + 0x40, rnd.getrandbits(40))
        fx.q(STATE + 0x48, rnd.randint(0, mode + 2))
        fx.q(STATE + 0x50, rnd.randint(0, mode))
    ctx = bytearray(rnd.randbytes(0x94))
    ctx[0:8] = p64(pick_cap(rnd))
    ctx[0x20:0x28] = p64(pick_cap(rnd))
    ctx[0x58:0x60] = p64(rnd.getrandbits(64))
    ctx[0x60:0x68] = p64(DEXREC)
    ctx[0x68:0x70] = p64(EXB)
    ctx[0x70:0x78] = p64(EVV)
    ctx[0x78:0x80] = p64(rnd.choice([rnd.getrandbits(8), M64, 1 << 20, 1 << 20, 1 << 30, 100, 101, 4, 5, M64 - 1]))
    fx.put(CTX, bytes(ctx))
    year = rnd.choice([rnd.randint(1, 3000), rnd.randint(-900, 0), 1970, 2025, 2026, 1, 400, -399, rnd.randint(-200000, 0), rnd.randint(-200000, 0), rnd.randint(1, 260000), 1 - 400 * rnd.randint(1, 650), 1 - 400 * rnd.randint(1, 650)])
    date = (year << 13 | rnd.randint(1, 366) << 4 | rnd.randint(0, 15)) & M32
    fx.d(EXB + 0x60, date)
    fx.d(EXB + 0x64, rnd.randint(0, 86399))
    fx.d(EXB + 0x68, rnd.choice([rnd.randint(0, 1999999999), 0, 999999, 1000000]))
    fx.q(EXB + 0x48, rnd.choice([0, 5, M64, M64 - 1, rnd.getrandbits(64)]))
    cap = rnd.choice([0, 3, 8])
    fx.q(EVV, cap)
    fx.q(EVV + 8, EVBUF)
    fx.q(EVV + 0x10, rnd.choice([0, cap, min(cap, 2)]))
    return fx


def body_config(rnd, image):
    vo = bytearray(rnd.randbytes(0x70))
    vo[0:2] = p16(0x1A2) if rnd.random() < 0.8 else p16(rnd.choice([0x156, 0x100, 0x1A3, 0]))
    vo[0x10] = rnd.choice([0, 1, 2, 3, 2, 2, 0xFF, 6, 0x82, 0x42])
    band = 0xA8C000000000
    b = rnd.choice([rnd.randint(0, band - 1), (-rnd.randint(1, 0x9A0000000000)) & M64, band - 1, band, (-0xA8C000000000) & M64, rnd.getrandbits(64), 0])
    tout = rnd.randbytes(8) + p64(b)
    return {
        "classify": rnd.choice([0, 3, 9, 1, 2, 4, 5, 6, 0, 7, 8, 10, 11, M64]), "count": rnd.choice([0, 1, 5, rnd.getrandbits(4), rnd.getrandbits(4), rnd.getrandbits(8), M64]),
        "validate_out": bytes(vo), "f64_bits": u64(image.blob, image.offset(0x4592B0)),
        "secs": rnd.choice([rnd.randint(0, 5000), rnd.randint(0, 5000), 9223372036, 9223372037, 1 << 63, M64]), "nanos": rnd.randint(0, 999999999), "time_out": tout,
        "days_ret": rnd.choice([0, 1, rnd.getrandbits(32), rnd.getrandbits(32)]),
        "record_out": rnd.randbytes(0x78), "body_out": b"",
        "const_default": bytes(image.blob[image.offset(0x4679D0):image.offset(0x4679D0) + 12]),
    }


def small_fixture(rnd):
    fx = Fixture()
    fx.q(ARG, pick_cap(rnd))
    fx.q(ARG + 8, rnd.getrandbits(40))
    fx.q(ARG + 0x20, pick_cap(rnd))
    fx.q(ARG + 0x28, rnd.getrandbits(40))
    return fx, {}


def events_fixture(rnd):
    fx = Fixture()
    cap = rnd.choice([0, 0, 1, 3, 8])
    fx.q(EVV, cap)
    fx.q(EVV + 8, EVBUF + rnd.randint(0, 16) * 0x2B8)
    fx.q(EVV + 0x10, rnd.randint(0, min(cap, 5)) if cap else rnd.choice([0, 0, 2]))
    return fx, {}


# ---------------------------------------------------------------------------------------------------------------------
# One checked case: run the bytes, run the model, compare everything the model claims
# ---------------------------------------------------------------------------------------------------------------------

def digest(obj):
    return hashlib.sha256(repr(obj).encode()).hexdigest()[:12]


def check_root(rig, rnd, mut=()):
    fx, cfg = root_fixture(rnd)
    status, rax, trace, mem = rig.run(ROOT_FN, fx, {RDI: OUT, RSI: KEY, RDX: ARG, RCX: EXS}, cfg)
    mstatus, mtrace, info = model_root(fx, mut)
    ok = status == mstatus and trace == mtrace
    if ok and status == "ret":
        ok = mem[OUT - H:OUT - H + 0x70] == cfg["body_out"]
    return ok, mstatus, mtrace


def body_path(status, trace, wrote, cfg):
    names = [t[0] for t in trace]
    if "apply_update" in names:
        last = [t for t in trace if t[0] == "date_days"]
        if "date_days" not in names:
            return "apply-range-fallback"
        return "apply-days-fallback" if cfg["days_ret"] & M32 == 0 else "apply-ok"
    if status.startswith("stop"):
        return "event-queued-grow" if "vec_grow" in names else "event-queued"
    if "validate" in names:
        return "validate-error"
    if "ring_count" in names:
        return "limit-reject"
    return "classify-reject"


def check_body(rig, rnd, mut=()):
    fx = body_fixture(rnd)
    cfg = body_config(rnd, rig.image)
    status, rax, trace, mem = rig.run(BODY_FN, fx, {RDI: OUT, RSI: STATE, RDX: CTX}, cfg)
    mstatus, mtrace, mout, wrote = model_body(fx, cfg, mut)
    ok = status == mstatus and trace == mtrace
    if ok:
        for off, data in mout.items():
            ok = ok and mem[OUT - H + off:OUT - H + off + len(data)] == data
        ex = fx.gq(CTX + 0x68)
        if "nonce" in wrote:
            ok = ok and u64(mem, EXB + 0x48 - H) == wrote["nonce"]
        if mstatus == "stop:tail":
            at = wrote["events_ptr"] + (wrote["events_len"] - 1) * 0x2B8 - H
            ok = ok and elem_defined(mem[at:at + 0x2B8]) == wrote["event"]
            ok = ok and (u64(mem, EVV + 0x10 - H), u64(mem, EVV - H), u64(mem, EVV + 8 - H)) == (wrote["events_len"], wrote["events_cap"], wrote["events_ptr"])
    return ok, body_path(mstatus, mtrace, wrote, cfg), mtrace


def check_small(rig, rnd, mut=()):
    fx, cfg = small_fixture(rnd)
    status, rax, trace, mem = rig.run(SMALL_DROP, fx, {RDI: ARG}, cfg)
    mstatus, mtrace = model_small_drop(fx, ARG, mut)
    return status == mstatus and trace == mtrace, "free-%d" % len(mtrace), mtrace



# ---------------------------------------------------------------------------------------------------------------------
# Result-enum drop glue 0x42320d0 (jump tables decoded from the bytes, nine handlers modelled)
# ---------------------------------------------------------------------------------------------------------------------

TABLE_A = (0x7C7828, 0x9C, 0x3D)   # tags 0x3d..0xd8
TABLE_B = (0x7C7A98, 0x1A, 0xF0)   # tags 0xf0..0x109
TABLE_C = (0x7C7B90, 7)            # sub-kinds of tag 0xc0 (byte at +8)
TABLE_D = (0x7C7B00, 0x24)         # sub-kinds of tag 0x160 (byte at +0x10)
HANDLER_NAMES = {
    0x42320FD: "dyn-first-slot", 0x4232130: "two-buffers", 0x4232195: "free-if-positive", 0x42321A9: "free-if-nonzero",
    0x42321C7: "niche-or-free", 0x4232209: "boxed-node", 0x4232232: "sub-kind-byte", 0x423225A: "free-len-at-0x10",
    0x423228A: "nothing",
}
SUB_NAMES = {0x423224C: "nested-at-0x10", 0x423225A: "free-len-at-0x10", 0x423228A: "nothing", 0x42322A6: "free-len-at-0x18",
             0x42322B8: "nested-at-0x20", 0x42322C6: "range-or-dyn", 0x423230B: "three-fields", 0x4232369: "free-len-at-0x20"}


class BadPointer(Exception):
    pass


class Probe(Fixture):
    def get(self, addr, n):
        if addr < H or addr + n > H + USED:
            raise BadPointer(hex(addr))
        return super().get(addr, n)

    def gq(self, addr):
        return u64(self.get(addr, 8), 0)


def jump_table(image, base, count):
    off = image.offset(base)
    return [base + struct.unpack_from("<i", image.blob, off + 4 * i)[0] for i in range(count)]


def decode_tables(image):
    a = jump_table(image, TABLE_A[0], TABLE_A[1])
    b = jump_table(image, TABLE_B[0], TABLE_B[1])
    c = jump_table(image, *TABLE_C)
    d = jump_table(image, *TABLE_D)
    return a, b, c, d


def handler_for_tag(tag, tables):
    a, b, c, d = tables
    if tag <= 0xEF:
        i = tag - TABLE_A[2]
        return a[i] if 0 <= i < TABLE_A[1] else 0x423228A
    if tag <= 0x15F:
        i = tag - TABLE_B[2]
        return b[i] if 0 <= i < TABLE_B[1] else 0x423228A
    if tag == 0x160:
        return "sub160"
    if tag in (0x16F, 0x17D):
        return 0x42321A9
    if tag == 0x188:
        return 0x4232195
    return 0x423228A


def dyn_box(fx, r14, r15, mut=()):
    out = []
    drop = fx.gq(r15)
    if drop and drop != DROPFN:
        raise BadPointer("drop slot is not the modelled target")
    if drop:
        out.append(("dyn", r14))
    size = fx.gq(r15 + 8)
    if size == 0:
        return out
    align = fx.gq(r15 + 0x10)
    tz = (align & -align).bit_length() - 1 if align else 64
    flag = 0
    if align > size:
        flag = tz
    if align >= (0x10 if "dyn_align" in mut else 0x11):
        flag = tz
    out.append(("dealloc", r14, size, flag))
    return out


def free_if(fx, at, size_at, nonzero_only=True):
    size = fx.gq(size_at)
    return [("dealloc", fx.gq(at), size, 0)] if size else []


def model_enum_drop(fx, at, tables, mut=()):
    tag = u16(fx.get(at, 2), 0)
    h = handler_for_tag(tag, tables)
    q = lambda off: fx.gq(at + off)
    if h == 0x423228A:
        return []
    if h == "sub160":
        sub = fx.get(at + 0x10, 1)[0]
        if sub > 0x23:
            return dyn_box(fx, q(0x18), q(0x20), mut)
        h2 = tables[3][sub]
        if h2 == 0x423228A:
            return []
        if h2 == 0x42322A6:
            return [("dealloc", q(0x20), q(0x18), 0)] if q(0x18) else []
        if h2 == 0x42322B8:
            return [("nested", 0x4233F10, at + 0x20)]
        if h2 == 0x4232369:
            return [("dealloc", q(0x28), q(0x20), 0)] if q(0x20) else []
        if h2 == 0x42322C6:
            x = q(0x20)
            k = x - 0x26 if x >= 0x26 else 0xB
            if k < 0xB or k == 0xC:
                return []
            if k == 0xB:
                return [("nested", 0x4233F10, at + 0x20)]
            return dyn_box(fx, q(0x28), q(0x30), mut)
        out = []
        s = q(0x40)
        if s not in (NICHE, 0):
            out.append(("dealloc", q(0x48), s, 0))
        if q(0x28) in (2, 0):
            return out
        if q(0x38):
            out.append(("dealloc", q(0x30), q(0x38), 0))
        return out
    if h == 0x42320FD:
        obj = q(8)
        if fx.gq(fx.gq(obj)) != DROPFN:
            raise BadPointer("no first slot")
        return [("dyn", obj)]
    if h == 0x4232130:
        out = [("dealloc", q(0x10), q(8), 0)] if q(8) else []
        if q(0x20):
            out.append(("dealloc", q(0x28), q(0x20) * (8 if "scale16" in mut else 16) & M64, 0))
        return out
    if h == 0x4232195:
        s = q(8)
        return [("dealloc", q(0x10), s, 0)] if (s != 0 if "free_pos" in mut else sext(s, 64) > 0) else []
    if h == 0x42321A9:
        return [("dealloc", q(0x10), q(8), 0)] if q(8) else []
    if h == 0x42321C7:
        s = q(8)
        k = (s ^ NICHE) if sext(s, 64) < 0 else 4
        if 1 <= k <= (2 if "k_range" in mut else 3):
            return []
        if k:
            return [("dealloc", q(0x10), s, 0)] if s else []
        return [("nested", 0x4232440, at + 0x18)]
    if h == 0x4232209:
        node = q(8)
        t0 = fx.gq(node)
        out = []
        if t0 == 1:
            out.append(("nested", 0x4232440, node + 8))
        elif t0 == 0 and fx.gq(node + 0x10):
            out.append(("dealloc", fx.gq(node + 8), fx.gq(node + 0x10), 0))
        out.append(("dealloc", node, 0x30 if "node_size" in mut else 0x28, 0))
        return out
    if h == 0x4232232:
        kind = fx.get(at + 8, 1)[0]
        if kind > 6:
            return []
        h2 = tables[2][kind]
        if h2 == 0x423224C:
            return [("nested", 0x4232440, at + 0x10)]
        if h2 == 0x423225A:
            return [("dealloc", q(0x18), q(0x10), 0)] if q(0x10) else []
        return []
    if h == 0x423225A:
        return [("dealloc", q(0x18), q(0x10), 0)] if q(0x10) else []
    raise EvidenceError("unmodelled handler %#x" % h)


def enum_fixture(rnd, tag):
    """A payload built from scalar pools and pointers to three universal objects plus a drop table."""
    fx = Fixture()
    vt = H + 0x8100          # {drop fn or 0, size, align} drop table
    u0, u1, uv = H + 0x8200, H + 0x8300, H + 0x8400
    drop = rnd.choice([0, DROPFN, DROPFN])
    fx.q(vt, drop)
    size, align = rnd.choice([0, 0x20, 8, 1, 0x1000, rnd.getrandbits(20)]), rnd.choice([0, 1, 8, 16, 32, 64, 4096, rnd.getrandbits(12)])
    if rnd.random() < 0.3:
        size, align = rnd.choice([0x10, 0x20, 0x40]), 16
    fx.q(vt + 8, size)
    fx.q(vt + 0x10, align)
    fx.q(u0, 0)
    fx.q(u0 + 8, rnd.getrandbits(40))
    fx.q(u0 + 0x10, rnd.choice([0, 5, 0x40]))
    fx.q(u1, 1)
    fx.q(u1 + 8, 0)
    fx.q(u1 + 0x10, 0)
    fx.q(uv, vt)
    fx.q(uv + 8, 0)
    fx.q(uv + 0x10, 0)
    fx.q(uv + 0x18, 0)
    # nested node object used by the boxed-node handler: first word picks the variant
    pool = [0, 1, 2, 3, 4, 5, 7, 0x26, 0x30, 0x31, 0x32, 0x40, NICHE, NICHE + 1, NICHE + 2, NICHE + 3, NICHE + 4, NICHE + 7,
            rnd.getrandbits(40), rnd.getrandbits(8), M64, u0, u1, uv, vt]
    words = [rnd.choice(pool) for _ in range(10)]
    if rnd.random() < 0.4:
        words[0] = NICHE + rnd.randint(0, 8)
    body = p16(tag) + bytes(6) + b"".join(p64(w) for w in words)
    if tag == 0x160 or tag == 0xC0:
        off = 0x10 if tag == 0x160 else 8
        body = bytearray(body)
        body[off] = rnd.choice([0, 3, 15, 21, 27, 29, 30, 31, 34, 0x23, 0x24, 5, 6, 1, 2, 4, 7, rnd.randint(0, 255), 3, 3, 0x24, 0x30])
        if tag == 0x160 and body[off] == 3:
            body[0x20:0x28] = p64(rnd.choice([0x26 + k for k in range(0, 16)] + [rnd.getrandbits(8)]))
        body = bytes(body)
    fx.put(ARG, body)
    return fx


ENUM_TAGS = list(range(0x30, 0x115)) + [0x15F, 0x160, 0x161, 0x16F, 0x17C, 0x17D, 0x17E, 0x188, 0x189, 0x1A2, 0x1FF]


def check_enum(rig, rnd, mut=(), tables=None):
    tag = rnd.choice(ENUM_TAGS) if rnd.random() < 0.4 else rnd.choice([0xC0, 0xC1, 0xC1, 0xC2, 0x160, 0x160, 0x160, 0x105, 0x7E, 0x89, 0xD7, 0x16F, 0x188])
    fx = enum_fixture(rnd, tag)
    probe = Probe()
    probe.buf = fx.buf
    try:
        mtrace = model_enum_drop(probe, ARG, tables or rig.tables, mut)
    except (BadPointer, IndexError):
        mtrace = None
    try:
        status, rax, trace, mem = rig.run(ENUM_DROP, fx, {RDI: ARG}, {})
    except (Halt, EvidenceError):
        status, trace = "halt", []
    if mtrace is None:
        return status == "halt", "invalid-pointer", []
    return status == "ret" and trace == mtrace, "tag-%s" % ("%#x" % tag if tag in (0xC0, 0xC1, 0xC2, 0x160, 0x105, 0x7E, 0x89, 0xD7, 0x16F, 0x188) else "other"), mtrace



def check_events(rig, rnd, mut=()):
    fx, cfg = events_fixture(rnd)
    status, rax, trace, mem = rig.run(EVENTS_DROP, fx, {RDI: EVV}, cfg)
    mstatus, mtrace = model_events_drop(fx, EVV, mut)
    return status == mstatus and trace == mtrace, "events-%d" % fx.gq(EVV + 0x10), mtrace


CHECKS = {"root": check_root, "body": check_body, "small": check_small, "events": check_events, "enum": check_enum}
SALT = {"root": 1, "body": 2, "small": 3, "events": 4, "enum": 5}
COUNTS = {"root": 4000, "body": 9000, "small": 1500, "events": 1500, "enum": 8000}
SAMPLE_EVERY = {"root": 8, "body": 8, "small": 5, "events": 5, "enum": 6}


def case_rng(kind, index):
    return random.Random(SEED * 1000003 + SALT[kind] * 100000007 + index)


# ---------------------------------------------------------------------------------------------------------------------
# Byte pins: immediates and literals the models rely on, read from the ELF with struct
# ---------------------------------------------------------------------------------------------------------------------

def fn_bytes(image, va):
    start, end = image.exact_fde(va)
    off = image.offset(start)
    return start, bytes(image.blob[off:off + end - start])


def find_all(data, pattern):
    at, found = 0, []
    while True:
        at = data.find(pattern, at)
        if at < 0:
            return found
        found.append(at)
        at += 1


PINS = [  # (function, name, byte pattern, expected count, meaning)
    (ROOT_FN, "divisor-10000-magic", b"\x48\xb9" + p64(0x346DC5D63886594B), 1, "movabs 0x346dc5d63886594b then shr 11: asset id / 10000"),
    (ROOT_FN, "clearinghouse-stride", b"\x69" + b"\xec" + p32(0x510), 0, "imul $0x510 (register form varies; counted by immediate)"),
    (ROOT_FN, "imm-0x510", p32(0x510), 1, "clearinghouse record stride 0x510"),
    (ROOT_FN, "imm-10000", p32(0x2710), 1, "imul $0x2710: asset id minus dex*10000"),
    (ROOT_FN, "imm-0x188", p32(0x188), 1, "add $0x188: oracle book offset inside the 0x200 stride entry"),
    (ROOT_FN, "len-field-0x7d0", p32(0x7D0), 2, "clearinghouse count at exchange state +0x7d0 (compare and base)"),
    (ROOT_FN, "len-field-0x3ad0", p32(0x3AD0), 1, "oracle book count at exchange state +0x3ad0"),
    (ROOT_FN, "limit-field-0x39d0", p32(0x39D0), 1, "limit read from exchange state +0x39d0"),
    (ROOT_FN, "guard-tag-0x156", b"\x66\xc7\x44\x24\x30" + p16(0x156), 4, "movw $0x156 guard tag stores"),
    (BODY_FN, "ok-tag-0x1a2", b"\x3d" + p32(0x1A2), 1, "cmp $0x1a2,%eax: validate result Ok tag"),
    (BODY_FN, "reject-0xd2", b"\x66\xc7\x03" + p16(0xD2), 1, "movw $0xd2: classification reject"),
    (BODY_FN, "reject-0xdd", b"\x66\xc7\x03" + p16(0xDD), 1, "movw $0xdd: size limit reject"),
    (BODY_FN, "imm-86400", p32(0x15180), 1, "imul $0x15180: seconds per day"),
    (BODY_FN, "imm-1000", p32(0x3E8), 1, "imul $0x3e8: seconds to milliseconds"),
    (BODY_FN, "imm-epoch-0xfff506c5", p32(0xFFF506C5), 1, "add $0xfff506c5 = -719163: days from CE to the Unix epoch"),
    (BODY_FN, "imm-1e9", p32(0x3B9ACA00), 2, "mov/imul $0x3b9aca00: nanoseconds per second"),
    (BODY_FN, "event-size-0x2b8", p32(0x2B8), 5, "event element size 0x2b8"),
    (EVENTS_DROP, "event-size-0x2b8", p32(0x2B8), 3, "event element size in the drop loop"),
    (SMALL_DROP, "niche-0x8000000000000001", p64(NICHE + 1), 1, "capacity niche that skips the whole block"),
]


def pin_rows(image):
    rows = []
    for fn, name, pattern, expect, meaning in PINS:
        start, data = fn_bytes(image, fn)
        hits = find_all(data, pattern)
        rows.append((fn, name, pattern.hex(), len(hits), ",".join("%#x" % (start + h) for h in hits[:6]), meaning))
    return rows


def panic_literals(image):
    """Decode the three RIP-relative lea triples of the root's panic sites from the bytes."""
    start, data = fn_bytes(image, ROOT_FN)
    rows = []
    for site in find_all(data, b"\x48\x8d\x3d"):
        disp = struct.unpack_from("<i", data, site + 3)[0]
        rows.append(("rdi", start + site, start + site + 7 + disp))
    for site in find_all(data, b"\x48\x8d\x0d"):
        disp = struct.unpack_from("<i", data, site + 3)[0]
        rows.append(("rcx", start + site, start + site + 7 + disp))
    for site in find_all(data, b"\x4c\x8d\x05"):
        disp = struct.unpack_from("<i", data, site + 3)[0]
        rows.append(("r8", start + site, start + site + 7 + disp))
    return rows


# ---------------------------------------------------------------------------------------------------------------------
# Negative controls
# ---------------------------------------------------------------------------------------------------------------------

MODEL_MUTANTS = [  # (kind, flag, description)
    ("root", "dex_div", "divide the asset id by 1000 instead of 10000"),
    ("root", "dex_stride", "clearinghouse stride 0x500"),
    ("root", "dex_cmp", "clearinghouse bound uses > instead of >="),
    ("root", "asset_stride", "asset row stride 0x58"),
    ("root", "price_off", "price read at row +0x28"),
    ("root", "local_mul", "local index uses dex*1000"),
    ("root", "book_stride", "oracle book stride 0x1f8"),
    ("root", "book_off", "oracle book offset 0x180"),
    ("root", "key_cut", "key copied as 0x13 bytes"),
    ("body", "limit_cmp", "size limit rejects only above the limit"),
    ("body", "ok_tag", "Ok tag 0x1a3"),
    ("body", "wrap", "event counter wraps instead of saturating"),
    ("body", "epoch", "epoch constant off by one"),
    ("body", "no_clamp", "milliseconds not clamped at zero"),
    ("body", "classify_ge", "classification reject above 8"),
    ("body", "limit_code", "size-limit reject code 0xde"),
    ("body", "ms_shift", "nanosecond divisor shift 0x31"),
    ("body", "flag_mask", "trading flag masked with 3"),
    ("body", "nonce_inc2", "event counter advances by two"),
    ("body", "ev_tag", "queued event tag 5"),
    ("body", "f64_total", "nanosecond total clamped one lower"),
    ("small", "first_niche1", "first niche 0x8000000000000001 not special"),
    ("small", "second_niche_free", "second niche frees"),
    ("events", "event_size", "event stride 0x2b0"),
    ("events", "cap_free", "frees a zero-capacity buffer"),
    ("enum", "free_pos", "free-if-positive handler frees any nonzero length"),
    ("enum", "scale16", "two-buffers handler scales the second length by 8"),
    ("enum", "k_range", "niche-or-free handler skips only kinds 1..2"),
    ("enum", "node_size", "boxed-node handler frees 0x30 bytes"),
    ("enum", "dyn_align", "boxed trait object keeps its alignment flag from 0x10"),
]

BYTE_PATCHES = [  # (kind, function, pattern, description); one byte of the first match is incremented
    ("root", ROOT_FN, p32(0x510), "clearinghouse stride immediate"),
    ("root", ROOT_FN, p32(0x2710), "per-clearinghouse asset count immediate"),
    ("root", ROOT_FN, p32(0x188), "oracle book offset immediate"),
    ("root", ROOT_FN, p32(0x3AD0), "oracle book count field offset"),
    ("root", ROOT_FN, p32(0x39D0), "limit field offset"),
    ("root", ROOT_FN, b"\x48\xb9" + p64(0x346DC5D63886594B), "division magic constant"),
    ("body", BODY_FN, b"\x3d" + p32(0x1A2), "Ok tag compare"),
    ("body", BODY_FN, b"\x66\xc7\x03" + p16(0xD2), "classification reject code"),
    ("body", BODY_FN, b"\x66\xc7\x03" + p16(0xDD), "size limit reject code"),
    ("body", BODY_FN, p32(0x15180), "seconds per day immediate"),
    ("body", BODY_FN, p32(0x3E8), "milliseconds immediate"),
    ("body", BODY_FN, p32(0xFFF506C5), "epoch day offset"),
    ("body", BODY_FN, p32(0x51EB851F), "century divisor magic (year <= 0 branch)", 0),
    ("body", BODY_FN, p32(0x51EB851F), "century divisor magic (division by 100)", 1),
    ("body", BODY_FN, p32(0x431BDE83), "nanosecond divisor magic"),
    ("body", BODY_FN, p32(0x5B5), "leap-year multiplier 1461"),
    ("small", SMALL_DROP, p64(NICHE + 1), "skip-all niche constant"),
    ("events", EVENTS_DROP, p32(0x2B8), "event size immediate"),
    ("enum", ENUM_DROP, b"\x48\x83\xea\x26", "range base 0x26 of the nested-or-dyn handler", 0, 3),
    ("enum", ENUM_DROP, b"\xbe\x28\x00\x00\x00", "boxed-node size 0x28", 0, 1),
    ("enum", ENUM_DROP, b"\x48\x83\xf8\x11", "alignment-flag threshold 0x11", 0, 3),
    ("enum", ENUM_DROP, b"\x48\x83\xf8\x23", "sub-kind bound 0x23", 0, 3),
    ("enum", ENUM_DROP, b"\x3d\x5f\x01\x00\x00", "tag bound 0x15f", 0, 1),
    ("enum", ENUM_DROP, b"\x48\xc1\xe6\x04", "second-buffer scale shift", 0, 3),
]


def first_mismatch(kind, limit, mut=(), patches=None, image=None, rig=None):
    check = CHECKS[kind]
    if rig is None:
        rig = Rig(image, patches)
    for index in range(limit):
        try:
            ok = check(rig, case_rng(kind, index), mut)[0]
        except (Halt, EvidenceError):
            ok = False
        if not ok:
            return index
    return -1


def control_rows(image):
    rows = []
    rigs = {}
    for kind, flag, text in MODEL_MUTANTS:
        if kind not in rigs:
            rigs[kind] = Rig(image)
        tries = 3000 if kind == "enum" else 600
        at = first_mismatch(kind, tries, (flag,), rig=rigs[kind])
        rows.append(("model-mutant", kind, flag, text, tries, at, int(at >= 0)))
    for entry in BYTE_PATCHES:
        kind, fn, pattern, text = entry[:4]
        start, data = fn_bytes(image, fn)
        hits = find_all(data, pattern)
        if not hits:
            rows.append(("byte-patch", kind, "%#x" % fn, text, 600, -1, 0))
            continue
        where = start + hits[entry[4] if len(entry) > 4 else 0] + (entry[5] if len(entry) > 5 else 3 if pattern[:1] == b"\x48" and len(pattern) > 8 else 0)
        patched = {where: image.blob[image.offset(where)] ^ 0x01}
        at = first_mismatch(kind, 4000, (), patches=patched, image=image)
        rows.append(("byte-patch", kind, "%#x" % where, text, 4000, at, int(at >= 0)))
    return rows


# ---------------------------------------------------------------------------------------------------------------------
# Evidence writer
# ---------------------------------------------------------------------------------------------------------------------

def tsv(path, header, rows):
    with open(path, "w", newline="\n") as handle:
        handle.write("\t".join(header) + "\n")
        for row in rows:
            handle.write("\t".join(str(item) for item in row) + "\n")


def run_cases(image, out):
    rig = Rig(image)
    summary = {}
    paths = {}
    total = 0
    for kind in ("root", "body", "small", "events", "enum"):
        rows = []
        failures = 0
        check = CHECKS[kind]
        for index in range(COUNTS[kind]):
            ok, label, trace = check(rig, case_rng(kind, index))
            total += 1
            failures += 0 if ok else 1
            paths[(kind, label)] = paths.get((kind, label), 0) + 1
            if index % SAMPLE_EVERY[kind] == 0:
                rows.append((kind, index, label, len(trace), digest(trace), "match" if ok else "DIFF"))
        tsv(out / ("cases-%s.tsv" % kind), ("kind", "case", "path", "calls", "trace-digest", "result"), rows)
        summary[kind] = failures
    tsv(out / "paths.tsv", ("kind", "path", "cases"), sorted((k, p, n) for (k, p), n in paths.items()))
    return total, summary


def members_rows(image):
    rows = []
    roles = {
        0x2419810: "event flush after the update (not modelled: calls through event vtables)",
        0x2753B90: "root: asset id to clearinghouse/asset, context build, body call, event flush (modelled)",
        0x2776870: "drop of the 0x2b8-byte event vector (modelled)",
        0x277E390: "drop glue of the large result enum (copy of 0x42320d0; not modelled)",
        0x2783790: "drop of the two-string argument block (modelled)",
        0x2D35A80: "update body: reject ladder, counter, block-time arithmetic, event queue (modelled to the map-entry call)",
        0x42320D0: "drop glue of the large result enum (tag 0x156 no-op class only is exercised by the root)",
    }
    for va in MEMBERS:
        start, end = image.exact_fde(va)
        rows.append(("%#x" % va, end - start, roles[va]))
    return rows


def century_equivalence():
    """The year <= 0 century magic cannot be observed: every such date maps to a negative day count, clamped to 0 ms."""
    checked = 0
    for year in range(-262144, 1):
        for ordinal in (1, 366):
            date = (year << 13 | ordinal << 4) & M32
            for secs, nanos in ((0, 0), (86399, 1999999999)):
                if days_millis(date, secs, nanos) != 0 or days_millis(date, secs, nanos, ("century_m1",)) != 0:
                    return checked, False
                checked += 1
    return checked, True


def tag_bound_equivalence(image):
    """Moving the 0x15f tag bound down by one routes tag 0x15f the other way, but both routes end in the no-op return."""
    base = Rig(image)
    where = fn_bytes(image, ENUM_DROP)[0] + find_all(fn_bytes(image, ENUM_DROP)[1], b"\x3d\x5f\x01\x00\x00")[0] + 1
    patched = Rig(image, {where: image.blob[image.offset(where)] ^ 1})
    checked = 0
    for tag in (0x15E, 0x15F, 0x160, 0x161):
        for index in range(60):
            fx = enum_fixture(random.Random(index * 977 + tag), tag)
            outcome = []
            for rig in (base, patched):
                try:
                    run = rig.run(ENUM_DROP, fx, {RDI: ARG}, {})
                    outcome.append((run[0], tuple(run[2])))
                except (Halt, EvidenceError):
                    outcome.append(("halt", ()))
            if outcome[0] != outcome[1]:
                return checked, False
            checked += 1
    return checked, True


def generate(out):
    out = pathlib.Path(out)
    out.mkdir(parents=True, exist_ok=True)
    image = load_image()
    total, summary = run_cases(image, out)
    if any(summary.values()):
        raise EvidenceError("model differs from the bytes: %r" % (summary,))
    controls = control_rows(image)
    tsv(out / "controls.tsv", ("kind", "target", "where", "description", "cases-tried", "first-mismatch", "detected"), controls)
    tsv(out / "members.tsv", ("function", "bytes", "role"), members_rows(image))
    tsv(out / "pins.tsv", ("function", "pin", "pattern", "matches", "addresses", "meaning"),
        [("%#x" % r[0],) + r[1:] for r in pin_rows(image)])
    tsv(out / "panic-literals.tsv", ("register", "lea-site", "target"), [(r, "%#x" % a, "%#x" % t) for r, a, t in panic_literals(image)])
    detected = sum(row[-1] for row in controls)
    checked, proven = century_equivalence()
    equivalent_rows = []
    for row in controls:
        if row[0] == "byte-patch" and not row[-1] and row[3].endswith("(year <= 0 branch)") and proven:
            equivalent_rows.append((row[1] + ":" + row[3], row[2], "year<=0 gives a negative day count; the Unix-ms clamp returns 0 for the patched and the original constant (%d dates x 2 clocks checked, whole i32 year field)" % checked))
    bound_checked, bound_proven = tag_bound_equivalence(image)
    for row in controls:
        if row[0] == "byte-patch" and not row[-1] and row[3] == "tag bound 0x15f" and bound_proven:
            equivalent_rows.append((row[1] + ":" + row[3], row[2], "tags above 0x109 and up to 0x15f reach the no-op return through the table bound check, tag 0x15f included, so lowering the first bound only changes which test sends 0x15f to the no-op (%d tag/payload pairs run on both byte versions)" % bound_checked))
    tsv(out / "equivalent-mutants.tsv", ("mutation", "address", "same-because"), equivalent_rows)
    measure = {"cases": total, "negative_controls": len(controls), "negative_detected": detected, "equivalent": len(equivalent_rows),
               "case_failures": sum(summary.values()), "binary_sha256": SHA256}
    (out / "measure.json").write_text(json.dumps(measure, indent=2, sort_keys=True) + "\n")
    return measure


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--out", required=True)
    args = parser.parse_args(argv)
    print(json.dumps(generate(args.out), sort_keys=True))


if __name__ == "__main__":
    main()
