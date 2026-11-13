#!/usr/bin/env python3
"""Reconstruct the node #115 order-nonce admission check (0x4228080) with its callees and prove it on the original bytes.

The body takes a sorted nonce ring, one candidate nonce, a clock made of a packed calendar date word plus
seconds and nanoseconds, two flag bytes and an optional second container (a 24-byte-entry ring or a B-tree
of u64 keys). It answers with a 24-byte record: a tag and up to two words. The tags are the action error
tags whose Display texts the error-display packet recovered (0xcb too low, 0xcc too high, 0xcd duplicate,
0x61 too many pending nonces) plus the success value 0x1a2, the first value past the 418-slot Display table,
which carries the insertion position. The binary is never run: a concrete x86-64 subset interpreter reads
the original bytes of the body and of its four callees (ring search, evict fold, 24-byte ring search,
B-tree search), and an independent model predicts the record for every case.
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
            lanes = (b"\xff" if (left[at] ^ 0x80) > (right[at] ^ 0x80) else b"\x00" for at in range(16))
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
# Packet code: model of the nonce admission body 0x4228080 and its proof against the bytes.
# ---------------------------------------------------------------------------------------------
import argparse
import json
import random

ENTRY = 0x4228080
SEARCH = 0x4551530
FOLD = 0x450C430
TABLE_VA = 0x7D8C1C
TABLE_SLOTS = 418
TAG_LOW, TAG_HIGH, TAG_DUP, TAG_FULL, TAG_OK = 0xCB, 0xCC, 0xCD, 0x61, 0x1A2
M32 = 0xFFFFFFFF
M64X = (1 << 64) - 1
OUT, ARGS, SET, SEC, BUF = HEAP_BASE + 0x100, HEAP_BASE + 0x200, HEAP_BASE + 0x300, HEAP_BASE + 0x400, HEAP_BASE + 0x1000
SENTINEL_OUT = 0x5EED5EED5EED5EED
CASES = 12000
PATCH_CASES = 1000
DIRECT_CASES = 6000
DIRECT_PATCH = 1500
WRAP_CASES = 4000
WRAP_PATCH = 500
CASE_SEED = 115


def s32(v):
    v &= M32
    return v - (1 << 32) if v & 0x80000000 else v


def s64(v):
    v &= M64X
    return v - (1 << 64) if v >> 63 else v


DEFAULT = dict(
    cap_swap=False, low_le=False, low_idx_plus=False, upper_flagless=False, upper_ge=False, lower_swap=False,
    lower_nosat=False, lower_le=False, skip_dup=False, dup_tag=TAG_DUP, early_tag=TAG_LOW, no_clamp=False,
    nano_div=1000000, ordinal_off=0, no_secs=False, no_c100=False, no_c400=False, no_cycle=False,
    pos_right=False, count_off=0, count_nosat=False, full_when_zero=False, skip_sec_check=False,
    dup_first=False, upper_first=False, swap_high=False, ok_len=False, early_gt=False, ok_lt=False,
    low_tag_late=TAG_LOW, ok_tag=TAG_OK, year_off=0, ms_off=0, newest=False, all_items=False,
)


def clock_ms(date, secs, nanos, o):
    """Millisecond clock the body derives from the packed date word and the two time words."""
    year = (s32(date) >> 13) + o['year_off']
    ordinal = ((date >> 4) & 0x1FF) + o['ordinal_off']
    y1 = year - 1
    delta = 0
    if year <= 0 and not o['no_cycle']:
        cycles = (((1 - year) & M32) * 0x51EB851F >> 39) + 1
        y1 = s32(y1 + cycles * 400)
        delta = s32(-cycles * 146097)
    t1 = s32(y1 * 0x5B5) >> 2
    prod = y1 * 0x51EB851F
    q100 = (prod >> 37) + (1 if prod < 0 else 0)
    q400 = q100 >> 2
    days = ordinal + delta
    if not o['no_c100']:
        days -= q100
    days += t1
    if not o['no_c400']:
        days += q400
    days = s32(days - 719163)
    seconds = days * 86400 + (0 if o['no_secs'] else secs)
    if o['nano_div'] == 1000000:
        sub_ms = (nanos * 0x431BDE83) >> 50
    else:
        sub_ms = nanos // o['nano_div']
    ms = s64(seconds * 1000 + sub_ms + o['ms_off'])
    if o['no_clamp']:
        return ms
    return ms if ms > 0 else 0


def admit(ring, nonce, sec, date, secs, nanos, flag_a, flag_b, o=DEFAULT):
    """Return ((tag, word1, word2), fold_call) for a sorted ring (logical order) and the argument words."""
    cap_big = flag_a != 0
    if o['cap_swap']:
        cap_big = not cap_big
    limit = 400 if cap_big else 100
    length = len(ring)
    flag = flag_b != 0
    now = clock_ms(date, secs, nanos, o)
    upper = now + (86400000 if (o['upper_flagless'] or not flag) else 86400000 - 120000)
    sub = 172680000 if flag else 172800000
    if o['lower_swap']:
        sub = 172800000 if flag else 172680000
    lower = now - sub
    if not o['lower_nosat']:
        lower = max(lower, 0)

    def early():
        if length >= limit + (1 if o['early_gt'] else 0):
            index = length - limit + (1 if o['low_idx_plus'] else 0)
            smallest = ring[min(index, length - 1)]
            if nonce < smallest or (o['low_le'] and nonce == smallest):
                return (o['early_tag'], nonce, smallest)
        return None

    def high():
        if nonce > upper or (o['upper_ge'] and nonce == upper):
            return (TAG_LOW if o['swap_high'] else TAG_HIGH, nonce, upper)
        return None

    def low():
        if nonce < lower or (o['lower_le'] and nonce == lower):
            return (o['low_tag_late'], nonce, lower)
        return None

    def dup():
        if not o['skip_dup'] and nonce in ring:
            return (o['dup_tag'], nonce, None)
        return None

    steps = [early, high, low, dup]
    if o['dup_first']:
        steps = [dup, early, high, low]
    elif o['upper_first']:
        steps = [high, early, low, dup]
    for check in steps:
        got = check()
        if got is not None:
            return got, None
    position = 0
    while position < length and ring[position] < nonce:
        position += 1
    if o['pos_right']:
        while position < length and ring[position] == nonce:
            position += 1
    if sec is None and not o['skip_sec_check']:
        return (o['ok_tag'], 1, position), None
    reach = length + 1
    count = max(reach - limit, 0) + o['count_off']
    if o['count_nosat']:
        count = reach - limit
    if (reach < limit) if o['ok_lt'] else (reach <= limit):
        return (o['ok_tag'], 1, position), None
    keys = set(sec[1]) if sec else set()
    items = ring[length - count:] if o['newest'] else ring[:count]
    if o['all_items']:
        items = ring
    hit = any(n in keys for n in items)
    if o['full_when_zero']:
        hit = not hit
    if hit:
        return (TAG_FULL, None, None), True
    return (o['ok_tag'], 1, length if o['ok_len'] else position), True


MUTANTS = [
    ('cap-flag-swapped', dict(cap_swap=True)), ('early-low-le', dict(low_le=True)), ('early-index-plus-one', dict(low_idx_plus=True)),
    ('upper-ignores-flag', dict(upper_flagless=True)), ('upper-ge', dict(upper_ge=True)), ('lower-constants-swapped', dict(lower_swap=True)),
    ('lower-not-saturated', dict(lower_nosat=True)), ('lower-le', dict(lower_le=True)), ('duplicate-check-skipped', dict(skip_dup=True)),
    ('duplicate-tag-low', dict(dup_tag=TAG_LOW)), ('early-tag-high', dict(early_tag=TAG_HIGH)), ('clock-not-clamped', dict(no_clamp=True)),
    ('nanos-divisor-1000', dict(nano_div=1000)), ('ordinal-plus-one', dict(ordinal_off=1)), ('seconds-of-day-dropped', dict(no_secs=True)),
    ('century-term-dropped', dict(no_c100=True)), ('four-century-term-dropped', dict(no_c400=True)),
    ('nonpositive-year-cycle-dropped', dict(no_cycle=True)), ('position-after-equals', dict(pos_right=True)),
    ('take-count-plus-one', dict(count_off=1)), ('take-count-minus-one', dict(count_off=-1)), ('take-newest-items', dict(newest=True)), ('take-all-items', dict(all_items=True)), ('skip-count-unsaturated', dict(count_nosat=True)),
    ('fold-result-inverted', dict(full_when_zero=True)), ('secondary-test-ignored', dict(skip_sec_check=True)),
    ('duplicate-before-bounds', dict(dup_first=True)), ('upper-before-early', dict(upper_first=True)),
    ('high-tag-low', dict(swap_high=True)), ('ok-payload-length', dict(ok_len=True)),
    ('early-needs-more-than-limit', dict(early_gt=True)), ('ok-when-reach-lt-limit', dict(ok_lt=True)),
    ('late-low-tag-high', dict(low_tag_late=TAG_HIGH)), ('ok-tag-off-by-one', dict(ok_tag=TAG_OK + 1)),
    ('year-off-by-one', dict(year_off=1)), ('clock-ms-plus-one', dict(ms_off=1)),
]



# ---------------------------------------------------------------------------------------------
# Per-account container lookup 0x3be7e80: the function behind slot 0x64e7ee8. It hashes the 20-byte address with
# SipHash-1-3 (keys held in the map), probes a 16-wide SwissTable of entry indices and returns the 64-byte entry
# (the nonce ring header comes first), appending a fresh empty entry when the address is absent.
# ---------------------------------------------------------------------------------------------
LOOKUP, HASHER, SIPWRITE, FINDER, INSERTER = 0x3BE7E80, 0x4717440, 0x45927A0, 0x3EE6E80, 0x3EC72B0
REHASH, TABLE_DROP, GOT_REHASH = 0x3EE0ED0, 0x3DDD030, 0x64E6290
GOT_ALLOC, GOT_MEMSET, GOT_FREE = 0x64DF480, 0x64DF750, 0x64DF4A0
FAKE_ALLOC, FAKE_MEMSET, FAKE_FREE = 0x7700005000, 0x7700005100, 0x7700005300
ALLOC_BASE = HEAP_BASE + 0x38000
LOOKUP_FUNCTIONS = [(LOOKUP, "account-lookup"), (HASHER, "siphash13-address"), (SIPWRITE, "siphash-write"), (FINDER, "table-find"), (INSERTER, "table-insert"),
                    (REHASH, "table-reserve-rehash"), (TABLE_DROP, "table-drop")]
MAP, KEY_PTR = HEAP_BASE + 0x20000, HEAP_BASE + 0x3400
CTRL_BASE, ENT_BASE = HEAP_BASE + 0x31000, HEAP_BASE + 0x34000
EMPTY, DELETED = 0xFF, 0x80
LK_DEFAULT = dict(rounds_c=1, rounds_d=3, h2_shift=57, no_mirror=False, deleted_full=False, stride_off=0, index_off=0, no_items=False,
                  growth_deleted=False, fresh_cap=0, fresh_ptr=8, hit_off=0, no_hash_store=False, first_group_fix=False,
                  never_in_place=False, in_place_full=False, reverse_reinsert=False, grow_items_off=0, no_grow_mirror=False, no_swap_chain=False,
                  skip_group_test=False, in_place_keep_full=False, halve_buckets=False)
GROW_MUTANTS = frozenset(("never_in_place", "in_place_full", "reverse_reinsert", "grow_items_off", "no_grow_mirror", "no_swap_chain", "skip_group_test", "in_place_keep_full", "halve_buckets"))
LK_MUTANTS = [(name, {name: value}) for name, value in
              (("rounds_c", 2), ("rounds_d", 4), ("h2_shift", 56), ("no_mirror", True), ("deleted_full", True), ("stride_off", 16),
               ("index_off", 1), ("no_items", True), ("growth_deleted", True), ("fresh_cap", 4), ("fresh_ptr", 0),
               ("hit_off", 1), ("no_hash_store", True), ("first_group_fix", True), ("never_in_place", True), ("in_place_full", True),
               ("reverse_reinsert", True), ("grow_items_off", 1), ("no_grow_mirror", True), ("no_swap_chain", True), ("skip_group_test", True),
               ("in_place_keep_full", True), ("halve_buckets", True))]


def rol64(v, n):
    return ((v << n) | (v >> (64 - n))) & M64X


def siphash13(k0, k1, data, o=LK_DEFAULT):
    v0, v1, v2, v3 = k0 ^ 0x736F6D6570736575, k1 ^ 0x646F72616E646F6D, k0 ^ 0x6C7967656E657261, k1 ^ 0x7465646279746573

    def rounds(count):
        nonlocal v0, v1, v2, v3
        for _ in range(count):
            v0 = (v0 + v1) & M64X
            v1 = rol64(v1, 13) ^ v0
            v0 = rol64(v0, 32)
            v2 = (v2 + v3) & M64X
            v3 = rol64(v3, 16) ^ v2
            v0 = (v0 + v3) & M64X
            v3 = rol64(v3, 21) ^ v0
            v2 = (v2 + v1) & M64X
            v1 = rol64(v1, 17) ^ v2
            v2 = rol64(v2, 32)

    for at in range(0, len(data) - len(data) % 8, 8):
        word = int.from_bytes(data[at:at + 8], "little")
        v3 ^= word
        rounds(o['rounds_c'])
        v0 ^= word
    tail = int.from_bytes(data[len(data) - len(data) % 8:], "little") | (len(data) & 0xFF) << 56
    v3 ^= tail
    rounds(o['rounds_c'])
    v0 ^= tail
    v2 ^= 0xFF
    rounds(o['rounds_d'])
    return v0 ^ v1 ^ v2 ^ v3


class Table:
    """Python SwissTable with the control-byte, mirror and probe rules the bytes of 0x3ee6e80 / 0x3ec72b0 follow."""

    def __init__(self, buckets, o=LK_DEFAULT):
        self.o, self.mask = o, buckets - 1
        self.ctrl = [EMPTY] * (buckets + 16)
        self.bucket = [0] * buckets
        self.growth = buckets * 7 // 8 if buckets >= 8 else buckets - 1
        self.items = 0

    def group(self, pos):
        return self.ctrl[pos:pos + 16]

    def set_ctrl(self, index, value):
        self.ctrl[index] = value
        if not self.o['no_mirror']:
            self.ctrl[((index - 16) & self.mask) + 16] = value

    def find(self, hash_, same, entries):
        h2 = hash_ >> self.o['h2_shift']
        pos, stride = hash_ & self.mask, 0
        while True:
            grp = self.group(pos)
            for bit, byte in enumerate(grp):
                if byte == h2:
                    slot = (pos + bit) & self.mask
                    if same(self.bucket[slot]):
                        return slot
            if EMPTY in grp:
                return None
            stride += 16
            pos = (pos + stride + self.o['stride_off']) & self.mask

    def insert_slot(self, hash_):
        pos, stride = hash_ & self.mask, 0
        while True:
            grp = self.group(pos)
            marks = [bit for bit, byte in enumerate(grp) if byte & 0x80 and not (self.o['deleted_full'] and byte == DELETED)]
            if marks:
                slot = (pos + marks[0]) & self.mask
                if not self.ctrl[slot] & 0x80 or self.o['first_group_fix']:
                    slot = [bit for bit, byte in enumerate(self.ctrl[0:16]) if byte & 0x80][0]
                return slot
            stride += 16
            pos = (pos + stride) & self.mask

    def capacity(self):
        return self.mask if self.mask < 8 else (self.mask + 1) // 8 * 7

    def reserve(self, entries):
        """Reserve one more item (0x3ee0ed0): rehash in place when at most half the capacity is live, else move into a table twice as large."""
        o = self.o
        need = self.items + 1
        if (need <= self.capacity() // 2 or o['in_place_full'] and need <= self.capacity()) and not o['never_in_place']:
            self.rehash_in_place(entries)
            return self
        want = max(need, self.capacity() + 1)
        buckets = (4 if want < 4 else 8) if want < 8 else 1 << (want * 8 // 7 - 1).bit_length()
        if o['halve_buckets']:
            buckets //= 2
        new = Table(buckets, o)
        order = range(self.mask, -1, -1) if o['reverse_reinsert'] else range(self.mask + 1)
        for i in order:
            if self.ctrl[i] < 0x80:
                hash_ = entries[self.bucket[i]][1]
                slot = new.insert_slot(hash_)
                new.ctrl[slot] = hash_ >> o['h2_shift']
                if not o['no_grow_mirror']:
                    new.ctrl[((slot - 16) & new.mask) + 16] = hash_ >> o['h2_shift']
                new.bucket[slot] = self.bucket[i]
        new.items = self.items
        new.growth = new.capacity() - self.items - o['grow_items_off']
        return new

    def rehash_in_place(self, entries):
        o = self.o
        for i in range(0, self.mask + 1, 16):
            for j in range(i, min(i + 16, len(self.ctrl))):
                self.ctrl[j] = DELETED if self.ctrl[j] < 0x80 else EMPTY
        if self.mask + 1 < 16:
            self.ctrl[16:16 + self.mask + 1] = self.ctrl[0:self.mask + 1]
        else:
            self.ctrl[self.mask + 1:self.mask + 17] = self.ctrl[0:16]
        if o['in_place_keep_full']:
            return
        for i in range(self.mask + 1):
            if self.ctrl[i] != DELETED:
                continue
            while True:
                hash_ = entries[self.bucket[i]][1]
                new_i = self.insert_slot(hash_)
                home = hash_ & self.mask
                if (((i - home) & self.mask) // 16 == ((new_i - home) & self.mask) // 16 and not o['skip_group_test']):
                    self.set_ctrl(i, hash_ >> o['h2_shift'])
                    break
                previous = self.ctrl[new_i]
                self.set_ctrl(new_i, hash_ >> o['h2_shift'])
                if previous == EMPTY:
                    self.set_ctrl(i, EMPTY)
                    self.bucket[new_i] = self.bucket[i]
                    break
                self.bucket[i], self.bucket[new_i] = self.bucket[new_i], self.bucket[i]
                if o['no_swap_chain']:
                    break
        self.growth = self.capacity() - self.items


def lookup_model(state, key, o=LK_DEFAULT):
    """state: dict(k0, k1, buckets, ctrl, bucket, growth, items, entries[(value4, hash, key20)]); returns (entry index, new state)."""
    new = {k: (list(v) if isinstance(v, list) else v) for k, v in state.items()}
    hash_ = siphash13(state['k0'], state['k1'], key, o)
    table = Table(state['buckets'], o)
    table.ctrl, table.bucket, table.growth, table.items = list(state['ctrl']), list(state['bucket']), state['growth'], state['items']
    hit = table.find(hash_, lambda i: state['entries'][i][2] == key, state['entries'])
    if hit is not None:
        return table.bucket[hit] + o['hit_off'], new
    slot = table.insert_slot(hash_)
    old = table.ctrl[slot]
    if table.growth == 0 and old & 1:
        table = table.reserve(state['entries'])
        slot = table.insert_slot(hash_)
        old = table.ctrl[slot]
    table.growth -= (old & 1) if not o['growth_deleted'] else 1
    table.set_ctrl(slot, hash_ >> o['h2_shift'])
    index = table.items
    table.bucket[slot] = index + o['index_off']
    if not o['no_items']:
        table.items += 1
    fresh = (o['fresh_cap'], o['fresh_ptr'], 0, 0)
    entry = (fresh, 0 if o['no_hash_store'] else hash_, key)
    new['entries'] = new['entries'] + [entry]
    new['ctrl'], new['bucket'], new['growth'], new['items'] = table.ctrl, table.bucket, table.growth, table.items
    new['buckets'] = table.mask + 1
    return index, new


def lookup_cases(count, seed):
    rnd = random.Random(seed)
    for n in range(count):
        packed = rnd.random() < 0.12
        buckets = rnd.choice([64, 128]) if packed else rnd.choice([4, 8, 16, 16, 32, 32, 64, 64, 128])
        k0, k1 = rnd.getrandbits(64), rnd.getrandbits(64)
        limit = buckets * 7 // 8 if buckets >= 8 else buckets - 1
        grow = packed or rnd.random() < 0.3
        cluster = buckets >= 32 and rnd.random() < 0.6 and not grow
        fill = limit if grow else rnd.randrange(limit - 3, limit) if cluster or rnd.random() < 0.3 else rnd.randrange(0, max(1, limit - 1))
        table = Table(buckets)
        keys = []
        entries = []
        while len(keys) < fill:
            key = bytes(rnd.getrandbits(8) for _ in range(20))
            if key in keys:
                continue
            h = siphash13(k0, k1, key)
            if cluster and (h & (buckets - 1)) >= 16:
                continue
            slot = table.insert_slot(h)
            table.growth -= table.ctrl[slot] & 1
            table.set_ctrl(slot, h >> 57)
            table.bucket[slot] = table.items
            table.items += 1
            keys.append(key)
            entries.append(((rnd.getrandbits(8), 8, rnd.getrandbits(8), rnd.getrandbits(8)), h, key))
        # tombstones: turn some full slots into DELETED without touching the entry list
        rate = rnd.choice([0.55, 0.7, 0.85])
        if packed:
            live = [slot for slot in range(buckets) if table.ctrl[slot] < 0x80]
            for slot in rnd.sample(live, len(live) - (table.capacity() // 2 - 1 - rnd.randrange(3))):
                table.set_ctrl(slot, DELETED)
            table.items = sum(1 for byte in table.ctrl[:buckets] if byte < 0x80)
        elif grow and rnd.random() < 0.6:
            for slot in range(buckets):
                if table.ctrl[slot] < 0x80 and rnd.random() < rate:
                    table.set_ctrl(slot, DELETED)
            table.items = sum(1 for byte in table.ctrl[:buckets] if byte < 0x80)
        elif not grow and rnd.random() < 0.4:
            for slot in range(buckets):
                if table.ctrl[slot] < 0x80 and rnd.random() < 0.2:
                    table.set_ctrl(slot, DELETED)
        if packed:
            probe = bytes(rnd.getrandbits(8) for _ in range(20))
            while table.ctrl[table.insert_slot(siphash13(k0, k1, probe))] != EMPTY:
                probe = bytes(rnd.getrandbits(8) for _ in range(20))
        elif keys and rnd.random() < 0.5:
            probe = rnd.choice(keys)
        else:
            probe = bytes(rnd.getrandbits(8) for _ in range(20))
            while cluster and (siphash13(k0, k1, probe) & (buckets - 1)) >= 16:
                probe = bytes(rnd.getrandbits(8) for _ in range(20))
        yield dict(k0=k0, k1=k1, buckets=buckets, ctrl=table.ctrl, bucket=table.bucket, growth=table.growth, items=table.items, entries=entries), probe


def write_lookup_state(mem, state, key):
    mem.write(MAP + 0x110, 8, state['k0'])
    mem.write(MAP + 0x118, 8, state['k1'])
    mem.write(MAP + 0xD8, 8, 64)
    mem.write(MAP + 0xE0, 8, ENT_BASE)
    mem.write(MAP + 0xE8, 8, len(state['entries']))
    buckets = state['buckets']
    mem.write(MAP + 0xF0, 8, CTRL_BASE)
    mem.write(MAP + 0xF8, 8, buckets - 1)
    mem.write(MAP + 0x100, 8, state['growth'])
    mem.write(MAP + 0x108, 8, state['items'])
    for i, byte in enumerate(state['ctrl']):
        mem.write(CTRL_BASE + i, 1, byte)
    for i, value in enumerate(state['bucket']):
        mem.write(CTRL_BASE - 8 * (i + 1), 8, value)
    for i, (value, hash_, k) in enumerate(state['entries']):
        at = ENT_BASE + 64 * i
        for j, word in enumerate(value):
            mem.write(at + 8 * j, 8, word)
        mem.write(at + 0x20, 8, hash_)
        mem.put_bytes(at + 0x28, k)
    mem.put_bytes(KEY_PTR, key)


def read_lookup_state(mem, base):
    count = mem.read(MAP + 0xE8, 8)
    entries = []
    for i in range(count):
        at = ENT_BASE + 64 * i
        entries.append((tuple(mem.read(at + 8 * j, 8) for j in range(4)), mem.read(at + 0x20, 8), bytes(mem.read(at + 0x28 + j, 1) for j in range(20))))
    ctrl, buckets = mem.read(MAP + 0xF0, 8), mem.read(MAP + 0xF8, 8) + 1
    return dict(k0=base['k0'], k1=base['k1'], buckets=buckets, ctrl=[mem.read(ctrl + i, 1) for i in range(buckets + 16)],
                bucket=[mem.read(ctrl - 8 * (i + 1), 8) for i in range(buckets)], growth=mem.read(MAP + 0x100, 8), items=mem.read(MAP + 0x108, 8), entries=entries)


def install_allocator(machine):
    """Contracts for the three libc / allocator slots the grow arm uses: a bump allocator (16-byte aligned), memset, and a free that does nothing."""
    top = [ALLOC_BASE]

    def alloc(m):
        top[0] = (top[0] + 15) & ~15
        m.regs[RAX] = top[0]
        top[0] += m.regs[RDI]

    def memset(m):
        m.memory.put_bytes(m.regs[RDI], bytes([m.regs[RSI] & 0xFF]) * m.regs[RDX])
        m.regs[RAX] = m.regs[RDI]

    machine.memory.statics[GOT_ALLOC], machine.memory.statics[GOT_MEMSET], machine.memory.statics[GOT_FREE] = FAKE_ALLOC, FAKE_MEMSET, FAKE_FREE
    machine.slots[FAKE_ALLOC], machine.slots[FAKE_MEMSET], machine.slots[FAKE_FREE] = alloc, memset, lambda m: None
    machine.memory.statics[GOT_REHASH] = REHASH
    machine.memory.statics[0x64DF568] = FAKE_MEMMOVE
    machine.slots[FAKE_MEMMOVE] = lambda m: (m.memory.copy(m.regs[RDI], m.regs[RSI], m.regs[RDX]), m.regs.__setitem__(RAX, m.regs[RDI]))


def run_lookup(machine, state, key):
    mem = machine.memory
    mem.reset(0x40000)
    write_lookup_state(mem, state, key)
    install_allocator(machine)
    machine.real = frozenset([HASHER, SIPWRITE, FINDER, INSERTER, REHASH, TABLE_DROP])
    machine.seen = set()
    entry = machine.run(LOOKUP, {RDI: MAP, RSI: KEY_PTR})
    index = (entry - ENT_BASE) // 64 if (entry - ENT_BASE) % 64 == 0 else -1
    return index, read_lookup_state(mem, state), set(machine.seen)


def live_view(state):
    """The state with bucket cells of empty or deleted slots blanked: a moved table leaves allocator garbage there."""
    view = dict(state)
    view['bucket'] = [cell if state['ctrl'][i] < 0x80 else 0 for i, cell in enumerate(state['bucket'])]
    return view


def lookup_agrees(run, want):
    return run[0] == want[0] and live_view(run[1]) == live_view(want[1])


def hasher_cases(count, seed):
    rnd = random.Random(seed)
    for _ in range(count):
        yield rnd.getrandbits(64), rnd.getrandbits(64), bytes(rnd.getrandbits(8) for _ in range(20))


def run_hasher(machine, k0, k1, key):
    machine.memory.reset(0x4000)
    machine.memory.put_bytes(KEY_PTR, key)
    machine.real = frozenset([SIPWRITE])
    machine.seen = set()
    value = machine.run(HASHER, {RDI: k0, RSI: k1, RDX: KEY_PTR})
    return value, set(machine.seen)
FUNCTIONS = [(0x4228080, "admission"), (0x4551530, "ring-search-u64"), (0x450C430, "evict-fold"), (0x4555F40, "ring-search-24"), (0x35BD8A0, "tree-search")]
SBUF, TREE = HEAP_BASE + 0x4000, HEAP_BASE + 0x8000
NODE_LEAF, NODE_INTERNAL = 0xE8, 0x148
RING24 = 24


def build_tree(mem, keys):
    """Write a B-tree of at most two levels (11 keys per node) for sorted unique keys; return (root, height)."""
    if not keys:
        return 0, 0
    cursor = [TREE]

    def node(ks, size):
        at = cursor[0]
        cursor[0] += size
        for i, k in enumerate(ks):
            mem.write(at + 8 + 8 * i, 8, k)
        mem.write(at + 0xE6, 2, len(ks))
        return at

    if len(keys) <= 11:
        return node(keys, NODE_LEAF), 0
    seps = -(-(len(keys) - 11) // 12)
    rest = len(keys) - seps
    leaves, base, extra = seps + 1, rest // (seps + 1), rest % (seps + 1)
    parts, separators, at = [], [], 0
    for i in range(leaves):
        take = base + (1 if i < extra else 0)
        parts.append(keys[at:at + take])
        at += take
        if i < seps:
            separators.append(keys[at])
            at += 1
    root = node(separators, NODE_INTERNAL)
    for i, ks in enumerate(parts):
        child = node(ks, NODE_LEAF)
        mem.write(child, 8, root)
        mem.write(root + 0xE8 + 8 * i, 8, child)
    return root, 1


def two_slices(cap, head, length):
    """Front and back slice (start, end) element indexes of the ring, as the body hands them to the fold."""
    if length == 0:
        return (head, 0, 0, 0)
    if head + length <= cap:
        return (head, head + length, 0, 0)
    return (head, cap, 0, length - (cap - head))


def build(machine, case):
    ring, cap, head, nonce, sec, date, secs, nanos, fa, fb = case
    mem = machine.memory
    mem.reset(0xA000)
    mem.write(SET, 8, cap)
    mem.write(SET + 8, 8, BUF)
    mem.write(SET + 0x10, 8, head)
    mem.write(SET + 0x18, 8, len(ring))
    for i, v in enumerate(ring):
        mem.write(BUF + ((head + i) % cap) * 8, 8, v)
    if sec is not None:
        if sec[0] == "ring":
            keys, cap2, head2 = sec[1], sec[2], sec[3]
            mem.write(SEC, 8, cap2)
            mem.write(SEC + 8, 8, SBUF)
            mem.write(SEC + 0x10, 8, head2)
            mem.write(SEC + 0x18, 8, len(keys))
            for i, k in enumerate(keys):
                at = SBUF + ((head2 + i) % cap2) * RING24
                mem.write(at, 8, k)
                mem.write(at + 8, 8, 0x1111 + i)
                mem.write(at + 16, 8, 0x2222 + i)
        else:
            root, height = build_tree(mem, sec[1])
            mem.write(SEC, 8, 1 << 63)
            mem.write(SEC + 8, 8, root)
            mem.write(SEC + 0x10, 8, height)
    mem.write(ARGS, 8, nonce)
    mem.write(ARGS + 8, 8, SEC if sec is not None else 0)
    mem.write(ARGS + 0x10, 4, date)
    mem.write(ARGS + 0x14, 4, secs)
    mem.write(ARGS + 0x18, 4, nanos)
    mem.write(ARGS + 0x1C, 1, fa)
    mem.write(ARGS + 0x1D, 1, fb)
    for k in range(3):
        mem.write(OUT + 8 * k, 8, SENTINEL_OUT)


def run_case(machine, case):
    build(machine, case)
    machine.seen = set()
    machine.real = frozenset([SEARCH, FOLD, 0x4555F40, 0x35BD8A0])
    machine.run(ENTRY, {RDI: OUT, RSI: SET, RDX: ARGS})
    mem = machine.memory
    return mem.read(OUT, 2), mem.read(OUT + 8, 8), mem.read(OUT + 16, 8), set(machine.seen)


def agrees(got, want):
    tag, w1, w2 = got[0], got[1], got[2]
    if tag != want[0]:
        return False
    if want[0] == TAG_DUP and w1 != want[1]:
        return False
    if want[0] in (TAG_OK, TAG_LOW, TAG_HIGH) and (w1 != want[1] or w2 != want[2]):
        return False
    return True


def pack_date(year, ordinal):
    return ((year << 13) | (ordinal << 4) | 0x3) & M32


def make_secondary(rnd, ring, count_hint):
    kind = rnd.choice(["none", "none", "ring", "tree", "tree", "ring", "empty-ring", "empty-tree"])
    if kind == "none":
        return None
    if kind == "empty-ring":
        return ("ring", [], rnd.choice([1, 4]), 0)
    if kind == "empty-tree":
        return ("tree", [])
    pool = set()
    for _ in range(rnd.choice([1, 3, 8, 20, 60, 130])):
        roll = rnd.random()
        if ring and roll < 0.35:
            pool.add(rnd.choice(ring[:max(count_hint + 2, 1)] if rnd.random() < 0.5 else ring))
        elif ring and roll < 0.75:
            pool.add(rnd.randint(max(ring[0] - 5000, 1), ring[-1] + 5000))
        else:
            pool.add(rnd.randint(1, 1 << 45))
    keys = sorted(pool)
    if kind == "tree":
        return ("tree", keys)
    cap2 = len(keys) + rnd.choice([0, 1, 5])
    cap2 = max(cap2, 1)
    return ("ring", keys, cap2, rnd.randrange(cap2))


def make_cases(count, seed):
    rnd = random.Random(seed)
    for n in range(count):
        mode = n % 8
        if mode == 0:
            year = rnd.randint(-900, 3000)
        elif mode == 1:
            year = rnd.choice([0, 1, -1, 400, -400, 1970, 1969, 2000, 2100, 2400, 1900, 1600, 262143, -262144])
        else:
            year = rnd.randint(1970, 2100)
        ordinal = rnd.choice([1, 59, 60, 365, 366, rnd.randint(1, 366)])
        date = pack_date(year, ordinal)
        secs = rnd.choice([0, 86399, rnd.randint(0, 86399)])
        nanos = rnd.choice([0, 999999999, 1000000, 999999, rnd.randint(0, 999999999)])
        fa = rnd.choice([0, 0, 1, 7])
        fb = rnd.choice([0, 1, 1, 5])
        now = clock_ms(date, secs, nanos, DEFAULT)
        limit = 400 if fa else 100
        length = rnd.choice([0, 1, 2, limit - 1, limit, limit, limit + 1, rnd.randint(0, limit + 40), rnd.randint(0, limit + 40)])
        gap = rnd.randint(1, 5000)
        shape = rnd.randint(0, 9)
        if shape == 0:
            center = now + 10 ** 9
        elif shape == 1:
            center = rnd.randint(1, 10 ** 6)
        else:
            center = now + rnd.randint(-100000, 100000)
        base = max(center - length * gap, 1)
        values = set()
        while len(values) < length:
            values.add(base + rnd.randint(0, length * gap + 50))
        ring = sorted(values)
        cap = max(length, 1) + rnd.choice([0, 0, 1, 3, 17])
        head = rnd.randrange(cap) if rnd.random() < 0.6 else rnd.choice([0, cap - 1, max(cap - 2, 0), max(cap - 3, 0), max(cap - 6, 0)])
        pick = rnd.randint(0, 9)
        if pick == 0 and ring:
            nonce = rnd.choice(ring)
        elif pick == 1:
            nonce = now + (86400000 - 120000 if fb else 86400000) + rnd.choice([-1, 0, 1])
        elif pick == 2:
            nonce = max(now - (172680000 if fb else 172800000) + rnd.choice([-1, 0, 1]), 0)
        elif pick == 3 and len(ring) >= limit:
            nonce = ring[len(ring) - limit] + rnd.choice([-1, 0, 1])
        elif pick == 4:
            nonce = rnd.choice([0, 1, M64X, M64X - 1, 1 << 63])
        else:
            nonce = max(now + rnd.randint(-200000, 200000), 0)
        nonce &= M64X
        sec = make_secondary(rnd, ring, max(length - limit + 1, 1))
        yield (ring, cap, head, nonce, sec, date, secs, nanos, fa, fb)


def predict(case, o=DEFAULT):
    ring, _, _, nonce, sec, date, secs, nanos, fa, fb = case
    return admit(ring, nonce, sec, date, secs, nanos, fa, fb, o)[0]



def direct_cases(count, seed):
    """Cases for the four callees alone: key searches, the tree search and the evict fold."""
    rnd = random.Random(seed)
    for n in range(count):
        kind = ("search64", "search24", "tree", "fold", "fold", "fold")[n % 6]
        length = rnd.choice([0, 1, 2, 3, 7, 11, 12, 30, 80, 140])
        keys = sorted({rnd.randint(1, 1 << rnd.choice([8, 16, 40])) for _ in range(length)})
        cap = len(keys) + rnd.choice([0, 1, 4])
        cap = max(cap, 1)
        head = rnd.randrange(cap)
        if kind == "fold":
            ring_len = rnd.choice([0, 1, 2, 5, 9, 20, 60])
            ring = sorted({rnd.randint(1, 1 << 12) for _ in range(ring_len)})
            ring_cap = len(ring) + rnd.choice([0, 1, 3])
            ring_cap = max(ring_cap, 1)
            ring_head = rnd.choice([rnd.randrange(ring_cap), ring_cap - 1, max(ring_cap - 2, 0)])
            if ring and rnd.random() < 0.7:
                keys = sorted(set(keys[:rnd.randint(0, len(keys))]) | {rnd.choice(ring) for _ in range(rnd.randint(1, 3))})
            container = rnd.choice(["ring", "tree"])
            count_arg = max(rnd.choice([1, 2, 3, 6, 7, 8, 13, len(ring), len(ring) + 2]), 1)
            cap2 = max(len(keys) + rnd.choice([0, 2]), 1)
            sec = ("ring", keys, cap2, rnd.randrange(cap2)) if container == "ring" else ("tree", keys)
            yield (kind, ring, ring_cap, ring_head, count_arg, sec)
        else:
            probe = rnd.choice(keys) if keys and rnd.random() < 0.5 else rnd.randint(0, 1 << 40)
            yield (kind, keys, cap, head, probe)


def run_direct(machine, item):
    """Run one callee case on the bytes and return True when it agrees with the model."""
    kind = item[0]
    machine.real = frozenset([SEARCH, FOLD, 0x4555F40, 0x35BD8A0])
    machine.seen = set()
    mem = machine.memory
    mem.reset(0xA000)
    probe_at = HEAP_BASE + 0x3000
    if kind == "search64":
        keys, cap, head, probe = item[1:]
        mem.write(SET, 8, cap)
        mem.write(SET + 8, 8, BUF)
        mem.write(SET + 0x10, 8, head)
        mem.write(SET + 0x18, 8, len(keys))
        for i, k in enumerate(keys):
            mem.write(BUF + ((head + i) % cap) * 8, 8, k)
        mem.write(probe_at, 8, probe)
        machine.run(SEARCH, {RDI: SET, RSI: probe_at})
        absent = machine.regs[RAX] & 0xFF
        position = bisect.bisect_left(keys, probe)
        return (absent == (0 if probe in keys else 1)) and machine.regs[RDX] == position, machine.seen
    if kind == "search24":
        keys, cap, head, probe = item[1:]
        build_ring24(mem, keys, cap, head)
        mem.write(probe_at, 8, probe)
        machine.run(0x4555F40, {RDI: SEC, RSI: probe_at})
        absent = machine.regs[RAX] & 0xFF
        return (absent == (0 if probe in keys else 1)) and machine.regs[RDX] == bisect.bisect_left(keys, probe), machine.seen
    if kind == "tree":
        keys, cap, head, probe = item[1:]
        root, height = build_tree(mem, keys)
        if not root:
            return True, set()
        mem.write(probe_at, 8, probe)
        mem.write(HEAP_BASE + 0x3100, 8, SENTINEL_OUT)
        machine.run(0x35BD8A0, {RDI: HEAP_BASE + 0x3100, RSI: root, RDX: height, RCX: probe_at})
        return (mem.read(HEAP_BASE + 0x3100, 8) == (0 if probe in keys else 1)), machine.seen
    ring, cap, head, count, sec = item[1:]
    mem.write(SET, 8, cap)
    mem.write(SET + 8, 8, BUF)
    mem.write(SET + 0x10, 8, head)
    mem.write(SET + 0x18, 8, len(ring))
    for i, v in enumerate(ring):
        mem.write(BUF + ((head + i) % cap) * 8, 8, v)
    if sec[0] == "ring":
        build_ring24(mem, sec[1], sec[2], sec[3])
    else:
        root, height = build_tree(mem, sec[1])
        mem.write(SEC, 8, 1 << 63)
        mem.write(SEC + 8, 8, root)
        mem.write(SEC + 0x10, 8, height)
    fs, fe, bs, be = two_slices(cap, head, len(ring))
    iter_at = HEAP_BASE + 0x3200
    for k, v in enumerate((BUF + fs * 8, BUF + fe * 8, BUF + bs * 8, BUF + be * 8)):
        mem.write(iter_at + 8 * k, 8, v)
    mem.write(probe_at, 8, count)
    machine.run(FOLD, {RDI: iter_at, RSI: probe_at, RDX: SEC})
    ret = machine.regs[RAX] & 0xFF
    hit = any(v in set(sec[1]) for v in ring[:count])
    return ret in (0, 1, 2) and (ret & 1) == int(hit), machine.seen


def build_ring24(mem, keys, cap, head):
    mem.write(SEC, 8, cap)
    mem.write(SEC + 8, 8, SBUF)
    mem.write(SEC + 0x10, 8, head)
    mem.write(SEC + 0x18, 8, len(keys))
    for i, k in enumerate(keys):
        at = SBUF + ((head + i) % cap) * RING24
        mem.write(at, 8, k)
        mem.write(at + 8, 8, 0x1111 + i)
        mem.write(at + 16, 8, 0x2222 + i)


def decode_function(image, start):
    begin, end = image.exact_fde(start)
    machine = Machine(image)
    rows, pc = [], begin
    while pc < end:
        row = decode(machine.read_code, pc)
        rows.append(row)
        pc = row.next
    if pc != end:
        raise EvidenceError("decode does not end on the FDE end at %#x" % start)
    return rows, begin, end


def patch_candidates(image, rows, with_stores):
    """Byte corruptions made from decoded rows: every conditional jump inverted; 16-bit store immediates bumped."""
    out = []
    blob = image.blob
    for row in rows:
        at = image.offset(row.va)
        if row.op == "jcc":
            where = 1 if blob[at] == 0x0F else 0
            out.append(("invert-jcc-%x" % row.va, row.va + where, blob[at + where], blob[at + where] ^ 1))
        elif with_stores and row.op == "mov" and row.width == 2 and row.b[0] == "i" and row.a[0] == "m":
            pos = row.next - 2 - row.va
            out.append(("bump-tag-immediate-%x" % row.va, row.va + pos, blob[at + pos], (blob[at + pos] + 1) & 0xFF))
    return out


def display_arm(image, tag):
    """Locate the Display arm of one tag through the rel32 jump table and read its text or template bytes."""
    slot = image.offset(TABLE_VA) + 4 * tag
    arm = TABLE_VA + struct.unpack("<i", image.blob[slot:slot + 4])[0]
    code = image.blob[image.offset(arm):image.offset(arm) + 96]
    for i in range(len(code) - 7):
        if code[i] in (0x48, 0x4C) and code[i + 1] == 0x8D and code[i + 2] in (0x15, 0x35):
            target = arm + i + 7 + struct.unpack_from("<i", code, i + 3)[0]
            at = image.offset(target)
            if code[i + 2] == 0x15:
                length = image.blob[at]
                tail = image.blob[at + 1 + length:at + 9 + length]
                text = "".join(chr(c) for c in image.blob[at + 1:at + 1 + length]) + " + raw " + tail.hex()
                return arm, "template", target, text
            for j in range(i + 7, len(code) - 4):
                if code[j] == 0xBA:
                    length = struct.unpack_from("<I", code, j + 1)[0]
                    return arm, "static", target, "".join(chr(c) for c in image.blob[at:at + length])
    return arm, "none", 0, ""


def tsv(path, header, lines):
    with open(path, "w", newline="\n") as handle:
        handle.write("\t".join(header) + "\n")
        for line in lines:
            handle.write("\t".join(str(x) for x in line) + "\n")


WRAP, INSERT, SPEC_A, SPEC_B = 0x4228310, 0x454B8C0, 0x421A520, 0x421A3C0
GOT_MEMMOVE, GOT_A, GOT_B = 0x64DF568, 0x64E5AE8, 0x64E6A80
FAKE_MEMMOVE = 0x7700001000
ADDR_AT, TIME_AT, WOUT = HEAP_BASE + 0x3400, HEAP_BASE + 0x3440, HEAP_BASE + 0x3500
GROW_FIX = 0x4560AF0
GOT_INS_GROW, GOT_RAW_GROW, GOT_MEMCPY = 0x64E2620, 0x64EA7B8, 0x64DF508
FAKE_RAW_GROW = 0x7700003000
WRAP_FUNCTIONS = [(WRAP, "admit-wrapper"), (SPEC_A, "special-set-a"), (SPEC_B, "special-set-b"), (INSERT, "ring-insert"), (GROW_FIX, "ring-grow-fixup")]
WRAP_DEFAULT = dict(only_a=False, drop_k3=False, insert_after=False, no_trim=False, trim_newest=False, limit_plus=False, skip_insert=False,
                    flag_b=False, drop_b=False)
WRAP_MUTANTS = [
    ('wrap-ignore-set-b', dict(drop_b=True)), ('wrap-only-set-a', dict(only_a=True)), ('wrap-drop-last-constant', dict(drop_k3=True)),
    ('wrap-insert-after-position', dict(insert_after=True)), ('wrap-no-trim', dict(no_trim=True)), ('wrap-trim-drops-newest', dict(trim_newest=True)),
    ('wrap-limit-plus-one', dict(limit_plus=True)), ('wrap-insert-skipped', dict(skip_insert=True)), ('wrap-flag-b-set', dict(flag_b=True)),
]


def constants_of(image, start):
    """20-byte addresses compared by a function: (16-byte body, 4-byte tail) pairs from its pcmpeqb operands."""
    rows, _, _ = decode_function(image, start)
    consts = [row.b[4] for row in rows if row.op == "pcmpeqb" and row.b[0] == "m" and row.b[1] is None]
    out = []
    for tail_va, body_va in zip(consts[0::2], consts[1::2]):
        body = bytes(image.blob[image.offset(body_va):image.offset(body_va) + 16])
        tail = bytes(image.blob[image.offset(tail_va):image.offset(tail_va) + 16])
        if tail[4:] != bytes(12):
            out.append(None)
        else:
            out.append(body + tail[:4])
    return out


def wrap_model(sets, addr, case, o=WRAP_DEFAULT):
    """Return (record tag, word1, word2, ring after) for the wrapper around the admission body."""
    ring, cap, head, nonce, sec, date, secs, nanos, _, _ = case
    set_a, set_b, consts = sets
    flag = addr in set_a or (addr in set_b and not o['drop_b']) or addr in consts[:2] or (addr == consts[2] and not o['drop_k3'])
    if o['only_a']:
        flag = addr in set_a
    result = admit(ring, nonce, sec, date, secs, nanos, 1 if flag else 0, 1 if o['flag_b'] else 0, DEFAULT)[0]
    if result[0] != TAG_OK:
        return result, list(ring)
    new = list(ring)
    if not o['skip_insert']:
        new.insert(result[2] + (1 if o['insert_after'] else 0), nonce)
    limit = (400 if flag else 100) + (1 if o['limit_plus'] else 0)
    if len(new) > limit and not o['no_trim']:
        new = new[:limit] if o['trim_newest'] else new[len(new) - limit:]
    return result, new


def wrap_cases(image, count, seed):
    """Whole-wrapper cases: the admission corpus with an address (special or not) and room for the insertion."""
    sets = special_sets(image)
    rnd = random.Random(seed)
    pool = sorted(sets[0] | sets[1] | set(sets[2]))
    for case in make_cases(count, seed):
        ring, cap, head, nonce, sec, date, secs, nanos, fa, fb = case
        if fa:
            addr = rnd.choice(pool)
        elif rnd.random() < 0.15:
            addr = rnd.choice(pool)
        else:
            addr = bytes(rnd.randrange(256) for _ in range(20))
        if ring and rnd.random() < 0.2:
            cap = len(ring)
        else:
            cap = max(cap, len(ring) + 1) + rnd.choice([0, 0, 2])
        head = rnd.randrange(cap) if rnd.random() < 0.7 else rnd.choice([cap - 1, max(cap - 2, 0), 0])
        yield addr, (ring, cap, head, nonce, sec, date, secs, nanos, fa, fb)


def special_sets(image):
    consts_a = constants_of(image, SPEC_A)
    consts_b = constants_of(image, SPEC_B)
    wrap_consts = constants_of(image, WRAP)
    return set(c for c in consts_a if c), set(c for c in consts_b if c), wrap_consts


def install_grow(machine):
    """Slot 0x64e2620 is the real fix-up 0x4560af0; the RawVec step behind slot 0x64ea7b8 is a contract (capacity max(2 * cap, 4), buffer kept in place)."""
    def raw_grow(m):
        cap = m.memory.read(m.regs[RDI], 8)
        m.memory.write(m.regs[RDI], 8, max(2 * cap, 4))
        m.keep_rdx = False

    machine.memory.statics[GOT_INS_GROW] = GROW_FIX
    machine.memory.statics[GOT_RAW_GROW] = FAKE_RAW_GROW
    machine.memory.statics[GOT_MEMCPY] = FAKE_MEMMOVE
    machine.slots[FAKE_RAW_GROW] = raw_grow


def run_wrap(machine, addr, case):
    build(machine, case)
    mem = machine.memory
    mem.put_bytes(ADDR_AT, addr)
    mem.write(TIME_AT, 4, case[5])
    mem.write(TIME_AT + 4, 4, case[6])
    mem.write(TIME_AT + 8, 4, case[7])
    for k in range(14):
        mem.write(WOUT + 8 * k, 8, SENTINEL_OUT)

    def memmove(m):
        m.memory.copy(m.regs[RDI], m.regs[RSI], m.regs[RDX])
        m.regs[RAX] = m.regs[RDI]
        m.keep_rdx = False

    install_grow(machine)
    machine.memory.statics[GOT_MEMMOVE] = FAKE_MEMMOVE
    machine.memory.statics[GOT_A] = SPEC_A
    machine.memory.statics[GOT_B] = SPEC_B
    machine.slots[FAKE_MEMMOVE] = memmove
    machine.real = frozenset([SEARCH, FOLD, 0x4555F40, 0x35BD8A0, ENTRY, SPEC_A, SPEC_B, INSERT, GROW_FIX])
    machine.seen = set()
    sec = SEC if case[4] is not None else 0
    machine.run(WRAP, {RDI: WOUT, RSI: SET, RDX: TIME_AT, RCX: ADDR_AT, R8: case[3], R9: sec})
    cap, head, length = mem.read(SET, 8), mem.read(SET + 0x10, 8), mem.read(SET + 0x18, 8)
    ring = [mem.read(BUF + ((head + i) % cap) * 8, 8) for i in range(length)]
    return (mem.read(WOUT, 2), mem.read(WOUT + 8, 8), mem.read(WOUT + 16, 8)), ring, cap, set(machine.seen)


def expected_cap(case, ok):
    """A successful insert into a full ring calls the VecDeque grow, whose RawVec step (a contract here) doubles the capacity to at least 4."""
    return max(2 * case[1], 4) if ok and len(case[0]) == case[1] else case[1]


def wrap_agrees(got, ring_after, cap, want, want_ring, case):
    same = got[0] == TAG_OK if want[0] == TAG_OK else agrees(got, want)
    return same and ring_after == want_ring and cap == expected_cap(case, want[0] == TAG_OK)


FUNCTIONS.extend(WRAP_FUNCTIONS)

# ---------------------------------------------------------------------------------------------
# Front ends: the three 233-byte bodies that reach the wrapper through the function-pointer slot 0x64e7ef0.
# Each bumps a saturating request counter, resolves the per-account container through slot 0x64e7ee8,
# calls the wrapper with the context clock and no second container, and bumps a second counter on success.
# ---------------------------------------------------------------------------------------------
GOT_LOOKUP, GOT_WRAP = 0x64E7EE8, 0x64E7EF0
FAKE_LOOKUP = 0x7700002000
FRONT_SIZE = 233
FRONT_STARTS = [(0x2C766E0, "front-a"), (0x560DBB0, "front-b"), (0x560DCA0, "front-c")]
CTX, FOUT = HEAP_BASE + 0x10000, HEAP_BASE + 0x3700
FRONT_DEFAULT = dict(no_c1=False, c1_wrap=False, c1_double=False, no_c2=False, c2_always=False, c2_wrap=False, bad_map=False,
                     key_ignored=False, swap_clock=False, wrong_addr=False)
FRONT_MUTANTS = [(name, {name: True}) for name in FRONT_DEFAULT]
FRONT_FUNCTIONS = list(FRONT_STARTS)
EXTRA_FUNCTIONS = FRONT_FUNCTIONS + LOOKUP_FUNCTIONS
LOOKUP_CASES, HASH_CASES, LOOKUP_PATCH = 2500, 600, 150
FRONT_CASES, FRONT_PATCH = 1500, 150


def front_layout(image, start):
    """Read the three context offsets of one front end from its bytes (fixed positions, verified by their opcodes)."""
    at = image.offset(start)
    code = bytes(image.blob[at:at + FRONT_SIZE])
    if code[28:31] != b"\x48\x8b\x86" or code[49:52] != b"\x48\x89\x86" or code[56:59] != b"\x48\x8d\xbe" or code[123:126] != b"\x49\x8b\x86" \
            or code[137:140] != b"\x49\x89\x86":
        raise EvidenceError("front end shape changed at %#x" % start)
    first, store1, mapping, second, store2 = (struct.unpack_from("<I", code, p)[0] for p in (31, 52, 59, 126, 140))
    if first != store1 or second != store2:
        raise EvidenceError("front end counter offsets disagree at %#x" % start)
    return first, second, mapping


def sat_inc(value, wrap=False):
    value = (value + 1) & M64X
    return value if value or wrap else M64X


def front_model(sets, addr, case, key, ctx, o=FRONT_DEFAULT):
    """Return (record, ring after, counter 1, counter 2, expected lookup arguments) for one front-end call."""
    c1, c2, map_at = ctx
    ring, cap, head, nonce, sec, date, secs, nanos, fa, fb = case
    if o['swap_clock']:
        case = (ring, cap, head, nonce, sec, date, nanos, secs, fa, fb)
    if o['wrong_addr']:
        addr = bytes(20)
    result, new = wrap_model(sets, addr, case)
    n1 = c1 if o['no_c1'] else sat_inc(c1, o['c1_wrap'])
    if o['c1_double']:
        n1 = sat_inc(n1)
    ok = result[0] == TAG_OK
    n2 = sat_inc(c2, o['c2_wrap']) if (ok and not o['no_c2']) or o['c2_always'] else c2
    return result, new, n1, n2, (map_at + (8 if o['bad_map'] else 0), 0 if o['key_ignored'] else key)


def front_cases(image, count, seed):
    rnd = random.Random(seed)
    edge = [0, 1, 2, 0xFFFFFFFE, M64X - 1, M64X]
    for addr, case in wrap_cases(image, count, seed):
        case = case[:4] + (None,) + case[5:]
        pick = lambda: rnd.choice(edge) if rnd.random() < 0.5 else rnd.getrandbits(rnd.choice([8, 32, 64]))
        yield addr, case, rnd.getrandbits(64), pick(), pick()


def run_front(machine, start, layout, addr, case, key, c1, c2):
    build(machine, case)
    mem = machine.memory
    first, second, mapping = layout
    mem.put_bytes(ADDR_AT, addr)
    mem.write(CTX + first, 8, c1)
    mem.write(CTX + second, 8, c2)
    mem.write(CTX + 0x60, 4, case[5])
    mem.write(CTX + 0x64, 4, case[6])
    mem.write(CTX + 0x68, 4, case[7])
    for k in range(8):
        mem.write(FOUT + 8 * k, 8, SENTINEL_OUT)
    calls = []

    def lookup(m):
        calls.append((m.regs[RDI], m.regs[RSI]))
        m.regs[RAX] = SET
        m.keep_rdx = False

    def memmove(m):
        m.memory.copy(m.regs[RDI], m.regs[RSI], m.regs[RDX])
        m.regs[RAX] = m.regs[RDI]
        m.keep_rdx = False

    machine.memory.statics[GOT_MEMMOVE] = FAKE_MEMMOVE
    machine.memory.statics[GOT_A] = SPEC_A
    machine.memory.statics[GOT_B] = SPEC_B
    machine.memory.statics[GOT_LOOKUP] = FAKE_LOOKUP
    install_grow(machine)
    machine.memory.statics[GOT_WRAP] = WRAP
    machine.slots[FAKE_MEMMOVE] = memmove
    machine.slots[FAKE_LOOKUP] = lookup
    machine.real = frozenset([SEARCH, FOLD, 0x4555F40, 0x35BD8A0, ENTRY, SPEC_A, SPEC_B, INSERT, WRAP, GROW_FIX, start])
    machine.seen = set()
    machine.run(start, {RDI: FOUT, RSI: CTX, RDX: ADDR_AT, RCX: key, R8: case[3]})
    cap, head, length = mem.read(SET, 8), mem.read(SET + 0x10, 8), mem.read(SET + 0x18, 8)
    ring = [mem.read(BUF + ((head + i) % cap) * 8, 8) for i in range(length)]
    got = (mem.read(FOUT, 2), mem.read(FOUT + 8, 8), mem.read(FOUT + 16, 8))
    return got, ring, cap, mem.read(CTX + first, 8), mem.read(CTX + second, 8), calls, set(machine.seen)


def front_agrees(run, want, case, key, layout):
    got, ring, cap, n1, n2, calls, _ = run
    result, new, w1, w2, lookup = want
    if result[0] == TAG_OK:
        same = got[0] == TAG_OK
    else:
        same = agrees(got, result)
    return same and ring == new and cap == expected_cap(case, result[0] == TAG_OK) and (n1, n2) == (w1, w2) and calls == [lookup]


def prove(image, cases, patch_cases, direct=None, direct_patch=None, wrap=None, wrap_patch=None):
    wrap = WRAP_CASES if wrap is None else wrap
    wrap_patch = WRAP_PATCH if wrap_patch is None else wrap_patch
    direct = DIRECT_CASES if direct is None else direct
    direct_patch = DIRECT_PATCH if direct_patch is None else direct_patch
    """Run the corpus; return the evidence tables and counts. Raises if the model disagrees with the bytes."""
    machine = Machine(image)
    func_rows = {va: decode_function(image, va) for va, _ in FUNCTIONS + EXTRA_FUNCTIONS}
    detected, sample, tag_counts, union = {}, [], {}, set()
    classes, mismatches, total, fold_runs = {}, 0, 0, 0
    kinds = {}
    for index, case in enumerate(make_cases(cases, CASE_SEED)):
        got = run_case(machine, case)
        want = predict(case)
        if not agrees(got, want):
            mismatches += 1
        total += 1
        union |= got[3]
        tag_counts[want[0]] = tag_counts.get(want[0], 0) + 1
        used = FOLD in got[3]
        fold_runs += 1 if used else 0
        sec = case[4]
        key = (want[0], sec[0] if sec else "-", used)
        kinds[key] = kinds.get(key, 0) + 1
        if key not in classes:
            classes[key] = index
        if index < 40 or classes[key] == index:
            sample.append((index, len(case[0]), case[1], case[2], case[3], sec[0] if sec else "-", len(sec[1]) if sec else 0, case[5], case[6], case[7],
                           case[8], case[9], "%#x" % got[0], got[1] if got[0] in (TAG_OK, TAG_LOW, TAG_HIGH, TAG_DUP) else "-",
                           got[2] if got[0] in (TAG_OK, TAG_LOW, TAG_HIGH) else "-", int(used)))
        for name, change in MUTANTS:
            if name in detected:
                continue
            o = dict(DEFAULT)
            o.update(change)
            if not agrees(got, predict(case, o)):
                detected[name] = index
    direct_total, direct_kinds = 0, {}
    for item in direct_cases(direct, CASE_SEED + 2):
        ok, seen = run_direct(machine, item)
        if not ok:
            mismatches += 1
        union |= seen
        direct_total += 1
        direct_kinds[item[0]] = direct_kinds.get(item[0], 0) + 1
    sets = special_sets(image)
    wrap_total, wrap_tags, wrap_detected, wrap_inserted = 0, {}, {}, 0
    for index, (addr, case) in enumerate(wrap_cases(image, wrap, CASE_SEED + 4)):
        got, ring_after, cap, seen = run_wrap(machine, addr, case)
        want, want_ring = wrap_model(sets, addr, case)
        if not wrap_agrees(got, ring_after, cap, want, want_ring, case):
            mismatches += 1
        union |= seen
        wrap_total += 1
        wrap_tags[want[0]] = wrap_tags.get(want[0], 0) + 1
        wrap_inserted += 1 if want[0] == TAG_OK else 0
        for name, change in WRAP_MUTANTS:
            if name in wrap_detected:
                continue
            o = dict(WRAP_DEFAULT)
            o.update(change)
            mw, mring = wrap_model(sets, addr, case, o)
            if not wrap_agrees(got, ring_after, cap, mw, mring, case):
                wrap_detected[name] = index
    layouts = {va: front_layout(image, va) for va, _ in FRONT_FUNCTIONS}
    front_total, front_tags, front_detected = 0, {}, {}
    for fi, (fva, _) in enumerate(FRONT_FUNCTIONS):
        for index, (addr, case, key, c1, c2) in enumerate(front_cases(image, FRONT_CASES, CASE_SEED + 6 + fi)):
            run = run_front(machine, fva, layouts[fva], addr, case, key, c1, c2)
            want = front_model(sets, addr, case, key, (c1, c2, CTX + layouts[fva][2]))
            if not front_agrees(run, want, case, key, layouts[fva]):
                mismatches += 1
            union |= run[-1]
            front_total += 1
            front_tags[want[0][0]] = front_tags.get(want[0][0], 0) + 1
            for name, change in FRONT_MUTANTS:
                if name in front_detected:
                    continue
                o = dict(FRONT_DEFAULT)
                o.update(change)
                alt = front_model(sets, addr, case, key, (c1, c2, CTX + layouts[fva][2]), o)
                if not front_agrees(run, alt, case, key, layouts[fva]):
                    front_detected[name] = (fi, index)
    lookup_total, lookup_detected = 0, {}
    for index, (state, key) in enumerate(lookup_cases(LOOKUP_CASES, CASE_SEED + 20)):
        run = run_lookup(machine, state, key)
        want = lookup_model(state, key)
        if not lookup_agrees(run, want):
            mismatches += 1
        union |= run[2]
        lookup_total += 1
        for name, change in LK_MUTANTS:
            if name in lookup_detected:
                continue
            o = dict(LK_DEFAULT)
            o.update(change)
            try:
                alt = lookup_model(state, key, o)
            except (EvidenceError, IndexError):
                continue
            if not lookup_agrees(run, alt):
                lookup_detected[name] = index
    hash_total = 0
    for k0, k1, key in hasher_cases(HASH_CASES, CASE_SEED + 21):
        value, seen = run_hasher(machine, k0, k1, key)
        if value != siphash13(k0, k1, key):
            mismatches += 1
        union |= seen
        hash_total += 1
        for name, change in LK_MUTANTS:
            if name in ("rounds_c", "rounds_d") and name not in lookup_detected:
                o = dict(LK_DEFAULT)
                o.update(change)
                if value != siphash13(k0, k1, key, o):
                    lookup_detected[name] = lookup_total + hash_total
    if mismatches:
        raise EvidenceError("model disagrees with the machine code in %d cases" % mismatches)
    total += direct_total + wrap_total + front_total + lookup_total + hash_total
    controls, equivalent, negative, found = [], [], 0, 0
    for name, _ in MUTANTS:
        negative += 1
        if name in detected:
            found += 1
            controls.append(("model", name, "-", detected[name]))
        else:
            equivalent.append((name, "-", EQUIVALENT_REASON.get(name, "no case separates it")))
    for name, _ in WRAP_MUTANTS:
        negative += 1
        if name in wrap_detected:
            found += 1
            controls.append(("wrapper-model", name, "-", wrap_detected[name]))
        else:
            equivalent.append((name, "-", "no wrapper case separates it"))
    for name, _ in FRONT_MUTANTS:
        negative += 1
        if name in front_detected:
            found += 1
            controls.append(("front-model", name, "-", front_detected[name][0] * FRONT_CASES + front_detected[name][1]))
        else:
            equivalent.append((name, "-", "no front-end case separates it"))
    for name, _ in LK_MUTANTS:
        negative += 1
        if name in lookup_detected:
            found += 1
            controls.append(("lookup-model", name, "-", lookup_detected[name]))
        else:
            equivalent.append((name, "-", "no lookup case separates it"))
    wcases = list(wrap_cases(image, wrap_patch, CASE_SEED + 5))
    pcases = list(make_cases(patch_cases, CASE_SEED + 1))
    dcases = list(direct_cases(direct_patch, CASE_SEED + 3))
    for va, label in FUNCTIONS:
        rows = func_rows[va][0]
        for name, at, original, new in patch_candidates(image, rows, va == ENTRY):
            negative += 1
            if image.blob[image.offset(at)] != original:
                raise EvidenceError("patch site changed: %#x" % at)
            patched = Machine(image, {at: new})
            hit = None
            for index, case in enumerate(pcases):
                try:
                    got = run_case(patched, case)
                    bad = not agrees(got, predict(case))
                except (Halt, EvidenceError, KeyError, IndexError):
                    bad = True
                if bad:
                    hit = index
                    break
            if hit is None:
                for index, item in enumerate(dcases):
                    try:
                        bad = not run_direct(patched, item)[0]
                    except (Halt, EvidenceError, KeyError, IndexError):
                        bad = True
                    if bad:
                        hit = len(pcases) + index
                        break
            if hit is None:
                sets_p = sets
                for index, (addr, case) in enumerate(wcases):
                    try:
                        got, ring_after, cap, _ = run_wrap(patched, addr, case)
                        want, want_ring = wrap_model(sets_p, addr, case)
                        bad = not wrap_agrees(got, ring_after, cap, want, want_ring, case)
                    except (Halt, EvidenceError, KeyError, IndexError):
                        bad = True
                    if bad:
                        hit = len(pcases) + len(dcases) + index
                        break
            tag = "%s:%s" % (label, name)
            if hit is None:
                equivalent.append((tag, "%#x" % at, patch_reason(va, at, len(pcases), len(dcases), len(wcases))))
            else:
                found += 1
                controls.append(("bytes", tag, "%#x" % at, hit))
    for fi, (fva, flabel) in enumerate(FRONT_FUNCTIONS):
        fcases = list(front_cases(image, FRONT_PATCH, CASE_SEED + 9 + fi))
        for name, at, original, new in patch_candidates(image, func_rows[fva][0], True):
            negative += 1
            if image.blob[image.offset(at)] != original:
                raise EvidenceError("patch site changed: %#x" % at)
            patched = Machine(image, {at: new})
            hit = None
            for index, (addr, case, key, c1, c2) in enumerate(fcases):
                try:
                    run = run_front(patched, fva, layouts[fva], addr, case, key, c1, c2)
                    bad = not front_agrees(run, front_model(sets, addr, case, key, (c1, c2, CTX + layouts[fva][2])), case, key, layouts[fva])
                except (Halt, EvidenceError, KeyError, IndexError):
                    bad = True
                if bad:
                    hit = index
                    break
            tag = "%s:%s" % (flabel, name)
            if hit is None:
                equivalent.append((tag, "%#x" % at, "none of the %d front-end patch cases separates it from the unmodified bytes" % len(fcases)))
            else:
                found += 1
                controls.append(("bytes", tag, "%#x" % at, hit))
    lcases = list(lookup_cases(LOOKUP_PATCH, CASE_SEED + 22))
    hcases = list(hasher_cases(LOOKUP_PATCH, CASE_SEED + 23))
    for va, label in LOOKUP_FUNCTIONS:
        for name, at, original, new in patch_candidates(image, func_rows[va][0], False):
            negative += 1
            if image.blob[image.offset(at)] != original:
                raise EvidenceError("patch site changed: %#x" % at)
            patched = Machine(image, {at: new})
            hit = None
            for index, (state, key) in enumerate(lcases):
                try:
                    bad = not lookup_agrees(run_lookup(patched, state, key), lookup_model(state, key))
                except (Halt, EvidenceError, KeyError, IndexError):
                    bad = True
                if bad:
                    hit = index
                    break
            if hit is None:
                for index, (k0, k1, key) in enumerate(hcases):
                    try:
                        bad = run_hasher(patched, k0, k1, key)[0] != siphash13(k0, k1, key)
                    except (Halt, EvidenceError, KeyError, IndexError):
                        bad = True
                    if bad:
                        hit = len(lcases) + index
                        break
            tag = "%s:%s" % (label, name)
            if hit is None:
                equivalent.append((tag, "%#x" % at, "none of the %d lookup and %d hasher patch cases separates it from the unmodified bytes" % (len(lcases), len(hcases))))
            else:
                found += 1
                controls.append(("bytes", tag, "%#x" % at, hit))
    direct_kinds["total"] = direct_total
    return dict(lookup=dict(total=lookup_total, hashes=hash_total), front=dict(total=front_total, tags=front_tags, layouts=layouts), wrap=dict(total=wrap_total, tags=wrap_tags, inserted=wrap_inserted), sets=sets, direct=direct_kinds, rows=func_rows, union=union, sample=sample, tag_counts=tag_counts, kinds=kinds, total=total, fold_runs=fold_runs,
                controls=controls, equivalent=equivalent, negative=negative, found=found)


def patch_reason(function, at, admission, callee, wrapper):
    base = "none of the %d admission, %d callee and %d wrapper patch cases separates it from the unmodified bytes" % (admission, callee, wrapper)
    if function == FOLD and (0x450C542 <= at < 0x450C599 or 0x450C677 <= at < 0x450C6CA or 0x450C6DB <= at < 0x450C75C):
        return "advance-only loop of the empty-tree path, every exit returns 0 or 2 and the caller reads only bit 0; " + base
    return base


EQUIVALENT_REASON = {
    "secondary-test-ignored": "with no second container the model's key set is empty, so the fold can never hit and the record is unchanged (the byte-level test of this branch is the invert-jcc control at 0x4228226)",
    "ok-when-reach-lt-limit": "at length + 1 == limit the take count is 0, so the fold sees no items and the record is the same",
    "lower-not-saturated": "the nonce is unsigned, so nonce < a negative bound is false exactly like nonce < 0",
    "nonpositive-year-cycle-dropped": "a year at or below 0 gives a negative millisecond clock either way and the clamp turns both into 0",
    "position-after-equals": "the position differs only when the nonce is already present, and that case ends in the duplicate tag first",
    "skip-count-unsaturated": "the count is only used when length + 1 > limit, where the saturating subtraction is the plain difference",
}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--out", required=True)
    args = parser.parse_args()
    out = pathlib.Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    image = load_image()
    r = prove(image, CASES, PATCH_CASES)
    tsv(out / "controls.tsv", ["kind", "mutation", "address", "first_case_detected"], r["controls"])
    tsv(out / "equivalent-mutants.tsv", ["mutation", "address", "reason"], r["equivalent"])
    tsv(out / "cases-sample.tsv", ["case", "ring_len", "ring_cap", "ring_head", "nonce", "secondary", "secondary_keys", "date_word", "secs", "nanos",
                                   "flag_a", "flag_b", "tag", "word1", "word2", "fold_ran"], r["sample"])
    lines = []
    for va, label in FUNCTIONS + EXTRA_FUNCTIONS:
        rows, begin, end = r["rows"][va]
        for row in rows:
            lines.append((label, "%#x" % row.va, row.next - row.va, row.op, 1 if row.va in r["union"] else 0))
    tsv(out / "body.tsv", ["function", "va", "bytes", "op", "executed"], lines)
    addr_rows = []
    for label, group in (("set-a", sorted(r["sets"][0])), ("set-b", sorted(r["sets"][1]))):
        for a in group:
            addr_rows.append((label, "0x" + a.hex()))
    for k, a in enumerate(r["sets"][2]):
        addr_rows.append(("wrapper-constant-%d" % (k + 1), "0x" + a.hex() if a else "-"))
    tsv(out / "special-addresses.tsv", ["group", "address20"], addr_rows)
    tag_rows = []
    for tag in (TAG_FULL, TAG_LOW, TAG_HIGH, TAG_DUP):
        arm, kind, target, text = display_arm(image, tag)
        tag_rows.append((tag, "%#x" % arm, kind, "%#x" % target, text))
    tsv(out / "tags.tsv", ["tag", "display_arm", "kind", "text_va", "text"], tag_rows)
    cov = []
    for va, label in FUNCTIONS + EXTRA_FUNCTIONS:
        rows, begin, end = r["rows"][va]
        ran = sum(1 for row in rows if row.va in r["union"])
        cov.append((label, "%#x" % begin, end - begin, len(rows), ran))
    tsv(out / "coverage.tsv", ["function", "start", "bytes", "instructions", "executed_in_corpus"], cov)
    tsv(out / "kinds.tsv", ["tag", "secondary", "fold_ran", "cases"],
        [("%#x" % k[0], k[1], int(k[2]), v) for k, v in sorted(r["kinds"].items())])
    summary = {"entry": "%#x" % ENTRY, "functions": {label: "%#x" % va for va, label in FUNCTIONS + EXTRA_FUNCTIONS}, "cases": r["total"],
               "tag_counts": {"%#x" % k: v for k, v in sorted(r["tag_counts"].items())}, "cases_where_fold_ran": r["fold_runs"], "callee_cases": r["direct"], "front_cases": {"%#x" % k if isinstance(k, int) else k: v for k, v in r["front"]["tags"].items()}, "lookup_cases": r["lookup"]["total"], "hasher_cases": r["lookup"]["hashes"], "front_layouts": {"%#x" % k: ["%#x" % x for x in v] for k, v in sorted(r["front"]["layouts"].items())}, "wrapper_cases": {"%#x" % k if isinstance(k, int) else k: v for k, v in r["wrap"]["tags"].items()},
               "binary_sha256": SHA256}
    (out / "summary.json").write_text(json.dumps(summary, indent=1, sort_keys=True) + "\n")
    measure = {"cases": r["total"], "negative_controls": r["negative"], "negative_detected": r["found"], "equivalent": len(r["equivalent"])}
    (out / "measure.json").write_text(json.dumps(measure, indent=1, sort_keys=True) + "\n")
    print(json.dumps(measure, sort_keys=True))


if __name__ == "__main__":
    main()
