#!/usr/bin/env python3
"""Reconstruct the node #115 user-signed action EIP-712 digest wrappers by running their bytes.

For every user-signed action whose wrapper, message-hash function and type builder form a slot pair in the relocated
signing table, the tool finds the layout of the action record (which record bytes feed each signed field and the
domain chain id), runs the original wrapper on fuzzed records inside an offline x86-64 interpreter (the binary is
never executed) and compares the 32-byte result with an independent Python EIP-712 digest. The interpreter part is
the shared offline x86-64 core copied below; the second part (after the marker) is specific to this packet.

    python3 tools/action_wire_signing_digest_115.py --out research/work-items/action-wire-signing-digest-115
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
                raise Halt("unmodelled indirect call at %#x target %#x" % (row.va, target))
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


# =====================================================================================
# Part 2: node #115 user-signed action digest reconstruction
# =====================================================================================

import argparse  # noqa: E402
import json  # noqa: E402
import re  # noqa: E402

TABLE_LO, TABLE_HI = 0x64EA840, 0x64EAB28   # relocated slot table: [message-hash fn, type builder] pairs
SLOT_VALUE, SLOT_STRUCT, SLOT_UPDATE, SLOT_FINAL = 0x64E0138, 0x64E0140, 0x64E0148, 0x64E0150
SLOT_DOMAIN = 0x64E2178
SLOT_ALLOC, SLOT_FREE, SLOT_REALLOC, SLOT_REALLOC_AL, SLOT_ALLOC_AL = 0x64DF480, 0x64DF4A0, 0x64DF588, 0x64DF580, 0x64DF590
ACT = STACK_TOP - 0x4000
OUT = ACT + 0x400
STR_AREA = HEAP_BASE + 0x100
HEAP_START = HEAP_BASE + 0x1000
LABEL_PTRS, LABEL_LENS = 0x648E198, 0x458700
PREFIX = b"HyperliquidTransaction:"
DOMAIN_TYPE = b"EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"
DOMAIN_NAME, DOMAIN_VERSION = b"HyperliquidSignTransaction", b"1"

_RC = [0x0000000000000001, 0x0000000000008082, 0x800000000000808A, 0x8000000080008000, 0x000000000000808B,
       0x0000000080000001, 0x8000000080008081, 0x8000000000008009, 0x000000000000008A, 0x0000000000000088,
       0x0000000080008009, 0x000000008000000A, 0x000000008000808B, 0x800000000000008B, 0x8000000000008089,
       0x8000000000008003, 0x8000000000008002, 0x8000000000000080, 0x000000000000800A, 0x800000008000000A,
       0x8000000080008081, 0x8000000000008080, 0x0000000080000001, 0x8000000080008008]
_ROT = [[0, 36, 3, 41, 18], [1, 44, 10, 45, 2], [62, 6, 43, 15, 61], [28, 55, 25, 21, 56], [27, 20, 39, 8, 14]]
M64 = (1 << 64) - 1


def keccak256(data):
    """Original-padding Keccak-256, the reference the wrapper's sponge is compared with."""
    a = [[0] * 5 for _ in range(5)]
    msg = bytearray(data)
    msg.append(1)
    while len(msg) % 136:
        msg.append(0)
    msg[-1] |= 0x80
    for off in range(0, len(msg), 136):
        for i in range(17):
            a[i % 5][i // 5] ^= int.from_bytes(msg[off + 8 * i:off + 8 * i + 8], "little")
        for rc in _RC:
            c = [a[x][0] ^ a[x][1] ^ a[x][2] ^ a[x][3] ^ a[x][4] for x in range(5)]
            d = [c[(x - 1) % 5] ^ (((c[(x + 1) % 5] << 1) | (c[(x + 1) % 5] >> 63)) & M64) for x in range(5)]
            for x in range(5):
                for y in range(5):
                    a[x][y] ^= d[x]
            b = [[0] * 5 for _ in range(5)]
            for x in range(5):
                for y in range(5):
                    r = _ROT[x][y]
                    v = a[x][y]
                    b[y][(2 * x + 3 * y) % 5] = ((v << r) | (v >> (64 - r))) & M64 if r else v
            for x in range(5):
                for y in range(5):
                    a[x][y] = b[x][y] ^ (~b[(x + 1) % 5][y] & b[(x + 2) % 5][y]) & M64
            a[0][0] ^= rc
    return b"".join(a[i % 5][i // 5].to_bytes(8, "little") for i in range(4))


def glob_dat_names(image):
    """GLOB_DAT slot -> imported symbol name, read from .dynsym / .dynstr."""
    dynsym, dynstr = image.named[".dynsym"], image.named[".dynstr"]
    blob = image.blob
    out = {}
    for slot, kind, _, sym in image.relocations():
        if kind == 6 and sym:
            name_off = struct.unpack_from("<I", blob, dynsym["offset"] + sym * 24)[0]
            start = dynstr["offset"] + name_off
            out[slot] = bytes(blob[start:blob.index(b"\0", start)]).decode().split("@")[0]
    return out


class LogMemory(Memory):
    """Memory that can log reads of the action record (offset, width) for layout probing."""

    def __init__(self, image):
        super().__init__(image)
        self.log = None

    def bytes_at(self, addr, count):
        if self.log is not None and ACT <= addr < ACT + 0x200:
            self.log.append(("r", addr - ACT, count))
        return super().bytes_at(addr, count)


class TraceMachine(Machine):
    def __init__(self, image):
        super().__init__(image)
        self.memory = LogMemory(image)
        self.marks = {}

    def step(self, row):
        if self.memory.log is not None and row.va in self.marks:
            self.memory.log.append(("m", self.marks[row.va], 0))
        return super().step(row)


class Rig:
    """One interpreter with the allocator, libc copies and (optionally) the sponge modelled."""

    def __init__(self, image):
        self.image = image
        self.rel = image.relative()
        m = self.m = TraceMachine(image)
        for slot, add in self.rel.items():
            m.memory.statics[slot] = add
        names = glob_dat_names(image)
        hooks = {"memcpy": self.h_copy, "memmove": self.h_copy, "memset": self.h_set}
        self.slot_hooks = {}
        for slot, name in names.items():
            fake = 0xC0DE0000 + (slot & 0xFFFF)
            m.memory.statics[slot] = fake
            if name in hooks:
                self.slot_hooks[fake] = hooks[name]
        rel = self.rel
        self.slot_hooks[rel[SLOT_ALLOC]] = self.h_alloc
        self.slot_hooks[rel[SLOT_FREE]] = self.h_free
        self.slot_hooks[rel[SLOT_REALLOC]] = self.h_realloc
        self.slot_hooks[rel[SLOT_REALLOC_AL]] = self.h_realloc
        self.slot_hooks[rel[SLOT_ALLOC_AL]] = self.h_alloc
        self.update, self.final = rel[SLOT_UPDATE], rel[SLOT_FINAL]
        self.real_extra = set()
        self.heap = HEAP_START
        self.sizes = {}
        self.bufs = {}
        self.nh = 0
        self.updates = []
        m.marks = {rel[SLOT_VALUE]: "v", rel[SLOT_DOMAIN]: "d"}
        self.set_mode(True)

    # -- modes -------------------------------------------------------------------
    def set_mode(self, fast):
        """fast: the Keccak update/finalize slots are served by a Python sponge; else the real bodies run."""
        self.fast = fast
        m = self.m
        m.slots = dict(self.slot_hooks)
        real = set(self.real_extra)
        for slot in (SLOT_VALUE, SLOT_STRUCT, SLOT_DOMAIN, 0x64E0158, 0x64ECB70):
            real.add(self.rel[slot])
        if fast:
            m.slots[self.update] = self.h_update
            m.slots[self.final] = self.h_final
        else:
            real.add(self.update)
            real.add(self.final)
        m.real = frozenset(real)

    # -- hooks -------------------------------------------------------------------
    def take(self, size, align):
        p = (self.heap + align - 1) & ~(align - 1)
        self.heap = p + max(size, 1)
        self.sizes[p] = size
        return p

    def h_alloc(self, m):
        m.regs[RAX] = self.take(m.regs[RDI], 16)

    def h_free(self, m):
        pass

    def h_realloc(self, m):
        old, size = m.regs[RDI], m.regs[RSI]
        p = self.take(size, 16)
        keep = min(self.sizes.get(old, 0), size)
        if keep:
            m.memory.copy(p, old, keep)
        m.regs[RAX] = p

    def h_copy(self, m):
        if m.regs[RDX]:
            m.memory.copy(m.regs[RDI], m.regs[RSI], m.regs[RDX])
        m.regs[RAX] = m.regs[RDI]

    def h_set(self, m):
        if m.regs[RDX]:
            m.memory.put_bytes(m.regs[RDI], bytes([m.regs[RSI] & 0xFF]) * m.regs[RDX])
        m.regs[RAX] = m.regs[RDI]

    def h_update(self, m):
        state = m.regs[RDI]
        data = m.memory.bytes_at(m.regs[RSI], m.regs[RDX]) if m.regs[RDX] else b""
        handle = m.memory.read(state, 8)
        if handle == 0:
            self.nh += 1
            handle = self.nh
            m.memory.write(state, 8, handle)
            self.bufs[handle] = bytearray()
        self.bufs[handle] += data
        self.updates.append(bytes(data))

    def h_final(self, m):
        handle = m.memory.read(m.regs[RDI], 8)
        m.memory.put_bytes(m.regs[RSI], keccak256(bytes(self.bufs.get(handle, b"")))[:m.regs[RDX]])

    # -- running -----------------------------------------------------------------
    def reset(self):
        self.m.memory.reset()
        self.heap = HEAP_START
        self.sizes.clear()
        self.bufs.clear()
        self.nh = 0
        self.updates = []

    def call(self, entry, record, strings=(), log=False):
        """Run `entry(out, record)`; `record` is the action bytes, `strings` are (address, bytes) to place."""
        self.reset()
        mem = self.m.memory
        mem.put_bytes(ACT, bytes(0x200))
        mem.put_bytes(ACT, record)
        for addr, data in strings:
            mem.put_bytes(addr, data)
        mem.put_bytes(OUT, bytes(0x40))
        self.m.steps = 0
        mem.log = [] if log else None
        try:
            self.m.run(entry, {RDI: OUT, RSI: ACT})
        finally:
            events, mem.log = mem.log, None
        return mem.bytes_at(OUT, 33), events, self.m.steps

    def learn(self, entry, record=bytes(0x200), limit=60):
        """Run once on a zero record; every unmodelled callee that the byte path reaches is promoted to a real body."""
        for _ in range(limit):
            try:
                return self.call(entry, record)
            except Halt as err:
                found = re.search(r"unmodelled call to (0x[0-9a-f]+)", str(err)) or \
                    re.search(r"unmodelled indirect call at 0x[0-9a-f]+ target (0x[0-9a-f]+)", str(err))
                if not found or int(found.group(1), 16) == 0:
                    raise
                self.real_extra.add(int(found.group(1), 16))
                self.set_mode(self.fast)
        raise EvidenceError("callee learning did not converge")


# -------------------------------------------------------------------- discovery

def table_calls(image):
    base, text = image.text_bytes()
    callers = {}
    at = 0
    while True:
        at = text.find(b"\xff\x15", at)
        if at < 0 or at + 6 > len(text):
            break
        slot = base + at + 6 + struct.unpack_from("<i", text, at + 2)[0]
        if TABLE_LO <= slot < TABLE_HI:
            callers.setdefault(slot, []).append(base + at)
        at += 1
    return callers


def find_triples(image):
    """(wrapper, message-hash function, type builder, hash slot): the hash function is the caller of the builder's slot,
    and the wrapper is the single caller of the table slot that holds that hash function."""
    rel, callers = image.relative(), table_calls(image)
    slot_of = {}
    for slot in range(TABLE_LO, TABLE_HI, 8):
        if slot in rel:
            slot_of.setdefault(rel[slot], []).append(slot)
    rows = []
    for slot in range(TABLE_LO, TABLE_HI, 8):
        users = callers.get(slot, [])
        if len(users) != 1 or slot not in rel:
            continue
        hash_fn = image.fde(users[0])[0]
        hslots = slot_of.get(hash_fn, [])
        if len(hslots) != 1 or hslots[0] == slot:
            continue
        wrappers = sorted({image.fde(va)[0] for va in callers.get(hslots[0], [])})
        if len(wrappers) == 1:
            rows.append(dict(wrapper=wrappers[0], hash=hash_fn, builder=rel[slot], slot=hslots[0], builder_slot=slot))
    return sorted(rows, key=lambda r: r["slot"])


def parse_encode_type(text):
    match = re.fullmatch(rb"HyperliquidTransaction:(\w+)\(([^)]*)\)", text)
    if not match:
        return None
    fields = []
    for item in match.group(2).split(b","):
        kind, name = item.split(b" ")
        fields.append((name.decode(), kind.decode()))
    return match.group(1).decode(), fields


def label_table(image, count=4):
    rel = image.relative()
    out = []
    for i in range(count):
        ptr = rel.get(LABEL_PTRS + 8 * i)
        if ptr is None:
            break
        length = struct.unpack_from("<Q", image.blob, image.offset(LABEL_LENS + 8 * i))[0]
        out.append(bytes(image.blob[image.offset(ptr):image.offset(ptr) + length]))
    return out


# -------------------------------------------------------------------- layout probing

def split_events(events):
    """Reads of the action record before the domain call, and per value-constructor group after it."""
    pre, groups, cur, state = [], [], [], 0
    for kind, a, b in events:
        if kind == "m" and a == "d":
            state = 1
            continue
        if state == 0:
            if kind == "r":
                pre.append((a, b))
            continue
        if kind == "m" and a == "v":
            groups.append(cur)
            cur = []
        elif kind == "r":
            cur.append((a, b))
    return pre, groups


def cover(reads):
    """Distinct (offset, width) reads in first-seen order, and the lowest offset they touch."""
    seen = []
    for item in reads:
        if item not in seen:
            seen.append(item)
    return seen, (min(o for o, _ in seen) if seen else None)


WIDTH = {"string": 24, "bytes": 24, "address": 20, "uint64": 8, "uint32": 4, "bool": 1, "bytes32": 32}


def probe(rig, row):
    """Learn the layout of one action by logging which record bytes each signed field reads."""
    rig.set_mode(True)
    rig.learn(row["wrapper"])
    result, events, steps = rig.call(row["wrapper"], bytes(0x200), log=True)
    encode = next((u for u in rig.updates if u.startswith(PREFIX)), None)
    parsed = parse_encode_type(encode) if encode else None
    if parsed is None:
        return None
    name, fields = parsed
    pre, groups = split_events(events)
    reads_after = groups
    # the domain record is read before the domain call as one 32-byte little-endian block
    pre_set, cid_off = cover(pre)
    if cid_off is None or sum(w for _, w in pre_set) != 32:
        return dict(name=name, encode=encode, fields=fields, status="domain-record-unresolved", steps=steps)
    # groups[0] holds the reads before the first value constructor after the domain call; the hash function's
    # own constructor calls follow, one per field
    value_groups = [g for g in reads_after]
    start = len(value_groups) - len(fields)
    if start < 0:
        return dict(name=name, encode=encode, fields=fields, status="too-few-values", steps=steps)
    value_groups = value_groups[start:]
    layout = []
    for (fname, ftype), reads in zip(fields, value_groups):
        seen, low = cover(reads)
        if not seen:
            return dict(name=name, encode=encode, fields=fields, status="field-without-reads:" + fname, steps=steps)
        if ftype in ("string", "bytes"):
            widths = [(o, w) for o, w in seen if w == 8]
            ones = [o for o, w in seen if w == 1]
            if widths:
                layout.append((fname, ftype, max(o for o, _ in widths) - 16, tuple(seen), "string"))
            elif len(ones) == 1 and len(seen) == 1:
                layout.append((fname, ftype, ones[0], tuple(seen), "chain" if fname == "hyperliquidChain" else "enum"))
            else:
                return dict(name=name, encode=encode, fields=fields, status="layout-unresolved:" + fname, steps=steps)
        else:
            layout.append((fname, ftype, low, tuple(seen), "plain"))
    spec = dict(name=name, encode=encode, fields=fields, layout=layout, cid_off=cid_off, status="ok", steps=steps,
                wrapper=row["wrapper"], hash=row["hash"], builder=row["builder"], slot=row["slot"])
    spec["enums"] = {}
    for fname, ftype, offset, _, kind in layout:
        if kind in ("enum", "chain"):
            spec["enums"][fname] = enum_labels(rig, row["wrapper"], offset)
            if not spec["enums"][fname]:
                spec["status"] = "enum-unresolved:" + fname
    return spec


def enum_labels(rig, wrapper, offset):
    """Labels a one-byte selector can take: run with selector 0, 1, 2.. and read the hashed string that changes."""
    labels, previous = [], None
    for value in range(12):
        record = bytearray(0x200)
        record[offset] = value
        try:
            out, _, _ = rig.call(wrapper, bytes(record))
        except (Halt, EvidenceError, IndexError, struct.error):
            break
        if out[0] != 0:
            break
        updates = list(rig.updates)
        if previous is not None:
            if len(updates) != len(previous):
                break
            changed = [k for k in range(len(updates)) if updates[k] != previous[k]]
            if not changed:
                break
            if not labels:
                labels.append(previous[changed[0]])
            labels.append(updates[changed[0]])
        previous = updates
    return labels


# -------------------------------------------------------------------- reference model

def be32(value):
    return value.to_bytes(32, "big")


def struct_hash(encode, words):
    return keccak256(keccak256(encode) + b"".join(words))


def domain_separator(chain_id, name=DOMAIN_NAME, version=DOMAIN_VERSION, prefix_type=DOMAIN_TYPE):
    return keccak256(keccak256(prefix_type) + keccak256(name) + keccak256(version) + be32(chain_id) + bytes(32))


def field_word(ftype, value):
    if ftype in ("string", "bytes"):
        return keccak256(value)
    if ftype == "address":
        return bytes(12) + value
    if ftype in ("uint64", "uint32"):
        return be32(value)
    if ftype == "bool":
        return be32(1 if value else 0)
    if ftype == "bytes32":
        return value
    raise ValueError(ftype)


MUTANTS = {}


def reference_digest(encode, fields, values, chain_id, mutant=None):
    """EIP-712 digest: keccak(0x1901 | domainSeparator | hashStruct) with the wrapper's fixed domain."""
    ftypes = [t for _, t in fields]
    words = [field_word(t, v) for t, v in zip(ftypes, values)]
    domain, prefix, enc = domain_separator(chain_id), b"\x19\x01", encode
    if mutant == "domain-name":
        domain = domain_separator(chain_id, name=DOMAIN_NAME[:-1])
    elif mutant == "domain-version":
        domain = domain_separator(chain_id, version=b"2")
    elif mutant == "chain-id-plus-one":
        domain = domain_separator(chain_id + 1)
    elif mutant == "domain-type":
        domain = domain_separator(chain_id, prefix_type=DOMAIN_TYPE.replace(b"uint256", b"uint64"))
    elif mutant == "prefix-0x1900":
        prefix = b"\x19\x00"
    elif mutant == "prefix-swapped":
        prefix = b"\x01\x19"
    elif mutant == "drop-last-field" and words:
        words = words[:-1]
    elif mutant == "swap-first-two" and len(words) > 1:
        words[0], words[1] = words[1], words[0]
    elif mutant == "string-not-hashed" and values and isinstance(values[0], bytes):
        words[0] = values[0].ljust(32, b"\0")[:32]
    elif mutant == "uint-little-endian":
        words = [w[::-1] if t in ("uint64", "uint32") else w for w, t in zip(words, ftypes)]
    elif mutant == "type-string-no-prefix":
        enc = encode[len(PREFIX):]
    elif mutant == "struct-hash-only":
        prefix, domain = b"", b""
    elif mutant == "domain-first-struct-twice":
        domain = struct_hash(enc, words)
    return keccak256(prefix + domain + struct_hash(enc, words))


# -------------------------------------------------------------------- inputs

class Lcg:
    def __init__(self, seed):
        self.s = (seed * 6364136223846793005 + 1442695040888963407) & M64

    def next(self):
        self.s = (self.s * 6364136223846793005 + 1442695040888963407) & M64
        return self.s >> 11

    def below(self, n):
        return self.next() % n

    def bytes(self, n):
        return bytes(self.below(256) for _ in range(n))

    def text(self, n):
        return bytes(32 + self.below(95) for _ in range(n))


def make_case(spec, rng, labels, index):
    """Random action values -> (record bytes, strings to place, python values, chain id, chain selector)."""
    record = bytearray(0x200)
    strings, values = [], []
    area = STR_AREA
    chain_id = (1 + rng.below(1 << 40)) if index % 7 else rng.below(1 << 16)
    record[spec["cid_off"]:spec["cid_off"] + 32] = chain_id.to_bytes(32, "little")
    chain_idx = 0
    for fname, ftype, offset, _, kind in spec["layout"]:
        if kind in ("chain", "enum"):
            choices = spec["enums"][fname]
            pick = rng.below(len(choices))
            record[offset] = pick
            values.append(choices[pick])
            if kind == "chain":
                chain_idx = pick
        elif kind == "string":
            n = (0, 1, 2, 19, 20, 42, 43, 64)[rng.below(8)] if index % 3 == 0 else rng.below(90)
            text = rng.text(n)
            strings.append((area, text))
            record[offset:offset + 24] = struct.pack("<QQQ", n, area if n else 1, n)
            area += ((n + 15) & ~15) or 16
            values.append(text)
        elif ftype == "address":
            raw = rng.bytes(20)
            record[offset:offset + 20] = raw
            values.append(raw)
        elif ftype == "uint64":
            v = (rng.next() << rng.below(20)) & M64
            record[offset:offset + 8] = v.to_bytes(8, "little")
            values.append(v)
        elif ftype == "uint32":
            v = rng.next() & 0xFFFFFFFF
            record[offset:offset + 4] = v.to_bytes(4, "little")
            values.append(v)
        elif ftype == "bool":
            v = rng.below(2)
            record[offset] = v
            values.append(v)
        elif ftype == "bytes32":
            raw = rng.bytes(32)
            record[offset:offset + 32] = raw
            values.append(raw)
        else:
            raise ValueError(ftype)
    return bytes(record), strings, values, chain_id, chain_idx


def case_matches(rig, spec, labels, case, mutant=None, entry=None):
    record, strings, values, chain_id, _ = case
    out, _, steps = rig.call(entry or spec["wrapper"], record, strings)
    expect = reference_digest(spec["encode"], spec["fields"], values, chain_id, mutant)
    return out[0] == 0 and out[1:33] == expect, out, steps


# -------------------------------------------------------------------- driver

CASES_PER_ACTION = 70
REAL_SPONGE_EVERY = 3   # the real Keccak bodies run for every third resolved action (about 2.6 s each)


def build(image):
    rig = Rig(image)
    labels = label_table(image)
    triples = find_triples(image)
    specs, rows = [], []
    for row in triples:
        try:
            spec = probe(rig, row)
        except (Halt, EvidenceError, Panicked, struct.error, ValueError, IndexError) as err:
            spec = dict(status="probe-failed:" + type(err).__name__, name="", encode=b"", fields=[])
        spec.update(row)
        specs.append(spec)
    return rig, labels, specs


def run_cases(rig, labels, specs, writer, stats):
    """Run every resolved action: fast-sponge fuzz cases, then real-sponge cases, compare with the reference."""
    resolved_index = -1
    for spec in specs:
        if spec["status"] != "ok":
            continue
        resolved_index += 1
        rng = Lcg(spec["wrapper"])
        spec["matched"] = spec["total"] = 0
        rig.set_mode(True)
        for index in range(CASES_PER_ACTION):
            case = make_case(spec, rng, labels, index)
            ok, out, steps = case_matches(rig, spec, labels, case)
            spec["total"] += 1
            spec["matched"] += ok
            stats["cases"] += 1
            stats["matched"] += ok
            writer(spec, "fast", index, case, out, ok)
            if index == 0:
                spec["sample_updates"] = list(rig.updates)
        if resolved_index % REAL_SPONGE_EVERY == 0:
            rig.set_mode(False)
            case = make_case(spec, Lcg(spec["wrapper"] ^ 0x5EED), labels, 0)
            ok, out, steps = case_matches(rig, spec, labels, case)
            spec["total"] += 1
            spec["matched"] += ok
            stats["cases"] += 1
            stats["matched"] += ok
            stats["real_sponge"] += 1
            stats["real_sponge_ok"] += ok
            writer(spec, "real", 0, case, out, ok)
            rig.set_mode(True)


def detect_mutants(rig, labels, specs, image):
    """Negative controls: wrong references, corrupted bytes, wrong entry points. Returns rows (name, detail, detected)."""
    good = [s for s in specs if s["status"] == "ok"]
    rows = []
    probe_specs = good[:: max(1, len(good) // 3)][:3]

    def cases_for(spec, n=3):
        rng = Lcg(spec["wrapper"] ^ 0xBAD)
        return [make_case(spec, rng, labels, i) for i in range(n)]

    for mutant in ("domain-name", "domain-version", "chain-id-plus-one", "domain-type", "prefix-0x1900", "prefix-swapped",
                   "drop-last-field", "swap-first-two", "string-not-hashed", "uint-little-endian", "type-string-no-prefix",
                   "struct-hash-only", "domain-first-struct-twice"):
        detected, equivalent = False, False
        for spec in probe_specs:
            if mutant == "string-not-hashed" and spec["fields"] and spec["fields"][0][1] not in ("string", "bytes"):
                continue
            for case in cases_for(spec):
                ok, _, _ = case_matches(rig, spec, labels, case, mutant)
                detected |= not ok
        rows.append((mutant, "reference", detected))
    # wrong field mapping: first field type read as another type
    spec = probe_specs[0]
    bad = dict(spec, fields=[(spec["fields"][0][0], "uint64")] + spec["fields"][1:])
    detected = False
    for case in cases_for(spec):
        try:
            ok, _, _ = case_matches(rig, bad, labels, case)
        except (ValueError, TypeError, AttributeError):
            ok = False
        detected |= not ok
    rows.append(("first-field-retyped", "reference", detected))
    # wrong label table
    swapped = list(reversed(labels))
    detected = False
    for case in cases_for(spec):
        record, strings, values, chain_id, chain_idx = case
        values = [swapped[chain_idx]] + values[1:]
        ok, _, _ = case_matches(rig, spec, labels, (record, strings, values, chain_id, chain_idx))
        detected |= not ok
    rows.append(("label-order-reversed", "reference", detected))
    # layout mutants: a record built with a wrong offset must not reproduce the wrapper's digest
    usd = next((s for s in good if s["name"] == "UsdSend"), good[0])
    addr = next((s for s in good if any(f[1] == "address" for f in s["layout"])), good[0])
    flag = next((s for s in good if any(f[1] == "bool" for f in s["layout"])), good[0])
    enum = next((s for s in good if any(f[4] == "enum" for f in s["layout"])), good[0])
    shifted = dict(usd, layout=[(f, t, o + (8 if f == "destination" else 0), r, k) for f, t, o, r, k in usd["layout"]])
    rows.append(("layout-string-offset-shifted", "UsdSend destination +8", wrong_spec_found(rig, shifted, usd, labels)))
    rows.append(("layout-chain-id-offset-shifted", "UsdSend chain id +8", wrong_spec_found(rig, dict(usd, cid_off=usd["cid_off"] + 8), usd, labels)))
    chain_shift = dict(usd, layout=[(f, t, o + (1 if k == "chain" else 0), r, k) for f, t, o, r, k in usd["layout"]])
    rows.append(("layout-selector-offset-shifted", "UsdSend selector +1", wrong_spec_found(rig, chain_shift, usd, labels)))
    time_shift = dict(usd, layout=[(f, t, o + (8 if f == "time" else 0), r, k) for f, t, o, r, k in usd["layout"]])
    rows.append(("layout-uint64-offset-shifted", "UsdSend time +8", wrong_spec_found(rig, time_shift, usd, labels)))
    flipped = []
    for case in cases_for(addr, 4):
        record, strings, values, chain_id, chain_idx = case
        flipped.append((record, strings, [v[::-1] if isinstance(v, bytes) and len(v) == 20 else v for v in values], chain_id, chain_idx))
    rows.append(("address-bytes-reversed", addr["name"], any(not case_matches(rig, addr, labels, c)[0] for c in flipped)))
    inverted = []
    for case in cases_for(flag, 4):
        record, strings, values, chain_id, chain_idx = case
        inverted.append((record, strings, [(1 - v) if isinstance(v, int) and v in (0, 1) else v for v in values], chain_id, chain_idx))
    rows.append(("bool-inverted", flag["name"], any(not case_matches(rig, flag, labels, c)[0] for c in inverted)))
    rotated = dict(enum, enums=dict((k, v[1:] + v[:1]) for k, v in enum["enums"].items()))
    rows.append(("selector-labels-rotated", enum["name"], wrong_spec_found(rig, rotated, enum, labels)))
    # byte corruption of the original image (code and data) in a private copy
    mut_image = copy_image(image)
    base = bytearray(mut_image.blob)
    mut_image.blob = base
    mrig = Rig(mut_image)
    mrig.real_extra = set(rig.real_extra)
    equivalent = []
    for label, va, delta, mode in byte_edits(image, usd):
        at = image.offset(va)
        saved = base[at]
        base[at] = (saved + delta) & 0xFF
        mrig.m.cache.clear()
        mrig.set_mode(mode == "fast")
        detected = False
        for case in cases_for(usd, 2):
            try:
                ok, _, _ = case_matches(mrig, usd, labels, case)
                detected |= not ok
            except (Halt, EvidenceError, Panicked, IndexError, struct.error):
                detected = True
        base[at] = saved
        mrig.m.cache.clear()
        if not detected and label in EQUIVALENT_EDITS:
            equivalent.append((label, "byte %#x +%d" % (va, delta), EQUIVALENT_EDITS[label]))
            rows.append((label, "byte %#x +%d" % (va, delta), "equivalent"))
        else:
            rows.append((label, "byte %#x +%d" % (va, delta), detected))
    # out-of-range entries
    for label, entry in (("entry-mid-function", usd["wrapper"] + 0x10), ("entry-hash-function-only", usd["hash"]),
                         ("entry-unmapped", 0x10), ("entry-past-image", len(image.blob) + 0x1000)):
        detected = False
        try:
            ok, _, _ = case_matches(rig, usd, labels, cases_for(usd, 1)[0], entry=entry)
            detected = not ok
        except (Halt, EvidenceError, Panicked, IndexError, struct.error):
            detected = True
        rows.append((label, "entry %#x" % entry, detected))
    rows.append(("wrong-binary-digest", "digest", digest_check_detects()))
    return rows, equivalent


EQUIVALENT_EDITS = {
    "final-length-immediate": "the real sponge was run and the 32-byte result and the tag are unchanged; the one extra squeezed byte "
                              "lands in stack padding after the result and is never read (observed, not proven for every path)",
    "state-copy-size": "the real sponge was run and the result is unchanged; the one extra copied byte is overwritten or "
                       "ignored before the state is used (observed, not proven for every path)",
    "domain-name-alloc-size": "the buffer is allocated for 26 bytes and written with exactly 26; the spare byte is never read, hashed "
                              "or compared, and the buffer is freed with the same size argument",
}


def wrong_spec_found(rig, wrong, right, labels):
    """True when records built from a wrong layout do not reproduce the digest the right layout predicts."""
    found = False
    for index in range(3):
        record, strings, values, chain_id, _ = make_case(wrong, Lcg(right["wrapper"] + index), labels, index)
        try:
            out, _, _ = rig.call(right["wrapper"], record, strings)
        except (Halt, EvidenceError, Panicked, IndexError, struct.error):
            found = True
            continue
        expect = reference_digest(right["encode"], right["fields"], values, chain_id)
        found |= not (out[0] == 0 and out[1:33] == expect)
    return found


def copy_image(image):
    import copy
    return copy.copy(image)


def byte_edits(image, spec):
    """Single-byte corruptions of the UsdSend wrapper and hash function: (label, address, delta, mode).

    mode `real` runs the real Keccak bodies, because the edited byte is only observable there."""
    base, text = image.text_bytes()

    def body(entry):
        start = entry - base
        return text[start:image.fde(entry)[1] - base]

    wrapper, hash_fn = body(spec["wrapper"]), body(spec["hash"])
    edits = []
    table = (
        (wrapper, spec["wrapper"], b"\xbf\x1a\x00\x00\x00", 1, "domain-name-alloc-size", "fast"),
        (wrapper, spec["wrapper"], b"\x41\xc6\x04\x24\x31", 4, "domain-version-byte", "fast"),
        (wrapper, spec["wrapper"], b"\xba\x03\x00\x00\x00", 1, "join-record-count", "fast"),
        (wrapper, spec["wrapper"], b"\x49\x8d\x46\x30", 3, "domain-record-offset", "fast"),
        (wrapper, spec["wrapper"], b"\xba\x20\x00\x00\x00", 1, "final-length-immediate", "real"),
        (wrapper, spec["wrapper"], b"\xba\xe0\x00\x00\x00", 1, "state-copy-size", "real"),
        (wrapper, spec["wrapper"], b"\x48\xc7\x84\x24\xf0\x01\x00\x00\x88\x00\x00\x00", 8, "sponge-rate-immediate", "real"),
        (hash_fn, spec["hash"], b"\x41\x0f\xb6\x47\x58", 4, "selector-read-offset", "fast"),
        (hash_fn, spec["hash"], b"\x49\x8b\x47\x50", 3, "time-read-offset", "fast"),
    )
    for data, entry, pattern, delta_at, label, mode in table:
        at = data.find(pattern)
        if at >= 0:
            edits.append((label, entry + at + delta_at, 1, mode))
    for at in range(len(wrapper) - 7):
        if wrapper[at:at + 3] == b"\x48\x8d\x05":
            target = spec["wrapper"] + at + 7 + struct.unpack_from("<i", wrapper, at + 3)[0]
            try:
                data = image.blob[image.offset(target):image.offset(target) + 2]
            except EvidenceError:
                continue
            if data == b"\x19\x01":
                edits.append(("prefix-literal-byte0", target, 1, "fast"))
                edits.append(("prefix-literal-byte1", target + 1, 1, "fast"))
    for at in range(len(wrapper) - 8):
        if wrapper[at:at + 3] == b"\x0f\x10\x05":
            edits.append(("domain-name-literal-byte", spec["wrapper"] + at + 8 + struct.unpack_from("<i", wrapper, at + 3)[0], 1, "fast"))
            break
    return edits


def digest_check_detects():
    try:
        load_image(BINARY, "0" * 64)
    except EvidenceError:
        return True
    return False


def generate(out):
    image = load_image()
    rig, labels, specs = build(image)
    lines = {"layouts.tsv": [], "cases.tsv": []}
    stats = dict(cases=0, matched=0, real_sponge=0, real_sponge_ok=0)

    def writer(spec, mode, index, case, out_bytes, ok):
        record, strings, values, chain_id, chain_idx = case
        lines["cases.tsv"].append("\t".join(map(str, (spec["name"], mode, index, chain_idx, chain_id,
                                                          out_bytes[1:33].hex(), "match" if ok else "MISMATCH"))))

    run_cases(rig, labels, specs, writer, stats)
    negatives, equivalent = detect_mutants(rig, labels, specs, image)
    return image, labels, specs, stats, negatives, equivalent, lines, rig


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", required=True)
    args = parser.parse_args()
    out = pathlib.Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    image, labels, specs, stats, negatives, equivalent, lines, rig = generate(out)
    emit(out, image, labels, specs, stats, negatives, equivalent, lines, rig)


def emit(out, image, labels, specs, stats, negatives, equivalent, lines, rig):
    (out / "labels.tsv").write_text("index\tlabel\n" + "".join("%d\t%s\n" % (i, v.decode()) for i, v in enumerate(labels)))
    rows = ["action\twrapper\thash_fn\tbuilder\tslot\tstatus\tfield_index\tfield\ttype_kind\trecord_offset\treads"]
    for s in specs:
        if s["status"] != "ok":
            rows.append("\t".join(map(str, (s.get("name", ""), "%#x" % s["wrapper"], "%#x" % s["hash"], "%#x" % s["builder"],
                                            "%#x" % s["slot"], s["status"], "", "", "", "", ""))))
            continue
        for i, (fname, ftype, offset, reads, kind) in enumerate(s["layout"]):
            rows.append("\t".join(map(str, (s["name"], "%#x" % s["wrapper"], "%#x" % s["hash"], "%#x" % s["builder"],
                                            "%#x" % s["slot"], s["status"], i, fname, ftype + "/" + kind, "%#x" % offset,
                                            " ".join("%#x/%d" % r for r in reads)))))
    (out / "layouts.tsv").write_text("\n".join(rows) + "\n")
    (out / "cases.tsv").write_text("action\tmode\tindex\tchain_index\tchain_id\tdigest\tresult\n" +
                                   "\n".join(lines["cases.tsv"]) + "\n")
    enc = ["action\twrapper\tcid_offset\tselector_labels\tsteps_zero_record\tencode_type"]
    for s in specs:
        if s["status"] == "ok":
            sel = ";".join("%s=%s" % (k, "|".join(v.decode() for v in vs)) for k, vs in sorted(s["enums"].items()))
            enc.append("\t".join(map(str, (s["name"], "%#x" % s["wrapper"], "%#x" % s["cid_off"], sel, s["steps"], s["encode"].decode()))))
    (out / "actions.tsv").write_text("\n".join(enc) + "\n")
    callees = ["target\tbytes"]
    for t in sorted(rig.real_extra):
        a, b = image.fde(t)
        callees.append("%#x\t%d" % (t, b - a))
    (out / "callees.tsv").write_text("\n".join(callees) + "\n")
    ups = ["action\twrapper\tseq\tbytes\tabsorbed_prefix_hex\tkind"]
    sels = ["action\twrapper\tfield\tvalue\tlabel"]
    for s in specs:
        if s["status"] != "ok":
            continue
        for seq, data in enumerate(s["sample_updates"]):
            if data.startswith(PREFIX):
                kind = "encodeType"
            elif data.startswith(b"EIP712Domain("):
                kind = "domain-type"
            elif data == DOMAIN_NAME:
                kind = "domain-name"
            elif data == DOMAIN_VERSION:
                kind = "domain-version"
            elif data[:2] == b"\x19\x01":
                kind = "final-preimage"
            elif len(data) == 32 * (len(s["fields"]) + 1) or len(data) == 160:
                kind = "struct-words"
            else:
                kind = "field-or-domain-word"
            ups.append("\t".join(map(str, (s["name"], "%#x" % s["wrapper"], seq, len(data), data[:48].hex(), kind))))
        for fname, labs in sorted(s["enums"].items()):
            for value, lab in enumerate(labs):
                sels.append("\t".join(map(str, (s["name"], "%#x" % s["wrapper"], fname, value, lab.decode()))))
    (out / "updates.tsv").write_text("\n".join(ups) + "\n")
    (out / "selectors.tsv").write_text("\n".join(sels) + "\n")
    neg = ["control\tdetail\tresult"]
    for n, d, x in negatives:
        neg.append("%s\t%s\t%s" % (n, d, "equivalent" if x == "equivalent" else ("detected" if x else "MISSED")))
    (out / "negatives.tsv").write_text("\n".join(neg) + "\n")
    (out / "equivalent-mutants.tsv").write_text("mutant\taddress\treason\n" + "".join("%s\t%s\t%s\n" % row for row in equivalent))
    detected = sum(1 for _, _, x in negatives if x is True)
    summary = dict(actions_found=len(specs), actions_resolved=sum(1 for s in specs if s["status"] == "ok"),
                   unresolved=sorted((s.get("name") or "%#x" % s["wrapper"]) + ":" + s["status"] for s in specs if s["status"] != "ok"),
                   labels=[v.decode() for v in labels], **stats)
    (out / "summary.json").write_text(json.dumps(summary, indent=1, sort_keys=True) + "\n")
    (out / "measure.json").write_text(json.dumps(dict(cases=stats["cases"], negative_controls=len(negatives),
                                                      negative_detected=detected, equivalent=len(equivalent)), indent=1, sort_keys=True) + "\n")
    print(json.dumps(summary, sort_keys=True)[:600])
    print("negatives", detected, "+", len(equivalent), "equivalent /", len(negatives))


if __name__ == "__main__":
    main()
