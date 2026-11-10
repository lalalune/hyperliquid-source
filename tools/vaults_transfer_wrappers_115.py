#!/usr/bin/env python3
"""Reconstruct eight node #115 vault-transfer result wrappers (0x50a5ce0, 0x58c23a0, 0x543ac80, 0x54f2840, 0x532fc60, 0x534bd60, 0x5208890, 0x532f980) from the ELF bytes.

Each subject is run as real code in a small offline x86-64 evaluator (the binary is never executed and no external program is called);
its callees are served by recording stubs with written contracts. A rule list written from the control flow is compared with the
evaluator over generated cases (result record bytes, outcome and ordered stub calls), then byte edits and wrong readings are shown to
be refused.

    python3 tools/vaults_transfer_wrappers_115.py --out research/work-items/vaults-transfer-wrappers-115
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




# =====================================================================================================================================
# Subjects: five vault-transfer era result wrappers of node #115 (l1/action/vault_transfer.rs, l1/qtys/*.rs) run as real code
# =====================================================================================================================================

import argparse  # noqa: E402
import collections  # noqa: E402
import json  # noqa: E402
import math  # noqa: E402
import re  # noqa: E402

G_A = 0x50A5CE0      # state gate A: two state bytes, an index bound, one lookup callee
G_B = 0x58C23A0      # quantity wrapper: amount bound (n < 0xccccccccccccccc), one callee
G_C = 0x543AC80      # quantity wrapper with a first slot call and a second direct callee
G_D = 0x54F2840      # amount bound + transfer record logger (the largest subject)
G_E = 0x532FC60      # guarded one byte setter
G_F = 0x534BD60      # result widener: Ok payload loses one padding byte
G_G = 0x5208890      # request forwarder: copies a 0x51 byte request into locals and forwards pointers
G_H = 0x532F980      # key forwarder: copies a 20 byte key and forwards a fixed argument frame
G_I = 0x5208370      # list forwarder: clones a vector of 16 byte items (capacity guard) and forwards it
G_J = 0x5436600      # pair forwarder: clones two optional byte strings (niche encoded) and forwards them with a 17 byte tail
SUBJECTS = (G_A, G_B, G_C, G_D, G_E, G_F, G_G, G_H, G_I, G_J)
NICHE = 1 << 63
NAMES = {G_A: "gate-a", G_B: "amount-wrap", G_C: "slot-wrap", G_D: "transfer-log", G_E: "flag-set", G_F: "result-widen",
         G_G: "request-forward", G_H: "key-forward", G_I: "list-forward", G_J: "pair-forward"}
CALL_F = 0x54CD990
CALL_G = 0x555F0D0
CALL_H = 0x558F390
CALL_I = 0x55687E0
CALL_J = 0x556D0B0
SLOT_LAYOUT = 0x64DF498      # capacity overflow / allocation error hook (never returns)
SLOT_COPY = 0x64DF508        # memcpy
ELEMS = HEAP_BASE + 0x7900
SIZE_LIMIT = 0x7FFFFFFFFFFFFFF8
LOCATION_H = 0x64A4748       # static Location record passed by G_H as the last stack argument

CALL_A = 0x55C6D50
CALL_B = 0x55F5AF0
CALL_C2 = 0x556E360
SLOT_C1 = 0x64E5B38
SLOT_D_CHECK = 0x64E7A68
SLOT_D_RECORD = 0x64EBC18
SLOT_ALLOC = 0x64DF480
SLOT_ALLOC_FAIL = 0x64DF490
SLOT_PANIC = 0x64DF6A0
DROP_D = 0x44E0810
CALL_E1 = 0x4DC91F0
CALL_E2 = 0x4DA56B0
DIV_CONST = 0x4599A0         # divisor of both f64 conversions in G_D
LIMIT_AT = {G_B: 0x58C23AE, G_C: 0x543ACC7, G_D: 0x54F285A}   # movabs imm64 of the bound compare
UNWRAP_VTABLE = 0x648C5F8    # Debug vtable of the error value handed to the unwrap failure
UNWRAP_LOCATION = 0x648B990  # Location record of the unwrap call in G_D
PANIC_TEXT_AT = 0x7D3212
PANIC_TEXT_LEN = 0x2B

OUT = HEAP_BASE + 0x100
OUT_LEN = 0x80
REQ = HEAP_BASE + 0x400
SIDE = HEAP_BASE + 0x600
CTX = HEAP_BASE + 0x1000
CLOCK = HEAP_BASE + 0x6000
OBJ = HEAP_BASE + 0x7000
ALLOC = HEAP_BASE + 0x7800
USED = 0x8000
FILL = 0xEE
SUCCESS = 0x1A2
M64 = MASK[8]
PATTERN = bytes((index * 29 + 5) & 0xFF for index in range(USED))
SLOT_NAMES = {SLOT_C1: "slot-c1", SLOT_D_CHECK: "d-check", SLOT_D_RECORD: "d-record", SLOT_ALLOC: "alloc", SLOT_ALLOC_FAIL: "alloc-fail",
              SLOT_PANIC: "panic", SLOT_LAYOUT: "layout-error", SLOT_COPY: "memcpy"}


def lcg(seed):
    state = seed & M64
    while True:
        state = (state * 6364136223846793005 + 1442695040888963407) & M64
        yield state >> 16


class Draw:
    def __init__(self, seed):
        self.stream = lcg(seed)

    def u(self, bound):
        return next(self.stream) % bound

    def u64(self):
        return (next(self.stream) << 40 ^ next(self.stream) << 8 ^ next(self.stream)) & M64

    def pick(self, items):
        return items[self.u(len(items))]

    def data(self, count):
        return bytes(self.u(256) for _ in range(count))


def read_u64(image, va):
    return struct.unpack_from("<Q", image.blob, image.offset(va))[0]


def constant_values(image):
    k = {"limit_%s" % NAMES[s]: read_u64(image, va + 2) for s, va in LIMIT_AT.items()}
    k["divisor"] = struct.unpack_from("<d", image.blob, image.offset(DIV_CONST))[0]
    k["panic_text"] = bytes(image.blob[image.offset(PANIC_TEXT_AT):image.offset(PANIC_TEXT_AT) + PANIC_TEXT_LEN]).decode()
    return k


class Case:
    def __init__(self, subject, name, **fields):
        self.subject, self.name = subject, name
        self.rdx = SIDE
        self.rec = self.rec2 = bytes(0x70)
        self.flag = self.state = self.byte = self.obj = 0
        self.idx = self.limit = self.n = self.n2 = 0
        self.u32 = self.sel = self.when = 0
        self.stamp = self.clock = self.pair = self.word = 0
        self.key = bytes(20)
        self.unwrap_err = self.alloc_fail = False
        self.req = bytes(0x58)
        self.count, self.elems = 0, b""
        self.fail_second = False
        self.x = self.y = self.len1 = self.len2 = 0
        self.tail = bytes(17)
        self.elems2 = b""
        self.addr = bytes(20)
        self.__dict__.update(fields)


def record(tag, body):
    return struct.pack("<H", tag) + body[:0x6E]


# --- the harness -------------------------------------------------------------------------------------------------------------------

class Harness:
    def __init__(self, image, patches=None):
        self.image = image
        machine = Machine(image, patches)
        self.machine = machine
        for target, hook in ((CALL_A, self.on_a), (CALL_B, self.on_b), (CALL_C2, self.on_c2), (DROP_D, self.on_drop),
                             (CALL_E1, self.on_e1), (CALL_E2, self.on_e2),
                             (CALL_F, self.on_f), (CALL_G, self.on_g), (CALL_H, self.on_h), (CALL_I, self.on_i), (CALL_J, self.on_j)):
            machine.calls[target] = hook
        hooks = {SLOT_C1: self.on_c1, SLOT_D_CHECK: self.on_d_check, SLOT_D_RECORD: self.on_d_record, SLOT_ALLOC: self.on_alloc,
                 SLOT_ALLOC_FAIL: self.on_alloc_fail, SLOT_PANIC: self.on_panic, SLOT_LAYOUT: self.on_layout, SLOT_COPY: self.on_copy}
        for slot, hook in hooks.items():
            machine.memory.statics[slot] = MARK_BASE + slot
            machine.slots[MARK_BASE + slot] = hook
        self.case, self.log, self.allocs = None, [], 0

    def expect(self, condition, text):
        if not condition:
            raise Halt("stub check failed: " + text)

    def stack_out(self, address):
        self.expect(self.machine.memory.stack_base <= address < STACK_TOP, "result slot on the stack")

    def put_record(self, address, data):
        self.stack_out(address)
        self.machine.memory.put_bytes(address, data)

    def on_a(self, machine):
        regs = machine.regs
        self.expect(regs[RSI] == CTX and regs[RCX] == self.case.idx, "gate-a callee arguments")
        self.log.append(("lookup", self.case.idx))
        self.put_record(regs[RDI], self.case.rec)

    def on_b(self, machine):
        regs = machine.regs
        self.expect(regs[RSI] == CTX and regs[RCX] == self.case.n and regs[R8] == REQ + 8 and regs[RDX] == self.case.rdx, "amount callee arguments")
        self.log.append(("amount", self.case.n))
        self.put_record(regs[RDI], self.case.rec)

    def on_c1(self, machine):
        regs = machine.regs
        self.expect(regs[RSI] == self.case.u32 and regs[RDX] == CTX + 0x1330 and regs[RCX] == CTX + 0x90, "slot-wrap first call arguments")
        self.log.append(("first", self.case.u32))
        self.put_record(regs[RDI], self.case.rec)

    def on_c2(self, machine):
        regs = machine.regs
        first = self.case.rec
        want = (struct.unpack_from("<Q", first, 8)[0], struct.unpack_from("<Q", first, 0x10)[0])
        self.expect(regs[RSI] == CTX and regs[RDX] == self.case.rdx and (regs[RCX], regs[R8]) == want, "slot-wrap second call arguments")
        self.log.append(("second", want[0], want[1]))
        self.put_record(regs[RDI], self.case.rec2)

    def on_f(self, machine):
        regs = machine.regs
        self.expect(regs[RSI] == CTX and regs[RCX] == REQ and regs[RDX] == self.case.rdx, "result-widen callee arguments")
        self.log.append(("widen",))
        self.put_record(regs[RDI], self.case.rec)

    def on_g(self, machine):
        regs, mem = machine.regs, machine.memory
        self.expect(regs[RSI] == CTX and regs[RDX] == self.case.rdx, "request-forward callee arguments")
        self.log.append(("forward", mem.bytes_at(regs[RCX], 0x18).hex(), mem.bytes_at(regs[R8], 0x38).hex(), regs[R9] & MASK[4]))
        self.put_record(regs[RDI], self.case.rec)

    def on_h(self, machine):
        regs, mem = machine.regs, machine.memory
        sp = regs[RSP]
        stack_args = tuple(mem.read(sp + 8 + 8 * i, 8) for i in range(3))
        self.expect(regs[RSI] == CTX, "key-forward context")
        self.log.append(("key", mem.bytes_at(regs[RDX], 20).hex(), regs[RCX], regs[R8], mem.read(regs[R9], 8), stack_args))
        self.put_record(regs[RDI], self.case.rec)

    def on_i(self, machine):
        regs, mem = machine.regs, machine.memory
        self.expect(regs[RSI] == CTX and regs[RDX] == self.case.rdx, "list-forward callee arguments")
        cap, ptr, count = (mem.read(regs[RCX] + 8 * i, 8) for i in range(3))
        item = mem.read(regs[RCX] + 0x18, 1)
        items = mem.bytes_at(ptr, 16 * count).hex() if count else ""
        self.log.append(("list", cap, ptr, count, item, items))
        self.put_record(regs[RDI], self.case.rec)

    def on_j(self, machine):
        regs, mem = machine.regs, machine.memory
        self.expect(regs[RSI] == CTX and regs[RDX] == self.case.rdx, "pair-forward callee arguments")
        base = regs[RCX]
        cap1, ptr1, len1 = (mem.read(base + 8 * i, 8) for i in range(3))
        if cap1 in (NICHE, NICHE + 1):
            first, second, byte = ("niche", cap1), ("unset",) if cap1 == NICHE + 1 else None, None
        else:
            first = ("vec", cap1, len1, mem.bytes_at(ptr1, len1).hex() if len1 else "", 0 if len1 else ptr1)
            byte = mem.read(base + 0x18, 1)
            second = None
        if second is None:
            cap2, ptr2, len2 = (mem.read(base + 0x20 + 8 * i, 8) for i in range(3))
            second = ("niche", cap2) if cap2 == NICHE else ("vec", cap2, len2, mem.bytes_at(ptr2, len2).hex() if len2 else "", 0 if len2 else ptr2)
        self.log.append(("pair", first, byte, second, mem.bytes_at(base + 0x38, 17).hex()))
        self.put_record(regs[RDI], self.case.rec)

    def on_layout(self, machine):
        raise Panicked("layout:%d:%#x" % (machine.regs[RDI], machine.regs[RSI]))

    def on_copy(self, machine):
        regs = machine.regs
        self.expect(regs[RDI] in (ALLOC, ALLOC + 0x40) and regs[RSI] in (ELEMS, ELEMS + 0x80) and regs[RDX] <= 0x100, "memcpy arguments")
        self.log.append(("copy", regs[RDX]))
        machine.memory.copy(regs[RDI], regs[RSI], regs[RDX])

    def on_drop(self, machine):
        self.log.append(("drop", machine.memory.read(machine.regs[RDI], 2)))

    def on_e1(self, machine):
        self.expect(machine.regs[RSI] == CTX + 0x4B68, "flag-set guard source")
        self.log.append(("enter",))

    def on_e2(self, machine):
        self.log.append(("leave",))
        machine.regs[RAX] = OBJ

    def on_d_check(self, machine):
        regs, case = machine.regs, self.case
        self.expect(regs[RSI] == CTX + 0x1710 and regs[RDX] == REQ and regs[RCX] == case.rdx and regs[R8] == CTX + 0x4A78, "transfer-log check arguments")
        pair = machine.memory.bytes_at(regs[R9], 12)
        self.expect(pair == struct.pack("<QI", case.stamp, case.word), "transfer-log stamp pair")
        self.log.append(("check", pair.hex()))
        self.put_record(regs[RDI], case.rec)

    def on_d_record(self, machine):
        regs, mem, case = machine.regs, machine.memory, self.case
        self.expect(regs[RDI] == CTX + 0x7C0, "recorder receiver")
        cap, ptr, count = (mem.read(regs[RSI] + 8 * i, 8) for i in range(3))
        self.expect(ptr == ALLOC, "recorder key vector buffer")
        keys = [mem.bytes_at(ptr + 20 * i, 20).hex() for i in range(count)]
        event = tuple(mem.read(regs[R8] + 8 * i, 8) for i in range(4))
        self.log.append(("record", cap, count, tuple(keys), mem.bytes_at(regs[RDX], 12).hex(), mem.bytes_at(regs[RCX], 32).hex(), event))

    def on_alloc(self, machine):
        self.log.append(("alloc", machine.regs[RDI]))
        nth = self.allocs
        self.allocs += 1
        failing = (self.case.alloc_fail and nth == 0) or (self.case.fail_second and nth == 1)
        machine.regs[RAX] = 0 if failing else ALLOC + 0x40 * nth

    def on_alloc_fail(self, machine):
        self.log.append(("alloc-fail", machine.regs[RDI], machine.regs[RSI]))
        raise Panicked("alloc-fail")

    def on_panic(self, machine):
        regs = machine.regs
        text = machine.memory.bytes_at(regs[RDI], regs[RSI]).decode()
        tag = machine.memory.read(regs[RDX], 2)
        raise Panicked("panic:%s|%#x|%#x|%#x" % (text, tag, regs[RCX], regs[R8]))

    def fresh(self, case):
        machine = self.machine
        mem = machine.memory
        mem.reset(USED)
        machine.xmm = [POISON | POISON << 64] * 16
        mem.put_bytes(HEAP_BASE, PATTERN)
        mem.put_bytes(OUT - 0x100, bytes([FILL]) * 0x200)
        self.case, self.log, self.allocs = case, [], 0
        sub = case.subject
        if sub == G_A:
            mem.write(CTX + 0x4349, 1, case.flag)
            mem.write(CTX + 0x170A, 1, case.state)
            mem.write(CTX + 0xB8, 8, case.limit)
            mem.write(REQ + 0x10, 8, case.idx)
        elif sub == G_B:
            mem.write(REQ, 8, case.n)
        elif sub == G_C:
            mem.write(REQ, 8, case.n)
            mem.write(REQ + 8, 4, case.u32)
        elif sub == G_D:
            mem.write(REQ + 0x20, 8, case.n2)
            mem.write(REQ + 0x28, 8, case.n)
            mem.put_bytes(REQ + 0x30, case.addr)
            mem.write(CTX + 0x60, 8, case.stamp)
            mem.write(CTX + 0x68, 4, case.word)
            mem.write(CTX + 0x1338, 8, CLOCK)
            mem.write(CTX + 0x1340, 8, 0 if case.unwrap_err else 1 + (case.clock & 0xFF))
            mem.write(CLOCK + 0x4C0, 8, case.clock)
        elif sub == G_F:
            pass
        elif sub == G_J:
            mem.write(REQ, 8, case.x)
            mem.write(REQ + 8, 8, ELEMS)
            mem.write(REQ + 0x10, 8, case.len1)
            mem.write(REQ + 0x18, 1, case.byte)
            mem.write(REQ + 0x20, 8, case.y)
            mem.write(REQ + 0x28, 8, ELEMS + 0x80)
            mem.write(REQ + 0x30, 8, case.len2)
            mem.put_bytes(REQ + 0x38, case.tail)
            mem.put_bytes(ELEMS, case.elems)
            mem.put_bytes(ELEMS + 0x80, case.elems2)
        elif sub == G_I:
            mem.write(REQ + 8, 8, ELEMS)
            mem.write(REQ + 0x10, 8, case.count)
            mem.write(REQ + 0x18, 1, case.byte)
            mem.put_bytes(ELEMS, case.elems)
        elif sub == G_G:
            mem.put_bytes(REQ, case.req)
        elif sub == G_H:
            mem.put_bytes(SIDE, case.key)
        elif sub == G_E:
            mem.write(CTX + 0x4E1D, 1, case.flag)
            mem.write(REQ, 1, case.byte)
            mem.write(OBJ + 0x1C, 1, case.obj)
        return bytes(mem.heap[:USED])

    def run(self, case):
        before = self.fresh(case)
        machine = self.machine
        sub = case.subject
        regs = {RDI: OUT, RSI: REQ, RDX: case.rdx, RCX: CTX}
        if sub in (G_D,):
            regs = {RDI: OUT, RSI: CTX, RDX: case.rdx, RCX: REQ}
        try:
            machine.run(sub, regs)
            outcome = "return"
        except Panicked as panic:
            return ("panic", str(panic), b"", b""), self.log
        after = bytes(machine.memory.heap[:USED])
        keep = [(OUT - HEAP_BASE, OUT - HEAP_BASE + OUT_LEN)]
        if sub == G_E:
            keep.append((OBJ + 0x1C - HEAP_BASE, OBJ + 0x1D - HEAP_BASE))
        if sub == G_D:
            keep.append((ALLOC - HEAP_BASE, ALLOC - HEAP_BASE + 0x14))
        if sub == G_J:
            keep.append((ALLOC - HEAP_BASE, ALLOC - HEAP_BASE + 0x80))
        if sub == G_I and 0 < case.count <= 8:
            keep.append((ALLOC - HEAP_BASE, ALLOC - HEAP_BASE + 16 * case.count))
        position = 0
        for lo, hi in sorted(keep):
            if after[position:lo] != before[position:lo]:
                raise Halt("the body changed memory outside the result record")
            position = hi
        if after[position:] != before[position:]:
            raise Halt("the body changed memory outside the result record")
        out = bytes(machine.memory.bytes_at(OUT, OUT_LEN))
        extra = bytes(machine.memory.bytes_at(OBJ + 0x1C, 1)) if sub == G_E else b""
        return (outcome, "", out, extra), self.log


# --- the rule lists: what each subject decides, written from the control flow and independent of the evaluator ----------------------

def blank():
    return bytearray([FILL]) * OUT_LEN


def put16(out, at, value):
    out[at:at + 2] = struct.pack("<H", value)


def put64(out, at, value):
    out[at:at + 8] = struct.pack("<Q", value & M64)


def tag_of(rec):
    return struct.unpack_from("<H", rec, 0)[0]


def spec_a(case, k, v=frozenset()):
    out, log = blank(), []
    flag_zero = case.flag == 0 if "flag_inverted" not in v else case.flag != 0
    state_three = case.state == (3 if "state_two" not in v else 2)
    if flag_zero and (state_three or "state_ignored" in v):
        put16(out, 0x10, 0x91)
        out[0] = 0xF
        return ("return", "", bytes(out), b""), log
    out_of_range = case.idx > case.limit if "idx_gt" in v else case.idx >= case.limit
    if out_of_range and "bound_ignored" not in v:
        put16(out, 0x10, 0xFA)
        out[0] = 0xF
        return ("return", "", bytes(out), b""), log
    log.append(("lookup", case.idx))
    if tag_of(case.rec) == SUCCESS and "err_always" not in v:
        out[0] = 0xE
        if "ok_copies" in v:
            out[0x10:0x80] = case.rec
    else:
        out[0x10:0x80] = case.rec
        out[0] = 0xF
    return ("return", "", bytes(out), b""), log


def spec_b(case, k, v=frozenset()):
    out, log = blank(), []
    limit = k["limit_amount-wrap"] + (1 if "limit_plus_one" in v else 0)
    if case.n >= limit and "bound_ignored" not in v:
        put16(out, 0x10, 0x154)
        put64(out, 0x18, case.n)
        out[0] = 0xF
        return ("return", "", bytes(out), b""), log
    log.append(("amount", case.n))
    if tag_of(case.rec) == SUCCESS:
        out[0] = 0xE
    else:
        out[0x10:0x80] = case.rec
        out[0] = 0xF
    return ("return", "", bytes(out), b""), log


def spec_c(case, k, v=frozenset()):
    out, log = blank(), []
    log.append(("first", case.u32))
    if tag_of(case.rec) != SUCCESS:
        out[0x10:0x80] = case.rec
        out[0] = 0xF
        return ("return", "", bytes(out), b""), log
    limit = k["limit_slot-wrap"]
    if (case.n > limit) if "limit_gt" in v else (case.n >= limit):
        put16(out, 0x10, 0x154)
        put64(out, 0x18, case.n)
        out[0] = 0xF
        return ("return", "", bytes(out), b""), log
    first = case.rec
    log.append(("second", struct.unpack_from("<Q", first, 8)[0], struct.unpack_from("<Q", first, 0x10)[0]))
    out[0] = 5
    out[1:0x10] = first[:15]
    if "second_tag_checked" in v and tag_of(case.rec2) != SUCCESS:
        out[0] = 0xF
    out[0x10:0x80] = case.rec2
    return ("return", "", bytes(out), b""), log


def f64_bits(value):
    return struct.unpack("<Q", struct.pack("<d", value))[0]


def spec_d(case, k, v=frozenset()):
    out, log = blank(), []
    limit = k["limit_transfer-log"]
    if (case.n > limit) if "limit_gt" in v else (case.n >= limit):
        put16(out, 0, 0x154)
        put64(out, 8, case.n)
        return ("return", "", bytes(out), b""), log
    log.append(("check", struct.pack("<QI", case.stamp, case.word).hex()))
    if tag_of(case.rec) != SUCCESS:
        out[0:0x70] = case.rec
        return ("return", "", bytes(out), b""), log
    if (case.rec[2] != 1) if "flag_nonzero" not in v else (case.rec[2] == 0):
        put16(out, 0, SUCCESS)
        return ("return", "", bytes(out), b""), log
    if case.unwrap_err:
        return ("panic", "panic:%s|%#x|%#x|%#x" % (k["panic_text"], 0x156, UNWRAP_VTABLE, UNWRAP_LOCATION), b"", b""), log
    log.append(("drop", 0x156))
    log.append(("alloc", 0x14))
    if case.alloc_fail:
        return ("panic", "alloc-fail", b"", b""), log + [("alloc-fail", 1, 0x14)]
    div = k["divisor"]
    amount = f64_bits(float(case.n) / div)
    clock = case.clock - (1 << 64) if ("clock_signed" in v and case.clock >> 63) else case.clock
    seconds = f64_bits(float(clock) / div)
    event = (0x8000000000000000, amount, case.n2, seconds)
    log.append(("record", 1, 1, (case.addr.hex(),), struct.pack("<QI", case.stamp, case.word).hex(), case.rec[3:0x23].hex(), event))
    put16(out, 0, SUCCESS)
    return ("return", "", bytes(out), b""), log


def spec_e(case, k, v=frozenset()):
    out, log = blank(), []
    if case.flag == 0:
        put16(out, 0x10, 0x92)
        out[0] = 0xF
        return ("return", "", bytes(out), bytes([case.obj])), log
    out[0] = 0xE
    if case.byte == 2:
        return ("return", "", bytes(out), bytes([case.obj])), log
    log += [("enter",), ("leave",)]
    return ("return", "", bytes(out), bytes([case.byte])), log


def spec_f(case, k, v=frozenset()):
    out, log = blank(), [("widen",)]
    if tag_of(case.rec) == SUCCESS:
        out[0] = 0xC
        out[1:0x20] = case.rec[:7] + case.rec[8:0x20]
    else:
        out[0x10:0x80] = case.rec
        out[0] = 0xF
    return ("return", "", bytes(out), b""), log


def spec_g(case, k, v=frozenset()):
    out = blank()
    log = [("forward", case.req[0:0x18].hex(), case.req[0x18:0x50].hex(), case.req[0x50])]
    if tag_of(case.rec) == SUCCESS:
        out[0] = 0xE
    else:
        out[0x10:0x80] = case.rec
        out[0] = 0xF
    return ("return", "", bytes(out), b""), log


def spec_h(case, k, v=frozenset()):
    out = blank()
    log = [("key", case.key.hex(), 0, 0, 0, (SIDE, REQ, LOCATION_H))]
    if tag_of(case.rec) == SUCCESS:
        out[0] = 0xE
    else:
        out[0x10:0x80] = case.rec
        out[0] = 0xF
    return ("return", "", bytes(out), b""), log


def spec_i(case, k, v=frozenset()):
    out, log = blank(), []
    count = case.count
    size = (count << 4) & M64
    if count >> 60 or size > SIZE_LIMIT:
        return ("panic", "layout:0:%#x" % size, b"", b""), log
    if size == 0:
        cap, ptr = 0, 8
    else:
        log.append(("alloc", size))
        if case.alloc_fail:
            return ("panic", "layout:8:%#x" % size, b"", b""), log
        log.append(("copy", size))
        cap, ptr = (count if "cap_is_size" not in v else size), ALLOC
    log.append(("list", cap, ptr, count, case.byte, case.elems[:16 * count].hex() if count else ""))
    if tag_of(case.rec) == SUCCESS:
        out[0] = 1 if "ok_tag_zero" not in v else 0
        out[1:0x20] = case.rec[:7] + case.rec[8:0x20]
    else:
        out[0x10:0x80] = case.rec
        out[0] = 0xF
    return ("return", "", bytes(out), b""), log


def spec_j(case, k, v=frozenset()):
    out, log = blank(), []
    x = case.x
    niche_one = x == NICHE + (1 if "min_plus_one_as_min" not in v else 0)
    dangling = 1 if "dangling_zero" not in v else 0
    if niche_one:
        cap1, ptr1, first, byte, second = x, CTX, ("niche", x), None, ("unset",)
    else:
        if x == NICHE:
            cap1, ptr1, first, byte = x, CTX, ("niche", x), None
        elif case.len1 == 0:
            cap1, ptr1, first, byte = 0, dangling, ("vec", 0, 0, "", dangling), case.byte
        else:
            log += [("alloc", case.len1)]
            if case.alloc_fail:
                return ("panic", "layout:1:%#x" % case.len1, b"", b""), log
            log += [("copy", case.len1)]
            cap1, ptr1, first, byte = case.len1, ALLOC, ("vec", case.len1, case.len1, case.elems[:case.len1].hex(), 0), case.byte
        if case.y == NICHE:
            second = ("niche", NICHE)
        elif case.len2 == 0:
            second = ("vec", 0, 0, "", dangling)
        else:
            log += [("alloc", case.len2)]
            nth = sum(1 for entry in log if entry[0] == "alloc") - 1       # the second allocation only when the first string was cloned
            if (case.alloc_fail and nth == 0) or (case.fail_second and nth == 1):
                return ("panic", "layout:1:%#x" % case.len2, b"", b""), log
            log += [("copy", case.len2)]
            second = ("vec", case.len2, case.len2, case.elems2[:case.len2].hex(), 0)
    log.append(("pair", first, byte, second, case.tail.hex()))
    out[0] = 4
    out[1:0x10] = (struct.pack("<Q", cap1) + struct.pack("<Q", ptr1))[:15]
    out[0x10:0x80] = case.rec
    return ("return", "", bytes(out), b""), log


SPECS = {G_J: spec_j, G_I: spec_i, G_F: spec_f, G_G: spec_g, G_H: spec_h, G_A: spec_a, G_B: spec_b, G_C: spec_c, G_D: spec_d, G_E: spec_e}
VARIANTS = {
    G_A: ("flag_inverted", "state_two", "state_ignored", "idx_gt", "bound_ignored", "err_always", "ok_copies"),
    G_B: ("limit_plus_one", "bound_ignored"),
    G_C: ("limit_gt", "second_tag_checked"),
    G_D: ("limit_gt", "flag_nonzero", "clock_signed"),
    G_E: (),
    G_F: (), G_G: (), G_H: (), G_I: ("cap_is_size", "ok_tag_zero"), G_J: ("dangling_zero", "min_plus_one_as_min"),
}


# --- cases ---------------------------------------------------------------------------------------------------------------------------

def rec_for(d, ok, byte2=None, fixed=None):
    body = bytearray(d.data(0x70))
    tag = SUCCESS if ok else d.pick((0, 1, 0x91, 0xFA, 0x154, 0x156, 0x1A1, 0x1A3, 0xFFFF, 0x7B, 0x98))
    body[0:2] = struct.pack("<H", tag)
    if byte2 is not None:
        body[2] = byte2
    return bytes(body)


def boundary_u64(d, limit):
    return d.pick((0, 1, limit - 1, limit, limit + 1, limit - 2, M64, M64 - 1, 1 << 63, (1 << 63) - 1, 1 << 32, d.u64() % limit, d.u64() % limit,
                   d.u64()))


def draw_a(d, index):
    limit = d.pick((0, 1, 2, 5, 100, 1 << 40, M64, d.u64()))
    idx = d.pick((0, 1, limit, limit - 1 if limit else 0, limit + 1 & M64, d.u64(), d.u(8), d.u(200)))
    return Case(G_A, "a-%d" % index, flag=d.pick((0, 0, 1, 2, 0xFF)), state=d.pick((3, 3, 0, 1, 2, 4, 0xFF)), limit=limit, idx=idx,
                rec=rec_for(d, d.u(2) == 0), rdx=SIDE + d.u(4))


def draw_b(d, index, k):
    limit = k["limit_amount-wrap"]
    return Case(G_B, "b-%d" % index, n=boundary_u64(d, limit), rec=rec_for(d, d.u(2) == 0), rdx=SIDE + d.u(8))


def draw_c(d, index, k):
    limit = k["limit_slot-wrap"]
    return Case(G_C, "c-%d" % index, n=boundary_u64(d, limit), u32=d.pick((0, 1, 0xFFFFFFFF, d.u(1 << 32), 7)), rec=rec_for(d, d.u(3) != 0),
                rec2=rec_for(d, d.u(2) == 0), rdx=SIDE + d.u(8))


def draw_d(d, index, k):
    limit = k["limit_transfer-log"]
    ok = d.u(4) != 0
    byte2 = d.pick((1, 1, 1, 0, 2, 0xFF, 3))
    return Case(G_D, "d-%d" % index, n=boundary_u64(d, limit), n2=d.u64(), addr=d.data(20), stamp=d.u64(), word=d.u(1 << 32),
                clock=d.pick((0, 1, d.u64(), d.u64() >> 11, 1 << 53, (1 << 53) + 1, M64, 1_700_000_000_000_000_000, d.u(10 ** 6))),
                rec=rec_for(d, ok, byte2), unwrap_err=d.u(12) == 0, alloc_fail=d.u(15) == 0, rdx=SIDE + d.u(8))


def draw_e(d, index):
    return Case(G_E, "e-%d" % index, flag=d.pick((0, 1, 2, 0xFF)), byte=d.pick((0, 1, 2, 3, 0xFF, d.u(256))), obj=d.u(256))


def draw_f(d, index):
    return Case(G_F, "f-%d" % index, rec=rec_for(d, d.u(2) == 0), rdx=SIDE + d.u(8))


def draw_g(d, index):
    return Case(G_G, "g-%d" % index, req=d.data(0x58), rec=rec_for(d, d.u(2) == 0), rdx=SIDE + d.u(8))


def draw_h(d, index):
    return Case(G_H, "h-%d" % index, key=d.data(20), rec=rec_for(d, d.u(2) == 0), rdx=SIDE)


def draw_i(d, index):
    count = d.pick((0, 1, 2, 3, 4, 8, d.u(9), d.u(9), d.u(9), 1 << 59, (1 << 59) - 1, 1 << 60, (1 << 60) + 1, M64, 1 << 63))
    huge = count > 8
    return Case(G_I, "i-%d" % index, count=count, byte=d.u(256), elems=d.data(16 * min(count, 8)), rec=rec_for(d, d.u(2) == 0),
                alloc_fail=huge and count << 4 & M64 <= SIZE_LIMIT and count >> 60 == 0 or d.u(12) == 0, rdx=SIDE + d.u(8))


def draw_j(d, index):
    x = d.pick((NICHE, NICHE + 1, 0, 1, d.u64(), M64, d.u64(), d.u64()))
    y = d.pick((NICHE, NICHE + 1, 0, 5, d.u64(), d.u(100)))
    niche = x in (NICHE, NICHE + 1)
    len1 = d.u64() if niche and d.u(2) else d.pick((0, 1, 5, 0x30, d.u(0x31), d.u(0x31)))
    len2 = d.u64() if (x == NICHE + 1 or y == NICHE) and d.u(2) else d.pick((0, 1, 7, 0x30, d.u(0x31), d.u(0x31)))
    return Case(G_J, "j-%d" % index, x=x, y=y, len1=len1, len2=len2, byte=d.u(256), elems=d.data(0x40), elems2=d.data(0x40), tail=d.data(17),
                rec=rec_for(d, d.u(2) == 0), alloc_fail=d.u(10) == 0, fail_second=d.u(10) == 0, rdx=SIDE + d.u(8))


def named_cases(k):
    ok, bad = record(SUCCESS, bytes(0x6E)), record(0x91, bytes(range(0x6E)))
    lim_b, lim_c, lim_d = k["limit_amount-wrap"], k["limit_slot-wrap"], k["limit_transfer-log"]
    out = [
        Case(G_A, "a-denied", flag=0, state=3, limit=10, idx=1, rec=ok),
        Case(G_A, "a-flag-set-passes", flag=1, state=3, limit=10, idx=1, rec=ok),
        Case(G_A, "a-state-2-passes", flag=0, state=2, limit=10, idx=1, rec=ok),
        Case(G_A, "a-index-equal-limit", flag=1, state=0, limit=10, idx=10, rec=ok),
        Case(G_A, "a-index-below-limit", flag=1, state=0, limit=10, idx=9, rec=ok),
        Case(G_A, "a-error-copied", flag=1, state=0, limit=10, idx=9, rec=bad),
        Case(G_B, "b-bound-1", n=lim_b - 1, rec=ok), Case(G_B, "b-bound", n=lim_b, rec=ok), Case(G_B, "b-bound+1", n=lim_b + 1, rec=ok),
        Case(G_B, "b-error", n=5, rec=bad),
        Case(G_C, "c-first-error", n=5, u32=3, rec=bad, rec2=ok), Case(G_C, "c-bound", n=lim_c, u32=3, rec=ok, rec2=bad),
        Case(G_C, "c-bound-1", n=lim_c - 1, u32=3, rec=ok, rec2=bad), Case(G_C, "c-both-ok", n=1, u32=3, rec=ok, rec2=ok),
        Case(G_D, "d-bound", n=lim_d, rec=record(SUCCESS, bytes([1]) + bytes(0x6D))),
        Case(G_D, "d-logged", n=1234567, n2=77, addr=bytes(range(20)), stamp=5, word=6, clock=10 ** 18,
             rec=record(SUCCESS, bytes([1]) + bytes(range(0x6D)))),
        Case(G_D, "d-not-logged", n=1, rec=record(SUCCESS, bytes([0]) + bytes(0x6D))),
        Case(G_D, "d-error", n=1, rec=record(0x98, bytes([1]) + bytes(range(0x6D)))),
        Case(G_D, "d-unwrap-err", n=1, unwrap_err=True, rec=record(SUCCESS, bytes([1]) + bytes(0x6D))),
        Case(G_D, "d-alloc-fail", n=1, alloc_fail=True, rec=record(SUCCESS, bytes([1]) + bytes(0x6D))),
        Case(G_F, "f-ok", rec=record(SUCCESS, bytes(range(1, 0x6F)))), Case(G_F, "f-error", rec=bad),
        Case(G_G, "g-ok", req=bytes(range(0x58)), rec=ok), Case(G_G, "g-error", req=bytes(range(0x58)), rec=bad),
        Case(G_H, "h-ok", key=bytes(range(20)), rec=ok), Case(G_H, "h-error", key=bytes(range(20)), rec=bad),
        Case(G_I, "i-empty", count=0, byte=5, rec=ok), Case(G_I, "i-three", count=3, byte=7, elems=bytes(range(48)), rec=ok),
        Case(G_I, "i-error", count=1, byte=7, elems=bytes(range(16)), rec=bad),
        Case(G_I, "i-wrap-to-zero", count=1 << 60, rec=ok), Case(G_I, "i-over-limit", count=1 << 59, rec=ok),
        Case(G_I, "i-at-limit", count=(1 << 59) - 1, rec=ok, alloc_fail=True),
        Case(G_I, "i-alloc-fail", count=2, elems=bytes(range(32)), rec=ok, alloc_fail=True),
        Case(G_J, "j-both", x=5, y=6, len1=4, len2=3, byte=9, elems=bytes(range(0x40)), elems2=bytes(range(100, 0x40 + 100)), tail=bytes(range(17)), rec=ok),
        Case(G_J, "j-empty", x=5, y=6, len1=0, len2=0, byte=9, tail=bytes(range(17)), rec=bad),
        Case(G_J, "j-a-niche", x=NICHE, y=6, len1=2, len2=2, elems2=bytes(range(0x40)), tail=bytes(range(17)), rec=ok),
        Case(G_J, "j-all-niche", x=NICHE + 1, y=6, len1=2, len2=2, tail=bytes(range(17)), rec=ok),
        Case(G_J, "j-b-niche", x=5, y=NICHE, len1=2, len2=2, byte=1, elems=bytes(range(0x40)), rec=ok),
        Case(G_J, "j-fail-first", x=5, y=6, len1=2, len2=2, alloc_fail=True, rec=ok),
        Case(G_J, "j-fail-second", x=5, y=6, len1=2, len2=2, fail_second=True, elems=bytes(range(0x40)), rec=ok),
        Case(G_E, "e-off", flag=0, byte=1, obj=9), Case(G_E, "e-two", flag=1, byte=2, obj=9), Case(G_E, "e-set", flag=1, byte=1, obj=9),
    ]
    return out


def draw_stream(count, k):
    for case in named_cases(k):
        yield case
    d = Draw(0x5EED5A17)
    weights = ((G_A, draw_a, False), (G_B, draw_b, True), (G_C, draw_c, True), (G_D, draw_d, True), (G_E, draw_e, False),
               (G_F, draw_f, False), (G_G, draw_g, False), (G_H, draw_h, False), (G_I, draw_i, False), (G_J, draw_j, False))
    for index in range(count):
        sub, fn, needs_k = weights[index % len(weights)]
        yield fn(d, index, k) if needs_k else fn(d, index)


# --- comparison ----------------------------------------------------------------------------------------------------------------------

def digest(outcome, log):
    return hashlib.sha256(repr((outcome, log)).encode()).hexdigest()[:16]


def run_case(harness, case):
    harness.machine.seen = set()
    try:
        got, log = harness.run(case)
    except (Halt, EvidenceError, IndexError, KeyError, ValueError, OverflowError, struct.error) as problem:
        got, log = ("halt", type(problem).__name__ + ":" + str(problem)[:40], b"", b""), []
    return got, log


def outcome_name(outcome):
    kind, text, out, extra = outcome
    if kind != "return":
        return kind
    return "byte0-%#x" % out[0]


def check_stream(harness, cases, k, keep=0, hits=None):
    stats = {"cases": 0, "mismatches": 0, "first_mismatch": None, "kinds": collections.Counter(), "stub_calls": collections.Counter()}
    caught = {(sub, name): [0, None] for sub in SUBJECTS for name in VARIANTS[sub]}
    rows = []
    for index, case in enumerate(cases):
        got, log = run_case(harness, case)
        spec = SPECS[case.subject]
        expected = spec(case, k)
        stats["cases"] += 1
        stats["kinds"][(NAMES[case.subject], outcome_name(expected[0]))] += 1
        for entry in expected[1]:
            stats["stub_calls"][(NAMES[case.subject], entry[0])] += 1
        if (got, log) != expected:
            stats["mismatches"] += 1
            if stats["first_mismatch"] is None:
                stats["first_mismatch"] = (index, case.name, str(got)[:120], str(expected[0])[:120])
        for name in VARIANTS[case.subject]:
            if spec(case, k, frozenset((name,))) != (got, log):
                caught[(case.subject, name)][0] += 1
                if caught[(case.subject, name)][1] is None:
                    caught[(case.subject, name)][1] = index
        if hits is not None:
            hits.update(harness.machine.seen)
        if keep and index % keep == 0:
            rows.append((index, case.name, NAMES[case.subject], outcome_name(expected[0]), len(log), digest(got, log)))
    return stats, caught, rows


# --- byte level controls -----------------------------------------------------------------------------------------------------------

def mutants_of(image, reached):
    out = []
    for entry in SUBJECTS:
        start, end = image.exact_fde(entry)
        for row in decode_range(image, start, end):
            if row.va not in reached:
                continue
            data = row.data
            if row.op == "jcc":
                at = 0 if 0x70 <= data[0] <= 0x7F else 1
                out.append((row.va, "condition", row.va + at, data[at], data[at] ^ 1))
                continue
            if row.imm_at is not None and row.imm_size in (1, 4) and row.op not in ("call", "jmp"):
                out.append((row.va, "immediate", row.va + row.imm_at, data[row.imm_at], data[row.imm_at] ^ 1))
            for operand in (row.a, row.b):
                if operand and operand[0] == "m" and operand[1] is not None and 0x8 <= abs(operand[4]) < 0x5000:
                    disp = operand[4]
                    packed = struct.pack("<i", disp) if abs(disp) >= 128 else struct.pack("<b", disp)
                    spot = bytes(data).find(packed)
                    if spot >= 0 and bytes(data).count(packed) == 1:
                        out.append((row.va, "displacement", row.va + spot, data[spot], data[spot] ^ 8))
    return out


def owner_of(image, va):
    return image.starts[bisect.bisect_right(image.starts, va) - 1]


def run_mutants(image, mutants, cases, k):
    rows = []
    by_subject = collections.defaultdict(list)
    for case in cases:
        by_subject[case.subject].append((case, SPECS[case.subject](case, k)))
    for va, kind, at, old, new in mutants:
        harness = Harness(image, {at: new})
        harness.machine.step_limit = MUTANT_STEP_LIMIT
        killed, first = False, ""
        for index, (case, want) in enumerate(by_subject[owner_of(image, va)]):
            if run_case(harness, case) != want:
                killed, first = True, "%d" % index
                break
        rows.append((va, kind, at, old, new, killed, first))
    return rows


def structural_controls(image, k, cases):
    out = []

    def raises(name, thunk, *errors):
        try:
            thunk()
        except errors or (EvidenceError,) as problem:
            out.append((name, True, type(problem).__name__))
            return
        out.append((name, False, "no error"))

    pick = {sub: [c for c in cases if c.subject == sub] for sub in SUBJECTS}
    raises("wrong image digest", lambda: load_image(BINARY, "0" * 64), EvidenceError)
    raises("mid-function address is not an FDE start", lambda: image.exact_fde(G_D + 1), EvidenceError)
    raises("address in a NOBITS section has no file bytes", lambda: image.offset(image.named[".bss"]["address"] + 8), EvidenceError)
    raises("decoder refuses a window that ends inside the body", lambda: decode_range(image, G_D, image.exact_fde(G_D)[1] - 1), EvidenceError)
    raises("truncated section table", lambda: Image(bytes(image.blob[:48])), Exception)
    for sub, hook_kind, key in ((G_A, "calls", CALL_A), (G_B, "calls", CALL_B), (G_C, "calls", CALL_C2), (G_E, "calls", CALL_E1), (G_F, "calls", CALL_F),
                                    (G_G, "calls", CALL_G), (G_H, "calls", CALL_H), (G_I, "calls", CALL_I), (G_J, "calls", CALL_J)):
        loose = Harness(image)
        del loose.machine.calls[key]
        wanted = {G_A: "lookup", G_B: "amount", G_C: "second", G_E: "enter", G_F: "widen", G_G: "forward", G_H: "key", G_I: "list", G_J: "pair"}[sub]
        probe = next(c for c in pick[sub] if any(e[0] == wanted for e in SPECS[sub](c, k)[1]))
        raises("callee %#x of %s removed" % (key, NAMES[sub]), lambda: loose.run(probe), Halt)
    for slot in (SLOT_C1, SLOT_D_CHECK, SLOT_D_RECORD, SLOT_ALLOC):
        loose = Harness(image)
        del loose.machine.slots[MARK_BASE + slot]
        sub = G_C if slot == SLOT_C1 else G_D
        probe = next(c for c in pick[sub] if c.name in ("c-both-ok", "d-logged"))
        raises("slot %#x (%s) removed" % (slot, SLOT_NAMES[slot]), lambda: loose.run(probe), Halt)
    trapped = Harness(image, {G_D: 0xCC})
    raises("entry byte of the logger replaced by int3", lambda: trapped.run(pick[G_D][0]), Halt)

    def tampered(name, role, value, sub):
        changed = dict(k, **{role: value})
        hit = any(run_case(machine_for(image), c) != SPECS[sub](c, changed) for c in pick[sub][:400])
        out.append((name, hit, "mismatch"))

    shared = {}

    def machine_for(img):
        if "h" not in shared:
            shared["h"] = Harness(img)
        return shared["h"]

    tampered("tampered amount bound", "limit_amount-wrap", k["limit_amount-wrap"] + 1, G_B)
    tampered("tampered slot-wrap bound", "limit_slot-wrap", k["limit_slot-wrap"] - 1, G_C)
    tampered("tampered logger bound", "limit_transfer-log", k["limit_transfer-log"] ^ 2, G_D)
    tampered("tampered logger divisor", "divisor", k["divisor"] * 10, G_D)
    tampered("tampered panic text", "panic_text", k["panic_text"] + "!", G_D)
    return out


# --- evidence tables -----------------------------------------------------------------------------------------------------------------

def call_site_rows(image):
    rows = []
    for entry in SUBJECTS:
        for row in decode_range(image, *image.exact_fde(entry)):
            if row.op == "call":
                rows.append((NAMES[entry], "%#x" % entry, "%#x" % row.va, "direct", "%#x" % row.target,
                             "stub" if row.target in (CALL_A, CALL_B, CALL_C2, DROP_D, CALL_E1, CALL_E2, CALL_F, CALL_G, CALL_H, CALL_I, CALL_J) else "unmodelled-cold"))
            elif row.op == "calli" and row.a[0] == "m" and row.a[1] is None:
                rows.append((NAMES[entry], "%#x" % entry, "%#x" % row.va, "slot", "%#x" % row.a[4], SLOT_NAMES.get(row.a[4], "cold-path")))
            elif row.op == "calli" and row.a[0] == "m" and row.a[1] == 15 - 0:
                rows.append((NAMES[entry], "%#x" % entry, "%#x" % row.va, "register", "-", "?"))
    return rows


def function_rows(image, hits):
    rows = []
    for entry in SUBJECTS:
        for row in decode_range(image, *image.exact_fde(entry)):
            rows.append((NAMES[entry], "%#x" % row.va, row.size, row.op, hits.get(row.va, 0)))
    return rows


def decoded_rows(image):
    rows = []
    for entry in SUBJECTS:
        for row in decode_range(image, *image.exact_fde(entry)):
            rows.append((NAMES[entry], "%#x" % row.va, row.size, row.data.hex(), row.op, row.width, "" if row.target is None else "%#x" % row.target,
                         "" if row.a is None else ":".join(str(part) for part in row.a), "" if row.b is None else ":".join(str(part) for part in row.b)))
    return rows


def field_rows(image):
    """Every displacement used with a pointer register by each subject, with the access widths."""
    names = {RDI: "rdi", RSI: "rsi", RDX: "rdx", RCX: "rcx", RBX: "rbx", RSP: "rsp", RBP: "rbp", R8: "r8", R9: "r9", R12: "r12", R13: "r13",
             R14: "r14", R15: "r15", RAX: "rax"}
    rows = []
    for entry in SUBJECTS:
        seen = collections.defaultdict(set)
        for row in decode_range(image, *image.exact_fde(entry)):
            for operand in (row.a, row.b):
                if operand and operand[0] == "m" and operand[1] is not None and operand[2] is None:
                    seen[(names.get(operand[1], str(operand[1])), operand[4])].add("%s/%d" % (row.op, row.width))
        for (base, disp), kinds in sorted(seen.items(), key=lambda item: (item[0][0], item[0][1])):
            rows.append((NAMES[entry], base, "%#x" % disp if disp >= 0 else "-%#x" % -disp, ";".join(sorted(kinds))))
    return rows


def direct_callers(image):
    rows = []
    start_text, text = image.text_bytes()
    wanted = set(SUBJECTS)
    for match in re.finditer(b"[\xe8\xe9]", text):
        at = match.start()
        if at + 5 > len(text):
            continue
        target = start_text + at + 5 + struct.unpack_from("<i", text, at + 1)[0]
        if target in wanted:
            rows.append(("%#x" % target, "%#x" % (start_text + at), "call" if text[at] == 0xE8 else "jmp", "%#x" % owner_of(image, start_text + at)))
    return sorted(rows)


def constant_rows(image, k):
    rows = [("%#x" % va, "bound of " + NAMES[s], "movabs imm64", "%#x" % k["limit_%s" % NAMES[s]]) for s, va in sorted(LIMIT_AT.items())]
    rows.append(("%#x" % DIV_CONST, "divisor of both f64 conversions", "f64", repr(k["divisor"])))
    rows.append(("%#x" % PANIC_TEXT_AT, "panic text (%d bytes)" % PANIC_TEXT_LEN, "utf-8", k["panic_text"]))
    relative = image.relative()
    for slot, role in ((UNWRAP_LOCATION, "Location of the unwrap in transfer-log"), (LOCATION_H, "Location passed by key-forward")):
        path, line, column = image.location(slot, relative)
        rows.append(("%#x" % slot, role, "Location", "%s:%d:%d" % (path, line, column)))
    for name, off in (("gate-a flag byte", 0x4349), ("gate-a state byte (3 = denied)", 0x170A), ("index limit", 0xB8)):
        rows.append(("ctx+%#x" % off, name, "-", "-"))
    return rows


def analyse(count=30000, mutate=True, mutant_cases=200):
    image = load_image()
    k = constant_values(image)
    harness = Harness(image)
    named = named_cases(k)
    cases = list(draw_stream(count, k))
    reached = collections.Counter()
    stats, caught, sample = check_stream(harness, cases, k, keep=max(1, count // 1200), hits=reached)
    result = {"image": image, "k": k, "stats": stats, "caught": caught, "sample": sample, "reached": reached, "cases": len(cases)}
    result["structural"] = structural_controls(image, k, cases)
    result["mutants"] = []
    if mutate:
        step = max(1, count // (mutant_cases * 5))
        while math.gcd(step, len(SUBJECTS)) != 1:
            step += 1                      # a step sharing a factor with the subject count would keep only some subjects (the draw cycles)
        picked = cases[:len(named)] + cases[len(named)::step]
        result["mutants"] = run_mutants(image, mutants_of(image, reached), picked, k)
    return result


EQUIVALENT_REASONS = {
    0x520845B: "dead store: the 0xc0(%rsp) copy of the payload is written and never read again (the later loads use 0x37/0x3f/0x47(%rsp))",
    0x534BD91: "dead store: the 0x90(%rsp) copy of the payload is written and never read again (the later loads use 0x7/0xf/0x17(%rsp))",
    0x534BD99: "dead store: the 0xa0(%rsp) copy of the payload tail is written and never read again",
    0x532FC8A: "stack address of the guard temporary; both guard calls use the same register copy, so the shifted address is not observable",
}


def render(result):
    image, k, stats = result["image"], result["k"], result["stats"]
    files = {}

    def tsv(name, header, rows):
        files[name] = "\n".join(["\t".join(header)] + ["\t".join(str(x) for x in row) for row in rows]) + "\n"

    tsv("constants.tsv", ("address", "role", "kind", "value"), constant_rows(image, k))
    tsv("call-sites.tsv", ("subject", "entry", "site", "kind", "target", "role"), call_site_rows(image))
    tsv("decoded.tsv", ("subject", "address", "size", "bytes", "op", "width", "target", "operand_a", "operand_b"), decoded_rows(image))
    tsv("fields.tsv", ("subject", "base", "displacement", "accesses"), field_rows(image))
    tsv("direct-callers.tsv", ("target", "site", "kind", "owner"), direct_callers(image))
    tsv("function-rows.tsv", ("subject", "address", "size", "op", "cases_reaching"), function_rows(image, result["reached"]))
    tsv("outcomes.tsv", ("subject", "outcome", "cases"), [(s, o, n) for (s, o), n in sorted(stats["kinds"].items())])
    tsv("stub-calls.tsv", ("subject", "stub", "calls_in_rule_list"), [(s, t, n) for (s, t), n in sorted(stats["stub_calls"].items())])
    tsv("cases-sample.tsv", ("index", "name", "subject", "outcome", "stub_calls", "digest"), result["sample"])
    tsv("variants.tsv", ("subject", "deviation", "cases_refused", "first_refusing_case"),
        [(NAMES[s], name, n, "" if first is None else first) for (s, name), (n, first) in sorted(result["caught"].items())])
    tsv("structural-controls.tsv", ("control", "detected", "how"), [(n, int(d), h) for n, d, h in result["structural"]])
    tsv("mutants.tsv", ("address", "kind", "edited_byte_at", "old", "new", "killed", "first_case"),
        [("%#x" % va, kind, "%#x" % at, old, new, int(killed), first) for va, kind, at, old, new, killed, first in result["mutants"]])
    equivalent = [("%s edit %#x -> %#x" % (kind, old, new), "%#x" % va, EQUIVALENT_REASONS.get(va, "unreviewed"))
                  for va, kind, at, old, new, killed, _ in result["mutants"] if not killed]
    tsv("equivalent-mutants.tsv", ("mutation", "address", "reason"), equivalent)
    tsv("unreached.tsv", ("address", "op"), [(a, op) for _, a, _, op, n in function_rows(image, result["reached"]) if n == 0])
    controls = len(result["caught"]) + len(result["structural"]) + len(result["mutants"])
    killed = sum(1 for row in result["mutants"] if row[5])
    detected = sum(1 for n, first in result["caught"].values() if n) + sum(1 for _, d, _ in result["structural"] if d) + killed
    evidence = {"binary_sha256": SHA256, "subjects": {NAMES[s]: "%#x" % s for s in SUBJECTS}, "cases": stats["cases"],
                "mismatches": stats["mismatches"], "first_mismatch": stats["first_mismatch"], "instructions_reached": len(result["reached"]),
                "mutants": len(result["mutants"]), "mutants_killed": killed, "mutants_equivalent": len(equivalent)}
    files["evidence.json"] = json.dumps(evidence, indent=1, sort_keys=True, default=str) + "\n"
    files["measure.json"] = json.dumps({"cases": stats["cases"], "negative_controls": controls, "negative_detected": detected,
                                        "equivalent": len(equivalent), "mismatches": stats["mismatches"], "mutants": len(result["mutants"]),
                                        "mutants_killed": killed}, indent=1, sort_keys=True) + "\n"
    return files


def main(argv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument("--out", required=True)
    parser.add_argument("--cases", type=int, default=30000)
    parser.add_argument("--no-mutants", action="store_true")
    args = parser.parse_args(argv)
    result = analyse(args.cases, not args.no_mutants)
    out = pathlib.Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    for name, text in render(result).items():
        (out / name).write_text(text)
    print(render(result)["measure.json"], end="")
    return 0 if result["stats"]["mismatches"] == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
