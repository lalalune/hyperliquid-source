#!/usr/bin/env python3
"""RE-009 node #115 db/owned_db_home.rs: path-row constructor 0x16961b0 and candidate verifier 0x1696870.

Rebuilds the evidence of the work item from the ELF bytes alone. The first part is an offline x86-64 interpreter (decoder, memory, machine) that
only reads the ELF image through the shared parsers; the second part holds the reference model, the case families, the mutation controls and the
evidence writers. The binary is never executed.

    python3 tools/hl_storage_owned_home_path_115.py --out research/work-items/RE-009-owned-db-home-path-scan-115
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
# Node #115 db/owned_db_home.rs: path-row constructor 0x16961b0 and its candidate verifier 0x1696870.
# ---------------------------------------------------------------------------------------------------------------------------------

import argparse
import hashlib
import json
import random

CTOR = 0x16961B0
VERIFY = 0x1696870
VEC_DROP = 0x1696730
ROW_DROP = 0x1696780
STATE_WORD = 0x64F01D8
FUNCTIONS = ((CTOR, "path-row-constructor"), (VEC_DROP, "vec-drop-glue"), (ROW_DROP, "row-drop-glue"), (VERIFY, "candidate-verifier"))
NEEDLE = b"checkpoint"
REST = NEEDLE[1:]
NAME_VA = 0x47B3E2
NAME = b"OwnedDbDir"
REST_VA = 0x47B3D9
LANE_C_VA, LANE_T_VA = 0x4566B0, 0x452340
PANIC_PIECES_VA = 0x447E28
PANIC_FMT_FN = 0x1696190
LOCATION_SLOT = 0x6408BD0
BOX_SIZE = 0x58
SLOTS = {
    0x64DF6B8: ("panic", "panic with a formatted message; wrapper 0x1680e80, never returns"),
    0x64DF480: ("alloc", "allocator entry, one size argument; callee 0x6355830 not decoded here"),
    0x64DF490: ("alloc_error", "allocation-failure diagnostic (align, size); never returns"),
    0x64E11E0: ("fmt", "opaque lock-guarded formatting helper 0x1560e30; its 48-byte result is copied verbatim"),
    0x64DF4A0: ("dealloc", "cleanup only: free(ptr, size, align)"),
    0x64DF4C0: ("cleanup_a", "cleanup only: landing-pad helper"),
    0x64E10A0: ("cleanup_b", "cleanup only: drop helper"),
    0x64DF9F0: ("once", "cleanup only: one-time initialisation call in the drop glue"),
}
# layout of the process image used by the harness (heap-relative addresses)
STRUCT = STACK_TOP - 0x2000
STATE = HEAP_BASE + 0x180
RESTBUF = HEAP_BASE + 0x1C0
PAD = 0x40
HAY = HEAP_BASE + 0x1000 + PAD
ARENA = HEAP_BASE + 0x2800
USED = 0x3000
FILLS = (bytes([0xA5]), b"checkpoint", b"t", b"c")


class World:
    def __init__(self):
        self.events = []
        self.fail_alloc = False
        self.next_box = ARENA
        self.hay = b""


def fmt_bytes(path):
    """Contract of the opaque formatter: 48 bytes derived from the path text."""
    return hashlib.sha256(b"a" + path).digest() + hashlib.sha256(b"b" + path).digest()[:16]


def hook_panic(world):
    def hook(machine):
        regs = machine.regs
        mem = machine.memory
        world.events.append(("panic", regs[RDI], mem.read(regs[RSI], 8), mem.read(regs[RSI] + 8, 8), regs[RDX]))
        raise Panicked("panic")
    return hook


def hook_alloc(world):
    def hook(machine):
        size = machine.regs[RDI]
        world.events.append(("alloc", size))
        if world.fail_alloc:
            machine.regs[RAX] = 0
            return
        machine.regs[RAX] = world.next_box
        world.next_box += 0x60
    return hook


def hook_alloc_error(world):
    def hook(machine):
        world.events.append(("alloc_error", machine.regs[RDI], machine.regs[RSI]))
        raise Panicked("alloc error")
    return hook


def hook_fmt(world):
    def hook(machine):
        regs = machine.regs
        mem = machine.memory
        size = regs[R8]
        path = mem.bytes_at(regs[RCX], size)
        world.events.append(("fmt", regs[RSI], regs[RDX], regs[RCX], size, mem.bytes_at(regs[RSI], regs[RDX])))
        mem.put_bytes(regs[RDI], fmt_bytes(path))
    return hook


def hook_dealloc(world):
    def hook(machine):
        regs = machine.regs
        world.events.append(("dealloc", regs[RDI], regs[RSI], regs[RDX] & 0xFFFFFFFF))
    return hook


def hook_drop_elems(world):
    def hook(machine):
        world.events.append(("drop_elems", machine.regs[RDI]))
    return hook


def hook_once(world):
    def hook(machine):
        regs = machine.regs
        closure = machine.memory.read(regs[RDX], 8)
        cell = machine.memory.read(closure, 8)
        world.events.append(("once", regs[RDI], regs[RSI] & 0xFFFFFFFF, regs[RCX], regs[R8], cell, closure == regs[RDX] - 8))
    return hook


def new_rig(image, patches=None, step_limit=60000):
    machine = Machine(image, patches)
    machine.step_limit = step_limit
    machine.real = frozenset({VERIFY})
    world = World()
    relative = image.relative()
    makers = dict(panic=hook_panic, alloc=hook_alloc, alloc_error=hook_alloc_error, fmt=hook_fmt, dealloc=hook_dealloc, cleanup_b=hook_drop_elems, once=hook_once)
    for slot, (name, _) in SLOTS.items():
        target = relative[slot]
        machine.memory.statics[slot] = target
        if name in makers:
            machine.slots[target] = makers[name](world)
    return machine, world


# ---- reference semantics (written from the reading of the bodies, independent of the interpreter) ----------------------------------

def verify_model(hay, rest, offset, mask, flag):
    """0x1696870: nonzero flag answers false; otherwise any candidate bit i of the 16-bit mask whose hay[offset+i+1:] starts with rest."""
    if flag & 0xFFFFFFFF:
        return 0
    for bit in range(16):
        if mask >> bit & 1 and hay[offset + bit + 1:offset + bit + 1 + len(rest)] == rest:
            return 1
    return 0


def ctor_model(hay, cap, fail_alloc):
    """0x16961b0: a path containing the ten bytes `checkpoint` panics; otherwise a 0x58-byte box {1, 1, string triple, 48 formatter bytes}."""
    if NEEDLE in hay:
        return ("panic", PANIC_PIECES_VA, STRUCT, PANIC_FMT_FN, LOCATION_SLOT)
    events = ["fmt", "alloc"]
    if fail_alloc:
        return ("alloc-error", tuple(events + ["alloc_error"]), 8, BOX_SIZE, (BOX_SIZE,))
    box = struct.pack("<QQQQQ", 1, 1, cap, HAY, len(hay)) + fmt_bytes(hay)
    return ("row", tuple(events), box.hex(), (NAME_VA, len(NAME), HAY, len(hay)), (BOX_SIZE,))


def lane_class(n):
    """Which search loop the byte count selects in 0x16961b0 (from the three compare/branch ladders at 0x16961cc, 0x16961d2, 0x169628d)."""
    if n <= 9:
        return "short-reject"
    if n == 10:
        return "exact-10"
    if n <= 24:
        return "scalar-window"
    if n < 0x4A:
        return "lane-16"
    return "block-64"


# ---- harness runs -----------------------------------------------------------------------------------------------------------------

def place(machine, hay, fill):
    mem = machine.memory
    mem.reset(USED)
    area = len(hay) + 2 * PAD + 64
    pattern = (fill * (area // len(fill) + 1))[:area]
    mem.put_bytes(HAY - PAD, pattern)
    mem.put_bytes(HAY, hay)


def run_ctor(rig, hay, cap, fail_alloc, fill):
    machine, world = rig
    place(machine, hay, fill)
    world.events = []
    world.fail_alloc = fail_alloc
    world.next_box = ARENA
    machine.memory.write(STRUCT, 8, cap)
    machine.memory.write(STRUCT + 8, 8, HAY)
    machine.memory.write(STRUCT + 16, 8, len(hay))
    machine.seen = set()
    try:
        box = machine.run(CTOR, {RDI: STRUCT})
    except Panicked:
        event = world.events[-1]
        if event[0] == "panic":
            return ("panic", event[1], event[2], event[3], event[4]), machine.seen
        return ("alloc-error", tuple(e[0] for e in world.events), event[1], event[2], tuple(e[1] for e in world.events if e[0] == "alloc")), machine.seen
    except Halt as error:
        return ("halt", str(error).split(" at ")[0]), machine.seen
    names = tuple(e[0] for e in world.events)
    fmt = [e for e in world.events if e[0] == "fmt"]
    seen = machine.seen
    if box != ARENA or len(fmt) != 1 or fmt[0][5] != NAME:
        return ("row-bad", hex(box)), seen
    return ("row", names, machine.memory.bytes_at(box, BOX_SIZE).hex(), (fmt[0][1], fmt[0][2], fmt[0][3], fmt[0][4]), tuple(e[1] for e in world.events if e[0] == "alloc")), seen


def run_verify(rig, hay, rest, offset, mask, flag, fill):
    machine, _ = rig
    place(machine, hay, fill)
    mem = machine.memory
    mem.put_bytes(RESTBUF, rest)
    mem.write(STATE, 8, HAY)
    mem.write(STATE + 8, 8, len(hay))
    mem.write(STATE + 16, 8, RESTBUF)
    mem.write(STATE + 24, 8, len(rest))
    machine.seen = set()
    try:
        value = machine.run(VERIFY, {RDI: STATE, RSI: offset, RDX: mask, RCX: flag})
    except (Halt, Panicked) as error:
        return ("halt", str(error).split(" at ")[0]), machine.seen
    return value & 0xFF, machine.seen


# ---- case generation ----------------------------------------------------------------------------------------------------------------

ALPHABET = b"chekpointx/_ct"


def background(rnd, n):
    return bytes(rnd.choice(ALPHABET) for _ in range(n))


def decoy(rnd, text):
    """Insert `c????????t` windows whose middle is a needle with one byte changed, so the pair filter fires and the verifier rejects."""
    data = bytearray(text)
    for _ in range(max(1, len(data) // 24)):
        if len(data) < 10:
            break
        at = rnd.randrange(len(data) - 9)
        window = bytearray(NEEDLE)
        window[rnd.randrange(1, 9)] = rnd.choice(b"xyz")
        data[at:at + 10] = window
    return bytes(data)


def ctor_cases():
    """Yield (kind, hay, cap, fail_alloc) in a fixed order."""
    rnd = random.Random(115)
    for n in range(10, 121):
        for pos in range(n - 9):
            base = bytearray(background(rnd, n))
            base[pos:pos + 10] = NEEDLE
            yield "placement", bytes(base), rnd.getrandbits(40), False
    for n in range(0, 261):
        for variant in range(3):
            text = background(rnd, n)
            if variant:
                text = decoy(rnd, text)
            yield "miss" if NEEDLE not in text else "miss-hit", text, rnd.getrandbits(40), False
    for n in (10, 11, 16, 24, 25, 26, 40, 41, 73, 74, 75, 96, 97, 150):
        for byte in range(10):
            for pos in sorted({0, 1, n - 10, (n - 10) // 2}):
                base = bytearray(b"x" * n)
                base[pos:pos + 10] = NEEDLE
                base[pos + byte] = ord("Z")
                yield "near-miss", bytes(base), rnd.getrandbits(40), False
    for n in (74, 80, 100, 130, 200, 300):
        for pos in (0, 15, 16, 17, 31, 32, 33, 47, 48, 49, 63, 64, 65, 79, 80, 81, 127, 128, 129, 143, 144, 145):
            if pos + 10 <= n:
                base = bytearray(b"x" * n)
                base[pos:pos + 10] = NEEDLE
                yield "boundary", bytes(base), rnd.getrandbits(40), False
    for n in range(9, 151):
        tail = bytearray(background(rnd, n))
        tail[n - 9:] = NEEDLE[:9]
        yield "truncated-tail", bytes(tail), rnd.getrandbits(40), False
        head = bytearray(background(rnd, n))
        head[:9] = NEEDLE[1:]
        yield "truncated-head", bytes(head), rnd.getrandbits(40), False
    for text in REAL_PATHS:
        yield "path", text, rnd.getrandbits(40), False
    for _ in range(300):
        n = rnd.randrange(260, 1400)
        text = bytearray(background(rnd, n))
        if rnd.random() < 0.6:
            at = rnd.randrange(n - 9)
            text[at:at + 10] = NEEDLE
        yield "long", bytes(text), rnd.getrandbits(40), False
    for index in range(200):
        n = rnd.randrange(0, 200)
        text = bytes(rnd.choice(b"abdfgjlmqrsuvwyz/") for _ in range(n))
        yield "alloc-fail", text, rnd.getrandbits(40), index % 4 != 0


ALWAYS = ("boundary", "truncated-tail", "truncated-head", "path")
REAL_PATHS = tuple(p.encode() for p in (
    "", "a", "db", "db_home", "db_hub", "/hyperliquid_data/db_hub", "/hyperliquid_data/db_hub/checkpoint", "checkpoint", "checkpoints",
    "xcheckpoint", "checkpointx", "Checkpoint", "CHECKPOINT", "checkpoin", "heckpoint", "check point", "check_point", "chekpoint",
    "/x/y/db_home/checkpoint/abci", "/x/y/db_home/abci_state", "/x/y/db_home/checkpoint", "checkpointcheckpoint", "ccheckpoint",
    "checkpoincheckpoint", "cheCKpoint", "/x/y/checkpoint_old", "/x/y/chec/kpoint", "db_bundle", "Exchange", "Rpc", "EvmState",
    "/hyperliquid_data/db_hub/Exchange", "/hyperliquid_data/db_hub/Rpc", "/hyperliquid_data/db_hub/EvmState",
    "../z/checkpoint/..", "/x/y/" + "n" * 60 + "checkpoint", "/x/y/" + "n" * 60 + "checkpoin", "p" * 73, "p" * 74, "p" * 75,
    "c" * 40, "t" * 40, "ct" * 40, "c" + "x" * 8 + "t", "c" + "heckpoin" + "t" * 20))


def verify_cases():
    rnd = random.Random(1696870)
    for _ in range(3200):
        k = rnd.choice((9, 9, 9, 9, 9, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 10, 11, 12, 13))
        rest = REST[:k] if k <= 9 and rnd.random() < 0.5 else bytes(rnd.choice(ALPHABET) for _ in range(k))
        n = rnd.randrange(24, 80)
        hay = bytearray(background(rnd, n))
        offset = rnd.randrange(0, n - 20)
        mask = 0
        for _ in range(rnd.randrange(1, 5)):
            mask |= 1 << rnd.randrange(16)
        for bit in range(16):
            if mask >> bit & 1 and rnd.random() < 0.5:
                start = offset + bit + 1
                hay[start:start + k] = rest
                if k and rnd.random() < 0.4:
                    hay[start + rnd.randrange(k)] ^= 1
        flag = rnd.choice((0, 0, 0, 0, 1, 2, 0x100, 0xFFFFFFFF))
        yield bytes(hay), rest, offset, mask, flag


def solid_mask_cases():
    """Every single-bit mask against a haystack that matches at exactly that bit."""
    rnd = random.Random(7)
    for bit in range(16):
        for k in (0, 1, 3, 4, 5, 9, 12):
            hay = bytearray(b"q" * 48)
            rest = bytes(rnd.choice(b"abc") for _ in range(k))
            hay[3 + bit + 1:3 + bit + 1 + k] = rest
            yield bytes(hay), rest, 3, 1 << bit, 0
            yield bytes(hay), rest, 3, 0xFFFF, 0
            yield bytes(hay), rest, 3, 0xFFFF ^ (1 << bit), 0
            for other in range(16):
                if other != bit and k:
                    yield bytes(hay), rest, 3, 1 << other, 0


def glue_cases():
    """Box words {strong, weak, path cap/ptr/len, payload cap/ptr/len, three more} dropped by 0x1696780 and vector triples dropped by 0x1696730."""
    rnd = random.Random(1696780)

    def word():
        return rnd.choice((0, 0, rnd.getrandbits(40) | 1, rnd.getrandbits(63)))

    for _ in range(1500):
        words = [1, 1] + [word() for _ in range(9)]
        yield "row", words, rnd.choice((0, 0, 0, 1, 2, 0x100, 0xFFFFFFFF))
    for _ in range(500):
        yield "vec", [word() for _ in range(3)] + [word() for _ in range(8)], 0


def glue_model(which, words, state):
    events = []
    if which == "vec":
        events.append(("drop_elems", BOXA))
        if words[0]:
            events.append(("dealloc", words[1], words[0], 0))
        return tuple(events)
    if state:
        events.append(("once", STATE_WORD, 1, 0x63FE250, 0x63FE278, STATE_WORD - 0x18, True))
    if words[2]:
        events.append(("dealloc", words[3], words[2], 0))
    events.append(("drop_elems", BOXA + 0x28))
    if words[5]:
        events.append(("dealloc", words[6], words[5], 0))
    return tuple(events)


BOXA = HEAP_BASE + 0x400


def run_glue(rig, which, words, state):
    machine, world = rig
    machine.memory.reset(USED)
    machine.memory.put_bytes(BOXA, struct.pack("<%dQ" % len(words), *words))
    machine.memory.statics[STATE_WORD] = state
    world.events = []
    machine.seen = set()
    try:
        machine.run(VEC_DROP if which == "vec" else ROW_DROP, {RDI: BOXA})
    except (Halt, Panicked) as error:
        return ("halt", str(error).split(" at ")[0]), machine.seen
    return tuple(world.events), machine.seen


def check_glue(rig, case):
    which, words, state = case
    got, _ = run_glue(rig, which, words, state)
    want = glue_model(which, words, state)
    return "" if got == want else "glue-mismatch got=%s want=%s" % (str(got)[:60], str(want)[:60])


def pipeline_cases(rig, ctor_list):
    """Boxes produced by the constructor, dropped by the row glue: the payload words are whatever the opaque formatter wrote."""
    for kind, hay, cap, fail in ctor_list:
        if kind == "miss" and len(hay) % 5 == 0 and not fail:
            got, _ = run_ctor(rig, hay, cap, False, FILLS[0])
            if got[0] == "row":
                yield "row", list(struct.unpack("<11Q", bytes.fromhex(got[2]))), len(hay) % 3


# ---- comparisons --------------------------------------------------------------------------------------------------------------------

def check_ctor(rig, hay, cap, fail_alloc):
    """Compare both fills against the model; returns (error text or empty, union of executed instructions)."""
    want = ctor_model(hay, cap, fail_alloc)
    seen = set()
    for fill in FILLS:
        got, executed = run_ctor(rig, hay, cap, fail_alloc, fill)
        seen |= executed
        if got != want:
            return "ctor-mismatch len=%d fill=%d got=%s want=%s" % (len(hay), FILLS.index(fill), str(got)[:60], str(want)[:60]), seen
    return "", seen


def check_verify(rig, case):
    hay, rest, offset, mask, flag = case
    want = verify_model(hay, rest, offset, mask, flag)
    for fill in FILLS:
        got, _ = run_verify(rig, hay, rest, offset, mask, flag, fill)
        if got != want:
            return "verify-mismatch got=%s want=%s" % (got, want)
    return ""


def pick(entries, limit=200):
    """All boundary cases first, then an even spread of the rest, in a fixed order."""
    first = [e for e in entries if e[0] == "b"]
    rest = [e for e in entries if e[0] != "b"]
    if len(rest) > limit:
        rest = [rest[i * len(rest) // limit] for i in range(limit)]
    return first + rest


def detect(image, patch, entries, ctor_list, verify_list, glue_list=()):
    rig = new_rig(image, {patch[0] + patch[1]: patch[2]}, step_limit=12000)
    for number, (kind, index) in enumerate(entries):
        try:
            if kind == "v":
                error = check_verify(rig, verify_list[index])
            elif kind == "g":
                error = check_glue(rig, glue_list[index])
            else:
                case = ctor_list[index]
                error, _ = check_ctor(rig, case[1], case[2], case[3])
        except Exception:  # noqa: BLE001 - any interpreter failure on mutated bytes is a detection
            return True, "crash", number
        if error:
            return True, error.split(" ")[0], number
    return False, "", -1


# ---- evidence ---------------------------------------------------------------------------------------------------------------------

def function_rows(image, start):
    return decode_range(image, start, image.exact_fde(start)[1])


def mutant_list(image):
    """Single-byte mutations of both bodies: condition flips, retargets to the next instruction boundary, immediates and displacements."""
    found = []
    for start, name in FUNCTIONS:
        body = function_rows(image, start)
        starts = [r.va for r in body]
        for index, row in enumerate(body):
            raw = row.data
            if row.op == "jcc":
                at = 0 if raw[0] != 0x0F else 1
                found.append((row.va, at, raw[at] ^ 1, "condition-flip", name, row.va))
            if row.op in ("jmp", "jcc") and row.imm_at is not None:
                later = [v for v in starts if v > row.target]
                rel = int.from_bytes(raw[row.imm_at:row.imm_at + row.imm_size], "little", signed=True)
                if later and later[0] - row.next >> 8 == rel >> 8:
                    found.append((row.va, row.imm_at, (later[0] - row.next) & 0xFF, "branch-retarget", name, row.va))
            elif row.imm_at is not None and row.op not in ("push", "pop", "call"):
                found.append((row.va, row.imm_at, raw[row.imm_at] ^ 1, "immediate-low-byte", name, row.va))
            elif row.op in ("mov", "lea", "add", "cmp", "movx", "movzx", "movdqu", "pcmpeqb"):
                for operand in (row.a, row.b):
                    if isinstance(operand, tuple) and operand and operand[0] == "m" and operand[1] is not None and 0x08 <= abs(operand[4]) < 0x7F:
                        spots = [i for i, v in enumerate(raw) if v == operand[4] & 0xFF]
                        if len(spots) == 1 and spots[0] != row.imm_at:
                            found.append((row.va, spots[0], raw[spots[0]] ^ 1, "displacement-low-byte", name, row.va))
                            break
    return found


def rip_target(row):
    if row.rip_at is None:
        return None
    disp = struct.unpack_from("<i", row.data, row.rip_at)[0]
    return row.next + disp


def region(va):
    """Coarse label of a code address in the four bodies (derived from the control-flow reading in the README)."""
    if va < CTOR + 1401:
        for low, high, label in REGIONS:
            if low <= va < high:
                return label
    if va < ROW_DROP:
        return "landing-pad" if va >= 0x1696760 else "vec-drop"
    if va < VERIFY:
        if va >= 0x169681C:
            return "landing-pad"
        return "row-drop-once" if va >= 0x16967DF else "row-drop"
    return "verifier-compare-loop" if va < 0x16968F0 else "verifier-short-needle-tail"


REGIONS = (
    (0x16961B0, 0x16961CC, "prologue"),
    (0x16961CC, 0x169623F, "length-dispatch-and-exact10"),
    (0x169623F, 0x169626E, "panic-route"),
    (0x169626E, 0x16962A5, "long-input-setup"),
    (0x16962A5, 0x1696356, "lane-16-loop"),
    (0x1696356, 0x1696478, "row-build"),
    (0x1696478, 0x16966BE, "block-64-loop"),
    (0x16966BE, 0x16966E3, "lane-tail"),
    (0x16966E3, 0x16966F5, "alloc-error"),
    (0x16966F5, 0x1696729, "landing-pad"),
)


def write_tsv(path, header, rows):
    with open(path, "w") as handle:
        handle.write("\t".join(header) + "\n")
        for row in rows:
            handle.write("\t".join(str(v) for v in row) + "\n")


BOUNDARY = "the 16-byte scalar-window loop and the 16-lane loop are both exact searches, so moving the length cut-over by one byte selects the other correct loop"
EXTRA_BLOCK = "moves a lane-loop guard by one byte: the loop runs one more in-bounds block, and the result is an any-match over blocks that the final unaligned window also covers"
FOUND = "taken only with a match already recorded (flag byte nonzero); the skipped instruction can only contribute to an any-match that is already true, and the verifier answers false for flagged calls"
EQUIVALENT_SITES = {
    0x16961D2: BOUNDARY, 0x169628D: BOUNDARY,
    0x1696269: "jump after the panic call, which never returns",
    0x169652D: EXTRA_BLOCK, 0x16966A9: EXTRA_BLOCK,
    0x1696273: "writes the haystack length into field +8 of the verifier state, which 0x1696870 never reads (the shifted store is overwritten by the next field store)",
    0x1696284: "needle-tail length 8 instead of 9: the dropped last byte `t` was already required at lane offset 9 by the pair filter before every verifier call",
    0x16966A4: "the next block start is consumed only after a match is recorded (flag byte nonzero), when every later step ends in the panic route",
    0x16962A8: FOUND, 0x16962F5: FOUND, 0x1696549: FOUND,
    0x169629C: EXTRA_BLOCK, 0x16962E3: EXTRA_BLOCK, 0x1696316: EXTRA_BLOCK,
}


def equivalent_reason(patch, rows_by_va):
    va, name = patch[0], patch[4]
    where = region(va)
    if where == "landing-pad":
        return "cleanup landing pad: entered only when a callee unwinds, and no callee in this model unwinds"
    if va in EQUIVALENT_SITES:
        return EQUIVALENT_SITES[va]
    if where == "verifier-short-needle-tail" and name == "candidate-verifier":
        return "short-needle tail: reached only for needles shorter than four bytes"
    return "unclassified"


def main(argv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument("--out", required=True)
    args = parser.parse_args(argv)
    out = pathlib.Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    image = load_image()
    relative = image.relative()
    rows = {start: function_rows(image, start) for start, _ in FUNCTIONS}
    # --- functions, bodies, instructions, branches, references
    func_lines, body_lines, insn_lines, branch_lines, ref_lines = [], [], [], [], []
    for start, name in FUNCTIONS:
        end = image.exact_fde(start)[1]
        raw = bytes(image.blob[image.offset(start):image.offset(start) + end - start])
        func_lines.append((hex(start), hex(end), end - start, len(rows[start]), hashlib.sha256(raw).hexdigest(), name))
        for at in range(0, len(raw), 16):
            body_lines.append((hex(start + at), raw[at:at + 16].hex()))
        for row in rows[start]:
            insn_lines.append((hex(row.va), row.size, row.op, row.data.hex(), region(row.va)))
            if row.op in ("jcc", "jmp", "call"):
                kind = row.op if row.op != "jcc" else "jcc-" + str(row.cc)
                branch_lines.append((hex(row.va), kind, hex(row.target), region(row.target) if CTOR <= row.target < CTOR + 1401 + 241 + 0x200 else "outside"))
            target = rip_target(row)
            if target is not None:
                try:
                    at = image.offset(target)
                    data = bytes(image.blob[at:at + 16]).hex()
                except EvidenceError:
                    data = "unmapped"
                ref_lines.append((hex(row.va), row.op, hex(target), SLOTS.get(target, ("", ""))[0], data))
    write_tsv(out / "functions.tsv", ("start", "end", "bytes", "instructions", "sha256", "role"), func_lines)
    write_tsv(out / "bodies.tsv", ("va", "hex16"), body_lines)
    write_tsv(out / "instructions.tsv", ("va", "size", "op", "bytes", "region"), insn_lines)
    write_tsv(out / "branches.tsv", ("va", "kind", "target", "target_region"), branch_lines)
    write_tsv(out / "references.tsv", ("va", "op", "target", "slot_role", "bytes_at_target"), ref_lines)
    write_tsv(out / "relocations.tsv", ("slot", "relative_addend", "role", "meaning"),
              [(hex(slot), hex(relative[slot]), name, text) for slot, (name, text) in sorted(SLOTS.items())])
    # --- constants read from the ELF
    consts = dict(
        needle_rest=bytes(image.blob[image.offset(REST_VA):image.offset(REST_VA) + 9]).decode(),
        type_name=bytes(image.blob[image.offset(NAME_VA):image.offset(NAME_VA) + 10]).decode(),
        lane_c=bytes(image.blob[image.offset(LANE_C_VA):image.offset(LANE_C_VA) + 16]).decode(),
        lane_t=bytes(image.blob[image.offset(LANE_T_VA):image.offset(LANE_T_VA) + 16]).decode(),
    )
    piece_len = image.blob[image.offset(PANIC_PIECES_VA)]
    piece = bytes(image.blob[image.offset(PANIC_PIECES_VA) + 1:image.offset(PANIC_PIECES_VA) + 1 + piece_len]).decode()
    after = bytes(image.blob[image.offset(PANIC_PIECES_VA) + 1 + piece_len:image.offset(PANIC_PIECES_VA) + 3 + piece_len]).hex()
    path, line, column = image.location(LOCATION_SLOT, relative)
    consts.update(panic_piece=piece, panic_piece_length_byte=piece_len, panic_after_piece=after, location_file=path, location_line=line, location_column=column)
    # --- cases
    rig = new_rig(image)
    seen = set()
    families = {}
    total = 0
    profile = []
    sample = []
    failures = []
    ctor_list = list(ctor_cases())
    verify_list = list(verify_cases()) + list(solid_mask_cases())
    covers = {}
    for number, (kind, hay, cap, fail) in enumerate(ctor_list):
        error, executed = check_ctor(rig, hay, cap, fail)
        seen |= executed
        for pc in executed:
            covers.setdefault(pc, []).append(("b" if kind in ALWAYS else "c", number))
        total += 1
        got_route = ctor_model(hay, cap, fail)[0]
        families[(kind, got_route)] = families.get((kind, got_route), 0) + 1
        if error:
            failures.append(error)
        if number % 3 == 0 and len(sample) < 1800:
            sample.append((number, kind, len(hay), lane_class(len(hay)), got_route, hay[:24].hex(), hashlib.sha256(hay).hexdigest()[:16]))
    for number, case in enumerate(verify_list):
        error = check_verify(rig, case)
        total += 1
        families[("verify", "direct")] = families.get(("verify", "direct"), 0) + 1
        if error:
            failures.append(error)
        hay, rest, offset, mask, flag = case
        r, ex = run_verify(rig, hay, rest, offset, mask, flag, FILLS[0])
        seen |= ex
        for pc in ex:
            covers.setdefault(pc, []).append(("v", number))
    glue_list = list(glue_cases()) + list(pipeline_cases(rig, ctor_list))
    for number, case in enumerate(glue_list):
        error = check_glue(rig, case)
        total += 1
        families[("glue", case[0])] = families.get(("glue", case[0]), 0) + 1
        if error:
            failures.append(error)
        _, ex = run_glue(rig, *case)
        seen |= ex
        for pc in ex:
            covers.setdefault(pc, []).append(("g", number))
    if failures:
        raise EvidenceError("model and interpreter disagree: %s" % failures[0])
    for n in range(0, 301):
        text = (b"yx" * 200)[:n]
        got, executed = run_ctor(rig, text, 0, False, FILLS[0])
        steps = len(executed)
        machine = rig[0]
        profile.append((n, lane_class(n), steps, got[0]))
    write_tsv(out / "cases-sample.tsv", ("case", "kind", "length", "search_class", "route", "first24_hex", "sha256_prefix"), sample)
    write_tsv(out / "length-profile.tsv", ("length", "search_class", "distinct_instructions_executed", "route"), profile)
    write_tsv(out / "routes.tsv", ("family", "route", "cases"), [(k[0], k[1], v) for k, v in sorted(families.items())])
    # --- coverage
    coverage = []
    for start, _ in FUNCTIONS:
        for row in rows[start]:
            coverage.append((hex(row.va), row.op, region(row.va), int(row.va in seen)))
    write_tsv(out / "coverage.tsv", ("va", "op", "region", "executed"), coverage)
    # --- negative controls
    mutants = mutant_list(image)
    detected, equivalent = 0, []
    control_lines = []
    by_va = {r.va: r for start, _ in FUNCTIONS for r in rows[start]}
    for patch in mutants:
        hit, reason, index = detect(image, patch, pick(covers.get(patch[5], [])), ctor_list, verify_list, glue_list)
        control_lines.append((hex(patch[0]), patch[1], hex(patch[2]), patch[3], patch[4], int(hit), reason, index))
        if hit:
            detected += 1
        else:
            equivalent.append(patch)
    write_tsv(out / "controls.tsv", ("va", "byte", "new", "kind", "function", "detected", "reason", "case"), control_lines)
    reasons = [equivalent_reason(p, by_va) for p in equivalent]
    write_tsv(out / "equivalent-mutants.tsv", ("va", "byte", "new", "kind", "reason"),
              [(hex(p[0]), p[1], hex(p[2]), p[3], r) for p, r in zip(equivalent, reasons)])
    if "unclassified" in reasons:
        raise EvidenceError("unclassified undetected mutants: %s" % [hex(p[0]) for p, r in zip(equivalent, reasons) if r == "unclassified"])
    measure = dict(cases=total, negative_controls=len(mutants), negative_detected=detected, equivalent=len(equivalent))
    (out / "measure.json").write_text(json.dumps(measure, indent=1, sort_keys=True) + "\n")
    summary = dict(binary_sha256=SHA256, constants=consts, functions={hex(s): n for s, n in FUNCTIONS}, box_size=BOX_SIZE,
                   detection_cases=dict(ctor=len(ctor_list), verify=len(verify_list), glue=len(glue_list)), executed_instructions=len(seen), instructions=sum(len(v) for v in rows.values()),
                   families={"%s/%s" % k: v for k, v in sorted(families.items())})
    (out / "summary.json").write_text(json.dumps(summary, indent=1, sort_keys=True) + "\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
