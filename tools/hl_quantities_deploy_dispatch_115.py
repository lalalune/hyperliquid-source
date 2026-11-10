#!/usr/bin/env python3
"""RE-009 hl-quantities, node #115: deploy-action dispatcher 0x50d3f40 and pair registration 0x55c1110.

Runs the real instruction bytes of both functions in an offline x86-64 interpreter (ELF bytes only, the binary is never executed) against
Python models, case by case, comparing the 0x70-byte result block, the ordered callee log and the whole fixture heap, then replays single-byte
mutations of every executed instruction as negative controls. The interpreter section is the shared one used by earlier #115 tools.

    python3 tools/hl_quantities_deploy_dispatch_115.py --out research/work-items/RE-009-quantities-deploy-dispatch-115
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




# ---------------------------------------------------------------------------------------------------------------------------------------
# RE-009 hl-quantities: deploy-action dispatcher 0x50d3f40 and the pair registration body 0x55c1110 (node #115).
# Everything below the interpreter is specific to this packet: fixture layout, callee contracts, the two models, the case makers, the
# mutation harness and the evidence writers.
# ---------------------------------------------------------------------------------------------------------------------------------------

import argparse  # noqa: E402
import json  # noqa: E402
import random  # noqa: E402

DISPATCH_FN = 0x50D3F40
PAIR_FN = 0x55C1110
SEARCH_FN = 0x43CD290
BTREE_FN = 0x4DD59A0
BIG_FN = 0x55CFE90
FUNCTIONS = [(DISPATCH_FN, "dispatch"), (PAIR_FN, "pair-register"), (0x4DA8DA0, "record-at"), (0x4DA8E10, "record-at-twin"), (0x4DA8390, "vacant-insert"), (SEARCH_FN, "char-search"), (0x4EF42F0, "set-has")]
TABLE_VA = 0x91A344           # relative jump table of the dispatcher, 4-byte entries
TABLE_ENTRIES = 7
NICHE = 1 << 63               # niche base of the action tag word
M64 = MASK[8]
M32 = MASK[4]
OK = 0x1A2                    # tag of the "no error" result
RESULT_SIZE = 0x70

H = HEAP_BASE
USED = 0x20000
STATE = H + 0x10000           # exchange state object (fields at 0xb0, 0xb8, 0x338, 0x398, 0x7c0, 0x968, 0x1108)
ELEMS = H + 0x12000           # first element of the vector at state+0xb0
DEXES = H + 0x14000           # three dex-like objects of 0x1000 bytes each (fields 0x10, 0x378, 0x408, 0x468)
ACTION = H + 0x16000
NAME = H + 0x17000            # action string buffer
OUT = H + 0x18000
OUT_FILL = 0xCC
VECS = H + 0x19000            # elements returned by the vec-producing callee
DEQUE = H + 0x1A010           # ring (VecDeque-like) header: capacity, buffer, head, length
RING = H + 0x1A100            # ring buffer of 0xa8-byte entries (8-byte header, record at +8)
NODE = H + 0x1A800            # tree node area: 0xa0-byte records
PARAM = H + 0x1B000           # parameter block for the direct pair call
SETENT = H + 0x1D000          # entries of the registered-address set (stride 0x60, key at +0x48)
SETSLOT = H + 0x1D800         # slot the hash-table find hands back
SPEC = H + 0x1C000            # char-searcher record for the direct search runs

GOT = dict(memcpy=0x64DF508, dealloc=0x64DF4A0, lookup_a=0x64E6A68, asset=0x64E69B8, rec_check=0x64E4E58, lookup_b=0x64E6C18,
           flag=0x64E6C20, divide=0x64E6AD8, finish=0x64E6C28, account=0x64E6FF8, panic=0x64DF830, panic_str=0x64DF770, memcmp=0x64DF9F8, memchr=0x64DFCB0, slice_panic=0x64DF570)
FAKE = {name: 0xF0000000 + 0x100 * index for index, name in enumerate(sorted(GOT))}
DIRECT = dict(find_sep=0x43CD290, emit=0x538CD30, btree_insert=BTREE_FN, post=0x55BD6B0, big=BIG_FN, pair=PAIR_FN, vec_of=0x5ACC8C0,
              per_elem=0x54CA190, drop=0x50F1840, cdd30=0x55CDD30, set_has=0x4EF42F0, map_find=0x4DC31D0, record_at=0x4DA8DA0,
              map_insert=0x4DA8390, map_finish=0x4DA8E10, tree_insert=0x51F3910, hash_key=0x4EF4560, table_find=0x4EFF000, ring_insert=0x57EC4D0)
ERR_TAGS = [0x100, 0x101, 0x14F, 0x156, 0x158, 0x15C, 0x166, 0x167, 0x168, 0x169, 0x1A1, 0x0FA, 0x0F0, 0x003]
SEP_DELIM = 0x3A0000003A
SENTINEL = 0x8000000000000000


class Crash(Exception):
    def __init__(self, kind, payload=()):
        super().__init__(kind)
        self.kind, self.payload = kind, tuple(payload)


def u(mem, addr, width=8):
    return mem.read(addr, width)


class Env:
    """The callee contracts. Both the interpreter hooks and the models call these methods, so a disagreement can only come from the
    function body under test. Every method appends one log row and returns data built from the case seed, the callee name and its call number."""

    def __init__(self, mem, case):
        self.mem, self.case, self.log, self.counts = mem, case, [], {}

    def rng(self, name):
        number = self.counts.get(name, 0)
        self.counts[name] = number + 1
        return random.Random("%d:%s:%d" % (self.case["seed"], name, number)), number

    def result(self, name, payload=None, tag_ok=OK):
        """A 0x70-byte result block: tag OK with `payload` at +8, or an error tag when the case fails this call."""
        rnd, number = self.rng(name)
        block = bytearray(rnd.getrandbits(8) for _ in range(RESULT_SIZE))
        if "%s:%d" % (name, number) in self.case["fail"]:
            tag = rnd.choice(ERR_TAGS)
        else:
            tag = tag_ok
            if payload is not None:
                block[8:16] = payload.to_bytes(8, "little")
        block[0:2] = tag.to_bytes(2, "little")
        return bytes(block)

    def lookup_a(self, table, ptr, length):
        rnd, _ = self.rng("lookup_a")
        self.log.append(("lookup_a", table, ptr, length))
        return self.result("lookup_a", rnd.getrandbits(64))

    def asset(self, ptr, length, value):
        rnd, _ = self.rng("asset")
        self.log.append(("asset", ptr, length, value))
        pick = rnd.choice([0, 1, 0x270F, 0x2710, 0x2711, 0x5F45A5F, 0x5F45A60, 0x1_0000_0000, M64, "small", "mid", "big"])
        if pick == "small":
            pick = rnd.randrange(0x2710)
        elif pick == "mid":
            pick = rnd.randrange(0x2710, 0x5F45A60)
        elif pick == "big":
            pick = rnd.randrange(0x5F45A60, 1 << 62)
        return self.result("asset", pick)

    def emit(self, state, tag, payload):
        self.log.append(("emit", state, tag, payload))
        return self.result("emit", None)

    def rec_check(self, cap, ptr, length):
        self.log.append(("rec_check", cap, ptr, length))
        return self.result("rec_check", None)

    def btree_insert(self, mapaddr, key, value):
        self.log.append(("btree_insert", mapaddr, key, value))

    def lookup_b(self, table, ptr, length):
        rnd, _ = self.rng("lookup_b")
        self.log.append(("lookup_b", table, ptr, length))
        return self.result("lookup_b", DEXES + 0x1000 * rnd.randrange(3))

    def post(self, state, cap, ptr, length):
        rnd, _ = self.rng("post")
        self.log.append(("post", state, cap, ptr, length))
        block = bytearray(self.result("post", DEXES + 0x1000 * rnd.randrange(3)))
        amount = rnd.choice([rnd.getrandbits(64), rnd.getrandbits(64), 0, 9999, 10000, 20000, M64 - M64 % 10000, rnd.randrange(1 << 20) * 10000,
                             rnd.randrange(1 << 49) * 10000])
        block[0x10:0x18] = amount.to_bytes(8, "little")
        return bytes(block)

    def flag(self, where, value):
        rnd, _ = self.rng("flag")
        self.log.append(("flag", where, value))
        block = bytearray(self.result("flag", None))
        block[8] = rnd.choice([0, 1, 2, 2, 3, 0xFF])
        return bytes(block)

    def divide(self, table, quotient):
        rnd, _ = self.rng("divide")
        self.log.append(("divide", table, quotient))
        return rnd.getrandbits(64)

    def finish(self, found, value, flag):
        self.log.append(("finish", found, value, flag))
        return self.result("finish", None)

    def vec_of(self, dex, first, third):
        rnd, _ = self.rng("vec_of")
        self.log.append(("vec_of", dex, first, third))
        count = rnd.choice([0, 0, 1, 2, 3, 5])
        cap = count + rnd.choice([0, 0, 1, 4])
        elems = [rnd.getrandbits(64) for _ in range(count)]
        self.mem.put_bytes(VECS, b"".join(e.to_bytes(8, "little") for e in elems))
        return cap, VECS, count

    def per_elem(self, state, elem):
        self.log.append(("per_elem", state, elem))

    def dealloc(self, ptr, size, align):
        self.log.append(("dealloc", ptr, size, align))

    def memcpy(self, dst, src, count, content=None):
        """Logged by length and content; the 0xa0-byte copy in 0x4da8390 reads 7 stack bytes the caller never wrote, so only 0x99 are content."""
        if content is None:
            content = self.mem.bytes_at(src, 0x99 if count == 0xA0 else count)
        self.log.append(("memcpy", count, content))

    def drop(self, content):
        self.log.append(("drop", content))

    def big(self, state, zero20, copy):
        self.log.append(("big", state, zero20, copy))
        return self.result("big", None)

    def cdd30(self, state, address, flag):
        self.log.append(("cdd30", state, address, flag))
        return self.result("cdd30", None)

    def account(self, table, address):
        rnd, _ = self.rng("account")
        self.log.append(("account", table, address))
        block = bytearray(rnd.getrandbits(8) for _ in range(0x50))
        block[0x28] = rnd.choice([0, 1, 1, 1])
        if rnd.random() < 0.8:
            block[0x29:0x49] = KECCAK_EMPTY
        return bytes(block)

    def hash_key(self, first, second, key):
        rnd, _ = self.rng("hash_key")
        self.log.append(("hash_key", first, second, key))
        return rnd.getrandbits(64)

    def table_find(self, table, hashed, key, entries, count):
        rnd, _ = self.rng("table_find")
        self.log.append(("table_find", table, hashed, key, entries, count))
        return SETSLOT if rnd.random() < 0.35 else 0

    def map_find(self, mapaddr, key):
        rnd, _ = self.rng("map_find")
        self.log.append(("map_find", mapaddr, key))
        block = bytearray(rnd.getrandbits(8) for _ in range(0x30))
        block[0] = rnd.choice([0, 0, 1, 1, 1])
        length = u(self.mem, DEQUE + 0x18)
        if rnd.random() < 0.3:
            block[8:0x20] = struct.pack("<QQQ", NODE, rnd.getrandbits(8), rnd.randrange(8))
        else:
            block[8:0x20] = struct.pack("<QQQ", 0, DEQUE, rnd.randrange(length + 2))
        return bytes(block)

    def tree_insert(self, handle):
        rnd, _ = self.rng("tree_insert")
        self.log.append(("tree_insert", handle))
        return struct.pack("<QQQQ", rnd.choice([NODE, 0]), DEQUE, rnd.randrange(4), rnd.getrandbits(64))

    def ring_insert(self, deque, index, entry):
        self.log.append(("ring_insert", deque, index, entry))
        self.mem.write(deque + 0x18, 8, (u(self.mem, deque + 0x18) + 1) & M64)


KECCAK_EMPTY = bytes.fromhex("c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470")


def tag_of(block):
    return int.from_bytes(block[:2], "little")


def finish_out(out, block):
    out[:RESULT_SIZE] = block[:RESULT_SIZE]


def free_buffer(env, cap, ptr):
    if cap:
        env.dealloc(ptr, cap, 0)


def pair_model(env, out, state, param, image):
    """0x55c1110: register a pair after the identity, ownership, code-hash and uniqueness checks. `param` holds the 0x58 parameter bytes:
    index at 0, then four 20-byte values at 8, 0x1c, 0x30, 0x44."""
    mem = env.mem
    index = int.from_bytes(param[:8], "little")
    a, b, c, d = (param[at:at + 20] for at in (8, 0x1C, 0x30, 0x44))
    if index != 0:
        out[0:2] = (0x101).to_bytes(2, "little")
        return
    if a == b:
        out[0:2] = (0x166).to_bytes(2, "little")
        return
    for number, address in enumerate((a, b)):
        block = env.cdd30(state, address, number)
        if tag_of(block) != OK:
            finish_out(out, block)
            return
    count = u(mem, state + 0xB8)
    if count == 0:
        raise Crash("panic", (0x64768D8,))
    first = u(mem, state + 0xB0)
    if mem.bytes_at(first + 0x12C, 1)[0] != 1:
        out[0:2] = (0x167).to_bytes(2, "little")
        return
    if mem.bytes_at(first + 0x12D, 20) == d:
        out[0:2] = (0x168).to_bytes(2, "little")
        return
    block = env.account(state + 0x1108, c)
    code_hash = block[0x29:0x49] if block[0x28] & 1 else image_bytes(image, 0x4585A0, 32)
    if code_hash != image_bytes(image, 0x4537F0, 16) + image_bytes(image, 0x452020, 16):
        out[0:2] = (0x169).to_bytes(2, "little")
        return
    if set_has_model(env, state + 0x968, c) == 1:
        out[0:2] = (0x169).to_bytes(2, "little")
        return
    found = env.map_find(state + 0x398, 0)
    if found[0]:
        record = record_model(mem, found[8:0x20])
        if mem.bytes_at(record + 0x84, 20) != d:
            out[0:2] = (0x168).to_bytes(2, "little")
            return
        if mem.bytes_at(record + 0x70, 20) != c:
            out[0:2] = (0x169).to_bytes(2, "little")
            return
        mem.put_bytes(record + 0x48, a)
        mem.put_bytes(record + 0x5C, b)
    else:
        content = (struct.pack("<QQ", 0, 8) + bytes(16) + struct.pack("<QQ", 0, 8) + bytes(16) + struct.pack("<Q", 0) + a + b + c + d + b"\x00")
        record_model(mem, insert_model(env, found[8:0x30], content)[:24])
    out[0:2] = OK.to_bytes(2, "little")


def set_has_model(env, base, key):
    """0x4ef42f0: membership of a 20-byte key in an index map: empty, one entry compared in place, or hashed and probed."""
    mem = env.mem
    count = u(mem, base + 0x10)
    if count == 0:
        return 0
    if count == 1:
        return int(mem.bytes_at(u(mem, base + 8) + 0x48, 20) == key)
    hashed = env.hash_key(u(mem, base + 0x38), u(mem, base + 0x40), key)
    return int(env.table_find(base + 0x18, hashed, key, u(mem, base + 8), count) != 0)


def record_model(mem, handle):
    """0x4da8da0 and its twin 0x4da8e10: the record a map handle (tree pointer, ring or node, index) designates."""
    node, ring, index = struct.unpack("<QQQ", handle[:24])
    if node:
        return (node + index * 0xA0) & M64
    if index >= u(mem, ring + 0x18):
        raise Crash("panic_str", (0x9171A2, 0x14, 0x649CC08))
    position = index + u(mem, ring + 0x10)
    capacity = u(mem, ring)
    if position >= capacity:
        position -= capacity
    return (u(mem, ring + 8) + position * 0xA8 + 8) & M64


def insert_model(env, handle, content):
    """0x4da8390: store a new record through a vacant handle; returns the four result words that 0x4da8e10 then resolves."""
    if int.from_bytes(handle[:8], "little"):
        return env.tree_insert(handle[:0x28])
    ring, index, extra = struct.unpack("<QQQ", handle[8:0x20])
    env.memcpy(0, 0, 0xA0, content)
    env.ring_insert(ring, index, struct.pack("<Q", extra) + content)
    return struct.pack("<QQQQ", 0, ring, index, 0)


def image_bytes(image, va, count):
    return bytes(image.blob[image.offset(va):image.offset(va) + count])


def search_model(hay, spec):
    """0x43cd290: next match of a one-to-four byte needle, as the char searcher over `hay` with the finger and back finger of `spec`.

    spec is the record: pointer, haystack length, finger, back finger, needle bytes at 0x20, needle size at 0x28. Returns ((start, end) or
    None, the finger left behind)."""
    length, finger, back = struct.unpack_from("<QQQ", spec, 8)[0], struct.unpack_from("<Q", spec, 0x10)[0], struct.unpack_from("<Q", spec, 0x18)[0]
    size = spec[0x28]
    if back > length or back < finger:
        return None, finger
    needle = spec[0x20:0x20 + size]
    while True:
        at = hay[finger:back].find(needle[-1:])
        if at < 0:
            return None, back
        finger += at + 1
        if size <= finger <= length and hay[finger - size:finger] == needle:
            return (finger - size, finger), finger
        if back < finger:
            return None, finger


def arm_index(tag):
    """Jump-table slot for a tag word: values 0x800000000000000d..0x13 map to 0..6, anything at or below 0x800000000000000c is the default arm 5."""
    return (tag - NICHE - 13) & M64 if tag > NICHE + 12 else 5


def dispatch_model(env, out, state, action, image):
    """0x50d3f40: route one deploy action on its tag word. The seven jump-table arms, the 0x12 alias and the default arm."""
    mem = env.mem
    tag = u(mem, action)
    index = arm_index(tag)
    if index == 0:
        cap, ptr, length = u(mem, action + 8), u(mem, action + 0x10), u(mem, action + 0x18)
        if length >= 0x65:
            free_buffer(env, cap, ptr)
            out[0:2] = (0x158).to_bytes(2, "little")
            return
        hit, _ = search_model(mem.bytes_at(ptr, length), struct.pack("<QQQQQB", ptr, length, 0, length, SEP_DELIM, 1))
        found, position = (1, hit[0]) if hit else (0, 0)
        block = env.lookup_a(state + 0x7C0, ptr if found else 1, position if found else 0)
        if tag_of(block) == OK:
            block = env.asset(ptr, length, int.from_bytes(block[8:16], "little"))
            if tag_of(block) == OK:
                value = int.from_bytes(block[8:16], "little")
                if value <= 0x270F:
                    asset = value & M32
                elif value <= 0x5F45A5F:
                    asset = (value + 0x186A0) & M32
                else:
                    asset = M32
                finish_out(out, env.emit(state, 0x35, struct.pack("<IB", asset, 1)))
                free_buffer(env, cap, ptr)
                return
        finish_out(out, block)
        free_buffer(env, cap, ptr)
    elif index == 1:
        finish_out(out, env.emit(state, 0x2D, mem.bytes_at(action + 8, 21)))
    elif index == 2:
        cap, ptr, length = u(mem, action + 8), u(mem, action + 0x10), u(mem, action + 0x18)
        block = env.rec_check(cap, ptr, length)
        if tag_of(block) != OK:
            free_buffer(env, cap, ptr)
            finish_out(out, block)
            return
        env.btree_insert(state + 0x338, mem.bytes_at(action + 8, 24), mem.bytes_at(action + 0x20, 20))
        out[0:2] = OK.to_bytes(2, "little")
    elif index == 3:
        cap, ptr, length = u(mem, action + 8), u(mem, action + 0x10), u(mem, action + 0x18)
        if length >= 0x65:
            free_buffer(env, cap, ptr)
            out[0:2] = (0x158).to_bytes(2, "little")
            return
        flagged = mem.bytes_at(action + 0x20, 1)[0]
        block = env.lookup_b(state + 0x7C0, ptr, length)
        if tag_of(block) != OK:
            finish_out(out, block)
        else:
            dex = int.from_bytes(block[8:16], "little")
            if u(mem, dex + 0x378) == SENTINEL:
                out[0:2] = (0x156).to_bytes(2, "little")
            elif flagged:
                mem.put_bytes(dex + 0x468, b"\x02")
                vcap, vptr, vlen = env.vec_of(dex, 0, u(mem, dex + 0x10))
                for position in range(vlen):
                    env.per_elem(state, u(mem, vptr + 8 * position))
                if vcap:
                    env.dealloc(vptr, vcap * 8, 0)
                out[0:2] = OK.to_bytes(2, "little")
            else:
                mem.put_bytes(dex + 0x468, b"\x00")
                out[0:2] = OK.to_bytes(2, "little")
        free_buffer(env, cap, ptr)
    elif index == 4:
        cap, ptr, length = u(mem, action + 8), u(mem, action + 0x10), u(mem, action + 0x18)
        flagged = mem.bytes_at(action + 0x20, 1)[0]
        block = env.post(state, cap, ptr, length)
        if tag_of(block) != OK:
            finish_out(out, block)
        else:
            dex = int.from_bytes(block[8:16], "little")
            if u(mem, dex + 0x378) == SENTINEL:
                out[0:2] = (0x156).to_bytes(2, "little")
            elif u(mem, dex + 0x408) != SENTINEL + 1:
                out[0:2] = (0x1A1).to_bytes(2, "little")
            else:
                amount = int.from_bytes(block[0x10:0x18], "little")
                answer = env.flag(dex + 0x378, amount)[8]
                wanted = 1 if flagged else 2
                if (answer == 2) == (wanted == 1):
                    quotient = amount // 10000
                    table = env.divide(state + 0x7C0, quotient)
                    block = env.finish(table, amount, wanted)
                    if tag_of(block) != OK:
                        finish_out(out, block)
                        free_buffer(env, cap, ptr)
                        return
                out[0:2] = OK.to_bytes(2, "little")
        free_buffer(env, cap, ptr)
    elif index == 5:
        copy = mem.bytes_at(action, 0xB0)
        env.memcpy(0, action, 0xB0)
        block = env.big(state, bytes(20), copy)
        if tag_of(block) == OK:
            out[0:2] = OK.to_bytes(2, "little")
        else:
            finish_out(out, block)
        env.drop(copy)
    else:
        position = u(mem, action + 8)
        if position >= u(mem, state + 0xB8):
            out[0:2] = (0xFA).to_bytes(2, "little")
            out[8:16] = position.to_bytes(8, "little")
            return
        param = mem.bytes_at(action + 8, 8) + mem.bytes_at(action + 0x10, 20) + mem.bytes_at(action + 0x24, 20) \
            + mem.bytes_at(action + 0x38, 20) + mem.bytes_at(action + 0x4C, 20)
        pair_model(env, out, state, param, image)


def function_rows(image, start):
    return decode_range(image, start, image.exact_fde(start)[1])


def code_bytes(image, row):
    at = image.offset(row.va)
    return bytes(image.blob[at:at + row.size])


# ---------------------------------------------------------------------------------------------------------------------------------------
# Fixture: the heap objects both runs start from.
# ---------------------------------------------------------------------------------------------------------------------------------------

ARM_TAGS = [NICHE + 13, NICHE + 14, NICHE + 15, NICHE + 16, NICHE + 17, None, NICHE + 0x13]
KINDS = ("dispatch", "pair", "search")


def pick_length(rnd):
    return rnd.choice([0, 1, 5, 17, 40, 99, 100, 0x64, 0x65, 0x66, 0xFF, 0x100, rnd.randrange(0x65), rnd.randrange(0x65), rnd.randrange(0x100)])


def build(mem, case):
    """Lay the case out in the heap; everything is derived from the case seed so the interpreter run and the model run start identical."""
    rnd = random.Random(case["seed"] * 7919 + 11)
    mem.reset(USED)
    mem.put_bytes(OUT, bytes([OUT_FILL]) * 0x80)
    if case["kind"] == "search":
        mem.put_bytes(NAME, case["haystack"])
        mem.put_bytes(SPEC, struct.pack("<QQQQ", NAME + case["offset"], case["hlen"], case["finger"], case["back"]) + case["needle"].ljust(8, b"\x00")
                      + bytes([case["size"]]))
        return
    n = case["count"]
    mem.write(STATE + 0xB0, 8, ELEMS)
    mem.write(STATE + 0xB8, 8, n)
    first = bytes(rnd.getrandbits(8) for _ in range(20))
    mem.put_bytes(ELEMS + 0x12C, bytes([case["first_flag"]]) + first)
    for index in range(3):
        base = DEXES + 0x1000 * index
        mem.write(base + 0x10, 8, rnd.getrandbits(64))
        mem.write(base + 0x378, 8, SENTINEL if (case["dex_mask"] >> index) & 1 else rnd.getrandbits(64) & ~SENTINEL)
        mem.write(base + 0x408, 8, SENTINEL + 1 if (case["dex_mask"] >> (index + 3)) & 1 else rnd.choice([SENTINEL, SENTINEL + 2, 0, 1]))
        mem.write(base + 0x468, 1, 0x77)
    length = case["length"]
    text = bytearray(rnd.getrandbits(8) for _ in range(0x120))
    for at in range(0x120):
        if rnd.random() < case["colon"]:
            text[at] = 0x3A
    mem.put_bytes(NAME, bytes(text))
    pieces = {}
    for key in "ABCD":
        pieces[key] = bytes(rnd.getrandbits(8) for _ in range(20))
    if case["same_ab"]:
        pieces["B"] = pieces["A"]
    if case["d_is_first"]:
        pieces["D"] = first
    if case["kind"] == "pair":
        mem.put_bytes(PARAM, struct.pack("<Q", case["index"]) + pieces["A"] + pieces["B"] + pieces["C"] + pieces["D"])
    else:
        tag = case["tag"]
        mem.write(ACTION, 8, tag)
        arm = case["arm"]
        if arm in (0, 2, 3, 4):
            mem.write(ACTION + 8, 8, 0 if case["cap0"] else length + case["slack"])
            mem.write(ACTION + 0x10, 8, NAME + case["name_at"])
            mem.write(ACTION + 0x18, 8, length)
            mem.write(ACTION + 0x20, 1, case["flagged"])
            if arm == 2:
                mem.put_bytes(ACTION + 0x20, pieces["A"])
        elif arm == 1:
            mem.put_bytes(ACTION + 8, bytes(rnd.getrandbits(8) for _ in range(0x20)))
        elif arm == 5:
            mem.put_bytes(ACTION + 8, bytes(rnd.getrandbits(8) for _ in range(0xA8)))
        else:
            mem.put_bytes(ACTION + 8, struct.pack("<Q", case["index"]) + pieces["A"] + b"\x00" * 4 + pieces["B"] + b"\x00" * 4 + pieces["C"]
                          + b"\x00" * 4 + pieces["D"] + b"\x00" * 4)
    members = case["set_len"]
    mem.put_bytes(STATE + 0x968, struct.pack("<QQQ", 0, SETENT, members))
    mem.put_bytes(STATE + 0x9A0, struct.pack("<QQ", rnd.getrandbits(64), rnd.getrandbits(64)))
    for slot in range(members):
        mem.put_bytes(SETENT + 0x60 * slot, bytes(rnd.getrandbits(8) for _ in range(0x60)))
        mem.put_bytes(SETENT + 0x60 * slot + 0x48, pieces["C"] if rnd.random() < 0.35 else bytes(rnd.getrandbits(8) for _ in range(20)))
    mem.put_bytes(SETSLOT - 8, struct.pack("<Q", rnd.randrange(members + 1)))
    capacity = rnd.choice([1, 2, 4, 5])
    length = rnd.randrange(capacity + 1)
    mem.put_bytes(DEQUE, struct.pack("<QQQQ", capacity, RING, rnd.randrange(capacity), length))
    for slot in range(capacity):
        record = bytearray(rnd.getrandbits(8) for _ in range(0xA8))
        record[0x78:0x8C] = pieces["C"] if rnd.random() < 0.7 else bytes(rnd.getrandbits(8) for _ in range(20))
        record[0x8C:0xA0] = pieces["D"] if rnd.random() < 0.7 else bytes(rnd.getrandbits(8) for _ in range(20))
        mem.put_bytes(RING + 0xA8 * slot, bytes(record))
    for slot in range(8):
        record = bytearray(rnd.getrandbits(8) for _ in range(0xA0))
        record[0x70:0x84] = pieces["C"] if rnd.random() < 0.7 else bytes(rnd.getrandbits(8) for _ in range(20))
        record[0x84:0x98] = pieces["D"] if rnd.random() < 0.7 else bytes(rnd.getrandbits(8) for _ in range(20))
        mem.put_bytes(NODE + 0xA0 * slot, bytes(record))


def make_search_case(rnd, number):
    size = rnd.choice([1, 1, 1, 2, 3, 4])
    needle = bytes(rnd.choice(b"abc:\xc3\xa9") for _ in range(size))
    alphabet = bytes(set(needle)) + rnd.choice([b"a", b"ab", b"\x00\xff", bytes(range(32, 40))])
    hlen = rnd.choice([0, 1, 3, 7, 8, 15, 16, 17, 31, 32, 33, 47, 48, 63, 64, 100, 255, 256, 257, 288, rnd.randrange(130), rnd.randrange(289)])
    haystack = bytes(rnd.choice(alphabet) for _ in range(0x120))
    finger = rnd.choice([0, 0, 0, rnd.randrange(hlen + 1), hlen, hlen + 1])
    back = rnd.choice([hlen, hlen, hlen, rnd.randrange(hlen + 1), finger, finger - 1 if finger else 0, hlen + 1, hlen + 3])
    return dict(seed=rnd.getrandbits(40), kind="search", number=number, haystack=haystack, hlen=hlen, finger=finger, back=back & M64, needle=needle,
                size=size, offset=rnd.randrange(16), fail=set(), arm=-1)


def make_case(rnd, number, kind):
    if kind == "search":
        return make_search_case(rnd, number)
    case = dict(seed=rnd.getrandbits(40), kind=kind, number=number)
    n = rnd.choice([0, 1, 2, 3, 7])
    case.update(count=n, first_flag=rnd.choice([1, 1, 1, 0, 2]), dex_mask=rnd.getrandbits(6), length=pick_length(rnd), slack=rnd.choice([0, 0, 1, 7, 1 << 32, 1 << 40]),
                name_at=rnd.randrange(0x20), flagged=rnd.choice([0, 1, 1, 0xFF]), same_ab=rnd.random() < 0.12, d_is_first=rnd.random() < 0.12,
                colon=rnd.choice([0, 0.02, 0.1, 0.5]), cap0=rnd.random() < 0.15, set_len=rnd.choice([0, 1, 1, 2, 3]))
    case["index"] = rnd.choice([0, 0, 0, 0, 1, 2, M64, rnd.randrange(8)]) if kind == "pair" else rnd.choice([0, 0, 0, 1, max(n - 1, 0), n, n + 1, M64, rnd.randrange(8)])
    if kind == "dispatch":
        arm = rnd.choice([0, 0, 1, 2, 3, 3, 4, 4, 5, 5, 6, 6, 6])
        case["arm"] = arm
        if arm == 5:
            case["tag"] = rnd.choice([0, 1, 0x40, rnd.randrange(0x10000), NICHE + 12, NICHE + 0x12, rnd.getrandbits(40)])
        else:
            case["tag"] = ARM_TAGS[arm]
    if kind == "dispatch" and case["arm"] == 4 and rnd.random() < 0.4:
        case.update(slack=rnd.choice([1 << 32, 1 << 40]), dex_mask=(case["dex_mask"] | 0b111000) & ~0b111)
    names = ["lookup_a", "asset", "emit", "rec_check", "lookup_b", "post", "flag", "finish", "big", "cdd30", "account", "map_find"]
    fail = set()
    for name in names:
        for call in range(2):
            if rnd.random() < 0.13:
                fail.add("%s:%d" % (name, call))
    case["fail"] = fail
    return case


# ---------------------------------------------------------------------------------------------------------------------------------------
# Interpreter hooks (one adapter per callee, decoding registers and stack blocks) and the two runners.
# ---------------------------------------------------------------------------------------------------------------------------------------

def install(machine, env):
    mem = machine.memory
    regs = lambda m: m.regs  # noqa: E731

    def block_out(m, block):
        mem.put_bytes(m.regs[RDI], block)

    def h_lookup_a(m):
        block_out(m, env.lookup_a(m.regs[RSI], m.regs[RDX], m.regs[RCX]))

    def h_asset(m):
        block_out(m, env.asset(m.regs[RSI], m.regs[RDX], m.regs[RCX]))

    def h_emit(m):
        rec = m.regs[RSI]
        tag = u(mem, rec)
        payload = mem.bytes_at(rec + 8, 21) if tag == 0x2D else struct.pack("<IB", u(mem, rec + 8, 4), u(mem, rec + 0xC, 1))
        block_out(m, env.emit(m.regs[RDX], tag, payload))

    def h_rec_check(m):
        rec = m.regs[RSI]
        block_out(m, env.rec_check(u(mem, rec), u(mem, rec + 8), u(mem, rec + 0x10)))

    def h_btree(m):
        env.btree_insert(m.regs[RSI], mem.bytes_at(m.regs[RDX], 24), mem.bytes_at(m.regs[RCX], 20))

    def h_lookup_b(m):
        block_out(m, env.lookup_b(m.regs[RSI], m.regs[RDX], m.regs[RCX]))

    def h_post(m):
        rec = m.regs[RDX]
        block_out(m, env.post(m.regs[RSI], u(mem, rec), u(mem, rec + 8), u(mem, rec + 0x10)))

    def h_flag(m):
        block_out(m, env.flag(m.regs[RSI], m.regs[RDX]))

    def h_divide(m):
        m.regs[RAX] = env.divide(m.regs[RDI], m.regs[RSI])

    def h_finish(m):
        block_out(m, env.finish(m.regs[RSI], m.regs[RDX], m.regs[RCX]))

    def h_vec_of(m):
        it = m.regs[RSI]
        cap, ptr, count = env.vec_of(u(mem, it), u(mem, it + 8), u(mem, it + 0x10))
        mem.put_bytes(m.regs[RDI], struct.pack("<QQQ", cap, ptr, count))

    def h_per_elem(m):
        env.per_elem(m.regs[RDI], m.regs[RSI])

    def h_dealloc(m):
        env.dealloc(m.regs[RDI], m.regs[RSI], m.regs[RDX])

    def h_memcpy(m):
        env.memcpy(m.regs[RDI], m.regs[RSI], m.regs[RDX])
        mem.put_bytes(m.regs[RDI], mem.bytes_at(m.regs[RSI], m.regs[RDX]))

    def h_drop(m):
        env.drop(mem.bytes_at(m.regs[RDI], 0xB0))

    def h_big(m):
        block_out(m, env.big(m.regs[RSI], mem.bytes_at(m.regs[RDX], 20), mem.bytes_at(m.regs[RCX], 0xB0)))

    def h_cdd30(m):
        block_out(m, env.cdd30(m.regs[RSI], mem.bytes_at(m.regs[RDX], 20), m.regs[RCX]))

    def h_account(m):
        block_out(m, env.account(m.regs[RSI], mem.bytes_at(m.regs[RDX], 20)))

    def h_hash_key(m):
        m.regs[RAX] = env.hash_key(m.regs[RDI], m.regs[RSI], mem.bytes_at(m.regs[RDX], 20))

    def h_table_find(m):
        probe = m.regs[RDX]
        m.regs[RAX] = env.table_find(m.regs[RDI], m.regs[RSI], mem.bytes_at(u(mem, probe), 20), u(mem, probe + 8), u(mem, probe + 0x10))

    def h_map_find(m):
        block_out(m, env.map_find(m.regs[RSI], m.regs[RDX]))

    def h_tree_insert(m):
        block_out(m, env.tree_insert(mem.bytes_at(m.regs[RSI], 0x28)))

    def h_ring_insert(m):
        entry = m.regs[RDX]
        env.ring_insert(m.regs[RDI], m.regs[RSI], mem.bytes_at(entry, 8) + mem.bytes_at(entry + 8, 0x99))

    def h_memcmp(m):
        left, right, count = m.regs[RDI], m.regs[RSI], m.regs[RDX]
        one, two = mem.bytes_at(left, count), mem.bytes_at(right, count)
        m.regs[RAX] = 0 if one == two else (1 if one > two else M32)

    def h_memchr(m):
        at = mem.bytes_at(m.regs[RSI], m.regs[RDX]).find(bytes([m.regs[RDI] & 0xFF]))
        m.regs[RAX] = int(at >= 0)
        m.regs[RDX] = max(at, 0)
        m.keep_rdx = True

    def h_slice_panic(m):
        raise Crash("slice_panic", (m.regs[RDI], m.regs[RSI], m.regs[RDX], m.regs[RCX]))

    def h_panic(m):
        raise Crash("panic", (m.regs[RDI],))

    def h_panic_str(m):
        raise Crash("panic_str", (m.regs[RDI], m.regs[RSI], m.regs[RDX]))

    for name, got in GOT.items():
        mem.statics[got] = FAKE[name]
    for name, hook in dict(lookup_a=h_lookup_a, asset=h_asset, rec_check=h_rec_check, lookup_b=h_lookup_b, flag=h_flag, divide=h_divide,
                           finish=h_finish, account=h_account, memcpy=h_memcpy, dealloc=h_dealloc, panic=h_panic, panic_str=h_panic_str, memcmp=h_memcmp, memchr=h_memchr, slice_panic=h_slice_panic).items():
        machine.slots[FAKE[name]] = hook
    for name, hook in dict(emit=h_emit, btree_insert=h_btree, post=h_post, big=h_big, vec_of=h_vec_of, per_elem=h_per_elem,
                           drop=h_drop, cdd30=h_cdd30, hash_key=h_hash_key, table_find=h_table_find, map_find=h_map_find, tree_insert=h_tree_insert, ring_insert=h_ring_insert).items():
        machine.calls[DIRECT[name]] = hook
    machine.real = frozenset([PAIR_FN, SEARCH_FN, DIRECT["set_has"], DIRECT["record_at"], DIRECT["map_insert"], DIRECT["map_finish"]])


MODEL_MEMORY = {}


def run_real(machine, case):
    mem = machine.memory
    build(mem, case)
    env = Env(mem, case)
    install(machine, env)
    machine.seen = set()
    crash, returned = None, OUT
    try:
        if case["kind"] == "search":
            returned = machine.run(SEARCH_FN, {RDI: OUT, RSI: SPEC})
        elif case["kind"] == "pair":
            returned = machine.run(PAIR_FN, {RDI: OUT, RSI: STATE, RDX: PARAM})
        else:
            returned = machine.run(DISPATCH_FN, {RDI: OUT, RSI: ACTION, RDX: STATE})
    except Crash as exc:
        crash = (exc.kind, exc.payload)
    env.log.append(("return", returned if not crash else OUT))
    return crash, env.log, bytes(mem.heap[:USED]), set(machine.seen)


def run_model(image, case):
    mem = MODEL_MEMORY.get("m")
    if mem is None:
        mem = MODEL_MEMORY["m"] = Memory(image)
    build(mem, case)
    env = Env(mem, case)
    out = bytearray(bytes([OUT_FILL]) * 0x80)
    crash, returned = None, OUT
    try:
        if case["kind"] == "search":
            spec = mem.bytes_at(SPEC, 0x29)
            ptr = u(mem, SPEC)
            hit, finger = search_model(mem.bytes_at(ptr, u(mem, SPEC + 8)), spec)
            mem.write(SPEC + 0x10, 8, finger)
            returned = int(hit is not None)
            out[0:8] = returned.to_bytes(8, "little")
            if hit:
                out[8:24] = struct.pack("<QQ", *hit)
        elif case["kind"] == "pair":
            pair_model(env, out, STATE, mem.bytes_at(PARAM, 0x58), image)
        else:
            dispatch_model(env, out, STATE, ACTION, image)
    except Crash as exc:
        crash = (exc.kind, exc.payload)
    mem.put_bytes(OUT, bytes(out))
    env.log.append(("return", returned))
    return crash, env.log, bytes(mem.heap[:USED])


def compare(image, machine, case):
    """First disagreement between the interpreter run on the bytes and the model (or None), plus the executed addresses."""
    try:
        got = run_real(machine, case)
    except (Halt, EvidenceError) as exc:
        return "halt: %s" % exc, set()
    want = run_model(image, case)
    if got[0] != want[0]:
        return "crash", got[3]
    if got[1] != want[1]:
        return "log", got[3]
    if got[2] != want[2]:
        return "heap", got[3]
    return None, got[3]


def route(case, log, crash):
    names = ">".join(row[0] for row in log)
    return "%s/%s%s" % (case["kind"] if case["kind"] != "dispatch" else "arm%d" % case["arm"], names or "-", "!" + crash[0] if crash else "")


# ---------------------------------------------------------------------------------------------------------------------------------------
# Negative controls: single-byte mutations of executed instructions, replayed against the model on the detection case sets.
# ---------------------------------------------------------------------------------------------------------------------------------------

CASES = dict(dispatch=6500, pair=4500, search=5000)
DETECT = dict(dispatch=140, pair=100, search=140)
SECOND = dict(dispatch=2000, pair=2000, search=2000)
MUTANT_STEPS = 30000
SEEDS = dict(dispatch=0x115A, pair=0x115B, search=0x115C)


def mutant_list(image, executed):
    found = []
    for start, name in FUNCTIONS:
        for index, row in enumerate(function_rows(image, start)):
            if row.va not in executed:
                continue
            raw = code_bytes(image, row)
            if row.op == "jcc":
                at = 0 if raw[0] != 0x0F else 1
                found.append((row.va, at, raw[at] ^ 1, "condition-flip", name))
                continue
            if row.imm_at is not None and row.op not in ("push", "pop"):
                found.append((row.va, row.imm_at, raw[row.imm_at] ^ 1, "immediate-low-byte", name))
                continue
            for operand in (row.a, row.b):
                if isinstance(operand, tuple) and operand and operand[0] == "m" and operand[1] is not None and 0x08 <= abs(operand[4]) < 0x7F:
                    spots = [i for i, v in enumerate(raw) if v == operand[4] & 0xFF]
                    if len(spots) == 1:
                        found.append((row.va, spots[0], raw[spots[0]] ^ 1, "displacement-low-byte", name))
                        break
    return found


def detect(image, case_lists, patch):
    machine = Machine(image, {patch[0] + patch[1]: patch[2]})
    machine.step_limit = MUTANT_STEPS
    for stage, lists in enumerate(case_lists, 1):
        for kind in KINDS:
            for index, case in enumerate(lists[kind]):
                result, _ = compare(image, machine, case)
                if result:
                    return True, result.split(" ")[0].rstrip(":"), index, stage
    return False, "", -1, len(case_lists)


class Prefixed:
    def __init__(self, base):
        self.base = base

    def __truediv__(self, name):
        return self.base / name


def tag_text(blob):
    return "%#x" % int.from_bytes(blob[OUT - HEAP_BASE:OUT - HEAP_BASE + 2], "little")


def main(argv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument("--out", required=True)
    args = parser.parse_args(argv)
    out = pathlib.Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    image = load_image()
    evidence(image, out)
    return 0


def evidence(image, out):
    total, routes, results, sample, executed, hits = 0, {}, {}, [], set(), {}
    detect_sets, second_sets = {}, {}
    for kind in KINDS:
        rnd = random.Random(SEEDS[kind])
        machine = Machine(image)
        detect_sets[kind], second_sets[kind] = [], []
        for number in range(CASES[kind]):
            case = make_case(rnd, number, kind)
            result, seen = compare(image, machine, case)
            if result:
                raise SystemExit("model disagrees with the bytes: %s case %d: %s" % (kind, number, result))
            executed |= seen
            for va in seen:
                hits[va] = hits.get(va, 0) + 1
            total += 1
            run = run_model(image, case)
            key = (route(case, run[1], run[0]), tag_text(run[2]))
            routes[key] = routes.get(key, 0) + 1
            arm = "dispatch-arm%d" % case["arm"] if kind == "dispatch" else kind
            results[arm, key[1]] = results.get((arm, key[1]), 0) + 1
            if number % (CASES[kind] // DETECT[kind]) == 0 and len(detect_sets[kind]) < DETECT[kind]:
                detect_sets[kind].append(case)
            elif number % (CASES[kind] // SECOND[kind]) == 1 and len(second_sets[kind]) < SECOND[kind]:
                second_sets[kind].append(case)
            if number < 50:
                sample.append((kind, number, arm, key[0], hashlib.sha256(run[2]).hexdigest()[:16]))
    with open(out / "body.tsv", "w") as body, open(out / "coverage.tsv", "w") as cover, open(out / "branches.tsv", "w") as branches:
        body.write("function\tva\tsize\tbytes\top\n")
        cover.write("function\tstart\tend\tinstructions\texecuted\n")
        branches.write("function\tva\tcc\ttarget\ttaken_side_executed\tfall_through_executed\n")
        for start, name in FUNCTIONS:
            rows = function_rows(image, start)
            for row in rows:
                body.write("%s\t%#x\t%d\t%s\t%s\n" % (name, row.va, row.size, code_bytes(image, row).hex(), row.op))
                if row.op == "jcc":
                    branches.write("%s\t%#x\t%d\t%#x\t%d\t%d\n" % (name, row.va, row.cc, row.target, row.target in executed, row.next in executed))
            cover.write("%s\t%#x\t%#x\t%d\t%d\n" % (name, start, image.exact_fde(start)[1], len(rows), sum(1 for r in rows if r.va in executed)))
    with open(out / "hits.tsv", "w") as table:
        table.write("function\tva\tcases_executing\n")
        for start, name in FUNCTIONS:
            for row in function_rows(image, start):
                table.write("%s\t%#x\t%d\n" % (name, row.va, hits.get(row.va, 0)))
    with open(out / "routes.tsv", "w") as table:
        table.write("route\tout_tag\tcases\n")
        for key in sorted(routes):
            table.write("%s\t%s\t%d\n" % (key + (routes[key],)))
    with open(out / "results.tsv", "w") as table:
        table.write("arm\tout_tag\tcases\n")
        for key in sorted(results):
            table.write("%s\t%s\t%d\n" % (key + (results[key],)))
    with open(out / "cases-sample.tsv", "w") as table:
        table.write("case_set\tcase\tarm\troute\theap_digest\n")
        for row in sample:
            table.write("%s\t%d\t%s\t%s\t%s\n" % row)
    with open(out / "jumptable.tsv", "w") as table:
        table.write("slot\ttag_word\ttarget\tinside_function\n")
        start, end = image.exact_fde(DISPATCH_FN)
        base = image.offset(TABLE_VA)
        for slot in range(TABLE_ENTRIES):
            target = (struct.unpack_from("<i", image.blob, base + 4 * slot)[0] + TABLE_VA) & M64
            tag = "default or %#x" % (NICHE + 0x12) if slot == 5 else "%#x" % (NICHE + 13 + slot)
            table.write("%d\t%s\t%#x\t%d\n" % (slot, tag, target, start <= target < end))
    with open(out / "constants.tsv", "w") as table:
        table.write("name\tva\tbytes\n")
        for name, va, count in (("empty-code-hash-low-half", 0x4537F0, 16), ("empty-code-hash-high-half", 0x452020, 16), ("default-code-hash", 0x4585A0, 32)):
            table.write("%s\t%#x\t%s\n" % (name, va, image_bytes(image, va, count).hex()))
        for slot, name in sorted((value, key) for key, value in GOT.items()):
            table.write("got-%s\t%#x\t%#x\n" % (name, slot, image.relative().get(slot, 0)))
    with open(out / "layout.tsv", "w") as table:
        table.write("object\toffset\tsize\tmeaning\n")
        for row in LAYOUT:
            table.write("%s\t%#x\t%d\t%s\n" % row)
    with open(out / "contracts.tsv", "w") as table:
        table.write("name\ttarget\tcontract\n")
        for name, text in CONTRACTS:
            va = DIRECT.get(name) or GOT.get(name)
            table.write("%s\t%#x\t%s\n" % (name, va, text))
    mutants = mutant_list(image, executed)
    detected, missed = 0, []
    with open(out / "controls.tsv", "w") as controls:
        controls.write("va\tbyte\tnew\tkind\tfunction\tdetected\treason\tcase\tstage\n")
        for patch in mutants:
            hit, reason, index, stage = detect(image, [detect_sets, second_sets], patch)
            controls.write("%#x\t%d\t%#x\t%s\t%s\t%d\t%s\t%d\t%d\n" % (patch[0], patch[1], patch[2], patch[3], patch[4], hit, reason, index, stage))
            if hit:
                detected += 1
            else:
                missed.append(patch)
    with open(out / "equivalent-mutants.tsv", "w") as table:
        table.write("va\tbyte\tnew\tkind\tfunction\treason\n")
        for patch in missed:
            table.write("%#x\t%d\t%#x\t%s\t%s\t%s\n" % (patch[0], patch[1], patch[2], patch[3], patch[4], equivalent_reason(image, patch, executed)))
    measure = dict(cases=total, negative_controls=len(mutants), negative_detected=detected, equivalent=len(missed))
    (out / "measure.json").write_text(json.dumps(measure, indent=1, sort_keys=True) + "\n")
    summary = dict(binary_sha256=SHA256, functions={name: hex(start) for start, name in FUNCTIONS}, cases=CASES, detect_cases=DETECT, second_stage=SECOND,
                   executed_instructions=len(executed),
                   callees_stubbed={name: hex(va) for name, va in sorted(DIRECT.items()) if name not in ("pair", "record_at", "map_insert", "map_finish")},
                   real_functions={name: hex(start) for start, name in FUNCTIONS})
    (out / "summary.json").write_text(json.dumps(summary, indent=1, sort_keys=True) + "\n")


def equivalent_reason(image, patch, executed):
    """Reasons are decided from the decoded bytes: a mutated instruction of the twin accessor only changes a return value that the one
    caller drops (the instruction after the call does not read rax)."""
    if patch[4] == "record-at-twin":
        rows = function_rows(image, PAIR_FN)
        for index, row in enumerate(rows):
            if row.op == "call" and row.target == DIRECT["map_finish"]:
                following = rows[index + 1]
                if following.op == "mov" and following.a == ("r", RDI) and following.b[0] == "r" and following.b[1] != RAX:
                    return "return value of 0x4da8e10 dropped at %#x: next instruction %#x only overwrites rdi from another register" % (row.va, following.va)
    if patch[4] == "char-search" and 0x43CD2E4 <= patch[0] < 0x43CD400:
        return ("word-at-a-time accelerator of the char searcher: a changed mask, bound, alignment or loop test only moves the hand-over to the "
                "byte loop, which finds the same first match")
    if patch[4] == "char-search" and patch[0] in (0x43CD40B, 0x43CD489):
        return "reload of the haystack length after the accelerator; it only feeds the finger > length test, which the entry guard back <= length already excludes"
    if patch[4] == "set-has" and patch[0] == 0x4EF4389:
        return "loads the found slot's index into rdx, the second return word; the only caller (0x55c131d) compares rax alone"
    return "OPEN: executed, no separating case"


LAYOUT = [
    ("action", 0, 8, "tag word: values 0x800000000000000d..0x13 pick jump-table slots 0..4,5,6; any value <= 0x800000000000000c is the default arm"),
    ("action (slots 0,2,3,4)", 8, 24, "String: capacity, pointer, length (length must be below 0x65 for slots 0 and 3)"),
    ("action (slots 3,4)", 0x20, 1, "flag byte"),
    ("action (slot 2)", 0x20, 20, "20-byte value stored with the 24-byte key in the map at state+0x338"),
    ("action (slot 1)", 8, 21, "one-byte kind followed by a 20-byte address, passed whole to the emitter with record tag 0x2d"),
    ("action (slot 6)", 8, 8, "vector position, bounds checked against state+0xb8"),
    ("action (slot 6)", 0x10, 20, "A; B at 0x24, C at 0x38, D at 0x4c (4 pad bytes after each)"),
    ("action (slot 5)", 0, 0xB0, "whole action copied by memcpy and handed to 0x55cfe90 with a zeroed 20-byte value"),
    ("state", 0xB0, 8, "pointer to the first element of a vector"),
    ("state", 0xB8, 8, "vector length"),
    ("state element 0", 0x12C, 1, "must be 1 (else error 0x167)"),
    ("state element 0", 0x12D, 20, "address D must differ from this (else error 0x168)"),
    ("state", 0x338, 8, "map receiving slot-2 insertions through 0x4dd59a0"),
    ("state", 0x398, 8, "map searched and extended by the pair registration"),
    ("state", 0x7C0, 8, "table behind the name lookups (slots 0, 3, 4)"),
    ("state", 0x968, 8, "set of already registered C addresses"),
    ("state", 0x1108, 8, "account table; its 32-byte code hash must equal the empty-code hash"),
    ("dex object", 0x10, 8, "third word of the iteration record passed to 0x5acc8c0"),
    ("dex object", 0x378, 8, "0x8000000000000000 means absent (error 0x156)"),
    ("dex object", 0x408, 8, "must be 0x8000000000000001 for slot 4 (else error 0x1a1)"),
    ("dex object", 0x468, 1, "written 2 (flagged) or 0 by slot 3"),
    ("result block", 0, 2, "tag; 0x1a2 is success; the other tags the bodies write themselves: 0xfa 0x101 0x156 0x158 0x166 0x167 0x168 0x169 0x1a1"),
    ("result block", 8, 8, "payload word of a success from the callees; position for tag 0xfa"),
    ("pair parameter", 0, 8, "index (zero gives 0x101)"),
    ("pair parameter", 8, 20, "A; B at 0x1c, C at 0x30, D at 0x44"),
]

CONTRACTS = [
    ("lookup_a", "(table, ptr, len) -> result; success payload is a table value forwarded to the asset callee"),
    ("asset", "(name ptr, name len, value) -> result; success payload is the packed asset number"),
    ("emit", "(state, record) -> result written straight to the output"),
    ("rec_check", "(cap, ptr, len) -> result"),
    ("btree_insert", "(map, key 24 bytes, value 20 bytes); the Option result is unused"),
    ("lookup_b", "(table, ptr, len) -> result with a dex object pointer"),
    ("post", "(state, cap, ptr, len) -> result with a dex object pointer"),
    ("flag", "(object+0x378, amount) -> result whose byte at +8 is compared with 2"),
    ("divide", "(table, amount div 10000) -> table value"),
    ("finish", "(table value, amount, flag 1 or 2) -> result"),
    ("vec_of", "(dex, 0, dex word 0x10) -> Vec<u64> (cap, ptr, len)"),
    ("per_elem", "(state, element)"),
    ("dealloc", "(ptr, size, align)"),
    ("memcpy", "(dst, src, count)"),
    ("memcmp", "(left, right, count) -> 0 when equal"),
    ("memchr", "(byte, ptr, len) -> (found, index in rdx); only the needle-size >= 5 branch calls it"),
    ("slice_panic", "(0, bound, 4, location) diverges; reached only when a needle of five bytes or more matches"),
    ("drop", "(0xb0-byte action copy)"),
    ("big", "(state, zero 20 bytes, 0xb0-byte action copy) -> result"),
    ("cdd30", "(state, 20-byte address, 0 or 1) -> result"),
    ("account", "(account table, 20-byte address) -> block; byte +0x28 bit 0 selects the hash at +0x29 over the default hash"),
    ("hash_key", "(hasher word 1, hasher word 2, 20-byte key) -> 64-bit hash"),
    ("table_find", "(table, hash, probe {key, entries, count}) -> slot pointer or 0; the word before the slot is read"),
    ("map_find", "(map, 0) -> block: byte 0 present flag, 32 payload bytes at +8"),
    ("tree_insert", "(0x28-byte vacant handle) -> four words; the new value is not passed"),
    ("ring_insert", "(ring, index, 8-byte extra word plus 0xa0-byte record); raises the ring length by one"),
    ("panic_str", "(message, length, location) diverges"),
    ("panic", "(location) diverges"),
]

if __name__ == "__main__":
    raise SystemExit(main())
