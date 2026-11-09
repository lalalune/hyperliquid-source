#!/usr/bin/env python3
"""Reconstruct and verify the BLAKE2 F compression precompile of node #115.

The tool carries a small offline x86-64 interpreter (Image, decode, Memory, Machine) and uses it to run the recorded run body, the
provider dispatcher and the portable compression body on bytes read from the ELF file. A pure Python model of the same behaviour is
compared with every run. The binary is never executed.

    python3 tools/evm_blake2f_compress115.py --out research/work-items/evm-blake2f-compress-115
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
        self.rel = image.relative()

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
        if count == 8 and addr in self.rel:
            return self.rel[addr].to_bytes(8, "little")
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
        self.hook_pcs = {}

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
            hook = self.hook_pcs.get(pc)
            if hook is not None:
                pc = hook(self)
                continue
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




# ---------------------------------------------------------------------------------------------------------------------
# Packet part: BLAKE2 F compression precompile (EIP-152 shape) of node #115.
# ---------------------------------------------------------------------------------------------------------------------

import argparse
import hashlib as stdlib_hashlib
import json
import os

RUN = 0x5C16650          # run(out, input_ptr, input_len, gas_limit)
DISPATCH = 0x5BEBAC0     # provider slot +0x58: (rounds, h, m, t, f)
COMPRESS = 0x5C38870     # portable BLAKE2b F body
AVX2_BODY = 0x5C37750    # vector-instruction arm of the dispatcher (not decodable by the shared core)
PROVIDER_INIT = 0x5BEE2D3
VTABLE = 0x64BFF60
CELL = 0x64FE3D8         # lazily initialised provider cell: data, vtable, state word at +0x10
CELL_STATE = CELL + 0x10
FLAG_POINTER_SLOT = 0x64DFA60   # RELATIVE slot -> feature word cell
FLAG_INIT_SLOT = 0x64DFA68      # RELATIVE slot -> cpu feature initialiser
ALLOC_SLOT = 0x64DF480          # RELATIVE slot -> allocator entry
VTABLE_EVEN_SLOT = 0x64DF8C0
VTABLE_ODD_SLOT = 0x64DF8C8
SLOT_COUNT = 21

ALLOC_ERROR_SLOT = 0x64DF498    # RELATIVE slot -> allocation-failure handler


class AllocationFailure(Exception):
    def __init__(self, size, align):
        super().__init__("allocation failure")
        self.size = size
        self.align = align


ERR_BASE = 0x8000000000000000
ERR_OUT_OF_GAS = ERR_BASE + 1
ERR_LENGTH = ERR_BASE + 2
ERR_FLAG = ERR_BASE + 3

HEAP_IN = HEAP_BASE + 0x1000
HEAP_OUT = HEAP_BASE + 0x2000
HEAP_H = HEAP_BASE + 0x3000
HEAP_M = HEAP_BASE + 0x3100
HEAP_T = HEAP_BASE + 0x3200
HEAP_ALLOC = HEAP_BASE + 0x10000
HEAP_USED = 0x12000
U64 = (1 << 64) - 1

IV = (0x6A09E667F3BCC908, 0xBB67AE8584CAA73B, 0x3C6EF372FE94F82B, 0xA54FF53A5F1D36F1,
      0x510E527FADE682D1, 0x9B05688C2B3E6C1F, 0x1F83D9ABFB41BD6B, 0x5BE0CD19137E2179)
SIGMA = (
    (0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15), (14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3),
    (11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4), (7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8),
    (9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13), (2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9),
    (12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11), (13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10),
    (6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5), (10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0))


def rotr(value, count):
    return (value >> count | value << (64 - count)) & U64


class Rng:
    """SplitMix64: the same sequence on every Python version."""

    def __init__(self, seed):
        self.state = seed & U64

    def next(self):
        self.state = (self.state + 0x9E3779B97F4A7C15) & U64
        z = self.state
        z = (z ^ z >> 30) * 0xBF58476D1CE4E5B9 & U64
        z = (z ^ z >> 27) * 0x94D049BB133111EB & U64
        return z ^ z >> 31

    def below(self, bound):
        return self.next() % bound

    def blob(self, count):
        out = bytearray()
        while len(out) < count:
            out += self.next().to_bytes(8, "little")
        return bytes(out[:count])


# ----------------------------------------------------------------------------- reconstruction (pure functions)

MUTATIONS = ()


def blake2_f(rounds, h, m, t, f, mut=None):
    """BLAKE2b F: rounds is unbounded, sigma row is rounds mod 10, any non-zero f is the final-block flag."""
    sigma = SIGMA
    if mut == "sigma-swap-rows-3-4":
        sigma = SIGMA[:3] + (SIGMA[4], SIGMA[3]) + SIGMA[5:]
    elif mut == "sigma-last-entry":
        sigma = SIGMA[:9] + (SIGMA[9][:15] + (1,),)
    iv = list(IV)
    if mut == "iv0-bit":
        iv[0] ^= 1
    elif mut == "iv7-bit":
        iv[7] ^= 1 << 63
    v = list(h) + iv
    if mut != "t0-ignored":
        v[12] ^= t[0]
    if mut != "t1-ignored":
        v[13] ^= t[1]
    if mut == "flag-only-one":
        invert = f == 1
    else:
        invert = f != 0
    if mut == "flag-inverts-v15":
        if invert:
            v[15] ^= U64
    elif mut != "flag-ignored" and invert:
        v[14] ^= U64
    r24, r16, r32, r63 = (23 if mut == "rot24-23" else 24), (15 if mut == "rot16-15" else 16), \
        (31 if mut == "rot32-31" else 32), (62 if mut == "rot63-62" else 63)
    total = rounds + 1 if mut == "rounds-plus-one" else rounds
    for r in range(total):
        if mut == "sigma-index-mod-12":
            s = sigma[r % 12 % 10]
        elif mut == "sigma-index-mod-9":
            s = sigma[r % 9]
        else:
            s = sigma[r % 10]
        for k, (a, b, c, d) in enumerate(((0, 4, 8, 12), (1, 5, 9, 13), (2, 6, 10, 14), (3, 7, 11, 15),
                                           (0, 5, 10, 15), (1, 6, 11, 12), (2, 7, 8, 13), (3, 4, 9, 14))):
            x, y = m[s[2 * k]], m[s[2 * k + 1]]
            v[a] = (v[a] + v[b] + x) & U64
            v[d] = rotr(v[d] ^ v[a], r32)
            v[c] = (v[c] + v[d]) & U64
            v[b] = rotr(v[b] ^ v[c], r24)
            v[a] = (v[a] + v[b] + y) & U64
            v[d] = rotr(v[d] ^ v[a], r16)
            v[c] = (v[c] + v[d]) & U64
            v[b] = rotr(v[b] ^ v[c], r63)
    if mut == "no-upper-half-xor":
        return [h[i] ^ v[i] for i in range(8)]
    return [h[i] ^ v[i] ^ v[i + 8] for i in range(8)]


def words(data, big=False):
    return [int.from_bytes(data[i:i + 8], "big" if big else "little") for i in range(0, len(data), 8)]


def pack(values, big=False):
    return b"".join(x.to_bytes(8, "big" if big else "little") for x in values)


def run_model(data, gas_limit, mut=None):
    """Result of the run body: ('err', code) or ('ok', output, gas_used). Check order: length, gas, flag."""
    need = 212 if mut == "length-212" else 213
    if (len(data) >= need) if mut == "length-ge" else (len(data) != need):
        return ("err", ERR_LENGTH if mut != "error-swap-length-gas" else ERR_OUT_OF_GAS)
    rounds = int.from_bytes(data[0:4], "little" if mut == "rounds-little" else "big")
    flag = data[212] if len(data) > 212 else 0
    short = gas_limit <= rounds if mut == "gas-le" else gas_limit < (rounds - 1 if mut == "gas-minus-one" else rounds)
    bad_flag = flag > 2 if mut == "flag-gt-2" else flag >= 2
    if mut == "flag-before-gas" and bad_flag:
        return ("err", ERR_FLAG)
    if short:
        return ("err", ERR_OUT_OF_GAS if mut != "error-swap-length-gas" else ERR_LENGTH)
    if bad_flag:
        return ("err", ERR_FLAG if mut != "error-flag-2" else ERR_BASE + 2)
    if mut is not None:
        data = data.ljust(213, b"\0")
    off = 3 if mut == "h-offset-3" else 4
    h = words(data[off:off + 64])
    m = words(data[68:196], big=mut == "m-big-endian")
    t = words(data[196:208]) + [] if mut == "t-short" else words(data[196:212])
    if mut == "t-short":
        t = [t[0], 0]
    out = [0] * 8 if mut is not None and rounds > 4096 else blake2_f(rounds, h, m, t, flag, mut)
    gas = rounds + 1 if mut == "gas-used-plus-one" else (0 if mut == "gas-used-zero" else rounds)
    return ("ok", pack(out, big=mut == "output-big-endian"), gas)


MODEL_MUTANTS = (
    "sigma-swap-rows-3-4", "sigma-last-entry", "sigma-index-mod-12", "sigma-index-mod-9", "rot24-23", "rot16-15",
    "rot32-31", "rot63-62", "iv0-bit", "iv7-bit", "t0-ignored", "t1-ignored", "flag-ignored", "flag-inverts-v15",
    "no-upper-half-xor", "rounds-plus-one", "gas-le", "gas-minus-one", "length-212", "length-ge", "flag-gt-2",
    "flag-before-gas", "rounds-little", "gas-used-plus-one", "gas-used-zero", "output-big-endian", "m-big-endian",
    "error-swap-length-gas", "error-flag-2", "h-offset-3", "t-short")
DIRECT_MUTANTS = ("flag-only-one",)

MUTANT_NOTES = {
    "sigma-swap-rows-3-4": "message schedule rows 3 and 4 exchanged",
    "sigma-last-entry": "last entry of schedule row 9 replaced",
    "sigma-index-mod-12": "round index reduced modulo 12 before modulo 10",
    "sigma-index-mod-9": "schedule row index reduced modulo 9",
    "rot24-23": "second rotation 24 replaced by 23",
    "rot16-15": "third rotation 16 replaced by 15",
    "rot32-31": "first rotation 32 replaced by 31",
    "rot63-62": "fourth rotation 63 replaced by 62",
    "iv0-bit": "low bit of IV word 0 flipped",
    "iv7-bit": "high bit of IV word 7 flipped",
    "t0-ignored": "low offset counter word not mixed into v12",
    "t1-ignored": "high offset counter word not mixed into v13",
    "flag-ignored": "final flag never inverts v14",
    "flag-inverts-v15": "final flag inverts v15 instead of v14",
    "no-upper-half-xor": "output omits the v[i+8] term",
    "rounds-plus-one": "one extra round",
    "gas-le": "gas test uses less-or-equal",
    "gas-minus-one": "gas test compares against rounds minus one",
    "length-212": "length check accepts 212",
    "length-ge": "length check accepts anything at least 213",
    "flag-gt-2": "flag limit is above 2 instead of at least 2",
    "flag-before-gas": "flag check runs before the gas check",
    "rounds-little": "rounds read little-endian",
    "gas-used-plus-one": "gas used is rounds plus one",
    "gas-used-zero": "gas used is zero",
    "output-big-endian": "output words written big-endian",
    "m-big-endian": "message words read big-endian",
    "error-swap-length-gas": "length and out-of-gas codes exchanged",
    "error-flag-2": "flag error code is the length code",
    "h-offset-3": "chaining words read from offset 3",
    "t-short": "only eight counter bytes read",
    "flag-only-one": "compression treats only the value 1 as final",
}


# ----------------------------------------------------------------------------- machine harness

class Rig:
    """One machine configured for the run body, the dispatcher or the compression body."""

    def __init__(self, image, patches=None):
        self.image = image
        self.m = Machine(image, patches)
        self.rel = image.relative()
        self.m.real = frozenset({RUN, DISPATCH, COMPRESS})
        self.alloc_slot = self.rel[ALLOC_SLOT]
        self.flag_init = self.rel[FLAG_INIT_SLOT]
        self.flag_cell = self.rel[FLAG_POINTER_SLOT]
        self.even_vtable = self.rel[VTABLE_EVEN_SLOT]
        self.odd_vtable = self.rel[VTABLE_ODD_SLOT]
        self.m.slots[self.alloc_slot] = self.hook_alloc
        self.alloc_error_target = self.rel[ALLOC_ERROR_SLOT]
        self.m.slots[self.alloc_error_target] = self.hook_alloc_error
        self.branches = {}
        plain = self.m.step

        def step(row):
            pc = plain(row)
            if row.op == "jcc":
                seen = self.branches.setdefault(row.va, [0, 0])
                seen[pc == row.target] += 1
            return pc

        self.m.step = step
        self.m.slots[self.flag_init] = self.hook_flag_init
        self.m.calls[PROVIDER_INIT] = self.hook_provider_init
        self.m.hook_pcs[AVX2_BODY] = self.hook_avx2
        self.parity = 0
        self.route = []
        self.alloc_sizes = []
        self.next_alloc = HEAP_ALLOC
        self.init_flag_value = 1

    # hooks: each stands for a callee outside the scope; the packet pins its arguments and result only
    def hook_alloc(self, m):
        self.alloc_sizes.append(m.regs[RDI])
        if self.parity == 2:
            m.regs[RAX] = 0
            return
        ptr = self.next_alloc + self.parity
        self.next_alloc += 0x100
        m.regs[RAX] = ptr

    def hook_alloc_error(self, m):
        raise AllocationFailure(m.regs[RDI], m.regs[RSI])

    def hook_flag_init(self, m):
        self.route.append("feature-init")
        m.memory.statics[self.flag_cell] = self.init_flag_value

    def hook_provider_init(self, m):
        self.route.append("provider-init")
        m.memory.statics[CELL] = 1
        m.memory.statics[CELL + 8] = VTABLE
        m.memory.statics[CELL_STATE] = 0

    def hook_avx2(self, m):
        rounds, f = m.regs[RDI] & 0xFFFFFFFF, m.regs[R8] & 0xFFFFFFFF
        self.route.append("avx2(%d,%d)" % (rounds, f))
        h = words(m.memory.bytes_at(m.regs[RSI], 64))
        mm = words(m.memory.bytes_at(m.regs[RDX], 128))
        t = words(m.memory.bytes_at(m.regs[RCX], 16))
        m.memory.put_bytes(m.regs[RSI], pack(blake2_f(rounds, h, mm, t, f)))
        return m.pop()

    def prepare(self, state, flag_word, parity):
        mem = self.m.memory
        mem.reset(HEAP_USED)
        mem.statics.clear()
        mem.statics[CELL] = 1
        mem.statics[CELL + 8] = VTABLE
        mem.statics[CELL_STATE] = state
        mem.statics[self.flag_cell] = flag_word
        self.parity = parity
        self.route = []
        self.alloc_sizes = []
        self.next_alloc = HEAP_ALLOC
        self.init_flag_value = 1 if flag_word == 0 else flag_word
        self.m.hook_count = 0

    def call_run(self, data, gas_limit, scenario, parity):
        state, flag_word = SCENARIOS[scenario]
        self.prepare(state, flag_word, parity)
        mem = self.m.memory
        mem.put_bytes(HEAP_IN, data)
        try:
            returned = self.m.run(RUN, {RDI: HEAP_OUT, RSI: HEAP_IN, RDX: len(data), RCX: gas_limit})
        except AllocationFailure as failure:
            return ("alloc-failure", failure.size, failure.align, ",".join(self.route) or "-")
        if returned != HEAP_OUT:
            raise Halt("run body did not return the out pointer")
        q = [mem.read(HEAP_OUT + 8 * i, 8) for i in range(5)]
        route = ",".join(self.route) or "-"
        if q[0] == 0:
            return ("err", q[1], route, len(self.alloc_sizes))
        body = mem.bytes_at(q[1], q[2])
        return ("ok", body, q[4], q[0], q[1], q[2], q[3], route, tuple(self.alloc_sizes))

    def call_compress(self, rounds, h, mm, t, f):
        self.prepare(0, 1, 0)
        mem = self.m.memory
        mem.put_bytes(HEAP_H, pack(h))
        mem.put_bytes(HEAP_M, pack(mm))
        mem.put_bytes(HEAP_T, pack(t))
        self.m.run(COMPRESS, {RDI: rounds, RSI: HEAP_H, RDX: HEAP_M, RCX: HEAP_T, R8: f})
        return words(mem.bytes_at(HEAP_H, 64))


# scenario -> (provider state word, feature word cell)
SCENARIOS = {0: (0, 0x0001), 1: (0, 0x0000), 2: (0, 0x8001), 3: (3, 0x0001)}
SCENARIO_NAMES = {0: "portable", 1: "feature-init-portable", 2: "vector-arm", 3: "provider-init-portable"}


def expected_run(rig, data, gas_limit, scenario, parity, mut=None):
    """Model of the whole call including provider routing, allocation and the Bytes layout."""
    result = run_model(data, gas_limit, mut)
    if result[0] == "err":
        return ("err", result[1], "-", 0)
    rounds = int.from_bytes(data[0:4], "big")
    flag = data[212] if len(data) > 212 else 0
    route = []
    if scenario == 3:
        route.append("provider-init")
    if scenario == 1:
        route.append("feature-init")
    if scenario == 2:
        route.append("avx2(%d,%d)" % (rounds, 1 if flag else 0))
    if parity == 2:
        return ("alloc-failure", 1, 0x40, ",".join(route) or "-")
    ptr = HEAP_ALLOC + parity
    vtable = rig.odd_vtable if parity else rig.even_vtable
    return ("ok", result[1], result[2], vtable, ptr, 0x40, ptr | 1, ",".join(route) or "-", (0x40,))


def ok_summary(row):
    if row[0] == "alloc-failure":
        return "alloc-failure:%d:%d:%s" % row[1:]
    if row[0] == "err":
        return "err:%x:%s:%d" % (row[1], row[2], row[3])
    return "ok:%s:%d:%x:%x:%x:%x:%s:%s" % (row[1].hex(), row[2], row[3], row[4], row[5], row[6], row[7],
                                             ",".join(str(x) for x in row[8]))


# ----------------------------------------------------------------------------- case generation

def make_input(rounds, h, mm, t, flag):
    return rounds.to_bytes(4, "big") + h + mm + t + bytes([flag])


def run_cases():
    """Yield (kind, data, gas_limit, scenario, parity) deterministically."""
    rng = Rng(0x115B1A4E2F0)
    n = 0
    for i in range(700):  # wrong lengths
        length = rng.below(213) if i % 2 else 214 + rng.below(200)
        if i % 50 == 0:
            length = (0, 1, 4, 212, 213 + 1, 4 + 64 + 128 + 16)[i // 50 % 6]
        if length == 213:
            length = 212
        yield ("length", rng.blob(length), rng.next() if i % 3 else rng.below(20), i % 4, i % 2)
    for i in range(700):  # gas below rounds, valid length, flag of any value
        rounds = rng.next() & 0xFFFFFFFF if i % 3 else rng.below(30)
        short = 1 + rng.below(3)
        gas = max(0, rounds - short) if i % 5 else 0
        if rounds == 0:
            gas = 0
            rounds = 1
        data = make_input(rounds, rng.blob(64), rng.blob(128), rng.blob(16), rng.below(256) if i % 2 else rng.below(2))
        yield ("gas", data, gas, i % 4, i % 2)
    for i in range(700):  # flag byte 2..255 with sufficient gas
        rounds = rng.next() & 0xFFFFFFFF if i % 3 == 0 else rng.below(13)
        gas = U64 if i % 7 == 0 else rounds + rng.below(4)
        data = make_input(rounds, rng.blob(64), rng.blob(128), rng.blob(16), 2 + rng.below(254))
        yield ("flag", data, gas, i % 4, i % 2)
    for i in range(5800):  # accepted calls
        rounds = (0, 1, 2, 10, 11, 12)[i % 6] if i % 3 == 0 else rng.below(13)
        if i % 29 == 0:
            rounds = 13 + rng.below(20)
        gas = rounds if i % 2 else rounds + rng.below(1 << 20)
        if i % 41 == 0:
            gas = U64
        h = rng.blob(64)
        mm = rng.blob(128)
        t = rng.blob(16)
        if i % 13 == 0:
            h, mm, t = bytes(64), bytes(128), bytes(16)
        if i % 17 == 0:
            h, mm = b"\xff" * 64, b"\xff" * 128
        yield ("accept", make_input(rounds, h, mm, t, (i // 4) & 1), gas, i % 4, (i // 8) & 1)
    for i in range(240):  # allocation failure after a valid call
        rounds = rng.below(8)
        yield ("alloc-failure", make_input(rounds, rng.blob(64), rng.blob(128), rng.blob(16), i & 1), rounds + (i >> 2), i % 4, 2)
    for length in range(129):  # single-block digests: the compression equals the standard library digest
        yield ("digest", None, length, 0, 0)


def compress_cases():
    rng = Rng(0x115C0FFEE)
    for i in range(3200):
        rounds = rng.below(41) if i % 5 else (0, 1, 9, 10, 11, 12, 13, 20)[i % 8]
        f = (0, 1, 2, 255, 0x100, 0x80000000, 0xFFFFFFFF, rng.next() & 0xFFFFFFFF)[i % 8]
        h = [rng.next() for _ in range(8)]
        mm = [rng.next() for _ in range(16)]
        t = [rng.next(), rng.next()]
        if i % 11 == 0:
            h, mm, t = [0] * 8, [0] * 16, [0, 0]
        if i % 19 == 0:
            h, mm, t = [U64] * 8, [U64] * 16, [U64, U64]
        yield (rounds, h, mm, t, f)


def digest_case(length):
    message = bytes((7 * i + length) & 0xFF for i in range(length))
    h = list(IV)
    h[0] ^= 0x01010040
    block = message + bytes(128 - length)
    data = make_input(12, pack(h), block, length.to_bytes(8, "little") + bytes(8), 1)
    return data, stdlib_hashlib.blake2b(message).digest()


# ----------------------------------------------------------------------------- byte-corruption controls

def corruption_controls(image):
    """(label, va, xor mask) triples; each flips bits of exactly one recorded code byte."""
    rows = decode_range(image, COMPRESS, COMPRESS + 0x4F0)
    rot = []
    seen = set()
    for row in rows:
        if row.op in ("rol", "ror") and row.b is not None and row.b[0] == "i" and row.b[1] not in seen:
            seen.add(row.b[1])
            rot.append(row)
    out = [
        ("run: length constant 0xd5 off by one", RUN + 0x10, 0x01),
        ("run: bswap ebx becomes bswap edx (rounds byte order)", RUN + 0x19, 0x01),
        ("run: jae gas test becomes jb", RUN + 0x1D, 0x01),
        ("run: out-of-gas code 1 becomes 0", RUN + 0x21, 0x01),
        ("run: out-of-gas code 1 becomes 3", RUN + 0x21, 0x02),
        ("run: wrong-length base code 1 becomes 3", RUN + 0x2D, 0x02),
        ("run: flag limit 2 becomes 3", RUN + 0x5E, 0x01),
        ("run: flag byte offset 0xd4 becomes 0xd5", RUN + 0x57, 0x01),
        ("run: h source offset 4 becomes 5", RUN + 0x6B, 0x01),
        ("run: m source offset 0x44 becomes 0x45", RUN + 0x8F, 0x01),
        ("run: vtable slot 0x58 becomes 0x59", RUN + 0x13E, 0x01),
        ("run: output length 0x40 becomes 0x41", RUN + 0x1C3, 0x01),
        ("run: gas-used store offset 0x20 becomes 0x21", RUN + 0x1D1, 0x01),
        ("run: pointer tag or-mask 1 becomes 3", RUN + 0x1A2, 0x02),
        ("dispatch: js becomes jns", DISPATCH + 0x2C, 0x01),
        ("dispatch: first argument move source", DISPATCH + 0xC, 0x02),
        ("dispatch: flag zero-extend byte move", DISPATCH + 0x1F, 0x01),
        ("compress: iv0 low byte", 0x5C3896D, 0x01),
        ("compress: iv1 low byte", 0x5C38885, 0x01),
        ("compress: iv2 low byte", 0x5C3895E, 0x01),
        ("compress: iv3 low byte", 0x5C3888F, 0x01),
        ("compress: iv4 low byte", 0x5C388AB, 0x01),
        ("compress: iv5 low byte", 0x5C388BC, 0x01),
        ("compress: iv6 low byte", 0x5C388E0, 0x01),
        ("compress: iv7 low byte", 0x5C3889E, 0x01),
        ("compress: flagged iv6 low byte", 0x5C388D6, 0x01),
    ]
    repeats = [row for row in rows if row.op in ("rol", "ror") and row.b is not None and row.b[0] == "i"]
    for row in rot + repeats[3::9][:8]:
        label = ("compress: rotate by %d at %#x, count byte +1" % (row.b[1], row.va)) if row.b[1] > 1 else \
            ("compress: rotate by one at %#x, register byte +1" % row.va)
        out.append((label, row.va + row.size - 1, 0x01))
    return out


# ----------------------------------------------------------------------------- evidence

class Counter:
    def __init__(self):
        self.cases = 0
        self.by_kind = {}
        self.chain = stdlib_hashlib.sha256()

    def add(self, kind, summary):
        self.cases += 1
        self.by_kind[kind] = self.by_kind.get(kind, 0) + 1
        self.chain.update(summary.encode() + b"\n")


def evaluate_run_cases(image, sink):
    """Run every case once on the real bytes; compare with the model and with every mutated model."""
    rig = Rig(image)
    detected = {name: 0 for name in MODEL_MUTANTS}
    first_case = {}
    counter = Counter()
    for index, (kind, data, gas, scenario, parity) in enumerate(run_cases()):
        if kind == "digest":
            data, reference = digest_case(gas)
            gas = 12
        else:
            reference = None
        actual = rig.call_run(data, gas, scenario, parity)
        want = expected_run(rig, data, gas, scenario, parity)
        if actual != want:
            raise EvidenceError("model differs from the bytes at case %d (%s)" % (index, kind))
        if reference is not None and actual[1] != reference:
            raise EvidenceError("digest anchor differs at case %d" % index)
        summary = ok_summary(actual)
        counter.add(kind, summary)
        for name in MODEL_MUTANTS:
            if expected_run(rig, data, gas, scenario, parity, name) != actual:
                detected[name] += 1
                first_case.setdefault(name, index)
        sink(index, kind, data, gas, scenario, parity, actual, summary)
    return counter, detected, first_case, rig


def evaluate_compress_cases(image, sink):
    rig = Rig(image)
    counter = Counter()
    detected = 0
    for index, (rounds, h, mm, t, f) in enumerate(compress_cases()):
        actual = rig.call_compress(rounds, h, mm, t, f)
        want = blake2_f(rounds, h, mm, t, f)
        if actual != want:
            raise EvidenceError("compression model differs from the bytes at case %d" % index)
        if blake2_f(rounds, h, mm, t, f, "flag-only-one") != actual:
            detected += 1
        summary = "c:%d:%x:%s" % (rounds, f, pack(actual).hex())
        counter.add("compress", summary)
        sink(index, rounds, f, summary)
    return counter, detected, rig


def control_suite():
    """A fixed set of calls that exercises every byte-corruption control."""
    rng = Rng(0xC0DE115)
    suite = []
    for scenario in range(4):
        for parity in (0, 1):
            suite.append((make_input(12, rng.blob(64), rng.blob(128), rng.blob(16), 1), 12, scenario, parity))
            suite.append((make_input(3, rng.blob(64), rng.blob(128), rng.blob(16), 0), 5, scenario, parity))
            suite.append((make_input(4, rng.blob(64), rng.blob(128), rng.blob(16), 0), 3, scenario, parity))
            suite.append((make_input(2, rng.blob(64), rng.blob(128), rng.blob(16), 7), 9, scenario, parity))
            suite.append((make_input(2, rng.blob(64), rng.blob(128), rng.blob(16), 2), 9, scenario, parity))
            suite.append((rng.blob(20 + scenario), 9, scenario, parity))
            suite.append((make_input(0x0102, rng.blob(64), rng.blob(128), rng.blob(16), 0), 0x0103, scenario, parity))
    return suite


FAULTS = (Halt, EvidenceError, KeyError, IndexError, ValueError, OverflowError)


def run_corruption_controls(image, sink):
    suite = control_suite()
    direct = list(compress_cases())[:300]
    detected = 0
    for label, va, mask in corruption_controls(image):
        offset = image.offset(va)
        patched = image.blob[offset] ^ mask
        rig = Rig(image, {va: patched})
        how = "survived"
        for data, gas, scenario, parity in suite:
            want = expected_run(rig, data, gas, scenario, parity)
            try:
                actual = rig.call_run(data, gas, scenario, parity)
            except FAULTS as exc:
                how = "halt:" + type(exc).__name__
                break
            if actual != want:
                how = "result-differs"
                break
        if how == "survived":
            rig = Rig(image, {va: patched})
            for rounds, h, mm, t, f in direct:
                try:
                    if rig.call_compress(rounds, h, mm, t, f) != blake2_f(rounds, h, mm, t, f):
                        how = "compress-differs"
                        break
                except FAULTS:
                    how = "compress-halt"
                    break
        if how != "survived":
            detected += 1
        sink(label, va, image.blob[offset], patched, how)
    return detected


def vtable_rows(image):
    rel = image.relative()
    rows = []
    for index in range(SLOT_COUNT):
        slot = VTABLE + 8 * index
        if slot in rel:
            target = rel[slot]
            size = image.fde_ends[target] - target if target in image.fde_ends else 0
            rows.append((index * 8, slot, "relative", target, size))
        else:
            offset = image.offset(slot)
            rows.append((index * 8, slot, "raw", int.from_bytes(image.blob[offset:offset + 8], "little"), 0))
    return rows


def constant_rows(image):
    rows = []
    start, end = COMPRESS, image.fde_ends[COMPRESS]
    body = image.blob[image.offset(start):image.offset(start) + (end - start)]
    for index, word in enumerate(IV):
        needle = word.to_bytes(8, "little")
        spots = []
        at = body.find(needle)
        while at >= 0:
            spots.append(start + at)
            at = body.find(needle, at + 1)
        rows.append(("iv%d" % index, "0x%016x" % word, ",".join("%#x" % s for s in spots) or "-"))
    inverted = (IV[6] ^ U64).to_bytes(8, "little")
    at = body.find(inverted)
    rows.append(("iv6-inverted", "0x%016x" % (IV[6] ^ U64), "%#x" % (start + at) if at >= 0 else "-"))
    table = image.blob[image.offset(0x943C33):image.offset(0x943C33) + 160]
    rows.append(("round-table-160", stdlib_hashlib.sha256(table).hexdigest(), "0x943c33"))
    for name, va in (("run", RUN), ("dispatch", DISPATCH), ("compress", COMPRESS), ("vector-arm", AVX2_BODY)):
        rows.append(("fde-" + name, "%#x" % va, "%#x" % image.fde_ends[va]))
    rel = image.relative()
    for name, slot in (("alloc-slot", ALLOC_SLOT), ("feature-pointer-slot", FLAG_POINTER_SLOT),
                       ("feature-init-slot", FLAG_INIT_SLOT), ("bytes-even-slot", VTABLE_EVEN_SLOT),
                       ("bytes-odd-slot", VTABLE_ODD_SLOT), ("provider-cell-slot", 0x64EC358)):
        rows.append((name, "%#x" % slot, "%#x" % rel[slot]))
    cell = image.blob[image.offset(CELL):image.offset(CELL) + 0x20]
    rows.append(("provider-cell-initial", cell.hex(), "%#x" % CELL))
    rows.append(("provider-state-initial", "%d" % int.from_bytes(cell[0x10:0x14], "little"), "%#x" % CELL_STATE))
    try:
        decode_range(image, AVX2_BODY, AVX2_BODY + 0x20)
        decodable = "yes"
    except FAULTS:
        decodable = "no"
    rows.append(("vector-arm-decodable-by-core", decodable, "%#x" % AVX2_BODY))
    return rows


def branch_rows(image, rigs):
    """Every conditional jump of the three bodies with the arms the case sets reached."""
    rows = []
    for name, start, end in (("run", RUN, image.fde_ends[RUN]), ("dispatch", DISPATCH, image.fde_ends[DISPATCH]),
                             ("compress", COMPRESS, image.fde_ends[COMPRESS])):
        for row in decode_range(image, start, end):
            if row.op != "jcc":
                continue
            not_taken = sum(rig.branches.get(row.va, (0, 0))[0] for rig in rigs)
            taken = sum(rig.branches.get(row.va, (0, 0))[1] for rig in rigs)
            rows.append((name, row.va, row.target, row.cc, taken, not_taken))
    return rows


def write_lines(path, lines):
    with open(path, "w", encoding="ascii", newline="\n") as handle:
        for line in lines:
            handle.write(line + "\n")


def digest_rejected():
    """The loader must refuse bytes whose digest differs from the recorded one."""
    try:
        load_image(expected="0" * 64)
    except EvidenceError:
        return True
    return False


def build(out):
    out = pathlib.Path(out)
    out.mkdir(parents=True, exist_ok=True)
    image = load_image()
    case_lines = ["index\tkind\tscenario\tparity\tinput_len\tgas_limit\toutcome\tresult_sha256_16"]
    compress_lines = ["index\trounds\tflag_word\tresult_sha256_16"]

    def run_sink(index, kind, data, gas, scenario, parity, actual, summary):
        if (kind in ("accept", "alloc-failure") and index % 4) or (kind in ("length", "gas", "flag") and index % 2):
            return
        outcome = {"err": "err:%x" % actual[1] if actual[0] == "err" else "", "ok": "ok:gas=%d" % actual[2] if actual[0] == "ok" else "",
                   "alloc-failure": "alloc-failure"}[actual[0]]
        case_lines.append("%d\t%s\t%s\t%d\t%d\t%d\t%s\t%s" % (
            index, kind, SCENARIO_NAMES[scenario], parity, len(data), gas, outcome,
            stdlib_hashlib.sha256(summary.encode()).hexdigest()[:16]))

    def compress_sink(index, rounds, f, summary):
        if index % 4 == 0:
            compress_lines.append("%d\t%d\t%#x\t%s" % (index, rounds, f, stdlib_hashlib.sha256(summary.encode()).hexdigest()[:16]))

    counter, detected, first_case, run_rig = evaluate_run_cases(image, run_sink)
    ccounter, cdetected, compress_rig = evaluate_compress_cases(image, compress_sink)
    control_lines = ["control\tkind\tlocation\tdetected_by\tchange"]
    for name in MODEL_MUTANTS:
        how = "case %d (%d cases differ)" % (first_case[name], detected[name]) if detected[name] else "NOT DETECTED"
        control_lines.append("%s\tmodel-mutant\trun-cases\t%s\t%s" % (name, how, MUTANT_NOTES[name]))
    control_lines.append("flag-only-one\tmodel-mutant\tcompress-cases\t%s\t%s" % (
        "%d cases differ" % cdetected if cdetected else "NOT DETECTED", MUTANT_NOTES["flag-only-one"]))
    byte_rows = []

    def byte_sink(label, va, old, new, how):
        byte_rows.append("%s\tbyte-corruption\t%#x %02x->%02x\t%s\tone code byte" % (label, va, old, new, how))

    byte_detected = run_corruption_controls(image, byte_sink)
    control_lines.extend(byte_rows)
    digest_ok = digest_rejected()
    control_lines.append("binary-digest-corruption\tinput-corruption\texpected digest altered\t%s\tloader input" % (
        "load_image refuses" if digest_ok else "NOT DETECTED"))
    total = len(MODEL_MUTANTS) + len(DIRECT_MUTANTS) + len(byte_rows) + 1
    found = sum(1 for n in MODEL_MUTANTS if detected[n]) + (1 if cdetected else 0) + byte_detected + (1 if digest_ok else 0)
    write_lines(out / "cases.tsv", case_lines)
    write_lines(out / "compress-cases.tsv", compress_lines)
    write_lines(out / "controls.tsv", control_lines)
    branches = branch_rows(image, (run_rig, compress_rig))
    write_lines(out / "branches.tsv", ["body\tjump\ttarget\tcondition\ttaken\tnot_taken"] +
                ["%s\t%#x\t%#x\t%d\t%d\t%d" % row for row in branches])
    write_lines(out / "provider-vtable.tsv", ["offset\tslot\tkind\tvalue_or_target\tfde_size"] +
                ["%#x\t%#x\t%s\t%#x\t%d" % row for row in vtable_rows(image)])
    write_lines(out / "constants.tsv", ["name\tvalue\tlocation"] + ["\t".join(row) for row in constant_rows(image)])
    summary = {
        "binary_sha256": SHA256,
        "run_cases": counter.cases,
        "run_cases_by_kind": dict(sorted(counter.by_kind.items())),
        "compress_cases": ccounter.cases,
        "run_result_chain_sha256": counter.chain.hexdigest(),
        "compress_result_chain_sha256": ccounter.chain.hexdigest(),
        "scenarios": {str(k): v for k, v in sorted(SCENARIO_NAMES.items())},
        "model_mutants": len(MODEL_MUTANTS) + len(DIRECT_MUTANTS),
        "byte_corruptions": len(byte_rows),
        "conditional_jumps": len(branches),
        "jumps_with_both_arms": sum(1 for r in branches if r[4] and r[5]),
        "jumps_with_one_arm": sum(1 for r in branches if bool(r[4]) != bool(r[5])),
        "jumps_never_executed": sum(1 for r in branches if not r[4] and not r[5]),
    }
    write_lines(out / "summary.json", json.dumps(summary, indent=1, sort_keys=True).split("\n"))
    measure = {"cases": counter.cases + ccounter.cases, "negative_controls": total, "negative_detected": found, "equivalent": 0}
    write_lines(out / "measure.json", json.dumps(measure, indent=1, sort_keys=True).split("\n"))
    return measure


def main():
    parser = argparse.ArgumentParser(description="Regenerate the BLAKE2 F precompile evidence for node #115.")
    parser.add_argument("--out", required=True, help="evidence folder to regenerate")
    args = parser.parse_args()
    print(json.dumps(build(args.out), sort_keys=True))


if __name__ == "__main__":
    main()
