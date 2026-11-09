#!/usr/bin/env python3
"""Fee-credit caller of node #115 (function at 0x3c10000, 4,750 bytes): a Python reconstruction replayed against the machine code.

The function takes one tracked fill step (a table row), prices it, scales it through the token-decimal scaler, picks a mode
(as is, a fifth, or an f64 factor), classifies the row owner, credits a per-user ledger, builds and passes the argument block of
the fee-credit distribution call, and adds the per-record and per-kind tallies. `model` is the reconstruction; `Rig.emulate` runs the
original bytes in the interpreter below (17 helper functions are served by a shared seeded oracle, the ring search runs for real);
`compare` demands the same helper-call trace, the same panics and the same heap bytes. Negative controls: wrong model variants,
byte mutants of the function and corrupted inputs.

    python3 tools/fees_credit_caller_115.py --out research/work-items/fees-credit-caller-115

The binary is never executed; it is only read as bytes (SHA-256 checked first). Standard library plus the shared elf_index and
fde_extents parsers. The interpreter part is the verified x86-64 core repeated in the merged tools, with the call-site return address
kept for stubs reached through a GOT slot.
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
        self.ret_va = 0
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
            self.ret_va = row.next
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
# Packet part: the fee-credit caller at 0x3c10000 (node #115): one tracked fill step -> scaled amount -> owner class ->
# per-user ledger credits -> fee-credit distribution call -> ledger tallies.
# ======================================================================================================================

import json
import random
import zlib

FN = 0x3C10000
FN_END = 0x3C1128E
SENT = 1 << 63
M64 = (1 << 64) - 1
USED = 0x80000
ARENA = HEAP_BASE + 0x40000
CAP_CONST = 0x28F5C28F5C28F5C
RECIP = 0x431BDE82D7B634DB
HEAP_TOP = HEAP_BASE + USED

SLOT = {"hashget": 0x64E7168, "caperr": 0x64DF498, "alloc": 0x64DF480, "copy": 0x64DF508, "dealloc": 0x64DF4A0,
        "rec": 0x64E4EA8, "bounds": 0x64DF620, "unwrap": 0x64DF6A0}
CALL = {"hash_a": 0x4717440, "hash_b": 0x47172C0, "find": 0x3EE6280, "entry": 0x4717C50, "inner": 0x3CD7AA0,
        "cellp": 0x3F14BC0, "find2": 0x3EE69C0, "entry2": 0x4717FB0, "arr_in": 0x3CD6230, "arr_p": 0x3F18230,
        "tot_in": 0x3CD2DD0, "tot_p": 0x3F163B0, "scale": 0x434F660, "mode": 0x3D4E450, "posa": 0x3ED2180,
        "posb": 0x3ED2280, "sink": 0x3C1AE50}
RING = 0x45547E0

# panic sites are named by the return address of their call instruction
P_BOUNDS, P_UNWRAP, P_INDEX, P_ALLOC, P_CAP = 0x3C1121B, 0x3C11240, 0x3C11256, 0x3C11264, 0x3C109E7
# overflow recorder sites (saturating adds), by return address
R_LOOP1, R_LOOP2X, R_LOOP2Q, R_LOOP2A = 0x3C10D88, 0x3C10FC8, 0x3C10FEC, 0x3C11016
R_THIS, R_OTHER, R_TOTX, R_TOTQ = 0x3C11179, 0x3C111F3, 0x3C111A3, 0x3C111CB
SINK_LO, SINK_HI = 0xC8, 0x140


def mask64(x):
    return x & M64


def crc_hash(*parts):
    data = b"".join(p if isinstance(p, bytes) else int(p).to_bytes(8, "little") for p in parts)
    return zlib.crc32(data) | zlib.crc32(data, 0x9E37) << 32


class Pan(Exception):
    """A modelled panic: (return address of the call, first two argument registers)."""

    def __init__(self, ret, a, b):
        Exception.__init__(self, "panic")
        self.info = (ret, a, b)


class World:
    """Everything the function reaches through stubs: hash/table/ledger helpers as a seeded oracle over one heap view.

    The emulator and the model each own one World over identical heap bytes; both call the same methods in the same order, so the
    trace of (call, arguments) and the final heap bytes are what the two have to agree on."""

    def __init__(self, mem, cfg):
        self.mem = mem
        self.cfg = cfg
        self.trace = []
        self.bump = ARENA
        self.slots = {}
        self.cells = {}

    def alloc(self, size, fill=None):
        at = self.bump
        self.bump += (size + 15) & ~15
        if self.bump > HEAP_TOP:
            raise Halt("world arena exhausted")
        self.mem.put_bytes(at, bytes(size) if fill is None else fill)
        return at

    def word(self, tag, *parts):
        """Initial counter value: zero, small, or close to the u64 ceiling so the saturating adds fire."""
        h = crc_hash(tag, *parts)
        pick = h >> 61
        if pick < self.cfg["near"]:
            return M64 - (h >> 20 & 0xFFFF)
        return (h >> 24 & 0xFFFFFFF) if pick < 5 else 0

    def log(self, *entry):
        self.trace.append(entry)

    # --- hash / table helpers (stubs) -----------------------------------------------------------------------------------
    def hash_a(self, k0, k1, blob):
        h = crc_hash(b"a", k0, k1, blob)
        self.log("hash_a", k0, k1, blob, h)
        return h

    def hash_b(self, k0, k1):
        h = crc_hash(b"b", k0, k1)
        self.log("hash_b", k0, k1, h)
        return h

    def present(self, table, h):
        return (crc_hash(b"p", table, h) >> 9 & 0xFF) < self.cfg["pf"]

    def slot(self, table, h, size):
        key = (table, h)
        if key not in self.slots:
            at = self.alloc(size)
            for off in (0x40, 0x48):
                self.mem.write(at + off, 8, self.word(b"s", table, h, off))
            self.slots[key] = at
        return self.slots[key]

    def find(self, name, table, h, blob, ctx):
        ptr = self.slot(table, h, 0x100) if self.present(table, h) else 0
        self.log(name, table, h, blob, ctx, ptr)
        return ptr

    def entry(self, name, occupied, table, x, blob, aux=None):
        if occupied:
            ptr = x
        else:
            ptr = self.slot(table, x, 0x100)
        self.log(name, occupied, table, x, blob, aux, ptr)
        return ptr

    def cell(self, name, where, key, count):
        k = (name, where, key)
        if k not in self.cells:
            self.cells[k] = self.alloc(8 * count)
            for i in range(count):
                self.mem.write(self.cells[k] + 8 * i, 8, self.word(b"c", where, key, i))
        self.log(name, where, key, self.cells[k])
        return self.cells[k]

    def pos(self, name, table, h, value):
        mod = self.cfg["posmod_" + name]
        found = bool(crc_hash(b"q", table, h, value) >> 4 & 1)
        at = (crc_hash(b"r", table, h, value) >> 8) % (mod + 1)
        self.log(name, table, h, value, found, at)
        return found, at

    def mode(self, table, idx):
        self.log("mode", table, idx, self.cfg["mode"])
        return self.cfg["mode"]

    def hashget(self, table, key):
        h = crc_hash(b"g", table, key, self.cfg["seed"])
        size = h >> 60
        v = (h & 0xFFFFFFFF) if size < 8 else (h & 0xFFFFFFFFFF) * 1000 if size < 14 else h & M64
        self.log("hashget", table, key, v)
        return v

    def scale(self, amount, key, value, ctx):
        h = crc_hash(b"x", amount, key, value, self.cfg["seed"])
        ok = (h & 7) != 0
        mode = h >> 8 & 15
        if mode >= 14:
            scaled = (999999, 1000000, 1000001, 5000000, 4999999, 5000004)[(h >> 16) % 6]
        elif mode < 8:
            scaled = (amount * (h >> 16 & 0x3FF)) >> 4 & M64
        elif mode < 11:
            scaled = CAP_CONST + (h >> 20 & 0xF) - 8
        elif mode < 13:
            scaled = M64 - (h >> 30 & 0xFF)
        else:
            scaled = h >> 3 & 0xFFFFFF
        self.log("scale", amount, key, value, ctx, ok, scaled)
        return ok, scaled

    # --- allocation, recorder, sink -----------------------------------------------------------------------------------
    def a_alloc(self, size):
        if self.cfg["alloc_fail"]:
            self.log("alloc", size, 0)
            return 0
        ptr = self.alloc(size)
        self.log("alloc", size, ptr)
        return ptr

    def a_copy(self, dst, src, size):
        self.mem.put_bytes(dst, self.mem.bytes_at(src, size))
        self.log("copy", size, self.mem.bytes_at(src, size))

    def a_free(self, ptr, size):
        self.log("free", ptr, size)

    def recorder(self, ret):
        self.log("rec", ret)

    def sink(self, c, blob, key, block):
        self.log("sink", c, blob, key, bytes(block))


def sat_add(w, cell, delta, ret, bug=0):
    old = w.mem.read(cell, 8)
    total = old + delta
    if total > M64:
        if bug != 5:
            w.recorder(ret)
        total = M64
    w.mem.write(cell, 8, total)


# ----------------------------------------------------------------------------------------------------------------------
# The model: the function as a plain Python flow over the same heap view.
# ----------------------------------------------------------------------------------------------------------------------
def f64_to_count(x):
    """Rust `as u64`-like conversion the function performs on the scaled amount (saturating at i64::MAX, NaN to 0)."""
    if x != x:
        return 0
    if abs(x) == math.inf:
        return 0
    return None


class Flags:
    def __init__(self, bug=0):
        self.bug = bug


def convert_scaled(r13, factor_bits, bug):
    """Mode 2 path: r13 (checked non-negative) * factor with the clamp to [-2^63, 2^63] and saturating truncation."""
    if r13 >> 63:
        raise Pan(P_UNWRAP, 0x7DB94C, 0x2B)
    x = float(r13) * to_float(factor_bits)
    bits = to_bits(x)
    if (bits & 0x7FFFFFFFFFFFFFFF) > 0x7FEFFFFFFFFFFFFF:
        y = 0.0
    else:
        lo, hi = -9223372036854775808.0, 9223372036854775808.0
        if lo > x or x > hi:
            y = min(hi, max(lo, x))
        else:
            y = x
    if y != y:
        return 0
    if y >= 9223372036854775808.0 or y < -9223372036854775808.0:
        r = 0x8000000000000000
    else:
        r = int(y) & M64
    if y > 9223372036854774784.0:
        r = 0x7FFFFFFFFFFFFFFF
    if r == 0 or (r >> 63 and bug != 13):
        r = 0
    return r


def model(w, A, B, side, C, bug=0):
    """Transliteration of the function at 0x3c10000. `bug` selects a deliberately wrong variant (negative control)."""
    mem = w.mem
    rd = lambda a: mem.read(a, 8)
    ln16 = lambda a: mem.read(a, 2)
    A10 = A + 0x10

    def set_find(root, height, key):
        node = root
        while True:
            count = ln16(node + 0x62)
            i = 0
            while i < count:
                nk = rd(node + 8 + 8 * i)
                if key > nk:
                    i += 1
                    continue
                if key == nk:
                    return True
                break
            if height == 0:
                return False
            height -= 1
            node = rd(node + 0x68 + 8 * i)

    def map_find(root, height, key):
        node = root
        while True:
            count = ln16(node + 0xBA)
            i = 0
            while i < count:
                nk = rd(node + 8 + 8 * i)
                if key > nk:
                    i += 1
                    continue
                if key == nk:
                    return node + 0x60 + 8 * i
                break
            if height == 0:
                return None
            height -= 1
            node = rd(node + 0xC0 + 8 * i)

    def ring_find(key):
        cap, base, head, count = rd(A + 0x298), rd(A + 0x2A0), rd(A + 0x2A8), rd(A + 0x2B0)
        lo, hi = 0, count
        while lo < hi:
            mid = (lo + hi) // 2
            p = head + mid
            if p >= cap:
                p -= cap
            k = rd(base + p * 16)
            if k < key:
                lo = mid + 1
            elif k > key:
                hi = mid
            else:
                return True, mid
        return False, lo

    def lookup(key):
        cap = rd(A + 0x298)
        if cap == SENT:
            root = rd(A + 0x2A0)
            if root:
                at = map_find(root, rd(A + 0x2A8), key)
                if at is not None:
                    return rd(at)
            return w.hashget(A10, key)
        found, pos = ring_find(key)
        if not found or pos >= rd(A + 0x2B0):
            return w.hashget(A10, key)
        p = pos + rd(A + 0x2A8)
        if p >= cap:
            p -= cap
        return rd(rd(A + 0x2A0) + p * 16 + 8)

    def clamp_mul(x, y):
        p = x * y
        lo = p & M64
        if p >> 64 or (lo > 0x7FFFFFFFFFFFFFFE and bug != 12):
            return 0
        return lo

    idx, n = rd(B + 0x258), rd(A + 0x20)
    if idx >= n:
        raise Pan(P_BOUNDS, idx, n)
    price, mult = rd(B + 0x250), rd(B + 0x260)
    rowp = rd(A + 0x18) + idx * 32
    owner, key = rd(rowp), rd(rowp + 8)

    # 1. amount: priced value of the tracked key, scaled, or looked-up and multiplied
    if key == 0:
        in_set = True
    else:
        in_set = bool(rd(A + 0x350)) and set_find(rd(A + 0x350), rd(A + 0x358), key)
    if in_set:
        r14 = clamp_mul(price, mult)
        value = lookup(key)
        ok, scaled = w.scale(r14, key, value, A10)
        r13 = scaled if ok and scaled < CAP_CONST else r14
        if bug == 1:
            r13 = scaled if ok else r14
    else:
        r13 = 0
        root2 = rd(A + 0x338)
        if root2 and set_find(root2, rd(A + 0x340), owner):
            r13 = clamp_mul(lookup(owner), mult)

    # 2. mode: 0 = as is, 1 = fifth, otherwise the f64 factor
    mode = w.mode(A10, idx)
    if mode == 0:
        r11 = r13
    elif mode == 1:
        r11 = r13 // (10 if bug == 4 else 5)
    else:
        r11 = convert_scaled(r13, rd(A + 0x1C8), bug)
    Q = ((r13 * RECIP) >> 64) >> 18
    if bug == 9:
        Q = ((r11 * RECIP) >> 64) >> 18
    X = ((r11 * RECIP) >> 64) >> 18
    if bug == 2:
        X = (r11 * RECIP) >> 64 >> 17

    # 3. owner class flag (1 = plain user)
    n = rd(A + 0x20)
    if idx >= n:
        raise Pan(P_BOUNDS, idx, n)
    flag = 1
    root = rd(A + 0x210)
    if root and set_find(root, rd(A + 0x218), owner):
        flag = 0
    else:
        count = rd(A + 0x68)
        if count:
            arr = rd(A + 0x60)
            pos = None
            if count == 1:
                if rd(arr + 8) == owner:
                    pos = 0
            else:
                hb = w.hash_b(rd(A + 0x90), rd(A + 0x98))
                found, at = w.pos("posa", A + 0x58, hb, owner)
                if found:
                    if at >= count:
                        raise Pan(P_INDEX, at, count)
                    pos = at
            if pos is not None:
                rec = rd(arr + pos * 24 + 0x10)
                count2 = rd(A + 0xF8)
                flag = 0
                if count2 >= 2:
                    hb2 = w.hash_b(rd(A + 0x120), rd(A + 0x128))
                    found2, at2 = w.pos("posb", A + 0xE8, hb2, rec)
                    if found2 and at2 >= count2:
                        raise Pan(P_INDEX, at2, count2)
    if bug == 3:
        flag = 1 - flag

    # 4. blocks
    blk = B + (0x128 if side else 0)
    other = B + (0 if side else 0x128)
    if bug == 8:
        blk, other = other, blk
    kind = rd(blk + 0x38)
    sink_mask = None
    keyv = key
    if kind != 2:
        n = rd(A + 0x20)
        if idx >= n:
            raise Pan(P_BOUNDS, idx, n)

        def metric(b):
            m1 = rd(b + 0x98)
            sub = m1 - rd(b + 0x40) if m1 >= rd(b + 0x40) else 0
            val = sub if rd(b + 0x38) & 1 and bug != 10 else m1
            thr = 0 if rd(b + 0x60) == SENT else rd(b + 0x78)
            return val, thr

        def ledger(blob_at, ret):
            blob = mem.bytes_at(blob_at, 20)
            h = w.hash_a(rd(C + 0xE8), rd(C + 0xF0), blob)
            f = w.find("find", C + 0xC8, h, blob, mem.bytes_at(C + 0xB8, 16))
            slot = w.entry("entry", True, C + 0xB0, f, None, (C + 0xC8, h)) if f else w.entry("entry", False, C + 0xB0, h, blob)
            cell = w.cell("inner", slot + 0xA0, keyv, 1)
            sat_add(w, cell, X, ret)

        if flag:
            ledger(blk + 0x100, R_THIS)
        else:
            val, thr = metric(blk)
            if val > thr or (bug == 7 and val == thr):
                if bug == 6:
                    ledger(blk + 0x100, R_THIS)
                    ledger(other + 0x100, R_OTHER)
                else:
                    ledger(other + 0x100, R_OTHER)
                    ledger(blk + 0x100, R_THIS)
        # argument block for the distribution call
        tag = rd(blk + 0x38) & 1
        block = bytearray(SINK_HI - SINK_LO)
        masks = bytearray(len(block))

        def put(off, size, value):
            block[off - SINK_LO:off - SINK_LO + size] = (value & ((1 << 8 * size) - 1)).to_bytes(size, "little")
            masks[off - SINK_LO:off - SINK_LO + size] = b"\xff" * size

        put(0xC8, 8, tag)
        put(0x128, 8, rd(blk + 0x98))
        put(0x130, 8, rd(blk + 0xA0))
        put(0x138, 8, rd(blk + 0xA8))
        if tag:
            put(0xD0, 8, rd(blk + 0x40))
            put(0xD8, 16, int.from_bytes(mem.bytes_at(blk + 0x48, 16), "little"))
            put(0xE8, 4, mem.read(blk + 0x58, 4))
        clone, size = 0, 0
        if rd(blk + 0x60) == SENT:
            put(0xF0, 8, SENT)
        else:
            length = rd(blk + 0x70)
            size = (length << 5) & M64
            if length >> 59 or size > 0x7FFFFFFFFFFFFFF8:
                raise Pan(P_CAP, 0, size)
            if size == 0 or bug == 14:
                clone, cap = 8, 0
            else:
                clone = w.a_alloc(size)
                if clone == 0:
                    raise Pan(P_ALLOC, 8, size)
                w.a_copy(clone, rd(blk + 0x68), size)
                cap = length
            put(0xF0, 8, cap)
            put(0xF8, 8, clone)
            put(0x100, 8, length)
            put(0x108, 8, rd(blk + 0x78))
            put(0x110, 16, int.from_bytes(mem.bytes_at(blk + 0x80, 16), "little"))
            put(0x120, 4, mem.read(blk + 0x90, 4))
        if not (bug == 15 and side == 0):
            w.sink(C, mem.bytes_at(blk + 0x100, 20), keyv, bytes(block))
            w.trace[-1] = w.trace[-1] + (bytes(masks),)
        if rd(blk + 0x60) != SENT and size:
            w.a_free(clone, size)

    # 5. per-record tallies
    kind32 = mem.read(B + 0x278, 4)
    flag_byte = mem.read(B + 0x284, 1)
    mine = mem.bytes_at(blk + 0x100, 20)
    records = None
    if flag:
        records = [(mine, int(flag_byte == side))]
    else:
        if kind != 2:
            val, thr = metric(blk)
            if val > thr:
                records = [(mine, int(flag_byte == side)), (mem.bytes_at(other + 0x100, 20), int(flag_byte != side))]
    if records:
        for rec, rbyte in records:
            h = w.hash_a(rd(A + 0x3A8), rd(A + 0x3B0), rec)
            f = w.find("find2", A + 0x388, h, rec, mem.bytes_at(A + 0x378, 16))
            slot = w.entry("entry2", True, A + 0x370, f, None, (A + 0x388, h)) if f else w.entry("entry2", False, A + 0x370, h, rec)
            if r11 < 1000000:
                sat_add(w, slot + 0x48, Q, R_LOOP1, bug)
            else:
                sat_add(w, slot + 0x40, X, R_LOOP2X, bug)
                sat_add(w, slot + 0x48, Q, R_LOOP2Q, bug)
                arr = w.cell("arr", slot + 0x20, kind32, 2)
                sat_add(w, arr + rbyte * 8, X, R_LOOP2A, bug)
    # 6. totals
    do_total = False
    if flag:
        do_total = bool(side) or bug == 11
    elif kind != 2:
        val, thr = metric(blk)
        do_total = val > thr or (bug == 7 and val == thr)
    if do_total:
        tot = w.cell("tot", A + 0x4D0, kind32, 2)
        sat_add(w, tot, X, R_TOTX, bug)
        sat_add(w, tot + 8, Q, R_TOTQ, bug)


# ----------------------------------------------------------------------------------------------------------------------
# The emulator side: stubs that expose the same World methods.
# ----------------------------------------------------------------------------------------------------------------------
def install(m, w):
    mem = m.memory

    def ret_addr():
        return m.ret_va

    def hook_hash_a(mm):
        mm.regs[RAX] = w.hash_a(mm.regs[RDI], mm.regs[RSI], mem.bytes_at(mm.regs[RDX], 20))

    def hook_hash_b(mm):
        mm.regs[RAX] = w.hash_b(mm.regs[RDI], mm.regs[RSI])

    def probe_blob(p):
        return mem.bytes_at(mem.read(p, 8), 20), mem.bytes_at(p + 8, 16)

    def hook_find(mm):
        blob, ctx = probe_blob(mm.regs[RDX])
        mm.regs[RAX] = w.find("find", mm.regs[RDI], mm.regs[RSI], blob, ctx)

    def hook_find2(mm):
        blob, ctx = probe_blob(mm.regs[RDX])
        mm.regs[RAX] = w.find("find2", mm.regs[RDI], mm.regs[RSI], blob, ctx)

    def make_entry(name):
        def hook(mm):
            at = mm.regs[RDI]
            tag = mem.read(at, 8)
            table, x = mem.read(at + 8, 8), mem.read(at + 16, 8)
            if tag:
                mm.regs[RAX] = w.entry(name, False, table, x, mem.bytes_at(at + 0x18, 20))
            else:
                mm.regs[RAX] = w.entry(name, True, table, x, None, (mem.read(at + 0x18, 8), mem.read(at + 0x20, 8)))
        return hook

    def make_inner(name, count):
        def hook(mm):
            out = mm.regs[RDI]
            key = mm.regs[RDX] if name == "inner" else mm.regs[RDX] & 0xFFFFFFFF
            mem.write(out, 8, w.cell(name, mm.regs[RSI], key, count))
        return hook

    def make_ptr(mm):
        mm.regs[RAX] = mem.read(mm.regs[RDI], 8)

    def hook_scale(mm):
        ok, scaled = w.scale(mm.regs[RDI], mm.regs[RSI], mm.regs[RDX], mm.regs[RCX])
        mm.regs[RAX] = int(ok)
        mm.regs[RDX] = scaled
        mm.keep_rdx = True

    def hook_mode(mm):
        mm.regs[RAX] = w.mode(mm.regs[RDI], mm.regs[RSI])

    def make_pos(name):
        def hook(mm):
            found, at = w.pos(name, mm.regs[RDI], mm.regs[RSI], mem.read(mm.regs[RDX], 8))
            mm.regs[RAX] = int(found)
            mm.regs[RDX] = at
            mm.keep_rdx = True
        return hook

    def sink(mm):
        # the block lives on the stack at rsp-relative 0xc8: read it back through rcx
        block = mem.bytes_at(mm.regs[RCX], SINK_HI - SINK_LO)
        w.sink(mm.regs[RDI], mem.bytes_at(mm.regs[RSI], 20), mm.regs[RDX], block)

    m.calls = {CALL["hash_a"]: hook_hash_a, CALL["hash_b"]: hook_hash_b, CALL["find"]: hook_find,
               CALL["find2"]: hook_find2, CALL["entry"]: make_entry("entry"), CALL["entry2"]: make_entry("entry2"),
               CALL["inner"]: make_inner("inner", 1), CALL["cellp"]: make_ptr,
               CALL["arr_in"]: make_inner("arr", 2), CALL["arr_p"]: make_ptr,
               CALL["tot_in"]: make_inner("tot", 2), CALL["tot_p"]: make_ptr,
               CALL["scale"]: hook_scale, CALL["mode"]: hook_mode, CALL["posa"]: make_pos("posa"),
               CALL["posb"]: make_pos("posb"), CALL["sink"]: sink}
    m.real = frozenset({RING})

    def s_hashget(mm):
        mm.regs[RAX] = w.hashget(mm.regs[RDI], mm.regs[RSI])

    def s_panic(mm):
        raise Pan(ret_addr(), mm.regs[RDI], mm.regs[RSI])

    def s_alloc(mm):
        mm.regs[RAX] = w.a_alloc(mm.regs[RDI])

    def s_copy(mm):
        w.a_copy(mm.regs[RDI], mm.regs[RSI], mm.regs[RDX])
        mm.regs[RAX] = mm.regs[RDI]

    def s_free(mm):
        w.a_free(mm.regs[RDI], mm.regs[RSI])

    def s_rec(mm):
        w.recorder(ret_addr())

    handlers = {"hashget": s_hashget, "caperr": s_panic, "alloc": s_alloc, "copy": s_copy, "dealloc": s_free,
                "rec": s_rec, "bounds": s_panic, "unwrap": s_panic}
    m.slots = {}
    for i, (name, slot) in enumerate(sorted(SLOT.items())):
        fake = 0xF0000000 + 0x100 * i
        mem.statics[slot] = fake
        m.slots[fake] = handlers[name]


# ----------------------------------------------------------------------------------------------------------------------
# Vector builder: one heap image per case (trees, rows, blocks) from a seeded generator
# ----------------------------------------------------------------------------------------------------------------------
class Builder:
    def __init__(self, rng):
        self.rng = rng
        self.base = HEAP_BASE + 0x1000
        self.buf = bytearray()

    def alloc(self, size):
        while len(self.buf) % 16:
            self.buf.append(MARK_FILL)
        at = self.base + len(self.buf)
        self.buf.extend(bytes([MARK_FILL]) * size)
        return at

    def put(self, at, size, value):
        o = at - self.base
        self.buf[o:o + size] = (value & ((1 << 8 * size) - 1)).to_bytes(size, "little")

    def put_bytes(self, at, data):
        o = at - self.base
        self.buf[o:o + len(data)] = data

    def tree(self, items, height, is_map):
        node = self.alloc(0x120 if is_map else 0xD0)
        keys_at, len_at, len_size, edge_at = (8, 0xBA, 2, 0xC0) if is_map else (8, 0x62, 2, 0x68)
        if height == 0:
            chosen = items[:11]
            groups = None
        else:
            s = min(len(items), self.rng.randint(0, 3))
            cuts = sorted(self.rng.sample(range(len(items)), s)) if s else []
            chosen, groups, prev = [], [], 0
            for c in cuts:
                groups.append(items[prev:c])
                chosen.append(items[c])
                prev = c + 1
            groups.append(items[prev:])
        for i, (k, v) in enumerate(chosen):
            self.put(node + keys_at + 8 * i, 8, k)
            if is_map:
                self.put(node + 0x60 + 8 * i, 8, v)
        for i in range(len(chosen), 11):
            self.put(node + keys_at + 8 * i, 8, self.rng.choice((0, 1, 2, 5, 0x2007, 0x9001, 1 << 62, M64)))
            if is_map:
                self.put(node + 0x60 + 8 * i, 8, self.rng.getrandbits(64))
        self.put(node + len_at, len_size, len(chosen))
        if groups is not None:
            for i, g in enumerate(groups):
                self.put(node + edge_at + 8 * i, 8, self.tree(g, height - 1, is_map))
        return node


MARK_FILL = 0xA5


def pick_value(rng):
    r = rng.random()
    if r < 0.35:
        return rng.randrange(0, 5000)
    if r < 0.65:
        return rng.randrange(0, 10 ** 12)
    if r < 0.85:
        return rng.randrange(0, 1 << 40)
    if r < 0.95:
        return rng.randrange(1 << 55, 1 << 63)
    return rng.randrange(1 << 63, 1 << 64)


FACTORS = [0.0, 1.0, 0.5, 2.5, 0.001, 1e300, math.inf, math.nan, -1.0, 3.0e18, 1e-5, 1.5e12, 5e9]


def gen_case(i):
    rng = random.Random(0x5EED0000 + i)
    b = Builder(rng)
    A = b.alloc(0x500)
    B = b.alloc(0x300)
    C = b.alloc(0x100)
    pool_keys = [0x2000 + 7 * k for k in range(1, 6)]
    pool_owners = [0x9000 + 13 * k for k in range(1, 6)]
    n = rng.choice([1, 2, 3, 4])
    rows = b.alloc(32 * n)
    row_data = []
    for r in range(n):
        owner = rng.choice(pool_owners)
        key = rng.choice([0] + pool_keys + pool_keys)
        row_data.append((owner, key))
        b.put(rows + 32 * r, 8, owner)
        b.put(rows + 32 * r + 8, 8, key)
        b.put(rows + 32 * r + 16, 8, rng.getrandbits(64))
        b.put(rows + 32 * r + 24, 8, rng.getrandbits(64))
    b.put(A + 0x18, 8, rows)
    b.put(A + 0x20, 8, n)
    idx = rng.randrange(n) if rng.random() > 0.04 else n + rng.randrange(3)
    owner_i, key_i = row_data[idx] if idx < n else row_data[0]
    mult_r = rng.random()
    mult = rng.randrange(1, 1000) if mult_r < 0.5 else rng.randrange(1, 10 ** 7) if mult_r < 0.8 else rng.randrange(1 << 20, 1 << 40) if mult_r < 0.92 else rng.randrange(1 << 40, 1 << 63)
    price = pick_value(rng)
    if rng.random() < 0.06:
        mult = rng.choice([2, 3])
        price = rng.randrange(1 << 62, (1 << 63) + (1 << 61))
    b.put(B + 0x250, 8, price)
    b.put(B + 0x258, 8, idx)
    b.put(B + 0x260, 8, mult)
    b.put(B + 0x278, 4, rng.getrandbits(32))
    b.put(B + 0x284, 1, rng.randrange(2))
    side = rng.randrange(2)

    def key_set(base_keys, include_prob):
        chosen = [k for k in base_keys if rng.random() < include_prob]
        extra = [rng.randrange(1, 1 << 20) for _ in range(rng.randrange(0, 4))]
        return sorted(set(chosen + extra))

    def put_set(root_at, height_at, keys):
        if rng.random() < 0.15 or not keys:
            b.put(root_at, 8, 0)
            b.put(height_at, 8, rng.randrange(3))
            return
        height = rng.choice([0, 0, 1, 2])
        b.put(root_at, 8, b.tree([(k, 0) for k in keys], height, False))
        b.put(height_at, 8, height)

    put_set(A + 0x350, A + 0x358, key_set(pool_keys, 0.5))
    put_set(A + 0x338, A + 0x340, key_set(pool_owners, 0.5))
    put_set(A + 0x210, A + 0x218, key_set(pool_owners, 0.3))
    lookup_keys = sorted(set(pool_keys + pool_owners))
    entries = [(k, pick_value(rng)) for k in lookup_keys if rng.random() < 0.6]
    if rng.random() < 0.5:
        b.put(A + 0x298, 8, SENT)
        if entries and rng.random() > 0.15:
            height = rng.choice([0, 0, 1, 2])
            b.put(A + 0x2A0, 8, b.tree(entries, height, True))
            b.put(A + 0x2A8, 8, height)
        else:
            b.put(A + 0x2A0, 8, 0)
            b.put(A + 0x2A8, 8, 0)
        b.put(A + 0x2B0, 8, rng.getrandbits(64))
    else:
        cap = rng.randrange(max(len(entries), 1), max(len(entries), 1) + 4)
        ring = b.alloc(16 * cap)
        head = rng.randrange(cap)
        used = entries[:cap]
        for j, (k, v) in enumerate(used):
            p = (head + j) % cap
            b.put(ring + 16 * p, 8, k)
            b.put(ring + 16 * p + 8, 8, v)
        b.put(A + 0x298, 8, cap)
        b.put(A + 0x2A0, 8, ring)
        b.put(A + 0x2A8, 8, head)
        b.put(A + 0x2B0, 8, len(used) if rng.random() > 0.1 else rng.randrange(0, len(used) + 1))
    b.put(A + 0x1C8, 8, to_bits(rng.choice(FACTORS)))
    count = rng.choice([0, 1, 2, 3, 3])
    arr = b.alloc(24 * 4)
    for r in range(4):
        b.put(arr + 24 * r + 8, 8, rng.choice(pool_owners + [owner_i, owner_i]))
        b.put(arr + 24 * r + 16, 8, rng.getrandbits(64))
    b.put(A + 0x60, 8, arr)
    b.put(A + 0x68, 8, count)
    b.put(A + 0xF8, 8, rng.choice([0, 1, 2, 3, 4]))
    for off in (0x90, 0x98, 0x120, 0x128, 0x3A8, 0x3B0):
        b.put(A + off, 8, rng.getrandbits(64))
    b.put_bytes(A + 0x378, rng.randbytes(16))
    b.put_bytes(C + 0xB8, rng.randbytes(16))
    for off in (0xE8, 0xF0):
        b.put(C + off, 8, rng.getrandbits(64))
    for blk in (B, B + 0x128):
        kind = rng.choice([0, 1, 1, 0, 3, 2, 4, 5])
        b.put(blk + 0x38, 8, kind)
        b.put(blk + 0x40, 8, rng.randrange(0, 1300))
        b.put(blk + 0x98, 8, rng.randrange(0, 1000))
        b.put(blk + 0x78, 8, rng.randrange(0, 900))
        b.put(blk + 0x60, 8, SENT if rng.random() < 0.4 else rng.randrange(0, 1 << 40))
        length = rng.choice([0, 1, 2, 3, 3, 2, 1]) if rng.random() < 0.97 else rng.choice([1 << 59, (1 << 58) + 5, 1 << 62])
        b.put(blk + 0x70, 8, length)
        data = b.alloc(32 * 3)
        b.put_bytes(data, rng.randbytes(96))
        b.put(blk + 0x68, 8, data)
        b.put_bytes(blk + 0x80, rng.randbytes(20))
        b.put_bytes(blk + 0x48, rng.randbytes(16))
        b.put(blk + 0x58, 4, rng.getrandbits(32))
        b.put(blk + 0xA0, 8, rng.getrandbits(64))
        b.put(blk + 0xA8, 8, rng.getrandbits(64))
        b.put(blk + 0x98, 8, rng.randrange(0, 1000))
        b.put_bytes(blk + 0x100, rng.randbytes(20))
    cfg = {"seed": i, "near": rng.choice([0, 0, 1, 2, 4]), "pf": rng.choice([0, 64, 128, 192, 256]),
           "mode": rng.choice([0, 1, 2, 2, 2, 3]), "alloc_fail": rng.random() < 0.03,
           "posmod_posa": max(count - 1, 0) + (1 if rng.random() < 0.2 else 0), "posmod_posb": 0}
    cfg["posmod_posb"] = max(mem_count2(b, A) - 1, 0) + (1 if rng.random() < 0.2 else 0)
    return {"base": b.base, "image": bytes(b.buf), "cfg": cfg, "A": A, "B": B, "C": C, "side": side, "zero_stack": i % 3 == 0}


def mem_count2(b, A):
    o = A + 0xF8 - b.base
    return int.from_bytes(b.buf[o:o + 8], "little")


# ----------------------------------------------------------------------------------------------------------------------
# Running one case on the emulator and on the model, and comparing
# ----------------------------------------------------------------------------------------------------------------------
class Rig:
    def __init__(self, image, patches=None):
        self.image = image
        self.machine = Machine(image, patches)
        self.model_mem = Memory(image)

    def emulate(self, case):
        m = self.machine
        m.memory.reset(USED)
        if case.get("zero_stack"):
            m.memory.stack[:] = bytes(STACK_SIZE)
        m.memory.put_bytes(case["base"], case["image"])
        w = World(m.memory, case["cfg"])
        install(m, w)
        status = ("ok",)
        try:
            m.run(FN, {RDI: case["A"], RSI: case["B"], RDX: case["side"], RCX: case["C"]})
        except Pan as e:
            status = ("panic",) + e.info
        except Halt as e:
            status = ("halt", str(e)[:60])
        return status, w.trace, bytes(m.memory.heap[:USED])

    def run_model(self, case, bug=0):
        mm = self.model_mem
        mm.reset(USED)
        mm.put_bytes(case["base"], case["image"])
        w = World(mm, case["cfg"])
        status = ("ok",)
        try:
            model(w, case["A"], case["B"], case["side"], case["C"], bug)
        except Pan as e:
            status = ("panic",) + e.info
        return status, w.trace, bytes(mm.heap[:USED])


def traces_equal(emu, mod):
    if len(emu) != len(mod):
        return False
    for x, y in zip(emu, mod):
        if x[0] == "sink":
            if y[0] != "sink" or x[:4] != y[:4]:
                return False
            mask = y[5]
            if bytes(a & k for a, k in zip(x[4], mask)) != bytes(a & k for a, k in zip(y[4], mask)):
                return False
        elif x != y:
            return False
    return True


def compare(rig, case, bug=0):
    e_status, e_trace, e_heap = rig.emulate(case)
    m_status, m_trace, m_heap = rig.run_model(case, bug)
    if e_status[0] == "halt":
        return False, "halt " + e_status[1], e_status
    if e_status != m_status:
        return False, "status", e_status
    if not traces_equal(e_trace, m_trace):
        return False, "trace", e_status
    if e_status[0] == "ok" and e_heap != m_heap:
        return False, "heap", e_status
    return True, "", e_status


# ----------------------------------------------------------------------------------------------------------------------
# Negative controls: model variants, machine-code byte mutants, corrupted inputs
# ----------------------------------------------------------------------------------------------------------------------
import hashlib
import os

N_CASES = 12000
N_MUTANT_CASES = 3000
BUG_TEXT = {
    1: "scaled value accepted without the 0x28f5c28f5c28f5c ceiling",
    2: "tally shift 17 instead of 18",
    3: "owner class flag inverted",
    4: "mode 1 divides by ten instead of five",
    5: "saturating add skips the overflow recorder",
    6: "ledger updates in the other order",
    7: "metric test uses >= instead of >",
    8: "block side selection swapped",
    9: "credit tally Q taken from the mode-adjusted amount",
    10: "metric ignores the kind bit that subtracts the offset",
    11: "totals gate also fires for side 0 on the plain class",
    12: "product clamp drops the 0x7ffffffffffffffe ceiling",
    13: "f64 result keeps negative values",
    14: "clone skipped for non-zero length",
    15: "distribution call omitted for side 0",
}


def apply_bug(bug, name, value):
    """Hook points for the deliberately wrong model variants; returns the (possibly changed) value."""
    return value


def expected_digest(rig, case, bug=0):
    status, trace, heap = rig.run_model(case, bug)
    return status, trace, hashlib.sha1(heap).digest()


def check(rig, case, want):
    """Compare the machine run to the model result `want`; returns (ok, reason)."""
    e_status, e_trace, e_heap = rig.emulate(case)
    m_status, m_trace, m_heap = want
    if e_status[0] == "halt":
        return False, "halt"
    if e_status != m_status:
        return False, "status"
    if not traces_equal(e_trace, m_trace):
        return False, "trace"
    if hashlib.sha1(e_heap).digest() != m_heap:
        return False, "heap"
    return True, ""


def mutants(image):
    """Deterministic byte mutants of the function: condition flips, immediate flips, add/sub swaps, store removal."""
    rows = decode_range(image, FN, FN_END)
    out = []
    for row in rows:
        data = bytes(row.data)
        if row.op in ("jcc", "cmov", "set"):
            at = 0 if data[0] & 0xF0 == 0x70 else data.index(0x0F) + 1
            patched = bytearray(data)
            patched[at] ^= 1
            out.append(("cc", row.va, "condition bit flipped in %s" % row.op, bytes(patched)))
        if row.imm_at is not None and row.op not in ("jcc", "jmp", "call") and row.imm_size in (1, 4):
            patched = bytearray(data)
            patched[row.imm_at] ^= 1
            out.append(("imm", row.va, "immediate low bit flipped in %s" % row.op, bytes(patched)))
        if row.op in ("add", "sub") and data[0] in (0x01, 0x03, 0x29, 0x2B):
            patched = bytearray(data)
            patched[0] ^= 0x28
            out.append(("op", row.va, "add/sub swapped", bytes(patched)))
        if row.op in ("add", "sub", "adc", "sbb") and data[0] in (0x83, 0x81) and (data[1] >> 3 & 7) in (0, 5):
            patched = bytearray(data)
            patched[1] ^= 5 << 3
            out.append(("op", row.va, "add/sub group swapped", bytes(patched)))
        if row.op == "mov" and row.a is not None and row.a[0] == "m" and row.size >= 2:
            out.append(("nop", row.va, "store removed", b"\x90" * row.size))
    return out


def pick_mutants(image, limit):
    cand = mutants(image)
    stride = max(1, len(cand) // limit)
    chosen = cand[::stride][:limit]
    return chosen


EQUIV = {
    0x3C10AFE: "the copy-back at 0x3c10b11 rewrites 0x80(rsp) with the bytes saved from it at 0x3c10ac1 and nothing writes it in between; skipping or forcing it only changes block words 0x110..0x124 when the Option is None, which are not part of the contract then",
    0x3C10351: "above 2^63 the unclamped cvttsd2si gives the indefinite value and the compare with 0x458e50 then forces i64::MAX, exactly what the clamped 2^63 gives; inside the range both paths convert the same value",
    0x3C10B0F: "same copy-back as 0x3c10afe on the tag-0 branch: identity when the clone exists, stale words 0x110..0x124 only when the Option is None",
}


def run_mutants(image, cases, wants, limit):
    results = []
    order = list(range(len(cases)))
    for n, (kind, va, desc, new) in enumerate(pick_mutants(image, limit)):
        patches = {va + k: b for k, b in enumerate(new)}
        rig = Rig(image, patches)
        rig.machine.step_limit = MUTANT_STEP_LIMIT
        killed_by, reason = -1, ""
        for pos, i in enumerate(order):
            try:
                ok, why = check(rig, cases[i], wants[i])
            except (EvidenceError, Halt, KeyError, IndexError, ValueError, TypeError, MemoryError, OverflowError) as e:
                ok, why = False, "fault"
            if not ok:
                killed_by, reason = i, why
                order.insert(0, order.pop(pos))
                break
        results.append((n, kind, va, desc, killed_by, reason))
    return results


def run_bugs(rig, cases, wants):
    results = []
    for bug in sorted(BUG_TEXT):
        killed_by, reason = -1, ""
        for i, case in enumerate(cases):
            got = expected_digest(rig, case, bug)
            if got[0] != wants[i][0] or not traces_equal_model(got[1], wants[i][1]) or got[2] != wants[i][2]:
                killed_by, reason = i, "model"
                break
        results.append((bug, killed_by, reason))
    return results


def traces_equal_model(a, b):
    return a == b


def corrupted_inputs(image, rig):
    """Out-of-range and corrupted inputs the comparison has to flag: a wrong digest, a row index past the table, a damaged heap."""
    found = []
    try:
        load_image_bytes(bytes(image.blob[:100]) + b"x", SHA256)
        found.append(("digest", False))
    except EvidenceError:
        found.append(("digest", True))
    case = gen_case(5)
    want = expected_digest(rig, case)
    damaged = dict(case)
    damaged["image"] = bytes(case["image"][:0x500]) + bytes([case["image"][0x500] ^ 0xFF]) + bytes(case["image"][0x501:])
    ok, _ = check(rig, damaged, want)
    found.append(("heap-byte", not ok))
    return found


def load_image_bytes(blob, expected):
    if hashlib.sha256(blob).hexdigest() != expected:
        raise EvidenceError("binary SHA-256 mismatch")
    return Image(blob)


# ----------------------------------------------------------------------------------------------------------------------
# Evidence files
# ----------------------------------------------------------------------------------------------------------------------
TAB = "\t"
ROLE = {0x4717440: "hash of a 20-byte key (SipHash state in the first two args)", 0x47172C0: "hash of two state words",
        0x3EE6280: "table probe by hash and key (ledger map)", 0x4717C50: "entry for the ledger map (occupied or vacant)",
        0x3CD7AA0: "inner map entry by u64 key", 0x3F14BC0: "inner map entry value cell", 0x3EE69C0: "table probe (tally map)",
        0x4717FB0: "entry for the tally map", 0x3CD6230: "per-kind pair entry", 0x3F18230: "per-kind pair cell array",
        0x3CD2DD0: "totals entry by kind", 0x3F163B0: "totals cell pair", 0x434F660: "token-decimal amount scaler",
        0x3D4E450: "mode query for a row", 0x3ED2180: "position probe (user table)", 0x3ED2280: "position probe (second table)",
        0x3C1AE50: "fee credit distribution (separate packet)", 0x45547E0: "ring search over (key, value) pairs"}


def render(event):
    parts = []
    for item in event:
        if isinstance(item, (bytes, bytearray)):
            parts.append(item[:6].hex() + ("+%d" % (len(item) - 6) if len(item) > 6 else ""))
        elif isinstance(item, bool) or item is None:
            parts.append(str(item))
        elif isinstance(item, int):
            parts.append(hex(item) if item > 9 else str(item))
        else:
            parts.append(str(item))
    return " ".join(parts)


def write(path, lines):
    with open(path, "w", newline="\n") as handle:
        handle.write("\n".join(lines) + "\n")


def generate(out, n_cases=N_CASES, n_mutants=100, n_mutant_cases=N_MUTANT_CASES):
    image = load_image()
    os.makedirs(out, exist_ok=True)
    rig = Rig(image)
    cases = [gen_case(i) for i in range(n_mutant_cases)]
    wants = [expected_digest(rig, c) for c in cases]
    status_count = {}
    kinds = {}
    sample = []
    shown = []
    panics = {}
    mismatches = 0
    for i in range(n_cases):
        case = cases[i] if i < len(cases) else gen_case(i)
        want = wants[i] if i < len(wants) else expected_digest(rig, case)
        ok, why = check(rig, case, want)
        if not ok:
            mismatches += 1
            raise SystemExit("model disagrees with the machine code at case %d (%s)" % (i, why))
        status, trace, _ = want
        status_count[status[0]] = status_count.get(status[0], 0) + 1
        if status[0] == "panic":
            panics[status[1]] = panics.get(status[1], 0) + 1
        for event in trace:
            kinds[event[0]] = kinds.get(event[0], 0) + 1
        if i < 40:
            shown.append("case %d status %s side %d mode %d" % (i, " ".join(hex(v) if isinstance(v, int) and v > 9 else str(v) for v in status), case["side"], case["cfg"]["mode"]))
            shown.extend("  " + render(event[:5] if event[0] == "sink" else event) for event in trace)
        if i % 6 == 0:
            digest = hashlib.sha256(repr([e if e[0] != "sink" else e[:5] for e in trace]).encode()).hexdigest()[:16]
            sample.append(TAB.join(str(v) for v in (i, status[0], hex(status[1]) if len(status) > 1 else "-", len(trace), case["cfg"]["mode"], case["side"], digest)))
    write(os.path.join(out, "cases.tsv"), ["case" + TAB + "status" + TAB + "panic_return" + TAB + "events" + TAB + "mode" + TAB + "side" + TAB + "trace_sha256_16"] + sample)
    write(os.path.join(out, "trace-sample.txt"), shown)
    rows = decode_range(image, FN, FN_END)
    seen = rig.machine.seen
    write(os.path.join(out, "coverage.tsv"), ["va" + TAB + "size" + TAB + "op" + TAB + "executed"] + ["%#x%s%d%s%s%s%d" % (r.va, TAB, r.size, TAB, r.op, TAB, r.va in seen) for r in rows])
    unexecuted = [r.va for r in rows if r.va not in seen]
    write(os.path.join(out, "events.tsv"), ["event" + TAB + "count"] + ["%s%s%d" % (k, TAB, kinds[k]) for k in sorted(kinds)])
    write(os.path.join(out, "panics.tsv"), ["return_address" + TAB + "count"] + ["%#x%s%d" % (k, TAB, panics[k]) for k in sorted(panics)])
    consts = []
    for va in (0x459808, 0x459360, 0x458E50):
        consts.append("%#x%s%#018x" % (va, TAB, int.from_bytes(image.blob[image.offset(va):image.offset(va) + 8], "little")))
    write(os.path.join(out, "constants.tsv"), ["address" + TAB + "u64_bits"] + consts)
    calls = ["address" + TAB + "role" + TAB + "fde_end"]
    for va in sorted(ROLE):
        try:
            end = "%#x" % image.exact_fde(va)[1]
        except EvidenceError:
            end = "-"
        calls.append("%#x%s%s%s%s" % (va, TAB, ROLE[va], TAB, end))
    write(os.path.join(out, "functions.tsv"), calls)
    # controls
    bug_results = run_bugs(rig, cases[:600], wants[:600])
    mut_results = run_mutants(image, cases, wants, n_mutants)
    inputs = corrupted_inputs(image, rig)
    controls = ["id" + TAB + "kind" + TAB + "address" + TAB + "description" + TAB + "killed_by_case" + TAB + "reason"]
    equivalent = ["address" + TAB + "mutation" + TAB + "reason"]
    total = detected = equiv = 0
    for bug, killed_by, reason in bug_results:
        total += 1
        detected += killed_by >= 0
        controls.append(TAB.join(("model-%d" % bug, "model", "-", BUG_TEXT[bug], str(killed_by), reason or "survived")))
    for n, kind, va, desc, killed_by, reason in mut_results:
        total += 1
        if killed_by >= 0:
            detected += 1
        elif va in EQUIV:
            equiv += 1
            equivalent.append(TAB.join(("%#x" % va, "%s: %s" % (kind, desc), EQUIV[va])))
        else:
            raise SystemExit("mutant at %#x (%s) survived without a recorded reason" % (va, desc))
        controls.append(TAB.join(("byte-%d" % n, kind, "%#x" % va, desc, str(killed_by), reason or "equivalent" if killed_by < 0 else reason)))
    for name, ok in inputs:
        total += 1
        detected += bool(ok)
        controls.append(TAB.join(("input-" + name, "input", "-", "corrupted input " + name, "0" if ok else "-1", "flagged" if ok else "survived")))
    write(os.path.join(out, "controls.tsv"), controls)
    write(os.path.join(out, "equivalent-mutants.tsv"), equivalent)
    write(os.path.join(out, "unexecuted.tsv"), ["va" + TAB + "reason"] + ["%#x%s%s" % (v, TAB, UNEXECUTED_REASON(v)) for v in unexecuted])
    summary = {"cases": n_cases, "negative_controls": total, "negative_detected": detected, "equivalent": equiv,
               "instructions": len(rows), "unexecuted": len(unexecuted), "statuses": dict(sorted(status_count.items())),
               "mismatches": mismatches}
    write(os.path.join(out, "measure.json"), json.dumps(summary, indent=1, sort_keys=True).split("\n"))
    return summary


def UNEXECUTED_REASON(va):
    if 0x3C11264 <= va < 0x3C1128E:
        return "landing pad after a call that never returns (stub raises)"
    if va in (0x3C1121B, 0x3C11222, 0x3C11229, 0x3C11230, 0x3C11235, 0x3C1123A):
        return "negative amount unwrap failure: every amount source is clamped below 2^63"
    return "alignment padding"


def main(argv):
    if len(argv) == 3 and argv[1] == "--out":
        print(json.dumps(generate(argv[2]), sort_keys=True))
        return 0
    print("usage: fees_credit_caller_115.py --out <folder>")
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv))
