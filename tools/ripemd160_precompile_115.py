#!/usr/bin/env python3
"""Reconstruct and verify node #115's RIPEMD-160 precompile hash path (address 0x03 body and its block function).

Two bodies carry the whole hash.  The body at 0x5bed950 takes (rdi = 32-byte result, rdx = input pointer, rcx = input length), absorbs
the input in 64-byte blocks through the function pointer in the relocated slot 0x64ec328, pads the tail (0x80, zeros, 64-bit LITTLE
endian bit length) and returns the 20-byte digest right-aligned in a zero-filled 32-byte word.  The block function at 0x5c3ce60 takes
(rdi = five u32 chaining words, rsi = sixteen u32 message words) and is the fully unrolled RIPEMD-160 two-line compression.  The
relocation table that carries the body (0x64bff88, next to the SHA-256 body at 0x64bff80) is read from the ELF bytes.

The reconstruction is `compress_model`, `padded_blocks` and `ripemd_word` below, written from the RIPEMD-160 definition.  A concrete
x86-64 evaluator (the shared interpreter, carried inside this tool) runs the real bytes of both bodies; memcpy, memset and the panic
slot are recording contract stubs.  Every comparison is machine bytes against the model; the binary is never executed.

    python3 tools/ripemd160_precompile_115.py --out <dir>
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
                  (0x54, True): "andpd", (0xDF, True): "pandn", (0x56, True): "orpd", (0x62, True): "punpckldq", (0x60, True): "punpcklbw", (0x68, True): "punpckhbw", (0x67, True): "packuswb",
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
        if two == 0x70 and (opsize or repne or rep):
            reg, rm = modrm(True)
            value = immediate(1) & 0xFF
            return finish("pshufd" if opsize else "pshuflw" if repne else "pshufhw", ("x", reg), rm, 16, target=value)
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
        elif op == "punpckhbw":
            left, right = self.xmm[row.a[1]].to_bytes(16, "little"), self.vector(row.b).to_bytes(16, "little")
            self.xmm[row.a[1]] = int.from_bytes(bytes(byte for pair in zip(left[8:], right[8:]) for byte in pair), "little")
        elif op == "packuswb":
            left, right = self.xmm[row.a[1]], self.vector(row.b)

            def saturate(word):
                word = word - 0x10000 if word & 0x8000 else word
                return 0 if word < 0 else 255 if word > 255 else word

            lanes = [saturate(left >> (16 * i) & 0xFFFF) for i in range(8)] + [saturate(right >> (16 * i) & 0xFFFF) for i in range(8)]
            self.xmm[row.a[1]] = int.from_bytes(bytes(lanes), "little")
        elif op == "pshufhw":
            source = self.vector(row.b)
            words = [(source >> (64 + 16 * index)) & 0xFFFF for index in range(4)]
            high = sum(words[(row.target >> (2 * index)) & 3] << (64 + 16 * index) for index in range(4))
            self.xmm[row.a[1]] = high | source & MASK[8]
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


# ---------------------------------------------------------------------------------------------------------------------------
# Packet part: RIPEMD-160 model, contract stubs, evidence and controls
# ---------------------------------------------------------------------------------------------------------------------------
import argparse  # noqa: E402
import json  # noqa: E402

WRAPPER = 0x5BED950
COMPRESS = 0x5C3CE60
SHA_BODY = 0x5BED690
TABLE_SLOT = 0x64BFF88
COMPRESS_SLOT = 0x64EC328
MEMCPY_SLOT = 0x64DF508
MEMSET_SLOT = 0x64DF750
PANIC_SLOT = 0x64DF870
MARK_MEMCPY = 0x7700000001
MARK_MEMSET = 0x7700000002
MARK_PANIC = 0x7700000003
MARK_COMPRESS = 0x7700000004

DATA_AT = HEAP_BASE + 0x2000
OUT_AT = HEAP_BASE + 0x100
STATE_AT = HEAP_BASE + 0x400
BLOCK_AT = HEAP_BASE + 0x800
MASK32 = 0xFFFFFFFF

INIT = (0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0)

R_LEFT = (0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
          7, 4, 13, 1, 10, 6, 15, 3, 12, 0, 9, 5, 2, 14, 11, 8,
          3, 10, 14, 4, 9, 15, 8, 1, 2, 7, 0, 6, 13, 11, 5, 12,
          1, 9, 11, 10, 0, 8, 12, 4, 13, 3, 7, 15, 14, 5, 6, 2,
          4, 0, 5, 9, 7, 12, 2, 10, 14, 1, 3, 8, 11, 6, 15, 13)
R_RIGHT = (5, 14, 7, 0, 9, 2, 11, 4, 13, 6, 15, 8, 1, 10, 3, 12,
           6, 11, 3, 7, 0, 13, 5, 10, 14, 15, 8, 12, 4, 9, 1, 2,
           15, 5, 1, 3, 7, 14, 6, 9, 11, 8, 12, 2, 10, 0, 4, 13,
           8, 6, 4, 1, 3, 11, 15, 0, 5, 12, 2, 13, 9, 7, 10, 14,
           12, 15, 10, 4, 1, 5, 8, 7, 6, 2, 13, 14, 0, 3, 9, 11)
S_LEFT = (11, 14, 15, 12, 5, 8, 7, 9, 11, 13, 14, 15, 6, 7, 9, 8,
          7, 6, 8, 13, 11, 9, 7, 15, 7, 12, 15, 9, 11, 7, 13, 12,
          11, 13, 6, 7, 14, 9, 13, 15, 14, 8, 13, 6, 5, 12, 7, 5,
          11, 12, 14, 15, 14, 15, 9, 8, 9, 14, 5, 6, 8, 6, 5, 12,
          9, 15, 5, 11, 6, 8, 13, 12, 5, 12, 13, 14, 11, 8, 5, 6)
S_RIGHT = (8, 9, 9, 11, 13, 15, 15, 5, 7, 7, 8, 11, 14, 14, 12, 6,
           9, 13, 15, 7, 12, 8, 9, 11, 7, 7, 12, 7, 6, 15, 13, 11,
           9, 7, 15, 11, 8, 6, 6, 14, 12, 13, 5, 14, 13, 13, 7, 5,
           15, 5, 8, 11, 14, 14, 6, 14, 6, 9, 12, 9, 12, 5, 15, 8,
           8, 5, 12, 9, 12, 5, 14, 6, 8, 13, 6, 5, 15, 13, 11, 11)
K_LEFT = (0x00000000, 0x5A827999, 0x6ED9EBA1, 0x8F1BBCDC, 0xA953FD4E)
K_RIGHT = (0x50A28BE6, 0x5C4DD124, 0x6D703EF3, 0x7A6D76E9, 0x00000000)
FUNCS = (0, 1, 2, 3, 4)


class Tables:
    """The parameters of the model, replaceable one at a time to make negative controls."""

    def __init__(self):
        self.r_left, self.r_right = R_LEFT, R_RIGHT
        self.s_left, self.s_right = S_LEFT, S_RIGHT
        self.k_left, self.k_right = K_LEFT, K_RIGHT
        self.func_left, self.func_right = FUNCS, FUNCS[::-1]
        self.rot10 = 10
        self.combine = 0
        self.final_add = True
        self.init = INIT


def rol32(value, count):
    count &= 31
    return (value << count | value >> (32 - count)) & MASK32


def boolean(kind, x, y, z):
    if kind == 0:
        return x ^ y ^ z
    if kind == 1:
        return x & y | ~x & z
    if kind == 2:
        return (x | ~y) ^ z
    if kind == 3:
        return x & z | y & ~z
    return x ^ (y | ~z)


def compress_model(state, words, t=None):
    """One RIPEMD-160 block: left and right lines of 80 steps, then the cross combination of the five chaining words."""
    t = t or Tables()
    a1, b1, c1, d1, e1 = a2, b2, c2, d2, e2 = state
    for j in range(80):
        rnd = j // 16
        x = (a1 + boolean(t.func_left[rnd], b1, c1, d1) + words[t.r_left[j]] + t.k_left[rnd]) & MASK32
        x = (rol32(x, t.s_left[j]) + e1) & MASK32
        a1, e1, d1, c1, b1 = e1, d1, rol32(c1, t.rot10), b1, x
        y = (a2 + boolean(t.func_right[rnd], b2, c2, d2) + words[t.r_right[j]] + t.k_right[rnd]) & MASK32
        y = (rol32(y, t.s_right[j]) + e2) & MASK32
        a2, e2, d2, c2, b2 = e2, d2, rol32(c2, t.rot10), b2, y
    if t.combine == 1:
        return ((state[1] + c1 + e2) & MASK32, (state[2] + d1 + a2) & MASK32, (state[3] + e1 + b2) & MASK32,
                (state[4] + a1 + c2) & MASK32, (state[0] + b1 + d2) & MASK32)
    total = ((state[1] + c1 + d2) & MASK32, (state[2] + d1 + e2) & MASK32, (state[3] + e1 + a2) & MASK32,
             (state[4] + a1 + b2) & MASK32, (state[0] + b1 + c2) & MASK32)
    if not t.final_add:
        total = (b1, c1, d1, e1, a1)
    return total


def words_of(block):
    return struct.unpack("<16I", block)


class PadOptions:
    """Padding parameters of the wrapper model, replaceable for negative controls."""

    def __init__(self):
        self.pad_byte = 0x80
        self.split = 56
        self.length_order = "<"
        self.length_unit = 8
        self.block = 64
        self.left_pad = True


def padded_blocks(length_total, tail, opts=None):
    """The final one or two blocks the wrapper compresses after the full input blocks."""
    opts = opts or PadOptions()
    rem = len(tail)
    buf = bytearray(tail) + bytes([opts.pad_byte])
    if rem < opts.split:
        buf += bytes(opts.block - len(buf) - 8)
        buf += struct.pack(opts.length_order + "Q", length_total * opts.length_unit & 0xFFFFFFFFFFFFFFFF)
        return [bytes(buf)]
    buf += bytes(2 * opts.block - len(buf) - 8)
    buf += struct.pack(opts.length_order + "Q", length_total * opts.length_unit & 0xFFFFFFFFFFFFFFFF)
    return [bytes(buf[:opts.block]), bytes(buf[opts.block:])]


def wrapper_model(data, t=None, opts=None):
    """Return (32-byte result, ordered events).  Events: ('compress', block bytes), ('memcpy', count, source offset), ('memset', count)."""
    opts = opts or PadOptions()
    n = len(data)
    events = []
    state = (t.init if t else INIT)
    cutoff = opts.block
    if n < cutoff:
        events.append(("memcpy", n, 0))
        tail = bytes(data)
    else:
        full = n // cutoff
        for i in range(full):
            blk = bytes(data[i * cutoff:(i + 1) * cutoff])
            events.append(("compress", blk))
            state = compress_model(state, words_of(blk), t)
        rem = n - full * cutoff
        events.append(("memcpy", rem, full * cutoff))
        tail = bytes(data[full * cutoff:])
    rem = len(tail)
    if rem != cutoff - 1:
        events.append(("memset", cutoff - 1 - rem))
    for blk in padded_blocks(n, tail, opts):
        events.append(("compress", blk))
        state = compress_model(state, words_of(blk), t)
    digest = struct.pack("<5I", *state)
    return (bytes(12) + digest if opts.left_pad else digest + bytes(12)), events


def ripemd160_digest(data):
    return wrapper_model(data)[0][12:]


# published test vectors of the RIPEMD-160 definition (hex digests)
VECTORS = (
    (b"", "9c1185a5c5e9fc54612808977ee8f548b2258d31"),
    (b"a", "0bdc9d2d256b3ee9daae347be6f4dc835a467ffe"),
    (b"abc", "8eb208f7e05d987a9b044a8e98c6b087f15a0bfc"),
    (b"message digest", "5d0689ef49d2fae572b881b123a85ffa21595f36"),
    (b"abcdefghijklmnopqrstuvwxyz", "f71c27109c692c1b56bbdceb5b9d2865b3708dbc"),
    (b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq", "12a053384a9c0c88e405a06c27dcf49ada62eb2b"),
)


class Rng:
    """Small deterministic generator (xorshift64*), independent of the interpreter's random module."""

    def __init__(self, seed):
        self.s = seed & 0xFFFFFFFFFFFFFFFF or 1

    def next(self):
        s = self.s
        s ^= s >> 12
        s ^= s << 25 & 0xFFFFFFFFFFFFFFFF
        s ^= s >> 27
        self.s = s
        return s * 0x2545F4914F6CDD1D & 0xFFFFFFFFFFFFFFFF

    def below(self, n):
        return self.next() % n

    def blob(self, n):
        out = bytearray()
        while len(out) < n:
            out += self.next().to_bytes(8, "little")
        return bytes(out[:n])


class ToolError(Exception):
    pass


# ----------------------------------------------------------------------------- machine harness

class Rig:
    """One machine with the three imported slots and the compress slot wired the way the relocation table wires them."""

    def __init__(self, image, patches=None, stub_compress=False, tables=None):
        self.m = Machine(image, patches)
        self.events = []
        self.stub_compress = stub_compress
        self.tables = tables
        m = self.m
        st = m.memory.statics
        st[MEMCPY_SLOT] = MARK_MEMCPY
        st[MEMSET_SLOT] = MARK_MEMSET
        st[PANIC_SLOT] = MARK_PANIC
        m.slots[MARK_MEMCPY] = self.hook_memcpy
        m.slots[MARK_MEMSET] = self.hook_memset
        m.slots[MARK_PANIC] = self.hook_panic
        if stub_compress:
            st[COMPRESS_SLOT] = MARK_COMPRESS
            m.slots[MARK_COMPRESS] = self.hook_compress
        else:
            st[COMPRESS_SLOT] = image.relative()[COMPRESS_SLOT]
            m.real = frozenset([COMPRESS])

    def hook_memcpy(self, m):
        dst, src, count = m.regs[RDI], m.regs[RSI], m.regs[RDX]
        m.memory.copy(dst, src, count)
        self.events.append(("memcpy", count, src - DATA_AT))

    def hook_memset(self, m):
        dst, value, count = m.regs[RDI], m.regs[RSI] & 0xFF, m.regs[RDX]
        if value != 0:
            raise Halt("memset with nonzero value")
        m.memory.put_bytes(dst, bytes(count))
        self.events.append(("memset", count))

    def hook_panic(self, m):
        raise Panicked("panic slot called")

    def hook_compress(self, m):
        state = struct.unpack("<5I", m.memory.bytes_at(m.regs[RDI], 20))
        blk = m.memory.bytes_at(m.regs[RSI], 64)
        self.events.append(("compress", bytes(blk)))
        m.memory.put_bytes(m.regs[RDI], struct.pack("<5I", *compress_model(state, words_of(blk), self.tables)))

    def run_compress(self, state, block):
        m = self.m
        m.memory.reset(0x4000)
        m.memory.put_bytes(STATE_AT, struct.pack("<5I", *state))
        m.memory.put_bytes(BLOCK_AT, block)
        m.run(COMPRESS, {RDI: STATE_AT, RSI: BLOCK_AT})
        return struct.unpack("<5I", m.memory.bytes_at(STATE_AT, 20))

    def run_wrapper(self, data):
        m = self.m
        m.memory.reset(0x4000)
        self.events = []
        m.memory.put_bytes(DATA_AT, data)
        steps = m.steps
        ret = m.run(WRAPPER, {RDI: OUT_AT, RSI: 0x1234, RDX: DATA_AT, RCX: len(data)})
        if ret != OUT_AT:
            raise Halt("result pointer not returned")
        return m.memory.bytes_at(OUT_AT, 32), list(self.events), m.steps - steps


# ----------------------------------------------------------------------------- evidence from ELF bytes

def function_rows(image):
    rows = []
    for role, va in (("ripemd_wrapper", WRAPPER), ("ripemd_block", COMPRESS), ("sha256_wrapper", SHA_BODY), ("sha256_block", 0x5C63ED0)):
        start, end = image.exact_fde(va)
        off = image.offset(start)
        rows.append((role, start, end, end - start, hashlib.sha256(image.blob[off:off + end - start]).hexdigest()))
    return rows


def slot_rows(image):
    rows = []
    rel = {slot: (kind, sym, add) for slot, kind, add, sym in image.relocations()}
    for role, slot in (("table entry sha256 body", TABLE_SLOT - 8), ("table entry ripemd body", TABLE_SLOT),
                       ("compress pointer", COMPRESS_SLOT), ("sha256 compress pointer", 0x64E1420), ("memcpy import", MEMCPY_SLOT), ("memset import", MEMSET_SLOT),
                       ("panic pointer", PANIC_SLOT)):
        kind, sym, add = rel.get(slot, (-1, 0, 0))
        rows.append((role, slot, kind, sym, add))
    return rows


def decoded(image, start, end):
    return decode_range(image, start, end)


def constant_rows(image):
    start, end = image.exact_fde(COMPRESS)
    code = image.blob[image.offset(start):image.offset(start) + end - start]
    rows = []
    for side, table in (("left", K_LEFT), ("right", K_RIGHT)):
        for rnd, k in enumerate(table):
            if k == 0:
                rows.append((side, rnd, k, 0))
                continue
            rows.append((side, rnd, k, code.count(struct.pack("<I", k))))
    return rows


def rotation_rows(image):
    """Histogram of rol-by-immediate counts in the block body against the model's 160 data rotations and 160 rol 10."""
    start, end = image.exact_fde(COMPRESS)
    got = {}
    for row in decoded(image, start, end):
        if row.op == "rol" and row.b is not None and row.b[0] == "i" and row.width == 4:
            got[row.b[1]] = got.get(row.b[1], 0) + 1
    want = {}
    for s in S_LEFT + S_RIGHT:
        want[s] = want.get(s, 0) + 1
    want[10] = want.get(10, 0) + 160
    return [(count, want.get(count, 0), got.get(count, 0)) for count in sorted(set(want) | set(got))]


def opcode_rows(image):
    out = {}
    for name, va in (("ripemd_block", COMPRESS), ("ripemd_wrapper", WRAPPER)):
        start, end = image.exact_fde(va)
        counts = {}
        for row in decoded(image, start, end):
            counts[row.op] = counts.get(row.op, 0) + 1
        out[name] = counts
    return out


# ----------------------------------------------------------------------------- cases

def run_compress_cases(image, count, sample, seed=0x5EED0001):
    rng = Rng(seed)
    rig = Rig(image)
    matched = 0
    steps = 0
    rows = []
    for index in range(count):
        mode = index % 4
        state = tuple(rng.next() & MASK32 for _ in range(5)) if mode else INIT
        block = rng.blob(64)
        if mode == 2:
            block = bytes(64) if index % 8 == 2 else bytes([0xFF]) * 64
        elif mode == 3:
            state = tuple((0, MASK32, 0x80000000, 1, 0x7FFFFFFF)[(i + index) % 5] for i in range(5))
        before = rig.m.steps
        got = rig.run_compress(state, block)
        steps += rig.m.steps - before
        want = compress_model(state, words_of(block))
        if got != want:
            raise ToolError("compress mismatch at case %d" % index)
        matched += 1
        if index < sample:
            rows.append((index, ",".join("%08x" % w for w in state), block.hex(), ",".join("%08x" % w for w in got)))
    return matched, steps, rows


def wrapper_lengths(extra):
    lens = list(range(0, 133)) + [183, 184, 185, 191, 192, 193, 247, 248, 255, 256, 257, 311, 312, 319, 320, 321]
    return lens + extra


def run_wrapper_cases(image, count_stub, count_real, sample, seed=0x5EED0002):
    rng = Rng(seed)
    lens = wrapper_lengths([])
    stub = Rig(image, stub_compress=True)
    real = Rig(image)
    rows = []
    done = 0
    for index in range(count_stub + count_real):
        use_real = index >= count_stub
        n = lens[index % len(lens)] if index < len(lens) * 2 else rng.below(330)
        if use_real:
            n = (n % 200)
        data = rng.blob(n)
        if index % 7 == 3:
            data = bytes([0xFF]) * n
        want, wevents = wrapper_model(data)
        rig = real if use_real else stub
        got, events, steps = rig.run_wrapper(data)
        if got != want:
            raise ToolError("wrapper result mismatch at case %d (length %d)" % (index, n))
        if not use_real and events != wevents:
            raise ToolError("wrapper event mismatch at case %d (length %d)" % (index, n))
        if use_real:
            memonly = [e for e in events if e[0] != "compress"]
            if memonly != [e for e in wevents if e[0] != "compress"]:
                raise ToolError("wrapper memory-call mismatch at case %d" % index)
        done += 1
        if index < sample:
            rows.append((index, n, "real" if use_real else "stub", sum(1 for e in wevents if e[0] == "compress"), want[12:].hex()))
    return done, rows


# ----------------------------------------------------------------------------- negative controls

def model_mutants():
    """Single-parameter replacements of the model; every one must differ from the machine bytes on the control inputs."""
    out = []

    def make(name, fn):
        t = Tables()
        fn(t)
        out.append((name, "model-table", t))

    for pos in (0, 17, 35, 52, 71, 79):
        def f(t, pos=pos):
            r = list(t.r_left)
            r[pos] = (r[pos] + 1) % 16
            t.r_left = tuple(r)
        make("r_left[%d]+1" % pos, f)
    for pos in (1, 20, 41, 60, 78):
        def f(t, pos=pos):
            r = list(t.r_right)
            r[pos] = (r[pos] + 1) % 16
            t.r_right = tuple(r)
        make("r_right[%d]+1" % pos, f)
    for pos in (2, 19, 33, 50, 79):
        def f(t, pos=pos):
            s = list(t.s_left)
            s[pos] += 1
            t.s_left = tuple(s)
        make("s_left[%d]+1" % pos, f)
    for pos in (3, 27, 47, 65, 77):
        def f(t, pos=pos):
            s = list(t.s_right)
            s[pos] -= 1
            t.s_right = tuple(s)
        make("s_right[%d]-1" % pos, f)
    for rnd in range(1, 5):
        def f(t, rnd=rnd):
            k = list(t.k_left)
            k[rnd] ^= 0x100
            t.k_left = tuple(k)
        make("k_left[%d]^0x100" % rnd, f)
    for rnd in range(0, 4):
        def f(t, rnd=rnd):
            k = list(t.k_right)
            k[rnd] ^= 1
            t.k_right = tuple(k)
        make("k_right[%d]^1" % rnd, f)
    for rnd in range(5):
        def f(t, rnd=rnd):
            fl = list(t.func_left)
            fl[rnd] = (fl[rnd] + 1) % 5
            t.func_left = tuple(fl)
        make("func_left[%d]+1" % rnd, f)
    make("right line uses left function order", lambda t: setattr(t, "func_right", FUNCS))
    make("rotate-10 becomes rotate-11", lambda t: setattr(t, "rot10", 11))
    make("cross combination uses the wrong right-line words", lambda t: setattr(t, "combine", 1))
    make("final addition dropped", lambda t: setattr(t, "final_add", False))
    make("initial word 4 changed", lambda t: setattr(t, "init", INIT[:4] + (0xC3D2E1F1,)))
    return out


def pad_mutants():
    out = []

    def make(name, fn):
        o = PadOptions()
        fn(o)
        out.append((name, "model-padding", o))

    make("pad byte 0x81", lambda o: setattr(o, "pad_byte", 0x81))
    make("split at 55", lambda o: setattr(o, "split", 55))
    make("split at 57", lambda o: setattr(o, "split", 57))
    make("big-endian bit length", lambda o: setattr(o, "length_order", ">"))
    make("length counted in bytes", lambda o: setattr(o, "length_unit", 1))
    make("digest left of padding", lambda o: setattr(o, "left_pad", False))
    return out


CONTROL_LENGTHS = tuple(list(range(0, 70)) + [119, 120, 121, 127, 128, 129, 183, 184, 185, 191, 192, 193])


def control_inputs(image):
    """Machine answers for the control inputs, computed once and compared against every model mutant."""
    rng = Rng(0xC0DE0001)
    compress_in = []
    for index in range(6):
        compress_in.append((tuple(rng.next() & MASK32 for _ in range(5)), rng.blob(64)))
    rig = Rig(image)
    compress_out = [rig.run_compress(s, b) for s, b in compress_in]
    wrapper_in = [rng.blob(n) for n in CONTROL_LENGTHS]
    stub = Rig(image, stub_compress=True)
    wrapper_out = []
    for data in wrapper_in:
        got, events, _ = stub.run_wrapper(data)
        wrapper_out.append((got, events))
    return compress_in, compress_out, wrapper_in, wrapper_out


def model_mutant_detected(kind, param, ctl):
    compress_in, compress_out, wrapper_in, wrapper_out = ctl
    if kind == "model-table":
        for (s, b), want in zip(compress_in, compress_out):
            if compress_model(s, words_of(b), param) != want:
                return True
        for data, (got, events) in zip(wrapper_in, wrapper_out):
            if wrapper_model(data, param)[0] != got:
                return True
        return False
    for data, (got, events) in zip(wrapper_in, wrapper_out):
        try:
            res, ev = wrapper_model(data, None, param)
        except ValueError:
            return True  # the variant cannot even lay out its own padding
        if res != got or ev != events:
            return True
    return False


def sites_in_block(image):
    start, end = image.exact_fde(COMPRESS)
    rows = decoded(image, start, end)
    rol_sites = [r for r in rows if r.op == "rol" and r.b is not None and r.b[0] == "i" and r.width == 4 and r.imm_at]
    const_sites = []
    code_off = image.offset(start)
    code = image.blob[code_off:code_off + end - start]
    for rnd, k in enumerate(K_LEFT + K_RIGHT):
        if k == 0:
            continue
        pat = struct.pack("<I", k)
        pos = code.find(pat)
        while pos >= 0:
            const_sites.append((start + pos, k))
            pos = code.find(pat, pos + 1)
    return rol_sites, const_sites


def byte_mutants_block(image):
    rol_sites, const_sites = sites_in_block(image)
    out = []
    step = len(rol_sites) // 12
    for i in range(12):
        site = rol_sites[i * step + 3]
        va = site.va + site.imm_at
        out.append(("block rol immediate at %#x" % va, "byte-patch", (va, image.blob[image.offset(va)] ^ 1)))
    step = len(const_sites) // 10
    for i in range(10):
        va, k = const_sites[i * step + 1]
        out.append(("block constant byte at %#x" % va, "byte-patch", (va, image.blob[image.offset(va)] ^ 0x10)))
    return out


def wrapper_patch_sites(image):
    """(label, va) of the wrapper bytes that carry the padding rules, found by fixed byte patterns inside the wrapper FDE."""
    start, end = image.exact_fde(WRAPPER)
    off = image.offset(start)
    code = bytes(image.blob[off:off + end - start])
    patterns = (
        ("full-block threshold cmp rcx,0x40", bytes.fromhex("4883f940"), 3),
        ("tail mask and r12d,0x3f", bytes.fromhex("4183e43f"), 3),
        ("block count shift shr rcx,6", bytes.fromhex("48c1e906"), 3),
        ("bit length shift shl rcx,9", bytes.fromhex("48c1e109"), 3),
        ("pad byte store 0x80", bytes.fromhex("42c6842cd000000080"), 8),
        ("full tail test cmp r13,0x3f", bytes.fromhex("4983fd3f"), 3),
        ("memset count xor rdx,0x3f", bytes.fromhex("4883f23f"), 3),
        ("two-block test xor r13d,0x38", bytes.fromhex("4183f538"), 3),
        ("two-block test cmp r13d,7", bytes.fromhex("4183fd07"), 3),
        ("result byte-count store", bytes.fromhex("4c89a4240801"), 5),
    )
    out = []
    for label, pat, at in patterns:
        pos = code.find(pat)
        if pos < 0:
            raise ToolError("wrapper pattern missing: " + label)
        out.append((label, start + pos + at))
    return out


def byte_mutants_wrapper(image):
    out = []
    for label, va in wrapper_patch_sites(image):
        out.append(("wrapper " + label + " at %#x" % va, "byte-patch-wrapper", (va, image.blob[image.offset(va)] ^ 1)))
    return out


def machine_mutant_detected(image, kind, param, ctl):
    compress_in, compress_out, wrapper_in, wrapper_out = ctl
    va, byte = param
    patches = {va: byte}
    try:
        if kind == "byte-patch":
            rig = Rig(image, patches)
            rig.m.step_limit = MUTANT_STEP_LIMIT
            for (s, b), want in zip(compress_in[:3], compress_out[:3]):
                if rig.run_compress(s, b) != want:
                    return True
            return False
        rig = Rig(image, patches, stub_compress=True)
        rig.m.step_limit = MUTANT_STEP_LIMIT
        for data, (got, events) in zip(wrapper_in, wrapper_out):
            res, ev, _ = rig.run_wrapper(data)
            if res != got or ev != events:
                return True
        return False
    except (Halt, Panicked, EvidenceError, struct.error, IndexError):
        return True


def range_controls(image):
    """Inputs and addresses outside the admitted range: each must be refused rather than answered."""
    out = []

    def attempt(name, fn):
        try:
            fn()
        except (Halt, Panicked, EvidenceError, ToolError, ValueError, struct.error):
            out.append((name, "out-of-range", True))
        else:
            out.append((name, "out-of-range", False))

    attempt("wrong binary digest", lambda: load_image_bytes(b"x" * 64))
    attempt("not an FDE start", lambda: image.exact_fde(COMPRESS + 1))
    attempt("address outside sections", lambda: image.offset(0x10))
    attempt("address past the last FDE", lambda: image.fde(0x7FFFFFFFFFFF))
    rig = Rig(image)

    def unmapped_input():
        rig.m.memory.reset(0x4000)
        rig.m.run(WRAPPER, {RDI: OUT_AT, RSI: 0, RDX: 0x10, RCX: 16})

    attempt("input pointer outside memory", unmapped_input)

    def short_stack_output():
        rig.m.memory.reset(0x4000)
        rig.m.run(WRAPPER, {RDI: 0x10, RSI: 0, RDX: DATA_AT, RCX: 3})

    attempt("result pointer outside memory", short_stack_output)

    def memset_nonzero():
        r2 = Rig(image, stub_compress=True)
        r2.hook_memset(HookArgs(RDI=OUT_AT, RSI=1, RDX=4, memory=r2.m.memory))

    attempt("memset of a nonzero byte", memset_nonzero)
    return out


class HookArgs:
    def __init__(self, **kw):
        self.regs = [0] * 16
        self.regs[RDI] = kw["RDI"]
        self.regs[RSI] = kw["RSI"]
        self.regs[RDX] = kw["RDX"]
        self.memory = kw["memory"]


def load_image_bytes(blob):
    digest = hashlib.sha256(blob).hexdigest()
    if digest != SHA256:
        raise EvidenceError("binary SHA-256 mismatch: " + digest)
    return Image(blob)


def check_vectors(image):
    rig = Rig(image)
    rows = []
    for data, hexdigest in VECTORS:
        if ripemd160_digest(data).hex() != hexdigest:
            raise ToolError("model disagrees with published vector " + hexdigest)
        got, _, _ = rig.run_wrapper(data)
        if got != bytes(12) + bytes.fromhex(hexdigest):
            raise ToolError("machine bytes disagree with published vector " + hexdigest)
        rows.append((len(data), hexdigest))
    return rows


# ----------------------------------------------------------------------------- SHA-256 body (portable arm)
#
# The neighbouring table entry 0x64bff80 is the SHA-256 body at 0x5bed690.  It has the same shape as the RIPEMD body, but its block
# function (0x5c63ed0, reached through the relocated slot 0x64e1420) takes a block COUNT in rdx and first tests a CPU-feature byte at
# 0x64fe3f9: 0xff = not yet probed (cpuid helpers), 1 = hardware arm (tail jump to 0x5c66b90), anything else = portable arm at 0x5c63fc6.
# Only the portable arm (byte value 0) is run here; the other two arms are listed as not covered.

SHA_WRAPPER = SHA_BODY
SHA_COMPRESS = 0x5C63ED0
SHA_SLOT = 0x64E1420
SHA_FLAG = 0x64FE3F9
MARK_SHA_COMPRESS = 0x7700000005


def first_primes(count):
    out = []
    n = 2
    while len(out) < count:
        if all(n % p for p in out if p * p <= n):
            out.append(n)
        n += 1
    return out


def icbrt(n):
    lo, hi = 0, 1 << (n.bit_length() // 3 + 2)
    while lo < hi:
        mid = (lo + hi + 1) // 2
        if mid ** 3 <= n:
            lo = mid
        else:
            hi = mid - 1
    return lo


def isqrt_floor(n):
    lo, hi = 0, 1 << (n.bit_length() // 2 + 2)
    while lo < hi:
        mid = (lo + hi + 1) // 2
        if mid * mid <= n:
            lo = mid
        else:
            hi = mid - 1
    return lo


SHA_PRIMES = first_primes(64)
SHA_K = tuple(icbrt(p << 96) & MASK32 for p in SHA_PRIMES)  # fractional bits of the cube roots, as in the SHA-256 definition
SHA_INIT = tuple(isqrt_floor(p << 64) & MASK32 for p in SHA_PRIMES[:8])


def ror32(value, count):
    return (value >> count | value << (32 - count)) & MASK32


class ShaTables:
    def __init__(self):
        self.k = SHA_K
        self.rot_s0 = (7, 18, 3)
        self.rot_s1 = (17, 19, 10)
        self.rot_e = (6, 11, 25)
        self.rot_a = (2, 13, 22)
        self.init = SHA_INIT
        self.choose = 0
        self.majority = 0


def sha_compress_model(state, block, t=None):
    t = t or ShaTables()
    w = list(struct.unpack(">16I", block))
    for i in range(16, 64):
        s0 = ror32(w[i - 15], t.rot_s0[0]) ^ ror32(w[i - 15], t.rot_s0[1]) ^ (w[i - 15] >> t.rot_s0[2])
        s1 = ror32(w[i - 2], t.rot_s1[0]) ^ ror32(w[i - 2], t.rot_s1[1]) ^ (w[i - 2] >> t.rot_s1[2])
        w.append((w[i - 16] + s0 + w[i - 7] + s1) & MASK32)
    a, b, c, d, e, f, g, h = state
    for i in range(64):
        s1 = ror32(e, t.rot_e[0]) ^ ror32(e, t.rot_e[1]) ^ ror32(e, t.rot_e[2])
        ch = (e & f) ^ (~e & g) if t.choose == 0 else (e & f) ^ (e & g)
        t1 = (h + s1 + ch + t.k[i] + w[i]) & MASK32
        s0 = ror32(a, t.rot_a[0]) ^ ror32(a, t.rot_a[1]) ^ ror32(a, t.rot_a[2])
        mj = (a & b) ^ (a & c) ^ (b & c) if t.majority == 0 else (a & b) ^ (a & c)
        t2 = (s0 + mj) & MASK32
        h, g, f, e, d, c, b, a = g, f, e, (d + t1) & MASK32, c, b, a, (t1 + t2) & MASK32
    return tuple((x + y) & MASK32 for x, y in zip(state, (a, b, c, d, e, f, g, h)))


def sha_options():
    opts = PadOptions()
    opts.length_order = ">"
    return opts


def sha_wrapper_model(data, t=None, opts=None):
    """Return (32-byte digest, events); events: ('compress', count, bytes), ('memcpy', count, offset), ('memset', count)."""
    opts = opts or sha_options()
    n = len(data)
    events = []
    state = t.init if t else SHA_INIT
    if n < 64:
        events.append(("memcpy", n, 0))
        tail = bytes(data)
    else:
        full = n // 64
        body = bytes(data[:full * 64])
        events.append(("compress", full, body))
        for i in range(full):
            state = sha_compress_model(state, body[i * 64:(i + 1) * 64], t)
        events.append(("memcpy", n - full * 64, full * 64))
        tail = bytes(data[full * 64:])
    if len(tail) != 63:
        events.append(("memset", 63 - len(tail)))
    for blk in padded_blocks(n, tail, opts):
        events.append(("compress", 1, blk))
        state = sha_compress_model(state, blk, t)
    return struct.pack(">8I", *state), events


class ShaRig:
    def __init__(self, image, patches=None, stub_compress=False, tables=None):
        self.m = Machine(image, patches)
        self.events = []
        self.tables = tables
        m = self.m
        st = m.memory.statics
        st[MEMCPY_SLOT] = MARK_MEMCPY
        st[MEMSET_SLOT] = MARK_MEMSET
        st[PANIC_SLOT] = MARK_PANIC
        st[SHA_FLAG] = 0
        m.slots[MARK_MEMCPY] = self.hook_memcpy
        m.slots[MARK_MEMSET] = self.hook_memset
        m.slots[MARK_PANIC] = self.hook_panic
        if stub_compress:
            st[SHA_SLOT] = MARK_SHA_COMPRESS
            m.slots[MARK_SHA_COMPRESS] = self.hook_compress
        else:
            st[SHA_SLOT] = image.relative()[SHA_SLOT]
            m.real = frozenset([SHA_COMPRESS])

    hook_memcpy = Rig.hook_memcpy
    hook_memset = Rig.hook_memset
    hook_panic = Rig.hook_panic

    def hook_compress(self, m):
        state = struct.unpack("<8I", m.memory.bytes_at(m.regs[RDI], 32))
        count = m.regs[RDX]
        data = bytes(m.memory.bytes_at(m.regs[RSI], 64 * count))
        self.events.append(("compress", count, data))
        for i in range(count):
            state = sha_compress_model(state, data[i * 64:(i + 1) * 64], self.tables)
        m.memory.put_bytes(m.regs[RDI], struct.pack("<8I", *state))

    def run_compress(self, state, block):
        m = self.m
        m.memory.reset(0x4000)
        m.memory.put_bytes(STATE_AT, struct.pack("<8I", *state))
        m.memory.put_bytes(BLOCK_AT, block)
        m.run(SHA_COMPRESS, {RDI: STATE_AT, RSI: BLOCK_AT, RDX: len(block) // 64})
        return struct.unpack("<8I", m.memory.bytes_at(STATE_AT, 32))

    def run_wrapper(self, data):
        m = self.m
        m.memory.reset(0x4000)
        self.events = []
        m.memory.put_bytes(DATA_AT, data)
        steps = m.steps
        ret = m.run(SHA_WRAPPER, {RDI: OUT_AT, RSI: 0x1234, RDX: DATA_AT, RCX: len(data)})
        if ret != OUT_AT:
            raise Halt("result pointer not returned")
        return m.memory.bytes_at(OUT_AT, 32), list(self.events), m.steps - steps


def sha_check_vectors(image):
    import hashlib as hl
    rig = ShaRig(image)
    rows = []
    for data in (b"", b"abc", b"a" * 55, b"a" * 56, b"a" * 64, bytes(range(200))):
        want = hl.sha256(data).digest()
        if sha_wrapper_model(data)[0] != want:
            raise ToolError("sha model disagrees with hashlib")
        got, _, _ = rig.run_wrapper(data)
        if got != want:
            raise ToolError("sha machine bytes disagree with hashlib")
        rows.append((len(data), want.hex()))
    return rows


def sha_function_rows(image):
    rows = []
    for role, va in (("sha256_wrapper", SHA_WRAPPER), ("sha256_block", SHA_COMPRESS)):
        start, end = image.exact_fde(va)
        off = image.offset(start)
        rows.append((role, start, end, end - start, hashlib.sha256(image.blob[off:off + end - start]).hexdigest()))
    return rows


def sha_constant_rows(image):
    start, end = image.exact_fde(SHA_COMPRESS)
    code = image.blob[image.offset(start):image.offset(start) + end - start]
    return [(i, "%08x" % k, code.count(struct.pack("<I", k))) for i, k in enumerate(SHA_K)]


def run_sha_compress_cases(image, count, sample, seed=0x5EED0003):
    rng = Rng(seed)
    rig = ShaRig(image)
    steps = 0
    rows = []
    for index in range(count):
        state = tuple(rng.next() & MASK32 for _ in range(8)) if index % 3 else SHA_INIT
        block = rng.blob(64) if index % 5 else bytes([index & 0xFF]) * 64
        before = rig.m.steps
        got = rig.run_compress(state, block)
        steps += rig.m.steps - before
        if got != sha_compress_model(state, block):
            raise ToolError("sha compress mismatch at case %d" % index)
        if index < sample:
            rows.append((index, ",".join("%08x" % w for w in state), block.hex(), ",".join("%08x" % w for w in got)))
    return count, steps, rows


def run_sha_wrapper_cases(image, count_stub, count_real, sample, seed=0x5EED0004):
    rng = Rng(seed)
    lens = wrapper_lengths([])
    stub = ShaRig(image, stub_compress=True)
    real = ShaRig(image)
    rows = []
    for index in range(count_stub + count_real):
        use_real = index >= count_stub
        n = lens[index % len(lens)] if index < len(lens) * 2 else rng.below(330)
        if use_real:
            n = n % 200
        data = rng.blob(n)
        want, wevents = sha_wrapper_model(data)
        if hashlib.sha256(data).digest() != want:
            raise ToolError("sha model disagrees with hashlib at case %d" % index)
        got, events, _ = (real if use_real else stub).run_wrapper(data)
        if got != want:
            raise ToolError("sha wrapper result mismatch at case %d (length %d)" % (index, n))
        if not use_real and events != wevents:
            raise ToolError("sha wrapper event mismatch at case %d (length %d)" % (index, n))
        if use_real and [e for e in events if e[0] != "compress"] != [e for e in wevents if e[0] != "compress"]:
            raise ToolError("sha wrapper memory-call mismatch at case %d" % index)
        if index < sample:
            rows.append((index, n, "real" if use_real else "stub", sum(e[1] for e in wevents if e[0] == "compress"), want.hex()))
    return count_stub + count_real, rows


def sha_model_mutants():
    out = []

    def make(name, fn):
        t = ShaTables()
        fn(t)
        out.append((name, "sha-model", t))

    for i in (0, 17, 33, 63):
        def f(t, i=i):
            k = list(t.k)
            k[i] ^= 1
            t.k = tuple(k)
        make("sha k[%d]^1" % i, f)
    for field in ("rot_s0", "rot_s1", "rot_e", "rot_a"):
        for pos in range(3):
            def f(t, field=field, pos=pos):
                v = list(getattr(t, field))
                v[pos] += 1
                setattr(t, field, tuple(v))
            make("sha %s[%d]+1" % (field, pos), f)
    make("sha choose function replaced", lambda t: setattr(t, "choose", 1))
    make("sha majority function replaced", lambda t: setattr(t, "majority", 1))
    make("sha initial word 7 changed", lambda t: setattr(t, "init", SHA_INIT[:7] + (SHA_INIT[7] ^ 1,)))
    return out


def sha_control_inputs(image):
    rng = Rng(0xC0DE0002)
    compress_in = [(tuple(rng.next() & MASK32 for _ in range(8)), rng.blob(64)) for _ in range(4)]
    rig = ShaRig(image)
    compress_out = [rig.run_compress(s, b) for s, b in compress_in]
    return compress_in, compress_out


def sha_mutant_detected(param, ctl):
    compress_in, compress_out = ctl
    if sha_wrapper_model(b"abc", param)[0] != hashlib.sha256(b"abc").digest():
        return True
    return any(sha_compress_model(s, b, param) != want for (s, b), want in zip(compress_in, compress_out))


def sha_pad_mutants():
    out = []
    for name, fn in (("sha pad byte 0x81", lambda o: setattr(o, "pad_byte", 0x81)),
                     ("sha split at 55", lambda o: setattr(o, "split", 55)),
                     ("sha little-endian bit length", lambda o: setattr(o, "length_order", "<")),
                     ("sha length counted in bytes", lambda o: setattr(o, "length_unit", 1))):
        o = sha_options()
        fn(o)
        out.append((name, "sha-padding", o))
    return out


def sha_pad_detected(param):
    for n in (0, 3, 54, 55, 56, 57, 63, 64, 65, 120, 130):
        data = bytes(range(n % 251)) + bytes(n - n % 251)
        try:
            got = sha_wrapper_model(data, None, param)[0]
        except ValueError:
            return True
        if got != hashlib.sha256(data).digest():
            return True
    return False


def sha_byte_sites(image):
    """Fixed byte patterns inside the portable arm and the wrapper: (label, va of the patched byte)."""
    out = []
    for fde, patterns in (
        (SHA_WRAPPER, (("sha wrapper full-block threshold cmp rcx,0x40", bytes.fromhex("4883f940"), 3),
                       ("sha wrapper block count shift shr r14,6", bytes.fromhex("49c1ee06"), 3),
                       ("sha wrapper tail mask and r13d,0x3f", bytes.fromhex("4183e53f"), 3),
                       ("sha wrapper pad byte store 0x80", bytes.fromhex("42c6843c9800000080"), 8),
                       ("sha wrapper bit length shift shl rax,9", bytes.fromhex("48c1e009"), 3),
                       ("sha wrapper memset count xor rdx,0x3f", bytes.fromhex("4883f23f"), 3))),
    ):
        start, end = image.exact_fde(fde)
        off = image.offset(start)
        code = bytes(image.blob[off:off + end - start])
        for label, pat, at in patterns:
            pos = code.find(pat)
            if pos < 0:
                raise ToolError("sha wrapper pattern missing: " + label)
            out.append((label, start + pos + at))
    return out


def sha_block_sites(image):
    start, end = image.exact_fde(SHA_COMPRESS)
    rows = decode_range(image, start, end)
    arm = [r for r in rows if r.va >= 0x5C63FC6]
    rors = [r for r in arm if r.op == "rol" and r.b is not None and r.b[0] == "i" and r.width == 4 and r.imm_at]
    return rors


def sha_machine_mutants(image):
    out = []
    for label, va in sha_byte_sites(image):
        out.append((label + " at %#x" % va, "sha-byte-wrapper", (va, image.blob[image.offset(va)] ^ 1)))
    rors = sha_block_sites(image)
    step = len(rors) // 10
    for i in range(10):
        r = rors[i * step + 2]
        va = r.va + r.imm_at
        out.append(("sha block rol immediate at %#x" % va, "sha-byte-block", (va, image.blob[image.offset(va)] ^ 1)))
    return out


def sha_machine_mutant_detected(image, kind, param, ctl):
    compress_in, compress_out = ctl
    va, byte = param
    try:
        if kind == "sha-byte-block":
            rig = ShaRig(image, {va: byte})
            rig.m.step_limit = MUTANT_STEP_LIMIT
            return any(rig.run_compress(s, b) != want for (s, b), want in zip(compress_in[:2], compress_out[:2]))
        rig = ShaRig(image, {va: byte}, stub_compress=True)
        rig.m.step_limit = MUTANT_STEP_LIMIT
        for n in CONTROL_LENGTHS:
            data = bytes(range(n % 251)) + bytes(n - n % 251)
            res, ev, _ = rig.run_wrapper(data)
            want, wev = sha_wrapper_model(data)
            if res != want or ev != wev:
                return True
        return False
    except (Halt, Panicked, EvidenceError, struct.error, IndexError):
        return True


# ----------------------------------------------------------------------------- driver

EQUIVALENT = (
    ("xor r13d,0x38", "the constant 0x39 differs from 0x38 only in bit 0; r13 ^ 0x38 and r13 ^ 0x39 are both above 7 exactly when r13 is outside 56..63, so the branch is identical"),
    ("cmp r13d,7", "the compare only separates the value 7 (tail length 63) from 0..6, but a tail of 63 bytes leaves through the earlier cmp r13,0x3f branch to the same two-block code, so the changed compare is never evaluated for 7"),
)

COMPRESS_CASES = 6000
WRAPPER_STUB_CASES = 4000
WRAPPER_REAL_CASES = 2000
SHA_COMPRESS_CASES = 4000
SHA_WRAPPER_STUB_CASES = 3000
SHA_WRAPPER_REAL_CASES = 1500
SAMPLE = 800


def write(path, text):
    with open(path, "w", newline="\n") as handle:
        handle.write(text)


def tsv(header, rows):
    return "\t".join(header) + "\n" + "".join("\t".join(str(c) for c in row) + "\n" for row in rows)


def build(out):
    out = pathlib.Path(out)
    out.mkdir(parents=True, exist_ok=True)
    image = load_image()
    vec = check_vectors(image)
    write(out / "functions.tsv", tsv(("role", "start", "end", "length", "sha256"),
                                       [(r, hex(s), hex(e), n, h) for r, s, e, n, h in function_rows(image)]))
    write(out / "slots.tsv", tsv(("role", "slot", "reloc_type", "symbol_index", "addend"),
                                   [(r, hex(s), k, y, hex(a)) for r, s, k, y, a in slot_rows(image)]))
    write(out / "constants.tsv", tsv(("line", "round", "constant", "byte_occurrences_in_block_body"),
                                       [(s, r, "%08x" % k, c) for s, r, k, c in constant_rows(image)]))
    write(out / "rotations.tsv", tsv(("rotate_count", "model_uses", "block_body_rol_imm32"), rotation_rows(image)))
    ops = opcode_rows(image)
    write(out / "opcodes.tsv", tsv(("body", "op", "count"), [(b, o, c) for b in sorted(ops) for o, c in sorted(ops[b].items())]))
    write(out / "vectors.tsv", tsv(("length", "digest"), vec))
    matched, csteps, crows = run_compress_cases(image, COMPRESS_CASES, SAMPLE)
    write(out / "compress-sample.tsv", tsv(("case", "state_in", "block", "state_out"), crows))
    wdone, wrows = run_wrapper_cases(image, WRAPPER_STUB_CASES, WRAPPER_REAL_CASES, SAMPLE)
    write(out / "wrapper-sample.tsv", tsv(("case", "length", "compress_body", "blocks", "digest"), wrows))
    sha_vec = sha_check_vectors(image)
    write(out / "sha-vectors.tsv", tsv(("length", "digest"), sha_vec))
    write(out / "sha-constants.tsv", tsv(("round", "constant", "byte_occurrences_in_block_body"), sha_constant_rows(image)))
    smatched, ssteps, srows = run_sha_compress_cases(image, SHA_COMPRESS_CASES, SAMPLE)
    write(out / "sha-compress-sample.tsv", tsv(("case", "state_in", "block", "state_out"), srows))
    swdone, swrows = run_sha_wrapper_cases(image, SHA_WRAPPER_STUB_CASES, SHA_WRAPPER_REAL_CASES, SAMPLE)
    write(out / "sha-wrapper-sample.tsv", tsv(("case", "length", "compress_body", "blocks", "digest"), swrows))
    ctl = control_inputs(image)
    sctl = sha_control_inputs(image)
    controls = []
    equivalent = []
    for name, kind, param in model_mutants() + pad_mutants():
        controls.append((name, kind, model_mutant_detected(kind, param, ctl)))
    for name, kind, param in byte_mutants_block(image) + byte_mutants_wrapper(image):
        controls.append((name, kind, machine_mutant_detected(image, kind, param, ctl)))
    for name, kind, param in sha_model_mutants():
        controls.append((name, kind, sha_mutant_detected(param, sctl)))
    for name, kind, param in sha_pad_mutants():
        controls.append((name, kind, sha_pad_detected(param)))
    for name, kind, param in sha_machine_mutants(image):
        controls.append((name, kind, sha_machine_mutant_detected(image, kind, param, sctl)))
    controls.extend(range_controls(image))
    kept = []
    for name, kind, d in controls:
        if d:
            kept.append((name, kind, True))
            continue
        reason = next((why for key, why in EQUIVALENT if key in name), None)
        if reason is None:
            raise ToolError("undetected control without an equivalence argument: " + name)
        equivalent.append((name.split(" at ")[0], name.split(" at ")[-1], reason))
    controls = [c for c in controls if c[2]]
    detected = len(controls)
    total_controls = detected + len(equivalent)
    write(out / "controls.tsv", tsv(("control", "kind", "detected"), [(n, k, int(d)) for n, k, d in sorted(kept, key=lambda c: c[0])]))
    write(out / "equivalent-mutants.tsv", tsv(("mutant", "address", "reason"), equivalent))
    cases = matched + wdone + len(vec) + smatched + swdone + len(sha_vec)
    write(out / "measure.json", json.dumps({
        "cases": cases, "negative_controls": total_controls, "negative_detected": detected, "equivalent": len(equivalent),
        "compress_cases": matched, "wrapper_stub_cases": WRAPPER_STUB_CASES, "wrapper_real_cases": WRAPPER_REAL_CASES,
        "published_vectors": len(vec), "sha_compress_cases": smatched, "sha_wrapper_stub_cases": SHA_WRAPPER_STUB_CASES,
        "sha_wrapper_real_cases": SHA_WRAPPER_REAL_CASES, "sha_hashlib_vectors": len(sha_vec)}, indent=1, sort_keys=True) + "\n")
    write(out / "summary.json", json.dumps({
        "target_sha256": SHA256, "wrapper": hex(WRAPPER), "block": hex(COMPRESS), "table_slot": hex(TABLE_SLOT),
        "compress_machine_steps": csteps, "sha_compress_machine_steps": ssteps, "controls": total_controls, "detected": detected, "equivalent": len(equivalent)}, indent=1, sort_keys=True) + "\n")
    names = sorted(p.name for p in out.iterdir() if p.is_file() and p.name not in ("MANIFEST.sha256", "README.md"))
    return names


def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", required=True)
    args = ap.parse_args(argv)
    build(args.out)
    return 0


if __name__ == "__main__":
    sys.exit(main())
