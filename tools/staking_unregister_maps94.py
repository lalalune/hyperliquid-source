#!/usr/bin/env python3
"""Recover the validator removal map path of node 94.

The instruction decoder and interpreter below are adapted from the repository's
staking_stake_accounting.py (MIT, Hyperliquid Source contributors). This tool
never executes the captured binary and imports the shared ELF and FDE parsers.
"""
import argparse
import bisect
import hashlib
import json
import pathlib
import struct
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))

from elf_index import sections  # noqa: E402
from fde_extents import eh_frame_records  # noqa: E402

BINARY = ROOT / "artifacts" / "node" / "94" / "hl-node"
SHA256 = "3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f"

RAX, RCX, RDX, RBX, RSP, RBP, RSI, RDI = range(8)
R8, R9, R10, R11, R12, R13, R14, R15 = range(8, 16)
VOLATILE = (RCX, RSI, RDI, R8, R9, R10, R11)
CALLEE_SAVED = (RBX, RBP, R12, R13, R14, R15)
MASK = {1: 0xFF, 2: 0xFFFF, 4: 0xFFFFFFFF, 8: 0xFFFFFFFFFFFFFFFF}
SIGN = {1: 0x80, 2: 0x8000, 4: 0x80000000, 8: 0x8000000000000000}
STACK_MARK = 0xA5
STACK_TOP = 0x7FF000000
STACK_SIZE = 0x8000
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


class BoundaryReached(Exception):
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
        self.named = {}
        for sec in self.sections:
            if sec["name"] in self.named:
                raise EvidenceError("duplicate section name")
            self.named[sec["name"]] = sec
        _, fdes = eh_frame_records(blob, self.sections)
        ends = {}
        self.fde_records = {}
        for row in fdes:
            if row["start"] in ends:
                raise EvidenceError("duplicate FDE start")
            ends[row["start"]] = row["end"]
            self.fde_records[row["start"]] = row
        self.fde_ends = ends
        self.starts = sorted(ends)

    def offset(self, va, size=1):
        if va < 0 or size < 0:
            raise EvidenceError("invalid address or size")
        matches = [sec for sec in self.mapped
                   if sec["address"] <= va and va + size <= sec["address"] + sec["size"]]
        if len(matches) != 1:
            raise EvidenceError("address lacks a unique file-backed mapping")
        return va - matches[0]["address"] + matches[0]["offset"]

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


def load_image(path=BINARY, expected=SHA256):
    blob = pathlib.Path(path).read_bytes()
    return image_from_blob(blob, expected)


def image_from_blob(blob, expected=SHA256):
    digest = hashlib.sha256(blob).hexdigest()
    if digest != expected:
        raise EvidenceError("binary SHA-256 mismatch: %s" % digest)
    return Image(blob)


def fdiv(left, right):
    return left / right


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
                  (0xDB, True): "andpd", (0xEB, True): "orpd", (0x58, True): "addpd", (0x5E, True): "divpd"}
        if (two, opsize) in vector:
            reg, rm = modrm(True)
            return finish(vector[(two, opsize)], ("x", reg), rm, 16)
        if two in (0x58, 0x59, 0x5C, 0x5D, 0x5E, 0x5F) and repne:
            reg, rm = modrm(True)
            return finish({0x58: "addsd", 0x59: "mulsd", 0x5C: "subsd", 0x5D: "minsd", 0x5E: "divsd", 0x5F: "maxsd"}[two], ("x", reg), rm, 8)
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

    def reset(self, used=HEAP_SIZE):
        """Refill the stack and the first `used` heap bytes; the rest must still be untouched."""
        self.stack[:] = self.fresh[0]
        self.heap[:used] = memoryview(self.fresh[1])[:used]

    def locate(self, addr, count):
        if self.stack_base <= addr and addr + count <= STACK_TOP:
            return self.stack, addr - self.stack_base
        if HEAP_BASE <= addr and addr + count <= HEAP_BASE + HEAP_SIZE:
            return self.heap, addr - HEAP_BASE
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
            offset = self.image.offset(addr, count)
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
        self.edges = set()
        self.steps = 0
        self.keep_rdx = False
        self.step_limit = STEP_LIMIT
        self.xmm_result = None

    def read_code(self, va, count):
        offset = self.image.offset(va, count)
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
            next_pc = self.step(row)
            if row.op == "jcc":
                self.edges.add((pc, next_pc))
            pc = next_pc
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
            count = row.b[1] % bits
            value = self.get(row.a, width)
            self.put(row.a, width, (value >> count | value << (bits - count)) & MASK[width])
        elif op == "rol":
            bits = 8 * width
            count = row.b[1] % bits
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
            count = (row.target if row.target is not None else self.regs[RCX]) & 63
            high, low = self.get(row.a, 8), self.get(row.b, 8)
            if op == "shld":
                value = (high << count | low >> (64 - count)) if count else high
            else:
                value = (high >> count | low << (64 - count)) if count else high
            self.put(row.a, 8, value)
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
            left, right = to_float(self.low(row.a)), to_float(self.low(row.b))
            if op == "addsd":
                result = left + right
            elif op == "divsd":
                result = fdiv(left, right)
            elif op == "subsd":
                result = left - right
            elif op == "mulsd":
                result = left * right
            elif op == "minsd":
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
        elif op in ("addpd", "divpd"):
            left, right = self.xmm[row.a[1]], self.vector(row.b)
            lanes = []
            for shift in (0, 64):
                one, two = to_float((left >> shift) & MASK[8]), to_float((right >> shift) & MASK[8])
                lanes.append(to_bits(one + two if op == "addpd" else fdiv(one, two)))
            self.xmm[row.a[1]] = lanes[0] | lanes[1] << 64
        elif op == "shufpd":
            left, right = self.xmm[row.a[1]], self.vector(row.b)
            first = (left >> (64 * (row.target & 1))) & MASK[8]
            second = (right >> (64 * ((row.target >> 1) & 1))) & MASK[8]
            self.xmm[row.a[1]] = first | second << 64
        elif op == "cmppd":
            if row.target != 5:
                raise Halt("unmodelled compare predicate at %#x" % row.va)
            left, right = self.xmm[row.a[1]], self.vector(row.b)
            value = 0
            for shift in (0, 64):
                if not to_float((left >> shift) & MASK[8]) < to_float((right >> shift) & MASK[8]):
                    value |= MASK[8] << shift
            self.xmm[row.a[1]] = value
        elif op == "movmskpd":
            value = self.xmm[row.b[1]]
            self.put(row.a, 4, int(bool(value >> 63 & 1)) | int(bool(value >> 127 & 1)) << 1)
        else:
            raise Halt("unmodelled operation %s at %#x" % (op, row.va))

    def vector(self, operand):
        if operand[0] == "x":
            return self.xmm[operand[1]]
        return int.from_bytes(self.memory.bytes_at(self.address(operand), 16), "little")



# Each selected entry was checked against the existing work-item address corpus.
STAKE_SEARCH = 0x33ab680
# This adapter belongs to an earlier packet; execution stops at its boundary.
STAKE_ADAPTER_BOUNDARY = 0x2fd8ea0
STATE_REMOVE = 0x33aae60
STATE_CURSOR = 0x2fda310
STATE_LEAF = 0x2fc6fc0
STATE_LEFT = 0x2fa5d00
STATE_RIGHT = 0x2fad5d0
STATE_MERGE = 0x2faded0
PROFILE_REMOVE = 0x33ac190
PROFILE_CURSOR = 0x2fda9d0
PROFILE_LEAF = 0x2fcb090
PROFILE_LEFT = 0x2fa7210
PROFILE_RIGHT = 0x2fac5e0
FUNCTIONS = (
    ('stake_search', STAKE_SEARCH),
    ('state_remove', STATE_REMOVE), ('state_cursor', STATE_CURSOR),
    ('state_leaf', STATE_LEAF), ('state_borrow_left', STATE_LEFT),
    ('state_borrow_right', STATE_RIGHT), ('state_merge', STATE_MERGE),
    ('profile_remove', PROFILE_REMOVE), ('profile_cursor', PROFILE_CURSOR),
    ('profile_leaf', PROFILE_LEAF), ('profile_borrow_left', PROFILE_LEFT),
    ('profile_borrow_right', PROFILE_RIGHT),
)
# Node fields are derived independently from the decoded operands below.
GEOMETRY = {
    'stake': dict(root=STAKE_SEARCH, key=0xb8, value=0, stride=16,
                  parent=0xb0, edge=0x194, length=0x196, children=0x198,
                  leaf_size=0x198, inner_size=0x1f8),
    'state': dict(root=STATE_REMOVE, key=8, value=0xe4, stride=28,
                  parent=0, edge=0x218, length=0x21a, children=0x220,
                  leaf_size=0x220, inner_size=0x280),
    'profile': dict(root=PROFILE_REMOVE, key=0x3d0, value=8, stride=88,
                    parent=0, edge=0x4ac, length=0x4ae, children=0x4b0,
                    leaf_size=0x4b0, inner_size=0x510),
}
SLOT_FREE = 0x576e010
SLOT_COMPARE = 0x576e488
SLOT_MOVE = 0x576e0e0
SLOT_COPY = 0x576dfe0
SLOT_PANICS = (0x576e470, 0x576e108, 0x576e098, 0x576dfb8, 0x576e020)
MARK_BASE = 0x7700000000
MAP_AT = HEAP_BASE + 0x100
OUTPUT_AT = HEAP_BASE + 0x200
KEY_AT = HEAP_BASE + 0x400
ARENA = HEAP_BASE + 0x10000


def key_bytes(number, pivot=19):
    if pivot is None:
        if not 0 <= number < (1 << 160):
            raise ValueError('key fixture outside address width')
        return number.to_bytes(20, 'big')
    if not 0 <= pivot < 20 or not 0 <= number <= 255:
        raise ValueError('key fixture outside byte range')
    key = bytearray((0x31 + 17*i) & 255 for i in range(20))
    key[pivot] = number
    return bytes(key)


def value_bytes(kind, number):
    if kind == 'stake':
        return number.to_bytes(8, 'little') + (number * 11).to_bytes(8, 'little')
    if kind == 'state':
        return (number.to_bytes(4, 'little') + (number + 1).to_bytes(4, 'little')
                + (number + 2).to_bytes(4, 'little') + (number + 3).to_bytes(4, 'little')
                + (number + 4).to_bytes(4, 'little') + (number + 5).to_bytes(4, 'little')
                + bytes([(number // 2) % 2, 0x42, 0x43, 0x44]))
    # Capacity words are ordinary non-niche values; all 88 bytes identify the row.
    return number.to_bytes(8, 'little') + bytes((number * 17 + i) % 256 for i in range(80))


class TreeCase:
    def __init__(self, image, kind, patches=None, pivot=19):
        self.kind = kind
        self.pivot = pivot
        self.g = GEOMETRY[kind]
        self.machine = Machine(image, patches)
        self.machine.real = {address for _, address in FUNCTIONS}
        self.machine.step_limit = 2000000
        self.mem = self.machine.memory
        self.next_addr = ARENA
        self.live = {}
        self.events = []
        self.cursor = None
        self.machine.calls[STAKE_ADAPTER_BOUNDARY] = self.adapter_boundary
        for slot, hook in ((SLOT_FREE, self.free), (SLOT_COMPARE, self.compare),
                           (SLOT_MOVE, self.copy), (SLOT_COPY, self.copy)):
            self.mem.statics[slot] = MARK_BASE + slot
            self.machine.slots[MARK_BASE + slot] = hook
        for slot in SLOT_PANICS:
            self.mem.statics[slot] = MARK_BASE + slot
            self.machine.slots[MARK_BASE + slot] = self.panic

    def adapter_boundary(self, m):
        cursor = m.regs[RSI]
        self.cursor = tuple(self.mem.read(cursor + i * 8, 8) for i in range(4))
        raise BoundaryReached('stake cursor boundary')

    def alloc(self, height):
        size = self.g['inner_size'] if height else self.g['leaf_size']
        at = self.next_addr
        self.next_addr += (size + 15) & ~15
        if self.next_addr >= HEAP_BASE + HEAP_SIZE:
            raise Halt('fixture arena exhausted')
        self.live[at] = size
        self.mem.put_bytes(at, b'\0' * size)
        return at

    def free(self, m):
        at, size = m.regs[RDI], m.regs[RSI]
        if self.live.get(at) != size:
            raise Halt('unexpected free or size')
        del self.live[at]
        self.events.append(('free', size))

    def compare(self, m):
        n = m.regs[RDX]
        if n != 20:
            raise Halt('unexpected comparison width')
        a = self.mem.bytes_at(m.regs[RDI], n)
        b = self.mem.bytes_at(m.regs[RSI], n)
        m.regs[RAX] = 0 if a == b else 1 if a > b else MASK[4]

    def copy(self, m):
        dst, src, n = m.regs[RDI], m.regs[RSI], m.regs[RDX]
        if n > 0x20000:
            raise Halt('unexpected copy length')
        self.mem.copy(dst, src, n)
        m.regs[RAX] = dst

    def panic(self, m):
        self.events.append(('panic', m.regs[RDI]))
        raise Panicked('target failure boundary')

    def node(self, keys, children=()):
        height = children[0][1] + 1 if children else 0
        if children and (len(children) != len(keys) + 1 or any(h != height - 1 for _, h in children)):
            raise ValueError('invalid fixture tree')
        if len(keys) > 11:
            raise ValueError('fixture node overflow')
        g, mem = self.g, self.mem
        at = self.alloc(height)
        mem.write(at + g['length'], 2, len(keys))
        for i, number in enumerate(keys):
            mem.put_bytes(at + g['key'] + 20 * i, key_bytes(number, self.pivot))
            mem.put_bytes(at + g['value'] + g['stride'] * i, value_bytes(self.kind, number))
        for i, (child, _) in enumerate(children):
            mem.write(at + g['children'] + i * 8, 8, child)
            mem.write(child + g['parent'], 8, at)
            mem.write(child + g['edge'], 2, i)
        return at, height

    def build(self, spec):
        # The shape is a nested tree of counts, filled in sorted in-order order.
        counter = [0]
        def next_number():
            counter[0] += 2
            return counter[0]
        def build_node(shape):
            if isinstance(shape, int):
                if shape < 0 or shape > 11:
                    raise ValueError('invalid leaf fixture')
                return self.node([next_number() for _ in range(shape)])
            if len(shape) < 2 or len(shape) > 12:
                raise ValueError('invalid internal fixture')
            children, keys = [], []
            for index, child in enumerate(shape):
                children.append(build_node(child))
                if index + 1 < len(shape):
                    keys.append(next_number())
            return self.node(keys, children)
        if spec is None:
            self.mem.write(MAP_AT, 8, 0)
            self.mem.write(MAP_AT + 8, 8, 0)
            self.mem.write(MAP_AT + 16, 8, 0)
            return 0
        root, height = build_node(spec)
        self.mem.write(MAP_AT, 8, root)
        self.mem.write(MAP_AT + 8, 8, height)
        self.mem.write(MAP_AT + 16, 8, counter[0] // 2)
        return counter[0] // 2

    def contents(self):
        g, mem = self.g, self.mem
        root, height, count = (mem.read(MAP_AT + 8*i, 8) for i in range(3))
        seen = set()
        def walk(node, depth, parent, edge):
            if node in seen or node not in self.live:
                raise Halt('invalid or freed tree pointer')
            seen.add(node)
            if mem.read(node + g['parent'], 8) != parent:
                raise Halt('wrong parent pointer')
            if parent and mem.read(node + g['edge'], 2) != edge:
                raise Halt('wrong parent edge')
            n = mem.read(node + g['length'], 2)
            if n > 11 or (parent and n < 5):
                raise Halt('tree occupancy outside valid bounds')
            result = []
            for i in range(n):
                if depth:
                    result.extend(walk(mem.read(node + g['children'] + i*8, 8), depth-1, node, i))
                result.append((mem.bytes_at(node + g['key'] + 20*i, 20),
                               mem.bytes_at(node + g['value'] + g['stride']*i, g['stride'])))
            if depth:
                result.extend(walk(mem.read(node + g['children'] + n*8, 8), depth-1, node, n))
            return result
        rows = walk(root, height, 0, 0) if root else []
        if len(rows) != count or any(a[0] >= b[0] for a,b in zip(rows, rows[1:])):
            raise Halt('tree order or global count mismatch')
        if set(self.live) != seen:
            raise Halt('orphaned fixture allocation')
        return rows, height

    def remove(self, number):
        self.mem.put_bytes(KEY_AT, key_bytes(number, self.pivot))
        self.mem.put_bytes(OUTPUT_AT, bytes([0xa5]) * 128)
        self.machine.run(self.g['root'], {RDI: OUTPUT_AT, RSI: MAP_AT, RDX: KEY_AT})
        if self.kind == 'state':
            found = self.mem.read(OUTPUT_AT + 24, 1) != 2
            val = self.mem.bytes_at(OUTPUT_AT, 28) if found else None
        else:
            found = self.mem.read(OUTPUT_AT, 8) != 1 << 63
            val = self.mem.bytes_at(OUTPUT_AT, 88) if found else None
        return val

# The caller windows only bind the map arguments and call order; the enclosing
# action host is outside this packet. Exact bytes make accidental drift fatal.
PINS = (
    ('action_niche_constant', 0x3994f41, '49bc0000000000000080'),
    ('action_word_load', 0x3994f59, '498b01'),
    ('action_niche_add', 0x3994f5c, '498d0c04'),
    ('action_niche_increment', 0x3994f60, '48ffc1'),
    ('action_sign', 0x3994f6b, '48c1f83f'),
    ('action_niche_mask', 0x3994f77, '4821c8'),
    ('register_branch', 0x3994f7a, '0f848b000000'),
    ('change_tag', 0x3994f85, '4883f801'),
    ('unregister_branch', 0x3994f89, '0f85c8000000'),
    ('validator_key_pointer', 0x3995145, '4c8b742458'),
    ('validator_tail_load', 0x399514a, '418b4610'),
    ('validator_tail_copy', 0x399514e, '89842430010000'),
    ('validator_head_load', 0x3995155, '410f1006'),
    ('validator_head_copy', 0x3995159, '0f29842420010000'),
    ('stake_map_argument', 0x3995161, '498d7710'),
    ('stake_key_argument', 0x399516d, '488d942420010000'),
    ('stake_map_call', 0x3995184, 'e8f764a1ff'),
    ('profile_map_argument', 0x399518e, '498db750010000'),
    ('profile_key_argument', 0x399519d, '4c89f2'),
    ('profile_map_call', 0x39951a0, 'e8eb6fa1ff'),
    ('state_map_argument', 0x39951e4, '4981c778020000'),
    ('state_map_pointer', 0x39951f3, '4c89fe'),
    ('state_key_argument', 0x39951f6, '4c89f2'),
    ('state_map_call', 0x39951f9, 'e8625ca1ff'),
    ('success_status', 0x39951fe, '66c745008601'),
    ('member_map_root', 0x3995061, '4d8bb780010000'),
    ('member_map_empty_test', 0x3995068, '4d85f6'),
    ('member_map_empty_branch', 0x399506b, '0f84d4000000'),
    ('member_hit_branch', 0x39950fa, '750c'),
    ('member_hit_jump', 0x39950fc, 'eb2c'),
    ('member_height_subtract', 0x3995112, '4883e801'),
    ('member_missing_branch', 0x3995116, '722d'),
    ('member_gate', 0x399512a, '48833b00'),
    ('zero_member_pass', 0x3995133, '7410'),
    ('member_refusal', 0x399513a, '66c745002f01'),
    ('state_length_load', 0x2fc6fe8, '0fb79d1a020000'),
    ('state_key_base', 0x2fc6ff4, '488d7c8508'),
    ('state_value_base', 0x2fc7055, '4881c7e4000000'),
    ('state_minimum', 0x2fc70a7, '6683f804'),
    ('state_left_limit', 0x2fc7122, '83fb0c'),
    ('state_right_limit', 0x2fc71b4, '83fb0c'),
    ('state_root_free_size', 0x33aaff0, 'be80020000'),
    ('profile_length_load', 0x2fcb0bb, '410fb79dae040000'),
    ('profile_key_base', 0x2fcb0c7, '498dbc85d0030000'),
    ('profile_value_stride', 0x2fcb118, '496bc458'),
    ('profile_minimum', 0x2fcb197, '6683fd04'),
    ('profile_left_limit', 0x2fcb219, '83fb0c'),
    ('profile_root_free_size', 0x33ac348, 'be10050000'),
)
MUTATIONS = (
    ('state_search', 'state', 5, 2, 0x33aaf05, 0x75),
    ('profile_search', 'profile', 5, 2, 0x33ac23a, 0x75),
    ('state_underflow', 'state', (5, 5), 2, 0x2fc70ac, 0x86),
    ('profile_underflow', 'profile', (5, 5), 2, 0x2fcb19c, 0x86),
    ('state_borrow_right', 'state', (5, 7), 2, 0x2fc71b7, 0x72),
    ('profile_borrow_right', 'profile', (5, 7), 2, 0x2fcb687, 0x72),
    ('state_borrow_left', 'state', (7, 5), 26, 0x2fc7126, 0x82),
    ('profile_borrow_left', 'profile', (7, 5), 26, 0x2fcb21d, 0x82),
)
DEEP_SHAPE = (((5, 5, 5, 5, 5, 5),) * 6, ((5, 5, 5, 5, 5, 5),) * 6)
SHAPES = (
    ('null', None), ('empty', 0), ('single', 1), ('leaf5', 5), ('leaf11', 11),
    ('merge_root', (5, 5)), ('merge_limit_right', (5, 6)),
    ('merge_limit_left', (6, 5)), ('borrow_right', (5, 7)),
    ('borrow_left', (7, 5)), ('no_repair', (7, 7)),
    ('merge_internal', (5, 5, 5)), ('large_siblings', (11, 11)),
    ('height2', ((5, 5, 5, 5, 5, 5), (5, 5, 5, 5, 5, 5))),
    ('height2_borrow', ((5, 5, 5, 5, 5, 5), (7, 7, 7, 7, 7, 7, 7, 7))),
    ('height2_borrow_left', ((7, 7, 7, 7, 7, 7, 7, 7), (5, 5, 5, 5, 5, 5))),
    ('height3', DEEP_SHAPE),
)


def verify_pins(image):
    rows = []
    for name, va, hexbytes in PINS:
        expected = bytes.fromhex(hexbytes)
        actual = bytes(image.blob[image.offset(va, len(expected)):][:len(expected)])
        if actual != expected:
            raise EvidenceError('context bytes changed: ' + name)
        rows.append((name, '0x%x' % va, actual.hex()))
    return rows


def hash_rows(rows):
    h = hashlib.sha256()
    for key, value in rows:
        h.update(key)
        h.update(value)
    return h.hexdigest()



def expected_first_repair(c, needle):
    # Predict from the input tree, before interpreting any removal instruction.
    g, mem = c.g, c.mem
    node, height = mem.read(MAP_AT, 8), mem.read(MAP_AT + 8, 8)
    while node:
        n = mem.read(node + g['length'], 2)
        keys = [mem.bytes_at(node + g['key'] + 20*i, 20) for i in range(n)]
        index = 0
        while index < n and keys[index] < needle:
            index += 1
        if index < n and keys[index] == needle:
            if height:
                node = mem.read(node + g['children'] + 8*index, 8)
                height -= 1
                while height:
                    count = mem.read(node + g['length'], 2)
                    node = mem.read(node + g['children'] + 8*count, 8)
                    height -= 1
            break
        if not height:
            return 'miss'
        node = mem.read(node + g['children'] + 8*index, 8)
        height -= 1
    if not node:
        return 'miss'
    n = mem.read(node + g['length'], 2)
    if n - 1 > 4:
        return 'no_repair'
    parent = mem.read(node + g['parent'], 8)
    if not parent:
        return 'root_leaf'
    edge = mem.read(node + g['edge'], 2)
    direction = 'left' if edge else 'right'
    sibling_index = edge - 1 if edge else 1
    sibling = mem.read(parent + g['children'] + 8*sibling_index, 8)
    sibling_count = mem.read(sibling + g['length'], 2)
    return direction + ('_borrow' if n + sibling_count >= 12 else '_merge')


def observed_first_repair(c, kind, found):
    if not found:
        return 'miss'
    branch_sites = ((0x2fc70ab, 0x2fc70b7, 0x2fc70cd, 0x2fc7125, 0x2fc71b7)
                    if kind == 'state' else
                    (0x2fcb19b, 0x2fcb1a7, 0x2fcb1c6, 0x2fcb21c, 0x2fcb687))
    def was_taken(site):
        row = decode(c.machine.read_code, site)
        return (site, row.target) in c.machine.edges
    if was_taken(branch_sites[0]):
        return 'no_repair'
    if was_taken(branch_sites[1]):
        return 'root_leaf'
    right = was_taken(branch_sites[2])
    borrow = was_taken(branch_sites[4 if right else 3])
    return ('right' if right else 'left') + ('_borrow' if borrow else '_merge')


def run_case(image, kind, shape, number, patches=None, pivot=19):
    c = TreeCase(image, kind, patches, pivot)
    c.build(shape)
    before, old_height = c.contents()
    expected = dict(before)
    repair = expected_first_repair(c, key_bytes(number, pivot))
    removed = expected.pop(key_bytes(number, pivot), None)
    actual = c.remove(number)
    observed = observed_first_repair(c, kind, actual is not None)
    if observed != repair:
        raise EvidenceError('repair branch disagrees with pre-removal model')
    c.first_repair = observed
    after, new_height = c.contents()
    want = sorted(expected.items())
    if actual != removed or after != want:
        raise EvidenceError('removed value or resulting rows differ from independent map model')
    return c, before, after, removed, old_height, new_height


def run_stake_probe(image, shape, number, pivot=19):
    c = TreeCase(image, 'stake', pivot=pivot)
    c.build(shape)
    before, _ = c.contents()
    c.mem.put_bytes(KEY_AT, key_bytes(number, pivot))
    c.mem.put_bytes(OUTPUT_AT, bytes([0xa5]) * 128)
    expected = dict(before).get(key_bytes(number, pivot))
    try:
        c.machine.run(STAKE_SEARCH, {RDI: OUTPUT_AT, RSI: MAP_AT, RDX: KEY_AT})
        if expected is not None or c.mem.read(OUTPUT_AT, 8) != 0:
            raise EvidenceError('stake miss disagrees with map model')
        result = 'miss'
    except BoundaryReached:
        if expected is None or c.cursor is None:
            raise EvidenceError('unexpected stake adapter call')
        node, depth, slot, owner = c.cursor
        if owner != MAP_AT or node not in c.live or depth > c.mem.read(MAP_AT + 8, 8):
            raise EvidenceError('invalid stake removal cursor')
        if slot >= c.mem.read(node + c.g['length'], 2):
            raise EvidenceError('stake cursor slot outside occupied entries')
        if c.mem.bytes_at(node + c.g['key'] + slot*20, 20) != key_bytes(number, pivot):
            raise EvidenceError('stake cursor points to wrong key')
        if c.mem.bytes_at(node + slot*16, 16) != expected:
            raise EvidenceError('stake cursor points to wrong value')
        result = 'boundary'
    after, _ = c.contents()
    if after != before:
        raise EvidenceError('stake search changed the map before adapter boundary')
    return c, result, len(before), hash_rows(before)


def run_sequence(image, kind, shape, order, pivot=19):
    c = TreeCase(image, kind, pivot=pivot)
    count = c.build(shape)
    before, height = c.contents()
    expected = dict(before)
    if sorted(order) != list(range(1, count + 1)):
        raise ValueError('sequence must be a permutation of fixture keys')
    root_shrinks = 0
    for i in order:
        key = key_bytes(2*i, pivot)
        value = expected.pop(key)
        got = c.remove(2*i)
        after, new_height = c.contents()
        if got != value or after != sorted(expected.items()):
            raise EvidenceError('sequence disagrees with map model')
        root_shrinks += new_height < height
        height = new_height
    if expected or c.contents()[0]:
        raise EvidenceError('sequence left rows behind')
    return c, before, root_shrinks




def slot_rows(image):
    expected = {SLOT_COMPARE: 'memcmp', SLOT_MOVE: 'memmove', SLOT_COPY: 'memcpy', SLOT_FREE: ''}
    relocs = {}
    for slot, kind, addend, symbol in image.relocations():
        if slot in expected:
            if slot in relocs:
                raise EvidenceError('duplicate hook relocation')
            relocs[slot] = (kind, addend, symbol)
    if set(relocs) != set(expected):
        raise EvidenceError('missing hook relocation')
    syms, strings = image.named['.dynsym'], image.named['.dynstr']
    if syms['type'] == 8 or strings['type'] == 8:
        raise EvidenceError('symbol table has no file bytes')
    rows = []
    for slot in sorted(expected):
        kind, addend, index = relocs[slot]
        if index * 24 + 24 > syms['size']:
            raise EvidenceError('dynamic symbol index out of bounds')
        name_index = struct.unpack_from('<I', image.blob, syms['offset'] + index*24)[0]
        if name_index >= strings['size']:
            raise EvidenceError('dynamic symbol name out of bounds')
        start = strings['offset'] + name_index
        end = image.blob.find(b'\0', start, strings['offset'] + strings['size'])
        if end < 0:
            raise EvidenceError('unterminated dynamic symbol name')
        name = bytes(image.blob[start:end]).decode('ascii')
        if name != expected[slot] or kind != (8 if slot == SLOT_FREE else 6):
            raise EvidenceError('hook relocation changed')
        rows.append(('0x%x' % slot, kind, index, name, '0x%x' % addend))
    return rows


def status_text(image):
    table_va, tag = 0x59a8d0, 0x12f
    delta = struct.unpack_from('<i', image.blob, image.offset(table_va + 4*tag, 4))[0]
    arm = table_va + delta
    at = image.offset(arm, 96)
    code = bytes(image.blob[at:at + 96])
    index = code.find(bytes.fromhex('488d35'))
    if index < 0 or code[index + 7] != 0xba:
        raise EvidenceError('unsupported status text arm')
    size = struct.unpack_from('<I', code, index + 8)[0]
    target = arm + index + 7 + struct.unpack_from('<i', code, index + 3)[0]
    start = image.offset(target, size)
    text = bytes(image.blob[start:start + size]).decode('ascii')
    if text != 'Cannot unregister validator with delegations':
        raise EvidenceError('unexpected status text')
    return tag, table_va + 4*tag, arm, target, size, text


def table(fields, rows):
    def cell(value):
        text = str(value)
        if any(x in text for x in ('\t', '\r', '\n')):
            raise EvidenceError('invalid TSV cell')
        return text
    return ('\t'.join(fields) + '\n' + ''.join('\t'.join(cell(v) for v in row) + '\n' for row in rows)).encode()


def json_data(value):
    return (json.dumps(value, indent=2, sort_keys=True) + '\n').encode()


def function_rows(image):
    rows, transfers, branch_targets = [], [], []
    for label, start in FUNCTIONS:
        _, end = image.exact_fde(start)
        text_section = image.named['.text']
        if text_section['type'] == 8 or not text_section['address'] <= start < end <= text_section['address'] + text_section['size']:
            raise EvidenceError('FDE range is not wholly in file-backed text')
        decoded = decode_range(image, start, end)
        instruction_starts = {r.va for r in decoded}
        for ins in decoded:
            if ins.op in ('jcc', 'jmp') and ins.target is not None and start <= ins.target < end and ins.target not in instruction_starts:
                raise EvidenceError('branch lands inside an instruction')
            if ins.op in ('jcc', 'jmp', 'call', 'calli', 'jmpi', 'ret'):
                transfers.append((label, '0x%x' % ins.va, ins.op,
                                  '0x%x' % ins.target if ins.target is not None else '', ins.data.hex()))
            if ins.op == 'jcc':
                branch_targets.append((label, ins.va, ins.next, ins.target, ins.data.hex()))
            rows.append((label, '0x%x' % ins.va, ins.data.hex(), ins.op,
                         '0x%x' % ins.target if ins.target is not None and ins.op in ('call', 'jmp', 'jcc') else ''))
    return rows, transfers, branch_targets



def borrow_failure(image, kind, direction, destination, source, count):
    c = TreeCase(image, kind)
    left, _ = c.node(list(range(2, 2*source+1, 2)))
    right, _ = c.node(list(range(102, 102+2*destination, 2)))
    desc = HEAP_BASE + 0x500
    if direction == 'left':
        src, dst = left, right
        helper = STATE_LEFT if kind == 'state' else PROFILE_LEFT
    elif direction == 'right':
        src, dst = right, left
        helper = STATE_RIGHT if kind == 'state' else PROFILE_RIGHT
        c.mem.write(src + c.g['length'], 2, source)
        c.mem.write(dst + c.g['length'], 2, destination)
    else:
        raise ValueError('unknown direction')
    c.mem.write(desc + 0x18, 8, left)
    c.mem.write(desc + 0x28, 8, right)
    try:
        c.machine.run(helper, {RDI: desc, RSI: count})
    except Panicked:
        pass
    else:
        raise EvidenceError('borrow guard did not reach failure boundary')
    after_dst = c.mem.read(dst + c.g['length'], 2)
    after_src = c.mem.read(src + c.g['length'], 2)
    if (after_dst, after_src) != (destination, source):
        raise EvidenceError('borrow guard changed counts before refusal')
    return c, after_dst, after_src


def merge_failure(image, left_count, right_count, side, cursor):
    c = TreeCase(image, 'state')
    left, _ = c.node(list(range(2, 2*left_count+1, 2)))
    right, _ = c.node(list(range(102, 102+2*right_count, 2)))
    desc = HEAP_BASE + 0x500
    c.mem.write(desc + 0x18, 8, left)
    c.mem.write(desc + 0x28, 8, right)
    try:
        c.machine.run(STATE_MERGE, {RDI: OUTPUT_AT, RSI: desc, RDX: side, RCX: cursor})
    except Panicked:
        pass
    else:
        raise EvidenceError('merge guard did not reach failure boundary')
    after = (c.mem.read(left + c.g['length'], 2), c.mem.read(right + c.g['length'], 2))
    if after != (left_count, right_count):
        raise EvidenceError('merge guard changed counts before refusal')
    return c, after


def failure_controls(image):
    rows = []
    for kind in ('state', 'profile'):
        for direction in ('left', 'right'):
            for name, dst, src, count in (('capacity', 11, 5, 1), ('source_underflow', 4, 5, 6)):
                c, got_dst, got_src = borrow_failure(image, kind, direction, dst, src, count)
                sites = {('state','left'): (0x2fa5d25, 0x2fa5d41),
                         ('state','right'): (0x2fad5f6, 0x2fad60b),
                         ('profile','left'): (0x2fa7235, 0x2fa7250),
                         ('profile','right'): (0x2fac606, 0x2fac61b)}
                site = sites[kind, direction][name == 'source_underflow']
                branch = decode(c.machine.read_code, site)
                if (site, branch.target) not in c.machine.edges:
                    raise EvidenceError('unexpected borrow failure branch')
                rows.append((kind, direction, name, dst, src, count, got_dst, got_src,
                             '0x%x' % site, '0x%x' % branch.target, 'panic'))
    for name, left, right, side, cursor in (('cursor', 5, 5, 0, 6), ('capacity', 6, 5, 0, 0)):
        c, after = merge_failure(image, left, right, side, cursor)
        site = 0x2fadf03 if name == 'cursor' else 0x2fadf1f
        branch = decode(c.machine.read_code, site)
        if (site, branch.target) not in c.machine.edges:
            raise EvidenceError('unexpected merge failure branch')
        rows.append(('state', 'merge', name, left, right, cursor, after[0], after[1],
                     '0x%x' % site, '0x%x' % branch.target, 'panic'))
    return rows


def mutation_controls(image):
    rows = []
    for name, kind, shape, number, address, replacement in MUTATIONS:
        run_case(image, kind, shape, number)  # Baseline must first agree.
        original = image.blob[image.offset(address)]
        if original == replacement:
            raise EvidenceError('mutation did not change a byte')
        try:
            run_case(image, kind, shape, number, {address: replacement})
        except (EvidenceError, Halt, Panicked) as exc:
            rows.append((name, '0x%x' % address, '%02x' % original,
                         '%02x' % replacement, type(exc).__name__))
        else:
            raise EvidenceError('mutation survived: ' + name)
    return rows


def generate(image):
    pins = verify_pins(image)
    status = status_text(image)
    slots = slot_rows(image)
    mutants = mutation_controls(image)
    failures = failure_controls(image)
    instructions, transfers, branches = function_rows(image)
    funcs = []
    for name, start in FUNCTIONS:
        _, end = image.exact_fde(start)
        data = image.blob[image.offset(start, end - start):][:end-start]
        funcs.append((name, '0x%x' % start, '0x%x' % end,
                      '0x%x' % image.fde_records[start]['fde'],
                      '0x%x' % image.offset(start, end-start), end-start,
                      hashlib.sha256(data).hexdigest()))
    cases, sequences, stake_probes, key_width = [], [], [], []
    seen, edges = set(), set()
    max_count = 0
    for name, shape in SHAPES:
        pivot = None if name == 'height3' else 19
        probe = TreeCase(image, 'stake', pivot=pivot)
        n = probe.build(shape)
        for number in list(range(2, 2*n + 1, 2)) + [1, 2*n + 1]:
            c, result, count, digest = run_stake_probe(image, shape, number, pivot)
            seen.update(c.machine.seen)
            edges.update(c.machine.edges)
            stake_probes.append((name, count, number, result, digest))
    for pivot in range(20):
        for number in (2, 12, 26, 11):
            c, result, count, digest = run_stake_probe(image, (5, 7), number, pivot)
            seen.update(c.machine.seen)
            edges.update(c.machine.edges)
            key_width.append(('stake', pivot, number, result, digest))
            for kind in ('state', 'profile'):
                c, before, after, result, _, _ = run_case(image, kind, (5, 7), number, pivot=pivot)
                seen.update(c.machine.seen)
                edges.update(c.machine.edges)
                key_width.append((kind, pivot, number, 'found' if result is not None else 'miss', hash_rows(after)))
    for kind in ('state', 'profile'):
        for name, shape in SHAPES:
            pivot = None if name == 'height3' else 19
            probe = TreeCase(image, kind, pivot=pivot)
            n = probe.build(shape)
            max_count = max(max_count, n)
            # Every occupied key and both outside bounds plus every gap in small trees.
            numbers = list(range(2, 2*n + 1, 2)) + [1, 2*n + 1]
            if n <= 23:
                numbers += list(range(3, 2*n, 2))
            for number in numbers:
                c, before, after, removed, old_height, new_height = run_case(image, kind, shape, number, pivot=pivot)
                seen.update(c.machine.seen)
                edges.update(c.machine.edges)
                cases.append((kind, name, n, number, int(removed is not None), old_height,
                              new_height, c.first_repair,
                              removed[24] if kind == 'state' and removed is not None else '-',
                              len(c.events), hash_rows(before), hash_rows(after),
                              hashlib.sha256(removed).hexdigest() if removed is not None else '-'))
        for shape_name, shape, pivot in (
                ('height2', ((5, 5, 5, 5, 5, 5), (5, 5, 5, 5, 5, 5)), 19),
                ('height3', DEEP_SHAPE, None)):
            probe = TreeCase(image, kind, pivot=pivot)
            n = probe.build(shape)
            alternating = []
            for i in range((n + 1) // 2):
                alternating.append(i + 1)
                if n - i != i + 1:
                    alternating.append(n - i)
            orders = (('ascending', list(range(1, n+1))),
                      ('descending', list(range(n, 0, -1))),
                      ('alternating', alternating))
            for name, order in orders:
                c, before, shrinks = run_sequence(image, kind, shape, order, pivot=pivot)
                seen.update(c.machine.seen)
                edges.update(c.machine.edges)
                sequences.append((kind, shape_name, name, len(order), shrinks, len(c.events), hash_rows(before), hash_rows([])))
    branch_rows = []
    for label, va, fall, taken, raw in branches:
        branch_rows.append((label, '0x%x' % va, raw, '0x%x' % fall, '0x%x' % taken,
                            int((va, fall) in edges), int((va, taken) in edges)))
    summary = {
        'artifact_sha256': SHA256, 'coordinate_system': 'ELF virtual address',
        'functions': len(funcs), 'body_bytes': sum(row[5] for row in funcs),
        'repair_counts': {kind: {name: sum(row[0] == kind and row[7] == name for row in cases)
                                 for name in ('miss', 'root_leaf', 'no_repair', 'left_merge',
                                              'right_merge', 'left_borrow', 'right_borrow')}
                          for kind in ('profile', 'state')},
        'instruction_rows': len(instructions),
        'transfer_rows': len(transfers), 'conditional_rows': len(branch_rows),
        'conditional_both_edges_seen': sum(bool(x[-1] and x[-2]) for x in branch_rows),
        'conditional_neither_edge_seen': sum(not x[-1] and not x[-2] for x in branch_rows),
        'reached_instruction_rows': sum(int(row[1],16) in seen for row in instructions),
        'single_removal_cases': len(cases), 'sequence_cases': len(sequences),
        'sequence_removals': sum(x[3] for x in sequences), 'largest_single_fixture': max_count,
        'stake_search_probes': len(stake_probes), 'key_position_cases': len(key_width),
        'model_mismatches': 0, 'mutation_controls_killed': len(mutants),
        'failure_boundary_cases': len(failures),
    }
    return {
        'summary.json': json_data(summary),
        'functions.tsv': table(('function','start_va','fde_end_va','fde_va','file_offset','body_bytes','sha256'), funcs),
        'instructions.tsv': table(('function','va','bytes','operation','relative_target'), instructions),
        'transfers.tsv': table(('function','va','operation','relative_target','bytes'), transfers),
        'context-pins.tsv': table(('name','va','bytes'), pins),
        'slots.tsv': table(('slot_va','relocation_type','symbol_index','symbol_name','addend'), slots),
        'status.tsv': table(('tag','table_entry_va','arm_va','text_va','length','text'),
                            [('0x%x' % status[0], '0x%x' % status[1], '0x%x' % status[2],
                              '0x%x' % status[3], status[4], status[5])]),
        'mutations.tsv': table(('case','edited_va','original','replacement','detected_as'), mutants),
        'failure-controls.tsv': table(('map','helper','case','destination_or_left','source_or_right','count_or_cursor','after_destination_or_left','after_source_or_right','branch_va','target_va','outcome'), failures),
        'branches.tsv': table(('function','va','bytes','fallthrough','taken','fall_seen','taken_seen'), branch_rows),
        'cases.tsv': table(('map','shape','count','key_number','found','height_before','height_after','first_repair','removed_blocked_byte','free_count','before_sha256','after_sha256','removed_sha256'), cases),
        'sequences.tsv': table(('map','shape','order','removals','height_drops','free_count','before_sha256','after_sha256'), sequences),
        'stake-probes.tsv': table(('shape','count','key_number','outcome','before_sha256'), stake_probes),
        'key-width.tsv': table(('map','varying_byte','key_number','outcome','content_sha256'), key_width),
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out', required=True, type=pathlib.Path)
    args = parser.parse_args()
    image = load_image()
    outputs = generate(image)
    args.out.mkdir(parents=True, exist_ok=True)
    for name, data in sorted(outputs.items()):
        (args.out / name).write_bytes(data)


if __name__ == '__main__':
    main()
