#!/usr/bin/env python3
"""Recover the validator fallback set clone and its alternate collector, node 94.

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

ROOT = pathlib.Path(__file__).absolute().parents[1]
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
        for row in fdes:
            if row["start"] in ends:
                raise EvidenceError("duplicate FDE start")
            ends[row["start"]] = row["end"]
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
            if not any(start <= pc < self.image.fde_ends[start] for start in self.real):
                raise Halt("execution left selected FDEs at %#x" % pc)
            self.last_pc = pc
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

# Only these FDEs are interpreted. Existing callers and sort functions are boundaries.
CLONE = 0x33e47a0
COLLECT = 0x3bb4d20
NEXT = 0x330f970
BUILD = 0x2fbf100
SMALL_SORT = 0x3386ec0
FUNCTIONS = {CLONE: 'set_clone', COLLECT: 'key_collector', NEXT: 'map_next', BUILD: 'set_bulk_build'}
SLOT_ALLOC = 0x576dfd8
SLOT_FREE = 0x576e010
SLOT_MOVE = 0x576e0e0
SLOT_COPY = 0x576dfe0
SLOT_CAPACITY = 0x576dfb8
SLOT_ALLOC_FAIL = 0x576e020
SLOT_ASSERT = 0x576e108
SLOT_PANIC = 0x576e470
SLOT_SORT = 0x5774f58
MARK = 0x7700000000
ARENA = HEAP_BASE + 0x10000
OUT = HEAP_BASE + 0x1000
ITER = HEAP_BASE + 0x2000


class Fixture:
    """Checked synthetic memory with actual selected instructions interpreted."""
    def __init__(self, image, patches=None, fail_at=None):
        self.m = Machine(image, patches)
        self.m.real = frozenset(FUNCTIONS)
        self.m.step_limit = 2000000
        self.m.calls = {SMALL_SORT: self.sort_small}
        self.alloc_next = ARENA
        self.allocations = {}
        self.events = []
        self.fail_at = fail_at
        self.attempts = 0
        slots = {SLOT_ALLOC: self.allocate_hook, SLOT_FREE: self.free,
                 SLOT_MOVE: self.move, SLOT_COPY: self.copy,
                 SLOT_CAPACITY: self.failure, SLOT_ALLOC_FAIL: self.failure,
                 SLOT_ASSERT: self.failure, SLOT_PANIC: self.failure,
                 SLOT_SORT: self.sort_large}
        for slot, hook in slots.items():
            self.m.memory.statics[slot] = MARK + slot
            self.m.slots[MARK + slot] = hook

    def read(self, addr, n=8):
        return self.m.memory.read(addr, n)

    def write(self, addr, value, n=8):
        self.m.memory.write(addr, n, value)

    def put(self, addr, raw):
        self.m.memory.put_bytes(addr, raw)

    def data(self, addr, n):
        return self.m.memory.bytes_at(addr, n)

    def allocate(self, size):
        if size < 1 or self.alloc_next + size > HEAP_BASE + HEAP_SIZE:
            raise Halt('fixture allocation outside arena')
        result = self.alloc_next
        self.alloc_next += (size + 15) & ~15
        self.allocations[result] = size
        self.put(result, bytes([0xa5]) * size)
        return result

    def allocate_hook(self, m):
        size = m.regs[RDI]
        self.attempts += 1
        self.events.append(('alloc', size))
        m.regs[RAX] = 0 if self.fail_at == self.attempts else self.allocate(size)

    def free(self, m):
        ptr, size = m.regs[RDI], m.regs[RSI]
        if size and self.allocations.get(ptr) != size:
            raise Halt('invalid free')
        if size:
            del self.allocations[ptr]
        self.events.append(('free', size))

    def failure(self, m):
        self.events.append(('failure', m.regs[RDI], m.regs[RSI]))
        raise Panicked('recorded external failure boundary')

    def move(self, m):
        dst, src, n = (m.regs[x] for x in (RDI, RSI, RDX))
        if n > HEAP_SIZE:
            raise Halt('oversized move')
        self.put(dst, self.data(src, n))
        m.regs[RAX] = dst

    def copy(self, m):
        dst, src, n = (m.regs[x] for x in (RDI, RSI, RDX))
        if n and max(dst, src) < min(dst + n, src + n):
            raise Halt('overlapping memcpy')
        self.move(m)

    def sort_small(self, m):
        self.sort(m, False)

    def sort_large(self, m):
        self.sort(m, True)

    def sort(self, m, large):
        ptr, count = m.regs[RDI], m.regs[RSI]
        if count < 2 or count > 1024 or large != (count >= 21):
            raise Halt('sort fixture outside bounds')
        rows = [self.data(ptr + 20*i, 20) for i in range(count)]
        self.put(ptr, b''.join(sorted(rows)))
        self.events.append(('sort_large' if large else 'sort_small', count))

    def source_tree(self, shape, kind):
        """Build one input tree in in-order, with uninitialised padding poisoned."""
        counter = [0]
        wanted = shape_expectation(shape, self.leaf_count)[1]
        fixture_keys = getattr(self, 'fixture_keys', None)
        if fixture_keys is None:
            fixture_keys = key_sequence(wanted)
        if len(fixture_keys) != wanted or fixture_keys != sorted(set(fixture_keys)) or any(len(k) != 20 for k in fixture_keys):
            raise ValueError('fixture keys do not match the tree')
        nodes = []
        def visit(spec, parent=0, edge=0):
            children = spec
            internal = children is not None
            count = len(children) - 1 if internal else self.leaf_count.pop(0)
            size = (0x148 if internal else 0xe8) if kind == 'set' else (0x1a0 if internal else 0x140)
            p = self.allocate(size)
            nodes.append(p)
            parent_offset = 0
            slot_offset = 0xe4 if kind == 'set' else 0x13c
            count_offset = 0xe6 if kind == 'set' else 0x13e
            edge_offset = 0xe8 if kind == 'set' else 0x140
            key_offset = 8 if kind == 'set' else 0x60
            self.write(p + parent_offset, parent)
            self.write(p + slot_offset, edge, 2)
            self.write(p + count_offset, count, 2)
            for i in range(count + 1):
                if internal:
                    child = visit(children[i], p, i)
                    self.write(p + edge_offset + 8*i, child)
                if i < count:
                    counter[0] += 1
                    key = fixture_keys[counter[0]-1]
                    self.put(p + key_offset + 20*i, key)
                    if kind == 'map':
                        self.write(p + 8 + i*8, counter[0] * 13)
            return p
        root = visit(shape)
        if self.leaf_count:
            raise Halt('unused fixture leaf lengths')
        return root, counter[0], nodes

    def tree(self, root, height, count, reject_nodes=(), preserve_shape=False):
        seen = set()
        shapes = []
        def walk(p, depth, parent, edge):
            if p in seen or p in reject_nodes or p not in self.allocations:
                raise Halt('set points outside fresh allocation or is aliased')
            seen.add(p)
            n = self.read(p + 0xe6, 2)
            size = self.allocations[p]
            if n > 11 or (parent and n < 5) or size != (0x148 if depth else 0xe8):
                raise Halt('bad set node size or occupancy')
            if self.read(p) != parent or (parent and self.read(p + 0xe4, 2) != edge):
                raise Halt('bad set parent link')
            keys = []
            for i in range(n):
                if depth:
                    keys.extend(walk(self.read(p + 0xe8 + i*8), depth-1, p, i))
                keys.append(self.data(p + 8 + 20*i, 20))
            if depth:
                keys.extend(walk(self.read(p + 0xe8 + n*8), depth-1, p, n))
            shapes.append((depth,n))
            return keys
        if root:
            keys = walk(root, height, 0, 0)
        else:
            keys = []
        if len(keys) != count or keys != sorted(set(keys)):
            raise Halt('bad set ordering or count')
        return keys, shapes

    def clone(self, shape, leaf_counts, height, keys=None):
        self.fixture_keys = keys
        self.leaf_count = list(leaf_counts)
        root, count, original = self.source_tree(shape, 'set')
        source = [(p, self.data(p,self.allocations[p])) for p in original]
        # Distinguish a target allocation attempt from fixture setup.
        self.events.clear()
        self.m.run(CLONE, {RDI: OUT, RSI: root, RDX: height})
        result, h, n = (self.read(OUT + off) for off in (0,8,16))
        keys, shapes = self.tree(result,h,n, original)
        if any(self.data(p,len(raw)) != raw for p,raw in source):
            raise Halt('source tree was changed')
        return keys, h, n, shapes, count

    def collect(self, shape, leaf_counts, height, force_empty=False):
        self.leaf_count = list(leaf_counts)
        root, count, original = self.source_tree(shape, 'map')
        source = [(p, self.data(p,self.allocations[p])) for p in original]
        self.put(ITER, bytes(0x48))
        self.write(ITER, 1)
        self.write(ITER+0x10, root)
        self.write(ITER+0x18, height)
        self.write(ITER+0x40, 0 if force_empty else count)
        before_iter = self.data(ITER, 0x48)
        self.events.clear()
        self.m.run(COLLECT, {RDI: OUT, RSI: ITER})
        if self.data(ITER,0x48) != before_iter or any(self.data(p,len(raw)) != raw for p,raw in source):
            raise Halt('collector changed its input')
        result = self.read(OUT)
        result_count = self.read(OUT+16)
        result_height = self.read(OUT+8) if result else 0
        keys, shapes = self.tree(result,result_height,result_count,original)
        return keys, result_height, result_count, shapes, 0 if force_empty else count

    def bulk(self, numbers):
        if numbers != sorted(numbers) or any(not 0 <= x < 1 << 160 for x in numbers):
            raise ValueError('bulk fixture requires sorted 160-bit keys')
        ptr = self.allocate(max(20*len(numbers),1))
        self.put(ptr, b''.join(x.to_bytes(20, 'big') for x in numbers))
        root = self.allocate(0xe8)
        self.write(root,0)
        self.write(root+0xe6,0,2)
        self.write(OUT,root)
        self.write(OUT+8,0)
        count_ptr = OUT+0x30
        self.write(count_ptr,0)
        self.put(ITER,bytes(0x38))
        self.write(ITER,ptr)
        self.write(ITER+8,ptr)
        self.write(ITER+16,len(numbers))
        self.write(ITER+24,ptr+20*len(numbers))
        self.write(ITER+32,2,1)
        self.events.clear()
        self.m.run(BUILD,{RDI:OUT,RSI:ITER,RDX:count_ptr})
        root,height,count = self.read(OUT),self.read(OUT+8),self.read(count_ptr)
        keys,shapes = self.tree(root,height,count)
        return keys,height,count,shapes


BODY_HASH = {
 CLONE: 'e39a3f178781fc6a52373df6215dee1609c2ba16833a6d75d53d4cedaecf36f9',
 COLLECT: '0b0d69aad40874a1924968972f0007358a88d8bb55324dc97127566bbdcac5d1',
 NEXT: 'aec15b9b219343b37025d6dc8e55464dc90384fcf26896d2ae23890a1f5ba371',
 BUILD: '55ac215aa2a2373ba757e2aee2cc555b7c45e185de732ccf6140e31864eca489',
}
PINS = {
 0x3c11d6e: ('live_flag', '807c2407000f85fa020000'),
 0x3c11d79: ('foundation_length', '49837c2410007438'),
 0x3c11d81: ('nonnull_foundation_root', '498b34244885f60f8430030000'),
 0x3c11d8e: ('clone_call_setup', '498b542408488d7c2458e8032a7dff'),
 0x3c11e1a: ('alternate_call_setup', '488dbc24a0000000488d742458e8f42efaff'),
 0x3bb4c00: ('vote_union_build_call', 'e8fba440ff'),
 0x3c11ead: ('fallback_next_or_end', '488b4424204885c00f8497010000'),
 0x3c11ff7: ('fallback_entry_and_saturating_increment', 'e874a97aff488b0848ffc148c7c2ffffffff480f44ca488908'),
 0x3c12073: ('fallback_return', '488b442418488b8c24b8000000488941100f104424080f1101'),
 0x2fbf67d: ('rightmost_minimum', '4883f90573cd'),
 0x33e4a0f: ('clone_leaf_capacity', '0fb7b0e60000004883fe0b0f838c000000'),
 0x3bb4d32: ('collector_bytes', 'b9140000004889d848f7e10f90c14885c00f98c208ca740b'),
 0x3bb4eab: ('collector_sort_threshold', '4983fc15733a488d4c2420ba010000004c89ff4c89e6e8fa1f7dff'),
 0x2fbf30f: ('builder_equal_key_test', '81ffffff00000f858c000000'),
}
SLOT_EXPECTED = {
 SLOT_ALLOC:(8,0,0x54c06b0), SLOT_FREE:(8,0,0x54c8cb0),
 SLOT_MOVE:(6,9,0), SLOT_COPY:(6,6,0), SLOT_CAPACITY:(8,0,0x1346068),
 SLOT_ALLOC_FAIL:(8,0,0x1345e2a), SLOT_ASSERT:(8,0,0x157b7f0),
 SLOT_PANIC:(8,0,0x157a9f0), SLOT_SORT:(8,0,0x3bc1e80),
}


def checked_capacity(count):
    if count < 0 or count >= 1 << 64:
        raise ValueError('count outside u64')
    size = count * 20
    if size >= 1 << 63:
        raise ValueError('collector rejects vector byte count')
    return size


def verify_static(image):
    all_fdes = eh_frame_records(image.blob,image.sections)[1]
    index = {f['start']:f for f in all_fdes}
    if len(index) != len(all_fdes):
        raise EvidenceError('duplicate FDE start')
    funcs=[]
    decoded={}
    for addr in sorted(FUNCTIONS):
        start,end=image.exact_fde(addr)
        off=image.offset(start,end-start)
        digest=hashlib.sha256(image.blob[off:off+end-start]).hexdigest()
        if digest != BODY_HASH[addr]:
            raise EvidenceError('selected FDE body hash mismatch')
        rows=decode_range(image,start,end)
        decoded[addr]=rows
        f=index[start]
        funcs.append((FUNCTIONS[addr],hex(start),hex(end),hex(off),hex(f['fde']),hex(f['cie']),
                      '' if f['lsda'] is None else hex(f['lsda']),end-start,len(rows),digest))
    pins=[]
    for va,(name,expected) in sorted(PINS.items()):
        raw=bytes.fromhex(expected)
        off=image.offset(va,len(raw))
        if image.blob[off:off+len(raw)] != raw:
            raise EvidenceError('pin mismatch at %#x' % va)
        pins.append((name,hex(va),hex(off),raw.hex()))
    byslot={slot:[] for slot in SLOT_EXPECTED}
    for slot,kind,addend,sym in image.relocations():
        if slot in byslot:
            byslot[slot].append((kind,sym,addend))
    rels=[]
    for slot in sorted(byslot):
        if len(byslot[slot]) != 1 or byslot[slot][0] != SLOT_EXPECTED[slot]:
            raise EvidenceError('missing, changed or ambiguous slot relocation')
        kind,sym,addend=byslot[slot][0]
        rels.append((hex(slot),kind,sym,hex(addend)))
    return funcs,pins,rels,decoded


def shape_cases():
    cases=[('leaf_%02d'%n,None,[n],0) for n in range(12)]
    for n in range(1,12):
        cases.append(('one_level_%02d'%n,[None]*(n+1),[5+(i%7) for i in range(n+1)],1))
    cases.extend([
        ('two_level_sparse',[[None]*6,[None]*6],[5]*12,2),
        ('two_level_mixed',[[None]*6,[None]*7,[None]*8],
         [5+(i%7) for i in range(21)],2),
        ('two_level_full',[[None]*12,[None]*12],[11]*24,2),
    ])
    return cases


def shape_expectation(shape, counts):
    counts=iter(counts)
    def walk(s,depth):
        if s is None:
            n=next(counts)
            return [(depth,n)],n
        result=[]
        total=len(s)-1
        for c in s:
            shapes,num=walk(c,depth-1)
            result+=shapes
            total+=num
        result.append((depth,len(s)-1))
        return result,total
    def height(s):
        return 0 if s is None else 1+height(s[0])
    result=walk(shape,height(shape))
    try:
        next(counts)
        raise ValueError('too many leaf counts')
    except StopIteration:
        return result


def foundation_inputs(image):
    # Cell ownership and the chain labels are inferences from the earlier staking packet.
    offsets = {1: [0x58ef77+20*i for i in range(4)],
               2: [0x58efc7+20*i for i in range(4)],
               3: [0x58ef27+20*i for i in range(4)] + [0x58f02b]}
    rows=[]
    for chain in sorted(offsets):
        for va in offsets[chain]:
            off = image.offset(va,20)
            rows.append((chain,hex(va),hex(off),image.blob[off:off+20].hex()))
    return rows


def key_sequence(n):
    return sorted(hashlib.sha256(('validator-%d' % i).encode('ascii')).digest()[:20] for i in range(n))


def run_scenarios(image):
    output=[]
    seen=set()
    edges=set()
    for name,shape,leaves,height in shape_cases():
        for mode in ('clone','collect'):
            fix=Fixture(image)
            keys,h,n,shapes,source_count=getattr(fix,mode)(shape,leaves,height)
            want_shape,want_count=shape_expectation(shape,leaves)
            if n != want_count or source_count != want_count or keys != key_sequence(want_count):
                raise EvidenceError('scenario mismatch: '+name+' '+mode)
            if mode == 'clone' and (h != height or shapes != want_shape):
                raise EvidenceError('clone did not preserve input shape')
            sorts=[v for v in fix.events if v[0].startswith('sort_')]
            expected_sort = 'sort_large' if want_count >= 21 else 'sort_small'
            if mode == 'collect' and sorts != ([(expected_sort,want_count)] if want_count>=2 else []):
                raise EvidenceError('unexpected sort boundary')
            output.append((mode,name,want_count,height,h,len(shapes),fix.m.steps,
                           hashlib.sha256(b''.join(keys)).hexdigest(),
                           ','.join('%s:%s'%(x[0],x[1]) for x in fix.events if x[0] in ('alloc','free','sort_small','sort_large'))))
            seen.update(fix.m.seen);edges.update(fix.m.edges)
    inputs=foundation_inputs(image)
    for chain in (1,2,3):
        expected=sorted(bytes.fromhex(r[3]) for r in inputs if r[0] == chain)
        fix=Fixture(image)
        keys,h,n,shapes,source_count=fix.clone(None,[len(expected)],0,keys=expected)
        if keys != expected or n != len(expected) or source_count != n or h != 0:
            raise EvidenceError('target-key fixture mismatch')
        output.append(('clone','foundation_chain_%d'%chain,n,0,h,len(shapes),fix.m.steps,
                       hashlib.sha256(b''.join(keys)).hexdigest(),
                       ','.join('%s:%s'%(x[0],x[1]) for x in fix.events if x[0] in ('alloc','free'))))
        seen.update(fix.m.seen); edges.update(fix.m.edges)
    for n in [0,1,2,5,10,11,12,16,20,21,22,23,24,31,35,64,100,143,144,200,260,2000]:
        for style in ('unique','triples','scattered'):
            if style == 'unique':
                seq = list(range(n))
            elif style == 'triples':
                seq = [i//3 for i in range(n)]
            else:
                seq = sorted(int.from_bytes(key,'big') for key in key_sequence(n))
            fix=Fixture(image)
            keys,h,k,shapes=fix.bulk(seq)
            expected=[i.to_bytes(20,'big') for i in sorted(set(seq))]
            if keys != expected:
                raise EvidenceError('bulk result mismatch')
            output.append(('bulk',style+'_%03d'%n,n,0,h,len(shapes),fix.m.steps,
                           hashlib.sha256(b''.join(keys)).hexdigest(),
                           ','.join('%s:%s'%(x[0],x[1]) for x in fix.events if x[0] in ('alloc','free','sort_small','sort_large'))))
            seen.update(fix.m.seen);edges.update(fix.m.edges)
    # Deterministic size and duplicate patterns are independent of the target's builder.
    for index in range(100):
        n = (7*index*index + 13*index + 5) % 301
        width = index % 7 + 1
        distinct = sorted(int.from_bytes(k,'big') for k in key_sequence((n+width-1)//width))
        seq = sorted(distinct[i//width] for i in range(n))
        fix = Fixture(image)
        keys,h,k,shapes = fix.bulk(seq)
        expected = [i.to_bytes(20,'big') for i in sorted(set(seq))]
        if keys != expected:
            raise EvidenceError('generated duplicate result mismatch')
        output.append(('bulk','generated_%03d'%index,n,0,h,len(shapes),fix.m.steps,
                       hashlib.sha256(b''.join(keys)).hexdigest(),
                       ','.join('%s:%s'%(x[0],x[1]) for x in fix.events if x[0] in ('alloc','free'))))
        seen.update(fix.m.seen); edges.update(fix.m.edges)
    return output,seen,edges


def run_controls(image):
    rows=[]
    observed=[]
    # Fail each allocation in a valid 2-level clone, and separately in collector.
    clone_shape=[[None]*6,[None]*6]
    for mode, shape, leaves, height, failures in (
        ('clone',clone_shape,[5]*12,2,15),
        ('collect',[None,None,None],[11,11,11],1,5),
    ):
        for fail in range(1,failures+1):
            fix=Fixture(image,fail_at=fail)
            try:
                getattr(fix,mode)(shape,leaves,height)
            except Panicked:
                rows.append(('allocation',mode,fail,hex(fix.m.last_pc),'failure_boundary'))
            else:
                raise EvidenceError('allocation control failed to reach failure boundary')
            observed.append(fix)
    max_accepted=((1<<63)-1)//20
    for label,count in [('last_accepted',max_accepted),('first_rejected',max_accepted+1),('u64_max',(1<<64)-1)]:
        fix=Fixture(image,fail_at=1)
        fix.put(ITER,bytes(0x48));fix.write(ITER+0x40,count)
        try:
            fix.m.run(COLLECT,{RDI:OUT,RSI:ITER})
        except Panicked:
            site=fix.m.last_pc
            expected=0x3bb4ee5 if label == 'last_accepted' else 0x3bb4d4f
            if site != expected:
                raise EvidenceError('wrong capacity control site')
            rows.append(('capacity',label,count,hex(site),'failure_boundary'))
        else:
            raise EvidenceError('capacity control returned')
        observed.append(fix)
    mutations = [
        ('clone_key_tail',CLONE,0x33e4a38,0x0f,lambda f:f.clone(None,[11],0)),
        ('clone_capacity',CLONE,0x33e4a19,0x0a,lambda f:f.clone(None,[11],0)),
        ('collector_stride',COLLECT,0x3bb4de0,0x13,lambda f:f.collect(None,[9],0)),
        ('bulk_duplicate',BUILD,0x2fbf311,0xfe,lambda f:f.bulk([1,1,2,2,3])),
        ('iterator_count',NEXT,0x330f980,0xc0,lambda f:f.collect(None,[5],0)),
    ]
    for name,function,at,new,call in mutations:
        fix=Fixture(image,patches={at:new})
        fix.m.step_limit=100000
        try:
            result=call(fix)
            expected=sorted(set([1,1,2,2,3])) if name=='bulk_duplicate' else None
            if name=='clone_key_tail':
                valid=result[0]==key_sequence(11)
            elif name=='collector_stride':
                valid=result[0]==key_sequence(9)
            elif name=='iterator_count':
                valid=result[0]==key_sequence(5)
            elif expected is not None:
                valid=result[0]==[x.to_bytes(20,'big') for x in expected]
            else:
                valid=True
            if valid:
                raise EvidenceError('mutation survived '+name)
            outcome='wrong_result'
        except (Halt,Panicked) as exc:
            outcome='rejected_'+type(exc).__name__
        rows.append(('mutation',name,hex(at),hex(fix.m.last_pc),outcome))
        observed.append(fix)
    return rows, observed


def write_table(out,name,head,rows):
    text='\t'.join(head)+'\n'
    for row in rows:
        text+='\t'.join(str(value) for value in row)+'\n'
    (out/name).write_text(text,encoding='utf-8',newline='\n')


def generate(out):
    image=load_image()
    funcs,pins,rels,decoded=verify_static(image)
    scenarios,seen,edges=run_scenarios(image)
    controls,fixtures=run_controls(image)
    # Patched executions are controls, not reachability evidence for the target.
    for row, f in zip(controls, fixtures):
        if row[0] != 'mutation':
            seen.update(f.m.seen)
            edges.update(f.m.edges)
    instruction_rows=[]
    transfers=[]
    summary={}
    for addr in sorted(FUNCTIONS):
        rows=decoded[addr]
        cond=both=reached=0
        for r in rows:
            hit=int(r.va in seen)
            reached+=hit
            instruction_rows.append((FUNCTIONS[addr],hex(r.va),r.data.hex(),r.op,
                                     '' if r.op not in ('jcc','jmp','call') or r.target is None else hex(r.target),hit))
            if r.op in ('jcc','jmp','call'):
                taken=int((r.va,r.target) in edges) if r.op=='jcc' else ''
                fall=int((r.va,r.next) in edges) if r.op=='jcc' else ''
                if r.op=='jcc':
                    cond+=1;both+=taken and fall
                transfers.append((FUNCTIONS[addr],hex(r.va),r.op,
                                  '' if r.target is None else hex(r.target),
                                  hex(r.next),taken,fall))
        summary[FUNCTIONS[addr]]={'fde_start':hex(addr),'fde_end':hex(image.fde_ends[addr]),
           'decoded_rows':len(rows),'reached_rows':reached,'conditional_sites':cond,
           'both_conditional_edges':both}
    out=pathlib.Path(out)
    out.mkdir(parents=True,exist_ok=True)
    write_table(out,'functions.tsv',('function','start_va','end_va','file_offset','fde_va','cie_va','lsda_va','size','decoded_rows','sha256'),funcs)
    write_table(out,'anchors.tsv',('role','virtual_address','file_offset','bytes'),pins)
    write_table(out,'foundation-inputs.tsv',('chain_label','virtual_address','file_offset','key_bytes'),foundation_inputs(image))
    write_table(out,'relocations.tsv',('slot_va','type','symbol_index','addend'),rels)
    write_table(out,'instructions.tsv',('function','va','bytes','operation','direct_target','reached'),instruction_rows)
    write_table(out,'transfers.tsv',('function','va','operation','target','fallthrough','taken_seen','fallthrough_seen'),transfers)
    write_table(out,'scenarios.tsv',('mode','case','input_count','input_height','output_height','output_nodes','steps','key_sha256','events'),scenarios)
    write_table(out,'controls.tsv',('kind','case','argument','site_va','outcome'),controls)
    document={'target_sha256':SHA256,'functions':summary,'scenario_count':len(scenarios),
              'control_count':len(controls),'scenario_mismatches':0,
              'method':'bounded instruction interpretation; sort, memory and failure boundaries are modeled',
              'coordinates':'ELF virtual addresses and file offsets; FDE ends are exclusive'}
    (out/'summary.json').write_text(json.dumps(document,indent=2,sort_keys=True)+'\n',encoding='utf-8')
    return document


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out',required=True,type=pathlib.Path)
    args=parser.parse_args()
    generate(args.out)


if __name__=='__main__':
    main()
