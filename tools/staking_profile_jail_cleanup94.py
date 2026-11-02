#!/usr/bin/env python3
"""Recover validator signer projection and jailed signer reconciliation, node 94.

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



# Workspace for the four path functions. Calls outside this set are hooked.
PROFILE_WRITE = 0x33A4600
PROFILE_INSERT = 0x2F65A00
ROOT_PROJECTION = 0x39966B0
COLLECT_SIGNERS = 0x3BB27C0
WALK_PROFILES = 0x3BE3FD0
JAILED_DIFFERENCE = 0x3BABFB0
SMALL_SORT = 0x3386EC0
BULK_BUILD = 0x2FBA3B0
REBALANCE = 0x2FA5270
SET_NEXT = 0x330F150
GROW = 0x32D6A00
SLOT_ALLOC = 0x576DFD8
SLOT_CAPACITY_ERROR = 0x576DFB8
SLOT_ALLOCATION_ERROR = 0x576E020
SLOT_FREE = 0x576E010
SLOT_COMPARE = 0x576E488
SLOT_COPY = 0x576E0E0
SLOT_MEMCPY = 0x576DFE0
SLOT_LARGE_SORT = 0x5776298
MARK_BASE = 0x7700000000
STATE = HEAP_BASE + 0x100
OUTPUT = HEAP_BASE + 0x1000
ITERATOR = HEAP_BASE + 0x2000
PROFILE_NODE = HEAP_BASE + 0x4000
JAILED_NODE = HEAP_BASE + 0x5000
ARENA = HEAP_BASE + 0x10000


class Fixture:
    """Leaf fixtures; boundary calls are checked and explicitly simulated."""
    def __init__(self, image, patches=None):
        self.m = Machine(image, patches)
        self.m.step_limit = 3000000
        self.m.real = {ROOT_PROJECTION, COLLECT_SIGNERS, WALK_PROFILES, JAILED_DIFFERENCE, SMALL_SORT, BULK_BUILD, REBALANCE, PROFILE_WRITE, PROFILE_INSERT}
        self.alloc_next = ARENA
        self.allocations = {}
        self.boundary = []
        self.fail_allocation_number = None
        self.allocation_calls = 0
        self.m.calls = {SET_NEXT: self.next_key, GROW: self.grow}
        for slot, hook in ((SLOT_ALLOC, self.alloc_hook), (SLOT_FREE, self.free),
                           (SLOT_COMPARE, self.compare), (SLOT_COPY, self.copy_bytes), (SLOT_MEMCPY, self.copy_bytes),
                           (SLOT_LARGE_SORT, self.sort), (SLOT_CAPACITY_ERROR, self.failure),
                           (SLOT_ALLOCATION_ERROR, self.failure)):
            self.m.memory.statics[slot] = MARK_BASE + slot
            self.m.slots[MARK_BASE + slot] = hook

    def read(self, addr, n=8):
        return self.m.memory.read(addr, n)

    def write(self, addr, value, n=8):
        self.m.memory.write(addr, n, value)

    def put(self, addr, data):
        self.m.memory.put_bytes(addr, data)

    def data(self, addr, n):
        return self.m.memory.bytes_at(addr, n)

    def alloc(self, size):
        at = self.alloc_next
        self.alloc_next += (size + 15) & ~15
        if self.alloc_next > HEAP_BASE + HEAP_SIZE:
            raise Halt('fixture arena exhausted')
        self.allocations[at] = size
        return at

    def alloc_hook(self, m):
        size = m.regs[RDI]
        self.allocation_calls += 1
        self.boundary.append(('allocate', size))
        m.regs[RAX] = 0 if self.fail_allocation_number == self.allocation_calls else self.alloc(size)

    def failure(self, m):
        self.boundary.append(('failure', m.regs[RSI]))
        raise Panicked('target reached the hooked failure boundary')

    def free(self, m):
        at, size = m.regs[RDI], m.regs[RSI]
        if self.allocations.get(at) != size:
            raise Halt('invalid free')
        self.boundary.append(('free', size))
        del self.allocations[at]

    def compare(self, m):
        size = m.regs[RDX]
        a, b = self.data(m.regs[RDI], size), self.data(m.regs[RSI], size)
        m.regs[RAX] = 0 if a == b else 1 if a > b else MASK[4]

    def copy_bytes(self, m):
        dest, src, size = m.regs[RDI], m.regs[RSI], m.regs[RDX]
        self.put(dest, self.data(src, size))
        m.regs[RAX] = dest

    def sort(self, m):
        at, n = m.regs[RDI], m.regs[RSI]
        if n < 2 or n > 24:
            raise Halt('outside fixture sort bound')
        rows = [self.data(at + 20 * i, 20) for i in range(n)]
        self.boundary.append(('sort', n))
        self.put(at, b''.join(sorted(rows)))

    def grow(self, m):
        vec, length, extra, align, width = (m.regs[r] for r in (RDI, RSI, RDX, RCX, R8))
        if width != 20 or align != 1 or extra != 1 or length != self.read(vec):
            raise Halt('unexpected vector growth')
        old, cap = self.read(vec + 8), self.read(vec)
        newcap = max(cap * 2, length + extra, 4)
        new = self.alloc(newcap * 20)
        self.put(new, self.data(old, length * 20))
        if self.allocations.get(old) != cap * 20:
            raise Halt('vector growth ownership mismatch')
        del self.allocations[old]
        self.write(vec, newcap)
        self.write(vec + 8, new)
        self.boundary.append(('grow', newcap))

    def next_key(self, m):
        # Checked model of the external set iterator on the fixture layouts.
        it = m.regs[RDI]
        if it != ITERATOR:
            raise Halt('unexpected set iterator')
        count = self.read(it + 0x40)
        if not count:
            m.regs[RAX] = 0
            return
        current = self.read(it + 8)
        depth = self.read(it + 0x10)
        index = self.read(it + 0x18)
        if not current:
            current = depth
            depth = index
            while depth:
                current = self.read(current + 0xE8)
                depth -= 1
            index = 0
        while index >= self.read(current + 0xE6, 2):
            parent = self.read(current)
            if not parent:
                raise Halt('iterator exhausted before stored count')
            index = self.read(current + 0xE4, 2)
            current = parent
            depth += 1
        result = current + 8 + 20 * index
        if depth:
            current = self.read(current + 0xE8 + 8 * (index + 1))
            depth -= 1
            while depth:
                current = self.read(current + 0xE8)
                depth -= 1
            index = 0
        else:
            index += 1
        self.write(it, 1)
        self.write(it + 8, current)
        self.write(it + 0x10, depth)
        self.write(it + 0x18, index)
        self.write(it + 0x40, count - 1)
        m.regs[RAX] = result

    def profiles(self, pairs):
        # One or two levels, preserving the on-target ordered map layout.
        if len(pairs) > 23 or len({k for k, _ in pairs}) != len(pairs):
            raise ValueError('profile fixture requires distinct keys and at most 23 rows')
        self.put(STATE, bytes(0x298))
        pairs = sorted(pairs)
        if any(len(k) != 20 or len(v) != 20 for k, v in pairs):
            raise ValueError('addresses must be 20 bytes')

        def node(rows, parent=0, edge=0, internal=False):
            size = 0x510 if internal else 0x4B0
            at = self.alloc(size)
            self.put(at, bytes(size))
            self.write(at, parent)
            self.write(at + 0x4AC, edge, 2)
            self.write(at + 0x4AE, len(rows), 2)
            for i, (key, signer) in enumerate(rows):
                self.put(at + 0x3D0 + 20*i, key)
                self.put(at + 0x58*i + 0x40, signer)
            return at

        if not pairs:
            root, height = 0, 0
        elif len(pairs) <= 11:
            root, height = node(pairs), 0
        else:
            mid = len(pairs) // 2
            root = node(pairs[mid:mid+1], internal=True)
            left = node(pairs[:mid], root, 0)
            right = node(pairs[mid+1:], root, 1)
            self.write(root + 0x4B0, left)
            self.write(root + 0x4B8, right)
            height = 1
        self.write(STATE + 0x150, root)
        self.write(STATE + 0x158, height)
        self.write(STATE + 0x160, len(pairs))

    def write_profile(self, key, signer):
        if len(key) != 20 or len(signer) != 20:
            raise ValueError('addresses must be 20 bytes')
        key_at = HEAP_BASE + 0x7000
        record_at = HEAP_BASE + 0x7100
        returned = HEAP_BASE + 0x7200
        self.put(key_at, key)
        self.put(record_at, bytes(0x58))
        self.put(record_at + 0x38, signer)
        self.put(returned, bytes(0x58))
        self.m.run(PROFILE_WRITE, {RDI: returned, RSI: STATE + 0x150,
                                   RDX: key_at, RCX: record_at})
        if self.read(returned) == 1 << 63:
            return None
        return self.data(returned + 0x38, 20)

    def projected(self):
        self.m.run(ROOT_PROJECTION, {RDI: OUTPUT, RSI: STATE})
        root, height, count = self.read(OUTPUT), self.read(OUTPUT + 8), self.read(OUTPUT + 16)
        def walk(node, height):
            if not node:
                raise Halt('null node in nonempty tree')
            n = self.read(node + 0xE6, 2)
            if n > 11:
                raise Halt('invalid set node length')
            result = []
            for i in range(n):
                if height:
                    result.extend(walk(self.read(node + 0xE8 + 8*i), height-1))
                result.append(self.data(node + 8 + 20*i, 20))
            if height:
                result.extend(walk(self.read(node + 0xE8 + 8*n), height-1))
            return result
        result = walk(root, height) if root else []
        if len(result) != count or result != sorted(set(result)):
            raise Halt('invalid projected tree')
        return result

    def difference(self, jailed, active_node, active_count, active_height=0):
        jailed = sorted(jailed)
        if len(set(jailed)) != len(jailed) or len(jailed) > 23:
            raise ValueError('jail fixture requires distinct addresses and at most 23 rows')
        if any(len(key) != 20 for key in jailed):
            raise ValueError('addresses must be 20 bytes')
        self.jail_nodes = []
        def node(keys, parent=0, edge=0, internal=False, fixed=None):
            size = 0x148 if internal else 0xE8
            at = fixed if fixed is not None else self.alloc(size)
            self.jail_nodes.append((at, size))
            self.put(at, bytes(size))
            self.write(at, parent)
            self.write(at + 0xE4, edge, 2)
            self.write(at + 0xE6, len(keys), 2)
            for i, key in enumerate(keys):
                self.put(at + 8 + 20*i, key)
            return at
        if len(jailed) <= 11:
            root = node(jailed, fixed=JAILED_NODE) if jailed else 0
            height = 0
        else:
            mid = len(jailed) // 2
            root = node(jailed[mid:mid+1], internal=True)
            left = node(jailed[:mid], root, 0)
            right = node(jailed[mid+1:], root, 1)
            self.write(root + 0xE8, left)
            self.write(root + 0xF0, right)
            height = 1
        self.write(STATE + 0xD8, root)
        self.write(STATE + 0xE0, height)
        self.write(STATE + 0xE8, len(jailed))
        active = HEAP_BASE + 0x3000
        self.write(active, active_node)
        self.write(active + 8, active_height)
        self.write(active + 0x10, active_count)
        self.put(ITERATOR, bytes(0x50))
        if jailed:
            self.write(ITERATOR, 1)
            self.write(ITERATOR + 0x10, root)
            self.write(ITERATOR + 0x18, height)
            self.write(ITERATOR + 0x40, len(jailed))
        self.write(ITERATOR + 0x48, active)
        self.m.run(JAILED_DIFFERENCE, {RDI: OUTPUT + 0x100, RSI: ITERATOR})
        out = OUTPUT + 0x100
        capacity, ptr, length = self.read(out), self.read(out + 8), self.read(out + 16)
        if length > capacity or length > 23:
            raise Halt('invalid difference vector')
        return [self.data(ptr + 20*i, 20) for i in range(length)]

    def removal_calls(self):
        # Execute only the post-difference loop; the removal callee is a
        # checked boundary. This does not claim the callee's tree semantics.
        m = self.m
        seen = []
        def remove(machine):
            if machine.regs[RDI] != STATE + 0xD8:
                raise Halt('wrong jailed-set argument')
            seen.append(self.data(machine.regs[RSI], 20))
            machine.regs[RAX] = 0
        m.calls[0x33AD2F0] = remove
        m.regs = [POISON] * 16
        m.regs[RSP] = STACK_TOP - 0x2000
        m.regs[RBX] = STATE
        for off in (0, 8, 16):
            self.write(m.regs[RSP] + 0x80 + off, self.read(OUTPUT + 0x100 + off))
        pc = 0x3995DF2
        for _ in range(3000):
            if pc in (0x3995E5E, 0x3995EFF):
                return seen
            row = m.cache.get(pc)
            if row is None:
                row = decode(m.read_code, pc)
                m.cache[pc] = row
            m.seen.add(pc)
            next_pc = m.step(row)
            if row.op == 'jcc':
                m.edges.add((pc, next_pc))
            pc = next_pc
        raise Halt('removal loop did not terminate')


def address(group, number):
    return hashlib.sha256(('%s:%d' % (group, number)).encode('ascii')).digest()[:20]


def scenario_specs():
    """Deterministic distinct profile keys, duplicate signers, and jail sets."""
    cases = []
    for count in range(24):
        for variant in range(4):
            keys = [address('key-%d-%d' % (count, variant), i) for i in range(count)]
            if variant == 0:
                signers = [address('signer-%d' % count, i) for i in range(count)]
            elif variant == 1:
                signers = [address('duplicates-%d' % count, i % 3) for i in range(count)]
            elif variant == 2:
                signers = list(reversed(keys))
            else:
                signers = [bytes(20) if i % 2 else bytes([255]) * 20 for i in range(count)]
            pairs = list(zip(keys, signers))
            pool = sorted(set(signers))
            include = pool[::2][:6]
            other = [address('other-%d-%d' % (count, variant), i) for i in range(5)]
            jail = sorted(set(include + other))[:11]
            cases.append(('size_%02d_variant_%d' % (count, variant), pairs, jail))
    cases.extend([
        ('empty_jail', [(address('a', i), address('b', i)) for i in range(5)], []),
        ('all_kept', [(address('c', i), address('d', i)) for i in range(11)],
         [address('d', i) for i in range(11)]),
        ('all_removed', [(address('e', i), address('f', i)) for i in range(11)],
         [address('g', i) for i in range(11)]),
        ('shared_signer', [(address('h', i), address('shared', 0)) for i in range(11)],
         [address('shared', 0), address('other', 0)]),
    ])
    for count in range(12, 24):
        signers = [address('jail-tree-signer-%d' % count, i) for i in range(8)]
        pairs = [(address('jail-tree-validator-%d' % count, i), signer)
                 for i, signer in enumerate(signers)]
        jail = sorted(signers[:4] + [address('jail-tree-other-%d' % count, i)
                                   for i in range(count - 4)])
        cases.append(('jail_tree_%02d' % count, pairs, jail))
    for seed in range(128):
        count = (seed * 17 + 5) % 24
        keys = [address('random-key-%d' % seed, i) for i in range(count)]
        signers = [address('random-signer-%d' % seed, (i * 7 + seed) % (1 + seed % 19))
                   for i in range(count)]
        universe = sorted(set(signers) | {address('random-jail-%d' % seed, i) for i in range(11)})
        jail = sorted(universe, key=lambda x: hashlib.sha256(bytes([seed]) + x).digest())[:seed % 12]
        cases.append(('varied_%03d' % seed, list(zip(keys, signers)), sorted(jail)))
    return cases


def run_case(image, name, pairs, jail, patches=None):
    f = Fixture(image, patches)
    f.profiles(pairs)
    projected = f.projected()
    root, height, length = f.read(OUTPUT), f.read(OUTPUT + 8), f.read(OUTPUT + 16)
    removed = f.difference(jail, root, length, height)
    before = f.data(STATE, 0x298) + b''.join(f.data(a, n) for a, n in f.jail_nodes)
    calls = f.removal_calls()
    after = f.data(STATE, 0x298) + b''.join(f.data(a, n) for a, n in f.jail_nodes)
    expected_set = sorted({s for _, s in pairs})
    expected_removed = sorted(set(jail) - set(expected_set))
    return dict(name=name, profiles=len(pairs), jail=len(jail),
                expected_signers=[a.hex() for a in expected_set],
                observed_signers=[a.hex() for a in projected],
                expected_removed=[a.hex() for a in expected_removed],
                observed_removed=[a.hex() for a in removed],
                removal_call_keys=[a.hex() for a in calls],
                input_profiles=[[k.hex(), v.hex()] for k, v in pairs],
                input_jail=[k.hex() for k in sorted(jail)],
                state_unchanged=(before == after),
                edges=sorted(f.m.edges),
                allocations=[list(row) for row in f.boundary],
                reached=sorted(f.m.seen))


def transition_specs():
    cases = []
    for count in range(1, 24):
        for shared in (False, True):
            keys = [address('transition-key-%d-%d' % (count, shared), i) for i in range(count)]
            signers = [address('transition-old-%d-%d' % (count, shared), i) for i in range(count)]
            target = count // 2
            if shared and count > 1:
                signers[(target + 1) % count] = signers[target]
            new = address('transition-new-%d-%d' % (count, shared), 0)
            extra = address('transition-extra-%d-%d' % (count, shared), 0)
            jail = sorted({signers[target], new, extra})
            cases.append(('change_%02d_shared_%d' % (count, shared), list(zip(keys, signers)),
                          keys[target], new, jail))
    for count in range(1, 24):
        keys = [address('insert-key-%d' % count, i) for i in range(count)]
        signers = [address('insert-signer-%d' % count, i) for i in range(count)]
        newkey = address('insert-new-key', count)
        newsigner = address('insert-new-signer', count)
        jail = [newsigner, address('insert-orphan', count)]
        cases.append(('insert_%02d' % count, list(zip(keys, signers)), newkey, newsigner, jail))
    cases.append(('insert_into_empty', [], address('new-validator', 0),
                  address('new-signer', 0), [address('new-signer', 0), address('old-jail', 0)]))
    return cases


def run_transition(image, name, pairs, key, signer, jail, patches=None):
    fixture = Fixture(image, patches)
    fixture.profiles(pairs)
    old_expected = dict(pairs).get(key)
    old_observed = fixture.write_profile(key, signer)
    profile_height_after = fixture.read(STATE + 0x158)
    profile_count_after = fixture.read(STATE + 0x160)
    expected_map = dict(pairs)
    expected_map[key] = signer
    projected = fixture.projected()
    root, height, count = fixture.read(OUTPUT), fixture.read(OUTPUT+8), fixture.read(OUTPUT+16)
    removed = fixture.difference(jail, root, count, height)
    before = fixture.data(STATE, 0x298) + b''.join(fixture.data(a, n) for a, n in fixture.jail_nodes)
    calls = fixture.removal_calls()
    after = fixture.data(STATE, 0x298) + b''.join(fixture.data(a, n) for a, n in fixture.jail_nodes)
    return {
        'name': name, 'profile_height_after': profile_height_after,
        'profile_count_after': profile_count_after, 'expected_profile_count': len(expected_map),
        'input_profiles': [[a.hex(), b.hex()] for a, b in pairs],
        'updated_key': key.hex(), 'new_signer': signer.hex(),
        'input_jail': [x.hex() for x in sorted(jail)],
        'expected_old': old_expected.hex() if old_expected is not None else None,
        'observed_old': old_observed.hex() if old_observed is not None else None,
        'expected_signers': [x.hex() for x in sorted(set(expected_map.values()))],
        'observed_signers': [x.hex() for x in projected],
        'expected_removed': [x.hex() for x in sorted(set(jail) - set(expected_map.values()))],
        'observed_removed': [x.hex() for x in removed],
        'removal_call_keys': [x.hex() for x in calls],
        'state_unchanged': before == after,
        'allocations': [list(row) for row in fixture.boundary],
        'reached': sorted(fixture.m.seen), 'edges': sorted(fixture.m.edges),
    }


def transition_matches(case):
    return (matches(case) and case['expected_old'] == case['observed_old']
            and case['profile_count_after'] == case['expected_profile_count'])


def matches(case):
    return (case['expected_signers'] == case['observed_signers']
            and case['expected_removed'] == case['observed_removed']
            and case['removal_call_keys'] == case['expected_removed']
            and case['state_unchanged'])


FUNCTIONS = (
    ('profile_insert', PROFILE_INSERT, 0x2F66E32, 'd9e8d2994c3e06f6acf0631357b4cdfd819d2f7c6f129b49ccc69b04ab1128f0'),
    ('profile_write', PROFILE_WRITE, 0x33A4991, '1b441eed7c0249f194bc35f19bf4493e12eded6c5e999e9e6af3f905019b6f11'),
    ('projection', ROOT_PROJECTION, 0x3996725, 'd1dc9a6637ad5cfb1f1f5be4d521dab99e4395e3529a633b3603772ec120f591'),
    ('collection', COLLECT_SIGNERS, 0x3BB29BD, 'fe99265daf250bcff0fd3b9364cee58be4c3561370eb481bfbc91b1308079c3d'),
    ('profile_walk', WALK_PROFILES, 0x3BE4221, 'e957176e0efc4cab1f848e7d6067ddccdacaa39ef2e78f97857e3f20d9b460f3'),
    ('jail_difference', JAILED_DIFFERENCE, 0x3BAC6E0, '41a5c99d9edf61a2689081daa073020ed8b97e46e2b2a35c472700a60f6527fc'),
    ('small_sort', SMALL_SORT, 0x3386FAE, '42e1cfb784a4c3748647aed3bbc24c78a246b2a405cf9d1f4b7c8597e6a59d79'),
    ('set_bulk_build', BULK_BUILD, 0x2FBAA61, 'c738a1ce1b9c3c283d35bee5822861abd3f68c6a2d6e3bdf8603b89e12b2ff22'),
    ('build_rebalance', REBALANCE, 0x2FA5514, '82601ac73aa5b09451279b8dce65dfc42c818db40201d51e7781f173f0c9934c'),
)

# These exact encodings fix the manual reading to the target bytes. The decoder
# must also consume every FDE exactly, and each whole body is hash-pinned above.
PINS = (
    ('profile_insert_call', 0x33A480B, 'e8f011bcff'),
    ('profile_leaf_capacity', 0x2F65A34, '4883fb0b'),
    ('profile_leaf_room_branch', 0x2F65A42, '7220'),
    ('profile_replace_load', 0x33A4744, '0f104140'),
    ('profile_replace_store', 0x33A4748, '410f114740'),
    ('profile_map_root', 0x39966B8, '488b8650010000'),
    ('profile_map_height', 0x39966BF, '488b8e58010000'),
    ('profile_map_length', 0x39966D3, '488bbe60010000'),
    ('collect_call', 0x3996717, 'e8a4c02100'),
    ('count', 0x3BB27CB, '4c8b7640'),
    ('element_size_20', 0x3BB27CF, 'b914000000'),
    ('multiply_20', 0x3BB27D7, '48f7e1'),
    ('overflow_flag', 0x3BB27DA, '0f90c1'),
    ('size_sign', 0x3BB27DD, '4885c0'),
    ('overflow_or_sign', 0x3BB27E3, '08ca'),
    ('size_gate', 0x3BB27E5, '740b'),
    ('walk_call', 0x3BB2854, 'e877170300'),
    ('single_count', 0x3BB2870, '4983ff01'),
    ('multi_count_branch', 0x3BB2874, '0f85b5000000'),
    ('bulk_build_call', 0x3BB28E2, 'e8c97a40ff'),
    ('sort_boundary_21', 0x3BB292F, '4983ff15'),
    ('large_sort_branch', 0x3BB2933, '733a'),
    ('small_sort_call', 0x3BB2945, 'e876457dff'),
    ('large_sort_slot', 0x3BB297A, 'ff151839bc01'),
    ('profile_value_stride', 0x3BE400A, '486bd258'),
    ('signer_tail', 0x3BE4012, '448b541750'),
    ('signer_head', 0x3BE401C, '0f10441740'),
    ('walk_remaining', 0x3BE4035, '4885c0'),
    ('walk_output_count', 0x3BE41EB, '4c8933'),
    ('jail_iterator', 0x3BABFCC, 'e87f3176ff'),
    ('jail_empty_exit', 0x3BABFD4, '0f84ee000000'),
    ('key_compare_slot', 0x3BAC071, 'ff151124bc01'),
    ('present_key_continues', 0x3BAC097, '0f8453ffffff'),
    ('first_vector_allocation', 0x3BAC103, 'bf50000000'),
    ('vector_capacity_test', 0x3BAC5EF, '4c3b742410'),
    ('vector_growth', 0x3BAC617, 'e8e4a372ff'),
    ('output_length', 0x3BAC642, '488b4c2420'),
    ('profile_map_pointer', 0x3995281, '498d8750010000'),
    ('profile_map_pointer_saved', 0x3995288, '4889842410020000'),
    ('profile_write_map_argument', 0x3995CF2, '488bb42410020000'),
    ('profile_write_call', 0x3995CFA, 'e801e9a0ff'),
    ('profile_reconcile_projection', 0x3995D59, 'ff15f904de01'),
    ('profile_reconcile_jail_root', 0x3995D5F, '488b83d8000000'),
    ('profile_reconcile_difference', 0x3995DED, 'e8be612100'),
    ('profile_reconcile_set', 0x3995E03, '4881c3d8000000'),
    ('profile_reconcile_remove', 0x3995E50, 'e89b74a1ff'),
    ('serializer_profile_key', 0x3990A8B, '488d356462c1fc'),
    ('serializer_profile_offset', 0x3990AA9, '498db650010000'),
    ('serializer_jail_offset', 0x3990B25, '498d96b0000000'),
)


def image_bytes(image, va, size, patches=None):
    offset = image.offset(va, size)
    result = bytearray(image.blob[offset:offset + size])
    for pos, value in (patches or {}).items():
        if va <= pos < va + size:
            result[pos - va] = value
    return bytes(result)


def check_pins(image, patches=None):
    for name, address_, expected in PINS:
        observed = image_bytes(image, address_, len(bytes.fromhex(expected)), patches)
        if observed != bytes.fromhex(expected):
            raise EvidenceError('instruction pin differs: ' + name)
    return True


def checked_capacity(count):
    """Model the pinned MUL overflow plus signed-size gate, with u64 input."""
    if not 0 <= count < 1 << 64:
        raise ValueError('count is not u64')
    result = count * 20
    if result >= 1 << 63:
        return None
    return result


def section_relocations(image):
    required = {SLOT_ALLOC, SLOT_FREE, SLOT_COMPARE, SLOT_COPY, SLOT_MEMCPY,
                SLOT_LARGE_SORT, 0x5776258, 0x576DFB8}
    rows = {}
    for slot, kind, addend, symbol in image.relocations():
        if slot in required:
            if slot in rows:
                raise EvidenceError('duplicate relocation for path slot')
            rows[slot] = (slot, kind, addend, symbol)
    if set(rows) != required:
        raise EvidenceError('missing path relocation')
    if rows[0x5776258][1:] != (8, ROOT_PROJECTION, 0):
        raise EvidenceError('projection relocation differs')
    if rows[SLOT_LARGE_SORT][1:] != (8, 0x3BC1250, 0):
        raise EvidenceError('large-sort relocation differs')
    return [rows[x] for x in sorted(rows)]


def static_data(image):
    check_pins(image)
    expected_labels = ((0x5A6CF6, b'validator_to_profile'), (0x5A6D37, b'jailed_signers'))
    for addr, value in expected_labels:
        if image_bytes(image, addr, len(value)) != value:
            raise EvidenceError('field name bytes differ')
    records, decoded = [], []
    text = image.named['.text']
    if text['type'] == 8 or not text['flags'] & 4:
        raise EvidenceError('text section is not file-backed executable code')
    for name, start, expected_end, expected_hash in FUNCTIONS:
        _, end = image.exact_fde(start)
        if end != expected_end or not (text['address'] <= start < end <= text['address'] + text['size']):
            raise EvidenceError('invalid subject FDE extent')
        code = image_bytes(image, start, end - start)
        actual_hash = hashlib.sha256(code).hexdigest()
        if actual_hash != expected_hash:
            raise EvidenceError('subject code hash differs')
        instructions = decode_range(image, start, end)
        records.append((name, start, end, image.offset(start, end-start), end-start,
                        len(instructions), actual_hash))
        decoded.extend((name, row) for row in instructions)
    # Only this narrow part of the previously mapped host is studied here.
    fragment = decode_range(image, 0x3995DF2, 0x3995E5E)
    decoded.extend(('removal_loop_slice', row) for row in fragment)
    return records, decoded, section_relocations(image)


def table(rows, headings):
    import csv
    import io
    stream = io.StringIO(newline='')
    writer = csv.writer(stream, delimiter='\t', lineterminator='\n')
    writer.writerow(headings)
    writer.writerows(rows)
    return stream.getvalue().encode('utf-8')


def json_data(value):
    return (json.dumps(value, sort_keys=True, indent=2, ensure_ascii=True) + '\n').encode('ascii')


def profile_copy_control(image):
    fixture = Fixture(image)
    key = address('copy-control-key', 0)
    fixture.profiles([(key, address('copy-control-signer', 0))])
    node = fixture.read(STATE + 0x150)
    previous = bytes((3 + 17 * i) % 256 for i in range(0x58))
    replacement = bytes((7 + 29 * i) % 256 for i in range(0x58))
    fixture.put(node + 8, previous)
    key_at, value_at, result_at = HEAP_BASE + 0x7000, HEAP_BASE + 0x7100, HEAP_BASE + 0x7200
    fixture.put(key_at, key)
    fixture.put(value_at, replacement)
    fixture.put(result_at, bytes(0x58))
    fixture.m.run(PROFILE_WRITE, {RDI: result_at, RSI: STATE + 0x150, RDX: key_at, RCX: value_at})
    returned = fixture.data(result_at, 0x58)
    stored = fixture.data(node + 8, 0x58)
    if returned != previous or stored != replacement:
        raise EvidenceError('whole-profile replacement differs')
    return {'key': key.hex(), 'previous': previous.hex(), 'replacement': replacement.hex(),
            'observed_return': returned.hex(), 'observed_stored': stored.hex(),
            'before_count': 1, 'after_count': fixture.read(STATE + 0x160)}


def failure_controls(image):
    tests = [
        ('signed_size_overflow', ((1 << 63) - 1) // 20 + 1, None),
        ('u64_product_overflow', ((1 << 64) - 1) // 20 + 1, None),
        ('vector_allocation_failure', 1, 1),
        ('tree_allocation_failure', 1, 2),
    ]
    results = []
    for name, count, fail_number in tests:
        fixture = Fixture(image)
        fixture.profiles([(address('failure-key', 0), address('failure-signer', 0))])
        fixture.write(STATE + 0x160, count)
        fixture.fail_allocation_number = fail_number
        try:
            fixture.projected()
        except Panicked:
            results.append({'case': name, 'count_word': count, 'failure_reached': True,
                            'calls': [list(row) for row in fixture.boundary]})
        else:
            raise EvidenceError('expected failure boundary not reached: ' + name)
    fixture = Fixture(image)
    fixture.profiles([])
    fixture.fail_allocation_number = 1
    try:
        fixture.write_profile(address('failure-key', 0), address('failure-signer', 0))
    except Panicked:
        results.append({'case': 'profile_node_allocation_failure', 'count_word': 0,
                        'failure_reached': True, 'calls': [list(row) for row in fixture.boundary]})
    else:
        raise EvidenceError('profile allocation failure boundary not reached')
    return results


def generate(image):
    function_rows, decoded, relocations = static_data(image)
    cases, reached, edges = [], set(), set()
    for spec in scenario_specs():
        result = run_case(image, *spec)
        if not matches(result):
            raise EvidenceError('scenario does not match independent rule: ' + spec[0])
        reached.update(result.pop('reached'))
        edges.update(tuple(edge) for edge in result.pop('edges'))
        cases.append(result)
    transitions = []
    for spec in transition_specs():
        result = run_transition(image, *spec)
        if not transition_matches(result):
            raise EvidenceError('transition does not match independent rule: ' + spec[0])
        reached.update(result.pop('reached'))
        edges.update(tuple(edge) for edge in result.pop('edges'))
        transitions.append(result)
    instructions, branches = [], []
    for name, row in decoded:
        target = hex(row.target) if row.op in ('call', 'jmp', 'jcc') else ''
        raw = image_bytes(image, row.va, row.size)
        instructions.append((name, hex(row.va), hex(image.offset(row.va, row.size)),
                             raw.hex(), row.op, target, int(row.va in reached)))
        if row.op == 'jcc':
            branches.append((name, hex(row.va), raw.hex(), hex(row.target), hex(row.next),
                             int((row.va, row.target) in edges), int((row.va, row.next) in edges)))
    profile_offset = struct.unpack_from('<i', image_bytes(image, 0x3990AA9, 7), 3)[0]
    jail_base = struct.unpack_from('<i', image_bytes(image, 0x3990B25, 7), 3)[0]
    jail_current = struct.unpack_from('<i', image_bytes(image, 0x3995D5F, 7), 3)[0]
    fields = [('validator_to_profile', hex(0x5A6CF6), image_bytes(image, 0x5A6CF6, 20).decode('ascii'), hex(profile_offset)),
              ('jailed_signers', hex(0x5A6D37), image_bytes(image, 0x5A6D37, 14).decode('ascii'), hex(jail_base)),
              ('jailed_current_root', '', '', hex(jail_current)),
              ('jailed_current_in_tracker', '', '', hex(jail_current - jail_base))]
    pins = [(name, hex(addr), hex(image.offset(addr, len(bytes.fromhex(data)))),
             image_bytes(image, addr, len(bytes.fromhex(data))).hex())
            for name, addr, data in PINS]
    mutation_cases = []
    for label, patch, index in (
        ('signer_head_offset_plus_one', {0x3BE4020: 0x41}, 20),
        ('invert_membership_branch', {0x3BAC098: 0x85}, 44),
    ):
        mutation = run_case(image, *scenario_specs()[index], patches=patch)
        mutation_cases.append({'name': label, 'case': mutation['name'],
                               'detected': not matches(mutation),
                               'expected_removed': mutation['expected_removed'],
                               'observed_removed': mutation['observed_removed'],
                               'expected_signers': mutation['expected_signers'],
                               'observed_signers': mutation['observed_signers']})
    mutated_write = run_transition(image, *transition_specs()[8], patches={0x33A4747: 0x41})
    mutation_cases.append({'name': 'profile_write_field_offset_plus_one',
                           'case': mutated_write['name'], 'detected': not transition_matches(mutated_write),
                           'expected_signers': mutated_write['expected_signers'],
                           'observed_signers': mutated_write['observed_signers'],
                           'expected_removed': mutated_write['expected_removed'],
                           'observed_removed': mutated_write['observed_removed']})
    if not all(row['detected'] for row in mutation_cases):
        raise EvidenceError('mutation control survived')
    failures = failure_controls(image)
    profile_copy = profile_copy_control(image)
    subject_insns = [row for name, row in decoded if name != 'removal_loop_slice']
    subject_seen = sum(row.va in reached for row in subject_insns)
    summary = {
        'target_sha256': SHA256,
        'subject_functions': len(function_rows),
        'subject_instruction_rows': len(subject_insns),
        'subject_rows_reached': subject_seen,
        'conditional_rows': len(branches),
        'conditional_both_edges_observed': sum(bool(r[-1] and r[-2]) for r in branches),
        'scenario_count': len(cases),
        'transition_scenario_count': len(transitions),
        'scenario_mismatches': 0,
        'mutation_controls_detected': len(mutation_cases),
        'failure_controls_reached': len(failures),
        'profile_copy_controls': 1,
        'profile_fixture_maximum': max(c['profiles'] for c in cases),
        'jail_fixture_maximum': max(c['jail'] for c in cases),
        'capacity_max_accepted': ((1 << 63) - 1) // 20,
        'capacity_first_rejected': ((1 << 63) - 1) // 20 + 1,
        'scope': 'FDEs, fixed instruction patterns, one caller loop slice, and bounded interpreted fixtures; boundary hooks are not target implementations.',
    }
    return {
        'functions.tsv': table(((name, hex(start), hex(end), hex(off), size, n, digest)
                                for name, start, end, off, size, n, digest in function_rows),
                               ['function', 'start_va', 'end_va', 'file_offset', 'size', 'instructions', 'sha256']),
        'instructions.tsv': table(instructions, ['function', 'address_va', 'file_offset', 'bytes', 'opcode', 'target_va', 'reached']),
        'branches.tsv': table(branches, ['function', 'address_va', 'bytes', 'taken_va', 'fallthrough_va', 'taken_seen', 'fallthrough_seen']),
        'fields.tsv': table(fields, ['role', 'label_va', 'label_bytes', 'offset']),
        'witnesses.tsv': table(pins, ['observation', 'address_va', 'file_offset', 'bytes']),
        'relocations.tsv': table(((hex(a), k, hex(v), s) for a,k,v,s in relocations), ['slot_va', 'type', 'addend', 'symbol_index']),
        'scenarios.json': json_data(cases),
        'transitions.json': json_data(transitions),
        'mutations.json': json_data(mutation_cases),
        'failure-controls.json': json_data(failures),
        'profile-copy-control.json': json_data(profile_copy),
        'summary.json': json_data(summary),
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out', type=pathlib.Path, required=True)
    args = parser.parse_args()
    result = generate(load_image())
    args.out.mkdir(parents=True, exist_ok=True)
    for name, data in result.items():
        (args.out / name).write_bytes(data)
    return 0


if __name__ == '__main__':
    try:
        raise SystemExit(main())
    except (EvidenceError, Halt, ValueError, OSError, struct.error) as error:
        print('staking profile jail cleanup: %s' % error, file=sys.stderr)
        raise SystemExit(1)
