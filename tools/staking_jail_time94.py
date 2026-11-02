#!/usr/bin/env python3
"""Trace the node 94 c-signer jail-time parser and checked time fields.

The x86 decoder and interpreter below are adapted from the MIT-licensed
staking_stake_accounting.py; input ELF and unwind parsing use shared tools.
"""
import argparse
import bisect
import collections
import copy
import datetime
import fractions
import hashlib
import json
import math
import multiprocessing
import pathlib
import re
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
            result = {}
            for slot, kind, addend, _ in self.relocations():
                if kind == 8:
                    if slot in result:
                        raise EvidenceError("duplicate RELATIVE relocation")
                    result[slot] = addend
            self.relative_map = result
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



# The parser hook below is an explicit boundary: it supplies decoded fields,
# not accepted text. The signed date and clock code then runs from ELF bytes.
import calendar
import csv

ENTRY = 0x219AB90
DATE_TIME = 0x151C2C0
DATE = 0x151B830
CLOCK = 0x151C1C0
PARSER_BOUNDARY = 0x1514B50
ERROR_BOUNDARY = 0x1EBADB0
SELECTED = (("content_adapter", ENTRY), ("date_time", DATE_TIME),
            ("date_builder", DATE), ("date_consistency", 0x151C0B0), ("clock_builder", CLOCK),
            ("invalid_content", 0x21C7170))
REAL = frozenset((ENTRY, DATE_TIME, DATE, CLOCK, 0x21C7170, 0x151B710, 0x151BEE0,
                  0x151BFD0, 0x151C0B0, 0x1520850))
INPUT = HEAP_BASE + 0x100
OUTPUT = HEAP_BASE + 0x400
TEXT = HEAP_BASE + 0x800
FLAGS_TABLE = 0x2504E5
FORMAT_START = 0x5671EE0
FORMAT_END = 0x5672090

# These witnesses fix the route and the conditions that the separate rule
# model uses. They are checked before any evidence is emitted.
PINS = (
 ("invalid_content_status", 0x21C71AD, "4989470841c70701000000"),
 ("invalid_content_call", 0x219AD11, "4983c608488d7c24184c89f6e84ec402008b6c241885ed"),
 ("default_error", 0x219AF4A, "488d1557cb4f03488d7424084c89f7e872ed0200b901000000ebcf"),
 ("wrapper_direct_status", 0x217D7D6, "833c2401754e488b442408b901000000eb50"),
 ("wrapper_success_copy", 0x217D82A, "8b4c2404488b442408894b0431c948894308890beb"),
 ("content_tag_gate", 0x219ABA5, "0fb60683c0f483f8030f8796030000"),
 ("format_and_parser_call", 0x219AC92, "4c8d0547724d034c8d0df0734d03488d7c2408488d7424384c89e2e89e9e37ff"),
 ("parse_result_gate", 0x219ACB2, "488b442408488b4c24104885c00f95c24885c9400f94c64084f20f84c5010000"),
 ("convert_call_gate", 0x219ACDE, "ff151c525d03837c2408000f84da010000"),
 ("convert_call_gate_second", 0x219AE6D, "ff158d505d03837c242c000f8485000000"),
 ("wrapper_box_status", 0x217D818, "833c24017522488b442408b901000000eb24"),
 ("wrapper_box_success_copy", 0x217D840, "8b4c2404488b442408894b0431c948894308890bbe"),
 ("output_carrier", 0x219AF26, "8b4c241c488b442420894b0431c948894308890b"),
 ("date_helper_call", 0x151C2DC, "ff15e63f2504458b7e7040b60241"),
 ("datetime_store", 0x151C8DF, "8903894b04895308e95dfdffff"),
 ("calendar_presence", 0x151BA8B, "4489642404440fb6e14109f4837f40010f8545010000807f68000f843b0100008b4f448b476c83f9"),
 ("calendar_month_day_limits", 0x151BAAB, "8b4f448b476c83f90d0f93c283f820400f93c641bb010000004008d60f850f010000"),
 ("calendar_table_lookup", 0x151BB10, "488d35ce49d3fe0fb63432c1e109c1e00409c809f089c1c1e903488d15214ed3fe0fbe0c1185c90f849f000000897424"),
 ("ordinal_bound", 0x151BC04, "8d9091feffff81fa92feffff0f92c208ca41bb0100000075bf"),
 ("ordinal_pack", 0x151BC57, "41c1e40dc1e0044409e04189c44109cc4489e025f81f00003d"),
 ("date_success", 0x151BDE1, "49c1e420b8000100004531dbeb28"),
 ("ordinal_consistency_gate", 0x151C161, "837f600175053947647517"),
 ("required_clock_fields", 0x151C1C3, "837e70010f85d60000008b4e7483f9020f83d3000000837e78010f85c00000008b567c83fa0c"),
 ("leap_second", 0x151C221, "4585d27424448b8e8c0000004183f93b77054531dbeb124183f93c756e41b93b00000041bb00ca9a3b83be9000000001"),
 ("fraction_gate", 0x151C24A, "83be90000000017515448b86940000004181f800ca9a3b73494585d2743b4501d84181f800ca9a3b400f93c64183f93b410f95c24184f275298d0c49"),
)


def checked_read(image, va, count, executable=False):
    if not isinstance(va, int) or not isinstance(count, int) or count < 0:
        raise EvidenceError("invalid read range")
    candidates = [s for s in image.sections if s["type"] != 8 and s["size"]
                  and s["address"] <= va and va + count <= s["address"] + s["size"]
                  and (not executable or s["flags"] & 4)]
    if len(candidates) != 1:
        raise EvidenceError("ambiguous or non-file-backed read")
    s = candidates[0]
    off = s["offset"] + va - s["address"]
    if off + count > len(image.blob):
        raise EvidenceError("file range exceeds input")
    return bytes(image.blob[off:off + count])


def validate_pins(image):
    for name, va, expected in PINS:
        if checked_read(image, va, len(bytes.fromhex(expected)), True).hex() != expected:
            raise EvidenceError("changed witness: " + name)


def get_records(image):
    _, rows = eh_frame_records(image.blob, image.sections)
    chosen = {}
    for name, address in SELECTED:
        matches = [x for x in rows if x["start"] == address]
        if len(matches) != 1:
            raise EvidenceError("selected FDE is absent or duplicated")
        r = matches[0]
        if r["end"] <= r["start"]:
            raise EvidenceError("empty FDE")
        checked_read(image, r["start"], r["end"] - r["start"], True)
        chosen[name] = r
    return chosen


def u32(value):
    return value & 0xffffffff


def clock_spec(fields):
    """Independent field-level rule; absence is a distinct integer state."""
    h12flag, half, hflag, hour, mflag, minute, sflag, second, nflag, nano = fields
    if h12flag != 1:
        return (1, 2, 0, 0)
    if half >= 2:
        return (1, 0, 0, 0)
    if hflag != 1:
        return (1, 2, 0, 0)
    if hour >= 12:
        return (1, 0, 0, 0)
    if mflag != 1:
        return (1, 2, 0, 0)
    if minute >= 60:
        return (1, 0, 0, 0)
    if sflag:
        if second > 60:
            return (1, 0, 0, 0)
        extra, second = (1000000000, 59) if second == 60 else (0, second)
    else:
        extra, second = 0, 0
    if nflag == 1:
        if nano >= 1000000000:
            return (1, 0, 0, 0)
        if not sflag:
            return (1, 2, 0, 0)
    else:
        nano = 0
    return (0, 0, (half * 12 + hour) * 3600 + minute * 60 + second, extra + nano)


def time_fields(half=0, hour=0, minute=0, sflag=1, second=0, nflag=0, nano=0):
    return (1, half, 1, hour, 1, minute, sflag, second, nflag, nano)


def put_clock(memory, pointer, fields):
    for i, value in enumerate(fields):
        memory.write(pointer + 0x70 + 4 * i, 4, value)


def decode_clock_result(memory, pointer):
    status = memory.read(pointer, 1)
    if status:
        return (status, memory.read(pointer + 1, 1), 0, 0)
    return (status, 0, memory.read(pointer + 4, 4), memory.read(pointer + 8, 4))


def setup_machine(image, patches=None):
    machine = Machine(image, patches)
    machine.memory.statics = image.relative()
    machine.real = REAL
    # Error values and destructors are deliberately modeled. The target writes
    # and tests the status itself; these hooks do not determine that status.
    machine.slots[0x4EBD240] = lambda cpu: cpu.regs.__setitem__(RAX, 0xBEEF100)
    machine.calls[0x21C9CD0] = lambda cpu: cpu.regs.__setitem__(RAX, 0xBEEF200)
    machine.calls[0x21C14C0] = lambda cpu: None
    return machine


def clock_run(machine, fields):
    machine.memory.put_bytes(INPUT, bytes(0x200))
    machine.memory.put_bytes(OUTPUT, bytes(32))
    put_clock(machine.memory, INPUT, fields)
    machine.run(CLOCK, {RDI: OUTPUT, RSI: INPUT})
    return decode_clock_result(machine.memory, OUTPUT)


def year_flags(image, year):
    return checked_read(image, FLAGS_TABLE + (year % 400), 1)[0]


def date_spec(image, year, ordinal):
    if year < -262143 or year > 262142:
        return None
    if not 1 <= ordinal <= (366 if calendar.isleap(year) else 365):
        return None
    flags = year_flags(image, year)
    if not 0 < flags < 16:
        raise EvidenceError("unexpected year flag")
    return u32((year << 13) | (ordinal << 4) | flags)


def parsed_fields(year, ordinal, fields):
    result = bytearray(0xa1)
    for offset, value in ((0x10, 1), (0x14, u32(year)), (0x60, 1), (0x64, ordinal)):
        struct.pack_into("<I", result, offset, value)
    for i, value in enumerate(fields):
        struct.pack_into("<I", result, 0x70 + i * 4, value)
    result[0xa0] = 7
    return bytes(result)


def calendar_fields(year, month, day, fields):
    result = bytearray(0xa1)
    for offset, value in ((0x10, 1), (0x14, u32(year)), (0x40, 1), (0x44, month), (0x68, 1), (0x6c, day)):
        struct.pack_into("<I", result, offset, value)
    for i, value in enumerate(fields):
        struct.pack_into("<I", result, 0x70 + i * 4, value)
    result[0xa0] = 7
    return bytes(result)


def calendar_spec(image, year, month, day):
    if year < -262143 or year > 262142 or not 1 <= month <= 12:
        return None
    lengths = [31, 28 + int(calendar.isleap(year)), 31, 30, 31, 30, 31, 31, 30, 31, 30, 31]
    if not 1 <= day <= lengths[month - 1]:
        return None
    return date_spec(image, year, sum(lengths[:month - 1]) + day)


def install_boundaries(machine, parsed, first=1, second=0):
    def parse(cpu):
        if cpu.regs[R8] != FORMAT_START or cpu.regs[R9] != FORMAT_END:
            raise Halt("unexpected format descriptor bounds")
        out, target = cpu.regs[RDI], cpu.regs[RSI]
        cpu.memory.put_bytes(target, parsed)
        cpu.memory.write(out, 8, first)
        cpu.memory.write(out + 8, 8, second)
    def error(cpu):
        # Distinct synthetic pointers make the error boundary observable.
        cpu.regs[RAX] = 0xBEEF000 + (cpu.regs[RDI] & 0xff)
    machine.calls[PARSER_BOUNDARY] = parse
    machine.calls[ERROR_BOUNDARY] = error


def adapter_run(machine, year, ordinal, fields, first=1, second=0, month=None, day=None, ordinal_constraint=None, tag=0x0c, entry=ENTRY, forced_date=None):
    machine.memory.put_bytes(INPUT, bytes(0x100))
    machine.memory.put_bytes(OUTPUT, bytes(32))
    machine.memory.write(INPUT, 1, tag)
    if tag == 0x0c:
        machine.memory.write(INPUT + 8, 8, 0)  # empty, unowned buffer
        machine.memory.write(INPUT + 16, 8, TEXT)
    elif tag == 0x0d:
        machine.memory.write(INPUT + 8, 8, TEXT)
    # All remaining bytes, including the length, are zero.
    parsed = parsed_fields(year, ordinal, fields) if month is None else calendar_fields(year, month, day, fields)
    if ordinal_constraint is not None:
        parsed = bytearray(parsed)
        struct.pack_into("<II", parsed, 0x60, 1, ordinal_constraint)
        parsed = bytes(parsed)
    install_boundaries(machine, parsed, first, second)
    if forced_date is not None:
        def force(cpu):
            target = cpu.regs[RDI]
            cpu.memory.write(target, 4, forced_date)
            cpu.memory.write(target + 4, 4, 7 if forced_date == 0 else 43210)
            cpu.memory.write(target + 8, 4, 123)
        machine.real = REAL - {DATE_TIME}
        machine.slots[DATE_TIME] = force
    try:
        machine.run(entry, {RDI: OUTPUT, RSI: INPUT, RDX: 0, RCX: 4})
    finally:
        machine.real = REAL
        machine.slots.pop(DATE_TIME, None)
    status = machine.memory.read(OUTPUT, 4)
    if status:
        return (status, machine.memory.read(OUTPUT + 8, 8), 0, 0)
    return (status, machine.memory.read(OUTPUT + 4, 4),
            machine.memory.read(OUTPUT + 8, 4), machine.memory.read(OUTPUT + 12, 4))


def boxed_wrapper_run(machine, depth, tag, date_word):
    if depth not in (1, 2) or tag not in (0x0c, 0x0d):
        raise EvidenceError("unsupported synthetic box fixture")
    outer, inner = HEAP_BASE + 0x1200, HEAP_BASE + 0x1300
    for address, size in ((INPUT, 0x100), (OUTPUT, 32), (outer, 32), (inner, 32)):
        machine.memory.put_bytes(address, bytes(size))
    machine.memory.write(INPUT, 1, 0x13)
    machine.memory.write(INPUT + 8, 8, outer)
    if depth == 2:
        machine.memory.write(outer, 1, 0x13)
        machine.memory.write(outer + 8, 8, inner)
    payload = inner if depth == 2 else outer
    machine.memory.write(payload, 1, tag)
    machine.memory.write(payload + (16 if tag == 0x0c else 8), 8, TEXT)
    install_boundaries(machine, calendar_fields(1970, 1, 1, time_fields()))
    freed = []
    def free(cpu):
        freed.append((cpu.regs[RDI], cpu.regs[RSI]))
        cpu.regs[RAX] = 0
    def force(cpu):
        result = cpu.regs[RDI]
        cpu.memory.write(result, 4, date_word)
        cpu.memory.write(result + 4, 4, 7 if date_word == 0 else 43210)
        cpu.memory.write(result + 8, 4, 123)
    statics = machine.memory.statics
    machine.memory.statics = dict(statics)
    machine.memory.statics[0x576E010] = 0xDEAD002
    machine.slots[0xDEAD002] = free
    machine.slots[DATE_TIME] = force
    machine.real = REAL - {DATE_TIME}
    try:
        machine.run(0x217D750, {RDI: OUTPUT, RSI: INPUT})
    finally:
        machine.memory.statics = statics
        machine.slots.pop(0xDEAD002, None)
        machine.slots.pop(DATE_TIME, None)
        machine.real = REAL
    expected_frees = ([(inner, 32)] if depth == 2 else []) + [(outer, 32)]
    if freed != expected_frees:
        raise EvidenceError("unexpected boxed-wrapper cleanup arguments")
    status = machine.memory.read(OUTPUT, 4)
    value = machine.memory.read(OUTPUT + 8, 8) if status else machine.memory.read(OUTPUT + 4, 4)
    seconds = 0 if status else machine.memory.read(OUTPUT + 8, 4)
    nanos = 0 if status else machine.memory.read(OUTPUT + 12, 4)
    return status, value, seconds, nanos, len(freed)


def clock_vectors():
    for half in (0, 1):
        for hour in (0, 1, 11, 12, 255):
            for minute in (0, 59, 60):
                for sf, second in ((0, 0), (1, 0), (1, 59), (1, 60), (1, 61)):
                    for nf, ns in ((0, 0), (1, 0), (1, 999999999), (1, 1000000000)):
                        yield time_fields(half, hour, minute, sf, second, nf, ns)
    for fields in ((0, 0, 1, 0, 1, 0, 1, 0, 0, 0),
                   (1, 2, 1, 0, 1, 0, 1, 0, 0, 0),
                   (1, 0, 0, 0, 1, 0, 1, 0, 0, 0),
                   (1, 0, 1, 0, 0, 0, 1, 0, 0, 0),
                   (1, 0, 1, 0, 1, 0, 2, 60, 2, 123)):
        yield fields


def date_vectors():
    for year in range(400):
        for ordinal in (0, 1, 365, 366, 367):
            yield year, ordinal
    for year in (-262144, -262143, -400, -100, -1, 400, 1900, 1970,
                 2000, 2024, 9999, 262142, 262143):
        for ordinal in (0, 1, 365, 366, 367):
            yield year, ordinal


def calendar_vectors():
    for year in range(400):
        for month in range(1, 13):
            for day in (0, 1, 28, 29, 30, 31, 32):
                yield year, month, day
    for year in (-262144, -262143, -400, -1, 1900, 1970, 2000, 2024, 262142, 262143):
        for month, day in ((0, 1), (1, 1), (2, 28), (2, 29), (12, 31), (13, 1)):
            yield year, month, day


def write_rows(out, name, header, rows):
    with (out / name).open("w", encoding="utf-8", newline="") as f:
        w = csv.writer(f, delimiter="\t", lineterminator="\n")
        w.writerow(header)
        w.writerows(rows)


def generate(image, out):
    validate_pins(image)
    records = get_records(image)
    out.mkdir(parents=True, exist_ok=True)
    machine = setup_machine(image)
    date_rows = []
    tfields = time_fields(1, 11, 59, 1, 60, 1, 999999999)
    for year, ordinal in date_vectors():
        actual = adapter_run(machine, year, ordinal, tfields)
        packed = date_spec(image, year, ordinal)
        expected = (1, 0xBEEF000, 0, 0) if packed is None else (0, packed, 86399, 1999999999)
        if actual != expected:
            raise EvidenceError("date model mismatch for %d/%d: %r != %r" % (year, ordinal, actual, expected))
        date_rows.append((year, ordinal, "error" if actual[0] else "ok", hex(actual[1]), actual[2], actual[3]))
    write_rows(out, "date-cases.tsv", ("year", "ordinal", "status", "date_or_hook", "second_of_day", "nanosecond"), date_rows)
    calendar_rows = []
    for year, month, day in calendar_vectors():
        actual = adapter_run(machine, year, 0, tfields, month=month, day=day)
        packed = calendar_spec(image, year, month, day)
        expected = (1, 0xBEEF000, 0, 0) if packed is None else (0, packed, 86399, 1999999999)
        if actual != expected:
            raise EvidenceError("calendar model mismatch for %d/%d/%d: %r != %r" % (year, month, day, actual, expected))
        calendar_rows.append((year, month, day, "error" if actual[0] else "ok", hex(actual[1]), actual[2], actual[3]))
    write_rows(out, "calendar-cases.tsv", ("year", "month", "day", "status", "date_or_hook", "second_of_day", "nanosecond"), calendar_rows)
    consistency_rows = []
    for year in range(400):
        for month, day in ((1, 1), (2, 28), (3, 1), (12, 31)):
            packed = calendar_spec(image, year, month, day)
            lengths = [31, 28 + int(calendar.isleap(year)), 31, 30, 31, 30, 31, 31, 30, 31, 30, 31]
            expected_ordinal = sum(lengths[:month - 1]) + day
            for supplied in (expected_ordinal - 1, expected_ordinal, expected_ordinal + 1):
                actual = adapter_run(machine, year, 0, tfields, month=month, day=day, ordinal_constraint=supplied)
                expected = ((0, packed, 86399, 1999999999) if supplied == expected_ordinal
                            else (1, 0xBEEF001, 0, 0))
                if actual != expected:
                    raise EvidenceError("date consistency mismatch %d/%d/%d/%d: %r != %r" % (year, month, day, supplied, actual, expected))
                consistency_rows.append((year, month, day, supplied, expected_ordinal, "error" if actual[0] else "ok", hex(actual[1])))
    write_rows(out, "consistency-cases.tsv", ("year", "month", "day", "supplied_ordinal", "calendar_ordinal", "status", "date_or_hook"), consistency_rows)
    clock_rows = []
    for fields in clock_vectors():
        actual, expected = clock_run(machine, fields), clock_spec(fields)
        if actual != expected:
            raise EvidenceError("clock model mismatch %r: %r != %r" % (fields, actual, expected))
        clock_rows.append((*fields, *actual))
    write_rows(out, "clock-cases.tsv", ("half_flag", "half", "hour_flag", "hour12", "minute_flag", "minute", "second_flag", "second", "nano_flag", "nano", "status", "error_code", "second_of_day", "nanosecond"), clock_rows)
    # These cases run the complete selected adapter and converter, with only
    # the text-parser and error formatter boundaries modeled.
    path_inputs = (
        ("midnight", 1970, 1, time_fields()),
        ("end_of_day", 1970, 1, time_fields(1, 11, 59, 1, 59, 1, 999999999)),
        ("leap_second", 1970, 1, time_fields(1, 11, 59, 1, 60, 1, 999999999)),
        ("leap_second_at_midnight", 1970, 1, time_fields(0, 0, 0, 1, 60)),
        ("missing_minute", 1970, 1, (1, 0, 1, 0, 0, 0, 1, 0, 0, 0)),
        ("minute_60", 1970, 1, time_fields(0, 0, 60)),
        ("second_61", 1970, 1, time_fields(0, 0, 0, 1, 61)),
        ("nanosecond_limit", 1970, 1, time_fields(0, 0, 0, 1, 0, 1, 1000000000)),
        ("fraction_without_seconds", 1970, 1, time_fields(0, 0, 0, 0, 0, 1, 0)),
        ("year_zero", 0, 1, time_fields()),
        ("bad_ordinal", 2023, 366, time_fields()),
    )
    path_rows = []
    for label, year, ordinal, fields in path_inputs:
        actual = adapter_run(machine, year, ordinal, fields)
        packed = date_spec(image, year, ordinal)
        rule = clock_spec(fields)
        expected = ((1, 0xBEEF000, 0, 0) if packed is None else
                    (1, 0xBEEF000 + rule[1], 0, 0) if rule[0] else
                    (0, packed, rule[2], rule[3]))
        if actual != expected:
            raise EvidenceError("path model mismatch for %s: %r != %r" % (label, actual, expected))
        path_rows.append((label, year, ordinal, *fields, actual[0], hex(actual[1]), actual[2], actual[3]))
    write_rows(out, "path-cases.tsv", ("case", "year", "ordinal", "half_flag", "half", "hour_flag", "hour12", "minute_flag", "minute", "second_flag", "second", "nano_flag", "nano", "status", "date_or_hook", "second_of_day", "nanosecond"), path_rows)
    tag_rows = []
    for tag in range(256):
        actual = adapter_run(machine, 1970, 1, time_fields(), tag=tag)
        expected = (0, 0xF6401A, 0, 0) if tag in (0x0c, 0x0d) else (1, 0xBEEF100 if tag in (0x0e, 0x0f) else 0xBEEF200, 0, 0)
        if actual != expected:
            raise EvidenceError("content-tag model mismatch for %#x" % tag)
        tag_rows.append((hex(tag), actual[0], hex(actual[1]), actual[2], actual[3]))
    write_rows(out, "content-cases.tsv", ("internal_tag", "status", "date_or_hook", "second_of_day", "nanosecond"), tag_rows)
    force_rows = []
    for entry_name, entry in (("adapter", ENTRY), ("direct_wrapper", 0x217D750)):
        for tag in (0x0c, 0x0d):
            for date_word in (0, 1, 0x14, 0xF6401A, 0xffffffff):
                actual = adapter_run(machine, 1970, 1, time_fields(), tag=tag, entry=entry, forced_date=date_word)
                expected = (1, 0xBEEF007, 0, 0) if date_word == 0 else (0, date_word, 43210, 123)
                if actual != expected:
                    raise EvidenceError("forced-date model mismatch")
                force_rows.append((entry_name, hex(tag), hex(date_word), actual[0], hex(actual[1]), actual[2], actual[3]))
    write_rows(out, "forced-date-cases.tsv", ("entry", "internal_tag", "injected_date", "status", "date_or_hook", "second_of_day", "nanosecond"), force_rows)
    boxed_rows = []
    for depth in (1, 2):
        for tag in (0x0c, 0x0d):
            for date_word in (0, 1):
                actual = boxed_wrapper_run(machine, depth, tag, date_word)
                expected = (1, 0xBEEF007, 0, 0, depth) if not date_word else (0, 1, 43210, 123, depth)
                if actual != expected:
                    raise EvidenceError("boxed-wrapper model mismatch")
                boxed_rows.append((depth, hex(tag), date_word, actual[0], hex(actual[1]), actual[2], actual[3], actual[4]))
    write_rows(out, "boxed-cases.tsv", ("depth", "internal_tag", "injected_date", "status", "date_or_hook", "second_of_day", "nanosecond", "free_hook_calls"), boxed_rows)
    # The two parse-result controls stop at the synthetic error boundary.
    controls = []
    for label, first, second in (("no_first", 0, 3), ("trailing", 1, 1)):
        result = adapter_run(machine, 1970, 1, tfields, first, second)
        controls.append((label, first, second, result[0], hex(result[1])))
        if result[0] != 1:
            raise EvidenceError("parse-result control accepted")
    write_rows(out, "parse-controls.tsv", ("case", "first", "second", "status", "error_hook_result"), controls)
    fn_rows, ins_rows = [], []
    for name, start in SELECTED:
        fde = records[name]
        end = fde["end"]
        body = checked_read(image, start, end - start, True)
        rows = decode_range(image, start, end)
        fn_rows.append((name, hex(start), hex(end), hex(fde["fde"]), hex(image.offset(start)), len(body), hashlib.sha256(body).hexdigest(), len(rows), sum(row.va in machine.seen for row in rows)))
        for row in rows:
            ins_rows.append((name, hex(row.va), row.data.hex(), row.op,
                             "" if row.target is None else hex(row.target)))
    write_rows(out, "functions.tsv", ("role", "start_va", "end_va", "fde_va", "file_offset", "bytes", "sha256", "instruction_rows", "reached_rows"), fn_rows)
    write_rows(out, "instructions.tsv", ("function", "address_va", "bytes", "operation", "direct_target_or_aux"), ins_rows)
    pin_rows = [(name, hex(va), checked_read(image, va, len(bytes.fromhex(expected)), True).hex()) for name, va, expected in PINS]
    write_rows(out, "anchors.tsv", ("name", "address_va", "bytes"), pin_rows)
    table_rows = []
    for index in range(4):
        raw = checked_read(image, 0x3CF0E8 + index * 4, 4)
        target = 0x3CF0E8 + struct.unpack("<i", raw)[0]
        table_rows.append((hex(0x0c + index), hex(0x3CF0E8 + index * 4), raw.hex(), hex(target)))
    write_rows(out, "content-table.tsv", ("internal_tag", "entry_va", "bytes", "target_va"), table_rows)
    # Context-only calls tie the upstream jail-vote value reader to the new
    # adapter. Only the four selected FDEs are claimed in this packet.
    link_specs = (
        ("map_value_to_wrapper", 0x1F24516, 0x217D750),
        ("sequence_value_to_wrapper", 0x1F4EB96, 0x217D750),
        ("wrapper_nested", 0x217D78E, ENTRY),
        ("wrapper_direct", 0x217D7D1, ENTRY),
        ("wrapper_owned", 0x217D813, ENTRY),
        ("compare_date_constraints", 0x151BDD4, 0x151C0B0),
        ("invalid_content_error", 0x219AD1D, 0x21C7170),
    )
    links = []
    for label, site, expected in link_specs:
        raw = checked_read(image, site, 5, True)
        if raw[0] != 0xe8:
            raise EvidenceError("unexpected direct-call opcode")
        target = site + 5 + struct.unpack("<i", raw[1:])[0]
        if target != expected:
            raise EvidenceError("unexpected direct-call target")
        links.append((label, hex(site), raw.hex(), "", hex(target)))
    for label, site, expected_slot, expected_target in (
            ("convert_on_input_a", 0x219ACDE, 0x576FF00, DATE_TIME),
            ("convert_on_input_b", 0x219AE6D, 0x576FF00, DATE_TIME),
            ("date_from_parsed", 0x151C2DC, 0x57702C8, DATE),
            ("clock_fallback", 0x151C8F6, 0x57702D8, CLOCK)):
        raw = checked_read(image, site, 6, True)
        if raw[:2] != b"\xff\x15":
            raise EvidenceError("unexpected slot-call opcode")
        slot = site + 6 + struct.unpack("<i", raw[2:])[0]
        if slot != expected_slot or image.relative().get(slot) != expected_target:
            raise EvidenceError("slot relocation or target differs")
        links.append((label, hex(site), raw.hex(), hex(slot), hex(expected_target)))
    write_rows(out, "links.tsv", ("role", "call_va", "bytes", "relative_slot_va", "target_va"), links)
    descriptors = []
    for index in range((FORMAT_END - FORMAT_START) // 24):
        address = FORMAT_START + index * 24
        raw = checked_read(image, address, 24)
        slot = address + 8
        target = image.relative().get(slot)
        descriptors.append((index, hex(address), raw.hex(), "" if target is None else hex(target)))
    write_rows(out, "format-descriptors.tsv", ("index", "address_va", "bytes", "pointer_relocation_target_va"), descriptors)
    year_bytes = checked_read(image, FLAGS_TABLE, 400)
    write_rows(out, "year-flags.tsv", ("cycle_index", "byte"), [(i, b) for i, b in enumerate(year_bytes)])
    summary = {"artifact_sha256": SHA256, "coordinate_system": "linked ELF virtual addresses",
               "date_vectors": len(date_rows), "date_successes": sum(r[2] == "ok" for r in date_rows),
               "calendar_vectors": len(calendar_rows), "calendar_successes": sum(r[3] == "ok" for r in calendar_rows),
               "consistency_vectors": len(consistency_rows), "consistency_successes": sum(r[5] == "ok" for r in consistency_rows),
               "clock_vectors": len(clock_rows), "clock_successes": sum(r[-4] == 0 for r in clock_rows),
               "parse_controls": len(controls), "path_vectors": len(path_rows), "content_vectors": len(tag_rows), "forced_date_vectors": len(force_rows), "boxed_vectors": len(boxed_rows), "link_witnesses": len(links), "format_descriptors": len(descriptors), "selected_fdes": len(fn_rows),
               "instructions_in_selected_fdes": len(ins_rows),
               "reached_selected_instruction_addresses": sum(r[8] for r in fn_rows),
               "normalization": "none", "parser_boundary": "injected parsed fields; text parsing and cleanup excluded"}
    (out / "summary.json").write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return summary


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--out", required=True, type=pathlib.Path)
    args = p.parse_args()
    image = load_image()
    generate(image, args.out)


if __name__ == "__main__":
    try:
        main()
    except (EvidenceError, Halt, OSError, ValueError, struct.error) as error:
        print("staking_jail_time94: %s" % error, file=sys.stderr)
        raise SystemExit(1)
