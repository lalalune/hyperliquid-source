#!/usr/bin/env python3
"""Reconstruct the node #115 signed-message admission front ends: stake set lookup, signer search, signature recovery and the move-or-error wrappers.

The block front end 0x57e8970, the signer check 0x57e8bd0 (slot 0x64e64b8), the ring search 0x57f54e0, the signed block wrapper 0x2786870
and the timeout message wrapper 0x2786a20 run as real bytes in an interpreter inside this tool. The stake set provider, the block rules, the
signing digest, the nested certificate wrapper, signature recovery, libc, the allocator and the panic entries are named contract stubs.
A separately written rule list predicts every output byte and the ordered stub calls. No disassembler output is parsed and the binary is
never executed. Standard library only.

    python3 tools/consensus_signer_front_115.py --out <dir>
"""
import argparse
import bisect
import collections
import hashlib
import itertools
import json
import multiprocessing
import pathlib
import re
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






class Real:
    """Every code address runs for real, but for the skipped stub targets."""

    def __init__(self, low, high):
        self.low, self.high, self.skip = low, high, set()

    def __contains__(self, va):
        return self.low <= va < self.high and va not in self.skip


# ---------------------------------------------------------------------------------------------
# Node #115 signed-message admission front ends (consensus): who may speak, then the certificate rules.
# ---------------------------------------------------------------------------------------------

FRONT, SIGNER, RING = 0x57E8970, 0x57E8BD0, 0x57F54E0
WRAP_BLOCK, WRAP_TV = 0x2786870, 0x2786A20
DIGEST, DROP_CERT, ITER_NEXT, QC_WRAP = 0x57E8D40, 0x2780350, 0x2448AA0, 0x595FD20
SLOT_STAKES, SLOT_SIGNER, SLOT_VERIFY, SLOT_RECOVER = 0x64E64B0, 0x64E64B8, 0x64E64C0, 0x64E0AD8
GOT_MALLOC, GOT_ALLOC_ERR, GOT_FREE = 0x64DF480, 0x64DF490, 0x64DF4A0
GOT_PANICS = (0x64DF4C0, 0x64DF570, 0x64DF620, 0x64DF730, 0x64DF830)
GOT_MEMCPY, GOT_MEMMOVE, GOT_MEMCMP = 0x64DF508, 0x64DF568, 0x64DFB50
MARK_BASE = 0x7700000000
SENT = 0x8000000000000001
MINW = 0x8000000000000000
OK_TAG = 0x2E
CAP = 11
KEY = 20
LEAF, INTERNAL = 0x140, 0x1A0
F_KEYS, F_PIDX, F_LEN, F_EDGES = 0x60, 0x13C, 0x13E, 0x140
ROW = 32
STATE_AT = HEAP_BASE + 0x100
BLOCK_AT = HEAP_BASE + 0x400
IN_AT = HEAP_BASE + 0x800
OUT_AT = HEAP_BASE + 0xA00
OUT_SIZE = 0x200
SETOBJ_AT = HEAP_BASE + 0x1000
ERRBOX_AT = HEAP_BASE + 0x1100
VT_AT = HEAP_BASE + 0x1180
ADDR_AT = HEAP_BASE + 0x1200
SIG_AT = HEAP_BASE + 0x1240
MSG_AT = HEAP_BASE + 0x1280
BOX_AT = HEAP_BASE + 0x12C0
VEC_AT = HEAP_BASE + 0x1400
FIX_AT = HEAP_BASE + 0x4000
ARENA = HEAP_BASE + 0x40000
ARENA_LIMIT = HEAP_BASE + 0x3E0000
USED = 0x60000
FILL = 0xA5
BLOCK_SIZE, TV_SIZE = 0x178, 0xE0


def r16(size):
    return (size + 15) // 16 * 16


class Stream:
    """xorshift64: the same numbers on every Python version."""

    def __init__(self, seed):
        self.state = (seed * 0x9E3779B97F4A7C15 + 0x1234567) & MASK[8] or 1

    def next(self, bound):
        x = self.state
        x ^= x << 13 & MASK[8]
        x ^= x >> 7
        x ^= x << 17 & MASK[8]
        self.state = x
        return x % bound

    def bytes(self, count):
        return bytes(self.next(256) for _ in range(count))


def addr_of(value):
    """A 20 byte address ordered like its integer: 2 big-endian bytes then a hash tail."""
    return value.to_bytes(2, "big") + hashlib.sha256(b"a%d" % value).digest()[:KEY - 2]


def digest_of(variant, content):
    """The contract of the signing digest stub: 32 bytes fixed by the variant word and the message content."""
    return hashlib.sha256(struct.pack("<Q", variant) + content).digest()


# ---- the models: a set as the code finds an address in it -----------------------------------

class MNode:
    __slots__ = ("keys", "edges")

    def __init__(self, keys, edges=None):
        self.keys, self.edges = keys, edges


def build_tree(keys, height, stream):
    """Pack sorted keys into a B-tree of exactly this height; fan-out and fill are chosen by the stream."""
    if height == 0:
        return MNode(list(keys))
    count = len(keys)
    low_cap = 12 ** height - 1 if height > 0 else 0
    children_cap = 12 ** (height - 1) - 1 if height > 1 else CAP
    # at least 2 children, at most 12, every child must fit its share
    need = max(2, -(-(count + 1) // (children_cap + 1)))
    kids = min(12, need + stream.next(3))
    kids = max(2, min(kids, count + 1))
    seps = kids - 1
    rest = count - seps
    shares = [rest // kids] * kids
    for i in range(rest - sum(shares)):
        shares[stream.next(kids)] += 1
    out_keys, edges, at = [], [], 0
    for i in range(kids):
        share = shares[i]
        edges.append(build_tree(keys[at:at + share], height - 1, stream))
        at += share
        if i < seps:
            out_keys.append(keys[at])
            at += 1
    return MNode(out_keys, edges)


def tree_height_for(count):
    height = 0
    while 12 ** (height + 1) - 1 < count:
        height += 1
    return height


def memcmp_sign(a, b):
    return (a > b) - (a < b)


def tree_contains(root, height, addr, flaws=()):
    """The walk of 0x57e8bd0 / 0x57e8970: keys left to right, equal found, smaller descends, bigger moves on."""
    node, level = root, height
    while True:
        index = 0
        for key in node.keys:
            order = memcmp_sign(addr, key)
            if "tree_reverse" in flaws:
                order = -order
            if order == 0:
                return True
            if order < 0:
                break
            index += 1
        if "tree_first_key_only" in flaws and node.keys and index > 0:
            index = 0
        if level == 0 or node.edges is None:
            return False
        if "no_height_stop" in flaws and level == 0:
            return False
        node, level = node.edges[index], level - 1


def ring_search(rows, head, cap, key, flaws=()):
    """VecDeque<row>::binary_search_by(row.key.cmp(key)): front slice, back slice, size halving. -> (found, index)"""
    count = len(rows)
    ordered = list(rows)
    split = min(count, cap - head) if cap else 0
    front, back = ordered[:split], ordered[split:]

    def bsearch(items):
        size, base = len(items), 0
        if size == 0:
            return False, 0
        while size > 1:
            half = size // 2
            mid = base + half
            if "ring_ge_moves" in flaws:
                base = mid if memcmp_sign(items[mid][:KEY], key) >= 0 else base
            else:
                base = mid if memcmp_sign(items[mid][:KEY], key) <= 0 else base
            size -= half
        order = memcmp_sign(items[base][:KEY], key)
        if order == 0:
            return True, base
        return False, base + (order < 0)

    if back:
        order = memcmp_sign(back[0][:KEY], key)
        if order == 0:
            return True, len(front)
        if order < 0:
            found, idx = bsearch(back)
            return found, idx + len(front)
    return bsearch(front)


# ---- the fixture: machine memory, stub contracts, one run -----------------------------------

class Run:
    """Machine plus fixture: every code address runs as bytes, but libc, the allocator, the panic entries and the named contracts."""

    def __init__(self, image, patches=None, cache=None):
        self.image = image
        machine = self.machine = Machine(image, patches)
        memory = self.memory = Memory(image)
        machine.memory = memory
        text = image.named[".text"]
        machine.real = Real(text["address"], text["address"] + text["size"])
        machine.real.skip.update({DIGEST, DROP_CERT, ITER_NEXT, QC_WRAP})
        machine.step_limit = 300000
        memory.statics = dict(image.relative())
        hooks = {GOT_MALLOC: self.h_malloc, GOT_ALLOC_ERR: self.h_alloc_error, GOT_FREE: self.h_free, GOT_MEMCPY: self.h_copy,
                 GOT_MEMMOVE: self.h_copy, GOT_MEMCMP: self.h_cmp, SLOT_STAKES: self.h_stakes, SLOT_VERIFY: self.h_verify,
                 SLOT_RECOVER: self.h_recover}
        for slot in GOT_PANICS:
            hooks[slot] = self.h_panic
        for slot, hook in hooks.items():
            fake = MARK_BASE + slot
            memory.statics[slot] = fake
            machine.slots[fake] = hook
        self.err_drop = MARK_BASE + 0x1
        machine.slots[self.err_drop] = self.h_err_drop
        machine.calls[DIGEST] = self.h_digest
        machine.calls[DROP_CERT] = self.h_drop_cert
        machine.calls[ITER_NEXT] = self.h_iter
        machine.calls[QC_WRAP] = self.h_qc
        if cache:
            machine.cache = dict(cache)
            for va in (patches or {}):
                for back in range(16):
                    machine.cache.pop(va - back, None)
        self.log, self.top, self.fix, self.mallocs = [], ARENA, FIX_AT, 0
        self.plan = {}
        self.fail_at = None

    # ---- stubs ------------------------------------------------------------------------------
    def rel(self, value):
        if STACK_TOP - STACK_SIZE <= value < STACK_TOP:
            return "stack"
        return value - HEAP_BASE if HEAP_BASE <= value < HEAP_BASE + HEAP_SIZE else value

    def h_malloc(self, machine):
        size = machine.regs[RDI]
        self.mallocs += 1
        if self.fail_at == self.mallocs:
            self.log.append(("malloc", size, -1))
            machine.regs[RAX] = 0
            return
        at = self.top
        self.top += r16(size)
        if self.top > ARENA_LIMIT:
            raise Halt("fixture arena full")
        self.memory.put_bytes(at, bytes([FILL]) * r16(size))
        self.log.append(("malloc", size, self.rel(at)))
        machine.regs[RAX] = at

    def h_alloc_error(self, machine):
        self.log.append(("alloc_error", machine.regs[RDI], machine.regs[RSI]))
        raise Panicked("allocation failure")

    def h_free(self, machine):
        self.log.append(("free", self.rel(machine.regs[RDI]), machine.regs[RSI], machine.regs[RDX]))

    def h_copy(self, machine):
        dst, src, count = machine.regs[RDI], machine.regs[RSI], machine.regs[RDX]
        self.log.append(("copy", self.rel(dst), self.rel(src), count))
        if count:
            self.memory.put_bytes(dst, self.memory.bytes_at(src, count))
        machine.regs[RAX] = dst

    def h_cmp(self, machine):
        count = machine.regs[RDX]
        left, right = self.memory.bytes_at(machine.regs[RDI], count), self.memory.bytes_at(machine.regs[RSI], count)
        result = 0
        for a, b in zip(left, right):
            if a != b:
                result = a - b
                break
        machine.regs[RAX] = result & MASK[4]

    def h_panic(self, machine):
        raise Panicked("panic path reached")

    def record(self, tag, seed):
        """A 0x48 byte result record: tag byte then seeded bytes, or only the tag for the success tag."""
        if tag == OK_TAG:
            return bytes([tag])
        return bytes([tag]) + Stream(seed).bytes(0x47)

    def h_stakes(self, machine):
        out, state, rnd = machine.regs[RDI], machine.regs[RSI], machine.regs[RDX]
        self.log.append(("stakes", self.rel(state), rnd))
        tag, seed = self.plan["stakes"]
        if tag == OK_TAG:
            self.memory.put_bytes(out, bytes([OK_TAG]))
            self.memory.write(out + 8, 8, SETOBJ_AT)
        else:
            self.memory.put_bytes(out, self.record(tag, seed))

    def h_verify(self, machine):
        out, block, state = machine.regs[RDI], machine.regs[RSI], machine.regs[RDX]
        self.log.append(("verify", self.rel(out), self.rel(block), self.rel(state)))
        tag, seed = self.plan["verify"]
        self.memory.put_bytes(out, self.record(tag, seed))

    def h_qc(self, machine):
        out, tv = machine.regs[RDI], machine.regs[RSI]
        self.log.append(("qc", self.rel(out), self.rel(tv)))
        tag, seed = self.plan["qc"]
        self.memory.put_bytes(out, self.record(tag, seed))

    def h_digest(self, machine):
        out, msg = machine.regs[RDI], machine.regs[RSI]
        variant = self.memory.read(msg, 8)
        ptr = self.memory.read(msg + 8, 8)
        content = self.memory.bytes_at(ptr, 0x38) if variant == 2 else struct.pack("<Q", self.rel(ptr))
        digest = digest_of(variant, content)
        self.log.append(("digest", variant, content.hex()))
        self.memory.put_bytes(out, digest)

    def h_recover(self, machine):
        out, sig, digest = machine.regs[RDI], machine.regs[RSI], machine.regs[RDX]
        got = self.memory.bytes_at(digest, 32)
        self.log.append(("recover", self.rel(sig), self.memory.bytes_at(sig, 8).hex(), got.hex()))
        kind, who = self.plan["recover"]
        if kind == "ok":
            self.memory.put_bytes(out, bytes([0]) + who)
        else:
            self.memory.put_bytes(out, bytes([1]))
            self.memory.write(out + 8, 8, ERRBOX_AT)

    def h_err_drop(self, machine):
        self.log.append(("err_drop", self.rel(machine.regs[RDI])))

    def h_drop_cert(self, machine):
        self.log.append(("drop_cert", self.rel(machine.regs[RDI])))

    def h_iter(self, machine):
        out, it = machine.regs[RDI], machine.regs[RSI]
        words = tuple(self.memory.read(it + 8 * i, 8) for i in range(10))
        left = self.memory.read(it + 0x40, 8)
        self.log.append(("iter", self.rel(out), self.rel(it), tuple(self.rel(w) for w in words), left))
        if left:
            self.memory.write(it + 0x40, 8, left - 1)
            self.memory.write(out, 8, 1)
        else:
            self.memory.write(out, 8, 0)

    # ---- fixture ----------------------------------------------------------------------------
    def reset(self):
        self.memory.reset(USED)
        self.log, self.top, self.fix, self.mallocs = [], ARENA, FIX_AT, 0

    def fix_alloc(self, size):
        at = self.fix
        self.fix += r16(size)
        if self.fix > ARENA:
            raise Halt("fixture area full")
        return at

    def place_node(self, node, level, parent):
        at = self.fix_alloc(INTERNAL if node.edges is not None else LEAF)
        write = self.memory.write
        write(at, 8, parent)
        write(at + F_PIDX, 2, 0)
        write(at + F_LEN, 2, len(node.keys))
        for i, key in enumerate(node.keys):
            self.memory.put_bytes(at + F_KEYS + KEY * i, key)
        if node.edges is not None:
            for i, child in enumerate(node.edges):
                write(at + F_EDGES + 8 * i, 8, self.place_node(child, level - 1, at))
        return at

    def place_set(self, spec):
        kind = spec["kind"]
        write = self.memory.write
        if kind == "tree":
            root = spec["root"]
            at = self.place_node(root, spec["height"], 0) if root is not None else 0
            write(SETOBJ_AT, 8, MINW)
            write(SETOBJ_AT + 8, 8, at)
            write(SETOBJ_AT + 0x10, 8, spec["height"])
            write(SETOBJ_AT + 0x18, 8, spec["count"])
        else:
            cap, head, rows = spec["cap"], spec["head"], spec["rows"]
            buf = self.fix_alloc(max(1, cap) * ROW)
            for i, row in enumerate(rows):
                self.memory.put_bytes(buf + ((head + i) % cap) * ROW, row)
            write(SETOBJ_AT, 8, cap)
            write(SETOBJ_AT + 8, 8, buf)
            write(SETOBJ_AT + 0x10, 8, head)
            write(SETOBJ_AT + 0x18, 8, len(rows))


# ---- the rule list (written from the observations, never from the instruction rows) ---------

HEAP_REL = lambda va: va - HEAP_BASE
STATE_REL, BLOCK_REL, IN_REL, OUT_REL = HEAP_REL(STATE_AT), HEAP_REL(BLOCK_AT), HEAP_REL(IN_AT), HEAP_REL(OUT_AT)
VEC_REL, ERRBOX_REL, BOX_REL = HEAP_REL(VEC_AT), HEAP_REL(ERRBOX_AT), HEAP_REL(BOX_AT)
M64 = MASK[8]


def record_bytes(tag, seed):
    if tag == OK_TAG:
        return bytes([tag])
    return bytes([tag]) + Stream(seed).bytes(0x47)


def block_round(block):
    """Which certificate carries the round the stake set is asked for: +0x18 sentinel picks the one at +0x20."""
    a, b, (rx, ry, rz) = block["a"], block["b"], block["rounds"]
    if a == SENT:
        return rx          # certificate at +0x20, round word at +0x60
    return ry if b == SENT else rz   # certificate at +0x18 (round at +0x58) or at +0xa8 (round at +0xe8)


def set_contains(spec, addr, flaws=()):
    if spec["kind"] == "none":
        return False
    if spec["kind"] == "tree":
        if spec["root"] is None:
            return False
        return tree_contains(spec["root"], spec["height"], addr, flaws)
    found, _ = ring_search(spec["rows"], spec["head"], spec["cap"], addr, flaws)
    return found


def signer_events(plan, variant, content, sig_rel, sig8, addr, who_default=None, flaws=()):
    """Events of 0x57e8bd0 after the set found the address: digest, recover, error drop. -> (ok, events)"""
    digest = digest_of(variant, content)
    ev = [("digest", variant, content.hex()), ("recover", sig_rel, sig8.hex(), digest.hex())]
    kind, who = plan["recover"]
    if kind != "ok":
        if "err_not_dropped" not in flaws:
            ev.append(("err_drop", ERRBOX_REL))
        return False, ev
    if "recover_compare_skipped" in flaws:
        return True, ev
    return who == addr, ev


def spec_front(c, flaws=()):
    plan, block, addr = c["plan"], c["block"], c["addr"]
    out = bytearray([FILL]) * OUT_SIZE
    ev = [("stakes", STATE_REL, block["rounds"][1] if "round_from_b" in flaws else block_round(block))]
    tag, seed = plan["stakes"]
    if tag != OK_TAG:
        out[0:0x48] = record_bytes(tag, seed)
        return OUT_AT, bytes(out), ev
    if not set_contains(c["set"], addr, flaws) and "set_miss_ignored" not in flaws:
        out[0] = 1
        return OUT_AT, bytes(out), ev
    ok, more = signer_events(plan, 0, struct.pack("<Q", BLOCK_REL), BLOCK_REL + 0x130, block["sig"][:8], addr, flaws=flaws)
    ev += more
    if not ok:
        out[0] = 1
        return OUT_AT, bytes(out), ev
    ev.append(("verify", OUT_REL, BLOCK_REL, STATE_REL))
    tag, seed = plan["verify"]
    rec = record_bytes(tag, seed)
    out[0:len(rec)] = rec
    return OUT_AT, bytes(out), ev


def spec_signer(c, flaws=()):
    plan, addr = c["plan"], c["addr"]
    if not set_contains(c["set"], addr, flaws):
        return 0, bytes([FILL]) * OUT_SIZE, []
    variant = c["variant"]
    content = struct.pack("<Q", BLOCK_REL) if variant == 0 else c["box"]
    ok, ev = signer_events(plan, variant, content, c["sigrel"], c["sig8"], addr)
    return int(ok), bytes([FILL]) * OUT_SIZE, ev


def spec_ring(c, flaws=()):
    found, index = ring_search(c["set"]["rows"], c["set"]["head"], c["set"]["cap"], c["addr"], flaws)
    return (0 if found else 1, index), bytes([FILL]) * OUT_SIZE, []


def error_out(out, rec, niche):
    out[0:8] = struct.pack("<Q", niche)
    out[8:8 + 0x48] = rec


def spec_wrap_block(c, flaws=()):
    plan, block, addr = c["plan"], c["block"], c["addr"]
    out = bytearray([FILL]) * OUT_SIZE
    ev = [("stakes", STATE_REL, block_round(block))]
    tag, seed = plan["stakes"]
    stack_garbage = bytes([FILL]) * 0x48
    rec = None
    if tag != OK_TAG:
        rec = record_bytes(tag, seed)
    elif not set_contains(c["set"], addr, flaws):
        rec = bytes([1]) + stack_garbage[1:]
    else:
        ok, more = signer_events(plan, 0, struct.pack("<Q", BLOCK_REL), BLOCK_REL + 0x130, block["sig"][:8], addr, flaws=flaws)
        ev += more
        if not ok:
            rec = bytes([1]) + stack_garbage[1:]
        else:
            ev.append(("verify", "stack", BLOCK_REL, STATE_REL))
            tag, seed = plan["verify"]
            if tag == OK_TAG or "verify_tag_ignored" in flaws:
                ev.append(("copy", OUT_REL, BLOCK_REL, BLOCK_SIZE))
                out[0:BLOCK_SIZE] = block["bytes"]
                return OUT_AT, bytes(out), ev
            rec = record_bytes(tag, seed)
    rec = rec + stack_garbage[len(rec):]
    error_out(out, rec, MINW)
    if block["cap"]:
        ev.append(("free", VEC_REL, block["cap"] if "free_size_not_shifted" in flaws else block["cap"] << 5 & M64, 0))
    if "no_cert_drop" not in flaws:
        ev.append(("drop_cert", BLOCK_REL + 0x18))
    return OUT_AT, bytes(out), ev


def spec_wrap_tv(c, flaws=()):
    plan, tv, addr = c["plan"], c["tv"], c["addr"]
    out = bytearray([FILL]) * OUT_SIZE
    ev = [("stakes", STATE_REL, tv["round"])]
    tag, seed = plan["stakes"]
    stack_garbage = bytes([FILL]) * 0x48
    tag_stakes_ok = tag == OK_TAG
    if tag != OK_TAG:
        rec = record_bytes(tag, seed)
    else:
        if c.get("fail_at") == 1 and "no_alloc_panic" not in flaws:
            ev += [("malloc", 0x38, -1), ("alloc_error", 8, 0x38)]
            return "panic", bytes(out), ev
        box_at = ARENA - HEAP_BASE
        ev.append(("malloc", 0x38, box_at))
        box = struct.pack("<QQQQ", tv["w68"], tv["w70"], tv["w78"], 0 if "box_without_v0" in flaws else tv["v0"]) + tv["addr"] + bytes([FILL]) * 4
        if set_contains(c["set"], tv["addr"], flaws):
            ok, more = signer_events(plan, 2, box, IN_REL + 0x98, tv["sig"][:8], tv["addr"], flaws=flaws)
        else:
            ok, more = False, []
        ev += more
        if not ok:
            rec = bytes([1]) + stack_garbage[1:]
            ev.append(("free", box_at, 0x38, 0))
        elif ((tv["w68"],) if "pair_first_only" in flaws else (tv["w68"], tv["w70"])) != ((tv["s50"],) if "pair_first_only" in flaws else (tv["s50"], tv["s58"])):
            rec = bytes([0]) + stack_garbage[1:8] + struct.pack("<QQQQ", tv["w68"], tv["w70"], tv["s50"], tv["s58"]) + stack_garbage[0x28:]
            ev.append(("free", box_at, 0x38, 0))
        elif tv["v0"] > tv["w78"] if "round_order_strict" in flaws else tv["v0"] >= tv["w78"]:
            rec = bytes([0xA]) + stack_garbage[1:]
            ev.append(("free", box_at, 0x38, 0))
        else:
            ev.append(("qc", "stack", IN_REL))
            tag, seed = plan["qc"]
            rec = record_bytes(tag, seed)
            ev.append(("free", box_at, 0x38, 0))
            if tag == OK_TAG:
                ev.append(("copy", OUT_REL, IN_REL, TV_SIZE))
                out[0:TV_SIZE] = tv["bytes"]
                return OUT_AT, bytes(out), ev
    rec = rec + stack_garbage[len(rec):]
    error_out(out, rec, MINW + 1)
    cap = tv["cap"]
    if cap == MINW:
        root, height, length = tv["root"], tv["height"], tv["length"]
        tail_word = tv["w68"] if tag_stakes_ok else 0xA5A5A5A5A5A5A5A5
        if root == 0:
            first, length, root_w, height_w, unset = 0, 0, None, None, None
        else:
            first, root_w, height_w, unset = 1, HEAP_REL(root), height, 0
        for j in range(length + 1):
            words = (first, unset, root_w, height_w, first, unset, root_w, height_w, length - j, tail_word)
            ev.append(("iter", "stack", "stack", words, length - j))
    elif cap:
        ev.append(("free", VEC_REL, (cap << 5 & M64) * (2 if "tv_free_size_64" in flaws else 3) & M64, 0))
    return OUT_AT, bytes(out), ev


SPECS = {"front": spec_front, "signer": spec_signer, "ring": spec_ring, "wrap_block": spec_wrap_block, "wrap_tv": spec_wrap_tv}
ENTRY = {"front": FRONT, "signer": SIGNER, "ring": RING, "wrap_block": WRAP_BLOCK, "wrap_tv": WRAP_TV}


# ---- cases ----------------------------------------------------------------------------------

TREE_COUNTS = (0, 1, 2, 5, 10, 11, 12, 13, 22, 23, 30, 60, 100, 133, 143, 144, 145, 200, 400, 900, 1500)
RING_SHAPES = ((1, 0, 0), (1, 0, 1), (2, 1, 2), (3, 2, 3), (4, 1, 4), (5, 3, 5), (7, 6, 7), (8, 5, 3), (9, 8, 9), (12, 7, 12),
               (16, 15, 16), (16, 9, 11), (20, 13, 20), (33, 30, 33), (40, 21, 17))
STAKE_TAGS = (0x2E, 0x2E, 0x2E, 0x2E, 0x2E, 0x28, 0x00, 0x2F)
VERIFY_TAGS = (0x2E, 0x2E, 0x0C, 0x0D, 0x29, 0x2A, 0x04, 0x05, 0x0F)
QC_TAGS = (0x2E, 0x2E, 0x02, 0x09, 0x07, 0x08)


def universe(count, stream):
    values = sorted({stream.next(60000) for _ in range(count * 2 + 4)})[:count]
    while len(values) < count:
        values.append(60000 + len(values))
    return [addr_of(v) for v in sorted(values)]


def make_set(kind, stream, shape):
    """-> (set spec, keys list). shape picks the size; a `damage` step breaks the sort order on some cases."""
    if kind == "none":
        return {"kind": "none"}, []
    if kind == "tree":
        count = TREE_COUNTS[shape % len(TREE_COUNTS)]
        keys = universe(count, stream)
        damage = stream.next(9) == 0 and count > 3
        walk = list(keys)
        if damage:
            i, j = stream.next(count), stream.next(count)
            walk[i], walk[j] = walk[j], walk[i]
        height = tree_height_for(count)
        root = build_tree(walk, height, stream) if count else None
        return {"kind": "tree", "root": root, "height": height, "count": count, "damage": damage}, keys
    cap, head, length = RING_SHAPES[shape % len(RING_SHAPES)]
    keys = universe(length, stream)
    walk = list(keys)
    damage = stream.next(8) == 0 and length > 2
    if damage:
        i, j = stream.next(length), stream.next(length)
        walk[i], walk[j] = walk[j], walk[i]
    rows = [key + Stream(len(key) + i).bytes(12) for i, key in enumerate(walk)]
    return {"kind": "ring", "cap": cap, "head": head, "rows": rows, "damage": damage}, keys


def pick_addr(stream, keys):
    """present at the front, middle or back; or absent below, between, above."""
    mode = stream.next(6) if keys else 3 + stream.next(3)
    if mode == 0:
        return keys[0]
    if mode == 1:
        return keys[stream.next(len(keys))]
    if mode == 2:
        return keys[-1]
    if mode == 3:
        return addr_of(0) if not keys or keys[0] != addr_of(0) else bytes(KEY)
    if mode == 4:
        base = keys[stream.next(len(keys))] if keys else addr_of(7)
        return base[:KEY - 1] + bytes([(base[-1] + 1) & 0xFF])
    return bytes([0xFF]) * KEY


def make_plan(stream, flavour):
    stakes = (STAKE_TAGS[stream.next(len(STAKE_TAGS))], stream.next(1 << 30))
    verify = (VERIFY_TAGS[stream.next(len(VERIFY_TAGS))], stream.next(1 << 30))
    qc = (QC_TAGS[stream.next(len(QC_TAGS))], stream.next(1 << 30))
    return {"stakes": stakes, "verify": verify, "qc": qc}


def make_recover(stream, addr):
    mode = stream.next(8)
    if mode == 0:
        return ("err", None)
    if mode == 1:
        wrong = bytearray(addr)
        wrong[stream.next(KEY)] ^= 1 << stream.next(8)
        return ("ok", bytes(wrong))
    return ("ok", addr)


def make_block(stream):
    a = SENT if stream.next(3) else 0x1000 + stream.next(1 << 20)
    b = SENT if stream.next(2) else 0x2000 + stream.next(1 << 20)
    rounds = tuple(stream.next(1 << 40) for _ in range(3))
    cap = (0, 1, 3, 100, 1 << 40, SENT, MINW + 5)[stream.next(7)] if True else 0
    return {"a": a, "b": b, "rounds": rounds, "cap": cap, "sig": stream.bytes(0x41), "bytes": None}


def block_bytes(block, addr, seed):
    raw = bytearray(Stream(seed + 99).bytes(BLOCK_SIZE))
    struct.pack_into("<QQQ", raw, 0, block["cap"], VEC_AT, 3)
    struct.pack_into("<QQ", raw, 0x18, block["a"], 0)
    struct.pack_into("<Q", raw, 0xA8, block["b"])
    rx, ry, rz = block["rounds"]
    struct.pack_into("<Q", raw, 0x60, rx)
    struct.pack_into("<Q", raw, 0x58, ry)
    struct.pack_into("<Q", raw, 0xE8, rz)
    raw[0x11C:0x130] = addr
    raw[0x130:0x130 + 0x41] = block["sig"]
    return bytes(raw[:BLOCK_SIZE])


def make_case(entry, index):
    stream = Stream(index * 8 + {"front": 1, "signer": 2, "ring": 3, "wrap_block": 4, "wrap_tv": 5}[entry])
    c = {"entry": entry, "index": index, "seed": stream.next(1 << 30)}
    kind = ("tree", "tree", "ring", "ring", "none")[stream.next(5)] if entry != "ring" else "ring"
    if entry in ("front", "wrap_block", "wrap_tv", "signer") and stream.next(37) == 0:
        kind = "tree"
    c["set"], keys = make_set(kind, stream, stream.next(64))
    c["addr"] = pick_addr(stream, keys)
    c["plan"] = make_plan(stream, entry)
    c["plan"]["recover"] = make_recover(stream, c["addr"])
    if entry in ("front", "wrap_block"):
        block = make_block(stream)
        block["bytes"] = block_bytes(block, c["addr"], c["seed"])
        c["block"] = block
    elif entry == "signer":
        c["variant"] = (0, 2)[stream.next(2)]
        c["box"] = Stream(c["seed"] + 5).bytes(0x38)
        c["sig8"] = Stream(c["seed"] + 6).bytes(8)
        c["sigrel"] = HEAP_REL(SIG_AT)
    elif entry == "wrap_tv":
        w68, w70 = stream.next(1 << 50), stream.next(1 << 50)
        mismatch = stream.next(4)
        s50, s58 = w68, w70
        if mismatch == 1:
            s50 ^= 1 << stream.next(40)
        elif mismatch == 2:
            s58 ^= 1 << stream.next(40)
        w78 = (0, 1, 1 << 40, M64, 77)[stream.next(5)] if stream.next(2) else stream.next(1 << 40)
        order = stream.next(5)
        v0 = (w78 - 1) & M64 if order < 2 else w78 if order == 2 else (w78 + 1) & M64 if order == 3 else stream.next(1 << 40)
        cap = (0, 1, 2, 9, 1 << 58, SENT, M64)[stream.next(7)]
        shape = stream.next(6)
        if shape == 0:
            cap = MINW
        root = 0 if stream.next(4) == 0 else FIX_AT + 0x2000
        tv = {"round": stream.next(1 << 40), "w68": w68, "w70": w70, "w78": w78, "v0": v0, "s50": s50, "s58": s58,
              "addr": c["addr"], "x90": Stream(c["seed"] + 8).bytes(4), "sig": Stream(c["seed"] + 9).bytes(0x41),
              "cap": cap, "root": root, "height": stream.next(4), "length": stream.next(4)}
        raw = bytearray(Stream(c["seed"] + 10).bytes(TV_SIZE))
        struct.pack_into("<QQQQ", raw, 0, cap, VEC_AT, 3, tv["length"])
        struct.pack_into("<Q", raw, 0x30, v0)
        struct.pack_into("<Q", raw, 0x40, tv["round"])
        struct.pack_into("<QQQ", raw, 0x68, w68, w70, w78)
        raw[0x80:0x94] = c["addr"]
        raw[0x98:0x98 + 0x41 - 0x1B] = tv["sig"][:0x41 - 0x1B]
        if cap == MINW:
            struct.pack_into("<QQQ", raw, 0, MINW, root, tv["height"])
            struct.pack_into("<Q", raw, 0x18, tv["length"])
        tv["bytes"] = bytes(raw)
        tv["sigfull"] = bytes(raw[0x98:0xA0])
        tv["sig"] = bytes(raw[0x98:0xA0])
        c["tv"] = tv
        c["state_pair"] = (s50, s58)
        if stream.next(23) == 0:
            c["fail_at"] = 1
    return c


COUNTS = {"front": 3200, "signer": 2400, "ring": 2400, "wrap_block": 3200, "wrap_tv": 3200}


def all_cases():
    for entry, count in COUNTS.items():
        for index in range(count):
            yield make_case(entry, index)


# ---- one run: write the fixture, run the bytes, read what they left -------------------------

def prepare(run, c):
    run.reset()
    run.plan = c["plan"]
    run.fail_at = c.get("fail_at")
    memory, entry = run.memory, c["entry"]
    memory.put_bytes(OUT_ADDR_FILL[0], bytes([FILL]) * OUT_SIZE)
    memory.put_bytes(STATE_AT, Stream(c["seed"] + 7).bytes(0x100))
    memory.write(ERRBOX_AT, 8, VT_AT)
    memory.write(VT_AT, 8, run.err_drop)
    spec = c["set"]
    if spec["kind"] != "none":
        run.place_set(spec)
    else:
        memory.put_bytes(SETOBJ_AT, struct.pack("<QQQQ", 4, 0, 0, 0))
    machine = run.machine
    if entry in ("front", "wrap_block"):
        memory.put_bytes(BLOCK_AT, c["block"]["bytes"])
        args = {RDI: OUT_AT, RSI: BLOCK_AT, RDX: STATE_AT}
    elif entry == "wrap_tv":
        tv = c["tv"]
        memory.put_bytes(IN_AT, tv["bytes"])
        memory.write(STATE_AT + 0x50, 8, tv["s50"])
        memory.write(STATE_AT + 0x58, 8, tv["s58"])
        args = {RDI: OUT_AT, RSI: IN_AT, RDX: STATE_AT}
    elif entry == "signer":
        memory.put_bytes(ADDR_AT, c["addr"])
        memory.put_bytes(SIG_AT, c["sig8"])
        memory.put_bytes(BOX_AT, c["box"])
        ptr = BLOCK_AT if c["variant"] == 0 else BOX_AT
        memory.write(MSG_AT, 8, c["variant"])
        memory.write(MSG_AT + 8, 8, ptr)
        args = {RDI: MSG_AT, RSI: ADDR_AT, RDX: SIG_AT, RCX: SETOBJ_AT}
    else:
        memory.put_bytes(ADDR_AT, c["addr"])
        args = {RDI: SETOBJ_AT, RSI: ADDR_AT}
    return args


OUT_ADDR_FILL = (OUT_AT,)


def execute(run, c, after_prepare=None, flaws=()):
    """-> (observed, predicted): (return, out bytes, log) of the bytes against the rule list."""
    args = prepare(run, c)
    if after_prepare is not None:
        after_prepare(run)
    entry = c["entry"]
    machine = run.machine
    try:
        ret = machine.run(ENTRY[entry], args)
    except Panicked:
        ret = "panic"
    out = bytes(run.memory.bytes_at(OUT_AT, OUT_SIZE))
    if entry == "signer":
        ret = ret & 0xFF if ret != "panic" else ret
    elif entry == "ring":
        ret = (machine.regs[RAX] & M64, machine.regs[RDX] & M64) if ret != "panic" else ret
    spec = SPECS[entry]
    want_ret, want_out, want_log = spec(c, flaws)
    if entry == "ring":
        want_ret = (want_ret[0], want_ret[1])
    log = list(run.log)
    for k, (a, b) in enumerate(zip(log, want_log)):
        if a[0] == "iter" and b[0] == "iter" and None in b[3]:
            log[k] = a[:3] + (tuple(None if w is None else v for v, w in zip(a[3], b[3])),) + a[4:]
    got = (ret, out, tuple(log))
    want = (want_ret, want_out, tuple(want_log))
    return got, want


# ---- rows the rule list is pinned to ---------------------------------------------------------

SCOPE = {
    FRONT: ("block_signer_front_end", "real", "stake set for the block round, signer search, digest, recovery, then the block rules"),
    SIGNER: ("signer_in_set_and_recovered", "real", "slot 0x64e64b8: set search, digest, recovery, address compare"),
    RING: ("stake_ring_binary_search", "real", "VecDeque of 32 byte rows: back slice first, size halving search"),
    WRAP_BLOCK: ("signed_block_validate_and_move", "real", "stake set, signer, block rules, move or error plus drops"),
    WRAP_TV: ("timeout_message_validate_and_move", "real", "stake set, box, signer, pair, round order, certificate, move or error plus drops"),
}
CONTRACTS = (
    (SLOT_STAKES, "slot 0x64e64b0 -> 0x595e5c0", "stake set for a round: tag 0x2e plus set pointer at +8, or a seeded 0x48 byte error record"),
    (SLOT_VERIFY, "slot 0x64e64c0 -> 0x59d6b80", "block rules: tag 0x2e writes only byte 0, any other tag a seeded 0x48 byte record"),
    (SLOT_RECOVER, "GOT 0x64e0ad8", "signature recovery: tag 0 plus a planned 20 byte address, or tag 1 plus a boxed error"),
    (DIGEST, "direct call", "signing digest: SHA-256 of the variant word and the message content, written as 32 bytes"),
    (QC_WRAP, "direct call", "nested certificate wrapper 0x595fd20: seeded record, 0x2e or another tag"),
    (DROP_CERT, "direct call", "drop of the block certificates, recorded"),
    (ITER_NEXT, "direct call", "B-tree into-iter step: writes 1 while the length word at +0x40 is non-zero and decrements it"),
    (GOT_MALLOC, "GOT", "bump allocator with 0xa5 fill, optional failure of the first call"),
    (GOT_ALLOC_ERR, "GOT", "allocation error handler: records and stops"),
    (GOT_FREE, "GOT", "sized free: records pointer, size, flags"),
    (GOT_MEMCPY, "GOT", "memcpy: records and copies"),
    (GOT_MEMCMP, "GOT", "memcmp: first differing byte difference"),
) + tuple((slot, "GOT", "panic entry: stops the run") for slot in GOT_PANICS)

# (function, site, kind, expected, rule): kind call = e8 target, slot = indirect call through that GOT slot, imm = mov/cmp immediate
RULES = (
    (FRONT, 0x57E898A, "imm", SENT, "tag sentinel 0x8000000000000001 picks the certificate that carries the round"),
    (FRONT, 0x57E89C2, "slot", SLOT_STAKES, "stake set for the round, called first"),
    (FRONT, 0x57E8A1D, "op", "dec", "set word 0 against 0x8000000000000000 (sentinel minus one): tree, else ring"),
    (FRONT, 0x57E8A83, "op", "calli", "tree walk: memcmp of 20 byte keys"),
    (FRONT, 0x57E8B28, "call", RING, "ring set: binary search 0x57f54e0"),
    (FRONT, 0x57E8B46, "call", DIGEST, "signing digest of variant 0"),
    (FRONT, 0x57E8B56, "slot", SLOT_RECOVER, "signature recovery over that digest"),
    (FRONT, 0x57E8B6B, "op", "calli", "recovery error box dropped through its vtable"),
    (FRONT, 0x57E8BBD, "slot", SLOT_VERIFY, "block rules run last"),
    (SIGNER, 0x57E8C51, "op", "calli", "tree walk: memcmp"),
    (SIGNER, 0x57E8CAD, "call", RING, "ring set: binary search"),
    (SIGNER, 0x57E8CC4, "call", DIGEST, "signing digest"),
    (SIGNER, 0x57E8CD6, "slot", SLOT_RECOVER, "signature recovery"),
    (SIGNER, 0x57E8CEB, "op", "calli", "recovery error box dropped"),
    (WRAP_BLOCK, 0x27868C1, "slot", SLOT_STAKES, "stake set for the round"),
    (WRAP_BLOCK, 0x27868F6, "slot", SLOT_SIGNER, "signer check slot 0x64e64b8"),
    (WRAP_BLOCK, 0x2786909, "slot", SLOT_VERIFY, "block rules"),
    (WRAP_BLOCK, 0x2786915, "imm", BLOCK_SIZE, "success moves 0x178 bytes of block"),
    (WRAP_BLOCK, 0x27869DE, "slot", GOT_FREE, "error path frees the hash vector, 32 bytes a row"),
    (WRAP_BLOCK, 0x27869E7, "call", DROP_CERT, "error path drops the certificates"),
    (WRAP_TV, 0x2786A46, "slot", SLOT_STAKES, "stake set for the round"),
    (WRAP_TV, 0x2786A86, "imm", 0x38, "message box of 0x38 bytes"),
    (WRAP_TV, 0x2786B04, "slot", SLOT_SIGNER, "signer check slot 0x64e64b8 with variant 2"),
    (WRAP_TV, 0x2786B56, "call", QC_WRAP, "nested certificate wrapper, last"),
    (WRAP_TV, 0x2786B79, "imm", TV_SIZE, "success moves 0xe0 bytes of message"),
    (WRAP_TV, 0x2786CF6, "call", ITER_NEXT, "tree-held vector dropped by stepping its into-iter"),
    (WRAP_TV, 0x2786D21, "slot", GOT_ALLOC_ERR, "box allocation failure goes to the allocation error handler"),
)


def check_rule(image, rule):
    function, site, kind, expected, _ = rule
    low, high = image.exact_fde(function)
    if not low <= site < high:
        raise EvidenceError("site outside the function: %#x" % site)
    rows = {row.va: row for row in decode_range(image, low, high)}
    row = rows.get(site)
    if row is None:
        raise EvidenceError("site is not an instruction start: %#x" % site)
    if kind == "call":
        ok = row.op == "call" and row.target == expected
    elif kind == "slot":
        ok = row.op == "calli" and row.a[0] == "m" and row.a[1] is None and row.a[4] == expected
    elif kind == "imm":
        ok = row.b is not None and row.b[0] == "i" and row.b[1] & MASK[8] == expected
    else:
        ok = row.op == expected
    if not ok:
        raise EvidenceError("row at %#x does not match the rule" % site)
    return row


# ---- classification, controls, analysis ----------------------------------------------------

def classify(c, got):
    ret, out, log = got
    names = [e[0] for e in log]
    entry = c["entry"]
    if entry == "ring":
        wrapped = c["set"]["head"] + len(c["set"]["rows"]) > c["set"]["cap"]
        return ("found" if ret[0] == 0 else "absent") + ("_wrapped" if wrapped else "_straight")
    if entry == "signer":
        if "digest" not in names:
            return "set_miss"
        if "err_drop" in names:
            return "recover_error"
        return "match" if ret == 1 else "other_address"
    if ret == "panic":
        return "alloc_failure"
    stakes_ok = c["plan"]["stakes"][0] == OK_TAG
    if not stakes_ok:
        return "stakes_error"
    if "digest" not in names:
        return "signer_not_in_set"
    if "err_drop" in names:
        return "recover_error"
    if entry == "wrap_tv":
        tv = c["tv"]
        if (tv["w68"], tv["w70"]) != (tv["s50"], tv["s58"]):
            if "qc" not in names and out[8] == 0 and ret != "panic" and "free" in names:
                return "pair_mismatch"
        if out[8] == 0x0A and out[0:8] == struct.pack("<Q", MINW + 1):
            return "round_order"
        if "qc" in names:
            return "admitted" if out[0:8] != struct.pack("<Q", MINW + 1) else "qc_error"
        if out[0:8] == struct.pack("<Q", MINW + 1) and out[8] == 1:
            return "other_address"
        return "pair_mismatch"
    if "verify" not in names:
        return "other_address"
    if entry == "front":
        return "admitted" if out[0] == OK_TAG else "verify_error"
    return "admitted" if out[0:8] != struct.pack("<Q", MINW) else "verify_error"


def digest_of_obs(obs):
    return hashlib.sha256(repr(obs).encode()).digest()[:10]


STATE = {}
WORKERS = 4
MUTANT_CASES = 48
FAILURES = (Halt, EvidenceError, Panicked, KeyError, IndexError, ValueError, OverflowError, struct.error, TypeError, AttributeError)
USES = {FRONT: ("front",), SIGNER: ("signer", "front", "wrap_block", "wrap_tv"), RING: ("ring", "front", "signer"),
        WRAP_BLOCK: ("wrap_block",), WRAP_TV: ("wrap_tv",)}


def edits_for(image, rows):
    edits = []
    for row in rows:
        data = bytes(image.blob[image.offset(row.va):image.offset(row.va) + row.size])
        if row.op == "jcc":
            at = row.size - 5 if row.size >= 6 else 0
            edits.append((row.va, "condition", {row.va + at: data[at] ^ 1}))
        elif row.op in ("cmov", "set"):
            at = next(i for i in range(row.size) if data[i] == 0x0F) + 1
            edits.append((row.va, "condition", {row.va + at: data[at] ^ 1}))
        elif row.imm_at is not None and row.op not in ("call", "jmp"):
            edits.append((row.va, "immediate", {row.va + row.imm_at: data[row.imm_at] ^ 1}))
    return edits


def mutant_task(job):
    function, va, kind, patch = job
    state = STATE
    run = Run(state["image"], patch, state["cache"])
    run.machine.step_limit = 90000
    for c in state["picked"][function]:
        try:
            got, want = execute(run, c)
        except FAILURES:
            return function, va, kind, "killed", "%s:%d" % (c["entry"], c["index"])
        if got != want:
            return function, va, kind, "killed", "%s:%d" % (c["entry"], c["index"])
    return function, va, kind, "survived", "equal on %d picked cases" % len(state["picked"][function])


FLAWS = (
    ("tree_reverse", ("front", "signer", "wrap_block", "wrap_tv")), ("tree_first_key_only", ("front", "signer", "wrap_block")),
    ("ring_ge_moves", ("ring", "front", "signer")), ("round_from_b", ("front",)), ("set_miss_ignored", ("front",)),
    ("err_not_dropped", ("front", "signer", "wrap_block", "wrap_tv")), ("recover_compare_skipped", ("front", "signer", "wrap_block", "wrap_tv")),
    ("verify_tag_ignored", ("wrap_block",)), ("free_size_not_shifted", ("wrap_block",)), ("no_cert_drop", ("wrap_block",)),
    ("no_alloc_panic", ("wrap_tv",)), ("box_without_v0", ("wrap_tv",)), ("pair_first_only", ("wrap_tv",)),
    ("round_order_strict", ("wrap_tv",)), ("tv_free_size_64", ("wrap_tv",)),
)


def flaw_task(job):
    flaw, entries = job
    for entry in entries:
        digests = STATE["digests"][entry]
        for index in range(COUNTS[entry]):
            c = make_case(entry, index)
            want = SPECS[entry](c, (flaw,))
            ret, out, log = want
            if "tv" in c and "iter" in [e[0] for e in log]:
                continue
            if digest_of_obs((ret, out, tuple(log))) != digests[index]:
                return flaw, True, "%s:%d" % (entry, index)
    return flaw, False, ""


def poke(address, mask=1):
    def action(run):
        run.memory.write(address, 1, run.memory.read(address, 1) ^ mask)
    return action


CORRUPTIONS = (
    ("front", "address byte in the block", lambda c: poke(BLOCK_AT + 0x11C), ("admitted", "verify_error", "recover_error", "other_address")),
    ("front", "signature byte in the block", lambda c: poke(BLOCK_AT + 0x130), ("admitted", "verify_error", "recover_error", "other_address")),
    ("wrap_block", "address byte in the block", lambda c: poke(BLOCK_AT + 0x11C), ("admitted", "verify_error", "recover_error", "other_address")),
    ("wrap_block", "signature byte in the block", lambda c: poke(BLOCK_AT + 0x130), ("admitted", "verify_error", "recover_error", "other_address")),
    ("wrap_tv", "address byte in the message", lambda c: poke(IN_AT + 0x80), ("admitted", "qc_error", "round_order", "pair_mismatch", "other_address", "recover_error")),
    ("wrap_tv", "state pair word", lambda c: poke(STATE_AT + 0x50), ("admitted", "qc_error", "round_order", "pair_mismatch")),
    ("wrap_tv", "round word of the message", lambda c: poke(IN_AT + 0x40), ("admitted", "qc_error", "round_order", "pair_mismatch")),
    ("signer", "address byte", lambda c: poke(ADDR_AT), ("match", "other_address", "recover_error")),
    ("ring", "key byte", lambda c: poke(ADDR_AT), ("found_wrapped", "found_straight")),
)
CORRUPT_PER_KIND = 6


def corrupt_task(job):
    entry, label, index, which = job
    c = make_case(entry, index)
    run = STATE["corrupt_run"]
    action = CORRUPTIONS[which][2](c)
    try:
        got, want = execute(run, c, after_prepare=action)
    except FAILURES:
        return entry, label, index, True
    return entry, label, index, got != want


def range_controls(image):
    rows = []

    def attempt(name, action):
        try:
            action()
        except (EvidenceError, Halt, Panicked, IndexError, KeyError, ValueError, struct.error):
            rows.append((name, True))
        else:
            rows.append((name, False))
    attempt("digest of the wrong file", lambda: load_image(BINARY, "0" * 64))
    attempt("address inside a function, not an FDE start", lambda: image.exact_fde(FRONT + 1))
    attempt("address outside every FDE", lambda: image.fde(0x100))
    attempt("address outside every file-backed section", lambda: image.offset(0x10))
    for rule in RULES:
        function, site, kind, expected, text = rule
        attempt("rule %#x moved one byte" % site, lambda rule=rule: check_rule(image, (rule[0], rule[1] + 1) + rule[2:]))
        wrong = expected ^ 2 if isinstance(expected, int) else "mov"
        attempt("rule %#x with another expectation" % site, lambda rule=rule, wrong=wrong: check_rule(image, rule[:3] + (wrong,) + rule[4:]))
    return rows


SAMPLE_EVERY = 5

FIELD_NAMES = {
    FRONT: {0x00: "block hash vector capacity/pointer", 0x18: "certificate tag word", 0x20: "certificate at +0x20", 0x40: "round word inside a certificate",
            0xA8: "second certificate tag word", 0x10: "set word (len / height)", 0x11C: "signer address, 20 bytes", 0x130: "signature",
            0x08: "set pointer / tree root", 0x60: "tree node key area", 0x13E: "tree node key count", 0x140: "tree node edges", 0x48: "stake record words"},
    SIGNER: {0x08: "set pointer / tree root", 0x10: "set word (len / height)", 0x60: "tree node key area", 0x13E: "tree node key count", 0x140: "tree node edges"},
    RING: {0x00: "ring capacity", 0x08: "ring buffer", 0x10: "ring head", 0x18: "ring length"},
    WRAP_BLOCK: {0x00: "block hash vector capacity", 0x08: "block hash vector pointer", 0x18: "certificate tag word", 0x20: "certificate at +0x20",
                 0x40: "round word inside a certificate", 0xA8: "second certificate tag word", 0x11C: "signer address, 20 bytes", 0x130: "signature"},
    WRAP_TV: {0x00: "vector capacity or tree niche", 0x08: "vector pointer or tree root", 0x10: "tree height", 0x18: "tree length", 0x30: "round bound word",
              0x40: "round of the stake set", 0x50: "state pair word", 0x58: "state pair word", 0x68: "pair word", 0x70: "pair word", 0x78: "round limit word",
              0x80: "signer address, 20 bytes", 0x90: "address tail", 0x98: "signature", 0xA8: "stake set pointer saved"},
}


def function_rows(image, reached):
    table = {}
    for target in sorted(SCOPE):
        low, high = image.exact_fde(target)
        rows = decode_range(image, low, high)
        table[target] = (low, high, rows, [row for row in rows if row.va in reached])
    return table


def analyse(image, workers=WORKERS):
    run = Run(image)
    digests = {entry: [] for entry in COUNTS}
    classes = {entry: [] for entry in COUNTS}
    tally = collections.Counter()
    sample, mismatches, total, steps = [], [], 0, 0
    for c in all_cases():
        got, want = execute(run, c)
        entry, index = c["entry"], c["index"]
        total += 1
        steps = run.machine.steps
        if got != want:
            mismatches.append((entry, index))
        label = classify(c, got)
        tally[(entry, label)] += 1
        digests[entry].append(digest_of_obs(want))
        classes[entry].append((index, label))
        if index % SAMPLE_EVERY == 0:
            setspec = c["set"]
            size = setspec.get("count", len(setspec.get("rows", ())))
            ret = got[0] if not isinstance(got[0], tuple) else "%d/%d" % got[0]
            sample.append((entry, index, label, setspec["kind"], size, "damaged" if setspec.get("damage") else "sorted",
                           ret, hashlib.sha256(got[1]).hexdigest()[:12], len(got[2])))
    reached = set(run.machine.seen)
    STATE.clear()
    STATE.update(image=image, cache=dict(run.machine.cache), digests=digests, corrupt_run=Run(image, None, run.machine.cache))
    functions = function_rows(image, reached)
    # byte mutants of the real rows, each against up to MUTANT_CASES cases that use the function
    picked = {}
    for function in sorted(SCOPE):
        groups = collections.defaultdict(list)
        for entry in USES[function]:
            for index, label in classes[entry]:
                groups[(entry, label)].append((entry, index))
        queues = [groups[key] for key in sorted(groups)]
        # spread inside each group so rare shapes are not only the early indices
        queues = [q[::max(1, len(q) // 6)] for q in queues]
        chosen = []
        while queues and len(chosen) < MUTANT_CASES:
            for queue in list(queues):
                chosen.append(queue.pop(0))
                if not queue:
                    queues.remove(queue)
                if len(chosen) == MUTANT_CASES:
                    break
        picked[function] = [make_case(entry, index) for entry, index in chosen]
    STATE["picked"] = picked
    jobs = []
    for function in sorted(SCOPE):
        low, high, rows, _ = functions[function]
        for va, kind, patch in edits_for(image, [row for row in rows if row.va in reached]):
            jobs.append((function, va, kind, patch))
    corrupt_jobs = []
    for which, (entry, label, _, allowed) in enumerate(CORRUPTIONS):
        pool = [index for index, name in classes[entry] if name in allowed]
        stride = max(1, len(pool) // CORRUPT_PER_KIND)
        for index in pool[::stride][:CORRUPT_PER_KIND]:
            corrupt_jobs.append((entry, label, index, which))
    context = multiprocessing.get_context("fork")
    with context.Pool(workers) as pool:
        mutants = sorted(pool.map(mutant_task, jobs, chunksize=4))
        flaws = sorted(pool.map(flaw_task, FLAWS))
        corrupt = sorted(pool.map(corrupt_task, corrupt_jobs))
    ranges = range_controls(image)
    pins = [(rule, check_rule(image, rule)) for rule in RULES]
    return dict(total=total, tally=tally, sample=sample, mismatches=mismatches, reached=reached, functions=functions, mutants=mutants,
                flaws=flaws, corrupt=corrupt, ranges=ranges, pins=pins, steps=steps)


def scan_callers(image):
    """Every e8 / e9 rel32 to one of the five scope functions and every ff 15 rip call through a scope slot, with the containing FDE."""
    base, text = image.text_bytes()
    direct = {FRONT, SIGNER, RING, WRAP_BLOCK, WRAP_TV}
    slots = {SLOT_STAKES: "stake set", SLOT_SIGNER: "signer check", SLOT_VERIFY: "block rules", SLOT_RECOVER: "recovery"}
    rows = []
    for match in re.finditer(rb"[\xe8\xe9]", text):
        at = match.start()
        if at + 5 > len(text):
            continue
        target = base + at + 5 + struct.unpack_from("<i", text, at + 1)[0]
        if target in direct:
            rows.append(("direct", base + at, "call" if text[at] == 0xE8 else "jmp", hex(target)))
    for match in re.finditer(rb"\xff\x15", text):
        at = match.start()
        if at + 6 > len(text):
            continue
        slot = base + at + 6 + struct.unpack_from("<i", text, at + 2)[0]
        if slot in slots:
            rows.append(("slot", base + at, slots[slot], hex(slot)))
    out = []
    for kind, site, what, target in sorted(rows):
        try:
            low, high = image.fde(site)
            home = "%#x..%#x" % (low, high)
        except EvidenceError:
            home = "none"
        out.append((kind, hex(site), what, target, home))
    return out


def tsv(header, rows):
    return "\n".join(["\t".join(header)] + ["\t".join(str(x) for x in row) for row in rows]) + "\n"


def render(result, image):
    files = {}
    files["outcomes.tsv"] = tsv(("entry", "class", "cases"), [(e, k, n) for (e, k), n in sorted(result["tally"].items())])
    rows = []
    for target in sorted(SCOPE):
        low, high, all_rows, hit = result["functions"][target]
        rows.append((hex(target), hex(high), high - low, len(all_rows), len(hit), SCOPE[target][0], SCOPE[target][2]))
    files["functions.tsv"] = tsv(("function", "end", "bytes", "instructions", "reached_instructions", "name", "role"), rows)
    files["stubs.tsv"] = tsv(("target", "kind", "contract"), [(hex(a), b, c) for a, b, c in CONTRACTS])
    files["gates.tsv"] = tsv(("function", "site", "kind", "expected", "rule"),
                             [(hex(r[0]), hex(r[1]), r[2], hex(r[3]) if isinstance(r[3], int) else r[3], r[4]) for r, _ in result["pins"]])
    rows = []
    for target in sorted(SCOPE):
        counts = collections.Counter()
        for row in result["functions"][target][2]:
            for operand in (row.a, row.b):
                if operand and operand[0] == "m" and operand[1] not in (None, RSP) and operand[4] < 0x400:
                    counts[operand[4]] += 1
        for disp in sorted(counts):
            rows.append((hex(target), hex(disp), counts[disp], FIELD_NAMES.get(target, {}).get(disp, "")))
    files["layouts.tsv"] = tsv(("function", "displacement", "rows", "name"), rows)
    files["callers.tsv"] = tsv(("kind", "site", "what", "target", "containing_fde"), scan_callers(image))
    relative = image.relative()
    slot_rows = []
    for slot in (SLOT_STAKES, SLOT_SIGNER, SLOT_VERIFY):
        low, high = image.fde(relative[slot])
        slot_rows.append((hex(slot), "R_X86_64_RELATIVE", hex(relative[slot]), "%#x..%#x" % (low, high), high - low))
    files["slots.tsv"] = tsv(("slot", "relocation", "target", "fde", "bytes"), slot_rows)
    files["cases.tsv"] = tsv(("entry", "index", "class", "set", "size", "order", "return", "out_sha256_12", "events"), result["sample"])
    files["mutations.tsv"] = tsv(("function", "row", "kind", "result", "witness"), [(hex(f), hex(v), k, r, w) for f, v, k, r, w in result["mutants"]])
    files["flaws.tsv"] = tsv(("flaw", "detected", "first_case"), [(f, "yes" if d else "NO", w) for f, d, w in result["flaws"]])
    controls = [(name, "yes" if ok else "NO") for name, ok in result["ranges"]]
    controls += [("%s: %s, case %d" % (entry, label, index), "yes" if ok else "NO") for entry, label, index, ok in result["corrupt"]]
    files["controls.tsv"] = tsv(("control", "detected"), controls)
    killed = sum(1 for m in result["mutants"] if m[3] == "killed")
    detected = sum(1 for _, d, _ in result["flaws"] if d) + killed + sum(1 for r in result["corrupt"] if r[3]) + sum(1 for _, ok in result["ranges"] if ok)
    negatives = len(result["flaws"]) + killed + len(result["corrupt"]) + len(result["ranges"])
    reached_rows = sum(len(result["functions"][t][3]) for t in SCOPE)
    all_rows = sum(len(result["functions"][t][2]) for t in SCOPE)
    metrics = {"cases": result["total"], "mismatches": len(result["mismatches"]), "negative_controls": negatives, "negative_detected": detected,
               "mutants_run": len(result["mutants"]), "mutants_killed": killed, "mutants_survived": len(result["mutants"]) - killed,
               "instructions": all_rows, "instructions_reached": reached_rows, "flaws": len(result["flaws"]),
               "corruptions": len(result["corrupt"]), "range_controls": len(result["ranges"]), "rules": len(result["pins"])}
    files["measure.json"] = json.dumps({k: metrics[k] for k in ("cases", "negative_controls", "negative_detected")} | {"mismatches": metrics["mismatches"]},
                                       indent=1, sort_keys=True) + "\n"
    files["evidence.json"] = json.dumps({"binary_sha256": SHA256, "metrics": metrics}, indent=1, sort_keys=True) + "\n"
    return files, metrics


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("--out", required=True)
    args = parser.parse_args(argv)
    image = load_image()
    result = analyse(image)
    files, metrics = render(result, image)
    out = pathlib.Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    for name, text in sorted(files.items()):
        (out / name).write_text(text)
    print(json.dumps(metrics, sort_keys=True))
    return 0 if metrics["mismatches"] == 0 and metrics["negative_detected"] == metrics["negative_controls"] else 1


if __name__ == "__main__":
    sys.exit(main())
