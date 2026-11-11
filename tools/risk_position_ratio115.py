#!/usr/bin/env python3
"""Reconstruct the node #115 clearinghouse position ratio: one body with its two real container searches, run from the ELF bytes against a written rule list.

0x446b840 looks a position up by asset key in a ring buffer or a B-tree, checks its side against a flag, indexes a margin row table by key modulo 10000,
multiplies the row field by the position size, asks a helper for a margin figure (or adds a stored one with saturation), and returns two floored f64
ratios multiplied together. The real bytes of the body, the ring search 0x455cb20 and the B-tree search 0x35be560 run in a small x86-64 evaluator with
the opaque helper slots as recording stubs; a separately written rule list predicts every result, panic and helper request, and every reached conditional,
immediate and field offset of the three bodies is edited. No objdump or readelf output is parsed and the binary is never executed. Standard library only.

    python3 tools/risk_position_ratio115.py --out <dir>
"""


import argparse
import bisect
import collections
import fractions
import hashlib
import itertools
import json
import math
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
STACK_SIZE = 0x8000
HEAP_BASE = 0x600000000
HEAP_SIZE = 0x20000
RETURN_SENTINEL = 0xDEAD0000
POISON = 0xA5A5A5A5A5A5A5A5
STEP_LIMIT = 200000
MUTANT_STEP_LIMIT = 20000


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
        if rela["size"] % 24:
            raise EvidenceError("truncated RELA section")
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
SHIFTS = {1: "ror", 4: "shl", 5: "shr", 7: "sar"}


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
            for operand in (a, b):
                if operand and operand[0] == "r" and 4 <= operand[1] <= 7:
                    raise EvidenceError("high byte register at %#x" % va)

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
    if byte == 0x98 and wide:
        return finish("cdqe")
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
        if kind in (2, 3, 4, 6):
            return finish({2: "not", 3: "neg", 4: "mul", 6: "div"}[kind], rm, w=w)
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
        if two == 0x73 and opsize:
            reg, rm = modrm(True)
            if reg & 7 != 2:
                raise EvidenceError("unsupported vector shift at %#x" % va)
            value = immediate(1) & 0xFF
            return finish("psrlq", rm, ("i", value), 16)
        if two == 0xBA:
            reg, rm = modrm()
            if reg & 7 != 4:
                raise EvidenceError("unsupported bit test at %#x" % va)
            value = immediate(1) & 0xFF
            return finish("bt", rm, ("i", value), width)
        if two == 0x1F:
            modrm()
            return finish("nop")
        if two in (0x10, 0x11) and repne:
            reg, rm = modrm(True)
            if two == 0x10:
                return finish("movsd", ("x", reg), rm, 8)
            return finish("movsd", rm, ("x", reg), 8)
        if two in (0x10, 0x11, 0x28, 0x29, 0x6F, 0x7F):
            reg, rm = modrm(True)
            if two in (0x10, 0x28, 0x6F):
                return finish("movx", ("x", reg), rm, 16)
            return finish("movx", rm, ("x", reg), 16)
        vector = {(0x57, False): "xorps", (0x57, True): "xorps", (0xEF, True): "xorps", (0x15, True): "unpckhpd", (0x5C, True): "subpd",
                  (0x54, True): "andpd", (0x56, True): "orpd", (0x62, True): "punpckldq", (0x60, True): "punpcklbw",
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
            return finish("shrdi", rm, ("r", reg), width, target=value)
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
        if kind == "i":
            return operand[1] & MASK[width]
        return self.memory.read(self.address(operand), width)

    def put(self, operand, width, value):
        value &= MASK[width]
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

    def run(self, entry, args):
        self.regs = [POISON] * 16
        for reg in CALLEE_SAVED:
            self.regs[reg] = 0x1111111111111100 + reg
        for reg, value in args.items():
            self.regs[reg] = value
        self.regs[RSP] = STACK_TOP - 0x100
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
        elif op == "mul":
            product = self.regs[RAX] * self.get(row.a, 8)
            self.regs[RAX] = product & MASK[8]
            self.regs[RDX] = product >> 64
            self.cf = self.of = self.regs[RDX] != 0
        elif op == "imul3":
            self.put(row.a, width, self.signed_product(self.get(row.b, width), row.target, width))
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
        elif op == "cdqe":
            self.regs[RAX] = (self.regs[RAX] & MASK[4]) | (MASK[8] ^ MASK[4] if self.regs[RAX] & SIGN[4] else 0)
        elif op == "imul2":
            self.put(row.a, width, self.signed_product(self.get(row.a, width), self.get(row.b, width), width))
        elif op == "nop":
            pass
        elif op == "bswap":
            self.put(row.a, width, int.from_bytes(self.get(row.a, width).to_bytes(width, "little"), "big"))
        elif op == "bsr":
            source = self.get(row.b, width)
            if source == 0:
                raise Halt("bsr of zero at %#x" % row.va)
            self.put(row.a, width, source.bit_length() - 1)
        elif op in ("shld", "shrd", "shrdi"):
            bits = 8 * width
            count = (self.regs[RCX] if op == "shrd" else row.target) & (bits - 1)
            high, low = self.get(row.a, width), self.get(row.b, width)
            if op == "shld":
                value = (high << count | low >> (bits - count)) if count else high
            else:
                value = (high >> count | low << (bits - count)) if count else high
            self.put(row.a, width, value)
        elif op == "ror":
            bits = 8 * width
            count = self.get(row.b, 1) & (bits - 1)
            value = self.get(row.a, width)
            self.put(row.a, width, (value >> count | value << (bits - count)) if count else value)
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

    def signed_product(self, left, right, width):
        """Two and three operand IMUL: the flags report a product that does not fit the signed operand width."""
        bits = 8 * width
        left, right = left & MASK[width], right & MASK[width]
        left = left - (1 << bits) if left >> (bits - 1) & 1 else left
        right = right - (1 << bits) if right >> (bits - 1) & 1 else right
        product = left * right
        self.cf = self.of = not -(1 << (bits - 1)) <= product < (1 << (bits - 1))
        return product & MASK[width]

    def step_vector(self, row, op):
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
        elif op == "punpcklqdq":
            self.xmm[row.a[1]] = (self.xmm[row.a[1]] & MASK[8]) | (self.vector(row.b) & MASK[8]) << 64
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


def fdiv(left, right):
    if right == 0:
        if left == 0 or left != left:
            return math.nan
        return math.copysign(math.inf, math.copysign(1.0, left) * math.copysign(1.0, right))
    return left / right




SUBJECT = 0x446B840
RING = 0x455CB20
TREE = 0x35BE560
TARGETS = (SUBJECT, RING, TREE)
NAMES = {SUBJECT: "position_ratio", RING: "ring_search", TREE: "tree_search"}

SLOTS = {0x64E6DC0: "ctor", 0x64E8BA8: "step", 0x64E6D20: "route", 0x64E4EA8: "sat", 0x64DF620: "index", 0x64DF830: "panic", 0x64DF6A0: "fmt"}
MARK_BASE = 0x7700000000

MIN64 = -(1 << 63)
MAX64 = (1 << 63) - 1
TOP = MASK[8]
OUT = HEAP_BASE + 0x200
OUT_SIZE = 0x30
BLK = HEAP_BASE + 0x300
TABLE = HEAP_BASE + 0x340
ROWS = HEAP_BASE + 0x400
RING_STRUCT = HEAP_BASE + 0x4000
BUF = HEAP_BASE + 0x4100
TREEMEM = HEAP_BASE + 0x5000
USED = 0x8000
ARG_SLOT = STACK_TOP - 0x100
OUT_INIT = bytes((0x60 + index) & 0xFF for index in range(OUT_SIZE))
MIN_RATIO_AT = 0x459B00
SEARCH_KEY_LIMIT = 10000

# Rule-list switches. Each one names a plausible but wrong reading; a run of the bytes must refuse every one.
VARIANTS = (
    "ignore_side", "side_inverted", "zero_size_ok", "index_mod_9999", "negative_x_zero", "no_product_check", "tag_bit1", "no_add_saturation", "no_sub_saturation",
    "route_always", "inverse_ratio", "no_floor_a", "a_ge_zero", "no_floor_b", "b_flag_swapped", "b_zero_ratio", "no_blk_tail", "difference_abs",
    "step_signed", "ctor_args_swapped", "route_without_table", "index_clamped", "rows_count_ignored", "sub_saturates_high",
)


class Case:
    __slots__ = ("name", "mode", "entries", "cap", "head", "key", "flag", "rows", "r8", "blk", "helper", "faults")

    def __init__(self, name, mode, entries, key, flag, rows, r8=0x1234, blk=None, helper=1000, cap=None, head=0, faults=()):
        self.name, self.mode, self.entries, self.key, self.flag, self.rows = name, mode, entries, key, flag, rows
        self.r8, self.helper, self.cap, self.head, self.faults = r8, helper, cap, head, faults
        self.blk = blk if blk is not None else bytes((0x11 * index + 3) & 0xFF for index in range(20))


def signed(value):
    value &= TOP
    return value - (1 << 64) if value >> 63 else value


def entry(tag=1, c=0, v=1, b=1, d=7, pad=None):
    return dict(tag=tag & 0xFFFFFFFF, c=c, v=v, b=b, d=d, pad=pad if pad is not None else bytes((0x40 + 5 * index) & 0xFF for index in range(24)))


def entry_bytes(item):
    return (struct.pack("<II", item["tag"], 0xA5A5A5A5) + struct.pack("<qq", item["c"], item["v"]) + item["pad"][:24]
            + struct.pack("<qQ", item["b"], item["d"] & TOP))


def sat(value):
    return max(MIN64, min(MAX64, value))


def rip_target(image, va):
    return decode_range(image, va, va + 7)[0].b[4]


class Locations:
    """Location records named by the panic and saturation sites of the subject, read from the bytes."""

    def __init__(self, image):
        self.image = image
        self.size = rip_target(image, 0x446BB9B)
        self.add = rip_target(image, 0x446BA77)
        self.sub = rip_target(image, 0x446BBBE)
        self.index = rip_target(image, 0x446BC23)
        self.fmt_length = int.from_bytes(image.blob[image.offset(0x446BB91):image.offset(0x446BB91) + 4], "little")
        self.fmt = (rip_target(image, 0x446BB76), self.fmt_length, rip_target(image, 0x446BB7D), rip_target(image, 0x446BB84))


def min_ratio(image):
    return struct.unpack_from("<d", image.blob, image.offset(MIN_RATIO_AT))[0]


def spec_run(case, locs, floor, m=frozenset()):
    """The rule list for the subject: what the bytes must return, panic with or request from a helper."""
    out = bytearray(OUT_INIT)
    log = []

    def refuse():
        out[0:8] = (0).to_bytes(8, "little")
        return ("ret", bytes(out), tuple(log))

    item = dict(case.entries).get(case.key)
    if item is None:
        return refuse()
    size = item["v"]
    side = (size <= 0) ^ (case.flag & 1)
    if "ignore_side" in m:
        side = True
    if "side_inverted" in m:
        side = not side
    if (size == 0 and "zero_size_ok" not in m) or not side:
        return refuse()
    index = case.key % (9999 if "index_mod_9999" in m else SEARCH_KEY_LIMIT)
    count = len(case.rows)
    if "rows_count_ignored" in m:
        count = 1 << 62
    if index >= count and "index_clamped" in m:
        index = count - 1
    if index >= count:
        return ("index", index, count, locs.index, tuple(log))
    x = case.rows[index] if index < len(case.rows) else 0
    xs = signed(x)
    if xs < 0 and "negative_x_zero" in m:
        xs = 0
    if xs < 0:
        return ("panic", locs.size, tuple(log))
    product = xs * size
    if not MIN64 <= product <= MAX64 and "no_product_check" not in m:
        return ("panic", locs.size, tuple(log))
    product = signed(product)
    magnitude = abs(product) & TOP if "step_signed" not in m else product & TOP
    if "ctor_args_swapped" in m:
        log.append(("ctor", item["d"] & TOP, case.r8))
    else:
        log.append(("ctor", case.r8, item["d"] & TOP))
    log.append(("step", magnitude))
    tagbit = item["tag"] >> (1 if "tag_bit1" in m else 0) & 1
    if "route_always" in m:
        tagbit = 0
    if tagbit:
        total = product + item["c"]
        helper = sat(total) if "no_add_saturation" not in m else signed(total)
        if total != helper or (not MIN64 <= total <= MAX64):
            log.append(("sat", 0, locs.add))
            log.append(("sat", 0, locs.add))
    else:
        log.append(("route", RING_STRUCT, 0, 1, TABLE if "route_without_table" not in m else 0, case.r8))
        helper = case.helper
    positive = helper > 0 if "a_ge_zero" not in m else helper >= 0
    if positive and (helper != 0 or "a_ge_zero" in m):
        if "inverse_ratio" in m:
            ratio = float(helper) / float(magnitude) if magnitude else math.inf
        else:
            ratio = float(magnitude) / float(helper)
        if "no_floor_a" not in m:
            ratio = ratio if ratio > floor else floor
    else:
        ratio = floor
    b = item["b"]
    if b < 0:
        return ("fmt", locs.fmt, tuple(log))
    long_side = (case.flag & 0xFF) != 0
    if "b_flag_swapped" in m:
        long_side = not long_side
    delta = b if long_side else -b
    difference = product - delta
    if not MIN64 <= difference <= MAX64:
        log.append(("sat", 0, locs.sub))
        if "no_sub_saturation" not in m:
            difference = sat(difference) if "sub_saturates_high" not in m else MAX64
        else:
            difference = signed(difference)
    if b == 0 and "b_zero_ratio" not in m:
        factor = floor
    else:
        numerator = float(abs(difference) if "difference_abs" in m else difference) if (difference > 0 or "difference_abs" in m) else 0.0
        factor = numerator / float(b) if b else math.inf
        if "no_floor_b" not in m:
            factor = factor if factor > floor else floor
    result = ratio * factor
    out[0:8] = (1).to_bytes(8, "little")
    out[8:16] = struct.pack("<d", result)
    out[0x10:0x20] = case.blk[:16]
    if "no_blk_tail" not in m:
        out[0x20:0x24] = case.blk[16:20]
    return ("ret", bytes(out), tuple(log))


class Harness:
    def __init__(self, image, patches=None):
        self.image = image
        machine = Machine(image, patches)
        machine.real = frozenset((RING, TREE))
        self.machine = machine
        for slot, name in SLOTS.items():
            machine.memory.statics[slot] = MARK_BASE + slot
            machine.slots[MARK_BASE + slot] = getattr(self, "on_" + name)
        self.case = None
        self.log = []

    def on_ctor(self, machine):
        self.log.append(("ctor", machine.regs[RSI], machine.regs[RDX]))

    def on_step(self, machine):
        self.log.append(("step", machine.regs[RSI]))

    def on_route(self, machine):
        regs = machine.regs
        self.log.append(("route", regs[RSI], regs[RDX], regs[RCX], regs[R9], machine.memory.read(regs[RSP], 8)))
        machine.memory.write(regs[RDI], 8, self.case.helper & TOP)

    def on_sat(self, machine):
        self.log.append(("sat", machine.regs[RDI], machine.regs[RSI]))

    def on_index(self, machine):
        raise Panicked(("index", machine.regs[RDI], machine.regs[RSI], machine.regs[RDX]))

    def on_panic(self, machine):
        raise Panicked(("panic", machine.regs[RDI]))

    def on_fmt(self, machine):
        regs = machine.regs
        raise Panicked(("fmt", (regs[RDI], regs[RSI], regs[RCX], regs[R8])))

    def put_tree(self, entries):
        """Height 0 for up to 11 keys, else a root with separators over leaves of 1..11 keys."""
        memory = self.machine.memory
        count = len(entries)
        if count == 0:
            return 0, 0

        def node(at, items, internal, parent_index, children):
            memory.put_bytes(at, bytes((0x90 + index) & 0xFF for index in range(0x388 if internal else 0x328)))
            for slot, (key, item) in enumerate(items):
                memory.put_bytes(at + slot * 64, entry_bytes(item))
                memory.write(at + 0x2C8 + slot * 8, 8, key)
            memory.write(at + 0x320, 2, parent_index)
            memory.write(at + 0x322, 2, len(items))
            for slot, child in enumerate(children):
                memory.write(at + 0x328 + slot * 8, 8, child)

        if count <= 11:
            node(TREEMEM, entries, False, 0, ())
            return TREEMEM, 0
        separators = min(11, count // 12 + 1)
        leaves = separators + 1
        rest = count - separators
        sizes = [rest // leaves + (1 if slot < rest % leaves else 0) for slot in range(leaves)]
        at, picked, roots, children = 0, [], [], []
        for slot, size in enumerate(sizes):
            leaf = TREEMEM + 0x400 * (slot + 1)
            node(leaf, entries[at:at + size], False, slot, ())
            children.append(leaf)
            at += size
            if slot < separators:
                picked.append(entries[at])
                at += 1
        node(TREEMEM, picked, True, 0, children)
        return TREEMEM, 1

    def fresh(self, case):
        machine = self.machine
        memory = machine.memory
        memory.reset(USED)
        machine.xmm = [POISON | POISON << 64] * 16
        self.case, self.log = case, []
        memory.put_bytes(OUT, OUT_INIT)
        memory.put_bytes(BLK, case.blk)
        memory.write(TABLE + 8, 8, ROWS)
        memory.write(TABLE + 0x10, 8, len(case.rows))
        for slot, value in enumerate(case.rows):
            memory.put_bytes(ROWS + slot * 96, bytes((0x55 + slot + index) & 0xFF for index in range(96)))
            memory.write(ROWS + slot * 96 + 0x20, 8, value)
        if case.mode == "deque":
            cap = case.cap
            memory.write(RING_STRUCT, 8, cap)
            memory.write(RING_STRUCT + 8, 8, BUF)
            memory.write(RING_STRUCT + 0x10, 8, case.head)
            memory.write(RING_STRUCT + 0x18, 8, len(case.entries))
            for slot, (key, item) in enumerate(case.entries):
                at = BUF + (case.head + slot) % cap * 72
                memory.write(at, 8, key)
                memory.put_bytes(at + 8, entry_bytes(item))
        else:
            root, height = self.put_tree(case.entries)
            memory.write(RING_STRUCT, 8, MIN64 & TOP)
            memory.write(RING_STRUCT + 8, 8, root)
            memory.write(RING_STRUCT + 0x10, 8, height)
            memory.write(RING_STRUCT + 0x18, 8, len(case.entries))
        memory.write(ARG_SLOT, 8, RING_STRUCT)
        return bytes(memory.heap[:USED])

    def run(self, case):
        before = self.fresh(case)
        machine = self.machine
        args = {RDI: OUT, RSI: case.key, RDX: case.flag, RCX: TABLE, R8: case.r8, R9: BLK}
        try:
            value = machine.run(SUBJECT, args)
        except Panicked as stop:
            return before, stop.args[0] + (tuple(self.log),)
        after = bytes(machine.memory.heap[:USED])
        start, end = OUT - HEAP_BASE, OUT - HEAP_BASE + OUT_SIZE
        if after[:start] + after[end:] != before[:start] + before[end:]:
            raise Halt("state changed outside the result")
        if value != OUT:
            raise Halt("result pointer")
        return before, ("ret", after[start:end], tuple(self.log))


def lcg(seed):
    state = seed
    while True:
        state = (state * 0x5851F42D4C957F2D + 0x14057B7EF767814F) & TOP
        yield state


def draw_signed(stream, big=False):
    word = next(stream)
    kind = word >> 40 & 7
    value = next(stream)
    if kind == 0:
        return 0
    if kind == 1:
        return (value % 2000) - 1000
    if kind == 2:
        return signed(value) >> (value >> 8 & 31 | 24)
    if kind == 3:
        return (value % 10 ** 12) * (1 if word & 1 else -1)
    if kind == 4:
        return [MAX64, MIN64, MAX64 - 1, MIN64 + 1][word >> 8 & 3] if big else (value % 100)
    if kind == 5:
        return value % 30
    return signed(value) >> (value >> 8 & 63)


def draw_key(stream):
    word = next(stream)
    kind = word >> 40 & 7
    value = next(stream)
    if kind <= 3:
        return value % 60
    if kind == 4:
        return 10000 * (value % 4) + value % 25
    if kind == 5:
        return value % 10000
    if kind == 6:
        return value
    return TOP - value % 4


def vector_case(stream, index):
    mode = "deque" if next(stream) >> 30 & 3 else "tree"
    limit = 17 if mode == "deque" else 34
    count = (next(stream) >> 30) % limit
    keys = set()
    while len(keys) < count:
        keys.add(draw_key(stream))
    keys = sorted(keys)
    entries = []
    for key in keys:
        word = next(stream)
        size = draw_signed(stream)
        if size == 0 and word & 3:
            size = 1 + word >> 8 & 255
        entries.append((key, entry(tag=word >> 16 & 0xFFFFFFFF, c=draw_signed(stream, True), v=size, b=abs(draw_signed(stream)) if word >> 12 & 7 else draw_signed(stream, True), d=next(stream),
                                   pad=next(stream).to_bytes(8, "little") * 3)))
    hit = count and next(stream) >> 30 & 3
    key = keys[(next(stream) >> 20) % count] if hit else draw_key(stream)
    item = dict(entries).get(key)
    word = next(stream)
    if item is not None and word & 15:
        flag = int(item["v"] > 0)
    else:
        flag = [0, 1, 2, 255][word >> 8 & 3]
    rows_count = 1 + (next(stream) >> 30) % 70
    rows = [abs(draw_signed(stream)) if word >> 4 & 7 else draw_signed(stream, True) & TOP for _ in range(rows_count)]
    cap = head = None
    if mode == "deque":
        cap = count + (next(stream) >> 30) % 9 or 1
        head = (next(stream) >> 30) % cap
    return Case("v%d" % index, mode, entries, key, flag, rows, r8=next(stream), blk=next(stream).to_bytes(8, "little") * 3, helper=draw_signed(stream, True), cap=cap, head=head)


def vector_cases(count, seed=0x1234ABCD):
    stream = lcg(seed)
    for index in range(count):
        yield vector_case(stream, index)


def named_cases():
    """Hand written cases for every branch and edge; sizes and fields chosen against the rule list."""
    cases = []
    base = [(3, entry(tag=0, v=5, b=40, c=0)), (7, entry(tag=1, v=-5, b=40, c=100)), (12, entry(tag=0, v=9, b=0)), (40, entry(tag=1, v=0, b=9))]

    def add(name, **kw):
        fields = dict(mode="deque", entries=base, key=3, flag=1, rows=[0, 10, 20, 30, 40] * 12, cap=6, head=2)
        fields.update(kw)
        fields["rows"] = fields["rows"] if fields["rows"] else [0]
        cases.append(Case(name, fields["mode"], fields["entries"], fields["key"], fields["flag"], fields["rows"], r8=kw.get("r8", 0x1234), helper=kw.get("helper", 1000),
                          cap=fields.get("cap"), head=fields.get("head", 0), blk=kw.get("blk")))

    add("deque long route", rows=[0, 0, 0, 100] + [0] * 8, key=3)
    add("deque short tag", key=7, flag=0, rows=[0] * 7 + [50] + [0] * 8)
    add("tree long route", mode="tree", key=3, cap=None, rows=[0, 0, 0, 100])
    add("tree short tag", mode="tree", key=7, flag=0, cap=None, rows=[0] * 7 + [50])
    add("missing key", key=4)
    add("zero size", key=40, flag=1)
    add("wrong side", key=3, flag=0, rows=[0, 0, 0, 100])
    add("index out of range", key=12, rows=[1, 2])
    add("negative row", key=3, rows=[0, 0, 0, MIN64 & TOP])
    add("product overflow", entries=[(3, entry(tag=0, v=MAX64, b=1))], key=3, rows=[0, 0, 0, 2])
    add("product min", entries=[(3, entry(tag=0, v=MIN64, b=1))], key=3, flag=0, rows=[0, 0, 0, 1], helper=7)
    add("helper zero", key=3, rows=[0, 0, 0, 100], helper=0)
    add("helper negative", key=3, rows=[0, 0, 0, 100], helper=-1)
    add("helper one", key=3, rows=[0, 0, 0, 100], helper=1)
    add("b zero", key=12, flag=1, rows=[0] * 12 + [50], entries=[(12, entry(tag=0, v=9, b=0))], helper=33)
    add("b negative", key=3, entries=[(3, entry(tag=0, v=5, b=-1))], rows=[0, 0, 0, 100])
    add("tag add saturates high", entries=[(3, entry(tag=1, v=5, b=3, c=MAX64))], key=3, rows=[0, 0, 0, 100])
    add("tag add saturates low", entries=[(3, entry(tag=1, v=-5, b=3, c=MIN64))], key=3, flag=0, rows=[0, 0, 0, 100])
    add("sub saturates high", entries=[(3, entry(tag=0, v=MAX64, b=MAX64))], key=3, flag=0, rows=[0, 0, 0, 1], helper=5)
    add("sub saturates low", entries=[(3, entry(tag=0, v=MIN64 + 5, b=MAX64))], key=3, flag=2, rows=[0, 0, 0, 1], helper=5)
    add("sub saturates low b zero", entries=[(3, entry(tag=0, v=MIN64 + 5, b=0))], key=3, flag=2, rows=[0, 0, 0, 1], helper=5)
    add("sub exactly min", entries=[(3, entry(tag=0, v=MIN64, b=0))], key=3, flag=2, rows=[0, 0, 0, 1], helper=5)
    add("sub min plus one by one", entries=[(3, entry(tag=0, v=MIN64 + 1, b=1))], key=3, flag=2, rows=[0, 0, 0, 1], helper=5)
    add("sub min plus two by one", entries=[(3, entry(tag=0, v=MIN64 + 2, b=1))], key=3, flag=2, rows=[0, 0, 0, 1], helper=5)
    for tag_name, product, extra in (("max plus one", MAX64, 1), ("max plus max", MAX64, MAX64), ("max plus zero", MAX64, 0), ("max minus one", MAX64, -1), ("big plus big", 1 << 62, 1 << 62),
                                     ("big plus big less one", 1 << 62, (1 << 62) - 1), ("two to 62 plus 2 to 61", 1 << 62, 1 << 61)):
        add("add " + tag_name, entries=[(3, entry(tag=1, v=product, b=3, c=extra))], key=3, rows=[0, 0, 0, 1])
    for tag_name, product, extra in (("min minus one", MIN64 + 1, -2), ("min minus zero", MIN64 + 1, -1), ("min plus max", MIN64 + 1, MAX64), ("min plus min", MIN64 + 1, MIN64),
                                     ("small minus min", -2, MIN64), ("small minus min plus one", -1, MIN64), ("minus 2 to 62 less", -(1 << 62), -(1 << 62)), ("minus 2 to 62 sum", -(1 << 62), -(1 << 62) - 1)):
        add("add " + tag_name, entries=[(3, entry(tag=1, v=product, b=3, c=extra))], key=3, flag=0, rows=[0, 0, 0, 1])
    add("difference not positive", entries=[(3, entry(tag=0, v=5, b=1000))], key=3, flag=1, rows=[0, 0, 0, 1], helper=3)
    add("flag two", key=3, flag=2, rows=[0, 0, 0, 100])
    add("flag byte only", key=3, flag=256, rows=[0, 0, 0, 100])
    add("empty deque", entries=[], key=3, cap=4, head=0)
    add("empty tree", mode="tree", entries=[], key=3, cap=None)
    add("full deque wrapped", entries=[(k, entry(tag=0, v=k + 1, b=5)) for k in (1, 2, 3, 4)], key=2, cap=4, head=3, rows=[0, 50, 50, 50, 50], helper=40)
    add("deque head at cap edge", entries=[(k, entry(tag=0, v=k + 1, b=5)) for k in (1, 2, 3, 4)], key=4, cap=4, head=3, rows=[0, 50, 50, 50, 50], helper=40)
    add("tree two level first", mode="tree", entries=[(k, entry(tag=0, v=k + 1, b=5)) for k in range(1, 31)], key=1, cap=None, rows=[0, 50], helper=40)
    add("tree two level last", mode="tree", entries=[(k, entry(tag=0, v=k + 1, b=5)) for k in range(1, 31)], key=30, cap=None, rows=[0] * 30 + [50], helper=40)
    add("tree separator key", mode="tree", entries=[(k, entry(tag=0, v=k + 1, b=5)) for k in range(1, 31)], key=12, cap=None, rows=[0] * 13, helper=40)
    add("tree absent key", mode="tree", entries=[(k * 2, entry(tag=0, v=k + 1, b=5)) for k in range(1, 31)], key=13, cap=None)
    add("large key", entries=[(TOP, entry(tag=0, v=3, b=5))], key=TOP, rows=[0] * 20, helper=9)
    add("key at row count", entries=[(10000, entry(tag=0, v=3, b=5))], key=10000, rows=[7], helper=9)
    return cases


def grid_cases():
    index = 0
    for mode in ("deque", "tree"):
        for tag in (0, 1):
            for size in (-3, 3):
                for flag in (0, 1):
                    for helper in (MIN64, -1, 0, 1, 77, MAX64):
                        for b in (0, 1, 500, MAX64):
                            for c in (0, MAX64, MIN64):
                                for x in (0, 9, 1 << 61):
                                    entries = [(2, entry(tag=0, v=1, b=1)), (5, entry(tag=tag, c=c, v=size, b=b)), (9, entry(tag=1, v=2, b=2))]
                                    yield Case("g%d" % index, mode, entries, 5, flag, [x] * 6, helper=helper, cap=5 if mode == "deque" else None, head=4 if mode == "deque" else 0)
                                    index += 1


def edge_cases():
    index = 0
    for size in (MAX64, MIN64, MIN64 + 1, -1, 1, 1 << 62, -(1 << 62)):
        for x in (1, 2):
            for c in (1, -1, MAX64, MIN64, 0, 1 << 62):
                for b in (0, 1, MAX64, 1 << 62):
                    for flag in (0, 1, 2):
                        for tag in (0, 1):
                            entries = [(5, entry(tag=tag, c=c, v=size, b=b))]
                            yield Case("e%d" % index, "deque", entries, 5, flag, [0] * 5 + [x], helper=5, cap=2, head=1)
                            index += 1


def digest_of(outcome):
    kind = outcome[0]
    body = outcome[1] if kind == "ret" else outcome[1:-1]
    text = body.hex() if isinstance(body, bytes) else repr(body)
    return kind, hashlib.sha256(text.encode()).hexdigest()[:16], len(outcome[-1])


def check_stream(harness, cases, locs, floor, rows=None, keep_every=0, variant=frozenset(), tally=None):
    """Run each case, compare at once, keep only counts and sampled rows."""
    count = 0
    for case in cases:
        before, got = harness.run(case)
        want = spec_run(case, locs, floor, variant)
        if got != want:
            raise EvidenceError("case disagrees with the rule list: %s %r %r" % (case.name, got, want))
        if tally is not None:
            tally[got[0]] = tally.get(got[0], 0) + 1
        if rows is not None and (keep_every == 0 or count % keep_every == 0):
            rows.append((case.mode, case.name) + digest_of(got))
        count += 1
    return count


def first_failure(harness, cases, locs, floor, variant=frozenset()):
    for case in cases:
        try:
            before, got = harness.run(case)
            if got != spec_run(case, locs, floor, variant):
                return case
        except (Halt, EvidenceError, KeyError, IndexError, ValueError, OverflowError, ZeroDivisionError, struct.error, Panicked):
            return case
    return None


def constant_rows(image, table):
    rows = []
    for target in TARGETS:
        for row in table[target]:
            if row.imm_at is not None and row.imm_size == 8 and row.op == "mov":
                value = int.from_bytes(row.data[row.imm_at:row.imm_at + 8], "little")
                rows.append((NAMES[target], "%#x" % row.va, "movabs", "%#x" % value))
    for row in table[SUBJECT]:
        if row.op in ("maxsd", "divsd", "mulsd") or (row.b and row.b[0] == "m" and row.b[4] and row.op in ("movsd", "punpckldq", "subpd")):
            if row.b and row.b[0] == "m" and row.b[1] is None:
                rows.append(("position_ratio", "%#x" % row.va, row.op, "%#x" % row.b[4]))
    rows.append(("position_ratio", "%#x" % MIN_RATIO_AT, "f64 floor", repr(min_ratio(image))))
    return rows


def site_rows(image):
    rows = []
    text_va, text = image.text_bytes()
    for target in (RING, TREE):
        sites, at = [], 0
        while True:
            at = text.find(b"\xe8", at)
            if at < 0 or at + 5 > len(text):
                break
            if text_va + at + 5 + struct.unpack_from("<i", text, at + 1)[0] == target:
                sites.append(text_va + at)
            at += 1
        inside = [site for site in sites if SUBJECT <= site < image.exact_fde(SUBJECT)[1]]
        rows.append((NAMES[target], "%#x" % target, "direct", len(sites), " ".join("%#x" % site for site in inside)))
    relative = image.relative()
    for slot, name in sorted(SLOTS.items()):
        sites, at = [], 0
        while True:
            at = text.find(b"\xff\x15", at)
            if at < 0:
                break
            if text_va + at + 6 + struct.unpack_from("<i", text, at + 2)[0] == slot:
                sites.append(text_va + at)
            at += 1
        inside = [site for site in sites if SUBJECT <= site < image.exact_fde(SUBJECT)[1]]
        rows.append((name, "%#x" % slot, "slot", len(sites), " ".join("%#x" % site for site in inside)))
    return rows


def location_rows(image, locs):
    relative = image.relative()
    rows = []
    for name, slot in (("size panic", locs.size), ("saturating add", locs.add), ("saturating subtract", locs.sub), ("row index", locs.index)):
        path, line, column = image.location(slot, relative)
        rows.append((name, "%#x" % slot, path, line, column))
    for name, slot in zip(("fmt rdi", "fmt length", "fmt rcx", "fmt r8"), locs.fmt):
        rows.append((name, "%#x" % slot, "-", "-", "-"))
    return rows


def edits_for(image, rows, seen):
    edits = []
    for row in rows:
        if row.va not in seen:
            continue
        data = bytes(image.blob[image.offset(row.va):image.offset(row.va) + row.size])
        if row.op == "jcc":
            at = row.size - 5 if row.size >= 6 else 0
            edits.append((row.va, "condition", {row.va + at: data[at] ^ 1}))
            continue
        if row.op in ("cmov", "set"):
            at = next(i for i in range(row.size) if data[i] == 0x0F) + 1
            edits.append((row.va, "condition", {row.va + at: data[at] ^ 1}))
            continue
        if row.imm_at is not None and row.op not in ("call", "jmp"):
            edits.append((row.va, "immediate", {row.va + row.imm_at: data[row.imm_at] ^ 1}))
        at = displacement_at(row, data)
        if at is not None:
            edits.append((row.va, "displacement", {row.va + at: data[at] ^ 8}))
    return edits


def displacement_at(row, data):
    operand = row.a if row.a and row.a[0] == "m" else row.b if row.b and row.b[0] == "m" else None
    if operand is None or operand[5] or operand[1] in (None, RSP) or operand[4] == 0:
        return None
    end = row.size - (row.imm_size or 0)
    value = operand[4]
    if -128 <= value < 128 and data[end - 1] == value & 0xFF:
        return end - 1
    if data[end - 4:end] == struct.pack("<i", value):
        return end - 4
    return None


SECOND_LOOKUP = "the second lookup repeats the first on unchanged containers, so its found test cannot differ"
UNUSED_INSERTION = "the insertion point of a missing key is never read: the subject returns on a miss"
REDUNDANT_GUARD = "guard whose flipped constant leaves the loop count of the following halving loop unchanged"
UNUSED_HEIGHT = "the height word of the tree search result is never read by the subject"
SATURATED_FIGURE = "the saturated sum is only read after conversion to f64, where a one or two unit change of 2^63-1 rounds to the same double"
ZERO_AFTER_SATURATION = "reached only after a saturating subtract, which needs a nonzero B, so the zero test always falls through"
EXPECTED_SURVIVORS = {
    (0x446BA57, "immediate"): SATURATED_FIGURE,
    (0x446BA5B, "immediate"): SATURATED_FIGURE,
    (0x446BBE3, "condition"): ZERO_AFTER_SATURATION,
    (0x446B9BC, "immediate"): SECOND_LOOKUP,
    (0x455CB75, "immediate"): REDUNDANT_GUARD,
    (0x455CBAC, "condition"): UNUSED_INSERTION,
    (0x455CBAE, "immediate"): UNUSED_INSERTION,
    (0x455CBE9, "immediate"): REDUNDANT_GUARD,
    (0x455CC1F, "immediate"): UNUSED_INSERTION,
    (0x35BE5DF, "displacement"): UNUSED_HEIGHT,
}


def run_mutants(image, table, seen, cases, locs, floor):
    results = []
    for target in TARGETS:
        for va, kind, patch in edits_for(image, table[target], seen):
            harness = Harness(image, patch)
            harness.machine.step_limit = MUTANT_STEP_LIMIT
            failure = first_failure(harness, cases, locs, floor)
            if failure is not None:
                results.append((va, kind, "killed", NAMES[target]))
            else:
                results.append((va, kind, "survived", EXPECTED_SURVIVORS.get((va, kind), "UNEXPLAINED")))
    unexplained = [row for row in results if row[3] == "UNEXPLAINED"]
    if unexplained:
        raise EvidenceError("unexplained survivors: %s" % [(hex(row[0]), row[1]) for row in unexplained])
    return results


def structural_controls(image, harness, cases, locs, floor):
    """Controls that are not byte edits: a changed digest, an address that is no function, a changed constant."""
    rows = []
    blob = bytearray(image.blob)
    blob[1000] ^= 1
    rows.append(("one flipped file byte changes the SHA-256", "detected" if hashlib.sha256(bytes(blob)).hexdigest() != SHA256 else "MISSED"))
    for label, va in (("address inside the subject", SUBJECT + 1), ("address before the subject", SUBJECT - 1), ("address in .rodata", 0x459230), ("address past the file", 0x7FFFFFFFFF)):
        try:
            image.exact_fde(va)
            rows.append((label + " is refused as a function start", "MISSED"))
        except EvidenceError:
            rows.append((label + " is refused as a function start", "detected"))
    rows.append(("floor constant of another value breaks the comparison", "detected" if first_failure(harness, cases, locs, floor * 2) is not None else "MISSED"))
    wrong = Locations(image)
    wrong.add, wrong.sub = wrong.size, wrong.size
    rows.append(("saturation sites swapped for the size panic site", "detected" if first_failure(harness, cases, wrong, floor) is not None else "MISSED"))
    wrong = Locations(image)
    wrong.index = wrong.size
    rows.append(("row index panic mapped to the size site", "detected" if first_failure(harness, cases, wrong, floor) is not None else "MISSED"))
    probe = next(case for case in cases if case.name == "deque long route")
    before, got = harness.run(probe)
    mangled = Case(probe.name, probe.mode, probe.entries, probe.key, probe.flag, probe.rows, r8=probe.r8 ^ 1, helper=probe.helper, cap=probe.cap, head=probe.head, blk=probe.blk)
    rows.append(("an altered opaque argument changes the logged helper request", "detected" if spec_run(mangled, locs, floor) != got else "MISSED"))
    return rows


def container_rows(harness, locs, floor):
    """Probe the two searches directly: the key set found, absent and the slot reached, over all wrap offsets."""
    rows = []
    for mode in ("deque", "tree"):
        for count in (0, 1, 2, 5, 11, 12, 23, 33):
            found = 0
            for index in range(count + 1):
                keys = [3 * slot + 1 for slot in range(count)]
                entries = [(key, entry(tag=0, v=1 + slot, b=1)) for slot, key in enumerate(keys)]
                cap = count + 2 if mode == "deque" else None
                for head in (range(cap) if mode == "deque" else (0,)):
                    probe_key = keys[index] if index < count else 3 * count + 2
                    case = Case("probe", mode, entries, probe_key, 1, [0] * 100 + [9], helper=100, cap=cap, head=head)
                    before, got = harness.run(case)
                    if got != spec_run(case, locs, floor):
                        raise EvidenceError("container probe disagrees")
                    found += got[0] == "ret" and got[1][0] == 1
            rows.append((mode, count, found))
    return rows


def analyse(image, vectors=10500, mutate=True):
    locs = Locations(image)
    floor = min_ratio(image)
    harness = Harness(image)
    cases = named_cases()
    tally = {}
    outcomes = []
    check_stream(harness, cases, locs, floor, outcomes, tally=tally)
    grid_rows = []
    grid_count = check_stream(harness, grid_cases(), locs, floor, grid_rows, keep_every=40, tally=tally)
    vector_rows = []
    vector_count = check_stream(harness, vector_cases(vectors), locs, floor, vector_rows, keep_every=100, tally=tally)
    edge_rows = []
    edge_count = check_stream(harness, edge_cases(), locs, floor, edge_rows, keep_every=30, tally=tally)
    containers = container_rows(harness, locs, floor)
    seen = set(harness.machine.seen)
    table = {target: decode_range(image, *image.exact_fde(target)) for target in TARGETS}
    unreached = {target: [row.va for row in table[target] if row.va not in seen and row.op not in ("int3", "nop")] for target in TARGETS}
    variants = []
    sample = cases + list(vector_cases(400, seed=0x77)) + list(itertools.islice(grid_cases(), 0, 4000, 7)) + list(itertools.islice((c for c in edge_cases() if c.flag == 2 or c.name.endswith("7")), 0, None, 2))
    for name in VARIANTS:
        failure = first_failure(harness, sample, locs, floor, frozenset((name,)))
        variants.append((name, "detected" if failure is not None else "MISSED", failure.name if failure else "-"))
    structural = structural_controls(image, harness, sample, locs, floor)
    result = dict(table=table, cases=cases, outcomes=outcomes, grid_rows=grid_rows, grid_count=grid_count, vector_rows=vector_rows, vector_count=vector_count, edge_rows=edge_rows, edge_count=edge_count,
                  unreached=unreached, sites=site_rows(image), constants=constant_rows(image, table), locations=location_rows(image, locs), containers=containers,
                  variants=variants, structural=structural, tally=tally)
    if mutate:
        picked = cases + list(itertools.islice(edge_cases(), 0, None, 5)) + list(vector_cases(300, seed=0x78)) + list(itertools.islice(grid_cases(), 0, None, 31))
        result["mutations"] = run_mutants(image, table, seen, picked, locs, floor)
    return result


def render(result):
    files = {}

    def tsv(name, header, rows):
        lines = ["\t".join(header)] + ["\t".join(str(cell) for cell in row) for row in rows]
        files[name] = "\n".join(lines) + "\n"

    tsv("function-rows.tsv", ("function", "address", "size", "bytes", "operation"),
        [(NAMES[target], "%#x" % row.va, row.size, row.data.hex(), row.op) for target in TARGETS for row in result["table"][target]])
    tsv("call-sites.tsv", ("callee", "address", "form", "sites_in_text", "sites_in_subject"), result["sites"])
    tsv("constants.tsv", ("function", "row", "form", "value"), result["constants"])
    tsv("locations.tsv", ("site", "record", "path", "line", "column"), result["locations"])
    tsv("container-probes.tsv", ("container", "entries", "keys_found_over_all_probes"), result["containers"])
    tsv("model-variants.tsv", ("switch", "outcome", "first_case"), result["variants"])
    tsv("structural-controls.tsv", ("control", "outcome"), result["structural"])
    tsv("outcomes.tsv", ("container", "case", "form", "result_digest", "helper_requests"), result["outcomes"])
    tsv("grid-outcomes.tsv", ("container", "case", "form", "result_digest", "helper_requests"), result["grid_rows"])
    tsv("edge-outcomes.tsv", ("container", "case", "form", "result_digest", "helper_requests"), result["edge_rows"])
    tsv("vector-outcomes.tsv", ("container", "case", "form", "result_digest", "helper_requests"), result["vector_rows"])
    mutations = result.get("mutations", [])
    if mutations:
        tsv("mutations.tsv", ("address", "kind", "outcome", "function_or_reason"), [("%#x" % va, kind, outcome, name) for va, kind, outcome, name in mutations])
    killed = sum(1 for row in mutations if row[2] == "killed")
    variants_detected = sum(1 for row in result["variants"] if row[1] == "detected")
    structural_detected = sum(1 for row in result["structural"] if row[1] == "detected")
    total_cases = len(result["cases"]) + result["grid_count"] + result["vector_count"] + result["edge_count"]
    controls = len(result["variants"]) + len(result["structural"]) + killed
    detected = variants_detected + structural_detected + killed
    summary = {
        "binary": "artifacts/node/115/hl-node", "sha256": SHA256,
        "functions": {NAMES[target]: {"address": "%#x" % target, "bytes": sum(row.size for row in result["table"][target]), "instructions": len(result["table"][target]),
                                      "unreached_rows": ["%#x" % va for va in result["unreached"][target]]} for target in TARGETS},
        "named_cases": len(result["cases"]), "grid_cases": result["grid_count"], "vector_cases": result["vector_count"], "edge_cases": result["edge_count"],
        "outcome_kinds": dict(sorted(result["tally"].items())),
        "model_variants": len(result["variants"]), "structural_controls": len(result["structural"]),
    }
    if mutations:
        summary["mutations"] = {"total": len(mutations), "killed": killed, "survived": sum(1 for r in mutations if r[2] == "survived")}
    files["evidence.json"] = json.dumps(summary, indent=1, sort_keys=True) + "\n"
    files["measure.json"] = json.dumps({"cases": total_cases, "negative_controls": controls, "negative_detected": detected}, indent=1, sort_keys=True) + "\n"
    return files


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.split("\n", 1)[0])
    parser.add_argument("--out", required=True, type=pathlib.Path)
    args = parser.parse_args(argv)
    image = load_image()
    files = render(analyse(image))
    args.out.mkdir(parents=True, exist_ok=True)
    for name, text in files.items():
        (args.out / name).write_text(text, encoding="ascii", newline="\n")
    print(json.dumps({"files": sorted(files)}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
