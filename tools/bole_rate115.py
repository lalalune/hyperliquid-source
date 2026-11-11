#!/usr/bin/env python3
"""Reconstruct node #115 BOLE utilization and the kinked borrow rate: four bodies run from the ELF bytes against a written rule list.

0x36a08b0 and 0x36a09f0 give the utilization as a Result (word / 1e10 and f64 / 1e14). 0x36a0b30 and 0x36a0d80 turn a token record into the
two slope rate (rate / 1e10 and f64 / 1e14). The real bytes run in a small x86-64 evaluator with the 128 bit divide as a recording stub, a
separately written rule list predicts every result and every divide request, and every reached conditional, immediate and field offset of
the subject code is edited. The rule list of the #94 packet is kept as a switch and shown to disagree with the #115 bytes. No objdump or
readelf output is parsed and the binary is never executed. Standard library only.

    python3 tools/bole_rate115.py --out <dir>
"""

import argparse
import bisect
import collections
import fractions
import hashlib
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
            self.put(row.a, width, self.get(row.b, width) * row.target)
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
            self.put(row.a, width, self.get(row.a, width) * self.get(row.b, width))
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



RATE = 0x36A0D80
RATE_INT = 0x36A0B30
UTIL_WORD = 0x36A08B0
UTIL_F64 = 0x36A09F0
TARGETS = (UTIL_WORD, UTIL_F64, RATE_INT, RATE)
NAMES = {RATE: "rate_f64", RATE_INT: "rate_e10", UTIL_WORD: "utilization_e10", UTIL_F64: "utilization_f64"}

SLOT_DIV = 0x64DFAF8
SLOT_RATE = 0x64E7198
SLOT_UTIL_F64 = 0x64E8D50
CALLER = 0x38E64B0
MARK_BASE = 0x7700000000

E14 = 10 ** 14
E10 = 10 ** 10
TOP = MASK[8]
TOP128 = (1 << 128) - 1
GUARD = E14 << 64
EDGE_LEFT = 3 * 13 * 7021362262547
EDGE_RIGHT = 2039 * 1058093 * 3122429689
MUL_RATE = 0xDBE6FECEBDEDD5BF
SHIFT_RATE = 97
MUL_UTIL = 0x6DF37F675EF7
SHIFT_UTIL = 80

OUT = HEAP_BASE + 0x200
OUT_SIZE = 0x60
REC = HEAP_BASE + 0x1000
USED = 0x2000
REC_SIZE = 0xB0

# Rule-list switches. Each one names a plausible but wrong reading; a run of the bytes must refuse every one.
VARIANTS = (
    "old94", "floor_total", "no_cap", "ge_kink", "ceil_low", "e10_rate", "util_e10", "f64_scale", "err_swap", "no_high_q",
    "no_a_zero", "top_below_off", "guard_off", "add_wrap", "supply_high_off", "low_arm_top",
)


class Case:
    __slots__ = ("name", "kind", "rec", "faults")

    def __init__(self, name, kind, rec=None, faults=None):
        self.name, self.kind, self.rec, self.faults = name, kind, rec, faults or {}


def record(a=0, ia=E14, b=0, ib=E14, mn=0, mx=E14, kr=5 * 10 ** 12, k=8 * 10 ** 13, ltv=None, px=0, bal=0):
    return dict(a=a, ia=ia, b=b, ib=ib, mn=mn, mx=mx, kr=kr, k=k, ltv=ltv, px=px, bal=bal)


class Div:
    """The model's 128 bit divide: logs every request and answers an injected quotient when a case asks."""

    def __init__(self, faults):
        self.log, self.faults = [], faults

    def __call__(self, num, den):
        index = len(self.log)
        self.log.append((num, den))
        if index in self.faults:
            return self.faults[index]
        return num // den


def low(value):
    return value & TOP


def high(value):
    return value >> 64


def ceil_total(a, ia, div, m):
    product = a * ia
    q = div(product, E14)
    rem = (product - q * E14) & TOP128
    if "floor_total" in m:
        return q & TOP128
    return (q + (1 if rem else 0)) & TOP128


def total_error(rec, total, m):
    """The borrowed side's refusal: 3 when the ceil needs a high word, 2 when no shares carry a debt."""
    if high(total):
        return 3
    if rec["a"] == 0 and low(total) and "no_a_zero" not in m:
        return 2
    return None


def supply_of(rec, div, m):
    """Returns (supplied, product_too_big). The #115 bodies always divide; the #94 rule list skipped it when the product was too big."""
    product = rec["b"] * rec["ib"]
    too_big = high(product) > E14 - 1
    if "old94" in m and too_big:
        return None, True
    return div(product, E14), too_big


def ratio_or_zero(rec, div, m=frozenset()):
    total = ceil_total(rec["a"], rec["ia"], div, m)
    supplied, too_big = supply_of(rec, div, m)
    if too_big or total_error(rec, total, m):
        return 0
    zero = (supplied == 0) if "supply_high_off" in m else (low(supplied) == 0)
    if zero:
        return 0
    if "old94" in m and rec["b"] == 0:
        return 0
    q = div(low(total) * E14, supplied)
    if high(q) and "no_high_q" not in m:
        return 0
    cap = low(q) if "no_cap" in m else min(low(q), E14)
    return cap


def curve(rec, u, div, m=frozenset()):
    bend, k = rec["kr"], rec["k"]
    if u == k and "ge_kink" not in m:
        return bend
    if u >= k if "ge_kink" in m else u > k:
        top = rec["mx"]
        if "low_arm_top" in m:
            return top
        if k > E14 - 1:
            return top
        f = div(((u - k) & TOP) * E14, E14 - k)
        if (top < bend and "top_below_off" not in m) or high(f):
            return top
        product = low(f) * ((top - bend) & TOP)
        if product >= GUARD and "guard_off" not in m:
            return top
        q = div(product, E14)
        if "ceil_low" in m and product % E14:
            q += 1
        value = low(q) + bend
        if value > TOP:
            return value & TOP if "add_wrap" in m else top
        return value
    floor_rate = rec["mn"]
    f = div(u * E14, k)
    if (bend < floor_rate and "top_below_off" not in m) or high(f):
        return bend
    product = low(f) * ((bend - floor_rate) & TOP)
    if product >= GUARD and "guard_off" not in m:
        return bend
    q = div(product, E14)
    if "ceil_low" in m and product % E14:
        q += 1
    value = low(q) + floor_rate
    if value > TOP:
        return value & TOP if "add_wrap" in m else bend
    return value


def util_result(rec, div, m=frozenset()):
    total = ceil_total(rec["a"], rec["ia"], div, m)
    err = total_error(rec, total, m)
    supplied, too_big = supply_of(rec, div, m)
    three, two = (2, 3) if "err_swap" in m else (3, 2)
    if err:
        err = three if err == 3 else two
    if too_big:
        return (1, err or three)
    if "old94" in m and rec["b"] == 0 and low(supplied):
        return (1, err or two)
    if err:
        return (1, err)
    if (supplied == 0) if "supply_high_off" in m else (low(supplied) == 0):
        return (0, 0)
    q = div(low(total) * E14, supplied)
    if high(q) and "no_high_q" not in m:
        return (1, three)
    return (0, low(q) if "no_cap" in m else min(low(q), E14))


def result_bytes(base, outcome, word, m=frozenset()):
    data = bytearray(base)
    if outcome[0]:
        data[0], data[1] = 1, outcome[1]
    else:
        data[0] = 0
        scale = 10 ** 9 if "util_e10" in m else E10
        value = outcome[1] // scale if word else to_bits(float(outcome[1]) / (1e13 if "f64_scale" in m else 1e14))
        data[8:16] = struct.pack("<Q", value & TOP)
    return bytes(data)


def spec_run(case, before, m=frozenset()):
    base = before[OUT - HEAP_BASE:OUT - HEAP_BASE + OUT_SIZE]
    div = Div(case.faults)
    if case.kind == RATE:
        word = curve(case.rec, ratio_or_zero(case.rec, div, m), div, m)
        return ("xmm", to_bits(float(word) / (1e13 if "f64_scale" in m else 1e14)), div.log, ())
    if case.kind == RATE_INT:
        word = curve(case.rec, ratio_or_zero(case.rec, div, m), div, m)
        return ("rax", word // (10 ** 9 if "e10_rate" in m else E10), div.log, ())
    return ("out", result_bytes(base, util_result(case.rec, div, m), case.kind == UTIL_WORD, m), div.log, ())


class Harness:
    def __init__(self, image, patches=None):
        self.image = image
        machine = Machine(image, patches)
        self.machine = machine
        statics = machine.memory.statics
        statics[SLOT_DIV] = MARK_BASE + SLOT_DIV
        machine.slots[MARK_BASE + SLOT_DIV] = self.on_div
        self.case = None
        self.log = []

    def expect(self, condition, text):
        if not condition:
            raise Halt("stub check failed: " + text)

    def on_div(self, machine):
        regs = machine.regs
        num, den = regs[RDI] | regs[RSI] << 64, regs[RDX] | regs[RCX] << 64
        index = len(self.log)
        self.log.append((num, den))
        if index in self.case.faults:
            q = self.case.faults[index]
        else:
            self.expect(den != 0, "divide by zero")
            q = num // den
        regs[RAX], regs[RDX] = low(q), high(q)
        machine.keep_rdx = True

    def put_rec(self, at, rec):
        memory = self.machine.memory
        memory.put_bytes(at, bytes((0x31 + 7 * index) & 0xFF for index in range(REC_SIZE)))
        tag = 2 if rec["ltv"] is None else 1
        for offset, value in ((0, tag), (8, rec["ltv"] or 0), (0x10, rec["px"]), (0x18, rec["bal"]), (0x40, rec["a"]), (0x58, rec["ia"]), (0x60, rec["b"]), (0x78, rec["ib"]),
                              (0x80, rec["mn"]), (0x88, rec["mx"]), (0x90, rec["kr"]), (0x98, rec["k"])):
            memory.write(at + offset, 8, value)

    def fresh(self, case):
        machine = self.machine
        memory = machine.memory
        memory.reset(USED)
        machine.xmm = [POISON | POISON << 64] * 16
        memory.put_bytes(HEAP_BASE, bytes(((index * 13) ^ (index >> 8)) & 0xFF or 1 for index in range(0x1000)))
        memory.put_bytes(OUT, bytes((0x60 + index) & 0xFF for index in range(OUT_SIZE)))
        self.case, self.log = case, []
        self.put_rec(REC, case.rec)
        return bytes(memory.heap[:USED])

    def run(self, case):
        before = self.fresh(case)
        machine = self.machine
        args = {RATE: {RDI: REC}, RATE_INT: {RDI: REC}, UTIL_WORD: {RDI: OUT, RSI: REC}, UTIL_F64: {RDI: OUT, RSI: REC}}[case.kind]
        value = machine.run(case.kind, args)
        after = bytes(machine.memory.heap[:USED])
        start, end = OUT - HEAP_BASE, OUT - HEAP_BASE + OUT_SIZE
        if after[:start] + after[end:] != before[:start] + before[end:]:
            raise Halt("state changed outside the result")
        if case.kind == RATE:
            return before, ("xmm", machine.xmm[0] & MASK[8], self.log, ())
        if case.kind == RATE_INT:
            return before, ("rax", value, self.log, ())
        if value != OUT:
            raise Halt("result pointer")
        return before, ("out", after[start:end], self.log, ())


def base_records():
    rows = [
        ("empty market", record()),
        ("half used", record(a=50, b=100)),
        ("at the bend", record(a=80, b=100)),
        ("one unit above the bend", record(a=800000000000001, b=1000000000000000)),
        ("one unit below the bend", record(a=799999999999999, b=1000000000000000)),
        ("fully used", record(a=100, b=100)),
        ("borrow above supply", record(a=300, b=100)),
        ("min floor", record(a=1, b=10 ** 14, mn=2 * 10 ** 11)),
        ("rounding low arm", record(a=7, b=9, mn=123456789, kr=987654321012, k=33333333333333)),
        ("rounding high arm", record(a=8, b=9, kr=987654321012, mx=7777777777777, k=33333333333333)),
        ("bend below floor", record(a=1, b=10, mn=9 * 10 ** 12, kr=10 ** 12, k=5 * 10 ** 13)),
        ("bend equal to floor", record(a=1, b=10, mn=10 ** 12, kr=10 ** 12, k=5 * 10 ** 13)),
        ("top below bend", record(a=9, b=10, kr=9 * 10 ** 12, mx=10 ** 12, k=5 * 10 ** 13)),
        ("top equal to bend", record(a=9, b=10, kr=9 * 10 ** 12, mx=9 * 10 ** 12, k=5 * 10 ** 13)),
        ("kink zero, some use", record(a=1, b=4, kr=10 ** 12, mx=10 ** 13, k=0)),
        ("kink zero, no use", record(kr=10 ** 12, mx=10 ** 13, k=0)),
        ("kink at one", record(a=1, b=4, kr=10 ** 12, mx=10 ** 13, k=E14)),
        ("kink at one, fully used", record(a=5, b=4, kr=10 ** 12, mx=10 ** 13, k=E14)),
        ("kink past one", record(a=9, b=4, kr=10 ** 12, mx=10 ** 13, k=E14 + 5)),
        ("kink just below one", record(a=9, b=4, kr=10 ** 12, mx=10 ** 13, k=E14 - 1)),
        ("ceil adds one", record(a=3, ia=E14 + 1, b=1000000, ib=E14)),
        ("exact product no ceil", record(a=3, ia=2 * E14, b=1000000, ib=E14)),
        ("borrow index below one", record(a=3, ia=1, b=1, ib=E14)),
        ("supply floors to zero", record(a=3, b=1, ib=1)),
        ("no supply with debt", record(a=3, b=0)),
        ("no shares, index zero", record(a=0, ia=0, b=0, ib=0)),
        ("borrow product at the top word", record(a=TOP, ia=E14, b=TOP, ib=E14)),
        ("ceil crosses 2^64", record(a=1 << 63, ia=2 * E14 + 1, b=1 << 50, ib=E14)),
        ("ceil ends at 2^64", record(a=1 << 63, ia=2 * E14, b=1 << 50, ib=E14)),
        ("ceil ends at 2^64 minus one", record(a=TOP, ia=E14, b=1 << 50, ib=E14)),
        ("borrow overflow with supply overflow", record(a=TOP, ia=TOP, b=TOP, ib=TOP)),
        ("supply just fits", record(a=5, b=TOP, ib=E14)),
        ("supply one past the word", record(a=5, b=1 << 63, ib=2 * E14)),
        ("supply just past the word", record(a=5, b=1 << 63, ib=2 * E14 + 1)),
        ("quotient at 2^64", record(a=1 << 50, b=1, ib=610351562500, ia=E14)),
        ("ratio above the cap by far", record(a=10 ** 18, b=6 * 10 ** 12, ia=E14, ib=1)),
        ("ratio past 2^64", record(a=10 ** 19, b=1, ia=E14, ib=E14)),
        ("ratio just under 2^64", record(a=184467, b=1)),
        ("ratio at the cut", record(a=184468, b=1)),
        ("big rates", record(a=7, b=9, mn=TOP - 100, kr=TOP - 10, mx=TOP, k=5 * 10 ** 13)),
        ("big rates high", record(a=8, b=9, mn=0, kr=TOP - 100, mx=TOP, k=5 * 10 ** 13)),
        ("wide span", record(a=9, b=10, kr=0, mx=TOP, k=0)),
        ("wide span low", record(a=1, b=10, mn=0, kr=TOP, k=99 * 10 ** 12)),
        ("wide span floor one", record(a=1, b=10, mn=1, kr=TOP, k=5 * 10 ** 13)),
        ("supply product one below the guard", record(a=5, b=EDGE_LEFT, ib=EDGE_RIGHT)),
        ("supply product exactly at the guard", record(a=5, b=1 << 63, ib=2 * E14)),
    ]
    faults = [
        ("no borrow shares with a quotient", record(a=0, b=10), {0: 5}),
        ("no supply shares with a quotient", record(a=4, b=0), {1: 5}),
        ("no supply shares with a quotient, zero debt", record(a=0, b=0), {1: 5}),
        ("supply quotient with a high word", record(a=4, b=10), {1: (1 << 64) | 40}),
        ("supply quotient with only a high word", record(a=4, b=10), {1: 1 << 64}),
        ("both quotients zero", record(a=4, b=10), {0: 0, 1: 0}),
        ("low arm quotient high word", record(a=1, b=10), {3: 1 << 64}),
        ("low arm wide quotient", record(a=1, b=10, mn=0, kr=TOP, k=5 * 10 ** 13), {3: E14 * 3}),
        ("low arm guard edge", record(a=1, b=10, mn=0, kr=1 << 63, k=5 * 10 ** 13), {3: (E14 << 1) - 1}),
        ("low arm guard hit", record(a=1, b=10, mn=0, kr=1 << 63, k=5 * 10 ** 13), {3: E14 << 1}),
        ("low arm add wraps", record(a=1, b=10, mn=TOP - 2, kr=TOP, k=5 * 10 ** 13), {4: 3}),
        ("low arm add just fits", record(a=1, b=10, mn=TOP - 2, kr=TOP, k=5 * 10 ** 13), {4: 2}),
        ("high arm quotient high word", record(a=9, b=10), {3: 1 << 64}),
        ("high arm wide quotient", record(a=9, b=10, kr=0, mx=TOP, k=5 * 10 ** 13), {3: E14 * 3}),
        ("high arm guard edge", record(a=9, b=10, kr=0, mx=1 << 63, k=5 * 10 ** 13), {3: (E14 << 1) - 1}),
        ("high arm guard hit", record(a=9, b=10, kr=0, mx=1 << 63, k=5 * 10 ** 13), {3: E14 << 1}),
        ("high arm add wraps", record(a=9, b=10, kr=TOP - 2, mx=TOP, k=5 * 10 ** 13), {4: 3}),
        ("high arm add just fits", record(a=9, b=10, kr=TOP - 2, mx=TOP, k=5 * 10 ** 13), {4: 2}),
        ("high arm kink forced above u", record(a=9, b=10, k=10 ** 15), {2: E14 * 2}),
        ("low arm product at the guard", record(a=1, b=10, mn=0, kr=EDGE_RIGHT, k=5 * 10 ** 13), {3: EDGE_LEFT}),
        ("high arm product at the guard", record(a=9, b=10, kr=0, mx=EDGE_RIGHT, k=5 * 10 ** 13), {3: EDGE_LEFT}),
        ("error path, low arm product at the guard", record(a=0, b=10, mn=0, kr=EDGE_RIGHT, k=5 * 10 ** 13), {0: 5, 2: EDGE_LEFT}),
        ("error path, low arm product past the guard", record(a=0, b=10, mn=0, kr=EDGE_RIGHT + 1, k=5 * 10 ** 13), {0: 5, 2: EDGE_LEFT}),
        ("error path, low arm quotient high word", record(a=0, b=10, mn=0, kr=1 << 40, k=5 * 10 ** 13), {0: 5, 2: 1 << 64}),
        ("error path, low arm sum", record(a=0, b=10, mn=7, kr=11, k=5 * 10 ** 13), {0: 5, 2: E14 // 2}),
    ]
    return [(name, rec, {}) for name, rec in rows] + faults


KINDS = (RATE, RATE_INT, UTIL_WORD, UTIL_F64)


def named_cases():
    rows = []
    for kind in KINDS:
        for name, rec, faults in base_records():
            rows.append(Case(name, kind, rec=rec, faults=faults))
    return rows


def grid_cases():
    """Every small share pair, then a percent sweep across the bend on two curve shapes."""
    for a in range(0, 11):
        for b in range(0, 11):
            for kind in KINDS:
                yield Case("grid a=%d b=%d" % (a, b), kind, rec=record(a=a, b=b))
    configs = ((0, E14, 5 * 10 ** 12, 8 * 10 ** 13), (2 * 10 ** 12, 5 * 10 ** 13, 10 ** 13, 9 * 10 ** 13))
    for mn, mx, kr, k in configs:
        for percent in range(0, 201, 2):
            for kind in KINDS:
                yield Case("sweep %d/%d/%d/%d p=%d" % (mn, mx, kr, k, percent), kind, rec=record(a=percent, b=100, mn=mn, mx=mx, kr=kr, k=k))


def lcg(seed):
    state = seed
    while True:
        state = (state * 0x5851F42D4C957F2D + 0x14057B7EF767814F) & TOP
        yield state


def draw(stream):
    word = next(stream)
    kind = word & 7
    value = next(stream)
    if kind == 0:
        return value
    if kind == 1:
        return value >> (word >> 8 & 63)
    if kind == 2:
        return value % (2 * E14)
    if kind == 3:
        return E14 + (value % 2001) - 1000
    if kind == 4:
        return value % 1000
    if kind == 5:
        return (1 << (word >> 8 & 63)) + (value % 5) - 2 & TOP
    return value % (10 ** 18)


def vector_cases(count, seed=0x1234ABCD):
    stream = lcg(seed)
    for index in range(count):
        rec = record(a=draw(stream), ia=draw(stream), b=draw(stream), ib=draw(stream), mn=draw(stream), mx=draw(stream), kr=draw(stream), k=draw(stream))
        yield Case("v%d" % index, KINDS[index % 4], rec=rec)


def digest_of(outcome):
    kind, value, log, events = outcome
    text = value.hex() if isinstance(value, bytes) else str(value)
    return kind, hashlib.sha256(text.encode()).hexdigest()[:16], len(log), ",".join(events)


def check_stream(harness, cases, rows=None, keep_every=0, variant=frozenset()):
    """Run each case, compare at once, keep only counts and sampled rows."""
    count = 0
    for case in cases:
        before, got = harness.run(case)
        want = spec_run(case, before, variant)
        if got != want:
            raise EvidenceError("case disagrees with the rule list: %s %r %r" % (case.name, got, want))
        if rows is not None and (keep_every == 0 or count % keep_every == 0):
            rows.append(("%#x" % case.kind, case.name) + digest_of(got))
        count += 1
    return count


def first_failure(harness, cases, variant=frozenset()):
    for case in cases:
        try:
            before, got = harness.run(case)
            if got != spec_run(case, before, variant):
                return case
        except (Halt, EvidenceError, KeyError, IndexError, ValueError, OverflowError, ZeroDivisionError, struct.error, Panicked):
            return case
    return None


def run_value(harness, kind, rec):
    return harness.run(Case("probe", kind, rec=rec))[1]


def reciprocal_rows():
    rows = []
    for name, multiplier, shift, limit in (("rate_e10", MUL_RATE, SHIFT_RATE, 1 << 64), ("utilization_e10", MUL_UTIL, SHIFT_UTIL, E14 + 1)):
        spare = multiplier * E10 - (1 << shift)
        worst = (limit - 1) * spare
        if spare <= 0 or worst >= 1 << shift:
            raise EvidenceError("reciprocal bound fails for " + name)
        rows.append((name, "%#x" % multiplier, shift, spare, limit, worst, 1 << shift))
    return rows


def shadow_rows():
    """Largest quotient and product each arm can see, from the argument word limits alone."""
    rows = []
    rows.append(("low arm f", "u < k, so u*1e14/k < 1e14", E14 - 1, "below 2^64"))
    rows.append(("high arm f", "k < u <= 1e14 and (u-k)*1e14/(1e14-k) <= 1e14", E14, "below 2^64"))
    if E14 * TOP >= GUARD:
        raise EvidenceError("product guard is reachable")
    rows.append(("product", "f * (2^64-1) with f <= 1e14", E14 * TOP, "below 1e14*2^64"))
    rows.append(("sum", "base + floor(f*(end-base)/1e14) with f <= 1e14", "end", "below 2^64"))
    rows.append(("kink bound", "the high arm needs k < u <= 1e14", E14 - 1, "k never above 1e14-1 there"))
    return rows


def fault_only_rows(image, table, seen):
    rows = []
    for target in TARGETS:
        chosen = [row.va for row in table[target] if row.va not in seen and row.op not in ("int3", "nop")]
        rows.append((NAMES[target], len(chosen), " ".join("%#x" % va for va in chosen)))
    return rows


def curve_rows(harness):
    configs = ((0, E14, 5 * 10 ** 12, 8 * 10 ** 13), (2 * 10 ** 12, 5 * 10 ** 13, 10 ** 13, 9 * 10 ** 13))
    rows = []
    for mn, mx, kr, k in configs:
        for percent in (0, 25, 50, 75, 80, 90, 100, 150):
            rec = record(a=percent, b=100, mn=mn, mx=mx, kr=kr, k=k)
            word = run_value(harness, RATE_INT, rec)[1]
            value = run_value(harness, RATE, rec)[1]
            rows.append((mn, mx, kr, k, percent, word, repr(to_float(value))))
    return rows


def ratio_rows(harness):
    rows = []
    for name, a, b, ia, ib in (("half", 50, 100, E14, E14), ("full", 100, 100, E14, E14), ("over", 300, 100, E14, E14), ("no supply", 3, 0, E14, E14),
                               ("just under the cut", 184467, 1, E14, E14), ("at the cut", 184468, 1, E14, E14), ("supply past the word", 5, 1 << 63, E14, 2 * E14), ("borrow past the word", TOP, 1, TOP, E14)):
        rec = record(a=a, b=b, ia=ia, ib=ib, mn=1000 * E10, kr=2000 * E10, mx=5000 * E10, k=5 * 10 ** 13)
        rate = run_value(harness, RATE_INT, rec)[1]
        out = run_value(harness, UTIL_WORD, rec)[1]
        result = "err %d" % out[1] if out[0] else "ok %d" % struct.unpack_from("<Q", out, 8)[0]
        rows.append((name, a, b, rate, result, len(run_value(harness, UTIL_WORD, rec)[1])))
    return rows


def delta_rows(harness, cases):
    """Cases where the #94 rule list (switch old94) disagrees with the #115 bytes, with the first difference named."""
    rows = []
    for case in cases:
        before, got = harness.run(case)
        want = spec_run(case, before, frozenset(("old94",)))
        if got == want:
            continue
        if got[1] != want[1]:
            why = "result differs"
        else:
            why = "divide requests %d against %d" % (len(got[2]), len(want[2]))
        rows.append(("%#x" % case.kind, case.name, why, digest_of(got)[1], digest_of(want)[1]))
    return rows


def constant_rows(image, table):
    """Every rip-relative data load and every 64 bit immediate of the four bodies, read from the decoded rows."""
    rows = []
    for target in TARGETS:
        seen = set()
        for row in table[target]:
            for operand in (row.a, row.b):
                if operand and operand[0] == "m" and row.rip_at is not None and operand[1] is None and operand[2] is None and row.op != "calli":
                    va = operand[4]
                    if va in seen:
                        continue
                    seen.add(va)
                    bits = struct.unpack_from("<Q", image.blob, image.offset(va))[0]
                    rows.append((NAMES[target], "%#x" % row.va, "rip %#x" % va, repr(to_float(bits)), "%#x" % bits))
            if row.op == "mov" and row.size >= 10 and row.data[0] & 0xF8 == 0x48 and 0xB8 <= row.data[1] <= 0xBF:
                value = struct.unpack_from("<Q", row.data, 2)[0]
                rows.append((NAMES[target], "%#x" % row.va, "movabs", str(value), "%#x" % value))
    return rows


def site_rows(image):
    rows = []
    text_va, text = image.text_bytes()
    relative = image.relative()
    for name, slot, target in (("rate_f64", SLOT_RATE, RATE), ("utilization_f64", SLOT_UTIL_F64, UTIL_F64)):
        if relative.get(slot) != target:
            raise EvidenceError("slot does not hold the target: %#x" % slot)
        sites = []
        at = 0
        while True:
            at = text.find(b"\xff\x15", at)
            if at < 0:
                break
            if text_va + at + 6 + struct.unpack_from("<i", text, at + 2)[0] == slot:
                sites.append(text_va + at)
            at += 1
        rows.append((name, "%#x" % slot, "%#x" % target, "slot", " ".join("%#x" % site for site in sites)))
    for name, target in (("rate_e10", RATE_INT), ("utilization_e10", UTIL_WORD)):
        sites = []
        at = 0
        while True:
            at = text.find(b"\xe8", at)
            if at < 0 or at + 5 > len(text):
                break
            if text_va + at + 5 + struct.unpack_from("<i", text, at + 1)[0] == target:
                sites.append(text_va + at)
            at += 1
        rows.append((name, "-", "%#x" % target, "direct", " ".join("%#x" % site for site in sites)))
    sites = []
    at = 0
    while True:
        at = text.find(b"\xff\x15", at)
        if at < 0:
            break
        if text_va + at + 6 + struct.unpack_from("<i", text, at + 2)[0] == SLOT_DIV:
            sites.append(text_va + at)
        at += 1
    inside = {target: [s for s in sites if target <= s < image.exact_fde(target)[1]] for target in TARGETS}
    for target in TARGETS:
        rows.append((NAMES[target] + " divide calls", "%#x" % SLOT_DIV, "128 bit divide", "slot", " ".join("%#x" % s for s in inside[target])))
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


ERROR_PATH_ONLY = "movabs of 1e14 on the error path, where u is 0: it only multiplies 0 in the low arm, and the high arm that reads it is unreachable with u = 0"
EXPECTED_SURVIVORS = {(0x36A0C4E, "immediate"): ERROR_PATH_ONLY, (0x36A0EA0, "immediate"): ERROR_PATH_ONLY}


def run_mutants(image, table, seen, cases, extra):
    results = []
    control = Harness(image)
    control.machine.step_limit = MUTANT_STEP_LIMIT
    if first_failure(control, cases) is not None:
        raise EvidenceError("an unedited image fails under the mutant step limit")
    for target in TARGETS:
        chosen = [case for case in cases if case.kind == target]
        plain = [case for case in chosen + [c for c in extra if c.kind == target] if not case.faults]
        forced = [case for case in chosen if case.faults]
        for va, kind, patch in edits_for(image, table[target], seen):
            harness = Harness(image, patch)
            harness.machine.step_limit = MUTANT_STEP_LIMIT
            if first_failure(harness, plain) is not None:
                results.append((va, kind, "killed", "plain input"))
            elif first_failure(harness, forced) is not None:
                results.append((va, kind, "killed", "injected quotient only"))
            else:
                results.append((va, kind, "survived", EXPECTED_SURVIVORS.get((va, kind), "UNEXPLAINED")))
    return results


def structural_controls(image, harness, cases):
    """Controls that are not byte edits: a changed digest, an address that is no function, a slot that holds another target."""
    rows = []
    blob = bytearray(image.blob)
    blob[1000] ^= 1
    try:
        digest = hashlib.sha256(bytes(blob)).hexdigest()
        if digest == SHA256:
            raise AssertionError("digest unchanged")
        rows.append(("one flipped file byte changes the SHA-256", "detected"))
    except AssertionError:
        rows.append(("one flipped file byte changes the SHA-256", "MISSED"))
    for label, va in (("address inside a function", RATE_INT + 1), ("address before the body", RATE_INT - 1), ("address in .rodata", 0x459230), ("address past the file", 0x7FFFFFFFFF)):
        try:
            image.exact_fde(va)
            rows.append((label + " is refused as a function start", "MISSED"))
        except EvidenceError:
            rows.append((label + " is refused as a function start", "detected"))
    for label, slot, target in (("rate slot against the integer rate", SLOT_RATE, RATE_INT), ("utilization slot against the rate", SLOT_UTIL_F64, RATE)):
        rows.append((label + " is not a relative slot to that target", "detected" if image.relative().get(slot) != target else "MISSED"))
    probe = next(case for case in cases if case.name == "half used" and case.kind == RATE_INT)
    wrong = Case("wrong kind", UTIL_WORD, rec=probe.rec)
    before, got = harness.run(wrong)
    rows.append(("result of one entry compared with the rule of another", "detected" if got != spec_run(probe, before) else "MISSED"))
    return rows


def analyse(image, vectors=9500, mutate=True):
    harness = Harness(image)
    cases = named_cases()
    outcomes = []
    check_stream(harness, cases, outcomes)
    grid_rows = []
    grid_count = check_stream(harness, grid_cases(), grid_rows, keep_every=2)
    vector_rows = []
    vector_count = check_stream(harness, vector_cases(vectors), vector_rows, keep_every=5)
    seen = set(harness.machine.seen)
    table = {target: decode_range(image, *image.exact_fde(target)) for target in TARGETS}
    unreached = {target: [row.va for row in table[target] if row.va not in seen and row.op not in ("int3", "nop")] for target in TARGETS}
    plain_seen = set()
    probe = Harness(image)
    for case in cases + list(vector_cases(800)):
        if not case.faults:
            probe.run(case)
    plain_seen = set(probe.machine.seen)
    variants = []
    sample = cases + list(vector_cases(120, seed=0x77))
    for name in VARIANTS:
        failure = first_failure(harness, sample, frozenset((name,)))
        variants.append((name, "detected" if failure is not None else "MISSED", failure.name if failure else "-", "%#x" % failure.kind if failure else "-"))
    structural = structural_controls(image, harness, cases)
    result = dict(table=table, cases=cases, outcomes=outcomes, grid_rows=grid_rows, grid_count=grid_count, vector_rows=vector_rows, vector_count=vector_count,
                  unreached=unreached, sites=site_rows(image), constants=constant_rows(image, table), reciprocals=reciprocal_rows(), shadows=shadow_rows(),
                  curve=curve_rows(harness), ratios=ratio_rows(harness), fault_only=fault_only_rows(image, table, plain_seen), variants=variants, structural=structural,
                  delta=delta_rows(harness, cases))
    if mutate:
        extra = list(vector_cases(240))
        result["mutations"] = run_mutants(image, table, plain_seen | seen, cases, extra)
        unexplained = [row for row in result["mutations"] if row[3] == "UNEXPLAINED"]
        if unexplained:
            raise EvidenceError("unexplained survivors: %s" % [(hex(row[0]), row[1]) for row in unexplained])
    return result


def render(result):
    files = {}

    def tsv(name, header, rows):
        lines = ["\t".join(header)] + ["\t".join(str(cell) for cell in row) for row in rows]
        files[name] = "\n".join(lines) + "\n"

    tsv("function-rows.tsv", ("function", "address", "size", "bytes", "operation"),
        [("%#x" % target, "%#x" % row.va, row.size, row.data.hex(), row.op) for target in TARGETS for row in result["table"][target]])
    tsv("call-sites.tsv", ("function", "slot", "target", "form", "sites"), result["sites"])
    tsv("constants.tsv", ("function", "row", "form", "value", "bits"), result["constants"])
    tsv("reciprocals.tsv", ("divide", "multiplier", "shift", "spare", "inputs_below", "worst_error", "two_to_shift"), result["reciprocals"])
    tsv("shadowed-guards.tsv", ("value", "why", "largest", "bound"), result["shadows"])
    tsv("curve-samples.tsv", ("min_rate", "max_rate", "kink_rate", "kink_utilization", "borrowed_per_100_supplied", "rate_e10", "rate_f64"), result["curve"])
    tsv("ratio-edges.tsv", ("case", "borrowed", "supplied", "rate_e10", "utilization_e10", "result_bytes"), result["ratios"])
    tsv("fault-only-rows.tsv", ("function", "rows", "addresses"), result["fault_only"])
    tsv("delta-against-94-rules.tsv", ("entry", "case", "difference", "digest_115", "digest_94_rules"), result["delta"])
    tsv("model-variants.tsv", ("switch", "outcome", "first_case", "entry"), result["variants"])
    tsv("structural-controls.tsv", ("control", "outcome"), result["structural"])
    tsv("outcomes.tsv", ("entry", "case", "form", "result_digest", "divides", "events"), result["outcomes"])
    tsv("grid-outcomes.tsv", ("entry", "case", "form", "result_digest", "divides", "events"), result["grid_rows"])
    tsv("vector-outcomes.tsv", ("entry", "case", "form", "result_digest", "divides", "events"), result["vector_rows"])
    mutations = result.get("mutations", [])
    if mutations:
        tsv("mutations.tsv", ("address", "kind", "outcome", "detail"), [("%#x" % va, k, o, d) for va, k, o, d in mutations])
    killed = sum(1 for row in mutations if row[2] == "killed")
    variants_detected = sum(1 for row in result["variants"] if row[1] == "detected")
    structural_detected = sum(1 for row in result["structural"] if row[1] == "detected")
    total_cases = len(result["cases"]) + result["grid_count"] + result["vector_count"]
    controls = len(result["variants"]) + len(result["structural"]) + killed
    detected = variants_detected + structural_detected + killed
    summary = {
        "binary": "artifacts/node/115/hl-node", "sha256": SHA256,
        "functions": {NAMES[target]: {"address": "%#x" % target, "bytes": sum(row.size for row in result["table"][target]), "instructions": len(result["table"][target]),
                                      "unreached_rows": ["%#x" % va for va in result["unreached"][target]]} for target in TARGETS},
        "named_cases": len(result["cases"]), "grid_cases": result["grid_count"], "vector_cases": result["vector_count"], "delta_cases": len(result["delta"]),
        "model_variants": len(result["variants"]), "structural_controls": len(result["structural"]),
    }
    if mutations:
        summary["mutations"] = {"total": len(mutations), "killed": killed, "survived": sum(1 for r in mutations if r[2] == "survived"),
                                "injected_only": sum(1 for r in mutations if r[3] == "injected quotient only")}
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
