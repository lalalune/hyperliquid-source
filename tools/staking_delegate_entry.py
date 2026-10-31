#!/usr/bin/env python3
"""Pin node #94 tokenDelegate and CValidator entry paths: gates, self delegation floor rule, foundation lists, delegate event.

0x1e5fa70 and 0x2757fe0 refuse or build the mode row for tokenDelegate, 0x2768ff0 and 0x275aa60 take register and profile change,
0x33de710 and 0x33de620 give the per chain foundation sets, and 0x4856ca0 writes the delegate event in the third copy. The real
bytes of all three copies run under recording stubs over real B-tree nodes, a separately written rule list predicts every run,
and every reached conditional row, immediate and field offset is mutated. No objdump or readelf output is parsed and the binary
is never executed. Standard library only.

    python3 tools/staking_delegate_entry.py --out <dir>
"""

import argparse
import bisect
import hashlib
import json
import math
import multiprocessing
import pathlib
import random
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
HEAP_SIZE = 0x80000
RETURN_SENTINEL = 0xDEAD0000
POISON = 0xA5A5A5A5A5A5A5A5
STEP_LIMIT = 400000
MUTANT_STEP_LIMIT = 60000
WORKERS = 4


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
        elif byte not in (0x2E, 0xF0):
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
    if byte == 0x0F:
        two = window[pos]
        pos += 1
        if two == 0x0B:
            return finish("ud2")
        if two == 0x13 and not opsize:
            reg, rm = modrm(True)
            return finish("movlps", rm, ("x", reg), 8)
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
                  (0x74, True): "pcmpeqb", (0x76, True): "pcmpeqd", (0x14, False): "punpckldq", (0x14, True): "punpcklqdq", (0x6C, True): "punpcklqdq",
                  (0xDB, True): "andpd", (0xEB, True): "orpd", (0x58, True): "addpd", (0x5E, True): "divpd"}
        if (two, opsize) in vector:
            reg, rm = modrm(True)
            return finish(vector[(two, opsize)], ("x", reg), rm, 16)
        if two in (0x58, 0x59, 0x5C, 0x5D, 0x5E, 0x5F) and repne:
            reg, rm = modrm(True)
            return finish({0x58: "addsd", 0x59: "mulsd", 0x5C: "subsd", 0x5D: "minsd", 0x5E: "divsd", 0x5F: "maxsd"}[two], ("x", reg), rm, 8)
        if two == 0x51 and repne:
            reg, rm = modrm(True)
            return finish("sqrtsd", ("x", reg), rm, 8)
        if two == 0xD4 and opsize:
            reg, rm = modrm(True)
            return finish("paddq", ("x", reg), rm, 16)
        if two == 0xD6 and opsize:
            reg, rm = modrm(True)
            return finish("movq", rm, ("x", reg), 8)
        if two in (0xB0, 0xB1, 0xC0, 0xC1):
            reg, rm = modrm()
            return finish("cold", rm, ("r", reg), 1 if two in (0xB0, 0xC0) else width)
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
        if two == 0xA3:
            reg, rm = modrm()
            return finish("btr", rm, ("r", reg), width)
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

    def reset(self, used=None):
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
        if not count:
            return b""
        buffer, at = self.locate(addr, count)
        if buffer is not None:
            return bytes(buffer[at:at + count])
        if addr in self.statics:
            return (self.statics[addr] & ((1 << 8 * count) - 1)).to_bytes(count, "little")
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
        self.hops = {}
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
            hop = self.hops.get(pc)
            if hop:
                pc = hop(self)
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
            hook = self.calls.get(row.target)
            if hook:
                self.stub(hook)
                return self.pop()
            return row.target
        elif op == "jmpi":
            target = self.get(row.a, 8)
            hook = self.slots.get(target)
            if hook:
                self.stub(hook)
                return self.pop()
            return target
        elif op == "btr":
            self.cf = bool(self.get(row.a, width) >> (self.get(row.b, width) & (8 * width - 1)) & 1)
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
        elif op == "imul1":
            left = self.regs[RAX] - (1 << 64) if self.regs[RAX] & SIGN[8] else self.regs[RAX]
            value = self.get(row.a, 8)
            product = left * (value - (1 << 64) if value & SIGN[8] else value)
            self.regs[RAX] = product & MASK[8]
            self.regs[RDX] = (product >> 64) & MASK[8]
            self.cf = self.of = not -(1 << 63) <= product < 1 << 63
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
        elif op == "movlps":
            self.memory.write(self.address(row.a), 8, self.xmm[row.b[1]] & MASK[8])
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
                result = left / right
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
        elif op == "subpd":
            right = self.vector(row.b)
            left = self.xmm[row.a[1]]
            low = to_float(left & MASK[8]) - to_float(right & MASK[8])
            high = to_float(left >> 64) - to_float(right >> 64)
            self.xmm[row.a[1]] = to_bits(low) | to_bits(high) << 64
        elif op == "andpd":
            self.xmm[row.a[1]] &= self.vector(row.b)
        elif op == "orpd":
            self.xmm[row.a[1]] |= self.vector(row.b)
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
        elif op == "cvttsd2si":
            value = to_float(self.low(row.b))
            if value != value or not -9223372036854775808.0 <= value < 9223372036854775808.0:
                self.put(row.a, 8, 1 << 63)
            else:
                self.put(row.a, 8, int(value))
        elif op == "divpd":
            left, right = self.xmm[row.a[1]], self.vector(row.b)
            self.xmm[row.a[1]] = to_bits(to_float(left & MASK[8]) / to_float(right & MASK[8])) | to_bits(to_float(left >> 64) / to_float(right >> 64)) << 64
        elif op == "sqrtsd":
            self.set_low(row.a[1], to_bits(math.sqrt(to_float(self.low(row.b)))))
        elif op == "paddq":
            left, right = self.xmm[row.a[1]], self.vector(row.b)
            self.xmm[row.a[1]] = ((left & MASK[8]) + (right & MASK[8])) & MASK[8] | (((left >> 64) + (right >> 64)) & MASK[8]) << 64
        elif op == "movmskpd":
            value = self.xmm[row.b[1]]
            self.put(row.a, 4, int(bool(value >> 63 & 1)) | int(bool(value >> 127 & 1)) << 1)
        else:
            raise Halt("unmodelled operation %s at %#x" % (op, row.va))

    def vector(self, operand):
        if operand[0] == "x":
            return self.xmm[operand[1]]
        return int.from_bytes(self.memory.bytes_at(self.address(operand), 16), "little")


def wrap32(value):
    value &= MASK[4]
    return value - (1 << 32) if value & SIGN[4] else value


WRAP_A = 0x1E5FA70
WRAP_B = 0x46774D0
WRAP_C = 0x4677420
GATE_A = 0x2757FE0
GATE_B = 0x4D80870
GATE_C = 0x4D80BC0
HOST_A = 0x2768FF0
HOST_B = 0x4D9E0D0
HOST_C = 0x4D9DCD0
SELF_A = 0x275AA60
SELF_B = 0x4D85FF0
BALANCE = 0x39963E0
SET_A = 0x284BB50
SET_B = 0x49277E0
EVENT = 0x4856CA0
LIST_V = 0x33DE710
LIST_S = 0x33DE620
STAMP = 0x3996230
TARGETS = (WRAP_A, WRAP_B, WRAP_C, GATE_A, GATE_B, GATE_C, HOST_A, HOST_B, HOST_C, SELF_A, SELF_B, BALANCE, SET_A, SET_B, EVENT, LIST_V, LIST_S, STAMP)
NAMES = {WRAP_A: "token_delegate_wrapper", WRAP_B: "token_delegate_wrapper_b", WRAP_C: "token_delegate_wrapper_c", GATE_A: "token_delegate_gate", GATE_B: "token_delegate_gate_b", GATE_C: "token_delegate_gate_c",
         HOST_A: "c_validator_host", HOST_B: "c_validator_host_b", HOST_C: "c_validator_host_c", SELF_A: "register_self_delegate", SELF_B: "register_self_delegate_b", BALANCE: "staking_balance", SET_A: "set_contains", SET_B: "set_contains_b",
         EVENT: "delegate_event", LIST_V: "foundation_validators", LIST_S: "foundation_self_signers", STAMP: "long_term_lock_stamp"}
SLOT_COMPARE = 0x576E488
SLOT_CORE = 0x5774D20
SLOT_LIST_V = 0x5774D28
SLOT_LIST_S = 0x57732E8
SLOT_TIME_ADD = 0x576EFB8
SLOT_PROFILE = 0x5774DE0
SLOT_BALANCE = 0x5774DE8
SLOT_EVENT = 0x5776B20
SLOT_CLOCK = 0x576E8A0
SLOT_ONCE = 0x576E8B8
SLOT_UNWRAP = 0x576E470
SLOT_CHAIN_PANIC = 0x576E098
DROP_A = 0x277EBA0
DROP_B = 0x4DAF4A0
DROP_MISSING = 0x3999770
CLONE_A = 0x27ADD60
CLONE_B = 0x4DF23A0
BLOCK_HASH = 0x3987CB0
SINK = 0x47ED710
USER_ENTRY = 0x33BC0A0
FRESH_ROW = HEAP_BASE + 0x3F0
LOCK_TABLE = 0x207150
SHORT = 300.0
MARK_BASE = 0x7700000000
OK = 0x186
GUARD = 0xCCCCCCCCCCCCCCC
YEAR = 31557600.0
UNREGISTER = 0x8000000000000001
CHANGE = 0x8000000000000000
EVENT_KIND = 0x8000000000000001
POWER_TABLE = 0x584B08
CHAIN_TEXT = 0x58C1CA
JUMP_TABLE = 0x58A6B4
TOP = MASK[8]
HANDLE = HEAP_BASE + 0x100
USER = HEAP_BASE + 0x140
VALIDATOR = HEAP_BASE + 0x180
ACTION = HEAP_BASE + 0x200
OUTPUT = HEAP_BASE + 0x400
TOKENS = HEAP_BASE + 0x800
EX = HEAP_BASE + 0x1000
NODES = HEAP_BASE + 0x5000
USED = 0x40000
FILL = 0xCC
EX_SIZE = 0x3E20
E_BLOCK = 0x0
E_BLOCK_A = 0x8
E_BLOCK_B = 0x28
E_NOW = 0x60
E_TAG = 0x80
E_TOKEN = 0x88
E_META = 0x90
E_TABLE = 0x210
E_COUNT = 0x218
E_LEDGER = 0x5B8
L_SINK = 0x808
L_WORDS = 0xA60
L_BYTE = 0xA78
TOKEN_ROW = 0xE8
ROW_DECIMALS = 0x49
S_SHIFT = 0x8F8
F_CHAIN = 0x8F2
F_ALLOWED = 0xA18
F_REQUIRED = 0xB38
F_STATES = 0xB70
F_ALLOW_ALL = 0xB88
F_USERS = 0xAF0


class Copy:
    def __init__(self, wrap, gate, host, helper, shift, drop, clone, contains):
        self.wrap, self.gate, self.host, self.helper, self.shift, self.drop, self.clone, self.contains = wrap, gate, host, helper, shift, drop, clone, contains


COPIES = (Copy(WRAP_A, GATE_A, HOST_A, SELF_A, 0, DROP_A, CLONE_A, SET_A), Copy(WRAP_B, GATE_B, HOST_B, SELF_B, 0, DROP_B, CLONE_B, SET_B), Copy(WRAP_C, GATE_C, HOST_C, None, 0xA80, DROP_B, CLONE_B, SET_B))


class Layout:
    def __init__(self, key_size, val_size, val_at, key_at, len_at, edge_at, parent_at, slot_at):
        self.key_size, self.val_size, self.val_at, self.key_at = key_size, val_size, val_at, key_at
        self.len_at, self.edge_at, self.parent_at, self.slot_at = len_at, edge_at, parent_at, slot_at
        self.size = edge_at + 12 * 8


SET_MAP = Layout(20, 0, 0xE4, 8, 0xE6, 0xE8, 0, 0xE4)
STATE_MAP = Layout(20, 0x1C, 0xE4, 8, 0x21A, 0x220, 0, 0x218)
USER_MAP = Layout(20, 0x18, 8, 0x110, 0x1EE, 0x1F0, 0, 0x1EC)
LISTS = {
    1: ("0x57861d8", "0x3432aa0", ("7db9972a235370a311d0ae3dfc545a954c786599", "a40cf273de4f77278b911dd4c6a023d60647d979", "a89a7f8ab7bcf9c57542e22dc0e4b768b0101762", "f027b2abfa8de836d8cdcce22af88bb8aacef849")),
    2: ("0x57861f8", "0x34327e0", ("172054cfc01b32effe0bf6af7a15b36e1ad730b3", "3c83a5cae32a05e88ca6a0350edb540194851a76", "4dbf394da4b348b88e8090d22051af83e4cbaef4", "946bf3135c7d15e4462b510f74b6e304aabb5b21")),
    3: ("0x5786218", "0x34328b0", ("5ac99df645f3414876c816caa18b2d234024b487", "80f0cd23da5bf3a0101110cfd0f89c8a69a1384d", "a82fe73bbd768bc15d1ef2f6142a21ff8bd762ad", "df35aee8ef5658686142acd1e5ab5dbcdf8c51e8")),
}
EXTRA_VALIDATOR = "66be52ec79f829cc88e5778a255e2cb9492798fd"
EXTRA_SIGNER = "5795ab6e71ecbefa255fc4728cc34893ba992d44"
LIST_CELLS = {(1, 0): (0x57861D8, 0x57861F0), (2, 0): (0x57861F8, 0x5786210), (3, 0): (0x5786218, 0x5786230), (3, 1): (0x5786238, 0x5786250)}
CELLS = {1: 0x57861D8, 2: 0x57861F8, 3: 0x5786238}
STATUS = {1: 0x57861F0, 2: 0x5786210, 3: 0x5786250}


def members(chain):
    if chain == 3:
        return tuple(bytes.fromhex(text) for text in sorted(LISTS[3][2] + (EXTRA_VALIDATOR,)))
    return tuple(bytes.fromhex(text) for text in LISTS[chain][2])


def address_of(index):
    return bytes([0x20 + index % 0x60]) + bytes((0xA0 + index + at * 5) & 0xFF for at in range(18)) + bytes([index & 0xFF])


def signed32(value):
    return value - (1 << 32) if value >> 31 else value


def time_order(key):
    return (signed32(key[0]), key[1], key[2])


def capacity(height):
    return 12 ** (height + 1) - 1


def user_tail(key):
    return bytes((key[19] + at) & 0xFF for at in range(16))


class Panic(Exception):
    pass


class Case:
    FIELDS = dict(copy=0, kind="token", mode=0, wei=100, user=address_of(1), validator=address_of(2), tag=1, chain=3, required=1000, allow_all=1, allowed=(), states=(), users=(), lock=(0x50000000, 1, 1), now=(0x40000000, 1000, 500), lazy=False, core=OK,
                  flag=1, word0=8, ip_tag=0, patch=2, disabled=0, profile=OK, set_extra=(), sink_off=False, token=150, count=200, decimals=8, block=0, sink_byte=7)

    def __init__(self, name, **fields):
        self.name = name
        unknown = set(fields) - set(self.FIELDS)
        if unknown:
            raise EvidenceError("unknown field %s" % sorted(unknown))
        for key, value in self.FIELDS.items():
            setattr(self, key, fields.get(key, value))


def payload(status):
    return bytes((status + at * 3) & 0xFF for at in range(0x5E))


class Spec:
    """Rule list of one action; written from the rules, shares no code with the harness tree walks."""

    def __init__(self, case):
        self.case = case
        self.events = []

    def core(self, tag, value, wei, user, validator):
        c = self.case
        self.events.append(("core", tag, value, wei, c.now, user, validator, c.chain))
        return c.core

    def foundation(self, key):
        c = self.case
        if c.chain == 0:
            raise Panic("invalid chain")
        if c.lazy:
            self.events.append(("once", c.chain))
        return key in set(members(c.chain)) | set(c.set_extra)

    def gate(self, mode, wei, user, validator):
        c = self.case
        if c.tag & MASK[4] != 1:
            return 0xFB
        self.events.append(("drop", 0xFB))
        if wei == 0:
            return 0x32
        if mode == 0:
            tag, value = 2, 0
        elif mode != 1:
            tag, value = 1, mode
        elif user != validator:
            tag, value = 0, 0
        else:
            tag = 0
            rows = dict(c.states)
            if validator not in rows:
                return 0x91
            self.events.append(("drop", 0x91))
            if self.foundation(validator):
                value = c.required
            else:
                self.events.append(("add_year", rows[validator]))
                value = 0 if time_order(c.lock) < time_order(c.now) else c.required
        status = self.core(tag, value, wei, user, validator)
        if status == OK and c.copy == 2 and not c.sink_off:
            self.event(mode, wei, user, validator)
        return status

    def event(self, mode, wei, user, validator):
        c = self.case
        self.events.append(("clock",))
        if c.block & MASK[4] == 1:
            self.events.append(("block", c.chain))
        if c.token >= c.count:
            raise Panic("unwrap")
        amount = to_bits(float(wei) / float(10 ** c.decimals))
        self.events.append(("sink", c.sink_byte, amount, user, validator, int(mode != 0), c.block & MASK[4] == 1, c.now))

    def token(self):
        c = self.case
        if c.wei >= GUARD:
            return ("failed", 0x13F, c.wei)
        status = self.gate(c.mode, c.wei, c.user, c.validator)
        if status == OK:
            return ("applied",)
        if self.core_failed():
            return ("failed", status, payload(status))
        return ("failed", status)

    def core_failed(self):
        return any(event[0] == "core" for event in self.events)

    def host(self):
        c = self.case
        if c.word0 == UNREGISTER:
            return ("status", 0x8E)
        if not c.allow_all & 0xFF and c.user not in set(c.allowed):
            return ("status", 0x94)
        local = int(c.chain == 0)
        if c.word0 >> 63:
            if c.patch != 2 and c.patch & 1 != local:
                return ("status", 0x8E)
        else:
            if (c.ip_tag ^ local) & 1:
                return ("status", 0x8E)
            if c.wei >= GUARD:
                return ("status", 0x13F, c.wei)
            if c.required | c.wei:
                if c.disabled:
                    return ("status", 0xFD)
                if c.tag & 0xFF == 0:
                    return ("status", 0xFB)
                self.events.append(("drop", 0xFB))
                if c.wei < c.required:
                    return ("status", 0x130)
                if dict(c.users).get(c.user, 0) < c.wei:
                    return ("status", 0xFC)
        self.events.append(("clone",))
        self.events.append(("profile", c.chain, c.now, c.user))
        if c.profile != OK:
            return ("status", c.profile, payload(c.profile))
        if c.word0 >> 63 or c.wei == 0:
            return ("status", OK)
        if c.copy == 2:
            status = self.gate(0, c.wei, c.user, c.user)
        elif c.tag & MASK[4] != 1:
            status = 0xFB
        else:
            self.events.append(("drop", 0xFB))
            status = self.core(2, 0, c.wei, c.user, c.user)
        if status != OK:
            self.events.append(("drop", status))
        return ("status", OK)


def spec_stamp(case):
    if not case.flag:
        return (("stamp", None, None), ())
    seconds = SHORT if case.chain in (1, 2) else YEAR
    rows = dict(case.users)
    return (("stamp", case.user in rows, case.lock), (("add_seconds", to_bits(seconds), case.now), ("entry", case.user)))


def spec_list(case):
    if case.chain == 0:
        return (("panic", "invalid chain"), ())
    cell, word = LIST_CELLS[(case.chain, case.mode & (case.chain == 3))]
    return (("list", cell), (("once_word", word),) if case.lazy else ())


def spec_run(case):
    if case.kind == "stamp":
        return spec_stamp(case)
    if case.kind == "list":
        return spec_list(case)
    spec = Spec(case)
    try:
        result = spec.token() if case.kind == "token" else spec.host()
    except Panic as caught:
        result = ("panic", str(caught))
    return (result, tuple(spec.events))


class Harness:
    def __init__(self, image, patches=None):
        self.image = image
        machine = Machine(image, patches)
        self.machine = machine
        machine.real = frozenset(TARGETS)
        statics = machine.memory.statics
        hooks = {SLOT_COMPARE: self.on_compare, SLOT_CORE: self.on_core, SLOT_TIME_ADD: self.on_time_add, SLOT_PROFILE: self.on_profile, SLOT_CLOCK: self.on_clock, SLOT_ONCE: self.on_once, SLOT_UNWRAP: self.on_unwrap, SLOT_CHAIN_PANIC: self.on_chain_panic}
        for slot, hook in hooks.items():
            marker = MARK_BASE + slot
            statics[slot] = marker
            machine.slots[marker] = hook
        for slot, target in ((SLOT_LIST_V, LIST_V), (SLOT_LIST_S, LIST_S), (SLOT_BALANCE, BALANCE), (SLOT_EVENT, EVENT)):
            statics[slot] = target
        machine.calls = {USER_ENTRY: self.on_entry, DROP_A: self.on_drop, DROP_B: self.on_drop, DROP_MISSING: self.on_drop, CLONE_A: self.on_clone, CLONE_B: self.on_clone, BLOCK_HASH: self.on_block, SINK: self.on_sink}
        self.case = None

    def expect(self, condition, text):
        if not condition:
            raise Halt("stub check failed: " + text)

    def bytes_at(self, addr, size):
        return self.machine.memory.bytes_at(addr, size)

    def word(self, at, value, size=8):
        self.machine.memory.write(at, size, value & MASK[8])

    def read(self, at, size=8):
        return self.machine.memory.read(at, size)

    def time_at(self, at):
        return (self.read(at, 4), self.read(at + 4, 4), self.read(at + 8, 4))

    def on_unwrap(self, machine):
        raise Panicked("unwrap")

    def on_chain_panic(self, machine):
        regs = machine.regs
        self.expect(regs[RDI] == CHAIN_TEXT and regs[RSI] == 0x1B, "panic text")
        raise Panicked("invalid chain")

    def on_compare(self, machine):
        regs = machine.regs
        size = regs[RDX]
        self.expect(size == 20, "compare length")
        left, right = self.bytes_at(regs[RDI], size), self.bytes_at(regs[RSI], size)
        result = 0 if left == right else 0x1234 if left > right else -0x1234
        regs[RAX] = (0x5A5A5A5A << 32) | result & MASK[4]

    def fail_out(self, out, status):
        self.word(out, status, 2)
        self.machine.memory.put_bytes(out + 2, payload(status))

    def on_core(self, machine):
        regs = machine.regs
        c = self.case
        self.expect(regs[RSI] == EX + S_SHIFT + COPIES[c.copy].shift, "core state")
        row = regs[RDX]
        self.events.append(("core", self.read(row), self.read(row + 8), self.read(row + 0x10), self.time_at(row + 0x18), self.bytes_at(row + 0x24, 20), self.bytes_at(row + 0x38, 20), self.read(row + 0x4C, 1)))
        if c.core == OK:
            self.word(regs[RDI], OK, 2)
        else:
            self.fail_out(regs[RDI], c.core)

    def on_drop(self, machine):
        self.events.append(("drop", self.read(machine.regs[RDI], 2)))

    def on_entry(self, machine):
        regs = machine.regs
        entry = regs[RDI]
        holder = EX + S_SHIFT + 0x1F8
        rows = dict(self.case.users)
        key = self.case.user
        if key in rows:
            self.expect(self.read(entry) == 0 and self.read(entry + 0x20) == holder, "occupied entry")
            node, index = self.read(entry + 8), self.read(entry + 0x18)
            self.expect(self.bytes_at(node + USER_MAP.key_at + 20 * index, 20) == key, "occupied key")
            regs[RAX] = node + USER_MAP.val_at + USER_MAP.val_size * index
        else:
            self.expect(self.read(entry) == holder and self.bytes_at(entry + 0x20, 20) == key, "vacant entry")
            self.expect(self.read(entry + 8) == 0 if not rows else self.read(entry + 0x10) == 0, "vacant handle")
            regs[RAX] = FRESH_ROW
        self.value_at = regs[RAX]
        self.events.append(("entry", key))

    def on_time_add(self, machine):
        regs = machine.regs
        if self.case.kind == "stamp":
            self.events.append(("add_seconds", machine.xmm[0] & MASK[8], self.time_at(regs[RSI])))
            for at, value in enumerate(self.case.lock):
                self.word(regs[RDI] + 4 * at, value, 4)
            return
        self.expect(machine.xmm[0] & MASK[8] == to_bits(YEAR), "seconds argument")
        self.events.append(("add_year", self.time_at(regs[RSI])))
        for at, value in enumerate(self.case.lock):
            self.word(regs[RDI] + 4 * at, value, 4)

    def on_once(self, machine):
        regs = machine.regs
        chain = self.case.chain
        if self.case.kind == "list":
            self.expect(regs[RSI] & MASK[4] == 1, "once arguments")
            self.events.append(("once_word", regs[RDI]))
            return
        self.expect(regs[RDI] == STATUS[chain] and regs[RSI] & MASK[4] == 1, "once arguments")
        self.events.append(("once", chain))
        self.machine.memory.statics[STATUS[chain]] = 0
        self.install(chain)

    def on_clone(self, machine):
        regs = machine.regs
        self.expect(regs[RSI] == ACTION, "clone source")
        self.word(regs[RDI], 0xC1C1C1C1C1C1C1C1)
        self.clone_at = regs[RDI]
        self.events.append(("clone",))

    def on_profile(self, machine):
        regs = machine.regs
        c = self.case
        self.expect(regs[RSI] == EX + S_SHIFT + COPIES[c.copy].shift and regs[R9] == self.clone_at and self.read(regs[R9]) == 0xC1C1C1C1C1C1C1C1, "profile arguments")
        self.expect(self.bytes_at(regs[R8], 20) == c.user, "profile user")
        self.events.append(("profile", regs[RDX] & 0xFF, self.time_at(regs[RCX]), self.bytes_at(regs[R8], 20)))
        if c.profile == OK:
            self.word(regs[RDI], OK, 2)
        else:
            self.fail_out(regs[RDI], c.profile)

    def on_clock(self, machine):
        self.events.append(("clock",))
        for at, value in enumerate((0x7777, 0x8888, 0x9999)):
            self.word(machine.regs[RDI] + 4 * at, value, 4)

    def on_block(self, machine):
        regs = machine.regs
        c = self.case
        self.expect(regs[RSI] & 0xFF == c.chain and regs[RCX] == 0xB10C and regs[RDX] == 0xB20C and regs[R8] & MASK[4] == 0, "block arguments")
        self.events.append(("block", c.chain))
        self.machine.memory.put_bytes(regs[RDI], bytes(range(0x40, 0x60)))

    def on_sink(self, machine):
        regs = machine.regs
        c = self.case
        ledger = EX + E_LEDGER
        self.expect(regs[RDI] == ledger + L_SINK and self.time_at(regs[RDX]) == (0x7777, 0x8888, 0x9999), "sink head")
        self.expect(self.bytes_at(regs[R8], 0x18) == bytes(range(0x18)), "sink words")
        record = regs[RCX]
        self.expect(self.read(record) == EVENT_KIND, "event kind")
        block = self.bytes_at(record + 0xC8, 32)
        self.expect(block == (bytes(range(0x40, 0x60)) if c.block & MASK[4] == 1 else bytes(32)), "block words")
        self.events.append(("sink", regs[RSI] & 0xFF, self.read(record + 8), self.bytes_at(record + 0x10, 20), self.bytes_at(record + 0x24, 20), self.read(record + 0x38, 1), c.block & MASK[4] == 1, self.time_at(record + 0xE8)))

    def walk(self, layout, root, height):
        found = []
        if not root:
            return found
        count = self.read(root + layout.len_at, 2)
        for at in range(count):
            if height:
                found.extend(self.walk(layout, self.read(root + layout.edge_at + 8 * at), height - 1))
            found.append((root, at))
        if height:
            found.extend(self.walk(layout, self.read(root + layout.edge_at + 8 * count), height - 1))
        return found

    def node(self, layout, items, children):
        base = self.next_node
        self.next_node += layout.size + 0x10
        self.expect(self.next_node < HEAP_BASE + USED, "node area")
        memory = self.machine.memory
        memory.put_bytes(base, bytes([FILL]) * (layout.size + 0x10))
        for at, (key, value) in enumerate(items):
            memory.put_bytes(base + layout.key_at + layout.key_size * at, key)
            if layout.val_size:
                memory.put_bytes(base + layout.val_at + layout.val_size * at, value)
        for at in range(len(items), 11):
            if layout.val_size:
                memory.put_bytes(base + layout.val_at + layout.val_size * at, b"\xFF" * layout.val_size)
            memory.put_bytes(base + layout.key_at + layout.key_size * at, bytes(layout.key_size))
        self.word(base + layout.len_at, len(items), 2)
        self.word(base + layout.parent_at, 0)
        for slot, child in enumerate(children):
            self.word(base + layout.edge_at + 8 * slot, child)
            self.word(child + layout.parent_at, base)
            self.word(child + layout.slot_at, slot, 2)
        return base

    def build(self, layout, items, height):
        if height == 0:
            return self.node(layout, items, ())
        size = len(items)
        parts = 2
        while (size - parts + 1) / parts > capacity(height - 1):
            parts += 1
        low = (size - parts + 1) // parts
        extra = (size - parts + 1) - low * parts
        children, separators, at = [], [], 0
        for part in range(parts):
            take = low + (1 if part < extra else 0)
            children.append(self.build(layout, items[at:at + take], height - 1))
            at += take
            if part < parts - 1:
                separators.append(items[at])
                at += 1
        return self.node(layout, separators, children)

    def tree(self, layout, items):
        items = sorted(items)
        if not items:
            return 0, 0xB1B1, 0
        height = 0
        while capacity(height) < len(items):
            height += 1
        return self.build(layout, items, height), height, len(items)

    def holder(self, at, layout, items):
        for place, value in enumerate(self.tree(layout, items)):
            self.word(at + 8 * place, value)

    def install(self, chain):
        c = self.case
        root, height, count = self.tree(SET_MAP, [(key, b"") for key in sorted(set(members(chain)) | set(c.set_extra))])
        statics = self.machine.memory.statics
        statics[CELLS[chain]], statics[CELLS[chain] + 8], statics[CELLS[chain] + 0x10] = root, height, count

    def fresh(self, case):
        memory = self.machine.memory
        memory.reset(USED)
        memory.put_bytes(EX, bytes([FILL]) * EX_SIZE)
        memory.put_bytes(ACTION, bytes((0x90 + at) & 0xFF for at in range(0x70)))
        memory.put_bytes(OUTPUT, bytes([0xEE]) * 0x80)
        self.next_node = NODES
        self.case = case
        self.events = []
        self.clone_at = None
        copy = COPIES[case.copy]
        shift = copy.shift
        for at, value in enumerate(case.now):
            self.word(EX + E_NOW + 4 * at, value, 4)
        self.word(EX + E_TAG, case.tag)
        self.word(EX + E_TOKEN, case.token)
        self.word(EX + E_TABLE, TOKENS - TOKEN_ROW * case.token)
        self.word(EX + E_COUNT, case.count)
        self.word(TOKENS + ROW_DECIMALS, case.decimals, 1)
        self.word(EX + E_BLOCK, case.block, 4)
        self.word(EX + E_BLOCK_A, 0xB10C)
        self.word(EX + E_BLOCK_B, 0xB20C)
        self.word(EX + F_CHAIN + shift, case.chain, 1)
        self.word(EX + F_REQUIRED + shift, case.required)
        self.word(EX + F_ALLOW_ALL + shift, case.allow_all, 1)
        ledger = EX + E_LEDGER
        if case.sink_off:
            self.word(ledger + L_SINK, 1 << 63)
        else:
            self.word(ledger + L_SINK, 0x1234)
        self.word(ledger + L_BYTE, case.sink_byte, 1)
        memory.put_bytes(ledger + L_WORDS, bytes(range(0x18)))
        memory.put_bytes(USER, case.user)
        memory.put_bytes(VALIDATOR, case.validator)
        self.holder(EX + F_ALLOWED + shift, SET_MAP, [(key, b"") for key in case.allowed])
        self.holder(EX + F_STATES + shift, STATE_MAP, [(key, struct.pack("<III", *when) + bytes(range(0x30, 0x40))) for key, when in case.states])
        self.holder(EX + F_USERS + shift, USER_MAP, [(key, struct.pack("<Q", amount) + user_tail(key)) for key, amount in case.users])
        statics = memory.statics
        for chain, cell in CELLS.items():
            statics[STATUS[chain]] = 0
        if case.chain in CELLS:
            if case.lazy:
                statics[STATUS[case.chain]] = 1
                statics[CELLS[case.chain]], statics[CELLS[case.chain] + 8] = 0x5151515151515151, 0x5252525252525252
            else:
                self.install(case.chain)
        self.frozen_digest = hashlib.sha256(self.bytes_at(EX, EX_SIZE)).digest()

    def fill_action(self, case):
        memory = self.machine.memory
        if case.kind == "token":
            self.word(ACTION + 0x20, case.wei)
            memory.put_bytes(ACTION + 0x30, case.validator)
            self.word(ACTION + 0x45, case.mode, 1)
        else:
            self.word(ACTION, case.word0)
            self.word(ACTION + 0x4C, case.ip_tag, 1)
            self.word(ACTION + 0x51, case.disabled, 1)
            self.word(ACTION + 0x58, case.wei)
            if case.word0 >> 63:
                self.word(ACTION + 0x5E, case.patch, 1)

    def result(self, case):
        self.expect(hashlib.sha256(self.bytes_at(EX, EX_SIZE)).digest() == self.frozen_digest, "bytes of the state")
        if case.kind == "token":
            tag = self.read(OUTPUT, 1)
            if tag == 0xD:
                return ("applied",)
            self.expect(tag == 0xE, "outer tag")
            status = self.read(OUTPUT + 8, 2)
            if status == 0x13F:
                return ("failed", status, self.read(OUTPUT + 0x10))
            if any(event[0] == "core" for event in self.events):
                return ("failed", status, self.bytes_at(OUTPUT + 10, 0x5E))
            return ("failed", status)
        status = self.read(OUTPUT, 2)
        if status == 0x13F:
            return ("status", status, self.read(OUTPUT + 8))
        if status == case.profile and status != OK and not any(event[0] == "core" for event in self.events):
            return ("status", status, self.bytes_at(OUTPUT + 2, 0x5E))
        return ("status", status)

    def run_stamp(self, case):
        memory = self.machine.memory
        memory.put_bytes(FRESH_ROW, bytes([0xDD]) * 0x18)
        self.value_at = None
        before = self.bytes_at(EX + S_SHIFT + 0x1F8, 0x18)
        self.word(ACTION + 0x29, case.flag, 1)
        self.word(HANDLE, case.now[0], 4)
        self.word(HANDLE + 4, case.now[1], 4)
        self.word(HANDLE + 8, case.now[2], 4)
        self.machine.run(STAMP, {RDI: EX + S_SHIFT, RSI: HANDLE, RDX: case.chain, RCX: USER, R8: ACTION})
        self.expect(self.bytes_at(EX + S_SHIFT + 0x1F8, 0x18) == before, "tree header")
        if self.value_at is None:
            return (("stamp", None, None), tuple(self.events))
        self.expect(self.read(self.value_at, 8) == (dict(case.users).get(case.user, 0xDDDDDDDDDDDDDDDD)), "first word of the row")
        return (("stamp", self.value_at != FRESH_ROW, self.time_at(self.value_at + 8)), tuple(self.events))

    def run_list(self, case):
        statics = self.machine.memory.statics
        for cell, word in LIST_CELLS.values():
            statics[word] = 1 if case.lazy else 0
        try:
            cell = self.machine.run(LIST_V if case.mode else LIST_S, {RDI: case.chain | 0x5500})
        except Panicked as caught:
            return (("panic", str(caught)), tuple(self.events))
        return (("list", cell), tuple(self.events))

    def run(self, case):
        self.fresh(case)
        if case.kind == "stamp":
            return self.run_stamp(case)
        if case.kind == "list":
            return self.run_list(case)
        self.fill_action(case)
        machine = self.machine
        copy = COPIES[case.copy]
        try:
            if case.kind == "token":
                machine.run(copy.wrap, {RDI: OUTPUT, RSI: ACTION, RDX: USER, RCX: EX})
            else:
                machine.run(copy.host, {RDI: OUTPUT, RSI: EX, RDX: USER, RCX: ACTION})
        except Panicked as caught:
            return (("panic", str(caught)), tuple(self.events))
        return (self.result(case), tuple(self.events))


NOW = (0x40000000, 1000, 500)
A, B, C = address_of(1), address_of(2), address_of(3)
RICH = ((A, 10 ** 6), (B, 10 ** 6))


def same(index=1):
    return dict(user=address_of(index), validator=address_of(index))


def self_row(index=1, when=(0x3FFFFF00, 5, 6), **fields):
    base = same(index)
    base.update(mode=1, states=((address_of(index), when),))
    base.update(fields)
    return base


def noise(count, skip=()):
    return tuple(address_of(50 + at) for at in range(count) if address_of(50 + at) not in skip)


def token_cases(copy):
    t = "c%d_token_" % copy
    out = []

    def add(name, **fields):
        out.append(Case(t + name, copy=copy, kind="token", **fields))

    add("delegate")
    for wei in (0, 1, 2, GUARD - 1, GUARD, GUARD + 1, TOP):
        add("wei_%x" % wei, wei=wei)
    for tag in (0, 2, 3, 0x101, 0x10000, 0x7FFFFFFF, 0xFFFFFFFF, 0x100000000, 0x100000001, 0xFFFFFFFF00000001):
        add("tag_%x" % tag, tag=tag)
        add("tag_zero_wei_%x" % tag, tag=tag, wei=0)
    for mode in (0, 1, 2, 3, 0x7F, 0x80, 0xFE, 0xFF):
        add("mode_%x" % mode, mode=mode)
        add("mode_same_%x" % mode, mode=mode, **same())
    for place in range(20):
        other = bytearray(A)
        other[place] ^= 0x40
        add("self_miss_byte_%d" % place, mode=1, user=A, validator=bytes(other), states=((A, NOW), (bytes(other), NOW)))
        add("self_hit_byte_%d" % place, mode=1, user=bytes(other), validator=bytes(other), states=((A, NOW), (bytes(other), NOW)))
    add("self_no_row", mode=1, **same())
    add("self_empty_tree_other", mode=1, states=((C, NOW),), **same())
    for size in (1, 2, 5, 11, 12, 13, 24, 40, 144, 200):
        keys = [address_of(5 + at) for at in range(size)]
        for pick in sorted({0, min(1, size - 1), size // 2, size - 1}):
            add("states_%d_hit_%d" % (size, pick), mode=1, user=keys[pick], validator=keys[pick], states=tuple((key, (0x3FFFFF00 + at, at, at)) for at, key in enumerate(keys)))
        low, high = address_of(4), bytes([0xF0]) + address_of(4)[1:]
        add("states_%d_low_miss" % size, mode=1, user=low, validator=low, states=tuple((key, NOW) for key in keys))
        add("states_%d_high_miss" % size, mode=1, user=high, validator=high, states=tuple((key, NOW) for key in keys))
        add("states_%d_mid_miss" % size, mode=1, user=keys[size // 2][:19] + b"\x01", validator=keys[size // 2][:19] + b"\x01", states=tuple((key, NOW) for key in keys))
    for label, lock, value in (("equal", NOW, 1), ("nano_below", (NOW[0], NOW[1], NOW[2] - 1), 0), ("nano_above", (NOW[0], NOW[1], NOW[2] + 1), 1), ("sec_below", (NOW[0], NOW[1] - 1, 0xFFFFFFFF), 0), ("sec_above", (NOW[0], NOW[1] + 1, 0), 1),
                               ("date_below", (NOW[0] - 1, 0xFFFFFFFF, 0xFFFFFFFF), 0), ("date_above", (NOW[0] + 1, 0, 0), 1), ("date_negative", (0x80000000, 0xFFFFFFFF, 0xFFFFFFFF), 0), ("date_top", (0x7FFFFFFF, 0, 0), 1), ("high_bit", (0xC0000000, 0, 0), 0)):
        add("lock_" + label, lock=lock, **self_row())
    add("now_negative_lock_positive", now=(0x80000010, 0, 0), lock=(5, 0, 0), **self_row())
    add("now_negative_lock_lower", now=(0x80000010, 5, 0), lock=(0x80000000, 9, 9), **self_row())
    add("required_zero_expired", required=0, lock=(1, 0, 0), **self_row())
    add("required_top", required=TOP, **self_row())
    add("core_fails", core=0xFE)
    add("core_fails_self", core=0xFF, **self_row())
    add("core_fails_undelegate", core=0x130, mode=1)
    for chain in (1, 2, 3):
        for at, key in enumerate(members(chain)):
            add("foundation_%d_%d" % (chain, at), chain=chain, **dict(self_row(), user=key, validator=key, states=((key, (0x3FFFFF00, 1, 2)),)))
        add("not_foundation_%d" % chain, chain=chain, **self_row())
        add("lazy_%d" % chain, chain=chain, lazy=True, **self_row())
        key = members(chain)[0]
        add("lazy_member_%d" % chain, chain=chain, lazy=True, **dict(self_row(), user=key, validator=key, states=((key, NOW),)))
    signer = bytes.fromhex(EXTRA_SIGNER)
    add("extra_signer_is_not_exempt", chain=3, **dict(self_row(), user=signer, validator=signer, states=((signer, NOW),)))
    extra = bytes.fromhex(EXTRA_VALIDATOR)
    for chain in (1, 2):
        add("extra_validator_chain_%d" % chain, chain=chain, **dict(self_row(), user=extra, validator=extra, states=((extra, NOW),)))
    add("chain_0_panics", chain=0, **self_row())
    add("chain_0_delegate", chain=0)
    add("chain_0_other_undelegate", chain=0, mode=1)
    for size in (8, 11, 12, 13, 30, 150):
        keys = noise(size)
        add("set_%d_hit_low" % size, set_extra=keys, **dict(self_row(), user=keys[0], validator=keys[0], states=((keys[0], NOW),)))
        add("set_%d_hit_high" % size, set_extra=keys, **dict(self_row(), user=keys[-1], validator=keys[-1], states=((keys[-1], NOW),)))
        add("set_%d_hit_mid" % size, set_extra=keys, **dict(self_row(), user=keys[size // 2], validator=keys[size // 2], states=((keys[size // 2], NOW),)))
        probe = keys[size // 2][:19] + b"\x00"
        add("set_%d_miss" % size, set_extra=keys, **dict(self_row(), user=probe, validator=probe, states=((probe, NOW),)))
    return out


def event_cases():
    out = []

    def add(name, **fields):
        out.append(Case("c2_event_" + name, copy=2, kind="token", **fields))

    add("off", sink_off=True)
    add("off_undelegate", sink_off=True, mode=1)
    add("sink_one", **{})
    for tag in (0, 1, 2, 0x100000001):
        add("block_%x" % tag, block=tag)
    for wei in (1, 3, 10 ** 8, 123456789, GUARD - 1, 1 << 53, (1 << 53) + 1):
        add("amount_%x" % wei, wei=wei)
    for decimals in (0, 1, 2, 6, 8, 10, 18, 22):
        add("decimals_%d" % decimals, decimals=decimals, wei=987654321)
    add("token_edge_ok", token=199, count=200)
    add("token_edge_panic", token=200, count=200)
    add("token_far_panic", token=TOP, count=200)
    add("undelegate", mode=1)
    add("undelegate_self", **self_row())
    add("mode_three", mode=3)
    add("mode_ff", mode=0xFF)
    add("byte_zero", sink_byte=0)
    add("byte_ff", sink_byte=0xFF)
    add("chain_1", chain=1, block=1)
    add("chain_2", chain=2)
    add("sink_after_core_fail", core=0xFE, block=1)
    return out


def host_cases(copy):
    t = "c%d_host_" % copy
    out = []

    def add(name, **fields):
        base = dict(copy=copy, kind="host", users=RICH)
        base.update(fields)
        out.append(Case(t + name, **base))

    add("register")
    add("register_exact", wei=1000, users=((A, 1000),))
    add("unregister", word0=UNREGISTER)
    add("unregister_closed", word0=UNREGISTER, allow_all=0)
    for word0 in (CHANGE, CHANGE + 2, CHANGE + 7, TOP, 0, 1, (1 << 63) - 1):
        add("word_%x" % word0, word0=word0)
    for allow in (0, 1, 2, 0x80, 0xFF):
        add("allow_%x_in" % allow, allow_all=allow, allowed=(A,))
        add("allow_%x_out" % allow, allow_all=allow, allowed=(B,))
        add("allow_%x_empty" % allow, allow_all=allow)
    for size in (2, 11, 12, 30, 150):
        keys = noise(size)
        for pick in sorted({0, size // 2, size - 1}):
            add("allowed_%d_hit_%d" % (size, pick), allow_all=0, user=keys[pick], allowed=keys, users=((keys[pick], 10 ** 6),))
        add("allowed_%d_miss_low" % size, allow_all=0, user=address_of(4), allowed=keys)
        probe = bytes([0xF0]) + keys[0][1:]
        add("allowed_%d_miss_high" % size, allow_all=0, user=probe, allowed=keys)
        probe = keys[size // 2][:19] + b"\x00"
        add("allowed_%d_miss_mid" % size, allow_all=0, user=probe, allowed=keys)
    for chain in (0, 1, 2, 3):
        for tag in (0, 1, 2, 3, 0xFE, 0xFF):
            add("ip_%d_%x" % (chain, tag), chain=chain, ip_tag=tag)
        for patch in (0, 1, 2, 3, 4, 0xFE, 0xFF):
            add("patch_%d_%x" % (chain, patch), chain=chain, word0=CHANGE, patch=patch)
    for wei in (0, 1, 999, 1000, 1001, GUARD - 1, GUARD, TOP):
        add("wei_%x" % wei, wei=wei, users=((A, TOP),))
        add("wei_%x_no_floor" % wei, wei=wei, required=0, users=((A, TOP),))
        add("wei_%x_change" % wei, wei=wei, word0=CHANGE)
    add("zero_zero", wei=0, required=0, disabled=1)
    add("zero_zero_tag", wei=0, required=0, tag=0)
    add("wei_zero_floor", wei=0, required=5)
    for flag in (1, 2, 0x80, 0xFF):
        add("disabled_%x" % flag, disabled=flag)
        add("disabled_floor_only_%x" % flag, disabled=flag, wei=0, required=1)
        add("disabled_no_floor_%x" % flag, disabled=flag, wei=1, required=0)
    add("disabled_change", word0=CHANGE, disabled=1)
    for tag in (0, 1, 2, 0x100, 0x101, 0x100000000, 0x100000001, 0xFF):
        add("tag_%x" % tag, tag=tag)
        add("tag_%x_change" % tag, tag=tag, word0=CHANGE)
        add("tag_%x_below_floor" % tag, tag=tag, wei=1)
    for have in (0, 999, 1000, 1001):
        add("balance_%d" % have, wei=1000, users=((A, have),))
    add("balance_absent", wei=1000, users=((B, TOP),))
    add("balance_no_rows", wei=1000, users=())
    for size in (2, 11, 12, 30, 100):
        keys = noise(size)
        for pick in sorted({0, size // 2, size - 1}):
            add("users_%d_hit_%d" % (size, pick), user=keys[pick], wei=1000, users=tuple((key, 1000 + at) for at, key in enumerate(keys)))
        add("users_%d_miss_low" % size, user=address_of(4), wei=1000, users=tuple((key, TOP) for key in keys))
        add("users_%d_miss_high" % size, user=bytes([0xF0]) + keys[0][1:], wei=1000, users=tuple((key, TOP) for key in keys))
        add("users_%d_miss_mid" % size, user=keys[size // 2][:19] + b"\x00", wei=1000, users=tuple((key, TOP) for key in keys))
    for status in (0x120, 0x121, 0x123, 0x124, 0x125, 0x143):
        add("profile_%x" % status, profile=status)
        add("profile_change_%x" % status, profile=status, word0=CHANGE)
    for status in (0xFE, 0x130, 0x91):
        add("self_core_fail_%x" % status, core=status, wei=1000)
        add("self_core_fail_no_floor_%x" % status, core=status, wei=1, required=0)
    add("self_core_fail_tag", tag=2, wei=1000)
    add("self_core_fail_tag_high", tag=0x100000002, wei=1000)
    add("self_core_fail_tag_byte", tag=0x101, wei=1000)
    add("self_delegate", wei=1000)
    add("self_delegate_no_floor", wei=5, required=0)
    add("chain_time", now=(0x12345678, 0x9ABC, 0xDEF0))
    return out


def stamp_cases():
    out = []

    def add(name, **fields):
        base = dict(kind="stamp", user=A, users=((A, 77), (B, 88)), lock=(0x40000100, 11, 22))
        base.update(fields)
        out.append(Case("stamp_" + name, **base))

    for chain in (0, 1, 2, 3, 4, 0xFF):
        add("chain_%x" % chain, chain=chain)
    for flag in (0, 1, 2, 0x80, 0xFF):
        add("flag_%x" % flag, flag=flag)
    add("flag_zero_absent", flag=0, users=())
    add("empty", users=())
    add("absent_low", user=address_of(0))
    add("absent_high", user=bytes([0xF0]) + A[1:])
    add("absent_mid", user=A[:19] + b"\x00", users=((address_of(0), 1), (B, 2)))
    for size in (2, 11, 12, 13, 30, 100):
        keys = noise(size)
        for pick in sorted({0, size // 2, size - 1}):
            add("users_%d_hit_%d" % (size, pick), user=keys[pick], users=tuple((key, 100 + at) for at, key in enumerate(keys)))
        add("users_%d_miss_low" % size, user=address_of(4), users=tuple((key, 1) for key in keys))
        add("users_%d_miss_high" % size, user=bytes([0xF0]) + keys[0][1:], users=tuple((key, 1) for key in keys))
        add("users_%d_miss_mid" % size, user=keys[size // 2][:19] + b"\x00", users=tuple((key, 1) for key in keys))
    return out


def list_cases():
    out = []
    for chain in (0, 1, 2, 3):
        for which in (0, 1):
            out.append(Case("list_%d_%d" % (chain, which), kind="list", chain=chain, mode=which))
            out.append(Case("list_lazy_%d_%d" % (chain, which), kind="list", chain=chain, mode=which, lazy=True))
    return out


def named_cases():
    cases = stamp_cases() + list_cases()
    for copy in range(3):
        cases.extend(token_cases(copy))
        cases.extend(host_cases(copy))
    cases.extend(event_cases())
    names = [case.name for case in cases]
    if len(names) != len(set(names)):
        raise EvidenceError("duplicate case name %s" % sorted(name for name in set(names) if names.count(name) > 1)[:4])
    return cases


def vector_cases(count):
    rng = random.Random(0x394)
    out = []
    pool = [address_of(at) for at in range(1, 9)]
    for at in range(count):
        copy = rng.randrange(3)
        user = rng.choice(pool)
        validator = rng.choice((user, rng.choice(pool)))
        chain = rng.choice((1, 2, 3, 3, 3, 0))
        if rng.random() < 0.3 and chain:
            user = validator = rng.choice(members(chain))
        states = tuple((key, (0x40000000 + rng.randrange(-2, 3), 1000 + rng.randrange(-1, 2), 500)) for key in pool + [user] if rng.random() < 0.5)
        states = tuple(dict(states).items())
        lock = (0x40000000 + rng.randrange(-2, 3), 1000 + rng.randrange(-1, 2), 500 + rng.randrange(-1, 2))
        wei = rng.choice((0, 1, 500, 1000, 1001, 10 ** 8, GUARD - 1, GUARD))
        common = dict(copy=copy, user=user, validator=validator, chain=chain, states=states, lock=lock, wei=wei, required=rng.choice((0, 1000, 10 ** 8)), tag=rng.choice((1, 1, 1, 1, 0, 2)), core=rng.choice((OK, OK, OK, 0xFE, 0xFF)),
                      lazy=rng.random() < 0.2, sink_off=rng.random() < 0.2, block=rng.choice((0, 1)), decimals=rng.randrange(0, 19))
        if rng.random() < 0.5:
            out.append(Case("vector_token_%d" % at, kind="token", mode=rng.choice((0, 1, 1, 1, 2)), **common))
        else:
            allowed = tuple(key for key in pool if rng.random() < 0.5)
            users = tuple((key, rng.choice((0, 1000, 10 ** 9))) for key in set(pool + [user]) if rng.random() < 0.7)
            users = tuple(sorted(users))
            out.append(Case("vector_host_%d" % at, kind="host", word0=rng.choice((8, 8, CHANGE, UNREGISTER)), allow_all=rng.choice((0, 1, 1)), allowed=allowed, users=users, ip_tag=rng.choice((0, 0, 0, 1)), patch=rng.choice((0, 1, 2)), disabled=rng.choice((0, 0, 0, 1)), profile=rng.choice((OK, OK, OK, 0x121)), **common))
    return out


def check_cases(harness, cases, reach=None):
    outcomes = []
    for at, case in enumerate(cases):
        before = set()
        if reach is not None:
            harness.machine.seen, before = set(), harness.machine.seen
        got = harness.run(case)
        if reach is not None:
            for va in harness.machine.seen:
                reach.setdefault(va, []).append(at)
            harness.machine.seen |= before
        want = spec_run(case)
        if got != want:
            raise EvidenceError("case %s: %r != %r" % (case.name, got, want))
        outcomes.append(got)
    return outcomes


SITES = {}


def site_maps(image):
    """All direct calls and slot calls of the text, read once."""
    if not SITES:
        start, text = image.text_bytes()
        calls, slots = {}, {}
        for match in re.finditer(b"\xe8", text):
            at = match.start()
            if at + 5 <= len(text):
                calls.setdefault(start + at + 5 + struct.unpack_from("<i", text, at + 1)[0], []).append(start + at)
        for match in re.finditer(b"\xff[\x15\x25]", text):
            at = match.start()
            if at + 6 <= len(text):
                slots.setdefault(start + at + 6 + struct.unpack_from("<i", text, at + 2)[0], []).append(start + at)
        SITES.update(calls=calls, slots=slots)
    return SITES


def direct_to(image, target):
    return site_maps(image)["calls"].get(target, [])


def slot_sites(image, slot):
    return site_maps(image)["slots"].get(slot, [])


def cell_sites(image, cells):
    """rip relative lea and mov rows that name one of the cells, found by fixed REX.W byte forms."""
    start, text = image.text_bytes()
    hits = []
    for match in re.finditer(b"[\x48\x4c][\x8b\x8d][\x05\x0d\x15\x1d\x25\x2d\x35\x3d]", text):
        at = match.start()
        if at + 7 > len(text):
            continue
        target = start + at + 7 + struct.unpack_from("<i", text, at + 3)[0]
        if target in cells:
            hits.append((target, start + at))
    return sorted(hits)


def caller_rows(image):
    rows = []
    for target in (WRAP_A, WRAP_B, WRAP_C, GATE_A, GATE_B, GATE_C, HOST_A, HOST_B, HOST_C, SELF_A, SELF_B, SET_A, SET_B):
        sites = sorted(direct_to(image, target))
        rows.append(("direct", NAMES[target], "%#x" % target, len(sites), " ".join("%#x in %#x" % (site, image.fde(site)[0]) for site in sites[:8])))
    relative = image.relative()
    for name, slot, target in (("core", SLOT_CORE, 0x398DC90), ("foundation_validators", SLOT_LIST_V, LIST_V), ("foundation_self_signers", SLOT_LIST_S, LIST_S), ("profile_gate", SLOT_PROFILE, 0x3994F20), ("staking_balance", SLOT_BALANCE, BALANCE), ("delegate_event", SLOT_EVENT, EVENT), ("long_term_lock_stamp", 0x5773130, STAMP), ("add_seconds", SLOT_TIME_ADD, 0x1459CA0), ("utc_now", SLOT_CLOCK, 0x151CBA0)):
        if relative.get(slot) != target:
            raise EvidenceError("slot %#x" % slot)
        sites = sorted(slot_sites(image, slot))
        rows.append(("slot %#x" % slot, name, "%#x" % target, len(sites), " ".join("%#x in %#x" % (site, image.fde(site)[0]) for site in sites[:30])))
    return rows


def shape(row, entry, end):
    """One decoded row with branch targets inside the function made relative."""
    target = row.target
    if target is not None and entry <= target < end:
        target -= entry
    return (row.op, row.a, row.b, row.width, row.cc, target)


def call_targets(rows):
    return {row.target if row.target is not None else row.a[4] for row in rows if row.op == "call" or (row.op == "calli" and row.a[0] == "m")}


def copy_rows(image, table):
    rows = []
    for first, other in ((WRAP_A, WRAP_B), (WRAP_A, WRAP_C), (GATE_A, GATE_B), (GATE_A, GATE_C), (HOST_A, HOST_B), (HOST_A, HOST_C), (SELF_A, SELF_B), (SET_A, SET_B)):
        base, second = table[first], table[other]
        base_end = image.exact_fde(first)[1]
        extent = image.exact_fde(other)
        same = sum(1 for left, right in zip(base, second) if shape(left, first, base_end) == shape(right, other, extent[1])) if len(base) == len(second) else 0
        rows.append((NAMES[first], NAMES[other], "%#x" % other, extent[1] - extent[0], len(base), len(second), same, " ".join("%#x" % va for va in sorted(call_targets(second) - call_targets(base))) or "none", " ".join("%#x" % va for va in sorted(call_targets(base) - call_targets(second))) or "none"))
    return rows


def rip_form(before, after):
    """A movups load from rip, a fixed row, then an immediate; both variable fields are groups."""
    return re.compile(re.escape(before) + b"(....)" + re.escape(after) + b"(....)", re.S)


FIXED_LIST = rip_form(b"\x0f\x10\x05", b"\x0f\x29\x04\x24\xc7\x44\x24\x10")
EXTRA_LIST = rip_form(b"\x0f\x10\x05", b"\x0f\x11\x44\x24\x59\xc7\x44\x24\x69")
BASE_CELL = re.compile(re.escape(b"\x48\x8b\x35") + b"(....)" + re.escape(b"\x48\x85\xf6"), re.S)
CLOSURES = (("sandbox_self_signers", 0x57861D8, 0x3432AA0, 1), ("testnet_self_signers", 0x57861F8, 0x34327E0, 2), ("mainnet_self_signers", 0x5786218, 0x34328B0, 3), ("mainnet_foundation_signers", 0x5786258, 0x3432B70, 4))
EXTENDED = (("mainnet_foundation_validators", 0x5786238, 0x3432980, EXTRA_VALIDATOR),)


def text_of(image, va, size):
    return bytes(image.blob[image.offset(va):image.offset(va) + size])


def rip_address(image, closure_at, match, group=1):
    return closure_at + match.start() + 7 + struct.unpack("<i", match[group])[0]


def list_rows(image):
    relative = image.relative()
    rows = []
    for name, cell, closure, chain in CLOSURES:
        if relative.get(cell) != closure:
            raise EvidenceError("cell %#x" % cell)
        extent = image.exact_fde(closure)
        code = text_of(image, closure, extent[1] - extent[0])
        found = []
        for match in FIXED_LIST.finditer(code):
            va = rip_address(image, closure, match)
            found.append((text_of(image, va, 16) + match[2], va))
        want = list(LISTS[chain][2]) if chain < 4 else sorted(LISTS[3][2] + (EXTRA_SIGNER,))
        if [item[0].hex() for item in found] != want:
            raise EvidenceError("list %s" % name)
        for key, va in found:
            rows.append((name, "%#x" % cell, "%#x" % closure, "", key.hex(), "%#x" % va))
    for name, cell, closure, extra in EXTENDED:
        if relative.get(cell) != closure:
            raise EvidenceError("cell %#x" % cell)
        extent = image.exact_fde(closure)
        code = text_of(image, closure, extent[1] - extent[0])
        base = BASE_CELL.search(code)
        one = EXTRA_LIST.search(code)
        if base is None or one is None:
            raise EvidenceError("closure form %s" % name)
        va = rip_address(image, closure, one)
        key = text_of(image, va, 16) + one[2]
        if key.hex() != extra:
            raise EvidenceError("extra key %s" % name)
        base_cell = closure + base.start() + 7 + struct.unpack("<i", base[1])[0]
        rows.append((name, "%#x" % cell, "%#x" % closure, "%#x" % base_cell, key.hex(), "%#x" % va))
    return rows


def chain_rows(image):
    rows = []
    for chain in range(4):
        arm = (JUMP_TABLE + struct.unpack_from("<i", image.blob, image.offset(JUMP_TABLE) + 4 * chain)[0]) & MASK[4]
        code = text_of(image, arm, 32)
        if chain == 0:
            if code[:3] != b"\x48\x8d\x3d" or arm + 7 + struct.unpack_from("<i", code, 3)[0] != CHAIN_TEXT:
                raise EvidenceError("chain 0 arm")
            rows.append((chain, "%#x" % arm, "", "", text_of(image, CHAIN_TEXT, 13).decode("ascii")))
            continue
        if code[:2] != b"\x8b\x05" or code[6:8] != b"\x85\xc0":
            raise EvidenceError("chain arm %d" % chain)
        status = arm + 6 + struct.unpack_from("<i", code, 2)[0]
        at = code.index(b"\x48\x8d\x05")
        cell = arm + at + 7 + struct.unpack_from("<i", code, at + 3)[0]
        rows.append((chain, "%#x" % arm, "%#x" % status, "%#x" % cell, "lazy set"))
    if [row[3] for row in rows[1:]] != ["%#x" % va for va in (0x57861D8, 0x57861F8, 0x5786218)]:
        raise EvidenceError("chain cells")
    return rows


def site_rows(image):
    cells = {0x57861D8: "sandbox_self_signers", 0x57861F8: "testnet_self_signers", 0x5786218: "mainnet_self_signers", 0x5786238: "mainnet_foundation_validators", 0x5786258: "mainnet_foundation_signers"}
    return [(cells[cell], "%#x" % cell, "%#x" % site, "%#x" % image.fde(site)[0]) for cell, site in cell_sites(image, set(cells))]


TEXT_TABLE = 0x59A8D0
STATUSES = (0x32, 0x8E, 0x91, 0x94, 0xFB, 0xFC, 0xFD, 0xFE, 0xFF, 0x130, 0x13F)


def status_rows(image):
    rows = []
    for tag in STATUSES:
        arm = TEXT_TABLE + struct.unpack_from("<i", image.blob, image.offset(TEXT_TABLE) + 4 * tag)[0]
        code = text_of(image, arm, 96)
        at = code.find(b"\x48\x8d\x35")
        if at < 0 or code[at + 7] != 0xBA:
            raise EvidenceError("status arm %#x" % tag)
        size = struct.unpack_from("<I", code, at + 8)[0]
        rows.append(("%#x" % tag, "%#x" % arm, text_of(image, arm + at + 7 + struct.unpack_from("<i", code, at + 3)[0], size).decode("ascii")))
    return rows


IMMEDIATES = (
    ("wei_guard", 0x1E5FA8E, "48b8cccccccccccccc0c", "movabs rax,0xccccccccccccccc: wrapper limit"),
    ("mode_byte", 0x1E5FA9D, "440fb64e45", "movzx r9d,byte [rsi+0x45]: mode byte of the action"),
    ("gate_tag", 0x2757FF4, "8b8680000000", "mov eax,[rsi+0x80]: dword compared with 1"),
    ("host_tag_byte", 0x2769337, "80be8000000000", "cmp byte [rsi+0x80],0: the host reads one byte of the same word"),
    ("states_field", 0x275817A, "498b85700b0000", "mov rax,[r13+0xb70]: validator_to_state root"),
    ("state_stride", 0x2758206, "4983c61c", "add r14,0x1c: 28 byte values"),
    ("floor_field", 0x27582BA, "498b85380b0000", "mov rax,[r13+0xb38]: the value word of the row is this floor"),
    ("unregister_word", 0x2769007, "48b80100000000000080", "movabs rax,0x8000000000000001: first word of the action in the refused arm"),
    ("floor_serializer_row", 0x399078D, "488d8b40020000", "lea rcx,[rbx+0x240]: value of the key at the next row, S+0x240 is E+0xb38"),
    ("state_serializer_row", 0x39907EB, "4881c378020000", "add rbx,0x278, then 0x3a05a10 writes the key validator_to_state: S+0x278 is E+0xb70"),
    ("allow_all_field", 0x276903A, "80be880b000000", "cmp byte [rsi+0xb88],0: allow_all_validators"),
    ("allowed_field", 0x27690A9, "488b86180a0000", "mov rax,[rsi+0xa18]: allowed_validators root"),
    ("chain_field", 0x2769053, "80bef208000000", "cmp byte [rsi+0x8f2],0"),
    ("event_niche", 0x4856CB3, "483b8708080000", "cmp rax,[rdi+0x808] with rax 0: overflow only for the i64::MIN word"),
    ("event_kind", 0x4856D44, "48b80000000000000080", "movabs rax,0x8000000000000000, then inc: record kind word 0x8000000000000001"),
    ("user_states_field", 0x3996270, "498d8ef8010000", "lea rcx,[r14+0x1f8]: user_states"),
    ("stamp_flag", 0x3996230, "4180782900", "cmp byte [r8+0x29],0: no stamp when clear"),
)


def constant_rows(image):
    rows = []
    for name, va, form, note in IMMEDIATES:
        want = bytes.fromhex(form)
        if text_of(image, va, len(want)) != want:
            raise EvidenceError("immediate %s: %s" % (name, text_of(image, va, len(want)).hex()))
        rows.append((name, "%#x" % va, form, note))
    for name, lea, key, size in (("self_delegation_requirement", 0x3990794, 0x5A6DEC, 27), ("validator_to_state", 0x3A05A24, 0x5A6E2B, 18)):
        code = text_of(image, lea, 7)
        if code[:3] != b"\x48\x8d\x35" or lea + 7 + struct.unpack_from("<i", code, 3)[0] != key or text_of(image, key, size).decode("ascii") != name:
            raise EvidenceError("key %s" % name)
        rows.append(("key_" + name, "%#x" % lea, code.hex(), "lea rsi of the key text in the CStaking serializer path"))
    if struct.unpack("<d", text_of(image, 0x20A4D0, 8))[0] != YEAR:
        raise EvidenceError("year constant")
    rows.append(("year_constant", "0x20a4d0", text_of(image, 0x20A4D0, 8).hex(), "double 31557600.0, the seconds argument of the gate"))
    if struct.unpack("<dd", text_of(image, LOCK_TABLE, 16)) != (YEAR, SHORT):
        raise EvidenceError("lock table")
    rows.append(("lock_table_values", "%#x" % LOCK_TABLE, text_of(image, LOCK_TABLE, 16).hex(), "31557600.0 then 300.0: chain 1 and 2 take index 1"))
    for power in range(23):
        if text_of(image, POWER_TABLE + 8 * power, 8) != struct.pack("<d", 10.0 ** power):
            raise EvidenceError("power %d" % power)
    rows.append(("power_table", "%#x" % POWER_TABLE, "", "23 doubles 1e0 to 1e22, index = wei decimals"))
    return rows


KEY_TEXTS = ("self_delegation_requirement", "disabled_validators", "validator_to_state", "register_time", "last_signer_change_time", "delegations_blocked", "extend_long_term_staking", "disable_delegations", "initial_wei", "delegations_disabled")


def key_rows(image):
    rows = []
    rodata = bytes(image.blob[:0x1343C80])
    for name in KEY_TEXTS:
        at = rodata.find(name.encode())
        if at < 0:
            raise EvidenceError("key %s" % name)
        rows.append((name, "%#x" % at))
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


def first_failure(harness, cases):
    for case in cases:
        try:
            got = harness.run(case)
            if got != spec_run(case):
                return case
        except (Halt, EvidenceError, Panicked, KeyError, IndexError, ValueError, OverflowError, ZeroDivisionError, TypeError, struct.error):
            return case
    return None


OPEN = "open: no named case tells this edit apart and it was not analysed further"
I, D, C_ = "immediate", "displacement", "condition"
CLASSES = (
    ("success tag test: the failure arm forwards the same 0x186 word, so both arms give one result", ((0x2758105, I), (0x4D80995, I), (0x275AB0B, I), (0x4D8609B, I))),
    ("second wei limit in the host: the first limit at 0x2769077 already passed, so this row cannot refuse", ((0x2769216, I), (0x4D9E2F6, I), (0x4D9DEF6, I))),
    ("failure bytes of the register self delegation: only the tag reaches the drop stub", tuple((va, D) for va in (0x275AB2A, 0x275AB36, 0x275AB51, 0x275AB55, 0x275AB59, 0x4D860BA, 0x4D860C6, 0x4D860E1, 0x4D860E5, 0x4D860E9))),
    ("found pointer of the set lookup: the callers test it against zero only", ((0x284BC02, I), (0x4927892, I))),
)
EXPECTED_SURVIVORS = {edit: text for text, edits in CLASSES for edit in edits}
POOL = {}
MUTANT_CASES = 300
MUTANT_LIMIT = 8000


def run_one(task):
    va, patch = task
    harness = Harness(POOL["image"], patch)
    harness.machine.step_limit = MUTANT_LIMIT
    places = POOL["reach"][va]
    places = places[::max(1, len(places) // MUTANT_CASES)]
    chosen = [POOL["cases"][at] for at in places]
    return first_failure(harness, chosen) is not None


def run_mutants(image, table, seen, cases, reach):
    control = Harness(image)
    control.machine.step_limit = MUTANT_LIMIT
    if first_failure(control, cases) is not None:
        raise EvidenceError("an unedited image fails under the mutant step limit")
    POOL.update(image=image, cases=cases, reach=reach)
    rows = [(target,) + edit for target in TARGETS for edit in edits_for(image, table[target], seen)]
    tasks = [(row[1], row[3]) for row in rows]
    try:
        with multiprocessing.get_context("fork").Pool(WORKERS) as pool:
            killed = pool.map(run_one, tasks, 8)
    except OSError:
        killed = [run_one(task) for task in tasks]
    return [(va, kind, "killed", "whole run") if dead else (va, kind, "survived", EXPECTED_SURVIVORS.get((va, kind), OPEN)) for (_, va, kind, _), dead in zip(rows, killed)]


def analyse(image, mutate=True, vectors=300):
    harness = Harness(image)
    cases = named_cases()
    reach = {}
    outcomes = check_cases(harness, cases, reach)
    seen = set(reach)
    check_cases(harness, vector_cases(vectors))
    table = {target: decode_range(image, *image.exact_fde(target)) for target in TARGETS}
    unreached = {target: [row.va for row in table[target] if row.va not in seen and row.op not in ("int3", "nop", "ud2")] for target in TARGETS}
    result = dict(table=table, cases=cases, outcomes=outcomes, vector_count=vectors, unreached=unreached, callers=caller_rows(image), constants=constant_rows(image), copies=copy_rows(image, table), lists=list_rows(image), chains=chain_rows(image), sites=site_rows(image), statuses=status_rows(image), keys=key_rows(image))
    if mutate:
        result["mutations"] = run_mutants(image, table, seen, cases, reach)
    return result


def describe(outcome):
    result, events = outcome
    kinds = {}
    for event in events:
        kinds[event[0]] = kinds.get(event[0], 0) + 1
    code = "" if len(result) < 2 else result[1]
    return (result[0], "%#x" % code if isinstance(code, int) and not isinstance(code, bool) else code, " ".join("%s=%d" % item for item in sorted(kinds.items())), hashlib.sha256(repr(outcome).encode()).hexdigest()[:16])


def render(result):
    files = {}

    def tsv(name, header, rows):
        lines = ["\t".join(header)] + ["\t".join(str(cell) for cell in row) for row in rows]
        files[name] = "\n".join(lines) + "\n"

    tsv("function-rows.tsv", ("function", "address", "size", "bytes", "operation"),
        [("%#x" % target, "%#x" % row.va, row.size, row.data.hex(), row.op) for target in TARGETS for row in result["table"][target]])
    tsv("callers.tsv", ("reach", "role", "target", "sites", "addresses"), result["callers"])
    tsv("constants.tsv", ("name", "address", "bytes", "note"), result["constants"])
    tsv("status-text.tsv", ("tag", "display_arm", "text"), result["statuses"])
    tsv("foundation-lists.tsv", ("set", "cell", "init_closure", "copied_from_cell", "address", "bytes_at"), result["lists"])
    tsv("chain-arms.tsv", ("chain_byte", "arm", "once_word", "cell", "meaning"), result["chains"])
    tsv("list-sites.tsv", ("set", "cell", "site", "function"), result["sites"])
    tsv("key-texts.tsv", ("text", "first_file_offset"), result["keys"])
    tsv("copy-compare.tsv", ("first", "copy", "address", "bytes", "rows_first", "rows_copy", "rows_equal", "calls_only_in_copy", "calls_only_in_first"), result["copies"])
    tsv("outcomes.tsv", ("case", "end", "status", "events", "digest"), [(case.name,) + describe(outcome) for case, outcome in zip(result["cases"], result["outcomes"])])
    if "mutations" in result:
        tsv("mutations.tsv", ("address", "kind", "outcome", "detail"), [("%#x" % va, k, o, d) for va, k, o, d in result["mutations"]])
    summary = {
        "binary": "artifacts/node/94/hl-node", "sha256": SHA256,
        "functions": {NAMES[target]: {"address": "%#x" % target, "bytes": sum(row.size for row in result["table"][target]), "instructions": len(result["table"][target]),
                                      "unreached_rows": ["%#x" % va for va in result["unreached"][target]]} for target in TARGETS},
        "named_cases": len(result["cases"]), "vector_cases": result["vector_count"],
    }
    if "mutations" in result:
        rows = result["mutations"]
        summary["mutations"] = {"total": len(rows), "killed": sum(1 for r in rows if r[2] == "killed"), "survived": sum(1 for r in rows if r[2] == "survived"), "open": sum(1 for r in rows if r[3] == OPEN)}
    files["evidence.json"] = json.dumps(summary, indent=1, sort_keys=True) + "\n"
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
