#!/usr/bin/env python3
"""Pin node #94 staking withdrawal drain: time split of the queue, pending totals, balance filter, spot credit and ledger row.

0x26fdaf0, 0x4ce6090 and 0x4ce5be0 are the three copies of the block step. 0x3c13400 splits the time keyed queue with 0x2fb2ce0,
0x2fb1c70 and 0x2fb2930, 0x3bae220 + 0x3babc50 + 0x33aedb0 + 0x3bbb120 collect the rows and lower the pending totals through
0x33bac00 and 0x33aa1b0, 0x33082c0 filters them against user_states. The real bytes run under recording stubs over real B-tree
nodes, a separately written rule list predicts every run, and every reached conditional row, immediate and field offset is
mutated. No objdump or readelf output is parsed and the binary is never executed. Standard library only.

    python3 tools/staking_withdrawal_drain.py --out <dir>
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


DRAIN = 0x26FDAF0
DRAIN_B = 0x4CE6090
DRAIN_C = 0x4CE5BE0
POP = 0x3C13400
COLLECT = 0x3BAE220
NEXT_ROW = 0x3BABC50
NEXT_KV = 0x33AEDB0
DROP_REST = 0x3BBB120
FILTER = 0x33082C0
SPLIT = 0x2FB2CE0
MERGE = 0x2FB1C70
LENGTHS = 0x2FB2930
ENTRY = 0x33BAC00
REMOVE = 0x33AA1B0
AVAILABLE = 0x39935D0
TARGETS = (DRAIN, DRAIN_B, DRAIN_C, POP, COLLECT, NEXT_ROW, NEXT_KV, DROP_REST, FILTER, SPLIT, MERGE, LENGTHS, ENTRY, REMOVE, AVAILABLE)
NAMES = {DRAIN: "drain_step", DRAIN_B: "drain_step_b", DRAIN_C: "drain_step_c", POP: "pop_due", COLLECT: "collect_rows", NEXT_ROW: "next_row", NEXT_KV: "next_tree_row", DROP_REST: "drop_rest", FILTER: "balance_filter",
         SPLIT: "tree_split", MERGE: "tree_merge", LENGTHS: "tree_lengths", ENTRY: "total_entry", REMOVE: "total_remove", AVAILABLE: "available_amount"}
SLOT_COMPARE = 0x576E488
SLOT_COPY = 0x576DFE0
SLOT_MOVE = 0x576E0E0
SLOT_ALLOC = 0x576DFD8
SLOT_FREE = 0x576E010
SLOT_ALLOC_FAIL = 0x576DFB8
SLOT_NODE_FAIL = 0x576E020
SLOT_UNWRAP = 0x576E470
SLOT_ASSERT = 0x576E108
SLOT_RECORD = 0x5773190
SLOT_NAME = 0x57746B8
SLOT_HANDLE = 0x5774910
SLOT_SINK = 0x5774738
SLOT_SINK_C = 0x5776AD0
SLOT_EXTRA_C = 0x5776B28
SLOT_STAKE_SUM = 0x5774900
SLOT_AVAILABLE = 0x5774CF0
S_SHIFT = 0x8F8
S_DELEGATIONS = 0x168
CREDIT = 0x371D120
LEAF_INSERT = 0x2F90CA0
REMOVE_KV = 0x2FD8EA0
GROW = 0x32D6A00
MARK_BASE = 0x7700000000
SITE_SUB = 0x56DFD90
LOG_ZERO = 0x20C520
POWER_TABLE = 0x584B08
KIND = 0x8000000000000016
TOP = MASK[8]
HANDLE_VALUE = 0x4848484848484800
EX = HEAP_BASE + 0x1000
NODES = HEAP_BASE + 0x5000
ARENA = HEAP_BASE + 0x60000
TOKENS = HEAP_BASE + 0x400
USED = 0x7C000
FILL = 0xCC
EX_SIZE = 0x3E20
E_NOW = 0x60
E_TAG = 0x80
E_TOKEN = 0x88
E_META = 0x90
E_TABLE = 0x210
E_COUNT = 0x218
TOKEN_ROW = 0xE8
ROW_DECIMALS = 0x49
LEAF = 0x198
INNER = 0x1F8
NICHE = 1 << 63


class Copy:
    def __init__(self, entry, shift, handle_arg, sink_state):
        self.entry, self.shift, self.handle_arg, self.sink_state = entry, shift, handle_arg, sink_state
        self.users = 0xAF0 + shift
        self.queue = 0xB08 + shift
        self.totals = 0xB20 + shift


COPIES = (Copy(DRAIN, 0, 0x3380, 0x8F3), Copy(DRAIN_B, 0, 0x3380, 0x8F3), Copy(DRAIN_C, 0xA80, 0x3E00, 0x5B8))
E_EXTRA_BYTE = 0x1372


class Layout:
    def __init__(self, key_size, val_size, val_at, key_at, len_at, edge_at, parent_at, slot_at):
        self.key_size, self.val_size, self.val_at, self.key_at = key_size, val_size, val_at, key_at
        self.len_at, self.edge_at, self.parent_at, self.slot_at = len_at, edge_at, parent_at, slot_at
        self.size = edge_at + 12 * 8


TIME_MAP = Layout(12, 0x18, 8, 0x110, 0x196, 0x198, 0, 0x194)
TOTAL_MAP = Layout(20, 0x10, 0, 0xB8, 0x196, 0x198, 0xB0, 0x194)
USER_MAP = Layout(20, 0x18, 8, 0x110, 0x1EE, 0x1F0, 0, 0x1EC)


def address_of(index):
    return bytes([0x20 + index]) + bytes((0xA0 + index + at * 5) & 0xFF for at in range(19))


def address_index(key):
    index = key[0] - 0x20
    if address_of(index) != key:
        raise Halt("address bytes")
    return index


def signed32(value):
    return value - (1 << 32) if value >> 31 else value


def time_order(key):
    return (signed32(key[0]), key[1], key[2])


def capacity(height):
    return 12 ** (height + 1) - 1


def user_tail(index):
    return bytes((0x31 + index + at) & 0xFF for at in range(16))


class Panic(Exception):
    pass


class Case:
    FIELDS = dict(copy=0, tag=1, now=(0x40000000, 1000, 500), token=150, count=200, decimals=8, symbol=b"HYPE", queue=(), totals=(), users=(), fail=None, again=None, extra_byte=3, view=None)

    def __init__(self, name, **fields):
        self.name = name
        unknown = set(fields) - set(self.FIELDS)
        if unknown:
            raise EvidenceError("unknown field %s" % sorted(unknown))
        for key, value in self.FIELDS.items():
            setattr(self, key, fields.get(key, value))


class Spec:
    """Rule list of one or two block steps; written from the rules, shares no code with the harness tree walks."""

    def __init__(self, case):
        self.case = case
        self.queue = {key: rows for key, rows, _ in case.queue}
        self.spare = {key: spare for key, _, spare in case.queue}
        self.totals = {user: [pending, count] for user, pending, count in case.totals}
        self.users = {user: amount for user, amount in case.users}
        self.events = []
        self.records = []
        self.frees = []

    def step(self, now):
        c = self.case
        if c.tag & MASK[4] != 1:
            return
        self.events.append(("name", c.token))
        self.events.append(("handle", c.token))
        due = sorted((key for key in self.queue if time_order(key) < time_order(now)), key=time_order)
        rows = []
        stop = False
        cap = 0
        for key in due:
            value = self.queue.pop(key)
            if value is None:
                stop = True
                continue
            if len(value) + self.spare[key]:
                self.frees.append((len(value) + self.spare[key]) * 0x20)
            if stop:
                continue
            for at, row in enumerate(value):
                left = len(value) - at - 1
                if not rows:
                    cap = max(3, left) + 1
                elif len(rows) == cap:
                    self.frees.append(cap * 0x20)
                    cap = max(4, cap * 2, cap + left + 1)
                rows.append(row)
                self.lower(*row)
        if cap:
            self.frees.append(cap * 0x20)
        kept = []
        for amount, user in rows:
            have = self.users.get(user)
            if have is None or have < amount:
                continue
            self.users[user] = have - amount
            kept.append((amount, user))
        for amount, user in kept:
            self.events.append(("credit", user, c.token, amount))
            if c.fail == 0x14:
                raise Panic("alloc")
            if c.fail == len(c.symbol) and c.symbol:
                raise Panic("alloc")
            if c.token >= c.count:
                raise Panic("unwrap")
            value = float(amount) / float(10 ** c.decimals)
            self.events.append(("sink", user, c.symbol, to_bits(value), now))
            if c.copy == 2:
                self.events.append(("extra", amount, c.token, user, c.extra_byte))
        if c.symbol:
            self.frees.append(len(c.symbol))

    def lower(self, amount, user):
        row = self.totals.get(user)
        if row is None:
            row = self.totals[user] = [0, 0]
        if amount > row[0]:
            self.records.append("sub")
            row[0] = 0
        else:
            row[0] -= amount
        old = row[1]
        row[1] = max(old - 1, 0)
        if old <= 1:
            del self.totals[user]


def spec_view(case):
    user, flag, stake = case.view
    users = dict(case.users)
    totals = {row[0]: row[1] for row in case.totals}
    held = users.get(user, 0) + stake
    if held > TOP:
        return ("view", None, (user,))
    if flag & 0xFF:
        return ("view", held, (user,))
    return ("view", max(held - totals.get(user, 0), 0), (user,))


def spec_run(case):
    if case.view is not None:
        return spec_view(case)
    spec = Spec(case)
    end = ("done", "")
    try:
        spec.step(case.now)
        if case.again is not None:
            spec.step(case.again)
    except Panic as caught:
        end = ("panic", str(caught))
    state = None
    if end[0] == "done":
        state = (tuple(sorted(((key, spec.queue[key]) for key in spec.queue), key=lambda row: time_order(row[0]))), tuple((user, row[0], row[1]) for user, row in sorted(spec.totals.items())), tuple(sorted(spec.users.items())))
    return end + (tuple(spec.events), tuple(spec.records), state, tuple(sorted(spec.frees)) if end[0] == "done" else None)


class Harness:
    def __init__(self, image, patches=None):
        self.image = image
        machine = Machine(image, patches)
        self.machine = machine
        machine.real = frozenset(TARGETS)
        statics = machine.memory.statics
        hooks = {SLOT_COMPARE: self.on_compare, SLOT_COPY: self.on_copy, SLOT_MOVE: self.on_copy, SLOT_ALLOC: self.on_alloc, SLOT_FREE: self.on_free, SLOT_ALLOC_FAIL: self.on_alloc_fail, SLOT_NODE_FAIL: self.on_alloc_fail, SLOT_UNWRAP: self.on_unwrap,
                 SLOT_ASSERT: self.on_stop, SLOT_RECORD: self.on_record, SLOT_NAME: self.on_name, SLOT_HANDLE: self.on_handle, SLOT_SINK: self.on_sink, SLOT_SINK_C: self.on_sink, SLOT_EXTRA_C: self.on_extra, SLOT_STAKE_SUM: self.on_stake_sum}
        for slot, hook in hooks.items():
            marker = MARK_BASE + slot
            statics[slot] = marker
            machine.slots[marker] = hook
        machine.calls = {CREDIT: self.on_credit, LEAF_INSERT: self.on_leaf_insert, REMOVE_KV: self.on_remove_kv, GROW: self.on_grow}
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

    def on_stop(self, machine):
        raise Panicked("stop")

    def on_unwrap(self, machine):
        raise Panicked("unwrap")

    def on_alloc_fail(self, machine):
        raise Panicked("alloc")

    def on_compare(self, machine):
        regs = machine.regs
        size = regs[RDX]
        self.expect(size == 20, "compare length")
        left, right = self.bytes_at(regs[RDI], size), self.bytes_at(regs[RSI], size)
        result = 0 if left == right else 0x1234 if left > right else -0x1234
        regs[RAX] = (0x5A5A5A5A << 32) | result & MASK[4]

    def on_copy(self, machine):
        regs = machine.regs
        self.expect(regs[RDX] <= 0x400, "copy length")
        if regs[RDX]:
            machine.memory.copy(regs[RDI], regs[RSI], regs[RDX])
        regs[RAX] = regs[RDI]

    def allocate(self, size):
        at = self.arena
        self.arena += (size + 15) & ~15
        self.expect(self.arena < HEAP_BASE + USED, "arena")
        self.machine.memory.put_bytes(at, bytes([FILL]) * size)
        return at

    def on_alloc(self, machine):
        size = machine.regs[RDI]
        if self.case.fail == size:
            machine.regs[RAX] = 0
            return
        machine.regs[RAX] = self.allocate(size)

    def on_free(self, machine):
        size = machine.regs[RSI]
        if size not in (LEAF, INNER):
            self.frees.append(size)

    def on_record(self, machine):
        self.expect(machine.regs[RDI] & MASK[4] == 0, "recorder direction")
        self.expect(machine.regs[RSI] == SITE_SUB, "recorder site")
        self.records.append("sub")

    def on_name(self, machine):
        regs = machine.regs
        self.expect(regs[RSI] == self.case.token and regs[RDX] == EX + E_META, "name arguments")
        name = self.case.symbol
        at = self.allocate(len(name)) if name else 1
        if name:
            machine.memory.put_bytes(at, name)
        self.word(regs[RDI], len(name))
        self.word(regs[RDI] + 8, at)
        self.word(regs[RDI] + 0x10, len(name))
        self.events.append(("name", regs[RSI]))

    def on_handle(self, machine):
        regs = machine.regs
        self.expect(regs[RDI] == EX + E_TAG and regs[RDX] == EX + COPIES[self.case.copy].handle_arg, "handle arguments")
        self.events.append(("handle", regs[RSI]))
        regs[RAX] = HANDLE_VALUE

    def on_credit(self, machine):
        regs = machine.regs
        self.expect(regs[RDI] == EX + E_TAG and regs[RCX] & MASK[1] == 0 and regs[R9] == HANDLE_VALUE, "credit arguments")
        self.events.append(("credit", address_index(self.bytes_at(regs[RSI], 20)), regs[RDX], regs[R8]))

    def on_sink(self, machine):
        regs = machine.regs
        copy = COPIES[self.case.copy]
        self.expect(regs[RDI] == EX + copy.sink_state, "sink state")
        vector = regs[RSI]
        self.expect(self.read(vector) == 1 and self.read(vector + 0x10) == 1, "user list")
        user = address_index(self.bytes_at(self.read(vector + 8), 20))
        date, seconds_value, nanos = self.read(regs[RDX], 4), self.read(regs[RDX] + 4, 4), self.read(regs[RDX] + 8, 4)
        self.expect(self.bytes_at(regs[RCX], 32) == bytes(32), "zero hash")
        if self.case.copy < 2:
            self.expect(regs[RCX] == LOG_ZERO, "zero hash address")
        record = regs[R8]
        self.expect(self.read(record) == KIND and self.read(record + 8) == self.read(record + 0x18) and self.read(record + 0x28, 1) == 0, "record words")
        name = self.bytes_at(self.read(record + 0x10), self.read(record + 0x18)) if self.read(record + 0x18) else b""
        self.events.append(("sink", user, name, self.read(record + 0x20), (date, seconds_value, nanos)))

    def on_extra(self, machine):
        regs = machine.regs
        row = regs[RSI]
        self.expect(regs[RDI] == EX + COPIES[2].sink_state and self.read(row + 0x10) == EX and self.read(row + 0x18) == EX + E_META and self.read(row + 0x35, 1) == 1, "extra arguments")
        self.events.append(("extra", self.read(row), self.read(row + 8), address_index(self.bytes_at(row + 0x20, 20)), self.read(row + 0x34, 1)))

    def on_stake_sum(self, machine):
        regs = machine.regs
        self.expect(regs[RDI] == EX + S_SHIFT + S_DELEGATIONS, "stake map")
        self.events.append(address_index(self.bytes_at(regs[RSI], 20)))
        regs[RAX] = self.case.view[2]

    def on_grow(self, machine):
        regs = machine.regs
        vector = regs[RDI]
        cap, ptr = self.read(vector), self.read(vector + 8)
        self.expect(regs[RSI] == cap and regs[RCX] == 8 and regs[R8] == 0x20 and regs[RDX] >= 1, "grow arguments")
        new = max(4, cap * 2, cap + regs[RDX])
        at = self.allocate(new * 0x20)
        machine.memory.copy(at, ptr, cap * 0x20)
        self.frees.append(cap * 0x20)
        self.word(vector, new)
        self.word(vector + 8, at)

    def on_leaf_insert(self, machine):
        regs = machine.regs
        handle, holder = regs[RSI], self.read(regs[R9])
        self.expect(regs[RCX] == 0 and regs[R8] == 0, "entry value")
        key = self.bytes_at(regs[RDX], 20)
        rows = self.pairs(TOTAL_MAP, holder)
        self.expect(all(row[0] != key for row in rows), "insert of a present key")
        self.expect(self.read(handle + 8) == 0, "leaf handle")
        rows = sorted(rows + [(key, bytes(0x10))])
        self.holder(holder, TOTAL_MAP, rows)
        self.word(holder + 0x10, len(rows) - 1)
        for node, index in self.walk(TOTAL_MAP, self.read(holder), self.read(holder + 8)):
            if self.bytes_at(node + TOTAL_MAP.key_at + 20 * index, 20) == key:
                self.word(regs[RDI], node)
                self.word(regs[RDI] + 8, 0)
                self.word(regs[RDI] + 0x10, index)

    def on_remove_kv(self, machine):
        regs = machine.regs
        handle = regs[RSI]
        node, index, holder = self.read(handle), self.read(handle + 0x10), self.read(handle + 0x18)
        rows = self.pairs(TOTAL_MAP, holder)
        key = self.bytes_at(node + TOTAL_MAP.key_at + 20 * index, 20)
        value = self.bytes_at(node + 0x10 * index, 0x10)
        rows = [row for row in rows if row[0] != key]
        self.machine.memory.put_bytes(regs[RDI], key)
        self.machine.memory.put_bytes(regs[RDI] + 0x18, value)
        if rows:
            self.holder(holder, TOTAL_MAP, rows)
        else:
            self.word(holder, self.node(TOTAL_MAP, (), ()))
            self.word(holder + 8, 0)
        self.word(holder + 0x10, len(rows) + 1)

    def walk(self, layout, root, height):
        """In-order (node, index) pairs of a real tree, checking its parent links and depth."""
        found = []
        if not root:
            return found
        count = self.read(root + layout.len_at, 2)
        self.expect(count <= 11, "node length")
        for at in range(count + 1 if height else 0):
            child = self.read(root + layout.edge_at + 8 * at)
            self.expect(self.read(child + layout.parent_at) == root and self.read(child + layout.slot_at, 2) == at, "parent link")
        for at in range(count):
            if height:
                found.extend(self.walk(layout, self.read(root + layout.edge_at + 8 * at), height - 1))
            found.append((root, at))
        if height:
            found.extend(self.walk(layout, self.read(root + layout.edge_at + 8 * count), height - 1))
        return found

    def pairs(self, layout, holder):
        rows = []
        for node, index in self.walk(layout, self.read(holder), self.read(holder + 8)):
            rows.append((self.bytes_at(node + layout.key_at + layout.key_size * index, layout.key_size), self.bytes_at(node + layout.val_at + layout.val_size * index, layout.val_size)))
        self.expect(len(rows) == self.read(holder + 0x10), "map length")
        return rows

    def node(self, layout, items, children):
        base = self.next_node
        size = LEAF if not children and layout is not USER_MAP else layout.size
        self.next_node += layout.size + 0x10
        self.expect(self.next_node < ARENA, "node area")
        memory = self.machine.memory
        memory.put_bytes(base, bytes([FILL]) * (layout.size + 0x10))
        for at, (key, value) in enumerate(items):
            memory.put_bytes(base + layout.key_at + layout.key_size * at, key)
            memory.put_bytes(base + layout.val_at + layout.val_size * at, value)
        for at in range(len(items), 11):
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

    def holder(self, at, layout, items):
        if not items:
            self.word(at, 0)
            self.word(at + 8, 0xB1B1)
            self.word(at + 0x10, 0)
            return
        height = 0
        while capacity(height) < len(items):
            height += 1
        self.word(at, self.build(layout, list(items), height))
        self.word(at + 8, height)
        self.word(at + 0x10, len(items))

    def frozen(self, copy):
        data = bytearray(self.bytes_at(EX, EX_SIZE))
        for offset in (copy.queue, copy.totals):
            data[offset:offset + 0x18] = bytes(0x18)
        return hashlib.sha256(bytes(data)).hexdigest()

    def fresh(self, case):
        memory = self.machine.memory
        memory.reset(USED)
        memory.put_bytes(EX, bytes([FILL]) * EX_SIZE)
        self.next_node = NODES
        self.arena = ARENA
        self.case = case
        self.records = []
        self.events = []
        self.frees = []
        copy = COPIES[case.copy]
        for at, value in enumerate(case.now):
            self.word(EX + E_NOW + 4 * at, value, 4)
        self.word(EX + E_TAG, case.tag | 0x77777777 << 32)
        self.word(EX + E_TOKEN, case.token)
        self.word(EX + E_TABLE, TOKENS - TOKEN_ROW * case.token)
        self.word(EX + E_COUNT, case.count)
        self.word(TOKENS + ROW_DECIMALS, case.decimals, 1)
        self.word(EX + E_EXTRA_BYTE, case.extra_byte, 1)
        items = []
        for key, rows, spare in sorted(case.queue, key=lambda row: time_order(row[0])):
            if rows is None:
                value = struct.pack("<QQQ", NICHE, 0x1234, 0x1234)
            else:
                cap = len(rows) + spare
                at = self.allocate(cap * 0x20) if cap else 8
                for place, (amount, user) in enumerate(rows):
                    memory.put_bytes(at + 0x20 * place, struct.pack("<Q", amount) + address_of(user) + b"\xDD\xDD\xDD\xDD")
                value = struct.pack("<QQQ", cap, at, len(rows))
            items.append((struct.pack("<III", *key), value))
        self.holder(EX + copy.queue, TIME_MAP, items)
        self.holder(EX + copy.totals, TOTAL_MAP, [(address_of(user), struct.pack("<QQ", pending, count)) for user, pending, count in sorted(case.totals)])
        self.holder(EX + copy.users, USER_MAP, [(address_of(user), struct.pack("<Q", amount) + user_tail(user)) for user, amount in sorted(case.users)])
        self.frozen_digest = self.frozen(copy)

    def state(self):
        copy = COPIES[self.case.copy]
        queue = []
        for key, value in self.pairs(TIME_MAP, EX + copy.queue):
            cap, at, count = struct.unpack("<QQQ", value)
            rows = None if cap == NICHE else tuple((self.read(at + 0x20 * place), address_index(self.bytes_at(at + 0x20 * place + 8, 20))) for place in range(count))
            queue.append((struct.unpack("<III", key), rows))
        totals = [(address_index(key),) + struct.unpack("<QQ", value) for key, value in self.pairs(TOTAL_MAP, EX + copy.totals)]
        users = []
        for key, value in self.pairs(USER_MAP, EX + copy.users):
            user = address_index(key)
            self.expect(value[8:] == user_tail(user), "user words")
            users.append((user, struct.unpack_from("<Q", value)[0]))
        self.expect(self.frozen(copy) == self.frozen_digest, "bytes outside the maps")
        return (tuple(queue), tuple(totals), tuple(users))

    def run_view(self, case):
        self.machine.memory.put_bytes(TOKENS + 0x100, address_of(case.view[0]))
        some = self.machine.run(AVAILABLE, {RDI: EX + S_SHIFT, RSI: TOKENS + 0x100, RDX: case.view[1]})
        return ("view", self.machine.regs[RDX] if some else None, tuple(self.events))

    def run(self, case):
        self.fresh(case)
        machine = self.machine
        if case.view is not None:
            return self.run_view(case)
        entry = COPIES[case.copy].entry
        try:
            machine.run(entry, {RDI: EX})
            if case.again is not None:
                for at, value in enumerate(case.again):
                    self.word(EX + E_NOW + 4 * at, value, 4)
                self.frozen_digest = self.frozen(COPIES[case.copy])
                machine.run(entry, {RDI: EX})
        except Panicked as caught:
            return ("panic", str(caught), tuple(self.events), tuple(self.records), None, None)
        return ("done", "", tuple(self.events), tuple(self.records), self.state(), tuple(sorted(self.frees)))


NOW = (0x40000000, 1000, 500)


def key_at(step):
    """Keys spaced by 10 nanoseconds below and above NOW."""
    return (NOW[0], NOW[1], (NOW[2] + 10 * step) & MASK[4])


def row_at(step, rows, spare=0):
    return (key_at(step), rows, spare)


def single(label, amount=100, pending=100, count=1, balance=100, **fields):
    base = dict(queue=(row_at(-1, ((amount, 1),)),), totals=((1, pending, count),), users=((1, balance),))
    base.update(fields)
    return Case(label, **base)


def many(size, cut, user_of=lambda at: at % 3 + 1, per=1):
    """`size` queue keys with `cut` of them due; totals and balances cover every row exactly."""
    queue, totals, users = [], {}, {}
    for at in range(size):
        rows = tuple((1000 + at + part, user_of(at + part)) for part in range(per))
        queue.append(row_at(at - cut, rows))
        if at < cut:
            for amount, user in rows:
                totals.setdefault(user, [0, 0])
                totals[user][0] += amount
                totals[user][1] += 1
                users[user] = users.get(user, 0) + amount
    return dict(queue=tuple(queue), totals=tuple((user, row[0], row[1]) for user, row in sorted(totals.items())), users=tuple(sorted(users.items())))


def base_cases():
    out = [Case("empty_queue"), single("one_row_exact"), single("tag_zero", tag=0), single("tag_two", tag=2), single("tag_high_word", tag=0x100000001), single("tag_high_only", tag=0x100000000)]
    for name, key, due in (("key_equal_now", NOW, 0), ("key_one_nano_below", (NOW[0], NOW[1], NOW[2] - 1), 1), ("key_one_nano_above", (NOW[0], NOW[1], NOW[2] + 1), 0), ("key_second_below", (NOW[0], NOW[1] - 1, 0xFFFFFFFF), 1), ("key_second_above", (NOW[0], NOW[1] + 1, 0), 0),
                           ("key_date_below", (NOW[0] - 1, 0xFFFFFFFF, 0xFFFFFFFF), 1), ("key_date_above", (NOW[0] + 1, 0, 0), 0), ("key_date_negative", (0x80000000, 0xFFFFFFFF, 0xFFFFFFFF), 1), ("key_date_top", (0x7FFFFFFF, 0, 0), 0), ("key_date_high_bit_unsigned_above", (0xC0000000, 0, 0), 1)):
        out.append(single(name, queue=((key, ((100, 1),), 0),)))
    out.append(Case("now_negative_date", now=(0x80000010, 0, 0), queue=(((0x80000000, 1, 1), ((5, 1),), 0), ((0x80000020, 1, 1), ((6, 1),), 0), ((5, 1, 1), ((7, 1),), 0)), totals=((1, 18, 3),), users=((1, 18),)))
    for size in (1, 2, 5, 11, 12, 13, 17, 23, 24, 35, 47, 60, 72, 100):
        for cut in sorted({0, 1, 2, size // 3, size // 2, size - 2, size - 1, size} - {-1}):
            if 0 <= cut <= size:
                out.append(Case("split_%d_%d" % (size, cut), **many(size, cut)))
    for size in (144, 200):
        for cut in (1, 7, 40, size // 2, size - 30, size - 1, size):
            out.append(Case("split_%d_%d" % (size, cut), **many(size, cut, lambda at: at % 5 + 1)))
    for cut in range(1, 24):
        out.append(Case("walk_24_%d" % cut, **many(24, cut)))
    for cut in range(1, 36):
        out.append(Case("walk_36_%d" % cut, **many(36, cut)))
    for per in (2, 3, 4, 5, 6, 9):
        out.append(Case("rows_per_key_%d" % per, **many(6, 4, per=per)))
    out.append(Case("empty_row_list", queue=(row_at(-3, ()), row_at(-2, ((7, 1),)), row_at(-1, ())), totals=((1, 7, 1),), users=((1, 7),)))
    out.append(Case("all_row_lists_empty", queue=(row_at(-2, ()), row_at(-1, ()))))
    out.append(Case("spare_room_freed", queue=(row_at(-2, ((7, 1),), 3), row_at(-1, (), 2)), totals=((1, 7, 1),), users=((1, 7),)))
    out.append(Case("none_niche_first", queue=(row_at(-2, None), row_at(-1, ((7, 1),))), totals=((1, 7, 1),), users=((1, 7),)))
    out.append(Case("none_niche_after_row", queue=(row_at(-3, ((7, 1),)), row_at(-2, None), row_at(-1, ((8, 1),))), totals=((1, 15, 2),), users=((1, 15),)))
    out.extend((single("pending_left", pending=250, count=2), single("pending_left_last_count", pending=250, count=1), single("pending_short", pending=40, count=2), single("pending_short_last", pending=40, count=1),
                single("pending_zero_count_zero", pending=0, count=0), single("count_zero_pending_kept", pending=500, count=0), single("count_top", pending=TOP, count=TOP), single("amount_zero", amount=0, pending=0, count=1), single("amount_zero_left", amount=0, pending=9, count=3),
                single("total_absent", totals=()), single("total_absent_other_row", totals=((2, 5, 1),)), single("total_absent_amount_zero", amount=0, totals=()), single("total_absent_amount_zero_tree", amount=0, totals=((0, 5, 1), (2, 5, 1))),
                Case("total_absent_two_rows", queue=(row_at(-2, ((7, 1),)), row_at(-1, ((8, 1),))), users=((1, 15),))))
    out.append(Case("same_user_two_rows_last_removes", queue=(row_at(-1, ((7, 1), (8, 1))),), totals=((1, 15, 2),), users=((1, 15),)))
    out.append(Case("removed_then_vacant", queue=(row_at(-1, ((7, 1), (8, 1))),), totals=((1, 15, 1),), users=((1, 15),)))
    out.append(Case("totals_tree_one_level", queue=(row_at(-1, ((7, 3),)),), totals=tuple((user, 7, 1) for user in range(16)), users=((3, 7),)))
    out.append(Case("totals_tree_two_levels", queue=(row_at(-1, ((7, 90), (8, 150))),), totals=tuple((user, 100, 2) for user in range(160)), users=((90, 7), (150, 8))))
    out.append(Case("totals_tree_key_absent", queue=(row_at(-1, ((7, 200),)),), totals=tuple((user, 100, 2) for user in range(0, 60, 2)), users=((200, 7),)))
    out.extend((single("user_absent", users=()), single("user_absent_other", users=((2, 500),)), single("balance_short", balance=99), single("balance_exact", balance=100), single("balance_more", balance=1000), single("balance_zero_amount_zero", amount=0, pending=0, balance=0)))
    out.append(Case("second_row_short_after_first", queue=(row_at(-2, ((70, 1),)), row_at(-1, ((50, 1),))), totals=((1, 120, 2),), users=((1, 100),)))
    out.append(Case("short_row_then_small_row", queue=(row_at(-2, ((150, 1),)), row_at(-1, ((50, 1),))), totals=((1, 200, 2),), users=((1, 100),)))
    out.append(Case("filter_all_dropped", queue=(row_at(-2, ((7, 1),)), row_at(-1, ((8, 2),))), totals=((1, 7, 1), (2, 8, 1)), users=((3, 100),)))
    out.append(Case("filter_middle_dropped", queue=(row_at(-3, ((7, 1),)), row_at(-2, ((8, 2),)), row_at(-1, ((9, 3),))), totals=((1, 7, 1), (2, 8, 1), (3, 9, 1)), users=((1, 7), (3, 9))))
    out.append(Case("users_tree_one_level", queue=(row_at(-1, ((7, 13),)),), totals=((13, 7, 1),), users=tuple((user, 50 + user) for user in range(30))))
    out.append(Case("users_tree_two_levels", queue=(row_at(-2, ((7, 13),)), row_at(-1, ((8, 170),))), totals=((13, 7, 1), (170, 8, 1)), users=tuple((user, 50 + user) for user in range(200))))
    out.append(Case("users_tree_key_absent", queue=(row_at(-1, ((7, 201),)),), totals=((201, 7, 1),), users=tuple((user, 50) for user in range(0, 180, 2))))
    out.extend((single("token_zero", token=0), single("token_last", token=199), single("token_past", token=200), single("token_past_no_kept_row", token=200, users=()), single("token_far_past", token=5000, count=3)))
    for decimals in (0, 1, 2, 5, 6, 7, 8, 18):
        out.append(single("decimals_%d" % decimals, decimals=decimals, amount=123456789, pending=123456789, balance=123456789))
    out.extend((single("name_empty", symbol=b""), single("name_long", symbol=b"LONGERTOKEN"), single("fail_user_list", fail=0x14), single("fail_name_copy", fail=4), single("fail_second_row", fail=0x14, queue=(row_at(-1, ((7, 1), (8, 1))),), totals=((1, 15, 2),), users=((1, 15),))))
    for name, amount in (("amount_2_53_plus_1", (1 << 53) + 1), ("amount_2_63", 1 << 63), ("amount_top", TOP), ("amount_low_word_high_bit", 0x80000000), ("amount_mixed_words", 0x123456789ABCDEF)):
        out.append(single(name, amount=amount, pending=amount, balance=amount))
    out.append(Case("again_later_key", now=key_at(0), again=key_at(5), queue=(row_at(-1, ((7, 1),)), row_at(3, ((8, 1),)), row_at(9, ((9, 1),))), totals=((1, 24, 3),), users=((1, 24),)))
    out.append(Case("again_nothing_left", now=key_at(0), again=key_at(5), queue=(row_at(-1, ((7, 1),)),), totals=((1, 7, 1),), users=((1, 7),)))
    out.append(Case("again_empty_twice", now=key_at(0), again=key_at(5)))
    out.append(Case("again_key_then_equal", now=key_at(0), again=key_at(4), queue=(row_at(0, ((7, 1),)), row_at(4, ((8, 1),)), row_at(5, ((9, 1),))), totals=((1, 24, 3),), users=((1, 24),)))
    grown = many(30, 10)
    out.append(Case("again_tree_shrinks", now=key_at(0), again=key_at(12), queue=grown["queue"], totals=((1, 40000, 40), (2, 40000, 40), (3, 40000, 40)), users=((1, 40000), (2, 40000), (3, 40000))))
    out.append(single("extra_byte_top", extra_byte=0xFF))
    return out


def view_cases():
    rows = dict(totals=((1, 30, 2), (2, 500, 1)), users=((1, 100), (3, 7)))
    out = []
    for name, user, flag, stake in (("plain", 1, 0, 50), ("flag_set", 1, 1, 50), ("flag_high_bits", 1, 0x100, 50), ("flag_any_low", 1, 0x80, 50), ("no_pending", 3, 0, 5), ("no_user_pending_left", 2, 0, 100), ("short_to_zero", 2, 0, 10), ("exact_zero", 2, 0, 500), ("no_rows", 4, 0, 9),
                                    ("wrap", 1, 0, TOP), ("wrap_flag", 1, 1, TOP), ("top_no_wrap", 1, 0, TOP - 100), ("top_no_wrap_flag", 1, 1, TOP - 100)):
        out.append(Case("view_" + name, view=(user, flag, stake), **rows))
    big = dict(totals=tuple((user, user * 10, 1) for user in range(40)), users=tuple((user, user * 100) for user in range(40)))
    for user in (0, 5, 11, 12, 13, 20, 39):
        out.append(Case("view_tree_%d" % user, view=(user, 0, 1000), **big))
    out.append(Case("view_tree_absent", view=(50, 0, 1000), **big))
    out.append(Case("view_empty_maps", view=(1, 0, 3)))
    return out


def named_cases():
    out = []
    for copy in range(3):
        for case in base_cases():
            case.copy = copy
            case.name = "%s_%s" % ("abc"[copy], case.name)
            out.append(case)
    return out + view_cases()


def vector_cases(count, seed=0x2109):
    rng = random.Random(seed)
    out = []
    for at in range(count):
        size = rng.choice((0, 1, 2, 3, 5, 8, 12, 15, 20, 30, 48))
        cut = rng.randint(0, 12) if size else 0
        users = rng.choice((2, 3, 6, 14, 30))
        queue = []
        steps = rng.sample(range(-cut * 2 - 2, size * 2 + 2), size)
        amounts = []
        for step in steps:
            rows = []
            for _ in range(rng.choice((0, 1, 1, 1, 2, 3, 6))):
                amount = rng.choice((0, 1, 5, 100, 1000, rng.getrandbits(20), rng.getrandbits(64)))
                rows.append((amount, rng.randrange(users)))
                amounts.append(rows[-1])
            queue.append(row_at(step, tuple(rows), rng.choice((0, 0, 1, 3))))
        totals = []
        balances = []
        for user in range(users):
            if rng.random() < 0.8:
                totals.append((user, rng.choice((0, 50, 2000, 1 << 40, sum(a for a, u in amounts if u == user) & TOP)), rng.choice((0, 1, 2, 3, 5))))
            if rng.random() < 0.8:
                balances.append((user, rng.choice((0, 50, 2000, 1 << 40, TOP, sum(a for a, u in amounts if u == user) & TOP))))
        if at % 10 == 9:
            out.append(Case("vector_%d" % at, view=(rng.randrange(users + 1), rng.getrandbits(1), rng.choice((0, 5, 1 << 40, TOP, rng.getrandbits(64)))), totals=tuple(totals), users=tuple(balances)))
            continue
        out.append(Case("vector_%d" % at, copy=at % 3, now=key_at(0), queue=tuple(queue), totals=tuple(totals), users=tuple(balances), decimals=rng.choice((0, 2, 8, 10, 18)), token=rng.choice((0, 7, 150)), again=key_at(rng.randint(1, 40)) if rng.random() < 0.3 else None))
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


def direct_to(image, target):
    start, text = image.text_bytes()
    hits = []
    for match in re.finditer(b"\xe8", text):
        at = match.start()
        if at + 5 <= len(text) and start + at + 5 + struct.unpack_from("<i", text, at + 1)[0] == target:
            hits.append(start + at)
    return hits


def slot_sites(image, slot):
    start, text = image.text_bytes()
    hits = []
    for match in re.finditer(b"\xff\x15", text):
        at = match.start()
        if at + 6 <= len(text) and start + at + 6 + struct.unpack_from("<i", text, at + 2)[0] == slot:
            hits.append(start + at)
    return hits


STEP_HOSTS = ((DRAIN, 0x222A12A, 0x22297C0), (DRAIN_B, 0x470F2BE, 0x470E9A0), (DRAIN_C, 0x4716D18, 0x47162D0))


def caller_rows(image):
    rows = []
    for target, site, host in STEP_HOSTS:
        if direct_to(image, target) != [site] or image.fde(site)[0] != host:
            raise EvidenceError("drain step site %#x" % target)
        rows.append(("step", NAMES[target], "%#x" % target, 1, "%#x in %#x" % (site, host)))
    for target in TARGETS[3:-1]:
        sites = sorted(direct_to(image, target))
        rows.append(("direct", NAMES[target], "%#x" % target, len(sites), " ".join("%#x" % site for site in sites[:12])))
    relative = image.relative()
    for name, slot, target in (("available_amount", SLOT_AVAILABLE, AVAILABLE), ("stake_sum", SLOT_STAKE_SUM, 0x3C0F050), ("token_name", SLOT_NAME, 0x3C0D6E0), ("balance_handle", SLOT_HANDLE, 0x371CF40), ("ledger_sink", SLOT_SINK, 0x3576710), ("ledger_sink_c", SLOT_SINK_C, 0x4855A50), ("extra_event_c", SLOT_EXTRA_C, 0x4856E20)):
        if relative.get(slot) != target:
            raise EvidenceError("slot %#x" % slot)
        sites = sorted(slot_sites(image, slot))
        rows.append(("slot %#x" % slot, name, "%#x" % target, len(sites), " ".join("%#x" % site for site in sites[:6])))
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
    first = table[DRAIN]
    base_end = image.exact_fde(DRAIN)[1]
    base_calls = call_targets(first)
    for other in (DRAIN_B, DRAIN_C):
        extent = image.exact_fde(other)
        second = table[other]
        same = sum(1 for left, right in zip(first, second) if shape(left, DRAIN, base_end) == shape(right, other, extent[1])) if len(first) == len(second) else 0
        rows.append((NAMES[other], "%#x" % other, extent[1] - extent[0], len(second), same, " ".join("%#x" % va for va in sorted(call_targets(second) - base_calls)) or "none"))
    return rows


FIELDS = (("user_states", 0x3DF9E4, 11, 0x1F8, 0x238D653, "lea"), ("pending_withdrawals", 0x3E05FA, 19, 0x210, 0x238D66F, "lea"))
TEXTS = (("queue", 0x5B874D, 5, 0x3C1398C), ("user_to_total_withdrawal", 0x5B8752, 24, 0x3C139C9))
IMMEDIATES = (
    ("gate_tag", 0x26FDB01, "83bf8000000001", "cmp dword [rdi+0x80],1: any other low word ends the step"),
    ("queue_field", 0x26FDB6D, "498db6080b0000", "lea rsi,[r14+0xb08]: staking +0x8f8 plus +0x210"),
    ("user_field", 0x26FDB9E, "498d86f00a0000", "lea rax,[r14+0xaf0]: staking +0x8f8 plus +0x1f8"),
    ("copy_c_queue_field", 0x4CE5C65, "498db788150000", "lea rsi,[r15+0x1588]: same field, shifted by 0xa80"),
    ("copy_c_user_field", 0x4CE5CA2, "498d8770150000", "lea rax,[r15+0x1570]: same field, shifted by 0xa80"),
    ("totals_field", 0x3C13478, "4983c618", "add r14,0x18: the total map sits after the time map"),
    ("drain_deposit_byte", 0x26FDDBF, "c68424e800000000", "mov byte [rsp+0xe8],0: the record byte is 0 here and 1 in the deposit"),
    ("kind_word", 0x26FDDC7, "48b81600000000000080", "movabs rax,0x8000000000000016: record kind word"),
    ("token_stride", 0x26FDC34, "4869442418e8000000", "imul rax,[rsp+0x18],0xe8: token row stride"),
    ("decimals_field", 0x26FDD6C, "0fb6440849", "movzx eax,byte [rax+rcx+0x49]: wei decimals byte"),
    ("row_stride", 0x26FDDFB, "4983c720", "add r15,0x20: queue rows are 32 bytes"),
    ("count_rule", 0x3BABEF8, "4883e801", "sub rax,1: count falls, the ja after it keeps a row only when the old count was above 1"),
    ("balance_rule", 0x3308434, "482b442460", "sub rax,[rsp+0x60]: amount from the first word of the user row"),
)


def proof_row(image, va):
    base = image.offset(va)
    code = bytes(image.blob[base:base + 32])
    return decode(lambda at, count: code[at - va:at - va + count], va), code


def field_rows(image):
    rows = []
    for name, key, size, offset, proof, op in FIELDS:
        text = bytes(image.blob[image.offset(key):image.offset(key) + size]).decode("ascii")
        if text != name:
            raise EvidenceError("key text %s" % text)
        row, code = proof_row(image, proof)
        operand = row.b if row.b and row.b[0] == "m" else row.a
        if operand[4] != offset:
            raise EvidenceError("field proof %#x" % proof)
        rows.append((name, "%#x" % key, "%#x" % offset, "%#x" % proof, code[:row.size].hex()))
    for name, key, size, proof in TEXTS:
        text = bytes(image.blob[image.offset(key):image.offset(key) + size]).decode("ascii")
        code = bytes(image.blob[image.offset(proof):image.offset(proof) + 7])
        if text != name or code[:3] != b"\x48\x8d\x35" or proof + 7 + struct.unpack_from("<i", code, 3)[0] != key:
            raise EvidenceError("text %s" % name)
        rows.append((name, "%#x" % key, "text", "%#x" % proof, code.hex()))
    return rows


def constant_rows(image):
    rows = []
    for name, va, form, note in IMMEDIATES:
        want = bytes.fromhex(form)
        if bytes(image.blob[image.offset(va):image.offset(va) + len(want)]) != want:
            raise EvidenceError("immediate %s" % name)
        rows.append((name, "%#x" % va, form, note))
    for power in range(23):
        data = struct.pack("<d", 10.0 ** power)
        if bytes(image.blob[image.offset(POWER_TABLE + 8 * power):image.offset(POWER_TABLE + 8 * power) + 8]) != data:
            raise EvidenceError("power %d" % power)
    rows.append(("power_table", "%#x" % POWER_TABLE, "", "23 doubles 1e0 to 1e22 at index = wei decimals"))
    return rows


def kind_sites(image):
    start, text = image.text_bytes()
    rows = []
    for match in re.finditer(re.escape(b"\x48\xb8" + struct.pack("<Q", KIND)), text):
        at = match.start()
        va = start + at
        byte = text[at - 1] if text[at - 8:at - 5] == b"\xc6\x84\x24" or text[at - 5:at - 3] == b"\xc6\x44" else None
        if byte is None:
            raise EvidenceError("no byte store before %#x" % va)
        rows.append(("%#x" % va, "%#x" % image.fde(va)[0], byte))
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
I, D, C = "immediate", "displacement", "condition"
STEP_FAIL = (0x26FDD30, 0x26FDE51, 0x26FDE56, 0x26FDE72, 0x4CE62D0, 0x4CE63F1, 0x4CE63F6, 0x4CE6412, 0x4CE5E10, 0x4CE5FB9, 0x4CE5FBE, 0x4CE5FDA)
CLASSES = (
    ("dangling name pointer, or size and align arguments of an allocation failure stub: the stub compares neither", tuple((va, I) for va in STEP_FAIL)),
    ("size hint words of the row buffer and the iterator copy length: same rows in every case", tuple((va, D) for va in (0x3BAE248, 0x3BAE263, 0x3BAE26A)) + tuple((va, I) for va in (0x3BAE26E, 0x3BAE293, 0x3BAE2A3, 0x3BAE2CC, 0x3BAE343, 0x3BAE3BC))),
    ("fresh node allocation size: the fixture arena does not check the size", ((0x2FB2CFD, I), (0x2FB2D40, I))),
)
EXPECTED_SURVIVORS = {edit: text for text, edits in CLASSES for edit in edits}
POOL = {}
MUTANT_CASES = 400
MUTANT_LIMIT = 90000


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
    result = dict(table=table, cases=cases, outcomes=outcomes, vector_count=vectors, unreached=unreached, callers=caller_rows(image), constants=constant_rows(image), fields=field_rows(image), kinds=kind_sites(image), copies=copy_rows(image, table))
    if mutate:
        result["mutations"] = run_mutants(image, table, seen, cases, reach)
    return result


def describe(outcome):
    if outcome[0] == "view":
        return ("view", "none" if outcome[1] is None else outcome[1], "", "", "", "", "", "")
    end, text, events, records, state, frees = outcome
    credited = [event for event in events if event[0] == "credit"]
    digest = hashlib.sha256(repr(outcome).encode()).hexdigest()[:16]
    return (end, text, len(credited), sum(event[3] for event in credited) & TOP, len(records), "" if state is None else len(state[0]), "" if state is None else len(state[1]), digest)


def render(result):
    files = {}

    def tsv(name, header, rows):
        lines = ["\t".join(header)] + ["\t".join(str(cell) for cell in row) for row in rows]
        files[name] = "\n".join(lines) + "\n"

    tsv("function-rows.tsv", ("function", "address", "size", "bytes", "operation"),
        [("%#x" % target, "%#x" % row.va, row.size, row.data.hex(), row.op) for target in TARGETS for row in result["table"][target]])
    tsv("callers.tsv", ("reach", "role", "target", "sites", "addresses"), result["callers"])
    tsv("constants.tsv", ("name", "address", "bytes", "note"), result["constants"])
    tsv("field-names.tsv", ("key", "key_address", "offset", "proof_address", "proof_bytes"), result["fields"])
    tsv("kind-sites.tsv", ("kind_word_address", "function", "byte_before_kind"), result["kinds"])
    tsv("copy-compare.tsv", ("copy", "address", "bytes", "rows", "rows_equal_to_first", "calls_not_in_first"), result["copies"])
    tsv("outcomes.tsv", ("case", "end", "panic", "credits", "credit_sum_mod_2_64", "recorder_hits", "queue_keys_left", "total_rows_left", "digest"), [(case.name,) + describe(outcome) for case, outcome in zip(result["cases"], result["outcomes"])])
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
