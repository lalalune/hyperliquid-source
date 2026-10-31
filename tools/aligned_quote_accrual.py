#!/usr/bin/env python3
"""Pin the node #94 aligned quote token accrual: the median rate, the daily owed map and the delayed payout.

Real rows run on a state image with real B-tree nodes: the bucket guard, the vote split, the stake-weighted median, the
sampling block of all three host copies and the map helpers. A separately written rule list predicts the stored words,
the maps and the payout events, and every reached conditional row, immediate and field offset is mutated. No objdump or
readelf output is parsed and the binary is never executed. Standard library only.

    python3 tools/aligned_quote_accrual.py --out <dir>
"""

import argparse
import bisect
import collections
import datetime
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
HEAP_SIZE = 0x40000
RETURN_SENTINEL = 0xDEAD0000
POISON = 0xA5A5A5A5A5A5A5A5
STEP_LIMIT = 3000000
MUTANT_STEP_LIMIT = 200000


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
            return finish("cvtsi2sd", ("x", reg), rm, width)
        if two == 0xC2 and repne:
            reg, rm = modrm(True)
            value = immediate(1) & 0xFF
            return finish("cmpsd", ("x", reg), rm, 8, target=value)
        if two == 0x7E and opsize and not wide:
            reg, rm = modrm()
            return finish("movdr", rm, ("x", reg), 4)
        if two == 0xD6 and opsize:
            reg, rm = modrm(True)
            return finish("movq", rm, ("x", reg), 8)
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
        self.stop = None
        self.frame = 0

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
        self.regs[RSP] -= self.frame
        saved = {reg: self.regs[reg] for reg in CALLEE_SAVED}
        top = self.regs[RSP]
        pc = entry
        limit = self.step_limit
        cache = self.cache
        while pc != RETURN_SENTINEL and pc != self.stop:
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
        if pc == self.stop:
            return None
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
            value = self.get(row.b, row.width)
            self.set_low(row.a[1], to_bits(float(value - (1 << (8 * row.width)) if value & SIGN[row.width] else value)))
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
        elif op == "cmpsd":
            if row.target != 2:
                raise Halt("unmodelled compare predicate at %#x" % row.va)
            left, right = to_float(self.low(row.a)), to_float(self.low(row.b))
            self.set_low(row.a[1], MASK[8] if left <= right else 0)
        elif op == "movdr":
            self.put(row.a, 4, self.xmm[row.b[1]] & MASK[4])
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

OK = 0x186
TAG_NUMBER = 0x13F
TAG_TOKEN = 0xEA
CAP = 0x0CCCCCCCCCCCCCCC
TOP = MASK[8]
YEAR_SECONDS = 31557600.0
FEE_GATE = 1.01
TWO64 = 18446744073709551616.0
CAST_TOP = 18446744073709549568.0
DAYS_MAIN = -45
DAYS_TWO = -2
GUARD = 0x3265810
CLOSURE = 0x3372B00
CLOSURE_STOP = 0x3372EA1
SPLIT = 0x3265980
REMOVE_VOTE = 0x2FD6EC0
COLLECT = 0x32D5280
MEDIAN = 0x3BB6C70
WEIGHTED = 0x336D390
JOIN = 0x3BB1830
SMALL_SORT = 0x3387E80
DROP_NEXT = 0x33B0800
CLOCK = 0x4EE3800
ROW_BUILDER = 0x3BAEDF0
GROW_ANY = 0x32D6A00
SLOT_FREE = 0x576E010
SLOT_ALLOC = 0x576DFD8
SLOT_REALLOC = 0x576E030
SLOT_COPY = 0x576DFE0
SLOT_MOVE = 0x576E0E0
SLOT_CMP = 0x576E488
SLOT_ELAPSED = 0x576E8C0
SLOT_ADD_DAYS = 0x576E8B0
SLOT_RECORDER = 0x5773190
SLOT_GROW_WORD = 0x57744B0
SLOT_GROW_ROW = 0x5774D68
SLOT_GROW_VOTE = 0x5774480
SLOT_ADD_SECONDS = 0x576EFB8
SLOT_STAKES = 0x5775C90
SLOT_SORT = 0x5775C98
SLOT_MEDIAN = 0x5775CA8
ADD_DAYS = 0x151F870
WEI_LOCATION = 0x56DFD78
TIME_TEXT = 0x5B9765
PANIC_SLOTS = (0x576DFB8, 0x576E020, 0x576E470, 0x576E108, 0x576E098, 0x576E468, 0x576DFC8, 0x576E128)
RESUME = 0x5660110
MARK_BASE = 0x7700000000
FILL_END = 0x9000
HEAP_FILL = bytes(((index * 13) ^ (index >> 8)) & 0xFF or 1 for index in range(FILL_END))
S = HEAP_BASE + 0x1000
TRACKER_FAKE = HEAP_BASE + 0x8000
LIST_AT = HEAP_BASE + 0x8100
NOW_AT = HEAP_BASE + 0x8200
KEY_TEXT = 0x5B67C7
BUMP = HEAP_BASE + 0x9000
BUMP_END = HEAP_BASE + 0x3F000
FRAME = 0x600


class Copy:
    def __init__(self, name, entry, stop, host, time_at, tracker, chain, tokens, transfer, drop, insert, remove):
        self.name, self.entry, self.stop, self.host, self.time_at, self.tracker, self.chain, self.tokens = name, entry, stop, host, time_at, tracker, chain, tokens
        self.transfer, self.drop, self.insert, self.remove = transfer, drop, insert, remove


COPIES = (
    Copy("a", 0x2763764, 0x27644E6, 0x2761B20, 0x3ABC, 0x3248, 0x8F2, 0xBC0, 0x2729C30, 0x277EBA0, 0x2878B20, 0x28682A0),
    Copy("b", 0x4D944FE, 0x4D95257, 0x4D92A10, 0x3ABC, 0x3248, 0x8F2, 0xBC0, 0x4D35340, 0x4DAF4A0, 0x4956AE0, 0x4942FC0),
    Copy("c", 0x4D917CE, 0x4D92527, 0x4D8FCE0, 0x453C, 0x3CC8, 0x1372, 0x1640, 0x4D336B0, 0x4DAF4A0, 0x4956AE0, 0x4942FC0),
)
MAP_CODE = tuple(sorted({copy.insert for copy in COPIES} | {copy.remove for copy in COPIES}))
SUBJECTS = (GUARD, SPLIT, MEDIAN, JOIN, SMALL_SORT, COLLECT, REMOVE_VOTE) + MAP_CODE
NAMES = {GUARD: "median_bucket_guard", SPLIT: "split_votes_by_age", MEDIAN: "median_entry", JOIN: "join_rate_to_stake", SMALL_SORT: "small_sort_rate_stake", COLLECT: "collect_rate_rows",
         REMOVE_VOTE: "remove_vote_row", 0x2878B20: "daily_entry_insert_a", 0x4956AE0: "daily_entry_insert_bc", 0x28682A0: "daily_remove_a", 0x4942FC0: "daily_remove_bc"}


class Layout:
    def __init__(self, key_at, key_size, val_at, val_size, len_at, edge_at, index_at, parent_at):
        self.key_at, self.key_size, self.val_at, self.val_size, self.len_at, self.edge_at, self.index_at, self.parent_at = key_at, key_size, val_at, val_size, len_at, edge_at, index_at, parent_at


L_DAILY = Layout(0x60, 4, 8, 8, 0x8E, 0x90, 0x8C, 0)
L_INFO = Layout(0x218, 8, 0, 0x30, 0x272, 0x278, 0x270, 0x210)
L_AQA = Layout(8, 8, 0x60, 0x68, 0x4DA, 0x4E0, 0x4D8, 0)
L_VOTES = Layout(0x110, 20, 8, 0x18, 0x1EE, 0x1F0, 0x1EC, 0)
L_STAKES = Layout(0x60, 20, 8, 8, 0x13E, 0x140, 0x13C, 0)


def date_word(year, ordinal):
    """chrono's packed date: year, ordinal, and the year flags."""
    first = datetime.date(year, 1, 1).weekday()
    leap = year % 4 == 0 and (year % 100 != 0 or year % 400 == 0)
    return year << 13 | ordinal << 4 | _flags(first, leap)


def _flags(weekday, leap):
    """Dominical letter of 1 January: Monday G, Tuesday F, ... Sunday A; a leap year clears bit 3."""
    table = {0: 0o16, 1: 0o17, 2: 0o11, 3: 0o12, 4: 0o13, 5: 0o14, 6: 0o15}
    if leap:
        return {0: 0o06, 1: 0o07, 2: 0o01, 3: 0o02, 4: 0o03, 5: 0o04, 6: 0o05}[weekday]
    return table[weekday]


def word_to_date(word):
    return datetime.date(word >> 13, 1, 1) + datetime.timedelta(days=((word >> 4) & 0x1FF) - 1)


def date_to_word(day):
    return date_word(day.year, day.timetuple().tm_yday)


def add_days(word, days):
    return date_to_word(word_to_date(word) + datetime.timedelta(days=days))


def signed32(word):
    return word - (1 << 32) if word & (1 << 31) else word


def time_ms(now):
    day = word_to_date(now[0])
    days = day.toordinal() - datetime.date(1970, 1, 1).toordinal()
    return max((days * 86400 + now[1]) * 1000 + now[2] // 1000000, 0)


def bits(value):
    return struct.unpack("<Q", struct.pack("<d", value))[0]


def value_of(pattern):
    return struct.unpack("<d", struct.pack("<Q", pattern))[0]


def cast_u64(value):
    """What the rows at the end of the loop do with the clamped product."""
    if value > CAST_TOP:
        return TOP
    return int(value)


def owed(amount, x):
    product = float(amount) * x
    if product != product or product in (float("inf"), float("-inf")):
        return 0
    if product < 0:
        return 0
    if product > TWO64:
        product = TWO64
    return cast_u64(product)


class Row:
    def __init__(self, token, amount, items=(), flag=0, who=1, tree=True):
        self.token, self.amount, self.items, self.flag, self.who, self.tree = token, amount, tuple(sorted(items)), flag, who, tree


class Case:
    DEFAULTS = dict(kind="sample", copy=0, date=date_word(2026, 200), secs=3600, nanos=7000, prev=None, last=None, dt=2.0, tag=1, rate=0.04, chain=3, rows=(), count=1000, decoys=(), refuse=(),
                    period=60000, guard=0, votes=(), stakes=(), old=0.5, large=False)

    def __init__(self, name, **fields):
        self.name = name
        for key, value in self.DEFAULTS.items():
            setattr(self, key, value)
        for key, value in fields.items():
            if key not in self.DEFAULTS:
                raise EvidenceError("unknown case field %s" % key)
            setattr(self, key, value)
        if self.prev is None:
            self.prev = self.date
        if self.last is None:
            self.last = (self.date, 3000, 5000)


def address(number):
    return struct.pack(">Q", 0x1000 + number).rjust(20, b"\xAA")


def spec_sample(case):
    """The rule list of the sampling block. Returns (panic text or None, last time, per token items, events)."""
    now = (case.date, case.secs, case.nanos)
    last = case.last
    if last[0] == 0:
        last = now
    rows = case.rows
    maps = {(row.flag, row.token): dict(row.items) for row in rows}
    events = []
    changed = signed32(case.prev) < signed32(case.date)

    def tail():
        cutoff = add_days(case.date, DAYS_TWO if case.chain == 2 else DAYS_MAIN)
        pay = []
        for row in rows:
            items = maps[row.flag, row.token]
            if cutoff in items:
                pay.append((row, items[cutoff]))
        for row, value in pay:
            if row.flag == 2:
                break
            if row.token >= case.count:
                events.append(("drop", TAG_TOKEN, value))
            elif value >= CAP:
                events.append(("drop", TAG_NUMBER, value))
            elif row.token in case.refuse:
                events.append(("transfer", address(row.who), row.token, value))
                events.append(("drop", 0x150, 0x7777))
            else:
                events.append(("transfer", address(row.who), row.token, value))
                if row.tree:
                    del maps[row.flag, row.token][cutoff]

    dt = case.dt
    if not dt >= 1.0:
        if changed:
            tail()
        return None, last, maps, events
    if rows:
        rate = case.rate if case.tag else 0.0
        if not rate >= 0.0:
            return "assertion failed: self >= 0.", last, maps, events
        if not dt >= 0.0:
            return "assertion failed: dur.0 >= 0.", last, maps, events
        x = dt * rate
        if not x >= 0.0:
            return "assertion failed: self.0 >= 0.", last, maps, events
        x = x / YEAR_SECONDS
        if x <= FEE_GATE and x >= 0.0:
            for row in rows:
                items = maps[row.flag, row.token]
                was = items.get(case.date, 0)
                add = owed(row.amount, x)
                total = was + add
                if total > TOP:
                    events.append(("recorder",))
                    total = TOP
                items[case.date] = total
    last = now
    if changed:
        tail()
    return None, last, maps, events


def order_key(pattern):
    return pattern | 1 << 63 if pattern < 1 << 63 else pattern ^ TOP


def spec_median(case):
    """The rule list of the bucket guard and the median. Returns (guard, tag, value, kept keys, sorted row count)."""
    now = (case.date, case.secs, case.nanos)
    bucket = time_ms(now) // case.period
    votes = sorted(case.votes, key=lambda row: address(row[0]))
    remaining = [row[0] for row in votes]
    if bucket <= case.guard:
        return case.guard, case.tag, bits(case.old), remaining
    ttl = float(case.period) / 1000.0
    fresh, stale = [], []
    for row in votes:
        (fresh if expiry(row[2], ttl) > (signed32(now[0]), now[1], now[2]) else stale).append(row)
    for row in stale:
        if row[2][0] == 0:
            break
        remaining.remove(row[0])
    stakes = dict(case.stakes)
    picked = []
    for who, pattern, _ in fresh:
        if not usable(pattern) or who not in stakes:
            continue
        picked.append((order_key(pattern), stakes[who], pattern))
    picked.sort(key=lambda row: row[:2])
    total = sum(row[1] for row in picked)
    tag, value = case.tag, bits(case.old)
    if picked and 0 < total <= TOP:
        half, done = total >> 1, 0
        for _, stake, pattern in picked:
            done += stake
            if done > half:
                tag, value = 1, pattern
                break
    return bucket, tag, value, remaining


def expiry(when, ttl):
    return signed32(when[0]), when[1] + int(ttl), when[2]


def usable(pattern):
    size = pattern & (TOP >> 1)
    if size >= 0x7FF0000000000000:
        return False
    return not (pattern >> 63 and size)


class Harness:
    def __init__(self, image, patches=None):
        self.image = image
        machine = Machine(image, patches)
        self.machine = machine
        statics = machine.memory.statics
        hooks = {SLOT_FREE: self.on_free, SLOT_ALLOC: self.on_alloc, SLOT_REALLOC: self.on_realloc, SLOT_COPY: self.on_copy, SLOT_MOVE: self.on_copy, SLOT_CMP: self.on_cmp, SLOT_ELAPSED: self.on_elapsed,
                 SLOT_RECORDER: self.on_recorder, SLOT_GROW_WORD: self.on_grow_word, SLOT_GROW_ROW: self.on_grow_row, SLOT_GROW_VOTE: self.on_grow_vote, SLOT_ADD_SECONDS: self.on_add_seconds,
                 SLOT_STAKES: self.on_stakes, SLOT_SORT: self.on_sort}
        for slot in PANIC_SLOTS:
            hooks[slot] = self.on_panic
        for slot, hook in hooks.items():
            statics[slot] = MARK_BASE + slot
            machine.slots[MARK_BASE + slot] = hook
        statics[SLOT_ADD_DAYS] = ADD_DAYS
        statics[SLOT_MEDIAN] = MEDIAN
        machine.real = RealCode.ALL
        machine.calls = {RESUME: self.on_panic, CLOCK: self.on_clock, ROW_BUILDER: self.on_builder, GROW_ANY: self.on_grow_any, DROP_NEXT: self.on_drop_next}
        for copy in COPIES:
            machine.calls[copy.transfer] = self.on_transfer
            machine.calls[copy.drop] = self.on_drop
        self.case = None
        self.events = []
        self.live = {}
        self.cur = BUMP

    def expect(self, condition, text):
        if not condition:
            raise Halt("stub check failed: " + text)

    def on_panic(self, machine):
        regs = machine.regs
        text = ""
        if regs[RSI] < 0x100 and 0x200000 <= regs[RDI] < 0x700000:
            text = machine.memory.bytes_at(regs[RDI], regs[RSI]).decode("latin-1")
        raise Panicked(text)

    def bump(self, size):
        at = self.cur
        self.cur += (size + 15) & ~15
        self.expect(self.cur <= BUMP_END, "allocator room")
        self.live[at] = size
        self.machine.memory.put_bytes(at, bytes([0x77]) * size)
        return at

    def on_alloc(self, machine):
        machine.regs[RAX] = self.bump(machine.regs[RDI])

    def on_free(self, machine):
        at, size = machine.regs[RDI], machine.regs[RSI]
        self.expect(self.live.pop(at, None) == size, "free of a live block with its size")
        self.events.append(("free", size))

    def on_realloc(self, machine):
        at, new = machine.regs[RDI], machine.regs[RSI]
        self.expect(at in self.live, "realloc of a live block")
        self.live[at] = new
        machine.regs[RAX] = at

    def on_copy(self, machine):
        dst, src, size = machine.regs[RDI], machine.regs[RSI], machine.regs[RDX]
        machine.memory.put_bytes(dst, machine.memory.bytes_at(src, size))
        machine.regs[RAX] = dst

    def on_cmp(self, machine):
        left = machine.memory.bytes_at(machine.regs[RDI], machine.regs[RDX])
        right = machine.memory.bytes_at(machine.regs[RSI], machine.regs[RDX])
        machine.regs[RAX] = (left > right) - (left < right) & MASK[4]

    def on_clock(self, machine):
        machine.regs[RAX] = 0x1234
        machine.regs[RDX] = 0x55
        machine.keep_rdx = True

    def grow(self, machine, vec, stride):
        memory = machine.memory
        cap = memory.read(vec, 8)
        old = memory.read(vec + 8, 8)
        new_cap = max(4, cap * 2)
        at = self.bump(new_cap * stride)
        if cap:
            memory.put_bytes(at, memory.bytes_at(old, cap * stride))
            self.expect(self.live.pop(old, None) == cap * stride, "grown block")
        memory.write(vec, 8, new_cap)
        memory.write(vec + 8, 8, at)

    def on_grow_word(self, machine):
        self.grow(machine, machine.regs[RDI], 8)

    def on_grow_row(self, machine):
        self.grow(machine, machine.regs[RDI], 0x28)

    def on_grow_vote(self, machine):
        self.grow(machine, machine.regs[RDI], 0x30)

    def on_grow_any(self, machine):
        self.grow(machine, machine.regs[RDI], machine.regs[R8])

    def on_recorder(self, machine):
        self.expect(machine.regs[RDI] == 0 and machine.regs[RSI] == WEI_LOCATION, "recorder arguments")
        self.events.append(("recorder",))

    def on_elapsed(self, machine):
        case = self.case
        memory = machine.memory
        regs = machine.regs
        now, old = regs[RDI], regs[RSI]
        self.expect((memory.read(now, 4), memory.read(now + 4, 4), memory.read(now + 8, 4)) == (case.date, case.secs, case.nanos), "elapsed: new time")
        last = case.last if case.last[0] else (case.date, case.secs, case.nanos)
        self.expect((memory.read(old, 4), memory.read(old + 4, 4), memory.read(old + 8, 4)) == last, "elapsed: old time")
        self.expect(memory.read(old + 0x10, 4) == 1 and memory.read(old + 0x14, 4) == 0x54, "elapsed: line word")
        self.expect(memory.read(old + 0x18, 8) == TIME_TEXT and memory.read(old + 0x20, 8) == 0x2B, "elapsed: file word")
        machine.xmm_result = bits(case.dt)

    def on_builder(self, machine):
        """The row list stands in for the listed builder; its iterator words must name both maps."""
        case = self.case
        copy = COPIES[case.copy]
        memory = machine.memory
        out, it = machine.regs[RDI], machine.regs[RSI]
        info, height, count = memory.read(S + 0x2B0, 8), memory.read(S + 0x2B8, 8), memory.read(S + 0x2C0, 8)
        second, height2, count2 = memory.read(S + 0x2F8, 8), memory.read(S + 0x300, 8), memory.read(S + 0x308, 8)
        words = [memory.read(it + 8 * index, 8) for index in range(0x15)]
        some = int(info != 0)
        self.expect(words[:4] == [some, 0, info, height], "builder: first iterator head")
        self.expect(words[4:8] == [some, 0, info, height], "builder: first iterator back")
        self.expect(words[8] == (count if info else 0), "builder: first count")
        self.expect(words[9] == S + 0x208, "builder: token table")
        some2 = int(second != 0)
        self.expect(words[10:14] == [some2, 0, second, height2], "builder: second iterator head")
        self.expect(words[14:18] == [some2, 0, second, height2], "builder: second iterator back")
        self.expect(words[18] == (count2 if second else 0), "builder: second count")
        self.expect(words[19] == S + 0x208 and words[20] == S + copy.tokens, "builder: tables")
        self.events.append(("builder",))
        rows = case.rows
        if not rows:
            memory.write(out, 8, 0)
            memory.write(out + 8, 8, 8)
            memory.write(out + 0x10, 8, 0)
            return
        at = self.bump(0x30 * len(rows))
        self.row_list = at
        for index, row in enumerate(rows):
            base = at + 0x30 * index
            memory.put_bytes(base, bytes((0x91 + slot) & 0xFF for slot in range(0x30)))
            memory.write(base, 8, self.headers[row.flag, row.token])
            memory.write(base + 8, 8, row.token)
            memory.write(base + 0x10, 8, row.amount)
            memory.put_bytes(base + 0x18, address(row.who))
            memory.write(base + 0x2C, 1, row.flag)
        memory.write(out, 8, len(rows))
        memory.write(out + 8, 8, at)
        memory.write(out + 0x10, 8, len(rows))

    def on_transfer(self, machine):
        case = self.case
        regs = machine.regs
        memory = machine.memory
        self.expect(regs[RSI] == S and regs[R8] & 0xFF == 0, "transfer: state and flag")
        self.expect(memory.read(S, 8) == 0, "transfer: first state word is held at zero")
        record = regs[RCX]
        self.expect(memory.read(record, 8) == 0 and memory.read(record + 0x10, 8) == 0 and memory.read(record + 0x30, 8) == 0, "transfer: record tags")
        self.expect(memory.read(record + 0x9C, 1) == 0, "transfer: record byte")
        self.expect(memory.bytes_at(record + 0x88, 16) == bytes(self.image.blob[self.image.offset(0x206BE0):self.image.offset(0x206BE0) + 16]) and memory.read(record + 0x98, 4) == 0xFEFEFEFE, "transfer: record tail")
        token, value = memory.read(record + 0x20, 8), memory.read(record + 0x28, 8)
        self.events.append(("transfer", memory.bytes_at(regs[RDX], 20), token, value))
        out = regs[RDI]
        if token in case.refuse:
            memory.put_bytes(out, struct.pack("<QQ", 0x150, 0x7777) + bytes((0x61 + index) & 0xFF for index in range(0x50)))
        else:
            memory.write(out, 2, OK)

    def on_drop(self, machine):
        memory = machine.memory
        at = machine.regs[RDI]
        tag, value = memory.read(at, 8), memory.read(at + 8, 8)
        if tag == 0x150:
            self.expect(memory.bytes_at(at + 0x10, 0x50) == bytes((0x61 + index) & 0xFF for index in range(0x50)), "drop: object bytes")
        self.events.append(("drop", tag, value))

    def on_add_seconds(self, machine):
        case = self.case
        memory = machine.memory
        regs = machine.regs
        ttl = float(case.period) / 1000.0
        self.expect(machine.xmm[0] & MASK[8] == bits(ttl), "add seconds: ttl")
        at = regs[RSI]
        date, secs, nanos = memory.read(at, 4), memory.read(at + 4, 4), memory.read(at + 8, 4)
        self.expect(any((date, secs, nanos) == row[2] for row in case.votes), "add seconds: a row time")
        out = regs[RDI]
        memory.write(out, 4, date)
        memory.write(out + 4, 4, secs + int(ttl))
        memory.write(out + 8, 4, nanos)

    def on_stakes(self, machine):
        case = self.case
        memory = machine.memory
        regs = machine.regs
        self.expect(regs[RDX] == LIST_AT and regs[RSI] & 0xFF == 3, "stake list arguments")
        out = regs[RDI]
        stale = address(case.votes[0][0]) if case.votes else address(0)
        root, height, count = self.tree(L_STAKES, [(address(who), struct.pack("<Q", stake)) for who, stake in case.stakes], stale, 0x140, 0x1A0)
        memory.write(out, 8, root)
        memory.write(out + 8, 8, height)
        memory.write(out + 0x10, 8, count)

    def on_drop_next(self, machine):
        machine.memory.write(machine.regs[RDI], 8, 0)

    def on_sort(self, machine):
        """Rust's stable sort for 21 rows or more; a stable sort by the same key has one answer."""
        memory = machine.memory
        at, count = machine.regs[RDI], machine.regs[RSI]
        rows = [(memory.read(at + 16 * index, 8), memory.read(at + 16 * index + 8, 8)) for index in range(count)]
        rows.sort(key=lambda row: (order_key(row[0]), row[1]))
        for index, (pattern, stake) in enumerate(rows):
            memory.write(at + 16 * index, 8, pattern)
            memory.write(at + 16 * index + 8, 8, stake)

    def node(self, layout, items, stale, size):
        memory = self.machine.memory
        at = self.cur
        self.cur += (size + 15) & ~15
        self.expect(self.cur <= BUMP_END, "allocator room")
        self.live[at] = size
        memory.put_bytes(at, bytes((0x31 + 7 * index) & 0xFF or 1 for index in range(size)))
        memory.write(at + layout.parent_at, 8, 0)
        memory.write(at + layout.len_at, 2, len(items))
        for slot in range(11):
            memory.put_bytes(at + layout.key_at + layout.key_size * slot, stale)
        for slot, (key, value) in enumerate(items):
            memory.put_bytes(at + layout.key_at + layout.key_size * slot, key)
            memory.put_bytes(at + layout.val_at + layout.val_size * slot, value)
        return at

    def tree(self, layout, items, stale, leaf, inner):
        """A leaf, or a root over leaves; items are (key bytes, value bytes) in key order."""
        memory = self.machine.memory
        if not items:
            return 0, 0xFEED, 0
        if len(items) <= 11:
            return self.node(layout, items, stale, leaf), 0, len(items)
        parts, seps, at = [], [], 0
        while len(items) - at > 11:
            parts.append(items[at:at + 5])
            seps.append(items[at + 5])
            at += 6
        parts.append(items[at:])
        kids = [self.node(layout, part, stale, leaf) for part in parts]
        root = self.node(layout, seps, stale, inner)
        for slot, kid in enumerate(kids):
            memory.write(root + layout.edge_at + 8 * slot, 8, kid)
            memory.write(kid + layout.parent_at, 8, root)
            memory.write(kid + layout.index_at, 2, slot)
        return root, 1, len(items)

    def walk(self, layout, root, height):
        memory = self.machine.memory
        rows = []

        def visit(at, level, parent, index):
            size = memory.read(at + layout.len_at, 2)
            self.expect(memory.read(at + layout.parent_at, 8) == parent, "parent link")
            if parent:
                self.expect(memory.read(at + layout.index_at, 2) == index, "parent index")
            for slot in range(size + 1):
                if level:
                    visit(memory.read(at + layout.edge_at + 8 * slot, 8), level - 1, at, slot)
                if slot < size:
                    rows.append((memory.bytes_at(at + layout.key_at + layout.key_size * slot, layout.key_size), at + layout.val_at + layout.val_size * slot))
        if root:
            visit(root, height, 0, 0)
        return rows

    def daily(self, items, stale):
        rows = [(struct.pack("<i", signed32(key)), struct.pack("<Q", value)) for key, value in sorted(items, key=lambda row: signed32(row[0]))]
        return self.tree(L_DAILY, rows, struct.pack("<i", signed32(stale)), 0x90, 0xF0)

    def fresh(self, case):
        machine = self.machine
        memory = machine.memory
        memory.reset(HEAP_SIZE)
        memory.heap[:FILL_END] = HEAP_FILL
        self.case = case
        self.events = []
        self.live = {}
        self.cur = BUMP
        self.headers = {}
        self.info_nodes = {}
        self.row_list = None
        copy = COPIES[case.copy]
        memory.write(S + 0x60, 4, case.date)
        memory.write(S + 0x64, 4, case.secs)
        memory.write(S + 0x68, 4, case.nanos)
        memory.write(S + 0x6C, 4, case.prev)
        memory.write(S + copy.time_at, 4, case.last[0])
        memory.write(S + copy.time_at + 4, 4, case.last[1])
        memory.write(S + copy.time_at + 8, 4, case.last[2])
        memory.write(S + copy.chain, 1, case.chain)
        memory.write(S + copy.tracker, 1, 1 if case.tag else 0)
        memory.write(S + copy.tracker + 8, 8, bits(case.rate))
        memory.write(S + 0x218, 8, case.count)
        for flag, offset, layout, leaf, inner in ((0, 0x2B0, L_INFO, 0x278, 0x2D8), (1, 0x2F8, L_AQA, 0x4E0, 0x540)):
            tokens = sorted({row.token for row in case.rows if row.flag == flag and row.tree} | {token for token in case.decoys if flag == 0})
            by_token = {row.token: row for row in case.rows if row.flag == flag and row.tree}
            rows = []
            for token in tokens:
                value = bytearray((0x41 + index) & 0xFF for index in range(layout.val_size))
                header = 8 if flag == 0 else 0
                value[header:header + 24] = bytes(24)
                rows.append((struct.pack("<Q", token), bytes(value)))
            stale = struct.pack("<Q", by_token and min(by_token) or 7)
            root, height, count = self.tree(layout, rows, stale, leaf, inner)
            memory.write(S + offset, 8, root)
            memory.write(S + offset + 8, 8, height)
            memory.write(S + offset + 0x10, 8, count)
            self.info_nodes[flag] = (layout, root, height)
            for key, at in self.walk(layout, root, height):
                token = struct.unpack("<Q", key)[0]
                header = at + (8 if flag == 0 else 0)
                row = by_token.get(token)
                daily = self.daily(row.items if row else ((case.date, 5),), case.date)
                memory.write(header, 8, daily[0])
                memory.write(header + 8, 8, daily[1])
                memory.write(header + 0x10, 8, daily[2])
                if row:
                    self.headers[flag, token] = header
        for row in case.rows:
            if not row.tree:
                header = self.bump(24)
                daily = self.daily(row.items, case.date)
                memory.write(header, 8, daily[0])
                memory.write(header + 8, 8, daily[1])
                memory.write(header + 0x10, 8, daily[2])
                self.headers[row.flag, row.token] = header
        return bytes(memory.heap[:FILL_END])

    def run_sample(self, case):
        before = self.fresh(case)
        machine = self.machine
        memory = machine.memory
        copy = COPIES[case.copy]
        machine.stop = copy.stop
        machine.frame = FRAME
        frame = STACK_TOP - 0x100 - 8 - FRAME
        memory.write(frame + (8 if copy.name == "a" else 0), 8, S)
        args = {} if copy.name == "a" else {R12: S}
        panic = None
        try:
            machine.run(copy.entry, args)
        except Panicked as stop:
            panic = str(stop)
        return before, self.read_sample(case, panic)

    def read_sample(self, case, panic):
        memory = self.machine.memory
        copy = COPIES[case.copy]
        maps = {}
        for flag, offset in ((0, 0x2B0), (1, 0x2F8)):
            layout = self.info_nodes[flag][0]
            for key, at in self.walk(layout, memory.read(S + offset, 8), memory.read(S + offset + 8, 8)):
                header = at + (8 if flag == 0 else 0)
                maps[flag, struct.unpack("<Q", key)[0]] = self.read_daily(header)
        for row in case.rows:
            if not row.tree:
                maps[row.flag, row.token] = self.read_daily(self.headers[row.flag, row.token])
        heap = bytes(memory.heap[:FILL_END])
        return dict(panic=panic, maps=maps, heap=heap, events=list(self.events), last=tuple(memory.read(S + copy.time_at + at, 4) for at in (0, 4, 8)), live=dict(self.live))

    def read_daily(self, header):
        memory = self.machine.memory
        rows = []
        for key, at in self.walk(L_DAILY, memory.read(header, 8), memory.read(header + 8, 8)):
            rows.append((struct.unpack("<I", key)[0], memory.read(at, 8)))
        self.expect(memory.read(header + 0x10, 8) == len(rows), "daily map length word")
        return tuple(rows)

    def run_median(self, case):
        before = self.fresh(case)
        machine = self.machine
        memory = machine.memory
        machine.stop = CLOSURE_STOP
        at = TRACKER_FAKE
        memory.write(at, 8, 1 if case.tag else 0)
        memory.write(at + 8, 8, bits(case.old))
        memory.write(at + 0x10, 8, case.period)
        memory.write(at + 0x18, 8, case.guard)
        votes = sorted(case.votes, key=lambda row: address(row[0]))
        items = [(address(who), struct.pack("<QIII", pattern, *when) + bytes(4)) for who, pattern, when in votes]
        stale = address(votes[0][0]) if votes else address(0)
        root, height, count = self.tree(L_VOTES, items, stale, 0x1F0, 0x250)
        memory.write(at + 0x20, 8, root)
        memory.write(at + 0x28, 8, height)
        memory.write(at + 0x30, 8, count)
        memory.write(NOW_AT, 4, case.date)
        memory.write(NOW_AT + 4, 4, case.secs)
        memory.write(NOW_AT + 8, 4, case.nanos)
        memory.write(STACK_TOP - 0x100, 8, 0x15)
        machine.frame = 0
        before = bytes(memory.heap[:FILL_END])
        panic = None
        try:
            machine.run(GUARD, {RDI: at, RSI: NOW_AT, RDX: LIST_AT, RCX: 3, R8: 0, R9: KEY_TEXT})
        except Panicked as stop:
            panic = str(stop)
        rows = [struct.unpack(">Q", key[12:])[0] - 0x1000 for key, _ in self.walk(L_VOTES, memory.read(at + 0x20, 8), memory.read(at + 0x28, 8))]
        count_now = memory.read(at + 0x30, 8)
        self.expect(count_now == len(rows), "vote map length word")
        return before, dict(panic=panic, guard=memory.read(at + 0x18, 8), tag=memory.read(at, 8), value=memory.read(at + 8, 8), rows=rows, heap=bytes(memory.heap[:FILL_END]), period=memory.read(at + 0x10, 8), live=dict(self.live))

    def run(self, case):
        return self.run_sample(case) if case.kind == "sample" else self.run_median(case)


class RealCode:
    ALL = frozenset()


def collect_real(image):
    """Subject code, the closure, the date helper and what those reach by direct calls, less the stubs."""
    seen = set(SUBJECTS) | {CLOSURE, WEIGHTED, ADD_DAYS}
    stop = {RESUME, CLOCK, ROW_BUILDER, GROW_ANY, DROP_NEXT}
    for copy in COPIES:
        stop |= {copy.transfer, copy.drop}
    todo = [va for va in seen if va != CLOSURE]
    while todo:
        for row in decode_range(image, *image.exact_fde(todo.pop())):
            if row.op == "call" and row.target not in seen and row.target not in stop and row.target < 0x5660000:
                seen.add(row.target)
                todo.append(row.target)
    return frozenset(seen)


def spec_run(case, before):
    return spec_sample(case) if case.kind == "sample" else spec_median(case)


def same(case, got, want, before):
    return mismatch(case, got, want, before) is None


def mismatch(case, got, want, before):
    if case.kind == "median":
        guard, tag, value, rows = want
        if got["panic"] is not None:
            return "panic %r" % got["panic"]
        if (got["guard"], got["tag"], got["value"]) != (guard, tag, value):
            return "guard/tag/value %r want %r" % ((got["guard"], got["tag"], hex(got["value"])), (guard, tag, hex(value)))
        if got["rows"] != sorted(rows, key=address):
            return "rows %r want %r" % (got["rows"], rows)
        if got["period"] != case.period:
            return "period word"
        after = bytearray(before)
        at = TRACKER_FAKE - HEAP_BASE
        after[at:at + 0x20] = struct.pack("<QQQQ", tag, value, case.period, guard)
        now = bytearray(got["heap"])
        now[at + 0x20:at + 0x38] = after[at + 0x20:at + 0x38]
        if now != after:
            return "heap at %#x" % next(index + HEAP_BASE for index in range(len(now)) if now[index] != after[index])
        return None
    panic, last, maps, events = want
    if panic is not None:
        if got["panic"] != panic:
            return "panic %r want %r" % (got["panic"], panic)
        return None
    if got["panic"] is not None:
        return "panic %r" % got["panic"]
    if got["last"] != last:
        return "last %r want %r" % (got["last"], last)
    plain = [event for event in got["events"] if event[0] in ("transfer", "drop", "recorder")]
    if plain != events:
        return "events %r want %r" % (plain, events)
    for key, items in maps.items():
        now = got["maps"].get(key)
        if now != tuple(sorted(items.items(), key=lambda row: signed32(row[0]))):
            return "map %r: %r want %r" % (key, now, items)
    for key, now in got["maps"].items():
        if key not in maps and now != ((case.date, 5),):
            return "decoy map %r" % (key,)
    copy = COPIES[case.copy]
    after = bytearray(before)
    at = S - HEAP_BASE + copy.time_at
    after[at:at + 12] = struct.pack("<III", *last)
    if got["heap"] != bytes(after):
        return "heap at %#x" % next(index + HEAP_BASE for index in range(len(after)) if got["heap"][index] != after[index])
    return None


def lcg(seed):
    state = seed
    while True:
        state = (state * 6364136223846793005 + 1442695040888963407) & TOP
        yield state >> 11


DAY = date_word(2026, 200)
NEXT = date_word(2026, 201)
CUT_MAIN = add_days(DAY, DAYS_MAIN)
CUT_TWO = add_days(DAY, DAYS_TWO)
BEFORE = add_days(DAY, -60)
LATER = add_days(DAY, -10)


def sample_cases():
    cases = []

    def add(label, **fields):
        for index in range(3):
            cases.append(Case("copy%d %s" % (index, label), copy=index, **fields))

    one = (Row(5, 10 ** 12, ((BEFORE, 9), (LATER, 11))),)
    rate_day = 86400.0
    add("first sample stores now and accrues nothing", last=(0, 0, 0), dt=0.0, rows=one)
    add("first sample with a later date runs no accrual", last=(0, 0, 0), dt=0.0, prev=add_days(DAY, -1), rows=one)
    add("below one second, same date", dt=0.999, rows=one)
    add("below one second keeps the old time", dt=0.5, last=(DAY, 100, 200), rows=one)
    add("exactly one second", dt=1.0, rows=one)
    add("just below one second", dt=value_of(bits(1.0) - 1), rows=one)
    add("NaN time difference stays quiet", dt=float("nan"), rows=one)
    add("one day at 4 percent", dt=rate_day, rate=0.04, rows=one)
    add("no rows still moves the time", dt=rate_day, rows=())
    add("no median reads rate 0", dt=rate_day, tag=0, rate=0.9, rows=one)
    add("rate 0 inserts today's key at 0", dt=rate_day, rate=0.0, rows=one)
    add("negative rate panics", dt=rate_day, rate=-0.01, rows=one)
    add("NaN rate panics", dt=rate_day, rate=float("nan"), rows=one)
    add("negative rate with no rows does not panic", dt=rate_day, rate=-0.01, rows=())
    add("infinite time times zero rate panics", dt=float("inf"), rate=0.0, rows=one)
    add("infinite time skips the loop", dt=float("inf"), rate=0.1, rows=one)
    add("infinite rate skips the loop", dt=rate_day, rate=float("inf"), rows=one)
    edge = FEE_GATE * YEAR_SECONDS
    add("fraction exactly 1.01", dt=edge, rate=1.0, rows=one)
    add("fraction above 1.01 skips the loop, time moves", dt=edge * 1.000001, rate=1.0, rows=one)
    add("fraction above 1.01 with a date change still pays", dt=edge * 2, rate=1.0, prev=add_days(DAY, -1), rows=(Row(5, 10 ** 12, ((CUT_MAIN, 77),)),))
    add("fraction 1 with u64 max amount clamps", dt=YEAR_SECONDS, rate=1.0, rows=(Row(5, TOP),))
    add("fraction 1.01 with u64 max amount clamps", dt=edge, rate=1.0, rows=(Row(5, TOP),))
    add("amount top with a tiny fraction", dt=1.0, rate=1e-7, rows=(Row(5, TOP),))
    add("product just above 2^63", dt=YEAR_SECONDS, rate=0.5000001, rows=(Row(5, 1 << 64 - 1),))
    add("product at 2^63", dt=YEAR_SECONDS, rate=0.5, rows=(Row(5, TOP),))
    add("product at the last double under 2^64", dt=YEAR_SECONDS, rate=value_of(bits(1.0) - 1), rows=(Row(5, TOP),))
    add("amount 0 inserts a key", dt=rate_day, rows=(Row(5, 0),))
    add("amount above 2^53 rounds in f64", dt=rate_day, rows=(Row(5, (1 << 53) + 1),))
    add("add to today's key", dt=rate_day, rows=(Row(5, 10 ** 12, ((DAY, 1000), (LATER, 11))),))
    add("add saturates with the recorder", dt=YEAR_SECONDS, rate=1.0, rows=(Row(5, 1 << 62, ((DAY, TOP - 5),)),))
    add("add lands exactly on max", dt=YEAR_SECONDS, rate=1.0, rows=(Row(5, 1 << 62, ((DAY, TOP - (1 << 62)),)),))
    add("add one past max", dt=YEAR_SECONDS, rate=1.0, rows=(Row(5, 1 << 62, ((DAY, TOP - (1 << 62) + 1),)),))
    add("two rows and a decoy", dt=rate_day, rows=(Row(3, 10 ** 13), Row(9, 2 * 10 ** 13, ((DAY, 4),))), decoys=(5, 7))
    add("aqa row and info row", dt=rate_day, rows=(Row(3, 10 ** 13), Row(4, 7 * 10 ** 12, flag=1, who=2)))
    full = tuple((add_days(DAY, -slot - 1), 100 + slot) for slot in range(11))
    add("full leaf splits on insert", dt=rate_day, rows=(Row(5, 10 ** 12, full),))
    add("new smallest key is impossible, new largest splits right", dt=rate_day, rows=(Row(5, 10 ** 12, tuple((add_days(DAY, slot - 12), slot) for slot in range(11))),))
    wide = tuple((add_days(DAY, -slot * 2 - 1), 100 + slot) for slot in range(16))
    add("two level map", dt=rate_day, rows=(Row(5, 10 ** 12, wide),))
    add("map with a future key after today", dt=rate_day, rows=(Row(5, 10 ** 12, ((NEXT, 3),)),))
    for label, chain, cut in (("main", 3, CUT_MAIN), ("chain 1", 1, CUT_MAIN), ("chain 0", 0, CUT_MAIN), ("chain 2", 2, CUT_TWO)):
        fields = dict(chain=chain, prev=add_days(DAY, -1))
        add(label + " date change pays the cutoff key", dt=rate_day, rows=(Row(5, 10 ** 12, ((BEFORE, 9), (cut, 1234))),), **fields)
        add(label + " date change without accrual", dt=0.5, rows=(Row(5, 10 ** 12, ((BEFORE, 9), (cut, 1234))),), **fields)
        add(label + " key one day after the cutoff stays", dt=0.5, rows=(Row(5, 10 ** 12, ((add_days(cut, 1), 1234),)),), **fields)
        add(label + " key one day before the cutoff stays", dt=0.5, rows=(Row(5, 10 ** 12, ((add_days(cut, -1), 1234),)),), **fields)
        add(label + " same date never pays", dt=0.5, chain=chain, rows=(Row(5, 10 ** 12, ((cut, 1234),)),))
        add(label + " later previous date never pays", dt=0.5, chain=chain, prev=NEXT, rows=(Row(5, 10 ** 12, ((cut, 1234),)),))
        add(label + " aqa row pays", dt=0.5, rows=(Row(6, 1, ((cut, 55),), flag=1, who=3),), **fields)
        add(label + " two rows", dt=0.5, rows=(Row(3, 1, ((cut, 8),)), Row(9, 1, ((cut, 9), (BEFORE, 4)), who=2)), decoys=(5, 7), **fields)
    move = dict(prev=add_days(DAY, -1), dt=0.5)
    add("zero value pays through", rows=(Row(5, 1, ((CUT_MAIN, 0),)),), **move)
    add("value just under the cap", rows=(Row(5, 1, ((CUT_MAIN, CAP - 1),)),), **move)
    add("value at the cap logs and stays", rows=(Row(5, 1, ((CUT_MAIN, CAP),)),), **move)
    add("value top logs", rows=(Row(5, 1, ((CUT_MAIN, TOP),)),), **move)
    add("token at the count logs", count=5, rows=(Row(5, 1, ((CUT_MAIN, 8),)),), **move)
    add("token just under the count pays", count=6, rows=(Row(5, 1, ((CUT_MAIN, 8),)),), **move)
    add("refused transfer logs and stays", refuse=(5,), rows=(Row(5, 1, ((CUT_MAIN, 8),)),), **move)
    add("refusal does not stop the next row", refuse=(3,), rows=(Row(3, 1, ((CUT_MAIN, 8),)), Row(9, 1, ((CUT_MAIN, 3),), who=2)), **move)
    add("token error does not stop the next row", count=5, rows=(Row(9, 1, ((CUT_MAIN, 8),)), Row(3, 1, ((CUT_MAIN, 3),), who=2)), **move)
    add("row flag 2 ends the payout", rows=(Row(3, 1, ((CUT_MAIN, 8),)), Row(4, 1, ((CUT_MAIN, 6),), flag=2, tree=False), Row(9, 1, ((CUT_MAIN, 3),), who=2)), **move)
    add("token missing from its tree pays and keeps the row map", rows=(Row(5, 1, ((CUT_MAIN, 8),), tree=False),), **move)
    add("aqa flag looks in the second tree", rows=(Row(5, 1, ((CUT_MAIN, 8),), flag=1, tree=False), Row(6, 1, ((CUT_MAIN, 4),))), **move)
    add("info row missing, decoys around", rows=(Row(6, 1, ((CUT_MAIN, 8),), tree=False),), decoys=(5, 7), **move)
    add("oldest key below the cutoff only", rows=(Row(5, 1, ((BEFORE, 9),)),), **move)
    add("empty map after an earlier removal", rows=(Row(5, 1),), **move)
    add("many rows grow both lists", rows=tuple(Row(index * 2 + 1, 1, ((BEFORE, 9), (CUT_MAIN, index + 1)), who=index + 1) for index in range(9)), **move)
    add("many rows, two level tree", rows=tuple(Row(index * 2 + 1, 1, ((BEFORE, 9), (CUT_MAIN, index + 1)), who=index + 1) for index in range(14)), **move)
    add("many aqa rows, two level tree", rows=tuple(Row(index * 2 + 1, 1, ((CUT_MAIN, index + 1),), flag=1, who=index + 1) for index in range(14)), **move)
    add("cutoff in a two level map", rows=(Row(5, 1, tuple((add_days(CUT_MAIN, slot - 8), 100 + slot) for slot in range(16))),), **move)
    add("removal in the right leaf of a two level map", rows=(Row(5, 1, tuple((add_days(CUT_MAIN, slot - 6), 100 + slot) for slot in range(12))),), **move)
    for at in range(12):
        add("removal of key %d merges and pops the root" % at, rows=(Row(5, 1, tuple((add_days(CUT_MAIN, slot - at), 100 + slot) for slot in range(12))),), **move)
    newyear = date_word(2027, 3)
    add("cutoff across a year", dt=0.5, date=newyear, prev=date_word(2027, 2), rows=(Row(5, 1, ((add_days(newyear, DAYS_MAIN), 88),)),))
    leap = date_word(2028, 60)
    add("cutoff across February of a leap year", dt=0.5, date=leap, prev=date_word(2028, 59), rows=(Row(5, 1, ((add_days(leap, DAYS_MAIN), 88),)),))
    add("cutoff across a year on chain 2", dt=0.5, chain=2, date=date_word(2027, 1), prev=date_word(2026, 365), rows=(Row(5, 1, ((date_word(2026, 364), 88),)),))
    add("accrual and payout in one sample", dt=3600.0, rate=0.05, prev=add_days(DAY, -1), rows=(Row(5, 3 * 10 ** 13, ((CUT_MAIN, 500), (DAY, 7))),))
    return cases


def rate_votes(pairs, when):
    return tuple((who, bits(rate), when) for who, rate in pairs)


def median_cases():
    cases = []

    def add(label, **fields):
        cases.append(Case(label, kind="median", **fields))

    now = date_word(2026, 200)
    fresh = (now, 3550, 0)
    secs = 3600
    bucket = time_ms((now, secs, 7000)) // 60000
    live = dict(guard=bucket - 1)
    who = ((1, 10), (2, 10), (3, 10))
    add("bucket not advanced", guard=bucket, votes=rate_votes(((1, 0.1),), fresh), stakes=who)
    add("bucket behind by more than one keeps old guard reading", guard=bucket + 5, votes=rate_votes(((1, 0.1),), fresh), stakes=who)
    add("bucket advanced by one", votes=rate_votes(((1, 0.1),), fresh), stakes=who, **live)
    add("no votes leaves the old median", stakes=who, **live)
    add("no votes and no old median", tag=0, stakes=who, **live)
    add("no stakes leaves the old median", votes=rate_votes(((1, 0.1),), fresh), **live)
    add("votes from non validators are ignored", votes=rate_votes(((7, 0.1), (8, 0.2)), fresh), stakes=who, **live)
    add("zero stake gives no median", votes=rate_votes(((1, 0.1),), fresh), stakes=((1, 0),), **live)
    add("zero total with two rows", votes=rate_votes(((1, 0.1), (2, 0.2)), fresh), stakes=((1, 0), (2, 0)), **live)
    add("three equal stakes pick the middle", votes=rate_votes(((1, 0.3), (2, 0.1), (3, 0.2)), fresh), stakes=who, **live)
    add("two equal stakes pick the larger", votes=rate_votes(((1, 0.3), (2, 0.1)), fresh), stakes=who, **live)
    add("cumulative equal to half moves on", votes=rate_votes(((1, 0.1), (2, 0.2), (3, 0.3)), fresh), stakes=((1, 5), (2, 5), (3, 0)), **live)
    add("odd total", votes=rate_votes(((1, 0.1), (2, 0.2), (3, 0.3)), fresh), stakes=((1, 3), (2, 1), (3, 3)), **live)
    add("first row holds a majority", votes=rate_votes(((1, 0.1), (2, 0.2), (3, 0.3)), fresh), stakes=((1, 100), (2, 1), (3, 1)), **live)
    add("last row holds a majority", votes=rate_votes(((1, 0.1), (2, 0.2), (3, 0.3)), fresh), stakes=((1, 1), (2, 1), (3, 100)), **live)
    add("equal rates break ties by stake", votes=rate_votes(((1, 0.2), (2, 0.2), (3, 0.5)), fresh), stakes=((1, 7), (2, 3), (3, 9)), **live)
    add("total overflow gives no median", votes=rate_votes(((1, 0.1), (2, 0.2)), fresh), stakes=((1, TOP), (2, 1)), **live)
    add("total exactly u64 max", votes=rate_votes(((1, 0.1), (2, 0.2)), fresh), stakes=((1, TOP - 1), (2, 1)), **live)
    for label, value in (("NaN", float("nan")), ("plus infinity", float("inf")), ("minus infinity", float("-inf")), ("negative", -0.25), ("negative subnormal", -5e-324), ("smallest negative normal", -2.2250738585072014e-308)):
        add(label + " vote is dropped", votes=rate_votes(((1, value), (2, 0.2), (3, 0.3)), fresh), stakes=who, **live)
        add(label + " vote as the only vote", votes=rate_votes(((1, value),), fresh), stakes=who, **live)
        add(label + " vote second", votes=rate_votes(((1, 0.2), (2, value), (3, 0.3)), fresh), stakes=who, **live)
    for label, value in (("minus zero", -0.0), ("zero", 0.0), ("subnormal", 5e-324), ("largest finite", 1.7976931348623157e308)):
        add(label + " vote is kept", votes=rate_votes(((1, value),), fresh), stakes=who, **live)
        add(label + " vote among others", votes=rate_votes(((1, value), (2, 0.2), (3, 0.3)), fresh), stakes=who, **live)
    add("minus zero sorts below zero", votes=rate_votes(((1, 0.0), (2, -0.0)), fresh), stakes=((1, 1), (2, 3)), **live)
    add("old votes are removed", votes=(((1, bits(0.1), (now, 1000, 0))), (2, bits(0.2), fresh)), stakes=who, **live)
    add("all votes old leaves the old median and empties the map", votes=rate_votes(((1, 0.1), (2, 0.2)), (now, 1000, 0)), stakes=who, **live)
    add("vote exactly at the age limit is old", votes=rate_votes(((1, 0.1),), (now, 3540, 7000)), stakes=who, **live)
    add("vote one nanosecond inside the age limit is fresh", votes=rate_votes(((1, 0.1),), (now, 3540, 7001)), stakes=who, **live)
    add("vote one second inside is fresh", votes=rate_votes(((1, 0.1),), (now, 3541, 0)), stakes=who, **live)
    add("vote one second past is old", votes=rate_votes(((1, 0.1),), (now, 3539, 9000)), stakes=who, **live)
    add("vote from the day before is old", votes=rate_votes(((1, 0.1),), (add_days(now, -1), 86000, 0)), stakes=who, **live)
    add("vote dated tomorrow is fresh", votes=rate_votes(((1, 0.1),), (add_days(now, 1), 0, 0)), stakes=who, **live)
    add("date word zero ends the stale walk", votes=(((1, bits(0.1), (now, 100, 0))), (2, bits(0.2), (0, 0, 0)), (3, bits(0.3), (now, 200, 0))), stakes=who, **live)
    add("period 1 second", period=1000, guard=time_ms((now, secs, 7000)) // 1000 - 1, votes=rate_votes(((1, 0.1),), fresh), stakes=who)
    add("period above 32 bits", period=1 << 33, guard=0, votes=rate_votes(((1, 0.1),), fresh), stakes=who)
    add("period with a part second", period=61500, guard=time_ms((now, secs, 7000)) // 61500 - 1, votes=rate_votes(((1, 0.1),), (now, 3550, 0)), stakes=who)
    add("nanoseconds reach the bucket", period=1000, date=now, secs=3599, nanos=999999999, guard=time_ms((now, 3599, 999999999)) // 1000 - 1, votes=rate_votes(((1, 0.1),), (now, 3599, 0)), stakes=who)
    add("millisecond edge of a bucket", period=7, date=now, secs=3600, nanos=999999, guard=time_ms((now, 3600, 999999)) // 7, votes=rate_votes(((1, 0.1),), (now, 3599, 0)), stakes=who)
    add("year before 1970 clamps to bucket 0", date=date_word(1960, 5), guard=0, stakes=who, votes=rate_votes(((1, 0.1),), (date_word(1960, 5), 3590, 0)))
    add("year 1 of a 400 cycle", date=date_word(2401, 5), guard=0, stakes=who, votes=rate_votes(((1, 0.1),), (date_word(2401, 5), 3590, 0)))
    add("century year", date=date_word(2101, 5), guard=0, stakes=who, votes=rate_votes(((1, 0.1),), (date_word(2101, 5), 3590, 0)))
    for size in (4, 5, 8, 11, 12, 16, 20, 21, 24, 33):
        votes = rate_votes(tuple((slot + 1, 0.01 * ((slot * 7) % size + 1)) for slot in range(size)), fresh)
        stakes = tuple((slot + 1, 3 + slot % 5) for slot in range(size))
        add("%d fresh votes" % size, votes=votes, stakes=stakes, **live)
        add("%d votes, half old" % size, votes=tuple((row[0], row[1], (now, 1000, 0) if row[0] % 2 else fresh) for row in votes), stakes=stakes, **live)
        add("%d votes, the other half old" % size, votes=tuple((row[0], row[1], (now, 1000, 0) if row[0] % 2 == 0 else fresh) for row in votes), stakes=stakes, **live)
        add("%d votes, all old" % size, votes=tuple((row[0], row[1], (now, 1000, 0)) for row in votes), stakes=stakes, **live)
        for one in range(1, size + 1, 3):
            add("%d votes, row %d old" % (size, one), votes=tuple((row[0], row[1], (now, 1000, 0) if row[0] == one else fresh) for row in votes), stakes=stakes, **live)
    return cases


def base_cases():
    return sample_cases() + median_cases()


def vector_cases(count):
    random = lcg(0x5EED5)
    cases = []
    for index in range(count):
        if next(random) % 3 == 0:
            cases.append(median_vector(random, index))
        else:
            cases.append(sample_vector(random, index))
    return cases


def sample_vector(random, index):
    day = date_word(2024 + next(random) % 9, 1 + next(random) % 360)
    chain = next(random) % 4
    cut = add_days(day, DAYS_TWO if chain == 2 else DAYS_MAIN)
    rows = []
    tokens = sorted({next(random) % 40 for _ in range(1 + next(random) % 6)})
    for token in tokens:
        items = {}
        for _ in range(next(random) % 6):
            items[add_days(day, -int(next(random) % 70))] = next(random) % (1 << 40)
        if next(random) % 2:
            items[cut] = next(random) % (1 << (20 + next(random) % 44))
        rows.append(Row(token, next(random) % (1 << (next(random) % 64 + 1)), tuple(items.items()), flag=next(random) % 2, who=next(random) % 9 + 1, tree=next(random) % 9 != 0))
    dt = (0.0, 0.5, 1.0, 1.0 + next(random) % 86400, 86400.0 * (1 + next(random) % 400))[next(random) % 5]
    rate = (0.0, 0.01 + (next(random) % 1000) / 10000.0, 1.0 + next(random) % 50)[next(random) % 3]
    prev = day if next(random) % 2 else add_days(day, -int(1 + next(random) % 3))
    return Case("vector %d" % index, copy=next(random) % 3, date=day, prev=prev, chain=chain, dt=dt, rate=rate, tag=next(random) % 4 != 0, rows=tuple(rows), count=20 + next(random) % 25,
                refuse=tuple(token for token in tokens if next(random) % 7 == 0), last=(day, 100, 7) if next(random) % 5 else (0, 0, 0))


def median_vector(random, index):
    now = date_word(2024 + next(random) % 9, 1 + next(random) % 360)
    secs = next(random) % 86400
    period = 1000 * (1 + next(random) % 300)
    bucket = time_ms((now, secs, 0)) // period
    size = next(random) % 26
    votes = []
    for slot in range(size):
        when = (now, max(0, secs - next(random) % (2 * period // 1000 + 2)), next(random) % 1000)
        rate = (next(random) % 40) / 100.0 if next(random) % 8 else (-0.5, float("nan"), float("inf"))[next(random) % 3]
        votes.append((slot + 1, bits(rate), when))
    stakes = tuple((slot + 1, next(random) % 50) for slot in range(size + 2) if next(random) % 6)
    return Case("vector %d" % index, kind="median", date=now, secs=secs, nanos=0, period=period, guard=bucket - 1 if next(random) % 6 else bucket, votes=tuple(votes), stakes=stakes, tag=next(random) % 2)


def check_cases(harness, cases):
    outcomes = []
    for case in cases:
        before, got = harness.run(case)
        want = spec_run(case, before)
        text = mismatch(case, got, want, before)
        if text is not None:
            raise EvidenceError("case disagrees with the rule list: %s: %s" % (case.name, text))
        outcomes.append(got)
    return outcomes


PINS = (
    (0x3BAEE31, "807a2c01", "first row family needs info +0x2c (active) == 1"),
    (0x3BAEE53, "80bc08d200000000", "token record +0xd2 must be nonzero"),
    (0x3BAEE6B, "8b88db000000", "row address word from the token record, +0xdb"),
    (0x3BAEE88, "488b1a", "row amount source: info +0 (evm_minted_supply)"),
    (0x3BAEE8B, "48d1eb", "row amount is halved"),
    (0x3BAEE8E, "4883c208", "row map pointer is info +8 (daily_wei_owed)"),
    (0x3BAF489, "80bc11bc00000001", "second row family needs token record +0xbc == 1"),
    (0x3BAF4F7, "ff15a351bc01", "second family reads through slot 0x57746a0"),
    (0x3BAF539, "e832226dff", "second family scales the word with 0x3281770"),
    (0x3BAF5A5, "c644240f50", "second family address starts with byte 0x50"),
    (0x3BAF57F, "480fc8", "second family address ends with the token id, big endian"),
    (0x3BAF59B, "b001", "second family flag byte is 1"),
)
KEYS = (
    ("AlignedQuoteTokenInfo", 0x375D872, "488d4b2c", 0x375D876, 0x2C, 6, "active"),
    ("AlignedQuoteTokenInfo", 0x375D8C1, "4c8d6320", 0x375D8A0, 0x20, 0x12, "first_aligned_time"),
    ("AlignedQuoteTokenInfo", 0x375D96F, "488b33", 0x375D91D, 0, 0x11, "evm_minted_supply"),
    ("AlignedQuoteTokenInfo", 0x375D99D, "4883c308", 0x375D97C, 8, 0xE, "daily_wei_owed"),
    ("spot meta at state +0x90", 0x375A739, "488db320020000", 0x3792094, 0x220, 0x27, "quote_token_to_aligned_quote_token_info"),
    ("spot meta at state +0x90", 0x375A79B, "4881c368020000", 0x37913C4, 0x268, 3, "ta2"),
    ("state at serializer base minus 0x1b20", 0x3753399, "488db39c1f0000", 0x37916E8, 0x1F9C, 0x14, "last_aqa_sample_time"),
    ("state at serializer base minus 0x1b20", 0x3753381, "488db328170000", 0x3792754, 0x1728, 0x1B, "validator_l1_stream_tracker"),
)
CONSTANTS = ((0x2763824, 0x20A730, 1.0, "lowest sample gap, seconds"), (0x2763BC0, 0x20A4D0, 31557600.0, "seconds in a Julian year"), (0x2763BCC, 0x20A528, 1.01, "largest fraction"),
             (0x2763C63, 0x20A510, TWO64, "clamp top"), (0x2763CA4, 0x20A7F0, 9223372036854775808.0, "cast split"), (0x2763CC8, 0x20A218, CAST_TOP, "saturation test"))
INTS = ((0x2763E77, "b8feffffff", DAYS_TWO, "days back, chain byte 2"), (0x2763E7C, "bed3ffffff", DAYS_MAIN, "days back, every other chain byte"), (0x27641DB, "48bacccccccccccccc0c", CAP, "value bound"),
        (0x27641BF, "b9ea000000", TAG_TOKEN, "token bound tag"), (0x27641D6, "b93f010000", TAG_NUMBER, "value bound tag"))
TEXTS = ((0x219D71, 0x1C, "assertion failed: self >= 0."), (0x219D8D, 0x1D, "assertion failed: dur.0 >= 0."), (0x219F59, 0x1E, "assertion failed: self.0 >= 0."), (KEY_TEXT, 0x15, "median_risk_free_rate"))
SERDE = (b"struct AlignedQuoteTokenInfo with 4 elements", b"struct Aqav2TokenInfo with 5 elements", b"struct ValidatorL1StreamTracker with 1 element", b"tuple variant ValidatorL1VoteAction::AlignedQuoteToken with 2 elements",
         b"struct variant ValidatorL1VoteAction::ModifyAqav2 with 5 elements", b"struct variant SpotDeployAction::EnableAlignedQuoteToken with 1 element")


def row_bytes(image, va, size):
    return bytes(image.blob[image.offset(va):image.offset(va) + size])


def pin_rows(image):
    rows = []
    for va, pattern, meaning in PINS:
        wanted = bytes.fromhex(pattern)
        if row_bytes(image, va, len(wanted)) != wanted:
            raise EvidenceError("pin row %#x" % va)
        rows.append(("%#x" % va, pattern, meaning))
    return rows


def lea_target(image, va):
    data = row_bytes(image, va, 7)
    if data[:2] not in (b"\x48\x8d", b"\x4c\x8d"):
        raise EvidenceError("no lea at %#x" % va)
    return va + 7 + struct.unpack_from("<i", data, 3)[0]


def key_rows(image):
    rows = []
    for record, va, pattern, lea, field, size, text in KEYS:
        if row_bytes(image, va, len(pattern) // 2) != bytes.fromhex(pattern):
            raise EvidenceError("field row %#x" % va)
        at = lea_target(image, lea)
        if row_bytes(image, at, size) != text.encode():
            raise EvidenceError("key at %#x" % lea)
        rows.append((record, "%#x" % va, pattern, "%#x" % lea, "%#x" % at, "%#x" % field, text))
    return rows


def constant_rows(image):
    rows = []
    for va, at, value, meaning in CONSTANTS:
        row = decode(lambda where, count: bytes(image.blob[image.offset(where):image.offset(where) + count]), va)
        tail = 1 if row.op == "cmpsd" else 0
        data = row_bytes(image, va, row.size)
        target = va + row.size + struct.unpack_from("<i", data, row.size - 4 - tail)[0]
        if target != at:
            raise EvidenceError("constant reader %#x reaches %#x" % (va, target))
        if struct.unpack("<d", row_bytes(image, at, 8))[0] != value:
            raise EvidenceError("constant at %#x" % at)
        rows.append(("%#x" % va, "%#x" % at, repr(value), meaning))
    for va, pattern, value, meaning in INTS:
        if row_bytes(image, va, len(pattern) // 2) != bytes.fromhex(pattern):
            raise EvidenceError("integer row %#x" % va)
        rows.append(("%#x" % va, pattern, str(value), meaning))
    return rows


def text_rows(image):
    rows = []
    for at, size, text in TEXTS:
        found = row_bytes(image, at, size).decode()
        if text is not None and found != text:
            raise EvidenceError("text at %#x" % at)
        if text is not None:
            rows.append(("%#x" % at, found))
    return rows


def serde_rows(image):
    blob = bytes(image.blob)
    rows = []
    for text in SERDE:
        at = blob.find(text)
        if at < 0:
            raise EvidenceError("no serde text")
        rows.append(("%#x" % at, text.decode()))
    return rows


def copy_rows():
    return [(copy.name, "%#x" % copy.entry, "%#x" % copy.stop, "%#x" % copy.time_at, "%#x" % copy.tracker, "%#x" % copy.chain, "%#x" % copy.tokens, "%#x" % copy.transfer, "%#x" % copy.insert, "%#x" % copy.remove) for copy in COPIES]


def rows_of(image, target):
    return decode_range(image, *image.exact_fde(target))


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
            before, got = harness.run(case)
            if not same(case, got, spec_run(case, before), before):
                return case
        except (Halt, EvidenceError, KeyError, IndexError, ValueError, OverflowError, ZeroDivisionError, struct.error, Panicked):
            return case
    return None


REACH_CAP = 12
UNCLASSIFIED = "not classified: survived the capped case list of at most 12 cases for this row"
EXPECTED_SURVIVORS = {}
#SURVIVORS#


MUTATED = (GUARD, SPLIT, MEDIAN, JOIN, SMALL_SORT, COLLECT, 0x2878B20, 0x28682A0)
MUTATED_WINDOWS = ("sample_a", "median_closure", "weighted_pick")


def spread(items):
    """At most REACH_CAP cases, evenly spaced, so that a row reached by every case does not cost every case."""
    step = max(1, len(items) // REACH_CAP)
    return items[::step]


def run_mutants(image, table, window, seen, cases):
    results = []
    control = Harness(image)
    control.machine.step_limit = MUTANT_STEP_LIMIT
    if first_failure(control, cases) is not None:
        raise EvidenceError("an unedited image fails under the mutant step limit")
    chosen = cases + vector_cases(240)
    reach = collections.defaultdict(list)
    for case in chosen:
        control.machine.seen = set()
        control.run(case)
        for va in control.machine.seen:
            reach[va].append(case)
    groups = [table[target] for target in SUBJECTS if target in MUTATED] + [window[name] for name in MUTATED_WINDOWS]
    for rows in groups:
        for va, kind, patch in edits_for(image, rows, seen):
            harness = Harness(image, patch)
            harness.machine.step_limit = MUTANT_STEP_LIMIT
            harness.machine.cache = {key: row for key, row in control.machine.cache.items() if not key <= va < key + row.size}
            hit = first_failure(harness, spread(reach[va]))
            if hit is not None:
                results.append((va, kind, "killed", hit.name))
            else:
                results.append((va, kind, "survived", EXPECTED_SURVIVORS.get((va, kind), UNCLASSIFIED)))
    return results



def windows(image, seen, cache):
    """Rows reached inside the listed hosts, from the block start on; these FDE starts stay out of the evidence."""
    groups = {}
    for copy in COPIES:
        low, high = image.exact_fde(copy.host)
        groups["sample_" + copy.name] = sorted(va for va in seen if low <= va < high)
    low, high = image.exact_fde(CLOSURE)
    groups["median_closure"] = sorted(va for va in seen if low + 0x11 <= va < high)
    low, high = image.exact_fde(WEIGHTED)
    groups["weighted_pick"] = sorted(va for va in seen if low + 0x43 <= va < high)
    tables = {}
    for name, vas in groups.items():
        rows = [cache[va] for va in vas]
        for row in rows:
            row.data = row_bytes(image, row.va, row.size)
        tables[name] = rows
    return tables


def analyse(image, mutate=True, vectors=1200):
    RealCode.ALL = collect_real(image)
    harness = Harness(image)
    cases = base_cases()
    outcomes = check_cases(harness, cases)
    vector = vector_cases(vectors)
    check_cases(harness, vector)
    seen = set(harness.machine.seen)
    table = {target: rows_of(image, target) for target in SUBJECTS}
    cache = harness.machine.cache
    window = windows(image, seen, cache)
    unreached = {target: [row.va for row in table[target] if row.va not in seen and row.op not in ("int3", "nop")] for target in SUBJECTS}
    result = dict(table=table, window=window, cases=cases, outcomes=outcomes, vector_count=len(vector), unreached=unreached, texts=text_rows(image), keys=key_rows(image), serde=serde_rows(image), pins=pin_rows(image), constants=constant_rows(image))
    if mutate:
        result["mutations"] = run_mutants(image, table, window, seen, cases)
        unexplained = [row for row in result["mutations"] if row[3] == "UNEXPLAINED"]
        if unexplained:
            raise EvidenceError("unexplained survivors: %s" % [(hex(row[0]), row[1]) for row in unexplained])
    return result


def outcome_row(case, got):
    copy = COPIES[case.copy].name if case.kind == "sample" else "-"
    if case.kind == "sample":
        maps = sorted((key, value) for key, value in got["maps"].items())
        events = [event for event in got["events"] if event[0] != "free"]
        label = got["panic"] or "transfers=%d drops=%d" % (sum(1 for event in events if event[0] == "transfer"), sum(1 for event in events if event[0] == "drop"))
        digest = hashlib.sha256(repr((maps, events, got["last"])).encode()).hexdigest()[:16]
    else:
        label = "tag=%d rows=%d" % (got["tag"], len(got["rows"]))
        digest = hashlib.sha256(repr((got["guard"], got["tag"], got["value"], got["rows"])).encode()).hexdigest()[:16]
    return (case.kind, copy, case.name, label, digest)


def render(result):
    files = {}

    def tsv(name, header, rows):
        lines = ["\t".join(header)] + ["\t".join(str(cell) for cell in row) for row in rows]
        files[name] = "\n".join(lines) + "\n"

    tsv("function-rows.tsv", ("function", "address", "size", "bytes", "operation"), [(NAMES[target], "%#x" % row.va, row.size, row.data.hex(), row.op) for target in SUBJECTS for row in result["table"][target]])
    tsv("window-rows.tsv", ("window", "address", "size", "bytes", "operation"), [(name, "%#x" % row.va, row.size, row.data.hex(), row.op) for name in sorted(result["window"]) for row in result["window"][name]])
    tsv("copies.tsv", ("copy", "block_start", "block_end", "last_sample_time", "median", "chain_byte", "token_table", "transfer", "entry_insert", "daily_remove"), copy_rows())
    tsv("keys.tsv", ("record", "field_row", "field_row_bytes", "key_row", "key_text_at", "field", "key"), result["keys"])
    tsv("pins.tsv", ("address", "bytes", "reading"), result["pins"])
    tsv("constants.tsv", ("row", "value_at_or_bytes", "value", "meaning"), result["constants"])
    tsv("texts.tsv", ("address", "text"), result["texts"])
    tsv("serde.tsv", ("file_offset", "text"), result["serde"])
    tsv("outcomes.tsv", ("kind", "copy", "case", "result", "digest"), [outcome_row(case, got) for case, got in zip(result["cases"], result["outcomes"])])
    if "mutations" in result:
        tsv("mutations.tsv", ("address", "kind", "outcome", "detail"), [("%#x" % va, k, o, d) for va, k, o, d in result["mutations"]])
    summary = {
        "binary": "artifacts/node/94/hl-node", "sha256": SHA256,
        "functions": {NAMES[target]: {"address": "%#x" % target, "bytes": sum(row.size for row in result["table"][target]), "instructions": len(result["table"][target]),
                                      "unreached_rows": ["%#x" % va for va in result["unreached"][target]]} for target in SUBJECTS},
        "window_rows_reached": {name: len(rows) for name, rows in sorted(result["window"].items())},
        "named_cases": len(result["cases"]), "vector_cases": result["vector_count"],
    }
    if "mutations" in result:
        rows = result["mutations"]
        summary["mutations"] = {"total": len(rows), "killed": sum(1 for r in rows if r[2] == "killed"), "survived": sum(1 for r in rows if r[2] == "survived")}
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

