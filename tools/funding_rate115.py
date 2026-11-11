#!/usr/bin/env python3
"""Reconstruct the node #115 funding rate value body 0x44d8590 from the ELF bytes and prove it against a written rule list.

The body takes the owner object and an asset key, finds that key's sample vector in the sample store (a VecDeque or a B-tree, chosen by a
niche word), sums the samples in order, divides by the count, pulls the interest term toward the average by a symmetric clamp, multiplies
by a per-key multiplier, clamps the result to a fixed band and scales it. The real bytes of the body and of the deque binary search
0x45562e0 run in a small x86-64 evaluator; the three index-map lookups (hash 0x47172c0, probe 0x3ed2810) are recording stubs. A separately
written bit level rule list predicts every result and every lookup, 24 named wrong readings must be refused, and every reached condition,
immediate and field displacement of the subject code is edited. No objdump or readelf output is parsed and the binary is never executed.
Standard library only.

    python3 tools/funding_rate115.py --out <dir>
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
            if op in ("addsd", "divsd", "subsd", "mulsd"):
                self.set_low(row.a[1], sse_arith(op[:3], self.low(row.a), self.low(row.b)))
                return
            if op == "minsd":
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




def sse_arith(op, a, b):
    """Scalar double add/sub/mul/div on raw bits with the x86 NaN rules: the first NaN operand wins and is quieted, a new NaN is the indefinite value."""
    quiet = 1 << 51
    for bits in (a, b):
        if (bits >> 52) & 0x7FF == 0x7FF and bits & ((1 << 52) - 1):
            return bits | quiet
    x, y = to_float(a), to_float(b)
    if op == "add":
        r = x + y
    elif op == "sub":
        r = x - y
    elif op == "mul":
        r = x * y
    else:
        r = fdiv(x, y)
    return 0xFFF8000000000000 if r != r else to_bits(r)


def fdiv(left, right):
    if right == 0:
        if left == 0 or left != left:
            return math.nan
        return math.copysign(math.inf, math.copysign(1.0, left) * math.copysign(1.0, right))
    return left / right


# ---------------------------------------------------------------------------------------------------------------------------
# Subject: the funding rate value body and the code it calls for the sample store.

RATE = 0x44D8590
BSEARCH = 0x45562E0
HASH = 0x47172C0
FIND = 0x3ED2810
SLOT_BOUNDS = 0x64DF620
SLOT_ASSERT = 0x64DF6B8
MARK_BASE = 0x7700000000

SELF = HEAP_BASE + 0x1000
SELF_SIZE = 0x150
RING = HEAP_BASE + 0x1200
ARENA = HEAP_BASE + 0x2000
USED = 0x12000
FILL = 0x37

# field offsets of the owner object read by the body
F_MULT, F_INTEREST, F_CLAMP = 0x48, 0x90, 0xD8      # three index maps: ptr +8, len +0x10, hasher words +0x38 / +0x40
F_STORE = 0x120                                      # sample store: word 0 is the capacity or the tree niche
F_DEFAULT_CLAMP = 0x140
TREE_NICHE = 1 << 63
MAPS = (("interest", F_INTEREST), ("clamp", F_CLAMP), ("multiplier", F_MULT))   # order of the lookups in the body
MAP_NAME = {F_INTEREST: "interest", F_CLAMP: "clamp", F_MULT: "multiplier"}

SIGN64 = 1 << 63
QUIET = 1 << 51
INDEFINITE = 0xFFF8000000000000
MAX_FINITE_ABS = 0x7FEFFFFFFFFFFFFF

CONSTANTS = (
    (0x459458, "sum_start", 8), (0x459B50, "default_interest", 8), (0x4592B0, "default_multiplier", 8),
    (0x4559C0, "sign_mask", 16), (0x459A78, "rate_floor", 8), (0x4590D0, "rate_ceiling", 8), (0x459230, "output_scale", 8),
)


def constant_bits(image):
    out = {}
    for va, name, size in CONSTANTS:
        at = image.offset(va)
        out[name] = int.from_bytes(image.blob[at:at + 8], "little")
    return out


# --- written rule list (bit level, no instruction decoding) ---------------------------------------------------------------

def is_nan(bits):
    return (bits >> 52) & 0x7FF == 0x7FF and bits & ((1 << 52) - 1) != 0


def is_finite(bits):
    return bits & ~SIGN64 <= MAX_FINITE_ABS


def arith(op, a, b):
    """x86 scalar double arithmetic on raw bits: the first NaN operand wins and is quieted, a fresh NaN is the indefinite value."""
    if is_nan(a):
        return a | QUIET
    if is_nan(b):
        return b | QUIET
    x, y = to_float(a), to_float(b)
    if op == "add":
        r = x + y
    elif op == "sub":
        r = x - y
    elif op == "mul":
        r = x * y
    else:
        if y == 0.0:
            return INDEFINITE if x == 0.0 else ((a ^ b) & SIGN64) | 0x7FF0000000000000
        r = x / y
    return INDEFINITE if r != r else to_bits(r)


def smin(a, b):
    """minsd a, b: a when a < b, otherwise b (NaN and equal zeros give b)."""
    return a if to_float(a) < to_float(b) else b


def smax(a, b):
    return a if to_float(a) > to_float(b) else b


class Panic(Exception):
    pass


def spec_rate(case, k, flags=frozenset()):
    """Predict (result, lookup log). result is ('none',), ('some', bits) or ('panic', site)."""
    log = []
    vec = case.samples_of(case.key)
    if vec is None or len(vec) == 0:
        return ("none",), log
    total = k["sum_start"]
    for bits in vec:
        total = arith("add", total, bits)
    avg = arith("div", total, to_bits(float(len(vec))))

    def lookup(name, default):
        table = case.maps[name]
        if len(table) == 0:
            return default
        if len(table) >= 2:
            log.append(("hash", name, case.key))
            log.append(("find", name, case.key))
            if case.bad_index == name:
                return None
        for key, value in table:
            if key == case.key:
                return value
        return default

    interest = lookup("interest", k["default_interest"])
    if interest is None:
        return ("panic", "bounds"), log
    clamp = lookup("clamp", case.default_clamp)
    if clamp is None:
        return ("panic", "bounds"), log
    diff = arith("sub", interest, avg)
    if is_finite(diff) and is_finite(clamp):
        neg = clamp ^ SIGN64
        lo, hi = smin(clamp, neg), smax(neg, clamp)
        if not to_float(lo) <= to_float(hi):
            return ("panic", "assert"), log
        diff = smin(hi, smax(lo, diff))
    mult = lookup("multiplier", k["default_multiplier"])
    if mult is None:
        return ("panic", "bounds"), log
    value = arith("mul", arith("add", avg, diff), mult)
    if is_finite(value):
        value = smin(k["rate_ceiling"], smax(k["rate_floor"], value))
    return ("some", arith("mul", value, k["output_scale"])), log


# --- cases ------------------------------------------------------------------------------------------------------------------

class Case:
    __slots__ = ("name", "store", "items", "cap", "head", "height", "key", "maps", "default_clamp", "bad_index", "chunks")

    def __init__(self, name, store, items, key, maps, default_clamp, cap=0, head=0, height=0, bad_index=None, chunks=None):
        self.name, self.store, self.items, self.key = name, store, items, key
        self.maps, self.default_clamp = maps, default_clamp
        self.cap, self.head, self.height, self.bad_index, self.chunks = cap, head, height, bad_index, chunks

    def samples_of(self, key):
        for stored, vec in self.items:
            if stored == key:
                return vec
        return None


class Arena:
    def __init__(self, memory):
        self.memory, self.top = memory, ARENA

    def alloc(self, size):
        at = self.top
        self.top = (self.top + size + 15) & ~15
        if self.top > HEAP_BASE + USED:
            raise Halt("arena exhausted")
        return at

    def words(self, values):
        at = self.alloc(8 * max(1, len(values)))
        for index, value in enumerate(values):
            self.memory.write(at + 8 * index, 8, value)
        return at


def split_tree(sorted_items, height, chunks):
    """Shape for a B-tree of the given height: list of (separator items, child shapes) built from the chunk plan."""
    if height == 0:
        return sorted_items, None
    parts = max(2, min(len(sorted_items) + 1, chunks.pop(0) if chunks else 3))
    size = max(1, (len(sorted_items) - (parts - 1)) // parts)
    children, seps, at = [], [], 0
    for index in range(parts):
        last = index == parts - 1
        take = len(sorted_items) - at if last else min(size, max(0, len(sorted_items) - at - (parts - 1 - index)))
        children.append(split_tree(sorted_items[at:at + take], height - 1, chunks))
        at += take
        if not last and at < len(sorted_items):
            seps.append(sorted_items[at])
            at += 1
    return seps, children


# --- evaluator harness --------------------------------------------------------------------------------------------------

class Harness:
    def __init__(self, image, patches=None):
        self.image = image
        machine = Machine(image, patches)
        self.machine = machine
        machine.real = frozenset({BSEARCH})
        machine.calls[HASH] = self.on_hash
        machine.calls[FIND] = self.on_find
        statics = machine.memory.statics
        for slot, hook in ((SLOT_BOUNDS, self.on_bounds), (SLOT_ASSERT, self.on_assert)):
            statics[slot] = MARK_BASE + slot
            machine.slots[MARK_BASE + slot] = hook
        self.case, self.log = None, []

    def expect(self, condition, text):
        if not condition:
            raise Halt("stub check failed: " + text)

    def table_of(self, address):
        return MAP_NAME[address - SELF]

    def on_hash(self, machine):
        regs = machine.regs
        at = regs[RDI] - 0x0F0F0F0F00000000
        self.expect(at in MAP_NAME, "hasher words name no table")
        name = MAP_NAME[at]
        mem = machine.memory
        self.expect(regs[RDI] == mem.read(SELF + at + 0x38, 8) and regs[RSI] == mem.read(SELF + at + 0x40, 8), "hasher words")
        self.expect(regs[RDX] == self.case.key, "hash key")
        self.log.append(("hash", name, regs[RDX]))
        regs[RAX] = self.hash_of(regs[RDX])

    @staticmethod
    def hash_of(key):
        return (key * 0x9E3779B97F4A7C15 + 0x1234) & MASK[8]

    def on_find(self, machine):
        regs = machine.regs
        name = self.table_of(regs[RDI])
        self.expect(regs[RSI] == self.hash_of(self.case.key), "probe hash")
        key = machine.memory.read(regs[RDX], 8)
        self.expect(key == self.case.key, "probe key")
        self.log.append(("find", name, key))
        table = self.case.maps[name]
        found = [index for index, (stored, _) in enumerate(table) if stored == key]
        if self.case.bad_index == name:
            regs[RAX], regs[RDX] = 1, len(table)
        elif found:
            regs[RAX], regs[RDX] = 1, found[0]
        else:
            regs[RAX], regs[RDX] = 0, 0
        machine.keep_rdx = True

    def on_bounds(self, machine):
        raise Panicked("bounds")

    def on_assert(self, machine):
        raise Panicked("assert")

    def build_map(self, arena, base, name):
        memory = self.machine.memory
        table = self.case.maps[name]
        ptr = arena.alloc(24 * max(1, len(table)) + 16)
        for index, (key, value) in enumerate(table):
            memory.write(ptr + 24 * index, 8, 0x5A5A000000000000 + index)
            memory.write(ptr + 24 * index + 8, 8, key)
            memory.write(ptr + 24 * index + 16, 8, value)
        memory.write(SELF + base + 8, 8, ptr)
        memory.write(SELF + base + 0x10, 8, len(table))
        memory.write(SELF + base + 0x38, 8, 0x0F0F0F0F00000000 + base)
        memory.write(SELF + base + 0x40, 8, 0x7070707000000000 + base)

    def build_vec(self, arena, vec):
        ptr = arena.words(vec)
        return len(vec) + 1, ptr, len(vec)         # capacity, pointer, length

    def build_store(self, arena, case):
        memory = self.machine.memory
        if case.store == "deque":
            cap = case.cap
            slots = [None] * cap
            for index, (key, vec) in enumerate(case.items):
                slots[(case.head + index) % cap] = (key, vec)
            for physical in range(cap):
                at = RING + 32 * physical
                if slots[physical] is None:
                    memory.put_bytes(at, bytes(32 * [0x9D]))
                    continue
                key, vec = slots[physical]
                vcap, vptr, vlen = self.build_vec(arena, vec)
                for offset, value in ((0, key), (8, vcap), (16, vptr), (24, vlen)):
                    memory.write(at + offset, 8, value)
            for offset, value in ((0, cap), (8, RING), (0x10, case.head), (0x18, len(case.items))):
                memory.write(SELF + F_STORE + offset, 8, value)
            return
        shape = split_tree(sorted(case.items), case.height, list(case.chunks or ()))
        root = self.build_node(arena, shape, case.height)
        for offset, value in ((0, TREE_NICHE), (8, root), (0x10, case.height), (0x18, len(case.items))):
            memory.write(SELF + F_STORE + offset, 8, value)

    def build_node(self, arena, shape, height):
        memory = self.machine.memory
        keys, children = shape
        node = arena.alloc(0x1D0)
        memory.put_bytes(node, bytes(0x1D0 * [0xC3]))
        memory.write(node, 8, 0)
        for index, item in enumerate(keys):
            key, vec = item
            vcap, vptr, vlen = self.build_vec(arena, vec)
            memory.write(node + 8 + 8 * index, 8, key)
            for offset, value in ((0, vcap), (8, vptr), (16, vlen)):
                memory.write(node + 0x60 + 24 * index + offset, 8, value)
        memory.write(node + 0x16A, 2, len(keys))
        if children is not None:
            for index, child in enumerate(children):
                memory.write(node + 0x170 + 8 * index, 8, self.build_node(arena, child, height - 1))
        return node

    def fresh(self, case):
        machine = self.machine
        memory = machine.memory
        memory.reset(USED)
        machine.xmm = [POISON | POISON << 64] * 16
        memory.put_bytes(HEAP_BASE, bytes((index * 29 + 5) & 0xFF for index in range(0x1000)))
        memory.put_bytes(SELF, bytes((FILL + 3 * index) & 0xFF for index in range(SELF_SIZE)))
        self.case, self.log = case, []
        arena = Arena(memory)
        memory.write(SELF + F_DEFAULT_CLAMP, 8, case.default_clamp)
        for name, base in MAPS:
            self.build_map(arena, base, name)
        self.build_store(arena, case)
        return bytes(memory.heap[:USED])

    def run(self, case):
        before = self.fresh(case)
        machine = self.machine
        try:
            outcome = self.drive(case)
        except Panicked as panic:
            outcome = ("panic", str(panic))
        after = bytes(machine.memory.heap[:USED])
        if after != before:
            raise Halt("the body changed the heap")
        return before, (outcome, self.log)

    def drive(self, case):
        machine = self.machine
        flag = machine.run(RATE, {RDI: SELF, RSI: case.key})
        if flag == 0:
            return ("none",)
        self.expect(flag == 1, "flag")
        return ("some", machine.xmm[0] & MASK[8])


# --- case generation ------------------------------------------------------------------------------------------------------

def lcg(seed):
    state = seed & MASK[8]
    while True:
        state = (state * 6364136223846793005 + 1442695040888963407) & MASK[8]
        yield state >> 11


SPECIALS = (
    0x0000000000000000, 0x8000000000000000, 0x3FF0000000000000, 0xBFF0000000000000, 0x7FF0000000000000, 0xFFF0000000000000,
    0x7FF8000000000000, 0xFFF8000000000000, 0x7FF4000000000001, 0x7FEFFFFFFFFFFFFF, 0xFFEFFFFFFFFFFFFF, 0x0000000000000001,
    0x000FFFFFFFFFFFFF, 0x3F1A36E2EB1C432D, 0x3FA47AE147AE147B, 0xBFA47AE147AE147B, 0x3F847AE147AE147B, 0x4000000000000000,
)


def draw_float(stream):
    kind = next(stream) % 10
    if kind <= 1:
        return SPECIALS[next(stream) % len(SPECIALS)]
    if kind == 2:
        return to_bits((next(stream) % 2000001 - 1000000) * 1e-9)
    if kind == 3:
        return to_bits(float(next(stream) % 2001 - 1000))
    if kind == 4:
        return next(stream) << 11 | next(stream) & 0x7FF
    return to_bits((next(stream) % 200001 - 100000) * 1e-7)


def pick_key(stream):
    return next(stream) % 6


def draw_map(stream, key, flavour):
    count = (0, 1, 2, 3, 5)[flavour % 5]
    keys = [1000 + index * 7 for index in range(count)]
    if count and next(stream) % 3:
        keys[next(stream) % count] = key
    return [(k, draw_float(stream)) for k in keys]


def named_cases():
    cases = []
    one = to_bits(1e-4)
    base = {name: [] for name, _ in MAPS}

    def add(name, store, items, key, maps=None, clamp=0x3F847AE147AE147B, **kw):
        cases.append(Case(name, store, items, key, dict(base, **(maps or {})), clamp, **kw))

    add("deque single sample", "deque", [(3, [one])], 3, cap=4, head=0)
    add("deque key absent", "deque", [(3, [one])], 2, cap=4, head=0)
    add("deque empty store", "deque", [], 3, cap=4, head=0)
    add("deque empty vector", "deque", [(3, [])], 3, cap=4, head=0)
    add("deque wrapped ring", "deque", [(1, [one]), (3, [one, one]), (5, [one] * 3)], 5, cap=4, head=3)
    add("tree leaf", "btree", [(3, [one, one])], 3, height=0)
    add("tree miss", "btree", [(3, [one])], 4, height=0)
    add("tree two levels", "btree", [(k, [one] * (k % 4 + 1)) for k in range(1, 9)], 6, height=1, chunks=[3])
    zero = {name: [] for name, _ in MAPS}
    for index, clamp in enumerate((0x0000000000000000, 0x8000000000000000)):
        for sample in (0x8000000000000000, 0x0000000000000000):
            add("zero clamp %d sample %#x" % (index, sample), "deque", [(5, [sample])], 5,
                maps={"interest": [(5, to_bits(-1e-3))], "clamp": [(5, clamp)]}, cap=2, head=1)
            add("zero default clamp %d sample %#x" % (index, sample), "btree", [(5, [sample, sample])], 5,
                maps={"interest": [(5, to_bits(-1e-3))]}, clamp=clamp, height=0)
    for probe in (11, 12, 6):
        add("tree full leaf key %d" % probe, "btree", [(k, [one] * (k % 3 + 1)) for k in range(1, 12)], probe, height=0)
    for probe in (22, 12, 23):
        add("tree full nodes key %d" % probe, "btree", [(k, [one] * (k % 3 + 1)) for k in range(1, 24)], probe, height=1, chunks=[2])
    add("tree three levels", "btree", [(k, [one] * (k % 4 + 1)) for k in range(1, 20)], 17, height=2, chunks=[3, 3, 3, 3])
    return cases


def random_cases(count, seed=0xF00D1234):
    stream = lcg(seed)
    out = []
    for index in range(count):
        flavour = next(stream) % 12
        key = pick_key(stream)
        total = (0, 1, 2, 3, 5, 6, 9, 15)[next(stream) % 8]
        keys = sorted({next(stream) % 8 for _ in range(total)} | ({key} if next(stream) % 4 else set()))
        items = []
        for stored in keys:
            width = (0, 1, 2, 3, 7, 8, 9, 15, 16, 17, 24, 33)[next(stream) % 12] if next(stream) % 3 else 1 + next(stream) % 5
            items.append((stored, [draw_float(stream) for _ in range(width)]))
        maps = {name: draw_map(stream, key, next(stream)) for name, _ in MAPS}
        clamp = draw_float(stream)
        bad = None
        if flavour == 0:
            wide = [name for name in maps if len(maps[name]) >= 2]
            bad = wide[next(stream) % len(wide)] if wide else None
        if flavour % 2:
            cap = max(len(items), 1) + next(stream) % 5
            out.append(Case("deque %d" % index, "deque", items, key, maps, clamp, cap=cap, head=next(stream) % cap, bad_index=bad))
        else:
            height = next(stream) % 3
            chunks = [2 + next(stream) % 3 for _ in range(8)]
            out.append(Case("tree %d" % index, "btree", items, key, maps, clamp, height=height if len(items) >= 3 * height else 0,
                            chunks=chunks, bad_index=bad))
    return out


def tree_ok(case):
    """A height h tree needs at least one key per node; the generator already limits height by the item count."""
    return True


def digest(outcome, log):
    return hashlib.sha256(repr((outcome, log)).encode()).hexdigest()[:16]


def check_cases(harness, cases, k, variant=frozenset(), keep=0):
    """Run every case, compare with the rule list; returns (count, first failure, kept rows, outcome kinds)."""
    rows, kinds, count, first = [], collections.Counter(), 0, None
    for index, case in enumerate(cases):
        expected, expected_log = spec_rate(case, k, variant)
        try:
            _, (got, log) = harness.run(case)
        except Halt as problem:
            got, log = ("halt", str(problem)), []
        count += 1
        kinds[expected[0]] += 1
        if (got, log) != (expected, expected_log):
            if first is None:
                first = (index, case.name, got, expected)
            if not variant:
                continue
        if keep and index % keep == 0:
            rows.append((index, case.name, case.store, expected, len(harness.log)))
    return count, first, rows, kinds


# --- plausible wrong readings (each one must be refused by the bytes) ------------------------------------------------------------

VARIANTS = (
    "average_skipped", "sum_reversed", "sum_two_lanes", "divide_by_len_plus_one", "no_output_scale", "no_ceiling", "no_floor",
    "clamp_asymmetric", "swap_difference", "clamp_nonfinite_too", "interest_default_zero", "multiplier_default_zero",
    "multiplier_on_average_only", "multiplier_looked_up_first", "single_entry_ignores_key", "empty_vector_is_zero",
    "absent_key_is_zero", "second_nan_wins", "nan_not_quieted", "indefinite_positive", "min_max_keep_first_on_equal",
    "single_entry_probes", "clamp_default_ignored", "interest_and_clamp_swapped",
)


def variant_arith(op, a, b, flags):
    if "second_nan_wins" in flags and is_nan(b):
        return b | QUIET
    if "nan_not_quieted" in flags:
        if is_nan(a):
            return a
        if is_nan(b):
            return b
    value = arith(op, a, b)
    if "indefinite_positive" in flags and value == INDEFINITE and not is_nan(a) and not is_nan(b):
        return INDEFINITE ^ SIGN64
    return value


def variant_spec(case, k, flags):
    """The rule list with named deviations; the base rule list is spec_rate."""
    log = []
    vec = case.samples_of(case.key)
    if vec is None and "absent_key_is_zero" in flags:
        return ("some", 0), log
    if vec is not None and len(vec) == 0 and "empty_vector_is_zero" in flags:
        return ("some", 0), log
    if vec is None or len(vec) == 0:
        return ("none",), log
    total = k["sum_start"]
    order = list(reversed(vec)) if "sum_reversed" in flags else vec
    if "sum_two_lanes" in flags:
        lane = [k["sum_start"], k["sum_start"]]
        for index, bits in enumerate(order):
            lane[index & 1] = variant_arith("add", lane[index & 1], bits, flags)
        total = variant_arith("add", lane[0], lane[1], flags)
    else:
        for bits in order:
            total = variant_arith("add", total, bits, flags)
    divisor = len(vec) + (1 if "divide_by_len_plus_one" in flags else 0)
    avg = total if "average_skipped" in flags else variant_arith("div", total, to_bits(float(divisor)), flags)

    def lookup(name, default):
        table = case.maps[name]
        if len(table) == 0:
            return default
        if len(table) >= 2 or "single_entry_probes" in flags:
            log.append(("hash", name, case.key))
            log.append(("find", name, case.key))
            if case.bad_index == name:
                return None
        if len(table) == 1 and "single_entry_ignores_key" in flags:
            return table[0][1]
        for key, value in table:
            if key == case.key:
                return value
        return default

    mult = None
    if "multiplier_looked_up_first" in flags:
        mult = lookup("multiplier", k["default_multiplier"])
    interest = lookup("interest", 0 if "interest_default_zero" in flags else k["default_interest"])
    if interest is None:
        return ("panic", "bounds"), log
    clamp = lookup("clamp", 0 if "clamp_default_ignored" in flags else case.default_clamp)
    if clamp is None:
        return ("panic", "bounds"), log
    if "interest_and_clamp_swapped" in flags:
        interest, clamp = clamp, interest
    diff = variant_arith("sub", avg, interest, flags) if "swap_difference" in flags else variant_arith("sub", interest, avg, flags)
    if (is_finite(diff) and is_finite(clamp)) or "clamp_nonfinite_too" in flags:
        neg = clamp ^ SIGN64
        if "clamp_asymmetric" in flags:
            lo, hi = neg, clamp
        else:
            lo, hi = smin(clamp, neg), smax(neg, clamp)
        if "min_max_keep_first_on_equal" in flags:
            lo, hi = (clamp if to_float(clamp) <= to_float(neg) else neg), (clamp if to_float(clamp) >= to_float(neg) else neg)
        if not to_float(lo) <= to_float(hi):
            return ("panic", "assert"), log
        diff = smin(hi, smax(lo, diff))
    if mult is None:
        mult = lookup("multiplier", 0 if "multiplier_default_zero" in flags else k["default_multiplier"])
    if mult is None:
        return ("panic", "bounds"), log
    if "multiplier_on_average_only" in flags:
        value = variant_arith("add", variant_arith("mul", avg, mult, flags), diff, flags)
    else:
        value = variant_arith("mul", variant_arith("add", avg, diff, flags), mult, flags)
    if is_finite(value):
        if "no_floor" not in flags:
            value = smax(k["rate_floor"], value)
        if "no_ceiling" not in flags:
            value = smin(k["rate_ceiling"], value)
    if "no_output_scale" not in flags:
        value = variant_arith("mul", value, k["output_scale"], flags)
    return ("some", value), log


# --- streaming comparison --------------------------------------------------------------------------------------------------------

def run_case(harness, case):
    harness.machine.seen = set()
    try:
        _, (got, log) = harness.run(case)
    except (Halt, EvidenceError, IndexError, KeyError, ValueError, OverflowError, struct.error) as problem:
        got, log = ("halt", type(problem).__name__), []
    return got, log


def check_stream(harness, cases, k, variants=(), keep=0, hits=None):
    """One real run per case, compared with the rule list and with every named deviation; nothing per case is kept except sample rows."""
    stats = {"cases": 0, "mismatches": 0, "first_mismatch": None, "kinds": collections.Counter(), "stores": collections.Counter()}
    caught = {name: [0, None] for name in variants}
    rows = []
    for index, case in enumerate(cases):
        got, log = run_case(harness, case)
        expected, expected_log = spec_rate(case, k)
        stats["cases"] += 1
        stats["kinds"][(case.store, expected[0])] += 1
        if (got, log) != (expected, expected_log):
            stats["mismatches"] += 1
            if stats["first_mismatch"] is None:
                stats["first_mismatch"] = (index, case.name, got, expected)
        for name in variants:
            if variant_spec(case, k, frozenset((name,))) != (got, log):
                caught[name][0] += 1
                if caught[name][1] is None:
                    caught[name][1] = index
        if hits is not None:
            hits.update(harness.machine.seen)
        if keep and index % keep == 0:
            detail = hexbits(expected[1]) if expected[0] == "some" else expected[1] if expected[0] == "panic" else ""
            rows.append((index, case.name, case.store, case.key, len(case.samples_of(case.key) or ()), expected[0], detail, len(harness.machine.seen), digest(got, log)))
    return stats, caught, rows


# --- byte level controls ---------------------------------------------------------------------------------------------------------

def mutants_of(image, reached):
    """One edit for every reached conditional jump, immediate and structure field displacement of the subject bodies."""
    out = []
    for entry in (RATE, BSEARCH):
        start, end = image.exact_fde(entry)
        for row in decode_range(image, start, end):
            if row.va not in reached:
                continue
            data = row.data
            if row.op == "jcc":
                at = 0 if 0x70 <= data[0] <= 0x7F else 1
                out.append((row.va, "condition", row.va + at, data[at], data[at] ^ 1))
                continue
            if row.imm_at is not None and row.imm_size in (1, 4) and row.op not in ("call", "jmp"):
                out.append((row.va, "immediate", row.va + row.imm_at, data[row.imm_at], data[row.imm_at] ^ 1))
            for operand in (row.a, row.b):
                if operand and operand[0] == "m" and operand[1] is not None and 0x20 <= abs(operand[4]) < 0x200:
                    disp = operand[4]
                    packed = struct.pack("<i", disp) if abs(disp) >= 128 else struct.pack("<b", disp)
                    spot = bytes(data).find(packed)
                    if spot >= 0 and bytes(data).count(packed) == 1:
                        out.append((row.va, "displacement", row.va + spot, data[spot], data[spot] ^ 8))
    return out


def run_mutants(image, mutants, cases, k):
    rows = []
    for va, kind, at, old, new in mutants:
        harness = Harness(image, {at: new})
        harness.machine.step_limit = MUTANT_STEP_LIMIT
        killed, first = False, ""
        for index, case in enumerate(cases):
            got, log = run_case(harness, case)
            if (got, log) != spec_rate(case, k):
                killed, first = True, "%d" % index
                break
        rows.append((va, kind, at, old, new, killed, first))
    return rows


def structural_controls(image, harness, k, cases):
    """Each entry: (name, detected)."""
    out = []

    def raises(name, thunk, *errors):
        try:
            thunk()
        except errors or (EvidenceError,) as problem:
            out.append((name, True, type(problem).__name__))
            return
        out.append((name, False, "no error"))

    raises("wrong image digest", lambda: load_image(BINARY, "0" * 64), EvidenceError)
    raises("mid-function address is not an FDE start", lambda: image.exact_fde(RATE + 1), EvidenceError)
    raises("address in a NOBITS section has no file bytes", lambda: image.offset(image.named[".bss"]["address"] + 8), EvidenceError)
    raises("decoder refuses a window that ends inside the body", lambda: decode_range(image, RATE, image.exact_fde(RATE)[1] - 1), EvidenceError)
    raises("truncated section table", lambda: Image(bytes(image.blob[:48])), Exception)

    wide = next(case for case in cases if all(len(case.maps[name]) >= 2 for name, _ in MAPS) and case.samples_of(case.key)
                and case.bad_index is None and case.store == "deque" and spec_rate(case, k)[0][0] == "some")
    stripped = Harness(image)
    del stripped.machine.calls[HASH]
    raises("hash call without a model", lambda: stripped.run(wide), Halt)
    plain = Harness(image)
    plain.machine.real = frozenset()
    raises("binary search not run as real code", lambda: plain.run(wide), Halt)
    trapped = Harness(image, {RATE: 0xCC})
    raises("entry byte replaced by int3", lambda: trapped.run(wide), Halt)

    plain_case = Case("plain", "deque", [(1, [to_bits(0.002)])], 1, {name: [] for name, _ in MAPS}, 0x3F847AE147AE147B, cap=2, head=1)
    changed = dict(k, output_scale=to_bits(0.25))
    out.append(("tampered scale constant", run_case(harness, plain_case) != spec_rate(plain_case, changed), "mismatch"))
    changed = dict(k, default_multiplier=to_bits(2.0))
    out.append(("tampered default multiplier constant", run_case(harness, plain_case) != spec_rate(plain_case, changed), "mismatch"))
    changed = dict(k, rate_ceiling=to_bits(0.05))
    hot = Case("hot", "deque", [(1, [to_bits(0.9)])], 1, {name: [] for name, _ in MAPS}, 0x3F847AE147AE147B, cap=2, head=1)
    out.append(("tampered ceiling constant", run_case(harness, hot) != spec_rate(hot, changed), "mismatch"))
    return out


# --- evidence tables ---------------------------------------------------------------------------------------------------------------

def hexbits(value):
    return "0x%016x" % value


def constant_rows(image, k):
    refs = collections.defaultdict(list)
    for row in decode_range(image, *image.exact_fde(RATE)):
        for operand in (row.a, row.b):
            if operand and operand[0] == "m" and operand[4] in [va for va, _, _ in CONSTANTS]:
                refs[operand[4]].append(row.va)
    rows = []
    for va, name, size in CONSTANTS:
        at = image.offset(va)
        raw = bytes(image.blob[at:at + size]).hex()
        rows.append((hexbits(va), name, size, raw, repr(to_float(k[name])), " ".join("%#x" % r for r in refs[va])))
    return rows


def layout_rows(image):
    """Fields of the owner object: every displacement used with the owner register (rbx) by the body."""
    ops = collections.defaultdict(set)
    for row in decode_range(image, *image.exact_fde(RATE)):
        for operand in (row.a, row.b):
            if operand and operand[0] == "m" and operand[1] == RBX and operand[2] is None:
                ops[operand[4]].add("%s/%d" % (row.op, row.width))
    return [("%#x" % disp, ";".join(sorted(ops[disp]))) for disp in sorted(ops)]


def slot_rows(image):
    rows = []
    for slot, kind, addend, _ in image.relocations():
        if kind == 8 and addend in (RATE, BSEARCH, HASH, FIND):
            section = next((s["name"] for s in image.sections if s["address"] <= slot < s["address"] + s["size"] and s["type"] != 8), "?")
            rows.append((hexbits(slot), "%#x" % addend, section))
    return sorted(rows)


def direct_callers(image, targets):
    rows = []
    start_text, text = image.text_bytes()
    for target in targets:
        for at in range(len(text) - 5):
            if text[at] in (0xE8, 0xE9) and start_text + at + 5 + struct.unpack_from("<i", text, at + 1)[0] == target:
                owner = bisect.bisect_right(image.starts, start_text + at) - 1
                rows.append(("%#x" % (start_text + at), "call" if text[at] == 0xE8 else "jmp", "%#x" % target, "%#x" % image.starts[owner]))
    return sorted(rows)


def function_rows(image, hits):
    rows = []
    for entry in (RATE, BSEARCH):
        start, end = image.exact_fde(entry)
        for row in decode_range(image, start, end):
            rows.append(("%#x" % entry, "%#x" % row.va, row.size, row.op, hits.get(row.va, 0)))
    return rows


def analyse(count=12000, mutate=True, mutant_cases=3000):
    image = load_image()
    k = constant_bits(image)
    harness = Harness(image)
    cases = named_cases() + random_cases(count)
    reached = collections.Counter()
    stats, caught, sample = check_stream(harness, cases, k, VARIANTS, keep=3, hits=reached)
    result = {"image": image, "k": k, "stats": stats, "caught": caught, "sample": sample, "reached": reached, "cases": len(cases)}
    result["structural"] = structural_controls(image, harness, k, cases)
    result["mutants"] = []
    if mutate:
        picked = cases[:len(named_cases())] + cases[len(named_cases())::max(1, count // mutant_cases)]
        result["mutants"] = run_mutants(image, mutants_of(image, reached), picked, k)
    return result


def render(result):
    image, k, stats = result["image"], result["k"], result["stats"]
    files = {}

    def tsv(name, header, rows):
        files[name] = "\n".join(["\t".join(header)] + ["\t".join(str(x) for x in row) for row in rows]) + "\n"

    tsv("constants.tsv", ("address", "role", "bytes", "raw", "double", "referenced_by"), constant_rows(image, k))
    tsv("owner-fields.tsv", ("displacement", "accesses"), layout_rows(image))
    tsv("pointer-slots.tsv", ("slot", "addend", "section"), slot_rows(image))
    tsv("direct-callers.tsv", ("site", "kind", "target", "owner"), direct_callers(image, (RATE, BSEARCH, FIND, HASH)))
    tsv("function-rows.tsv", ("function", "address", "size", "op", "cases_reaching"), function_rows(image, result["reached"]))
    tsv("outcomes.tsv", ("store", "outcome", "cases"), [(s, o, n) for (s, o), n in sorted(stats["kinds"].items())])
    tsv("cases-sample.tsv", ("index", "name", "store", "key", "samples", "outcome", "bits", "distinct_insns", "digest"), result["sample"])
    tsv("variants.tsv", ("deviation", "cases_refused", "first_refusing_case"),
        [(name, n, "" if first is None else first) for name, (n, first) in sorted(result["caught"].items())])
    tsv("structural-controls.tsv", ("control", "detected", "how"), [(n, int(d), h) for n, d, h in result["structural"]])
    tsv("mutants.tsv", ("address", "kind", "edited_byte_at", "old", "new", "killed", "first_case"),
        [("%#x" % va, kind, "%#x" % at, old, new, int(killed), first) for va, kind, at, old, new, killed, first in result["mutants"]])
    controls = len(result["caught"]) + len(result["structural"])
    detected = sum(1 for n, first in result["caught"].values() if n) + sum(1 for _, d, _ in result["structural"] if d)
    killed = sum(1 for row in result["mutants"] if row[5])
    evidence = {
        "binary_sha256": SHA256, "function": "%#x" % RATE, "helpers": {"binary_search": "%#x" % BSEARCH, "hash": "%#x" % HASH, "probe": "%#x" % FIND},
        "cases": stats["cases"], "mismatches": stats["mismatches"], "first_mismatch": stats["first_mismatch"],
        "instructions_reached": len(result["reached"]), "mutants": len(result["mutants"]), "mutants_killed": killed,
    }
    files["evidence.json"] = json.dumps(evidence, indent=1, sort_keys=True, default=str) + "\n"
    files["measure.json"] = json.dumps({"cases": stats["cases"], "negative_controls": controls, "negative_detected": detected,
                                        "mismatches": stats["mismatches"], "mutants": len(result["mutants"]), "mutants_killed": killed},
                                       indent=1, sort_keys=True) + "\n"
    return files


def main(argv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument("--out", required=True)
    parser.add_argument("--cases", type=int, default=12000)
    parser.add_argument("--no-mutants", action="store_true")
    args = parser.parse_args(argv)
    result = analyse(args.cases, not args.no_mutants)
    out = pathlib.Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    files = render(result)
    for name, text in files.items():
        (out / name).write_text(text)
    print(files["measure.json"], end="")
    return 0 if result["stats"]["mismatches"] == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
