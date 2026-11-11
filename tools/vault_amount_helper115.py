#!/usr/bin/env python3
"""Reconstruct the node #115 vault amount helper 0x44a9430 from the ELF bytes and prove it against a written rule list.

The body takes a context of three object pointers and a 20 byte key. It looks the key up in a first index map and turns the cell into a
signed base amount, looks the key up in a second map whose value is a keyed store (a VecDeque or a B-tree, chosen by a niche word) and
reads the entry stored under key 0, then looks the key up in a third keyed store (a VecDeque of 40 byte entries or a B-tree key set)
and, when that store holds key 0, adds an extra term. The sum of the store entry and the extra term saturates at 2^64-1, is divided by
100 through the multiply-shift constant 0x28f5c28f5c28f5c3 and is added to the base with signed saturation at 2^63-1. The real bytes of
the body and of the two deque searches 0x45584b0 and 0x455b7b0 run in a small x86-64 evaluator; the map lookups, the base conversion, the
extra term and the lazy default initialisers are recording stubs. A separately written rule list predicts every result and every call
log, 30 named wrong readings must be refused, and every reached condition, immediate and field displacement of the subject code is edited.
No objdump or readelf output is parsed and the binary is never executed. Standard library only.

    python3 tools/vault_amount_helper115.py --out <dir>
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
        elif op in ("ror", "rol"):
            bits = 8 * width
            count = self.get(row.b, 1) & (bits - 1)
            value = self.get(row.a, width)
            if op == "rol":
                count = -count & (bits - 1)
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




class Arena:
    def __init__(self, memory):
        self.memory, self.top = memory, 0

    def alloc(self, size):
        at = self.top
        self.top = (self.top + size + 15) & ~15
        if self.top > HEAP_BASE + USED:
            raise Halt("arena exhausted")
        return at


def lcg(seed):
    state = seed & MASK[8]
    while True:
        state = (state * 6364136223846793005 + 1442695040888963407) & MASK[8]
        yield state >> 11


def hexbits(value):
    return "0x%016x" % value


# --- subject: the vault amount helper and the code it runs -------------------------------------------------------------------

FEE = 0x44A9430
DEQUE32 = 0x45584B0
DEQUE40 = 0x455B7B0
MAP1 = 0x4716BE0            # first index map lookup (self + 0x60)
MAP2 = 0x4716CC0            # second index map lookup (second object + 0x370)
HASHER = 0x4717440          # SipHash-1-3 of the 20 key bytes under the map hasher words
SIPWRITE = 0x45927A0        # SipHasher13::write, called by the hasher
PROBE1 = 0x3EE6740          # raw table probe of the first map
PROBE2 = 0x3EE69C0          # raw table probe of the second map
EXTRA = 0x3694920           # extra term of the third store
SLOT_BASE = 0x64E6D20       # base amount conversion
SLOT_MAP3 = 0x64E6498       # third store lookup
SLOT_OVERFLOW = 0x64E4EA8   # checked-arithmetic event, returns
SLOT_INIT = 0x64DF9F0       # lazy initialiser, returns
FLAG1, FLAG2 = 0x64FDAF8, 0x64FD9A8
DEFAULT1, DEFAULT2 = 0x64FDA80, 0x64FD958
SEARCH_KEY = 0x459348
LOC_SUM, LOC_TOTAL = 0x6487460, 0x648BA50
MAGIC = 0x28F5C28F5C28F5C3
NICHE = 1 << 63
I64_MAX = (1 << 63) - 1

# heap layout of the harness
CTX = HEAP_BASE + 0x1000
SELF = HEAP_BASE + 0x1100
OBJ2 = HEAP_BASE + 0x1500
OBJ3 = HEAP_BASE + 0x1900
KEYBUF = HEAP_BASE + 0x1A00
ARENA = HEAP_BASE + 0x2000
USED = 0x12000
SELF_SIZE = 0x400
SLOT_BOUNDS = 0x64DF620     # slice index panic
MARK_BASE = 0x7700000000
FUNCTIONS = (FEE, DEQUE32, DEQUE40, MAP1, MAP2, HASHER, SIPWRITE)
MAP_STRIDE = {MAP1: 0x98, MAP2: 0x70}
MAP_KEY_AT = {MAP1: 0x80, MAP2: 0x58}
MAP_BASE = {MAP1: SELF + 0x60, MAP2: OBJ2 + 0x370}
MAP_NAME = {MAP1: "map1", MAP2: "map2"}
HASH_WORDS = {MAP1: (0x0123456789ABCDEF, 0x0FEDCBA987654321), MAP2: (0x1111222233334444, 0x5555666677778888)}


def rotl(value, count):
    return (value << count | value >> (64 - count)) & MASK[8]


def siphash13(k0, k1, data):
    """SipHash-1-3 over a byte string, written from the published round function (one compression round, three finalisation rounds)."""
    v = [k0 ^ 0x736F6D6570736575, k1 ^ 0x646F72616E646F6D, k0 ^ 0x6C7967656E657261, k1 ^ 0x7465646279746573]

    def rounds(count):
        for _ in range(count):
            v[0] = (v[0] + v[1]) & MASK[8]
            v[1] = rotl(v[1], 13) ^ v[0]
            v[0] = rotl(v[0], 32)
            v[2] = (v[2] + v[3]) & MASK[8]
            v[3] = rotl(v[3], 16) ^ v[2]
            v[0] = (v[0] + v[3]) & MASK[8]
            v[3] = rotl(v[3], 21) ^ v[0]
            v[2] = (v[2] + v[1]) & MASK[8]
            v[1] = rotl(v[1], 17) ^ v[2]
            v[2] = rotl(v[2], 32)

    whole = len(data) // 8 * 8
    for at in range(0, whole, 8):
        word = int.from_bytes(data[at:at + 8], "little")
        v[3] ^= word
        rounds(1)
        v[0] ^= word
    last = int.from_bytes(data[whole:], "little") | (len(data) & 0xFF) << 56
    v[3] ^= last
    rounds(1)
    v[0] ^= last
    v[2] ^= 0xFF
    rounds(3)
    return v[0] ^ v[1] ^ v[2] ^ v[3]


def signed(value):
    return value - (1 << 64) if value >> 63 else value


# --- case model -----------------------------------------------------------------------------------------------------------------

class Tree:
    """A B-tree node: keys, first-word values (store 1 only) and children; every leaf sits at the same depth."""

    def __init__(self, keys, vals=None, kids=None):
        self.keys, self.vals, self.kids = keys, vals or [0] * len(keys), kids


class Store:
    """kind 'none' is a pointer-less lookup miss; 'deque' has cap/head/entries; 'tree' has a root and a height."""

    def __init__(self, kind, entries=(), cap=0, head=0, root=None, height=0):
        self.kind, self.entries, self.cap, self.head, self.root, self.height = kind, list(entries), cap, head, root, height


class Case:
    def __init__(self, name, key, cell, default_cell, flag1, store2, default2, flag2, store3, flag3_unused, extra_flag, extra, m1=(1, 0), m2=(1, 0)):
        self.name, self.key = name, key
        self.m1, self.m2 = m1, m2          # (entries in the index map, 1 = the probe answers with an out-of-range index)
        self.cell, self.default_cell, self.flag1 = cell, default_cell, flag1
        self.store2, self.default2, self.flag2 = store2, default2, flag2
        self.store3, self.extra_flag, self.extra = store3, extra_flag, extra


# --- evaluator harness ----------------------------------------------------------------------------------------------------------

class Harness:
    def __init__(self, image, patches=None):
        self.image = image
        machine = Machine(image, patches)
        self.machine = machine
        machine.real = frozenset({DEQUE32, DEQUE40, MAP1, MAP2, HASHER, SIPWRITE})
        machine.calls[PROBE1] = self.on_probe(MAP1)
        machine.calls[PROBE2] = self.on_probe(MAP2)
        machine.calls[EXTRA] = self.on_extra
        for slot, hook in ((SLOT_BASE, self.on_base), (SLOT_MAP3, self.on_map3), (SLOT_OVERFLOW, self.on_overflow), (SLOT_INIT, self.on_init),
                           (SLOT_BOUNDS, self.on_bounds)):
            machine.memory.statics[slot] = MARK_BASE + slot
            machine.slots[MARK_BASE + slot] = hook
        self.case, self.log = None, []

    def expect(self, condition, text):
        if not condition:
            raise Halt("stub check failed: " + text)

    def key_ok(self, address):
        self.expect(self.machine.memory.bytes_at(address, 20) == self.case.key, "key bytes")

    # stubs
    def on_probe(self, which):
        def hook(machine):
            regs = machine.regs
            mem = machine.memory
            entries, size, bad, present, position = self.maps[which]
            self.expect(regs[RDI] == MAP_BASE[which] + 0x18 and regs[RSI] == siphash13(*HASH_WORDS[which], self.case.key), "probe table and hash")
            self.key_ok(mem.read(regs[RDX], 8))
            self.expect(mem.read(regs[RDX] + 8, 8) == entries and mem.read(regs[RDX] + 16, 8) == size, "probe closure")
            self.log.append(("probe", MAP_NAME[which], regs[RSI]))
            if not present:
                regs[RAX] = 0
                return
            cell = self.probe_cell[which]
            regs[RAX] = cell + 8
        return hook

    def on_bounds(self, machine):
        self.log.append(("bounds", machine.regs[RDI], machine.regs[RSI]))
        raise Panicked("bounds")

    def on_base(self, machine):
        regs = machine.regs
        mem = machine.memory
        self.expect(regs[RSI] in (self.cell_at, DEFAULT1), "base cell")
        self.expect(regs[RDX] == 1 and regs[RCX] == 1 and regs[R9] == SELF + 0x148, "base arguments")
        self.expect(mem.read(regs[RSP], 8) == SELF, "base self argument")
        value = mem.read(regs[RSI], 8)
        self.log.append(("base", "cell" if regs[RSI] == self.cell_at else "default", value))
        mem.write(regs[RDI], 8, value)

    def on_map3(self, machine):
        regs = machine.regs
        self.expect(regs[RDI] == self.third_map, "map3 object")
        self.key_ok(regs[RSI])
        self.log.append(("map3", self.case.key.hex()))
        regs[RAX] = self.store3_at

    def on_extra(self, machine):
        regs = machine.regs
        self.expect(regs[RSI] == self.store3_at and regs[RDX] == 0 and regs[RCX] == 0 and regs[R8] == self.third_map + 0x58, "extra arguments")
        self.log.append(("extra", self.case.extra_flag, self.case.extra))
        machine.memory.write(regs[RDI], 8, self.case.extra_flag | 0xAB00)
        machine.memory.write(regs[RDI] + 8, 8, self.case.extra)

    def on_overflow(self, machine):
        regs = machine.regs
        self.expect(regs[RDI] == 0, "overflow first argument")
        self.log.append(("overflow", regs[RSI]))

    def on_init(self, machine):
        regs = machine.regs
        flag = regs[RDI]
        self.expect(flag in (FLAG1, FLAG2) and regs[RSI] == 1, "init arguments")
        mem = machine.memory
        outer = mem.read(regs[RDX], 8)
        self.expect(mem.read(outer, 8) == (DEFAULT1 if flag == FLAG1 else DEFAULT2), "init payload")
        self.expect((regs[RCX], regs[R8]) == ((0x648C498, 0x648C4C0) if flag == FLAG1 else (0x6476B20, 0x6476B48)), "init tables")
        statics = machine.memory.statics
        self.log.append(("init", flag))
        statics[flag] = 0
        if flag == FLAG2:
            self.install_default_store(machine.memory)

    # memory construction
    def install_default_store(self, memory):
        words = self.default_words
        for index, value in enumerate(words):
            memory.statics[DEFAULT2 + 8 * index] = value

    def build_tree(self, arena, node, store_one, depth):
        mem = self.machine.memory
        size = 0x1D0 if store_one else 0x228
        at = arena.alloc(size)
        mem.put_bytes(at, bytes(size * [0xC3]))
        mem.write(at, 8, 0)
        mem.put_bytes(at + (8 if store_one else 0x168), bytes(0x58))
        for index, key in enumerate(node.keys):
            if store_one:
                mem.write(at + 8 + 8 * index, 8, key)
                mem.write(at + 0x60 + 24 * index, 8, node.vals[index])
            else:
                mem.write(at + 0x168 + 8 * index, 8, key)
        mem.write(at + (0x16A if store_one else 0x1C2), 2, len(node.keys))
        if node.kids is not None:
            for index, kid in enumerate(node.kids):
                mem.write(at + (0x170 if store_one else 0x1C8) + 8 * index, 8, self.build_tree(arena, kid, store_one, depth - 1))
        return at

    def build_store(self, arena, store, entry_size, store_one):
        """Write the four header words in the arena and return (words, address of header or 0)."""
        mem = self.machine.memory
        if store.kind == "none":
            return [0, 0, 0, 0]
        if store.kind == "deque":
            ring = arena.alloc(entry_size * max(1, store.cap))
            mem.put_bytes(ring, bytes(entry_size * max(1, store.cap) * [0x9D]))
            for index, (key, value) in enumerate(store.entries):
                at = ring + entry_size * ((store.head + index) % store.cap)
                mem.write(at, 8, key)
                mem.write(at + 8, 8, value)
                for extra in range(16, entry_size, 8):
                    mem.write(at + extra, 8, 0x4545000000000000 + index)
            return [store.cap, ring, store.head, len(store.entries)]
        root = self.build_tree(arena, store.root, store_one, store.height) if store.root is not None else 0
        return [NICHE, root, store.height, 7]

    @staticmethod
    def decoy_lane(index):
        """The key byte in which decoy entry `index` differs from the looked-up key."""
        return (index * 7) % 20

    def build_map(self, arena, which, shape, present, words):
        """An index map of `size` entries: key bytes at the entry key offset, the looked-up words at the entry start."""
        mem = self.machine.memory
        size, bad = shape
        stride, key_at = MAP_STRIDE[which], MAP_KEY_AT[which]
        entries = arena.alloc(stride * max(1, size))
        position = self.case.key[0] % size if size else 0
        for index in range(size):
            at = entries + stride * index
            for offset in range(0, stride, 8):
                mem.write(at + offset, 8, 0x5A5A000000000000 + (index << 16) + offset)
            decoy = bytearray(self.case.key)
            decoy[self.decoy_lane(index)] ^= 1 + index
            mem.put_bytes(at + key_at, bytes(self.case.key) if present and index == position else bytes(decoy))
            if present and index == position:
                for offset, value in enumerate(words):
                    mem.write(at + 8 * offset, 8, value)
        base_at = MAP_BASE[which]
        mem.write(base_at + 8, 8, entries)
        mem.write(base_at + 0x10, 8, size)
        mem.write(base_at + 0x18, 8, 0x3333000000000000 + which)
        mem.write(base_at + 0x38, 8, HASH_WORDS[which][0])
        mem.write(base_at + 0x40, 8, HASH_WORDS[which][1])
        self.maps[which] = (entries, size, bad, present, position)
        self.probe_cell[which] = arena.alloc(16)
        mem.write(self.probe_cell[which], 8, size + 3 if bad else position)
        return entries + stride * position

    def fresh(self, case):
        machine = self.machine
        mem = machine.memory
        mem.reset(USED)
        machine.xmm = [POISON | POISON << 64] * 16
        mem.statics.clear()
        for slot, hook in ((SLOT_BASE, 0), (SLOT_MAP3, 0), (SLOT_OVERFLOW, 0), (SLOT_INIT, 0)):
            mem.statics[slot] = MARK_BASE + slot
        self.case, self.log, self.maps, self.hashes, self.probe_cell = case, [], {}, {}, {}
        arena = Arena(mem)
        arena.top = ARENA
        for at, size in ((SELF, SELF_SIZE), (OBJ2, 0x400), (OBJ3, 0x100)):
            mem.put_bytes(at, bytes((0x37 + 3 * i) & 0xFF for i in range(size)))
        mem.write(CTX, 8, SELF)
        mem.write(CTX + 8, 8, OBJ2)
        mem.write(CTX + 0x10, 8, OBJ3)
        self.third_map = OBJ3
        mem.put_bytes(KEYBUF, case.key)
        mem.write(KEYBUF + 20, 4, 0xDEADBEEF)
        mem.statics[SLOT_BOUNDS] = MARK_BASE + SLOT_BOUNDS
        mem.statics[FLAG1] = case.flag1
        mem.statics[FLAG2] = case.flag2
        mem.statics[DEFAULT1] = case.default_cell
        words2 = self.build_store(arena, case.store2, 32, True)
        self.cell_at = self.build_map(arena, MAP1, case.m1, case.cell is not None, [case.cell or 0])
        self.store2_at = self.build_map(arena, MAP2, case.m2, case.store2.kind != "none", words2)
        self.default_words = self.build_store(arena, case.default2, 32, True)
        for index, value in enumerate(self.default_words if not case.flag2 else [0, 0, 0, 0]):
            mem.statics[DEFAULT2 + 8 * index] = value
        words3 = self.build_store(arena, case.store3, 40, False)
        self.store3_at = arena.alloc(32)
        for index, value in enumerate(words3):
            mem.write(self.store3_at + 8 * index, 8, value)
        return bytes(mem.heap[:USED])

    def run(self, case):
        before = self.fresh(case)
        try:
            outcome = ("ret", self.machine.run(FEE, {RDI: CTX, RSI: KEYBUF}))
        except Panicked as panic:
            outcome = ("panic", str(panic))
        if bytes(self.machine.memory.heap[:USED]) != before:
            raise Halt("the body changed the heap")
        return outcome, self.log


# --- the rule list ---------------------------------------------------------------------------------------------------------------

def deque_find(store, flags):
    """Index of key 0 by the VecDeque::binary_search rule: the back slice is consulted only when its first key equals or precedes the
    target, otherwise the front slice is searched by the branch-free halving loop; None when the search reports Err."""
    entries = store.entries
    if "deque_last_entry" in flags:
        return len(entries) - 1 if entries and entries[-1][0] == 0 else None
    front_len = min(len(entries), store.cap - store.head)
    front, back = entries[:front_len], entries[front_len:]
    if back and back[0][0] == 0:
        return front_len
    if not front:
        return None
    start, size = 0, len(front)
    while size > 1:
        half = size // 2
        if not front[start + half][0] > 0:
            start += half
        size -= half
    return start if front[start][0] == 0 else None


def tree_find(store, store_one, flags):
    """Walk the tree by the written rule: at each node compare key 0 against the keys in order."""
    node = store.root
    if node is None:
        return None
    for level in range(store.height + 1):
        if "tree_no_descend" in flags and level:
            return None
        child = len(node.keys)
        for index, key in enumerate(node.keys):
            if key == 0:
                if "tree_any_key" in flags or True:
                    return node.vals[index] if store_one else True
            if 0 < key:
                child = index
                break
        if node.kids is None:
            return None
        node = node.kids[child]
    return None


def lookup_rows(which, shape, present, key):
    """Events of one index map lookup: no table work below two entries, otherwise hash then probe; a bad index ends in the bounds panic."""
    size, bad = shape
    if size < 2:
        return [], False
    value = siphash13(HASH_WORDS[which][0], HASH_WORDS[which][1], key)
    rows = [("probe", MAP_NAME[which], value)]
    if present and bad:
        rows.append(("bounds", size + 3, size))
        return rows, True
    return rows, False


def spec(case, flags=frozenset()):
    log = []
    rows1, dead1 = lookup_rows(MAP1, case.m1, case.cell is not None, case.key)
    log.extend(rows1)
    if dead1:
        return ("panic", "bounds"), log
    if case.flag1 and "init_skipped" not in flags:
        log.append(("init", FLAG1))
    if case.cell is not None or "cell_default_ignored" in flags:
        cell = case.cell if case.cell is not None else 0
        log.append(("base", "cell" if case.cell is not None else "default", cell))
        if case.cell is None:
            cell = 0
    else:
        cell = case.default_cell
        log.append(("base", "default", cell))
    base_value = signed(cell)
    if "base_unsigned" in flags:
        base_value = cell
    rows2, dead2 = lookup_rows(MAP2, case.m2, case.store2.kind != "none", case.key)
    log.extend(rows2)
    if dead2:
        return ("panic", "bounds"), log
    if case.flag2 and "init_skipped" not in flags:
        log.append(("init", FLAG2))
    store2 = case.store2 if case.store2.kind != "none" or "default_store_ignored" in flags else case.default2
    if case.store2.kind == "none" and "default_store_ignored" in flags:
        store2 = Store("deque")
    held = 0
    if store2.kind == "deque":
        index = deque_find(store2, flags)
        if index is not None:
            entry = store2.entries[index]
            held = entry[1] if "entry_key_as_value" not in flags else entry[0]
    elif store2.kind == "tree":
        found = tree_find(store2, True, flags)
        held = found if found is not None else 0
    if "held_ignored" in flags:
        held = 0
    log.append(("map3", case.key.hex()))
    present = False
    store3 = case.store3
    if store3.kind == "deque":
        present = deque_find(store3, flags) is not None
    elif store3.kind == "tree":
        present = tree_find(store3, False, flags) is not None
    if "present_inverted" in flags:
        present = not present
    extra = 0
    if present or "extra_when_absent" in flags:
        log.append(("extra", case.extra_flag, case.extra))
        bit = case.extra_flag >> 1 & 1 if "extra_flag_bit1" in flags else case.extra_flag & 1
        if "extra_flag_any" in flags:
            bit = int(case.extra_flag != 0)
        extra = case.extra if not bit else 0
        if "extra_ignored" in flags:
            extra = 0
        if "extra_doubled" in flags:
            extra *= 2
    total = held + extra
    if total >> 64:
        if "overflow_not_logged" not in flags:
            log.append(("overflow", LOC_SUM))
        total = total & MASK[8] if "u64_wraps" in flags else MASK[8]
    if "no_division" in flags:
        quotient = total
    elif "divide_128" in flags:
        quotient = total >> 7
    elif "ceil_division" in flags:
        quotient = -(-total // 100)
    elif "round_half_up" in flags:
        quotient = (total + 50) // 100
    else:
        quotient = total // 100
    result = base_value + quotient
    if result > I64_MAX:
        if "overflow_not_logged" not in flags:
            log.append(("overflow", LOC_TOTAL))
        result = (result & MASK[8]) if "i64_wraps" in flags else (I64_MAX + 1 if "i64_saturates_min" in flags else I64_MAX)
    elif result < -(1 << 63):
        result &= MASK[8]
    if "swap_lookup_order" in flags:
        # the third lookup before the second: only the log order differs
        a = [i for i, row in enumerate(log) if row[0] == "probe" and row[1] == "map2"]
        b = [i for i, row in enumerate(log) if row[0] == "map3"]
        if a and b:
            log[a[0]], log[b[0]] = log[b[0]], log[a[0]]
    return ("ret", result & MASK[8]), log


VARIANTS = (
    "no_division", "divide_128", "ceil_division", "round_half_up", "u64_wraps", "i64_wraps", "i64_saturates_min", "base_unsigned",
    "extra_when_absent", "extra_ignored", "extra_doubled", "extra_flag_bit1", "extra_flag_any", "present_inverted",
    "held_ignored", "cell_default_ignored", "default_store_ignored", "deque_last_entry", "entry_key_as_value", "tree_no_descend",
    "overflow_not_logged", "init_skipped", "swap_lookup_order",
)


# --- case generation -------------------------------------------------------------------------------------------------------------

EDGE_WORDS = (0, 1, 99, 100, 101, 5000, (1 << 63) - 1, 1 << 63, (1 << 64) - 1, (1 << 64) - 100, (1 << 64) - 101, 1 << 62, 0x28F5C28F5C28F5C3)
EDGE_BASES = (0, 1, 7, I64_MAX, I64_MAX - 1, I64_MAX - 100, 1 << 63, (1 << 64) - 1, (1 << 63) + 5, 123456789012345)


def draw_word(stream):
    kind = next(stream) % 6
    if kind <= 1:
        return EDGE_WORDS[next(stream) % len(EDGE_WORDS)]
    if kind == 2:
        return next(stream) % 10000
    if kind == 3:
        return (1 << 64) - 1 - next(stream) % 1000
    return (next(stream) << 20 ^ next(stream)) & MASK[8]


def draw_base(stream):
    kind = next(stream) % 4
    if kind <= 1:
        return EDGE_BASES[next(stream) % len(EDGE_BASES)]
    if kind == 2:
        return next(stream) % 100000
    return (next(stream) << 20 ^ next(stream)) & MASK[8]


def draw_tree(stream, height, store_one, zero_first, is_root=True):
    count = 1 + next(stream) % (4 if height == 0 else 3 if height == 1 else 2) if not (height == 0 and is_root and next(stream) % 6 == 0) else 0
    keys = sorted({1 + next(stream) % (1 << 40) for _ in range(count)})
    if zero_first and keys and next(stream) % 4:
        keys[0] = 0
    vals = [draw_word(stream) for _ in keys]
    kids = None
    if height:
        kids = [draw_tree(stream, height - 1, store_one, False, False) for _ in range(len(keys) + 1)]
    return Tree(keys, vals, kids)


def draw_store(stream, store_one, force=None):
    kind = force or ("none", "deque", "deque", "tree", "tree")[next(stream) % 5]
    if kind == "none":
        return Store("none")
    if kind == "deque":
        count = (0, 1, 2, 3, 5, 9)[next(stream) % 6]
        zero = count and next(stream) % 3
        keys = [next(stream) % 6 if next(stream) % 3 else 1 + next(stream) % 1000 for _ in range(count)]
        if next(stream) % 2:
            keys.sort()
        if zero and keys:
            keys[next(stream) % len(keys)] = 0
        entries = [(key, draw_word(stream)) for key in keys]
        cap = max(len(entries), 1) + next(stream) % 4
        return Store("deque", entries, cap, next(stream) % cap)
    height = next(stream) % 4
    return Store("tree", [], 0, 0, draw_tree(stream, height, store_one, next(stream) % 3 != 0), height)


def draw_case(stream, index):
    key = bytes(next(stream) & 0xFF for _ in range(20))
    cell = draw_base(stream) if next(stream) % 3 else None
    flag1 = 3 if next(stream) % 4 == 0 else 0
    flag2 = 3 if next(stream) % 4 == 0 else 0
    default2 = draw_store(stream, True, "deque" if next(stream) % 2 else "none")
    if default2.kind == "none":
        default2 = Store("deque", [], 1, 0)
    store2 = draw_store(stream, True)
    shapes = []
    for present in (cell is not None, store2.kind != "none"):
        size = max((0, 1, 2, 3, 5)[next(stream) % 5], 1 if present else 0)
        shapes.append((size, int(present and size > 1 and next(stream) % 14 == 0)))
    return Case("random %d" % index, key, cell, draw_base(stream), flag1, store2, default2, flag2,
                draw_store(stream, False, ("deque", "tree")[next(stream) % 2]), 0, next(stream) % 4, draw_word(stream), shapes[0], shapes[1])


def named_cases():
    key = bytes(range(1, 21))
    empty = Store("deque", [], 1, 0)
    zero_entry = lambda value: Store("deque", [(0, value), (4, 9)], 3, 2)
    present = Store("deque", [(0, 1)], 1, 0)
    absent = Store("deque", [(5, 1)], 1, 0)
    out = []

    def add(name, **kw):
        fields = dict(cell=100, default_cell=555, flag1=0, store2=empty, default2=empty, flag2=0, store3=absent, extra_flag=0, extra=0,
                      m1=(1, 0), m2=(1, 0))
        fields.update(kw)
        out.append(Case(name, key, fields["cell"], fields["default_cell"], fields["flag1"], fields["store2"], fields["default2"],
                        fields["flag2"], fields["store3"], 0, fields["extra_flag"], fields["extra"], fields["m1"], fields["m2"]))

    add("base only")
    add("cell missing uses default", cell=None)
    add("held value over 100", store2=zero_entry(1234567))
    add("held value with extra", store2=zero_entry(1000), store3=present, extra=2000)
    add("extra flag none", store2=zero_entry(1000), store3=present, extra=2000, extra_flag=1)
    add("extra flag bit1 only", store2=zero_entry(1000), store3=present, extra=2000, extra_flag=2)
    add("sum overflow", store2=zero_entry((1 << 64) - 1), store3=present, extra=5)
    add("sum max", store2=zero_entry((1 << 64) - 1))
    add("total overflow", cell=I64_MAX, store2=zero_entry(1000))
    add("total just fits", cell=I64_MAX - 10, store2=zero_entry(1000))
    add("negative base", cell=(1 << 64) - 5, store2=zero_entry(1000))
    add("lazy flag 1", flag1=3)
    add("lazy flag 2 default store", flag2=3, store2=Store("none"), default2=zero_entry(777))
    add("lazy flag 2 default with store present", flag2=3, store2=zero_entry(300), default2=zero_entry(777))
    add("store2 missing default holds value", store2=Store("none"), default2=zero_entry(9000))
    add("deque wraps", store2=Store("deque", [(0, 4000), (3, 1)], 3, 2))
    add("deque head last slot", store2=Store("deque", [(0, 4000), (3, 1), (8, 2)], 3, 2))
    # deque shapes for the second store: where key 0 sits relative to the wrap point decides which slice the search consults
    add("deque key 0 first, contiguous", store2=Store("deque", [(0, 700), (2, 1), (5, 2), (9, 3)], 6, 0))
    add("deque key 0 first, head inside the ring", store2=Store("deque", [(0, 700), (2, 1), (5, 2), (9, 3)], 6, 2))
    add("deque key 0 first, wraps after one entry", store2=Store("deque", [(0, 700), (2, 1), (5, 2), (9, 3)], 4, 3))
    add("deque key 0 only in the back slice", store2=Store("deque", [(3, 1), (4, 2), (0, 800), (6, 3)], 4, 2))
    add("deque key 0 in the middle of the front slice", store2=Store("deque", [(4, 1), (0, 900), (6, 2)], 5, 1))
    add("deque keys all above 0", store2=Store("deque", [(1, 1), (2, 2), (3, 3), (4, 4), (5, 5)], 5, 3))
    add("deque with duplicate zero keys", store2=Store("deque", [(0, 11), (0, 22), (0, 33), (0, 44), (0, 55)], 7, 4))
    add("deque full ring, head at zero", store2=Store("deque", [(1, 1), (0, 600), (2, 2)], 3, 0))
    add("deque zero length", store2=Store("deque", [], 4, 3))
    add("deque store3 key 0 in the back slice", store3=Store("deque", [(3, 1), (0, 1)], 2, 1), extra=1500)
    add("deque store3 duplicate zeros", store3=Store("deque", [(0, 1), (0, 1), (0, 1)], 4, 2), extra=1500)
    add("deque store3 all above zero", store3=Store("deque", [(7, 1), (8, 1), (9, 1)], 4, 1), extra=1500)
    add("map1 empty", cell=None, m1=(0, 0))
    add("map1 one decoy entry", cell=None, m1=(1, 0))
    add("map1 three entries hit", m1=(3, 0))
    add("map1 five entries hit", m1=(5, 0))
    add("map1 five entries miss", cell=None, m1=(5, 0))
    add("map1 probe answers out of range", m1=(2, 1))
    add("map1 probe miss ignores the range flag", cell=None, m1=(4, 1))
    add("map2 empty", store2=Store("none"), default2=zero_entry(321), m2=(0, 0))
    add("map2 two entries hit", store2=zero_entry(5000), m2=(2, 0))
    add("map2 five entries miss", store2=Store("none"), default2=zero_entry(321), m2=(5, 0))
    add("map2 probe answers out of range", store2=zero_entry(5000), m2=(3, 1))
    add("map1 and map2 hash apart", store2=zero_entry(5000), m1=(2, 0), m2=(2, 0))
    add("tree leaf holds key 0", store2=Store("tree", [], 0, 0, Tree([0, 5], [800, 1]), 0), store3=Store("tree", [], 0, 0, Tree([0]), 0), extra=3000)
    add("tree key 0 only in a deeper node", store2=Store("tree", [], 0, 0, Tree([9], [1], [Tree([0], [6000]), Tree([20], [2])]), 1),
        store3=Store("tree", [], 0, 0, Tree([9], None, [Tree([0]), Tree([20])]), 1), extra=400)
    add("tree without key 0", store2=Store("tree", [], 0, 0, Tree([2], [8], [Tree([3], [4]), Tree([9], [5])]), 1),
        store3=Store("tree", [], 0, 0, Tree([2], None, [Tree([3]), Tree([9])]), 1), extra=400)
    add("empty tree root", store2=Store("tree", [], 0, 0, None, 0), store3=Store("tree", [], 0, 0, None, 0), extra=400)
    add("three-level tree", store2=Store("tree", [], 0, 0, Tree([7], [1], [Tree([8], [2], [Tree([0], [12345]), Tree([9], [3])]), Tree([10], [4], [Tree([11], [5]), Tree([12], [6])])]), 2),
        store3=Store("tree", [], 0, 0, Tree([7], None, [Tree([8], None, [Tree([0]), Tree([9])]), Tree([10], None, [Tree([11]), Tree([12])])]), 2), extra=1)
    add("store3 deque with key 0 first and wrapped", store3=Store("deque", [(0, 1), (1, 1)], 2, 1), extra=9000)
    return out


def random_cases(count, seed=0xFEED5EED):
    stream = lcg(seed)
    return (draw_case(stream, index) for index in range(count))


# --- run and compare ----------------------------------------------------------------------------------------------------------

def run_case(harness, case):
    harness.machine.seen = set()
    try:
        return harness.run(case)
    except (Halt, EvidenceError, IndexError, KeyError, ValueError, OverflowError, struct.error) as problem:
        return ("halt", type(problem).__name__), []


def outcome_kind(case, expected):
    if expected[0][0] != "ret":
        return "panic"
    return "saturated" if any(row[0] == "overflow" for row in expected[1]) else "plain"


def check_stream(harness, cases, variants=(), keep=0, hits=None, kinds_out=None):
    stats = {"cases": 0, "mismatches": 0, "first_mismatch": None, "kinds": collections.Counter(), "stores": collections.Counter(),
             "magic": 0}
    caught = {name: [0, None] for name in variants}
    rows = []
    for index, case in enumerate(cases):
        got, log = run_case(harness, case)
        expected = spec(case)
        stats["cases"] += 1
        kind = outcome_kind(case, expected)
        stats["kinds"][(case.store2.kind, case.store3.kind, kind)] += 1
        if (got, log) != expected:
            stats["mismatches"] += 1
            if stats["first_mismatch"] is None:
                stats["first_mismatch"] = (index, case.name, got, expected[0])
        for name in variants:
            if spec(case, frozenset((name,))) != (got, log):
                caught[name][0] += 1
                if caught[name][1] is None:
                    caught[name][1] = index
        if hits is not None:
            hits.update(harness.machine.seen)
        if keep and index % keep == 0:
            rows.append((index, case.name, case.store2.kind, case.store3.kind, case.flag1, case.flag2, kind, got[1] if got[0] == "ret" else got[1],
                         len(harness.machine.seen), len(log)))
    return stats, caught, rows


# --- byte level controls --------------------------------------------------------------------------------------------------------

def mutants_of(image, reached):
    out = []
    for entry in FUNCTIONS:
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
                if operand and operand[0] == "m" and operand[1] is not None and 0x8 <= abs(operand[4]) < 0x200:
                    disp = operand[4]
                    packed = struct.pack("<i", disp) if abs(disp) >= 128 else struct.pack("<b", disp)
                    spot = bytes(data).find(packed)
                    if spot >= 0 and bytes(data).count(packed) == 1:
                        out.append((row.va, "displacement", row.va + spot, data[spot], data[spot] ^ 8))
    return out


def run_mutants(image, mutants, cases):
    rows = []
    for va, kind, at, old, new in mutants:
        harness = Harness(image, {at: new})
        harness.machine.step_limit = MUTANT_STEP_LIMIT
        killed, first = False, ""
        for index, case in enumerate(cases):
            got, log = run_case(harness, case)
            if (got, log) != spec(case):
                killed, first = True, "%d" % index
                break
        rows.append((va, kind, at, old, new, killed, first))
    return rows


def structural_controls(image, harness, cases):
    out = []

    def raises(name, thunk, *errors):
        try:
            thunk()
        except errors or (EvidenceError,) as problem:
            out.append((name, True, type(problem).__name__))
            return
        out.append((name, False, "no error"))

    raises("wrong image digest", lambda: load_image(BINARY, "0" * 64), EvidenceError)
    raises("mid-function address is not an FDE start", lambda: image.exact_fde(FEE + 1), EvidenceError)
    raises("address in a NOBITS section has no file bytes", lambda: image.offset(image.named[".bss"]["address"] + 8), EvidenceError)
    raises("decoder refuses a window that ends inside the body", lambda: decode_range(image, FEE, image.exact_fde(FEE)[1] - 1), EvidenceError)
    raises("truncated section table", lambda: Image(bytes(image.blob[:48])), Exception)
    def usable(case):
        got = spec(case)
        return (case.store2.kind == "deque" and case.store3.kind == "deque" and case.m1[0] > 1 and case.m2[0] > 1 and got[0][0] == "ret"
                and any(row[0] == "extra" for row in got[1]) and (deque_find(case.store2, ()) is not None)
                and case.store2.entries[deque_find(case.store2, ())][1] >= 1000)
    wide = next(case for case in cases if usable(case))
    for name, address in (("first map probe", PROBE1), ("second map probe", PROBE2), ("extra term", EXTRA)):
        stripped = Harness(image)
        del stripped.machine.calls[address]
        raises("%s without a model" % name, lambda: stripped.run(wide), Halt)
    saturating = next(case for case in cases if any(row[0] == "overflow" for row in spec(case)[1]))
    bounded = next(case for case in cases if spec(case)[0][0] == "panic")
    for name, address, subject in (("base conversion", SLOT_BASE, wide), ("third map lookup", SLOT_MAP3, wide), ("overflow event", SLOT_OVERFLOW, saturating),
                                   ("bounds panic", SLOT_BOUNDS, bounded), ("lazy initialiser", SLOT_INIT, next(case for case in cases if case.flag2))):
        stripped = Harness(image)
        del stripped.machine.slots[MARK_BASE + address]
        raises("%s without a model" % name, lambda: stripped.run(subject), Halt)
    realised = {DEQUE32, DEQUE40, MAP1, MAP2, HASHER, SIPWRITE}
    for name, address in (("32 byte deque search", DEQUE32), ("40 byte deque search", DEQUE40), ("first map lookup", MAP1),
                          ("second map lookup", MAP2), ("key hash", HASHER), ("hasher write", SIPWRITE)):
        plain = Harness(image)
        plain.machine.real = frozenset(realised - {address})
        raises("%s not run as real code" % name, lambda: plain.run(wide), Halt)
    for name, address in (("entry", FEE), ("32 byte deque search", DEQUE32), ("40 byte deque search", DEQUE40), ("key hash", HASHER), ("hasher write", SIPWRITE)):
        trapped = Harness(image, {address: 0xCC})
        raises("%s first byte replaced by int3" % name, lambda: trapped.run(wide), Halt)
    wrong_key = Case("wrong key", bytes(20), 5, 6, 0, Store("none"), Store("deque", [], 1, 0), 0, Store("deque", [], 1, 0), 0, 0, 0)
    bad_run = Harness(image)
    original = bad_run.key_ok
    bad_run.key_ok = lambda address: original(address + 1)
    raises("key pointer off by one is refused by the lookup model", lambda: bad_run.run(wrong_key), Halt)
    wrong_hash = Harness(image)
    original_probe = wrong_hash.machine.calls[PROBE1]
    wrong_hash.machine.calls[PROBE1] = lambda machine: (machine.regs.__setitem__(RSI, machine.regs[RSI] ^ 1), original_probe(machine))
    hashed = next(case for case in cases if case.m1[0] > 1 and spec(case)[0][0] == "ret")
    raises("flipped hash bit is refused by the probe model", lambda: wrong_hash.run(hashed), Halt)
    out.append(("tampered divisor constant", run_case(harness, wide) != spec(wide, frozenset({"divide_128"})), "mismatch"))
    for name, entry, at in (("division multiplier byte edited", FEE, 0x44A96AF), ("first map stride byte edited", MAP1, 0x4716C8C)):
        blob = bytearray(image.blob)
        blob[image.offset(at)] ^= 1
        edited = Image(bytes(blob))
        broken = [row[0] for row in fact_rows(edited) if not row[7]]
        out.append(("layout fact table notices: " + name, bool(broken), ";".join(broken)[:60]))
    return out


def magic_rows():
    """The shift-multiply-shift sequence computes (x >> 2) * M >> 66 with M = ceil(2^66 / 25).

    With e = 25 * M - 2^66 the product is y / 25 + y * e / (25 * 2^66) for y = x >> 2 < 2^62, so the floor is exact whenever e * 2^62 < 2^66,
    and (x >> 2) // 25 == x // 100 for every x. The boundary scan checks the same identity on explicit points."""
    error = 25 * MAGIC - (1 << 66)
    exact = error * (1 << 62) < (1 << 66) and MAGIC == -(-(1 << 66) // 25)
    points = set()
    for center in (0, 99, 100, 101, 199, 200, 10 ** 9, 10 ** 15, 1 << 62, (1 << 64) - 1, (1 << 64) - 100, (1 << 63) - 1):
        for delta in range(-40, 41):
            if 0 <= center + delta < (1 << 64):
                points.add(center + delta)
    mismatches = sum(1 for value in points if ((value >> 2) * MAGIC >> 64) >> 2 != value // 100)
    return [(error, int(exact), len(points), mismatches)]


# --- evidence tables --------------------------------------------------------------------------------------------------------------

def constant_rows(image):
    rows = []
    for va, name, size in ((SEARCH_KEY, "deque search key", 8), (FLAG1, "lazy state 1 (file bytes)", 8), (FLAG2, "lazy state 2 (file bytes)", 8),
                           (DEFAULT1, "default cell", 8), (DEFAULT2, "default store word 0", 8), (DEFAULT2 + 8, "default store word 1", 8),
                           (DEFAULT2 + 0x10, "default store word 2", 8), (DEFAULT2 + 0x18, "default store word 3", 8),
                           (LOC_SUM, "sum overflow location", 4), (LOC_TOTAL, "total overflow location", 4)):
        at = image.offset(va)
        rows.append((hexbits(va), name, size, bytes(image.blob[at:at + size]).hex()))
    rows.append(("-", "divisor multiplier", 8, "%016x" % MAGIC))
    return rows


def call_rows(image):
    """Every call of the subject bodies; an indirect call names its pointer slot and the relocation that fills it."""
    relocs = {slot: (kind, addend) for slot, kind, addend, _ in image.relocations()}
    rows = []
    for entry in FUNCTIONS:
        for row in decode_range(image, *image.exact_fde(entry)):
            if row.op == "call":
                rows.append(("%#x" % entry, "%#x" % row.va, "direct", "%#x" % row.target, ""))
            elif row.op == "calli":
                slot = row.a[4] & MASK[8]
                kind, addend = relocs.get(slot, (None, None))
                note = "no relocation" if kind is None else "reloc type %d addend %#x" % (kind, addend & MASK[8])
                rows.append(("%#x" % entry, "%#x" % row.va, "indirect", "%#x" % slot, note))
    return rows


# Static facts: each row is a claim of the README that is read from the decoded instruction bytes, independent of the evaluator runs.
# A fact is (name, function, kind, value, count): `kind` is the operand shape searched for in that function and `count` the number of
# matching instructions that must exist (an exact number, so an added or removed use is noticed).
FACTS = (
    ("first map entry stride", MAP1, "imm3", 0x98, 1),
    ("second map entry stride", MAP2, "imm3", 0x70, 1),
    ("first map key lane at entry +0x80", MAP1, "disp", 0x80, 1),
    ("first map key tail at entry +0x90", MAP1, "disp", 0x90, 1),
    ("second map key lane at entry +0x58", MAP2, "disp", 0x58, 1),
    ("second map key tail at entry +0x68", MAP2, "disp", 0x68, 1),
    ("map entries pointer at +8", MAP1, "disp", 0x8, 1),
    ("map length at +0x10", MAP1, "disp", 0x10, 1),
    ("map hasher word 0 at +0x38", MAP1, "disp", 0x38, 1),
    ("map hasher word 1 at +0x40", MAP1, "disp", 0x40, 1),
    ("second map hasher word 0 at +0x38", MAP2, "disp", 0x38, 1),
    ("second map hasher word 1 at +0x40", MAP2, "disp", 0x40, 1),
    ("division multiplier", FEE, "imm", MAGIC, 1),
    ("tree niche word", FEE, "imm", NICHE, 1),
    ("signed saturation limit", FEE, "imm", I64_MAX, 1),
    ("store one node length at +0x16a", FEE, "disp", 0x16A, 1),
    ("store one child base at +0x170", FEE, "disp", 0x170, 1),
    ("store one value offset +0x48 from the key cursor", FEE, "imm", 0x48, 1),
    ("store two node length at +0x1c2", FEE, "disp", 0x1C2, 1),
    ("store two child base at +0x1c8", FEE, "disp", 0x1C8, 1),
    ("extra term output word at stack +0x28", FEE, "disp", 0x28, 1),
    ("base conversion table argument self +0x148", FEE, "imm", 0x148, 1),
    ("deque 32 byte entry shift", DEQUE32, "imm", 5, 3),
    ("deque 40 byte entry scale (lea x5, shl 3)", DEQUE40, "imm", 3, 1),
    ("sip initial constant 0", HASHER, "imm", 0x736F6D6570736575, 1),
    ("sip initial constant 1", HASHER, "imm", 0x646F72616E646F6D, 1),
    ("sip initial constant 2", HASHER, "imm", 0x6C7967656E657261, 1),
    ("sip initial constant 3", HASHER, "imm", 0x7465646279746573, 1),
    ("sip finalisation xor", HASHER, "imm", 0xFF, 1),
    ("hashed length of the key", HASHER, "imm", 0x14, 1),
    ("hasher length counter at state +0x30", SIPWRITE, "disp", 0x30, 1),
    ("hasher tail word at state +0x38", SIPWRITE, "disp", 0x38, 3),
    ("hasher tail length at state +0x40", SIPWRITE, "disp", 0x40, 3),
)


def matches(row, kind, value):
    """Does the decoded instruction carry the operand shape: an immediate, a memory displacement, or a three operand multiplier."""
    if kind == "imm3":
        return row.op == "imul3" and row.target == value
    for operand in (row.a, row.b):
        if not operand:
            continue
        if kind == "imm" and operand[0] == "i" and operand[1] & MASK[8] == value:
            return True
        if kind == "disp" and operand[0] == "m" and operand[1] is not None and operand[4] == value:
            return True
    if kind == "imm" and row.op in ("shl", "shr", "rol", "ror", "sar", "bt") and row.b and row.b[0] == "i" and row.b[1] == value:
        return True
    return False


def fact_rows(image):
    rows = []
    for name, entry, kind, value, count in FACTS:
        sites = [row.va for row in decode_range(image, *image.exact_fde(entry)) if matches(row, kind, value)]
        rows.append((name, "%#x" % entry, kind, "%#x" % value, count, len(sites), " ".join("%#x" % va for va in sites[:6]), int(len(sites) >= count)))
    return rows


def field_rows(image):
    ops = collections.defaultdict(set)
    for row in decode_range(image, *image.exact_fde(FEE)):
        for operand in (row.a, row.b):
            if operand and operand[0] == "m" and operand[1] in (RBX, R14, 15, 12, 13) and operand[2] is None:
                ops[(operand[1], operand[4])].add("%s/%d" % (row.op, row.width))
    names = {RBX: "rbx", R14: "r14", 15: "r15", 12: "r12", 13: "r13"}
    return [(names[reg], "%#x" % disp, ";".join(sorted(v))) for (reg, disp), v in sorted(ops.items())]


def function_rows(image, hits):
    rows = []
    for entry in FUNCTIONS:
        start, end = image.exact_fde(entry)
        for row in decode_range(image, start, end):
            rows.append(("%#x" % entry, "%#x" % row.va, row.size, row.op, hits.get(row.va, 0)))
    return rows


EQUIVALENT = {
    (0x44A95C6, "displacement"): "the key tail copy for the third lookup moves to another stack slot, but slot 0x30 already holds the same four bytes from the copy at 0x44a94b9 and nothing writes it in between",
    (0x44A9601, "immediate"): "r8 = n << 3 versus n << 2 is only tested against zero before the first key comparison; the back edge that would use it never runs",
    (0x44A9628, "immediate"): "the decrement of r8 feeds only the next loop iteration, and the back edge needs 0 > key, which never holds for an unsigned key",
    (0x44A979F, "immediate"): "a saturated sum of 2^64-2 instead of 2^64-1 has the same quotient: (2^64-2) >> 2 == (2^64-1) >> 2",
    (0x45584F9, "immediate"): "the compare only separates Less from Greater for the first key of the back slice against target 0; Less cannot occur for unsigned keys",
    (0x455B7F8, "immediate"): "the compare only separates Less from Greater for the first key of the back slice against target 0; Less cannot occur for unsigned keys",
    (0x455857A, "immediate"): "for a one element slice the loop body halves 1 to 0, changes nothing and reaches the same final compare as the shortcut",
    (0x455B879, "immediate"): "for a one element slice the loop body halves 1 to 0, changes nothing and reaches the same final compare as the shortcut",
    (0x459289B, "immediate"): "the tail length mask 7 versus 6 differs only in bit 0, and the hasher is only called with 20 bytes, whose tail length is 4 under both masks",
    (0x459289F, "immediate"): "the whole-word byte count mask differs only in bit 0 and 20 & mask is 16 under both masks",
    (0x459291C, "immediate"): "the tail offset 4 versus 5 only changes whether a following 2 byte or 1 byte read is attempted, and a 4 byte tail needs neither",
    (0x4592923, "immediate"): "or ecx,1 versus or ecx,0 gives 5 or 4 and both fail the 2 byte read test against a tail length of 4",
    (0x471748E, "displacement"): "the stored copy of the first hasher key word is never read again: write and finish touch only offsets 0 to 0x18 and 0x30 to 0x40",
    (0x4717493, "displacement"): "the stored copy of the second hasher key word is never read again and the slot at 0x30 is overwritten by the next two stores",
    (0x45585B5, "immediate"): "adc rdi,imm only changes the insertion index of a miss, and the caller reads the index only when the search reported a hit",
    (0x455B8AF, "immediate"): "adc rdi,imm only changes the insertion index of a miss, and the caller reads the index only when the search reported a hit",
}


def analyse(count=11000, mutate=True, mutant_cases=1000):
    image = load_image()
    harness = Harness(image)
    named = named_cases()
    cases = named + list(random_cases(count))
    reached = collections.Counter()
    stats, caught, sample = check_stream(harness, cases, VARIANTS, keep=5, hits=reached)
    result = {"image": image, "stats": stats, "caught": caught, "sample": sample, "reached": reached, "cases": len(cases)}
    result["structural"] = structural_controls(image, harness, cases)
    result["mutants"] = []
    if mutate:
        picked = named + cases[len(named)::max(1, count // mutant_cases)]
        result["mutants"] = run_mutants(image, mutants_of(image, reached), picked)
        survivors = {(row[0], row[1]) for row in result["mutants"] if not row[5]}
        if survivors != set(EQUIVALENT):
            raise EvidenceError("unexplained or stale surviving mutants: %s" % sorted(survivors ^ set(EQUIVALENT)))
    result["magic"] = magic_rows()
    return result


def render(result):
    image, stats = result["image"], result["stats"]
    files = {}

    def tsv(name, header, rows):
        files[name] = "\n".join(["\t".join(header)] + ["\t".join(str(x) for x in row) for row in rows]) + "\n"

    tsv("constants.tsv", ("address", "role", "bytes", "raw"), constant_rows(image))
    tsv("layout-facts.tsv", ("fact", "function", "shape", "value", "required_at_least", "found", "sites", "holds"), fact_rows(image))
    tsv("call-sites.tsv", ("function", "site", "kind", "target_or_slot", "note"), call_rows(image))
    tsv("object-fields.tsv", ("register", "displacement", "accesses"), field_rows(image))
    tsv("function-rows.tsv", ("function", "address", "size", "op", "cases_reaching"), function_rows(image, result["reached"]))
    tsv("outcomes.tsv", ("store2", "store3", "outcome", "cases"), [(a, b, c, n) for (a, b, c), n in sorted(stats["kinds"].items())])
    tsv("cases-sample.tsv", ("index", "name", "store2", "store3", "lazy1", "lazy2", "outcome", "result", "distinct_insns", "log_rows"), result["sample"])
    tsv("variants.tsv", ("deviation", "cases_refused", "first_refusing_case"),
        [(name, n, "" if first is None else first) for name, (n, first) in sorted(result["caught"].items())])
    tsv("structural-controls.tsv", ("control", "detected", "how"), [(n, int(d), h) for n, d, h in result["structural"]])
    tsv("mutants.tsv", ("address", "kind", "edited_byte_at", "old", "new", "killed", "first_case"),
        [("%#x" % va, kind, "%#x" % at, old, new, int(killed), first) for va, kind, at, old, new, killed, first in result["mutants"]])
    tsv("divisor-check.tsv", ("error_e", "exact_for_all_inputs", "boundary_points", "mismatches"), result["magic"])
    survivors = [row for row in result["mutants"] if not row[5]]
    tsv("equivalent-mutants.tsv", ("address", "kind", "edited_byte_at", "reason"),
        [("%#x" % va, kind, "%#x" % at, EQUIVALENT[(va, kind)]) for va, kind, at, old, new, killed, first in survivors])
    controls = len(result["caught"]) + len(result["structural"]) + len(result["mutants"])
    detected = sum(1 for n, first in result["caught"].values() if n) + sum(1 for _, d, _ in result["structural"] if d) + \
        sum(1 for row in result["mutants"] if row[5])
    evidence = {
        "binary_sha256": SHA256, "function": "%#x" % FEE, "helpers": {"deque32": "%#x" % DEQUE32, "deque40": "%#x" % DEQUE40},
        "cases": stats["cases"], "mismatches": stats["mismatches"], "first_mismatch": stats["first_mismatch"],
        "instructions_reached": len(result["reached"]), "mutants": len(result["mutants"]), "mutant_survivors": len(survivors),
    }
    files["evidence.json"] = json.dumps(evidence, indent=1, sort_keys=True, default=str) + "\n"
    files["measure.json"] = json.dumps({"cases": stats["cases"], "negative_controls": controls, "negative_detected": detected,
                                        "equivalent": len(survivors), "mismatches": stats["mismatches"]}, indent=1, sort_keys=True) + "\n"
    return files


def main(argv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument("--out", required=True)
    args = parser.parse_args(argv)
    result = analyse()
    out = pathlib.Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    files = render(result)
    for name, text in files.items():
        (out / name).write_text(text)
    print(files["measure.json"], end="")
    return 0 if result["stats"]["mismatches"] == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
