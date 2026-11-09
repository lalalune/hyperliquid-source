#!/usr/bin/env python3
"""Reconstruct the node #115 wire form of EthEventId and of the two deposit vote actions.

The real serializer and Content reader bytes of the #115 capture run in a small x86-64 interpreter on fixtures.
EthEventId has five fields b, t, e, i, h, e is a six-variant EventType string, h is a 0x hex string, and the two
Action variants are flat (type, user, usd, ethId) and nested (type, action). A separately written rule list
predicts every output byte and every error text of 9 entry functions and 13 compiled copies, 34 negative controls
(wrong rule lists, corrupted bytes, bad inputs) must all be caught, and reached rows of the entries are edited.
The interpreter and the rule list are the node #94 packet of the same name, re-bound to #115: every entry address,
allocator entry, import slot and text address below was found again in the #115 bytes. No objdump or readelf
output is parsed and the binary is never executed. Standard library only.

    python3 tools/bridge_eth_event_wire_115.py --out <dir>
"""

import argparse
import bisect
import collections
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
HEAP_SIZE = 0x200000
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
SHIFTS = {0: "rol", 4: "shl", 5: "shr", 7: "sar"}


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
        elif op in ("shld", "shrd"):
            count = (row.target if op == "shld" else self.regs[RCX]) & 63
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



FLAT_MP_A = 0x290CE10
NEST_MP_A = 0x291BDE0
FLAT_MP_B = 0x290C4B0
NEST_MP_B = 0x291B860
ACT_MP_B = 0x46CCDA0
ACT_JSON = 0x290C6C0
FLAT_JSON = 0x290CB40
DE_ACT_R = 0x2011090
DE_ACT_J = 0x20BAFF0

NAMES = {FLAT_MP_A: "flat_msgpack_a", NEST_MP_A: "nested_msgpack_a", FLAT_MP_B: "flat_msgpack_b", NEST_MP_B: "nested_msgpack_b",
         ACT_MP_B: "action_msgpack_b", ACT_JSON: "action_json", FLAT_JSON: "flat_json",
         DE_ACT_R: "action_from_content_rmp", DE_ACT_J: "action_from_content_json"}
TARGETS = tuple(sorted(NAMES))

SLOT_NAMES = {"malloc": "alloc", "free": "free", "memcpy": "copy", "memmove": "copy", "memcmp": "compare", "bcmp": "compare",
              "realloc": "realloc", "abort": "stop", "_Unwind_Resume": "stop"}
REAL_FUNCTIONS = ()
ALLOCATOR_ENTRIES = {0x6355830: "alloc", 0x635de30: "free", 0x635a7a0: "realloc", 0x1680cab: "stop", 0x1680bd0: "stop"}
MARK_BASE = 0x7700000000

ARENA = HEAP_BASE + 0x10000
HEAP_USED = 0x40000
ARENA_END = HEAP_BASE + HEAP_USED
OUT = HEAP_BASE + 0x100
ACTION = HEAP_BASE + 0x1000
SERIALIZER = HEAP_BASE + 0x2000
WRITER = SERIALIZER + 0x40
CONTENT = HEAP_BASE + 0x7000
INDENT = HEAP_BASE + 0x4000
TAGS = HEAP_BASE + 0x5000
VARIANT = HEAP_BASE + 0x6000
KEY_SIZE = 0x40
TAG_KEY = "type"
FLAT_TAG = "VoteEthDepositAction"
NEST_TAG = "l1ValidatorVoteBridgeDeposit"
EVENTS = ("Deposit", "InvalidatedWithdrawal", "RequestedWithdrawal", "FinalizedWithdrawal", "FinalizedValidatorSetUpdate", "RequestedValidatorSetUpdateEvent")

NULL, BOOL, U8, U16, U32, U64, I8, I16, I32, I64, F32, F64, CHAR, STRING, STR, BYTEBUF, BYTES, NONE, SOME, UNIT, NEWTYPE, SEQ, MAP = "null", 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21
LONG_STEP_LIMIT = 600000
MUTANT_STEP_LIMIT = 60000


class Con:
    """One serde Content value; `kind` is the enum byte."""

    def __init__(self, kind, value=None):
        self.kind, self.value = kind, value

    def __repr__(self):
        return "Con(%s, %r)" % (self.kind, self.value)


def wrap(value):
    """Plain python shapes to Content: str, int, list, dict, Con."""
    if isinstance(value, Con):
        return value
    if isinstance(value, bool):
        return Con(BOOL, value)
    if isinstance(value, str):
        return Con(STRING, value)
    if isinstance(value, int):
        return Con(U64, value)
    if isinstance(value, list):
        return Con(SEQ, [wrap(item) for item in value])
    if isinstance(value, dict):
        return Con(MAP, [(wrap(key), wrap(item)) for key, item in value.items()])
    raise EvidenceError("no content form")


class Harness:
    def __init__(self, image, patches=None, cache=None):
        self.image = image
        machine = Machine(image, patches)
        self.machine = machine
        machine.real = frozenset(image.real_set())
        machine.memory.statics = image.static_view()
        handlers = {"alloc": self.on_alloc, "free": self.on_free, "copy": self.on_copy, "compare": self.on_compare,
                    "realloc": self.on_realloc, "stop": self.on_stop}
        table = {slot: handlers[kind] for slot, kind in image.symbol_slots().items()}
        for entry, kind in ALLOCATOR_ENTRIES.items():
            machine.calls[entry] = handlers[kind]
            machine.slots[entry] = handlers[kind]
        for slot, hook in table.items():
            machine.slots[MARK_BASE + slot] = hook
        if cache:
            machine.cache = dict(cache)
            for va in (patches or {}):
                for back in range(16):
                    machine.cache.pop(va - back, None)
        self.top = ARENA
        self.live = {}

    def expect(self, condition, text):
        if not condition:
            raise Halt("fixture check failed: " + text)

    def read(self, at, size=8):
        return self.machine.memory.read(at, size)

    def data(self, at, size):
        return self.machine.memory.bytes_at(at, size)

    def write(self, at, value, size=8):
        self.machine.memory.write(at, size, value & MASK[8])

    def put(self, at, data):
        self.machine.memory.put_bytes(at, data)

    def alloc(self, size):
        at = self.top
        self.top += (size + 15) & ~15
        if self.top > ARENA_END:
            raise Halt("fixture arena full")
        self.live[at] = size
        return at

    def on_alloc(self, machine):
        machine.regs[RAX] = self.alloc(machine.regs[RDI])

    def on_free(self, machine):
        at, size = machine.regs[RDI], machine.regs[RSI]
        self.expect(self.live.get(at) == size, "freed block size")
        del self.live[at]

    def on_realloc(self, machine):
        old, size = machine.regs[RDI], machine.regs[RSI]
        self.expect(old in self.live, "realloc of a live block")
        at = self.alloc(size)
        self.put(at, self.data(old, min(size, self.live[old])))
        del self.live[old]
        machine.regs[RAX] = at

    def on_copy(self, machine):
        self.put(machine.regs[RDI], self.data(machine.regs[RSI], machine.regs[RDX]))
        machine.regs[RAX] = machine.regs[RDI]

    def on_compare(self, machine):
        left, right = self.data(machine.regs[RDI], machine.regs[RDX]), self.data(machine.regs[RSI], machine.regs[RDX])
        machine.regs[RAX] = 0 if left == right else 1 if left > right else MASK[4]

    def on_stop(self, machine):
        raise Panicked("panic path reached")

    def fresh(self):
        self.machine.memory.reset(HEAP_USED)
        self.top = ARENA
        self.live = {}

    def put_action(self, action):
        self.write(ACTION, action.usd)
        self.write(ACTION + 8, action.block)
        self.write(ACTION + 0x10, action.t)
        self.write(ACTION + 0x18, action.i)
        self.put(ACTION + 0x20, action.hash)
        self.write(ACTION + 0x40, action.event, 1)
        self.put(ACTION + 0x48, action.user)

    def vector(self, at, capacity):
        pointer = self.alloc(capacity) if capacity else 1
        self.write(at, capacity)
        self.write(at + 8, pointer)
        self.write(at + 16, 0)

    def serialize(self, case):
        """Run one serializer; returns the error word and the bytes written."""
        self.fresh()
        self.put_action(case.action)
        entry = case.entry
        form = FORMS[entry]
        run = self.machine.run
        if form[0] == "a":
            self.vector(SERIALIZER, case.capacity)
            self.write(SERIALIZER + 0x18, 0)
            self.write(SERIALIZER + 0x1B, case.named, 1)
            sink, vector = SERIALIZER, SERIALIZER
        elif form[0] == "b":
            self.vector(WRITER, case.capacity)
            self.write(SERIALIZER, WRITER)
            self.write(SERIALIZER + 8, 0)
            self.write(SERIALIZER + 0xB, case.named, 1)
            sink, vector = SERIALIZER, WRITER
        else:
            self.vector(WRITER, case.capacity)
            self.put(INDENT, b"  ")
            self.write(SERIALIZER, WRITER)
            self.write(SERIALIZER + 8, INDENT)
            self.write(SERIALIZER + 16, 2)
            self.write(SERIALIZER + 0x18, 0)
            self.write(SERIALIZER + 0x20, 0, 1)
            sink, vector = SERIALIZER, WRITER
        subject = ACTION + 8 if form[1] == "id" else ACTION
        if form[1] == "event":
            subject = ACTION + 0x40
        target = sink
        if form[1] in ("flat", "nest"):
            self.put(TAGS, (TAG_KEY + FLAT_TAG + NEST_TAG).encode())
            self.write(VARIANT + 0x20, TAGS)
            self.write(VARIANT + 0x28, len(TAG_KEY))
            self.write(VARIANT + 0x30, TAGS + len(TAG_KEY) + (len(FLAT_TAG) if form[1] == "nest" else 0))
            self.write(VARIANT + 0x38, len(NEST_TAG if form[1] == "nest" else FLAT_TAG))
            self.write(VARIANT + 0x40, sink)
            target = VARIANT
        if form[0] == "j":
            self.expect(run(entry, {RDI: subject, RSI: target}) == 0, "json status")
        else:
            run(entry, {RDI: OUT, RSI: subject, RDX: target})
            status = self.read(OUT)
            self.expect(status == 0x8000000000000004, "serializer status %#x" % status)
        data = self.data(self.read(vector + 8), self.read(vector + 16))
        self.expect(set(self.live) <= {self.read(vector + 8)}, "only the writer stays allocated")
        return data

    def lay(self, at, value):
        kind = value.kind
        self.write(at, kind, 1)
        if kind in (STRING, BYTEBUF):
            data = value.value.encode() if isinstance(value.value, str) else value.value
            pointer = self.alloc(len(data)) if data else HEAP_BASE + 1
            self.put(pointer, data)
            self.write(at + 8, len(data))
            self.write(at + 0x10, pointer)
            self.write(at + 0x18, len(data))
        elif kind in (STR, BYTES):
            data = value.value.encode() if isinstance(value.value, str) else value.value
            self.put(self.static_top, data)
            self.write(at + 8, self.static_top)
            self.write(at + 0x10, len(data))
            self.static_top += (len(data) + 15) & ~15
        elif kind in (U8, I8, BOOL):
            self.write(at + 1, value.value, 1)
        elif kind in (U16, I16):
            self.write(at + 2, value.value, 2)
        elif kind in (U32, I32):
            self.write(at + 4, value.value, 4)
        elif kind in (U64, I64):
            self.write(at + 8, value.value)
        elif kind == NEWTYPE or kind == SOME:
            pointer = self.alloc(0x20)
            self.write(at + 8, pointer)
            self.lay(pointer, value.value)
        elif kind == SEQ:
            rows = value.value
            pointer = self.alloc(0x20 * len(rows)) if rows else 16
            self.write(at + 8, len(rows))
            self.write(at + 0x10, pointer)
            self.write(at + 0x18, len(rows))
            for index, row in enumerate(rows):
                self.lay(pointer + 0x20 * index, row)
        elif kind == MAP:
            rows = value.value
            pointer = self.alloc(0x40 * len(rows)) if rows else 16
            self.write(at + 8, len(rows))
            self.write(at + 0x10, pointer)
            self.write(at + 0x18, len(rows))
            for index, (key, row) in enumerate(rows):
                self.lay(pointer + 0x40 * index, key)
                self.lay(pointer + 0x40 * index + 0x20, row)
        elif kind not in (NONE, UNIT):
            raise Halt("content kind")

    def json_text(self, word):
        """The message of a boxed serde_json error."""
        self.expect(word in self.live, "json error box")
        pointer, size = self.read(word + 8), self.read(word + 16)
        self.expect(self.read(word) == 0 and pointer in self.live, "json error code is Message")
        return self.data(pointer, size).decode(), {word, pointer}

    def deserialize(self, case):
        """Run one Content deserializer. Returns ("ok", fields) or ("error", text)."""
        self.fresh()
        self.static_top = HEAP_BASE + 0x8000
        self.lay(CONTENT, case.value)
        form = DE_FORMS[case.entry]
        self.machine.run(case.entry, {RDI: OUT, RSI: CONTENT})
        tag = self.read(OUT + form[1], 1)
        if tag == form[2]:
            if form[0] == "j":
                text, kept = self.json_text(self.read(OUT))
            else:
                self.expect(self.read(OUT, 1) == 6, "rmp error tag")
                pointer, size = self.read(OUT + 0x10), self.read(OUT + 0x18)
                text, kept = self.data(pointer, size).decode(), {pointer}
            self.expect(set(self.live) == kept, "only the error stays allocated, %s" % sorted(self.live))
            return ("error", text)
        self.expect(not self.live, "ok leaves nothing allocated")
        return ("ok",) + form[3](self)


def read_event_id(harness, at):
    return (harness.read(at), harness.read(at + 8), harness.read(at + 0x38, 1), harness.read(at + 0x10), harness.data(at + 0x18, 0x20).hex())


def read_action(harness):
    return (harness.read(OUT),) + read_event_id(harness, OUT + 8) + (harness.data(OUT + 0x48, 20).hex(),)


def read_id(harness):
    return read_event_id(harness, OUT)


def read_event(harness):
    return (harness.read(OUT + 1, 1),)


FORMS = {FLAT_MP_A: ("a", "flat"), NEST_MP_A: ("a", "nest"), FLAT_MP_B: ("b", "flat"), NEST_MP_B: ("b", "nest"), ACT_MP_B: ("b", "act"), ACT_JSON: ("j", "act"), FLAT_JSON: ("j", "flat")}
DE_FORMS = {DE_ACT_J: ("j", 0x40, 6, read_action, "act"), DE_ACT_R: ("r", 0x40, 6, read_action, "act")}
DECODERS = (DE_ACT_J, DE_ACT_R)


def real_set(self):
    return [va for va in self.starts if va not in ALLOCATOR_ENTRIES]


def static_view(self):
    if self.static_map is None:
        table = dict(self.relative())
        for slot in self.symbol_slots():
            table[slot] = MARK_BASE + slot
        self.static_map = table
    return self.static_map


def symbol_slots(self):
    """GOT and PLT slots (GLOB_DAT, JUMP_SLOT) of the imported symbols the fixtures model, by role."""
    if self.slot_roles is None:
        dynsym, dynstr = self.named[".dynsym"], self.named[".dynstr"]
        roles = {}
        for slot, kind, _, index in self.relocations():
            if kind not in (6, 7) or not index:
                continue
            start = dynstr["offset"] + struct.unpack_from("<I", self.blob, dynsym["offset"] + index * 24)[0]
            name = self.blob[start:self.blob.index(b"\0", start)].decode()
            if name in SLOT_NAMES:
                roles[slot] = SLOT_NAMES[name]
        self.slot_roles = roles
    return self.slot_roles


Image.symbol_slots = symbol_slots
Image.slot_roles = None
Image.real_set = real_set
Image.static_view = static_view
Image.static_map = None


class Bad(Exception):
    """A rule-list refusal; the text is the expected error."""


class Action:
    def __init__(self, usd=5, block=0x100, t=0x7F, i=0x80, event=2, digest=bytes(range(0xA0, 0xC0)), user=bytes(range(0x40, 0x54))):
        self.usd, self.block, self.t, self.i, self.event, self.hash, self.user = usd, block, t, i, event, digest, user


class Ser:
    def __init__(self, name, entry, action, named=1, capacity=0x1000):
        self.name, self.entry, self.action, self.named, self.capacity = name, entry, action, named, capacity


class De:
    def __init__(self, name, entry, value):
        self.name, self.entry, self.value = name, entry, wrap(value)


def run_case(harness, case):
    if isinstance(case, Ser):
        return ("bytes", harness.serialize(case).hex())
    return harness.deserialize(case)


def mp_uint(value):
    if value < 0x80:
        return bytes([value])
    if value < 0x100:
        return bytes([0xCC, value])
    if value < 0x10000:
        return b"\xcd" + value.to_bytes(2, "big")
    if value < 0x100000000:
        return b"\xce" + value.to_bytes(4, "big")
    return b"\xcf" + value.to_bytes(8, "big")


def mp_str(text):
    data = text.encode()
    if len(data) < 32:
        return bytes([0xA0 | len(data)]) + data
    if len(data) < 256:
        return bytes([0xD9, len(data)]) + data
    return b"\xda" + len(data).to_bytes(2, "big") + data


def mp_pack(item, named):
    if isinstance(item, int):
        return mp_uint(item)
    if isinstance(item, str):
        return mp_str(item)
    head = bytes([(0x80 if named else 0x90) | len(item)])
    return head + b"".join((mp_str(key) if named else b"") + mp_pack(value, named) for key, value in item)


def json_pack(item, depth=0):
    if isinstance(item, int):
        return str(item)
    if isinstance(item, str):
        return '"%s"' % item
    pad = "  " * (depth + 1)
    rows = ['%s"%s": %s' % (pad, key, json_pack(value, depth + 1)) for key, value in item]
    return "{\n" + ",\n".join(rows) + "\n" + "  " * depth + "}"


def id_shape(action):
    return [("b", action.block), ("t", action.t), ("e", EVENTS[action.event]), ("i", action.i), ("h", "0x" + action.hash.hex())]


def action_shape(action):
    return [("user", "0x" + action.user.hex()), ("usd", action.usd), ("ethId", id_shape(action))]


def shape(form, action):
    if form == "id":
        return id_shape(action)
    if form == "event":
        return EVENTS[action.event]
    if form == "act":
        return action_shape(action)
    if form == "flat":
        return [(TAG_KEY, FLAT_TAG)] + action_shape(action)
    return [(TAG_KEY, NEST_TAG), ("action", action_shape(action))]


def spec_ser(case):
    family, form = FORMS[case.entry]
    item = shape(form, case.action)
    if family == "j":
        return ("bytes", json_pack(item).encode().hex())
    return ("bytes", mp_pack(item, case.named).hex())


def describe(value, flavor):
    kind = value.kind
    if kind == BOOL:
        return "boolean `%s`" % ("true" if value.value else "false")
    if kind in (U8, U16, U32, U64):
        return "integer `%d`" % value.value
    if kind in (I8, I16, I32, I64):
        return "integer `%d`" % signed(value)
    if kind in (STRING, STR):
        return 'string "%s"' % value.value
    if kind in (BYTES, BYTEBUF):
        return "byte array"
    if kind in (NONE, SOME):
        return "Option value"
    if kind == UNIT:
        return "null" if flavor == "j" else "unit value"
    if kind == NEWTYPE:
        return "newtype struct"
    if kind == SEQ:
        return "sequence"
    return "map"


def signed(value):
    bits = {I8: 8, I16: 16, I32: 32, I64: 64}[value.kind]
    return value.value - (1 << bits) if value.value >> (bits - 1) else value.value


def spec_u64(value, flavor):
    if value.kind in (U8, U16, U32, U64):
        return value.value
    if value.kind in (I8, I16, I32, I64):
        number = signed(value)
        if number < 0:
            raise Bad("invalid value: integer `%d`, expected u64" % number)
        return number
    raise Bad("invalid type: %s, expected u64" % describe(value, flavor))


def spec_hex(value, size, flavor):
    expected = "a (both 0x-prefixed or not) hex string or byte array containing %d bytes" % size
    if value.kind in (BYTES, BYTEBUF):
        if len(value.value) != size:
            raise Bad("invalid length %d, expected %s" % (len(value.value), expected))
        return bytes(value.value).hex()
    if value.kind not in (STRING, STR):
        raise Bad("invalid type: %s, expected %s" % (describe(value, flavor), expected))
    data = value.value.encode()
    skip = 2 if data[:2] == b"0x" else 0
    body = data[skip:]
    if len(body) != 2 * size:
        raise Bad("invalid length %d, expected %s" % (len(body), expected))
    for index, byte in enumerate(body):
        if byte not in b"0123456789abcdefABCDEF":
            raise Bad("invalid hex character: %s, at %d" % (chr(byte), index + skip))
    return body.decode().lower()


def spec_variant(key, flavor):
    if key.kind in (STRING, STR):
        name = key.value
    elif key.kind in (BYTES, BYTEBUF):
        name = bytes(key.value).decode()
    elif key.kind in (U8, U64):
        if key.value >= len(EVENTS):
            raise Bad("invalid value: integer `%d`, expected variant index 0 <= i < 6" % key.value)
        return key.value
    else:
        raise Bad("invalid type: %s, expected variant identifier" % describe(key, flavor))
    if name not in EVENTS:
        raise Bad("unknown variant `%s`, expected one of %s" % (name, ", ".join("`%s`" % item for item in EVENTS)))
    return EVENTS.index(name)


def spec_event(value, flavor):
    if value.kind in (STRING, STR):
        return spec_variant(value, flavor)
    if value.kind != MAP:
        raise Bad("invalid type: %s, expected string or map" % describe(value, flavor))
    if len(value.value) != 1:
        raise Bad("invalid value: map, expected map with a single key")
    key, item = value.value[0]
    index = spec_variant(key, flavor)
    if item.kind != UNIT:
        raise Bad("invalid type: %s, expected unit" % describe(item, flavor))
    return index


def field_index(key, names, deny, flavor):
    """The position of a map key, or None when the key is ignored."""
    if key.kind in (STRING, STR, BYTES, BYTEBUF):
        name = key.value if key.kind in (STRING, STR) else bytes(key.value).decode()
        if name in names:
            return names.index(name)
        if deny:
            listed = ", ".join("`%s`" % item for item in names)
            raise Bad("unknown field `%s`, expected %s" % (name, listed if len(names) == 1 else "one of " + listed))
        return None
    if key.kind in (U8, U64):
        if key.value < len(names):
            return key.value
        if deny:
            raise Bad("invalid value: integer `%d`, expected field index 0 <= i < %d" % (key.value, len(names)))
        return None
    raise Bad("invalid type: %s, expected field identifier" % describe(key, flavor))


def spec_struct(value, name, names, readers, deny, flavor):
    """Sequence and map forms of one derived struct."""
    count = len(names)
    plural = "%d element%s" % (count, "" if count == 1 else "s")
    if value.kind == SEQ:
        rows = value.value
        found = []
        for index, reader in enumerate(readers):
            if index >= len(rows):
                raise Bad("invalid length %d, expected struct %s with %s" % (index, name, plural))
            found.append(reader(rows[index], flavor))
        if len(rows) > count:
            raise Bad("invalid length %d, expected %s in sequence" % (len(rows), plural))
        return found
    if value.kind != MAP:
        raise Bad("invalid type: %s, expected struct %s" % (describe(value, flavor), name))
    found = [None] * count
    for key, item in value.value:
        index = field_index(key, names, deny, flavor)
        if index is None:
            continue
        if found[index] is not None:
            raise Bad("duplicate field `%s`" % names[index])
        found[index] = readers[index](item, flavor)
    for index, label in enumerate(names):
        if found[index] is None:
            raise Bad("missing field `%s`" % label)
    return found


def spec_id(value, flavor):
    return spec_struct(value, "EthEventId", ("b", "t", "e", "i", "h"), (spec_u64, spec_u64, spec_event, spec_u64, lambda item, kind: spec_hex(item, 32, kind)), False, flavor)


def unwrap(value):
    return value.value if value.kind == NEWTYPE else value


def unwrap_all(value):
    while value.kind == NEWTYPE:
        value = value.value
    return value


def spec_action(value, flavor):
    readers = (lambda item, kind: spec_hex(unwrap_all(item), 20, kind), lambda item, kind: spec_u64(unwrap(item), kind), spec_id)
    return spec_struct(value, "VoteEthDepositAction", ("user", "usd", "ethId"), readers, True, flavor)


def spec_nest(value, flavor):
    return spec_struct(value, "L1ValidatorVoteBridgeDepositAction", ("action",), (spec_action,), True, flavor)[0]


def spec_de(case):
    family, _, _, _, level = DE_FORMS[case.entry]
    try:
        if level == "id":
            block, t_word, event, index, digest = spec_id(case.value, family)
            return ("ok", block, t_word, event, index, digest)
        user, usd, (block, t_word, event, index, digest) = (spec_nest if level == "nest" else spec_action)(case.value, family)
        return ("ok", usd, block, t_word, event, index, digest, user)
    except Bad as error:
        return ("error", error.args[0])


def spec_run(case):
    return spec_ser(case) if isinstance(case, Ser) else spec_de(case)


HASH = bytes(range(0xA0, 0xC0)).hex()
USER = bytes(range(0x40, 0x54)).hex()
GOOD_ID = {"b": 0x11223344556677, "t": 0x7F, "e": "RequestedWithdrawal", "i": 0x10000, "h": "0x" + HASH}
GOOD_ACT = {"user": "0x" + USER, "usd": 100000000, "ethId": GOOD_ID}
EDGES = (0, 1, 0x7F, 0x80, 0xFF, 0x100, 0xFFFF, 0x10000, 0xFFFFFFFF, 0x100000000, MASK[8])


def changed(base, **items):
    out = dict(base)
    for key, item in items.items():
        if item is None:
            del out[key]
        else:
            out[key] = item
    return out


def map_of(*rows):
    return Con(MAP, [(wrap(key), wrap(item)) for key, item in rows])


def number(kind, value):
    return Con(kind, value)


UNIT_VALUE = Con(UNIT)
ID_FORMS = {"u8": number(U8, 200), "u16": number(U16, 2000), "u32": number(U32, 70000), "u64": number(U64, MASK[8]), "i8": number(I8, 5), "i16": number(I16, 3), "i32": number(I32, 4), "i64": number(I64, 7), "i8_minus": number(I8, 0xFF), "i16_minus": number(I16, 0xFFFE), "i32_minus": number(I32, 0xFFFFFFFD), "i64_minus": number(I64, MASK[8]),
            "text": "1", "str": Con(STR, "x"), "true": True, "false": False, "unit": UNIT_VALUE, "none": Con(NONE), "some": Con(SOME, number(U64, 1)), "newtype": Con(NEWTYPE, number(U64, 9)), "seq": [], "map": {}, "bytes": Con(BYTES, b"a")}


def id_cases():
    cases = [("good", GOOD_ID), ("seq_good", [1, 2, "Deposit", 4, HASH]), ("seq_empty", []), ("seq_short", [1, 2, "Deposit", 4]), ("seq_one", [1]), ("seq_long", [1, 2, "Deposit", 4, HASH, 5]), ("seq_bad_e", [1, 2, "Bad", 4, HASH]), ("seq_bad_b", ["x", 2, "Deposit", 4, HASH]), ("seq_bad_h", [1, 2, "Deposit", 4, "zz"]), ("seq_bad_t", [1, "x", "Deposit", 4, HASH]), ("seq_bad_i", [1, 2, "Deposit", "x", HASH]),
             ("extra_key", changed(GOOD_ID, z=1)), ("extra_map_value", changed(GOOD_ID, z={"a": [1, "b"]})), ("int_keys", map_of((0, 1), (1, 2), (2, "Deposit"), (3, 4), (4, HASH))), ("int_key_5", map_of((5, 1))), ("u8_key", map_of((number(U8, 1), 1))), ("u8_key_big", map_of((number(U8, 9), 1))), ("u16_key", map_of((number(U16, 1), 1))), ("u32_key", map_of((number(U32, 1), 1))), ("i8_key", map_of((number(I8, 1), 1))),
             ("bytes_key", map_of((Con(BYTES, b"b"), 1), ("t", 1), ("e", "Deposit"), ("i", 1), ("h", HASH))), ("bytebuf_key", map_of((Con(BYTEBUF, b"t"), 1))), ("str_key", map_of((Con(STR, "b"), 1), ("t", 1), ("e", "Deposit"), ("i", 1), ("h", HASH))), ("bool_key", map_of((True, 1))), ("unit_key", map_of((UNIT_VALUE, 1))), ("bytes_key_unknown", map_of((Con(BYTES, b"q"), 1))),
             ("reordered", {"h": HASH, "i": 3, "e": "Deposit", "t": 2, "b": 1})]
    names = ("b", "t", "e", "i", "h")
    for mask in range(32):
        rows = dict((name, GOOD_ID[name]) for bit, name in enumerate(names) if mask >> bit & 1)
        cases.append(("subset_%02d" % mask, rows))
    for name in names:
        cases.append(("dup_" + name, map_of((name, GOOD_ID[name]), (name, GOOD_ID[name]))))
    for index, name in enumerate(EVENTS):
        cases.append(("event_%d" % index, changed(GOOD_ID, e=name)))
        cases.append(("event_map_%d" % index, changed(GOOD_ID, e={name: UNIT_VALUE})))
        cases.append(("event_index_map_%d" % index, changed(GOOD_ID, e=map_of((index, UNIT_VALUE)))))
    cases += [("event_str", changed(GOOD_ID, e=Con(STR, "Deposit"))), ("event_unknown", changed(GOOD_ID, e="Nope")), ("event_case", changed(GOOD_ID, e="deposit")), ("event_empty", changed(GOOD_ID, e="")), ("event_int", changed(GOOD_ID, e=3)), ("event_u8", changed(GOOD_ID, e=number(U8, 1))), ("event_bool", changed(GOOD_ID, e=True)), ("event_unit", changed(GOOD_ID, e=UNIT_VALUE)), ("event_none", changed(GOOD_ID, e=Con(NONE))), ("event_some", changed(GOOD_ID, e=Con(SOME, wrap("Deposit")))), ("event_seq", changed(GOOD_ID, e=[1])), ("event_bytes", changed(GOOD_ID, e=Con(BYTES, b"Deposit"))), ("event_bytebuf", changed(GOOD_ID, e=Con(BYTEBUF, b"Deposit"))), ("event_newtype", changed(GOOD_ID, e=Con(NEWTYPE, wrap("Deposit")))),
              ("event_map_empty", changed(GOOD_ID, e=Con(MAP, []))), ("event_map_two", changed(GOOD_ID, e={"Deposit": UNIT_VALUE, "x": UNIT_VALUE})), ("event_map_bad_key", changed(GOOD_ID, e={"Bad": UNIT_VALUE})), ("event_map_index_6", changed(GOOD_ID, e=map_of((6, UNIT_VALUE)))), ("event_map_u8_key", changed(GOOD_ID, e=map_of((number(U8, 2), UNIT_VALUE)))), ("event_map_bool_key", changed(GOOD_ID, e=map_of((True, UNIT_VALUE)))), ("event_map_bytes_key", changed(GOOD_ID, e=map_of((Con(BYTES, b"Deposit"), UNIT_VALUE)))), ("event_map_int_value", changed(GOOD_ID, e={"Deposit": 1})), ("event_map_none_value", changed(GOOD_ID, e={"Deposit": Con(NONE)})), ("event_map_some_value", changed(GOOD_ID, e={"Deposit": Con(SOME, UNIT_VALUE)})), ("event_map_seq_value", changed(GOOD_ID, e={"Deposit": []}))]
    for name in ("b", "t", "i"):
        for label, form in ID_FORMS.items():
            cases.append(("%s_%s" % (name, label), changed(GOOD_ID, **{name: form})))
    upper = HASH.upper()
    forms = {"bare": HASH, "upper": "0x" + upper, "bare_upper": upper, "mixed": "0x" + "aB" * 32, "cap_prefix": "0X" + HASH, "double_prefix": "0x0x" + HASH[4:], "short": "0x" + HASH[:-2], "odd": "0x" + HASH[:-1], "long": "0x" + HASH + "aa", "empty": "", "prefix_only": "0x", "bad": "0x" + "zz" * 32, "bad_bare": "zz" * 32, "bad_low": "0xa" + "z" + HASH[2:], "bad_last": "0x" + HASH[:-1] + "g", "bad_at": "0x" + HASH[:-2] + "@0", "bad_colon": "0x:" + HASH[1:], "bad_slash": "0x/" + HASH[1:], "bad_nonascii": "0xé" + HASH[2:], "odd_bad_head": "z" + HASH[:63] + "a", "str": Con(STR, "0x" + HASH), "bytes": Con(BYTES, bytes(range(32))), "bytebuf": Con(BYTEBUF, bytes(range(32))), "bytes_short": Con(BYTES, bytes(31)), "bytebuf_long": Con(BYTEBUF, bytes(33)), "int": 5, "seq": list(range(32)), "unit": UNIT_VALUE, "none": Con(NONE), "true": True, "map": {}, "newtype": Con(NEWTYPE, wrap(HASH)), "newtype_newtype": Con(NEWTYPE, Con(NEWTYPE, wrap(HASH))), "newtype_int": Con(NEWTYPE, number(U64, 1))}
    for label, form in forms.items():
        cases.append(("h_" + label, changed(GOOD_ID, h=form)))
    return cases


def action_cases():
    cases = [("good", GOOD_ACT), ("seq_good", ["0x" + USER, 5, GOOD_ID]), ("seq_empty", []), ("seq_one", ["0x" + USER]), ("seq_two", ["0x" + USER, 5]), ("seq_long", ["0x" + USER, 5, GOOD_ID, 1]), ("seq_newtype", [Con(NEWTYPE, wrap("0x" + USER)), Con(NEWTYPE, number(U64, 5)), GOOD_ID]), ("seq_bad_user", ["x", 5, GOOD_ID]), ("seq_bad_usd", ["0x" + USER, "x", GOOD_ID]), ("seq_bad_id", ["0x" + USER, 5, 1]), ("seq_id_seq", ["0x" + USER, 5, [1, 2, "Deposit", 4, HASH]]),
             ("id_seq", changed(GOOD_ACT, ethId=[1, 2, "Deposit", 4, HASH])), ("id_int", changed(GOOD_ACT, ethId=5)), ("id_newtype", changed(GOOD_ACT, ethId=Con(NEWTYPE, wrap(GOOD_ID)))), ("id_unit", changed(GOOD_ACT, ethId=UNIT_VALUE)), ("extra_key", changed(GOOD_ACT, z=1)), ("int_keys", map_of((0, "0x" + USER), (1, 5), (2, GOOD_ID))), ("int_key_3", map_of((3, 1))), ("u8_key_3", map_of((number(U8, 3), 1))), ("bytes_keys", map_of((Con(BYTES, b"user"), "0x" + USER), (Con(BYTES, b"usd"), 5), (Con(BYTES, b"ethId"), GOOD_ID))), ("bytes_key_unknown", map_of((Con(BYTES, b"q"), 1))), ("str_keys", map_of((Con(STR, "user"), "0x" + USER), (Con(STR, "usd"), 5), (Con(STR, "ethId"), GOOD_ID))), ("unit_key", map_of((UNIT_VALUE, 1))), ("bool_key", map_of((True, 1))),
             ("dup_user", map_of(("user", "0x" + USER), ("user", "0x" + USER))), ("dup_usd", map_of(("usd", 1), ("usd", 1))), ("dup_id", map_of(("ethId", GOOD_ID), ("ethId", GOOD_ID))), ("not_struct_unit", UNIT_VALUE), ("not_struct_int", 5), ("not_struct_text", "x"), ("not_struct_true", True), ("not_struct_none", Con(NONE)), ("not_struct_newtype", Con(NEWTYPE, wrap(GOOD_ACT))),
             ("user_bare", changed(GOOD_ACT, user=USER)), ("user_upper", changed(GOOD_ACT, user="0x" + USER.upper())), ("user_mixed", changed(GOOD_ACT, user="0x" + "aB" * 20)), ("user_short", changed(GOOD_ACT, user="0x" + USER[:-2])), ("user_bad", changed(GOOD_ACT, user="0x" + "zz" * 20)), ("user_bytes", changed(GOOD_ACT, user=Con(BYTES, bytes(range(20))))), ("user_bytes_short", changed(GOOD_ACT, user=Con(BYTES, bytes(19)))), ("user_int", changed(GOOD_ACT, user=5)), ("user_newtype", changed(GOOD_ACT, user=Con(NEWTYPE, wrap("0x" + USER)))), ("user_newtype_newtype", changed(GOOD_ACT, user=Con(NEWTYPE, Con(NEWTYPE, wrap("0x" + USER))))), ("user_str", changed(GOOD_ACT, user=Con(STR, "0x" + USER))), ("user_bytebuf", changed(GOOD_ACT, user=Con(BYTEBUF, bytes(20)))), ("user_unit", changed(GOOD_ACT, user=UNIT_VALUE)),
             ("usd_newtype", changed(GOOD_ACT, usd=Con(NEWTYPE, number(U64, 9)))), ("usd_newtype_text", changed(GOOD_ACT, usd=Con(NEWTYPE, wrap("x")))), ("usd_newtype_newtype", changed(GOOD_ACT, usd=Con(NEWTYPE, Con(NEWTYPE, number(U64, 9))))), ("usd_text", changed(GOOD_ACT, usd="x")), ("usd_minus", changed(GOOD_ACT, usd=number(I64, MASK[8]))), ("usd_u8", changed(GOOD_ACT, usd=number(U8, 9))), ("usd_u16", changed(GOOD_ACT, usd=number(U16, 900))), ("usd_u32", changed(GOOD_ACT, usd=number(U32, 90000))), ("usd_i8", changed(GOOD_ACT, usd=number(I8, 9))), ("usd_unit", changed(GOOD_ACT, usd=UNIT_VALUE)), ("reordered", {"ethId": GOOD_ID, "usd": 1, "user": "0x" + USER})]
    names = ("user", "usd", "ethId")
    for mask in range(8):
        cases.append(("subset_%d" % mask, dict((name, GOOD_ACT[name]) for bit, name in enumerate(names) if mask >> bit & 1)))
    return cases


def nest_cases():
    return [("good", {"action": GOOD_ACT}), ("seq_good", [GOOD_ACT]), ("seq_empty", []), ("seq_long", [GOOD_ACT, 1]), ("seq_bad", [5]), ("empty_map", {}), ("extra_key", {"action": GOOD_ACT, "z": 1}), ("extra_first", map_of(("z", 1), ("action", GOOD_ACT))), ("near_key", {"action2": 1}), ("dup", map_of(("action", GOOD_ACT), ("action", GOOD_ACT))), ("int_key", map_of((0, GOOD_ACT))), ("u8_key", map_of((number(U8, 0), GOOD_ACT))), ("int_key_1", map_of((1, GOOD_ACT))), ("bytes_key", map_of((Con(BYTES, b"action"), GOOD_ACT))), ("str_key", map_of((Con(STR, "action"), GOOD_ACT))), ("bool_key", map_of((True, 1))), ("unit_key", map_of((UNIT_VALUE, 1))), ("newtype", {"action": Con(NEWTYPE, wrap(GOOD_ACT))}), ("not_struct_int", 5), ("not_struct_unit", UNIT_VALUE), ("inner_int", {"action": 5}), ("inner_seq", {"action": ["0x" + USER, 5, GOOD_ID]}), ("inner_bad_id", {"action": changed(GOOD_ACT, ethId=changed(GOOD_ID, h="0x"))})]


def lift(entry, value):
    level = DE_FORMS[entry][4]
    if level == "id":
        return value
    action = changed(GOOD_ACT, ethId=value)
    return action if level == "act" else {"action": action}


def lift_action(entry, value):
    return value if DE_FORMS[entry][4] == "act" else {"action": value}


def named_cases():
    cases = []
    for entry in sorted(FORMS):
        form = FORMS[entry]
        label = NAMES[entry]
        if form[1] == "event":
            cases += [Ser("%s_%d" % (label, index), entry, Action(event=index)) for index in range(6)]
            cases += [Ser("%s_%d_grow" % (label, index), entry, Action(event=index), 1, 0) for index in range(6)]
            continue
        modes = (1,) if form[0] == "j" else (1, 0)
        for named in modes:
            tail = "_named" if named else "_compact"
            for index in range(6):
                cases.append(Ser("%s%s_event_%d" % (label, tail, index), entry, Action(event=index), named))
            for value in EDGES:
                cases.append(Ser("%s%s_b_%x" % (label, tail, value), entry, Action(block=value), named))
                cases.append(Ser("%s%s_t_%x" % (label, tail, value), entry, Action(t=value), named))
                cases.append(Ser("%s%s_i_%x" % (label, tail, value), entry, Action(i=value), named))
                if form[1] != "id":
                    cases.append(Ser("%s%s_usd_%x" % (label, tail, value), entry, Action(usd=value), named))
            for capacity in (0, 1, 2, 3, 4, 5, 6, 7, 9, 10, 12, 16, 24, 30, 40, 50, 60, 64, 70, 80, 90, 100, 120, 130, 140, 150, 170, 200):
                cases.append(Ser("%s%s_capacity_%d" % (label, tail, capacity), entry, Action(block=0x11223344556677, i=0x10000), named, capacity))
            cases.append(Ser("%s%s_zero_bytes" % (label, tail), entry, Action(digest=bytes(32), user=bytes(20)), named))
            cases.append(Ser("%s%s_ff_bytes" % (label, tail), entry, Action(digest=b"\xff" * 32, user=b"\xff" * 20), named))
    for entry in DECODERS:
        label = NAMES[entry]
        for name, value in id_cases():
            cases.append(De("%s_id_%s" % (label, name), entry, lift(entry, value)))
        if DE_FORMS[entry][4] != "id":
            for name, value in action_cases():
                cases.append(De("%s_act_%s" % (label, name), entry, lift_action(entry, value)))
        if DE_FORMS[entry][4] == "nest":
            for name, value in nest_cases():
                cases.append(De("%s_nest_%s" % (label, name), entry, value))
    return cases


def lcg(seed):
    state = seed
    while True:
        state = (state * 0x5851F42D4C957F2D + 0x14057B7EF767814F) & MASK[8]
        yield state >> 16


def vector_cases(count):
    cases = []
    random = lcg(0xE7E)
    serializers = sorted(FORMS)
    decoders = DECODERS
    for index in range(count):
        width = next(random) % 65
        values = [next(random) >> (48 - min(width, 48)) for _ in range(4)]
        digest = bytes(next(random) & 0xFF for _ in range(32))
        user = bytes(next(random) & 0xFF for _ in range(20))
        event = next(random) % 6
        action = Action(values[0], values[1], values[2], values[3], event, digest, user)
        if index % 2:
            entry = serializers[next(random) % len(serializers)]
            cases.append(Ser("vector_%03d" % index, entry, action, next(random) & 1, next(random) % 240))
            continue
        entry = decoders[next(random) % len(decoders)]
        text = "0x" + digest.hex() if next(random) & 1 else digest.hex().upper()
        identity = {"b": values[1], "t": values[2], "e": EVENTS[event], "i": values[3], "h": text}
        if next(random) & 1:
            identity = [values[1], values[2], EVENTS[event], values[3], text]
        cases.append(De("vector_%03d" % index, entry, lift(entry, identity)))
    return cases


def describe_case(case, outcome):
    if outcome[0] == "bytes":
        return outcome[1]
    if outcome[0] == "error":
        return "error: " + outcome[1].encode("unicode_escape").decode().replace("@", "\\x40")
    return "ok: " + " ".join(str(item) for item in outcome[1:])


def check_all(harness, cases):
    done = []
    for case in cases:
        got = run_case(harness, case)
        want = spec_run(case)
        if got != want:
            raise EvidenceError("case %s differs: %s against %s" % (case.name, got, want))
        done.append((case, got))
    return done


SERIALIZER_COPIES = ((0x46CC580, FLAT_MP_A), (0x5925BB0, FLAT_MP_A), (0x421CF30, NEST_MP_A), (0x592E950, NEST_MP_A),
                     (0x46CC8B0, FLAT_MP_B), (0x5925520, FLAT_MP_B), (0x592E710, NEST_MP_B), (0x5925730, ACT_JSON),
                     (0x46CC1A0, FLAT_JSON), (0x5926010, FLAT_JSON))
DECODER_COPIES = ((0x39EFD10, DE_ACT_R), (0x572CE20, DE_ACT_R), (0x3A85FE0, DE_ACT_J))
EVENT_POOLS = (0x643E050, 0x648A528, 0x64BC6C0)
TEXT_ROWS = ((0x5E68E0, "ethId"), (0x5E68EC, "VoteEthDepositAction"), (0x60C8CC, "l1ValidatorVoteBridgeDeposit"),
             (0x5E75A8, "L1ValidatorVoteBridgeDepositAction"), (0x5C8D28, "struct EthEventId"))
MUTANT_SCENARIOS = 6
WORKERS = 4
SAMPLE_EVERY = 2
SURVIVED = "class: equal outcome on every picked case that reaches the row, such as a spill slot, a register choice or a word no rule reads"
MUTANT_STATE = {}


def row_at(image, va):
    return decode(lambda at, count: bytes(image.blob[image.offset(at):image.offset(at) + count]), va)


def edits_for(image, rows):
    edits = []
    for row in rows:
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


def first_failure(harness, cases, wants):
    for case, want in zip(cases, wants):
        try:
            if run_case(harness, case) != want:
                return case
        except (Halt, EvidenceError, Panicked, KeyError, IndexError, ValueError, OverflowError, ZeroDivisionError, UnicodeDecodeError, struct.error):
            return case
    return None


def spread(items, count):
    """The cheapest half of the picked count and an even walk over the rest, so rare cases stay in."""
    if len(items) <= count:
        return items
    head = items[:count // 2]
    rest = items[count // 2:]
    step = len(rest) / (count - count // 2)
    return head + [rest[int(index * step)] for index in range(count - count // 2)]


def mutant_job(job):
    va, kind, patch = job
    state = MUTANT_STATE
    picked = spread([case for case in state["order"] if va in state["reach"][case.name]], MUTANT_SCENARIOS)
    harness = Harness(state["image"], patch, state["cache"])
    harness.machine.step_limit = MUTANT_STEP_LIMIT
    hit = first_failure(harness, picked, [state["wants"][case.name] for case in picked])
    return va, kind, "killed" if hit is not None else "survived", hit.name if hit is not None else SURVIVED


def run_mutants(image, table, cases):
    control = Harness(image)
    control.machine.step_limit = MUTANT_STEP_LIMIT
    wants, reach, cost = {}, {}, {}
    for case in cases:
        control.machine.seen = set()
        before = control.machine.steps
        got = run_case(control, case)
        want = spec_run(case)
        if got != want:
            raise EvidenceError("an unedited image fails on %s" % case.name)
        wants[case.name], reach[case.name], cost[case.name] = want, control.machine.seen, control.machine.steps - before
    order = sorted(cases, key=lambda item: (cost[item.name], item.name))
    jobs = []
    for target in sorted(table):
        jobs += edits_for(image, table[target])[::SAMPLE_EVERY]
    MUTANT_STATE.update(image=image, order=order, reach=reach, wants=wants, cache=control.machine.cache)
    with multiprocessing.get_context("fork").Pool(WORKERS) as pool:
        return pool.map(mutant_job, jobs, 8)


def key_rows(image, table):
    """Rows the reconstruction binds: the msgpack head byte of each writer and the Content tag tests of each reader."""
    out = []
    for target in TARGETS:
        rows = table[target]
        if target in DE_FORMS:
            wanted, seen = (0x14, 0x15, 0x13), {}
            for row in rows:
                if row.op == "cmp" and row.width == 1 and row.imm_at is not None and row.data[row.imm_at] in wanted and row.data[row.imm_at] not in seen:
                    seen[row.data[row.imm_at]] = row
            notes = {0x14: "Content tag 0x14: sequence", 0x15: "Content tag 0x15: map", 0x13: "Content tag 0x13: newtype"}
            found = [(row, notes[tag]) for tag, row in sorted(seen.items())]
        else:
            heads = [row for row in rows if row.op == "or" and row.imm_at is not None and row.data[row.imm_at] in (0x82, 0x83, 0x84, 0x85)]
            found = [(row, "msgpack head %#x: field count %d, flag picks map or array" % (row.data[row.imm_at], row.data[row.imm_at] & 15)) for row in heads[:1]]
            if not found:
                counts = [row for row in rows if row.op == "mov" and row.size == 5 and row.data[0] == 0xBA and row.data[1] in (2, 3, 4, 5)]
                found = [(row, "field count %d passed in edx to the map length helper" % row.data[1]) for row in counts[:1]]
        if not found:
            raise EvidenceError("no bound row in %#x" % target)
        for row, note in found:
            again = row_at(image, row.va)
            if again.op != row.op or again.size != row.size:
                raise EvidenceError("row %#x moved" % row.va)
            out.append((NAMES[target], "%#x" % row.va, bytes(image.blob[image.offset(row.va):image.offset(row.va) + row.size]).hex(), row.op, note))
    return out


def event_rows(image):
    rows = []
    relative = image.relative()
    for pool in EVENT_POOLS:
        for index, name in enumerate(EVENTS):
            slot = pool + 16 * index
            at = relative[slot]
            size = struct.unpack_from("<Q", image.blob, image.offset(slot + 8))[0]
            text = bytes(image.blob[image.offset(at):image.offset(at) + size]).decode()
            if text != name:
                raise EvidenceError("event pool %#x row %d is %s" % (pool, index, text))
            rows.append((index, name, "%#x" % pool, "%#x" % at, size))
    return rows


def text_rows(image):
    rows = []
    for at, text in TEXT_ROWS:
        data = bytes(image.blob[image.offset(at):image.offset(at) + len(text)]).decode()
        if data != text:
            raise EvidenceError("text at %#x is %s" % (at, data))
        rows.append(("%#x" % at, text))
    return rows


def copy_rows(image, harness, cases):
    rows = []
    for copy, base in SERIALIZER_COPIES:
        FORMS[copy] = FORMS[base]
        count = 0
        for named in (1, 0):
            for event in range(6):
                case = Ser("copy", copy, Action(usd=0x100 + event, block=0x10000 * event, event=event), named, 7 * event)
                if run_case(harness, case) != spec_ser(case):
                    raise EvidenceError("copy %#x differs" % copy)
                count += 1
        rows.append(("%#x" % copy, image.exact_fde(copy)[1] - copy, NAMES[base], "%#x" % base, count))
        del FORMS[copy]
    for copy, base in DECODER_COPIES:
        DE_FORMS[copy] = DE_FORMS[base]
        count = 0
        for item in cases:
            if isinstance(item, De) and item.entry == base:
                case = De("copy", copy, item.value)
                if run_case(harness, case) != spec_de(case):
                    raise EvidenceError("copy %#x differs on %s" % (copy, item.name))
                count += 1
        rows.append(("%#x" % copy, image.exact_fde(copy)[1] - copy, NAMES[base], "%#x" % base, count))
        del DE_FORMS[copy]
    return rows


def samples():
    action = Action(usd=100000000, block=0x11223344556677, t=0x7F, i=0x10000, event=0)
    out = []
    for entry in sorted(FORMS):
        for named in ((1,) if FORMS[entry][0] == "j" else (1, 0)):
            out.append(Ser("sample", entry, action, named))
    return out


def analyse(image, mutate=True, vectors=9000):
    harness = Harness(image)
    cases = named_cases()
    named = check_all(harness, cases)
    generated = vector_cases(vectors)
    check_all(harness, generated)
    seen = set(harness.machine.seen)
    table = {}
    for target in TARGETS:
        low, high = image.exact_fde(target)
        table[target] = [row_at(image, va) for va in sorted(seen) if low <= va < high]
        for row in table[target]:
            row.data = bytes(image.blob[image.offset(row.va):image.offset(row.va) + row.size])
    wire = [(NAMES[case.entry], case.named, harness.serialize(case).hex()) for case in samples()]
    result = dict(table=table, named=named, vector_count=vectors, keys=key_rows(image, table), events=event_rows(image), texts=text_rows(image), copies=copy_rows(image, harness, cases), wire=wire, sizes={target: image.exact_fde(target)[1] - target for target in TARGETS})
    result["negatives"] = negative_controls(image, harness, named, table)
    missed = [row for row in result["negatives"] if not row[3]]
    if missed:
        raise EvidenceError("negative control not caught: %s" % (missed,))
    if mutate:
        result["mutations"] = run_mutants(image, table, [case for case, _ in named] + generated[:40])
    return result


def render(result):
    files = {}

    def tsv(name, header, rows):
        lines = ["\t".join(header)] + ["\t".join(str(cell) for cell in row) for row in rows]
        files[name] = "\n".join(lines) + "\n"

    table = result["table"]
    sizes = result["sizes"]
    tsv("function-rows.tsv", ("function", "address", "size", "bytes", "operation"), [(NAMES[target], "%#x" % row.va, row.size, bytes(row.data).hex(), row.op) for target in TARGETS for row in table[target]])
    tsv("path.tsv", ("name", "address", "body_bytes", "reached_rows", "reached_bytes"), [(NAMES[target], "%#x" % target, sizes[target], len(table[target]), sum(row.size for row in table[target])) for target in TARGETS])
    tsv("events.tsv", ("index", "name", "pool", "text_at", "text_size"), result["events"])
    tsv("texts.tsv", ("address", "text"), result["texts"])
    tsv("copies.tsv", ("copy", "body_bytes", "same_rules_as", "primary", "cases_matched"), result["copies"])
    tsv("wire-samples.tsv", ("function", "named", "bytes"), result["wire"])
    tsv("key-rows.tsv", ("function", "at", "bytes", "operation", "note"), result["keys"])
    rows = []
    for case, trace in result["named"]:
        if isinstance(case, Ser):
            rows.append((case.name, "%d bytes sha256 %s" % (len(trace[1]) // 2, hashlib.sha256(trace[1].encode()).hexdigest()[:16])))
        else:
            rows.append((case.name, describe_case(case, trace)))
    tsv("scenarios.tsv", ("case", "outcome"), rows)
    if "mutations" in result:
        tsv("mutations.tsv", ("address", "kind", "outcome", "detail"), [("%#x" % va, kind, outcome, detail) for va, kind, outcome, detail in result["mutations"]])
    tsv("negatives.tsv", ("group", "kind", "control", "outcome"), [(a, b, c, "caught" if d else "missed") for a, b, c, d in result["negatives"]])
    named = result["named"]
    reached = sum(row.size for rows in table.values() for row in rows)
    summary = {"binary": "artifacts/node/115/hl-node", "sha256": SHA256, "functions": len(TARGETS), "instructions": sum(len(items) for items in table.values()), "named_scenarios": len(named), "serializer_cases": sum(1 for case, _ in named if isinstance(case, Ser)), "decoder_cases": sum(1 for case, _ in named if isinstance(case, De)), "vector_scenarios": result["vector_count"], "body_bytes": sum(sizes.values()), "reached_bytes": reached, "unreached_rows": sum(sizes.values()) - reached, "copies": len(result["copies"])}
    if "mutations" in result:
        items = result["mutations"]
        summary["mutations"] = {"total": len(items), "killed": sum(1 for item in items if item[2] == "killed"), "survived": sum(1 for item in items if item[2] == "survived")}
    cases = len(named) + result["vector_count"] + sum(row[4] for row in result["copies"])
    summary["cases"] = cases
    summary["negative_controls"] = len(result["negatives"])
    summary["negative_detected"] = sum(1 for row in result["negatives"] if row[3])
    files["measure.json"] = json.dumps({"cases": cases, "negative_controls": summary["negative_controls"], "negative_detected": summary["negative_detected"]}, indent=1, sort_keys=True) + "\n"
    files["evidence.json"] = json.dumps(summary, indent=1, sort_keys=True) + "\n"
    return files


def bound_imm_rows(target, rows):
    """The reached rows whose immediate byte the reconstruction ties to the wire: msgpack head byte, map length or Content tag."""
    if target in DE_FORMS:
        picked = {}
        for row in rows:
            if row.op == "cmp" and row.width == 1 and row.imm_at is not None and row.data[row.imm_at] in (0x14, 0x15):
                picked.setdefault(row.data[row.imm_at], row)
        return [picked[tag] for tag in sorted(picked)]
    heads = [row for row in rows if row.op == "or" and row.imm_at is not None and row.data[row.imm_at] in (0x82, 0x83, 0x84, 0x85)]
    if heads:
        return heads[:1]
    return [row for row in rows if row.op == "mov" and row.size == 5 and row.data[0] == 0xBA and row.data[1] in (2, 3, 4, 5)][:1]


def patched(name, replacement):
    """Swap one module function for a wrong reconstruction; returns the restore callable."""
    table = globals()
    saved = table[name]
    table[name] = replacement
    return lambda: table.__setitem__(name, saved)


def spec_mutants():
    original = {name: globals()[name] for name in ("mp_uint", "mp_str", "json_pack", "id_shape", "action_shape", "spec_struct", "spec_hex", "spec_u64", "unwrap", "unwrap_all", "describe", "mp_pack")}

    def uint_low(value):
        return b"\xcc" + bytes([value]) if value == 0x7F else original["mp_uint"](value)

    def uint_wide(value):
        return b"\xce" + value.to_bytes(4, "big") if 0xFF < value < 0x10000 else original["mp_uint"](value)

    def str_short(text):
        data = text.encode()
        return bytes([0xD9, len(data)]) + data if 27 < len(data) < 32 else original["mp_str"](text)

    def json_four(item, depth=0):
        return original["json_pack"](item, depth).replace("  ", "    ")

    def json_tight(item, depth=0):
        return original["json_pack"](item, depth).replace('": ', '":')

    def id_swapped(action):
        rows = original["id_shape"](action)
        return [rows[1], rows[0]] + rows[2:]

    def action_swapped(action):
        rows = original["action_shape"](action)
        return [rows[1], rows[0], rows[2]]

    def compact_keys(item, named):
        return original["mp_pack"](item, True)

    def deny_off(value, name, names, readers, deny, flavor):
        return original["spec_struct"](value, name, names, readers, False, flavor)

    def hex_upper_refused(value, size, flavor):
        if value.kind in (STRING, STR) and any(ch in "ABCDEF" for ch in value.value):
            raise Bad("invalid hex digit")
        return original["spec_hex"](value, size, flavor)

    def u64_zero(value, flavor):
        return 0

    def unwrap_off(value):
        return value

    def unwrap_all_one(value):
        return original["unwrap"](value)

    def describe_blank(value, flavor):
        return "value"

    return (("uint_fixint_edge", "mp_uint", uint_low), ("uint_width_odd", "mp_uint", uint_wide), ("str_width_early", "mp_str", str_short),
            ("json_indent_four", "json_pack", json_four), ("json_tight_colon", "json_pack", json_tight), ("id_fields_swapped", "id_shape", id_swapped),
            ("action_fields_swapped", "action_shape", action_swapped), ("compact_keeps_keys", "mp_pack", compact_keys), ("unknown_key_accepted", "spec_struct", deny_off),
            ("hex_upper_refused", "spec_hex", hex_upper_refused), ("u64_always_zero", "spec_u64", u64_zero), ("newtype_never_unwrapped", "unwrap", unwrap_off),
            ("newtype_unwrapped_once", "unwrap_all", unwrap_all_one), ("error_text_blank", "describe", describe_blank))


def negative_controls(image, harness, named, table):
    """Deliberately wrong reconstructions, corrupted bytes and bad inputs; each must be caught."""
    rows = []
    cache = harness.machine.cache
    serial = {}
    for case, _ in named:
        serial.setdefault(case.entry, []).append(case)
    for target in TARGETS:
        pool = serial[target]
        picked = spread(pool, 40)
        wants = [spec_run(case) for case in picked]
        for row in bound_imm_rows(target, table[target]):
            patch = {row.va + row.imm_at: row.data[row.imm_at] ^ 1}
            run = Harness(image, patch, cache)
            run.machine.step_limit = MUTANT_STEP_LIMIT
            hit = first_failure(run, picked, wants)
            rows.append((NAMES[target], "byte", "flip the low bit of the immediate at %#x" % (row.va + row.imm_at), hit is not None))
    for target in sorted(FORMS):
        saved = FORMS[target]
        wrong = ("a", "act") if saved[1] != "act" else ("a", "flat")
        FORMS[target] = wrong
        try:
            case = Ser("wrong_form", target, Action(), 1)
            run = Harness(image)
            run.machine.step_limit = MUTANT_STEP_LIMIT
            hit = first_failure(run, [case], [spec_ser(case)]) is not None
        finally:
            FORMS[target] = saved
        rows.append((NAMES[target], "form", "run as the %s writer of the rule list" % wrong[1], hit))
    for label, name, fn in spec_mutants():
        restore = patched(name, fn)
        try:
            caught = any(spec_run(case) != got for case, got in named)
        except Exception:
            caught = True
        finally:
            restore()
        rows.append(("rule list", "spec", label, caught))
    other = bytes(image.blob)
    checks = []

    def refuses(call):
        try:
            call()
        except (EvidenceError, ValueError, KeyError, struct.error):
            return True
        return False

    checks.append(("input", "sha", "image with a changed digest", lambda: load_image(BINARY, "0" * 64)))
    checks.append(("input", "address", "non-FDE-start target", lambda: image.exact_fde(TARGETS[0] + 1)))
    checks.append(("input", "address", "address outside every section", lambda: image.offset(0x10)))
    cut = Image(other)
    cut.named = dict(cut.named)
    cut.named[".rela.dyn"] = dict(cut.named[".rela.dyn"], size=cut.named[".rela.dyn"]["size"] + 1)
    checks.append(("input", "section", "truncated RELA section", lambda: list(cut.relocations())))
    damaged = bytearray(other)
    first = image.relative()[EVENT_POOLS[0]]
    damaged[image.offset(first)] ^= 0x20
    bad_image = Image(bytes(damaged))
    checks.append(("input", "bytes", "changed first event name byte", lambda: event_rows(bad_image)))
    damaged = bytearray(other)
    damaged[image.offset(TEXT_ROWS[0][0])] ^= 0x20
    bad_text = Image(bytes(damaged))
    checks.append(("input", "bytes", "changed ethId text byte", lambda: text_rows(bad_text)))
    for kind, group, label, call in checks:
        rows.append((kind, group, label, refuses(call)))
    return rows


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

