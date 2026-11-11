#!/usr/bin/env python3
"""Reconstruct the node #115 vault amount accumulation body 0x3beb980 together with its per-entry amount body 0x448b800 and prove it.

The body walks a map of 64-byte parameter rows, held either as a ring buffer (VecDeque) or as a B-tree chosen by a niche word, skips rows
whose first dword is set unless a flag byte is given, reduces each key modulo 10000 to pick a 96-byte row of a second array, asks the
per-entry body for an amount (a rounding mode byte, a cap byte and a context word select the rule) and adds four results into four
saturating accumulators, each saturation raising an overflow event. The real bytes of the loop, of the per-entry body 0x448b800 and of the
B-tree step 0x37c5ba0 run in a small x86-64 evaluator; the pointer slots they call through are recording stubs. A separately written rule
list predicts every result and every event, 28 named wrong readings must be refused, and every reached condition, immediate and field
displacement of the three bodies is edited. No objdump or readelf output is parsed and the binary is never executed. Standard library only.

    python3 tools/vault_base_conversion115.py --out <dir>
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
        self.branches = collections.Counter()

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
            taken = self.condition(row.cc)
            self.branches[(row.va, taken)] += 1
            return row.target if taken else row.next
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
            left, right = self.get(row.a, width), self.get(row.b, width)
            left -= (1 << (8 * width)) if left & SIGN[width] else 0
            right -= (1 << (8 * width)) if right & SIGN[width] else 0
            product = left * right
            self.cf = self.of = not -(SIGN[width]) <= product < SIGN[width]
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



# --- the subject bodies ----------------------------------------------------------------------------------------------------------

LOOP = 0x3BEB980        # accumulate over a map of per-entry parameter rows
RANGE = 0x37C5BA0       # B-tree iterator step (real code)
CALLEE = 0x448B800      # per-entry amount (reached through a pointer slot)
JUMP_TABLE = 0x7CF4CC
MAGIC = 0x346DC5D63886594B

SLOT_LOOP = 0x64E6D20
SLOT_CALLEE, SLOT_EVENT, SLOT_BOUNDS, SLOT_UNWRAP = 0x64E95D8, 0x64E4EA8, 0x64DF620, 0x64DF830
SLOT_PREP, SLOT_DOWN, SLOT_UP = 0x64E6DC0, 0x64E8BA8, 0x64E9508
HOOK_SLOTS = (SLOT_EVENT, SLOT_BOUNDS, SLOT_UNWRAP, SLOT_PREP, SLOT_DOWN, SLOT_UP)
LOC_SIGNED, LOC_UNSIGNED, LOC_CALLEE = 0x64765B8, 0x64765D0, 0x648BA50
MARK_BASE = 0x5555000000

OUT = HEAP_BASE + 0x100
SELF = HEAP_BASE + 0x200
SELF_SIZE = 0x50
ARRHDR = HEAP_BASE + 0x300
ARR = HEAP_BASE + 0x1000
RING = HEAP_BASE + 0x2000
ARENA = HEAP_BASE + 0x4000
ROW = HEAP_BASE + 0x400
USED = 0x14000
STACK_ARG = STACK_TOP - 0x100
NICHE = 0x8000000000000000
INT_MIN, INT_MAX, U64 = -(1 << 63), (1 << 63) - 1, (1 << 64) - 1
LEAF_SIZE, NODE_SIZE = 0x328, 0x388


class Case:
    """One input: the map, the 96-byte row array, the flag byte, the rounding mode, the cap byte, the context word and the start sum."""
    __slots__ = ("name", "store", "items", "cap", "head", "height", "chunks", "flag", "mode", "capb", "ctx", "rows", "start", "junk")

    def __init__(self, name, store, items, rows, flag=1, mode=1, capb=255, ctx=0, start=0, cap=0, head=0, height=0, chunks=None, junk=0):
        self.name, self.store, self.items, self.rows = name, store, items, rows
        self.flag, self.mode, self.capb, self.ctx, self.start = flag, mode, capb, ctx, start
        self.cap, self.head, self.height, self.chunks, self.junk = cap, head, height, chunks, junk


class AmountCase:
    """A direct call of the per-entry body: one parameter row, one amount word, the mode byte, the cap byte and the context word."""
    __slots__ = ("name", "store", "row", "value", "mode", "capb", "ctx", "junk")

    def __init__(self, name, row, value, mode, capb, ctx, junk=0):
        self.name, self.store, self.row, self.value, self.mode, self.capb, self.ctx, self.junk = name, "amount", row, value, mode, capb, ctx, junk


def row_value(tag=0, div=1, off=0, mult=1, prec=0):
    return (tag, div, off, mult, prec)


# --- the independent rule list ----------------------------------------------------------------------------------------------------

def sat_signed(total, delta, loc, log, wrap=False):
    result = total + delta
    if INT_MIN <= result <= INT_MAX:
        return result
    log.append(("overflow", loc))
    if wrap:
        return (result + (1 << 63)) % (1 << 64) - (1 << 63)
    return INT_MAX if delta > 0 else INT_MIN


def sat_unsigned(total, delta, loc, log, wrap=False):
    result = total + delta
    if result <= U64:
        return result
    log.append(("overflow", loc))
    return result & U64 if wrap else U64


def stub_quotient(mode, magnitude, ctx, prec):
    scaled = magnitude * (prec + 1) + ctx
    return (scaled // 3 if mode == 2 else (scaled + 2) // 3) & U64


def amount_spec(row, value, mode, capb, ctx, log, flags=frozenset()):
    """The per-entry amount: returns ('ok', flag, total, second, magnitude, offset, quotient) or ('panic', 'unwrap') or ('halt',)."""
    tag, div, off, mult, prec = row
    if value >= 1 << 63 and "negative_allowed" not in flags:
        return ("panic", "unwrap")
    product = value * mult
    if "negative_allowed" in flags and value >= 1 << 63:
        product = (value - (1 << 64)) * mult
    if not INT_MIN <= product <= INT_MAX:
        if "multiplier_wraps" not in flags:
            return ("panic", "unwrap")
        product = (product + (1 << 63)) % (1 << 64) - (1 << 63)
    magnitude = product if "abs_not_taken" in flags and product >= 0 else abs(product)
    if "abs_not_taken" in flags and product < 0:
        magnitude = product & U64
    if mode == 0:
        quotient = 1 if "mode0_quotient_one" in flags else 0
    elif mode == 1:
        divisor = min(div, capb) if "mode1_uses_cap" in flags else div
        if divisor == 0:
            return ("halt",)
        quotient = magnitude // divisor
    elif mode == 4:
        divisor = div if "mode4_ignores_cap" in flags else max(div, capb) if "mode4_max_instead_of_min" in flags else min(div, capb)
        if divisor == 0:
            return ("halt",)
        quotient = magnitude // divisor
    elif mode in (2, 3):
        swapped = mode ^ 1 if "modes_2_3_swapped" in flags else mode
        log.append(("prep", ctx, prec))
        log.append(("down" if swapped == 2 else "up", magnitude))
        quotient = stub_quotient(swapped, magnitude, ctx, prec)
    else:
        raise ValueError("mode outside the jump table")
    carries = tag != 0 if "tag_nonzero_adds" in flags else tag == 1
    if carries:
        total = product + off
        if not INT_MIN <= total <= INT_MAX:
            log.append(("overflow", LOC_CALLEE))
            if "offset_wraps" in flags:
                total = (total + (1 << 63)) % (1 << 64) - (1 << 63)
            else:
                total = INT_MAX if off > 0 else INT_MIN
        second = total if "second_unclamped" in flags else max(total, 0)
        return ("ok", 1, total, second, magnitude, off, quotient)
    return ("ok", 0, product, quotient, magnitude, 0, quotient)


def spec_case(case, flags=frozenset()):
    if isinstance(case, AmountCase):
        log = []
        result = amount_spec(case.row, case.value, case.mode, case.capb, case.ctx, log, flags)
        if result[0] == "halt":
            return ("halt", "Halt"), []
        return result, log
    return spec_loop(case, flags)


def ordered_items(case, flags=frozenset()):
    items = list(case.items)
    if "reverse_order" in flags:
        items.reverse()
    if "first_entry_only" in flags:
        items = items[:1]
    return items


def spec_loop(case, flags=frozenset()):
    """Outcome and event log of the accumulation loop; the rule list is written from the 'Rules' table of the README."""
    log = []
    acc = [case.start, 0, 0, case.start]
    if "init_zero" in flags:
        acc = [0, 0, 0, 0]
    if "init_only_first" in flags:
        acc[3] = 0
    modulus = {"index_mod_9999": 9999, "index_mod_10001": 10001}.get(next((f for f in flags if f.startswith("index_")), ""), 10000)
    skip_flag = case.flag & 0xFF
    if "flag_ignored" in flags:
        skip_flag = 0
    for key, row in ordered_items(case, flags):
        skipped = row[0] != 0
        if "no_skip" in flags:
            skipped = False
        elif "invert_skip" in flags:
            skipped = row[0] == 0
        if skipped and not skip_flag:
            continue
        index = key % modulus
        length = len(case.rows) + (1 if "bounds_off_by_one" in flags else 0)
        if index >= length:
            return ("panic", "bounds", acc[0], acc[1], acc[2], acc[3]), log
        value = case.rows[index] if index < len(case.rows) else 0
        result = amount_spec(row, value, case.mode, case.capb, case.ctx, log, flags)
        if result[0] == "halt":
            return ("halt", "Halt"), []
        if result[0] == "panic":
            return result, log
        _, flagged, first, second, magnitude, offset, _quotient = result
        loc_a, loc_b = (LOC_UNSIGNED, LOC_SIGNED) if "locations_swapped" in flags else (LOC_SIGNED, LOC_UNSIGNED)
        acc[0] = sat_signed(acc[0], first, loc_a, log, "acc0_wraps" in flags)
        acc[1] = sat_unsigned(acc[1], second if second >= 0 else second & U64, loc_b, log, "acc1_wraps" in flags)
        third = magnitude if "swap_second_third" not in flags else second
        acc[2] = sat_unsigned(acc[2], third if third >= 0 else third & U64, loc_b, log, "acc2_wraps" in flags)
        carried = offset if flagged else row[2] if "offset_always_added" in flags else 0
        acc[3] = sat_signed(acc[3], carried, loc_a, log, "acc3_wraps" in flags)
    return ("ok", acc[0], acc[1], acc[2], acc[3]), log


# --- evaluator harness -----------------------------------------------------------------------------------------------------------

def split_tree(sorted_items, height, chunks):
    """Shape of a B-tree of the given height: (separator items, child shapes); leaves are (items, None)."""
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


def shape_ok(shape, height):
    keys, children = shape
    if not keys or len(keys) > 11:
        return False
    if height == 0:
        return children is None
    return children is not None and len(children) == len(keys) + 1 and all(shape_ok(child, height - 1) for child in children)


def shape_walk(shape):
    keys, children = shape
    if children is None:
        return list(keys)
    out = []
    for index, child in enumerate(children):
        out += shape_walk(child)
        if index < len(keys):
            out.append(keys[index])
    return out


def tree_shape(case):
    """None when the requested height cannot be built from the items."""
    if not case.items:
        return None
    shape = split_tree(list(case.items), case.height, list(case.chunks or ()))
    if not shape_ok(shape, case.height) or shape_walk(shape) != list(case.items):
        return None
    return shape


class Arena:
    def __init__(self, memory):
        self.memory, self.top = memory, ARENA

    def alloc(self, size):
        at = self.top
        self.top = (self.top + size + 15) & ~15
        if self.top > HEAP_BASE + USED:
            raise Halt("arena exhausted")
        return at


class Harness:
    def __init__(self, image, patches=None):
        self.image = image
        machine = Machine(image, patches)
        self.machine = machine
        machine.real = frozenset({RANGE, CALLEE})
        statics = machine.memory.statics
        statics[SLOT_CALLEE] = CALLEE
        for slot, hook in ((SLOT_EVENT, self.on_event), (SLOT_BOUNDS, self.on_bounds), (SLOT_UNWRAP, self.on_unwrap),
                           (SLOT_PREP, self.on_prep), (SLOT_DOWN, self.on_down), (SLOT_UP, self.on_up)):
            statics[slot] = MARK_BASE + slot
            machine.slots[MARK_BASE + slot] = hook
        self.case, self.log = None, []

    def expect(self, condition, text):
        if not condition:
            raise Halt("stub check failed: " + text)

    def on_event(self, machine):
        regs = machine.regs
        self.expect(regs[RDI] == 0, "event first argument")
        self.expect(regs[RSI] in (LOC_SIGNED, LOC_UNSIGNED, LOC_CALLEE), "event location")
        self.log.append(("overflow", regs[RSI]))

    def on_bounds(self, machine):
        raise Panicked("bounds")

    def on_unwrap(self, machine):
        raise Panicked("unwrap")

    def on_prep(self, machine):
        regs = machine.regs
        self.expect(regs[RDX] <= MASK[4], "prec is a dword")
        machine.memory.write(regs[RDI], 8, regs[RSI])
        machine.memory.write(regs[RDI] + 8, 8, regs[RDX])
        self.log.append(("prep", regs[RSI], regs[RDX]))

    def on_round(self, machine, name, mode):
        regs = machine.regs
        buf = regs[RDI]
        ctx, prec = machine.memory.read(buf, 8), machine.memory.read(buf + 8, 8)
        self.log.append((name, regs[RSI]))
        regs[RAX] = stub_quotient(mode, regs[RSI], ctx, prec)

    def on_down(self, machine):
        self.on_round(machine, "down", 2)

    def on_up(self, machine):
        self.on_round(machine, "up", 3)

    def put_row(self, at, row):
        memory = self.machine.memory
        tag, div, off, mult, prec = row
        memory.write(at, 4, tag)
        memory.write(at + 4, 4, div)
        memory.write(at + 8, 8, off & U64)
        memory.write(at + 0x10, 8, mult & U64)
        memory.write(at + 0x38, 4, prec)

    def build_node(self, arena, shape, height, parent, slot):
        memory = self.machine.memory
        keys, children = shape
        size = LEAF_SIZE if children is None else NODE_SIZE
        node = arena.alloc(size + 16)
        memory.put_bytes(node, bytes(0xC3 for _ in range(size)) + bytes(16))
        memory.write(node + 0x2C0, 8, parent)
        memory.write(node + 0x320, 2, slot)
        memory.write(node + 0x322, 2, len(keys))
        for index, (key, row) in enumerate(keys):
            memory.write(node + 0x2C8 + 8 * index, 8, key)
            self.put_row(node + 64 * index, row)
        if children is not None:
            for index, child in enumerate(children):
                memory.write(node + 0x328 + 8 * index, 8, self.build_node(arena, child, height - 1, node, index))
        return node

    def build_store(self, arena, case):
        memory = self.machine.memory
        if case.store == "deque":
            cap = case.cap
            slots = [None] * cap
            for index, item in enumerate(case.items):
                slots[(case.head + index) % cap] = item
            for physical in range(cap):
                at = RING + 72 * physical
                if slots[physical] is None:
                    memory.put_bytes(at, bytes(72 * [0x9D]))
                    continue
                memory.put_bytes(at + 8, bytes(64 * [0x6B]))
                memory.write(at, 8, slots[physical][0])
                self.put_row(at + 8, slots[physical][1])
            fields = (case.cap, RING, case.head, len(case.items))
        elif not case.items:
            fields = (NICHE, 0, 0, 0)
        else:
            root = self.build_node(arena, tree_shape(case), case.height, 0, 0)
            fields = (NICHE, root, case.height, len(case.items))
        for offset, value in zip((0, 8, 0x10, 0x18), fields):
            memory.write(SELF + offset, 8, value)
        memory.write(SELF + 0x48, 8, case.start & U64)

    def fresh(self, case):
        machine = self.machine
        memory = machine.memory
        memory.reset(USED)
        machine.xmm = [POISON | POISON << 64] * 16
        memory.put_bytes(HEAP_BASE, bytes((index * 29 + 5) & 0xFF for index in range(0x1000)))
        memory.put_bytes(SELF, bytes((0xA7 + 3 * index) & 0xFF for index in range(SELF_SIZE)))
        self.case, self.log = case, []
        for index, value in enumerate(case.rows):
            memory.put_bytes(ARR + 96 * index, bytes(96 * [0x3C]))
            memory.write(ARR + 96 * index + 0x20, 8, value)
        memory.write(ARRHDR, 8, 0x4444444444444444)
        memory.write(ARRHDR + 8, 8, ARR)
        memory.write(ARRHDR + 0x10, 8, len(case.rows))
        memory.write(STACK_ARG, 8, case.ctx)
        self.build_store(Arena(memory), case)
        return bytes(memory.heap[:USED])

    def run_amount(self, case):
        machine = self.machine
        memory = machine.memory
        memory.reset(USED)
        machine.xmm = [POISON | POISON << 64] * 16
        memory.put_bytes(HEAP_BASE, bytes((index * 29 + 5) & 0xFF for index in range(0x1000)))
        self.case, self.log = case, []
        memory.put_bytes(ROW, bytes(64 * [0x6B]))
        self.put_row(ROW, case.row)
        memory.put_bytes(OUT, bytes(0x30 * [0xE1]))
        before = bytes(memory.heap[:USED])
        try:
            machine.run(CALLEE, {RDI: OUT, RSI: ROW, RDX: case.value, RCX: case.mode | case.junk << 8, R8: case.capb | case.junk << 8, R9: case.ctx})
            self.expect(machine.regs[RAX] == OUT, "the body returns its result pointer")
            words = [memory.read(OUT + 8 * index, 8) for index in range(6)]
            if words[0] == 1:
                outcome = ("ok", 1, signed(words[1]), words[2], words[3], signed(words[4]), words[5])
            else:
                self.expect(words[0] == 0, "flag word")
                outcome = ("ok", 0, signed(words[1]), words[2], words[3], 0, words[2])
        except Panicked as panic:
            outcome = ("panic", str(panic))
        after = bytes(memory.heap[:USED])
        cut = OUT - HEAP_BASE
        if after[:cut] + after[cut + 0x30:] != before[:cut] + before[cut + 0x30:]:
            raise Halt("the body changed the heap outside the result")
        return outcome, self.log

    def run(self, case):
        if isinstance(case, AmountCase):
            return self.run_amount(case)
        before = self.fresh(case)
        machine = self.machine
        try:
            flag = case.flag | case.junk << 8
            machine.run(LOOP, {RDI: OUT, RSI: SELF, RDX: flag, RCX: case.mode | case.junk << 8, R8: case.capb | case.junk << 8, R9: ARRHDR})
            outcome = ("ok",) + tuple(machine.memory.read(OUT + 8 * index, 8) for index in range(4))
        except Panicked as panic:
            outcome = ("panic", str(panic))
            if str(panic) == "bounds":
                outcome += tuple(machine.memory.read(OUT + 8 * index, 8) for index in range(4))
        after = bytes(machine.memory.heap[:USED])
        cut = OUT - HEAP_BASE
        if after[:cut] + after[cut + 32:] != before[:cut] + before[cut + 32:]:
            raise Halt("the body changed the heap outside the result")
        return outcome, self.log


def signed_view(outcome):
    """Outcome words as the rule list states them: accumulators 0 and 3 are signed."""
    if outcome[0] == "ok":
        words = outcome[1:]
        return ("ok", signed(words[0]), words[1], words[2], signed(words[3]))
    if outcome[0] == "panic" and outcome[1] == "bounds":
        words = outcome[2:]
        return ("panic", "bounds", signed(words[0]), words[1], words[2], signed(words[3]))
    return outcome


def signed(word):
    return word - (1 << 64) if word >> 63 else word


# --- case generation -------------------------------------------------------------------------------------------------------------

def lcg(seed):
    state = seed & MASK[8]
    while True:
        state = (state * 6364136223846793005 + 1442695040888963407) & MASK[8]
        yield state >> 11


SMALL_DIV = (1, 2, 3, 7, 10, 100, 255, 256, 1000, 65535)
BIG_DIV = (1 << 31, (1 << 32) - 1, 3, 10)
SMALL_MULT = (0, 1, -1, 2, 3, 10, -10, 1000, 10 ** 6, 10 ** 9)
BIG_MULT = (1 << 31, 1 << 32, 10 ** 12, 1 << 62, -(1 << 62), INT_MAX, INT_MIN, 12345678901)
SMALL_VALUE = (0, 1, 2, 5, 100, 10 ** 6, (1 << 31) - 1)
BIG_VALUE = (1 << 32, 1 << 40, 1 << 62, INT_MAX, 1 << 63, U64)
SMALL_OFF = (0, 1, -1, 5, -5, 10 ** 9, -10 ** 9)
BIG_OFF = (1 << 62, -(1 << 62), INT_MAX, INT_MIN)
STARTS = (0, 0, 1, -1, 100, INT_MAX - 5, INT_MIN + 5, 1 << 62)
TAGS = (0, 0, 0, 1, 1, 2, 0xFFFFFFFF)


def draw_row(stream):
    big = next(stream) % 4 == 0
    divisors = BIG_DIV if big else SMALL_DIV
    return row_value(TAGS[next(stream) % len(TAGS)], divisors[next(stream) % len(divisors)], draw_pick(stream, SMALL_OFF, BIG_OFF),
                     draw_pick(stream, SMALL_MULT, BIG_MULT), next(stream) % 6 * 17)


def draw_pick(stream, small, big):
    pool = big if next(stream) % 40 == 0 else small
    return pool[next(stream) % len(pool)]


def draw_keys(stream, count, rows):
    keys = set()
    for _ in range(4 * count):
        if len(keys) >= count:
            break
        index = next(stream) % (len(rows) + (1 if next(stream) % 40 == 0 else 0))
        high = (0, 0, 1, 2, 7, 1 << 40, U64 // 10000 - 1)[next(stream) % 7]
        keys.add((high * 10000 + index) & U64)
    return sorted(keys)


def make_case(stream, index, forced=None):
    store = "deque" if next(stream) % 2 else "btree"
    rows = [draw_pick(stream, SMALL_VALUE, BIG_VALUE) for _ in range(1 + next(stream) % 8)]
    total = (1, 2, 3, 4, 5, 8, 11, 12, 14, 23)[next(stream) % 10]
    keys = draw_keys(stream, total, rows)
    items = [(key, draw_row(stream)) for key in keys]
    mode = (0, 1, 1, 2, 3, 4, 4)[next(stream) % 7]
    common = dict(flag=(0, 1, 1, 2, 0x80)[next(stream) % 5], mode=mode, capb=(1, 3, 255, 7, 2, 4, 0)[next(stream) % 7] if next(stream) % 6 else 1, ctx=next(stream) % 50,
                  start=STARTS[next(stream) % len(STARTS)], junk=next(stream) % 3 * 0x5A)
    if store == "deque":
        if next(stream) % 3 == 0:
            items = [(key, row) for key, row in items][::-1]
        cap = max(len(items), 1) + next(stream) % 4
        return Case("deque %d" % index, store, items, rows, cap=cap, head=next(stream) % cap, **common)
    height = 0 if len(items) <= 11 and next(stream) % 3 else 1 + next(stream) % 2
    chunks = [2 + next(stream) % 4 for _ in range(8)]
    case = Case("tree %d" % index, store, items, rows, height=height, chunks=chunks, **common)
    if items and tree_shape(case) is None:
        case.height, case.chunks = (0, None) if len(items) <= 11 else (1, [max(2, (len(items) + 10) // 11)])
        if tree_shape(case) is None:
            case.store, case.cap, case.head, case.height = "deque", len(items), 0, 0
    return case


def named_cases():
    cases = []
    one = row_value(0, 1, 0, 1, 0)
    rows = [100, 7, 1 << 40]

    def add(name, store, items, **kw):
        cases.append(Case(name, store, items, kw.pop("rows", rows), **kw))

    for store, extra in (("deque", dict(cap=4, head=0)), ("btree", dict(height=0))):
        add(store + " empty", store, [], **extra)
        add(store + " one entry", store, [(1, one)], **extra)
        add(store + " tag skipped", store, [(1, row_value(1, 1, 5, 1, 0))], flag=0, **extra)
        add(store + " tag taken with flag", store, [(1, row_value(1, 1, 5, 1, 0))], flag=1, **extra)
        add(store + " flag high byte only", store, [(1, row_value(1, 1, 5, 1, 0))], flag=0, junk=1, **extra)
        add(store + " bounds panic", store, [(1, one), (3, one)], **extra)
        add(store + " key mod 10000", store, [(20001, one), (30000, one)], **extra)
        add(store + " largest key reduces to zero", store, [(U64 - 1615, one)], **extra)
        add(store + " largest key bounds", store, [(U64, one)], **extra)
        add(store + " zero divisor", store, [(0, row_value(0, 0, 0, 1, 0))], mode=1, **extra)
        add(store + " zero divisor mode 4", store, [(0, row_value(0, 5, 0, 1, 0))], mode=4, capb=0, **extra)
        add(store + " negative amount panics", store, [(0, one), (1, one)], rows=[5, 1 << 63], **extra)
        add(store + " product overflow panics", store, [(0, row_value(0, 1, 0, INT_MAX, 0))], rows=[3], **extra)
        add(store + " min product", store, [(0, row_value(0, 3, 0, INT_MIN, 0))], rows=[1], mode=1, **extra)
        add(store + " offset saturates up", store, [(0, row_value(1, 1, INT_MAX, 5, 0))], rows=[3], **extra)
        add(store + " offset saturates down", store, [(0, row_value(1, 1, INT_MIN, -5, 0))], rows=[3], **extra)
        add(store + " accumulators saturate", store, [(0, row_value(1, 1, INT_MAX, INT_MAX, 0)), (1, row_value(1, 1, INT_MAX, INT_MAX, 0))],
            rows=[1, 1], start=INT_MAX - 2, **extra)
        add(store + " magnitude sum overflows", store, [(0, row_value(0, 1, 0, INT_MIN, 0)), (1, row_value(0, 1, 0, INT_MIN, 0)),
                                                         (2, row_value(0, 1, 0, 7, 0))], rows=[1, 1, 1], **extra)
        add(store + " unflagged offset stays out", store, [(0, row_value(0, 1, 9, 2, 0)), (1, row_value(2, 1, 9, 2, 0))], rows=[3, 3], flag=1, **extra)
        add(store + " magnitude overflow beside offset overflow", store,
            [(0, row_value(1, 1, INT_MAX, INT_MIN, 0)), (1, row_value(1, 1, INT_MIN, INT_MIN, 0)), (2, row_value(1, 1, INT_MAX, -3, 0))],
            rows=[1, 1, 1], start=INT_MIN + 1, **extra)
        add(store + " order matters", store, [(0, row_value(0, 1, 0, 1, 0)), (1, row_value(0, 1, 0, -1, 0)), (2, row_value(0, 1, 0, 1, 0))],
            rows=[1 << 62, 1 << 62, 1 << 62], start=INT_MAX - (1 << 62) + 1, **extra)
        for mode in range(5):
            add(store + " mode %d" % mode, store, [(0, row_value(0, 7, 0, 5, 9)), (1, row_value(1, 3, -4, 5, 2))], rows=[1000, 17], mode=mode,
                capb=2, ctx=11, flag=1, **extra)
    spread = [(key, row_value(key % 3 % 2, 1 + key % 4, key % 5 - 2, key % 7 - 3, key)) for key in range(23)]
    for count, height, chunks in ((11, 0, None), (12, 1, [2]), (23, 1, [2]), (23, 2, [3, 3, 3, 3]), (5, 1, [2])):
        for flag in (0, 1):
            cases.append(Case("tree %d entries height %d flag %d" % (count, height, flag), "btree", spread[:count], list(range(40, 63)),
                              flag=flag, mode=1, height=height, chunks=chunks))
    for cap, head in ((23, 0), (24, 5), (25, 24), (23, 22)):
        cases.append(Case("deque ring cap %d head %d" % (cap, head), "deque", spread, list(range(40, 63)), flag=1, mode=2, cap=cap, head=head))
    return cases


GRID_VALUES = (0, 1, 7, 100, (1 << 31) + 5, 1 << 62, INT_MAX, 1 << 63)
GRID_MULTS = (0, 1, -1, 3, -7, 1 << 32, INT_MIN)
GRID_ROWS = ((0, 7, 0, 3), (1, 3, -100, 9), (1, 1, INT_MAX, 0), (2, 255, 5, 1), (0, (1 << 32) - 1, 0, 200))


def grid_cases():
    """Every combination of five modes, eight amount words, seven multipliers and five parameter rows."""
    index = 0
    for mode in range(5):
        for value in GRID_VALUES:
            for mult in GRID_MULTS:
                for tag, div, off, prec in GRID_ROWS:
                    yield AmountCase("amount %d" % index, row_value(tag, div, off, mult, prec), value, mode, (1, 2, 255)[index % 3], 13)
                    index += 1


def random_cases(count, seed=0xB0A71E55):
    stream = lcg(seed)
    return (make_case(stream, index) for index in range(count))


# --- streaming comparison --------------------------------------------------------------------------------------------------------

VARIANTS = (
    "no_skip", "invert_skip", "flag_ignored", "index_mod_9999", "index_mod_10001", "bounds_off_by_one", "acc0_wraps", "acc1_wraps",
    "acc2_wraps", "acc3_wraps", "offset_always_added", "init_zero", "init_only_first", "swap_second_third", "locations_swapped",
    "reverse_order", "first_entry_only", "negative_allowed", "multiplier_wraps", "abs_not_taken", "mode0_quotient_one", "mode1_uses_cap",
    "mode4_ignores_cap", "mode4_max_instead_of_min", "modes_2_3_swapped", "tag_nonzero_adds", "offset_wraps", "second_unclamped",
)

# Byte edits that leave every result unchanged, each with the reason; the tool fails on an unlisted survivor and on a stale entry.
EQUIVALENT = {
    (0x3BEBA40, "immediate"): "stores zero into the unused back handle of the iterator; a forward step never reads it",
    (0x3BEBB2B, "displacement"): "copies row bytes 0x28..0x38 instead of 0x20..0x30 into the stack row copy; the per-entry body reads only +0, +4, +8, +0x10 and +0x38",
    (0x3BEBC31, "displacement"): "address computed into rdx on the path where the entry pointer is null; rdx is dead before the exit",
    (0x37C5BE7, "displacement"): "zeroes bytes 0x18..0x28 of the iterator instead of 0x10..0x20; the front handle words are rewritten at the end of the step and the back handle is never read",
    (0x37C5C25, "immediate"): "threshold 8 versus 9 on a path that is entered only with height % 8 != 0, so the height is never exactly 8",
    (0x37C5D08, "immediate"): "threshold 8 versus 9 on a path that is entered only with steps % 8 != 0, so the count is never exactly 8",
    (0x37C5D86, "displacement"): "stores the zero height at +0x18 instead of +0x10; +0x10 already holds zero on every path that reaches the store and +0x18 is rewritten next",
}


def run_case(harness, case):
    harness.machine.seen = set()
    try:
        outcome, log = harness.run(case)
        return (outcome if isinstance(case, AmountCase) else signed_view(outcome)), log
    except (Halt, EvidenceError, IndexError, KeyError, ValueError, OverflowError, struct.error) as problem:
        return ("halt", type(problem).__name__), []


def hexbits(value):
    return "0x%016x" % value


def check_stream(harness, cases, variants=(), keep=0, hits=None):
    """One real run per case, compared with the rule list and with every named deviation; only counters and sample rows are kept."""
    stats = {"cases": 0, "mismatches": 0, "first_mismatch": None, "kinds": collections.Counter(), "grid": []}
    caught = {name: [0, None] for name in variants}
    rows = []
    for index, case in enumerate(cases):
        got, log = run_case(harness, case)
        expected, expected_log = spec_case(case)
        stats["cases"] += 1
        stats["kinds"][(case.store, expected[0] if expected[0] != "panic" else "panic-" + expected[1])] += 1
        if (got, log) != (expected, expected_log):
            stats["mismatches"] += 1
            if stats["first_mismatch"] is None:
                stats["first_mismatch"] = (index, case.name, got, expected)
        for name in variants:
            if spec_case(case, frozenset((name,))) != (got, log):
                caught[name][0] += 1
                if caught[name][1] is None:
                    caught[name][1] = index
        if hits is not None:
            hits.update(harness.machine.seen)
        if isinstance(case, AmountCase):
            stats["grid"].append((case.name[7:], case.mode, case.row[0], hexbits(case.value), case.row[3], case.row[1], case.row[2], case.capb,
                                  expected[0] if expected[0] != "panic" else "panic-" + expected[1],
                                  ",".join(str(word) for word in expected[1:]) if expected[0] == "ok" else "", len(log)))
        elif keep and index % keep == 0:
            detail = ",".join(hexbits(word & U64) for word in expected[1:]) if expected[0] == "ok" else "/".join(map(str, expected[1:2]))
            rows.append((index, case.name, case.store, len(case.items), case.mode, expected[0], detail, len(log), len(harness.machine.seen)))
    return stats, caught, rows


def mutants_of(image, reached):
    """One edit for every reached conditional jump, immediate and structure field displacement of the three subject bodies."""
    out = []
    for entry in (LOOP, RANGE, CALLEE):
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
                if operand and operand[0] == "m" and operand[1] is not None and 0x8 <= abs(operand[4]) < 0x400 and operand[1] != RSP:
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
            if run_case(harness, case) != spec_case(case):
                killed, first = True, "%d" % index
                break
        rows.append((va, kind, at, old, new, killed, first))
    return rows


def structural_controls(image, cases):
    """Each entry: (name, detected, how)."""
    out = []

    def raises(name, thunk, *errors):
        try:
            thunk()
        except errors or (EvidenceError,) as problem:
            out.append((name, True, type(problem).__name__))
            return
        out.append((name, False, "no error"))

    pick = lambda text: next(case for case in cases if case.name == text)
    raises("wrong image digest", lambda: load_image(BINARY, "0" * 64), EvidenceError)
    raises("mid-function address is not an FDE start", lambda: image.exact_fde(LOOP + 1), EvidenceError)
    raises("address in a NOBITS section has no file bytes", lambda: image.offset(image.named[".bss"]["address"] + 8), EvidenceError)
    raises("decoder refuses a window that ends inside the body", lambda: decode_range(image, LOOP, image.exact_fde(LOOP)[1] - 1), EvidenceError)
    raises("truncated section table", lambda: Image(bytes(image.blob[:48])), Exception)
    saturating = pick("deque accumulators saturate")
    stripped = Harness(image)
    del stripped.machine.slots[MARK_BASE + SLOT_EVENT]
    raises("overflow event slot without a model", lambda: stripped.run(saturating), Halt)
    plain = Harness(image)
    plain.machine.real = frozenset({RANGE})
    raises("per-entry body not run as real code", lambda: plain.run(saturating), Halt)
    walker = Harness(image)
    walker.machine.real = frozenset({CALLEE})
    raises("tree walker not run as real code", lambda: walker.run(pick("tree 5 entries height 1 flag 1")), Halt)
    trapped = Harness(image, {LOOP: 0xCC})
    raises("entry byte replaced by int3", lambda: trapped.run(saturating), Halt)
    magic = [at for at in range(LOOP, LOOP + 994) if bytes(image.blob[image.offset(at):image.offset(at) + 8]) == MAGIC.to_bytes(8, "little")]
    out.append(("reciprocal constant located in the body", len(magic) == 1, "%d hits" % len(magic)))
    if len(magic) == 1:
        broken = Harness(image, {magic[0]: image.blob[image.offset(magic[0])] ^ 1})
        case = pick("deque key mod 10000")
        out.append(("tampered reciprocal constant", run_case(broken, case) != spec_loop(case), "mismatch"))
    out.append(("reciprocal agrees with division on the edge keys", all(reciprocal(x) == x // 10000 for x in EDGE_KEYS), "%d keys" % len(EDGE_KEYS)))
    wrong = lambda x: (x * (MAGIC ^ 1) >> 64) >> 11
    out.append(("one-bit wrong reciprocal is refused by some edge key", any(wrong(x) != x // 10000 for x in EDGE_KEYS), "mismatch"))
    return out


EDGE_KEYS = tuple(sorted({0, 1, 9999, 10000, 10001, 19999, 20000, 99999, 100000, (1 << 31) - 1, 1 << 31, (1 << 32) - 1, 1 << 32,
                          10 ** 12 - 1, 10 ** 12, 1 << 53, 1 << 62, (1 << 63) - 1, 1 << 63, U64 - 1, U64, U64 - 1615, U64 - 9999,
                          18446744073709550000, 18446744073709540000} | {n * 10000 + d for n in (3, 12345, 1844674407370955) for d in (-1, 0, 1)}))


def reciprocal(x):
    return (x * MAGIC >> 64) >> 11


# --- evidence tables ---------------------------------------------------------------------------------------------------------------

def layout_rows(image):
    """Fields of the map, the row array and the entry row: every displacement used through a base register by each body."""
    ops = collections.defaultdict(set)
    for entry in (LOOP, RANGE, CALLEE):
        for row in decode_range(image, *image.exact_fde(entry)):
            for operand in (row.a, row.b):
                if operand and operand[0] == "m" and operand[1] not in (None, RSP) and operand[2] is None:
                    ops[("%#x" % entry, REG_NAMES[operand[1]], operand[4])].add("%s/%d" % (row.op, row.width))
    return [(entry, base, "%#x" % disp, ";".join(sorted(ops[(entry, base, disp)]))) for entry, base, disp in
            sorted(ops, key=lambda k: (int(k[0], 16), k[1], k[2]))]


REG_NAMES = ("rax", "rcx", "rdx", "rbx", "rsp", "rbp", "rsi", "rdi", "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15")


def slot_rows(image):
    rel = image.relative()
    rows = []
    for slot in (SLOT_LOOP, SLOT_CALLEE, SLOT_EVENT, SLOT_BOUNDS, SLOT_UNWRAP, SLOT_PREP, SLOT_DOWN, SLOT_UP):
        target = rel[slot]
        start, end = image.exact_fde(target)
        role = {SLOT_LOOP: "the subject body itself", SLOT_CALLEE: "run as real code", SLOT_EVENT: "recording stub"}.get(slot, "stub")
        rows.append((hexbits(slot), "%#x" % target, end - start, role))
    return rows


def location_rows(image):
    rel = image.relative()
    return [("%#x" % at, *image.location(at, rel)) for at in (LOC_SIGNED, LOC_UNSIGNED, LOC_CALLEE)]


def jump_rows(image):
    rows = []
    for mode in range(5):
        offset = image.offset(JUMP_TABLE + 4 * mode)
        target = JUMP_TABLE + struct.unpack_from("<i", image.blob, offset)[0]
        rows.append((mode, "%#x" % target, "inside the body" if CALLEE <= target < image.exact_fde(CALLEE)[1] else "outside"))
    return rows


def direct_callers(image, targets):
    rows = []
    start_text, text = image.text_bytes()
    wanted = set(targets)
    for match in re.finditer(rb"[\xe8\xe9]", text):
        at = match.start()
        if at + 5 > len(text):
            continue
        target = start_text + at + 5 + struct.unpack_from("<i", text, at + 1)[0]
        if target in wanted:
            owner = bisect.bisect_right(image.starts, start_text + at) - 1
            rows.append(("%#x" % (start_text + at), "call" if text[at] == 0xE8 else "jmp", "%#x" % target, "%#x" % image.starts[owner]))
    return sorted(rows)


def slot_callers(image):
    """Indirect call sites through the two slots that name the subject bodies: call *disp(%rip) with a 6-byte encoding."""
    rows = []
    start_text, text = image.text_bytes()
    for match in re.finditer(rb"\xff\x15", text):
        at = match.start()
        if at + 6 > len(text):
            continue
        slot = start_text + at + 6 + struct.unpack_from("<i", text, at + 2)[0]
        if slot in (SLOT_LOOP, SLOT_CALLEE):
            owner = bisect.bisect_right(image.starts, start_text + at) - 1
            rows.append(("%#x" % (start_text + at), hexbits(slot), "%#x" % image.starts[owner]))
    return sorted(rows)


def branch_rows(image, branches):
    rows = []
    for entry in (LOOP, RANGE, CALLEE):
        for row in decode_range(image, *image.exact_fde(entry)):
            if row.op == "jcc":
                rows.append(("%#x" % entry, "%#x" % row.va, "%#x" % row.target, branches[(row.va, True)], branches[(row.va, False)]))
    return rows


def function_rows(image, hits):
    rows = []
    for entry in (LOOP, RANGE, CALLEE):
        start, end = image.exact_fde(entry)
        for row in decode_range(image, start, end):
            rows.append(("%#x" % entry, "%#x" % row.va, row.size, row.op, hits.get(row.va, 0)))
    return rows


def reciprocal_rows():
    return [(x, reciprocal(x), x // 10000, x % 10000, int(reciprocal(x) == x // 10000)) for x in EDGE_KEYS]


def analyse(count=10400, mutant_cases=420):
    image = load_image()
    harness = Harness(image)
    named = named_cases()
    grid = list(grid_cases())
    cases = named + list(random_cases(count)) + grid
    reached = collections.Counter()
    stats, caught, sample = check_stream(harness, cases, VARIANTS, keep=6, hits=reached)
    result = {"image": image, "branches": harness.machine.branches, "stats": stats, "caught": caught, "sample": sample, "reached": reached, "cases": len(cases)}
    result["structural"] = structural_controls(image, named)
    picked = named + cases[len(named):len(named) + count:max(1, count // mutant_cases)] + grid[::6]
    result["mutants"] = run_mutants(image, mutants_of(image, reached), picked)
    return result


def tsv_text(header, rows):
    return "\n".join(["\t".join(header)] + ["\t".join(str(x) for x in row) for row in rows]) + "\n"


def render(result):
    image, stats = result["image"], result["stats"]
    files = {}

    def tsv(name, header, rows):
        files[name] = tsv_text(header, rows)

    tsv("owner-fields.tsv", ("function", "base", "displacement", "accesses"), layout_rows(image))
    tsv("pointer-slots.tsv", ("slot", "target", "target_bytes", "model"), slot_rows(image))
    tsv("locations.tsv", ("address", "file", "line", "column"), location_rows(image))
    tsv("jump-table.tsv", ("mode", "target", "placement"), jump_rows(image))
    tsv("direct-callers.tsv", ("site", "kind", "target", "owner"), direct_callers(image, (LOOP, CALLEE)))
    tsv("slot-callers.tsv", ("site", "slot", "owner"), slot_callers(image))
    tsv("branch-coverage.tsv", ("function", "address", "target", "taken", "not_taken"), branch_rows(image, result["branches"]))
    tsv("amount-grid.tsv", ("index", "mode", "tag", "amount_word", "multiplier", "divisor", "offset", "cap", "outcome", "words", "events"),
        stats["grid"])
    tsv("function-rows.tsv", ("function", "address", "size", "op", "cases_reaching"), function_rows(image, result["reached"]))
    tsv("reciprocal.tsv", ("key", "magic_quotient", "division_quotient", "remainder", "agree"), reciprocal_rows())
    tsv("outcomes.tsv", ("store", "outcome", "cases"), [(s, o, n) for (s, o), n in sorted(stats["kinds"].items())])
    tsv("cases-sample.tsv", ("index", "name", "store", "entries", "mode", "outcome", "words", "events", "distinct_insns"), result["sample"])
    tsv("variants.tsv", ("deviation", "cases_refused", "first_refusing_case"),
        [(name, n, "" if first is None else first) for name, (n, first) in sorted(result["caught"].items())])
    tsv("structural-controls.tsv", ("control", "detected", "how"), [(n, int(d), h) for n, d, h in result["structural"]])
    survivors = [row for row in result["mutants"] if not row[5]]
    unexplained = [row for row in survivors if (row[0], row[1]) not in EQUIVALENT]
    stale = [key for key in EQUIVALENT if not any((row[0], row[1]) == key for row in survivors)]
    tsv("mutants.tsv", ("address", "kind", "edited_byte_at", "old", "new", "killed", "first_case"),
        [("%#x" % va, kind, "%#x" % at, old, new, int(killed), first) for va, kind, at, old, new, killed, first in result["mutants"]])
    tsv("equivalent-mutants.tsv", ("mutant", "address", "reason"), [(kind, "%#x" % va, EQUIVALENT[(va, kind)]) for va, kind, *_ in survivors
                                                                    if (va, kind) in EQUIVALENT])
    equivalent = len(survivors) - len(unexplained)
    controls = len(result["caught"]) + len(result["structural"]) + len(result["mutants"])
    detected = (sum(1 for n, first in result["caught"].values() if n) + sum(1 for _, d, _ in result["structural"] if d)
                + sum(1 for row in result["mutants"] if row[5]))
    evidence = {
        "binary_sha256": SHA256, "function": "%#x" % LOOP, "helpers": {"tree_step": "%#x" % RANGE, "entry_amount": "%#x" % CALLEE},
        "cases": stats["cases"], "mismatches": stats["mismatches"], "first_mismatch": stats["first_mismatch"],
        "instructions_reached": len(result["reached"]), "mutants": len(result["mutants"]),
        "mutants_killed": sum(1 for row in result["mutants"] if row[5]), "unexplained_survivors": ["%#x %s" % (r[0], r[1]) for r in unexplained],
        "stale_equivalents": ["%#x %s" % key for key in stale],
    }
    files["evidence.json"] = json.dumps(evidence, indent=1, sort_keys=True, default=str) + "\n"
    files["measure.json"] = json.dumps({"cases": stats["cases"], "negative_controls": controls, "negative_detected": detected,
                                        "equivalent": equivalent, "mismatches": stats["mismatches"], "mutants": len(result["mutants"])},
                                       indent=1, sort_keys=True) + "\n"
    return files, bool(unexplained or stale)


def main(argv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument("--out", required=True)
    args = parser.parse_args(argv)
    result = analyse()
    out = pathlib.Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    files, flawed = render(result)
    for name, text in files.items():
        (out / name).write_text(text)
    print(files["measure.json"], end="")
    if flawed:
        print("unexplained or stale mutant entries; see evidence.json", file=sys.stderr)
    return 0 if result["stats"]["mismatches"] == 0 and not flawed else 1


if __name__ == "__main__":
    sys.exit(main())
