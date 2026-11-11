#!/usr/bin/env python3
"""Reconstruct the node #115 open-interest at-cap test 0x44883f0 with its sum fold 0x37c1480 and ordered-map search 0x45547e0.

The test answers, for one dex row and one asset id, whether the asset (or the whole dex) is at 90% of an open-interest cap. The
real bytes of all three functions run in a Python evaluator over memory images built from the field layout read out of the bytes
(B-tree maps and sorted VecDeque maps, both shapes); a separately written specification predicts every result, panic and
iterator side effect. Deliberately wrong specifications, corrupted code bytes and out-of-range inputs must all be caught. No
objdump or readelf output is parsed and the binary is never executed. Standard library only.
"""

import argparse
import bisect
import collections
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

PREDICATE = 0x44883F0
FOLD = 0x37C1480
SEARCH = 0x45547E0
PREDICATE_SLOT = 0x64E5A78
SLOT_BOUNDS = 0x64DF620
SLOT_UNWRAP = 0x64DF6A0
SLOT_MUL = 0x64DF870
SLOT_ADD = 0x64DF520
LOC_PRED_BOUNDS = 0x648BA20
LOC_PRED_UNWRAP = 0x648BA38
LOC_FOLD_BOUNDS = 0x646E3E0
LOC_FOLD_ARITH = 0x646E3F8
UNWRAP_LEN = 0x2B
CAP_FACTOR = 0x459788
INF_WORD = 0x459010
CLAMP_TOP = 0x459360
CLAMP_LOW = 0x458E50
NICHE = 0x8000000000000000
MAX_I64 = (1 << 63) - 1
UNMAPPED = 0x10


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
MUTANT_STEP_LIMIT = 100000

class EvidenceError(Exception):
    pass


class Halt(Exception):
    pass


class Panicked(Exception):
    pass


class PriceTable(dict):
    """Asset rows by index; a row nobody wrote reads as the stack mark word."""

    def __missing__(self, key):
        return POISON


class Image:
    """Section, relocation and FDE views of one ELF byte string, through the shared parsers."""

    def __init__(self, blob):
        self.blob = blob
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

    def location(self, slot, relative):
        """Decode one Location record; the path is kept only below the crate or std root."""
        size, line, column = struct.unpack_from("<QII", self.blob, self.offset(slot) + 8)
        start = self.offset(relative[slot])
        path = bytes(self.blob[start:start + size]).decode()
        for marker in ("/l1/", "/library/", "/base/", "/chrono-"):
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
    __slots__ = ("va", "size", "op", "a", "b", "width", "cc", "target", "next", "imm_at", "imm_size", "rip_at")

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
    if byte == 0x6A:
        value = immediate(1)
        return finish("pushi", ("i", value), w=8)
    if byte == 0x90:
        return finish("nop")
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
            return finish("pushi", rm, w=8)
        raise EvidenceError("unsupported group 5 opcode at %#x" % va)
    if byte == 0x0F:
        two = window[pos]
        pos += 1
        if two == 0x0B:
            return finish("ud2")
        if two == 0x1F:
            modrm()
            return finish("nop")
        if two in (0x10, 0x11) and repne:
            reg, rm = modrm(True)
            if two == 0x10:
                return finish("movsd", ("x", reg), rm, 8)
            return finish("movsd", rm, ("x", reg), 8)
        if two == 0x13 and not opsize:
            reg, rm = modrm(True)
            return finish("movsd", rm, ("x", reg), 8)
        if two in (0x10, 0x11, 0x28, 0x29, 0x6F, 0x7F):
            reg, rm = modrm(True)
            if two in (0x10, 0x28, 0x6F):
                return finish("movx", ("x", reg), rm, 16)
            return finish("movx", rm, ("x", reg), 16)
        vector = {(0x57, False): "xorps", (0x57, True): "xorps", (0xEF, True): "xorps", (0x15, True): "unpckhpd", (0x5C, True): "subpd",
                  (0x54, True): "andpd", (0x56, True): "orpd", (0x62, True): "punpckldq", (0x14, False): "punpckldq",
                  (0x55, True): "andnpd", (0x14, True): "unpcklpd", (0x60, True): "punpcklbw", (0x74, True): "pcmpeqb", (0x76, True): "pcmpeqd", (0xDB, True): "andpd"}
        if (two, opsize) in vector:
            reg, rm = modrm(True)
            return finish(vector[(two, opsize)], ("x", reg), rm, 16)
        if two in (0x58, 0x59, 0x5C, 0x5D, 0x5E, 0x5F) and repne:
            reg, rm = modrm(True)
            return finish({0x58: "addsd", 0x59: "mulsd", 0x5C: "subsd", 0x5D: "minsd", 0x5E: "divsd", 0x5F: "maxsd"}[two], ("x", reg), rm, 8)
        if two == 0xC2 and repne:
            reg, rm = modrm(True)
            value = immediate(1)
            if value != 0:
                raise EvidenceError("unsupported compare predicate at %#x" % va)
            return finish("cmpeqsd", ("x", reg), rm, 8)
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
        if two == 0x6E and opsize and not wide:
            reg, rm = modrm()
            return finish("movd", ("x", reg), rm, 4)
        if two == 0x7E and rep:
            reg, rm = modrm(True)
            return finish("movq", ("x", reg), rm, 8)
        if two == 0x2C and repne:
            reg, rm = modrm(True)
            return finish("cvttsd2si", ("r", reg), rm, 8)
        if two == 0x2A and repne:
            reg, rm = modrm()
            return finish("cvtsi2sd", ("x", reg), rm, width)
        if two == 0x2E and opsize:
            reg, rm = modrm(True)
            return finish("ucomisd", ("x", reg), rm, 8)
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
            return finish("bt", rm, ("r", reg), width)
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
        self.keep_float = False
        self.step_limit = STEP_LIMIT
        self.jump_low = self.jump_high = 0

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
        self.keep_rdx = self.keep_float = False
        hook(self)
        for reg in VOLATILE:
            self.regs[reg] = POISON
        if not self.keep_rdx:
            self.regs[RDX] = POISON
        kept = self.xmm[0]
        self.xmm = [POISON | POISON << 64] * 16
        if self.keep_float:
            self.xmm[0] = kept

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
        elif op == "pushi":
            self.push(self.get(row.a, 8))
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
        elif op == "imul1":
            left = self.regs[RAX] - (1 << 64) if self.regs[RAX] & SIGN[8] else self.regs[RAX]
            right = self.get(row.a, 8)
            right = right - (1 << 64) if right & SIGN[8] else right
            product = (left * right) & ((1 << 128) - 1)
            self.regs[RAX] = product & MASK[8]
            self.regs[RDX] = product >> 64
        elif op == "jmp":
            return row.target
        elif op == "calli":
            target = self.get(row.a, 8)
            if target in self.real:
                self.push(row.next)
                return target
            hook = self.slots.get(target)
            if not hook:
                raise Halt("unmodelled indirect call at %#x" % row.va)
            self.call_site = row.va
            self.call_target = target
            self.stub(hook)
        elif op == "jmpi":
            target = self.get(row.a, 8)
            hook = self.slots.get(target)
            if hook:
                self.stub(hook)
                return self.pop()
            if not self.jump_low <= target < self.jump_high:
                raise Halt("indirect jump out of the function at %#x" % row.va)
            return target
        elif op == "bt":
            self.cf = bool(self.get(row.a, width) >> (self.regs[row.b[1]] & (8 * width - 1)) & 1)
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
        elif op in ("shl", "shr", "sar", "rol"):
            count = (self.regs[RCX] if row.b[0] == "r" else row.b[1]) & (63 if width == 8 else 31)
            value = self.get(row.a, width)
            if op == "rol":
                result = (value << count | value >> (8 * width - count)) & MASK[width]
            elif op == "shl":
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
        elif op == "cdqe":
            self.regs[RAX] = (self.regs[RAX] & MASK[4]) | (MASK[8] ^ MASK[4] if self.regs[RAX] & SIGN[4] else 0)
        elif op == "imul2":
            left, right = self.get(row.a, width), self.get(row.b, width)
            left = left - (1 << (8 * width)) if left & SIGN[width] else left
            right = right - (1 << (8 * width)) if right & SIGN[width] else right
            product = left * right
            self.cf = self.of = not -SIGN[width] <= product < SIGN[width]
            self.put(row.a, width, product)
        elif op == "nop":
            pass
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
                self.xmm[row.a[1]] = self.low(row.b) if row.b[0] != "r" else self.get(row.b, 8)
            else:
                self.put(row.a, 8, self.xmm[row.b[1]] & MASK[8])
        elif op == "cmpeqsd":
            left, right = to_float(self.low(row.a)), to_float(self.low(row.b))
            self.set_low(row.a[1], MASK[8] if left == right else 0)
        elif op in ("addsd", "subsd", "mulsd", "divsd", "minsd", "maxsd"):
            left, right = to_float(self.low(row.a)), to_float(self.low(row.b))
            if op == "addsd":
                result = left + right
            elif op == "subsd":
                result = left - right
            elif op == "mulsd":
                result = left * right
            elif op == "divsd":
                result = left / right if right else math.copysign(math.inf, left) * math.copysign(1.0, right) if left == left and left else math.nan
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
        elif op == "andnpd":
            self.xmm[row.a[1]] = (~self.xmm[row.a[1]] & ((1 << 128) - 1)) & self.vector(row.b)
        elif op == "orpd":
            self.xmm[row.a[1]] |= self.vector(row.b)
        elif op == "subpd":
            right = self.vector(row.b)
            left = self.xmm[row.a[1]]
            low = to_float(left & MASK[8]) - to_float(right & MASK[8])
            high = to_float(left >> 64) - to_float(right >> 64)
            self.xmm[row.a[1]] = to_bits(low) | to_bits(high) << 64
        elif op == "unpcklpd":
            self.xmm[row.a[1]] = (self.xmm[row.a[1]] & MASK[8]) | (self.vector(row.b) & MASK[8]) << 64
        elif op == "movd":
            self.xmm[row.a[1]] = self.get(row.b, 4)
        elif op == "punpcklbw":
            left, right = self.xmm[row.a[1]], self.vector(row.b)
            self.xmm[row.a[1]] = sum((((left >> (8 * at)) & 0xFF) | ((right >> (8 * at)) & 0xFF) << 8) << (16 * at) for at in range(8))
        elif op == "pshuflw":
            source = self.vector(row.b)
            words = sum(((source >> (16 * ((row.target >> (2 * at)) & 3))) & 0xFFFF) << (16 * at) for at in range(4))
            self.xmm[row.a[1]] = (source >> 64) << 64 | words
        elif op == "pshufd":
            source = self.vector(row.b)
            self.xmm[row.a[1]] = sum(((source >> (32 * ((row.target >> (2 * at)) & 3))) & MASK[4]) << (32 * at) for at in range(4))
        elif op in ("pcmpeqb", "pcmpeqd"):
            size = 1 if op == "pcmpeqb" else 4
            left, right = self.xmm[row.a[1]], self.vector(row.b)
            bits = 8 * size
            self.xmm[row.a[1]] = sum((MASK[size] if (left >> at) & MASK[size] == (right >> at) & MASK[size] else 0) << at for at in range(0, 128, bits))
        elif op == "pmovmskb":
            source = self.xmm[row.b[1]]
            self.put(row.a, 4, sum(((source >> (8 * at + 7)) & 1) << at for at in range(16)))
        elif op == "tzcnt":
            value = self.get(row.b, row.width)
            result = 8 * row.width if value == 0 else (value & -value).bit_length() - 1
            self.cf = value == 0
            self.zf = result == 0
            self.put(row.a, row.width, result)
        elif op == "unpckhpd":
            self.xmm[row.a[1]] = self.xmm[row.a[1]] >> 64 | (self.vector(row.b) >> 64) << 64
        elif op == "punpckldq":
            left, right = self.xmm[row.a[1]], self.vector(row.b)
            self.xmm[row.a[1]] = (left & MASK[4]) | (right & MASK[4]) << 32 | ((left >> 32) & MASK[4]) << 64 | ((right >> 32) & MASK[4]) << 96
        else:
            raise Halt("unmodelled operation %s at %#x" % (op, row.va))

    def vector(self, operand):
        if operand[0] == "x":
            return self.xmm[operand[1]]
        return int.from_bytes(self.memory.bytes_at(self.address(operand), 16), "little")



def direct_sites(image, targets):
    """Every E8/E9 rel32 byte pattern in .text that lands on a target."""
    base, text = image.text_bytes()
    found = {target: [] for target in targets}
    for opcode in (b"\xe8", b"\xe9"):
        at = text.find(opcode)
        while 0 <= at <= len(text) - 5:
            target = base + at + 5 + struct.unpack_from("<i", text, at + 1)[0]
            if target in found:
                found[target].append((base + at, opcode[0]))
            at = text.find(opcode, at + 1)
    return found


def slot_sites(image, slot):
    """Every FF 15 call in .text through one data slot."""
    base, text = image.text_bytes()
    rows = []
    at = text.find(b"\xff\x15")
    while 0 <= at <= len(text) - 6:
        if base + at + 6 + struct.unpack_from("<i", text, at + 2)[0] == slot:
            rows.append(base + at)
        at = text.find(b"\xff\x15", at + 1)
    return rows


# ---- mutation ----

def displacement_at(image, row):
    """Offset inside the instruction of a non-stack field displacement, or None."""
    for operand in (row.a, row.b):
        if operand and operand[0] == "m" and operand[1] not in (None, RSP) and operand[4]:
            disp = operand[4]
            end = row.size - (row.imm_size or 0)
            data = bytes(image.blob[image.offset(row.va):image.offset(row.va) + row.size])
            if -128 <= disp <= 127 and data[end - 1:end] == struct.pack("<b", disp):
                return end - 1
            if data[end - 4:end] == struct.pack("<i", disp):
                return end - 4
            raise EvidenceError("displacement not found at %#x" % row.va)
    return None


def mutation_targets(image, rows):
    """Yield (va, offset in instruction, kind) for every conditional, immediate and field offset."""
    for row in rows:
        at = displacement_at(image, row)
        if at is not None:
            yield row.va, at, "offset"
        if row.op == "jcc":
            yield row.va, row.size - (2 if row.size == 2 else 5), "branch"
        elif row.op in ("set", "cmov"):
            yield row.va, None, row.op
        if row.imm_at is not None and row.op not in ("jcc", "call", "jmp"):
            yield row.va, row.imm_at, "immediate"


def mutate_patch(image, row_va, at, kind="branch"):
    base = image.offset(row_va)
    window = bytes(image.blob[base:base + 16])
    if at is None:
        at = window.index(b"\x0f") + 1
    return {row_va + at: window[at] ^ (8 if kind == "offset" else 1)}




# ---- specification, written from the claim ----

class Lcg:
    """Fixed generator so that the case list never depends on the Python build."""

    def __init__(self, start):
        self.state = start & MASK[8] or 1

    def next(self):
        self.state = (self.state * 6364136223846793005 + 1442695040888963407) & MASK[8]
        return self.state >> 33

    def below(self, bound):
        return self.next() % bound

    def pick(self, items):
        return items[self.below(len(items))]


def signed(value):
    return value - (1 << 64) if value & SIGN[8] else value


def threshold(value, bug=None):
    """floor(value * 0.9) as the saturating double to i64 cast; value is a non-negative i64."""
    factor = {"cap_factor_low": 0.8, "cap_factor_one": 1.0, "cap_factor_high": 0.95}.get(bug, 0.9)
    scaled = float(value) * factor
    if scaled != scaled:
        return 0
    if bug == "round_cap":
        return min(int(round(scaled)), MAX_I64)
    if bug == "ceil_cap":
        return min(int(math.ceil(scaled)), MAX_I64)
    return min(int(scaled), MAX_I64)


def lookup(table, key):
    return table.get(key)


def spec_fold(w, pos, length, init, cache, bug=None):
    """Sum of price * size over the assets pos..length of one dex, or None. Returns (ok, sum word, new pos) or a panic."""
    total = init
    dex = w["dex"]
    if bug == "fold_start_one":
        pos += 1
    if bug == "fold_extra":
        length += 1
    while pos < length:
        pos += 1
        if dex * 10000 > MASK[8]:
            return ("panic", ("multiply overflow", LOC_FOLD_ARITH))
        asset = dex * 10000 + (pos - 1)
        if asset > MASK[8]:
            return ("panic", ("add overflow", LOC_FOLD_ARITH))
        if cache[0] and cache[1] == asset and bug != "fold_cache_ignored":
            price = cache[0]
        else:
            local = asset % 10000
            if bug == "fold_local_1000":
                local = asset % 1000
            if local >= w["row_len"]:
                return ("panic", ("bounds", local, w["row_len"], LOC_FOLD_BOUNDS))
            price = w["prices"][local]
        size = lookup(w["sizes"], asset if bug != "fold_size_local" else asset % 10000)
        if size is None:
            if bug == "fold_absent_price":
                size = 1
            else:
                continue
        if price & SIGN[8] and bug != "fold_negative_price":
            return ("fold", 0, total, pos)
        product = signed(price) * signed(size)
        if not -SIGN[8] <= product < SIGN[8] and bug != "fold_product_wrap":
            return ("fold", 0, total, pos)
        wrapped = (total + product) & MASK[8]
        if bug != "fold_sum_wrap" and not -SIGN[8] <= signed(total) + product < SIGN[8]:
            return ("fold", 0, wrapped, pos)
        total = wrapped
    return ("fold", 1, total, pos)


def spec_pred(w, bug=None):
    asset = w["asset"]
    if w["mode_set"]:
        if bug == "set_always_false":
            return ("ret", 0)
        return ("ret", int((asset + (1 if bug == "set_off_by_one" else 0)) in w["set"]))
    cap = lookup(w["caps"], asset if bug != "cap_key_local" else asset % 10000)
    if bug == "cap_ignored":
        cap = None
    if cap is not None:
        local = asset % 10000
        if local >= w["row_len"] - (1 if bug == "bound_short" else 0) and bug != "bound_missing":
            return ("panic", ("bounds", local, w["row_len"], LOC_PRED_BOUNDS))
        price = w["prices"][local] if bug != "price_row_zero" else w["prices"][0]
        size = lookup(w["sizes"], asset if bug != "size_key_local" else asset % 10000)
        if size is None:
            size = 0
        if price & SIGN[8] and bug != "price_negative_ok":
            return ("ret", 1)
        product = signed(price) * signed(size)
        if not -SIGN[8] <= product < SIGN[8] and bug != "product_overflow_ok":
            return ("ret", 1)
        if cap & SIGN[8] and bug != "cap_negative_ok":
            return ("panic", ("unwrap", LOC_PRED_UNWRAP, UNWRAP_LEN))
        limit = threshold(cap, bug)
        if bug == "cap_unsigned":
            if (product & MASK[8]) > limit:
                return ("ret", 1)
        elif bug == "cap_at_least":
            if product >= limit:
                return ("ret", 1)
        elif product > limit:
            return ("ret", 1)
    if bug == "cap_only":
        return ("ret", 0)
    folded = spec_fold(w, 0, w["count"], 0, (0, 0), bug)
    if folded[0] == "panic":
        return folded
    if not folded[1]:
        return ("ret", 0 if bug == "fold_none_false" else 1)
    total = w["total"]
    if total & SIGN[8] and bug != "total_negative_ok":
        return ("panic", ("unwrap", LOC_PRED_UNWRAP, UNWRAP_LEN))
    limit = threshold(total, bug) if bug != "total_uses_cap" or cap is None else threshold(cap, bug)
    amount = signed(folded[2])
    if bug == "total_unsigned":
        return ("ret", int(folded[2] > limit))
    if bug == "total_at_least":
        return ("ret", int(amount >= limit))
    return ("ret", int(amount > limit))


SPEC_BUGS = (
    "cap_factor_low", "cap_factor_one", "round_cap", "ceil_cap", "cap_factor_high", "set_always_false", "set_off_by_one", "cap_key_local",
    "cap_ignored", "bound_short", "bound_missing", "price_row_zero", "size_key_local", "price_negative_ok", "product_overflow_ok",
    "cap_negative_ok", "cap_unsigned", "cap_at_least", "cap_only", "fold_none_false", "total_negative_ok", "total_uses_cap",
    "total_unsigned", "total_at_least", "fold_start_one", "fold_extra", "fold_cache_ignored", "fold_local_1000", "fold_size_local",
    "fold_absent_price", "fold_negative_price", "fold_product_wrap", "fold_sum_wrap",
)


# ---- harness: real bytes over memory images built from the field layout ----

Shape = collections.namedtuple("Shape", "values length edges size")
MAP_SHAPE = Shape(0x60, 0xBA, 0xC0, 0x120)
SET_SHAPE = Shape(None, 0x62, 0x68, 0xC8)
NODE_KEYS = 0x08
CAPACITY = 11

DEX = HEAP_BASE + 0x1000
CAP_BLOCK = HEAP_BASE + 0x1800
ROWS = HEAP_BASE + 0x10000
POOL = HEAP_BASE + 0x4000
POOL_END = HEAP_BASE + 0xA000
ITER = HEAP_BASE + 0xB000
CACHE = HEAP_BASE + 0xB040
CTX = HEAP_BASE + 0xB080
USED = 0x2A000
DEX_SIZE = 0x600
ROW_STRIDE = 0x60
PRICE_AT = 0x20


class Panicked(Exception):
    pass


class RealExcept:
    """Every call target runs its real bytes unless the harness stubs it."""

    def __init__(self):
        self.stubs = frozenset()

    def __contains__(self, target):
        return target not in self.stubs


def min_items(height):
    return 1 if height == 0 else 2 * min_items(height - 1) + 1


def fit_height(count):
    height, room = 0, CAPACITY
    while room < count:
        height += 1
        room = 12 * room + CAPACITY
    return height


class Harness:
    def __init__(self, image):
        self.image = image
        self.machine = Machine(image)
        machine = self.machine
        relative = {slot: addend for slot, kind, addend, _ in image.relocations() if kind == 8}
        self.relative = relative
        table = {SLOT_BOUNDS: self.on_bounds, SLOT_UNWRAP: self.on_unwrap, SLOT_MUL: self.on_mul, SLOT_ADD: self.on_add}
        for slot in table:
            relative.setdefault(slot, slot)
        machine.memory.statics.update(relative)
        machine.slots = {relative[slot]: hook for slot, hook in table.items()}
        self.real = RealExcept()
        self.real.stubs = frozenset(machine.slots)
        machine.real = self.real
        self.brk = POOL

    def on_bounds(self, m):
        raise Panicked(("bounds", m.regs[RDI], m.regs[RSI], m.regs[RDX]))

    def on_unwrap(self, m):
        raise Panicked(("unwrap", m.regs[R8], m.regs[RSI]))

    def on_mul(self, m):
        raise Panicked(("multiply overflow", m.regs[RDI]))

    def on_add(self, m):
        raise Panicked(("add overflow", m.regs[RDI]))

    # -- memory images --

    def word(self, addr, value):
        self.machine.memory.write(addr, 8, value)

    def alloc(self, size):
        at = (self.brk + 15) & ~15
        self.brk = at + size
        if self.brk > POOL_END:
            raise EvidenceError("pool full")
        return at

    def node(self, items, height, shape, rng, filler):
        memory = self.machine.memory
        at = self.alloc(shape.size)
        for slot in range(12):
            if slot < CAPACITY:
                self.word(at + NODE_KEYS + 8 * slot, filler)
                if shape.values is not None:
                    self.word(at + shape.values + 8 * slot, 0x7E57000000000000 | slot)
            memory.write(at + shape.edges + 8 * slot, 8, UNMAPPED)
        if height == 0:
            keys, kids = items, []
        else:
            low = min_items(height - 1)
            top = min(12, (len(items) + 1) // (low + 1))
            room = CAPACITY if height == 1 else 143
            bottom = 2
            while len(items) - (bottom - 1) > bottom * room:
                bottom += 1
            count = bottom + (rng.below(top - bottom + 1) if top > bottom else 0)
            rest = len(items) - (count - 1)
            keys, kids, cursor = [], [], 0
            for index in range(count):
                size = rest // count + (1 if index < rest % count else 0)
                kids.append(items[cursor:cursor + size])
                cursor += size
                if index < count - 1:
                    keys.append(items[cursor])
                    cursor += 1
        for slot, (key, value) in enumerate(keys):
            self.word(at + NODE_KEYS + 8 * slot, key)
            if shape.values is not None:
                self.word(at + shape.values + 8 * slot, value)
        memory.write(at + shape.length, 2, len(keys))
        for slot, kid in enumerate(kids):
            self.word(at + shape.edges + 8 * slot, self.node(kid, height - 1, shape, rng, filler))
        return at

    def tree(self, items, height, shape, rng, filler):
        """Return (root, height) for sorted (key, value) pairs; an empty tree has a null root."""
        if not items:
            return 0, height
        floor = fit_height(len(items))
        ceiling = max(floor, max(h for h in range(4) if min_items(h) <= len(items)))
        height = max(floor, min(height, ceiling))
        return self.node(items, height, shape, rng, filler), height

    def map_at(self, base, kind, table, option, rng, filler):
        """The map enum at base: a B-tree behind the niche word, or a sorted ring buffer of 16 byte entries."""
        items = sorted(table.items())
        if kind in ("tree", "none"):
            root, height = self.tree(items, option, MAP_SHAPE, rng, filler)
            self.word(base, NICHE)
            self.word(base + 8, root)
            self.word(base + 0x10, height)
            self.word(base + 0x18, len(items))
            return
        capacity = len(items) + option % 4 if items else option % 3 * 2
        head = rng.below(capacity) if capacity else 0
        buffer = self.alloc(max(16, 16 * capacity))
        for slot in range(capacity):
            self.word(buffer + 16 * slot, filler)
            self.word(buffer + 16 * slot + 8, 0x7E57000000000000 | slot)
        for index, (key, value) in enumerate(items):
            spot = (head + index) % capacity
            self.word(buffer + 16 * spot, key)
            self.word(buffer + 16 * spot + 8, value)
        self.word(base, capacity)
        self.word(base + 8, buffer)
        self.word(base + 0x10, head)
        self.word(base + 0x18, len(items))

    def build(self, w):
        memory = self.machine.memory
        memory.reset(USED)
        self.brk = POOL
        rng = Lcg(w["stream"])
        filler = w["filler"]
        memory.put_bytes(DEX, bytes((index * 7 + 3) & 0xFF or 1 for index in range(DEX_SIZE)))
        self.word(DEX + 0x10, w["count"])
        self.word(DEX + 0x50, w["dex"])
        self.map_at(DEX + 0xF0, w["sizes_kind"], w["sizes"], w["sizes_option"], rng, filler)
        for index, price in w["prices"].items():
            memory.put_bytes(ROWS + ROW_STRIDE * index, bytes((index * 11 + at) & 0xFF or 1 for at in range(ROW_STRIDE)))
            self.word(ROWS + ROW_STRIDE * index + PRICE_AT, price)
        self.word(DEX + 0x150, ROWS)
        self.word(DEX + 0x158, w["row_len"])
        if w["mode_set"]:
            self.word(DEX + 0x378, NICHE)
            root, height = self.tree(sorted((key, 0) for key in w["set"]), w["set_height"], SET_SHAPE, rng, filler)
            self.word(DEX + 0x3D0, root)
            self.word(DEX + 0x3D8, height)
        else:
            self.word(DEX + 0x378, 3)
        self.word(DEX + 0x478, w["total"])
        self.word(DEX + 0x4A0, CAP_BLOCK)
        memory.put_bytes(CAP_BLOCK, bytes((index * 5 + 1) & 0xFF or 1 for index in range(0x60)))
        self.map_at(CAP_BLOCK + 0x30, w["caps_kind"], w["caps"], w["caps_option"], rng, filler)
        if w["kind"] == "fold":
            self.word(ITER, DEX)
            self.word(ITER + 8, w["pos"])
            self.word(ITER + 0x10, w["length"])
            self.word(CACHE, w["cache"][0])
            self.word(CACHE + 8, w["cache"][1])
            self.word(CTX, CACHE)
            self.word(CTX + 8, DEX)

    def run(self, w):
        """Run the real bytes and return the same tuples the specification gives."""
        self.build(w)
        machine = self.machine
        before = bytes(machine.memory.heap[:USED])
        try:
            if w["kind"] == "fold":
                result = machine.run(FOLD, {RDI: ITER, RSI: w["init"], RDX: CTX})
                outcome = ("fold", result & MASK[4], machine.regs[RDX], machine.memory.read(ITER + 8, 8))
                expected = bytearray(before)
                expected[ITER + 8 - HEAP_BASE:ITER + 16 - HEAP_BASE] = outcome[3].to_bytes(8, "little")
                before = bytes(expected)
            else:
                result = machine.run(PREDICATE, {RDI: DEX, RSI: w["asset"]})
                outcome = ("ret", result & 0xFF)
        except Panicked as stop:
            return ("panic", stop.args[0])
        if bytes(machine.memory.heap[:USED]) != before:
            return ("heap changed",)
        return outcome


def spec_for(w, bug=None):
    if w["kind"] == "fold":
        return spec_fold(w, w["pos"], w["length"], w["init"], w["cache"], bug)
    return spec_pred(w, bug)


# ---- cases ----

SIZES_SPECIAL = (0, 1, 2, 5, 7, 100, 123456, 10 ** 9, 10 ** 12, (1 << 62), (1 << 63) - 1, (1 << 63), (1 << 64) - 1, (1 << 64) - 5)
PRICES_SPECIAL = (0, 1, 2, 3, 9, 10, 99, 1000, 10 ** 6, 10 ** 9, (1 << 31), (1 << 32), (1 << 40), (1 << 62), (1 << 63) - 1, (1 << 63), (1 << 64) - 1)
CAPS_SPECIAL = (0, 1, 9, 10, 11, 100, 1000, 10 ** 6, 10 ** 9, 10 ** 12, 10 ** 15, (1 << 62), (1 << 63) - 1, (1 << 63), (1 << 64) - 2)
DEXES_SPECIAL = (0, 1, 2, 3, 7, 100, 1844674407370955, 1844674407370956, 1844674407370955, (1 << 63) // 10000, (1 << 64) // 10000 + 1)
KINDS = ("tree", "flat", "none")


def pick_value(rng, special, small=None):
    roll = rng.below(10)
    if roll < 5:
        return rng.pick(special)
    if roll < 8:
        return rng.below(small or 2000)
    return rng.next() << 20 | rng.below(1 << 20)


def make_world(rng, kind):
    dex = rng.pick(DEXES_SPECIAL) if rng.below(4) == 0 else rng.below(5)
    count = rng.below(7) if rng.below(8) else rng.pick((0, 1, 9, 10001))
    if count > 12:
        count = 1 + rng.below(3)
    row_len = count + rng.pick((0, 0, 0, 1, 3)) if rng.below(6) else max(0, count - 1 - rng.below(2))
    row_len = min(row_len, 40)
    prices = PriceTable((index, pick_value(rng, PRICES_SPECIAL, 500)) for index in range(row_len))
    assets = [dex * 10000 + local for local in range(count)]
    assets = [a for a in assets if a <= MASK[8]]
    def make_table(special, density):
        table = {}
        for asset in assets:
            if rng.below(10) < density:
                table[asset] = pick_value(rng, special, 3000)
        for _ in range(rng.below(5)):
            table[rng.next() << 8 | rng.below(256) if rng.below(2) else rng.below(30)] = pick_value(rng, special, 3000)
        return table
    w = {
        "kind": kind, "stream": rng.next() | 1, "dex": dex, "count": count, "row_len": row_len, "prices": prices,
        "mode_set": False, "set": [], "set_height": 0,
        "sizes": make_table(SIZES_SPECIAL, 6), "sizes_kind": rng.pick(KINDS), "sizes_option": rng.below(3),
        "caps": make_table(CAPS_SPECIAL, 5), "caps_kind": rng.pick(KINDS), "caps_option": rng.below(3),
        "total": pick_value(rng, CAPS_SPECIAL, 100000), "asset": 0, "filler": 0,
    }
    if w["sizes_kind"] == "none":
        w["sizes"] = {}
    if w["caps_kind"] == "none":
        w["caps"] = {}
    if assets:
        w["asset"] = rng.pick(assets) if rng.below(8) else rng.next()
    else:
        w["asset"] = dex * 10000 + rng.below(5)
    if w["asset"] > MASK[8]:
        w["asset"] = MASK[8]
    if rng.below(3) == 0 and w["caps"] and w["asset"] not in w["caps"] and rng.below(2):
        w["caps"][w["asset"]] = pick_value(rng, CAPS_SPECIAL, 3000)
    w["filler"] = w["asset"] if rng.below(3) else (1 << 64) - 3
    if kind == "pred" and rng.below(6) == 0:
        w["mode_set"] = True
        members = {rng.below(40) + dex * 10000 for _ in range(rng.below(24))}
        members = {m for m in members if m <= MASK[8]}
        if rng.below(2) and w["asset"] not in members and rng.below(2):
            members.add(w["asset"])
        if rng.below(5) == 0 and members:
            members.discard(w["asset"])
        w["set"] = sorted(members)
        w["set_height"] = rng.below(3)
    if kind == "fold":
        w["length"] = count if rng.below(3) else count + rng.below(3)
        w["pos"] = rng.below(w["length"] + 2) if w["length"] else 0
        w["init"] = pick_value(rng, SIZES_SPECIAL, 1000)
        if rng.below(2):
            w["init"] = rng.below(5000)
        w["cache"] = (0, 0)
        if rng.below(3) == 0:
            w["cache"] = (pick_value(rng, PRICES_SPECIAL, 500) or 5, w["dex"] * 10000 + rng.below(max(1, count)) if rng.below(4) else rng.next())
        if w["pos"] > 0 and w["length"] > w["count"] and rng.below(2):
            w["length"] = w["count"] + 1
    return w


def label_for(w):
    if w["kind"] == "fold":
        return "fold dex=%d pos=%d length=%d" % (w["dex"], w["pos"], w["length"])
    return "pred %s asset=%d" % ("set" if w["mode_set"] else "caps", w["asset"])


CASE_PREDICATE = 7200
CASE_FOLD = 3600
CASE_EDGE = 1200
CASE_FAR = 600


def make_edge(rng):
    """One asset whose notional sits within two units of the 90% line of its cap, and a dex total near its own line."""
    w = make_world(rng, "pred")
    dex = rng.below(3)
    local = rng.below(4)
    asset = dex * 10000 + local
    cap = rng.pick((1, 2, 3, 9, 10, 11, 19, 20, 21, 99, 100, 101, 999, 1000, 10 ** 6 + 7, 10 ** 9 + 3, (1 << 40) + 11)) if rng.below(3) else 1 + rng.below(10000)
    size = rng.pick((1, 1, 2, 3))
    product = max(0, threshold(cap) + rng.pick((-2, -1, 0, 1, 2)))
    price = product // size
    product = price * size
    w.update({"mode_set": False, "set": [], "dex": dex, "asset": asset, "filler": asset, "caps_kind": rng.pick(("tree", "flat")), "caps": {asset: cap},
              "sizes_kind": rng.pick(("tree", "flat")), "sizes": {asset: size}, "row_len": local + 1 + rng.below(2), "count": 0 if rng.below(2) else local + 1,
              "total": max(0, int(product / 0.9) + rng.pick((-2, -1, 0, 1, 2)))})
    w["prices"] = PriceTable((index, price if index == local else 7) for index in range(w["row_len"]))
    if rng.below(3) == 0:
        w["caps"] = {}
        w["count"] = local + 1
    return w


def make_far(rng, kind):
    """Assets whose index inside the dex is 1000 or more, so that `asset % 10000` differs from smaller moduli."""
    w = make_world(rng, kind)
    dex = rng.below(2)
    local = 1000 + rng.below(500)
    asset = dex * 10000 + local
    cap = rng.pick(CAPS_SPECIAL)
    w.update({"mode_set": False, "set": [], "dex": dex, "asset": asset, "filler": asset, "caps_kind": rng.pick(("tree", "flat")), "caps": {asset: cap},
              "sizes_kind": rng.pick(("tree", "flat")), "sizes": {asset: 1 + rng.below(50), asset + 1: 1 + rng.below(50)}, "row_len": local + 1 + rng.below(3), "count": 0})
    w["prices"] = PriceTable({local: 1 + rng.below(100), local + 1: 1 + rng.below(100), 3: 4})
    if kind == "fold":
        w.update({"pos": local, "length": local + 1 + rng.below(2), "init": rng.below(100), "cache": (0, 0)})
    return w


def case_stream():
    rng = Lcg(0x115A11CA9)
    for index in range(CASE_PREDICATE):
        yield make_world(rng, "pred")
    for index in range(CASE_FOLD):
        yield make_world(rng, "fold")
    for index in range(CASE_EDGE):
        yield make_edge(rng)
    for index in range(CASE_FAR):
        yield make_far(rng, "pred" if index % 2 else "fold")


def describe(w, outcome):
    if outcome[0] == "panic":
        return "%s panic %s" % (w["kind"], outcome[1][0])
    if outcome[0] == "ret":
        return "pred %s %s" % ("set" if w["mode_set"] else "caps", "at cap" if outcome[1] else "below cap")
    if outcome[0] == "fold":
        return "fold %s" % ("sum" if outcome[1] else "stops")
    return "other"


# ---- comparison, negative controls, mutants ----

CRASHES = (Halt, IndexError, KeyError, OverflowError, ValueError, TypeError, ZeroDivisionError, EvidenceError, Panicked)
MUTANT_CASES = 24
GROUPS = ((PREDICATE, "at-cap test"), (FOLD, "sum fold"), (SEARCH, "ring search"))


def run_case(harness, w):
    try:
        return harness.run(w)
    except CRASHES as error:
        return ("crash", type(error).__name__)


def verify_digest(blob, expected=SHA256):
    digest = hashlib.sha256(blob).hexdigest()
    if digest != expected:
        raise EvidenceError("binary SHA-256 mismatch: %s" % digest)


def group_rows(image, start):
    begin, end = image.exact_fde(start)
    return begin, end, decode_range(image, begin, end)


def detects_bug(bug, worlds_outcomes):
    for w, outcome in worlds_outcomes():
        try:
            if spec_for(w, bug) != outcome:
                return True
        except IndexError:
            return True
    return False


def input_controls(image):
    """Each entry must raise the named error; returns (name, detected) rows."""
    rows = []

    def raises(name, error, action):
        try:
            action()
        except error:
            rows.append((name, True))
            return
        rows.append((name, False))

    raises("flipped digest", EvidenceError, lambda: verify_digest(b"not the node binary"))
    raises("address outside every section", EvidenceError, lambda: image.offset(0x10))
    raises("not an FDE start", EvidenceError, lambda: image.exact_fde(PREDICATE + 1))
    raises("address before every FDE", EvidenceError, lambda: image.fde(0))
    raises("decode past the FDE end", EvidenceError, lambda: decode_range(image, PREDICATE, PREDICATE + 2))
    harness = Harness(image)
    harness.machine.step_limit = 5
    sample = next(case_stream())
    raises("step limit", Halt, lambda: harness.run(sample))
    raises("write outside heap and stack", Halt, lambda: harness.machine.memory.write(0x1234, 8, 1))
    return rows


def mutation_targets_for(image, rows):
    return list(mutation_targets(image, rows))


def analyse(image, full=True):
    harness = Harness(image)
    machine = harness.machine
    machine.step_limit = STEP_LIMIT
    reached = {}
    seen = set()
    mismatches = []
    outcomes = collections.Counter()
    sample_lines = []
    ran = []
    total = 0
    for index, w in enumerate(case_stream()):
        machine.seen = set()
        outcome = run_case(harness, w)
        total += 1
        expected = spec_for(w)
        if expected != outcome:
            mismatches.append("%d %s: machine %r, spec %r" % (index, label_for(w), outcome, expected))
        for va in machine.seen:
            slot = reached.setdefault(va, [])
            if len(slot) < MUTANT_CASES:
                slot.append(index)
        seen |= machine.seen
        outcomes[describe(w, expected)] += 1
        ran.append(outcome)
        if index % 25 == 0:
            sample_lines.append("%d\t%s\t%s" % (index, label_for(w), describe(w, expected)))
    steps = machine.steps
    if mismatches and full:
        raise EvidenceError("spec mismatch: %s" % mismatches[0])

    def pairs():
        return zip(case_stream(), ran)

    controls = []
    for bug in SPEC_BUGS:
        controls.append(("specification: " + bug, detects_bug(bug, pairs)))
    results = []
    if full:
        results = run_mutants(image, harness, reached)
    killed = [row for row in results if row["result"] == "killed" and row["kind"] == "branch"]
    chosen = killed[::max(1, len(killed) // 12)][:12]
    for row in chosen:
        controls.append(("code byte: %#x %s" % (row["va"], row["kind"]), True))
    controls += [("input: " + name, ok) for name, ok in input_controls(image)]
    functions = []
    for start, role in GROUPS:
        begin, end, rows = group_rows(image, start)
        functions.append({"role": role, "start": "%#x" % begin, "end": "%#x" % end, "size": end - begin, "instructions": len(rows),
                          "instructions_stepped": sum(1 for row_ in rows if row_.va in seen)})
    return {
        "functions": functions, "cases": total, "mismatches": len(mismatches), "first_mismatch": mismatches[0] if mismatches else "",
        "instructions_stepped": steps, "outcomes": dict(sorted(outcomes.items())), "controls": controls, "results": results,
        "samples": sample_lines,
    }


def run_mutants(image, harness, reached):
    machine = harness.machine
    machine.step_limit = MUTANT_STEP_LIMIT
    wanted = set()
    for indices in reached.values():
        wanted.update(indices)
    worlds = {index: w for index, w in enumerate(case_stream()) if index in wanted}
    results = []
    for start, _ in GROUPS:
        begin, end, rows = group_rows(image, start)
        for va, at, kind in mutation_targets(image, rows):
            indices = reached.get(va)
            if not indices:
                results.append({"function": begin, "va": va, "kind": kind, "result": "unreached"})
                continue
            machine.patches = mutate_patch(image, va, at, kind)
            machine.cache.pop(va, None)
            failed = False
            for index in indices:
                w = worlds[index]
                if run_case(harness, w) != spec_for(w):
                    failed = True
                    break
            machine.patches = {}
            machine.cache.pop(va, None)
            results.append({"function": begin, "va": va, "kind": kind, "result": "killed" if failed else "survived"})
    return results


# ---- evidence ----

FIELDS = {
    "dex_row": {
        "+0x10": "asset count of the dex", "+0x50": "dex number; asset id = dex * 10000 + index",
        "+0xf0/+0xf8/+0x100/+0x108": "size map: niche word or ring capacity, then root or buffer, height or head, length",
        "+0x150/+0x158": "asset rows: pointer and length, stride 0x60, price word at +0x20",
        "+0x378": "mode word; the niche value 0x8000000000000000 selects the stored asset set",
        "+0x3d0/+0x3d8": "stored asset set: root and height", "+0x478": "total cap, i64",
        "+0x4a0": "pointer to a block whose cap map starts at +0x30",
    },
    "map_enum": {
        "niche word": "0x8000000000000000: B-tree map with root at +8 and height at +0x10",
        "other word": "capacity of a sorted ring buffer of 16 byte entries: buffer +8, head +0x10, length +0x18",
        "tree node": "11 keys at +0x08, 11 values at +0x60, length u16 at +0xba, 12 edges at +0xc0, size 0x120",
        "set node": "11 keys at +0x08, length u16 at +0x62, 12 edges at +0x68, size 0xc8",
    },
}


def slot_loads(image, slot):
    """Every `mov reg, [rip+disp]` in .text (REX.W 8B, rip-relative) that reads one data slot."""
    base, text = image.text_bytes()
    rows = []
    for match in re.finditer(rb"[\x48\x4c]\x8b[\x05\x0d\x15\x1d\x25\x2d\x35\x3d]", text, re.S):
        at = match.start()
        if base + at + 7 + struct.unpack_from("<i", text, at + 3)[0] == slot:
            rows.append(base + at)
    return rows


STEP_NAME = b"cancel_aggressive_orders_at_oi_cap"


def step_name_sites(image):
    """Every copy of the step name text in file-backed data and every rip-relative lea of it in .text, with the owning FDE."""
    base, text = image.text_bytes()
    rows = []
    for section in image.mapped:
        data = image.blob[section["offset"]:section["offset"] + section["size"]]
        at = data.find(STEP_NAME)
        while at >= 0:
            va = section["address"] + at
            for match in re.finditer(rb"[\x48\x4c]\x8d[\x05\x0d\x15\x1d\x25\x2d\x35\x3d]", text, re.S):
                spot = match.start()
                if base + spot + 7 + struct.unpack_from("<i", text, spot + 3)[0] == va:
                    rows.append({"string_va": "%#x" % va, "lea": "%#x" % (base + spot), "owner_fde": "%#x" % image.fde(base + spot)[0], "owner_size": image.fde(base + spot)[1] - image.fde(base + spot)[0]})
            at = data.find(STEP_NAME, at + 1)
    return rows


def read_double(image, va):
    return struct.unpack_from("<d", image.blob, image.offset(va))[0]


def evidence_for(image, state):
    relative = {slot: addend for slot, kind, addend, _ in image.relocations() if kind == 8}
    if relative.get(PREDICATE_SLOT) != PREDICATE:
        raise EvidenceError("predicate slot")
    doubles = {"cap_factor": read_double(image, CAP_FACTOR), "inf": read_double(image, INF_WORD), "clamp_top": read_double(image, CLAMP_TOP), "clamp_low": read_double(image, CLAMP_LOW)}
    if doubles["cap_factor"] != 0.9 or doubles["clamp_top"] != 2.0 ** 63 or doubles["clamp_low"] != 2.0 ** 63 - 1024:
        raise EvidenceError("doubles")
    locations = []
    for slot, name in ((LOC_PRED_BOUNDS, "asset row bound in the test"), (LOC_PRED_UNWRAP, "negative cap in the test"), (LOC_FOLD_BOUNDS, "asset row bound in the fold"), (LOC_FOLD_ARITH, "id arithmetic in the fold")):
        path, line, column = image.location(slot, relative)
        locations.append({"slot": "%#x" % slot, "name": name, "path": path, "line": line, "column": column})
    rows = []
    direct = direct_sites(image, (PREDICATE, FOLD, SEARCH))
    for target in sorted(direct):
        for va, opcode in sorted(direct[target]):
            rows.append((target, va, "rel32 %#x" % opcode, image.fde(va)[0], image.fde(va)[1]))
    for va in slot_sites(image, PREDICATE_SLOT):
        rows.append((PREDICATE, va, "slot", image.fde(va)[0], image.fde(va)[1]))
    for va in slot_loads(image, PREDICATE_SLOT):
        rows.append((PREDICATE, va, "slot load", image.fde(va)[0], image.fde(va)[1]))
    tally = {key: sum(1 for row in state["results"] if row["result"] == key) for key in ("killed", "survived", "unreached")}
    evidence = {
        "target": {"file": "artifacts/node/115/hl-node", "sha256": SHA256},
        "step_name_sites": step_name_sites(image), "functions": state["functions"], "doubles": doubles, "locations": locations, "fields": FIELDS,
        "slot": {"address": "%#x" % PREDICATE_SLOT, "target": "%#x" % relative[PREDICATE_SLOT]},
        "cases": {"total": state["cases"], "predicate": CASE_PREDICATE, "fold": CASE_FOLD, "edge": CASE_EDGE, "far": CASE_FAR},
        "outcomes": state["outcomes"], "mismatches": state["mismatches"], "first_mismatch": state["first_mismatch"],
        "instructions_stepped": state["instructions_stepped"], "mutations": tally,
        "negative_controls": {"total": len(state["controls"]), "detected": sum(1 for _, ok in state["controls"] if ok)},
    }
    return evidence, rows


def render(image, state):
    evidence, sites = evidence_for(image, state)
    files = {"evidence.json": (json.dumps(evidence, indent=2, sort_keys=True) + "\n").replace("\x40", "[at]")}
    lines = ["target\tsite\tcall\tcaller_fde\tcaller_fde_end"] + ["%#x\t%#x\t%s\t%#x\t%#x" % row for row in sites]
    files["call_sites.tsv"] = "\n".join(lines) + "\n"
    files["cases.tsv"] = "\n".join(["index\tlabel\toutcome"] + state["samples"]) + "\n"
    lines = ["function\tva\tkind\tresult"] + ["%#x\t%#x\t%s\t%s" % (row["function"], row["va"], row["kind"], row["result"]) for row in state["results"]]
    files["mutations.tsv"] = "\n".join(lines) + "\n"
    lines = ["control\tdetected"] + ["%s\t%s" % (name, "yes" if ok else "no") for name, ok in state["controls"]]
    files["controls.tsv"] = "\n".join(lines) + "\n"
    tally = evidence["mutations"]
    files["measure.json"] = json.dumps({"cases": state["cases"], "negative_controls": len(state["controls"]), "negative_detected": sum(1 for _, ok in state["controls"] if ok),
                                        "mutants_killed": tally["killed"], "mutants_survived": tally["survived"], "mutants_unreached": tally["unreached"]}, indent=2, sort_keys=True) + "\n"
    return files


def write_outputs(folder, files):
    folder = pathlib.Path(folder)
    folder.mkdir(parents=True, exist_ok=True)
    for name, text in sorted(files.items()):
        (folder / name).write_text(text, encoding="ascii", newline="\n")


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--out", required=True, help="output folder")
    options = parser.parse_args(argv)
    image = load_image()
    files = render(image, analyse(image))
    write_outputs(options.out, files)
    for name in sorted(files):
        print(name, hashlib.sha256(files[name].encode()).hexdigest())
    return 0


if __name__ == "__main__":
    sys.exit(main())
