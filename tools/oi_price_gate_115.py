#!/usr/bin/env python3
"""Rebuild the node #115 open interest gate on a price update from ELF bytes and prove it against the real instructions.

`0x447ab80` takes the three price lists of one dex. `0x366ce20` runs the row closure `0x3d987f0` on every row of the Spot, Mark and
External lists: the closure adds the book field `total_sz` to the stored size of the asset (read from a B-tree or a sorted ring
through `0x35bd660` / `0x45547e0`) and tests size times price in `0x447c620`. Failing rows leave their list and push two texts.
Unless the niche word at owner `+0x378` is `i64::MIN`, the gate then folds the Mark list into a total, compares a tenth of it with
the cap at owner `+0x478` and clears the Mark list through `0x366cc80`. The real bytes run in a Python evaluator with the callees
at the edge stubbed. A separately written specification predicts every result and stub argument, and every condition, immediate and
field offset is flipped to show the run can tell. No objdump or readelf output is parsed, and the binary is never executed.
Standard library only.
"""

import argparse
import bisect
import hashlib
import json
import math
import pathlib
import random
import re
import struct
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))

from elf_index import sections  # noqa: E402
from fde_extents import eh_frame_records  # noqa: E402

BINARY = ROOT / "artifacts" / "node" / "115" / "hl-node"
SHA256 = "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301"

HOST = 0x447AB80
RETAIN = 0x366CE20
ROW = 0x3D987F0
CHECK = 0x447C620
CLEAR = 0x366CC80
RING = 0x45547E0
BTREE = 0x35BD660
CLONE = 0x3DC86B0
COLLECT = 0x3CC57C0
FOLD = 0x44810D0

SLOT_HOST = 0x64E79C0
SLOT_FOLD = 0x64EAAC0
SLOT_FORMAT = 0x64DF6E8
SLOT_GROW = 0x64E0C10
SLOT_RECORD = 0x64E4EA8
SLOT_FREE = 0x64DF4A0
SLOT_UNWRAP = 0x64DF6A0
SLOT_BOUNDS = 0x64DF620
SLOT_SHOW_U32 = 0x64E8090
SLOT_SHOW_KIND = 0x64E8098
SLOT_SHOW_SOURCE = 0x64E8C68
SLOT_SHOW_F64 = 0x64E5A68

TEXT_ASSET = 0x449121
TEXT_TOTAL = 0x44CAF1
TEXT_MISSING = 0x43AF28
LOC_SATURATE = 0x648BA08
LOC_CHECK_UNWRAP = 0x648B9F0
LOC_HOST_UNWRAP = 0x648BA38
LOC_BOOK = 0x647DC08
LOC_ROW = 0x647A6C8
MSG_UNWRAP = 0x7D3212
LIMIT_LOW = 0x28F5C28F5C28F5D
LIMIT_HIGH = 0x199999999999999A
NONE_WORD = 0x8000000000000000

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
HEAP_SIZE = 0xA000
RETURN_SENTINEL = 0xDEAD0000
POISON = 0xA5A5A5A5A5A5A5A5
STEP_LIMIT = 200000
MUTANT_STEP_LIMIT = 20000

OWNER = HEAP_BASE + 0x100
SIZE_NODES = HEAP_BASE + 0x1000
RING_ROWS = HEAP_BASE + 0x3000
MAP_HEADER = HEAP_BASE + 0x3800
CLONE_ROWS = HEAP_BASE + 0x3A00
BOOKS = HEAP_BASE + 0x4000
BOOK_LIST = HEAP_BASE + 0x6000
LISTS = HEAP_BASE + 0x6100
ERROR_LIST = LISTS + 0x50
OUT = HEAP_BASE + 0x6200
CLOSURE = HEAP_BASE + 0x6300
ROWS_0 = HEAP_BASE + 0x6500
ROWS_1 = HEAP_BASE + 0x6700
ROWS_2 = HEAP_BASE + 0x6900
ERRORS = HEAP_BASE + 0x7000
TEXT_BASE = 0x7000000
ROWS = (ROWS_0, ROWS_1, ROWS_2)

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



# ---- specification, written from a full instruction read and kept apart from the evaluator ----

def signed(value):
    return value - (1 << 64) if value & SIGN[8] else value


def wrapped(value):
    value &= MASK[8]
    return signed(value)


def wire_asset(asset):
    """The u32 id a text shows for an internal asset."""
    if asset < 10000:
        return asset
    if asset <= 99899999:
        return asset + 100000
    return MASK[4]


def saturating_int(value):
    """Rust `as i64` on a double: NaN is 0, out of range saturates."""
    if value != value:
        return 0
    if value >= 9223372036854775808.0:
        return (1 << 63) - 1
    if value <= -9223372036854775808.0:
        return -(1 << 63)
    return int(value)


def text_word(number):
    return (0x20 + number, TEXT_BASE + number * 0x10, 0x30 + number)


def map_words(unique):
    """The four words the stubbed map builder leaves in the host frame."""
    return (NONE_WORD, MAP_HEADER, unique, 0xC011EC7 + unique)


class Spec:
    """One world: the owner fields, the size map, the books and the three price lists. `bug` plants one wrong rule."""

    def __init__(self, w, bug=None):
        self.w = w
        self.bug = bug
        self.events = []
        self.texts = 0
        self.errors = list(w["errors"])
        self.error_cap = w["error_cap"]
        self.lists = [list(rows) for rows in w["lists"]]
        self.mark_cap = w["caps"][1]
        self.mark_head = (w["caps"][1], ROWS_1)

    def text(self, template, args):
        self.events.append(("format", template, args))
        self.texts += 1
        return text_word(self.texts)

    def push(self, text):
        if len(self.errors) == self.error_cap:
            self.events.append(("grow", ERROR_LIST))
            self.error_cap = self.error_cap * 2 or 4
        self.errors.append(text)

    def check(self, asset, kind, price, stored, book):
        """None when the row passes, else the text word."""
        bug = self.bug
        if bug == "ignore_book":
            book = 0
        if bug == "ignore_stored":
            stored = 0
        if book & SIGN[8] and bug != "negative_book_ok":
            raise Panicked(("unwrap", LOC_CHECK_UNWRAP))
        total = signed(stored) + signed(book) if bug == "negative_book_ok" else signed(stored) + book
        if total >= SIGN[8]:
            if bug != "no_record_saturate":
                self.events.append(("record", 0, LOC_SATURATE))
            total = SIGN[8] - 1 if bug != "no_saturate" else wrapped(total)
        price = signed(price)
        fits = False
        product = price
        if price >= 0 or bug == "negative_price_fits":
            exact = price * total
            fits = -SIGN[8] <= exact < SIGN[8]
            product = wrapped(exact)
        low = LIMIT_LOW + {"low_plus": 1, "low_minus": -1}.get(bug, 0)
        high = LIMIT_HIGH + {"limit_plus": 1, "limit_minus": -1}.get(bug, 0)
        word_min = self.w["mode_min"]
        if bug == "record_always":
            word_min = True
        if bug == "record_inverted":
            word_min = not word_min
        if not (fits and product < low) and word_min:
            self.events.append(("record", 1, self.w.get("check_location", LOC_ROW)))
        if fits and (product <= high if bug == "limit_inclusive" else product < high):
            return None
        shown = float(product) / 1000000.0 if fits else 0.0
        if bug == "shown_unscaled":
            shown = float(product) if fits else 0.0
        if bug == "shown_unfit_product":
            shown = float(product) / 1000000.0
        wire = asset if bug == "wire_plain" else wire_asset(asset) if bug != "wire_edge" else (asset if asset < 10000 else asset + 100000 if asset <= 99899998 else MASK[4])
        return self.text(TEXT_ASSET, (wire, kind, to_bits(shown)))

    def row(self, kind, asset, price):
        """True when the row stays."""
        w = self.w
        bug = self.bug
        sizes = {} if w["form"] == "null" else w["sizes"]
        stored = sizes.get(asset, 1 if bug == "absent_is_one" else 0)
        book = 0
        if w["books"] is not None:
            index = asset % (9999 if bug == "book_mod_9999" else 10000)
            if index >= len(w["books"]):
                if bug != "book_no_bounds":
                    raise Panicked(("bounds", index, len(w["books"]), LOC_BOOK))
            else:
                book = w["books"][index]
        word = self.check(asset, kind, price, stored, book)
        if word is None:
            return True
        self.push(word)
        if bug == "single_text":
            return bug == "keep_failed_row"
        source = 0 if bug == "source_zero" else w["source"]
        shown_kind = 2 - kind if bug == "kind_swapped" else kind
        self.push(self.text(TEXT_MISSING, (source, wire_asset(asset), shown_kind)))
        return bug == "keep_failed_row"

    def retain(self):
        order = (2, 1, 0) if self.bug == "retain_reverse" else (0, 1, 2)
        for kind in order:
            self.lists[kind] = [(asset, price) for asset, price in self.lists[kind] if self.row(kind, asset, price)]

    def clear(self):
        rows = self.lists[1]
        if self.bug != "clear_keeps_mark":
            self.lists[1] = []
            self.mark_head = (0, 8)
        order = rows[::-1] if self.bug == "clear_reverse" else rows
        for asset, _ in order:
            self.push(self.text(TEXT_MISSING, (self.w["source"], wire_asset(asset), 1 if self.bug != "clear_kind_zero" else 0)))
        if self.mark_cap or self.bug == "free_always":
            self.events.append(("free", ROWS_1, self.mark_cap * 16, 0))

    def host(self):
        """The whole gate: rows, the Mark total, the Mark list, result."""
        w = self.w
        bug = self.bug
        self.retain()
        if w["mode_min"] != (bug == "gate_inverted"):
            return
        rows = tuple(self.lists[1])
        self.events.append(("clone", rows))
        self.events.append(("collect", rows))
        self.events.append(("fold", OWNER, map_words(len(dict(rows)))))
        whole = w["fold"]
        if whole is None:
            self.clear()
            return
        cap = signed(w["cap"])
        scaled = (0.125 if bug == "scale_eighth" else 0.1) * float(whole)
        if cap < 0 and bug != "negative_cap_ok":
            raise Panicked(("unwrap", LOC_HOST_UNWRAP))
        over = saturating_int(scaled) >= cap if bug == "cap_inclusive" else saturating_int(scaled) > cap
        if over:
            self.push(self.text(TEXT_TOTAL, (to_bits(float(whole) / 1000000.0), to_bits(float(cap) / 1000000.0))))
            if bug != "no_clear_after_text":
                self.clear()


SPEC_BUGS = (
    "limit_plus", "limit_minus", "low_plus", "low_minus", "limit_inclusive", "ignore_book", "ignore_stored", "negative_book_ok",
    "no_saturate", "no_record_saturate", "record_always", "record_inverted", "negative_price_fits", "shown_unscaled", "shown_unfit_product",
    "wire_plain", "wire_edge", "kind_swapped", "source_zero", "single_text", "keep_failed_row", "book_mod_9999", "book_no_bounds",
    "absent_is_one", "retain_reverse", "clear_reverse", "clear_keeps_mark", "clear_kind_zero", "free_always", "gate_inverted",
    "scale_eighth", "negative_cap_ok", "cap_inclusive", "no_clear_after_text",
)


def run_spec(case, bug=None):
    w = case.world
    spec = Spec(w, bug)
    answer = {"events": spec.events, "stop": None, "out": None}
    try:
        if case.kind == "check":
            word = spec.check(w["asset"], w["kind"], w["price"], w["stored"], w["book"])
            answer["out"] = None if word is None else word
        elif case.kind == "row":
            answer["out"] = spec.row(w["kind"], w["asset"], w["price"])
            answer["errors"] = spec.errors
        elif case.kind == "retain":
            spec.retain()
            answer["lists"] = spec.lists
            answer["errors"] = spec.errors
        elif case.kind == "clear":
            spec.clear()
            answer["lists"] = spec.lists
            answer["errors"] = spec.errors
            answer["mark_head"] = spec.mark_head
        elif case.kind == "host":
            spec.host()
            answer["out"] = "ok"
            answer["lists"] = spec.lists
            answer["errors"] = spec.errors
            answer["mark_head"] = spec.mark_head
    except Panicked as stop:
        answer["stop"] = stop.args[0]
    return answer


# ---- harness: real bytes; the callees at the edge are stubbed and their arguments compared ----

class RealExcept:
    """Every call target runs its real bytes unless the harness stubs it."""

    def __init__(self):
        self.stubs = frozenset()

    def __contains__(self, target):
        return target not in self.stubs


class Case:
    def __init__(self, label, kind, world):
        self.label = label
        self.kind = kind
        self.world = world


NODE_KEYS = 0x08
NODE_VALUES = 0x60
NODE_LENGTH = 0xBA
NODE_EDGES = 0xC0
NODE_SIZE = 0x120
NODE_CAPACITY = 11
BOOK_STRIDE = 0x120
BOOK_TOTAL = 0x118
UNMAPPED = 0x10
TEMPTING = (1 << 63) - 3


def ramp(count, start):
    return bytes((start + index * 7) & 0xFF or 1 for index in range(count))


OWNER_IMAGE = ramp(0x500, 0x2B)
BOOK_IMAGE = ramp(BOOK_STRIDE, 0x39)


def tree_rows(pairs):
    """Split sorted pairs into one leaf or one root over leaves, with uniform depth."""
    pairs = sorted(pairs)
    if len(pairs) <= NODE_CAPACITY:
        return pairs, []
    per = NODE_CAPACITY - 1
    keys, leaves, at = [], [], 0
    while True:
        leaves.append(pairs[at:at + per])
        at += per
        if at >= len(pairs):
            break
        keys.append(pairs[at])
        at += 1
    return keys, leaves


class Harness:
    def __init__(self, image):
        self.image = image
        self.machine = Machine(image)
        machine = self.machine
        self.relative = {slot: addend for slot, kind, addend, _ in image.relocations() if kind == 8}
        relative = self.relative
        machine.memory.statics.update(relative)
        self.show = {relative[SLOT_SHOW_U32]: "u32", relative[SLOT_SHOW_KIND]: "kind", relative[SLOT_SHOW_F64]: "f64", relative[SLOT_SHOW_SOURCE]: "source"}
        self.base_slots = {relative[SLOT_UNWRAP]: self.on_unwrap, relative[SLOT_BOUNDS]: self.on_bounds,
                           relative[SLOT_FORMAT]: self.on_format, relative[SLOT_GROW]: self.on_grow, relative[SLOT_RECORD]: self.on_record, relative[SLOT_FREE]: self.on_free,
                           relative[SLOT_FOLD]: self.on_fold}
        machine.slots = dict(self.base_slots)
        self.real = RealExcept()
        self.real.stubs = frozenset(self.base_slots) | frozenset((CLONE, COLLECT))
        machine.real = self.real
        machine.calls = {CLONE: self.on_clone, COLLECT: self.on_collect}
        self.events = []
        self.texts = 0
        self.w = None

    def on_unwrap(self, m):
        raise Panicked(("unwrap", m.regs[R8], m.regs[RSI], m.regs[RDI]))

    def on_bounds(self, m):
        raise Panicked(("bounds", m.regs[RDI], m.regs[RSI], m.regs[RDX]))

    def on_record(self, m):
        self.events.append(("record", m.regs[RDI] & 0xFF, m.regs[RSI]))

    def on_free(self, m):
        self.events.append(("free", m.regs[RDI], m.regs[RSI], m.regs[RDX]))

    def on_grow(self, m):
        memory = m.memory
        at = m.regs[RDI]
        self.events.append(("grow", at))
        cap = memory.read(at, 8)
        memory.write(at, 8, cap * 2 or 4)

    def on_format(self, m):
        memory = m.memory
        template = m.regs[RSI]
        count = {TEXT_ASSET: 3, TEXT_MISSING: 3, TEXT_TOTAL: 2}.get(template)
        if count is None:
            raise Halt("template %#x" % template)
        args = []
        for index in range(count):
            at = memory.read(m.regs[RDX] + index * 16, 8)
            show = memory.read(m.regs[RDX] + index * 16 + 8, 8)
            kind = self.show.get(show)
            if kind is None:
                raise Halt("display function %#x" % show)
            args.append((kind, memory.read(at, {"u32": 4, "kind": 1, "f64": 8, "source": 1}[kind])))
        wanted = {TEXT_ASSET: ("u32", "kind", "f64"), TEXT_MISSING: ("source", "u32", "kind"), TEXT_TOTAL: ("f64", "f64")}[template]
        if tuple(item[0] for item in args) != wanted:
            raise Halt("argument kinds")
        self.events.append(("format", template, tuple(item[1] for item in args)))
        self.texts += 1
        word = text_word(self.texts)
        for index in range(3):
            memory.write(m.regs[RDI] + index * 8, 8, word[index])

    def read_rows(self, at, count):
        if count > 64:
            raise Halt("row count")
        memory = self.machine.memory
        return [(memory.read(at + index * 16, 8), memory.read(at + index * 16 + 8, 8)) for index in range(count)]

    def on_clone(self, m):
        """0x3dc86b0 copies a slice of 16 byte rows into a fresh vector."""
        memory = m.memory
        begin, end = m.regs[RSI], m.regs[RDX]
        count = (end - begin) // 16
        rows = tuple(self.read_rows(begin, count))
        self.events.append(("clone", rows))
        out = m.regs[RDI]
        memory.put_bytes(CLONE_ROWS, memory.bytes_at(begin, count * 16))
        memory.write(out, 8, count)
        memory.write(out + 8, 8, CLONE_ROWS if count else 8)
        memory.write(out + 0x10, 8, count)
        m.regs[RAX] = out

    def on_collect(self, m):
        """0x3cc57c0 builds the price map from the cloned rows."""
        memory = m.memory
        vec = m.regs[RSI]
        rows = tuple(self.read_rows(memory.read(vec + 8, 8), memory.read(vec + 0x10, 8)))
        self.events.append(("collect", rows))
        for index, word in enumerate(map_words(len(dict(rows)))):
            memory.write(m.regs[RDI] + index * 8, 8, word)

    def on_fold(self, m):
        """The total fold behind slot 0x64eaac0: (owner, map) -> (tag, total)."""
        self.events.append(("fold", m.regs[RDI], tuple(m.memory.read(m.regs[RSI] + 8 * index, 8) for index in range(4))))
        total = self.w["fold"]
        m.regs[RAX] = 0 if total is None else 1
        m.regs[RDX] = 0 if total is None else total & MASK[8]
        m.keep_rdx = True

    def write_tree(self, at, pairs):
        memory = self.machine.memory
        keys, leaves = tree_rows(pairs)

        def node(where, rows, edges):
            memory.put_bytes(where, ramp(NODE_SIZE, 0x19))
            for index in range(NODE_CAPACITY):
                memory.write(where + NODE_KEYS + index * 8, 8, rows[index][0] if index < len(rows) else TEMPTING)
                if index < len(rows):
                    memory.write(where + NODE_VALUES + index * 8, 8, rows[index][1])
            memory.write(where + NODE_LENGTH, 2, len(rows))
            for index in range(NODE_CAPACITY + 1):
                memory.write(where + NODE_EDGES + index * 8, 8, edges[index] if index < len(edges) else UNMAPPED + index * 8)
        edges = [at + (index + 1) * NODE_SIZE for index in range(len(leaves))]
        node(at, keys, edges)
        for where, leaf in zip(edges, leaves):
            node(where, leaf, [])
        return at, 1 if leaves else 0

    def write_ring(self, pairs, extra, head):
        """A sorted ring: logical row i sits at physical (head + i) % capacity; the other slots hold tempting keys."""
        memory = self.machine.memory
        pairs = sorted(pairs)
        capacity = len(pairs) + extra
        for index in range(capacity):
            memory.write(RING_ROWS + index * 16, 8, TEMPTING - index)
            memory.write(RING_ROWS + index * 16 + 8, 8, 0xBAD0 + index)
        if capacity:
            head %= capacity
        for index, (key, value) in enumerate(pairs):
            at = (head + index) % capacity
            memory.write(RING_ROWS + at * 16, 8, key)
            memory.write(RING_ROWS + at * 16 + 8, 8, value)
        return capacity, head, len(pairs)

    def world(self, w):
        """Lay one world out in memory."""
        memory = self.machine.memory
        memory.put_bytes(OWNER, OWNER_IMAGE)
        pairs = sorted(w["sizes"].items())
        if w["form"] == "ring":
            capacity, head, count = self.write_ring(pairs, w["ring_extra"], w["ring_head"])
            memory.write(OWNER + 0xF0, 8, capacity)
            memory.write(OWNER + 0xF8, 8, RING_ROWS)
            memory.write(OWNER + 0x100, 8, head)
            memory.write(OWNER + 0x108, 8, count)
        else:
            root, height = self.write_tree(SIZE_NODES, pairs) if pairs and w["form"] == "tree" else (0, 0)
            memory.write(OWNER + 0xF0, 8, NONE_WORD)
            memory.write(OWNER + 0xF8, 8, root)
            memory.write(OWNER + 0x100, 8, height)
            memory.write(OWNER + 0x108, 8, len(pairs))
        memory.write(OWNER + 0x378, 8, NONE_WORD if w["mode_min"] else w["mode_word"])
        memory.write(OWNER + 0x478, 8, w["cap"])
        books = w["books"] or ()
        for index, total in enumerate(books):
            memory.put_bytes(BOOKS + index * BOOK_STRIDE, BOOK_IMAGE)
            memory.write(BOOKS + index * BOOK_STRIDE + BOOK_TOTAL, 8, total)
        memory.put_bytes(BOOK_LIST, ramp(0x18, 0x55))
        memory.write(BOOK_LIST + 8, 8, BOOKS)
        memory.write(BOOK_LIST + 0x10, 8, len(books))
        memory.put_bytes(LISTS, ramp(0x68, 0x61))
        for index, rows in enumerate(w["lists"]):
            memory.write(LISTS + index * 0x18, 8, w["caps"][index])
            memory.write(LISTS + index * 0x18 + 8, 8, ROWS[index])
            memory.write(LISTS + index * 0x18 + 0x10, 8, len(rows))
            for at, (asset, price) in enumerate(rows):
                memory.write(ROWS[index] + at * 16, 8, asset)
                memory.write(ROWS[index] + at * 16 + 8, 8, price)
        memory.write(LISTS + 0x48, 1, w["source"])
        memory.write(ERROR_LIST, 8, w["error_cap"])
        memory.write(ERROR_LIST + 8, 8, ERRORS)
        memory.write(ERROR_LIST + 0x10, 8, len(w["errors"]))
        for index, word in enumerate(w["errors"]):
            for part in range(3):
                memory.write(ERRORS + index * 24 + part * 8, 8, word[part])

    def closure(self, kind):
        memory = self.machine.memory
        w = self.w
        pair = CLOSURE + 0x40
        memory.write(pair, 8, OWNER)
        memory.write(pair + 8, 8, CLOSURE + 0x60)
        memory.write(CLOSURE + 0x60, 8, BOOK_LIST if w["books"] is not None else 0)
        memory.write(CLOSURE + 0x68, 1, kind)
        memory.write(CLOSURE + 0x69, 1, w["source"])
        memory.write(CLOSURE, 8, pair)
        memory.write(CLOSURE + 8, 8, CLOSURE + 0x68)
        memory.write(CLOSURE + 0x10, 8, ERROR_LIST)
        memory.write(CLOSURE + 0x18, 8, CLOSURE + 0x69)

    def read_errors(self, base=ERROR_LIST):
        memory = self.machine.memory
        count = memory.read(base + 0x10, 8)
        if count > 64:
            raise Halt("error count")
        at = memory.read(base + 8, 8)
        return [tuple(memory.read(at + index * 24 + part * 8, 8) for part in range(3)) for index in range(count)]

    def read_lists(self, base):
        memory = self.machine.memory
        rows = []
        for index in range(3):
            count = memory.read(base + index * 0x18 + 0x10, 8)
            at = memory.read(base + index * 0x18 + 8, 8)
            rows.append(self.read_rows(at, count) if count else [])
        return rows

    def run(self, case):
        w = case.world
        machine = self.machine
        memory = machine.memory
        self.events = []
        self.texts = 0
        self.w = w
        memory.reset()
        self.world(w)
        answer = {"events": self.events, "stop": None, "out": None}
        try:
            if case.kind == "check":
                memory.write(STACK_TOP - 0x100, 8, w["book"])
                memory.write(STACK_TOP - 0xF8, 8, w.get("check_location", LOC_ROW))
                memory.write(OUT, 8, 0x1234)
                machine.run(CHECK, {RDI: OUT, RSI: OWNER, RDX: w["asset"], RCX: w["kind"] | 0xAB00, R8: w["price"], R9: w["stored"]})
                word = memory.read(OUT, 8)
                if word == NONE_WORD:
                    answer["out"] = None
                else:
                    answer["out"] = (word, memory.read(OUT + 8, 8), memory.read(OUT + 16, 8))
            elif case.kind == "row":
                self.closure(w["kind"])
                rax = machine.run(ROW, {RDI: CLOSURE, RSI: w["asset"], RDX: w["price"]})
                answer["out"] = bool(rax & 0xFF)
                answer["errors"] = self.read_errors()
            elif case.kind == "retain":
                memory.write(CLOSURE + 0x60, 8, BOOK_LIST if w["books"] is not None else 0)
                machine.run(RETAIN, {RDI: LISTS, RSI: OWNER, RDX: CLOSURE + 0x60})
                answer["lists"] = self.read_lists(LISTS)
                answer["errors"] = self.read_errors()
            elif case.kind == "clear":
                machine.run(CLEAR, {RDI: LISTS})
                answer["lists"] = self.read_lists(LISTS)
                answer["errors"] = self.read_errors()
                answer["mark_head"] = (memory.read(LISTS + 0x18, 8), memory.read(LISTS + 0x20, 8))
            else:
                rcx = BOOK_LIST if w["books"] is not None else 0
                rax = machine.run(HOST, {RDI: OUT, RSI: OWNER, RDX: LISTS, RCX: rcx})
                if rax != OUT:
                    raise Halt("result pointer")
                answer["out"] = "ok"
                answer["lists"] = self.read_lists(OUT)
                answer["mark_head"] = (memory.read(OUT + 0x18, 8), memory.read(OUT + 0x20, 8))
                if memory.read(OUT + 0x48, 1) != w["source"]:
                    raise Halt("source byte")
                answer["errors"] = self.read_errors(OUT + 0x50)
        except Panicked as stop:
            answer["stop"] = stop.args[0]
            answer.pop("errors", None)
            answer.pop("lists", None)
            answer.pop("mark_head", None)
        return answer


def normal(case, spec):
    """Stop words in the same shape on both sides."""
    if spec["stop"] and spec["stop"][0] == "unwrap":
        spec = dict(spec, stop=("unwrap", spec["stop"][1], 0x2B, MSG_UNWRAP))
    if spec["stop"]:
        spec = {key: value for key, value in spec.items() if key not in ("errors", "lists", "mark_head")}
    return spec


def spec_run(case, bug=None):
    return normal(case, run_spec(case, bug))


CRASHES = (Halt, IndexError, KeyError, OverflowError, ValueError, TypeError, ZeroDivisionError, EvidenceError)


def compare_answers(case, found, wanted):
    if found != wanted:
        keys = sorted(key for key in set(wanted) | set(found) if found.get(key) != wanted.get(key))
        detail = ""
        if keys:
            left, right = found.get(keys[0]), wanted.get(keys[0])
            if isinstance(left, list) and isinstance(right, list):
                pairs = [(one, two) for one, two in zip(left, right) if one != two]
                left, right = pairs[0] if pairs else (len(left), len(right))
            detail = "%s found %s wanted %s" % (keys[0], str(left)[:300], str(right)[:300])
        return "%s: differs: %s" % (case.label, detail)
    return ""


def compare_run(harness, case):
    """Empty when the bytes and the specification agree, else one line."""
    wanted = spec_run(case)
    try:
        found = harness.run(case)
    except CRASHES as error:
        return "%s: crash %s %s" % (case.label, type(error).__name__, error)
    return compare_answers(case, found, wanted)


# ---- cases ----

def world(**changes):
    base = {"sizes": {}, "form": "tree", "ring_extra": 0, "ring_head": 0, "books": [0, 0, 0, 0], "lists": ([], [], []), "caps": (6, 6, 6), "source": 0,
            "errors": [], "error_cap": 8, "mode_min": False, "mode_word": 3, "cap": 1 << 62, "fold": None,
            "asset": 7, "kind": 0, "price": 100, "stored": 5, "book": 6}
    base.update(changes)
    return base


def spread(count, start=2, step=3, value=11):
    """A sized map with a key every `step`, values unique per key."""
    return {start + index * step: value + index * 13 for index in range(count)}


def check_cases():
    rows = []
    for gated in (False, True):
        for name, limit in (("high", LIMIT_HIGH), ("low", LIMIT_LOW)):
            for delta in (-1, 0, 1):
                rows.append(("product %s%+d gated %d" % (name, delta, gated), world(mode_min=gated, price=1, stored=limit + delta, book=0)))
                rows.append(("split product %s%+d gated %d" % (name, delta, gated), world(mode_min=gated, price=1, stored=limit + delta - 12345, book=12345)))
                rows.append(("price times two %s%+d gated %d" % (name, delta, gated), world(mode_min=gated, price=2, stored=(limit + delta) // 2, book=(limit + delta) % 2)))
        rows.append(("negative price gated %d" % gated, world(mode_min=gated, price=1 << 63 | 5)))
        rows.append(("price -1 gated %d" % gated, world(mode_min=gated, price=MASK[8])))
        rows.append(("zero price gated %d" % gated, world(mode_min=gated, price=0, stored=1 << 62)))
        rows.append(("product over i64 gated %d" % gated, world(mode_min=gated, price=1 << 32, stored=1 << 31, book=0)))
        rows.append(("product wraps negative gated %d" % gated, world(mode_min=gated, price=3, stored=1 << 62, book=0)))
        rows.append(("product wraps small gated %d" % gated, world(mode_min=gated, price=4, stored=1 << 62, book=7)))
        rows.append(("just below i64 gated %d" % gated, world(mode_min=gated, price=1, stored=(1 << 63) - 1, book=0)))
        rows.append(("saturated sum gated %d" % gated, world(mode_min=gated, price=1, stored=(1 << 63) - 5, book=9)))
        rows.append(("saturated sum zero price gated %d" % gated, world(mode_min=gated, price=0, stored=(1 << 63) - 5, book=9)))
        rows.append(("sum exactly i64 max gated %d" % gated, world(mode_min=gated, price=1, stored=(1 << 63) - 5, book=4)))
        rows.append(("sum one over i64 max gated %d" % gated, world(mode_min=gated, price=1, stored=(1 << 63) - 5, book=5)))
        rows.append(("negative stored gated %d" % gated, world(mode_min=gated, stored=(1 << 64) - 50, book=3)))
        rows.append(("negative sum large price gated %d" % gated, world(mode_min=gated, price=1 << 40, stored=(1 << 64) - 50, book=3)))
    rows.append(("book top bit panics", world(book=1 << 63)))
    rows.append(("book all ones panics", world(book=MASK[8])))
    rows.append(("book i64 max", world(price=0, stored=0, book=(1 << 63) - 1)))
    for asset in (0, 1, 9999, 10000, 10001, 99899998, 99899999, 99900000, 99900001, 1 << 32, MASK[8]):
        for kind in (0, 1, 2):
            rows.append(("asset %d kind %d" % (asset, kind), world(asset=asset, kind=kind, price=1, stored=LIMIT_HIGH + 2 + kind, book=0)))
    rows.append(("other location word", world(mode_min=True, price=1, stored=LIMIT_LOW, book=0, check_location=0x5714A28)))
    return [Case("check: " + label, "check", w) for label, w in rows]


def row_cases():
    rows = []
    big = spread(40)
    for form in ("tree", "ring"):
        for key, value in list(big.items())[::4]:
            rows.append(("%s present key %d" % (form, key), world(asset=key, sizes=big, form=form, ring_extra=3, ring_head=7, books=[0] * 16, price=9)))
            rows.append(("%s absent key %d" % (form, key + 1), world(asset=key + 1, sizes=big, form=form, ring_extra=3, ring_head=7, books=[0] * 16, price=9)))
        rows.append(("%s key past every stored key" % form, world(asset=1000, sizes=spread(5), form=form, books=[0] * 16, price=LIMIT_HIGH)))
        rows.append(("%s key below every stored key" % form, world(asset=1, sizes=spread(5), form=form, books=[0] * 16, price=LIMIT_HIGH)))
        rows.append(("%s key past a large map" % form, world(asset=1000, sizes=big, form=form, books=[0] * 16, price=LIMIT_HIGH)))
        high = MASK[8] - 5
        rows.append(("%s key above the filler keys" % form, world(asset=high, sizes=spread(5), form=form, books=None, price=1)))
        rows.append(("%s largest stored key" % form, world(asset=high, sizes={3: 1, high: LIMIT_HIGH}, form=form, books=None, price=1)))
        rows.append(("%s stored fails key" % form, world(asset=5, sizes={5: LIMIT_HIGH}, form=form, price=1)))
        rows.append(("%s stored passes key" % form, world(asset=5, sizes={5: LIMIT_HIGH - 1}, form=form, price=1)))
        rows.append(("%s empty map" % form, world(asset=5, sizes={}, form=form, price=LIMIT_HIGH)))
    for head in range(0, 9):
        for extra in (0, 1, 4):
            rows.append(("ring head %d extra %d hit" % (head, extra), world(asset=8, sizes=spread(6), form="ring", ring_extra=extra, ring_head=head, books=None, price=1)))
            rows.append(("ring head %d extra %d last" % (head, extra), world(asset=17, sizes=spread(6), form="ring", ring_extra=extra, ring_head=head, books=None, price=1)))
            rows.append(("ring head %d extra %d miss" % (head, extra), world(asset=9, sizes=spread(6), form="ring", ring_extra=extra, ring_head=head, books=None, price=1)))
    for form in ("tree", "ring"):
        rows.append(("%s one key hit" % form, world(asset=4, sizes={4: LIMIT_HIGH}, form=form, price=1)))
        rows.append(("%s one key miss low" % form, world(asset=3, sizes={4: LIMIT_HIGH}, form=form, price=1)))
        rows.append(("%s one key miss high" % form, world(asset=5, sizes={4: LIMIT_HIGH}, form=form, price=1)))
    for at in range(4):
        rows.append(("book row %d alone fails" % at, world(asset=at, books=[LIMIT_HIGH if index == at else 0 for index in range(4)], price=1)))
        rows.append(("book row %d of dex 1 fails" % at, world(asset=10000 + at, books=[LIMIT_HIGH if index == at else 0 for index in range(4)], price=1)))
        rows.append(("other book row %d stays" % at, world(asset=at, books=[0 if index == at else LIMIT_HIGH for index in range(4)], price=1)))
    rows.append(("book plus stored fails", world(asset=1, sizes={1: LIMIT_HIGH - 1}, books=[0, 1, 0, 0], price=1)))
    rows.append(("book plus stored passes", world(asset=1, sizes={1: LIMIT_HIGH - 2}, books=[0, 1, 0, 0], price=1)))
    rows.append(("no books", world(asset=1, books=None, sizes={1: LIMIT_HIGH}, price=1)))
    rows.append(("no books passes", world(asset=1, books=None, sizes={1: LIMIT_HIGH - 1}, price=1)))
    rows.append(("no size map", world(asset=1, sizes={}, books=[0, LIMIT_HIGH, 0, 0], price=1)))
    rows.append(("no size map passes", world(asset=1, sizes={}, books=[0, 3, 0, 0], price=1)))
    rows.append(("no size map no books", world(asset=1, sizes={}, books=None, price=MASK[8])))
    rows.append(("empty root", world(asset=1, sizes={5: 1}, form="null", books=[0, LIMIT_HIGH, 0, 0], price=1)))
    rows.append(("index at book length", world(asset=4, books=[0, 0, 0, 0], price=1)))
    rows.append(("index past book length dex 2", world(asset=20009, books=[0, 0, 0, 0], price=1)))
    rows.append(("index last book", world(asset=3, books=[0, 0, 0, 0], price=1)))
    rows.append(("empty books", world(asset=0, books=[], price=1)))
    rows.append(("constant needs 10000 exactly", world(asset=10000, books=[LIMIT_HIGH], price=1)))
    rows.append(("constant needs 9999", world(asset=9999, books=None, sizes={9999: LIMIT_HIGH}, price=1)))
    rows.append(("book row 9999 is the last", world(asset=9999, books=[0] * 16, price=1)))
    for kind in (0, 1, 2):
        for source in (0, 1):
            rows.append(("failing row kind %d source %d" % (kind, source), world(asset=2, kind=kind, source=source, sizes={2: LIMIT_HIGH}, price=1)))
    for asset in (123456, 99900000, 99899999, 10000, 9999):
        rows.append(("wire asset %d" % asset, world(asset=asset, books=None, sizes={asset: LIMIT_HIGH}, price=1)))
    for full in (0, 1, 2):
        rows.append(("error list room for %d" % full, world(asset=2, sizes={2: LIMIT_HIGH}, price=1, error_cap=2, errors=[text_word(90 + at) for at in range(2 - full)])))
    rows.append(("error list starts empty with no room", world(asset=2, sizes={2: LIMIT_HIGH}, price=1, error_cap=0)))
    rows.append(("error list one short", world(asset=2, sizes={2: LIMIT_HIGH}, price=1, error_cap=3, errors=[text_word(91), text_word(92)])))
    rows.append(("negative price row", world(asset=2, price=MASK[8] - 3)))
    rows.append(("saturated row", world(asset=1, sizes={1: (1 << 63) - 1}, books=[0, 5, 0, 0], price=1, mode_min=True)))
    return [Case("row: " + label, "row", w) for label, w in rows]


def retain_cases():
    rows = []
    fail, good = LIMIT_HIGH, 3

    def lists(*patterns):
        built = []
        for which, pattern in enumerate(patterns):
            built.append([(index % 4 + 10000 * which, (fail if bit == "x" else good) + index + which * 100) for index, bit in enumerate(pattern)])
        return tuple(built)
    sizes = {index + 10000 * which: 1 for index in range(4) for which in range(3)}
    for pattern in ("", ".", "x", "..", "x.", ".x", "xx", "...", "x..", ".x.", "..x", "xx.", "x.x", ".xx", "xxx", "..x.x.", "x.x.x."):
        rows.append(("first list " + (pattern or "empty"), lists(pattern, "", "")))
        rows.append(("second list " + (pattern or "empty"), lists("", pattern, "")))
        rows.append(("third list " + (pattern or "empty"), lists("", "", pattern)))
    rows.append(("all lists", lists("x.x", ".x.", "xx.")))
    rows.append(("all lists keep", lists("...", "...", "...")))
    rows.append(("all lists drop", lists("xx", "xx", "xx")))
    answer = [Case("retain: " + label, "retain", world(lists=value, sizes=sizes, error_cap=2)) for label, value in rows]
    answer.append(Case("retain: source 1", "retain", world(lists=lists("x", "x", "x"), sizes=sizes, source=1)))
    answer.append(Case("retain: ring map", "retain", world(lists=lists("x.x", ".x.", "xx."), sizes=sizes, form="ring", ring_extra=2, ring_head=5)))
    answer.append(Case("retain: panic in a later row", "retain", world(lists=([(1, 3), (9, 3)], [], []), sizes=sizes)))
    answer.append(Case("retain: panic in the scan after a drop", "retain", world(lists=([(1, fail), (2, 3), (9, 3)], [], []), sizes=sizes)))
    return answer


def clear_cases():
    rows = []
    for count in (0, 1, 3):
        for cap in (0, 6):
            rows.append(("rows %d cap %d" % (count, cap), world(lists=([], [(index + 1, 9) for index in range(count)], []), caps=(6, cap, 6))))
    rows.append(("source 1", world(lists=([], [(1, 9)], []), source=1)))
    rows.append(("other lists stay", world(lists=([(3, 4)], [(1, 9)], [(5, 6), (7, 8)]))))
    rows.append(("grow on first", world(lists=([], [(1, 9), (2, 9)], []), error_cap=0)))
    rows.append(("grow on second", world(lists=([], [(1, 9), (2, 9)], []), error_cap=1)))
    for asset in (0, 9999, 10000, 109999, 99899999, 99900000, 99999999, 100000000, 134217727 * 32 - 1, 137438953472 - 1, 1 << 37, (0x7FFF3CB << 5) - 1, 0x7FFF3CB << 5, (0x7FFF3CC << 5), MASK[8] - 50000, MASK[8]):
        rows.append(("asset %d" % asset, world(lists=([], [(asset, 9)], []))))
    return [Case("clear: " + label, "clear", w) for label, w in rows]


def host_cases():
    rows = []
    rows.append(("nothing to do", world()))
    rows.append(("gated skips the total", world(mode_min=True, cap=0, fold=1000, lists=([], [(0, 5)], []))))
    rows.append(("gated still filters rows", world(mode_min=True, sizes={0: LIMIT_HIGH}, lists=([(0, 1), (1, 1)], [], []))))
    rows.append(("fold none clears with no text", world(fold=None, lists=([], [(1, 5)], []))))
    rows.append(("fold none no marks", world(fold=None, caps=(6, 0, 6))))
    rows.append(("fold none beats a bad cap", world(fold=None, cap=1 << 63)))
    for whole, cap, label in ((1000, 100, "tenth equals cap"), (1009, 100, "just below the next unit"), (1010, 100, "one unit over"), (1020, 100, "two over"),
                              (10, 0, "unit at zero cap"), (9, 0, "below one unit at zero cap"), (0, 0, "zero at zero cap"), (-5000, 0, "negative whole"),
                              (-5000, -1, "negative whole negative cap")):
        rows.append((label, world(cap=cap & MASK[8], fold=whole, lists=([], [(0, 1)], []))))
    rows.append(("over cap with marks", world(cap=10, fold=1000, lists=([], [(0, 5), (2, 6), (3, 7)], []))))
    rows.append(("over cap no marks", world(cap=10, fold=1000, caps=(6, 0, 6))))
    rows.append(("over cap with source 1", world(cap=10, source=1, fold=1000, lists=([], [(0, 5)], []))))
    rows.append(("over cap duplicate mark rows", world(cap=10, fold=1000, lists=([], [(0, 5), (0, 6)], []))))
    rows.append(("failed mark row leaves the clone", world(cap=10, fold=1000, sizes={0: LIMIT_HIGH // 8, 1: 0}, lists=([], [(0, 9), (1, 5)], []))))
    rows.append(("row fails and total fails", world(cap=0, fold=500, sizes={0: LIMIT_HIGH, 1: 500}, lists=([(0, 1)], [(1, 7)], [(0, 1)]))))
    rows.append(("fold none, rows fail", world(fold=None, sizes={0: LIMIT_HIGH}, lists=([(0, 1)], [(0, 1), (1, 1)], [(0, 1)]))))
    rows.append(("negative cap panics", world(cap=1 << 63, fold=5)))
    rows.append(("negative cap panics with text room", world(cap=MASK[8], fold=1, error_cap=0)))
    rows.append(("error list grows at the total text", world(cap=0, fold=1000, errors=[text_word(91)], error_cap=1)))
    rows.append(("error list room at the total text", world(cap=0, fold=1000, errors=[text_word(91)], error_cap=2)))
    rows.append(("error list grows for rows and marks", world(cap=0, fold=100, sizes={1: LIMIT_HIGH}, error_cap=0, lists=([(1, 1)], [(0, 1), (2, 1)], []))))
    rows.append(("no books", world(books=None, sizes={1: LIMIT_HIGH}, lists=([(1, 1)], [], []))))
    rows.append(("no books under limit", world(books=None, sizes={1: LIMIT_HIGH - 1}, lists=([(1, 1)], [], []))))
    rows.append(("book total fails the row", world(sizes={}, books=[0, 0, LIMIT_HIGH, 0], lists=([(2, 1)], [(2, 1)], [(2, 1)]), fold=1)))
    rows.append(("ring map", world(sizes=spread(6), form="ring", ring_extra=2, ring_head=4, fold=77, cap=3, lists=([(2, LIMIT_HIGH), (5, 1)], [(8, 1)], [(11, 1)]))))
    rows.append(("largest whole", world(cap=1 << 62, fold=(1 << 63) - 1)))
    rows.append(("largest whole under a large cap", world(cap=(1 << 63) - 1, fold=(1 << 63) - 1)))
    rows.append(("large cap edge", world(cap=922337203685477580, fold=(1 << 63) - 1)))
    rows.append(("large cap edge plus one", world(cap=922337203685477581, fold=(1 << 63) - 1)))
    rows.append(("most negative whole", world(cap=0, fold=-(1 << 63))))
    rows.append(("other mode words", world(mode_word=0, fold=1000, cap=0, lists=([], [(0, 5)], []))))
    rows.append(("mode word max", world(mode_word=(1 << 63) - 1, fold=1000, cap=0)))
    rows.append(("mode word one above min", world(mode_word=(1 << 63) + 1, fold=1000, cap=0)))
    return [Case("host: " + label, "host", w) for label, w in rows]


def random_world(rng, kind):
    """One seeded world; limits are probed from both sides."""
    price = rng.choice((1, 1, 2, 3, 7, 100, 12345, 1 << 20, 1 << 33, (1 << 63) - 1, 1 << 63, MASK[8], 0))
    form = rng.choice(("tree", "tree", "ring", "ring", "null"))
    count = rng.choice((0, 1, 2, 5, 11, 12, 25))
    keys = sorted(rng.sample(range(0, 60), count)) if count else []
    sizes = {key: MASK[8] & rng.choice((0, 1, rng.randrange(1 << 20), LIMIT_HIGH // max(price, 1) - 1, LIMIT_HIGH // max(price, 1), LIMIT_HIGH // max(price, 1) + 1, (1 << 63) - 1, MASK[8] - 7)) for key in keys}
    books = rng.choice((None, [0] * 8, [rng.choice((0, 1, 2, LIMIT_HIGH // 3, 1 << 62)) for _ in range(8)]))
    return dict(sizes=sizes, form=form, ring_extra=rng.randrange(5), ring_head=rng.randrange(12), books=books, mode_min=rng.random() < 0.3,
                mode_word=rng.choice((0, 3, 1 << 62)), source=rng.randrange(2), cap=rng.choice((0, 1, 100, 1 << 40, 1 << 62, (1 << 63) - 1, 1 << 63, MASK[8])),
                fold=rng.choice((None, 0, 10, 999, 1 << 40, -77, (1 << 63) - 1)), error_cap=rng.choice((0, 1, 3, 8)), price=price), keys


def random_cases(count, seed=115):
    rng = random.Random(seed)
    cases = []
    plan = ("check",) * 30 + ("row",) * 35 + ("retain",) * 15 + ("host",) * 15 + ("clear",) * 5
    for index in range(count):
        kind = plan[index % len(plan)]
        changes, keys = random_world(rng, kind)
        if kind == "check":
            limit = rng.choice((LIMIT_HIGH, LIMIT_LOW))
            price = rng.choice((1, 2, 3, 5, 1 << 20, 1 << 40, 0, MASK[8], 1 << 63))
            total = limit // max(price, 1) + rng.choice((-2, -1, 0, 1, 2))
            book = rng.choice((0, 1, total // 3, total // 2)) if total > 0 else 0
            if rng.random() < 0.04:
                book = rng.choice((1 << 63, MASK[8]))
            stored = (total - book) & MASK[8] if rng.random() < 0.9 else rng.randrange(1 << 64)
            w = world(**changes)
            w.update(asset=rng.choice((0, 5, 9999, 10000, 123456, 99899999, 99900000, MASK[8])), kind=rng.randrange(3), price=price, stored=stored, book=book)
        elif kind == "row":
            asset = rng.choice(keys + [k + 1 for k in keys] + [3, 70, 10005, 29999]) if keys else rng.choice((0, 3, 70, 10005, 29999))
            w = world(**changes)
            w.update(asset=asset, kind=rng.randrange(3))
            if w["books"] is not None and asset % 10000 >= len(w["books"]) and rng.random() < 0.8:
                w["asset"] = asset % len(w["books"])
        else:
            rows = []
            for _ in range(3):
                n = rng.choice((0, 1, 2, 3, 4, 6))
                pool = (keys or [1, 2, 3]) + [8, 9]
                rows.append([(rng.choice(pool) % 8 if changes["books"] is not None else rng.choice(pool), rng.choice((1, 2, changes["price"], LIMIT_HIGH, 5))) for _ in range(n)])
            w = world(**changes)
            w.update(lists=tuple(rows), caps=(rng.choice((6, 8)), rng.choice((0, 6, 8)), 6))
            if not rows[1]:
                w["caps"] = (w["caps"][0], rng.choice((0, 6)), 6)
            if kind == "host":
                w["errors"] = [text_word(80 + at) for at in range(rng.randrange(3))]
                w["error_cap"] = max(w["error_cap"], len(w["errors"]))
            else:
                w["errors"] = []
        cases.append(Case("random %d %s" % (index, kind), kind, w))
    return cases


RANDOM_COUNT = 10500


def curated_cases():
    return check_cases() + row_cases() + retain_cases() + clear_cases() + host_cases()


def case_stream():
    """Curated cases first, then the seeded ones, one at a time."""
    for case in curated_cases():
        yield case
    for case in random_cases(RANDOM_COUNT):
        yield case


# ---- static reads ----

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


def lea_sites(image, target):
    """Every RIP relative lea of a 64 bit register in .text that lands on `target`."""
    base, text = image.text_bytes()
    rows = []
    for match in re.finditer(rb"[\x48\x4c]\x8d[\x05\x0d\x15\x1d\x25\x2d\x35\x3d]", text):
        at = match.start()
        if base + at + 7 + struct.unpack_from("<i", text, at + 3)[0] == target:
            rows.append(base + at)
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


GROUPS = (
    (HOST, "update gate"), (RETAIN, "three list retain"), (ROW, "row closure"), (CHECK, "size times price check"), (CLEAR, "Mark list clear"),
    (RING, "sorted ring search"), (BTREE, "B-tree search"),
)
SAMPLE_EVERY = 25


def mutated_groups(image):
    """(function start, role, decoded rows)."""
    return [(start, role, decode_range(image, *image.exact_fde(start))) for start, role in GROUPS]


def run_mutants(image, subset, reached, verbose=False):
    """A mutant only changes a run that reaches its instruction, so only those cases run."""
    results = []
    harness = Harness(image)
    machine = harness.machine
    machine.step_limit = MUTANT_STEP_LIMIT
    by_va = {}
    for index, touched in enumerate(reached):
        for va in touched:
            by_va.setdefault(va, []).append(index)
    first_kill = []
    for start, _, rows in mutated_groups(image):
        for va, at, kind in mutation_targets(image, rows):
            indices = by_va.get(va)
            if not indices:
                results.append({"function": start, "va": va, "kind": kind, "result": "unreached", "by": ""})
                continue
            machine.patches = mutate_patch(image, va, at, kind)
            machine.cache.pop(va, None)
            failed = None
            wanted = set(indices)
            order = [index for index in first_kill if index in wanted] + indices
            for index in order:
                failed = compare_run(harness, subset[index])
                if failed:
                    if index in first_kill:
                        first_kill.remove(index)
                    first_kill.insert(0, index)
                    break
            machine.patches = {}
            machine.cache.pop(va, None)
            results.append({"function": start, "va": va, "kind": kind, "result": "killed" if failed else "survived", "by": failed.split(":")[0] if failed else ""})
            if verbose and not failed:
                print("survived %#x %s" % (va, kind), flush=True)
    return results


# ---- negative controls: wrong specifications, damaged bytes, out of range input ----

def spec_controls(subset, answers):
    """Each planted wrong rule must disagree with the real run on at least one case."""
    rows = []
    for bug in SPEC_BUGS:
        caught = ""
        for case, found in zip(subset, answers):
            trouble = compare_answers(case, found, spec_run(case, bug))
            if trouble:
                caught = case.label
                break
        rows.append({"control": "wrong rule: " + bug, "kind": "specification", "detected": bool(caught), "by": caught})
    return rows


def byte_controls(results, image):
    """Every 17th killed mutant, named by its patched byte."""
    killed = [row for row in results if row["result"] == "killed"]
    rows = []
    for row in killed[::max(1, len(killed) // 12)][:12]:
        rows.append({"control": "damaged byte in %#x at %#x (%s)" % (row["function"], row["va"], row["kind"]), "kind": "bytes", "detected": True, "by": row["by"]})
    return rows


def range_controls(image):
    """Input outside the proven range must be refused, not answered."""
    start, end = image.exact_fde(CHECK)
    empty = Harness(image)
    odd = Harness(image)
    odd.base_slots = {}
    attempts = (
        ("digest of a damaged binary", lambda: load_image_bytes(bytes(image.blob[:-1]) + bytes([image.blob[-1] ^ 1]))),
        ("address inside a function is not an FDE start", lambda: image.exact_fde(CHECK + 1)),
        ("address before the first mapping", lambda: image.offset(0x10)),
        ("address past every mapping", lambda: image.offset(1 << 40)),
        ("decoder must end on the FDE end", lambda: decode_range(image, start, end - 1)),
        ("stub table without the record slot halts the check", lambda: run_without_record(image)),
        ("ring with more rows than the reader accepts", lambda: empty.read_rows(HEAP_BASE, 65)),
        ("unknown format template", lambda: empty.on_format(template_machine(empty, 0x1234))),
        ("read outside the stack and heap", lambda: empty.machine.memory.bytes_at(0x10, 8)),
        ("write outside the stack and heap", lambda: empty.machine.memory.write(0x10, 8, 1)),
    )
    rows = []
    for name, action in attempts:
        try:
            action()
            rows.append({"control": "out of range: " + name, "kind": "range", "detected": False, "by": ""})
        except CRASHES as error:
            rows.append({"control": "out of range: " + name, "kind": "range", "detected": True, "by": type(error).__name__})
    return rows


def load_image_bytes(blob):
    if hashlib.sha256(blob).hexdigest() != SHA256:
        raise EvidenceError("binary SHA-256 mismatch")
    return Image(blob)


def template_machine(harness, template):
    machine = harness.machine
    machine.regs[RSI] = template
    return machine


def run_without_record(image):
    harness = Harness(image)
    machine = harness.machine
    machine.slots = {key: value for key, value in harness.base_slots.items() if value != harness.on_record}
    case = Case("control", "check", world(mode_min=True, price=1, stored=LIMIT_LOW, book=0))
    harness.run(case)


# ---- evidence ----

HOST_FIELDS = (
    (0x447ABAB, 0x378, "cmp rax, [r15+0x378]: the gate tests the niche word of owner +0x378 against i64::MIN"),
    (0x447ABB8, 0x478, "mov r12, [r15+0x478]: the total cap is owner +0x478"),
    (0x447C6AF, 0x378, "cmp [rsi+0x378], r12: the check tests the same niche word for the second record"),
    (0x3D98823, 0xF0, "mov rbp, [r12+0xf0]: the row closure reads the size map niche word at owner +0xf0"),
    (0x3D98833, 0xF8, "mov rsi, [r12+0xf8]: tree root, or ring pointer"),
    (0x3D98847, 0x100, "mov rdx, [r12+0x100]: tree height, or ring head"),
    (0x3D988A8, 0x108, "cmp rdx, [r12+0x108]: ring length"),
    (0x3D9894D, 0x118, "mov rax, [rax+rcx+0x118]: book total_sz inside a 0x120 byte book row"),
)
FLOAT_BYTES = (
    (0x4593E0, 0.1, "multiplier of the Mark total before the cap test"),
    (0x4599A0, 1000000.0, "divisor of the texts"),
    (0x459808, -9223372036854775808.0, "lower clamp of the saturating cast"),
    (0x459360, 9223372036854775807.0, "upper clamp of the saturating cast"),
    (0x458E50, 9223372036854774784.0, "largest double below 2^63: above it the cast result is replaced by i64::MAX"),
)
FIELDS = {
    "owner": {"+0xf0/+0xf8/+0x100/+0x108": "size map by asset: niche word i64::MIN then B-tree root and height, else a sorted ring of (asset, size): capacity, pointer, head, length",
              "+0x378": "niche word: i64::MIN turns the second record on in the check and skips the Mark total in the gate", "+0x478": "total cap, i64"},
    "size_map_node": {"+0x08": "keys, u64", "+0x60": "values, u64", "+0xba": "length, u16", "+0xc0": "edges"},
    "ring_row": {"+0x00": "asset key", "+0x08": "size"},
    "book_list": {"+0x08": "book rows pointer", "+0x10": "book rows length", "row stride": "0x120", "row +0x118": "total_sz"},
    "price_lists": {"+0x00/+0x08/+0x10": "kind 0 Spot: capacity, pointer, length, rows (asset, price)", "+0x18/+0x20/+0x28": "kind 1 Mark", "+0x30/+0x38/+0x40": "kind 2 External",
                    "+0x48": "source byte", "+0x50/+0x58/+0x60": "text list: capacity, pointer, length, rows of 24 bytes"},
    "row_closure": {"+0x00": "pointer to (owner, pointer to book list cell)", "+0x08": "pointer to the kind byte", "+0x10": "pointer to the text list", "+0x18": "pointer to the source byte"},
}
TEXTS = ((TEXT_ASSET, "per asset gate"), (TEXT_MISSING, "row and Mark list drop"), (TEXT_TOTAL, "total gate"))
UNWIND = "unwind landing pad: no case unwinds"


def fixed_text(image, va, size):
    return bytes(image.blob[image.offset(va):image.offset(va) + size]).decode("ascii")


def template(image, va):
    """Printable pieces of one fmt template: a length byte, then text and 0xc0 markers."""
    data = bytes(image.blob[image.offset(va):image.offset(va) + 0x90])
    size = data[0]
    out = []
    at = 1
    remaining = size
    while True:
        chunk = data[at:at + remaining]
        out.append(chunk.decode("ascii"))
        at += remaining
        if data[at] != 0xC0:
            raise EvidenceError("template marker at %#x" % va)
        remaining = data[at + 1]
        at += 2
        if remaining == 0:
            break
        out.append("{}")
    out.append("{}")
    return "".join(out)


def field_displacement(image, va):
    """The memory displacement of the instruction at va, decoded from its bytes."""
    start, end = image.fde(va)
    for row in decode_range(image, start, end):
        if row.va == va:
            for operand in (row.a, row.b):
                if operand and operand[0] == "m" and operand[4]:
                    return operand[4]
    raise EvidenceError("no field operand at %#x" % va)


def read_fields(image):
    rows = []
    for va, wanted, meaning in HOST_FIELDS:
        found = field_displacement(image, va)
        if found != wanted:
            raise EvidenceError("field at %#x is %#x" % (va, found))
        rows.append({"va": "%#x" % va, "disp": "%#x" % found, "meaning": meaning})
    return rows


def read_floats(image):
    rows = []
    for va, wanted, meaning in FLOAT_BYTES:
        found = struct.unpack("<d", bytes(image.blob[image.offset(va):image.offset(va) + 8]))[0]
        if found != wanted:
            raise EvidenceError("constant at %#x is %r" % (va, found))
        rows.append({"va": "%#x" % va, "value": repr(found), "meaning": meaning})
    return rows


def outcome_name(case, spec):
    if spec["stop"]:
        return "panic: " + str(spec["stop"][0])
    names = sorted({event[0] for event in spec["events"]})
    out = spec["out"]
    if case.kind == "check":
        word = "pass" if out is None else "text"
    elif case.kind == "row":
        word = "kept" if out else "dropped"
    else:
        word = "done"
    return "%s %s [%s]" % (case.kind, word, " ".join(names))


def case_line(case, spec):
    return "%s\t%s\t%s" % (case.kind, case.label.split(": ", 1)[1], outcome_name(case, spec))


def analyse(image, full=True, verbose=False):
    harness = Harness(image)
    mismatches = []
    outcomes = {}
    kinds = {}
    subset, answers, reached = [], [], []
    seen = set()
    lines = []
    machine = harness.machine
    curated = len(curated_cases())
    total = 0
    for index, case in enumerate(case_stream()):
        total += 1
        machine.seen = set()
        wanted = spec_run(case)
        try:
            found = harness.run(case)
            trouble = compare_answers(case, found, wanted)
        except CRASHES as error:
            found, trouble = None, "%s: crash %s %s" % (case.label, type(error).__name__, error)
        if trouble:
            mismatches.append(trouble)
            if full:
                raise EvidenceError("spec mismatch: %s" % trouble)
        seen |= machine.seen
        name = outcome_name(case, wanted)
        outcomes[name] = outcomes.get(name, 0) + 1
        kinds[case.kind] = kinds.get(case.kind, 0) + 1
        if index < curated:
            lines.append(case_line(case, wanted))
        if index < curated or index % SAMPLE_EVERY == 0:
            subset.append(case)
            answers.append(found)
            reached.append(frozenset(machine.seen))
    steps = machine.steps
    functions = []
    for start, role in GROUPS + ((CLONE, "clone slice (stubbed)"), (COLLECT, "price map builder (stubbed)")):
        if start in (CLONE, COLLECT):
            begin, end = image.exact_fde(start)
            functions.append({"role": role, "start": "%#x" % begin, "end": "%#x" % end, "size": end - begin, "instructions": None, "instructions_stepped": None})
            continue
        begin, end = image.exact_fde(start)
        rows = decode_range(image, begin, end)
        functions.append({"role": role, "start": "%#x" % begin, "end": "%#x" % end, "size": end - begin, "instructions": len(rows), "instructions_stepped": sum(1 for row_ in rows if row_.va in seen)})
    begin, end = image.exact_fde(FOLD)
    functions.append({"role": "total fold behind the fold slot (stubbed)", "start": "%#x" % begin, "end": "%#x" % end, "size": end - begin, "instructions": None, "instructions_stepped": None})
    relative = harness.relative
    tables = {SLOT_HOST: HOST, SLOT_FOLD: FOLD, SLOT_FORMAT: 0x141E3A0, SLOT_GROW: 0x5C8B150, SLOT_FREE: 0x635DE30, SLOT_UNWRAP: 0x1680C30}
    for slot, value in tables.items():
        if relative.get(slot) != value:
            raise EvidenceError("slot %#x" % slot)
    shows = {"%#x" % slot: "%#x" % relative[slot] for slot in (SLOT_SHOW_U32, SLOT_SHOW_KIND, SLOT_SHOW_SOURCE, SLOT_SHOW_F64, SLOT_RECORD, SLOT_BOUNDS)}
    site_rows = []
    for va in slot_sites(image, SLOT_HOST):
        site_rows.append((HOST, va, "slot", image.fde(va)[0], image.fde(va)[1]))
    for va in slot_sites(image, SLOT_FOLD):
        site_rows.append((FOLD, va, "slot", image.fde(va)[0], image.fde(va)[1]))
    direct = direct_sites(image, (RETAIN, ROW, CHECK, CLEAR, CLONE, COLLECT, RING, BTREE))
    for target in sorted(direct):
        for va, opcode in sorted(direct[target]):
            site_rows.append((target, va, "rel32 %#x" % opcode, image.fde(va)[0], image.fde(va)[1]))
    template_uses = {}
    for va, use in TEXTS:
        template_uses["%#x" % va] = [("%#x" % site) for site in lea_sites(image, va)]
    locations = []
    for slot, name in ((LOC_BOOK, "book row bound"), (LOC_ROW, "second record, passed by the row closure"), (LOC_SATURATE, "first record, size sum"),
                       (LOC_CHECK_UNWRAP, "negative book total"), (LOC_HOST_UNWRAP, "negative total cap")):
        path, line, column = image.location(slot, relative)
        locations.append({"slot": "%#x" % slot, "name": name, "path": path, "line": line, "column": column})
    texts = {"%#x" % va: {"use": use, "text": template(image, va), "lea_sites": template_uses["%#x" % va]} for va, use in TEXTS}
    fields = read_fields(image)
    floats = read_floats(image)
    results_rows = []
    controls = []
    if full:
        results_rows = run_mutants(image, subset, reached, verbose)
        controls = spec_controls(subset, answers) + byte_controls(results_rows, image) + range_controls(image)
    tally = {key: sum(1 for row_ in results_rows if row_["result"] == key) for key in ("killed", "survived", "unreached")}
    return {
        "target": {"file": "artifacts/node/115/hl-node", "sha256": SHA256},
        "functions": functions,
        "data_words": {"%#x" % slot: "%#x" % value for slot, value in sorted(tables.items())},
        "display_and_helper_slots": shows,
        "limits": {"row_limit": "%#x" % LIMIT_HIGH, "second_record_limit": "%#x" % LIMIT_LOW, "row_limit_times_10": str(LIMIT_HIGH * 10), "two_to_64": str(1 << 64)},
        "field_reads": fields,
        "float_constants": floats,
        "texts": texts,
        "locations": locations,
        "fields": FIELDS,
        "cases": {"total": total, "curated": curated, "random": total - curated, "by_kind": dict(sorted(kinds.items())), "mutant_subset": len(subset)},
        "outcomes": dict(sorted(outcomes.items())),
        "mismatches": len(mismatches),
        "first_mismatch": mismatches[0] if mismatches else "",
        "instructions_stepped": steps,
        "mutations": tally,
        "negative_controls": {"total": len(controls), "detected": sum(1 for row_ in controls if row_["detected"])},
        "_sites": site_rows, "_results": results_rows, "_lines": lines, "_controls": controls,
        "_measure": {"cases": total, "negative_controls": len(controls), "negative_detected": sum(1 for row_ in controls if row_["detected"])},
    }


def reason_for(row):
    if row["result"] == "killed":
        return ""
    va = row["va"]
    for low, high, reason in REASON_RANGES:
        if low <= va < high:
            return reason
    return REASONS.get(va, "no case in the list separates this mutant; no claim rests on this row")


FINITE = "the input is 0.1 times an i64, so it is finite and inside the i64 range: this guard and its clamp arm change nothing"
RANGE = "the clamp arm returns the same in-range value either way: maxsd and minsd leave it alone"
SATURATED = "the saturated sum is only reachable with an add overflow; the changed shift gives i64::MAX minus one, the product then overflows or lands over the limit, and the text rounds to the same double"
NONE_WORD_RETURN = "the return value compares the text word with the none word; a one bit change of the none word still differs from every text word"
INSERT_INDEX = "only the insertion index of a miss changes, and the row closure treats every miss as absent without reading the index"
SINGLE_ROW = "with one candidate row left the loop body is a no-op, so entering it changes nothing"
HEIGHT_FIELD = "the handle height at +0x10 is never read by the row closure"
REASONS = {0x447AC15: FINITE, 0x447AC26: FINITE, 0x447AC41: RANGE, 0x447AC4B: RANGE, 0x447C66D: SATURATED, 0x3D98A1B: NONE_WORD_RETURN, 0x3D98A33: NONE_WORD_RETURN,
           0x4554872: INSERT_INDEX, 0x4554874: INSERT_INDEX, 0x45548E5: INSERT_INDEX, 0x4554836: SINGLE_ROW, 0x45548AA: SINGLE_ROW, 0x35BD6DF: HEIGHT_FIELD}
REASON_RANGES = ((0x447ADB4, 0x447ADED, UNWIND), (0x366D14D, 0x366D1FE, UNWIND), (0x3D98AFE, 0x3D98B32, UNWIND), (0x366CDD9, 0x366CE1C, UNWIND))


def render(evidence):
    evidence = dict(evidence)
    sites = evidence.pop("_sites")
    results = evidence.pop("_results")
    case_lines = evidence.pop("_lines")
    controls = evidence.pop("_controls")
    measure = evidence.pop("_measure")
    files = {"evidence.json": (json.dumps(evidence, indent=2, sort_keys=True) + "\n").replace("\x40", "[at]")}
    lines = ["target\tsite\tcall\tcaller_fde\tcaller_fde_end"]
    lines += ["%#x\t%#x\t%s\t%#x\t%#x" % row_ for row_ in sites]
    files["call_sites.tsv"] = "\n".join(lines) + "\n"
    files["cases.tsv"] = "\n".join(["copy\tlabel\toutcome"] + case_lines) + "\n"
    lines = ["function\tva\tkind\tresult\tkilled_by\treason"]
    lines += ["%#x\t%#x\t%s\t%s\t%s\t%s" % (row_["function"], row_["va"], row_["kind"], row_["result"], row_["by"], reason_for(row_)) for row_ in results]
    files["mutations.tsv"] = "\n".join(lines) + "\n"
    lines = ["control\tkind\tdetected\tby"]
    lines += ["%s\t%s\t%d\t%s" % (row_["control"], row_["kind"], row_["detected"], row_["by"]) for row_ in controls]
    files["controls.tsv"] = "\n".join(lines) + "\n"
    files["measure.json"] = json.dumps(measure, indent=2, sort_keys=True) + "\n"
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
    files = render(analyse(load_image()))
    write_outputs(options.out, files)
    for name in sorted(files):
        print(name, hashlib.sha256(files[name].encode()).hexdigest())
    return 0


if __name__ == "__main__":
    sys.exit(main())
