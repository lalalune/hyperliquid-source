#!/usr/bin/env python3
"""Pin the node #94 open interest gates on a price update from ELF bytes: per asset rows, book total_sz and the total gate.

`0x3709040` takes a list of new prices for one dex. Each row of the three price lists runs `0x3bc3630`, which adds the book
field `total_sz` to the stored size for that asset and tests size times price through `0x3708e80`. Rows that fail leave the
list with two texts. `0x3be6420` then sums the notional of every asset, and when a tenth of it is above the cap the whole
Mark list goes through `0x3bfd1d0`. The real bytes run in a Python evaluator with the callees at the edge stubbed. A separately
written specification predicts every result and stub argument, and every condition, immediate and field offset is flipped
to show the run can tell. No objdump or readelf output is parsed, and the binary is never executed. Standard library only.
"""

import argparse
import bisect
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

HOST = 0x3709040
RETAIN = 0x3BFD3C0
ROW = 0x3BC3630
CHECK = 0x3708E80
TOTAL = 0x3BE6420
CLEAR = 0x3BFD1D0
PARSE = 0x3BFD7A0
COLLECT = 0x33167E0
DROP_MAP = 0x33F4660

SLOT_HOST = 0x5774988
SLOT_FORMAT = 0x576E040
SLOT_GROW = 0x576EA38
SLOT_RECORD = 0x5773190
SLOT_FREE = 0x576E010
SLOT_UNWRAP = 0x576E048
SLOT_BOUNDS = 0x576DFC8
SLOT_MUL = 0x576E1B0
SLOT_ADD = 0x576E118
SLOT_SHOW_U32 = 0x57739A0
SLOT_SHOW_KIND = 0x57739A8
SLOT_SHOW_F64 = 0x57739B0
SLOT_SHOW_SOURCE = 0x57762E8

TEXT_ASSET = 0x1FA4B9
TEXT_TOTAL = 0x1FE7EC
TEXT_MISSING = 0x1E9ABE
LOC_SATURATE = 0x56F1C98
LOC_CHECK_UNWRAP = 0x56F1C80
LOC_HOST_UNWRAP = 0x56F1CE0
LOC_BOOK = 0x56DFDA8
LOC_ROW = 0x57146F0
LOC_ORACLE = 0x5714C58
LOC_MUL = 0x5714DB8
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
HEAP_SIZE = 0x8000
RETURN_SENTINEL = 0xDEAD0000
POISON = 0xA5A5A5A5A5A5A5A5
STEP_LIMIT = 200000
MUTANT_STEP_LIMIT = 20000

OWNER = HEAP_BASE + 0x100
SIZE_NODES = HEAP_BASE + 0x1000
MARK_NODES = HEAP_BASE + 0x3000
BOOKS = HEAP_BASE + 0x5000
BOOK_LIST = HEAP_BASE + 0x5F00
ASSET_ROWS = HEAP_BASE + 0x6000
LISTS = HEAP_BASE + 0x6800
OUT = HEAP_BASE + 0x6900
ERROR_LIST = HEAP_BASE + 0x6980
WIRE_LIST = HEAP_BASE + 0x69C0
CLOSURE = HEAP_BASE + 0x6A00
ROWS_0 = HEAP_BASE + 0x7000
ROWS_1 = HEAP_BASE + 0x7200
ROWS_2 = HEAP_BASE + 0x7400
ERRORS = HEAP_BASE + 0x7600
WIRE_ROWS = HEAP_BASE + 0x7E00
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


class Spec:
    """One world: the owner fields, the two maps, the books and the three price lists."""

    def __init__(self, w):
        self.w = w
        self.events = []
        self.texts = 0
        self.errors = list(w["errors"])
        self.error_cap = w["error_cap"]
        self.lists = [list(rows) for rows in w["lists"]]
        self.mark_cap = w["caps"][1]
        self.mark_head = (w["caps"][1], ROWS_1)
        self.index = w["start"]

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
        if book & SIGN[8]:
            raise Panicked(("unwrap", LOC_CHECK_UNWRAP))
        total = signed(stored) + book
        if total >= SIGN[8]:
            self.events.append(("record", 0, LOC_SATURATE))
            total = SIGN[8] - 1
        price = signed(price)
        fits = False
        product = price
        if price >= 0:
            exact = price * total
            fits = -SIGN[8] <= exact < SIGN[8]
            product = wrapped(exact)
        if not (fits and product < LIMIT_LOW) and self.w["mode"] == 3:
            self.events.append(("record", 1, self.w.get("check_location", LOC_ROW)))
        if fits and product < LIMIT_HIGH:
            return None
        shown = float(product) / 1000000.0 if fits else 0.0
        return self.text(TEXT_ASSET, (wire_asset(asset), kind, to_bits(shown)))

    def row(self, kind, asset, price):
        """True when the row stays."""
        w = self.w
        stored = w["sizes"].get(asset, 0) if w["sizes"] is not None else 0
        book = 0
        if w["books"] is not None:
            index = asset % 10000
            if index >= len(w["books"]):
                raise Panicked(("bounds", index, len(w["books"]), LOC_BOOK))
            book = w["books"][index]
        word = self.check(asset, kind, price, stored, book)
        if word is None:
            return True
        self.push(word)
        self.push(self.text(TEXT_MISSING, (w["source"], wire_asset(asset), kind)))
        return False

    def retain(self):
        for kind in range(3):
            self.lists[kind] = [(asset, price) for asset, price in self.lists[kind] if self.row(kind, asset, price)]

    def clear(self):
        rows = self.lists[1]
        self.lists[1] = []
        self.mark_head = (0, 8)
        for asset, _ in rows:
            self.push(self.text(TEXT_MISSING, (self.w["source"], wire_asset(asset), 1)))
        if self.mark_cap:
            self.events.append(("free", ROWS_1, self.mark_cap * 16, 0))

    def total(self):
        """(sum) or None, from the marks in the list, then the asset row words."""
        w = self.w
        marks = dict(self.lists[1])
        whole = 0
        first = w["dex"] * 10000
        if first >= 1 << 64:
            raise Panicked(("multiply overflow",))
        for index in range(w["start"], w["assets_word"]):
            asset = first + index
            self.index = index + 1
            if asset >= 1 << 64:
                raise Panicked(("add overflow",))
            if asset in marks:
                price = marks[asset]
            else:
                slot = asset % 10000
                if slot >= len(w["asset_rows"]):
                    raise Panicked(("bounds", slot, len(w["asset_rows"]), LOC_ORACLE))
                price = w["asset_rows"][slot]
            stored = w["sizes"].get(asset, 0) if w["sizes"] is not None else 0
            if price & SIGN[8]:
                return None
            product = price * signed(stored)
            if not -SIGN[8] <= product < SIGN[8]:
                return None
            whole += product
            if not -SIGN[8] <= whole < SIGN[8]:
                return None
        return whole

    def host(self):
        """The whole gate: rows, total, Mark list, result."""
        w = self.w
        self.retain()
        if w["mode"] == 3:
            return
        self.events.append(("collect", tuple(self.lists[1])))
        marks = len(dict(self.lists[1]))
        whole = self.total()
        if whole is None:
            self.clear()
        else:
            cap = signed(w["cap"])
            scaled = 0.1 * float(whole)
            if cap < 0:
                raise Panicked(("unwrap", LOC_HOST_UNWRAP))
            if int(scaled) > cap:
                self.push(self.text(TEXT_TOTAL, (to_bits(float(whole) / 1000000.0), to_bits(float(cap) / 1000000.0))))
                self.clear()
        self.events.append(("drop map", marks))


def text_word(number):
    return (0x20 + number, TEXT_BASE + number * 0x10, 0x30 + number)


def run_spec(case):
    w = case.world
    spec = Spec(w)
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
        elif case.kind == "total":
            answer["out"] = spec.total()
            answer["index"] = spec.index
        elif case.kind == "clear":
            spec.clear()
            answer["lists"] = spec.lists
            answer["errors"] = spec.errors
            answer["mark_head"] = spec.mark_head
        elif case.kind == "host":
            if w["wire_length"] != w["assets_word"]:
                if w["wire_cap"]:
                    spec.events.append(("free", WIRE_ROWS, w["wire_cap"] * 0x3C, 0))
                answer["out"] = ("length", w["wire_length"], w["assets_word"])
                return answer
            spec.events.append(("parse", w["wire_length"], w["wire_kind"]))
            if w["parse_error"]:
                answer["out"] = ("parse", w["parse_error"])
                return answer
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
BOOK_STRIDE = 0xD8
ASSET_STRIDE = 0x60
UNMAPPED = 0x10
TEMPTING = (1 << 63) - 3
HOST_FRAME = STACK_TOP - 0x108 - 0x28 - 0x1B0


def ramp(count, start):
    return bytes((start + index * 7) & 0xFF or 1 for index in range(count))


OWNER_IMAGE = ramp(0x300, 0x2B)
BOOK_IMAGE = ramp(BOOK_STRIDE, 0x39)
ASSET_IMAGE = ramp(ASSET_STRIDE, 0x47)


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
        self.base_slots = {relative[SLOT_UNWRAP]: self.on_unwrap, relative[SLOT_BOUNDS]: self.on_bounds, relative[SLOT_MUL]: self.on_mul, relative[SLOT_ADD]: self.on_add,
                           relative[SLOT_FORMAT]: self.on_format, relative[SLOT_GROW]: self.on_grow, relative[SLOT_RECORD]: self.on_record, relative[SLOT_FREE]: self.on_free}
        machine.slots = dict(self.base_slots)
        self.real = RealExcept()
        self.real.stubs = frozenset(self.base_slots) | frozenset((PARSE, COLLECT, DROP_MAP))
        machine.real = self.real
        machine.calls = {PARSE: self.on_parse, COLLECT: self.on_collect, DROP_MAP: self.on_drop_map}
        self.events = []
        self.texts = 0
        self.w = None

    def on_unwrap(self, m):
        raise Panicked(("unwrap", m.regs[R8], m.regs[RSI], m.regs[RDI]))

    def on_bounds(self, m):
        raise Panicked(("bounds", m.regs[RDI], m.regs[RSI], m.regs[RDX]))

    def on_mul(self, m):
        raise Panicked(("multiply overflow", m.regs[RDI]))

    def on_add(self, m):
        raise Panicked(("add overflow", m.regs[RDI]))

    def on_record(self, m):
        self.events.append(("record", m.regs[RDI] & 0xFF, m.regs[RSI]))

    def on_free(self, m):
        self.events.append(("free", m.regs[RDI], m.regs[RSI], m.regs[RDX]))

    def on_grow(self, m):
        memory = m.memory
        at = m.regs[RDI]
        self.events.append(("grow", ERROR_LIST if at == HOST_FRAME else at))
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

    def on_parse(self, m):
        w = self.w
        memory = m.memory
        self.events.append(("parse", memory.read(m.regs[RSI] + 0x10, 8), m.regs[RDX] & 0xFF))
        if m.regs[RCX] != OWNER:
            raise Halt("parse owner")
        out = m.regs[RDI]
        if w["parse_error"]:
            memory.write(out, 8, NONE_WORD)
            memory.put_bytes(out + 8, ramp(0x60, w["parse_error"]))
            return
        memory.put_bytes(out, memory.bytes_at(LISTS, 0x50))
        memory.put_bytes(out + 0x50, memory.bytes_at(ERROR_LIST, 0x18))

    def on_collect(self, m):
        memory = m.memory
        begin, end = m.regs[RSI], m.regs[RDX]
        rows = tuple(self.read_rows(begin, (end - begin) // 16))
        self.events.append(("collect", rows))
        pairs = sorted(dict(rows).items())
        root, height = self.write_tree(MARK_NODES, pairs)
        memory.write(m.regs[RDI], 8, root)
        memory.write(m.regs[RDI] + 8, 8, height)
        memory.write(m.regs[RDI] + 0x10, 8, len(pairs))
        m.regs[RAX] = m.regs[RDI]

    def on_drop_map(self, m):
        self.events.append(("drop map", m.memory.read(m.regs[RDI] + 0x10, 8)))

    def read_rows(self, at, count):
        if count > 64:
            raise Halt("row count")
        memory = self.machine.memory
        return [(memory.read(at + index * 16, 8), memory.read(at + index * 16 + 8, 8)) for index in range(count)]

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

    def world(self, w):
        """Lay one world out in memory."""
        memory = self.machine.memory
        memory.put_bytes(OWNER, OWNER_IMAGE)
        if w["sizes"] is None:
            memory.write(OWNER + 0x170, 8, 0)
            memory.write(OWNER + 0x178, 8, 3)
        else:
            root, height = self.write_tree(SIZE_NODES, sorted(w["sizes"].items()))
            memory.write(OWNER + 0x170, 8, root)
            memory.write(OWNER + 0x178, 8, height)
        memory.write(OWNER + 0x10, 8, w["assets_word"])
        memory.write(OWNER + 0x30, 8, w["dex"])
        memory.write(OWNER + 0x68, 8, ASSET_ROWS)
        memory.write(OWNER + 0x70, 8, len(w["asset_rows"]))
        memory.write(OWNER + 0x1B0, 8, w["cap"])
        memory.write(OWNER + 0x230, 1, w["mode"])
        for index, price in enumerate(w["asset_rows"]):
            memory.put_bytes(ASSET_ROWS + index * ASSET_STRIDE, ASSET_IMAGE)
            memory.write(ASSET_ROWS + index * ASSET_STRIDE + 0x20, 8, price)
        books = w["books"] or ()
        for index, total in enumerate(books):
            memory.put_bytes(BOOKS + index * BOOK_STRIDE, BOOK_IMAGE)
            memory.write(BOOKS + index * BOOK_STRIDE + 0xD0, 8, total)
        memory.put_bytes(BOOK_LIST, ramp(0x18, 0x55))
        memory.write(BOOK_LIST + 8, 8, BOOKS)
        memory.write(BOOK_LIST + 0x10, 8, len(books))
        memory.put_bytes(LISTS, ramp(0x50, 0x61))
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

    def read_errors(self):
        memory = self.machine.memory
        count = memory.read(ERROR_LIST + 0x10, 8)
        if count > 40:
            raise Halt("error count")
        return [tuple(memory.read(ERRORS + index * 24 + part * 8, 8) for part in range(3)) for index in range(count)]

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
                machine.run(RETAIN, {RDI: LISTS, RSI: OWNER, RDX: CLOSURE + 0x60, RCX: ERROR_LIST})
                answer["lists"] = self.read_lists(LISTS)
                answer["errors"] = self.read_errors()
            elif case.kind == "total":
                pairs = sorted(dict(w["lists"][1]).items())
                root, height = self.write_tree(MARK_NODES, pairs)
                memory.write(CLOSURE, 8, root if pairs else 0)
                memory.write(CLOSURE + 8, 8, height)
                memory.write(CLOSURE + 0x20, 8, OWNER)
                memory.write(CLOSURE + 0x28, 8, w["start"])
                memory.write(CLOSURE + 0x30, 8, w["assets_word"])
                memory.write(CLOSURE + 0x38, 8, CLOSURE)
                memory.write(CLOSURE + 0x40, 8, OWNER)
                rax = machine.run(TOTAL, {RDI: CLOSURE + 0x20, RSI: 0, RDX: CLOSURE + 0x38})
                answer["out"] = wrapped(machine.regs[RDX]) if rax & 1 else None
                answer["index"] = memory.read(CLOSURE + 0x28, 8)
            elif case.kind == "clear":
                machine.run(CLEAR, {RDI: LISTS, RSI: ERROR_LIST})
                answer["lists"] = self.read_lists(LISTS)
                answer["errors"] = self.read_errors()
                answer["mark_head"] = (memory.read(LISTS + 0x18, 8), memory.read(LISTS + 0x20, 8))
            else:
                memory.write(WIRE_LIST, 8, w["wire_cap"])
                memory.write(WIRE_LIST + 8, 8, WIRE_ROWS)
                memory.write(WIRE_LIST + 0x10, 8, w["wire_length"])
                rcx = BOOK_LIST if w["books"] is not None else 0
                rax = machine.run(HOST, {RDI: OUT, RSI: OWNER, RDX: WIRE_LIST, RCX: rcx, R8: w["wire_kind"] | 0xCD00})
                if rax != OUT:
                    raise Halt("result pointer")
                word = memory.read(OUT, 8)
                if word == NONE_WORD:
                    if w["wire_length"] != w["assets_word"]:
                        answer["out"] = ("length", memory.read(OUT + 0x10, 8), memory.read(OUT + 0x18, 8)) if memory.read(OUT + 8, 2) == 0x76 else "bad tag"
                    else:
                        answer["out"] = ("parse", w["parse_error"]) if memory.bytes_at(OUT + 8, 0x60) == ramp(0x60, w["parse_error"]) else "bad copy"
                else:
                    answer["out"] = "ok"
                    answer["lists"] = self.read_lists(OUT)
                    answer["mark_head"] = (memory.read(OUT + 0x18, 8), memory.read(OUT + 0x20, 8))
                    if memory.read(OUT + 0x48, 1) != w["source"]:
                        raise Halt("source byte")
                    answer["errors"] = [tuple(memory.read(memory.read(OUT + 0x58, 8) + index * 24 + part * 8, 8) for part in range(3)) for index in range(self.bounded(memory.read(OUT + 0x60, 8)))]
        except Panicked as stop:
            answer["stop"] = stop.args[0]
            answer.pop("errors", None)
            answer.pop("lists", None)
            answer.pop("mark_head", None)
            answer.pop("index", None)
        return answer

    def bounded(self, count):
        if count > 40:
            raise Halt("error count")
        return count


def normal(case, spec):
    """Stop and text words in the same shape on both sides."""
    if spec["stop"] and spec["stop"][0] == "unwrap":
        spec = dict(spec, stop=("unwrap", spec["stop"][1], 0x2B, 0x599A53))
    if spec["stop"] and spec["stop"][0] in ("multiply overflow", "add overflow"):
        spec = dict(spec, stop=(spec["stop"][0], LOC_MUL))
    if spec["stop"]:
        spec = {key: value for key, value in spec.items() if key not in ("errors", "lists", "mark_head", "index")}
    return spec


def spec_run(case):
    return normal(case, run_spec(case))


CRASHES = (Halt, IndexError, KeyError, OverflowError, ValueError, TypeError, ZeroDivisionError, EvidenceError)


def compare_run(harness, case):
    """Empty when the bytes and the specification agree, else one line."""
    wanted = spec_run(case)
    try:
        found = harness.run(case)
    except CRASHES as error:
        return "%s: crash %s %s" % (case.label, type(error).__name__, error)
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


# ---- cases ----

def world(**changes):
    base = {"sizes": {}, "books": [0, 0, 0, 0], "lists": ([], [], []), "caps": (6, 6, 6), "source": 0, "errors": [], "error_cap": 8, "mode": 0,
            "dex": 0, "assets_word": 4, "start": 0, "asset_rows": [1000, 2000, 3000, 4000], "cap": 1 << 62, "wire_length": 4, "wire_kind": 0, "wire_cap": 6, "parse_error": 0,
            "asset": 7, "kind": 0, "price": 100, "stored": 5, "book": 6}
    base.update(changes)
    return base


def spread(count, start=2, step=3, value=11):
    """A sized map with a key every `step`, values unique per key."""
    return {start + index * step: value + index * 13 for index in range(count)}


def check_cases():
    rows = []
    for mode in (0, 3):
        for name, limit in (("high", LIMIT_HIGH), ("low", LIMIT_LOW)):
            for delta in (-1, 0, 1):
                rows.append(("product %s%+d mode %d" % (name, delta, mode), world(mode=mode, price=1, stored=limit + delta, book=0)))
                rows.append(("split product %s%+d mode %d" % (name, delta, mode), world(mode=mode, price=1, stored=limit + delta - 12345, book=12345)))
                rows.append(("price times two %s%+d mode %d" % (name, delta, mode), world(mode=mode, price=2, stored=(limit + delta) // 2, book=(limit + delta) % 2)))
        rows.append(("negative price mode %d" % mode, world(mode=mode, price=1 << 63 | 5)))
        rows.append(("price -1 mode %d" % mode, world(mode=mode, price=MASK[8])))
        rows.append(("zero price mode %d" % mode, world(mode=mode, price=0, stored=1 << 62)))
        rows.append(("product over i64 mode %d" % mode, world(mode=mode, price=1 << 32, stored=1 << 31, book=0)))
        rows.append(("product wraps negative mode %d" % mode, world(mode=mode, price=3, stored=1 << 62, book=0)))
        rows.append(("product wraps small mode %d" % mode, world(mode=mode, price=4, stored=1 << 62, book=7)))
        rows.append(("just below i64 mode %d" % mode, world(mode=mode, price=1, stored=(1 << 63) - 1, book=0)))
        rows.append(("saturated sum mode %d" % mode, world(mode=mode, price=1, stored=(1 << 63) - 5, book=9)))
        rows.append(("saturated sum zero price mode %d" % mode, world(mode=mode, price=0, stored=(1 << 63) - 5, book=9)))
        rows.append(("sum exactly i64 max mode %d" % mode, world(mode=mode, price=1, stored=(1 << 63) - 5, book=4)))
        rows.append(("sum one over i64 max mode %d" % mode, world(mode=mode, price=1, stored=(1 << 63) - 5, book=5)))
        rows.append(("negative stored mode %d" % mode, world(mode=mode, stored=(1 << 64) - 50, book=3)))
        rows.append(("negative sum large price mode %d" % mode, world(mode=mode, price=1 << 40, stored=(1 << 64) - 50, book=3)))
    rows.append(("book top bit panics", world(book=1 << 63)))
    rows.append(("book all ones panics", world(book=MASK[8])))
    rows.append(("book i64 max", world(price=0, stored=0, book=(1 << 63) - 1)))
    for asset in (0, 1, 9999, 10000, 10001, 99899998, 99899999, 99900000, 99900001, 1 << 32, MASK[8]):
        for kind in (0, 1, 2):
            rows.append(("asset %d kind %d" % (asset, kind), world(asset=asset, kind=kind, price=1, stored=LIMIT_HIGH + 2 + kind, book=0)))
    rows.append(("other location word", world(mode=3, price=1, stored=LIMIT_LOW, book=0, check_location=0x5714A28)))
    return [Case("check: " + label, "check", w) for label, w in rows]


def row_cases():
    rows = []
    big = spread(40)
    many = dict(big)
    for key, value in list(big.items())[::4]:
        rows.append(("present key %d" % key, world(asset=key, sizes=many, books=[0] * 16, price=9)))
        rows.append(("absent key %d" % (key + 1), world(asset=key + 1, sizes=many, books=[0] * 16, price=9)))
    rows.append(("key past every stored key", world(asset=1000, sizes=spread(5), books=[0] * 16, price=LIMIT_HIGH)))
    rows.append(("key below every stored key", world(asset=1, sizes=spread(5), books=[0] * 16, price=LIMIT_HIGH)))
    rows.append(("key past a two level tree", world(asset=1000, sizes=many, books=[0] * 16, price=LIMIT_HIGH)))
    high = MASK[8] - 5
    rows.append(("key above the filler keys, one leaf", world(asset=high, sizes=spread(5), books=None, price=1)))
    rows.append(("key above the filler keys, two levels", world(asset=high, sizes=many, books=None, price=1)))
    rows.append(("largest stored key", world(asset=high, sizes={3: 1, high: LIMIT_HIGH}, books=None, price=1)))
    rows.append(("stored fails key", world(asset=5, sizes={5: LIMIT_HIGH}, price=1)))
    rows.append(("stored passes key", world(asset=5, sizes={5: LIMIT_HIGH - 1}, price=1)))
    rows.append(("stored value at the separator", world(asset=many and sorted(tree_rows(sorted(many.items()))[0])[0][0], sizes=many, books=[0] * 16, price=LIMIT_HIGH // 100)))
    for at in range(4):
        rows.append(("book row %d alone fails" % at, world(asset=at, books=[LIMIT_HIGH if index == at else 0 for index in range(4)], price=1)))
        rows.append(("book row %d of dex 1 fails" % at, world(asset=10000 + at, books=[LIMIT_HIGH if index == at else 0 for index in range(4)], price=1)))
        rows.append(("other book row %d stays" % at, world(asset=at, books=[0 if index == at else LIMIT_HIGH for index in range(4)], price=1)))
    rows.append(("book plus stored fails", world(asset=1, sizes={1: LIMIT_HIGH - 1}, books=[0, 1, 0, 0], price=1)))
    rows.append(("book plus stored passes", world(asset=1, sizes={1: LIMIT_HIGH - 2}, books=[0, 1, 0, 0], price=1)))
    rows.append(("no books", world(asset=1, books=None, sizes={1: LIMIT_HIGH}, price=1)))
    rows.append(("no books passes", world(asset=1, books=None, sizes={1: LIMIT_HIGH - 1}, price=1)))
    rows.append(("no size map", world(asset=1, sizes=None, books=[0, LIMIT_HIGH, 0, 0], price=1)))
    rows.append(("no size map passes", world(asset=1, sizes=None, books=[0, 3, 0, 0], price=1)))
    rows.append(("no size map no books", world(asset=1, sizes=None, books=None, price=MASK[8])))
    rows.append(("index at book length", world(asset=4, books=[0, 0, 0, 0], price=1)))
    rows.append(("index past book length dex 2", world(asset=20009, books=[0, 0, 0, 0], price=1)))
    rows.append(("index last book", world(asset=3, books=[0, 0, 0, 0], price=1)))
    rows.append(("empty books", world(asset=0, books=[], price=1)))
    rows.append(("constant needs 10000 exactly", world(asset=10000, books=[LIMIT_HIGH], price=1)))
    rows.append(("constant needs 9999", world(asset=9999, books=[0] * 16, price=1) | {"books": None, "sizes": {9999: LIMIT_HIGH}}))
    for kind in (0, 1, 2):
        for source in (0, 1):
            rows.append(("failing row kind %d source %d" % (kind, source), world(asset=2, kind=kind, source=source, sizes={2: LIMIT_HIGH}, price=1)))
    rows.append(("wire asset large", world(asset=123456, books=[LIMIT_HIGH] * 16, sizes=None, price=1) | {"books": None, "sizes": {123456: LIMIT_HIGH}}))
    rows.append(("wire asset none", world(asset=99900000, books=None, sizes={99900000: LIMIT_HIGH}, price=1)))
    rows.append(("wire asset last", world(asset=99899999, books=None, sizes={99899999: LIMIT_HIGH}, price=1)))
    rows.append(("wire asset 10000", world(asset=10000, books=None, sizes={10000: LIMIT_HIGH}, price=1)))
    rows.append(("wire asset 9999", world(asset=9999, books=None, sizes={9999: LIMIT_HIGH}, price=1)))
    for full in (0, 1, 2):
        rows.append(("error list room for %d" % full, world(asset=2, sizes={2: LIMIT_HIGH}, price=1, error_cap=2, errors=[text_word(90 + at) for at in range(2 - full)])))
    rows.append(("error list starts empty with no room", world(asset=2, sizes={2: LIMIT_HIGH}, price=1, error_cap=0)))
    rows.append(("error list one short", world(asset=2, sizes={2: LIMIT_HIGH}, price=1, error_cap=3, errors=[text_word(91), text_word(92)])))
    rows.append(("negative price row", world(asset=2, price=MASK[8] - 3)))
    rows.append(("saturated row", world(asset=1, sizes={1: (1 << 63) - 1}, books=[0, 5, 0, 0], price=1, mode=3)))
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


def total_cases():
    rows = []
    prices = [1000, 2000, 3000, 4000]
    rows.append(("no sizes", world()))
    rows.append(("one asset", world(sizes={1: 7})))
    rows.append(("every asset", world(sizes={0: 1, 1: 2, 2: 3, 3: 4})))
    rows.append(("marks replace", world(sizes={0: 1, 1: 2, 2: 3, 3: 4}, lists=([], [(1, 77), (3, 99)], []))))
    rows.append(("mark on a zero size", world(sizes={0: 1}, lists=([], [(1, MASK[8])], []))))
    rows.append(("dex 2", world(dex=2, sizes={20000: 1, 20001: 2, 1: 100}, lists=([], [(20001, 5), (1, 9)], []))))
    rows.append(("no size map", world(sizes=None)))
    rows.append(("no size map with marks", world(sizes=None, lists=([], [(1, 5)], []))))
    rows.append(("big tree", world(sizes=spread(40, 0, 1), assets_word=4)))
    rows.append(("big mark tree", world(sizes=spread(40, 0, 1), assets_word=12, asset_rows=[5] * 12, lists=([], [(index, 3 + index) for index in range(0, 30)], []))))
    rows.append(("start past end", world(start=4, sizes={0: 1})))
    rows.append(("start in the middle", world(start=2, sizes={0: 1, 2: 5, 3: 1})))
    rows.append(("no assets", world(assets_word=0)))
    rows.append(("row negative price", world(asset_rows=[1000, 1 << 63, 3000, 4000], sizes={0: 1})))
    rows.append(("row negative price zero size", world(asset_rows=[MASK[8], 2, 3, 4])))
    rows.append(("mark negative price", world(lists=([], [(2, 1 << 63)], []), sizes={2: 1})))
    rows.append(("negative price after a positive sum", world(asset_rows=[1, 2, 3, 1 << 63], sizes={0: 5})))
    rows.append(("product overflow", world(asset_rows=[1 << 32, 1, 1, 1], sizes={0: 1 << 31})))
    rows.append(("product just fits", world(asset_rows=[1 << 32, 1, 1, 1], sizes={0: (1 << 31) - 1})))
    rows.append(("negative size", world(sizes={1: MASK[8] - 4})))
    rows.append(("negative product floor", world(asset_rows=[1 << 62, 1, 1, 1], sizes={0: (1 << 64) - 2})))
    rows.append(("sum overflow", world(asset_rows=[1 << 40, 1 << 40, 1, 1], sizes={0: 1 << 22, 1: 1 << 22})))
    rows.append(("sum just fits", world(asset_rows=[1 << 40, 1 << 40, 1, 1], sizes={0: 1 << 22, 1: (1 << 22) - 1})))
    rows.append(("row bound", world(assets_word=5)))
    rows.append(("row bound by slot with dex", world(dex=1, assets_word=6, sizes={})))
    rows.append(("mark avoids the row bound", world(assets_word=5, lists=([], [(4, 9)], []), sizes={4: 2})))
    rows.append(("multiply overflow", world(dex=1 << 51, assets_word=1)))
    rows.append(("multiply fits", world(dex=(MASK[8] // 10000), start=1615, assets_word=1616, lists=([], [(MASK[8], 5)], []))))
    rows.append(("add overflow", world(dex=(MASK[8] // 10000), start=1615, assets_word=1617, lists=([], [(MASK[8], 5)], []))))
    top = MASK[8] // 10000
    rows.append(("key above the filler keys in the size map", world(dex=top, start=1615, assets_word=1616, sizes={5: 1, 6: 2}, lists=([], [(MASK[8], 5)], []))))
    rows.append(("key above the filler keys in a two level size map", world(dex=top, start=1615, assets_word=1616, sizes=spread(40), lists=([], [(MASK[8], 5)], []))))
    rows.append(("key above the filler keys in the mark map", world(dex=top, start=1615, assets_word=1616, lists=([], [(5, 1), (6, 2)], []))))
    rows.append(("key above the filler keys in a two level mark map", world(dex=top, start=1615, assets_word=1616, lists=([], [(index, 2) for index in range(30)], []))))
    rows.append(("asset 9999 row", world(start=9999, assets_word=10000, asset_rows=[1] * 4 + [9], lists=([], [(9999, 5)], []), sizes={9999: 2})))
    rows.append(("slot 10000 wraps", world(dex=1, start=0, assets_word=1, sizes={10000: 3})))
    return [Case("total: " + label, "total", w) for label, w in rows]


def host_cases():
    rows = []
    rows.append(("length short", world(wire_length=3)))
    rows.append(("length long no capacity", world(wire_length=5, wire_cap=0)))
    rows.append(("parse error", world(parse_error=0x31)))
    rows.append(("parse error kind 1", world(parse_error=0x77, wire_kind=1)))
    rows.append(("nothing to do", world()))
    rows.append(("wire kind 1", world(wire_kind=1)))
    rows.append(("mode 3 skips the total", world(mode=3, cap=0, sizes={0: 1}, lists=([], [(0, 5)], []))))
    rows.append(("mode 3 still filters rows", world(mode=3, sizes={0: LIMIT_HIGH}, lists=([(0, 1), (1, 1)], [], []))))
    rows.append(("marks stay under cap", world(cap=100, sizes={0: 1}, lists=([], [(0, 1000)], []))))
    for whole, cap, label in ((1000, 100, "tenth equals cap"), (1009, 100, "just below the next unit"), (1010, 100, "one unit over"), (1020, 100, "two over"), (10, 0, "unit at zero cap"), (9, 0, "below one unit at zero cap"), (0, 0, "zero at zero cap")):
        rows.append((label, world(cap=cap, assets_word=1, asset_rows=[1], sizes={0: whole}, lists=([], [(0, 1)], []))))
    rows.append(("over cap with marks", world(cap=10, sizes={0: 1000, 2: 3}, lists=([], [(0, 5), (2, 6), (3, 7)], []))))
    rows.append(("over cap no marks", world(cap=10, sizes={0: 1000}, caps=(6, 0, 6))))
    rows.append(("over cap with source 1", world(cap=10, source=1, sizes={0: 1000}, lists=([], [(0, 5)], []))))
    rows.append(("over cap duplicate mark rows", world(cap=10, sizes={0: 1000}, lists=([], [(0, 5), (0, 6)], []))))
    rows.append(("failed mark row leaves the sum", world(cap=10, sizes={0: LIMIT_HIGH // 8, 1: 0}, asset_rows=[1, 1, 1, 1], lists=([], [(0, 9), (1, 5)], []))))
    rows.append(("row fails and total fails", world(cap=0, sizes={0: LIMIT_HIGH, 1: 500}, lists=([(0, 1)], [(1, 7)], [(0, 1)]))))
    rows.append(("total none clears with no text", world(asset_rows=[1 << 63, 1, 1, 1], lists=([], [(1, 5)], []))))
    rows.append(("total none no marks", world(asset_rows=[1 << 63, 1, 1, 1], caps=(6, 0, 6))))
    rows.append(("total none beats a bad cap", world(asset_rows=[1 << 63, 1, 1, 1], cap=1 << 63)))
    rows.append(("negative cap panics", world(cap=1 << 63)))
    rows.append(("negative cap panics with text room", world(cap=MASK[8], sizes={0: 1}, error_cap=0)))
    rows.append(("negative total stays", world(cap=0, sizes={0: MASK[8] - 1000})))
    rows.append(("error list grows at the total text", world(cap=0, sizes={0: 1000}, errors=[text_word(91)], error_cap=1)))
    rows.append(("error list room at the total text", world(cap=0, sizes={0: 1000}, errors=[text_word(91)], error_cap=2)))
    rows.append(("error list grows for rows and marks", world(cap=0, sizes={0: 1000, 1: LIMIT_HIGH}, error_cap=0, lists=([(1, 1)], [(0, 1), (2, 1)], []))))
    rows.append(("dex 3 wire", world(dex=3, assets_word=2, wire_length=2, asset_rows=[5, 6], books=[0, 0], sizes={30000: 1000, 30001: 2}, cap=0, lists=([], [(30000, 5)], []))))
    rows.append(("no books", world(books=None, sizes={1: LIMIT_HIGH}, lists=([(1, 1)], [], []))))
    rows.append(("no books under limit", world(books=None, sizes={1: LIMIT_HIGH - 1}, lists=([(1, 1)], [], []))))
    rows.append(("book total fails the row", world(sizes={}, books=[0, 0, LIMIT_HIGH, 0], lists=([(2, 1)], [(2, 1)], [(2, 1)]))))
    rows.append(("total ignores book sizes", world(cap=1, sizes={}, books=[1000000, 1000000, 1000000, 1000000])))
    rows.append(("largest whole", world(cap=1 << 62, assets_word=1, asset_rows=[1], sizes={0: (1 << 63) - 1})))
    rows.append(("largest whole under a large cap", world(cap=(1 << 63) - 1, assets_word=1, asset_rows=[1], sizes={0: (1 << 63) - 1})))
    rows.append(("large cap edge", world(cap=922337203685477580, assets_word=1, asset_rows=[1], sizes={0: (1 << 63) - 1})))
    for label, w in rows:
        if not label.startswith("length"):
            w["wire_length"] = w["assets_word"]
    return [Case("host: " + label, "host", w) for label, w in rows]


def all_cases():
    return check_cases() + row_cases() + retain_cases() + clear_cases() + total_cases() + host_cases()


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
    (HOST, "update gate"), (RETAIN, "three list retain"), (ROW, "row closure"), (CHECK, "size times price check"), (TOTAL, "total notional fold"), (CLEAR, "Mark list clear"),
)


def mutated_groups(image):
    """(function start, role, decoded rows)."""
    return [(start, role, decode_range(image, *image.exact_fde(start))) for start, role in GROUPS]


def run_mutants(image, reached, verbose=False):
    """A mutant only changes a run that reaches its instruction, so only those cases run."""
    results = []
    harness = Harness(image)
    machine = harness.machine
    machine.step_limit = MUTANT_STEP_LIMIT
    cases = all_cases()
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
                failed = compare_run(harness, cases[index])
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


# ---- evidence ----

HOST_BYTES = (
    (0x3BC3717, "4869d7d8000000", "imul rdx, rdi, 0xd8: the row closure indexes book rows with stride 0xd8"),
    (0x3BC371E, "488b8410d0000000", "mov rax, [rax+rdx+0xd0]: and reads book +0xd0"),
    (0x4848AFA, "49898c39d0000000", "mov [r9+rdi+0xd0], rcx: the book row reader stores +0xd0 last"),
    (0x484A9DC, "49898430d0000000", "mov [r8+rsi+0xd0], rax: the same store in the second reader"),
    (0x49E4F30, "4c8ba7c8000000", "mov r12, [rdi+0xc8]: 0x49e4f20 takes the old slot size"),
    (0x49E4F40, "4c89c3", "mov rbx, r8: its pointer argument"),
    (0x49E4F49, "488997c8000000", "mov [rdi+0xc8], rdx: it writes the new slot size"),
    (0x49E4FDE, "4c8b3b", "mov r15, [rbx]: it reads the running total"),
    (0x49E4FE1, "4d29e7", "sub r15, r12: subtracts the old size"),
    (0x49E5001, "4c893b", "mov [rbx], r15: stores it"),
    (0x49E5004, "4c89f8", "mov rax, r15"),
    (0x49E5007, "4c01f0", "add rax, r14: adds the new size"),
    (0x49E500C, "488903", "mov [rbx], rax: stores the running total"),
)
SERDE_COPIES = (0x431EA20, 0x431EEE0, 0x431F200, 0x431F6C0)
SERDE_FIELDS = ((0x78, "last_trade_px"), (0xD0, "total_sz"))
NAME_BYTES = ((0x704D49, 7, "SideMap"), (0x6F0123, 13, "user_trackers"), (0x6F055F, 10, "BookOrders"), (0x6EFFA7, 5, "asset"))
DISPLAYS = ((0x3BDDF10, ((0x5B8704, 6, "oracle", "byte 0"), (0x5B870A, 9, "reference", "other bytes"))),
            (0x3818CF0, ((0x20A040, 4, "Spot", "kind 0"), (0x209DCC, 4, "Mark", "kind 1"), (0x59F20A, 8, "External", "other kinds"))))
TEXTS = ((TEXT_ASSET, "per asset gate"), (TEXT_MISSING, "row and Mark list drop"), (TEXT_TOTAL, "total gate"))
REFERENCE_CLAIMS = (
    {"reference": "l1/clearinghouse/clearinghouse.rs:645", "claim": "retain_if_under_open_interest_cap compares stored size plus a request against a per asset cap map, when a side flag is on", "observed": "0x3708e80 compares (stored size + book total_sz) * price with one fixed limit; no cap map is read and there is no side flag", "verdict": "rule differs"},
    {"reference": "l1/clearinghouse/clearinghouse.rs:716", "claim": "the text is 'open interest cap: asset= requested_delta= current_open_interest= cap='", "observed": "the text at 0x1fa4b9 is 'Asset open interest exceeded cap asset= kind=, oi=', and oi is the product over 1e6", "verdict": "text differs"},
    {"reference": "l1/clearinghouse/clearinghouse.rs:657", "claim": "a failing row logs one record", "observed": "a failing row pushes two strings and leaves its price list", "verdict": "differs"},
    {"reference": "l1/books.rs:535", "claim": "Book has no running size total; total_resting_sz folds the orders map", "observed": "field +0xd0 is written out as total_sz, read at load, and kept by 0x49e4f20 as new size minus old size", "verdict": "field missing in the reference"},
    {"reference": "l1/books.rs:547", "claim": "Book keeps mark_px and oracle_px", "observed": "field +0x78 is written out as last_trade_px by 0x438a810", "verdict": "name differs"},
)
FIELDS = {
    "owner": {"+0x10": "asset count, must equal the wire list length; the total fold's end", "+0x30": "dex number, asset id = dex * 10000 + index", "+0x68/+0x70": "asset rows pointer and length, stride 0x60, signed price at +0x20", "+0x170/+0x178": "map asset to size: root, height", "+0x1b0": "total cap, i64", "+0x230": "mode byte: 3 skips the total gate and turns on the second record"},
    "size_map_node": {"+0x08": "keys, u64", "+0x60": "values, u64", "+0xba": "length, u16", "+0xc0": "edges"},
    "book_list": {"+0x08": "book rows pointer", "+0x10": "book rows length", "row stride": "0xd8", "row +0xd0": "total_sz"},
    "price_lists": {"+0x00/+0x08/+0x10": "kind 0 Spot: capacity, pointer, length, rows (asset, price)", "+0x18/+0x20/+0x28": "kind 1 Mark", "+0x30/+0x38/+0x40": "kind 2 External", "+0x48": "source byte, 0 oracle, other reference"},
    "result": {"+0x00..+0x50": "price lists, word 0x8000000000000000 at +0 means an error follows at +8", "+0x50/+0x58/+0x60": "text list: capacity, pointer, length, rows of 24 bytes"},
}
UNWIND = "unwind landing pad: no case unwinds"
PADDING = "alignment nop between arms"


def read_host_bytes(image):
    rows = []
    for va, wanted, meaning in HOST_BYTES:
        data = bytes(image.blob[image.offset(va):image.offset(va) + len(wanted) // 2]).hex()
        if data != wanted:
            raise EvidenceError("host bytes at %#x: %s" % (va, data))
        rows.append({"va": "%#x" % va, "bytes": data, "meaning": meaning})
    return rows


def fixed_text(image, va, size):
    return bytes(image.blob[image.offset(va):image.offset(va) + size]).decode("ascii")


def name_words(image, start):
    """The ASCII name a field writer puts inline as 8 byte immediates, last word first as stored."""
    rows = decode_range(image, *image.exact_fde(start))
    words = [row for row in rows if row.op == "mov" and row.imm_size == 8]
    pieces = [struct.pack("<Q", row.b[1] & MASK[8]) for row in words]
    pieces = [piece for piece in pieces if all(0x20 <= byte < 0x7F for byte in piece)]
    if len(pieces) == 1:
        return pieces[0].decode("ascii")
    if len(pieces) == 2:
        # Two overlapping words: the second holds the first 8 bytes, the first starts at +5.
        return (pieces[1] + pieces[0][3:]).decode("ascii")
    if not pieces:
        return loaded_name(image, rows)
    raise EvidenceError("field writer %#x has %d name words" % (start, len(pieces)))


def loaded_name(image, rows):
    """A name passed as a .rodata pointer and a length in edx."""
    for at, first in enumerate(rows):
        if first.op == "lea" and first.b[1] is None:
            for second in rows[at + 1:at + 4]:
                if second.op == "mov" and second.a == ("r", RDX) and second.b[0] == "i":
                    return fixed_text(image, first.b[4], second.b[1])
    return None


def serde_fields(image):
    """In each book writer: the load of a field offset, its next call, and the name that call writes."""
    table = []
    named = 0
    for copy in SERDE_COPIES:
        rows = decode_range(image, *image.exact_fde(copy))
        found = {}
        for at, row in enumerate(rows):
            for offset, _ in SERDE_FIELDS:
                if row.op == "mov" and row.b and row.b[0] == "m" and row.b[1] == R15 and row.b[4] == offset:
                    target = next(later.target for later in rows[at:] if later.op == "call")
                    found[offset] = {"load": "%#x" % row.va, "writer": "%#x" % target, "name": name_words(image, target)}
        for offset, name in SERDE_FIELDS:
            if offset not in found or found[offset]["name"] not in (name, None):
                raise EvidenceError("field %#x in %#x" % (offset, copy))
            named += found[offset]["name"] == name
        table.append({"writer": "%#x" % copy, "fields": {"%#x" % key: value for key, value in sorted(found.items())}})
    if named != len(SERDE_COPIES) * len(SERDE_FIELDS):
        raise EvidenceError("named book writers: %d" % named)
    return table


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


def call_flag(image, site):
    """The r8 flag the caller sets just before a slot call, by exact bytes."""
    data = bytes(image.blob[image.offset(site - 6):image.offset(site)])
    if data[-3:] == b"\x45\x31\xc0":
        return 0
    if data == b"\x41\xb8\x01\x00\x00\x00":
        return 1
    raise EvidenceError("flag bytes at %#x" % site)


def outcome_name(case, spec):
    if spec["stop"]:
        return "panic: " + str(spec["stop"][0])
    names = sorted({event[0] for event in spec["events"]})
    out = spec["out"]
    if case.kind == "check":
        word = "pass" if out is None else "text"
    elif case.kind == "row":
        word = "kept" if out else "dropped"
    elif case.kind == "total":
        word = "none" if out is None else "sum"
    elif case.kind == "host":
        word = out if isinstance(out, str) else out[0]
    else:
        word = "done"
    return "%s %s [%s]" % (case.kind, word, " ".join(names))


def case_line(case, spec):
    return "%s\t%s\t%s" % (case.kind, case.label.split(": ", 1)[1], outcome_name(case, spec))


def worked_runs(harness):
    """One row at the limit, and one total gate step."""
    just_under = compare_label(harness, Case("worked", "check", world(price=3, stored=LIMIT_HIGH // 3 - 1, book=0)))
    at_limit = compare_label(harness, Case("worked", "check", world(price=1, stored=LIMIT_HIGH, book=0)))
    book_only = harness.run(Case("worked", "host", world(books=[0, 0, LIMIT_HIGH, 0], lists=([(2, 1)], [(2, 1)], [(2, 1)]))))
    return {"product_just_under": just_under, "product_at_limit": at_limit, "limit": LIMIT_HIGH, "second_limit": LIMIT_LOW, "book_total_alone_drops_rows_left": [len(rows) for rows in book_only["lists"]], "book_total_alone_texts": len(book_only["errors"])}


def compare_label(harness, case):
    return "passes" if harness.run(case)["out"] is None else "fails"


def analyse(image, full=True, verbose=False):
    cases = all_cases()
    harness = Harness(image)
    mismatches = []
    outcomes = {}
    reached = []
    seen = set()
    lines = []
    machine = harness.machine
    for case in cases:
        machine.seen = set()
        trouble = compare_run(harness, case)
        if trouble:
            mismatches.append(trouble)
        reached.append(frozenset(machine.seen))
        seen |= machine.seen
        spec = spec_run(case)
        name = outcome_name(case, spec)
        outcomes[name] = outcomes.get(name, 0) + 1
        lines.append(case_line(case, spec))
    steps = machine.steps
    if mismatches and full:
        raise EvidenceError("spec mismatch: %s" % mismatches[0])
    functions = []
    for start, role in GROUPS:
        begin, end = image.exact_fde(start)
        rows = decode_range(image, begin, end)
        functions.append({"role": role, "start": "%#x" % begin, "end": "%#x" % end, "size": end - begin, "instructions": len(rows), "instructions_stepped": sum(1 for row_ in rows if row_.va in seen)})
    relative = harness.relative
    tables = {SLOT_HOST: HOST, SLOT_SHOW_U32: 0x3C978C0, SLOT_SHOW_KIND: 0x3818CF0, SLOT_SHOW_F64: 0x38033F0, SLOT_SHOW_SOURCE: 0x3BDDF10, SLOT_RECORD: 0x358DCD0}
    for slot, value in tables.items():
        if relative.get(slot) != value:
            raise EvidenceError("slot %#x" % slot)
    site_rows = []
    for va in slot_sites(image, SLOT_HOST):
        site_rows.append((HOST, va, "slot, flag %d" % call_flag(image, va), image.fde(va)[0], image.fde(va)[1]))
    direct = direct_sites(image, (RETAIN, ROW, CHECK, TOTAL, CLEAR, PARSE, 0x49E4F20))
    for target in sorted(direct):
        for va, opcode in sorted(direct[target]):
            site_rows.append((target, va, "rel32 %#x" % opcode, image.fde(va)[0], image.fde(va)[1]))
    locations = []
    for slot, name in ((LOC_BOOK, "book row bound"), (LOC_ROW, "second record, passed by the row closure"), (LOC_SATURATE, "first record, size sum"), (LOC_CHECK_UNWRAP, "negative book total"), (LOC_HOST_UNWRAP, "negative total cap"), (LOC_ORACLE, "asset row bound")):
        path, line, column = image.location(slot, relative)
        locations.append({"slot": "%#x" % slot, "name": name, "path": path, "line": line, "column": column})
    names = {}
    for va, size, wanted in NAME_BYTES:
        names["%#x" % va] = fixed_text(image, va, size)
        if names["%#x" % va] != wanted:
            raise EvidenceError("name at %#x" % va)
    displays = {}
    for function, rows in DISPLAYS:
        image.exact_fde(function)
        displays["%#x" % function] = {note: fixed_text(image, va, size) for va, size, wanted, note in rows}
        for va, size, wanted, note in rows:
            if fixed_text(image, va, size) != wanted:
                raise EvidenceError("display name at %#x" % va)
    texts = {"%#x" % va: {"use": use, "text": template(image, va)} for va, use in TEXTS}
    host_bytes = read_host_bytes(image)
    serde = serde_fields(image)
    worked = worked_runs(harness)
    results_rows = run_mutants(image, reached, verbose) if full else []
    tally = {key: sum(1 for row_ in results_rows if row_["result"] == key) for key in ("killed", "survived", "unreached")}
    return {
        "target": {"file": "artifacts/node/94/hl-node", "sha256": SHA256},
        "functions": functions,
        "data_words": {"%#x" % slot: "%#x" % value for slot, value in sorted(tables.items())},
        "limits": {"row_limit": "%#x" % LIMIT_HIGH, "second_record_limit": "%#x" % LIMIT_LOW, "row_limit_times_10": str(LIMIT_HIGH * 10), "two_to_64": str(1 << 64)},
        "serde_fields": serde,
        "host_bytes": host_bytes,
        "field_names": names,
        "displays": displays,
        "texts": texts,
        "locations": locations,
        "fields": FIELDS,
        "worked_example": worked,
        "reference_claims": list(REFERENCE_CLAIMS),
        "cases": {"total": len(cases)},
        "outcomes": dict(sorted(outcomes.items())),
        "mismatches": len(mismatches),
        "first_mismatch": mismatches[0] if mismatches else "",
        "instructions_stepped": steps,
        "mutations": tally,
        "_sites": site_rows, "_results": results_rows, "_lines": lines,
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
SATURATED = "the saturated sum is only reachable with an add overflow; any nonzero price then overflows or lands over the limit, and the text rounds to the same double"
REDUNDANT = "the checked wire step in 0x3bfd1d0 repeats a range test: a value that passes or fails here gets the same result from the next tests, so its output is the same for all u64"
REASONS = {0x370925D: FINITE, 0x370926E: FINITE, 0x370928D: RANGE, 0x370929B: RANGE, 0x3708EC3: SATURATED, 0x3708EC7: SATURATED,
           0x3BFD282: REDUNDANT, 0x3BFD28B: REDUNDANT, 0x3BFD2AC: REDUNDANT, 0x3BFD2C8: REDUNDANT}
REASON_RANGES = ((0x3709502, 0x3709552, UNWIND), (0x3BFD6ED, 0x3BFD7A0, UNWIND), (0x3BC38BC, 0x3BC38F0, UNWIND), (0x3BFD372, 0x3BFD3B5, UNWIND))


def render(evidence):
    evidence = dict(evidence)
    sites = evidence.pop("_sites")
    results = evidence.pop("_results")
    case_lines = evidence.pop("_lines")
    files = {"evidence.json": (json.dumps(evidence, indent=2, sort_keys=True) + "\n").replace("\x40", "[at]")}
    lines = ["target\tsite\tcall\tcaller_fde\tcaller_fde_end"]
    lines += ["%#x\t%#x\t%s\t%#x\t%#x" % row_ for row_ in sites]
    files["call_sites.tsv"] = "\n".join(lines) + "\n"
    files["cases.tsv"] = "\n".join(["copy\tlabel\toutcome"] + case_lines) + "\n"
    lines = ["function\tva\tkind\tresult\tkilled_by\treason"]
    lines += ["%#x\t%#x\t%s\t%s\t%s\t%s" % (row_["function"], row_["va"], row_["kind"], row_["result"], row_["by"], reason_for(row_)) for row_ in results]
    files["mutations.tsv"] = "\n".join(lines) + "\n"
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
