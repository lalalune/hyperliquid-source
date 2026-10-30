#!/usr/bin/env python3
"""Pin the node #94 quote token disable from ELF bytes: gate, spot scan, book sweep, TWAP sweep.

Spot deploy case 14 and one global vote arm reach `0x4d63950`. It checks the quote token, marks it
disabled, and for every spot pair quoted in that token removes one tree entry, cancels every user in
the book with reason 0xc, ends the TWAP orders on that spot, and flushes the rows. The real bytes of
the three copies, the pair scan, the whole-book walk, the queue sweep and the heap push and pop run in
a Python evaluator with only the edges stubbed. A separately written specification predicts every
edge call, row and queue entry, and every condition, immediate and field offset of the first copy is
then flipped to show the run can tell. No objdump or readelf output is parsed, and the binary is never
executed. Standard library only.
"""

import argparse
import bisect
import hashlib
import json
import math
import pathlib
import struct
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))

from elf_index import sections  # noqa: E402
from fde_extents import eh_frame_records  # noqa: E402

BINARY = ROOT / "artifacts" / "node" / "94" / "hl-node"
SHA256 = "3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f"

STATUS_WRITE = 0x339D350
NOT_ENABLED_TEXT = 0x5998A9
NOT_ENABLED = b"quote token is not currently enabled"
WORD_OK = 0x186
WORD_NOT_ENABLED = 0xDF
WORD_TOKEN_ZERO = 0xEF
WORD_REMOVE_MISSED = 0xCE
REASON_DELISTED = 0xC
ROW_TAG = 4
ROW_TERMINATED = 0x8000000000000001
ROW_SIZE = 0x268
ENTRY_SIZE = 0x28
VALUE_SIZE = 0x60
BOOK_STRIDE = 0xD8
PAIR_STRIDE = 0x20

SLOT_TREE_REMOVE = 0x5774C28
SLOT_GROW_ROWS = 0x5773D50
SLOT_GROW_KEEP = 0x57747D8
SLOT_MEMCMP = 0x576E488
SLOT_MEMCPY = 0x576DFE0
SLOT_ALLOC = 0x576DFD8
SLOT_ALLOC_FAILED = 0x576DFB8
SLOT_FREE = 0x576E010
SLOT_PANIC = 0x576E470
SLOT_BOUNDS = 0x576DFC8
SLOT_NAMES = {SLOT_TREE_REMOVE: "remove one key from a u64 tree, stubbed", SLOT_GROW_ROWS: "grow the row vector, stubbed", SLOT_GROW_KEEP: "grow the kept entry vector, stubbed",
              SLOT_ALLOC: "allocate, stubbed", SLOT_FREE: "free, stubbed", SLOT_PANIC: "panic with Location", SLOT_BOUNDS: "index bounds panic"}

# Each copy names the same steps with its own callees and exchange offsets.
COPIES = (
    dict(name="first", entry=0x4D63950, collector=0x48839E0, grow_list=0x454F5D0, whole=0x4308160, cancel=0x43038B0, clone=0x499C210, clone_drop=0x49AD040,
         sweep=0x42F3360, pop=0x44C0FE0, push=0x44C1900, remove=0x4944230, remove_user=0x49463E0, map_drop=0x49B7AD0, error_drop=0x4344430, state_row=0x46CA2B0,
         flush=0x432B440, tree=0x3A00, queue=0x34E0, books=0x3388),
    dict(name="second", entry=0x4D636C0, collector=0x48839E0, grow_list=0x454F5D0, whole=0x4307B60, cancel=0x4303B30, clone=0x499C210, clone_drop=0x49AD040,
         sweep=0x42F39B0, pop=0x44C0FE0, push=0x44C1900, remove=0x4944230, remove_user=0x49463E0, map_drop=0x49B7AD0, error_drop=0x4344430, state_row=0x46CA2B0,
         flush=0x432A990, tree=0x4480, queue=0x3F60, books=0x3E08),
    dict(name="third", entry=0x2747D90, collector=0x2570A50, grow_list=0x251B070, whole=None, cancel=0x26E4240, clone=0x28A24B0, clone_drop=0x28B0E30,
         sweep=0x26DD540, pop=0x279FBD0, push=0x279FFE0, remove=0x2868790, remove_user=0x2868060, map_drop=0x28AF080, error_drop=0x277EBA0, state_row=0x2311450,
         flush=0x24FC8A0, tree=0x3A00, queue=0x34E0, books=0x3388),
)
FIRST = COPIES[0]

# Routes: a nested spot deploy case and a global vote arm, read from the jump tables.
ROUTES = (
    dict(name="spot deploy, first family", table=0x703FF8, index=14, arm=0x4AD7AFE, site=0x4AD7B17, entry=0x4D63950),
    dict(name="global vote, first family", table=0x711064, index=62, arm=0x4CACDE3, gate=0x4CACDFC, block=0x4CAF273, site=0x4CAF27B, entry=0x4D63950),
)

LOCATION_NAMES = {0x5742338: "books", 0x56BB478: "books", 0x57357B8: "root", 0x56C6A38: "root", 0x5733F50: "walk", 0x56C5540: "walk"}

LEAF_EDGE = 0x7300000000
STATUS_NODE = dict(parent=0, keys=8, stride=8, index=0x60, length=0x62, values=0x64, value_stride=1, edges=0x70, size=0xD0)
USER_NODE = dict(parent=0, values=8, value_stride=0x18, keys=0x110, stride=0x14, index=0x1EC, length=0x1EE, edges=0x1F0, size=0x250)
ORDER_NODE = dict(values=0, value_stride=VALUE_SIZE, parent=0x420, keys=0x428, stride=8, index=0x480, length=0x482, edges=0x488, size=0x4E8)
BOOK_USER_NODE = dict(values=0, value_stride=0x50, parent=0x370, keys=0x378, stride=0x14, index=0x454, length=0x456, edges=0x458, size=0x4B8)
NODE_KEYS = 11

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
HEAP_SIZE = 0x400000
RETURN_SENTINEL = 0xDEAD0000
POISON = 0xA5A5A5A5A5A5A5A5
STEP_LIMIT = 2000000
MUTANT_STEP_LIMIT = 150000
UNMAPPED = 0x7300000000
FAKE_MEMCMP = 0x7E000000

EX = HEAP_BASE + 0x1000
OUT = EX + 0x4F00
PAIRS = EX + 0x5000
BOOKS = PAIRS + 0x2000
HEAP_ARRAY = BOOKS + 0x4000
BUMP = HEAP_ARRAY + 0x3000
FIELD_NOW = 0x60
FIELD_META = 0x90
FIELD_PAIRS = 0x1F8
FIELD_PAIR_COUNT = 0x200
FIELD_STATUS = 0x2E0


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
            self.put(row.a, width, self.get(row.a, width) * self.get(row.b, width))
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



# ---- specification, written from the disassembly as prose, never from a run ----

def user_id(number):
    return bytes((number * 37 + index * 11 + 5) & 0xFF for index in range(20))


def pack_date(year, ordinal, flags=0):
    return ((year << 13) | (ordinal << 4) | flags) & MASK[4]


def signed32(value):
    value &= MASK[4]
    return value - (1 << 32) if value & SIGN[4] else value


def body_bytes(asset, oid):
    """One TWAP state value: asset first, then a ramp that never gives byte +0x22 the value 2."""
    tail = bytes((oid * 7 + index * 3 + 1) & 0xFF for index in range(8, VALUE_SIZE))
    return struct.pack("<Q", asset) + tail[:0x1A] + bytes([0x31]) + tail[0x1B:]


def state_row_bytes(body):
    return bytes((body[index] ^ 0x5A ^ index) & 0xFF for index in range(0x58))


class Entry:
    def __init__(self, oid, user, due):
        self.oid, self.user, self.due = oid, user, due

    def bytes(self):
        return struct.pack("<Q", self.oid) + struct.pack("<III", *self.due) + user_id(self.user)

    def key(self):
        return (signed32(self.due[0]), self.due[1], self.due[2], user_id(self.user), self.oid)


class Case:
    def __init__(self, label, token=7, status=None, status_width=NODE_KEYS, pairs=(), books=0, users=None, entries=(), twaps=None, **extra):
        self.label, self.token = label, token
        self.status = {7: 0} if status is None else status
        self.status_width = status_width
        self.pairs = tuple(pairs)
        self.book_count = books
        # users: {book index: list of user numbers}; a book not named has no users.
        self.users = users or {}
        self.entries = tuple(entries)
        # twaps: {user number: {order id: asset}}, or None for a user with no order tree.
        self.twaps = twaps or {}
        self.now = extra.pop("now", (pack_date(2025, 100), 3600, 77))
        self.width = extra.pop("width", NODE_KEYS)
        self.book_width = extra.pop("book_width", NODE_KEYS)
        self.book_height = extra.pop("book_height", {})
        self.claimed = extra.pop("claimed", {})
        self.null_root = extra.pop("null_root", ())
        self.clone_none = extra.pop("clone_none", ())
        self.clone_extra = extra.pop("clone_extra", {})
        self.book_rows = extra.pop("book_rows", 0)
        self.remove_none = extra.pop("remove_none", ())
        self.user_none = extra.pop("user_none", ())
        self.spare = extra.pop("spare", 64)
        if extra:
            raise EvidenceError("unknown case fields: %s" % sorted(extra))


class SpecPanic(Exception):
    pass


def grow_size(capacity):
    return 4 if capacity == 0 else capacity * 2


def spec_book(case, copy, index, events, rows):
    """Clone the user map, walk it in key order, and cancel each user with flag 1 and reason 0xc."""
    users = sorted(case.users.get(index, ()), key=user_id)
    claimed = case.claimed.get(index, len(users))
    clone_root = clone_len = 0
    if claimed:
        if index in case.null_root or not users:
            raise SpecPanic(("panic", "root"))
        events.append(("clone", index, case.book_height.get(index, tree_height(len(users), case.book_width))))
        if index not in case.clone_none:
            clone_root = 1
            clone_len = len(users) + case.clone_extra.get(index, 0)
    if clone_root and clone_len:
        left = clone_len
        for number in users:
            if not left:
                break
            events.append(("cancel", index, user_id(number).hex(), 1, REASON_DELISTED))
            left -= 1
            for row in range(case.book_rows):
                rows.append(("book", number, row))
        if left:
            raise SpecPanic(("panic", "walk"))
    events.append(("clone drop", clone_root, clone_len))


def spec_sweep(case, asset, queue, twaps, events, rows, grown):
    """Pop every entry; end the ones on this spot and put the rest back, in pop order."""
    kept = []
    capacity = 0
    while queue:
        entry = queue.pop(0)
        orders = twaps.get(entry.user)
        if orders is None or entry.oid not in orders or orders[entry.oid] != asset:
            if len(kept) == capacity:
                events.append(("grow keep", capacity))
                capacity = grow_size(capacity)
            kept.append(entry)
            continue
        events.append(("remove", entry.user, entry.oid))
        if (entry.user, entry.oid) in case.remove_none:
            events.append(("error drop", WORD_REMOVE_MISSED))
            continue
        body = body_bytes(asset, entry.oid)
        del orders[entry.oid]
        if not orders:
            events.append(("remove user", user_id(entry.user).hex()))
            if entry.user not in case.user_none:
                events.append(("map drop", 0))
            del twaps[entry.user]
        events.append(("state row", body.hex()))
        if len(rows) == grown[0]:
            events.append(("grow rows", grown[0]))
            grown[0] = grow_size(grown[0])
        rows.append(("twap", entry.oid, entry.user, body))
    for entry in kept:
        queue.append(entry)
    if capacity:
        events.append(("free", "keep", capacity * ENTRY_SIZE, 0))
    queue.sort(key=Entry.key)


def spec_run(case, copy=FIRST):
    events = []
    twaps = {user: dict(orders) for user, orders in case.twaps.items() if orders is not None}
    queue = sorted(case.entries, key=Entry.key)
    result = {"events": events, "stop": None, "word": None, "error_text": False}

    def finish(word, text):
        result["word"] = word
        result["error_text"] = text
        result["queue"] = [entry.bytes().hex() for entry in queue]
        result["twaps"] = {user: sorted(orders) for user, orders in twaps.items()}
        return result

    if case.token == 0:
        return finish(WORD_TOKEN_ZERO, True)
    if case.token not in case.status or case.status[case.token] == 1:
        return finish(WORD_NOT_ENABLED, True)
    events.append(("write status", EX + FIELD_STATUS, case.token, 1))
    spots = [index for index, pair in enumerate(case.pairs) if pair[1] == case.token]
    capacity = 0
    for position in range(len(spots)):
        if position == 0:
            events.append(("alloc", 0x20))
            capacity = 4
        elif position == capacity:
            events.append(("grow list", position, 1, 8, 8))
            capacity *= 2
    try:
        for index in spots:
            events.append(("tree remove", EX + copy["tree"], index))
            if index >= case.book_count:
                raise SpecPanic(("panic", "books"))
            rows = []
            spec_book(case, copy, index, events, rows)
            # Rows the book sweep left count against the vector the sweep then appends to.
            grown = [0]
            while grown[0] < len(rows):
                grown[0] = grow_size(grown[0])
            spec_sweep(case, index, queue, twaps, events, rows, grown)
            events.append(("flush", grown[0], [row_digest(row, case) for row in rows]))
    except SpecPanic as caught:
        result["stop"] = caught.args[0]
        result["queue"] = None
        result["twaps"] = None
        return result
    if capacity:
        events.append(("free", "list", capacity * 8, 0))
    return finish(WORD_OK, False)


def row_digest(row, case):
    if row[0] == "book":
        return ("book", row[1], row[2])
    _, oid, user, body = row
    now = struct.pack("<III", *case.now)
    return ("twap", state_row_bytes(body).hex(), ROW_TERMINATED, oid, now.hex(), user_id(user).hex())


def tree_height(count, width):
    height = 0
    while (width + 1) ** (height + 1) - 1 < count:
        height += 1
    return height


def split(keys, width, height):
    """Separators and child key lists of one node; short lists become a keyless spine."""
    if height == 0:
        return keys, None
    if len(keys) <= 1:
        return [], [keys]
    below = (width + 1) ** height - 1
    count = 2
    while count * below + count - 1 < len(keys):
        count += 1
    share = (len(keys) - (count - 1)) / count
    separators, children, start = [], [], 0
    for index in range(1, count):
        at = int(share * index) + index - 1
        children.append(keys[start:at])
        separators.append(keys[at])
        start = at + 1
    children.append(keys[start:])
    return separators, children


# ---- harness: real bytes, edges stubbed, every edge argument recorded ----

class Harness:
    def __init__(self, image, copy=FIRST):
        self.image = image
        self.machine = Machine(image)
        machine = self.machine
        self.relative = {slot: addend for slot, kind, addend, _ in image.relocations() if kind == 8}
        relative = self.relative
        for slot in (SLOT_TREE_REMOVE, SLOT_GROW_ROWS, SLOT_GROW_KEEP, SLOT_ALLOC, SLOT_ALLOC_FAILED, SLOT_FREE, SLOT_PANIC, SLOT_BOUNDS):
            machine.memory.statics[slot] = relative[slot]
        machine.memory.statics[SLOT_MEMCMP] = FAKE_MEMCMP
        machine.memory.statics[SLOT_MEMCPY] = FAKE_MEMCMP + 0x10
        machine.slots = {relative[SLOT_TREE_REMOVE]: self.on_tree_remove, relative[SLOT_GROW_ROWS]: self.on_grow_rows, relative[SLOT_GROW_KEEP]: self.on_grow_keep,
                         relative[SLOT_ALLOC]: self.on_alloc, relative[SLOT_ALLOC_FAILED]: self.on_alloc_failed, relative[SLOT_FREE]: self.on_free,
                         relative[SLOT_PANIC]: self.on_panic, relative[SLOT_BOUNDS]: self.on_bounds, FAKE_MEMCMP: self.on_memcmp, FAKE_MEMCMP + 0x10: self.on_memcpy}
        self.select(copy)
        self.top = HEAP_SIZE
        self.bump = BUMP
        self.events = []
        self.names = {}

    def select(self, copy):
        self.copy = copy
        machine = self.machine
        real = {copy["entry"], copy["collector"], copy["sweep"], copy["pop"], copy["push"]}
        if copy["whole"]:
            real.add(copy["whole"])
        machine.real = frozenset(real)
        machine.calls = {STATUS_WRITE: self.on_status, copy["grow_list"]: self.on_grow_list, copy["cancel"]: self.on_cancel, copy["clone"]: self.on_clone,
                         copy["clone_drop"]: self.on_clone_drop, copy["remove"]: self.on_remove, copy["remove_user"]: self.on_remove_user, copy["map_drop"]: self.on_map_drop,
                         copy["error_drop"]: self.on_error_drop, copy["state_row"]: self.on_state_row, copy["flush"]: self.on_flush}

    # layout helpers

    def alloc(self, size):
        at = self.bump
        self.bump += (size + 15) & ~15
        if self.bump > HEAP_BASE + HEAP_SIZE:
            raise Halt("harness heap too small")
        return at

    def put(self, addr, width, value):
        self.machine.memory.write(addr, width, value)

    def build_tree(self, at, keys, shape, width, write_key, write_value=None, height=None, tempt=None, tempt_value=True):
        """(root, height, length) at `at`; unused key slots hold a tempting key."""
        keys = list(keys)

        def make(items, parent, slot, level):
            node = self.alloc(shape["size"])
            memory = self.machine.memory
            memory.put_bytes(node, bytes(shape["size"]))
            memory.put_bytes(node + shape["edges"], struct.pack("<Q", LEAF_EDGE) * 12)
            self.put(node + shape["parent"], 8, parent)
            self.put(node + shape["index"], 2, slot)
            separators, children = split(items, width, level)
            self.put(node + shape["length"], 2, len(separators))
            for index, key in enumerate(separators):
                write_key(node + shape["keys"] + index * shape["stride"], key)
                if write_value:
                    write_value(node + shape["values"] + index * shape["value_stride"], key)
            if tempt is not None:
                for index in range(len(separators), NODE_KEYS):
                    write_key(node + shape["keys"] + index * shape["stride"], tempt)
                    if write_value and tempt_value:
                        write_value(node + shape["values"] + index * shape["value_stride"], tempt)
            for index, child in enumerate(children or ()):
                self.put(node + shape["edges"] + index * 8, 8, make(child, node, index, level - 1))
            return node

        if not keys and height is None:
            self.put(at, 8, 0)
            self.put(at + 8, 8, 0)
            self.put(at + 0x10, 8, 0)
            return
        level = tree_height(len(keys), width) if height is None else height
        self.put(at, 8, make(keys, 0, 0, level))
        self.put(at + 8, 8, level)
        self.put(at + 0x10, 8, len(keys))

    def write_user(self, at, number):
        self.machine.memory.put_bytes(at, user_id(number))

    def write_oid(self, at, oid):
        self.put(at, 8, oid)

    def install_orders(self, at, user):
        orders = self.model[user]

        def body(slot, oid):
            self.machine.memory.put_bytes(slot, body_bytes(orders.get(oid, 0x7B), oid))

        keys = sorted(orders)
        self.value_at[at] = user
        # A slot past the length holds the first key, with the spot of the sweep, so a wrong length ends an order.
        self.build_tree(at, keys, ORDER_NODE, self.case.width, self.write_oid, body, tempt=keys[0] if keys else None)

    def install_users(self):
        users = sorted(self.model, key=user_id)
        self.value_at = {}

        def value(slot, user):
            if user in self.model:
                self.install_orders(slot, user)

        def plain(slot, user):
            value(slot, user)

        queue_at = EX + self.copy["queue"]
        self.build_tree(queue_at + 0x18, users, USER_NODE, self.case.width, self.write_user, plain, tempt=users[0] if users else None, tempt_value=False)

    def build(self, case):
        memory = self.machine.memory
        memory.reset(self.top)
        self.top = BUMP - HEAP_BASE
        self.bump = BUMP
        self.events = []
        self.names = {}
        self.case = case
        self.rows_cap = None
        self.model = {user: dict(orders) for user, orders in case.twaps.items() if orders is not None}
        for index, value in enumerate(case.now):
            self.put(EX + FIELD_NOW + index * 4, 4, value)
        self.put(EX + FIELD_PAIRS, 8, PAIRS)
        self.put(EX + FIELD_PAIR_COUNT, 8, len(case.pairs))
        # The slot next to the pair count holds 0, so a scan that reads it for its bound panics.
        self.put(EX + FIELD_META + 0x178, 8, 0)
        for index, (base, quote) in enumerate(case.pairs):
            self.put(PAIRS + index * PAIR_STRIDE, 8, base)
            self.put(PAIRS + index * PAIR_STRIDE + 8, 8, quote)
        status_keys = sorted(case.status)
        self.build_tree(EX + FIELD_STATUS, status_keys, STATUS_NODE, case.status_width, self.write_oid,
                        lambda slot, key: self.put(slot, 1, case.status.get(key, 0)), tempt=case.token if status_keys else None)
        copy = self.copy
        self.put(EX + copy["books"], 8, BOOKS)
        self.put(EX + copy["books"] + 8, 8, case.book_count)
        self.clones = {}
        for index in range(min(case.book_count, 64)):
            base = BOOKS + index * BOOK_STRIDE
            memory.put_bytes(base, bytes(BOOK_STRIDE))
            users = sorted(case.users.get(index, ()), key=user_id)
            self.put(base + 0xC0, 8, 0x4142)
            if users:
                height = case.book_height.get(index)
                self.build_tree(base + 0xB8, users, BOOK_USER_NODE, case.book_width, self.write_user, height=height)
                clone = self.alloc(0x18)
                self.build_tree(clone, users, BOOK_USER_NODE, case.book_width, self.write_user, height=height, tempt=users[0])
                self.clones[index] = (memory.read(clone, 8), memory.read(clone + 8, 8))
            self.put(base + 0xC8, 8, case.claimed.get(index, len(users)))
            if index in case.null_root:
                self.put(base + 0xB8, 8, 0)
        queue_at = EX + copy["queue"]
        entries = sorted(case.entries, key=Entry.key)
        self.put(queue_at, 8, max(len(entries), 1) + case.spare)
        self.put(queue_at + 8, 8, HEAP_ARRAY)
        self.put(queue_at + 0x10, 8, len(entries))
        memory.put_bytes(HEAP_ARRAY - ENTRY_SIZE, bytes([0x7F]) * ENTRY_SIZE)
        for index, entry in enumerate(entries):
            memory.put_bytes(HEAP_ARRAY + index * ENTRY_SIZE, entry.bytes())
        self.install_users()
        self.top = self.bump - HEAP_BASE

    # stubs

    def on_status(self, m):
        self.events.append(("write status", m.regs[RDI], m.regs[RSI], m.regs[RDX] & 0xFF))

    def on_tree_remove(self, m):
        self.events.append(("tree remove", m.regs[RDI], m.regs[RSI]))

    def on_alloc(self, m):
        self.events.append(("alloc", m.regs[RDI]))
        at = self.alloc(m.regs[RDI])
        self.names[at] = "list"
        m.regs[RAX] = at

    def on_alloc_failed(self, m):
        raise Panicked(("alloc failed", m.regs[RDI], m.regs[RSI]))

    def on_grow_list(self, m):
        vec = m.regs[RDI]
        read = m.memory.read
        capacity, pointer = read(vec, 8), read(vec + 8, 8)
        self.events.append(("grow list", m.regs[RSI], m.regs[RDX], m.regs[RCX], m.regs[R8] & MASK[8]))
        new = self.alloc(capacity * 16)
        m.memory.copy(new, pointer, capacity * 8)
        self.names[new] = "list"
        self.put(vec, 8, capacity * 2)
        self.put(vec + 8, 8, new)

    def grow(self, m, vec, element, name):
        read = m.memory.read
        capacity, pointer = read(vec, 8), read(vec + 8, 8)
        if not capacity and pointer != 8:
            raise Halt("empty vector pointer")
        new = grow_size(capacity)
        at = self.alloc(new * element)
        if capacity:
            m.memory.copy(at, pointer, capacity * element)
        self.names[at] = name
        self.put(vec, 8, new)
        self.put(vec + 8, 8, at)

    def on_grow_keep(self, m):
        self.events.append(("grow keep", m.memory.read(m.regs[RDI], 8)))
        self.grow(m, m.regs[RDI], ENTRY_SIZE, "keep")

    def on_grow_rows(self, m):
        self.events.append(("grow rows", m.memory.read(m.regs[RDI], 8)))
        self.grow(m, m.regs[RDI], ROW_SIZE, "rows")

    def on_free(self, m):
        self.events.append(("free", self.names.get(m.regs[RDI], "%#x" % m.regs[RDI]), m.regs[RSI], m.regs[RDX] & MASK[8]))

    def on_memcmp(self, m):
        left = m.memory.bytes_at(m.regs[RDI], m.regs[RDX])
        right = m.memory.bytes_at(m.regs[RSI], m.regs[RDX])
        m.regs[RAX] = 0 if left == right else (-1 & MASK[8] if left < right else 1)

    def on_memcpy(self, m):
        m.memory.copy(m.regs[RDI], m.regs[RSI], m.regs[RDX])
        m.regs[RAX] = m.regs[RDI]

    def on_panic(self, m):
        raise Panicked(("panic", LOCATION_NAMES.get(m.regs[RDI], "%#x" % m.regs[RDI])))

    def on_bounds(self, m):
        raise Panicked(("bounds", m.regs[RDI], m.regs[RSI]))

    def on_clone(self, m):
        index = (m.regs[RSI] and self.book_of(m.regs[RSI]))
        self.events.append(("clone", index, m.regs[RDX]))
        out = m.regs[RDI]
        if index in self.case.clone_none:
            self.put(out, 8, 0)
            self.put(out + 8, 8, 0x4242)
            self.put(out + 0x10, 8, 0)
            return
        root, height = self.clones[index]
        self.put(out, 8, root)
        self.put(out + 8, 8, height)
        self.put(out + 0x10, 8, len(self.case.users[index]) + self.case.clone_extra.get(index, 0))

    def book_of(self, root):
        for index in range(min(self.case.book_count, 64)):
            if self.machine.memory.read(BOOKS + index * BOOK_STRIDE + 0xB8, 8) == root:
                return index
        raise Halt("clone of an unknown root")

    def on_clone_drop(self, m):
        at = m.regs[RDI]
        self.events.append(("clone drop", 1 if m.memory.read(at, 8) else 0, m.memory.read(at + 0x10, 8)))

    def on_cancel(self, m):
        book = m.regs[RDI]
        index, extra = divmod(book - BOOKS, BOOK_STRIDE)
        if extra or m.regs[RCX] != EX:
            raise Halt("cancel arguments")
        user = m.memory.bytes_at(m.regs[RSI], 20)
        self.events.append(("cancel", index, user.hex(), m.regs[RDX] & 0xFF, m.regs[R9] & MASK[4]))
        vec = m.regs[R8]
        number = next(value for value in self.case.users[index] if user_id(value) == user)
        for row in range(self.case.book_rows):
            size = m.memory.read(vec + 0x10, 8)
            if size == m.memory.read(vec, 8):
                self.grow(m, vec, ROW_SIZE, "rows")
            at = m.memory.read(vec + 8, 8) + size * ROW_SIZE
            self.put(at, 8, 0x11)
            self.put(at + 8, 8, number)
            self.put(at + 0x10, 8, row)
            self.put(vec + 0x10, 8, size + 1)

    def on_remove(self, m):
        out, value, key_at = m.regs[RDI], m.regs[RSI], m.regs[RDX]
        user = self.value_at.get(value)
        oid = m.memory.read(key_at, 8)
        self.events.append(("remove", user, oid))
        if (user, oid) in self.case.remove_none:
            self.put(out + 0x22, 1, 2)
            return
        orders = self.model[user]
        asset = orders.pop(oid)
        m.memory.put_bytes(out, body_bytes(asset, oid))
        keys = sorted(orders)

        def body(slot, key):
            m.memory.put_bytes(slot, body_bytes(orders.get(key, 0x7B), key))

        self.build_tree(value, keys, ORDER_NODE, self.case.width, self.write_oid, body, tempt=keys[0] if keys else None)
        self.top = max(self.top, self.bump - HEAP_BASE)

    def on_remove_user(self, m):
        out = m.regs[RDI]
        user = m.memory.bytes_at(m.regs[RDX], 20)
        self.events.append(("remove user", user.hex()))
        number = next(value for value in self.model if user_id(value) == user)
        if m.regs[RSI] != EX + self.copy["queue"] + 0x18:
            raise Halt("remove user tree")
        del self.model[number]
        self.install_users()
        self.top = max(self.top, self.bump - HEAP_BASE)
        self.put(out, 8, 0 if number in self.case.user_none else 1)
        self.put(out + 0x18, 8, 0)

    def on_map_drop(self, m):
        self.events.append(("map drop", m.memory.read(m.regs[RDI] + 0x10, 8)))

    def on_error_drop(self, m):
        self.events.append(("error drop", m.memory.read(m.regs[RDI], 2)))

    def on_state_row(self, m):
        if m.regs[RDX] != EX + FIELD_META:
            raise Halt("state row meta")
        body = m.memory.bytes_at(m.regs[RSI], VALUE_SIZE)
        self.events.append(("state row", body.hex()))
        m.memory.put_bytes(m.regs[RDI], state_row_bytes(body))
        m.regs[RAX] = m.regs[RDI]

    def on_flush(self, m):
        vec = m.regs[RDI]
        if m.regs[RSI] != EX:
            raise Halt("flush exchange")
        read = m.memory.read
        capacity, pointer, size = read(vec, 8), read(vec + 8, 8), read(vec + 0x10, 8)
        rows = []
        for index in range(size):
            at = pointer + index * ROW_SIZE
            tag = read(at, 8)
            if tag == 0x11:
                rows.append(("book", read(at + 8, 8), read(at + 0x10, 8)))
            elif tag == ROW_TAG:
                rows.append(("twap", m.memory.bytes_at(at + 8, 0x58).hex(), read(at + 0x60, 8), read(at + 0x78, 8),
                             m.memory.bytes_at(at + 0x80, 12).hex(), m.memory.bytes_at(at + 0x8C, 20).hex()))
            else:
                rows.append(("bad row", tag))
        self.events.append(("flush", capacity, rows))

    # runs

    def run(self, case):
        self.build(case)
        machine = self.machine
        memory = machine.memory
        self.put(OUT, 8, 0)
        self.put(OUT + 8, 8, 0x5151)
        self.put(OUT + 0x10, 8, 0x5252)
        result = {"stop": None, "events": self.events, "word": None, "error_text": False, "queue": None, "twaps": None}
        try:
            returned = machine.run(self.copy["entry"], {RDI: OUT, RSI: EX, RDX: case.token})
        except Panicked as caught:
            result["stop"] = caught.args[0]
            return result
        finally:
            self.top = max(self.top, self.bump - HEAP_BASE)
        if returned != OUT:
            raise Halt("returned value")
        result["word"] = memory.read(OUT, 2)
        pointer, size = memory.read(OUT + 8, 8), memory.read(OUT + 0x10, 8)
        if (pointer, size) == (0x5151, 0x5252):
            result["error_text"] = False
        elif (pointer, size) == (NOT_ENABLED_TEXT, len(NOT_ENABLED)):
            result["error_text"] = True
        else:
            result["error_text"] = "other"
        result["queue"] = self.drain()
        result["twaps"] = {user: sorted(orders) for user, orders in self.model.items()}
        return result

    def drain(self):
        """Pop what is left with the real pop, so a broken heap shape shows as a wrong order."""
        machine = self.machine
        queue_at = EX + self.copy["queue"]
        popped = []
        for _ in range(machine.memory.read(queue_at + 0x10, 8) + 1):
            self.put(OUT + 0x40 + 8, 4, 1)
            machine.run(self.copy["pop"], {RDI: OUT + 0x40, RSI: queue_at})
            if machine.memory.read(OUT + 0x40 + 8, 4) == 0:
                return popped
            popped.append(machine.memory.bytes_at(OUT + 0x40, ENTRY_SIZE).hex())
        raise Halt("queue did not end")


def compare_run(harness, case):
    try:
        actual = harness.run(case)
    except (Halt, EvidenceError, IndexError, KeyError, ZeroDivisionError, StopIteration) as caught:
        return "%s: crash %s" % (case.label, caught)
    expected = spec_run(case, harness.copy)
    for key in ("stop", "events", "word", "error_text", "queue", "twaps"):
        if actual.get(key) != expected.get(key):
            return "%s: %s differs" % (case.label, key)
    return None


# ---- cases ----

def lcg(state):
    while True:
        state = (state * 6364136223846793005 + 1442695040888963407) & MASK[8]
        yield state >> 33


def due(step, day=100):
    return (pack_date(2025, day), 3600 + step, 5)


def row(oid, user, step=None):
    return Entry(oid, user, due(oid if step is None else step))


SPOTS = ((3, 7), (4, 8), (5, 7))


def gate_cases():
    rows = [Case("token zero", token=0, status={0: 0, 7: 0}), Case("token zero, no tree", token=0, status={}), Case("empty tree", status={}),
            Case("lower keys only", status={1: 0, 5: 0}), Case("higher keys only", status={8: 0, 900: 0}), Case("between keys", status={5: 0, 9: 0}),
            Case("already disabled", status={7: 1}), Case("disabled among others", status={1: 0, 7: 1, 9: 0}), Case("enabled", status={7: 0}),
            Case("enabled last in node", status={1: 1, 3: 1, 7: 0}), Case("value 2 passes", status={7: 2}), Case("value 255 passes", status={7: 255}),
            Case("top bit token", token=1 << 63, status={1 << 63: 0}), Case("top bit neighbour", token=1 << 63, status={(1 << 63) - 1: 0, (1 << 63) + 1: 0})]
    for width in (2, 3, 5, 11):
        tree = {key * 3: key % 2 for key in range(1, 90)}
        for token in (3, 6, 45, 48, 120, 267, 270, 4, 268, 271):
            rows.append(Case("status tree %d token %d" % (width, token), token=token, status=tree, status_width=width))
    return rows


def spot_cases():
    rows = [Case("no pairs"), Case("no pair matches", pairs=((3, 8), (4, 9)), books=2), Case("base equals the token only", pairs=((7, 8), (7, 9)), books=2),
            Case("one pair", pairs=((3, 7),), books=1), Case("first of two", pairs=((3, 7), (4, 8)), books=2), Case("last of two", pairs=((4, 8), (3, 7)), books=2),
            Case("two pairs", pairs=SPOTS, books=3)]
    for count in (3, 4, 5, 6, 8, 9, 10, 17):
        rows.append(Case("all of %d pairs" % count, pairs=tuple((index + 20, 7) for index in range(count)), books=count))
        rows.append(Case("every other of %d pairs" % count, pairs=tuple((index + 20, 7 if index & 1 else 8) for index in range(2 * count)), books=2 * count))
    rows.append(Case("no book for the spot", pairs=((3, 7),), books=0))
    rows.append(Case("book count equals the spot", pairs=((3, 8), (4, 7)), books=1))
    rows.append(Case("second spot has no book", pairs=SPOTS, books=2, users={0: [1, 2]}, entries=[row(1, 1)], twaps={1: {1: 0}}, book_rows=1))
    rows.append(Case("high pair word above low pair word", pairs=((7, 1 << 40 | 7), (9, 7)), books=2))
    return rows


def book_cases():
    rows = []
    one = ((3, 7),)
    for count in (1, 2, 3, 5, 11, 12, 13, 24, 40, 100):
        for width in (11, 2):
            rows.append(Case("book %d users width %d" % (count, width), pairs=one, books=1, users={0: list(range(1, count + 1))}, book_width=width))
    for height in (1, 2, 3, 5, 7, 8, 9, 10, 16, 17):
        for count in (0, 1, 2, 3, 5):
            if count:
                rows.append(Case("spine %d with %d users" % (height, count), pairs=one, books=1, users={0: list(range(1, count + 1))}, book_width=1, book_height={0: height}))
    rows.append(Case("users map claims none", pairs=one, books=1, users={0: [1, 2]}, claimed={0: 0}))
    rows.append(Case("null root with a length", pairs=one, books=1, users={0: [1, 2]}, null_root=(0,)))
    rows.append(Case("empty clone", pairs=one, books=1, users={0: [1, 2]}, clone_none=(0,)))
    rows.append(Case("clone one short", pairs=one, books=1, users={0: [1, 2, 3]}, clone_extra={0: -1}))
    rows.append(Case("clone one over", pairs=one, books=1, users={0: [1, 2, 3]}, clone_extra={0: 1}))
    rows.append(Case("clone over on a deep tree", pairs=one, books=1, users={0: list(range(1, 30))}, book_width=2, clone_extra={0: 2}))
    rows.append(Case("clone length zero", pairs=one, books=1, users={0: [1]}, clone_extra={0: -1}))
    rows.append(Case("two books", pairs=SPOTS, books=3, users={0: [1, 2], 1: [3], 2: [4, 5, 6]}, book_rows=1))
    rows.append(Case("book rows pass four", pairs=one, books=1, users={0: [1, 2, 3, 4, 5]}, book_rows=2))
    rows.append(Case("book rows then twap rows", pairs=one, books=1, users={0: [1, 2]}, book_rows=2, entries=[row(1, 1)], twaps={1: {1: 0}}))
    return rows


def sweep_cases():
    rows = []
    one = ((3, 7),)

    def add(label, entries, twaps, **extra):
        rows.append(Case(label, pairs=extra.pop("pairs", one), books=extra.pop("books", 1), entries=entries, twaps=twaps, **extra))

    add("empty queue, live map", [], {1: {1: 0}})
    add("one entry, one order", [row(1, 1)], {1: {1: 0}})
    add("one entry, other spot", [row(1, 1)], {1: {1: 4}})
    add("entry, no user map", [row(1, 1)], {})
    add("entry, other user", [row(1, 1)], {2: {1: 0}})
    add("entry, user without orders", [row(1, 1)], {1: {}})
    add("entry, user above every map key", [row(1, 2)], {1: {1: 0}})
    add("entry, user below every map key", [row(1, 1)], {2: {1: 0}, 4: {1: 0}})
    add("entry, user above the keys of a tall map", [row(1, 3)], {user: {1: 0} for user in (1, 2, 8, 9, 10, 11, 12, 13)}, width=2)
    add("entry, order above every key", [row(9, 1)], {1: {1: 0, 2: 0}})
    add("entry, order below every key", [row(1, 1)], {1: {5: 0, 6: 0}})
    add("entry, other order id", [row(1, 1)], {1: {2: 0}})
    add("two orders, one user, both end", [row(1, 1), row(2, 1)], {1: {1: 0, 2: 0}})
    add("two orders, one stays", [row(1, 1), row(2, 1)], {1: {1: 0, 2: 9}})
    add("two users, one stays", [row(1, 1), row(2, 2)], {1: {1: 0}, 2: {2: 9}})
    add("map order with no entry stays", [row(1, 1)], {1: {1: 0, 2: 0}})
    add("removal misses", [row(1, 1), row(2, 1)], {1: {1: 0, 2: 0}}, remove_none=((1, 1),))
    add("user removal gives none", [row(1, 1)], {1: {1: 0}}, user_none=(1,))
    add("equal due, order by user", [row(1, 1, 7), row(2, 2, 7), row(3, 3, 7)], {1: {1: 0}, 2: {2: 9}, 3: {3: 0}})
    add("equal due and user, order by id", [row(3, 1, 7), row(1, 1, 7), row(2, 1, 7)], {1: {1: 0, 2: 9, 3: 0}})
    add("signed date order", [Entry(1, 1, (pack_date(2025, 100), 5, 5)), Entry(2, 1, ((-(1 << 20)) & MASK[4], 5, 5))], {1: {1: 0}})
    add("kept entries pass four", [row(index, 1) for index in range(1, 7)], {1: {index: 9 for index in range(1, 7)}})
    add("kept entries pass eight", [row(index, 1) for index in range(1, 11)], {1: {index: 9 for index in range(1, 11)}})
    add("kept and ended mixed", [row(index, 1 + index % 3) for index in range(1, 14)], {1 + user: {index: index % 2 * 9 for index in range(1, 14) if (1 + index % 3) == 1 + user} for user in range(3)})
    add("rows pass four", [row(index, 1) for index in range(1, 7)], {1: {index: 0 for index in range(1, 7)}})
    add("rows pass eight", [row(index, index) for index in range(1, 11)], {index: {index: 0} for index in range(1, 11)})
    add("empty heap slot spare", [row(1, 1)], {1: {1: 9}}, spare=0)
    add("two spots, same user", [row(1, 1), row(2, 1)], {1: {1: 0, 2: 2}}, pairs=SPOTS, books=3)
    add("two spots, rows split", [row(index, index % 2 + 1) for index in range(1, 9)], {user + 1: {index: index % 3 for index in range(1, 9) if index % 2 == user} for user in range(2)}, pairs=SPOTS, books=3)
    for width in (2, 3, 11):
        users = {user: {user * 100 + index: (index % 2) * 9 for index in range(6)} for user in range(1, 16)}
        entries = [row(oid, user, oid % 37) for user, orders in users.items() for oid in orders]
        add("deep trees width %d" % width, entries, users, width=width)
        add("deep trees all end width %d" % width, entries, {user: {oid: 0 for oid in orders} for user, orders in users.items()}, width=width)
    for count in range(1, 12):
        add("one user, %d orders of 12 end" % count, [row(index, 1) for index in range(1, 13)], {1: {index: 0 if index <= count else 9 for index in range(1, 13)}}, width=2)
    return rows


def mixed_cases():
    random = lcg(61)
    rows = []
    for number in range(60):
        token = 7 + next(random) % 2
        pair_count = 1 + next(random) % 7
        pairs = tuple((10 + index, 7 + next(random) % 3) for index in range(pair_count))
        users = {index: sorted({1 + next(random) % 9 for _ in range(next(random) % 6)}) for index in range(pair_count)}
        owners = {}
        entries = []
        for oid in range(1, 2 + next(random) % 18):
            user = 1 + next(random) % 6
            owners.setdefault(user, {})[oid] = next(random) % pair_count
            if next(random) % 8:
                entries.append(row(oid, user, next(random) % 5))
        rows.append(Case("mixed %d" % number, token=token, status={7: 0, 8: 0, 9: 1}, pairs=pairs, books=pair_count, users=users, entries=entries, twaps=owners,
                         width=(2, 3, 11)[next(random) % 3], book_width=(2, 11)[next(random) % 2], book_rows=next(random) % 3))
    return rows


def all_cases():
    return gate_cases() + spot_cases() + book_cases() + sweep_cases() + mixed_cases()


# ---- structure of the bytes ----

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


def find_all(image, start, pattern):
    """Every place a byte pattern occurs inside a function."""
    begin, end = image.exact_fde(start)
    data = bytes(image.blob[image.offset(begin):image.offset(begin) + end - begin])
    found = []
    at = data.find(pattern)
    while at >= 0:
        found.append(begin + at)
        at = data.find(pattern, at + 1)
    return found


def pin_rows():
    rows = []
    for copy in COPIES:
        entry = copy["entry"]
        rows += [(entry, "mov cx, 0xdf: word for a token not enabled", b"\x66\xb9\xdf\x00", 1),
                 (entry, "mov cx, 0xef: word for token 0", b"\x66\xb9\xef\x00", 1),
                 (entry, "mov edx, 1: value written to the status tree, and the flag of the cancel in the inlined copy", b"\xba\x01\x00\x00\x00", 1 if copy["whole"] else 2),
                 (entry, "mov word [rdi], 0x186: done", b"\x66\xc7\x07\x86\x01", 1),
                 (entry, "mov qword [rdi+0x10], 0x24: length of the text", b"\x48\xc7\x47\x10\x24\x00\x00\x00", 1)]
        whole = copy["whole"] or entry
        rows += [(whole, "mov r9d, 0xc: cancel reason", b"\x41\xb9\x0c\x00\x00\x00", 1)]
        sweep = copy["sweep"]
        rows += [(sweep, "mov word [rsp+0x1c0], 0xce: word for a removal that misses", b"\x66\xc7\x84\x24\xc0\x01\x00\x00\xce\x00", 1),
                 (sweep, "movabs rax, 1 << 63 | 1: status word of the row", b"\x48\xb8" + struct.pack("<Q", ROW_TERMINATED), 1),
                 (sweep, "mov qword [rsp+0x1c0], 4: row tag", b"\x48\xc7\x84\x24\xc0\x01\x00\x00\x04\x00\x00\x00", 1),
                 (sweep, "imul rdi, rbx, 0x268: row stride", b"\x48\x69\xfb\x68\x02\x00\x00", 1),
                 (sweep, "mov edx, 0x268: row copy length", b"\xba\x68\x02\x00\x00", 1),
                 (sweep, "cmp byte [rsp+0x1e2], 2: no value from the removal", b"\x80\xbc\x24\xe2\x01\x00\x00\x02", 1)]
    return rows


def read_pins(image):
    rows = []
    for start, meaning, pattern, expected in pin_rows():
        found = find_all(image, start, pattern)
        if len(found) != expected:
            raise EvidenceError("pin %r at %#x has %d sites" % (meaning, start, len(found)))
        rows.append({"function": "%#x" % start, "sites": ["%#x" % va for va in found], "bytes": pattern.hex(), "meaning": meaning})
    return rows


def read_routes(image):
    """Jump table slot, arm and call of each route, all from bytes."""
    rows = []
    for route in ROUTES:
        table = route["table"]
        slot = table + route["index"] * 4
        arm = table + struct.unpack_from("<i", image.blob, image.offset(slot))[0]
        if arm != route["arm"]:
            raise EvidenceError("route %s arm %#x" % (route["name"], arm))
        site = route["site"]
        call = bytes(image.blob[image.offset(site):image.offset(site) + 5])
        if call[0] != 0xE8 or site + 5 + struct.unpack_from("<i", call, 1)[0] != route["entry"]:
            raise EvidenceError("route %s call" % route["name"])
        row = {"name": route["name"], "table": "%#x" % table, "index": route["index"], "arm": "%#x" % arm, "site": "%#x" % site, "entry": "%#x" % route["entry"]}
        if "gate" in route:
            gate = route["gate"]
            data = bytes(image.blob[image.offset(gate) - 5:image.offset(gate) + 6])
            if data[:5] != b"\x41\x80\x7f\x10\x00" or data[5:7] != b"\x0f\x84":
                raise EvidenceError("route gate bytes")
            if gate + 6 + struct.unpack_from("<i", data, 7)[0] != route["block"]:
                raise EvidenceError("route gate target")
            row["gate"] = {"site": "%#x" % gate, "reads": "byte at action +0x10", "zero_goes_to": "%#x" % route["block"]}
        rows.append(row)
    return rows


def read_constants(image):
    text = bytes(image.blob[image.offset(NOT_ENABLED_TEXT):image.offset(NOT_ENABLED_TEXT) + len(NOT_ENABLED)])
    if text != NOT_ENABLED:
        raise EvidenceError("text differs")
    return {"text": {"va": "%#x" % NOT_ENABLED_TEXT, "bytes": text.decode("ascii")}}


def call_targets(image, start):
    """Direct call targets of one function, read through the byte decoder."""
    found = []
    for row in decode_range(image, *image.exact_fde(start)):
        if row.op == "call" and row.target and row.target not in found:
            found.append(row.target)
    return found


def check_edges(image):
    """Each stubbed edge of each copy is a direct call inside the function that the copy table says."""
    rows = []
    for copy in COPIES:
        wanted = {copy["entry"]: [STATUS_WRITE, copy["collector"], copy["sweep"], copy["flush"]] + ([copy["whole"]] if copy["whole"] else [copy["cancel"], copy["clone"], copy["clone_drop"]]),
                  copy["sweep"]: [copy["pop"], copy["push"], copy["remove"], copy["remove_user"], copy["map_drop"], copy["error_drop"], copy["state_row"]],
                  copy["collector"]: [copy["grow_list"]]}
        if copy["whole"]:
            wanted[copy["whole"]] = [copy["cancel"], copy["clone"], copy["clone_drop"]]
        for start, targets in wanted.items():
            calls = call_targets(image, start)
            missing = [target for target in targets if target not in calls]
            if missing:
                raise EvidenceError("%#x misses %s" % (start, [hex(value) for value in missing]))
            rows.append({"copy": copy["name"], "function": "%#x" % start, "targets": ["%#x" % value for value in targets]})
    return rows


# ---- mutation pass ----

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


MUTATED = ((FIRST["entry"], "disable"), (FIRST["collector"], "pair scan"), (FIRST["whole"], "whole book"), (FIRST["sweep"], "queue sweep"))


def run_mutants(image, seen, verbose=False):
    results = []
    harness = Harness(image)
    machine = harness.machine
    machine.step_limit = MUTANT_STEP_LIMIT
    for start, _ in MUTATED:
        cases = all_cases()
        cases.sort(key=lambda case: len(case.entries) + sum(len(value) for value in case.users.values()) + len(case.status))
        rows = decode_range(image, *image.exact_fde(start))
        for va, at, kind in mutation_targets(image, rows):
            if va not in seen:
                results.append({"function": start, "va": va, "kind": kind, "result": "unreached", "by": ""})
                continue
            machine.patches = mutate_patch(image, va, at, kind)
            machine.cache.pop(va, None)
            failed = None
            for index, case in enumerate(cases):
                failed = compare_run(harness, case)
                if failed:
                    cases.insert(0, cases.pop(index))
                    break
            machine.patches = {}
            machine.cache.pop(va, None)
            results.append({"function": start, "va": va, "kind": kind, "result": "killed" if failed else "survived",
                            "by": failed.split(":")[0] if failed else ""})
            if verbose and not failed:
                print("survived %#x %s" % (va, kind), flush=True)
    return results


# ---- evidence ----

STATUS_MAP = (
    (0x00, "parent"),
    (0x08, "key, u64 token, 11 slots"),
    (0x60, "index in the parent"),
    (0x62, "key count"),
    (0x64, "value byte per key: 1 is disabled, anything else passes the gate"),
    (0x70, "edges of an inner node"),
)
ENTRY_MAP = (
    (0x00, 8, "TWAP order id, the key of the inner map"),
    (0x08, 12, "due time; the first word is 0 only for the no-entry niche"),
    (0x14, 20, "user, the key of the outer map"),
)
QUEUE_MAP = (
    (0x00, "heap capacity"),
    (0x08, "heap array, stride 0x28"),
    (0x10, "heap length"),
    (0x18, "user map: root, height, length"),
)
VALUE_MAP = (
    (0x00, "spot index, compared with the sweep's spot"),
    (0x22, "byte; 2 is the niche for no value from the removal"),
)
ROW_MAP = (
    (0x00, 8, "tag 4"),
    (0x08, 0x58, "state row made by the state row helper from the removed value"),
    (0x60, 8, "1 << 63 | 1: the serializer word for \"terminated\""),
    (0x78, 8, "TWAP order id"),
    (0x80, 12, "block time from exchange +0x60"),
    (0x8C, 20, "user"),
)
BOOK_FIELDS = ((0xB8, "user map root; 0 with a nonzero length panics at the unwrap"), (0xC0, "user map height"), (0xC8, "user map length; 0 skips the clone and the walk"))
USER_NODE_MAP = (
    (0x370, "parent"), (0x378, "key, 20-byte user, 11 slots at stride 0x14"), (0x454, "index in the parent"), (0x456, "key count"), (0x458, "edges of an inner node"),
)
REFERENCE_CLAIMS = (
    {"reference": "l1/exchange/handlers/26_spot_deploy.rs:143,286,366", "claim": "nested case 14 is DisableQuoteToken and calls an abstract external disable_quote_token",
     "bytes": "table 0x703ff8 entry 14 lands on the arm that bound-checks the token against +0x218 and calls 0x4d63950, so the case number agrees; the reference has no body for the external, and this packet is that body"},
    {"reference": "l1/action/vote_global.rs:132", "claim": "EnableQuoteToken { token, allowed } is raw 0x52, case 0x40",
     "bytes": "an arm that reads a token word at +0x08 and a byte at +0x10, and calls 0x4d63950 when the byte is 0, sits at index 62 (0x3e) of table 0x711064, not 0x40. The reference names case 0x3e SetActionDelayerEnabled"},
    {"reference": "l1/spot_meta.rs:182-190,389-390", "claim": "quote_token_to_status holds Active or Disabled",
     "bytes": "agrees in shape: the tree at exchange +0x2e0 maps a token to a byte, 1 stops the disable, and this path writes 1. Which byte means Active is not read here beyond 1"},
)
NOT_REACHED = "no case reaches it"
LANDING = "unwind landing pad or panic tail: no case unwinds"


def reason_for(row):
    va = row["va"]
    if row["result"] == "killed":
        return ""
    for low, high, reason in REASON_RANGES:
        if low <= va < high:
            return reason
    return REASONS.get(va, "")


def outcome_name(spec):
    if spec["stop"]:
        return "panic %s" % spec["stop"][1]
    if spec["word"] != WORD_OK:
        return "refused %#x" % spec["word"]
    kinds = {event[0] for event in spec["events"]}
    if "state row" in kinds:
        return "done, TWAP orders ended"
    if "cancel" in kinds:
        return "done, book users cancelled"
    if "tree remove" in kinds:
        return "done, spots with nothing on them"
    return "done, no spot quoted in the token"


def worked_run(harness):
    """Two spots quoted in token 7, a third that is not, and a queue that touches all three."""
    case = Case("worked", pairs=((3, 7), (4, 8), (5, 7)), books=3, users={0: [1, 2], 1: [3], 2: [4]},
                entries=[row(1, 1, 1), row(2, 2, 2), row(3, 2, 3), row(4, 3, 4)], twaps={1: {1: 0}, 2: {2: 1, 3: 2}, 3: {4: 0}}, book_rows=1)
    run = harness.run(case)
    steps = []
    for event in run["events"]:
        name = event[0]
        if name == "write status":
            steps.append({"step": "status byte set to 1", "token": event[2]})
        elif name == "tree remove":
            steps.append({"step": "key removed from the tree", "key": event[2]})
        elif name == "cancel":
            steps.append({"step": "all orders of one user cancelled", "book": event[1], "reason": event[4]})
        elif name == "remove":
            steps.append({"step": "TWAP order ended", "user": event[1], "order": event[2]})
        elif name == "flush":
            steps.append({"step": "rows flushed", "rows": ["book" if item[0] == "book" else "twap order %d" % item[3] for item in event[2]]})
    return {"token": 7, "pairs": [[3, 7], [4, 8], [5, 7]], "steps": steps, "word": "%#x" % run["word"],
            "orders_left": {str(user): orders for user, orders in sorted(run["twaps"].items())}, "queue_left": len(run["queue"])}


def field_offsets(image, start):
    counts = {}
    for row_ in decode_range(image, *image.exact_fde(start)):
        for operand in (row_.a, row_.b):
            if operand and operand[0] == "m" and operand[1] not in (None, RSP):
                counts[operand[4]] = counts.get(operand[4], 0) + 1
    return counts


def copy_offset_rows(image):
    """Field offsets of each copy's entry that the first copy does not use the same number of times."""
    base = field_offsets(image, FIRST["entry"])
    rows = []
    for copy in COPIES[1:]:
        counts = field_offsets(image, copy["entry"])
        rows.append({"entry": "%#x" % copy["entry"], "differs_from_first": {"%#x" % key: [base.get(key, 0), counts.get(key, 0)] for key in sorted(set(base) | set(counts)) if base.get(key, 0) != counts.get(key, 0)}})
    return rows


def sweep_diff(image):
    """The two asset sweeps against each other: bytes that differ after masking rel32 call and rip fields."""
    rows = {}
    for name, copy in (("first", FIRST), ("second", COPIES[1])):
        begin, end = image.exact_fde(copy["sweep"])
        rows[name] = decode_range(image, begin, end)
    pairs = zip(rows["first"], rows["second"])
    differ = [("%#x" % left.va, "%#x" % right.va) for left, right in pairs if left.op != right.op or left.size != right.size or (left.a != right.a and left.op != "call") or (left.b != right.b and left.op not in ("call", "lea"))]
    return {"instructions": [len(rows["first"]), len(rows["second"])], "differing_pairs": differ[:8], "differing_count": len(differ)}


def analyse(image, full=True, verbose=False):
    cases = all_cases()
    harnesses = [Harness(image, copy) for copy in COPIES]
    mismatches = []
    outcomes = {}
    for harness in harnesses:
        for case in cases:
            trouble = compare_run(harness, case)
            if trouble:
                mismatches.append("%s %s" % (harness.copy["name"], trouble))
    for case in cases:
        name = outcome_name(spec_run(case))
        outcomes[name] = outcomes.get(name, 0) + 1
    worked = worked_run(harnesses[0])
    seen = set()
    for harness in harnesses:
        seen |= harness.machine.seen
    first_seen = set(harnesses[0].machine.seen)
    steps = sum(harness.machine.steps for harness in harnesses)
    functions = []
    for copy in COPIES:
        for role in ("entry", "collector", "whole", "sweep"):
            start = copy[role]
            if not start:
                continue
            begin, end = image.exact_fde(start)
            rows = decode_range(image, begin, end)
            functions.append({"copy": copy["name"], "role": role, "start": "%#x" % begin, "end": "%#x" % end, "size": end - begin, "instructions": len(rows),
                              "instructions_stepped": sum(1 for row_ in rows if row_.va in seen)})
    relative = harnesses[0].relative
    targets = sorted({copy[key] for copy in COPIES for key in ("entry", "whole", "sweep", "collector") if copy[key]})
    sites = direct_sites(image, targets)
    site_rows = []
    for target in sorted(sites):
        for va, opcode in sorted(sites[target]):
            site_rows.append((target, va, opcode, image.fde(va)[0], image.fde(va)[1]))
    results_rows = run_mutants(image, first_seen, verbose) if full else []
    tally = {key: sum(1 for row_ in results_rows if row_["result"] == key) for key in ("killed", "survived", "unreached")}
    return {
        "target": {"file": "artifacts/node/94/hl-node", "sha256": SHA256},
        "functions": functions,
        "routes": read_routes(image),
        "edges": check_edges(image),
        "copies": [{key: ("%#x" % value if isinstance(value, int) else value) for key, value in copy.items()} for copy in COPIES],
        "copy_offsets": copy_offset_rows(image),
        "sweep_pair": sweep_diff(image),
        "constants": read_constants(image),
        "slots": {"%#x" % slot: {"target": "%#x" % relative[slot], "meaning": SLOT_NAMES[slot]} for slot in sorted(SLOT_NAMES)},
        "pins": read_pins(image),
        "locations": [{"slot": "%#x" % slot, "name": name, "path": image.location(slot, relative)[0], "line": image.location(slot, relative)[1],
                       "column": image.location(slot, relative)[2]} for slot, name in sorted(LOCATION_NAMES.items())],
        "status_node": [{"offset": "%#x" % offset, "meaning": meaning} for offset, meaning in STATUS_MAP],
        "queue_map": [{"offset": "%#x" % offset, "meaning": meaning} for offset, meaning in QUEUE_MAP],
        "entry_map": [{"offset": "%#x" % offset, "size": size, "meaning": meaning} for offset, size, meaning in ENTRY_MAP],
        "value_map": [{"offset": "%#x" % offset, "meaning": meaning} for offset, meaning in VALUE_MAP],
        "row_map": [{"offset": "%#x" % offset, "size": size, "meaning": meaning} for offset, size, meaning in ROW_MAP],
        "book_fields": [{"offset": "%#x" % offset, "meaning": meaning} for offset, meaning in BOOK_FIELDS],
        "book_user_node": [{"offset": "%#x" % offset, "meaning": meaning} for offset, meaning in USER_NODE_MAP],
        "nodes": {"status": STATUS_NODE, "twap_user": USER_NODE, "twap_order": ORDER_NODE, "book_user": BOOK_USER_NODE},
        "worked_example": worked,
        "reference_claims": list(REFERENCE_CLAIMS),
        "cases": {"total": len(cases), "per_copy": len(cases)},
        "outcomes": dict(sorted(outcomes.items())),
        "mismatches": len(mismatches),
        "first_mismatch": mismatches[0] if mismatches else "",
        "instructions_stepped": steps,
        "mutations": tally,
        "_sites": site_rows, "_results": results_rows,
    }


def render(evidence):
    evidence = dict(evidence)
    sites = evidence.pop("_sites")
    results = evidence.pop("_results")
    files = {"evidence.json": json.dumps(evidence, indent=2, sort_keys=True) + "\n"}
    lines = ["target\tsite\topcode\tcaller_fde\tcaller_fde_end"]
    lines += ["%#x\t%#x\t%#x\t%#x\t%#x" % row_ for row_ in sites]
    files["call_sites.tsv"] = "\n".join(lines) + "\n"
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


START_ZERO = "shift of the start index, which every caller passes as 0"
EMPTY_POINTER = "dangling pointer of an empty vector: length 0 means nothing reads it and capacity 0 means nothing frees it"
HEIGHT_EIGHT = "reached only with the low three bits of the height nonzero, so height 8 never arrives and 8 and 9 compare alike"
SECOND_WALK = "the second user walk repeats a walk that just found the same key, so it never reads this height step's result"
REASON_RANGES = ((0x4D63B9B, 0x4D63BE0, LANDING), (0x4883B4D, 0x4883B84, LANDING), (0x42F3962, 0x42F39B0, LANDING))
REASONS = {0x4883A03: START_ZERO, 0x4883AF7: EMPTY_POINTER, 0x4308235: HEIGHT_EIGHT, 0x4308318: HEIGHT_EIGHT, 0x42F3647: SECOND_WALK, 0x42F3658: SECOND_WALK}

if __name__ == "__main__":
    sys.exit(main())
