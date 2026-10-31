#!/usr/bin/env python3
"""Pin the node #94 distribute_funding step from ELF bytes: bucket gate, rate map, per-dex loop, residual and premium reset.

The three copies of the host, the three copies of the rate map builder and the shared per-dex body 0x3703f20 run in a Python
evaluator with their result tree helpers. The per-user worker sits behind the rayon boundary and is replaced by given summary
rows. A separately written specification predicts every stub argument, output row and state word, and every condition, immediate
and field offset is flipped to show the run can tell. No objdump or readelf output is parsed, and the binary is never executed.
Standard library only.
"""

import argparse
import bisect
import datetime
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

WORK = 0x3703F20
COLLECT = 0x3BC9A80
RAYON = 0x38DC6A0
INTO_MAP = 0x33C5500
EXTEND = 0x33077D0
TREE_INSERT = 0x33A5E70
TREE_SPLIT = 0x2F646D0
TO_ROWS = 0x3BB1150
TREE_NEXT = 0x33AF8E0
FLATTEN = 0x3BAFB90
FLATTEN_DROP = 0x3BBB8E0
ENTRY = 0x33BD420
DROP_RATES = 0x33F4660
USER_ROW = 0x3596940
SET_INSERT = 0x339B590
SET_REMOVE = 0x33ACFE0
OI = 0x36F7350
LEV_INDEX = 0x370E6A0
CLOCK = 0x4EE3800
VEC_GROW = 0x32D6A00
ALLOC_FAIL = 0x157A6F0
SERIALIZER = 0x36F59F0
COPIES = (
    dict(name="primary", caller=0x22297C0, host=0x222BEF0, builder=0x275EDA0, insert=0x28502D0, clone=0x289DAB0, drop=0x28A8BE0,
         dex_rows=0x5C0, trackers=0x3370, guard=0x37C0),
    dict(name="second", caller=0x470E9A0, host=0x4715000, builder=0x4D8B730, insert=0x4939FB0, clone=0x49913A0, drop=0x49A9410,
         dex_rows=0x5C0, trackers=0x3370, guard=0x37C0),
    dict(name="recording", caller=0x47162D0, host=0x4712940, builder=0x4D8B9E0, insert=0x4939FB0, clone=0x49913A0, drop=0x49A9410,
         dex_rows=0x1040, trackers=0x3DF0, guard=0x4240),
)
BY_NAME = {copy["name"]: copy for copy in COPIES}
REAL = (WORK, INTO_MAP, EXTEND, TREE_INSERT, TREE_SPLIT, TO_ROWS, TREE_NEXT, FLATTEN, FLATTEN_DROP, ENTRY, ALLOC_FAIL)
SLOT_FREE = 0x576E010
SLOT_ALLOC = 0x576DFD8
SLOT_PANIC = 0x576E470
SLOT_MUL = 0x576E1B0
SLOT_ADD = 0x576E118
SLOT_LOG = 0x5773190
SLOT_MEMCMP = 0x576E488
SLOT_MEMCPY = 0x576DFE0
SLOT_MEMMOVE = 0x576E0E0
SLOT_RATE = 0x5774D48
SLOT_GROW = 0x5773A50
SLOT_WORK = 0x5773A78
SLOT_CONSUMER = 0x5776AD8
SLOT_ONCE = 0x576E8B8
SLOT_STAMP = 0x576E8A0
ROW_MAP = 0x454DD50
WRITER = 0x47ED710
WRITER_TAG = 0x8000000000000005
WRITER_NAME = bytes(range(0x30, 0x48))
ONCE_WORD = 0x577AB98
CONSUMER = 0x4856FC0
LOC_LENGTHS = 0x56E9AC8
LOC_SUM = 0x56F1C50
LOC_SUB = 0x56F1CF8
PANIC_MUL = "multiply"
PANIC_ADD = "add"
STEP_NAME = b"distribute_funding"
NEXT_STEP_NAME = b"update_funding_rates"
GATE_HEAD = b"\x4c\x8b\x6c\x24\x08\x41\x0f\xb6\x85"
EPOCH_ORDINAL = 719163
RAX, RCX, RDX, RBX, RSP, RBP, RSI, RDI, R8, R9, R10, R11, R12, R13, R14, R15 = range(16)
VOLATILE = (RCX, RSI, RDI, R8, R9, R10, R11)
CALLEE_SAVED = (RBX, RBP, R12, R13, R14, R15)
MASK = {1: 0xFF, 2: 0xFFFF, 4: 0xFFFFFFFF, 8: 0xFFFFFFFFFFFFFFFF}
SIGN = {1: 0x80, 2: 0x8000, 4: 0x80000000, 8: 0x8000000000000000}
STACK_MARK = 0xA5
STACK_TOP = 0x7FF000000
STACK_SIZE = 0x4000
HEAP_BASE = 0x600000000
HEAP_SIZE = 0x60000
RETURN_SENTINEL = 0xDEAD0000
POISON = 0xA5A5A5A5A5A5A5A5
STEP_LIMIT = 400000
MUTANT_STEP_LIMIT = 40000
OUT = HEAP_BASE + 0x100
DEX_CONTROL = HEAP_BASE + 0x800
EXCHANGE = HEAP_BASE + 0x1000
DEX_TABLE = HEAP_BASE + 0x6000
DEX_STRIDE = 0x2F0
TRACKER_TABLE = HEAP_BASE + 0x7000
TRACKER_STRIDE = 0x138
BUMP = HEAP_BASE + 0x8000
RATE_ROOT = 0x7100000
RATE_COPY = 0x7200000


class EvidenceError(Exception):
    pass


class Halt(Exception):
    pass


class Panicked(Exception):
    pass


class Finished(Exception):
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
                  (0x55, True): "andnpd", (0x14, True): "unpcklpd", (0x60, True): "punpcklbw", (0x74, True): "pcmpeqb", (0x76, True): "pcmpeqd", (0xDB, True): "andpd",
                  (0xEB, True): "orpd", (0x6C, True): "unpcklpd", (0x58, True): "addpd", (0x59, True): "mulpd", (0x5E, True): "divpd", (0x5F, True): "maxpd"}
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
        if two == 0xC2 and opsize:
            reg, rm = modrm(True)
            value = immediate(1)
            if value != 2:
                raise EvidenceError("unsupported compare predicate at %#x" % va)
            return finish("cmplepd", ("x", reg), rm, 16)
        if two == 0x50 and opsize:
            reg, rm = modrm(True)
            return finish("movmskpd", ("r", reg), rm, 4)
        if two == 0x73 and opsize:
            reg, rm = modrm(True)
            value = immediate(1) & 0xFF
            if reg & 7 != 2:
                raise EvidenceError("unsupported vector shift at %#x" % va)
            return finish("psrlq", rm, ("i", value), 16)
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
        self.call_site = 0

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
                self.call_site = row.va
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
        elif op in ("addpd", "mulpd", "divpd", "maxpd"):
            right = self.vector(row.b)
            left = self.xmm[row.a[1]]
            parts = []
            for at in (0, 64):
                x, y = to_float(left >> at & MASK[8]), to_float(right >> at & MASK[8])
                parts.append(x + y if op == "addpd" else x * y if op == "mulpd" else x / y if op == "divpd" else (x if x > y else y))
            self.xmm[row.a[1]] = to_bits(parts[0]) | to_bits(parts[1]) << 64
        elif op == "cmplepd":
            right = self.vector(row.b)
            left = self.xmm[row.a[1]]
            self.xmm[row.a[1]] = sum((MASK[8] if to_float(left >> at & MASK[8]) <= to_float(right >> at & MASK[8]) else 0) << at for at in (0, 64))
        elif op == "movmskpd":
            source = self.xmm[row.b[1]]
            self.put(row.a, 4, (source >> 63 & 1) | (source >> 127 & 1) << 1)
        elif op == "psrlq":
            source = self.xmm[row.a[1]]
            self.xmm[row.a[1]] = sum(((source >> at & MASK[8]) >> row.b[1]) << at for at in (0, 64))
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



# ---- specification ----

def to_signed(value):
    return value - (1 << 64) if value & SIGN[8] else value


def saturate(value):
    return max(-(1 << 63), min((1 << 63) - 1, value))


def address(tail, first=0xAA):
    return bytes([first] * 19 + [tail])


def unix_millis(date_word, secs, frac):
    """Block time words to Unix milliseconds; the epoch date is ordinal 719163 of the proleptic calendar."""
    signed = date_word - (1 << 32) if date_word & SIGN[4] else date_word
    year = signed >> 13
    ordinal = (date_word >> 4) & 0x1FF
    cycles = 0
    while year < 1:
        year += 400
        cycles += 1
    days = datetime.date(year, 1, 1).toordinal() + ordinal - 1 - cycles * 146097 - EPOCH_ORDINAL
    return days * 86400000 + secs * 1000 + frac // 1000000


def gate_spec(case):
    millis = max(unix_millis(*case["time"]), 0)
    width = case["bucket_millis"]
    if width == 0:
        return dict(fault=True)
    bucket = millis // width
    last = case["last_bucket"]
    return dict(fault=False, run=bucket > last, last=max(bucket, last))


def builder_spec(case):
    """Rows of the map builder: every asset of every paired dex gets its rate or 0.0, in dex then index order."""
    calls, inserted, missing = [], [], []
    if case["trackers"] != len(case["dexes"]):
        calls.append(("log", 5, LOC_LENGTHS))
    for index in range(min(case["trackers"], len(case["dexes"]))):
        dex = case["dexes"][index]
        for slot in range(dex["count"]):
            product = dex["id"] * 10000
            if product >= 1 << 64:
                return dict(calls=calls, panic=PANIC_MUL, inserted=inserted, missing=missing)
            asset = product + slot
            if asset >= 1 << 64:
                return dict(calls=calls, panic=PANIC_ADD, inserted=inserted, missing=missing)
            calls.append(("rate", index, asset))
            rate = dex["rates"].get(asset)
            if rate is None and asset < 10000 and asset not in dex["hl"]:
                missing.append(asset)
            inserted.append((asset, to_bits(rate if rate is not None else 0.0)))
    return dict(calls=calls, panic=None, inserted=inserted, missing=missing)


def worker_spec(dex, once, count_after):
    """Residual step of 0x3703f20 over one dex; summaries are ordered by address before the walk."""
    rows = sorted(dex["summaries"], key=lambda row: row["user"])
    total, calls = 0, []
    for row in rows:
        moved = total + row["sum"]
        if saturate(moved) != moved:
            calls.append(("log", 0, LOC_SUM))
        total = saturate(moved)
    best = None
    for row in rows:
        if row["tag"] == 1 and (best is None or row["max"] > best["max"]):
            best = row
    flat = []
    for row in rows:
        for item in row["rows"]:
            if item[0x3C:0x40] == bytes(4):
                break
            flat.append(item)
    state = {}
    if best is not None and total != 0:
        if once:
            calls.append(("once",))
        user = dex["users"][best["user"]]
        calls.append(("user", best["user"]))
        calls.append(("set", 0x188, best["user"]))
        position = user["positions"][best["asset"]]
        word = position["margin"] if position["isolated"] else user["balance"]
        moved = word - total
        if saturate(moved) != moved:
            calls.append(("log", 0, LOC_SUB))
        if position["isolated"]:
            state["margin"] = (best["user"], best["asset"], saturate(moved))
        else:
            state["balance"] = (best["user"], saturate(moved))
        calls.append(("oi", best["asset"], position["sz"], position["sz"], best["user"]))
        before = user["count"]
        after = before if count_after is None else count_after
        if before and not after:
            calls.append(("remove", 0x158, best["user"]))
        elif after and not before:
            calls.append(("set", 0x158, best["user"]))
    return dict(calls=calls, flat=flat, state=state)


# ---- harness ----

def build_positions(memory, bump, positions):
    """Position B-tree over the sorted assets: one leaf, or a root with one key over two leaves."""
    assets = sorted(positions)
    spots = {}

    def fill(node, keys):
        memory.write(node + 0x322, 2, len(keys))
        for index, asset in enumerate(keys):
            memory.write(node + 0x2C8 + 8 * index, 8, asset)
            row = positions[asset]
            spot = node + 0x40 * index
            memory.write(spot, 4, 1 if row["isolated"] else 0)
            memory.write(spot + 4, 4, row.get("leverage", 10))
            memory.write(spot + 8, 8, row["margin"])
            memory.write(spot + 0x10, 8, row["sz"])
            spots[asset] = spot

    if len(assets) <= 3:
        node = bump(0x328)
        fill(node, assets)
        return node, 0, spots
    middle = len(assets) // 2
    left, right, root = bump(0x328), bump(0x328), bump(0x388)
    fill(left, assets[:middle])
    fill(right, assets[middle + 1:])
    fill(root, assets[middle:middle + 1])
    memory.write(root + 0x328, 8, left)
    memory.write(root + 0x330, 8, right)
    return root, 1, spots


def build_premiums(memory, bump, depth, width):
    """Premium B-tree of the requested depth; returns the root, the (node, index) of each entry and the entry count."""
    entries = []
    key = [0]

    def make(level, parent, slot):
        node = bump(0x1D0 if level else 0x170)
        memory.write(node, 8, parent)
        memory.write(node + 0x168, 2, slot)
        memory.write(node + 0x16A, 2, width)
        for index in range(width):
            if level:
                memory.write(node + 0x170 + 8 * index, 8, make(level - 1, node, index))
            memory.write(node + 8 + 8 * index, 8, key[0])
            memory.write(node + 0x60 + 24 * index, 8, 16)
            memory.write(node + 0x68 + 24 * index, 8, 0x5000 + key[0])
            memory.write(node + 0x70 + 24 * index, 8, 3 + key[0])
            entries.append((node, index))
            key[0] += 1
        if level:
            memory.write(node + 0x170 + 8 * width, 8, make(level - 1, node, width))
        return node

    root = make(depth, 0, 0)
    return root, entries, key[0]


def build_set(memory, bump, keys):
    """Asset set B-tree: one leaf, or a root with one key over two leaves."""
    keys = sorted(keys)

    def leaf(values):
        node = bump(0xC8)
        memory.write(node + 0x62, 2, len(values))
        for index, value in enumerate(values):
            memory.write(node + 8 + 8 * index, 8, value)
        return node

    if len(keys) <= 3:
        return leaf(keys), 0
    left, right, root = leaf(keys[:1]), leaf(keys[2:]), leaf(keys[1:2])
    memory.write(root + 0x68, 8, left)
    memory.write(root + 0x70, 8, right)
    return root, 1


class Harness:
    def __init__(self, image):
        self.image = image
        machine = self.machine = Machine(image)
        real = set(REAL) | {CONSUMER}
        for copy in COPIES:
            real.update((copy["host"], copy["builder"]))
        machine.real = frozenset(real)
        calls = {CLOCK: self.on_clock, COLLECT: self.on_collect, RAYON: self.on_rayon, DROP_RATES: self.on_drop_rates, USER_ROW: self.on_user,
                 SET_INSERT: self.on_set, SET_REMOVE: self.on_remove, OI: self.on_oi, LEV_INDEX: self.on_lev, VEC_GROW: self.on_vec_grow, ROW_MAP: self.on_row_map, WRITER: self.on_writer}
        for copy in COPIES:
            calls[copy["insert"]] = self.on_insert
            calls[copy["clone"]] = self.on_clone
            calls[copy["drop"]] = self.on_drop
        machine.calls = calls
        tokens = {SLOT_FREE: self.on_free, SLOT_ALLOC: self.on_alloc, SLOT_PANIC: self.on_panic, SLOT_MUL: self.on_mul, SLOT_ADD: self.on_add,
                  SLOT_LOG: self.on_log, SLOT_MEMCMP: self.on_memcmp, SLOT_RATE: self.on_rate, SLOT_GROW: self.on_grow, SLOT_STAMP: self.on_stamp,
                  SLOT_ONCE: self.on_once, SLOT_MEMCPY: self.on_memcpy, SLOT_MEMMOVE: self.on_memcpy}
        for at, (slot, hook) in enumerate(tokens.items()):
            token = 0x7000000 + at * 16
            machine.memory.statics[slot] = token
            machine.slots[token] = hook
        machine.memory.statics[SLOT_WORK] = WORK
        machine.memory.statics[SLOT_CONSUMER] = CONSUMER
        self.case = None
        self.calls = []
        self.at = BUMP
        self.layout = COPIES[0]
        self.clock = 0
        self.vec_frees = []
        self.host_frees = []
        self.seen_rows = []
        self.inserted = []
        self.state_dexes = []
        self.users = {}
        self.spots = {}
        self.premiums = {}
        self.after = None
        self.gate = None
        self.spans = {}
        self.consumer_span = image.exact_fde(CONSUMER)
        self.consumer_frees = 0
        for copy in COPIES:
            self.spans[copy["name"]] = (image.exact_fde(copy["host"]), image.exact_fde(copy["builder"]))

    def bump(self, size):
        here = self.at
        self.at += (size + 15) & ~15
        if self.at >= HEAP_BASE + HEAP_SIZE:
            raise Halt("heap exhausted")
        return here

    def begin(self, case, layout):
        memory = self.machine.memory
        memory.reset()
        self.case = case
        self.layout = layout
        self.calls = []
        self.at = BUMP
        self.clock = 0
        self.vec_frees = []
        self.host_frees = []
        self.seen_rows = []
        self.inserted = []
        self.consumer_frees = 0
        self.machine.call_site = 0
        memory.statics[ONCE_WORD] = 3 if case.get("once") else 0

    def dex_of(self, pointer):
        return (pointer - DEX_TABLE) // DEX_STRIDE

    # edge hooks

    def on_alloc(self, machine):
        machine.regs[RAX] = self.bump(machine.regs[RDI])

    def on_free(self, machine):
        size = machine.regs[RSI]
        site = machine.call_site
        host, builder = self.spans[self.layout["name"]]
        if host[0] <= site < host[1] and size and size % 0x48 == 0:
            self.host_frees.append(size)
        if self.consumer_span[0] <= site < self.consumer_span[1] and size % 0x48 == 0:
            self.consumer_frees += 1
        if builder[0] <= site < builder[1] and size and size % 8 == 0:
            used = machine.memory.read(machine.regs[RSP] + 0x18, 8)
            self.vec_frees.append(machine.memory.bytes_at(machine.regs[RDI], 8 * used))

    def on_panic(self, machine):
        raise Panicked(machine.regs[RDI])

    def on_mul(self, machine):
        raise Panicked(PANIC_MUL)

    def on_add(self, machine):
        raise Panicked(PANIC_ADD)

    def on_log(self, machine):
        self.calls.append(("log", machine.regs[RDI] & MASK[4], machine.regs[RSI]))

    def on_once(self, machine):
        self.calls.append(("once",))

    def on_memcmp(self, machine):
        regs, memory = machine.regs, machine.memory
        left = memory.bytes_at(regs[RDI], regs[RDX])
        right = memory.bytes_at(regs[RSI], regs[RDX])
        regs[RAX] = 0 if left == right else (1 if left > right else MASK[4])

    def on_memcpy(self, machine):
        regs = machine.regs
        machine.memory.copy(regs[RDI], regs[RSI], regs[RDX])
        regs[RAX] = regs[RDI]

    def on_clock(self, machine):
        if machine.regs[RDI] & MASK[4] != 1:
            raise Halt("clock argument")
        self.clock += 1
        if self.clock == 2:
            raise Finished()
        machine.regs[RAX] = 0x1234
        machine.regs[RDX] = 5
        machine.keep_rdx = True

    def on_rate(self, machine):
        regs = machine.regs
        index = (regs[RDI] - 0x48 - TRACKER_TABLE) // TRACKER_STRIDE
        if regs[RDI] != TRACKER_TABLE + TRACKER_STRIDE * index + 0x48:
            raise Halt("tracker argument")
        self.calls.append(("rate", index, regs[RSI]))
        rate = self.case["dexes"][index]["rates"].get(regs[RSI])
        regs[RAX] = 0x4400 if rate is None else 0x4401
        machine.xmm[0] = POISON if rate is None else to_bits(rate)
        machine.keep_float = True

    def on_insert(self, machine):
        regs, memory = machine.regs, machine.memory
        target = regs[RDI]
        count = memory.read(target + 16, 8)
        self.inserted.append((regs[RSI], machine.xmm[0] & MASK[8]))
        memory.write(target, 8, RATE_ROOT)
        memory.write(target + 8, 8, 0)
        memory.write(target + 16, 8, count + 1)

    def on_grow(self, machine):
        regs, memory = machine.regs, machine.memory
        vector = regs[RDI]
        capacity, data = memory.read(vector, 8), memory.read(vector + 8, 8)
        wider = max(4, capacity * 2)
        fresh = self.bump(8 * wider)
        if capacity:
            memory.copy(fresh, data, 8 * capacity)
        memory.write(vector, 8, wider)
        memory.write(vector + 8, 8, fresh)

    def on_vec_grow(self, machine):
        regs, memory = machine.regs, machine.memory
        vector, used, extra, element = regs[RDI], regs[RSI], regs[RDX], regs[R8]
        capacity, data = memory.read(vector, 8), memory.read(vector + 8, 8)
        wider = max(4, capacity * 2, used + extra)
        fresh = self.bump(element * wider)
        if capacity:
            memory.copy(fresh, data, element * capacity)
        memory.write(vector, 8, wider)
        memory.write(vector + 8, 8, fresh)

    def on_clone(self, machine):
        regs, memory = machine.regs, machine.memory
        self.calls.append(("clone", regs[RSI], regs[RDX]))
        out = regs[RDI]
        memory.write(out, 8, RATE_COPY)
        memory.write(out + 8, 8, 0)
        memory.write(out + 16, 8, 1)

    def on_drop(self, machine):
        self.calls.append(("drop",))

    def on_drop_rates(self, machine):
        self.calls.append(("drop rates", machine.memory.read(machine.regs[RDI], 8), machine.memory.read(machine.regs[RDI] + 16, 8)))

    def on_collect(self, machine):
        regs, memory = machine.regs, machine.memory
        iterator = regs[RSI]
        control = memory.read(iterator, 8)
        self.calls.append(("collect", (control - DEX_CONTROL) // 0x20, memory.read(iterator + 8, 8) - control, memory.read(iterator + 16, 8) - control, memory.read(iterator + 32, 8)))
        out = regs[RDI]
        memory.write(out, 8, 1)
        memory.write(out + 8, 8, 0x5400)
        memory.write(out + 16, 8, 7)

    def on_rayon(self, machine):
        regs, memory = machine.regs, machine.memory
        words = memory.read(regs[RDX], 8)
        ch = memory.read(words, 8) - 0x158
        dex = self.dex_of(ch)
        marks = tuple(memory.read(words + 8 * index, 8) for index in (0, 1, 3, 4))
        if marks[:3] != (ch + 0x158, ch + 0x1A0, ch + 0x60):
            raise Halt("closure capture")
        taken = memory.bytes_at(memory.read(words + 16, 8), 12)
        self.calls.append(("rayon", dex, taken, memory.read(marks[3], 8), memory.read(regs[RSI] + 8, 8), memory.read(regs[RSI] + 16, 8), regs[RCX]))
        spec = self.state_dexes[dex]
        rows = spec["summaries"]
        chunks = spec.get("chunks", 1)
        heads = []
        for part in range(chunks):
            take = rows[part::chunks]
            data = self.bump(max(len(take), 1) * 0x68)
            for index, row in enumerate(take):
                at = data + 0x68 * index
                memory.put_bytes(at, row["user"] + bytes(4))
                vector = 0
                if row["rows"]:
                    vector = self.bump(0x48 * len(row["rows"]))
                    for slot, item in enumerate(row["rows"]):
                        memory.put_bytes(vector + 0x48 * slot, item)
                memory.write(at + 0x18, 8, len(row["rows"]))
                memory.write(at + 0x20, 8, vector or 8)
                memory.write(at + 0x28, 8, len(row["rows"]))
                memory.write(at + 0x30, 8, row["sum"])
                memory.write(at + 0x38, 8, row["tag"])
                memory.write(at + 0x40, 8, row["asset"])
                memory.write(at + 0x48, 8, row["max"])
                memory.put_bytes(at + 0x50, row["user"] + bytes(4))
            node = self.bump(0x28)
            memory.write(node, 8, len(take) or 1)
            memory.write(node + 8, 8, data)
            memory.write(node + 16, 8, len(take))
            heads.append(node)
        for index, node in enumerate(heads):
            memory.write(node + 0x18, 8, heads[index + 1] if index + 1 < len(heads) else 0)
            memory.write(node + 0x20, 8, heads[index - 1] if index else 0)
        out = regs[RDI]
        memory.write(out, 8, heads[0])
        memory.write(out + 8, 8, heads[-1])
        memory.write(out + 16, 8, len(heads))

    def on_user(self, machine):
        regs, memory = machine.regs, machine.memory
        dex = self.dex_of(regs[RDI] - 0xF8)
        if regs[RDI] != DEX_TABLE + dex * DEX_STRIDE + 0xF8:
            raise Halt("user map argument")
        user = memory.bytes_at(regs[RSI], 20)
        self.calls.append(("user", user))
        regs[RAX] = self.users[dex, user]

    def on_set(self, machine):
        regs, memory = machine.regs, machine.memory
        dex = self.dex_of(regs[RDI])
        self.calls.append(("set", regs[RDI] - DEX_TABLE - dex * DEX_STRIDE, memory.bytes_at(regs[RSI], 20)))

    def on_remove(self, machine):
        regs, memory = machine.regs, machine.memory
        dex = self.dex_of(regs[RDI])
        self.calls.append(("remove", regs[RDI] - DEX_TABLE - dex * DEX_STRIDE, memory.bytes_at(regs[RSI], 20)))

    def on_oi(self, machine):
        regs, memory = machine.regs, machine.memory
        dex = self.dex_of(regs[R8])
        if regs[R8] != DEX_TABLE + dex * DEX_STRIDE + 0x170:
            raise Halt("open interest map")
        owner = [key[1] for key, row in self.users.items() if key[0] == dex and row + 0x20 == regs[RCX]]
        self.calls.append(("oi", regs[RDI], to_signed(regs[RSI]), to_signed(regs[RDX]), owner[0] if owner else None))
        if self.after is not None:
            memory.write(regs[RCX], 8, self.after)

    def on_lev(self, machine):
        self.calls.append(("lev",))

    def on_stamp(self, machine):
        self.calls.append(("stamp",))

    def on_row_map(self, machine):
        regs, memory = machine.regs, machine.memory
        iterator = regs[RSI]
        begin, finish = memory.read(iterator + 8, 8), memory.read(iterator + 24, 8)
        count = (finish - begin) // 0x48
        taken = memory.bytes_at(regs[RSP] + 8 + 0x148, 12)
        self.calls.append(("consumer", taken, self.dex_of(memory.read(iterator + 32, 8))))
        self.seen_rows.append([memory.bytes_at(begin + 0x48 * index, 0x48) for index in range(count)])

    def on_writer(self, machine):
        regs, memory = machine.regs, machine.memory
        self.calls.append(("writer", regs[RDI] - EXCHANGE, regs[RSI] & 0xFF, memory.read(regs[RCX], 8), memory.bytes_at(regs[R8], 24)))

    def on_gate_host(self, machine):
        regs, memory = machine.regs, machine.memory
        step = regs[RDI]
        self.gate = dict(name=memory.bytes_at(memory.read(step, 8), memory.read(step + 8, 8)), low=memory.read(step + 16, 8), high=memory.read(step + 24, 8),
                         run=memory.read(step + 32, 1), exchange=regs[RSI], byte=memory.read(regs[RDX], 1))
        raise Finished()

    # fixtures

    def lay_exchange(self, case, layout):
        memory = self.machine.memory
        memory.put_bytes(EXCHANGE + 0x60, struct.pack("<III", *case["time"]))
        dexes = case["dexes"]
        memory.write(EXCHANGE + layout["dex_rows"], 8, DEX_TABLE)
        memory.write(EXCHANGE + layout["dex_rows"] + 8, 8, len(dexes))
        memory.write(EXCHANGE + layout["trackers"], 8, TRACKER_TABLE)
        memory.write(EXCHANGE + layout["trackers"] + 8, 8, case["trackers"])
        memory.write(EXCHANGE + 0x5B8 + 0x808, 8, 1 << 63 if case.get("no_writer") else 0x44)
        memory.write(EXCHANGE + 0x5B8 + 0xA78, 1, 0x3A)
        memory.put_bytes(EXCHANGE + 0x5B8 + 0xA60, WRITER_NAME)
        self.spots = {}
        self.users = {}
        self.premiums = {}
        self.state_dexes = dexes
        self.after = case.get("count_after")
        for index in range(max(len(dexes), case["trackers"])):
            tracker = TRACKER_TABLE + index * TRACKER_STRIDE
            premium = dexes[index].get("premiums") if index < len(dexes) else None
            memory.write(tracker + 0xD8, 8, 0)
            memory.write(tracker + 0xE0, 8, 0)
            memory.write(tracker + 0xE8, 8, 0)
            if premium is not None:
                node, entries, total = build_premiums(memory, self.bump, *premium)
                memory.write(tracker + 0xD8, 8, node)
                memory.write(tracker + 0xE0, 8, premium[0])
                memory.write(tracker + 0xE8, 8, total)
                self.premiums[index] = entries
        for index, dex in enumerate(dexes):
            ch = DEX_TABLE + index * DEX_STRIDE
            memory.write(ch + 0x10, 8, dex["count"])
            memory.write(ch + 0x30, 8, dex["id"])
            root, height = build_set(memory, self.bump, dex["hl"]) if dex["hl"] else (0, 0)
            memory.write(ch + 0x270, 8, root)
            memory.write(ch + 0x278, 8, height)
            control = DEX_CONTROL + 0x20 * index
            memory.put_bytes(control, bytes([0x80] * 16))
            memory.write(ch + 0xF8, 8, control)
            memory.write(ch + 0x100, 8, 15)
            memory.write(ch + 0x110, 8, len(dex.get("users", ())))
            for user, row in dex.get("users", {}).items():
                block = self.bump(0x30)
                memory.write(block, 8, row["balance"])
                node, level, spots = build_positions(memory, self.bump, row["positions"])
                memory.write(block + 8, 8, node)
                memory.write(block + 0x10, 8, level)
                memory.write(block + 0x18, 8, 0)
                memory.write(block + 0x20, 8, row["count"])
                self.users[index, user] = block
                self.spots[index, user] = spots

    # runs

    def run_gate(self, case, layout):
        machine, memory = self.machine, self.machine.memory
        self.begin(case, layout)
        memory.put_bytes(EXCHANGE + 0x60, struct.pack("<III", *case["time"]))
        memory.write(EXCHANGE + layout["guard"], 8, case["bucket_millis"])
        memory.write(EXCHANGE + layout["guard"] + 8, 8, case["last_bucket"])
        memory.write(EXCHANGE + layout["network_byte"], 1, 0x5C)
        memory.write(STACK_TOP - 0x100, 8, EXCHANGE)
        self.gate = None
        saved = machine.calls
        machine.calls = dict(saved)
        machine.calls[layout["host"]] = self.on_gate_host
        real = machine.real
        machine.real = frozenset(real - {layout["host"]})
        try:
            machine.run(layout["gate"], {})
        except Finished:
            pass
        finally:
            machine.calls = saved
            machine.real = real
        return self.gate, memory.read(EXCHANGE + layout["guard"] + 8, 8)

    def run_builder(self, case, layout):
        machine = self.machine
        self.begin(case, layout)
        self.lay_exchange(case, layout)
        machine.memory.write(OUT + 16, 8, POISON)
        machine.run(layout["builder"], {RDI: OUT, RSI: EXCHANGE})
        return [machine.memory.read(OUT + 8 * index, 8) for index in range(3)]

    def run_worker(self, case):
        machine, memory = self.machine, self.machine.memory
        self.begin(case, COPIES[0])
        self.lay_exchange(case, COPIES[0])
        time_at = self.bump(16)
        memory.put_bytes(time_at, struct.pack("<III", *case["time"]))
        map_at = self.bump(32)
        memory.write(map_at, 8, RATE_COPY)
        memory.write(map_at + 16, 8, 1)
        machine.run(WORK, {RDI: OUT, RSI: DEX_TABLE, RDX: 0x77, RCX: time_at, R8: map_at})
        length = memory.read(OUT + 16, 8)
        data = memory.read(OUT + 8, 8)
        return [memory.bytes_at(data + 0x48 * index, 0x48) for index in range(length)]

    def run_host(self, case, layout):
        machine, memory = self.machine, self.machine.memory
        self.begin(case, layout)
        self.lay_exchange(case, layout)
        step = self.bump(0x28)
        memory.write(step + 0x20, 1, case.get("flag", 1))
        arg = self.bump(8)
        memory.write(arg, 1, 9)
        try:
            machine.run(layout["host"], {RDI: step, RSI: EXCHANGE, RDX: arg})
        except Finished:
            pass

    def read_balance(self, dex, user):
        return to_signed(self.machine.memory.read(self.users[dex, user], 8))

    def read_margin(self, dex, user, asset):
        return to_signed(self.machine.memory.read(self.spots[dex, user][asset] + 8, 8))


def layout_gates(image):
    """Find each bucket gate in front of its direct host call and fill in the copy table."""
    base, text = image.text_bytes()
    for layout in COPIES:
        begin, end = image.exact_fde(layout["caller"])
        at = text.find(b"\xe8", begin - base)
        site = None
        while 0 <= at < end - base:
            if base + at + 5 + struct.unpack_from("<i", text, at + 1)[0] == layout["host"]:
                site = base + at
                break
            at = text.find(b"\xe8", at + 1)
        if site is None:
            raise EvidenceError("host call not found")
        window = text[site - base - 0x180:site - base]
        start = window.rfind(GATE_HEAD)
        if start < 0:
            raise EvidenceError("gate head not found")
        layout["gate"] = site - 0x180 + start
        layout["gate_end"] = site + 5
        layout["network_byte"] = struct.unpack_from("<i", window, start + len(GATE_HEAD))[0]


# ---- cases ----

def plain_user(balance=1000, sz=500, margin=0, isolated=False, asset=3, count=1, extra=None):
    positions = {asset: dict(isolated=isolated, margin=margin, sz=sz)}
    positions.update(extra or {})
    return dict(balance=balance, positions=positions, count=count)


def row_bytes(mark, word=7):
    item = bytearray((mark + at) & 0xFF for at in range(0x48))
    item[0x3C:0x40] = struct.pack("<I", word)
    return bytes(item)


def summary(user, value, largest, asset=3, tag=1, rows=None):
    return dict(user=user, sum=value, tag=tag, asset=asset, max=largest, rows=[row_bytes(user[-1])] if rows is None else rows)


TIME = (2024 << 13 | 1 << 4 | 0x8, 3600, 5000000)


def work_case(label, summaries, users, chunks=1, **fields):
    dex = dict(count=0, id=0, rates={}, hl=(), summaries=summaries, users=users, chunks=chunks)
    return dict(kind="work", label=label, dexes=[dex], trackers=1, time=TIME, **fields)


def gate_cases():
    rows = []
    hour = 3600000
    base = (2024 << 13 | 60 << 4 | 2, 7200, 0)
    start = unix_millis(*base)
    for label, time, width, last in (
        ("first bucket after a large gap", base, hour, 0),
        ("same bucket", base, hour, start // hour),
        ("one bucket on", base, hour, start // hour - 1),
        ("last bucket ahead of the clock", base, hour, start // hour + 5),
        ("millisecond below the boundary", (base[0], 7199, 999999999), hour, start // hour - 1),
        ("leap frac past one second", (base[0], 86399, 1500000000), 1000, 0),
        ("sub-millisecond frac drops", (base[0], 0, 999999), 1, 0),
        ("wide bucket takes the 64-bit divide", base, 1 << 33, 0),
        ("small clock takes the 32-bit divide", (1970 << 13 | 1 << 4, 30, 0), 1000, 3),
        ("small clock at the guard", (1970 << 13 | 1 << 4, 3, 0), 1000, 3),
        ("before the epoch clamps to zero", (1969 << 13 | 1 << 4, 0, 0), hour, 0),
        ("epoch exactly", (1970 << 13 | 1 << 4, 0, 0), hour, 0),
        ("frac is an exact millisecond", (base[0], 0, 123000000), 1, 0),
        ("frac of exactly one millisecond", (base[0], 0, 1000000), 1, 0),
        ("clock just past 32 bits", (1970 << 13 | 51 << 4, 0, 0), 1000, 0),
        ("year after a century", (2001 << 13 | 1 << 4, 0, 0), hour, 0),
        ("year after a plain century", (2101 << 13 | 1 << 4, 0, 0), hour, 0),
        ("year after a 400-year cycle", (2001 << 13 | 365 << 4, 86399, 0), hour, 0),
        ("year -1 takes the 400-year shift", ((-1 << 13) & MASK[4] | 1 << 4, 0, 0), hour, 0),
        ("zero width with a 32-bit clock", (1970 << 13 | 1 << 4, 5, 0), 0, 0),
        ("zero width with a 64-bit clock", base, 0, 0),
    ):
        for layout in COPIES:
            rows.append(dict(kind="gate", label=label, copy=layout["name"], time=time, bucket_millis=width, last_bucket=last))
    return rows


def builder_dex(count, ident=0, rates=None, hl=()):
    return dict(count=count, id=ident, rates=rates or {}, hl=tuple(hl))


def builder_cases():
    rows = []
    for label, dexes, trackers in (
        ("no dexes", [], 0),
        ("one dex, all rates", [builder_dex(3, 0, {0: 0.00125, 1: -0.0001, 2: 0.04})], 1),
        ("None below 10000, not listed", [builder_dex(2, 0, {1: 0.5})], 1),
        ("None below 10000, listed", [builder_dex(3, 0, {1: 0.5}, (0, 2))], 1),
        ("None at a later list key", [builder_dex(5, 0, {}, (1, 2, 3, 4))], 1),
        ("None with a key above the list", [builder_dex(3, 0, {}, (7,))], 1),
        ("zero rate is not None", [builder_dex(1, 0, {0: 0.0})], 1),
        ("second dex, None is above 9999", [builder_dex(1, 0, {0: 0.25}), builder_dex(2, 1, {10001: 0.5})], 2),
        ("zero asset count", [builder_dex(0, 0), builder_dex(1, 2, {20000: 1.5})], 2),
        ("fewer trackers than dexes", [builder_dex(1), builder_dex(1, 1)], 1),
        ("more trackers than dexes", [builder_dex(1)], 2),
        ("dex id multiply overflow", [builder_dex(1, 1 << 62)], 1),
        ("dex id add overflow", [builder_dex(3, (1 << 64) // 10000)], 1),
        ("vector grows past four", [builder_dex(6, 0)], 1),
    ):
        for layout in COPIES:
            rows.append(dict(kind="builder", label=label, copy=layout["name"], dexes=dexes, trackers=trackers, time=TIME))
    return rows


def work_cases():
    a, b, c, d, e = (address(tail) for tail in (1, 2, 3, 4, 5))
    high, low = address(0x10, 0xFF), address(0xF0, 0x01)
    many = tuple(address(40 - 3 * n) for n in range(12))
    wider = tuple(address(200 - 7 * n) for n in range(20))
    widest = tuple(address((n * 37) % 251) for n in range(40))
    tree = {x: dict(isolated=x == 7, margin=8, sz=2) for x in (5, 6, 7)}
    return [
        work_case("no users", [], {}),
        work_case("no row carries a position", [summary(a, 0, 0, tag=0, rows=[])], {a: plain_user()}),
        work_case("sum is zero", [summary(a, 100, 50), summary(b, -100, 900)], {a: plain_user(), b: plain_user()}),
        work_case("sum is zero, rows still flatten", [summary(a, 7, 50, rows=[row_bytes(1), row_bytes(2)]), summary(b, -7, 9, rows=[row_bytes(3)])], {a: plain_user(), b: plain_user()}),
        work_case("positive residual, cross", [summary(a, 100, 50), summary(b, -99, 900)], {a: plain_user(), b: plain_user(5000)}),
        work_case("negative residual, cross", [summary(a, 100, 900), summary(b, -101, 50)], {a: plain_user(40), b: plain_user()}),
        work_case("positive residual, isolated", [summary(a, 1, 50), summary(b, 1, 900)], {a: plain_user(), b: plain_user(777, margin=400, isolated=True)}),
        work_case("negative residual, isolated keeps balance", [summary(a, -5, 900)], {a: plain_user(777, margin=400, isolated=True)}),
        work_case("first of equal maxima wins", [summary(a, 1, 900), summary(b, 1, 900)], {a: plain_user(), b: plain_user()}),
        work_case("equal maxima, third row larger", [summary(a, 1, 900), summary(b, 1, 900), summary(c, 1, 901)], {a: plain_user(), b: plain_user(), c: plain_user()}),
        work_case("largest in the second of a pair", [summary(a, 1, 1), summary(b, 1, 2), summary(c, 1, 3), summary(d, 1, 2)], {u: plain_user() for u in (a, b, c, d)}),
        work_case("largest in the first of a pair", [summary(a, 1, 1), summary(b, 1, 2), summary(c, 1, 9), summary(d, 1, 2), summary(e, 1, 3)], {u: plain_user() for u in (a, b, c, d, e)}),
        work_case("tail row is largest", [summary(a, 1, 1), summary(b, 1, 2), summary(c, 1, 3)], {u: plain_user() for u in (a, b, c)}),
        work_case("tail row has no position", [summary(a, 1, 1), summary(b, 1, 2), summary(c, 1, 3, tag=0)], {u: plain_user() for u in (a, b, c)}),
        work_case("tag 0 first of a pair", [summary(a, 1, 99, tag=0), summary(b, 1, 2), summary(c, 1, 1)], {u: plain_user() for u in (a, b, c)}),
        work_case("tag 0 second of a pair", [summary(a, 1, 2), summary(b, 1, 99, tag=0), summary(c, 1, 1), summary(d, 1, 1)], {u: plain_user() for u in (a, b, c, d)}),
        work_case("tag 0 row still counts in the sum", [summary(a, 5, 2), summary(b, 7, 99, tag=0)], {a: plain_user(), b: plain_user()}),
        work_case("max compare is unsigned", [summary(a, 1, 1 << 63), summary(b, 1, 5)], {a: plain_user(), b: plain_user()}),
        work_case("first row with max 0 is taken", [summary(a, 1, 0)], {a: plain_user()}),
        work_case("sum overflows up", [summary(a, (1 << 63) - 1, 1), summary(b, 5, 2), summary(c, 1, 3)], {u: plain_user() for u in (a, b, c)}),
        work_case("sum falls after saturating", [summary(a, (1 << 63) - 1, 1), summary(b, 5, 2), summary(c, -10, 3), summary(d, -7, 3)], {u: plain_user() for u in (a, b, c, d)}),
        work_case("sum overflows down", [summary(a, -(1 << 63), 1), summary(b, -5, 2)], {a: plain_user(), b: plain_user()}),
        work_case("balance subtract saturates down", [summary(a, 10, 1)], {a: plain_user(-(1 << 63) + 3)}),
        work_case("balance subtract saturates up", [summary(a, -10, 1)], {a: plain_user((1 << 63) - 3)}),
        work_case("margin subtract saturates down", [summary(a, 10, 1)], {a: plain_user(margin=-(1 << 63) + 3, isolated=True)}),
        work_case("margin subtract saturates up", [summary(a, -10, 1)], {a: plain_user(margin=(1 << 63) - 3, isolated=True)}),
        work_case("address order is unsigned bytes", [summary(high, 1, 7), summary(low, 1, 7)], {high: plain_user(), low: plain_user()}),
        work_case("address order beats input order", [summary(c, 1, 7), summary(a, 1, 7), summary(b, 1, 7)], {u: plain_user() for u in (a, b, c)}),
        work_case("rows from two chunks", [summary(c, 1, 7), summary(a, 1, 7), summary(b, 1, 7), summary(d, 2, 8)], {u: plain_user() for u in (a, b, c, d)}, chunks=2),
        work_case("rows from three chunks", [summary(e, 1, 7), summary(a, 1, 7), summary(b, 1, 7), summary(d, 2, 8), summary(c, 3, 9)], {u: plain_user() for u in (a, b, c, d, e)}, chunks=3),
        work_case("empty chunk", [summary(a, 1, 7)], {a: plain_user()}, chunks=2),
        work_case("position in a left leaf", [summary(a, 9, 7, asset=1)], {a: plain_user(asset=1, extra=tree)}),
        work_case("position in a right leaf", [summary(a, 9, 7, asset=7)], {a: plain_user(asset=1, extra=tree)}),
        work_case("position at the root key", [summary(a, 9, 7, asset=6)], {a: plain_user(asset=1, extra=tree)}),
        work_case("position past a smaller key", [summary(a, 9, 7, asset=5)], {a: plain_user(asset=1, extra={2: dict(isolated=True, margin=8, sz=2), 5: dict(isolated=False, margin=8, sz=2)})}),
        work_case("negative size passes through", [summary(a, 3, 7)], {a: plain_user(sz=-500)}),
        work_case("count falls to zero", [summary(a, 3, 7)], {a: plain_user()}, count_after=0),
        work_case("count rises from zero", [summary(a, 3, 7)], {a: plain_user(count=0)}, count_after=2),
        work_case("count stays above zero, changed", [summary(a, 3, 7)], {a: plain_user(count=2)}, count_after=1),
        work_case("process once word still set", [summary(a, 3, 7)], {a: plain_user()}, once=True),
        work_case("once word stays unread without a residual", [summary(a, 0, 7)], {a: plain_user()}, once=True),
        work_case("many rows grow the output", [summary(a, 0, 7, rows=[row_bytes(x) for x in range(3)]), summary(b, 0, 7, rows=[row_bytes(x) for x in range(3, 9)]), summary(c, 0, 7, rows=[row_bytes(9)])], {u: plain_user() for u in (a, b, c)}),
        work_case("row with zero time word ends its vector", [summary(a, 0, 7, rows=[row_bytes(1), row_bytes(2, 0), row_bytes(3)]), summary(b, 0, 7, rows=[row_bytes(4)])], {a: plain_user(), b: plain_user()}),
        work_case("first row of the first vector ends it", [summary(a, 0, 7, rows=[row_bytes(1, 0), row_bytes(2)]), summary(b, 0, 7, rows=[row_bytes(4)]), summary(c, 0, 7, rows=[row_bytes(5)])], {u: plain_user() for u in (a, b, c)}),
        work_case("empty vector between rows", [summary(a, 0, 7, rows=[]), summary(b, 0, 7, rows=[row_bytes(4)]), summary(c, 0, 7, rows=[]), summary(d, 0, 7, rows=[row_bytes(5)])], {u: plain_user() for u in (a, b, c, d)}),
        work_case("twelve users split the row tree", [summary(u, 1, n) for n, u in enumerate(many)], {u: plain_user() for u in many}),
        work_case("twenty users split twice", [summary(u, 1, 3) for u in wider], {u: plain_user() for u in wider}),
        work_case("forty users grow the row tree", [summary(u, 1, n % 5) for n, u in enumerate(widest)], {u: plain_user() for u in widest}, chunks=4),
    ]


def host_dex(index, rates, count, summaries, users, premiums=None, chunks=1):
    return dict(count=count, id=index, rates=rates, hl=(), summaries=summaries, users=users, premiums=premiums, chunks=chunks)


def host_cases():
    rows = []
    a, b = address(1), address(2)
    residual = ([summary(a, 5, 9)], {a: plain_user()})
    for label, dexes, trackers, fields in (
        ("step flag clear", [host_dex(0, {0: 0.5}, 1, *residual)], 1, dict(flag=0)),
        ("step flag 2", [host_dex(0, {0: 0.5}, 1, *residual)], 1, dict(flag=2)),
        ("no dexes", [], 0, {}),
        ("one dex, residual", [host_dex(0, {0: 0.5}, 1, *residual, premiums=(0, 3))], 1, {}),
        ("one dex, no rows", [host_dex(0, {0: 0.5}, 1, [], {}, premiums=(0, 3))], 1, {}),
        ("no assets, empty rate map", [host_dex(0, {}, 0, [], {}, premiums=(0, 2))], 1, {}),
        ("premium tree depth 1", [host_dex(0, {0: 0.5}, 1, [], {}, premiums=(1, 2))], 1, {}),
        ("premium tree depth 2", [host_dex(0, {0: 0.5}, 1, [], {}, premiums=(2, 2))], 1, {}),
        ("no premium tree", [host_dex(0, {0: 0.5}, 1, [], {}, premiums=None)], 1, {}),
        ("two dexes", [host_dex(0, {0: 0.5}, 1, *residual, premiums=(1, 1)), host_dex(1, {10000: 0.25}, 1, [summary(b, -3, 4)], {b: plain_user(9)}, premiums=(0, 1))], 2, {}),
        ("second dex has no tracker", [host_dex(0, {0: 0.5}, 1, *residual, premiums=(0, 1)), host_dex(1, {}, 1, [], {}, premiums=(0, 1))], 1, {}),
        ("second tracker has no dex", [host_dex(0, {0: 0.5}, 1, *residual, premiums=(0, 1))], 2, {}),
        ("no row writer", [host_dex(0, {0: 0.5}, 1, *residual, premiums=(0, 1))], 1, dict(no_writer=True)),
        ("no row writer, no rows", [host_dex(0, {0: 0.5}, 1, [], {}, premiums=(0, 1))], 1, dict(no_writer=True)),
    ):
        for layout in COPIES:
            rows.append(dict(kind="host", label=label, copy=layout["name"], dexes=dexes, trackers=trackers, time=TIME, **fields))
    return rows


def all_cases():
    return gate_cases() + builder_cases() + work_cases() + host_cases()


# ---- comparison ----

def compare_builder(harness, case, layout):
    want = builder_spec(case)
    got_panic = None
    words = None
    try:
        words = harness.run_builder(case, layout)
    except Panicked as stop:
        got_panic = stop.args[0]
    if got_panic != want["panic"]:
        return "panic %r wanted %r" % (got_panic, want["panic"])
    if harness.calls != want["calls"]:
        return "calls %r wanted %r" % (harness.calls[:6], want["calls"][:6])
    if harness.inserted != want["inserted"]:
        return "inserted %r wanted %r" % (harness.inserted[:6], want["inserted"][:6])
    if want["panic"] is not None:
        return ""
    held = [struct.unpack_from("<Q", blob, 8 * at)[0] for blob in harness.vec_frees for at in range(len(blob) // 8)]
    if held != want["missing"]:
        return "dropped vector %r wanted %r" % (held, want["missing"])
    if want["inserted"] and words != [RATE_ROOT, 0, len(want["inserted"])] or not want["inserted"] and (words[0], words[2]) != (0, 0):
        return "map words %r" % (words,)
    return ""


def worker_expected(case, dex_index):
    dex = case["dexes"][dex_index]
    spec = worker_spec(dex, case.get("once"), case.get("count_after"))
    head = [("collect", dex_index, 16, 16, len(dex["users"])), ("rayon", dex_index, struct.pack("<III", *case["time"]), None, 0x5400, 7, 7)]
    return head, spec


def compare_state(harness, case, dex_index, spec):
    dex = case["dexes"][dex_index]
    state = spec["state"]
    for user, row in dex["users"].items():
        balance = state["balance"][1] if "balance" in state and state["balance"][0] == user else row["balance"]
        got = harness.read_balance(dex_index, user)
        if got != balance:
            return "balance %d wanted %d" % (got, balance)
        for asset, position in row["positions"].items():
            margin = position["margin"]
            if "margin" in state and state["margin"][:2] == (user, asset):
                margin = state["margin"][2]
            got = harness.read_margin(dex_index, user, asset)
            if got != margin:
                return "margin %d wanted %d" % (got, margin)
            if to_signed(harness.machine.memory.read(harness.spots[dex_index, user][asset] + 0x10, 8)) != position["sz"]:
                return "size moved"
    return ""


def trim(calls):
    return [call[:3] + (None,) + call[4:] if call[0] == "rayon" else call for call in calls]


def compare_worker(harness, case):
    head, spec = worker_expected(case, 0)
    flat = harness.run_worker(case)
    wanted = head + spec["calls"] + [("drop rates", RATE_COPY, 1)]
    got = trim(harness.calls)
    if got != wanted:
        return "calls %r wanted %r" % (got[:7], wanted[:7])
    if flat != spec["flat"]:
        return "rows %d wanted %d" % (len(flat), len(spec["flat"]))
    if harness.machine.regs[RAX] != OUT:
        return "return pointer"
    return compare_state(harness, case, 0, spec)


def compare_host(harness, case, layout):
    harness.run_host(case, layout)
    if case.get("flag", 1) != 1:
        if harness.calls or harness.clock:
            return "disabled step did work"
        return "" if harness.machine.regs[RAX] & 0xFF == case["flag"] else "disabled return"
    paired = min(case["trackers"], len(case["dexes"]))
    rates = builder_spec(case)
    wanted = list(rates["calls"])
    if case["trackers"] != len(case["dexes"]):
        wanted.append(("log", 5, LOC_LENGTHS))
    frees, seen, dropped = 0, [], 0
    for index in range(paired):
        if rates["inserted"]:
            wanted.append(("clone", RATE_ROOT, 0))
        head, spec = worker_expected(case, index)
        wanted += head + spec["calls"] + [("drop rates", RATE_COPY, 1) if rates["inserted"] else ("drop rates", 0, 0)]
        if layout["name"] != "recording":
            frees += 1 if spec["flat"] else 0
        elif case.get("no_writer"):
            dropped += 1 if spec["flat"] else 0
        else:
            wanted.append(("stamp",))
            wanted.append(("consumer", struct.pack("<III", *case["time"]), index))
            wanted.append(("writer", 0x5B8 + 0x808, 0x3A, WRITER_TAG, WRITER_NAME))
            seen.append(spec["flat"])
    wanted.append(("drop",))
    got = trim(harness.calls)
    if got != wanted:
        return "calls %r wanted %r" % (got[:8], wanted[:8])
    if layout["name"] == "recording":
        if harness.seen_rows != seen:
            return "consumer rows"
        if harness.consumer_frees != dropped:
            return "consumer frees %d wanted %d" % (harness.consumer_frees, dropped)
    elif len(harness.host_frees) != frees:
        return "row frees %d wanted %d" % (len(harness.host_frees), frees)
    if harness.inserted != rates["inserted"]:
        return "rate map rows"
    memory = harness.machine.memory
    for index, entries in harness.premiums.items():
        for at, (node, slot) in enumerate(entries):
            length = memory.read(node + 0x70 + 24 * slot, 8)
            if index < paired and length != 0:
                return "premium vector %d kept %d" % (at, length)
            if index >= paired and length != 3 + at:
                return "premium vector past the paired range moved"
            if memory.read(node + 0x60 + 24 * slot, 8) != 16 or memory.read(node + 8 + 8 * slot, 8) != at:
                return "premium capacity or key moved"
    for index in range(paired):
        failed = compare_state(harness, case, index, worker_expected(case, index)[1])
        if failed:
            return failed
    return ""


def compare_gate(harness, case, layout):
    want = gate_spec(case)
    try:
        gate, last = harness.run_gate(case, layout)
    except Halt as stop:
        if want["fault"] and "division by zero" in str(stop):
            return ""
        raise
    if want["fault"]:
        return "expected a divide fault"
    if gate is None:
        return "host never reached"
    if last != want["last"]:
        return "last bucket %d wanted %d" % (last, want["last"])
    if gate["run"] != int(want["run"]):
        return "run flag"
    if gate["name"] != STEP_NAME or gate["exchange"] != EXCHANGE or gate["byte"] != 0x5C:
        return "step arguments"
    if (gate["low"], gate["high"]) != (to_bits(0.25), to_bits(0.05)):
        return "step thresholds"
    return ""


def compare_run(harness, case):
    try:
        layout = BY_NAME.get(case.get("copy"))
        if case["kind"] == "gate":
            failed = compare_gate(harness, case, layout)
        elif case["kind"] == "builder":
            failed = compare_builder(harness, case, layout)
        elif case["kind"] == "work":
            failed = compare_worker(harness, case)
        else:
            failed = compare_host(harness, case, layout)
    except Exception as stop:
        failed = "stopped: %r" % (stop,)
    return "%s/%s: %s" % (case["label"], case.get("copy", "shared"), failed) if failed else ""


# ---- static evidence ----

FIELD_ROWS = (
    # name lea, name, field site, how the field offset is written, offset from the user state block at dex +0xf8
    (0x36F5A41, b"user_to_state", None, None, 0x00),
    (0x36F5AA6, b"users_with_positions", 0x36F5AC4, "lea", 0x60),
    (0x36F5B13, b"check_all_users_for_liquidatables", 0x36F5B0C, "lea", 0xA8),
    (0x36F5B3A, b"asset_to_oi_sz", 0x36F5B58, "lea", 0x78),
    (0x3793914, b"open_order_tracker", 0x36F5B9C, "lea", 0x30),
    (0x3793104, b"aru", 0x36F5BAD, "add", 0x90),
)
GUARD_ROWS = ((0x275BA19, 0x275BA20, 0x37C0), (0x4D86329, 0x4D86330, 0x4240))
GUARD_NAME = b"funding_distribute_guard"
REASONS = ()
GROUP_REASONS = (
    ("gate", "arm for years below 1, which always clamps to 0, or its sign fix"),
    ("host", "free size read only by the stub, a repeat of the node length read, or the unrolled tree walk for 8 or more levels, which no case builds"),
    ("rate map", "dangling vector pointer, loop step in the set key scan, the 9999 limit (asset 9999 needs 10000 rate calls), or an unwind or free path"),
    ("per-dex body", "scan step or shift that keeps the same result over the keys built, vacant entry setup, row count arithmetic that divides out, side call argument, or an unwind path"),
    ("row vector", "capacity arithmetic read only by the allocator stub, a copy of bytes no later code reads, or a drop path"),
    ("row flatten", "capacity arithmetic read only by the allocator stub, a free path, or the back iterator, which this caller never fills"),
    ("row consumer", "free size read only by the stub, or an unwind path"),
    ("summary map collect", "list link write read only by a free path, or the drop path after a panic in the extend step"),
    ("summary map extend", "iterator field no later code reads, the replaced-row path (addresses are unique), or a drain path"),
)
REFERENCE_CLAIMS = (
    {"reference": "l1/dex_registry/dex_registry.rs:402", "claim": "distribute_funding_guarded copies each asset value into a clearinghouse accumulator and a tracker map", "observed": "the step clones one rate map per dex and moves balances in 0x3703f20, then empties the premium vectors", "verdict": "different body"},
    {"reference": "l1/dex_registry/dex_registry.rs:487", "claim": "funding is due when seconds / 1000 changes", "observed": "due when block millis / bucket_millis passes last_bucket, read from the exchange guard", "verdict": "different test"},
    {"reference": "l1/dex_registry/dex_registry.rs:489", "claim": "mark price update follows distribution", "observed": "update_funding_rates is the next call after this step in the block host", "verdict": "different next step"},
    {"reference": "base/bucket_guard.rs:23", "claim": "last_bucket is the first field, bucket_millis the second", "observed": "the gate divides by the word at the guard offset and stores into the word 8 bytes above it", "verdict": "field order reversed in memory"},
    {"reference": "base/bucket_guard.rs:53", "claim": "advance_to_millis stores when bucket > last_bucket", "observed": "same rule, and the result is written to the step flag at +0x20", "verdict": "agrees"},
)
STUBS = (
    ("0x38dc6a0", "rayon bridge over the user list. It runs the per-user worker through 0x3766a10; given summary rows stand in for that output, as a linked list of row chunks"),
    ("0x3bc9a80", "collects (address, user) pointers from the user map; only its arguments are checked"),
    ("0x3596940", "user lookup by address"),
    ("0x339b590, 0x33acfe0", "address set insert and remove"),
    ("0x36f7350", "open interest and position count update; arguments checked"),
    ("0x33f4660", "rate map drop; argument checked"),
    ("0x3750610 through slot 0x5774d48", "funding rate, pinned by #860"),
    ("0x28502d0, 0x4939fb0", "rate map insert; asset and value bits checked"),
    ("0x289dab0, 0x49913a0", "rate map clone"),
    ("0x4ee3800", "clock read; the second read ends the run, so the shared timing tail is not stepped"),
    ("0x454dd50, 0x47ed710, slot 0x576e8a0", "row conversion, row writer, wall clock read in the recording copy; arguments checked"),
)


def relative_slots(image):
    return {slot: addend for slot, kind, addend, _ in image.relocations() if kind == 8}


def rip_target(image, site):
    base = image.offset(site)
    return site + 7 + struct.unpack_from("<i", image.blob, base + 3)[0]


def text_at(image, va, count):
    base = image.offset(va)
    return bytes(image.blob[base:base + count])


def field_names(image):
    """Field names and offsets of the user state block, read from its serializer bytes."""
    rows = []
    start, end = image.exact_fde(SERIALIZER)
    for name_site, name, field_site, form, offset in FIELD_ROWS:
        if text_at(image, rip_target(image, name_site), len(name)) != name:
            raise EvidenceError("field name moved: %r" % name)
        if field_site is not None:
            if not start <= field_site < end:
                raise EvidenceError("field site outside the serializer")
            data = text_at(image, field_site, 7)
            if form == "add":
                if data[:3] != b"\x48\x81\xc3" or struct.unpack_from("<i", data, 3)[0] != offset:
                    raise EvidenceError("field offset moved: %r" % name)
            elif data[:2] == b"\x48\x8d" and data[2] & 0xC7 == 0x83:
                if struct.unpack_from("<i", data, 3)[0] != offset:
                    raise EvidenceError("field offset moved: %r" % name)
            elif data[:2] != b"\x48\x8d" or data[2] & 0xC7 != 0x43 or data[3] != offset:
                raise EvidenceError("field offset moved: %r" % name)
        rows.append({"name": name.decode(), "name_site": "%#x" % name_site, "block_offset": "%#x" % offset, "dex_offset": "%#x" % (0xF8 + offset)})
    return rows


def guard_names(image):
    rows = []
    for field_site, name_site, offset in GUARD_ROWS:
        data = text_at(image, field_site, 7)
        if data[:3] != b"\x48\x8d\x8b" or struct.unpack_from("<i", data, 3)[0] != offset:
            raise EvidenceError("guard field moved")
        if text_at(image, rip_target(image, name_site), len(GUARD_NAME)) != GUARD_NAME:
            raise EvidenceError("guard name moved")
        rows.append({"field_site": "%#x" % field_site, "name_site": "%#x" % name_site, "offset": "%#x" % offset, "name": GUARD_NAME.decode()})
    return rows


def direct_callers(image, targets):
    base, text = image.text_bytes()
    found = {target: [] for target in targets}
    at = text.find(b"\xe8")
    while 0 <= at <= len(text) - 5:
        target = base + at + 5 + struct.unpack_from("<i", text, at + 1)[0]
        if target in found:
            found[target].append(base + at)
        at = text.find(b"\xe8", at + 1)
    return found


def slot_callers(image, slots):
    base, text = image.text_bytes()
    found = {slot: [] for slot in slots}
    at = text.find(b"\xff\x15")
    while 0 <= at <= len(text) - 6:
        target = base + at + 6 + struct.unpack_from("<i", text, at + 2)[0]
        if target in found:
            found[target].append(base + at)
        at = text.find(b"\xff\x15", at + 1)
    return found


def call_map(image):
    relative = relative_slots(image)
    pairs = ((SLOT_WORK, WORK), (SLOT_RATE, 0x3750610), (SLOT_CONSUMER, CONSUMER))
    for slot, target in pairs:
        if relative.get(slot) != target:
            raise EvidenceError("slot table changed")
    wanted = [copy["host"] for copy in COPIES] + [copy["builder"] for copy in COPIES] + [copy["caller"] for copy in COPIES]
    direct = direct_callers(image, wanted)
    through = slot_callers(image, [slot for slot, _ in pairs])
    rows = []
    for layout in COPIES:
        name_at = rip_target(image, layout["gate_end"] - 5 - 0x38)
        following = layout["gate_end"] + 3
        if text_at(image, following, 1) != b"\xe8":
            raise EvidenceError("next step call moved")
        next_step = following + 5 + struct.unpack_from("<i", image.blob, image.offset(following) + 1)[0]
        begin, end = image.exact_fde(next_step)
        data = text_at(image, begin, end - begin)
        named = False
        at = data.find(b"\x8d")
        while 0 <= at <= len(data) - 6:
            if data[at + 1] & 0xC7 == 0x05 and data[at - 1] in (0x48, 0x4C):
                target = begin + at + 6 + struct.unpack_from("<i", data, at + 2)[0]
                try:
                    named = named or text_at(image, target, len(NEXT_STEP_NAME)) == NEXT_STEP_NAME
                except EvidenceError:
                    pass
            at = data.find(b"\x8d", at + 1)
        rows.append({"copy": layout["name"], "caller": "%#x" % layout["caller"], "caller_called_by": ["%#x" % va for va in direct[layout["caller"]]],
                     "gate": "%#x..%#x" % (layout["gate"], layout["gate_end"]), "host": "%#x" % layout["host"], "host_calls": ["%#x" % va for va in direct[layout["host"]]],
                     "builder": "%#x" % layout["builder"], "builder_calls": ["%#x" % va for va in direct[layout["builder"]]], "step_name": text_at(image, name_at, len(STEP_NAME)).decode(),
                     "next_call": "%#x" % next_step, "next_call_names_update_funding_rates": named, "dex_rows": "%#x" % layout["dex_rows"], "trackers": "%#x" % layout["trackers"],
                     "guard": "%#x" % layout["guard"], "byte_arg": "%#x" % layout["network_byte"]})
    return {"copies": rows, "slots": [{"slot": "%#x" % slot, "target": "%#x" % target, "calls": ["%#x" % va for va in through[slot]]} for slot, target in pairs]}


def locations(image):
    relative = relative_slots(image)
    rows = []
    for slot, role in ((LOC_LENGTHS, "dex and tracker list lengths differ"), (LOC_SUM, "residual sum overflow"), (LOC_SUB, "balance or margin subtract overflow")):
        path, line, column = image.location(slot, relative)
        rows.append({"slot": "%#x" % slot, "path": path, "line": line, "column": column, "role": role})
    return rows


def dead_third_argument(image):
    """rdx of 0x3703f20 is overwritten by a lea before any instruction reads it."""
    begin, end = image.exact_fde(WORK)
    for row in decode_range(image, begin, end):
        operands = [item for item in (row.a, row.b) if item]
        if row.op == "lea" and row.a == ("r", RDX):
            return "%#x" % row.va
        for item in operands:
            if item[0] == "r" and item[1] == RDX or item[0] == "m" and RDX in item[1:3]:
                raise EvidenceError("rdx read at %#x" % row.va)
    raise EvidenceError("no rdx write")


# ---- mutation ----

def displacement_at(image, row):
    for operand in (row.a, row.b):
        if operand and operand[0] == "m" and operand[1] not in (None, RSP) and operand[4]:
            disp = operand[4]
            end = row.size - (row.imm_size or 0)
            base = image.offset(row.va)
            data = bytes(image.blob[base:base + row.size])
            if -128 <= disp <= 127 and data[end - 1:end] == struct.pack("<b", disp):
                return end - 1
            if data[end - 4:end] == struct.pack("<i", disp):
                return end - 4
            raise EvidenceError("displacement not found at %#x" % row.va)
    return None


def mutation_targets(image, rows):
    """Yield (va, byte offset in the instruction, xor mask, kind)."""
    for row in rows:
        at = displacement_at(image, row)
        if at is not None:
            yield row.va, at, 8, "offset"
        if row.op == "jcc":
            yield row.va, row.size - (2 if row.size == 2 else 5), 1, "branch"
        elif row.op in ("set", "cmov"):
            base = image.offset(row.va)
            yield row.va, bytes(image.blob[base:base + 16]).index(b"\x0f") + 1, 1, row.op
        if row.imm_at is not None and row.op not in ("jcc", "call", "jmp"):
            yield row.va, row.imm_at, 1, "immediate"


def groups(image):
    rows = []
    for layout in COPIES:
        rows.append(("gate " + layout["name"], layout["gate"], layout["gate_end"]))
    clocks = direct_callers(image, [CLOCK])[CLOCK]
    for layout in COPIES:
        begin, end = image.exact_fde(layout["host"])
        reads = [va for va in clocks if begin <= va < end]
        rows.append(("host " + layout["name"], begin, reads[1] + 5))
    for layout in COPIES:
        begin, end = image.exact_fde(layout["builder"])
        rows.append(("rate map " + layout["name"], begin, end))
    for role, start in (("per-dex body", WORK), ("row vector", TO_ROWS), ("row flatten", FLATTEN), ("row consumer", CONSUMER), ("summary map collect", INTO_MAP), ("summary map extend", EXTEND)):
        begin, end = image.exact_fde(start)
        rows.append((role, begin, end))
    return rows


def run_mutants(image, reached, cases):
    results = []
    harness = Harness(image)
    machine = harness.machine
    machine.step_limit = MUTANT_STEP_LIMIT
    by_va = {}
    for index, touched in enumerate(reached):
        for va in touched:
            by_va.setdefault(va, []).append(index)
    first_kill = []
    for role, begin, end in groups(image):
        for va, at, xor, kind in mutation_targets(image, decode_range(image, begin, end)):
            indices = by_va.get(va)
            if not indices:
                results.append({"group": role, "va": va, "kind": kind, "result": "unreached", "by": ""})
                continue
            base = image.offset(va)
            machine.patches = {va + at: image.blob[base + at] ^ xor}
            machine.cache.pop(va, None)
            failed = None
            wanted = set(indices)
            for index in [item for item in first_kill if item in wanted] + indices:
                failed = compare_run(harness, cases[index])
                if failed:
                    if index in first_kill:
                        first_kill.remove(index)
                    first_kill.insert(0, index)
                    del first_kill[40:]
                    break
            machine.patches = {}
            machine.cache.pop(va, None)
            results.append({"group": role, "va": va, "kind": kind, "result": "killed" if failed else "survived", "by": failed.split(":")[0] if failed else ""})
    return results


# ---- evidence ----

def outcome_of(case):
    if case["kind"] == "gate":
        want = gate_spec(case)
        return "divide fault" if want["fault"] else ("step runs" if want["run"] else "step skipped")
    if case["kind"] == "builder":
        return "panic" if builder_spec(case)["panic"] else "map built"
    if case["kind"] == "work":
        state = worker_expected(case, 0)[1]["state"]
        return "margin moved" if "margin" in state else "balance moved" if "balance" in state else "no residual"
    return "disabled" if case.get("flag", 1) != 1 else "ran"


def worked(image):
    """One residual through the real bytes."""
    harness = Harness(image)
    a, b, c = address(1), address(2), address(3)
    rows = []
    for label, summaries, users in (
        ("rounding left +7 across three users", [summary(a, -1000, 40000), summary(b, 1500, 70000), summary(c, -493, 30000)], {a: plain_user(5000), b: plain_user(6000), c: plain_user(7000)}),
        ("rounding left -2, largest is isolated", [summary(a, 3, 40000), summary(b, -5, 70000)], {a: plain_user(5000), b: plain_user(6000, margin=900, isolated=True)}),
        ("tie on the largest value", [summary(b, 2, 70000), summary(a, 2, 70000)], {a: plain_user(5000), b: plain_user(6000)}),
    ):
        case = work_case(label, summaries, users)
        harness.run_worker(case)
        rows.append({"label": label, "sum": sum(row["sum"] for row in summaries),
                     "users_after": [{"user": user.hex()[-2:], "balance_before": row["balance"], "balance_after": harness.read_balance(0, user),
                                      "margin_before": row["positions"][3]["margin"], "margin_after": harness.read_margin(0, user, 3)} for user, row in sorted(users.items())]})
    return rows


def analyse(image, full=True):
    layout_gates(image)
    cases = all_cases()
    harness = Harness(image)
    machine = harness.machine
    mismatches, first = 0, ""
    reached = []
    outcomes = {}
    for case in cases:
        machine.seen = set()
        failed = compare_run(harness, case)
        reached.append(frozenset(machine.seen))
        if failed:
            mismatches += 1
            first = first or failed
        key = case["kind"] + ": " + outcome_of(case)
        outcomes[key] = outcomes.get(key, 0) + 1
    touched = set().union(*reached)
    functions = []
    for role, begin, end in groups(image) + [("summary map insert", *image.exact_fde(TREE_INSERT)), ("summary map split", *image.exact_fde(TREE_SPLIT)), ("summary map next", *image.exact_fde(TREE_NEXT)), ("position entry", *image.exact_fde(ENTRY))]:
        rows = decode_range(image, begin, end)
        base = image.offset(begin)
        functions.append({"role": role, "start": "%#x" % begin, "end": "%#x" % end, "bytes": end - begin, "sha256": hashlib.sha256(bytes(image.blob[base:base + end - begin])).hexdigest(),
                          "instructions": len(rows), "instructions_stepped": sum(1 for row in rows if row.va in touched)})
    evidence = {
        "target_sha256": SHA256,
        "functions": functions,
        "user_state_fields": field_names(image),
        "guard_fields": guard_names(image),
        "call_map": call_map(image),
        "locations": locations(image),
        "third_argument_overwritten_at": dead_third_argument(image),
        "step_thresholds": [struct.unpack_from("<d", text_at(image, 0x206880, 16), at)[0] for at in (0, 8)],
        "stubs": [{"edge": edge, "role": role} for edge, role in STUBS],
        "cases": {"total": len(cases), "outcomes": dict(sorted(outcomes.items()))},
        "mismatches": mismatches,
        "first_mismatch": first,
        "instructions_stepped": machine.steps,
        "worked": worked(image),
        "reference_claims": list(REFERENCE_CLAIMS),
    }
    results = None
    if full:
        results = run_mutants(image, reached, cases)
        summary_rows = {}
        for row in results:
            summary_rows[row["result"]] = summary_rows.get(row["result"], 0) + 1
        evidence["mutations"] = {name: summary_rows.get(name, 0) for name in ("killed", "survived", "unreached")}
    return evidence, results


def reason_for(row):
    for group, low, high, text in REASONS:
        if row["group"].startswith(group) and low <= row["va"] < high:
            return text
    for group, text in GROUP_REASONS:
        if row["group"].startswith(group):
            return text
    return ""


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--out", required=True)
    args = parser.parse_args(argv)
    image = load_image()
    evidence, results = analyse(image)
    if evidence["mismatches"]:
        raise EvidenceError("specification mismatch: %s" % evidence["first_mismatch"])
    out = pathlib.Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    (out / "evidence.json").write_text(json.dumps(evidence, indent=1, sort_keys=True) + "\n", encoding="utf-8", newline="\n")
    lines = ["group\tva\tkind\tresult\tkilled_by\treason"]
    for row in results:
        reason = "" if row["result"] == "killed" else reason_for(row)
        lines.append("%s\t%#x\t%s\t%s\t%s\t%s" % (row["group"], row["va"], row["kind"], row["result"], row["by"], reason))
    (out / "mutations.tsv").write_text("\n".join(lines) + "\n", encoding="utf-8", newline="\n")
    print("cases %d, mismatches %d, mutants %r" % (evidence["cases"]["total"], evidence["mismatches"], evidence["mutations"]))
    return 0


if __name__ == "__main__":
    sys.exit(main())
