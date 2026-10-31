#!/usr/bin/env python3
"""Pin the node #94 block step named cancel_aggressive_orders_at_oi_cap from ELF bytes: asset choice, reference price, 1% sweep.

The step `0x2228130` (copies `0x47180e0`, `0x470d770`) walks every asset of every dex through the at-cap test `0x3713f20`, picks a
reference price for each hit, and calls the sweep `0x26e48c0` (copies `0x4305490`, `0x43060a0`). The sweep reads each user's orders
from one book, keeps those more than 1% from the reference on the crossing side, and cancels them with reason 8 after the scan.
The real bytes run in a Python evaluator with the callees at the edge stubbed. A separately written specification predicts every
result and stub argument, and every condition, immediate and field offset is flipped to show the run can tell. No objdump or
readelf output is parsed, and the binary is never executed. Standard library only.
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

BINARY = ROOT / "artifacts" / "node" / "94" / "hl-node"
SHA256 = "3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f"

Copy = collections.namedtuple("Copy", "name host sweep accessor cancel flush caller site dex_list")
COPIES = (
    Copy("first", 0x2228130, 0x26E48C0, 0x2755C70, 0x26DE150, 0x24FB610, 0x22297C0, 0x2229B8B, 0x5C0),
    Copy("second", 0x47180E0, 0x4305490, 0x4D78330, 0x42F7420, 0x432A100, 0x47162D0, 0x47166ED, 0x1040),
    Copy("third", 0x470D770, 0x43060A0, 0x4D78200, 0x42F7590, 0x4329870, 0x470E9A0, 0x470ED6B, 0x5C0),
)
PREDICATE = 0x3713F20
SUM_FOLD = 0x3BE6660
INSTANT = 0x4EE3800
DROP_WORD = 0x3379490
STATUS_FN = 0x4A9A1A0
STATUS_TABLE = 0x7038DC
STEP_NAME = 0x3EFAB7
STEP_NAME_SIZE = 0x22
STEP_LIMITS = 0x205E70
RATIO = 0x20A2F8
MINUS_ONE = 0x20A278
SIGN_BIT = 0x2082F0
CAP_FACTOR = 0x20AC60

SLOT_PREDICATE = 0x5773A48
SLOT_GROW_IDS = 0x5773A50
SLOT_GROW_ROWS = 0x5774808
SLOT_REALLOC = 0x576E030
SLOT_MALLOC = 0x576DFD8
SLOT_FREE = 0x576E010
SLOT_MEMCPY = 0x576DFE0
SLOT_MEMMOVE = 0x576E0E0
SLOT_SORT = 0x5774F50
SLOT_PANIC = 0x576E470
SLOT_NOUNWIND = 0x576E128
SLOT_ALLOC_ERROR = (0x576DFB8, 0x576E020, 0x576E108)
SLOT_UNWRAP = 0x576E048
SLOT_BOUNDS = 0x576DFC8
SLOT_MUL = 0x576E1B0
SLOT_ADD = 0x576E118
SLOT_SUB = 0x576E150
SLOT_EXPECT = 0x576E468
LOC_ID_MUL = 0x56A0488
LOC_ROW_BOUND = 0x569DAF8
LOC_ROW_BOUND_OTHER = 0x572E3D0
LOC_ID_MUL_OTHER = 0x572F8D0
HOST_STOP = 0x408
LOC_PRED_BOUND = 0x56F1CB0
LOC_PRED_UNWRAP = 0x56F1CE0
LOC_DEX_UNWRAP = 0x56E9AE0
STOP_REASON = 8
ROW_STRIDE = 0x60
DEX_STRIDE = 0x2F0
SLOT_STRIDE = 0xF8
USER_SIZE = 20
VACANT = 2
MUL_HASH = 0xF1357AEA2E62A9C5
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
HEAP_SIZE = 0x80000
RETURN_SENTINEL = 0xDEAD0000
POISON = 0xA5A5A5A5A5A5A5A5
STEP_LIMIT = 400000
MUTANT_STEP_LIMIT = 100000

BOOK = HEAP_BASE + 0x100
TIME_WORDS = HEAP_BASE + 0x40
GATE = HEAP_BASE + 0x60
OUT_WORDS = HEAP_BASE + 0x2800
CTX_WORD = 0x4444444444444400
VEC_WORD = HEAP_BASE + 0x200
SET_NODES = HEAP_BASE + 0x400
CAP_MAP = HEAP_BASE + 0x800
CAP_NODES = HEAP_BASE + 0x1000
SIZE_NODES = HEAP_BASE + 0x1800
ROWS = HEAP_BASE + 0x3000
DEXES = HEAP_BASE + 0x6000
STATE = HEAP_BASE + 0x8800
HASH_BYTES = HEAP_BASE + 0xA800
SLAB = HEAP_BASE + 0xC000
HEAP_FREE = HEAP_BASE + 0x18000

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


# ---- specification, written from the claim ----

def over_reference(px, ref, side):
    """The double the sweep compares with 0.01."""
    if ref:
        value = float(px) / float(ref)
    else:
        value = math.inf if px else math.nan
    value += -1.0
    return -value if side else value


def aggressive(px, ref, side):
    return over_reference(px, ref, side) > 0.01


def spec_candidates(w, entry):
    """Sorted unique order ids of one user: live slots of the first set, then the keys of the second tree."""
    found = set()
    for index in entry["first"]:
        if index < w["slab_len"] and index < len(w["slab"]) and w["slab"][index]["state"] != VACANT:
            found.add(w["slab"][index]["oid"])
    found.update(entry["second"])
    return sorted(found)


def spec_sweep(w):
    picked = []
    count = w["user_len"]
    entries = sorted(w["users"], key=lambda item: item["user"])
    if w["users"] and count:
        for entry in entries[:count]:
            for oid in spec_candidates(w, entry):
                if not w["hash_items"]:
                    continue
                index = w["hash"].get(oid)
                if index is None or index >= w["slab_len"]:
                    continue
                slot = w["slab"][index]
                if slot["state"] == VACANT:
                    continue
                if aggressive(slot["px"], w["ref"], slot["side"]):
                    picked.append((entry["user"], oid))
    events = [("cancel", user, oid, w["rdx"], w["rcx"], STOP_REASON) for user, oid in picked]
    grows = 0
    capacity = 0
    for length in range(len(picked)):
        if length == capacity:
            capacity = capacity * 2 or 4
            grows += 1
    return {"events": events, "stop": None, "grows": grows, "leaked": 0}


def next_second(date, secs, frac):
    """The stored time plus 1800 s, inside one common year."""
    total = secs + 1800
    if total >= 86400:
        return date + (1 << 4), total - 86400, frac
    return date, total, frac


def signed32(value):
    return value - (1 << 32) if value & SIGN[4] else value


def spec_price(w, row):
    if w["time"] is None:
        return row["base"]
    limit = next_second(row["date"], row["secs"], row["frac"])
    now = w["time"]
    return row["second"] if (signed32(now[0]), now[1], now[2]) <= (signed32(limit[0]), limit[1], limit[2]) else row["base"]


def spec_host(w):
    events = []
    answer = {"events": events, "stop": None, "done": False, "leaked": 0}
    if w["flag"] != 1:
        return answer
    ids = []
    for at, dex in enumerate(w["dexes"]):
        for local in range(dex["count"]):
            if dex["number"] * 10000 > MASK[8]:
                answer["stop"] = ("multiply overflow", LOC_ID_MUL)
                return answer
            asset = dex["number"] * 10000 + local
            if asset > MASK[8]:
                answer["stop"] = ("add overflow", LOC_ID_MUL)
                return answer
            hit = asset in w["hits"]
            events.append(("predicate", DEXES + at * DEX_STRIDE, asset))
            if hit:
                ids.append(asset)
    for asset in ids:
        events.append(("accessor", asset))
        at = asset // 10000
        if at >= w["dex_len"]:
            answer["stop"] = ("unwrap", LOC_DEX_UNWRAP)
            return answer
        dex = w["dexes"][at]
        local = asset - at * 10000
        if local >= dex["row_len"]:
            answer["stop"] = ("bounds", local, dex["row_len"], LOC_ROW_BOUND)
            return answer
        row = dex["rows"][local]
        px = row["base"] if dex["mode"] == 3 else spec_price(w, row)
        book = book_word(asset)
        events.append(("sweep", book, px, STATE, tuple(vec_words(asset))))
        events.append(("flush", tuple(vec_words(asset)), at, STATE))
    answer["done"] = True
    return answer


def book_word(asset):
    return 0x7700000000 + asset * 0xD8


def vec_words(asset):
    return (0x51 + asset, 0x6100 + asset, 0x7100 + asset)


def cap_floor(value):
    """value * 0.9 as the saturating double to i64 cast."""
    scaled = float(value) * 0.9
    return min(int(scaled), (1 << 63) - 1)


def spec_predicate(w):
    events = []
    answer = {"events": events, "stop": None, "out": None}
    asset = w["asset"]
    if w["mode"] == 3:
        answer["out"] = asset in w["set"]
        return answer
    cap = w["caps"].get(asset)
    if w["caps_empty"]:
        cap = None
    if cap is not None:
        local = asset % 10000
        if local >= w["row_len"]:
            answer["stop"] = ("bounds", local, w["row_len"], LOC_PRED_BOUND)
            return answer
        price = w["row_prices"][local]
        size = 0 if w["sizes_empty"] else w["sizes"].get(asset, 0)
        if price >= SIGN[8]:
            answer["out"] = True
            return answer
        product = price * (size - (1 << 64) if size >= SIGN[8] else size)
        if not -SIGN[8] <= product < SIGN[8]:
            answer["out"] = True
            return answer
        if cap >= SIGN[8]:
            answer["stop"] = ("unwrap",)
            return answer
        if product > cap_floor(cap):
            answer["out"] = True
            return answer
    events.append(("sum", DEXES, 0, w["sum_end"], 0, DEXES))
    if w["sum"] is None:
        answer["out"] = True
        return answer
    if w["total_cap"] >= SIGN[8]:
        answer["stop"] = ("unwrap",)
        return answer
    total = w["sum"] - (1 << 64) if w["sum"] >= SIGN[8] else w["sum"]
    answer["out"] = total > cap_floor(w["total_cap"])
    return answer


def run_spec(case):
    return {"sweep": spec_sweep, "host": spec_host, "pred": spec_predicate}[case.kind](case.world)


# ---- harness: real bytes; the callees at the edge are stubbed and their arguments compared ----

class RealExcept:
    """Every call target runs its real bytes unless the harness stubs it."""

    def __init__(self):
        self.stubs = frozenset()

    def __contains__(self, target):
        return target not in self.stubs


class Finished(Exception):
    """The host reached its timing tail: the state change is over."""


class Case:
    def __init__(self, label, kind, world, copy=0):
        self.label = label
        self.kind = kind
        self.world = world
        self.copy = copy


Shape = collections.namedtuple("Shape", "parent keys key_size value_size parent_index length edges")
SET_SHAPE = Shape(0x0, 0x8, 8, 0, 0x60, 0x62, 0x68)
MAP_SHAPE = Shape(0x0, 0x8, 8, 0xB8, 0x848, 0x84A, 0x850)
USER_SHAPE = Shape(0x370, 0x378, USER_SIZE, 0x50, 0x454, 0x456, 0x458)
FANOUT = 12
ENTRY_FIRST = 0x20
ENTRY_SECOND = 0x38
NODE_KEYS = 0x08
NODE_VALUES = 0x60
NODE_LENGTH = 0xBA
NODE_EDGES = 0xC0
NODE_SIZE = 0x120
NODE_CAPACITY = 11
UNMAPPED = 0x10
TEMPTING = (1 << 64) - 3


def ramp(count, start):
    return bytes((start + index * 7) & 0xFF or 1 for index in range(count))


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


def fx_hash(key):
    value = key * MUL_HASH & MASK[8]
    return (value << 20 | value >> 44) & MASK[8]


class Harness:
    def __init__(self, image):
        self.image = image
        self.machine = Machine(image)
        machine = self.machine
        self.relative = {slot: addend for slot, kind, addend, _ in image.relocations() if kind == 8}
        relative = self.relative
        machine.memory.statics.update(relative)
        table = {SLOT_REALLOC: self.on_realloc, SLOT_MALLOC: self.on_malloc, SLOT_FREE: self.on_free, SLOT_MEMCPY: self.on_copy, SLOT_MEMMOVE: self.on_copy, SLOT_SORT: self.on_sort,
                 SLOT_PANIC: self.on_panic, SLOT_NOUNWIND: self.on_panic, SLOT_UNWRAP: self.on_unwrap, SLOT_BOUNDS: self.on_bounds, SLOT_MUL: self.on_mul,
                 SLOT_ADD: self.on_add, SLOT_SUB: self.on_add, SLOT_EXPECT: self.on_panic, SLOT_GROW_ROWS: self.on_grow_rows, SLOT_GROW_IDS: self.on_grow_ids,
                 SLOT_PREDICATE: self.on_predicate}
        for slot in SLOT_ALLOC_ERROR:
            table[slot] = self.on_panic
        for slot in table:
            relative.setdefault(slot, slot)
        machine.memory.statics.update(relative)
        machine.slots = {relative[slot]: hook for slot, hook in table.items()}
        self.base = frozenset(machine.slots) | frozenset((INSTANT, DROP_WORD, SUM_FOLD))
        self.real = RealExcept()
        machine.real = self.real
        self.select(COPIES[0])
        self.events = []
        self.w = None
        self.brk = HEAP_FREE
        self.live = {}
        self.grows = 0
        self.instants = 0

    def select(self, copy):
        self.copy = copy
        machine = self.machine
        machine.calls = {INSTANT: self.on_instant, DROP_WORD: self.on_drop_word, SUM_FOLD: self.on_sum, copy.accessor: self.on_accessor,
                         copy.cancel: self.on_cancel, copy.flush: self.on_flush, copy.sweep: self.on_sweep}
        self.real.stubs = self.base | frozenset((copy.accessor, copy.cancel, copy.flush))

    # ---- stubs ----

    def on_panic(self, m):
        raise Panicked(("panic", m.regs[RDI]))

    def on_unwrap(self, m):
        raise Panicked(("unwrap", m.regs[R8], m.regs[RSI]))

    def on_bounds(self, m):
        raise Panicked(("bounds", m.regs[RDI], m.regs[RSI], m.regs[RDX]))

    def on_mul(self, m):
        raise Panicked(("multiply overflow", m.regs[RDI]))

    def on_add(self, m):
        raise Panicked(("add overflow", m.regs[RDI]))

    def allocate(self, size):
        at = (self.brk + 15) & ~15
        self.brk = at + size
        if self.brk > HEAP_BASE + HEAP_SIZE:
            raise Halt("heap full")
        self.live[at] = size
        return at

    def on_malloc(self, m):
        if m.regs[RDI] > 0x40000:
            raise Halt("allocation size")
        m.regs[RAX] = self.allocate(m.regs[RDI])

    def on_free(self, m):
        at, size = m.regs[RDI], m.regs[RSI]
        if self.live.pop(at, None) != size:
            raise Halt("free %#x size %#x" % (at, size))

    def on_realloc(self, m):
        at, size = m.regs[RDI], m.regs[RSI]
        old = self.live.pop(at, None)
        if old is None or size > 0x40000:
            raise Halt("realloc %#x" % at)
        fresh = self.allocate(size)
        m.memory.copy(fresh, at, min(old, size))
        m.regs[RAX] = fresh

    def on_copy(self, m):
        regs = m.regs
        if regs[RDX] > 0x40000:
            raise Halt("copy size")
        m.memory.copy(regs[RDI], regs[RSI], regs[RDX])
        regs[RAX] = regs[RDI]

    def on_sort(self, m):
        at, count = m.regs[RDI], m.regs[RSI]
        if count > 0x400:
            raise Halt("sort size")
        memory = m.memory
        values = sorted(memory.read(at + index * 8, 8) for index in range(count))
        for index, value in enumerate(values):
            memory.write(at + index * 8, 8, value)

    def grow(self, m, stride):
        memory = m.memory
        vector = m.regs[RDI]
        capacity, old = memory.read(vector, 8), memory.read(vector + 8, 8)
        if capacity > 0x400:
            raise Halt("vector size")
        wanted = capacity * 2 or 4
        fresh = self.allocate(wanted * stride)
        if capacity:
            memory.copy(fresh, old, capacity * stride)
            if self.live.pop(old, None) != capacity * stride:
                raise Halt("vector buffer")
        memory.write(vector, 8, wanted)
        memory.write(vector + 8, 8, fresh)
        self.grows += 1

    def on_grow_rows(self, m):
        self.grow(m, 0x20)

    def on_grow_ids(self, m):
        self.grow(m, 8)
        self.grows -= 1

    def on_predicate(self, m):
        asset = m.regs[RSI]
        self.events.append(("predicate", m.regs[RDI], asset))
        m.regs[RAX] = (POISON & ~0xFF) | int(asset in self.w["hits"])

    def on_instant(self, m):
        if m.regs[RDI] & MASK[4] != 1:
            raise Halt("clock id")
        self.instants += 1
        if self.instants == 2:
            raise Finished()
        m.regs[RAX] = 0x1000
        m.regs[RDX] = 0x2000
        m.keep_rdx = True

    def on_drop_word(self, m):
        if m.memory.read(m.regs[RDI], 2) != 0x141:
            raise Halt("dropped word")

    def on_sum(self, m):
        memory = m.memory
        args = m.regs[RDI]
        closure = m.regs[RDX]
        if memory.read(memory.read(closure + 8, 8), 8) != 0:
            raise Halt("sum start")
        self.events.append(("sum", memory.read(args, 8), memory.read(args + 8, 8), memory.read(args + 0x10, 8), m.regs[RSI], memory.read(closure, 8)))
        w = self.w
        m.regs[RAX] = (POISON & ~1) | (w["sum"] is not None)
        m.regs[RDX] = w["sum"] or 0
        m.keep_rdx = True

    def on_accessor(self, m):
        memory = m.memory
        asset = m.regs[RDX]
        if m.regs[RSI] != STATE:
            raise Halt("accessor state")
        self.events.append(("accessor", asset))
        out = m.regs[RDI]
        for index, word in enumerate(vec_words(asset)):
            memory.write(out + index * 8, 8, word)
        memory.write(out + 0x18, 8, book_word(asset))
        memory.write(out + 0x20, 8, STATE)
        m.regs[RAX] = out

    def on_sweep(self, m):
        memory = m.memory
        self.events.append(("sweep", m.regs[RDI], m.regs[RSI], m.regs[RDX], tuple(memory.read(m.regs[RCX] + index * 8, 8) for index in range(3))))

    def on_flush(self, m):
        memory = m.memory
        self.events.append(("flush", tuple(memory.read(m.regs[RDI] + index * 8, 8) for index in range(3)), m.regs[RSI], m.regs[RDX]))

    def on_cancel(self, m):
        memory = m.memory
        self.events.append(("cancel", memory.bytes_at(m.regs[RSI], USER_SIZE), m.regs[RDX], m.regs[RCX], m.regs[R8], m.regs[R9] & MASK[4]))
        if self.w.get("clobber"):
            for index in range(len(self.w["slab"])):
                memory.write(SLAB + index * SLOT_STRIDE, 8, VACANT)
            memory.write(BOOK + 0x10, 8, 0)
            memory.write(BOOK + 0x40, 8, 0)
        m.regs[RAX] = POISON

    # ---- worlds ----

    def carve(self, size):
        at = (self.brk + 15) & ~15
        self.brk = at + size
        if self.brk > HEAP_BASE + HEAP_SIZE:
            raise EvidenceError("case does not fit the heap")
        return at

    def place(self, shape, keys, fill, parent, index, height=None):
        """A tree of uniform depth, keys in order; `keys` holds (key bytes, value)."""
        memory = self.machine.memory
        if height is None:
            height = 1 if len(keys) > FANOUT - 1 else 0
        own, kids = list(keys), []
        if height:
            fan = max(3, (len(keys) + 11) // 11)
            base, extra = divmod(len(keys) - (fan - 1), fan)
            own, at = [], 0
            for child in range(fan):
                size = base + (1 if child < extra else 0)
                kids.append(keys[at:at + size])
                at += size
                if child < fan - 1:
                    own.append(keys[at])
                    at += 1
        node = self.carve(shape.edges + (FANOUT * 8 if kids else 0))
        memory.write(node + shape.parent, 8, parent)
        memory.write(node + shape.parent_index, 2, index)
        memory.write(node + shape.length, 2, len(own))
        for at, (key, value) in enumerate(own):
            memory.put_bytes(node + shape.keys + at * shape.key_size, key)
            if fill:
                fill(node + at * shape.value_size, value)
        for at in range(len(own), FANOUT - 1):
            filler = self.w.get("filler")
            memory.put_bytes(node + shape.keys + at * shape.key_size, b"\xfd" * shape.key_size if filler is None or shape.key_size != 8 else filler.to_bytes(8, "little"))
        for at, kid in enumerate(kids):
            memory.write(node + shape.edges + at * 8, 8, self.place(shape, kid, fill, node, at, height - 1)[0])
        return node, height

    def set_tree(self, at, shape, keys):
        memory = self.machine.memory
        if not keys:
            memory.write(at, 8, 0)
            memory.write(at + 8, 8, 0x55)
            memory.write(at + 16, 8, 0)
            return
        root, height = self.place(shape, [(key.to_bytes(8, "little"), None) for key in sorted(keys)], None, 0, 0xFFFF, self.w.get("set_height"))
        memory.write(at, 8, root)
        memory.write(at + 8, 8, height)
        memory.write(at + 16, 8, len(keys))

    def fill_entry(self, at, entry):
        self.set_tree(at + ENTRY_FIRST, SET_SHAPE, entry["first"])
        self.set_tree(at + ENTRY_SECOND, MAP_SHAPE, entry["second"])

    def write_hash(self, table, buckets):
        memory = self.machine.memory
        ctrl = HASH_BYTES + buckets * 16
        memory.put_bytes(ctrl, b"\xff" * (buckets + 16))
        memory.put_bytes(HASH_BYTES, ramp(buckets * 16, 0x33))
        mask = buckets - 1
        for key, value in table.items():
            hashed = fx_hash(key)
            top = hashed >> 57
            pos, step = hashed & mask, 16
            while True:
                group = memory.bytes_at(ctrl + pos, 16)
                empty = next((index for index in range(16) if group[index] == 0xFF), None)
                if empty is not None:
                    at = (pos + empty) & mask
                    break
                pos = (pos + step) & mask
                step += 16
            memory.write(ctrl + at, 1, top)
            if at < 16:
                memory.write(ctrl + buckets + at, 1, top)
            memory.write(ctrl - (at + 1) * 16, 8, key)
            memory.write(ctrl - (at + 1) * 16 + 8, 8, value)
        return ctrl

    def sweep_world(self, w):
        memory = self.machine.memory
        memory.put_bytes(BOOK, ramp(0xD8, 0x2B))
        memory.write(BOOK + 0x8, 8, SLAB)
        memory.write(BOOK + 0x10, 8, w["slab_len"])
        buckets = w.get("buckets") or (64 if len(w["hash"]) <= 50 else 256)
        ctrl = self.write_hash(w["hash"], buckets)
        memory.write(BOOK + 0x28, 8, ctrl)
        memory.write(BOOK + 0x30, 8, buckets - 1)
        memory.write(BOOK + 0x40, 8, w["hash_items"])
        for index, slot in enumerate(w["slab"]):
            at = SLAB + index * SLOT_STRIDE
            memory.put_bytes(at, ramp(SLOT_STRIDE, 0x41 + index))
            memory.write(at, 8, slot["state"])
            memory.write(at + 0xA0, 8, slot["px"])
            memory.write(at + 0xC2, 1, slot["side"])
            memory.write(at + 0xD8, 8, slot["oid"])
        if w["users"]:
            rows = [(entry["user"], entry) for entry in sorted(w["users"], key=lambda item: item["user"])]
            root, height = self.place(USER_SHAPE, rows, self.fill_entry, 0, 0xFFFF, w.get("user_height"))
            memory.write(BOOK + 0xB8, 8, root)
            memory.write(BOOK + 0xC0, 8, height)
        else:
            memory.write(BOOK + 0xB8, 8, 0)
        memory.write(BOOK + 0xC8, 8, w["user_len"])

    def host_world(self, w):
        memory = self.machine.memory
        memory.put_bytes(GATE, ramp(0x28, 0x13))
        memory.write(GATE + 0x20, 1, w["flag"])
        memory.put_bytes(STATE, ramp(0x1100, 0x21))
        memory.write(STATE + self.copy.dex_list, 8, DEXES)
        memory.write(STATE + self.copy.dex_list + 8, 8, w["dex_len"])
        if w["time"] is not None:
            for index, word in enumerate(w["time"]):
                memory.write(TIME_WORDS + index * 4, 4, word)
        row_at = ROWS
        for at, dex in enumerate(w["dexes"]):
            base = DEXES + at * DEX_STRIDE
            memory.put_bytes(base, ramp(DEX_STRIDE, 0x35 + at))
            memory.write(base + 0x10, 8, dex["count"])
            memory.write(base + 0x30, 8, dex["number"])
            memory.write(base + 0x68, 8, row_at)
            memory.write(base + 0x70, 8, dex["row_len"])
            memory.write(base + 0x230, 1, dex["mode"])
            for index, row in enumerate(dex["rows"]):
                memory.put_bytes(row_at, ramp(ROW_STRIDE, 0x47 + index))
                memory.write(row_at, 8, row["base"])
                memory.write(row_at + 0x40, 8, row["second"])
                memory.write(row_at + 0x50, 4, row["date"])
                memory.write(row_at + 0x54, 4, row["secs"])
                memory.write(row_at + 0x58, 4, row["frac"])
                row_at += ROW_STRIDE

    def write_map(self, at, pairs):
        memory = self.machine.memory
        keys, leaves = tree_rows(pairs)

        def node(where, rows, edges):
            memory.put_bytes(where, ramp(NODE_SIZE, 0x19))
            for index in range(NODE_CAPACITY):
                memory.write(where + NODE_KEYS + index * 8, 8, rows[index][0] if index < len(rows) else self.w.get("filler", TEMPTING))
                memory.write(where + NODE_VALUES + index * 8, 8, rows[index][1] if index < len(rows) else 0x7E7E7E)
            memory.write(where + NODE_LENGTH, 2, len(rows))
            for index in range(NODE_CAPACITY + 1):
                memory.write(where + NODE_EDGES + index * 8, 8, edges[index] if index < len(edges) else UNMAPPED + index * 8)
        edges = [at + (index + 1) * NODE_SIZE for index in range(len(leaves))]
        node(at, keys, edges)
        for where, leaf in zip(edges, leaves):
            node(where, leaf, [])
        return at, 1 if leaves else 0

    def pred_world(self, w):
        memory = self.machine.memory
        memory.put_bytes(DEXES, ramp(DEX_STRIDE, 0x2D))
        memory.put_bytes(CAP_MAP, ramp(0x40, 0x37))
        memory.write(DEXES + 0x10, 8, w["sum_end"])
        memory.write(DEXES + 0x68, 8, ROWS)
        memory.write(DEXES + 0x70, 8, w["row_len"])
        memory.write(DEXES + 0x1B0, 8, w["total_cap"])
        memory.write(DEXES + 0x208, 8, CAP_MAP)
        memory.write(DEXES + 0x230, 1, w["mode"])
        if w["mode"] == 3:
            pairs = sorted(w["set"])
            if pairs:
                self.brk = max(self.brk, HEAP_FREE)
                root, height = self.place(SET_SHAPE, [(key.to_bytes(8, "little"), None) for key in pairs], None, 0, 0xFFFF)
                memory.write(DEXES + 0x1E8, 8, root)
                memory.write(DEXES + 0x1F0, 8, height)
            else:
                memory.write(DEXES + 0x1E8, 8, 0)
                memory.write(DEXES + 0x1F0, 8, 2)
            return
        if w["caps_empty"]:
            memory.write(CAP_MAP + 0x30, 8, 0)
            memory.write(CAP_MAP + 0x38, 8, 2)
        else:
            root, height = self.write_map(CAP_NODES, sorted(w["caps"].items()))
            memory.write(CAP_MAP + 0x30, 8, root)
            memory.write(CAP_MAP + 0x38, 8, height)
        if w["sizes_empty"]:
            memory.write(DEXES + 0x170, 8, 0)
            memory.write(DEXES + 0x178, 8, 2)
        else:
            root, height = self.write_map(SIZE_NODES, sorted(w["sizes"].items()))
            memory.write(DEXES + 0x170, 8, root)
            memory.write(DEXES + 0x178, 8, height)
        for index, price in enumerate(w["row_prices"]):
            memory.put_bytes(ROWS + index * ROW_STRIDE, ramp(ROW_STRIDE, 0x49))
            memory.write(ROWS + index * ROW_STRIDE + 0x20, 8, price)

    def run(self, case):
        w = case.world
        machine = self.machine
        memory = machine.memory
        if self.copy is not COPIES[case.copy]:
            self.select(COPIES[case.copy])
        self.events = []
        self.w = w
        self.grows = 0
        self.instants = 0
        self.live = {}
        memory.reset(self.brk - HEAP_BASE)
        self.brk = HEAP_FREE
        answer = {"events": self.events, "stop": None}
        try:
            if case.kind == "sweep":
                self.sweep_world(w)
                memory.write(VEC_WORD, 8, w["rcx"])
                machine.run(self.copy.sweep, {RDI: BOOK, RSI: w["ref"], RDX: w["rdx"], RCX: w["rcx"]})
                answer["grows"] = self.grows
                answer["leaked"] = len(self.live)
            elif case.kind == "host":
                self.host_world(w)
                answer["done"] = False
                self.real.stubs = self.real.stubs | {self.copy.sweep}
                try:
                    machine.run(self.copy.host, {RDI: GATE, RSI: STATE, RDX: TIME_WORDS})
                except Finished:
                    answer["done"] = True
                finally:
                    self.real.stubs = self.real.stubs - {self.copy.sweep}
                answer["leaked"] = len(self.live)
            else:
                self.pred_world(w)
                rax = machine.run(PREDICATE, {RDI: DEXES, RSI: w["asset"]})
                answer["out"] = bool(rax & 0xFF)
        except Panicked as stop:
            answer["stop"] = stop.args[0]
            answer.pop("grows", None)
            answer.pop("out", None)
            answer.pop("leaked", None)
        return answer


def normal(case, spec):
    """Stop words in the same shape on both sides."""
    if spec["stop"]:
        if spec["stop"][0] == "unwrap":
            spec = dict(spec, stop=("unwrap", spec["stop"][1] if len(spec["stop"]) > 1 else LOC_PRED_UNWRAP, 0x2B))
        spec = {key: value for key, value in spec.items() if key not in ("grows", "out", "leaked")}
        if case.kind == "host":
            spec = dict(spec, done=False)
            if case.copy:
                swap = {LOC_ROW_BOUND: LOC_ROW_BOUND_OTHER, LOC_ID_MUL: LOC_ID_MUL_OTHER}
                spec = dict(spec, stop=tuple(swap.get(word, word) for word in spec["stop"]))
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

def user_id(number):
    return bytes((number * 29 + index * 13 + 5) & 0xFF for index in range(USER_SIZE))


def slot(px, side=0, oid=0, state=0):
    return {"px": px, "side": side, "oid": oid, "state": state}


def sweep_world(rows, ref=1000000, users=None, **fields):
    """rows: (px, side), one order per row, each its own slab slot, oid 501 + 3 * index, held by user 1."""
    slab = [slot(px, side, 501 + 3 * index) for index, (px, side) in enumerate(rows)]
    table = {row["oid"]: index for index, row in enumerate(slab)}
    users = [{"user": user_id(1), "first": list(range(len(rows))), "second": []}] if users is None else users
    w = {"slab": slab, "slab_len": len(slab), "hash": table, "hash_items": len(table), "users": users, "user_len": len(users), "ref": ref, "rdx": CTX_WORD, "rcx": VEC_WORD}
    w.update(fields)
    return w


def sweep_cases():
    rows = []

    def add(label, world):
        rows.append((label, world))
    ref = 1000000
    for px, name in ((1010000, "exactly 1 percent over"), (1010001, "one over"), (1009999, "one under"), (1009000, "0.9 percent over"), (1020000, "2 percent over"), (ref, "at the reference"), (990000, "1 percent under"), (989999, "one under 99"), (990001, "one over 99"), (980000, "2 percent under"), (1, "tiny"), (1 << 63, "top bit"), (MASK[8], "u64 max"), (0, "zero price")):
        for side in (0, 1):
            add("%s side %d" % (name, side), sweep_world([(px, side)], ref))
    for ref_value, px, name in ((100, 101, "101 over 100"), (100, 99, "99 over 100"), (200, 202, "202 over 200"), (1000, 1010, "1010 over 1000"), (7, 8, "small ref"), (MASK[8], 1, "ref u64 max"), ((1 << 53) + 2, (1 << 53) + 2 + (1 << 47), "above 2 to 53"), (1 << 40, (1 << 40) + (1 << 33) + 3, "low bits"), (3 << 32, 5 << 32, "high words"), (0xFFFFFFFF, 0x1FFFFFFFF, "low word")):
        for side in (0, 1):
            add("%s side %d" % (name, side), sweep_world([(px, side)], ref_value))
    add("side 2 counts as nonzero", sweep_world([(980000, 2), (1020000, 0x80)], ref))
    for px, side, name in ((5, 0, "zero ref px 5 side 0"), (5, 1, "zero ref px 5 side 1"), (0, 0, "zero ref zero px side 0"), (0, 1, "zero ref zero px side 1")):
        add(name, sweep_world([(px, side)], 0))
    add("empty book", sweep_world([], users=[], user_len=0))
    add("user tree root missing but count kept", sweep_world([], users=[], user_len=3))
    add("count zero with a tree", sweep_world([(1020000, 0)], user_len=0))
    add("hash items zero", sweep_world([(1020000, 0)], hash_items=0))
    add("order vacant", dict(sweep_world([(1020000, 0), (1020000, 0)]), slab=[slot(1020000, 0, 501), slot(1020000, 0, 504, VACANT)]))
    add("second key absent from hash", sweep_world([(1020000, 0)], users=[{"user": user_id(1), "first": [0], "second": [999]}]))
    add("second key in hash", sweep_world([(1020000, 0), (1020000, 0)], users=[{"user": user_id(1), "first": [0], "second": [504]}]))
    add("second key equals first", sweep_world([(1020000, 0)], users=[{"user": user_id(1), "first": [0], "second": [501]}]))
    add("second tree only", sweep_world([(1020000, 0)], users=[{"user": user_id(1), "first": [], "second": [501]}]))
    add("both empty", sweep_world([(1020000, 0)], users=[{"user": user_id(1), "first": [], "second": []}, {"user": user_id(2), "first": [0], "second": []}]))
    add("first set index past slab", sweep_world([(1020000, 0)], users=[{"user": user_id(1), "first": [0, 1], "second": []}]))
    world = sweep_world([(1020000, 0), (1020000, 0)])
    world["slab_len"] = 1
    add("hash index past slab", dict(world, users=[{"user": user_id(1), "first": [0], "second": [504]}]))
    world = sweep_world([(1020000, 0), (1020000, 0)])
    world["hash"] = {501: 1, 504: 1}
    world["hash_items"] = 2
    add("hash gives another slot", world)
    world = sweep_world([(1020000, 0), (1000000, 0)])
    world["hash"] = {504: 0, 501: 1}
    add("hash swaps two slots", world)
    world = sweep_world([(1020000, 1), (1000000, 0)])
    add("price and side from the hash slot", dict(world, hash={501: 1, 504: 0}))
    for count in (2, 3, 5, 8, 9, 13, 21, 25):
        rows_in = [(1020000 if index % 2 else 980000, index % 3 == 0) for index in range(count)]
        add("%d orders" % count, sweep_world(rows_in, ref))
    add("all cancel 9 rows growth", sweep_world([(1020000, 0)] * 9))
    add("two cancels with the slab cleared after the first", sweep_world([(1020000, 0), (980000, 1), (1020000, 0)], clobber=True))
    for count in (2, 3, 7, 12, 13, 24):
        users = []
        rows_in = []
        for number in range(count):
            users.append({"user": user_id(number + 7), "first": [number], "second": []})
            rows_in.append((1020000 if number % 2 else 1000000, 0))
        add("%d users" % count, sweep_world(rows_in, ref, users=users))
    world = sweep_world([(1020000, 0), (1020000, 0), (1020000, 0)], users=[{"user": user_id(number + 7), "first": [number], "second": []} for number in range(3)])
    add("count below the tree stops early", dict(world, user_len=2))
    add("other context words", sweep_world([(1020000, 0)], rdx=0x123456789, rcx=VEC_WORD + 0x18))
    world = sweep_world([(1020000, 0), (1020000, 0), (1020000, 0)])
    world["slab"][0]["oid"] = 3 << 50
    world["slab"][1]["oid"] = (5 << 48) + 11
    world["slab"][2]["oid"] = MASK[8] - 2
    world["hash"] = {row["oid"]: index for index, row in enumerate(world["slab"])}
    add("large order ids", world)
    add("second tree key on a vacant slot", dict(sweep_world([(1020000, 0), (1020000, 0)], users=[{"user": user_id(1), "first": [0], "second": [504]}]), slab=[slot(1020000, 0, 501), slot(1020000, 0, 504, VACANT)]))
    add("state 3 is live", dict(sweep_world([(1020000, 0), (1020000, 0)]), slab=[slot(1020000, 0, 501, 3), slot(1020000, 0, 504, 1)]))
    add("state word past the low byte", dict(sweep_world([(1020000, 0)], users=[{"user": user_id(1), "first": [], "second": [501]}]), slab=[slot(1020000, 0, 501, 0x102)]))
    groups = {}
    pair = None
    for key in range(1000, 400000):
        hashed = fx_hash(key)
        mark = (hashed >> 57, hashed & 48)
        if mark in groups:
            pair = (groups[mark], key)
            break
        groups[mark] = key
    world = sweep_world([(1020000, 0), (1020000, 0)])
    world["slab"][0]["oid"], world["slab"][1]["oid"] = pair
    world["hash"] = {pair[0]: 0, pair[1]: 1}
    add("two ids with one tag in one group", world)
    world = sweep_world([(1020000, 0), (980000, 1), (1020000, 0), (1000000, 0)])
    world["hash"] = {**world["hash"], **{70000 + index * 11: 1 for index in range(58)}}
    world["hash_items"] = len(world["hash"])
    world["buckets"] = 64
    add("dense table", world)
    world = sweep_world([(1020000, 0)] * 5, users=[{"user": user_id(1), "first": [0, 1], "second": []}])
    world["slab"][4]["oid"] = 123456
    world["hash"] = {123456: 3, 123457: 0, 501: 0, 504: 1}
    add("table holds other keys", world)
    deep = [{"user": user_id(number + 7), "first": [number], "second": []} for number in range(20)]
    add("20 users height 2", sweep_world([(1020000, 0)] * 20, users=deep, user_height=2))
    return rows


def dex(number=0, count=2, row_count=None, mode=0, rows=None):
    rows = rows if rows is not None else [row(index) for index in range(count)]
    return {"number": number, "count": count, "row_len": len(rows) if row_count is None else row_count, "mode": mode, "rows": rows}


DATE = (2026 << 13) | (120 << 4) | 10


def row(index=0, date=DATE, secs=3600, frac=500, base=None, second=None):
    return {"base": 7000 + index if base is None else base, "second": 9000 + index if second is None else second, "date": date, "secs": secs, "frac": frac}


def host_world(dexes=None, hits=(0,), now=(DATE, 3700, 0), flag=1, dex_len=None):
    dexes = [dex()] if dexes is None else dexes
    return {"dexes": dexes, "hits": frozenset(hits), "time": now, "flag": flag, "dex_len": len(dexes) if dex_len is None else dex_len}


def host_cases():
    rows = []

    def add(label, world):
        rows.append((label, world))
    for flag in (0, 2, 0x81):
        add("gate byte %#x" % flag, host_world(flag=flag))
    add("no dex", host_world(dexes=[], hits=()))
    add("dex with no assets", host_world(dexes=[dex(count=0, rows=[])], hits=()))
    add("no hits", host_world(hits=()))
    add("one hit", host_world())
    add("all hits", host_world(hits=(0, 1)))
    add("second dex", host_world(dexes=[dex(0), dex(1, count=3)], hits=(1, 10000, 10002)))
    add("eight hits grow the id list", host_world(dexes=[dex(count=9)], hits=range(9)))
    add("mode 3 takes the first word", host_world(dexes=[dex(mode=3)], now=(DATE + (9 << 4), 0, 0)))
    add("mode 3 fresh time", host_world(dexes=[dex(mode=3)]))
    add("mode 2 is not mode 3", host_world(dexes=[dex(mode=2)]))
    add("mode 7 is not mode 3", host_world(dexes=[dex(mode=7)]))
    limit = 3600 + 1800
    for name, now, in (("equal to the limit", (DATE, limit, 500)), ("one nano past", (DATE, limit, 501)), ("one nano before", (DATE, limit, 499)), ("one second past", (DATE, limit + 1, 0)), ("one second before", (DATE, limit - 1, 999)), ("next day", (DATE + (1 << 4), 0, 0)), ("previous day", (DATE - (1 << 4), 86399, 0)), ("next year word", (DATE + (1 << 13), 0, 0)), ("old year word", (DATE - (1 << 13), 86399, 999))):
        add("time " + name, host_world(now=now))
    wrap = dex(rows=[row(0, secs=86000, frac=7), row(1)])
    for name, now in (("before the wrap", (DATE, 86399, 0)), ("next day inside", (DATE + (1 << 4), 1399, 0)), ("next day edge", (DATE + (1 << 4), 1400, 7)), ("next day past", (DATE + (1 << 4), 1400, 8)), ("next day second past", (DATE + (1 << 4), 1401, 0))):
        add("wrap " + name, host_world(dexes=[wrap], now=now))
    add("bound hit on a short row list", host_world(dexes=[dex(count=2, row_count=1, rows=[row(0)])], hits=(1,)))
    add("bound hit in mode 3", host_world(dexes=[dex(count=2, row_count=1, mode=3, rows=[row(0)])], hits=(1,)))
    add("dex number past the list", host_world(dexes=[dex(1, count=1, rows=[row(0)])], hits=(10000,)))
    add("mode 3 second dex", host_world(dexes=[dex(0, count=1, rows=[row(0)]), dex(1, count=3, mode=3)], hits=(10002,)))
    add("second dex stale time", host_world(dexes=[dex(0, count=1, rows=[row(0)]), dex(1, count=3)], hits=(10002,), now=(DATE + (9 << 4), 0, 0)))
    add("id product overflow", host_world(dexes=[dex(((1 << 64) // 10000) + 1, count=1, rows=[row(0)])], hits=()))
    return rows


def caps_world(asset=5, caps=None, sizes=None, prices=None, total_cap=100000, total=10, mode=0, **fields):
    prices = [100 + index for index in range(8)] if prices is None else prices
    w = {"asset": asset, "caps": {5: 1000} if caps is None else caps, "caps_empty": False, "sizes": {5: 3} if sizes is None else sizes, "sizes_empty": False,
         "row_prices": prices, "row_len": len(prices), "total_cap": total_cap, "sum": total, "sum_end": 8, "mode": mode, "set": ()}
    w.update(fields)
    return w


def pred_cases():
    rows = []

    def add(label, world):
        rows.append((label, world))
    add("mode 3 empty set", caps_world(mode=3))
    add("mode 3 member", caps_world(mode=3, set=(5,)))
    add("mode 3 absent", caps_world(mode=3, set=(4, 6)))
    add("mode 3 below all", caps_world(mode=3, set=(6, 7)))
    add("mode 3 above all", caps_world(mode=3, set=(1, 2)))
    for count in (9, 14, 23, 31):
        add("mode 3 tree of %d member" % count, caps_world(mode=3, asset=100, set=tuple(range(90, 90 + count))))
        add("mode 3 tree of %d absent" % count, caps_world(mode=3, asset=89, set=tuple(range(90, 90 + count))))
        add("mode 3 tree of %d high" % count, caps_world(mode=3, asset=500, set=tuple(range(90, 90 + count))))
    for mode in (1, 2, 4):
        add("mode %d is not the set" % mode, caps_world(mode=mode))
    add("caps empty, sum under", caps_world(caps_empty=True))
    add("asset not in caps", caps_world(asset=4))
    add("asset over caps keys", caps_world(asset=6))
    add("many caps found", caps_world(asset=7, caps={index: 1000 for index in range(30)}, sizes={7: 3}, prices=[100] * 8))
    add("many caps found high", caps_world(asset=7, caps={index - 20: 0 for index in range(21, 28)} | {index: 1000 for index in range(8, 30)}, sizes={7: 3}, prices=[100] * 8))
    add("last key of a full set node", caps_world(mode=3, asset=11, set=tuple(range(1, 12))))
    add("last key of a full cap node", caps_world(asset=7, caps={index: 1000 for index in range(1, 8)}, sizes={7: 900}, prices=[1] * 8))
    add("last size of a full node", caps_world(asset=7, caps={7: 1000}, sizes={index: 901 for index in range(1, 8)}, prices=[1] * 8))
    add("set filler equal to the key", caps_world(mode=3, asset=9, set=(1, 2), filler=9))
    add("cap filler equal to the key", caps_world(asset=5, caps={1: 7}, filler=5, total_cap=1000000))
    add("size filler equal to the key", caps_world(asset=5, caps={5: 1000}, sizes={1: 9}, filler=5))
    add("low filler set", caps_world(mode=3, asset=9, set=(1, 2), filler=0))
    add("low filler caps", caps_world(asset=5, caps={1: 7}, filler=0))
    add("low filler sizes", caps_world(asset=5, caps={5: 1000}, sizes={1: 9}, filler=0))
    add("price negative, sizes empty", caps_world(sizes_empty=True, prices=[0, 0, 0, 0, 0, 1 << 63, 0, 0]))
    add("product overflow, sizes empty is zero", caps_world(sizes_empty=True, prices=[0, 0, 0, 0, 0, (1 << 63) - 1, 0, 0]))
    add("huge asset id", caps_world(asset=(1 << 60) * 15 // 10000 * 10000 + 5, caps={(1 << 60) * 15 // 10000 * 10000 + 5: 1000}, sizes={(1 << 60) * 15 // 10000 * 10000 + 5: 9}, prices=[1, 2, 3, 4, 5, 101, 7, 8]))
    add("many caps absent", caps_world(asset=300, caps={90 + index: 1000 for index in range(30)}, prices=[100] * 8))
    # cap 1000 floors to 900, price 105 at index 5
    add("product just over", caps_world(sizes={5: 9}, prices=[1, 2, 3, 4, 5, 101, 7, 8]))
    add("product equal to the cap floor", caps_world(sizes={5: 9}, prices=[1, 2, 3, 4, 5, 100, 7, 8]))
    add("product just under", caps_world(sizes={5: 9}, prices=[1, 2, 3, 4, 5, 99, 7, 8]))
    add("size missing", caps_world(sizes={4: 9}, prices=[100] * 8))
    add("sizes empty", caps_world(sizes_empty=True))
    add("many sizes", caps_world(asset=7, caps={7: 1000}, sizes={index: index + 1 for index in range(30)}, prices=[9] * 8))
    add("many sizes high", caps_world(asset=7, caps={7: 1000}, sizes={index + 8: index + 1 for index in range(30)}, prices=[9] * 8))
    add("size key above", caps_world(asset=5, sizes={6: 1000}))
    add("price negative", caps_world(prices=[0, 0, 0, 0, 0, 1 << 63, 0, 0]))
    add("price max positive", caps_world(prices=[0, 0, 0, 0, 0, (1 << 63) - 1, 0, 0], sizes={5: 1}, caps={5: 1 << 62}))
    add("product overflow", caps_world(prices=[0, 0, 0, 0, 0, 1 << 62, 0, 0], sizes={5: 2}))
    add("product wraps negative word", caps_world(prices=[0, 0, 0, 0, 0, 1 << 61, 0, 0], sizes={5: 5}))
    add("size top bit", caps_world(prices=[0, 0, 0, 0, 0, 1, 0, 0], sizes={5: 1 << 63}))
    add("price zero", caps_world(prices=[0] * 8))
    add("cap top bit panics", caps_world(caps={5: 1 << 63}))
    add("cap zero", caps_world(caps={5: 0}))
    add("cap zero, product zero", caps_world(caps={5: 0}, sizes={5: 0}))
    add("cap i64 max", caps_world(caps={5: (1 << 63) - 1}))
    add("cap large rounds", caps_world(caps={5: (1 << 53) + 1}, prices=[0, 0, 0, 0, 0, 1, 0, 0], sizes={5: cap_floor((1 << 53) + 1)}))
    add("row bound", caps_world(asset=8))
    add("row bound one less", caps_world(asset=7, caps={7: 1000}))
    add("local index of a dex", caps_world(asset=20005, caps={20005: 1000}, sizes={20005: 9}, prices=[1, 2, 3, 4, 5, 101, 7, 8]))
    add("local index at the bound", caps_world(asset=20008, caps={20008: 1000}))
    add("sum none", caps_world(total=None))
    add("sum none, no cap row", caps_world(caps_empty=True, total=None))
    add("sum just over", caps_world(total_cap=1000, total=901))
    add("sum equal", caps_world(total_cap=1000, total=900))
    add("sum just under", caps_world(total_cap=1000, total=899))
    add("sum zero", caps_world(total=0, total_cap=0))
    add("sum negative word", caps_world(total=(1 << 64) - 5, total_cap=0))
    add("sum over, cap zero", caps_world(total=1, total_cap=0))
    add("total cap top bit panics", caps_world(total_cap=1 << 63))
    add("total cap i64 max", caps_world(total_cap=(1 << 63) - 1, total=(1 << 63) - 1))
    add("sum end word", caps_world(sum_end=0x1234))
    return rows


def all_cases():
    cases = []
    for index, copy in enumerate(COPIES):
        cases += [Case("%s: %s" % (copy.name, label), "sweep", world, index) for label, world in sweep_cases()]
        cases += [Case("%s: %s" % (copy.name, label), "host", world, index) for label, world in host_cases()]
    cases += [Case("predicate: %s" % label, "pred", world) for label, world in pred_cases()]
    return cases


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



GROUPS = tuple((copy.sweep, "sweep, %s copy" % copy.name, None) for copy in COPIES[:1]) + tuple((copy.host, "step up to its timing tail, %s copy" % copy.name, HOST_STOP) for copy in COPIES[:1]) + ((PREDICATE, "at-cap test", None),)


def group_rows(image, start, stop):
    begin, end = image.exact_fde(start)
    return begin, begin + stop if stop else end, end


def mutated_groups(image):
    """(function start, role, decoded rows)."""
    groups = []
    for start, role, stop in GROUPS:
        begin, limit, _ = group_rows(image, start, stop)
        groups.append((start, role, decode_range(image, begin, limit)))
    return groups


def run_mutants(image, reached, costs, verbose=False):
    """A mutant only changes a run that reaches its instruction, so only those cases run; large trees run only for rows nothing smaller reaches."""
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
            if indices:
                indices = [index for index in indices if costs[index] <= HEAVY_STEPS] or indices
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

SWEEP_ANCHORS = (
    ("mov rax, [rdi+0xb8]", 0x3C, "488b87b8000000"),
    ("mov rdx, [rdi+0xc8]", 0x43, "488b97c8000000"),
    ("cmp dword [rax+rcx], 2", 0x529, "833c0802"),
    ("movsd xmm1, [rax+0xa0]", 0x536, "f20f1088a0000000"),
    ("cmp byte [rax+0xc2], 0", 0x56A, "80b8c200000000"),
    ("mov r9d, 8", 0xB03, "41b908000000"),
)
FIELDS = {
    "state": {"+0x5c0/+0x5c8": "dex row list pointer and length in the first and third copies, stride 0x2f0", "+0x1040/+0x1048": "the same list in the second copy"},
    "dex_row": {"+0x10": "asset count", "+0x30": "dex number, asset id = dex * 10000 + index", "+0x68/+0x70": "asset row pointer and length, stride 0x60", "+0x170/+0x178": "map asset to size: root, height", "+0x1b0": "total cap, i64", "+0x1e8/+0x1f0": "mode 3 set of assets: root, height", "+0x208": "pointer to a block with the asset cap map at +0x30/+0x38", "+0x230": "mode byte"},
    "asset_row": {"+0x00": "price word used when the +0x40 word is stale, and always in mode 3", "+0x20": "price in the at-cap test", "+0x40": "price word used while block time <= stored time + 1800 s", "+0x50/+0x54/+0x58": "stored time: date, seconds, nanoseconds"},
    "book": {"+0x08/+0x10": "slab pointer and length", "+0x28/+0x30/+0x40": "hash map control, mask, items", "+0xb8/+0xc0/+0xc8": "user tree root, height, length"},
    "slab_slot": {"+0x00": "state, 2 = vacant", "+0xa0": "limit price, u64", "+0xc2": "side byte", "+0xd8": "order id"},
}
REFERENCE_CLAIMS = (
    {"reference": "l1/ (whole tree)", "claim": "no text cancel_aggressive_orders_at_oi_cap and no function that cancels resting orders by distance from a price", "observed": "the step name is at 0x3efab7 and the sweep is 0x26e48c0", "verdict": "missing in the reference"},
    {"reference": "l1/clearinghouse/clearinghouse.rs:614", "claim": "collect_perps_at_open_interest_cap walks open_interest_by_asset and skips size 0", "observed": "0x2228130 walks every asset index of every dex row and asks 0x3713f20; a missing size counts as 0 and the total test still runs", "verdict": "shape differs"},
)
HEAVY_STEPS = 3000


def fixed_text(image, va, size):
    return bytes(image.blob[image.offset(va):image.offset(va) + size]).decode("ascii")


def read_double(image, va):
    return struct.unpack_from("<d", image.blob, image.offset(va))[0]


def status_names(image):
    """Follow the jump table of the status serializer: byte value to name."""
    start, end = image.exact_fde(STATUS_FN)
    base = image.offset(STATUS_TABLE)

    def read(va, count):
        at = image.offset(va)
        return bytes(image.blob[at:at + count])

    rows = []
    while True:
        arm = STATUS_TABLE + struct.unpack_from("<i", image.blob, base + len(rows) * 4)[0]
        if not start <= arm < end:
            break
        row = decode(read, arm)
        if row.op != "lea" or row.a != ("r", RSI) or row.b[1] is not None:
            raise EvidenceError("status arm %#x" % arm)
        following = decode(read, row.next)
        if following.op == "jmp":
            following = decode(read, following.target)
        if following.op != "mov" or following.a != ("r", RDX) or following.b[0] != "i":
            raise EvidenceError("status arm length %#x" % arm)
        rows.append(read(row.b[4], following.b[1]).decode("ascii"))
    return rows


def step_rows(image):
    """In each caller: the name, its length, the bucket gate and the fields behind it, by exact byte patterns before the call."""
    rows = []
    for copy in COPIES:
        window = bytes(image.blob[image.offset(copy.site - 0xB0):image.offset(copy.site)])
        at = window.rfind(b"\x48\xc7\x44\x24\x28\x22\x00\x00\x00")
        lea = at - 12
        if at < 0 or window[lea:lea + 3] != b"\x48\x8d\x05":
            raise EvidenceError("name bytes before %#x" % copy.site)
        name = copy.site - 0xB0 + lea + 7 + struct.unpack_from("<i", window, lea + 3)[0]
        if fixed_text(image, name, STEP_NAME_SIZE) != "cancel_aggressive_orders_at_oi_cap":
            raise EvidenceError("name address %#x" % name)
        limits_at = window.find(b"\x0f\x28\x05", at)
        limits = copy.site - 0xB0 + limits_at + 7 + struct.unpack_from("<i", window, limits_at + 3)[0]
        if (read_double(image, limits), read_double(image, limits + 8)) != (0.01, 0.05) or b"\x0f\x97\x44\x24\x40" not in window or b"\x48\xf7\xf1" not in window:
            raise EvidenceError("gate bytes before %#x" % copy.site)
        period = re.search(rb"\x48\x8b\x89(....)", window, re.S)
        bucket = re.search(rb"\x49\x8b\x8d(....)", window, re.S)
        rows.append({"site": "%#x" % copy.site, "caller": "%#x" % copy.caller, "name": "%#x" % name, "period_field": "%#x" % struct.unpack("<I", period.group(1))[0], "bucket_field": "%#x" % struct.unpack("<I", bucket.group(1))[0]})
    return rows


def anchors(image):
    rows = []
    for copy in COPIES:
        for meaning, offset, wanted in SWEEP_ANCHORS:
            va = copy.sweep + offset
            data = bytes(image.blob[image.offset(va):image.offset(va) + len(wanted) // 2]).hex()
            if data != wanted:
                raise EvidenceError("sweep bytes at %#x: %s" % (va, data))
            rows.append({"va": "%#x" % va, "bytes": data, "meaning": meaning})
    return rows


def outcome_name(case, spec):
    if spec["stop"]:
        return "%s panic: %s" % (case.kind, spec["stop"][0])
    if case.kind == "sweep":
        return "sweep %s" % ("cancels" if spec["events"] else "cancels nothing")
    if case.kind == "pred":
        return "at-cap test %s" % ("true" if spec["out"] else "false")
    return "step %s" % ("sweeps" if any(event[0] == "sweep" for event in spec["events"]) else "no sweep")


def case_line(case, spec):
    return "%s\t%s\t%s" % (case.kind, case.label.replace(": ", "\t", 1), outcome_name(case, spec))


WORKED = ((101, 100, 0), (99, 100, 1), (1010000, 1000000, 0), (990000, 1000000, 1), (202, 200, 0), (1010, 1000, 0), (1009999, 1000000, 0), (5, 0, 0), (5, 0, 1), (0, 0, 0))


def worked_rows():
    rows = []
    for px, ref, side in WORKED:
        value = over_reference(px, ref, side)
        rows.append({"px": px, "reference": ref, "side": side, "value": "nan" if value != value else ("inf" if value == math.inf else ("-inf" if value == -math.inf else repr(value))), "cancelled": aggressive(px, ref, side)})
    return rows


def analyse(image, full=True, verbose=False):
    cases = all_cases()
    harness = Harness(image)
    mismatches = []
    outcomes = {}
    reached = []
    seen = set()
    lines = []
    machine = harness.machine
    costs = []
    for case in cases:
        machine.seen = set()
        before = machine.steps
        trouble = compare_run(harness, case)
        costs.append(machine.steps - before)
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
    for start, role, stop in GROUPS:
        begin, limit, end = group_rows(image, start, stop)
        rows = decode_range(image, begin, limit)
        functions.append({"role": role, "start": "%#x" % begin, "end": "%#x" % end, "evaluated_to": "%#x" % limit, "size": end - begin, "instructions": len(rows), "instructions_stepped": sum(1 for row_ in rows if row_.va in seen)})
    relative = harness.relative
    if relative.get(SLOT_PREDICATE) != PREDICATE:
        raise EvidenceError("predicate slot")
    site_rows = []
    targets = tuple(sorted({copy.host for copy in COPIES} | {copy.sweep for copy in COPIES}))
    direct = direct_sites(image, targets)
    for target in sorted(direct):
        for va, opcode in sorted(direct[target]):
            site_rows.append((target, va, "rel32 %#x" % opcode, image.fde(va)[0], image.fde(va)[1]))
    for va in slot_sites(image, SLOT_PREDICATE):
        site_rows.append((PREDICATE, va, "slot", image.fde(va)[0], image.fde(va)[1]))
    names = status_names(image)
    if names[STOP_REASON] != "openInterestCapCanceled":
        raise EvidenceError("status name %s" % names[STOP_REASON])
    locations = []
    for slot, name in ((LOC_ROW_BOUND, "asset row bound in the step, first copy"), (LOC_ROW_BOUND_OTHER, "asset row bound in the step, other copies"), (LOC_PRED_BOUND, "asset row bound in the at-cap test"), (LOC_PRED_UNWRAP, "negative cap in the at-cap test"), (LOC_DEX_UNWRAP, "dex index in the step")):
        path, line, column = image.location(slot, relative)
        locations.append({"slot": "%#x" % slot, "name": name, "path": path, "line": line, "column": column})
    step_name = fixed_text(image, STEP_NAME, STEP_NAME_SIZE)
    if step_name != "cancel_aggressive_orders_at_oi_cap":
        raise EvidenceError("step name")
    doubles = {"ratio": read_double(image, RATIO), "added": read_double(image, MINUS_ONE), "cap_factor": read_double(image, CAP_FACTOR), "step_first_limit": read_double(image, STEP_LIMITS), "step_second_limit": read_double(image, STEP_LIMITS + 8)}
    if doubles["ratio"] != 0.01 or doubles["added"] != -1.0 or doubles["cap_factor"] != 0.9:
        raise EvidenceError("doubles")
    steps_table = step_rows(image)
    byte_rows = anchors(image)
    results_rows = run_mutants(image, reached, costs, verbose) if full else []
    tally = {key: sum(1 for row_ in results_rows if row_["result"] == key) for key in ("killed", "survived", "unreached")}
    return {
        "target": {"file": "artifacts/node/94/hl-node", "sha256": SHA256},
        "functions": functions,
        "step_name": step_name,
        "step_sites": steps_table,
        "doubles": doubles,
        "status_names": {"%d" % index: name for index, name in enumerate(names)},
        "reason": {"value": STOP_REASON, "name": names[STOP_REASON]},
        "sweep_bytes": byte_rows,
        "locations": locations,
        "fields": FIELDS,
        "worked_boundaries": worked_rows(),
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
    if row["result"] == "unreached":
        return "no case reaches it: eight level descent arms, a drain arm that needs a set length above its items, a two level free, or an unwind pad"
    return "not separated by the case list: an iterator state word, a compare with height 8, a free size, a dangling pointer word or a finite guard; no claim rests on this row"


def render(evidence):
    evidence = dict(evidence)
    sites = evidence.pop("_sites")
    results = evidence.pop("_results")
    case_lines = evidence.pop("_lines")
    files = {"evidence.json": (json.dumps(evidence, indent=2, sort_keys=True) + "\n").replace("\x40", "[at]")}
    lines = ["target\tsite\tcall\tcaller_fde\tcaller_fde_end"]
    lines += ["%#x\t%#x\t%s\t%#x\t%#x" % row_ for row_ in sites]
    files["call_sites.tsv"] = "\n".join(lines) + "\n"
    files["cases.tsv"] = "\n".join(["kind\tcopy\tlabel\toutcome"] + case_lines) + "\n"
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
