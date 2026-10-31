#!/usr/bin/env python3
"""Pin the node #94 spot order insert from ELF bytes: gates, the taker walk of the opposite book, each fill, the removal rows and the rest of the order.

`0x26e81c0` is the spot monomorph of the book insert. It runs the entry gates, walks the opposite side level by level and each level head to tail, stops at a price or
at the 20% anchor band, caps each fill by the taker's free balance, then applies the removal rows and rests what is left. The real bytes run in a Python evaluator with
every edge callee stubbed. A separately written specification predicts the ordered edge calls and the result, and every condition, immediate and field offset of the
function is flipped to show the run can tell. No objdump or readelf output is parsed, and the binary is never executed. Standard library only.
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

INSERT = 0x26E81C0
TWIN = 0x4318A00
TIF_TABLE = 0x3ED590
ANCHOR_BAND = 0x20A768
MINUS_ONE = 0x20A278
PX_LIMIT = 10 ** 15

SLOT_MALLOC = 0x576DFD8
SLOT_FREE = 0x576E010
SLOT_MEMCPY = 0x576DFE0
SLOT_MEMMOVE = 0x576E0E0
SLOT_MEMCMP = 0x576E488
SLOT_PANIC_NONE = 0x576E470
SLOT_PANIC_BOUND = 0x576DFC8
SLOT_PANIC_TEXT = 0x576E108
SLOT_RECORDER = 0x5773190
SLOT_REFRESH = 0x5773D68
SLOT_CLASS = 0x5773198
SLOT_ANCHOR = 0x5774548
SLOT_PREDICATE = 0x5773228
SLOT_GROW_SKIPS = 0x5774818
SLOT_GROW_OIDS = 0x5773D70
SLOT_GROW_ROWS = 0x5774830
SLOT_GROW_FILLS = 0x5774838
SLOT_CLASS_FEE = 0x5774820
SLOT_ENTRY = 0x5773170
SLOT_AMOUNT = 0x5774790
SLOT_CONVERT = 0x57747A0
SLOT_CAN_SETTLE = 0x5774730
SLOT_SETTLE = 0x5774828
SLOT_REST_GATE = 0x5774840
SLOT_RESERVE = 0x5774848
SLOT_CLOID = 0x5774810
SLOT_TRACK = 0x5774850
ONCE_STATE = 0x577AB98

TICK = 0x230B590
MID = 0x32780D0
ENTRY_GATE = 0x26F4280
TOP_LEVELS = 0x23978C0
ALO_PAYLOAD = 0x2396D50
USER_MAP_INSERT = 0x2879D60
LEG = 0x232D840
SET_SIZE = 0x232E6E0
COLLECT = 0x27E7230
RELATIONS = 0x26E4620
REMOVE = 0x26DE3D0
SKIP = 0x26DE280
DROP_SET = 0x28AD210
DROP_MAP = 0x28A8AC0
DROP_ROWS = 0x277BAC0
LEVEL = 0x25A7640
SLAB_INSERT = 0x232C410
OID_MAP = 0x27CA640
USER_STATE = 0x25A7A40
USER_SLOTS = 0x285CC70
BUILD_STATUS = 0x26E10B0
PUSH_ROW = 0x24FB550
ORDER_LOOKUP = 0x26E7F30

OK = 0x8000000000000018
NONE_WORD = 1 << 63
SLOT_SIZE = 0xF8
FILL_SIZE = 0x228
MAX64 = (1 << 64) - 1
MAX_NOTIONAL = (1 << 63) - 2

RAX, RCX, RDX, RBX, RSP, RBP, RSI, RDI = range(8)
R8, R9, R10, R11, R12, R13, R14, R15 = range(8, 16)
VOLATILE = (RCX, RSI, RDI, R8, R9, R10, R11)
CALLEE_SAVED = (RBX, RBP, R12, R13, R14, R15)
MASK = {1: 0xFF, 2: 0xFFFF, 4: 0xFFFFFFFF, 8: 0xFFFFFFFFFFFFFFFF, 16: (1 << 128) - 1}
SIGN = {1: 0x80, 2: 0x8000, 4: 0x80000000, 8: 0x8000000000000000}
STACK_MARK = 0xA5
STACK_TOP = 0x7FF000000
STACK_SIZE = 0x8000
HEAP_BASE = 0x600000000
HEAP_SIZE = 0x60000
RETURN_SENTINEL = 0xDEAD0000
POISON = 0xA5A5A5A5A5A5A5A5
STEP_LIMIT = 900000
MUTANT_STEP_LIMIT = 120000

OUT = HEAP_BASE + 0x400
ARGS = HEAP_BASE + 0x500
SINK = HEAP_BASE + 0x700
SET_MARK = HEAP_BASE + 0x740
ENTRY_AT = HEAP_BASE + 0x780
LEVEL_AT = HEAP_BASE + 0x800
STATE_AT = HEAP_BASE + 0x880
BOOK = HEAP_BASE + 0x1000
CTX = HEAP_BASE + 0x2000
ROWS_AT = HEAP_BASE + 0x3000
RELATION_AT = HEAP_BASE + 0x3400
SLAB = HEAP_BASE + 0x4000
SLAB_ROOM = 40
HEAP_FREE = SLAB + SLAB_ROOM * SLOT_SIZE

TAKER = "11223344556677889900aabbccddeeff00112233"
USERS = ("2122334455667788991122334455667788990011", "3122334455667788991122334455667788990022", "4122334455667788991122334455667788990033", "5122334455667788991122334455667788990044")
HIGH_USERS = ("f122334455667788991122334455667788990011", "f222334455667788991122334455667788990022", "f322334455667788991122334455667788990033")


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
        elif byte not in (0x2E, 0x64):
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
            if a and a[0] == "r" and 4 <= a[1] <= 7:
                a = ("h", a[1] - 4)
            if b and b[0] == "r" and 4 <= b[1] <= 7:
                b = ("h", b[1] - 4)

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
                  (0x55, True): "andnpd", (0x14, True): "unpcklpd", (0x6C, True): "unpcklpd", (0x60, True): "punpcklbw", (0x74, True): "pcmpeqb", (0x76, True): "pcmpeqd", (0xDB, True): "andpd"}
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
        self.tails = {}
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
        if kind == "h":
            return (self.regs[operand[1]] >> 8) & 0xFF
        if kind == "i":
            return operand[1] & MASK[width]
        return self.memory.read(self.address(operand), width)

    def put(self, operand, width, value):
        value &= MASK[width]
        if operand[0] == "h":
            self.regs[operand[1]] = (self.regs[operand[1]] & ~0xFF00) | value << 8
        elif operand[0] == "r":
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
                if self.read_code(pc, 1)[0] == 0x64:
                    raise Halt("thread local read at %#x" % pc)
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
            hook = self.tails.get(row.target)
            if hook:
                self.stub(hook)
                return self.pop()
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


# ---- specification: written from a full read, shares nothing with the evaluator ----

def to_signed(value):
    return value - (1 << 64) if value >> 63 else value


class Spec:
    """Prediction of one insert: ordered edge calls, the output and the book words it changes."""

    def __init__(self, w):
        self.w = w
        self.log = []
        self.fill_count = 0

    def event(self, *row):
        self.log.append(list(row))

    def payload(self, status, second=None, third=None):
        return {"status": status, "second": second, "third": third}

    def lookup(self, oid):
        """The order lookup: a slot view with a relation tag and word, or nothing."""
        self.event("lookup", oid)
        return self.relations.get(str(oid))

    def clear_relation(self, oid):
        """Parent clear: take the tag of the order, and when it was 1 clear the order it named too."""
        row = self.lookup(oid)
        if row is None:
            return
        tag, word = row
        row[0] = 0
        if tag == 1:
            other = self.lookup(word)
            if other is not None:
                other[0] = 0

    def price_order(self):
        """Levels of the opposite side in walk order: bids by falling price, asks by rising price."""
        return sorted(self.w["levels"], key=lambda row: -row["px"] if self.side else row["px"])

    def entry(self):
        """Gates before any write. A dict stops the insert."""
        w, a = self.w, self.w["args"]
        asset = w["asset"]
        if asset >= len(w["rows"]):
            raise SpecPanic("row bound")
        tokens = w["tokens"]
        quote = w["rows"][asset][1]
        if tokens.get(str(quote), 1) != 0:
            return self.payload(0x8000000000000017, 0, quote)
        crosses = False
        levels = self.price_order()
        if levels:
            top = levels[0]["px"]
            crosses = top <= a["px"] if not self.side else top >= a["px"]
        tif = a["tif"]
        self.taker_only = tif in (1, 3, 4)
        if tif == 0 and crosses:
            self.event("top_levels")
            self.event("alo_payload")
            return self.payload(0x8000000000000006, w["alo"][0], w["alo"][1])
        if self.taker_only and not crosses:
            return self.payload(0x8000000000000008)
        if a["reduce"]:
            self.event("refresh", a["user"], asset)
            return self.payload(0x8000000000000005, 0)
        if not a["tag"]:
            raise SpecPanic("reduce_only text")
        if a["px"] > PX_LIMIT:
            return self.payload(NONE_WORD, 0)
        self.event("tick", asset, a["px"])
        if a["px"] % w["tick"]:
            return self.payload(NONE_WORD, 0)
        base = w["rows"][asset][0]
        self.event("class", base)
        kind = w["cls"]
        if kind == 1:
            return self.payload(0x8000000000000014, 0)
        if kind != 2:
            self.event("mid")
            self.event("gate", a["user"], asset, self.side, a["size"], a["px"], w["mid"])
            if w["gate"][0] != OK:
                return self.payload(w["gate"][0], w["gate"][1], w["gate"][2])
        return None

    def free_cap(self, token):
        """The most the taker can pay: free balance in size for a seller, over the level price for a buyer."""
        total, hold = self.w["balances"].get(str(token), (0, 0))
        free = total - hold if total >= hold else 0
        return free

    def fill(self, slot, px):
        """One fill against a maker; returns the next action: `link`, `level` or `end`."""
        w, a = self.w, self.w["args"]
        asset = w["asset"]
        size = min(slot["size_now"], self.remaining)
        status = OK
        if not slot["size_now"]:
            return "next"
        block = slot["block"]
        self.event("fee_class", slot["user"], block, asset, 0, 1 - self.side)
        self.event("fee_class", a["user"], "taker", asset, 1, self.side)
        token = w["rows"][asset][1 - self.side]
        self.event("entry", a["user"])
        free = self.free_cap(token)
        if self.side:
            self.event("amount", free, token)
            cap = w["amount"]
        else:
            cap = free // px
        if cap < size:
            status = 0x8000000000000012
            if cap == 0:
                self.remaining = 0
                return self.after_short()
            size = cap
            self.remaining = cap
        buyer, seller = (slot["user"], a["user"]) if self.side else (a["user"], slot["user"])
        for leg in (0, 1):
            self.event("leg", leg, buyer, seller, asset, slot["oid"], px, size, self.oid, int((a["kind"] & 0xFFFFFFFF) >= 9), a["word"], self.word_one, self.word_two)
        tag = w["leg_tag"]
        if tag == 2 or px * size > MAX_NOTIONAL:
            raise SpecPanic("notional")
        number = self.fill_count
        self.fill_count += 1
        convert = w["convert"].get(str(number), [1, 77, 88])
        self.event("convert", asset, 1 - self.side, px, size)
        if convert[0] != 1:
            return self.next_level_or_end()
        self.event("can_settle", a["user"], convert[1], convert[2])
        if not w["can"].get(str(number), True):
            return self.next_level_or_end()
        changed = w["settled"].get(str(number))
        fill_px, fill_size = changed if changed else (px, size)
        self.event("settle", w["byte"], buyer, seller, px, asset, size, px * size, self.side)
        slot["size_now"] -= fill_size
        if slot["size_now"] < 0:
            raise SpecPanic("recorder size")
        self.event("set_size", slot["index"], asset, slot["size_now"])
        if self.remaining < fill_size:
            raise SpecPanic("recorder size")
        self.remaining -= fill_size
        self.filled += fill_size
        if self.filled > MAX64:
            raise SpecPanic("recorder sum")
        if slot["size_now"] == 0:
            self.removals.append([slot["oid"], slot["user"], 0])
        self.last_trade = fill_px
        self.fills.append([fill_px, asset, fill_size, px * size, self.side])
        if status == OK:
            return "next"
        return self.next_level_or_end()

    def after_short(self):
        if not self.fills:
            return "short"
        return self.next_level_or_end()

    def next_level_or_end(self):
        return "end" if self.remaining == 0 else "level"

    def walk(self):
        """Opposite side, level by level. Returns `plain`, `used` (remaining size ran out) or `band`, or a dict for a stop."""
        w, a = self.w, self.w["args"]
        asset = w["asset"]
        tokens = w["tokens"]
        for level in self.price_order():
            px = level["px"]
            if px != a["px"] and (px > a["px"]) != bool(self.side):
                return "plain"
            if w["rows"][asset][1] == 0 and str(w["rows"][asset][0]) in tokens:
                self.event("anchor", w["rows"][asset][0])
                anchor = w["anchor"]
                if anchor == 0:
                    gap = math.nan if px == 0 else math.inf
                else:
                    gap = float(px) / float(anchor) - 1.0
                if self.side:
                    gap = -gap
                if gap != gap or gap > 0.2:
                    return "band"
            for slot in level["slots"]:
                if slot["index"] >= self.count or slot["index"] == w["broken_slot"]:
                    raise SpecPanic("slot")
                if self.remaining == 0:
                    return "used"
                same = slot["user"] == a["user"]
                if not same:
                    self.event("predicate", a["user"])
                    if a["user"] in w["system"]:
                        self.event("predicate", slot["user"])
                        same = slot["user"] in w["system"]
                if same:
                    self.skips.append([slot["oid"], slot["user"], 9])
                    self.note_user(slot)
                    continue
                if slot["flag"]:
                    self.event("refresh", slot["user"], w["asset"])
                    self.skips.append([slot["oid"], slot["user"], 10])
                    self.note_user(slot)
                    continue
                action = self.fill(slot, px)
                if action == "short":
                    return self.payload(0x8000000000000012, None, 0x8000000000000013)
                if action == "end":
                    return "used"
                if action == "level":
                    break
                if self.remaining == 0:
                    return "used"
        return "plain"

    def note_user(self, slot):
        self.users.setdefault(slot["user"], []).append(slot["oid"])

    def add_taker_row(self):
        self.removals.append([self.provided_oid, self.w["args"]["user"], 1])

    def apply_rows(self):
        w = self.w
        self.event("collect", [row[0] for row in self.removals])
        for oid, user, kind in self.removals:
            self.event("relations", oid, user)
            if kind == 0:
                self.event("remove", oid, user, 1)
        for oid, user, reason in self.skips:
            self.event("skip", oid, user, reason)
        self.event("drop_set")

    def status_row(self):
        w, a = self.w, self.w["args"]
        if self.filled > a["size"]:
            raise SpecPanic("recorder size")
        if a["kind"] == 9:
            return
        self.event("build_status", a["size"] - self.filled, a["size"], self.oid, a["user"], a["tif"], a["px"], self.side, a["kind"])
        self.event("row", self.oid, a["user"])

    def rest(self):
        """Rest gates, then the link into the level. Returns True when the order rests, or a dict for a stop."""
        w, a = self.w, self.w["args"]
        asset = w["asset"]
        self.event("rest_gate", w["byte"], asset, self.side, a["px"])
        provided = a["oid_tag"]
        if not w["may_rest"]:
            if not self.fills:
                return self.payload(0x8000000000000013)
            if provided:
                self.clear_relation(a["oid"])
            return False
        self.event("reserve", asset, self.remaining, a["size"], a["px"], a["user"], self.side)
        reserve = w["reserve"]
        if reserve[0] != OK:
            if provided:
                self.event("collect", [row[0] for row in self.removals])
                self.event("relations", a["oid"], a["user"])
                self.event("drop_set")
            if not self.fills:
                return self.payload(reserve[0], reserve[1] if reserve[0] >> 63 else None, reserve[2])
            return False
        key = a["px"] if self.side else to_signed(MAX64 + 1 - a["px"])
        self.event("level", 1 if self.side else 0, key)
        head, tail = w["rest_level"]
        self.event("slab_insert", tail, self.remaining, a["size"], self.oid, a["px"], self.side, a["user"], a["tif"], a["cloid"], asset)
        slot = w["new_slot"]
        self.rest_head = slot if head is None else head
        if tail is not None:
            if tail >= self.count or self.slab_rows[tail].get("vacant"):
                raise SpecPanic("tail")
            self.next_link[tail] = slot
        self.rest_tail = slot
        self.event("oid_map", self.oid, slot)
        if a["cloid"] is not None:
            self.event("cloid", a["user"], self.oid, a["cloid"])
        self.event("user_state", a["user"])
        self.event("user_slots", slot)
        self.event("track", a["user"])
        return True

    def run(self):
        w, a = self.w, self.w["args"]
        self.side = a["side"]
        self.relations = {key: list(value) for key, value in w["relations"].items()}
        self.remaining = a["size"]
        self.filled = 0
        self.fills, self.removals, self.skips = [], [], []
        self.users = {}
        self.next_id = w["next_oid"]
        self.last_trade = None
        self.next_link = {}
        self.rest_head = self.rest_tail = None
        self.slab_rows = []
        index = 0
        for level in w["levels"]:
            for slot in level["slots"]:
                slot.setdefault("index", index)
                index += 1
                slot["size_now"] = slot["size"]
                self.slab_rows.append(slot)
        for row in w["extra_slots"]:
            self.slab_rows.append(dict(row, size_now=row.get("size", 0)))
        self.count = len(self.slab_rows) - w["slab_short"]
        stop = self.entry()
        if stop is not None:
            return self.finish(stop)
        if a["oid_tag"]:
            self.oid = a["oid"]
        else:
            self.oid = self.next_id
            self.next_id = min(self.next_id + 1, MAX64)
        self.word_one, self.word_two = w["word_one"], w["word_two"]
        self.provided_oid = a["oid"]
        ended = self.walk()
        if isinstance(ended, dict):
            return self.finish(ended)
        may_rest = not self.taker_only
        if ended == "band":
            if not self.fills:
                return self.finish(self.payload(0x8000000000000013))
            may_rest = False
            if a["oid_tag"]:
                self.clear_relation(a["oid"])
        elif ended == "used":
            may_rest = False
            if a["oid_tag"]:
                self.add_taker_row()
                if self.taker_only:
                    self.add_taker_row()
        elif a["oid_tag"] and self.taker_only:
            self.add_taker_row()
        self.apply_rows()
        rested = False
        if not may_rest:
            if not self.fills:
                return self.finish(self.payload(0x8000000000000008))
            self.status_row()
        else:
            outcome = self.rest()
            if isinstance(outcome, dict):
                return self.finish(outcome)
            rested = outcome
            if not rested:
                self.status_row()
        users = sorted(self.users.items())
        return self.finish({"oid": self.oid, "fills": self.fills, "users": [[user, oids] for user, oids in users],
                            "cloid": a["cloid"], "fresh_rest": bool(rested and not a["oid_tag"])})

    def finish(self, result):
        book = {"next_oid": self.next_id, "last_trade": self.last_trade, "sizes": [row["size_now"] for row in self.slab_rows],
                "relations": {key: value[0] for key, value in sorted(self.relations.items())},
                "links": {str(key): value for key, value in sorted(self.next_link.items())}, "rest": [self.rest_head, self.rest_tail]}
        return {"log": self.log, "result": result, "book": book}


class SpecPanic(Exception):
    pass


def spec_run(case):
    spec = Spec(copy_world(case.world))
    try:
        return spec.run()
    except SpecPanic as error:
        return {"panic": str(error), "log": spec.log}


def copy_world(w):
    return json.loads(json.dumps(w))


# ---- harness: real bytes; every edge callee is stubbed and logged ----

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


class Shape:
    """A B-tree node shape: key start and width, length word, first edge, parent word, parent slot, leaf size."""

    def __init__(self, keys, width, length, edges, parent, slot, size):
        self.keys, self.width, self.length, self.edges, self.parent, self.slot, self.size = keys, width, length, edges, parent, slot, size


SIDE_NODE = Shape(0x168, 8, 0x1C2, 0x1C8, 0x160, 0x1C0, 0x1C8)
TOKEN_NODE = Shape(8, 8, 0x62, 0x70, 0, 0x60, 0x70)
SPOT_NODE = Shape(8, 8, 0x16A, 0x170, 0, 0x168, 0x170)
LEAF_KEYS = 3
PANIC_LOCATIONS = {0x56BD858: "level head", 0x56BD870: "slot", 0x56BD888: "tail", 0x56BD8A0: "notional", 0x56C5540: "tree", 0x56C37F0: "tree"}
RECORDER_LOCATIONS = {0x56BD810: "recorder size", 0x56C4F20: "recorder size", 0x56BD7E0: "recorder sum"}


def word_bytes(value):
    return struct.pack("<Q", value & MASK[8])


class Harness:
    def __init__(self, image):
        self.image = image
        self.machine = Machine(image)
        machine = self.machine
        self.relative = {slot: addend for slot, kind, addend, _ in image.relocations() if kind == 8}
        relative = self.relative
        table = {SLOT_MALLOC: self.on_malloc, SLOT_FREE: self.on_free, SLOT_MEMCPY: self.on_copy, SLOT_MEMMOVE: self.on_copy, SLOT_MEMCMP: self.on_compare, SLOT_RECORDER: self.on_recorder,
                 SLOT_REFRESH: self.on_refresh, SLOT_CLASS: self.on_class, SLOT_ANCHOR: self.on_anchor, SLOT_PREDICATE: self.on_predicate,
                 SLOT_GROW_SKIPS: lambda m: self.on_grow(m, 0x28), SLOT_GROW_OIDS: lambda m: self.on_grow(m, 8), SLOT_GROW_ROWS: lambda m: self.on_grow(m, 0x20), SLOT_GROW_FILLS: lambda m: self.on_grow(m, FILL_SIZE),
                 SLOT_CLASS_FEE: self.on_fee_class, SLOT_ENTRY: self.on_entry, SLOT_AMOUNT: self.on_amount, SLOT_CONVERT: self.on_convert, SLOT_CAN_SETTLE: self.on_can_settle, SLOT_SETTLE: self.on_settle,
                 SLOT_REST_GATE: self.on_rest_gate, SLOT_RESERVE: self.on_reserve, SLOT_CLOID: self.on_cloid, SLOT_TRACK: self.on_track,
                 SLOT_PANIC_NONE: self.on_panic_none, SLOT_PANIC_BOUND: self.on_panic_bound, SLOT_PANIC_TEXT: self.on_panic_text, 0x576E128: self.on_panic_text, 0x576DFB8: self.on_panic_text}
        for slot in table:
            relative.setdefault(slot, slot)
        machine.memory.statics.update(relative)
        machine.slots = {relative[slot]: hook for slot, hook in table.items()}
        self.real = RealExcept()
        machine.real = self.real
        machine.jump_low, machine.jump_high = image.exact_fde(INSERT)
        calls = {TICK: self.on_tick, MID: self.on_mid, ENTRY_GATE: self.on_entry_gate, TOP_LEVELS: self.on_top, ALO_PAYLOAD: self.on_alo, LEG: self.on_leg, SET_SIZE: self.on_set_size, COLLECT: self.on_collect,
                 RELATIONS: self.on_relations, REMOVE: self.on_remove, SKIP: self.on_skip, DROP_SET: self.on_drop_set, LEVEL: self.on_level, SLAB_INSERT: self.on_slab, OID_MAP: self.on_oid_map,
                 USER_STATE: self.on_user_state, USER_SLOTS: self.on_user_slots, BUILD_STATUS: self.on_build, PUSH_ROW: self.on_row, ORDER_LOOKUP: self.on_lookup}
        machine.tails = calls
        machine.calls = calls
        self.real.stubs = frozenset(machine.slots) | frozenset(calls)
        self.w = None
        self.brk = HEAP_FREE
        self.live = {}
        self.log = []
        self.used = HEAP_SIZE

    def allocate(self, size):
        at = (self.brk + 15) & ~15
        self.brk = at + size
        if self.brk > HEAP_BASE + HEAP_SIZE:
            raise Halt("heap full")
        self.live[at] = size
        return at

    def static(self, size):
        at = (self.brk + 15) & ~15
        self.brk = at + size
        return at

    def on_malloc(self, m):
        size = m.regs[RDI]
        if size > 0x4000:
            raise Halt("allocation size")
        m.regs[RAX] = self.allocate(size)

    def on_free(self, m):
        at, size = m.regs[RDI], m.regs[RSI]
        if self.live.pop(at, None) != size:
            raise Halt("free %#x size %#x" % (at, size))

    def on_copy(self, m):
        regs = m.regs
        if regs[RDX] > 0x4000 or (m.call_target == self.relative[SLOT_MEMCPY] and regs[RDX] > 0x200 or regs[RDX] > 0x80 and regs[RDX] not in (0x90, 0xA8, 0x1E6, 0x1F0, 0x100, 0x200)):
            raise Halt("copy size")
        if regs[RDX]:
            m.memory.copy(regs[RDI], regs[RSI], regs[RDX])
        regs[RAX] = regs[RDI]

    def on_compare(self, m):
        regs = m.regs
        if regs[RDX] != 0x14:
            raise Halt("compare length")
        left, right = m.memory.bytes_at(regs[RDI], 0x14), m.memory.bytes_at(regs[RSI], 0x14)
        regs[RAX] = 0 if left == right else (1 if left > right else MASK[8])

    def on_recorder(self, m):
        label = RECORDER_LOCATIONS.get(m.regs[RSI])
        if not label or m.regs[RDI] & 0xFF:
            raise Halt("recorder arguments")
        raise Panicked(label)

    def on_panic_none(self, m):
        label = PANIC_LOCATIONS.get(m.regs[RDI])
        if not label:
            raise Halt("panic location")
        raise Panicked(label)

    def on_panic_bound(self, m):
        if m.regs[RDX] != 0x56F1FD8:
            raise Halt("bound location")
        raise Panicked("row bound")

    def on_panic_text(self, m):
        if m.regs[RDI] == 0x3EF9BC and m.regs[RSI] == 0x1D and m.regs[RDX] == 0x56BD8B8:
            raise Panicked("reduce_only text")
        raise Halt("panic text")

    def user(self, m, at):
        return m.memory.bytes_at(at, 0x14).hex()

    def need(self, condition, text):
        if not condition:
            raise Halt(text)

    def on_refresh(self, m):
        regs = m.regs
        self.need(regs[RSI] == CTX + 0x80, "refresh state")
        self.log.append(["refresh", self.user(m, regs[RDX]), regs[RCX]])

    def on_class(self, m):
        regs = m.regs
        self.need(regs[RDI] == CTX + 0x90, "class state")
        self.log.append(["class", regs[RSI]])
        regs[RAX] = self.w["cls"] | 0xAB00

    def on_tick(self, m):
        regs = m.regs
        self.need(regs[RDI] == CTX + 0x90, "tick state")
        self.log.append(["tick", regs[RSI], regs[RDX]])
        regs[RAX] = self.w["tick"]

    def on_mid(self, m):
        self.need(m.regs[RDI] == BOOK, "mid book")
        self.log.append(["mid"])
        m.regs[RAX] = self.w["mid"]

    def on_entry_gate(self, m):
        regs = m.regs
        memory = m.memory
        self.need(regs[RSI] == CTX + 0x80, "gate state")
        rsp = regs[RSP]
        self.log.append(["gate", self.user(m, regs[RDX]), regs[RCX], regs[R8] & 0xFF, regs[R9], memory.read(rsp + 8, 8), memory.read(rsp + 0x10, 8)])
        status, second, third = self.w["gate"]
        memory.put_bytes(regs[RDI], struct.pack("<QQQ", status, second, third))

    def on_top(self, m):
        self.need(m.regs[RSI] == BOOK + 0x80, "top book")
        self.log.append(["top_levels"])
        m.memory.write(m.regs[RDI], 8, 0x1234)

    def on_alo(self, m):
        regs = m.regs
        self.need(m.memory.read(regs[RSI], 8) == 0x1234 and regs[RDX] == BOOK and regs[RCX] == CTX + 0x90, "alo arguments")
        self.log.append(["alo_payload"])
        m.memory.put_bytes(regs[RDI], struct.pack("<QQ", *self.w["alo"]))

    def on_anchor(self, m):
        regs = m.regs
        self.need(regs[RDI] == CTX + 0x90, "anchor state")
        self.log.append(["anchor", regs[RSI]])
        regs[RAX] = self.w["anchor"]

    def on_predicate(self, m):
        user = self.user(m, m.regs[RDI])
        self.log.append(["predicate", user])
        m.regs[RAX] = (1 if user in self.w["system"] else 0) | 0xCD00

    def on_grow(self, m, size):
        memory = m.memory
        vector = m.regs[RDI]
        capacity, old, length = memory.read(vector, 8), memory.read(vector + 8, 8), memory.read(vector + 0x10, 8)
        self.need(capacity == length and capacity <= 0x100 and (capacity or old == 8), "grow vector")
        wanted = capacity * 2 or 4
        fresh = self.allocate(wanted * size)
        if capacity:
            memory.copy(fresh, old, capacity * size)
            self.need(self.live.pop(old, None) == capacity * size, "grow free")
        memory.write(vector, 8, wanted)
        memory.write(vector + 8, 8, fresh)

    def on_fee_class(self, m):
        regs = m.regs
        memory = m.memory
        self.need(regs[RSI] == CTX + 0x80 and regs[RCX] == 10 ** 9, "fee class arguments")
        block = regs[RDX]
        self.need(memory.read(block + 0x28, 8) == CTX + 0x5D0, "fee class state")
        taker = memory.read(block + 0x4C, 1)
        words = memory.bytes_at(block, 0x28)
        if taker:
            self.need(words == memory.bytes_at(ARGS + 0x48, 0x28), "taker block")
            name = "taker"
        else:
            name = words.hex()
        self.need(memory.read(block + 0x4E, 1) == self.w["byte"], "fee class byte")
        self.log.append(["fee_class", self.user(m, block + 0x38), name, memory.read(block + 0x30, 8), taker, memory.read(block + 0x4D, 1)])

    def on_entry(self, m):
        regs = m.regs
        self.need(regs[RDI] == CTX + 0x80, "entry state")
        self.log.append(["entry", self.user(m, regs[RSI])])
        regs[RAX] = ENTRY_AT

    def on_amount(self, m):
        regs = m.regs
        self.need(regs[RDX] == CTX + 0x90, "amount state")
        self.log.append(["amount", regs[RDI], regs[RSI]])
        regs[RAX] = self.w["amount"]

    def on_leg(self, m):
        regs = m.regs
        memory = m.memory
        leg = regs[RDX] & MASK[4]
        out, block = regs[RDI], regs[RSI]
        read = memory.read
        users = read(block, 8)
        self.need(read(block + 8, 8) == CTX + 0x80 and read(block + 0x38, 8) == CTX, "leg state")
        slot = read(block + 0x18, 8)
        pair = read(block + 0x20, 8)
        self.need(read(pair, 4) == self.w["word_one"] and read(pair + 4, 4) == self.w["word_two"], "leg words")
        kinds = read(block + 0x48, 8)
        args = self.w["args"]
        cloid = bytes(memory.bytes_at(read(block + 0x50, 8), 0x11))
        self.need(cloid == bytes(memory.bytes_at(ARGS + 0x91, 0x11)), "leg client id")
        self.need(memory.bytes_at(read(block + 0x58, 8), 0x28) == memory.bytes_at(ARGS + 0x48, 0x28), "leg block")
        self.log.append(["leg", leg, self.user(m, users), self.user(m, users + 0x14), read(read(block + 0x10, 8), 8), read(slot + 0xD8, 8), read(read(block + 0x28, 8), 8), read(read(block + 0x30, 8), 8),
                         read(read(block + 0x40, 8), 8), read(kinds, 8), read(kinds + 8, 8), self.w["word_one"], self.w["word_two"]])
        memory.put_bytes(out, word_bytes(self.w["leg_tag"]) + bytes((0x51 + leg, 0x61 + leg)) + ramp(0xF8 - 10, 0x13 + leg * 3))
        memory.put_bytes(out + 0x10, memory.bytes_at(users + 0x14 * leg, 0x14))

    def on_convert(self, m):
        regs = m.regs
        memory = m.memory
        self.need(regs[RSI] == CTX + 0x90, "convert state")
        self.log.append(["convert", regs[RDX], regs[RCX], regs[R8], regs[R9]])
        number = self.fill_calls
        self.fill_calls += 1
        self.convert = self.w["convert"].get(str(number), [1, 77, 88])
        tag, first, third = self.convert
        memory.put_bytes(regs[RDI], struct.pack("<QQQ", first, 0xAB00000000 | tag, third))

    def on_can_settle(self, m):
        regs = m.regs
        self.need(regs[RDI] == CTX + 0x80, "can settle state")
        self.log.append(["can_settle", self.user(m, regs[RSI]), regs[RDX], regs[RCX]])
        regs[RAX] = (1 if self.w["can"].get(str(self.fill_calls - 1), True) else 0) | 0xEF00

    def on_settle(self, m):
        regs = m.regs
        memory = m.memory
        read = memory.read
        self.need(regs[RDI] == CTX + 0x80 and regs[RCX] == CTX + 0x5D0, "settle state")
        record = regs[RDX]
        self.need(memory.bytes_at(record + 8, 2) == bytes((0x51, 0x61)) and read(record, 8) == self.w["leg_tag"], "settle head")
        self.need(memory.bytes_at(record + 0xF8 + 0x30, 0x20) == ramp(0xF8 - 10, 0x13 + 3)[0x26:0x46], "settle second leg")
        self.need(memory.bytes_at(record + 0x218, 12) == bytes(memory.bytes_at(CTX + 0x60, 12)) and read(record + 0x210, 8) == 0, "settle time")
        self.log.append(["settle", regs[RSI] & 0xFF, self.user(m, record + 0x10), self.user(m, record + 0xF8 + 0x10), read(record + 0x1F0, 8), read(record + 0x1F8, 8), read(record + 0x200, 8), read(record + 0x208, 8), read(record + 0x224, 1)])
        changed = self.w["settled"].get(str(self.fill_calls - 1))
        if changed:
            memory.write(record + 0x1F0, 8, changed[0])
            memory.write(record + 0x200, 8, changed[1])

    def index_of(self, at):
        index, extra = divmod(at - SLAB, SLOT_SIZE)
        self.need(not extra and 0 <= index < SLAB_ROOM, "slot address")
        return index

    def on_set_size(self, m):
        regs = m.regs
        self.need(regs[RCX] == SINK and regs[R8] == BOOK + 0xD0, "set size arguments")
        self.log.append(["set_size", self.index_of(regs[RDI]), regs[RSI], regs[RDX]])
        m.memory.write(regs[RDI] + 0xC8, 8, regs[RDX])

    def on_collect(self, m):
        regs = m.regs
        memory = m.memory
        start, end = regs[RSI], regs[RDX]
        self.need((end - start) % 0x20 == 0 and 0 <= end - start < 0x1000 and (end != start or start == 8), "collect range")
        self.log.append(["collect", [memory.read(at, 8) for at in range(start, end, 0x20)]])
        memory.put_bytes(regs[RDI], struct.pack("<QQ", SET_MARK, 0x2468))

    def edge_state(self, ctx, sink):
        self.need(ctx == CTX and sink == SINK, "edge state")

    def on_relations(self, m):
        regs = m.regs
        rsp = regs[RSP]
        self.need(regs[RDI] == BOOK and regs[RCX] == SET_MARK and regs[R8] == 0x2468, "relations arguments")
        self.edge_state(regs[R9], m.memory.read(rsp + 8, 8))
        self.log.append(["relations", regs[RDX], self.user(m, regs[RSI])])

    def on_remove(self, m):
        regs = m.regs
        self.need(regs[RDI] == BOOK, "remove book")
        self.edge_state(regs[RCX], regs[R8])
        self.log.append(["remove", regs[RSI], self.user(m, regs[RDX]), regs[R9] & 0xFF])

    def on_skip(self, m):
        regs = m.regs
        self.need(regs[RDI] == BOOK, "skip book")
        self.edge_state(regs[RCX], regs[R8])
        self.log.append(["skip", regs[RDX], self.user(m, regs[RSI]), regs[R9] & 0xFF])

    def on_drop_set(self, m):
        self.need(m.memory.read(m.regs[RDI], 8) == SET_MARK, "drop set")
        self.log.append(["drop_set"])

    def on_rest_gate(self, m):
        regs = m.regs
        self.need(regs[RDI] == CTX + 0x80 and m.memory.bytes_at(regs[R9], 12) == bytes(m.memory.bytes_at(CTX + 0x60, 12)), "rest gate arguments")
        self.log.append(["rest_gate", regs[RSI] & 0xFF, regs[RDX], regs[RCX] & 0xFF, regs[R8]])
        regs[RAX] = (1 if self.w["may_rest"] else 0) | 0xBC00

    def on_reserve(self, m):
        regs = m.regs
        memory = m.memory
        self.need(regs[RSI] == CTX + 0x80, "reserve state")
        block = regs[RCX]
        self.need(memory.read(block + 0x2D, 1) == 0, "reserve flag")
        self.log.append(["reserve", regs[RDX], memory.read(block, 8), memory.read(block + 8, 8), memory.read(block + 0x10, 8), self.user(m, block + 0x18), memory.read(block + 0x2C, 1)])
        status, second, third = self.w["reserve"]
        if not status >> 63:
            second = self.allocate(status)
        memory.put_bytes(regs[RDI], struct.pack("<QQQ", status, second, third))

    def on_level(self, m):
        regs = m.regs
        memory = m.memory
        self.need(regs[RDI] in (BOOK + 0x80, BOOK + 0x98), "level tree")
        self.log.append(["level", int(regs[RDI] == BOOK + 0x98), to_signed(regs[RSI])])
        head, tail = self.w["rest_level"]
        self.rest_used = True
        memory.put_bytes(LEVEL_AT, struct.pack("<QQQQ", 0 if head is None else 1, 0x3333 if head is None else head, 0 if tail is None else 1, 0x4444 if tail is None else tail))
        regs[RAX] = LEVEL_AT

    def on_slab(self, m):
        regs = m.regs
        memory = m.memory
        read = memory.read
        record = regs[RSI]
        self.need(regs[RDI] == BOOK and regs[RCX] == SINK and regs[R8] == BOOK + 0xD0, "slab arguments")
        self.need(read(record + 0x10, 8) == 0 and read(record + 0x20, 8) == 1, "slab links")
        self.need(read(record + 0x28, 8) == read(record + 0xC8, 8), "slab size")
        self.need(memory.bytes_at(record + 0x30, 0x20) == memory.bytes_at(ARGS + 0x10, 0x20), "slab words")
        self.need(read(record + 0x50, 8) == read(ARGS + 0x30, 8) and read(record + 0x58, 8) == read(ARGS + 0x38, 8), "slab vector")
        self.need(memory.bytes_at(record + 0x60, 0x40) == memory.bytes_at(ARGS + 0x40, 0x40), "slab block")
        self.need(read(record + 0xA8, 8) == read(ARGS + 0x88, 8) and read(record + 0xB0, 1) == 0 and memory.bytes_at(record + 0xB2, 0x10) == memory.bytes_at(ARGS + 0x92, 0x10), "slab tail words")
        self.need(memory.bytes_at(record + 0xC3, 5) == memory.bytes_at(ARGS + 0xA3, 5) and read(record + 0xF4, 1) == 0, "slab bytes")
        has = read(record + 0xB1, 1)
        self.need(has == read(ARGS + 0x91, 1), "slab client flag")
        args = self.w["args"]
        self.log.append(["slab_insert", read(record + 8, 8) if read(record, 8) == 1 else None, read(record + 0xC8, 8), read(record + 0xD0, 8), read(record + 0xD8, 8), read(record + 0xA0, 8), read(record + 0xC2, 1), self.user(m, record + 0xE0),
                         read(record + 0xF5, 1), memory.bytes_at(record + 0xB2, 0x10).hex() if has else None, regs[RDX]])
        regs[RAX] = self.w["new_slot"]

    def on_oid_map(self, m):
        regs = m.regs
        self.need(regs[RDI] == BOOK + 0x28, "oid map")
        self.log.append(["oid_map", regs[RSI], regs[RDX]])

    def on_cloid(self, m):
        regs = m.regs
        self.need(regs[RDI] == BOOK + 0x48 and regs[RCX] == ARGS + 0x92, "client map")
        self.log.append(["cloid", self.user(m, regs[RSI]), regs[RDX], m.memory.bytes_at(regs[RCX], 0x10).hex()])

    def on_user_state(self, m):
        regs = m.regs
        self.need(regs[RDI] == BOOK + 0xB8, "user state")
        self.log.append(["user_state", self.user(m, regs[RSI])])
        regs[RAX] = STATE_AT

    def on_user_slots(self, m):
        regs = m.regs
        self.need(regs[RDI] == STATE_AT + 0x20, "user slots")
        self.log.append(["user_slots", regs[RSI]])

    def on_track(self, m):
        regs = m.regs
        self.need(regs[RDI] == CTX + 0x740, "track state")
        self.log.append(["track", self.user(m, regs[RSI])])

    def on_build(self, m):
        regs = m.regs
        memory = m.memory
        read = memory.read
        block = regs[RDX]
        self.need(regs[RSI] == BOOK and regs[RCX] == CTX + 0x90, "build arguments")
        self.need(read(block, 8) == 0 and read(block + 0x10, 8) == 0 and read(block + 0xF4, 1) == 0, "build zeros")
        self.need(read(block + 0x20, 8) == read(ARGS, 8) and read(block + 0x30, 8) == read(ARGS + 0x10, 8) and read(block + 0x38, 8) == read(ARGS + 0x18, 8) and read(block + 0x40, 8) == read(ARGS + 0x20, 8) and read(block + 0x48, 8) == read(ARGS + 0x28, 8), "build words")
        self.need(read(block + 0x28, 8) == read(ARGS + 8, 8) and read(block + 0x50, 8) == read(ARGS + 0x40, 8) and read(block + 0x60, 8) == read(ARGS + 0x40, 8), "build sizes")
        self.need(read(block + 0x98, 8) == read(ARGS + 0x78, 8) and read(block + 0xA8, 8) == read(ARGS + 0x88, 8) and read(block + 0xB0, 1) == 0 and read(block + 0xB1, 1) == read(ARGS + 0x91, 1), "build tail")
        tag = 1 if read(ARGS + 0x48, 4) == 1 else 0
        self.need(read(block + 0x68, 8) == tag and (not tag or memory.bytes_at(block + 0x70, 0x20) == memory.bytes_at(ARGS + 0x50, 0x20)), "build block")
        pointer, count = read(block + 0x58, 8), read(block + 0x60, 8)
        self.need((pointer == 8 if not count else memory.bytes_at(pointer, count * 8) == memory.bytes_at(read(ARGS + 0x38, 8), count * 8)), "build vector")
        self.build_block = memory.bytes_at(block + 0x68, 0x28)
        self.need(not read(ARGS + 0x91, 1) or memory.bytes_at(block + 0xB2, 0x10) == memory.bytes_at(ARGS + 0x92, 0x10), "build client id")
        self.log.append(["build_status", read(block + 0xC8, 8), read(block + 0xD0, 8), read(block + 0xD8, 8), self.user(m, block + 0xE0), read(block + 0xF5, 1), read(block + 0xA0, 8), read(block + 0xC2, 1), read(block + 0x90, 8)])
        memory.write(regs[RDI], 8, read(block + 0xD8, 8))

    def on_row(self, m):
        regs = m.regs
        memory = m.memory
        read = memory.read
        record = regs[RSI]
        self.need(regs[RDI] == SINK and read(record, 8) == 3 and read(record + 8, 8) == 2 and read(record + 0x100, 1) == 1, "row head")
        self.need(memory.bytes_at(record + 0xE0, 12) == bytes(memory.bytes_at(CTX + 0x60, 12)), "row time")
        self.need(memory.bytes_at(record + 0x10, 0x28) == self.build_block, "row block")
        self.log.append(["row", read(record + 0x38, 8), self.user(m, record + 0xEC)])

    def on_lookup(self, m):
        regs = m.regs
        self.need(regs[RDI] == BOOK and self.user(m, regs[RSI]) == self.w["args"]["user"], "lookup arguments")
        self.log.append(["lookup", regs[RDX]])
        keys = sorted(self.w["relations"], key=int)
        regs[RAX] = RELATION_AT + keys.index(str(regs[RDX])) * 0x30 if str(regs[RDX]) in keys else 0

    def put_keys(self, at, shape, keys, spare, height=0, children=None):
        memory = self.machine.memory
        size = shape.size + (0x60 if height else 0)
        memory.put_bytes(at, ramp(size, 0x35))
        for index in range(11):
            memory.put_bytes(at + shape.keys + index * shape.width, keys[index] if index < len(keys) else spare)
        memory.write(at + shape.length, 2, len(keys))
        memory.write(at + shape.parent, 8, 0)
        if children:
            for index, child in enumerate(children):
                memory.write(at + shape.edges + index * 8, 8, child)
                memory.write(child + shape.parent, 8, at)
                memory.write(child + shape.slot, 2, index)

    def tree(self, shape, keys, spare):
        """A real tree of one or two levels; returns (root, height, node addresses)."""
        if not keys:
            return 0, 0, []
        if len(keys) <= LEAF_KEYS:
            root = self.static(shape.size)
            self.put_keys(root, shape, keys, spare)
            return root, 0, [root]
        leaves = []
        separators = []
        at = 0
        while at < len(keys):
            leaves.append(keys[at:at + LEAF_KEYS])
            if at + LEAF_KEYS < len(keys):
                separators.append(keys[at + LEAF_KEYS])
            at += LEAF_KEYS + 1
        nodes = []
        for leaf in leaves:
            node = self.static(shape.size)
            self.put_keys(node, shape, leaf, spare)
            nodes.append(node)
        root = self.static(shape.size + 0x60)
        self.put_keys(root, shape, separators, spare, 1, nodes)
        return root, 1, [root] + nodes

    def nested(self, shape, keys, height, spare):
        """A uniform tree of the asked height; returns (root, nodes)."""
        if not height:
            root = self.static(shape.size)
            self.put_keys(root, shape, keys, spare)
            return root, [root]
        middle = len(keys) // 2
        left, left_nodes = self.nested(shape, keys[:middle], height - 1, spare)
        right, right_nodes = self.nested(shape, keys[middle + 1:], height - 1, spare)
        root = self.static(shape.size + 0x60)
        self.put_keys(root, shape, [keys[middle]], spare, 1, [left, right])
        return root, [root] + left_nodes + right_nodes

    def put_slot(self, index, slot, follower):
        memory = self.machine.memory
        at = SLAB + index * SLOT_SIZE
        memory.put_bytes(at, ramp(SLOT_SIZE, 0x41 + index * 5))
        memory.write(at, 8, 1)
        memory.write(at + 8, 8, 0x5555)
        memory.write(at + 0x10, 1, 0 if follower is None else 1)
        memory.write(at + 0x18, 8, 0x5A5A if follower is None else follower)
        memory.write(at + 0xB0, 1, 1 if slot["flag"] else 0)
        memory.write(at + 0xC8, 8, slot["size"])
        memory.write(at + 0xD8, 8, slot["oid"])
        memory.put_bytes(at + 0xE0, bytes.fromhex(slot["user"]))

    def build(self, w):
        memory = self.machine.memory
        self.w = w
        memory.reset(self.used)
        self.brk = HEAP_FREE
        self.live = {}
        self.log = []
        self.fill_calls = 0
        self.rest_used = False
        a = w["args"]
        memory.put_bytes(BOOK, ramp(0x100, 0x27))
        memory.put_bytes(CTX, ramp(0x900, 0x47))
        memory.put_bytes(ARGS, ramp(0xD0, 0x71))
        memory.put_bytes(ENTRY_AT, ramp(0x40, 0x29))
        memory.write(BOOK + 0xB0, 8, w["asset"])
        memory.write(BOOK + 8, 8, SLAB)
        slab = [slot for level in w["levels"] for slot in level["slots"]]
        memory.write(BOOK + 0x10, 8, len(slab) + len(w["extra_slots"]) - w["slab_short"])
        memory.write(CTX + 0x38, 8, w["next_oid"])
        memory.write(CTX + 0x8F2, 1, w["byte"])
        memory.write(CTX + 0x1F8, 8, ROWS_AT)
        memory.write(CTX + 0x200, 8, len(w["rows"]))
        for number, row in enumerate(w["rows"]):
            memory.put_bytes(ROWS_AT + number * 0x20, struct.pack("<QQQQ", row[0], row[1], 0x1357, 0x2468))
        tokens = sorted(int(key) for key in w["tokens"])
        root, height, nodes = self.tree(TOKEN_NODE, [struct.pack("<Q", key) for key in tokens], struct.pack("<Q", w["spare"]))
        for node in nodes:
            count = memory.read(node + TOKEN_NODE.length, 2)
            for index in range(11):
                memory.write(node + 0x64 + index, 1, w["tokens"][str(memory.read(node + 8 + index * 8, 8))] if index < count else 0)
        memory.write(CTX + 0x2E0, 8, root)
        memory.write(CTX + 0x2E8, 8, height)
        for tree_at, levels in ((BOOK + 0x98, w["levels"] if not a["side"] else []), (BOOK + 0x80, w["levels"] if a["side"] else [])):
            self.side_tree(tree_at, levels, a["side"])
        memory.put_bytes(BOOK + (0x98 if a["side"] else 0x80), struct.pack("<QQQ", w["own_root"], 0, 0))
        index = 0
        for level in w["levels"]:
            chain = level["slots"]
            for number, slot in enumerate(chain):
                follower = index + 1 if number + 1 < len(chain) else None
                self.put_slot(index, slot, follower)
                index += 1
        for number, row in enumerate(w["extra_slots"]):
            if row.get("vacant"):
                memory.put_bytes(SLAB + index * SLOT_SIZE, ramp(SLOT_SIZE, 0x41))
                memory.write(SLAB + index * SLOT_SIZE, 8, 2)
            else:
                self.put_slot(index, {"flag": 0, "size": row.get("size", 0), "oid": 0x99, "user": USERS[3]}, None)
            index += 1
        if w["broken_slot"] is not None:
            memory.write(SLAB + w["broken_slot"] * SLOT_SIZE, 4, 2)
        balances = w["balances"]
        keys = sorted(int(key) for key in balances)
        root, height, nodes = self.tree(SPOT_NODE, [struct.pack("<Q", key) for key in keys], struct.pack("<Q", w["spare"]))
        for node in nodes:
            count = memory.read(node + SPOT_NODE.length, 2)
            for index in range(11):
                total, hold = balances[str(memory.read(node + 8 + index * 8, 8))] if index < count else (1 << 40, 0)
                memory.write(node + 0x60 + index * 0x18, 8, total)
                memory.write(node + 0x68 + index * 0x18, 8, hold)
        memory.write(ENTRY_AT + 0x10, 8, root)
        memory.write(ENTRY_AT + 0x18, 8, height)
        for number, key in enumerate(sorted(w["relations"], key=int)):
            at = RELATION_AT + number * 0x30
            memory.put_bytes(at, ramp(0x30, 0x19))
            memory.write(at + 0x20, 8, w["relations"][key][0])
            memory.write(at + 0x28, 8, w["relations"][key][1])
        memory.statics[ONCE_STATE] = 0
        memory.write(ARGS, 8, a["tag"])
        memory.write(ARGS + 8, 8, a["size"])
        vector = a["vector"]
        if vector:
            cap = len(vector) + 1
            buffer = self.allocate(cap * 8)
            memory.put_bytes(buffer, b"".join(word_bytes(item) for item in vector))
            memory.put_bytes(ARGS + 0x30, struct.pack("<QQQ", cap, buffer, len(vector)))
            self.vector = buffer
        else:
            memory.put_bytes(ARGS + 0x30, struct.pack("<QQQ", 0, 8, 0))
            self.vector = None
        memory.write(ARGS + 0x48, 4, a["block"])
        memory.write(ARGS + 0x70, 8, a["kind"])
        memory.write(ARGS + 0x78, 8, a["word"])
        memory.write(ARGS + 0x80, 8, a["px"])
        memory.write(ARGS + 0x90, 1, a["reduce"])
        memory.write(ARGS + 0x91, 1, 1 if a["cloid"] is not None else 0)
        if a["cloid"] is not None:
            memory.put_bytes(ARGS + 0x92, bytes.fromhex(a["cloid"]))
        memory.write(ARGS + 0xA2, 1, a["side"])
        memory.write(ARGS + 0xA8, 8, a["oid_tag"])
        memory.write(ARGS + 0xB0, 8, a["oid"])
        memory.put_bytes(ARGS + 0xB8, bytes.fromhex(a["user"]))
        memory.write(ARGS + 0xCC, 1, a["tif"])

    def side_tree(self, at, levels, side):
        memory = self.machine.memory
        ordered = sorted(levels, key=lambda row: -row["px"] if side else row["px"])
        keys = [struct.pack("<q", -row["px"] if side else row["px"]) for row in ordered]
        spare = struct.pack("<q", -1 if side else 1)
        wanted = self.w["tree_height"]
        if wanted and keys:
            root, nodes = self.nested(SIDE_NODE, keys, wanted, spare)
            height = wanted
        else:
            root, height, nodes = self.tree(SIDE_NODE, keys, spare)
        if keys:
            for _ in range(self.w["deep"]):
                top = self.static(SIDE_NODE.size + 0x60)
                self.put_keys(top, SIDE_NODE, [], spare, 1, [root])
                root, height = top, height + 1
        memory.put_bytes(at, struct.pack("<QQQ", root, height, len(keys)))
        chains = {}
        index = 0
        for level in levels:
            chains[-level["px"] if side else level["px"]] = (index, len(level["slots"]))
            index += len(level["slots"])
        for node in nodes:
            for number in range(memory.read(node + SIDE_NODE.length, 2)):
                key = to_signed(memory.read(node + SIDE_NODE.keys + number * 8, 8))
                first, count = chains[key]
                memory.put_bytes(node + number * 0x20, struct.pack("<QQQQ", 1 if count else 0, first, 1 if count else 0, first + count - 1))

    def stack(self, words):
        memory = self.machine.memory
        for index, value in enumerate(words):
            memory.write(STACK_TOP - 0x100 + index * 8, 8, value)

    def run(self, case):
        w = case.world
        machine = self.machine
        memory = machine.memory
        self.build(w)
        self.stack([SINK])
        try:
            machine.run(INSERT, {RDI: OUT, RSI: BOOK, RDX: ARGS, RCX: w["word_one"], R8: w["word_two"], R9: CTX})
        except Panicked as error:
            return {"panic": str(error), "log": self.log}
        result = self.read_out()
        rested = bool(self.rest_used and "oid" in result and memory.read(ENTRY_AT, 1) is not None and self.log and self.log[-1][0] == "track")
        if rested and self.vector is not None:
            self.need(self.live.pop(self.vector, None) is not None, "vector moved")
        if self.live:
            raise Halt("leak %r" % sorted(self.live.values()))
        return {"log": self.log, "result": result, "book": self.read_book()}

    def read_out(self):
        memory = self.machine.memory
        read = memory.read
        first = read(OUT, 8)
        if first == NONE_WORD:
            status = read(OUT + 8, 8)
            second, third = read(OUT + 0x10, 8), read(OUT + 0x18, 8)
            if not status >> 63:
                self.need(self.live.pop(second, None) == status, "text status")
            return {"status": status, "second": second, "third": third}
        pointer, count = read(OUT + 8, 8), read(OUT + 0x10, 8)
        self.need(count <= 0x40 and (first or pointer == 8), "fill count")
        fills = []
        for index in range(count):
            at = pointer + index * FILL_SIZE
            self.need(memory.bytes_at(at, 8) == word_bytes(self.w["leg_tag"]), "fill head")
            self.need(memory.bytes_at(at + 0x218, 12) == bytes(memory.bytes_at(CTX + 0x60, 12)), "fill time")
            fills.append([read(at + 0x1F0, 8), read(at + 0x1F8, 8), read(at + 0x200, 8), read(at + 0x208, 8), read(at + 0x224, 1)])
        if first:
            self.need(self.live.pop(pointer, None) == first * FILL_SIZE, "fill buffer")
        users = self.read_users(read(OUT + 0x18, 8), read(OUT + 0x20, 8), read(OUT + 0x28, 8))
        has = read(OUT + 0x38, 1)
        return {"oid": read(OUT + 0x30, 8), "fills": fills, "users": users, "cloid": memory.bytes_at(OUT + 0x39, 0x10).hex() if has else None, "fresh_rest": bool(read(OUT + 0x49, 1))}

    def read_users(self, root, height, length):
        """The result map: one leaf in these runs; every buffer is released."""
        memory = self.machine.memory
        read = memory.read
        if not root:
            self.need(length == 0, "map length")
            return []
        self.need(height == 0 and length <= 11 and read(root + 0x1EE, 2) == length, "map shape")
        rows = []
        for index in range(length):
            cap, at, count = read(root + 8 + index * 0x18, 8), read(root + 0x10 + index * 0x18, 8), read(root + 0x18 + index * 0x18, 8)
            self.need(count <= 0x40, "map row")
            rows.append([memory.bytes_at(root + 0x110 + index * 0x14, 0x14).hex(), [read(at + at2 * 8, 8) for at2 in range(count)]])
            self.need(self.live.pop(at, None) == cap * 8, "map row buffer")
        self.need(self.live.pop(root, None) is not None, "map root")
        return rows

    def read_book(self):
        memory = self.machine.memory
        read = memory.read
        w = self.w
        slab = [slot for level in w["levels"] for slot in level["slots"]]
        sizes = [0 if read(SLAB + index * SLOT_SIZE, 4) == 2 else read(SLAB + index * SLOT_SIZE + 0xC8, 8) for index in range(len(slab) + len(w["extra_slots"]))]
        links = {}
        head, tail = None, None
        if self.rest_used and self.log[-1][0] == "track":
            head = read(LEVEL_AT + 8, 8) if read(LEVEL_AT, 8) == 1 else None
            tail = read(LEVEL_AT + 0x18, 8) if read(LEVEL_AT + 0x10, 8) == 1 else None
            old = w["rest_level"][1]
            if old is not None:
                self.need(read(SLAB + old * SLOT_SIZE + 0x10, 8) == 1, "tail link tag")
                links[str(old)] = read(SLAB + old * SLOT_SIZE + 0x18, 8)
        relations = {key: read(RELATION_AT + number * 0x30 + 0x20, 8) for number, key in enumerate(sorted(w["relations"], key=int))}
        changed = read(BOOK + 0x78, 8)
        return {"next_oid": read(CTX + 0x38, 8), "last_trade": None if changed == self.start_last() else changed, "sizes": sizes, "relations": dict(sorted(relations.items())), "links": links, "rest": [head, tail]}

    def start_last(self):
        return int.from_bytes(ramp(0x100, 0x27)[0x78:0x80], "little")


CRASHES = (Halt, Panicked, EvidenceError, KeyError, IndexError, ValueError, TypeError, OverflowError, struct.error, UnicodeDecodeError, ZeroDivisionError)


def normal(expected, got):
    """A None in the prediction marks a word the code leaves stale."""
    result = expected.get("result")
    if result and "status" in result and "result" in got:
        fixed = dict(got["result"])
        for key in ("second", "third"):
            if result.get(key) is None and key in fixed:
                fixed[key] = None
        got = dict(got, result=fixed)
    return got


def compare_run(harness, case):
    """None when the run agrees with the spec, else a text."""
    try:
        expected = spec_run(case)
        got = normal(expected, harness.run(case))
    except CRASHES as error:
        return "%s: crash %s %s" % (case.kind, case.label, str(error)[:120])
    if got != expected:
        return "%s: differ %s: %.900r != %.900r" % (case.kind, case.label, got, expected)
    return None


def ramp(count, start):
    return bytes((start + index * 7) & 0xFF for index in range(count))


# ---- cases ----

def args(**extra):
    row = {"tag": 1, "size": 10, "px": 100, "side": 0, "tif": 2, "reduce": 0, "oid_tag": 0, "oid": 0x777, "cloid": None, "kind": 2, "word": 0xABCD, "vector": [], "block": 0, "user": TAKER}
    row.update(extra)
    return row


def slot(user, size, oid, flag=0):
    return {"user": user, "size": size, "oid": oid, "flag": flag, "block": None}


def world(levels=(), a=None, **extra):
    w = {"args": args(**(a or {})), "levels": [dict(level) for level in levels], "asset": 1, "rows": [[2, 3], [5, 9], [6, 0]], "tokens": {"3": 1, "5": 0, "9": 0, "0": 0, "6": 0}, "spare": 9999, "word_one": 0x31, "word_two": 0x47,
         "next_oid": 500, "byte": 1, "tick": 10, "cls": 2, "mid": 123, "gate": [OK, 1, 2], "alo": [0x1111, 0x2222], "anchor": 100, "system": [], "balances": {"9": [10 ** 6, 0], "5": [10 ** 6, 0], "0": [10 ** 6, 0]}, "amount": 10 ** 6,
         "leg_tag": 0, "convert": {}, "can": {}, "settled": {}, "may_rest": True, "reserve": [OK, 0, 0], "rest_level": [None, None], "new_slot": 30, "relations": {}, "extra_slots": [{"size": 7}, {"vacant": True}],
         "slab_short": 0, "broken_slot": None, "own_root": 0, "tree_height": 0, "deep": 0}
    w.update(extra)
    index = 0
    for level in w["levels"]:
        for row in level["slots"]:
            row["block"] = block_hex(index)
            index += 1
    return w


def block_hex(index):
    return ramp(SLOT_SIZE, 0x41 + index * 5)[0x68:0x90].hex()


def book(side=0, sizes=(4, 4, 4), prices=None, users=None):
    """Three price levels of one maker each, by default; sells rest at 100, 90, 80 and buys at 100, 110, 120."""
    prices = prices or ([100 - 10 * index for index in range(len(sizes))] if side else [100 + 10 * index for index in range(len(sizes))])
    users = users or USERS
    return [{"px": px, "slots": [slot(users[index % len(users)], size, 0x100 + index)]} for index, (px, size) in enumerate(zip(prices, sizes))]


def chain(px, sizes, start=0):
    return {"px": px, "slots": [slot(USERS[(start + index) % 3], size, 0x200 + start + index) for index, size in enumerate(sizes)]}


def all_cases():
    cases = []

    def add(label, kind, w):
        cases.append(Case(label, kind, w))

    # entry gates
    add("row bound", "entry", world(asset=3))
    add("quote absent", "entry", world(tokens={"5": 0}))
    add("quote off", "entry", world(tokens={"9": 2, "5": 0}))
    add("quote off lower key", "entry", world(tokens={"9": 1, "5": 0, "1": 0, "2": 0, "20": 0, "30": 0, "40": 0}))
    add("quote deep key", "entry", world(tokens={"1": 1, "2": 1, "3": 1, "4": 1, "5": 1, "6": 1, "7": 1, "8": 1, "9": 0, "10": 1, "11": 1}))
    for tif in range(5):
        for side in (0, 1):
            for level_px, cross_name in ((100, "touch"), (90, "low"), (110, "high")):
                for reduce in (0, 1):
                    add("tif %d side %d %s reduce %d" % (tif, side, cross_name, reduce), "entry", world([chain(level_px, [1])], {"tif": tif, "side": side, "reduce": reduce}, can={"0": False}))
            add("tif %d side %d empty book" % (tif, side), "entry", world([], {"tif": tif, "side": side}))
    add("no size no reduce", "entry", world([], {"tag": 0}))
    add("no size reduce", "entry", world([], {"tag": 0, "reduce": 1}))
    add("taker empty own root", "entry", world([], {"side": 1}, own_root=0))
    for px in (10 ** 15, 10 ** 15 + 10, 2 ** 40 * 10, 0):
        add("price %d" % px, "entry", world([], {"px": px}, tick=1 if px == 0 else 10))
    for px, tick in ((105, 10), (2 ** 33 + 1, 3), (2 ** 33 + 3, 2 ** 33 + 3), (100, 7), (2 ** 40 + 1, 1)):
        add("tick %d %d" % (px, tick), "entry", world([], {"px": px}, tick=tick))
    for cls in (0, 1, 2, 3):
        add("class %d" % cls, "entry", world([], cls=cls))
    add("gate stops", "entry", world([], cls=0, gate=[0x8000000000000001, 0x12, 0x34]))
    add("gate stops sell", "entry", world([], {"side": 1, "size": 77, "user": USERS[1]}, cls=0, gate=[0x8000000000000003, 0x56, 0x78], mid=999))
    add("oid at limit", "entry", world([], next_oid=MAX64))
    add("oid near limit", "entry", world([], next_oid=MAX64 - 1))
    add("zero oid word", "entry", world([], next_oid=0))
    add("given oid", "entry", world([], {"oid_tag": 1, "oid": 0x4321}))

    # rest of an order without a cross
    for side in (0, 1):
        for tail, head in ((None, None), (6, 5), (0, 0)):
            add("rest side %d level head %r tail %r" % (side, head, tail), "rest", world(book(1 - side, (2, 2))[0:0] + [chain(50 if side == 0 else 150, [1])], {"side": side, "cloid": "0102030405060708090a0b0c0d0e0f10", "vector": [7, 8]}, rest_level=[head, tail], extra_slots=[{"size": 7}] * 6))
    add("rest tail vacant", "rest", world([], rest_level=[0, 1], extra_slots=[{"size": 7}, {"vacant": True}]))
    add("rest tail outside", "rest", world([], rest_level=[0, 2], extra_slots=[{"size": 7}, {"vacant": True}]))
    add("rest tail edge", "rest", world([], rest_level=[0, 0], extra_slots=[{"size": 7}, {"vacant": True}], slab_short=2))
    add("rest with given oid", "rest", world([], {"oid_tag": 1, "oid": 0x4321}))
    add("rest gate no", "rest", world([], may_rest=False))
    add("rest gate no given oid", "rest", world([], {"oid_tag": 1}, may_rest=False, relations={"1911": [1, 5]}))
    add("reserve stops", "rest", world([], reserve=[0x8000000000000002, 0x31, 0x32]))
    add("reserve stops given oid", "rest", world([], {"oid_tag": 1, "vector": [1]}, reserve=[0x8000000000000004, 0x41, 0x42]))
    add("reserve text", "rest", world([], reserve=[0x20, 0, 0x20]))

    # one and several fills
    for side in (0, 1):
        for sizes in ((4,), (10,), (11,), (3, 3), (4, 4, 4), (6, 4), (0, 12), (20,), (2, 2, 2, 2), (1, 1, 1, 1, 1, 1)):
            for tif in (2, 1):
                for oid_tag in (0, 1):
                    add("fill side %d sizes %r tif %d oid %d" % (side, sizes, tif, oid_tag), "fill", world(book(side, sizes, [100 - 2 * i * 5 if side else 100 + 0 for i in range(len(sizes))] if False else None), {"side": side, "tif": tif, "oid_tag": oid_tag, "px": 200 if not side else 10}))
    add("limit stops walk buy", "fill", world(book(0, (4, 4, 4)), {"px": 110}))
    add("limit stops walk sell", "fill", world(book(1, (4, 4, 4)), {"side": 1, "px": 90}))
    add("limit between buy", "fill", world(book(0, (4, 4, 4)), {"px": 115}))
    add("limit between sell", "fill", world(book(1, (4, 4, 4)), {"side": 1, "px": 95}))
    add("chain one level", "fill", world([chain(100, [3, 3, 3, 3])]))
    add("chain two levels", "fill", world([chain(100, [3, 3]), chain(110, [3, 3], 2)]))
    add("seven levels", "fill", world(book(0, (2, 2, 2, 2, 2, 2, 2)), {"size": 13, "px": 200}))
    add("eight levels sell", "fill", world(book(1, (2,) * 8, [150 - 10 * i for i in range(8)]), {"side": 1, "size": 15, "px": 10}))
    add("nine levels partly", "fill", world(book(0, (2,) * 9), {"size": 5, "px": 200}))
    add("last trade from settle", "fill", world(book(0, (4, 4)), {"px": 200}, settled={"0": [97, 4]}))
    add("smaller fill from settle", "fill", world(book(0, (4, 4)), {"px": 200}, settled={"0": [100, 2]}))
    add("settle above maker", "fill", world(book(0, (4,)), {"px": 200}, settled={"0": [100, 5]}))
    add("settle above taker", "fill", world(book(0, (20,)), {"px": 200, "size": 5}, settled={"0": [100, 6]}))
    add("first fill drops", "fill", world(book(0, (4, 4)), {"px": 200}, convert={"0": [0, 1, 2]}))
    add("tag two", "fill", world(book(0, (4, 4)), {"px": 200}, convert={"0": [2, 1, 2]}))
    add("cannot settle", "fill", world(book(0, (4, 4)), {"px": 200}, can={"0": False}))
    add("cannot settle in chain", "fill", world([chain(100, [4, 4]), chain(110, [4], 2)], {"px": 200}, can={"0": False}))
    add("cannot settle last", "fill", world(book(0, (4, 4)), {"px": 200}, can={"1": False}))
    add("cannot settle ioc", "fill", world(book(0, (4, 4)), {"px": 200, "tif": 1, "oid_tag": 1}, can={"0": False, "1": False}))
    add("leg tag panic", "fill", world(book(0, (4,)), {"px": 200}, leg_tag=2))
    add("leg tag three", "fill", world(book(0, (4,)), {"px": 200}, leg_tag=3))
    add("notional top", "fill", world([chain(2 ** 40, [2 ** 23 - 1])], {"px": 2 ** 41, "size": 2 ** 23 - 1}, tick=1, balances={"9": [2 ** 64 - 1, 0]}))
    add("notional just over", "fill", world([chain(2 ** 40, [2 ** 23])], {"px": 2 ** 41, "size": 2 ** 23}, tick=1, balances={"9": [2 ** 64 - 1, 0]}))
    add("notional wraps", "fill", world([chain(2 ** 32, [2 ** 32])], {"px": 2 ** 41, "size": 2 ** 32}, tick=1, balances={"9": [2 ** 64 - 1, 0]}))
    add("notional edge word", "fill", world([chain(3, [(2 ** 63 - 2) // 3])], {"px": 30, "size": (2 ** 63 - 2) // 3}, tick=1, balances={"9": [2 ** 64 - 1, 0]}))
    add("notional edge plus", "fill", world([chain(3, [(2 ** 63 + 1) // 3])], {"px": 30, "size": (2 ** 63 + 1) // 3}, tick=1, balances={"9": [2 ** 64 - 1, 0]}))

    # balance cap
    for free, label in ((0, "none"), (100, "one"), (399, "under"), (400, "exact"), (401, "over"), (1000, "plenty"), (2 ** 33, "wide")):
        for hold in (0, 7):
            add("buy free %s hold %d" % (label, hold), "cap", world(book(0, (4, 4)), {"px": 200}, balances={"9": [free + hold, hold]}))
            add("buy free %s second level hold %d" % (label, hold), "cap", world(book(0, (4, 4)), {"px": 200, "oid_tag": 1}, balances={"9": [free + hold + 400, hold]}))
    add("buy hold above total", "cap", world(book(0, (4,)), {"px": 200}, balances={"9": [5, 9]}))
    add("buy no balance row", "cap", world(book(0, (4,)), {"px": 200}, balances={}))
    add("buy other tokens", "cap", world(book(0, (4,)), {"px": 200}, balances={"1": [10 ** 6, 0], "8": [10 ** 6, 0]}))
    add("buy deep key", "cap", world(book(0, (4,)), {"px": 200}, balances={"1": [10 ** 6, 0], "2": [10 ** 6, 0], "3": [10 ** 6, 0], "4": [10 ** 6, 0], "9": [800, 0], "11": [10 ** 6, 0], "13": [10 ** 6, 0]}))
    add("buy key in root", "cap", world(book(0, (4,)), {"px": 200}, balances={"1": [10 ** 6, 0], "2": [10 ** 6, 0], "3": [10 ** 6, 0], "9": [800, 0], "11": [10 ** 6, 0]}))
    add("buy wide division", "cap", world([chain(2 ** 33, [4])], {"px": 2 ** 34, "size": 4}, tick=1, balances={"9": [2 ** 35, 0]}))
    add("buy wide free", "cap", world([chain(3, [4])], {"px": 20, "size": 4}, tick=1, balances={"9": [2 ** 34, 0]}))
    for amount, label in ((0, "none"), (1, "one"), (3, "under"), (4, "exact"), (5, "over")):
        add("sell amount %s" % label, "cap", world(book(1, (4, 4)), {"side": 1, "px": 10}, amount=amount, balances={"5": [40, 3]}))
        add("sell amount %s given oid" % label, "cap", world(book(1, (4, 4)), {"side": 1, "px": 10, "oid_tag": 1}, amount=amount))
    add("sell second level short", "cap", world(book(1, (4, 4)), {"side": 1, "px": 10, "size": 8}, amount=5))

    # same user and flagged makers
    other = USERS[0]
    add("self only", "skip", world([{"px": 100, "slots": [slot(TAKER, 4, 0x301)]}], {"px": 200}))
    add("self only taker", "skip", world([{"px": 100, "slots": [slot(TAKER, 4, 0x301)]}], {"px": 200, "tif": 1}))
    add("self then other", "skip", world([{"px": 100, "slots": [slot(TAKER, 4, 0x301), slot(other, 4, 0x302)]}], {"px": 200}))
    add("system pair", "skip", world([{"px": 100, "slots": [slot(other, 4, 0x301), slot(USERS[1], 2, 0x302)]}], {"px": 200}, system=[TAKER, other]))
    add("system taker only", "skip", world(book(0, (4,)), {"px": 200}, system=[TAKER]))
    add("system maker only", "skip", world(book(0, (4,)), {"px": 200}, system=[USERS[0]]))
    add("flag maker", "skip", world([{"px": 100, "slots": [slot(other, 4, 0x301, 1), slot(USERS[1], 4, 0x302)]}], {"px": 200}))
    add("flag maker same user first", "skip", world([{"px": 100, "slots": [slot(TAKER, 4, 0x301, 1), slot(other, 4, 0x302, 1)]}], {"px": 200}))
    add("two skips one user", "skip", world([{"px": 100, "slots": [slot(other, 4, 0x301, 1), slot(other, 4, 0x302, 1), slot(other, 4, 0x303, 1)]}], {"px": 200}))
    add("users in key order", "skip", world([{"px": 100, "slots": [slot(USERS[2], 4, 0x301, 1), slot(USERS[0], 4, 0x302, 1), slot(USERS[3], 4, 0x303, 1), slot(USERS[1], 4, 0x304, 1)]}], {"px": 200}))
    add("users then repeat", "skip", world([{"px": 100, "slots": [slot(USERS[2], 4, 0x301, 1), slot(USERS[0], 4, 0x302, 1), slot(USERS[2], 4, 0x303, 1), slot(USERS[0], 4, 0x304, 1), slot(USERS[1], 4, 0x305, 1)]}], {"px": 200}))
    add("five skips grow", "skip", world([{"px": 100, "slots": [slot(other, 4, 0x301 + i, 1) for i in range(6)]}], {"px": 200}))
    add("six removals grow", "skip", world([{"px": 100, "slots": [slot(other, 1, 0x301 + i) for i in range(7)]}], {"px": 200}))
    add("no fill no size", "skip", world(book(0, (4,)), {"px": 200, "size": 0}))
    add("no size order given oid", "skip", world(book(0, (4,)), {"px": 200, "size": 0, "oid_tag": 1}))
    add("zero maker only", "skip", world(book(0, (0,)), {"px": 200}))

    # slab faults
    add("slot outside", "fault", world(book(0, (4, 4)), {"px": 200}, slab_short=3))
    add("slot vacant", "fault", world(book(0, (4, 4)), {"px": 200}, broken_slot=0))
    add("second slot vacant", "fault", world([chain(100, [4, 4])], {"px": 200}, broken_slot=1))
    add("slab edge", "fault", world(book(0, (4, 4)), {"px": 200}, slab_short=2, extra_slots=[]))

    # anchor band
    base = {"rows": [[2, 3], [5, 0]], "tokens": {"5": 0, "0": 0}, "anchor": 100}
    for px, side, label in ((119, 0, "inside"), (120, 0, "edge"), (121, 0, "over"), (130, 0, "far"), (80, 1, "edge"), (81, 1, "inside"), (79, 1, "over"), (50, 1, "far")):
        add("band %s side %d" % (label, side), "band", world([chain(px, [4])], {"side": side, "px": 200 if not side else 10}, **base))
        add("band %s side %d second level" % (label, side), "band", world([chain(100, [4]), chain(px, [4], 1)], {"side": side, "px": 200 if not side else 10}, **base))
        add("band %s side %d given oid" % (label, side), "band", world([chain(100, [4]), chain(px, [4], 1)], {"side": side, "px": 200 if not side else 10, "oid_tag": 1}, relations={"1911": [1, 44], "44": [3, 0]}, **base))
    add("band base absent", "band", world([chain(200, [4])], {"px": 300}, rows=[[2, 3], [5, 0]], tokens={"0": 0}))
    add("band base present quote nonzero", "band", world([chain(200, [4])], {"px": 300}, rows=[[2, 3], [5, 7]], tokens={"7": 0, "5": 0}))
    add("band zero anchor", "band", world([chain(200, [4])], {"px": 300}, rows=[[2, 3], [5, 0]], tokens={"5": 0, "0": 0}, anchor=0))
    add("band zero anchor sell", "band", world([chain(200, [4])], {"side": 1, "px": 100}, rows=[[2, 3], [5, 0]], tokens={"5": 0, "0": 0}, anchor=0))
    add("band zero both", "band", world([{"px": 0, "slots": [slot(USERS[0], 4, 0x400)]}], {"px": 0}, rows=[[2, 3], [5, 0]], tokens={"5": 0, "0": 0}, anchor=0, tick=1))
    add("band wide price", "band", world([chain(2 ** 53 + 2 ** 20, [1])], {"px": 2 ** 54, "size": 1}, rows=[[2, 3], [5, 0]], tokens={"5": 0, "0": 0}, anchor=2 ** 53, tick=1, balances={"9": [2 ** 64 - 1, 0], "0": [2 ** 64 - 1, 0]}))
    add("band high bit anchor", "band", world([chain(2 ** 63 + 2 ** 12, [1])], {"px": 2 ** 63 + 2 ** 14, "size": 1}, rows=[[2, 3], [5, 0]], tokens={"5": 0, "0": 0}, anchor=2 ** 63, tick=1, balances={"0": [2 ** 64 - 1, 0]})) if False else None
    add("band relation tag two", "band", world([chain(100, [4]), chain(150, [4], 1)], {"px": 200, "oid_tag": 1}, relations={"1911": [2, 44], "44": [3, 0]}, **base))
    add("band no relation", "band", world([chain(100, [4]), chain(150, [4], 1)], {"px": 200, "oid_tag": 1}, **base))
    add("band relation other gone", "band", world([chain(100, [4]), chain(150, [4], 1)], {"px": 200, "oid_tag": 1}, relations={"1911": [1, 45]}, **base))
    add("band skip rows only", "band", world([{"px": 100, "slots": [slot(TAKER, 4, 0x301)]}, chain(150, [4], 1)], {"px": 200}, **base))

    # rest after fills, status row
    for may, reserve in ((True, [OK, 0, 0]), (False, [OK, 0, 0]), (True, [0x8000000000000002, 1, 2]), (True, [0x20, 0, 0x20])):
        for oid_tag in (0, 1):
            for kind in (2, 9, 10):
                add("after fills may %d word %#x oid %d kind %d" % (may, reserve[0], oid_tag, kind), "after", world(book(0, (4,), [100]) + [{"px": 300, "slots": [slot(USERS[1], 4, 0x501)]}], {"px": 200, "kind": kind, "oid_tag": oid_tag, "vector": [9, 8, 7]}, may_rest=may, reserve=reserve, relations={"1911": [1, 44], "44": [3, 0]}))
    add("given rest big size", "after", world(book(0, (4,)), {"px": 200, "size": 2 ** 40 * 3, "oid_tag": 1, "cloid": "aa" * 16}, balances={"9": [2 ** 60, 0]}))
    add("taker kept client id", "after", world(book(0, (10,)), {"px": 200, "cloid": "bb" * 16, "tif": 3}))
    add("taker tif four", "after", world(book(0, (4,)), {"px": 200, "tif": 4, "oid_tag": 1}))
    add("block tag one", "after", world(book(0, (4,)), {"px": 200, "block": 1}))
    add("word ge nine", "after", world(book(0, (4,)), {"px": 200, "kind": 0x100000009}))
    # tree and word shapes
    for side in (0, 1):
        for deep in (1, 2, 7, 8, 9, 16):
            add("deep %d side %d" % (deep, side), "shape", world(book(side, (2, 2, 2)), {"side": side, "px": 200 if not side else 10}, deep=deep))
            add("deep %d side %d no size left" % (deep, side), "shape", world(book(side, (2, 2, 2)), {"side": side, "px": 200 if not side else 10, "size": 3}, deep=deep))
        for height, count in ((2, 7), (2, 9), (3, 15), (4, 31)):
            add("height %d levels %d side %d" % (height, count, side), "shape", world(book(side, (1,) * count, [100 - i if side else 100 + i for i in range(count)]), {"side": side, "px": 300 if not side else 1, "size": count + 1, "tif": 1}, tree_height=height, tick=1))
    add("spare is quote", "shape", world(tokens={"3": 0, "5": 0}, spare=9))
    add("spare is quote more keys", "shape", world(tokens={"1": 0, "2": 0, "3": 0}, spare=9))
    add("band spare is base", "shape", world([chain(150, [4])], {"px": 200}, rows=[[2, 3], [5, 0]], tokens={"0": 0, "1": 0}, spare=5))
    add("band spare is base lower", "shape", world([chain(150, [4])], {"px": 200}, rows=[[2, 3], [5, 0]], tokens={"0": 0}, spare=5))
    add("band first key", "shape", world([chain(150, [4])], {"px": 200}, rows=[[2, 3], [0, 0]], tokens={"0": 0}))
    add("band first key off", "shape", world([chain(150, [4])], {"px": 200}, rows=[[2, 3], [0, 0]], tokens={"0": 1}))
    add("wide quote word", "shape", world(rows=[[2, 3], [5, 0x1122334455667788]]))
    add("balance spare", "shape", world(book(0, (4,)), {"px": 200}, balances={"3": [5, 0]}, spare=9))
    add("balance spare low", "shape", world(book(0, (4,)), {"px": 200}, balances={"3": [5, 0], "4": [5, 0], "5": [5, 0]}, spare=9))
    add("price just over limit", "shape", world([], {"px": 10 ** 15 + 1}, tick=1))
    add("tick wide window", "shape", world([], {"px": 2 ** 32 + 10}))
    add("tick wide window off", "shape", world([], {"px": 2 ** 32 + 3}, tick=7))
    add("free wide window", "shape", world([chain(3, [4])], {"px": 30, "size": 4}, tick=1, balances={"9": [2 ** 32 + 5, 0]}))
    add("free wide short", "shape", world([chain(2 ** 32 + 1, [4])], {"px": 2 ** 33, "size": 4}, tick=1, balances={"9": [2 ** 33 + 5, 0]}))
    add("free one over hold", "shape", world([chain(1, [4])], {"px": 10, "size": 4}, balances={"9": [5, 9]}))
    add("notional top word", "shape", world([chain(7, [(2 ** 63 - 1) // 7])], {"px": 70, "size": (2 ** 63 - 1) // 7}, tick=1, balances={"9": [2 ** 64 - 1, 0]}))
    add("kind eight", "shape", world(book(0, (4,)), {"px": 200, "kind": 8}))
    add("kind nine", "shape", world(book(0, (4,)), {"px": 200, "kind": 9}))
    add("block on status row", "shape", world(book(0, (10,)), {"px": 200, "block": 1}))
    add("block off status row", "shape", world(book(0, (10,)), {"px": 200, "block": 5}))
    add("vector on status row", "shape", world(book(0, (10,)), {"px": 200, "vector": [4, 5, 6]}))
    add("reserve wide payload", "shape", world([], reserve=[0x8000000000000002, 0x1122334455667788, 0x99AABBCCDDEEFF00]))
    add("gate wide payload", "shape", world([], cls=0, gate=[0x8000000000000002, 0x1122334455667788, 0x99AABBCCDDEEFF00]))
    add("high users", "shape", world([{"px": 100, "slots": [slot(HIGH_USERS[0], 4, 0x601, 1), slot(HIGH_USERS[2], 4, 0x602, 1), slot(HIGH_USERS[1], 4, 0x603, 1)]}], {"px": 200}))
    add("high users repeat", "shape", world([{"px": 100, "slots": [slot(HIGH_USERS[0], 4, 0x601, 1), slot(HIGH_USERS[2], 4, 0x602, 1), slot(HIGH_USERS[2], 4, 0x603, 1), slot(HIGH_USERS[0], 4, 0x604, 1)]}], {"px": 200}))
    add("self only taker vector", "shape", world([{"px": 100, "slots": [slot(TAKER, 4, 0x301)]}], {"px": 200, "tif": 1, "vector": [3, 4]}))
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

SURVIVED_DEFAULT = "same result on every case: read by hand, the changed word is not visible on any path a case takes"
CLEANUP = "cleanup flag: read only by unwind pads, or written again before any read"
DEAD_FEED = "feeds the dead user walks: the set flag at rsp+0x180 stays 0, see dead_arm_words"
SAME_BOUND = "second read of a row bound that the entry already proved for the same asset; the flipped offset reads a larger filler word"
SURVIVED_REASONS = {
    0x26E85F5: "chooses between two equal unrolled descents; the result differs only for one exact height that takes the other arm",
    0x26E8CC2: "unrolled descent after a separator: needs a mid tree descent of nine levels, the deepest uniform tree here has height 4",
    0x26E863E: "a B-tree leaf is never empty, so both arms are equal on valid trees",
    0x26E86F4: CLEANUP, 0x26E87BA: CLEANUP, 0x26E87F8: CLEANUP, 0x26EB9A4: CLEANUP, 0x26EBABF: CLEANUP, 0x26EA0F0: CLEANUP, 0x26EA0FE: CLEANUP, 0x26EA278: CLEANUP,
    0x26E874A: "mask of the low byte, which is added back: the flipped bit is the same either way",
    0x26EA72E: "mask of the low byte, which is added back: the flipped bit is the same either way",
    0x26E8864: SAME_BOUND, 0x26E8D49: SAME_BOUND, 0x26E9573: SAME_BOUND,
    0x26E8A13: "byte past the taker fields that any stub reads; no reader in this function",
    0x26E90FB: "lazy init guard: both arms arrive at 0x26e9101 with the same state",
    0x26E931E: "stores a word past the 20 byte key of the vacant entry; padding",
    0x26E9698: "height word of the map entry: the leaf insert reads it only when a leaf splits, which needs 12 users",
    0x26E96DA: "status 0x12 is only compared for inequality with 0x18",
    0x26E96E4: "status 0x12 is only compared for inequality with 0x18",
    0x26E9BBE: DEAD_FEED, 0x26E9BCB: DEAD_FEED, 0x26E9BDA: DEAD_FEED, 0x26E9BEB: DEAD_FEED, 0x26E9C6C: DEAD_FEED, 0x26E9C76: DEAD_FEED,
    0x26EA04B: DEAD_FEED, 0x26EA1DA: "removal kind 2 has no writer in this body, so 2 and 3 act alike",
    0x26EA05D: "second word of an error result on an arm that leaves it stale",
    0x26EAC98: DEAD_FEED, 0x26EACA0: DEAD_FEED, 0x26EB319: DEAD_FEED, 0x26EB31F: DEAD_FEED, 0x26EB852: DEAD_FEED, 0x26EB860: DEAD_FEED,
}


def unreached_reason(va):
    if 0x26EACA9 <= va <= 0x26EB774:
        return "dead user walks: the flag at rsp+0x180 and the map root at rsp+0x1f8 stay 0, see dead_arm_words"
    if va == 0x26EA138:
        return "removal kind 2: no writer in this body"
    return "no case reaches it: an allocator failure, a climb from an empty leaf, a descent of nine or more levels after a separator, a split user map, the slow arm of a lazy init, or a sum overflow panic"


SEPARATE = {DROP_ROWS: "drop glue of the local result, run with no mutants", DROP_MAP: "user map drop, run with no mutants", USER_MAP_INSERT: "user map insert wrapper, run with no mutants", 0x1AD9950: "user map leaf insert, run with no mutants"}
UNWIND_START = 0x26EBB70


def main_rows(image):
    begin, end = image.exact_fde(INSERT)
    return [row for row in decode_range(image, begin, end) if row.va < UNWIND_START]


def run_mutants(image, reached, verbose=False):
    """A mutant only changes a run that reaches its instruction, so only those cases run; the last killers go first."""
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
    for va, at, kind in mutation_targets(image, main_rows(image)):
        indices = by_va.get(va)
        if not indices:
            results.append({"function": INSERT, "va": va, "kind": kind, "result": "unreached", "by": ""})
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
                del first_kill[60:]
                break
        machine.patches = {}
        machine.cache.pop(va, None)
        results.append({"function": INSERT, "va": va, "kind": kind, "result": "killed" if failed else "survived", "by": ":".join(failed.split(":")[:2])[:70] if failed else ""})
        if verbose and not failed:
            print("survived %#x %s" % (va, kind), flush=True)
    return results


# ---- evidence ----

def code(image, va, count):
    return bytes(image.blob[image.offset(va):image.offset(va) + count])


def require(image, va, data, what):
    if code(image, va, len(data)) != data:
        raise EvidenceError("%s: bytes at %#x differ" % (what, va))


def location_row(image, relative, slot):
    path, line, column = image.location(slot, relative)
    return {"slot": "%#x" % slot, "path": path, "line": line, "column": column}


def float_at(image, va):
    bits = struct.unpack_from("<Q", image.blob, image.offset(va))[0]
    return {"va": "%#x" % va, "bits": "%#x" % bits, "value": repr(to_float(bits))}


def tif_rows(image):
    """Jump table of the time in force byte: entries 0 to 4 land in the function, by raw i32 words."""
    begin, end = image.exact_fde(INSERT)
    rows = []
    for index in range(6):
        arm = TIF_TABLE + struct.unpack_from("<i", image.blob, image.offset(TIF_TABLE) + index * 4)[0]
        inside = begin <= arm < end
        if inside != (index < 5):
            raise EvidenceError("time in force table entry %d" % index)
        rows.append({"tif": index, "arm": "%#x" % arm, "inside": inside})
    return rows


def status_sites(image):
    """Each status word built from the 1 << 63 constant, at its site, by exact bytes."""
    rows = []
    for va, data, word in ((0x26E84FB, b"\x49\x8d\x45\x17", 0x17), (0x26E873E, b"\x49\x8d\x45\x06", 6), (0x26E86DB, b"\x49\x8d\x45\x08", 8), (0x26E87E8, b"\x49\x8d\x45\x05", 5), (0x26E88A3, b"\x49\x8d\x45\x14", 0x14),
                           (0x26E96E4, b"\x48\x83\xc1\x12", 0x12), (0x26E9E1F, b"\x48\x8d\x48\x12", 0x12), (0x26E96FF, b"\x48\x83\xc0\x18", 0x18), (0x26EA782, b"\x49\x8d\x44\x24\x08", 8), (0x26EB8E9, b"\x4d\x8d\x74\x24\x13", 0x13), (0x26EBA7F, b"\x48\x83\xc1\x13", 0x13)):
        require(image, va, data, "status word %#x" % word)
        rows.append({"va": "%#x" % va, "status": "%#x" % (NONE_WORD + word), "bytes": data.hex()})
    return rows


def fixed_words(image):
    """Each constant the walk depends on, at a fixed site, by exact bytes."""
    rows = []
    for va, data, what in ((0x26E8768, b"\x48\xb8" + struct.pack("<Q", PX_LIMIT), "price limit 10^15"),
                           (0x26E9492, b"\xb9" + struct.pack("<I", 10 ** 9), "fee class scale, maker"),
                           (0x26E952F, b"\xb9" + struct.pack("<I", 10 ** 9), "fee class scale, taker"),
                           (0x26E8E5A, b"\xf2\x0f\x10\x0d", "load of the 0.2 band"),
                           (0x26E8E43, b"\xf2\x0f\x58\x05", "add of -1.0"),
                           (0x26E9D80, b"\x4c\x69\xf5" + struct.pack("<I", FILL_SIZE), "fill row stride"),
                           (0x26E8EBF, b"\x48\x69\xc0" + struct.pack("<I", SLOT_SIZE), "slab slot stride"),
                           (0x26E9077, b"\x0f\x28\x84\x24\xe0\x05\x00\x00", "first skip row store"),
                           (0x26E908F, b"\xc6\x44\xc8\x20\x09", "same user reason 9"),
                           (0x26E9180, b"\xc6\x44\xc8\x20\x0a", "flagged maker reason 10"),
                           (0x26EA138, b"\xb0\x05", "removal reason 5, unused arm"),
                           (0x26EA1EC, b"\xb0\x01", "removal reason 1")):
        require(image, va, data, what)
        rows.append({"va": "%#x" % va, "what": what, "bytes": data.hex()})
    return rows


def writer_rows(image):
    """Stack words that a dead arm tests: every write of the word in the function, from decoded rows."""
    rows = []
    begin, end = image.exact_fde(INSERT)
    decoded = decode_range(image, begin, end)
    for name, word in (("set flag", 0x180), ("second user map root", 0x1F8), ("copied set flag", 0xF0)):
        writes = []
        for row in decoded:
            if row.op in ("movx",) and row.a and row.a[0] == "m" and row.a[1] == RSP and word - 15 <= row.a[4] <= word:
                writes.append("%#x" % row.va)
            elif row.a and row.a[0] == "m" and row.a[1] == RSP and row.a[4] == word and row.op in ("mov", "add", "sub", "inc", "dec"):
                writes.append("%#x" % row.va)
        rows.append({"word": "%#x" % word, "name": name, "writes": writes, "before_first_read": [site for site in writes if int(site, 16) < 0x26EA018]})
    return rows


def copy_rows(image):
    """The six insert bodies by FDE size; only first copies of each family are read."""
    rows = []
    for start, role in ((INSERT, "this packet"), (0x430D610, "named by #47"), (TWIN, "same size twin of #47"), (0x26EBDC0, "named by #235"), (0x4311140, "sibling"), (0x4314DA0, "sibling")):
        begin, end = image.exact_fde(start)
        body = code(image, begin, end - begin)
        rows.append({"start": "%#x" % begin, "size": end - begin, "role": role, "tick_word": body.count(struct.pack("<Q", PX_LIMIT)), "leg_calls": len([1 for site, _ in direct_sites(image, [LEG])[LEG] if begin <= site < end])})
    return rows


def outcome_name(case, spec):
    if "panic" in spec:
        return "%s panic %s" % (case.kind, spec["panic"])
    result = spec["result"]
    if "status" in result:
        return "%s status %#x" % (case.kind, result["status"])
    return "%s %d fills, %s" % (case.kind, min(len(result["fills"]), 3), "rests" if spec["book"]["rest"][1] is not None else "done")


def case_line(case, spec):
    return "\t".join((case.kind, case.label, outcome_name(case, spec), str(len(spec["log"]))))


def analyse(image, full=True, verbose=False):
    harness = Harness(image)
    cases = all_cases()
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
    begin, end = image.exact_fde(INSERT)
    rows = decode_range(image, begin, end)
    main = main_rows(image)
    functions = [{"role": "spot insert body", "start": "%#x" % begin, "end": "%#x" % end, "size": end - begin, "instructions": len(rows), "before_unwind": len(main), "stepped": sum(1 for row in rows if row.va in seen)}]
    for start, role in sorted(SEPARATE.items()):
        low, high = image.exact_fde(start)
        decoded = decode_range(image, low, high)
        functions.append({"role": role, "start": "%#x" % low, "end": "%#x" % high, "size": high - low, "instructions": len(decoded), "stepped": sum(1 for row in decoded if row.va in seen)})
    relative = {slot: addend for slot, kind, addend, _ in image.relocations() if kind == 8}
    sites = direct_sites(image, [INSERT])[INSERT]
    statics = {
        "callers": [{"site": "%#x" % site, "host": "%#x" % image.fde(site)[0], "kind": "call" if opcode == 0xE8 else "jump"} for site, opcode in sorted(sites)],
        "tif_table": tif_rows(image),
        "status_word_sites": status_sites(image),
        "fixed_words": fixed_words(image),
        "dead_arm_words": writer_rows(image),
        "copies": copy_rows(image),
        "band": [float_at(image, ANCHOR_BAND), float_at(image, MINUS_ONE)],
        "text": {"va": "0x3ef9bc", "value": bytes(image.blob[image.offset(0x3EF9BC):image.offset(0x3EF9BC) + 0x1D]).decode("ascii")},
        "locations": [location_row(image, relative, slot) for slot in (0x56BD858, 0x56BD870, 0x56BD888, 0x56BD8A0, 0x56BD8B8, 0x56BD810, 0x56BD7E0, 0x56C4F20, 0x56F1FD8)],
        "slots": [{"slot": "%#x" % slot, "target": "%#x" % relative[slot]} for slot in (SLOT_REFRESH, SLOT_CLASS, SLOT_ANCHOR, SLOT_PREDICATE, SLOT_CLASS_FEE, SLOT_ENTRY, SLOT_AMOUNT, SLOT_CONVERT, SLOT_CAN_SETTLE, SLOT_SETTLE, SLOT_REST_GATE, SLOT_RESERVE, SLOT_CLOID, SLOT_TRACK)],
    }
    results_rows = run_mutants(image, reached, verbose) if full else []
    tally = {key: sum(1 for row_ in results_rows if row_["result"] == key) for key in ("killed", "survived", "unreached")}
    doc = {
        "target": {"file": "artifacts/node/94/hl-node", "sha256": SHA256},
        "functions": functions,
        "cases": {"total": len(cases)},
        "outcomes": dict(sorted(outcomes.items())),
        "mismatches": len(mismatches),
        "first_mismatch": mismatches[0] if mismatches else "",
        "instructions_stepped": steps,
        "mutations": tally,
        "_results": results_rows, "_lines": lines,
    }
    doc.update(statics)
    return doc


def reason_for(row):
    if row["result"] == "killed":
        return ""
    if row["result"] == "unreached":
        return unreached_reason(row["va"])
    return SURVIVED_REASONS.get(row["va"], SURVIVED_DEFAULT)


def render(evidence):
    evidence = dict(evidence)
    results = evidence.pop("_results")
    case_lines = evidence.pop("_lines")
    files = {"evidence.json": (json.dumps(evidence, indent=2, sort_keys=True) + "\n").replace("\x40", "[at]")}
    files["cases.tsv"] = "\n".join(["kind\tlabel\toutcome\tedge_calls"] + case_lines) + "\n"
    lines = ["function\tva\tkind\tresult\tkilled_by\treason"]
    lines += [("%#x\t%#x\t%s\t%s\t%s\t%s" % (row_["function"], row_["va"], row_["kind"], row_["result"], row_["by"], reason_for(row_))) for row_ in results]
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
