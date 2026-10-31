#!/usr/bin/env python3
"""Pin the node #94 order status and TWAP status output from ELF bytes: row kinds 3 and 4, the handlers, the pending vector, the output modes and the JSON lines.

Book hosts write row kind 3 with an inner word: 2 keeps a status in a pending vector, 4 writes the pending vector out, and a builder word of 0 or 1 is a whole row
with a hash. Sinks `0x48547d0` and `0x48551e0` tail jump to handlers `0x47f1100` (kind 3) and `0x47f0d10` (kind 4) through data slots. Handlers pick a rotating file
line, a vector for the block end drain, or a streaming line. The real bytes run in a Python evaluator with the edge callees stubbed. A separately written
specification predicts every step, and every condition, immediate and field offset of the fresh functions is flipped to show the run can tell. No objdump or
readelf output is parsed, and the binary is never executed. Standard library only.
"""

import argparse
import bisect
import collections
import hashlib
import json
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

SLOT_MALLOC = 0x576DFD8
SLOT_FREE = 0x576E010
SLOT_MEMCPY = 0x576DFE0
SLOT_BOUNDS = 0x576DFC8
SLOT_ERROR = 0x576EF80
SLOT_FORMAT = 0x576E040
SLOT_CLOCK = 0x576E8A0
SLOT_TIME_ADD = 0x576E8A8
SLOT_DATE_ADD = 0x576E8B0
SLOT_OPEN = 0x576EAC0
SLOT_FLUSH = 0x576EAA8
SLOT_FLUSH_FLAG = 0x576EF18
SLOT_GROW_STATUS = 0x5776A68
SLOT_GROW_TWAP = 0x5776A48
SLOT_STATUS_HANDLER = 0x5776B00
SLOT_TWAP_HANDLER = 0x5776AF8
SLOT_PANIC = (0x576E470, 0x576E128, 0x576E048, 0x576DFB8, 0x576E108, 0x576E150, 0x576E468)
SLOT_DIR_TEXT = 0x576EB20
SLOT_HOUR_TEXT = 0x576EA60
FLUSH_FLAG_BYTE = 0x5788312

SPOT_SINK = 0x48547D0
PERP_SINK = 0x48551E0
SINK_TABLES = ((SPOT_SINK, 0x6FD33C), (PERP_SINK, 0x6FD35C))
STATUS_HANDLER = 0x47F1100
TWAP_HANDLER = 0x47F0D10
STATUS_BUFFER = 0x47ED990
BLOCK_END = 0x48576A0
DROP_ROW = 0x47E6190
DROP_PACKED = 0x447DED0
DROP_LEFT = 0x44C82E0
ROTATIONS = collections.OrderedDict((
    ("status file", (0x4703AB0, 0x45B3EF0)), ("status stream", (0x47034B0, 0x45B3220)), ("status batch", (0x47052B0, 0x45B3BA0)),
    ("twap file", (0x4701FB0, 0x45B9AB0)), ("twap stream", (0x4705EB0, 0x45B2C20)), ("twap batch", (0x47046B0, 0x45BC6C0)),
))
STATUS_JSON = 0x47EF4D0
STATUS_STREAM_JSON = 0x47EFDA0
STATUS_BATCH_JSON = 0x47EFC70
STATUS_ONE_EVENT = 0x4A78820
STATUS_ALL_EVENTS = 0x4AA1D20
TWAP_STREAM_JSON = 0x47F0130
TWAP_BATCH_JSON = 0x47F05F0
TWAP_ONE_EVENT = 0x4A8CFF0
TWAP_ALL_EVENTS = 0x4A96890
TWAP_JSON = 0x47EF250
STATUS_KEY = 0x48652C0
ORDER_KEY = 0x4865380
STATUS_FIELD = 0x4A9A1A0
STATUS_TABLE = 0x7038DC
ORDER_FIELD = 0x4A9F620
ORDER_JSON = 0x49E8B60
HASH_FIELD = 0x4A98B80
BUILDER_FIELD = 0x4A935D0
BUILDER_JSON = 0x43270A0
TIME_FIELD = 0x4A8F530
OBJECT_END = 0x4865440
ESCAPE = 0x49C6940
DROP_DIR = 0x472FB70
LINE_WRITE = 0x13D12A0
LINE_GROW = 0x13EDC40
TEXT_GROW = 0x454F5D0
ERROR_WRAP = 0x45BE9D0
CONSTRUCTOR = 0x47F1590
HOURLY_TEMPLATE = 0x1E9393
DAILY_TEMPLATE = 0x1E938E

STATUS_ROW = 0x118
TWAP_ROW = 0x88
ROW_WORD = 0x118
MAX64 = (1 << 64) - 1
CLOSED = 1 << 63
BUFFER_BASES = (0x420, 0x4E8, 0x5B0, 0x678, 0x740, 0x808, 0x8D0, 0x998)

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
HEAP_SIZE = 0x40000
RETURN_SENTINEL = 0xDEAD0000
POISON = 0xA5A5A5A5A5A5A5A5
STEP_LIMIT = 400000
MUTANT_STEP_LIMIT = 40000

TIME_IN = HEAP_BASE + 0x580
BLOCK_IN = HEAP_BASE + 0x5C0
TEXT_IN = HEAP_BASE + 0x600
OBJECT = HEAP_BASE + 0x1000
ROW_IN = HEAP_BASE + 0x9000
STATUS_AT = OBJECT + 0x740
TWAP_AT = OBJECT + 0x678
HEAP_FREE = HEAP_BASE + 0xC000

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



# ---- specification: written from the reading of the bytes, shares nothing with the evaluator ----

HASH_SLICE = (0xF0, 0x111)
VIEW_SLICES = ((0x00, 0x28), (0x28, 0xD0), (0xD0, 0xDC), (0xDC, 0xF0), (0x111, 0x112))


def row_view(row):
    """The bytes of a status row that carry a field; padding is stale in stack copies."""
    return {"fields": [row[low:high].hex() for low, high in VIEW_SLICES], "hash_flag": row[0xF0], "hash": row[0xF1:0x111].hex() if row[0xF0] else None}


def unpack_pending(source):
    """Inner word 2 holds a row without a hash, eight bytes down."""
    row = bytearray(STATUS_ROW)
    row[0x00:0xD0] = source[0x08:0xD8]
    row[0xD0:0xF0] = source[0xD8:0xF8]
    row[0x111] = source[0xF8]
    return bytes(row)


def inner_kind(word):
    return "pending" if word == 2 else "flush" if word >= 4 else "direct"


def spec_sink(w):
    return {"slot": SLOT_STATUS_HANDLER if w["kind"] == 3 else SLOT_TWAP_HANDLER, "row": 8}


def spec_handler(w):
    kind = inner_kind(w["word"])
    pending = w["pending"]
    capacity = w["capacity"]
    if w["gate"] == CLOSED:
        log = [] if kind == "flush" else [["drop", 0x30 if kind == "pending" else 0x28]]
        return {"log": log, "vector": [capacity, len(pending)]}
    if kind == "pending":
        log = [["grow"]] if len(pending) == capacity else []
        return {"log": log, "vector": [capacity * 2 or 4 if log else capacity, len(pending) + 1], "pushed": row_view(unpack_pending(w["row"]))}
    if kind == "direct":
        return {"log": [["buffer", w["flag"], list(w["clock"]), row_view(w["row"]), w["block"].hex()]], "vector": [capacity, len(pending)]}
    log = []
    stop = len(pending)
    for index, row in enumerate(pending):
        if struct.unpack_from("<Q", row, 0)[0] == 2:
            stop = index
            break
        log.append(["buffer", w["flag"], list(w["clock"]), row_view(row), w["block"].hex()])
    for index in range(stop + 1, len(pending)):
        log.append(["left", index])
    if capacity:
        log.append(["free", capacity * STATUS_ROW])
    return {"log": log, "vector": [0, 0]}


def later_clock(w):
    """Local time and the helper calls of the 40 ms shift, or None on the overflow panic."""
    clock = w["clock"]
    if not w["flag"]:
        return list(clock), []
    secs, nanos = clock[1] + w["carry"][0], clock[2] + 40000000
    days = w["carry"][1]
    calls = [["time", clock[1], clock[2]]]
    if (days + 0xFFFF574000000000) & MAX64 < 0xFFFEAE7FFFFEAE81:
        return None, calls
    whole = abs(days) // 86400
    calls.append(["date", clock[0], -whole if days < 0 else whole])
    if not w["date_result"]:
        return None, calls
    return [w["date_result"], secs, nanos], calls


def spec_buffer(w):
    mode = w["mode"]
    row = w["row"]
    if mode == "file":
        return {"path": "file", "log": [["drop", "row"]]}
    if mode == "vector":
        grew = w["length"] == w["capacity"]
        return {"path": "vector", "log": [], "length": w["length"] + 1, "grew": grew}
    if not w["block_date"]:
        return {"path": "no block", "log": [["drop", "row"]]}
    local, calls = later_clock(w)
    if local is None:
        return {"path": "panic overflow", "calls": calls}
    return {"path": "stream", "local": local, "calls": calls, "log": [["drop", "copy"]]}


def twap_frees(w, first_then_second=True):
    first = [["free", w["text_cap"]]] if w["text_cap"] else []
    extra = w["extra_cap"]
    second = [["free", extra]] if extra and not CLOSED <= extra <= CLOSED + 2 else []
    return first + second if first_then_second else second + first


def spec_twap(w):
    mode = w["mode"]
    if mode == "closed":
        return {"path": "closed", "log": twap_frees(w, False)}
    if mode == "vector":
        grew = w["length"] == w["capacity"]
        return {"path": "vector", "log": [], "length": w["length"] + 1, "grew": grew}
    if mode == "file":
        return {"path": "file", "log": twap_frees(w)}
    if not w["block_date"]:
        return {"path": "no block", "log": twap_frees(w)}
    local, calls = later_clock(w)
    if local is None:
        return {"path": "panic overflow", "calls": calls}
    return {"path": "stream", "local": local, "calls": calls, "log": twap_frees(w)}


def spec_block(w):
    which = w["which"]
    if not w["date"] or w["gate"] == CLOSED:
        return {"log": []}
    log = []
    calls = []
    drained = w["word"] >> 63 == 0
    if drained:
        local, calls = later_clock(w)
        if local is None:
            return {"path": "panic overflow", "calls": calls}
        log.append(["batch", which, local, w["number"], list(w["block"]), w["length"]])
        for index in range(w["length"]):
            if which == "status":
                log.append(["drop", index])
            else:
                text, extra = w["strings"][index]
                if text:
                    log.append(["free", text])
                if extra and not CLOSED <= extra <= CLOSED + 2:
                    log.append(["free", extra])
        if w["word"]:
            log.append(["free", w["word"] * (STATUS_ROW if which == "status" else TWAP_ROW)])
    if w["flush"]:
        log.append(["flush"])
    return {"log": log, "reset": drained, "calls": calls}


def spec_file(w):
    date, secs = w["time"][0], w["time"][1]
    if not w["open"]:
        return {"path": "closed", "log": []}
    if secs >= 0xE1000:
        return {"path": "panic unwrap", "log": []}
    if secs >= 90000:
        return {"path": "panic hour", "log": []}
    hour = secs // 3600
    log = []
    hourly = w["hourly"]
    if hourly == 1:
        if hour != w["old_hour"] or date != w["old_date"]:
            log.append(["open", "%s/hourly/%s/%s" % (w["dir"], "D%d" % date, "H%d" % hour)])
    elif date != w["old_date"]:
        log.append(["open", "%s/%s" % (w["dir"], "D%d" % date)])
    log.append(["line", list(w["time"])])
    if w["flush"] and w["global_flush"] and w["file_word"] != 1 << 63:
        log.append(["flush"])
    opened = log[0][0] == "open"
    return {"path": "line", "log": log, "date": date if opened else w["old_date"], "hourly": hourly, "hour": hour if opened and hourly == 1 else w["old_hour"], "last": list(w["time"])}


def status_text(r, pad=""):
    builder = "null" if r["builder"] is None else '{"b":"0x%s","f":%d}' % (r["builder"][1], r["builder"][0])
    digest = "null" if r["hash"] is None else '"0x%s"' % r["hash"]
    return '{"time":"C%s%s","user":"0x%s","hash":%s,"builder":%s,"status":"%s","order":"O%s"}' % (pad, r["time"].hex(), r["user"], digest, builder, status_name(r["status"]), r["order"].hex())


def twap_text(r, pad=""):
    return '"T%s%s"' % (pad, r["mark"].hex())


def spec_line(w):
    text = status_text if w["family"] == "status" else twap_text
    pad = "x" * w.get("pad", 0)
    if w["line"] == "file":
        return text(w["rows"][0], pad) + "\n"
    head = '{"local_time":"L%s%s","block_time":"T%s","block_number":%d,"events":[' % (pad, w["local"].hex(), w["block"].hex(), w["number"])
    return head + ",".join(text(r) for r in w["rows"]) + "]}\n"


def spec_run(case):
    return {"sink": spec_sink, "handler": spec_handler, "buffer": spec_buffer, "twap": spec_twap, "block": spec_block, "file": spec_file, "line": spec_line}[case.kind](case.world)


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


NAMES = {}


def status_name(byte):
    return NAMES[byte]


def status_arm(image, arm, end):
    """Text of one arm of the status field: a rip lea of rsi, then the length in this arm or at its jump target."""
    data = bytes(image.blob[image.offset(arm):image.offset(arm) + 20])
    if data[:3] != b"\x48\x8d\x35":
        raise EvidenceError("status arm %#x has no lea" % arm)
    text = arm + 7 + struct.unpack_from("<i", data, 3)[0]
    if data[7] == 0xBA:
        size = struct.unpack_from("<I", data, 8)[0]
    elif data[7] == 0xE9 or data[7] == 0xEB:
        target = arm + 7 + (5 + struct.unpack_from("<i", data, 8)[0] if data[7] == 0xE9 else 2 + struct.unpack_from("<b", data, 8)[0])
        tail = bytes(image.blob[image.offset(target):image.offset(target) + 5])
        if tail[0] != 0xBA:
            raise EvidenceError("status arm %#x has no length" % arm)
        size = struct.unpack_from("<I", tail, 1)[0]
    else:
        raise EvidenceError("status arm %#x shape" % arm)
    return text, size


def status_rows(image):
    """Every entry of table 0x7038dc that lands inside the field writer, with its text."""
    begin, end = image.exact_fde(STATUS_FIELD)
    rows = []
    for index in range(256):
        arm = STATUS_TABLE + struct.unpack_from("<i", image.blob, image.offset(STATUS_TABLE) + index * 4)[0]
        if not begin <= arm < end:
            break
        text, size = status_arm(image, arm, end)
        rows.append((index, arm, text, bytes(image.blob[image.offset(text):image.offset(text) + size]).decode("ascii")))
    return rows


class Harness:
    def __init__(self, image):
        self.image = image
        self.machine = Machine(image)
        machine = self.machine
        self.relative = {slot: addend for slot, kind, addend, _ in image.relocations() if kind == 8}
        relative = self.relative
        NAMES.update({row[0]: row[3] for row in status_rows(image)})
        table = {SLOT_MALLOC: self.on_malloc, SLOT_FREE: self.on_free, SLOT_MEMCPY: self.on_copy, SLOT_GROW_STATUS: self.on_grow, SLOT_GROW_TWAP: self.on_grow, SLOT_BOUNDS: self.on_bounds,
                 SLOT_FORMAT: self.on_format, SLOT_CLOCK: self.on_clock, SLOT_TIME_ADD: self.on_time_add, SLOT_DATE_ADD: self.on_date_add, SLOT_OPEN: self.on_open, SLOT_FLUSH: self.on_flush,
                 SLOT_ERROR: self.on_error, SLOT_STATUS_HANDLER: lambda m: self.on_handler(m, SLOT_STATUS_HANDLER), SLOT_TWAP_HANDLER: lambda m: self.on_handler(m, SLOT_TWAP_HANDLER)}
        for slot in SLOT_PANIC:
            table[slot] = lambda m, which=slot: self.on_panic(m, which)
        for slot in table:
            relative.setdefault(slot, slot)
        machine.memory.statics.update(relative)
        machine.slots = {relative[slot]: hook for slot, hook in table.items()}
        self.real = RealExcept()
        machine.real = self.real
        calls = {DROP_DIR: self.on_drop_dir, TIME_FIELD: self.on_time_field, TEXT_GROW: self.on_text_grow, LINE_GROW: self.on_text_grow, LINE_WRITE: self.on_line, ERROR_WRAP: self.on_wrap,
                 ORDER_JSON: self.on_order, TWAP_JSON: self.on_twap_json}
        machine.tails = {}
        machine.calls = calls
        self.base_calls = calls
        self.base_real = frozenset(machine.slots) | frozenset(calls)
        self.real.stubs = self.base_real
        self.w = None
        self.brk = HEAP_FREE
        self.live = {}
        self.log = []
        self.line = None
        self.vectors = {}
        self.copy_sizes = None
        self.file_at = 0
        self.hit = None

    def use(self, stubs):
        """Stub these targets for this run on top of the base set."""
        calls = dict(self.base_calls)
        calls.update(stubs)
        self.machine.calls = calls
        self.machine.tails = calls
        self.real.stubs = self.base_real | frozenset(stubs)

    def fresh(self, world):
        memory = self.machine.memory
        memory.reset()
        self.brk = HEAP_FREE
        self.live = {}
        self.log = []
        self.line = None
        self.copy_sizes = None
        self.vectors = {}
        self.outs = []
        self.hit = None
        self.w = world
        self.pad = world.get("pad", 0)
        self.machine.jump_low = self.machine.jump_high = 0

    def allocate(self, size):
        at = (self.brk + 15) & ~15
        self.brk = at + size
        if self.brk > HEAP_BASE + HEAP_SIZE:
            raise Halt("heap full")
        self.live[at] = size
        return at

    def on_malloc(self, m):
        size = m.regs[RDI]
        if size > 0x10000:
            raise Halt("allocation size")
        m.regs[RAX] = self.allocate(size)

    def on_free(self, m):
        at, size = m.regs[RDI], m.regs[RSI]
        if self.live.pop(at, None) != size:
            raise Halt("free %#x size %#x" % (at, size))
        self.log.append(["free", size])

    def quiet_free(self, m):
        at, size = m.regs[RDI], m.regs[RSI]
        if self.live.pop(at, None) != size:
            raise Halt("free %#x size %#x" % (at, size))

    def on_copy(self, m):
        regs = m.regs
        if regs[RDX] > 0x10000:
            raise Halt("copy size")
        if self.copy_sizes is not None and regs[RDX] not in self.copy_sizes:
            raise Halt("row copy size")
        if regs[RDX]:
            m.memory.copy(regs[RDI], regs[RSI], regs[RDX])
        regs[RAX] = regs[RDI]

    def on_grow(self, m):
        memory = m.memory
        vector = m.regs[RDI]
        width = self.vectors.get(vector)
        if width is None:
            raise Halt("grow vector")
        capacity, old = memory.read(vector, 8), memory.read(vector + 8, 8)
        if capacity > 0x40 or memory.read(vector + 0x10, 8) != capacity:
            raise Halt("vector size")
        wanted = capacity * 2 or 4
        fresh = self.allocate(wanted * width)
        if capacity:
            memory.copy(fresh, old, capacity * width)
            if self.live.pop(old, None) != capacity * width:
                raise Halt("row buffer")
        memory.write(vector, 8, wanted)
        memory.write(vector + 8, 8, fresh)
        self.log.append(["grow"])

    def on_bounds(self, m):
        raise Panicked("bounds")

    def on_panic(self, m, slot):
        wanted = PANIC_TEXT.get(slot)
        if wanted is not None and m.regs[RSI] != wanted:
            raise Halt("panic text length")
        raise Panicked("panic %#x" % slot)

    def on_error(self, m):
        m.regs[RAX] = 0xE1

    def on_clock(self, m):
        m.memory.put_bytes(m.regs[RDI], struct.pack("<III", *self.w["clock"]))

    def on_time_add(self, m):
        regs = m.regs
        memory = m.memory
        if regs[RDX] & MASK[8] != 0 or regs[RCX] != 40000000:
            raise Halt("time add arguments")
        secs, nanos = memory.read(regs[RSI], 4), memory.read(regs[RSI] + 4, 4)
        self.log.append(["time", secs, nanos])
        carry, days = self.w["carry"]
        memory.put_bytes(regs[RDI], struct.pack("<IIq", secs + carry, nanos + 40000000, days))

    def on_date_add(self, m):
        regs = m.regs
        low = regs[RSI] & MASK[4]
        self.log.append(["date", regs[RDI] & MASK[4], low - (1 << 32) if low >> 31 else low])
        regs[RAX] = self.w["date_result"]

    def on_handler(self, m, slot):
        self.hit = [slot, m.regs[RSI] - ROW_IN, m.regs[RDI] == OBJECT]

    def text_arg(self, m, at):
        return m.memory.bytes_at(m.memory.read(at, 8), m.memory.read(at + 8, 8)).decode("utf-8")

    def string_out(self, m, text):
        data = text.encode("utf-8")
        at = self.allocate(max(len(data), 1))
        m.memory.put_bytes(at, data)
        out = m.regs[RDI]
        m.memory.write(out, 8, len(data))
        m.memory.write(out + 8, 8, at)
        m.memory.write(out + 0x10, 8, len(data))

    def on_format(self, m):
        regs = m.regs
        memory = m.memory
        template, args = regs[RSI], regs[RDX]
        statics = memory.statics
        if template not in (HOURLY_TEMPLATE, DAILY_TEMPLATE):
            raise Halt("format template %#x" % template)
        where = memory.read(args, 8)
        text = self.text_arg(m, where)
        if template == HOURLY_TEMPLATE:
            if memory.read(args + 0x18, 8) != statics[SLOT_HOUR_TEXT] or memory.read(args + 0x28, 8) != statics[SLOT_DIR_TEXT]:
                raise Halt("path text functions")
            text += "/hourly/D%d/H%d" % (memory.read(memory.read(args + 0x10, 8), 4), memory.read(memory.read(args + 0x20, 8), 1))
        else:
            if memory.read(args + 0x18, 8) != statics[SLOT_HOUR_TEXT]:
                raise Halt("path text functions")
            text += "/D%d" % memory.read(memory.read(args + 0x10, 8), 4)
        self.string_out(m, text)

    def on_open(self, m):
        regs = m.regs
        memory = m.memory
        at = regs[RSI]
        self.log.append(["open", memory.bytes_at(memory.read(at + 8, 8), memory.read(at + 0x10, 8)).decode("utf-8")])
        if self.live.pop(memory.read(at + 8, 8), None) is None:
            raise Halt("path buffer")
        memory.put_bytes(regs[RDI], ramp(0x50, 0x41))

    def on_drop_dir(self, m):
        if m.regs[RDI] != self.file_at:
            raise Halt("drop argument")

    def on_flush(self, m):
        if m.regs[RDI] != self.file_at:
            raise Halt("flush argument")
        self.log.append(["flush"])

    def on_file_line(self, m):
        regs = m.regs
        memory = m.memory
        if regs[RDI] != self.file_at or regs[RDX] != ROW_IN:
            raise Halt("line arguments")
        self.log.append(["line", [memory.read(regs[RSI] + 4 * index, 4) for index in range(3)]])

    def on_text_grow(self, m):
        regs = m.regs
        memory = m.memory
        vector, used, extra = regs[RDI], regs[RSI], regs[RDX]
        capacity, old = memory.read(vector, 8), memory.read(vector + 8, 8)
        if regs[RCX] != 1 or regs[R8] != 1 or used + extra <= capacity:
            raise Halt("grow arguments")
        slack = self.w.get("exact")
        wanted = max(capacity * 2, used + extra, 8) if slack is None else used + extra + slack
        fresh = self.allocate(wanted)
        memory.copy(fresh, old, used)
        if capacity and self.live.pop(old, None) != capacity:
            raise Halt("text buffer")
        memory.write(vector, 8, wanted)
        memory.write(vector + 8, 8, fresh)

    def on_line(self, m):
        regs = m.regs
        if regs[RDI] != self.file_at or regs[RSI] != TIME_IN:
            raise Halt("write arguments")
        if self.live.get(regs[RDX], 0) < regs[RCX]:
            raise Halt("line past its buffer")
        self.line = m.memory.bytes_at(regs[RDX], regs[RCX]).decode("utf-8")

    def on_wrap(self, m):
        raise Halt("error line")

    def append_text(self, m, state_vector, data):
        memory = m.memory
        length = memory.read(state_vector + 0x10, 8)
        if (memory.read(state_vector, 8) - length) & MASK[8] < len(data):
            regs = m.regs
            regs[RDI], regs[RSI], regs[RDX], regs[RCX], regs[R8] = state_vector, length, len(data), 1, 1
            self.on_text_grow(m)
        memory.put_bytes(memory.read(state_vector + 8, 8) + length, data)
        memory.write(state_vector + 0x10, 8, length + len(data))

    def on_time_field(self, m):
        """Key, then the twelve time bytes as a marked string: the date text itself is a callee."""
        regs = m.regs
        memory = m.memory
        state = regs[RDI]
        if memory.read(state, 1) != 0:
            raise Halt("field state")
        key = memory.bytes_at(regs[RSI], regs[RDX]).decode("ascii")
        comma = "" if memory.read(state + 1, 1) == 1 else ","
        memory.write(state + 1, 1, 2)
        vector = memory.read(memory.read(state + 8, 8), 8)
        mark = {"local_time": "L", "block_time": "T", "time": "C"}[key]
        value = memory.bytes_at(regs[RCX], 12)
        self.append_text(m, vector, ('%s"%s":"%s%s%s"' % (comma, key, mark, self.take_pad(), value.hex())).encode("ascii"))
        regs[RAX] = 0

    def take_pad(self):
        """Filler in the first stubbed value of a line: it moves every later write across the buffer end."""
        text = "x" * self.pad
        self.pad = 0
        return text

    def text_block(self, size):
        """A live allocation of a size no fake heap holds: only its free is checked."""
        at = self.allocate(8)
        self.live[at] = size
        return at

    def on_order(self, m):
        """Value of the `order` key: the marker is the first eight bytes of the record it got."""
        regs = m.regs
        memory = m.memory
        vector = memory.read(regs[RSI], 8)
        self.append_text(m, vector, ('"O%s"' % memory.bytes_at(regs[RDI], 8).hex()).encode("ascii"))
        regs[RAX] = 0

    def on_twap_json(self, m):
        """Whole TWAP status object, a named serializer in another packet: the marker is the first eight bytes of the row."""
        regs = m.regs
        memory = m.memory
        vector = memory.read(regs[RSI], 8)
        self.append_text(m, vector, ('"T%s%s"' % (self.take_pad(), memory.bytes_at(regs[RDI], 8).hex())).encode("ascii"))
        regs[RAX] = 0

    def on_drop_row(self, m):
        self.log.append(["drop", m.regs[RDI] - ROW_IN])

    def run_sink(self, case):
        w = case.world
        memory = self.machine.memory
        self.fresh(w)
        self.use({})
        memory.put_bytes(ROW_IN, ramp(0x278, 0x21))
        memory.write(ROW_IN, 8, w["kind"])
        start = SPOT_SINK if w["market"] == "spot" else PERP_SINK
        self.machine.jump_low, self.machine.jump_high = self.image.exact_fde(start)
        self.machine.run(start, {RDI: OBJECT, RSI: ROW_IN, RDX: 0x1000, RCX: 0x2000})
        if self.hit is None or not self.hit[2]:
            raise Halt("handler not reached")
        return {"slot": self.hit[0], "row": self.hit[1]}

    def status_buffer(self, m):
        regs = m.regs
        memory = m.memory
        if regs[RDI] != STATUS_AT:
            raise Halt("buffer argument")
        clock = [memory.read(regs[RDX] + 4 * index, 4) for index in range(3)]
        self.log.append(["buffer", regs[RSI] & 0xFF, clock, row_view(memory.bytes_at(regs[RCX], STATUS_ROW)), memory.bytes_at(regs[R8], 0x18).hex()])

    def on_left(self, m):
        at = m.regs[RDI]
        base = self.vector_base
        index, extra = divmod(at - 0x28 - base, STATUS_ROW)
        if extra:
            raise Halt("left row")
        self.log.append(["left", index])

    def run_handler(self, case):
        w = case.world
        machine = self.machine
        memory = machine.memory
        self.fresh(w)
        self.use({STATUS_BUFFER: self.status_buffer, DROP_ROW: self.on_drop_row, DROP_PACKED: self.on_left})
        self.copy_sizes = (0xA8, 0x110, STATUS_ROW)
        self.vectors = {OBJECT + 0x408: STATUS_ROW}
        memory.write(OBJECT + 0xA78, 1, w["flag"])
        memory.put_bytes(OBJECT + 0xA60, w["block"])
        memory.write(STATUS_AT, 8, w["gate"])
        capacity = w["capacity"]
        base = self.allocate(capacity * STATUS_ROW) if capacity else 8
        self.vector_base = base
        for index, row in enumerate(w["pending"]):
            memory.put_bytes(base + index * STATUS_ROW, row)
        memory.write(OBJECT + 0x408, 8, capacity)
        memory.write(OBJECT + 0x410, 8, base)
        memory.write(OBJECT + 0x418, 8, len(w["pending"]))
        memory.put_bytes(ROW_IN, w["row"])
        machine.run(STATUS_HANDLER, {RDI: OBJECT, RSI: ROW_IN})
        out = {"log": self.log, "vector": [memory.read(OBJECT + 0x408, 8), memory.read(OBJECT + 0x418, 8)]}
        if out["vector"][1] > 0x40:
            raise Halt("vector length")
        if inner_kind(w["word"]) == "pending" and w["gate"] != CLOSED:
            at = memory.read(OBJECT + 0x410, 8) + len(w["pending"]) * STATUS_ROW
            out["pushed"] = pending_view(memory.bytes_at(at, STATUS_ROW))
            for index, row in enumerate(w["pending"]):
                if memory.bytes_at(memory.read(OBJECT + 0x410, 8) + index * STATUS_ROW, STATUS_ROW) != row:
                    raise Halt("old row changed")
        elif inner_kind(w["word"]) == "flush" and w["gate"] != CLOSED:
            if memory.read(OBJECT + 0x410, 8) != 8:
                raise Halt("vector pointer")
        elif memory.read(OBJECT + 0x410, 8) != base:
            raise Halt("vector moved")
        return out

    def on_out(self, m, path):
        regs = m.regs
        memory = m.memory
        w = self.w
        if regs[RDI] != self.buffer_at:
            raise Halt("writer argument")
        width = self.row_width
        if path == "file":
            if memory.bytes_at(regs[RSI], 12) != struct.pack("<III", *w["clock"]) or memory.bytes_at(regs[RDX], self.compare) != w["row"][:self.compare]:
                raise Halt("file arguments")
            self.outs.append(["file"])
            return
        at = regs[RDX]
        if memory.bytes_at(at, self.compare) != w["row"][:self.compare]:
            raise Halt("stream row")
        if memory.read(at + width, 8) != w["number"] or memory.read(at + width + 0x14, 4) != w["block_date"] or memory.read(at + width + 0x18, 4) != 0x12345 or memory.read(at + width + 0x1C, 4) != 0x6789A:
            raise Halt("stream block")
        if memory.bytes_at(at + width + 8, 12) != memory.bytes_at(regs[RSI], 12):
            raise Halt("stream time")
        self.outs.append(["stream", [memory.read(regs[RSI] + 4 * index, 4) for index in range(3)]])

    def on_drop_copy(self, m):
        at = m.regs[RDI]
        if at == ROW_IN + 0x28:
            self.log.append(["drop", "row"])
        else:
            if m.memory.bytes_at(at, 0xA8) != self.w["row"][0x28:0xD0]:
                raise Halt("dropped copy")
            self.log.append(["drop", "copy"])

    def run_buffer(self, case):
        w = case.world
        machine = self.machine
        memory = machine.memory
        self.fresh(w)
        self.use({ROTATIONS["status file"][0]: lambda m: self.on_out(m, "file"), ROTATIONS["status stream"][0]: lambda m: self.on_out(m, "stream"), DROP_ROW: self.on_drop_copy})
        self.copy_sizes = (STATUS_ROW,)
        self.buffer_at, self.row_width, self.compare = STATUS_AT, STATUS_ROW, STATUS_ROW
        self.vectors = {STATUS_AT + 0xB0: STATUS_ROW}
        memory.put_bytes(ROW_IN, w["row"])
        memory.put_bytes(TIME_IN, struct.pack("<III", *w["clock"]))
        memory.write(BLOCK_IN, 8, w["number"])
        memory.write(BLOCK_IN + 8, 4, w["block_date"])
        memory.write(BLOCK_IN + 0xC, 4, 0x12345)
        memory.write(BLOCK_IN + 0x10, 4, 0x6789A)
        if w["mode"] == "file":
            word = CLOSED
        elif w["mode"] == "stream":
            word = CLOSED + 2
        else:
            word = w["capacity"]
            base = self.allocate(word * STATUS_ROW) if word else 8
            memory.write(STATUS_AT + 0xB8, 8, base)
            memory.write(STATUS_AT + 0xC0, 8, w["length"])
        memory.write(STATUS_AT + 0xB0, 8, word)
        try:
            machine.run(STATUS_BUFFER, {RDI: STATUS_AT, RSI: w["flag"], RDX: TIME_IN, RCX: ROW_IN, R8: BLOCK_IN})
        except Panicked:
            return {"path": "panic overflow", "calls": [row_ for row_ in self.log if row_[0] in ("time", "date")]}
        calls = [row_ for row_ in self.log if row_[0] in ("time", "date")]
        log = [row_ for row_ in self.log if row_[0] == "drop"]
        mode = w["mode"]
        if mode == "vector":
            length = memory.read(STATUS_AT + 0xC0, 8)
            if length > 0x40:
                raise Halt("vector length")
            stored = memory.bytes_at(memory.read(STATUS_AT + 0xB8, 8) + (length - 1) * STATUS_ROW, STATUS_ROW)
            if stored != w["row"]:
                raise Halt("stored row")
            return {"path": "vector", "log": log, "length": length, "grew": memory.read(STATUS_AT + 0xB0, 8) != w["capacity"]}
        if not self.outs:
            return {"path": "no block", "log": log}
        path = self.outs[0][0]
        out = {"path": path, "log": log}
        if path == "stream":
            out.update(local=self.outs[0][1], calls=calls)
        return out

    def run_twap(self, case):
        w = case.world
        machine = self.machine
        memory = machine.memory
        self.fresh(w)
        self.use({ROTATIONS["twap file"][0]: lambda m: self.on_out(m, "file"), ROTATIONS["twap stream"][0]: lambda m: self.on_out(m, "stream")})
        self.copy_sizes = (TWAP_ROW,)
        self.buffer_at, self.row_width, self.compare = TWAP_AT, TWAP_ROW, 0x84
        self.vectors = {TWAP_AT + 0xB0: TWAP_ROW}
        row = bytearray(ramp(TWAP_ROW, 0x31))
        text = self.allocate(w["text_cap"]) if w["text_cap"] else 1
        struct.pack_into("<QQ", row, 0, w["text_cap"], text)
        extra_cap = w["extra_cap"]
        real = extra_cap and not CLOSED <= extra_cap <= CLOSED + 2
        extra = self.text_block(extra_cap) if real else 0x51
        struct.pack_into("<QQ", row, 0x58, extra_cap, extra)
        w = dict(w, row=bytes(row))
        self.w = w
        memory.put_bytes(ROW_IN, row)
        memory.write(OBJECT + 0xA78, 1, w["flag"])
        memory.write(OBJECT + 0xA60, 8, w["number"])
        memory.write(OBJECT + 0xA68, 4, w["block_date"])
        memory.write(OBJECT + 0xA6C, 4, 0x12345)
        memory.write(OBJECT + 0xA70, 4, 0x6789A)
        mode = w["mode"]
        memory.write(TWAP_AT, 8, CLOSED if mode == "closed" else 0x51)
        word = {"file": CLOSED, "stream": CLOSED + 2}.get(mode, w["capacity"])
        if mode == "vector":
            base = self.allocate(word * TWAP_ROW) if word else 8
            memory.write(TWAP_AT + 0xB8, 8, base)
            memory.write(TWAP_AT + 0xC0, 8, w["length"])
        memory.write(TWAP_AT + 0xB0, 8, word)
        try:
            machine.run(TWAP_HANDLER, {RDI: OBJECT, RSI: ROW_IN})
        except Panicked:
            return {"path": "panic overflow", "calls": [row_ for row_ in self.log if row_[0] in ("time", "date")]}
        calls = [row_ for row_ in self.log if row_[0] in ("time", "date")]
        log = [row_ for row_ in self.log if row_[0] == "free"]
        if mode == "vector":
            length = memory.read(TWAP_AT + 0xC0, 8)
            if length > 0x40:
                raise Halt("vector length")
            stored = memory.bytes_at(memory.read(TWAP_AT + 0xB8, 8) + (length - 1) * TWAP_ROW, 0x84)
            if stored != w["row"][:0x84]:
                raise Halt("stored row")
            return {"path": "vector", "log": log, "length": length, "grew": memory.read(TWAP_AT + 0xB0, 8) != w["capacity"]}
        if mode == "closed":
            return {"path": "closed", "log": log}
        if not self.outs:
            return {"path": "no block", "log": log}
        path = self.outs[0][0]
        out = {"path": path, "log": log}
        if path == "stream":
            out.update(local=self.outs[0][1], calls=calls)
        return out

    def on_batch(self, m, which):
        regs = m.regs
        memory = m.memory
        w = self.w
        at = regs[RDX]
        if regs[RDI] != self.buffer_at or memory.read(at, 8) != w["word"] or memory.read(at + 8, 8) != self.base:
            raise Halt("batch arguments")
        local = [memory.read(regs[RSI] + 4 * index, 4) for index in range(3)]
        if [memory.read(at + 0x20 + 4 * index, 4) for index in range(3)] != local:
            raise Halt("batch time")
        self.log.append(["batch", which, local, memory.read(at + 0x18, 8), [memory.read(at + 0x2C + 4 * index, 4) for index in range(3)], memory.read(at + 0x10, 8)])

    def on_block_drop(self, m):
        index, extra = divmod(m.regs[RDI] - 0x28 - self.base, STATUS_ROW)
        if extra:
            raise Halt("row drop")
        self.log.append(["drop", index])

    def run_block(self, case):
        w = case.world
        machine = self.machine
        memory = machine.memory
        self.fresh(w)
        which = w["which"]
        at, width, name = (STATUS_AT, STATUS_ROW, "status batch") if which == "status" else (TWAP_AT, TWAP_ROW, "twap batch")
        self.use({ROTATIONS[name][0]: lambda m: self.on_batch(m, which), DROP_ROW: self.on_block_drop})
        self.buffer_at = at
        for base in BUFFER_BASES:
            memory.write(OBJECT + base, 8, CLOSED)
            memory.write(OBJECT + base + 0x48, 8, CLOSED)
            memory.write(OBJECT + base + 0xB0, 8, CLOSED)
        memory.write(OBJECT + 0x9E0, 8, CLOSED)
        memory.write(OBJECT + 0x70, 8, 3)
        memory.write(OBJECT + 0xA60, 8, w["number"])
        memory.put_bytes(OBJECT + 0xA68, struct.pack("<III", w["date"], w["block"][1], w["block"][2]))
        memory.write(OBJECT + 0xA78, 1, w["flag"])
        memory.write(at, 8, w["gate"])
        memory.write(at + 0x48, 8, 0x41 if w["open_file"] else CLOSED)
        self.file_at = OBJECT + (0x788 if which == "status" else 0x6C0)
        word = w["word"]
        base = self.allocate(word * width) if word and word >> 63 == 0 else 8
        self.base = base
        memory.write(at + 0xB0, 8, word)
        memory.write(at + 0xB8, 8, base)
        memory.write(at + 0xC0, 8, w["length"])
        if which == "twap":
            for index, (text, extra) in enumerate(w["strings"]):
                row = base + index * TWAP_ROW
                memory.put_bytes(row, ramp(TWAP_ROW, 0x31 + index))
                memory.write(row, 8, text)
                memory.write(row + 8, 8, self.allocate(text) if text else 1)
                memory.write(row + 0x58, 8, extra)
                memory.write(row + 0x60, 8, self.text_block(extra) if extra and not CLOSED <= extra <= CLOSED + 2 else 0x71)
        try:
            machine.run(BLOCK_END, {RDI: OBJECT, RDX: w["flag_argument"]})
        except Panicked:
            return {"path": "panic overflow", "calls": [row_ for row_ in self.log if row_[0] in ("time", "date")]}
        log = [row_ for row_ in self.log if row_[0] not in ("time", "date")]
        calls = [row_ for row_ in self.log if row_[0] in ("time", "date")]
        if not w["date"] or w["gate"] == CLOSED:
            return {"log": log}
        reset = word >> 63 == 0
        if reset and [memory.read(at + 0xB0, 8), memory.read(at + 0xB8, 8), memory.read(at + 0xC0, 8)] != [0, 8, 0]:
            raise Halt("vector not reset")
        if not reset and memory.read(at + 0xB0, 8) != word:
            raise Halt("vector touched")
        return {"log": log, "reset": reset, "calls": calls}

    def run_file(self, case):
        w = case.world
        machine = self.machine
        memory = machine.memory
        self.fresh(w)
        start, line = ROTATIONS[w["which"]]
        self.use({line: self.on_file_line})
        at = OBJECT + 0x100
        self.file_at = at + 0x48
        word = (1 << 63) if not w["open"] else w["file_word"]
        memory.put_bytes(at, ramp(0xB0, 0x61))
        data = w["dir"].encode("ascii")
        memory.put_bytes(TEXT_IN, data)
        memory.write(at + 8, 8, TEXT_IN)
        memory.write(at + 0x10, 8, len(data))
        memory.write(at + 0x48, 8, word)
        memory.write(at + 0x98, 4, w["old_date"])
        memory.write(at + 0xA8, 1, w["hourly"])
        memory.write(at + 0xA9, 1, w["old_hour"])
        memory.write(at + 0xAA, 1, w["flush"])
        memory.statics[FLUSH_FLAG_BYTE] = w["global_flush"]
        memory.put_bytes(TIME_IN, struct.pack("<III", *w["time"]))
        try:
            machine.run(start, {RDI: at, RSI: TIME_IN, RDX: ROW_IN})
        except Panicked as error:
            return {"path": "panic hour" if "e108" in str(error) else "panic unwrap", "log": self.log}
        if not self.log:
            return {"path": "closed", "log": []}
        if self.live:
            raise Halt("path leak")
        opened = self.log[0][0] == "open"
        if memory.bytes_at(at + 0x48, 0x50) != (ramp(0x50, 0x41) if opened else struct.pack("<Q", word) + ramp(0xB0, 0x61)[0x50:0x98]):
            raise Halt("file bytes")
        return {"path": "line", "log": self.log, "date": memory.read(at + 0x98, 4), "hourly": memory.read(at + 0xA8, 1), "hour": memory.read(at + 0xA9, 1), "last": [memory.read(at + 0x9C + 4 * index, 4) for index in range(3)]}

    def put_status(self, at, r, index=0):
        memory = self.machine.memory
        row = bytearray(ramp(STATUS_ROW, 0x13 + index * 3))
        builder = r["builder"]
        row[0x00:0x08] = struct.pack("<Q", 1 if builder else 0)
        if builder:
            row[0x08:0x10] = struct.pack("<Q", builder[0])
            row[0x10:0x24] = bytes.fromhex(builder[1])
        row[0x28:0x30] = r["order"]
        row[0xD0:0xDC] = r["time"]
        row[0xDC:0xF0] = bytes.fromhex(r["user"])
        row[0xF0] = 1 if r["hash"] else 0
        if r["hash"]:
            row[0xF1:0x111] = bytes.fromhex(r["hash"])
        row[0x111] = r["status"]
        memory.put_bytes(at, bytes(row))

    def put_twap(self, at, r, index=0):
        memory = self.machine.memory
        memory.put_bytes(at, ramp(TWAP_ROW, 0x13 + index * 3))
        memory.put_bytes(at, r["mark"])

    def run_line(self, case):
        w = case.world
        machine = self.machine
        memory = machine.memory
        self.fresh(w)
        self.use({})
        self.file_at = OBJECT + 0x148
        machine.jump_low, machine.jump_high = self.image.exact_fde(ESCAPE)
        family = w["family"]
        line = w["line"]
        rows = w["rows"]
        name = "%s %s" % (family, line)
        start = ROTATIONS[name][1]
        width, put = (STATUS_ROW, self.put_status) if family == "status" else (TWAP_ROW, self.put_twap)
        if line == "file":
            put(ROW_IN, rows[0])
        elif line == "stream":
            put(ROW_IN, rows[0])
            memory.write(ROW_IN + width, 8, w["number"])
            memory.put_bytes(ROW_IN + width + 8, w["local"])
            memory.put_bytes(ROW_IN + width + 0x14, w["block"])
        else:
            base = self.allocate(max(len(rows), 1) * width)
            for index, row in enumerate(rows):
                put(base + index * width, row, index)
            memory.write(ROW_IN, 8, len(rows))
            memory.write(ROW_IN + 8, 8, base)
            memory.write(ROW_IN + 0x10, 8, len(rows))
            memory.write(ROW_IN + 0x18, 8, w["number"])
            memory.put_bytes(ROW_IN + 0x20, w["local"])
            memory.put_bytes(ROW_IN + 0x2C, w["block"])
        machine.status_jump = None
        machine.jump_low, machine.jump_high = self.image.exact_fde(STATUS_FIELD)
        machine.run(start, {RDI: self.file_at, RSI: TIME_IN, RDX: ROW_IN})
        return self.line

    def run(self, case):
        return {"sink": self.run_sink, "handler": self.run_handler, "buffer": self.run_buffer, "twap": self.run_twap, "block": self.run_block, "file": self.run_file, "line": self.run_line}[case.kind](case)


def pending_view(row):
    """A row pushed from inner word 2: the hash flag is zero and the hash bytes are stale."""
    view = row_view(row)
    view["hash"] = None
    return view


PANIC_TEXT = {0x576E468: 0x26, 0x576E108: 0x1C, 0x576E048: 0x2B}
CRASHES = (Halt, Panicked, EvidenceError, KeyError, IndexError, ValueError, TypeError, OverflowError, struct.error, UnicodeDecodeError, ZeroDivisionError)


def compare_run(harness, case):
    """None when the run agrees with the spec, else a text."""
    try:
        expected = spec_run(case)
        got = harness.run(case)
    except CRASHES as error:
        return "%s: crash %s %s" % (case.kind, case.label, str(error)[:120])
    if case.kind == "file" and expected["path"] != "line":
        got = {"path": got["path"], "log": got["log"]}
    if got != expected:
        return "%s: differ %s: %.400r != %.400r" % (case.kind, case.label, got, expected)
    return None


def ramp(count, start):
    return bytes((start + index * 7) & 0xFF for index in range(count))


# ---- cases ----

USER = "00112233445566778899aabbccddeeff01234567"
USER_TWO = "f0e1d2c3b4a5968778695a4b3c2d1e0f10203040"
CLOCK = (2460000, 45296, 123456789)
BLOCK = bytes(range(0x30, 0x48))
DIGEST = "".join("%02x" % ((index * 5 + 0x11) & 0xFF) for index in range(32))


def status_row(word, start=0x21):
    row = bytearray(ramp(STATUS_ROW, start))
    struct.pack_into("<Q", row, 0, word)
    return bytes(row)


def sink_cases():
    cases = []
    for market in ("spot", "perp"):
        for kind in (3, 4):
            cases.append(Case("%s kind %d" % (market, kind), "sink", dict(market=market, kind=kind)))
    return cases


def handler_cases():
    cases = []

    def add(label, **world):
        data = dict(gate=0x41, word=2, row=status_row(2), pending=[], capacity=4, flag=0, clock=CLOCK, block=BLOCK)
        data.update(world)
        cases.append(Case("%s: %s" % (inner_kind(data["word"]), label), "handler", data))

    rows = [status_row(index & 1, 0x41 + index * 3) for index in range(5)]
    for word in (2, 4, 5, 0, 1, 3):
        name = "word %d" % word
        add(name + " closed", word=word, row=status_row(word), gate=CLOSED, pending=rows[:1])
        add(name + " closed no flag bytes", word=word, row=status_row(word), gate=CLOSED, flag=1)
        add(name + " gate word 1", word=word, row=status_row(word), gate=1)
        add(name + " gate above closed", word=word, row=status_row(word), gate=CLOSED + 1, pending=rows[:2])
    add("first row", word=2, row=status_row(2))
    add("second row", word=2, row=status_row(2, 0x77), pending=rows[:1])
    add("vector full", word=2, row=status_row(2), pending=rows[:4])
    add("vector empty and no room", word=2, row=status_row(2), capacity=0)
    add("builder word", word=0, row=status_row(0))
    add("builder word one", word=1, row=status_row(1, 0x55))
    add("flag", word=1, row=status_row(1), flag=1)
    add("pending stays", word=1, row=status_row(1), pending=rows[:2])
    add("nothing pending", word=4, row=status_row(4), pending=[])
    add("nothing pending and no room", word=4, row=status_row(4), pending=[], capacity=0)
    add("one", word=4, row=status_row(4), pending=rows[:1])
    add("three", word=4, row=status_row(4), pending=rows[:3], flag=1)
    add("full", word=4, row=status_row(4), pending=rows[:4])
    add("row with word 2 stops the walk", word=4, row=status_row(4), pending=[rows[0], status_row(2), rows[1], rows[2]])
    add("word 2 first", word=4, row=status_row(4), pending=[status_row(2), rows[1]])
    add("word 2 last", word=4, row=status_row(4), pending=[rows[0], status_row(2)])
    add("word 3 is a row", word=4, row=status_row(4), pending=[status_row(3), rows[1]])
    add("large word", word=MAX64, row=status_row(MAX64), pending=rows[:1])
    return cases


def buffer_cases():
    cases = []

    def add(label, **world):
        data = dict(row=status_row(0, 0x35), flag=0, number=777, block_date=2460001, clock=CLOCK, carry=(0, 0), date_result=2460002, capacity=4, length=0)
        data.update(world)
        cases.append(Case("%s: %s" % (data["mode"], label), "buffer", data))

    add("plain", mode="file")
    add("flag ignored", mode="file", flag=1)
    add("no block date", mode="file", block_date=0)
    add("room", mode="vector", capacity=4, length=1)
    add("full", mode="vector", capacity=4, length=4)
    add("empty", mode="vector", capacity=0, length=0)
    add("flag ignored", mode="vector", capacity=4, length=2, flag=1)
    add("no block date", mode="vector", capacity=4, length=0, block_date=0)
    add("clock", mode="stream")
    add("no block", mode="stream", block_date=0)
    add("no block with flag", mode="stream", block_date=0, flag=1)
    add("flag plus 40 ms", mode="stream", flag=1)
    add("flag carry into the next day", mode="stream", flag=1, carry=(1, 86400), date_result=2460007)
    add("flag two days", mode="stream", flag=1, carry=(1, 172800), date_result=2460009)
    add("flag one second below a day", mode="stream", flag=1, carry=(1, 86399), date_result=2460011)
    add("flag negative days", mode="stream", flag=1, carry=(1, -86400 * 3), date_result=2460013)
    add("flag date add fails", mode="stream", flag=1, carry=(1, 86400), date_result=0)
    add("flag seconds at the top of range", mode="stream", flag=1, carry=(0, 0xA8BFFFFFFFFF), date_result=2460015)
    add("flag seconds past the top of range", mode="stream", flag=1, carry=(0, 0xA8C000000000), date_result=2460015)
    low = 0xFFFEAE7FFFFEAE81 - 0xFFFF574000000000
    add("flag seconds at the checked lower limit", mode="stream", flag=1, carry=(0, low), date_result=2460019)
    add("flag seconds below the checked lower limit", mode="stream", flag=1, carry=(0, low - 1), date_result=2460019)
    return cases


def twap_cases():
    cases = []

    def add(label, **world):
        data = dict(text_cap=16, extra_cap=CLOSED, flag=0, number=777, block_date=2460001, clock=CLOCK, carry=(0, 0), date_result=2460002, capacity=4, length=0)
        data.update(world)
        cases.append(Case("%s: %s" % (data["mode"], label), "twap", data))

    extras = (("no second text", CLOSED), ("niche 1", CLOSED + 1), ("niche 2", CLOSED + 2), ("second empty", 0), ("second text", 24), ("first word past the niche", CLOSED + 3))
    for mode in ("closed", "file", "stream"):
        for label, extra in extras:
            add(label, mode=mode, extra_cap=extra)
            add(label + " no first text", mode=mode, extra_cap=extra, text_cap=0)
    add("no block", mode="stream", block_date=0)
    add("no block two texts", mode="stream", block_date=0, extra_cap=24)
    add("flag ignored", mode="file", flag=1)
    add("flag ignored when closed", mode="closed", flag=1)
    add("room", mode="vector", capacity=4, length=1)
    add("room with texts", mode="vector", capacity=4, length=1, extra_cap=24)
    add("full", mode="vector", capacity=4, length=4)
    add("empty", mode="vector", capacity=0, length=0)
    add("no block date", mode="vector", block_date=0)
    add("flag ignored", mode="vector", flag=1)
    add("flag plus 40 ms", mode="stream", flag=1)
    add("flag carry into the next day", mode="stream", flag=1, carry=(1, 86400), date_result=2460007)
    add("flag two days", mode="stream", flag=1, carry=(1, 172800), date_result=2460009)
    add("flag one second below a day", mode="stream", flag=1, carry=(1, 86399), date_result=2460011)
    add("flag negative days", mode="stream", flag=1, carry=(1, -86400 * 3), date_result=2460013)
    add("flag date add fails", mode="stream", flag=1, carry=(1, 86400), date_result=0)
    add("flag seconds past the top of range", mode="stream", flag=1, carry=(0, 0xA8C000000000), date_result=2460015)
    add("flag seconds at the top of range", mode="stream", flag=1, carry=(0, 0xA8BFFFFFFFFF), date_result=2460015)
    low = 0xFFFEAE7FFFFEAE81 - 0xFFFF574000000000
    add("flag seconds at the checked lower limit", mode="stream", flag=1, carry=(0, low), date_result=2460019)
    add("flag seconds below the checked lower limit", mode="stream", flag=1, carry=(0, low - 1), date_result=2460019)
    return cases


def block_cases():
    cases = []

    def add(label, which, **world):
        data = dict(which=which, gate=0x41, word=4, length=2, date=2460001, block=(2460001, 0x12345, 0x6789A), number=999, flag=0, flag_argument=0, open_file=True, clock=CLOCK, carry=(0, 0),
                    date_result=2460002, strings=[(16, CLOSED), (0, 24)], flush=False)
        data.update(world)
        data["flush"] = bool(data["flag_argument"] & 0xFF) and data["open_file"]
        data["strings"] = data["strings"][:data["length"]]
        cases.append(Case("%s: %s" % (which, label), "block", data))

    for which in ("status", "twap"):
        add("two rows", which)
        add("no rows", which, length=0)
        add("empty vector", which, word=0, length=0)
        add("one row", which, length=1)
        add("no block date", which, date=0)
        add("closed", which, gate=CLOSED)
        add("closed with the flush argument", which, gate=CLOSED, flag_argument=1)
        add("no vector", which, word=CLOSED, length=0)
        add("streaming word", which, word=CLOSED + 2, length=0)
        add("flush argument", which, flag_argument=1)
        add("flush argument with no vector", which, word=CLOSED, length=0, flag_argument=1)
        add("flush argument, file closed", which, flag_argument=1, open_file=False)
        add("flush argument high bits only", which, flag_argument=0x100)
        add("flag plus 40 ms", which, flag=1)
        add("flag date add fails", which, flag=1, carry=(1, 86400), date_result=0)
        add("flag seconds past the top of range", which, flag=1, carry=(0, 0xA8C000000000), date_result=2460015)
        add("flag seconds at the top of range", which, flag=1, carry=(0, 0xA8BFFFFFFFFF), date_result=2460015)
        low = 0xFFFEAE7FFFFEAE81 - 0xFFFF574000000000
        add("flag seconds at the checked lower limit", which, flag=1, carry=(0, low), date_result=2460019)
        add("flag seconds below the checked lower limit", which, flag=1, carry=(0, low - 1), date_result=2460019)
        add("flag negative days", which, flag=1, carry=(1, -86400 * 3), date_result=2460013)
    add("texts in every row", "twap", length=3, strings=[(16, 24), (32, CLOSED + 1), (0, 0)])
    add("niche 2 text", "twap", length=1, strings=[(0, CLOSED + 2)])
    add("word past the niche", "twap", length=1, strings=[(0, CLOSED + 3)])
    return cases


def file_cases():
    cases = []
    for which in ROTATIONS:
        def add(label, **world):
            data = dict(which=which, dir="base/node_order_statuses", open=True, file_word=0x41, time=(2460100, 7300, 5), old_date=2460100, old_hour=2, hourly=1, flush=0, global_flush=0)
            data.update(world)
            cases.append(Case("%s: %s" % (which, label), "file", data))

        add("same hour")
        add("next hour", time=(2460100, 10800, 5))
        add("last second of the hour", time=(2460100, 10799, 1))
        add("hour 0", time=(2460100, 0, 0), old_hour=0)
        add("next day same hour", time=(2460101, 7300, 5))
        add("no file yet", hourly=0, old_date=0, old_hour=9, time=(2460100, 7300, 5))
        add("daily same date", hourly=0)
        add("daily next date", hourly=0, time=(2460101, 7300, 5))
        add("hourly byte 2 is daily", hourly=2)
        add("hourly byte 2 next date", hourly=2, time=(2460101, 7300, 5))
        add("closed", open=False)
        add("closed bad time", open=False, time=(1, 0xF0000, 0))
        add("seconds at the unwrap limit", time=(2460100, 0xE1000, 0))
        add("seconds below the unwrap limit", time=(2460100, 0xE0FFF, 0))
        add("seconds at the hour limit", time=(2460100, 90000, 0))
        add("seconds below the hour limit", time=(2460100, 89999, 0), old_hour=24)
        add("flush both", flush=1, global_flush=1)
        add("flush row only", flush=1, global_flush=0)
        add("flush global only", flush=0, global_flush=1)
        add("flush after open", flush=1, global_flush=1, time=(2460100, 10800, 5))
        add("flush on word above", flush=1, global_flush=1, file_word=(1 << 63) + 1)
    return cases


LOCAL = bytes(range(0x50, 0x5C))
STAMP = bytes(range(0x70, 0x7C))
ORDER_MARK = bytes(range(0x90, 0x98))
TIME_MARK = bytes(range(0xB0, 0xBC))
BASE_ROW = dict(builder=None, order=ORDER_MARK, time=TIME_MARK, user=USER, hash=None, status=1)
TWAP_MARK = dict(mark=bytes(range(0xC0, 0xC8)))


def line_cases():
    cases = []
    rows = [
        ("plain", dict(BASE_ROW)),
        ("with hash", dict(BASE_ROW, hash=DIGEST)),
        ("with builder", dict(BASE_ROW, builder=(7, USER_TWO))),
        ("both", dict(BASE_ROW, builder=(0, USER_TWO), hash=DIGEST, user=USER_TWO, status=3)),
        ("high builder word", dict(BASE_ROW, builder=(99999, USER))),
    ]
    for label, row in rows:
        cases.append(Case("file: " + label, "line", dict(family="status", line="file", rows=[row])))
        cases.append(Case("stream: " + label, "line", dict(family="status", line="stream", rows=[row], number=123456, local=LOCAL, block=STAMP)))
    for byte in sorted(NAMES):
        cases.append(Case("file: status byte %d" % byte, "line", dict(family="status", line="file", rows=[dict(BASE_ROW, status=byte)])))
    for count in (0, 1, 2, 3, 7):
        cases.append(Case("batch: %d rows" % count, "line", dict(family="status", line="batch", rows=[rows[index % 4][1] for index in range(count)], number=999, local=LOCAL, block=STAMP)))
    cases.append(Case("twap stream: one", "line", dict(family="twap", line="stream", rows=[dict(TWAP_MARK)], number=123456, local=LOCAL, block=STAMP)))
    for count in (0, 1, 2, 5):
        cases.append(Case("twap batch: %d rows" % count, "line", dict(family="twap", line="batch", rows=[dict(mark=bytes((0xC0 + index + at) & 0xFF for at in range(8))) for index in range(count)], number=999, local=LOCAL, block=STAMP)))
    cases.append(Case("twap file: one", "line", dict(family="twap", line="file", rows=[dict(TWAP_MARK)])))
    full = dict(BASE_ROW, builder=(7, USER_TWO), hash=DIGEST)
    shapes = (("status file full", dict(family="status", line="file", rows=[full])), ("status file plain", dict(family="status", line="file", rows=[dict(BASE_ROW)])),
              ("status stream full", dict(family="status", line="stream", rows=[full], number=7, local=LOCAL, block=STAMP)), ("status stream plain", dict(family="status", line="stream", rows=[dict(BASE_ROW)], number=7, local=LOCAL, block=STAMP)),
              ("status batch", dict(family="status", line="batch", rows=[full, dict(BASE_ROW)], number=7, local=LOCAL, block=STAMP)), ("status batch none", dict(family="status", line="batch", rows=[], number=7, local=LOCAL, block=STAMP)),
              ("twap file", dict(family="twap", line="file", rows=[dict(TWAP_MARK)])), ("twap stream", dict(family="twap", line="stream", rows=[dict(TWAP_MARK)], number=7, local=LOCAL, block=STAMP)),
              ("twap batch", dict(family="twap", line="batch", rows=[dict(TWAP_MARK), dict(TWAP_MARK)], number=7, local=LOCAL, block=STAMP)), ("twap batch none", dict(family="twap", line="batch", rows=[], number=7, local=LOCAL, block=STAMP)))
    for label, world in shapes:
        for slack in range(0, 6):
            cases.append(Case("%s: past the buffer, room %d" % (label, slack), "line", dict(world, pad=0x90, exact=slack)))
    for room in range(50, 90):
        cases.append(Case("status file plain: room %d after the first field" % room, "line", dict(shapes[1][1], pad=0x90, exact=room)))
    return cases


def all_cases():
    return sink_cases() + handler_cases() + buffer_cases() + twap_cases() + block_cases() + file_cases() + line_cases()

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


BLOCK_ARMS = ((0x48576A0, 0x48576F7), (0x4857D35, 0x4858141))
GROUPS = (
    (STATUS_HANDLER, "row kind 3 handler", None), (TWAP_HANDLER, "row kind 4 handler", None), (STATUS_BUFFER, "status output mode switch", None),
    (DROP_LEFT, "pending rows left after the walk", None), (BLOCK_END, "block end: entry and the TWAP and order status arms", BLOCK_ARMS),
) + tuple((pair[0], name + " rotation", None) for name, pair in ROTATIONS.items()) + tuple((pair[1], name + " line", None) for name, pair in ROTATIONS.items()) + (
    (STATUS_JSON, "status row serializer", None), (STATUS_KEY, "status key wrapper", None), (ORDER_KEY, "order key wrapper", None), (ORDER_FIELD, "order field", None),
    (HASH_FIELD, "hash field", None), (BUILDER_FIELD, "builder field", None), (BUILDER_JSON, "builder object", None), (STATUS_STREAM_JSON, "status streaming serializer", None),
    (STATUS_BATCH_JSON, "status batch serializer", None), (STATUS_ONE_EVENT, "status events field, one row", None), (STATUS_ALL_EVENTS, "status events field, all rows", None),
    (TWAP_STREAM_JSON, "TWAP streaming serializer", None), (TWAP_BATCH_JSON, "TWAP batch serializer", None), (TWAP_ONE_EVENT, "TWAP events field, one row", None), (TWAP_ALL_EVENTS, "TWAP events field, all rows", None))
EXTRA_FUNCTIONS = ((STATUS_FIELD, "status text field: table 0x7038dc is a row in earlier packets, run with no mutants", None), (0x4A83200, "address field: a row in #1036, run with no mutants", None))


def group_rows(image, begin, end, ranges):
    """Whole body, or only the listed arms."""
    if ranges is None:
        return decode_range(image, begin, end)
    rows = []
    for low, high in ranges:
        rows += decode_range(image, low, high)
    return rows


def mutated_groups(image):
    """(function start, role, decoded rows inside the range of the group)."""
    groups = []
    for start, role, ranges in GROUPS:
        begin, end = image.exact_fde(start)
        groups.append((start, role, group_rows(image, begin, end, ranges)))
    return groups


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
                    del first_kill[60:]
                    break
            machine.patches = {}
            machine.cache.pop(va, None)
            results.append({"function": start, "va": va, "kind": kind, "result": "killed" if failed else "survived", "by": ":".join(failed.split(":")[:2])[:70] if failed else ""})
            if verbose and not failed:
                print("survived %#x %s" % (va, kind), flush=True)
    return results


# ---- evidence ----

def code(image, va, count):
    return bytes(image.blob[image.offset(va):image.offset(va) + count])


def require(image, va, data, what):
    if code(image, va, len(data)) != data:
        raise EvidenceError("%s: bytes at %#x differ" % (what, va))


def lea_target(image, site):
    """Target of a rip relative lea of seven bytes."""
    data = code(image, site, 7)
    if data[1] != 0x8D or data[2] & 0xC7 != 5:
        raise EvidenceError("no rip lea at %#x" % site)
    return site + 7 + struct.unpack_from("<i", data, 3)[0]


def text_at(image, va, size):
    return bytes(image.blob[image.offset(va):image.offset(va) + size]).decode("ascii")


def stack_store(data, at):
    """Displacement and end of `48 c7 .. imm32` with an rsp base at this offset, or None."""
    if data[at:at + 2] != b"\x48\xc7":
        return None
    if data[at + 2:at + 4] == b"\x04\x24":
        return 0, at + 4
    if data[at + 2:at + 4] == b"\x44\x24":
        return data[at + 4], at + 5
    if data[at + 2:at + 4] == b"\x84\x24":
        return struct.unpack_from("<i", data, at + 4)[0], at + 8
    return None


def row_sites(image):
    """Every stack row head of kind 3 in .text: word 3 stored with the inner word 2 or 4 at the next offset within 0x60 bytes, in a function that copies a whole row."""
    base, text = image.text_bytes()
    rows = []
    for match in re.finditer(rb"\x48\xc7(?:\x04\x24|\x44\x24.|\x84\x24....)\x03\x00\x00\x00", text, re.S):
        at = match.start()
        disp = stack_store(text, at)[0]
        inner = None
        for near in range(max(0, at - 0x60), min(len(text), at + 0x60)):
            found = stack_store(text, near)
            if found and found[0] == disp + 8:
                word = struct.unpack_from("<I", text, found[1])[0]
                if word in (2, 4):
                    inner = word
                    break
        if inner is None:
            continue
        begin, end = image.fde(base + at)
        body = text[begin - base:end - base]
        tail = text[at:at + 0x90]
        width = 0x268 if b"\xba\x68\x02\x00\x00" in tail or b"\x41\xb8\x68\x02\x00\x00" in tail else 0x278 if b"\xba\x78\x02\x00\x00" in tail else 0
        if not width:
            continue
        status = "none"
        if inner == 2:
            window = text[max(0, at - 0x200):at + 0x40]
            mark = struct.pack("<i", disp + 0x100)
            direct = list(re.finditer(rb"\xc6\x84\x24" + re.escape(mark) + rb"(.)", window, re.S))
            spilled = list(re.finditer(rb"(?:\x88|\x40\x88|\x44\x88)[\x84\x8c\x94\x9c\xa4\xac\xb4\xbc]\x24" + re.escape(mark), window, re.S))
            if direct:
                status = "%#x" % direct[-1].group(1)[0]
            elif spilled:
                status = "register"
            else:
                status = "not in window"
        rows.append({"host": "%#x" % begin, "site": "%#x" % (base + at), "row_bytes": width, "inner": inner, "status": status, "name": NAMES.get(int(status, 16), "") if status.startswith("0x") else ""})
    return rows


def copy_shapes(image, starts):
    """Copies differ only in rip displacements and rel32 calls."""
    first = decode_range(image, *image.exact_fde(starts[0]))
    rows = []
    for other in starts[1:]:
        low, high = image.exact_fde(other)
        decoded = decode_range(image, low, high)
        rows.append({"first": "%#x" % starts[0], "other": "%#x" % other, "size": high - low, "same_instruction_shape": len(decoded) == len(first) and all(a.op == b.op and a.size == b.size for a, b in zip(first, decoded))})
    return rows


def sink_rows(image):
    """Both sinks: table entries 1 and 2 are the row kind 3 and 4 arms, and each arm ends in a jump through a data slot."""
    rows = []
    slots = {slot: addend for slot, kind, addend, _ in image.relocations() if kind == 8}
    for start, table in SINK_TABLES:
        begin, end = image.exact_fde(start)
        for index, slot, handler, wanted_kind in ((1, SLOT_STATUS_HANDLER, STATUS_HANDLER, 3), (2, SLOT_TWAP_HANDLER, TWAP_HANDLER, 4)):
            arm = table + struct.unpack_from("<i", image.blob, image.offset(table) + index * 4)[0]
            body = code(image, begin, end - begin)
            sites = [begin + m.start() for m in re.finditer(b"\xff\x25", body) if begin + m.start() + 6 + struct.unpack_from("<i", body, m.start() + 2)[0] == slot]
            if len(sites) != 1 or slots.get(slot) != handler:
                raise EvidenceError("handler slot %#x" % slot)
            rows.append({"sink": "%#x" % start, "table": "%#x" % table, "row_kind": wanted_kind, "arm": "%#x" % arm, "jump_site": "%#x" % sites[0], "slot": "%#x" % slot, "handler": "%#x" % handler})
    return rows


NAME_SITES = ((0x47F16F4, "node_fills"), (0x47F1933, "node_raw_book_diffs"), (0x47F1DD1, "misc_events"), (0x47F1FBD, "node_order_statuses"), (0x47F21DD, "hip3_oracle_updates"), (0x47F2404, "system_and_core_writer_actions"))
TWAP_NAME = (0x47F1B52, "node_twap_statuses")
BOTH_CLOSED = (0x47F191A, b"\x4c\x89\xac\x24\xf0\x0e\x00\x00\x4c\x89\xac\x24\xb8\x0f\x00\x00")
TWAP_FINISH = (0x47F1F80, b"\x48\x8d\xbc\x24\xb8\x0f\x00\x00\x48\x8d\xb4\x24\x80\x06\x00\x00\xba\xc8\x00\x00\x00")
OBJECT_BLOCK = b"\x48\x8d\xbb\x20\x04\x00\x00\x48\x8d\xb4\x24\x80\x06\x00\x00\xba\x40\x06\x00\x00"


def buffer_rows(image):
    """A gate jumps to the name lea; the next instruction stores the closed word in the stack slot of that buffer; a 0xc8 copy moves the slot into the block that lands at object +0x420."""
    begin, end = image.exact_fde(CONSTRUCTOR)
    body = code(image, begin, end - begin)
    if body.count(OBJECT_BLOCK) != 1:
        raise EvidenceError("object block copy")

    def object_offset(slot):
        moved = re.findall(rb"\x48\x8d\xbc\x24(....)\x48\x8d\xb4\x24" + re.escape(struct.pack("<i", slot)) + rb"(?:\x4c\x8b\x3d....)?\xba\xc8\x00\x00\x00", body, re.S)
        if len(moved) != 1:
            raise EvidenceError("buffer copy of %#x" % slot)
        return struct.unpack("<i", moved[0])[0] - 0x680 + 0x420

    rows = []
    for site, name in NAME_SITES:
        if text_at(image, lea_target(image, site), len(name)) != name:
            raise EvidenceError("name at %#x" % site)
        slots = []
        for match in re.finditer(rb"\x0f\x85(....)\x4c\x89\xac\x24(....)", body, re.S):
            if begin + match.start() + 6 + struct.unpack("<i", match.group(1))[0] == site:
                slots.append((begin + match.start(), struct.unpack("<i", match.group(2))[0]))
        if len(slots) != 1:
            raise EvidenceError("gate of %s" % name)
        rows.append({"name": name, "name_lea": "%#x" % site, "gate_jump": "%#x" % slots[0][0], "stack_slot": "%#x" % slots[0][1], "object_offset": "%#x" % object_offset(slots[0][1])})
    if text_at(image, lea_target(image, TWAP_NAME[0]), len(TWAP_NAME[1])) != TWAP_NAME[1]:
        raise EvidenceError("twap name")
    require(image, BOTH_CLOSED[0], BOTH_CLOSED[1], "fills and twap closed together")
    require(image, TWAP_FINISH[0], TWAP_FINISH[1], "twap finish")
    rows.append({"name": TWAP_NAME[1], "name_lea": "%#x" % TWAP_NAME[0], "gate_jump": "falls in after the node_fills block, closed with it at %#x" % BOTH_CLOSED[0], "stack_slot": "0xfb8", "object_offset": "%#x" % object_offset(0xFB8)})
    return sorted(rows, key=lambda row: int(row["object_offset"], 16))


CONFIG_BYTES = (
    (0x47F15BE, b"\x44\x0f\xb6\x66\x02", "config byte +2 goes to r12b"),
    (0x47F1911, b"\x45\x84\xe4", "r12b gates the node_fills block"),
    (0x47F15C3, b"\x44\x0f\xb6\x76\x03", "config byte +3 goes to r14b, the node_raw_book_diffs gate"),
    (0x47F15C8, b"\x44\x0f\xb6\x5e\x04", "config byte +4 goes to r11b"),
    (0x47F1620, b"\x44\x88\x5c\x24\x0f", "r11b goes to stack +0xf"),
    (0x47F1DB3, b"\x80\x7c\x24\x0f\x00", "stack +0xf gates the node_order_statuses block"),
    (0x47F15E8, b"\x80\x7e\x08\x00", "config byte +8 set"),
    (0x47F15EE, b"\x48\x8b\x35", "loads the slot of the global flush byte"),
    (0x47F15F5, b"\xc6\x06\x01", "and stores 1 there"),
)


def config_rows(image):
    rows = []
    for va, data, meaning in CONFIG_BYTES:
        require(image, va, data, meaning)
        rows.append({"va": "%#x" % va, "bytes": data.hex(), "meaning": meaning})
    return rows


DRAIN_BYTES = ((0x4858075, b"\x48\x8d\xbb\x40\x07\x00\x00", "order status drain passes object +0x740"), (0x48580D8, b"\xe8", "and calls the batch rotation"), (0x4857E57, b"\x48\x8d\xbb\x78\x06\x00\x00", "TWAP drain passes object +0x678"), (0x4857EBA, b"\xe8", "and calls the batch rotation"))


def drain_rows(image):
    rows = []
    for va, data, meaning in DRAIN_BYTES:
        require(image, va, data, meaning)
        row = {"va": "%#x" % va, "meaning": meaning}
        if data == b"\xe8":
            row["target"] = "%#x" % (va + 5 + struct.unpack_from("<i", image.blob, image.offset(va) + 1)[0])
        rows.append(row)
    if rows[1]["target"] != "%#x" % ROTATIONS["status batch"][0] or rows[3]["target"] != "%#x" % ROTATIONS["twap batch"][0]:
        raise EvidenceError("drain target")
    return rows


KEY_SITES = (
    (STATUS_JSON, 0x47EF50A, 0xD0, "time", 4), (STATUS_JSON, 0x47EF538, 0xDC, "user", 4), (STATUS_JSON, 0x47EF566, 0xF0, "hash", 4), (STATUS_JSON, 0x47EF585, 0x00, "builder", 7),
    (STATUS_KEY, 0x48652C8, 0x111, "status", 6), (ORDER_KEY, 0x4865388, 0x28, "order", 5), (BUILDER_JSON, 0x43270DB, 0x10, "b", 1), (BUILDER_JSON, 0x43270FD, 0x08, "f", 1),
    (STATUS_STREAM_JSON, 0x47EFDDB, 0x120, "local_time", 10), (STATUS_STREAM_JSON, 0x47EFE08, 0x12C, "block_time", 10), (STATUS_STREAM_JSON, 0x47EFE31, 0x118, "block_number", 12), (STATUS_STREAM_JSON, 0x47EFE53, 0x00, "events", 6),
    (STATUS_BATCH_JSON, 0x47EFCA8, 0x20, "local_time", 10), (STATUS_BATCH_JSON, 0x47EFCD2, 0x2C, "block_time", 10), (STATUS_BATCH_JSON, 0x47EFCF8, 0x18, "block_number", 12), (STATUS_BATCH_JSON, 0x47EFD1A, 0x00, "events", 6),
    (TWAP_STREAM_JSON, 0x47F016B, 0x90, "local_time", 10), (TWAP_STREAM_JSON, 0x47F0198, 0x9C, "block_time", 10), (TWAP_STREAM_JSON, 0x47F01C1, 0x88, "block_number", 12), (TWAP_STREAM_JSON, 0x47F01E3, 0x00, "events", 6),
)


def key_rows(image):
    rows = []
    for function, site, field, text, size in KEY_SITES:
        target = lea_target(image, site)
        if text_at(image, target, size) != text:
            raise EvidenceError("key text at %#x" % site)
        rows.append({"function": "%#x" % function, "lea": "%#x" % site, "key": text, "row_offset": "%#x" % field})
    return rows


def outcome_name(case, spec):
    if case.kind == "handler":
        return "handler: %s, %s" % (inner_kind(case.world["word"]), "closed" if case.world["gate"] == CLOSED else "open")
    if case.kind == "line":
        return "line: %s %s" % (case.world["family"], case.world["line"])
    if case.kind == "sink":
        return "sink: kind %d" % case.world["kind"]
    if case.kind == "block":
        return "block: %s, %s" % (case.world["which"], spec["path"] if "path" in spec else "%d steps" % len(spec["log"]))
    return "%s: %s" % (case.kind, spec["path"])


def case_line(case, spec):
    return "%s\t%s\t%s" % (case.kind, case.label.replace(": ", "\t", 1) if ": " in case.label else case.label + "\t", outcome_name(case, spec))


def sample_lines():
    """Lines printed by the real serializer bytes; time and order values are markers because their writers are stubbed."""
    harness = Harness(load_image())
    lines = []
    for label, row in (("no hash", dict(BASE_ROW)), ("hash and builder", dict(BASE_ROW, builder=(7, USER_TWO), hash=DIGEST, status=2))):
        lines.append(harness.run(Case("file: " + label, "line", dict(family="status", line="file", rows=[row]))))
    lines.append(harness.run(Case("batch: two", "line", dict(family="status", line="batch", rows=[dict(BASE_ROW), dict(BASE_ROW, status=3)], number=999, local=LOCAL, block=STAMP))))
    return lines


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
    functions = []
    for start, role, ranges in GROUPS + EXTRA_FUNCTIONS:
        begin, end = image.exact_fde(start)
        rows = group_rows(image, begin, end, ranges)
        functions.append({"role": role, "start": "%#x" % begin, "end": "%#x" % end, "size": end - begin, "instructions": len(rows), "instructions_stepped": sum(1 for row_ in rows if row_.va in seen)})
    sites = row_sites(image)
    statics = {
        "sinks": sink_rows(image),
        "buffers": buffer_rows(image),
        "config": config_rows(image),
        "drains": drain_rows(image),
        "json_keys": key_rows(image),
        "rotation_shapes": copy_shapes(image, [pair[0] for pair in ROTATIONS.values()]),
        "line_shapes": copy_shapes(image, [pair[1] for pair in ROTATIONS.values()]),
    }
    results_rows = run_mutants(image, reached, verbose) if full else []
    tally = {key: sum(1 for row_ in results_rows if row_["result"] == key) for key in ("killed", "survived", "unreached")}
    census = collections.Counter(row_["inner"] for row_ in sites)
    doc = {
        "target": {"file": "artifacts/node/94/hl-node", "sha256": SHA256},
        "functions": functions,
        "row_site_census": {"sites": len(sites), "hosts": len({row_["host"] for row_ in sites}), "inner_2": census[2], "inner_4": census[4]},
        "status_names": len(NAMES),
        "samples": sample_lines(),
        "cases": {"total": len(cases)},
        "outcomes": dict(sorted(outcomes.items())),
        "mismatches": len(mismatches),
        "first_mismatch": mismatches[0] if mismatches else "",
        "instructions_stepped": steps,
        "mutations": tally,
        "_results": results_rows, "_lines": lines, "_sites": sites, "_names": status_rows(image),
    }
    doc.update(statics)
    return doc


SURVIVED_DEFAULT = "no reason recorded"
_UNWIND = "the byte is read only on the unwind path, and no run unwinds"
_HOURLY = "the store of 1 sits in the arm where the byte is already 1, and the bytes at the mutated offset are rewritten by the last-time store"
_CAP = "the capacity of this buffer is never 0 here, so the free is always taken"
_NEVER_FIRST = "this key is never the first of its object, so the first-key byte is 2 in every run and is only ever compared with 1"
_STATE = "the state byte is only ever compared with 1, so 2 and 3 act alike"
_ZERO = "the stack text buffer is longer than the 66 bytes of 32 bytes in hex, so its last two bytes are never read"
_LENGTH = "one more byte of stated room changes nothing for the fixed 32 byte hex text"
_NO_ERROR = "the writer below fails only on a text buffer error, and no run gives one"
_GROW = "the request is the size of a null: asking for one byte more only leaves a spare byte in the text buffer"
_OBJECT = "the error byte is 0 and the first-key byte is 2 in every run, so these two tests fall the same way"
REASONS_BY_VA = (
    (_UNWIND, (0x47F1153, 0x47F115B)),
    (_HOURLY, (0x4703BE5, 0x47035E5, 0x47053E5, 0x47020E5, 0x4705FE5, 0x47047E5)),
    (_CAP, (0x45B3FCA, 0x45B32FA, 0x45B3C7A, 0x45B9B8A, 0x45B2CFA, 0x45BC79A)),
    (_NEVER_FIRST, (0x4A9F63B, 0x4A98B9E, 0x4A935EB, 0x4A7883B, 0x4AA1D3B, 0x4A8D00B, 0x4A968AB)),
    (_STATE, (0x4A9F660, 0x4A98BC3, 0x4A93610, 0x4A78860, 0x4AA1D60, 0x4A8D030, 0x4A968D0)),
    (_ZERO, (0x4A98C47,)),
    (_LENGTH, (0x4A98C51,)),
    (_NO_ERROR, (0x4A98C69, 0x4A9368D)),
    (_GROW, (0x4A98D69, 0x4A9378D)),
    (_OBJECT, (0x432711D, 0x4327124)),
)
SURVIVED_REASONS = {va: text for text, rows in REASONS_BY_VA for va in rows}


UNREACHED_REASON = "no case reaches it: an allocator failure arm, a serializer error arm, a panic arm, an unwind pad, or a text buffer grow the harness stubs at its call"


def reason_for(row):
    if row["result"] == "killed":
        return ""
    if row["result"] == "unreached":
        return UNREACHED_REASON
    return SURVIVED_REASONS.get(row["va"], SURVIVED_DEFAULT)


def render(evidence):
    evidence = dict(evidence)
    results = evidence.pop("_results")
    case_lines = evidence.pop("_lines")
    sites = evidence.pop("_sites")
    names = evidence.pop("_names")
    files = {"evidence.json": (json.dumps(evidence, indent=2, sort_keys=True) + "\n").replace("\x40", "[at]")}
    lines = ["host\tsite\trow_bytes\tinner_word\tstatus_byte\tstatus_text"]
    lines += ["\t".join((row_["host"], row_["site"], "%#x" % row_["row_bytes"], str(row_["inner"]), row_["status"], row_["name"])) for row_ in sites]
    files["status_row_sites.tsv"] = "\n".join(lines) + "\n"
    lines = ["byte\tarm\ttext_va\ttext"]
    lines += ["%#x\t%#x\t%#x\t%s" % row_ for row_ in names]
    files["status_names.tsv"] = "\n".join(lines) + "\n"
    files["cases.tsv"] = "\n".join(["kind\tgroup\tlabel\toutcome"] + [line.replace("\x40", "[at]") for line in case_lines]) + "\n"
    lines = ["function\tva\tkind\tresult\tkilled_by\treason"]
    lines += [("%#x\t%#x\t%s\t%s\t%s\t%s" % (row_["function"], row_["va"], row_["kind"], row_["result"], row_["by"], reason_for(row_))).replace("\x40", "[at]") for row_ in results]
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
