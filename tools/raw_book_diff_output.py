#!/usr/bin/env python3
"""Pin the node #94 raw book diff path from ELF bytes: the row each book change writes, the sink arms, the three output modes and the JSON line.

Twelve small functions write one row kind 2 for every resting order change: new (with the slab insert), update (size change) and remove (with the
slab removal). The sinks `0x48547d0` (spot) and `0x48551e0` (perp) turn the row into a 0x58 byte record with coin text and f64 numbers, and
`0x47ee2b0` either writes a line to the rotating `node_raw_book_diffs` file, keeps it in a vector (batch_by_block), or writes one `events` line
(stream_with_block_info). The real bytes run in a Python evaluator with the edge callees stubbed. A separately written specification predicts
every row, record, path and JSON text, and every condition, immediate and field offset of the fresh functions is flipped to show the run can
tell. No objdump or readelf output is parsed, and the binary is never executed. Standard library only.
"""

import argparse
import bisect
import collections
import hashlib
import json
import pathlib
import struct
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))

from elf_index import sections  # noqa: E402
from fde_extents import eh_frame_records  # noqa: E402

BINARY = ROOT / "artifacts" / "node" / "94" / "hl-node"
SHA256 = "3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f"

Writer = collections.namedtuple("Writer", "kind start width insert")
WRITERS = (
    Writer("new", 0x42E85C0, 0x268, 0x45A4C90), Writer("new", 0x42E8710, 0x278, 0x45A4DD0), Writer("new", 0x232C410, 0, 0), Writer("new", 0x232C560, 0, 0),
    Writer("update", 0x49E4F20, 0x268, 0), Writer("update", 0x49E4DE0, 0x278, 0), Writer("update", 0x232E5A0, 0, 0), Writer("update", 0x232E6E0, 0, 0),
    Writer("remove", 0x42E8BF0, 0x268, 0), Writer("remove", 0x42E8860, 0x278, 0), Writer("remove", 0x232C6B0, 0, 0), Writer("remove", 0x232CA40, 0, 0),
)
NAMED_ELSEWHERE = (0x42E85C0, 0x42E8BF0)
SLOT_MALLOC = 0x576DFD8
SLOT_FREE = 0x576E010
SLOT_MEMCPY = 0x576DFE0
SLOT_GROW_268 = 0x5773D50
SLOT_GROW_278 = 0x5773D58
SLOT_RECORDER = 0x5773190
SLOT_BOUNDS = 0x576DFC8
SLOT_ERROR = 0x576EF80
SLOT_FORMAT = 0x576E040
SLOT_CLOCK = 0x576E8A0
SLOT_TIME_ADD = 0x576E8A8
SLOT_DATE_ADD = 0x576E8B0
SLOT_OPEN = 0x576EAC0
SLOT_FLUSH = 0x576EAA8
SLOT_FLUSH_FLAG = 0x576EF18
SLOT_GROW_RECORD = 0x5776A50
SLOT_OUTCOME = 0x57738C8
SLOT_PANIC = (0x576E470, 0x576E128, 0x576E048, 0x576DFB8, 0x576E108, 0x576E150, 0x576E468)
SLOT_CHAR_TEXT = 0x576E780
SLOT_U64_TEXT = 0x576E090
SLOT_F64_TEXT = 0x576EA18
SLOT_DIR_TEXT = 0x576EB20
SLOT_HOUR_TEXT = 0x576EA60
FLUSH_FLAG_BYTE = 0x5788312

SPOT_SINK = 0x48547D0
PERP_SINK = 0x48551E0
SINK_TABLES = ((SPOT_SINK, 0x6FD33C), (PERP_SINK, 0x6FD35C))
BUFFER = 0x47EE2B0
FILE_WRITER = 0x47028B0
STREAM_WRITER = 0x47013B0
BATCH_WRITER = 0x47037B0
FILE_LINE = 0x45B4D70
STREAM_LINE = 0x45BA320
BATCH_LINE = 0x45B19A0
RECORD_JSON = 0x47EF630
DIFF_JSON = 0x47EE890
DIFF_KEY = 0x48653C0
STREAM_JSON = 0x47F04C0
BATCH_JSON = 0x47EFB40
ONE_EVENT = 0x4A7B210
ALL_EVENTS = 0x4A7FC00
OBJECT_END = 0x4865440
ESCAPE = 0x49C6940
FLOAT_VALUE = 0x4C27FA0
FLOAT_TRIM = 0x37E5350
FLOAT_FIELD = 0x4A7A460
DIFF_FIELD = 0x4A98D90
TIME_FIELD = 0x4A8F530
DROP_DIR = 0x472FB70
LINE_WRITE = 0x13D12A0
LINE_GROW = 0x13EDC40
TEXT_GROW = 0x454F5D0
ERROR_WRAP = 0x45BE9D0
CONSTRUCTOR = 0x47F1590
PACK_TEMPLATE = 0x1E0FD2
FLOAT_TEMPLATE = 0x20AD58
HOURLY_TEMPLATE = 0x1E9393
DAILY_TEMPLATE = 0x1E938E
CHAR_AT = 0x20A100
CHAR_HASH = 0x20A04C
PURR_TEXT = 0x5B9790
POWERS = 0x6F7470
OUTCOME_OFFSET = 100000000
SPOT_RECORD_KIND = 2

RECORD = 0x58
SLOT_SIZE = 0xF8
MAX64 = (1 << 64) - 1

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

ROWS = HEAP_BASE + 0x100
TOTAL = HEAP_BASE + 0x140
SLAB = HEAP_BASE + 0x180
RESULT = HEAP_BASE + 0x200
META = HEAP_BASE + 0x400
RECORD_IN = HEAP_BASE + 0x500
TIME_IN = HEAP_BASE + 0x580
BLOCK_IN = HEAP_BASE + 0x5C0
TEXT_IN = HEAP_BASE + 0x600
OBJECT = HEAP_BASE + 0x1000
SLOTS = HEAP_BASE + 0x2000
PAIRS = HEAP_BASE + 0x3000
TOKENS = HEAP_BASE + 0x3800
PERPS = HEAP_BASE + 0x8000
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

def add_saturating(left, right):
    total = left + right
    return (MAX64, 1) if total > MAX64 else (total, 0)


def sub_saturating(left, right):
    return (0, 1) if left < right else (left - right, 0)


def slot_fields(slot):
    return {"px": struct.unpack_from("<Q", slot, 0xA0)[0], "side": slot[0xC2], "size": struct.unpack_from("<Q", slot, 0xC8)[0], "oid": struct.unpack_from("<Q", slot, 0xD8)[0], "user": slot[0xE0:0xF4].hex()}


def row_for(tag, slot, asset, first=None, second=None):
    fields = slot_fields(slot)
    return {"word": SPOT_RECORD_KIND, "tag": tag, "first": first, "second": second, "px": fields["px"], "asset": asset, "oid": fields["oid"], "user": fields["user"], "side": fields["side"]}


def spec_new(w):
    fields = slot_fields(w["slot"])
    total, recorded = add_saturating(w["total"], fields["size"])
    return {"rows": [row_for(0, w["slot"], w["asset"], fields["size"])], "total": total, "recorder": recorded, "inserted": w["slot"].hex(), "returned": w["next"]}


def spec_update(w):
    old = slot_fields(w["slot"])["size"]
    new = w["new"]
    if new == old:
        return {"rows": [], "total": w["total"], "recorder": 0, "size": old}
    left, borrowed = sub_saturating(w["total"], old)
    total, carried = add_saturating(left, new)
    return {"rows": [row_for(1, w["slot"], w["asset"], old, new)], "total": total, "recorder": borrowed + carried, "size": new}


def spec_remove(w):
    slots, key = w["slots"], w["key"]
    if key >= len(slots) or struct.unpack_from("<Q", slots[key], 0)[0] == 2:
        return {"rows": [], "total": w["total"], "recorder": 0, "result": None, "count": w["count"], "next": w["next"], "link": None}
    slot = slots[key]
    total, recorded = sub_saturating(w["total"], slot_fields(slot)["size"])
    return {"rows": [row_for(2, slot, w["asset"])], "total": total, "recorder": recorded, "result": slot.hex(), "count": sub_saturating(w["count"], 1)[0], "next": key, "link": w["next"]}


def spec_writer(w):
    return {"new": spec_new, "update": spec_update, "remove": spec_remove}[w["what"]](w)


def power(places):
    return 10.0 ** places


def spot_coin(w):
    """Text for a spot row: outcome tokens win, then index 0 is the fixed pair, then [at]index, then #index above the offset."""
    asset = w["asset"]
    base = w["pairs"][asset][0]
    pair = w["outcomes"].get(base)
    if pair is not None and pair[1] < 2:
        value, _ = add_saturating(min(pair[0] * 10, MAX64) if pair[0] * 10 <= MAX64 else MAX64, pair[1])
        return "#%d" % (add_saturating(value, OUTCOME_OFFSET)[0] - OUTCOME_OFFSET)
    if asset == 0:
        return "PURR/USDC"
    if asset < OUTCOME_OFFSET:
        return "\x40%d" % asset
    return "#%d" % (asset - OUTCOME_OFFSET)


def spec_sink(w):
    if w["gate"] == 1 << 63:
        return {"path": "off"}
    tag = w["tag"]
    if w["market"] == "spot":
        asset = w["asset"]
        if asset >= len(w["pairs"]):
            return {"path": "panic bounds pairs"}
        coin = spot_coin(w)
        base, quote = w["pairs"][asset]
        if base >= len(w["tokens"]) or quote >= len(w["tokens"]):
            return {"path": "panic bounds tokens"}
        size_places, wei = w["tokens"][base][0], w["tokens"][quote][1]
        if wei < size_places:
            return {"path": "panic decimals"}
        px_places = wei - size_places
    else:
        dex, index = w["asset"] // 10000, w["asset"] % 10000
        if dex != w["dex"] or index >= len(w["perps"]):
            return {"path": "panic bounds perp"}
        coin, size_places = w["perps"][index]
        if size_places >= 7:
            return {"path": "panic decimals"}
        px_places = 6 - size_places
    record = {"tag": tag, "px": w["px"] / power(px_places), "coin": coin, "oid": w["oid"], "user": w["user"], "side": w["side"]}
    if tag == 0:
        record["first"] = float(w["first"]) / power(size_places) if w["first"] else 0.0
    elif tag == 1:
        record["first"] = float(w["first"]) / power(size_places) if w["first"] else 0.0
        record["second"] = float(w["second"]) / power(size_places) if w["second"] else 0.0
    return {"path": "record", "record": record, "flag": w["flag"], "block": w["block"]}


def spec_buffer(w):
    mode = w["mode"]
    owned = 1 if w["record"]["coin"] else 0
    if mode == "file":
        return {"path": "file", "free": owned}
    if mode == "vector":
        grew = w["length"] == w["capacity"]
        return {"path": "vector", "free": 0, "length": w["length"] + 1, "grew": grew}
    if not w["block_date"]:
        return {"path": "no block", "free": owned}
    clock = w["clock"]
    if not w["flag"]:
        return {"path": "stream", "free": owned, "local": list(clock), "calls": []}
    secs, nanos = clock[1] + w["carry"][0], clock[2] + 40000000
    days = w["carry"][1]
    calls = [["time", clock[1], clock[2]]]
    if (days + 0xFFFF574000000000) & MAX64 < 0xFFFEAE7FFFFEAE81:
        return {"path": "panic overflow", "calls": calls}
    whole = abs(days) // 86400
    calls.append(["date", clock[0], -whole if days < 0 else whole])
    if not w["date_result"]:
        return {"path": "panic overflow", "calls": calls}
    return {"path": "stream", "free": owned, "local": [w["date_result"], secs, nanos], "calls": calls}


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


def float_text(value):
    text = "%.10f" % value
    while text.endswith("0") and not text.endswith(".0"):
        text = text[:-1]
    return "0.0" if text == "-0.0" else text


def escape(text):
    return text.replace("\\", "\\\\").replace('"', '\\"')


def diff_text(r):
    if r["tag"] == 0:
        return '{"new":{"sz":"%s"}}' % float_text(r["first"])
    if r["tag"] == 1:
        return '{"update":{"origSz":"%s","newSz":"%s"}}' % (float_text(r["first"]), float_text(r["second"]))
    return '"remove"'


def record_text(r):
    return '{"user":"0x%s","oid":%d,"coin":"%s","side":"%s","px":"%s","raw_book_diff":%s}' % (r["user"], r["oid"], escape(r["coin"]), "A" if r["side"] else "B", float_text(r["px"]), diff_text(r))


def spec_line(w):
    if w["line"] == "file":
        return record_text(w["records"][0]) + "\n"
    head = '{"local_time":"L%s","block_time":"T%s","block_number":%d,"events":[' % (w["local"].hex(), w["block"].hex(), w["number"])
    return head + ",".join(record_text(r) for r in w["records"]) + "]}\n"


def spec_run(case):
    return {"writer": spec_writer, "sink": spec_sink, "buffer": spec_buffer, "file": spec_file, "line": spec_line}[case.kind](case.world)

# ---- harness: real bytes; every edge callee is stubbed and logged ----

class RealExcept:
    """Every call target runs its real bytes unless the harness stubs it."""

    def __init__(self):
        self.stubs = frozenset()

    def __contains__(self, target):
        return target not in self.stubs


class Case:
    def __init__(self, label, kind, world, copy=0):
        self.label = label
        self.kind = kind
        self.world = world
        self.copy = copy


def first_call(image, start):
    """First E8 target in a function body."""
    begin, end = image.exact_fde(start)
    for row in decode_range(image, begin, end):
        if row.op == "call":
            return row.target
    raise EvidenceError("no call in %#x" % start)


def row_width(image, start):
    """The stride of the row vector: the only imul immediate of 0x268 or 0x278 in the body."""
    begin, end = image.exact_fde(start)
    data = bytes(image.blob[image.offset(begin):image.offset(end)])
    seen = {width for width in (0x268, 0x278) if data.count(b"\x69") and any(data[at:at + 4] == struct.pack("<I", width) and data[at - 2] == 0x69 for at in range(2, len(data) - 4))}
    if len(seen) != 1:
        raise EvidenceError("row width at %#x: %r" % (start, seen))
    return seen.pop()


class Harness:
    def __init__(self, image):
        self.image = image
        self.machine = Machine(image)
        machine = self.machine
        self.relative = {slot: addend for slot, kind, addend, _ in image.relocations() if kind == 8}
        relative = self.relative
        table = {SLOT_MALLOC: self.on_malloc, SLOT_FREE: self.on_free, SLOT_MEMCPY: self.on_copy, SLOT_GROW_268: self.on_grow, SLOT_GROW_278: self.on_grow, SLOT_RECORDER: self.on_recorder,
                 SLOT_BOUNDS: self.on_bounds, SLOT_FORMAT: self.on_format, SLOT_CLOCK: self.on_clock, SLOT_TIME_ADD: self.on_time_add, SLOT_DATE_ADD: self.on_date_add, SLOT_OPEN: self.on_open,
                 SLOT_FLUSH: self.on_flush, SLOT_GROW_RECORD: self.on_grow_record, SLOT_OUTCOME: self.on_outcome, SLOT_ERROR: self.on_error}
        for slot in SLOT_PANIC:
            table[slot] = lambda m, which=slot: self.on_panic(m, which)
        for slot in table:
            relative.setdefault(slot, slot)
        machine.memory.statics.update(relative)
        machine.slots = {relative[slot]: hook for slot, hook in table.items()}
        self.real = RealExcept()
        machine.real = self.real
        self.widths = {writer.start: row_width(image, writer.start) for writer in WRITERS}
        calls = {DROP_DIR: self.on_drop_dir, TIME_FIELD: self.on_time_field, TEXT_GROW: self.on_text_grow, LINE_GROW: self.on_text_grow, LINE_WRITE: self.on_line, ERROR_WRAP: self.on_wrap}
        for writer in WRITERS:
            if writer.kind == "new":
                calls[first_call(image, writer.start)] = self.on_insert
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

    def use(self, stubs):
        """Stub these targets for this run on top of the base set."""
        calls = dict(self.base_calls)
        calls.update(stubs)
        self.machine.calls = calls
        self.real.stubs = self.base_real | frozenset(stubs)

    def fresh(self):
        memory = self.machine.memory
        memory.reset()
        self.brk = HEAP_FREE
        self.live = {}
        self.log = []
        self.line = None
        self.copy_sizes = None

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
        width = self.width
        if vector != ROWS:
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

    def on_grow_record(self, m):
        memory = m.memory
        vector = m.regs[RDI]
        if vector != OBJECT + 0x5B0 + 0xB0:
            raise Halt("record vector")
        capacity, old, length = memory.read(vector, 8), memory.read(vector + 8, 8), memory.read(vector + 0x10, 8)
        if capacity > 0x40 or length != capacity:
            raise Halt("record length")
        wanted = capacity * 2 or 4
        fresh = self.allocate(wanted * RECORD)
        if capacity:
            memory.copy(fresh, old, capacity * RECORD)
            if self.live.pop(old, None) != capacity * RECORD:
                raise Halt("record buffer")
        memory.write(vector, 8, wanted)
        memory.write(vector + 8, 8, fresh)

    def on_recorder(self, m):
        if m.regs[RDI] != 0:
            raise Halt("recorder argument")
        self.log.append(["recorder"])

    def on_bounds(self, m):
        raise Panicked("bounds pairs")

    def on_panic(self, m, slot):
        wanted = PANIC_TEXT.get(slot)
        if wanted is not None and m.regs[RSI] != wanted:
            raise Halt("panic text length")
        raise Panicked("panic %#x" % slot)

    def on_error(self, m):
        m.regs[RAX] = 0xE1

    def on_insert(self, m):
        regs = m.regs
        if regs[RDI] != SLAB or regs[RSI] != m.memory.read(SLAB + 0x20, 8):
            raise Halt("insert arguments")
        self.log.append(["insert", m.memory.bytes_at(regs[RDX], SLOT_SIZE).hex()])

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

    def on_outcome(self, m):
        regs = m.regs
        if regs[RSI] != META:
            raise Halt("outcome arguments")
        pair = self.w["outcomes"].get(regs[RDX])
        out = struct.pack("<QB", 0x7777, 2) if pair is None else struct.pack("<QB", pair[0], pair[1])
        m.memory.put_bytes(regs[RDI], out)

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
        if template == PACK_TEMPLATE:
            if memory.read(args + 8, 8) != statics[SLOT_CHAR_TEXT] or memory.read(args + 0x18, 8) != statics[SLOT_U64_TEXT]:
                raise Halt("coin text functions")
            text = "%c%d" % (memory.read(memory.read(args, 8), 4), memory.read(memory.read(args + 0x10, 8), 8))
        elif template == FLOAT_TEMPLATE:
            if memory.read(args + 8, 8) != statics[SLOT_F64_TEXT]:
                raise Halt("float text function")
            text = "%.10f" % to_float(memory.read(memory.read(args, 8), 8))
        elif template in (HOURLY_TEMPLATE, DAILY_TEMPLATE):
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
        else:
            raise Halt("format template %#x" % template)
        self.string_out(m, text)

    def on_open(self, m):
        regs = m.regs
        memory = m.memory
        at = regs[RSI]
        self.log.append(["open", self.text_arg(m, at + 8) if False else memory.bytes_at(memory.read(at + 8, 8), memory.read(at + 0x10, 8)).decode("utf-8")])
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
        if regs[RDI] != self.file_at or regs[RDX] != RECORD_IN:
            raise Halt("line arguments")
        self.log.append(["line", [memory.read(regs[RSI] + 4 * index, 4) for index in range(3)]])

    def on_text_grow(self, m):
        regs = m.regs
        memory = m.memory
        vector, used, extra = regs[RDI], regs[RSI], regs[RDX]
        capacity, old = memory.read(vector, 8), memory.read(vector + 8, 8)
        if regs[RCX] != 1 or regs[R8] != 1 or used + extra <= capacity:
            raise Halt("grow arguments")
        wanted = max(capacity * 2, used + extra, 8)
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
        mark = {"local_time": "L", "block_time": "T"}[key]
        text = ('%s"%s":"%s%s"' % (comma, key, mark, memory.bytes_at(regs[RCX], 12).hex())).encode("ascii")
        length = memory.read(vector + 0x10, 8)
        if memory.read(vector, 8) < length + len(text):
            regs[RDI], regs[RSI], regs[RDX], regs[RCX], regs[R8] = vector, length, len(text), 1, 1
            self.on_text_grow(m)
        memory.put_bytes(memory.read(vector + 8, 8) + length, text)
        memory.write(vector + 0x10, 8, length + len(text))
        regs[RAX] = 0

    def run_writer(self, case):
        w = case.world
        writer = WRITERS[case.copy]
        self.width = self.widths[writer.start]
        machine = self.machine
        memory = machine.memory
        self.fresh()
        self.use({})
        self.w = w
        self.copy_sizes = (self.width, SLOT_SIZE)
        capacity = w["capacity"]
        buffer = self.allocate(capacity * self.width) if capacity else 8
        for index in range(w["length"]):
            memory.put_bytes(buffer + index * self.width, ramp(self.width, 0x55 + index))
        memory.write(ROWS, 8, capacity)
        memory.write(ROWS + 8, 8, buffer)
        memory.write(ROWS + 0x10, 8, w["length"])
        memory.write(TOTAL, 8, w["total"])
        what = writer.kind
        if what == "new":
            memory.put_bytes(SLOTS, w["slot"])
            memory.write(SLAB + 0x20, 8, w["next"])
            args = {RDI: SLAB, RSI: SLOTS, RDX: w["asset"], RCX: ROWS, R8: TOTAL}
        elif what == "update":
            memory.put_bytes(SLOTS, w["slot"])
            args = {RDI: SLOTS, RSI: w["asset"], RDX: w["new"], RCX: ROWS, R8: TOTAL}
        else:
            for index, slot in enumerate(w["slots"]):
                memory.put_bytes(SLOTS + index * SLOT_SIZE, slot)
            memory.write(SLAB, 8, 8)
            memory.write(SLAB + 8, 8, SLOTS)
            memory.write(SLAB + 0x10, 8, len(w["slots"]))
            memory.write(SLAB + 0x18, 8, w["count"])
            memory.write(SLAB + 0x20, 8, w["next"])
            args = {RDI: RESULT, RSI: SLAB, RDX: w["key"], RCX: w["asset"], R8: ROWS, R9: TOTAL}
        returned = machine.run(writer.start, args)
        length = memory.read(ROWS + 0x10, 8)
        if length > 0x40:
            raise Halt("row count")
        base = memory.read(ROWS + 8, 8)
        rows = []
        for index in range(w["length"], length):
            at = base + index * self.width
            tag = memory.read(at + 8, 8)
            rows.append({"word": memory.read(at, 8), "tag": tag, "first": memory.read(at + 0x10, 8) if tag in (0, 1) else None, "second": memory.read(at + 0x18, 8) if tag == 1 else None,
                         "px": memory.read(at + 0x20, 8), "asset": memory.read(at + 0x28, 8), "oid": memory.read(at + 0x30, 8), "user": memory.bytes_at(at + 0x38, 20).hex(), "side": memory.read(at + 0x4C, 1)})
        for index in range(min(w["length"], 3)):
            if memory.bytes_at(base + index * self.width, self.width) != ramp(self.width, 0x55 + index):
                raise Halt("old row changed")
        out = {"rows": rows, "total": memory.read(TOTAL, 8), "recorder": sum(1 for row_ in self.log if row_[0] == "recorder")}
        grew = sum(1 for row_ in self.log if row_[0] == "grow")
        if grew != (1 if rows and w["length"] == capacity else 0):
            raise Halt("growth count")
        if what == "new":
            inserted = [row_ for row_ in self.log if row_[0] == "insert"]
            if len(inserted) != 1:
                raise Halt("insert count")
            out.update(inserted=inserted[0][1], returned=returned)
        elif what == "update":
            out["size"] = memory.read(SLOTS + 0xC8, 8)
        else:
            word = memory.read(RESULT, 8)
            out.update(result=memory.bytes_at(RESULT, SLOT_SIZE).hex() if word != 2 else None, count=memory.read(SLAB + 0x18, 8), next=memory.read(SLAB + 0x20, 8))
            out["link"] = None
            if rows:
                entry = SLOTS + w["key"] * SLOT_SIZE
                if memory.read(entry, 8) != 2:
                    raise Halt("slot not vacant")
                out["link"] = memory.read(entry + 8, 8)
        return out

    def run_sink(self, case):
        w = case.world
        machine = self.machine
        memory = machine.memory
        self.fresh()
        self.use({BUFFER: self.on_record})
        self.w = w
        captured = self.captured = {}
        memory.write(OBJECT + 0x5B0, 8, w["gate"])
        memory.write(OBJECT + 0xA78, 1, w["flag"])
        memory.put_bytes(OBJECT + 0xA60, w["block"])
        row = HEAP_BASE + 0x9000
        memory.put_bytes(row, ramp(0x278, 0x21))
        memory.write(row, 8, 2)
        for at, value in ((8, w["tag"]), (0x10, w["first"]), (0x18, w["second"]), (0x20, w["px"]), (0x28, w["asset"]), (0x30, w["oid"])):
            memory.write(row + at, 8, value)
        memory.put_bytes(row + 0x38, bytes.fromhex(w["user"]))
        memory.write(row + 0x4C, 1, w["side"])
        if w["market"] == "spot":
            start = SPOT_SINK
            far = w["asset"] >= 0x1000 and w["asset"] < len(w["pairs"])
            memory.write(META + 0x168, 8, (PAIRS - w["asset"] * 0x20) & MASK[8] if far else PAIRS)
            memory.write(META + 0x170, 8, len(w["pairs"]))
            memory.write(META + 0x180, 8, TOKENS)
            memory.write(META + 0x188, 8, len(w["tokens"]))
            for index, (base, quote) in enumerate(list(w["pairs"])[:4]):
                memory.write(PAIRS + index * 0x20, 8, base)
                memory.write(PAIRS + index * 0x20 + 8, 8, quote)
            for index, (size_places, wei) in enumerate(w["tokens"]):
                memory.write(TOKENS + index * 0xE8 + 0x48, 1, size_places)
                memory.write(TOKENS + index * 0xE8 + 0x49, 1, wei)
        else:
            start = PERP_SINK
            memory.write(META + 8, 8, PERPS)
            memory.write(META + 0x10, 8, len(w["perps"]))
            memory.write(META + 0x30, 8, w["dex"])
            for index, (name, places) in enumerate(w["perps"]):
                data = name.encode("ascii")
                text = TEXT_IN + index * 0x20
                memory.put_bytes(text, data)
                memory.write(PERPS + index * 0x30 + 8, 8, text)
                memory.write(PERPS + index * 0x30 + 0x10, 8, len(data))
                memory.write(PERPS + index * 0x30 + 0x2A, 1, places)
        machine.jump_low, machine.jump_high = self.image.exact_fde(start)
        try:
            machine.run(start, {RDI: OBJECT, RSI: row, RDX: META, RCX: META + 0x20})
        except Panicked as error:
            return {"path": {"bounds pairs": "panic bounds pairs", "panic %#x" % 0x576E150: "panic decimals"}.get(str(error), {True: "panic bounds tokens", False: "panic bounds perp"}[w["market"] == "spot"])}
        if not captured:
            return {"path": "off"}
        return captured

    def on_record(self, m):
        regs = m.regs
        memory = m.memory
        at = regs[RCX]
        if regs[RDI] != OBJECT + 0x5B0:
            raise Halt("record buffer argument")
        if memory.bytes_at(regs[RDX], 12) != struct.pack("<III", *self.w["clock"]):
            raise Halt("record time")
        tag = memory.read(at, 8)
        cap, text, length = memory.read(at + 0x18, 8), memory.read(at + 0x20, 8), memory.read(at + 0x28, 8)
        if length > 0x40 or cap != length:
            raise Halt("coin length")
        record = {"tag": tag, "px": to_float(memory.read(at + 0x38, 8)), "coin": memory.bytes_at(text, length).decode("utf-8") if length else "", "oid": memory.read(at + 0x30, 8), "user": memory.bytes_at(at + 0x40, 20).hex(), "side": memory.read(at + 0x54, 1)}
        if tag in (0, 1):
            record["first"] = to_float(memory.read(at + 8, 8))
        if tag == 1:
            record["second"] = to_float(memory.read(at + 0x10, 8))
        self.captured.update(path="record", record=record, flag=regs[RSI] & 0xFF, block=memory.bytes_at(regs[R8], 0x18))
        if length:
            if self.live.pop(text, None) != length:
                raise Halt("coin buffer")
        elif text != 1:
            raise Halt("empty coin pointer")

    def put_record(self, at, r):
        memory = self.machine.memory
        memory.write(at, 8, r["tag"])
        memory.write(at + 8, 8, to_bits(r.get("first", 0.0)))
        memory.write(at + 0x10, 8, to_bits(r.get("second", 0.0)))
        data = r["coin"].encode("utf-8")
        text = self.allocate(max(len(data), 1))
        memory.put_bytes(text, data)
        memory.write(at + 0x18, 8, len(data))
        memory.write(at + 0x20, 8, text)
        memory.write(at + 0x28, 8, len(data))
        memory.write(at + 0x30, 8, r["oid"])
        memory.write(at + 0x38, 8, to_bits(r["px"]))
        memory.put_bytes(at + 0x40, bytes.fromhex(r["user"]))
        memory.write(at + 0x54, 1, r["side"])
        return text

    def run_buffer(self, case):
        w = case.world
        machine = self.machine
        memory = machine.memory
        self.fresh()
        self.w = w
        self.use({FILE_WRITER: lambda m: self.on_out(m, "file"), STREAM_WRITER: lambda m: self.on_out(m, "stream")})
        at = OBJECT + 0x5B0
        record = w["record"]
        text = self.put_record(RECORD_IN, record)
        memory.put_bytes(TIME_IN, ramp(12, 0x31))
        memory.write(BLOCK_IN, 8, w["number"])
        memory.write(BLOCK_IN + 8, 4, w["block_date"])
        memory.write(BLOCK_IN + 0xC, 4, 0x12345)
        memory.write(BLOCK_IN + 0x10, 4, 0x6789A)
        if w["mode"] == "file":
            word = 1 << 63
        elif w["mode"] == "stream":
            word = (1 << 63) + 2
        else:
            word = w["capacity"]
            buffer = self.allocate(word * RECORD) if word else 8
            memory.write(at + 0xB8, 8, buffer)
            memory.write(at + 0xC0, 8, w["length"])
        memory.write(at + 0xB0, 8, word)
        self.outs = []
        try:
            machine.run(BUFFER, {RDI: at, RSI: w["flag"], RDX: TIME_IN, RCX: RECORD_IN, R8: BLOCK_IN})
        except Panicked:
            return {"path": "panic overflow", "calls": [row_ for row_ in self.log if row_[0] in ("time", "date")]}
        calls = [row_ for row_ in self.log if row_[0] in ("time", "date")]
        freed = int(text not in self.live)
        mode = w["mode"]
        if mode == "vector":
            length = memory.read(at + 0xC0, 8)
            stored = memory.bytes_at(memory.read(at + 0xB8, 8) + (length - 1) * RECORD, RECORD)
            if stored != memory.bytes_at(RECORD_IN, RECORD):
                raise Halt("stored record")
            return {"path": "vector", "free": freed, "length": length, "grew": memory.read(at + 0xB0, 8) != w["capacity"]}
        if not self.outs:
            return {"path": "no block", "free": freed}
        path = self.outs[0][0]
        out = {"path": path, "free": freed}
        if path == "stream":
            out.update(local=self.outs[0][1], calls=calls)
        return out

    def on_out(self, m, path):
        regs = m.regs
        memory = m.memory
        if regs[RDI] != OBJECT + 0x5B0:
            raise Halt("writer argument")
        if path == "file":
            if regs[RSI] != TIME_IN or regs[RDX] != RECORD_IN:
                raise Halt("file arguments")
            self.outs.append(["file"])
            return
        w = self.w
        at = regs[RDX]
        if memory.bytes_at(at, RECORD) != memory.bytes_at(RECORD_IN, RECORD):
            raise Halt("stream record")
        if memory.read(at + 0x58, 8) != w["number"] or memory.read(at + 0x6C, 4) != w["block_date"] or memory.read(at + 0x70, 4) != 0x12345 or memory.read(at + 0x74, 4) != 0x6789A:
            raise Halt("stream block")
        if memory.bytes_at(at + 0x60, 12) != memory.bytes_at(regs[RSI], 12):
            raise Halt("stream time")
        self.outs.append(["stream", [memory.read(regs[RSI] + 4 * index, 4) for index in range(3)]])

    def run_file(self, case):
        w = case.world
        machine = self.machine
        memory = machine.memory
        self.fresh()
        self.w = w
        start, line = {"file": (FILE_WRITER, FILE_LINE), "stream": (STREAM_WRITER, STREAM_LINE), "batch": (BATCH_WRITER, BATCH_LINE)}[w["which"]]
        self.use({line: self.on_file_line})
        at = OBJECT + 0x100
        self.file_at = at + 0x48
        word = w["file_word"] if w["open"] else 1 << 63 | 1
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
            machine.run(start, {RDI: at, RSI: TIME_IN, RDX: RECORD_IN})
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

    def run_line(self, case):
        w = case.world
        machine = self.machine
        memory = machine.memory
        self.fresh()
        self.w = w
        self.use({})
        self.file_at = OBJECT + 0x148
        machine.jump_low, machine.jump_high = self.image.exact_fde(ESCAPE)
        line = w["line"]
        records = w["records"]
        texts = []
        if line == "file":
            texts.append(self.put_record(RECORD_IN, records[0]))
            machine.run(FILE_LINE, {RDI: self.file_at, RSI: TIME_IN, RDX: RECORD_IN})
        elif line == "stream":
            texts.append(self.put_record(RECORD_IN, records[0]))
            memory.write(RECORD_IN + 0x58, 8, w["number"])
            memory.put_bytes(RECORD_IN + 0x60, w["local"])
            memory.put_bytes(RECORD_IN + 0x6C, w["block"])
            machine.run(STREAM_LINE, {RDI: self.file_at, RSI: TIME_IN, RDX: RECORD_IN})
        else:
            base = self.allocate(max(len(records), 1) * RECORD)
            for index, record in enumerate(records):
                texts.append(self.put_record(base + index * RECORD, record))
            memory.write(RECORD_IN, 8, len(records))
            memory.write(RECORD_IN + 8, 8, base)
            memory.write(RECORD_IN + 0x10, 8, len(records))
            memory.write(RECORD_IN + 0x18, 8, w["number"])
            memory.put_bytes(RECORD_IN + 0x20, w["local"])
            memory.put_bytes(RECORD_IN + 0x2C, w["block"])
            machine.run(BATCH_LINE, {RDI: self.file_at, RSI: TIME_IN, RDX: RECORD_IN})
        return self.line

    def run(self, case):
        return {"writer": self.run_writer, "sink": self.run_sink, "buffer": self.run_buffer, "file": self.run_file, "line": self.run_line}[case.kind](case)


PANIC_TEXT = {0x576E468: 0x26, 0x576E108: 0x1C, 0x576E048: 0x2B}
CRASHES = (Halt, Panicked, EvidenceError, KeyError, IndexError, ValueError, TypeError, OverflowError, struct.error, UnicodeDecodeError, ZeroDivisionError)


def compare_run(harness, case):
    """None when the run agrees with the spec, else a text."""
    expected = spec_run(case)
    try:
        got = harness.run(case)
    except CRASHES as error:
        return "%s: crash %s %s" % (case.kind, case.label, str(error)[:120])
    if case.kind == "buffer" and expected.get("path") == "panic overflow":
        got.pop("free", None)
    if isinstance(expected, dict):
        if case.kind == "file" and expected["path"] != "line":
            got = {"path": got["path"], "log": got["log"]}
    if got != expected:
        return "%s: differ %s: %.300r != %.300r" % (case.kind, case.label, got, expected)
    return None


def ramp(count, start):
    return bytes((start + index * 7) & 0xFF for index in range(count))

# ---- cases ----

USER = "00112233445566778899aabbccddeeff01234567"
USER_TWO = "f0e1d2c3b4a5968778695a4b3c2d1e0f10203040"
CLOCK = (2460000, 45296, 123456789)


def make_slot(px=0x1234567, side=1, size=0x4D2, oid=0x7BCDE, user=USER, word=0, index=0):
    slot = bytearray(ramp(SLOT_SIZE, 0x13 + index * 5))
    struct.pack_into("<Q", slot, 0, word)
    struct.pack_into("<Q", slot, 0xA0, px)
    slot[0xC2] = side
    struct.pack_into("<Q", slot, 0xC8, size)
    struct.pack_into("<Q", slot, 0xD8, oid)
    slot[0xE0:0xF4] = bytes.fromhex(user)
    return bytes(slot)


def writer_cases():
    cases = []
    for copy, writer in enumerate(WRITERS):
        name = "%s %#x: " % (writer.kind, writer.start)
        vectors = ((4, 1), (4, 4), (0, 0), (8, 3))

        def add(label, **world):
            for capacity, length in (vectors if not world.pop("short", False) else vectors[:1]):
                cases.append(Case(name + label + " rows %d of %d" % (length, capacity), "writer", dict(world, what=writer.kind, capacity=capacity, length=length), copy))

        if writer.kind == "new":
            add("plain", slot=make_slot(), asset=7, total=100, next=3)
            add("second side", slot=make_slot(px=9, side=0, size=1, oid=2, user=USER_TWO, index=1), asset=120003, total=0, next=0, short=True)
            add("total exactly fills", slot=make_slot(size=5), asset=1, total=MAX64 - 5, next=9, short=True)
            add("total one past", slot=make_slot(size=6), asset=1, total=MAX64 - 5, next=9, short=True)
            add("high words", slot=make_slot(px=MAX64, size=MAX64, oid=MAX64), asset=MAX64, total=MAX64, next=MAX64, short=True)
        elif writer.kind == "update":
            add("smaller", slot=make_slot(size=500), new=200, asset=7, total=900)
            add("larger", slot=make_slot(size=500, side=0, user=USER_TWO, index=2), new=800, asset=120003, total=500, short=True)
            add("same size", slot=make_slot(size=500), new=500, asset=7, total=900, short=True)
            add("to zero", slot=make_slot(size=500), new=0, asset=7, total=500, short=True)
            add("total below old", slot=make_slot(size=500), new=300, asset=7, total=499, short=True)
            add("total equal old", slot=make_slot(size=500), new=300, asset=7, total=500, short=True)
            add("sum exactly fills", slot=make_slot(size=1), new=MAX64 - 4, asset=7, total=5, short=True)
            add("sum one past", slot=make_slot(size=1), new=MAX64 - 3, asset=7, total=5, short=True)
        else:
            full = [make_slot(px=11 + index, side=index & 1, size=100 + index, oid=50 + index, user=USER if index else USER_TWO, index=index) for index in range(3)]
            vacant = bytearray(full[1])
            struct.pack_into("<Q", vacant, 0, 2)
            mixed = [full[0], bytes(vacant), full[2]]
            add("middle key", slots=full, key=1, asset=7, total=1000, count=3, next=9)
            add("first key", slots=full, key=0, asset=120003, total=100, count=1, next=0, short=True)
            add("last key", slots=full, key=2, asset=7, total=1000, count=0, next=5, short=True)
            add("key past the end", slots=full, key=3, asset=7, total=1000, count=3, next=9, short=True)
            add("huge key", slots=full, key=MAX64, asset=7, total=1000, count=3, next=9, short=True)
            add("vacant key", slots=mixed, key=1, asset=7, total=1000, count=2, next=9, short=True)
            add("total below size", slots=full, key=1, asset=7, total=100, count=3, next=9, short=True)
            add("total equal size", slots=full, key=1, asset=7, total=101, count=3, next=9, short=True)
            add("word 1 occupied", slots=[make_slot(word=1)], key=0, asset=7, total=2000, count=1, next=4, short=True)
            add("word 3 occupied", slots=[make_slot(word=3)], key=0, asset=7, total=2000, count=1, next=4, short=True)
    return cases


BLOCK = bytes(range(0x30, 0x48))


def spot_world(**changes):
    world = dict(market="spot", gate=0, flag=0, block=BLOCK, clock=CLOCK, tag=0, first=123456, second=654321, px=98765432, asset=1, oid=5551212, user=USER, side=1,
                 pairs=[(1, 0), (2, 0), (3, 4), (5, 0)], tokens=[(8, 8), (2, 8), (3, 6), (0, 8), (9, 11), (6, 9)], outcomes={})
    world.update(changes)
    return world


def perp_world(**changes):
    world = dict(market="perp", gate=0, flag=0, block=BLOCK, clock=CLOCK, tag=0, first=123456, second=654321, px=98765432, asset=1, oid=5551212, user=USER, side=1,
                 dex=0, perps=[("BTC", 5), ("ETH", 4), ("", 0), ("LONGERCOINNAME", 6), ("BAD", 7)])
    world.update(changes)
    return world


def sink_cases():
    cases = []
    def add(label, world):
        cases.append(Case("%s: %s" % (world["market"], label), "sink", world))

    for make in (spot_world, perp_world):
        for tag, name in ((0, "new"), (1, "update"), (2, "remove"), (3, "tag 3")):
            add(name, make(tag=tag))
        add("gate off", make(gate=1 << 63))
        add("gate any word", make(gate=5))
        add("gate low bit", make(gate=(1 << 63) + 1))
        add("flag", make(flag=1))
        add("other user side 0", make(user=USER_TWO, side=0, oid=MAX64))
        add("zero first new", make(tag=0, first=0))
        add("zero first update", make(tag=1, first=0))
        add("zero second update", make(tag=1, second=0))
        add("zero both update", make(tag=1, first=0, second=0))
        add("high word first", make(tag=1, first=MAX64, second=1 << 63))
        add("high word px", make(px=MAX64, tag=0))
        add("high word new", make(tag=0, first=(1 << 63) + 3))
    add("index 0 is the fixed pair", spot_world(asset=0))
    add("index 3", spot_world(asset=3))
    add("wei and size equal", spot_world(asset=2, tokens=[(8, 8), (2, 8), (3, 6), (6, 0), (0, 6)], pairs=[(1, 0), (2, 0), (3, 4)]))
    add("second pair", spot_world(asset=2))
    add("wei below size", spot_world(asset=2, tokens=[(8, 8), (2, 8), (3, 6), (7, 0), (0, 6)], pairs=[(1, 0), (2, 0), (3, 4)]))
    add("asset past pairs", spot_world(asset=4))
    add("asset equal pairs", spot_world(asset=4, pairs=[(1, 0), (2, 0), (3, 4), (5, 0)]))
    add("quote past tokens", spot_world(asset=1, pairs=[(1, 0), (2, 6)]))
    add("base past tokens", spot_world(asset=1, pairs=[(1, 0), (6, 0)]))
    add("quote equal tokens check", spot_world(asset=1, pairs=[(1, 0), (2, 7)]))
    add("outcome token side 0", spot_world(outcomes={2: (17, 0)}))
    add("outcome token side 1", spot_world(outcomes={2: (17, 1)}))
    add("outcome at the fixed pair index", spot_world(asset=0, outcomes={1: (0, 0)}))
    add("outcome id with a large word", spot_world(outcomes={2: (1 << 60, 1)}))
    add("outcome product overflows", spot_world(outcomes={2: (1 << 62, 1)}))
    add("outcome byte 2 is no outcome", spot_world(outcomes={2: (17, 2)}))
    add("outcome byte 3 at the fixed pair index", spot_world(asset=0, outcomes={1: (17, 3)}))
    add("outcome near the top", spot_world(outcomes={2: ((MAX64 - 100000000) // 10, 1)}))
    add("outcome exactly below the offset top", spot_world(outcomes={2: ((MAX64 - 100000001) // 10 + 1, 0)}))
    add("outcome just below the top", spot_world(outcomes={2: ((MAX64 - 100000000) // 10 - 1, 1)}))
    add("outcome offset carries", spot_world(outcomes={2: (MAX64 // 10, 0)}))
    for delta, value in ((-1, 99999999), (0, 100000000), (1, 100000001)):
        pairs = {value: (1, 0)}
        add("index near the offset %d" % delta, spot_world(asset=value, pairs=_Pairs(value)))
    add("perp second dex", perp_world(asset=20003, dex=2))
    add("perp asset 0", perp_world(asset=0))
    add("perp asset 10000 in dex 0", perp_world(asset=10000))
    add("perp dex 1 index 0", perp_world(asset=10000, dex=1))
    add("perp index past", perp_world(asset=5))
    add("perp index equal length", perp_world(asset=5, perps=[("A", 1), ("B", 1), ("C", 1), ("D", 1), ("E", 1)]))
    add("perp empty name", perp_world(asset=2))
    add("perp long name", perp_world(asset=3))
    add("perp decimals 7", perp_world(asset=4))
    add("perp high asset", perp_world(asset=MAX64))
    add("perp dex wrong", perp_world(asset=1, dex=1))
    return cases


class _Pairs(list):
    """A pair table with one row far out, without building it: the spot harness writes only real rows, so the far row sits in a short list."""

    def __init__(self, index):
        list.__init__(self, [(1, 0)] * 4)
        self.index = index

    def __getitem__(self, at):
        return (1, 0)

    def __iter__(self):
        return iter([(1, 0)] * 4)

    def __len__(self):
        return self.index + 1


BASE_RECORD = dict(tag=0, first=1.5, px=3000.25, coin="BTC", oid=99, user=USER, side=1)


def buffer_cases():
    cases = []
    def add(label, **world):
        data = dict(record=BASE_RECORD, flag=0, number=777, block_date=2460001, clock=CLOCK, carry=(0, 0), date_result=2460002, capacity=4, length=0)
        data.update(world)
        cases.append(Case("%s: %s" % (data["mode"], label), "buffer", data))

    add("plain", mode="file")
    add("flag ignored", mode="file", flag=1)
    add("empty coin", mode="file", record=dict(BASE_RECORD, coin=""))
    add("no block date", mode="file", block_date=0)
    add("room", mode="vector", capacity=4, length=1)
    add("full", mode="vector", capacity=4, length=4)
    add("empty", mode="vector", capacity=0, length=0)
    add("flag ignored", mode="vector", capacity=4, length=2, flag=1)
    add("no block date", mode="vector", capacity=4, length=0, block_date=0)
    add("clock", mode="stream")
    add("no block", mode="stream", block_date=0)
    add("no block empty coin", mode="stream", block_date=0, record=dict(BASE_RECORD, coin=""))
    add("empty coin", mode="stream", record=dict(BASE_RECORD, coin=""))
    add("flag plus 40 ms", mode="stream", flag=1)
    add("flag carry into the next day", mode="stream", flag=1, carry=(1, 86400), date_result=2460007)
    add("flag two days", mode="stream", flag=1, carry=(1, 172800), date_result=2460009)
    add("flag one second below a day", mode="stream", flag=1, carry=(1, 86399), date_result=2460011)
    add("flag negative days", mode="stream", flag=1, carry=(1, -86400 * 3), date_result=2460013)
    add("flag date add fails", mode="stream", flag=1, carry=(1, 86400), date_result=0)
    add("flag seconds at the top of range", mode="stream", flag=1, carry=(0, 0xA8BFFFFFFFFF), date_result=2460015)
    add("flag seconds past the top of range", mode="stream", flag=1, carry=(0, 0xA8C000000000), date_result=2460015)
    add("flag seconds at the low end", mode="stream", flag=1, carry=(0, -0xA8BFFFFFFFFF + 0), date_result=2460017)
    add("flag seconds past the low end", mode="stream", flag=1, carry=(0, -0xA8C000000000), date_result=2460017)
    low = 0xFFFEAE7FFFFEAE81 - 0xFFFF574000000000
    add("flag seconds at the checked lower limit", mode="stream", flag=1, carry=(0, low), date_result=2460019)
    add("flag seconds below the checked lower limit", mode="stream", flag=1, carry=(0, low - 1), date_result=2460019)
    return cases


def file_cases():
    cases = []
    for which in ("file", "stream", "batch"):
        def add(label, **world):
            data = dict(which=which, dir="base/node_raw_book_diffs", open=True, file_word=0x41, time=(2460100, 7300, 5), old_date=2460100, old_hour=2, hourly=1, flush=0, global_flush=0)
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


def line_cases():
    cases = []
    records = [
        ("new", dict(BASE_RECORD)),
        ("update", dict(BASE_RECORD, tag=1, first=2.5, second=0.125, user=USER_TWO, side=0)),
        ("remove", dict(BASE_RECORD, tag=2, coin="\x40107", oid=0)),
        ("whole numbers", dict(BASE_RECORD, tag=1, first=2.0, second=100.0, px=40000.0)),
        ("zero", dict(BASE_RECORD, tag=1, first=0.0, second=0.0, px=0.0)),
        ("small", dict(BASE_RECORD, first=0.00000001, px=0.0000000001)),
        ("below the digits", dict(BASE_RECORD, first=0.00000000001, px=0.00000000004)),
        ("rounding", dict(BASE_RECORD, first=0.12345678905, px=1.00000000005)),
        ("large", dict(BASE_RECORD, first=1234567890123.0, px=1e15)),
        ("coin quote", dict(BASE_RECORD, coin='a"b')),
        ("coin backslash", dict(BASE_RECORD, coin="a\\b")),
        ("empty coin", dict(BASE_RECORD, coin="")),
        ("long coin", dict(BASE_RECORD, coin="PURR/USDC" * 12)),
        ("big oid", dict(BASE_RECORD, oid=MAX64)),
    ]
    for label, record in records:
        cases.append(Case("file: " + label, "line", dict(line="file", records=[record])))
        cases.append(Case("stream: " + label, "line", dict(line="stream", records=[record], number=123456, local=LOCAL, block=STAMP)))
    cases.append(Case("file: minus zero", "line", dict(line="file", records=[dict(BASE_RECORD, tag=1, first=-0.0, second=-1e-11, px=-0.0)])))
    for name, size in (("file", 0x80), ("stream", 0x100), ("batch", 0x100)):
        for length in range(0, 0x60):
            world = dict(line=name, records=[dict(BASE_RECORD, tag=2, coin="C" * length)], number=7, local=LOCAL, block=STAMP)
            if len(spec_line(world)) - 1 == size:
                cases.append(Case("%s: line fills the buffer exactly" % name, "line", world))
    for count in (0, 1, 2, 3, 7):
        cases.append(Case("batch: %d records" % count, "line", dict(line="batch", records=[records[index % 4][1] for index in range(count)], number=999, local=LOCAL, block=STAMP)))
    return cases


def all_cases():
    return writer_cases() + sink_cases() + buffer_cases() + file_cases() + line_cases()
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


SPOT_ARM = ((0x4854950, 0x4854A3F), (0x4854C6D, 0x4854F67))
PERP_ARM = ((0x4855361, 0x485543C), (0x4855644, 0x4855815))
GROUPS = tuple((writer.start, "%s row writer, 0x%x rows" % (writer.kind, 0), None) for writer in WRITERS if writer.start not in NAMED_ELSEWHERE) + (
    (BUFFER, "output mode switch", None), (FILE_WRITER, "rotating file, one record per line", None), (STREAM_WRITER, "rotating file, streaming line", None), (BATCH_WRITER, "rotating file, batch line", None),
    (FILE_LINE, "one record line", None), (STREAM_LINE, "streaming line", None), (BATCH_LINE, "batch line", None), (RECORD_JSON, "record serializer", None), (DIFF_JSON, "raw_book_diff value", None),
    (DIFF_KEY, "raw_book_diff key wrapper", None), (DIFF_FIELD, "raw_book_diff field", None), (STREAM_JSON, "streaming serializer", None), (BATCH_JSON, "batch serializer", None), (ONE_EVENT, "events field, one record", None),
    (ALL_EVENTS, "events field, all records", None), (FLOAT_VALUE, "f64 as a string", None), (FLOAT_TRIM, "trailing zero trim", None), (FLOAT_FIELD, "f64 field", None),
    (PERP_SINK, "perp sink, row kind 2 arm only", PERP_ARM), (SPOT_SINK, "spot sink, row kind 2 arm only", SPOT_ARM))
EXTRA_FUNCTIONS = ((0x42E85C0, "new row writer, the 0x268 copy: address named in #47, run with no mutants", None), (0x42E8BF0, "remove row writer, the 0x268 copy: address named in #47, run with no mutants", None))


def group_rows(image, begin, end, ranges):
    """Whole body, or only the listed arms of a sink: the rest of a sink is the fill path."""
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


def row_tag_pattern(writer):
    if writer.kind == "new":
        return b"\x48\xc7\x44\x24\x08\x00\x00\x00\x00", b"\x48\xc7\x04\x24\x02\x00\x00\x00"
    if writer.kind == "update":
        return b"\x48\xc7\x44\x24\x10\x01\x00\x00\x00", b"\x48\xc7\x44\x24\x08\x02\x00\x00\x00"
    return b"\x48\xc7\x84\x24\x28\x01\x00\x00\x02\x00\x00\x00", b"\x48\xc7\x84\x24\x20\x01\x00\x00\x02\x00\x00\x00"


def writer_rows(image):
    """One line per row writer, every number from the bytes of its FDE range."""
    found = direct_sites(image, [writer.start for writer in WRITERS])
    rows = []
    for writer in WRITERS:
        begin, end = image.exact_fde(writer.start)
        data = code(image, begin, end - begin)
        tag, word = row_tag_pattern(writer)
        if data.count(tag) != 1 or data.count(word) != 1:
            raise EvidenceError("row words at %#x" % begin)
        width = row_width(image, begin)
        grow = {0x268: SLOT_GROW_268, 0x278: SLOT_GROW_278}[width]
        callers = sorted({image.fde(site)[0] for site, opcode in found[writer.start] if opcode == 0xE8})
        rows.append({"kind": writer.kind, "start": "%#x" % begin, "end": "%#x" % end, "size": end - begin, "row_bytes": width, "grow_slot": "%#x" % grow, "call_sites": len(found[writer.start]),
                     "caller_functions": ["%#x" % caller for caller in callers], "scope": "listed only, named in #47" if begin in NAMED_ELSEWHERE else "mutated"})
    return rows


def row_scan(image):
    """Functions in .text with a stack row head: word 2 stored, with the oid and side stores of the same row within 0x90 bytes, and a row sized copy."""
    base, text = image.text_bytes()
    found = set()
    for head, wide in ((b"\x48\xc7\x44\x24", False), (b"\x48\xc7\x84\x24", True), (b"\x48\xc7\x04\x24", None)):
        at = text.find(head)
        while at >= 0:
            if wide is None:
                disp, tail = 0, at + 4
            elif wide:
                disp, tail = struct.unpack_from("<i", text, at + 4)[0], at + 8
            else:
                disp, tail = text[at + 4], at + 5
            if text[tail:tail + 4] == b"\x02\x00\x00\x00" and 0 <= disp < 0x1000:
                window = text[max(0, at - 0x90):at + 0x40]
                marks = [bytes([0x24, offset]) if offset < 0x80 else b"\x24" + struct.pack("<i", offset) for offset in (disp + 0x30, disp + 0x4C)]
                if all(mark in window for mark in marks):
                    begin, end = image.fde(base + at)
                    body = text[begin - base:end - base]
                    if b"\xba\x68\x02\x00\x00" in body or b"\xba\x78\x02\x00\x00" in body:
                        found.add(begin)
            at = text.find(head, at + 1)
    return sorted(found)


def copy_diff(image):
    """Copies of one kind differ only in rip displacements, rel32 calls and the width words."""
    rows = []
    for kind in ("new", "update", "remove"):
        group = [writer for writer in WRITERS if writer.kind == kind]
        first = group[0]
        begin, end = image.exact_fde(first.start)
        base = decode_range(image, begin, end)
        for other in group[1:]:
            low, high = image.exact_fde(other.start)
            rows_other = decode_range(image, low, high)
            same = len(rows_other) == len(base) and all(a.op == b.op and a.size == b.size for a, b in zip(base, rows_other))
            rows.append({"kind": kind, "first": "%#x" % first.start, "other": "%#x" % other.start, "size": high - low, "same_instruction_shape": same})
    return rows


def sink_rows(image):
    rows = []
    for start, table in SINK_TABLES:
        arms = []
        for index in range(8):
            arm = table + struct.unpack_from("<i", image.blob, image.offset(table) + index * 4)[0]
            arms.append({"index": index, "row_kind": index + 2, "arm": "%#x" % arm})
        rows.append({"sink": "%#x" % start, "table": "%#x" % table, "arms": arms})
    if rows[0]["arms"][0]["arm"] != "0x4854950" or rows[1]["arms"][0]["arm"] != "0x4855361":
        raise EvidenceError("kind 2 arm moved")
    return rows


def flush_rows(image):
    """The flush reaches the sink at known sites; kind 2 copies 0x48 bytes and sets the head back to 2."""
    arm = 0x6EED68 + struct.unpack_from("<i", image.blob, image.offset(0x6EED68))[0]
    if arm != 0x432A234:
        raise EvidenceError("flush arm moved")
    require(image, arm + 0x36, b"\x48\xc7\x84\x24\xb0\x00\x00\x00\x02\x00\x00\x00", "flush head")
    found = direct_sites(image, [SPOT_SINK, PERP_SINK, CONSTRUCTOR])
    out = {"table": "0x6eed68", "kind_2_arm": "%#x" % arm, "sites": []}
    for target in (SPOT_SINK, PERP_SINK):
        for site, opcode in found[target]:
            out["sites"].append({"sink": "%#x" % target, "site": "%#x" % site, "host": "%#x" % image.fde(site)[0]})
    return out


KEY_SITES = (
    (RECORD_JSON, 0x47EF668, 0x40, "user", 4), (RECORD_JSON, 0x47EF696, 0x30, "oid", 3), (RECORD_JSON, 0x47EF6C4, 0x18, "coin", 4), (RECORD_JSON, 0x47EF6EE, 0x54, "side", 4), (RECORD_JSON, 0x47EF714, 0x38, "px", 2),
    (DIFF_KEY, 0x48653C8, 0x00, "raw_book_diff", 13), (DIFF_JSON, 0x47EE926, None, "remove", 6), (DIFF_JSON, 0x47EE8D7, None, "new", 3), (DIFF_JSON, 0x47EE8A7, None, "update", 6),
    (DIFF_JSON, 0x47EE9FD, 0x08, "sz", 2), (DIFF_JSON, 0x47EE985, 0x08, "origSz", 6), (DIFF_JSON, 0x47EE9B3, 0x10, "newSz", 5),
    (STREAM_JSON, 0x47F04F8, 0x60, "local_time", 10), (STREAM_JSON, 0x47F0522, 0x6C, "block_time", 10), (STREAM_JSON, 0x47F0548, 0x58, "block_number", 12), (STREAM_JSON, 0x47F056A, 0x00, "events", 6),
)


def key_rows(image):
    rows = []
    for function, site, field, text, size in KEY_SITES:
        target = lea_target(image, site)
        if text_at(image, target, size) != text:
            raise EvidenceError("key text at %#x" % site)
        rows.append({"function": "%#x" % function, "lea": "%#x" % site, "key": text, "record_offset": None if field is None else "%#x" % field})
    return rows


def ascii_preview(image, va, count):
    data = bytes(image.blob[image.offset(va):image.offset(va) + count])
    return "".join(chr(value) if 0x20 <= value < 0x7F else "\\x%02x" % value for value in data)


CONSTRUCTOR_BYTES = (
    (0x47F15C3, b"\x44\x0f\xb6\x76\x03", "write flag byte: r14b = config +3"),
    (0x47F192A, b"\x45\x84\xf6", "raw_book_diffs block runs only if that byte is set"),
    (0x47F1933, b"\x48\x8d\x05", "lea of the name node_raw_book_diffs"),
    (0x47F1D98, b"\x48\x8d\xbc\x24\x80\x10\x00\x00", "finished buffer goes to stack slot +0x1080"),
    (0x47F29C8, b"\x48\x8d\xbc\x24\x10\x08\x00\x00", "slot +0x1080 is copied to +0x810"),
    (0x47F29D0, b"\x48\x8d\xb4\x24\x80\x10\x00\x00", "source of that copy"),
    (0x47F2B32, b"\x48\x8d\xbb\x20\x04\x00\x00", "+0x680 block goes to object +0x420, so +0x810 is object +0x5b0"),
    (0x47F2B39, b"\x48\x8d\xb4\x24\x80\x06\x00\x00", "source of the block"),
    (0x47F2B41, b"\xba\x40\x06\x00\x00", "0x640 bytes, eight buffers of 0xc8"),
    (0x4857C58, b"\x48\x8d\xbb\xb0\x05\x00\x00", "block end drain passes object +0x5b0"),
    (0x4857CBB, b"\xe8", "and calls the batch file writer"),
    (0x4857B58, b"\x44\x0f\xb6\xb3\x78\x0a\x00\x00", "drain reads the same +0xa78 clock flag"),
)


def constructor_rows(image):
    rows = []
    for va, data, meaning in CONSTRUCTOR_BYTES:
        require(image, va, data, meaning)
        rows.append({"va": "%#x" % va, "bytes": data.hex(), "meaning": meaning})
    if lea_target(image, 0x47F1933) != 0x6FD952 or text_at(image, 0x6FD952, 19) != "node_raw_book_diffs":
        raise EvidenceError("buffer name")
    if 0x4857CBB + 5 + struct.unpack_from("<i", image.blob, image.offset(0x4857CBC))[0] != BATCH_WRITER:
        raise EvidenceError("drain target")
    return rows


TEXT_ROWS = (
    ("by block suffix template", 0x1FC51B, 12), ("streaming suffix template", 0x1F1364, 13), ("hourly path template", HOURLY_TEMPLATE, 15), ("daily path template", DAILY_TEMPLATE, 5), ("float template", FLOAT_TEMPLATE, 9),
    ("coin template", PACK_TEMPLATE, 4), ("both options panic", 0x6FD9CA, 57), ("fixed coin", PURR_TEXT, 9),
)
FLOAT_PRECISION = 10


def text_rows(image):
    require(image, FLOAT_TEMPLATE, b"\xc5\x20\x00\x00\x70\x0a\x00\x00", "float template")
    require(image, CHAR_AT, b"\x40\x00\x00\x00", "char at")
    require(image, CHAR_HASH, b"\x23\x00\x00\x00", "char hash")
    return [{"what": what, "va": "%#x" % va, "text": ascii_preview(image, va, size)} for what, va, size in TEXT_ROWS]


def powers_rows(image):
    """The f64 powers of ten behind both sinks."""
    return [{"index": index, "value": to_float(struct.unpack_from("<Q", image.blob, image.offset(POWERS) + index * 8)[0])} for index in range(9)]


def outcome_name(case, spec):
    if case.kind == "writer":
        return "%s: %d rows" % (case.world["what"], len(spec["rows"]))
    if case.kind == "line":
        return "line: " + case.world["line"]
    if case.kind == "file":
        return "file: " + spec["path"]
    return "%s: %s" % (case.kind, spec["path"])


def case_line(case, spec):
    return "%s\t%s\t%s" % (case.kind, case.label.replace(": ", "\t", 1), outcome_name(case, spec))


def sample_lines():
    """Three lines printed by the real serializer bytes, one per raw_book_diff shape."""
    harness = Harness(load_image())
    lines = []
    for label, record in (("new", dict(BASE_RECORD)), ("update", dict(BASE_RECORD, tag=1, first=2.5, second=0.125, user=USER_TWO, side=0)), ("remove", dict(BASE_RECORD, tag=2, coin="\x40107"))):
        lines.append(harness.run(Case("file: " + label, "line", dict(line="file", records=[record]))))
    lines.append(harness.run(Case("batch: two", "line", dict(line="batch", records=[dict(BASE_RECORD), dict(BASE_RECORD, tag=2)], number=999, local=LOCAL, block=STAMP))))
    return lines


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
    for start, role, ranges in GROUPS + EXTRA_FUNCTIONS:
        begin, end = image.exact_fde(start)
        rows = group_rows(image, begin, end, ranges)
        functions.append({"role": role.replace("0x0 rows", "0x%x rows" % harness.widths.get(start, 0)), "start": "%#x" % begin, "end": "%#x" % end, "size": end - begin, "instructions": len(rows), "instructions_stepped": sum(1 for row_ in rows if row_.va in seen)})
    writers = writer_rows(image)
    results_rows = run_mutants(image, reached, verbose) if full else []
    tally = {key: sum(1 for row_ in results_rows if row_["result"] == key) for key in ("killed", "survived", "unreached")}
    return {
        "target": {"file": "artifacts/node/94/hl-node", "sha256": SHA256},
        "functions": functions,
        "row_writers": writers,
        "row_scan": ["%#x" % start for start in row_scan(image)],
        "copy_shapes": copy_diff(image),
        "sinks": sink_rows(image),
        "flush": flush_rows(image),
        "json_keys": key_rows(image),
        "constructor": constructor_rows(image),
        "texts": text_rows(image),
        "powers_of_ten": powers_rows(image),
        "float_digits": FLOAT_PRECISION,
        "samples": sample_lines(),
        "cases": {"total": len(cases)},
        "outcomes": dict(sorted(outcomes.items())),
        "mismatches": len(mismatches),
        "first_mismatch": mismatches[0] if mismatches else "",
        "instructions_stepped": steps,
        "mutations": tally,
        "_results": results_rows, "_lines": lines,
    }


SURVIVED_DEFAULT = "no reason recorded"
_DEAD_ZERO = "dead store: the word set to 0 after the recorder call is overwritten at the shared store a few instructions later"
_HOURLY = "the store of 1 sits in the arm where the byte is already 1, and the bytes at the mutated offset are rewritten by the last-time store"
_CAP = "the capacity of this buffer is never 0 here, so the free is always taken"
_STATE_ERROR = "the byte is set only by a serializer error arm and no run fails, so the mutated compare takes the same way"
_NEVER_FIRST = "this key is never the first of its object, so the first-key byte is 2 in every run and is only ever compared with 1"
_STATE = "the state byte is only ever compared with 1, so 2 and 3 act alike"
REASONS_BY_VA = (
    (_DEAD_ZERO, (0x49E4FF5, 0x49E4EB5, 0x232E675, 0x232E7B5)),
    (_HOURLY, (0x47029E5, 0x47014E5, 0x47038E5)),
    (_CAP, (0x45B4E4A, 0x45BA3FA, 0x45B1A7A, 0x4C28046, 0x37E547A)),
    (_STATE_ERROR, (0x47EE8C2, 0x47EE8F2, 0x47EE979, 0x47EE9F5, 0x47EEA1F)),
    ("after the fields this byte is 2, so a compare with 0 or 1 is the same not-equal", (0x47EEA2F,)),
    (_NEVER_FIRST, (0x4A98DAB, 0x4A7B22B, 0x4A7FC1B)),
    (_STATE, (0x4A98DD0, 0x4A7B250, 0x4A7FC40, 0x4A7A4A0)),
    ("the text is ASCII digits, so the multi-byte arm stays dead and the sign test on a compare with 1 gives the same result", (0x37E5377,)),
    ("the text always has at least 12 bytes, so length 2 or 3 never decides", (0x37E5396,)),
    ("only 2^64 - 1e8 itself tells this limit apart, and 10 * id + side ends in digit 0 or 1 while that number ends in 6", (0x4854A22,)),
    ("in this arm the word is at or above 2^64 - 1e8, so adding 1e8 or 1e8 + 1 both carry and saturate", (0x4854A2F,)),
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
    files = {"evidence.json": (json.dumps(evidence, indent=2, sort_keys=True) + "\n").replace("\x40", "[at]")}
    writers = evidence["row_writers"]
    lines = ["kind\tstart\tend\tsize\trow_bytes\tgrow_slot\tcall_sites\tcallers\tscope"]
    lines += ["\t".join((row_["kind"], row_["start"], row_["end"], str(row_["size"]), "%#x" % row_["row_bytes"], row_["grow_slot"], str(row_["call_sites"]), ",".join(row_["caller_functions"]), row_["scope"])) for row_ in writers]
    files["row_writers.tsv"] = "\n".join(lines) + "\n"
    files["cases.tsv"] = "\n".join(["kind\tcopy\tlabel\toutcome"] + [line.replace("\x40", "[at]") for line in case_lines]) + "\n"
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
