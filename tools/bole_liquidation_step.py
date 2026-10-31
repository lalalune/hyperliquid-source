#!/usr/bin/env python3
"""Pin the node #94 apply_bole_liquidations block step from ELF bytes: bucket gate, token refresh, debt flag and user sweep.

The three copies of the bucket gate, step body and user sweep, the token refresh 0x373b060, the interest index writer 0x3740990,
the median 0x359ca70, the row collector 0x3739ef0 and 0x3733d70, and the B-tree range helpers run in a Python evaluator. A separately
written specification predicts every stub argument, token row and state word, and every condition, immediate and field offset is
flipped to show the run can tell. No objdump or readelf output is parsed, and the binary is never executed. Standard library only.
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

REFRESH = 0x373B060
ACCRUE = 0x3740990
MEDIAN = 0x359CA70
COLLECT = 0x3739EF0
COLLECT_ROWS = 0x3733D70
TREE_STEP = 0x2FE1C20
SCALE = 0x37400C0
DROP_ERR = 0x3762510
DROP_RESULT = 0x3379490
MAP_INSERT = 0x3395AA0
MAP_NEXT = 0x33B0F60
CLOCK = 0x4EE3800
UDIV = 0x565F5A0
OVERFLOW_LOG = 0x358DCD0
PUSH_PX = 0x32D5780
PUSH_ERR = 0x4F51BB0
PUSH_ROW = 0x32D57F0
PUSH_USER = 0x32D64A0
PANIC_NONE = 0x157A9F0
PANIC_INDEX = 0x157B520
PANIC_BOUND = 0x157B64F
PANIC_UNWRAP = 0x157AA10
ONCE_CALL = 0x4EE3B20
SLOT_REFRESH = 0x5773A80
SLOT_ACCRUE = 0x5775110
SLOT_ROWS = 0x5773180
SLOT_ALLOC = 0x576DFD8
SLOT_FREE = 0x576E010
SLOT_MEMCMP = 0x576E488
SLOT_MEMCPY = 0x576DFE0
ONCE_WORD = 0x5786380
DEFAULT_USER = 0x5786350
SYSTEM_BYTES = 0x204560
COPIES = (
    dict(name="primary", caller=0x22297C0, step=0x222CAF0, sweep=0x26FDF20, liq=0x2739D70, second=0x2765600, health=0x28DB540, user=0x272DE40,
         range_a=0x1B25830, range_b=0x1B255A0, mode=0x8F2, dex_rows=0x5C0, budget=0x3A68, flag=0x3ACC),
    dict(name="second", caller=0x470E9A0, step=0x4714080, sweep=0x4CE64C0, liq=0x4D4A3A0, second=0x4D96AD0, health=0x48CFB90, user=0x46ED7D0,
         range_a=0x42BA570, range_b=0x42BA2E0, mode=0x8F2, dex_rows=0x5C0, budget=0x3A68, flag=0x3ACC),
    dict(name="recording", caller=0x47162D0, step=0x47121B0, sweep=0x4CE6DB0, liq=0x4D4A260, second=0x4D98480, health=0x48CFB90, user=0x46EBCA0,
         range_a=0x42BA570, range_b=0x42BA2E0, mode=0x1372, dex_rows=0x1040, budget=0x44E8, flag=0x454C),
)
BY_NAME = {copy["name"]: copy for copy in COPIES}
BOLE = 0x498
USERS = 0x598
SPOT_MAP = 0x250
SPOT_INFO = 0x80
HEALTH_A = 0x560
HEALTH_B = 0x90
CAP = 0x590
DIRECT_GATE = 0x5B3
DEBT_FLAG = 0x5B4
BUCKET = 0x4D8
LAST_BUCKET = 0x4E0
STEP_NAME = b"apply_bole_liquidations"
GATE_HEAD = b"\x48\x8b\x4c\x24\x18\x8b\x11\x8b\x41\x04\x8b\x49\x08"
E14 = 10 ** 14
YEAR_MS = 31557600000
OK_TAG = 0x11
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
MUTANT_STEP_LIMIT = 120000
OUT = HEAP_BASE + 0x100
EXCHANGE = HEAP_BASE + 0x1000
DEX_ROW = HEAP_BASE + 0x6000
BUMP = HEAP_BASE + 0x8000
MAP_NODE = 0x7300000


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
        elif byte not in (0x2E, 0xF0):
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
        if two == 0xB0:
            reg, rm = modrm()
            return finish("cmpxchg", rm, ("r", reg), 1)
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
        self.jump_ranges = ()
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
            if not any(low <= target < high for low, high in self.jump_ranges):
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


def wide(value, factor):
    """128 by 64 multiply as the code does it: low words widen, the high word multiplies and wraps."""
    return (value & MASK[8]) * factor + (((value >> 64) * factor & MASK[8]) << 64) & ((1 << 128) - 1)


def scaled(value, factor):
    """value * factor / 1e14 with the guard that the quotient fits 64 bits; None when the guard fires."""
    product = wide(value, factor)
    return None if product >> 64 > E14 - 1 else product // E14


def rate_of(row, u):
    low, high, bend, k = row["min"], row["max"], row["bend"], row["k"]
    if u == k:
        return bend
    if u < k:
        f = u * E14 // k
        if bend < low or f >> 64:
            return bend
        part = scaled(f, bend - low)
        if part is None or low + part >> 64:
            return bend
        return low + part
    if k > E14 - 1:
        return high
    f = (u - k) * E14 // (E14 + 0 - k)
    if high < bend or f >> 64:
        return high
    part = scaled(f, high - bend)
    if part is None or bend + part >> 64:
        return high
    return bend + part


def settle(row, logs):
    moved = min(row["pending"], row["balance"])
    row["balance"] -= moved
    row["pending"] -= moved
    total = row["paid"] + moved
    if total >> 64:
        logs.append("paid")
    row["paid"] = min(total, MASK[8])


def accrue_spec(before, now, keep):
    """Interest index writer: returns the row after the call and the overflow log rows."""
    row, logs = dict(before), []
    if row["time"] == now:
        settle(row, logs)
        return row, logs
    a, ia, b, ib = row["a"], row["ia"], row["b"], row["ib"]
    product = a * ia
    borrowed = (product + E14 - 1) // E14
    if (b * ib) >> 64 > E14 - 1:
        return row, logs
    supplied = (b * ib) // E14
    if borrowed >> 64:
        return row, logs
    u = 0
    if supplied:
        u = borrowed * E14 // supplied
        if u >> 64:
            return row, logs
        u = min(u, E14)
    rate = rate_of(row, u)
    now_ms = max(unix_millis(*now), 0)
    last_ms = unix_millis(*row["time"])
    if last_ms > now_ms:
        return row, logs
    elapsed = now_ms - max(last_ms, 0)
    if elapsed > YEAR_MS:
        return row, logs
    grown = scaled(elapsed * rate // YEAR_MS, ia)
    if grown is None:
        return row, logs
    share = 0
    if b:
        share = a * E14 // b
        if share >> 64:
            return row, logs
    supply = scaled(grown, share)
    if supply is None:
        return row, logs
    fee = scaled(supply, keep)
    if fee is None:
        return row, logs
    tokens = scaled(fee, b)
    if tokens is None:
        return row, logs
    if (supply & MASK[8]) < (fee & MASK[8]):
        return row, logs
    next_ia = ia + (grown & MASK[8])
    next_ib = ib + ((supply & MASK[8]) - (fee & MASK[8]))
    if next_ia >> 64 or next_ib >> 64:
        return row, logs
    row["time"] = now
    total = row["pending"] + (tokens & MASK[8])
    if total >> 64:
        logs.append("pending")
    row["pending"] = min(total, MASK[8])
    row["ib"], row["ia"] = next_ib, next_ia
    settle(row, logs)
    return row, logs


def perp_of(mode, key):
    """Returns a perp index, "skip" for a token that needs no perp, or None for missing."""
    if mode == 0:
        return 0 if key == 3 else None
    if mode == 2:
        if key in (0x59B, 0x5DF, 0x607, 0x608):
            return "skip"
        return {1: 0x7D, 0x451: 0x87}.get(key)
    if mode == 3:
        if key == 0x168:
            return "skip"
        return {0x96: 0x9F, 0xC5: 0}.get(key)
    return None


def scale_value(case, x0, x1):
    if to_bits(x0) in case.get("zero", ()):
        return 0
    return int(x0 * x1 * 1000.0) & MASK[8]


def median_of(values):
    ordered = sorted(values)
    size = len(ordered)
    if size == 0:
        return 0
    if size & 1:
        return ordered[size // 2]
    low, high = ordered[size // 2 - 1], ordered[size // 2]
    return (low & high) + ((low ^ high) >> 1)


def refresh_spec(case):
    """Token refresh: rows after the call, scale calls, drop tags, error lists and the panic if any."""
    mode, native = case["mode"], case["native"]
    rows, calls, errors, drops, logs = {}, [], [], [], []
    panic = None
    for key in sorted(case["tokens"]):
        row, logged = accrue_spec(case["tokens"][key], case["time"], case["keep"])
        logs += logged
        rows[key] = row
        if key == 0:
            continue
        px, errs = [], []
        if key in case["spot"]:
            px.append(case["spot"][key])
        else:
            errs.append("spot px")
        perp = perp_of(mode, key)
        if perp is None:
            errs.append("missing perp")
        elif perp != "skip":
            if case["dex_id"] == 0 and perp < case["count"]:
                entry = case["perps"].get(perp)
                if entry is None:
                    panic = "bound"
                    break
                if entry["decimals"] > 6:
                    panic = "index"
                    break
                native_here = key == native and case["native_flag"]
                divisor = 10.0 ** (6 - entry["decimals"])
                mark = float(entry["mark"]) / divisor
                x1 = 1.0 if native_here else case["x48"]
                calls.append((key, to_bits(mark), to_bits(x1)))
                value = scale_value(case, mark, x1)
                if value:
                    px.append(value)
                else:
                    errs.append("mark px")
                if native_here:
                    calls.append((native, to_bits(case["xc8"]), to_bits(case["x48"])))
                    value = scale_value(case, case["xc8"], case["x48"])
                    if value:
                        px.append(value)
                    else:
                        errs.append("native oracle px")
                else:
                    oracle = float(entry["oracle"]) / divisor
                    calls.append((key, to_bits(oracle), to_bits(case["x48"])))
                    value = scale_value(case, oracle, case["x48"])
                    if value:
                        px.append(value)
                    else:
                        errs.append("oracle px")
            else:
                drops.append(0x60)
                errs.append("missing perp")
        if len(px) != 3:
            allowed = mode >= 2 and len(px) == 1 and (key in (0x5DF, 0x607, 0x608, 0x59B) if mode == 2 else key == 0x168)
            if not allowed:
                errs.append("unexpected length")
        px.sort()
        if mode != 2 and px and float(px[-1]) / float(px[0]) > 1.01:
            errs.append("unexpected range")
        med = median_of(px)
        if med == 0:
            errs.append("missing median")
        else:
            low, high = row["low"], row["high"]
            if low and float(med) / float(low) - 1.0 < 0.0:
                med = low
            if high and float(med) / float(high) - 1.0 > 0.0:
                med = high
            row["px"] = med
        if errs:
            errors.append((key, errs))
    return dict(rows=rows, calls=calls, errors=errors, drops=drops, logs=logs, panic=panic)


def debt_flag(flag, cap, low, high):
    """The flag kept at exchange +0x5b4: set past the cap, cleared at or under 80 percent of it."""
    gap = low - high
    if gap <= 0:
        return 0
    if gap > cap:
        return 1
    return flag if gap > int(float(cap) * 0.8) else 0


def step_spec(case, layout):
    if case.get("flag", 1) != 1:
        return dict(ran=False)
    if case["dexes"] == 0:
        return dict(ran=True, panic="unwrap", calls=[], halt=case["halt"], debt=case["debt"], rows=None)
    system = bytes([0xBB] * 20)
    calls = [("drop", 0x141)]
    refreshed = refresh_spec(case)
    halt = case["halt"]
    calls.append(("liq", case["liq"] and 0, system))
    if case["liq"] != OK_TAG:
        halt = 0
    calls.append(("second",))
    if case["second"] != OK_TAG:
        halt = 0
    if case.get("once"):
        calls.append(("once",))
    calls.append(("health", "user" if system in case["users"] else "default"))
    report = case["report"]
    debt = case["debt"]
    if report[0]:
        halt = 0
    else:
        if report[1] >> 63 or report[2] >> 63 or case["cap"] >> 63:
            return dict(ran=True, panic="unwrap", calls=calls, halt=halt, debt=debt, rows=refreshed["rows"])
        debt = debt_flag(debt, case["cap"], report[1], report[2])
    return dict(ran=True, panic=None, calls=calls, halt=halt, debt=debt, rows=refreshed["rows"])


def sweep_spec(case):
    budget = case["budget"]
    users = sorted(case["users"])
    start = case["cursor"]
    cursor = start
    used = start is not None
    seen = []
    if budget:
        mark = start if start is not None else bytes(20)
        order = [u for u in users if u > mark] + [u for u in users if u <= mark]
        seen = order[:budget]
    if seen:
        cursor = seen[-1]
        used = True
    picked = [u for u in seen if any(row[0] for row in case["users"][u].values())]
    return dict(picked=picked, cursor=cursor, used=used)


def collect_spec(case):
    system = bytes([0xBB] * 20)
    rows = []
    for key, (word_a, word_b) in sorted(case["users"].get(system, {}).items()):
        token = case["tokens"].get(key)
        if token is None:
            return dict(code=9)
        high = (word_a * token["ia"] + E14 - 1) // E14
        if high >> 64 or (word_b * token["ib"]) >> 64 > E14 - 1:
            return dict(code=3)
        rows.append((key, high, word_b * token["ib"] // E14))
    return dict(rows=rows)


# ---- harness ----

TOKEN_TREE = dict(leaf=0x7F8, inner=0x858, parent=0x790, slot=0x7F0, length=0x7F2, keys=0x798, stride=8, edges=0x7F8, values=0xB0)
USER_TREE = dict(leaf=0x2F8, inner=0x358, parent=0x210, slot=0x2F4, length=0x2F6, keys=0x218, stride=20, edges=0x2F8, values=0x30)
ENTRY_TREE = dict(leaf=0x1C8, inner=0x228, parent=0x160, slot=0x1C0, length=0x1C2, keys=0x168, stride=8, edges=0x1C8, values=0x20)
SPOT_TREE = dict(leaf=0xC0, inner=0x120, parent=None, slot=None, length=0xBA, keys=8, stride=8, edges=0xC0, values=8, value_base=0x60)
CAPACITY = 11


def tree_height(count):
    level, room = 0, CAPACITY
    while room < count:
        level += 1
        room = room * (CAPACITY + 1) + CAPACITY
    return level


def build_tree(memory, bump, shape, items, put):
    """B-tree over sorted (key bytes, value) items; returns the root and its height. put(address, value) fills one value slot."""
    if not items:
        return 0, 0
    base = shape.get("value_base", 0)

    def make(rows, level, parent, slot):
        node = bump(shape["inner"] if level else shape["leaf"])
        if shape["parent"] is not None:
            memory.write(node + shape["parent"], 8, parent)
            memory.write(node + shape["slot"], 2, slot)
        room = CAPACITY
        for _ in range(level - 1):
            room = room * (CAPACITY + 1) + CAPACITY
        if level == 0:
            entries, children = rows, []
        else:
            parts = 2
            while (len(rows) - (parts - 1)) > parts * room:
                parts += 1
            size = (len(rows) - (parts - 1)) // parts
            extra = (len(rows) - (parts - 1)) - size * parts
            at, entries, children = 0, [], []
            for index in range(parts):
                take = size + (1 if index < extra else 0)
                children.append(rows[at:at + take])
                at += take
                if index + 1 < parts:
                    entries.append(rows[at])
                    at += 1
        memory.write(node + shape["length"], 2, len(entries))
        for index, (key, value) in enumerate(entries):
            memory.put_bytes(node + shape["keys"] + shape["stride"] * index, key)
            put(node + base + shape["values"] * index, value)
        for index, part in enumerate(children):
            memory.write(node + shape["edges"] + 8 * index, 8, make(part, level - 1, node, index))
        return node

    height = tree_height(len(items))
    return make(items, height, 0, 0), height


def word_key(value):
    return struct.pack("<Q", value)


class Harness:
    def __init__(self, image):
        self.image = image
        machine = self.machine = Machine(image)
        real = {REFRESH, ACCRUE, MEDIAN, COLLECT, COLLECT_ROWS, TREE_STEP}
        for copy in COPIES:
            real.update((copy["step"], copy["sweep"], copy["range_a"], copy["range_b"]))
        machine.real = frozenset(real)
        self.real_ranges = [image.exact_fde(start) for start in real]
        machine.jump_ranges = self.real_ranges
        calls = {CLOCK: self.on_clock, DROP_RESULT: self.on_drop_result, DROP_ERR: self.on_drop_err, SCALE: self.on_scale, MAP_INSERT: self.on_insert, MAP_NEXT: self.on_next}
        for copy in COPIES:
            calls[copy["liq"]] = self.on_liq
            calls[copy["second"]] = self.on_second
            calls[copy["health"]] = self.on_health
            calls[copy["user"]] = self.on_user
        machine.calls = calls
        hooks = {UDIV: self.on_div, OVERFLOW_LOG: self.on_log, PUSH_PX: self.on_push(8), PUSH_ROW: self.on_push(0x18), PUSH_USER: self.on_push(20), PUSH_ERR: self.on_push(16),
                 PANIC_NONE: self.on_panic("none"), PANIC_INDEX: self.on_panic("index"), PANIC_BOUND: self.on_panic("bound"), PANIC_UNWRAP: self.on_panic("unwrap"), ONCE_CALL: self.on_once}
        tokens = {}
        for at, (target, hook) in enumerate(hooks.items()):
            token = 0x7000000 + at * 16
            tokens[target] = token
            machine.slots[token] = hook
        for slot, target in relative_slots(image).items():
            if target in tokens:
                machine.memory.statics[slot] = tokens[target]
        for at, (slot, hook) in enumerate(((SLOT_ALLOC, self.on_alloc), (SLOT_FREE, self.on_free), (SLOT_MEMCMP, self.on_memcmp), (SLOT_MEMCPY, self.on_memcpy))):
            token = 0x7100000 + at * 16
            machine.memory.statics[slot] = token
            machine.slots[token] = hook
        for slot, target in ((SLOT_REFRESH, REFRESH), (SLOT_ACCRUE, ACCRUE), (SLOT_ROWS, COLLECT_ROWS)):
            machine.memory.statics[slot] = target
        machine.memory.statics[DEFAULT_USER + 0x18] = 0
        machine.memory.statics[DEFAULT_USER + 0x28] = 0
        self.case = None
        self.layout = COPIES[0]
        self.at = BUMP
        self.calls = []
        self.scales = []
        self.drops = []
        self.inserted = []
        self.logs = []
        self.frees = []
        self.picked = []
        self.pending_nodes = []
        self.clock = 0
        self.row_at = {}
        self.user_at = {}
        self.gate = None

    def bump(self, size):
        here = self.at
        self.at += (size + 15) & ~15
        if self.at >= HEAP_BASE + HEAP_SIZE:
            raise Halt("heap exhausted")
        return here

    def begin(self, case, layout):
        memory = self.machine.memory
        memory.reset()
        self.case, self.layout = case, layout
        self.at = BUMP
        self.calls, self.scales, self.drops, self.inserted, self.logs, self.frees, self.picked, self.pending_nodes = [], [], [], [], [], [], [], []
        self.clock = 0
        memory.statics[ONCE_WORD] = 1 if case.get("once") else 0

    # edge hooks

    def on_alloc(self, machine):
        machine.regs[RAX] = self.bump(machine.regs[RDI])

    def on_free(self, machine):
        self.frees.append(machine.regs[RSI])

    def on_memcmp(self, machine):
        regs, memory = machine.regs, machine.memory
        left = memory.bytes_at(regs[RDI], regs[RDX])
        right = memory.bytes_at(regs[RSI], regs[RDX])
        regs[RAX] = 0 if left == right else (1 if left > right else MASK[4])

    def on_memcpy(self, machine):
        regs = machine.regs
        if regs[RDX]:
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

    def on_drop_result(self, machine):
        self.calls.append(("drop", machine.memory.read(machine.regs[RDI], 2)))

    def on_drop_err(self, machine):
        self.drops.append(machine.memory.read(machine.regs[RDI], 2))

    def on_scale(self, machine):
        regs = machine.regs
        if regs[RSI] != EXCHANGE + SPOT_INFO + 0x10:
            raise Halt("scale table argument")
        x0, x1 = machine.xmm[0] & MASK[8], machine.xmm[1] & MASK[8]
        self.scales.append((regs[RDI], x0, x1))
        regs[RAX] = scale_value(self.case, to_float(x0), to_float(x1))

    def on_insert(self, machine):
        regs, memory = machine.regs, machine.memory
        vector = regs[RCX]
        data, used = memory.read(vector + 8, 8), memory.read(vector + 16, 8)
        words = []
        for index in range(used):
            pointer, size = memory.read(data + 16 * index, 8), memory.read(data + 16 * index + 8, 8)
            words.append(memory.bytes_at(pointer, size).decode())
        self.inserted.append((regs[RDX], words))
        target = regs[RSI]
        count = memory.read(target + 16, 8)
        node = self.bump(0x80)
        memory.write(node + 0x60, 8, memory.read(vector, 8))
        memory.write(node + 0x68, 8, data)
        self.pending_nodes.append(node)
        memory.write(target, 8, MAP_NODE)
        memory.write(target + 8, 8, 0)
        memory.write(target + 16, 8, count + 1)
        memory.write(regs[RDI], 8, 1 << 63)

    def on_next(self, machine):
        regs, memory = machine.regs, machine.memory
        out = regs[RDI]
        if self.pending_nodes:
            memory.write(out, 8, self.pending_nodes.pop(0))
            memory.write(out + 16, 8, 0)
        else:
            memory.write(out, 8, 0)

    def on_liq(self, machine):
        regs, memory = machine.regs, machine.memory
        if regs[RDI] != EXCHANGE:
            raise Halt("liquidation exchange")
        self.calls.append(("liq", 0, memory.bytes_at(regs[RSI], 20)))
        regs[RAX] = self.case["liq"]

    def on_second(self, machine):
        regs = machine.regs
        if regs[RDI] != EXCHANGE:
            raise Halt("sweep exchange")
        self.calls.append(("second",))
        regs[RAX] = self.case["second"]

    def on_health(self, machine):
        regs, memory = machine.regs, machine.memory
        if (regs[RDX], regs[RCX], regs[R8]) != (EXCHANGE + HEALTH_A, EXCHANGE + HEALTH_B, 0):
            raise Halt("health arguments")
        wanted = self.user_at.get(bytes([0xBB] * 20))
        if regs[RSI] == DEFAULT_USER and wanted is None:
            self.calls.append(("health", "default"))
        elif regs[RSI] == wanted:
            self.calls.append(("health", "user"))
        else:
            raise Halt("health user")
        report = self.case["report"]
        memory.write(regs[RDI], 1, report[0])
        memory.write(regs[RDI] + 8, 8, report[1])
        memory.write(regs[RDI] + 16, 8, report[2])

    def on_user(self, machine):
        regs, memory = machine.regs, machine.memory
        if (regs[RSI], regs[RCX] & MASK[4], regs[R8] & MASK[4]) != (EXCHANGE, 0, 1):
            raise Halt("user sweep arguments")
        user = memory.bytes_at(regs[RDX], 20)
        self.picked.append(user)
        memory.write(regs[RDI], 8, self.case.get("user_word", 1 << 63))
        memory.write(regs[RDI] + 8, 8, 0x4440)

    def on_div(self, machine):
        regs = machine.regs
        dividend = regs[RDI] | regs[RSI] << 64
        divisor = regs[RDX] | regs[RCX] << 64
        if divisor == 0:
            raise Halt("division by zero in the wide divide")
        quotient = dividend // divisor
        regs[RAX] = quotient & MASK[8]
        regs[RDX] = quotient >> 64
        machine.keep_rdx = True

    def on_log(self, machine):
        self.logs.append(machine.regs[RSI])

    def on_push(self, element):
        def push(machine):
            regs, memory = machine.regs, machine.memory
            vector = regs[RDI]
            capacity, data = memory.read(vector, 8), memory.read(vector + 8, 8)
            wider = max(4, capacity * 2)
            fresh = self.bump(element * wider)
            if capacity:
                memory.copy(fresh, data, element * capacity)
            memory.write(vector, 8, wider)
            memory.write(vector + 8, 8, fresh)
        return push

    def on_panic(self, name):
        def panic(machine):
            raise Panicked(name)
        return panic

    def on_once(self, machine):
        self.calls.append(("once",))

    def on_gate_step(self, machine):
        regs, memory = machine.regs, machine.memory
        step = regs[RDI]
        self.gate = dict(name=memory.bytes_at(memory.read(step, 8), memory.read(step + 8, 8)), low=memory.read(step + 16, 8), high=memory.read(step + 24, 8),
                         run=memory.read(step + 32, 1), exchange=regs[RSI])
        raise Finished()

    # fixtures

    def put_row(self, at, row):
        memory = self.machine.memory
        for offset, name in ((0x10, "px"), (0x18, "balance"), (0x20, "paid"), (0x28, "pending"), (0x30, "low"), (0x38, "high"), (0x40, "a"), (0x58, "ia"), (0x60, "b"), (0x78, "ib"),
                             (0x80, "min"), (0x88, "max"), (0x90, "bend"), (0x98, "k")):
            memory.write(at + offset, 8, row[name])
        memory.put_bytes(at + 0xA0, struct.pack("<III", *row["time"]))

    def read_row(self, at):
        memory = self.machine.memory
        row = {}
        for offset, name in ((0x10, "px"), (0x18, "balance"), (0x20, "paid"), (0x28, "pending"), (0x30, "low"), (0x38, "high"), (0x40, "a"), (0x58, "ia"), (0x60, "b"), (0x78, "ib"),
                             (0x80, "min"), (0x88, "max"), (0x90, "bend"), (0x98, "k")):
            row[name] = memory.read(at + offset, 8)
        row["time"] = struct.unpack("<III", memory.bytes_at(at + 0xA0, 12))
        return row

    def lay_tokens(self, tokens):
        memory = self.machine.memory
        self.row_at = {}
        spots = {}

        def put(at, key):
            self.put_row(at, tokens[key])
            spots[key] = at
        root, height = build_tree(memory, self.bump, TOKEN_TREE, [(word_key(key), key) for key in sorted(tokens)], put)
        memory.write(EXCHANGE + BOLE + 0xD0, 8, root)
        memory.write(EXCHANGE + BOLE + 0xD8, 8, height)
        memory.write(EXCHANGE + BOLE + 0xE0, 8, len(tokens))
        self.row_at = spots

    def lay_entries(self, at, entries):
        memory = self.machine.memory

        def put(where, value):
            memory.write(where + 8, 8, value[0])
            memory.write(where + 0x18, 8, value[1])
        root, height = build_tree(memory, self.bump, ENTRY_TREE, [(word_key(key), entries[key]) for key in sorted(entries)], put)
        memory.write(at + 0x18, 8, root)
        memory.write(at + 0x20, 8, height)
        memory.write(at + 0x28, 8, len(entries))

    def lay_users(self, users):
        memory = self.machine.memory
        self.user_at = {}

        def put(where, user):
            self.lay_entries(where, users[user])
            self.user_at[user] = where
        root, height = build_tree(memory, self.bump, USER_TREE, [(user, user) for user in sorted(users)], put)
        memory.write(EXCHANGE + USERS, 8, root)
        memory.write(EXCHANGE + USERS + 8, 8, height)
        memory.write(EXCHANGE + USERS + 16, 8, len(users))

    def lay_refresh(self, case, layout):
        memory = self.machine.memory
        memory.write(EXCHANGE + BOLE + 0xC8, 8, case["keep"])
        memory.write(EXCHANGE + BOLE + 0xE8, 8, to_bits(case["x48"]))
        memory.write(EXCHANGE + BOLE + 0xF0, 8, to_bits(case["xc8"]))
        self.lay_tokens(case["tokens"])
        root, height = build_tree(memory, self.bump, SPOT_TREE, [(word_key(key), value) for key, value in sorted(case["spot"].items())], lambda at, value: memory.write(at, 8, value))
        memory.write(EXCHANGE + SPOT_MAP, 8, root)
        memory.write(EXCHANGE + SPOT_MAP + 8, 8, height)
        memory.write(EXCHANGE + SPOT_INFO, 1, 1 if case["native_flag"] else 0)
        memory.write(EXCHANGE + SPOT_INFO + 8, 8, case["native"])
        perps = case["perps"]
        size = max(perps, default=-1) + 1
        meta, table = self.bump(0x30 * max(size, 1)), self.bump(0x60 * max(size, 1))
        for index, entry in perps.items():
            memory.write(meta + 0x30 * index + 0x2A, 1, entry["decimals"])
            memory.write(table + 0x60 * index + 0x20, 8, entry["mark"])
            memory.write(table + 0x60 * index, 8, entry["oracle"])
        memory.write(DEX_ROW + 8, 8, meta)
        memory.write(DEX_ROW + 0x10, 8, case["count"])
        memory.write(DEX_ROW + 0x30, 8, case["dex_id"])
        memory.write(DEX_ROW + 0x68, 8, table)
        memory.write(DEX_ROW + 0x70, 8, size)
        memory.put_bytes(EXCHANGE + 0x60, struct.pack("<III", *case["time"]))
        memory.write(EXCHANGE + layout["mode"], 1, case["mode"])
        memory.write(EXCHANGE + layout["dex_rows"], 8, DEX_ROW)
        memory.write(EXCHANGE + layout["dex_rows"] + 8, 8, case.get("dexes", 1))

    # runs

    def run_gate(self, case, layout):
        machine, memory = self.machine, self.machine.memory
        self.begin(case, layout)
        time_at = self.bump(16)
        memory.put_bytes(time_at, struct.pack("<III", *case["time"]))
        memory.write(EXCHANGE + BUCKET, 8, case["bucket_millis"])
        memory.write(EXCHANGE + LAST_BUCKET, 8, case["last_bucket"])
        memory.write(STACK_TOP - 0x100, 8, EXCHANGE)
        memory.write(STACK_TOP - 0xF0, 8, time_at)
        self.gate = None
        saved, real = machine.calls, machine.real
        machine.calls = dict(saved)
        machine.calls[layout["step"]] = self.on_gate_step
        machine.real = frozenset(real - {layout["step"]})
        try:
            machine.run(layout["gate"], {R15: EXCHANGE})
        except Finished:
            pass
        finally:
            machine.calls, machine.real = saved, real
        return self.gate, memory.read(EXCHANGE + LAST_BUCKET, 8)

    def run_accrue(self, case):
        machine, memory = self.machine, self.machine.memory
        self.begin(case, COPIES[0])
        at = self.bump(0xB0)
        self.put_row(at, case["row"])
        time_at = self.bump(16)
        memory.put_bytes(time_at, struct.pack("<III", *case["time"]))
        machine.run(ACCRUE, {RDI: at, RSI: time_at, RDX: case["keep"]})
        return self.read_row(at)

    def run_refresh(self, case):
        machine = self.machine
        self.begin(case, COPIES[0])
        self.lay_refresh(case, COPIES[0])
        machine.run(REFRESH, {RDI: EXCHANGE + BOLE, RSI: case["mode"], RDX: EXCHANGE + 0x60, RCX: EXCHANGE + SPOT_MAP, R8: EXCHANGE + SPOT_INFO, R9: DEX_ROW})
        return {key: self.read_row(at) for key, at in self.row_at.items()}

    def run_median(self, case):
        machine, memory = self.machine, self.machine.memory
        self.begin(case, COPIES[0])
        data = self.bump(8 * max(len(case["values"]), 1))
        for index, value in enumerate(case["values"]):
            memory.write(data + 8 * index, 8, value)
        return machine.run(MEDIAN, {RDI: data, RSI: len(case["values"])})

    def run_step(self, case, layout):
        machine, memory = self.machine, self.machine.memory
        self.begin(case, layout)
        self.lay_refresh(case, layout)
        self.lay_users(case["users"])
        memory.write(EXCHANGE + CAP, 8, case["cap"])
        memory.write(EXCHANGE + DIRECT_GATE, 1, case["halt"])
        memory.write(EXCHANGE + DEBT_FLAG, 1, case["debt"])
        step = self.bump(0x28)
        memory.write(step + 0x20, 1, case.get("flag", 1))
        try:
            machine.run(layout["step"], {RDI: step, RSI: EXCHANGE})
        except Finished:
            pass

    def run_sweep(self, case, layout):
        machine, memory = self.machine, self.machine.memory
        self.begin(case, layout)
        self.lay_users(case["users"])
        memory.write(EXCHANGE + layout["budget"], 8, case["budget"])
        memory.write(EXCHANGE + layout["flag"], 1, 0 if case["cursor"] is None else 1)
        memory.put_bytes(EXCHANGE + layout["flag"] + 1, case["cursor"] or FILLER)
        machine.run(layout["sweep"], {RDI: EXCHANGE})
        return memory.read(EXCHANGE + layout["flag"], 1), memory.bytes_at(EXCHANGE + layout["flag"] + 1, 20)

    def run_collect(self, case):
        machine, memory = self.machine, self.machine.memory
        self.begin(case, COPIES[0])
        self.lay_tokens(case["tokens"])
        self.lay_users(case["users"])
        machine.run(COLLECT, {RDI: OUT, RSI: EXCHANGE + BOLE})
        return memory.read(OUT, 8), memory.read(OUT + 8, 8), memory.read(OUT + 16, 8)


def layout_gates(image):
    """Find each bucket gate in front of its direct step call."""
    base, text = image.text_bytes()
    for layout in COPIES:
        begin, end = image.exact_fde(layout["caller"])
        at = text.find(b"\xe8", begin - base)
        site = None
        while 0 <= at < end - base:
            if base + at + 5 + struct.unpack_from("<i", text, at + 1)[0] == layout["step"]:
                site = base + at
                break
            at = text.find(b"\xe8", at + 1)
        if site is None:
            raise EvidenceError("step call not found")
        window = text[site - base - 0x180:site - base]
        start = window.rfind(GATE_HEAD)
        if start < 0:
            raise EvidenceError("gate head not found")
        layout["gate"] = site - 0x180 + start
        layout["gate_end"] = site + 5


# ---- cases ----

FILLER = address(25)

NOW = (2024 << 13 | 200 << 4 | 2, 3600, 5000000)
AGO = (2024 << 13 | 199 << 4 | 2, 3600, 5000000)


def shift_day(time, days):
    return ((time[0] & ~(0x1FF << 4)) | ((time[0] >> 4 & 0x1FF) - days) << 4, time[1], time[2])


def token(time=AGO, **fields):
    row = dict(px=7, balance=0, paid=0, pending=0, low=0, high=0, a=10 ** 8, ia=E14, b=2 * 10 ** 8, ib=E14, min=E14 // 100, max=E14 // 2, bend=E14 // 10, k=8 * E14 // 10, time=time)
    row.update(fields)
    return row


def accrue_cases():
    rows = []
    year_ago = (2023 << 13 | 200 << 4 | 2, 3600, 5000000)
    for label, row, now, keep in (
        ("same time settles only", token(NOW, balance=100, pending=30, paid=5), NOW, E14 // 10),
        ("same time, pending above balance", token(NOW, balance=20, pending=30), NOW, 0),
        ("same time, nothing pending", token(NOW, balance=20), NOW, 0),
        ("one day below the bend", token(), NOW, E14 // 10),
        ("one day, reserve share zero", token(), NOW, 0),
        ("one day, reserve share full", token(), NOW, E14),
        ("one day, reserve share above full returns", token(), NOW, 2 * E14),
        ("date differs, seconds equal", token((NOW[0] - (1 << 4), NOW[1], NOW[2])), NOW, 0),
        ("seconds differ, date equal", token((NOW[0], NOW[1] - 60, NOW[2])), NOW, 0),
        ("frac differs by one nanosecond", token((NOW[0], NOW[1], NOW[2] - 1)), NOW, 0),
        ("frac differs below a millisecond keeps a zero span", token((NOW[0], NOW[1], NOW[2] - 1)), NOW, E14 // 10),
        ("at the bend exactly", token(a=8 * 10 ** 7, b=10 ** 8), NOW, 0),
        ("above the bend", token(a=9 * 10 ** 7, b=10 ** 8), NOW, E14 // 5),
        ("full use", token(a=10 ** 8, b=10 ** 8), NOW, E14 // 5),
        ("use above full clamps", token(a=3 * 10 ** 8, b=10 ** 8), NOW, 0),
        ("bend at zero", token(k=0, a=10 ** 7, b=10 ** 8), NOW, 0),
        ("bend at full, low arm", token(k=E14, a=10 ** 7, b=10 ** 8), NOW, 0),
        ("bend above full, high arm unreachable", token(k=2 * E14, a=10 ** 8, b=10 ** 8), NOW, 0),
        ("bend rate below the low rate", token(bend=E14 // 1000), NOW, 0),
        ("top rate below the bend rate", token(a=9 * 10 ** 7, b=10 ** 8, max=E14 // 1000), NOW, 0),
        ("nothing supplied, nothing borrowed", token(a=0, b=0), NOW, E14 // 10),
        ("nothing supplied, something borrowed", token(b=0), NOW, E14 // 10),
        ("nothing borrowed", token(a=0), NOW, E14 // 10),
        ("borrow total reaches 2^64", token(a=1 << 62, ia=8 * E14), NOW, 0),
        ("supply product past the 2^64 guard", token(b=1 << 63, ib=4 * E14), NOW, 0),
        ("ratio past 2^64 with small supply", token(a=184468, ia=E14, b=1, ib=E14), NOW, 0),
        ("ratio at the cut", token(a=184467, ia=E14, b=1, ib=E14), NOW, 0),
        ("clock behind the row", token((NOW[0] + (1 << 4), NOW[1], NOW[2])), NOW, 0),
        ("exactly one year", token(year_ago), (2024 << 13 | 200 << 4 | 2, 25200, 5000000), 0),
        ("one millisecond past a year", token(year_ago), (2024 << 13 | 200 << 4 | 2, 25200, 6000000), 0),
        ("365 days is inside the year", token(year_ago), (2024 << 13 | 200 << 4 | 2, 3600, 6000000), 0),
        ("row time zero word", token((0, 0, 0)), NOW, 0),
        ("row time before the epoch, inside a year", token((1969 << 13 | 365 << 4, 0, 0)), (1970 << 13 | 10 << 4, 0, 0), 0),
        ("clock before the epoch", token((1960 << 13 | 2 << 4, 0, 0)), (1960 << 13 | 3 << 4, 0, 0), 0),
        ("row year below one", token(((-5 << 13) & MASK[4] | 1 << 4, 0, 0)), NOW, 0),
        ("clock year below one", token(((-5 << 13) & MASK[4] | 1 << 4, 0, 0)), ((-5 << 13) & MASK[4] | 2 << 4, 0, 0), 0),
        ("index product past the guard", token(ia=1 << 63, min=1 << 62, bend=1 << 63, max=(1 << 64) - 1, a=10 ** 4, b=10 ** 5, k=E14 // 2), NOW, 0),
        ("share past 2^64", token(a=1 << 60, ia=1, b=1, ib=1 << 50), NOW, 0),
        ("supply guard fires", token(a=1 << 40, b=1 << 8, ib=E14, ia=E14 * 1000, max=E14, bend=E14, min=E14), NOW, 0),
        ("fee guard fires", token(a=1 << 30, b=1 << 30, min=(1 << 62), bend=(1 << 63), max=(1 << 63), ia=1 << 58), NOW, E14),
        ("token guard fires", token(a=10 ** 10, b=1 << 62, ib=1, min=E14 * 1000, bend=E14 * 1000, max=E14 * 1000, ia=1 << 56), NOW, E14),
        ("borrow index wraps", token(ia=(1 << 64) - 1000), NOW, 0),
        ("supply index wraps", token(ib=(1 << 64) - 1, b=1), NOW, 0),
        ("pending add saturates", token(pending=(1 << 64) - 2, min=E14 * 100, bend=E14 * 100, max=E14 * 100), NOW, E14),
        ("paid add saturates", token(balance=50, pending=50, paid=(1 << 64) - 3), NOW, 0),
        ("paid add saturates at same time", token(NOW, balance=50, pending=50, paid=(1 << 64) - 3), NOW, 0),
        ("pending paid from balance after growth", token(balance=10 ** 9, pending=3, min=E14, bend=E14, max=E14), NOW, E14 // 2),
        ("high rate over small span rounds", token((NOW[0], NOW[1] - 1, NOW[2]), a=7, ia=3 * E14 + 1, b=13, ib=E14 + 7), NOW, 123456789),
        ("borrow ceil on an inexact product", token(a=3, ia=E14 // 7, b=10, ib=E14), NOW, 0),
        ("same time skips a guard that would fire", token(NOW, b=1 << 63, ib=4 * E14, balance=100, pending=30), NOW, 0),
        ("same date and seconds, frac word differs by a second", token((NOW[0], NOW[1], NOW[2] + 1000000000), balance=100, pending=30, b=1 << 63, ib=4 * E14), NOW, 0),
        ("same date and frac, seconds differ, guard fires", token((NOW[0], NOW[1] + 1, NOW[2]), balance=100, pending=30, b=1 << 63, ib=4 * E14), NOW, 0),
        ("large totals with an exact quotient", token(a=10 ** 15, b=2 * 10 ** 15), NOW, 0),
        ("clock on an odd day", token(), (NOW[0] | 1 << 4, NOW[1], NOW[2]), 0),
        ("row on an odd day", token((AGO[0] | 1 << 4, AGO[1], AGO[2])), (NOW[0] | 1 << 4, NOW[1], NOW[2]), 0),
        ("supply product at the top of the guard", token(a=1, b=1 << 63, ib=2 * (E14 - 1) + 1), NOW, 0),
        ("large fee token count", token(a=10 ** 18, b=10 ** 18, balance=7), NOW, E14),
        ("top rate above one", token(a=9 * 10 ** 7, b=10 ** 8, max=10 * E14, bend=E14 // 10), NOW, 0),
        ("bend rate above one", token(a=4 * 10 ** 7, b=10 ** 8, bend=10 * E14), NOW, 0),
        ("supply floor on an inexact product", token(a=3, b=10, ib=E14 // 7 + 1), NOW, 0),
    ):
        rows.append(dict(kind="accrue", label=label, row=row, time=now, keep=keep))
    return rows


def perp(mark=2000000, oracle=2000000, decimals=2):
    return dict(mark=mark, oracle=oracle, decimals=decimals)


def refresh_case(label, mode, tokens, spot, perps=None, **fields):
    case = dict(kind="refresh", label=label, mode=mode, tokens=tokens, spot=spot, perps=perps or {}, time=NOW, keep=E14 // 10, native=0x96, native_flag=True, x48=0.5, xc8=40.0, dex_id=0, count=256)
    case.update(fields)
    return case


def refresh_cases():
    zero_mark = to_bits(float(2000000) / 10000.0)
    rows = [
        refresh_case("no tokens", 3, {}, {}),
        refresh_case("token 0 accrues, no price", 3, {0: token()}, {}),
        refresh_case("mode 3, token 0xc5 three prices", 3, {0xC5: token()}, {0xC5: 99999000}, {0: perp()}, xc8=1.0),
        refresh_case("mode 3, native token", 3, {0x96: token()}, {0x96: 20000}, {0x9F: perp()}, x48=1.0, xc8=20.0, keep=0),
        refresh_case("mode 3, native flag clear", 3, {0x96: token()}, {0x96: 100000}, {0x9F: perp()}, native_flag=False, x48=1.0),
        refresh_case("mode 3, native id elsewhere", 3, {0x96: token()}, {0x96: 100000}, {0x9F: perp()}, native=0x97, x48=1.0),
        refresh_case("mode 3, token 0x168 spot only", 3, {0x168: token()}, {0x168: 1000}),
        refresh_case("mode 3, token 0x168 no spot", 3, {0x168: token()}, {}),
        refresh_case("mode 3, unknown token", 3, {0x200: token()}, {0x200: 1000}),
        refresh_case("mode 3, unknown token, no spot", 3, {0x200: token()}, {}),
        refresh_case("mode 2, token 1", 2, {1: token()}, {1: 100000}, {0x7D: perp()}, x48=1.0),
        refresh_case("mode 2, token 0x451", 2, {0x451: token()}, {0x451: 100000}, {0x87: perp()}, x48=1.0),
        refresh_case("mode 2, wide spread passes", 2, {1: token()}, {1: 900000}, {0x7D: perp()}, x48=1.0),
        refresh_case("mode 2, token 0x59b spot only", 2, {0x59B: token()}, {0x59B: 1000}),
        refresh_case("mode 2, token 0x5df spot only", 2, {0x5DF: token()}, {0x5DF: 1000}),
        refresh_case("mode 2, token 0x607 spot only", 2, {0x607: token()}, {0x607: 1000}),
        refresh_case("mode 2, token 0x608 spot only", 2, {0x608: token()}, {0x608: 1000}),
        refresh_case("mode 2, token 0x5e0 missing perp", 2, {0x5E0: token()}, {0x5E0: 1000}),
        refresh_case("mode 2, token 0x609 past the mask", 2, {0x609: token()}, {0x609: 1000}),
        refresh_case("mode 2, token 0x606 inside the mask", 2, {0x606: token()}, {0x606: 1000}),
        refresh_case("mode 2, token 0x5de just under", 2, {0x5DE: token()}, {0x5DE: 1000}),
        refresh_case("mode 2, skip token without spot", 2, {0x59B: token()}, {}),
        refresh_case("mode 0, token 3", 0, {3: token()}, {3: 100000}, {0: perp()}, x48=1.0),
        refresh_case("mode 0, token 4", 0, {4: token()}, {4: 100000}),
        refresh_case("mode 1, any token", 1, {3: token()}, {3: 100000}, {0: perp()}),
        refresh_case("mode 1, token 0x168", 1, {0x168: token()}, {0x168: 100000}),
        refresh_case("mode 0, token 0x168", 0, {0x168: token()}, {0x168: 100000}),
        refresh_case("dex id nonzero", 3, {0xC5: token()}, {0xC5: 100000}, {0: perp()}, dex_id=1),
        refresh_case("perp past the count", 3, {0x96: token()}, {0x96: 100000}, {0x9F: perp()}, count=0x9F),
        refresh_case("perp at the last count", 3, {0x96: token()}, {0x96: 100000}, {0x9F: perp()}, count=0xA0, x48=1.0),
        refresh_case("perp past the price table", 3, {0x96: token()}, {0x96: 100000}, {0: perp()}),
        refresh_case("decimals 7 panic", 3, {0xC5: token()}, {0xC5: 100000}, {0: perp(decimals=7)}),
        refresh_case("decimals 0", 3, {0xC5: token()}, {0xC5: 100000}, {0: perp(decimals=0)}, x48=1.0),
        refresh_case("decimals 6", 3, {0xC5: token()}, {0xC5: 100000}, {0: perp(decimals=6)}, x48=1.0),
        refresh_case("mark scales to zero", 3, {0xC5: token()}, {0xC5: 100000}, {0: perp()}, zero=(zero_mark,), x48=1.0),
        refresh_case("oracle scales to zero", 3, {0xC5: token()}, {0xC5: 100000}, {0: perp(oracle=3000000)}, zero=(to_bits(300.0),), x48=1.0),
        refresh_case("native oracle scales to zero", 3, {0x96: token()}, {0x96: 200000}, {0x9F: perp()}, zero=(to_bits(40.0),), x48=1.0),
        refresh_case("mark and oracle zero leaves one price", 3, {0xC5: token()}, {0xC5: 100000}, {0: perp()}, zero=(zero_mark,), x48=1.0),
        refresh_case("no price at all", 3, {0xC5: token()}, {}, {0: perp()}, zero=(zero_mark,), x48=1.0),
        refresh_case("two prices average", 3, {0xC5: token()}, {}, {0: perp(oracle=2000020)}, x48=1.0),
        refresh_case("two prices, order reversed", 3, {0xC5: token()}, {}, {0: perp(mark=2000020, oracle=2000000)}, x48=1.0),
        refresh_case("two prices, reversed and wide", 3, {0xC5: token()}, {}, {0: perp(mark=3000000, oracle=2000000)}, x48=1.0),
        refresh_case("three prices, reversed and wide", 3, {0xC5: token()}, {0xC5: 300000}, {0: perp(mark=2500000, oracle=2000000)}, x48=1.0),
        refresh_case("three prices, top within 1 percent", 3, {0xC5: token()}, {0xC5: 202000}, {0: perp()}, x48=1.0),
        refresh_case("three prices, top past 1 percent", 3, {0xC5: token()}, {0xC5: 202001}, {0: perp()}, x48=1.0),
        refresh_case("range error still writes the price", 3, {0xC5: token()}, {0xC5: 900000}, {0: perp()}, x48=1.0),
        refresh_case("spot lowest, sort moves two", 3, {0xC5: token()}, {0xC5: 199000}, {0: perp(mark=2000000, oracle=2010000)}, x48=1.0),
        refresh_case("spot middle", 3, {0xC5: token()}, {0xC5: 200500}, {0: perp(mark=2000000, oracle=2010000)}, x48=1.0),
        refresh_case("spot highest, oracle lowest", 3, {0xC5: token()}, {0xC5: 201500}, {0: perp(mark=2010000, oracle=2000000)}, x48=1.0),
        refresh_case("clamp to the lower band", 3, {0xC5: token(low=300000)}, {0xC5: 200000}, {0: perp()}, x48=1.0),
        refresh_case("clamp to the upper band", 3, {0xC5: token(high=100000)}, {0xC5: 200000}, {0: perp()}, x48=1.0),
        refresh_case("band above and below keeps the median", 3, {0xC5: token(low=100000, high=300000)}, {0xC5: 200000}, {0: perp()}, x48=1.0),
        refresh_case("band equal to the median", 3, {0xC5: token(low=200000, high=200000)}, {0xC5: 200000}, {0: perp()}, x48=1.0),
        refresh_case("crossed band ends at the top", 3, {0xC5: token(low=300000, high=100000)}, {0xC5: 200000}, {0: perp()}, x48=1.0),
        refresh_case("float compare hides a one-off band", 3, {0x168: token(low=(1 << 60) + 1)}, {0x168: 1 << 60}),
        refresh_case("no median keeps the old price", 3, {0x168: token(px=55)}, {}),
        refresh_case("several tokens", 3, {0: token(), 0x96: token(), 0xC5: token(), 0x168: token()}, {0x96: 200000, 0xC5: 200000, 0x168: 1000}, {0: perp(), 0x9F: perp()}, x48=1.0, xc8=200.0),
        refresh_case("error tokens between good ones", 3, {0x10: token(), 0x168: token(), 0x170: token(), 0x171: token()}, {0x168: 1000}),
        refresh_case("token tree of two levels", 3, {key * 10: token() for key in range(1, 30)}, {}),
        refresh_case("token tree of three levels", 3, {key: token(balance=0) for key in range(2, 12)} | {key * 3: token() for key in range(4, 60)}, {}),
        refresh_case("spot tree of two levels", 3, {0x168: token()}, {key: key + 5 for key in range(0x160, 0x178)}),
        refresh_case("spot key on an inner node", 3, {0x168: token()}, {0x100 + key: key + 5 for key in (0x62, 0x68, 0x70, 0x72, 0x74, 0x76, 0x78, 0x7A, 0x7C, 0x7E, 0x80, 0x82)}),
        refresh_case("spot key absent past inner node", 3, {0x168: token()}, {key * 40: 5 for key in range(1, 30)}),
        refresh_case("accrual skipped, price still moves", 3, {0x168: token(b=1 << 63, ib=4 * E14)}, {0x168: 1000}),
    ]
    return rows


def median_cases():
    return [dict(kind="median", label=label, values=values) for label, values in (
        ("empty", []), ("one", [5]), ("two", [5, 9]), ("two, odd sum floors", [5, 8]), ("two near the top", [(1 << 64) - 1, (1 << 64) - 3]),
        ("three sorted", [1, 2, 3]), ("three reversed", [3, 2, 1]), ("four", [4, 1, 3, 2]), ("five", [5, 1, 4, 2, 3]), ("six with repeats", [2, 2, 9, 1, 1, 9]), ("twenty", [(n * 7) % 20 for n in range(20)]),
    )]


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
        ("wide bucket takes the 64-bit divide", base, 1 << 33, 0),
        ("small clock takes the 32-bit divide", (1970 << 13 | 1 << 4, 30, 0), 1000, 3),
        ("small clock at the guard", (1970 << 13 | 1 << 4, 3, 0), 1000, 3),
        ("before the epoch clamps to zero", (1969 << 13 | 1 << 4, 0, 0), hour, 0),
        ("frac of exactly one millisecond", (base[0], 0, 1000000), 1, 0),
        ("clock just past 32 bits", (1970 << 13 | 51 << 4, 0, 0), 1000, 0),
        ("year after a century", (2001 << 13 | 1 << 4, 0, 0), hour, 0),
        ("year after a plain century", (2101 << 13 | 1 << 4, 0, 0), hour, 0),
        ("year -1 takes the 400-year shift", ((-1 << 13) & MASK[4] | 1 << 4, 0, 0), hour, 0),
        ("zero width with a 32-bit clock", (1970 << 13 | 1 << 4, 5, 0), 0, 0),
        ("zero width with a 64-bit clock", base, 0, 0),
    ):
        for layout in COPIES:
            rows.append(dict(kind="gate", label=label, copy=layout["name"], time=time, bucket_millis=width, last_bucket=last))
    return rows


def step_cases():
    rows = []
    system = bytes([0xBB] * 20)
    other = address(1)
    for label, fields in (
        ("step flag clear", dict(flag=0)),
        ("step flag 2", dict(flag=2)),
        ("no dexes", dict(dexes=0)),
        ("all clear, no gap", dict()),
        ("liquidation pass failed clears the direct gate byte", dict(liq=3, halt=1)),
        ("second sweep failed clears the direct gate byte", dict(second=7, halt=1)),
        ("both passes fine keep the byte", dict(halt=1)),
        ("health error clears the byte", dict(report=(1, 0, 0), halt=1)),
        ("health error keeps the debt flag", dict(report=(1, 500, 0), debt=1, cap=100)),
        ("first report word negative", dict(report=(0, 1 << 63, 0))),
        ("second report word negative", dict(report=(0, 0, 1 << 63))),
        ("cap negative", dict(cap=1 << 63)),
        ("surplus clears", dict(report=(0, 100, 900), debt=1, cap=1000)),
        ("zero gap clears", dict(report=(0, 900, 900), debt=1, cap=1000)),
        ("gap past the cap sets", dict(report=(0, 2001, 1000), cap=1000)),
        ("gap at the cap, flag clear", dict(report=(0, 2000, 1000), cap=1000)),
        ("gap at the cap, flag set", dict(report=(0, 2000, 1000), cap=1000, debt=1)),
        ("gap above 80 percent keeps set", dict(report=(0, 1801, 1000), cap=1000, debt=1)),
        ("gap above 80 percent keeps clear", dict(report=(0, 1801, 1000), cap=1000)),
        ("gap at 80 percent clears", dict(report=(0, 1800, 1000), cap=1000, debt=1)),
        ("gap under 80 percent clears", dict(report=(0, 1700, 1000), cap=1000, debt=1)),
        ("cap zero, gap one sets", dict(report=(0, 1, 0), cap=0)),
        ("large cap truncates", dict(report=(0, 7378697629483820646, 0), cap=(1 << 63) - 1, debt=1)),
        ("system user holds a row", dict(users={system: {}, address(1, 0xCC): {}})),
        ("token with a perp in the step", dict(tokens={0xC5: token()}, spot={0xC5: 100000}, perps={0: perp()}, x48=1.0, keep=0)),
        ("user tree without the system user", dict(users={other: {}})),
        ("user tree of two levels", dict(users={address(n): {} for n in range(16)} | {system: {}})),
        ("key above the system user", dict(users={address(1, 0xCC): {}, address(1, 0x10): {}})),
        ("process once word set", dict(once=True)),
        ("token row accrues in the step", dict(tokens={0: token()}, spot={})),
        ("token price refreshes in the step", dict(tokens={0x168: token()}, spot={0x168: 1000})),
    ):
        case = dict(kind="step", label=label, mode=3, tokens={}, spot={}, perps={}, time=NOW, keep=E14 // 10, native=0x96, native_flag=True, x48=0.5, xc8=40.0, dex_id=0, count=256,
                    users={}, cap=1000, halt=0, debt=0, liq=OK_TAG, second=OK_TAG, report=(0, 0, 0), dexes=1)
        case.update(fields)
        for layout in COPIES:
            rows.append(dict(case, copy=layout["name"]))
    return rows


def debtor(*words):
    return {index: (word, 3) for index, word in enumerate(words)}


def sweep_cases():
    a, b, c, d, e = (address(n) for n in (10, 20, 30, 40, 50))
    plain = {a: debtor(1), b: debtor(0), c: debtor(0, 5), d: {}, e: debtor(9)}
    many = {address(n * 2): debtor(n % 2) for n in range(30)}
    deep = {address(n): debtor(*([0] * 12 + [1])) for n in range(4)}
    wide_map = {a: {n: (0, 1) for n in range(40)} | {50: (7, 0)}, b: {n: (0, 1) for n in range(40)}}
    rows = []
    for label, users, budget, cursor, fields in (
        ("zero budget", plain, 0, None, {}),
        ("no users", {}, 5, None, {}),
        ("no users, cursor set", {}, 5, b, {}),
        ("no cursor, budget covers all", plain, 9, None, {}),
        ("no cursor, budget of one", plain, 1, None, {}),
        ("no cursor, budget of two", plain, 2, None, {}),
        ("cursor on a user", plain, 2, b, {}),
        ("cursor between users", plain, 2, address(25), {}),
        ("cursor at the last user wraps", plain, 2, e, {}),
        ("cursor past the last user wraps", plain, 2, address(60), {}),
        ("cursor before the first user", plain, 2, address(5), {}),
        ("budget wraps back to the cursor", plain, 9, c, {}),
        ("budget stops one before the cursor", plain, 4, c, {}),
        ("budget stops exactly at the cursor", plain, 5, c, {}),
        ("cursor at the first user", plain, 9, a, {}),
        ("zero address user with no cursor", {bytes(20): debtor(1), a: debtor(1)}, 9, None, {}),
        ("only a user at the cursor", {b: debtor(1)}, 3, b, {}),
        ("visited without debt still moves the cursor", {a: debtor(0), b: debtor(0)}, 1, None, {}),
        ("two level user tree", many, 7, address(31), {}),
        ("two level user tree wraps", many, 40, address(45), {}),
        ("cursor key on an inner node", many, 6, address(12), {}),
        ("cursor absent past an inner node", many, 6, address(13), {}),
        ("entry past a leaf end", deep, 9, None, {}),
        ("entries over two levels, late debt", wide_map, 9, None, {}),
        ("user result frees a vector", plain, 9, None, dict(user_word=3)),
        ("user result with an empty vector", plain, 9, None, dict(user_word=0)),
    ):
        for layout in COPIES:
            rows.append(dict(kind="sweep", label=label, copy=layout["name"], users=users, budget=budget, cursor=cursor, **fields))
    return rows


def collect_cases():
    system = bytes([0xBB] * 20)
    table = {0: token(), 1: token(ia=E14 + 3), 2: token(ib=E14 // 3), 300: token()}
    rows = []
    for label, users, tokens in (
        ("no system user", {address(1): {0: (1, 1)}}, table),
        ("system user without rows", {system: {}}, table),
        ("one row", {system: {0: (5, 7)}}, table),
        ("rows round up then down", {system: {1: (10 ** 6, 3), 2: (3, 10 ** 6)}}, table),
        ("row of zeros is kept", {system: {0: (0, 0)}}, table),
        ("token missing", {system: {5: (1, 1)}}, table),
        ("first word far above the divisor", {system: {0: (10 ** 16, 10 ** 16)}}, table),
        ("later token missing drops the rows", {system: {0: (1, 1), 5: (1, 1)}}, table),
        ("token table empty", {system: {5: (1, 1)}}, {}),
        ("token table empty, no rows", {system: {}}, {}),
        ("first word overflows", {system: {0: (1 << 64 - 1, 3)}}, {0: token(ia=1 << 63)}),
        ("first word ceil crosses 2^64", {system: {0: (MASK[8], 0)}}, {0: token(ia=E14 + 1)}),
        ("second word overflows", {system: {0: (0, 1 << 63)}}, {0: token(ib=1 << 63)}),
        ("second word at the guard", {system: {0: (0, 1 << 47)}}, {0: token(ib=(E14 << 17))}),
        ("second word just under the guard", {system: {0: (0, (1 << 47) - 1)}}, {0: token(ib=(E14 << 17))}),
        ("both overflow", {system: {0: (MASK[8], MASK[8])}}, {0: token(ia=MASK[8], ib=MASK[8])}),
        ("rows over two levels", {system: {key: (key, key) for key in range(1, 30)}}, {key: token() for key in range(1, 30)}),
        ("token on an inner node", {system: {key * 2: (1, 1) for key in range(1, 20)}}, {key: token() for key in range(1, 60)}),
        ("three levels of rows", {system: {key: (1, 1) for key in range(1, 40)}}, {key: token() for key in range(1, 40)}),
        ("process once word set", {system: {0: (5, 7)}}, table),
    ):
        rows.append(dict(kind="collect", label=label, users=users, tokens=tokens, once=label.startswith("process")))
    return rows


def all_cases():
    return gate_cases() + accrue_cases() + median_cases() + refresh_cases() + step_cases() + sweep_cases() + collect_cases()


# ---- comparison ----

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
        return "step never reached"
    if last != want["last"]:
        return "last bucket %d wanted %d" % (last, want["last"])
    if gate["run"] != int(want["run"]):
        return "run flag"
    if gate["name"] != STEP_NAME or gate["exchange"] != EXCHANGE:
        return "step arguments"
    if (gate["low"], gate["high"]) != (to_bits(0.01), to_bits(0.05)):
        return "step thresholds"
    return ""


def row_diff(got, want):
    for name in sorted(want):
        if got[name] != want[name]:
            return "%s %r wanted %r" % (name, got[name], want[name])
    return ""


def compare_accrue(harness, case):
    got = harness.run_accrue(case)
    want, logs = accrue_spec(case["row"], case["time"], case["keep"])
    if len(harness.logs) != len(logs):
        return "log rows %d wanted %d" % (len(harness.logs), len(logs))
    return row_diff(got, want)


def compare_refresh(harness, case):
    want = refresh_spec(case)
    panic = None
    rows = None
    try:
        rows = harness.run_refresh(case)
    except Panicked as stop:
        panic = stop.args[0]
    if panic != want["panic"]:
        return "panic %r wanted %r" % (panic, want["panic"])
    if harness.scales != want["calls"]:
        return "scale calls %r wanted %r" % (harness.scales[:4], want["calls"][:4])
    if harness.inserted != want["errors"]:
        return "errors %r wanted %r" % (harness.inserted[:3], want["errors"][:3])
    if [tag for tag in harness.drops if tag != 0x186] != want["drops"] or any(tag not in (0x186, 0x60) for tag in harness.drops):
        return "drop tags %r wanted %r" % (harness.drops[:4], want["drops"][:4])
    if panic:
        return ""
    if len(harness.logs) != len(want["logs"]):
        return "log rows"
    if set(rows) != set(want["rows"]):
        return "token set"
    for key, row in want["rows"].items():
        failed = row_diff(rows[key], row)
        if failed:
            return "token %d: %s" % (key, failed)
    if len(harness.pending_nodes) != 0:
        return "error map not drained"
    return ""


def compare_step(harness, case, layout):
    want = step_spec(case, layout)
    panic = None
    try:
        harness.run_step(case, layout)
    except Panicked as stop:
        panic = stop.args[0]
    memory = harness.machine.memory
    if not want["ran"]:
        if harness.calls or harness.clock:
            return "disabled step did work"
        return "" if harness.machine.regs[RAX] & 0xFF == case["flag"] else "disabled return"
    if panic != want["panic"]:
        return "panic %r wanted %r" % (panic, want["panic"])
    if harness.calls != [call if call[0] != "liq" else ("liq", 0, call[2]) for call in want["calls"]]:
        return "calls %r wanted %r" % (harness.calls[:6], want["calls"][:6])
    if memory.read(EXCHANGE + DIRECT_GATE, 1) != want["halt"]:
        return "direct gate byte"
    if memory.read(EXCHANGE + DEBT_FLAG, 1) != want["debt"]:
        return "debt flag"
    if want["rows"] is not None:
        for key, row in want["rows"].items():
            failed = row_diff(harness.read_row(harness.row_at[key]), row)
            if failed:
                return "token %d: %s" % (key, failed)
    return ""


def compare_sweep(harness, case, layout):
    want = sweep_spec(case)
    flag, cursor = harness.run_sweep(case, layout)
    if harness.picked != want["picked"]:
        return "users %d wanted %d" % (len(harness.picked), len(want["picked"]))
    if flag != int(want["used"]):
        return "cursor flag"
    wanted = want["cursor"] or FILLER
    if cursor != wanted:
        return "cursor %s wanted %s" % (cursor.hex()[-4:], wanted.hex()[-4:])
    expected = want["picked"] and case.get("user_word") == 3
    if expected and harness.frees.count(0x18) != len(want["picked"]):
        return "result frees"
    return ""


def compare_collect(harness, case):
    want = collect_spec(case)
    first, second, third = harness.run_collect(case)
    memory = harness.machine.memory
    if harness.machine.regs[RAX] != OUT:
        return "return pointer"
    if bool(case.get("once")) != (("once",) in harness.calls):
        return "once call"
    if "code" in want:
        if first != 1 << 63 or second & 0xFF != want["code"]:
            return "error %x %x wanted %d" % (first, second, want["code"])
        return ""
    if first == 1 << 63:
        return "unexpected error %d" % (second & 0xFF)
    if third != len(want["rows"]):
        return "row count %d wanted %d" % (third, len(want["rows"]))
    got = [tuple(memory.read(second + 0x18 * index + 8 * word, 8) for word in range(3)) for index in range(third)]
    return "" if got == want["rows"] else "rows %r wanted %r" % (got[:3], want["rows"][:3])


def compare_run(harness, case):
    try:
        layout = BY_NAME.get(case.get("copy"))
        kind = case["kind"]
        if kind == "gate":
            failed = compare_gate(harness, case, layout)
        elif kind == "accrue":
            failed = compare_accrue(harness, case)
        elif kind == "refresh":
            failed = compare_refresh(harness, case)
        elif kind == "median":
            got = harness.run_median(case)
            failed = "" if got == median_of(case["values"]) else "median %d" % got
        elif kind == "step":
            failed = compare_step(harness, case, layout)
        elif kind == "sweep":
            failed = compare_sweep(harness, case, layout)
        else:
            failed = compare_collect(harness, case)
    except Exception as stop:
        failed = "stopped: %r" % (stop,)
    return "%s %s/%s: %s" % (case["kind"], case["label"], case.get("copy", "shared"), failed) if failed else ""


def relative_slots(image):
    return {slot: addend for slot, kind, addend, _ in image.relocations() if kind == 8}


# ---- static evidence ----

ERROR_ROWS = ((0x373B4A0, b"spot px"), (0x373B800, b"mark px"), (0x373BC11, b"native oracle px"), (0x373BC3A, b"oracle px"), (0x373B72D, b"missing perp"),
              (0x373B948, b"unexpected length"), (0x373BA04, b"unexpected range"), (0x373BB93, b"missing median"))
LOCATION_ROWS = ((0x3740FC6, "paid word add overflow in the index writer"), (0x3740FE8, "pending word add overflow in the index writer"), (0x373BDB5, "szDecimals above 6"),
                 (0x373BDC4, "perp index past the price table"), (0x222D1F4, "report word does not fit i64"), (0x222D219, "cap word does not fit i64"))
FIELD_ROWS = ((0x275C133, 0x3A68, "budget, primary serializer"), (0x275C115, 0x3ACC, "cursor Option, primary serializer"), (0x4D86A2D, 0x44E8, "budget, recording serializer"),
              (0x4D86A03, 0x454C, "cursor Option, recording serializer"))
BUDGET_KEY_SITE = 0x275C13A
REASONS = (
    ("refresh", 0x373BC5E, 0x373BC7B, "sort call for 21 or more prices; a token holds at most 3"),
    ("refresh", 0x373BDD8, 0x373BE38, "unwind path"),
    ("median", 0x359CB5D, 0x359CB7C, "alloc failure or the sort call for 21 or more values"),
    ("median", 0x359CBB4, 0x359CBD5, "bound test on a position inside the vector, or an unwind path"),
    ("sweep", 0x0, 0x10000000, ""),
)
GROUP_REASONS = (
    ("gate", "arm for years below 1, which always clamps to 0, or its sign fix"),
    ("step", "free size or vector word read only by a stub, the shadowed infinity or range arms of the 0.8 cast (the input is a finite f64 below 2^63), a loop step that gives the same result over the keys built, or an unwind path"),
    ("refresh", "vector or map word read only by a stub, loop step or length read that gives the same result because the scan stops at the fill bytes, the unrolled walk for 8 or more levels, a bound repeated from an earlier row, the replaced-value arm of the map (tokens are unique), the mode 3 test after a failed perp (token 0x168 never gets there), the success tag word (never dropped), or a free path"),
    ("index writer", "exact edge of a 1e14 guard or divisor (one bit off needs a high word equal to 1e14 - 1 or a quotient past 1e14), a guard the operands cannot reach (a zero input with a nonzero total), or the arm for years below 1, whose date always clamps to 0"),
    ("median", "repeat of a bound or a free size read only by the stub"),
    ("collector", "loop step that gives the same result over the keys built, or the Once path text"),
    ("row collector", "free size read only by the stub, a shadowed arm for a zero word with a nonzero result, the unrolled walk for 8 or more levels, or the empty table walk that always ends at code 9"),
    ("sweep", "free size or vector word read only by a stub, the unrolled walk for 8 or more levels, an empty-range arm, or a panic branch that needs a broken tree"),
    ("range front", "range arm for bound kinds this caller never passes, a panic for an inverted range, or the descent for 8 or more levels"),
    ("range back", "arm of the same search that gives the same edge on the keys built, or a descent word"),
    ("tree step", "parent walk arm that needs a broken tree"),
)
REFERENCE_CLAIMS = (
    {"reference": "l1/exchange/impl_bole.rs", "claim": "the file holds only generated order builders", "observed": "no index writer, no token refresh, no debt flag, no user sweep", "verdict": "gap in the reference"},
    {"reference": "l1/exchange/impl_global.rs:17", "claim": "0.8 is GENERATED_ORDER_REPRICE_ON_POSITIVE_DELTA", "observed": "the step uses f64 0x20b0c0 = 0.8 as the release point of the flag at exchange +0x5b4; another 0.8 in the reference has another role", "verdict": "different use of the same value"},
)
STUBS = (
    ("0x37400c0", "price scale, subject of #782 and decimal-scaled-301518; x0, x1, token and table pointer are checked, the result is a given function of x0 * x1"),
    ("0x2739d70, 0x4d4a3a0, 0x4d4a260", "system user pass; arguments checked, result byte given"),
    ("0x2765600, 0x4d96ad0, 0x4d98480", "sweep over the shortfall set, named in #629; argument checked, result byte given"),
    ("0x28db540, 0x48cfb90", "health report of the system user; arguments checked, report words given"),
    ("0x272de40, 0x46ed7d0, 0x46ebca0", "per-user liquidation entry; arguments checked, result word given"),
    ("0x3395aa0, 0x33b0f60", "error map insert and drain; key and message list checked"),
    ("0x565f5a0 through slot 0x576e1a8", "128 bit divide, modelled by exact integers; a zero divisor halts"),
    ("0x4ee3800", "clock read; the second read ends the run, so the shared timing tail is not stepped"),
    ("0x3379490, 0x3762510", "drop of an error value; tag checked"),
)


def rip_target(image, site):
    base = image.offset(site)
    return site + 7 + struct.unpack_from("<i", image.blob, base + 3)[0]


def text_at(image, va, count):
    base = image.offset(va)
    return bytes(image.blob[base:base + count])


def rows_of(image, start):
    begin, end = image.exact_fde(start)
    return decode_range(image, begin, end)


def error_strings(image):
    rows = []
    for site, text in ERROR_ROWS:
        if text_at(image, rip_target(image, site), len(text)) != text:
            raise EvidenceError("error text moved: %r" % text)
        rows.append({"site": "%#x" % site, "text": text.decode(), "target": "%#x" % rip_target(image, site)})
    return rows


def locations(image):
    relative = relative_slots(image)
    rows = []
    for site, role in LOCATION_ROWS:
        slot = rip_target(image, site)
        path, line, column = image.location(slot, relative)
        rows.append({"site": "%#x" % site, "slot": "%#x" % slot, "path": path, "line": line, "column": column, "role": role})
    return rows


def token_rows(image):
    """Compare rows on the token word r15, the perp index loads, the mode table and the skip mask, read from the decoded bytes."""
    compare, loads, mask = [], [], []
    for row in rows_of(image, REFRESH):
        if row.op == "cmp" and row.a == ("r", R15) and row.b and row.b[0] == "i":
            compare.append({"va": "%#x" % row.va, "token": "%#x" % (row.b[1] & MASK[8])})
        if row.op == "mov" and row.a == ("r", RDI) and row.b and row.b[0] == "i":
            loads.append({"va": "%#x" % row.va, "perp": "%#x" % row.b[1]})
        if row.op == "mov" and row.b and row.b[0] == "i" and row.b[1] == 0x30000000001:
            mask.append({"va": "%#x" % row.va, "mask": "%#x" % row.b[1]})
    table = []
    for index in range(4):
        word = struct.unpack_from("<i", text_at(image, 0x597440 + 4 * index, 4))[0]
        table.append({"mode": index, "target": "%#x" % (0x597440 + word)})
    return dict(compares=compare, perp_loads=loads, skip_mask=mask, mode_table=table, mode_table_base="0x597440", low_bits=[0x5DF + at for at in range(64) if 0x30000000001 >> at & 1])


def constants(image):
    rows = [{"name": name, "va": "%#x" % va, "value": struct.unpack("<d", text_at(image, va, 8))[0]} for name, va in
            (("debt flag release", 0x20B0C0), ("price spread limit", 0x20A528), ("step threshold low", 0x205E70), ("step threshold high", 0x205E78))]
    powers = [struct.unpack("<d", text_at(image, 0x584B08 + 8 * at, 8))[0] for at in range(7)]
    year = [("%#x" % row.va) for row in rows_of(image, ACCRUE) if row.op == "mov" and row.b and row.b[0] == "i" and row.b[1] == YEAR_MS]
    if not year or powers != [10.0 ** at for at in range(7)]:
        raise EvidenceError("constant moved")
    if text_at(image, SYSTEM_BYTES, 16) != bytes([0xBB] * 16):
        raise EvidenceError("system address moved")
    fourth = [("%#x" % row.va) for row in rows_of(image, COPIES[0]["step"]) if row.op == "mov" and row.b and row.b[0] == "i" and row.b[1] == 0xBBBBBBBB]
    return dict(floats=rows, power_table="0x584b08", powers=powers, year_millis=YEAR_MS, year_sites=year, system_address_prefix="%#x" % SYSTEM_BYTES, system_address_tail_sites=fourth)


def field_names(image):
    rows = []
    for site, offset, role in FIELD_ROWS:
        data = text_at(image, site, 7)
        if data[:2] != b"\x48\x8d" and data[:2] != b"\x49\x8d" and data[:2] != b"\x4d\x8d":
            raise EvidenceError("field site moved")
        if struct.unpack_from("<i", data, 3)[0] != offset:
            raise EvidenceError("field offset moved")
        rows.append({"site": "%#x" % site, "offset": "%#x" % offset, "role": role})
    key = text_at(image, rip_target(image, BUDGET_KEY_SITE), 3)
    if key != b"pmn":
        raise EvidenceError("budget key moved")
    return dict(rows=rows, budget_key=key.decode(), key_site="%#x" % BUDGET_KEY_SITE)


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


def calls_in(image, start):
    return ["%#x" % row.target for row in rows_of(image, start) if row.op == "call"]


def call_map(image):
    wanted = []
    for copy in COPIES:
        wanted += [copy["step"], copy["sweep"], copy["caller"]]
    direct = direct_callers(image, wanted)
    rows = []
    for layout in COPIES:
        name_at = rip_target(image, layout["gate_end"] - 5 - 0x30)
        if text_at(image, name_at, len(STEP_NAME)) != STEP_NAME:
            raise EvidenceError("step name moved")
        hosts = direct[layout["sweep"]]
        if len(hosts) != 1 or image.fde(hosts[0])[0] != layout["caller"] or not layout["gate_end"] <= hosts[0] < layout["gate_end"] + 0x40:
            raise EvidenceError("sweep call moved")
        marks = []
        site = layout["gate_end"]
        while site < hosts[0] + 0x40:
            data = text_at(image, site, 5)
            if data[0] == 0xBE and struct.unpack_from("<I", data, 1)[0] < 0x100:
                marks.append({"site": "%#x" % site, "tag": struct.unpack_from("<I", data, 1)[0]})
            site += 1
        rows.append({"copy": layout["name"], "caller": "%#x" % layout["caller"], "caller_called_by": ["%#x" % va for va in direct[layout["caller"]]], "gate": "%#x..%#x" % (layout["gate"], layout["gate_end"]),
                     "step": "%#x" % layout["step"], "step_calls_from": ["%#x" % va for va in direct[layout["step"]]], "step_callees": calls_in(image, layout["step"]),
                     "sweep": "%#x" % layout["sweep"], "sweep_call": "%#x" % hosts[0], "sweep_callees": calls_in(image, layout["sweep"]), "marker_tags": marks,
                     "mode_byte": "%#x" % layout["mode"], "dex_rows": "%#x" % layout["dex_rows"], "budget": "%#x" % layout["budget"], "cursor_flag": "%#x" % layout["flag"]})
    return rows


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
        begin, end = image.exact_fde(layout["step"])
        reads = [va for va in clocks if begin <= va < end]
        rows.append(("step " + layout["name"], begin, reads[1] + 5))
    for role, start in (("refresh", REFRESH), ("index writer", ACCRUE), ("median", MEDIAN), ("collector", COLLECT), ("row collector", COLLECT_ROWS)):
        rows.append((role, *image.exact_fde(start)))
    for layout in COPIES:
        rows.append(("sweep " + layout["name"], *image.exact_fde(layout["sweep"])))
    for role, start in (("range front", COPIES[0]["range_a"]), ("range back", COPIES[0]["range_b"]), ("tree step", TREE_STEP)):
        rows.append((role, *image.exact_fde(start)))
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
    kind = case["kind"]
    if kind == "gate":
        want = gate_spec(case)
        return "divide fault" if want["fault"] else ("step runs" if want["run"] else "step skipped")
    if kind == "accrue":
        row, _ = accrue_spec(case["row"], case["time"], case["keep"])
        return "stamped" if row["time"] == case["time"] else "left unstamped"
    if kind == "refresh":
        want = refresh_spec(case)
        return "panic" if want["panic"] else ("errors kept" if want["errors"] else "clean")
    if kind == "step":
        want = step_spec(case, BY_NAME[case["copy"]])
        return "disabled" if not want["ran"] else "panic" if want["panic"] else "flag %d" % want["debt"]
    if kind == "sweep":
        return "%d users" % min(len(sweep_spec(case)["picked"]), 3)
    if kind == "collect":
        want = collect_spec(case)
        return "code %d" % want["code"] if "code" in want else "rows"
    return "value"


def accrual_samples(image):
    """Real runs of the index writer over one day, with the row words after the call."""
    harness = Harness(image)
    rows = []
    for label, row, keep in (
        ("use 50 percent, below the bend", token(), E14 // 10),
        ("use 80 percent, at the bend", token(a=8 * 10 ** 7, b=10 ** 8), E14 // 10),
        ("use 90 percent, above the bend", token(a=9 * 10 ** 7, b=10 ** 8), E14 // 10),
        ("use 100 percent", token(a=10 ** 8, b=10 ** 8), E14 // 10),
        ("use 50 percent, reserve share 0", token(), 0),
        ("use 50 percent, reserve share 1", token(), E14),
    ):
        case = dict(kind="accrue", label=label, row=row, time=NOW, keep=keep)
        after = harness.run_accrue(case)
        rows.append((label, keep, after["ia"], after["ib"], after["pending"], after["paid"], after["balance"]))
    return rows


def debt_samples(image):
    harness = Harness(image)
    base = [case for case in step_cases() if case["label"] == "all clear, no gap" and case["copy"] == "primary"][0]
    rows = []
    for gap in (0, 1, 799, 800, 801, 1000, 1001):
        for before in (0, 1):
            case = dict(base, cap=1000, debt=before, report=(0, gap + 5, 5))
            harness.run_step(case, COPIES[0])
            rows.append((1000, gap, before, harness.machine.memory.read(EXCHANGE + DEBT_FLAG, 1)))
    return rows


def path_rows():
    return [
        ("1", "block host", "0x22297c0, 0x470e9a0, 0x47162d0", "bucket gate: millis / word +0x4d8, stored in +0x4e0 when larger; byte +0x20 of the step record says the bucket moved"),
        ("2", "step body", "0x222caf0, 0x4714080, 0x47121b0", "does nothing unless byte +0x20 is 1; first dex row must exist"),
        ("3", "token refresh", "0x373b060", "for each token: index writer, then price median and band; token 0 keeps its price"),
        ("4", "index writer", "0x3740990", "rate from use, index growth over elapsed millis / 31557600000, reserve share, pending to paid"),
        ("5", "median", "0x359ca70", "sorted copy; middle value, or average of the two middle values, 0 when empty"),
        ("6", "system user pass", "0x2739d70 family", "not stepped; a result other than 0x11 clears +0x5b3; it reads rows through 0x3739ef0 and 0x3733d70"),
        ("7", "row collector", "0x3739ef0, 0x3733d70", "system user rows: ceil of word +8 by the borrow index, floor of word +0x18 by the supply index"),
        ("8", "second sweep", "0x2765600 family", "not stepped; a result other than 0x11 clears +0x5b3"),
        ("9", "debt flag", "step body", "report of the system user: flag +0x5b4 set past the cap +0x590, released at 80 percent"),
        ("10", "user sweep", "0x26fdf20, 0x4ce64c0, 0x4ce6db0", "visit pmn users after the cursor, wrapping; users with a nonzero word +8 go to the per-user entry"),
    ]


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
    for role, begin, end in groups(image):
        rows = decode_range(image, begin, end)
        base = image.offset(begin)
        functions.append({"role": role, "start": "%#x" % begin, "end": "%#x" % end, "bytes": end - begin, "sha256": hashlib.sha256(bytes(image.blob[base:base + end - begin])).hexdigest(),
                          "instructions": len(rows), "instructions_stepped": sum(1 for row in rows if row.va in touched)})
    evidence = {
        "target_sha256": SHA256,
        "functions": functions,
        "call_map": call_map(image),
        "constants": constants(image),
        "token_rows": token_rows(image),
        "error_strings": error_strings(image),
        "fields": field_names(image),
        "locations": locations(image),
        "stubs": [{"edge": edge, "role": role} for edge, role in STUBS],
        "cases": {"total": len(cases), "outcomes": dict(sorted(outcomes.items()))},
        "mismatches": mismatches,
        "first_mismatch": first,
        "instructions_stepped": machine.steps,
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
        if text and row["group"].startswith(group) and low <= row["va"] < high:
            return text
    for group, text in GROUP_REASONS:
        if row["group"].startswith(group):
            return text
    return ""


def write_tsv(path, header, rows):
    lines = ["\t".join(header)] + ["\t".join(str(item) for item in row) for row in rows]
    path.write_text("\n".join(lines) + "\n", encoding="utf-8", newline="\n")


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
    write_tsv(out / "path-map.tsv", ("order", "stage", "address", "behaviour"), path_rows())
    write_tsv(out / "accrual-samples.tsv", ("label", "reserve_share", "borrow_index", "supply_index", "pending", "paid", "balance"), accrual_samples(image))
    write_tsv(out / "debt-flag.tsv", ("cap", "gap", "flag_before", "flag_after"), debt_samples(image))
    lines = ["group\tva\tkind\tresult\tkilled_by\treason"]
    for row in results:
        reason = "" if row["result"] == "killed" else reason_for(row)
        lines.append("%s\t%#x\t%s\t%s\t%s\t%s" % (row["group"], row["va"], row["kind"], row["result"], row["by"], reason))
    (out / "mutations.tsv").write_text("\n".join(lines) + "\n", encoding="utf-8", newline="\n")
    print("cases %d, mismatches %d, mutants %r" % (evidence["cases"]["total"], evidence["mismatches"], evidence["mutations"]))
    return 0


if __name__ == "__main__":
    sys.exit(main())
