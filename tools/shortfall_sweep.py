#!/usr/bin/env python3
"""Pin the node #94 shortfall sweep from ELF bytes: user classes, counters, claim rows, token scaling, order modes and final check.

The sweep 0x2765600, its copies, the value helper 0x21a35e0 and the row iterator drop run whole in a Python evaluator. A separately
written specification predicts every stub argument and outcome, and every condition, immediate and field offset of the primary
copy is flipped to show the run can tell. No objdump or readelf output is parsed, and the binary is never executed. Standard
library only.
"""

import argparse
import bisect
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

COPIES = (
    dict(name="primary", entry=0x2765600, state=0x2755400, cancels=0x2731030, count=0x1F84640, health=0x28DB540, add_set=0x284F810, drop_row=0x250D2A0, sides=0x21A35E0, orders=0x251A290,
         send=0x26F4400, flush=0x24FC8A0, drop_tokens=0x28A7F20, drop_iter=0x255CB70, drop_users=0x28B6EA0, host=0x222CAF0, drop_claim=0, shift=0),
    dict(name="second", entry=0x4D96AD0, state=0x46F2FE0, cancels=0x4D3B330, count=0x47D7550, health=0x48CFB90, add_set=0x4941FE0, drop_row=0x47EAA20, sides=0x4C22CF0, orders=0x47F71D0,
         send=0x4470BE0, flush=0x432B440, drop_tokens=0x49A90C0, drop_iter=0x44C6F60, drop_users=0x49B2500, host=0x4714080, drop_claim=0x49B3140, shift=0),
    dict(name="recording", entry=0x4D98480, state=0x46F2E60, cancels=0x4D3B5C0, count=0x47D7550, health=0x48CFB90, add_set=0x4941FE0, drop_row=0x47EAA20, sides=0x4C22CF0, orders=0x47F8550,
         send=0x4470BE0, flush=0x432A990, drop_tokens=0x49A90C0, drop_iter=0x44C6F60, drop_users=0x49B2500, host=0x47121B0, drop_claim=0x49B3140, shift=0xA80),
)
BY_NAME = {layout["name"]: layout for layout in COPIES}
VALUE = 0x32815F0
ROWS = 0x3739BE0
CLAIM = 0x3735DB0
BUILD = 0x3736BD0
REPORT = 0x373D8E0
FILTER = 0x3767210
REFS = 0x3BD3EB0
COLLECT = 0x33C3B00
LIST_NEXT = 0x33B0BB0
LIST_INSERT = 0x3395F60
LIST_SPLIT = 0x2F2EBD0
DROP_LIST = 0x33F6900
GROW_FOLD = 0x32D5E10
ITER_NEXT = 0x33B0060
ENTRY_INSERT = 0x33BCBC0
USER_INSERT = 0x33BEAA0
ACCOUNT_SPLIT = 0x2F34470
USER_SPLIT = 0x2F1CC20
DROP_ACCOUNTS = 0x33F5270
DATE = 0x151F6F0
GROW_ROWS = 0x454E930
GROW_LIST = 0x454E460
UDIV = 0x565F5A0
OVERFLOW_LOG = 0x358DCD0
PANIC_NONE = 0x157A9F0
PANIC_INDEX = 0x157B520
PANIC_BOUND = 0x157B64F
PANIC_UNWRAP = 0x157AA10
ONCE_CALL = 0x4EE3B20
SLOT_ALLOC = 0x576DFD8
SLOT_FREE = 0x576E010
SLOT_MEMCMP = 0x576E488
SLOT_MEMCPY = 0x576DFE0
SLOT_MEMMOVE = 0x576E0E0
ONCE_WORD = 0x5786380
ONCE_TWO = 0x577AB98
DEFAULT_USER = 0x5786350
BOLE = 0x498
OK_TAG = 0x11
RAX, RCX, RDX, RBX, RSP, RBP, RSI, RDI, R8, R9, R10, R11, R12, R13, R14, R15 = range(16)
VOLATILE = (RCX, RSI, RDI, R8, R9, R10, R11)
CALLEE_SAVED = (RBX, RBP, R12, R13, R14, R15)
MASK = {1: 0xFF, 2: 0xFFFF, 4: 0xFFFFFFFF, 8: 0xFFFFFFFFFFFFFFFF}
SIGN = {1: 0x80, 2: 0x8000, 4: 0x80000000, 8: 0x8000000000000000}
STACK_MARK = 0xA5
STACK_TOP = 0x7FF000000
STACK_SIZE = 0x4000
HEAP_BASE = 0x600000000
HEAP_SIZE = 0x80000
RETURN_SENTINEL = 0xDEAD0000
POISON = 0xA5A5A5A5A5A5A5A5
STEP_LIMIT = 900000
MUTANT_STEP_LIMIT = 300000
EXCHANGE = HEAP_BASE + 0x1000
BUMP = HEAP_BASE + 0x8000


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
        if two == 0xD6 and opsize:
            reg, rm = modrm(True)
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
        self.watch = {}
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
            if pc in self.watch:
                self.watch[pc](self)
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

VALUE_LIMIT = 0x28F5C28F5C28F5C
TIER_MIN = 4
DUST = 1000000
SCALE = 100000000000000
NO_LIST = 0x8000000000000002
TOP = 1 << 63
ORDER_SIZE = 0x228
MODE_SCALED = 0x90009
MODE_RATIO = 0x80008
BLOCK_TIME = bytes(range(0x31, 0x3D))
INDEX_CLASS, INDEX_EMPTY, INDEX_FAILED, INDEX_LOW, INDEX_AFTER = range(5)
COUNTERS = 0x7A0
EPOCH_DAYS = 719163
HEAD = (0x4545, 0x66, 0x7788)
DATE_WORD = 0x5A5A1
HIGH_GROUP = 0x50
LOW_GROUP = 0x78


class Stop(Exception):
    def __init__(self, code):
        Exception.__init__(self)
        self.code = code


def address(tail, first=0xAA):
    return bytes([first] * 19 + [tail])


SYSTEM = bytes([0xBB] * 20)


def group(flag):
    return HIGH_GROUP if flag else LOW_GROUP


def signed(word):
    return word - (1 << 64) if word >> 63 else word


def user_class(score, soft, mid, hard):
    if score > hard:
        return 0
    if score > mid:
        return 1
    return 2 if score > soft else 3


def grown(count):
    """Capacity of a vector after `count` pushes from nothing."""
    cap = 0
    while cap < count:
        cap = max(cap * 2, 4)
    return cap


class Spec:
    """Reads the case as a reader of the bytes would, and predicts every outward call and counter."""

    def __init__(self, case):
        self.case = case
        self.events = []
        self.frees = []
        self.logs = 0
        self.global_counts = dict(case.get("start", {}))
        self.user_counts = {}
        self.once = bool(case.get("once"))
        self.twice = bool(case.get("once_two"))
        users = [user for user in case.get("users", ()) if user.get("mapped", True)]
        self.accounts = {key: {} for key in case.get("extra", ())}
        self.accounts.update({user["key"]: {token: list(words) for token, words in user.get("accounts", {}).items()} for user in users})
        if case.get("system") is not None:
            self.accounts[SYSTEM] = {token: list(words) for token, words in case["system"].items()}
        self.heads = {key: HEAD for key in self.accounts}
        self.live = set()

    def default_once(self):
        if self.once:
            self.once = False
            self.events.append(("once", ONCE_WORD))

    def bump(self, flag, index, user):
        at = COUNTERS + group(flag) + 8 * index
        self.global_counts[at] = min(self.global_counts.get(at, 0) + 1, MASK[8])
        block = self.user_counts.setdefault(user, dict(self.case.get("user_start", {})))
        at = group(flag) + 8 * index
        block[at] = min(block.get(at, 0) + 1, MASK[8])

    def diff(self, token):
        table = self.case["decimals"]
        if token >= len(table):
            raise Panicked("none")
        low, high = table[token]
        if high < low:
            raise Panicked("none")
        return high - low

    def value(self, amount, token, px, up):
        scale = 100 * 10 ** self.diff(token)
        product = amount * px
        quotient = product // scale
        if up and product % scale:
            quotient += 1
        return quotient < VALUE_LIMIT, quotient & MASK[8]

    def side(self, rows, up):
        total = 0
        for token, amount in rows:
            if token not in self.case["tokens"]:
                return False, total
            good, worth = self.value(amount, token, self.case["tokens"][token][0], up)
            if not good:
                return False, total
            total += worth
            if total >> 64:
                self.logs += 1
                total = MASK[8]
        return True, total

    def drop_word(self, word):
        if signed(word) >= signed(0x8000000000000003) and word:
            self.frees.append(word * 8 & MASK[8])

    def stage_one(self, user, rows):
        key, row = user["key"], []
        self.events.append(("state", key))
        word = NO_LIST
        if user.get("tier", 0) >= TIER_MIN and not self.case.get("bit", 0) & 1:
            self.events.append(("cancels", key))
            word = user.get("word", NO_LIST)
        self.default_once()
        self.events.append(("report", key))
        fail, code, score, soft, mid, hard = user.get("first", (0, 0, 5, 10, 20, 30))
        if fail:
            self.drop_word(word)
            raise Stop(code)
        kind = user_class(score, soft, mid, hard)
        flag = user.get("flag", 0)
        if kind >= 2 or key == SYSTEM:
            if word == NO_LIST:
                return
            if not word >> 63:
                if word:
                    self.frees.append(word * 8 & MASK[8])
                return
            self.bump(flag, INDEX_FAILED if word ^ TOP == 1 else INDEX_EMPTY, key)
            return
        low = kind == 1 and score >= DUST
        if self.twice:
            self.twice = False
            self.events.append(("once", ONCE_TWO))
        self.bump(flag, INDEX_LOW, key)
        self.bump(low, INDEX_CLASS, key)
        self.default_once()
        self.events.append(("health", key))
        fail, code, first, second = user.get("second", (0, 0, 0, 0))
        if fail:
            self.drop_word(word)
            raise Stop(code)
        if second >> 63 or first >> 63:
            raise Panicked("unwrap")
        self.events.append(("build", key, int(low)))
        built = user.get("row")
        if built is None:
            self.events.append(("set", key))
        else:
            rows.append((user, int(user.get("mark", low))))
            if built.get("rows"):
                self.live.add(key)
        self.drop_word(word)

    def added(self, total, amount):
        total += amount
        if total >> 64:
            self.logs += 1
            total = MASK[8]
        return total

    def account(self, key):
        if key not in self.accounts:
            self.events.append(("date",))
            if not self.case.get("date", DATE_WORD):
                raise Panicked("none")
            self.accounts[key] = {}
            self.heads[key] = (0, self.case.get("date", DATE_WORD), 0)
        return self.accounts[key]

    def move(self, user):
        """The rows go to the system account, and the user keeps only what the row kept."""
        key = user["key"]
        self.events.append(("claim", key))
        table = self.account(SYSTEM)
        kept = {}
        rows = user["row"].get("rows", ())
        for token, first, first_pair, debit, credit, second, second_pair, other_debit, other_credit in sorted(rows):
            if first == 3:
                break
            if first != 2:
                entry = table.setdefault(token, [0, 0, 0, 0])
                entry[0] = self.added(entry[0], debit)
                entry[1] = self.added(entry[1], credit)
                if first & 1:
                    kept.setdefault(token, [0, 0, 0, 0])[:2] = first_pair
            if second & ~1 == 2:
                continue
            entry = table.setdefault(token, [0, 0, 0, 0])
            entry[2] = self.added(entry[2], other_debit)
            entry[3] = self.added(entry[3], other_credit)
            if second & 1:
                kept.setdefault(token, [0, 0, 0, 0])[2:] = second_pair
        self.account(key)
        self.events.append(("drop accounts", key))
        self.accounts[key] = kept
        self.live.discard(key)

    def after(self, user, mark):
        key = user["key"]
        self.default_once()
        self.events.append(("health", key))
        fail, code, score, mid, hard = user.get("third", (0, 0, 5, 20, 30))
        if fail:
            raise Stop(code)
        if score > hard or score > mid:
            self.bump(mark, INDEX_AFTER, key)

    def scaled(self, built):
        items, cap = [], 0
        for token, amount, fraction in built.get("map", ()):
            if token not in self.case["tokens"]:
                return None, cap
            product = amount * self.case["tokens"][token][1]
            if product // SCALE >> 64:
                return None, cap
            items.append((token, product // SCALE, fraction))
            cap = grown(len(items))
        return items, cap

    def ratio(self, built):
        good, top = self.side(built.get("a", ()), True)
        fine, bottom = self.side(built.get("b", ()), False)
        if not good or not fine:
            return None
        share = float(top) / float(bottom) if bottom else 1.0
        return [(token, amount, share) for token, amount in built.get("b", ())]

    def claim(self, user, mark):
        built = user["row"]
        self.move(user)
        tag = built.get("tag", 1)
        if tag & 1:
            items, cap = self.scaled(built)
            if items is None:
                if cap:
                    self.frees.append(cap * 24)
                self.events.append(("drop tokens",))
                items = None
            scaled = True
        else:
            items, cap = self.ratio(built), None
            scaled = False
        if items is not None:
            self.events.append(("orders", user["key"], tuple(items)))
            count = built.get("count", 1)
            size = built.get("order_cap", count)
            if count:
                self.events.append(("send", count, MODE_SCALED if tag & 1 else MODE_RATIO))
                self.events.append(("flush",))
            if size:
                self.frees.append(size * ORDER_SIZE)
            if tag:
                self.events.append(("drop tokens",))
        for name in ("cap_a", "cap_b"):
            size = built.get(name, len(built.get(name[-1], ())))
            if size:
                self.frees.append(size * 16)
        self.after(user, mark)

    def drop_rows(self, rows, start, cap, inline=False):
        for item in rows[start:]:
            self.events.append(("drop row", item[0]["key"]))
            if inline and self.case.get("copy", "primary") != "primary" and item[0]["row"].get("tag", 1):
                self.events.append(("drop row map",))
            if inline and self.case.get("copy", "primary") != "primary":
                for name in ("cap_a", "cap_b"):
                    size = item[0]["row"].get(name, len(item[0]["row"].get(name[-1], ())))
                    if size:
                        self.frees.append(size * 16)
        if cap:
            self.frees.append(cap * 128)

    def body(self):
        case = self.case
        self.events.append(("users",))
        failed = case.get("users_error")
        if failed is not None:
            raise Stop(failed)
        rows = []
        try:
            for user in sorted(case["users"], key=lambda item: item["key"]):
                self.stage_one(user, rows)
        except Stop:
            self.drop_rows(rows, 0, grown(len(rows)))
            self.events.append(("drop users",))
            raise
        cap = grown(len(rows))
        for index, (user, mark) in enumerate(rows):
            try:
                self.claim(user, mark)
            except Stop:
                self.drop_rows(rows, index + 1, cap, True)
                self.events.append(("drop users",))
                raise
        self.drop_rows(rows, len(rows), cap, True)
        self.events.append(("drop users",))

    def run(self):
        result = OK_TAG
        if self.case.get("gate", 1) == 1:
            try:
                self.body()
            except Stop as stop:
                result = stop.code
        return dict(events=self.events, frees=self.frees, logs=self.logs, result=result, globals=self.global_counts, users=self.user_counts,
                    accounts={key: (self.heads[key], {token: tuple(words) for token, words in table.items()}) for key, table in self.accounts.items()}, live=self.live)


def sweep_spec(case):
    return Spec(case).run()


def filter_spec(case):
    """Rows of 0x3767210: failed reports keep their byte and code, healthy users and the system address leave."""
    rows = []
    for key, report in case["items"]:
        tag, code, score, soft, mid, hard = report
        if tag:
            if tag != 2:
                rows.append((key, tag, code))
            continue
        kind = user_class(score, soft, mid, hard)
        if key == SYSTEM or kind >= 2:
            continue
        rows.append((key, 0, int(kind == 1 and score >= DUST)))
    return rows


def list_spec(case):
    """Result of 0x3739be0 over status rows in key order."""
    found = {}
    for key, tag, value in sorted(case["statuses"]):
        if tag:
            return dict(failed=value)
        if key != SYSTEM:
            found[key] = value
    return dict(flags=found)


# ---- harness ----

TOKEN_TREE = dict(leaf=0x7F8, inner=0x858, parent=0x790, slot=0x7F0, length=0x7F2, keys=0x798, stride=8, edges=0x7F8, values=0xB0)
USER_TREE = dict(leaf=0x2F8, inner=0x358, parent=0x210, slot=0x2F4, length=0x2F6, keys=0x218, stride=20, edges=0x2F8, values=0x30)
LIST_TREE = dict(leaf=0xF8, inner=0x158, parent=0, slot=0xE4, length=0xE6, keys=8, stride=20, edges=0xF8, values=1, value_base=0xE8)
CLAIM_TREE = dict(leaf=0x170, inner=0x1D0, parent=0, slot=0x168, length=0x16A, keys=8, stride=8, edges=0x170, values=0x18, value_base=0x60)
ACCOUNT_TREE = dict(leaf=0x1C8, inner=0x228, parent=0x160, slot=0x1C0, length=0x1C2, keys=0x168, stride=8, edges=0x1C8, values=0x20)
ROW_TREE = dict(leaf=0x3D8, inner=0x438, parent=0x370, slot=0x3D0, length=0x3D2, keys=0x378, stride=8, edges=0x3D8, values=0x50)
STATUS_TREE = dict(leaf=0x100, inner=0x160, parent=0, slot=0xE4, length=0xE6, keys=8, stride=20, edges=0x100, values=2, value_base=0xE8)
CAPACITY = 11


def tree_height(count):
    level, room = 0, CAPACITY
    while room < count:
        level += 1
        room = room * (CAPACITY + 1) + CAPACITY
    return level


def build_tree(memory, bump, shape, items, put):
    """B-tree over sorted (key bytes, value) items; returns the root and its height."""
    if not items:
        return 0, 0
    base = shape.get("value_base", 0)

    def make(rows, level, parent, slot):
        node = bump(shape["inner"] if level else shape["leaf"])
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


def tree_items(memory, shape, node, height):
    """(key bytes, value address) in key order."""
    if not node:
        return []
    found = []
    count = memory.read(node + shape["length"], 2)
    for index in range(count + 1):
        if height:
            found += tree_items(memory, shape, memory.read(node + shape["edges"] + 8 * index, 8), height - 1)
        if index < count:
            found.append((memory.bytes_at(node + shape["keys"] + shape["stride"] * index, shape["stride"]), node + shape.get("value_base", 0) + shape["values"] * index))
    return found


def word_key(value):
    return struct.pack("<Q", value)


class Harness:
    def __init__(self, image):
        self.image = image
        machine = self.machine = Machine(image)
        real = {VALUE, CLAIM, ITER_NEXT, ENTRY_INSERT, USER_INSERT, ACCOUNT_SPLIT, USER_SPLIT, FILTER, ROWS, REFS, LIST_NEXT, LIST_INSERT, LIST_SPLIT}
        for layout in COPIES:
            real.update((layout["entry"], layout["sides"], layout["drop_iter"]))
        machine.real = frozenset(real)
        machine.jump_ranges = [image.exact_fde(start) for start in real]
        machine.calls = {REPORT: self.on_report, DROP_ACCOUNTS: self.on_drop_accounts, COLLECT: self.on_collect, DROP_LIST: self.on_drop_list}
        machine.watch = {CLAIM: self.on_claim}
        for layout in COPIES:
            machine.calls.update({layout["state"]: self.on_state, layout["cancels"]: self.on_cancels, layout["count"]: self.on_count, layout["health"]: self.on_health,
                                  layout["add_set"]: self.on_set, layout["drop_row"]: self.on_drop_row, layout["orders"]: self.on_orders, layout["send"]: self.on_send,
                                  layout["flush"]: self.on_flush, layout["drop_tokens"]: self.on_drop_tokens, layout["drop_users"]: self.on_drop_users})
            if layout["drop_claim"]:
                machine.calls[layout["drop_claim"]] = self.on_drop_claim
        hooks = {ROWS: self.on_users, DATE: self.on_date, BUILD: self.on_build, GROW_ROWS: self.on_grow(128), GROW_LIST: self.on_grow(24), GROW_FOLD: self.on_grow(22), UDIV: self.on_div, OVERFLOW_LOG: self.on_log,
                 PANIC_NONE: self.on_panic("none"), PANIC_BOUND: self.on_panic("bound"), PANIC_UNWRAP: self.on_panic("unwrap"), PANIC_INDEX: self.on_panic("index"), ONCE_CALL: self.on_once}
        tokens = {}
        for at, (target, hook) in enumerate(hooks.items()):
            token = 0x7000000 + at * 16
            tokens[target] = token
            machine.slots[token] = hook
        for slot, target in relative_slots(image).items():
            if target in tokens:
                machine.memory.statics[slot] = tokens[target]
            elif target in (VALUE, CLAIM):
                machine.memory.statics[slot] = target
        for at, (slot, hook) in enumerate(((SLOT_ALLOC, self.on_alloc), (SLOT_FREE, self.on_free), (SLOT_MEMCMP, self.on_memcmp), (SLOT_MEMCPY, self.on_memcpy), (SLOT_MEMMOVE, self.on_memcpy))):
            token = 0x7100000 + at * 16
            machine.memory.statics[slot] = token
            machine.slots[token] = hook
        self.case = None
        self.at = BUMP
        self.events, self.frees = [], []
        self.logs = 0
        self.by_key = {}
        self.entries = {}
        self.blocks = {}
        self.current = None
        self.claimed = False
        self.row_images = {}
        self.users_map = 0
        self.tokens_map = 0
        self.last_orders = 0
        self.first_value = 0
        self.nodes = {}
        self.shift = 0
        self.dropping = False

    def bump(self, size):
        here = self.at
        self.at += (size + 15) & ~15
        if self.at >= HEAP_BASE + HEAP_SIZE:
            raise Halt("heap exhausted")
        return here

    # edge hooks

    def on_alloc(self, machine):
        machine.regs[RAX] = self.bump(machine.regs[RDI])

    def on_free(self, machine):
        if machine.regs[RDI] in self.nodes:
            del self.nodes[machine.regs[RDI]]
        else:
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
        self.logs += 1

    def on_panic(self, name):
        def panic(machine):
            raise Panicked(name)
        return panic

    def on_once(self, machine):
        regs = machine.regs
        if regs[RDI] not in (ONCE_WORD, ONCE_TWO) or regs[RSI] & 0xFF != 1:
            raise Halt("once arguments")
        machine.memory.statics[regs[RDI]] = 0
        self.events.append(("once", regs[RDI]))

    def on_grow(self, size):
        def grow(machine):
            regs, memory = machine.regs, machine.memory
            vector = regs[RDI]
            cap, data = memory.read(vector, 8), memory.read(vector + 8, 8)
            wider = max(cap * 2, 4)
            fresh = self.bump(wider * size)
            if cap:
                memory.copy(fresh, data, cap * size)
            memory.write(vector, 8, wider)
            memory.write(vector + 8, 8, fresh)
        return grow

    def value_of(self, key):
        memory = self.machine.memory
        for found, at in tree_items(memory, USER_TREE, memory.read(EXCHANGE + 0x598, 8), memory.read(EXCHANGE + 0x5A0, 8)):
            if found == key:
                return at
        return DEFAULT_USER

    def on_date(self, machine):
        if machine.regs[RDI] & MASK[4] != EPOCH_DAYS:
            raise Halt("date argument")
        self.events.append(("date",))
        machine.regs[RAX] = self.case.get("date", DATE_WORD)

    def on_drop_accounts(self, machine):
        regs = machine.regs
        if regs[RDI] != self.value_of(self.current) + 0x18:
            raise Halt("drop accounts argument")
        self.events.append(("drop accounts", self.current))

    def on_users(self, machine):
        regs, memory = machine.regs, machine.memory
        if regs[RSI] != EXCHANGE + BOLE or regs[RDX] != EXCHANGE + 0x90:
            raise Halt("users arguments")
        self.events.append(("users",))
        out = regs[RDI]
        failed = self.case.get("users_error")
        if failed is not None:
            memory.write(out, 1, 1)
            memory.write(out + 1, 1, failed)
            return
        users = sorted(self.case["users"], key=lambda item: item["key"])
        root, height = build_tree(memory, self.bump, LIST_TREE, [(item["key"], item.get("flag", 0)) for item in users], lambda at, value: memory.write(at, 1, value))
        memory.write(out, 1, 0)
        memory.write(out + 8, 8, root)
        memory.write(out + 16, 8, height)
        memory.write(out + 24, 8, len(users))
        self.users_map = root

    def on_state(self, machine):
        regs, memory = machine.regs, machine.memory
        key = memory.bytes_at(regs[RSI], 20)
        if regs[RDI] != EXCHANGE or key not in self.by_key:
            raise Halt("state arguments")
        self.current = key
        self.events.append(("state", key))
        block = self.bump(0x40)
        memory.write(block + 0x3C, 1, self.by_key[key].get("tier", 0))
        regs[RAX] = block

    def on_cancels(self, machine):
        regs, memory = machine.regs, machine.memory
        key = memory.bytes_at(regs[RDX], 20)
        if regs[RSI] != EXCHANGE or key != self.current or regs[RCX] != 1:
            raise Halt("cancels arguments")
        self.events.append(("cancels", key))
        memory.write(regs[RDI], 8, self.by_key[key].get("word", NO_LIST))
        memory.write(regs[RDI] + 8, 8, 0x4440)

    def on_collect(self, machine):
        regs, memory = machine.regs, machine.memory
        source, out = regs[RSI], regs[RDI]
        data, count = memory.read(source + 8, 8), memory.read(source + 0x10, 8)
        want = tree_items(memory, USER_TREE, memory.read(EXCHANGE + 0x598, 8), memory.read(EXCHANGE + 0x5A0, 8))
        found = [(memory.bytes_at(memory.read(data + 16 * index, 8), 20), memory.read(data + 16 * index + 8, 8)) for index in range(count)]
        if found != want or memory.read(source + 0x18, 8) != EXCHANGE + BOLE or memory.read(source + 0x20, 8) != EXCHANGE + 0x90:
            raise Halt("collect arguments")
        self.events.append(("collect", count))
        rows = sorted(self.case["statuses"])

        def tracked(size):
            at = self.bump(size)
            self.nodes[at] = b"list"
            return at

        def put(at, value):
            memory.write(at, 1, value[0])
            memory.write(at + 1, 1, value[1])
        root, height = build_tree(memory, tracked, STATUS_TREE, [(key, (tag, value)) for key, tag, value in rows], put)
        memory.write(out, 8, root)
        memory.write(out + 8, 8, height)
        memory.write(out + 16, 8, len(rows))

    def on_drop_list(self, machine):
        self.events.append(("drop list",))

    def on_report(self, machine):
        regs, memory = machine.regs, machine.memory
        if self.case.get("kind") == "filter":
            if regs[RDX] != EXCHANGE + 0x560 or regs[RCX] != EXCHANGE + 0x90:
                raise Halt("filter report arguments")
            index = (regs[RSI] - self.first_value) // 0x10
            tag, code, score, soft, mid, hard = self.case["items"][index][1]
            self.events.append(("report", index))
            out = regs[RDI]
            memory.write(out, 1, tag)
            memory.write(out + 1, 1, code)
            memory.write(out + 8, 8, score)
            memory.write(out + 0x18, 8, soft)
            memory.write(out + 0x20, 8, mid)
            memory.write(out + 0x28, 8, hard)
            return
        if regs[RSI] != self.value_of(self.current) or regs[RDX] != EXCHANGE + 0x560 or regs[RCX] != EXCHANGE + 0x90:
            raise Halt("report arguments")
        self.events.append(("report", self.current))
        fail, code, score, soft, mid, hard = self.by_key[self.current].get("first", (0, 0, 5, 10, 20, 30))
        out = regs[RDI]
        memory.write(out, 1, fail)
        memory.write(out + 1, 1, code)
        memory.write(out + 8, 8, score)
        memory.write(out + 0x18, 8, soft)
        memory.write(out + 0x20, 8, mid)
        memory.write(out + 0x28, 8, hard)

    def on_health(self, machine):
        regs, memory = machine.regs, machine.memory
        if regs[RSI] != self.value_of(self.current) or regs[RDX] != EXCHANGE + 0x560 or regs[RCX] != EXCHANGE + 0x90 or regs[R8] & 0xFF:
            raise Halt("health arguments")
        self.events.append(("health", self.current))
        user = self.by_key[self.current]
        out = regs[RDI]
        if self.claimed:
            fail, code, score, mid, hard = user.get("third", (0, 0, 5, 20, 30))
            memory.write(out + 8, 8, score)
            memory.write(out + 0x20, 8, mid)
            memory.write(out + 0x28, 8, hard)
        else:
            fail, code, first, second = user.get("second", (0, 0, 0, 0))
            memory.write(out + 8, 8, first)
            memory.write(out + 0x10, 8, second)
        memory.write(out, 1, fail)
        memory.write(out + 1, 1, code)

    def on_count(self, machine):
        regs, memory = machine.regs, machine.memory
        key = memory.bytes_at(regs[RSI], 20)
        if regs[RDI] != EXCHANGE + 0x770 + self.shift or key != self.current:
            raise Halt("count arguments")
        block = self.blocks.get(key)
        if block is None:
            block = self.blocks[key] = self.bump(0xA0)
            memory.put_bytes(block, bytes(0xA0))
            for at, value in self.case.get("user_start", {}).items():
                memory.write(block + at, 8, value)
        regs[RAX] = block

    def on_build(self, machine):
        regs, memory = machine.regs, machine.memory
        key = memory.bytes_at(regs[RDX], 20)
        if regs[RSI] != EXCHANGE + BOLE or key != self.current or regs[R8] != EXCHANGE + 0x80:
            raise Halt("build arguments")
        low = regs[RCX] & 0xFF
        self.events.append(("build", key, low))
        user, out = self.by_key[key], regs[RDI]
        built = user.get("row")
        if built is None:
            memory.write(out, 4, 2)
            memory.write(out + 4, 4, 0x77777777)
            return
        image = bytearray(bytes((index * 7 + 3) & 0xFF for index in range(0x80)))
        image[0:8] = struct.pack("<Q", built.get("tag", 1))
        items = [(word_key(token), (amount, fraction)) for token, amount, fraction in sorted(built.get("map", ()))]

        def put(at, value):
            memory.write(at, 8, 0x3333)
            memory.write(at + 8, 8, value[0])
            memory.write(at + 0x10, 8, to_bits(value[1]))
        root, height = build_tree(memory, self.bump, CLAIM_TREE, items, put)
        image[8:0x20] = struct.pack("<QQQ", root, height, len(items))
        for name, at in (("a", 0x20), ("b", 0x38)):
            rows = built.get(name, ())
            data = self.bump(max(len(rows), 1) * 16)
            for index, (token, amount) in enumerate(rows):
                memory.write(data + index * 16, 8, token)
                memory.write(data + index * 16 + 8, 8, amount)
            image[at:at + 0x18] = struct.pack("<QQQ", built.get("cap_" + name, len(rows)), data, len(rows))

        def put_row(at, value):
            _, first, first_pair, debit, credit, second, second_pair, other_debit, other_credit = value
            memory.write(at, 8, first)
            memory.write(at + 8, 8, first_pair[0])
            memory.write(at + 0x10, 8, first_pair[1])
            memory.write(at + 0x18, 8, debit)
            memory.write(at + 0x20, 8, credit)
            memory.write(at + 0x28, 8, second)
            memory.write(at + 0x30, 8, second_pair[0])
            memory.write(at + 0x38, 8, second_pair[1])
            memory.write(at + 0x40, 8, other_debit)
            memory.write(at + 0x48, 8, other_credit)
        rows = [(word_key(row[0]), row) for row in sorted(built.get("rows", ()))]

        def tracked(size):
            at = self.bump(size)
            self.nodes[at] = key
            return at
        root, height = build_tree(memory, tracked, ROW_TREE, rows, put_row)
        image[0x50:0x68] = struct.pack("<QQQ", root, height, len(rows))
        image[0x68:0x7C] = key
        image[0x7C] = user.get("mark", low)
        memory.put_bytes(out, bytes(image))
        self.row_images[key] = bytes(image)

    def on_set(self, machine):
        regs, memory = machine.regs, machine.memory
        key = memory.bytes_at(regs[RSI], 20)
        if regs[RDI] != EXCHANGE + 0x8B8 + self.shift or key != self.current:
            raise Halt("set arguments")
        self.events.append(("set", key))

    def on_drop_row(self, machine):
        regs, memory = machine.regs, machine.memory
        self.events.append(("drop row", memory.bytes_at(regs[RDI] + 0x68, 20)))

    def on_drop_claim(self, machine):
        """The iterator drop of the copies opens the row drop inline; this call is its first step."""
        regs, memory = machine.regs, machine.memory
        self.events.append(("drop row", memory.bytes_at(regs[RDI] + 0x18, 20)))
        self.dropping = True

    def on_claim(self, machine):
        regs, memory = machine.regs, machine.memory
        image = memory.bytes_at(regs[RDX], 0x80)
        key = image[0x68:0x7C]
        if regs[RSI] != EXCHANGE + BOLE or self.row_images.get(key) != image:
            raise Halt("claim arguments")
        self.current = key
        self.claimed = True
        self.events.append(("claim", key))

    def on_orders(self, machine):
        regs, memory = machine.regs, machine.memory
        out, source = regs[RDI], regs[RSI]
        buffer, cursor, end = memory.read(source, 8), memory.read(source + 8, 8), memory.read(source + 0x18, 8)
        if buffer != cursor or memory.read(source + 0x20, 8) != EXCHANGE or memory.bytes_at(memory.read(source + 0x28, 8), 20) != self.current \
                or memory.bytes_at(memory.read(source + 0x30, 8), 12) != BLOCK_TIME:
            raise Halt("orders arguments")
        items = []
        while cursor != end:
            items.append((memory.read(cursor, 8), memory.read(cursor + 8, 8), to_float(memory.read(cursor + 16, 8))))
            cursor += 24
        self.events.append(("orders", self.current, tuple(items)))
        built = self.by_key[self.current]["row"]
        count = built.get("count", 1)
        data = self.bump(max(count, 1) * 8)
        memory.write(out, 8, built.get("order_cap", count))
        memory.write(out + 8, 8, data)
        memory.write(out + 16, 8, count)
        self.last_orders = data

    def on_send(self, machine):
        regs, memory = machine.regs, machine.memory
        if self.case.get("copy", "primary") == "primary":
            data, count, source, zero, mode, vector = regs[RDI], regs[RSI], regs[RDX], regs[RCX], regs[R8], regs[R9]
        else:
            # The copies pass exchange +0x80 first, so every argument moves one place and the vector goes on the stack.
            if regs[RDI] != EXCHANGE + 0x80:
                raise Halt("send balance view")
            data, count, source, zero, mode, vector = regs[RSI], regs[RDX], regs[RCX], regs[R8], regs[R9], memory.read(regs[RSP] + 8, 8)
        if data != self.last_orders or memory.bytes_at(source, 33) != b"\x01" + bytes(32) or zero & MASK[4] != 0:
            raise Halt("send arguments")
        self.events.append(("send", count, mode & MASK[4]))
        if memory.read(vector, 8) != 0 or memory.read(vector + 8, 8) != 8 or memory.read(vector + 16, 8) != 0:
            raise Halt("send vector")
        memory.write(vector, 8, 0x51)
        memory.write(vector + 8, 8, 0x52)
        memory.write(vector + 16, 8, 0x53)

    def on_flush(self, machine):
        regs, memory = machine.regs, machine.memory
        if regs[RSI] != EXCHANGE or [memory.read(regs[RDI] + at, 8) for at in (0, 8, 16)] != [0x51, 0x52, 0x53]:
            raise Halt("flush arguments")
        self.events.append(("flush",))

    def on_drop_tokens(self, machine):
        regs, memory = machine.regs, machine.memory
        if self.dropping:
            self.dropping = False
            self.events.append(("drop row map",))
            return
        built = self.by_key[self.current]["row"]
        if memory.read(regs[RDI] + 0x10, 8) != len(built.get("map", ())) or regs[RDI] & 0xF != 8:
            raise Halt("drop tokens argument")
        self.events.append(("drop tokens",))

    def on_drop_users(self, machine):
        regs, memory = machine.regs, machine.memory
        if memory.read(regs[RDI], 8) != self.users_map:
            raise Halt("drop users argument")
        self.events.append(("drop users",))

    # fixtures

    def lay_table(self, case):
        memory = self.machine.memory
        table = case["decimals"]
        data = self.bump(0xE8 * max(len(table), 1))
        for index, (low, high) in enumerate(table):
            memory.write(data + 0xE8 * index + 0x48, 1, low)
            memory.write(data + 0xE8 * index + 0x49, 1, high)
        memory.write(EXCHANGE + 0x90 + 0x180, 8, data)
        memory.write(EXCHANGE + 0x90 + 0x188, 8, len(table))

    def run_case(self, case):
        machine, memory = self.machine, self.machine.memory
        memory.reset()
        self.case = case
        self.at = BUMP
        self.events, self.frees = [], []
        self.logs = 0
        self.blocks, self.entries, self.row_images, self.nodes = {}, {}, {}, {}
        self.current = None
        self.claimed = False
        self.by_key = {user["key"]: user for user in case.get("users", ())}
        self.shift = BY_NAME[case.get("copy", "primary")]["shift"]
        self.dropping = False
        memory.statics[ONCE_WORD] = 1 if case.get("once") else 0
        memory.statics[ONCE_TWO] = 1 if case.get("once_two") else 0
        memory.write(EXCHANGE + 0x5B3, 1, case.get("gate", 1))
        memory.write(EXCHANGE + 0x5B0, 1, case.get("bit", 0))
        memory.put_bytes(EXCHANGE + 0x60, BLOCK_TIME)
        memory.put_bytes(EXCHANGE + COUNTERS + self.shift, bytes(0xA0))
        for at, value in case.get("start", {}).items():
            memory.write(EXCHANGE + at + self.shift, 8, value)
        self.lay_table(case)
        tokens = case["tokens"]

        def put_token(at, key):
            memory.write(at + 0x10, 8, tokens[key][0])
            memory.write(at + 0x78, 8, tokens[key][1])
        root, height = build_tree(memory, self.bump, TOKEN_TREE, [(word_key(key), key) for key in sorted(tokens)], put_token)
        memory.write(EXCHANGE + 0x568, 8, root)
        memory.write(EXCHANGE + 0x570, 8, height)
        lay = self.entries
        keys = sorted(key for key, user in self.by_key.items() if user.get("mapped", True)) + case.get("extra", [])
        if case.get("system") is not None and SYSTEM not in keys:
            keys.append(SYSTEM)

        def put_account(at, words):
            for index, word in enumerate(words):
                memory.write(at + 8 * index, 8, word)

        def put_user(at, key):
            lay[key] = at
            memory.write(at, 8, HEAD[0])
            memory.write(at + 8, 4, HEAD[1])
            memory.write(at + 0xC, 8, HEAD[2])
            table = case["system"] if key == SYSTEM and case.get("system") is not None else self.by_key.get(key, {}).get("accounts", {})
            items = [(word_key(token), table[token]) for token in sorted(table)]
            account, height = build_tree(memory, self.bump, ACCOUNT_TREE, items, put_account)
            memory.write(at + 0x18, 8, account)
            memory.write(at + 0x20, 8, height)
            memory.write(at + 0x28, 8, len(items))
        root, height = build_tree(memory, self.bump, USER_TREE, [(key, key) for key in sorted(keys)], put_user)
        memory.write(EXCHANGE + 0x598, 8, root)
        memory.write(EXCHANGE + 0x5A0, 8, height)
        result = machine.run(BY_NAME[case.get("copy", "primary")]["entry"], {RDI: EXCHANGE})
        return result & 0xFF

    def start(self, case):
        self.machine.memory.reset()
        self.case = case
        self.at = BUMP
        self.events, self.frees = [], []
        self.logs = 0
        self.nodes = {}
        self.blocks, self.entries, self.row_images = {}, {}, {}

    def run_filter(self, case):
        machine, memory = self.machine, self.machine.memory
        self.start(case)
        items = case["items"]
        pairs = self.bump(max(len(items), 1) * 16)
        keys = self.bump(max(len(items), 1) * 24)
        values = self.first_value = self.bump(max(len(items), 1) * 16)
        for index, (key, _) in enumerate(items):
            memory.put_bytes(keys + 24 * index, key)
            memory.write(pairs + 16 * index, 8, keys + 24 * index)
            memory.write(pairs + 16 * index + 8, 8, values + 16 * index)
        context = self.bump(16)
        memory.write(context, 8, EXCHANGE + BOLE)
        memory.write(context + 8, 8, EXCHANGE + 0x90)
        folder = self.bump(0x20)
        reserved = case.get("reserved", 0)
        data = self.bump(max(reserved, 1) * 22)
        memory.write(folder, 8, reserved)
        memory.write(folder + 8, 8, data)
        memory.write(folder + 0x10, 8, 0)
        memory.write(folder + 0x18, 8, context)
        out = self.bump(0x20)
        machine.run(FILTER, {RDI: out, RSI: folder, RDX: pairs, RCX: pairs + 16 * len(items)})
        if memory.read(out + 0x18, 8) != context:
            raise Halt("filter context")
        data, count = memory.read(out + 8, 8), memory.read(out + 0x10, 8)
        rows = []
        for index in range(count):
            at = data + 22 * index
            rows.append((memory.bytes_at(at, 20), memory.read(at + 20, 1), memory.read(at + 21, 1)))
        return rows

    def run_list(self, case):
        machine, memory = self.machine, self.machine.memory
        self.start(case)
        keys = sorted(case["map"])

        def put_user(at, key):
            memory.write(at, 8, HEAD[0])
        root, height = build_tree(memory, self.bump, USER_TREE, [(key, key) for key in keys], put_user)
        memory.write(EXCHANGE + 0x598, 8, root)
        memory.write(EXCHANGE + 0x5A0, 8, height)
        memory.write(EXCHANGE + 0x5A8, 8, len(keys))
        out = self.bump(0x20)
        machine.run(ROWS, {RDI: out, RSI: EXCHANGE + BOLE, RDX: EXCHANGE + 0x90})
        if memory.read(out, 1):
            return dict(failed=memory.read(out + 1, 1))
        items = tree_items(memory, LIST_TREE, memory.read(out + 8, 8), memory.read(out + 16, 8))
        if len(items) != memory.read(out + 24, 8):
            raise Halt("list length word")
        return dict(flags={key: memory.read(at, 1) for key, at in items})

    def account_dump(self):
        memory = self.machine.memory
        found = {}
        for key, at in tree_items(memory, USER_TREE, memory.read(EXCHANGE + 0x598, 8), memory.read(EXCHANGE + 0x5A0, 8)):
            table = {}
            items = tree_items(memory, ACCOUNT_TREE, memory.read(at + 0x18, 8), memory.read(at + 0x20, 8))
            if len(items) != memory.read(at + 0x28, 8):
                raise Halt("account length word")
            for token, value in items:
                table[struct.unpack("<Q", token)[0]] = tuple(memory.read(value + 8 * index, 8) for index in range(4))
            found[key] = ((memory.read(at, 8), memory.read(at + 8, 4), memory.read(at + 0xC, 8)), table)
        return found

    def counters(self):
        memory = self.machine.memory
        found = {}
        for group_at in (HIGH_GROUP, LOW_GROUP):
            for index in range(5):
                at = COUNTERS + group_at + 8 * index
                value = memory.read(EXCHANGE + at + self.shift, 8)
                if value:
                    found[at] = value
        users = {}
        for key, block in self.blocks.items():
            users[key] = {}
            for group_at in (HIGH_GROUP, LOW_GROUP):
                for index in range(5):
                    value = memory.read(block + group_at + 8 * index, 8)
                    if value:
                        users[key][group_at + 8 * index] = value
        return found, users


# ---- cases ----

ONE = address(1)
TWO = address(2)
THREE = address(3)
PX = 10 ** 8
WEI = 10 ** 14
DECIMALS = [(8, 8), (2, 8), (4, 8), (0, 6), (6, 6), (3, 8), (5, 7), (1, 8)]
TOKENS = {0: (PX, WEI), 1: (2 * PX, 2 * WEI), 2: (3 * PX, WEI // 2), 3: (5 * PX, 3 * WEI)}
LIQUID = (0, 0, 50, 10, 20, 30)
THIN = (0, 0, 25, 10, 20, 30)
THIN_LOW = (0, 0, DUST, 10, 20, DUST + 5)
CLAIM_ROW = dict(tag=1, map=[(1, 1000, 0.5)], count=2)


def make(label, **fields):
    case = dict(label=label, decimals=DECIMALS, tokens=TOKENS, users=[dict(key=ONE)])
    case.update(fields)
    return case


def row_user(key=ONE, **fields):
    user = dict(key=key, first=LIQUID, row=dict(CLAIM_ROW))
    user.update(fields)
    return user


def many_map(count, start=1):
    return [(index + start, 1000 + index, 0.25) for index in range(count)]


def sweep_cases():
    wide_tokens = {index: (PX, WEI) for index in range(60)}
    wide_decimals = [(4, 8)] * 60
    cases = [
        make("gate zero", gate=0),
        make("gate two", gate=2),
        make("gate 0x81", gate=0x81),
        make("users error", users_error=0x23),
        make("users error with ok byte", users_error=OK_TAG),
        make("no users", users=[]),
        make("one healthy user"),
        make("three healthy users", users=[dict(key=THREE), dict(key=ONE), dict(key=TWO)]),
        make("twelve users, two levels", users=[dict(key=address(index + 1), flag=index & 1) for index in range(12)]),
        make("forty users, flags split", users=[dict(key=address(index + 1), flag=index % 3 == 0) for index in range(40)]),
        make("user missing from the map", users=[dict(key=ONE, mapped=False)]),
        make("user missing, keys around it", users=[dict(key=TWO, mapped=False)], extra=[ONE, THREE]),
        make("user in a deep map", users=[dict(key=address(9))], extra=[address(index + 20) for index in range(30)]),
        make("user past the last key", users=[dict(key=address(99), mapped=False)], extra=[address(index + 20) for index in range(30)]),
        make("once of the default row", once=True),
        make("once of the default row, row path", once=True, users=[row_user()], once_two=True),
        make("once two only", once_two=True, users=[row_user()]),
        make("once two, healthy user", once_two=True),
    ]
    # tier and cancels word
    for tier, word in ((3, 5), (4, 5), (5, 5), (0xFF, 5), (4, 0), (4, NO_LIST), (4, TOP), (4, TOP | 1), (4, TOP | 3), (4, TOP | 9), (4, (1 << 62) | 1)):
        cases.append(make("tier %d word %#x healthy" % (tier, word), users=[dict(key=ONE, tier=tier, word=word)]))
        cases.append(make("tier %d word %#x flagged" % (tier, word), users=[dict(key=ONE, tier=tier, word=word, flag=1)]))
        cases.append(make("tier %d word %#x row path" % (tier, word), users=[row_user(tier=tier, word=word)]))
        cases.append(make("tier %d word %#x set path" % (tier, word), users=[dict(key=ONE, tier=tier, word=word, first=THIN, row=None)]))
    for bit in (1, 3, 0xFF, 2, 0xFE):
        cases.append(make("bit %#x" % bit, bit=bit, users=[dict(key=ONE, tier=4, word=TOP)]))
    # classes
    for score, soft, mid, hard in ((5, 10, 20, 30), (10, 10, 20, 30), (11, 10, 20, 30), (20, 10, 20, 30), (21, 10, 20, 30), (30, 10, 20, 30), (31, 10, 20, 30), (1 << 63, 10, 20, 30), (0, 0, 0, 0), (1, 0, 0, 0),
                                  (40, 50, 30, 60), (40, 30, 50, 60), (40, 60, 50, 30), (40, 30, 60, 50), (1 << 40, 1 << 39, 1 << 41, 1 << 42)):
        first = (0, 0, score, soft, mid, hard)
        cases.append(make("class %d %d %d %d" % (score, soft, mid, hard), users=[dict(key=ONE, first=first, tier=4, word=TOP | 1, row=dict(CLAIM_ROW))]))
        cases.append(make("class %d %d %d %d set" % (score, soft, mid, hard), users=[dict(key=ONE, first=first, flag=1, row=None)]))
    for score in (DUST - 1, DUST, DUST + 1, 1 << 32, 1 << 33 | 5):
        cases.append(make("dust edge %d" % score, users=[dict(key=ONE, first=(0, 0, score, 10, 20, 1 << 40), row=dict(CLAIM_ROW))]))
        cases.append(make("dust edge %d, flag 1" % score, users=[dict(key=ONE, flag=1, first=(0, 0, score, 10, 20, 1 << 40), row=None)]))
        cases.append(make("dust edge %d, above hard" % score, users=[dict(key=ONE, first=(0, 0, score, 1, 2, 3), row=None)]))
    for tail in (0, 1, 0xBA, 0xBC):
        cases.append(make("near system key %#x" % tail, users=[dict(key=SYSTEM[:19] + bytes([tail]), first=THIN, row=None)]))
    for at in range(20):
        key = bytearray(SYSTEM)
        key[at] = 0xBA
        if at in (0, 7, 15, 16, 19):
            cases.append(make("system key off at byte %d" % at, users=[dict(key=bytes(key), first=THIN, row=None)]))
    cases.append(make("system key, thin", users=[dict(key=SYSTEM, first=THIN, row=dict(CLAIM_ROW))]))
    cases.append(make("system key, liquid, empty word", users=[dict(key=SYSTEM, first=LIQUID, tier=4, word=TOP)]))
    # failures
    many = [row_user(ONE), row_user(TWO), dict(key=THREE, first=(1, 0x2C, 0, 0, 0, 0), tier=4, word=3)]
    cases.append(make("report fails after two rows", users=many))
    cases.append(make("report fails on the first user", users=[dict(key=ONE, first=(1, 0x2D, 0, 0, 0, 0))]))
    cases.append(make("report fails, tagged word", users=[dict(key=ONE, first=(1, 0x2D, 0, 0, 0, 0), tier=4, word=TOP)]))
    cases.append(make("report fails, none word", users=[dict(key=ONE, first=(1, 0x2D, 0, 0, 0, 0), tier=4, word=NO_LIST)]))
    cases.append(make("report fails, zero word", users=[dict(key=ONE, first=(1, 0x2D, 0, 0, 0, 0), tier=4, word=0)]))
    cases.append(make("report fails, odd tag word", users=[dict(key=ONE, first=(1, 0x2D, 0, 0, 0, 0), tier=4, word=TOP | 3)]))
    cases.append(make("health fails", users=[dict(key=ONE, first=LIQUID, second=(1, 0x2E, 0, 0), tier=4, word=9)]))
    cases.append(make("health fails after a row", users=[row_user(ONE), dict(key=TWO, first=LIQUID, second=(1, 0x2F, 0, 0))]))
    cases.append(make("health first word negative", users=[dict(key=ONE, first=LIQUID, second=(0, 0, TOP, 1), row=None)]))
    cases.append(make("health second word negative", users=[dict(key=ONE, first=LIQUID, second=(0, 0, 1, TOP), row=None)]))
    cases.append(make("health words largest positive", users=[dict(key=ONE, first=LIQUID, second=(0, 0, TOP - 1, TOP - 1), row=None)]))
    for count in (1, 3, 4, 5, 8, 9):
        cases.append(make("%d rows fail at the end" % count, users=[row_user(address(index + 1)) for index in range(count)] + [dict(key=address(40), first=(1, 0x31, 0, 0, 0, 0))]))
        cases.append(make("%d rows pass" % count, users=[row_user(address(index + 1)) for index in range(count)]))
        cases.append(make("%d rows, third check fails on the first" % count, users=[row_user(address(1), third=(1, 0x32, 0, 0, 0))] + [row_user(address(index + 2)) for index in range(count - 1)]))
    # counters and saturation
    full = MASK[8]
    hit = {COUNTERS + LOW_GROUP + 8 * index: full for index in range(5)}
    hit.update({COUNTERS + HIGH_GROUP + 8 * index: full for index in range(5)})
    below = {key: full - 1 for key in hit}
    per = {group_at + 8 * index: full for group_at in (HIGH_GROUP, LOW_GROUP) for index in range(5)}
    under = {key: full - 1 for key in per}
    variety = lambda flag: [row_user(ONE, flag=flag, first=(0, 0, 25, 10, 20, 30), mark=1, third=(0, 0, 40, 20, 30)), row_user(TWO, flag=flag, first=(0, 0, 40, 10, 20, 30), mark=0, third=(0, 0, 40, 20, 30)),
                            dict(key=THREE, flag=flag, tier=4, word=TOP), dict(key=address(4), flag=flag, tier=4, word=TOP | 1)]
    for flag in (0, 1):
        cases.append(make("all counters flag %d" % flag, users=variety(flag)))
        cases.append(make("all counters flag %d, saturated" % flag, users=variety(flag), start=hit, user_start=per))
        cases.append(make("all counters flag %d, one below" % flag, users=variety(flag), start=below, user_start=under))
    for score, mid, hard in ((5, 20, 30), (20, 20, 30), (21, 20, 30), (30, 20, 30), (31, 20, 30), (25, 30, 20), (35, 30, 20), (20, 30, 20), (TOP, 1, 2), (0, 0, 0)):
        cases.append(make("third check %d %d %d" % (score, mid, hard), users=[row_user(third=(0, 0, score, mid, hard), mark=1)]))
        cases.append(make("third check %d %d %d, mark 0" % (score, mid, hard), users=[row_user(third=(0, 0, score, mid, hard), mark=0)]))
    # claim rows: scaled map
    cases.append(make("mapped token with empty map", users=[row_user(row=dict(tag=1, map=[], count=0))]))
    cases.append(make("map row sends", users=[row_user(row=dict(tag=1, map=many_map(3), count=3))]))
    cases.append(make("map row, no orders", users=[row_user(row=dict(tag=1, map=many_map(3), count=0))]))
    cases.append(make("map row, order capacity above length", users=[row_user(row=dict(tag=1, map=many_map(2), count=1, order_cap=5))]))
    cases.append(make("map row, no orders with capacity", users=[row_user(row=dict(tag=1, map=many_map(2), count=0, order_cap=5))]))
    cases.append(make("map row, vectors held", users=[row_user(row=dict(tag=1, map=many_map(1), a=[(1, 5)], b=[(2, 6), (3, 7)], cap_a=4, cap_b=8))]))
    cases.append(make("map row, tag 3", users=[row_user(row=dict(tag=3, map=many_map(1)))]))
    for count in (4, 5, 11, 12, 13, 24, 30, 45):
        cases.append(make("map of %d" % count, tokens=wide_tokens, decimals=wide_decimals, users=[row_user(row=dict(tag=1, map=many_map(count), count=1))]))
    cases.append(make("map misses a token", users=[row_user(row=dict(tag=1, map=[(1, 5, 0.5), (9, 5, 0.5)]))]))
    cases.append(make("map misses a token past 4", tokens=wide_tokens, decimals=wide_decimals, users=[row_user(row=dict(tag=1, map=many_map(6) + [(70, 1, 0.5)]))]))
    cases.append(make("map misses the first", users=[row_user(row=dict(tag=1, map=[(9, 5, 0.5)]))]))
    cases.append(make("token before the keys", tokens={3: (PX, WEI)}, users=[row_user(row=dict(tag=1, map=[(1, 5, 0.5)]))]))
    cases.append(make("empty token tree, map row", tokens={}, users=[row_user(row=dict(tag=1, map=[(1, 5, 0.5)]))]))
    cases.append(make("empty token tree, empty map", tokens={}, users=[row_user(row=dict(tag=1, map=[], count=0))]))
    cases.append(make("token in a deep tree", tokens=wide_tokens, decimals=wide_decimals, users=[row_user(row=dict(tag=1, map=[(40, 9, 0.5), (41, 9, 0.5)]))]))
    for amount, scale in ((1, WEI), (WEI, 1), (WEI - 1, 1), (3, WEI // 2), (7, 3), (0, 5), (5, 0), (MASK[8], WEI), (MASK[8], WEI + 1), (MASK[8], WEI - 1), (1 << 63, 1 << 47), (1 << 63, (1 << 47) + 1), (MASK[8], 5427), (MASK[8], 5420)):
        tokens = dict(TOKENS)
        tokens[1] = (PX, scale)
        cases.append(make("scale %d by %d" % (amount, scale), tokens=tokens, users=[row_user(row=dict(tag=1, map=[(1, amount, 0.125)]))]))
    edge = (1 << 64) * WEI // ((1 << 64) - 1)
    for scale in (edge - 1, edge, edge + 1):
        tokens = dict(TOKENS)
        tokens[1] = (PX, scale)
        cases.append(make("quotient limit at scale %d" % scale, tokens=tokens, users=[row_user(row=dict(tag=1, map=[(1, MASK[8], 0.125)]))]))
    # claim rows: value sides
    two = dict(a=[(1, 1000)], b=[(2, 3000)])
    cases.append(make("ratio row", users=[row_user(row=dict(tag=0, **two))]))
    cases.append(make("ratio row, no orders", users=[row_user(row=dict(tag=0, count=0, **two))]))
    cases.append(make("ratio row, tag 4", users=[row_user(row=dict(tag=4, **two))]))
    cases.append(make("ratio row, tag 2 mark", users=[row_user(row=dict(tag=6, **two))]))
    cases.append(make("ratio row, no b", users=[row_user(row=dict(tag=0, a=[(1, 1000)]))]))
    cases.append(make("ratio row, no a", users=[row_user(row=dict(tag=0, b=[(1, 1000)]))]))
    cases.append(make("ratio row, empty", users=[row_user(row=dict(tag=0))]))
    cases.append(make("ratio row, b worth zero", users=[row_user(row=dict(tag=0, a=[(1, 1000)], b=[(1, 1)]))]))
    cases.append(make("ratio row, capacities", users=[row_user(row=dict(tag=0, cap_a=9, cap_b=7, **two))]))
    for count in (2, 3, 4, 5):
        cases.append(make("ratio row, %d b rows" % count, users=[row_user(row=dict(tag=0, a=[(1, 777), (2, 5000)], b=[(index + 1, 100 * index + 1234) for index in range(count)]))]))
    cases.append(make("ratio row, a token missing", users=[row_user(row=dict(tag=0, a=[(9, 1)], b=[(1, 5)]))]))
    cases.append(make("ratio row, b token missing", users=[row_user(row=dict(tag=0, a=[(1, 5)], b=[(9, 1)]))]))
    cases.append(make("ratio row, second a token missing", users=[row_user(row=dict(tag=0, a=[(1, 5), (9, 1)], b=[(1, 1)]))]))
    cases.append(make("ratio row, second b token missing", users=[row_user(row=dict(tag=0, a=[(1, 5)], b=[(1, 1), (9, 1)]))]))
    cases.append(make("ratio row, a missing, b overflows", users=[row_user(row=dict(tag=0, a=[(9, 5)], b=[(3, 1 << 63)]))], tokens={3: (1 << 63, WEI)}))
    cases.append(make("empty token tree, ratio row", tokens={}, users=[row_user(row=dict(tag=0, a=[(1, 5)], b=[(1, 5)]))]))
    extended = dict(TOKENS)
    extended[20] = (PX, WEI)
    cases.append(make("token past the decimals table", tokens=extended, users=[row_user(row=dict(tag=0, a=[(20, 5)]))]))
    cases.append(make("token past the decimals table, b side", tokens=extended, users=[row_user(row=dict(tag=0, b=[(20, 5)]))]))
    cases.append(make("decimals reversed", decimals=[(8, 8), (8, 2)], users=[row_user(row=dict(tag=0, a=[(1, 5)]))]))
    wide = {0: (100, WEI)}
    top = VALUE_LIMIT - 1
    cases.append(make("a side value limit", tokens=wide, decimals=[(8, 8)], users=[row_user(row=dict(tag=0, a=[(0, VALUE_LIMIT)]))]))
    cases.append(make("b side value limit", tokens=wide, decimals=[(8, 8)], users=[row_user(row=dict(tag=0, b=[(0, VALUE_LIMIT)]))]))
    cases.append(make("a side under the limit", tokens=wide, decimals=[(8, 8)], users=[row_user(row=dict(tag=0, a=[(0, top)]))]))
    cases.append(make("a side sum overflow", tokens=wide, decimals=[(8, 8)], users=[row_user(row=dict(tag=0, a=[(0, top)] * 105, b=[(0, 1)]))]))
    cases.append(make("b side sum overflow", tokens=wide, decimals=[(8, 8)], users=[row_user(row=dict(tag=0, a=[(0, 1)], b=[(0, top)] * 105))]))
    cases.append(make("a rounds up, b rounds down", tokens={1: (33, WEI)}, decimals=[(8, 8), (8, 8)], users=[row_user(row=dict(tag=0, a=[(1, 1)], b=[(1, 7)]))]))
    cases.append(make("large sides for the float", tokens={0: (PX, WEI)}, decimals=[(8, 8)], users=[row_user(row=dict(tag=0, a=[(0, (1 << 53) + 1)], b=[(0, (1 << 54) + 3)]))]))
    cases.append(make("sides above 2^52", tokens={0: (PX * 100, WEI)}, decimals=[(8, 8)], users=[row_user(row=dict(tag=0, a=[(0, 3 << 54)], b=[(0, (1 << 56) + 1)]))]))
    # map walks on the later reads
    deep = [address(index + 20) for index in range(30)]
    cases.append(make("row user under a deep map", extra=deep, users=[row_user(address(9))]))
    cases.append(make("row user inside a deep map", extra=[key for key in deep if key != address(33)], users=[row_user(address(33))]))
    cases.append(make("row user past a deep map", extra=deep, users=[row_user(address(99), mapped=False)]))
    cases.append(make("row user between keys of a deep map", extra=[address(index * 2 + 20) for index in range(30)], users=[row_user(address(33), mapped=False)]))
    cases.append(make("row user missing", users=[row_user(mapped=False)]))
    cases.append(make("set user under a deep map", extra=deep, users=[dict(key=address(9), first=LIQUID, row=None)]))
    cases.append(make("set user between keys", extra=[address(index * 2 + 20) for index in range(30)], users=[dict(key=address(33), mapped=False, first=LIQUID, row=None)]))
    cases.append(make("set user missing", users=[dict(key=ONE, mapped=False, first=LIQUID, row=None)]))
    cases.append(make("no keys in the map", users=[row_user(mapped=False), dict(key=TWO, mapped=False, first=LIQUID, row=None), dict(key=THREE, mapped=False)]))
    cases.append(make("empty token tree, long map", tokens={}, users=[row_user(row=dict(tag=1, map=many_map(13)))]))
    cases.append(make("deep tokens, ratio row", tokens=wide_tokens, decimals=wide_decimals, users=[row_user(row=dict(tag=0, a=[(40, 50000), (3, 70000), (59, 90000)], b=[(41, 110000), (55, 130000), (0, 5)]))]))
    cases.append(make("deep tokens, ratio miss", tokens={index * 2: (PX, WEI) for index in range(30)}, decimals=wide_decimals, users=[row_user(row=dict(tag=0, a=[(41, 5)], b=[(43, 5)]))]))
    cases.append(make("deep tokens, past the last", tokens={index * 2: (PX, WEI) for index in range(30)}, decimals=wide_decimals, users=[row_user(row=dict(tag=0, a=[(59, 5)], b=[(59, 5)]))]))
    cases.append(make("deep tokens, map miss", tokens={index * 2: (PX, WEI) for index in range(30)}, decimals=wide_decimals, users=[row_user(row=dict(tag=1, map=[(41, 5, 0.5)]))]))
    cases.append(make("empty token tree, a only", tokens={}, users=[row_user(row=dict(tag=0, a=[(1, 5)]))]))
    cases.append(make("empty token tree, b only", tokens={}, users=[row_user(row=dict(tag=0, b=[(1, 5)]))]))
    # moving rows to the system account
    item = (1, 0, (0x11, 0x12), 500, 600, 0, (0x13, 0x14), 700, 800)
    for first in range(4):
        for second in range(4):
            line = (1, first, (0x11, 0x12), 500, 600, second, (0x13, 0x14), 700, 800)
            for label, system in (("no system row", None), ("system row, no token", {}), ("system row, token", {1: (5, 6, 7, 8)})):
                cases.append(make("row tags %d %d, %s" % (first, second, label), system=system, users=[row_user(row=dict(tag=1, rows=[line]))]))
    held = {1: (1, 2, 3, 4), 9: (5, 6, 7, 8)}
    cases.append(make("user accounts replaced", system={}, users=[row_user(accounts=held, row=dict(tag=1, rows=[(1, 1, (21, 22), 1, 2, 1, (23, 24), 3, 4)]))]))
    cases.append(make("user accounts cleared", system={}, users=[row_user(accounts=held, row=dict(tag=1))]))
    cases.append(make("user accounts cleared by a plain row", system={}, users=[row_user(accounts=held, row=dict(tag=1, rows=[item]))]))
    cases.append(make("unmapped user gets a row", system={}, users=[row_user(mapped=False, row=dict(tag=1, rows=[(1, 1, (21, 22), 1, 2, 0, (0, 0), 3, 4)]))]))
    cases.append(make("unmapped user between keys", system={}, extra=[address(1), address(9)], users=[row_user(address(5), mapped=False, row=dict(tag=1, rows=[item]))]))
    cases.append(make("unmapped user, deep map", system={}, extra=[address(index * 2 + 20) for index in range(30)], users=[row_user(address(33), mapped=False, row=dict(tag=1, rows=[item]))]))
    cases.append(make("unmapped user, full leaf", system={}, extra=[address(index * 2 + 20) for index in range(10)], users=[row_user(address(33), mapped=False, row=dict(tag=1, rows=[item]))]))
    cases.append(make("system row inserted, deep map", extra=[address(index + 20) for index in range(30)], users=[row_user(address(21 + 40), row=dict(tag=1, rows=[item]))]))
    cases.append(make("system row inserted, keys above", extra=[bytes([0xCC] * 19 + [index]) for index in range(30)], users=[row_user(row=dict(tag=1, rows=[item]))]))
    cases.append(make("system row inserted, empty map", users=[row_user(mapped=False, row=dict(tag=1, rows=[item]))]))
    cases.append(make("date zero on the system row", date=0, users=[row_user(row=dict(tag=1, rows=[item]))]))
    cases.append(make("date zero on the user row", date=0, system={}, users=[row_user(mapped=False, row=dict(tag=1, rows=[item]))]))
    cases.append(make("system user claims", system={1: (5, 6, 7, 8)}, users=[row_user(SYSTEM, first=THIN, row=dict(tag=1, rows=[(1, 1, (21, 22), 1, 2, 0, (0, 0), 3, 4)]))]))
    cases.append(make("two users add up", system={}, users=[row_user(ONE, row=dict(tag=1, rows=[item, (2, 0, (0, 0), 1, 2, 0, (0, 0), 3, 4)])), row_user(TWO, row=dict(tag=1, rows=[item]))]))
    lines = [(index + 1, index % 2, (31 + index, 32), 100 + index, 200, (index + 1) % 2, (33, 34 + index), 300, 400 + index) for index in range(40)]
    for count in (2, 5, 11, 12, 13, 24, 40):
        cases.append(make("row of %d tokens" % count, system={}, users=[row_user(row=dict(tag=1, rows=lines[:count]))]))
        cases.append(make("row of %d tokens, system holds some" % count, system={index * 3 + 1: (1, 2, 3, 4) for index in range(10)}, users=[row_user(row=dict(tag=1, rows=lines[:count]))]))
    for at in (0, 1, 5, 12, 25):
        stopped = list(lines[:30])
        stopped[at] = (stopped[at][0], 3) + stopped[at][2:]
        cases.append(make("row stops at token %d" % at, system={}, users=[row_user(row=dict(tag=1, rows=stopped))]))
    full = MASK[8]
    for words, line in (((full, 0, 0, 0), (1, 0, (0, 0), 1, 0, 2, (0, 0), 0, 0)), ((0, full, 0, 0), (1, 0, (0, 0), 0, 1, 2, (0, 0), 0, 0)), ((0, 0, full, 0), (1, 2, (0, 0), 0, 0, 0, (0, 0), 1, 0)), ((0, 0, 0, full), (1, 2, (0, 0), 0, 0, 0, (0, 0), 0, 1)),
                        ((full, full, full, full), (1, 0, (0, 0), full, full, 0, (0, 0), full, full)), ((full - 5, full - 5, full - 5, full - 5), (1, 0, (0, 0), 5, 5, 0, (0, 0), 5, 5))):
        cases.append(make("system words %x %x" % (words[0], words[3]), system={1: words}, users=[row_user(row=dict(tag=1, rows=[line]))]))
    cases.append(make("rows stay on a later failure", system={}, users=[row_user(ONE, row=dict(tag=1, rows=[item]), third=(1, 0x35, 0, 0, 0)), row_user(TWO, row=dict(tag=1, rows=[item]))]))
    cases.append(make("rows stay on an early failure", system={}, users=[row_user(ONE, row=dict(tag=1, rows=[item])), dict(key=TWO, first=(1, 0x36, 0, 0, 0, 0))]))
    cases.append(make("ratio row moves too", system={}, users=[row_user(row=dict(tag=0, a=[(1, 1000)], b=[(2, 3000)], rows=[item]))]))
    cases.append(make("skipped row still moved", system={}, users=[row_user(row=dict(tag=0, a=[(9, 1)], rows=[item]))]))
    # closing cases
    distinct = {group_at + 8 * index: 1000 + 7 * index + group_at for group_at in (HIGH_GROUP, LOW_GROUP) for index in range(5)}
    for flag in (0, 1):
        cases.append(make("distinct user counters, flag %d" % flag, users=variety(flag), user_start=distinct))
    cases.append(make("twenty users, flags clear", users=[dict(key=address(index + 1)) for index in range(20)]))
    cases.append(make("twenty row users, flags clear", users=[row_user(address(index + 1)) for index in range(20)]))
    cases.append(make("map token in the last child", tokens=wide_tokens, decimals=wide_decimals, users=[row_user(row=dict(tag=1, map=[(59, 9, 0.5)]))]))
    cases.append(make("a missing, b past the decimals table", tokens=extended, users=[row_user(row=dict(tag=0, a=[(9, 5)], b=[(20, 5)]))]))
    cases.append(make("a missing, b sum overflow", tokens=wide, decimals=[(8, 8)], users=[row_user(row=dict(tag=0, a=[(9, 1)], b=[(0, top)] * 105))]))
    skipping = [(index * 3 + 2, 2, (0, 0), 0, 0, index % 2, (41, 42), 7, 8) for index in range(14)]
    cases.append(make("second pair only, deep system map", system={index * 3 + 1: (1, 2, 3, 4) for index in range(30)}, users=[row_user(row=dict(tag=1, rows=skipping))]))
    cases.append(make("second pair only, system holds them", system={index * 3 + 2: (1, 2, 3, 4) for index in range(30)}, users=[row_user(row=dict(tag=1, rows=skipping))]))
    cases.append(make("first pair saturates, odd tag", system={1: (MASK[8], MASK[8], 0, 0)}, users=[row_user(row=dict(tag=1, rows=[(1, 1, (51, 52), 1, 1, 1, (53, 54), 0, 0)]))]))
    cases.append(make("first word saturates, odd tag", system={1: (MASK[8], 0, 0, 0)}, users=[row_user(row=dict(tag=1, rows=[(1, 1, (51, 52), 1, 0, 2, (0, 0), 0, 0)]))]))
    cases.append(make("second word saturates, even tag", system={1: (0, MASK[8], 0, 0)}, users=[row_user(row=dict(tag=1, rows=[(1, 0, (51, 52), 0, 1, 2, (0, 0), 0, 0)]))]))
    cases.append(make("second pair saturates, odd tag", system={1: (0, 0, MASK[8], MASK[8])}, users=[row_user(row=dict(tag=1, rows=[(1, 2, (0, 0), 0, 0, 1, (53, 54), 1, 1)]))]))
    cases.append(make("last word saturates, even tag", system={1: (0, 0, 0, MASK[8])}, users=[row_user(row=dict(tag=1, rows=[(1, 2, (0, 0), 0, 0, 0, (53, 54), 0, 1)]))]))
    # mixed runs
    cases.append(make("rows of both kinds", users=[row_user(ONE, row=dict(tag=0, **two)), row_user(TWO, row=dict(tag=1, map=many_map(2))), dict(key=THREE, first=THIN, row=None), row_user(address(4), row=dict(tag=0, a=[(9, 1)]))]))
    cases.append(make("set users among rows", users=[dict(key=address(index + 1), first=LIQUID, row=None if index % 2 else dict(CLAIM_ROW)) for index in range(7)]))
    return cases


def filter_cases():
    cases = [dict(kind="filter", label="no items", items=[]), dict(kind="filter", label="reserved room", items=[(ONE, THIN)], reserved=4)]
    for label, report in (("under soft", (0, 0, 5, 10, 20, 30)), ("at soft", (0, 0, 10, 10, 20, 30)), ("above soft", (0, 0, 11, 10, 20, 30)), ("at mid", (0, 0, 20, 10, 20, 30)), ("above mid", (0, 0, 21, 10, 20, 30)),
                          ("at hard", (0, 0, 30, 10, 20, 30)), ("above hard", (0, 0, 31, 10, 20, 30)), ("all zero", (0, 0, 0, 0, 0, 0)), ("dust less one", (0, 0, DUST - 1, 10, 20, DUST + 5)), ("dust", (0, 0, DUST, 10, 20, DUST + 5)),
                          ("dust plus one", (0, 0, DUST + 1, 10, 20, DUST + 5)), ("dust above hard", (0, 0, DUST, 10, 20, 30)), ("large", (0, 0, 1 << 40, 10, 1 << 39, 1 << 41)), ("large low word small", (0, 0, 1 << 33 | 5, 10, 20, 1 << 40)),
                          ("mid above hard", (0, 0, 40, 10, 50, 30)), ("soft above mid", (0, 0, 15, 40, 10, 50)),
                          ("failed report", (1, 0x2A, 0, 0, 0, 0)), ("failed report, other byte", (3, 0x2B, 99, 1, 2, 3)), ("failed report, byte 2", (2, 0x2C, 99, 1, 2, 3))):
        cases.append(dict(kind="filter", label=label, items=[(ONE, report)]))
        cases.append(dict(kind="filter", label=label + ", system key", items=[(SYSTEM, report)]))
        cases.append(dict(kind="filter", label=label + ", near system key", items=[(SYSTEM[:19] + b"\xba", report)]))
        cases.append(dict(kind="filter", label=label + ", second row", items=[(ONE, THIN), (TWO, report), (THREE, LIQUID)]))
    for at in (0, 5, 12, 15, 16, 17, 18):
        key = bytearray(SYSTEM)
        key[at] = 0xBA
        cases.append(dict(kind="filter", label="system key off at byte %d" % at, items=[(bytes(key), THIN)]))
    cases.append(dict(kind="filter", label="five rows from empty", items=[(address(index + 1), THIN) for index in range(5)]))
    cases.append(dict(kind="filter", label="nine rows from empty", items=[(address(index + 1), THIN_LOW) for index in range(9)]))
    return cases


def list_cases():
    keys = [address(index + 1) for index in range(40)]
    cases = [dict(kind="list", label="empty map", map=[], statuses=[]), dict(kind="list", label="one user, not listed", map=[ONE], statuses=[])]
    for count in (1, 2, 11, 12, 13, 40):
        cases.append(dict(kind="list", label="all %d listed" % count, map=keys[:count], statuses=[(key, 0, index & 1) for index, key in enumerate(keys[:count])]))
        cases.append(dict(kind="list", label="every third of %d" % count, map=keys[:count], statuses=[(key, 0, 1) for key in keys[:count:3]]))
    cases.append(dict(kind="list", label="deep map", map=[address(index) for index in range(150)], statuses=[(ONE, 0, 1)]))
    for at in (0, 1, 5, 20, 39):
        rows = [(key, 0, 0) for key in keys]
        rows[at] = (keys[at], 1, 0x40 + at)
        cases.append(dict(kind="list", label="failed row %d" % at, map=keys, statuses=rows))
        wide = list(rows)
        wide[(at + 3) % 40] = (keys[(at + 3) % 40], 3, 0x70)
        cases.append(dict(kind="list", label="two failed rows %d" % at, map=keys, statuses=wide))
    cases.append(dict(kind="list", label="system row skipped", map=[ONE, SYSTEM], statuses=[(ONE, 0, 1), (SYSTEM, 0, 1)]))
    cases.append(dict(kind="list", label="near system rows", map=[SYSTEM[:19] + b"\xba", SYSTEM[:15] + b"\xba" + SYSTEM[16:], SYSTEM], statuses=[(SYSTEM[:19] + b"\xba", 0, 0), (SYSTEM[:15] + b"\xba" + SYSTEM[16:], 0, 1)]))
    cases.append(dict(kind="list", label="flag byte above 1", map=[ONE], statuses=[(ONE, 0, 0x81)]))
    return cases


def all_cases():
    cases = []
    for layout in COPIES:
        cases += [dict(case, copy=layout["name"], kind="sweep") for case in sweep_cases()]
    for case in filter_cases() + list_cases():
        cases.append(dict(case, copy="primary"))
    return cases


# ---- comparison ----

def show(left, right):
    for index, (one, two) in enumerate(zip(left, right)):
        if one != two:
            return "event %d: %r, want %r" % (index, one, two)
    return "length %d, want %d" % (len(left), len(right))


def compare_run(harness, case):
    label = "%s %s/%s" % (case.get("kind", "sweep"), case["label"], case.get("copy", "primary"))
    try:
        if case.get("kind") == "filter":
            rows, want = harness.run_filter(case), filter_spec(case)
            return "" if rows == want else "%s: rows %r, want %r" % (label, rows, want)
        if case.get("kind") == "list":
            got, want = harness.run_list(case), list_spec(case)
            if got != want:
                return "%s: %r, want %r" % (label, got, want)
            if harness.nodes:
                return "%s: %d status nodes live" % (label, len(harness.nodes))
            events = [("collect", len(case["map"]))] + ([("drop list",)] if "failed" in want else [])
            return "" if harness.events == events else "%s: %s" % (label, show(harness.events, events))
        try:
            want = sweep_spec(case)
        except Panicked as panic:
            want = dict(panic=str(panic))
        try:
            result = harness.run_case(case)
        except Panicked as panic:
            return "" if want.get("panic") == str(panic) else "%s: panic %s" % (label, panic)
        if "panic" in want:
            return "%s: no panic" % label
        if harness.events != want["events"]:
            return "%s: %s" % (label, show(harness.events, want["events"]))
        if result != want["result"]:
            return "%s: result %#x" % (label, result)
        if harness.logs != want["logs"]:
            return "%s: logs %d, want %d" % (label, harness.logs, want["logs"])
        if sorted(harness.frees) != sorted(want["frees"]):
            return "%s: frees %r, want %r" % (label, sorted(harness.frees), sorted(want["frees"]))
        accounts = harness.account_dump()
        if accounts != want["accounts"]:
            return "%s: accounts differ: %r, want %r" % (label, sorted(accounts.items())[:3], sorted(want["accounts"].items())[:3])
        if set(harness.nodes.values()) != want["live"]:
            return "%s: row nodes live %r, want %r" % (label, set(harness.nodes.values()), want["live"])
        found, users = harness.counters()
        want_global = {at: value for at, value in want["globals"].items() if value}
        if found != want_global:
            return "%s: counters %r, want %r" % (label, found, want_global)
        want_users = {key: {at: value for at, value in block.items() if value} for key, block in want["users"].items()}
        if users != want_users:
            return "%s: user counters %r, want %r" % (label, users, want_users)
        return ""
    except Exception as stop:
        return "%s: stopped: %r" % (label, stop)


def relative_slots(image):
    return {slot: addend for slot, kind, addend, _ in image.relocations() if kind == 8}


# ---- static evidence ----

STUBS = (
    ("0x3739be0 in sweep cases", "user list, arguments checked, a B-tree of users with one flag byte given by the case; list cases run it whole"),
    ("0x33c3b00", "rayon collect under 0x3739be0; reference pairs and context checked, status tree given by the case; filter cases run the fold body 0x3767210 whole"),
    ("0x33f6900", "drop of the partly built list on the failure path; call recorded"),
    ("0x2755400, 0x46f2fe0, 0x46f2e60", "user state read; arguments checked, tier byte +0x3c given"),
    ("0x2731030, 0x4d3b330, 0x4d3b5c0", "tier cancel list; all 4 arguments checked, word and pointer given. 0x2731030 is mapped by #354"),
    ("0x373d8e0", "value report; arguments checked, the 4 words given. Listed by #629"),
    ("0x28db540, 0x48cfb90", "health read; arguments checked, words given. Mapped by others"),
    ("0x1f84640, 0x47d7550", "per-user counter map get-or-insert; arguments checked, a zeroed block returned"),
    ("0x3736bd0", "liquidation row builder; arguments checked, 0x80 row or tag 2 given. Mapped by others"),
    ("0x284f810, 0x4941fe0", "user set insert; arguments checked"),
    ("0x251a290, 0x47f71d0, 0x47f8550", "order builder over the list iterator; iterator words, user and block time checked, order count given. Mapped by #278"),
    ("0x26f4400, 0x4470be0", "order send; all arguments checked, including the 33 byte source and the mode word. Not modelled"),
    ("0x24fc8a0, 0x432b440, 0x432a990", "event flush; arguments checked"),
    ("0x28a7f20, 0x49a90c0, 0x28b6ea0, 0x49b2500, 0x33f5270", "map drops; arguments checked"),
    ("0x250d2a0, 0x47eaa20, 0x49b3140", "row drop and its first step in the copies; row user read back"),
    ("0x151f6f0", "date from day count, argument checked, packed word given by the case"),
)
REAL_HELPERS = (("0x33b0060", "consuming map iterator"), ("0x33bcbc0", "account map entry insert"), ("0x33beaa0", "user map entry insert"), ("0x2f34470", "account map split insert"), ("0x2f1cc20", "user map split insert"),
                ("0x3bd3eb0", "reference pair collect"), ("0x33b0bb0", "consuming status iterator"), ("0x3395f60", "list insert"), ("0x2f2ebd0", "list split insert"),
                ("0x32815f0", "value helper, listed by others; run as is, no mutants"))
GROUP_REASONS = "cold unwind, panic or allocation failure path"
POINTER = "pointer high bytes are 0 in the harness heap"
PAST_KEY = "moves the stop test past the last key; poison keys end the walk at the same row"
LENGTH = "node length read at another offset; poison keys end the walk at the same row"
DANGLING = "dangling pointer of an empty vector, never read"
TALL = "height of 8 or more, not built by the fixtures"
SOFT = "class 2 and class 3 take the same path, so the soft word has no effect here"
CODE = "failure code byte of 0x21a35e0; the sweep reads only the failure bit"
ITERATOR = "back handle or unused word of the map iterator"
STRIDE = "scan stride of the key walk; poison keys end the walk at the same row"
LOCAL = "the kept map fills in ascending order, so a key compare in it is always above"
FLOAT = "saturated sum minus 1 rounds to the same f64"
FRESH = "account map of the new user row is replaced before any read"
UNWIND = "flag read only by the unwind path"
REASONS = {0x2765839: "fill bytes past the last flag end the climb at the same node", 0x376727F: "word loaded and never read", 0x37672DE: SOFT, 0x37672E1: SOFT, 0x3767320: SOFT, 0x3739C24: ITERATOR, 0x3739C73: ITERATOR, 0x3739C7C: ITERATOR, 0x3739D10: ITERATOR,
           0x2765694: DANGLING, 0x27657A5: TALL, 0x2765873: TALL, 0x2765888: TALL, 0x2765B59: SOFT, 0x2765B5C: SOFT, 0x2765B95: SOFT, 0x276615A: "once path, reached with the word already 0 in a run of real order",
           0x27661AC: DANGLING, 0x2766463: DANGLING, 0x276646C: "list length word rewritten before the read", 0x2766565: TALL, 0x27665FA: POINTER, 0x2766633: TALL, 0x2766648: TALL, 0x2766700: PAST_KEY,
           0x276687F: "capacity limit, needs 2^59 rows", 0x27668E5: DANGLING, 0x2766AE7: "height word only bounds a walk that misses, and this read always finds the user after the move", 0x2766B75: "height word only bounds a walk that misses, and this read always finds the user after the move", 0x2766B94: DANGLING, 0x2766DB8: "panic message length; the panic stub reads no argument",
           0x21A3637: CODE, 0x21A365D: PAST_KEY, 0x21A36E8: CODE, 0x21A372C: FLOAT, 0x21A378A: CODE, 0x21A37B0: PAST_KEY, 0x21A3845: CODE, 0x21A3884: FLOAT, 0x21A38BE: CODE, 0x21A38CA: CODE, 0x21A38A1: "empty tree fails the b side either way",
           0x21A38A8: "empty tree fails the b side either way", 0x21A38E7: "empty tree fails the b side either way", 0x21A38EE: "empty tree fails the b side either way",
           0x3735F50: ITERATOR, 0x3735F8F: UNWIND, 0x3736048: ITERATOR, 0x3736158: STRIDE, 0x373622D: LOCAL, 0x3736243: LOCAL, 0x3736245: LOCAL, 0x3736258: LOCAL, 0x373625C: LOCAL, 0x3736260: LOCAL, 0x373628D: LOCAL,
           0x3736348: STRIDE, 0x3736429: LOCAL, 0x3736458: LOCAL, 0x373648D: LOCAL, 0x373676F: ITERATOR, 0x37367D8: FRESH, 0x37367E1: FRESH}


def rows_of(image, start):
    begin, end = image.exact_fde(start)
    return decode_range(image, begin, end)


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


def groups(image):
    return [("sweep primary", *image.exact_fde(COPIES[0]["entry"])), ("sides primary", *image.exact_fde(COPIES[0]["sides"])), ("claim shared", *image.exact_fde(CLAIM)),
            ("iterator drop primary", *image.exact_fde(COPIES[0]["drop_iter"])), ("filter shared", *image.exact_fde(FILTER)), ("list shared", *image.exact_fde(ROWS))]


def stepped_groups(image):
    rows = list(groups(image))
    for layout in COPIES[1:]:
        rows.append(("sweep " + layout["name"], *image.exact_fde(layout["entry"])))
    rows.append(("sides copy", *image.exact_fde(COPIES[1]["sides"])))
    rows.append(("iterator drop copy", *image.exact_fde(COPIES[1]["drop_iter"])))
    return rows


def constants(image):
    rows = []
    entry = image.exact_fde(COPIES[0]["entry"])
    claim = image.exact_fde(CLAIM)
    for name, span, pattern, value in (
        ("dust limit compare", entry, b"\x48\x3d" + struct.pack("<I", DUST), DUST),
        ("tier gate compare", entry, b"\x80\x78\x3c\x04", TIER_MIN),
        ("no list sentinel", entry, struct.pack("<Q", NO_LIST), NO_LIST),
        ("quotient limit high word", entry, struct.pack("<Q", SCALE - 1), SCALE - 1),
        ("scale divisor", entry, struct.pack("<Q", SCALE), SCALE),
        ("mode, scaled rows", entry, struct.pack("<I", MODE_SCALED), MODE_SCALED),
        ("mode, value rows", entry, struct.pack("<I", MODE_RATIO), MODE_RATIO),
        ("epoch day count", claim, b"\xbf" + struct.pack("<I", EPOCH_DAYS), EPOCH_DAYS),
    ):
        base = image.offset(span[0])
        at = bytes(image.blob[base:base + span[1] - span[0]]).find(pattern)
        if at < 0:
            raise EvidenceError("constant moved: " + name)
        rows.append({"name": name, "address": "%#x" % (span[0] + at), "value": value})
    at = image.offset(0x204560)
    if bytes(image.blob[at:at + 16]) != SYSTEM[:16]:
        raise EvidenceError("system address pattern moved")
    rows.append({"name": "system address fill, first 16 bytes", "address": "0x204560", "value": 0xBB})
    return rows


def call_map(image):
    wanted = [layout["entry"] for layout in COPIES]
    direct = direct_callers(image, wanted)
    return [{"function": "%#x" % target, "direct_calls_from": ["%#x" % site for site in direct[target]], "callers": sorted({"%#x" % image.fde(site)[0] for site in direct[target]})} for target in wanted]


def copy_calls(image):
    """Ordered direct call targets of each copy, from the decoded call rows."""
    rows = []
    for layout in COPIES:
        rows.append({"copy": layout["name"], "entry": "%#x" % layout["entry"], "calls": ["%#x" % row.target for row in rows_of(image, layout["entry"]) if row.op == "call" and row.target]})
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


def run_mutants(image, reached, cases):
    results = []
    harness = Harness(image)
    machine = harness.machine
    machine.step_limit = MUTANT_STEP_LIMIT
    by_va = {}
    for index, touched in enumerate(reached):
        if cases[index].get("copy") != "primary":
            continue
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
    if case.get("kind") == "filter":
        return "filter: %d rows kept" % min(len(filter_spec(case)), 2)
    if case.get("kind") == "list":
        return "list: failed" if "failed" in list_spec(case) else "list: built"
    try:
        want = sweep_spec(case)
    except Panicked:
        return "panic"
    kinds = {event[0] for event in want["events"]}
    if not kinds:
        return "gate closed"
    if want["result"] != OK_TAG:
        return "stopped with a code"
    if "send" in kinds:
        return "orders sent"
    if "claim" in kinds:
        return "rows moved, no order"
    if "set" in kinds:
        return "user set only"
    return "counters only" if want["globals"] else "no change"


def path_rows():
    return [
        ("0a", "filter", "0x3767210", "over all users in parallel: report score above hard = class 0, above mid = class 1, others leave; the system address leaves; flag = class 1 and score >= 1000000; a failed report keeps its byte and code, byte 2 leaves"),
        ("0b", "list", "0x3739be0", "in key order the first failed row stops with its code, the system address is skipped, the others enter a map of user to flag"),
        ("1", "gate", "0x2765600 head", "only +0x5b3 == 1 enters; any other byte returns 0x11"),
        ("2", "user list", "0x3739be0", "failure returns its code; rows are (user, flag) in key order"),
        ("3", "tier cancels", "0x2755400, 0x2731030", "state byte +0x3c >= 4 and bit 0 of +0x5b0 clear asks for a cancel word; else the word stays 0x8000000000000002"),
        ("4", "class", "0x373d8e0", "score above hard = 0, above mid = 1, above soft = 2, else 3; a failed report stops the sweep with its code"),
        ("5", "healthy or system", "class >= 2 or user 0xbb x 20", "word 0x8000000000000001 counts index 2, other negative words index 1, a positive word is freed; no row"),
        ("6", "unhealthy", "class 0 or 1", "counts index 3 by list flag and index 0 by low flag; low flag = class 1 and score >= 1000000"),
        ("7", "row", "0x28db540, 0x3736bd0", "failed health stops the sweep, negative words panic; tag 2 inserts the user in the set at +0x8b8, anything else pushes a 0x80 row"),
        ("8", "move", "0x3735db0", "every row token adds its 2 pairs to the system account, tag 3 ends the walk; the user keeps only the pairs with an odd tag and the old account map is dropped"),
        ("9", "amounts", "0x2765600 stage 2", "odd row tag: token map amount x token word +0x78 / 1e14, a missing token or quotient >= 2^64 drops the row; even tag: every b side row at share = ceil value of a / floor value of b, 1.0 when b is 0"),
        ("10", "send", "0x251a290, 0x26f4400, 0x24fc8a0", "orders built from the list; when any exist they are sent with source byte 1, mode 0x90009 for odd tags and 0x80008 for even tags, then flushed"),
        ("11", "final check", "0x28db540", "after the row, score above mid or hard counts index 4 by the row byte +0x7c; a failed health stops the sweep and drops the rows left"),
    ]


def class_samples(image):
    harness = Harness(image)
    rows = []
    for label, first, row in (
        ("under soft", (0, 0, 5, 10, 20, 30), True),
        ("above soft", (0, 0, 15, 10, 20, 30), True),
        ("at mid", (0, 0, 20, 10, 20, 30), True),
        ("above mid, under dust", (0, 0, 25, 10, 20, 30), True),
        ("above mid, at dust", (0, 0, DUST, 10, 20, DUST + 5), True),
        ("above hard", (0, 0, 31, 10, 20, 30), True),
        ("above hard, past dust", (0, 0, DUST * 2, 10, 20, 30), False),
    ):
        case = make(label, users=[dict(key=ONE, first=first, row=dict(CLAIM_ROW) if row else None)])
        if compare_run(harness, case):
            raise EvidenceError("sample mismatch: " + label)
        found, _ = harness.counters()
        built = [event for event in harness.events if event[0] == "build"]
        rows.append((label, first[2], first[3], first[4], first[5], user_class(*first[2:]), built[0][2] if built else "none", ",".join("%#x" % at for at in sorted(found)) or "none",
                     "row" if any(event[0] == "claim" for event in harness.events) else "set" if built else "none"))
    return rows


def move_samples(image):
    harness = Harness(image)
    rows = []
    for first in range(4):
        for second in range(4):
            case = make("sample", system={1: (5, 6, 7, 8)}, users=[row_user(accounts={1: (9, 9, 9, 9)}, row=dict(tag=1, rows=[(1, first, (0x11, 0x12), 500, 600, second, (0x13, 0x14), 700, 800), (2, 1, (0x21, 0x22), 1, 2, 2, (0, 0), 0, 0)]))])
            if compare_run(harness, case):
                raise EvidenceError("move sample mismatch")
            accounts = harness.account_dump()
            rows.append((first, second, ",".join(str(word) for word in accounts[SYSTEM][1].get(1, ())), ",".join(str(word) for word in accounts[ONE][1].get(1, ())) or "none", "yes" if 2 in accounts[ONE][1] else "no"))
    return rows


def amount_samples(image):
    harness = Harness(image)
    rows = []
    for label, row in (
        ("token 1, word 2e14", dict(tag=1, map=[(1, 1000, 0.5)])),
        ("token 2, word 2e14", dict(tag=1, map=[(2, 1000, 0.25)])),
        ("value sides", dict(tag=0, a=[(1, 1000)], b=[(2, 3000)])),
        ("no b value", dict(tag=0, a=[(1, 1000)], b=[(1, 0)])),
        ("missing token drops the row", dict(tag=1, map=[(1, 5, 0.5), (9, 5, 0.5)])),
        ("a side missing token drops the row", dict(tag=0, a=[(9, 1)], b=[(1, 5)])),
    ):
        tokens = dict(TOKENS)
        tokens[2] = (3 * PX, 2 * WEI)
        case = make(label, tokens=tokens, users=[row_user(row=row)])
        if compare_run(harness, case):
            raise EvidenceError("amount sample mismatch")
        orders = [event for event in harness.events if event[0] == "orders"]
        send = [event for event in harness.events if event[0] == "send"]
        rows.append((label, row["tag"], ";".join("%d:%d:%r" % item for item in orders[0][2]) if orders else "none", "%#x" % send[0][2] if send else "none"))
    return rows


def analyse(image, full=True):
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
        key = outcome_of(case)
        outcomes[key] = outcomes.get(key, 0) + 1
    touched = set().union(*reached)
    functions = []
    for role, begin, end in stepped_groups(image):
        rows = decode_range(image, begin, end)
        base = image.offset(begin)
        functions.append({"role": role, "start": "%#x" % begin, "end": "%#x" % end, "bytes": end - begin, "sha256": hashlib.sha256(bytes(image.blob[base:base + end - begin])).hexdigest(),
                          "instructions": len(rows), "instructions_stepped": sum(1 for row in rows if row.va in touched)})
    evidence = {
        "target_sha256": SHA256,
        "functions": functions,
        "call_map": call_map(image),
        "copy_calls": copy_calls(image),
        "constants": constants(image),
        "stubs": [{"edge": edge, "role": role} for edge, role in STUBS],
        "real_helpers": [{"function": edge, "role": role} for edge, role in REAL_HELPERS],
        "cases": {"total": len(cases), "sweep_per_copy": sum(1 for case in cases if case["kind"] == "sweep") // len(COPIES), "filter": sum(1 for case in cases if case["kind"] == "filter"), "list": sum(1 for case in cases if case["kind"] == "list"), "outcomes": dict(sorted(outcomes.items()))},
        "mismatches": mismatches,
        "first_mismatch": first,
        "instructions_stepped": machine.steps,
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
    return REASONS.get(row["va"], GROUP_REASONS)


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
    write_tsv(out / "class-samples.tsv", ("label", "score", "soft", "mid", "hard", "class", "low_flag", "exchange_counters", "result"), class_samples(image))
    write_tsv(out / "move-samples.tsv", ("first_tag", "second_tag", "system_token_1", "user_token_1", "user_keeps_token_2"), move_samples(image))
    write_tsv(out / "amount-samples.tsv", ("label", "row_tag", "list_token_amount_share", "mode"), amount_samples(image))
    lines = ["group\tva\tkind\tresult\tkilled_by\treason"]
    for row in results:
        reason = "" if row["result"] == "killed" else reason_for(row)
        lines.append("%s\t%#x\t%s\t%s\t%s\t%s" % (row["group"], row["va"], row["kind"], row["result"], row["by"], reason))
    (out / "mutations.tsv").write_text("\n".join(lines) + "\n", encoding="utf-8", newline="\n")
    print("cases %d, mismatches %d, mutants %r" % (evidence["cases"]["total"], evidence["mismatches"], evidence["mutations"]))
    return 0


if __name__ == "__main__":
    sys.exit(main())
