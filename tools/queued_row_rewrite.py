#!/usr/bin/env python3
"""Pin the node #94 rewrite of queued rows after a second insert, from ELF bytes: drivers, row tests, fill turn, fill totals.

When an order runs a second insert, a driver walks the 0x268 byte rows the first insert queued. `0x24f8f80`,
`0x43292e0` and `0x4329560` build one new 0xa8 order record and test each row: `0x24f92e0`, `0x47d6f80` and `0x47d7150`,
the last two through `0x47f4fc0`, `0x47f50d0` and `0x4472550`. Order rows with the old id take the new record, fill rows
of the other side are turned by `0x3790200`, and leg ids move to the new id. `0x24f8d90` and `0x47d6d90` total a list of
fills. The real bytes run in a Python evaluator with the callees at the edge stubbed. A separately written specification
predicts every row and stub argument, and every condition, immediate and field offset is flipped to show the run can
tell. No objdump or readelf output is parsed, and the binary is never executed. Standard library only.
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

DRIVER_A = 0x24F8F80
DRIVER_B = 0x43292E0
DRIVER_C = 0x4329560
RETAIN_B = 0x47F4FC0
RETAIN_C = 0x47F50D0
ROW_TEST_A = 0x24F92E0
ROW_TEST_B = 0x47D6F80
ROW_TEST_C = 0x47D7150
PREPARE = 0x4472550
LEG_COPY = 0x47C39B0
TURN = 0x3790200
TOTAL_A = 0x24F8D90
TOTAL_B = 0x47D6D90
LEGS = 0x3C18540
SIBLING = 0x37272C0
CLASS = 0x3728670
HOST_A = 0x26D2560
HOST_B = 0x4D12E80
HOST_C = 0x4D15710

SLOT_MEMCPY = 0x576DFE0
SLOT_BOUNDS = 0x576DFC8
SLOT_PANIC = 0x576E470
SLOT_NOUNWIND = 0x576E128
SLOT_TURN = 0x5774370
SLOT_CLASS = 0x5773198
SLOT_RECORDER = 0x5773190
SLOT_AMOUNT = 0x5774768
FAKE_MEMCPY = 0xFACE0010

LOC_META = 0x56F1FD8
LOC_TOKEN = 0x56F21F0
LOC_BOOK_A = 0x56BB460
LOC_BOOK_B = 0x5742320
LOC_LEG_ADD = 0x56DFD78
LOC_SUM_FIRST = 0x56B8570
LOC_SUM_SECOND = 0x56B8588
LOC_SUM_FIRST_B = 0x572ff98
LOC_SUM_SECOND_B = 0x572ffb0

ROW_SIZE = 0x268
FILL_STRIDE = 0x228
RECORD_SIZE = 0xA8
BOOK_STRIDE = 0xD8
TOKEN_STRIDE = 0xE8
LIST_STRIDE = 0x20
LEG_SIZE = 0xF8

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
HEAP_SIZE = 0x10000
RETURN_SENTINEL = 0xDEAD0000
POISON = 0xA5A5A5A5A5A5A5A5
STEP_LIMIT = 400000
MUTANT_STEP_LIMIT = 30000

BLOCK = HEAP_BASE + 0x100
REQUEST = HEAP_BASE + 0x200
VECTOR = HEAP_BASE + 0x300
OUT = HEAP_BASE + 0x400
PAIR = HEAP_BASE + 0x7E0
STATE = HEAP_BASE + 0x1000
SPOT_META = STATE + 0x90
BOOKS = HEAP_BASE + 0x5000
TOKENS = HEAP_BASE + 0x6000
LISTS = HEAP_BASE + 0x6C00
SPOTS = HEAP_BASE + 0x6E00
SIBLING_ROW = HEAP_BASE + 0x7000
ROWS = HEAP_BASE + 0x8000
IMAGE = HEAP_BASE + 0xC000

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


# ---- specification, written from a full read of the bytes, separate from the evaluator ----

RAMPS = {}


def ramp(size, start):
    """Non-periodic filler, so that a wrong field offset reads a wrong value."""
    key = (size, start)
    if key not in RAMPS:
        RAMPS[key] = bytes((start + index * 37 + (index >> 4)) & 0xFF | 1 for index in range(size))
    return RAMPS[key]


COPIES = {
    "a": {"driver": DRIVER_A, "view": 0x26E16F0, "clone": 0x254DED0, "drop": 0x2508760, "finish": 0x2508760, "row_drop": 0x25024E0, "books": 0x3388, "panic_book": LOC_BOOK_A},
    "b": {"driver": DRIVER_B, "view": 0x42FE970, "clone": 0x4846F60, "drop": 0x47E6190, "finish": 0x4349370, "row_drop": 0x47E0520, "books": 0x3E08, "panic_book": LOC_BOOK_B},
    "c": {"driver": DRIVER_C, "view": 0x42FE970, "clone": 0x4846F60, "drop": 0x47E6190, "finish": 0x4349370, "row_drop": 0x47E0520, "books": 0x3388, "panic_book": LOC_BOOK_B},
}


def word(data, at, width=8):
    return int.from_bytes(data[at:at + width], "little")


def put_word(data, at, width, value):
    data[at:at + width] = (value & MASK[width]).to_bytes(width, "little")


def leg_view(leg):
    """The bytes the row test hands on for one leg, as (offset, bytes), with None payloads left out."""
    rows = []

    def tag(at, wide=8):
        value = 1 if word(leg, at, 4 if wide == 8 else 1) == 1 else 0
        rows.append((at, value.to_bytes(wide, "little")))
        return value

    if tag(0):
        rows.append((8, leg[8:0x18]))
    rows.append((0x18, leg[0x18:0x28]))
    if tag(0x28):
        rows.append((0x30, leg[0x30:0x50]))
    rows.append((0x50, leg[0x50:0x60]))
    middle = word(leg, 0x60)
    if middle == 2:
        rows.append((0x60, (2).to_bytes(8, "little")))
    else:
        low = middle & 1
        rows.append((0x60, low.to_bytes(8, "little")))
        if low:
            rows.append((0x68, leg[0x68:0x84]))
        if tag(0x88):
            rows.append((0x90, leg[0x90:0xAC]))
        rows.append((0xB0, leg[0xB0:0xC8]))
    rows.append((0xC8, leg[0xC8:0xE4]))
    if tag(0xE4, 1):
        rows.append((0xE5, leg[0xE5:0xF5]))
    return rows


def image_view(row):
    """Everything the transform can trust in its input, from one 0x268 row."""
    rows = []
    for base in (8, 8 + LEG_SIZE):
        rows += [(base - 8 + at, data) for at, data in leg_view(row[base:base + LEG_SIZE])]
    rows.append((0x1F0, row[0x1F8:0x210]))
    rows.append((0x208, row[0x210:0x218]))
    rows.append((0x210, row[0x218:0x220]))
    rows.append((0x218, row[0x220:0x22D]))
    return tuple((at, bytes(data)) for at, data in rows)


def turned_out(start, tag, words):
    """What the stubbed transform writes: a row image with the words a case wants."""
    out = bytearray(ramp(0x258, start))
    put_word(out, 0, 8, tag)
    for at, value in words.items():
        put_word(out, at, 8, value)
    return out


def spec_total(fills, locations=(LOC_SUM_FIRST, LOC_SUM_SECOND)):
    """0x24f8d90: fills are (key, first, second). Totals saturate and record; one key; first in 1..=second."""
    events = []
    if not fills:
        return {"answer": None, "events": events}
    key, first, second = fills[0]
    same = True
    for other, more_first, more_second in fills[1:]:
        if first + more_first > MASK[8]:
            events.append(("recorded", locations[0]))
        first = min(first + more_first, MASK[8])
        if second + more_second > MASK[8]:
            events.append(("recorded", locations[1]))
        second = min(second + more_second, MASK[8])
        if other != key:
            same = False
            break
    if not same or first == 0 or first > second:
        return {"answer": None, "events": events}
    return {"answer": (second // first, first, second, key), "events": events}


def spec_turn(w):
    """0x3790200: turn one fill to the sibling book, or say why not."""
    image = w["image"]
    spot, px, size = word(image, 0x1F0), word(image, 0x1F8), word(image, 0x200)
    side = image[0x224]
    events = []
    answer = {"events": events, "stop": None, "out": None}

    def code(value):
        answer["out"] = {"tag": 3, "byte": value}
        return answer

    if px == 0:
        return code(9)
    spots = w["spots"]
    if spot >= len(spots):
        answer["stop"] = ("bounds", spot, len(spots), LOC_META)
        return answer
    events.append(("class", SPOT_META, spots[spot][0]))
    if w["class"] < 2:
        answer["out"] = {"tag": 2}
        return answer
    events.append(("sibling", SPOT_META, spot, SPOTS, len(spots)))
    error = w["sibling"].get("error")
    if error is not None:
        return code(error)
    token = w["sibling"]["token"]
    tokens = w["tokens"]
    if token >= len(tokens):
        answer["stop"] = ("panic", LOC_TOKEN)
        return answer
    if tokens[token]["count"] != 1:
        return code(0)
    value = w["sibling"]["value"]
    if value < px:
        return code(8)
    if value == px:
        return code(9)
    book = tokens[token]["book"]
    if book >= len(spots):
        answer["stop"] = ("bounds", book, len(spots), LOC_META)
        return answer
    turned = value - px
    if w["pair"]:
        result = w["legs"]
        events.append(("legs", IMAGE, side, side ^ 1, PAIR, SPOT_META, spots[book][0], size, turned, spots[spot][1]))
        tags = (result[0], result[2])
        bytes_ = (result[1], result[3])
        if tags[0] == 2:
            return code(bytes_[0])
        if tags[1] == 2:
            return code(bytes_[1])
        body_a, body_b = ramp(0xEF, 0x37), ramp(0xEF, 0x62)
    else:
        tags = (word(image, 0), word(image, LEG_SIZE))
        bytes_ = (image[8], image[LEG_SIZE + 8])
        body_a, body_b = image[9:LEG_SIZE], image[LEG_SIZE + 9:2 * LEG_SIZE]
    product = turned * size
    if product > MASK[8] or product > 0x7FFFFFFFFFFFFFFE or tags[1] == 2:
        return code(0x11)
    out = bytearray(0x225)
    put_word(out, 0, 8, tags[1])
    out[8] = bytes_[1]
    out[9:LEG_SIZE] = body_b
    put_word(out, LEG_SIZE, 8, tags[0])
    out[LEG_SIZE + 8] = bytes_[0]
    out[LEG_SIZE + 9:2 * LEG_SIZE] = body_a
    put_word(out, 0x1F0, 8, turned)
    put_word(out, 0x1F8, 8, book)
    put_word(out, 0x200, 8, size)
    put_word(out, 0x208, 8, product)
    put_word(out, 0x210, 8, 0)
    out[0x218:0x224] = image[0x218:0x224]
    out[0x224] = side ^ 1
    answer["out"] = {"tag": "turned", "bytes": bytes(out)}
    return answer


def spec_legs(w):
    """0x3c18540: side 0 runs the first leg through the pair and keeps the second, any other side the reverse."""
    image = w["image"]
    side, flip = w["side"], w["flip"]
    base, quote = w["pair_words"]
    ok, amount = w["amount"]
    size, price = w["size"], w["price"]
    events = []
    pair_bytes = base.to_bytes(8, "little") + quote.to_bytes(8, "little")
    legs = [(word(image, 0), image[8], bytes(image[9:LEG_SIZE])), (word(image, LEG_SIZE), image[LEG_SIZE + 8], bytes(image[LEG_SIZE + 9:2 * LEG_SIZE]))]
    index = 0 if side == 0 else 1
    events.append(("amount", SPOT_META, w["word"], size))
    code = 0xB
    if ok & 1:
        if flip:
            if base >= amount:
                base -= amount
        else:
            if base + amount > MASK[8]:
                events.append(("recorded", LOC_LEG_ADD))
            base = min(base + amount, MASK[8])
        code = 0xC
        product = size * price
        if product <= 0x7FFFFFFFFFFFFFFE:
            code = None
            if side == 1:
                if quote >= product:
                    quote -= product
            else:
                if quote + product > MASK[8]:
                    events.append(("recorded", LOC_LEG_ADD))
                quote = min(quote + product, MASK[8])
    if code is None:
        legs[index] = (1, pair_bytes[0], pair_bytes[1:16] + legs[index][2][15:])
    else:
        legs[index] = (2, code, None)
    return {"events": events, "legs": legs, "pair": (base, quote), "order": index}


def spec_rewrite(case):
    w = case.world
    copy = COPIES[case.copy]
    new_tag, new_value = w["new"]
    old = w["old"]
    chosen = new_value if new_tag else old
    index = word(w["request"], 0x28)
    answer = {"events": [], "stop": None, "rows": None, "length": None}
    events = answer["events"]
    if index >= w["books"]:
        answer["stop"] = ("bounds", index, w["books"], copy["panic_book"])
        return answer
    events.append(("view", BOOKS + index * BOOK_STRIDE) + view_fields(w["request"], index, chosen, w["clock"], w["user"]))
    view = view_record(chosen, w["start"])
    side = w["request"][0x30]
    rows = [bytearray(row) for row in w["rows"]]
    kept = 0
    removed = False
    for at, row in enumerate(rows):
        keep = True
        tag = word(row, 0)
        kind = tag - 2 if tag >= 2 else 7
        if kind == 1:
            sub = word(row, 8)
            inner = sub - 2 if sub >= 2 else 1
            if inner in (0, 1):
                base, flag = (0x38, 0x100) if inner == 0 else (0x30, 0x119)
                if word(row, base + 0x70) == old:
                    size = struct.unpack_from("<d", row, base + 0x68)[0]
                    events.append(("clone",))
                    events.append(("drop", at, base))
                    row[base:base + RECORD_SIZE] = view
                    struct.pack_into("<d", row, base + 0x68, size + w["add"])
                if new_tag & 0xFF and word(row, base + 0x70) == new_value:
                    keep = row[flag] != 1
        elif kind == 6 or kind >= 9:
            if row[0x23A] != side:
                stop = turn_row(case, w, row, at, events)
                if stop:
                    answer["stop"] = stop
                    return answer
            for field in (0xD0, 0x1C8):
                if word(row, field) == old:
                    put_word(row, field, 8, chosen)
        if not keep:
            events.append(("row drop", at))
            removed = True
        else:
            if removed:
                rows[kept] = bytearray(row)
            kept += 1
    events.append(("finish",))
    answer["rows"] = [bytes(row) for row in rows[:kept]]
    answer["length"] = kept
    return answer


def turn_row(case, w, row, at, events):
    """The fill arm of a row test. Returns a stop, or None after changing the row in place."""
    amount = word(row, 0x230)
    spot = word(row, 0x1F8)
    turned_amount = 0
    if amount:
        events.append(("sibling", SPOT_META, spot, SPOTS, len(w["spots"])))
        result = w["sibling_by_row"].get(at, w["sibling"])
        if result.get("error") is not None:
            return None
        token = result["token"]
        if token >= len(w["tokens"]):
            return ("panic", LOC_TOKEN)
        if w["tokens"][token]["count"] != 1 or result["value"] <= amount:
            return None
        turned_amount = result["value"] - amount
    tag, words = w["turn"].get(at, (2, {}))
    events.append(("turn", SPOT_META, IMAGE_MARK, PAIR_WORDS, image_view(row)))
    if tag >= 2:
        return None
    out = turned_out(0x40 + at, tag, words)
    side = row[0x23A]
    put_word(row, 8, 8, tag)
    row[0x10:0x1F8] = out[8:0x1F0]
    put_word(row, 0x1F8, 8, word(out, 0x1F8))
    put_word(row, 0x200, 8, word(out, 0x1F0))
    put_word(row, 0x208, 8, word(out, 0x200))
    put_word(row, 0x210, 8, word(out, 0x208))
    put_word(row, 0x218, 8, word(out, 0x210))
    put_word(row, 0x220, 8, word(out, 0x218))
    put_word(row, 0x228, 4, word(out, 0x220, 4))
    row[0x22C] = out[0x224]
    put_word(row, 0x230, 8, turned_amount)
    row[0x23A] = side ^ 1
    return None


IMAGE_MARK = "image"
PAIR_WORDS = (0x1234, 0x5678)


def view_fields(request, index, chosen, clock, user):
    """The request block the driver hands to the record builder, as named pieces."""
    two = request[0x19] == 2
    has_cloid = request[0x32] == 1
    return (word(request, 0), word(request, 8), word(request, 0x10), request[0x18], request[0x19], bytes(request[0x1A:0x20]) if two else b"",
            word(request, 0x20), index, request[0x30], request[0x31], int(has_cloid), bytes(request[0x33:0x43]) if has_cloid else b"",
            0, 0, 8, 0, SPOT_META, chosen, clock, user)


def view_record(chosen, start):
    record = bytearray(ramp(RECORD_SIZE, start))
    put_word(record, 0x70, 8, chosen)
    struct.pack_into("<d", record, 0x68, 2.5)
    return bytes(record)


# ---- harness: real bytes; the callees at the edge are stubbed and their arguments compared ----

class RealExcept:
    """Every call target runs its real bytes unless the harness stubs it."""

    def __init__(self):
        self.stubs = frozenset()

    def __contains__(self, target):
        return target not in self.stubs


class Case:
    def __init__(self, label, kind, copy, world):
        self.label = label
        self.kind = kind
        self.copy = copy
        self.world = world


class Harness:
    def __init__(self, image):
        self.image = image
        self.machine = Machine(image)
        machine = self.machine
        self.relative = {slot: addend for slot, kind, addend, _ in image.relocations() if kind == 8}
        machine.memory.statics.update(self.relative)
        relative = self.relative
        machine.memory.statics[SLOT_MEMCPY] = FAKE_MEMCPY
        machine.slots = {relative[SLOT_PANIC]: self.on_panic, relative[SLOT_BOUNDS]: self.on_bounds, FAKE_MEMCPY: self.on_memcpy, relative[SLOT_RECORDER]: self.on_recorder}
        self.turn_hook = relative[SLOT_TURN]
        self.class_hook = relative[SLOT_CLASS]
        self.amount_hook = relative[SLOT_AMOUNT]
        self.base_slots = dict(machine.slots)
        self.real = RealExcept()
        machine.real = self.real
        self.events = []
        self.case = None

    def on_panic(self, m):
        raise Panicked(("panic", m.regs[RDI]))

    def on_bounds(self, m):
        raise Panicked(("bounds", m.regs[RDI], m.regs[RSI], m.regs[RDX]))

    def on_recorder(self, m):
        if m.regs[RDI] != 0:
            raise Halt("recorder argument")
        self.events.append(("recorded", m.regs[RSI]))

    def on_memcpy(self, m):
        count = m.regs[RDX]
        if count > 0x400:
            raise Halt("copy size")
        if count:
            m.memory.copy(m.regs[RDI], m.regs[RSI], count)
        m.regs[RAX] = m.regs[RDI]

    def stubs(self, slots, calls):
        machine = self.machine
        machine.slots = dict(self.base_slots)
        machine.slots.update(slots)
        machine.calls = calls
        self.real.stubs = frozenset(machine.slots) | frozenset(calls)

    def on_view(self, m):
        memory = m.memory
        block = m.regs[RDX]
        read = memory.bytes_at(block, 0xB8)
        two = read[0x19] == 2
        has = read[0x32]
        self.events.append(("view", m.regs[RSI], word(read, 0), word(read, 8), word(read, 0x10), read[0x18], read[0x19], read[0x1A:0x20] if two else b"",
                            word(read, 0x20), word(read, 0x28), read[0x30], read[0x31], has, read[0x33:0x43] if has else b"",
                            word(read, 0x48), word(read, 0x70), word(read, 0x78), word(read, 0x80), word(read, 0x88), word(read, 0x90), read[0x98:0xA4], read[0xA4:0xB8]))
        chosen = word(read, 0x90)
        self.view_at = m.regs[RDI]
        memory.put_bytes(self.view_at, view_record(chosen, self.case.world["start"]))
        m.regs[RAX] = m.regs[RDI]

    def on_clone(self, m):
        if m.regs[RSI] != self.view_at:
            raise Halt("clone of another record")
        self.events.append(("clone",))
        m.memory.copy(m.regs[RDI], m.regs[RSI], RECORD_SIZE)
        m.regs[RAX] = m.regs[RDI]

    def on_drop(self, m):
        if m.regs[RDI] == self.view_at:
            self.events.append(("finish",))
            return
        at, base = divmod(m.regs[RDI] - ROWS, ROW_SIZE)
        self.events.append(("drop", at, base))

    def on_row_drop(self, m):
        at, rest = divmod(m.regs[RDI] - ROWS, ROW_SIZE)
        self.events.append(("row drop", at if not rest else -1))

    def on_sibling(self, m):
        out, meta, spot, listed, length = m.regs[RDI], m.regs[RSI], m.regs[RDX], m.regs[RCX], m.regs[R8]
        self.events.append(("sibling", meta, spot, listed, length))
        w = self.case.world
        at = len([event for event in self.events if event[0] == "sibling"]) - 1
        result = self.sibling_rows.get(at, w.get("sibling", {}))
        memory = m.memory
        if result.get("error") is not None:
            memory.write(out, 1, 1)
            memory.write(out + 1, 1, result["error"])
        else:
            memory.write(out, 1, 0)
            memory.write(out + 8, 8, SIBLING_ROW)
            memory.write(SIBLING_ROW + 0x18, 8, result["value"])
            memory.write(SIBLING_ROW + 0x20, 8, result["token"])
        m.regs[RAX] = out

    def on_turn(self, m):
        out, meta, image_at, pair = m.regs[RDI], m.regs[RSI], m.regs[RDX], m.regs[RCX]
        memory = m.memory
        row_at = self.turn_rows.pop(0) if self.turn_rows else None
        if row_at is None:
            raise Halt("turn on an unexpected row")
        view = image_view(self.expected_row(row_at))
        found = tuple((at, memory.bytes_at(image_at + at, len(data))) for at, data in view)
        self.events.append(("turn", meta, IMAGE_MARK, (memory.read(pair, 8), memory.read(pair + 8, 8)), found))
        tag, words = self.case.world["turn"].get(row_at, (2, {}))
        memory.put_bytes(out, bytes(turned_out(0x40 + row_at, tag, words)))
        m.regs[RAX] = out

    def expected_row(self, at):
        return self.case.world["rows"][at]

    def write_world(self, w):
        memory = self.machine.memory
        put = memory.write
        put(STATE + 0x60, 8, word(w["clock"], 0))
        put(STATE + 0x68, 4, word(w["clock"], 8, 4))
        put(STATE + 0x1F8, 8, SPOTS)
        put(STATE + 0x200, 8, len(w["spots"]))
        put(STATE + 0x210, 8, TOKENS)
        put(STATE + 0x218, 8, len(w["tokens"]))
        for index, row in enumerate(w["spots"]):
            put(SPOTS + index * LIST_STRIDE, 8, row[0])
            put(SPOTS + index * LIST_STRIDE + 8, 8, row[1])
        for index, row in enumerate(w["tokens"]):
            memory.put_bytes(TOKENS + index * TOKEN_STRIDE, ramp(TOKEN_STRIDE, 0x11 + index))
            put(TOKENS + index * TOKEN_STRIDE + 0x60, 8, row["count"])
            put(TOKENS + index * TOKEN_STRIDE + 0x58, 8, LISTS + index * 8)
            put(LISTS + index * 8, 8, row["book"])

    def run_total(self, case):
        w = case.world
        memory = self.machine.memory
        self.stubs({}, {})
        fills = w["fills"]
        memory.reset()
        for index, (key, first, second) in enumerate(fills):
            at = ROWS + index * FILL_STRIDE
            memory.put_bytes(at, ramp(FILL_STRIDE, 0x21 + index))
            memory.write(at + 0x1F8, 8, key)
            memory.write(at + 0x200, 8, first)
            memory.write(at + 0x208, 8, second)
        memory.write(OUT, 8, 0x55)
        self.events = []
        entry = TOTAL_A if case.copy == "a" else TOTAL_B
        self.machine.run(entry, {RDI: OUT, RSI: ROWS, RDX: len(fills)})
        out = [memory.read(OUT + index * 8, 8) for index in range(4)]
        if out[0] == 0 and not any(self.answer_flag(w)):
            return {"answer": None, "events": self.events}
        return {"answer": tuple(out), "events": self.events}

    def answer_flag(self, w):
        return [spec_total(w["fills"])["answer"] is not None]

    def run_turn(self, case):
        w = case.world
        machine = self.machine
        memory = machine.memory
        self.events = []
        self.case = case

        def on_class(m):
            self.events.append(("class", m.regs[RDI], m.regs[RSI]))
            m.regs[RAX] = w["class"]

        def on_legs(m):
            closure = [memory.read(m.regs[RDX] + index * 8, 8) for index in range(8)]
            self.events.append(("legs", m.regs[RSI], memory.read(closure[0], 1), memory.read(closure[2], 1), closure[1], closure[3], memory.read(closure[4], 8), memory.read(closure[5], 8), memory.read(closure[6], 8), memory.read(closure[7], 8)))
            result = w["legs"]
            out = m.regs[RDI]
            memory.write(out, 8, result[0])
            memory.write(out + 8, 1, result[1])
            memory.put_bytes(out + 9, ramp(0xEF, 0x37))
            memory.write(out + 0xF8, 8, result[2])
            memory.write(out + 0x100, 1, result[3])
            memory.put_bytes(out + 0x101, ramp(0xEF, 0x62))
            m.regs[RAX] = out

        self.sibling_rows = {}
        self.stubs({self.class_hook: on_class}, {LEGS: on_legs, SIBLING: self.on_sibling})
        memory.reset()
        self.write_world(w)
        memory.put_bytes(IMAGE, w["image"])
        memory.write(OUT, 8, 0x77)
        rax = machine.run(TURN, {RDI: OUT, RSI: SPOT_META, RDX: IMAGE, RCX: PAIR if w["pair"] else 0})
        if rax != OUT:
            raise Halt("result pointer")
        tag = memory.read(OUT, 8)
        if tag == 2:
            out = {"tag": 2}
        elif tag == 3:
            out = {"tag": 3, "byte": memory.read(OUT + 8, 1)}
        else:
            out = {"tag": "turned", "bytes": memory.bytes_at(OUT, 0x225)}
        return {"events": self.events, "stop": None, "out": out}

    def run_legs(self, case):
        w = case.world
        machine = self.machine
        memory = machine.memory
        self.events = []
        self.sibling_rows = {}

        def on_amount(m):
            self.events.append(("amount", m.regs[RDI], m.regs[RSI], m.regs[RDX]))
            m.regs[RAX] = w["amount"][0]
            m.regs[RDX] = w["amount"][1]
            m.keep_rdx = True

        self.stubs({self.amount_hook: on_amount}, {})
        memory.reset()
        memory.put_bytes(IMAGE, w["image"])
        memory.write(PAIR, 8, w["pair_words"][0])
        memory.write(PAIR + 8, 8, w["pair_words"][1])
        cells = BLOCK
        for index, (width, value) in enumerate(((1, w["side"]), (1, w["flip"]), (8, w["word"]), (8, w["size"]), (8, w["price"]))):
            memory.write(cells + index * 8, width, value)
        closure = REQUEST
        for index, value in enumerate((cells, PAIR, cells + 8, SPOT_META, cells + 16, cells + 24, cells + 32, 0)):
            memory.write(closure + index * 8, 8, value)
        rax = machine.run(LEGS, {RDI: OUT, RSI: IMAGE, RDX: closure})
        if rax != OUT:
            raise Halt("result pointer")
        legs = []
        for base in (0, LEG_SIZE):
            tag = memory.read(OUT + base, 8)
            legs.append((tag, memory.read(OUT + base + 8, 1), None if tag == 2 else memory.bytes_at(OUT + base + 9, 0xEF)))
        return {"events": self.events, "legs": legs, "pair": (memory.read(PAIR, 8), memory.read(PAIR + 8, 8)), "order": 0 if w["side"] == 0 else 1}

    def run_rewrite(self, case):
        w = case.world
        copy = COPIES[case.copy]
        machine = self.machine
        memory = machine.memory
        self.case = case
        self.events = []
        self.view_at = None
        self.sibling_rows = dict(w["sibling_by_row"])
        self.turn_rows = list(w["turn_order"])
        slots = {self.turn_hook: self.on_turn}
        calls = {copy["view"]: self.on_view, copy["clone"]: self.on_clone, copy["drop"]: self.on_drop, copy["finish"]: self.on_drop, copy["row_drop"]: self.on_row_drop, SIBLING: self.on_sibling}
        self.stubs(slots, calls)
        memory.reset()
        self.write_world(w)
        memory.write(STATE + copy["books"], 8, BOOKS)
        memory.write(STATE + copy["books"] + 8, 8, w["books"])
        memory.put_bytes(REQUEST, w["request"])
        memory.write(BLOCK, 8, w["new"][0])
        memory.write(BLOCK + 8, 8, w["new"][1])
        memory.write(BLOCK + 0x10, 8, REQUEST)
        memory.write(BLOCK + 0x18, 8, STATE)
        memory.write(BLOCK + 0x20, 8, 0x1234)
        memory.write(BLOCK + 0x28, 8, 0x5678)
        memory.write(BLOCK + 0x30, 8, w["old"])
        memory.write(BLOCK + 0x38, 8, to_bits(w["add"]))
        memory.put_bytes(BLOCK + 0x40, w["user"])
        memory.write(VECTOR, 8, 99)
        memory.write(VECTOR + 8, 8, ROWS)
        memory.write(VECTOR + 0x10, 8, len(w["rows"]))
        for index, row in enumerate(w["rows"]):
            memory.put_bytes(ROWS + index * ROW_SIZE, row)
        answer = {"events": self.events, "stop": None, "rows": None, "length": None}
        try:
            machine.run(copy["driver"], {RDI: VECTOR, RSI: BLOCK})
        except Panicked as stop:
            answer["stop"] = stop.args[0]
            return answer
        length = memory.read(VECTOR + 0x10, 8)
        if length > 16:
            raise Halt("row count")
        answer["length"] = length
        answer["rows"] = [memory.bytes_at(ROWS + index * ROW_SIZE, ROW_SIZE) for index in range(length)]
        return answer

    def run(self, case):
        if case.kind == "total":
            return self.run_total(case)
        if case.kind == "turn":
            return self.run_turn(case)
        if case.kind == "legs":
            return self.run_legs(case)
        return self.run_rewrite(case)


def spec_run(case):
    if case.kind == "total":
        return spec_total(case.world["fills"], (LOC_SUM_FIRST, LOC_SUM_SECOND) if case.copy == "a" else (LOC_SUM_FIRST_B, LOC_SUM_SECOND_B))
    if case.kind == "turn":
        return spec_turn(case.world)
    if case.kind == "legs":
        return spec_legs(case.world)
    return spec_rewrite(case)


def scrub(rows):
    """Bytes 0x22d..0x22f and those from 0x25c on are padding, and a stack copy can leave them stale."""
    return [row[:0x22D] + row[0x230:0x25C] for row in rows]


CRASHES = (Halt, IndexError, KeyError, OverflowError, ValueError, TypeError, ZeroDivisionError, EvidenceError)


def compare_run(harness, case):
    """Empty when the bytes and the specification agree, else one line."""
    wanted = spec_run(case)
    try:
        found = harness.run(case)
    except Panicked as stop:
        found = {"events": harness.events, "stop": stop.args[0], "out": None}
        if case.kind == "turn" and wanted["stop"] == found["stop"] and wanted["events"] == found["events"]:
            return ""
        return "%s: unexpected stop %s" % (case.label, stop.args[0])
    except CRASHES as error:
        return "%s: crash %s %s" % (case.label, type(error).__name__, error)
    if case.kind == "rewrite" and found["rows"] is not None and wanted["rows"] is not None:
        found = dict(found)
        wanted = dict(wanted)
        found["rows"] = scrub(found["rows"])
        wanted["rows"] = scrub(wanted["rows"])
    if found != wanted:
        keys = sorted(key for key in wanted if found.get(key) != wanted[key])
        detail = ""
        if keys:
            detail = "%s found %s wanted %s" % (keys[0], str(found.get(keys[0]))[:300], str(wanted[keys[0]])[:300])
        return "%s: differs: %s" % (case.label, detail)
    return ""


# ---- cases ----

USER = bytes(range(0x61, 0x75))
CLOCK = bytes(range(0xA1, 0xAD))
OLD_ID = 0x1122334455667788
NEW_ID = 0x0102030405060708


def make_row(tag, start=0x13, fields=None, legs=()):
    row = bytearray(ramp(ROW_SIZE, start))
    put_word(row, 0, 8, tag)
    for at, (width, value) in (fields or {}).items():
        put_word(row, at, width, value)
    return bytes(row)


def order_row(sub=2, oid=OLD_ID, flag=0, size=1.5, start=0x13):
    base = 0x38 if sub == 2 else 0x30
    fields = {8: (8, sub), base + 0x70: (8, oid), 0x100: (1, flag), 0x119: (1, flag)}
    row = bytearray(make_row(3, start, fields))
    struct.pack_into("<d", row, base + 0x68, size)
    return bytes(row)


def fill_row(side=1, amount=0, spot=2, ids=(1, 2), tag=8, start=0x17, more=None):
    fields = {8: (8, 1), 0x30: (8, 1), 0x68: (8, 1), 0x90: (8, 1), 0xEC: (1, 1), 0x100: (8, 1), 0x128: (8, 1), 0x160: (8, 1), 0x188: (8, 1), 0x1E4: (1, 1),
              0xD0: (8, ids[0]), 0x1C8: (8, ids[1]), 0x1F8: (8, spot), 0x230: (8, amount), 0x23A: (1, side)}
    fields.update(more or {})
    return make_row(tag, start, fields)


def request(asset=1, k=2, m=3, side=0, cloid=1, start=0x29):
    data = bytearray(ramp(0x50, start))
    put_word(data, 0, 8, 1)
    put_word(data, 8, 8, 0x4000)
    put_word(data, 0x10, 8, 0x77)
    data[0x18] = m
    data[0x19] = k
    put_word(data, 0x20, 8, 0x9000)
    put_word(data, 0x28, 8, asset)
    data[0x30] = side
    data[0x31] = 1
    data[0x32] = cloid
    return bytes(data)


def world(rows=(), **change):
    w = {"rows": list(rows), "request": request(), "new": (1, NEW_ID), "old": OLD_ID, "add": 0.25, "user": USER, "clock": CLOCK, "start": 0x33, "books": 3,
         "spots": [(100 + index, 200 + index) for index in range(5)], "tokens": [{"count": 1, "book": index} for index in range(4)],
         "sibling": {"value": 0x1000, "token": 1}, "sibling_by_row": {}, "turn": {}, "turn_order": []}
    w.update(change)
    return w


def rewrite_cases():
    table = []

    def add(label, rows=(), **change):
        w = world(rows, **change)
        order = []
        for at, row in enumerate(w["rows"]):
            tag = word(row, 0)
            kind = tag - 2 if tag >= 2 else 7
            if (kind == 6 or kind >= 9) and row[0x23A] != w["request"][0x30]:
                amount = word(row, 0x230)
                result = w["sibling_by_row"].get(at, w["sibling"])
                if amount and (result.get("error") is not None or result["token"] >= len(w["tokens"]) or w["tokens"][result["token"]]["count"] != 1 or result["value"] <= amount):
                    continue
                order.append(at)
        w["turn_order"] = order
        table.append((label, w))

    add("no rows")
    add("book index past the list", [order_row()], request=request(asset=3))
    add("last book", [order_row()], request=request(asset=2), books=3)
    add("book index zero", [order_row()], request=request(asset=0))
    for k in (0, 1, 2, 3):
        add("request k %d" % k, [order_row()], request=request(k=k))
    for cloid in (0, 1, 2):
        add("cloid flag %d" % cloid, [order_row()], request=request(cloid=cloid))
    add("no new id", [order_row()], new=(0, NEW_ID))
    add("new id tag with a zero low byte", [order_row()], new=(0x100, NEW_ID))
    add("new id tag 2", [order_row(oid=NEW_ID, flag=1)], new=(2, NEW_ID))
    for tag in range(0, 13):
        add("plain row tag %d" % tag, [make_row(tag, 0x41, {8: (8, 9), 0x68: (8, OLD_ID), 0xA8: (8, OLD_ID), 0xD0: (8, 5), 0x1C8: (8, 6), 0x23A: (1, 0)})])
        add("old id row tag %d" % tag, [make_row(tag, 0x43, {8: (8, 2), 0xA8: (8, OLD_ID), 0xA0: (8, OLD_ID), 0xD0: (8, OLD_ID), 0x1C8: (8, OLD_ID), 0x23A: (1, 0)})])
    for sub in (0, 1, 2, 3, 4, 5, 7):
        for oid in (OLD_ID, 77):
            for flag in (0, 1, 2):
                add("order row sub %d oid %#x flag %d" % (sub, oid, flag), [order_row(sub, oid, flag)])
                add("order row sub %d oid %#x flag %d new id on it" % (sub, oid, flag), [order_row(sub, NEW_ID, flag)])
                add("order row sub %d oid %#x flag %d no id" % (sub, oid, flag), [order_row(sub, oid, flag)], new=(0, 0))
    add("old id equals new id", [order_row(flag=1)], new=(1, OLD_ID))
    add("old id equals new id, flag 0", [order_row(flag=0)], new=(1, OLD_ID))
    add("add is zero", [order_row()], add=0.0)
    add("large sum", [order_row(size=1e300)], add=1e300)
    for side in (0, 1):
        add("fill side %d, request side 0" % side, [fill_row(side)], turn={0: (0, {})})
        add("fill side %d, request side 1" % side, [fill_row(side)], request=request(side=1), turn={0: (1, {})})
    for tag in (0, 1, 2, 3):
        add("turn result %d" % tag, [fill_row()], turn={0: (tag, {})})
    add("turn with amount", [fill_row(amount=0x400)], turn={0: (0, {})})
    add("amount one below the value", [fill_row(amount=0xFFF)], turn={0: (0, {})})
    add("amount equals the value", [fill_row(amount=0x1000)], turn={0: (0, {})})
    add("amount above the value", [fill_row(amount=0x1001)], turn={0: (0, {})})
    add("sibling error", [fill_row(amount=5)], sibling={"error": 4}, turn={0: (0, {})})
    add("token past the rows", [fill_row(amount=5)], sibling={"value": 0x1000, "token": 4})
    add("last token", [fill_row(amount=5)], sibling={"value": 0x1000, "token": 3}, turn={0: (0, {})})
    add("token list of two", [fill_row(amount=5)], tokens=[{"count": 1, "book": 0}, {"count": 2, "book": 0}], turn={0: (0, {})})
    add("token list empty", [fill_row(amount=5)], tokens=[{"count": 1, "book": 0}, {"count": 0, "book": 0}], turn={0: (0, {})})
    add("large token list word", [fill_row(amount=5)], tokens=[{"count": 1, "book": 0}, {"count": 0x101, "book": 0}], turn={0: (0, {})})
    for first, second in ((OLD_ID, 3), (3, OLD_ID), (OLD_ID, OLD_ID), (3, 4)):
        add("fill ids %#x %#x same side" % (first, second), [fill_row(0, ids=(first, second))])
        add("fill ids %#x %#x other side kept" % (first, second), [fill_row(1, ids=(first, second))], turn={0: (2, {})})
        add("fill ids %#x %#x no new id" % (first, second), [fill_row(0, ids=(first, second))], new=(0, 9))
    add("turned leg ids", [fill_row(1, ids=(7, 8))], turn={0: (0, {0xC8: OLD_ID, 0x1C0: OLD_ID})})
    add("turned one leg id", [fill_row(1, ids=(OLD_ID, OLD_ID))], turn={0: (1, {0xC8: 4, 0x1C0: OLD_ID})})
    add("fill as tag 11", [fill_row(1, tag=11)], turn={0: (0, {})})
    add("fill as tag 12", [fill_row(0, tag=12, ids=(OLD_ID, 1))])
    for name, more in (("first leg none", {8: (8, 0)}), ("first leg wide tag", {8: (8, 0x100000001)}), ("second option none", {0x30: (8, 0)}), ("middle two", {0x68: (8, 2)}), ("middle zero", {0x68: (8, 0)}), ("middle wide", {0x68: (8, 0x101)}), ("inner none", {0x90: (8, 0)}), ("byte none", {0xEC: (1, 0)}), ("byte two", {0xEC: (1, 2)}),
                       ("second leg none", {0x100: (8, 0)}), ("second leg option none", {0x128: (8, 0)}), ("second leg middle two", {0x160: (8, 2)}), ("second leg middle zero", {0x160: (8, 0)}), ("second leg inner none", {0x188: (8, 0)}), ("second leg byte none", {0x1E4: (1, 0)})):
        add("image: " + name, [fill_row(more=more)], turn={0: (0, {})})
    mixed = [order_row(flag=0), make_row(5, 0x19), fill_row(0, ids=(OLD_ID, 3)), order_row(3, NEW_ID, 1), fill_row(1, ids=(OLD_ID, OLD_ID)), order_row(2, OLD_ID, 1, start=0x15), make_row(0, 0x1B)]
    add("seven rows", mixed, turn={4: (0, {0xC8: OLD_ID})})
    add("seven rows, no id", mixed, new=(0, 1), turn={4: (1, {0x1C0: OLD_ID})})
    drop = order_row(2, OLD_ID, 1)
    keep = order_row(2, 5, 0)
    add("drop first", [drop, keep, make_row(4, 0x1D)])
    add("drop middle", [keep, drop, make_row(4, 0x1D)])
    add("drop last", [keep, make_row(4, 0x1D), drop])
    add("drop all", [drop, order_row(3, OLD_ID, 1), drop])
    add("drop two apart", [drop, keep, drop, make_row(4, 0x1D), drop])
    add("drop one of one", [drop])
    add("panic after a drop", [drop, fill_row(amount=5)], sibling={"value": 0x1000, "token": 4})
    add("turn after a drop", [drop, fill_row(), keep], turn={1: (0, {})})
    add("second row uses its own sibling", [fill_row(amount=5), fill_row(amount=6, spot=3)], sibling_by_row={0: {"error": 2}, 1: {"value": 0x2000, "token": 2}}, turn={1: (0, {})})
    cases = []
    for copy in sorted(COPIES):
        for label, w in table:
            cases.append(Case("%s %s" % (copy, label), "rewrite", copy, w))
    return cases


def total_cases():
    table = [("no fills", []), ("one fill", [(5, 4, 100)]), ("one fill, first equals second", [(5, 7, 7)]), ("one fill, first above second", [(5, 8, 7)]), ("one fill, first zero", [(5, 0, 7)]),
             ("one fill, both zero", [(5, 0, 0)]), ("one fill, first one", [(5, 1, 0)]), ("first above 2^32", [(5, 1 << 33, 1 << 34)]), ("second above 2^32", [(5, 3, 1 << 33)]), ("both words small", [(5, 0xFFFFFFFF, 0xFFFFFFFF)]),
             ("floor", [(5, 7, 100)]), ("two fills", [(5, 4, 100), (5, 6, 100)]), ("three fills", [(5, 1, 3), (5, 2, 3), (5, 3, 3)]), ("four fills", [(9, 1, 3), (9, 2, 3), (9, 3, 3), (9, 4, 3)]), ("keys differ", [(5, 4, 100), (6, 6, 100)]),
             ("third key differs", [(5, 4, 100), (5, 6, 100), (6, 1, 1)]), ("last key differs, first sum overflow", [(5, MASK[8], MASK[8]), (6, 1, 0)]), ("first sum overflows", [(5, MASK[8], MASK[8]), (5, 1, 0)]), ("second sum overflows", [(5, 3, MASK[8]), (5, 1, 1)]),
             ("both overflow", [(5, MASK[8], MASK[8]), (5, 1, 1)]), ("both overflow, keys differ", [(5, MASK[8], MASK[8]), (6, 1, 1)]), ("overflow by two", [(5, MASK[8] - 1, MASK[8]), (5, 3, 3)]), ("exact top", [(5, MASK[8] - 1, MASK[8] - 1), (5, 1, 1)]),
             ("second fill zero", [(5, 4, 100), (5, 0, 0)]), ("first fill zero", [(5, 0, 0), (5, 4, 100)]), ("sum above second", [(5, 10, 10), (5, 1, 0)]), ("sum equals second", [(5, 10, 10), (5, 0, 0)]), ("key zero", [(0, 2, 4)]), ("key high", [(MASK[8], 2, 4), (MASK[8], 1, 2)])]
    cases = []
    for copy in ("a", "b"):
        for label, fills in table:
            cases.append(Case("total %s %s" % (copy, label), "total", copy, {"fills": fills}))
    return cases


def turn_image(spot=1, px=0x100, size=7, side=0, tags=(0, 1), bytes_=(5, 6)):
    image = bytearray(ramp(0x258, 0x25))
    put_word(image, 0, 8, tags[0])
    image[8] = bytes_[0]
    put_word(image, LEG_SIZE, 8, tags[1])
    image[LEG_SIZE + 8] = bytes_[1]
    put_word(image, 0x1F0, 8, spot)
    put_word(image, 0x1F8, 8, px)
    put_word(image, 0x200, 8, size)
    image[0x224] = side
    return bytes(image)


def turn_cases():
    base = {"class": 2, "pair": True, "legs": (1, 2, 0, 3), "image": turn_image()}
    table = [("plain", {}), ("side 1", {"image": turn_image(side=1)}), ("px zero", {"image": turn_image(px=0)}), ("spot past the list", {"image": turn_image(spot=5)}), ("last spot", {"image": turn_image(spot=4)}),
             ("class 0", {"class": 0}), ("class 1", {"class": 1}), ("class 3", {"class": 3}), ("sibling error 1", {"sibling": {"error": 1}}), ("sibling error 4", {"sibling": {"error": 4}}),
             ("token past the rows", {"sibling": {"value": 0x1000, "token": 4}}), ("last token", {"sibling": {"value": 0x1000, "token": 3}}), ("token list of two", {"tokens": [{"count": 1, "book": 0}, {"count": 2, "book": 0}]}), ("token list empty", {"tokens": [{"count": 1, "book": 0}, {"count": 0, "book": 0}]}),
             ("value below px", {"sibling": {"value": 0xFF, "token": 1}}), ("value equals px", {"sibling": {"value": 0x100, "token": 1}}), ("value one above px", {"sibling": {"value": 0x101, "token": 1}}), ("book past the list", {"tokens": [{"count": 1, "book": 0}, {"count": 1, "book": 5}]}), ("last book", {"tokens": [{"count": 1, "book": 0}, {"count": 1, "book": 4}]}),
             ("first leg stops", {"legs": (2, 7, 1, 3)}), ("second leg stops", {"legs": (1, 7, 2, 9)}), ("both legs stop", {"legs": (2, 7, 2, 9)}), ("tags 0 and 0", {"legs": (0, 1, 0, 2)}), ("tags 0 and 1", {"legs": (0, 1, 1, 2)}),
             ("product at the top", {"sibling": {"value": 0x100 + 0x3FFFFFFFFFFFFFFF, "token": 1}, "image": turn_image(size=2)}), ("product at i64 max", {"sibling": {"value": 0x100 + 0x7FFFFFFFFFFFFFFF, "token": 1}, "image": turn_image(size=1)}), ("product just below", {"sibling": {"value": 0x100 + 0x7FFFFFFFFFFFFFFE, "token": 1}, "image": turn_image(size=1)}), ("product past 2^64", {"sibling": {"value": 1 << 33, "token": 1}, "image": turn_image(size=1 << 33)}), ("size zero", {"image": turn_image(size=0)}),
             ("no pair", {"pair": False}), ("no pair, tags 1 and 0", {"pair": False, "image": turn_image(tags=(1, 0))}), ("no pair, first tag 2", {"pair": False, "image": turn_image(tags=(2, 0))}), ("no pair, second tag 2", {"pair": False, "image": turn_image(tags=(0, 2))}), ("no pair, side 1", {"pair": False, "image": turn_image(side=1)}), ("no pair, product high", {"pair": False, "sibling": {"value": 1 << 33, "token": 1}, "image": turn_image(size=1 << 33)})]
    cases = []
    for label, change in table:
        w = world()
        w.update(base)
        w.update(change)
        cases.append(Case("turn " + label, "turn", "", w))
    return cases


def legs_cases():
    cases = []

    def add(label, **change):
        w = {"image": turn_image(tags=(0, 1), bytes_=(5, 6)), "side": 0, "flip": 1, "pair_words": (1000, 2000), "amount": (1, 30), "size": 4, "price": 25, "word": 0x77}
        w.update(change)
        cases.append(Case("legs " + label, "legs", "", w))

    for side, flip in ((0, 1), (1, 0), (0, 0), (1, 1), (2, 0), (2, 3), (0, 2), (1, 2)):
        for pair in ((1000, 2000), (30, 100), (29, 99), (0, 0), (MASK[8], MASK[8]), (MASK[8] - 29, MASK[8] - 99), (MASK[8] - 30, MASK[8] - 100), (0x1122334455667788, 0x99AABBCCDDEEFF10)):
            add("side %d flip %d pair %#x" % (side, flip, pair[0]), side=side, flip=flip, pair_words=pair)
        add("side %d flip %d amount refused" % (side, flip), side=side, flip=flip, amount=(0, 30))
        add("side %d flip %d amount flag 2" % (side, flip), side=side, flip=flip, amount=(2, 30))
        add("side %d flip %d amount flag 3" % (side, flip), side=side, flip=flip, amount=(3, 30))
        add("side %d flip %d amount zero" % (side, flip), side=side, flip=flip, amount=(1, 0))
        add("side %d flip %d product at the limit" % (side, flip), side=side, flip=flip, size=1, price=0x7FFFFFFFFFFFFFFE, pair_words=(5, 0x7FFFFFFFFFFFFFFE))
        add("side %d flip %d product above" % (side, flip), side=side, flip=flip, size=1, price=0x7FFFFFFFFFFFFFFF)
        add("side %d flip %d product past 2^64" % (side, flip), side=side, flip=flip, size=1 << 33, price=1 << 33)
        add("side %d flip %d high sign bit" % (side, flip), side=side, flip=flip, size=1, price=MASK[8])
    add("tags 2 and 3", image=turn_image(tags=(2, 3), bytes_=(7, 8)))
    add("tags 3 and 2, side 1", side=1, flip=0, image=turn_image(tags=(3, 2), bytes_=(7, 8)))
    return cases


def all_cases():
    return rewrite_cases() + total_cases() + turn_cases() + legs_cases()


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


def twin_rows(image, left, right):
    """Two functions of one source: same length, and every instruction equal once call targets and rip words are compared as absolute targets."""
    first = decode_range(image, *image.exact_fde(left))
    second = decode_range(image, *image.exact_fde(right))
    if len(first) != len(second):
        raise EvidenceError("twin length differs: %#x" % left)
    targets = {}
    other = 0
    offsets = {}
    for one, two in zip(first, second):
        one_bytes = bytes(image.blob[image.offset(one.va):image.offset(one.va) + one.size])
        two_bytes = bytes(image.blob[image.offset(two.va):image.offset(two.va) + two.size])
        if one_bytes == two_bytes:
            continue
        if one.op in ("call", "jmp", "jcc") and one.target is not None:
            local = left <= one.target < image.exact_fde(left)[1]
            if local and one.target - left != two.target - right:
                raise EvidenceError("twin jump differs at %#x" % one.va)
            if not local and one.target != two.target:
                targets[one.target] = two.target
            continue
        if one.rip_at is not None and one.size == two.size:
            other += 1
            continue
        if one.size == two.size and one.op == two.op:
            changed = [index for index in range(one.size) if one_bytes[index] != two_bytes[index]]
            if changed and changed[-1] - changed[0] < 4:
                offsets["%#x" % one.va] = "%s to %s" % (one_bytes.hex(), two_bytes.hex())
                continue
        raise EvidenceError("twin instruction differs at %#x" % one.va)
    return {"left": "%#x" % left, "right": "%#x" % right, "instructions": len(first), "call_targets_that_differ": {"%#x" % key: "%#x" % value for key, value in sorted(targets.items())}, "rip_words_that_differ": other, "field_words_that_differ": offsets}


HOST_BYTES = (
    (0x26D56AA, "48b90000000000000080", "movabs rcx, the None word of the first insert result"),
    (0x26D56B4, "48394c2428", "cmp [rsp+0x28], rcx"),
    (0x26D5385, "31c0", "xor eax, eax: no new id, on the arm with nothing left resting"),
    (0x26D56A5, "b801000000", "mov eax, 1: new id present"),
)


def read_host_bytes(image):
    rows = []
    for va, wanted, meaning in HOST_BYTES:
        data = bytes(image.blob[image.offset(va):image.offset(va) + len(wanted) // 2]).hex()
        if data != wanted:
            raise EvidenceError("host bytes at %#x: %s" % (va, data))
        rows.append({"va": "%#x" % va, "bytes": data, "meaning": meaning})
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


GROUPS = ((DRIVER_A, "driver, first copy"), (ROW_TEST_A, "row test, first copy"), (DRIVER_B, "driver, second copy"), (RETAIN_B, "row walk, second copy"), (ROW_TEST_B, "row test, second copy"),
          (DRIVER_C, "driver, third copy"), (RETAIN_C, "row walk, third copy"), (ROW_TEST_C, "row test, third copy"), (PREPARE, "fill gate, second and third copies"), (LEG_COPY, "leg copy"),
          (TURN, "fill turn"), (LEGS, "leg update"), (TOTAL_A, "fill totals, first copy"), (TOTAL_B, "fill totals, second copy"))


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

REFERENCE_CLAIMS = (
    {"reference": "l1/exchange/handlers/12_modify.rs:143", "claim": "the replace flow removes the old order, inserts the new one and rebinds child ids", "observed": "that flow has no step that rewrites queued rows; none of the 13 functions here is named in the tree", "verdict": "absent from the reference"},
    {"reference": "l1/qtys/impl_sz.rs:392", "claim": "both 616-byte and 632-byte event-vector monomorphs exist", "observed": "the row stride here is 0x268 (616)", "verdict": "agrees for 616"},
    {"reference": "l1/exchange/impl_bole.rs:13", "claim": "GENERATED_ORDER_ROW_BYTES is 552", "observed": "fill stride 0x228 (552) in 0x24f8d90 and 0x47d6d90, which read +0x1f8, +0x200, +0x208", "verdict": "same size; the reference does not name these fields"},
    {"reference": "whole tree", "claim": "no price turn of a fill to a sibling book", "observed": "0x3790200 and 0x24f92e0, 0x4472550", "verdict": "absent from the reference"},
)
FIELDS = {
    "row_0x268": {"+0x00": "kind word; kind = word - 2, or 7 for words 0 and 1", "kind 1, +0x08": "inner word; 2 selects a record at +0x38 with flag +0x100, 0, 1 and 3 a record at +0x30 with flag +0x119, others are skipped", "kind 6 and above 8": "fill row"},
    "fill_row": {"+0x08": "first leg, 0xf8 bytes", "+0x100": "second leg, 0xf8 bytes", "+0xd0": "id in the first leg, leg +0xc8", "+0x1c8": "id in the second leg, leg +0xc8", "+0x1f8": "spot index", "+0x200": "price", "+0x208": "size", "+0x210": "price * size", "+0x218": "word set to 0 by a turn", "+0x22c": "byte, set from the transform result", "+0x230": "amount, turned as value - amount", "+0x23a": "side byte"},
    "record_0xa8_used_here": {"+0x68": "sz, from the earlier open order view reading", "+0x70": "oid, same source"},
    "block_of_a_driver": {"+0x00/+0x08": "new id option: tag, value", "+0x10": "request", "+0x18": "state", "+0x20": "16 bytes handed to the transform", "+0x30": "old id", "+0x38": "f64 added to sz", "+0x40": "user, 20 bytes"},
    "request_used_here": {"+0x28": "book index", "+0x30": "side byte", "+0x19": "byte k; 2 keeps +0x1a..+0x1f", "+0x32": "cloid flag, +0x33 cloid"},
    "state": {"+0x60": "12 byte time block handed to the record builder", "+0x90": "spot meta", "+0x1f8/+0x200": "spot list: pointer, length, stride 0x20; meta +0x168/+0x170", "+0x210/+0x218": "token rows: pointer, length, stride 0xe8; meta +0x180/+0x188", "+0x3388/+0x3390": "books, stride 0xd8, first and third copies", "+0x3e08/+0x3e10": "books, stride 0xd8, second copy"},
    "token_row": {"+0x58/+0x60": "book list: pointer, length"},
}
UNWIND = "unwind landing pad: no case unwinds"
ONE_MORE = "one byte more is copied, into space that is dead or written next"
SAME_KIND = "word 2 falls to kind 7 instead of kind 0, and both kinds are in the kept mask"
SAME_DIVIDE = "the 32 bit divide is a shortcut: the 64 bit divide gives the same quotient"
UNUSED = "the second word of the leg cursor is never read"
REASONS = {0x24F9221: ONE_MORE, 0x24F9C21: ONE_MORE, 0x47F5046: ONE_MORE, 0x47F5156: ONE_MORE, 0x47D7045: ONE_MORE, 0x47D7215: ONE_MORE, 0x447268B: ONE_MORE, 0x44726B2: ONE_MORE, 0x44726C7: ONE_MORE, 0x44726DE: ONE_MORE, 0x4472705: ONE_MORE, 0x4472712: ONE_MORE, 0x447274D: ONE_MORE, 0x44727F8: ONE_MORE,
           0x24F92F8: SAME_KIND, 0x47D6F95: SAME_KIND, 0x47D7165: SAME_KIND, 0x24F8DDD: SAME_DIVIDE, 0x47D6DDD: SAME_DIVIDE, 0x4472631: UNUSED,
           0x24F9D12: UNWIND, 0x47D7139: UNWIND, 0x47D7309: UNWIND}
DEAD_ARM = "the arm tests side 1 on a path that needs side 0, so no input reaches it"
REASON_RANGES = ((0x3C18766, 0x3C1877E, DEAD_ARM), (0x24F9275, 0x24F92D8, UNWIND), (0x47F5085, 0x47F50C9, UNWIND), (0x47F5195, 0x47F51D9, UNWIND))


def reason_for(row):
    if row["result"] == "killed":
        return ""
    va = row["va"]
    for low, high, reason in REASON_RANGES:
        if low <= va < high:
            return reason
    return REASONS.get(va, "no case in the list separates this mutant; no claim rests on this row")


def outcome_name(case, spec):
    if case.kind == "total":
        return "totals: " + ("some" if spec["answer"] else "none")
    if case.kind == "legs":
        tags = sorted({spec["legs"][spec["order"]][0]})
        return "legs: %s" % ("stopped" if tags == [2] else "updated")
    if case.kind == "turn":
        if spec["stop"]:
            return "turn: panic"
        return "turn: %s" % (spec["out"]["tag"] if spec["out"]["tag"] != 3 else "code %d" % spec["out"]["byte"])
    return "rewrite: panic" if spec["stop"] else "rewrite: done"


def row_action(harness, copy, label, row, **change):
    """One real run of a one row vector: what happened to the row."""
    case = Case(label, "rewrite", copy, world([row], **change))
    tag = word(row, 0)
    kind = tag - 2 if tag >= 2 else 7
    if (kind == 6 or kind >= 9) and row[0x23A] != case.world["request"][0x30]:
        case.world["turn_order"] = [0]
    found = harness.run(case)
    if found["length"] == 0:
        return "row removed"
    return "row unchanged" if scrub(found["rows"])[0] == scrub([row])[0] else "row changed"


def row_action_rows(harness):
    rows = []
    for tag in range(0, 13):
        row = make_row(tag, 0x43, {8: (8, 2), 0xA8: (8, OLD_ID), 0x100: (1, 0), 0xD0: (8, OLD_ID), 0x1C8: (8, OLD_ID), 0x23A: (1, 0)})
        rows.append(("word %d" % tag, ) + tuple(row_action(harness, copy, "tag", row) for copy in sorted(COPIES)))
    for sub in range(0, 6):
        row = order_row(sub, OLD_ID, 0)
        rows.append(("word 3, inner %d, old id, flag 0" % sub, ) + tuple(row_action(harness, copy, "sub", row) for copy in sorted(COPIES)))
        row = order_row(sub, OLD_ID, 1)
        rows.append(("word 3, inner %d, old id, flag 1" % sub, ) + tuple(row_action(harness, copy, "sub", row) for copy in sorted(COPIES)))
        row = order_row(sub, 5, 1)
        rows.append(("word 3, inner %d, other id, flag 1" % sub, ) + tuple(row_action(harness, copy, "sub", row) for copy in sorted(COPIES)))
    return rows


def worked_runs(harness):
    """Values of 1e8 with a price 0.6e8: the turn gives 0.4e8."""
    w = world()
    w.update({"class": 2, "pair": False, "legs": (0, 0, 0, 0), "image": turn_image(px=60000000, size=25, side=1), "sibling": {"value": 100000000, "token": 1}})
    found = harness.run(Case("worked", "turn", "", w))
    data = found["out"]["bytes"]
    turn = {"input": {"spot": 1, "price": 60000000, "size": 25, "side": 1, "value": 100000000}, "output": {"spot": word(data, 0x1F8), "price": word(data, 0x1F0), "size": word(data, 0x200), "notional": word(data, 0x208), "cleared_word": word(data, 0x210), "side": data[0x224]}}
    harness.machine.step_limit = STEP_LIMIT
    total = harness.run(Case("worked", "total", "a", {"fills": [(5, 4, 100), (5, 6, 100)]}))
    return {"fill turn": turn, "fill totals of (key 5, 4, 100) and (key 5, 6, 100)": {"average": total["answer"][0], "first": total["answer"][1], "second": total["answer"][2], "key": total["answer"][3]}}


def analyse(image, full=True, verbose=False):
    cases = all_cases()
    harness = Harness(image)
    mismatches = []
    outcomes = {}
    reached = []
    seen = set()
    machine = harness.machine
    for case in cases:
        machine.seen = set()
        trouble = compare_run(harness, case)
        if trouble:
            mismatches.append(trouble)
        reached.append(frozenset(machine.seen))
        seen |= machine.seen
        name = outcome_name(case, spec_run(case))
        outcomes[name] = outcomes.get(name, 0) + 1
    steps = machine.steps
    if mismatches and full:
        raise EvidenceError("spec mismatch: %s" % mismatches[0])
    functions = []
    for start, role in GROUPS:
        begin, end = image.exact_fde(start)
        rows = decode_range(image, begin, end)
        functions.append({"role": role, "start": "%#x" % begin, "end": "%#x" % end, "size": end - begin, "instructions": len(rows), "instructions_stepped": sum(1 for row_ in rows if row_.va in seen)})
    relative = harness.relative
    slots = {SLOT_TURN: TURN, SLOT_CLASS: CLASS, SLOT_RECORDER: None, SLOT_AMOUNT: None}
    for slot, value in slots.items():
        if value is not None and relative.get(slot) != value:
            raise EvidenceError("slot %#x" % slot)
    slots = {slot: relative[slot] for slot in slots}
    site_rows = []
    direct = direct_sites(image, (DRIVER_A, DRIVER_B, DRIVER_C, RETAIN_B, RETAIN_C, ROW_TEST_A, ROW_TEST_B, ROW_TEST_C, PREPARE, LEGS, TOTAL_A, TOTAL_B))
    for target in sorted(direct):
        for va, opcode in sorted(direct[target]):
            site_rows.append((target, va, "rel32 %#x" % opcode, image.fde(va)[0], image.fde(va)[1]))
    for va in slot_sites(image, SLOT_TURN):
        site_rows.append((TURN, va, "slot %#x" % SLOT_TURN, image.fde(va)[0], image.fde(va)[1]))
    locations = []
    for slot, name in ((LOC_META, "spot or book index past the spot list"), (LOC_TOKEN, "token past the rows"), (LOC_BOOK_A, "book index, first copy"), (LOC_BOOK_B, "book index, second and third copies"), (LOC_SUM_FIRST, "first total"), (LOC_SUM_SECOND, "second total"), (LOC_SUM_FIRST_B, "first total, second copy"), (LOC_SUM_SECOND_B, "second total, second copy"), (LOC_LEG_ADD, "saturating leg add")):
        path, line, column = image.location(slot, relative)
        locations.append({"slot": "%#x" % slot, "name": name, "path": path, "line": line, "column": column})
    twins = [twin_rows(image, DRIVER_B, DRIVER_C), twin_rows(image, RETAIN_B, RETAIN_C), twin_rows(image, ROW_TEST_B, ROW_TEST_C), twin_rows(image, TOTAL_A, TOTAL_B)]
    host_bytes = read_host_bytes(image)
    actions = row_action_rows(harness)
    worked = worked_runs(harness)
    results_rows = run_mutants(image, reached, verbose) if full else []
    tally = {key: sum(1 for row_ in results_rows if row_["result"] == key) for key in ("killed", "survived", "unreached")}
    return {
        "target": {"file": "artifacts/node/94/hl-node", "sha256": SHA256},
        "functions": functions,
        "slots": {"%#x" % slot: "%#x" % value for slot, value in sorted(slots.items())},
        "twins": twins,
        "host_bytes": host_bytes,
        "locations": locations,
        "fields": FIELDS,
        "worked_examples": worked,
        "reference_claims": list(REFERENCE_CLAIMS),
        "cases": {"total": len(cases)},
        "outcomes": dict(sorted(outcomes.items())),
        "mismatches": len(mismatches),
        "first_mismatch": mismatches[0] if mismatches else "",
        "instructions_stepped": steps,
        "mutations": tally,
        "_sites": site_rows, "_results": results_rows, "_actions": actions,
    }


def render(evidence):
    evidence = dict(evidence)
    sites = evidence.pop("_sites")
    results = evidence.pop("_results")
    actions = evidence.pop("_actions")
    files = {"evidence.json": (json.dumps(evidence, indent=2, sort_keys=True) + "\n").replace("\x40", "[at]")}
    lines = ["target\tsite\tcall\tcaller_fde\tcaller_fde_end"]
    lines += ["%#x\t%#x\t%s\t%#x\t%#x" % row_ for row_ in sites]
    files["call_sites.tsv"] = "\n".join(lines) + "\n"
    lines = ["row\tfirst_copy\tsecond_copy\tthird_copy"]
    lines += ["%s\t%s\t%s\t%s" % row_ for row_ in actions]
    files["row_actions.tsv"] = "\n".join(lines) + "\n"
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
