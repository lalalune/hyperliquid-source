#!/usr/bin/env python3
"""Pin the node #94 system user pass from ELF bytes: value test, sell loop, buy loop, price guard, size cap and gate release.

The pass 0x2739d70 and the order builder 0x27653a0 run whole in a Python evaluator, with the two small unit helpers and the
standard B-tree map under them. A separately written specification predicts every stub argument and outcome, and every condition,
immediate and field offset is flipped to show the run can tell. No objdump or readelf output is parsed, and the binary is never
executed. Standard library only.
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
    dict(name="primary", entry=0x2739D70, books=0x3388, body=0, snapshot=0, order=0x27653A0, report=0x2739210, cancel=0x232B4F0, drop=0x28ABF00, system=0x2730520, finish=0x2739B00,
         place=0x24FA890, insert=0x28538C0, next=0x286C020, drop_map=0x28A98C0, split=0x1A6C0B0),
    dict(name="second", entry=0x4D4A3A0, books=0x3388, body=0x46F7560, snapshot=0x46F2BE0, order=0x4D96870, report=0x46F1B90, cancel=0x48CE500, drop=0x49A8520, system=0x4D3A7E0, finish=0x46F26F0,
         place=0x4AE93A0, insert=0x49404E0, next=0x4954340, drop_map=0x49B2FA0, split=0x4234A30),
    dict(name="recording", entry=0x4D4A260, books=0x3E08, body=0x46F8400, snapshot=0x46F2960, order=0x4D96610, report=0x46F12A0, cancel=0x48CE500, drop=0x49A8520, system=0x4D39CE0, finish=0x46F2480,
         place=0x4AE87E0, insert=0x49404E0, next=0x4954340, drop_map=0x49B2FA0, split=0x4234A30),
)
BY_NAME = {layout["name"]: layout for layout in COPIES}
VALUE = 0x32815F0
SIZE = 0x32813D0
MAP_NODE_SIZES = (0xC0, 0x120)
HEALTH = 0x28DB540
CLONE = 0x289A040
COLLECT = 0x3739EF0
SPOT = 0x371B3A0
PRICE = 0x3736960
HASH = 0x399C4A0
BOOK = 0x32780D0
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
DEFAULT_USER = 0x5786350
LOG_ADD = 0x56DFD90
LOG_SUM = 0x56C7358
BOLE = 0x498
BUCKET = 0x4D8
BOLE_WORDS = (0x6060606060606060, 0x7070707070707070)
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
HEAP_SIZE = 0x60000
RETURN_SENTINEL = 0xDEAD0000
POISON = 0xA5A5A5A5A5A5A5A5
STEP_LIMIT = 400000
MUTANT_STEP_LIMIT = 120000
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

SLIP_SELL = 0.01
SLIP_BUY = 0.005
NOTIONAL_CAP = 50000000000000
VALUE_LIMIT = 0x28F5C28F5C28F5C


class Abort(Exception):
    pass


def address(tail, first=0xAA):
    return bytes([first] * 19 + [tail])


SYSTEM = bytes([0xBB] * 20)


class Spec:
    """Reads the case as a reader of the bytes would, and predicts every outward call."""

    def __init__(self, case):
        self.case = case
        self.events = []
        self.logs = []
        self.frees = []
        self.cancelled = False

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

    def size(self, amount, token):
        return amount // 10 ** self.diff(token)

    def spot(self, token):
        self.events.append(("spot",))
        table = self.case["spot"]
        if self.cancelled and token in self.case.get("after", {}):
            table = self.case["after"]
        return table.get(token, 0)

    def add(self, total, amount, slot):
        total += amount
        if total >> 64:
            self.logs.append(slot)
            total = MASK[8]
        return total

    def cancel(self, token):
        """True to go on, False to leave the pass."""
        self.events.append(("cancel", token))
        self.cancelled = True
        outcome = self.case.get("cancels", {}).get(token, ("ok",))
        if outcome[0] == "ok":
            return True
        if outcome[0] == "err":
            return False
        if outcome[0] == "none":
            return True
        if outcome[0] == "report":
            self.events.append(("report", token, outcome[1], outcome[2]))
            return True
        self.events.append(("drop",))
        return False

    def order(self, token, mode, amount):
        if amount == 0:
            return
        case = self.case
        self.events.append(("price", token, mode, SLIP_SELL if mode else SLIP_BUY))
        asset, px = case["prices"].get(token, (0, 0))
        if px == 0:
            return
        guards = case.get("guards")
        if guards is not None:
            self.events.append(("hash", token))
            limit = guards.get(token, (0, 0))[0 if mode else 1]
            if limit and (px < limit if mode else px >= limit):
                px = limit
        books = case["refs"]
        if asset >= len(books):
            raise Panicked("bound")
        self.events.append(("book", asset))
        cap = NOTIONAL_CAP // books[asset]
        size = min(self.size(amount, token), cap)
        if mode and size == 0:
            return
        self.events.append(("place", asset, size, px, mode))

    def body(self):
        case = self.case
        self.events.append(("rows",))
        failed = case.get("rows_error")
        if failed is not None:
            if failed != OK_TAG:
                raise Abort()
            return
        rows = case["rows"]
        tokens = case["tokens"]
        shortfall = {}
        have = need = 0
        try:
            for token, debt, supply in rows:
                if token not in tokens:
                    raise Abort()
                self.events.append(("spot",))
                table = case["spot"]
                balance = table.get(token, 0)
                px, pool = tokens[token]
                available = min(supply, pool)
                total = available + balance
                if total >> 64:
                    self.logs.append(LOG_ADD)
                    total = MASK[8]
                if token:
                    if not debt:
                        continue
                    amount = debt - total if debt > total else 0
                    shortfall[token] = amount
                else:
                    good, worth = self.value(total, 0, px, False)
                    if not good:
                        raise Abort()
                    have = self.add(have, worth, LOG_SUM)
                    amount = debt
                    if not amount:
                        continue
                good, worth = self.value(amount, token, px, True)
                if not good:
                    raise Abort()
                need = self.add(need, worth, LOG_SUM)
            if need > have:
                if len(rows) * 8 not in MAP_NODE_SIZES:
                    self.frees.append(len(rows) * 8)
                for token, _, _ in rows:
                    if not token or token in shortfall:
                        continue
                    if not self.cancel(token):
                        raise Abort()
                    self.order(token, 1, self.spot(token))
            if need:
                if not self.cancel(0):
                    raise Abort()
                for token in sorted(shortfall):
                    if not self.cancel(token):
                        raise Abort()
                    self.order(token, 0, shortfall[token])
        finally:
            cap = case.get("cap", len(rows))
            if cap:
                self.frees.append(cap * 24)

    def run(self):
        case = self.case
        if case.get("once"):
            self.events.append(("once",))
        entry = case["users"].get(case["user"])
        if entry is not None and entry.get("positions"):
            self.events.append(("clone",))
        self.events.append(("health",))
        fail, code, low, high = case["report"]
        if fail:
            self.events.append(("drop",))
            return dict(events=self.events, logs=self.logs, frees=self.frees, result=code, cleared=False)
        if high >> 63 or low >> 63:
            raise Panicked("unwrap")
        word = case.get("default", 0) >> 64 & MASK[4] if entry is None else entry["word"]
        tag = case.get("default", 0) & 0xFF if entry is None else entry["tag"]
        if word == 0:
            return dict(events=self.events, logs=self.logs, frees=self.frees, result=tag, cleared=False)
        cleared = False
        if case["gate"] == 1:
            try:
                self.body()
            except Abort:
                cleared = True
        self.events.append(("system",))
        self.events.append(("finish", (high - low) & MASK[8]))
        return dict(events=self.events, logs=self.logs, frees=self.frees, result=case.get("finish", OK_TAG), cleared=cleared)


def pass_spec(case):
    return Spec(case).run()


def order_spec(case):
    spec = Spec(case)
    spec.order(case["token"], case["mode"], case["amount"])
    return spec.events


# ---- harness ----

TOKEN_TREE = dict(leaf=0x7F8, inner=0x858, parent=0x790, slot=0x7F0, length=0x7F2, keys=0x798, stride=8, edges=0x7F8, values=0xB0)
USER_TREE = dict(leaf=0x2F8, inner=0x358, parent=0x210, slot=0x2F4, length=0x2F6, keys=0x218, stride=20, edges=0x2F8, values=0x30)
SPOT_TREE = dict(leaf=0x170, inner=0x1D0, parent=None, slot=None, length=0x16A, keys=8, stride=8, edges=0x170, values=0x18, value_base=0x60)
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


def hash_of(token):
    return (token * 0x9E3779B97F4A7C15 + 0x1234567) & MASK[8]


class Harness:
    def __init__(self, image):
        self.image = image
        machine = self.machine = Machine(image)
        real = {VALUE, SIZE}
        for layout in COPIES:
            real.update(layout[name] for name in ("entry", "body", "order", "insert", "next", "drop_map", "split") if layout[name])
        machine.real = frozenset(real)
        machine.jump_ranges = [image.exact_fde(start) for start in real]
        machine.calls = {HEALTH: self.on_health, CLONE: self.on_clone, HASH: self.on_hash, BOOK: self.on_book}
        for layout in COPIES:
            machine.calls.update({layout["drop"]: self.on_drop, layout["cancel"]: self.on_cancel, layout["report"]: self.on_report, layout["system"]: self.on_system,
                                  layout["finish"]: self.on_finish, layout["place"]: self.on_place})
            if layout["snapshot"]:
                machine.calls[layout["snapshot"]] = self.on_snapshot
        hooks = {COLLECT: self.on_rows, SPOT: self.on_spot, PRICE: self.on_price, UDIV: self.on_div, OVERFLOW_LOG: self.on_log, PANIC_NONE: self.on_panic("none"), PANIC_BOUND: self.on_panic("bound"),
                 PANIC_UNWRAP: self.on_panic("unwrap"), PANIC_INDEX: self.on_panic("index"), ONCE_CALL: self.on_once}
        tokens = {}
        for at, (target, hook) in enumerate(hooks.items()):
            token = 0x7000000 + at * 16
            tokens[target] = token
            machine.slots[token] = hook
        for slot, target in relative_slots(image).items():
            if target in tokens:
                machine.memory.statics[slot] = tokens[target]
            elif target in (VALUE, SIZE):
                machine.memory.statics[slot] = target
        for at, (slot, hook) in enumerate(((SLOT_ALLOC, self.on_alloc), (SLOT_FREE, self.on_free), (SLOT_MEMCMP, self.on_memcmp), (SLOT_MEMCPY, self.on_memcpy), (SLOT_MEMMOVE, self.on_memcpy))):
            token = 0x7100000 + at * 16
            machine.memory.statics[slot] = token
            machine.slots[token] = hook
        self.case = None
        self.at = BUMP
        self.events = []
        self.logs = []
        self.frees = []
        self.nodes = set()
        self.table = 0
        self.tables = (0, 0)
        self.entry_at = 0
        self.entry_bytes = bytes(0x18)
        self.cancelled = False
        self.secs = 0
        self.books = 0

    def bump(self, size):
        here = self.at
        self.at += (size + 15) & ~15
        if self.at >= HEAP_BASE + HEAP_SIZE:
            raise Halt("heap exhausted")
        return here

    # edge hooks

    def on_alloc(self, machine):
        size = machine.regs[RDI]
        at = self.bump(size)
        if size in MAP_NODE_SIZES:
            self.nodes.add(at)
        machine.regs[RAX] = at

    def on_free(self, machine):
        if machine.regs[RDI] in self.nodes:
            self.nodes.remove(machine.regs[RDI])
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
        self.logs.append(machine.regs[RSI])

    def on_panic(self, name):
        def panic(machine):
            raise Panicked(name)
        return panic

    def on_once(self, machine):
        regs = machine.regs
        if regs[RDI] != ONCE_WORD or regs[RSI] & 0xFF != 1:
            raise Halt("once arguments")
        self.events.append(("once",))

    def on_clone(self, machine):
        regs, memory = machine.regs, machine.memory
        if (regs[RSI], regs[RDX]) != (self.entry_at_word(0x18), self.entry_at_word(0x20)):
            raise Halt("clone arguments")
        self.events.append(("clone",))
        memory.write(regs[RDI], 8, 0x4440)
        memory.write(regs[RDI] + 8, 8, 0x4441)
        memory.write(regs[RDI] + 16, 8, 0x4442)

    def entry_at_word(self, offset):
        return self.machine.memory.read(self.entry_at + offset, 8)

    def on_health(self, machine):
        regs, memory = machine.regs, machine.memory
        if memory.bytes_at(regs[RSI], 0x18) != self.entry_bytes or (regs[RDX], regs[RCX], regs[R8] & 0xFF) != (EXCHANGE + 0x560, EXCHANGE + 0x90, 0):
            raise Halt("health arguments")
        self.events.append(("health",))
        fail, code, low, high = self.case["report"]
        memory.write(regs[RDI], 1, fail)
        memory.write(regs[RDI] + 1, 1, code)
        memory.write(regs[RDI] + 8, 8, low)
        memory.write(regs[RDI] + 16, 8, high)

    def on_snapshot(self, machine):
        """The copies move the row copy, health read and clone into one call; the row bytes and the gap come back in its output."""
        regs, memory = machine.regs, machine.memory
        if regs[RSI] != EXCHANGE or memory.bytes_at(regs[RDX], 20) != self.case["user"]:
            raise Halt("snapshot arguments")
        fail, code, low, high = self.case["report"]
        out = regs[RDI]
        if fail:
            memory.write(out, 1, code)
            memory.write(out + 8, 4, 0)
            return
        memory.put_bytes(out, self.entry_bytes)
        cloned = self.case["users"].get(self.case["user"], {}).get("positions", 0)
        memory.write(out + 0x18, 8, 0x4440 if cloned else 0)
        memory.write(out + 0x20, 8, 0x4441)
        memory.write(out + 0x28, 8, 0x4442 if cloned else 0)
        memory.write(out + 0x30, 8, (high - low) & MASK[8])

    def on_drop(self, machine):
        self.events.append(("drop",))

    def on_rows(self, machine):
        regs, memory = machine.regs, machine.memory
        if regs[RSI] != EXCHANGE + BOLE:
            raise Halt("rows argument")
        self.events.append(("rows",))
        case = self.case
        out = regs[RDI]
        if case.get("rows_error") is not None:
            memory.write(out, 8, 1 << 63)
            memory.write(out + 8, 1, case["rows_error"])
            return
        rows = case["rows"]
        cap = case.get("cap", len(rows))
        data = self.bump(max(cap, 1) * 24)
        for index, row in enumerate(rows):
            for word, value in enumerate(row):
                memory.write(data + index * 24 + word * 8, 8, value)
        memory.write(out, 8, cap)
        memory.write(out + 8, 8, data)
        memory.write(out + 16, 8, len(rows))

    def on_spot(self, machine):
        regs, memory = machine.regs, machine.memory
        if regs[RDI] != EXCHANGE + 0x80 or memory.bytes_at(regs[RSI], 20) != self.case["user"]:
            raise Halt("spot arguments")
        self.events.append(("spot",))
        machine.regs[RAX] = self.tables[1 if self.cancelled else 0]

    def on_cancel(self, machine):
        regs, memory = machine.regs, machine.memory
        top = regs[RSP]
        if regs[RSI] != EXCHANGE + BOLE or memory.bytes_at(regs[RDX], 20) != self.case["user"] or regs[R8] & MASK[4] != 3:
            raise Halt("cancel arguments")
        if memory.read(top + 8, 8) != 0 or memory.read(top + 0x20, 8) != EXCHANGE + 0x80 or memory.bytes_at(memory.read(top + 0x18, 8), 12) != BLOCK_TIME:
            raise Halt("cancel stack arguments")
        token = regs[RCX]
        self.events.append(("cancel", token))
        self.cancelled = True
        out = regs[RDI]
        outcome = self.case.get("cancels", {}).get(token, ("ok",))
        if outcome[0] == "ok":
            memory.write(out, 8, 3)
            memory.write(out + 8, 1, OK_TAG)
        elif outcome[0] == "err":
            memory.write(out, 8, 3)
            memory.write(out + 8, 1, outcome[1])
        elif outcome[0] == "none":
            memory.write(out, 8, 2)
            memory.write(out + 8, 1, OK_TAG)
        else:
            memory.write(out, 8, outcome[1] if outcome[0] == "report" else 1)
            memory.write(out + 8, 1, 0x22)
            memory.write(out + 0x100, 8, outcome[2] if outcome[0] == "report" else 7)
            memory.write(out + 0x108, 1, 0 if outcome[0] == "report" else 1)
            memory.write(out + 0x10F, 1, 0x5A)

    def on_report(self, machine):
        regs, memory = machine.regs, machine.memory
        if regs[RDI] != EXCHANGE or memory.bytes_at(regs[RSI], 20) != self.case["user"] or regs[RCX] & MASK[4] != 3 or regs[R9] & MASK[4] != 0:
            raise Halt("report arguments")
        report = regs[R8]
        if memory.read(report + 8, 1) != 0x22 or memory.read(report + 0x10F, 1) != 0x5A:
            raise Halt("report byte")
        self.events.append(("report", regs[RDX], memory.read(report, 8), memory.read(report + 0x100, 8)))

    def on_system(self, machine):
        regs, memory = machine.regs, machine.memory
        if regs[RDI] != EXCHANGE or memory.bytes_at(regs[RSI], 20) != SYSTEM or regs[RDX] & 0xFF != 4 or regs[RCX] != 6:
            raise Halt("system arguments")
        self.events.append(("system",))

    def on_finish(self, machine):
        regs, memory = machine.regs, machine.memory
        if regs[RDI] != EXCHANGE or memory.bytes_at(regs[RSI], 20) != self.case["user"] or memory.bytes_at(regs[RDX], 0x18) != self.entry_bytes:
            raise Halt("finish arguments")
        cloned = self.case["users"].get(self.case["user"], {}).get("positions", 0)
        if (memory.read(regs[RDX] + 0x18, 8), memory.read(regs[RDX] + 0x28, 8)) != ((0x4440, 0x4442) if cloned else (0, 0)):
            raise Halt("finish clone words")
        self.events.append(("finish", regs[RCX]))
        regs[RAX] = self.case.get("finish", OK_TAG)

    def on_price(self, machine):
        regs, memory = machine.regs, machine.memory
        if regs[RSI] != EXCHANGE + BOLE or regs[R8] != EXCHANGE + 0x90:
            raise Halt("price arguments")
        token, mode = regs[RDX], regs[RCX] & 0xFF
        self.events.append(("price", token, mode, to_float(machine.xmm[0] & MASK[8])))
        asset, px = self.case["prices"].get(token, (0, 0))
        memory.write(regs[RDI], 8, asset)
        memory.write(regs[RDI] + 8, 8, px)

    def on_hash(self, machine):
        regs, memory = machine.regs, machine.memory
        if regs[RDI] != EXCHANGE + 0x4C8:
            raise Halt("hash argument")
        token = memory.read(regs[RSI], 8)
        self.events.append(("hash", token))
        regs[RAX] = self.case.get("hash", hash_of)(token)

    def on_book(self, machine):
        regs = machine.regs
        asset = (regs[RDI] - self.books) // 0xD8
        if regs[RDI] != self.books + asset * 0xD8:
            raise Halt("book argument")
        self.events.append(("book", asset))
        regs[RAX] = self.case["refs"][asset]

    def on_place(self, machine):
        regs, memory = machine.regs, machine.memory
        head, body = regs[RDI], regs[RSI]
        words = (memory.read(head, 8), memory.read(head + 8, 8))
        if words != (BOLE_WORDS[0], BOLE_WORDS[1]) or memory.read(head + 0x10, 8) != to_bits(self.secs) or memory.bytes_at(head + 0x18, 20) != SYSTEM:
            raise Halt("place head")
        if memory.read(body + 0x18, 8) != EXCHANGE or memory.read(body + 0x21, 1) != 0:
            raise Halt("place body")
        self.events.append(("place", memory.read(body, 8), memory.read(body + 8, 8), memory.read(body + 0x10, 8), memory.read(body + 0x20, 1)))

    # fixtures

    def lay_guards(self, case):
        memory = self.machine.memory
        guards = case.get("guards")
        if guards is None:
            memory.write(EXCHANGE + 0x4C0, 8, 0)
            return
        buckets = 32
        hasher = case.get("hash", hash_of)
        ctrl = self.bump(buckets * 0x28 + buckets + 32) + buckets * 0x28
        memory.put_bytes(ctrl, b"\xff" * (buckets + 16))
        for token in sorted(guards):
            value = hasher(token)
            at = value & (buckets - 1)
            while memory.read(ctrl + at, 1) != 0xFF:
                at = (at + 1) & (buckets - 1)
            top = (value >> 57) & 0x7F
            memory.write(ctrl + at, 1, top)
            if at < 16:
                memory.write(ctrl + buckets + at, 1, top)
            memory.write(ctrl - 0x28 * (at + 1), 8, token)
            memory.write(ctrl - 0x28 * at - 0x10, 8, guards[token][0])
            memory.write(ctrl - 0x28 * at - 8, 8, guards[token][1])
        memory.write(EXCHANGE + 0x4A8, 8, ctrl)
        memory.write(EXCHANGE + 0x4B0, 8, buckets - 1)
        memory.write(EXCHANGE + 0x4C0, 8, max(len(guards), 1))

    def lay_table(self, case):
        memory = self.machine.memory
        table = case["decimals"]
        data = self.bump(0xE8 * max(len(table), 1))
        for index, (low, high) in enumerate(table):
            memory.write(data + 0xE8 * index + 0x48, 1, low)
            memory.write(data + 0xE8 * index + 0x49, 1, high)
        memory.write(EXCHANGE + 0x90 + 0x180, 8, data)
        memory.write(EXCHANGE + 0x90 + 0x188, 8, len(table))

    def lay_common(self, case):
        memory = self.machine.memory
        memory.reset()
        self.case = case
        self.at = BUMP
        self.events, self.logs, self.frees = [], [], []
        self.nodes = set()
        self.cancelled = False
        self.entry_at = 0
        self.entry_bytes = case.get("default", 0).to_bytes(16, "little") + bytes(8)
        memory.statics[ONCE_WORD] = 1 if case.get("once") else 0
        memory.statics[DEFAULT_USER] = case.get("default", 0)
        memory.statics[DEFAULT_USER + 0x10] = 0
        memory.statics[DEFAULT_USER + 0x28] = 0
        self.secs = case.get("bucket", 60000) / 1000
        memory.write(EXCHANGE + BOLE, 8, BOLE_WORDS[0])
        memory.write(EXCHANGE + BOLE + 8, 8, BOLE_WORDS[1])
        memory.write(EXCHANGE + BUCKET, 8, case.get("bucket", 60000))
        memory.put_bytes(EXCHANGE + 0x60, BLOCK_TIME)
        self.lay_table(case)
        self.lay_guards(case)
        books = case.get("refs", ())
        self.books = self.bump(0xD8 * max(len(books), 1))
        table = BY_NAME[case.get("copy", "primary")]["books"]
        memory.write(EXCHANGE + table, 8, self.books)
        memory.write(EXCHANGE + table + 8, 8, len(books))

    def spot_table(self, balances):
        memory = self.machine.memory
        root, height = build_tree(memory, self.bump, SPOT_TREE, [(word_key(key), value) for key, value in sorted(balances.items())], lambda at, value: memory.write(at, 8, value))
        view = self.bump(0x20)
        memory.write(view + 0x10, 8, root)
        memory.write(view + 0x18, 8, height)
        return view

    def run_pass(self, case):
        machine, memory = self.machine, self.machine.memory
        self.lay_common(case)
        tokens = case["tokens"]

        def put_token(at, key):
            memory.write(at + 0x10, 8, tokens[key][0])
            memory.write(at + 0x18, 8, tokens[key][1])
        root, height = build_tree(memory, self.bump, TOKEN_TREE, [(word_key(key), key) for key in sorted(tokens)], put_token)
        memory.write(EXCHANGE + 0x568, 8, root)
        memory.write(EXCHANGE + 0x570, 8, height)
        spot = dict(case["spot"])
        merged = dict(spot)
        merged.update(case.get("after", {}))
        self.tables = (self.spot_table(spot), self.spot_table(merged))
        users = case["users"]
        lay = {}

        def put_user(at, user):
            entry = users[user]
            memory.write(at, 1, entry["tag"])
            memory.write(at + 1, 4, 0x10203040)
            memory.write(at + 8, 4, entry["word"])
            memory.write(at + 0x10, 8, entry.get("low", 0x77))
            memory.write(at + 0x18, 8, 0x5550 if entry.get("positions") else 0)
            memory.write(at + 0x20, 8, 0x5551)
            memory.write(at + 0x28, 8, entry.get("positions", 0))
            lay[user] = at
        root, height = build_tree(memory, self.bump, USER_TREE, [(user, user) for user in sorted(users)], put_user)
        memory.write(EXCHANGE + 0x598, 8, root)
        memory.write(EXCHANGE + 0x5A0, 8, height)
        memory.write(EXCHANGE + 0x5A8, 8, len(users))
        self.entry_at = lay.get(case["user"], 0)
        if self.entry_at:
            self.entry_bytes = memory.bytes_at(self.entry_at, 0x18)
        memory.write(EXCHANGE + 0x5B3, 1, case["gate"])
        user = self.bump(24)
        memory.put_bytes(user, case["user"])
        result = machine.run(BY_NAME[case.get("copy", "primary")]["entry"], {RDI: EXCHANGE, RSI: user})
        return result & 0xFF, memory.read(EXCHANGE + 0x5B3, 1)

    def run_order(self, case):
        machine, memory = self.machine, self.machine.memory
        self.lay_common(case)
        machine.xmm[0] = to_bits(self.secs)
        machine.run(BY_NAME[case.get("copy", "primary")]["order"], {RDI: EXCHANGE, RSI: case["token"], RDX: case["mode"], RCX: case["amount"]})


# ---- cases ----

USER = address(1)
PX = 10 ** 8
BLOCK_TIME = bytes(range(0x31, 0x3D))
DECIMALS = [(8, 8), (2, 8), (4, 8), (0, 6), (6, 6), (3, 8), (5, 7), (1, 8)]
BASE = dict(kind="pass", user=USER, users={USER: dict(tag=0x33, word=5, positions=2)}, gate=1, report=(0, 0, 100, 400), decimals=DECIMALS,
            tokens={0: (PX, 10 ** 12), 1: (2 * PX, 10 ** 12), 2: (3 * PX, 10 ** 12), 3: (5 * PX, 10 ** 12)}, spot={}, rows=[], refs=[2 * PX, 3 * PX, 5 * PX, 7 * PX],
            prices={1: (0, 2 * PX), 2: (1, 3 * PX), 3: (2, 5 * PX)})


def priced(token, px, pool):
    tokens = dict(BASE["tokens"])
    tokens[token] = (px, pool)
    return tokens


def make(label, **fields):
    return dict(BASE, label=label, **fields)


def pass_cases():
    cases = [
        make("gate zero, finish only", gate=0, rows=[(1, 5, 5)]),
        make("gate two, finish only", gate=2),
        make("health error", report=(1, 0x2A, 0, 0)),
        make("health high negative", report=(0, 0, 1, 1 << 63)),
        make("health low negative", report=(0, 0, 1 << 63, 1)),
        make("high below low", report=(0, 0, 500, 100)),
        make("no user row, word zero", users={}),
        make("no user row, default set", users={}, default=(9 << 64) | 0x44),
        make("word zero, tag out", users={USER: dict(tag=0x33, word=0)}),
        make("word zero, positions", users={USER: dict(tag=0x33, word=0, positions=1)}),
        make("no positions", users={USER: dict(tag=0, word=5)}),
        make("first user of three", user=address(1), users={address(1): dict(tag=1, word=2), address(2): dict(tag=2, word=3), address(3): dict(tag=3, word=4)}),
        make("last user of three", user=address(3), users={address(1): dict(tag=1, word=2), address(2): dict(tag=2, word=3), address(3): dict(tag=3, word=4)}),
        make("user in a deep tree", user=address(9), users={address(i): dict(tag=i, word=i + 1) for i in range(1, 16)}),
        make("once path", once=True),
        make("finish result out", finish=0x2B),
        make("no rows"),
        make("no rows, capacity", cap=4),
        make("rows error kept", rows_error=OK_TAG),
        make("rows error tag", rows_error=0x12),
        make("rows error tag low", rows_error=0x10),
        make("empty token tree", tokens={}, rows=[(1, 5, 5)]),
        make("missing token", tokens={0: (PX, 1)}, rows=[(1, 5, 5)]),
        make("missing second token", rows=[(1, 0, 0), (9, 5, 5)]),
        make("token before the first key", tokens={2: (PX, 5)}, rows=[(1, 5, 0)]),
        make("capacity above length", rows=[(0, 0, 5)], cap=9),
        make("usdc supply only", rows=[(0, 0, 10 ** 6)]),
        make("usdc debt under supply", rows=[(0, 400, 1000)]),
        make("usdc debt equals supply", rows=[(0, 1000, 1000)]),
        make("usdc debt over supply, nothing to sell", rows=[(0, 1001, 1000)]),
        make("usdc debt over supply, sell listed", rows=[(0, 1001, 1000), (1, 0, 500)], spot={1: 9000}),
        make("usdc supply capped by pool", rows=[(0, 900, 1000)], tokens=priced(0, PX, 800)),
        make("usdc pool equal supply", rows=[(0, 900, 800)], tokens=priced(0, PX, 800)),
        make("usdc balance counts", rows=[(0, 900, 800)], spot={0: 100}),
        make("usdc balance short by one", rows=[(0, 901, 800)], spot={0: 100, 1: 5000}, tokens=BASE["tokens"]),
        make("usdc price floors have", rows=[(0, 0, 1)], tokens=priced(0, 3, 10)),
        make("usdc value rounds", rows=[(0, 34, 100), (1, 0, 0)], tokens=priced(0, PX // 3 + 1, 10 ** 6), spot={1: 700}),
        make("have value limit", rows=[(0, 0, VALUE_LIMIT)], tokens=priced(0, 100, 1 << 63)),
        make("have value under the limit", rows=[(0, 0, VALUE_LIMIT - 1)], tokens=priced(0, 100, 1 << 63)),
        make("need value limit", rows=[(1, VALUE_LIMIT * 100, 0)], tokens=priced(1, 1000000, 1)),
        make("need value under the limit", rows=[(1, (VALUE_LIMIT - 1) * 100, 0)], tokens=priced(1, 1000000, 1)),
        make("usdc debt value limit", rows=[(0, VALUE_LIMIT, 0)], tokens=priced(0, 100, 1)),
        make("high word of the wide value", rows=[(1, 1 << 63, 0)], tokens=priced(1, 1 << 63, 1)),
        make("token supply no debt ignored", rows=[(1, 0, 900)], spot={1: 5}),
        make("token debt covered", rows=[(1, 500, 900)]),
        make("token debt exact", rows=[(1, 900, 900)]),
        make("token debt short", rows=[(1, 901, 900)]),
        make("token debt, balance covers", rows=[(1, 1000, 900)], spot={1: 100}),
        make("token debt, balance short", rows=[(1, 1000, 800)], spot={1: 100}),
        make("token supply capped by pool", rows=[(1, 1000, 900)], tokens=priced(1, 2 * PX, 300)),
        make("token add overflow", rows=[(1, 7, 1 << 63), (1, 0, 0)], tokens=priced(1, 2 * PX, 1 << 63), spot={1: 1 << 63}),
        make("usdc add overflow", rows=[(0, 0, 1 << 63)], tokens=priced(0, 1, 1 << 63), spot={0: 1 << 63}),
        make("usdc add one below overflow", rows=[(0, 0, (1 << 63) - 1)], tokens=priced(0, 1, 1 << 63), spot={0: 1 << 63}),
        make("two tokens short, usdc covers", rows=[(0, 0, 10 ** 8), (1, 2000, 0), (2, 3000, 0)]),
        make("two tokens short, usdc thin", rows=[(0, 0, 10 ** 4), (1, 2000, 0), (2, 3000, 0), (3, 0, 40)], spot={3: 800}),
        make("sell two listed tokens", rows=[(0, 900, 100), (1, 0, 0), (2, 0, 0), (3, 0, 0)], spot={1: 900, 3: 700}),
        make("sell token zero balance", rows=[(0, 900, 100), (1, 0, 0)]),
        make("sell uses balance after cancels", rows=[(0, 900, 100), (1, 0, 0)], spot={1: 900}, after={1: 1500}),
        make("buy uses shortfall before cancels", rows=[(1, 900, 100), (0, 0, 0)], spot={1: 100}, after={1: 700}),
        make("four rows unrolled", rows=[(0, 900, 1), (1, 0, 0), (2, 0, 0), (3, 0, 0)], spot={1: 900, 2: 800, 3: 700}),
        make("five rows tail", rows=[(0, 900, 1), (1, 0, 0), (2, 0, 0), (3, 0, 0), (0, 0, 0)], spot={1: 900, 2: 800, 3: 700}),
        make("six rows tail", rows=[(0, 900, 1), (1, 0, 0), (2, 0, 0), (3, 0, 0), (0, 0, 0), (1, 0, 0)], spot={1: 900, 2: 800, 3: 700}),
        make("seven rows tail", rows=[(0, 900, 1), (1, 0, 0), (2, 0, 0), (3, 0, 0), (0, 0, 0), (1, 0, 0), (2, 0, 0)], spot={1: 900, 2: 800, 3: 700}),
        make("shortfall zero keeps a row", rows=[(1, 900, 900), (2, 900, 0), (0, 0, 0)]),
        make("system user path", user=SYSTEM, users={SYSTEM: dict(tag=1, word=2)}),
        make("user miss between keys of a deep tree", user=address(9), users={address(2 * i): dict(tag=i, word=i + 1) for i in range(1, 16)}, default=(7 << 64) | 0x55),
        make("user miss past the last key of a deep tree", user=address(99), users={address(2 * i): dict(tag=i, word=i + 1) for i in range(1, 16)}, default=(7 << 64) | 0x55),
        make("huge missing token", rows=[(1 << 63 | 5, 5, 5)]),
        make("spot tree of two levels", tokens={index: (PX, 10 ** 12) for index in range(16)}, decimals=[(4, 8)] * 16, prices={index: (0, PX) for index in range(16)},
             rows=[(0, 700, 1), (2, 0, 0), (7, 0, 0), (13, 0, 0)], spot={index: index * 1000 + 1 for index in range(16)}),
        make("spot tree miss in two levels", tokens={index: (PX, 10 ** 12) for index in range(40)}, decimals=[(4, 8)] * 40, prices={index: (0, PX) for index in range(40)},
             rows=[(0, 700, 1), (3, 0, 0), (21, 900, 0), (39, 0, 0)], spot={index: index * 1000 + 1 for index in range(0, 40, 2)}),
        make("largest debt, saturated available", rows=[(1, MASK[8], 1 << 63)], tokens=priced(1, 1, 1 << 63), spot={1: 1 << 63}),
        make("need rounds up from zero", rows=[(0, 3, 0)], tokens=priced(0, 33, 10)),
        make("shortfall rounds up", rows=[(0, 1, 100), (1, 3, 0), (2, 0, 9)], tokens=priced(1, 33, 10), spot={2: 40}),
    ]
    # every cancel outcome at every call
    many = dict(rows=[(0, 900, 100), (1, 500, 100), (2, 400, 0), (3, 0, 0)], spot={3: 900})
    for label, value in (("error", ("err", 0x12)), ("none", ("none",)), ("report tag 0", ("report", 0, 0x51)), ("report tag 1", ("report", 1, 0x52)), ("report flagged", ("flagged",))):
        for token, where in ((3, "sell"), (0, "quote"), (1, "first buy"), (2, "last buy")):
            cases.append(make("cancel %s at %s" % (label, where), cancels={token: value}, **many))
    for size in (1, 2, 3, 4, 11, 12, 13, 24, 25):
        tokens = {index: (PX, 10 ** 12) for index in range(size + 1)}
        decimals = [(4, 8)] * (size + 1)
        prices = {index: (0, PX) for index in range(size + 1)}
        cases.append(make("shortfall set of %d" % size, tokens=tokens, decimals=decimals, prices=prices, rows=[(index, 700, 0) for index in range(size, 0, -1)]))
    tokens = {index: (PX, 10 ** 12) for index in range(14)}
    cases.append(make("token tree of two levels", tokens=tokens, decimals=[(4, 8)] * 14, rows=[(13, 0, 0), (7, 0, 0)], spot={}))
    decimals_rows = []
    for diff in range(0, 9):
        table = [(8, 8), (8 - diff, 8)]
        decimals_rows.append(make("value at decimal gap %d" % diff, decimals=table, tokens={0: (PX, 10 ** 12), 1: (777 * PX // 100 + 3, 10 ** 12)}, rows=[(1, 12345678, 0)], prices={1: (0, 2 * PX)}))
    cases += decimals_rows
    cases.append(make("table too short", decimals=[(8, 8)], rows=[(1, 7, 0)]))
    cases.append(make("decimals reversed", decimals=[(8, 8), (8, 2)], rows=[(1, 7, 0)]))
    top = VALUE_LIMIT - 1
    wide = priced(0, 100, 1 << 62)
    wide[1] = (1000000, 1)
    cases.append(make("have sum overflow", rows=[(0, 0, top)] * 110, tokens=wide))
    cases.append(make("have sum just under", rows=[(0, 0, top)] * 99, tokens=wide))
    cases.append(make("need sum overflow, token rows", rows=[(1, top * 100, 0)] * 110, tokens=wide))
    cases.append(make("need sum overflow, usdc rows", rows=[(0, top, 0)] * 110, tokens=wide))
    cases.append(make("usdc debt rows after have overflow", rows=[(0, 5, top)] * 110, tokens=wide))
    cases.append(make("saturated have holds off the sell", rows=[(0, 0, top)] * 110 + [(0, top, 0)] * 20 + [(2, 0, 0)], tokens=wide, spot={2: 900}))
    cases.append(make("saturated need keeps the sell", rows=[(0, top, 0)] * 110 + [(0, 0, top)] * 12 + [(2, 0, 0)], tokens=wide, spot={2: 900}))
    return cases


def order_case(label, **fields):
    case = dict(kind="order", label=label, user=USER, token=1, mode=1, amount=10 ** 7, decimals=DECIMALS, refs=[2 * PX, 3 * PX], prices={1: (1, 2 * PX), 2: (0, 3 * PX)})
    case.update(fields)
    return case


def order_cases():
    cases = [order_case("amount zero", amount=0), order_case("amount zero buy", amount=0, mode=0), order_case("price none", prices={}), order_case("price none buy", mode=0, prices={})]
    for mode in (0, 1):
        name = "buy" if mode == 0 else "sell"
        cases += [
            order_case(name + " plain", mode=mode),
            order_case(name + " small size", mode=mode, amount=99),
            order_case(name + " one unit", mode=mode, amount=10 ** 6),
            order_case(name + " second asset", mode=mode, token=2),
            order_case(name + " notional cap", mode=mode, amount=10 ** 19),
            order_case(name + " cap meets size", mode=mode, refs=[1, 5 * 10 ** 12], amount=10 ** 7),
            order_case(name + " size one past cap", mode=mode, refs=[1, 5 * 10 ** 12], amount=2 * 10 ** 7),
            order_case(name + " ref above cap gives size zero", mode=mode, refs=[1, 10 ** 15]),
            order_case(name + " asset out of range", mode=mode, refs=[PX]),
            order_case(name + " bucket 1500", mode=mode, bucket=1500),
            order_case(name + " bucket large", mode=mode, bucket=(1 << 40) + 7),
            order_case(name + " guard above price", mode=mode, guards={1: (3 * PX, 3 * PX)}),
            order_case(name + " guard below price", mode=mode, guards={1: (PX, PX)}),
            order_case(name + " guard equals price", mode=mode, guards={1: (2 * PX, 2 * PX)}),
            order_case(name + " guard side word only", mode=mode, guards={1: (3 * PX, PX)}),
            order_case(name + " guard other side word", mode=mode, guards={1: (PX, 3 * PX)}),
            order_case(name + " guard zero", mode=mode, guards={1: (0, 0)}),
            order_case(name + " guard other token", mode=mode, guards={5: (9 * PX, 9 * PX)}),
            order_case(name + " guard same bucket", mode=mode, guards={1: (3 * PX, PX), 2: (PX, 3 * PX)}, hash=lambda token: 0x0200000000000005),
            order_case(name + " guard same tag, later slot", mode=mode, guards={index: (index * PX, index * PX) for index in (5, 1, 2)}, hash=lambda token: 0x0200000000000005),
            order_case(name + " guard past first group", mode=mode, token=1, guards={index: (PX * (9 if index > 1 else 8),) * 2 for index in range(1, 20)}, hash=lambda token: 0x0200000000000000 if token != 1 else 0x0200000000000000),
            order_case(name + " guard miss after full group", mode=mode, token=1, guards={index: (PX * 9, PX * 9) for index in range(2, 20)}, hash=lambda token: 0x0200000000000000),
            order_case(name + " guard tag differs in the group", mode=mode, guards={1: (3 * PX, 3 * PX), 2: (PX, PX)}, hash=lambda token: (token << 57) | 3),
            order_case(name + " guard third slot of one tag", mode=mode, token=2, guards={0: (PX, PX), 1: (PX, PX), 2: (9 * PX, 9 * PX)}, hash=lambda token: 0x0200000000000005),
            order_case(name + " guard sits first in the second group", mode=mode, token=19, decimals=[(4, 8)] * 20, prices={19: (1, 2 * PX)}, guards={index: (PX * 9, PX * 9) for index in range(3, 20)},
                       hash=lambda token: 0x0200000000000000),
            order_case(name + " guard table, asset out of range", mode=mode, refs=[PX], guards={1: (PX, PX)}),
            order_case(name + " cap at reference 1", mode=mode, token=2, refs=[1, 1], amount=1 << 63),
        ]
    return cases


def all_cases():
    cases = []
    for layout in COPIES:
        name = layout["name"]
        for case in pass_cases():
            if layout["snapshot"] and (case["report"][2] >> 63 or case["report"][3] >> 63):
                continue
            cases.append(dict(case, copy=name))
        cases += [dict(case, copy=name) for case in order_cases()]
    return cases


# ---- comparison ----

def show(left, right):
    for index, (one, two) in enumerate(zip(left, right)):
        if one != two:
            return "event %d: %r, want %r" % (index, one, two)
    return "length %d, want %d" % (len(left), len(right))


def compare_run(harness, case):
    label = "%s %s/%s" % (case["kind"], case["label"], case.get("copy", "primary"))
    try:
        if case["kind"] == "pass":
            try:
                want = pass_spec(case)
            except Panicked as panic:
                want = dict(panic=str(panic))
            try:
                result, gate = harness.run_pass(case)
            except Panicked as panic:
                return "" if want.get("panic") == str(panic) else "%s: panic %s" % (label, panic)
            if "panic" in want:
                return "%s: no panic" % label
            if BY_NAME[case.get("copy", "primary")]["snapshot"]:
                # clone, health read and the drop after a failed read sit inside the stubbed snapshot.
                want["events"] = [event for index, event in enumerate(want["events"]) if event not in (("clone",), ("health",), ("once",)) and not (case["report"][0] and event == ("drop",))]
            if harness.events != want["events"]:
                return "%s: %s" % (label, show(harness.events, want["events"]))
            if result != want["result"]:
                return "%s: result %#x" % (label, result)
            if gate != (0 if want["cleared"] else case["gate"]):
                return "%s: gate %d" % (label, gate)
            # The copies carry their own Location records, so only the primary compares addresses.
            if (harness.logs if case.get("copy", "primary") == "primary" else len(harness.logs)) != (want["logs"] if case.get("copy", "primary") == "primary" else len(want["logs"])):
                return "%s: logs %r" % (label, harness.logs)
            if sorted(harness.frees) != sorted(want["frees"]):
                return "%s: frees %r, want %r" % (label, harness.frees, want["frees"])
            if harness.nodes:
                return "%s: %d map nodes live" % (label, harness.nodes)
            return ""
        try:
            want = order_spec(case)
        except Panicked as panic:
            want = str(panic)
        try:
            harness.run_order(case)
        except Panicked as panic:
            return "" if want == str(panic) else "%s: panic %s" % (label, panic)
        if isinstance(want, str):
            return "%s: no panic" % label
        return "" if harness.events == want else "%s: %s" % (label, show(harness.events, want))
    except Exception as stop:
        return "%s: stopped: %r" % (label, stop)


def relative_slots(image):
    return {slot: addend for slot, kind, addend, _ in image.relocations() if kind == 8}


# ---- static evidence ----

STUBS = (
    ("0x28db540, 0x289a040, 0x28abf00 and the copies", "health read, row clone, row drop; arguments checked, report given by the case. 0x28db540 is mapped by others"),
    ("0x46f2be0, 0x46f2960", "snapshot in the copies: row copy plus gap, given by the case; bound by #629"),
    ("0x3739ef0", "row collector, pinned by the bole step packet; argument checked, rows given"),
    ("0x371b3a0", "spot balance view of the user; arguments checked, a B-tree view given"),
    ("0x232b4f0, 0x48ce500", "cancel of the user's orders for one token; all 7 arguments checked, outcome given"),
    ("0x2739210, 0x46f1b90, 0x46f12a0", "cancel report consumer, listed by #629; arguments checked"),
    ("0x2730520, 0x4d3a7e0, 0x4d39ce0", "event writer, called with the system address, 4 and 6; arguments checked"),
    ("0x2739b00, 0x46f26f0, 0x46f2480", "post check and shortfall set insert, bound by #629; arguments checked, result given"),
    ("0x3736960", "order price, pinned by the price band packet; arguments and slippage checked, asset and price given"),
    ("0x399c4a0", "hasher for the guard table; key checked, a fixed mix returned"),
    ("0x32780d0", "reference price of the book, pinned by the book mid sampler packet; book address checked, price given"),
    ("0x24fa890, 0x4ae93a0, 0x4ae87e0", "order entry; both records checked word by word"),
)
POINTER = "pointer high bytes are 0 in the harness heap"
PAST_KEY = "moves the stop test past the last key; poison keys end the walk at the same row"
LENGTH = "node length read at another offset; poison keys end the walk at the same row"
SATURATED = "saturated word minus 1 takes the same compare in every case"
BACK = "back handle of the map iterator, never read when walking from the front"
TAG = "failure tag; the wrapper compares it only with 0x11"
REASONS = {
    "pass": {0x273A0FD: POINTER, 0x273A111: POINTER, 0x273A1D5: PAST_KEY, 0x273A27C: LENGTH, 0x273A40F: SATURATED, 0x273A433: SATURATED, 0x273A625: PAST_KEY, 0x273A7A5: LENGTH,
             0x273AA02: BACK, 0x273AD25: BACK, 0x273AE0B: "panic message length; the panic stub reads no argument", 0x273A0B3: "map is empty when row collection fails",
             0x273A0CF: "map is empty when row collection fails", 0x273A0EB: "map is empty when row collection fails"},
    "body": {0x46F75EF: POINTER, 0x46F7603: POINTER, 0x46F767C: TAG, 0x46F76A7: PAST_KEY, 0x46F775E: LENGTH, 0x46F790E: SATURATED, 0x46F7932: SATURATED, 0x46F79C2: TAG, 0x46F7A17: BACK,
             0x46F7B95: PAST_KEY, 0x46F7D11: LENGTH, 0x46F7EBE: BACK, 0x46F7FA8: TAG, 0x46F7FE4: BACK, 0x46F80C9: BACK, 0x46F8299: TAG, 0x46F82F7: TAG},
    "order": {0x2765460: "the pattern byte fills every lane, so the dword order does not matter", 0x27654A1: "the walk over match bits still reaches the slot in each case",
              0x27654C3: "third probe group needs more than the 32 buckets of the fixture"},
}
BASES = {"pass": COPIES[0]["entry"], "body": COPIES[1]["body"], "order": COPIES[0]["order"]}
GROUP_REASONS = "cold unwind or allocation failure path"


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
    rows = []
    for layout in COPIES:
        name = layout["name"]
        rows.append(("order " + name, *image.exact_fde(layout["order"])))
        if layout["snapshot"]:
            rows.append(("wrapper " + name, *image.exact_fde(layout["entry"])))
            rows.append(("body " + name, *image.exact_fde(layout["body"])))
        else:
            rows.append(("pass " + name, *image.exact_fde(layout["entry"])))
    return rows


def constants(image):
    rows = []
    for name, at, want in (("sell slippage f64", 0x20A2F8, SLIP_SELL), ("buy slippage f64", 0x20B168, SLIP_BUY), ("milliseconds per second f64", 0x20AF40, 1000.0)):
        value = struct.unpack_from("<d", image.blob, image.offset(at))[0]
        if value != want:
            raise EvidenceError("constant moved: " + name)
        rows.append({"name": name, "address": "%#x" % at, "value": value})
    for layout in COPIES:
        begin, end = image.exact_fde(layout["order"])
        base = image.offset(begin)
        at = bytes(image.blob[base:base + end - begin]).find(b"\x48\xb8" + struct.pack("<Q", NOTIONAL_CAP))
        if at < 0:
            raise EvidenceError("notional cap moved")
        rows.append({"name": "order cap numerator, " + layout["name"], "address": "%#x" % (begin + at), "value": NOTIONAL_CAP})
    begin, end = image.exact_fde(VALUE)
    base = image.offset(begin)
    at = bytes(image.blob[base:base + end - begin]).find(b"\x48\xba" + struct.pack("<Q", VALUE_LIMIT))
    if at < 0:
        raise EvidenceError("value limit moved")
    rows.append({"name": "value limit in 0x32815f0", "address": "%#x" % (begin + at), "value": VALUE_LIMIT})
    return rows


def call_map(image):
    wanted = [layout["entry"] for layout in COPIES] + [layout["order"] for layout in COPIES] + [layout["body"] for layout in COPIES if layout["body"]]
    direct = direct_callers(image, wanted)
    return [{"function": "%#x" % target, "direct_calls_from": ["%#x" % site for site in direct[target]], "callers": sorted({"%#x" % image.fde(site)[0] for site in direct[target]})} for target in wanted]


def twin_rows(image):
    """Same operation list in each pair; a call target or the book table offset is all that moves."""
    rows = []
    for left, right in ((COPIES[1]["body"], COPIES[2]["body"]), (COPIES[0]["order"], COPIES[1]["order"]), (COPIES[1]["order"], COPIES[2]["order"]), (COPIES[1]["entry"], COPIES[2]["entry"])):
        one, two = rows_of(image, left), rows_of(image, right)
        same = len(one) == len(two) and all(a.op == b.op and a.size == b.size for a, b in zip(one, two))
        moved = 0
        for a, b in zip(one, two):
            base_a, base_b = image.offset(a.va), image.offset(b.va)
            if bytes(image.blob[base_a:base_a + a.size]) != bytes(image.blob[base_b:base_b + b.size]):
                moved += 1
        rows.append({"left": "%#x" % left, "right": "%#x" % right, "instructions": len(one), "same_operation_list": same, "instructions_with_other_bytes": moved})
    return rows


def body_tags(image):
    """Bytes the outlined bodies load into r12b as their result, from the fixed encoding 41 B4 imm8."""
    rows = []
    for layout in COPIES[1:]:
        begin, end = image.exact_fde(layout["body"])
        tags = []
        for row in decode_range(image, begin, end):
            data = text_at(image, row.va, row.size)
            if row.size == 3 and data[:2] == b"\x41\xb4":
                tags.append({"site": "%#x" % row.va, "tag": data[2]})
        rows.append({"body": "%#x" % begin, "tags": tags})
    return rows


def text_at(image, va, count):
    base = image.offset(va)
    return bytes(image.blob[base:base + count])


def wrapper_calls(image):
    rows = []
    for layout in COPIES[1:]:
        rows.append({"copy": layout["name"], "wrapper": "%#x" % layout["entry"], "calls": ["%#x" % row.target for row in rows_of(image, layout["entry"]) if row.op == "call"]})
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
    if case["kind"] == "order":
        try:
            events = order_spec(case)
        except Panicked:
            return "panic"
        return "order placed" if events and events[-1][0] == "place" else "no order"
    try:
        want = pass_spec(case)
    except Panicked:
        return "panic"
    kinds = {event[0] for event in want["events"]}
    if "rows" not in kinds:
        return "stopped before rows" if "finish" not in kinds else "gate closed"
    prices = [event for event in want["events"] if event[0] == "price"]
    name = "sell and buy" if {event[2] for event in prices} == {0, 1} else "sell only" if prices and prices[0][2] else "buy only" if prices else "no order"
    return name + (", gate released" if want["cleared"] else "")


def path_rows():
    return [
        ("1", "user row", "0x2739d70 head", "find the user in the map at +0x598, or use the default row"),
        ("2", "health read", "0x28db540", "read failure returns its byte; negative words panic in unwrap; row word +8 of 0 returns the row byte"),
        ("3", "gate", "+0x5b3", "only byte 1 enters the body; every other value goes to step 12"),
        ("4", "rows", "0x3739ef0", "rows (token, debt, supply) of the system user; failure releases the gate unless its byte is 0x11"),
        ("5", "row scan", "0x2739d70 loop", "available = min(supply, pool word +0x18) + spot balance, saturating; token 0 adds its floor value to have; other tokens with debt record shortfall = debt - available, saturating at 0"),
        ("6", "need", "0x32815f0", "need adds the ceil value of the token 0 debt and of every shortfall, at the row price"),
        ("7", "sell loop", "need > have", "for tokens other than 0 with no debt row: cancel, read the balance after the cancel, sell it all"),
        ("8", "quote cancel", "need > 0", "cancel token 0 once, then the buy loop"),
        ("9", "buy loop", "need > 0", "in key order: cancel, buy the shortfall computed before any cancel"),
        ("10", "order", "0x27653a0", "slippage 0.01 sell, 0.005 buy; guard words keep sell at or above and buy at or below; size = min(wei to size, 5e13 / reference price); a sell of size 0 stops, a buy of size 0 still goes out"),
        ("11", "release", "+0x5b3", "missing token, value limit or a failed cancel clears the gate, before the writer in step 12"),
        ("12", "finish", "0x2730520, 0x2739b00", "event writer with the system address, then the post check with gap = high word - low word"),
    ]


def order_samples(image):
    harness = Harness(image)
    rows = []
    for label, fields in (
        ("sell, no guard", dict(mode=1)),
        ("buy, no guard", dict(mode=0)),
        ("sell, guard above price lifts it", dict(mode=1, guards={1: (3 * PX, 3 * PX)})),
        ("sell, guard below price leaves it", dict(mode=1, guards={1: (PX, PX)})),
        ("buy, guard below price lowers it", dict(mode=0, guards={1: (PX, PX)})),
        ("buy, guard above price leaves it", dict(mode=0, guards={1: (3 * PX, 3 * PX)})),
        ("sell, cap binds", dict(mode=1, amount=10 ** 19)),
        ("buy, cap binds", dict(mode=0, amount=10 ** 19)),
        ("sell, size under one unit stops", dict(mode=1, amount=99)),
        ("buy, size under one unit still goes out", dict(mode=0, amount=99)),
    ):
        case = order_case(label, **fields)
        harness.run_order(case)
        placed = [event for event in harness.events if event[0] == "place"]
        price = [event for event in harness.events if event[0] == "price"][0]
        rows.append((label, fields["mode"], fields.get("amount", case["amount"]), price[3], *(placed[0][1:4] if placed else ("none", "none", "none"))))
    return rows


def decision_samples(image):
    harness = Harness(image)
    rows = []
    for label, fields in (
        ("usdc debt equals usdc available", dict(rows=[(0, 1000, 1000), (1, 0, 0)], spot={1: 9 * 10 ** 7})),
        ("usdc debt one above, token listed", dict(rows=[(0, 1001, 1000), (1, 0, 500)], spot={1: 9 * 10 ** 7})),
        ("token debt covered by supply", dict(rows=[(1, 500, 900)])),
        ("token short, usdc value covers", dict(rows=[(0, 0, 10 ** 8), (1, 2 * 10 ** 7, 0), (3, 0, 0)], spot={3: 8 * 10 ** 7})),
        ("token short, usdc value thin", dict(rows=[(0, 0, 10), (1, 2 * 10 ** 7, 0), (3, 0, 0)], spot={3: 8 * 10 ** 7})),
        ("token with debt is never sold", dict(rows=[(0, 900, 100), (1, 5 * 10 ** 7, 100)], spot={1: 9 * 10 ** 7})),
        ("missing token releases the gate", dict(rows=[(1, 0, 0), (9, 5, 5)])),
        ("cancel error releases the gate", dict(rows=[(1, 2 * 10 ** 7, 0)], cancels={1: ("err", 0x12)})),
    ):
        case = make(label, **fields)
        result, gate = harness.run_pass(case)
        orders = ["%s:%d:%d" % ("sell" if event[4] else "buy", event[1], event[2]) for event in harness.events if event[0] == "place"]
        cancels = [str(event[1]) for event in harness.events if event[0] == "cancel"]
        rows.append((label, ",".join(cancels) or "none", ",".join(orders) or "none", gate, "%#x" % result))
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
        "twins": twin_rows(image),
        "wrapper_calls": wrapper_calls(image),
        "body_tags": body_tags(image),
        "stubs": [{"edge": edge, "role": role} for edge, role in STUBS],
        "cases": {"total": len(cases), "outcomes": dict(sorted(outcomes.items()))},
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


def reason_for(row, begins):
    family = row["group"].split()[0]
    table = REASONS.get(family, {})
    return table.get(row["va"] - begins[row["group"]] + BASES.get(family, 0), GROUP_REASONS)


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
    write_tsv(out / "order-samples.tsv", ("label", "side", "amount", "slippage", "asset", "size", "price"), order_samples(image))
    write_tsv(out / "decision-samples.tsv", ("label", "cancels", "orders", "gate_after", "result"), decision_samples(image))
    begins = {role: begin for role, begin, _ in groups(image)}
    lines = ["group\tva\tkind\tresult\tkilled_by\treason"]
    for row in results:
        reason = "" if row["result"] == "killed" else reason_for(row, begins)
        lines.append("%s\t%#x\t%s\t%s\t%s\t%s" % (row["group"], row["va"], row["kind"], row["result"], row["by"], reason))
    (out / "mutations.tsv").write_text("\n".join(lines) + "\n", encoding="utf-8", newline="\n")
    print("cases %d, mismatches %d, mutants %r" % (evidence["cases"]["total"], evidence["mismatches"], evidence["mutations"]))
    return 0


if __name__ == "__main__":
    sys.exit(main())
