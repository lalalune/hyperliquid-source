#!/usr/bin/env python3
"""Reconstruct the node #115 BOLE interest index writer 0x36a0200 from ELF bytes and check it against an independent model.

The writer takes one token row, the block time and a reserve share, and moves the row's borrow and supply interest indices forward by
the elapsed span. A Python evaluator steps the real instruction bytes; a separately written specification (exact integers, no
instruction semantics) predicts every row word and every overflow-log call. Generated and hand-written cases compare the two, flawed
specifications, corrupted inputs and killed byte mutants show that the comparison can tell. No objdump or readelf output is parsed,
and the binary is never executed. Standard library plus the two repository parsers only.
"""

import argparse
import bisect
import datetime
import hashlib
import json
import pathlib
import struct
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))

from elf_index import sections  # noqa: E402
from fde_extents import eh_frame_records  # noqa: E402

BINARY = ROOT / "artifacts" / "node" / "115" / "hl-node"
SHA256 = "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301"

ACCRUE = 0x36A0200
UDIV = 0x63EFEC0
OVERFLOW_LOG = 0x4524E40
REFRESH = 0x369A480
SLOT_ACCRUE = 0x64E7828
SLOT_UDIV = 0x64DFAF8
SLOT_LOG = 0x64E4EA8
E14 = 10 ** 14
YEAR_MS = 31557600000
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
        if rela["size"] % 24:
            raise EvidenceError("truncated RELA section")
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

# ---- time words, arithmetic and the specification ----

def to_signed(value):
    return value - (1 << 64) if value & SIGN[8] else value


def jan1_ordinal(year):
    """Proleptic Gregorian ordinal of January 1 of a year of at least 1, by integer arithmetic so any 19 bit year works."""
    before = year - 1
    return before * 365 + before // 4 - before // 100 + before // 400 + 1


def unix_millis(date_word, secs, frac):
    """Block time words to Unix milliseconds; the epoch date is ordinal 719163 of the proleptic calendar.

    Years below 1 are lifted by whole 400 year cycles, which keeps the calendar position, so the date always clamps at zero later."""
    signed = date_word - (1 << 32) if date_word & SIGN[4] else date_word
    year = signed >> 13
    ordinal = (date_word >> 4) & 0x1FF
    cycles = 0
    while year < 1:
        year += 400
        cycles += 1
    days = jan1_ordinal(year) + ordinal - 1 - cycles * 146097 - EPOCH_ORDINAL
    return days * 86400000 + secs * 1000 + frac // 1000000


def time_word(year, ordinal, secs=0, frac=0):
    return (((year << 13) | (ordinal << 4) | 2) & MASK[4], secs, frac)


def time_from_millis(millis, extra_ns=0):
    """Inverse of unix_millis for non-negative spans between years 1 and 9999."""
    days, rest = divmod(millis, 86400000)
    day = datetime.date.fromordinal(days + EPOCH_ORDINAL)
    return time_word(day.year, day.timetuple().tm_yday, rest // 1000, (rest % 1000) * 1000000 + extra_ns)


def wide(value, factor):
    """128 by 64 multiply as the code does it: low words widen, the high word multiplies and wraps."""
    return (value & MASK[8]) * factor + (((value >> 64) * factor & MASK[8]) << 64) & ((1 << 128) - 1)


def scaled(value, factor):
    """value * factor / 1e14 with the guard that the high half stays under 1e14; None when the guard fires."""
    product = wide(value, factor)
    return None if product >> 64 > E14 - 1 else product // E14


def rate_of(row, u, flaw=None):
    low, high, bend, k = row["min"], row["max"], row["bend"], row["k"]
    if u == k:
        return low if flaw == "bend_equal_low" else bend
    if u < k:
        if flaw == "no_low_arm":
            return bend
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


def settle(row, logs, flaw=None):
    moved = row["pending"] if flaw == "settle_ignores_balance" else min(row["pending"], row["balance"])
    row["balance"] = (row["balance"] - moved) & MASK[8]
    row["pending"] -= moved
    total = row["paid"] + moved
    if total >> 64 and flaw != "paid_log_missing":
        logs.append("paid")
    row["paid"] = (total & MASK[8]) if flaw == "paid_wraps" else min(total, MASK[8])


def accrue_spec(before, now, keep, flaw=None):
    """Interest index writer: returns the row after the call and the overflow log rows.

    Every guard that fires leaves the row untouched and unstamped. `flaw` names one deliberate fault used only by the negative controls."""
    year_ms = 365 * 86400000 if flaw == "year_365_days" else YEAR_MS
    row, logs = dict(before), []
    if row["time"] == now:
        if flaw != "same_time_skips_settle":
            settle(row, logs, flaw)
        return row, logs
    a, ia, b, ib = row["a"], row["ia"], row["b"], row["ib"]
    product = a * ia
    borrowed = product // E14 if flaw == "borrow_floor" else (product + E14 - 1) // E14
    if flaw != "supply_guard_missing" and (b * ib) >> 64 > E14 - 1:
        return row, logs
    supplied = (b * ib + E14 - 1) // E14 if flaw == "supply_ceil" else (b * ib) // E14
    if flaw != "borrow_guard_missing" and borrowed >> 64:
        return row, logs
    u = 0
    if supplied:
        u = borrowed * E14 // supplied
        if u >> 64:
            return row, logs
        if flaw != "use_cap_missing":
            u = min(u, E14)
    rate = rate_of(row, u, flaw)
    now_ms = max(unix_millis(*now) + (1 if flaw == "epoch_off_by_ms" else 0), 0)
    last_ms = unix_millis(*row["time"])
    if flaw != "clock_check_missing" and last_ms > now_ms:
        return row, logs
    elapsed = max(now_ms - max(last_ms, 0), 0)
    if elapsed > year_ms or (flaw == "year_inclusive" and elapsed == year_ms):
        return row, logs
    grown = scaled(elapsed * rate // year_ms, ia)
    if grown is None:
        return row, logs
    share = 0
    if b:
        share = (a * E14 + b - 1) // b if flaw == "share_ceil" else a * E14 // b
        if flaw != "share_guard_missing" and share >> 64:
            return row, logs
    supply = scaled(grown, share)
    if supply is None:
        return row, logs
    fee = scaled(supply, keep)
    if fee is None:
        if flaw != "fee_guard_missing":
            return row, logs
        fee = 0
    tokens = scaled(fee, a if flaw == "tokens_from_borrow" else b)
    if tokens is None:
        return row, logs
    if flaw != "fee_above_supply_ignored" and (supply & MASK[8]) < (fee & MASK[8]):
        return row, logs
    next_ia = ia + (grown & MASK[8])
    next_ib = ib + (((supply & MASK[8]) - (fee & MASK[8])) & MASK[8])
    if flaw == "index_wrap_unchecked":
        next_ia, next_ib = next_ia & MASK[8], next_ib & MASK[8]
    if next_ia >> 64 or next_ib >> 64:
        return row, logs
    if flaw == "swapped_indices":
        next_ia, next_ib = next_ib, next_ia
    row["time"] = now
    total = row["pending"] + (tokens & MASK[8])
    if flaw == "pending_replaced":
        total = tokens & MASK[8]
    if total >> 64 and flaw != "pending_log_missing":
        logs.append("pending")
    row["pending"] = (total & MASK[8]) if flaw == "pending_wraps" else min(total, MASK[8])
    row["ib"], row["ia"] = next_ib, next_ia
    settle(row, logs, flaw)
    return row, logs


FLAWS = (
    "borrow_floor", "supply_ceil", "use_cap_missing", "year_365_days", "year_inclusive", "supply_guard_missing", "borrow_guard_missing",
    "share_guard_missing", "share_ceil", "fee_guard_missing", "fee_above_supply_ignored", "index_wrap_unchecked", "swapped_indices",
    "pending_wraps", "paid_wraps", "pending_replaced", "pending_log_missing", "paid_log_missing", "clock_check_missing", "epoch_off_by_ms",
    "same_time_skips_settle", "settle_ignores_balance", "tokens_from_borrow", "no_low_arm", "bend_equal_low",
)

ROW_FIELDS = ((0x10, "px"), (0x18, "balance"), (0x20, "paid"), (0x28, "pending"), (0x30, "low"), (0x38, "high"), (0x40, "a"), (0x58, "ia"), (0x60, "b"),
              (0x78, "ib"), (0x80, "min"), (0x88, "max"), (0x90, "bend"), (0x98, "k"))
TIME_AT = 0xA0


def row_key(row):
    return tuple(row[name] for _, name in ROW_FIELDS) + tuple(row["time"])


# ---- cases ----

NOW = (2024 << 13 | 200 << 4 | 2, 3600, 5000000)
AGO = (2024 << 13 | 199 << 4 | 2, 3600, 5000000)


def token(time=AGO, **fields):
    row = dict(px=7, balance=0, paid=0, pending=0, low=0, high=0, a=10 ** 8, ia=E14, b=2 * 10 ** 8, ib=E14, min=E14 // 100, max=E14 // 2, bend=E14 // 10,
               k=8 * E14 // 10, time=time)
    row.update(fields)
    return row


def hand_cases():
    year_ago = (2023 << 13 | 200 << 4 | 2, 3600, 5000000)
    out = []
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
        ("supply index wraps with real growth", token(ib=(1 << 64) - 1, a=10 ** 8, b=10 ** 8), NOW, 0),
        ("both indices wrap with real growth", token(ia=(1 << 64) - 1, ib=(1 << 64) - 1, a=10 ** 8, b=10 ** 8), NOW, 0),
        ("borrow index lands on 2^64 - 1", token(ia=(1 << 64) - 1 - 22831, a=10 ** 8, b=10 ** 8), NOW, 0),
    ):
        out.append(dict(label=label, row=row, time=now, keep=keep))
    return out


EDGES = (0, 1, 2, 3, 7, 10 ** 4, 10 ** 8, 2 * 10 ** 8, E14 // 100, E14 // 10, E14 // 2, E14 - 1, E14, E14 + 1, 2 * E14, 10 ** 15, 10 ** 18, 1 << 32, 1 << 40,
         1 << 53, 1 << 56, 1 << 62, 1 << 63, (1 << 63) + 1, (1 << 64) - 1000, (1 << 64) - 3, (1 << 64) - 2, (1 << 64) - 1)
RATES = (0, 1, E14 // 1000, E14 // 100, E14 // 20, E14 // 10, E14 // 4, E14 // 2, E14, 3 * E14, 10 * E14, 1 << 62, 1 << 63, (1 << 64) - 1)
BENDS = (0, 1, E14 // 4, E14 // 2, 7 * E14 // 10, 8 * E14 // 10, 9 * E14 // 10, E14 - 1, E14, E14 + 1, 2 * E14)
CLOCKS = ((2024, 200), (2024, 1), (2024, 366), (2023, 365), (2100, 59), (1970, 1), (1970, 2), (1969, 300), (1965, 366), (2, 1), (1, 1), (9999, 200), (-3, 100), (-401, 1))
SPANS = (0, 1, 999, 1000, 1001, 60000, 3600000, 86399999, 86400000, 86400001, 31449600000, YEAR_MS - 1, YEAR_MS, YEAR_MS + 1, YEAR_MS + 86400000, -1, -1000, -86400000)
KEEPS = (0, 1, E14 // 100, E14 // 10, E14 // 5, E14 // 2, E14 - 1, E14, E14 + 1, 2 * E14, (1 << 64) - 1)


class Rng:
    """xorshift64* so generated cases do not depend on the interpreter's random module."""

    def __init__(self, seed):
        self.state = seed

    def next(self):
        x = self.state
        x ^= x >> 12
        x ^= (x << 25) & MASK[8]
        x ^= x >> 27
        self.state = x
        return (x * 0x2545F4914F6CDD1D) & MASK[8]

    def pick(self, pool):
        return pool[self.next() % len(pool)]

    def below(self, bound):
        return self.next() % bound


def ordinary(rng, low, high):
    return low + rng.below(high - low)


def generated_row(rng, profile):
    if profile == 0:
        fields = dict(a=ordinary(rng, 1, 10 ** 12), ia=E14 + ordinary(rng, 0, 10 ** 12), b=ordinary(rng, 1, 10 ** 13), ib=E14 + ordinary(rng, 0, 10 ** 12),
                      min=ordinary(rng, 0, E14 // 10), max=ordinary(rng, E14 // 2, E14), bend=ordinary(rng, E14 // 100, E14 // 3), k=ordinary(rng, 1, E14))
    elif profile == 1:
        fields = {name: rng.pick(EDGES) for name in ("a", "ia", "b", "ib")}
        fields.update(min=rng.pick(RATES), max=rng.pick(RATES), bend=rng.pick(RATES), k=rng.pick(BENDS))
    elif profile == 2:
        fields = {name: (1 << ordinary(rng, 30, 64)) + rng.below(1 << 20) for name in ("a", "ia", "b", "ib")}
        fields.update(min=rng.pick(RATES), max=rng.pick(RATES), bend=rng.pick(RATES), k=rng.pick(BENDS))
    else:
        base = generated_row(rng, 0)
        for name in ("a", "ia", "b", "ib", "min", "max", "bend", "k"):
            if rng.below(3) == 0:
                base[name] = rng.pick(EDGES if name in ("a", "ia", "b", "ib") else RATES)
        fields = base
    for name in ("balance", "paid", "pending", "low", "high", "px"):
        fields[name] = rng.pick(EDGES) if rng.below(4) == 0 else ordinary(rng, 0, 10 ** 9)
    return fields


def generated_cases(count):
    rng = Rng(0x9E3779B97F4A7C15)
    for index in range(count):
        profile = index % 4
        year, ordinal = rng.pick(CLOCKS)
        now = time_word(year, ordinal, ordinary(rng, 0, 86400), ordinary(rng, 0, 10 ** 9))
        span = rng.pick(SPANS) if rng.below(3) else ordinary(rng, 0, 2 * YEAR_MS)
        now_ms = unix_millis(*now)
        extra = rng.below(1000000) if rng.below(2) else 0
        if now_ms - span >= 0 and span >= 0:
            then = time_from_millis(now_ms - span, extra)
        elif span < 0:
            then = time_from_millis(max(now_ms - span, 0), extra)
        else:
            then = time_word(year - 1, ordinal, 0, 0)
        if rng.below(40) == 0:
            then = now
        keep = rng.pick(KEEPS) if rng.below(2) else ordinary(rng, 0, E14)
        row = token(then, **generated_row(rng, profile))
        yield dict(label="generated %d" % index, row=row, time=now, keep=keep)


CALENDAR_SPECIALS = (10000, 16384, 32767, 65535, 100000, 131071, 200000, 262142, 262143, 1583, 1600, 1700, 1800, 1900, 1969, 1970, 2000, 2024, 2100, 2399, 2400, 4000, 9999, -1, -4, -100, -400, -401, -800, 0)
CALENDAR_ORDINALS = (1, 2, 59, 60, 61, 100, 200, 300, 365)


def calendar_cases():
    """One day of accrual at years spread over the calendar, so every term of the date arithmetic is exercised for the row time and the clock."""
    for year in list(range(1, 3001, 3)) + list(range(10001, 262144, 1999)) + list(CALENDAR_SPECIALS):
        for ordinal in ((year * 7) % 365 + 1,) if year in range(1, 3001, 3) or year in range(10001, 262144, 1999) else CALENDAR_ORDINALS:
            before = time_word(year, ordinal - 1, 0, 0) if ordinal > 1 else time_word(year - 1, 365, 0, 0)
            yield dict(label="calendar %d/%d" % (year, ordinal), row=token(before), time=time_word(year, ordinal, 0, 0), keep=E14 // 10)


# ---- harness around the real bytes ----

class Harness:
    def __init__(self, image):
        self.image = image
        machine = self.machine = Machine(image)
        machine.real = frozenset({ACCRUE})
        machine.jump_ranges = [image.exact_fde(ACCRUE)]
        machine.calls = {}
        self.at = BUMP
        self.logs = []
        self.divides = 0
        relative = {slot: addend for slot, kind, addend, _ in image.relocations() if kind == 8}
        for at, (target, hook) in enumerate(((UDIV, self.on_div), (OVERFLOW_LOG, self.on_log))):
            token_va = 0x7000000 + at * 16
            machine.slots[token_va] = hook
            for slot, aim in relative.items():
                if aim == target:
                    machine.memory.statics[slot] = token_va

    def bump(self, size):
        here = self.at
        self.at += (size + 15) & ~15
        if self.at >= HEAP_BASE + HEAP_SIZE:
            raise Halt("heap exhausted")
        return here

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
        self.divides += 1

    def on_log(self, machine):
        self.logs.append(machine.regs[RSI])

    def put_row(self, at, row):
        memory = self.machine.memory
        for offset, name in ROW_FIELDS:
            memory.write(at + offset, 8, row[name])
        memory.put_bytes(at + TIME_AT, struct.pack("<III", *row["time"]))

    def read_row(self, at):
        memory = self.machine.memory
        row = {name: memory.read(at + offset, 8) for offset, name in ROW_FIELDS}
        row["time"] = struct.unpack("<III", memory.bytes_at(at + TIME_AT, 12))
        return row

    def run(self, case):
        machine, memory = self.machine, self.machine.memory
        memory.reset()
        self.at, self.logs, self.divides = BUMP, [], 0
        at = self.bump(0xB0)
        self.put_row(at, case["row"])
        time_at = self.bump(16)
        memory.put_bytes(time_at, struct.pack("<III", *case["time"]))
        machine.run(ACCRUE, {RDI: at, RSI: time_at, RDX: case["keep"]})
        return self.read_row(at)


def row_diff(got, want):
    for name in sorted(want):
        if got[name] != want[name]:
            return "%s %r wanted %r" % (name, got[name], want[name])
    return ""


def compare(harness, case, flaw=None):
    """Run the real bytes and the specification; return an empty string when they agree."""
    try:
        got = harness.run(case)
    except Exception as stop:
        return "stopped: %r" % (stop,)
    want, logs = accrue_spec(case["row"], case["time"], case["keep"], flaw)
    if len(harness.logs) != len(logs):
        return "log rows %d wanted %d" % (len(harness.logs), len(logs))
    return row_diff(got, want)


def outcome_of(case):
    row, logs = accrue_spec(case["row"], case["time"], case["keep"])
    if row["time"] != case["time"]:
        return "left unstamped"
    if case["row"]["time"] == case["time"]:
        return "same time"
    return "stamped, %d overflow logs" % len(logs) if logs else "stamped"


# ---- static evidence from bytes ----

def function_facts(image, start):
    begin, end = image.exact_fde(start)
    rows = decode_range(image, begin, end)
    base = image.offset(begin)
    data = bytes(image.blob[base:base + end - begin])
    return begin, end, rows, data


def displacement_counts(rows):
    counts = {}
    for row in rows:
        for operand in (row.a, row.b):
            if operand and operand[0] == "m" and operand[1] not in (None, RSP) and operand[4]:
                key = operand[4] & MASK[8] if operand[4] >= 0 else operand[4]
                counts[key] = counts.get(key, 0) + 1
    return counts


def indirect_calls(image, rows, relative):
    found = []
    for row in rows:
        if row.op == "calli" and row.a[0] == "m" and row.a[1] is None:
            slot = row.a[4]
            found.append({"site": "%#x" % row.va, "slot": "%#x" % slot, "relocated_target": "%#x" % relative[slot] if slot in relative else "none"})
    return found


def log_locations(image, rows, relative):
    """Each overflow-log call is preceded by a RIP-relative lea into rsi that names a Location record."""
    sites = []
    for at, row in enumerate(rows):
        if row.op == "calli" and row.a[0] == "m" and row.a[1] is None and relative.get(row.a[4]) == OVERFLOW_LOG:
            for back in range(at - 1, max(at - 8, -1), -1):
                prior = rows[back]
                if prior.op == "lea" and prior.a == ("r", RSI):
                    path, line, column = image.location(prior.b[4], relative)
                    sites.append({"call": "%#x" % row.va, "lea": "%#x" % prior.va, "record": "%#x" % prior.b[4], "path": path, "line": line, "column": column})
                    break
    return sites


def immediate_sites(begin, data, value):
    pattern = struct.pack("<Q", value)
    found, at = [], data.find(pattern)
    while at >= 0:
        found.append("%#x" % (begin + at))
        at = data.find(pattern, at + 1)
    return found


def caller_boundary(image, relative):
    """The only direct use of the writer in the refresh body: an indirect call through a slot that a relative relocation points at the writer."""
    begin, end = image.exact_fde(REFRESH)
    base = image.offset(begin)
    data = bytes(image.blob[base:base + end - begin])
    sites = []
    at = data.find(b"\xff\x15")
    while at >= 0:
        slot = begin + at + 6 + struct.unpack_from("<i", data, at + 2)[0]
        if relative.get(slot) == ACCRUE:
            sites.append("%#x" % (begin + at))
        at = data.find(b"\xff\x15", at + 1)
    return {"refresh_start": "%#x" % begin, "refresh_end": "%#x" % end, "slot": "%#x" % SLOT_ACCRUE, "slot_target": "%#x" % relative[SLOT_ACCRUE], "call_sites": sites}


# ---- analysis ----

SAMPLE_STRIDE = 32
FLAW_CACHE = 1600
MUTANT_CASES = 360
GENERATED = 10200


def mutation_targets(image, rows):
    """Yield (va, byte offset in the instruction, xor mask, kind)."""
    for row in rows:
        for operand in (row.a, row.b):
            if operand and operand[0] == "m" and operand[1] not in (None, RSP) and operand[4]:
                disp = operand[4]
                end = row.size - (row.imm_size or 0)
                base = image.offset(row.va)
                data = bytes(image.blob[base:base + row.size])
                if -128 <= disp <= 127 and data[end - 1:end] == struct.pack("<b", disp):
                    yield row.va, end - 1, 8, "offset"
                elif data[end - 4:end] == struct.pack("<i", disp):
                    yield row.va, end - 4, 8, "offset"
                break
        if row.op == "jcc":
            yield row.va, row.size - (2 if row.size == 2 else 5), 1, "branch"
        elif row.op in ("set", "cmov"):
            base = image.offset(row.va)
            yield row.va, bytes(image.blob[base:base + 16]).index(b"\x0f") + 1, 1, row.op
        if row.imm_at is not None and row.op not in ("jcc", "call", "jmp"):
            yield row.va, row.imm_at, 1, "immediate"


def reason_for(row_by_va, result):
    """Classify a survivor from the decoded instruction alone; an empty string means no reason is claimed."""
    if result["result"] == "unreached":
        return "arm taken only when the supply index add carries; the cases keep that sum below 2^64 or fail an earlier guard"
    row = row_by_va[result["va"]]
    if row.op in ("imul3", "shr"):
        return "bit 0 of a calendar division constant leaves every quotient of a 19 bit year word unchanged"
    if row.op == "mov" and row.b[0] == "i" and row.b[1] in (E14 - 1, E14):
        return "1e14 divisor or high-word edge: changes a result only for a quotient of at least 1e14 or a high word of exactly 1e14 - 1"
    return ""


def run_mutants(image, rows, sample, reached):
    harness = Harness(image)
    machine = harness.machine
    machine.step_limit = MUTANT_STEP_LIMIT
    by_va = {}
    for index, touched in enumerate(reached):
        for va in touched:
            by_va.setdefault(va, []).append(index)
    first_kill = []
    results = []
    for va, at, xor, kind in mutation_targets(image, rows):
        indices = by_va.get(va)
        if not indices:
            results.append({"va": va, "kind": kind, "result": "unreached", "by": ""})
            continue
        base = image.offset(va)
        machine.patches = {va + at: image.blob[base + at] ^ xor}
        machine.cache.pop(va, None)
        failed = None
        wanted = set(indices)
        for index in [item for item in first_kill if item in wanted] + indices:
            failed = compare(harness, sample[index])
            if failed:
                if index in first_kill:
                    first_kill.remove(index)
                first_kill.insert(0, index)
                del first_kill[40:]
                break
        machine.patches = {}
        machine.cache.pop(va, None)
        results.append({"va": va, "kind": kind, "result": "killed" if failed else "survived", "by": sample[index]["label"] if failed else ""})
    return results


def corruption_controls(image):
    """Inputs the checks must refuse: each entry is (name, callable that must raise EvidenceError or Halt, or return a nonempty mismatch)."""
    blob = bytes(image.blob)
    controls = []

    def wrong_digest():
        mangled = bytearray(blob)
        mangled[len(mangled) // 2] ^= 1
        digest = hashlib.sha256(bytes(mangled)).hexdigest()
        if digest == SHA256:
            return ""
        raise EvidenceError("binary SHA-256 mismatch: %s" % digest)

    def truncated_image():
        Image(blob[:len(blob) // 2])
        return ""

    def middle_of_function():
        image.exact_fde(ACCRUE + 1)
        return ""

    def outside_sections():
        image.offset(0x10)
        return ""

    def before_function():
        image.exact_fde(ACCRUE - 0x10)
        return ""

    def zero_divisor_hook():
        harness = Harness(image)
        case = dict(hand_cases()[3])
        case["row"] = dict(case["row"], a=10 ** 8, b=0, ib=0)
        harness.machine.step_limit = 10
        return compare(harness, case)

    def unhooked_divide():
        harness = Harness(image)
        harness.machine.slots.clear()
        return compare(harness, hand_cases()[3])

    def unhooked_log():
        harness = Harness(image)
        harness.machine.slots.pop(0x7000010, None)
        return compare(harness, [case for case in hand_cases() if case["label"] == "pending add saturates"][0])

    def tiny_step_limit():
        harness = Harness(image)
        harness.machine.step_limit = 20
        return compare(harness, hand_cases()[3])

    def hooks_swapped():
        harness = Harness(image)
        slots = harness.machine.slots
        slots[0x7000000], slots[0x7000010] = slots[0x7000010], slots[0x7000000]
        return compare(harness, hand_cases()[3])

    for name, action in (("corrupted input digest", wrong_digest), ("truncated image", truncated_image), ("address inside the function", middle_of_function),
                         ("address outside every section", outside_sections), ("address before the function", before_function),
                         ("zero divisor reaches the wide divide", zero_divisor_hook), ("divide hook removed", unhooked_divide),
                         ("log hook removed", unhooked_log), ("step limit of 20", tiny_step_limit), ("divide and log hooks swapped", hooks_swapped)):
        try:
            outcome = action()
            detected = bool(outcome)
            note = outcome.split(":")[0] if outcome else "not refused"
        except (EvidenceError, Halt, Panicked, struct.error, IndexError, ValueError) as stop:
            detected, note = True, type(stop).__name__
        controls.append(("input", name, detected, note))
    return controls


def analyse(image, generated=GENERATED, full=True):
    relative = {slot: addend for slot, kind, addend, _ in image.relocations() if kind == 8}
    begin, end, rows, data = function_facts(image, ACCRUE)
    harness = Harness(image)
    machine = harness.machine
    cases = list(hand_cases())
    mismatches, first = 0, ""
    outcomes, total = {}, 0
    sample, reached, divides, logged = [], [], 0, 0
    stepped = set()
    hand = len(cases)

    calendar = list(calendar_cases())
    sample_wanted = hand + len(calendar) + MUTANT_CASES

    def stream():
        yield from cases
        yield from calendar
        yield from generated_cases(generated)

    for index, case in enumerate(stream()):
        machine.seen = set()
        failed = compare(harness, case)
        total += 1
        stepped |= machine.seen
        divides += harness.divides
        logged += len(harness.logs)
        if failed:
            mismatches += 1
            first = first or "%s: %s" % (case["label"], failed)
        key = outcome_of(case)
        outcomes[key] = outcomes.get(key, 0) + 1
        if index < hand + len(calendar) or (index - hand - len(calendar)) % SAMPLE_STRIDE == 0 and len(sample) < sample_wanted:
            sample.append(case)
            reached.append(frozenset(machine.seen))
    evidence = {
        "target_sha256": SHA256,
        "function": {"start": "%#x" % begin, "end": "%#x" % end, "bytes": end - begin, "sha256": hashlib.sha256(data).hexdigest(), "instructions": len(rows),
                     "instructions_stepped": sum(1 for row in rows if row.va in stepped)},
        "indirect_calls": indirect_calls(image, rows, relative),
        "log_locations": log_locations(image, rows, relative),
        "constants": {"1e14_movabs": immediate_sites(begin, data, E14), "year_millis_movabs": immediate_sites(begin, data, YEAR_MS), "year_millis": YEAR_MS,
                      "udiv_target": "%#x" % UDIV, "log_target": "%#x" % OVERFLOW_LOG},
        "row_offsets": {"%#x" % key: value for key, value in sorted(displacement_counts(rows).items()) if 0 <= key < 0x200},
        "caller": caller_boundary(image, relative),
        "cases": {"hand": hand, "calendar": len(calendar), "generated": total - hand - len(calendar), "total": total, "outcomes": dict(sorted(outcomes.items()))},
        "mismatches": mismatches,
        "first_mismatch": first,
        "wide_divides": divides,
        "overflow_logs": logged,
        "instructions_stepped_total": machine.steps,
    }
    flaws, mutants, controls = [], None, []
    if full:
        # flawed specifications are compared with real results of the first FLAW_CACHE cases
        runner = Harness(image)
        pool = list(hand_cases())
        pool += list(generated_cases(FLAW_CACHE))[:FLAW_CACHE - len(pool)]
        real = []
        for case in pool:
            real.append((case, runner.run(case), len(runner.logs)))
        for flaw in FLAWS:
            killed_by = ""
            for case, got, logs in real:
                want, want_logs = accrue_spec(case["row"], case["time"], case["keep"], flaw)
                if row_diff(got, want) or logs != len(want_logs):
                    killed_by = case["label"]
                    break
            flaws.append((flaw, bool(killed_by), killed_by))
        mutants = run_mutants(image, rows, sample, reached)
        controls = corruption_controls(image)
        evidence["mutations"] = {name: sum(1 for row in mutants if row["result"] == name) for name in ("killed", "survived", "unreached")}
    return evidence, flaws, mutants, controls, sample


# ---- output ----

def write_tsv(path, header, rows):
    lines = ["\t".join(header)] + ["\t".join(str(item) for item in row) for row in rows]
    path.write_text("\n".join(lines) + "\n", encoding="utf-8", newline="\n")


def case_row(harness, case):
    got = harness.run(case)
    want, logs = accrue_spec(case["row"], case["time"], case["keep"])
    return (case["label"], case["keep"], case["row"]["a"], case["row"]["ia"], case["row"]["b"], case["row"]["ib"], got["ia"], got["ib"], got["pending"], got["paid"],
            got["balance"], len(harness.logs), "yes" if row_key(got) == row_key(want) and len(harness.logs) == len(logs) else "NO")


def accrual_samples(image):
    """Real runs over one day at several uses of the pool and reserve shares."""
    harness = Harness(image)
    rows = []
    for use in (0, 10, 25, 50, 70, 79, 80, 81, 90, 100, 120):
        for keep in (0, E14 // 10, E14):
            case = dict(label="use %d percent" % use, row=token(a=use * 10 ** 6, b=10 ** 8), time=NOW, keep=keep)
            after = harness.run(case)
            rows.append((use, keep, after["ia"] - E14, after["ib"] - E14, after["pending"]))
    return rows


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--out", required=True)
    args = parser.parse_args(argv)
    blob = pathlib.Path(BINARY).read_bytes()
    if hashlib.sha256(blob).hexdigest() != SHA256:
        raise EvidenceError("binary SHA-256 mismatch")
    image = Image(blob)
    evidence, flaws, mutants, controls, sample = analyse(image)
    if evidence["mismatches"]:
        raise EvidenceError("specification mismatch: %s" % evidence["first_mismatch"])
    undetected = [name for name, caught, _ in flaws if not caught]
    if undetected:
        raise EvidenceError("flawed specifications not detected: %s" % ", ".join(undetected))
    refused = [name for _, name, caught, _ in controls if not caught]
    if refused:
        raise EvidenceError("input controls not refused: %s" % ", ".join(refused))
    out = pathlib.Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    killed = sum(1 for row in mutants if row["result"] == "killed")
    controls_total = len(flaws) + len(controls) + killed
    evidence["negative_controls"] = {"flawed_specifications": len(flaws), "input_corruptions": len(controls), "killed_byte_mutants": killed, "total": controls_total}
    (out / "evidence.json").write_text(json.dumps(evidence, indent=1, sort_keys=True) + "\n", encoding="utf-8", newline="\n")
    harness = Harness(image)
    rows = [case_row(harness, case) for case in hand_cases()]
    rows += [case_row(harness, case) for position, case in enumerate(generated_cases(GENERATED)) if position % 100 == 0]
    write_tsv(out / "cases-sample.tsv", ("label", "reserve_share", "borrowed", "borrow_index", "supplied", "supply_index", "borrow_index_after", "supply_index_after",
                                       "pending_after", "paid_after", "balance_after", "overflow_logs", "spec_agrees"), rows)
    write_tsv(out / "accrual-samples.tsv", ("use_percent", "reserve_share", "borrow_index_growth", "supply_index_growth", "pending_after"), accrual_samples(image))
    lines = ["kind\tname\tdetected\tdetail"]
    lines += ["flawed specification\t%s\t%s\t%s" % (name, "yes" if caught else "no", by) for name, caught, by in flaws]
    lines += ["input corruption\t%s\t%s\t%s" % (name, "yes" if caught else "no", note) for _, name, caught, note in controls]
    (out / "controls.tsv").write_text("\n".join(lines) + "\n", encoding="utf-8", newline="\n")
    by_va = {row.va: row for row in decode_range(image, *image.exact_fde(ACCRUE))}
    lines = ["va\tkind\tresult\tkilled_by\treason"]
    lines += ["%#x\t%s\t%s\t%s\t%s" % (row["va"], row["kind"], row["result"], row["by"], "" if row["result"] == "killed" else reason_for(by_va, row)) for row in mutants]
    (out / "mutations.tsv").write_text("\n".join(lines) + "\n", encoding="utf-8", newline="\n")
    measure = {"cases": evidence["cases"]["total"], "negative_controls": controls_total, "negative_detected": controls_total,
               "survivors_not_counted": evidence["mutations"]["survived"], "unreached_not_counted": evidence["mutations"]["unreached"]}
    (out / "measure.json").write_text(json.dumps(measure, indent=1, sort_keys=True) + "\n", encoding="utf-8", newline="\n")
    print("cases %d, mismatches %d, controls %d, mutants %r" % (evidence["cases"]["total"], evidence["mismatches"], controls_total, evidence["mutations"]))
    return 0


if __name__ == "__main__":
    sys.exit(main())
